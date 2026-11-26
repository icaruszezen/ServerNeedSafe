package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// startRootBreachTestSSHServer starts an in-process SSHv2 + SFTP + PTY shell + ProxyJump server.
func startRootBreachTestSSHServer(t *testing.T, expectedUser, expectedPass string, dynamicAuthKeys *sync.Map) (host string, port int, stop func()) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen host key: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == expectedUser && expectedPass != "" && string(pass) == expectedPass {
				return nil, nil
			}
			return nil, errors.New("bad password")
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if c.User() != expectedUser || dynamicAuthKeys == nil {
				return nil, errors.New("bad user")
			}
			ok := false
			dynamicAuthKeys.Range(func(_, value any) bool {
				allowed, isKey := value.(ssh.PublicKey)
				if isKey && bytes.Equal(allowed.Marshal(), key.Marshal()) {
					ok = true
					return false
				}
				return true
			})
			if ok {
				return nil, nil
			}
			return nil, errors.New("untrusted pubkey")
		},
	}
	cfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen ssh: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleBreachSSHConn(conn, cfg)
		}
	}()

	return "127.0.0.1", ln.Addr().(*net.TCPAddr).Port, func() { _ = ln.Close() }
}

func handleBreachSSHConn(netConn net.Conn, cfg *ssh.ServerConfig) {
	_, chans, reqs, err := ssh.NewServerConn(netConn, cfg)
	if err != nil {
		_ = netConn.Close()
		return
	}
	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		switch newChan.ChannelType() {
		case "direct-tcpip":
			var payload struct {
				DestHost string
				DestPort uint32
				OrigHost string
				OrigPort uint32
			}
			if err := ssh.Unmarshal(newChan.ExtraData(), &payload); err != nil {
				_ = newChan.Reject(ssh.Prohibited, "bad payload")
				continue
			}
			dest := net.JoinHostPort(payload.DestHost, strconv.Itoa(int(payload.DestPort)))
			dConn, err := net.Dial("tcp", dest)
			if err != nil {
				_ = newChan.Reject(ssh.ConnectionFailed, err.Error())
				continue
			}
			ch, chReqs, err := newChan.Accept()
			if err != nil {
				_ = dConn.Close()
				continue
			}
			go ssh.DiscardRequests(chReqs)
			go func() {
				defer ch.Close()
				defer dConn.Close()
				_, _ = io.Copy(ch, dConn)
			}()
			go func() {
				defer ch.Close()
				defer dConn.Close()
				_, _ = io.Copy(dConn, ch)
			}()

		case "session":
			ch, chReqs, err := newChan.Accept()
			if err != nil {
				continue
			}
			go func(in <-chan *ssh.Request) {
				for req := range in {
					switch req.Type {
					case "exec":
						var execPayload struct{ Command string }
						_ = ssh.Unmarshal(req.Payload, &execPayload)
						if req.WantReply {
							_ = req.Reply(true, nil)
						}
						cmd := exec.Command("/bin/sh", "-c", execPayload.Command)
						cmd.Stdin = ch
						cmd.Stdout = ch
						cmd.Stderr = ch.Stderr()
						exitStatus := uint32(0)
						if err := cmd.Run(); err != nil {
							exitStatus = 1
						}
						_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: exitStatus}))
						_ = ch.Close()
						return
					case "shell":
						if req.WantReply {
							_ = req.Reply(true, nil)
						}
						cmd := exec.Command("/bin/sh")
						cmd.Stdin = ch
						cmd.Stdout = ch
						cmd.Stderr = ch.Stderr()
						exitStatus := uint32(0)
						if err := cmd.Run(); err != nil {
							exitStatus = 1
						}
						_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: exitStatus}))
						_ = ch.Close()
						return
					case "subsystem":
						var sub struct{ Name string }
						_ = ssh.Unmarshal(req.Payload, &sub)
						if sub.Name == "sftp" {
							if req.WantReply {
								_ = req.Reply(true, nil)
							}
							srv, err := sftp.NewServer(ch)
							if err == nil {
								_ = srv.Serve()
							}
							_ = ch.Close()
							return
						}
						if req.WantReply {
							_ = req.Reply(false, nil)
						}
					default:
						if req.WantReply {
							_ = req.Reply(true, nil)
						}
					}
				}
			}(chReqs)
		default:
			_ = newChan.Reject(ssh.UnknownChannelType, "unsupported")
		}
	}
}

func TestSplitStorageProxyJumpWebSocketPTYBackgroundMonitorAndBackupSync(t *testing.T) {
	t.Setenv("NO_PROXY", "127.0.0.1,localhost")
	primaryDir := t.TempDir()
	primarySecretsPath := filepath.Join(primaryDir, "secrets.enc")
	primarySrv, primaryTS := newTestServerInstance(t, primaryDir, 8*time.Hour)
	defer primaryTS.Close()
	defer primarySrv.Close()

	secondaryDir := t.TempDir()
	secondarySecretsPath := filepath.Join(secondaryDir, "secrets.enc")
	secondarySrv, secondaryTS := newTestServerInstance(t, secondaryDir, 8*time.Hour)
	defer secondaryTS.Close()
	defer secondarySrv.Close()

	// Initialize secondary instance with its own admin password and distinct local monitor telemetry
	secondaryAdminPass := "SecondaryNodePass!2026"
	secondaryHTTP := newCookieHTTPClient()
	secSetupReq, _ := json.Marshal(map[string]string{"password": secondaryAdminPass})
	sInitRes, err := secondaryHTTP.Post(secondaryTS.URL+"/api/auth/setup", "application/json", bytes.NewReader(secSetupReq))
	if err != nil || sInitRes.StatusCode != http.StatusOK {
		t.Fatalf("secondary POST /api/auth/setup: status=%v err=%v", sInitRes.StatusCode, err)
	}
	sInitRes.Body.Close()

	// Create a local server and seed a local monitor snapshot on secondary so we can prove default sync (include_runtime=false) preserves it
	secLocalSrv, err := secondarySrv.cfg.Store.CreateServer(vault.ServerMutationInput{
		Name:     "secondary-local-sentinel",
		Group:    "本地监控节点",
		Host:     "10.250.0.1",
		Port:     22,
		Username: "ops",
		AuthType: vault.AuthPassword,
		Password: strPtrForTest("SecLocalPass!1"),
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("create secondary local server: %v", err)
	}
	_, _, _, err = secondarySrv.cfg.Store.RecordMonitorSnapshots([]*vault.ServerMonitorSnapshot{{
		ServerID:    secLocalSrv.ID,
		ServerName:  "secondary-local-sentinel",
		CollectedAt: time.Now().UTC(),
		Reachable:   true,
		CPUPercent:  77.7,
	}})
	if err != nil {
		t.Fatalf("seed secondary monitor snapshot: %v", err)
	}

	// 1. Start Bastion SSH server + Internal CoreDB SSH server (reachable via Bastion ProxyJump)
	var internalAuthorizedKeys sync.Map
	bastionHost, bastionPort, stopBastion := startRootBreachTestSSHServer(t, "jumpops_secret_user", "BastionSSHPass!9988", nil)
	defer stopBastion()

	targetHost, targetPort, stopTarget := startRootBreachTestSSHServer(t, "coredb_secret_admin", "", &internalAuthorizedKeys)
	defer stopTarget()

	adminPass := "StrongDaemonMasterPass!2026"
	adminHTTP := newCookieHTTPClient()

	setupReq, _ := json.Marshal(map[string]string{"password": adminPass})
	res, err := adminHTTP.Post(primaryTS.URL+"/api/auth/setup", "application/json", bytes.NewReader(setupReq))
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/auth/setup: status=%v err=%v", res.StatusCode, err)
	}
	res.Body.Close()

	// Generate Ed25519 SSH keypair via native API & authorize on target SSH server
	kgReq, _ := json.Marshal(map[string]string{"algorithm": "ed25519", "comment": "secops-canary@sns"})
	kgRes, err := adminHTTP.Post(primaryTS.URL+"/api/ssh/keygen", "application/json", bytes.NewReader(kgReq))
	if err != nil || kgRes.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/ssh/keygen: status=%v err=%v", kgRes.StatusCode, err)
	}
	var kp struct {
		Algorithm   string `json:"algorithm"`
		PrivateKey  string `json:"private_key"`
		PublicKey   string `json:"public_key"`
		Fingerprint string `json:"fingerprint"`
	}
	_ = json.NewDecoder(kgRes.Body).Decode(&kp)
	kgRes.Body.Close()

	parsedPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(kp.PublicKey))
	if err != nil {
		t.Fatalf("ParseAuthorizedKey: %v", err)
	}
	internalAuthorizedKeys.Store("ed25519", parsedPub)

	// Save Ed25519 Credential + Bastion + ProxyJump Target Server
	credBody, _ := json.Marshal(map[string]any{
		"name":          "Secret-Ed25519-Keychain-Item",
		"kind":          "private_key",
		"username_hint": "coredb_secret_admin",
		"private_key":   kp.PrivateKey,
		"public_key":    kp.PublicKey,
		"fingerprint":   kp.Fingerprint,
		"key_algorithm": kp.Algorithm,
		"notes":         "TOP_SECRET_CREDENTIAL_NOTES_4411",
	})
	credRes, err := adminHTTP.Post(primaryTS.URL+"/api/credentials", "application/json", bytes.NewReader(credBody))
	if err != nil || credRes.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/credentials: status=%v err=%v", credRes.StatusCode, err)
	}
	var credWrap struct {
		Credential vault.CredentialView `json:"credential"`
	}
	_ = json.NewDecoder(credRes.Body).Decode(&credWrap)
	credRes.Body.Close()
	credOut := credWrap.Credential

	bastionBody, _ := json.Marshal(map[string]any{
		"name":      "Bastion-Alpha-Secret-Node",
		"group":     "核心涉密网关组",
		"tags":      []string{"secret-bastion-tag"},
		"host":      bastionHost,
		"port":      bastionPort,
		"username":  "jumpops_secret_user",
		"auth_type": "password",
		"password":  "BastionSSHPass!9988",
		"notes":     "BASTION_INTERNAL_NOTE_5522",
	})
	bRes, err := adminHTTP.Post(primaryTS.URL+"/api/servers", "application/json", bytes.NewReader(bastionBody))
	if err != nil || bRes.StatusCode != http.StatusOK {
		t.Fatalf("POST bastion /api/servers: status=%v err=%v", bRes.StatusCode, err)
	}
	var bWrap struct {
		Server vault.ServerView `json:"server"`
	}
	_ = json.NewDecoder(bRes.Body).Decode(&bWrap)
	bRes.Body.Close()
	bastionOut := bWrap.Server

	targetBody, _ := json.Marshal(map[string]any{
		"name":             "CoreDB-Master-Secret-Vault",
		"group":            "核心涉密数据库组",
		"tags":             []string{"zero-trust-db"},
		"host":             targetHost,
		"port":             targetPort,
		"username":         "coredb_secret_admin",
		"auth_type":        "credential",
		"credential_id":    credOut.ID,
		"jump_server_id":   bastionOut.ID,
		"notes":            "COREDB_PRIVATE_NOTE_6633",
		"watched_services": []string{"secret-watched-daemon-canary"},
	})
	tRes, err := adminHTTP.Post(primaryTS.URL+"/api/servers", "application/json", bytes.NewReader(targetBody))
	if err != nil || tRes.StatusCode != http.StatusOK {
		t.Fatalf("POST target /api/servers: status=%v err=%v", tRes.StatusCode, err)
	}
	var tWrap struct {
		Server vault.ServerView `json:"server"`
	}
	_ = json.NewDecoder(tRes.Body).Decode(&tWrap)
	tRes.Body.Close()
	targetOut := tWrap.Server

	// 2. Probe & BatchExec through Bastion ProxyJump -> Target
	probeRes, err := adminHTTP.Post(primaryTS.URL+"/api/servers/"+targetOut.ID+"/probe", "application/json", bytes.NewReader([]byte(`{}`)))
	if err != nil || probeRes.StatusCode != http.StatusOK {
		t.Fatalf("POST probe failed: status=%v err=%v", probeRes.StatusCode, err)
	}
	var probeOut struct {
		Probe struct {
			Reachable bool `json:"reachable"`
		} `json:"probe"`
	}
	_ = json.NewDecoder(probeRes.Body).Decode(&probeOut)
	probeRes.Body.Close()
	if !probeOut.Probe.Reachable {
		t.Fatalf("expected target server reachable over ProxyJump")
	}

	batchReq, _ := json.Marshal(map[string]any{
		"server_ids":  []string{targetOut.ID},
		"command":     "echo SUPER_SECRET_BATCH_TOKEN_7749",
		"timeout_sec": 15,
	})
	batchRes, err := adminHTTP.Post(primaryTS.URL+"/api/ssh/batch-exec", "application/json", bytes.NewReader(batchReq))
	if err != nil || batchRes.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/ssh/batch-exec: status=%v err=%v", batchRes.StatusCode, err)
	}
	var batchOut struct {
		Results []struct {
			Success bool   `json:"success"`
			Stdout  string `json:"stdout"`
		} `json:"results"`
	}
	_ = json.NewDecoder(batchRes.Body).Decode(&batchOut)
	batchRes.Body.Close()
	if len(batchOut.Results) != 1 || !batchOut.Results[0].Success || !strings.Contains(batchOut.Results[0].Stdout, "SUPER_SECRET_BATCH_TOKEN_7749") {
		t.Fatalf("unexpected batch-exec output: %+v", batchOut)
	}

	// 3. Opaque null-origin WebSocket rejected + Live Native Binary WebSocket PTY (/api/ws/terminal)
	wsURL := "ws" + strings.TrimPrefix(primaryTS.URL, "http") + "/api/ws/terminal?server_id=" + url.QueryEscape(targetOut.ID) + "&cols=100&rows=30"
	wsDialer := websocket.Dialer{Jar: adminHTTP.Jar}
	_, nullResp, nullErr := wsDialer.Dial(wsURL, http.Header{"Origin": []string{"null"}})
	if nullErr == nil || nullResp == nil || nullResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected opaque Origin: null WebSocket blocked with 403, resp=%v err=%v", nullResp, nullErr)
	}

	sameOriginHeader := http.Header{"Origin": []string{primaryTS.URL}}
	wsConn, _, err := wsDialer.Dial(wsURL, sameOriginHeader)
	if err != nil {
		t.Fatalf("WebSocket /api/ws/terminal dial failed: %v", err)
	}
	defer wsConn.Close()

	_ = wsConn.SetReadDeadline(time.Now().Add(8 * time.Second))
	_, firstFrame, err := wsConn.ReadMessage()
	if err != nil || !strings.Contains(string(firstFrame), `"ready"`) {
		t.Fatalf("expected ready message on /api/ws/terminal, got %q (err=%v)", string(firstFrame), err)
	}
	if err := wsConn.WriteMessage(websocket.BinaryMessage, []byte("echo TERMINAL_WS_PTY_CANARY_8821\nexit\n")); err != nil {
		t.Fatalf("ws WriteMessage: %v", err)
	}

	var ptyCombined bytes.Buffer
	for {
		_ = wsConn.SetReadDeadline(time.Now().Add(8 * time.Second))
		msgType, data, rErr := wsConn.ReadMessage()
		if rErr != nil {
			break
		}
		if msgType == websocket.BinaryMessage {
			ptyCombined.Write(data)
			if strings.Contains(ptyCombined.String(), "TERMINAL_WS_PTY_CANARY_8821") {
				break
			}
		}
	}
	if !strings.Contains(ptyCombined.String(), "TERMINAL_WS_PTY_CANARY_8821") {
		t.Fatalf("did not receive PTY canary over /api/ws/terminal, got %q", ptyCombined.String())
	}

	// 4. Streaming SFTP Upload + Download via REST endpoints
	sftpRemoteDir := t.TempDir()
	secretFileName := "top_secret_payroll_2026.txt"
	secretFileContent := "CONFIDENTIAL_SFTP_PAYLOAD_991234"

	var mpBuf bytes.Buffer
	mpWriter := multipart.NewWriter(&mpBuf)
	_ = mpWriter.WriteField("server_id", targetOut.ID)
	_ = mpWriter.WriteField("dir", sftpRemoteDir)
	fw, _ := mpWriter.CreateFormFile("file", secretFileName)
	_, _ = fw.Write([]byte(secretFileContent))
	_ = mpWriter.Close()

	upRes, err := adminHTTP.Post(primaryTS.URL+"/api/sftp/upload", mpWriter.FormDataContentType(), &mpBuf)
	if err != nil || upRes.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/sftp/upload failed: status=%v err=%v", upRes.StatusCode, err)
	}
	var upOut struct {
		Path string `json:"path"`
	}
	_ = json.NewDecoder(upRes.Body).Decode(&upOut)
	upRes.Body.Close()

	dlReq, _ := json.Marshal(map[string]string{
		"server_id": targetOut.ID,
		"path":      upOut.Path,
	})
	dlRes, err := adminHTTP.Post(primaryTS.URL+"/api/sftp/download", "application/json", bytes.NewReader(dlReq))
	if err != nil || dlRes.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/sftp/download failed: status=%v err=%v", dlRes.StatusCode, err)
	}
	dlBytes, _ := io.ReadAll(dlRes.Body)
	dlRes.Body.Close()
	if string(dlBytes) != secretFileContent {
		t.Fatalf("SFTP download mismatch: got %q", string(dlBytes))
	}

	// 5. 7x24 Background Daemon Decoupling Proof + Zero secrets.enc Rewrite During Monitoring:
	// Lock ALL Web sessions -> Web console gets 401, yet background Monitor Engine STILL collects SSH telemetry
	// and writes ONLY to monitor_runtime.json without touching secrets.enc!
	secretsBeforeMonitor, err := os.ReadFile(primarySecretsPath)
	if err != nil {
		t.Fatalf("ReadFile secrets.enc before monitor: %v", err)
	}

	lockRes, err := adminHTTP.Post(primaryTS.URL+"/api/auth/lock", "application/json", bytes.NewReader([]byte(`{}`)))
	if err != nil || lockRes.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/auth/lock: status=%v err=%v", lockRes.StatusCode, err)
	}
	lockRes.Body.Close()

	unauthMonRes, _ := adminHTTP.Get(primaryTS.URL + "/api/monitor/overview")
	unauthMonRes.Body.Close()
	if unauthMonRes.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 on /api/monitor/overview while web console is locked, got %d", unauthMonRes.StatusCode)
	}

	bgSnap, err := primarySrv.cfg.Monitor.CollectServerNow(context.Background(), targetOut.ID, "", "daemon:patrol")
	if err != nil || bgSnap == nil || !bgSnap.Reachable || bgSnap.CPUCores < 1 {
		t.Fatalf("expected 7x24 background monitor collection to succeed while Web sessions are locked! snap=%+v err=%v", bgSnap, err)
	}
	if err := primarySrv.cfg.Store.FlushNow(); err != nil {
		t.Fatalf("FlushNow: %v", err)
	}
	secretsAfterMonitor, err := os.ReadFile(primarySecretsPath)
	if err != nil {
		t.Fatalf("ReadFile secrets.enc after monitor: %v", err)
	}
	if !bytes.Equal(secretsBeforeMonitor, secretsAfterMonitor) {
		t.Fatalf("DECOUPLING VIOLATION: background monitoring/lock rewrote secrets.enc!")
	}

	// Re-login to Web console and verify Portable .sns v3 Backup Export + Simplified Cross-Instance Sync
	loginReq, _ := json.Marshal(map[string]string{"password": adminPass})
	reloginRes, err := adminHTTP.Post(primaryTS.URL+"/api/auth/login", "application/json", bytes.NewReader(loginReq))
	if err != nil || reloginRes.StatusCode != http.StatusOK {
		t.Fatalf("re-login failed: status=%v err=%v", reloginRes.StatusCode, err)
	}
	reloginRes.Body.Close()

	backupPass := "PortableBackupPass#2026!"
	expReqBody, _ := json.Marshal(map[string]any{
		"backup_password": backupPass,
		"include_runtime": true,
	})
	expRes, err := adminHTTP.Post(primaryTS.URL+"/api/vault/export", "application/json", bytes.NewReader(expReqBody))
	if err != nil || expRes.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/vault/export: status=%v err=%v", expRes.StatusCode, err)
	}
	exportedSNSBytes, _ := io.ReadAll(expRes.Body)
	expRes.Body.Close()

	// Push core config + AI knowledge (default include_runtime=false) to Secondary Server via /api/vault/sync/push
	syncPushReq, _ := json.Marshal(map[string]any{
		"remote_url":      secondaryTS.URL,
		"remote_password": secondaryAdminPass,
		"include_runtime": false,
	})
	syncRes, err := adminHTTP.Post(primaryTS.URL+"/api/vault/sync/push", "application/json", bytes.NewReader(syncPushReq))
	if err != nil || syncRes.StatusCode != http.StatusOK {
		bodyTxt, _ := io.ReadAll(syncRes.Body)
		t.Fatalf("POST /api/vault/sync/push: status=%v body=%s err=%v", syncRes.StatusCode, string(bodyTxt), err)
	}
	syncRes.Body.Close()

	// Verify secondary received primary's servers while PRESERVING secondary's own monitor runtime snapshot!
	secServers, err := secondarySrv.cfg.Store.ListServers()
	if err != nil || len(secServers) != 2 {
		t.Fatalf("expected secondary to receive 2 synced servers, got %+v err=%v", secServers, err)
	}
	secBundle, err := secondarySrv.cfg.Store.BuildBackupBundle(true)
	if err != nil {
		t.Fatalf("secondary BuildBackupBundle: %v", err)
	}
	if secBundle.Runtime == nil || secBundle.Runtime.Monitor.LatestSnapshots[secLocalSrv.ID] == nil ||
		secBundle.Runtime.Monitor.LatestSnapshots[secLocalSrv.ID].CPUPercent != 77.7 {
		t.Fatalf("expected include_runtime=false sync to preserve secondary local monitor telemetry, got %+v", secBundle.Runtime)
	}

	// =========================================================================
	// AT-REST ENCRYPTION AUDIT: Disk secrets.enc & Exported .sns Backup Zero Plaintext
	// =========================================================================
	primaryDiskBytes, err := os.ReadFile(primarySecretsPath)
	if err != nil {
		t.Fatalf("ReadFile primary secrets.enc: %v", err)
	}
	secondaryDiskBytes, err := os.ReadFile(secondarySecretsPath)
	if err != nil {
		t.Fatalf("ReadFile secondary secrets.enc: %v", err)
	}

	forbiddenCanaries := []string{
		adminPass,
		backupPass,
		"Secret-Ed25519-Keychain-Item",
		"OPENSSH PRIVATE KEY",
		"secops-canary@sns",
		"TOP_SECRET_CREDENTIAL_NOTES_4411",
		"Bastion-Alpha-Secret-Node",
		"jumpops_secret_user",
		"BastionSSHPass!9988",
		"BASTION_INTERNAL_NOTE_5522",
		"CoreDB-Master-Secret-Vault",
		"coredb_secret_admin",
		"COREDB_PRIVATE_NOTE_6633",
		"secret-watched-daemon-canary",
	}
	for surfaceName, blob := range map[string][]byte{
		"primary_disk(secrets.enc)":   primaryDiskBytes,
		"secondary_disk(secrets.enc)": secondaryDiskBytes,
		"exported_backup(.sns)":       exportedSNSBytes,
	} {
		for _, canary := range forbiddenCanaries {
			if bytes.Contains(blob, []byte(canary)) {
				t.Fatalf("AT-REST ENCRYPTION BREACH: plaintext canary %q leaked in %s!", canary, surfaceName)
			}
			b64 := base64.StdEncoding.EncodeToString([]byte(canary))
			if len(b64) >= 12 && bytes.Contains(blob, []byte(b64)) {
				t.Fatalf("AT-REST ENCRYPTION BREACH: base64 canary %q leaked in %s!", canary, surfaceName)
			}
		}
	}

	// Verify exported .sns backup is password-wrapped (wrong password rejected on portable restore)
	checkStore, err := vault.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("checkStore NewStore: %v", err)
	}
	defer checkStore.Close()
	if err := checkStore.ImportBackupBytes(exportedSNSBytes, "WrongRestorePass!000", true, "restore-test"); !errors.Is(err, vault.ErrInvalidPassword) {
		t.Fatalf("expected exported .sns backup to require backup password, got %v", err)
	}

	// =========================================================================
	// ACTIVE ATTACK #1: Unauthenticated /api/vault/import/file Overwrite -> 401
	// =========================================================================
	rogueStore, err := vault.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("rogue NewStore: %v", err)
	}
	defer rogueStore.Close()
	if err := rogueStore.Setup("AttackerRoguePass!123", "attacker"); err != nil {
		t.Fatalf("rogue Setup: %v", err)
	}
	rogueBlob, err := rogueStore.ExportBackupBytes("AttackerRoguePass!123", false, "attacker")
	if err != nil {
		t.Fatalf("rogue ExportBackupBytes: %v", err)
	}

	var rogueMP bytes.Buffer
	rogueWriter := multipart.NewWriter(&rogueMP)
	_ = rogueWriter.WriteField("password", "AttackerRoguePass!123")
	rfw, _ := rogueWriter.CreateFormFile("file", "rogue.sns")
	_, _ = rfw.Write(rogueBlob)
	_ = rogueWriter.Close()

	mpImpRes, err := http.Post(primaryTS.URL+"/api/vault/import/file", rogueWriter.FormDataContentType(), &rogueMP)
	if err != nil {
		t.Fatalf("POST unauth /api/vault/import/file: %v", err)
	}
	mpImpRes.Body.Close()
	if mpImpRes.StatusCode != http.StatusUnauthorized {
		t.Fatalf("SECURITY FAILURE: unauthenticated /api/vault/import/file overwrite was not blocked with 401! got %d", mpImpRes.StatusCode)
	}

	// =========================================================================
	// ACTIVE ATTACK #2: Bit-Flip Ciphertext Tamper on Backup & Disk -> AEAD REJECTED
	// =========================================================================
	tampered := append([]byte(nil), exportedSNSBytes...)
	tampered[len(tampered)-17] ^= 0xFF
	tamperedStore, err := vault.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("tampered NewStore: %v", err)
	}
	defer tamperedStore.Close()
	if err := tamperedStore.ImportBackupBytes(tampered, backupPass, true, "tamper-test"); !errors.Is(err, vault.ErrInvalidPassword) && !errors.Is(err, vault.ErrCorruptedVault) {
		t.Fatalf("SECURITY FAILURE: tampered backup ciphertext was not rejected by AEAD! got %v", err)
	}

	tamperedSecrets := append([]byte(nil), primaryDiskBytes...)
	tamperedSecrets[len(tamperedSecrets)-5] ^= 0xFF
	tamperDir := t.TempDir()
	primaryKeyBytes, err := os.ReadFile(filepath.Join(primaryDir, "master.key"))
	if err != nil {
		t.Fatalf("read master.key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tamperDir, "master.key"), primaryKeyBytes, 0o600); err != nil {
		t.Fatalf("write tamper master.key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tamperDir, "secrets.enc"), tamperedSecrets, 0o600); err != nil {
		t.Fatalf("write tamper secrets.enc: %v", err)
	}
	if _, err := vault.NewStore(tamperDir); !errors.Is(err, vault.ErrCorruptedVault) {
		t.Fatalf("SECURITY FAILURE: tampered disk secrets.enc was not rejected with ErrCorruptedVault! got %v", err)
	}
}

func strPtrForTest(v string) *string {
	return &v
}

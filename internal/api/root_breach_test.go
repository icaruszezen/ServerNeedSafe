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

func TestEncryptedVaultAtRestProxyJumpWebSocketPTYBackgroundMonitorAndBackupSecurity(t *testing.T) {
	primaryDir := t.TempDir()
	primaryVaultPath := filepath.Join(primaryDir, "vault.sns")
	primarySrv, primaryTS := newTestServerInstance(t, primaryDir, 8*time.Hour)
	defer primaryTS.Close()
	defer primarySrv.Close()

	secondaryDir := t.TempDir()
	secondaryVaultPath := filepath.Join(secondaryDir, "vault.sns")
	secondarySrv, secondaryTS := newTestServerInstance(t, secondaryDir, 8*time.Hour)
	defer secondaryTS.Close()
	defer secondarySrv.Close()

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

	// 3. Cross-Origin WebSocket Hijacking Guard + Live Native Binary WebSocket PTY (/api/ws/terminal)
	wsURL := "ws" + strings.TrimPrefix(primaryTS.URL, "http") + "/api/ws/terminal?server_id=" + url.QueryEscape(targetOut.ID) + "&cols=100&rows=30"
	evilDialer := websocket.Dialer{Jar: adminHTTP.Jar}
	evilHeader := http.Header{"Origin": []string{"https://evil-attacker.example"}}
	_, evilResp, evilErr := evilDialer.Dial(wsURL, evilHeader)
	// Blocked either by the cookie same-origin guard in the auth layer (401) or by the WS origin check (403).
	if evilErr == nil || evilResp == nil || (evilResp.StatusCode != http.StatusForbidden && evilResp.StatusCode != http.StatusUnauthorized) {
		t.Fatalf("SECURITY FAILURE: cross-origin WebSocket hijack was not blocked with 401/403! resp=%v err=%v", evilResp, evilErr)
	}

	sameOriginHeader := http.Header{"Origin": []string{primaryTS.URL}}
	wsConn, _, err := evilDialer.Dial(wsURL, sameOriginHeader)
	if err != nil {
		t.Fatalf("WebSocket /api/ws/terminal dial failed: %v", err)
	}
	defer wsConn.Close()

	// Wait for {"type":"ready"} control frame, then execute command over binary frame
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

	// 4. Streaming SFTP Upload + ReadText + Download via REST endpoints
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

	// 5. 7x24 Background Daemon Decoupling Proof:
	// Lock ALL Web sessions -> Web console gets 401, yet background Monitor Engine STILL collects SSH telemetry & persists to vault.sns!
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

	// Background 7x24 Monitor Engine executes scheduled SSH collection while zero Web sessions exist!
	bgSnap, err := primarySrv.cfg.Monitor.CollectServerNow(context.Background(), targetOut.ID, "", "daemon:patrol")
	if err != nil || bgSnap == nil || !bgSnap.Reachable || bgSnap.CPUCores < 1 {
		t.Fatalf("expected 7x24 background monitor collection to succeed while Web sessions are locked! snap=%+v err=%v", bgSnap, err)
	}

	// Re-login to Web console and verify fresh telemetry & Portable .sns Export + Remote Cloud Sync
	loginReq, _ := json.Marshal(map[string]string{"password": adminPass})
	reloginRes, err := adminHTTP.Post(primaryTS.URL+"/api/auth/login", "application/json", bytes.NewReader(loginReq))
	if err != nil || reloginRes.StatusCode != http.StatusOK {
		t.Fatalf("re-login failed: status=%v err=%v", reloginRes.StatusCode, err)
	}
	reloginRes.Body.Close()

	expRes, err := adminHTTP.Get(primaryTS.URL + "/api/vault/export")
	if err != nil || expRes.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/vault/export: status=%v err=%v", expRes.StatusCode, err)
	}
	exportedSNSBytes, _ := io.ReadAll(expRes.Body)
	expRes.Body.Close()

	// Push encrypted container to Secondary Server via /api/vault/sync/push
	syncPushReq, _ := json.Marshal(map[string]string{"remote_url": secondaryTS.URL})
	syncRes, err := adminHTTP.Post(primaryTS.URL+"/api/vault/sync/push", "application/json", bytes.NewReader(syncPushReq))
	if err != nil || syncRes.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/vault/sync/push: status=%v err=%v", syncRes.StatusCode, err)
	}
	syncRes.Body.Close()

	// =========================================================================
	// AT-REST ENCRYPTION AUDIT: Disk vault.sns & Exported .sns Backup Zero Plaintext
	// =========================================================================
	primaryDiskBytes, err := os.ReadFile(primaryVaultPath)
	if err != nil {
		t.Fatalf("ReadFile primary vault.sns: %v", err)
	}
	secondaryDiskBytes, err := os.ReadFile(secondaryVaultPath)
	if err != nil {
		t.Fatalf("ReadFile secondary vault.sns: %v", err)
	}

	forbiddenCanaries := []string{
		adminPass,
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
		"primary_disk(vault.sns)":   primaryDiskBytes,
		"secondary_disk(vault.sns)": secondaryDiskBytes,
		"exported_backup(.sns)":     exportedSNSBytes,
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

	// Verify exported .sns backup is strictly password-wrapped (wrong password rejected on portable restore)
	checkStore := vault.NewClientVault(vault.NewBlindStoreBackend(mustNewTempBlindStore(t)))
	if err := checkStore.ImportEncryptedVault(exportedSNSBytes, "WrongRestorePass!000", "", "restore-test"); !errors.Is(err, vault.ErrInvalidPassword) {
		t.Fatalf("expected exported .sns backup to require admin password, got %v", err)
	}

	// =========================================================================
	// ACTIVE ATTACK #1: Unauthenticated Backup Overwrite via /import & /import/file -> 401
	// =========================================================================
	rogueCV := vault.NewClientVault(vault.NewBlindStoreBackend(mustNewTempBlindStore(t)))
	rogueCV.SetKDFParams(1, 16*1024, 2)
	if err := rogueCV.Setup("AttackerRoguePass!123", "attacker"); err != nil {
		t.Fatalf("rogue Setup: %v", err)
	}
	rogueBlob, rogueHdr, _ := rogueCV.LastSealedBlob()
	roguePriv := rogueCV.AuthPrivateKeyCopy()
	rogueNewSig := vault.SignVaultImport(roguePriv, rogueHdr.VaultID, rogueHdr.Revision, rogueBlob)
	forgedOverwriteSig := vault.SignVaultImportOverwrite(roguePriv, "forged-old-id", rogueHdr.VaultID, rogueBlob)
	importPayload, _ := json.Marshal(map[string]string{
		"blob_b64":                base64.StdEncoding.EncodeToString(rogueBlob),
		"new_signature_b64":       base64.StdEncoding.EncodeToString(rogueNewSig),
		"overwrite_signature_b64": base64.StdEncoding.EncodeToString(forgedOverwriteSig),
	})
	impRes, err := http.Post(primaryTS.URL+"/api/vault/import", "application/json", bytes.NewReader(importPayload))
	if err != nil {
		t.Fatalf("POST /api/vault/import: %v", err)
	}
	impRes.Body.Close()
	if impRes.StatusCode != http.StatusUnauthorized {
		t.Fatalf("SECURITY FAILURE: forged signed import overwrite was not rejected with 401! got %d", impRes.StatusCode)
	}

	// Also verify unauthenticated multipart /api/vault/import/file WITHOUT current admin password is rejected with 401!
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
	// ACTIVE ATTACK #2: Bit-Flip Ciphertext Tamper on Disk -> AEAD REJECTED
	// =========================================================================
	tampered := append([]byte(nil), exportedSNSBytes...)
	tampered[len(tampered)-17] ^= 0xFF
	tamperedStore := vault.NewClientVault(vault.NewBlindStoreBackend(mustNewTempBlindStore(t)))
	if err := tamperedStore.ImportEncryptedVault(tampered, adminPass, "", "tamper-test"); !errors.Is(err, vault.ErrCorruptedVault) {
		t.Fatalf("SECURITY FAILURE: tampered ciphertext was not rejected with ErrCorruptedVault! got %v", err)
	}
}

func mustNewTempBlindStore(t *testing.T) *vault.BlindStore {
	t.Helper()
	bs, err := vault.NewBlindStore(filepath.Join(t.TempDir(), "rogue.sns"))
	if err != nil {
		t.Fatalf("NewBlindStore: %v", err)
	}
	return bs
}

package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/auth"
	"github.com/icaruszezen/ServerNeedSafe/internal/relay"
	"github.com/icaruszezen/ServerNeedSafe/internal/sshmanager"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
	"github.com/icaruszezen/ServerNeedSafe/internal/zkclient"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// socketWireTap simulates a root attacker running full-packet tcpdump on sns-server's loopback/NIC,
// capturing every raw HTTP request, HTTP response, and WebSocket TCP-relay frame in both directions.
type socketWireTap struct {
	mu       sync.Mutex
	inbound  bytes.Buffer
	outbound bytes.Buffer
}

func (t *socketWireTap) AllBytes() []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]byte, 0, t.inbound.Len()+t.outbound.Len())
	out = append(out, t.inbound.Bytes()...)
	out = append(out, '\n')
	out = append(out, t.outbound.Bytes()...)
	return out
}

type tapConn struct {
	net.Conn
	tap *socketWireTap
}

func (c *tapConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.tap.mu.Lock()
		_, _ = c.tap.inbound.Write(p[:n])
		c.tap.mu.Unlock()
	}
	return n, err
}

func (c *tapConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.tap.mu.Lock()
		_, _ = c.tap.outbound.Write(p[:n])
		c.tap.mu.Unlock()
	}
	return n, err
}

type tapListener struct {
	net.Listener
	tap *socketWireTap
}

func (l *tapListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &tapConn{Conn: conn, tap: l.tap}, nil
}

func newTappedHTTPServer(t *testing.T, handler http.Handler) (*httptest.Server, *socketWireTap) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	tap := &socketWireTap{}
	ts := httptest.NewUnstartedServer(handler)
	_ = ts.Listener.Close()
	ts.Listener = &tapListener{Listener: ln, tap: tap}
	ts.Start()
	return ts, tap
}

// inspectGoHeapStringsAndBytes simulates a root attacker dumping Go process heap objects (/proc/<pid>/mem),
// walking every exported and unexported struct field, map, slice, array, and string reachable from rootVal.
func inspectGoHeapStringsAndBytes(rootVal any) []byte {
	visited := make(map[uintptr]bool)
	var dump bytes.Buffer

	var walk func(v reflect.Value, depth int)
	walk = func(v reflect.Value, depth int) {
		if !v.IsValid() || depth > 14 {
			return
		}
		switch v.Kind() {
		case reflect.Pointer, reflect.Interface:
			if v.IsNil() {
				return
			}
			if v.Kind() == reflect.Pointer {
				ptr := v.Pointer()
				if ptr != 0 {
					if visited[ptr] {
						return
					}
					visited[ptr] = true
				}
			}
			walk(v.Elem(), depth+1)

		case reflect.Struct:
			// Skip sync primitives to avoid meaningless internal mutex state noise
			pkgPath := v.Type().PkgPath()
			if pkgPath == "sync" || pkgPath == "sync/atomic" {
				return
			}
			for i := 0; i < v.NumField(); i++ {
				walk(v.Field(i), depth+1)
			}

		case reflect.String:
			dump.WriteString(v.String())
			dump.WriteByte('\n')

		case reflect.Slice:
			if v.IsNil() {
				return
			}
			if v.Type().Elem().Kind() == reflect.Uint8 {
				for i := 0; i < v.Len(); i++ {
					dump.WriteByte(byte(v.Index(i).Uint()))
				}
				dump.WriteByte('\n')
				return
			}
			for i := 0; i < v.Len(); i++ {
				walk(v.Index(i), depth+1)
			}

		case reflect.Array:
			if v.Type().Elem().Kind() == reflect.Uint8 {
				for i := 0; i < v.Len(); i++ {
					dump.WriteByte(byte(v.Index(i).Uint()))
				}
				dump.WriteByte('\n')
				return
			}
			for i := 0; i < v.Len(); i++ {
				walk(v.Index(i), depth+1)
			}

		case reflect.Map:
			if v.IsNil() {
				return
			}
			iter := v.MapRange()
			for iter.Next() {
				walk(iter.Key(), depth+1)
				walk(iter.Value(), depth+1)
			}
		}
	}

	walk(reflect.ValueOf(rootVal), 0)
	return dump.Bytes()
}

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

func TestServerRootCompromiseZeroLeakageAndActiveAttacks(t *testing.T) {
	// 1. Deploy Primary sns-server + Secondary Remote-Sync sns-server, BOTH under simulated root compromise!
	primaryDir := t.TempDir()
	primaryVaultPath := filepath.Join(primaryDir, "vault.sns")
	primaryBlind, err := vault.NewBlindStore(primaryVaultPath)
	if err != nil {
		t.Fatalf("primary NewBlindStore: %v", err)
	}
	primaryAuth, _ := auth.NewManager(time.Hour, false)
	primaryRelay := relay.NewManager("127.0.0.1:0")
	primarySrv := NewServer(Config{
		DeployMode: "server",
		BlindStore: primaryBlind,
		Auth:       primaryAuth,
		Relay:      primaryRelay,
	})
	defer primarySrv.Close()
	primaryTS, primaryTap := newTappedHTTPServer(t, primarySrv.Handler())
	defer primaryTS.Close()

	secondaryDir := t.TempDir()
	secondaryVaultPath := filepath.Join(secondaryDir, "vault.sns")
	secondaryBlind, err := vault.NewBlindStore(secondaryVaultPath)
	if err != nil {
		t.Fatalf("secondary NewBlindStore: %v", err)
	}
	secondaryAuth, _ := auth.NewManager(time.Hour, false)
	secondaryRelay := relay.NewManager("127.0.0.1:0")
	secondarySrv := NewServer(Config{
		DeployMode: "server",
		BlindStore: secondaryBlind,
		Auth:       secondaryAuth,
		Relay:      secondaryRelay,
	})
	defer secondarySrv.Close()
	secondaryTS, secondaryTap := newTappedHTTPServer(t, secondarySrv.Handler())
	defer secondaryTS.Close()

	// 2. Start Bastion SSH server + Internal CoreDB SSH server (reachable via Bastion ProxyJump)
	var internalAuthorizedKeys sync.Map
	kp, err := sshmanager.GenerateSSHKeyPair("ed25519", "secops-canary@sns", "")
	if err != nil {
		t.Fatalf("GenerateSSHKeyPair: %v", err)
	}
	parsedPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(kp.PublicKey))
	if err != nil {
		t.Fatalf("ParseAuthorizedKey: %v", err)
	}
	internalAuthorizedKeys.Store("ed25519", parsedPub)

	bastionHost, bastionPort, stopBastion := startRootBreachTestSSHServer(t, "jumpops_secret_user", "BastionSSHPass!9988", nil)
	defer stopBastion()

	targetHost, targetPort, stopTarget := startRootBreachTestSSHServer(t, "coredb_secret_admin", "", &internalAuthorizedKeys)
	defer stopTarget()

	// 3. Legitimate Admin connects via Zero-Knowledge Client Engine and executes EVERY sensitive workflow
	adminPass1 := "RootCannotStealThisMasterPass!2026"
	adminPass2 := "RotatedAdminMasterKey!2027"

	client := zkclient.NewEngine(primaryTS.URL, nil)
	client.Vault().SetKDFParams(1, 16*1024, 2)

	if _, err := client.Setup(adminPass1); err != nil {
		t.Fatalf("client.Setup: %v", err)
	}

	// Save Ed25519 private key credential
	privCopy := kp.PrivateKey
	cred, err := client.Vault().CreateCredential(vault.CredentialMutationInput{
		Name:         "Secret-Ed25519-Keychain-Item",
		Kind:         vault.AuthPrivateKey,
		UsernameHint: "coredb_secret_admin",
		PrivateKey:   &privCopy,
		PublicKey:    kp.PublicKey,
		Fingerprint:  kp.Fingerprint,
		KeyAlgorithm: kp.Algorithm,
		Notes:        "TOP_SECRET_CREDENTIAL_NOTES_4411",
	}, "client-zk")
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}

	// Save Bastion & Internal Target servers
	bPass := "BastionSSHPass!9988"
	bastionSrv, err := client.Vault().CreateServer(vault.ServerMutationInput{
		Name:     "Bastion-Alpha-Secret-Node",
		Group:    "核心涉密网关组",
		Tags:     []string{"secret-bastion-tag"},
		Host:     bastionHost,
		Port:     bastionPort,
		Username: "jumpops_secret_user",
		AuthType: vault.AuthPassword,
		Password: &bPass,
		Notes:    "BASTION_INTERNAL_NOTE_5522",
	}, "client-zk")
	if err != nil {
		t.Fatalf("CreateServer bastion: %v", err)
	}

	// Use "localhost" as target host so we can even prove ProxyJump inner target hostname never touches sns-server!
	_ = targetHost
	internalTargetHost := "localhost"
	targetSrv, err := client.Vault().CreateServer(vault.ServerMutationInput{
		Name:         "CoreDB-Master-Secret-Vault",
		Group:        "核心涉密数据库组",
		Tags:         []string{"zero-trust-db"},
		Host:         internalTargetHost,
		Port:         targetPort,
		Username:     "coredb_secret_admin",
		AuthType:     vault.AuthCredential,
		CredentialID: cred.ID,
		JumpServerID: bastionSrv.ID,
		Notes:        "COREDB_PRIVATE_NOTE_6633",
	}, "client-zk")
	if err != nil {
		t.Fatalf("CreateServer target: %v", err)
	}

	// Snapshot disk ciphertext at Revision #4 (for rollback attack test later!)
	rollbackSnapshotBytes, err := os.ReadFile(primaryVaultPath)
	if err != nil {
		t.Fatalf("ReadFile snapshot: %v", err)
	}

	// Create secret Snippet & execute BatchExec over Bastion -> Target
	snip, err := client.Vault().UpsertSnippet(vault.Snippet{
		Title:       "Secret-DB-Audit-Snippet",
		Category:    "绝密巡检",
		Command:     "echo SUPER_SECRET_BATCH_TOKEN_7749",
		Description: "SNIPPET_SECRET_DESC_8800",
	}, "client-zk")
	if err != nil {
		t.Fatalf("UpsertSnippet: %v", err)
	}

	probeRes, err := client.SSH().ProbeServer(targetSrv.ID, "", "client-zk")
	if err != nil || !probeRes.Reachable {
		t.Fatalf("ProbeServer through blind relay + ProxyJump failed: %+v (err=%v)", probeRes, err)
	}

	batchRes := client.SSH().BatchExecute([]string{targetSrv.ID}, snip.Command, 15*time.Second, "client-zk")
	if len(batchRes) != 1 || !batchRes[0].Success || !strings.Contains(batchRes[0].Stdout, "SUPER_SECRET_BATCH_TOKEN_7749") {
		t.Fatalf("BatchExecute failed: %+v", batchRes)
	}

	// Interactive SSH PTY Shell over blind TCP relay
	var ptyOut bytes.Buffer
	var ptyMu sync.Mutex
	ptyDone := make(chan struct{}, 1)
	tsess, _, err := client.SSH().OpenTerminalSession(
		targetSrv.ID,
		100,
		30,
		"",
		"client-zk",
		sshmanager.TerminalCallbacks{
			OnOutput: func(chunk []byte) {
				ptyMu.Lock()
				ptyOut.Write(chunk)
				got := ptyOut.String()
				ptyMu.Unlock()
				if strings.Contains(got, "TERMINAL_PTY_CANARY_8821") {
					select {
					case ptyDone <- struct{}{}:
					default:
					}
				}
			},
			OnExit: func(string) {},
		},
	)
	if err != nil {
		t.Fatalf("OpenTerminalSession: %v", err)
	}
	if err := tsess.WriteInput([]byte("echo TERMINAL_PTY_CANARY_8821\nexit\n")); err != nil {
		t.Fatalf("WriteInput: %v", err)
	}
	select {
	case <-ptyDone:
	case <-time.After(8 * time.Second):
		ptyMu.Lock()
		got := ptyOut.String()
		ptyMu.Unlock()
		t.Fatalf("timed out waiting for PTY canary output, got: %q", got)
	}
	client.SSH().CloseSession(tsess.ID)

	// SFTP Upload + List + Read + Download over blind TCP relay
	sftpRemoteDir := t.TempDir()
	secretFileName := "top_secret_payroll_2026.txt"
	secretFileContent := "CONFIDENTIAL_SFTP_PAYLOAD_991234_DO_NOT_LEAK"
	uploadedPath, _, err := client.SSH().SFTPUpload(
		targetSrv.ID,
		sftpRemoteDir,
		secretFileName,
		strings.NewReader(secretFileContent),
		"client-zk",
	)
	if err != nil {
		t.Fatalf("SFTPUpload: %v", err)
	}
	readBackText, err := client.SSH().SFTPReadText(targetSrv.ID, uploadedPath, "client-zk")
	if err != nil || readBackText != secretFileContent {
		t.Fatalf("SFTPReadText mismatch: got=%q err=%v", readBackText, err)
	}
	dlBytes, dlName, err := client.SSH().SFTPDownloadBytes(targetSrv.ID, uploadedPath, 1024*1024, "client-zk")
	if err != nil || string(dlBytes) != secretFileContent || dlName != secretFileName {
		t.Fatalf("SFTPDownloadBytes mismatch: name=%q bytes=%q err=%v", dlName, string(dlBytes), err)
	}

	// Rotate Master Password (rotates Argon2id salt, DEK, and Ed25519 AuthKeyPair)
	if err := client.ChangePassword(adminPass1, adminPass2); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}

	// Remote Zero-Knowledge Sync: Push to Secondary Server & Pull into a 3rd Client!
	pushSum, err := client.SyncPushToRemote(secondaryTS.URL, "")
	if err != nil || pushSum.Revision == 0 {
		t.Fatalf("SyncPushToRemote: %+v (err=%v)", pushSum, err)
	}

	desktopPullClient := zkclient.NewEngine(secondaryTS.URL, nil)
	desktopPullClient.Vault().SetKDFParams(1, 16*1024, 2)
	// Unlock via challenge-response against secondary server to prove zero-knowledge sync integrity!
	if _, err := desktopPullClient.Unlock(adminPass2); err != nil {
		t.Fatalf("desktopPullClient.Unlock against synced secondary server: %v", err)
	}
	pulledServers, err := desktopPullClient.Vault().ListServers()
	if err != nil || len(pulledServers) != 2 {
		t.Fatalf("expected 2 synced servers on secondary server, got %d (err=%v)", len(pulledServers), err)
	}
	_ = desktopPullClient.Lock()

	// Also capture client's raw AuthPrivateKey seed before locking so we can verify it NEVER leaked to server!
	clientAuthPriv := client.Vault().AuthPrivateKeyCopy()
	if len(clientAuthPriv) != ed25519.PrivateKeySize {
		t.Fatalf("expected 64-byte Ed25519 private key in client while unlocked")
	}
	clientAuthSeed := append([]byte(nil), clientAuthPriv.Seed()...)

	// =========================================================================
	// ROOT COMPROMISE FORENSIC AUDIT: Disk + Wire (HTTP & WS) + Server Heap RAM
	// =========================================================================
	primaryDiskBytes, err := os.ReadFile(primaryVaultPath)
	if err != nil {
		t.Fatalf("ReadFile primary vault.sns: %v", err)
	}
	secondaryDiskBytes, err := os.ReadFile(secondaryVaultPath)
	if err != nil {
		t.Fatalf("ReadFile secondary vault.sns: %v", err)
	}

	primaryHeapDump := inspectGoHeapStringsAndBytes(primarySrv)
	secondaryHeapDump := inspectGoHeapStringsAndBytes(secondarySrv)
	primaryWireBytes := primaryTap.AllBytes()
	secondaryWireBytes := secondaryTap.AllBytes()

	forbiddenStringCanaries := []string{
		adminPass1,
		adminPass2,
		"Secret-Ed25519-Keychain-Item",
		"OPENSSH PRIVATE KEY",
		"secops-canary@sns",
		"TOP_SECRET_CREDENTIAL_NOTES_4411",
		"Bastion-Alpha-Secret-Node",
		"核心涉密网关组",
		"secret-bastion-tag",
		"jumpops_secret_user",
		"BastionSSHPass!9988",
		"BASTION_INTERNAL_NOTE_5522",
		"CoreDB-Master-Secret-Vault",
		"核心涉密数据库组",
		"zero-trust-db",
		"coredb_secret_admin",
		"COREDB_PRIVATE_NOTE_6633",
		fmt.Sprintf("localhost:%d", targetPort), // inner ProxyJump target never even touches sns-server relay!
		"Secret-DB-Audit-Snippet",
		"SUPER_SECRET_BATCH_TOKEN_7749",
		"SNIPPET_SECRET_DESC_8800",
		"TERMINAL_PTY_CANARY_8821",
		secretFileName,
		secretFileContent,
	}

	surfaces := map[string][]byte{
		"primary_disk(/data/vault.sns)":   primaryDiskBytes,
		"secondary_disk(/data/vault.sns)": secondaryDiskBytes,
		"primary_server_heap_structs":     primaryHeapDump,
		"secondary_server_heap_structs":   secondaryHeapDump,
		"primary_raw_tcp_wire_capture":    primaryWireBytes,
		"secondary_raw_tcp_wire_capture":  secondaryWireBytes,
	}

	for surfaceName, data := range surfaces {
		for _, canary := range forbiddenStringCanaries {
			if bytes.Contains(data, []byte(canary)) {
				t.Fatalf("CRITICAL ZERO-KNOWLEDGE BREACH: secret canary %q was found in %s!", canary, surfaceName)
			}
			// Also check standard base64 encoding in case raw JSON/plaintext was base64-encoded without encryption!
			b64Canary := base64.StdEncoding.EncodeToString([]byte(canary))
			if len(b64Canary) >= 12 && bytes.Contains(data, []byte(b64Canary)) {
				t.Fatalf("CRITICAL ZERO-KNOWLEDGE BREACH: base64-encoded canary %q (%s) was found in %s!", canary, b64Canary, surfaceName)
			}
		}
		if bytes.Contains(data, clientAuthSeed) {
			t.Fatalf("CRITICAL ZERO-KNOWLEDGE BREACH: client Ed25519 private key seed leaked into %s!", surfaceName)
		}
	}

	// Lock client before testing active root attacks on unlock/import!
	latestAnchor := client.Vault().GetAnchor()
	if latestAnchor == nil || latestAnchor.MinRevision < 6 {
		t.Fatalf("expected client VaultAnchor to track monotonic revision >= 6, got %+v", latestAnchor)
	}
	_ = client.Lock()

	// =========================================================================
	// ACTIVE ROOT ATTACK #1: Unauthenticated Backup Overwrite Attack -> BLOCKED
	// =========================================================================
	rogueBackend := vault.NewBlindStoreBackend(mustNewTempBlindStore(t))
	rogueCV := vault.NewClientVault(rogueBackend)
	rogueCV.SetKDFParams(1, 16*1024, 2)
	if err := rogueCV.Setup("AttackerRoguePass!123", "attacker"); err != nil {
		t.Fatalf("rogue Setup: %v", err)
	}
	rogueBlob, rogueHdr, err := rogueCV.LastSealedBlob()
	if err != nil {
		t.Fatalf("rogue LastSealedBlob: %v", err)
	}
	roguePriv := rogueCV.AuthPrivateKeyCopy()
	rogueNewSig := vault.SignVaultImport(roguePriv, rogueHdr.VaultID, rogueHdr.Revision, rogueBlob)
	// Attacker signs overwrite with rogue key instead of legitimate admin's current key!
	forgedOverwriteSig := vault.SignVaultImportOverwrite(roguePriv, latestAnchor.VaultID, rogueHdr.VaultID, rogueBlob)
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
		t.Fatalf("SECURITY FAILURE: forged backup overwrite was not rejected with 401! got %d", impRes.StatusCode)
	}

	// =========================================================================
	// ACTIVE ROOT ATTACK #2: Root Rollback Attack on /data/vault.sns -> BLOCKED
	// =========================================================================
	// Root replaces /data/vault.sns with the older Revision #4 snapshot and restarts BlindStore
	if err := os.WriteFile(primaryVaultPath, rollbackSnapshotBytes, 0o600); err != nil {
		t.Fatalf("WriteFile rollback snapshot: %v", err)
	}
	restartedBlind, err := vault.NewBlindStore(primaryVaultPath)
	if err != nil {
		t.Fatalf("restarted NewBlindStore: %v", err)
	}
	primarySrv.cfg.BlindStore = restartedBlind

	anchoredClient := zkclient.NewEngine(primaryTS.URL, nil)
	anchoredClient.Vault().SetKDFParams(1, 16*1024, 2)
	anchoredClient.Vault().SetAnchor(latestAnchor)
	if _, err := anchoredClient.Unlock(adminPass1); !errors.Is(err, vault.ErrRollbackDetected) {
		t.Fatalf("SECURITY FAILURE: client failed to detect root rollback attack! got err=%v", err)
	}

	// =========================================================================
	// ACTIVE ROOT ATTACK #3: Root Substitutes Rogue Vault on Disk -> BLOCKED
	// =========================================================================
	if err := os.WriteFile(primaryVaultPath, rogueBlob, 0o600); err != nil {
		t.Fatalf("WriteFile rogueBlob: %v", err)
	}
	rogueSubstitutedBlind, err := vault.NewBlindStore(primaryVaultPath)
	if err != nil {
		t.Fatalf("rogueSubstitutedBlind: %v", err)
	}
	primarySrv.cfg.BlindStore = rogueSubstitutedBlind

	if _, err := anchoredClient.Unlock(adminPass2); !errors.Is(err, vault.ErrRollbackDetected) {
		t.Fatalf("SECURITY FAILURE: client failed to detect root vault substitution (VaultID mismatch)! got err=%v", err)
	}

	// =========================================================================
	// ACTIVE ROOT ATTACK #4: Root Bit-Flip Ciphertext Tamper -> AEAD REJECTED
	// =========================================================================
	tampered := append([]byte(nil), primaryDiskBytes...)
	tampered[len(tampered)-17] ^= 0xFF
	if err := os.WriteFile(primaryVaultPath, tampered, 0o600); err != nil {
		t.Fatalf("WriteFile tampered: %v", err)
	}
	tamperedBlind, err := vault.NewBlindStore(primaryVaultPath)
	if err != nil {
		t.Fatalf("tamperedBlind: %v", err)
	}
	primarySrv.cfg.BlindStore = tamperedBlind

	freshClient := zkclient.NewEngine(primaryTS.URL, nil)
	freshClient.Vault().SetKDFParams(1, 16*1024, 2)
	if _, err := freshClient.Unlock(adminPass2); !errors.Is(err, vault.ErrCorruptedVault) {
		t.Fatalf("SECURITY FAILURE: tampered ciphertext was not rejected with ErrCorruptedVault! got err=%v", err)
	}

	// =========================================================================
	// ACTIVE ROOT ATTACK #5: Malicious Server KDF Downgrade -> BLOCKED
	// =========================================================================
	downgradeMux := http.NewServeMux()
	downgradeMux.HandleFunc("POST /api/auth/challenge", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"challenge_id": "evil-challenge",
			"nonce":        "0102030405060708090a0b0c0d0e0f10",
			"kdf": map[string]any{
				"vault_id":        latestAnchor.VaultID,
				"revision":        latestAnchor.MinRevision + 1,
				"kdf_algo":        "argon2id",
				"kdf_salt":        base64.StdEncoding.EncodeToString(make([]byte, 32)),
				"kdf_time":        1,
				"kdf_memory_kib":  64, // Maliciously weak 64 KiB KDF!
				"kdf_threads":     1,
				"auth_pubkey_b64": base64.StdEncoding.EncodeToString(make([]byte, 32)),
			},
		})
	})
	evilTS := httptest.NewServer(downgradeMux)
	defer evilTS.Close()

	victimClient := zkclient.NewEngine(evilTS.URL, nil)
	if _, err := victimClient.Unlock(adminPass2); !errors.Is(err, vault.ErrKDFDowngrade) {
		t.Fatalf("SECURITY FAILURE: client did not block malicious server KDF downgrade! got err=%v", err)
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

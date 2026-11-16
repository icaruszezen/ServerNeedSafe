package sshmanager

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// startMockSSHServer starts a real SSHv2 server supporting password + pubkey auth, exec, sftp, and direct-tcpip jump forwarding.
func startMockSSHServer(t *testing.T, expectedUser, expectedPass string, allowedPubKey ssh.PublicKey) (host string, port int, stop func()) {
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
			if c.User() == expectedUser && string(pass) == expectedPass {
				return nil, nil
			}
			return nil, errors.New("bad credentials")
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if allowedPubKey != nil && c.User() == expectedUser && bytes.Equal(key.Marshal(), allowedPubKey.Marshal()) {
				return nil, nil
			}
			return nil, errors.New("bad pubkey")
		},
	}
	cfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleTestSSHConn(conn, cfg)
		}
	}()

	tcpAddr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", tcpAddr.Port, func() { _ = ln.Close() }
}

func handleTestSSHConn(netConn net.Conn, cfg *ssh.ServerConfig) {
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

func TestSSHJumpHostKeygenSFTPAndMITMDetection(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := vault.NewStore(filepath.Join(tmpDir, "vault.sns"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := store.Setup("StrongMasterPass#2026", "127.0.0.1"); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	// Generate Ed25519 SSH key pair
	kp, err := GenerateSSHKeyPair("ed25519", "ops@sns", "")
	if err != nil {
		t.Fatalf("GenerateSSHKeyPair: %v", err)
	}
	parsedPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(kp.PublicKey))
	if err != nil {
		t.Fatalf("ParseAuthorizedKey: %v", err)
	}

	// Start Bastion server (password auth) and Internal Target server (Ed25519 key auth)
	bastionHost, bastionPort, stopBastion := startMockSSHServer(t, "jumpadmin", "JumpPass!123", nil)
	defer stopBastion()

	targetHost, targetPort, stopTarget := startMockSSHServer(t, "root", "unused", parsedPub)
	defer stopTarget()

	pass := "JumpPass!123"
	bastionSrv, err := store.CreateServer(vault.ServerMutationInput{
		Name:     "Bastion-Gateway",
		Group:    "边缘与网关",
		Host:     bastionHost,
		Port:     bastionPort,
		Username: "jumpadmin",
		AuthType: vault.AuthPassword,
		Password: &pass,
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("CreateServer bastion: %v", err)
	}

	cred, err := store.CreateCredential(vault.CredentialMutationInput{
		Name:         "Ed25519-Root-Key",
		Kind:         vault.AuthPrivateKey,
		PrivateKey:   &kp.PrivateKey,
		PublicKey:    kp.PublicKey,
		Fingerprint:  kp.Fingerprint,
		KeyAlgorithm: kp.Algorithm,
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}

	sftpSandbox := filepath.Join(tmpDir, "remote_sftp_dir")
	if err := os.MkdirAll(sftpSandbox, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	internalSrv, err := store.CreateServer(vault.ServerMutationInput{
		Name:         "Internal-Core-App",
		Group:        "生产环境",
		Host:         targetHost,
		Port:         targetPort,
		Username:     "root",
		AuthType:     vault.AuthCredential,
		CredentialID: cred.ID,
		JumpServerID: bastionSrv.ID,
		DefaultPath:  sftpSandbox,
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("CreateServer internal: %v", err)
	}

	mgr := NewManager(store)

	// 1. Test Probe via Bastion Jump Host!
	probeRes, err := mgr.ProbeServer(internalSrv.ID, "", "127.0.0.1")
	if err != nil {
		t.Fatalf("ProbeServer through JumpHost failed: %v", err)
	}
	if !probeRes.Reachable || probeRes.CPUCores < 1 {
		t.Fatalf("unexpected probe result: %+v", probeRes)
	}

	// 2. Test Batch Execute across both servers concurrently
	batchRes := mgr.BatchExecute([]string{bastionSrv.ID, internalSrv.ID}, "echo HELLO_SNS", 0, "127.0.0.1")
	if len(batchRes) != 2 || !batchRes[0].Success || !batchRes[1].Success || !strings.Contains(batchRes[1].Stdout, "HELLO_SNS") {
		t.Fatalf("BatchExecute unexpected results: %+v", batchRes)
	}

	// 3. Test SFTP Operations through Jump Host
	destFile, n, err := mgr.SFTPUpload(internalSrv.ID, sftpSandbox, "app.conf", strings.NewReader("PORT=9000\nMODE=secure\n"), "127.0.0.1")
	if err != nil || n == 0 {
		t.Fatalf("SFTPUpload failed: %v", err)
	}
	readBack, err := mgr.SFTPReadText(internalSrv.ID, destFile, "127.0.0.1")
	if err != nil || !strings.Contains(readBack, "MODE=secure") {
		t.Fatalf("SFTPReadText failed: %v, content=%q", err, readBack)
	}
	if err := mgr.SFTPWriteText(internalSrv.ID, destFile, "PORT=9443\nMODE=strict\n", "127.0.0.1"); err != nil {
		t.Fatalf("SFTPWriteText failed: %v", err)
	}
	subDir := filepath.Join(sftpSandbox, "backups")
	if err := mgr.SFTPMkdir(internalSrv.ID, subDir, "127.0.0.1"); err != nil {
		t.Fatalf("SFTPMkdir failed: %v", err)
	}
	listResp, err := mgr.SFTPList(internalSrv.ID, sftpSandbox, "127.0.0.1")
	if err != nil || len(listResp.Entries) != 2 {
		t.Fatalf("SFTPList unexpected: %+v, err=%v", listResp, err)
	}

	// 4. Test MITM Host Key Mismatch Protection!
	// Tamper with the stored KnownHost fingerprint for internalSrv and verify connection is blocked
	_ = store.TrustKnownHost(vault.KnownHost{
		Address:      fmt.Sprintf("%s:%d", targetHost, targetPort),
		ServerName:   internalSrv.Name,
		KeyType:      "ssh-ed25519",
		Fingerprint:  "SHA256:FakeOldFingerprint000000000",
		PublicKeyB64: "AAAAFake",
	}, "127.0.0.1")

	_, err = mgr.ProbeServer(internalSrv.ID, "", "127.0.0.1")
	var hkErr *HostKeyUntrustedError
	if !errors.As(err, &hkErr) || hkErr.Reason != "mismatch" {
		t.Fatalf("expected HostKeyUntrustedError(mismatch), got: %v", err)
	}

	// Explicitly approve new fingerprint -> connection succeeds again!
	if _, err := mgr.ProbeServer(internalSrv.ID, hkErr.PresentedFingerprint, "127.0.0.1"); err != nil {
		t.Fatalf("ProbeServer with explicit TrustFingerprint failed: %v", err)
	}
}

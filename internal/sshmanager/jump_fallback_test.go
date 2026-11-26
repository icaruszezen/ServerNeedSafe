package sshmanager

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
	"golang.org/x/crypto/ssh"
)

func boolPtr(b bool) *bool { return &b }

// controllableMockSSHServer tracks connection counts and allows forcefully killing all live TCP conns.
type controllableMockSSHServer struct {
	host      string
	port      int
	ln        net.Listener
	mu        sync.Mutex
	conns     map[net.Conn]struct{}
	connCount atomic.Int32
}

func startControllableMockSSHServer(t *testing.T, expectedUser, expectedPass string) *controllableMockSSHServer {
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
	}
	cfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	s := &controllableMockSSHServer{
		host:  "127.0.0.1",
		port:  ln.Addr().(*net.TCPAddr).Port,
		ln:    ln,
		conns: make(map[net.Conn]struct{}),
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			s.connCount.Add(1)
			s.mu.Lock()
			s.conns[conn] = struct{}{}
			s.mu.Unlock()
			go func(c net.Conn) {
				defer func() {
					s.mu.Lock()
					delete(s.conns, c)
					s.mu.Unlock()
				}()
				handleControllableSSHConn(c, cfg)
			}(conn)
		}
	}()

	return s
}

func (s *controllableMockSSHServer) StopAll() {
	_ = s.ln.Close()
	s.mu.Lock()
	for c := range s.conns {
		_ = c.Close()
	}
	clear(s.conns)
	s.mu.Unlock()
}

// handleControllableSSHConn supports direct-tcpip, exec, and interactive shell with immediate exit-status reporting.
func handleControllableSSHConn(netConn net.Conn, cfg *ssh.ServerConfig) {
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
						stdinPipe, pipeErr := cmd.StdinPipe()
						if pipeErr != nil {
							_ = ch.Close()
							return
						}
						cmd.Stdout = ch
						cmd.Stderr = ch.Stderr()
						if startErr := cmd.Start(); startErr != nil {
							_ = stdinPipe.Close()
							_ = ch.Close()
							return
						}
						go func() {
							_, _ = io.Copy(stdinPipe, ch)
							_ = stdinPipe.Close()
						}()
						exitStatus := uint32(0)
						if waitErr := cmd.Wait(); waitErr != nil {
							var ee *exec.ExitError
							if errors.As(waitErr, &ee) {
								exitStatus = uint32(ee.ExitCode())
							} else {
								exitStatus = 1
							}
						}
						_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: exitStatus}))
						_ = ch.Close()
						return
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

func unusedLocalPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen unused port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func setupFallbackTestEnv(t *testing.T) (*vault.Store, *Manager) {
	t.Helper()
	tmpDir := t.TempDir()
	store, err := vault.NewStore(filepath.Join(tmpDir, "data"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(store.Close)
	store.SetFlushDebounce(20 * time.Millisecond)
	if err := store.Setup("StrongMasterPass#2026", "127.0.0.1"); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	mgr := NewManager(store)
	mgr.SetJumpCooldownTTL(250 * time.Millisecond)
	mgr.SetFallbackHopTimeout(3 * time.Second)
	return store, mgr
}

func TestMultiJumpFallbackCooldownAndDirectFallback(t *testing.T) {
	store, mgr := setupFallbackTestEnv(t)

	deadPort := unusedLocalPort(t)
	j2SrvMock := startControllableMockSSHServer(t, "jump2", "PassJump2!")
	defer j2SrvMock.StopAll()
	targetMock := startControllableMockSSHServer(t, "root", "TargetPass!")
	defer targetMock.StopAll()

	p1 := "PassJump1!"
	p2 := "PassJump2!"
	pt := "TargetPass!"

	j1, err := store.CreateServer(vault.ServerMutationInput{
		Name:     "Jump-HK",
		Group:    "边缘与网关",
		Host:     "127.0.0.1",
		Port:     deadPort,
		Username: "jump1",
		AuthType: vault.AuthPassword,
		Password: &p1,
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("create j1: %v", err)
	}

	j2, err := store.CreateServer(vault.ServerMutationInput{
		Name:     "Jump-SG",
		Group:    "边缘与网关",
		Host:     j2SrvMock.host,
		Port:     j2SrvMock.port,
		Username: "jump2",
		AuthType: vault.AuthPassword,
		Password: &p2,
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("create j2: %v", err)
	}

	target, err := store.CreateServer(vault.ServerMutationInput{
		Name:               "US-App",
		Group:              "生产环境",
		Host:               targetMock.host,
		Port:               targetMock.port,
		Username:           "root",
		AuthType:           vault.AuthPassword,
		Password:           &pt,
		JumpServerIDs:      []string{j1.ID, j2.ID},
		JumpFallbackDirect: boolPtr(false),
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("create target: %v", err)
	}

	// 1. First dial: j1 fails -> falls back to j2 with progress events
	var stages []string
	c1, err := mgr.Dial(target.ID, DialOptions{
		ClientIP: "127.0.0.1",
		OnProgress: func(ev DialProgressEvent) {
			stages = append(stages, ev.Stage+":"+ev.Message)
		},
	})
	if err != nil {
		t.Fatalf("expected fallback dial via j2 to succeed, got: %v", err)
	}
	defer c1.Close()

	if c1.Route.Direct || !c1.Route.FallbackUsed {
		t.Fatalf("expected fallback jump route, got: %+v", c1.Route)
	}
	if !slices.Equal(c1.Route.JumpServerNames, []string{"Jump-SG"}) {
		t.Fatalf("expected Jump-SG, got: %+v", c1.Route)
	}
	if !slices.Equal(c1.Route.SkippedJumps, []string{"Jump-HK"}) {
		t.Fatalf("expected skipped Jump-HK, got: %+v", c1.Route)
	}
	if !strings.Contains(c1.Route.Label, "Jump-SG") || !strings.Contains(c1.Route.Label, "已退避") {
		t.Fatalf("unexpected route label: %q", c1.Route.Label)
	}
	if !slices.ContainsFunc(stages, func(s string) bool { return strings.HasPrefix(s, "failed:") }) {
		t.Fatalf("expected failed progress event, got: %v", stages)
	}

	// 2. Second dial immediately within cooldown: j1 must be skipped (stage "skipped")
	var stages2 []string
	c2, err := mgr.Dial(target.ID, DialOptions{
		ClientIP: "127.0.0.1",
		OnProgress: func(ev DialProgressEvent) {
			stages2 = append(stages2, ev.Stage+":"+ev.Message)
		},
	})
	if err != nil {
		t.Fatalf("cooldown dial failed: %v", err)
	}
	c2.Close()
	if !slices.ContainsFunc(stages2, func(s string) bool { return strings.HasPrefix(s, "skipped:") && strings.Contains(s, "Jump-HK") }) {
		t.Fatalf("expected Jump-HK to be skipped during cooldown, got: %v", stages2)
	}

	// 3. Bring j1 online, wait for cooldown expiry -> automatically recovers primary j1!
	j1Recovered := startControllableMockSSHServer(t, "jump1", "PassJump1!")
	defer j1Recovered.StopAll()
	if _, err := store.UpdateServer(j1.ID, vault.ServerMutationInput{
		Name:     j1.Name,
		Group:    j1.Group,
		Host:     j1Recovered.host,
		Port:     j1Recovered.port,
		Username: j1.Username,
		AuthType: vault.AuthPassword,
	}, "127.0.0.1"); err != nil {
		t.Fatalf("update j1 port: %v", err)
	}
	time.Sleep(300 * time.Millisecond)

	c3, err := mgr.Dial(target.ID, DialOptions{ClientIP: "127.0.0.1"})
	if err != nil {
		t.Fatalf("recovery dial failed: %v", err)
	}
	c3.Close()
	if c3.Route.FallbackUsed || !slices.Equal(c3.Route.JumpServerNames, []string{"Jump-HK"}) {
		t.Fatalf("expected primary Jump-HK recovery without fallback, got: %+v", c3.Route)
	}

	// 4. Kill BOTH jump hosts -> without direct fallback, Dial fails with aggregated error
	j1Recovered.StopAll()
	j2SrvMock.StopAll()
	if _, err := mgr.Dial(target.ID, DialOptions{ClientIP: "127.0.0.1"}); err == nil {
		t.Fatalf("expected error when all jump hosts down and direct fallback disabled")
	} else if !strings.Contains(err.Error(), "Jump-HK") || !strings.Contains(err.Error(), "Jump-SG") {
		t.Fatalf("expected aggregated error mentioning both jumps, got: %v", err)
	}

	// 5. Enable JumpFallbackDirect -> ProbeServer succeeds directly with route metadata
	if _, err := store.UpdateServer(target.ID, vault.ServerMutationInput{
		Name:               target.Name,
		Group:              target.Group,
		Host:               target.Host,
		Port:               target.Port,
		Username:           target.Username,
		AuthType:           vault.AuthPassword,
		JumpServerIDs:      []string{j1.ID, j2.ID},
		JumpFallbackDirect: boolPtr(true),
	}, "127.0.0.1"); err != nil {
		t.Fatalf("enable direct fallback: %v", err)
	}

	probeRes, err := mgr.ProbeServer(target.ID, "", "127.0.0.1")
	if err != nil {
		t.Fatalf("expected ProbeServer direct fallback to succeed, got: %v", err)
	}
	if !probeRes.Reachable || !probeRes.RouteFallback || probeRes.RouteLabel != "直连 (跳板退避)" {
		t.Fatalf("unexpected probe route metadata: %+v", probeRes)
	}
}

func TestFallbackSecurityBoundariesAndDiamondDAG(t *testing.T) {
	store, mgr := setupFallbackTestEnv(t)

	outerMock := startControllableMockSSHServer(t, "outer", "OuterPass!")
	defer outerMock.StopAll()
	j1Mock := startControllableMockSSHServer(t, "jump1", "Jump1Pass!")
	defer j1Mock.StopAll()
	j2Mock := startControllableMockSSHServer(t, "jump2", "Jump2Pass!")
	defer j2Mock.StopAll()
	targetMock := startControllableMockSSHServer(t, "root", "RightPass!")
	defer targetMock.StopAll()

	pOuter := "OuterPass!"
	p1 := "Jump1Pass!"
	p2 := "Jump2Pass!"
	pWrong := "WrongTargetPass!"
	pRight := "RightPass!"

	outer, err := store.CreateServer(vault.ServerMutationInput{
		Name: "Outer", Group: "网关", Host: outerMock.host, Port: outerMock.port,
		Username: "outer", AuthType: vault.AuthPassword, Password: &pOuter,
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("create outer: %v", err)
	}
	j1, err := store.CreateServer(vault.ServerMutationInput{
		Name: "Jump-1", Group: "网关", Host: j1Mock.host, Port: j1Mock.port,
		Username: "jump1", AuthType: vault.AuthPassword, Password: &p1,
		JumpServerIDs: []string{outer.ID},
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("create j1: %v", err)
	}
	j2, err := store.CreateServer(vault.ServerMutationInput{
		Name: "Jump-2", Group: "网关", Host: j2Mock.host, Port: j2Mock.port,
		Username: "jump2", AuthType: vault.AuthPassword, Password: &p2,
		JumpServerIDs: []string{outer.ID},
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("create j2: %v", err)
	}

	// 1. Target explicit auth failure must stop immediately and NOT touch Jump-2
	badAuthTarget, err := store.CreateServer(vault.ServerMutationInput{
		Name: "AuthFail-Target", Group: "生产", Host: targetMock.host, Port: targetMock.port,
		Username: "root", AuthType: vault.AuthPassword, Password: &pWrong,
		JumpServerIDs: []string{j1.ID, j2.ID}, JumpFallbackDirect: boolPtr(true),
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("create badAuthTarget: %v", err)
	}
	_, err = mgr.Dial(badAuthTarget.ID, DialOptions{ClientIP: "127.0.0.1"})
	if err == nil {
		t.Fatalf("expected target auth failure")
	}
	if j2Mock.connCount.Load() != 0 {
		t.Fatalf("target auth failure must NOT retry Jump-2, got %d conns on j2", j2Mock.connCount.Load())
	}

	// 2. Target HostKey mismatch must stop immediately and return *HostKeyUntrustedError without trying Jump-2
	goodTarget, err := store.CreateServer(vault.ServerMutationInput{
		Name: "Good-Target", Group: "生产", Host: targetMock.host, Port: targetMock.port,
		Username: "root", AuthType: vault.AuthPassword, Password: &pRight,
		JumpServerIDs: []string{j1.ID, j2.ID}, JumpFallbackDirect: boolPtr(true),
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("create goodTarget: %v", err)
	}

	// Poison target KnownHost fingerprint
	_ = store.TrustKnownHost(vault.KnownHost{
		Address:      net.JoinHostPort(targetMock.host, strconv.Itoa(targetMock.port)),
		ServerName:   goodTarget.Name,
		KeyType:      "ssh-ed25519",
		Fingerprint:  "SHA256:TamperedTargetFP",
		PublicKeyB64: "AAAA",
	}, "127.0.0.1")

	_, err = mgr.Dial(goodTarget.ID, DialOptions{ClientIP: "127.0.0.1"})
	var hkErr *HostKeyUntrustedError
	if !errors.As(err, &hkErr) || hkErr.Reason != "mismatch" {
		t.Fatalf("expected target HostKeyUntrustedError(mismatch), got: %v", err)
	}
	if j2Mock.connCount.Load() != 0 {
		t.Fatalf("target host key mismatch must NOT retry Jump-2, got %d conns on j2", j2Mock.connCount.Load())
	}

	// Fix target KnownHost, poison Jump-1 KnownHost -> Jump-1 HostKey mismatch falls back to Jump-2 (and Diamond DAG Outer -> Jump-2 works!)
	_ = store.DeleteKnownHost(net.JoinHostPort(targetMock.host, strconv.Itoa(targetMock.port)), "127.0.0.1")
	_ = store.TrustKnownHost(vault.KnownHost{
		Address:      net.JoinHostPort(j1Mock.host, strconv.Itoa(j1Mock.port)),
		ServerName:   j1.Name,
		KeyType:      "ssh-ed25519",
		Fingerprint:  "SHA256:TamperedJump1FP",
		PublicKeyB64: "AAAA",
	}, "127.0.0.1")

	c, err := mgr.Dial(goodTarget.ID, DialOptions{ClientIP: "127.0.0.1"})
	if err != nil {
		t.Fatalf("expected Jump-1 host key mismatch to fall back to diamond Jump-2 -> Outer, got: %v", err)
	}
	defer c.Close()

	if !c.Route.FallbackUsed || !slices.Equal(c.Route.JumpServerNames, []string{"Outer", "Jump-2"}) {
		t.Fatalf("expected diamond route Outer -> Jump-2 with fallback, got: %+v", c.Route)
	}
}

func TestTerminalAbnormalJumpDropTriggersAutoReconnectAndCooldown(t *testing.T) {
	store, mgr := setupFallbackTestEnv(t)
	mgr.SetJumpCooldownTTL(5 * time.Second)

	j1Mock := startControllableMockSSHServer(t, "jump1", "Pass1!")
	defer j1Mock.StopAll()
	j2Mock := startControllableMockSSHServer(t, "jump2", "Pass2!")
	defer j2Mock.StopAll()
	targetMock := startControllableMockSSHServer(t, "root", "TargetPass!")
	defer targetMock.StopAll()

	p1, p2, pt := "Pass1!", "Pass2!", "TargetPass!"
	j1, _ := store.CreateServer(vault.ServerMutationInput{
		Name: "Jump-1", Group: "网关", Host: j1Mock.host, Port: j1Mock.port,
		Username: "jump1", AuthType: vault.AuthPassword, Password: &p1,
	}, "127.0.0.1")
	j2, _ := store.CreateServer(vault.ServerMutationInput{
		Name: "Jump-2", Group: "网关", Host: j2Mock.host, Port: j2Mock.port,
		Username: "jump2", AuthType: vault.AuthPassword, Password: &p2,
	}, "127.0.0.1")
	target, _ := store.CreateServer(vault.ServerMutationInput{
		Name: "Overseas-Box", Group: "生产", Host: targetMock.host, Port: targetMock.port,
		Username: "root", AuthType: vault.AuthPassword, Password: &pt,
		JumpServerIDs: []string{j1.ID, j2.ID}, JumpFallbackDirect: boolPtr(false),
	}, "127.0.0.1")

	// 1. Normal non-zero shell exit (exit 1) must NOT trigger auto_reconnect
	normalExitCh := make(chan TerminalExitEvent, 1)
	ts1, ready1, err := mgr.OpenTerminalSession(target.ID, 80, 24, "", "127.0.0.1", TerminalCallbacks{
		OnExitDetail: func(ev TerminalExitEvent) {
			normalExitCh <- ev
		},
	})
	if err != nil {
		t.Fatalf("OpenTerminalSession 1: %v", err)
	}
	if !slices.Equal(ready1.Route.JumpServerNames, []string{"Jump-1"}) {
		t.Fatalf("expected initial route via Jump-1, got: %+v", ready1.Route)
	}
	_ = ts1.WriteInput([]byte("exit 1\n"))
	select {
	case ev := <-normalExitCh:
		if ev.Abnormal || ev.AutoReconnect {
			t.Fatalf("expected normal exit with AutoReconnect=false, got: %+v", ev)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for normal shell exit")
	}

	// 2. Abnormal jump drop mid-session MUST emit AutoReconnect=true and place Jump-1 in cooldown
	dropExitCh := make(chan TerminalExitEvent, 1)
	ts2, _, err := mgr.OpenTerminalSession(target.ID, 80, 24, "", "127.0.0.1", TerminalCallbacks{
		OnExitDetail: func(ev TerminalExitEvent) {
			dropExitCh <- ev
		},
	})
	if err != nil {
		t.Fatalf("OpenTerminalSession 2: %v", err)
	}
	defer ts2.Close()

	// Kill Jump-1 abruptly
	j1Mock.StopAll()

	select {
	case ev := <-dropExitCh:
		if !ev.Abnormal || !ev.AutoReconnect {
			t.Fatalf("expected Abnormal=true and AutoReconnect=true on jump drop, got: %+v", ev)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for abnormal jump drop exit event")
	}

	// Immediately reconnect -> Jump-1 is in cooldown, routes straight through Jump-2
	ts3, ready3, err := mgr.OpenTerminalSession(target.ID, 80, 24, "", "127.0.0.1", TerminalCallbacks{})
	if err != nil {
		t.Fatalf("OpenTerminalSession reconnect: %v", err)
	}
	defer ts3.Close()
	if !ready3.Route.FallbackUsed || !slices.Equal(ready3.Route.JumpServerNames, []string{"Jump-2"}) {
		t.Fatalf("expected auto-reconnect to route via Jump-2, got: %+v", ready3.Route)
	}
}

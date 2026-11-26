package sshmanager

import (
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
	"golang.org/x/crypto/ssh"
)

// TerminalReadyInfo contains connection metadata once the end-to-end SSH PTY is established.
type TerminalReadyInfo struct {
	SessionID   string        `json:"session_id"`
	ServerID    string        `json:"server_id"`
	ServerName  string        `json:"server_name"`
	Fingerprint string        `json:"fingerprint"`
	LatencyMs   int64         `json:"latency_ms"`
	Route       DialRouteInfo `json:"route"`
}

// TerminalExitEvent describes how an interactive terminal session ended.
type TerminalExitEvent struct {
	Message       string `json:"message"`
	Abnormal      bool   `json:"abnormal,omitempty"`
	AutoReconnect bool   `json:"auto_reconnect,omitempty"`
}

// TerminalCallbacks streams PTY output and lifecycle events directly to the caller (e.g. WebSocket -> xterm.js).
type TerminalCallbacks struct {
	OnProgress   func(ev DialProgressEvent)
	OnOutput     func(chunk []byte)
	OnExit       func(message string)
	OnExitDetail func(ev TerminalExitEvent)
}

// TerminalSession represents a live interactive client-side SSH PTY session.
type TerminalSession struct {
	ID         string
	ServerID   string
	ServerName string
	StartedAt  time.Time
	client     *ManagedSSHClient
	sshSession *ssh.Session
	stdinPipe  io.WriteCloser
	writeMu    sync.Mutex
	callbacks  TerminalCallbacks
	closing    atomic.Bool
	exited     atomic.Bool
	closeOnce  sync.Once
	exitOnce   sync.Once
	done       chan struct{}
}

func (ts *TerminalSession) emitExit(msg string) {
	ts.emitExitEvent(TerminalExitEvent{Message: msg})
}

func (ts *TerminalSession) emitExitEvent(ev TerminalExitEvent) {
	ts.exitOnce.Do(func() {
		ts.exited.Store(true)
		if ts.callbacks.OnExitDetail != nil {
			ts.callbacks.OnExitDetail(ev)
			return
		}
		if ts.callbacks.OnExit != nil {
			ts.callbacks.OnExit(ev.Message)
		}
	})
}

// WriteInput writes raw user keystrokes into the encrypted SSH PTY stdin stream.
func (ts *TerminalSession) WriteInput(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	ts.writeMu.Lock()
	defer ts.writeMu.Unlock()
	if ts.stdinPipe == nil {
		return io.ErrClosedPipe
	}
	_, err := ts.stdinPipe.Write(data)
	return err
}

// Resize updates remote PTY dimensions.
func (ts *TerminalSession) Resize(cols, rows int) error {
	if cols <= 0 || rows <= 0 || cols > 500 || rows > 300 {
		return nil
	}
	if ts.sshSession == nil {
		return nil
	}
	return ts.sshSession.WindowChange(rows, cols)
}

// Close terminates the SSH PTY session and underlying tunnel cleanly.
func (ts *TerminalSession) Close() {
	ts.closing.Store(true)
	ts.closeOnce.Do(func() {
		close(ts.done)
		if ts.stdinPipe != nil {
			_ = ts.stdinPipe.Close()
		}
		if ts.sshSession != nil {
			_ = ts.sshSession.Close()
		}
		if ts.client != nil {
			_ = ts.client.Close()
		}
	})
}

// ActiveSessionSummary describes an open interactive SSH terminal session.
type ActiveSessionSummary struct {
	ID         string    `json:"id"`
	ServerID   string    `json:"server_id"`
	ServerName string    `json:"server_name"`
	StartedAt  time.Time `json:"started_at"`
}

// ListActiveSessions returns metadata on currently active SSH PTY sessions.
func (m *Manager) ListActiveSessions() []ActiveSessionSummary {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]ActiveSessionSummary, 0, len(m.activeSessions))
	for _, s := range m.activeSessions {
		out = append(out, ActiveSessionSummary{
			ID:         s.ID,
			ServerID:   s.ServerID,
			ServerName: s.ServerName,
			StartedAt:  s.StartedAt,
		})
	}
	return out
}

// GetSession looks up an active PTY session by ID.
func (m *Manager) GetSession(sessionID string) *TerminalSession {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.activeSessions[sessionID]
}

// CloseSession closes a specific active PTY session by ID.
func (m *Manager) CloseSession(sessionID string) {
	m.mu.Lock()
	s, ok := m.activeSessions[sessionID]
	if ok {
		delete(m.activeSessions, sessionID)
	}
	m.mu.Unlock()
	if ok && s != nil {
		s.Close()
	}
}

// CloseAllSessions immediately closes all active interactive SSH connections (e.g. on Vault Lock).
func (m *Manager) CloseAllSessions() {
	m.mu.Lock()
	sessions := make([]*TerminalSession, 0, len(m.activeSessions))
	for _, s := range m.activeSessions {
		sessions = append(sessions, s)
	}
	clear(m.activeSessions)
	m.mu.Unlock()

	for _, s := range sessions {
		s.closing.Store(true)
		s.emitExit("加密保险库已锁定，所有活跃 SSH 会话已安全断开")
		s.Close()
	}
}

func (m *Manager) handleAbnormalSessionDrop(client *ManagedSSHClient) bool {
	if client == nil || client.ImmediateJumpID == "" {
		return false
	}
	if !client.IsImmediateJumpAlive(1500 * time.Millisecond) {
		m.MarkJumpNodeFailed(client.ImmediateJumpID)
	} else if client.Server != nil {
		m.MarkJumpEdgeFailed(client.ImmediateJumpID, client.Server.ID)
	}
	return client.HasAlternateRoutes
}

// OpenTerminalSession dials the target SSH server end-to-end, allocates a PTY, and starts streaming output callbacks.
func (m *Manager) OpenTerminalSession(
	serverID string,
	cols, rows int,
	trustFingerprint, clientIP string,
	callbacks TerminalCallbacks,
) (*TerminalSession, *TerminalReadyInfo, error) {
	if cols <= 0 || cols > 500 {
		cols = 120
	}
	if rows <= 0 || rows > 300 {
		rows = 34
	}

	startDial := time.Now()
	client, err := m.Dial(serverID, DialOptions{
		TrustFingerprint: trustFingerprint,
		ClientIP:         clientIP,
		OnProgress:       callbacks.OnProgress,
	})
	if err != nil {
		m.store.RecordAudit("ssh.connect_failed", serverID, err.Error(), clientIP, false)
		return nil, nil, err
	}
	latencyMs := time.Since(startDial).Milliseconds()
	if latencyMs <= 0 {
		latencyMs = 1
	}

	sshSess, err := client.NewSession()
	if err != nil {
		_ = client.Close()
		return nil, nil, fmt.Errorf("创建 SSH 会话通道失败: %w", err)
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 115200,
		ssh.TTY_OP_OSPEED: 115200,
	}
	if err := sshSess.RequestPty("xterm-256color", rows, cols, modes); err != nil {
		_ = sshSess.Close()
		_ = client.Close()
		return nil, nil, fmt.Errorf("分配远程伪终端 (PTY) 失败: %w", err)
	}

	stdinPipe, err := sshSess.StdinPipe()
	if err != nil {
		_ = sshSess.Close()
		_ = client.Close()
		return nil, nil, err
	}
	stdoutPipe, err := sshSess.StdoutPipe()
	if err != nil {
		_ = sshSess.Close()
		_ = client.Close()
		return nil, nil, err
	}
	stderrPipe, err := sshSess.StderrPipe()
	if err != nil {
		_ = sshSess.Close()
		_ = client.Close()
		return nil, nil, err
	}

	if err := sshSess.Shell(); err != nil {
		_ = sshSess.Close()
		_ = client.Close()
		return nil, nil, fmt.Errorf("启动远程交互式 Shell 失败: %w", err)
	}

	ts := &TerminalSession{
		ID:         uuid.NewString(),
		ServerID:   serverID,
		ServerName: client.Server.Name,
		StartedAt:  time.Now().UTC(),
		client:     client,
		sshSession: sshSess,
		stdinPipe:  stdinPipe,
		callbacks:  callbacks,
		done:       make(chan struct{}),
	}

	if client.Server.DefaultPath != "" {
		_ = ts.WriteInput([]byte(fmt.Sprintf("cd %q 2>/dev/null && clear\n", client.Server.DefaultPath)))
	}

	m.mu.Lock()
	m.activeSessions[ts.ID] = ts
	m.mu.Unlock()

	m.store.UpdateServerRuntimeMeta(serverID, latencyMs, "", true)
	m.store.RecordAudit(
		"ssh.connect",
		fmt.Sprintf("%s (%s:%d)", client.Server.Name, client.Server.Host, client.Server.Port),
		fmt.Sprintf("建立端到端加密 SSH 终端连接 (%s · 延迟 %dms)", client.Route.Label, latencyMs),
		clientIP,
		true,
	)

	ready := &TerminalReadyInfo{
		SessionID:   ts.ID,
		ServerID:    serverID,
		ServerName:  client.Server.Name,
		Fingerprint: client.Fingerprint,
		LatencyMs:   latencyMs,
		Route:       client.Route,
	}

	streamPipe := func(r io.Reader) {
		buf := make([]byte, 16*1024)
		defer vault.ZeroBytes(buf)
		for {
			n, readErr := r.Read(buf)
			if n > 0 && ts.callbacks.OnOutput != nil {
				chunk := slices.Clone(buf[:n])
				ts.callbacks.OnOutput(chunk)
			}
			if readErr != nil {
				return
			}
		}
	}
	go streamPipe(stdoutPipe)
	go streamPipe(stderrPipe)

	// Wait for remote shell exit and clean up registry
	go func() {
		waitErr := sshSess.Wait()
		localClosing := ts.closing.Load()
		alreadyExited := ts.exited.Load()

		ev := TerminalExitEvent{Message: "远程 Shell 会话已正常退出"}
		if waitErr != nil {
			var exitErr *ssh.ExitError
			if errors.As(waitErr, &exitErr) {
				ev.Message = fmt.Sprintf("远程 Shell 会话已退出 (退出码 %d)", exitErr.ExitStatus())
			} else if !localClosing && !alreadyExited {
				ev.Abnormal = true
				ev.AutoReconnect = m.handleAbnormalSessionDrop(client)
				if ev.AutoReconnect {
					ev.Message = fmt.Sprintf("当前跳板链路连接异常中断 (%v)，正在自动切换备用链路重连", waitErr)
				} else {
					ev.Message = fmt.Sprintf("远程连接已断开: %v", waitErr)
				}
			} else {
				ev.Message = fmt.Sprintf("远程连接已断开: %v", waitErr)
			}
		}

		m.mu.Lock()
		delete(m.activeSessions, ts.ID)
		m.mu.Unlock()
		ts.emitExitEvent(ev)
		ts.Close()
		m.store.RecordAudit("ssh.disconnect", fmt.Sprintf("%s (%s:%d)", client.Server.Name, client.Server.Host, client.Server.Port), "SSH 终端会话结束", clientIP, true)
	}()

	// SSH KeepAlive goroutine
	keepAliveSec := client.Server.KeepAliveSec
	if keepAliveSec <= 0 {
		keepAliveSec = 30
	}
	go func() {
		ticker := time.NewTicker(time.Duration(keepAliveSec) * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ts.done:
				return
			case <-ticker.C:
				if _, _, err := client.SendRequest("keepalive@openssh.com", true, nil); err != nil {
					if ts.closing.Load() || ts.exited.Load() {
						return
					}
					autoReconnect := m.handleAbnormalSessionDrop(client)
					msg := "SSH KeepAlive 检测超时，连接已断开"
					if autoReconnect {
						msg = "SSH KeepAlive 检测超时（当前跳板链路中断），正在自动切换备用链路重连"
					}
					ts.emitExitEvent(TerminalExitEvent{
						Message:       msg,
						Abnormal:      true,
						AutoReconnect: autoReconnect,
					})
					m.CloseSession(ts.ID)
					return
				}
			}
		}
	}()

	return ts, ready, nil
}

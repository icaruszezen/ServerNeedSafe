package sshmanager

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

type wsIncomingMsg struct {
	Type    string `json:"type"`               // "input", "resize", "ping"
	Data    string `json:"data,omitempty"`     // UTF-8 keystrokes
	DataB64 string `json:"data_b64,omitempty"` // optional raw bytes
	Cols    int    `json:"cols,omitempty"`
	Rows    int    `json:"rows,omitempty"`
}

type wsOutgoingMsg struct {
	Type        string      `json:"type"` // "ready", "output", "error", "exit", "pong"
	SessionID   string      `json:"session_id,omitempty"`
	ServerName  string      `json:"server_name,omitempty"`
	Fingerprint string      `json:"fingerprint,omitempty"`
	LatencyMs   int64       `json:"latency_ms,omitempty"`
	DataB64     string      `json:"data_b64,omitempty"`
	Message     string      `json:"message,omitempty"`
	Code        string      `json:"code,omitempty"`
	HostKeyInfo interface{} `json:"host_key_info,omitempty"`
}

// TerminalSession represents a live interactive SSH PTY session bridged to a WebSocket.
type TerminalSession struct {
	ID         string
	ServerID   string
	ServerName string
	StartedAt  time.Time
	client     *ManagedSSHClient
	sshSession *ssh.Session
	ws         *websocket.Conn
	wsWriteMu  sync.Mutex
	closeOnce  sync.Once
	done       chan struct{}
}

func (ts *TerminalSession) sendJSON(msg wsOutgoingMsg) error {
	ts.wsWriteMu.Lock()
	defer ts.wsWriteMu.Unlock()
	_ = ts.ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return ts.ws.WriteJSON(msg)
}

func (ts *TerminalSession) Close() {
	ts.closeOnce.Do(func() {
		close(ts.done)
		if ts.sshSession != nil {
			_ = ts.sshSession.Close()
		}
		if ts.client != nil {
			_ = ts.client.Close()
		}
		if ts.ws != nil {
			_ = ts.ws.Close()
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
		_ = s.sendJSON(wsOutgoingMsg{
			Type:    "exit",
			Message: "加密保险库已锁定，所有活跃 SSH 会话已安全断开",
		})
		s.Close()
	}
}

// ServeWebSocketTerminal dials the target SSH server, allocates a PTY, and bridges I/O over ws.
func (m *Manager) ServeWebSocketTerminal(ws *websocket.Conn, serverID string, cols, rows int, trustFingerprint, clientIP string) {
	if cols <= 0 || cols > 500 {
		cols = 120
	}
	if rows <= 0 || rows > 300 {
		rows = 34
	}

	ts := &TerminalSession{
		ID:        uuid.NewString(),
		ServerID:  serverID,
		StartedAt: time.Now().UTC(),
		ws:        ws,
		done:      make(chan struct{}),
	}

	startDial := time.Now()
	client, err := m.Dial(serverID, DialOptions{
		TrustFingerprint: trustFingerprint,
		ClientIP:         clientIP,
	})
	if err != nil {
		if hkErr, ok := err.(*HostKeyUntrustedError); ok {
			_ = ts.sendJSON(wsOutgoingMsg{
				Type:        "error",
				Code:        "HOST_KEY_UNTRUSTED",
				Message:     hkErr.Error(),
				HostKeyInfo: hkErr,
			})
		} else {
			_ = ts.sendJSON(wsOutgoingMsg{
				Type:    "error",
				Code:    "DIAL_FAILED",
				Message: err.Error(),
			})
		}
		m.store.RecordAudit("ssh.connect_failed", serverID, err.Error(), clientIP, false)
		_ = ws.Close()
		return
	}
	latencyMs := time.Since(startDial).Milliseconds()
	if latencyMs <= 0 {
		latencyMs = 1
	}

	ts.client = client
	ts.ServerName = client.Server.Name

	sshSess, err := client.NewSession()
	if err != nil {
		_ = ts.sendJSON(wsOutgoingMsg{
			Type:    "error",
			Code:    "SESSION_FAILED",
			Message: fmt.Sprintf("创建 SSH 会话通道失败: %v", err),
		})
		ts.Close()
		return
	}
	ts.sshSession = sshSess

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 115200,
		ssh.TTY_OP_OSPEED: 115200,
	}
	if err := sshSess.RequestPty("xterm-256color", rows, cols, modes); err != nil {
		_ = ts.sendJSON(wsOutgoingMsg{
			Type:    "error",
			Code:    "PTY_FAILED",
			Message: fmt.Sprintf("分配远程伪终端 (PTY) 失败: %v", err),
		})
		ts.Close()
		return
	}

	stdinPipe, err := sshSess.StdinPipe()
	if err != nil {
		ts.Close()
		return
	}
	stdoutPipe, err := sshSess.StdoutPipe()
	if err != nil {
		ts.Close()
		return
	}
	stderrPipe, err := sshSess.StderrPipe()
	if err != nil {
		ts.Close()
		return
	}

	if err := sshSess.Shell(); err != nil {
		_ = ts.sendJSON(wsOutgoingMsg{
			Type:    "error",
			Code:    "SHELL_FAILED",
			Message: fmt.Sprintf("启动远程交互式 Shell 失败: %v", err),
		})
		ts.Close()
		return
	}

	// Optional initial directory cd
	if client.Server.DefaultPath != "" {
		_, _ = io.WriteString(stdinPipe, fmt.Sprintf("cd %q 2>/dev/null && clear\n", client.Server.DefaultPath))
	}

	m.mu.Lock()
	m.activeSessions[ts.ID] = ts
	m.mu.Unlock()

	defer func() {
		m.mu.Lock()
		delete(m.activeSessions, ts.ID)
		m.mu.Unlock()
		ts.Close()
		m.store.RecordAudit("ssh.disconnect", fmt.Sprintf("%s (%s:%d)", client.Server.Name, client.Server.Host, client.Server.Port), "SSH 终端会话结束", clientIP, true)
	}()

	m.store.UpdateServerRuntimeMeta(serverID, latencyMs, "", true)
	m.store.RecordAudit("ssh.connect", fmt.Sprintf("%s (%s:%d)", client.Server.Name, client.Server.Host, client.Server.Port), fmt.Sprintf("建立 SSH 终端连接 (延迟 %dms)", latencyMs), clientIP, true)

	_ = ts.sendJSON(wsOutgoingMsg{
		Type:        "ready",
		SessionID:   ts.ID,
		ServerName:  client.Server.Name,
		Fingerprint: client.Fingerprint,
		LatencyMs:   latencyMs,
	})

	// Forward stdout & stderr to WebSocket
	streamPipe := func(r io.Reader) {
		buf := make([]byte, 8192)
		for {
			n, readErr := r.Read(buf)
			if n > 0 {
				encoded := base64.StdEncoding.EncodeToString(buf[:n])
				if sendErr := ts.sendJSON(wsOutgoingMsg{
					Type:    "output",
					DataB64: encoded,
				}); sendErr != nil {
					ts.Close()
					return
				}
			}
			if readErr != nil {
				return
			}
		}
	}
	go streamPipe(stdoutPipe)
	go streamPipe(stderrPipe)

	// Wait for remote shell exit
	go func() {
		waitErr := sshSess.Wait()
		msg := "远程 Shell 会话已正常退出"
		if waitErr != nil {
			msg = fmt.Sprintf("远程连接已断开: %v", waitErr)
		}
		_ = ts.sendJSON(wsOutgoingMsg{
			Type:    "exit",
			Message: msg,
		})
		ts.Close()
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
				_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
				if err != nil {
					ts.Close()
					return
				}
			}
		}
	}()

	// Read WebSocket control & input messages
	for {
		_, rawMsg, err := ws.ReadMessage()
		if err != nil {
			return
		}
		m.store.TouchActivity()

		var msg wsIncomingMsg
		if err := json.Unmarshal(rawMsg, &msg); err != nil {
			continue
		}

		switch msg.Type {
		case "input":
			if msg.DataB64 != "" {
				if decoded, decErr := base64.StdEncoding.DecodeString(msg.DataB64); decErr == nil && len(decoded) > 0 {
					_, _ = stdinPipe.Write(decoded)
				}
			} else if msg.Data != "" {
				_, _ = io.WriteString(stdinPipe, msg.Data)
			}
		case "resize":
			if msg.Cols > 0 && msg.Rows > 0 && msg.Cols <= 500 && msg.Rows <= 300 {
				_ = sshSess.WindowChange(msg.Rows, msg.Cols)
			}
		case "ping":
			_ = ts.sendJSON(wsOutgoingMsg{Type: "pong"})
		}
	}
}

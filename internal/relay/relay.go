package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

type dialHandshakeReq struct {
	Target    string `json:"target"`
	TimeoutMs int    `json:"timeout_ms,omitempty"`
}

type dialHandshakeResp struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

type activePipe struct {
	ws  *websocket.Conn
	tcp net.Conn
}

func (p *activePipe) Close() {
	if p.ws != nil {
		_ = p.ws.Close()
	}
	if p.tcp != nil {
		_ = p.tcp.Close()
	}
}

// Manager provides a zero-knowledge blind TCP byte pipe over WebSocket so the client's
// in-browser WASM (or local) SSHv2 engine performs end-to-end encrypted SSH & SFTP handshakes
// without ever exposing SSH keys, passwords, commands, terminal output, or files to this server.
//
// SECURITY INVARIANT:
// Manager stores ZERO target addresses, ZERO server IDs, and logs ZERO connection metadata.
type Manager struct {
	mu       sync.Mutex
	nextID   atomic.Uint64
	active   map[uint64]*activePipe
	selfPort int
	dialFn   func(ctx context.Context, network, address string) (net.Conn, error)
}

func NewManager(selfListenAddr string) *Manager {
	port := 0
	if _, pStr, err := net.SplitHostPort(selfListenAddr); err == nil {
		if p, pErr := strconv.Atoi(pStr); pErr == nil {
			port = p
		}
	}
	d := &net.Dialer{KeepAlive: 30 * time.Second}
	return &Manager{
		active:   make(map[uint64]*activePipe),
		selfPort: port,
		dialFn:   d.DialContext,
	}
}

// CloseAll immediately tears down all active blind TCP relay pipes (invoked on lock/logout/shutdown).
func (m *Manager) CloseAll() {
	m.mu.Lock()
	list := make([]*activePipe, 0, len(m.active))
	for id, p := range m.active {
		list = append(list, p)
		delete(m.active, id)
	}
	m.mu.Unlock()

	for _, p := range list {
		p.Close()
	}
}

// ActiveCount returns the count of open blind TCP relay pipes.
func (m *Manager) ActiveCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.active)
}

func checkSameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

// ServeWebSocket upgrades an authenticated HTTP request to a blind binary TCP relay.
func (m *Manager) ServeWebSocket(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{
		ReadBufferSize:  32 * 1024,
		WriteBufferSize: 32 * 1024,
		CheckOrigin:     checkSameOrigin,
	}
	wsConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	wsConn.SetReadLimit(1024)
	_ = wsConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, rawHandshake, err := wsConn.ReadMessage()
	if err != nil {
		_ = wsConn.Close()
		return
	}

	var req dialHandshakeReq
	unmarshalErr := json.Unmarshal(rawHandshake, &req)
	vault.ZeroBytes(rawHandshake)
	if unmarshalErr != nil {
		sendHandshakeError(wsConn, "invalid relay handshake")
		_ = wsConn.Close()
		return
	}

	host, portNum, vErr := validateTarget(req.Target, m.selfPort)
	if vErr != nil {
		req.Target = ""
		sendHandshakeError(wsConn, vErr.Error())
		_ = wsConn.Close()
		return
	}

	timeout := time.Duration(req.TimeoutMs) * time.Millisecond
	if timeout <= 0 || timeout > 30*time.Second {
		timeout = 12 * time.Second
	}

	dialAddr := net.JoinHostPort(host, strconv.Itoa(portNum))
	// Clear transient strings immediately after constructing local dial context
	req.Target = ""
	host = ""

	dialCtx, cancel := context.WithTimeout(r.Context(), timeout)
	tcpConn, err := m.dialFn(dialCtx, "tcp", dialAddr)
	cancel()
	dialAddr = ""
	if err != nil {
		sendHandshakeError(wsConn, "tcp connection failed")
		_ = wsConn.Close()
		return
	}

	_ = wsConn.SetReadDeadline(time.Time{})
	wsConn.SetReadLimit(2 * 1024 * 1024)

	okBytes, _ := json.Marshal(dialHandshakeResp{OK: true})
	_ = wsConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := wsConn.WriteMessage(websocket.TextMessage, okBytes); err != nil {
		_ = tcpConn.Close()
		_ = wsConn.Close()
		return
	}
	_ = wsConn.SetWriteDeadline(time.Time{})

	pipeID := m.nextID.Add(1)
	pipe := &activePipe{ws: wsConn, tcp: tcpConn}
	m.mu.Lock()
	m.active[pipeID] = pipe
	m.mu.Unlock()

	defer func() {
		m.mu.Lock()
		delete(m.active, pipeID)
		m.mu.Unlock()
		pipe.Close()
	}()

	var writeMu sync.Mutex
	writeWSBinary := func(payload []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = wsConn.SetWriteDeadline(time.Now().Add(30 * time.Second))
		return wsConn.WriteMessage(websocket.BinaryMessage, payload)
	}

	doneCh := make(chan struct{})
	var closeOnce sync.Once
	signalDone := func() {
		closeOnce.Do(func() {
			close(doneCh)
			pipe.Close()
		})
	}

	// TCP -> WebSocket Binary pump
	go func() {
		buf := make([]byte, 32*1024)
		defer func() {
			vault.ZeroBytes(buf)
			signalDone()
		}()
		for {
			n, rErr := tcpConn.Read(buf)
			if n > 0 {
				if wErr := writeWSBinary(buf[:n]); wErr != nil {
					return
				}
			}
			if rErr != nil {
				return
			}
		}
	}()

	// WebSocket Binary -> TCP pump
	go func() {
		defer signalDone()
		for {
			msgType, data, rErr := wsConn.ReadMessage()
			if rErr != nil {
				return
			}
			if msgType == websocket.BinaryMessage && len(data) > 0 {
				_, wErr := writeFull(tcpConn, data)
				vault.ZeroBytes(data)
				if wErr != nil {
					return
				}
			} else {
				vault.ZeroBytes(data)
			}
		}
	}()

	// Ping keepalive so reverse proxies do not drop idle SSH sessions
	pingTicker := time.NewTicker(25 * time.Second)
	defer pingTicker.Stop()
	for {
		select {
		case <-doneCh:
			return
		case <-r.Context().Done():
			signalDone()
			return
		case <-pingTicker.C:
			writeMu.Lock()
			_ = wsConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			err := wsConn.WriteMessage(websocket.PingMessage, nil)
			writeMu.Unlock()
			if err != nil {
				signalDone()
				return
			}
		}
	}
}

func writeFull(w io.Writer, b []byte) (int, error) {
	total := 0
	for total < len(b) {
		n, err := w.Write(b[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func validateTarget(target string, selfPort int) (string, int, error) {
	host, portStr, err := net.SplitHostPort(strings.TrimSpace(target))
	if err != nil || host == "" {
		return "", 0, errors.New("invalid target host:port")
	}
	portNum, err := strconv.Atoi(portStr)
	if err != nil || portNum < 1 || portNum > 65535 {
		return "", 0, errors.New("invalid target port")
	}
	if selfPort > 0 && portNum == selfPort {
		lower := strings.ToLower(host)
		if lower == "localhost" || lower == "127.0.0.1" || lower == "::1" || lower == "0.0.0.0" {
			return "", 0, fmt.Errorf("loopback self-port %d is blocked", selfPort)
		}
	}
	return host, portNum, nil
}

func sendHandshakeError(ws *websocket.Conn, msg string) {
	b, _ := json.Marshal(dialHandshakeResp{OK: false, Error: msg})
	_ = ws.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_ = ws.WriteMessage(websocket.TextMessage, b)
}

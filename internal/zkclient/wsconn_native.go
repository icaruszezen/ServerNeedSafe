//go:build !js

package zkclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

type relayHandshakeReq struct {
	Target    string `json:"target"`
	TimeoutMs int    `json:"timeout_ms"`
}

type relayHandshakeResp struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

type wsAddr string

func (a wsAddr) Network() string { return "ws-tcp-relay" }
func (a wsAddr) String() string  { return string(a) }

type nativeWSConn struct {
	ws        *websocket.Conn
	remote    wsAddr
	readMu    sync.Mutex
	writeMu   sync.Mutex
	rxBuf     bytes.Buffer
	closeOnce sync.Once
}

func dialWebSocketConn(ctx context.Context, wsURL, originBaseURL, targetAddr string, timeout time.Duration) (net.Conn, error) {
	dialer := websocket.Dialer{
		HandshakeTimeout: timeout,
	}
	var hdr http.Header
	if originBaseURL != "" {
		if u, err := url.Parse(originBaseURL); err == nil && u.Scheme != "" && u.Host != "" {
			hdr = http.Header{"Origin": []string{u.Scheme + "://" + u.Host}}
		}
	}

	ws, _, err := dialer.DialContext(ctx, wsURL, hdr)
	if err != nil {
		return nil, fmt.Errorf("建立安全中继通道失败: %w", err)
	}

	reqBytes, _ := json.Marshal(relayHandshakeReq{
		Target:    targetAddr,
		TimeoutMs: int(timeout.Milliseconds()),
	})
	_ = ws.SetWriteDeadline(time.Now().Add(timeout))
	wErr := ws.WriteMessage(websocket.TextMessage, reqBytes)
	vault.ZeroBytes(reqBytes)
	if wErr != nil {
		_ = ws.Close()
		return nil, wErr
	}

	_ = ws.SetReadDeadline(time.Now().Add(timeout))
	_, respBytes, rErr := ws.ReadMessage()
	if rErr != nil {
		_ = ws.Close()
		return nil, rErr
	}
	var resp relayHandshakeResp
	if err := json.Unmarshal(respBytes, &resp); err != nil || !resp.OK {
		_ = ws.Close()
		if resp.Error != "" {
			return nil, errors.New(resp.Error)
		}
		return nil, errors.New("安全中继连接目标服务器失败")
	}

	_ = ws.SetReadDeadline(time.Time{})
	_ = ws.SetWriteDeadline(time.Time{})

	return &nativeWSConn{
		ws:     ws,
		remote: wsAddr(targetAddr),
	}, nil
}

func (c *nativeWSConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	for c.rxBuf.Len() == 0 {
		msgType, data, err := c.ws.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				return 0, io.EOF
			}
			return 0, err
		}
		if msgType == websocket.BinaryMessage && len(data) > 0 {
			c.rxBuf.Write(data)
			vault.ZeroBytes(data)
		}
	}
	return c.rxBuf.Read(p)
}

func (c *nativeWSConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.ws.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *nativeWSConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		err = c.ws.Close()
	})
	return err
}

func (c *nativeWSConn) LocalAddr() net.Addr  { return wsAddr("client-zk") }
func (c *nativeWSConn) RemoteAddr() net.Addr { return c.remote }

func (c *nativeWSConn) SetDeadline(t time.Time) error {
	_ = c.ws.SetReadDeadline(t)
	return c.ws.SetWriteDeadline(t)
}

func (c *nativeWSConn) SetReadDeadline(t time.Time) error {
	return c.ws.SetReadDeadline(t)
}

func (c *nativeWSConn) SetWriteDeadline(t time.Time) error {
	return c.ws.SetWriteDeadline(t)
}

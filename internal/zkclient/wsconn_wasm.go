//go:build js && wasm

package zkclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"syscall/js"
	"time"
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

type wasmWSConn struct {
	ws            js.Value
	remote        wsAddr
	mu            sync.Mutex
	rxBuf         bytes.Buffer
	rxNotify      chan struct{}
	closeCh       chan struct{}
	closed        bool
	readDeadline  time.Time
	writeDeadline time.Time
	closeOnce     sync.Once
	jsFuncs       []js.Func
}

func dialWebSocketConn(ctx context.Context, wsURL, _ string, targetAddr string, timeout time.Duration) (net.Conn, error) {
	if timeout <= 0 {
		timeout = 12 * time.Second
	}

	wsCtor := js.Global().Get("WebSocket")
	if wsCtor.IsUndefined() || wsCtor.IsNull() {
		return nil, errors.New("当前运行环境不支持 WebSocket")
	}

	ws := wsCtor.New(wsURL)
	ws.Set("binaryType", "arraybuffer")

	c := &wasmWSConn{
		ws:       ws,
		remote:   wsAddr(targetAddr),
		rxNotify: make(chan struct{}, 1),
		closeCh:  make(chan struct{}),
	}

	openCh := make(chan error, 1)
	hsCh := make(chan error, 1)
	handshakeDone := false

	onOpen := js.FuncOf(func(this js.Value, args []js.Value) any {
		select {
		case openCh <- nil:
		default:
		}
		return nil
	})

	onMessage := js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) == 0 {
			return nil
		}
		data := args[0].Get("data")
		c.mu.Lock()
		done := handshakeDone
		c.mu.Unlock()

		if !done {
			if data.Type() == js.TypeString {
				var resp relayHandshakeResp
				err := json.Unmarshal([]byte(data.String()), &resp)
				if err != nil {
					select {
					case hsCh <- err:
					default:
					}
					return nil
				}
				if !resp.OK {
					msg := resp.Error
					if msg == "" {
						msg = "安全中继连接目标服务器失败"
					}
					select {
					case hsCh <- errors.New(msg):
					default:
					}
					return nil
				}
				c.mu.Lock()
				handshakeDone = true
				c.mu.Unlock()
				select {
				case hsCh <- nil:
				default:
				}
			}
			return nil
		}

		// Binary SSHv2 frame (ArrayBuffer)
		if data.Type() == js.TypeObject && !data.IsNull() {
			u8 := js.Global().Get("Uint8Array").New(data)
			n := u8.Get("byteLength").Int()
			if n > 0 {
				chunk := make([]byte, n)
				js.CopyBytesToGo(chunk, u8)
				c.mu.Lock()
				c.rxBuf.Write(chunk)
				c.mu.Unlock()
				select {
				case c.rxNotify <- struct{}{}:
				default:
				}
			}
		}
		return nil
	})

	onError := js.FuncOf(func(this js.Value, args []js.Value) any {
		err := errors.New("WebSocket 安全中继连接异常中断")
		select {
		case openCh <- err:
		default:
		}
		select {
		case hsCh <- err:
		default:
		}
		c.markClosed()
		return nil
	})

	onClose := js.FuncOf(func(this js.Value, args []js.Value) any {
		err := io.EOF
		select {
		case openCh <- err:
		default:
		}
		select {
		case hsCh <- err:
		default:
		}
		c.markClosed()
		return nil
	})

	c.jsFuncs = []js.Func{onOpen, onMessage, onError, onClose}
	ws.Set("onopen", onOpen)
	ws.Set("onmessage", onMessage)
	ws.Set("onerror", onError)
	ws.Set("onclose", onClose)

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case err := <-openCh:
		if err != nil {
			_ = c.Close()
			return nil, err
		}
	case <-ctx.Done():
		_ = c.Close()
		return nil, ctx.Err()
	case <-timer.C:
		_ = c.Close()
		return nil, os.ErrDeadlineExceeded
	}

	reqBytes, _ := json.Marshal(relayHandshakeReq{
		Target:    targetAddr,
		TimeoutMs: int(timeout.Milliseconds()),
	})
	ws.Call("send", string(reqBytes))

	select {
	case err := <-hsCh:
		if err != nil {
			_ = c.Close()
			return nil, err
		}
	case <-ctx.Done():
		_ = c.Close()
		return nil, ctx.Err()
	case <-timer.C:
		_ = c.Close()
		return nil, os.ErrDeadlineExceeded
	}

	return c, nil
}

func (c *wasmWSConn) markClosed() {
	c.mu.Lock()
	wasClosed := c.closed
	c.closed = true
	c.mu.Unlock()
	if !wasClosed {
		select {
		case <-c.closeCh:
		default:
			close(c.closeCh)
		}
		select {
		case c.rxNotify <- struct{}{}:
		default:
		}
	}
}

func (c *wasmWSConn) Read(p []byte) (int, error) {
	for {
		c.mu.Lock()
		if c.rxBuf.Len() > 0 {
			n, err := c.rxBuf.Read(p)
			c.mu.Unlock()
			return n, err
		}
		if c.closed {
			c.mu.Unlock()
			return 0, io.EOF
		}
		dl := c.readDeadline
		c.mu.Unlock()

		var deadlineCh <-chan time.Time
		var timer *time.Timer
		if !dl.IsZero() {
			rem := time.Until(dl)
			if rem <= 0 {
				return 0, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(rem)
			deadlineCh = timer.C
		}

		select {
		case <-c.rxNotify:
			if timer != nil {
				timer.Stop()
			}
		case <-c.closeCh:
			if timer != nil {
				timer.Stop()
			}
		case <-deadlineCh:
			return 0, os.ErrDeadlineExceeded
		}
	}
}

func (c *wasmWSConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.mu.Lock()
	closed := c.closed
	dl := c.writeDeadline
	c.mu.Unlock()

	if closed {
		return 0, io.ErrClosedPipe
	}
	if !dl.IsZero() && time.Now().After(dl) {
		return 0, os.ErrDeadlineExceeded
	}

	u8 := js.Global().Get("Uint8Array").New(len(p))
	js.CopyBytesToJS(u8, p)
	c.ws.Call("send", u8)
	return len(p), nil
}

func (c *wasmWSConn) Close() error {
	c.closeOnce.Do(func() {
		c.markClosed()
		c.ws.Set("onopen", js.Null())
		c.ws.Set("onmessage", js.Null())
		c.ws.Set("onerror", js.Null())
		c.ws.Set("onclose", js.Null())
		if c.ws.Get("readyState").Int() < 2 {
			c.ws.Call("close", 1000, "closed")
		}
		for _, fn := range c.jsFuncs {
			fn.Release()
		}
		c.jsFuncs = nil
	})
	return nil
}

func (c *wasmWSConn) LocalAddr() net.Addr  { return wsAddr("wasm-zk-worker") }
func (c *wasmWSConn) RemoteAddr() net.Addr { return c.remote }

func (c *wasmWSConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.writeDeadline = t
	c.mu.Unlock()
	select {
	case c.rxNotify <- struct{}{}:
	default:
	}
	return nil
}

func (c *wasmWSConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.mu.Unlock()
	select {
	case c.rxNotify <- struct{}{}:
	default:
	}
	return nil
}

func (c *wasmWSConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDeadline = t
	c.mu.Unlock()
	return nil
}

package api

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

// MCPRuntimeStatus reports live MCP gateway endpoints and desktop loopback listener health to the UI.
type MCPRuntimeStatus struct {
	DeployMode             string `json:"deploy_mode"`
	ServerEndpointPath     string `json:"server_endpoint_path"`
	EffectiveEndpointURL   string `json:"effective_endpoint_url"`
	DesktopLoopbackRunning bool   `json:"desktop_loopback_running"`
	DesktopLoopbackAddr    string `json:"desktop_loopback_addr,omitempty"`
	DesktopLoopbackError   string `json:"desktop_loopback_error,omitempty"`
}

// desktopMCPLoopback manages the opt-in dedicated 127.0.0.1:<port> HTTP listener in desktop mode.
// It exposes ONLY /api/mcp (and /health) behind mandatory scoped MCP Bearer Token authentication,
// leaving the primary WebView2 random-port HTTP server and desktopGuardCookie isolation untouched.
type desktopMCPLoopback struct {
	mu      sync.Mutex
	server  *http.Server
	addr    string
	port    int
	running bool
	lastErr string
}

func newDesktopMCPLoopback() *desktopMCPLoopback {
	return &desktopMCPLoopback{}
}

func (d *desktopMCPLoopback) Reconcile(enabled bool, port int, mcpHandler http.Handler) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !enabled {
		d.stopLocked()
		d.lastErr = ""
		return
	}

	if port < 1024 || port > 65535 {
		port = 18900
	}

	if d.running && d.port == port {
		return
	}

	d.stopLocked()

	bindAddr := fmt.Sprintf("127.0.0.1:%d", port)
	ln, err := net.Listen("tcp", bindAddr)
	if err != nil {
		d.lastErr = fmt.Sprintf("绑定桌面回环端口 %s 失败: %v", bindAddr, err)
		log.Printf("[ServerNeedSafe] %s", d.lastErr)
		return
	}

	mux := http.NewServeMux()
	mux.Handle("/api/mcp", mcpHandler)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":       true,
			"mode":     "desktop_mcp_loopback",
			"endpoint": "/api/mcp",
		})
	})

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	d.server = srv
	d.addr = ln.Addr().String()
	d.port = port
	d.running = true
	d.lastErr = ""

	go func(s *http.Server, l net.Listener) {
		if err := s.Serve(l); err != nil && err != http.ErrServerClosed {
			d.mu.Lock()
			if d.server == s {
				d.running = false
				d.lastErr = err.Error()
			}
			d.mu.Unlock()
		}
	}(srv, ln)
}

func (d *desktopMCPLoopback) Status() (running bool, addr string, lastErr string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.running, d.addr, d.lastErr
}

func (d *desktopMCPLoopback) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.stopLocked()
}

func (d *desktopMCPLoopback) stopLocked() {
	if d.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = d.server.Shutdown(ctx)
		cancel()
		d.server = nil
	}
	d.running = false
	d.addr = ""
	d.port = 0
}

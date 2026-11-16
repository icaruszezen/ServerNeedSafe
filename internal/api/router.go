package api

import (
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/icaruszezen/ServerNeedSafe/internal/auth"
	"github.com/icaruszezen/ServerNeedSafe/internal/sshmanager"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

const desktopGuardCookieName = "sns_desktop_guard"

// Config holds dependencies and runtime flags for the HTTP/WS API server.
type Config struct {
	DeployMode string // "server" or "desktop"
	Store      *vault.Store
	Auth       *auth.Manager
	SSH        *sshmanager.Manager
	StaticFS   fs.FS // Embedded frontend dist FS (optional in pure API unit tests)
}

type Server struct {
	cfg      Config
	mux      *http.ServeMux
	upgrader websocket.Upgrader
	stopCh   chan struct{}
}

func NewServer(cfg Config) *Server {
	if cfg.DeployMode == "" {
		cfg.DeployMode = "server"
	}
	s := &Server{
		cfg:    cfg,
		mux:    http.NewServeMux(),
		stopCh: make(chan struct{}),
	}
	s.upgrader = websocket.Upgrader{
		ReadBufferSize:  16 * 1024,
		WriteBufferSize: 16 * 1024,
		CheckOrigin:     s.checkWebSocketOrigin,
	}

	// Ensure locking the vault immediately revokes all active bearer sessions
	cfg.Store.RegisterOnLock(func() {
		cfg.Auth.RevokeAll()
	})

	s.registerRoutes()
	go s.autoLockLoop()
	return s
}

func (s *Server) Close() {
	select {
	case <-s.stopCh:
	default:
		close(s.stopCh)
	}
}

func (s *Server) autoLockLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.cfg.Store.CheckAutoLock()
		}
	}
}

func (s *Server) Handler() http.Handler {
	return s.securityHeadersMiddleware(s.mux)
}

func (s *Server) securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
			if s.cfg.Auth.DesktopGuardEnabled() {
				c, err := r.Cookie(desktopGuardCookieName)
				if err != nil || !s.cfg.Auth.VerifyDesktopCookie(c.Value) {
					writeError(w, http.StatusForbidden, "FORBIDDEN_ORIGIN", "本地桌面安全隔离策略已拦截外部未授权进程访问")
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) checkWebSocketOrigin(r *http.Request) bool {
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

func (s *Server) registerRoutes() {
	// Desktop bootstrap route (sets HttpOnly local instance cookie)
	s.mux.HandleFunc("GET /__desktop_boot", s.handleDesktopBoot)

	// Public healthcheck
	s.mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":   true,
			"mode": s.cfg.DeployMode,
		})
	})

	// Auth & Vault Lifecycle
	s.mux.HandleFunc("GET /api/auth/status", s.handleAuthStatus)
	s.mux.HandleFunc("POST /api/auth/setup", s.handleAuthSetup)
	s.mux.HandleFunc("POST /api/auth/unlock", s.handleAuthUnlock)
	s.mux.HandleFunc("POST /api/auth/logout", s.requireAuth(s.handleAuthLogout))
	s.mux.HandleFunc("POST /api/auth/lock", s.requireAuth(s.handleAuthLock))
	s.mux.HandleFunc("POST /api/auth/password", s.requireAuth(s.handleChangePassword))

	// Encrypted Vault Backup Export & Import
	s.mux.HandleFunc("GET /api/vault/export", s.requireAuth(s.handleVaultExport))
	s.mux.HandleFunc("POST /api/vault/import", s.handleVaultImport)

	// Vault Security Center, Settings, KnownHosts, Audit
	s.mux.HandleFunc("GET /api/vault/security", s.requireAuth(s.handleVaultSecurity))
	s.mux.HandleFunc("PUT /api/vault/settings", s.requireAuth(s.handleUpdateSettings))
	s.mux.HandleFunc("DELETE /api/vault/known-hosts", s.requireAuth(s.handleDeleteKnownHost))

	// Servers & Groups
	s.mux.HandleFunc("GET /api/servers", s.requireAuth(s.handleListServers))
	s.mux.HandleFunc("POST /api/servers", s.requireAuth(s.handleCreateServer))
	s.mux.HandleFunc("PUT /api/servers/{id}", s.requireAuth(s.handleUpdateServer))
	s.mux.HandleFunc("DELETE /api/servers/{id}", s.requireAuth(s.handleDeleteServer))
	s.mux.HandleFunc("POST /api/servers/{id}/probe", s.requireAuth(s.handleProbeServer))
	s.mux.HandleFunc("POST /api/groups", s.requireAuth(s.handleAddGroup))
	s.mux.HandleFunc("DELETE /api/groups", s.requireAuth(s.handleDeleteGroup))

	// Credentials & SSH Key Generator / Deployer
	s.mux.HandleFunc("GET /api/credentials", s.requireAuth(s.handleListCredentials))
	s.mux.HandleFunc("POST /api/credentials", s.requireAuth(s.handleCreateCredential))
	s.mux.HandleFunc("PUT /api/credentials/{id}", s.requireAuth(s.handleUpdateCredential))
	s.mux.HandleFunc("DELETE /api/credentials/{id}", s.requireAuth(s.handleDeleteCredential))
	s.mux.HandleFunc("POST /api/keys/generate", s.requireAuth(s.handleGenerateKeyPair))
	s.mux.HandleFunc("POST /api/keys/deploy", s.requireAuth(s.handleDeployPublicKey))

	// Quick Snippets & Multi-Server Batch Exec
	s.mux.HandleFunc("GET /api/snippets", s.requireAuth(s.handleListSnippets))
	s.mux.HandleFunc("POST /api/snippets", s.requireAuth(s.handleUpsertSnippet))
	s.mux.HandleFunc("DELETE /api/snippets/{id}", s.requireAuth(s.handleDeleteSnippet))
	s.mux.HandleFunc("POST /api/snippets/batch-exec", s.requireAuth(s.handleBatchExec))

	// One-time Tickets & Interactive SSH WebSocket
	s.mux.HandleFunc("POST /api/ws/ticket", s.requireAuth(s.handleIssueTicket))
	s.mux.HandleFunc("GET /api/ws/ssh/{id}", s.handleWebSocketSSH)

	// SFTP File Manager
	s.mux.HandleFunc("GET /api/sftp/{id}/list", s.requireAuth(s.handleSFTPList))
	s.mux.HandleFunc("GET /api/sftp/{id}/read", s.requireAuth(s.handleSFTPRead))
	s.mux.HandleFunc("POST /api/sftp/{id}/write", s.requireAuth(s.handleSFTPWrite))
	s.mux.HandleFunc("POST /api/sftp/{id}/upload", s.requireAuth(s.handleSFTPUpload))
	s.mux.HandleFunc("GET /api/sftp/{id}/download", s.handleSFTPDownload)
	s.mux.HandleFunc("POST /api/sftp/{id}/mkdir", s.requireAuth(s.handleSFTPMkdir))
	s.mux.HandleFunc("POST /api/sftp/{id}/rename", s.requireAuth(s.handleSFTPRename))
	s.mux.HandleFunc("POST /api/sftp/{id}/delete", s.requireAuth(s.handleSFTPDelete))
	s.mux.HandleFunc("POST /api/sftp/{id}/chmod", s.requireAuth(s.handleSFTPChmod))

	// Embedded Single-Page Web Application fallback
	if s.cfg.StaticFS != nil {
		fileServer := http.FileServer(http.FS(s.cfg.StaticFS))
		s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				writeError(w, http.StatusNotFound, "NOT_FOUND", "API 路径不存在")
				return
			}
			cleanPath := strings.TrimPrefix(r.URL.Path, "/")
			if cleanPath == "" {
				cleanPath = "index.html"
			}
			if _, err := fs.Stat(s.cfg.StaticFS, cleanPath); err != nil {
				// SPA client-side fallback -> index.html
				r2 := new(http.Request)
				*r2 = *r
				r2.URL = new(url.URL)
				*r2.URL = *r.URL
				r2.URL.Path = "/"
				fileServer.ServeHTTP(w, r2)
				return
			}
			fileServer.ServeHTTP(w, r)
		})
	}
}

func extractBearerToken(r *http.Request) string {
	hdr := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(hdr), "bearer ") {
		return strings.TrimSpace(hdr[7:])
	}
	return ""
}

func extractClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.Store.Status() != vault.StatusUnlocked {
			writeError(w, http.StatusUnauthorized, "VAULT_LOCKED", "加密保险库已锁定，请先验证管理员密码")
			return
		}
		tok := extractBearerToken(r)
		if _, err := s.cfg.Auth.ValidateSession(tok); err != nil {
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "尚未通过管理员密码验证或会话已失效")
			return
		}
		s.cfg.Store.TouchActivity()
		next(w, r)
	}
}

func decodeJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 8*1024*1024))
	return dec.Decode(dst)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{
		"error": message,
		"code":  code,
	})
}

func writeDomainError(w http.ResponseWriter, err error) {
	var hkErr *sshmanager.HostKeyUntrustedError
	if errors.As(err, &hkErr) {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error":         hkErr.Error(),
			"code":          "HOST_KEY_UNTRUSTED",
			"host_key_info": hkErr,
		})
		return
	}
	switch {
	case errors.Is(err, vault.ErrVaultLocked):
		writeError(w, http.StatusUnauthorized, "VAULT_LOCKED", err.Error())
	case errors.Is(err, vault.ErrInvalidPassword):
		writeError(w, http.StatusUnauthorized, "INVALID_PASSWORD", err.Error())
	case errors.Is(err, vault.ErrWeakPassword), errors.Is(err, vault.ErrInvalidInput):
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", err.Error())
	case errors.Is(err, vault.ErrNotFound):
		writeError(w, http.StatusNotFound, "NOT_FOUND", err.Error())
	default:
		writeError(w, http.StatusBadRequest, "OPERATION_FAILED", err.Error())
	}
}

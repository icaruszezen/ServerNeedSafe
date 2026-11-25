package api

import (
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/aiops"
	"github.com/icaruszezen/ServerNeedSafe/internal/auth"
	"github.com/icaruszezen/ServerNeedSafe/internal/monitor"
	"github.com/icaruszezen/ServerNeedSafe/internal/relay"
	"github.com/icaruszezen/ServerNeedSafe/internal/sshmanager"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

const (
	desktopGuardCookieName = "sns_desktop_guard"
	adminSessionCookieName = "sns_admin_session"
)

// Config holds dependencies for the ServerNeedSafe HTTP/WebSocket daemon.
// Store, KeyMgr, SSH, Monitor, and AI run natively in-process 7x24 so web pages load
// in <50ms without WASM downloads and background SSH monitoring + AI patrol run unattended.
type Config struct {
	DeployMode string // "server" or "desktop"
	BlindStore *vault.BlindStore
	Store      *vault.ClientVault
	KeyMgr     *vault.ServerKeyManager
	SSH        *sshmanager.Manager
	Monitor    *monitor.Engine
	AI         *aiops.Service
	Auth       *auth.Manager
	Relay      *relay.Manager
	StaticFS   fs.FS // Embedded frontend dist FS (optional in pure API unit tests)
}

type Server struct {
	cfg Config
	mux *http.ServeMux

	stateMu          sync.RWMutex
	migrationPending bool

	// kdfSlots bounds concurrent server-side Argon2id password derivations on unauthenticated endpoints.
	kdfSlots chan struct{}
}

func NewServer(cfg Config) *Server {
	if cfg.DeployMode == "" {
		cfg.DeployMode = "server"
	}
	if cfg.Auth == nil {
		cfg.Auth, _ = auth.NewManager(8*time.Hour, false)
	}
	if cfg.Relay == nil {
		cfg.Relay = relay.NewManager("")
	}
	if cfg.BlindStore != nil {
		if cfg.Store == nil {
			cfg.Store = vault.NewClientVault(vault.NewBlindStoreBackend(cfg.BlindStore))
		}
		if cfg.KeyMgr == nil {
			cfg.KeyMgr = vault.NewServerKeyManager(filepath.Dir(cfg.BlindStore.FilePath()))
		}
	}
	if cfg.Store != nil {
		if cfg.SSH == nil {
			cfg.SSH = sshmanager.NewManager(cfg.Store)
		}
		if cfg.Monitor == nil {
			cfg.Monitor = monitor.NewEngine(cfg.Store, cfg.SSH)
		}
		if cfg.AI == nil {
			cfg.AI = aiops.NewService(cfg.Store, cfg.SSH)
		}
	}

	var migPending bool
	if cfg.KeyMgr != nil && cfg.Store != nil && cfg.BlindStore != nil {
		var unlockErr error
		_, migPending, unlockErr = cfg.KeyMgr.TryAutoUnlock(cfg.Store, cfg.BlindStore)
		if unlockErr != nil {
			log.Printf("[ServerNeedSafe] 自动挂载加密保险库失败，需管理员密码登录一次完成挂载：%v", unlockErr)
		}
		if cfg.DeployMode == "server" && cfg.KeyMgr.HasLocalKey() && cfg.KeyMgr.SealMode() == vault.SealModeFile {
			log.Printf("[ServerNeedSafe] 安全提示：%s 以文件内主密钥方式封装（数据目录整体泄露即可解密保险库），生产环境建议配置 SNS_MASTER_KEY 将封装主密钥与数据目录分离", cfg.KeyMgr.KeyPath())
		}
	}

	s := &Server{
		cfg:              cfg,
		mux:              http.NewServeMux(),
		migrationPending: migPending,
		kdfSlots:         make(chan struct{}, maxConcurrentPasswordKDF),
	}
	if s.cfg.Monitor != nil {
		s.cfg.Monitor.Start()
	}
	s.registerRoutes()
	return s
}

func (s *Server) Close() {
	if s.cfg.AI != nil {
		s.cfg.AI.Close()
	}
	if s.cfg.Monitor != nil {
		s.cfg.Monitor.Close()
	}
	if s.cfg.SSH != nil {
		s.cfg.SSH.CloseAllSessions()
	}
	if s.cfg.Relay != nil {
		s.cfg.Relay.CloseAll()
	}
}

func (s *Server) isMigrationPending() bool {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return s.migrationPending
}

func (s *Server) setMigrationPending(v bool) {
	s.stateMu.Lock()
	s.migrationPending = v
	s.stateMu.Unlock()
}

func (s *Server) isDaemonUnlocked() bool {
	return s.cfg.Store != nil && s.cfg.Store.Status() == vault.StatusUnlocked
}

func (s *Server) Handler() http.Handler {
	return s.securityHeadersMiddleware(s.mux)
}

func (s *Server) securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; worker-src 'self' blob:; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self' http: https: ws: wss:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")

		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
			if s.cfg.Auth.DesktopGuardEnabled() {
				c, err := r.Cookie(desktopGuardCookieName)
				if err != nil || !s.cfg.Auth.VerifyDesktopCookie(c.Value) {
					writeError(w, http.StatusForbidden, "FORBIDDEN_ORIGIN", "本地桌面安全隔离策略已拦截外部未授权进程访问")
					return
				}
			} else if origin := r.Header.Get("Origin"); origin != "" && !isSameOriginRequest(r, origin) {
				// Allow token/signature-based Remote Vault Sync preflights across origins (never with credentials/cookies)
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				if r.Method == http.MethodOptions {
					w.WriteHeader(http.StatusNoContent)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func isSameOriginRequest(r *http.Request, origin string) bool {
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	if strings.EqualFold(u.Host, r.Host) {
		return true
	}
	// Reverse proxies that rewrite Host (e.g. proxy_pass to 127.0.0.1 without "proxy_set_header Host")
	// usually forward the public host here; only believe it when the peer is our own local proxy.
	if fwdHost := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Host"), ",")[0]); fwdHost != "" && isTrustedProxyPeer(r.RemoteAddr) {
		return strings.EqualFold(u.Host, fwdHost)
	}
	return false
}

func (s *Server) registerRoutes() {
	// Desktop bootstrap route (sets HttpOnly local instance cookie)
	s.mux.HandleFunc("GET /__desktop_boot", s.handleDesktopBoot)

	// Public healthcheck
	s.mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":             true,
			"mode":           s.cfg.DeployMode,
			"initialized":    s.cfg.BlindStore.IsInitialized(),
			"daemon_mode":    true,
			"daemon_running": s.isDaemonUnlocked() || !s.cfg.BlindStore.IsInitialized(),
		})
	})

	// Authentication, Session Lifecycle & KDF Tuning
	s.mux.HandleFunc("GET /api/auth/status", s.handleAuthStatus)
	s.mux.HandleFunc("POST /api/auth/setup", s.handleAuthSetup)
	s.mux.HandleFunc("POST /api/auth/login", s.handleAuthLogin)
	s.mux.HandleFunc("POST /api/auth/challenge", s.handleAuthChallenge)
	s.mux.HandleFunc("POST /api/auth/verify", s.handleAuthVerify)
	s.mux.HandleFunc("POST /api/auth/logout", s.requireAuth(s.handleAuthLogout))
	s.mux.HandleFunc("POST /api/auth/lock", s.requireAuth(s.handleAuthLock))
	s.mux.HandleFunc("POST /api/auth/password", s.requireAuth(s.handleChangePassword))
	s.mux.HandleFunc("POST /api/vault/kdf", s.requireAuth(s.handleUpdateVaultKDF))

	// Vault Security Settings, Backup Export/Import & Cross-Instance Sync
	s.mux.HandleFunc("GET /api/vault/security", s.requireAuth(s.handleGetVaultSecurity))
	s.mux.HandleFunc("PUT /api/vault/settings", s.requireAuth(s.handleUpdateVaultSettings))
	s.mux.HandleFunc("DELETE /api/vault/known-hosts", s.requireAuth(s.handleDeleteKnownHost))
	s.mux.HandleFunc("GET /api/vault/blob", s.requireAuth(s.handleGetVaultBlob))
	s.mux.HandleFunc("PUT /api/vault/blob", s.requireAuth(s.handlePutVaultBlob))
	s.mux.HandleFunc("GET /api/vault/export", s.requireAuth(s.handleExportVaultBlob))
	s.mux.HandleFunc("POST /api/vault/import", s.handleImportVaultBlob)
	s.mux.HandleFunc("POST /api/vault/import/file", s.handleImportVaultFile)
	s.mux.HandleFunc("POST /api/vault/sync/push", s.requireAuth(s.handleVaultSyncPush))
	s.mux.HandleFunc("POST /api/vault/sync/pull", s.requireAuth(s.handleVaultSyncPull))

	// Workspace Bootstrap, Servers, Groups, Credentials, Snippets & Batch SSH
	s.mux.HandleFunc("GET /api/workspace/bootstrap", s.requireAuth(s.handleWorkspaceBootstrap))
	s.mux.HandleFunc("GET /api/servers", s.requireAuth(s.handleListServers))
	s.mux.HandleFunc("POST /api/servers", s.requireAuth(s.handleCreateServer))
	s.mux.HandleFunc("PUT /api/servers/{id}", s.requireAuth(s.handleUpdateServer))
	s.mux.HandleFunc("DELETE /api/servers/{id}", s.requireAuth(s.handleDeleteServer))
	s.mux.HandleFunc("POST /api/servers/{id}/probe", s.requireAuth(s.handleProbeServer))
	s.mux.HandleFunc("POST /api/groups", s.requireAuth(s.handleAddGroup))
	s.mux.HandleFunc("DELETE /api/groups", s.requireAuth(s.handleDeleteGroup))

	s.mux.HandleFunc("GET /api/credentials", s.requireAuth(s.handleListCredentials))
	s.mux.HandleFunc("POST /api/credentials", s.requireAuth(s.handleCreateCredential))
	s.mux.HandleFunc("PUT /api/credentials/{id}", s.requireAuth(s.handleUpdateCredential))
	s.mux.HandleFunc("DELETE /api/credentials/{id}", s.requireAuth(s.handleDeleteCredential))
	s.mux.HandleFunc("POST /api/ssh/keygen", s.requireAuth(s.handleGenerateKeyPair))
	s.mux.HandleFunc("POST /api/ssh/deploy-key", s.requireAuth(s.handleDeployPublicKey))

	s.mux.HandleFunc("GET /api/snippets", s.requireAuth(s.handleListSnippets))
	s.mux.HandleFunc("POST /api/snippets", s.requireAuth(s.handleUpsertSnippet))
	s.mux.HandleFunc("DELETE /api/snippets/{id}", s.requireAuth(s.handleDeleteSnippet))
	s.mux.HandleFunc("POST /api/ssh/batch-exec", s.requireAuth(s.handleBatchExec))

	// Native SFTP File Management
	s.mux.HandleFunc("POST /api/sftp/list", s.requireAuth(s.handleSFTPList))
	s.mux.HandleFunc("POST /api/sftp/read", s.requireAuth(s.handleSFTPRead))
	s.mux.HandleFunc("POST /api/sftp/write", s.requireAuth(s.handleSFTPWrite))
	s.mux.HandleFunc("POST /api/sftp/upload", s.requireAuth(s.handleSFTPUpload))
	s.mux.HandleFunc("POST /api/sftp/download", s.requireAuth(s.handleSFTPDownload))
	s.mux.HandleFunc("POST /api/sftp/mkdir", s.requireAuth(s.handleSFTPMkdir))
	s.mux.HandleFunc("POST /api/sftp/rename", s.requireAuth(s.handleSFTPRename))
	s.mux.HandleFunc("POST /api/sftp/delete", s.requireAuth(s.handleSFTPDelete))
	s.mux.HandleFunc("POST /api/sftp/chmod", s.requireAuth(s.handleSFTPChmod))

	// 7x24 Server Status Monitoring & Telemetry
	s.mux.HandleFunc("GET /api/monitor/overview", s.requireAuth(s.handleGetMonitorOverview))
	s.mux.HandleFunc("GET /api/monitor/detail", s.requireAuth(s.handleGetServerMonitorDetail))
	s.mux.HandleFunc("POST /api/monitor/collect-all", s.requireAuth(s.handleCollectAllMonitor))
	s.mux.HandleFunc("POST /api/monitor/collect-server", s.requireAuth(s.handleCollectServerMonitor))
	s.mux.HandleFunc("POST /api/monitor/port-baseline", s.requireAuth(s.handleAcceptPortBaseline))
	s.mux.HandleFunc("GET /api/monitor/alerts", s.requireAuth(s.handleListMonitorAlerts))
	s.mux.HandleFunc("POST /api/monitor/alerts/ack", s.requireAuth(s.handleAckMonitorAlert))
	s.mux.HandleFunc("POST /api/monitor/alerts/clear-resolved", s.requireAuth(s.handleClearResolvedMonitorAlerts))
	s.mux.HandleFunc("GET /api/monitor/policy", s.requireAuth(s.handleGetMonitorPolicy))
	s.mux.HandleFunc("PUT /api/monitor/policy", s.requireAuth(s.handleUpdateMonitorPolicy))
	s.mux.HandleFunc("POST /api/monitor/clear-history", s.requireAuth(s.handleClearMonitorHistory))
	s.mux.HandleFunc("GET /api/monitor/export", s.requireAuth(s.handleExportMonitorHistory))

	// 7x24 AI Ops Agent, SSE Streaming, Global AGENTS.md, Hybrid Memory, Runbooks & Scheduled Patrol
	s.mux.HandleFunc("GET /api/ai/overview", s.requireAuth(s.handleGetAIOverview))
	s.mux.HandleFunc("POST /api/ai/providers", s.requireAuth(s.handleUpsertAIProvider))
	s.mux.HandleFunc("PUT /api/ai/active-provider", s.requireAuth(s.handleSetActiveAIProvider))
	s.mux.HandleFunc("DELETE /api/ai/providers/{id}", s.requireAuth(s.handleDeleteAIProvider))
	s.mux.HandleFunc("POST /api/ai/test-provider", s.requireAuth(s.handleTestAIProvider))
	s.mux.HandleFunc("PUT /api/ai/agents-md", s.requireAuth(s.handleUpdateAgentsMD))
	s.mux.HandleFunc("PUT /api/ai/memory-config", s.requireAuth(s.handleUpdateAIMemoryConfig))
	s.mux.HandleFunc("POST /api/ai/agents-md-proposals/resolve", s.requireAuth(s.handleResolveAgentsMDProposal))
	s.mux.HandleFunc("GET /api/ai/sessions", s.requireAuth(s.handleListAISessions))
	s.mux.HandleFunc("POST /api/ai/sessions", s.requireAuth(s.handleCreateAISession))
	s.mux.HandleFunc("GET /api/ai/sessions/{id}", s.requireAuth(s.handleGetAISession))
	s.mux.HandleFunc("PUT /api/ai/sessions/{id}", s.requireAuth(s.handleUpdateAISession))
	s.mux.HandleFunc("DELETE /api/ai/sessions/{id}", s.requireAuth(s.handleDeleteAISession))
	s.mux.HandleFunc("GET /api/ai/sessions/{id}/context", s.requireAuth(s.handleInspectAISessionContext))
	s.mux.HandleFunc("POST /api/ai/sessions/{id}/compact", s.requireAuth(s.handleCompactAISession))
	s.mux.HandleFunc("POST /api/ai/chat/stream", s.requireAuth(s.handleStreamAIChat))
	s.mux.HandleFunc("POST /api/ai/approval/stream", s.requireAuth(s.handleStreamAIApproval))
	s.mux.HandleFunc("PUT /api/ai/host-memory/{serverId}", s.requireAuth(s.handleUpsertHostMemory))
	s.mux.HandleFunc("DELETE /api/ai/host-memory/{serverId}", s.requireAuth(s.handleDeleteHostMemory))
	s.mux.HandleFunc("POST /api/ai/host-memory/sync-monitor", s.requireAuth(s.handleSyncHostMemoryFromMonitor))
	s.mux.HandleFunc("GET /api/ai/memories", s.requireAuth(s.handleListAIMemories))
	s.mux.HandleFunc("POST /api/ai/memories", s.requireAuth(s.handleUpsertAIMemory))
	s.mux.HandleFunc("DELETE /api/ai/memories/{id}", s.requireAuth(s.handleDeleteAIMemory))
	s.mux.HandleFunc("POST /api/ai/runbook-proposals/resolve", s.requireAuth(s.handleResolveRunbookProposal))
	s.mux.HandleFunc("POST /api/ai/runbooks", s.requireAuth(s.handleUpsertRunbook))
	s.mux.HandleFunc("DELETE /api/ai/runbooks/{id}", s.requireAuth(s.handleDeleteRunbook))
	s.mux.HandleFunc("PUT /api/ai/patrol/config", s.requireAuth(s.handleUpdatePatrolConfig))
	s.mux.HandleFunc("GET /api/ai/patrol/records", s.requireAuth(s.handleListPatrolRecords))
	s.mux.HandleFunc("POST /api/ai/patrol/run", s.requireAuth(s.handleRunPatrolNow))
	s.mux.HandleFunc("POST /api/ai/test-webhook", s.requireAuth(s.handleTestAIWebhook))

	// Native WebSocket Interactive SSH PTY Terminal + Legacy Relay Compatibility
	s.mux.HandleFunc("GET /api/ws/terminal", s.requireAuth(s.handleWebSocketTerminal))
	s.mux.HandleFunc("POST /api/ws/ticket", s.requireAuth(s.handleIssueRelayTicket))
	s.mux.HandleFunc("GET /api/ws/tcp-relay", s.handleWebSocketTCPRelay)

	// Embedded Lightweight Single-Page Web Application (zero WASM bundle)
	if s.cfg.StaticFS != nil {
		fileServer := http.FileServer(http.FS(s.cfg.StaticFS))
		s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				writeError(w, http.StatusNotFound, "NOT_FOUND", "API 路径不存在")
				return
			}
			cleanPath := strings.TrimPrefix(r.URL.Path, "/")
			if strings.HasPrefix(cleanPath, "assets/") {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			} else {
				w.Header().Set("Cache-Control", "no-cache")
			}
			if cleanPath == "" {
				cleanPath = "index.html"
			}
			if _, err := fs.Stat(s.cfg.StaticFS, cleanPath); err != nil {
				w.Header().Set("Cache-Control", "no-cache")
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

func extractSessionToken(r *http.Request) string {
	hdr := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(hdr), "bearer ") {
		if tok := strings.TrimSpace(hdr[7:]); tok != "" {
			return tok
		}
	}
	// HttpOnly cookie sessions are ONLY accepted for same-origin requests (CSRF protection).
	if !isCookieSessionRequestAllowed(r) {
		return ""
	}
	if c, err := r.Cookie(adminSessionCookieName); err == nil && strings.TrimSpace(c.Value) != "" {
		return strings.TrimSpace(c.Value)
	}
	return ""
}

func isRequestHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https")
}

func (s *Server) setAdminSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     adminSessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(s.cfg.Auth.SessionTTL().Seconds()),
		HttpOnly: true,
		Secure:   isRequestHTTPS(r),
		SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) clearAdminSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     adminSessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   isRequestHTTPS(r),
		SameSite: http.SameSiteStrictMode,
	})
}

func extractClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || host == "" {
		host = r.RemoteAddr
	}
	// Proxy headers are attacker-controlled unless the direct peer is our own local reverse proxy.
	if !isTrustedProxyPeer(r.RemoteAddr) {
		return host
	}
	if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" && net.ParseIP(realIP) != nil {
		return realIP
	}
	if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
		// The RIGHTMOST hop is the one appended by the trusted proxy ($proxy_add_x_forwarded_for);
		// leftmost entries can be forged by the client.
		parts := strings.Split(xff, ",")
		if last := strings.TrimSpace(parts[len(parts)-1]); last != "" && net.ParseIP(last) != nil {
			return last
		}
	}
	return host
}

func (s *Server) currentAuthPubFingerprint() string {
	if s.isDaemonUnlocked() {
		if enc, err := s.cfg.Store.EncryptionInfo(); err == nil && enc.AuthPubKeySHA256 != "" {
			return enc.AuthPubKeySHA256
		}
	}
	if !s.cfg.BlindStore.IsInitialized() {
		return ""
	}
	info := s.cfg.BlindStore.EncryptionInfo(true)
	return info.AuthPubKeySHA256
}

func (s *Server) currentSessionIdleTimeout() time.Duration {
	if s.isDaemonUnlocked() {
		if settings, err := s.cfg.Store.GetSettings(); err == nil {
			if settings.AutoLockMinutes <= 0 {
				return 0
			}
			return time.Duration(settings.AutoLockMinutes) * time.Minute
		}
	}
	return 30 * time.Minute
}

func (s *Server) validateRequestSession(r *http.Request, touch bool) (*auth.Session, bool) {
	if !s.cfg.BlindStore.IsInitialized() {
		return nil, false
	}
	tok := extractSessionToken(r)
	if tok == "" {
		return nil, false
	}
	pubFP := s.currentAuthPubFingerprint()
	sess, err := s.cfg.Auth.ValidateSessionWithIdle(tok, pubFP, s.currentSessionIdleTimeout(), touch)
	if err != nil {
		return nil, false
	}
	return sess, true
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.cfg.BlindStore.IsInitialized() {
			writeError(w, http.StatusUnauthorized, "VAULT_NOT_INIT", vault.ErrVaultNotInit.Error())
			return
		}
		if _, ok := s.validateRequestSession(r, true); !ok {
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "尚未登录管理后台或会话已过期，请重新输入管理员密码")
			return
		}
		next(w, r)
	}
}

func decodeJSON(r *http.Request, dst any, maxBytes int64) error {
	if maxBytes <= 0 {
		maxBytes = 16 * 1024 * 1024
	}
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, maxBytes))
	return dec.Decode(dst)
}

func decodeStrictJSON(r *http.Request, dst any, maxBytes int64) error {
	if maxBytes <= 0 {
		maxBytes = 72 * 1024 * 1024
	}
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, maxBytes))
	dec.DisallowUnknownFields()
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
	switch {
	case errors.As(err, &hkErr):
		writeJSON(w, http.StatusConflict, map[string]any{
			"error":    hkErr.Error(),
			"code":     "HOST_KEY_UNTRUSTED",
			"host_key": hkErr,
		})
	case errors.Is(err, vault.ErrVaultNotInit):
		writeError(w, http.StatusBadRequest, "VAULT_NOT_INIT", err.Error())
	case errors.Is(err, vault.ErrVaultAlreadyInit):
		writeError(w, http.StatusConflict, "VAULT_ALREADY_INIT", err.Error())
	case errors.Is(err, vault.ErrVaultLocked):
		writeError(w, http.StatusConflict, "DAEMON_MIGRATION_REQUIRED", "服务端保险库尚未挂载主密钥，请先使用管理员密码登录一次完成自动挂载")
	case errors.Is(err, vault.ErrRevisionConflict):
		writeError(w, http.StatusConflict, "REVISION_CONFLICT", err.Error())
	case errors.Is(err, vault.ErrRollbackDetected):
		writeError(w, http.StatusConflict, "ROLLBACK_DETECTED", err.Error())
	case errors.Is(err, vault.ErrKDFDowngrade):
		writeError(w, http.StatusConflict, "KDF_DOWNGRADE", err.Error())
	case errors.Is(err, vault.ErrInvalidPassword), errors.Is(err, vault.ErrInvalidSignature):
		writeError(w, http.StatusUnauthorized, "INVALID_PASSWORD", err.Error())
	case errors.Is(err, vault.ErrWeakPassword), errors.Is(err, vault.ErrInvalidInput):
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", err.Error())
	case errors.Is(err, vault.ErrNotFound):
		writeError(w, http.StatusNotFound, "NOT_FOUND", err.Error())
	case errors.Is(err, vault.ErrCorruptedVault):
		writeError(w, http.StatusBadRequest, "CORRUPTED_VAULT", err.Error())
	default:
		writeError(w, http.StatusBadRequest, "OPERATION_FAILED", err.Error())
	}
}

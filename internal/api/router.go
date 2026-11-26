package api

import (
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/aiops"
	"github.com/icaruszezen/ServerNeedSafe/internal/auth"
	"github.com/icaruszezen/ServerNeedSafe/internal/mcp"
	"github.com/icaruszezen/ServerNeedSafe/internal/monitor"
	"github.com/icaruszezen/ServerNeedSafe/internal/sshmanager"
	"github.com/icaruszezen/ServerNeedSafe/internal/updater"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
	"github.com/icaruszezen/ServerNeedSafe/internal/version"
)

const (
	desktopGuardCookieName = "sns_desktop_guard"
	adminSessionCookieName = "sns_admin_session"
)

// Config holds dependencies for the ServerNeedSafe HTTP/WebSocket daemon.
// Store, SSH, Monitor, and AI run natively in-process 7x24 with split encrypted secrets +
// non-encrypted runtime storage so background monitoring & patrol never lock or stall.
type Config struct {
	DeployMode             string // "server" or "desktop"
	Store                  *vault.Store
	SSH                    *sshmanager.Manager
	Monitor                *monitor.Engine
	AI                     *aiops.Service
	Updater                *updater.Service
	Auth                   *auth.Manager
	StaticFS               fs.FS // Embedded frontend dist FS (optional in pure API unit tests)
	OnRestart              func(exePath, backupPath string) error
	DisableAutoUpdateCheck bool
}

type Server struct {
	cfg         Config
	mux         *http.ServeMux
	mcpServer   *mcp.Server
	mcpLoopback *desktopMCPLoopback
}

func NewServer(cfg Config) *Server {
	if cfg.DeployMode == "" {
		cfg.DeployMode = "server"
	}
	if cfg.Auth == nil {
		cfg.Auth, _ = auth.NewManager(auth.DefaultSessionTTL, false)
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
	if cfg.Updater == nil {
		cfg.Updater = updater.NewService(updater.Config{
			DeployMode: cfg.DeployMode,
			Store:      cfg.Store,
			ActiveSSHCount: func() int {
				if cfg.SSH == nil {
					return 0
				}
				return len(cfg.SSH.ListActiveSessions())
			},
			OnRestart:       cfg.OnRestart,
			DisableAutoLoop: cfg.DisableAutoUpdateCheck || cfg.Store == nil,
		})
	}

	s := &Server{
		cfg:         cfg,
		mux:         http.NewServeMux(),
		mcpServer:   mcp.NewServer(cfg.Store, cfg.SSH, cfg.Monitor, cfg.AI),
		mcpLoopback: newDesktopMCPLoopback(),
	}
	if s.cfg.Monitor != nil {
		s.cfg.Monitor.Start()
	}
	if s.cfg.Updater != nil {
		s.cfg.Updater.Start()
	}
	if s.cfg.Store != nil && s.cfg.DeployMode == "desktop" {
		s.cfg.Store.RegisterOnReady(func() {
			s.syncDesktopMCPLoopback()
		})
		if s.cfg.Store.IsReady() {
			s.syncDesktopMCPLoopback()
		}
	}
	s.registerRoutes()
	return s
}

func (s *Server) Close() {
	if s.cfg.Updater != nil {
		s.cfg.Updater.Close()
	}
	if s.mcpLoopback != nil {
		s.mcpLoopback.Close()
	}
	if s.cfg.AI != nil {
		s.cfg.AI.Close()
	}
	if s.cfg.Monitor != nil {
		s.cfg.Monitor.Close()
	}
	if s.cfg.SSH != nil {
		s.cfg.SSH.CloseAllSessions()
	}
	if s.cfg.Store != nil {
		s.cfg.Store.Close()
	}
}

func (s *Server) isDaemonReady() bool {
	return s.cfg.Store != nil && s.cfg.Store.IsReady()
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
			} else if r.URL.Path != "/api/mcp" {
				if origin := r.Header.Get("Origin"); origin != "" && !isSameHostOrigin(r, origin) {
					// Support cross-origin bearer-authenticated sync/API requests cleanly.
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
		}
		next.ServeHTTP(w, r)
	})
}

func isSameHostOrigin(r *http.Request, origin string) bool {
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
	if fwdHost := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Host"), ",")[0]); fwdHost != "" {
		return strings.EqualFold(u.Host, fwdHost)
	}
	return false
}

func (s *Server) registerRoutes() {
	// Desktop bootstrap route (sets HttpOnly local instance cookie)
	s.mux.HandleFunc("GET /__desktop_boot", s.handleDesktopBoot)

	// Public healthcheck
	s.mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		curVer := version.Current()
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":             true,
			"mode":           s.cfg.DeployMode,
			"version":        curVer.Version,
			"build":          curVer,
			"initialized":    s.cfg.Store != nil && s.cfg.Store.IsInitialized(),
			"daemon_mode":    true,
			"daemon_running": s.isDaemonReady() || (s.cfg.Store != nil && !s.cfg.Store.IsInitialized()),
		})
	})

	// Authentication & Session Lifecycle
	s.mux.HandleFunc("GET /api/auth/status", s.handleAuthStatus)
	s.mux.HandleFunc("POST /api/auth/setup", s.handleAuthSetup)
	s.mux.HandleFunc("POST /api/auth/login", s.handleAuthLogin)
	s.mux.HandleFunc("POST /api/auth/logout", s.requireAuth(s.handleAuthLogout))
	s.mux.HandleFunc("POST /api/auth/lock", s.requireAuth(s.handleAuthLock))
	s.mux.HandleFunc("POST /api/auth/password", s.requireAuth(s.handleChangePassword))

	// Vault Security Settings, Password-Encrypted Backup Export/Import & Simplified Cross-Instance Sync
	s.mux.HandleFunc("GET /api/vault/security", s.requireAuth(s.handleGetVaultSecurity))
	s.mux.HandleFunc("PUT /api/vault/settings", s.requireAuth(s.handleUpdateVaultSettings))
	s.mux.HandleFunc("DELETE /api/vault/known-hosts", s.requireAuth(s.handleDeleteKnownHost))
	s.mux.HandleFunc("POST /api/vault/export", s.requireAuth(s.handleExportVaultBackup))
	s.mux.HandleFunc("POST /api/vault/import/file", s.handleImportVaultFile)
	s.mux.HandleFunc("GET /api/vault/sync/snapshot", s.requireAuth(s.handleVaultSyncSnapshot))
	s.mux.HandleFunc("POST /api/vault/sync/apply", s.requireAuth(s.handleVaultSyncApply))
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
	s.mux.HandleFunc("POST /api/credentials/import-file", s.requireAuth(s.handleImportCredentialFile))
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
	s.mux.HandleFunc("POST /api/monitor/security-baseline", s.requireAuth(s.handleAcceptSecurityBaseline))
	s.mux.HandleFunc("POST /api/monitor/test-webhook", s.requireAuth(s.handleTestMonitorWebhook))
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

	// External AI Takeover (MCP Streamable HTTP Gateway, Persistent Scoped Tokens & External HITL Approvals)
	s.mux.HandleFunc("GET /api/ai/mcp/overview", s.requireAuth(s.handleGetMCPOverview))
	s.mux.HandleFunc("PUT /api/ai/mcp/config", s.requireAuth(s.handleUpdateMCPConfig))
	s.mux.HandleFunc("POST /api/ai/mcp/tokens", s.requireAuth(s.handleCreateMCPToken))
	s.mux.HandleFunc("PUT /api/ai/mcp/tokens/{id}", s.requireAuth(s.handleUpdateMCPToken))
	s.mux.HandleFunc("DELETE /api/ai/mcp/tokens/{id}", s.requireAuth(s.handleDeleteMCPToken))
	s.mux.HandleFunc("GET /api/ai/external-approvals", s.requireAuth(s.handleListExternalApprovals))
	s.mux.HandleFunc("POST /api/ai/external-approvals/{id}/resolve", s.requireAuth(s.handleResolveExternalApproval))

	// Built-in MCP Streamable HTTP endpoint (authenticates strictly via scoped MCP Bearer Token, never admin session)
	if s.mcpServer != nil {
		s.mux.Handle("/api/mcp", s.mcpServer.HTTPHandler(false))
	}

	// GitHub Release Auto-Detection, China Mirror Probing & Self-Update
	s.mux.HandleFunc("GET /api/system/update/status", s.requireAuth(s.handleGetUpdateStatus))
	s.mux.HandleFunc("POST /api/system/update/check", s.requireAuth(s.handleCheckUpdateNow))
	s.mux.HandleFunc("POST /api/system/update/mirrors/probe", s.requireAuth(s.handleProbeUpdateMirrors))
	s.mux.HandleFunc("PUT /api/system/update/config", s.requireAuth(s.handleUpdateUpdateConfig))
	s.mux.HandleFunc("POST /api/system/update/skip", s.requireAuth(s.handleSkipUpdateVersion))
	s.mux.HandleFunc("POST /api/system/update/apply", s.requireAuth(s.handleApplyUpdate))

	// Native WebSocket Interactive SSH PTY Terminal
	s.mux.HandleFunc("GET /api/ws/terminal", s.requireAuth(s.handleWebSocketTerminal))

	// Embedded Lightweight Single-Page Web Application
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
		SameSite: http.SameSiteLaxMode,
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
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) currentSessionIdleTimeout() time.Duration {
	if s.isDaemonReady() {
		if settings, err := s.cfg.Store.GetSettings(); err == nil {
			if settings.AutoLockMinutes <= 0 {
				return 0
			}
			return time.Duration(settings.AutoLockMinutes) * time.Minute
		}
	}
	return 0
}

func (s *Server) validateRequestSession(r *http.Request, touch bool) (*auth.Session, bool) {
	if s.cfg.Store == nil || !s.cfg.Store.IsReady() {
		return nil, false
	}
	tok := extractSessionToken(r)
	if tok == "" {
		return nil, false
	}
	authVer := s.cfg.Store.AuthVersion()
	sess, err := s.cfg.Auth.ValidateSessionWithIdle(tok, authVer, s.currentSessionIdleTimeout(), touch)
	if err != nil {
		return nil, false
	}
	return sess, true
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.Store == nil || !s.cfg.Store.IsInitialized() {
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
		writeError(w, http.StatusConflict, "LEGACY_MIGRATION_REQUIRED", err.Error())
	case errors.Is(err, vault.ErrInvalidPassword):
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

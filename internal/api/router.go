package api

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/icaruszezen/ServerNeedSafe/internal/auth"
	"github.com/icaruszezen/ServerNeedSafe/internal/relay"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

const desktopGuardCookieName = "sns_desktop_guard"

// Config holds zero-knowledge dependencies for the HTTP/WS API server.
// Notice that neither vault.ClientVault nor sshmanager.Manager is referenced here:
// the server physically cannot hold admin passwords, DEKs, SSH keys, or VaultState.
type Config struct {
	DeployMode string // "server" or "desktop"
	BlindStore *vault.BlindStore
	Auth       *auth.Manager
	Relay      *relay.Manager
	StaticFS   fs.FS // Embedded frontend dist FS (optional in pure API unit tests)
}

type Server struct {
	cfg Config
	mux *http.ServeMux
}

func NewServer(cfg Config) *Server {
	if cfg.DeployMode == "" {
		cfg.DeployMode = "server"
	}
	if cfg.Relay == nil {
		cfg.Relay = relay.NewManager("")
	}
	s := &Server{
		cfg: cfg,
		mux: http.NewServeMux(),
	}
	s.registerRoutes()
	return s
}

func (s *Server) Close() {
	if s.cfg.Relay != nil {
		s.cfg.Relay.CloseAll()
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
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self' blob:; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self' http: https: ws: wss:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")

		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
			if s.cfg.Auth.DesktopGuardEnabled() {
				c, err := r.Cookie(desktopGuardCookieName)
				if err != nil || !s.cfg.Auth.VerifyDesktopCookie(c.Value) {
					writeError(w, http.StatusForbidden, "FORBIDDEN_ORIGIN", "本地桌面安全隔离策略已拦截外部未授权进程访问")
					return
				}
			} else if origin := r.Header.Get("Origin"); origin != "" {
				// Allow token/signature-based Remote Zero-Knowledge Vault Sync preflights in server mode (never with credentials/cookies)
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS")
				if r.Method == http.MethodOptions {
					w.WriteHeader(http.StatusNoContent)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) registerRoutes() {
	// Desktop bootstrap route (sets HttpOnly local instance cookie)
	s.mux.HandleFunc("GET /__desktop_boot", s.handleDesktopBoot)

	// Public healthcheck
	s.mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":             true,
			"mode":           s.cfg.DeployMode,
			"zero_knowledge": true,
		})
	})

	// Zero-Knowledge Authentication & Lifecycle
	s.mux.HandleFunc("GET /api/auth/status", s.handleAuthStatus)
	s.mux.HandleFunc("POST /api/auth/setup", s.handleAuthSetup)
	s.mux.HandleFunc("POST /api/auth/challenge", s.handleAuthChallenge)
	s.mux.HandleFunc("POST /api/auth/verify", s.handleAuthVerify)
	s.mux.HandleFunc("POST /api/auth/logout", s.requireAuth(s.handleAuthLogout))
	s.mux.HandleFunc("POST /api/auth/lock", s.requireAuth(s.handleAuthLock))
	s.mux.HandleFunc("POST /api/auth/password", s.requireAuth(s.handleChangePassword))

	// Zero-Knowledge Opaque Ciphertext Blob Transport & Backup Import/Export
	s.mux.HandleFunc("GET /api/vault/blob", s.requireAuth(s.handleGetVaultBlob))
	s.mux.HandleFunc("PUT /api/vault/blob", s.requireAuth(s.handlePutVaultBlob))
	s.mux.HandleFunc("GET /api/vault/export", s.requireAuth(s.handleExportVaultBlob))
	s.mux.HandleFunc("POST /api/vault/import", s.handleImportVaultBlob)

	// Zero-Knowledge Blind TCP Relay over WebSocket (carries end-to-end encrypted SSHv2 frames)
	s.mux.HandleFunc("POST /api/ws/ticket", s.requireAuth(s.handleIssueRelayTicket))
	s.mux.HandleFunc("GET /api/ws/tcp-relay", s.handleWebSocketTCPRelay)

	// Embedded Single-Page Web Application + Pre-Compressed Go WASM Engine
	if s.cfg.StaticFS != nil {
		fileServer := http.FileServer(http.FS(s.cfg.StaticFS))
		s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				writeError(w, http.StatusNotFound, "NOT_FOUND", "零知识 API 路径不存在")
				return
			}
			cleanPath := strings.TrimPrefix(r.URL.Path, "/")
			if cleanPath == "sns-zk.wasm" {
				if s.servePrecompressedWASM(w, r) {
					return
				}
			}
			if cleanPath == "" {
				cleanPath = "index.html"
			}
			if _, err := fs.Stat(s.cfg.StaticFS, cleanPath); err != nil {
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

func (s *Server) servePrecompressedWASM(w http.ResponseWriter, r *http.Request) bool {
	gzFile, err := s.cfg.StaticFS.Open("sns-zk.wasm.gz")
	if err != nil {
		return false
	}
	defer gzFile.Close()

	w.Header().Set("Content-Type", "application/wasm")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Vary", "Accept-Encoding")

	if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		_, _ = io.Copy(w, gzFile)
		return true
	}

	gzReader, err := gzip.NewReader(gzFile)
	if err != nil {
		return false
	}
	defer gzReader.Close()
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, gzReader)
	return true
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

func (s *Server) currentAuthPubFingerprint() string {
	if !s.cfg.BlindStore.IsInitialized() {
		return ""
	}
	info := s.cfg.BlindStore.EncryptionInfo(true)
	return info.AuthPubKeySHA256
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.cfg.BlindStore.IsInitialized() {
			writeError(w, http.StatusUnauthorized, "VAULT_NOT_INIT", vault.ErrVaultNotInit.Error())
			return
		}
		tok := extractBearerToken(r)
		pubFP := s.currentAuthPubFingerprint()
		if _, err := s.cfg.Auth.ValidateSession(tok, pubFP); err != nil {
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "尚未通过零知识管理员验证或会话已失效")
			return
		}
		next(w, r)
	}
}

// decodeStrictJSON decodes JSON with DisallowUnknownFields so any accidental or legacy
// plaintext field (such as "password") is strictly rejected at the wire boundary.
func decodeStrictJSON(r *http.Request, dst any, maxBytes int64) error {
	if maxBytes <= 0 {
		maxBytes = 72 * 1024 * 1024 // accommodates base64 of 64 MiB max vault container
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
	switch {
	case errors.Is(err, vault.ErrVaultNotInit):
		writeError(w, http.StatusBadRequest, "VAULT_NOT_INIT", err.Error())
	case errors.Is(err, vault.ErrVaultAlreadyInit):
		writeError(w, http.StatusConflict, "VAULT_ALREADY_INIT", err.Error())
	case errors.Is(err, vault.ErrRevisionConflict):
		writeError(w, http.StatusConflict, "REVISION_CONFLICT", err.Error())
	case errors.Is(err, vault.ErrInvalidPassword), errors.Is(err, vault.ErrInvalidSignature):
		writeError(w, http.StatusUnauthorized, "INVALID_PASSWORD", err.Error())
	case errors.Is(err, vault.ErrCorruptedVault):
		writeError(w, http.StatusBadRequest, "CORRUPTED_VAULT", err.Error())
	default:
		writeError(w, http.StatusBadRequest, "OPERATION_FAILED", err.Error())
	}
}

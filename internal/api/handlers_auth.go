package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

func (s *Server) handleDesktopBoot(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("boot")
	cookieVal, ok := s.cfg.Auth.VerifyDesktopBootCode(code)
	if !ok {
		http.Error(w, "Invalid desktop bootstrap token", http.StatusForbidden)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     desktopGuardCookieName,
		Value:    cookieVal,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) buildStatusPayload(authenticated bool) map[string]any {
	initialized := s.cfg.Store != nil && s.cfg.Store.IsInitialized()
	daemonRunning := s.isDaemonReady()
	legacyPending := s.cfg.Store != nil && s.cfg.Store.IsLegacyMigrationPending()

	vStatus := vault.StatusUninitialized
	if initialized {
		if authenticated {
			vStatus = vault.StatusUnlocked
		} else {
			vStatus = vault.StatusLocked
		}
	}

	var encInfo *vault.EncryptionInfo
	if s.cfg.Store != nil {
		encInfo, _ = s.cfg.Store.EncryptionInfo()
	}

	resp := map[string]any{
		"initialized":              initialized,
		"vault_status":             vStatus,
		"authenticated":            authenticated,
		"deploy_mode":              s.cfg.DeployMode,
		"daemon_running":           daemonRunning,
		"legacy_migration_pending": legacyPending,
		"session_ttl_hours":        int(s.cfg.Auth.SessionTTL().Hours()),
		"encryption":               encInfo,
	}

	if authenticated && s.cfg.Store != nil {
		resp["storage"] = s.cfg.Store.StorageInfo()
		resp["active_sessions"] = s.cfg.Auth.ActiveSessionCount()
		if s.cfg.SSH != nil {
			resp["active_ssh_tabs"] = len(s.cfg.SSH.ListActiveSessions())
		}
		if daemonRunning {
			if settings, err := s.cfg.Store.GetSettings(); err == nil {
				resp["settings"] = settings
			}
			if _, _, _, patrolCfg, err := s.cfg.Store.GetAISettingsView(); err == nil {
				resp["patrol_enabled"] = patrolCfg.Enabled
			}
		}
	}
	return resp
}

func (s *Server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	_, authenticated := s.validateRequestSession(r, false)
	writeJSON(w, http.StatusOK, s.buildStatusPayload(authenticated))
}

func (s *Server) handleAuthSetup(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &body, 64*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "初始化请求格式错误")
		return
	}

	clientIP := extractClientIP(r)
	err := s.cfg.Store.Setup(body.Password, clientIP)
	body.Password = ""
	if err != nil {
		writeDomainError(w, err)
		return
	}

	if s.cfg.Monitor != nil {
		s.cfg.Monitor.Wake()
	}
	if s.cfg.AI != nil {
		s.cfg.AI.NotifyPatrolConfigUpdated()
	}

	s.cfg.Auth.ResetAuthFailures()
	sess, err := s.cfg.Auth.CreateSession(s.cfg.Store.AuthVersion(), clientIP, r.UserAgent())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "SESSION_ERROR", err.Error())
		return
	}
	s.setAdminSessionCookie(w, r, sess.Token)

	settings, _ := s.cfg.Store.GetSettings()
	encInfo, _ := s.cfg.Store.EncryptionInfo()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"token":      sess.Token,
		"encryption": encInfo,
		"settings":   settings,
		"status":     s.buildStatusPayload(true),
	})
}

func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if retrySec, err := s.cfg.Auth.CheckRateLimit(); err != nil {
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error":           err.Error(),
			"code":            "RATE_LIMITED",
			"retry_after_sec": retrySec,
		})
		return
	}
	if s.cfg.Store == nil || !s.cfg.Store.IsInitialized() {
		writeError(w, http.StatusBadRequest, "VAULT_NOT_INIT", vault.ErrVaultNotInit.Error())
		return
	}

	var body struct {
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &body, 64*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "登录请求格式无效")
		return
	}
	if strings.TrimSpace(body.Password) == "" {
		writeError(w, http.StatusUnauthorized, "INVALID_PASSWORD", "请输入管理员密码")
		return
	}

	clientIP := extractClientIP(r)
	wasPendingMigration := s.cfg.Store.IsLegacyMigrationPending()
	authErr := s.cfg.Store.LoginWithPassword(body.Password, clientIP)
	body.Password = ""

	if authErr != nil {
		failCnt, lockedSec := s.cfg.Auth.RecordAuthFailure()
		msg := authErr.Error()
		if lockedSec > 0 {
			msg = fmt.Sprintf("%s（连续失败 %d 次，已触发 %d 秒防爆破冷却保护）", msg, failCnt, lockedSec)
		}
		if s.isDaemonReady() {
			s.cfg.Store.RecordAuditAsync("auth.login_failed", "web-console", "Web 管理控制台登录密码校验失败", clientIP, false)
		}
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error":           msg,
			"code":            "INVALID_PASSWORD",
			"failed_attempts": failCnt,
			"retry_after_sec": lockedSec,
		})
		return
	}

	if wasPendingMigration {
		if s.cfg.Monitor != nil {
			s.cfg.Monitor.Wake()
		}
		if s.cfg.AI != nil {
			s.cfg.AI.NotifyPatrolConfigUpdated()
		}
	} else {
		s.cfg.Store.RecordAuditAsync("auth.login", "web-console", "管理员登录 Web 管理控制台", clientIP, true)
	}

	s.cfg.Auth.ResetAuthFailures()
	sess, err := s.cfg.Auth.CreateSession(s.cfg.Store.AuthVersion(), clientIP, r.UserAgent())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "SESSION_ERROR", err.Error())
		return
	}
	s.setAdminSessionCookie(w, r, sess.Token)

	settings, _ := s.cfg.Store.GetSettings()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"token":    sess.Token,
		"settings": settings,
		"status":   s.buildStatusPayload(true),
	})
}

// handleAuthLogout revokes ONLY the caller's Web session without affecting 7x24 monitoring & AI patrol.
func (s *Server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	tok := extractSessionToken(r)
	s.cfg.Auth.RevokeSession(tok)
	s.clearAdminSessionCookie(w, r)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":             true,
		"daemon_running": s.isDaemonReady(),
	})
}

// handleAuthLock revokes ALL active Web sessions across browsers/devices and closes interactive PTY terminals,
// while 7x24 monitoring and scheduled AI patrol keep running uninterrupted.
func (s *Server) handleAuthLock(w http.ResponseWriter, r *http.Request) {
	s.cfg.Auth.RevokeAll()
	if s.cfg.SSH != nil {
		s.cfg.SSH.CloseAllSessions()
	}
	s.clearAdminSessionCookie(w, r)
	if s.isDaemonReady() {
		s.cfg.Store.RecordAuditAsync("auth.sessions_revoked", "web-console", "管理员注销全部活跃 Web 会话并断开交互终端（7×24 后台监控与巡检保持运行）", extractClientIP(r), true)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":             true,
		"daemon_running": s.isDaemonReady(),
	})
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := decodeJSON(r, &body, 64*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "修改密码请求格式无效")
		return
	}

	clientIP := extractClientIP(r)
	err := s.cfg.Store.ChangePassword(body.OldPassword, body.NewPassword, clientIP)
	body.OldPassword = ""
	body.NewPassword = ""
	if err != nil {
		writeDomainError(w, err)
		return
	}

	s.cfg.Auth.RevokeAll()
	sess, err := s.cfg.Auth.CreateSession(s.cfg.Store.AuthVersion(), clientIP, r.UserAgent())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "SESSION_ERROR", err.Error())
		return
	}
	s.setAdminSessionCookie(w, r, sess.Token)
	encInfo, _ := s.cfg.Store.EncryptionInfo()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"token":      sess.Token,
		"encryption": encInfo,
	})
}

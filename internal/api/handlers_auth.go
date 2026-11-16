package api

import (
	"fmt"
	"io"
	"net/http"
	"time"

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

func (s *Server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	vStatus := s.cfg.Store.Status()
	authenticated := false
	var settings *vault.AppSettings

	if vStatus == vault.StatusUnlocked {
		tok := extractBearerToken(r)
		if _, err := s.cfg.Auth.ValidateSession(tok); err == nil {
			authenticated = true
			settings, _ = s.cfg.Store.GetSettings()
		}
	}

	encInfo, _ := s.cfg.Store.EncryptionInfo()
	writeJSON(w, http.StatusOK, map[string]any{
		"vault_status":  vStatus,
		"authenticated": authenticated,
		"deploy_mode":   s.cfg.DeployMode,
		"vault_path":    s.cfg.Store.FilePath(),
		"encryption":    encInfo,
		"settings":      settings,
	})
}

func (s *Server) handleAuthSetup(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "请求数据格式错误")
		return
	}
	clientIP := extractClientIP(r)
	if err := s.cfg.Store.Setup(body.Password, clientIP); err != nil {
		writeDomainError(w, err)
		return
	}
	s.cfg.Auth.ResetAuthFailures()
	sess, err := s.cfg.Auth.CreateSession(clientIP, r.UserAgent())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "SESSION_ERROR", err.Error())
		return
	}
	settings, _ := s.cfg.Store.GetSettings()
	writeJSON(w, http.StatusOK, map[string]any{
		"token":    sess.Token,
		"settings": settings,
	})
}

func (s *Server) handleAuthUnlock(w http.ResponseWriter, r *http.Request) {
	if retrySec, err := s.cfg.Auth.CheckRateLimit(); err != nil {
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error":           err.Error(),
			"code":            "RATE_LIMITED",
			"retry_after_sec": retrySec,
		})
		return
	}

	var body struct {
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "请求数据格式错误")
		return
	}

	clientIP := extractClientIP(r)
	if err := s.cfg.Store.UnlockOrVerify(body.Password, clientIP); err != nil {
		failCnt, lockedSec := s.cfg.Auth.RecordAuthFailure()
		msg := err.Error()
		if lockedSec > 0 {
			msg = fmt.Sprintf("%s（连续失败 %d 次，已触发 %d 秒防爆破冷却保护）", msg, failCnt, lockedSec)
		}
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error":           msg,
			"code":            "INVALID_PASSWORD",
			"failed_attempts": failCnt,
			"retry_after_sec": lockedSec,
		})
		return
	}

	s.cfg.Auth.ResetAuthFailures()
	sess, err := s.cfg.Auth.CreateSession(clientIP, r.UserAgent())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "SESSION_ERROR", err.Error())
		return
	}
	settings, _ := s.cfg.Store.GetSettings()
	writeJSON(w, http.StatusOK, map[string]any{
		"token":    sess.Token,
		"settings": settings,
	})
}

func (s *Server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	tok := extractBearerToken(r)
	s.cfg.Auth.RevokeSession(tok)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleAuthLock(w http.ResponseWriter, r *http.Request) {
	clientIP := extractClientIP(r)
	s.cfg.Store.Lock("管理员手动锁定保险库", clientIP)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "请求数据格式错误")
		return
	}
	clientIP := extractClientIP(r)
	if err := s.cfg.Store.ChangePassword(body.OldPassword, body.NewPassword, clientIP); err != nil {
		writeDomainError(w, err)
		return
	}
	// Rotate all active sessions and issue a fresh token for the caller
	s.cfg.Auth.RevokeAll()
	sess, err := s.cfg.Auth.CreateSession(clientIP, r.UserAgent())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "SESSION_ERROR", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":    true,
		"token": sess.Token,
	})
}

func (s *Server) handleVaultExport(w http.ResponseWriter, r *http.Request) {
	raw, err := s.cfg.Store.ExportEncryptedBytes(extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	filename := fmt.Sprintf("ServerNeedSafe-vault-%s.sns", time.Now().Format("20060102-150405"))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

func (s *Server) handleVaultImport(w http.ResponseWriter, r *http.Request) {
	if retrySec, err := s.cfg.Auth.CheckRateLimit(); err != nil {
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error":           err.Error(),
			"code":            "RATE_LIMITED",
			"retry_after_sec": retrySec,
		})
		return
	}

	if err := r.ParseMultipartForm(64 * 1024 * 1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_MULTIPART", "解析上传的加密备份包失败")
		return
	}
	password := r.FormValue("password")
	file, _, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "MISSING_FILE", "请选择要恢复的 .sns 加密备份文件")
		return
	}
	defer file.Close()

	raw, err := io.ReadAll(io.LimitReader(file, 64*1024*1024))
	if err != nil {
		writeError(w, http.StatusBadRequest, "READ_FAILED", "读取备份文件失败")
		return
	}

	clientIP := extractClientIP(r)
	if err := s.cfg.Store.ImportEncryptedVault(raw, password, clientIP); err != nil {
		s.cfg.Auth.RecordAuthFailure()
		writeDomainError(w, err)
		return
	}

	s.cfg.Auth.ResetAuthFailures()
	s.cfg.Auth.RevokeAll()
	sess, err := s.cfg.Auth.CreateSession(clientIP, r.UserAgent())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "SESSION_ERROR", err.Error())
		return
	}
	settings, _ := s.cfg.Store.GetSettings()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"token":    sess.Token,
		"settings": settings,
	})
}

func (s *Server) handleVaultSecurity(w http.ResponseWriter, r *http.Request) {
	encInfo, _ := s.cfg.Store.EncryptionInfo()
	settings, err := s.cfg.Store.GetSettings()
	if err != nil {
		writeDomainError(w, err)
		return
	}
	knownHosts, _ := s.cfg.Store.ListKnownHosts()
	auditLogs, _ := s.cfg.Store.ListAuditLogs(200)

	writeJSON(w, http.StatusOK, map[string]any{
		"deploy_mode":     s.cfg.DeployMode,
		"vault_path":      s.cfg.Store.FilePath(),
		"encryption":      encInfo,
		"settings":        settings,
		"known_hosts":     knownHosts,
		"audit_logs":      auditLogs,
		"active_sessions": s.cfg.Auth.ActiveSessionCount(),
		"active_ssh_tabs": len(s.cfg.SSH.ListActiveSessions()),
	})
}

func (s *Server) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	var in vault.AppSettings
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "设置参数格式无效")
		return
	}
	updated, err := s.cfg.Store.UpdateSettings(in, extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"settings": updated})
}

func (s *Server) handleDeleteKnownHost(w http.ResponseWriter, r *http.Request) {
	addr := r.URL.Query().Get("address")
	if err := s.cfg.Store.DeleteKnownHost(addr, extractClientIP(r)); err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

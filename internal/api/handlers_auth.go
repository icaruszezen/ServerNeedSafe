package api

import (
	"encoding/base64"
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
	initialized := s.cfg.BlindStore.IsInitialized()
	vStatus := vault.StatusUninitialized
	if initialized {
		if authenticated {
			vStatus = vault.StatusUnlocked
		} else {
			vStatus = vault.StatusLocked
		}
	}

	autoUnlockEnabled := s.cfg.KeyMgr != nil && s.cfg.KeyMgr.HasLocalKey()
	daemonRunning := s.isDaemonUnlocked()

	var encInfo *vault.EncryptionInfo
	if authenticated && daemonRunning {
		if info, err := s.cfg.Store.EncryptionInfo(); err == nil {
			encInfo = info
		}
	}
	if encInfo == nil {
		encInfo = s.cfg.BlindStore.EncryptionInfo(authenticated)
	}

	resp := map[string]any{
		"initialized":         initialized,
		"vault_status":        vStatus,
		"authenticated":       authenticated,
		"deploy_mode":         s.cfg.DeployMode,
		"daemon_running":      daemonRunning,
		"migration_pending":   initialized && !daemonRunning && s.isMigrationPending(),
		"auto_unlock_enabled": autoUnlockEnabled,
		"encryption":          encInfo,
	}

	if authenticated {
		resp["vault_path"] = s.cfg.BlindStore.FilePath()
		resp["active_sessions"] = s.cfg.Auth.ActiveSessionCount()
		resp["active_relays"] = s.cfg.Relay.ActiveCount()
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
		Password     string `json:"password,omitempty"`
		BlobB64      string `json:"blob_b64,omitempty"`
		SignatureB64 string `json:"signature_b64,omitempty"`
	}
	if err := decodeStrictJSON(r, &body, 0); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "初始化请求格式错误")
		return
	}

	clientIP := extractClientIP(r)

	// Path A: Native Web Admin Console setup (creates SNSVAULT v2 + .vault.key auto-mount seal)
	if body.Password != "" {
		if err := s.cfg.Store.Setup(body.Password, clientIP); err != nil {
			body.Password = ""
			writeDomainError(w, err)
			return
		}
		body.Password = ""

		if s.cfg.KeyMgr != nil {
			_ = s.cfg.KeyMgr.SaveFromStore(s.cfg.Store)
		}
		s.setMigrationPending(false)
		if s.cfg.Monitor != nil {
			s.cfg.Monitor.Wake()
		}
		if s.cfg.AI != nil {
			s.cfg.AI.NotifyPatrolConfigUpdated()
		}

		s.cfg.Auth.ResetAuthFailures()
		pubFP := s.currentAuthPubFingerprint()
		sess, err := s.cfg.Auth.CreateSession(pubFP, clientIP, r.UserAgent())
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
		return
	}

	// Path B: Remote signed ciphertext container initialization
	rawBlob, err := base64.StdEncoding.DecodeString(body.BlobB64)
	if err != nil || len(rawBlob) == 0 {
		writeError(w, http.StatusBadRequest, "BAD_BLOB", "无效的加密容器编码")
		return
	}
	sig, err := base64.StdEncoding.DecodeString(body.SignatureB64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "BAD_SIGNATURE", "无效的签名编码")
		return
	}
	pubFP, encInfo, err := s.cfg.BlindStore.InitializeBlob(rawBlob, sig)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	s.setMigrationPending(true)
	s.cfg.Auth.ResetAuthFailures()
	sess, err := s.cfg.Auth.CreateSession(pubFP, clientIP, r.UserAgent())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "SESSION_ERROR", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"token":      sess.Token,
		"encryption": encInfo,
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
	if !s.cfg.BlindStore.IsInitialized() {
		writeError(w, http.StatusBadRequest, "VAULT_NOT_INIT", vault.ErrVaultNotInit.Error())
		return
	}

	var body struct {
		Password string `json:"password"`
	}
	if err := decodeStrictJSON(r, &body, 64*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "登录请求格式无效")
		return
	}
	if strings.TrimSpace(body.Password) == "" {
		writeError(w, http.StatusUnauthorized, "INVALID_PASSWORD", "请输入管理员密码")
		return
	}

	clientIP := extractClientIP(r)
	var authErr error

	if s.isDaemonUnlocked() {
		// Fast native Argon2id check against wrapped DEK (~45ms) without interrupting 7x24 tasks
		authErr = s.cfg.Store.VerifyPassword(body.Password)
		if authErr == nil {
			if s.cfg.KeyMgr != nil && !s.cfg.KeyMgr.HasLocalKey() {
				_ = s.cfg.KeyMgr.SaveFromStore(s.cfg.Store)
			}
			s.setMigrationPending(false)
			s.cfg.Store.RecordAuditAsync("auth.login", "web-console", "管理员登录 Web 管理控制台", clientIP, true)
		}
	} else {
		// Seamless migration path: legacy vault.sns without .vault.key is decrypted & auto-mounted on first login!
		authErr = s.cfg.Store.UnlockOrVerify(body.Password, clientIP)
		if authErr == nil {
			if s.cfg.KeyMgr != nil {
				_ = s.cfg.KeyMgr.SaveFromStore(s.cfg.Store)
			}
			s.setMigrationPending(false)
			if s.cfg.Monitor != nil {
				s.cfg.Monitor.Wake()
			}
			if s.cfg.AI != nil {
				s.cfg.AI.NotifyPatrolConfigUpdated()
			}
		}
	}
	body.Password = ""

	if authErr != nil {
		failCnt, lockedSec := s.cfg.Auth.RecordAuthFailure()
		msg := authErr.Error()
		if lockedSec > 0 {
			msg = fmt.Sprintf("%s（连续失败 %d 次，已触发 %d 秒防爆破冷却保护）", msg, failCnt, lockedSec)
		}
		if s.isDaemonUnlocked() {
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

	s.cfg.Auth.ResetAuthFailures()
	pubFP := s.currentAuthPubFingerprint()
	sess, err := s.cfg.Auth.CreateSession(pubFP, clientIP, r.UserAgent())
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

func (s *Server) handleAuthChallenge(w http.ResponseWriter, r *http.Request) {
	if retrySec, err := s.cfg.Auth.CheckRateLimit(); err != nil {
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error":           err.Error(),
			"code":            "RATE_LIMITED",
			"retry_after_sec": retrySec,
		})
		return
	}

	params, err := s.cfg.BlindStore.PublicChallengeParams()
	if err != nil {
		writeDomainError(w, err)
		return
	}
	ch, err := s.cfg.Auth.IssueChallenge()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "CHALLENGE_ERROR", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"challenge_id": ch.ID,
		"nonce":        ch.Nonce,
		"kdf":          params,
	})
}

func (s *Server) handleAuthVerify(w http.ResponseWriter, r *http.Request) {
	if retrySec, err := s.cfg.Auth.CheckRateLimit(); err != nil {
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error":           err.Error(),
			"code":            "RATE_LIMITED",
			"retry_after_sec": retrySec,
		})
		return
	}

	var body struct {
		ChallengeID  string `json:"challenge_id"`
		SignatureB64 string `json:"signature_b64"`
	}
	if err := decodeStrictJSON(r, &body, 64*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "挑战响应格式无效")
		return
	}
	sig, err := base64.StdEncoding.DecodeString(body.SignatureB64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "BAD_SIGNATURE", "签名编码无效")
		return
	}

	nonce, err := s.cfg.Auth.ConsumeChallenge(body.ChallengeID)
	if err != nil {
		failCnt, lockedSec := s.cfg.Auth.RecordAuthFailure()
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error":           "认证挑战已失效或已被使用，请重试",
			"code":            "CHALLENGE_EXPIRED",
			"failed_attempts": failCnt,
			"retry_after_sec": lockedSec,
		})
		return
	}

	pubFP, err := s.cfg.BlindStore.VerifyClientChallenge(body.ChallengeID, nonce, sig)
	if err != nil {
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
	sess, err := s.cfg.Auth.CreateSession(pubFP, extractClientIP(r), r.UserAgent())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "SESSION_ERROR", err.Error())
		return
	}
	s.setAdminSessionCookie(w, r, sess.Token)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"token":      sess.Token,
		"encryption": s.cfg.BlindStore.EncryptionInfo(true),
	})
}

// handleAuthLogout revokes ONLY the caller's Web session without stopping 7x24 monitoring & AI patrol.
func (s *Server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	tok := extractSessionToken(r)
	s.cfg.Auth.RevokeSession(tok)
	s.clearAdminSessionCookie(w, r)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":             true,
		"daemon_running": s.isDaemonUnlocked(),
	})
}

// handleAuthLock revokes ALL active Web admin sessions across browsers/devices while keeping
// the backend 7x24 SSH status monitoring and AI scheduled patrol daemon running uninterrupted.
func (s *Server) handleAuthLock(w http.ResponseWriter, r *http.Request) {
	s.cfg.Auth.RevokeAll()
	if s.cfg.Relay != nil {
		s.cfg.Relay.CloseAll()
	}
	s.clearAdminSessionCookie(w, r)
	if s.isDaemonUnlocked() {
		s.cfg.Store.RecordAuditAsync("auth.sessions_revoked", "web-console", "管理员锁定控制台并注销全部活跃 Web 会话（7×24 后台监控与巡检保持运行）", extractClientIP(r), true)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":             true,
		"daemon_running": s.isDaemonUnlocked(),
	})
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		OldPassword          string `json:"old_password,omitempty"`
		NewPassword          string `json:"new_password,omitempty"`
		ExpectedPrevRevision uint64 `json:"expected_prev_revision,omitempty"`
		BlobB64              string `json:"blob_b64,omitempty"`
		OldSignatureB64      string `json:"old_signature_b64,omitempty"`
		NewSignatureB64      string `json:"new_signature_b64,omitempty"`
	}
	if err := decodeStrictJSON(r, &body, 0); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "修改密码请求格式无效")
		return
	}

	clientIP := extractClientIP(r)

	if body.OldPassword != "" || body.NewPassword != "" {
		err := s.cfg.Store.ChangePassword(body.OldPassword, body.NewPassword, clientIP)
		body.OldPassword = ""
		body.NewPassword = ""
		if err != nil {
			writeDomainError(w, err)
			return
		}
		if s.cfg.KeyMgr != nil {
			_ = s.cfg.KeyMgr.SaveFromStore(s.cfg.Store)
		}
		s.setMigrationPending(false)

		newPubFP := s.currentAuthPubFingerprint()
		s.cfg.Auth.RevokeAll()
		sess, err := s.cfg.Auth.CreateSession(newPubFP, clientIP, r.UserAgent())
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
		return
	}

	rawBlob, err := base64.StdEncoding.DecodeString(body.BlobB64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "BAD_BLOB", "无效的加密容器编码")
		return
	}
	oldSig, err1 := base64.StdEncoding.DecodeString(body.OldSignatureB64)
	newSig, err2 := base64.StdEncoding.DecodeString(body.NewSignatureB64)
	if err1 != nil || err2 != nil {
		writeError(w, http.StatusBadRequest, "BAD_SIGNATURE", "无效的双重轮换签名编码")
		return
	}

	newPubFP, encInfo, err := s.cfg.BlindStore.RotatePasswordBlob(rawBlob, body.ExpectedPrevRevision, oldSig, newSig)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	if s.cfg.Store != nil {
		s.cfg.Store.Lock("远端轮换密码后等待新主密钥挂载", clientIP)
	}
	s.setMigrationPending(true)
	s.cfg.Auth.RevokeAll()
	sess, err := s.cfg.Auth.CreateSession(newPubFP, clientIP, r.UserAgent())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "SESSION_ERROR", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"token":      sess.Token,
		"encryption": encInfo,
	})
}

func (s *Server) handleUpdateVaultKDF(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password     string `json:"password"`
		KDFMemoryKiB uint32 `json:"kdf_memory_kib"`
		KDFTime      uint32 `json:"kdf_time"`
		KDFThreads   uint8  `json:"kdf_threads"`
	}
	if err := decodeStrictJSON(r, &body, 64*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "KDF 参数更新请求格式无效")
		return
	}
	if body.KDFTime == 0 {
		body.KDFTime = vault.DefaultKDFTime
	}
	if body.KDFThreads == 0 {
		body.KDFThreads = vault.DefaultKDFThreads
	}

	clientIP := extractClientIP(r)
	encInfo, err := s.cfg.Store.UpdateKDFParams(body.Password, body.KDFTime, body.KDFMemoryKiB, body.KDFThreads, clientIP)
	body.Password = ""
	if err != nil {
		writeDomainError(w, err)
		return
	}
	if s.cfg.KeyMgr != nil {
		_ = s.cfg.KeyMgr.SaveFromStore(s.cfg.Store)
	}
	s.setMigrationPending(false)

	newPubFP := s.currentAuthPubFingerprint()
	s.cfg.Auth.RevokeAll()
	sess, err := s.cfg.Auth.CreateSession(newPubFP, clientIP, r.UserAgent())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "SESSION_ERROR", err.Error())
		return
	}
	s.setAdminSessionCookie(w, r, sess.Token)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"token":      sess.Token,
		"encryption": encInfo,
	})
}

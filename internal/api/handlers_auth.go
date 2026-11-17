package api

import (
	"encoding/base64"
	"fmt"
	"net/http"

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
	initialized := s.cfg.BlindStore.IsInitialized()
	authenticated := false
	vStatus := vault.StatusUninitialized

	if initialized {
		vStatus = vault.StatusLocked
		tok := extractBearerToken(r)
		pubFP := s.currentAuthPubFingerprint()
		if _, err := s.cfg.Auth.ValidateSession(tok, pubFP); err == nil {
			authenticated = true
			vStatus = vault.StatusUnlocked
		}
	}

	resp := map[string]any{
		"initialized":    initialized,
		"vault_status":   vStatus,
		"authenticated":  authenticated,
		"deploy_mode":    s.cfg.DeployMode,
		"zero_knowledge": true,
		"vault_path":     s.cfg.BlindStore.FilePath(),
		"encryption":     s.cfg.BlindStore.EncryptionInfo(authenticated),
	}
	if authenticated {
		resp["active_sessions"] = s.cfg.Auth.ActiveSessionCount()
		resp["active_relays"] = s.cfg.Relay.ActiveCount()
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleAuthSetup(w http.ResponseWriter, r *http.Request) {
	var body struct {
		BlobB64      string `json:"blob_b64"`
		SignatureB64 string `json:"signature_b64"`
	}
	if err := decodeStrictJSON(r, &body, 0); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "零知识初始化请求格式错误（严禁传输明文密码）")
		return
	}
	rawBlob, err := base64.StdEncoding.DecodeString(body.BlobB64)
	if err != nil || len(rawBlob) == 0 {
		writeError(w, http.StatusBadRequest, "BAD_BLOB", "无效的加密容器编码")
		return
	}
	sig, err := base64.StdEncoding.DecodeString(body.SignatureB64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "BAD_SIGNATURE", "无效的零知识签名编码")
		return
	}

	pubFP, encInfo, err := s.cfg.BlindStore.InitializeBlob(rawBlob, sig)
	if err != nil {
		writeDomainError(w, err)
		return
	}

	s.cfg.Auth.ResetAuthFailures()
	sess, err := s.cfg.Auth.CreateSession(pubFP, extractClientIP(r), r.UserAgent())
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
		writeError(w, http.StatusBadRequest, "BAD_JSON", "零知识挑战响应格式无效（严禁传输明文密码）")
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
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"token":      sess.Token,
		"encryption": s.cfg.BlindStore.EncryptionInfo(true),
	})
}

func (s *Server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	tok := extractBearerToken(r)
	s.cfg.Auth.RevokeSession(tok)
	if s.cfg.Auth.ActiveSessionCount() == 0 {
		s.cfg.Relay.CloseAll()
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleAuthLock(w http.ResponseWriter, r *http.Request) {
	s.cfg.Auth.RevokeAll()
	s.cfg.Relay.CloseAll()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ExpectedPrevRevision uint64 `json:"expected_prev_revision"`
		BlobB64              string `json:"blob_b64"`
		OldSignatureB64      string `json:"old_signature_b64"`
		NewSignatureB64      string `json:"new_signature_b64"`
	}
	if err := decodeStrictJSON(r, &body, 0); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "密钥轮换数据包格式无效（严禁传输明文密码）")
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

	s.cfg.Auth.RevokeAll()
	sess, err := s.cfg.Auth.CreateSession(newPubFP, extractClientIP(r), r.UserAgent())
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

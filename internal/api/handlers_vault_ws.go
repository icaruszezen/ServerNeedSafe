package api

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"time"
)

func (s *Server) handleGetVaultBlob(w http.ResponseWriter, r *http.Request) {
	raw, vaultID, rev, err := s.cfg.BlindStore.ReadBlob()
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"vault_id":   vaultID,
		"revision":   rev,
		"blob_b64":   base64.StdEncoding.EncodeToString(raw),
		"encryption": s.cfg.BlindStore.EncryptionInfo(true),
	})
}

func (s *Server) handlePutVaultBlob(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ExpectedPrevRevision uint64 `json:"expected_prev_revision"`
		BlobB64              string `json:"blob_b64"`
		SignatureB64         string `json:"signature_b64"`
	}
	if err := decodeStrictJSON(r, &body, 0); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "加密同步数据包格式无效")
		return
	}
	rawBlob, err := base64.StdEncoding.DecodeString(body.BlobB64)
	if err != nil || len(rawBlob) == 0 {
		writeError(w, http.StatusBadRequest, "BAD_BLOB", "无效的加密数据包编码")
		return
	}
	sig, err := base64.StdEncoding.DecodeString(body.SignatureB64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "BAD_SIGNATURE", "无效的签名编码")
		return
	}

	encInfo, err := s.cfg.BlindStore.PutBlob(rawBlob, body.ExpectedPrevRevision, sig)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"encryption": encInfo,
	})
}

func (s *Server) handleExportVaultBlob(w http.ResponseWriter, r *http.Request) {
	raw, _, _, err := s.cfg.BlindStore.ReadBlob()
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

func (s *Server) handleImportVaultBlob(w http.ResponseWriter, r *http.Request) {
	if retrySec, err := s.cfg.Auth.CheckRateLimit(); err != nil {
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error":           err.Error(),
			"code":            "RATE_LIMITED",
			"retry_after_sec": retrySec,
		})
		return
	}

	var body struct {
		BlobB64               string `json:"blob_b64"`
		NewSignatureB64       string `json:"new_signature_b64"`
		OverwriteSignatureB64 string `json:"overwrite_signature_b64,omitempty"`
	}
	if err := decodeStrictJSON(r, &body, 0); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "加密备份恢复请求格式无效")
		return
	}
	rawBlob, err := base64.StdEncoding.DecodeString(body.BlobB64)
	if err != nil || len(rawBlob) == 0 {
		writeError(w, http.StatusBadRequest, "BAD_BLOB", "无效的加密备份编码")
		return
	}
	newSig, err := base64.StdEncoding.DecodeString(body.NewSignatureB64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "BAD_SIGNATURE", "无效的备份签名编码")
		return
	}
	var overwriteSig []byte
	if body.OverwriteSignatureB64 != "" {
		overwriteSig, err = base64.StdEncoding.DecodeString(body.OverwriteSignatureB64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "BAD_SIGNATURE", "无效的覆盖授权签名编码")
			return
		}
	}

	pubFP, encInfo, err := s.cfg.BlindStore.ImportBlob(rawBlob, newSig, overwriteSig)
	if err != nil {
		s.cfg.Auth.RecordAuthFailure()
		writeDomainError(w, err)
		return
	}

	s.cfg.Auth.ResetAuthFailures()
	s.cfg.Auth.RevokeAll()
	s.cfg.Relay.CloseAll()
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

func (s *Server) handleIssueRelayTicket(w http.ResponseWriter, r *http.Request) {
	pubFP := s.currentAuthPubFingerprint()
	ticket, err := s.cfg.Auth.IssueTicket("tcp_relay", pubFP)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "TICKET_ERROR", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ticket": ticket})
}

func (s *Server) handleWebSocketTCPRelay(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.BlindStore.IsInitialized() {
		writeError(w, http.StatusUnauthorized, "VAULT_NOT_INIT", "加密保险库尚未初始化")
		return
	}
	ticket := r.URL.Query().Get("ticket")
	pubFP := s.currentAuthPubFingerprint()
	if err := s.cfg.Auth.ConsumeTicket(ticket, "tcp_relay", pubFP); err != nil {
		writeError(w, http.StatusUnauthorized, "INVALID_TICKET", "单次安全中继票据无效或已过期")
		return
	}
	s.cfg.Relay.ServeWebSocket(w, r)
}

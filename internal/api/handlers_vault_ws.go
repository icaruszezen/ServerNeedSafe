package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/icaruszezen/ServerNeedSafe/internal/sshmanager"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

func (s *Server) handleGetVaultSecurity(w http.ResponseWriter, r *http.Request) {
	encInfo, err := s.cfg.Store.EncryptionInfo()
	if err != nil {
		writeDomainError(w, err)
		return
	}
	settings, err := s.cfg.Store.GetSettings()
	if err != nil {
		writeDomainError(w, err)
		return
	}
	knownHosts, _ := s.cfg.Store.ListKnownHosts()
	auditLogs, _ := s.cfg.Store.ListAuditLogs(200)

	writeJSON(w, http.StatusOK, map[string]any{
		"deploy_mode":         s.cfg.DeployMode,
		"vault_path":          s.cfg.BlindStore.FilePath(),
		"daemon_running":      s.isDaemonUnlocked(),
		"auto_unlock_enabled": s.cfg.KeyMgr != nil && s.cfg.KeyMgr.HasLocalKey(),
		"auto_unlock_mode":    s.autoUnlockMode(),
		"key_seal_path":       s.keySealPathDisplay(),
		"encryption":          encInfo,
		"settings":            settings,
		"known_hosts":         knownHosts,
		"audit_logs":          auditLogs,
		"active_sessions":     s.cfg.Auth.ActiveSessionCount(),
		"active_relays":       s.cfg.Relay.ActiveCount(),
		"active_ssh_tabs":     len(s.cfg.SSH.ListActiveSessions()),
		"anchor":              s.cfg.Store.GetAnchor(),
	})
}

func (s *Server) keySealPathDisplay() string {
	if s.cfg.KeyMgr == nil {
		return ""
	}
	return s.cfg.KeyMgr.KeyPath()
}

func (s *Server) handleUpdateVaultSettings(w http.ResponseWriter, r *http.Request) {
	var in vault.AppSettings
	if err := decodeJSON(r, &in, 64*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "设置参数格式错误")
		return
	}
	updated, err := s.cfg.Store.UpdateSettings(in, extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"settings": updated,
	})
}

func (s *Server) handleDeleteKnownHost(w http.ResponseWriter, r *http.Request) {
	addr := strings.TrimSpace(r.URL.Query().Get("address"))
	if addr == "" {
		var body struct {
			Address string `json:"address"`
		}
		_ = decodeJSON(r, &body, 16*1024)
		addr = strings.TrimSpace(body.Address)
	}
	if err := s.cfg.Store.DeleteKnownHost(addr, extractClientIP(r)); err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

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
	s.reloadDaemonAfterRemoteWrite("远端同步写入", extractClientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"encryption": encInfo,
	})
}

func (s *Server) handleExportVaultBlob(w http.ResponseWriter, r *http.Request) {
	var (
		raw []byte
		err error
	)
	if s.isDaemonUnlocked() {
		raw, err = s.cfg.Store.ExportEncryptedBytes(extractClientIP(r))
	} else {
		raw, _, _, err = s.cfg.BlindStore.ReadBlob()
	}
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

	// Reload in-memory daemon if the in-memory DEK / .vault.key matches the imported VaultID;
	// otherwise lock it, drop the obsolete seal and wait for the next password login.
	s.reloadDaemonAfterRemoteWrite("远端导入保险库", extractClientIP(r))

	s.cfg.Auth.ResetAuthFailures()
	s.cfg.Auth.RevokeAll()
	s.cfg.Relay.CloseAll()
	sess, err := s.cfg.Auth.CreateSession(pubFP, extractClientIP(r), r.UserAgent())
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

func (s *Server) verifyExistingVaultPassword(pw string) error {
	if strings.TrimSpace(pw) == "" {
		return vault.ErrInvalidPassword
	}
	if s.isDaemonUnlocked() {
		return s.cfg.Store.VerifyPassword(pw)
	}
	raw, _, _, err := s.cfg.BlindStore.ReadBlob()
	if err != nil {
		return err
	}
	dek, authPriv, _, _, _, err := vault.OpenVaultContainer(raw, pw, s.cfg.Store.MinMemoryKiB())
	vault.ZeroBytes(dek)
	vault.ZeroBytes(authPriv)
	return err
}

func (s *Server) handleImportVaultFile(w http.ResponseWriter, r *http.Request) {
	if retrySec, err := s.cfg.Auth.CheckRateLimit(); err != nil {
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error":           err.Error(),
			"code":            "RATE_LIMITED",
			"retry_after_sec": retrySec,
		})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 68*1024*1024)
	if err := r.ParseMultipartForm(68 * 1024 * 1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_FORM", "解析 .sns 备份上传表单失败")
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "MISSING_FILE", "请选择要导入的 .sns 加密备份文件")
		return
	}
	defer file.Close()

	rawBytes, err := io.ReadAll(io.LimitReader(file, 68*1024*1024))
	if err != nil || len(rawBytes) == 0 {
		writeError(w, http.StatusBadRequest, "BAD_BLOB", "备份文件内容为空或读取失败")
		return
	}

	backupPassword := r.FormValue("password")
	currentAdminPassword := r.FormValue("current_admin_password")
	clearAnchor := r.FormValue("clear_anchor") == "true" || r.FormValue("clear_anchor") == "1"
	clientIP := extractClientIP(r)

	// Both the existing-password proof and the backup decryption run memory-hard Argon2id server-side.
	release, ok := s.acquirePasswordKDFSlot(w, r)
	if !ok {
		return
	}
	defer release()

	_, callerAuthed := s.validateRequestSession(r, false)
	if s.cfg.BlindStore.IsInitialized() && !callerAuthed {
		// Unauthenticated restore MUST prove possession of the existing server vault's admin password!
		pwToCheck := currentAdminPassword
		if pwToCheck == "" {
			pwToCheck = backupPassword
		}
		if vErr := s.verifyExistingVaultPassword(pwToCheck); vErr != nil {
			failCnt, lockedSec := s.cfg.Auth.RecordAuthFailure()
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"error":           "当前服务器原管理员密码校验未通过，已拦截覆盖操作",
				"code":            "INVALID_PASSWORD",
				"failed_attempts": failCnt,
				"retry_after_sec": lockedSec,
			})
			return
		}
	}

	// Remember the anti-rollback anchor so that a FAILED import (wrong backup password, corrupt file)
	// cannot be abused to silently wipe rollback protection.
	prevAnchor := s.cfg.Store.GetAnchor()
	if clearAnchor {
		s.cfg.Store.SetAnchor(nil)
	}

	if err := s.cfg.Store.ImportEncryptedVault(rawBytes, backupPassword, currentAdminPassword, clientIP); err != nil {
		if clearAnchor {
			s.cfg.Store.SetAnchor(prevAnchor)
		}
		s.cfg.Auth.RecordAuthFailure()
		writeDomainError(w, err)
		return
	}

	s.persistAutoUnlockKey("import-file")
	// If re-sealing failed, never keep a seal that belongs to the replaced vault.
	s.dropStaleAutoUnlockKey("import-file", false)
	s.setMigrationPending(false)
	if s.cfg.Monitor != nil {
		s.cfg.Monitor.Wake()
	}
	if s.cfg.AI != nil {
		s.cfg.AI.NotifyPatrolConfigUpdated()
	}

	s.cfg.Auth.ResetAuthFailures()
	s.cfg.Auth.RevokeAll()
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

func doRemoteSyncJSON(client *http.Client, method, fullURL string, reqBody any, bearer string, dst any) error {
	var reader io.Reader
	if reqBody != nil {
		b, err := json.Marshal(reqBody)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, fullURL, reader)
	if err != nil {
		return err
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("无法连接到远端同步服务 (%s): %w", fullURL, err)
	}
	defer res.Body.Close()

	respBytes, err := io.ReadAll(io.LimitReader(res.Body, 72*1024*1024))
	if err != nil {
		return err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		var ep struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(respBytes, &ep)
		if ep.Error != "" {
			return errors.New(ep.Error)
		}
		return fmt.Errorf("远端服务返回 HTTP %d", res.StatusCode)
	}
	if dst != nil && len(respBytes) > 0 {
		return json.Unmarshal(respBytes, dst)
	}
	return nil
}

func (s *Server) handleVaultSyncPush(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RemoteURL      string `json:"remote_url"`
		RemotePassword string `json:"remote_password"`
	}
	if err := decodeJSON(r, &req, 64*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "请求参数格式错误")
		return
	}
	remoteURL := strings.TrimRight(strings.TrimSpace(req.RemoteURL), "/")
	if remoteURL == "" {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "请填写远端 ServerNeedSafe 服务地址")
		return
	}

	rawBlob, hdr, err := s.cfg.Store.LastSealedBlob()
	if err != nil {
		writeDomainError(w, err)
		return
	}
	localPriv := s.cfg.Store.AuthPrivateKeyCopy()
	if len(localPriv) == 0 {
		writeDomainError(w, vault.ErrVaultLocked)
		return
	}
	defer vault.ZeroBytes(localPriv)

	httpClient := &http.Client{Timeout: 45 * time.Second}
	var stResp struct {
		Initialized bool `json:"initialized"`
	}
	if err := doRemoteSyncJSON(httpClient, http.MethodGet, remoteURL+"/api/auth/status", nil, "", &stResp); err != nil {
		writeError(w, http.StatusBadGateway, "SYNC_FAILED", err.Error())
		return
	}

	newSig := vault.SignVaultImport(localPriv, hdr.VaultID, hdr.Revision, rawBlob)
	var overwriteSig []byte
	if stResp.Initialized {
		var chResp struct {
			KDF *vault.PublicKDFParams `json:"kdf"`
		}
		if err := doRemoteSyncJSON(httpClient, http.MethodPost, remoteURL+"/api/auth/challenge", map[string]any{}, "", &chResp); err != nil || chResp.KDF == nil {
			writeError(w, http.StatusBadGateway, "SYNC_FAILED", "获取远端挑战参数失败")
			return
		}
		if req.RemotePassword == "" && chResp.KDF.VaultID == hdr.VaultID {
			overwriteSig = vault.SignVaultImportOverwrite(localPriv, chResp.KDF.VaultID, hdr.VaultID, rawBlob)
		} else {
			if req.RemotePassword == "" {
				writeError(w, http.StatusBadRequest, "INVALID_INPUT", "远端已存在不同保险库，请填写远端当前管理员密码以授权覆盖")
				return
			}
			kekTmp, remPriv, _, dErr := vault.DeriveVaultKeys(
				req.RemotePassword,
				chResp.KDF.KDFSalt,
				chResp.KDF.KDFTime,
				chResp.KDF.KDFMemoryKiB,
				chResp.KDF.KDFThreads,
				s.cfg.Store.MinMemoryKiB(),
			)
			req.RemotePassword = ""
			if dErr != nil {
				writeDomainError(w, dErr)
				return
			}
			vault.ZeroBytes(kekTmp)
			overwriteSig = vault.SignVaultImportOverwrite(remPriv, chResp.KDF.VaultID, hdr.VaultID, rawBlob)
			vault.ZeroBytes(remPriv)
		}
	}

	impPayload := map[string]any{
		"blob_b64":          base64.StdEncoding.EncodeToString(rawBlob),
		"new_signature_b64": base64.StdEncoding.EncodeToString(newSig),
	}
	if len(overwriteSig) > 0 {
		impPayload["overwrite_signature_b64"] = base64.StdEncoding.EncodeToString(overwriteSig)
	}
	var impResp struct {
		Token string `json:"token"`
	}
	if err := doRemoteSyncJSON(httpClient, http.MethodPost, remoteURL+"/api/vault/import", impPayload, "", &impResp); err != nil {
		writeError(w, http.StatusBadGateway, "SYNC_FAILED", err.Error())
		return
	}
	if impResp.Token != "" {
		_ = doRemoteSyncJSON(httpClient, http.MethodPost, remoteURL+"/api/auth/logout", map[string]any{}, impResp.Token, nil)
	}

	s.cfg.Store.RecordAuditAsync("vault.sync_push", remoteURL, fmt.Sprintf("推送加密密文容器 (Revision #%d)", hdr.Revision), extractClientIP(r), true)
	writeJSON(w, http.StatusOK, map[string]any{
		"summary": map[string]any{
			"direction":  "push",
			"remote_url": remoteURL,
			"vault_id":   hdr.VaultID,
			"revision":   hdr.Revision,
			"bytes":      len(rawBlob),
		},
	})
}

func (s *Server) handleVaultSyncPull(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RemoteURL            string `json:"remote_url"`
		RemotePassword       string `json:"remote_password"`
		CurrentLocalPassword string `json:"current_local_password"`
	}
	if err := decodeJSON(r, &req, 64*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "请求参数格式错误")
		return
	}
	remoteURL := strings.TrimRight(strings.TrimSpace(req.RemoteURL), "/")
	if remoteURL == "" || req.RemotePassword == "" {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "请填写远端服务地址与远端保险库密码")
		return
	}

	httpClient := &http.Client{Timeout: 45 * time.Second}
	var chResp struct {
		ChallengeID string                 `json:"challenge_id"`
		Nonce       string                 `json:"nonce"`
		KDF         *vault.PublicKDFParams `json:"kdf"`
	}
	if err := doRemoteSyncJSON(httpClient, http.MethodPost, remoteURL+"/api/auth/challenge", map[string]any{}, "", &chResp); err != nil || chResp.KDF == nil {
		writeError(w, http.StatusBadGateway, "SYNC_FAILED", "连接远端挑战接口失败")
		return
	}

	kekTmp, remPriv, _, err := vault.DeriveVaultKeys(
		req.RemotePassword,
		chResp.KDF.KDFSalt,
		chResp.KDF.KDFTime,
		chResp.KDF.KDFMemoryKiB,
		chResp.KDF.KDFThreads,
		s.cfg.Store.MinMemoryKiB(),
	)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	vault.ZeroBytes(kekTmp)
	sig := vault.SignAuthChallenge(remPriv, chResp.ChallengeID, chResp.Nonce, chResp.KDF.VaultID)
	vault.ZeroBytes(remPriv)

	var verResp struct {
		Token string `json:"token"`
	}
	if err := doRemoteSyncJSON(httpClient, http.MethodPost, remoteURL+"/api/auth/verify", map[string]any{
		"challenge_id":  chResp.ChallengeID,
		"signature_b64": base64.StdEncoding.EncodeToString(sig),
	}, "", &verResp); err != nil {
		writeError(w, http.StatusUnauthorized, "INVALID_PASSWORD", err.Error())
		return
	}

	var blobResp struct {
		BlobB64 string `json:"blob_b64"`
	}
	err = doRemoteSyncJSON(httpClient, http.MethodGet, remoteURL+"/api/vault/blob", nil, verResp.Token, &blobResp)
	_ = doRemoteSyncJSON(httpClient, http.MethodPost, remoteURL+"/api/auth/logout", map[string]any{}, verResp.Token, nil)
	if err != nil {
		writeError(w, http.StatusBadGateway, "SYNC_FAILED", err.Error())
		return
	}

	remoteBlob, err := base64.StdEncoding.DecodeString(blobResp.BlobB64)
	if err != nil || len(remoteBlob) == 0 {
		writeError(w, http.StatusBadGateway, "BAD_BLOB", "远端返回的加密容器无效")
		return
	}

	prevAnchor := s.cfg.Store.GetAnchor()
	if prevAnchor != nil && prevAnchor.VaultID != chResp.KDF.VaultID {
		s.cfg.Store.SetAnchor(nil)
	}

	clientIP := extractClientIP(r)
	if err := s.cfg.Store.ImportEncryptedVault(remoteBlob, req.RemotePassword, req.CurrentLocalPassword, clientIP); err != nil {
		req.RemotePassword = ""
		req.CurrentLocalPassword = ""
		if s.cfg.Store.GetAnchor() == nil && prevAnchor != nil {
			s.cfg.Store.SetAnchor(prevAnchor)
		}
		writeDomainError(w, err)
		return
	}
	req.RemotePassword = ""
	req.CurrentLocalPassword = ""

	s.persistAutoUnlockKey("sync-pull")
	s.dropStaleAutoUnlockKey("sync-pull", false)
	s.setMigrationPending(false)
	if s.cfg.Monitor != nil {
		s.cfg.Monitor.Wake()
	}
	if s.cfg.AI != nil {
		s.cfg.AI.NotifyPatrolConfigUpdated()
	}

	pubFP := s.currentAuthPubFingerprint()
	s.cfg.Auth.RevokeAll()
	if sess, sErr := s.cfg.Auth.CreateSession(pubFP, clientIP, r.UserAgent()); sErr == nil {
		s.setAdminSessionCookie(w, r, sess.Token)
	}

	_, hdr, _ := s.cfg.Store.LastSealedBlob()
	rev := chResp.KDF.Revision
	if hdr != nil {
		rev = hdr.Revision
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"summary": map[string]any{
			"direction":  "pull",
			"remote_url": remoteURL,
			"vault_id":   chResp.KDF.VaultID,
			"revision":   rev,
			"bytes":      len(remoteBlob),
		},
	})
}

func checkWebSocketSameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	return origin != "null" && isSameOriginRequest(r, origin)
}

func (s *Server) handleWebSocketTerminal(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	serverID := strings.TrimSpace(q.Get("server_id"))
	if serverID == "" {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "缺少 server_id 参数")
		return
	}
	cols, _ := strconv.Atoi(q.Get("cols"))
	if cols <= 0 {
		cols = 120
	}
	rows, _ := strconv.Atoi(q.Get("rows"))
	if rows <= 0 {
		rows = 34
	}
	trustFP := strings.TrimSpace(q.Get("trust_fingerprint"))

	upgrader := websocket.Upgrader{
		ReadBufferSize:  32 * 1024,
		WriteBufferSize: 32 * 1024,
		CheckOrigin:     checkWebSocketSameOrigin,
	}
	wsConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	var writeMu sync.Mutex
	writeJSONFrame := func(v any) error {
		b, mErr := json.Marshal(v)
		if mErr != nil {
			return mErr
		}
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = wsConn.SetWriteDeadline(time.Now().Add(15 * time.Second))
		return wsConn.WriteMessage(websocket.TextMessage, b)
	}
	writeBinaryFrame := func(chunk []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = wsConn.SetWriteDeadline(time.Now().Add(30 * time.Second))
		return wsConn.WriteMessage(websocket.BinaryMessage, chunk)
	}

	doneCh := make(chan struct{})
	var closeOnce sync.Once
	signalDone := func() {
		closeOnce.Do(func() {
			close(doneCh)
			_ = wsConn.Close()
		})
	}

	ts, ready, openErr := s.cfg.SSH.OpenTerminalSession(
		serverID,
		cols,
		rows,
		trustFP,
		extractClientIP(r),
		sshmanager.TerminalCallbacks{
			OnOutput: func(chunk []byte) {
				if err := writeBinaryFrame(chunk); err != nil {
					signalDone()
				}
			},
			OnExit: func(msg string) {
				_ = writeJSONFrame(map[string]any{
					"type":    "exit",
					"message": msg,
				})
				signalDone()
			},
		},
	)
	if openErr != nil {
		var hkErr *sshmanager.HostKeyUntrustedError
		if errors.As(openErr, &hkErr) {
			_ = writeJSONFrame(map[string]any{
				"type":     "host_key_untrusted",
				"error":    hkErr.Error(),
				"host_key": hkErr,
			})
		} else {
			_ = writeJSONFrame(map[string]any{
				"type":  "error",
				"error": openErr.Error(),
			})
		}
		_ = wsConn.Close()
		return
	}

	defer func() {
		s.cfg.SSH.CloseSession(ts.ID)
		signalDone()
	}()

	if err := writeJSONFrame(map[string]any{
		"type":  "ready",
		"ready": ready,
	}); err != nil {
		return
	}

	wsConn.SetReadLimit(512 * 1024)
	go func() {
		defer signalDone()
		for {
			msgType, payload, rErr := wsConn.ReadMessage()
			if rErr != nil {
				return
			}
			var ctrl struct {
				Type string `json:"type"`
				Data string `json:"data,omitempty"`
				Cols int    `json:"cols,omitempty"`
				Rows int    `json:"rows,omitempty"`
			}
			isInput := msgType == websocket.BinaryMessage
			if !isInput {
				if json.Unmarshal(payload, &ctrl) != nil {
					continue
				}
				isInput = ctrl.Type == "input"
			}

			// Every frame requires a still-valid admin session. Previously the validation result was
			// ignored, so a tab whose session had been revoked (lock / logout / password change) or had
			// expired kept a fully interactive shell indefinitely. Only real keystrokes refresh the idle
			// timer, so automatic keep-alive pings / resizes can no longer defeat the idle timeout.
			if _, ok := s.validateRequestSession(r, isInput); !ok {
				vault.ZeroBytes(payload)
				_ = writeJSONFrame(map[string]any{
					"type":    "exit",
					"message": sessionGoneTerminalMsg,
				})
				return
			}

			if msgType == websocket.BinaryMessage {
				if len(payload) > 0 {
					_ = ts.WriteInput(payload)
					vault.ZeroBytes(payload)
				}
				continue
			}

			switch ctrl.Type {
			case "input":
				if ctrl.Data != "" {
					_ = ts.WriteInput([]byte(ctrl.Data))
				}
			case "resize":
				if ctrl.Cols > 0 && ctrl.Rows > 0 {
					_ = ts.Resize(ctrl.Cols, ctrl.Rows)
				}
			case "ping":
				_ = writeJSONFrame(map[string]any{"type": "pong"})
			}
		}
	}()

	pingTicker := time.NewTicker(25 * time.Second)
	defer pingTicker.Stop()
	for {
		select {
		case <-doneCh:
			return
		case <-r.Context().Done():
			return
		case <-pingTicker.C:
			if _, ok := s.validateRequestSession(r, false); !ok {
				_ = writeJSONFrame(map[string]any{
					"type":    "exit",
					"message": sessionGoneTerminalMsg,
				})
				return
			}
			writeMu.Lock()
			_ = wsConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			err := wsConn.WriteMessage(websocket.PingMessage, nil)
			writeMu.Unlock()
			if err != nil {
				return
			}
		}
	}
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

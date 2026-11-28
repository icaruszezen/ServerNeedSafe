package api

import (
	"bytes"
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
	storageInfo := s.cfg.Store.StorageInfo()

	writeJSON(w, http.StatusOK, map[string]any{
		"deploy_mode":       s.cfg.DeployMode,
		"data_dir":          storageInfo.DataDir,
		"secrets_path":      storageInfo.SecretsPath,
		"daemon_running":    s.isDaemonReady(),
		"session_ttl_hours": int(s.cfg.Auth.SessionTTL().Hours()),
		"encryption":        encInfo,
		"storage":           storageInfo,
		"settings":          settings,
		"known_hosts":       knownHosts,
		"audit_logs":        auditLogs,
		"active_sessions":   s.cfg.Auth.ActiveSessionCount(),
		"active_ssh_tabs":   len(s.cfg.SSH.ListActiveSessions()),
	})
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

// handleExportVaultBackup creates a portable password-encrypted .sns v3 backup container on the fly.
func (s *Server) handleExportVaultBackup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BackupPassword string `json:"backup_password"`
		IncludeRuntime bool   `json:"include_runtime"`
	}
	if err := decodeJSON(r, &req, 64*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "备份导出请求格式无效")
		return
	}

	raw, err := s.cfg.Store.ExportBackupBytes(req.BackupPassword, req.IncludeRuntime, extractClientIP(r))
	req.BackupPassword = ""
	if err != nil {
		writeDomainError(w, err)
		return
	}

	suffix := "config"
	if req.IncludeRuntime {
		suffix = "full"
	}
	filename := fmt.Sprintf("ServerNeedSafe-%s-%s.sns", suffix, time.Now().Format("20060102-150405"))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.Header().Set("X-Filename", filename)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
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

	r.Body = http.MaxBytesReader(w, r.Body, 128*1024*1024)
	if err := r.ParseMultipartForm(128 * 1024 * 1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_FORM", "解析 .sns 备份上传表单失败")
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "MISSING_FILE", "请选择要导入的 .sns 加密备份文件")
		return
	}
	defer file.Close()

	rawBytes, err := io.ReadAll(io.LimitReader(file, 128*1024*1024))
	if err != nil || len(rawBytes) == 0 {
		writeError(w, http.StatusBadRequest, "BAD_BLOB", "备份文件内容为空或读取失败")
		return
	}

	backupPassword := r.FormValue("password")
	currentAdminPassword := r.FormValue("current_admin_password")
	includeRuntime := true
	if rawFlag := strings.TrimSpace(r.FormValue("include_runtime")); rawFlag != "" {
		includeRuntime = rawFlag == "true" || rawFlag == "1"
	}
	clientIP := extractClientIP(r)

	_, callerAuthed := s.validateRequestSession(r, false)
	if s.cfg.Store.IsInitialized() && !callerAuthed {
		pwToCheck := currentAdminPassword
		if pwToCheck == "" {
			pwToCheck = backupPassword
		}
		if vErr := s.cfg.Store.LoginWithPassword(pwToCheck, clientIP); vErr != nil {
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

	if err := s.cfg.Store.ImportBackupBytes(rawBytes, backupPassword, includeRuntime, clientIP); err != nil {
		s.cfg.Auth.RecordAuthFailure()
		writeDomainError(w, err)
		return
	}

	if s.cfg.Monitor != nil {
		s.cfg.Monitor.Wake()
	}
	if s.cfg.AI != nil {
		s.cfg.AI.NotifyPatrolConfigUpdated()
	}
	if s.cfg.QQBot != nil {
		s.cfg.QQBot.NotifyConfigUpdated()
	}
	if s.cfg.Updater != nil {
		s.cfg.Updater.NotifySettingsUpdated()
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

// --- Simplified Authenticated Cross-Instance Sync (Desktop <-> Server) ---

func (s *Server) handleVaultSyncSnapshot(w http.ResponseWriter, r *http.Request) {
	includeRuntime := r.URL.Query().Get("include_runtime") == "true" || r.URL.Query().Get("include_runtime") == "1"
	snap, err := s.cfg.Store.BuildBackupBundle(includeRuntime)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"snapshot": snap,
	})
}

func (s *Server) handleVaultSyncApply(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Snapshot       *vault.SyncSnapshot `json:"snapshot"`
		IncludeRuntime bool                `json:"include_runtime"`
	}
	if err := decodeJSON(r, &req, 128*1024*1024); err != nil || req.Snapshot == nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "同步数据包格式无效")
		return
	}

	if err := s.cfg.Store.ApplySyncSnapshot(req.Snapshot, req.IncludeRuntime, "", extractClientIP(r), "vault.sync_apply"); err != nil {
		writeDomainError(w, err)
		return
	}
	if s.cfg.Monitor != nil {
		s.cfg.Monitor.Wake()
	}
	if s.cfg.AI != nil {
		s.cfg.AI.NotifyPatrolConfigUpdated()
	}
	if s.cfg.QQBot != nil {
		s.cfg.QQBot.NotifyConfigUpdated()
	}
	if s.cfg.Updater != nil {
		s.cfg.Updater.NotifySettingsUpdated()
	}

	encInfo, _ := s.cfg.Store.EncryptionInfo()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"encryption": encInfo,
	})
}

func doRemoteSyncJSON(client *http.Client, method, fullURL string, reqBody any, bearer string, dst any) (int, error) {
	var reader io.Reader
	var sentBytes int
	if reqBody != nil {
		b, err := json.Marshal(reqBody)
		if err != nil {
			return 0, err
		}
		sentBytes = len(b)
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, fullURL, reader)
	if err != nil {
		return 0, err
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	res, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("无法连接到远端同步服务 (%s): %w", fullURL, err)
	}
	defer res.Body.Close()

	respBytes, err := io.ReadAll(io.LimitReader(res.Body, 128*1024*1024))
	if err != nil {
		return 0, err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		var ep struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(respBytes, &ep)
		if ep.Error != "" {
			return 0, errors.New(ep.Error)
		}
		return 0, fmt.Errorf("远端服务返回 HTTP %d", res.StatusCode)
	}
	if dst != nil && len(respBytes) > 0 {
		if err := json.Unmarshal(respBytes, dst); err != nil {
			return 0, err
		}
	}
	if sentBytes > 0 {
		return sentBytes, nil
	}
	return len(respBytes), nil
}

func (s *Server) handleVaultSyncPush(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RemoteURL      string `json:"remote_url"`
		RemotePassword string `json:"remote_password"`
		IncludeRuntime bool   `json:"include_runtime"`
	}
	if err := decodeJSON(r, &req, 64*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "请求参数格式错误")
		return
	}
	remoteURL := strings.TrimRight(strings.TrimSpace(req.RemoteURL), "/")
	if remoteURL == "" || strings.TrimSpace(req.RemotePassword) == "" {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "请填写远端 ServerNeedSafe 地址与远端管理员密码")
		return
	}

	snap, err := s.cfg.Store.BuildBackupBundle(req.IncludeRuntime)
	if err != nil {
		writeDomainError(w, err)
		return
	}

	httpClient := &http.Client{Timeout: 45 * time.Second}
	var loginResp struct {
		Token string `json:"token"`
	}
	if _, err := doRemoteSyncJSON(httpClient, http.MethodPost, remoteURL+"/api/auth/login", map[string]any{
		"password": req.RemotePassword,
	}, "", &loginResp); err != nil || loginResp.Token == "" {
		if err == nil {
			err = errors.New("远端管理员登录未返回有效会话令牌")
		}
		writeError(w, http.StatusUnauthorized, "SYNC_AUTH_FAILED", err.Error())
		return
	}
	req.RemotePassword = ""
	defer func() {
		_, _ = doRemoteSyncJSON(httpClient, http.MethodPost, remoteURL+"/api/auth/logout", map[string]any{}, loginResp.Token, nil)
	}()

	var applyResp struct {
		Encryption *vault.EncryptionInfo `json:"encryption"`
	}
	sentBytes, err := doRemoteSyncJSON(httpClient, http.MethodPost, remoteURL+"/api/vault/sync/apply", map[string]any{
		"snapshot":        snap,
		"include_runtime": req.IncludeRuntime,
	}, loginResp.Token, &applyResp)
	if err != nil {
		writeError(w, http.StatusBadGateway, "SYNC_FAILED", err.Error())
		return
	}

	rev := snap.Config.Revision
	if applyResp.Encryption != nil && applyResp.Encryption.Revision > 0 {
		rev = applyResp.Encryption.Revision
	}
	scopeLabel := "核心配置与 AI 记忆"
	if req.IncludeRuntime {
		scopeLabel = "全量配置与运行数据"
	}
	s.cfg.Store.RecordAuditAsync("vault.sync_push", remoteURL, fmt.Sprintf("推送同步至远端 (%s, Rev #%d)", scopeLabel, rev), extractClientIP(r), true)
	writeJSON(w, http.StatusOK, map[string]any{
		"summary": map[string]any{
			"direction":       "push",
			"remote_url":      remoteURL,
			"vault_id":        snap.Config.VaultID,
			"revision":        rev,
			"bytes":           sentBytes,
			"include_runtime": req.IncludeRuntime,
		},
	})
}

func (s *Server) handleVaultSyncPull(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RemoteURL      string `json:"remote_url"`
		RemotePassword string `json:"remote_password"`
		IncludeRuntime bool   `json:"include_runtime"`
	}
	if err := decodeJSON(r, &req, 64*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "请求参数格式错误")
		return
	}
	remoteURL := strings.TrimRight(strings.TrimSpace(req.RemoteURL), "/")
	if remoteURL == "" || strings.TrimSpace(req.RemotePassword) == "" {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "请填写远端服务地址与远端管理员密码")
		return
	}

	httpClient := &http.Client{Timeout: 45 * time.Second}
	var loginResp struct {
		Token string `json:"token"`
	}
	if _, err := doRemoteSyncJSON(httpClient, http.MethodPost, remoteURL+"/api/auth/login", map[string]any{
		"password": req.RemotePassword,
	}, "", &loginResp); err != nil || loginResp.Token == "" {
		if err == nil {
			err = errors.New("远端管理员登录未返回有效会话令牌")
		}
		writeError(w, http.StatusUnauthorized, "SYNC_AUTH_FAILED", err.Error())
		return
	}
	req.RemotePassword = ""
	defer func() {
		_, _ = doRemoteSyncJSON(httpClient, http.MethodPost, remoteURL+"/api/auth/logout", map[string]any{}, loginResp.Token, nil)
	}()

	snapURL := remoteURL + "/api/vault/sync/snapshot"
	if req.IncludeRuntime {
		snapURL += "?include_runtime=true"
	}
	var snapResp struct {
		Snapshot *vault.SyncSnapshot `json:"snapshot"`
	}
	recvBytes, err := doRemoteSyncJSON(httpClient, http.MethodGet, snapURL, nil, loginResp.Token, &snapResp)
	if err != nil || snapResp.Snapshot == nil {
		if err == nil {
			err = errors.New("远端返回的同步快照为空")
		}
		writeError(w, http.StatusBadGateway, "SYNC_FAILED", err.Error())
		return
	}

	if err := s.cfg.Store.ApplySyncSnapshot(snapResp.Snapshot, req.IncludeRuntime, "", extractClientIP(r), "vault.sync_pull"); err != nil {
		writeDomainError(w, err)
		return
	}
	if s.cfg.Monitor != nil {
		s.cfg.Monitor.Wake()
	}
	if s.cfg.AI != nil {
		s.cfg.AI.NotifyPatrolConfigUpdated()
	}
	if s.cfg.QQBot != nil {
		s.cfg.QQBot.NotifyConfigUpdated()
	}
	if s.cfg.Updater != nil {
		s.cfg.Updater.NotifySettingsUpdated()
	}

	encInfo, _ := s.cfg.Store.EncryptionInfo()
	rev := snapResp.Snapshot.Config.Revision
	if encInfo != nil && encInfo.Revision > 0 {
		rev = encInfo.Revision
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"summary": map[string]any{
			"direction":       "pull",
			"remote_url":      remoteURL,
			"vault_id":        snapResp.Snapshot.Config.VaultID,
			"revision":        rev,
			"bytes":           recvBytes,
			"include_runtime": req.IncludeRuntime,
		},
	})
}

// --- Native WebSocket Interactive SSH PTY Terminal ---

func checkWebSocketOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	return origin != "null"
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
		CheckOrigin:     checkWebSocketOrigin,
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
			OnProgress: func(ev sshmanager.DialProgressEvent) {
				_ = writeJSONFrame(map[string]any{
					"type":    "progress",
					"stage":   ev.Stage,
					"message": ev.Message,
				})
			},
			OnOutput: func(chunk []byte) {
				if err := writeBinaryFrame(chunk); err != nil {
					signalDone()
				}
			},
			OnExitDetail: func(ev sshmanager.TerminalExitEvent) {
				_ = writeJSONFrame(map[string]any{
					"type":           "exit",
					"message":        ev.Message,
					"abnormal":       ev.Abnormal,
					"auto_reconnect": ev.AutoReconnect,
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

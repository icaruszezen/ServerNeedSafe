package api

import (
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/sshmanager"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

// handleWorkspaceBootstrap returns all initial workspace lists in a single HTTP round-trip
// so page refresh or initial login populates the console in <20ms.
func (s *Server) handleWorkspaceBootstrap(w http.ResponseWriter, r *http.Request) {
	servers, err := s.cfg.Store.ListServers()
	if err != nil {
		writeDomainError(w, err)
		return
	}
	groups, _ := s.cfg.Store.ListGroups()
	creds, _ := s.cfg.Store.ListCredentials()
	snippets, _ := s.cfg.Store.ListSnippets()

	firingAlerts := 0
	activeAlertsByServer := make(map[string]int)
	if monOv, mErr := s.cfg.Store.GetMonitorOverview(); mErr == nil && monOv != nil {
		firingAlerts = monOv.KPI.FiringAlerts
		for _, node := range monOv.Nodes {
			if node.ActiveAlerts > 0 {
				activeAlertsByServer[node.Server.ID] = node.ActiveAlerts
			}
		}
	}
	_, patrolUnread, _ := s.cfg.Store.ListPatrolRecords(1, false)
	pendingExtPatrols, pendingExtApprovals := s.cfg.Store.CountExternalPending()

	writeJSON(w, http.StatusOK, map[string]any{
		"servers":                    servers,
		"groups":                     groups,
		"credentials":                creds,
		"snippets":                   snippets,
		"active_sessions":            s.cfg.SSH.ListActiveSessions(),
		"firing_alerts":              firingAlerts,
		"active_alerts_by_server":    activeAlertsByServer,
		"patrol_unread":              patrolUnread + pendingExtApprovals,
		"pending_external_patrols":   pendingExtPatrols,
		"pending_external_approvals": pendingExtApprovals,
	})
}

func (s *Server) handleListServers(w http.ResponseWriter, r *http.Request) {
	servers, err := s.cfg.Store.ListServers()
	if err != nil {
		writeDomainError(w, err)
		return
	}
	groups, err := s.cfg.Store.ListGroups()
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"servers":         servers,
		"groups":          groups,
		"active_sessions": s.cfg.SSH.ListActiveSessions(),
	})
}

func (s *Server) handleCreateServer(w http.ResponseWriter, r *http.Request) {
	var in vault.ServerMutationInput
	if err := decodeJSON(r, &in, 512*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "主机参数格式错误")
		return
	}
	if err := validateServerPrivateKey(&in, ""); err != nil {
		writeDomainError(w, err)
		return
	}
	srv, err := s.cfg.Store.CreateServer(in, extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	if s.cfg.Monitor != nil {
		s.cfg.Monitor.Wake()
	}
	writeJSON(w, http.StatusOK, map[string]any{"server": srv})
}

func (s *Server) handleUpdateServer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in vault.ServerMutationInput
	if err := decodeJSON(r, &in, 512*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "主机更新参数格式错误")
		return
	}
	existingPass := ""
	if in.AuthType == vault.AuthPrivateKey && in.PrivateKey != nil && strings.TrimSpace(*in.PrivateKey) != "" && in.Passphrase == nil {
		if existing, gErr := s.cfg.Store.GetServerSecret(id); gErr == nil && existing != nil {
			existingPass = existing.Passphrase
		}
	}
	if err := validateServerPrivateKey(&in, existingPass); err != nil {
		writeDomainError(w, err)
		return
	}
	srv, err := s.cfg.Store.UpdateServer(id, in, extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	if s.cfg.Monitor != nil {
		s.cfg.Monitor.EvictServerConnection(id)
		s.cfg.Monitor.Wake()
	}
	writeJSON(w, http.StatusOK, map[string]any{"server": srv})
}

func (s *Server) handleDeleteServer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.cfg.Store.DeleteServer(id, extractClientIP(r)); err != nil {
		writeDomainError(w, err)
		return
	}
	if s.cfg.Monitor != nil {
		s.cfg.Monitor.EvictServerConnection(id)
		s.cfg.Monitor.Wake()
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleProbeServer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		TrustFingerprint string `json:"trust_fingerprint"`
	}
	_ = decodeJSON(r, &req, 16*1024)
	probe, err := s.cfg.SSH.ProbeServer(id, req.TrustFingerprint, extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"probe": probe})
}

func (s *Server) handleAddGroup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(r, &req, 16*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "分组参数格式错误")
		return
	}
	groups, err := s.cfg.Store.AddGroup(req.Name)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"groups": groups})
}

func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		var req struct {
			Name string `json:"name"`
		}
		_ = decodeJSON(r, &req, 16*1024)
		name = strings.TrimSpace(req.Name)
	}
	groups, err := s.cfg.Store.DeleteGroup(name)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"groups": groups})
}

func (s *Server) handleListCredentials(w http.ResponseWriter, r *http.Request) {
	creds, err := s.cfg.Store.ListCredentials()
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"credentials": creds})
}

func (s *Server) handleCreateCredential(w http.ResponseWriter, r *http.Request) {
	var in vault.CredentialMutationInput
	if err := decodeJSON(r, &in, 512*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "凭据参数格式错误")
		return
	}
	if err := enrichCredentialInput(&in, "", true); err != nil {
		writeDomainError(w, err)
		return
	}
	cred, err := s.cfg.Store.CreateCredential(in, extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"credential": cred})
}

// handleImportCredentialFile imports an SSH private key (and optional .pub file) directly via multipart/form-data.
func (s *Server) handleImportCredentialFile(w http.ResponseWriter, r *http.Request) {
	const maxMultipartBytes = 1 * 1024 * 1024
	r.Body = http.MaxBytesReader(w, r.Body, maxMultipartBytes)
	if err := r.ParseMultipartForm(maxMultipartBytes); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_FORM", "解析密钥上传表单失败（单次上传请勿超过 1 MB）")
		return
	}
	defer func() {
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll()
		}
	}()

	privFile, privHeader, err := r.FormFile("private_key_file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "MISSING_FILE", "请选择要上传的 SSH 私钥文件")
		return
	}
	defer privFile.Close()

	privBytes, err := io.ReadAll(io.LimitReader(privFile, sshmanager.MaxPrivateKeyBytes+1))
	defer vault.ZeroBytes(privBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, "BAD_FILE", "读取上传的私钥文件失败")
		return
	}
	if len(privBytes) == 0 {
		writeError(w, http.StatusBadRequest, "EMPTY_FILE", "上传的私钥文件内容为空")
		return
	}
	if len(privBytes) > sshmanager.MaxPrivateKeyBytes {
		writeError(w, http.StatusBadRequest, "FILE_TOO_LARGE", "私钥文件体积超过限制（最大支持 256 KB）")
		return
	}

	pubKeyText := strings.TrimSpace(r.FormValue("public_key"))
	if pubFile, _, pubErr := r.FormFile("public_key_file"); pubErr == nil {
		defer pubFile.Close()
		pubBytes, readErr := io.ReadAll(io.LimitReader(pubFile, sshmanager.MaxPublicKeyBytes+1))
		if readErr != nil {
			writeError(w, http.StatusBadRequest, "BAD_FILE", "读取上传的公钥文件失败")
			return
		}
		if len(pubBytes) > sshmanager.MaxPublicKeyBytes {
			writeError(w, http.StatusBadRequest, "FILE_TOO_LARGE", "公钥文件体积超过限制（最大支持 64 KB）")
			return
		}
		pubKeyText = string(pubBytes)
	}

	safeFilename := ""
	if privHeader != nil {
		safeFilename = sanitizeUploadedFilename(privHeader.Filename)
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		name = suggestCredentialNameFromFilename(safeFilename)
	}

	privStr := string(privBytes)
	passStr := r.FormValue("passphrase")
	in := vault.CredentialMutationInput{
		Name:         name,
		Kind:         vault.AuthPrivateKey,
		UsernameHint: strings.TrimSpace(r.FormValue("username_hint")),
		PrivateKey:   &privStr,
		Passphrase:   &passStr,
		PublicKey:    pubKeyText,
		Notes:        strings.TrimSpace(r.FormValue("notes")),
	}
	if err := enrichCredentialInput(&in, "", true); err != nil {
		writeDomainError(w, err)
		return
	}

	cred, err := s.cfg.Store.CreateCredential(in, extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"credential":        cred,
		"imported_filename": safeFilename,
	})
}

func (s *Server) handleUpdateCredential(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in vault.CredentialMutationInput
	if err := decodeJSON(r, &in, 512*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "凭据更新参数格式错误")
		return
	}
	existingPass := ""
	if in.Kind == vault.AuthPrivateKey && in.PrivateKey != nil && strings.TrimSpace(*in.PrivateKey) != "" && in.Passphrase == nil {
		if existing, gErr := s.cfg.Store.GetCredentialSecret(id); gErr == nil && existing != nil {
			existingPass = existing.Passphrase
		}
	}
	if err := enrichCredentialInput(&in, existingPass, false); err != nil {
		writeDomainError(w, err)
		return
	}
	cred, err := s.cfg.Store.UpdateCredential(id, in, extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"credential": cred})
}

func validateServerPrivateKey(in *vault.ServerMutationInput, existingPassphrase string) error {
	if in.AuthType != vault.AuthPrivateKey || in.PrivateKey == nil || strings.TrimSpace(*in.PrivateKey) == "" {
		return nil
	}
	passphrase := existingPassphrase
	if in.Passphrase != nil {
		passphrase = *in.Passphrase
	}
	inspected, err := sshmanager.InspectPrivateKey(*in.PrivateKey, passphrase)
	if err != nil {
		return fmt.Errorf("%w: %v", vault.ErrInvalidInput, err)
	}
	*in.PrivateKey = inspected.NormalizedPEM
	if !inspected.Encrypted && in.Passphrase != nil && *in.Passphrase != "" {
		empty := ""
		in.Passphrase = &empty
	}
	return nil
}

func enrichCredentialInput(in *vault.CredentialMutationInput, existingPassphrase string, requireSecret bool) error {
	switch in.Kind {
	case vault.AuthPassword:
		if requireSecret && (in.Password == nil || *in.Password == "") {
			return fmt.Errorf("%w: SSH 密码不能为空", vault.ErrInvalidInput)
		}
		return nil

	case vault.AuthPrivateKey:
		hasPriv := in.PrivateKey != nil && strings.TrimSpace(*in.PrivateKey) != ""
		if !hasPriv {
			if requireSecret {
				return fmt.Errorf("%w: SSH 私钥内容不能为空", vault.ErrInvalidInput)
			}
			if strings.TrimSpace(in.PublicKey) != "" {
				cleanedPub, err := sshmanager.ValidateAndMatchPublicKey(in.PublicKey, "")
				if err != nil {
					return fmt.Errorf("%w: %v", vault.ErrInvalidInput, err)
				}
				in.PublicKey = cleanedPub
			}
			return nil
		}

		passphrase := existingPassphrase
		if in.Passphrase != nil {
			passphrase = *in.Passphrase
		}
		inspected, err := sshmanager.InspectPrivateKey(*in.PrivateKey, passphrase)
		if err != nil {
			return fmt.Errorf("%w: %v", vault.ErrInvalidInput, err)
		}
		*in.PrivateKey = inspected.NormalizedPEM
		if !inspected.Encrypted {
			empty := ""
			in.Passphrase = &empty
		}
		if strings.TrimSpace(in.PublicKey) != "" {
			cleanedPub, err := sshmanager.ValidateAndMatchPublicKey(in.PublicKey, inspected.Fingerprint)
			if err != nil {
				return fmt.Errorf("%w: %v", vault.ErrInvalidInput, err)
			}
			in.PublicKey = cleanedPub
		} else {
			in.PublicKey = inspected.PublicKey
		}
		in.Fingerprint = inspected.Fingerprint
		in.KeyAlgorithm = inspected.Algorithm
		return nil
	}
	return nil
}

func sanitizeUploadedFilename(raw string) string {
	normalized := strings.ReplaceAll(raw, "\\", "/")
	base := filepath.Base(strings.TrimSpace(normalized))
	if base == "." || base == "/" || base == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range base {
		if r >= 0x20 && r != 0x7f {
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

func suggestCredentialNameFromFilename(filename string) string {
	name := sanitizeUploadedFilename(filename)
	if name == "" {
		return "Imported-SSH-Key"
	}
	lower := strings.ToLower(name)
	for _, ext := range []string{".pem", ".key", ".pri", ".openssh", ".txt"} {
		if strings.HasSuffix(lower, ext) && len(name) > len(ext) {
			return name[:len(name)-len(ext)]
		}
	}
	return name
}

func (s *Server) handleDeleteCredential(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.cfg.Store.DeleteCredential(id, extractClientIP(r)); err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleGenerateKeyPair(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Algorithm    string `json:"algorithm"`
		Comment      string `json:"comment"`
		Passphrase   string `json:"passphrase"`
		SaveName     string `json:"save_name"`
		UsernameHint string `json:"username_hint"`
		Notes        string `json:"notes"`
	}
	if err := decodeJSON(r, &req, 64*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "密钥生成参数格式错误")
		return
	}
	kp, err := sshmanager.GenerateSSHKeyPair(req.Algorithm, req.Comment, req.Passphrase)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	resp := map[string]any{
		"algorithm":   kp.Algorithm,
		"public_key":  kp.PublicKey,
		"fingerprint": kp.Fingerprint,
	}
	if strings.TrimSpace(req.SaveName) != "" {
		privCopy := kp.PrivateKey
		passCopy := req.Passphrase
		saved, cErr := s.cfg.Store.CreateCredential(vault.CredentialMutationInput{
			Name:         req.SaveName,
			Kind:         vault.AuthPrivateKey,
			UsernameHint: req.UsernameHint,
			PrivateKey:   &privCopy,
			Passphrase:   &passCopy,
			PublicKey:    kp.PublicKey,
			Fingerprint:  kp.Fingerprint,
			KeyAlgorithm: kp.Algorithm,
			Notes:        req.Notes,
		}, extractClientIP(r))
		if cErr != nil {
			writeDomainError(w, cErr)
			return
		}
		resp["credential"] = saved
	} else {
		resp["private_key"] = kp.PrivateKey
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleDeployPublicKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ServerID     string `json:"server_id"`
		CredentialID string `json:"credential_id"`
		PublicKey    string `json:"public_key"`
	}
	if err := decodeJSON(r, &req, 64*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "公钥部署参数格式错误")
		return
	}
	pubKey := strings.TrimSpace(req.PublicKey)
	if pubKey == "" && req.CredentialID != "" {
		cred, err := s.cfg.Store.GetCredentialSecret(req.CredentialID)
		if err != nil {
			writeDomainError(w, err)
			return
		}
		pubKey = cred.PublicKey
	}
	if err := s.cfg.SSH.DeployPublicKey(req.ServerID, pubKey, extractClientIP(r)); err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleListSnippets(w http.ResponseWriter, r *http.Request) {
	snips, err := s.cfg.Store.ListSnippets()
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"snippets": snips})
}

func (s *Server) handleUpsertSnippet(w http.ResponseWriter, r *http.Request) {
	var in vault.Snippet
	if err := decodeJSON(r, &in, 256*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "快捷指令参数格式错误")
		return
	}
	snip, err := s.cfg.Store.UpsertSnippet(in, extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"snippet": snip})
}

func (s *Server) handleDeleteSnippet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.cfg.Store.DeleteSnippet(id, extractClientIP(r)); err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleBatchExec(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ServerIDs  []string `json:"server_ids"`
		Command    string   `json:"command"`
		TimeoutSec int      `json:"timeout_sec"`
	}
	if err := decodeJSON(r, &req, 256*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "批量执行参数格式错误")
		return
	}
	results := s.cfg.SSH.BatchExecute(req.ServerIDs, req.Command, time.Duration(req.TimeoutSec)*time.Second, extractClientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

// ============================================================================
// Native SFTP File Management Handlers
// ============================================================================

func (s *Server) handleSFTPList(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ServerID string `json:"server_id"`
		Path     string `json:"path"`
	}
	if err := decodeJSON(r, &req, 64*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "SFTP 目录列表参数格式错误")
		return
	}
	resp, err := s.cfg.SSH.SFTPList(req.ServerID, req.Path, extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleSFTPRead(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ServerID string `json:"server_id"`
		Path     string `json:"path"`
	}
	if err := decodeJSON(r, &req, 64*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "SFTP 读取参数格式错误")
		return
	}
	content, err := s.cfg.SSH.SFTPReadText(req.ServerID, req.Path, extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"path":    req.Path,
		"content": content,
	})
}

func (s *Server) handleSFTPWrite(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ServerID string `json:"server_id"`
		Path     string `json:"path"`
		Content  string `json:"content"`
	}
	if err := decodeJSON(r, &req, 8*1024*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "SFTP 写入参数格式错误")
		return
	}
	if err := s.cfg.SSH.SFTPWriteText(req.ServerID, req.Path, req.Content, extractClientIP(r)); err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleSFTPUpload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 512*1024*1024)
	if err := r.ParseMultipartForm(32 * 1024 * 1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_FORM", "解析 SFTP 上传表单失败")
		return
	}
	serverID := strings.TrimSpace(r.FormValue("server_id"))
	dir := r.FormValue("dir")
	file, fh, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "MISSING_FILE", "未找到上传文件")
		return
	}
	defer file.Close()

	filename := strings.TrimSpace(r.FormValue("filename"))
	if filename == "" && fh != nil {
		filename = fh.Filename
	}

	destPath, written, err := s.cfg.SSH.SFTPUpload(serverID, dir, filename, file, extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":    true,
		"path":  destPath,
		"bytes": written,
	})
}

func (s *Server) handleSFTPDownload(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ServerID string `json:"server_id"`
		Path     string `json:"path"`
	}
	if err := decodeJSON(r, &req, 64*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "SFTP 下载参数格式错误")
		return
	}
	data, name, err := s.cfg.SSH.SFTPDownloadBytes(req.ServerID, req.Path, 256*1024*1024, extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Filename", name)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, strings.NewReader(""))
	_, _ = w.Write(data)
}

func (s *Server) handleSFTPMkdir(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ServerID string `json:"server_id"`
		Path     string `json:"path"`
	}
	if err := decodeJSON(r, &req, 64*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "SFTP 新建目录参数格式错误")
		return
	}
	if err := s.cfg.SSH.SFTPMkdir(req.ServerID, req.Path, extractClientIP(r)); err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleSFTPRename(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ServerID string `json:"server_id"`
		OldPath  string `json:"old_path"`
		NewPath  string `json:"new_path"`
	}
	if err := decodeJSON(r, &req, 64*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "SFTP 重命名参数格式错误")
		return
	}
	if err := s.cfg.SSH.SFTPRename(req.ServerID, req.OldPath, req.NewPath, extractClientIP(r)); err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleSFTPDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ServerID string `json:"server_id"`
		Path     string `json:"path"`
	}
	if err := decodeJSON(r, &req, 64*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "SFTP 删除参数格式错误")
		return
	}
	if err := s.cfg.SSH.SFTPRemove(req.ServerID, req.Path, extractClientIP(r)); err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleSFTPChmod(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ServerID string `json:"server_id"`
		Path     string `json:"path"`
		Mode     string `json:"mode"`
	}
	if err := decodeJSON(r, &req, 64*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "SFTP 权限参数格式错误")
		return
	}
	if err := s.cfg.SSH.SFTPChmod(req.ServerID, req.Path, req.Mode, extractClientIP(r)); err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

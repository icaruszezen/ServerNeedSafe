package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/sshmanager"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

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
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "请求参数格式错误")
		return
	}
	view, err := s.cfg.Store.CreateServer(in, extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"server": view})
}

func (s *Server) handleUpdateServer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in vault.ServerMutationInput
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "请求参数格式错误")
		return
	}
	view, err := s.cfg.Store.UpdateServer(id, in, extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"server": view})
}

func (s *Server) handleDeleteServer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.cfg.Store.DeleteServer(id, extractClientIP(r)); err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleProbeServer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var body struct {
		TrustFingerprint string `json:"trust_fingerprint"`
	}
	_ = decodeJSON(r, &body)

	res, err := s.cfg.SSH.ProbeServer(id, body.TrustFingerprint, extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"probe": res})
}

func (s *Server) handleAddGroup(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "请求格式错误")
		return
	}
	groups, err := s.cfg.Store.AddGroup(body.Name)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"groups": groups})
}

func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	groups, err := s.cfg.Store.DeleteGroup(name)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"groups": groups})
}

// --- Credentials & SSH KeyGen ---

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
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "请求格式错误")
		return
	}
	view, err := s.cfg.Store.CreateCredential(in, extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"credential": view})
}

func (s *Server) handleUpdateCredential(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in vault.CredentialMutationInput
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "请求格式错误")
		return
	}
	view, err := s.cfg.Store.UpdateCredential(id, in, extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"credential": view})
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
	var body struct {
		Algorithm    string `json:"algorithm"`
		Comment      string `json:"comment"`
		Passphrase   string `json:"passphrase"`
		SaveName     string `json:"save_name"`
		UsernameHint string `json:"username_hint"`
		Notes        string `json:"notes"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "请求格式错误")
		return
	}

	kp, err := sshmanager.GenerateSSHKeyPair(body.Algorithm, body.Comment, body.Passphrase)
	if err != nil {
		writeDomainError(w, err)
		return
	}

	var savedView *vault.CredentialView
	if strings.TrimSpace(body.SaveName) != "" {
		priv := kp.PrivateKey
		pass := body.Passphrase
		created, saveErr := s.cfg.Store.CreateCredential(vault.CredentialMutationInput{
			Name:         body.SaveName,
			Kind:         vault.AuthPrivateKey,
			UsernameHint: body.UsernameHint,
			PrivateKey:   &priv,
			Passphrase:   &pass,
			PublicKey:    kp.PublicKey,
			Fingerprint:  kp.Fingerprint,
			KeyAlgorithm: kp.Algorithm,
			Notes:        body.Notes,
		}, extractClientIP(r))
		if saveErr != nil {
			writeDomainError(w, saveErr)
			return
		}
		savedView = created
	} else {
		s.cfg.Store.RecordAudit("key.generate", kp.Algorithm, "生成临时 SSH 密钥对 ("+kp.Fingerprint+")", extractClientIP(r), true)
	}

	// Only return raw private_key if NOT saved directly into vault keychain (or if user explicitly didn't save)
	resp := map[string]any{
		"algorithm":   kp.Algorithm,
		"public_key":  kp.PublicKey,
		"fingerprint": kp.Fingerprint,
		"credential":  savedView,
	}
	if savedView == nil {
		resp["private_key"] = kp.PrivateKey
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleDeployPublicKey(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ServerID     string `json:"server_id"`
		CredentialID string `json:"credential_id"`
		PublicKey    string `json:"public_key"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "请求格式错误")
		return
	}
	pubKey := strings.TrimSpace(body.PublicKey)
	if pubKey == "" && body.CredentialID != "" {
		cred, err := s.cfg.Store.GetCredentialSecret(body.CredentialID)
		if err != nil {
			writeDomainError(w, err)
			return
		}
		pubKey = cred.PublicKey
	}
	if pubKey == "" || body.ServerID == "" {
		writeError(w, http.StatusBadRequest, "MISSING_PARAMS", "请选择目标服务器并提供有效的 SSH 公钥")
		return
	}

	if err := s.cfg.SSH.DeployPublicKey(body.ServerID, pubKey, extractClientIP(r)); err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// --- Snippets & Batch Exec ---

func (s *Server) handleListSnippets(w http.ResponseWriter, r *http.Request) {
	list, err := s.cfg.Store.ListSnippets()
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"snippets": list})
}

func (s *Server) handleUpsertSnippet(w http.ResponseWriter, r *http.Request) {
	var in vault.Snippet
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "请求格式错误")
		return
	}
	out, err := s.cfg.Store.UpsertSnippet(in, extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"snippet": out})
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
	var body struct {
		ServerIDs  []string `json:"server_ids"`
		Command    string   `json:"command"`
		TimeoutSec int      `json:"timeout_sec"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "请求格式错误")
		return
	}
	if len(body.ServerIDs) == 0 || strings.TrimSpace(body.Command) == "" {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "请选择至少一台服务器并输入待执行命令")
		return
	}
	timeout := time.Duration(body.TimeoutSec) * time.Second
	results := s.cfg.SSH.BatchExecute(body.ServerIDs, body.Command, timeout, extractClientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

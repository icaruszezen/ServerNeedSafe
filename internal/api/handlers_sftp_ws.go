package api

import (
	"fmt"
	"io"
	"mime"
	"net/http"
	"path"
	"strconv"

	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

func (s *Server) handleIssueTicket(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Purpose  string `json:"purpose"` // "ws_ssh" or "sftp_download"
		ServerID string `json:"server_id"`
		Path     string `json:"path,omitempty"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "请求格式错误")
		return
	}
	if (body.Purpose != "ws_ssh" && body.Purpose != "sftp_download") || body.ServerID == "" {
		writeError(w, http.StatusBadRequest, "INVALID_TICKET_PURPOSE", "无效的临时授权票据类型")
		return
	}
	ticket, err := s.cfg.Auth.IssueTicket(body.Purpose, body.ServerID, body.Path)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "TICKET_ERROR", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ticket": ticket})
}

func (s *Server) handleWebSocketSSH(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Store.Status() != vault.StatusUnlocked {
		writeError(w, http.StatusUnauthorized, "VAULT_LOCKED", "加密保险库已锁定")
		return
	}
	serverID := r.PathValue("id")
	ticket := r.URL.Query().Get("ticket")
	if _, err := s.cfg.Auth.ConsumeTicket(ticket, "ws_ssh", serverID); err != nil {
		writeError(w, http.StatusUnauthorized, "INVALID_TICKET", "WebSocket 终端连接票据无效或已过期")
		return
	}

	cols, _ := strconv.Atoi(r.URL.Query().Get("cols"))
	rows, _ := strconv.Atoi(r.URL.Query().Get("rows"))
	trustFP := r.URL.Query().Get("trust_fingerprint")

	wsConn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	s.cfg.SSH.ServeWebSocketTerminal(wsConn, serverID, cols, rows, trustFP, extractClientIP(r))
}

// --- SFTP Handlers ---

func (s *Server) handleSFTPList(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	dir := r.URL.Query().Get("path")
	res, err := s.cfg.SSH.SFTPList(serverID, dir, extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleSFTPRead(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	remotePath := r.URL.Query().Get("path")
	content, err := s.cfg.SSH.SFTPReadText(serverID, remotePath, extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"path":    remotePath,
		"content": content,
	})
}

func (s *Server) handleSFTPWrite(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	var body struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "请求格式错误")
		return
	}
	if err := s.cfg.SSH.SFTPWriteText(serverID, body.Path, body.Content, extractClientIP(r)); err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleSFTPUpload(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	// Allow streaming multipart uploads up to 512 MiB
	r.Body = http.MaxBytesReader(w, r.Body, 512*1024*1024)
	mr, err := r.MultipartReader()
	if err != nil {
		writeError(w, http.StatusBadRequest, "BAD_MULTIPART", "解析上传流失败")
		return
	}

	var targetDir string
	var uploadedPath string
	var totalBytes int64

	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			writeError(w, http.StatusBadRequest, "PART_ERROR", err.Error())
			return
		}
		formName := part.FormName()
		if formName == "dir" {
			b, _ := io.ReadAll(io.LimitReader(part, 4096))
			targetDir = string(b)
			_ = part.Close()
			continue
		}
		if formName == "file" && part.FileName() != "" {
			dest, n, upErr := s.cfg.SSH.SFTPUpload(serverID, targetDir, part.FileName(), part, extractClientIP(r))
			_ = part.Close()
			if upErr != nil {
				writeDomainError(w, upErr)
				return
			}
			uploadedPath = dest
			totalBytes = n
			break
		}
		_ = part.Close()
	}

	if uploadedPath == "" {
		writeError(w, http.StatusBadRequest, "NO_FILE", "未收到上传文件")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":    true,
		"path":  uploadedPath,
		"bytes": totalBytes,
	})
}

func (s *Server) handleSFTPDownload(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Store.Status() != vault.StatusUnlocked {
		writeError(w, http.StatusUnauthorized, "VAULT_LOCKED", "加密保险库已锁定")
		return
	}
	serverID := r.PathValue("id")
	ticket := r.URL.Query().Get("ticket")
	remotePath, err := s.cfg.Auth.ConsumeTicket(ticket, "sftp_download", serverID)
	if err != nil || remotePath == "" {
		writeError(w, http.StatusUnauthorized, "INVALID_TICKET", "文件下载票据无效或已过期")
		return
	}

	rc, stat, cleanup, err := s.cfg.SSH.SFTPDownloadStream(serverID, remotePath, extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	defer cleanup()

	baseName := path.Base(remotePath)
	disp := mime.FormatMediaType("attachment", map[string]string{"filename": baseName})
	w.Header().Set("Content-Type", "application/octet-stream")
	if disp != "" {
		w.Header().Set("Content-Disposition", disp)
	} else {
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", baseName))
	}
	w.Header().Set("Content-Length", strconv.FormatInt(stat.Size(), 10))
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, rc)
}

func (s *Server) handleSFTPMkdir(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	var body struct {
		Path string `json:"path"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "请求格式错误")
		return
	}
	if err := s.cfg.SSH.SFTPMkdir(serverID, body.Path, extractClientIP(r)); err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleSFTPRename(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	var body struct {
		OldPath string `json:"old_path"`
		NewPath string `json:"new_path"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "请求格式错误")
		return
	}
	if err := s.cfg.SSH.SFTPRename(serverID, body.OldPath, body.NewPath, extractClientIP(r)); err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleSFTPDelete(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	var body struct {
		Path string `json:"path"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "请求格式错误")
		return
	}
	if err := s.cfg.SSH.SFTPRemove(serverID, body.Path, extractClientIP(r)); err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleSFTPChmod(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	var body struct {
		Path string `json:"path"`
		Mode string `json:"mode"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "请求格式错误")
		return
	}
	if err := s.cfg.SSH.SFTPChmod(serverID, body.Path, body.Mode, extractClientIP(r)); err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/updater"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

func (s *Server) activeSSHTabCount() int {
	if s.cfg.SSH == nil {
		return 0
	}
	return len(s.cfg.SSH.ListActiveSessions())
}

func (s *Server) buildUpdateStatusResponse(ov updater.UpdateOverview) map[string]any {
	return map[string]any{
		"current":          ov.Current,
		"capabilities":     ov.Capabilities,
		"settings":         ov.Settings,
		"latest_release":   ov.LatestRelease,
		"update_available": ov.UpdateAvailable,
		"skipped":          ov.Skipped,
		"checking":         ov.Checking,
		"last_checked_at":  ov.LastCheckedAt,
		"next_check_at":    ov.NextCheckAt,
		"last_error":       ov.LastError,
		"active_mirror":    ov.ActiveMirror,
		"mirrors":          ov.Mirrors,
		"builtin_mirrors":  ov.BuiltinMirrors,
		"job":              ov.Job,
		"docker_commands":  ov.DockerCommands,
		"active_ssh_tabs":  s.activeSSHTabCount(),
	}
}

func (s *Server) handleGetUpdateStatus(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Updater == nil {
		writeError(w, http.StatusServiceUnavailable, "UPDATER_UNAVAILABLE", "更新服务尚未初始化")
		return
	}
	writeJSON(w, http.StatusOK, s.buildUpdateStatusResponse(s.cfg.Updater.Status()))
}

func (s *Server) handleCheckUpdateNow(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Updater == nil {
		writeError(w, http.StatusServiceUnavailable, "UPDATER_UNAVAILABLE", "更新服务尚未初始化")
		return
	}
	var body struct {
		ForceProbe bool `json:"force_probe"`
	}
	_ = decodeJSON(r, &body, 16*1024)

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	ov, err := s.cfg.Updater.CheckNow(ctx, body.ForceProbe)
	resp := s.buildUpdateStatusResponse(ov)
	if err != nil {
		resp["ok"] = false
		resp["error"] = err.Error()
		writeJSON(w, http.StatusOK, resp)
		return
	}
	resp["ok"] = true
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleProbeUpdateMirrors(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Updater == nil {
		writeError(w, http.StatusServiceUnavailable, "UPDATER_UNAVAILABLE", "更新服务尚未初始化")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	results := s.cfg.Updater.ProbeMirrorsNow(ctx)
	ov := s.cfg.Updater.Status()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"mirrors": results,
		"status":  s.buildUpdateStatusResponse(ov),
	})
}

func (s *Server) handleUpdateUpdateConfig(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Store == nil || s.cfg.Updater == nil {
		writeError(w, http.StatusServiceUnavailable, "UPDATER_UNAVAILABLE", "更新服务尚未初始化")
		return
	}

	var req vault.UpdateSettings
	if err := decodeJSON(r, &req, 32*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "更新配置参数格式错误")
		return
	}

	normalizedMirror, err := updater.ValidateCustomMirrorURL(req.CustomMirrorURL)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_MIRROR_URL", err.Error())
		return
	}
	req.CustomMirrorURL = normalizedMirror

	if req.MirrorMode == "custom" && req.CustomMirrorURL == "" {
		writeError(w, http.StatusBadRequest, "MISSING_CUSTOM_MIRROR", "选择「指定自定义加速镜像」时，请先填写或选择一个加速镜像前缀")
		return
	}

	// Preserve skipped_version if caller omitted it intentionally? Wait: allow explicit clear via empty string only when sent,
	// or callers send the full UpdateSettings object. Standardizing on full UpdateSettings object from form.
	updated, err := s.cfg.Store.UpdateUpdateSettings(req, extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	s.cfg.Updater.NotifySettingsUpdated()

	ov := s.cfg.Updater.Status()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"settings": updated,
		"status":   s.buildUpdateStatusResponse(ov),
	})
}

func (s *Server) handleSkipUpdateVersion(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Store == nil || s.cfg.Updater == nil {
		writeError(w, http.StatusServiceUnavailable, "UPDATER_UNAVAILABLE", "更新服务尚未初始化")
		return
	}
	var req struct {
		Version string `json:"version"`
	}
	if err := decodeJSON(r, &req, 16*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "请求参数格式错误")
		return
	}

	cur := s.cfg.Store.GetUpdateSettings()
	cur.SkippedVersion = strings.TrimSpace(req.Version)
	updated, err := s.cfg.Store.UpdateUpdateSettings(cur, extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}

	ov := s.cfg.Updater.Status()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"settings": updated,
		"status":   s.buildUpdateStatusResponse(ov),
	})
}

func (s *Server) handleApplyUpdate(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Updater == nil {
		writeError(w, http.StatusServiceUnavailable, "UPDATER_UNAVAILABLE", "更新服务尚未初始化")
		return
	}
	var req struct {
		ConfirmDisconnectSSH bool `json:"confirm_disconnect_ssh"`
	}
	_ = decodeJSON(r, &req, 16*1024)

	ov, activeSSH, err := s.cfg.Updater.StartUpdate(req.ConfirmDisconnectSSH, extractClientIP(r))
	if err != nil {
		if errors.Is(err, updater.ErrActiveSSHSessions) {
			writeJSON(w, http.StatusConflict, map[string]any{
				"error":           err.Error(),
				"code":            "ACTIVE_SSH_SESSIONS",
				"active_ssh_tabs": activeSSH,
				"status":          s.buildUpdateStatusResponse(ov),
			})
			return
		}
		writeError(w, http.StatusBadRequest, "UPDATE_REJECTED", err.Error())
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]any{
		"ok":     true,
		"status": s.buildUpdateStatusResponse(ov),
	})
}

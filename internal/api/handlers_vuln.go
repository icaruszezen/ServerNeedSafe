package api

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
	"github.com/icaruszezen/ServerNeedSafe/internal/vuln"
)

// ============================================================================
// Vulnerability Monitor (7x24 Official Advisory Rolling Feed) Handlers
// ============================================================================

func (s *Server) handleGetVulnOverview(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Vuln == nil {
		writeError(w, http.StatusServiceUnavailable, "VULN_UNAVAILABLE", "漏洞监测服务尚未就绪")
		return
	}
	q := r.URL.Query()
	splitCSV := func(key string) []string {
		raw := strings.TrimSpace(q.Get(key))
		if raw == "" {
			return nil
		}
		parts := strings.Split(raw, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			if t := strings.TrimSpace(p); t != "" {
				out = append(out, t)
			}
		}
		return out
	}

	days, _ := strconv.Atoi(strings.TrimSpace(q.Get("days")))
	limit, _ := strconv.Atoi(strings.TrimSpace(q.Get("limit")))
	offset, _ := strconv.Atoi(strings.TrimSpace(q.Get("offset")))
	var since time.Time
	if rawSince := strings.TrimSpace(q.Get("since")); rawSince != "" {
		if t, err := time.Parse(time.RFC3339Nano, rawSince); err == nil {
			since = t
		} else if t2, err2 := time.Parse(time.RFC3339, rawSince); err2 == nil {
			since = t2
		}
	}

	ov, err := s.cfg.Vuln.BuildOverview(vuln.QueryFilter{
		AppIDs:     splitCSV("apps"),
		Categories: splitCSV("categories"),
		Severities: splitCSV("severities"),
		State:      strings.TrimSpace(q.Get("state")),
		KEVOnly:    strings.EqualFold(strings.TrimSpace(q.Get("kev_only")), "true") || q.Get("kev_only") == "1",
		FixedOnly:  strings.EqualFold(strings.TrimSpace(q.Get("fixed_only")), "true") || q.Get("fixed_only") == "1",
		Days:       days,
		Search:     strings.TrimSpace(q.Get("search")),
		Since:      since,
		Limit:      limit,
		Offset:     offset,
	})
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ov)
}

func (s *Server) handleSyncVulnsNow(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Vuln == nil {
		writeError(w, http.StatusServiceUnavailable, "VULN_UNAVAILABLE", "漏洞监测服务尚未就绪")
		return
	}
	var req struct {
		AppIDs []string `json:"app_ids"`
		Async  bool     `json:"async"`
	}
	_ = decodeJSON(r, &req, 64*1024)

	if req.Async {
		s.cfg.Vuln.TriggerAsyncSync(req.AppIDs)
		writeJSON(w, http.StatusAccepted, map[string]any{
			"ok":      true,
			"started": true,
			"runtime": s.cfg.Vuln.RuntimeStatus(),
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	res, err := s.cfg.Vuln.SyncNow(ctx, req.AppIDs)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleUpdateVulnConfig(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Vuln == nil {
		writeError(w, http.StatusServiceUnavailable, "VULN_UNAVAILABLE", "漏洞监测服务尚未就绪")
		return
	}
	var in vault.VulnSettingsUpdateInput
	if err := decodeJSON(r, &in, 256*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "漏洞监测配置格式错误")
		return
	}
	view, newlyEnabled, err := s.cfg.Store.UpdateVulnSettings(in, extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	s.cfg.Vuln.Wake()
	if len(newlyEnabled) > 0 {
		s.cfg.Vuln.TriggerAsyncSync(newlyEnabled)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"settings":      view,
		"newly_enabled": newlyEnabled,
		"runtime":       s.cfg.Vuln.RuntimeStatus(),
	})
}

func (s *Server) handleUpsertCustomVulnApp(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Vuln == nil {
		writeError(w, http.StatusServiceUnavailable, "VULN_UNAVAILABLE", "漏洞监测服务尚未就绪")
		return
	}
	var req vault.VulnCustomApp
	if err := decodeJSON(r, &req, 64*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "自定义应用参数格式错误")
		return
	}
	// Default newly added custom app to enabled
	if req.ID == "" {
		req.Enabled = true
	}
	saved, view, err := s.cfg.Store.UpsertCustomVulnApp(req, extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	if saved.Enabled {
		s.cfg.Vuln.TriggerAsyncSync([]string{saved.ID})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"app":      saved,
		"settings": view,
		"runtime":  s.cfg.Vuln.RuntimeStatus(),
	})
}

func (s *Server) handleDeleteCustomVulnApp(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Vuln == nil {
		writeError(w, http.StatusServiceUnavailable, "VULN_UNAVAILABLE", "漏洞监测服务尚未就绪")
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	view, err := s.cfg.Store.DeleteCustomVulnApp(id, extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"settings": view,
		"runtime":  s.cfg.Vuln.RuntimeStatus(),
	})
}

func (s *Server) handleUpdateVulnState(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDs     []string `json:"ids"`
		ID      string   `json:"id"`
		Read    *bool    `json:"read,omitempty"`
		Starred *bool    `json:"starred,omitempty"`
		Ignored *bool    `json:"ignored,omitempty"`
	}
	if err := decodeJSON(r, &req, 128*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "状态更新参数格式错误")
		return
	}
	ids := req.IDs
	if strings.TrimSpace(req.ID) != "" {
		ids = append(ids, strings.TrimSpace(req.ID))
	}
	updated := s.cfg.Store.UpdateVulnUserStates(ids, req.Read, req.Starred, req.Ignored)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":               true,
		"updated":          updated,
		"vuln_unread_high": s.cfg.Store.CountUnreadHighVulns(),
	})
}

func (s *Server) handleMarkAllVulnsRead(w http.ResponseWriter, r *http.Request) {
	ts := s.cfg.Store.MarkAllVulnsRead()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":               true,
		"read_all_before":  ts,
		"vuln_unread_high": s.cfg.Store.CountUnreadHighVulns(),
	})
}

func (s *Server) handleExplainVuln(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Vuln == nil {
		writeError(w, http.StatusServiceUnavailable, "VULN_UNAVAILABLE", "漏洞监测服务尚未就绪")
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	var req struct {
		Force bool `json:"force"`
	}
	_ = decodeJSON(r, &req, 16*1024)

	ctx, cancel := context.WithTimeout(r.Context(), 95*time.Second)
	defer cancel()
	analysis, err := s.cfg.Vuln.ExplainAdvisory(ctx, id, req.Force)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"analysis": analysis,
	})
}

func (s *Server) handleTestVulnWebhook(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Vuln == nil {
		writeError(w, http.StatusServiceUnavailable, "VULN_UNAVAILABLE", "漏洞监测服务尚未就绪")
		return
	}
	var req struct {
		CustomWebhookURL     string `json:"custom_webhook_url"`
		ReuseAIPatrolWebhook *bool  `json:"reuse_ai_patrol_webhook"`
	}
	_ = decodeJSON(r, &req, 32*1024)

	stored, _ := s.cfg.Store.GetVulnSettings()
	urlVal := strings.TrimSpace(req.CustomWebhookURL)
	if urlVal == "" {
		urlVal = stored.CustomWebhookURL
	}
	reuse := stored.ReuseAIPatrolWebhook
	if req.ReuseAIPatrolWebhook != nil {
		reuse = *req.ReuseAIPatrolWebhook
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	if err := s.cfg.Vuln.TestWebhook(ctx, urlVal, reuse); err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

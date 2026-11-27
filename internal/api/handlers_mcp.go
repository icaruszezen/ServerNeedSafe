package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/icaruszezen/ServerNeedSafe/internal/aiops"
	"github.com/icaruszezen/ServerNeedSafe/internal/mcp"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

func (s *Server) buildMCPRuntimeStatus(r *http.Request, cfg *vault.MCPConfigView) MCPRuntimeStatus {
	st := MCPRuntimeStatus{
		DeployMode:         s.cfg.DeployMode,
		ServerEndpointPath: "/api/mcp",
	}

	if s.cfg.DeployMode == "desktop" {
		running, addr, lastErr := s.mcpLoopback.Status()
		st.DesktopLoopbackRunning = running
		st.DesktopLoopbackAddr = addr
		st.DesktopLoopbackError = lastErr
		port := 18900
		if cfg != nil && cfg.DesktopLoopbackPort >= 1024 {
			port = cfg.DesktopLoopbackPort
		}
		if addr != "" {
			st.EffectiveEndpointURL = fmt.Sprintf("http://%s/api/mcp", addr)
		} else {
			st.EffectiveEndpointURL = fmt.Sprintf("http://127.0.0.1:%d/api/mcp", port)
		}
		return st
	}

	if cfg != nil && strings.TrimSpace(cfg.PublicEndpointHint) != "" {
		base := strings.TrimRight(strings.TrimSpace(cfg.PublicEndpointHint), "/")
		if strings.HasSuffix(base, "/api/mcp") {
			st.EffectiveEndpointURL = base
		} else {
			st.EffectiveEndpointURL = base + "/api/mcp"
		}
		return st
	}

	scheme := "http"
	if r != nil && isRequestHTTPS(r) {
		scheme = "https"
	}
	host := "127.0.0.1:18899"
	if r != nil {
		if fwdHost := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Host"), ",")[0]); fwdHost != "" {
			host = fwdHost
		} else if strings.TrimSpace(r.Host) != "" {
			host = strings.TrimSpace(r.Host)
		}
	}
	st.EffectiveEndpointURL = fmt.Sprintf("%s://%s/api/mcp", scheme, host)
	return st
}

func (s *Server) syncDesktopMCPLoopback() {
	if s.cfg.DeployMode != "desktop" || s.mcpLoopback == nil || s.mcpServer == nil || s.cfg.Store == nil || !s.cfg.Store.IsReady() {
		return
	}
	cfg, err := s.cfg.Store.GetMCPConfigSecret()
	if err != nil || cfg == nil {
		s.mcpLoopback.Reconcile(false, 0, nil)
		return
	}
	s.mcpLoopback.Reconcile(cfg.DesktopLoopbackEnabled, cfg.DesktopLoopbackPort, s.mcpServer.HTTPHandler(true))
}

func (s *Server) handleGetMCPOverview(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.cfg.Store.GetMCPConfigView()
	if err != nil {
		writeDomainError(w, err)
		return
	}
	approvals, pendingAp, err := s.cfg.Store.ListExternalApprovals("all", 60)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	pendingPatrols, _ := s.cfg.Store.CountExternalPending()
	runtime := s.buildMCPRuntimeStatus(r, cfg)

	writeJSON(w, http.StatusOK, map[string]any{
		"mcp_config":               cfg,
		"mcp_runtime":              runtime,
		"external_approvals":       approvals,
		"pending_approvals_count":  pendingAp,
		"running_approvals_count":  countRunningExternalApprovals(approvals),
		"pending_patrols_count":    pendingPatrols,
		"skill_markdown":           mcp.StandardPatrolSkillMarkdown(runtime.EffectiveEndpointURL),
	})
}

func (s *Server) handleUpdateMCPConfig(w http.ResponseWriter, r *http.Request) {
	var in vault.MCPConfigMutationInput
	if err := decodeJSON(r, &in, 32*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "外部 AI MCP 网关配置格式错误")
		return
	}
	cfg, err := s.cfg.Store.UpdateMCPConfig(in, extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	s.syncDesktopMCPLoopback()
	runtime := s.buildMCPRuntimeStatus(r, cfg)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":             true,
		"mcp_config":     cfg,
		"mcp_runtime":    runtime,
		"skill_markdown": mcp.StandardPatrolSkillMarkdown(runtime.EffectiveEndpointURL),
	})
}

func (s *Server) handleCreateMCPToken(w http.ResponseWriter, r *http.Request) {
	var in vault.CreateMCPTokenInput
	if err := decodeJSON(r, &in, 32*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "创建 MCP 令牌参数格式错误")
		return
	}
	tokView, rawToken, err := s.cfg.Store.CreateMCPToken(in, extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	cfg, _ := s.cfg.Store.GetMCPConfigView()
	runtime := s.buildMCPRuntimeStatus(r, cfg)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"token":       tokView,
		"raw_token":   rawToken,
		"mcp_config":  cfg,
		"mcp_runtime": runtime,
	})
}

func (s *Server) handleUpdateMCPToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in vault.UpdateMCPTokenInput
	if err := decodeJSON(r, &in, 32*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "更新 MCP 令牌参数格式错误")
		return
	}
	tokView, err := s.cfg.Store.UpdateMCPToken(id, in, extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	cfg, _ := s.cfg.Store.GetMCPConfigView()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"token":      tokView,
		"mcp_config": cfg,
	})
}

func (s *Server) handleDeleteMCPToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.cfg.Store.DeleteMCPToken(id, extractClientIP(r)); err != nil {
		writeDomainError(w, err)
		return
	}
	cfg, _ := s.cfg.Store.GetMCPConfigView()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"mcp_config": cfg,
	})
}

func countRunningExternalApprovals(approvals []vault.ExternalApproval) int {
	n := 0
	for _, ap := range approvals {
		if ap.Status == "running" {
			n++
		}
	}
	return n
}

func (s *Server) handleListUnifiedApprovals(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	summaryOnly := strings.EqualFold(strings.TrimSpace(q.Get("summary_only")), "1") ||
		strings.EqualFold(strings.TrimSpace(q.Get("summary_only")), "true")
	if summaryOnly {
		if !s.cfg.Store.IsReady() {
			writeDomainError(w, vault.ErrVaultLocked)
			return
		}
		pendingExt, runningExt, pendingSess := s.cfg.Store.CountApprovalSummary()
		_, patrolUnread, _ := s.cfg.Store.ListPatrolRecords(1, false)
		writeJSON(w, http.StatusOK, map[string]any{
			"pending_external_count": pendingExt,
			"running_external_count": runningExt,
			"pending_session_count":  pendingSess,
			"pending_total":          pendingExt + pendingSess,
			"patrol_unread":          patrolUnread,
		})
		return
	}

	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 200 {
		limit = 80
	}
	extApprovals, pendingExt, err := s.cfg.Store.ListExternalApprovals("all", limit)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	sessApprovals, pendingSess, err := s.cfg.Store.ListSessionApprovals(limit)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	runningExt := countRunningExternalApprovals(extApprovals)
	writeJSON(w, http.StatusOK, map[string]any{
		"external_approvals":     extApprovals,
		"session_approvals":      sessApprovals,
		"pending_external_count": pendingExt,
		"running_external_count": runningExt,
		"pending_session_count":  pendingSess,
		"pending_total":          pendingExt + pendingSess,
	})
}

func (s *Server) handleListExternalApprovals(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	status := strings.TrimSpace(q.Get("status"))
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 120 {
		limit = 60
	}
	approvals, pending, err := s.cfg.Store.ListExternalApprovals(status, limit)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"approvals":     approvals,
		"pending_count": pending,
		"running_count": countRunningExternalApprovals(approvals),
	})
}

func (s *Server) handleResolveExternalApproval(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		Approve         bool      `json:"approve"`
		SelectedStepIDs *[]string `json:"selected_step_ids,omitempty"`
	}
	if err := decodeJSON(r, &req, 64*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "外部 AI 审批参数格式错误")
		return
	}
	ap, err := s.cfg.AI.ResolveExternalApproval(r.Context(), id, aiops.ResolveExternalApprovalInput{
		Approve:         req.Approve,
		SelectedStepIDs: req.SelectedStepIDs,
	}, extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	approvals, pending, _ := s.cfg.Store.ListExternalApprovals("all", 60)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"approval":      ap,
		"approvals":     approvals,
		"pending_count": pending,
		"running_count": countRunningExternalApprovals(approvals),
	})
}

func (s *Server) handleCancelExternalApproval(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ap, err := s.cfg.AI.CancelExternalApproval(id, extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	approvals, pending, _ := s.cfg.Store.ListExternalApprovals("all", 60)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"approval":      ap,
		"approvals":     approvals,
		"pending_count": pending,
		"running_count": countRunningExternalApprovals(approvals),
	})
}

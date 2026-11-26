package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/aiops"
	"github.com/icaruszezen/ServerNeedSafe/internal/mcp"
	"github.com/icaruszezen/ServerNeedSafe/internal/monitor"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

// ============================================================================
// 7x24 Server Status Monitoring & Time-Series Telemetry Handlers
// ============================================================================

func (s *Server) handleGetMonitorOverview(w http.ResponseWriter, r *http.Request) {
	ov, err := s.cfg.Store.GetMonitorOverview()
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"settings": ov.Settings,
		"kpi":      ov.KPI,
		"nodes":    ov.Nodes,
		"alerts":   ov.Alerts,
		"runtime":  s.cfg.Monitor.Status(),
	})
}

func (s *Server) handleGetServerMonitorDetail(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	rng := strings.TrimSpace(r.URL.Query().Get("range"))
	detail, err := s.cfg.Store.GetServerMonitorDetail(id, monitor.ParseHistoryRange(rng))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"detail":  detail,
		"runtime": s.cfg.Monitor.Status(),
	})
}

func (s *Server) handleCollectAllMonitor(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ServerIDs []string `json:"server_ids"`
	}
	_ = decodeJSON(r, &req, 64*1024)
	snaps, err := s.cfg.Monitor.CollectAllNow(r.Context(), req.ServerIDs, extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":        true,
		"count":     len(snaps),
		"snapshots": snaps,
		"runtime":   s.cfg.Monitor.Status(),
	})
}

func (s *Server) handleCollectServerMonitor(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID               string `json:"id"`
		TrustFingerprint string `json:"trust_fingerprint"`
	}
	if err := decodeJSON(r, &req, 64*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "采集请求格式错误")
		return
	}
	snap, err := s.cfg.Monitor.CollectServerNow(r.Context(), req.ID, req.TrustFingerprint, extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"snapshot": snap,
		"runtime":  s.cfg.Monitor.Status(),
	})
}

func (s *Server) handleAcceptPortBaseline(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if err := decodeJSON(r, &req, 32*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "端口基线请求格式错误")
		return
	}
	base, err := s.cfg.Store.AcceptServerPortBaseline(req.ID, extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"port_baseline": base,
	})
}

func (s *Server) handleAcceptSecurityBaseline(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if err := decodeJSON(r, &req, 32*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "安全基线请求格式错误")
		return
	}
	base, err := s.cfg.Store.AcceptServerSecurityBaseline(req.ID, extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                true,
		"security_baseline": base,
	})
}

func (s *Server) handleTestMonitorWebhook(w http.ResponseWriter, r *http.Request) {
	var req struct {
		WebhookURL            string `json:"webhook_url"`
		ReuseAIPatrolWebhooks *bool  `json:"reuse_ai_patrol_webhooks"`
	}
	if err := decodeJSON(r, &req, 32*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "Webhook 测试参数格式错误")
		return
	}
	urlVal := strings.TrimSpace(req.WebhookURL)
	reuseAI := false
	if req.ReuseAIPatrolWebhooks != nil {
		reuseAI = *req.ReuseAIPatrolWebhooks
	} else if stored, _, err := s.cfg.Store.GetMonitorPolicy(); err == nil {
		reuseAI = stored.ReuseAIPatrolWebhooks
		if urlVal == "" {
			urlVal = stored.WebhookURL
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	if err := s.cfg.Monitor.TestWebhook(ctx, urlVal, reuseAI, extractClientIP(r)); err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"runtime": s.cfg.Monitor.Status(),
	})
}

func (s *Server) handleListMonitorAlerts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	status := strings.TrimSpace(q.Get("status"))
	serverID := strings.TrimSpace(q.Get("server_id"))
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 300
	}
	alerts, err := s.cfg.Store.ListMonitorAlerts(status, serverID, limit)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"alerts": alerts})
}

func (s *Server) handleAckMonitorAlert(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if err := decodeJSON(r, &req, 32*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "确认告警参数格式错误")
		return
	}
	al, err := s.cfg.Store.AcknowledgeMonitorAlert(req.ID, extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":    true,
		"alert": al,
	})
}

func (s *Server) handleClearResolvedMonitorAlerts(w http.ResponseWriter, r *http.Request) {
	removed, err := s.cfg.Store.ClearResolvedMonitorAlerts(extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"removed": removed,
	})
}

func (s *Server) handleGetMonitorPolicy(w http.ResponseWriter, r *http.Request) {
	settings, rules, err := s.cfg.Store.GetMonitorPolicy()
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"settings": settings,
		"rules":    rules,
		"runtime":  s.cfg.Monitor.Status(),
	})
}

func (s *Server) handleUpdateMonitorPolicy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Settings vault.MonitorSettings    `json:"settings"`
		Rules    []vault.MonitorAlertRule `json:"rules"`
	}
	if err := decodeJSON(r, &req, 256*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "监控策略参数格式错误")
		return
	}
	settings, rules, err := s.cfg.Store.UpdateMonitorPolicy(req.Settings, req.Rules, extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	s.cfg.Monitor.OnPolicyUpdated(settings)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"settings": settings,
		"rules":    rules,
		"runtime":  s.cfg.Monitor.Status(),
	})
}

func (s *Server) handleClearMonitorHistory(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ServerID string `json:"server_id"`
	}
	_ = decodeJSON(r, &req, 32*1024)
	if err := s.cfg.Store.ClearMonitorHistory(req.ServerID, extractClientIP(r)); err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleExportMonitorHistory(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	format := strings.TrimSpace(q.Get("format"))
	serverID := strings.TrimSpace(q.Get("server_id"))
	rng := strings.TrimSpace(q.Get("range"))
	raw, filename, contentType, err := monitor.ExportHistory(s.cfg.Store, format, serverID, rng, extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("X-Filename", filename)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

// ============================================================================
// 7x24 AI Ops Agent, SSE Streaming, Hybrid Memory, Runbooks & Scheduled Patrol
// ============================================================================

func (s *Server) handleGetAIOverview(w http.ResponseWriter, r *http.Request) {
	scope := strings.TrimSpace(r.URL.Query().Get("scope"))
	activeID, defaultMode, providers, patrolCfg, err := s.cfg.Store.GetAISettingsView()
	if err != nil {
		writeDomainError(w, err)
		return
	}
	agentsMD, err := s.cfg.Store.GetAgentsMD()
	if err != nil {
		writeDomainError(w, err)
		return
	}
	memoryCfg, err := s.cfg.Store.GetAIMemoryConfig()
	if err != nil {
		writeDomainError(w, err)
		return
	}
	hostMemories, err := s.cfg.Store.ListHostMemories()
	if err != nil {
		writeDomainError(w, err)
		return
	}
	longMemories, err := s.cfg.Store.ListAIMemories()
	if err != nil {
		writeDomainError(w, err)
		return
	}
	runbooks, err := s.cfg.Store.ListRunbooks()
	if err != nil {
		writeDomainError(w, err)
		return
	}
	sessions, err := s.cfg.Store.ListAISessions(scope)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	records, unread, _ := s.cfg.Store.ListPatrolRecords(20, false)
	patrolStatus := s.cfg.AI.GetPatrolStatus()
	patrolStatus.UnreadAlerts = unread

	mcpCfg, _ := s.cfg.Store.GetMCPConfigView()
	mcpRuntime := s.buildMCPRuntimeStatus(r, mcpCfg)
	extApprovals, pendingExtAp, _ := s.cfg.Store.ListExternalApprovals("all", 60)

	writeJSON(w, http.StatusOK, map[string]any{
		"active_provider_id":         activeID,
		"default_mode":               defaultMode,
		"providers":                  providers,
		"presets":                    aiops.BuiltinProviderPresets(),
		"agents_md":                  agentsMD,
		"agents_md_template":         vault.DefaultAgentsMDTemplate(),
		"memory_config":              memoryCfg,
		"patrol_config":              patrolCfg,
		"patrol_status":              patrolStatus,
		"patrol_records":             records,
		"mcp_config":                 mcpCfg,
		"mcp_runtime":                mcpRuntime,
		"external_approvals":         extApprovals,
		"pending_external_approvals": pendingExtAp,
		"skill_markdown":             mcp.StandardPatrolSkillMarkdown(mcpRuntime.EffectiveEndpointURL),
		"host_memories":              hostMemories,
		"memories":                   longMemories,
		"runbooks":                   runbooks,
		"sessions":                   sessions,
	})
}

func (s *Server) handleUpsertAIProvider(w http.ResponseWriter, r *http.Request) {
	var in vault.AIProviderMutationInput
	if err := decodeJSON(r, &in, 128*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "AI 模型配置参数格式错误")
		return
	}
	provView, activeID, err := s.cfg.Store.UpsertAIProvider(in, extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"provider":           provView,
		"active_provider_id": activeID,
	})
}

func (s *Server) handleSetActiveAIProvider(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProviderID  string                `json:"provider_id"`
		DefaultMode vault.AIExecutionMode `json:"default_mode"`
	}
	if err := decodeJSON(r, &req, 64*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "切换活跃模型参数格式错误")
		return
	}
	if err := s.cfg.Store.SetActiveAIProvider(req.ProviderID, req.DefaultMode, extractClientIP(r)); err != nil {
		writeDomainError(w, err)
		return
	}
	activeID, defMode, _, _, _ := s.cfg.Store.GetAISettingsView()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                 true,
		"active_provider_id": activeID,
		"default_mode":       defMode,
	})
}

func (s *Server) handleDeleteAIProvider(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	activeID, err := s.cfg.Store.DeleteAIProvider(id, extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                 true,
		"active_provider_id": activeID,
	})
}

func (s *Server) handleTestAIProvider(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID       string           `json:"id"`
		Protocol vault.AIProtocol `json:"protocol"`
		BaseURL  string           `json:"base_url"`
		APIKey   string           `json:"api_key"`
		Model    string           `json:"model"`
	}
	if err := decodeJSON(r, &req, 64*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "测试连接参数格式错误")
		return
	}
	var cfg vault.AIProviderConfig
	var storedBaseURL string
	var storedProtocol vault.AIProtocol
	if req.ID != "" {
		if stored, sErr := s.cfg.Store.GetAIProviderSecret(req.ID); sErr == nil && stored != nil {
			cfg = *stored
			storedBaseURL = cfg.BaseURL
			storedProtocol = cfg.Protocol
			if storedProtocol == "" {
				storedProtocol = vault.AIProtocolOpenAI
			}
		}
	}
	if req.Protocol != "" {
		cfg.Protocol = req.Protocol
	}
	if cfg.Protocol == "" {
		cfg.Protocol = vault.AIProtocolOpenAI
	}
	if strings.TrimSpace(req.BaseURL) != "" {
		cfg.BaseURL = strings.TrimSpace(req.BaseURL)
	}
	if strings.TrimSpace(req.Model) != "" {
		cfg.Model = strings.TrimSpace(req.Model)
	}
	if strings.TrimSpace(req.APIKey) != "" {
		cfg.APIKey = strings.TrimSpace(req.APIKey)
	} else if cfg.APIKey != "" && (!vault.SameEndpointURL(cfg.BaseURL, storedBaseURL) || cfg.Protocol != storedProtocol) {
		// The stored (masked) API key must never be sent to a caller-chosen endpoint: otherwise anyone
		// holding a session could exfiltrate the plaintext key by "testing" against their own server.
		cfg.APIKey = ""
		req.APIKey = ""
		writeDomainError(w, fmt.Errorf("%w: 更换接口地址或协议时必须重新填写 API Key", vault.ErrInvalidInput))
		return
	}
	req.APIKey = ""
	if cfg.BaseURL == "" || cfg.Model == "" {
		writeDomainError(w, fmt.Errorf("%w: 请填写接口地址与模型名称", vault.ErrInvalidInput))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	latencyMs, reply, err := s.cfg.AI.LLM().TestConnection(ctx, cfg)
	cfg.APIKey = ""
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"latency_ms": latencyMs,
		"reply":      reply,
	})
}

func (s *Server) handleListAISessions(w http.ResponseWriter, r *http.Request) {
	scope := strings.TrimSpace(r.URL.Query().Get("scope"))
	sessions, err := s.cfg.Store.ListAISessions(scope)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": sessions})
}

func (s *Server) handleCreateAISession(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Title     string                `json:"title"`
		Scope     string                `json:"scope"`
		ServerIDs []string              `json:"server_ids"`
		Mode      vault.AIExecutionMode `json:"mode"`
	}
	if err := decodeJSON(r, &req, 64*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "创建会话参数格式错误")
		return
	}
	sess, err := s.cfg.Store.CreateAISession(req.Title, req.Scope, req.ServerIDs, req.Mode)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"session": sess})
}

func (s *Server) handleGetAISession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	sess, err := s.cfg.Store.GetAISession(id)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"session": sess})
}

func (s *Server) handleUpdateAISession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		Mode      vault.AIExecutionMode `json:"mode,omitempty"`
		ServerIDs *[]string             `json:"server_ids,omitempty"`
		Title     *string               `json:"title,omitempty"`
	}
	if err := decodeJSON(r, &req, 64*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "更新会话参数格式错误")
		return
	}
	sess, err := s.cfg.Store.GetAISession(id)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	if req.Mode == vault.AIModeSuggest || req.Mode == vault.AIModeStandard || req.Mode == vault.AIModeAutonomous {
		sess.Mode = req.Mode
	}
	if req.ServerIDs != nil {
		sess.ServerIDs = *req.ServerIDs
	}
	if req.Title != nil && strings.TrimSpace(*req.Title) != "" {
		sess.Title = strings.TrimSpace(*req.Title)
	}
	if err := s.cfg.Store.SaveAISession(*sess); err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"session": sess})
}

func (s *Server) handleDeleteAISession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.cfg.Store.DeleteAISession(id, extractClientIP(r)); err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func prepareSSEWriter(w http.ResponseWriter) (func(aiops.StreamEvent), bool) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		return nil, false
	}
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	var mu sync.Mutex
	emit := func(ev aiops.StreamEvent) {
		raw, err := json.Marshal(ev)
		if err != nil {
			return
		}
		mu.Lock()
		_, _ = fmt.Fprintf(w, "data: %s\n\n", raw)
		flusher.Flush()
		mu.Unlock()
	}
	return emit, true
}

func (s *Server) handleStreamAIChat(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID       string                `json:"session_id"`
		Message         string                `json:"message"`
		ServerIDs       []string              `json:"server_ids,omitempty"`
		Mode            vault.AIExecutionMode `json:"mode,omitempty"`
		TerminalContext string                `json:"terminal_context,omitempty"`
	}
	if err := decodeJSON(r, &req, 512*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "AI 对话请求格式错误")
		return
	}

	emit, ok := prepareSSEWriter(w)
	if !ok {
		writeError(w, http.StatusInternalServerError, "SSE_UNSUPPORTED", "当前 HTTP 连接不支持流式响应")
		return
	}

	if err := s.cfg.AI.RunChatStream(r.Context(), aiops.ChatRequest{
		SessionID:       req.SessionID,
		Message:         req.Message,
		ServerIDs:       req.ServerIDs,
		Mode:            req.Mode,
		TerminalContext: req.TerminalContext,
		ClientIP:        extractClientIP(r),
	}, emit); err != nil {
		emit(aiops.StreamEvent{Type: "error", Error: err.Error()})
	}
}

func (s *Server) handleStreamAIApproval(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID  string `json:"session_id"`
		ApprovalID string `json:"approval_id"`
		Approve    bool   `json:"approve"`
	}
	if err := decodeJSON(r, &req, 64*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "审批请求格式错误")
		return
	}

	emit, ok := prepareSSEWriter(w)
	if !ok {
		writeError(w, http.StatusInternalServerError, "SSE_UNSUPPORTED", "当前 HTTP 连接不支持流式响应")
		return
	}

	if err := s.cfg.AI.ResolveApprovalStream(r.Context(), req.SessionID, req.ApprovalID, req.Approve, extractClientIP(r), emit); err != nil {
		emit(aiops.StreamEvent{Type: "error", Error: err.Error()})
	}
}

func (s *Server) handleUpsertHostMemory(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("serverId")
	var in vault.HostMemory
	if err := decodeJSON(r, &in, 256*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "主机记忆参数格式错误")
		return
	}
	in.ServerID = serverID
	mem, err := s.cfg.Store.UpsertHostMemory(in, false, extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"memory": mem})
}

func (s *Server) handleDeleteHostMemory(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("serverId")
	if err := s.cfg.Store.DeleteHostMemory(serverID, extractClientIP(r)); err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleSyncHostMemoryFromMonitor(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ServerID string `json:"server_id"`
	}
	_ = decodeJSON(r, &req, 32*1024)
	memories, syncedCount, err := s.cfg.Store.SyncHostMemoriesFromMonitor(strings.TrimSpace(req.ServerID), extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"synced_count":  syncedCount,
		"host_memories": memories,
	})
}

func (s *Server) handleUpdateAgentsMD(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled      bool   `json:"enabled"`
		Content      string `json:"content"`
		ResetDefault bool   `json:"reset_default"`
	}
	if err := decodeJSON(r, &req, 128*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "AGENTS.md 请求参数格式错误")
		return
	}
	cfg, err := s.cfg.Store.UpdateAgentsMD(req.Enabled, req.Content, req.ResetDefault, extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":        true,
		"agents_md": cfg,
	})
}

func (s *Server) handleUpdateAIMemoryConfig(w http.ResponseWriter, r *http.Request) {
	var in vault.AIMemoryConfig
	if err := decodeJSON(r, &in, 32*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "记忆与上下文预算配置参数格式错误")
		return
	}
	cfg, err := s.cfg.Store.UpdateAIMemoryConfig(in, extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"memory_config": cfg,
	})
}

func (s *Server) handleResolveAgentsMDProposal(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProposalID string `json:"proposal_id"`
		Accept     bool   `json:"accept"`
	}
	if err := decodeJSON(r, &req, 64*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "AGENTS.md 修订提案参数格式错误")
		return
	}
	cfg, prop, err := s.cfg.Store.ResolveAgentsMDProposal(strings.TrimSpace(req.ProposalID), req.Accept, extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":        true,
		"agents_md": cfg,
		"proposal":  prop,
	})
}

func (s *Server) handleListAIMemories(w http.ResponseWriter, r *http.Request) {
	memories, err := s.cfg.Store.ListAIMemories()
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"memories": memories})
}

func (s *Server) handleUpsertAIMemory(w http.ResponseWriter, r *http.Request) {
	var in vault.AIMemoryEntry
	if err := decodeJSON(r, &in, 128*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "长期记忆参数格式错误")
		return
	}
	saved, err := s.cfg.Store.UpsertAIMemory(in, false, extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"memory": saved})
}

func (s *Server) handleDeleteAIMemory(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.cfg.Store.DeleteAIMemory(id, extractClientIP(r)); err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleInspectAISessionContext(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	inspection, err := s.cfg.AI.InspectSessionContext(id)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"context": inspection})
}

func (s *Server) handleCompactAISession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		Reset bool `json:"reset"`
	}
	_ = decodeJSON(r, &req, 16*1024)
	sess, compInfo, inspection, err := s.cfg.AI.CompactSessionNow(r.Context(), id, req.Reset)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"session":    sess,
		"compaction": compInfo,
		"context":    inspection,
	})
}

func (s *Server) handleResolveRunbookProposal(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProposalID  string `json:"proposal_id"`
		Accept      bool   `json:"accept"`
		SyncSnippet bool   `json:"sync_snippet"`
	}
	if err := decodeJSON(r, &req, 64*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "经验卡提案审批参数格式错误")
		return
	}
	rb, err := s.cfg.Store.ResolveRunbookProposal(req.ProposalID, req.Accept, req.SyncSnippet, extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"runbook": rb,
	})
}

func (s *Server) handleUpsertRunbook(w http.ResponseWriter, r *http.Request) {
	var req struct {
		vault.AIRunbook
		SyncSnippet bool `json:"sync_snippet"`
	}
	if err := decodeJSON(r, &req, 256*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "Runbook 参数格式错误")
		return
	}
	rb, err := s.cfg.Store.UpsertRunbook(req.AIRunbook, req.SyncSnippet, extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"runbook": rb})
}

func (s *Server) handleDeleteRunbook(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.cfg.Store.DeleteRunbook(id, extractClientIP(r)); err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleUpdatePatrolConfig(w http.ResponseWriter, r *http.Request) {
	var in vault.PatrolConfigMutationInput
	if err := decodeJSON(r, &in, 128*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "定时巡检配置参数格式错误")
		return
	}
	view, err := s.cfg.Store.UpdatePatrolConfig(in, extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	s.cfg.AI.NotifyPatrolConfigUpdated()
	writeJSON(w, http.StatusOK, map[string]any{
		"patrol_config": view,
		"patrol_status": s.cfg.AI.GetPatrolStatus(),
	})
}

func (s *Server) handleListPatrolRecords(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 30
	}
	markRead := q.Get("mark_read") == "true" || q.Get("mark_read") == "1"
	records, unread, err := s.cfg.Store.ListPatrolRecords(limit, markRead)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	st := s.cfg.AI.GetPatrolStatus()
	if markRead {
		st.UnreadAlerts = 0
	} else {
		st.UnreadAlerts = unread
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"records":       records,
		"unread_alerts": unread,
		"patrol_status": st,
	})
}

func (s *Server) handleRunPatrolNow(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ForceAI bool `json:"force_ai"`
	}
	_ = decodeJSON(r, &req, 16*1024)
	rec, err := s.cfg.AI.RunPatrolNow(r.Context(), "manual", req.ForceAI)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"record":        rec,
		"patrol_status": s.cfg.AI.GetPatrolStatus(),
	})
}

func (s *Server) handleTestAIWebhook(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		Kind   string `json:"kind"`
		URL    string `json:"url"`
		Secret string `json:"secret"`
	}
	if err := decodeJSON(r, &req, 64*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "Webhook 测试参数格式错误")
		return
	}
	ch := vault.WebhookChannel{
		ID:      req.ID,
		Name:    strings.TrimSpace(req.Name),
		Kind:    strings.TrimSpace(req.Kind),
		URL:     strings.TrimSpace(req.URL),
		Secret:  strings.TrimSpace(req.Secret),
		Enabled: true,
	}
	if req.ID != "" && (ch.URL == "" || ch.Secret == "") {
		if cfg, cErr := s.cfg.Store.GetPatrolConfigSecret(); cErr == nil && cfg != nil {
			for _, wch := range cfg.Webhooks {
				if wch.ID == req.ID {
					// Only sign with the stored secret when delivering to the STORED destination;
					// otherwise a session holder could harvest valid signatures on their own server.
					sameDest := (ch.URL == "" || vault.SameEndpointURL(ch.URL, wch.URL)) && (ch.Kind == "" || ch.Kind == wch.Kind)
					if ch.Secret == "" && wch.Secret != "" && !sameDest {
						writeDomainError(w, fmt.Errorf("%w: 更换 Webhook 地址或类型时必须重新填写签名密钥", vault.ErrInvalidInput))
						return
					}
					if ch.URL == "" {
						ch.URL = wch.URL
					}
					if ch.Secret == "" {
						ch.Secret = wch.Secret
					}
					if ch.Kind == "" {
						ch.Kind = wch.Kind
					}
					if ch.Name == "" {
						ch.Name = wch.Name
					}
					break
				}
			}
		}
	}
	req.Secret = ""
	if ch.URL == "" {
		writeDomainError(w, fmt.Errorf("%w: 请填写完整的 Webhook URL", vault.ErrInvalidInput))
		return
	}
	now := time.Now().UTC()
	sampleRec := vault.PatrolRecord{
		ID:            "test-webhook",
		Trigger:       "manual",
		StartedAt:     now,
		CompletedAt:   now,
		Status:        "warning",
		TotalServers:  2,
		HealthyCount:  1,
		WarningCount:  1,
		CriticalCount: 0,
		Findings: []vault.PatrolFinding{
			{
				ServerName: "示例业务节点 (连通性测试)",
				Host:       "10.0.0.10",
				Reachable:  true,
				Anomalies:  []string{"这是一条由 ServerNeedSafe 7×24 守护进程发出的巡检告警通道连通性测试消息"},
			},
		},
		AISummary:         "Webhook 通道签名与网络投递验证正常，当后台定时巡检发现真实异常时将自动推送至该群组。",
		AIRecommendations: []string{"无需人工处理，您已完成告警通知配置"},
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if err := aiops.SendPatrolAlertWebhook(ctx, s.cfg.AI.LLM().Transport(), ch, sampleRec); err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

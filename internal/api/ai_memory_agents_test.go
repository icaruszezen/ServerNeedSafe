package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/aiops"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

func TestAIMemoryAndAgentsMDHTTPEndpoints(t *testing.T) {
	dataDir := t.TempDir()
	srv, ts := newTestServerInstance(t, dataDir, 8*time.Hour)
	defer ts.Close()
	defer srv.Close()

	rawHTTP := &http.Client{}
	adminClient := newCookieHTTPClient()

	// 1. Setup native admin session
	setupBody, _ := json.Marshal(map[string]string{"password": "AdminSecretPassword!2026"})
	res, err := adminClient.Post(ts.URL+"/api/auth/setup", "application/json", bytes.NewReader(setupBody))
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/auth/setup failed: status=%v err=%v", res, err)
	}
	res.Body.Close()

	// 2. Unauthenticated callers must get 401 on ALL new AI memory/AGENTS.md endpoints
	unauthChecks := []struct {
		method string
		path   string
		body   string
	}{
		{"GET", "/api/ai/memories", ""},
		{"POST", "/api/ai/memories", `{"title":"x","content":"y"}`},
		{"DELETE", "/api/ai/memories/nonexistent", ""},
		{"PUT", "/api/ai/agents-md", `{"enabled":true,"content":"hi"}`},
		{"PUT", "/api/ai/memory-config", `{}`},
		{"POST", "/api/ai/agents-md-proposals/resolve", `{"proposal_id":"p1","accept":true}`},
		{"POST", "/api/ai/host-memory/sync-monitor", `{}`},
		{"GET", "/api/ai/sessions/s1/context", ""},
		{"POST", "/api/ai/sessions/s1/compact", `{}`},
	}
	for _, tc := range unauthChecks {
		req, _ := http.NewRequest(tc.method, ts.URL+tc.path, strings.NewReader(tc.body))
		if tc.body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		uRes, err := rawHTTP.Do(req)
		if err != nil {
			t.Fatalf("unauth %s %s: %v", tc.method, tc.path, err)
		}
		uRes.Body.Close()
		if uRes.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 for unauth %s %s, got %d", tc.method, tc.path, uRes.StatusCode)
		}
	}

	// Helper for authenticated JSON calls
	doJSON := func(method, path string, payload any) *http.Response {
		t.Helper()
		var body *bytes.Reader
		if payload != nil {
			b, _ := json.Marshal(payload)
			body = bytes.NewReader(b)
		} else {
			body = bytes.NewReader(nil)
		}
		req, err := http.NewRequest(method, ts.URL+path, body)
		if err != nil {
			t.Fatalf("NewRequest %s %s: %v", method, path, err)
		}
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := adminClient.Do(req)
		if err != nil {
			t.Fatalf("Do %s %s: %v", method, path, err)
		}
		return resp
	}

	// 3. Create a server & seed monitor snapshot directly in vault
	srvResp := doJSON("POST", "/api/servers", map[string]any{
		"name":      "api-gateway-01",
		"group":     "生产环境",
		"host":      "10.20.30.40",
		"port":      22,
		"username":  "root",
		"auth_type": "password",
		"password":  "GatewayPass!2026",
	})
	if srvResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/servers status=%d", srvResp.StatusCode)
	}
	var srvPayload struct {
		Server vault.ServerView `json:"server"`
	}
	_ = json.NewDecoder(srvResp.Body).Decode(&srvPayload)
	srvResp.Body.Close()
	serverID := srvPayload.Server.ID

	_, _, _, err = srv.cfg.Store.RecordMonitorSnapshots([]*vault.ServerMonitorSnapshot{{
		ServerID:    serverID,
		ServerName:  "api-gateway-01",
		CollectedAt: time.Now().UTC(),
		Reachable:   true,
		HealthLevel: "healthy",
		HealthScore: 96,
		OS:          "Debian 12",
		Kernel:      "6.1.0-25",
		Arch:        "x86_64",
		CPUPercent:  21.4,
		MemPercent:  48.2,
		DiskPercent: 35.0,
		Services:    []vault.ServiceStat{{Name: "nginx.service", State: "active", Watched: true}},
		ListeningPorts: []vault.ListeningPortStat{
			{Port: 443, Proto: "tcp", Process: "nginx", PublicExposed: true},
		},
	}})
	if err != nil {
		t.Fatalf("RecordMonitorSnapshots: %v", err)
	}

	// 4. GET /api/ai/overview exposes agents_md, agents_md_template, memory_config, memories
	ovResp := doJSON("GET", "/api/ai/overview", nil)
	if ovResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/ai/overview status=%d", ovResp.StatusCode)
	}
	var ov struct {
		AgentsMD         vault.AgentsMDConfig  `json:"agents_md"`
		AgentsMDTemplate string                `json:"agents_md_template"`
		MemoryConfig     vault.AIMemoryConfig  `json:"memory_config"`
		Memories         []vault.AIMemoryEntry `json:"memories"`
		HostMemories     []vault.HostMemory    `json:"host_memories"`
	}
	_ = json.NewDecoder(ovResp.Body).Decode(&ov)
	ovResp.Body.Close()
	if !ov.AgentsMD.Enabled || ov.AgentsMDTemplate == "" || ov.MemoryConfig.AgentsMDMaxChars <= 0 || len(ov.HostMemories) != 1 {
		t.Fatalf("unexpected /api/ai/overview payload: %+v", ov)
	}

	// 5. PUT /api/ai/agents-md & PUT /api/ai/memory-config
	agResp := doJSON("PUT", "/api/ai/agents-md", map[string]any{
		"enabled": true,
		"content": "# 团队生产规范\n- 所有 Nginx 修改必须先执行 nginx -t",
	})
	if agResp.StatusCode != http.StatusOK {
		t.Fatalf("PUT /api/ai/agents-md status=%d", agResp.StatusCode)
	}
	var agOut struct {
		AgentsMD vault.AgentsMDConfig `json:"agents_md"`
	}
	_ = json.NewDecoder(agResp.Body).Decode(&agOut)
	agResp.Body.Close()
	if !strings.Contains(agOut.AgentsMD.Content, "nginx -t") {
		t.Fatalf("unexpected updated AGENTS.md: %+v", agOut.AgentsMD)
	}

	mcResp := doJSON("PUT", "/api/ai/memory-config", map[string]any{
		"agents_md_max_chars":          5000,
		"memory_prompt_budget_chars":   4500,
		"compaction_trigger_ratio":     0.72,
		"compaction_keep_recent":       6,
		"auto_sync_monitor_to_memory":  true,
		"auto_record_approved_changes": true,
	})
	if mcResp.StatusCode != http.StatusOK {
		t.Fatalf("PUT /api/ai/memory-config status=%d", mcResp.StatusCode)
	}
	mcResp.Body.Close()

	// 6. POST /api/ai/memories -> GET /api/ai/memories -> DELETE /api/ai/memories/{id}
	mResp := doJSON("POST", "/api/ai/memories", map[string]any{
		"scope":      "server",
		"server_ids": []string{serverID},
		"category":   "topology",
		"title":      "网关上游链路",
		"content":    "api-gateway-01 转发至内网 10.20.30.51:8080 与 10.20.30.52:8080",
		"tags":       []string{"gateway", "upstream"},
		"pinned":     true,
		"importance": 5,
	})
	if mResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/ai/memories status=%d", mResp.StatusCode)
	}
	var mOut struct {
		Memory vault.AIMemoryEntry `json:"memory"`
	}
	_ = json.NewDecoder(mResp.Body).Decode(&mOut)
	mResp.Body.Close()
	if mOut.Memory.ID == "" || !mOut.Memory.Pinned {
		t.Fatalf("unexpected created memory: %+v", mOut.Memory)
	}

	listResp := doJSON("GET", "/api/ai/memories", nil)
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/ai/memories status=%d", listResp.StatusCode)
	}
	var listOut struct {
		Memories []vault.AIMemoryEntry `json:"memories"`
	}
	_ = json.NewDecoder(listResp.Body).Decode(&listOut)
	listResp.Body.Close()
	if len(listOut.Memories) != 1 || listOut.Memories[0].ID != mOut.Memory.ID {
		t.Fatalf("unexpected memories list: %+v", listOut.Memories)
	}

	// 7. POST /api/ai/host-memory/sync-monitor
	syncResp := doJSON("POST", "/api/ai/host-memory/sync-monitor", map[string]any{"server_id": serverID})
	if syncResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/ai/host-memory/sync-monitor status=%d", syncResp.StatusCode)
	}
	syncResp.Body.Close()

	// 8. Create session, inspect context, compact session (fallback mode since no active provider), resolve AGENTS.md proposal
	sessResp := doJSON("POST", "/api/ai/sessions", map[string]any{
		"title":      "API 上下文测试会话",
		"source":     "center",
		"server_ids": []string{serverID},
		"mode":       "standard",
	})
	if sessResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/ai/sessions status=%d", sessResp.StatusCode)
	}
	var sessOut struct {
		Session vault.AIChatSession `json:"session"`
	}
	_ = json.NewDecoder(sessResp.Body).Decode(&sessOut)
	sessResp.Body.Close()
	sessID := sessOut.Session.ID

	// Seed messages + a pending AGENTS.md proposal on the session
	sessPtr, err := srv.cfg.Store.GetAISession(sessID)
	if err != nil {
		t.Fatalf("GetAISession: %v", err)
	}
	now := time.Now().UTC()
	sessPtr.Messages = []vault.AIChatMessage{
		{ID: "m1", Role: "user", Content: "请检查网关状态", Timestamp: now},
		{ID: "m2", Role: "assistant", Content: "网关目前正常，CPU 21%。", Timestamp: now},
		{ID: "m3", Role: "user", Content: "查看 443 端口证书有效期", Timestamp: now},
		{ID: "m4", Role: "assistant", Content: "证书还有 62 天到期。", Timestamp: now},
		{ID: "m5", Role: "user", Content: "记下证书到期提醒", Timestamp: now},
		{ID: "m6", Role: "assistant", Content: "已记录。", Timestamp: now},
	}
	sessPtr.AgentsMDProposals = []vault.AIAgentsMDProposal{{
		ID:              "prop-api-1",
		SessionID:       sessID,
		Summary:         "补充证书巡检周期",
		Reason:          "避免 TLS 证书过期",
		ProposedContent: "# 团队生产规范\n- 所有 Nginx 修改必须先执行 nginx -t\n- 证书剩余 < 30 天必须提前续签",
		DiffPreview:     "--- a/AGENTS.md\n+++ b/AGENTS.md\n+- 证书剩余 < 30 天必须提前续签\n",
		Status:          "pending",
		CreatedAt:       now,
	}}
	if err := srv.cfg.Store.SaveAISession(*sessPtr); err != nil {
		t.Fatalf("SaveAISession: %v", err)
	}

	// Inspect context
	ctxResp := doJSON("GET", "/api/ai/sessions/"+sessID+"/context", nil)
	if ctxResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/ai/sessions/{id}/context status=%d", ctxResp.StatusCode)
	}
	var ctxOut struct {
		Context aiops.SessionContextInspection `json:"context"`
	}
	_ = json.NewDecoder(ctxResp.Body).Decode(&ctxOut)
	ctxResp.Body.Close()
	if !ctxOut.Context.AgentsMDEnabled || len(ctxOut.Context.InjectedMemories) != 1 || len(ctxOut.Context.LiveMonitors) != 1 {
		t.Fatalf("unexpected context inspection: %+v", ctxOut.Context)
	}

	// Compact session
	compResp := doJSON("POST", "/api/ai/sessions/"+sessID+"/compact", map[string]any{"reset": false})
	if compResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/ai/sessions/{id}/compact status=%d", compResp.StatusCode)
	}
	var compOut struct {
		Compaction aiops.CompactionInfo `json:"compaction"`
	}
	_ = json.NewDecoder(compResp.Body).Decode(&compOut)
	compResp.Body.Close()
	if !compOut.Compaction.Triggered || compOut.Compaction.CompactedUntilCount <= 0 {
		t.Fatalf("unexpected compaction response: %+v", compOut.Compaction)
	}

	// Resolve AGENTS.md proposal (accept)
	resProp := doJSON("POST", "/api/ai/agents-md-proposals/resolve", map[string]any{
		"proposal_id": "prop-api-1",
		"accept":      true,
	})
	if resProp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/ai/agents-md-proposals/resolve status=%d", resProp.StatusCode)
	}
	var propOut struct {
		AgentsMD vault.AgentsMDConfig     `json:"agents_md"`
		Proposal vault.AIAgentsMDProposal `json:"proposal"`
	}
	_ = json.NewDecoder(resProp.Body).Decode(&propOut)
	resProp.Body.Close()
	if propOut.Proposal.Status != "accepted" || !strings.Contains(propOut.AgentsMD.Content, "证书剩余 < 30 天") {
		t.Fatalf("unexpected resolved proposal response: %+v", propOut)
	}

	// Delete memory
	delResp := doJSON("DELETE", "/api/ai/memories/"+mOut.Memory.ID, nil)
	if delResp.StatusCode != http.StatusOK {
		t.Fatalf("DELETE /api/ai/memories/{id} status=%d", delResp.StatusCode)
	}
	delResp.Body.Close()
}

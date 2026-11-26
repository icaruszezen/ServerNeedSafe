package aiops

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/sshmanager"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

func setupMemoryTestEnv(t *testing.T, llmHandler http.HandlerFunc) (*vault.Store, *Service, *vault.ServerView, *vault.ServerView, *httptest.Server) {
	t.Helper()
	t.Setenv("NO_PROXY", "127.0.0.1,localhost")

	mockLLM := httptest.NewServer(llmHandler)
	t.Cleanup(mockLLM.Close)

	store, err := vault.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(store.Close)
	if err := store.Setup("StrongMasterPass!2026", "127.0.0.1"); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	srv1, err := store.CreateServer(vault.ServerMutationInput{
		Name:     "edge-nginx-01",
		Group:    "生产环境",
		Host:     "10.88.1.10",
		Port:     22,
		Username: "root",
		AuthType: vault.AuthPassword,
		Password: strPtr("UltraSecretEdgePass#2026"),
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("CreateServer srv1: %v", err)
	}

	srv2, err := store.CreateServer(vault.ServerMutationInput{
		Name:     "db-postgres-01",
		Group:    "核心库",
		Host:     "10.88.2.20",
		Port:     22,
		Username: "root",
		AuthType: vault.AuthPassword,
		Password: strPtr("UltraSecretPgPass#2026"),
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("CreateServer srv2: %v", err)
	}

	_, _, err = store.UpsertAIProvider(vault.AIProviderMutationInput{
		Name:          "Mock OpenAI",
		Protocol:      vault.AIProtocolOpenAI,
		BaseURL:       mockLLM.URL + "/v1",
		APIKey:        strPtr("sk-mock-secret-key-99887766"),
		Model:         "deepseek-chat",
		ContextWindow: 65536,
		SetActive:     true,
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("UpsertAIProvider: %v", err)
	}

	sshMgr := sshmanager.NewManager(store)
	svc := NewService(store, sshMgr)
	t.Cleanup(svc.Close)

	return store, svc, srv1, srv2, mockLLM
}

func TestPromptAssemblyToolsProposalsAndGuardrailPrecedence(t *testing.T) {
	var capturedMu sync.Mutex
	var capturedSystemPrompts []string
	var callNum atomic.Int32
	var srv1ID string
	var createdMemIDForDelete string
	var runbookIDForGet string

	store, svc, srv1, srv2, _ := setupMemoryTestEnv(t, func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Messages []struct {
				Role    string `json:"role"`
				Content any    `json:"content"`
			} `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&payload)
		if len(payload.Messages) > 0 && payload.Messages[0].Role == "system" {
			if s, ok := payload.Messages[0].Content.(string); ok {
				capturedMu.Lock()
				capturedSystemPrompts = append(capturedSystemPrompts, s)
				capturedMu.Unlock()
			}
		}

		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		n := callNum.Add(1)
		switch n {
		case 1:
			// Emit save_memory, search_memory, get_runbook, propose_agents_md_update
			saveArgs, _ := json.Marshal(map[string]any{
				"scope":      "server",
				"server_ids": []string{srv1ID},
				"category":   "lesson",
				"title":      "Nginx Keepalive 调优经验",
				"content":    "upstream keepalive 设为 64 后 502 显著下降，忽略临时 token sk-proj-99998888777766665555",
				"tags":       []string{"nginx", "tuning"},
				"importance": 4,
			})
			searchArgs, _ := json.Marshal(map[string]any{
				"query": "主库备库延迟",
			})
			rbArgs, _ := json.Marshal(map[string]any{
				"runbook_id": runbookIDForGet,
			})
			propArgs, _ := json.Marshal(map[string]any{
				"summary":         "补充网关变更前强制检查配置",
				"reason":          "防止错误语法直接 reload 导致中断",
				"updated_content": "# 生产 SRE 规范\n- 变更前必须执行 nginx -t\n- 变更窗口为周二/周四 02:00-05:00",
			})

			emitTool := func(idx int, id, name string, args []byte) {
				b, _ := json.Marshal(map[string]any{
					"choices": []map[string]any{{
						"delta": map[string]any{
							"tool_calls": []map[string]any{{
								"index": idx,
								"id":    id,
								"function": map[string]any{
									"name":      name,
									"arguments": string(args),
								},
							}},
						},
					}},
				})
				_, _ = fmt.Fprintf(w, "data: %s\n\n", string(b))
				flusher.Flush()
			}
			emitTool(0, "call_save", "save_memory", saveArgs)
			emitTool(1, "call_search", "search_memory", searchArgs)
			emitTool(2, "call_rb", "get_runbook", rbArgs)
			emitTool(3, "call_prop", "propose_agents_md_update", propArgs)
			_, _ = fmt.Fprintf(w, "data: [DONE]\n\n")
			flusher.Flush()
		default:
			// Verify tool results arrived in history and respond cleanly
			_, _ = fmt.Fprintf(w, "data: %s\n\n", `{"choices":[{"delta":{"content":"已完成记忆沉淀、跨机历史检索、Runbook 查询，并提交了 AGENTS.md 修订提案等待您的审批。"}}]}`)
			_, _ = fmt.Fprintf(w, "data: [DONE]\n\n")
			flusher.Flush()
		}
	})

	srv1ID = srv1.ID

	// Seed customized AGENTS.md, HostMemory 2.0, Long-Term Memories, Live Monitor + Alert, Runbook
	agentsBefore, err := store.UpdateAgentsMD(true, "# 生产 SRE 规范\n- 变更窗口为周二/周四 02:00-05:00", false, "127.0.0.1")
	if err != nil {
		t.Fatalf("UpdateAgentsMD: %v", err)
	}

	_, err = store.UpsertHostMemory(vault.HostMemory{
		ServerID:    srv1.ID,
		ServerName:  srv1.Name,
		Summary:     "公网入口 Nginx 网关节点",
		OSArch:      "Debian 12 / x86_64",
		KeyServices: []string{"nginx", "fail2ban"},
		DeployPaths: []string{"/etc/nginx/conf.d"},
		PortsNote:   "80/443 公网入口，8080 内网健康检查",
		Constraints: "绝对禁止在业务高峰直接 stop nginx",
		Notes:       "上游连接 app-worker-01 与 app-worker-02",
	}, false, "127.0.0.1")
	if err != nil {
		t.Fatalf("UpsertHostMemory: %v", err)
	}

	// Global pinned memory + srv1 memory + unrelated srv2 memory
	_, err = store.UpsertAIMemory(vault.AIMemoryEntry{
		Scope:      "global",
		Category:   "preference",
		Title:      "中文优先与回滚命令要求",
		Content:    "所有修复方案必须附带回滚命令，并优先使用无损 reload。",
		Pinned:     true,
		Importance: 5,
		Source:     "manual",
	}, false, "127.0.0.1")
	if err != nil {
		t.Fatalf("UpsertAIMemory global: %v", err)
	}

	srv2Mem, err := store.UpsertAIMemory(vault.AIMemoryEntry{
		Scope:      "server",
		ServerIDs:  []string{srv2.ID},
		Category:   "topology",
		Title:      "主库备库延迟告警基线",
		Content:    "db-postgres-01 备库流复制延迟超过 50MB 时需检查 WAL 归档磁盘。",
		Importance: 4,
		Source:     "manual",
	}, false, "127.0.0.1")
	if err != nil {
		t.Fatalf("UpsertAIMemory srv2: %v", err)
	}
	createdMemIDForDelete = srv2Mem.ID

	rb, err := store.UpsertRunbook(vault.AIRunbook{
		Title:           "Nginx 502 快速排障 SOP",
		Category:        "Web网关",
		Symptom:         "上游超时导致 502 Bad Gateway",
		RootCause:       "上游服务连接池满或进程 OOM",
		DiagnosticSteps: []string{"nginx -t", "tail -n 100 /var/log/nginx/error.log"},
		FixCommands:     []string{"systemctl reload nginx"},
		Verification:    "curl -I http://127.0.0.1/healthz",
	}, false, "127.0.0.1")
	if err != nil {
		t.Fatalf("UpsertRunbook: %v", err)
	}
	runbookIDForGet = rb.ID

	// Seed 2 consecutive high-CPU 7x24 monitor snapshots so built-in alert rule fires (ConsecutiveCount=2)
	snap1 := &vault.ServerMonitorSnapshot{
		ServerID:    srv1.ID,
		ServerName:  srv1.Name,
		CollectedAt: time.Now().UTC().Add(-10 * time.Second),
		Reachable:   true,
		HealthLevel: "warning",
		HealthScore: 72,
		CPUPercent:  96.5,
		Load1:       6.20,
		MemPercent:  68.1,
		MemUsedMB:   5500,
		MemTotalMB:  8192,
		DiskPercent: 95.5,
		LatencyMs:   18,
	}
	if _, _, _, err := store.RecordMonitorSnapshots([]*vault.ServerMonitorSnapshot{snap1}); err != nil {
		t.Fatalf("RecordMonitorSnapshots 1: %v", err)
	}
	snap2 := *snap1
	snap2.CollectedAt = time.Now().UTC()
	triggeredAlerts, _, _, err := store.RecordMonitorSnapshots([]*vault.ServerMonitorSnapshot{&snap2})
	if err != nil {
		t.Fatalf("RecordMonitorSnapshots 2: %v", err)
	}
	if len(triggeredAlerts) == 0 {
		t.Fatalf("expected built-in monitor alert to fire for sustained high CPU/Disk")
	}

	sess, err := store.CreateAISession("网关 502 排查", "center", []string{srv1.ID}, vault.AIModeStandard)
	if err != nil {
		t.Fatalf("CreateAISession: %v", err)
	}

	var gotSavedMem *vault.AIMemoryEntry
	var gotProposal *vault.AIAgentsMDProposal
	err = svc.RunChatStream(context.Background(), ChatRequest{
		SessionID: sess.ID,
		Message:   "帮我记录 Nginx 调优经验，查一下数据库备库延迟的记忆，看看 Nginx 502 Runbook，并提议更新 AGENTS.md",
		ServerIDs: []string{srv1.ID},
		Mode:      vault.AIModeStandard,
		ClientIP:  "127.0.0.1",
	}, func(ev StreamEvent) {
		switch ev.Type {
		case "memory_saved":
			gotSavedMem = ev.MemoryEntry
		case "agents_md_proposed":
			gotProposal = ev.AgentsMDProposal
		}
	})
	if err != nil {
		t.Fatalf("RunChatStream: %v", err)
	}

	// Verify system prompt structure & security precedence
	capturedMu.Lock()
	if len(capturedSystemPrompts) == 0 {
		capturedMu.Unlock()
		t.Fatalf("expected at least 1 captured system prompt")
	}
	sysPrompt := capturedSystemPrompts[0]
	capturedMu.Unlock()

	idxGuardrail := strings.Index(sysPrompt, "### 系统级不可覆盖安全护栏")
	idxAgents := strings.Index(sysPrompt, "### 全局运维规范宪章 (AGENTS.md")
	if idxGuardrail < 0 || idxAgents < 0 || idxGuardrail >= idxAgents {
		t.Fatalf("expected immutable security guardrails to appear BEFORE AGENTS.md (guardrail=%d agents=%d)", idxGuardrail, idxAgents)
	}
	for _, mustHave := range []string{
		"变更窗口为周二/周四 02:00-05:00",
		"绝对禁止在业务高峰直接 stop nginx",
		"80/443 公网入口",
		"上游连接 app-worker-01",
		"CPU 96.5%",
		"中文优先与回滚命令要求",
		"Nginx 502 快速排障 SOP",
	} {
		if !strings.Contains(sysPrompt, mustHave) {
			t.Fatalf("expected system prompt to contain %q", mustHave)
		}
	}
	// Unrelated server-scoped memory must NOT be auto-injected into prompt (recalled via search_memory instead)
	if strings.Contains(sysPrompt, "主库备库延迟告警基线") {
		t.Fatalf("unrelated server memory should not be injected directly into prompt")
	}
	// Secrets MUST NEVER appear in prompt
	for _, secret := range []string{"UltraSecretEdgePass#2026", "UltraSecretPgPass#2026", "sk-mock-secret-key-99887766"} {
		if strings.Contains(sysPrompt, secret) {
			t.Fatalf("SECURITY FAILURE: leaked secret %q into LLM system prompt!", secret)
		}
	}

	// Verify tool outcomes
	if gotSavedMem == nil || strings.Contains(gotSavedMem.Content, "sk-proj-99998888777766665555") {
		t.Fatalf("expected memory_saved event with redacted secret, got %+v", gotSavedMem)
	}
	if gotProposal == nil || gotProposal.Status != "pending" || !strings.Contains(gotProposal.DiffPreview, "+- 变更前必须执行 nginx -t") {
		t.Fatalf("expected pending agents_md_proposed event with Unified Diff, got %+v", gotProposal)
	}

	// CRITICAL INVARIANT: AI tool MUST NOT directly mutate global AGENTS.md before admin acceptance!
	agentsAfterTool, _ := store.GetAgentsMD()
	if agentsAfterTool.Revision != agentsBefore.Revision || agentsAfterTool.Content != agentsBefore.Content {
		t.Fatalf("SECURITY FAILURE: AI mutated global AGENTS.md directly without admin approval!")
	}

	// Verify Context Inspector API
	insp, err := svc.InspectSessionContext(sess.ID)
	if err != nil {
		t.Fatalf("InspectSessionContext: %v", err)
	}
	if !insp.AgentsMDEnabled || insp.AgentsMDRevision != agentsBefore.Revision || len(insp.LiveMonitors) != 1 || insp.FiringAlertsCount < 1 || insp.RunbookCount < 1 {
		t.Fatalf("unexpected context inspection: %+v", insp)
	}

	// Verify delete_memory & approved change memory recording
	svc.maybeRecordApprovedChangeMemory(sess, vault.AIPendingApproval{
		ToolName:    "exec_ssh_command",
		ServerIDs:   []string{srv1.ID},
		ServerNames: []string{srv1.Name},
		Command:     "systemctl reload nginx # password=ShouldRedact123",
		Reason:      "平滑重载网关配置",
	}, "127.0.0.1")

	allMems, _ := store.ListAIMemories()
	foundChange := false
	for _, m := range allMems {
		if m.Category == "change" && m.Source == "approval" {
			foundChange = true
			if strings.Contains(m.Content, "ShouldRedact123") {
				t.Fatalf("expected approved change memory to redact password, got %s", m.Content)
			}
		}
	}
	if !foundChange {
		t.Fatalf("expected HITL approval change memory to be automatically recorded")
	}

	// Test delete_memory via dispatchToolCall
	delOutcome := svc.dispatchToolCall(sess, LLMToolCall{
		ID:        "tc_del",
		Name:      "delete_memory",
		Arguments: fmt.Sprintf(`{"memory_id":%q,"reason":"已迁移"}`, createdMemIDForDelete),
	}, "127.0.0.1", nil)
	if delOutcome.isError || !strings.Contains(delOutcome.toolOutput, "已删除") {
		t.Fatalf("delete_memory failed: isErr=%v out=%s", delOutcome.isError, delOutcome.toolOutput)
	}
}

func TestNonDestructiveRollingCompactionLLMAndFallback(t *testing.T) {
	var failLLM atomic.Bool

	store, svc, srv1, _, _ := setupMemoryTestEnv(t, func(w http.ResponseWriter, r *http.Request) {
		if failLLM.Load() {
			http.Error(w, "upstream overloaded", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		_, _ = fmt.Fprintf(w, "data: %s\n\n", `{"choices":[{"delta":{"content":"### 核心排查目标\n排查 edge-nginx-01 延迟升高问题。\n### 已证实证据\n- 确认 nginx worker 正常，磁盘占用 51%。\n### 下一步\n检查上游应用响应时间。"}}]}`)
		_, _ = fmt.Fprintf(w, "data: [DONE]\n\n")
		flusher.Flush()
	})

	sess, err := store.CreateAISession("长会话压缩测试", "center", []string{srv1.ID}, vault.AIModeStandard)
	if err != nil {
		t.Fatalf("CreateAISession: %v", err)
	}

	now := time.Now().UTC()
	// Build realistic multi-turn session WITH assistant(tool_calls) <-> tool pairs!
	sess.Messages = []vault.AIChatMessage{
		{ID: "m1", Role: "user", Content: "请检查 edge-nginx-01 的磁盘与负载", Timestamp: now},
		{
			ID:      "m2",
			Role:    "assistant",
			Content: "我先检查磁盘与负载情况。",
			ToolCalls: []vault.AIToolCallRecord{{
				ID:        "tc_1",
				Name:      "exec_ssh_command",
				Arguments: `{"server_ids":["s1"],"command":"df -h && uptime"}`,
				Status:    "completed",
			}},
			Timestamp: now,
		},
		{ID: "m3", Role: "tool", ToolCallID: "tc_1", ToolName: "exec_ssh_command", Content: "/dev/vda1 51% used, load average: 1.2", Timestamp: now},
		{ID: "m4", Role: "assistant", Content: "磁盘占用 51%，负载 1.2 正常。", Timestamp: now},
		{ID: "m5", Role: "user", Content: "那看看 nginx 最近错误日志", Timestamp: now},
		{
			ID:      "m6",
			Role:    "assistant",
			Content: "正在查看错误日志。",
			ToolCalls: []vault.AIToolCallRecord{{
				ID:        "tc_2",
				Name:      "exec_ssh_command",
				Arguments: `{"server_ids":["s1"],"command":"tail -n 20 /var/log/nginx/error.log"}`,
				Status:    "completed",
			}},
			Timestamp: now,
		},
		{ID: "m7", Role: "tool", ToolCallID: "tc_2", ToolName: "exec_ssh_command", Content: "upstream timed out (110: Connection timed out)", Timestamp: now},
		{ID: "m8", Role: "assistant", Content: "发现上游超时错误。", Timestamp: now},
		{ID: "m9", Role: "user", Content: "帮我检查上游应用容器状态", Timestamp: now},
		{ID: "m10", Role: "assistant", Content: "好的，接下来检查容器状态。", Timestamp: now},
	}
	if err := store.SaveAISession(*sess); err != nil {
		t.Fatalf("SaveAISession: %v", err)
	}

	// 1. Manual compaction with LLM summary
	updatedSess, info, insp, err := svc.CompactSessionNow(context.Background(), sess.ID, false)
	if err != nil {
		t.Fatalf("CompactSessionNow LLM: %v", err)
	}
	if !info.Triggered || info.Mode != "llm" || updatedSess.CompactionCount != 1 {
		t.Fatalf("expected triggered LLM compaction, got info=%+v count=%d", info, updatedSess.CompactionCount)
	}
	// Non-destructive: ALL 10 raw messages MUST still be preserved in vault.sns!
	if len(updatedSess.Messages) != 10 {
		t.Fatalf("compaction must be non-destructive; expected 10 messages, got %d", len(updatedSess.Messages))
	}
	// Split boundary MUST be on a "user" message so tool_calls/tool pairs are NEVER orphaned!
	if updatedSess.Messages[updatedSess.CompactedUntilCount].Role != "user" {
		t.Fatalf("compaction split index %d landed on role %q instead of 'user'",
			updatedSess.CompactedUntilCount, updatedSess.Messages[updatedSess.CompactedUntilCount].Role)
	}
	if !strings.Contains(insp.CompactedSummary, "核心排查目标") {
		t.Fatalf("expected LLM summary in inspection, got %q", insp.CompactedSummary)
	}

	// Verify effective history sent to LLM starts with synthetic user->assistant pair and contains NO orphan tool messages
	eff := buildEffectiveHistoryForLLM(updatedSess, 40000)
	if len(eff) < 3 || eff[0].Role != "user" || eff[1].Role != "assistant" || eff[2].Role != "user" {
		t.Fatalf("unexpected effective history role sequence: %+v", eff)
	}

	// 2. Reset compaction, then test deterministic fallback when LLM returns HTTP 503
	_, resetInfo, _, err := svc.CompactSessionNow(context.Background(), sess.ID, true)
	if err != nil || resetInfo.Mode != "reset" {
		t.Fatalf("reset compaction failed: info=%+v err=%v", resetInfo, err)
	}

	failLLM.Store(true)
	fallbackSess, fbInfo, _, err := svc.CompactSessionNow(context.Background(), sess.ID, false)
	if err != nil {
		t.Fatalf("CompactSessionNow fallback: %v", err)
	}
	if !fbInfo.Triggered || fbInfo.Mode != "fallback" || !strings.Contains(fallbackSess.CompactedSummary, "本地确定性压缩") {
		t.Fatalf("expected deterministic fallback summary, got info=%+v summary=%q", fbInfo, fallbackSess.CompactedSummary)
	}
}

func TestPatrolLLMContextEnrichmentAndStrictJSON(t *testing.T) {
	var capturedPatrolPrompt string
	var srv1ID string

	store, svc, srv1, _, _ := setupMemoryTestEnv(t, func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&payload)
		for _, m := range payload.Messages {
			if m.Role == "user" {
				capturedPatrolPrompt = m.Content
			}
		}

		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		jsonReply := `{"summary":"edge-nginx-01 负载略高，结合避坑红线建议低峰期扩容。","root_cause":"早高峰潮汐流量导致上游连接池接近饱和","recommendations":["请在周二维护窗口调整 worker_connections","持续观察 15 分钟确认潮汐回落"]}`
		b, _ := json.Marshal(map[string]any{
			"choices": []map[string]any{{
				"delta": map[string]any{"content": jsonReply},
			}},
		})
		_, _ = fmt.Fprintf(w, "data: %s\n\n", string(b))
		_, _ = fmt.Fprintf(w, "data: [DONE]\n\n")
		flusher.Flush()
	})
	_ = srv1ID

	_, _ = store.UpdateAgentsMD(true, "# 巡检参考规范\n- 严禁自动重启核心网关", false, "127.0.0.1")
	_, _ = store.UpsertHostMemory(vault.HostMemory{
		ServerID:    srv1.ID,
		ServerName:  srv1.Name,
		Summary:     "公网入口网关",
		Constraints: "仅允许周二维护窗口变更",
	}, false, "127.0.0.1")
	_, _ = store.UpsertAIMemory(vault.AIMemoryEntry{
		Scope:      "server",
		ServerIDs:  []string{srv1.ID},
		Category:   "incident",
		Title:      "早高峰流量激增特征",
		Content:    "每日 09:30 会出现 15 分钟 CPU 峰值，属正常业务潮汐。",
		Importance: 4,
		Source:     "manual",
	}, false, "127.0.0.1")

	prov, err := store.GetActiveAIProviderSecret()
	if err != nil {
		t.Fatalf("GetActiveAIProviderSecret: %v", err)
	}

	rec := vault.PatrolRecord{
		ID:            "patrol-1",
		Status:        "warning",
		TotalServers:  1,
		WarningCount:  1,
		Findings: []vault.PatrolFinding{{
			ServerID:       srv1.ID,
			ServerName:     srv1.Name,
			Severity:       "warning",
			MetricsSummary: "CPU负载 85.0%",
			Anomalies:      []string{"CPU 归一化负载偏高"},
		}},
	}

	svc.enrichPatrolWithLLM(context.Background(), *prov, &rec)

	for _, expected := range []string{
		"严禁自动重启核心网关",
		"仅允许周二维护窗口变更",
		"早高峰流量激增特征",
	} {
		if !strings.Contains(capturedPatrolPrompt, expected) {
			t.Fatalf("expected patrol prompt to contain %q, got:\n%s", expected, capturedPatrolPrompt)
		}
	}
	if !rec.AIAnalyzed || !strings.Contains(rec.AISummary, "edge-nginx-01") || !strings.Contains(rec.AIRootCause, "潮汐流量") || len(rec.AIRecommendations) != 2 {
		t.Fatalf("expected strict JSON patrol enrichment parsed cleanly, got summary=%q root=%q recs=%+v", rec.AISummary, rec.AIRootCause, rec.AIRecommendations)
	}
}

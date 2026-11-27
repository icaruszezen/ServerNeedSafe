package aiops

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/icaruszezen/ServerNeedSafe/internal/sshmanager"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

func TestClassifierHardeningAndSFTPPaths(t *testing.T) {
	blockedCases := []string{
		"rm -fr /",
		"rm -r -f /",
		"rm -f -r /",
		"rm --recursive --force /",
		"/bin/rm -rf /",
		"/sbin/mkfs.ext4 /dev/sda",
		"/usr/sbin/shutdown -h now",
		"/sbin/reboot -f",
	}
	for _, cmd := range blockedCases {
		risk, reason := ClassifyCommand(cmd)
		if risk != RiskBlocked {
			t.Fatalf("expected RiskBlocked for %q, got %s (%s)", cmd, risk, reason)
		}
	}

	mutatingCases := []string{
		"cat <(id)",
		`echo "unclosed quote`,
		`echo 'unclosed quote`,
		"sed 's/a/b/e' /etc/hosts",
		"sed '1w /tmp/leaked' /etc/hosts",
		"sed -f /tmp/evil.sed /etc/hosts",
		"sed --file=/tmp/evil.sed /etc/hosts",
		"find /var -okdir id {} \\;",
		"find /var -fprintf /tmp/out '%p'",
		"find /var -fls /tmp/out",
		"tail -fn 20 /var/log/syslog",
		"docker logs --follow nginx",
		"docker logs -ft nginx",
		"journalctl --rotate",
		"journalctl -fu sshd",
		"journalctl --flush",
	}
	for _, cmd := range mutatingCases {
		risk, reason := ClassifyCommand(cmd)
		if risk != RiskMutating {
			t.Fatalf("expected RiskMutating for %q, got %s (%s)", cmd, risk, reason)
		}
	}

	readOnlyCases := []string{
		"sed 's/foo/bar/g' /etc/hosts",
		"sed -n '1,20p' /var/log/syslog",
		"tail -n 20 /var/log/syslog",
		"docker logs --tail 50 nginx",
		"journalctl -u sshd -n 20 --no-pager",
		`log show --predicate 'process == "sshd"' --last 1h`,
		`echo "escaped \"quote\" ok" | grep ok`,
	}
	for _, cmd := range readOnlyCases {
		risk, reason := ClassifyCommand(cmd)
		if risk != RiskReadOnly {
			t.Fatalf("expected RiskReadOnly for %q, got %s (%s)", cmd, risk, reason)
		}
	}

	blockedReads := []string{
		"/etc/shadow",
		"/etc//shadow",
		"/tmp/../etc/shadow",
		"/etc/gshadow",
		"/etc/master.passwd",
		"/home/ops/.ssh/id_ed25519",
		".ssh/id_rsa",
		`C:\Users\ops\.ssh\id_rsa`,
		"/opt/sns/secrets.enc",
		"/var/lib/sns/vault.sns",
		"/etc/sns/master.key",
		"/root/.vault.key",
	}
	for _, p := range blockedReads {
		if !IsBlockedReadPath(p) {
			t.Fatalf("expected IsBlockedReadPath(%q) = true", p)
		}
	}

	allowedReads := []string{
		"/etc/nginx/nginx.conf",
		"/home/ops/.ssh/known_hosts",
		"/home/ops/.ssh/authorized_keys",
		"/home/ops/.ssh/id_ed25519.pub",
		"/home/ops/.ssh/config",
	}
	for _, p := range allowedReads {
		if IsBlockedReadPath(p) {
			t.Fatalf("expected IsBlockedReadPath(%q) = false", p)
		}
	}

	blockedWrites := []string{
		"/etc/passwd",
		"/tmp/../etc/passwd",
		"/etc/sudoers",
		"/etc/sudoers.d/ops",
		"/etc/shadow",
		"/home/ops/.ssh/id_rsa",
		"/opt/sns/secrets.enc",
	}
	for _, p := range blockedWrites {
		if !IsBlockedWritePath(p) {
			t.Fatalf("expected IsBlockedWritePath(%q) = true", p)
		}
	}
	if IsBlockedWritePath("/etc/nginx/conf.d/app.conf") {
		t.Fatalf("expected normal nginx config write to be allowed")
	}
}

func TestUTF8SafeTruncationAndVaultRedaction(t *testing.T) {
	sample := "服务器告警：🔥磁盘空间不足-测试截断安全性🔥"
	for maxB := 0; maxB <= len(sample)+3; maxB++ {
		got := TruncateUTF8Bytes(sample, maxB)
		if !utf8.ValidString(got) {
			t.Fatalf("TruncateUTF8Bytes(%d) produced invalid UTF-8: %q", maxB, got)
		}
		if len(got) > maxB {
			t.Fatalf("TruncateUTF8Bytes(%d) exceeded byte cap: len=%d", maxB, len(got))
		}
		tr := truncateStr(sample, maxB)
		if !utf8.ValidString(tr) {
			t.Fatalf("truncateStr(%d) produced invalid UTF-8: %q", maxB, tr)
		}
	}

	store, err := vault.NewStore(filepath.Join(t.TempDir(), "vault.sns"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := store.Setup("StrongMasterPass!2026", "127.0.0.1"); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	// Oversized Chinese memory entry (> 8000 bytes) must stay valid UTF-8 after truncation.
	longCN := strings.Repeat("运维排查记录日志🔥", 500)
	mem, err := store.UpsertAIMemory(vault.AIMemoryEntry{
		Title:    "超长中文运维记忆",
		Category: "incident",
		Scope:    "global",
		Content:  longCN,
	}, false, "127.0.0.1")
	if err != nil {
		t.Fatalf("UpsertAIMemory: %v", err)
	}
	if !utf8.ValidString(mem.Content) || len(mem.Content) > 8000 {
		t.Fatalf("invalid UTF-8 or exceeded 8000 bytes: valid=%v len=%d", utf8.ValidString(mem.Content), len(mem.Content))
	}

	// Multi-byte secret/URL preview masking must remain valid UTF-8.
	pv, _, err := store.UpsertAIProvider(vault.AIProviderMutationInput{
		Name:     "UTF8 Key Provider",
		Protocol: vault.AIProtocolOpenAI,
		BaseURL:  "https://example.com/v1",
		APIKey:   strPtr("密钥前缀-测试超长多字节SecretKey-结尾密码"),
		Model:    "gpt-test",
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("UpsertAIProvider: %v", err)
	}
	if !utf8.ValidString(pv.APIKeyPreview) {
		t.Fatalf("APIKeyPreview is not valid UTF-8: %q", pv.APIKeyPreview)
	}
}

func TestAnthropicMessageCoalescingSSEErrorsAndUniqueToolIDs(t *testing.T) {
	t.Setenv("NO_PROXY", "127.0.0.1,localhost")

	// 1. Consecutive same-role messages & leading assistant must normalize to user-first alternating roles.
	rawMsgs := []vault.AIChatMessage{
		{Role: "assistant", Content: "orphan leading assistant"},
		{Role: "user", Content: "first user msg"},
		{Role: "user", Content: "second user msg after failed turn"},
		{Role: "assistant", Content: "part 1"},
		{Role: "assistant", ToolCalls: []vault.AIToolCallRecord{{ID: "toolu_1", Name: "list_servers", Arguments: "{}"}}},
		{Role: "tool", ToolCallID: "toolu_1", Content: "server list result"},
		{Role: "user", Content: "follow-up question"},
	}
	antMsgs := buildAnthropicMessages(rawMsgs)
	if len(antMsgs) < 3 {
		t.Fatalf("expected coalesced messages, got %d: %+v", len(antMsgs), antMsgs)
	}
	if antMsgs[0]["role"] != "user" {
		t.Fatalf("expected first Anthropic message role=user, got %v", antMsgs[0]["role"])
	}
	for i := 1; i < len(antMsgs); i++ {
		if antMsgs[i]["role"] == antMsgs[i-1]["role"] {
			t.Fatalf("consecutive identical Anthropic roles at index %d: %+v", i, antMsgs)
		}
	}

	// 2. In-stream SSE error events (OpenAI + Anthropic) and unique fallback tool call IDs.
	var toolCallSeq atomic.Int32
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		switch r.URL.Path {
		case "/openai-err/v1/chat/completions":
			_, _ = fmt.Fprint(w, "data: {\"error\":{\"message\":\"upstream rate limit reached\"}}\n\n")
			flusher.Flush()
		case "/anthropic-err/v1/messages":
			_, _ = fmt.Fprint(w, "data: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"service temporarily overloaded\"}}\n\n")
			flusher.Flush()
		case "/openai-noid/v1/chat/completions":
			_ = toolCallSeq.Add(1)
			_, _ = fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"name\":\"list_servers\",\"arguments\":\"{}\"}}]}}]}\n\n")
			_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
			flusher.Flush()
		default:
			http.NotFound(w, r)
		}
	}))
	defer mockServer.Close()

	client := NewLLMClient()
	_, err := client.StreamChat(context.Background(), vault.AIProviderConfig{
		Protocol: vault.AIProtocolOpenAI,
		BaseURL:  mockServer.URL + "/openai-err",
		APIKey:   "sk-test",
		Model:    "test-model",
	}, "sys", []vault.AIChatMessage{{Role: "user", Content: "hi"}}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "rate limit") {
		t.Fatalf("expected OpenAI SSE error to surface, got err=%v", err)
	}

	_, err = client.StreamChat(context.Background(), vault.AIProviderConfig{
		Protocol: vault.AIProtocolAnthropic,
		BaseURL:  mockServer.URL + "/anthropic-err",
		APIKey:   "sk-ant-test",
		Model:    "claude-test",
	}, "sys", []vault.AIChatMessage{{Role: "user", Content: "hi"}}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "overloaded") {
		t.Fatalf("expected Anthropic SSE error to surface, got err=%v", err)
	}

	turn1, err := client.StreamChat(context.Background(), vault.AIProviderConfig{
		Protocol: vault.AIProtocolOpenAI,
		BaseURL:  mockServer.URL + "/openai-noid",
		APIKey:   "sk-test",
		Model:    "test-model",
	}, "sys", []vault.AIChatMessage{{Role: "user", Content: "1"}}, nil, nil)
	if err != nil || len(turn1.ToolCalls) != 1 {
		t.Fatalf("turn1 failed: turn=%+v err=%v", turn1, err)
	}
	turn2, err := client.StreamChat(context.Background(), vault.AIProviderConfig{
		Protocol: vault.AIProtocolOpenAI,
		BaseURL:  mockServer.URL + "/openai-noid",
		APIKey:   "sk-test",
		Model:    "test-model",
	}, "sys", []vault.AIChatMessage{{Role: "user", Content: "2"}}, nil, nil)
	if err != nil || len(turn2.ToolCalls) != 1 {
		t.Fatalf("turn2 failed: turn=%+v err=%v", turn2, err)
	}
	if turn1.ToolCalls[0].ID == "" || turn1.ToolCalls[0].ID == turn2.ToolCalls[0].ID {
		t.Fatalf("expected unique fallback tool call IDs across turns, got %q and %q", turn1.ToolCalls[0].ID, turn2.ToolCalls[0].ID)
	}
}

func TestPatrolBaselinePreservedOnNewPortsAndFallbackRace(t *testing.T) {
	t.Setenv("NO_PROXY", "127.0.0.1,localhost")

	store, err := vault.NewStore(filepath.Join(t.TempDir(), "vault.sns"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := store.Setup("StrongMasterPass!2026", "127.0.0.1"); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	srv, err := store.CreateServer(vault.ServerMutationInput{
		Name:     "patrol-node-01",
		Host:     "10.0.0.10",
		Port:     22,
		Username: "root",
		AuthType: vault.AuthPassword,
		Password: strPtr("Pass123!"),
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("CreateServer: %v", err)
	}

	sshMgr := sshmanager.NewManager(store)
	svc := NewService(store, sshMgr)
	defer svc.Close()

	// 1. Existing port baseline [22, 80] must NOT be overwritten when unexpected port 4444 appears.
	if err := store.SavePatrolBaseline(vault.ServerBaselineSnapshot{
		ServerID:       srv.ID,
		ListeningPorts: []string{"22", "80"},
		UIDZeroUsers:   []string{"root"},
	}); err != nil {
		t.Fatalf("SavePatrolBaseline: %v", err)
	}
	cfg := &vault.PatrolConfig{
		CPUWarnPercent:       85,
		MemWarnPercent:       85,
		DiskWarnPercent:      85,
		SSHFailWarnCount:     15,
		CheckListeningPorts:  true,
		CheckPrivilegedUsers: true,
	}
	rawOut := "METRIC_CORES=4\nMETRIC_LOAD1=0.4\nMETRIC_MEM=30.0\nMETRIC_DISK=40\nMETRIC_SSH_FAILS=0\nMETRIC_UID0=root\nMETRIC_PORTS=22,80,4444\nMETRIC_FAILED_UNITS=\n"
	finding := svc.evaluateServerPatrol(*srv, cfg, rawOut, true, 12, "")
	if finding.Severity != "warning" || len(finding.NewPorts) != 1 || finding.NewPorts[0] != "4444" {
		t.Fatalf("expected unexpected port 4444 warning, got %+v", finding)
	}
	baselineAfter, err := store.GetPatrolBaseline(srv.ID)
	if err != nil || baselineAfter == nil {
		t.Fatalf("GetPatrolBaseline failed: %v", err)
	}
	for _, p := range baselineAfter.ListeningPorts {
		if p == "4444" {
			t.Fatalf("suspicious port 4444 was silently absorbed into baseline: %+v", baselineAfter.ListeningPorts)
		}
	}

	// 2. Empty LLM output must NOT set AIAnalyzed=true.
	emptyLLM := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"   "}}]}`))
	}))
	defer emptyLLM.Close()

	recEmpty := vault.PatrolRecord{
		ID:       "patrol-empty-llm",
		Status:   "warning",
		Findings: []vault.PatrolFinding{finding},
	}
	svc.enrichPatrolWithLLM(context.Background(), vault.AIProviderConfig{
		Protocol: vault.AIProtocolOpenAI,
		BaseURL:  emptyLLM.URL + "/v1",
		APIKey:   "sk-test",
		Model:    "empty-model",
	}, &recEmpty)
	if recEmpty.AIAnalyzed {
		t.Fatalf("expected AIAnalyzed=false when LLM returns empty content")
	}

	// 3. Fallback race: if external MCP submits report while fallback LLM is in flight,
	//    fallback must NOT overwrite the external report and must NOT send a duplicate webhook.
	var webhookHits atomic.Int32
	mockWH := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		webhookHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer mockWH.Close()

	if _, err := store.UpdatePatrolConfig(vault.PatrolConfigMutationInput{
		Enabled:                 false,
		IntervalMinutes:         30,
		AnalysisMode:            "external_with_fallback",
		ExternalFallbackMinutes: 10,
		Webhooks: []vault.WebhookMutationInput{{
			Name:    "race-wh",
			Kind:    "custom",
			URL:     strPtr(mockWH.URL),
			Enabled: true,
		}},
	}, "127.0.0.1"); err != nil {
		t.Fatalf("UpdatePatrolConfig: %v", err)
	}

	raceRecID := "patrol-race-001"
	racingLLM := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate external MCP client winning the race right before fallback LLM returns!
		_, _ = store.UpdatePatrolRecordAnalysis(raceRecID, vault.PatrolAnalysisUpdate{
			AnalysisState:  "completed",
			AISource:       "external_mcp",
			ExternalClient: "Claude Code",
			AISummary:      "外部 AI 已抢先完成深度研判",
		}, "127.0.0.1")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"summary\":\"内置兜底迟到结果\"}"}}]}`))
	}))
	defer racingLLM.Close()

	if _, _, err := store.UpsertAIProvider(vault.AIProviderMutationInput{
		Name:      "RacingFallbackLLM",
		Protocol:  vault.AIProtocolOpenAI,
		BaseURL:   racingLLM.URL + "/v1",
		APIKey:    strPtr("sk-race"),
		Model:     "gpt-race",
		SetActive: true,
	}, "127.0.0.1"); err != nil {
		t.Fatalf("UpsertAIProvider: %v", err)
	}

	past := time.Now().UTC().Add(-2 * time.Minute)
	if err := store.AppendPatrolRecord(vault.PatrolRecord{
		ID:                 raceRecID,
		StartedAt:          past.Add(-15 * time.Minute),
		CompletedAt:        past.Add(-14 * time.Minute),
		Trigger:            "scheduled",
		TotalServers:       1,
		WarningCount:       1,
		Status:             "warning",
		AnalysisState:      "pending_external",
		ExternalDeadlineAt: &past,
		Findings:           []vault.PatrolFinding{finding},
	}); err != nil {
		t.Fatalf("AppendPatrolRecord: %v", err)
	}

	processed := svc.ProcessExpiredExternalPatrolFallbacks(context.Background())
	if processed != 0 {
		t.Fatalf("expected 0 processed when external AI won race, got %d", processed)
	}
	gotRec, err := store.GetPatrolRecord(raceRecID)
	if err != nil {
		t.Fatalf("GetPatrolRecord: %v", err)
	}
	if gotRec.AISource != "external_mcp" || !strings.Contains(gotRec.AISummary, "外部 AI 已抢先完成") {
		t.Fatalf("fallback overwrote external MCP analysis! got %+v", gotRec)
	}
	if webhookHits.Load() != 0 {
		t.Fatalf("expected 0 fallback webhook calls when race lost, got %d", webhookHits.Load())
	}
}

func TestSessionStaleApprovalConcurrentProposalsAndVaultHardening(t *testing.T) {
	t.Setenv("NO_PROXY", "127.0.0.1,localhost")

	var llmCalls atomic.Int32
	mockLLM := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := llmCalls.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		if n == 1 {
			var reqPayload map[string]any
			_ = json.NewDecoder(r.Body).Decode(&reqPayload)
			srvID := extractServerIDFromSystemPrompt(reqPayload)
			line := fmt.Sprintf(`{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_stale_1","function":{"name":"exec_ssh_command","arguments":"{\"server_ids\":[\"%s\"],\"command\":\"systemctl reload nginx\",\"purpose\":\"test stale approval\"}"}}]}}]}`, srvID)
			_, _ = fmt.Fprintf(w, "data: %s\n\ndata: [DONE]\n\n", line)
			flusher.Flush()
			return
		}
		_, _ = fmt.Fprintf(w, "data: %s\n\ndata: [DONE]\n\n", `{"choices":[{"delta":{"content":"已开始新的排查对话。"}}]}`)
		flusher.Flush()
	}))
	defer mockLLM.Close()

	store, err := vault.NewStore(filepath.Join(t.TempDir(), "vault.sns"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := store.Setup("StrongMasterPass!2026", "127.0.0.1"); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	srv, err := store.CreateServer(vault.ServerMutationInput{
		Name:     "node-stale-01",
		Host:     "10.0.0.99",
		Port:     22,
		Username: "root",
		AuthType: vault.AuthPassword,
		Password: strPtr("Pass123!"),
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("CreateServer: %v", err)
	}
	if _, _, err := store.UpsertAIProvider(vault.AIProviderMutationInput{
		Name:      "MockOpenAI",
		Protocol:  vault.AIProtocolOpenAI,
		BaseURL:   mockLLM.URL + "/v1",
		APIKey:    strPtr("sk-stale"),
		Model:     "gpt-test",
		SetActive: true,
	}, "127.0.0.1"); err != nil {
		t.Fatalf("UpsertAIProvider: %v", err)
	}

	sshMgr := sshmanager.NewManager(store)
	svc := NewService(store, sshMgr)
	defer svc.Close()

	// 1. Stale pending approval auto-rejection must also update assistant ToolCalls[].Status -> "rejected".
	sess, err := store.CreateAISession("stale-test", "center", []string{srv.ID}, vault.AIModeStandard)
	if err != nil {
		t.Fatalf("CreateAISession: %v", err)
	}
	if err := svc.RunChatStream(context.Background(), ChatRequest{
		SessionID: sess.ID,
		Message:   "重启 nginx",
		ServerIDs: []string{srv.ID},
		Mode:      vault.AIModeStandard,
		ClientIP:  "127.0.0.1",
	}, nil); err != nil {
		t.Fatalf("first RunChatStream: %v", err)
	}

	// Send a second user message without approving/rejecting the pending approval
	if err := svc.RunChatStream(context.Background(), ChatRequest{
		SessionID: sess.ID,
		Message:   "先跳过刚才的变更，帮我查另一个问题",
		ServerIDs: []string{srv.ID},
		Mode:      vault.AIModeStandard,
		ClientIP:  "127.0.0.1",
	}, nil); err != nil {
		t.Fatalf("second RunChatStream: %v", err)
	}

	updatedSess, err := store.GetAISession(sess.ID)
	if err != nil {
		t.Fatalf("GetAISession: %v", err)
	}
	foundUpdatedTool := false
	for _, m := range updatedSess.Messages {
		for _, tc := range m.ToolCalls {
			if tc.ID == "call_stale_1" {
				foundUpdatedTool = true
				if tc.Status != "rejected" {
					t.Fatalf("expected stale pending tool call status='rejected', got %q", tc.Status)
				}
			}
		}
	}
	if !foundUpdatedTool {
		t.Fatalf("expected to find call_stale_1 in session messages")
	}

	// 2. Concurrent ResolveRunbookProposal must accept only once (no duplicate Runbooks/Snippets).
	updatedSess.RunbookProposals = append(updatedSess.RunbookProposals, vault.AIRunbookProposal{
		ID:          "rb-prop-race",
		Title:       "并发去重测试 SOP",
		Category:    "Web",
		FixCommands: []string{"nginx -t"},
		Status:      "pending",
		CreatedAt:   time.Now().UTC(),
	})
	updatedSess.AgentsMDProposals = append(updatedSess.AgentsMDProposals, vault.AIAgentsMDProposal{
		ID:              "ag-prop-race",
		Summary:         "并发修订测试",
		ProposedContent: "# Updated AGENTS\n- Rule 1\n",
		Status:          "pending",
		CreatedAt:       time.Now().UTC(),
	})
	if err := store.SaveAISession(*updatedSess); err != nil {
		t.Fatalf("SaveAISession: %v", err)
	}

	rbsBefore, _ := store.ListRunbooks()
	snipsBefore, _ := store.ListSnippets()
	var rbOK atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := store.ResolveRunbookProposal("rb-prop-race", true, true, "127.0.0.1"); err == nil {
				rbOK.Add(1)
			}
		}()
	}
	wg.Wait()
	if rbOK.Load() != 1 {
		t.Fatalf("expected exactly 1 concurrent ResolveRunbookProposal to succeed, got %d", rbOK.Load())
	}
	rbs, _ := store.ListRunbooks()
	if len(rbs) != len(rbsBefore)+1 {
		t.Fatalf("expected exactly 1 new Runbook created (before=%d), got %d", len(rbsBefore), len(rbs))
	}
	snips, _ := store.ListSnippets()
	if len(snips) != len(snipsBefore)+1 {
		t.Fatalf("expected exactly 1 new Snippet synced (before=%d), got %d", len(snipsBefore), len(snips))
	}

	// 3. Concurrent ResolveAgentsMDProposal must accept only once (Revision increments by 1).
	agBefore, _ := store.GetAgentsMD()
	var agOK atomic.Int32
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := store.ResolveAgentsMDProposal("ag-prop-race", true, "127.0.0.1"); err == nil {
				agOK.Add(1)
			}
		}()
	}
	wg.Wait()
	if agOK.Load() != 1 {
		t.Fatalf("expected exactly 1 concurrent ResolveAgentsMDProposal to succeed, got %d", agOK.Load())
	}
	agAfter, _ := store.GetAgentsMD()
	if agAfter.Revision != agBefore.Revision+1 {
		t.Fatalf("expected AGENTS.md Revision=%d, got %d", agBefore.Revision+1, agAfter.Revision)
	}

	// 4. UpdatePatrolConfig must reject repointing webhook URL/Kind without re-supplying Secret.
	savedWHCfg, err := store.UpdatePatrolConfig(vault.PatrolConfigMutationInput{
		Enabled:         false,
		IntervalMinutes: 30,
		Webhooks: []vault.WebhookMutationInput{{
			Name:    "Signed Hook",
			Kind:    "custom",
			URL:     strPtr("https://hooks.example.com/a"),
			Secret:  strPtr("whsec_keep_safe_123"),
			Enabled: true,
		}},
	}, "127.0.0.1")
	if err != nil || len(savedWHCfg.Webhooks) != 1 {
		t.Fatalf("initial UpdatePatrolConfig: %v", err)
	}
	whID := savedWHCfg.Webhooks[0].ID
	if _, err := store.UpdatePatrolConfig(vault.PatrolConfigMutationInput{
		Enabled:         false,
		IntervalMinutes: 30,
		Webhooks: []vault.WebhookMutationInput{{
			ID:      whID,
			Name:    "Signed Hook Repointed",
			Kind:    "custom",
			URL:     strPtr("https://evil.attacker.example/steal"),
			Enabled: true,
		}},
	}, "127.0.0.1"); err == nil {
		t.Fatalf("expected UpdatePatrolConfig to reject URL change without re-supplying Secret")
	}

	// 5. DeleteServer cleans up HostMemory and PatrolBaseline without escalating MCP token allowlist.
	if _, err := store.UpsertHostMemory(vault.HostMemory{
		ServerID: srv.ID,
		Summary:  "to be cleaned",
	}, false, "127.0.0.1"); err != nil {
		t.Fatalf("UpsertHostMemory: %v", err)
	}
	if err := store.SavePatrolBaseline(vault.ServerBaselineSnapshot{
		ServerID:       srv.ID,
		ListeningPorts: []string{"22"},
	}); err != nil {
		t.Fatalf("SavePatrolBaseline: %v", err)
	}
	mcpTok, _, err := store.CreateMCPToken(vault.CreateMCPTokenInput{
		Name:           "Scoped Token",
		Scope:          vault.MCPScopePatrolReadOnly,
		AllowedServers: []string{srv.ID},
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("CreateMCPToken: %v", err)
	}
	if err := store.DeleteServer(srv.ID, "127.0.0.1"); err != nil {
		t.Fatalf("DeleteServer: %v", err)
	}
	hms, _ := store.ListHostMemories()
	for _, hm := range hms {
		if hm.ServerID == srv.ID {
			t.Fatalf("expected HostMemory to be deleted when server is deleted, got %+v", hm)
		}
	}
	if bl, _ := store.GetPatrolBaseline(srv.ID); bl != nil {
		t.Fatalf("expected PatrolBaseline to be deleted when server is deleted, got %+v", bl)
	}
	mcpView, err := store.GetMCPConfigView()
	if err != nil {
		t.Fatalf("GetMCPConfigView: %v", err)
	}
	for _, tk := range mcpView.Tokens {
		if tk.ID == mcpTok.ID && len(tk.AllowedServers) == 0 {
			t.Fatalf("SECURITY FAILURE: deleting server emptied MCP token AllowedServers (privilege escalation to all servers)!")
		}
	}
}

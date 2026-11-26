package aiops

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/icaruszezen/ServerNeedSafe/internal/sshmanager"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

func strPtr(s string) *string { return &s }

func TestCommandRiskClassifierAndUnifiedDiff(t *testing.T) {
	readOnlyCases := []string{
		"df -h",
		"free -m && uptime",
		"ps aux | head -n 15",
		"journalctl -u nginx -n 50 --no-pager",
		"systemctl status sshd --no-pager",
		"ss -tulnp | grep 80",
	}
	for _, cmd := range readOnlyCases {
		risk, reason := ClassifyCommand(cmd)
		if risk != RiskReadOnly {
			t.Fatalf("expected RiskReadOnly for %q, got %s (%s)", cmd, risk, reason)
		}
	}

	mutatingCases := []string{
		"systemctl restart nginx",
		"kill -9 4182",
		"sed -i 's/worker_processes 1/worker_processes auto/' /etc/nginx/nginx.conf",
		"echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf",
		"apt-get install -y htop",
		"ufw allow 443/tcp",
	}
	for _, cmd := range mutatingCases {
		risk, _ := ClassifyCommand(cmd)
		if risk != RiskMutating {
			t.Fatalf("expected RiskMutating for %q, got %s", cmd, risk)
		}
	}

	blockedCases := []string{
		"rm -rf /",
		"rm -rf --no-preserve-root /",
		"mkfs.ext4 /dev/vda1",
		"dd if=/dev/zero of=/dev/sda bs=1M",
		"shutdown -h now",
		":(){ :|:& };:",
	}
	for _, cmd := range blockedCases {
		risk, _ := ClassifyCommand(cmd)
		if risk != RiskBlocked {
			t.Fatalf("expected RiskBlocked for catastrophic command %q, got %s", cmd, risk)
		}
	}

	diff := BuildUnifiedDiff("/etc/ssh/sshd_config", "Port 22\nPermitRootLogin yes\nPasswordAuthentication yes\n", "Port 22\nPermitRootLogin prohibit-password\nPasswordAuthentication no\n")
	if !strings.Contains(diff, "--- a/etc/ssh/sshd_config") ||
		!strings.Contains(diff, "-PermitRootLogin yes") ||
		!strings.Contains(diff, "+PermitRootLogin prohibit-password") {
		t.Fatalf("unexpected unified diff output:\n%s", diff)
	}
}

func TestOpenAIAndAnthropicStreamingHITLMemoryAndZeroKnowledgeDisk(t *testing.T) {
	t.Setenv("NO_PROXY", "127.0.0.1,localhost")

	var openAICallNum atomic.Int32
	mockLLM := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/chat/completions":
			n := openAICallNum.Add(1)
			w.Header().Set("Content-Type", "text/event-stream")
			flusher := w.(http.Flusher)
			if n == 1 {
				// First call: emit text + 3 tool calls: update_host_memory, propose_runbook, and mutating exec_ssh_command
				chunks := []string{
					`{"choices":[{"delta":{"content":"正在归档主机环境画像并准备重启 Nginx 服务…"}}]}`,
					`{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_mem_1","function":{"name":"update_host_memory","arguments":"{\"server_id\":\"SRV_ID\",\"summary\":\"Nginx 边缘网关节点\",\"os_arch\":\"Debian 12 amd64\",\"key_services\":[\"nginx\",\"fail2ban\"],\"deploy_paths\":[\"/etc/nginx\"]}"}}]}}]}`,
					`{"choices":[{"delta":{"tool_calls":[{"index":1,"id":"call_rb_1","function":{"name":"propose_runbook","arguments":"{\"title\":\"Nginx 502 快速恢复 SOP\",\"category\":\"Web网关\",\"symptom\":\"上游连接超时返回 502\",\"root_cause\":\"worker 连接池耗尽\",\"diagnostic_steps\":[\"nginx -t\",\"ss -s\"],\"fix_commands\":[\"systemctl reload nginx\"],\"verification\":\"curl -I http://127.0.0.1\"}"}}]}}]}`,
					`{"choices":[{"delta":{"tool_calls":[{"index":2,"id":"call_mut_1","function":{"name":"exec_ssh_command","arguments":"{\"server_ids\":[\"SRV_ID\"],\"command\":\"systemctl restart nginx\",\"purpose\":\"重启边缘网关恢复连接池\"}"}}]}}]}`,
				}
				// Replace SRV_ID placeholder dynamically from request body if present
				var reqPayload map[string]any
				_ = json.NewDecoder(r.Body).Decode(&reqPayload)
				srvID := extractServerIDFromSystemPrompt(reqPayload)
				for _, c := range chunks {
					line := strings.ReplaceAll(c, "SRV_ID", srvID)
					_, _ = fmt.Fprintf(w, "data: %s\n\n", line)
					flusher.Flush()
				}
				_, _ = fmt.Fprintf(w, "data: [DONE]\n\n")
				flusher.Flush()
				return
			}
			// Second call after admin rejects mutating command -> AI gives safe manual advice
			_, _ = fmt.Fprintf(w, "data: %s\n\n", `{"choices":[{"delta":{"content":"收到，已取消自动重启操作，建议在业务低峰期手动执行 nginx -s reload。"}}]}`)
			_, _ = fmt.Fprintf(w, "data: [DONE]\n\n")
			flusher.Flush()

		case "/v1/messages":
			// Native Anthropic Messages SSE protocol
			if r.Header.Get("x-api-key") != "sk-ant-secret-key-8899" {
				http.Error(w, "missing x-api-key", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			flusher := w.(http.Flusher)
			events := []string{
				`{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
				`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"连接正常"}}`,
				`{"type":"message_stop"}`,
			}
			for _, ev := range events {
				_, _ = fmt.Fprintf(w, "data: %s\n\n", ev)
				flusher.Flush()
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer mockLLM.Close()

	var webhookReceived atomic.Int32
	mockWebhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.Header.Get("X-SNS-Signature"), "sha256=") {
			webhookReceived.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer mockWebhook.Close()

	vaultFile := filepath.Join(t.TempDir(), "vault.sns")
	store, err := vault.NewStore(vaultFile)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := store.Setup("StrongMasterPass!2026", "127.0.0.1"); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	srv, err := store.CreateServer(vault.ServerMutationInput{
		Name:     "edge-nginx-01",
		Group:    "生产环境",
		Host:     "10.88.1.10",
		Port:     22,
		Username: "root",
		AuthType: vault.AuthPassword,
		Password: strPtr("UltraSecretSSHPassword#2026"),
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("CreateServer: %v", err)
	}

	// Add OpenAI-compatible provider & Anthropic provider
	_, _, err = store.UpsertAIProvider(vault.AIProviderMutationInput{
		Name:      "DeepSeek Test",
		Protocol:  vault.AIProtocolOpenAI,
		BaseURL:   mockLLM.URL + "/v1",
		APIKey:    strPtr("sk-secret-deepseek-998877"),
		Model:     "deepseek-chat",
		SetActive: true,
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("UpsertAIProvider openai: %v", err)
	}

	antView, _, err := store.UpsertAIProvider(vault.AIProviderMutationInput{
		Name:      "Claude Native",
		Protocol:  vault.AIProtocolAnthropic,
		BaseURL:   mockLLM.URL,
		APIKey:    strPtr("sk-ant-secret-key-8899"),
		Model:     "claude-sonnet-4-5",
		SetActive: false,
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("UpsertAIProvider anthropic: %v", err)
	}

	_, err = store.UpdatePatrolConfig(vault.PatrolConfigMutationInput{
		Enabled:         true,
		IntervalMinutes: 30,
		ServerIDs:       []string{srv.ID},
		Webhooks: []vault.WebhookMutationInput{
			{
				Name:    "SecOps Webhook",
				Kind:    "custom",
				URL:     strPtr(mockWebhook.URL),
				Secret:  strPtr("whsec_super_secret_7766"),
				Enabled: true,
			},
		},
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("UpdatePatrolConfig: %v", err)
	}

	sshMgr := sshmanager.NewManager(store)
	svc := NewService(store, sshMgr)
	defer svc.Close()

	// Test Anthropic native protocol ping
	antSecret, err := store.GetAIProviderSecret(antView.ID)
	if err != nil {
		t.Fatalf("GetAIProviderSecret: %v", err)
	}
	_, reply, err := svc.LLM().TestConnection(context.Background(), *antSecret)
	if err != nil || !strings.Contains(reply, "连接正常") {
		t.Fatalf("Anthropic TestConnection failed: reply=%q err=%v", reply, err)
	}

	// Create AI Ops session in Standard HITL mode
	sess, err := store.CreateAISession("排查网关 502", "center", []string{srv.ID}, vault.AIModeStandard)
	if err != nil {
		t.Fatalf("CreateAISession: %v", err)
	}

	var gotApproval *vault.AIPendingApproval
	var gotMemory *vault.HostMemory
	var gotProposal *vault.AIRunbookProposal
	err = svc.RunChatStream(context.Background(), ChatRequest{
		SessionID: sess.ID,
		Message:   "请帮我排查 edge-nginx-01 的 502 问题并重启修复",
		ServerIDs: []string{srv.ID},
		Mode:      vault.AIModeStandard,
		ClientIP:  "127.0.0.1",
	}, func(ev StreamEvent) {
		switch ev.Type {
		case "approval_required":
			gotApproval = ev.Approval
		case "memory_updated":
			gotMemory = ev.Memory
		case "runbook_proposed":
			gotProposal = ev.Proposal
		}
	})
	if err != nil {
		t.Fatalf("RunChatStream: %v", err)
	}

	if gotMemory == nil || gotMemory.Summary != "Nginx 边缘网关节点" {
		t.Fatalf("expected HostMemory auto-update, got %+v", gotMemory)
	}
	if gotProposal == nil || gotProposal.Title != "Nginx 502 快速恢复 SOP" {
		t.Fatalf("expected Runbook proposal, got %+v", gotProposal)
	}
	if gotApproval == nil || gotApproval.Status != "pending" || gotApproval.Command != "systemctl restart nginx" {
		t.Fatalf("expected HITL pending approval for systemctl restart nginx, got %+v", gotApproval)
	}

	// Accept Runbook proposal and sync to Snippets
	savedRB, err := store.ResolveRunbookProposal(gotProposal.ID, true, true, "127.0.0.1")
	if err != nil || savedRB == nil || savedRB.LinkedSnippetID == "" {
		t.Fatalf("ResolveRunbookProposal failed: rb=%+v err=%v", savedRB, err)
	}

	// Reject the mutating command -> AI resumes loop and gives safe manual advice
	var postRejectText strings.Builder
	err = svc.ResolveApprovalStream(context.Background(), sess.ID, gotApproval.ID, false, "127.0.0.1", func(ev StreamEvent) {
		if ev.Type == "delta" {
			postRejectText.WriteString(ev.Delta)
		}
	})
	if err != nil {
		t.Fatalf("ResolveApprovalStream: %v", err)
	}
	if !strings.Contains(postRejectText.String(), "nginx -s reload") {
		t.Fatalf("expected follow-up advice after rejection, got %q", postRejectText.String())
	}

	// Test custom signed Webhook delivery
	wch, _ := store.GetPatrolConfigSecret()
	if err := SendPatrolAlertWebhook(context.Background(), nil, wch.Webhooks[0], vault.PatrolRecord{
		Status:        "warning",
		TotalServers:  1,
		WarningCount:  1,
		AISummary:     "测试告警摘要",
		Findings:      []vault.PatrolFinding{{ServerName: "edge-nginx-01", Host: "10.88.1.10", Anomalies: []string{"SSH 爆破激增"}}},
	}); err != nil || webhookReceived.Load() != 1 {
		t.Fatalf("SendPatrolAlertWebhook failed: err=%v count=%d", err, webhookReceived.Load())
	}

	// Verify ZERO plaintext leakage of AI API keys, Webhook secrets, and SSH passwords inside secrets.enc and aiops_runtime.json!
	if err := store.FlushNow(); err != nil {
		t.Fatalf("FlushNow: %v", err)
	}
	rawDisk, err := os.ReadFile(store.SecretsPath())
	if err != nil {
		t.Fatalf("ReadFile secrets.enc: %v", err)
	}
	for _, secret := range []string{
		"sk-secret-deepseek-998877",
		"sk-ant-secret-key-8899",
		"whsec_super_secret_7766",
		"UltraSecretSSHPassword#2026",
	} {
		if bytes.Contains(rawDisk, []byte(secret)) {
			t.Fatalf("SECURITY FAILURE: leaked plaintext %q inside encrypted secrets.enc!", secret)
		}
	}
	rawRT, err := os.ReadFile(filepath.Join(store.DataDir(), "aiops_runtime.json"))
	if err != nil || len(rawRT) == 0 {
		t.Fatalf("ReadFile aiops_runtime.json: %v", err)
	}
	for _, secret := range []string{
		"sk-secret-deepseek-998877",
		"sk-ant-secret-key-8899",
		"whsec_super_secret_7766",
		"UltraSecretSSHPassword#2026",
	} {
		if bytes.Contains(rawRT, []byte(secret)) {
			t.Fatalf("SECURITY FAILURE: leaked secret %q inside aiops_runtime.json!", secret)
		}
	}
}

func extractServerIDFromSystemPrompt(payload map[string]any) string {
	msgs, _ := payload["messages"].([]any)
	for _, m := range msgs {
		mm, _ := m.(map[string]any)
		if mm["role"] == "system" {
			content, _ := mm["content"].(string)
			idx := strings.Index(content, "[server_id=")
			if idx >= 0 {
				rest := content[idx+len("[server_id="):]
				end := strings.Index(rest, "]")
				if end > 0 {
					return rest[:end]
				}
			}
		}
	}
	return ""
}

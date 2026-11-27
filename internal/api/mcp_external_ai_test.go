package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/auth"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
	"github.com/icaruszezen/ServerNeedSafe/internal/version"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func postMCPJSONRPC(t *testing.T, url, bearerToken, sessionID string, payload any) (*http.Response, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}
	if sessionID != "" {
		req.Header.Set("Mcp-Session-Id", sessionID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	bodyBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var decoded map[string]any
	if len(bytes.TrimSpace(bodyBytes)) > 0 {
		_ = json.Unmarshal(bodyBytes, &decoded)
	}
	return resp, decoded
}

func TestExternalAIMCPGatewayPatrolTakeoverAndHITL(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := vault.NewStore(tmpDir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	srv := NewServer(Config{
		DeployMode: "server",
		Store:      store,
	})
	defer srv.Close()

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Capture webhook notifications (patrol report + pending HITL approval)
	var whMu sync.Mutex
	var whPayloads []map[string]any
	whServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p map[string]any
		_ = json.NewDecoder(r.Body).Decode(&p)
		whMu.Lock()
		whPayloads = append(whPayloads, p)
		whMu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer whServer.Close()

	// 1. Setup admin vault & obtain admin session token
	setupBody, _ := json.Marshal(map[string]string{"password": "AdminStrongPass!2026"})
	res, err := http.Post(ts.URL+"/api/auth/setup", "application/json", bytes.NewReader(setupBody))
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/auth/setup failed: %v status=%v", err, res)
	}
	var setupResp struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(res.Body).Decode(&setupResp)
	res.Body.Close()
	adminToken := setupResp.Token

	adminReq := func(method, path string, body any) (*http.Response, []byte) {
		var rdr io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rdr = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, ts.URL+path, rdr)
		req.Header.Set("Authorization", "Bearer "+adminToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, b
	}

	// Create two servers in vault (srvA and srvB)
	_, srvABytes := adminReq(http.MethodPost, "/api/servers", map[string]any{
		"name":      "prod-web-01",
		"group":     "生产环境",
		"host":      "10.0.1.10",
		"port":      22,
		"username":  "root",
		"auth_type": "password",
		"password":  "SuperSecretSSHPassword123!",
	})
	var srvAResp struct {
		Server vault.ServerView `json:"server"`
	}
	_ = json.Unmarshal(srvABytes, &srvAResp)
	srvA := srvAResp.Server

	_, srvBBytes := adminReq(http.MethodPost, "/api/servers", map[string]any{
		"name":      "prod-db-01",
		"group":     "核心数据库",
		"host":      "10.0.1.20",
		"port":      22,
		"username":  "root",
		"auth_type": "password",
		"password":  "SuperSecretDBPassword456!",
	})
	var srvBResp struct {
		Server vault.ServerView `json:"server"`
	}
	_ = json.Unmarshal(srvBBytes, &srvBResp)
	srvB := srvBResp.Server

	// Configure patrol with external_with_fallback + webhook + notify_pending_approvals
	patrolResp, _ := adminReq(http.MethodPut, "/api/ai/patrol/config", map[string]any{
		"enabled":                   false,
		"interval_minutes":          30,
		"server_ids":                []string{},
		"cpu_warn_percent":          85,
		"mem_warn_percent":          85,
		"disk_warn_percent":         85,
		"ssh_fail_warn_count":       15,
		"check_listening_ports":     true,
		"check_privileged_users":    true,
		"analysis_mode":             "external_with_fallback",
		"external_fallback_minutes": 15,
		"notify_pending_approvals":  true,
		"webhooks": []map[string]any{
			{
				"name":    "Test Custom Webhook",
				"kind":    "custom",
				"url":     whServer.URL,
				"enabled": true,
			},
		},
	})
	if patrolResp.StatusCode != http.StatusOK {
		t.Fatalf("PUT /api/ai/patrol/config failed: %d", patrolResp.StatusCode)
	}

	// 2. Create two scoped MCP tokens:
	//    - readonlyToken: patrol_readonly, all servers
	//    - opsToken: ops_propose, restricted to srvA only
	_, roTokBytes := adminReq(http.MethodPost, "/api/ai/mcp/tokens", map[string]any{
		"name":        "Cursor ReadOnly",
		"client_hint": "cursor",
		"scope":       "patrol_readonly",
	})
	var roTokResp struct {
		RawToken string             `json:"raw_token"`
		Token    vault.MCPTokenView `json:"token"`
	}
	_ = json.Unmarshal(roTokBytes, &roTokResp)
	if !strings.HasPrefix(roTokResp.RawToken, "sns_mcp_") {
		t.Fatalf("expected sns_mcp_ prefix, got %q", roTokResp.RawToken)
	}

	_, opsTokBytes := adminReq(http.MethodPost, "/api/ai/mcp/tokens", map[string]any{
		"name":            "MacBook Claude Code",
		"client_hint":     "claude_code",
		"scope":           "ops_propose",
		"allowed_servers": []string{srvA.ID},
	})
	var opsTokResp struct {
		RawToken string             `json:"raw_token"`
		Token    vault.MCPTokenView `json:"token"`
	}
	_ = json.Unmarshal(opsTokBytes, &opsTokResp)
	if !strings.HasPrefix(opsTokResp.RawToken, "sns_mcp_") {
		t.Fatalf("expected ops sns_mcp_ token, got %q", opsTokResp.RawToken)
	}

	mcpURL := ts.URL + "/api/mcp"

	// 3. Auth Isolation Checks
	// 3a. No token -> 401
	resp, _ := postMCPJSONRPC(t, mcpURL, "", "", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "ping"})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", resp.StatusCode)
	}
	// 3b. Admin session token CANNOT be used on /api/mcp -> 401
	resp, _ = postMCPJSONRPC(t, mcpURL, adminToken, "", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "ping"})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 when using admin session token on /api/mcp, got %d", resp.StatusCode)
	}
	// 3c. MCP token CANNOT access admin REST routes (/api/servers, /api/credentials) -> 401
	for _, adminPath := range []string{"/api/servers", "/api/credentials", "/api/vault/security"} {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+adminPath, nil)
		req.Header.Set("Authorization", "Bearer "+opsTokResp.RawToken)
		aRes, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET %s with MCP token: %v", adminPath, err)
		}
		aRes.Body.Close()
		if aRes.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 using MCP token on %s, got %d", adminPath, aRes.StatusCode)
		}
	}

	// 4. MCP Handshake (initialize + notifications/initialized) as Claude Code
	initResp, initBody := postMCPJSONRPC(t, mcpURL, opsTokResp.RawToken, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": "2025-03-26",
			"clientInfo": map[string]any{
				"name":    "claude-code",
				"version": "1.2.0",
			},
		},
	})
	if initResp.StatusCode != http.StatusOK {
		t.Fatalf("initialize expected 200, got %d", initResp.StatusCode)
	}
	sessionID := initResp.Header.Get("Mcp-Session-Id")
	if sessionID == "" {
		t.Fatalf("expected Mcp-Session-Id header on initialize")
	}
	resultObj := initBody["result"].(map[string]any)
	if resultObj["protocolVersion"] != "2025-03-26" {
		t.Fatalf("unexpected protocolVersion: %v", resultObj["protocolVersion"])
	}

	notifResp, _ := postMCPJSONRPC(t, mcpURL, opsTokResp.RawToken, sessionID, map[string]any{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	})
	if notifResp.StatusCode != http.StatusAccepted {
		t.Fatalf("notifications/initialized expected 202, got %d", notifResp.StatusCode)
	}

	// 5. Token Scope & Server Allowlist Enforcement
	// 5a. list_servers with opsToken (allowed only srvA) must return ONLY srvA and NEVER expose SSH passwords
	_, listSrvBody := postMCPJSONRPC(t, mcpURL, opsTokResp.RawToken, sessionID, map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/call",
		"params":  map[string]any{"name": "list_servers", "arguments": map[string]any{}},
	})
	listText := extractMCPToolText(t, listSrvBody)
	if !strings.Contains(listText, srvA.ID) || strings.Contains(listText, srvB.ID) {
		t.Fatalf("expected allowlist to filter servers to srvA only, got:\n%s", listText)
	}
	if strings.Contains(listText, "SuperSecretSSHPassword123!") || strings.Contains(listText, "SuperSecretDBPassword456!") {
		t.Fatalf("CRITICAL: raw SSH password leaked into MCP list_servers response!")
	}

	// 5b. readonlyToken cannot call propose_change_plan; retired single-step tools return migration error
	_, toolsListBody := postMCPJSONRPC(t, mcpURL, opsTokResp.RawToken, sessionID, map[string]any{
		"jsonrpc": "2.0",
		"id":      30,
		"method":  "tools/list",
	})
	toolsJSON, _ := json.Marshal(toolsListBody)
	if !strings.Contains(string(toolsJSON), `"propose_change_plan"`) || !strings.Contains(string(toolsJSON), `"wait_for_approval"`) {
		t.Fatalf("expected ops_propose tools/list to expose propose_change_plan and wait_for_approval, got: %s", string(toolsJSON))
	}
	if strings.Contains(string(toolsJSON), `"propose_ssh_command"`) || strings.Contains(string(toolsJSON), `"propose_sftp_write"`) {
		t.Fatalf("expected legacy propose_ssh_command/propose_sftp_write to be retired from tools/list, got: %s", string(toolsJSON))
	}

	_, legacyCallBody := postMCPJSONRPC(t, mcpURL, opsTokResp.RawToken, sessionID, map[string]any{
		"jsonrpc": "2.0",
		"id":      31,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "propose_ssh_command",
			"arguments": map[string]any{"server_ids": []string{srvA.ID}, "command": "systemctl reload nginx", "reason": "legacy"},
		},
	})
	if !extractMCPToolIsError(t, legacyCallBody) || !strings.Contains(extractMCPToolText(t, legacyCallBody), "propose_change_plan") {
		t.Fatalf("expected legacy propose_ssh_command call to return migration guidance error, got: %v", legacyCallBody)
	}

	_, roDenyBody := postMCPJSONRPC(t, mcpURL, roTokResp.RawToken, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      3,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "propose_change_plan",
			"arguments": map[string]any{
				"title":  "readonly denial plan",
				"reason": "test readonly denial",
				"steps": []map[string]any{
					{
						"type":       "exec_ssh_command",
						"server_ids": []string{srvA.ID},
						"command":    "systemctl reload nginx",
					},
				},
			},
		},
	})
	if !extractMCPToolIsError(t, roDenyBody) {
		t.Fatalf("expected patrol_readonly token to be rejected for propose_change_plan")
	}

	// 5c. exec_readonly_ssh MUST reject mutating and catastrophic commands
	_, mutDenyBody := postMCPJSONRPC(t, mcpURL, opsTokResp.RawToken, sessionID, map[string]any{
		"jsonrpc": "2.0",
		"id":      4,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "exec_readonly_ssh",
			"arguments": map[string]any{
				"server_ids": []string{srvA.ID},
				"command":    "systemctl restart nginx",
				"reason":     "try mutating in readonly tool",
			},
		},
	})
	if !extractMCPToolIsError(t, mutDenyBody) {
		t.Fatalf("expected exec_readonly_ssh to reject mutating command")
	}

	// 5d. sftp_read_file MUST hard-block /etc/shadow and private key paths
	for _, blockedPath := range []string{"/etc/shadow", "/root/.ssh/id_ed25519", "/data/secrets.enc", "/data/master.key"} {
		_, secDeny := postMCPJSONRPC(t, mcpURL, opsTokResp.RawToken, sessionID, map[string]any{
			"jsonrpc": "2.0",
			"id":      5,
			"method":  "tools/call",
			"params": map[string]any{
				"name":      "sftp_read_file",
				"arguments": map[string]any{"server_id": srvA.ID, "path": blockedPath},
			},
		})
		if !extractMCPToolIsError(t, secDeny) {
			t.Fatalf("expected sftp_read_file to block sensitive path %s", blockedPath)
		}
	}

	// 6. Patrol Takeover Queue End-to-End: pending_external -> claim_patrol -> submit_patrol_report -> webhook
	now := time.Now().UTC()
	deadline := now.Add(15 * time.Minute)
	seedRec := vault.PatrolRecord{
		ID:                 "patrol-seed-001",
		StartedAt:          now.Add(-10 * time.Second),
		CompletedAt:        now,
		Trigger:            "scheduled",
		TotalServers:       1,
		WarningCount:       1,
		Status:             "warning",
		AnalysisState:      "pending_external",
		ExternalDeadlineAt: &deadline,
		Unread:             true,
		Findings: []vault.PatrolFinding{
			{
				ServerID:       srvA.ID,
				ServerName:     srvA.Name,
				Host:           "10.0.1.10:22",
				Reachable:      true,
				Severity:       "warning",
				DiskPercent:    91.5,
				SSHFailCount1h: 42,
				Anomalies:      []string{"根分区磁盘空间告警 (91.5% >= 85%)", "近 1 小时检测到 42 次 SSH 失败认证尝试"},
			},
		},
	}
	if err := store.AppendPatrolRecord(seedRec); err != nil {
		t.Fatalf("AppendPatrolRecord: %v", err)
	}

	// 6a. list_patrol_records(pending_only=true)
	_, pendBody := postMCPJSONRPC(t, mcpURL, opsTokResp.RawToken, sessionID, map[string]any{
		"jsonrpc": "2.0",
		"id":      6,
		"method":  "tools/call",
		"params":  map[string]any{"name": "list_patrol_records", "arguments": map[string]any{"pending_only": true}},
	})
	pendText := extractMCPToolText(t, pendBody)
	if !strings.Contains(pendText, "patrol-seed-001") {
		t.Fatalf("expected pending patrol record in queue, got:\n%s", pendText)
	}

	// 6b. claim_patrol
	_, claimBody := postMCPJSONRPC(t, mcpURL, opsTokResp.RawToken, sessionID, map[string]any{
		"jsonrpc": "2.0",
		"id":      7,
		"method":  "tools/call",
		"params":  map[string]any{"name": "claim_patrol", "arguments": map[string]any{"patrol_record_id": "patrol-seed-001"}},
	})
	claimText := extractMCPToolText(t, claimBody)
	if !strings.Contains(claimText, "AGENTS.md") || !strings.Contains(claimText, `"claimed"`) {
		t.Fatalf("expected claimed state + AGENTS.md ops context, got:\n%s", claimText)
	}

	// 6c. submit_patrol_report
	_, submitBody := postMCPJSONRPC(t, mcpURL, opsTokResp.RawToken, sessionID, map[string]any{
		"jsonrpc": "2.0",
		"id":      8,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "submit_patrol_report",
			"arguments": map[string]any{
				"patrol_record_id": "patrol-seed-001",
				"summary":          "prod-web-01 根分区受 systemd journal 日志膨胀影响达 91.5%，伴随低频 SSH 扫描。",
				"root_cause":       "通过只读取证定位 /var/log/journal 占用 14.2GB 未配置上限；SSH 爆破来自单一扫描 IP。",
				"deep_evidence":    []string{"journalctl --disk-usage -> 14.2G", "lastb top IP: 203.0.113.88 (39次)"},
				"recommendations":  []string{"执行 journalctl --vacuum-size=200M 释放空间", "配置 /etc/systemd/journald.conf SystemMaxUse=500M"},
				"model_name":       "claude-sonnet-4-5",
				"dispatch_webhook": true,
			},
		},
	})
	if extractMCPToolIsError(t, submitBody) {
		t.Fatalf("submit_patrol_report failed: %s", extractMCPToolText(t, submitBody))
	}

	updatedRec, err := store.GetPatrolRecord("patrol-seed-001")
	if err != nil {
		t.Fatalf("GetPatrolRecord: %v", err)
	}
	if !updatedRec.AIAnalyzed || updatedRec.AISource != "external_mcp" || updatedRec.ExternalClient != "Claude Code" || !updatedRec.AIWebhookNotified {
		t.Fatalf("unexpected updated patrol record: %+v", updatedRec)
	}

	// 7. External AI HITL Change Plan Flow
	// 7a. Catastrophic command enters the queue marked blocked (red-locked, non-executable) so admin can audit what AI attempted
	_, blockBody := postMCPJSONRPC(t, mcpURL, opsTokResp.RawToken, sessionID, map[string]any{
		"jsonrpc": "2.0",
		"id":      9,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "propose_change_plan",
			"arguments": map[string]any{
				"title":  "高危指令拦截测试",
				"reason": "catastrophic test",
				"steps": []map[string]any{
					{
						"type":       "exec_ssh_command",
						"server_ids": []string{srvA.ID},
						"command":    "rm -rf /",
					},
				},
			},
		},
	})
	if extractMCPToolIsError(t, blockBody) {
		t.Fatalf("expected blocked step plan to enqueue as locked for admin visibility, got error: %s", extractMCPToolText(t, blockBody))
	}
	var blockRes struct {
		ApprovalID      string `json:"approval_id"`
		BlockedSteps    int    `json:"blocked_steps"`
		ExecutableSteps int    `json:"executable_steps"`
		HasBlockedSteps bool   `json:"has_blocked_steps"`
	}
	_ = json.Unmarshal([]byte(extractMCPToolText(t, blockBody)), &blockRes)
	if blockRes.ApprovalID == "" || !blockRes.HasBlockedSteps || blockRes.BlockedSteps != 1 || blockRes.ExecutableSteps != 0 {
		t.Fatalf("expected 1 blocked step and 0 executable steps, got: %+v", blockRes)
	}
	// Attempting to approve an all-blocked plan MUST be hard-refused by backend
	approveBlockedResp, _ := adminReq(http.MethodPost, "/api/ai/external-approvals/"+blockRes.ApprovalID+"/resolve", map[string]any{
		"approve": true,
	})
	if approveBlockedResp.StatusCode == http.StatusOK {
		t.Fatalf("SECURITY FAILURE: backend approved a plan containing only blocked steps!")
	}
	// Admin rejects the blocked plan cleanly
	rejectBlockedResp, _ := adminReq(http.MethodPost, "/api/ai/external-approvals/"+blockRes.ApprovalID+"/resolve", map[string]any{
		"approve": false,
	})
	if rejectBlockedResp.StatusCode != http.StatusOK {
		t.Fatalf("expected rejecting blocked plan to succeed, got %d", rejectBlockedResp.StatusCode)
	}

	// 7b. Valid repair change plan -> lands in pending approval queue & fires 1 aggregated pending-approval webhook
	_, propBody := postMCPJSONRPC(t, mcpURL, opsTokResp.RawToken, sessionID, map[string]any{
		"jsonrpc": "2.0",
		"id":      10,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "propose_change_plan",
			"arguments": map[string]any{
				"title":            "清理系统日志释放根分区空间",
				"reason":           "清理膨胀的 systemd journal 日志释放根分区空间",
				"patrol_record_id": "patrol-seed-001",
				"steps": []map[string]any{
					{
						"type":       "exec_ssh_command",
						"title":      "收缩 journal 日志",
						"server_ids": []string{srvA.ID},
						"command":    "journalctl --vacuum-size=200M",
					},
				},
			},
		},
	})
	if extractMCPToolIsError(t, propBody) {
		t.Fatalf("propose_change_plan failed: %s", extractMCPToolText(t, propBody))
	}
	var propResult struct {
		ApprovalID      string `json:"approval_id"`
		Status          string `json:"status"`
		TotalSteps      int    `json:"total_steps"`
		WebhookNotified bool   `json:"webhook_notified"`
	}
	_ = json.Unmarshal([]byte(extractMCPToolText(t, propBody)), &propResult)
	if propResult.ApprovalID == "" || propResult.Status != "pending" || propResult.TotalSteps != 1 || !propResult.WebhookNotified {
		t.Fatalf("unexpected proposal result: %+v", propResult)
	}

	// 7c. Admin rejects the proposal in Web UI -> external AI queries get_approval_status and sees rejected
	resolveResp, resolveBytes := adminReq(http.MethodPost, "/api/ai/external-approvals/"+propResult.ApprovalID+"/resolve", map[string]any{
		"approve": false,
	})
	if resolveResp.StatusCode != http.StatusOK {
		t.Fatalf("resolve external approval failed: %d %s", resolveResp.StatusCode, string(resolveBytes))
	}
	_, statusBody := postMCPJSONRPC(t, mcpURL, opsTokResp.RawToken, sessionID, map[string]any{
		"jsonrpc": "2.0",
		"id":      11,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "get_approval_status",
			"arguments": map[string]any{"approval_id": propResult.ApprovalID},
		},
	})
	if !strings.Contains(extractMCPToolText(t, statusBody), `"rejected"`) {
		t.Fatalf("expected get_approval_status to reflect rejected status, got: %s", extractMCPToolText(t, statusBody))
	}

	// 7d. Verify MCP Resources & Prompts work cleanly
	_, resBody := postMCPJSONRPC(t, mcpURL, opsTokResp.RawToken, sessionID, map[string]any{
		"jsonrpc": "2.0",
		"id":      12,
		"method":  "resources/read",
		"params":  map[string]any{"uri": "serverneedsafe://agents-md"},
	})
	if resBody["error"] != nil {
		t.Fatalf("resources/read failed: %v", resBody["error"])
	}

	_, promptBody := postMCPJSONRPC(t, mcpURL, opsTokResp.RawToken, sessionID, map[string]any{
		"jsonrpc": "2.0",
		"id":      13,
		"method":  "prompts/get",
		"params":  map[string]any{"name": "patrol_triage"},
	})
	if promptBody["error"] != nil {
		t.Fatalf("prompts/get failed: %v", promptBody["error"])
	}

	// Verify both patrol report & pending approval webhooks were delivered
	whMu.Lock()
	whCount := len(whPayloads)
	whMu.Unlock()
	if whCount < 2 {
		t.Fatalf("expected at least 2 webhook dispatches (patrol report + pending approval), got %d", whCount)
	}

	// 8. Disabling MCP gateway immediately blocks /api/mcp with 403
	disableResp, _ := adminReq(http.MethodPut, "/api/ai/mcp/config", map[string]any{"enabled": false})
	if disableResp.StatusCode != http.StatusOK {
		t.Fatalf("disable MCP failed: %d", disableResp.StatusCode)
	}
	disResp, _ := postMCPJSONRPC(t, mcpURL, opsTokResp.RawToken, sessionID, map[string]any{
		"jsonrpc": "2.0",
		"id":      14,
		"method":  "ping",
	})
	if disResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 when MCP gateway is disabled, got %d", disResp.StatusCode)
	}
}

func TestDesktopModeDedicatedMCPLoopbackIsolation(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := vault.NewStore(tmpDir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	authMgr, err := auth.NewManager(auth.DefaultSessionTTL, true)
	if err != nil {
		store.Close()
		t.Fatalf("NewManager: %v", err)
	}

	srv := NewServer(Config{
		DeployMode: "desktop",
		Store:      store,
		Auth:       authMgr,
	})
	defer srv.Close()

	mainTS := httptest.NewServer(srv.Handler())
	defer mainTS.Close()

	// Boot desktop session via WebView2 cookie
	jar, _ := cookiejar.New(nil)
	desktopClient := &http.Client{Jar: jar}
	bootRes, err := desktopClient.Get(mainTS.URL + "/__desktop_boot?boot=" + authMgr.DesktopBootCode())
	if err != nil {
		t.Fatalf("desktop boot: %v", err)
	}
	bootRes.Body.Close()

	setupPayload, _ := json.Marshal(map[string]string{"password": "DesktopMCPPass!2026"})
	setupRes, err := desktopClient.Post(mainTS.URL+"/api/auth/setup", "application/json", bytes.NewReader(setupPayload))
	if err != nil || setupRes.StatusCode != http.StatusOK {
		t.Fatalf("desktop setup failed: %v", err)
	}
	setupRes.Body.Close()

	// Create MCP token inside desktop app
	tokReqPayload, _ := json.Marshal(map[string]any{
		"name":        "Local Desktop Antigravity",
		"client_hint": "antigravity",
		"scope":       "ops_propose",
	})
	tokRes, err := desktopClient.Post(mainTS.URL+"/api/ai/mcp/tokens", "application/json", bytes.NewReader(tokReqPayload))
	if err != nil || tokRes.StatusCode != http.StatusOK {
		t.Fatalf("create MCP token in desktop: %v", err)
	}
	var tokOut struct {
		RawToken string `json:"raw_token"`
	}
	_ = json.NewDecoder(tokRes.Body).Decode(&tokOut)
	tokRes.Body.Close()

	// 1. Primary WebView2 random-port server MUST STILL reject external /api/mcp calls without desktopGuardCookie (403)
	mainMCPResp, _ := postMCPJSONRPC(t, mainTS.URL+"/api/mcp", tokOut.RawToken, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "ping",
	})
	if mainMCPResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected desktop primary server to block untrusted /api/mcp with 403, got %d", mainMCPResp.StatusCode)
	}

	// 2. Desktop loopback listener MUST be OFF by default
	if running, _, _ := srv.mcpLoopback.Status(); running {
		t.Fatalf("expected desktop MCP loopback listener to be OFF by default")
	}

	// Find a free localhost port for testing opt-in desktop loopback listener
	probeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate free port: %v", err)
	}
	freePort := probeLn.Addr().(*net.TCPAddr).Port
	probeLn.Close()

	// 3. Opt-in via PUT /api/ai/mcp/config -> starts dedicated 127.0.0.1:<freePort> MCP-only listener
	cfgPayload, _ := json.Marshal(map[string]any{
		"desktop_loopback_enabled": true,
		"desktop_loopback_port":    freePort,
	})
	cfgReq, _ := http.NewRequest(http.MethodPut, mainTS.URL+"/api/ai/mcp/config", bytes.NewReader(cfgPayload))
	cfgReq.Header.Set("Content-Type", "application/json")
	cfgRes, err := desktopClient.Do(cfgReq)
	if err != nil || cfgRes.StatusCode != http.StatusOK {
		t.Fatalf("enable desktop loopback failed: %v", err)
	}
	cfgRes.Body.Close()

	loopbackBase := fmt.Sprintf("http://127.0.0.1:%d", freePort)

	// 3a. /api/mcp on dedicated loopback accepts valid MCP Bearer Token!
	pingResp, pingBody := postMCPJSONRPC(t, loopbackBase+"/api/mcp", tokOut.RawToken, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "ping",
	})
	if pingResp.StatusCode != http.StatusOK || pingBody["error"] != nil {
		t.Fatalf("expected desktop loopback /api/mcp ping 200, got %d body=%v", pingResp.StatusCode, pingBody)
	}

	// 3b. Non-MCP admin routes MUST NOT exist on the dedicated loopback listener (404)
	srvRes, err := http.Get(loopbackBase + "/api/servers")
	if err != nil {
		t.Fatalf("GET loopback /api/servers: %v", err)
	}
	srvRes.Body.Close()
	if srvRes.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 for /api/servers on desktop MCP-only loopback listener, got %d", srvRes.StatusCode)
	}

	// 4. Disable desktop loopback -> listener shuts down cleanly
	offPayload, _ := json.Marshal(map[string]any{"desktop_loopback_enabled": false})
	offReq, _ := http.NewRequest(http.MethodPut, mainTS.URL+"/api/ai/mcp/config", bytes.NewReader(offPayload))
	offReq.Header.Set("Content-Type", "application/json")
	offRes, err := desktopClient.Do(offReq)
	if err != nil || offRes.StatusCode != http.StatusOK {
		t.Fatalf("disable desktop loopback failed: %v", err)
	}
	offRes.Body.Close()

	if running, _, _ := srv.mcpLoopback.Status(); running {
		t.Fatalf("expected desktop MCP loopback listener to stop after disabling")
	}
}

func TestExternalPatrolTimeoutFallbackToBuiltinLLM(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := vault.NewStore(tmpDir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := store.Setup("FallbackAdminPass!2026", "127.0.0.1"); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	srv := NewServer(Config{DeployMode: "server", Store: store})
	defer srv.Close()

	// Mock OpenAI-compatible SSE streaming server for built-in fallback
	mockLLM := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"{\\\"summary\\\":\\\"内置兜底：根分区日志满载\\\",\\\"root_cause\\\":\\\"超过外部等待时间，由内置模型兜底定位日志膨胀\\\",\\\"recommendations\\\":[\\\"执行 journalctl --vacuum-size=200M\\\"]}\"}}]}\n\ndata: [DONE]\n\n"))
	}))
	defer mockLLM.Close()

	key := "test-key"
	if _, _, err := store.UpsertAIProvider(vault.AIProviderMutationInput{
		Name:      "MockFallbackLLM",
		Protocol:  vault.AIProtocolOpenAI,
		BaseURL:   mockLLM.URL + "/v1",
		APIKey:    &key,
		Model:     "gpt-4.1-mini",
		SetActive: true,
	}, "127.0.0.1"); err != nil {
		t.Fatalf("UpsertAIProvider: %v", err)
	}

	past := time.Now().UTC().Add(-2 * time.Minute)
	if err := store.AppendPatrolRecord(vault.PatrolRecord{
		ID:                 "patrol-expired-001",
		StartedAt:          past.Add(-16 * time.Minute),
		CompletedAt:        past.Add(-15 * time.Minute),
		Trigger:            "scheduled",
		TotalServers:       1,
		WarningCount:       1,
		Status:             "warning",
		AnalysisState:      "pending_external",
		ExternalDeadlineAt: &past,
		Findings: []vault.PatrolFinding{
			{
				ServerID:   "srv-1",
				ServerName: "edge-01",
				Host:       "10.0.0.5:22",
				Reachable:  true,
				Severity:   "warning",
				Anomalies:  []string{"根分区磁盘空间告警 (92.0% >= 85%)"},
			},
		},
	}); err != nil {
		t.Fatalf("AppendPatrolRecord: %v", err)
	}

	processed := srv.cfg.AI.ProcessExpiredExternalPatrolFallbacks(context.Background())
	if processed != 1 {
		t.Fatalf("expected 1 expired patrol record to fall back to built-in LLM, got %d", processed)
	}
	rec, err := store.GetPatrolRecord("patrol-expired-001")
	if err != nil {
		t.Fatalf("GetPatrolRecord: %v", err)
	}
	if !rec.AIAnalyzed || rec.AnalysisState != "fallback_completed" || rec.AISource != "builtin" {
		t.Fatalf("expected fallback_completed builtin analysis, got %+v", rec)
	}
	if !strings.Contains(rec.AISummary, "内置兜底") {
		t.Fatalf("unexpected fallback summary: %q", rec.AISummary)
	}
}

func extractMCPToolText(t *testing.T, body map[string]any) string {
	t.Helper()
	res, ok := body["result"].(map[string]any)
	if !ok {
		t.Fatalf("missing result in MCP response: %v", body)
	}
	content, ok := res["content"].([]any)
	if !ok || len(content) == 0 {
		t.Fatalf("missing content array in MCP response: %v", body)
	}
	first := content[0].(map[string]any)
	text, _ := first["text"].(string)
	return text
}

func extractMCPToolIsError(t *testing.T, body map[string]any) bool {
	t.Helper()
	res, ok := body["result"].(map[string]any)
	if !ok {
		return true
	}
	isErr, _ := res["isError"].(bool)
	return isErr
}

func TestMCPReviewSecurityAndIsolationFixes(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := vault.NewStore(tmpDir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := store.Setup("MCPSecurityAdmin!2026", "127.0.0.1"); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	srv := NewServer(Config{DeployMode: "server", Store: store})
	defer srv.Close()

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	mcpURL := ts.URL + "/api/mcp"

	srvA, err := store.CreateServer(vault.ServerMutationInput{
		Name: "web-a", Host: "10.10.0.1", Port: 22, Username: "root",
		AuthType: vault.AuthPassword, Password: strPtr("PassA!123"),
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("CreateServer A: %v", err)
	}
	srvB, err := store.CreateServer(vault.ServerMutationInput{
		Name: "db-b", Host: "10.10.0.2", Port: 22, Username: "root",
		AuthType: vault.AuthPassword, Password: strPtr("PassB!456"),
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("CreateServer B: %v", err)
	}

	// Seed memories & host profiles for srvA, srvB, and global
	_, _ = store.UpsertHostMemory(vault.HostMemory{ServerID: srvA.ID, Summary: "SRV_A_PROFILE_PUBLIC"}, false, "127.0.0.1")
	_, _ = store.UpsertHostMemory(vault.HostMemory{ServerID: srvB.ID, Summary: "SRV_B_SECRET_DB_PROFILE"}, false, "127.0.0.1")
	_, _ = store.UpsertAIMemory(vault.AIMemoryEntry{
		Title: "Global Rule", Category: "preference", Scope: "global", Content: "GLOBAL_RULE_VISIBLE",
	}, false, "127.0.0.1")
	_, _ = store.UpsertAIMemory(vault.AIMemoryEntry{
		Title: "Server A Note", Category: "architecture", Scope: "server", ServerIDs: []string{srvA.ID}, Content: "SRV_A_MEM_VISIBLE",
	}, false, "127.0.0.1")
	_, _ = store.UpsertAIMemory(vault.AIMemoryEntry{
		Title: "Server B Note", Category: "architecture", Scope: "server", ServerIDs: []string{srvB.ID}, Content: "SRV_B_MEM_CONFIDENTIAL",
	}, false, "127.0.0.1")

	// Seed a multi-server patrol record containing both srvA and srvB
	now := time.Now().UTC()
	patrolID := "patrol-scope-check-1"
	if err := store.AppendPatrolRecord(vault.PatrolRecord{
		ID:            patrolID,
		StartedAt:     now.Add(-time.Minute),
		CompletedAt:   now,
		Trigger:       "scheduled",
		TotalServers:  2,
		WarningCount:  1,
		Status:        "warning",
		AnalysisState: "pending_external",
		Findings: []vault.PatrolFinding{
			{ServerID: srvA.ID, ServerName: srvA.Name, Host: "10.10.0.1:22", Reachable: true, Severity: "healthy"},
			{ServerID: srvB.ID, ServerName: srvB.Name, Host: "10.10.0.2:22", Reachable: true, Severity: "warning", Anomalies: []string{"DB 磁盘偏高"}},
		},
	}); err != nil {
		t.Fatalf("AppendPatrolRecord: %v", err)
	}

	_, rawScoped, err := store.CreateMCPToken(vault.CreateMCPTokenInput{
		Name:           "Scoped Ops A",
		Scope:          vault.MCPScopeOpsPropose,
		AllowedServers: []string{srvA.ID},
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("CreateMCPToken scoped: %v", err)
	}
	_, rawFull, err := store.CreateMCPToken(vault.CreateMCPTokenInput{
		Name:  "Full Ops",
		Scope: vault.MCPScopeOpsPropose,
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("CreateMCPToken full: %v", err)
	}

	// 1. Initialize reports dynamic version.Current().Version and binds session to token
	initRes, initBody := postMCPJSONRPC(t, mcpURL, rawFull, "", map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]any{
			"protocolVersion": "2025-03-26",
			"clientInfo":      map[string]any{"name": "cursor", "version": "1.0"},
		},
	})
	if initRes.StatusCode != http.StatusOK {
		t.Fatalf("initialize full failed: %d", initRes.StatusCode)
	}
	fullSessionID := initRes.Header.Get("Mcp-Session-Id")
	srvInfo := initBody["result"].(map[string]any)["serverInfo"].(map[string]any)
	if srvInfo["version"] != version.Current().Version {
		t.Fatalf("expected MCP serverInfo.version=%q, got %v", version.Current().Version, srvInfo["version"])
	}

	// Token B attempting to DELETE Token A's session must NOT delete Token A's session
	delReq, _ := http.NewRequest(http.MethodDelete, mcpURL, nil)
	delReq.Header.Set("Authorization", "Bearer "+rawScoped)
	delReq.Header.Set("Mcp-Session-Id", fullSessionID)
	delResp, err := http.DefaultClient.Do(delReq)
	if err != nil {
		t.Fatalf("DELETE /api/mcp: %v", err)
	}
	delResp.Body.Close()

	// Verify fullSessionID still belongs to rawFull by proposing a change plan under fullSessionID
	_, propBBody := postMCPJSONRPC(t, mcpURL, rawFull, fullSessionID, map[string]any{
		"jsonrpc": "2.0", "id": 2, "method": "tools/call",
		"params": map[string]any{
			"name": "propose_change_plan",
			"arguments": map[string]any{
				"title":  "update db proxy",
				"reason": "update db proxy",
				"steps": []map[string]any{
					{
						"type":      "sftp_write_file",
						"server_id": srvB.ID,
						"path":      "/etc/nginx/conf.d/db-proxy.conf",
						"content":   "SUPER_SENSITIVE_FILE_PAYLOAD_999",
					},
				},
			},
		},
	})
	if extractMCPToolIsError(t, propBBody) {
		t.Fatalf("propose_change_plan on srvB failed: %v", propBBody)
	}
	// If fullSessionID had been deleted by rawScoped, client_name would have fallen back away from "Cursor".
	apsAll, _, _ := store.ListExternalApprovals("pending", 20)
	if len(apsAll) != 1 || apsAll[0].ClientName != "Cursor" {
		t.Fatalf("expected fullSessionID to remain intact with ClientName=Cursor, got %+v", apsAll)
	}

	// Out-of-scope server inside ANY step of propose_change_plan MUST be rejected at gateway boundary
	_, crossScopeDeny := postMCPJSONRPC(t, mcpURL, rawScoped, "", map[string]any{
		"jsonrpc": "2.0", "id": 301, "method": "tools/call",
		"params": map[string]any{
			"name": "propose_change_plan",
			"arguments": map[string]any{
				"title":  "cross scope attempt",
				"reason": "should be rejected",
				"steps": []map[string]any{
					{"type": "exec_ssh_command", "server_ids": []string{srvA.ID}, "command": "systemctl reload nginx"},
					{"type": "exec_ssh_command", "server_ids": []string{srvB.ID}, "command": "systemctl reload postgresql"},
				},
			},
		},
	})
	if !extractMCPToolIsError(t, crossScopeDeny) {
		t.Fatalf("SECURITY FAILURE: scoped token was allowed to submit plan targeting unauthorized srvB!")
	}

	// Also create a pending approval plan on srvA
	_, propABody := postMCPJSONRPC(t, mcpURL, rawScoped, "", map[string]any{
		"jsonrpc": "2.0", "id": 3, "method": "tools/call",
		"params": map[string]any{
			"name": "propose_change_plan",
			"arguments": map[string]any{
				"title":  "reload web-a",
				"reason": "reload web-a",
				"steps": []map[string]any{
					{
						"type":       "exec_ssh_command",
						"server_ids": []string{srvA.ID},
						"command":    "systemctl reload nginx",
					},
				},
			},
		},
	})
	if extractMCPToolIsError(t, propABody) {
		t.Fatalf("propose_change_plan on srvA failed: %v", propABody)
	}

	// 2. list_approvals and approvals/pending MUST strip new_content even for fullToken,
	//    and compute token-scoped pending_total for scopedToken!
	_, fullListApBody := postMCPJSONRPC(t, mcpURL, rawFull, fullSessionID, map[string]any{
		"jsonrpc": "2.0", "id": 4, "method": "tools/call",
		"params": map[string]any{"name": "list_approvals", "arguments": map[string]any{"status": "pending"}},
	})
	fullListApText := extractMCPToolText(t, fullListApBody)
	if strings.Contains(fullListApText, "SUPER_SENSITIVE_FILE_PAYLOAD_999") {
		t.Fatalf("SECURITY FAILURE: list_approvals leaked raw new_content for unrestricted token!")
	}

	_, scopedListApBody := postMCPJSONRPC(t, mcpURL, rawScoped, "", map[string]any{
		"jsonrpc": "2.0", "id": 5, "method": "tools/call",
		"params": map[string]any{"name": "list_approvals", "arguments": map[string]any{"status": "pending"}},
	})
	scopedListApText := extractMCPToolText(t, scopedListApBody)
	var scopedApResp struct {
		PendingTotal int `json:"pending_total"`
		Approvals    []any `json:"approvals"`
	}
	if err := json.Unmarshal([]byte(scopedListApText), &scopedApResp); err != nil {
		t.Fatalf("unmarshal scoped list_approvals: %v text=%s", err, scopedListApText)
	}
	if scopedApResp.PendingTotal != 1 || len(scopedApResp.Approvals) != 1 {
		t.Fatalf("expected scoped token pending_total=1 and 1 approval, got pending_total=%d len=%d", scopedApResp.PendingTotal, len(scopedApResp.Approvals))
	}

	// 3. search_memory without server_id MUST filter out srvB memories & host profile for scopedToken
	_, memBody := postMCPJSONRPC(t, mcpURL, rawScoped, "", map[string]any{
		"jsonrpc": "2.0", "id": 6, "method": "tools/call",
		"params": map[string]any{"name": "search_memory", "arguments": map[string]any{"query": ""}},
	})
	memText := extractMCPToolText(t, memBody)
	if !strings.Contains(memText, "GLOBAL_RULE_VISIBLE") || !strings.Contains(memText, "SRV_A_MEM_VISIBLE") {
		t.Fatalf("expected scoped search_memory to include global and srvA memories, got:\n%s", memText)
	}
	if strings.Contains(memText, "SRV_B_MEM_CONFIDENTIAL") || strings.Contains(memText, "SRV_B_SECRET_DB_PROFILE") {
		t.Fatalf("SECURITY FAILURE: scoped search_memory leaked srvB memory/host profile!\n%s", memText)
	}

	// 4. get_ops_context with unauthorized server_ids:[srvB] MUST error instead of falling back to all servers
	_, ctxDenyBody := postMCPJSONRPC(t, mcpURL, rawScoped, "", map[string]any{
		"jsonrpc": "2.0", "id": 7, "method": "tools/call",
		"params": map[string]any{"name": "get_ops_context", "arguments": map[string]any{"server_ids": []string{srvB.ID}}},
	})
	if !extractMCPToolIsError(t, ctxDenyBody) {
		t.Fatalf("expected get_ops_context for unauthorized srvB to return error, got: %v", ctxDenyBody)
	}

	// 5. claim_patrol and submit_patrol_report MUST reject patrol records containing out-of-scope srvB
	_, claimDenyBody := postMCPJSONRPC(t, mcpURL, rawScoped, "", map[string]any{
		"jsonrpc": "2.0", "id": 8, "method": "tools/call",
		"params": map[string]any{"name": "claim_patrol", "arguments": map[string]any{"patrol_id": patrolID}},
	})
	if !extractMCPToolIsError(t, claimDenyBody) {
		t.Fatalf("expected claim_patrol on out-of-scope patrol to be rejected, got: %v", claimDenyBody)
	}
	_, submitDenyBody := postMCPJSONRPC(t, mcpURL, rawScoped, "", map[string]any{
		"jsonrpc": "2.0", "id": 9, "method": "tools/call",
		"params": map[string]any{
			"name": "submit_patrol_report",
			"arguments": map[string]any{
				"patrol_id": patrolID,
				"summary":   "unauthorized write attempt",
			},
		},
	})
	if !extractMCPToolIsError(t, submitDenyBody) {
		t.Fatalf("expected submit_patrol_report on out-of-scope patrol to be rejected, got: %v", submitDenyBody)
	}
	recAfter, _ := store.GetPatrolRecord(patrolID)
	if recAfter.AnalysisState != "pending_external" || recAfter.AIAnalyzed {
		t.Fatalf("out-of-scope patrol was mutated despite denial! got %+v", recAfter)
	}

	// 6. sftp_read_file MUST block path traversal (/tmp/../etc/shadow) and SSH private keys
	for i, badPath := range []string{"/tmp/../etc/shadow", "/home/ops/.ssh/id_ed25519", "/opt/sns/secrets.enc"} {
		_, readDeny := postMCPJSONRPC(t, mcpURL, rawScoped, "", map[string]any{
			"jsonrpc": "2.0", "id": 10 + i, "method": "tools/call",
			"params": map[string]any{
				"name":      "sftp_read_file",
				"arguments": map[string]any{"server_id": srvA.ID, "path": badPath},
			},
		})
		if !extractMCPToolIsError(t, readDeny) {
			t.Fatalf("expected sftp_read_file to reject sensitive path %q, got: %v", badPath, readDeny)
		}
	}
}

func strPtr(s string) *string { return &s }

func startMockMCPTestSSHServer(t *testing.T, expectedUser, expectedPass string) (string, int, func()) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen host key: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == expectedUser && string(pass) == expectedPass {
				return nil, nil
			}
			return nil, errors.New("bad credentials")
		},
	}
	cfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen ssh mock: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(netConn net.Conn) {
				_, chans, reqs, err := ssh.NewServerConn(netConn, cfg)
				if err != nil {
					_ = netConn.Close()
					return
				}
				go ssh.DiscardRequests(reqs)
				for newChan := range chans {
					if newChan.ChannelType() != "session" {
						_ = newChan.Reject(ssh.UnknownChannelType, "unsupported")
						continue
					}
					ch, chReqs, err := newChan.Accept()
					if err != nil {
						continue
					}
					go func(in <-chan *ssh.Request) {
						for req := range in {
							switch req.Type {
							case "exec":
								var payload struct{ Command string }
								_ = ssh.Unmarshal(req.Payload, &payload)
								if req.WantReply {
									_ = req.Reply(true, nil)
								}
								cmdCtx, cmdCancel := context.WithCancel(context.Background())
								cmd := exec.CommandContext(cmdCtx, "/bin/sh", "-c", payload.Command)
								cmd.Stdout = ch
								cmd.Stderr = ch.Stderr()
								if err := cmd.Start(); err != nil {
									cmdCancel()
									_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: 1}))
									_ = ch.Close()
									return
								}
								waitCh := make(chan error, 1)
								go func() { waitCh <- cmd.Wait() }()
								go func() {
									for range in {
									}
									cmdCancel()
								}()
								runErr := <-waitCh
								cmdCancel()
								exitStatus := uint32(0)
								if runErr != nil {
									var exitErr *exec.ExitError
									if errors.As(runErr, &exitErr) && exitErr.ExitCode() > 0 {
										exitStatus = uint32(exitErr.ExitCode())
									} else {
										exitStatus = 1
									}
								}
								_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: exitStatus}))
								_ = ch.Close()
								return
							case "subsystem":
								var sub struct{ Name string }
								_ = ssh.Unmarshal(req.Payload, &sub)
								if sub.Name == "sftp" {
									if req.WantReply {
										_ = req.Reply(true, nil)
									}
									sftpSrv, err := sftp.NewServer(ch)
									if err == nil {
										_ = sftpSrv.Serve()
									}
									_ = ch.Close()
									return
								}
								if req.WantReply {
									_ = req.Reply(false, nil)
								}
							default:
								if req.WantReply {
									_ = req.Reply(true, nil)
								}
							}
						}
					}(chReqs)
				}
			}(conn)
		}
	}()

	tcpAddr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", tcpAddr.Port, func() { _ = ln.Close() }
}

func TestMCPBatchChangePlanSequentialExecutionAndWait(t *testing.T) {
	sshHost, sshPort, stopSSH := startMockMCPTestSSHServer(t, "ops", "MockPass!123")
	defer stopSSH()

	tmpDir := t.TempDir()
	workDir := t.TempDir()
	targetFile := filepath.Join(workDir, "app.conf")

	store, err := vault.NewStore(tmpDir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	srv := NewServer(Config{DeployMode: "server", Store: store})
	defer srv.Close()

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Setup admin vault & get session token
	setupBody, _ := json.Marshal(map[string]string{"password": "BatchPlanAdmin!2026"})
	res, err := http.Post(ts.URL+"/api/auth/setup", "application/json", bytes.NewReader(setupBody))
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("setup failed: %v %v", err, res)
	}
	var setupResp struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(res.Body).Decode(&setupResp)
	res.Body.Close()
	adminToken := setupResp.Token

	adminReq := func(method, path string, body any) (*http.Response, []byte) {
		var rdr io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rdr = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, ts.URL+path, rdr)
		req.Header.Set("Authorization", "Bearer "+adminToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, b
	}

	// Register mock SSH server
	_, srvBytes := adminReq(http.MethodPost, "/api/servers", map[string]any{
		"name":      "mock-linux-01",
		"group":     "测试环境",
		"host":      sshHost,
		"port":      sshPort,
		"username":  "ops",
		"auth_type": "password",
		"password":  "MockPass!123",
	})
	var srvResp struct {
		Server vault.ServerView `json:"server"`
	}
	_ = json.Unmarshal(srvBytes, &srvResp)
	mockSrv := srvResp.Server

	// Create ops_propose MCP token
	_, tokBytes := adminReq(http.MethodPost, "/api/ai/mcp/tokens", map[string]any{
		"name":        "Batch Plan Tester",
		"client_hint": "claude_code",
		"scope":       "ops_propose",
	})
	var tokResp struct {
		RawToken string `json:"raw_token"`
	}
	_ = json.Unmarshal(tokBytes, &tokResp)
	mcpURL := ts.URL + "/api/mcp"

	// -------------------------------------------------------------------------
	// Scenario A: Mixed SFTP (chained diff) + Blocked Step + Admin-Skipped Step + SSH Verify + wait_for_approval
	// -------------------------------------------------------------------------
	_, planABody := postMCPJSONRPC(t, mcpURL, tokResp.RawToken, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "propose_change_plan",
			"arguments": map[string]any{
				"title":  "端到端有序变更测试计划",
				"reason": "验证 SFTP 链式 Diff、拦截步骤锁定、勾选跳过与严格按序执行",
				"steps": []map[string]any{
					{
						"type":      "sftp_write_file",
						"title":     "首次写入配置",
						"server_id": mockSrv.ID,
						"path":      targetFile,
						"content":   "worker_connections 1024;\n",
					},
					{
						"type":      "sftp_write_file",
						"title":     "增量追加配置（链式 Diff）",
						"server_id": mockSrv.ID,
						"path":      targetFile,
						"content":   "worker_connections 1024;\nkeepalive_timeout 65;\n",
					},
					{
						"type":       "exec_ssh_command",
						"title":      "高危毁灭命令（应被标红锁定）",
						"server_ids": []string{mockSrv.ID},
						"command":    "rm -rf /",
					},
					{
						"type":       "exec_ssh_command",
						"title":      "管理员取消勾选的步骤",
						"server_ids": []string{mockSrv.ID},
						"command":    "echo SHOULD_NOT_EXECUTE_UNCHECKED",
					},
					{
						"type":       "exec_ssh_command",
						"title":      "顺序验证最终文件内容",
						"server_ids": []string{mockSrv.ID},
						"command":    fmt.Sprintf("cat %q && echo SEQ_VERIFIED", targetFile),
					},
				},
			},
		},
	})
	if extractMCPToolIsError(t, planABody) {
		t.Fatalf("Scenario A propose_change_plan failed: %s", extractMCPToolText(t, planABody))
	}
	var planARes struct {
		ApprovalID      string `json:"approval_id"`
		TotalSteps      int    `json:"total_steps"`
		ExecutableSteps int    `json:"executable_steps"`
		BlockedSteps    int    `json:"blocked_steps"`
		Steps           []struct {
			ID          string `json:"id"`
			Index       int    `json:"index"`
			Blocked     bool   `json:"blocked"`
			Status      string `json:"status"`
			DiffPreview string `json:"diff_preview"`
		} `json:"steps"`
	}
	_ = json.Unmarshal([]byte(extractMCPToolText(t, planABody)), &planARes)
	if planARes.TotalSteps != 5 || planARes.ExecutableSteps != 4 || planARes.BlockedSteps != 1 {
		t.Fatalf("unexpected Scenario A step counts: %+v", planARes)
	}
	if !planARes.Steps[2].Blocked || planARes.Steps[2].Status != "blocked" {
		t.Fatalf("expected step 3 to be blocked, got %+v", planARes.Steps[2])
	}
	// Verify chained diff on step 2 diffs against step 1 (so line1 is context, only keepalive_timeout is added)
	if !strings.Contains(planARes.Steps[1].DiffPreview, " worker_connections 1024;") ||
		!strings.Contains(planARes.Steps[1].DiffPreview, "+keepalive_timeout 65;") {
		t.Fatalf("expected step 2 chained diff against step 1, got:\n%s", planARes.Steps[1].DiffPreview)
	}

	// Launch concurrent wait_for_approval BEFORE admin approves
	waitDone := make(chan map[string]any, 1)
	go func() {
		_, body := postMCPJSONRPC(t, mcpURL, tokResp.RawToken, "", map[string]any{
			"jsonrpc": "2.0",
			"id":      2,
			"method":  "tools/call",
			"params": map[string]any{
				"name": "wait_for_approval",
				"arguments": map[string]any{
					"approval_id": planARes.ApprovalID,
					"timeout_sec": 15,
				},
			},
		})
		waitDone <- body
	}()
	time.Sleep(80 * time.Millisecond)

	// Admin approves Steps 1, 2, 5 (intentionally also passing blocked Step 3 to verify backend refuses it, omitting Step 4)
	resolveResp, resolveBytes := adminReq(http.MethodPost, "/api/ai/external-approvals/"+planARes.ApprovalID+"/resolve", map[string]any{
		"approve":           true,
		"selected_step_ids": []string{planARes.Steps[0].ID, planARes.Steps[1].ID, planARes.Steps[2].ID, planARes.Steps[4].ID},
	})
	if resolveResp.StatusCode != http.StatusOK {
		t.Fatalf("Scenario A resolve failed: %d %s", resolveResp.StatusCode, string(resolveBytes))
	}

	// Receive wait_for_approval completion
	waitBody := <-waitDone
	if extractMCPToolIsError(t, waitBody) {
		t.Fatalf("wait_for_approval returned error: %s", extractMCPToolText(t, waitBody))
	}
	var waitOut struct {
		OK       bool                   `json:"ok"`
		TimedOut bool                   `json:"timed_out"`
		Terminal bool                   `json:"terminal"`
		Approval vault.ExternalApproval `json:"approval"`
	}
	if err := json.Unmarshal([]byte(extractMCPToolText(t, waitBody)), &waitOut); err != nil {
		t.Fatalf("unmarshal wait_for_approval: %v", err)
	}
	if waitOut.TimedOut || !waitOut.Terminal || waitOut.Approval.Status != "completed" {
		t.Fatalf("expected Scenario A completed via wait_for_approval, got: %+v", waitOut)
	}
	if waitOut.Approval.Steps[0].Status != "succeeded" ||
		waitOut.Approval.Steps[1].Status != "succeeded" ||
		waitOut.Approval.Steps[2].Status != "blocked" ||
		waitOut.Approval.Steps[3].Status != "skipped" ||
		waitOut.Approval.Steps[4].Status != "succeeded" {
		t.Fatalf("unexpected Scenario A per-step statuses: %+v", waitOut.Approval.Steps)
	}
	if !strings.Contains(waitOut.Approval.Steps[4].ExecutionOut, "keepalive_timeout 65;") ||
		!strings.Contains(waitOut.Approval.Steps[4].ExecutionOut, "SEQ_VERIFIED") {
		t.Fatalf("expected step 5 to observe step 1 & 2 SFTP writes in order, got:\n%s", waitOut.Approval.Steps[4].ExecutionOut)
	}
	rawDisk, err := os.ReadFile(targetFile)
	if err != nil || string(rawDisk) != "worker_connections 1024;\nkeepalive_timeout 65;\n" {
		t.Fatalf("unexpected targetFile content on disk: err=%v content=%q", err, string(rawDisk))
	}
	// Verify consolidated change memory recorded once for the plan
	memories, _ := store.ListAIMemories()
	foundPlanMem := false
	for _, m := range memories {
		if m.Category == "change" && m.Source == "approval" && strings.Contains(m.Title, "端到端有序变更测试计划") {
			foundPlanMem = true
			break
		}
	}
	if !foundPlanMem {
		t.Fatalf("expected consolidated approved-change memory for plan, got: %+v", memories)
	}

	// -------------------------------------------------------------------------
	// Scenario B: continue_on_error=true vs Default Fail-Fast
	// -------------------------------------------------------------------------
	_, planBBody := postMCPJSONRPC(t, mcpURL, tokResp.RawToken, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      3,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "propose_change_plan",
			"arguments": map[string]any{
				"title":  "遇错策略验证计划",
				"reason": "测试 continue_on_error 与默认 fail-fast",
				"steps": []map[string]any{
					{"type": "exec_ssh_command", "server_id": mockSrv.ID, "command": "exit 2", "continue_on_error": true},
					{"type": "exec_ssh_command", "server_id": mockSrv.ID, "command": "echo STEP2_RAN"},
					{"type": "exec_ssh_command", "server_id": mockSrv.ID, "command": "exit 3"},
					{"type": "exec_ssh_command", "server_id": mockSrv.ID, "command": "echo STEP4_MUST_SKIP"},
				},
			},
		},
	})
	var planBRes struct {
		ApprovalID string `json:"approval_id"`
	}
	_ = json.Unmarshal([]byte(extractMCPToolText(t, planBBody)), &planBRes)

	rB, _ := adminReq(http.MethodPost, "/api/ai/external-approvals/"+planBRes.ApprovalID+"/resolve", map[string]any{"approve": true})
	if rB.StatusCode != http.StatusOK {
		t.Fatalf("Scenario B resolve failed: %d", rB.StatusCode)
	}
	_, waitBBody := postMCPJSONRPC(t, mcpURL, tokResp.RawToken, "", map[string]any{
		"jsonrpc": "2.0", "id": 4, "method": "tools/call",
		"params": map[string]any{"name": "wait_for_approval", "arguments": map[string]any{"approval_id": planBRes.ApprovalID, "timeout_sec": 15}},
	})
	var waitBOut struct {
		Approval vault.ExternalApproval `json:"approval"`
	}
	_ = json.Unmarshal([]byte(extractMCPToolText(t, waitBBody)), &waitBOut)
	if waitBOut.Approval.Status != "partial_failed" ||
		waitBOut.Approval.Steps[0].Status != "failed" ||
		waitBOut.Approval.Steps[1].Status != "succeeded" ||
		waitBOut.Approval.Steps[2].Status != "failed" ||
		waitBOut.Approval.Steps[3].Status != "skipped" {
		t.Fatalf("unexpected Scenario B outcome: status=%s steps=%+v", waitBOut.Approval.Status, waitBOut.Approval.Steps)
	}

	// -------------------------------------------------------------------------
	// Scenario C: Mid-execution Cancel
	// -------------------------------------------------------------------------
	_, planCBody := postMCPJSONRPC(t, mcpURL, tokResp.RawToken, "", map[string]any{
		"jsonrpc": "2.0", "id": 5, "method": "tools/call",
		"params": map[string]any{
			"name": "propose_change_plan",
			"arguments": map[string]any{
				"title":  "中途取消验证计划",
				"reason": "测试执行中点击中止",
				"steps": []map[string]any{
					{"type": "exec_ssh_command", "server_id": mockSrv.ID, "command": "sleep 6"},
					{"type": "exec_ssh_command", "server_id": mockSrv.ID, "command": "echo NEVER_RUN"},
				},
			},
		},
	})
	var planCRes struct {
		ApprovalID string `json:"approval_id"`
	}
	_ = json.Unmarshal([]byte(extractMCPToolText(t, planCBody)), &planCRes)

	rC, _ := adminReq(http.MethodPost, "/api/ai/external-approvals/"+planCRes.ApprovalID+"/resolve", map[string]any{"approve": true})
	if rC.StatusCode != http.StatusOK {
		t.Fatalf("Scenario C resolve failed: %d", rC.StatusCode)
	}
	time.Sleep(150 * time.Millisecond)
	cancelStart := time.Now()
	cResp, cBytes := adminReq(http.MethodPost, "/api/ai/external-approvals/"+planCRes.ApprovalID+"/cancel", map[string]any{})
	if cResp.StatusCode != http.StatusOK {
		t.Fatalf("Scenario C cancel failed: %d %s", cResp.StatusCode, string(cBytes))
	}
	_, waitCBody := postMCPJSONRPC(t, mcpURL, tokResp.RawToken, "", map[string]any{
		"jsonrpc": "2.0", "id": 6, "method": "tools/call",
		"params": map[string]any{"name": "wait_for_approval", "arguments": map[string]any{"approval_id": planCRes.ApprovalID, "timeout_sec": 5}},
	})
	var waitCOut struct {
		Terminal bool                   `json:"terminal"`
		Approval vault.ExternalApproval `json:"approval"`
	}
	_ = json.Unmarshal([]byte(extractMCPToolText(t, waitCBody)), &waitCOut)
	if !waitCOut.Terminal || waitCOut.Approval.Status != "cancelled" || time.Since(cancelStart) > 4*time.Second {
		t.Fatalf("expected prompt cancellation, got terminal=%v status=%s elapsed=%v steps=%+v",
			waitCOut.Terminal, waitCOut.Approval.Status, time.Since(cancelStart), waitCOut.Approval.Steps)
	}
	if waitCOut.Approval.Steps[1].Status != "cancelled" {
		t.Fatalf("expected step 2 to be cancelled, got %+v", waitCOut.Approval.Steps[1])
	}

	// -------------------------------------------------------------------------
	// Scenario D: wait_for_approval timeout + legacy single-step migration + restart recovery
	// -------------------------------------------------------------------------
	_, planDBody := postMCPJSONRPC(t, mcpURL, tokResp.RawToken, "", map[string]any{
		"jsonrpc": "2.0", "id": 7, "method": "tools/call",
		"params": map[string]any{
			"name": "propose_change_plan",
			"arguments": map[string]any{
				"title":  "等待超时测试",
				"reason": "测试 wait_for_approval 超时返回",
				"steps": []map[string]any{
					{"type": "exec_ssh_command", "server_id": mockSrv.ID, "command": "echo hello"},
				},
			},
		},
	})
	var planDRes struct {
		ApprovalID string `json:"approval_id"`
	}
	_ = json.Unmarshal([]byte(extractMCPToolText(t, planDBody)), &planDRes)

	_, waitDTimeout := postMCPJSONRPC(t, mcpURL, tokResp.RawToken, "", map[string]any{
		"jsonrpc": "2.0", "id": 8, "method": "tools/call",
		"params": map[string]any{"name": "wait_for_approval", "arguments": map[string]any{"approval_id": planDRes.ApprovalID, "timeout_sec": 1}},
	})
	if extractMCPToolIsError(t, waitDTimeout) {
		t.Fatalf("expected wait_for_approval timeout to return non-error snapshot, got: %s", extractMCPToolText(t, waitDTimeout))
	}
	var waitDOut struct {
		TimedOut bool                   `json:"timed_out"`
		Terminal bool                   `json:"terminal"`
		Approval vault.ExternalApproval `json:"approval"`
	}
	_ = json.Unmarshal([]byte(extractMCPToolText(t, waitDTimeout)), &waitDOut)
	if !waitDOut.TimedOut || waitDOut.Terminal || waitDOut.Approval.Status != "pending" {
		t.Fatalf("expected timed_out=true terminal=false status=pending, got %+v", waitDOut)
	}

	// Verify legacy flat ExternalApproval normalization
	legacy := vault.ExternalApproval{
		ID:          "legacy-ap-001",
		ToolName:    "exec_ssh_command",
		ServerIDs:   []string{mockSrv.ID},
		ServerNames: []string{mockSrv.Name},
		Command:     "systemctl reload nginx",
		Reason:      "legacy reload",
		Status:      "approved",
		ExecutionOut: "ok",
	}
	vault.NormalizeExternalApproval(&legacy)
	if legacy.Status != "completed" || len(legacy.Steps) != 1 || legacy.Steps[0].Status != "succeeded" || legacy.TotalSteps != 1 {
		t.Fatalf("unexpected legacy normalization: %+v", legacy)
	}

	// Verify daemon restart recovery of orphaned running plan
	orphaned, err := store.CreateExternalApproval(vault.ExternalApproval{
		ID:         "orphan-run-001",
		Title:      "重启恢复测试",
		ClientName: "Claude Code",
		Reason:     "simulate crash",
		Steps: []vault.ExternalApprovalStep{
			{ID: "s1", Index: 1, ToolName: "exec_ssh_command", ServerIDs: []string{mockSrv.ID}, ServerNames: []string{mockSrv.Name}, Command: "echo 1", Selected: true, Status: "succeeded"},
			{ID: "s2", Index: 2, ToolName: "exec_ssh_command", ServerIDs: []string{mockSrv.ID}, ServerNames: []string{mockSrv.Name}, Command: "sleep 10", Selected: true, Status: "running"},
			{ID: "s3", Index: 3, ToolName: "exec_ssh_command", ServerIDs: []string{mockSrv.ID}, ServerNames: []string{mockSrv.Name}, Command: "echo 3", Selected: true, Status: "pending"},
		},
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("CreateExternalApproval orphan: %v", err)
	}
	orphaned.Status = "running"
	orphaned.Steps[0].Status = "succeeded"
	orphaned.Steps[1].Status = "running"
	orphaned.Steps[2].Status = "pending"
	if err := store.UpdateExternalApproval(*orphaned); err != nil {
		t.Fatalf("UpdateExternalApproval orphan: %v", err)
	}
	if err := store.FlushNow(); err != nil {
		t.Fatalf("FlushNow: %v", err)
	}

	reopened, err := vault.NewStore(tmpDir)
	if err != nil {
		t.Fatalf("reopen vault.NewStore: %v", err)
	}
	defer reopened.Close()
	recOrphan, err := reopened.GetExternalApproval("orphan-run-001")
	if err != nil {
		t.Fatalf("GetExternalApproval after reopen: %v", err)
	}
	if recOrphan.Status != "partial_failed" ||
		recOrphan.Steps[0].Status != "succeeded" ||
		recOrphan.Steps[1].Status != "failed" ||
		recOrphan.Steps[2].Status != "cancelled" {
		t.Fatalf("expected restart recovery partial_failed (succeeded/failed/cancelled), got status=%s steps=%+v", recOrphan.Status, recOrphan.Steps)
	}
}

func TestUnifiedExecutionApprovalCenterAPIAndBootstrapDecoupling(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := vault.NewStore(tmpDir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	srv := NewServer(Config{DeployMode: "server", Store: store})
	defer srv.Close()

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Setup vault & obtain admin token
	setupBody, _ := json.Marshal(map[string]string{"password": "ApprovalCenterAdmin!2026"})
	res, err := http.Post(ts.URL+"/api/auth/setup", "application/json", bytes.NewReader(setupBody))
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("setup failed: %v %v", err, res)
	}
	var setupResp struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(res.Body).Decode(&setupResp)
	res.Body.Close()
	adminToken := setupResp.Token

	// Unauthenticated request to /api/ai/approvals MUST be rejected with 401
	unauthResp, err := http.Get(ts.URL + "/api/ai/approvals")
	if err != nil {
		t.Fatalf("unauth GET /api/ai/approvals: %v", err)
	}
	unauthResp.Body.Close()
	if unauthResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated /api/ai/approvals, got %d", unauthResp.StatusCode)
	}

	adminGet := func(path string) (*http.Response, []byte) {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+adminToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, b
	}

	// Seed 1 unread patrol record
	now := time.Now().UTC()
	if err := store.AppendPatrolRecord(vault.PatrolRecord{
		ID:           "patrol-unread-01",
		StartedAt:    now,
		CompletedAt:  now,
		Trigger:      "scheduled",
		TotalServers: 1,
		WarningCount: 1,
		Status:       "warning",
		Unread:       true,
	}); err != nil {
		t.Fatalf("AppendPatrolRecord: %v", err)
	}

	// Seed 1 pending MCP external approval + 1 completed MCP external approval
	if _, err := store.CreateExternalApproval(vault.ExternalApproval{
		ID:         "ext-ap-pending",
		Title:      "重启 Nginx 服务",
		ClientName: "Claude Code",
		TokenName:  "MacBook",
		Reason:     "应用新配置",
		Status:     "pending",
		Steps: []vault.ExternalApprovalStep{
			{
				ID:          "st-1",
				Index:       1,
				ToolName:    "exec_ssh_command",
				ServerIDs:   []string{"srv-1"},
				ServerNames: []string{"prod-web-01"},
				Command:     "systemctl reload nginx",
				Selected:    true,
				Status:      "pending",
			},
		},
		CreatedAt: now,
	}, "127.0.0.1"); err != nil {
		t.Fatalf("CreateExternalApproval pending: %v", err)
	}
	doneAt := now.Add(-10 * time.Minute)
	doneAp, err := store.CreateExternalApproval(vault.ExternalApproval{
		ID:         "ext-ap-done",
		Title:      "清理旧日志",
		ClientName: "Codex",
		TokenName:  "CI",
		Reason:     "释放磁盘空间",
		Status:     "completed",
		Steps: []vault.ExternalApprovalStep{
			{
				ID:          "st-done-1",
				Index:       1,
				ToolName:    "exec_ssh_command",
				ServerIDs:   []string{"srv-1"},
				ServerNames: []string{"prod-web-01"},
				Command:     "journalctl --vacuum-time=7d",
				Selected:    true,
				Status:      "succeeded",
			},
		},
		CreatedAt:  doneAt,
		ResolvedAt: &doneAt,
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("CreateExternalApproval done: %v", err)
	}
	doneAp.Status = "completed"
	doneAp.Steps[0].Status = "succeeded"
	doneAp.ResolvedAt = &doneAt
	if err := store.UpdateExternalApproval(*doneAp); err != nil {
		t.Fatalf("UpdateExternalApproval done: %v", err)
	}

	// Seed built-in AI sessions (center + terminal) with pending and historical approvals
	centerSess, err := store.CreateAISession("线上高负载排障", "center", []string{"srv-1"}, vault.AIModeStandard)
	if err != nil {
		t.Fatalf("CreateAISession center: %v", err)
	}
	centerSess.PendingApprovals = []vault.AIPendingApproval{
		{
			ID:          "sess-ap-center-pending",
			SessionID:   centerSess.ID,
			ToolCallID:  "tc-1",
			ToolName:    "exec_ssh_command",
			ServerIDs:   []string{"srv-1"},
			ServerNames: []string{"prod-web-01"},
			RiskLevel:   "high",
			Reason:      "重启异常 worker 进程",
			Command:     "systemctl restart worker",
			Status:      "pending",
			CreatedAt:   now.Add(-2 * time.Minute),
		},
		{
			ID:          "sess-ap-center-approved",
			SessionID:   centerSess.ID,
			ToolCallID:  "tc-2",
			ToolName:    "sftp_write_file",
			ServerIDs:   []string{"srv-1"},
			ServerNames: []string{"prod-web-01"},
			RiskLevel:   "medium",
			Reason:      "调整连接超时",
			FilePath:    "/etc/nginx/nginx.conf",
			Status:      "approved",
			CreatedAt:   now.Add(-20 * time.Minute),
			ResolvedAt:  &doneAt,
		},
	}
	if err := store.SaveAISession(*centerSess); err != nil {
		t.Fatalf("SaveAISession center: %v", err)
	}

	termSess, err := store.CreateAISession("终端副驾驶 · prod-web-01", "terminal", []string{"srv-1"}, vault.AIModeStandard)
	if err != nil {
		t.Fatalf("CreateAISession terminal: %v", err)
	}
	termSess.PendingApprovals = []vault.AIPendingApproval{
		{
			ID:          "sess-ap-term-pending",
			SessionID:   termSess.ID,
			ToolCallID:  "tc-3",
			ToolName:    "exec_ssh_command",
			ServerIDs:   []string{"srv-1"},
			ServerNames: []string{"prod-web-01"},
			RiskLevel:   "high",
			Reason:      "重载防火墙规则",
			Command:     "ufw reload",
			Status:      "pending",
			CreatedAt:   now.Add(-1 * time.Minute),
		},
	}
	if err := store.SaveAISession(*termSess); err != nil {
		t.Fatalf("SaveAISession terminal: %v", err)
	}

	// 1. Verify /api/workspace/bootstrap decouples patrol_unread from pending approvals
	bootResp, bootBytes := adminGet("/api/workspace/bootstrap")
	if bootResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/workspace/bootstrap failed: %d %s", bootResp.StatusCode, string(bootBytes))
	}
	var boot struct {
		PatrolUnread             int `json:"patrol_unread"`
		PendingExternalApprovals int `json:"pending_external_approvals"`
		RunningExternalApprovals int `json:"running_external_approvals"`
		PendingSessionApprovals  int `json:"pending_session_approvals"`
		PendingApprovalsTotal    int `json:"pending_approvals_total"`
	}
	if err := json.Unmarshal(bootBytes, &boot); err != nil {
		t.Fatalf("unmarshal bootstrap: %v", err)
	}
	if boot.PatrolUnread != 1 {
		t.Fatalf("expected patrol_unread=1 (decoupled from approvals), got %d", boot.PatrolUnread)
	}
	if boot.PendingExternalApprovals != 1 || boot.RunningExternalApprovals != 0 ||
		boot.PendingSessionApprovals != 2 || boot.PendingApprovalsTotal != 3 {
		t.Fatalf("unexpected bootstrap approval counts: %+v", boot)
	}

	// 2. Verify GET /api/ai/approvals returns unified MCP + built-in session approvals (pending & history)
	apResp, apBytes := adminGet("/api/ai/approvals?limit=50")
	if apResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/ai/approvals failed: %d %s", apResp.StatusCode, string(apBytes))
	}
	var unified struct {
		ExternalApprovals    []vault.ExternalApproval    `json:"external_approvals"`
		SessionApprovals     []vault.SessionApprovalItem `json:"session_approvals"`
		PendingExternalCount int                         `json:"pending_external_count"`
		RunningExternalCount int                         `json:"running_external_count"`
		PendingSessionCount  int                         `json:"pending_session_count"`
		PendingTotal         int                         `json:"pending_total"`
	}
	if err := json.Unmarshal(apBytes, &unified); err != nil {
		t.Fatalf("unmarshal unified approvals: %v", err)
	}
	if len(unified.ExternalApprovals) != 2 || len(unified.SessionApprovals) != 3 {
		t.Fatalf("expected 2 external and 3 session approvals, got ext=%d sess=%d",
			len(unified.ExternalApprovals), len(unified.SessionApprovals))
	}
	if unified.PendingExternalCount != 1 || unified.PendingSessionCount != 2 || unified.PendingTotal != 3 {
		t.Fatalf("unexpected unified pending counts: %+v", unified)
	}
	// Pending session approvals MUST sort before historical resolved ones, newest first
	if unified.SessionApprovals[0].ID != "sess-ap-term-pending" ||
		unified.SessionApprovals[0].SessionScope != "terminal" ||
		unified.SessionApprovals[1].ID != "sess-ap-center-pending" ||
		unified.SessionApprovals[1].SessionScope != "center" ||
		unified.SessionApprovals[2].ID != "sess-ap-center-approved" {
		t.Fatalf("unexpected session approvals ordering/metadata: %+v", unified.SessionApprovals)
	}

	// 3. Verify GET /api/ai/approvals?summary_only=1 returns lightweight counts only
	sumResp, sumBytes := adminGet("/api/ai/approvals?summary_only=1")
	if sumResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/ai/approvals?summary_only=1 failed: %d %s", sumResp.StatusCode, string(sumBytes))
	}
	var sumRaw map[string]any
	if err := json.Unmarshal(sumBytes, &sumRaw); err != nil {
		t.Fatalf("unmarshal summary_only: %v", err)
	}
	if _, hasFullExt := sumRaw["external_approvals"]; hasFullExt {
		t.Fatalf("summary_only response should not include external_approvals array")
	}
	if int(sumRaw["pending_total"].(float64)) != 3 || int(sumRaw["patrol_unread"].(float64)) != 1 {
		t.Fatalf("unexpected summary_only counts: %v", sumRaw)
	}

	// 4. Verify SKILL.md guidance points to standalone 「执行审批」
	ovResp, ovBytes := adminGet("/api/ai/mcp/overview")
	if ovResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/ai/mcp/overview failed: %d", ovResp.StatusCode)
	}
	var mcpOv struct {
		SkillMarkdown string `json:"skill_markdown"`
	}
	_ = json.Unmarshal(ovBytes, &mcpOv)
	if !strings.Contains(mcpOv.SkillMarkdown, "左侧「执行审批」") {
		t.Fatalf("expected SKILL.md to point to 左侧「执行审批」, got:\n%s", mcpOv.SkillMarkdown)
	}
}

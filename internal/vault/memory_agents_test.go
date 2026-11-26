package vault

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRedactSensitiveText(t *testing.T) {
	input := strings.Join([]string{
		"正常运维记录：Nginx 监听 80/443，上游端口 8080。",
		"-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAB3NzaC1yc2EAAAADAQAB\n-----END OPENSSH PRIVATE KEY-----",
		"Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig",
		"OpenAI key sk-proj-1234567890abcdef1234567890abcdef",
		"Anthropic key sk-ant-api03-1234567890abcdef1234567890",
		"DB_URL password='SuperSecretDBPass99!' and api_key=my_secret_token_value",
	}, "\n")

	redacted := RedactSensitiveText(input)

	for _, leaked := range []string{
		"AAAAB3NzaC1yc2EAAAADAQAB",
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
		"sk-proj-1234567890abcdef",
		"sk-ant-api03-1234567890abcdef",
		"SuperSecretDBPass99!",
		"my_secret_token_value",
	} {
		if strings.Contains(redacted, leaked) {
			t.Fatalf("expected secret %q to be redacted, got:\n%s", leaked, redacted)
		}
	}
	if !strings.Contains(redacted, "Nginx 监听 80/443") {
		t.Fatalf("expected normal SRE text to be preserved, got:\n%s", redacted)
	}
	if !strings.Contains(redacted, "[REDACTED_PRIVATE_KEY]") ||
		!strings.Contains(redacted, "[REDACTED_TOKEN]") ||
		!strings.Contains(redacted, "[REDACTED_API_KEY]") ||
		!strings.Contains(redacted, "[REDACTED]") {
		t.Fatalf("expected redaction placeholders in output:\n%s", redacted)
	}
}

func TestLegacyVaultUpgradeAndAgentsMDGovernance(t *testing.T) {
	// 1. Legacy state with uninitialized AgentsMD & MemoryConfig gets defaults
	legacy := &VaultState{}
	EnsureStateDefaults(legacy)
	if !legacy.AISettings.AgentsMD.Initialized || !legacy.AISettings.AgentsMD.Enabled || legacy.AISettings.AgentsMD.Content == "" {
		t.Fatalf("expected legacy state to initialize default AGENTS.md, got %+v", legacy.AISettings.AgentsMD)
	}
	if !legacy.AISettings.MemoryConfig.Initialized || legacy.AISettings.MemoryConfig.AgentsMDMaxChars <= 0 {
		t.Fatalf("expected legacy state to initialize default MemoryConfig, got %+v", legacy.AISettings.MemoryConfig)
	}

	// 2. User intentionally disables AgentsMD & clears content -> EnsureStateDefaults MUST NOT clobber it
	legacy.AISettings.AgentsMD.Enabled = false
	legacy.AISettings.AgentsMD.Content = ""
	EnsureStateDefaults(legacy)
	if legacy.AISettings.AgentsMD.Enabled || legacy.AISettings.AgentsMD.Content != "" {
		t.Fatalf("EnsureStateDefaults clobbered intentional user-disabled AgentsMD: %+v", legacy.AISettings.AgentsMD)
	}

	// 3. End-to-end store persistence, revisioning, reset template, and proposal accept/dismiss
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()
	if err := store.Setup("StrongMasterPass!2026", "127.0.0.1"); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	initial, err := store.GetAgentsMD()
	if err != nil || !initial.Enabled || !strings.Contains(initial.Content, "ServerNeedSafe") {
		t.Fatalf("unexpected initial AGENTS.md: %+v err=%v", initial, err)
	}

	updated, err := store.UpdateAgentsMD(true, "# 生产规范\n- 严禁未经批准重启 Postgres\n- 附带敏感词测试 password=TopSecretValue88", false, "127.0.0.1")
	if err != nil {
		t.Fatalf("UpdateAgentsMD: %v", err)
	}
	if updated.Revision != initial.Revision+1 {
		t.Fatalf("expected revision %d, got %d", initial.Revision+1, updated.Revision)
	}
	if strings.Contains(updated.Content, "TopSecretValue88") {
		t.Fatalf("expected secret redaction in AGENTS.md update, got: %s", updated.Content)
	}

	// Create session with two pending AGENTS.md proposals
	sess, err := store.CreateAISession("规范修订测试", "center", nil, AIModeStandard)
	if err != nil {
		t.Fatalf("CreateAISession: %v", err)
	}
	sess.AgentsMDProposals = []AIAgentsMDProposal{
		{
			ID:              "prop-dismiss",
			SessionID:       sess.ID,
			Summary:         "会被驳回的修订",
			Reason:          "测试驳回路径",
			ProposedContent: "# 不应合入的内容",
			DiffPreview:     "--- a/AGENTS.md\n+++ b/AGENTS.md\n",
			Status:          "pending",
			CreatedAt:       time.Now().UTC(),
		},
		{
			ID:              "prop-accept",
			SessionID:       sess.ID,
			Summary:         "补充零停机 reload 约束",
			Reason:          "避免高峰期 Nginx 502",
			ProposedContent: "# 生产规范\n- 变更 Nginx 前必须先执行 nginx -t 并使用 reload 而非 restart",
			DiffPreview:     "--- a/AGENTS.md\n+++ b/AGENTS.md\n",
			Status:          "pending",
			CreatedAt:       time.Now().UTC(),
		},
	}
	if err := store.SaveAISession(*sess); err != nil {
		t.Fatalf("SaveAISession: %v", err)
	}

	// Dismiss first proposal -> AGENTS.md unchanged
	cfgAfterDismiss, propDismiss, err := store.ResolveAgentsMDProposal("prop-dismiss", false, "127.0.0.1")
	if err != nil {
		t.Fatalf("ResolveAgentsMDProposal dismiss: %v", err)
	}
	if propDismiss.Status != "dismissed" || cfgAfterDismiss.Revision != updated.Revision {
		t.Fatalf("unexpected dismiss result: prop=%+v cfg=%+v", propDismiss, cfgAfterDismiss)
	}

	// Accept second proposal -> AGENTS.md merged & revision incremented
	cfgAfterAccept, propAccept, err := store.ResolveAgentsMDProposal("prop-accept", true, "127.0.0.1")
	if err != nil {
		t.Fatalf("ResolveAgentsMDProposal accept: %v", err)
	}
	if propAccept.Status != "accepted" || cfgAfterAccept.Revision != updated.Revision+1 || !strings.Contains(cfgAfterAccept.Content, "nginx -t") {
		t.Fatalf("unexpected accept result: prop=%+v cfg=%+v", propAccept, cfgAfterAccept)
	}

	// Reset to built-in template
	resetCfg, err := store.UpdateAgentsMD(false, "", true, "127.0.0.1")
	if err != nil {
		t.Fatalf("reset AGENTS.md: %v", err)
	}
	if !resetCfg.Enabled || resetCfg.Content != DefaultAgentsMDTemplate() || resetCfg.Revision != cfgAfterAccept.Revision+1 {
		t.Fatalf("unexpected reset AGENTS.md: %+v", resetCfg)
	}
}

func TestAIMemoryCRUDDedupMonitorSyncAndZeroPlaintext(t *testing.T) {
	dataDir := t.TempDir()
	store, err := NewStore(dataDir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()
	if err := store.Setup("StrongMasterPass!2026", "127.0.0.1"); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	srv, err := store.CreateServer(ServerMutationInput{
		Name:     "db-postgres-01",
		Group:    "核心库",
		Host:     "10.10.2.20",
		Port:     22,
		Username: "root",
		AuthType: AuthPassword,
		Password: strPtr("PgSshSecret#2026"),
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("CreateServer: %v", err)
	}

	// 1. Seed human-authored HostMemory with Constraints & Notes
	hm, err := store.UpsertHostMemory(HostMemory{
		ServerID:    srv.ID,
		ServerName:  srv.Name,
		Summary:     "核心账务 PostgreSQL 主库（人工维护）",
		OSArch:      "Ubuntu 22.04",
		KeyServices: []string{"postgresql"},
		DeployPaths: []string{"/var/lib/postgresql/16/main"},
		Constraints: "绝对禁止在工作日 09:00-21:00 重启数据库或执行 VACUUM FULL",
		Notes:       "备库位于 10.10.2.21，流复制延迟阈值 50MB",
	}, false, "127.0.0.1")
	if err != nil || hm.Constraints == "" || hm.Notes == "" {
		t.Fatalf("UpsertHostMemory: %+v err=%v", hm, err)
	}

	// 2. Record 7x24 monitor snapshot -> auto incremental sync updates OSArch/KeyServices/PortsNote
	// while strictly preserving human-authored Summary, Constraints, and Notes!
	snap := &ServerMonitorSnapshot{
		ServerID:    srv.ID,
		ServerName:  srv.Name,
		CollectedAt: time.Now().UTC(),
		Reachable:   true,
		HealthLevel: "healthy",
		HealthScore: 95,
		OS:          "Ubuntu 24.04.1 LTS",
		Kernel:      "6.8.0-49-generic",
		Arch:        "x86_64",
		Services: []ServiceStat{
			{Name: "postgresql.service", State: "active", Watched: true},
			{Name: "pgbouncer.service", State: "active", Watched: true},
		},
		ListeningPorts: []ListeningPortStat{
			{Port: 5432, Proto: "tcp", Process: "postgres", PublicExposed: false},
			{Port: 6432, Proto: "tcp", Process: "pgbouncer", PublicExposed: false},
		},
	}
	if _, _, _, err := store.RecordMonitorSnapshots([]*ServerMonitorSnapshot{snap}); err != nil {
		t.Fatalf("RecordMonitorSnapshots: %v", err)
	}

	memories, err := store.ListHostMemories()
	if err != nil || len(memories) != 1 {
		t.Fatalf("ListHostMemories: len=%d err=%v", len(memories), err)
	}
	gotHM := memories[0]
	if gotHM.Summary != "核心账务 PostgreSQL 主库（人工维护）" {
		t.Fatalf("monitor sync overwrote human Summary: %q", gotHM.Summary)
	}
	if gotHM.Constraints != "绝对禁止在工作日 09:00-21:00 重启数据库或执行 VACUUM FULL" {
		t.Fatalf("monitor sync overwrote human Constraints: %q", gotHM.Constraints)
	}
	if gotHM.Notes != "备库位于 10.10.2.21，流复制延迟阈值 50MB" {
		t.Fatalf("monitor sync overwrote human Notes: %q", gotHM.Notes)
	}
	if !strings.Contains(gotHM.OSArch, "Ubuntu 24.04.1 LTS") || !strings.Contains(gotHM.PortsNote, "5432") || gotHM.MonitorSyncedAt == nil {
		t.Fatalf("expected objective fields synced from monitor snapshot, got: %+v", gotHM)
	}

	// Verify manual SyncHostMemoriesFromMonitor works cleanly
	_, _, err = store.SyncHostMemoriesFromMonitor(srv.ID, "127.0.0.1")
	if err != nil {
		t.Fatalf("SyncHostMemoriesFromMonitor: %v", err)
	}

	// 3. Long-term memory CRUD, auto dedup, secret redaction, and usage tracking
	m1, err := store.UpsertAIMemory(AIMemoryEntry{
		Scope:      "server",
		ServerIDs:  []string{srv.ID},
		Category:   "incident",
		Title:      "连接池打满根因",
		Content:    "pgbouncer max_client_conn 偏小导致突发超时，临时凭证 sk-proj-shouldneverbeleaked123456 必须脱敏。",
		Tags:       []string{"pgbouncer", "incident"},
		Pinned:     true,
		Importance: 5,
		Source:     "ai",
	}, true, "127.0.0.1")
	if err != nil {
		t.Fatalf("UpsertAIMemory m1: %v", err)
	}
	if strings.Contains(m1.Content, "sk-proj-shouldneverbeleaked123456") {
		t.Fatalf("expected secret redaction in AIMemoryEntry, got: %s", m1.Content)
	}

	// Auto-dedup with same scope/category/title/server_ids updates in-place instead of duplicating
	m1Dup, err := store.UpsertAIMemory(AIMemoryEntry{
		Scope:      "server",
		ServerIDs:  []string{srv.ID},
		Category:   "incident",
		Title:      "连接池打满根因",
		Content:    "已将 pgbouncer max_client_conn 提升至 2000，default_pool_size=80，故障彻底缓解。",
		Tags:       []string{"resolved"},
		Importance: 4,
		Source:     "ai",
	}, true, "127.0.0.1")
	if err != nil {
		t.Fatalf("UpsertAIMemory dedup: %v", err)
	}
	if m1Dup.ID != m1.ID || !m1Dup.Pinned || m1Dup.Importance != 5 || len(m1Dup.Tags) != 3 {
		t.Fatalf("expected in-place dedup preserving Pinned=true & max Importance=5 & merged tags, got %+v", m1Dup)
	}

	store.TouchAIMemoryUsage([]string{m1.ID})
	listed, err := store.ListAIMemories()
	if err != nil || len(listed) != 1 || listed[0].UseCount != 1 {
		t.Fatalf("expected 1 memory with UseCount=1, got %+v err=%v", listed, err)
	}

	// 4. Verify secrets.enc encrypts SSH password & AGENTS.md, and aiops_runtime.json never leaks secrets
	if err := store.FlushNow(); err != nil {
		t.Fatalf("FlushNow: %v", err)
	}
	rawDisk, err := os.ReadFile(store.SecretsPath())
	if err != nil {
		t.Fatalf("ReadFile secrets.enc: %v", err)
	}
	for _, secretText := range []string{
		"PgSshSecret#2026",
		"db-postgres-01",
	} {
		if bytes.Contains(rawDisk, []byte(secretText)) {
			t.Fatalf("SECURITY FAILURE: raw secrets.enc leaked plaintext %q", secretText)
		}
	}
	rawRT, err := os.ReadFile(filepath.Join(dataDir, aiopsRuntimeFileName))
	if err != nil || len(rawRT) == 0 {
		t.Fatalf("ReadFile aiops_runtime.json: %v", err)
	}
	for _, secretText := range []string{"PgSshSecret#2026", "sk-proj-shouldneverbeleaked123456"} {
		if bytes.Contains(rawRT, []byte(secretText)) {
			t.Fatalf("SECURITY FAILURE: aiops_runtime.json leaked secret %q", secretText)
		}
	}

	// Delete memory
	if err := store.DeleteAIMemory(m1.ID, "127.0.0.1"); err != nil {
		t.Fatalf("DeleteAIMemory: %v", err)
	}
	listedAfter, _ := store.ListAIMemories()
	if len(listedAfter) != 0 {
		t.Fatalf("expected 0 memories after delete, got %d", len(listedAfter))
	}
}

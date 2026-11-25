package vault

import (
	"slices"
	"time"
)

// AIProtocol defines the wire format used to talk to an LLM provider.
type AIProtocol string

const (
	AIProtocolOpenAI    AIProtocol = "openai"    // OpenAI-compatible /chat/completions (OpenAI, DeepSeek, Qwen, Ollama, vLLM, OpenRouter, etc.)
	AIProtocolAnthropic AIProtocol = "anthropic" // Anthropic native /v1/messages protocol (Claude)
)

// AIExecutionMode controls Human-in-the-Loop (HITL) gating for remote SSH/SFTP tool execution.
type AIExecutionMode string

const (
	AIModeSuggest    AIExecutionMode = "suggest"    // Suggest only; never execute remote commands automatically
	AIModeStandard   AIExecutionMode = "standard"   // Default: read-only probes auto-run; mutating/file-write ops require approval
	AIModeAutonomous AIExecutionMode = "autonomous" // Auto-execute except catastrophic hard-blocked commands
)

// AIProviderConfig stores an LLM endpoint and secret API key strictly inside encrypted vault.sns.
type AIProviderConfig struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	Protocol      AIProtocol `json:"protocol"`
	BaseURL       string     `json:"base_url"`
	APIKey        string     `json:"api_key,omitempty"`
	Model         string     `json:"model"`
	MaxTokens     int        `json:"max_tokens,omitempty"`
	ContextWindow int        `json:"context_window,omitempty"` // 0 = auto-infer from model name (default 65536)
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// AIProviderView omits the raw API key when listing providers to UI views.
type AIProviderView struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	Protocol      AIProtocol `json:"protocol"`
	BaseURL       string     `json:"base_url"`
	HasAPIKey     bool       `json:"has_api_key"`
	APIKeyPreview string     `json:"api_key_preview,omitempty"`
	Model         string     `json:"model"`
	MaxTokens     int        `json:"max_tokens"`
	ContextWindow int        `json:"context_window"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

func maskSecretPreview(secret string) string {
	n := len(secret)
	if n == 0 {
		return ""
	}
	if n <= 8 {
		return "••••••••"
	}
	return secret[:4] + "••••" + secret[n-4:]
}

func (p AIProviderConfig) ToView() AIProviderView {
	maxTok := p.MaxTokens
	if maxTok <= 0 {
		maxTok = 4096
	}
	return AIProviderView{
		ID:            p.ID,
		Name:          p.Name,
		Protocol:      p.Protocol,
		BaseURL:       p.BaseURL,
		HasAPIKey:     p.APIKey != "",
		APIKeyPreview: maskSecretPreview(p.APIKey),
		Model:         p.Model,
		MaxTokens:     maxTok,
		ContextWindow: p.ContextWindow,
		CreatedAt:     p.CreatedAt,
		UpdatedAt:     p.UpdatedAt,
	}
}

// WebhookChannel configures an external IM/HTTP alert target stored inside vault.sns.
type WebhookChannel struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Kind    string `json:"kind"` // "feishu", "dingtalk", "wecom", "custom"
	URL     string `json:"url,omitempty"`
	Secret  string `json:"secret,omitempty"`
	Enabled bool   `json:"enabled"`
}

// WebhookChannelView redacts sensitive webhook tokens/secrets in list views.
type WebhookChannelView struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	URLMasked string `json:"url_masked"`
	HasSecret bool   `json:"has_secret"`
	Enabled   bool   `json:"enabled"`
}

func maskWebhookURL(raw string) string {
	if raw == "" {
		return ""
	}
	if len(raw) <= 28 {
		return raw[:len(raw)/2] + "••••"
	}
	return raw[:24] + "••••" + raw[len(raw)-6:]
}

func (w WebhookChannel) ToView() WebhookChannelView {
	return WebhookChannelView{
		ID:        w.ID,
		Name:      w.Name,
		Kind:      w.Kind,
		URLMasked: maskWebhookURL(w.URL),
		HasSecret: w.Secret != "",
		Enabled:   w.Enabled,
	}
}

// PatrolConfig defines periodic unattended read-only inspection & alert rules.
type PatrolConfig struct {
	Enabled              bool             `json:"enabled"`
	IntervalMinutes      int              `json:"interval_minutes"`       // e.g. 15, 30, 60, 360, 1440
	ServerIDs            []string         `json:"server_ids"`             // empty = patrol all servers
	CPUWarnPercent       float64          `json:"cpu_warn_percent"`       // load/cores * 100 threshold
	MemWarnPercent       float64          `json:"mem_warn_percent"`       // default 85
	DiskWarnPercent      float64          `json:"disk_warn_percent"`      // default 85
	SSHFailWarnCount     int              `json:"ssh_fail_warn_count"`    // recent failed SSH logins threshold
	CheckListeningPorts  bool             `json:"check_listening_ports"`  // alert on new listening TCP/UDP ports
	CheckPrivilegedUsers bool             `json:"check_privileged_users"` // alert on non-root UID=0 accounts
	Webhooks             []WebhookChannel `json:"webhooks"`
}

// PatrolConfigView returns PatrolConfig with masked webhook secrets for frontend display.
type PatrolConfigView struct {
	Enabled              bool                 `json:"enabled"`
	IntervalMinutes      int                  `json:"interval_minutes"`
	ServerIDs            []string             `json:"server_ids"`
	CPUWarnPercent       float64              `json:"cpu_warn_percent"`
	MemWarnPercent       float64              `json:"mem_warn_percent"`
	DiskWarnPercent      float64              `json:"disk_warn_percent"`
	SSHFailWarnCount     int                  `json:"ssh_fail_warn_count"`
	CheckListeningPorts  bool                 `json:"check_listening_ports"`
	CheckPrivilegedUsers bool                 `json:"check_privileged_users"`
	Webhooks             []WebhookChannelView `json:"webhooks"`
}

func (c PatrolConfig) ToView() PatrolConfigView {
	sids := c.ServerIDs
	if sids == nil {
		sids = []string{}
	}
	whViews := make([]WebhookChannelView, len(c.Webhooks))
	for i, w := range c.Webhooks {
		whViews[i] = w.ToView()
	}
	return PatrolConfigView{
		Enabled:              c.Enabled,
		IntervalMinutes:      c.IntervalMinutes,
		ServerIDs:            sids,
		CPUWarnPercent:       c.CPUWarnPercent,
		MemWarnPercent:       c.MemWarnPercent,
		DiskWarnPercent:      c.DiskWarnPercent,
		SSHFailWarnCount:     c.SSHFailWarnCount,
		CheckListeningPorts:  c.CheckListeningPorts,
		CheckPrivilegedUsers: c.CheckPrivilegedUsers,
		Webhooks:             whViews,
	}
}

// AgentsMDConfig stores the encrypted global AGENTS.md operational charter for all AI surfaces.
type AgentsMDConfig struct {
	Enabled     bool      `json:"enabled"`
	Content     string    `json:"content"`
	Revision    int       `json:"revision"`
	Initialized bool      `json:"initialized,omitempty"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// AIMemoryConfig tunes prompt injection budgets, rolling session compaction, and automatic memory sync.
type AIMemoryConfig struct {
	AgentsMDMaxChars          int     `json:"agents_md_max_chars"`
	MemoryPromptBudgetChars   int     `json:"memory_prompt_budget_chars"`
	CompactionTriggerRatio    float64 `json:"compaction_trigger_ratio"`
	CompactionKeepRecent      int     `json:"compaction_keep_recent"`
	AutoSyncMonitorToMemory   bool    `json:"auto_sync_monitor_to_memory"`
	AutoRecordApprovedChanges bool    `json:"auto_record_approved_changes"`
	Initialized               bool    `json:"initialized,omitempty"`
}

// AISettings holds global single-active LLM selection, providers, default HITL mode, patrol rules,
// global AGENTS.md charter, and memory/context budget preferences.
type AISettings struct {
	ActiveProviderID string             `json:"active_provider_id"`
	DefaultMode      AIExecutionMode    `json:"default_mode"`
	Providers        []AIProviderConfig `json:"providers"`
	Patrol           PatrolConfig       `json:"patrol"`
	AgentsMD         AgentsMDConfig     `json:"agents_md"`
	MemoryConfig     AIMemoryConfig     `json:"memory_config"`
}

// HostMemory stores objective server environment facts automatically learned by AI or synced from
// 7x24 monitor snapshots, plus human-maintained operational constraints & notes.
type HostMemory struct {
	ServerID         string     `json:"server_id"`
	ServerName       string     `json:"server_name"`
	Summary          string     `json:"summary"`
	OSArch           string     `json:"os_arch,omitempty"`
	KeyServices      []string   `json:"key_services"`
	DeployPaths      []string   `json:"deploy_paths"`
	PortsNote        string     `json:"ports_note,omitempty"`
	Constraints      string     `json:"constraints,omitempty"` // Operational redlines / pitfalls for this server
	Notes            string     `json:"notes,omitempty"`
	AutoUpdatedCount int        `json:"auto_updated_count"`
	MonitorSyncedAt  *time.Time `json:"monitor_synced_at,omitempty"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

// AIMemoryEntry stores a durable cross-session operational memory (preference, topology, incident, change, lesson).
type AIMemoryEntry struct {
	ID              string     `json:"id"`
	Scope           string     `json:"scope"` // "global" or "server"
	ServerIDs       []string   `json:"server_ids"`
	Category        string     `json:"category"` // "preference", "topology", "incident", "change", "lesson"
	Title           string     `json:"title"`
	Content         string     `json:"content"`
	Tags            []string   `json:"tags"`
	Pinned          bool       `json:"pinned"`
	Importance      int        `json:"importance"` // 1..5 (default 3)
	Source          string     `json:"source"`     // "manual", "ai", "approval"
	SourceSessionID string     `json:"source_session_id,omitempty"`
	UseCount        int        `json:"use_count"`
	LastUsedAt      *time.Time `json:"last_used_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// AIAgentsMDProposal represents an AI-proposed revision to global AGENTS.md with Unified Diff preview,
// awaiting explicit administrator approval before merging.
type AIAgentsMDProposal struct {
	ID              string     `json:"id"`
	SessionID       string     `json:"session_id"`
	Reason          string     `json:"reason"`
	Summary         string     `json:"summary"`
	ProposedContent string     `json:"proposed_content"`
	DiffPreview     string     `json:"diff_preview"`
	Status          string     `json:"status"` // "pending", "accepted", "dismissed"
	CreatedAt       time.Time  `json:"created_at"`
	ResolvedAt      *time.Time `json:"resolved_at,omitempty"`
}

// AIRunbook stores a reusable troubleshooting SOP confirmed by the administrator.
type AIRunbook struct {
	ID              string    `json:"id"`
	Title           string    `json:"title"`
	Category        string    `json:"category"`
	Tags            []string  `json:"tags"`
	Symptom         string    `json:"symptom"`
	RootCause       string    `json:"root_cause,omitempty"`
	DiagnosticSteps []string  `json:"diagnostic_steps"`
	FixCommands     []string  `json:"fix_commands"`
	Verification    string    `json:"verification,omitempty"`
	SourceSessionID string    `json:"source_session_id,omitempty"`
	LinkedSnippetID string    `json:"linked_snippet_id,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// AIToolCallRecord records an LLM tool invocation and its outcome inside a chat message.
type AIToolCallRecord struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Arguments  string `json:"arguments"`
	Summary    string `json:"summary,omitempty"`
	RiskLevel  string `json:"risk_level,omitempty"` // "readonly", "mutating", "blocked"
	Status     string `json:"status,omitempty"`     // "completed", "pending_approval", "rejected", "blocked", "error"
	Output     string `json:"output,omitempty"`
	DurationMs int64  `json:"duration_ms,omitempty"`
}

// AIPendingApproval represents a paused mutating SSH command or SFTP file modification awaiting human approval.
type AIPendingApproval struct {
	ID            string     `json:"id"`
	SessionID     string     `json:"session_id"`
	ToolCallID    string     `json:"tool_call_id"`
	ToolName      string     `json:"tool_name"`
	ServerIDs     []string   `json:"server_ids,omitempty"`
	ServerNames   []string   `json:"server_names,omitempty"`
	RiskLevel     string     `json:"risk_level"` // "medium" or "high"
	Reason        string     `json:"reason"`
	Command       string     `json:"command,omitempty"`
	FilePath      string     `json:"file_path,omitempty"`
	NewContent    string     `json:"new_content,omitempty"`
	DiffPreview   string     `json:"diff_preview,omitempty"`
	ArgumentsJSON string     `json:"arguments_json"`
	Status        string     `json:"status"` // "pending", "approved", "rejected"
	ExecutionOut  string     `json:"execution_out,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	ResolvedAt    *time.Time `json:"resolved_at,omitempty"`
}

// AIRunbookProposal represents an AI-distilled Runbook draft awaiting one-click admin confirmation.
type AIRunbookProposal struct {
	ID              string    `json:"id"`
	SessionID       string    `json:"session_id"`
	Title           string    `json:"title"`
	Category        string    `json:"category"`
	Symptom         string    `json:"symptom"`
	RootCause       string    `json:"root_cause,omitempty"`
	DiagnosticSteps []string  `json:"diagnostic_steps"`
	FixCommands     []string  `json:"fix_commands"`
	Verification    string    `json:"verification,omitempty"`
	Status          string    `json:"status"` // "pending", "accepted", "dismissed"
	SavedRunbookID  string    `json:"saved_runbook_id,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
}

// AIChatMessage represents one conversational or tool-result turn inside AIChatSession.
type AIChatMessage struct {
	ID         string             `json:"id"`
	Role       string             `json:"role"` // "user", "assistant", "tool"
	Content    string             `json:"content"`
	ToolCalls  []AIToolCallRecord `json:"tool_calls,omitempty"`
	ToolCallID string             `json:"tool_call_id,omitempty"`
	ToolName   string             `json:"tool_name,omitempty"`
	IsError    bool               `json:"is_error,omitempty"`
	Timestamp  time.Time          `json:"timestamp"`
}

// AIChatSession stores an encrypted AI Ops troubleshooting or Terminal Copilot conversation.
type AIChatSession struct {
	ID                  string               `json:"id"`
	Title               string               `json:"title"`
	Scope               string               `json:"scope"` // "center" or "terminal"
	ServerIDs           []string             `json:"server_ids"`
	Mode                AIExecutionMode      `json:"mode"`
	Messages            []AIChatMessage      `json:"messages"`
	PendingApprovals    []AIPendingApproval  `json:"pending_approvals"`
	RunbookProposals    []AIRunbookProposal  `json:"runbook_proposals"`
	AgentsMDProposals   []AIAgentsMDProposal `json:"agents_md_proposals"`
	CompactedSummary    string               `json:"compacted_summary,omitempty"`
	CompactedUntilCount int                  `json:"compacted_until_count,omitempty"`
	CompactedAt         *time.Time           `json:"compacted_at,omitempty"`
	CompactionCount     int                  `json:"compaction_count,omitempty"`
	CreatedAt           time.Time            `json:"created_at"`
	UpdatedAt           time.Time            `json:"updated_at"`
}

// AIChatSessionSummary is a lightweight list item for session history sidebars.
type AIChatSessionSummary struct {
	ID                           string          `json:"id"`
	Title                        string          `json:"title"`
	Scope                        string          `json:"scope"`
	ServerIDs                    []string        `json:"server_ids"`
	Mode                         AIExecutionMode `json:"mode"`
	MessageCount                 int             `json:"message_count"`
	PendingApprovalCount         int             `json:"pending_approval_count"`
	PendingAgentsMDProposalCount int             `json:"pending_agents_md_proposal_count"`
	CompactionCount              int             `json:"compaction_count"`
	CreatedAt                    time.Time       `json:"created_at"`
	UpdatedAt                    time.Time       `json:"updated_at"`
}

func (cs AIChatSession) ToSummary() AIChatSessionSummary {
	pending := 0
	for _, ap := range cs.PendingApprovals {
		if ap.Status == "pending" {
			pending++
		}
	}
	pendingAgents := 0
	for _, p := range cs.AgentsMDProposals {
		if p.Status == "pending" {
			pendingAgents++
		}
	}
	sids := cs.ServerIDs
	if sids == nil {
		sids = []string{}
	}
	return AIChatSessionSummary{
		ID:                           cs.ID,
		Title:                        cs.Title,
		Scope:                        cs.Scope,
		ServerIDs:                    sids,
		Mode:                         cs.Mode,
		MessageCount:                 len(cs.Messages),
		PendingApprovalCount:         pending,
		PendingAgentsMDProposalCount: pendingAgents,
		CompactionCount:              cs.CompactionCount,
		CreatedAt:                    cs.CreatedAt,
		UpdatedAt:                    cs.UpdatedAt,
	}
}

// ServerBaselineSnapshot records security baseline fingerprints per server for anomaly diffing.
type ServerBaselineSnapshot struct {
	ServerID       string    `json:"server_id"`
	ListeningPorts []string  `json:"listening_ports"`
	UIDZeroUsers   []string  `json:"uid_zero_users"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// PatrolFinding captures telemetry and detected anomalies for one server during a patrol cycle.
type PatrolFinding struct {
	ServerID       string   `json:"server_id"`
	ServerName     string   `json:"server_name"`
	Host           string   `json:"host"`
	Reachable      bool     `json:"reachable"`
	Severity       string   `json:"severity"` // "healthy", "warning", "critical"
	LatencyMs      int64    `json:"latency_ms"`
	CPULoadPercent float64  `json:"cpu_load_percent"`
	MemPercent     float64  `json:"mem_percent"`
	DiskPercent    float64  `json:"disk_percent"`
	SSHFailCount1h int      `json:"ssh_fail_count_1h"`
	NewPorts       []string `json:"new_ports,omitempty"`
	MetricsSummary string   `json:"metrics_summary"`
	Anomalies      []string `json:"anomalies"`
}

// PatrolRecord archives a scheduled or manual inspection run and its optional AI root-cause report.
type PatrolRecord struct {
	ID                string          `json:"id"`
	StartedAt         time.Time       `json:"started_at"`
	CompletedAt       time.Time       `json:"completed_at"`
	Trigger           string          `json:"trigger"` // "scheduled" or "manual"
	TotalServers      int             `json:"total_servers"`
	HealthyCount      int             `json:"healthy_count"`
	WarningCount      int             `json:"warning_count"`
	CriticalCount     int             `json:"critical_count"`
	Status            string          `json:"status"` // "healthy", "warning", "critical"
	Findings          []PatrolFinding `json:"findings"`
	AIAnalyzed        bool            `json:"ai_analyzed"`
	AIModel           string          `json:"ai_model,omitempty"`
	AISummary         string          `json:"ai_summary,omitempty"`
	AIRootCause       string          `json:"ai_root_cause,omitempty"`
	AIRecommendations []string        `json:"ai_recommendations,omitempty"`
	WebhookNotified   bool            `json:"webhook_notified"`
	Unread            bool            `json:"unread"`
}

// DefaultPatrolConfig returns safe default thresholds for periodic read-only server patrol.
func DefaultPatrolConfig() PatrolConfig {
	return PatrolConfig{
		Enabled:              false,
		IntervalMinutes:      60,
		ServerIDs:            []string{},
		CPUWarnPercent:       85,
		MemWarnPercent:       85,
		DiskWarnPercent:      85,
		SSHFailWarnCount:     15,
		CheckListeningPorts:  true,
		CheckPrivilegedUsers: true,
		Webhooks:             []WebhookChannel{},
	}
}

// DefaultAgentsMDTemplate returns a practical built-in global AGENTS.md SRE operational charter.
func DefaultAgentsMDTemplate() string {
	return `# ServerNeedSafe 全局运维智能体规范 (AGENTS.md)

## 1. 排查与诊断习惯
- **先查已有态势与记忆**：优先结合已注入的主机画像、7×24 实时监控快照与历史记忆判断现状，避免重复执行冗余探测。
- **证据优先**：涉及性能、网络或安全问题时，优先采用无损只读命令（` + "`ss`" + `、` + "`journalctl`" + `、` + "`systemctl status`" + `、` + "`df -h`" + `、` + "`free -m`" + `）取证，再给出明确根因结论。
- **按需深度召回**：排查疑似复发问题或跨机关联故障时，主动调用 ` + "`search_memory`" + ` 查阅历史变更与根因记录，或调用 ` + "`get_runbook`" + ` 获取完整标准 SOP。

## 2. 变更安全红线
- **配置变更先校验再重载**：修改 Nginx、SSH、Systemd 等关键配置前优先使用 ` + "`sftp_write_file`" + ` 展示 Diff，重载前务必验证语法（如 ` + "`nginx -t`" + `、` + "`sshd -t`" + `）。
- **尊重主机避坑约束**：严格遵守每台主机画像中标注的「运维红线/禁忌（Constraints）」，涉及数据库主节点、核心网关或在线业务重启前必须先说明业务影响范围与回滚方案。
- **零凭据泄漏**：禁止在回答、记忆条目或 Runbook 中记录任何明文密码、SSH 私钥、API Key 或 Token。

## 3. 记忆沉淀与协同规范
- 发现新的服务拓扑、非标准部署路径或业务端口用途时，及时调用 ` + "`update_host_memory`" + ` 补充主机画像。
- 定位典型故障根因、跨机依赖关系或管理员明确提到的运维偏好时，调用 ` + "`save_memory`" + ` 沉淀长期记忆（避免重复条目）。
- 若管理员提出适用于全部主机的长期规范修订，请调用 ` + "`propose_agents_md_update`" + ` 生成变更对比卡片供审批合入。

## 4. 回答输出风格
- 使用简洁、结构化的中文 Markdown：**结论先行 → 关键证据 → 建议操作 / 风险提示**。
- 巡检研判时结合主机既有端口用途与运维备注，避免将已知正常业务端口或预期缓存内存误判为入侵告警。
`
}

// DefaultAgentsMDConfig returns the initial enabled global AGENTS.md configuration.
func DefaultAgentsMDConfig(now time.Time) AgentsMDConfig {
	return AgentsMDConfig{
		Enabled:     true,
		Content:     DefaultAgentsMDTemplate(),
		Revision:    1,
		Initialized: true,
		UpdatedAt:   now,
	}
}

// DefaultAIMemoryConfig returns balanced out-of-the-box budgets for AGENTS.md, memory recall, and rolling compaction.
func DefaultAIMemoryConfig() AIMemoryConfig {
	return AIMemoryConfig{
		AgentsMDMaxChars:          6000,
		MemoryPromptBudgetChars:   4500,
		CompactionTriggerRatio:    0.70,
		CompactionKeepRecent:      6,
		AutoSyncMonitorToMemory:   true,
		AutoRecordApprovedChanges: true,
		Initialized:               true,
	}
}

// SanitizeAIMemoryConfig clamps user-edited memory/context budget parameters into safe operational bounds.
func SanitizeAIMemoryConfig(in AIMemoryConfig) AIMemoryConfig {
	def := DefaultAIMemoryConfig()
	if in.AgentsMDMaxChars < 1000 || in.AgentsMDMaxChars > 30000 {
		in.AgentsMDMaxChars = def.AgentsMDMaxChars
	}
	if in.MemoryPromptBudgetChars < 1000 || in.MemoryPromptBudgetChars > 24000 {
		in.MemoryPromptBudgetChars = def.MemoryPromptBudgetChars
	}
	if in.CompactionTriggerRatio < 0.40 || in.CompactionTriggerRatio > 0.90 {
		in.CompactionTriggerRatio = def.CompactionTriggerRatio
	}
	if in.CompactionKeepRecent < 2 || in.CompactionKeepRecent > 20 {
		in.CompactionKeepRecent = def.CompactionKeepRecent
	}
	in.Initialized = true
	return in
}

// DefaultStarterRunbooks returns built-in operational SOPs seeded in a fresh encrypted vault.
func DefaultStarterRunbooks(now time.Time) []AIRunbook {
	return []AIRunbook{
		{
			ID:        "rb-ssh-hardening",
			Title:     "SSH 暴力破解排查与基线加固 SOP",
			Category:  "安全加固",
			Tags:      []string{"SSH", "防爆破", "sshd_config"},
			Symptom:   "后台巡检发现近 1 小时 SSH 认证失败次数激增，或 auth.log 出现高频字典扫描 IP",
			RootCause: "公网暴露默认 22 端口且允许密码登录或 Root 口令尝试，未启用自动封禁机制",
			DiagnosticSteps: []string{
				"统计最近失败登录来源 IP Top 10 与被尝试用户名分布",
				"核查 /etc/ssh/sshd_config 中 PermitRootLogin、PasswordAuthentication 与 MaxAuthTries 配置",
				"确认 ~/.ssh/authorized_keys 已部署有效公钥且权限为 0600",
			},
			FixCommands: []string{
				"sshd -t && systemctl reload sshd",
			},
			Verification: "确认新开密钥会话可正常登录后，复查 sshd -T 输出与近期拦截状态",
			CreatedAt:    now,
			UpdatedAt:    now,
		},
		{
			ID:        "rb-disk-full-triage",
			Title:     "根分区磁盘爆满无损定位与安全清理 SOP",
			Category:  "故障恢复",
			Tags:      []string{"磁盘", "日志清理", "inode"},
			Symptom:   "磁盘使用率超过 85% 或服务报 No space left on device",
			RootCause: "未轮转容器/应用日志膨胀、systemd journal 堆积或已删除文件句柄仍被进程占用",
			DiagnosticSteps: []string{
				"通过 df -h 与 df -i 同时确认块空间与 inode 使用率",
				"定位 /var/log、/var/lib/docker 等高占用目录及 >100MB 大文件",
				"检查 lsof +L1 是否存在 deleted 状态却未释放空间的僵尸句柄",
			},
			FixCommands: []string{
				"journalctl --vacuum-size=200M",
			},
			Verification: "再次执行 df -h 确认可用空间水位回落至 80% 以下且核心服务写入正常",
			CreatedAt:    now,
			UpdatedAt:    now,
		},
	}
}

// EnsureStateDefaults upgrades older schema states in-place so all v2 AI slices/defaults are initialized.
func EnsureStateDefaults(st *VaultState) {
	if st == nil {
		return
	}
	now := time.Now().UTC()
	if st.SchemaVersion < 2 {
		st.SchemaVersion = 2
	}
	if st.AISettings.DefaultMode == "" {
		st.AISettings.DefaultMode = AIModeStandard
	}
	if st.AISettings.Providers == nil {
		st.AISettings.Providers = []AIProviderConfig{}
	}
	if st.AISettings.Patrol.IntervalMinutes <= 0 {
		def := DefaultPatrolConfig()
		st.AISettings.Patrol.IntervalMinutes = def.IntervalMinutes
		st.AISettings.Patrol.CPUWarnPercent = def.CPUWarnPercent
		st.AISettings.Patrol.MemWarnPercent = def.MemWarnPercent
		st.AISettings.Patrol.DiskWarnPercent = def.DiskWarnPercent
		st.AISettings.Patrol.SSHFailWarnCount = def.SSHFailWarnCount
		st.AISettings.Patrol.CheckListeningPorts = def.CheckListeningPorts
		st.AISettings.Patrol.CheckPrivilegedUsers = def.CheckPrivilegedUsers
	}
	if st.AISettings.Patrol.ServerIDs == nil {
		st.AISettings.Patrol.ServerIDs = []string{}
	}
	if st.AISettings.Patrol.Webhooks == nil {
		st.AISettings.Patrol.Webhooks = []WebhookChannel{}
	}
	if !st.AISettings.AgentsMD.Initialized && st.AISettings.AgentsMD.Revision == 0 && st.AISettings.AgentsMD.Content == "" {
		st.AISettings.AgentsMD = DefaultAgentsMDConfig(now)
	}
	if !st.AISettings.MemoryConfig.Initialized && st.AISettings.MemoryConfig.AgentsMDMaxChars == 0 {
		st.AISettings.MemoryConfig = DefaultAIMemoryConfig()
	} else if clean := SanitizeAIMemoryConfig(st.AISettings.MemoryConfig); clean != st.AISettings.MemoryConfig {
		st.AISettings.MemoryConfig = clean
	}
	if st.HostMemories == nil {
		st.HostMemories = []HostMemory{}
	}
	if st.AIMemories == nil {
		st.AIMemories = []AIMemoryEntry{}
	}
	if st.Runbooks == nil {
		st.Runbooks = DefaultStarterRunbooks(now)
	}
	if st.AISessions == nil {
		st.AISessions = []AIChatSession{}
	}
	if st.PatrolBaselines == nil {
		st.PatrolBaselines = []ServerBaselineSnapshot{}
	}
	if st.PatrolRecords == nil {
		st.PatrolRecords = []PatrolRecord{}
	}
}

func scrubAIData(st *VaultState) {
	if st == nil {
		return
	}
	for i := range st.AISettings.Providers {
		st.AISettings.Providers[i].APIKey = ""
		st.AISettings.Providers[i].BaseURL = ""
	}
	for i := range st.AISettings.Patrol.Webhooks {
		st.AISettings.Patrol.Webhooks[i].URL = ""
		st.AISettings.Patrol.Webhooks[i].Secret = ""
	}
	st.AISettings.AgentsMD.Content = ""
	st.HostMemories = nil
	st.AIMemories = nil
	st.Runbooks = nil
	st.AISessions = nil
	st.PatrolBaselines = nil
	st.PatrolRecords = nil
}

func cloneAIData(dst, src *VaultState) {
	if dst == nil || src == nil {
		return
	}
	dst.AISettings = src.AISettings
	dst.AISettings.Providers = slices.Clone(src.AISettings.Providers)
	dst.AISettings.Patrol.ServerIDs = slices.Clone(src.AISettings.Patrol.ServerIDs)
	dst.AISettings.Patrol.Webhooks = slices.Clone(src.AISettings.Patrol.Webhooks)

	dst.HostMemories = make([]HostMemory, len(src.HostMemories))
	for i, m := range src.HostMemories {
		mc := m
		mc.KeyServices = slices.Clone(m.KeyServices)
		mc.DeployPaths = slices.Clone(m.DeployPaths)
		if m.MonitorSyncedAt != nil {
			t := *m.MonitorSyncedAt
			mc.MonitorSyncedAt = &t
		}
		dst.HostMemories[i] = mc
	}

	dst.AIMemories = make([]AIMemoryEntry, len(src.AIMemories))
	for i, mem := range src.AIMemories {
		mc := mem
		mc.ServerIDs = slices.Clone(mem.ServerIDs)
		mc.Tags = slices.Clone(mem.Tags)
		if mem.LastUsedAt != nil {
			t := *mem.LastUsedAt
			mc.LastUsedAt = &t
		}
		dst.AIMemories[i] = mc
	}

	dst.Runbooks = make([]AIRunbook, len(src.Runbooks))
	for i, rb := range src.Runbooks {
		rc := rb
		rc.Tags = slices.Clone(rb.Tags)
		rc.DiagnosticSteps = slices.Clone(rb.DiagnosticSteps)
		rc.FixCommands = slices.Clone(rb.FixCommands)
		dst.Runbooks[i] = rc
	}

	dst.AISessions = make([]AIChatSession, len(src.AISessions))
	for i, cs := range src.AISessions {
		dst.AISessions[i] = cloneSession(cs)
	}

	dst.PatrolBaselines = make([]ServerBaselineSnapshot, len(src.PatrolBaselines))
	for i, b := range src.PatrolBaselines {
		bc := b
		bc.ListeningPorts = slices.Clone(b.ListeningPorts)
		bc.UIDZeroUsers = slices.Clone(b.UIDZeroUsers)
		dst.PatrolBaselines[i] = bc
	}

	dst.PatrolRecords = make([]PatrolRecord, len(src.PatrolRecords))
	for i, rec := range src.PatrolRecords {
		rc := rec
		rc.Findings = make([]PatrolFinding, len(rec.Findings))
		for fi, f := range rec.Findings {
			fc := f
			fc.NewPorts = slices.Clone(f.NewPorts)
			fc.Anomalies = slices.Clone(f.Anomalies)
			rc.Findings[fi] = fc
		}
		rc.AIRecommendations = slices.Clone(rec.AIRecommendations)
		dst.PatrolRecords[i] = rc
	}
}

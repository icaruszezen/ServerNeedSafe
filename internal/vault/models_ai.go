package vault

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// AIProtocol defines the wire format used to talk to an LLM provider.
type AIProtocol string

const (
	AIProtocolOpenAI          AIProtocol = "openai"           // OpenAI-compatible /chat/completions (OpenAI, DeepSeek, Qwen, Ollama, vLLM, OpenRouter, etc.)
	AIProtocolOpenAIResponses AIProtocol = "openai_responses" // OpenAI Responses API (/responses)
	AIProtocolAnthropic       AIProtocol = "anthropic"        // Anthropic Messages API (/messages)
	AIProtocolGemini          AIProtocol = "gemini"           // Google Gemini API (:streamGenerateContent?alt=sse)
)

// IsValidAIProtocol reports whether p is a supported LLM wire protocol.
func IsValidAIProtocol(p AIProtocol) bool {
	switch p {
	case AIProtocolOpenAI, AIProtocolOpenAIResponses, AIProtocolAnthropic, AIProtocolGemini:
		return true
	default:
		return false
	}
}

// NormalizeAIProtocol returns a canonical AIProtocol (defaulting empty to OpenAI Chat Completions).
func NormalizeAIProtocol(p AIProtocol) AIProtocol {
	p = AIProtocol(strings.ToLower(strings.TrimSpace(string(p))))
	switch p {
	case AIProtocolOpenAIResponses, AIProtocolAnthropic, AIProtocolGemini:
		return p
	default:
		return AIProtocolOpenAI
	}
}

// AIEndpointMode controls how the final HTTP request URL is derived from BaseURL.
type AIEndpointMode string

const (
	AIEndpointModeAuto  AIEndpointMode = "auto"  // Automatically append protocol-standard endpoint suffix when needed
	AIEndpointModeExact AIEndpointMode = "exact" // Send requests directly to BaseURL verbatim
)

func NormalizeAIEndpointMode(m AIEndpointMode) AIEndpointMode {
	if strings.EqualFold(strings.TrimSpace(string(m)), string(AIEndpointModeExact)) {
		return AIEndpointModeExact
	}
	return AIEndpointModeAuto
}

// AIAuthMode controls how APIKey is attached to outbound LLM HTTP requests.
type AIAuthMode string

const (
	AIAuthModeAuto        AIAuthMode = "auto"           // Protocol default (OpenAI: Bearer, Anthropic: x-api-key, Gemini: x-goog-api-key)
	AIAuthModeBearer      AIAuthMode = "bearer"         // Authorization: Bearer <key>
	AIAuthModeXAPIKey     AIAuthMode = "x-api-key"      // x-api-key: <key>
	AIAuthModeXGoogAPIKey AIAuthMode = "x-goog-api-key" // x-goog-api-key: <key>
	AIAuthModeQueryKey    AIAuthMode = "query_key"      // ?key=<key>
	AIAuthModeNone        AIAuthMode = "none"           // Do not send API key automatically
)

func NormalizeAIAuthMode(m AIAuthMode) AIAuthMode {
	switch AIAuthMode(strings.ToLower(strings.TrimSpace(string(m)))) {
	case AIAuthModeBearer:
		return AIAuthModeBearer
	case AIAuthModeXAPIKey:
		return AIAuthModeXAPIKey
	case AIAuthModeXGoogAPIKey:
		return AIAuthModeXGoogAPIKey
	case AIAuthModeQueryKey:
		return AIAuthModeQueryKey
	case AIAuthModeNone:
		return AIAuthModeNone
	default:
		return AIAuthModeAuto
	}
}

// AIReasoningEffort specifies unified thinking/reasoning depth across providers.
type AIReasoningEffort string

const (
	AIReasoningDefault AIReasoningEffort = ""       // Follow provider/model default
	AIReasoningOff     AIReasoningEffort = "off"    // Disable thinking/reasoning when supported
	AIReasoningLow     AIReasoningEffort = "low"    // Fast, low-token reasoning
	AIReasoningMedium  AIReasoningEffort = "medium" // Balanced reasoning
	AIReasoningHigh    AIReasoningEffort = "high"   // Deep reasoning
	AIReasoningMax     AIReasoningEffort = "max"    // Maximum reasoning (maps to xhigh/max)
)

func NormalizeAIReasoningEffort(r AIReasoningEffort) AIReasoningEffort {
	switch AIReasoningEffort(strings.ToLower(strings.TrimSpace(string(r)))) {
	case AIReasoningOff, "none", "disabled":
		return AIReasoningOff
	case AIReasoningLow, "minimal":
		return AIReasoningLow
	case AIReasoningMedium:
		return AIReasoningMedium
	case AIReasoningHigh:
		return AIReasoningHigh
	case AIReasoningMax, "xhigh":
		return AIReasoningMax
	default:
		return AIReasoningDefault
	}
}

// AICustomHeader represents an arbitrary custom HTTP header encrypted inside secrets.enc.
type AICustomHeader struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// AICustomHeaderView redacts sensitive custom header values when returned to the UI.
type AICustomHeaderView struct {
	Key          string `json:"key"`
	ValuePreview string `json:"value_preview"`
	IsSensitive  bool   `json:"is_sensitive"`
	HasValue     bool   `json:"has_value"`
}

// IsSensitiveHeaderKey reports whether an HTTP header name likely carries credentials or secrets.
func IsSensitiveHeaderKey(key string) bool {
	k := strings.ToLower(strings.TrimSpace(key))
	if k == "" {
		return false
	}
	for _, needle := range []string{"auth", "key", "token", "secret", "cookie", "pass", "credential", "signature"} {
		if strings.Contains(k, needle) {
			return true
		}
	}
	return false
}

// AIExecutionMode controls Human-in-the-Loop (HITL) gating for remote SSH/SFTP tool execution.
type AIExecutionMode string

const (
	AIModeSuggest    AIExecutionMode = "suggest"    // Suggest only; never execute remote commands automatically
	AIModeStandard   AIExecutionMode = "standard"   // Default: read-only probes auto-run; mutating/file-write ops require approval
	AIModeAutonomous AIExecutionMode = "autonomous" // Auto-execute except catastrophic hard-blocked commands
)

// AIProviderConfig stores an LLM endpoint, secret credentials, and unrestricted model parameters strictly inside encrypted secrets.enc.
type AIProviderConfig struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	Protocol        AIProtocol        `json:"protocol"`
	BaseURL         string            `json:"base_url"`
	EndpointMode    AIEndpointMode    `json:"endpoint_mode,omitempty"`
	AuthMode        AIAuthMode        `json:"auth_mode,omitempty"`
	APIKey          string            `json:"api_key,omitempty"`
	Model           string            `json:"model"`
	MaxTokens       int               `json:"max_tokens,omitempty"`        // Legacy alias synced with MaxOutputTokens
	MaxOutputTokens int               `json:"max_output_tokens,omitempty"` // 0 = unset (use model/provider default); unrestricted positive integer
	MaxInputTokens  int               `json:"max_input_tokens,omitempty"`  // 0 = auto from catalog/ContextWindow; unrestricted positive integer
	ContextWindow   int               `json:"context_window,omitempty"`    // 0 = auto from catalog; unrestricted positive integer
	Temperature     *float64          `json:"temperature,omitempty"`       // nil = omit / follow model default
	TopP            *float64          `json:"top_p,omitempty"`             // nil = omit / follow model default
	ReasoningEffort AIReasoningEffort `json:"reasoning_effort,omitempty"`  // "", "off", "low", "medium", "high", "max"
	CustomHeaders   []AICustomHeader  `json:"custom_headers,omitempty"`    // Arbitrary encrypted HTTP headers
	ExtraBodyJSON   string            `json:"extra_body_json,omitempty"`   // Unrestricted JSON object deep-merged into outbound payload
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
}

// EffectiveMaxOutputTokens returns the configured max output token cap (0 means unset / model default).
func (p AIProviderConfig) EffectiveMaxOutputTokens() int {
	if p.MaxOutputTokens > 0 {
		return p.MaxOutputTokens
	}
	if p.MaxTokens > 0 {
		return p.MaxTokens
	}
	return 0
}

// CloneAIProviderConfig returns a deep copy of AIProviderConfig so callers can safely mutate copies.
func CloneAIProviderConfig(p AIProviderConfig) AIProviderConfig {
	cp := p
	if p.Temperature != nil {
		v := *p.Temperature
		cp.Temperature = &v
	}
	if p.TopP != nil {
		v := *p.TopP
		cp.TopP = &v
	}
	if p.CustomHeaders != nil {
		cp.CustomHeaders = slices.Clone(p.CustomHeaders)
	}
	return cp
}

func cloneAIProviders(in []AIProviderConfig) []AIProviderConfig {
	if in == nil {
		return []AIProviderConfig{}
	}
	out := make([]AIProviderConfig, len(in))
	for i, p := range in {
		out[i] = CloneAIProviderConfig(p)
	}
	return out
}

// AIProviderView omits raw secrets when listing providers to UI views.
type AIProviderView struct {
	ID              string               `json:"id"`
	Name            string               `json:"name"`
	Protocol        AIProtocol           `json:"protocol"`
	BaseURL         string               `json:"base_url"`
	EndpointMode    AIEndpointMode       `json:"endpoint_mode"`
	AuthMode        AIAuthMode           `json:"auth_mode"`
	HasAPIKey       bool                 `json:"has_api_key"`
	APIKeyPreview   string               `json:"api_key_preview,omitempty"`
	Model           string               `json:"model"`
	MaxTokens       int                  `json:"max_tokens"`
	MaxOutputTokens int                  `json:"max_output_tokens"`
	MaxInputTokens  int                  `json:"max_input_tokens"`
	ContextWindow   int                  `json:"context_window"`
	Temperature     *float64             `json:"temperature,omitempty"`
	TopP            *float64             `json:"top_p,omitempty"`
	ReasoningEffort AIReasoningEffort    `json:"reasoning_effort,omitempty"`
	CustomHeaders   []AICustomHeaderView `json:"custom_headers,omitempty"`
	ExtraBodyJSON   string               `json:"extra_body_json,omitempty"`
	CreatedAt       time.Time            `json:"created_at"`
	UpdatedAt       time.Time            `json:"updated_at"`
}

func maskSecretPreview(secret string) string {
	runes := []rune(secret)
	n := len(runes)
	if n == 0 {
		return ""
	}
	if n <= 8 {
		return "••••••••"
	}
	return string(runes[:4]) + "••••" + string(runes[n-4:])
}

func (p AIProviderConfig) ToView() AIProviderView {
	maxOut := p.EffectiveMaxOutputTokens()
	var tempPtr, topPPtr *float64
	if p.Temperature != nil {
		v := *p.Temperature
		tempPtr = &v
	}
	if p.TopP != nil {
		v := *p.TopP
		topPPtr = &v
	}
	var hdrViews []AICustomHeaderView
	if len(p.CustomHeaders) > 0 {
		hdrViews = make([]AICustomHeaderView, 0, len(p.CustomHeaders))
		for _, h := range p.CustomHeaders {
			k := strings.TrimSpace(h.Key)
			if k == "" {
				continue
			}
			sens := IsSensitiveHeaderKey(k)
			preview := h.Value
			if sens {
				preview = maskSecretPreview(h.Value)
			}
			hdrViews = append(hdrViews, AICustomHeaderView{
				Key:          k,
				ValuePreview: preview,
				IsSensitive:  sens,
				HasValue:     h.Value != "",
			})
		}
	}
	return AIProviderView{
		ID:              p.ID,
		Name:            p.Name,
		Protocol:        NormalizeAIProtocol(p.Protocol),
		BaseURL:         p.BaseURL,
		EndpointMode:    NormalizeAIEndpointMode(p.EndpointMode),
		AuthMode:        NormalizeAIAuthMode(p.AuthMode),
		HasAPIKey:       p.APIKey != "",
		APIKeyPreview:   maskSecretPreview(p.APIKey),
		Model:           p.Model,
		MaxTokens:       maxOut,
		MaxOutputTokens: maxOut,
		MaxInputTokens:  max(0, p.MaxInputTokens),
		ContextWindow:   max(0, p.ContextWindow),
		Temperature:     tempPtr,
		TopP:            topPPtr,
		ReasoningEffort: NormalizeAIReasoningEffort(p.ReasoningEffort),
		CustomHeaders:   hdrViews,
		ExtraBodyJSON:   p.ExtraBodyJSON,
		CreatedAt:       p.CreatedAt,
		UpdatedAt:       p.UpdatedAt,
	}
}

// AITokenUsage captures real token usage reported by an upstream LLM streaming response.
type AITokenUsage struct {
	InputTokens       int `json:"input_tokens,omitempty"`
	OutputTokens      int `json:"output_tokens,omitempty"`
	ReasoningTokens   int `json:"reasoning_tokens,omitempty"`
	CachedInputTokens int `json:"cached_input_tokens,omitempty"`
	TotalTokens       int `json:"total_tokens,omitempty"`
}

// AIAnthropicThinkingBlock preserves Claude thinking/redacted_thinking blocks with signatures for multi-turn tool calling.
type AIAnthropicThinkingBlock struct {
	Type      string `json:"type"` // "thinking" or "redacted_thinking"
	Thinking  string `json:"thinking,omitempty"`
	Signature string `json:"signature,omitempty"`
	Data      string `json:"data,omitempty"`
}

// AIMessageMeta stores protocol-specific opaque reasoning state required to round-trip multi-turn tool calls cleanly.
type AIMessageMeta struct {
	Protocol               AIProtocol                 `json:"protocol,omitempty"`
	AnthropicThinking      []AIAnthropicThinkingBlock `json:"anthropic_thinking,omitempty"`
	GeminiThoughtSignature string                     `json:"gemini_thought_signature,omitempty"`
	GeminiToolSignatures   map[string]string          `json:"gemini_tool_signatures,omitempty"`
	GeminiToolIDs          map[string]string          `json:"gemini_tool_ids,omitempty"`
	ResponsesReasoningRaw  []string                   `json:"responses_reasoning_raw,omitempty"`
}

// AIModelCatalogEntry stores default limits and capability metadata for a known LLM model.
type AIModelCatalogEntry struct {
	ID                      string     `json:"id"`
	Name                    string     `json:"name,omitempty"`
	Vendor                  string     `json:"vendor,omitempty"`
	Protocol                AIProtocol `json:"protocol,omitempty"`
	ContextWindow           int        `json:"context_window,omitempty"`
	MaxInputTokens          int        `json:"max_input_tokens,omitempty"`
	MaxOutputTokens         int        `json:"max_output_tokens,omitempty"`
	SupportsReasoning       bool       `json:"supports_reasoning,omitempty"`
	SupportsTemperature     *bool      `json:"supports_temperature,omitempty"` // nil defaults to true
	SupportsTools           bool       `json:"supports_tools,omitempty"`
	InterleavedReasoningKey string     `json:"interleaved_reasoning_key,omitempty"`
	ReleaseDate             string     `json:"release_date,omitempty"`
	Source                  string     `json:"source,omitempty"` // "builtin", "models.dev", "openrouter", "provider"
}

// AIModelCatalogCache caches synced public model metadata inside aiops_runtime.json.
type AIModelCatalogCache struct {
	Source   string                `json:"source,omitempty"`
	SyncedAt *time.Time            `json:"synced_at,omitempty"`
	Models   []AIModelCatalogEntry `json:"models,omitempty"`
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
	runes := []rune(raw)
	if len(runes) <= 28 {
		return string(runes[:len(runes)/2]) + "••••"
	}
	return string(runes[:24]) + "••••" + string(runes[len(runes)-6:])
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

// PatrolAnalysisMode controls which AI engine performs root-cause analysis on patrol anomalies.
type PatrolAnalysisMode string

const (
	PatrolAnalysisBuiltin              PatrolAnalysisMode = "builtin"                // Default: built-in HTTP LLM provider
	PatrolAnalysisExternal             PatrolAnalysisMode = "external"               // External MCP AI takeover only (zero built-in API cost)
	PatrolAnalysisExternalWithFallback PatrolAnalysisMode = "external_with_fallback" // External MCP AI first; fallback to built-in LLM on timeout
)

// NormalizePatrolAnalysisMode validates and normalizes a PatrolAnalysisMode value.
func NormalizePatrolAnalysisMode(m PatrolAnalysisMode) PatrolAnalysisMode {
	switch m {
	case PatrolAnalysisExternal, PatrolAnalysisExternalWithFallback:
		return m
	default:
		return PatrolAnalysisBuiltin
	}
}

// PatrolConfig defines periodic unattended read-only inspection & alert rules.
type PatrolConfig struct {
	Enabled                 bool               `json:"enabled"`
	IntervalMinutes         int                `json:"interval_minutes"`          // e.g. 15, 30, 60, 360, 1440
	ServerIDs               []string           `json:"server_ids"`                // empty = patrol all servers
	CPUWarnPercent          float64            `json:"cpu_warn_percent"`          // load/cores * 100 threshold
	MemWarnPercent          float64            `json:"mem_warn_percent"`          // default 85
	DiskWarnPercent         float64            `json:"disk_warn_percent"`         // default 85
	SSHFailWarnCount        int                `json:"ssh_fail_warn_count"`       // recent failed SSH logins threshold
	CheckListeningPorts     bool               `json:"check_listening_ports"`     // alert on new listening TCP/UDP ports
	CheckPrivilegedUsers    bool               `json:"check_privileged_users"`    // alert on non-root UID=0 accounts
	AnalysisMode            PatrolAnalysisMode `json:"analysis_mode,omitempty"`   // "builtin", "external", "external_with_fallback"
	ExternalFallbackMinutes int                `json:"external_fallback_minutes"` // timeout in minutes before built-in fallback (default 15)
	NotifyPendingApprovals  bool               `json:"notify_pending_approvals"`  // dispatch webhook when external AI submits HITL approval
	Webhooks                []WebhookChannel   `json:"webhooks"`
}

// PatrolConfigView returns PatrolConfig with masked webhook secrets for frontend display.
type PatrolConfigView struct {
	Enabled                 bool                 `json:"enabled"`
	IntervalMinutes         int                  `json:"interval_minutes"`
	ServerIDs               []string             `json:"server_ids"`
	CPUWarnPercent          float64              `json:"cpu_warn_percent"`
	MemWarnPercent          float64              `json:"mem_warn_percent"`
	DiskWarnPercent         float64              `json:"disk_warn_percent"`
	SSHFailWarnCount        int                  `json:"ssh_fail_warn_count"`
	CheckListeningPorts     bool                 `json:"check_listening_ports"`
	CheckPrivilegedUsers    bool                 `json:"check_privileged_users"`
	AnalysisMode            PatrolAnalysisMode   `json:"analysis_mode"`
	ExternalFallbackMinutes int                  `json:"external_fallback_minutes"`
	NotifyPendingApprovals  bool                 `json:"notify_pending_approvals"`
	Webhooks                []WebhookChannelView `json:"webhooks"`
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
	fallbackMins := c.ExternalFallbackMinutes
	if fallbackMins <= 0 {
		fallbackMins = 15
	}
	return PatrolConfigView{
		Enabled:                 c.Enabled,
		IntervalMinutes:         c.IntervalMinutes,
		ServerIDs:               sids,
		CPUWarnPercent:          c.CPUWarnPercent,
		MemWarnPercent:          c.MemWarnPercent,
		DiskWarnPercent:         c.DiskWarnPercent,
		SSHFailWarnCount:        c.SSHFailWarnCount,
		CheckListeningPorts:     c.CheckListeningPorts,
		CheckPrivilegedUsers:    c.CheckPrivilegedUsers,
		AnalysisMode:            NormalizePatrolAnalysisMode(c.AnalysisMode),
		ExternalFallbackMinutes: fallbackMins,
		NotifyPendingApprovals:  c.NotifyPendingApprovals,
		Webhooks:                whViews,
	}
}

// MCPTokenScope limits what an external AI client can invoke through /api/mcp.
type MCPTokenScope string

const (
	MCPScopePatrolReadOnly MCPTokenScope = "patrol_readonly" // Telemetry, patrol queue/report, read-only SSH/SFTP forensics, memory updates
	MCPScopeOpsPropose     MCPTokenScope = "ops_propose"     // All of patrol_readonly + submit mutating SSH/SFTP proposals into HITL approval queue
)

// NormalizeMCPTokenScope validates and defaults an MCPTokenScope value.
func NormalizeMCPTokenScope(sc MCPTokenScope) MCPTokenScope {
	if sc == MCPScopeOpsPropose {
		return MCPScopeOpsPropose
	}
	return MCPScopePatrolReadOnly
}

// MCPToken stores a revocable scoped API token hash for external AI MCP clients inside secrets.enc.
// The raw token is returned only once at creation time and never persisted in plaintext.
type MCPToken struct {
	ID             string        `json:"id"`
	Name           string        `json:"name"`
	ClientHint     string        `json:"client_hint,omitempty"` // "claude_code", "codex", "antigravity", "cursor", "custom"
	Scope          MCPTokenScope `json:"scope"`
	TokenHash      string        `json:"token_hash"`
	TokenPrefix    string        `json:"token_prefix"`
	AllowedServers []string      `json:"allowed_servers,omitempty"` // empty = all managed servers
	Enabled        bool          `json:"enabled"`
	CreatedAt      time.Time     `json:"created_at"`
}

// MCPTokenRuntimeUsage records high-frequency MCP call telemetry in aiops_runtime.json (never touches secrets.enc).
type MCPTokenRuntimeUsage struct {
	LastUsedAt     *time.Time `json:"last_used_at,omitempty"`
	LastClientName string     `json:"last_client_name,omitempty"`
	LastClientIP   string     `json:"last_client_ip,omitempty"`
	CallCount      int64      `json:"call_count,omitempty"`
}

// MCPTokenView redacts TokenHash and merges live runtime usage stats for frontend display.
type MCPTokenView struct {
	ID             string        `json:"id"`
	Name           string        `json:"name"`
	ClientHint     string        `json:"client_hint,omitempty"`
	Scope          MCPTokenScope `json:"scope"`
	TokenPrefix    string        `json:"token_prefix"`
	AllowedServers []string      `json:"allowed_servers"`
	Enabled        bool          `json:"enabled"`
	CreatedAt      time.Time     `json:"created_at"`
	LastUsedAt     *time.Time    `json:"last_used_at,omitempty"`
	LastClientName string        `json:"last_client_name,omitempty"`
	LastClientIP   string        `json:"last_client_ip,omitempty"`
	CallCount      int64         `json:"call_count"`
}

// MCPConfig configures the built-in MCP Streamable HTTP gateway for external AI clients.
type MCPConfig struct {
	Enabled                bool       `json:"enabled"`
	DesktopLoopbackEnabled bool       `json:"desktop_loopback_enabled"`
	DesktopLoopbackPort    int        `json:"desktop_loopback_port"`
	PublicEndpointHint     string     `json:"public_endpoint_hint,omitempty"`
	Tokens                 []MCPToken `json:"tokens"`
}

// MCPConfigView exposes redacted MCP settings and token metadata to the admin UI.
type MCPConfigView struct {
	Enabled                bool           `json:"enabled"`
	DesktopLoopbackEnabled bool           `json:"desktop_loopback_enabled"`
	DesktopLoopbackPort    int            `json:"desktop_loopback_port"`
	PublicEndpointHint     string         `json:"public_endpoint_hint,omitempty"`
	Tokens                 []MCPTokenView `json:"tokens"`
}

// DefaultMCPConfig returns secure defaults for the built-in MCP gateway.
func DefaultMCPConfig() MCPConfig {
	return MCPConfig{
		Enabled:                false,
		DesktopLoopbackEnabled: false,
		DesktopLoopbackPort:    18900,
		PublicEndpointHint:     "",
		Tokens:                 []MCPToken{},
	}
}

// ExternalApprovalStep represents one ordered action inside an external MCP AI change plan.
type ExternalApprovalStep struct {
	ID              string     `json:"id"`
	Index           int        `json:"index"` // 1-based execution order submitted by the AI
	Title           string     `json:"title,omitempty"`
	ToolName        string     `json:"tool_name"` // "exec_ssh_command" or "sftp_write_file"
	ServerIDs       []string   `json:"server_ids"`
	ServerNames     []string   `json:"server_names"`
	RiskLevel       string     `json:"risk_level"` // "medium", "high", or "blocked"
	Reason          string     `json:"reason,omitempty"`
	Command         string     `json:"command,omitempty"`
	TimeoutSec      int        `json:"timeout_sec,omitempty"`
	FilePath        string     `json:"file_path,omitempty"`
	NewContent      string     `json:"new_content,omitempty"`
	DiffPreview     string     `json:"diff_preview,omitempty"`
	ContinueOnError bool       `json:"continue_on_error,omitempty"`
	Blocked         bool       `json:"blocked,omitempty"`
	BlockedReason   string     `json:"blocked_reason,omitempty"`
	Selected        bool       `json:"selected"`
	Status          string     `json:"status"` // "pending", "blocked", "running", "succeeded", "failed", "skipped", "cancelled", "rejected"
	ExecutionOut    string     `json:"execution_out,omitempty"`
	ExecutionError  string     `json:"execution_error,omitempty"`
	DurationMs      int64      `json:"duration_ms,omitempty"`
	StartedAt       *time.Time `json:"started_at,omitempty"`
	CompletedAt     *time.Time `json:"completed_at,omitempty"`
}

// ExternalApproval represents an ordered change plan (1..N steps) proposed by an external AI via MCP.
// Proposals NEVER auto-execute remotely; an administrator must explicitly approve them in the Web console.
type ExternalApproval struct {
	ID              string                 `json:"id"`
	Title           string                 `json:"title,omitempty"`
	PatrolRecordID  string                 `json:"patrol_record_id,omitempty"`
	TokenID         string                 `json:"token_id"`
	TokenName       string                 `json:"token_name"`
	ClientName      string                 `json:"client_name"`
	ToolName        string                 `json:"tool_name,omitempty"` // "change_plan" or legacy single-step tool
	ServerIDs       []string               `json:"server_ids"`
	ServerNames     []string               `json:"server_names"`
	RiskLevel       string                 `json:"risk_level"` // "medium", "high", or "blocked"
	Reason          string                 `json:"reason"`
	Command         string                 `json:"command,omitempty"`
	FilePath        string                 `json:"file_path,omitempty"`
	NewContent      string                 `json:"new_content,omitempty"`
	DiffPreview     string                 `json:"diff_preview,omitempty"`
	Steps           []ExternalApprovalStep `json:"steps"`
	TotalSteps      int                    `json:"total_steps"`
	ExecutableSteps int                    `json:"executable_steps"`
	BlockedSteps    int                    `json:"blocked_steps"`
	CompletedSteps  int                    `json:"completed_steps"`
	FailedSteps     int                    `json:"failed_steps"`
	SkippedSteps    int                    `json:"skipped_steps"`
	CurrentStepIdx  int                    `json:"current_step_index,omitempty"`
	Status          string                 `json:"status"` // "pending", "running", "completed", "partial_failed", "failed", "cancelled", "rejected"
	ExecutionOut    string                 `json:"execution_out,omitempty"`
	ExecutionError  string                 `json:"execution_error,omitempty"`
	DurationMs      int64                  `json:"duration_ms,omitempty"`
	WebhookNotified bool                   `json:"webhook_notified,omitempty"`
	CreatedAt       time.Time              `json:"created_at"`
	StartedAt       *time.Time             `json:"started_at,omitempty"`
	ResolvedAt      *time.Time             `json:"resolved_at,omitempty"`
}

// IsExternalApprovalTerminal reports whether an external change plan has reached an immutable final state.
func IsExternalApprovalTerminal(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "completed", "partial_failed", "failed", "cancelled", "rejected", "approved":
		return true
	default:
		return false
	}
}

// RecalculateSummary refreshes aggregate step counters, server union, and risk level on an ExternalApproval.
func (ap *ExternalApproval) RecalculateSummary() {
	if ap == nil {
		return
	}
	ap.TotalSteps = len(ap.Steps)
	ap.ExecutableSteps = 0
	ap.BlockedSteps = 0
	ap.CompletedSteps = 0
	ap.FailedSteps = 0
	ap.SkippedSteps = 0
	ap.CurrentStepIdx = 0

	hasHigh := false
	hasBlocked := false
	serverIDs := make([]string, 0, len(ap.ServerIDs))
	serverNames := make([]string, 0, len(ap.ServerNames))
	seenID := make(map[string]bool)
	seenName := make(map[string]bool)

	for i := range ap.Steps {
		st := &ap.Steps[i]
		if st.Index <= 0 {
			st.Index = i + 1
		}
		if st.Blocked {
			st.Selected = false
			st.Status = "blocked"
			if st.RiskLevel == "" {
				st.RiskLevel = "blocked"
			}
			ap.BlockedSteps++
			hasBlocked = true
		} else {
			ap.ExecutableSteps++
			if st.RiskLevel == "high" {
				hasHigh = true
			}
			switch st.Status {
			case "running":
				ap.CurrentStepIdx = st.Index
			case "succeeded":
				ap.CompletedSteps++
			case "failed":
				ap.FailedSteps++
			case "skipped", "cancelled", "rejected":
				ap.SkippedSteps++
			}
		}
		for _, sid := range st.ServerIDs {
			if sid != "" && !seenID[sid] {
				seenID[sid] = true
				serverIDs = append(serverIDs, sid)
			}
		}
		for _, sname := range st.ServerNames {
			if sname != "" && !seenName[sname] {
				seenName[sname] = true
				serverNames = append(serverNames, sname)
			}
		}
	}

	if len(serverIDs) > 0 {
		ap.ServerIDs = serverIDs
	} else if ap.ServerIDs == nil {
		ap.ServerIDs = []string{}
	}
	if len(serverNames) > 0 {
		ap.ServerNames = serverNames
	} else if ap.ServerNames == nil {
		ap.ServerNames = []string{}
	}

	switch {
	case hasBlocked:
		ap.RiskLevel = "blocked"
	case hasHigh:
		ap.RiskLevel = "high"
	case ap.RiskLevel == "":
		ap.RiskLevel = "medium"
	}
}

// NormalizeExternalApproval migrates legacy flat single-step ExternalApproval records into the unified step-list schema.
func NormalizeExternalApproval(ap *ExternalApproval) {
	if ap == nil {
		return
	}
	if len(ap.Steps) == 0 && (ap.ToolName == "exec_ssh_command" || ap.ToolName == "sftp_write_file" || ap.Command != "" || ap.FilePath != "") {
		tool := ap.ToolName
		if tool == "" {
			if ap.FilePath != "" {
				tool = "sftp_write_file"
			} else {
				tool = "exec_ssh_command"
			}
		}
		stepStatus := "pending"
		selected := true
		switch ap.Status {
		case "rejected":
			stepStatus = "rejected"
			selected = false
		case "approved", "completed":
			if ap.ExecutionError != "" {
				stepStatus = "failed"
				ap.Status = "failed"
			} else {
				stepStatus = "succeeded"
				ap.Status = "completed"
			}
		case "failed":
			stepStatus = "failed"
		}
		stepTitle := ap.Title
		if stepTitle == "" {
			if tool == "sftp_write_file" {
				stepTitle = fmt.Sprintf("修改配置 %s", ap.FilePath)
			} else {
				stepTitle = strings.TrimSpace(ap.Command)
				if len([]rune(stepTitle)) > 48 {
					stepTitle = string([]rune(stepTitle)[:48]) + "..."
				}
			}
		}
		ap.Steps = []ExternalApprovalStep{
			{
				ID:             ap.ID + "-step-1",
				Index:          1,
				Title:          stepTitle,
				ToolName:       tool,
				ServerIDs:      slices.Clone(ap.ServerIDs),
				ServerNames:    slices.Clone(ap.ServerNames),
				RiskLevel:      ap.RiskLevel,
				Reason:         ap.Reason,
				Command:        ap.Command,
				FilePath:       ap.FilePath,
				NewContent:     ap.NewContent,
				DiffPreview:    ap.DiffPreview,
				Selected:       selected,
				Status:         stepStatus,
				ExecutionOut:   ap.ExecutionOut,
				ExecutionError: ap.ExecutionError,
				DurationMs:     ap.DurationMs,
				CompletedAt:    ap.ResolvedAt,
			},
		}
		if ap.Title == "" {
			ap.Title = stepTitle
		}
	}
	if ap.Status == "approved" {
		if ap.ExecutionError != "" {
			ap.Status = "failed"
		} else {
			ap.Status = "completed"
		}
	}
	if ap.Steps == nil {
		ap.Steps = []ExternalApprovalStep{}
	}
	if ap.ToolName == "" {
		ap.ToolName = "change_plan"
	}
	if ap.Title == "" {
		if len(ap.Steps) == 1 && strings.TrimSpace(ap.Steps[0].Title) != "" {
			ap.Title = ap.Steps[0].Title
		} else if len(ap.Steps) > 0 {
			ap.Title = fmt.Sprintf("%d 步变更执行计划", len(ap.Steps))
		} else {
			ap.Title = "外部 AI 变更计划"
		}
	}
	ap.RecalculateSummary()
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
// MCP external AI gateway configuration, global AGENTS.md charter, and memory/context budget preferences.
type AISettings struct {
	ActiveProviderID string             `json:"active_provider_id"`
	DefaultMode      AIExecutionMode    `json:"default_mode"`
	Providers        []AIProviderConfig `json:"providers"`
	Patrol           PatrolConfig       `json:"patrol"`
	MCP              MCPConfig          `json:"mcp"`
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
	ID               string             `json:"id"`
	Role             string             `json:"role"` // "user", "assistant", "tool"
	Content          string             `json:"content"`
	ReasoningContent string             `json:"reasoning_content,omitempty"`
	ProviderState    *AIMessageMeta     `json:"provider_state,omitempty"`
	Usage            *AITokenUsage      `json:"usage,omitempty"`
	ToolCalls        []AIToolCallRecord `json:"tool_calls,omitempty"`
	ToolCallID       string             `json:"tool_call_id,omitempty"`
	ToolName         string             `json:"tool_name,omitempty"`
	IsError          bool               `json:"is_error,omitempty"`
	Timestamp        time.Time          `json:"timestamp"`
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

// PatrolRecord archives a scheduled, manual, or external-MCP inspection run and its optional AI root-cause report.
type PatrolRecord struct {
	ID                 string          `json:"id"`
	StartedAt          time.Time       `json:"started_at"`
	CompletedAt        time.Time       `json:"completed_at"`
	Trigger            string          `json:"trigger"` // "scheduled", "manual", or "external_mcp"
	TotalServers       int             `json:"total_servers"`
	HealthyCount       int             `json:"healthy_count"`
	WarningCount       int             `json:"warning_count"`
	CriticalCount      int             `json:"critical_count"`
	Status             string          `json:"status"` // "healthy", "warning", "critical"
	Findings           []PatrolFinding `json:"findings"`
	AnalysisState      string          `json:"analysis_state,omitempty"` // "", "none", "pending_external", "claimed", "completed", "fallback_completed"
	AISource           string          `json:"ai_source,omitempty"`      // "builtin" or "external_mcp"
	ExternalClient     string          `json:"external_client,omitempty"`
	ClaimedBy          string          `json:"claimed_by,omitempty"`
	ClaimedAt          *time.Time      `json:"claimed_at,omitempty"`
	ExternalDeadlineAt *time.Time      `json:"external_deadline_at,omitempty"`
	AIAnalyzed         bool            `json:"ai_analyzed"`
	AIAnalyzedAt       *time.Time      `json:"ai_analyzed_at,omitempty"`
	AIModel            string          `json:"ai_model,omitempty"`
	AISummary          string          `json:"ai_summary,omitempty"`
	AIRootCause        string          `json:"ai_root_cause,omitempty"`
	AIRecommendations  []string        `json:"ai_recommendations,omitempty"`
	DeepEvidence       []string        `json:"deep_evidence,omitempty"`
	WebhookNotified    bool            `json:"webhook_notified"`
	AIWebhookNotified  bool            `json:"ai_webhook_notified,omitempty"`
	Unread             bool            `json:"unread"`
}

// DefaultPatrolConfig returns safe default thresholds for periodic read-only server patrol.
func DefaultPatrolConfig() PatrolConfig {
	return PatrolConfig{
		Enabled:                 false,
		IntervalMinutes:         60,
		ServerIDs:               []string{},
		CPUWarnPercent:          85,
		MemWarnPercent:          85,
		DiskWarnPercent:         85,
		SSHFailWarnCount:        15,
		CheckListeningPorts:     true,
		CheckPrivilegedUsers:    true,
		AnalysisMode:            PatrolAnalysisBuiltin,
		ExternalFallbackMinutes: 15,
		NotifyPendingApprovals:  true,
		Webhooks:                []WebhookChannel{},
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
		st.AISettings.Patrol.AnalysisMode = def.AnalysisMode
		st.AISettings.Patrol.ExternalFallbackMinutes = def.ExternalFallbackMinutes
		st.AISettings.Patrol.NotifyPendingApprovals = def.NotifyPendingApprovals
	}
	st.AISettings.Patrol.AnalysisMode = NormalizePatrolAnalysisMode(st.AISettings.Patrol.AnalysisMode)
	if st.AISettings.Patrol.ExternalFallbackMinutes <= 0 {
		st.AISettings.Patrol.ExternalFallbackMinutes = 15
	}
	if st.AISettings.Patrol.ServerIDs == nil {
		st.AISettings.Patrol.ServerIDs = []string{}
	}
	if st.AISettings.Patrol.Webhooks == nil {
		st.AISettings.Patrol.Webhooks = []WebhookChannel{}
	}
	if st.AISettings.MCP.DesktopLoopbackPort < 1024 || st.AISettings.MCP.DesktopLoopbackPort > 65535 {
		st.AISettings.MCP.DesktopLoopbackPort = DefaultMCPConfig().DesktopLoopbackPort
	}
	if st.AISettings.MCP.Tokens == nil {
		st.AISettings.MCP.Tokens = []MCPToken{}
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
		st.AISettings.Providers[i].CustomHeaders = nil
		st.AISettings.Providers[i].ExtraBodyJSON = ""
	}
	for i := range st.AISettings.Patrol.Webhooks {
		st.AISettings.Patrol.Webhooks[i].URL = ""
		st.AISettings.Patrol.Webhooks[i].Secret = ""
	}
	for i := range st.AISettings.MCP.Tokens {
		st.AISettings.MCP.Tokens[i].TokenHash = ""
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
	dst.AISettings.Providers = cloneAIProviders(src.AISettings.Providers)
	dst.AISettings.Patrol.ServerIDs = slices.Clone(src.AISettings.Patrol.ServerIDs)
	dst.AISettings.Patrol.Webhooks = slices.Clone(src.AISettings.Patrol.Webhooks)
	dst.AISettings.MCP.Tokens = cloneMCPTokens(src.AISettings.MCP.Tokens)

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
		dst.PatrolRecords[i] = cloneSinglePatrolRecord(rec)
	}
}

func cloneMCPTokens(in []MCPToken) []MCPToken {
	if in == nil {
		return []MCPToken{}
	}
	out := make([]MCPToken, len(in))
	for i, t := range in {
		cp := t
		cp.AllowedServers = slices.Clone(t.AllowedServers)
		out[i] = cp
	}
	return out
}

func cloneSinglePatrolRecord(rec PatrolRecord) PatrolRecord {
	rc := rec
	rc.Findings = make([]PatrolFinding, len(rec.Findings))
	for fi, f := range rec.Findings {
		fc := f
		fc.NewPorts = slices.Clone(f.NewPorts)
		fc.Anomalies = slices.Clone(f.Anomalies)
		rc.Findings[fi] = fc
	}
	rc.AIRecommendations = slices.Clone(rec.AIRecommendations)
	rc.DeepEvidence = slices.Clone(rec.DeepEvidence)
	if rec.ClaimedAt != nil {
		t := *rec.ClaimedAt
		rc.ClaimedAt = &t
	}
	if rec.ExternalDeadlineAt != nil {
		t := *rec.ExternalDeadlineAt
		rc.ExternalDeadlineAt = &t
	}
	if rec.AIAnalyzedAt != nil {
		t := *rec.AIAnalyzedAt
		rc.AIAnalyzedAt = &t
	}
	return rc
}

func cloneExternalApprovalStep(st ExternalApprovalStep) ExternalApprovalStep {
	cp := st
	cp.ServerIDs = slices.Clone(st.ServerIDs)
	cp.ServerNames = slices.Clone(st.ServerNames)
	if st.StartedAt != nil {
		t := *st.StartedAt
		cp.StartedAt = &t
	}
	if st.CompletedAt != nil {
		t := *st.CompletedAt
		cp.CompletedAt = &t
	}
	return cp
}

func cloneExternalApproval(ap ExternalApproval) ExternalApproval {
	cp := ap
	cp.ServerIDs = slices.Clone(ap.ServerIDs)
	cp.ServerNames = slices.Clone(ap.ServerNames)
	if ap.Steps != nil {
		cp.Steps = make([]ExternalApprovalStep, len(ap.Steps))
		for i, st := range ap.Steps {
			cp.Steps[i] = cloneExternalApprovalStep(st)
		}
	} else {
		cp.Steps = []ExternalApprovalStep{}
	}
	if ap.StartedAt != nil {
		t := *ap.StartedAt
		cp.StartedAt = &t
	}
	if ap.ResolvedAt != nil {
		t := *ap.ResolvedAt
		cp.ResolvedAt = &t
	}
	return cp
}

func cloneExternalApprovals(in []ExternalApproval) []ExternalApproval {
	if in == nil {
		return []ExternalApproval{}
	}
	out := make([]ExternalApproval, len(in))
	for i, ap := range in {
		out[i] = cloneExternalApproval(ap)
	}
	return out
}

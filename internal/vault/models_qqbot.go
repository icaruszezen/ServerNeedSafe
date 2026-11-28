package vault

import (
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"
)

// Official QQ Open Platform API v2 endpoints.
const (
	QQBotProdAPIBaseURL    = "https://api.bot.qq.com"
	QQBotSandboxAPIBaseURL = "https://sandbox.api.sgroup.qq.com"
)

// Official QQ Open Platform WebSocket Gateway Intents bitmask constants.
// Reference: https://bot.q.qq.com/wiki/develop/api-v2/dev-prepare/interface-framework/event-emit.html
const (
	QQIntentGuilds              uint32 = 1 << 0  // GUILDS (频道/子频道变更)
	QQIntentGuildMembers        uint32 = 1 << 1  // GUILD_MEMBERS (频道成员变更)
	QQIntentGuildMessages       uint32 = 1 << 9  // GUILD_MESSAGES (私域频道全量消息)
	QQIntentGuildReactions      uint32 = 1 << 10 // GUILD_MESSAGE_REACTIONS (表情表态)
	QQIntentDirectMessage       uint32 = 1 << 12 // DIRECT_MESSAGE (频道私信)
	QQIntentGroupAndC2CEvent    uint32 = 1 << 25 // GROUP_AND_C2C_EVENT (QQ 单聊与群聊事件)
	QQIntentInteraction         uint32 = 1 << 26 // INTERACTION (互动事件)
	QQIntentMessageAudit        uint32 = 1 << 27 // MESSAGE_AUDIT (消息审核事件)
	QQIntentForumsEvent         uint32 = 1 << 28 // FORUMS_EVENT (私域论坛事件)
	QQIntentAudioAction         uint32 = 1 << 29 // AUDIO_ACTION (音频事件)
	QQIntentPublicGuildMessages uint32 = 1 << 30 // PUBLIC_GUILD_MESSAGES (公域频道 @消息)
)

// QQBotTargetType defines the delivery destination category in QQ Open Platform API v2.
type QQBotTargetType string

const (
	QQBotTargetC2C     QQBotTargetType = "c2c"     // QQ single chat (/v2/users/{user_openid}/messages)
	QQBotTargetGroup   QQBotTargetType = "group"   // QQ group (/v2/groups/{group_openid}/messages)
	QQBotTargetChannel QQBotTargetType = "channel" // QQ Guild sub-channel (/channels/{channel_id}/messages)
)

// IsValidQQBotTargetType reports whether t is a supported QQ Bot message target type.
func IsValidQQBotTargetType(t QQBotTargetType) bool {
	switch t {
	case QQBotTargetC2C, QQBotTargetGroup, QQBotTargetChannel:
		return true
	default:
		return false
	}
}

// NormalizeQQBotTargetType lowercases and validates a target type string.
func NormalizeQQBotTargetType(raw QQBotTargetType) QQBotTargetType {
	switch QQBotTargetType(strings.ToLower(strings.TrimSpace(string(raw)))) {
	case QQBotTargetC2C:
		return QQBotTargetC2C
	case QQBotTargetGroup:
		return QQBotTargetGroup
	case QQBotTargetChannel:
		return QQBotTargetChannel
	default:
		return ""
	}
}

// QQBotTarget represents a bound push destination (QQ user openid, group openid, or guild channel_id).
type QQBotTarget struct {
	ID         string          `json:"id"`
	Name       string          `json:"name"`
	TargetType QQBotTargetType `json:"target_type"` // "c2c", "group", "channel"
	TargetID   string          `json:"target_id"`   // user_openid / group_openid / channel_id
	GuildID    string          `json:"guild_id,omitempty"`
	Enabled    bool            `json:"enabled"`
	CreatedAt  time.Time       `json:"created_at"`
}

// QQBotSettings configures the 7x24 QQ Open Platform WebSocket event gateway and notification dispatcher.
// Stored 100% encrypted inside SecretsState (secrets.enc).
type QQBotSettings struct {
	Enabled                 bool          `json:"enabled"`
	AppID                   string        `json:"app_id,omitempty"`
	AppSecret               string        `json:"app_secret,omitempty"`     // Encrypted at rest; never exposed in API views
	Sandbox                 bool          `json:"sandbox,omitempty"`        // false=production (api.bot.qq.com), true=sandbox (sandbox.api.sgroup.qq.com)
	APIBaseURL              string        `json:"api_base_url,omitempty"`   // Optional custom OpenAPI base URL override
	TokenBaseURL            string        `json:"token_base_url,omitempty"` // Optional custom token endpoint base URL override
	Intents                 uint32        `json:"intents,omitempty"`        // Gateway event subscription bitmask
	ShardID                 int           `json:"shard_id,omitempty"`       // Default 0
	ShardCount              int           `json:"shard_count,omitempty"`    // Default 1
	MessageFormat           string        `json:"message_format,omitempty"` // "text" (default) or "markdown"
	PushMode                string        `json:"push_mode,omitempty"`      // "proactive" (default) or "passive_prefer"
	AllowBotCommands        bool          `json:"allow_bot_commands"`       // Enable /bind, /id, and bound-target /status, /alerts, /help
	NotifyMonitorAlerts     bool          `json:"notify_monitor_alerts"`    // Status monitor alert fire / escalate / resolve
	NotifyAIPatrol          bool          `json:"notify_ai_patrol"`         // AI patrol anomalies & enriched reports
	NotifyExternalApprovals bool          `json:"notify_external_approvals"` // External MCP AI pending HITL change plans
	NotifyVulnAdvisories    bool          `json:"notify_vuln_advisories"`   // New high / critical / CISA KEV vulnerability advisories
	Targets                 []QQBotTarget `json:"targets"`
	Initialized             bool          `json:"initialized,omitempty"`
}

// QQBotSettingsView redacts AppSecret when returning settings to Web UI APIs.
type QQBotSettingsView struct {
	Enabled                 bool          `json:"enabled"`
	AppID                   string        `json:"app_id"`
	HasAppSecret            bool          `json:"has_app_secret"`
	AppSecretPreview        string        `json:"app_secret_preview,omitempty"`
	Sandbox                 bool          `json:"sandbox"`
	APIBaseURL              string        `json:"api_base_url,omitempty"`
	TokenBaseURL            string        `json:"token_base_url,omitempty"`
	EffectiveAPIBaseURL     string        `json:"effective_api_base_url"`
	EffectiveTokenBaseURL   string        `json:"effective_token_base_url"`
	Intents                 uint32        `json:"intents"`
	ShardID                 int           `json:"shard_id"`
	ShardCount              int           `json:"shard_count"`
	MessageFormat           string        `json:"message_format"`
	PushMode                string        `json:"push_mode"`
	AllowBotCommands        bool          `json:"allow_bot_commands"`
	NotifyMonitorAlerts     bool          `json:"notify_monitor_alerts"`
	NotifyAIPatrol          bool          `json:"notify_ai_patrol"`
	NotifyExternalApprovals bool          `json:"notify_external_approvals"`
	NotifyVulnAdvisories    bool          `json:"notify_vuln_advisories"`
	Targets                 []QQBotTarget `json:"targets"`
}

// QQBotDiscoveredTarget tracks a QQ user/group/channel observed via inbound WebSocket Dispatch events.
type QQBotDiscoveredTarget struct {
	TargetType         QQBotTargetType `json:"target_type"`
	TargetID           string          `json:"target_id"`
	GuildID            string          `json:"guild_id,omitempty"`
	Label              string          `json:"label,omitempty"`
	LastEventType      string          `json:"last_event_type,omitempty"`
	LastMessagePreview string          `json:"last_message_preview,omitempty"`
	ProactiveRejected  bool            `json:"proactive_rejected,omitempty"`
	LastSeenAt         time.Time       `json:"last_seen_at"`
	HitCount           int             `json:"hit_count"`
}

// QQBotEventRecord captures a recent inbound WebSocket gateway dispatch/control event for diagnostics.
type QQBotEventRecord struct {
	ID         string          `json:"id"`
	Seq        int64           `json:"seq,omitempty"`
	OpCode     int             `json:"op"`
	EventType  string          `json:"event_type"`
	TargetType QQBotTargetType `json:"target_type,omitempty"`
	TargetID   string          `json:"target_id,omitempty"`
	Sender     string          `json:"sender,omitempty"`
	Summary    string          `json:"summary,omitempty"`
	ReceivedAt time.Time       `json:"received_at"`
}

// QQBotPushRecord logs an outbound event notification attempt delivered through QQ Bot API v2.
type QQBotPushRecord struct {
	ID         string          `json:"id"`
	Category   string          `json:"category"` // monitor_alert, ai_patrol, external_approval, vuln_advisory, test
	Title      string          `json:"title"`
	TargetType QQBotTargetType `json:"target_type"`
	TargetID   string          `json:"target_id"`
	TargetName string          `json:"target_name,omitempty"`
	Mode       string          `json:"mode"` // "proactive" or "passive"
	Success    bool            `json:"success"`
	Error      string          `json:"error,omitempty"`
	SentAt     time.Time       `json:"sent_at"`
}

// QQBotRuntimeState stores non-secret runtime observations inside aiops_runtime.json.
type QQBotRuntimeState struct {
	DiscoveredTargets []QQBotDiscoveredTarget `json:"discovered_targets"`
	RecentEvents      []QQBotEventRecord      `json:"recent_events"`
	PushHistory       []QQBotPushRecord       `json:"push_history"`
}

// DefaultQQBotRuntimeState initializes empty slices for non-secret QQ Bot runtime state.
func DefaultQQBotRuntimeState() *QQBotRuntimeState {
	return &QQBotRuntimeState{
		DiscoveredTargets: []QQBotDiscoveredTarget{},
		RecentEvents:      []QQBotEventRecord{},
		PushHistory:       []QQBotPushRecord{},
	}
}

// DefaultQQBotSettings returns safe, ready-to-configure defaults for QQ Open Platform WebSocket notifications.
func DefaultQQBotSettings() QQBotSettings {
	return QQBotSettings{
		Enabled:                 false,
		Intents:                 QQIntentGroupAndC2CEvent,
		ShardID:                 0,
		ShardCount:              1,
		MessageFormat:           "text",
		PushMode:                "proactive",
		AllowBotCommands:        true,
		NotifyMonitorAlerts:     true,
		NotifyAIPatrol:          true,
		NotifyExternalApprovals: true,
		NotifyVulnAdvisories:    false,
		Targets:                 []QQBotTarget{},
	}
}

// EffectiveAPIBaseURL returns the OpenAPI base URL taking Sandbox and optional custom override into account.
func (s QQBotSettings) EffectiveAPIBaseURL() string {
	if custom := strings.TrimRight(strings.TrimSpace(s.APIBaseURL), "/"); custom != "" {
		return custom
	}
	if s.Sandbox {
		return QQBotSandboxAPIBaseURL
	}
	return QQBotProdAPIBaseURL
}

// EffectiveTokenBaseURL returns the access token base URL.
// If TokenBaseURL is omitted and a custom APIBaseURL is configured (e.g. proxy or test server),
// APIBaseURL is reused so single-endpoint overrides work cleanly.
func (s QQBotSettings) EffectiveTokenBaseURL() string {
	if custom := strings.TrimRight(strings.TrimSpace(s.TokenBaseURL), "/"); custom != "" {
		return custom
	}
	if apiCustom := strings.TrimRight(strings.TrimSpace(s.APIBaseURL), "/"); apiCustom != "" {
		return apiCustom
	}
	return QQBotProdAPIBaseURL
}

// SameQQBotSecretDestination checks whether two QQBotSettings target the exact same AppID and API/Token hosts
// so a stored AppSecret is never forwarded to a caller-changed destination.
func SameQQBotSecretDestination(a, b QQBotSettings) bool {
	return strings.TrimSpace(a.AppID) == strings.TrimSpace(b.AppID) &&
		SameEndpointURL(a.EffectiveAPIBaseURL(), b.EffectiveAPIBaseURL()) &&
		SameEndpointURL(a.EffectiveTokenBaseURL(), b.EffectiveTokenBaseURL())
}

// NormalizeQQBotSettings clamps and fills defaults on QQBotSettings cleanly.
func NormalizeQQBotSettings(in QQBotSettings) QQBotSettings {
	if !in.Initialized && !in.Enabled &&
		strings.TrimSpace(in.AppID) == "" &&
		strings.TrimSpace(in.AppSecret) == "" &&
		in.Intents == 0 &&
		len(in.Targets) == 0 &&
		strings.TrimSpace(in.APIBaseURL) == "" &&
		strings.TrimSpace(in.TokenBaseURL) == "" {
		return DefaultQQBotSettings()
	}
	out := in
	out.AppID = strings.TrimSpace(out.AppID)
	out.AppSecret = strings.TrimSpace(out.AppSecret)
	out.APIBaseURL = strings.TrimRight(strings.TrimSpace(out.APIBaseURL), "/")
	out.TokenBaseURL = strings.TrimRight(strings.TrimSpace(out.TokenBaseURL), "/")
	if out.Intents == 0 {
		out.Intents = QQIntentGroupAndC2CEvent
	}
	if out.ShardCount < 1 {
		out.ShardCount = 1
	} else if out.ShardCount > 64 {
		out.ShardCount = 64
	}
	if out.ShardID < 0 {
		out.ShardID = 0
	} else if out.ShardID >= out.ShardCount {
		out.ShardID = out.ShardCount - 1
	}
	switch strings.ToLower(strings.TrimSpace(out.MessageFormat)) {
	case "markdown":
		out.MessageFormat = "markdown"
	default:
		out.MessageFormat = "text"
	}
	switch strings.ToLower(strings.TrimSpace(out.PushMode)) {
	case "passive_prefer":
		out.PushMode = "passive_prefer"
	default:
		out.PushMode = "proactive"
	}
	if out.Targets == nil {
		out.Targets = []QQBotTarget{}
	} else {
		cleaned := make([]QQBotTarget, 0, len(out.Targets))
		for _, t := range out.Targets {
			tt := NormalizeQQBotTargetType(t.TargetType)
			tid := strings.TrimSpace(t.TargetID)
			if tt == "" || tid == "" {
				continue
			}
			t.TargetType = tt
			t.TargetID = tid
			t.GuildID = strings.TrimSpace(t.GuildID)
			t.Name = strings.TrimSpace(t.Name)
			if t.Name == "" {
				t.Name = defaultQQTargetName(tt, tid)
			}
			cleaned = append(cleaned, t)
		}
		out.Targets = cleaned
	}
	return out
}

func defaultQQTargetName(tt QQBotTargetType, tid string) string {
	short := tid
	if len(short) > 10 {
		short = short[:6] + "…" + short[len(short)-4:]
	}
	switch tt {
	case QQBotTargetC2C:
		return "QQ 单聊 " + short
	case QQBotTargetGroup:
		return "QQ 群 " + short
	case QQBotTargetChannel:
		return "QQ 频道 " + short
	default:
		return short
	}
}

func validateOptionalHTTPBaseURL(raw, fieldName string) (string, error) {
	trimmed := strings.TrimRight(strings.TrimSpace(raw), "/")
	if trimmed == "" {
		return "", nil
	}
	u, err := url.Parse(trimmed)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("%w: %s 必须是合法的 http:// 或 https:// 地址", ErrInvalidInput, fieldName)
	}
	return trimmed, nil
}

// ToView returns a secret-redacted QQBotSettingsView suitable for JSON API responses.
func (s QQBotSettings) ToView() QQBotSettingsView {
	norm := NormalizeQQBotSettings(s)
	return QQBotSettingsView{
		Enabled:                 norm.Enabled,
		AppID:                   norm.AppID,
		HasAppSecret:            norm.AppSecret != "",
		AppSecretPreview:        maskSecretPreview(norm.AppSecret),
		Sandbox:                 norm.Sandbox,
		APIBaseURL:              norm.APIBaseURL,
		TokenBaseURL:            norm.TokenBaseURL,
		EffectiveAPIBaseURL:     norm.EffectiveAPIBaseURL(),
		EffectiveTokenBaseURL:   norm.EffectiveTokenBaseURL(),
		Intents:                 norm.Intents,
		ShardID:                 norm.ShardID,
		ShardCount:              norm.ShardCount,
		MessageFormat:           norm.MessageFormat,
		PushMode:                norm.PushMode,
		AllowBotCommands:        norm.AllowBotCommands,
		NotifyMonitorAlerts:     norm.NotifyMonitorAlerts,
		NotifyAIPatrol:          norm.NotifyAIPatrol,
		NotifyExternalApprovals: norm.NotifyExternalApprovals,
		NotifyVulnAdvisories:    norm.NotifyVulnAdvisories,
		Targets:                 slices.Clone(norm.Targets),
	}
}

func cloneQQBotSettings(src QQBotSettings) QQBotSettings {
	cp := src
	cp.Targets = slices.Clone(src.Targets)
	if cp.Targets == nil {
		cp.Targets = []QQBotTarget{}
	}
	return cp
}

func cloneQQBotRuntimeState(src *QQBotRuntimeState) *QQBotRuntimeState {
	if src == nil {
		return DefaultQQBotRuntimeState()
	}
	cp := &QQBotRuntimeState{
		DiscoveredTargets: slices.Clone(src.DiscoveredTargets),
		RecentEvents:      slices.Clone(src.RecentEvents),
		PushHistory:       slices.Clone(src.PushHistory),
	}
	if cp.DiscoveredTargets == nil {
		cp.DiscoveredTargets = []QQBotDiscoveredTarget{}
	}
	if cp.RecentEvents == nil {
		cp.RecentEvents = []QQBotEventRecord{}
	}
	if cp.PushHistory == nil {
		cp.PushHistory = []QQBotPushRecord{}
	}
	return cp
}

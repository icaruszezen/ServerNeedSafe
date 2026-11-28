package qqbot

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

// Official QQ Open Platform Gateway OpCodes.
// Reference: https://bot.q.qq.com/wiki/develop/api-v2/dev-prepare/interface-framework/event-emit.html
const (
	OpDispatch           = 0  // 服务端进行消息推送 (Receive)
	OpHeartbeat          = 1  // 客户端或服务端发送心跳 (Send / Receive)
	OpIdentify           = 2  // 客户端发送鉴权 (Send)
	OpResume             = 6  // 客户端恢复连接 (Send)
	OpReconnect          = 7  // 服务端通知客户端重新连接 (Receive)
	OpInvalidSession     = 9  // Identify 或 Resume 参数无效 (Receive)
	OpHello              = 10 // 建立 WS 连接后网关下发的第一条消息 (Receive)
	OpHeartbeatACK       = 11 // 心跳确认响应 (Receive)
	OpHTTPCallbackACK    = 12 // HTTP 回调模式 ACK
	OpCallbackValidation = 13 // HTTP 回调地址验证
)

// GatewayPayload is the unified JSON envelope used on QQ Bot WebSocket connections.
type GatewayPayload struct {
	ID string          `json:"id,omitempty"`
	Op int             `json:"op"`
	D  json.RawMessage `json:"d,omitempty"`
	S  int64           `json:"s,omitempty"`
	T  string          `json:"t,omitempty"`
}

// HelloData is the payload data of OpCode 10 Hello.
type HelloData struct {
	HeartbeatInterval int `json:"heartbeat_interval"` // milliseconds
}

// IdentifyData is the payload data of OpCode 2 Identify.
type IdentifyData struct {
	Token      string            `json:"token"`
	Intents    uint32            `json:"intents"`
	Shard      [2]int            `json:"shard"`
	Properties map[string]string `json:"properties,omitempty"`
}

// ResumeData is the payload data of OpCode 6 Resume.
type ResumeData struct {
	Token     string `json:"token"`
	SessionID string `json:"session_id"`
	Seq       int64  `json:"seq"`
}

// ReadyUser identifies the authenticated QQ Bot user returned in the READY event.
type ReadyUser struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Bot      bool   `json:"bot"`
}

// ReadyEvent is the payload data of Dispatch event "READY".
type ReadyEvent struct {
	Version   int       `json:"version"`
	SessionID string    `json:"session_id"`
	User      ReadyUser `json:"user"`
	Shard     []int     `json:"shard,omitempty"`
}

// SessionStartLimit reports QQ gateway concurrency & daily session quota from GET /gateway/bot.
type SessionStartLimit struct {
	Total          int `json:"total"`
	Remaining      int `json:"remaining"`
	ResetAfter     int `json:"reset_after"`
	MaxConcurrency int `json:"max_concurrency"`
}

// GatewayInfo is returned by GET /gateway/bot or GET /gateway.
type GatewayInfo struct {
	URL               string             `json:"url"`
	Shards            int                `json:"shards,omitempty"`
	SessionStartLimit *SessionStartLimit `json:"session_start_limit,omitempty"`
}

// FlexInt decodes a JSON integer encoded as either a number (7200) or a quoted string ("7200").
type FlexInt int

func (f *FlexInt) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		*f = 0
		return nil
	}
	if trimmed[0] == '"' {
		var s string
		if err := json.Unmarshal(trimmed, &s); err != nil {
			return err
		}
		s = strings.TrimSpace(s)
		if s == "" {
			*f = 0
			return nil
		}
		n, err := strconv.Atoi(s)
		if err != nil {
			return err
		}
		*f = FlexInt(n)
		return nil
	}
	var n int
	if err := json.Unmarshal(trimmed, &n); err != nil {
		return err
	}
	*f = FlexInt(n)
	return nil
}

// AccessTokenResponse is returned by POST /app/getAppAccessToken.
// Note: QQ Open Platform may return HTTP 200 with a non-zero business `code` on error.
type AccessTokenResponse struct {
	AccessToken string  `json:"access_token"`
	ExpiresIn   FlexInt `json:"expires_in"`
	Code        int     `json:"code"`
	Message     string  `json:"message"`
}

// APIErrorResponse captures standard QQ OpenAPI error payloads.
type APIErrorResponse struct {
	ErrCode int    `json:"err_code"`
	Code    int    `json:"code"`
	Message string `json:"message"`
	TraceID string `json:"trace_id"`
}

func (e APIErrorResponse) EffectiveCode() int {
	if e.ErrCode != 0 {
		return e.ErrCode
	}
	return e.Code
}

// C2CMessageEvent is dispatched for C2C_MESSAGE_CREATE (Intent GROUP_AND_C2C_EVENT).
type C2CMessageEvent struct {
	ID      string `json:"id"`
	Content string `json:"content"`
	Author  struct {
		ID         string `json:"id"`
		UserOpenID string `json:"user_openid"`
		Username   string `json:"username"`
		Bot        bool   `json:"bot"`
	} `json:"author"`
}

// GroupMessageEvent is dispatched for GROUP_AT_MESSAGE_CREATE / GROUP_MESSAGE_CREATE.
type GroupMessageEvent struct {
	ID          string `json:"id"`
	GroupOpenID string `json:"group_openid"`
	Content     string `json:"content"`
	Author      struct {
		ID             string `json:"id"`
		MemberOpenID   string `json:"member_openid"`
		MemberNickname string `json:"member_nickname"`
		Username       string `json:"username"`
		MemberRole     string `json:"member_role"`
		Bot            bool   `json:"bot"`
	} `json:"author"`
}

// GuildMessageEvent is dispatched for AT_MESSAGE_CREATE / MESSAGE_CREATE / DIRECT_MESSAGE_CREATE.
type GuildMessageEvent struct {
	ID        string `json:"id"`
	ChannelID string `json:"channel_id"`
	GuildID   string `json:"guild_id"`
	Content   string `json:"content"`
	Author    struct {
		ID       string `json:"id"`
		Username string `json:"username"`
		Bot      bool   `json:"bot"`
	} `json:"author"`
}

// FriendLifecycleEvent is dispatched for FRIEND_ADD / FRIEND_DEL / C2C_MSG_RECEIVE / C2C_MSG_REJECT.
type FriendLifecycleEvent struct {
	OpenID     string `json:"openid"`
	UserOpenID string `json:"user_openid"`
	Scene      int    `json:"scene"`
	SceneParam string `json:"scene_param"`
}

// GroupLifecycleEvent is dispatched for GROUP_ADD_ROBOT / GROUP_DEL_ROBOT / GROUP_MSG_RECEIVE / GROUP_MSG_REJECT.
type GroupLifecycleEvent struct {
	GroupOpenID    string `json:"group_openid"`
	OpMemberOpenID string `json:"op_member_openid"`
}

// GuildChannelLifecycleEvent is dispatched for CHANNEL_CREATE / CHANNEL_UPDATE / CHANNEL_DELETE.
type GuildChannelLifecycleEvent struct {
	ID      string `json:"id"`
	GuildID string `json:"guild_id"`
	Name    string `json:"name"`
	Type    int    `json:"type"`
}

// MessageAuditEvent is dispatched for MESSAGE_AUDIT_PASS / MESSAGE_AUDIT_REJECT.
type MessageAuditEvent struct {
	AuditID   string `json:"audit_id"`
	MessageID string `json:"message_id"`
	GuildID   string `json:"guild_id"`
	ChannelID string `json:"channel_id"`
}

// CloseAction classifies how the WebSocket supervisor should respond to a gateway close code.
type CloseAction int

const (
	CloseActionReidentify CloseAction = iota // Clear session (or retry identify) with backoff
	CloseActionResume                        // Reconnect and send OpCode 6 Resume
	CloseActionConfigError                   // Invalid intent/shard/auth config — pause reconnect until updated
	CloseActionFatalBanned                   // Bot offline/sandbox-only (4914) or banned (4915) — halt reconnect
)

// ClassifyCloseCode maps official QQ WebSocket gateway close codes to recovery actions and Chinese diagnostics.
func ClassifyCloseCode(code int) (CloseAction, string) {
	switch code {
	case 4008:
		return CloseActionResume, "WebSocket 发送频率过快 (4008)，将退避重连并尝试 Resume 恢复会话"
	case 4009:
		return CloseActionResume, "WebSocket 连接已过期 (4009)，正在重连并执行 Resume 恢复会话"
	case 4006:
		return CloseActionReidentify, "Session ID 已失效 (4006)，将重新执行 Identify 鉴权"
	case 4007:
		return CloseActionReidentify, "消息序列号 seq 异常 (4007)，将重新执行 Identify 鉴权"
	case 4001:
		return CloseActionConfigError, "无效的 Gateway OpCode (4001)"
	case 4002:
		return CloseActionConfigError, "无效的 Gateway Payload (4002)"
	case 4010:
		return CloseActionConfigError, "无效的分片参数 Shard (4010)，请检查分片编号与总分片数配置"
	case 4011:
		return CloseActionConfigError, "当前连接需处理的频道过多 (4011)，请增加分片数"
	case 4012:
		return CloseActionConfigError, "无效的网关协议版本 (4012)"
	case 4013:
		return CloseActionConfigError, "无效的事件订阅 Intents 位图 (4013)，请重新勾选事件订阅项"
	case 4014:
		return CloseActionConfigError, "所选事件订阅 Intents 存在未开通权限 (4014)，请前往 QQ 开放平台检查权限或取消勾选未开通场景（如私域/频道/群聊）"
	case 4914:
		return CloseActionFatalBanned, "机器人已下架且仅允许连接沙箱环境 (4914)，请开启「沙箱环境」或前往 QQ 开放平台检查应用状态"
	case 4915:
		return CloseActionFatalBanned, "机器人已被平台封禁 (4915)，已停止自动重连，请前往 QQ 开放平台申请解封"
	default:
		if code >= 4900 && code <= 4913 {
			return CloseActionReidentify, fmt.Sprintf("QQ 网关内部错误 (%d)，将自动退避重连", code)
		}
		if code == 1000 || code == 1001 {
			return CloseActionResume, fmt.Sprintf("网关连接正常关闭 (%d)，正在重连恢复", code)
		}
		return CloseActionReidentify, fmt.Sprintf("WebSocket 连接断开 (code=%d)，将自动重连", code)
	}
}

// IntentCatalogItem describes one QQ Open Platform WebSocket Intent bit for the Web UI.
type IntentCatalogItem struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	Bit         int    `json:"bit"`
	Value       uint32 `json:"value"`
	Description string `json:"description"`
	Recommended bool   `json:"recommended,omitempty"`
	PrivateOnly bool   `json:"private_only,omitempty"`
}

// IntentCatalog returns the supported QQ Open Platform v2 WebSocket event subscription options.
func IntentCatalog() []IntentCatalogItem {
	return []IntentCatalogItem{
		{
			Key:         "GROUP_AND_C2C_EVENT",
			Name:        "QQ 单聊与群聊事件",
			Bit:         25,
			Value:       vault.QQIntentGroupAndC2CEvent,
			Description: "接收单聊消息、群 @消息、加好友、入群及用户开关主动推送事件（推荐）",
			Recommended: true,
		},
		{
			Key:         "PUBLIC_GUILD_MESSAGES",
			Name:        "QQ 频道公域 @消息",
			Bit:         30,
			Value:       vault.QQIntentPublicGuildMessages,
			Description: "接收 QQ 频道文字子频道内 @机器人 的公域消息（基础默认权限）",
		},
		{
			Key:         "GUILDS",
			Name:        "QQ 频道与子频道变更",
			Bit:         0,
			Value:       vault.QQIntentGuilds,
			Description: "接收加入/退出频道与子频道创建更新事件（基础默认权限）",
		},
		{
			Key:         "DIRECT_MESSAGE",
			Name:        "QQ 频道私信事件",
			Bit:         12,
			Value:       vault.QQIntentDirectMessage,
			Description: "接收频道私信消息创建与撤回事件",
		},
		{
			Key:         "GUILD_MESSAGES",
			Name:        "QQ 频道私域全量消息",
			Bit:         9,
			Value:       vault.QQIntentGuildMessages,
			Description: "接收私域频道子频道内的全部消息（仅私域机器人有权限，否则触发 4014）",
			PrivateOnly: true,
		},
		{
			Key:         "INTERACTION",
			Name:        "互动按钮回调事件",
			Bit:         26,
			Value:       vault.QQIntentInteraction,
			Description: "接收消息按钮/互动组件回调事件",
		},
		{
			Key:         "MESSAGE_AUDIT",
			Name:        "消息审核结果事件",
			Bit:         27,
			Value:       vault.QQIntentMessageAudit,
			Description: "接收频道主动推送消息审核通过/拒绝回调",
		},
	}
}

// MarkdownToQQPlainText strips common Markdown syntax into clean, compact plain text suitable for QQ msg_type=0.
func MarkdownToQQPlainText(md string, maxRunes int) string {
	lines := strings.Split(strings.ReplaceAll(md, "\r\n", "\n"), "\n")
	out := make([]string, 0, len(lines))
	prevBlank := false
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			if len(out) > 0 && !prevBlank {
				out = append(out, "")
				prevBlank = true
			}
			continue
		}
		prevBlank = false
		for strings.HasPrefix(line, "#") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "#"))
		}
		if strings.HasPrefix(line, ">") {
			line = strings.TrimSpace(strings.TrimPrefix(line, ">"))
		}
		line = strings.ReplaceAll(line, "**", "")
		line = strings.ReplaceAll(line, "__", "")
		line = strings.ReplaceAll(line, "`", "")
		out = append(out, line)
	}
	res := strings.TrimSpace(strings.Join(out, "\n"))
	return truncateRunes(res, maxRunes)
}

func truncateRunes(s string, maxRunes int) string {
	if maxRunes <= 0 || utf8.RuneCountInString(s) <= maxRunes {
		return s
	}
	runes := []rune(s)
	if maxRunes <= 1 {
		return string(runes[:maxRunes])
	}
	return string(runes[:maxRunes-1]) + "…"
}

func maskSessionID(sid string) string {
	sid = strings.TrimSpace(sid)
	if sid == "" {
		return ""
	}
	if len(sid) <= 12 {
		return "••••"
	}
	return sid[:6] + "••••" + sid[len(sid)-4:]
}

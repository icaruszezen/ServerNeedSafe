package vault

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	maxQQBotTargets           = 100
	maxQQBotDiscoveredTargets = 100
	maxQQBotRecentEvents      = 60
	maxQQBotPushHistory       = 50
)

// QQBotSettingsUpdateInput carries partial or full configuration updates from the Web UI.
// AppSecret is preserved when omitted ONLY if AppID, Sandbox, APIBaseURL, and TokenBaseURL stay unchanged.
type QQBotSettingsUpdateInput struct {
	Enabled                 *bool          `json:"enabled,omitempty"`
	AppID                   *string        `json:"app_id,omitempty"`
	AppSecret               *string        `json:"app_secret,omitempty"`
	ClearAppSecret          bool           `json:"clear_app_secret,omitempty"`
	Sandbox                 *bool          `json:"sandbox,omitempty"`
	APIBaseURL              *string        `json:"api_base_url,omitempty"`
	TokenBaseURL            *string        `json:"token_base_url,omitempty"`
	Intents                 *uint32        `json:"intents,omitempty"`
	ShardID                 *int           `json:"shard_id,omitempty"`
	ShardCount              *int           `json:"shard_count,omitempty"`
	MessageFormat           *string        `json:"message_format,omitempty"`
	PushMode                *string        `json:"push_mode,omitempty"`
	AllowBotCommands        *bool          `json:"allow_bot_commands,omitempty"`
	NotifyMonitorAlerts     *bool          `json:"notify_monitor_alerts,omitempty"`
	NotifyAIPatrol          *bool          `json:"notify_ai_patrol,omitempty"`
	NotifyExternalApprovals *bool          `json:"notify_external_approvals,omitempty"`
	NotifyVulnAdvisories    *bool          `json:"notify_vuln_advisories,omitempty"`
	Targets                 *[]QQBotTarget `json:"targets,omitempty"`
}

// GetQQBotSettings returns a deep copy of normalized QQBotSettings including AppSecret (for backend engine only).
func (s *Store) GetQQBotSettings() (QQBotSettings, error) {
	s.secMu.RLock()
	defer s.secMu.RUnlock()
	if s.secrets == nil {
		return DefaultQQBotSettings(), ErrVaultLocked
	}
	return cloneQQBotSettings(NormalizeQQBotSettings(s.secrets.QQBotSettings)), nil
}

// GetQQBotSettingsView returns secret-redacted QQ Bot configuration for HTTP APIs.
func (s *Store) GetQQBotSettingsView() (QQBotSettingsView, error) {
	cfg, err := s.GetQQBotSettings()
	if err != nil {
		return DefaultQQBotSettings().ToView(), err
	}
	return cfg.ToView(), nil
}

// UpdateQQBotSettings validates and persists QQ Bot WebSocket settings into encrypted secrets.enc.
func (s *Store) UpdateQQBotSettings(in QQBotSettingsUpdateInput, clientIP string) (QQBotSettingsView, error) {
	var out QQBotSettings
	err := s.mutateSecrets(func(sec *SecretsState) error {
		prev := NormalizeQQBotSettings(sec.QQBotSettings)
		cur := cloneQQBotSettings(prev)

		if in.Enabled != nil {
			cur.Enabled = *in.Enabled
		}
		if in.AppID != nil {
			cur.AppID = strings.TrimSpace(*in.AppID)
		}
		if in.Sandbox != nil {
			cur.Sandbox = *in.Sandbox
		}
		if in.APIBaseURL != nil {
			validated, err := validateOptionalHTTPBaseURL(*in.APIBaseURL, "自定义 OpenAPI 地址")
			if err != nil {
				return err
			}
			cur.APIBaseURL = validated
		}
		if in.TokenBaseURL != nil {
			validated, err := validateOptionalHTTPBaseURL(*in.TokenBaseURL, "自定义 Token 地址")
			if err != nil {
				return err
			}
			cur.TokenBaseURL = validated
		}
		if in.Intents != nil {
			if *in.Intents == 0 {
				return fmt.Errorf("%w: 请至少勾选一项 QQ 开放平台事件订阅 Intents", ErrInvalidInput)
			}
			cur.Intents = *in.Intents
		}
		if in.ShardCount != nil {
			cur.ShardCount = *in.ShardCount
		}
		if in.ShardID != nil {
			cur.ShardID = *in.ShardID
		}
		if in.MessageFormat != nil {
			cur.MessageFormat = strings.TrimSpace(*in.MessageFormat)
		}
		if in.PushMode != nil {
			cur.PushMode = strings.TrimSpace(*in.PushMode)
		}
		if in.AllowBotCommands != nil {
			cur.AllowBotCommands = *in.AllowBotCommands
		}
		if in.NotifyMonitorAlerts != nil {
			cur.NotifyMonitorAlerts = *in.NotifyMonitorAlerts
		}
		if in.NotifyAIPatrol != nil {
			cur.NotifyAIPatrol = *in.NotifyAIPatrol
		}
		if in.NotifyExternalApprovals != nil {
			cur.NotifyExternalApprovals = *in.NotifyExternalApprovals
		}
		if in.NotifyVulnAdvisories != nil {
			cur.NotifyVulnAdvisories = *in.NotifyVulnAdvisories
		}
		if in.Targets != nil {
			if len(*in.Targets) > maxQQBotTargets {
				return fmt.Errorf("%w: QQ 推送目标数量不能超过 %d 个", ErrInvalidInput, maxQQBotTargets)
			}
			now := time.Now().UTC()
			existingByID := make(map[string]QQBotTarget, len(prev.Targets))
			for _, t := range prev.Targets {
				existingByID[t.ID] = t
			}
			nextTargets := make([]QQBotTarget, 0, len(*in.Targets))
			seenKey := make(map[string]bool, len(*in.Targets))
			for _, t := range *in.Targets {
				tt := NormalizeQQBotTargetType(t.TargetType)
				tid := strings.TrimSpace(t.TargetID)
				if tt == "" || tid == "" {
					continue
				}
				dedup := string(tt) + "|" + tid
				if seenKey[dedup] {
					continue
				}
				seenKey[dedup] = true
				id := strings.TrimSpace(t.ID)
				createdAt := now
				if id != "" {
					if old, ok := existingByID[id]; ok && !old.CreatedAt.IsZero() {
						createdAt = old.CreatedAt
					}
				} else {
					id = uuid.NewString()
				}
				name := strings.TrimSpace(t.Name)
				if name == "" {
					name = defaultQQTargetName(tt, tid)
				}
				nextTargets = append(nextTargets, QQBotTarget{
					ID:         id,
					Name:       name,
					TargetType: tt,
					TargetID:   tid,
					GuildID:    strings.TrimSpace(t.GuildID),
					Enabled:    t.Enabled,
					CreatedAt:  createdAt,
				})
			}
			cur.Targets = nextTargets
		}

		// Protect stored AppSecret against silent exfiltration to a changed endpoint or AppID.
		if in.ClearAppSecret {
			cur.AppSecret = ""
		} else {
			suppliedSecret := ""
			if in.AppSecret != nil {
				suppliedSecret = strings.TrimSpace(*in.AppSecret)
			}
			if suppliedSecret != "" {
				cur.AppSecret = suppliedSecret
			} else if prev.AppSecret != "" && !SameQQBotSecretDestination(prev, cur) {
				return fmt.Errorf("%w: 更换 AppID、沙箱环境或接口地址时必须重新填写 AppSecret", ErrInvalidInput)
			}
		}

		if cur.Enabled && (cur.AppID == "" || cur.AppSecret == "") {
			return fmt.Errorf("%w: 启用 QQ 机器人 WebSocket 前请填写完整的 AppID 与 AppSecret", ErrInvalidInput)
		}

		cur.Initialized = true
		norm := NormalizeQQBotSettings(cur)
		sec.QQBotSettings = norm
		out = cloneQQBotSettings(norm)
		return nil
	})
	if err != nil {
		return QQBotSettingsView{}, err
	}

	s.RecordAudit(
		"qqbot.config",
		"qqbot-websocket",
		fmt.Sprintf("更新 QQ 机器人 WebSocket 配置 (启用=%v, 沙箱=%v, Intents=%d, 绑定目标=%d)", out.Enabled, out.Sandbox, out.Intents, len(out.Targets)),
		clientIP,
		true,
	)
	return out.ToView(), nil
}

// ResolveQQBotSettingsForTransientCall merges caller-supplied overrides with stored QQBotSettings
// for transient probe/test calls while enforcing that stored AppSecret is NEVER sent to a changed destination.
func (s *Store) ResolveQQBotSettingsForTransientCall(in QQBotSettingsUpdateInput) (QQBotSettings, error) {
	stored, err := s.GetQQBotSettings()
	if err != nil {
		return DefaultQQBotSettings(), err
	}
	cur := cloneQQBotSettings(stored)
	if in.AppID != nil && strings.TrimSpace(*in.AppID) != "" {
		cur.AppID = strings.TrimSpace(*in.AppID)
	}
	if in.Sandbox != nil {
		cur.Sandbox = *in.Sandbox
	}
	if in.APIBaseURL != nil {
		validated, err := validateOptionalHTTPBaseURL(*in.APIBaseURL, "自定义 OpenAPI 地址")
		if err != nil {
			return DefaultQQBotSettings(), err
		}
		cur.APIBaseURL = validated
	}
	if in.TokenBaseURL != nil {
		validated, err := validateOptionalHTTPBaseURL(*in.TokenBaseURL, "自定义 Token 地址")
		if err != nil {
			return DefaultQQBotSettings(), err
		}
		cur.TokenBaseURL = validated
	}
	if in.Intents != nil && *in.Intents != 0 {
		cur.Intents = *in.Intents
	}
	if in.ShardCount != nil {
		cur.ShardCount = *in.ShardCount
	}
	if in.ShardID != nil {
		cur.ShardID = *in.ShardID
	}
	if in.MessageFormat != nil && strings.TrimSpace(*in.MessageFormat) != "" {
		cur.MessageFormat = strings.TrimSpace(*in.MessageFormat)
	}
	if in.PushMode != nil && strings.TrimSpace(*in.PushMode) != "" {
		cur.PushMode = strings.TrimSpace(*in.PushMode)
	}

	suppliedSecret := ""
	if in.AppSecret != nil {
		suppliedSecret = strings.TrimSpace(*in.AppSecret)
	}
	if suppliedSecret != "" {
		cur.AppSecret = suppliedSecret
	} else if stored.AppSecret != "" && !SameQQBotSecretDestination(stored, cur) {
		cur.AppSecret = ""
		return DefaultQQBotSettings(), fmt.Errorf("%w: 更换 AppID、沙箱环境或接口地址时必须重新填写 AppSecret", ErrInvalidInput)
	}
	return NormalizeQQBotSettings(cur), nil
}

// UpsertQQBotTarget adds or updates a bound QQ notification target (c2c / group / channel).
func (s *Store) UpsertQQBotTarget(in QQBotTarget, clientIP string) (QQBotTarget, QQBotSettingsView, error) {
	tt := NormalizeQQBotTargetType(in.TargetType)
	if !IsValidQQBotTargetType(tt) {
		return QQBotTarget{}, QQBotSettingsView{}, fmt.Errorf("%w: 不支持的 QQ 推送目标类型（仅支持 c2c / group / channel）", ErrInvalidInput)
	}
	tid := strings.TrimSpace(in.TargetID)
	if tid == "" {
		return QQBotTarget{}, QQBotSettingsView{}, fmt.Errorf("%w: 目标 OpenID / ChannelID 不能为空", ErrInvalidInput)
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = defaultQQTargetName(tt, tid)
	}
	guildID := strings.TrimSpace(in.GuildID)

	var saved QQBotTarget
	var outView QQBotSettingsView
	err := s.mutateSecrets(func(sec *SecretsState) error {
		cur := NormalizeQQBotSettings(sec.QQBotSettings)
		now := time.Now().UTC()
		updated := false
		for i := range cur.Targets {
			if (in.ID != "" && cur.Targets[i].ID == in.ID) ||
				(cur.Targets[i].TargetType == tt && cur.Targets[i].TargetID == tid) {
				cur.Targets[i].Name = name
				cur.Targets[i].TargetType = tt
				cur.Targets[i].TargetID = tid
				if guildID != "" {
					cur.Targets[i].GuildID = guildID
				}
				cur.Targets[i].Enabled = in.Enabled
				saved = cur.Targets[i]
				updated = true
				break
			}
		}
		if !updated {
			if len(cur.Targets) >= maxQQBotTargets {
				return fmt.Errorf("%w: QQ 推送目标数量已达上限（%d 个）", ErrInvalidInput, maxQQBotTargets)
			}
			saved = QQBotTarget{
				ID:         uuid.NewString(),
				Name:       name,
				TargetType: tt,
				TargetID:   tid,
				GuildID:    guildID,
				Enabled:    in.Enabled,
				CreatedAt:  now,
			}
			cur.Targets = append(cur.Targets, saved)
		}
		cur.Initialized = true
		sec.QQBotSettings = NormalizeQQBotSettings(cur)
		outView = sec.QQBotSettings.ToView()
		return nil
	})
	if err != nil {
		return QQBotTarget{}, QQBotSettingsView{}, err
	}
	s.RecordAudit("qqbot.target_upsert", saved.Name, fmt.Sprintf("绑定/更新 QQ 通知目标 (%s: %s, 启用=%v)", saved.TargetType, saved.TargetID, saved.Enabled), clientIP, true)
	return saved, outView, nil
}

// DeleteQQBotTarget removes a bound QQ notification target by ID.
func (s *Store) DeleteQQBotTarget(id, clientIP string) (QQBotSettingsView, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return QQBotSettingsView{}, ErrInvalidInput
	}
	var deletedName string
	var outView QQBotSettingsView
	err := s.mutateSecrets(func(sec *SecretsState) error {
		cur := NormalizeQQBotSettings(sec.QQBotSettings)
		for i, t := range cur.Targets {
			if t.ID == id {
				deletedName = t.Name
				cur.Targets = slices.Delete(cur.Targets, i, i+1)
				cur.Initialized = true
				sec.QQBotSettings = NormalizeQQBotSettings(cur)
				outView = sec.QQBotSettings.ToView()
				return nil
			}
		}
		return ErrNotFound
	})
	if err != nil {
		return QQBotSettingsView{}, err
	}
	s.RecordAudit("qqbot.target_delete", deletedName, "移除 QQ 通知目标", clientIP, true)
	return outView, nil
}

// --- Non-Secret Runtime Persistence (stored inside aiops_runtime.json, never touches secrets.enc) ---

func (s *Store) ensureQQBotRuntimeLocked() *QQBotRuntimeState {
	if s.aiopsRT == nil {
		s.aiopsRT = DefaultAIOpsRuntimeState(time.Now().UTC())
	}
	if s.aiopsRT.QQBot == nil {
		s.aiopsRT.QQBot = DefaultQQBotRuntimeState()
	}
	return s.aiopsRT.QQBot
}

// RecordQQBotDiscoveredTarget upserts a discovered QQ user/group/channel from inbound WebSocket events.
func (s *Store) RecordQQBotDiscoveredTarget(dt QQBotDiscoveredTarget, setProactiveRejected *bool) {
	if !s.IsReady() {
		return
	}
	dt.TargetType = NormalizeQQBotTargetType(dt.TargetType)
	dt.TargetID = strings.TrimSpace(dt.TargetID)
	if dt.TargetType == "" || dt.TargetID == "" {
		return
	}
	if dt.LastSeenAt.IsZero() {
		dt.LastSeenAt = time.Now().UTC()
	}

	s.rtMu.Lock()
	rt := s.ensureQQBotRuntimeLocked()
	found := false
	for i := range rt.DiscoveredTargets {
		cur := &rt.DiscoveredTargets[i]
		if cur.TargetType == dt.TargetType && cur.TargetID == dt.TargetID {
			if strings.TrimSpace(dt.GuildID) != "" {
				cur.GuildID = strings.TrimSpace(dt.GuildID)
			}
			if strings.TrimSpace(dt.Label) != "" {
				cur.Label = strings.TrimSpace(dt.Label)
			}
			if strings.TrimSpace(dt.LastEventType) != "" {
				cur.LastEventType = strings.TrimSpace(dt.LastEventType)
			}
			if strings.TrimSpace(dt.LastMessagePreview) != "" {
				cur.LastMessagePreview = strings.TrimSpace(dt.LastMessagePreview)
			}
			if setProactiveRejected != nil {
				cur.ProactiveRejected = *setProactiveRejected
			}
			cur.LastSeenAt = dt.LastSeenAt
			cur.HitCount++
			found = true
			break
		}
	}
	if !found {
		if dt.HitCount <= 0 {
			dt.HitCount = 1
		}
		if setProactiveRejected != nil {
			dt.ProactiveRejected = *setProactiveRejected
		}
		rt.DiscoveredTargets = append([]QQBotDiscoveredTarget{dt}, rt.DiscoveredTargets...)
	}
	sort.SliceStable(rt.DiscoveredTargets, func(i, j int) bool {
		return rt.DiscoveredTargets[i].LastSeenAt.After(rt.DiscoveredTargets[j].LastSeenAt)
	})
	if len(rt.DiscoveredTargets) > maxQQBotDiscoveredTargets {
		rt.DiscoveredTargets = rt.DiscoveredTargets[:maxQQBotDiscoveredTargets]
	}
	s.dirtyAIOps = true
	s.rtMu.Unlock()
	s.triggerFlush()
}

// RecordQQBotEvent appends a gateway event record to the rolling diagnostics log.
func (s *Store) RecordQQBotEvent(ev QQBotEventRecord) {
	if !s.IsReady() {
		return
	}
	if ev.ID == "" {
		ev.ID = uuid.NewString()
	}
	if ev.ReceivedAt.IsZero() {
		ev.ReceivedAt = time.Now().UTC()
	}
	s.rtMu.Lock()
	rt := s.ensureQQBotRuntimeLocked()
	rt.RecentEvents = append([]QQBotEventRecord{ev}, rt.RecentEvents...)
	if len(rt.RecentEvents) > maxQQBotRecentEvents {
		rt.RecentEvents = rt.RecentEvents[:maxQQBotRecentEvents]
	}
	s.dirtyAIOps = true
	s.rtMu.Unlock()
	s.triggerFlush()
}

// RecordQQBotPush appends an outbound notification delivery record to the rolling push log.
func (s *Store) RecordQQBotPush(rec QQBotPushRecord) {
	if !s.IsReady() {
		return
	}
	if rec.ID == "" {
		rec.ID = uuid.NewString()
	}
	if rec.SentAt.IsZero() {
		rec.SentAt = time.Now().UTC()
	}
	s.rtMu.Lock()
	rt := s.ensureQQBotRuntimeLocked()
	rt.PushHistory = append([]QQBotPushRecord{rec}, rt.PushHistory...)
	if len(rt.PushHistory) > maxQQBotPushHistory {
		rt.PushHistory = rt.PushHistory[:maxQQBotPushHistory]
	}
	s.dirtyAIOps = true
	s.rtMu.Unlock()
	s.triggerFlush()
}

// GetQQBotRuntimeSnapshot returns a deep copy of QQ Bot runtime observations.
func (s *Store) GetQQBotRuntimeSnapshot() QQBotRuntimeState {
	if !s.IsReady() {
		return *DefaultQQBotRuntimeState()
	}
	s.rtMu.RLock()
	defer s.rtMu.RUnlock()
	if s.aiopsRT == nil || s.aiopsRT.QQBot == nil {
		return *DefaultQQBotRuntimeState()
	}
	return *cloneQQBotRuntimeState(s.aiopsRT.QQBot)
}

// ClearQQBotRuntimeLogs clears recent gateway events and push history while keeping discovered targets intact.
func (s *Store) ClearQQBotRuntimeLogs(includeDiscovered bool) {
	if !s.IsReady() {
		return
	}
	s.rtMu.Lock()
	rt := s.ensureQQBotRuntimeLocked()
	rt.RecentEvents = []QQBotEventRecord{}
	rt.PushHistory = []QQBotPushRecord{}
	if includeDiscovered {
		rt.DiscoveredTargets = []QQBotDiscoveredTarget{}
	}
	s.dirtyAIOps = true
	s.rtMu.Unlock()
	s.triggerFlush()
}

package qqbot

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

const (
	bindCodeAlphabet   = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	bindCodeLength     = 6
	bindCodeTTL        = 10 * time.Minute
	dedupCacheLimit    = 512
	passiveC2CTTL      = 55 * time.Minute
	passiveGroupTTL    = 55 * time.Minute
	passiveChannelTTL  = 4*time.Minute + 30*time.Second
	passiveC2CMaxSeq   = 4
	passiveGroupMaxSeq = 5
	passiveChanMaxSeq  = 2
)

// ServiceConfig configures the QQ Open Platform WebSocket gateway and notification service.
type ServiceConfig struct {
	Store                *vault.Store
	HTTPClient           *http.Client
	WSDialer             *websocket.Dialer
	DisableAutoLoop      bool
	MinHeartbeatInterval time.Duration // Testing hook; defaults to 5s
	BaseReconnectBackoff time.Duration // Testing hook; defaults to 2s
	MaxReconnectBackoff  time.Duration // Testing hook; defaults to 60s
}

// BindCodeInfo represents an active single-use bind verification code.
type BindCodeInfo struct {
	Code      string    `json:"code"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ProbeResult reports the outcome of a transient AccessToken + Gateway + Hello probe.
type ProbeResult struct {
	OK                  bool   `json:"ok"`
	LatencyMs           int64  `json:"latency_ms"`
	GatewayURL          string `json:"gateway_url"`
	RecommendedShards   int    `json:"recommended_shards,omitempty"`
	SessionTotal        int    `json:"session_total,omitempty"`
	SessionRemaining    int    `json:"session_remaining,omitempty"`
	HeartbeatIntervalMs int    `json:"heartbeat_interval_ms,omitempty"`
}

// RuntimeStatus summarizes live WebSocket gateway connection and notification delivery health.
type RuntimeStatus struct {
	State               string        `json:"state"` // disabled, connecting, identifying, resuming, connected, reconnecting, error, stopped_error
	Connected           bool          `json:"connected"`
	GatewayURL          string        `json:"gateway_url,omitempty"`
	BotUserID           string        `json:"bot_user_id,omitempty"`
	BotUsername         string        `json:"bot_username,omitempty"`
	SessionIDMasked     string        `json:"session_id_masked,omitempty"`
	LastSeq             int64         `json:"last_seq"`
	Shard               [2]int        `json:"shard"`
	RecommendedShards   int           `json:"recommended_shards,omitempty"`
	SessionTotal        int           `json:"session_total,omitempty"`
	SessionRemaining    int           `json:"session_remaining,omitempty"`
	HeartbeatIntervalMs int           `json:"heartbeat_interval_ms,omitempty"`
	HeartbeatLatencyMs  int64         `json:"heartbeat_latency_ms,omitempty"`
	LastHeartbeatAckAt  *time.Time    `json:"last_heartbeat_ack_at,omitempty"`
	ConnectedSince      *time.Time    `json:"connected_since,omitempty"`
	ReconnectCount      int           `json:"reconnect_count"`
	ResumeCount         int           `json:"resume_count"`
	EventsReceived      int64         `json:"events_received"`
	PushSuccessCount    int64         `json:"push_success_count"`
	PushFailureCount    int64         `json:"push_failure_count"`
	LastPushAt          *time.Time    `json:"last_push_at,omitempty"`
	LastPushError       string        `json:"last_push_error,omitempty"`
	LastError           string        `json:"last_error,omitempty"`
	ActiveBindCode      *BindCodeInfo `json:"active_bind_code,omitempty"`
}

// EventMessage is a normalized ServerNeedSafe notification ready for QQ Bot delivery.
type EventMessage struct {
	Category  string // "monitor_alert", "ai_patrol", "external_approval", "vuln_advisory", "test"
	Title     string
	PlainText string
	Markdown  string
}

// TargetDeliveryResult reports per-target delivery outcome for test pushes and summaries.
type TargetDeliveryResult struct {
	TargetID      string                `json:"target_id"`
	TargetType    vault.QQBotTargetType `json:"target_type"`
	TargetName    string                `json:"target_name"`
	Mode          string                `json:"mode"` // "proactive" or "passive"
	Success       bool                  `json:"success"`
	AuditPending  bool                  `json:"audit_pending,omitempty"`
	FallbackPlain bool                  `json:"fallback_plain,omitempty"`
	Error         string                `json:"error,omitempty"`
}

// DispatchSummary aggregates delivery results across bound targets.
type DispatchSummary struct {
	Total   int                    `json:"total"`
	Sent    int                    `json:"sent"`
	Failed  int                    `json:"failed"`
	Results []TargetDeliveryResult `json:"results"`
}

type passiveReplySlot struct {
	msgID     string
	eventID   string
	expiresAt time.Time
	usedSeq   int
	maxSeq    int
}

// Service manages the 7x24 QQ Open Platform WebSocket connection, inbound event processing,
// automatic target discovery, one-time bind codes, and outbound event notification delivery.
type Service struct {
	store           *vault.Store
	client          *APIClient
	wsDialer        *websocket.Dialer
	disableAutoLoop bool
	minHeartbeat    time.Duration
	baseBackoff     time.Duration
	maxBackoff      time.Duration

	wakeCh    chan struct{}
	stopCh    chan struct{}
	doneCh    chan struct{}
	startOnce sync.Once
	closeOnce sync.Once
	started   bool

	mu                  sync.RWMutex
	state               string
	connected           bool
	gatewayURL          string
	botUserID           string
	botUsername         string
	sessionID           string
	lastSeq             int64
	canResume           bool
	pausedError         bool
	lastConfigSig       string
	recommendedShards   int
	sessionTotal        int
	sessionRemaining    int
	heartbeatIntervalMs int
	heartbeatLatencyMs  int64
	lastHeartbeatAckAt  *time.Time
	connectedSince      *time.Time
	reconnectCount      int
	resumeCount         int
	eventsReceived      int64
	pushSuccessCount    int64
	pushFailureCount    int64
	lastPushAt          *time.Time
	lastPushError       string
	lastError           string
	sessionCancel       context.CancelFunc

	bindMu   sync.Mutex
	bindCode *BindCodeInfo

	dedupMu    sync.Mutex
	dedupOrder []string
	dedupSet   map[string]struct{}

	passiveMu    sync.Mutex
	passiveSlots map[string]*passiveReplySlot

	eventWG sync.WaitGroup
}

// NewService constructs a QQ Bot WebSocket event gateway & notification service.
func NewService(cfg ServiceConfig) *Service {
	return &Service{
		store:           cfg.Store,
		client:          NewAPIClient(cfg.HTTPClient),
		wsDialer:        cfg.WSDialer,
		disableAutoLoop: cfg.DisableAutoLoop,
		minHeartbeat:    cfg.MinHeartbeatInterval,
		baseBackoff:     cfg.BaseReconnectBackoff,
		maxBackoff:      cfg.MaxReconnectBackoff,
		wakeCh:          make(chan struct{}, 1),
		stopCh:          make(chan struct{}),
		doneCh:          make(chan struct{}),
		state:           "disabled",
		dedupSet:        make(map[string]struct{}, dedupCacheLimit),
		passiveSlots:    make(map[string]*passiveReplySlot),
	}
}

func (s *Service) effectiveMinHeartbeat() time.Duration {
	if s.minHeartbeat > 0 {
		return s.minHeartbeat
	}
	return defaultMinHeartbeatInterval
}

func (s *Service) effectiveBaseBackoff() time.Duration {
	if s.baseBackoff > 0 {
		return s.baseBackoff
	}
	return defaultBaseReconnectBackoff
}

func (s *Service) effectiveMaxBackoff() time.Duration {
	if s.maxBackoff > 0 {
		return s.maxBackoff
	}
	return defaultMaxReconnectBackoff
}

// Start launches the background WebSocket gateway supervisor (unless DisableAutoLoop is true).
func (s *Service) Start() {
	if s.disableAutoLoop {
		return
	}
	s.startOnce.Do(func() {
		s.started = true
		if s.store != nil {
			s.store.RegisterOnReady(func() {
				s.NotifyConfigUpdated()
			})
		}
		go s.supervisorLoop()
	})
}

// Close shuts down the WebSocket supervisor and waits cleanly for in-flight event handlers.
func (s *Service) Close() {
	s.closeOnce.Do(func() {
		close(s.stopCh)
		s.mu.Lock()
		cancel := s.sessionCancel
		s.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		if s.started {
			<-s.doneCh
		}
		s.eventWG.Wait()
	})
}

// NotifyConfigUpdated wakes the supervisor and restarts the WebSocket session if needed.
func (s *Service) NotifyConfigUpdated() {
	s.client.InvalidateToken()
	s.mu.Lock()
	s.pausedError = false
	cancel := s.sessionCancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	s.wake()
}

// ReconnectNow forces a fresh WebSocket reconnect (clearing paused error state and session state).
func (s *Service) ReconnectNow() {
	s.client.InvalidateToken()
	s.mu.Lock()
	s.pausedError = false
	s.sessionID = ""
	s.lastSeq = 0
	s.canResume = false
	s.lastError = ""
	cancel := s.sessionCancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	s.wake()
}

func (s *Service) wake() {
	select {
	case s.wakeCh <- struct{}{}:
	default:
	}
}

func (s *Service) waitForWakeOrTimeout(d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-s.stopCh:
		return false
	case <-s.wakeCh:
		return true
	case <-timer.C:
		return true
	}
}

func (s *Service) setStoppedState(state, errMsg string) {
	s.mu.Lock()
	s.state = state
	s.connected = false
	s.connectedSince = nil
	if errMsg != "" {
		s.lastError = errMsg
	} else if state == "disabled" {
		s.lastError = ""
	}
	s.mu.Unlock()
}

func (s *Service) resetSessionResumeState() {
	s.mu.Lock()
	s.sessionID = ""
	s.lastSeq = 0
	s.canResume = false
	s.pausedError = false
	s.mu.Unlock()
}

func configFingerprint(cfg vault.QQBotSettings) string {
	return fmt.Sprintf("%v|%s|%s|%v|%s|%s|%d|%d|%d",
		cfg.Enabled,
		cfg.AppID,
		cfg.AppSecret,
		cfg.Sandbox,
		cfg.APIBaseURL,
		cfg.TokenBaseURL,
		cfg.Intents,
		cfg.ShardID,
		cfg.ShardCount,
	)
}

// Status returns a consistent point-in-time snapshot of the WebSocket gateway runtime status.
func (s *Service) Status() RuntimeStatus {
	var shard [2]int
	shard[1] = 1
	if s.store != nil && s.store.IsReady() {
		if cfg, err := s.store.GetQQBotSettings(); err == nil {
			shard = [2]int{cfg.ShardID, cfg.ShardCount}
		}
	}

	s.mu.RLock()
	st := RuntimeStatus{
		State:               s.state,
		Connected:           s.connected,
		GatewayURL:          s.gatewayURL,
		BotUserID:           s.botUserID,
		BotUsername:         s.botUsername,
		SessionIDMasked:     maskSessionID(s.sessionID),
		LastSeq:             s.lastSeq,
		Shard:               shard,
		RecommendedShards:   s.recommendedShards,
		SessionTotal:        s.sessionTotal,
		SessionRemaining:    s.sessionRemaining,
		HeartbeatIntervalMs: s.heartbeatIntervalMs,
		HeartbeatLatencyMs:  s.heartbeatLatencyMs,
		ReconnectCount:      s.reconnectCount,
		ResumeCount:         s.resumeCount,
		EventsReceived:      s.eventsReceived,
		PushSuccessCount:    s.pushSuccessCount,
		PushFailureCount:    s.pushFailureCount,
		LastPushError:       s.lastPushError,
		LastError:           s.lastError,
	}
	if s.lastHeartbeatAckAt != nil {
		t := *s.lastHeartbeatAckAt
		st.LastHeartbeatAckAt = &t
	}
	if s.connectedSince != nil {
		t := *s.connectedSince
		st.ConnectedSince = &t
	}
	if s.lastPushAt != nil {
		t := *s.lastPushAt
		st.LastPushAt = &t
	}
	s.mu.RUnlock()

	s.bindMu.Lock()
	if s.bindCode != nil && time.Now().UTC().Before(s.bindCode.ExpiresAt) {
		cp := *s.bindCode
		st.ActiveBindCode = &cp
	}
	s.bindMu.Unlock()

	return st
}

// GenerateBindCode creates a cryptographically random 6-character single-use bind code valid for 10 minutes.
func (s *Service) GenerateBindCode() BindCodeInfo {
	buf := make([]byte, bindCodeLength)
	_, _ = rand.Read(buf)
	out := make([]byte, bindCodeLength)
	for i := range buf {
		out[i] = bindCodeAlphabet[int(buf[i])%len(bindCodeAlphabet)]
	}
	info := BindCodeInfo{
		Code:      string(out),
		ExpiresAt: time.Now().UTC().Add(bindCodeTTL),
	}
	s.bindMu.Lock()
	s.bindCode = &info
	s.bindMu.Unlock()
	return info
}

func (s *Service) consumeBindCode(candidate string) bool {
	cand := strings.ToUpper(strings.TrimSpace(candidate))
	if len(cand) != bindCodeLength {
		return false
	}
	s.bindMu.Lock()
	defer s.bindMu.Unlock()
	if s.bindCode == nil || !time.Now().UTC().Before(s.bindCode.ExpiresAt) {
		s.bindCode = nil
		return false
	}
	if subtle.ConstantTimeCompare([]byte(cand), []byte(s.bindCode.Code)) == 1 {
		s.bindCode = nil
		return true
	}
	return false
}

// --- Inbound Dispatch Event Processing, Target Auto-Discovery & Interactive Bot Commands ---

func (s *Service) isDuplicateEvent(key string) bool {
	key = strings.TrimSpace(key)
	if key == "" {
		return false
	}
	s.dedupMu.Lock()
	defer s.dedupMu.Unlock()
	if _, exists := s.dedupSet[key]; exists {
		return true
	}
	s.dedupSet[key] = struct{}{}
	s.dedupOrder = append(s.dedupOrder, key)
	if len(s.dedupOrder) > dedupCacheLimit {
		evict := s.dedupOrder[0]
		s.dedupOrder = s.dedupOrder[1:]
		delete(s.dedupSet, evict)
	}
	return false
}

func passiveSlotKey(tt vault.QQBotTargetType, tid string) string {
	return string(tt) + ":" + tid
}

func (s *Service) rememberPassiveSlot(tt vault.QQBotTargetType, tid, msgID, eventID string) {
	if tt == "" || tid == "" || (msgID == "" && eventID == "") {
		return
	}
	ttl := passiveC2CTTL
	maxSeq := passiveC2CMaxSeq
	switch tt {
	case vault.QQBotTargetGroup:
		ttl = passiveGroupTTL
		maxSeq = passiveGroupMaxSeq
	case vault.QQBotTargetChannel:
		ttl = passiveChannelTTL
		maxSeq = passiveChanMaxSeq
	}
	s.passiveMu.Lock()
	s.passiveSlots[passiveSlotKey(tt, tid)] = &passiveReplySlot{
		msgID:     msgID,
		eventID:   eventID,
		expiresAt: time.Now().UTC().Add(ttl),
		usedSeq:   0,
		maxSeq:    maxSeq,
	}
	s.passiveMu.Unlock()
}

func (s *Service) takePassiveSlot(tt vault.QQBotTargetType, tid string) (msgID, eventID string, seq int, ok bool) {
	key := passiveSlotKey(tt, tid)
	s.passiveMu.Lock()
	defer s.passiveMu.Unlock()
	slot, exists := s.passiveSlots[key]
	if !exists || slot == nil {
		return "", "", 0, false
	}
	if time.Now().UTC().After(slot.expiresAt) || slot.usedSeq >= slot.maxSeq {
		delete(s.passiveSlots, key)
		return "", "", 0, false
	}
	slot.usedSeq++
	return slot.msgID, slot.eventID, slot.usedSeq, true
}

func (s *Service) recordControlEvent(p GatewayPayload, eventType, summary string) {
	if s.store == nil {
		return
	}
	s.store.RecordQQBotEvent(vault.QQBotEventRecord{
		ID:         p.ID,
		Seq:        p.S,
		OpCode:     p.Op,
		EventType:  eventType,
		Summary:    summary,
		ReceivedAt: time.Now().UTC(),
	})
}

func (s *Service) handleDispatchAsync(ctx context.Context, cfg vault.QQBotSettings, payload GatewayPayload) {
	s.eventWG.Add(1)
	go func() {
		defer s.eventWG.Done()
		evCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		s.handleDispatchEvent(evCtx, cfg, payload)
	}()
}

func (s *Service) handleDispatchEvent(ctx context.Context, cfg vault.QQBotSettings, payload GatewayPayload) {
	// Refresh latest settings so newly bound targets / toggles apply immediately without reconnect
	if s.store != nil {
		if latest, err := s.store.GetQQBotSettings(); err == nil {
			cfg = latest
		}
	}

	now := time.Now().UTC()
	falseVal := false
	trueVal := true

	switch payload.T {
	case "C2C_MESSAGE_CREATE":
		var ev C2CMessageEvent
		if err := json.Unmarshal(payload.D, &ev); err != nil {
			return
		}
		if ev.Author.Bot {
			return
		}
		dedupKey := "c2c:" + nonEmptyStr(ev.ID, payload.ID)
		if s.isDuplicateEvent(dedupKey) {
			return
		}
		userID := nonEmptyStr(ev.Author.UserOpenID, ev.Author.ID)
		label := nonEmptyStr(ev.Author.Username, "QQ 用户")
		content := strings.TrimSpace(ev.Content)
		if s.store != nil {
			s.store.RecordQQBotDiscoveredTarget(vault.QQBotDiscoveredTarget{
				TargetType:         vault.QQBotTargetC2C,
				TargetID:           userID,
				Label:              label,
				LastEventType:      payload.T,
				LastMessagePreview: truncateRunes(content, 80),
				LastSeenAt:         now,
			}, &falseVal)
			s.store.RecordQQBotEvent(vault.QQBotEventRecord{
				ID:         nonEmptyStr(payload.ID, ev.ID),
				Seq:        payload.S,
				OpCode:     payload.Op,
				EventType:  payload.T,
				TargetType: vault.QQBotTargetC2C,
				TargetID:   userID,
				Sender:     label,
				Summary:    truncateRunes(content, 100),
				ReceivedAt: now,
			})
		}
		s.rememberPassiveSlot(vault.QQBotTargetC2C, userID, ev.ID, payload.ID)
		s.maybeHandleCommand(ctx, cfg, vault.QQBotTargetC2C, userID, "", label, ev.ID, content)

	case "GROUP_AT_MESSAGE_CREATE", "GROUP_MESSAGE_CREATE":
		var ev GroupMessageEvent
		if err := json.Unmarshal(payload.D, &ev); err != nil {
			return
		}
		if ev.Author.Bot {
			return
		}
		dedupKey := "grp:" + nonEmptyStr(ev.ID, payload.ID)
		if s.isDuplicateEvent(dedupKey) {
			return
		}
		groupID := strings.TrimSpace(ev.GroupOpenID)
		sender := nonEmptyStr(ev.Author.MemberNickname, ev.Author.Username, ev.Author.MemberOpenID)
		content := strings.TrimSpace(ev.Content)
		if s.store != nil && groupID != "" {
			s.store.RecordQQBotDiscoveredTarget(vault.QQBotDiscoveredTarget{
				TargetType:         vault.QQBotTargetGroup,
				TargetID:           groupID,
				Label:              "QQ 群 (最近发言: " + truncateRunes(sender, 24) + ")",
				LastEventType:      payload.T,
				LastMessagePreview: truncateRunes(content, 80),
				LastSeenAt:         now,
			}, &falseVal)
			s.store.RecordQQBotEvent(vault.QQBotEventRecord{
				ID:         nonEmptyStr(payload.ID, ev.ID),
				Seq:        payload.S,
				OpCode:     payload.Op,
				EventType:  payload.T,
				TargetType: vault.QQBotTargetGroup,
				TargetID:   groupID,
				Sender:     sender,
				Summary:    truncateRunes(content, 100),
				ReceivedAt: now,
			})
		}
		s.rememberPassiveSlot(vault.QQBotTargetGroup, groupID, ev.ID, payload.ID)
		s.maybeHandleCommand(ctx, cfg, vault.QQBotTargetGroup, groupID, "", "QQ 群", ev.ID, content)

	case "AT_MESSAGE_CREATE", "MESSAGE_CREATE":
		var ev GuildMessageEvent
		if err := json.Unmarshal(payload.D, &ev); err != nil {
			return
		}
		if ev.Author.Bot {
			return
		}
		dedupKey := "chan:" + nonEmptyStr(ev.ID, payload.ID)
		if s.isDuplicateEvent(dedupKey) {
			return
		}
		chanID := strings.TrimSpace(ev.ChannelID)
		sender := nonEmptyStr(ev.Author.Username, ev.Author.ID)
		content := stripGuildAtMention(ev.Content)
		if s.store != nil && chanID != "" {
			s.store.RecordQQBotDiscoveredTarget(vault.QQBotDiscoveredTarget{
				TargetType:         vault.QQBotTargetChannel,
				TargetID:           chanID,
				GuildID:            ev.GuildID,
				Label:              "频道子频道 (" + truncateRunes(sender, 24) + ")",
				LastEventType:      payload.T,
				LastMessagePreview: truncateRunes(content, 80),
				LastSeenAt:         now,
			}, &falseVal)
			s.store.RecordQQBotEvent(vault.QQBotEventRecord{
				ID:         nonEmptyStr(payload.ID, ev.ID),
				Seq:        payload.S,
				OpCode:     payload.Op,
				EventType:  payload.T,
				TargetType: vault.QQBotTargetChannel,
				TargetID:   chanID,
				Sender:     sender,
				Summary:    truncateRunes(content, 100),
				ReceivedAt: now,
			})
		}
		s.rememberPassiveSlot(vault.QQBotTargetChannel, chanID, ev.ID, payload.ID)
		s.maybeHandleCommand(ctx, cfg, vault.QQBotTargetChannel, chanID, ev.GuildID, "QQ 频道子频道", ev.ID, content)

	case "FRIEND_ADD", "C2C_MSG_RECEIVE":
		var ev FriendLifecycleEvent
		if err := json.Unmarshal(payload.D, &ev); err != nil {
			return
		}
		uid := nonEmptyStr(ev.OpenID, ev.UserOpenID)
		if uid == "" {
			return
		}
		summary := "用户添加机器人为好友，已自动发现 user_openid"
		if payload.T == "C2C_MSG_RECEIVE" {
			summary = "用户已开启单聊主动消息推送开关"
		}
		if s.store != nil {
			s.store.RecordQQBotDiscoveredTarget(vault.QQBotDiscoveredTarget{
				TargetType:    vault.QQBotTargetC2C,
				TargetID:      uid,
				Label:         "QQ 好友",
				LastEventType: payload.T,
				LastSeenAt:    now,
			}, &falseVal)
			s.store.RecordQQBotEvent(vault.QQBotEventRecord{
				ID:         payload.ID,
				Seq:        payload.S,
				OpCode:     payload.Op,
				EventType:  payload.T,
				TargetType: vault.QQBotTargetC2C,
				TargetID:   uid,
				Summary:    summary,
				ReceivedAt: now,
			})
		}
		s.rememberPassiveSlot(vault.QQBotTargetC2C, uid, "", payload.ID)

	case "FRIEND_DEL", "C2C_MSG_REJECT":
		var ev FriendLifecycleEvent
		if err := json.Unmarshal(payload.D, &ev); err != nil {
			return
		}
		uid := nonEmptyStr(ev.OpenID, ev.UserOpenID)
		if uid == "" {
			return
		}
		summary := "用户删除机器人好友"
		if payload.T == "C2C_MSG_REJECT" {
			summary = "用户关闭了单聊主动消息推送开关"
		}
		if s.store != nil {
			s.store.RecordQQBotDiscoveredTarget(vault.QQBotDiscoveredTarget{
				TargetType:    vault.QQBotTargetC2C,
				TargetID:      uid,
				LastEventType: payload.T,
				LastSeenAt:    now,
			}, &trueVal)
			s.store.RecordQQBotEvent(vault.QQBotEventRecord{
				ID:         payload.ID,
				Seq:        payload.S,
				OpCode:     payload.Op,
				EventType:  payload.T,
				TargetType: vault.QQBotTargetC2C,
				TargetID:   uid,
				Summary:    summary,
				ReceivedAt: now,
			})
		}

	case "GROUP_ADD_ROBOT", "GROUP_MSG_RECEIVE":
		var ev GroupLifecycleEvent
		if err := json.Unmarshal(payload.D, &ev); err != nil {
			return
		}
		gid := strings.TrimSpace(ev.GroupOpenID)
		if gid == "" {
			return
		}
		summary := "机器人已加入 QQ 群，已自动发现 group_openid"
		if payload.T == "GROUP_MSG_RECEIVE" {
			summary = "群管理员已开启主动通知开关"
		}
		if s.store != nil {
			s.store.RecordQQBotDiscoveredTarget(vault.QQBotDiscoveredTarget{
				TargetType:    vault.QQBotTargetGroup,
				TargetID:      gid,
				Label:         "QQ 群",
				LastEventType: payload.T,
				LastSeenAt:    now,
			}, &falseVal)
			s.store.RecordQQBotEvent(vault.QQBotEventRecord{
				ID:         payload.ID,
				Seq:        payload.S,
				OpCode:     payload.Op,
				EventType:  payload.T,
				TargetType: vault.QQBotTargetGroup,
				TargetID:   gid,
				Summary:    summary,
				ReceivedAt: now,
			})
		}
		s.rememberPassiveSlot(vault.QQBotTargetGroup, gid, "", payload.ID)

	case "GROUP_DEL_ROBOT", "GROUP_MSG_REJECT":
		var ev GroupLifecycleEvent
		if err := json.Unmarshal(payload.D, &ev); err != nil {
			return
		}
		gid := strings.TrimSpace(ev.GroupOpenID)
		if gid == "" {
			return
		}
		summary := "机器人被移出 QQ 群"
		if payload.T == "GROUP_MSG_REJECT" {
			summary = "群管理员已关闭主动通知开关"
		}
		if s.store != nil {
			s.store.RecordQQBotDiscoveredTarget(vault.QQBotDiscoveredTarget{
				TargetType:    vault.QQBotTargetGroup,
				TargetID:      gid,
				LastEventType: payload.T,
				LastSeenAt:    now,
			}, &trueVal)
			s.store.RecordQQBotEvent(vault.QQBotEventRecord{
				ID:         payload.ID,
				Seq:        payload.S,
				OpCode:     payload.Op,
				EventType:  payload.T,
				TargetType: vault.QQBotTargetGroup,
				TargetID:   gid,
				Summary:    summary,
				ReceivedAt: now,
			})
		}

	case "CHANNEL_CREATE", "CHANNEL_UPDATE":
		var ev GuildChannelLifecycleEvent
		if err := json.Unmarshal(payload.D, &ev); err != nil {
			return
		}
		if ev.ID == "" {
			return
		}
		if s.store != nil {
			s.store.RecordQQBotDiscoveredTarget(vault.QQBotDiscoveredTarget{
				TargetType:    vault.QQBotTargetChannel,
				TargetID:      ev.ID,
				GuildID:       ev.GuildID,
				Label:         nonEmptyStr(ev.Name, "频道子频道"),
				LastEventType: payload.T,
				LastSeenAt:    now,
			}, &falseVal)
			s.store.RecordQQBotEvent(vault.QQBotEventRecord{
				ID:         payload.ID,
				Seq:        payload.S,
				OpCode:     payload.Op,
				EventType:  payload.T,
				TargetType: vault.QQBotTargetChannel,
				TargetID:   ev.ID,
				Summary:    fmt.Sprintf("子频道 %s (%s)", nonEmptyStr(ev.Name, ev.ID), payload.T),
				ReceivedAt: now,
			})
		}

	case "MESSAGE_AUDIT_PASS", "MESSAGE_AUDIT_REJECT":
		var ev MessageAuditEvent
		_ = json.Unmarshal(payload.D, &ev)
		if s.store != nil {
			s.store.RecordQQBotEvent(vault.QQBotEventRecord{
				ID:         payload.ID,
				Seq:        payload.S,
				OpCode:     payload.Op,
				EventType:  payload.T,
				TargetType: vault.QQBotTargetChannel,
				TargetID:   ev.ChannelID,
				Summary:    fmt.Sprintf("消息审核结果: %s (audit_id=%s)", payload.T, ev.AuditID),
				ReceivedAt: now,
			})
		}

	default:
		if s.store != nil && payload.T != "" {
			s.store.RecordQQBotEvent(vault.QQBotEventRecord{
				ID:         payload.ID,
				Seq:        payload.S,
				OpCode:     payload.Op,
				EventType:  payload.T,
				Summary:    "收到 QQ 开放平台事件推送",
				ReceivedAt: now,
			})
		}
	}
}

func (s *Service) maybeHandleCommand(
	ctx context.Context,
	cfg vault.QQBotSettings,
	tt vault.QQBotTargetType,
	tid string,
	guildID string,
	defaultLabel string,
	msgID string,
	content string,
) {
	if !cfg.AllowBotCommands || tid == "" || msgID == "" {
		return
	}
	fields := strings.Fields(strings.TrimSpace(content))
	if len(fields) == 0 {
		return
	}
	cmd := strings.ToLower(fields[0])
	arg := ""
	if len(fields) > 1 {
		arg = strings.TrimSpace(fields[1])
	}

	replyText := ""
	switch cmd {
	case "/bind", "bind", "绑定":
		if arg == "" {
			replyText = fmt.Sprintf(
				"ServerNeedSafe 绑定指引\n目标类型：%s\n目标标识：%s\n\n请在 ServerNeedSafe 控制台「告警信息 -> QQ 机器人通知」中直接点击已发现目标绑定，或生成 6 位一次性绑定码后发送：/bind 绑定码",
				targetTypeLabel(tt), tid,
			)
		} else if s.consumeBindCode(arg) {
			if s.store != nil {
				saved, _, err := s.store.UpsertQQBotTarget(vault.QQBotTarget{
					Name:       defaultLabel,
					TargetType: tt,
					TargetID:   tid,
					GuildID:    guildID,
					Enabled:    true,
				}, "qqbot-ws-bind")
				if err != nil {
					replyText = "绑定失败：" + err.Error()
				} else {
					replyText = fmt.Sprintf(
						"✅ 已成功绑定 ServerNeedSafe 事件通知！\n名称：%s\n类型：%s\n标识：%s\n后续监控告警、AI 巡检异常与待审批提醒将自动推送至此。",
						saved.Name, targetTypeLabel(tt), tid,
					)
				}
			}
		} else {
			replyText = "❌ 绑定码无效或已过期，请在 ServerNeedSafe 控制台重新生成一次性绑定码后再发送 /bind <绑定码>。"
		}

	case "/id", "id", "openid":
		replyText = fmt.Sprintf("ServerNeedSafe 目标识别信息\n类型：%s\nOpenID / ChannelID：%s", targetTypeLabel(tt), tid)
		if guildID != "" {
			replyText += "\nGuildID：" + guildID
		}

	case "/help", "help", "帮助":
		if !isBoundEnabledTarget(cfg.Targets, tt, tid) {
			replyText = "此会话尚未绑定 ServerNeedSafe 通知权限。请先发送 /bind <一次性绑定码> 或在控制台绑定当前目标后使用查询指令。"
		} else {
			replyText = "ServerNeedSafe QQ 运维助手指令：\n• /status (状态) — 查看主机在线率与健康概览\n• /alerts (告警) — 查看当前未恢复活跃告警\n• /id — 查看当前会话 OpenID / ChannelID\n• /help (帮助) — 查看指令列表"
		}

	case "/status", "status", "状态":
		if !isBoundEnabledTarget(cfg.Targets, tt, tid) {
			return
		}
		replyText = s.buildStatusReplyText()

	case "/alerts", "alerts", "告警":
		if !isBoundEnabledTarget(cfg.Targets, tt, tid) {
			return
		}
		replyText = s.buildAlertsReplyText()

	default:
		return
	}

	if replyText == "" {
		return
	}

	// Consume sequence 1 from passive reply slot so any subsequent passive reuse uses seq 2+
	_, _, seq, ok := s.takePassiveSlot(tt, tid)
	if !ok {
		seq = 1
	}
	_, err := s.client.SendMessage(ctx, cfg, SendMessageRequest{
		TargetType: tt,
		TargetID:   tid,
		Format:     "text",
		PlainText:  replyText,
		MsgID:      msgID,
		MsgSeq:     seq,
	})
	if err != nil {
		log.Printf("[ServerNeedSafe] QQ 机器人被动回复指令 (%s) 失败: %v", cmd, err)
	}
}

func (s *Service) buildStatusReplyText() string {
	if s.store == nil || !s.store.IsReady() {
		return "ServerNeedSafe 守护服务尚未就绪。"
	}
	ov, err := s.store.GetMonitorOverview()
	if err != nil {
		return "获取监控概览失败：" + err.Error()
	}
	var b strings.Builder
	b.WriteString("[ServerNeedSafe] 全网主机健康概览\n")
	b.WriteString(fmt.Sprintf("时间：%s\n", time.Now().Local().Format("2006-01-02 15:04:05")))
	b.WriteString(fmt.Sprintf("总主机：%d 台（在线 %d · 离线 %d）\n", ov.KPI.TotalServers, ov.KPI.OnlineServers, ov.KPI.OfflineServers))
	b.WriteString(fmt.Sprintf("健康分布：正常 %d · 预警 %d · 严重 %d\n", ov.KPI.HealthyServers, ov.KPI.WarningServers, ov.KPI.CriticalServers))
	b.WriteString(fmt.Sprintf("未恢复告警：%d 条\n", ov.KPI.FiringAlerts))
	if ov.KPI.OnlineServers > 0 {
		b.WriteString(fmt.Sprintf("平均资源：CPU %.1f%% · 内存 %.1f%% · 磁盘 %.1f%%", ov.KPI.AvgCPUPercent, ov.KPI.AvgMemPercent, ov.KPI.AvgDiskPercent))
	}
	return b.String()
}

func (s *Service) buildAlertsReplyText() string {
	if s.store == nil || !s.store.IsReady() {
		return "ServerNeedSafe 守护服务尚未就绪。"
	}
	alerts, err := s.store.ListMonitorAlerts("active", "", 8)
	if err != nil {
		return "获取告警列表失败：" + err.Error()
	}
	if len(alerts) == 0 {
		return "✅ 当前全网零活跃告警，所有主机运行平稳。"
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("[ServerNeedSafe] 当前未恢复告警（展示前 %d 条）\n", len(alerts)))
	for i, al := range alerts {
		sev := strings.ToUpper(string(al.Severity))
		b.WriteString(fmt.Sprintf("%d. [%s] %s — %s\n", i+1, sev, al.Title, truncateRunes(al.Detail, 90)))
	}
	return strings.TrimSpace(b.String())
}

// --- Outbound Event Notification Dispatch ---

// DispatchEvent sends a formatted EventMessage to all enabled bound QQ targets (or one specific target).
func (s *Service) DispatchEvent(ctx context.Context, cfg vault.QQBotSettings, ev EventMessage, specificTargetID string) (*DispatchSummary, error) {
	cfg = vault.NormalizeQQBotSettings(cfg)
	if cfg.AppID == "" || cfg.AppSecret == "" {
		return nil, fmt.Errorf("%w: 请先配置 QQ 机器人的 AppID 与 AppSecret", vault.ErrInvalidInput)
	}

	var targets []vault.QQBotTarget
	for _, t := range cfg.Targets {
		if specificTargetID != "" {
			if t.ID == specificTargetID || t.TargetID == specificTargetID {
				targets = append(targets, t)
			}
			continue
		}
		if t.Enabled {
			targets = append(targets, t)
		}
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("%w: 尚未绑定并启用任何 QQ 推送目标，请先添加单聊 OpenID / 群 OpenID / 子频道 ID 或通过 /bind 绑定", vault.ErrInvalidInput)
	}

	summary := &DispatchSummary{
		Total:   len(targets),
		Results: make([]TargetDeliveryResult, 0, len(targets)),
	}

	var lastErr error
	for _, t := range targets {
		res := s.deliverToTarget(ctx, cfg, t, ev)
		summary.Results = append(summary.Results, res)
		if res.Success {
			summary.Sent++
		} else {
			summary.Failed++
			if res.Error != "" {
				lastErr = fmt.Errorf("[%s] %s", t.Name, res.Error)
			}
		}
	}

	now := time.Now().UTC()
	s.mu.Lock()
	s.pushSuccessCount += int64(summary.Sent)
	s.pushFailureCount += int64(summary.Failed)
	if summary.Sent > 0 {
		s.lastPushAt = &now
	}
	if lastErr != nil {
		s.lastPushError = lastErr.Error()
	} else if summary.Sent > 0 {
		s.lastPushError = ""
	}
	s.mu.Unlock()

	if summary.Sent == 0 && lastErr != nil {
		if s.store != nil {
			s.store.RecordAuditAsync("qqbot.push_failed", ev.Category, fmt.Sprintf("QQ 机器人事件通知推送失败: %v", lastErr), "qqbot-notifier", false)
		}
		return summary, lastErr
	}
	return summary, nil
}

func (s *Service) deliverToTarget(ctx context.Context, cfg vault.QQBotSettings, t vault.QQBotTarget, ev EventMessage) TargetDeliveryResult {
	mode := "proactive"
	var msgID, eventID string
	var msgSeq int

	if cfg.PushMode == "passive_prefer" {
		if mid, eid, seq, ok := s.takePassiveSlot(t.TargetType, t.TargetID); ok {
			msgID, eventID, msgSeq = mid, eid, seq
			mode = "passive"
		}
	}

	sendReq := SendMessageRequest{
		TargetType: t.TargetType,
		TargetID:   t.TargetID,
		Format:     cfg.MessageFormat,
		PlainText:  ev.PlainText,
		Markdown:   ev.Markdown,
		MsgID:      msgID,
		EventID:    eventID,
		MsgSeq:     msgSeq,
	}

	var resp *SendMessageResponse
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(400 * time.Millisecond):
			case <-ctx.Done():
				err = ctx.Err()
				break
			}
		}
		callCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
		resp, err = s.client.SendMessage(callCtx, cfg, sendReq)
		cancel()
		if err == nil {
			break
		}
		// Only retry transient network or 5xx errors
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.StatusCode < 500 {
			break
		}
	}

	// If proactive push failed with a 4xx policy/frequency error and we hold a fresh passive reply slot, try passive fallback once.
	if err != nil && mode == "proactive" {
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.StatusCode >= 400 && apiErr.StatusCode < 500 && !apiErr.isTokenError() {
			if mid, eid, seq, ok := s.takePassiveSlot(t.TargetType, t.TargetID); ok {
				sendReq.MsgID = mid
				sendReq.EventID = eid
				sendReq.MsgSeq = seq
				callCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
				fbResp, fbErr := s.client.SendMessage(callCtx, cfg, sendReq)
				cancel()
				if fbErr == nil {
					resp = fbResp
					err = nil
					mode = "passive"
				}
			}
		}
	}

	out := TargetDeliveryResult{
		TargetID:   t.TargetID,
		TargetType: t.TargetType,
		TargetName: t.Name,
		Mode:       mode,
		Success:    err == nil,
	}
	if resp != nil {
		out.AuditPending = resp.AuditPending
		out.FallbackPlain = resp.FallbackPlain
	}
	if err != nil {
		out.Error = err.Error()
	}

	if s.store != nil {
		s.store.RecordQQBotPush(vault.QQBotPushRecord{
			Category:   ev.Category,
			Title:      ev.Title,
			TargetType: t.TargetType,
			TargetID:   t.TargetID,
			TargetName: t.Name,
			Mode:       mode,
			Success:    out.Success,
			Error:      out.Error,
			SentAt:     time.Now().UTC(),
		})
	}
	return out
}

// SendTestNotification sends a connectivity test notification to one target (if specified) or all enabled targets.
func (s *Service) SendTestNotification(ctx context.Context, cfg vault.QQBotSettings, targetID string, customMessage string) (*DispatchSummary, error) {
	nowStr := time.Now().Local().Format("2006-01-02 15:04:05")
	extra := strings.TrimSpace(customMessage)
	if extra == "" {
		extra = "这是一条由 ServerNeedSafe QQ 开放平台 WebSocket 事件通知引擎发出的连通性测试消息。"
	}
	md := fmt.Sprintf("### [ServerNeedSafe] QQ 机器人事件通知连通性测试\n- **发送时间**：%s\n- **连接方式**：QQ 开放平台 API v2 WebSocket 网关\n- **状态说明**：%s\n", nowStr, extra)
	plain := MarkdownToQQPlainText(md, maxQQMessageRunes)
	return s.DispatchEvent(ctx, cfg, EventMessage{
		Category:  "test",
		Title:     "ServerNeedSafe · QQ 机器人连通性测试",
		PlainText: plain,
		Markdown:  md,
	}, targetID)
}

// --- Domain Event Adapters (Monitor, AI Patrol, External MCP Approvals, Vulnerability Advisories) ---

// NotifyMonitorAlerts delivers status monitor alert trigger/escalation/recovery events if subscribed.
func (s *Service) NotifyMonitorAlerts(ctx context.Context, triggered, resolved []vault.MonitorAlert) bool {
	if s == nil || s.store == nil || !s.store.IsReady() || (len(triggered) == 0 && len(resolved) == 0) {
		return false
	}
	cfg, err := s.store.GetQQBotSettings()
	if err != nil || !cfg.Enabled || !cfg.NotifyMonitorAlerts || len(cfg.Targets) == 0 {
		return false
	}

	hasCrit := false
	for _, a := range triggered {
		if a.Severity == vault.SeverityCritical {
			hasCrit = true
			break
		}
	}
	title := fmt.Sprintf("ServerNeedSafe · 告警恢复通知 (%d 条)", len(resolved))
	if hasCrit {
		title = fmt.Sprintf("ServerNeedSafe · 严重监控告警 (%d 条)", len(triggered))
	} else if len(triggered) > 0 {
		title = fmt.Sprintf("ServerNeedSafe · 监控预警 (%d 条)", len(triggered))
	}

	var md strings.Builder
	md.WriteString(fmt.Sprintf("### %s\n", title))
	md.WriteString(fmt.Sprintf("- **时间**：%s\n", time.Now().Local().Format("2006-01-02 15:04:05")))
	if len(triggered) > 0 {
		md.WriteString(fmt.Sprintf("\n**触发/升级告警 (%d 条)**：\n", len(triggered)))
		for i, a := range triggered {
			if i >= 8 {
				md.WriteString(fmt.Sprintf("- ... 其余 %d 条请前往控制台「告警信息」查看\n", len(triggered)-8))
				break
			}
			md.WriteString(fmt.Sprintf("- **[%s]** %s — %s\n", strings.ToUpper(string(a.Severity)), a.Title, a.Detail))
		}
	}
	if len(resolved) > 0 {
		md.WriteString(fmt.Sprintf("\n**恢复通知 (%d 条)**：\n", len(resolved)))
		for i, a := range resolved {
			if i >= 8 {
				md.WriteString(fmt.Sprintf("- ... 其余 %d 条已恢复\n", len(resolved)-8))
				break
			}
			md.WriteString(fmt.Sprintf("- **[已恢复]** %s\n", a.Title))
		}
	}
	mdText := md.String()

	sum, err := s.DispatchEvent(ctx, cfg, EventMessage{
		Category:  "monitor_alert",
		Title:     title,
		PlainText: MarkdownToQQPlainText(mdText, maxQQMessageRunes),
		Markdown:  mdText,
	}, "")
	return err == nil && sum != nil && sum.Sent > 0
}

// NotifyPatrolRecord delivers AI scheduled patrol anomaly & Stage 2 report events if subscribed.
func (s *Service) NotifyPatrolRecord(ctx context.Context, rec vault.PatrolRecord) bool {
	if s == nil || s.store == nil || !s.store.IsReady() {
		return false
	}
	cfg, err := s.store.GetQQBotSettings()
	if err != nil || !cfg.Enabled || !cfg.NotifyAIPatrol || len(cfg.Targets) == 0 {
		return false
	}

	statusLabel := "健康"
	switch rec.Status {
	case "critical":
		statusLabel = "严重告警"
	case "warning":
		statusLabel = "风险预警"
	}
	title := fmt.Sprintf("ServerNeedSafe · AI 巡检%s", statusLabel)
	var md strings.Builder
	md.WriteString(fmt.Sprintf("### [ServerNeedSafe] AI 巡检%s\n", statusLabel))
	md.WriteString(fmt.Sprintf("- **巡检时间**：%s\n", rec.CompletedAt.Local().Format("2006-01-02 15:04:05")))
	md.WriteString(fmt.Sprintf("- **主机统计**：共 %d 台（正常 %d · 预警 %d · 严重 %d）\n", rec.TotalServers, rec.HealthyCount, rec.WarningCount, rec.CriticalCount))
	for _, f := range rec.Findings {
		if len(f.Anomalies) == 0 && f.Reachable {
			continue
		}
		md.WriteString(fmt.Sprintf("- **%s (%s)**：%s\n", f.ServerName, f.Host, strings.Join(f.Anomalies, "；")))
	}
	if rec.AISummary != "" {
		md.WriteString(fmt.Sprintf("\n**AI 根因研判**：%s\n", truncateRunes(rec.AISummary, 400)))
	}
	if len(rec.AIRecommendations) > 0 {
		md.WriteString("\n**处置建议**：\n")
		for i, r := range rec.AIRecommendations {
			if i >= 3 {
				break
			}
			md.WriteString(fmt.Sprintf("%d. %s\n", i+1, r))
		}
	}
	mdText := md.String()

	sum, err := s.DispatchEvent(ctx, cfg, EventMessage{
		Category:  "ai_patrol",
		Title:     title,
		PlainText: MarkdownToQQPlainText(mdText, maxQQMessageRunes),
		Markdown:  mdText,
	}, "")
	return err == nil && sum != nil && sum.Sent > 0
}

// NotifyExternalApproval delivers external MCP AI pending HITL change plan notifications if subscribed.
func (s *Service) NotifyExternalApproval(ctx context.Context, ap vault.ExternalApproval) bool {
	if s == nil || s.store == nil || !s.store.IsReady() {
		return false
	}
	cfg, err := s.store.GetQQBotSettings()
	if err != nil || !cfg.Enabled || !cfg.NotifyExternalApprovals || len(cfg.Targets) == 0 {
		return false
	}

	vault.NormalizeExternalApproval(&ap)
	title := fmt.Sprintf("ServerNeedSafe · 待审批外部 AI 变更计划 (%d 步)", ap.TotalSteps)
	var md strings.Builder
	md.WriteString(fmt.Sprintf("### [ServerNeedSafe] 外部 AI 提交变更审批计划（共 %d 步）\n", ap.TotalSteps))
	md.WriteString(fmt.Sprintf("- **计划标题**：%s\n", nonEmptyStr(ap.Title, "外部 AI 变更计划")))
	md.WriteString(fmt.Sprintf("- **提交来源**：%s\n", nonEmptyStr(ap.ClientName, "外部 MCP AI")))
	md.WriteString(fmt.Sprintf("- **风险等级**：%s（可执行 %d 步 / 拦截 %d 步）\n", nonEmptyStr(ap.RiskLevel, "high"), ap.ExecutableSteps, ap.BlockedSteps))
	md.WriteString(fmt.Sprintf("- **目标主机**：%s\n", nonEmptyStr(strings.Join(ap.ServerNames, ", "), strings.Join(ap.ServerIDs, ", "))))
	if ap.Reason != "" {
		md.WriteString(fmt.Sprintf("- **变更原因**：%s\n", truncateRunes(ap.Reason, 220)))
	}
	md.WriteString("\n请登录 ServerNeedSafe 控制台「执行审批」审阅全部步骤与 Diff 后批准或拒绝。")
	mdText := md.String()

	sum, err := s.DispatchEvent(ctx, cfg, EventMessage{
		Category:  "external_approval",
		Title:     title,
		PlainText: MarkdownToQQPlainText(mdText, maxQQMessageRunes),
		Markdown:  mdText,
	}, "")
	return err == nil && sum != nil && sum.Sent > 0
}

// NotifyVulnAdvisories delivers new high/critical/CISA KEV vulnerability advisories if subscribed.
func (s *Service) NotifyVulnAdvisories(ctx context.Context, hits []vault.VulnAdvisory) bool {
	if s == nil || s.store == nil || !s.store.IsReady() || len(hits) == 0 {
		return false
	}
	cfg, err := s.store.GetQQBotSettings()
	if err != nil || !cfg.Enabled || !cfg.NotifyVulnAdvisories || len(cfg.Targets) == 0 {
		return false
	}

	title := fmt.Sprintf("ServerNeedSafe · 发现 %d 条新官方高危漏洞动态", len(hits))
	var md strings.Builder
	md.WriteString(fmt.Sprintf("### [ServerNeedSafe] 发现 %d 条新的主流应用官方高危漏洞动态\n", len(hits)))
	for i, a := range hits {
		if i >= 6 {
			md.WriteString(fmt.Sprintf("- ... 其余 %d 条请前往「漏洞监测」查看\n", len(hits)-6))
			break
		}
		kevTag := ""
		if a.IsKEV {
			kevTag = " [在野利用 KEV]"
		}
		fixHint := "暂无明确补丁"
		if a.FixedVersion != "" {
			fixHint = "修复版本: " + a.FixedVersion
		}
		md.WriteString(fmt.Sprintf("- **[%s]%s %s** (%s) — %s（%s）\n",
			strings.ToUpper(string(a.Severity)), kevTag, a.ID, strings.Join(a.AppNames, "/"), truncateRunes(a.Title, 80), fixHint))
	}
	mdText := md.String()

	sum, err := s.DispatchEvent(ctx, cfg, EventMessage{
		Category:  "vuln_advisory",
		Title:     title,
		PlainText: MarkdownToQQPlainText(mdText, maxQQMessageRunes),
		Markdown:  mdText,
	}, "")
	return err == nil && sum != nil && sum.Sent > 0
}

// --- Helpers ---

func isBoundEnabledTarget(targets []vault.QQBotTarget, tt vault.QQBotTargetType, tid string) bool {
	for _, t := range targets {
		if t.Enabled && t.TargetType == tt && t.TargetID == tid {
			return true
		}
	}
	return false
}

func targetTypeLabel(tt vault.QQBotTargetType) string {
	switch tt {
	case vault.QQBotTargetC2C:
		return "QQ 单聊 (C2C)"
	case vault.QQBotTargetGroup:
		return "QQ 群聊 (Group)"
	case vault.QQBotTargetChannel:
		return "QQ 频道子频道 (Channel)"
	default:
		return string(tt)
	}
}

func nonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if t := strings.TrimSpace(v); t != "" {
			return t
		}
	}
	return ""
}

// stripGuildAtMention strips leading <@!123456> bot mention tags from QQ Guild messages.
func stripGuildAtMention(raw string) string {
	s := strings.TrimSpace(raw)
	for strings.HasPrefix(s, "<@") {
		idx := strings.Index(s, ">")
		if idx < 0 {
			break
		}
		s = strings.TrimSpace(s[idx+1:])
	}
	return s
}

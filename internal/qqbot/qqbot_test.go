package qqbot

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

// mockQQPlatform simulates the official QQ Open Platform API v2 HTTP + WebSocket Gateway.
type mockQQPlatform struct {
	t *testing.T

	server *httptest.Server

	mu                    sync.Mutex
	expectedAppID         string
	expectedSecret        string
	tokenStringExpires    bool
	tokenCallCount        int
	gatewayBot404         bool
	rejectMarkdown        bool
	rejectProactiveOnce   bool
	currentToken          string
	heartbeatIntervalMs   int
	identifyPayloads      []IdentifyData
	resumePayloads        []ResumeData
	heartbeatsReceived    int
	sentMessages          []mockSentMessage
	activeConn            *websocket.Conn
	connWriteMu           sync.Mutex
	connectedCount        int
	autoReady             bool
	autoResumed           bool
	nextCloseCodeOnIdent  int
	onIdentify            func(conn *websocket.Conn, writeJSON func(any) error, id IdentifyData)
	onResume              func(conn *websocket.Conn, writeJSON func(any) error, res ResumeData)
}

type mockSentMessage struct {
	Path    string
	Auth    string
	Body    map[string]any
	RawBody string
}

func newMockQQPlatform(t *testing.T) *mockQQPlatform {
	t.Helper()
	m := &mockQQPlatform{
		t:                   t,
		expectedAppID:       "102030405",
		expectedSecret:      "mock-qq-secret-abcdef123456",
		tokenStringExpires:  true,
		currentToken:        "qq-access-token-v1",
		heartbeatIntervalMs: 80,
		autoReady:           true,
		autoResumed:         true,
	}

	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/app/getAppAccessToken", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			AppID        string `json:"appId"`
			ClientSecret string `json:"clientSecret"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		m.mu.Lock()
		m.tokenCallCount++
		ok := req.AppID == m.expectedAppID && req.ClientSecret == m.expectedSecret
		tok := m.currentToken
		asStr := m.tokenStringExpires
		m.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		if !ok {
			// Official QQ docs: HTTP 200 with business error code 100016
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code":    100016,
				"message": "invalid appid or secret",
			})
			return
		}
		if asStr {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": tok,
				"expires_in":   "7200",
			})
		} else {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": tok,
				"expires_in":   7200,
			})
		}
	})

	gatewayHandler := func(isBot bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			m.mu.Lock()
			tok := m.currentToken
			bot404 := m.gatewayBot404
			m.mu.Unlock()
			if r.Header.Get("Authorization") != "QQBot "+tok {
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"err_code": 11243,
					"message":  "token invalid",
				})
				return
			}
			if isBot && bot404 {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			wsURL := "ws" + strings.TrimPrefix(m.server.URL, "http") + "/websocket"
			w.Header().Set("Content-Type", "application/json")
			if isBot {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"url":    wsURL,
					"shards": 1,
					"session_start_limit": map[string]any{
						"total":           1000,
						"remaining":       999,
						"reset_after":     86400000,
						"max_concurrency": 1,
					},
				})
			} else {
				_ = json.NewEncoder(w).Encode(map[string]any{"url": wsURL})
			}
		}
	}
	mux.HandleFunc("/gateway/bot", gatewayHandler(true))
	mux.HandleFunc("/gateway", gatewayHandler(false))

	mux.HandleFunc("/websocket", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		m.mu.Lock()
		m.activeConn = conn
		m.connectedCount++
		hbMs := m.heartbeatIntervalMs
		m.mu.Unlock()

		writeJSON := func(v any) error {
			m.connWriteMu.Lock()
			defer m.connWriteMu.Unlock()
			return conn.WriteJSON(v)
		}

		// Step 1: Send OpCode 10 Hello immediately upon connection
		if err := writeJSON(map[string]any{
			"op": OpHello,
			"d":  map[string]any{"heartbeat_interval": hbMs},
		}); err != nil {
			return
		}

		for {
			var frame GatewayPayload
			if err := conn.ReadJSON(&frame); err != nil {
				return
			}
			switch frame.Op {
			case OpIdentify:
				var id IdentifyData
				_ = json.Unmarshal(frame.D, &id)
				m.mu.Lock()
				m.identifyPayloads = append(m.identifyPayloads, id)
				closeCode := m.nextCloseCodeOnIdent
				m.nextCloseCodeOnIdent = 0
				autoReady := m.autoReady
				cb := m.onIdentify
				m.mu.Unlock()

				if closeCode != 0 {
					m.connWriteMu.Lock()
					_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(closeCode, "mock close"), time.Now().Add(time.Second))
					m.connWriteMu.Unlock()
					return
				}
				if cb != nil {
					cb(conn, writeJSON, id)
					continue
				}
				if autoReady {
					_ = writeJSON(map[string]any{
						"op": OpDispatch,
						"s":  1,
						"t":  "READY",
						"d": map[string]any{
							"version":    1,
							"session_id": "sess-qq-1234567890abcdef",
							"user": map[string]any{
								"id":       "6158788878435714165",
								"username": "ServerNeedSafe告警机器人",
								"bot":      true,
							},
							"shard": id.Shard,
						},
					})
				}

			case OpResume:
				var res ResumeData
				_ = json.Unmarshal(frame.D, &res)
				m.mu.Lock()
				m.resumePayloads = append(m.resumePayloads, res)
				autoResumed := m.autoResumed
				cb := m.onResume
				m.mu.Unlock()
				if cb != nil {
					cb(conn, writeJSON, res)
					continue
				}
				if autoResumed {
					_ = writeJSON(map[string]any{
						"op": OpDispatch,
						"s":  res.Seq + 1,
						"t":  "RESUMED",
						"d":  "",
					})
				}

			case OpHeartbeat:
				m.mu.Lock()
				m.heartbeatsReceived++
				m.mu.Unlock()
				_ = writeJSON(map[string]any{"op": OpHeartbeatACK})
			}
		}
	})

	msgHandler := func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		tok := m.currentToken
		rejectMD := m.rejectMarkdown
		rejectProOnce := m.rejectProactiveOnce
		m.mu.Unlock()

		auth := r.Header.Get("Authorization")
		if auth != "QQBot "+tok {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"err_code": 11243,
				"message":  "invalid access token",
			})
			return
		}

		var body map[string]any
		rawBytes := new(strings.Builder)
		dec := json.NewDecoder(r.Body)
		_ = dec.Decode(&body)
		b, _ := json.Marshal(body)
		rawBytes.Write(b)

		m.mu.Lock()
		if rejectMD {
			if mt, ok := body["msg_type"].(float64); ok && int(mt) == 2 {
				m.mu.Unlock()
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"err_code": 50040,
					"message":  "markdown not permitted",
				})
				return
			}
		}
		if rejectProOnce {
			if _, hasMsgID := body["msg_id"]; !hasMsgID {
				m.rejectProactiveOnce = false
				m.mu.Unlock()
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"err_code": 11253,
					"message":  "proactive message quota exceeded",
				})
				return
			}
		}
		m.sentMessages = append(m.sentMessages, mockSentMessage{
			Path:    r.URL.Path,
			Auth:    auth,
			Body:    body,
			RawBody: rawBytes.String(),
		})
		m.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":        "sent-msg-001",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		})
	}
	mux.HandleFunc("/v2/users/", msgHandler)
	mux.HandleFunc("/v2/groups/", msgHandler)
	mux.HandleFunc("/channels/", msgHandler)

	m.server = httptest.NewServer(mux)
	t.Cleanup(m.server.Close)
	return m
}

func (m *mockQQPlatform) pushFrame(v any) error {
	m.mu.Lock()
	conn := m.activeConn
	m.mu.Unlock()
	if conn == nil {
		return nil
	}
	m.connWriteMu.Lock()
	defer m.connWriteMu.Unlock()
	return conn.WriteJSON(v)
}

func (m *mockQQPlatform) closeActiveWithCode(code int, reason string) {
	m.mu.Lock()
	conn := m.activeConn
	m.mu.Unlock()
	if conn == nil {
		return
	}
	m.connWriteMu.Lock()
	_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, reason), time.Now().Add(time.Second))
	_ = conn.Close()
	m.connWriteMu.Unlock()
}

func newReadyVaultStore(t *testing.T) *vault.Store {
	t.Helper()
	st, err := vault.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	st.SetFlushDebounce(10 * time.Millisecond)
	if err := st.Setup("QQBotTestAdmin#2026!", "127.0.0.1"); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	t.Cleanup(st.Close)
	return st
}

func waitUntil(t *testing.T, timeout time.Duration, desc string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", desc)
}

func TestAPIClientTokenCachingAndGatewayFallback(t *testing.T) {
	mock := newMockQQPlatform(t)
	client := NewAPIClient(nil)

	cfg := vault.NormalizeQQBotSettings(vault.QQBotSettings{
		AppID:      mock.expectedAppID,
		AppSecret:  mock.expectedSecret,
		APIBaseURL: mock.server.URL,
	})

	// 1. String expires_in ("7200") + caching
	tok1, err := client.GetAccessToken(context.Background(), cfg, false)
	if err != nil || tok1 != "qq-access-token-v1" {
		t.Fatalf("GetAccessToken #1: tok=%q err=%v", tok1, err)
	}
	tok2, err := client.GetAccessToken(context.Background(), cfg, false)
	if err != nil || tok2 != tok1 {
		t.Fatalf("GetAccessToken #2 cached: tok=%q err=%v", tok2, err)
	}
	mock.mu.Lock()
	calls := mock.tokenCallCount
	mock.mu.Unlock()
	if calls != 1 {
		t.Fatalf("expected 1 cached token HTTP call, got %d", calls)
	}

	// 2. Numeric expires_in (7200) after force refresh
	mock.mu.Lock()
	mock.tokenStringExpires = false
	mock.currentToken = "qq-access-token-v2"
	mock.mu.Unlock()

	tok3, err := client.GetAccessToken(context.Background(), cfg, true)
	if err != nil || tok3 != "qq-access-token-v2" {
		t.Fatalf("GetAccessToken numeric force refresh: tok=%q err=%v", tok3, err)
	}

	// 3. HTTP 200 business error code 100016 MUST fail!
	badCfg := cfg
	badCfg.AppSecret = "wrong-secret"
	if _, err := client.GetAccessToken(context.Background(), badCfg, true); err == nil || !strings.Contains(err.Error(), "100016") {
		t.Fatalf("expected 100016 business error, got: %v", err)
	}

	// 4. GET /gateway/bot -> 404 gracefully falls back to GET /gateway
	mock.mu.Lock()
	mock.gatewayBot404 = true
	mock.mu.Unlock()
	gw, _, err := client.GetGatewayInfo(context.Background(), cfg)
	if err != nil || !strings.HasSuffix(gw.URL, "/websocket") {
		t.Fatalf("expected /gateway fallback URL, got gw=%+v err=%v", gw, err)
	}

	// 5. Auto-refresh on 401 when sending message
	mock.mu.Lock()
	mock.currentToken = "qq-access-token-v3"
	mock.mu.Unlock()
	res, err := client.SendMessage(context.Background(), cfg, SendMessageRequest{
		TargetType: vault.QQBotTargetC2C,
		TargetID:   "USEROPENID001",
		Format:     "text",
		PlainText:  "token refresh test",
	})
	if err != nil || res == nil || res.ID != "sent-msg-001" {
		t.Fatalf("expected SendMessage auto-refresh retry to succeed, got res=%+v err=%v", res, err)
	}
}

func TestWebSocketGatewayLifecycleIdentifyHeartbeatReconnectResumeAndErrors(t *testing.T) {
	mock := newMockQQPlatform(t)
	store := newReadyVaultStore(t)

	enabled := true
	intents := vault.QQIntentGroupAndC2CEvent | vault.QQIntentPublicGuildMessages
	if _, err := store.UpdateQQBotSettings(vault.QQBotSettingsUpdateInput{
		Enabled:    &enabled,
		AppID:      &mock.expectedAppID,
		AppSecret:  &mock.expectedSecret,
		APIBaseURL: &mock.server.URL,
		Intents:    &intents,
	}, "127.0.0.1"); err != nil {
		t.Fatalf("UpdateQQBotSettings: %v", err)
	}

	svc := NewService(ServiceConfig{
		Store:                store,
		MinHeartbeatInterval: 40 * time.Millisecond,
		BaseReconnectBackoff: 40 * time.Millisecond,
		MaxReconnectBackoff:  120 * time.Millisecond,
	})
	svc.Start()
	defer svc.Close()

	// 1. Wait for Hello -> Identify -> READY -> Connected + Heartbeat ACK
	waitUntil(t, 5*time.Second, "WebSocket connected & heartbeat ACKed", func() bool {
		st := svc.Status()
		return st.Connected && st.State == "connected" && st.BotUsername == "ServerNeedSafe告警机器人" && st.LastHeartbeatAckAt != nil
	})

	mock.mu.Lock()
	if len(mock.identifyPayloads) != 1 {
		mock.mu.Unlock()
		t.Fatalf("expected 1 Identify frame, got %d", len(mock.identifyPayloads))
	}
	idFrame := mock.identifyPayloads[0]
	hbCount := mock.heartbeatsReceived
	mock.mu.Unlock()

	if idFrame.Token != "QQBot qq-access-token-v1" {
		t.Fatalf("unexpected Identify token: %q", idFrame.Token)
	}
	if idFrame.Intents != intents {
		t.Fatalf("expected intents=%d, got %d", intents, idFrame.Intents)
	}
	if idFrame.Shard != [2]int{0, 1} {
		t.Fatalf("expected shard [0,1], got %v", idFrame.Shard)
	}
	if hbCount < 1 {
		t.Fatalf("expected at least 1 heartbeat received, got %d", hbCount)
	}

	// 2. Server sends OpCode 7 Reconnect -> client MUST send OpCode 6 Resume with session_id + seq!
	if err := mock.pushFrame(map[string]any{"op": OpReconnect}); err != nil {
		t.Fatalf("push OpReconnect: %v", err)
	}
	waitUntil(t, 5*time.Second, "WebSocket RESUMED after OpCode 7", func() bool {
		st := svc.Status()
		return st.Connected && st.ResumeCount >= 1
	})
	mock.mu.Lock()
	if len(mock.resumePayloads) < 1 || mock.resumePayloads[0].SessionID != "sess-qq-1234567890abcdef" {
		mock.mu.Unlock()
		t.Fatalf("expected Resume with stored session_id, got %+v", mock.resumePayloads)
	}
	mock.mu.Unlock()

	// 3. Server closes with 4009 (connection expired) -> client MUST Resume again!
	prevResumes := svc.Status().ResumeCount
	mock.closeActiveWithCode(4009, "session expired")
	waitUntil(t, 5*time.Second, "WebSocket RESUMED after close 4009", func() bool {
		st := svc.Status()
		return st.Connected && st.ResumeCount > prevResumes
	})

	// 4. Server sends OpCode 9 Invalid Session (false) -> client MUST clear session & re-Identify!
	prevIdents := func() int {
		mock.mu.Lock()
		defer mock.mu.Unlock()
		return len(mock.identifyPayloads)
	}()
	if err := mock.pushFrame(map[string]any{"op": OpInvalidSession, "d": false}); err != nil {
		t.Fatalf("push OpInvalidSession: %v", err)
	}
	waitUntil(t, 5*time.Second, "WebSocket re-Identified after OpCode 9(false)", func() bool {
		mock.mu.Lock()
		defer mock.mu.Unlock()
		return len(mock.identifyPayloads) > prevIdents && svc.Status().Connected
	})

	// 5. Server closes with 4014 (unauthorized intent) on next identify -> pauses reconnect with clear error!
	mock.mu.Lock()
	mock.nextCloseCodeOnIdent = 4014
	mock.mu.Unlock()
	svc.ReconnectNow()
	waitUntil(t, 5*time.Second, "WebSocket paused in error state on 4014", func() bool {
		st := svc.Status()
		return st.State == "error" && strings.Contains(st.LastError, "4014")
	})

	// 6. ProbeConnection validates AccessToken + Gateway + OpCode 10 Hello handshake
	cfg, _ := store.GetQQBotSettings()
	probeRes, err := svc.ProbeConnection(context.Background(), cfg)
	if err != nil || !probeRes.OK || probeRes.HeartbeatIntervalMs != 80 {
		t.Fatalf("ProbeConnection failed: res=%+v err=%v", probeRes, err)
	}
}

func TestDispatchEventsAutoDiscoveryBindCodeCommandsAndNotifications(t *testing.T) {
	mock := newMockQQPlatform(t)
	store := newReadyVaultStore(t)

	enabled := true
	notifyVulns := true
	if _, err := store.UpdateQQBotSettings(vault.QQBotSettingsUpdateInput{
		Enabled:              &enabled,
		AppID:                &mock.expectedAppID,
		AppSecret:            &mock.expectedSecret,
		APIBaseURL:           &mock.server.URL,
		NotifyVulnAdvisories: &notifyVulns,
	}, "127.0.0.1"); err != nil {
		t.Fatalf("UpdateQQBotSettings: %v", err)
	}

	svc := NewService(ServiceConfig{
		Store:                store,
		MinHeartbeatInterval: 50 * time.Millisecond,
		BaseReconnectBackoff: 50 * time.Millisecond,
	})
	svc.Start()
	defer svc.Close()

	waitUntil(t, 5*time.Second, "connected", func() bool { return svc.Status().Connected })

	// 1. Generate one-time bind code and send GROUP_AT_MESSAGE_CREATE with "/bind <CODE>"
	bindInfo := svc.GenerateBindCode()
	groupOpenID := "GROUP_OPENID_OPS_1234567890ABCDEF"
	if err := mock.pushFrame(map[string]any{
		"id": "evt-bind-1",
		"op": OpDispatch,
		"s":  2,
		"t":  "GROUP_AT_MESSAGE_CREATE",
		"d": map[string]any{
			"id":           "msg-bind-1",
			"group_openid": groupOpenID,
			"content":      " /bind " + bindInfo.Code + " ",
			"author": map[string]any{
				"id":              "MEM_001",
				"member_openid":   "MEM_001",
				"member_nickname": "运维值班员",
				"bot":             false,
			},
		},
	}); err != nil {
		t.Fatalf("push bind event: %v", err)
	}

	// Verify target automatically bound in encrypted secrets + passive reply delivered!
	waitUntil(t, 4*time.Second, "group bound via /bind code", func() bool {
		cfg, err := store.GetQQBotSettings()
		return err == nil && len(cfg.Targets) == 1 && cfg.Targets[0].TargetID == groupOpenID && cfg.Targets[0].Enabled
	})
	waitUntil(t, 4*time.Second, "passive reply sent for /bind", func() bool {
		mock.mu.Lock()
		defer mock.mu.Unlock()
		return len(mock.sentMessages) >= 1
	})
	mock.mu.Lock()
	bindReply := mock.sentMessages[0]
	mock.mu.Unlock()
	if !strings.Contains(bindReply.Path, "/v2/groups/"+groupOpenID+"/messages") {
		t.Fatalf("unexpected bind reply path: %s", bindReply.Path)
	}
	if bindReply.Body["msg_id"] != "msg-bind-1" {
		t.Fatalf("expected passive msg_id=msg-bind-1, got %v", bindReply.Body["msg_id"])
	}

	// 2. Duplicate message event with same msg_id is deduplicated; unbound C2C stranger "/status" gets NO reply!
	prevSent := func() int {
		mock.mu.Lock()
		defer mock.mu.Unlock()
		return len(mock.sentMessages)
	}()
	_ = mock.pushFrame(map[string]any{
		"id": "evt-bind-1-dup",
		"op": OpDispatch,
		"s":  3,
		"t":  "GROUP_AT_MESSAGE_CREATE",
		"d": map[string]any{
			"id":           "msg-bind-1", // duplicate msg_id!
			"group_openid": groupOpenID,
			"content":      "/status",
			"author":       map[string]any{"id": "MEM_001", "bot": false},
		},
	})
	_ = mock.pushFrame(map[string]any{
		"id": "evt-stranger-1",
		"op": OpDispatch,
		"s":  4,
		"t":  "C2C_MESSAGE_CREATE",
		"d": map[string]any{
			"id":      "msg-stranger-1",
			"content": "/status",
			"author":  map[string]any{"user_openid": "STRANGER_OPENID_999", "username": "路人", "bot": false},
		},
	})
	// Wait until stranger is discovered, then confirm zero replies went out
	waitUntil(t, 4*time.Second, "stranger discovered", func() bool {
		rt := store.GetQQBotRuntimeSnapshot()
		for _, dt := range rt.DiscoveredTargets {
			if dt.TargetID == "STRANGER_OPENID_999" {
				return true
			}
		}
		return false
	})
	time.Sleep(120 * time.Millisecond)
	mock.mu.Lock()
	afterStranger := len(mock.sentMessages)
	mock.mu.Unlock()
	if afterStranger != prevSent {
		t.Fatalf("expected zero replies for duplicate msg and unbound stranger, sent delta=%d", afterStranger-prevSent)
	}

	// 3. Bound group sends "/status" -> receives real-time fleet health passive reply!
	_ = mock.pushFrame(map[string]any{
		"id": "evt-status-1",
		"op": OpDispatch,
		"s":  5,
		"t":  "GROUP_AT_MESSAGE_CREATE",
		"d": map[string]any{
			"id":           "msg-status-1",
			"group_openid": groupOpenID,
			"content":      "/status",
			"author":       map[string]any{"member_openid": "MEM_001", "username": "运维值班员", "bot": false},
		},
	})
	waitUntil(t, 4*time.Second, "bound group /status passive reply", func() bool {
		mock.mu.Lock()
		defer mock.mu.Unlock()
		return len(mock.sentMessages) > afterStranger
	})
	mock.mu.Lock()
	statusReply := mock.sentMessages[len(mock.sentMessages)-1]
	mock.mu.Unlock()
	if content, _ := statusReply.Body["content"].(string); !strings.Contains(content, "全网主机健康概览") {
		t.Fatalf("unexpected /status reply body: %+v", statusReply.Body)
	}

	// 4. Test GROUP_MSG_REJECT marks proactive_rejected on discovered target
	_ = mock.pushFrame(map[string]any{
		"id": "evt-reject-1",
		"op": OpDispatch,
		"s":  6,
		"t":  "GROUP_MSG_REJECT",
		"d":  map[string]any{"group_openid": groupOpenID},
	})
	waitUntil(t, 4*time.Second, "GROUP_MSG_REJECT recorded", func() bool {
		rt := store.GetQQBotRuntimeSnapshot()
		for _, dt := range rt.DiscoveredTargets {
			if dt.TargetID == groupOpenID && dt.ProactiveRejected {
				return true
			}
		}
		return false
	})

	// 5. Markdown auto-fallback to plain text + Proactive-failure passive fallback!
	mdFmt := "markdown"
	if _, err := store.UpdateQQBotSettings(vault.QQBotSettingsUpdateInput{
		MessageFormat: &mdFmt,
	}, "127.0.0.1"); err != nil {
		t.Fatalf("set markdown format: %v", err)
	}
	mock.mu.Lock()
	mock.rejectMarkdown = true
	mock.rejectProactiveOnce = true
	beforeAlerts := len(mock.sentMessages)
	mock.mu.Unlock()

	ok := svc.NotifyMonitorAlerts(context.Background(), []vault.MonitorAlert{
		{
			ServerName: "prod-api-01",
			Severity:   vault.SeverityCritical,
			Title:      "[prod-api-01] CPU 使用率 96%",
			Detail:     "连续 2 次超过严重阈值 92%",
		},
	}, nil)
	if !ok {
		t.Fatalf("expected NotifyMonitorAlerts to succeed via passive+plain fallback")
	}

	mock.mu.Lock()
	alertMsg := mock.sentMessages[len(mock.sentMessages)-1]
	mock.mu.Unlock()
	if len(mock.sentMessages) <= beforeAlerts {
		t.Fatalf("expected alert message to be delivered")
	}
	if alertMsg.Body["msg_id"] != "msg-status-1" {
		t.Fatalf("expected passive fallback to reuse latest msg-status-1, got %v", alertMsg.Body["msg_id"])
	}
	if mt, _ := alertMsg.Body["msg_type"].(float64); int(mt) != 0 {
		t.Fatalf("expected markdown fallback to plain text msg_type=0, got %v", alertMsg.Body["msg_type"])
	}

	// 6. Test AI Patrol, External Approval, and Vulnerability Advisory domain notifications!
	mock.mu.Lock()
	mock.rejectMarkdown = false
	mock.mu.Unlock()

	if !svc.NotifyPatrolRecord(context.Background(), vault.PatrolRecord{
		Status:       "warning",
		CompletedAt:  time.Now().UTC(),
		TotalServers: 3,
		WarningCount: 1,
		AISummary:    "磁盘写入偏高",
	}) {
		t.Fatalf("expected NotifyPatrolRecord to succeed")
	}
	if !svc.NotifyExternalApproval(context.Background(), vault.ExternalApproval{
		Title:       "清理过期日志",
		ClientName:  "Claude Code",
		RiskLevel:   "high",
		ServerNames: []string{"prod-api-01"},
		Reason:      "释放 /var/log 空间",
		Steps:       []vault.ExternalApprovalStep{{Index: 1, ToolName: "exec_ssh_command", Command: "journalctl --vacuum-time=7d"}},
	}) {
		t.Fatalf("expected NotifyExternalApproval to succeed")
	}
	if !svc.NotifyVulnAdvisories(context.Background(), []vault.VulnAdvisory{
		{
			ID:           "CVE-2026-99999",
			Severity:     vault.VulnSeverityCritical,
			IsKEV:        true,
			AppNames:     []string{"OpenSSL"},
			Title:        "Remote code execution in TLS handshake",
			FixedVersion: "3.4.2",
		},
	}) {
		t.Fatalf("expected NotifyVulnAdvisories to succeed")
	}

	// Verify push history recorded cleanly in runtime state
	rtSnap := store.GetQQBotRuntimeSnapshot()
	if len(rtSnap.PushHistory) < 4 {
		t.Fatalf("expected at least 4 push history entries, got %d", len(rtSnap.PushHistory))
	}
}

func TestClassifyCloseCodeMatrix(t *testing.T) {
	cases := []struct {
		code   int
		action CloseAction
	}{
		{4009, CloseActionResume},
		{4008, CloseActionResume},
		{4006, CloseActionReidentify},
		{4007, CloseActionReidentify},
		{4014, CloseActionConfigError},
		{4013, CloseActionConfigError},
		{4914, CloseActionFatalBanned},
		{4915, CloseActionFatalBanned},
	}
	for _, tc := range cases {
		act, msg := ClassifyCloseCode(tc.code)
		if act != tc.action || msg == "" {
			t.Fatalf("code %d: expected action %v with message, got action=%v msg=%q", tc.code, tc.action, act, msg)
		}
	}
}

func TestAtomicRaceSafeCloseWhileConnecting(t *testing.T) {
	// Ensure rapid Start -> NotifyConfigUpdated -> Close has zero data races or goroutine hangs
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	store := newReadyVaultStore(t)
	enabled := true
	appID := "12345"
	secret := "sec-race-test"
	_, _ = store.UpdateQQBotSettings(vault.QQBotSettingsUpdateInput{
		Enabled:    &enabled,
		AppID:      &appID,
		AppSecret:  &secret,
		APIBaseURL: &srv.URL,
	}, "127.0.0.1")

	svc := NewService(ServiceConfig{
		Store:                store,
		BaseReconnectBackoff: 20 * time.Millisecond,
	})
	svc.Start()
	time.Sleep(80 * time.Millisecond)
	svc.NotifyConfigUpdated()
	svc.Close()
}

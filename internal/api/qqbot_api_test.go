package api

import (
	"bytes"
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

func startMockQQGatewayForAPI(t *testing.T, appID, secret string) (*httptest.Server, *[]map[string]any, *sync.Mutex) {
	t.Helper()
	var mu sync.Mutex
	var pushed []map[string]any
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

	var ts *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/app/getAppAccessToken", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			AppID        string `json:"appId"`
			ClientSecret string `json:"clientSecret"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		if req.AppID != appID || req.ClientSecret != secret {
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 100016, "message": "invalid credentials"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "api-test-token", "expires_in": "7200"})
	})
	mux.HandleFunc("/gateway/bot", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "QQBot api-test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/websocket"
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"url":    wsURL,
			"shards": 1,
			"session_start_limit": map[string]any{
				"total": 1000, "remaining": 998, "reset_after": 86400000, "max_concurrency": 1,
			},
		})
	})
	mux.HandleFunc("/websocket", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.WriteJSON(map[string]any{"op": 10, "d": map[string]any{"heartbeat_interval": 30000}})
		for {
			var frame struct {
				Op int `json:"op"`
			}
			if err := conn.ReadJSON(&frame); err != nil {
				return
			}
			if frame.Op == 2 {
				_ = conn.WriteJSON(map[string]any{
					"op": 0, "s": 1, "t": "READY",
					"d": map[string]any{
						"version": 1, "session_id": "api-sess-001",
						"user": map[string]any{"id": "bot-1", "username": "SNS测试机器人", "bot": true},
					},
				})
			} else if frame.Op == 1 {
				_ = conn.WriteJSON(map[string]any{"op": 11})
			}
		}
	})
	msgHandler := func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "QQBot api-test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		body["_path"] = r.URL.Path
		mu.Lock()
		pushed = append(pushed, body)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "msg-ok-1"})
	}
	mux.HandleFunc("/v2/users/", msgHandler)
	mux.HandleFunc("/v2/groups/", msgHandler)
	mux.HandleFunc("/channels/", msgHandler)

	ts = httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts, &pushed, &mu
}

func TestQQBotNotificationAPIEndToEndAndSecretLeakGuard(t *testing.T) {
	const (
		qqAppID  = "102999888"
		qqSecret = "qq-super-secret-never-leak-7741"
	)
	mockQQ, pushed, pushedMu := startMockQQGatewayForAPI(t, qqAppID, qqSecret)

	srv, ts := newTestServerInstance(t, t.TempDir(), 8*time.Hour)
	defer ts.Close()
	defer srv.Close()

	// 1. Unauthenticated requests MUST be rejected with 401
	unauthClient := newCookieHTTPClient()
	if got := doWithHeaders(t, unauthClient, http.MethodGet, ts.URL+"/api/notifications/qqbot/overview", nil, nil); got != http.StatusUnauthorized {
		t.Fatalf("expected 401 unauthenticated GET overview, got %d", got)
	}

	client := newCookieHTTPClient()
	setupAdminForRegression(t, ts, client, "QQBotApiAdmin#2026!")

	// 2. Save encrypted QQ Bot WebSocket config
	cfgBody, _ := json.Marshal(map[string]any{
		"enabled":              true,
		"app_id":               qqAppID,
		"app_secret":           qqSecret,
		"api_base_url":         mockQQ.URL,
		"intents":              vault.QQIntentGroupAndC2CEvent,
		"message_format":       "text",
		"notify_monitor_alerts": true,
	})
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/notifications/qqbot/config", bytes.NewReader(cfgBody))
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("PUT /api/notifications/qqbot/config: status=%v err=%v", res.StatusCode, err)
	}
	res.Body.Close()

	// 3. GET overview must redact AppSecret completely and expose live WebSocket status
	deadline := time.Now().Add(5 * time.Second)
	var connected bool
	for time.Now().Before(deadline) {
		ovRes, err := client.Get(ts.URL + "/api/notifications/qqbot/overview")
		if err != nil || ovRes.StatusCode != http.StatusOK {
			t.Fatalf("GET overview: err=%v", err)
		}
		var raw bytes.Buffer
		_, _ = raw.ReadFrom(ovRes.Body)
		ovRes.Body.Close()
		if strings.Contains(raw.String(), qqSecret) {
			t.Fatalf("SECURITY FAILURE: raw QQ AppSecret leaked in overview response!")
		}
		var ov struct {
			Settings struct {
				HasAppSecret bool `json:"has_app_secret"`
			} `json:"settings"`
			Runtime struct {
				Connected   bool   `json:"connected"`
				BotUsername string `json:"bot_username"`
			} `json:"runtime"`
		}
		_ = json.Unmarshal(raw.Bytes(), &ov)
		if !ov.Settings.HasAppSecret {
			t.Fatalf("expected has_app_secret=true")
		}
		if ov.Runtime.Connected && ov.Runtime.BotUsername == "SNS测试机器人" {
			connected = true
			break
		}
		time.Sleep(40 * time.Millisecond)
	}
	if !connected {
		t.Fatalf("expected QQ Bot WebSocket to reach connected READY state")
	}

	// 4. SECURITY REGRESSION: Changing api_base_url / token_base_url / app_id without re-entering AppSecret
	// MUST be rejected on PUT /config, POST /probe, and POST /test-push so stored AppSecret can NEVER be harvested!
	var attackerHits atomic.Int32
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attackerHits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer attacker.Close()

	for _, tc := range []struct {
		method string
		path   string
		body   map[string]any
	}{
		{http.MethodPut, "/api/notifications/qqbot/config", map[string]any{"api_base_url": attacker.URL}},
		{http.MethodPost, "/api/notifications/qqbot/probe", map[string]any{"api_base_url": attacker.URL}},
		{http.MethodPost, "/api/notifications/qqbot/probe", map[string]any{"token_base_url": attacker.URL}},
		{http.MethodPost, "/api/notifications/qqbot/test-push", map[string]any{"api_base_url": attacker.URL, "target_type": "group", "target_id": "GRP1"}},
	} {
		b, _ := json.Marshal(tc.body)
		if got := doWithHeaders(t, client, tc.method, ts.URL+tc.path, b, nil); got != http.StatusBadRequest {
			t.Fatalf("security guard %s %s: expected 400, got %d", tc.method, tc.path, got)
		}
	}
	if attackerHits.Load() != 0 {
		t.Fatalf("SECURITY FAILURE: stored QQ AppSecret was sent to attacker endpoint (%d hits)", attackerHits.Load())
	}

	// 5. Probe against stored endpoint succeeds without re-entering secret
	if got := doWithHeaders(t, client, http.MethodPost, ts.URL+"/api/notifications/qqbot/probe", []byte(`{}`), nil); got != http.StatusOK {
		t.Fatalf("POST /api/notifications/qqbot/probe with stored config: expected 200, got %d", got)
	}

	// 6. Generate bind code, add a bound group target, send test-push, and verify delivery
	bindRes, err := client.Post(ts.URL+"/api/notifications/qqbot/bind-code", "application/json", bytes.NewReader([]byte(`{}`)))
	if err != nil || bindRes.StatusCode != http.StatusOK {
		t.Fatalf("POST bind-code: status=%v err=%v", bindRes.StatusCode, err)
	}
	bindRes.Body.Close()

	targetBody, _ := json.Marshal(map[string]any{
		"name":        "核心生产告警群",
		"target_type": "group",
		"target_id":   "GROUP_OPENID_API_TEST_01",
		"enabled":     true,
	})
	tRes, err := client.Post(ts.URL+"/api/notifications/qqbot/targets", "application/json", bytes.NewReader(targetBody))
	if err != nil || tRes.StatusCode != http.StatusOK {
		t.Fatalf("POST targets: status=%v err=%v", tRes.StatusCode, err)
	}
	var createdTarget struct {
		Target struct {
			ID string `json:"id"`
		} `json:"target"`
	}
	_ = json.NewDecoder(tRes.Body).Decode(&createdTarget)
	tRes.Body.Close()

	if got := doWithHeaders(t, client, http.MethodPost, ts.URL+"/api/notifications/qqbot/test-push", []byte(`{}`), nil); got != http.StatusOK {
		t.Fatalf("POST test-push: expected 200, got %d", got)
	}

	pushedMu.Lock()
	count := len(*pushed)
	pushedMu.Unlock()
	if count != 1 {
		t.Fatalf("expected 1 delivered QQ test push, got %d", count)
	}

	// 7. Backup & restore preserves encrypted QQBotSettings cleanly
	bundle, err := srv.cfg.Store.BuildBackupBundle(false)
	if err != nil {
		t.Fatalf("BuildBackupBundle: %v", err)
	}
	if bundle.Config.QQBotSettings.AppID != qqAppID || bundle.Config.QQBotSettings.AppSecret != qqSecret || len(bundle.Config.QQBotSettings.Targets) != 1 {
		t.Fatalf("expected BackupBundle to preserve QQBotSettings, got %+v", bundle.Config.QQBotSettings)
	}

	// 8. Delete target & clear logs
	if got := doWithHeaders(t, client, http.MethodDelete, ts.URL+"/api/notifications/qqbot/targets/"+createdTarget.Target.ID, nil, nil); got != http.StatusOK {
		t.Fatalf("DELETE target: expected 200, got %d", got)
	}
	if got := doWithHeaders(t, client, http.MethodPost, ts.URL+"/api/notifications/qqbot/clear-logs", []byte(`{}`), nil); got != http.StatusOK {
		t.Fatalf("POST clear-logs: expected 200, got %d", got)
	}
}

func TestQQBotServerWiredDomainNotifications(t *testing.T) {
	const (
		qqAppID  = "102777666"
		qqSecret = "qq-domain-hook-secret-8899"
	)
	mockQQ, pushed, pushedMu := startMockQQGatewayForAPI(t, qqAppID, qqSecret)

	srv, ts := newTestServerInstance(t, t.TempDir(), 8*time.Hour)
	defer ts.Close()
	defer srv.Close()

	client := newCookieHTTPClient()
	setupAdminForRegression(t, ts, client, "QQBotHooksAdmin#2026!")

	// Enable QQ Bot with a bound C2C target & all event domains enabled
	cfgBody, _ := json.Marshal(map[string]any{
		"enabled":                   true,
		"app_id":                    qqAppID,
		"app_secret":                qqSecret,
		"api_base_url":              mockQQ.URL,
		"notify_monitor_alerts":     true,
		"notify_ai_patrol":          true,
		"notify_external_approvals": true,
		"notify_vuln_advisories":    true,
	})
	if got := doWithHeaders(t, client, http.MethodPut, ts.URL+"/api/notifications/qqbot/config", cfgBody, nil); got != http.StatusOK {
		t.Fatalf("PUT config: expected 200, got %d", got)
	}
	targetBody, _ := json.Marshal(map[string]any{
		"name":        "值班工程师私聊",
		"target_type": "c2c",
		"target_id":   "USER_OPENID_HOOK_001",
		"enabled":     true,
	})
	if got := doWithHeaders(t, client, http.MethodPost, ts.URL+"/api/notifications/qqbot/targets", targetBody, nil); got != http.StatusOK {
		t.Fatalf("POST target: expected 200, got %d", got)
	}

	// Trigger QQBot domain notifications directly through the server's wired QQBot service
	okMon := srv.cfg.QQBot.NotifyMonitorAlerts(t.Context(), []vault.MonitorAlert{
		{ServerName: "edge-node-01", Severity: vault.SeverityCritical, Title: "[edge-node-01] 主机离线", Detail: "连续 2 次不可达"},
	}, nil)
	okVuln := srv.cfg.QQBot.NotifyVulnAdvisories(t.Context(), []vault.VulnAdvisory{
		{ID: "CVE-2026-11111", Severity: vault.VulnSeverityCritical, IsKEV: true, AppNames: []string{"Nginx"}, Title: "HTTP/3 memory corruption"},
	})
	if !okMon || !okVuln {
		t.Fatalf("expected wired monitor & vuln QQ notifications to succeed (mon=%v vuln=%v)", okMon, okVuln)
	}

	pushedMu.Lock()
	gotCount := len(*pushed)
	pushedMu.Unlock()
	if gotCount != 2 {
		t.Fatalf("expected 2 QQ notifications delivered to /v2/users/USER_OPENID_HOOK_001/messages, got %d", gotCount)
	}
}

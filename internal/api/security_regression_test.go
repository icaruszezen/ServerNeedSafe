package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func setupAdminForRegression(t *testing.T, ts *httptest.Server, client *http.Client, password string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"password": password})
	res, err := client.Post(ts.URL+"/api/auth/setup", "application/json", bytes.NewReader(body))
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/auth/setup: status=%v err=%v", res.StatusCode, err)
	}
	defer res.Body.Close()
	var out struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(res.Body).Decode(&out)
	if out.Token == "" {
		t.Fatalf("setup returned empty token")
	}
	return out.Token
}

func doWithHeaders(t *testing.T, client *http.Client, method, target string, body []byte, headers map[string]string) int {
	t.Helper()
	req, _ := http.NewRequest(method, target, bytes.NewReader(body))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	res.Body.Close()
	return res.StatusCode
}

// Reverse-proxy friendly client IP extraction for trusted intranet / reverse proxy deployments.
func TestExtractClientIPFriendlyProxyHeaders(t *testing.T) {
	mk := func(remote string, hdr map[string]string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "http://sns.internal/api/health", nil)
		r.RemoteAddr = remote
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		return r
	}
	if ip := extractClientIP(mk("10.0.0.5:4000", map[string]string{"X-Real-IP": "192.168.1.42"})); ip != "192.168.1.42" {
		t.Fatalf("expected X-Real-IP, got %s", ip)
	}
	if ip := extractClientIP(mk("172.18.0.1:4000", map[string]string{"X-Forwarded-For": "198.51.100.8, 10.0.0.2"})); ip != "198.51.100.8" {
		t.Fatalf("expected first valid X-Forwarded-For hop, got %s", ip)
	}
	if ip := extractClientIP(mk("10.0.0.9:5555", map[string]string{"X-Real-IP": "not-an-ip"})); ip != "10.0.0.9" {
		t.Fatalf("invalid header must fall back to RemoteAddr host, got %s", ip)
	}
}

// Stored (masked) AI API keys must never be sent to a caller-chosen endpoint via "test connection".
func TestAITestProviderDoesNotLeakStoredKey(t *testing.T) {
	srv, ts := newTestServerInstance(t, t.TempDir(), 8*time.Hour)
	defer ts.Close()
	defer srv.Close()

	var attackerHits atomic.Int32
	var attackerAuth atomic.Value
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attackerHits.Add(1)
		attackerAuth.Store(r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer attacker.Close()

	client := newCookieHTTPClient()
	setupAdminForRegression(t, ts, client, "AiLeakGuardAdmin#2026!")

	const storedKey = "sk-stored-secret-never-leak-9931"
	provBody, _ := json.Marshal(map[string]any{
		"name": "prod", "protocol": "openai", "base_url": "https://llm.internal.example/v1",
		"api_key": storedKey, "model": "gpt-x",
	})
	res, err := client.Post(ts.URL+"/api/ai/providers", "application/json", bytes.NewReader(provBody))
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/ai/providers: status=%v err=%v", res.StatusCode, err)
	}
	var created struct {
		Provider struct {
			ID string `json:"id"`
		} `json:"provider"`
	}
	_ = json.NewDecoder(res.Body).Decode(&created)
	res.Body.Close()

	testBody, _ := json.Marshal(map[string]any{
		"id": created.Provider.ID, "protocol": "openai", "base_url": attacker.URL + "/v1", "model": "gpt-x",
	})
	if got := doWithHeaders(t, client, http.MethodPost, ts.URL+"/api/ai/test-provider", testBody, nil); got != http.StatusBadRequest {
		t.Fatalf("test-provider with new base_url and stored key: expected 400, got %d", got)
	}
	if attackerHits.Load() != 0 {
		t.Fatalf("SECURITY FAILURE: stored API key was sent to attacker endpoint (auth=%v)", attackerAuth.Load())
	}

	// Persisting the re-pointed endpoint without re-entering the key is rejected as well.
	updBody, _ := json.Marshal(map[string]any{
		"id": created.Provider.ID, "name": "prod", "protocol": "openai", "base_url": attacker.URL + "/v1", "model": "gpt-x",
	})
	if got := doWithHeaders(t, client, http.MethodPost, ts.URL+"/api/ai/providers", updBody, nil); got != http.StatusBadRequest {
		t.Fatalf("update provider endpoint without key: expected 400, got %d", got)
	}

	// Explicit new key for the new endpoint is still allowed (key is caller-supplied, nothing leaks).
	testBody2, _ := json.Marshal(map[string]any{
		"id": created.Provider.ID, "protocol": "openai", "base_url": attacker.URL + "/v1", "model": "gpt-x", "api_key": "sk-caller-supplied",
	})
	_ = doWithHeaders(t, client, http.MethodPost, ts.URL+"/api/ai/test-provider", testBody2, nil)
	if v, _ := attackerAuth.Load().(string); strings.Contains(v, storedKey) {
		t.Fatalf("SECURITY FAILURE: stored key leaked: %q", v)
	}
}

// Revoked / logged-out sessions must not keep a live interactive SSH PTY, and "lock all sessions"
// must tear down open terminals.
func TestTerminalClosedAfterSessionRevocation(t *testing.T) {
	srv, ts := newTestServerInstance(t, t.TempDir(), 8*time.Hour)
	defer ts.Close()
	defer srv.Close()

	host, port, stop := startRootBreachTestSSHServer(t, "term_ops", "TermOpsPass!77", nil)
	defer stop()

	admin := newCookieHTTPClient()
	const adminPass = "TerminalRevokeAdmin#2026!"
	setupAdminForRegression(t, ts, admin, adminPass)

	srvBody, _ := json.Marshal(map[string]any{
		"name": "term-node", "host": host, "port": port, "username": "term_ops",
		"auth_type": "password", "password": "TermOpsPass!77",
	})
	res, err := admin.Post(ts.URL+"/api/servers", "application/json", bytes.NewReader(srvBody))
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/servers: status=%v err=%v", res.StatusCode, err)
	}
	var sWrap struct {
		Server struct {
			ID string `json:"id"`
		} `json:"server"`
	}
	_ = json.NewDecoder(res.Body).Decode(&sWrap)
	res.Body.Close()
	probe, err := admin.Post(ts.URL+"/api/servers/"+sWrap.Server.ID+"/probe", "application/json", bytes.NewReader([]byte(`{}`)))
	if err != nil || probe.StatusCode != http.StatusOK {
		t.Fatalf("probe: status=%v err=%v", probe.StatusCode, err)
	}
	probe.Body.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/api/ws/terminal?server_id=" + url.QueryEscape(sWrap.Server.ID)
	openTerminal := func(jar http.CookieJar) *websocket.Conn {
		d := websocket.Dialer{Jar: jar}
		c, _, err := d.Dial(wsURL, http.Header{"Origin": []string{ts.URL}})
		if err != nil {
			t.Fatalf("dial terminal: %v", err)
		}
		_ = c.SetReadDeadline(time.Now().Add(8 * time.Second))
		_, first, err := c.ReadMessage()
		if err != nil || !strings.Contains(string(first), `"ready"`) {
			t.Fatalf("expected ready frame, got %q err=%v", first, err)
		}
		return c
	}
	waitClosed := func(c *websocket.Conn, why string) string {
		var exitMsg string
		deadline := time.Now().Add(8 * time.Second)
		for time.Now().Before(deadline) {
			_ = c.SetReadDeadline(deadline)
			mt, data, err := c.ReadMessage()
			if err != nil {
				return exitMsg
			}
			if mt == websocket.TextMessage && strings.Contains(string(data), `"exit"`) {
				exitMsg = string(data)
			}
		}
		t.Fatalf("%s: terminal WebSocket still open", why)
		return ""
	}

	// (a) logout of the owning session → next keystroke is refused and the PTY is closed.
	c1 := openTerminal(admin.Jar)
	if code := doWithHeaders(t, admin, http.MethodPost, ts.URL+"/api/auth/logout", []byte(`{}`), nil); code != http.StatusOK {
		t.Fatalf("logout: %d", code)
	}
	_ = c1.WriteMessage(websocket.BinaryMessage, []byte("echo SHOULD_NOT_RUN_4410\n"))
	if msg := waitClosed(c1, "after logout"); !strings.Contains(msg, "会话已失效") {
		t.Fatalf("expected session-gone exit frame after logout, got %q", msg)
	}
	c1.Close()

	// (b) lock (revoke all) → open terminals are torn down immediately, without any client input.
	admin2 := newCookieHTTPClient()
	loginBody, _ := json.Marshal(map[string]string{"password": adminPass})
	lres, err := admin2.Post(ts.URL+"/api/auth/login", "application/json", bytes.NewReader(loginBody))
	if err != nil || lres.StatusCode != http.StatusOK {
		t.Fatalf("login: status=%v err=%v", lres.StatusCode, err)
	}
	lres.Body.Close()
	c2 := openTerminal(admin2.Jar)
	var wg sync.WaitGroup
	wg.Add(1)
	var lockedMsg string
	go func() {
		defer wg.Done()
		lockedMsg = waitClosed(c2, "after lock")
	}()
	if code := doWithHeaders(t, admin2, http.MethodPost, ts.URL+"/api/auth/lock", []byte(`{}`), nil); code != http.StatusOK {
		t.Fatalf("lock: %d", code)
	}
	wg.Wait()
	if lockedMsg == "" {
		t.Fatalf("expected an exit frame when sessions were locked")
	}
	c2.Close()
	if n := len(srv.cfg.SSH.ListActiveSessions()); n != 0 {
		t.Fatalf("expected no active SSH PTY sessions after lock, got %d", n)
	}
}

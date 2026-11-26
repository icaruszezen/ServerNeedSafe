package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

func doTestJSONRequest(t *testing.T, client *http.Client, method, fullURL string, payload any) (int, []byte) {
	t.Helper()
	var body io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, fullURL, body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s failed: %v", method, fullURL, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

func TestMultiJumpFallbackRESTAndWebSocketProgress(t *testing.T) {
	t.Setenv("NO_PROXY", "127.0.0.1,localhost")
	dir := t.TempDir()
	srv, ts := newTestServerInstance(t, dir, 8*time.Hour)
	defer ts.Close()
	defer srv.Close()

	client := newCookieHTTPClient()
	status, raw := doTestJSONRequest(t, client, http.MethodPost, ts.URL+"/api/auth/setup", map[string]string{
		"password": "AdminPass#2026",
	})
	if status != http.StatusOK {
		t.Fatalf("setup failed (%d): %s", status, string(raw))
	}

	// Start one live backup jump server and one live target server; primary jump uses a closed port.
	deadLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen dead port: %v", err)
	}
	deadPort := deadLn.Addr().(*net.TCPAddr).Port
	_ = deadLn.Close()

	backupHost, backupPort, stopBackup := startRootBreachTestSSHServer(t, "jump2", "Jump2Pass!", nil)
	defer stopBackup()
	targetHost, targetPort, stopTarget := startRootBreachTestSSHServer(t, "root", "TargetPass!", nil)
	defer stopTarget()

	createSrv := func(payload map[string]any) vault.ServerView {
		st, body := doTestJSONRequest(t, client, http.MethodPost, ts.URL+"/api/servers", payload)
		if st != http.StatusOK {
			t.Fatalf("create server failed (%d): %s", st, string(body))
		}
		var out struct {
			Server vault.ServerView `json:"server"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatalf("decode server: %v", err)
		}
		return out.Server
	}

	j1 := createSrv(map[string]any{
		"name": "Jump-Dead-HK", "group": "网关", "host": "127.0.0.1", "port": deadPort,
		"username": "jump1", "auth_type": "password", "password": "Jump1Pass!",
	})
	j2 := createSrv(map[string]any{
		"name": "Jump-Live-SG", "group": "网关", "host": backupHost, "port": backupPort,
		"username": "jump2", "auth_type": "password", "password": "Jump2Pass!",
	})
	target := createSrv(map[string]any{
		"name":                 "US-Target",
		"group":                "海外节点",
		"host":                 targetHost,
		"port":                 targetPort,
		"username":             "root",
		"auth_type":            "password",
		"password":             "TargetPass!",
		"jump_server_ids":      []string{j1.ID, j2.ID},
		"jump_fallback_direct": true,
	})
	if len(target.JumpServerIDs) != 2 || target.JumpServerIDs[0] != j1.ID || target.JumpServerIDs[1] != j2.ID || !target.JumpFallbackDirect {
		t.Fatalf("unexpected created multi-jump server view: %+v", target)
	}

	// 1. WebSocket /api/ws/terminal must stream progress frames before ready with route info
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/api/ws/terminal?server_id=" + url.QueryEscape(target.ID) + "&cols=100&rows=30"
	wsDialer := websocket.Dialer{Jar: client.Jar}
	wsConn, _, err := wsDialer.Dial(wsURL, http.Header{"Origin": []string{ts.URL}})
	if err != nil {
		t.Fatalf("ws dial failed: %v", err)
	}
	defer wsConn.Close()

	var sawProgress bool
	var readyFrame string
	for i := 0; i < 10; i++ {
		_ = wsConn.SetReadDeadline(time.Now().Add(8 * time.Second))
		_, frame, rErr := wsConn.ReadMessage()
		if rErr != nil {
			t.Fatalf("ws read frame %d failed: %v", i, rErr)
		}
		var env struct {
			Type string `json:"type"`
		}
		_ = json.Unmarshal(frame, &env)
		if env.Type == "progress" {
			sawProgress = true
			continue
		}
		if env.Type == "ready" {
			readyFrame = string(frame)
			break
		}
	}
	if !sawProgress {
		t.Fatalf("expected at least one progress frame before ready on multi-jump WS terminal")
	}
	if readyFrame == "" || !strings.Contains(readyFrame, "Jump-Live-SG") || !strings.Contains(readyFrame, `"fallback_used":true`) {
		t.Fatalf("expected ready frame with fallback route via Jump-Live-SG, got: %s", readyFrame)
	}

	// 2. REST Probe endpoint returns route_label & route_fallback
	status, raw = doTestJSONRequest(t, client, http.MethodPost, ts.URL+"/api/servers/"+target.ID+"/probe", map[string]any{})
	if status != http.StatusOK {
		t.Fatalf("probe failed (%d): %s", status, string(raw))
	}
	var probeOut struct {
		Probe struct {
			Reachable     bool   `json:"reachable"`
			RouteLabel    string `json:"route_label"`
			RouteFallback bool   `json:"route_fallback"`
		} `json:"probe"`
	}
	if err := json.Unmarshal(raw, &probeOut); err != nil {
		t.Fatalf("decode probe: %v", err)
	}
	if !probeOut.Probe.Reachable || !probeOut.Probe.RouteFallback || !strings.Contains(probeOut.Probe.RouteLabel, "Jump-Live-SG") {
		t.Fatalf("unexpected probe route output: %+v", probeOut.Probe)
	}

	// 3. Deleting dead j1 promotes j2 to primary cleanly
	status, raw = doTestJSONRequest(t, client, http.MethodDelete, ts.URL+"/api/servers/"+j1.ID, nil)
	if status != http.StatusOK {
		t.Fatalf("delete j1 failed (%d): %s", status, string(raw))
	}
	status, raw = doTestJSONRequest(t, client, http.MethodGet, ts.URL+"/api/servers", nil)
	if status != http.StatusOK {
		t.Fatalf("list servers failed (%d): %s", status, string(raw))
	}
	var listOut struct {
		Servers []vault.ServerView `json:"servers"`
	}
	_ = json.Unmarshal(raw, &listOut)
	var updatedTarget *vault.ServerView
	for i := range listOut.Servers {
		if listOut.Servers[i].ID == target.ID {
			updatedTarget = &listOut.Servers[i]
			break
		}
	}
	if updatedTarget == nil || len(updatedTarget.JumpServerIDs) != 1 || updatedTarget.JumpServerIDs[0] != j2.ID || !updatedTarget.JumpFallbackDirect {
		t.Fatalf("expected target jump list shifted to [j2] after deleting j1, got: %+v", updatedTarget)
	}
}

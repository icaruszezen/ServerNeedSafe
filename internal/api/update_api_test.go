package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/icaruszezen/ServerNeedSafe/internal/auth"
	"github.com/icaruszezen/ServerNeedSafe/internal/updater"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

func TestUpdateAPIEndpointsAndActiveSSHGuard(t *testing.T) {
	tmpDir := t.TempDir()
	fakeExe := filepath.Join(tmpDir, "sns-server")
	_ = os.WriteFile(fakeExe, []byte{0x7f, 'E', 'L', 'F'}, 0o755)

	mockMirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "releases.atom") {
			w.Header().Set("Content-Type", "application/atom+xml")
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Release notes from ServerNeedSafe</title>
  <entry>
    <id>tag:github.com,2008:Repository/1/v2.4.0</id>
    <updated>2026-11-26T12:00:00Z</updated>
    <link rel="alternate" type="text/html" href="https://github.com/icaruszezen/ServerNeedSafe/releases/tag/v2.4.0"/>
    <title>ServerNeedSafe v2.4.0</title>
    <content type="html">&lt;p&gt;New auto-update feature&lt;/p&gt;</content>
  </entry>
</feed>`))
			return
		}
		http.NotFound(w, r)
	}))
	defer mockMirror.Close()

	store, err := vault.NewStore(filepath.Join(tmpDir, "data"))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := store.Setup("AdminPass#2026", "127.0.0.1"); err != nil {
		t.Fatalf("setup store: %v", err)
	}
	authMgr, err := auth.NewManager(auth.DefaultSessionTTL, false)
	if err != nil {
		t.Fatalf("new auth: %v", err)
	}

	activeSSH := 2
	inDocker := false
	upd := updater.NewService(updater.Config{
		DeployMode:      "server",
		Store:           store,
		CurrentVersion:  "v2.3.0",
		ExecutablePath:  fakeExe,
		InDocker:        &inDocker,
		GitHubBaseURL:   mockMirror.URL,
		GitHubAPIBase:   mockMirror.URL + "/api-disabled",
		DisableAutoLoop: true,
		ActiveSSHCount:  func() int { return activeSSH },
		BuiltinMirrors: []updater.MirrorNode{
			{ID: "cn-test", Name: "测试国内镜像", Prefix: mockMirror.URL + "/", Region: "cn"},
		},
	})

	srv := NewServer(Config{
		DeployMode: "server",
		Store:      store,
		Auth:       authMgr,
		Updater:    upd,
	})
	defer srv.Close()

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// 1. Public /api/health returns version info
	healthResp, err := http.Get(ts.URL + "/api/health")
	if err != nil {
		t.Fatalf("health GET: %v", err)
	}
	var healthBody map[string]any
	_ = json.NewDecoder(healthResp.Body).Decode(&healthBody)
	healthResp.Body.Close()
	if healthBody["version"] == nil {
		t.Fatalf("expected version field in /api/health, got %+v", healthBody)
	}

	// 2. Unauthenticated update status must return 401
	unauthResp, err := http.Get(ts.URL + "/api/system/update/status")
	if err != nil {
		t.Fatalf("unauth GET: %v", err)
	}
	unauthResp.Body.Close()
	if unauthResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated update status, got %d", unauthResp.StatusCode)
	}

	// Authenticate as admin
	sess, err := authMgr.CreateSession(store.AuthVersion(), "127.0.0.1", "test")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	doReq := func(method, path string, body any) *http.Response {
		var rdr *bytes.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rdr = bytes.NewReader(b)
		} else {
			rdr = bytes.NewReader(nil)
		}
		req, _ := http.NewRequest(method, ts.URL+path, rdr)
		req.Header.Set("Authorization", "Bearer "+sess.Token)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s failed: %v", method, path, err)
		}
		return resp
	}

	// 3. Check update now
	chkResp := doReq(http.MethodPost, "/api/system/update/check", map[string]any{"force_probe": true})
	var chkBody map[string]any
	_ = json.NewDecoder(chkResp.Body).Decode(&chkBody)
	chkResp.Body.Close()
	if chkResp.StatusCode != http.StatusOK || chkBody["update_available"] != true {
		t.Fatalf("expected update_available=true, status=%d body=%+v", chkResp.StatusCode, chkBody)
	}

	// 4. Reject insecure custom mirror URL
	badCfgResp := doReq(http.MethodPut, "/api/system/update/config", map[string]any{
		"mirror_mode":       "custom",
		"custom_mirror_url": "http://insecure.example.com/",
	})
	badCfgResp.Body.Close()
	if badCfgResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for insecure custom mirror, got %d", badCfgResp.StatusCode)
	}

	// 5. Save valid update config
	goodCfgResp := doReq(http.MethodPut, "/api/system/update/config", map[string]any{
		"auto_check_enabled":   true,
		"check_interval_hours": 12,
		"mirror_mode":          "auto",
		"custom_mirror_url":    "https://gh-proxy.com",
		"include_prerelease":   true,
	})
	var goodCfgBody map[string]any
	_ = json.NewDecoder(goodCfgResp.Body).Decode(&goodCfgBody)
	goodCfgResp.Body.Close()
	if goodCfgResp.StatusCode != http.StatusOK || goodCfgBody["ok"] != true {
		t.Fatalf("expected 200 saving valid config, got %d %+v", goodCfgResp.StatusCode, goodCfgBody)
	}

	// 6. Skip and unskip version
	skipResp := doReq(http.MethodPost, "/api/system/update/skip", map[string]any{"version": "v2.4.0"})
	var skipBody map[string]any
	_ = json.NewDecoder(skipResp.Body).Decode(&skipBody)
	skipResp.Body.Close()
	if skipResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 skip, got %d", skipResp.StatusCode)
	}
	statusMap, _ := skipBody["status"].(map[string]any)
	if statusMap["skipped"] != true {
		t.Fatalf("expected skipped=true after skipping v2.4.0, got %+v", statusMap)
	}

	// 7. Apply update with active SSH tabs -> 409 ACTIVE_SSH_SESSIONS
	applyResp := doReq(http.MethodPost, "/api/system/update/apply", map[string]any{"confirm_disconnect_ssh": false})
	var applyBody map[string]any
	_ = json.NewDecoder(applyResp.Body).Decode(&applyBody)
	applyResp.Body.Close()
	if applyResp.StatusCode != http.StatusConflict || applyBody["code"] != "ACTIVE_SSH_SESSIONS" {
		t.Fatalf("expected 409 ACTIVE_SSH_SESSIONS, got %d %+v", applyResp.StatusCode, applyBody)
	}
}

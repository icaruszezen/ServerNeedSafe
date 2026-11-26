package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/auth"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
	"github.com/icaruszezen/ServerNeedSafe/web"
)

func TestDesktopLoopbackGuardEmbeddedSPAAndFastAutoBoot(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := vault.NewStore(tmpDir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	authMgr, err := auth.NewManager(auth.DefaultSessionTTL, true)
	if err != nil {
		store.Close()
		t.Fatalf("NewManager: %v", err)
	}
	staticFS, err := web.DistFS()
	if err != nil {
		store.Close()
		t.Fatalf("DistFS: %v", err)
	}

	srv := NewServer(Config{
		DeployMode: "desktop",
		Store:      store,
		Auth:       authMgr,
		StaticFS:   staticFS,
	})
	defer srv.Close()

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// 1. External local browser tab WITHOUT desktop boot cookie MUST get 403 Forbidden on /api/*
	untrustedClient := &http.Client{}
	res, err := untrustedClient.Get(ts.URL + "/api/auth/status")
	if err != nil {
		t.Fatalf("GET /api/auth/status: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for untrusted local origin, got %d", res.StatusCode)
	}

	// 2. Native WebView2 window navigating to /__desktop_boot?boot=<code> receives HttpOnly cookie & loads SPA
	jar, _ := cookiejar.New(nil)
	desktopClient := &http.Client{Jar: jar}
	bootURL := ts.URL + "/__desktop_boot?boot=" + authMgr.DesktopBootCode()
	res, err = desktopClient.Get(bootURL)
	if err != nil {
		t.Fatalf("GET bootURL: %v", err)
	}
	htmlBytes, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK on SPA redirect, got %d", res.StatusCode)
	}
	if !strings.Contains(string(htmlBytes), "<div id=\"root\">") {
		t.Fatalf("expected embedded SPA index.html, got:\n%s", string(htmlBytes))
	}
	if strings.Contains(string(htmlBytes), "sns-zk.wasm") {
		t.Fatalf("expected lightweight SPA without sns-zk.wasm reference")
	}

	// 3. /api/auth/status works inside desktop window, while protected APIs still require session auth
	res, err = desktopClient.Get(ts.URL + "/api/auth/status")
	if err != nil {
		t.Fatalf("GET /api/auth/status with desktop cookie: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK with desktop guard cookie, got %d", res.StatusCode)
	}

	for _, protectedPath := range []string{"/api/servers", "/api/vault/security", "/api/workspace/bootstrap"} {
		pRes, err := desktopClient.Get(ts.URL + protectedPath)
		if err != nil {
			t.Fatalf("GET %s: %v", protectedPath, err)
		}
		pRes.Body.Close()
		if pRes.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized on %s before setup/login, got %d", protectedPath, pRes.StatusCode)
		}
	}

	// 4. Initialize vault in desktop window -> writes secrets.enc + 0600 master.key and marks daemon ready
	setupPayload, _ := json.Marshal(map[string]string{"password": "DesktopMasterPass!2026"})
	setupRes, err := desktopClient.Post(ts.URL+"/api/auth/setup", "application/json", bytes.NewReader(setupPayload))
	if err != nil {
		t.Fatalf("POST /api/auth/setup: %v", err)
	}
	setupRes.Body.Close()
	if setupRes.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK on desktop setup, got %d", setupRes.StatusCode)
	}

	keyInfo, err := os.Stat(filepath.Join(tmpDir, "master.key"))
	if err != nil {
		t.Fatalf("expected master.key to be created: %v", err)
	}
	if keyInfo.Mode().Perm() != 0o600 {
		t.Fatalf("expected master.key permissions 0600, got %o", keyInfo.Mode().Perm())
	}

	// 5. Simulate restarting desktop process -> auto-boots ready in <250ms via master.key without Argon2id!
	srv.Close()
	bootStart := time.Now()
	store2, err := vault.NewStore(tmpDir)
	if err != nil {
		t.Fatalf("reopened NewStore: %v", err)
	}
	authMgr2, _ := auth.NewManager(auth.DefaultSessionTTL, true)
	srv2 := NewServer(Config{
		DeployMode: "desktop",
		Store:      store2,
		Auth:       authMgr2,
		StaticFS:   staticFS,
	})
	defer srv2.Close()
	bootElapsed := time.Since(bootStart)
	if !srv2.isDaemonReady() {
		t.Fatalf("expected desktop daemon to auto-boot ready via master.key on restart")
	}
	if bootElapsed > 250*time.Millisecond {
		t.Fatalf("expected fast <250ms master.key auto-boot on restart, took %s", bootElapsed)
	}
}

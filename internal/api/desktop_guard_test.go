package api

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/auth"
	"github.com/icaruszezen/ServerNeedSafe/internal/sshmanager"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
	"github.com/icaruszezen/ServerNeedSafe/web"
)

func TestDesktopLoopbackGuardAndEmbeddedWebUI(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := vault.NewStore(filepath.Join(tmpDir, "vault.sns"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	authMgr, err := auth.NewManager(time.Hour, true)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	staticFS, err := web.DistFS()
	if err != nil {
		t.Fatalf("DistFS: %v", err)
	}

	srv := NewServer(Config{
		DeployMode: "desktop",
		Store:      store,
		Auth:       authMgr,
		SSH:        sshmanager.NewManager(store),
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
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK on SPA redirect, got %d", res.StatusCode)
	}

	// 3. Now /api/auth/status works inside the desktop window, and still requires Admin Password setup/unlock!
	res, err = desktopClient.Get(ts.URL + "/api/auth/status")
	if err != nil {
		t.Fatalf("GET /api/auth/status with desktop cookie: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK with desktop guard cookie, got %d", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("unexpected content-type: %s", ct)
	}
}

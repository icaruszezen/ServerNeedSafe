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
	"github.com/icaruszezen/ServerNeedSafe/internal/relay"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
	"github.com/icaruszezen/ServerNeedSafe/web"
)

func TestDesktopLoopbackGuardEmbeddedSRIAndAutoUnlock(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sns")
	blindStore, err := vault.NewBlindStore(vaultPath)
	if err != nil {
		t.Fatalf("NewBlindStore: %v", err)
	}
	authMgr, err := auth.NewManager(time.Hour, true)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	staticFS, err := web.DistFS()
	if err != nil {
		t.Fatalf("DistFS: %v", err)
	}
	keyMgr := vault.NewServerKeyManager(tmpDir)

	srv := NewServer(Config{
		DeployMode: "desktop",
		BlindStore: blindStore,
		KeyMgr:     keyMgr,
		Auth:       authMgr,
		Relay:      relay.NewManager("127.0.0.1:0"),
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

	// 2. Native WebView2 window navigating to /__desktop_boot?boot=<code> receives HttpOnly cookie & loads SRI-protected SPA
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
	if !strings.Contains(string(htmlBytes), `integrity="sha384-`) {
		t.Fatalf("expected Subresource Integrity sha384 hashes in embedded index.html, got:\n%s", string(htmlBytes))
	}
	if strings.Contains(string(htmlBytes), "sns-zk.wasm") {
		t.Fatalf("expected lightweight SPA without sns-zk.wasm reference")
	}

	// 3. /api/auth/status works inside desktop window, while /api/servers and /api/vault/blob still require session auth!
	res, err = desktopClient.Get(ts.URL + "/api/auth/status")
	if err != nil {
		t.Fatalf("GET /api/auth/status with desktop cookie: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK with desktop guard cookie, got %d", res.StatusCode)
	}

	for _, protectedPath := range []string{"/api/servers", "/api/vault/blob", "/api/workspace/bootstrap"} {
		pRes, err := desktopClient.Get(ts.URL + protectedPath)
		if err != nil {
			t.Fatalf("GET %s: %v", protectedPath, err)
		}
		pRes.Body.Close()
		if pRes.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized on %s before setup/login, got %d", protectedPath, pRes.StatusCode)
		}
	}

	// 4. Initialize vault in desktop window -> writes vault.sns + 0600 .vault.key and unlocks daemon
	setupPayload, _ := json.Marshal(map[string]string{"password": "DesktopMasterPass!2026"})
	setupRes, err := desktopClient.Post(ts.URL+"/api/auth/setup", "application/json", bytes.NewReader(setupPayload))
	if err != nil {
		t.Fatalf("POST /api/auth/setup: %v", err)
	}
	setupRes.Body.Close()
	if setupRes.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK on desktop setup, got %d", setupRes.StatusCode)
	}

	keyInfo, err := os.Stat(keyMgr.KeyPath())
	if err != nil {
		t.Fatalf("expected .vault.key to be created: %v", err)
	}
	if keyInfo.Mode().Perm() != 0o600 {
		t.Fatalf("expected .vault.key permissions 0600, got %o", keyInfo.Mode().Perm())
	}

	// 5. Simulate restarting desktop process -> auto-unlocks in <20ms via .vault.key without Argon2id!
	srv.Close()
	blindStore2, err := vault.NewBlindStore(vaultPath)
	if err != nil {
		t.Fatalf("reopened NewBlindStore: %v", err)
	}
	authMgr2, _ := auth.NewManager(time.Hour, true)
	bootStart := time.Now()
	srv2 := NewServer(Config{
		DeployMode: "desktop",
		BlindStore: blindStore2,
		KeyMgr:     vault.NewServerKeyManager(tmpDir),
		Auth:       authMgr2,
		Relay:      relay.NewManager("127.0.0.1:0"),
		StaticFS:   staticFS,
	})
	defer srv2.Close()
	bootElapsed := time.Since(bootStart)
	if !srv2.isDaemonUnlocked() {
		t.Fatalf("expected desktop daemon to auto-unlock via .vault.key on restart")
	}
	if bootElapsed > 250*time.Millisecond {
		t.Fatalf("expected fast <250ms .vault.key auto-unlock on restart, took %s", bootElapsed)
	}
}

package api

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/auth"
	"github.com/icaruszezen/ServerNeedSafe/internal/relay"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
	"github.com/icaruszezen/ServerNeedSafe/web"
)

func TestDesktopLoopbackGuardEmbeddedSRIAndWASM(t *testing.T) {
	tmpDir := t.TempDir()
	blindStore, err := vault.NewBlindStore(filepath.Join(tmpDir, "vault.sns"))
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

	srv := NewServer(Config{
		DeployMode: "desktop",
		BlindStore: blindStore,
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

	// 3. Embedded /sns-zk.wasm serves valid WebAssembly binary (both gzip-negotiated and raw)
	wasmReq, _ := http.NewRequest("GET", ts.URL+"/sns-zk.wasm", nil)
	wasmReq.Header.Set("Accept-Encoding", "gzip")
	wasmRes, err := desktopClient.Do(wasmReq)
	if err != nil {
		t.Fatalf("GET /sns-zk.wasm: %v", err)
	}
	if wasmRes.StatusCode != http.StatusOK || wasmRes.Header.Get("Content-Encoding") != "gzip" {
		wasmRes.Body.Close()
		t.Fatalf("expected 200 gzipped WASM, got status=%d enc=%q", wasmRes.StatusCode, wasmRes.Header.Get("Content-Encoding"))
	}
	gzReader, err := gzip.NewReader(wasmRes.Body)
	if err != nil {
		wasmRes.Body.Close()
		t.Fatalf("gzip.NewReader: %v", err)
	}
	magic := make([]byte, 4)
	_, err = io.ReadFull(gzReader, magic)
	_ = gzReader.Close()
	wasmRes.Body.Close()
	if err != nil || !bytes.Equal(magic, []byte{0x00, 'a', 's', 'm'}) {
		t.Fatalf("expected WebAssembly magic header \\x00asm, got %v (err=%v)", magic, err)
	}

	// 4. /api/auth/status works inside desktop window, while /api/vault/blob still requires zero-knowledge auth!
	res, err = desktopClient.Get(ts.URL + "/api/auth/status")
	if err != nil {
		t.Fatalf("GET /api/auth/status with desktop cookie: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK with desktop guard cookie, got %d", res.StatusCode)
	}

	blobRes, err := desktopClient.Get(ts.URL + "/api/vault/blob")
	if err != nil {
		t.Fatalf("GET /api/vault/blob: %v", err)
	}
	blobRes.Body.Close()
	if blobRes.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized on /api/vault/blob before setup/unlock, got %d", blobRes.StatusCode)
	}
}

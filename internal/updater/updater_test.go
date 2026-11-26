package updater

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

func TestSemVerComparison(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"v2.3.0", "v2.3.0", 0},
		{"2.3.0", "v2.3.0", 0},
		{"v2.4.0", "v2.3.0", 1},
		{"v2.3.0", "v2.4.0", -1},
		{"v2.4.0-rc.1", "v2.4.0", -1},
		{"v2.4.0", "v2.4.0-rc.1", 1},
		{"v2.4.0-rc.2", "v2.4.0-rc.1", 1},
		{"v2.4.0-alpha.1", "v2.4.0-beta.1", -1},
		{"v2.10.0", "v2.9.9", 1},
	}
	for _, tc := range cases {
		got, err := CompareSemVer(tc.a, tc.b)
		if err != nil {
			t.Fatalf("CompareSemVer(%q, %q) unexpected error: %v", tc.a, tc.b, err)
		}
		if got != tc.want {
			t.Fatalf("CompareSemVer(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}

	if IsNewerVersion("v2.4.0", "dev") {
		t.Fatalf("expected dev build not to trigger update_available")
	}
	if !IsNewerVersion("v2.4.0", "v2.3.0") {
		t.Fatalf("expected v2.4.0 > v2.3.0")
	}
	if IsNewerVersion("v2.3.0", "v2.3.0") {
		t.Fatalf("expected equal version not newer")
	}
}

func TestValidateCustomMirrorURL(t *testing.T) {
	got, err := ValidateCustomMirrorURL("https://gh-proxy.com")
	if err != nil || got != "https://gh-proxy.com/" {
		t.Fatalf("expected normalized https://gh-proxy.com/, got %q err=%v", got, err)
	}

	got, err = ValidateCustomMirrorURL("https://mirror.example.cn/proxy?target={url}")
	if err != nil || got != "https://mirror.example.cn/proxy?target={url}" {
		t.Fatalf("expected template preserved, got %q err=%v", got, err)
	}

	if _, err := ValidateCustomMirrorURL("http://127.0.0.1:9999"); err != nil {
		t.Fatalf("expected loopback http mirror allowed for local proxy/testing, got %v", err)
	}

	for _, bad := range []string{
		"http://insecure.example.com/",
		"ftp://mirror.example.com/",
		"https://user:pass@gh-proxy.com/",
		"https://gh-proxy.com/ with space",
	} {
		if _, err := ValidateCustomMirrorURL(bad); err == nil {
			t.Fatalf("expected ValidateCustomMirrorURL(%q) to fail", bad)
		}
	}
}

func sampleAtomFeed(tags ...string) string {
	var buf strings.Builder
	buf.WriteString(`<?xml version="1.0" encoding="UTF-8"?><feed xmlns="http://www.w3.org/2005/Atom">`)
	buf.WriteString(`<title>Release notes from ServerNeedSafe</title>`)
	for _, tag := range tags {
		fmt.Fprintf(&buf, `<entry>
  <id>tag:github.com,2008:Repository/1/%s</id>
  <updated>2026-11-26T12:00:00Z</updated>
  <link rel="alternate" type="text/html" href="https://github.com/icaruszezen/ServerNeedSafe/releases/tag/%s"/>
  <title>ServerNeedSafe %s</title>
  <content type="html">&lt;p&gt;Release notes for %s&lt;/p&gt;&lt;ul&gt;&lt;li&gt;Auto update support&lt;/li&gt;&lt;/ul&gt;</content>
</entry>`, tag, tag, tag, tag)
	}
	buf.WriteString(`</feed>`)
	return buf.String()
}

func TestMirrorAutoRaceAndChinaAtomFallback(t *testing.T) {
	// Official GitHub simulates GFW drop / 503 failure.
	deadGitHub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "blocked", http.StatusBadGateway)
	}))
	defer deadGitHub.Close()

	// Slow China mirror (150ms)
	slowMirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(150 * time.Millisecond)
		if strings.Contains(r.URL.Path, "releases.atom") {
			w.Header().Set("Content-Type", "application/atom+xml")
			_, _ = w.Write([]byte(sampleAtomFeed("v2.5.0-rc.1", "v2.4.0", "v2.3.0")))
			return
		}
		http.NotFound(w, r)
	}))
	defer slowMirror.Close()

	// Fast China mirror (instant)
	fastMirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "releases.atom") {
			w.Header().Set("Content-Type", "application/atom+xml")
			_, _ = w.Write([]byte(sampleAtomFeed("v2.5.0-rc.1", "v2.4.0", "v2.3.0")))
			return
		}
		http.NotFound(w, r)
	}))
	defer fastMirror.Close()

	store, err := vault.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	defer store.Close()
	if err := store.Setup("TestPassword#123", "127.0.0.1"); err != nil {
		t.Fatalf("setup store: %v", err)
	}

	inDocker := false
	svc := NewService(Config{
		DeployMode:      "server",
		Store:           store,
		GitHubBaseURL:   deadGitHub.URL,
		GitHubAPIBase:   deadGitHub.URL,
		CurrentVersion:  "v2.3.0",
		InDocker:        &inDocker,
		DisableAutoLoop: true,
		BuiltinMirrors: []MirrorNode{
			{ID: "direct", Name: "GitHub 官方直连", Prefix: "", Region: "global", SupportsAPI: true},
			{ID: "cn-slow", Name: "慢速国内镜像", Prefix: slowMirror.URL + "/", Region: "cn"},
			{ID: "cn-fast", Name: "极速国内镜像", Prefix: fastMirror.URL + "/", Region: "cn"},
		},
	})

	// Stable channel should pick v2.4.0 (skipping v2.5.0-rc.1) via fast China mirror!
	ov, err := svc.CheckNow(context.Background(), true)
	if err != nil {
		t.Fatalf("CheckNow failed: %v", err)
	}
	if ov.LatestRelease == nil || ov.LatestRelease.TagName != "v2.4.0" {
		t.Fatalf("expected latest stable v2.4.0, got %+v", ov.LatestRelease)
	}
	if !ov.UpdateAvailable {
		t.Fatalf("expected update_available=true for v2.3.0 -> v2.4.0")
	}
	if ov.ActiveMirror == nil || ov.ActiveMirror.ID != "cn-fast" {
		t.Fatalf("expected fastest China mirror cn-fast, got %+v", ov.ActiveMirror)
	}
	if !strings.Contains(ov.LatestRelease.Body, "Auto update support") {
		t.Fatalf("expected cleaned release notes from Atom feed, got %q", ov.LatestRelease.Body)
	}

	// Enabling prerelease channel should discover v2.5.0-rc.1!
	cfg := store.GetUpdateSettings()
	cfg.IncludePrerelease = true
	if _, err := store.UpdateUpdateSettings(cfg, "127.0.0.1"); err != nil {
		t.Fatalf("update settings: %v", err)
	}
	ov2, err := svc.CheckNow(context.Background(), false)
	if err != nil {
		t.Fatalf("CheckNow prerelease failed: %v", err)
	}
	if ov2.LatestRelease == nil || ov2.LatestRelease.TagName != "v2.5.0-rc.1" || !ov2.LatestRelease.Prerelease {
		t.Fatalf("expected prerelease v2.5.0-rc.1, got %+v", ov2.LatestRelease)
	}
}

func TestChecksumCrossMirrorVerificationAndTamperAbort(t *testing.T) {
	deadGitHub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "blocked", http.StatusServiceUnavailable)
	}))
	defer deadGitHub.Close()

	asset := "sns-server-linux-amd64"
	goodHash := strings.Repeat("a", 64)
	evilHash := strings.Repeat("f", 64)

	mirrorA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "%s  %s\n", goodHash, asset)
	}))
	defer mirrorA.Close()

	mirrorB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "%s  %s\n", goodHash, asset)
	}))
	defer mirrorB.Close()

	rogueMirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "%s  %s\n", evilHash, asset)
	}))
	defer rogueMirror.Close()

	// 1. Two honest independent China mirrors agree -> pass!
	res, err := FetchVerifiedChecksum(
		context.Background(),
		nil,
		deadGitHub.URL,
		"icaruszezen/ServerNeedSafe",
		"v2.4.0",
		asset,
		"auto",
		[]MirrorNode{
			{ID: "direct", Name: "Direct", Prefix: ""},
			{ID: "m1", Name: "Mirror A", Prefix: mirrorA.URL + "/"},
			{ID: "m2", Name: "Mirror B", Prefix: mirrorB.URL + "/"},
		},
	)
	if err != nil {
		t.Fatalf("expected cross-mirror verification success, got: %v", err)
	}
	if res.SHA256 != goodHash || res.TrustSource != "cross_verified_mirrors" || len(res.VerifiedHosts) != 2 {
		t.Fatalf("unexpected verification result: %+v", res)
	}

	// 2. Rogue mirror disagrees with honest mirror -> hard tamper abort!
	_, err = FetchVerifiedChecksum(
		context.Background(),
		nil,
		deadGitHub.URL,
		"icaruszezen/ServerNeedSafe",
		"v2.4.0",
		asset,
		"auto",
		[]MirrorNode{
			{ID: "m1", Name: "Mirror A", Prefix: mirrorA.URL + "/"},
			{ID: "rogue", Name: "Rogue Mirror", Prefix: rogueMirror.URL + "/"},
		},
	)
	if err == nil || !strings.Contains(err.Error(), "不一致") {
		t.Fatalf("expected tamper mismatch abort, got err=%v", err)
	}

	// 3. Single mirror only when direct is dead in auto mode -> fail closed!
	_, err = FetchVerifiedChecksum(
		context.Background(),
		nil,
		deadGitHub.URL,
		"icaruszezen/ServerNeedSafe",
		"v2.4.0",
		asset,
		"auto",
		[]MirrorNode{
			{ID: "m1", Name: "Mirror A", Prefix: mirrorA.URL + "/"},
		},
	)
	if err == nil {
		t.Fatalf("expected fail-closed error when fewer than 2 mirrors reachable")
	}
}

func TestEndToEndSelfUpdateFailoverVerifyAndReplace(t *testing.T) {
	assetName := ExpectedAssetName("server", runtime.GOOS, runtime.GOARCH)
	if assetName == "" {
		t.Skipf("no server asset mapping for %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	// Build a valid fake ELF payload (> 1024 bytes) for the target version.
	newPayload := append([]byte{0x7f, 'E', 'L', 'F'}, bytes.Repeat([]byte("V240"), 512)...)
	sumArr := sha256.Sum256(newPayload)
	expectedHash := hex.EncodeToString(sumArr[:])
	sumsContent := fmt.Sprintf("%s  %s\n", expectedHash, assetName)

	badPayload := append([]byte{0x7f, 'E', 'L', 'F'}, bytes.Repeat([]byte("EVIL"), 512)...)

	deadGitHub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "blocked", http.StatusBadGateway)
	}))
	defer deadGitHub.Close()

	// Mirror 1 serves valid atom + valid checksums, BUT corrupted binary payload (tests failover!).
	corruptMirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "releases.atom"):
			_, _ = w.Write([]byte(sampleAtomFeed("v2.4.0")))
		case strings.Contains(r.URL.Path, "SHA256SUMS.txt"):
			_, _ = w.Write([]byte(sumsContent))
		case strings.Contains(r.URL.Path, assetName):
			_, _ = w.Write(badPayload)
		default:
			http.NotFound(w, r)
		}
	}))
	defer corruptMirror.Close()

	// Mirror 2 serves genuine atom + checksums + genuine binary payload.
	goodMirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(40 * time.Millisecond) // slightly slower so corruptMirror is attempted first!
		switch {
		case strings.Contains(r.URL.Path, "releases.atom"):
			_, _ = w.Write([]byte(sampleAtomFeed("v2.4.0")))
		case strings.Contains(r.URL.Path, "SHA256SUMS.txt"):
			_, _ = w.Write([]byte(sumsContent))
		case strings.Contains(r.URL.Path, assetName):
			_, _ = w.Write(newPayload)
		default:
			http.NotFound(w, r)
		}
	}))
	defer goodMirror.Close()

	tmpDir := t.TempDir()
	fakeExe := filepath.Join(tmpDir, "sns-server")
	oldPayload := append([]byte{0x7f, 'E', 'L', 'F'}, bytes.Repeat([]byte("OLD1"), 512)...)
	if err := os.WriteFile(fakeExe, oldPayload, 0o755); err != nil {
		t.Fatalf("write fake exe: %v", err)
	}

	store, err := vault.NewStore(filepath.Join(tmpDir, "data"))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	defer store.Close()
	if err := store.Setup("TestPassword#123", "127.0.0.1"); err != nil {
		t.Fatalf("setup store: %v", err)
	}

	var restartCalled atomic.Bool
	var selfCheckCalled atomic.Bool
	inDocker := false

	svc := NewService(Config{
		DeployMode:      "server",
		Store:           store,
		GitHubBaseURL:   deadGitHub.URL,
		GitHubAPIBase:   deadGitHub.URL,
		CurrentVersion:  "v2.3.0",
		ExecutablePath:  fakeExe,
		InDocker:        &inDocker,
		DisableAutoLoop: true,
		BuiltinMirrors: []MirrorNode{
			{ID: "direct", Name: "GitHub 官方直连", Prefix: "", Region: "global", SupportsAPI: true},
			{ID: "cn-1", Name: "故障镜像1", Prefix: corruptMirror.URL + "/", Region: "cn"},
			{ID: "cn-2", Name: "健康镜像2", Prefix: goodMirror.URL + "/", Region: "cn"},
		},
		SelfCheckFunc: func(ctx context.Context, binaryPath, expectedTag string) error {
			selfCheckCalled.Store(true)
			if err := verifyBinaryHeader(binaryPath, "linux"); err != nil {
				return err
			}
			if expectedTag != "v2.4.0" {
				return fmt.Errorf("unexpected tag %s", expectedTag)
			}
			return nil
		},
		OnRestart: func(exePath, backupPath string) error {
			restartCalled.Store(true)
			if exePath != fakeExe {
				return fmt.Errorf("unexpected exePath %s", exePath)
			}
			if _, err := os.Stat(backupPath); err != nil {
				return fmt.Errorf("expected backup at %s: %w", backupPath, err)
			}
			return nil
		},
	})

	if _, err := svc.CheckNow(context.Background(), true); err != nil {
		t.Fatalf("CheckNow: %v", err)
	}

	if _, _, err := svc.StartUpdate(true, "127.0.0.1"); err != nil {
		t.Fatalf("StartUpdate: %v", err)
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		st := svc.Status()
		if st.Job.Stage == StageRestarting && restartCalled.Load() {
			break
		}
		if st.Job.Stage == StageFailed {
			t.Fatalf("update failed unexpectedly: %s", st.Job.Error)
		}
		time.Sleep(50 * time.Millisecond)
	}

	if !selfCheckCalled.Load() {
		t.Fatalf("expected pre-swap self-check to run")
	}
	if !restartCalled.Load() {
		t.Fatalf("expected OnRestart hook to fire after atomic swap")
	}

	replacedBytes, err := os.ReadFile(fakeExe)
	if err != nil {
		t.Fatalf("read replaced exe: %v", err)
	}
	if !bytes.Equal(replacedBytes, newPayload) {
		t.Fatalf("expected executable to contain verified new payload")
	}
	bakBytes, err := os.ReadFile(fakeExe + ".bak")
	if err != nil {
		t.Fatalf("read backup exe: %v", err)
	}
	if !bytes.Equal(bakBytes, oldPayload) {
		t.Fatalf("expected backup file to preserve previous executable")
	}
}

func TestDockerAndDevCapabilities(t *testing.T) {
	inDocker := true
	svcDocker := NewService(Config{
		DeployMode:      "server",
		CurrentVersion:  "v2.3.0",
		InDocker:        &inDocker,
		DisableAutoLoop: true,
	})
	stDocker := svcDocker.Status()
	if stDocker.Capabilities.CanSelfUpdate || !stDocker.Capabilities.InDocker {
		t.Fatalf("expected Docker container to disable self-update: %+v", stDocker.Capabilities)
	}
	if stDocker.DockerCommands == nil || len(stDocker.DockerCommands.ChinaMirrors) < 2 {
		t.Fatalf("expected Docker China mirror upgrade commands, got %+v", stDocker.DockerCommands)
	}

	notDocker := false
	svcDev := NewService(Config{
		DeployMode:      "server",
		CurrentVersion:  "dev",
		ExecutablePath:  filepath.Join(t.TempDir(), "sns-server"),
		InDocker:        &notDocker,
		DisableAutoLoop: true,
	})
	stDev := svcDev.Status()
	if stDev.Capabilities.CanSelfUpdate || !stDev.Current.IsDev {
		t.Fatalf("expected dev build to disallow self-overwrite: %+v", stDev.Capabilities)
	}
}

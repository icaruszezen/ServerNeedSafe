package vuln

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

func TestParseCVSSv3BaseScore(t *testing.T) {
	cases := []struct {
		vec      string
		want     float64
		wantSev  vault.VulnSeverity
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, vault.VulnSeverityCritical},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, vault.VulnSeverityHigh},
		{"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", 5.4, vault.VulnSeverityMedium},
		{"CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.8, vault.VulnSeverityLow},
		{"8.8", 8.8, vault.VulnSeverityHigh},
	}
	for _, tc := range cases {
		score, sev := ParseCVSSScoreAndSeverity(tc.vec)
		if score != tc.want || sev != tc.wantSev {
			t.Errorf("ParseCVSSScoreAndSeverity(%q) = (%.1f, %s), want (%.1f, %s)", tc.vec, score, sev, tc.want, tc.wantSev)
		}
	}
}

func TestDefaultMinimalCoreCatalog(t *testing.T) {
	settings := vault.DefaultVulnSettings()
	if len(settings.WatchedAppIDs) != 4 {
		t.Fatalf("expected 4 default watched core apps, got %d: %v", len(settings.WatchedAppIDs), settings.WatchedAppIDs)
	}
	cat := BuildResolvedCatalog(settings)
	if len(cat) < 30 {
		t.Fatalf("expected >=30 built-in full-stack catalog apps, got %d", len(cat))
	}
	watched := 0
	for _, a := range cat {
		if a.Watched {
			watched++
		}
	}
	if watched != 4 {
		t.Fatalf("expected exactly 4 watched apps in default catalog, got %d", watched)
	}
}

func TestMultiSourceSyncMergeFilterWatchToggleAndRestart(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := vault.NewStore(tmpDir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	store.SetFlushDebounce(20 * time.Millisecond)
	if err := store.Setup("TestPass1234!", "127.0.0.1"); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	nowStr := time.Now().UTC().Format(time.RFC3339)
	todayStr := time.Now().UTC().Format("2006-01-02")
	var phase atomic.Int32
	phase.Store(1)

	mux := http.NewServeMux()
	// Mock OSV querybatch
	mux.HandleFunc("/v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Queries []struct {
				Package struct {
					Name      string `json:"name"`
					Ecosystem string `json:"ecosystem"`
				} `json:"package"`
			} `json:"queries"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		results := make([]map[string]any, len(req.Queries))
		for i, q := range req.Queries {
			switch q.Package.Name {
			case "openssl":
				results[i] = map[string]any{
					"vulns": []map[string]string{
						{"id": "OSV-OPENSSL-1", "modified": nowStr},
					},
				}
			case "openssh":
				vulns := []map[string]string{{"id": "OSV-SSH-1", "modified": nowStr}}
				if phase.Load() >= 2 {
					vulns = append(vulns, map[string]string{"id": "OSV-SSH-2", "modified": nowStr})
				}
				results[i] = map[string]any{"vulns": vulns}
			case "redis":
				results[i] = map[string]any{
					"vulns": []map[string]string{{"id": "OSV-REDIS-1", "modified": nowStr}},
				}
			default:
				results[i] = map[string]any{"vulns": []any{}}
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
	})

	// Mock OSV detail
	mux.HandleFunc("/v1/vulns/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")
		switch id {
		case "OSV-OPENSSL-1":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":        "OSV-OPENSSL-1",
				"aliases":   []string{"CVE-2026-10001"},
				"summary":   "OpenSSL TLS handshake buffer overflow",
				"details":   "Detailed OSV writeup for OpenSSL overflow.",
				"published": nowStr,
				"modified":  nowStr,
				"severity":  []map[string]string{{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
				"affected": []map[string]any{{
					"package": map[string]string{"ecosystem": "Debian", "name": "openssl"},
					"ranges":  []map[string]any{{"type": "ECOSYSTEM", "events": []map[string]string{{"introduced": "3.0.0"}, {"fixed": "3.0.16"}}}},
				}},
				"references": []map[string]string{{"type": "ADVISORY", "url": "https://osv.dev/OSV-OPENSSL-1"}},
			})
		case "OSV-SSH-1":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":        "OSV-SSH-1",
				"aliases":   []string{"CVE-2026-20001"},
				"summary":   "OpenSSH pre-auth race condition",
				"published": nowStr,
				"modified":  nowStr,
				"severity":  []map[string]string{{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}},
				"affected": []map[string]any{{
					"package": map[string]string{"ecosystem": "Ubuntu", "name": "openssh"},
					"ranges":  []map[string]any{{"type": "ECOSYSTEM", "events": []map[string]string{{"introduced": "9.0"}, {"fixed": "9.9p2"}}}},
				}},
			})
		case "OSV-SSH-2":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":        "OSV-SSH-2",
				"aliases":   []string{"CVE-2026-29999"},
				"summary":   "New critical OpenSSH remote code execution",
				"published": nowStr,
				"modified":  nowStr,
				"severity":  []map[string]string{{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
				"affected": []map[string]any{{
					"package": map[string]string{"ecosystem": "Ubuntu", "name": "openssh"},
					"ranges":  []map[string]any{{"type": "ECOSYSTEM", "events": []map[string]string{{"introduced": "9.5"}, {"fixed": "9.9p3"}}}},
				}},
			})
		case "OSV-REDIS-1":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":        "OSV-REDIS-1",
				"aliases":   []string{"CVE-2026-30001"},
				"summary":   "Redis Lua sandbox escape",
				"published": nowStr,
				"modified":  nowStr,
				"severity":  []map[string]string{{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"}},
				"affected": []map[string]any{{
					"package": map[string]string{"ecosystem": "Debian", "name": "redis"},
					"ranges":  []map[string]any{{"type": "ECOSYSTEM", "events": []map[string]string{{"introduced": "7.0.0"}, {"fixed": "7.4.2"}}}},
				}},
			})
		default:
			http.NotFound(w, r)
		}
	})

	// Mock OpenSSL official XML (same CVE-2026-10001 -> must deduplicate and prefer vendor source!)
	mux.HandleFunc("/openssl.xml", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<?xml version="1.0"?>
<security>
  <issue public="` + todayStr + `">
    <cve name="2026-10001"/>
    <title>OpenSSL Official Critical Buffer Overflow</title>
    <impact severity="Critical"/>
    <description>Official OpenSSL advisory description.</description>
    <fixed base="3.0" version="3.0.16" date="` + todayStr + `"/>
    <advisory url="/news/secadv/20261127.txt"/>
  </issue>
</security>`))
	})

	// Mock Nginx official HTML
	mux.HandleFunc("/nginx.html", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><body><ul>
<li><p>HTTP/3 QUIC null pointer dereference (<a href="https://nvd.nist.gov/vuln/detail/CVE-2026-40001">CVE-2026-40001</a>)<br/>
Severity: medium<br/>
Not vulnerable: 1.27.4+, 1.26.3+<br/>
Vulnerable: 1.25.0-1.27.3<br/>
Published ` + todayStr + `</p></li>
</ul></body></html>`))
	})

	// Mock CISA KEV (marks CVE-2026-10001 as actively exploited!)
	mux.HandleFunc("/kev.json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"vulnerabilities": []map[string]string{
				{
					"cveID":             "CVE-2026-10001",
					"vendorProject":     "OpenSSL",
					"product":           "OpenSSL",
					"vulnerabilityName": "OpenSSL Critical RCE",
					"dateAdded":         todayStr,
					"shortDescription":  "Actively exploited in the wild.",
					"requiredAction":    "Upgrade to 3.0.16 immediately.",
					"dueDate":           "2026-12-15",
				},
			},
		})
	})

	// Mock GitHub repo advisories
	mux.HandleFunc("/repos/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]any{})
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	var webhookHits atomic.Int32
	var aiHits atomic.Int32
	svc := NewService(Config{
		Store: store,
		Endpoints: SourceEndpoints{
			OSVBaseURL:         ts.URL,
			GitHubAPIBaseURL:   ts.URL,
			CISAKEVURL:         ts.URL + "/kev.json",
			OpenSSLXMLURL:      ts.URL + "/openssl.xml",
			OpenSSLXMLFallback: ts.URL + "/openssl.xml",
			NginxHTMLURL:       ts.URL + "/nginx.html",
		},
		HTTPClient: ts.Client(),
		AICompleter: func(ctx context.Context, sys, usr string) (string, string, error) {
			aiHits.Add(1)
			return `{"summary_zh":"OpenSSL 握手溢出高危漏洞","impact_zh":"公网 HTTPS 服务可直接触发","fix_steps_zh":["升级至 OpenSSL 3.0.16","重启关联服务"],"verification_cmd":"openssl version"}`, "mock-model", nil
		},
		WebhookSender: func(ctx context.Context, ch vault.WebhookChannel, title, color, md string, payload map[string]any) error {
			webhookHits.Add(1)
			return nil
		},
		DisableAutoLoop: true,
	})

	// 1. Cold first sync (default 4 core apps only -> Redis must NOT be fetched or shown)
	res, err := svc.SyncNow(context.Background(), nil)
	if err != nil {
		t.Fatalf("SyncNow #1: %v", err)
	}
	if !res.OK || res.FetchedCount != 3 {
		t.Fatalf("expected 3 deduplicated advisories (OpenSSL + OpenSSH + Nginx), got %+v", res)
	}

	ov, err := svc.BuildOverview(QueryFilter{})
	if err != nil {
		t.Fatalf("BuildOverview: %v", err)
	}
	if ov.KPI.Total != 3 || ov.KPI.Critical != 1 || ov.KPI.High != 1 || ov.KPI.Medium != 1 || ov.KPI.KEV != 1 {
		t.Fatalf("unexpected KPI: %+v", ov.KPI)
	}
	// Verify OpenSSL CVE merged vendor official title/URL + CVSS 9.8 + KEV tag!
	var opensslAdv *vault.VulnAdvisory
	for i := range ov.Advisories {
		if ov.Advisories[i].ID == "CVE-2026-10001" {
			opensslAdv = &ov.Advisories[i]
		}
	}
	if opensslAdv == nil {
		t.Fatalf("missing merged CVE-2026-10001")
	}
	if !opensslAdv.IsKEV || opensslAdv.CVSSScore != 9.8 || opensslAdv.PrimarySource != "OpenSSL 官方公告" || !opensslAdv.HasFix {
		t.Fatalf("unexpected merged OpenSSL advisory: %+v", opensslAdv)
	}

	// 2. Test self-selecting apps: enable Redis -> sync -> Redis appears; uncheck Nginx -> Nginx immediately disappears!
	watchedWithRedis := []string{"linux-kernel", "openssh", "openssl", "redis"}
	_, newly, err := store.UpdateVulnSettings(vault.VulnSettingsUpdateInput{
		WatchedAppIDs: &watchedWithRedis,
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("UpdateVulnSettings: %v", err)
	}
	if len(newly) != 1 || newly[0] != "redis" {
		t.Fatalf("expected newly enabled [redis], got %v", newly)
	}
	if _, err := svc.SyncNow(context.Background(), newly); err != nil {
		t.Fatalf("incremental SyncNow for redis: %v", err)
	}
	ov2, err := svc.BuildOverview(QueryFilter{})
	if err != nil {
		t.Fatalf("BuildOverview after toggle: %v", err)
	}
	if ov2.KPI.Total != 3 {
		t.Fatalf("expected 3 watched advisories (OpenSSL + OpenSSH + Redis; Nginx hidden), got %d", ov2.KPI.Total)
	}
	for _, a := range ov2.Advisories {
		if a.ID == "CVE-2026-40001" {
			t.Fatalf("unchecked app Nginx advisory should be hidden immediately")
		}
	}

	// 3. Test AI explanation caching
	ai1, err := svc.ExplainAdvisory(context.Background(), "CVE-2026-10001", false)
	if err != nil || ai1.SummaryZH == "" || aiHits.Load() != 1 {
		t.Fatalf("ExplainAdvisory #1 failed: %v %+v hits=%d", err, ai1, aiHits.Load())
	}
	ai2, err := svc.ExplainAdvisory(context.Background(), "CVE-2026-10001", false)
	if err != nil || ai2.SummaryZH != ai1.SummaryZH || aiHits.Load() != 1 {
		t.Fatalf("expected cached AI analysis without extra call, hits=%d", aiHits.Load())
	}

	// 4. Test Webhook push on second sync when new critical CVE arrives
	notifyOn := true
	customWH := ts.URL + "/webhook"
	if _, _, err := store.UpdateVulnSettings(vault.VulnSettingsUpdateInput{
		NotifyWebhook:    &notifyOn,
		CustomWebhookURL: &customWH,
	}, "127.0.0.1"); err != nil {
		t.Fatalf("enable webhook: %v", err)
	}
	phase.Store(2)
	if _, err := svc.SyncNow(context.Background(), nil); err != nil {
		t.Fatalf("SyncNow #2: %v", err)
	}
	if webhookHits.Load() != 1 {
		t.Fatalf("expected 1 webhook hit for newly discovered critical CVE-2026-29999, got %d", webhookHits.Load())
	}
	// Syncing again must NOT re-notify same CVE
	if _, err := svc.SyncNow(context.Background(), nil); err != nil {
		t.Fatalf("SyncNow #3: %v", err)
	}
	if webhookHits.Load() != 1 {
		t.Fatalf("expected deduplicated webhook hits=1, got %d", webhookHits.Load())
	}

	// 5. Verify triage state + vuln_runtime.json persistence across store reopen
	star := true
	store.UpdateVulnUserStates([]string{"CVE-2026-10001"}, nil, &star, nil)
	store.MarkAllVulnsRead()
	if err := store.FlushNow(); err != nil {
		t.Fatalf("FlushNow: %v", err)
	}
	store.Close()

	reopened, err := vault.NewStore(tmpDir)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer reopened.Close()
	if reopened.CountUnreadHighVulns() != 0 {
		t.Fatalf("expected 0 unread high vulns after MarkAllVulnsRead + reopen, got %d", reopened.CountUnreadHighVulns())
	}
	advReopened, err := reopened.GetVulnAdvisory("CVE-2026-10001")
	if err != nil || !advReopened.IsStarred || !advReopened.IsRead || advReopened.AIAnalysis == nil {
		t.Fatalf("expected persisted star/read/AIAnalysis after restart, got %+v err=%v", advReopened, err)
	}
}

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/auth"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
	"github.com/icaruszezen/ServerNeedSafe/internal/vuln"
)

func TestVulnerabilityMonitorAPI(t *testing.T) {
	store, err := vault.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	authMgr, err := auth.NewManager(time.Hour, false)
	if err != nil {
		t.Fatalf("auth.NewManager: %v", err)
	}

	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339)
	todayStr := now.Format("2006-01-02")

	// Lightweight mock upstream advisory server
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/querybatch":
			var req struct {
				Queries []struct {
					Package struct {
						Name string `json:"name"`
					} `json:"package"`
				} `json:"queries"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			res := make([]map[string]any, len(req.Queries))
			for i, q := range req.Queries {
				if q.Package.Name == "openssh" {
					res[i] = map[string]any{"vulns": []map[string]string{{"id": "OSV-API-SSH", "modified": nowStr}}}
				} else {
					res[i] = map[string]any{"vulns": []any{}}
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"results": res})
		case r.URL.Path == "/v1/vulns/OSV-API-SSH":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":        "OSV-API-SSH",
				"aliases":   []string{"CVE-2026-88001"},
				"summary":   "OpenSSH authentication bypass",
				"published": nowStr,
				"modified":  nowStr,
				"severity":  []map[string]string{{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
				"affected": []map[string]any{{
					"package": map[string]string{"ecosystem": "Debian", "name": "openssh"},
					"ranges":  []map[string]any{{"type": "ECOSYSTEM", "events": []map[string]string{{"introduced": "9.0"}, {"fixed": "9.9p2"}}}},
				}},
			})
		case r.URL.Path == "/nginx.html":
			_, _ = w.Write([]byte(`<ul><li><p>Nginx worker crash (CVE-2026-88002)<br/>Severity: low<br/>Not vulnerable: 1.27.5+<br/>Vulnerable: 1.27.0-1.27.4<br/>` + todayStr + `</p></li></ul>`))
		case r.URL.Path == "/openssl.xml":
			_, _ = w.Write([]byte(`<security></security>`))
		case r.URL.Path == "/kev.json":
			_ = json.NewEncoder(w).Encode(map[string]any{"vulnerabilities": []any{}})
		default:
			_ = json.NewEncoder(w).Encode([]any{})
		}
	}))
	defer mockUpstream.Close()

	vulnSvc := vuln.NewService(vuln.Config{
		Store: store,
		Endpoints: vuln.SourceEndpoints{
			OSVBaseURL:         mockUpstream.URL,
			GitHubAPIBaseURL:   mockUpstream.URL,
			CISAKEVURL:         mockUpstream.URL + "/kev.json",
			OpenSSLXMLURL:      mockUpstream.URL + "/openssl.xml",
			OpenSSLXMLFallback: mockUpstream.URL + "/openssl.xml",
			NginxHTMLURL:       mockUpstream.URL + "/nginx.html",
		},
		HTTPClient: mockUpstream.Client(),
		AICompleter: func(ctx context.Context, sys, usr string) (string, string, error) {
			return `{"summary_zh":"测试中文解读","impact_zh":"高危认证绕过","fix_steps_zh":["升级 OpenSSH 至 9.9p2"],"verification_cmd":"ssh -V"}`, "test-llm", nil
		},
		DisableAutoLoop: true,
	})

	srv := NewServer(Config{
		DeployMode:             "server",
		Store:                  store,
		Auth:                   authMgr,
		Vuln:                   vulnSvc,
		DisableAutoUpdateCheck: true,
		DisableAutoVulnSync:    true,
	})
	defer srv.Close()

	// Setup vault & obtain Bearer token
	setupReq := httptest.NewRequest(http.MethodPost, "/api/auth/setup", bytes.NewBufferString(`{"password":"StrongPassword123!"}`))
	setupRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(setupRes, setupReq)
	if setupRes.Code != http.StatusOK {
		t.Fatalf("setup failed: %d %s", setupRes.Code, setupRes.Body.String())
	}
	var setupPayload struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(setupRes.Body.Bytes(), &setupPayload)
	authHdr := "Bearer " + setupPayload.Token

	doReq := func(method, path string, body any) *httptest.ResponseRecorder {
		var buf bytes.Buffer
		if body != nil {
			_ = json.NewEncoder(&buf).Encode(body)
		}
		req := httptest.NewRequest(method, path, &buf)
		req.Header.Set("Authorization", authHdr)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec
	}

	// 1. Trigger sync
	syncRec := doReq(http.MethodPost, "/api/vulns/sync", map[string]any{})
	if syncRec.Code != http.StatusOK {
		t.Fatalf("sync failed: %d %s", syncRec.Code, syncRec.Body.String())
	}

	// 2. Check workspace bootstrap reports vuln_unread_high == 1 (only OpenSSH Critical, Nginx is Low)
	bootRec := doReq(http.MethodGet, "/api/workspace/bootstrap", nil)
	if bootRec.Code != http.StatusOK {
		t.Fatalf("bootstrap failed: %d", bootRec.Code)
	}
	var bootData map[string]any
	_ = json.Unmarshal(bootRec.Body.Bytes(), &bootData)
	if int(bootData["vuln_unread_high"].(float64)) != 1 {
		t.Fatalf("expected vuln_unread_high=1, got %v", bootData["vuln_unread_high"])
	}

	// 3. Filter overview by severity=critical & apps=openssh
	ovRec := doReq(http.MethodGet, "/api/vulns/overview?severities=critical&apps=openssh", nil)
	if ovRec.Code != http.StatusOK {
		t.Fatalf("overview failed: %d %s", ovRec.Code, ovRec.Body.String())
	}
	var ov vuln.OverviewResponse
	_ = json.Unmarshal(ovRec.Body.Bytes(), &ov)
	if len(ov.Advisories) != 1 || ov.Advisories[0].ID != "CVE-2026-88001" {
		t.Fatalf("unexpected filtered advisories: %+v", ov.Advisories)
	}
	if len(ov.Settings.WatchedAppIDs) != 4 {
		t.Fatalf("expected 4 minimal core watched apps, got %v", ov.Settings.WatchedAppIDs)
	}

	// 4. Add custom GitHub app & delete it
	addRec := doReq(http.MethodPost, "/api/vulns/custom-apps", map[string]any{
		"name": "Nacos",
		"kind": "github_repo",
		"repo": "alibaba/nacos",
	})
	if addRec.Code != http.StatusOK {
		t.Fatalf("add custom app failed: %d %s", addRec.Code, addRec.Body.String())
	}
	var addData struct {
		App vault.VulnCustomApp `json:"app"`
	}
	_ = json.Unmarshal(addRec.Body.Bytes(), &addData)
	delRec := doReq(http.MethodDelete, "/api/vulns/custom-apps/"+addData.App.ID, nil)
	if delRec.Code != http.StatusOK {
		t.Fatalf("delete custom app failed: %d %s", delRec.Code, delRec.Body.String())
	}

	// 5. On-demand AI Chinese explain
	expRec := doReq(http.MethodPost, "/api/vulns/CVE-2026-88001/explain", map[string]any{})
	if expRec.Code != http.StatusOK {
		t.Fatalf("explain failed: %d %s", expRec.Code, expRec.Body.String())
	}
	var expData struct {
		Analysis vault.VulnAIAnalysis `json:"analysis"`
	}
	_ = json.Unmarshal(expRec.Body.Bytes(), &expData)
	if expData.Analysis.SummaryZH != "测试中文解读" {
		t.Fatalf("unexpected AI analysis: %+v", expData.Analysis)
	}

	// 6. Mark all read clears badge count
	readRec := doReq(http.MethodPost, "/api/vulns/mark-all-read", map[string]any{})
	if readRec.Code != http.StatusOK {
		t.Fatalf("mark-all-read failed: %d", readRec.Code)
	}
	var readData map[string]any
	_ = json.Unmarshal(readRec.Body.Bytes(), &readData)
	if int(readData["vuln_unread_high"].(float64)) != 0 {
		t.Fatalf("expected vuln_unread_high=0 after mark-all-read, got %v", readData["vuln_unread_high"])
	}

	// 7. Secret redaction check on PUT /api/vulns/config
	cfgRec := doReq(http.MethodPut, "/api/vulns/config", map[string]any{
		"github_token":   "ghp_supersecret123456",
		"http_proxy_url": "http://user:pass123@127.0.0.1:7890",
	})
	if cfgRec.Code != http.StatusOK {
		t.Fatalf("config update failed: %d %s", cfgRec.Code, cfgRec.Body.String())
	}
	if bytes.Contains(cfgRec.Body.Bytes(), []byte("ghp_supersecret123456")) || bytes.Contains(cfgRec.Body.Bytes(), []byte("pass123")) {
		t.Fatalf("secret leaked in config response: %s", cfgRec.Body.String())
	}
}

package vuln

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

const vulnUserAgent = "ServerNeedSafe-VulnMonitor/1.0"

// SourceEndpoints defines upstream official advisory endpoints (overridable in unit tests).
type SourceEndpoints struct {
	OSVBaseURL        string
	GitHubAPIBaseURL  string
	CISAKEVURL        string
	OpenSSLXMLURL     string
	OpenSSLXMLFallback string
	NginxHTMLURL      string
	K8sCVEFeedURL     string
	UbuntuUSNRSSURL   string
	DebianDSARSSURL   string
	GitLabSecRSSURL   string
	PostgresRSSURL    string
}

// DefaultSourceEndpoints returns official upstream advisory API and feed URLs.
func DefaultSourceEndpoints() SourceEndpoints {
	return SourceEndpoints{
		OSVBaseURL:         "https://api.osv.dev",
		GitHubAPIBaseURL:   "https://api.github.com",
		CISAKEVURL:         "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
		OpenSSLXMLURL:      "https://openssl-library.org/news/vulnerabilities.xml",
		OpenSSLXMLFallback: "https://www.openssl.org/news/vulnerabilities.xml",
		NginxHTMLURL:       "https://nginx.org/en/security_advisories.html",
		K8sCVEFeedURL:      "https://kubernetes.io/docs/reference/issues-security/official-cve-feed/feed.json",
		UbuntuUSNRSSURL:    "https://ubuntu.com/security/notices/rss.xml",
		DebianDSARSSURL:    "https://www.debian.org/security/dsa-long",
		GitLabSecRSSURL:    "https://about.gitlab.com/security-releases.xml",
		PostgresRSSURL:     "https://www.postgresql.org/news.rss",
	}
}

var (
	reCVE           = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,7}\b`)
	reGHSA          = regexp.MustCompile(`(?i)\bGHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}\b`)
	reHTMLTags      = regexp.MustCompile(`<[^>]+>`)
	reSpaces        = regexp.MustCompile(`\s+`)
	reVersionTokens = regexp.MustCompile(`\b\d+\.\d+(?:\.\d+){0,2}(?:[a-zA-Z0-9._+-]*)\b`)
)

func buildHTTPClient(proxyRaw string, timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	proxyFn := http.ProxyFromEnvironment
	if trimmed := strings.TrimSpace(proxyRaw); trimmed != "" {
		if parsed, err := url.Parse(trimmed); err == nil && parsed.Host != "" {
			proxyFn = http.ProxyURL(parsed)
		}
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:                 proxyFn,
			MaxIdleConns:          16,
			MaxIdleConnsPerHost:   6,
			IdleConnTimeout:       30 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 18 * time.Second,
		},
	}
}

func summarizeFetchErr(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	low := strings.ToLower(msg)
	switch {
	case errors.Is(err, context.DeadlineExceeded) || strings.Contains(low, "timeout") || strings.Contains(low, "deadline exceeded"):
		return "请求超时（国内网络可在配置中填写可选 HTTP 代理）"
	case strings.Contains(low, "no such host"):
		return "DNS 解析失败"
	case strings.Contains(low, "connection refused"):
		return "连接被拒绝（请检查代理或网络）"
	case strings.Contains(low, "tls") || strings.Contains(low, "x509"):
		return "TLS 证书握手失败"
	default:
		if len(msg) > 140 {
			return msg[:140] + "..."
		}
		return msg
	}
}

func doGET(ctx context.Context, client *http.Client, targetURL string, headers map[string]string, maxBytes int64) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", vulnUserAgent)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if maxBytes <= 0 {
		maxBytes = 8 * 1024 * 1024
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if readErr != nil && len(body) == 0 {
		return nil, resp.StatusCode, readErr
	}
	if resp.StatusCode >= 400 {
		snippet := strings.TrimSpace(string(body))
		if len(snippet) > 180 {
			snippet = snippet[:180] + "..."
		}
		return body, resp.StatusCode, fmt.Errorf("HTTP %d: %s", resp.StatusCode, snippet)
	}
	return body, resp.StatusCode, nil
}

// --- 1. CISA KEV Catalog ---

type cisaKEVEntry struct {
	CVEID             string `json:"cveID"`
	VendorProject     string `json:"vendorProject"`
	Product           string `json:"product"`
	VulnerabilityName string `json:"vulnerabilityName"`
	DateAdded         string `json:"dateAdded"`
	ShortDescription  string `json:"shortDescription"`
	RequiredAction    string `json:"requiredAction"`
	DueDate           string `json:"dueDate"`
	Notes             string `json:"notes"`
}

type cisaKEVFeed struct {
	Vulnerabilities []cisaKEVEntry `json:"vulnerabilities"`
}

func fetchCISAKEV(ctx context.Context, client *http.Client, feedURL string) (map[string]cisaKEVEntry, []cisaKEVEntry, vault.VulnSourceStatus) {
	now := time.Now().UTC()
	st := vault.VulnSourceStatus{
		ID:         "cisa-kev",
		Name:       "CISA KEV 在野利用目录",
		Kind:       "kev",
		URL:        feedURL,
		LastSyncAt: &now,
	}
	start := time.Now()
	body, _, err := doGET(ctx, client, feedURL, map[string]string{"Accept": "application/json"}, 12*1024*1024)
	st.DurationMs = max(int64(1), time.Since(start).Milliseconds())
	if err != nil {
		st.LastError = summarizeFetchErr(err)
		return nil, nil, st
	}
	var parsed cisaKEVFeed
	if err := json.Unmarshal(body, &parsed); err != nil {
		st.LastError = "CISA KEV JSON 解析失败"
		return nil, nil, st
	}
	byCVE := make(map[string]cisaKEVEntry, len(parsed.Vulnerabilities))
	for _, entry := range parsed.Vulnerabilities {
		id := strings.ToUpper(strings.TrimSpace(entry.CVEID))
		if id != "" {
			byCVE[id] = entry
		}
	}
	st.OK = true
	st.ItemCount = len(byCVE)
	return byCVE, parsed.Vulnerabilities, st
}

// buildAdvisoriesFromKEV emits recent KEV entries matching watched apps' KEVKeywords.
func buildAdvisoriesFromKEV(entries []cisaKEVEntry, watchedApps []AppDefinition, cutoff time.Time) []vault.VulnAdvisory {
	if len(entries) == 0 || len(watchedApps) == 0 {
		return nil
	}
	var out []vault.VulnAdvisory
	for _, e := range entries {
		cve := strings.ToUpper(strings.TrimSpace(e.CVEID))
		if cve == "" {
			continue
		}
		pub := parseFlexibleDate(e.DateAdded)
		if !pub.IsZero() && pub.Before(cutoff) {
			continue
		}
		hay := strings.ToLower(e.VendorProject + " " + e.Product + " " + e.VulnerabilityName)
		var matched []AppDefinition
		for _, app := range watchedApps {
			for _, kw := range app.KEVKeywords {
				kwLow := strings.ToLower(strings.TrimSpace(kw))
				if kwLow != "" && strings.Contains(hay, kwLow) {
					matched = append(matched, app)
					break
				}
			}
		}
		if len(matched) == 0 {
			continue
		}
		adv := vault.VulnAdvisory{
			ID:            cve,
			CVEID:         cve,
			Title:         nonEmpty(strings.TrimSpace(e.VulnerabilityName), cve+" ("+e.Product+")"),
			Summary:       strings.TrimSpace(e.ShortDescription),
			Details:       strings.TrimSpace(e.ShortDescription + "\n\nRequired Action: " + e.RequiredAction),
			Severity:      vault.VulnSeverityCritical,
			IsKEV:         true,
			KEVDateAdded:  e.DateAdded,
			KEVDueDate:    e.DueDate,
			KEVAction:     strings.TrimSpace(e.RequiredAction),
			Sources:       []string{"CISA KEV"},
			PrimarySource: "CISA KEV",
			OfficialURL:   "https://nvd.nist.gov/vuln/detail/" + cve,
			PublishedAt:   pub,
			ModifiedAt:    pub,
		}
		for _, m := range matched {
			adv.AppIDs = append(adv.AppIDs, m.ID)
			adv.AppNames = append(adv.AppNames, m.Name)
			adv.Categories = append(adv.Categories, m.Category)
		}
		out = append(out, adv)
	}
	return out
}

// --- 2. OSV.dev Batch + Detail Fetcher ---

type osvQueryItem struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
}

type osvBatchResp struct {
	Results []struct {
		Vulns []struct {
			ID       string `json:"id"`
			Modified string `json:"modified"`
		} `json:"vulns"`
	} `json:"results"`
}

type osvVulnDetail struct {
	ID        string   `json:"id"`
	Summary   string   `json:"summary"`
	Details   string   `json:"details"`
	Aliases   []string `json:"aliases"`
	Modified  string   `json:"modified"`
	Published string   `json:"published"`
	Severity  []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	DatabaseSpecific struct {
		Severity string   `json:"severity"`
		CWEIDs   []string `json:"cwe_ids"`
	} `json:"database_specific"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced   string `json:"introduced,omitempty"`
				Fixed        string `json:"fixed,omitempty"`
				LastAffected string `json:"last_affected,omitempty"`
			} `json:"events"`
		} `json:"ranges"`
		Versions []string `json:"versions"`
	} `json:"affected"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
}

func fetchOSVAdvisories(
	ctx context.Context,
	client *http.Client,
	osvBaseURL string,
	watchedApps []AppDefinition,
	retentionDays int,
) ([]vault.VulnAdvisory, vault.VulnSourceStatus) {
	now := time.Now().UTC()
	st := vault.VulnSourceStatus{
		ID:         "osv-dev",
		Name:       "OSV.dev 官方生态漏洞库",
		Kind:       "osv",
		URL:        strings.TrimRight(osvBaseURL, "/") + "/v1/querybatch",
		LastSyncAt: &now,
	}

	type queryRef struct {
		app AppDefinition
		pkg OSVPackageRef
	}
	var refs []queryRef
	for _, app := range watchedApps {
		for _, pkg := range app.OSVPackages {
			if strings.TrimSpace(pkg.Ecosystem) != "" && strings.TrimSpace(pkg.Name) != "" {
				refs = append(refs, queryRef{app: app, pkg: pkg})
			}
		}
	}
	if len(refs) == 0 {
		st.OK = true
		return nil, st
	}

	start := time.Now()
	queries := make([]osvQueryItem, len(refs))
	for i, r := range refs {
		queries[i].Package.Ecosystem = r.pkg.Ecosystem
		queries[i].Package.Name = r.pkg.Name
	}
	reqBody, _ := json.Marshal(map[string]any{"queries": queries})

	batchURL := strings.TrimRight(osvBaseURL, "/") + "/v1/querybatch"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, batchURL, bytes.NewReader(reqBody))
	if err != nil {
		st.LastError = err.Error()
		return nil, st
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", vulnUserAgent)

	resp, err := client.Do(req)
	if err != nil {
		st.DurationMs = max(int64(1), time.Since(start).Milliseconds())
		st.LastError = summarizeFetchErr(err)
		return nil, st
	}
	rawBatch, readErr := io.ReadAll(io.LimitReader(resp.Body, 16*1024*1024))
	_ = resp.Body.Close()
	if err := readErr; err != nil && len(rawBatch) == 0 {
		st.DurationMs = max(int64(1), time.Since(start).Milliseconds())
		st.LastError = summarizeFetchErr(err)
		return nil, st
	}
	if resp.StatusCode >= 400 {
		st.DurationMs = max(int64(1), time.Since(start).Milliseconds())
		st.LastError = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return nil, st
	}

	var batch osvBatchResp
	if err := json.Unmarshal(rawBatch, &batch); err != nil {
		st.DurationMs = max(int64(1), time.Since(start).Milliseconds())
		st.LastError = "OSV 响应解析失败"
		return nil, st
	}

	// Select top newest vulnerabilities per package (within retention window OR latest 8 per package)
	// capped globally to keep sync quick and respectful of upstream servers.
	cutoff := now.AddDate(0, 0, -retentionDays)
	type candidate struct {
		id       string
		modified time.Time
		apps     []AppDefinition
		pkg      OSVPackageRef
	}
	candByID := make(map[string]*candidate)

	const maxPerPkg = 12
	for idx, res := range batch.Results {
		if idx >= len(refs) || len(res.Vulns) == 0 {
			continue
		}
		type itemTS struct {
			id string
			ts time.Time
		}
		sorted := make([]itemTS, 0, len(res.Vulns))
		for _, v := range res.Vulns {
			if strings.TrimSpace(v.ID) == "" {
				continue
			}
			sorted = append(sorted, itemTS{id: v.ID, ts: parseFlexibleDate(v.Modified)})
		}
		sort.SliceStable(sorted, func(i, j int) bool {
			return sorted[i].ts.After(sorted[j].ts)
		})
		picked := 0
		for _, item := range sorted {
			within := !item.ts.IsZero() && !item.ts.Before(cutoff)
			if !within && picked >= 5 {
				break
			}
			if picked >= maxPerPkg {
				break
			}
			picked++
			if existing, ok := candByID[item.id]; ok {
				if !slices.ContainsFunc(existing.apps, func(a AppDefinition) bool { return a.ID == refs[idx].app.ID }) {
					existing.apps = append(existing.apps, refs[idx].app)
				}
			} else {
				candByID[item.id] = &candidate{
					id:       item.id,
					modified: item.ts,
					apps:     []AppDefinition{refs[idx].app},
					pkg:      refs[idx].pkg,
				}
			}
		}
	}

	cands := make([]*candidate, 0, len(candByID))
	for _, c := range candByID {
		cands = append(cands, c)
	}
	sort.SliceStable(cands, func(i, j int) bool {
		return cands[i].modified.After(cands[j].modified)
	})
	const maxDetailFetches = 120
	if len(cands) > maxDetailFetches {
		cands = cands[:maxDetailFetches]
	}

	// Fetch full advisory details with bounded concurrency (6 workers)
	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup
	var outMu sync.Mutex
	out := make([]vault.VulnAdvisory, 0, len(cands))
	var fetchErrors int

	for _, c := range cands {
		wg.Add(1)
		go func(cand *candidate) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			detailURL := strings.TrimRight(osvBaseURL, "/") + "/v1/vulns/" + url.PathEscape(cand.id)
			raw, _, err := doGET(ctx, client, detailURL, map[string]string{"Accept": "application/json"}, 2*1024*1024)
			if err != nil {
				outMu.Lock()
				fetchErrors++
				outMu.Unlock()
				return
			}
			var detail osvVulnDetail
			if err := json.Unmarshal(raw, &detail); err != nil {
				return
			}
			adv := convertOSVDetail(detail, cand.apps, cand.pkg)
			outMu.Lock()
			out = append(out, adv)
			outMu.Unlock()
		}(c)
	}
	wg.Wait()

	st.DurationMs = max(int64(1), time.Since(start).Milliseconds())
	st.ItemCount = len(out)
	st.OK = len(out) > 0 || fetchErrors == 0
	if fetchErrors > 0 && len(out) == 0 {
		st.LastError = fmt.Sprintf("详情拉取失败 (%d 条)", fetchErrors)
	} else if fetchErrors > 0 {
		st.LastError = fmt.Sprintf("部分详情超时 (%d 条已跳过)", fetchErrors)
	}
	return out, st
}

func convertOSVDetail(d osvVulnDetail, apps []AppDefinition, fallbackPkg OSVPackageRef) vault.VulnAdvisory {
	cveID := ""
	ghsaID := ""
	aliases := make([]string, 0, len(d.Aliases)+1)
	checkID := func(s string) {
		up := strings.ToUpper(strings.TrimSpace(s))
		if up == "" {
			return
		}
		if !slices.Contains(aliases, up) {
			aliases = append(aliases, up)
		}
		if cveID == "" && strings.HasPrefix(up, "CVE-") {
			cveID = up
		}
		if ghsaID == "" && strings.HasPrefix(up, "GHSA-") {
			ghsaID = up
		}
	}
	checkID(d.ID)
	for _, al := range d.Aliases {
		checkID(al)
	}
	canonicalID := cveID
	if canonicalID == "" {
		canonicalID = ghsaID
	}
	if canonicalID == "" {
		canonicalID = strings.TrimSpace(d.ID)
	}

	var bestScore float64
	var bestVector string
	bestSev := vault.NormalizeVulnSeverity(d.DatabaseSpecific.Severity)
	for _, sv := range d.Severity {
		score, sev := ParseCVSSScoreAndSeverity(sv.Score)
		if score > bestScore {
			bestScore = score
			bestVector = sv.Score
		}
		if vault.VulnSeverityRank(sev) > vault.VulnSeverityRank(bestSev) {
			bestSev = sev
		}
	}

	var ranges []vault.VulnAffectedRange
	var fixedVersions []string
	var affectedParts []string
	ecosystem := fallbackPkg.Ecosystem
	pkgName := fallbackPkg.Name

	for _, aff := range d.Affected {
		if aff.Package.Ecosystem != "" && ecosystem == "" {
			ecosystem = aff.Package.Ecosystem
		}
		if aff.Package.Name != "" && pkgName == "" {
			pkgName = aff.Package.Name
		}
		for _, rng := range aff.Ranges {
			var intro, fixed, lastAff string
			var rFixed []string
			for _, ev := range rng.Events {
				if ev.Introduced != "" && intro == "" {
					intro = ev.Introduced
				}
				if ev.Fixed != "" {
					if fixed == "" {
						fixed = ev.Fixed
					}
					if !slices.Contains(rFixed, ev.Fixed) {
						rFixed = append(rFixed, ev.Fixed)
					}
					if !slices.Contains(fixedVersions, ev.Fixed) {
						fixedVersions = append(fixedVersions, ev.Fixed)
					}
				}
				if ev.LastAffected != "" && lastAff == "" {
					lastAff = ev.LastAffected
				}
			}
			rText := formatRangeText(intro, fixed, lastAff)
			if rText != "" && !slices.Contains(affectedParts, rText) && len(affectedParts) < 4 {
				affectedParts = append(affectedParts, rText)
			}
			if intro != "" || fixed != "" || lastAff != "" {
				ranges = append(ranges, vault.VulnAffectedRange{
					Ecosystem:     nonEmpty(aff.Package.Ecosystem, ecosystem),
					PackageName:   nonEmpty(aff.Package.Name, pkgName),
					Introduced:    intro,
					Fixed:         fixed,
					LastAffected:  lastAff,
					RangeText:     rText,
					FixedVersions: rFixed,
				})
			}
		}
	}

	refs := make([]vault.VulnReference, 0, len(d.References))
	officialURL := ""
	for _, r := range d.References {
		u := strings.TrimSpace(r.URL)
		if u == "" {
			continue
		}
		refs = append(refs, vault.VulnReference{Type: r.Type, URL: u})
		if officialURL == "" && (strings.EqualFold(r.Type, "ADVISORY") || strings.EqualFold(r.Type, "FIX")) {
			officialURL = u
		}
	}
	if officialURL == "" {
		if len(refs) > 0 {
			officialURL = refs[0].URL
		} else {
			officialURL = "https://osv.dev/vulnerability/" + url.PathEscape(d.ID)
		}
	}

	title := strings.TrimSpace(d.Summary)
	if title == "" {
		title = firstLineSummary(d.Details, 140)
	}
	if title == "" {
		title = canonicalID
	}
	summary := strings.TrimSpace(d.Summary)
	if summary == "" {
		summary = firstLineSummary(d.Details, 280)
	}

	pub := parseFlexibleDate(d.Published)
	mod := parseFlexibleDate(d.Modified)
	if pub.IsZero() {
		pub = mod
	}
	if mod.IsZero() {
		mod = pub
	}

	primaryFixed := ""
	if len(fixedVersions) > 0 {
		primaryFixed = fixedVersions[0]
	}

	adv := vault.VulnAdvisory{
		ID:             canonicalID,
		CVEID:          cveID,
		GHSAID:         ghsaID,
		Aliases:        aliases,
		Title:          title,
		Summary:        summary,
		Details:        truncateRunes(strings.TrimSpace(d.Details), 6000),
		Severity:       bestSev,
		CVSSScore:      bestScore,
		CVSSVector:     bestVector,
		CWEIDs:         slices.Clone(d.DatabaseSpecific.CWEIDs),
		Ecosystem:      ecosystem,
		PackageName:    pkgName,
		AffectedText:   strings.Join(affectedParts, ", "),
		FixedVersion:   primaryFixed,
		FixedVersions:  fixedVersions,
		HasFix:         len(fixedVersions) > 0,
		AffectedRanges: ranges,
		Sources:        []string{"OSV.dev"},
		PrimarySource:  "OSV.dev",
		OfficialURL:    officialURL,
		References:     refs,
		PublishedAt:    pub,
		ModifiedAt:     mod,
	}
	for _, app := range apps {
		adv.AppIDs = append(adv.AppIDs, app.ID)
		adv.AppNames = append(adv.AppNames, app.Name)
		adv.Categories = append(adv.Categories, app.Category)
		adv.CPEHints = mergeStringsUnique(adv.CPEHints, app.CPEHints)
	}
	return adv
}

// --- 3. GitHub Repository Security Advisories (GHSA) ---

type ghsaRepoAdvisory struct {
	GHSAID      string `json:"ghsa_id"`
	CVEID       string `json:"cve_id"`
	HTMLURL     string `json:"html_url"`
	Summary     string `json:"summary"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	PublishedAt string `json:"published_at"`
	UpdatedAt   string `json:"updated_at"`
	CVSS        struct {
		Score        float64 `json:"score"`
		VectorString string  `json:"vector_string"`
	} `json:"cvss"`
	CWEs []struct {
		CWEID string `json:"cwe_id"`
	} `json:"cwes"`
	Vulnerabilities []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		VulnerableVersionRange string `json:"vulnerable_version_range"`
		PatchedVersions        string `json:"patched_versions"`
	} `json:"vulnerabilities"`
}

func fetchGHSAAdvisories(
	ctx context.Context,
	client *http.Client,
	githubAPIBase string,
	githubToken string,
	watchedApps []AppDefinition,
) ([]vault.VulnAdvisory, vault.VulnSourceStatus) {
	now := time.Now().UTC()
	st := vault.VulnSourceStatus{
		ID:         "github-advisories",
		Name:       "GitHub Security Advisories (GHSA)",
		Kind:       "ghsa",
		URL:        strings.TrimRight(githubAPIBase, "/") + "/repos/*/security-advisories",
		LastSyncAt: &now,
	}

	type repoJob struct {
		app  AppDefinition
		repo string
	}
	var jobs []repoJob
	seenRepo := make(map[string]struct{})
	for _, app := range watchedApps {
		for _, repo := range app.GitHubRepos {
			clean := strings.Trim(strings.TrimSpace(repo), "/")
			if clean == "" {
				continue
			}
			key := app.ID + "::" + strings.ToLower(clean)
			if _, ok := seenRepo[key]; ok {
				continue
			}
			seenRepo[key] = struct{}{}
			jobs = append(jobs, repoJob{app: app, repo: clean})
		}
	}
	if len(jobs) == 0 {
		st.OK = true
		return nil, st
	}

	headers := map[string]string{
		"Accept":               "application/vnd.github+json",
		"X-GitHub-Api-Version": "2022-11-28",
	}
	if tok := strings.TrimSpace(githubToken); tok != "" {
		headers["Authorization"] = "Bearer " + tok
	}

	start := time.Now()
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var out []vault.VulnAdvisory
	rateLimited := false
	errCount := 0
	lastErr := ""

	for _, j := range jobs {
		wg.Add(1)
		go func(job repoJob) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			mu.Lock()
			if rateLimited {
				mu.Unlock()
				return
			}
			mu.Unlock()

			target := fmt.Sprintf("%s/repos/%s/security-advisories?per_page=15&state=published",
				strings.TrimRight(githubAPIBase, "/"), job.repo)
			raw, code, err := doGET(ctx, client, target, headers, 4*1024*1024)
			if err != nil {
				mu.Lock()
				if code == http.StatusForbidden || code == http.StatusTooManyRequests {
					rateLimited = true
					lastErr = "GitHub API 速率受限（可在设置中配置可选 GitHub Token 提升至 5000 次/小时）"
				} else if code != http.StatusNotFound {
					errCount++
					if lastErr == "" {
						lastErr = summarizeFetchErr(err)
					}
				}
				mu.Unlock()
				return
			}

			var items []ghsaRepoAdvisory
			if err := json.Unmarshal(raw, &items); err != nil {
				return
			}
			local := make([]vault.VulnAdvisory, 0, len(items))
			for _, it := range items {
				local = append(local, convertGHSAAdvisory(it, job.app, job.repo))
			}
			mu.Lock()
			out = append(out, local...)
			mu.Unlock()
		}(j)
	}
	wg.Wait()

	st.DurationMs = max(int64(1), time.Since(start).Milliseconds())
	st.ItemCount = len(out)
	if rateLimited && len(out) == 0 {
		st.OK = false
		st.LastError = lastErr
	} else if errCount > 0 && len(out) == 0 {
		st.OK = false
		st.LastError = lastErr
	} else {
		st.OK = true
		if rateLimited {
			st.LastError = lastErr
		}
	}
	return out, st
}

func convertGHSAAdvisory(it ghsaRepoAdvisory, app AppDefinition, repo string) vault.VulnAdvisory {
	cve := strings.ToUpper(strings.TrimSpace(it.CVEID))
	ghsa := strings.ToUpper(strings.TrimSpace(it.GHSAID))
	canonical := cve
	if canonical == "" {
		canonical = ghsa
	}
	var aliases []string
	if cve != "" {
		aliases = append(aliases, cve)
	}
	if ghsa != "" && ghsa != cve {
		aliases = append(aliases, ghsa)
	}

	sev := vault.NormalizeVulnSeverity(it.Severity)
	score := it.CVSS.Score
	if score == 0 && it.CVSS.VectorString != "" {
		s2, sv2 := ParseCVSSScoreAndSeverity(it.CVSS.VectorString)
		score = s2
		if vault.VulnSeverityRank(sv2) > vault.VulnSeverityRank(sev) {
			sev = sv2
		}
	} else if score > 0 && sev == vault.VulnSeverityUnknown {
		sev = vault.SeverityFromCVSS(score)
	}

	var cwes []string
	for _, c := range it.CWEs {
		if strings.TrimSpace(c.CWEID) != "" {
			cwes = append(cwes, strings.TrimSpace(c.CWEID))
		}
	}

	var ranges []vault.VulnAffectedRange
	var fixedVersions []string
	var affTexts []string
	eco := ""
	pkgName := ""
	for _, v := range it.Vulnerabilities {
		if eco == "" && v.Package.Ecosystem != "" {
			eco = v.Package.Ecosystem
		}
		if pkgName == "" && v.Package.Name != "" {
			pkgName = v.Package.Name
		}
		vr := strings.TrimSpace(v.VulnerableVersionRange)
		pv := strings.TrimSpace(v.PatchedVersions)
		var rFixed []string
		if pv != "" {
			for _, tok := range strings.Split(pv, ",") {
				t := strings.TrimSpace(tok)
				if t != "" {
					rFixed = append(rFixed, t)
					if !slices.Contains(fixedVersions, t) {
						fixedVersions = append(fixedVersions, t)
					}
				}
			}
		}
		if vr != "" && !slices.Contains(affTexts, vr) && len(affTexts) < 4 {
			affTexts = append(affTexts, vr)
		}
		ranges = append(ranges, vault.VulnAffectedRange{
			Ecosystem:     v.Package.Ecosystem,
			PackageName:   nonEmpty(v.Package.Name, repo),
			RangeText:     vr,
			Fixed:         pv,
			FixedVersions: rFixed,
		})
	}

	pub := parseFlexibleDate(it.PublishedAt)
	mod := parseFlexibleDate(it.UpdatedAt)
	if mod.IsZero() {
		mod = pub
	}
	primaryFixed := ""
	if len(fixedVersions) > 0 {
		primaryFixed = fixedVersions[0]
	}

	var refs []vault.VulnReference
	if strings.TrimSpace(it.HTMLURL) != "" {
		refs = append(refs, vault.VulnReference{Type: "ADVISORY", URL: strings.TrimSpace(it.HTMLURL), Label: "GitHub 官方安全公告"})
	}

	return vault.VulnAdvisory{
		ID:             canonical,
		CVEID:          cve,
		GHSAID:         ghsa,
		Aliases:        aliases,
		AppIDs:         []string{app.ID},
		AppNames:       []string{app.Name},
		Categories:     []string{app.Category},
		Title:          nonEmpty(strings.TrimSpace(it.Summary), canonical),
		Summary:        nonEmpty(strings.TrimSpace(it.Summary), firstLineSummary(it.Description, 280)),
		Details:        truncateRunes(strings.TrimSpace(it.Description), 6000),
		Severity:       sev,
		CVSSScore:      score,
		CVSSVector:     strings.TrimSpace(it.CVSS.VectorString),
		CWEIDs:         cwes,
		Ecosystem:      eco,
		PackageName:    nonEmpty(pkgName, repo),
		CPEHints:       slices.Clone(app.CPEHints),
		AffectedText:   strings.Join(affTexts, ", "),
		FixedVersion:   primaryFixed,
		FixedVersions:  fixedVersions,
		HasFix:         len(fixedVersions) > 0,
		AffectedRanges: ranges,
		Sources:        []string{"GitHub Advisory"},
		PrimarySource:  "GitHub Advisory",
		OfficialURL:    strings.TrimSpace(it.HTMLURL),
		References:     refs,
		PublishedAt:    pub,
		ModifiedAt:     mod,
	}
}

// --- 4. Official Vendor Direct Feeds ---

// 4a. OpenSSL Official vulnerabilities.xml
type openSSLXMLDoc struct {
	Issues []struct {
		Public string `xml:"public,attr"`
		CVE    struct {
			Name string `xml:"name,attr"`
		} `xml:"cve"`
		Title  string `xml:"title"`
		Impact struct {
			Severity string `xml:"severity,attr"`
		} `xml:"impact"`
		Description string `xml:"description"`
		Fixed       []struct {
			Base    string `xml:"base,attr"`
			Version string `xml:"version,attr"`
			Date    string `xml:"date,attr"`
		} `xml:"fixed"`
		Affects []struct {
			Base    string `xml:"base,attr"`
			Version string `xml:"version,attr"`
		} `xml:"affects"`
		Advisory []struct {
			URL string `xml:"url,attr"`
		} `xml:"advisory"`
	} `xml:"issue"`
}

func fetchOpenSSLFeed(ctx context.Context, client *http.Client, primaryURL, fallbackURL string, app AppDefinition) ([]vault.VulnAdvisory, vault.VulnSourceStatus) {
	now := time.Now().UTC()
	st := vault.VulnSourceStatus{
		ID:         "vendor-openssl",
		Name:       "OpenSSL 官方安全公告",
		Kind:       "vendor",
		URL:        primaryURL,
		LastSyncAt: &now,
	}
	start := time.Now()
	body, _, err := doGET(ctx, client, primaryURL, map[string]string{"Accept": "application/xml,text/xml"}, 6*1024*1024)
	if err != nil && fallbackURL != "" && fallbackURL != primaryURL {
		body, _, err = doGET(ctx, client, fallbackURL, map[string]string{"Accept": "application/xml,text/xml"}, 6*1024*1024)
	}
	st.DurationMs = max(int64(1), time.Since(start).Milliseconds())
	if err != nil {
		st.LastError = summarizeFetchErr(err)
		return nil, st
	}
	var doc openSSLXMLDoc
	if err := xml.Unmarshal(body, &doc); err != nil {
		st.LastError = "OpenSSL XML 解析失败"
		return nil, st
	}

	out := make([]vault.VulnAdvisory, 0, min(len(doc.Issues), 40))
	// Limit to newest 40 issues from OpenSSL XML
	for idx, iss := range doc.Issues {
		if idx >= 40 {
			break
		}
		cve := strings.ToUpper(strings.TrimSpace(iss.CVE.Name))
		if cve != "" && !strings.HasPrefix(cve, "CVE-") {
			cve = "CVE-" + cve
		}
		if cve == "" {
			continue
		}
		pub := parseFlexibleDate(iss.Public)
		var fixedVersions []string
		var ranges []vault.VulnAffectedRange
		for _, fx := range iss.Fixed {
			v := strings.TrimSpace(fx.Version)
			if v != "" && !slices.Contains(fixedVersions, v) {
				fixedVersions = append(fixedVersions, v)
			}
			if v != "" {
				ranges = append(ranges, vault.VulnAffectedRange{
					Ecosystem:     "OpenSSL",
					PackageName:   "openssl",
					Introduced:    fx.Base,
					Fixed:         v,
					RangeText:     fmt.Sprintf("%s.x → 修复版本 %s", fx.Base, v),
					FixedVersions: []string{v},
				})
			}
		}
		var affBases []string
		for _, af := range iss.Affects {
			v := strings.TrimSpace(af.Version)
			if v != "" && !slices.Contains(affBases, v) && len(affBases) < 5 {
				affBases = append(affBases, v)
			}
		}
		officialURL := "https://openssl-library.org/news/vulnerabilities/#" + cve
		var refs []vault.VulnReference
		for _, ad := range iss.Advisory {
			if u := strings.TrimSpace(ad.URL); u != "" {
				if strings.HasPrefix(u, "/") {
					u = "https://openssl-library.org" + u
				}
				officialURL = u
				refs = append(refs, vault.VulnReference{Type: "ADVISORY", URL: u, Label: "OpenSSL 官方公告"})
			}
		}
		desc := cleanPlainText(iss.Description)
		title := cleanPlainText(iss.Title)
		if title == "" {
			title = cve
		}
		primaryFixed := ""
		if len(fixedVersions) > 0 {
			primaryFixed = strings.Join(fixedVersions[:min(len(fixedVersions), 3)], " / ")
		}
		out = append(out, vault.VulnAdvisory{
			ID:             cve,
			CVEID:          cve,
			Aliases:        []string{cve},
			AppIDs:         []string{app.ID},
			AppNames:       []string{app.Name},
			Categories:     []string{app.Category},
			Title:          title,
			Summary:        firstLineSummary(desc, 260),
			Details:        truncateRunes(desc, 5000),
			Severity:       vault.NormalizeVulnSeverity(iss.Impact.Severity),
			Ecosystem:      "OpenSSL",
			PackageName:    "openssl",
			CPEHints:       slices.Clone(app.CPEHints),
			AffectedText:   strings.Join(affBases, ", "),
			FixedVersion:   primaryFixed,
			FixedVersions:  fixedVersions,
			HasFix:         len(fixedVersions) > 0,
			AffectedRanges: ranges,
			Sources:        []string{"OpenSSL 官方公告"},
			PrimarySource:  "OpenSSL 官方公告",
			OfficialURL:    officialURL,
			References:     refs,
			PublishedAt:    pub,
			ModifiedAt:     pub,
		})
	}
	st.OK = true
	st.ItemCount = len(out)
	return out, st
}

// 4b. Nginx Official security_advisories.html
var (
	reNginxLI    = regexp.MustCompile(`(?is)<li\b[^>]*>(.*?)</li>`)
	reNginxSev   = regexp.MustCompile(`(?i)Severity:\s*([a-z]+)`)
	reNginxFixed = regexp.MustCompile(`(?i)Not vulnerable:\s*([^<\n]+)`)
	reNginxVuln  = regexp.MustCompile(`(?i)Vulnerable:\s*([^<\n]+)`)
	reNginxDate  = regexp.MustCompile(`\b(20\d{2}-\d{2}-\d{2})\b`)
	reHref       = regexp.MustCompile(`(?i)href=["']([^"']+)["']`)
)

func fetchNginxFeed(ctx context.Context, client *http.Client, feedURL string, app AppDefinition) ([]vault.VulnAdvisory, vault.VulnSourceStatus) {
	now := time.Now().UTC()
	st := vault.VulnSourceStatus{
		ID:         "vendor-nginx",
		Name:       "Nginx 官方安全公告",
		Kind:       "vendor",
		URL:        feedURL,
		LastSyncAt: &now,
	}
	start := time.Now()
	body, _, err := doGET(ctx, client, feedURL, map[string]string{"Accept": "text/html"}, 4*1024*1024)
	st.DurationMs = max(int64(1), time.Since(start).Milliseconds())
	if err != nil {
		st.LastError = summarizeFetchErr(err)
		return nil, st
	}
	content := string(body)
	matches := reNginxLI.FindAllStringSubmatch(content, 40)
	out := make([]vault.VulnAdvisory, 0, len(matches))
	for _, m := range matches {
		block := m[1]
		cve := strings.ToUpper(reCVE.FindString(block))
		if cve == "" {
			continue
		}
		plain := cleanPlainText(block)
		sev := vault.VulnSeverityMedium
		if sm := reNginxSev.FindStringSubmatch(plain); len(sm) > 1 {
			sev = vault.NormalizeVulnSeverity(sm[1])
		}
		fixedRaw := ""
		var fixedList []string
		if fm := reNginxFixed.FindStringSubmatch(plain); len(fm) > 1 {
			fixedRaw = strings.TrimSpace(strings.TrimRight(fm[1], ".;"))
			if idx := strings.Index(strings.ToLower(fixedRaw), "vulnerable:"); idx >= 0 {
				fixedRaw = strings.TrimSpace(fixedRaw[:idx])
			}
			fixedList = extractVersionTokens(fixedRaw)
		}
		vulnRaw := ""
		if vm := reNginxVuln.FindStringSubmatch(plain); len(vm) > 1 {
			vulnRaw = strings.TrimSpace(strings.TrimRight(vm[1], ".;"))
			if idx := strings.Index(strings.ToLower(vulnRaw), "the patch"); idx >= 0 {
				vulnRaw = strings.TrimSpace(vulnRaw[:idx])
			}
		}
		pub := time.Time{}
		if dm := reNginxDate.FindStringSubmatch(plain); len(dm) > 1 {
			pub = parseFlexibleDate(dm[1])
		}
		title := plain
		if idx := strings.Index(strings.ToLower(title), "severity:"); idx > 6 {
			title = strings.TrimSpace(title[:idx])
		}
		title = truncateRunes(title, 140)
		refs := []vault.VulnReference{
			{Type: "ADVISORY", URL: feedURL, Label: "Nginx 官方安全公告"},
		}
		for _, hm := range reHref.FindAllStringSubmatch(block, 5) {
			u := strings.TrimSpace(hm[1])
			if strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
				refs = append(refs, vault.VulnReference{Type: "WEB", URL: u})
			} else if strings.HasPrefix(u, "/") {
				refs = append(refs, vault.VulnReference{Type: "FIX", URL: "https://nginx.org" + u})
			}
		}
		var ranges []vault.VulnAffectedRange
		if vulnRaw != "" || fixedRaw != "" {
			ranges = append(ranges, vault.VulnAffectedRange{
				Ecosystem:     "Nginx",
				PackageName:   "nginx",
				RangeText:     vulnRaw,
				Fixed:         fixedRaw,
				FixedVersions: fixedList,
			})
		}
		out = append(out, vault.VulnAdvisory{
			ID:             cve,
			CVEID:          cve,
			Aliases:        []string{cve},
			AppIDs:         []string{app.ID},
			AppNames:       []string{app.Name},
			Categories:     []string{app.Category},
			Title:          title,
			Summary:        truncateRunes(plain, 260),
			Details:        truncateRunes(plain, 4000),
			Severity:       sev,
			Ecosystem:      "Nginx",
			PackageName:    "nginx",
			CPEHints:       slices.Clone(app.CPEHints),
			AffectedText:   truncateRunes(vulnRaw, 120),
			FixedVersion:   truncateRunes(fixedRaw, 80),
			FixedVersions:  fixedList,
			HasFix:         fixedRaw != "" || len(fixedList) > 0,
			AffectedRanges: ranges,
			Sources:        []string{"Nginx 官方公告"},
			PrimarySource:  "Nginx 官方公告",
			OfficialURL:    feedURL,
			References:     refs,
			PublishedAt:    pub,
			ModifiedAt:     pub,
		})
	}
	st.OK = true
	st.ItemCount = len(out)
	return out, st
}

// 4c. Kubernetes Official JSON CVE Feed
type k8sCVEFeed struct {
	Items []struct {
		ID            string `json:"id"`
		URL           string `json:"url"`
		ExternalURL   string `json:"external_url"`
		Title         string `json:"title"`
		Summary       string `json:"summary"`
		ContentText   string `json:"content_text"`
		DatePublished string `json:"date_published"`
	} `json:"items"`
}

func fetchK8sFeed(ctx context.Context, client *http.Client, feedURL string, app AppDefinition) ([]vault.VulnAdvisory, vault.VulnSourceStatus) {
	now := time.Now().UTC()
	st := vault.VulnSourceStatus{
		ID:         "vendor-k8s",
		Name:       "Kubernetes 官方 CVE Feed",
		Kind:       "vendor",
		URL:        feedURL,
		LastSyncAt: &now,
	}
	start := time.Now()
	body, _, err := doGET(ctx, client, feedURL, map[string]string{"Accept": "application/json"}, 4*1024*1024)
	st.DurationMs = max(int64(1), time.Since(start).Milliseconds())
	if err != nil {
		st.LastError = summarizeFetchErr(err)
		return nil, st
	}
	var doc k8sCVEFeed
	if err := json.Unmarshal(body, &doc); err != nil {
		st.LastError = "Kubernetes CVE JSON 解析失败"
		return nil, st
	}
	out := make([]vault.VulnAdvisory, 0, min(len(doc.Items), 30))
	for i, it := range doc.Items {
		if i >= 30 {
			break
		}
		cve := strings.ToUpper(reCVE.FindString(it.ID + " " + it.Title))
		if cve == "" {
			continue
		}
		pub := parseFlexibleDate(it.DatePublished)
		text := nonEmpty(strings.TrimSpace(it.ContentText), strings.TrimSpace(it.Summary))
		fixedList := extractFixedVersionsFromText(text)
		primaryFixed := ""
		if len(fixedList) > 0 {
			primaryFixed = strings.Join(fixedList[:min(len(fixedList), 3)], ", ")
		}
		offURL := nonEmpty(strings.TrimSpace(it.ExternalURL), strings.TrimSpace(it.URL))
		var refs []vault.VulnReference
		if offURL != "" {
			refs = append(refs, vault.VulnReference{Type: "ADVISORY", URL: offURL, Label: "Kubernetes 官方 CVE 通告"})
		}
		out = append(out, vault.VulnAdvisory{
			ID:            cve,
			CVEID:         cve,
			Aliases:       []string{cve},
			AppIDs:        []string{app.ID},
			AppNames:      []string{app.Name},
			Categories:    []string{app.Category},
			Title:         nonEmpty(strings.TrimSpace(it.Title), cve),
			Summary:       truncateRunes(nonEmpty(strings.TrimSpace(it.Summary), text), 260),
			Details:       truncateRunes(text, 5000),
			Severity:      inferSeverityFromText(it.Title + " " + text),
			Ecosystem:     "Kubernetes",
			PackageName:   "k8s.io/kubernetes",
			CPEHints:      slices.Clone(app.CPEHints),
			FixedVersion:  primaryFixed,
			FixedVersions: fixedList,
			HasFix:        len(fixedList) > 0,
			Sources:       []string{"Kubernetes 官方公告"},
			PrimarySource: "Kubernetes 官方公告",
			OfficialURL:   offURL,
			References:    refs,
			PublishedAt:   pub,
			ModifiedAt:    pub,
		})
	}
	st.OK = true
	st.ItemCount = len(out)
	return out, st
}

// 4d. Generic RSS / RDF / Atom parser for Ubuntu USN, Debian DSA, GitLab Security, PostgreSQL Security
type genericRSS struct {
	Channel struct {
		Items []rssItem `xml:"item"`
	} `xml:"channel"`
	Items []rssItem `xml:"item"` // RDF style (Debian DSA)
}

type rssItem struct {
	Title       string `xml:"title"`
	Link        string `xml:"link"`
	Description string `xml:"description"`
	PubDate     string `xml:"pubDate"`
	DCDate      string `xml:"date"`
}

type genericAtom struct {
	Entries []struct {
		Title   string `xml:"title"`
		Updated string `xml:"updated"`
		Summary string `xml:"summary"`
		Content string `xml:"content"`
		Link    []struct {
			Href string `xml:"href,attr"`
		} `xml:"link"`
	} `xml:"entry"`
}

func fetchVendorRSSFeed(
	ctx context.Context,
	client *http.Client,
	sourceID, sourceName, feedURL string,
	app AppDefinition,
	requireSecurityKeyword bool,
) ([]vault.VulnAdvisory, vault.VulnSourceStatus) {
	now := time.Now().UTC()
	st := vault.VulnSourceStatus{
		ID:         sourceID,
		Name:       sourceName,
		Kind:       "vendor",
		URL:        feedURL,
		LastSyncAt: &now,
	}
	start := time.Now()
	body, _, err := doGET(ctx, client, feedURL, map[string]string{"Accept": "application/rss+xml,application/atom+xml,application/xml,text/xml"}, 4*1024*1024)
	st.DurationMs = max(int64(1), time.Since(start).Milliseconds())
	if err != nil {
		st.LastError = summarizeFetchErr(err)
		return nil, st
	}

	type rawEntry struct {
		title string
		link  string
		desc  string
		date  string
	}
	var entries []rawEntry

	var rss genericRSS
	if xml.Unmarshal(body, &rss) == nil {
		items := rss.Channel.Items
		if len(items) == 0 {
			items = rss.Items
		}
		for _, it := range items {
			entries = append(entries, rawEntry{
				title: cleanPlainText(it.Title),
				link:  strings.TrimSpace(it.Link),
				desc:  cleanPlainText(it.Description),
				date:  nonEmpty(it.PubDate, it.DCDate),
			})
		}
	}
	if len(entries) == 0 {
		var atom genericAtom
		if xml.Unmarshal(body, &atom) == nil {
			for _, en := range atom.Entries {
				lnk := ""
				if len(en.Link) > 0 {
					lnk = strings.TrimSpace(en.Link[0].Href)
				}
				entries = append(entries, rawEntry{
					title: cleanPlainText(en.Title),
					link:  lnk,
					desc:  cleanPlainText(nonEmpty(en.Summary, en.Content)),
					date:  en.Updated,
				})
			}
		}
	}

	out := make([]vault.VulnAdvisory, 0, min(len(entries), 25))
	for _, en := range entries {
		if len(out) >= 25 {
			break
		}
		combined := en.title + " " + en.desc
		if requireSecurityKeyword {
			low := strings.ToLower(combined)
			if !strings.Contains(low, "security") && !strings.Contains(low, "cve-") && !strings.Contains(low, "vulnerab") {
				continue
			}
		}
		cves := reCVE.FindAllString(combined, 6)
		primaryCVE := ""
		var aliases []string
		for _, c := range cves {
			up := strings.ToUpper(c)
			if primaryCVE == "" {
				primaryCVE = up
			}
			if !slices.Contains(aliases, up) {
				aliases = append(aliases, up)
			}
		}
		id := primaryCVE
		if id == "" {
			id = strings.ToUpper(app.ID) + "-" + sanitizeFeedSlug(en.title)
		}
		pub := parseFlexibleDate(en.date)
		fixedList := extractFixedVersionsFromText(combined)
		primaryFixed := ""
		if len(fixedList) > 0 {
			primaryFixed = strings.Join(fixedList[:min(len(fixedList), 3)], ", ")
		}
		var refs []vault.VulnReference
		if en.link != "" {
			refs = append(refs, vault.VulnReference{Type: "ADVISORY", URL: en.link, Label: sourceName})
		}
		out = append(out, vault.VulnAdvisory{
			ID:            id,
			CVEID:         primaryCVE,
			Aliases:       aliases,
			AppIDs:        []string{app.ID},
			AppNames:      []string{app.Name},
			Categories:    []string{app.Category},
			Title:         truncateRunes(nonEmpty(en.title, id), 160),
			Summary:       truncateRunes(nonEmpty(en.desc, en.title), 280),
			Details:       truncateRunes(en.desc, 4000),
			Severity:      inferSeverityFromText(combined),
			Ecosystem:     app.Name,
			PackageName:   app.ID,
			CPEHints:      slices.Clone(app.CPEHints),
			FixedVersion:  primaryFixed,
			FixedVersions: fixedList,
			HasFix:        len(fixedList) > 0 || strings.Contains(strings.ToLower(combined), "fixed") || strings.Contains(strings.ToLower(combined), "update") || strings.Contains(strings.ToLower(combined), "security release"),
			Sources:       []string{sourceName},
			PrimarySource: sourceName,
			OfficialURL:   en.link,
			References:    refs,
			PublishedAt:   pub,
			ModifiedAt:    pub,
		})
	}
	st.OK = true
	st.ItemCount = len(out)
	return out, st
}

// --- Parsing & Text Utilities ---

func cleanPlainText(raw string) string {
	s := reHTMLTags.ReplaceAllString(raw, " ")
	s = html.UnescapeString(s)
	s = reSpaces.ReplaceAllString(s, " ")
	return strings.TrimSpace(s)
}

func firstLineSummary(raw string, maxRunes int) string {
	for _, line := range strings.Split(raw, "\n") {
		t := strings.TrimSpace(strings.TrimLeft(line, "#*- "))
		if len(t) >= 8 {
			return truncateRunes(t, maxRunes)
		}
	}
	return truncateRunes(strings.TrimSpace(raw), maxRunes)
}

func truncateRunes(s string, maxLen int) string {
	if maxLen <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen-1]) + "…"
}

func parseFlexibleDate(raw string) time.Time {
	s := strings.TrimSpace(raw)
	if s == "" {
		return time.Time{}
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		time.RFC1123Z,
		time.RFC1123,
		time.RFC822Z,
		time.RFC822,
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05",
		"2006-01-02",
		"20060102",
		"Mon, 2 Jan 2006 15:04:05 -0700",
		"Mon, 2 Jan 2006 15:04:05 MST",
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

func formatRangeText(intro, fixed, lastAff string) string {
	intro = strings.TrimSpace(intro)
	fixed = strings.TrimSpace(fixed)
	lastAff = strings.TrimSpace(lastAff)
	switch {
	case intro != "" && intro != "0" && fixed != "":
		return fmt.Sprintf(">=%s, <%s", intro, fixed)
	case fixed != "":
		return "< " + fixed
	case intro != "" && intro != "0" && lastAff != "":
		return fmt.Sprintf(">=%s, <=%s", intro, lastAff)
	case lastAff != "":
		return "<= " + lastAff
	case intro != "" && intro != "0":
		return ">= " + intro
	default:
		return ""
	}
}

func extractVersionTokens(raw string) []string {
	matches := reVersionTokens.FindAllString(raw, 8)
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		if !slices.Contains(out, m) {
			out = append(out, m)
		}
	}
	return out
}

func extractFixedVersionsFromText(text string) []string {
	low := strings.ToLower(text)
	for _, kw := range []string{"fixed in", "patched in", "upgrade to", "not vulnerable", "resolved in", "release "} {
		if idx := strings.Index(low, kw); idx >= 0 {
			end := min(len(text), idx+120)
			if toks := extractVersionTokens(text[idx:end]); len(toks) > 0 {
				return toks
			}
		}
	}
	return nil
}

func inferSeverityFromText(text string) vault.VulnSeverity {
	low := strings.ToLower(text)
	switch {
	case strings.Contains(low, "critical") || strings.Contains(low, "remote code execution") || strings.Contains(low, "unauthenticated rce"):
		return vault.VulnSeverityCritical
	case strings.Contains(low, "high severity") || strings.Contains(low, "high impact") || strings.Contains(low, "privilege escalation") || strings.Contains(low, "important"):
		return vault.VulnSeverityHigh
	case strings.Contains(low, "medium") || strings.Contains(low, "moderate"):
		return vault.VulnSeverityMedium
	case strings.Contains(low, "low severity") || strings.Contains(low, "low impact"):
		return vault.VulnSeverityLow
	default:
		return vault.VulnSeverityMedium
	}
}

func sanitizeFeedSlug(raw string) string {
	low := strings.ToLower(strings.TrimSpace(raw))
	var b strings.Builder
	for _, r := range low {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else if b.Len() > 0 && b.String()[b.Len()-1] != '-' {
			b.WriteByte('-')
		}
		if b.Len() >= 32 {
			break
		}
	}
	res := strings.Trim(b.String(), "-")
	if res == "" {
		return "ADVISORY"
	}
	return strings.ToUpper(res)
}

func nonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return strings.TrimSpace(a)
	}
	return strings.TrimSpace(b)
}

func mergeStringsUnique(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, list := range [][]string{a, b} {
		for _, item := range list {
			trimmed := strings.TrimSpace(item)
			if trimmed == "" {
				continue
			}
			if _, ok := seen[trimmed]; ok {
				continue
			}
			seen[trimmed] = struct{}{}
			out = append(out, trimmed)
		}
	}
	return out
}

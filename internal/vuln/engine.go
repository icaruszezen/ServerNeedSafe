package vuln

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/aiops"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

// AICompleter executes a single-turn text completion using the configured active AI provider.
type AICompleter func(ctx context.Context, systemPrompt, userPrompt string) (content string, model string, err error)

// Config holds dependencies and options for the 7x24 vulnerability advisory monitor.
type Config struct {
	Store           *vault.Store
	Endpoints       SourceEndpoints
	HTTPClient      *http.Client // Optional override (mainly for tests)
	AICompleter     AICompleter  // Optional on-demand Chinese AI explainer
	WebhookSender   func(ctx context.Context, ch vault.WebhookChannel, title, color, md string, payload map[string]any) error
	StartupDelay    time.Duration
	DisableAutoLoop bool
}

// RuntimeStatus summarizes background sync status for the Web UI.
type RuntimeStatus struct {
	Syncing       bool                     `json:"syncing"`
	LastSyncAt    *time.Time               `json:"last_sync_at,omitempty"`
	NextSyncAt    *time.Time               `json:"next_sync_at,omitempty"`
	LastError     string                   `json:"last_error,omitempty"`
	LastNewCount  int                      `json:"last_new_count"`
	SourceStatus  []vault.VulnSourceStatus `json:"source_status"`
	WatchedCount  int                      `json:"watched_count"`
	CatalogTotal  int                      `json:"catalog_total"`
}

// KPIStats summarizes vulnerability posture across currently watched applications.
type KPIStats struct {
	Total              int `json:"total"`
	Critical           int `json:"critical"`
	High               int `json:"high"`
	Medium             int `json:"medium"`
	Low                int `json:"low"`
	Unknown            int `json:"unknown"`
	KEV                int `json:"kev"`
	HasFix             int `json:"has_fix"`
	Recent7d           int `json:"recent_7d"`
	UnreadTotal        int `json:"unread_total"`
	UnreadCriticalHigh int `json:"unread_critical_high"`
	StarredTotal       int `json:"starred_total"`
	SourcesOK          int `json:"sources_ok"`
	SourcesTotal       int `json:"sources_total"`
}

// QueryFilter controls server-side filtering and pagination for GET /api/vulns/overview.
type QueryFilter struct {
	AppIDs     []string
	Categories []string
	Severities []string
	State      string // "all", "unread", "starred", "ignored"
	KEVOnly    bool
	FixedOnly  bool
	Days       int // 0 = all, otherwise 1/7/30/90
	Search     string
	Since      time.Time // Optional incremental polling marker
	Limit      int
	Offset     int
}

// OverviewResponse is returned by GET /api/vulns/overview.
type OverviewResponse struct {
	Advisories    []vault.VulnAdvisory   `json:"advisories"`
	TotalMatched  int                    `json:"total_matched"`
	HasMore       bool                   `json:"has_more"`
	NewSinceCount int                    `json:"new_since_count"`
	Ticker        []vault.VulnAdvisory   `json:"ticker"`
	KPI           KPIStats               `json:"kpi"`
	Settings      vault.VulnSettingsView `json:"settings"`
	Catalog       []AppDefinition        `json:"catalog"`
	Categories    []AppCategoryInfo      `json:"categories"`
	Presets       []AppPreset            `json:"presets"`
	Runtime       RuntimeStatus          `json:"runtime"`
}

// SyncResult reports the outcome of a manual or scheduled sync cycle.
type SyncResult struct {
	OK           bool          `json:"ok"`
	FetchedCount int           `json:"fetched_count"`
	NewCount     int           `json:"new_count"`
	Error        string        `json:"error,omitempty"`
	Runtime      RuntimeStatus `json:"runtime"`
}

// Service manages 7x24 multi-source vulnerability ingestion, deduplication, AI explanation, and webhook push.
type Service struct {
	cfg Config

	mu         sync.RWMutex
	syncing    bool
	nextSyncAt *time.Time
	kevCache   map[string]cisaKEVEntry
	kevEntries []cisaKEVEntry
	kevAt      time.Time

	syncMu  sync.Mutex // Serializes full/incremental sync executions
	wakeCh  chan struct{}
	stopCh  chan struct{}
	closeMu sync.Once
	wg      sync.WaitGroup
}

// NewService constructs a vulnerability monitoring service. Call Start() to begin the 7x24 scheduler.
func NewService(cfg Config) *Service {
	defEP := DefaultSourceEndpoints()
	if cfg.Endpoints.OSVBaseURL == "" {
		cfg.Endpoints.OSVBaseURL = defEP.OSVBaseURL
	}
	if cfg.Endpoints.GitHubAPIBaseURL == "" {
		cfg.Endpoints.GitHubAPIBaseURL = defEP.GitHubAPIBaseURL
	}
	if cfg.Endpoints.CISAKEVURL == "" {
		cfg.Endpoints.CISAKEVURL = defEP.CISAKEVURL
	}
	if cfg.Endpoints.OpenSSLXMLURL == "" {
		cfg.Endpoints.OpenSSLXMLURL = defEP.OpenSSLXMLURL
	}
	if cfg.Endpoints.OpenSSLXMLFallback == "" {
		cfg.Endpoints.OpenSSLXMLFallback = defEP.OpenSSLXMLFallback
	}
	if cfg.Endpoints.NginxHTMLURL == "" {
		cfg.Endpoints.NginxHTMLURL = defEP.NginxHTMLURL
	}
	if cfg.Endpoints.K8sCVEFeedURL == "" {
		cfg.Endpoints.K8sCVEFeedURL = defEP.K8sCVEFeedURL
	}
	if cfg.Endpoints.UbuntuUSNRSSURL == "" {
		cfg.Endpoints.UbuntuUSNRSSURL = defEP.UbuntuUSNRSSURL
	}
	if cfg.Endpoints.DebianDSARSSURL == "" {
		cfg.Endpoints.DebianDSARSSURL = defEP.DebianDSARSSURL
	}
	if cfg.Endpoints.GitLabSecRSSURL == "" {
		cfg.Endpoints.GitLabSecRSSURL = defEP.GitLabSecRSSURL
	}
	if cfg.Endpoints.PostgresRSSURL == "" {
		cfg.Endpoints.PostgresRSSURL = defEP.PostgresRSSURL
	}
	if cfg.StartupDelay <= 0 {
		cfg.StartupDelay = 4 * time.Second
	}
	if cfg.WebhookSender == nil {
		cfg.WebhookSender = func(ctx context.Context, ch vault.WebhookChannel, title, color, md string, payload map[string]any) error {
			return aiops.SendCustomMarkdownWebhook(ctx, nil, ch, title, color, md, payload)
		}
	}

	return &Service{
		cfg:    cfg,
		wakeCh: make(chan struct{}, 1),
		stopCh: make(chan struct{}),
	}
}

// Start launches the 7x24 background synchronization loop (unless DisableAutoLoop is true).
func (s *Service) Start() {
	if s.cfg.DisableAutoLoop || s.cfg.Store == nil {
		return
	}
	s.cfg.Store.RegisterOnReady(func() {
		s.Wake()
	})
	s.wg.Add(1)
	go s.schedulerLoop()
}

// Close stops the background loop and waits for active syncs to exit cleanly.
func (s *Service) Close() {
	s.closeMu.Do(func() {
		close(s.stopCh)
		s.wg.Wait()
	})
}

// Wake nudges the scheduler after settings changes or store readiness.
func (s *Service) Wake() {
	select {
	case s.wakeCh <- struct{}{}:
	default:
	}
}

// TriggerAsyncSync kicks off an immediate background sync (e.g. when a user newly selects apps to watch).
func (s *Service) TriggerAsyncSync(targetAppIDs []string) {
	if s.cfg.Store == nil || !s.cfg.Store.IsReady() {
		return
	}
	if s.cfg.DisableAutoLoop && s.cfg.HTTPClient == nil {
		// Avoid unexpected external traffic inside isolated API tests unless a mock HTTPClient is provided.
		return
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		_, _ = s.SyncNow(ctx, targetAppIDs)
	}()
}

func (s *Service) schedulerLoop() {
	defer s.wg.Done()

	// Brief startup grace delay so daemon boots in <1ms
	initTimer := time.NewTimer(s.cfg.StartupDelay)
	select {
	case <-s.stopCh:
		initTimer.Stop()
		return
	case <-initTimer.C:
	case <-s.wakeCh:
		initTimer.Stop()
	}

	for {
		if s.cfg.Store != nil && s.cfg.Store.IsReady() {
			if cfg, err := s.cfg.Store.GetVulnSettings(); err == nil && cfg.Enabled {
				rt := s.cfg.Store.GetVulnRuntimeSnapshot()
				interval := time.Duration(max(10, cfg.SyncIntervalMinutes)) * time.Minute
				needSync := rt.LastSyncAt == nil || time.Since(*rt.LastSyncAt) >= interval
				if needSync {
					ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
					_, _ = s.SyncNow(ctx, nil)
					cancel()
				}
				next := time.Now().UTC().Add(interval)
				s.mu.Lock()
				s.nextSyncAt = &next
				s.mu.Unlock()

				waitTimer := time.NewTimer(interval)
				select {
				case <-s.stopCh:
					waitTimer.Stop()
					return
				case <-s.wakeCh:
					waitTimer.Stop()
				case <-waitTimer.C:
				}
				continue
			}
		}

		// Store not ready or auto-sync disabled: wait quietly for wake or 1m check
		s.mu.Lock()
		s.nextSyncAt = nil
		s.mu.Unlock()
		idleTimer := time.NewTimer(60 * time.Second)
		select {
		case <-s.stopCh:
			idleTimer.Stop()
			return
		case <-s.wakeCh:
			idleTimer.Stop()
		case <-idleTimer.C:
		}
	}
}

// SyncNow executes an immediate multi-source sync for all watched apps (or only targetAppIDs when specified).
func (s *Service) SyncNow(ctx context.Context, targetAppIDs []string) (*SyncResult, error) {
	if s.cfg.Store == nil || !s.cfg.Store.IsReady() {
		return nil, vault.ErrVaultNotInit
	}
	s.syncMu.Lock()
	defer s.syncMu.Unlock()

	s.mu.Lock()
	s.syncing = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.syncing = false
		s.mu.Unlock()
	}()

	settings, err := s.cfg.Store.GetVulnSettings()
	if err != nil {
		return nil, err
	}
	catalog := BuildResolvedCatalog(settings)

	var watchedApps []AppDefinition
	targetSet := make(map[string]struct{}, len(targetAppIDs))
	for _, id := range targetAppIDs {
		if trimmed := strings.ToLower(strings.TrimSpace(id)); trimmed != "" {
			targetSet[trimmed] = struct{}{}
		}
	}
	for _, app := range catalog {
		if !app.Watched {
			continue
		}
		if len(targetSet) > 0 {
			if _, ok := targetSet[strings.ToLower(app.ID)]; !ok {
				continue
			}
		}
		watchedApps = append(watchedApps, app)
	}

	if len(watchedApps) == 0 {
		rt := s.RuntimeStatus()
		return &SyncResult{
			OK:      true,
			Runtime: rt,
		}, nil
	}

	client := s.cfg.HTTPClient
	if client == nil {
		client = buildHTTPClient(settings.HTTPProxyURL, 22*time.Second)
	}

	var (
		allRaw     []vault.VulnAdvisory
		rawMu      sync.Mutex
		statuses   []vault.VulnSourceStatus
		statusMu   sync.Mutex
		kevMap     map[string]cisaKEVEntry
		kevEntries []cisaKEVEntry
		wg         sync.WaitGroup
	)
	addRaw := func(items []vault.VulnAdvisory) {
		if len(items) == 0 {
			return
		}
		rawMu.Lock()
		allRaw = append(allRaw, items...)
		rawMu.Unlock()
	}
	addStatus := func(st vault.VulnSourceStatus) {
		statusMu.Lock()
		statuses = append(statuses, st)
		statusMu.Unlock()
	}

	// 1. CISA KEV (use cached copy if fetched within last 2 hours during incremental sync)
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.mu.RLock()
		hasFreshKEV := len(s.kevCache) > 0 && time.Since(s.kevAt) < 2*time.Hour && len(targetSet) > 0
		cachedMap := s.kevCache
		cachedEntries := s.kevEntries
		s.mu.RUnlock()

		if hasFreshKEV {
			kevMap = cachedMap
			kevEntries = cachedEntries
			return
		}
		km, ke, st := fetchCISAKEV(ctx, client, s.cfg.Endpoints.CISAKEVURL)
		addStatus(st)
		if st.OK && len(km) > 0 {
			kevMap = km
			kevEntries = ke
			s.mu.Lock()
			s.kevCache = km
			s.kevEntries = ke
			s.kevAt = time.Now().UTC()
			s.mu.Unlock()
		} else {
			s.mu.RLock()
			kevMap = s.kevCache
			kevEntries = s.kevEntries
			s.mu.RUnlock()
		}
	}()

	// 2. OSV.dev Batch + Detail
	wg.Add(1)
	go func() {
		defer wg.Done()
		items, st := fetchOSVAdvisories(ctx, client, s.cfg.Endpoints.OSVBaseURL, watchedApps, settings.RetentionDays)
		addRaw(items)
		addStatus(st)
	}()

	// 3. GitHub Security Advisories
	wg.Add(1)
	go func() {
		defer wg.Done()
		items, st := fetchGHSAAdvisories(ctx, client, s.cfg.Endpoints.GitHubAPIBaseURL, settings.GitHubToken, watchedApps)
		addRaw(items)
		addStatus(st)
	}()

	// 4. Official Vendor Direct Feeds (only for watched apps that have one!)
	for _, app := range watchedApps {
		if app.VendorFeedID == "" {
			continue
		}
		wg.Add(1)
		go func(a AppDefinition) {
			defer wg.Done()
			var items []vault.VulnAdvisory
			var st vault.VulnSourceStatus
			switch a.VendorFeedID {
			case "openssl_xml":
				items, st = fetchOpenSSLFeed(ctx, client, s.cfg.Endpoints.OpenSSLXMLURL, s.cfg.Endpoints.OpenSSLXMLFallback, a)
			case "nginx_html":
				items, st = fetchNginxFeed(ctx, client, s.cfg.Endpoints.NginxHTMLURL, a)
			case "k8s_cve_json":
				items, st = fetchK8sFeed(ctx, client, s.cfg.Endpoints.K8sCVEFeedURL, a)
			case "ubuntu_usn_rss":
				items, st = fetchVendorRSSFeed(ctx, client, "vendor-ubuntu", "Ubuntu 官方安全公告 (USN)", s.cfg.Endpoints.UbuntuUSNRSSURL, a, false)
			case "debian_dsa_rss":
				items, st = fetchVendorRSSFeed(ctx, client, "vendor-debian", "Debian 官方安全公告 (DSA)", s.cfg.Endpoints.DebianDSARSSURL, a, false)
			case "gitlab_rss":
				items, st = fetchVendorRSSFeed(ctx, client, "vendor-gitlab", "GitLab 官方安全发布", s.cfg.Endpoints.GitLabSecRSSURL, a, false)
			case "postgres_rss":
				items, st = fetchVendorRSSFeed(ctx, client, "vendor-postgres", "PostgreSQL 官方安全通告", s.cfg.Endpoints.PostgresRSSURL, a, true)
			default:
				return
			}
			addRaw(items)
			addStatus(st)
		}(app)
	}

	wg.Wait()

	// Emit recent CISA KEV items matching watched apps
	if len(kevEntries) > 0 {
		cutoff := time.Now().UTC().AddDate(0, 0, -settings.RetentionDays)
		addRaw(buildAdvisoriesFromKEV(kevEntries, watchedApps, cutoff))
	}

	// Merge, deduplicate by canonical CVE/GHSA ID, and enrich with CISA KEV metadata
	merged := mergeAndEnrichAdvisories(allRaw, kevMap)

	// Sort source statuses deterministically for UI
	sort.SliceStable(statuses, func(i, j int) bool {
		return statuses[i].ID < statuses[j].ID
	})

	// Build summary error if ALL attempted sources failed
	okSources := 0
	var errMsgs []string
	for _, st := range statuses {
		if st.OK {
			okSources++
		} else if st.LastError != "" {
			errMsgs = append(errMsgs, st.Name+": "+st.LastError)
		}
	}
	syncErr := ""
	if okSources == 0 && len(errMsgs) > 0 {
		syncErr = strings.Join(errMsgs, "；")
	}

	newlyAdded, isFirstSync := s.cfg.Store.SaveVulnSyncResults(
		merged,
		statuses,
		syncErr,
		settings.RetentionDays,
		settings.MaxRecords,
	)

	// Optional Webhook notification for truly new Critical/High/KEV advisories (never spam on cold first sync)
	if settings.NotifyWebhook && !isFirstSync && len(newlyAdded) > 0 {
		s.notifyNewAdvisories(ctx, settings, newlyAdded)
	}

	rt := s.RuntimeStatus()
	return &SyncResult{
		OK:           okSources > 0 || len(statuses) == 0,
		FetchedCount: len(merged),
		NewCount:     len(newlyAdded),
		Error:        syncErr,
		Runtime:      rt,
	}, nil
}

// mergeAndEnrichAdvisories deduplicates advisories by canonical CVE / GHSA ID and applies CISA KEV enrichment.
func mergeAndEnrichAdvisories(raw []vault.VulnAdvisory, kevMap map[string]cisaKEVEntry) []vault.VulnAdvisory {
	byKey := make(map[string]*vault.VulnAdvisory, len(raw))

	for _, item := range raw {
		canon := canonicalAdvisoryKey(item)
		if canon == "" {
			continue
		}
		item.ID = canon
		if item.Severity == "" {
			item.Severity = vault.VulnSeverityUnknown
		}
		if cur, ok := byKey[canon]; ok {
			mergeIntoAdvisory(cur, item)
		} else {
			cp := item
			byKey[canon] = &cp
		}
	}

	out := make([]vault.VulnAdvisory, 0, len(byKey))
	for _, adv := range byKey {
		// Enrich with CISA KEV
		if len(kevMap) > 0 {
			lookupCVE := strings.ToUpper(adv.CVEID)
			if lookupCVE == "" && strings.HasPrefix(strings.ToUpper(adv.ID), "CVE-") {
				lookupCVE = strings.ToUpper(adv.ID)
			}
			if kev, ok := kevMap[lookupCVE]; ok {
				adv.IsKEV = true
				adv.KEVDateAdded = kev.DateAdded
				adv.KEVDueDate = kev.DueDate
				adv.KEVAction = strings.TrimSpace(kev.RequiredAction)
				adv.Sources = mergeStringsUnique(adv.Sources, []string{"CISA KEV"})
			}
		}
		if adv.Severity == vault.VulnSeverityUnknown && adv.CVSSScore > 0 {
			adv.Severity = vault.SeverityFromCVSS(adv.CVSSScore)
		}
		if adv.FixedVersion == "" && len(adv.FixedVersions) > 0 {
			adv.FixedVersion = strings.Join(adv.FixedVersions[:min(len(adv.FixedVersions), 3)], ", ")
		}
		if len(adv.FixedVersions) > 0 || adv.FixedVersion != "" {
			adv.HasFix = true
		}
		out = append(out, *adv)
	}
	return out
}

func canonicalAdvisoryKey(a vault.VulnAdvisory) string {
	if cve := strings.ToUpper(strings.TrimSpace(a.CVEID)); strings.HasPrefix(cve, "CVE-") {
		return cve
	}
	for _, al := range a.Aliases {
		if up := strings.ToUpper(strings.TrimSpace(al)); strings.HasPrefix(up, "CVE-") {
			return up
		}
	}
	if ghsa := strings.ToUpper(strings.TrimSpace(a.GHSAID)); strings.HasPrefix(ghsa, "GHSA-") {
		return ghsa
	}
	return strings.ToUpper(strings.TrimSpace(a.ID))
}

func mergeIntoAdvisory(dst *vault.VulnAdvisory, src vault.VulnAdvisory) {
	if dst.CVEID == "" && src.CVEID != "" {
		dst.CVEID = src.CVEID
	}
	if dst.GHSAID == "" && src.GHSAID != "" {
		dst.GHSAID = src.GHSAID
	}
	dst.Aliases = mergeStringsUnique(dst.Aliases, src.Aliases)
	dst.AppIDs = mergeStringsUnique(dst.AppIDs, src.AppIDs)
	dst.AppNames = mergeStringsUnique(dst.AppNames, src.AppNames)
	dst.Categories = mergeStringsUnique(dst.Categories, src.Categories)
	dst.CWEIDs = mergeStringsUnique(dst.CWEIDs, src.CWEIDs)
	dst.CPEHints = mergeStringsUnique(dst.CPEHints, src.CPEHints)
	dst.FixedVersions = mergeStringsUnique(dst.FixedVersions, src.FixedVersions)
	dst.Sources = mergeStringsUnique(dst.Sources, src.Sources)

	if src.CVSSScore > dst.CVSSScore {
		dst.CVSSScore = src.CVSSScore
		if src.CVSSVector != "" {
			dst.CVSSVector = src.CVSSVector
		}
	}
	if vault.VulnSeverityRank(src.Severity) > vault.VulnSeverityRank(dst.Severity) {
		dst.Severity = src.Severity
	}

	// Prefer vendor official announcements as primary source & URL over aggregators
	if isHigherPrioritySource(src.PrimarySource, dst.PrimarySource) {
		dst.PrimarySource = src.PrimarySource
		if src.OfficialURL != "" {
			dst.OfficialURL = src.OfficialURL
		}
		if src.Title != "" && len(src.Title) >= 12 {
			dst.Title = src.Title
		}
	}
	if dst.OfficialURL == "" && src.OfficialURL != "" {
		dst.OfficialURL = src.OfficialURL
	}
	if len(src.Summary) > len(dst.Summary) {
		dst.Summary = src.Summary
	}
	if len(src.Details) > len(dst.Details) {
		dst.Details = src.Details
	}
	if dst.AffectedText == "" && src.AffectedText != "" {
		dst.AffectedText = src.AffectedText
	}
	if dst.FixedVersion == "" && src.FixedVersion != "" {
		dst.FixedVersion = src.FixedVersion
	}
	if src.HasFix {
		dst.HasFix = true
	}
	if len(src.AffectedRanges) > 0 {
		for _, r := range src.AffectedRanges {
			if len(dst.AffectedRanges) >= 16 {
				break
			}
			dup := slices.ContainsFunc(dst.AffectedRanges, func(ex vault.VulnAffectedRange) bool {
				return ex.PackageName == r.PackageName && ex.RangeText == r.RangeText && ex.Fixed == r.Fixed
			})
			if !dup {
				dst.AffectedRanges = append(dst.AffectedRanges, r)
			}
		}
	}
	if len(src.References) > 0 {
		for _, r := range src.References {
			if len(dst.References) >= 20 {
				break
			}
			dup := slices.ContainsFunc(dst.References, func(ex vault.VulnReference) bool {
				return strings.EqualFold(ex.URL, r.URL)
			})
			if !dup {
				dst.References = append(dst.References, r)
			}
		}
	}
	if src.IsKEV {
		dst.IsKEV = true
		if src.KEVDateAdded != "" {
			dst.KEVDateAdded = src.KEVDateAdded
		}
		if src.KEVDueDate != "" {
			dst.KEVDueDate = src.KEVDueDate
		}
		if src.KEVAction != "" {
			dst.KEVAction = src.KEVAction
		}
	}
	if !src.PublishedAt.IsZero() && (dst.PublishedAt.IsZero() || src.PublishedAt.Before(dst.PublishedAt)) {
		dst.PublishedAt = src.PublishedAt
	}
	if !src.ModifiedAt.IsZero() && (dst.ModifiedAt.IsZero() || src.ModifiedAt.After(dst.ModifiedAt)) {
		dst.ModifiedAt = src.ModifiedAt
	}
}

func isHigherPrioritySource(candidate, current string) bool {
	rank := func(s string) int {
		switch {
		case strings.Contains(s, "官方"):
			return 4
		case strings.Contains(s, "GitHub"):
			return 3
		case strings.Contains(s, "OSV"):
			return 2
		case strings.Contains(s, "CISA"):
			return 1
		default:
			return 0
		}
	}
	return rank(candidate) > rank(current)
}

// RuntimeStatus returns a thread-safe snapshot of background sync status.
func (s *Service) RuntimeStatus() RuntimeStatus {
	var rt *vault.VulnRuntimeState
	var settings vault.VulnSettings
	if s.cfg.Store != nil && s.cfg.Store.IsReady() {
		rt = s.cfg.Store.GetVulnRuntimeSnapshot()
		settings, _ = s.cfg.Store.GetVulnSettings()
	} else {
		rt = vault.DefaultVulnRuntimeState()
		settings = vault.DefaultVulnSettings()
	}
	catalog := BuildResolvedCatalog(settings)
	watchedCount := 0
	for _, a := range catalog {
		if a.Watched {
			watchedCount++
		}
	}

	s.mu.RLock()
	syncing := s.syncing
	var nextCopy *time.Time
	if s.nextSyncAt != nil {
		t := *s.nextSyncAt
		nextCopy = &t
	}
	s.mu.RUnlock()

	return RuntimeStatus{
		Syncing:      syncing,
		LastSyncAt:   rt.LastSyncAt,
		NextSyncAt:   nextCopy,
		LastError:    rt.LastSyncError,
		LastNewCount: rt.LastNewCount,
		SourceStatus: rt.SourceStatus,
		WatchedCount: watchedCount,
		CatalogTotal: len(catalog),
	}
}

// BuildOverview computes KPIs, Live Ticker, catalog state, and filtered/paginated advisories strictly for watched apps.
func (s *Service) BuildOverview(q QueryFilter) (*OverviewResponse, error) {
	if s.cfg.Store == nil || !s.cfg.Store.IsReady() {
		return nil, vault.ErrVaultLocked
	}
	settings, err := s.cfg.Store.GetVulnSettings()
	if err != nil {
		return nil, err
	}
	rt := s.cfg.Store.GetVulnRuntimeSnapshot()
	catalog := BuildResolvedCatalog(settings)
	watchedSet := settings.ActiveWatchedAppSet()

	now := time.Now().UTC()
	sevenDaysAgo := now.AddDate(0, 0, -7)

	// 1. Collect all advisories belonging to currently watched apps (unchecking an app hides it immediately!)
	watchedAdvisories := make([]vault.VulnAdvisory, 0, len(rt.Advisories))
	kpi := KPIStats{}
	for _, st := range rt.SourceStatus {
		kpi.SourcesTotal++
		if st.OK {
			kpi.SourcesOK++
		}
	}

	newSinceCount := 0
	for _, adv := range rt.Advisories {
		matched := false
		for _, appID := range adv.AppIDs {
			if _, ok := watchedSet[appID]; ok {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		watchedAdvisories = append(watchedAdvisories, adv)

		if !q.Since.IsZero() && !adv.FirstSeenAt.IsZero() && adv.FirstSeenAt.After(q.Since) && !adv.IsIgnored {
			newSinceCount++
		}

		if adv.IsStarred {
			kpi.StarredTotal++
		}
		if adv.IsIgnored {
			continue
		}
		kpi.Total++
		switch adv.Severity {
		case vault.VulnSeverityCritical:
			kpi.Critical++
		case vault.VulnSeverityHigh:
			kpi.High++
		case vault.VulnSeverityMedium:
			kpi.Medium++
		case vault.VulnSeverityLow:
			kpi.Low++
		default:
			kpi.Unknown++
		}
		if adv.IsKEV {
			kpi.KEV++
		}
		if adv.HasFix {
			kpi.HasFix++
		}
		eff := effectiveTime(adv)
		if !eff.IsZero() && !eff.Before(sevenDaysAgo) {
			kpi.Recent7d++
		}
		if !adv.IsRead {
			kpi.UnreadTotal++
			if adv.Severity == vault.VulnSeverityCritical || adv.Severity == vault.VulnSeverityHigh || adv.IsKEV {
				kpi.UnreadCriticalHigh++
			}
		}
	}

	// 2. Build Top Live Ticker (up to 12 latest Critical/High/KEV non-ignored advisories; fallback to latest watched)
	ticker := make([]vault.VulnAdvisory, 0, 12)
	for _, adv := range watchedAdvisories {
		if adv.IsIgnored {
			continue
		}
		if adv.Severity == vault.VulnSeverityCritical || adv.Severity == vault.VulnSeverityHigh || adv.IsKEV {
			ticker = append(ticker, adv)
			if len(ticker) >= 12 {
				break
			}
		}
	}
	if len(ticker) < 6 {
		for _, adv := range watchedAdvisories {
			if adv.IsIgnored {
				continue
			}
			if slices.ContainsFunc(ticker, func(t vault.VulnAdvisory) bool { return t.ID == adv.ID }) {
				continue
			}
			ticker = append(ticker, adv)
			if len(ticker) >= 10 {
				break
			}
		}
	}

	// 3. Apply user filters
	appFilter := make(map[string]struct{}, len(q.AppIDs))
	for _, id := range q.AppIDs {
		if t := strings.ToLower(strings.TrimSpace(id)); t != "" && t != "all" {
			appFilter[t] = struct{}{}
		}
	}
	catFilter := make(map[string]struct{}, len(q.Categories))
	for _, c := range q.Categories {
		if t := strings.ToLower(strings.TrimSpace(c)); t != "" && t != "all" {
			catFilter[t] = struct{}{}
		}
	}
	sevFilter := make(map[vault.VulnSeverity]struct{}, len(q.Severities))
	for _, sv := range q.Severities {
		t := strings.ToLower(strings.TrimSpace(sv))
		if t != "" && t != "all" {
			sevFilter[vault.NormalizeVulnSeverity(t)] = struct{}{}
		}
	}
	searchLow := strings.ToLower(strings.TrimSpace(q.Search))
	var dayCutoff time.Time
	if q.Days > 0 {
		dayCutoff = now.AddDate(0, 0, -q.Days)
	}

	filtered := make([]vault.VulnAdvisory, 0, len(watchedAdvisories))
	for _, adv := range watchedAdvisories {
		switch strings.ToLower(strings.TrimSpace(q.State)) {
		case "unread":
			if adv.IsRead || adv.IsIgnored {
				continue
			}
		case "starred":
			if !adv.IsStarred {
				continue
			}
		case "ignored":
			if !adv.IsIgnored {
				continue
			}
		default: // "all" hides ignored by default unless user explicitly views "ignored"
			if adv.IsIgnored {
				continue
			}
		}

		if len(appFilter) > 0 {
			hit := false
			for _, id := range adv.AppIDs {
				if _, ok := appFilter[strings.ToLower(id)]; ok {
					hit = true
					break
				}
			}
			if !hit {
				continue
			}
		}
		if len(catFilter) > 0 {
			hit := false
			for _, c := range adv.Categories {
				if _, ok := catFilter[strings.ToLower(c)]; ok {
					hit = true
					break
				}
			}
			if !hit {
				continue
			}
		}
		if len(sevFilter) > 0 {
			if _, ok := sevFilter[adv.Severity]; !ok {
				continue
			}
		}
		if q.KEVOnly && !adv.IsKEV {
			continue
		}
		if q.FixedOnly && !adv.HasFix {
			continue
		}
		if !dayCutoff.IsZero() {
			eff := effectiveTime(adv)
			if !eff.IsZero() && eff.Before(dayCutoff) {
				continue
			}
		}
		if searchLow != "" {
			hay := strings.ToLower(strings.Join([]string{
				adv.ID,
				adv.CVEID,
				adv.GHSAID,
				strings.Join(adv.Aliases, " "),
				strings.Join(adv.AppNames, " "),
				adv.Title,
				adv.Summary,
				adv.PackageName,
				adv.FixedVersion,
				adv.AffectedText,
				strings.Join(adv.Sources, " "),
			}, " "))
			if !strings.Contains(hay, searchLow) {
				continue
			}
		}
		filtered = append(filtered, adv)
	}

	totalMatched := len(filtered)
	limit := q.Limit
	if limit <= 0 {
		limit = 40
	} else if limit > 200 {
		limit = 200
	}
	offset := max(0, q.Offset)
	if offset > totalMatched {
		offset = totalMatched
	}
	end := min(totalMatched, offset+limit)
	page := filtered[offset:end]
	hasMore := end < totalMatched

	return &OverviewResponse{
		Advisories:    page,
		TotalMatched:  totalMatched,
		HasMore:       hasMore,
		NewSinceCount: newSinceCount,
		Ticker:        ticker,
		KPI:           kpi,
		Settings:      settings.ToView(),
		Catalog:       catalog,
		Categories:    AppCategories(),
		Presets:       BuiltinAppPresets(),
		Runtime:       s.RuntimeStatus(),
	}, nil
}

func effectiveTime(a vault.VulnAdvisory) time.Time {
	if !a.PublishedAt.IsZero() && !a.ModifiedAt.IsZero() {
		if a.ModifiedAt.After(a.PublishedAt) {
			return a.ModifiedAt
		}
		return a.PublishedAt
	}
	if !a.PublishedAt.IsZero() {
		return a.PublishedAt
	}
	if !a.ModifiedAt.IsZero() {
		return a.ModifiedAt
	}
	return a.FirstSeenAt
}

// ExplainAdvisory generates (or returns cached) Chinese AI explanation and remediation guidance for an advisory.
func (s *Service) ExplainAdvisory(ctx context.Context, advisoryID string, force bool) (*vault.VulnAIAnalysis, error) {
	if s.cfg.Store == nil || !s.cfg.Store.IsReady() {
		return nil, vault.ErrVaultLocked
	}
	adv, err := s.cfg.Store.GetVulnAdvisory(advisoryID)
	if err != nil {
		return nil, err
	}
	if !force && adv.AIAnalysis != nil && strings.TrimSpace(adv.AIAnalysis.SummaryZH) != "" {
		return adv.AIAnalysis, nil
	}
	if s.cfg.AICompleter == nil {
		return nil, fmt.Errorf("AI 解读引擎未初始化")
	}

	sysPrompt := `你是资深 Linux/云原生安全运维专家。请根据用户提供的官方安全漏洞公告，输出简洁、准确、可落地的简体中文解读。
请严格仅输出合法 JSON（不要包裹 markdown 代码块），包含以下字段：
{
  "summary_zh": "1~2句中文概括漏洞本质、触发条件与官方修复结论",
  "impact_zh": "受影响范围、潜在危害与暴露面评估（是否需公网暴露/认证等）",
  "fix_steps_zh": ["具体升级步骤或缓解措施1", "具体步骤2", "具体步骤3"],
  "verification_cmd": "一条安全的只读 Shell 命令用于检查服务器当前软件版本（如 nginx -v 或 openssl version）"
}`

	userPrompt := fmt.Sprintf(
		"漏洞编号: %s (CVE: %s, GHSA: %s)\n关联应用: %s\n等级与分数: %s (CVSS %.1f)\n是否已知在野利用(CISA KEV): %v\n受影响版本: %s\n官方修复版本: %s\n官方标题: %s\n官方摘要: %s\n官方详情:\n%s",
		adv.ID,
		adv.CVEID,
		adv.GHSAID,
		strings.Join(adv.AppNames, ", "),
		adv.Severity,
		adv.CVSSScore,
		adv.IsKEV,
		nonEmpty(adv.AffectedText, "未明确标注"),
		nonEmpty(adv.FixedVersion, "暂未提供明确修复版本号"),
		adv.Title,
		adv.Summary,
		truncateRunes(adv.Details, 2400),
	)

	content, model, err := s.cfg.AICompleter(ctx, sysPrompt, userPrompt)
	if err != nil {
		return nil, err
	}

	analysis := parseAIAnalysisResponse(content, model)
	if err := s.cfg.Store.SaveVulnAIAnalysis(adv.ID, analysis); err != nil {
		return nil, err
	}
	return &analysis, nil
}

func parseAIAnalysisResponse(raw, model string) vault.VulnAIAnalysis {
	now := time.Now().UTC()
	cleaned := strings.TrimSpace(raw)
	if strings.HasPrefix(cleaned, "```") {
		if idx := strings.Index(cleaned, "\n"); idx >= 0 {
			cleaned = cleaned[idx+1:]
		}
		cleaned = strings.TrimSuffix(strings.TrimSpace(cleaned), "```")
		cleaned = strings.TrimSpace(cleaned)
	}
	// Try to locate outermost JSON object
	if start := strings.Index(cleaned, "{"); start >= 0 {
		if end := strings.LastIndex(cleaned, "}"); end > start {
			candidate := cleaned[start : end+1]
			var parsed struct {
				SummaryZH       string   `json:"summary_zh"`
				ImpactZH        string   `json:"impact_zh"`
				FixStepsZH      []string `json:"fix_steps_zh"`
				VerificationCmd string   `json:"verification_cmd"`
			}
			if json.Unmarshal([]byte(candidate), &parsed) == nil && strings.TrimSpace(parsed.SummaryZH) != "" {
				return vault.VulnAIAnalysis{
					SummaryZH:       strings.TrimSpace(parsed.SummaryZH),
					ImpactZH:        strings.TrimSpace(parsed.ImpactZH),
					FixStepsZH:      parsed.FixStepsZH,
					VerificationCmd: strings.TrimSpace(parsed.VerificationCmd),
					Model:           model,
					GeneratedAt:     now,
				}
			}
		}
	}
	return vault.VulnAIAnalysis{
		SummaryZH:   firstLineSummary(cleaned, 240),
		RawMarkdown: cleaned,
		Model:       model,
		GeneratedAt: now,
	}
}

// TestWebhook sends a test vulnerability notification to verify configured webhook delivery.
func (s *Service) TestWebhook(ctx context.Context, customURL string, reusePatrol bool) error {
	channels := s.resolveWebhookChannels(customURL, reusePatrol)
	if len(channels) == 0 {
		return fmt.Errorf("%w: 未找到可用的 Webhook 渠道，请填写自定义 Webhook 地址或先在 AI 巡检中启用 Webhook", vault.ErrInvalidInput)
	}
	title := "ServerNeedSafe · 漏洞监测测试通知"
	md := "### [ServerNeedSafe] 漏洞监测 Webhook 连通性测试\n" +
		"- **测试状态**：通道配置正常，可实时接收新发现的高危/严重及在野利用 (CISA KEV) 官方漏洞修复动态。\n" +
		"- **发送时间**：" + time.Now().Local().Format("2006-01-02 15:04:05") + "\n"
	payload := map[string]any{
		"source":    "ServerNeedSafe",
		"event":     "vuln.test",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"markdown":  md,
	}
	var lastErr error
	sent := 0
	for _, ch := range channels {
		if err := s.cfg.WebhookSender(ctx, ch, title, "turquoise", md, payload); err != nil {
			lastErr = err
		} else {
			sent++
		}
	}
	if sent == 0 && lastErr != nil {
		return lastErr
	}
	return nil
}

func (s *Service) notifyNewAdvisories(ctx context.Context, settings vault.VulnSettings, newlyAdded []vault.VulnAdvisory) {
	minRank := vault.VulnSeverityRank(settings.NotifyMinSeverity)
	var hits []vault.VulnAdvisory
	for _, adv := range newlyAdded {
		if s.cfg.Store.IsVulnNotified(adv.ID) {
			continue
		}
		if settings.NotifyKEVOnly && !adv.IsKEV {
			continue
		}
		if !adv.IsKEV && vault.VulnSeverityRank(adv.Severity) < minRank {
			continue
		}
		hits = append(hits, adv)
	}
	if len(hits) == 0 {
		return
	}

	channels := s.resolveWebhookChannels(settings.CustomWebhookURL, settings.ReuseAIPatrolWebhook)
	if len(channels) == 0 {
		return
	}

	hasCritOrKEV := false
	var md strings.Builder
	md.WriteString(fmt.Sprintf("### [ServerNeedSafe] 发现 %d 条新的主流应用官方高危漏洞动态\n", len(hits)))
	for i, a := range hits {
		if a.Severity == vault.VulnSeverityCritical || a.IsKEV {
			hasCritOrKEV = true
		}
		if i >= 8 {
			md.WriteString(fmt.Sprintf("- ... 其余 %d 条请前往「漏洞监测」查看\n", len(hits)-8))
			break
		}
		kevBadge := ""
		if a.IsKEV {
			kevBadge = " 🔥[在野利用 KEV]"
		}
		fixHint := "暂无明确补丁"
		if a.FixedVersion != "" {
			fixHint = "修复版本: `" + a.FixedVersion + "`"
		}
		md.WriteString(fmt.Sprintf("- **[%s]%s %s** (%s) — %s（%s）\n",
			strings.ToUpper(string(a.Severity)), kevBadge, a.ID, strings.Join(a.AppNames, "/"), truncateRunes(a.Title, 90), fixHint))
	}

	color := "orange"
	if hasCritOrKEV {
		color = "red"
	}
	title := fmt.Sprintf("ServerNeedSafe · 发现 %d 条新官方漏洞修复动态", len(hits))
	payload := map[string]any{
		"source":     "ServerNeedSafe",
		"event":      "vuln.new_advisories",
		"count":      len(hits),
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
		"advisories": hits,
		"markdown":   md.String(),
	}

	sentAny := false
	for _, ch := range channels {
		if err := s.cfg.WebhookSender(ctx, ch, title, color, md.String(), payload); err != nil {
			log.Printf("[ServerNeedSafe] 漏洞监测 Webhook 推送失败 (%s): %v", ch.Name, err)
		} else {
			sentAny = true
		}
	}
	if sentAny {
		ids := make([]string, 0, len(hits))
		for _, h := range hits {
			ids = append(ids, h.ID)
		}
		s.cfg.Store.MarkVulnNotified(ids)
	}
}

func (s *Service) resolveWebhookChannels(customURL string, reusePatrol bool) []vault.WebhookChannel {
	var channels []vault.WebhookChannel
	seen := make(map[string]struct{})
	addCh := func(ch vault.WebhookChannel) {
		u := strings.TrimSpace(ch.URL)
		if u == "" {
			return
		}
		if _, dup := seen[u]; dup {
			return
		}
		seen[u] = struct{}{}
		channels = append(channels, ch)
	}
	if u := strings.TrimSpace(customURL); u != "" {
		addCh(vault.WebhookChannel{
			ID:      "vuln-custom",
			Name:    "漏洞监测专用 Webhook",
			Kind:    inferWebhookKind(u),
			URL:     u,
			Enabled: true,
		})
	}
	if reusePatrol && s.cfg.Store != nil {
		if patrol, err := s.cfg.Store.GetPatrolConfigSecret(); err == nil && patrol != nil {
			for _, wh := range patrol.Webhooks {
				if wh.Enabled && strings.TrimSpace(wh.URL) != "" {
					addCh(wh)
				}
			}
		}
	}
	return channels
}

func inferWebhookKind(rawURL string) string {
	low := strings.ToLower(rawURL)
	switch {
	case strings.Contains(low, "feishu.cn") || strings.Contains(low, "larksuite.com"):
		return "feishu"
	case strings.Contains(low, "dingtalk.com"):
		return "dingtalk"
	case strings.Contains(low, "weixin.qq.com"):
		return "wecom"
	default:
		return "custom"
	}
}

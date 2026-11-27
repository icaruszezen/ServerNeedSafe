package vault

import (
	"net/url"
	"slices"
	"strings"
	"time"
)

// VulnSeverity represents the normalized CVSS severity level of a security advisory.
type VulnSeverity string

const (
	VulnSeverityCritical VulnSeverity = "critical"
	VulnSeverityHigh     VulnSeverity = "high"
	VulnSeverityMedium   VulnSeverity = "medium"
	VulnSeverityLow      VulnSeverity = "low"
	VulnSeverityUnknown  VulnSeverity = "unknown"
)

// VulnSeverityRank returns a descending sort rank (higher = more severe).
func VulnSeverityRank(s VulnSeverity) int {
	switch NormalizeVulnSeverity(string(s)) {
	case VulnSeverityCritical:
		return 5
	case VulnSeverityHigh:
		return 4
	case VulnSeverityMedium:
		return 3
	case VulnSeverityLow:
		return 2
	default:
		return 1
	}
}

// NormalizeVulnSeverity maps diverse upstream severity strings (CVSS/GHSA/OpenSSL/Ubuntu/Nginx)
// onto the canonical 4-tier + unknown vocabulary.
func NormalizeVulnSeverity(raw string) VulnSeverity {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical", "crit", "urgent", "emergency", "p0":
		return VulnSeverityCritical
	case "high", "important", "severe", "p1":
		return VulnSeverityHigh
	case "medium", "moderate", "med", "warning", "p2":
		return VulnSeverityMedium
	case "low", "minor", "negligible", "info", "informational", "p3":
		return VulnSeverityLow
	default:
		return VulnSeverityUnknown
	}
}

// SeverityFromCVSS converts a CVSS v3/v4 numeric score (0.0..10.0) into a VulnSeverity.
func SeverityFromCVSS(score float64) VulnSeverity {
	switch {
	case score >= 9.0:
		return VulnSeverityCritical
	case score >= 7.0:
		return VulnSeverityHigh
	case score >= 4.0:
		return VulnSeverityMedium
	case score > 0:
		return VulnSeverityLow
	default:
		return VulnSeverityUnknown
	}
}

// DefaultWatchedVulnAppIDs returns the minimal 4-app core security baseline enabled out of the box.
func DefaultWatchedVulnAppIDs() []string {
	return []string{
		"linux-kernel",
		"openssh",
		"openssl",
		"nginx",
	}
}

// VulnCustomApp represents a user-added GitHub repository or OSV ecosystem package to track.
type VulnCustomApp struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Category    string    `json:"category"` // default "custom"
	Kind        string    `json:"kind"`     // "github_repo" or "osv_package"
	Repo        string    `json:"repo,omitempty"`
	Ecosystem   string    `json:"ecosystem,omitempty"`
	PackageName string    `json:"package_name,omitempty"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
}

// VulnSettings configures the 7x24 vulnerability advisory monitor.
// Stored encrypted inside SecretsState (secrets.enc) so proxy credentials and GitHub tokens are protected at rest.
type VulnSettings struct {
	Enabled              bool            `json:"enabled"`
	SyncIntervalMinutes  int             `json:"sync_interval_minutes"`         // 10..1440, default 30
	RetentionDays        int             `json:"retention_days"`                // 7..365, default 90
	MaxRecords           int             `json:"max_records"`                   // 200..5000, default 3000
	WatchedAppIDs        []string        `json:"watched_app_ids"`               // Built-in watched app IDs
	CustomApps           []VulnCustomApp `json:"custom_apps,omitempty"`         // User-added GitHub repos / OSV packages
	HTTPProxyURL         string          `json:"http_proxy_url,omitempty"`      // Optional encrypted proxy URL
	GitHubToken          string          `json:"github_token,omitempty"`        // Optional encrypted GitHub PAT
	NotifyWebhook        bool            `json:"notify_webhook"`                // Default false
	NotifyMinSeverity    VulnSeverity    `json:"notify_min_severity,omitempty"` // "critical" (default) or "high"
	NotifyKEVOnly        bool            `json:"notify_kev_only,omitempty"`     // Only push KEV alerts
	ReuseAIPatrolWebhook bool            `json:"reuse_ai_patrol_webhook"`       // Reuse enabled AI patrol webhooks
	CustomWebhookURL     string          `json:"custom_webhook_url,omitempty"`  // Optional dedicated webhook URL
	Initialized          bool            `json:"initialized,omitempty"`         // Marks explicit initialization
}

// VulnSettingsView is the redacted representation returned to the Web UI.
type VulnSettingsView struct {
	Enabled              bool            `json:"enabled"`
	SyncIntervalMinutes  int             `json:"sync_interval_minutes"`
	RetentionDays        int             `json:"retention_days"`
	MaxRecords           int             `json:"max_records"`
	WatchedAppIDs        []string        `json:"watched_app_ids"`
	CustomApps           []VulnCustomApp `json:"custom_apps"`
	HasHTTPProxy         bool            `json:"has_http_proxy"`
	HTTPProxyDisplay     string          `json:"http_proxy_display,omitempty"`
	HasGitHubToken       bool            `json:"has_github_token"`
	NotifyWebhook        bool            `json:"notify_webhook"`
	NotifyMinSeverity    VulnSeverity    `json:"notify_min_severity"`
	NotifyKEVOnly        bool            `json:"notify_kev_only"`
	ReuseAIPatrolWebhook bool            `json:"reuse_ai_patrol_webhook"`
	HasCustomWebhook     bool            `json:"has_custom_webhook"`
	CustomWebhookDisplay string          `json:"custom_webhook_display,omitempty"`
}

// DefaultVulnSettings returns out-of-the-box settings tracking only the minimal 4 core security apps.
func DefaultVulnSettings() VulnSettings {
	return VulnSettings{
		Enabled:              true,
		SyncIntervalMinutes:  30,
		RetentionDays:        90,
		MaxRecords:           3000,
		WatchedAppIDs:        DefaultWatchedVulnAppIDs(),
		CustomApps:           []VulnCustomApp{},
		NotifyWebhook:        false,
		NotifyMinSeverity:    VulnSeverityCritical,
		NotifyKEVOnly:        false,
		ReuseAIPatrolWebhook: true,
		Initialized:          true,
	}
}

// NormalizeVulnSettings clamps bounds and preserves explicit empty watched lists once initialized.
func NormalizeVulnSettings(in VulnSettings) VulnSettings {
	if !in.Initialized &&
		in.SyncIntervalMinutes == 0 &&
		in.RetentionDays == 0 &&
		in.MaxRecords == 0 &&
		len(in.WatchedAppIDs) == 0 &&
		len(in.CustomApps) == 0 {
		return DefaultVulnSettings()
	}
	out := in
	out.Initialized = true
	if out.SyncIntervalMinutes <= 0 {
		out.SyncIntervalMinutes = 30
	} else if out.SyncIntervalMinutes < 10 {
		out.SyncIntervalMinutes = 10
	} else if out.SyncIntervalMinutes > 1440 {
		out.SyncIntervalMinutes = 1440
	}
	if out.RetentionDays <= 0 {
		out.RetentionDays = 90
	} else if out.RetentionDays < 7 {
		out.RetentionDays = 7
	} else if out.RetentionDays > 365 {
		out.RetentionDays = 365
	}
	if out.MaxRecords <= 0 {
		out.MaxRecords = 3000
	} else if out.MaxRecords < 200 {
		out.MaxRecords = 200
	} else if out.MaxRecords > 5000 {
		out.MaxRecords = 5000
	}

	seenApps := make(map[string]struct{}, len(out.WatchedAppIDs))
	cleanedApps := make([]string, 0, len(out.WatchedAppIDs))
	for _, raw := range out.WatchedAppIDs {
		id := strings.ToLower(strings.TrimSpace(raw))
		if id == "" {
			continue
		}
		if _, dup := seenApps[id]; dup {
			continue
		}
		seenApps[id] = struct{}{}
		cleanedApps = append(cleanedApps, id)
	}
	out.WatchedAppIDs = cleanedApps

	cleanedCustom := make([]VulnCustomApp, 0, len(out.CustomApps))
	seenCustom := make(map[string]struct{}, len(out.CustomApps))
	for _, ca := range out.CustomApps {
		ca.ID = strings.TrimSpace(ca.ID)
		ca.Name = strings.TrimSpace(ca.Name)
		ca.Category = strings.TrimSpace(ca.Category)
		if ca.Category == "" {
			ca.Category = "custom"
		}
		ca.Kind = strings.ToLower(strings.TrimSpace(ca.Kind))
		ca.Repo = strings.Trim(strings.TrimSpace(ca.Repo), "/")
		ca.Ecosystem = strings.TrimSpace(ca.Ecosystem)
		ca.PackageName = strings.TrimSpace(ca.PackageName)
		if ca.ID == "" || ca.Name == "" {
			continue
		}
		if ca.Kind != "github_repo" && ca.Kind != "osv_package" {
			continue
		}
		if _, dup := seenCustom[ca.ID]; dup {
			continue
		}
		seenCustom[ca.ID] = struct{}{}
		cleanedCustom = append(cleanedCustom, ca)
	}
	out.CustomApps = cleanedCustom

	out.HTTPProxyURL = strings.TrimSpace(out.HTTPProxyURL)
	out.GitHubToken = strings.TrimSpace(out.GitHubToken)
	out.CustomWebhookURL = strings.TrimSpace(out.CustomWebhookURL)

	switch NormalizeVulnSeverity(string(out.NotifyMinSeverity)) {
	case VulnSeverityHigh:
		out.NotifyMinSeverity = VulnSeverityHigh
	default:
		out.NotifyMinSeverity = VulnSeverityCritical
	}
	return out
}

func cloneVulnSettings(in VulnSettings) VulnSettings {
	cp := in
	cp.WatchedAppIDs = slices.Clone(in.WatchedAppIDs)
	if cp.WatchedAppIDs == nil {
		cp.WatchedAppIDs = []string{}
	}
	cp.CustomApps = slices.Clone(in.CustomApps)
	if cp.CustomApps == nil {
		cp.CustomApps = []VulnCustomApp{}
	}
	return cp
}

// ToView creates a secret-redacted representation of VulnSettings for HTTP APIs.
func (s VulnSettings) ToView() VulnSettingsView {
	norm := NormalizeVulnSettings(s)
	return VulnSettingsView{
		Enabled:              norm.Enabled,
		SyncIntervalMinutes:  norm.SyncIntervalMinutes,
		RetentionDays:        norm.RetentionDays,
		MaxRecords:           norm.MaxRecords,
		WatchedAppIDs:        slices.Clone(norm.WatchedAppIDs),
		CustomApps:           slices.Clone(norm.CustomApps),
		HasHTTPProxy:         norm.HTTPProxyURL != "",
		HTTPProxyDisplay:     redactURLCredentials(norm.HTTPProxyURL),
		HasGitHubToken:       norm.GitHubToken != "",
		NotifyWebhook:        norm.NotifyWebhook,
		NotifyMinSeverity:    norm.NotifyMinSeverity,
		NotifyKEVOnly:        norm.NotifyKEVOnly,
		ReuseAIPatrolWebhook: norm.ReuseAIPatrolWebhook,
		HasCustomWebhook:     norm.CustomWebhookURL != "",
		CustomWebhookDisplay: redactWebhookDisplay(norm.CustomWebhookURL),
	}
}

// ActiveWatchedAppSet returns the combined set of enabled built-in + custom app IDs.
func (s VulnSettings) ActiveWatchedAppSet() map[string]struct{} {
	norm := NormalizeVulnSettings(s)
	out := make(map[string]struct{}, len(norm.WatchedAppIDs)+len(norm.CustomApps))
	for _, id := range norm.WatchedAppIDs {
		out[id] = struct{}{}
	}
	for _, ca := range norm.CustomApps {
		if ca.Enabled {
			out[ca.ID] = struct{}{}
		}
	}
	return out
}

func redactURLCredentials(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return "[已配置代理]"
	}
	if u.User != nil {
		username := u.User.Username()
		if username != "" {
			u.User = url.UserPassword(username, "******")
		} else {
			u.User = url.User("******")
		}
	}
	return u.String()
}

func redactWebhookDisplay(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	u, err := url.Parse(trimmed)
	if err != nil || u.Host == "" {
		return "[已配置 Webhook]"
	}
	pathPreview := u.Path
	if len(pathPreview) > 18 {
		pathPreview = pathPreview[:12] + "…" + pathPreview[len(pathPreview)-4:]
	}
	return u.Scheme + "://" + u.Host + pathPreview
}

// VulnAffectedRange captures structured version ranges for display and future Phase-2 host matching.
type VulnAffectedRange struct {
	Ecosystem     string   `json:"ecosystem,omitempty"`
	PackageName   string   `json:"package_name,omitempty"`
	Introduced    string   `json:"introduced,omitempty"`
	Fixed         string   `json:"fixed,omitempty"`
	LastAffected  string   `json:"last_affected,omitempty"`
	RangeText     string   `json:"range_text,omitempty"`
	FixedVersions []string `json:"fixed_versions,omitempty"`
}

// VulnReference links to an official vendor advisory, commit, release note, or NVD entry.
type VulnReference struct {
	Type  string `json:"type,omitempty"`
	URL   string `json:"url"`
	Label string `json:"label,omitempty"`
}

// VulnAIAnalysis caches an on-demand Chinese interpretation and upgrade guide generated by the configured AI provider.
type VulnAIAnalysis struct {
	SummaryZH       string    `json:"summary_zh"`
	ImpactZH        string    `json:"impact_zh,omitempty"`
	FixStepsZH      []string  `json:"fix_steps_zh,omitempty"`
	VerificationCmd string    `json:"verification_cmd,omitempty"`
	RawMarkdown     string    `json:"raw_markdown,omitempty"`
	Model           string    `json:"model,omitempty"`
	GeneratedAt     time.Time `json:"generated_at"`
}

// VulnAdvisory represents a deduplicated, normalized security advisory from one or more official sources.
type VulnAdvisory struct {
	ID             string              `json:"id"`
	CVEID          string              `json:"cve_id,omitempty"`
	GHSAID         string              `json:"ghsa_id,omitempty"`
	Aliases        []string            `json:"aliases,omitempty"`
	AppIDs         []string            `json:"app_ids"`
	AppNames       []string            `json:"app_names"`
	Categories     []string            `json:"categories"`
	Title          string              `json:"title"`
	Summary        string              `json:"summary"`
	Details        string              `json:"details,omitempty"`
	Severity       VulnSeverity        `json:"severity"`
	CVSSScore      float64             `json:"cvss_score,omitempty"`
	CVSSVector     string              `json:"cvss_vector,omitempty"`
	CWEIDs         []string            `json:"cwe_ids,omitempty"`
	Ecosystem      string              `json:"ecosystem,omitempty"`
	PackageName    string              `json:"package_name,omitempty"`
	CPEHints       []string            `json:"cpe_hints,omitempty"`
	AffectedText   string              `json:"affected_text,omitempty"`
	FixedVersion   string              `json:"fixed_version,omitempty"`
	FixedVersions  []string            `json:"fixed_versions,omitempty"`
	HasFix         bool                `json:"has_fix"`
	AffectedRanges []VulnAffectedRange `json:"affected_ranges,omitempty"`
	IsKEV          bool                `json:"is_kev"`
	KEVDateAdded   string              `json:"kev_date_added,omitempty"`
	KEVDueDate     string              `json:"kev_due_date,omitempty"`
	KEVAction      string              `json:"kev_action,omitempty"`
	Sources        []string            `json:"sources"`
	PrimarySource  string              `json:"primary_source"`
	OfficialURL    string              `json:"official_url,omitempty"`
	References     []VulnReference     `json:"references,omitempty"`
	PublishedAt    time.Time           `json:"published_at"`
	ModifiedAt     time.Time           `json:"modified_at"`
	FirstSeenAt    time.Time           `json:"first_seen_at"`
	LastSyncedAt   time.Time           `json:"last_synced_at"`

	// Hydrated view-time fields merged from VulnRuntimeState.UserStates & AIAnalyses
	IsRead     bool            `json:"is_read"`
	IsStarred  bool            `json:"is_starred"`
	IsIgnored  bool            `json:"is_ignored"`
	IsNew      bool            `json:"is_new"`
	AIAnalysis *VulnAIAnalysis `json:"ai_analysis,omitempty"`
}

// VulnUserState persists lightweight operator triage flags independent of upstream advisory syncs.
type VulnUserState struct {
	Read      bool      `json:"read,omitempty"`
	Starred   bool      `json:"starred,omitempty"`
	Ignored   bool      `json:"ignored,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

// VulnSourceStatus reports per-upstream source health and diagnostics from the most recent sync.
type VulnSourceStatus struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Kind       string     `json:"kind"` // "osv", "ghsa", "vendor", "kev"
	URL        string     `json:"url,omitempty"`
	OK         bool       `json:"ok"`
	ItemCount  int        `json:"item_count"`
	DurationMs int64      `json:"duration_ms"`
	LastSyncAt *time.Time `json:"last_sync_at,omitempty"`
	LastError  string     `json:"last_error,omitempty"`
}

// VulnRuntimeState is persisted asynchronously to vuln_runtime.json without touching secrets.enc.
type VulnRuntimeState struct {
	Advisories    []VulnAdvisory            `json:"advisories"`
	UserStates    map[string]VulnUserState  `json:"user_states"`
	AIAnalyses    map[string]VulnAIAnalysis `json:"ai_analyses"`
	SourceStatus  []VulnSourceStatus        `json:"source_status"`
	NotifiedIDs   map[string]time.Time      `json:"notified_ids,omitempty"`
	LastSyncAt    *time.Time                `json:"last_sync_at,omitempty"`
	LastSyncError string                    `json:"last_sync_error,omitempty"`
	LastNewCount  int                       `json:"last_new_count,omitempty"`
	ReadAllBefore *time.Time                `json:"read_all_before,omitempty"`
}

// DefaultVulnRuntimeState returns an initialized empty vulnerability runtime store.
func DefaultVulnRuntimeState() *VulnRuntimeState {
	return &VulnRuntimeState{
		Advisories:   []VulnAdvisory{},
		UserStates:   make(map[string]VulnUserState),
		AIAnalyses:   make(map[string]VulnAIAnalysis),
		SourceStatus: []VulnSourceStatus{},
		NotifiedIDs:  make(map[string]time.Time),
	}
}

func ensureVulnRuntimeDefaults(rt *VulnRuntimeState) {
	if rt == nil {
		return
	}
	if rt.Advisories == nil {
		rt.Advisories = []VulnAdvisory{}
	}
	if rt.UserStates == nil {
		rt.UserStates = make(map[string]VulnUserState)
	}
	if rt.AIAnalyses == nil {
		rt.AIAnalyses = make(map[string]VulnAIAnalysis)
	}
	if rt.SourceStatus == nil {
		rt.SourceStatus = []VulnSourceStatus{}
	}
	if rt.NotifiedIDs == nil {
		rt.NotifiedIDs = make(map[string]time.Time)
	}
}

func cloneVulnAdvisory(a VulnAdvisory) VulnAdvisory {
	cp := a
	cp.Aliases = slices.Clone(a.Aliases)
	cp.AppIDs = slices.Clone(a.AppIDs)
	cp.AppNames = slices.Clone(a.AppNames)
	cp.Categories = slices.Clone(a.Categories)
	cp.CWEIDs = slices.Clone(a.CWEIDs)
	cp.CPEHints = slices.Clone(a.CPEHints)
	cp.FixedVersions = slices.Clone(a.FixedVersions)
	cp.Sources = slices.Clone(a.Sources)
	cp.References = slices.Clone(a.References)
	if len(a.AffectedRanges) > 0 {
		cp.AffectedRanges = make([]VulnAffectedRange, len(a.AffectedRanges))
		for i, r := range a.AffectedRanges {
			rCp := r
			rCp.FixedVersions = slices.Clone(r.FixedVersions)
			cp.AffectedRanges[i] = rCp
		}
	}
	if a.AIAnalysis != nil {
		aiCp := *a.AIAnalysis
		aiCp.FixStepsZH = slices.Clone(a.AIAnalysis.FixStepsZH)
		cp.AIAnalysis = &aiCp
	}
	return cp
}

func cloneVulnRuntimeState(in *VulnRuntimeState) *VulnRuntimeState {
	if in == nil {
		return DefaultVulnRuntimeState()
	}
	cp := &VulnRuntimeState{
		Advisories:    make([]VulnAdvisory, len(in.Advisories)),
		UserStates:    make(map[string]VulnUserState, len(in.UserStates)),
		AIAnalyses:    make(map[string]VulnAIAnalysis, len(in.AIAnalyses)),
		SourceStatus:  make([]VulnSourceStatus, len(in.SourceStatus)),
		NotifiedIDs:   make(map[string]time.Time, len(in.NotifiedIDs)),
		LastSyncError: in.LastSyncError,
		LastNewCount:  in.LastNewCount,
	}
	for i, a := range in.Advisories {
		cp.Advisories[i] = cloneVulnAdvisory(a)
	}
	for k, v := range in.UserStates {
		cp.UserStates[k] = v
	}
	for k, v := range in.AIAnalyses {
		vCp := v
		vCp.FixStepsZH = slices.Clone(v.FixStepsZH)
		cp.AIAnalyses[k] = vCp
	}
	for i, st := range in.SourceStatus {
		stCp := st
		if st.LastSyncAt != nil {
			t := *st.LastSyncAt
			stCp.LastSyncAt = &t
		}
		cp.SourceStatus[i] = stCp
	}
	for k, v := range in.NotifiedIDs {
		cp.NotifiedIDs[k] = v
	}
	if in.LastSyncAt != nil {
		t := *in.LastSyncAt
		cp.LastSyncAt = &t
	}
	if in.ReadAllBefore != nil {
		t := *in.ReadAllBefore
		cp.ReadAllBefore = &t
	}
	return cp
}

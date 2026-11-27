package vault

import (
	"fmt"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"
)

// VulnSettingsUpdateInput represents a partial or full update payload from the Web UI.
// Secret fields (HTTPProxyURL, GitHubToken, CustomWebhookURL) preserve existing stored values when omitted
// unless their corresponding Clear* flag is set.
type VulnSettingsUpdateInput struct {
	Enabled              *bool           `json:"enabled,omitempty"`
	SyncIntervalMinutes  *int            `json:"sync_interval_minutes,omitempty"`
	RetentionDays        *int            `json:"retention_days,omitempty"`
	MaxRecords           *int            `json:"max_records,omitempty"`
	WatchedAppIDs        *[]string       `json:"watched_app_ids,omitempty"`
	CustomApps           *[]VulnCustomApp `json:"custom_apps,omitempty"`
	HTTPProxyURL         *string         `json:"http_proxy_url,omitempty"`
	ClearHTTPProxy       bool            `json:"clear_http_proxy,omitempty"`
	GitHubToken          *string         `json:"github_token,omitempty"`
	ClearGitHubToken     bool            `json:"clear_github_token,omitempty"`
	NotifyWebhook        *bool           `json:"notify_webhook,omitempty"`
	NotifyMinSeverity    *VulnSeverity   `json:"notify_min_severity,omitempty"`
	NotifyKEVOnly        *bool           `json:"notify_kev_only,omitempty"`
	ReuseAIPatrolWebhook *bool           `json:"reuse_ai_patrol_webhook,omitempty"`
	CustomWebhookURL     *string         `json:"custom_webhook_url,omitempty"`
	ClearCustomWebhook   bool            `json:"clear_custom_webhook,omitempty"`
}

// GetVulnSettings returns a deep copy of normalized VulnSettings including secrets (for internal backend engine).
func (s *Store) GetVulnSettings() (VulnSettings, error) {
	s.secMu.RLock()
	defer s.secMu.RUnlock()
	if s.secrets == nil {
		return DefaultVulnSettings(), ErrVaultLocked
	}
	return cloneVulnSettings(NormalizeVulnSettings(s.secrets.VulnSettings)), nil
}

// GetVulnSettingsView returns the secret-redacted VulnSettingsView for HTTP APIs.
func (s *Store) GetVulnSettingsView() (VulnSettingsView, error) {
	cfg, err := s.GetVulnSettings()
	if err != nil {
		return DefaultVulnSettings().ToView(), err
	}
	return cfg.ToView(), nil
}

// UpdateVulnSettings validates and saves vulnerability monitoring configuration into secrets.enc.
// Returns the updated settings view and the slice of newly enabled app IDs (for immediate incremental sync).
func (s *Store) UpdateVulnSettings(in VulnSettingsUpdateInput, clientIP string) (VulnSettingsView, []string, error) {
	var out VulnSettings
	var newlyEnabled []string

	err := s.mutateSecrets(func(sec *SecretsState) error {
		cur := NormalizeVulnSettings(sec.VulnSettings)
		prevWatched := cur.ActiveWatchedAppSet()

		if in.Enabled != nil {
			cur.Enabled = *in.Enabled
		}
		if in.SyncIntervalMinutes != nil {
			cur.SyncIntervalMinutes = *in.SyncIntervalMinutes
		}
		if in.RetentionDays != nil {
			cur.RetentionDays = *in.RetentionDays
		}
		if in.MaxRecords != nil {
			cur.MaxRecords = *in.MaxRecords
		}
		if in.WatchedAppIDs != nil {
			cur.WatchedAppIDs = slices.Clone(*in.WatchedAppIDs)
		}
		if in.CustomApps != nil {
			cur.CustomApps = slices.Clone(*in.CustomApps)
		}
		if in.ClearHTTPProxy {
			cur.HTTPProxyURL = ""
		} else if in.HTTPProxyURL != nil {
			trimmed := strings.TrimSpace(*in.HTTPProxyURL)
			if trimmed != "" {
				if err := validateProxyURL(trimmed); err != nil {
					return err
				}
				cur.HTTPProxyURL = trimmed
			}
		}
		if in.ClearGitHubToken {
			cur.GitHubToken = ""
		} else if in.GitHubToken != nil {
			trimmed := strings.TrimSpace(*in.GitHubToken)
			if trimmed != "" {
				cur.GitHubToken = trimmed
			}
		}
		if in.NotifyWebhook != nil {
			cur.NotifyWebhook = *in.NotifyWebhook
		}
		if in.NotifyMinSeverity != nil {
			cur.NotifyMinSeverity = *in.NotifyMinSeverity
		}
		if in.NotifyKEVOnly != nil {
			cur.NotifyKEVOnly = *in.NotifyKEVOnly
		}
		if in.ReuseAIPatrolWebhook != nil {
			cur.ReuseAIPatrolWebhook = *in.ReuseAIPatrolWebhook
		}
		if in.ClearCustomWebhook {
			cur.CustomWebhookURL = ""
		} else if in.CustomWebhookURL != nil {
			trimmed := strings.TrimSpace(*in.CustomWebhookURL)
			if trimmed != "" {
				if err := validateWebhookURL(trimmed); err != nil {
					return err
				}
				cur.CustomWebhookURL = trimmed
			}
		}

		cur.Initialized = true
		norm := NormalizeVulnSettings(cur)
		nextWatched := norm.ActiveWatchedAppSet()
		for id := range nextWatched {
			if _, existed := prevWatched[id]; !existed {
				newlyEnabled = append(newlyEnabled, id)
			}
		}
		sort.Strings(newlyEnabled)

		sec.VulnSettings = norm
		out = cloneVulnSettings(norm)
		return nil
	})
	if err != nil {
		return VulnSettingsView{}, nil, err
	}

	s.RecordAudit(
		"vuln.config",
		"vulnerability-monitor",
		fmt.Sprintf("更新漏洞监测配置（已监看 %d 个内置应用 + %d 个自定义应用，同步间隔 %d 分钟）", len(out.WatchedAppIDs), len(out.CustomApps), out.SyncIntervalMinutes),
		clientIP,
		true,
	)
	return out.ToView(), newlyEnabled, nil
}

// UpsertCustomVulnApp adds or updates a custom GitHub repository or OSV package subscription.
func (s *Store) UpsertCustomVulnApp(app VulnCustomApp, clientIP string) (VulnCustomApp, VulnSettingsView, error) {
	app.Name = strings.TrimSpace(app.Name)
	app.Kind = strings.ToLower(strings.TrimSpace(app.Kind))
	app.Category = strings.TrimSpace(app.Category)
	if app.Category == "" {
		app.Category = "custom"
	}
	app.Repo = strings.Trim(strings.TrimSpace(app.Repo), "/")
	app.Ecosystem = strings.TrimSpace(app.Ecosystem)
	app.PackageName = strings.TrimSpace(app.PackageName)

	switch app.Kind {
	case "github_repo":
		// Accept either "owner/repo" or "https://github.com/owner/repo"
		if strings.HasPrefix(strings.ToLower(app.Repo), "http://") || strings.HasPrefix(strings.ToLower(app.Repo), "https://") {
			if u, err := url.Parse(app.Repo); err == nil {
				app.Repo = strings.Trim(strings.TrimSuffix(u.Path, ".git"), "/")
			}
		}
		parts := strings.Split(app.Repo, "/")
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
			return VulnCustomApp{}, VulnSettingsView{}, fmt.Errorf("%w: GitHub 仓库格式必须为 owner/repo（例如 alibaba/nacos）", ErrInvalidInput)
		}
		app.Repo = strings.TrimSpace(parts[0]) + "/" + strings.TrimSpace(parts[1])
		if app.Name == "" {
			app.Name = parts[1]
		}
		if app.ID == "" {
			app.ID = "custom-gh-" + sanitizeCustomSlug(app.Repo)
		}
	case "osv_package":
		if app.Ecosystem == "" || app.PackageName == "" {
			return VulnCustomApp{}, VulnSettingsView{}, fmt.Errorf("%w: OSV 生态名与包名均不能为空（例如 Go + github.com/gin-gonic/gin）", ErrInvalidInput)
		}
		if app.Name == "" {
			app.Name = app.PackageName
		}
		if app.ID == "" {
			app.ID = "custom-osv-" + sanitizeCustomSlug(app.Ecosystem+"-"+app.PackageName)
		}
	default:
		return VulnCustomApp{}, VulnSettingsView{}, fmt.Errorf("%w: 不支持的自定义应用类型（仅支持 github_repo 或 osv_package）", ErrInvalidInput)
	}

	if app.CreatedAt.IsZero() {
		app.CreatedAt = time.Now().UTC()
	}

	var saved VulnCustomApp
	var outView VulnSettingsView
	err := s.mutateSecrets(func(sec *SecretsState) error {
		cur := NormalizeVulnSettings(sec.VulnSettings)
		updated := false
		for i := range cur.CustomApps {
			if cur.CustomApps[i].ID == app.ID {
				app.CreatedAt = cur.CustomApps[i].CreatedAt
				cur.CustomApps[i] = app
				updated = true
				break
			}
		}
		if !updated {
			if len(cur.CustomApps) >= 60 {
				return fmt.Errorf("%w: 自定义监看应用数量已达上限（60 个）", ErrInvalidInput)
			}
			cur.CustomApps = append(cur.CustomApps, app)
		}
		cur.Initialized = true
		sec.VulnSettings = NormalizeVulnSettings(cur)
		saved = app
		outView = sec.VulnSettings.ToView()
		return nil
	})
	if err != nil {
		return VulnCustomApp{}, VulnSettingsView{}, err
	}
	s.RecordAudit("vuln.custom_app.upsert", saved.Name, fmt.Sprintf("保存自定义漏洞监看应用 (%s)", saved.ID), clientIP, true)
	return saved, outView, nil
}

// DeleteCustomVulnApp removes a user-defined vulnerability subscription.
func (s *Store) DeleteCustomVulnApp(id, clientIP string) (VulnSettingsView, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return VulnSettingsView{}, ErrInvalidInput
	}
	var deletedName string
	var outView VulnSettingsView
	err := s.mutateSecrets(func(sec *SecretsState) error {
		cur := NormalizeVulnSettings(sec.VulnSettings)
		for i, ca := range cur.CustomApps {
			if ca.ID == id {
				deletedName = ca.Name
				cur.CustomApps = slices.Delete(cur.CustomApps, i, i+1)
				cur.Initialized = true
				sec.VulnSettings = NormalizeVulnSettings(cur)
				outView = sec.VulnSettings.ToView()
				return nil
			}
		}
		return ErrNotFound
	})
	if err != nil {
		return VulnSettingsView{}, err
	}
	s.RecordAudit("vuln.custom_app.delete", deletedName, fmt.Sprintf("删除自定义漏洞监看应用 (%s)", id), clientIP, true)
	return outView, nil
}

// GetVulnRuntimeSnapshot returns a deep copy of the current vulnerability runtime state with hydrated user flags.
func (s *Store) GetVulnRuntimeSnapshot() *VulnRuntimeState {
	s.rtMu.RLock()
	defer s.rtMu.RUnlock()
	if s.vulnRT == nil {
		return DefaultVulnRuntimeState()
	}
	cp := cloneVulnRuntimeState(s.vulnRT)
	hydrateAdvisoryRuntimeFields(cp, time.Now().UTC())
	return cp
}

// GetVulnAdvisory returns a single hydrated advisory by canonical ID.
func (s *Store) GetVulnAdvisory(id string) (*VulnAdvisory, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, ErrNotFound
	}
	s.rtMu.RLock()
	defer s.rtMu.RUnlock()
	if s.vulnRT == nil {
		return nil, ErrNotFound
	}
	now := time.Now().UTC()
	for _, adv := range s.vulnRT.Advisories {
		if strings.EqualFold(adv.ID, id) {
			cp := cloneVulnAdvisory(adv)
			applySingleAdvisoryHydration(&cp, s.vulnRT, now)
			return &cp, nil
		}
	}
	return nil, ErrNotFound
}

// SaveVulnSyncResults merges freshly fetched advisories into vuln_runtime.json, updates source status,
// prunes old entries beyond retention/cap, and returns the slice of newly discovered advisories.
func (s *Store) SaveVulnSyncResults(
	mergedAdvisories []VulnAdvisory,
	sourceStatus []VulnSourceStatus,
	syncErr string,
	retentionDays int,
	maxRecords int,
) (newlyAdded []VulnAdvisory, isFirstSync bool) {
	if retentionDays <= 0 {
		retentionDays = 90
	}
	if maxRecords <= 0 {
		maxRecords = 3000
	}
	now := time.Now().UTC()

	s.rtMu.Lock()
	if s.vulnRT == nil {
		s.vulnRT = DefaultVulnRuntimeState()
	}
	ensureVulnRuntimeDefaults(s.vulnRT)
	isFirstSync = s.vulnRT.LastSyncAt == nil

	existingByID := make(map[string]VulnAdvisory, len(s.vulnRT.Advisories))
	for _, a := range s.vulnRT.Advisories {
		existingByID[strings.ToUpper(a.ID)] = a
	}

	// Merge incoming advisories into existing store map while preserving FirstSeenAt for known entries.
	for _, inc := range mergedAdvisories {
		key := strings.ToUpper(strings.TrimSpace(inc.ID))
		if key == "" {
			continue
		}
		if prev, ok := existingByID[key]; ok {
			inc.FirstSeenAt = prev.FirstSeenAt
			if inc.FirstSeenAt.IsZero() {
				inc.FirstSeenAt = now
			}
			// Union app associations when doing partial/incremental sync so previously matched apps aren't lost.
			inc.AppIDs = mergeUniqueStrings(prev.AppIDs, inc.AppIDs)
			inc.AppNames = mergeUniqueStrings(prev.AppNames, inc.AppNames)
			inc.Categories = mergeUniqueStrings(prev.Categories, inc.Categories)
			inc.Sources = mergeUniqueStrings(prev.Sources, inc.Sources)
			inc.Aliases = mergeUniqueStrings(prev.Aliases, inc.Aliases)
			inc.FixedVersions = mergeUniqueStrings(prev.FixedVersions, inc.FixedVersions)
			if inc.FixedVersion == "" && prev.FixedVersion != "" {
				inc.FixedVersion = prev.FixedVersion
			}
			if !inc.HasFix && prev.HasFix {
				inc.HasFix = true
			}
			if inc.OfficialURL == "" && prev.OfficialURL != "" {
				inc.OfficialURL = prev.OfficialURL
			}
			if inc.Details == "" && prev.Details != "" {
				inc.Details = prev.Details
			}
			if !inc.IsKEV && prev.IsKEV {
				inc.IsKEV = true
				inc.KEVDateAdded = prev.KEVDateAdded
				inc.KEVDueDate = prev.KEVDueDate
				inc.KEVAction = prev.KEVAction
			}
			if inc.CVSSScore == 0 && prev.CVSSScore > 0 {
				inc.CVSSScore = prev.CVSSScore
				inc.CVSSVector = prev.CVSSVector
			}
			if VulnSeverityRank(prev.Severity) > VulnSeverityRank(inc.Severity) {
				inc.Severity = prev.Severity
			}
			inc.LastSyncedAt = now
			existingByID[key] = inc
		} else {
			if inc.FirstSeenAt.IsZero() {
				inc.FirstSeenAt = now
			}
			inc.LastSyncedAt = now
			existingByID[key] = inc
			newlyAdded = append(newlyAdded, cloneVulnAdvisory(inc))
		}
	}

	// Build sorted slice (newest ModifiedAt/PublishedAt first) and prune gently while keeping
	// at least the most recent advisories per app so quiet apps remain visible.
	all := make([]VulnAdvisory, 0, len(existingByID))
	for _, a := range existingByID {
		// Clear transient view fields before persisting
		a.IsRead = false
		a.IsStarred = false
		a.IsIgnored = false
		a.IsNew = false
		a.AIAnalysis = nil
		all = append(all, a)
	}
	sortAdvisoriesNewestFirst(all)

	cutoff := now.AddDate(0, 0, -retentionDays)
	perAppKept := make(map[string]int)
	pruned := make([]VulnAdvisory, 0, min(len(all), maxRecords))
	validIDs := make(map[string]struct{}, min(len(all), maxRecords))

	for _, a := range all {
		st := s.vulnRT.UserStates[a.ID]
		refTime := advisoryEffectiveTime(a)
		withinWindow := refTime.IsZero() || !refTime.Before(cutoff)
		needMinPerApp := false
		for _, appID := range a.AppIDs {
			if perAppKept[appID] < 12 {
				needMinPerApp = true
				break
			}
		}
		if !withinWindow && !st.Starred && !needMinPerApp {
			continue
		}
		pruned = append(pruned, a)
		validIDs[a.ID] = struct{}{}
		for _, appID := range a.AppIDs {
			perAppKept[appID]++
		}
		if len(pruned) >= maxRecords {
			break
		}
	}

	// Clean stale user state / AI analysis / notification keys for pruned advisories
	for k := range s.vulnRT.UserStates {
		if _, ok := validIDs[k]; !ok {
			delete(s.vulnRT.UserStates, k)
		}
	}
	for k := range s.vulnRT.AIAnalyses {
		if _, ok := validIDs[k]; !ok {
			delete(s.vulnRT.AIAnalyses, k)
		}
	}
	for k, ts := range s.vulnRT.NotifiedIDs {
		if now.Sub(ts) > 180*24*time.Hour {
			delete(s.vulnRT.NotifiedIDs, k)
		}
	}

	s.vulnRT.Advisories = pruned
	if sourceStatus != nil {
		// Merge or replace source statuses by ID so partial incremental syncs keep other source statuses visible.
		if len(s.vulnRT.SourceStatus) == 0 {
			s.vulnRT.SourceStatus = slices.Clone(sourceStatus)
		} else {
			byID := make(map[string]VulnSourceStatus, len(s.vulnRT.SourceStatus)+len(sourceStatus))
			order := make([]string, 0, len(s.vulnRT.SourceStatus)+len(sourceStatus))
			for _, st := range s.vulnRT.SourceStatus {
				byID[st.ID] = st
				order = append(order, st.ID)
			}
			for _, st := range sourceStatus {
				if _, exists := byID[st.ID]; !exists {
					order = append(order, st.ID)
				}
				byID[st.ID] = st
			}
			mergedStatus := make([]VulnSourceStatus, 0, len(order))
			for _, id := range order {
				mergedStatus = append(mergedStatus, byID[id])
			}
			s.vulnRT.SourceStatus = mergedStatus
		}
	}
	syncNow := now
	s.vulnRT.LastSyncAt = &syncNow
	s.vulnRT.LastSyncError = strings.TrimSpace(syncErr)
	s.vulnRT.LastNewCount = len(newlyAdded)
	s.dirtyVuln = true
	s.rtMu.Unlock()

	s.triggerFlush()
	return newlyAdded, isFirstSync
}

// MarkVulnNotified records notified advisory IDs so future syncs never resend duplicate webhooks.
func (s *Store) MarkVulnNotified(ids []string) {
	if len(ids) == 0 {
		return
	}
	now := time.Now().UTC()
	s.rtMu.Lock()
	if s.vulnRT == nil {
		s.vulnRT = DefaultVulnRuntimeState()
	}
	ensureVulnRuntimeDefaults(s.vulnRT)
	for _, id := range ids {
		if id != "" {
			s.vulnRT.NotifiedIDs[id] = now
		}
	}
	s.dirtyVuln = true
	s.rtMu.Unlock()
	s.triggerFlush()
}

// IsVulnNotified checks whether an advisory has already triggered a webhook notification.
func (s *Store) IsVulnNotified(id string) bool {
	s.rtMu.RLock()
	defer s.rtMu.RUnlock()
	if s.vulnRT == nil || s.vulnRT.NotifiedIDs == nil {
		return false
	}
	_, ok := s.vulnRT.NotifiedIDs[id]
	return ok
}

// SaveVulnAIAnalysis caches a generated Chinese explanation & remediation guide in vuln_runtime.json.
func (s *Store) SaveVulnAIAnalysis(advisoryID string, analysis VulnAIAnalysis) error {
	advisoryID = strings.TrimSpace(advisoryID)
	if advisoryID == "" {
		return ErrInvalidInput
	}
	s.rtMu.Lock()
	if s.vulnRT == nil {
		s.vulnRT = DefaultVulnRuntimeState()
	}
	ensureVulnRuntimeDefaults(s.vulnRT)
	// Resolve canonical casing if present
	canonical := advisoryID
	for _, a := range s.vulnRT.Advisories {
		if strings.EqualFold(a.ID, advisoryID) {
			canonical = a.ID
			break
		}
	}
	cp := analysis
	cp.FixStepsZH = slices.Clone(analysis.FixStepsZH)
	s.vulnRT.AIAnalyses[canonical] = cp
	s.dirtyVuln = true
	s.rtMu.Unlock()
	s.triggerFlush()
	return nil
}

// UpdateVulnUserStates updates read / starred / ignored flags for one or more advisory IDs.
func (s *Store) UpdateVulnUserStates(ids []string, read, starred, ignored *bool) int {
	if len(ids) == 0 {
		return 0
	}
	now := time.Now().UTC()
	updated := 0

	s.rtMu.Lock()
	if s.vulnRT == nil {
		s.vulnRT = DefaultVulnRuntimeState()
	}
	ensureVulnRuntimeDefaults(s.vulnRT)

	canonicalByLower := make(map[string]string, len(s.vulnRT.Advisories))
	for _, a := range s.vulnRT.Advisories {
		canonicalByLower[strings.ToLower(a.ID)] = a.ID
	}

	for _, rawID := range ids {
		trimmed := strings.TrimSpace(rawID)
		if trimmed == "" {
			continue
		}
		key := trimmed
		if canon, ok := canonicalByLower[strings.ToLower(trimmed)]; ok {
			key = canon
		}
		st := s.vulnRT.UserStates[key]
		if read != nil {
			st.Read = *read
		}
		if starred != nil {
			st.Starred = *starred
		}
		if ignored != nil {
			st.Ignored = *ignored
			if *ignored {
				st.Read = true
			}
		}
		st.UpdatedAt = now
		s.vulnRT.UserStates[key] = st
		updated++
	}
	if updated > 0 {
		s.dirtyVuln = true
	}
	s.rtMu.Unlock()

	if updated > 0 {
		s.triggerFlush()
	}
	return updated
}

// MarkAllVulnsRead marks all currently stored advisories as read via the ReadAllBefore watermark.
func (s *Store) MarkAllVulnsRead() time.Time {
	now := time.Now().UTC()
	s.rtMu.Lock()
	if s.vulnRT == nil {
		s.vulnRT = DefaultVulnRuntimeState()
	}
	ensureVulnRuntimeDefaults(s.vulnRT)
	ts := now
	s.vulnRT.ReadAllBefore = &ts
	for k, st := range s.vulnRT.UserStates {
		if !st.Read {
			st.Read = true
			st.UpdatedAt = now
			s.vulnRT.UserStates[k] = st
		}
	}
	s.dirtyVuln = true
	s.rtMu.Unlock()
	s.triggerFlush()
	return now
}

// CountUnreadHighVulns returns the count of unread Critical/High/KEV advisories matching currently watched apps.
// Used by /api/workspace/bootstrap to populate the sidebar badge in 1 RTT.
func (s *Store) CountUnreadHighVulns() int {
	cfg, err := s.GetVulnSettings()
	if err != nil {
		return 0
	}
	watched := cfg.ActiveWatchedAppSet()
	if len(watched) == 0 {
		return 0
	}
	s.rtMu.RLock()
	defer s.rtMu.RUnlock()
	if s.vulnRT == nil {
		return 0
	}
	now := time.Now().UTC()
	count := 0
	for _, adv := range s.vulnRT.Advisories {
		if !advisoryMatchesWatched(adv, watched) {
			continue
		}
		cp := adv
		applySingleAdvisoryHydration(&cp, s.vulnRT, now)
		if cp.IsRead || cp.IsIgnored {
			continue
		}
		if cp.Severity == VulnSeverityCritical || cp.Severity == VulnSeverityHigh || cp.IsKEV {
			count++
		}
	}
	return count
}

func advisoryMatchesWatched(adv VulnAdvisory, watched map[string]struct{}) bool {
	if len(watched) == 0 {
		return false
	}
	for _, appID := range adv.AppIDs {
		if _, ok := watched[appID]; ok {
			return true
		}
	}
	return false
}

func hydrateAdvisoryRuntimeFields(rt *VulnRuntimeState, now time.Time) {
	if rt == nil {
		return
	}
	for i := range rt.Advisories {
		applySingleAdvisoryHydration(&rt.Advisories[i], rt, now)
	}
}

func applySingleAdvisoryHydration(a *VulnAdvisory, rt *VulnRuntimeState, now time.Time) {
	if a == nil || rt == nil {
		return
	}
	st, hasState := rt.UserStates[a.ID]
	isRead := st.Read
	if !hasState && rt.ReadAllBefore != nil && !a.FirstSeenAt.IsZero() && !a.FirstSeenAt.After(*rt.ReadAllBefore) {
		isRead = true
	}
	a.IsRead = isRead
	a.IsStarred = st.Starred
	a.IsIgnored = st.Ignored
	a.IsNew = !a.IsRead && !a.IsIgnored && !a.FirstSeenAt.IsZero() && now.Sub(a.FirstSeenAt) <= 48*time.Hour
	if ai, ok := rt.AIAnalyses[a.ID]; ok {
		aiCp := ai
		aiCp.FixStepsZH = slices.Clone(ai.FixStepsZH)
		a.AIAnalysis = &aiCp
	}
}

func advisoryEffectiveTime(a VulnAdvisory) time.Time {
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

func sortAdvisoriesNewestFirst(list []VulnAdvisory) {
	sort.SliceStable(list, func(i, j int) bool {
		ti := advisoryEffectiveTime(list[i])
		tj := advisoryEffectiveTime(list[j])
		if !ti.Equal(tj) {
			return ti.After(tj)
		}
		ri := VulnSeverityRank(list[i].Severity)
		rj := VulnSeverityRank(list[j].Severity)
		if ri != rj {
			return ri > rj
		}
		return list[i].ID > list[j].ID
	})
}

func mergeUniqueStrings(a, b []string) []string {
	if len(a) == 0 && len(b) == 0 {
		return []string{}
	}
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

func sanitizeCustomSlug(raw string) string {
	low := strings.ToLower(strings.TrimSpace(raw))
	var b strings.Builder
	lastDash := false
	for _, r := range low {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastDash = false
		} else if !lastDash && b.Len() > 0 {
			b.WriteByte('-')
			lastDash = true
		}
		if b.Len() >= 48 {
			break
		}
	}
	return strings.Trim(b.String(), "-")
}

func validateProxyURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("%w: HTTP 代理地址格式无效，请填写如 http://127.0.0.1:7890", ErrInvalidInput)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https", "socks5", "socks5h":
		return nil
	default:
		return fmt.Errorf("%w: 代理协议仅支持 http://、https:// 或 socks5://", ErrInvalidInput)
	}
}

func validateWebhookURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("%w: Webhook 地址格式无效", ErrInvalidInput)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("%w: Webhook 地址必须以 http:// 或 https:// 开头", ErrInvalidInput)
	}
	return nil
}

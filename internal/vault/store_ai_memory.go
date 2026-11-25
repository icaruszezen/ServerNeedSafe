package vault

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	maxAIMemoryEntries = 400
	maxAgentsMDBytes   = 64 * 1024
)

var (
	rePEMBlock = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)
	reBearer   = regexp.MustCompile(`(?i)(Bearer\s+)[A-Za-z0-9._\-+/=]{16,}`)
	reAPIKey   = regexp.MustCompile(`\b(sk-(?:ant-|proj-)?[A-Za-z0-9_\-]{16,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})\b`)
	reKVSecret = regexp.MustCompile(`(?i)\b(password|passwd|passphrase|api_key|apikey|secret_key|access_token)\s*([:=])\s*(['"]?)([^\s'",;]{6,})(['"]?)`)
)

// RedactSensitiveText strips private keys, API tokens, and inline credential assignments before
// persisting any AI memory entry, HostMemory field, or AGENTS.md proposal inside vault.sns.
func RedactSensitiveText(raw string) string {
	if raw == "" {
		return ""
	}
	out := rePEMBlock.ReplaceAllString(raw, "[REDACTED_PRIVATE_KEY]")
	out = reBearer.ReplaceAllString(out, "${1}[REDACTED_TOKEN]")
	out = reAPIKey.ReplaceAllString(out, "[REDACTED_API_KEY]")
	out = reKVSecret.ReplaceAllString(out, "${1}${2}${3}[REDACTED]${5}")
	return out
}

// --- Global AGENTS.md Management ---

func (s *ClientVault) GetAgentsMD() (AgentsMDConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state == nil {
		return AgentsMDConfig{}, ErrVaultLocked
	}
	if !s.state.AISettings.AgentsMD.Initialized && s.state.AISettings.AgentsMD.Revision == 0 && s.state.AISettings.AgentsMD.Content == "" {
		return DefaultAgentsMDConfig(time.Now().UTC()), nil
	}
	return s.state.AISettings.AgentsMD, nil
}

func (s *ClientVault) UpdateAgentsMD(enabled bool, content string, resetDefault bool, clientIP string) (*AgentsMDConfig, error) {
	if len(content) > maxAgentsMDBytes {
		return nil, fmt.Errorf("%w: AGENTS.md 内容超过上限 (%d KB)", ErrInvalidInput, maxAgentsMDBytes/1024)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return nil, ErrVaultLocked
	}

	var out AgentsMDConfig
	err := s.mutateLocked(func(st *VaultState) error {
		EnsureStateDefaults(st)
		now := time.Now().UTC()
		cur := st.AISettings.AgentsMD
		nextContent := content
		if resetDefault {
			nextContent = DefaultAgentsMDTemplate()
			enabled = true
		} else {
			nextContent = RedactSensitiveText(strings.ReplaceAll(content, "\r\n", "\n"))
		}
		rev := cur.Revision + 1
		if rev < 1 {
			rev = 1
		}
		st.AISettings.AgentsMD = AgentsMDConfig{
			Enabled:     enabled,
			Content:     nextContent,
			Revision:    rev,
			Initialized: true,
			UpdatedAt:   now,
		}
		actionDetail := fmt.Sprintf("更新全局 AGENTS.md 规范 (启用=%v, 版本=v%d, %d 字符)", enabled, rev, len([]rune(nextContent)))
		if resetDefault {
			actionDetail = fmt.Sprintf("重置全局 AGENTS.md 为默认 SRE 运维模板 (版本=v%d)", rev)
		}
		appendAuditLocked(st, "ai.agents_md_update", "AGENTS.md", actionDetail, clientIP, true)
		out = st.AISettings.AgentsMD
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// ResolveAgentsMDProposal accepts (merges into global AGENTS.md) or dismisses an AI-generated revision proposal.
func (s *ClientVault) ResolveAgentsMDProposal(proposalID string, accept bool, clientIP string) (*AgentsMDConfig, *AIAgentsMDProposal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return nil, nil, ErrVaultLocked
	}

	var outCfg AgentsMDConfig
	var outProp AIAgentsMDProposal
	err := s.mutateLocked(func(st *VaultState) error {
		EnsureStateDefaults(st)
		si, pi := -1, -1
		for i := range st.AISessions {
			for j := range st.AISessions[i].AgentsMDProposals {
				if st.AISessions[i].AgentsMDProposals[j].ID == proposalID {
					si, pi = i, j
					break
				}
			}
			if si >= 0 {
				break
			}
		}
		if si < 0 {
			return ErrNotFound
		}

		prop := st.AISessions[si].AgentsMDProposals[pi]
		if prop.Status != "pending" {
			return fmt.Errorf("%w: 该 AGENTS.md 修订提案已处理 (%s)", ErrInvalidInput, prop.Status)
		}

		now := time.Now().UTC()
		prop.ResolvedAt = &now
		if !accept {
			prop.Status = "dismissed"
			st.AISessions[si].AgentsMDProposals[pi] = prop
			outCfg = st.AISettings.AgentsMD
			outProp = prop
			return nil
		}

		cleanContent := RedactSensitiveText(strings.ReplaceAll(prop.ProposedContent, "\r\n", "\n"))
		if len(cleanContent) > maxAgentsMDBytes {
			return fmt.Errorf("%w: 提议的 AGENTS.md 内容超过上限", ErrInvalidInput)
		}
		rev := st.AISettings.AgentsMD.Revision + 1
		if rev < 1 {
			rev = 1
		}
		st.AISettings.AgentsMD = AgentsMDConfig{
			Enabled:     true,
			Content:     cleanContent,
			Revision:    rev,
			Initialized: true,
			UpdatedAt:   now,
		}
		prop.Status = "accepted"
		st.AISessions[si].AgentsMDProposals[pi] = prop
		appendAuditLocked(st, "ai.agents_md_merge", "AGENTS.md", fmt.Sprintf("批准合入 AI 提议的 AGENTS.md 修订 (%s, v%d)", prop.Summary, rev), clientIP, true)
		outCfg = st.AISettings.AgentsMD
		outProp = prop
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return &outCfg, &outProp, nil
}

// --- Memory & Context Budget Config ---

func (s *ClientVault) GetAIMemoryConfig() (AIMemoryConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state == nil {
		return AIMemoryConfig{}, ErrVaultLocked
	}
	if !s.state.AISettings.MemoryConfig.Initialized && s.state.AISettings.MemoryConfig.AgentsMDMaxChars == 0 {
		return DefaultAIMemoryConfig(), nil
	}
	return SanitizeAIMemoryConfig(s.state.AISettings.MemoryConfig), nil
}

func (s *ClientVault) UpdateAIMemoryConfig(in AIMemoryConfig, clientIP string) (*AIMemoryConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return nil, ErrVaultLocked
	}
	var out AIMemoryConfig
	err := s.mutateLocked(func(st *VaultState) error {
		EnsureStateDefaults(st)
		clean := SanitizeAIMemoryConfig(in)
		st.AISettings.MemoryConfig = clean
		appendAuditLocked(st, "ai.memory_config", "memory", fmt.Sprintf("更新 AI 记忆与上下文预算配置 (AGENTS预算=%d, 记忆预算=%d, 压缩阈值=%.0f%%)", clean.AgentsMDMaxChars, clean.MemoryPromptBudgetChars, clean.CompactionTriggerRatio*100), clientIP, true)
		out = clean
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// --- Long-Term Cross-Session Memory Entries (AIMemoryEntry) ---

func normalizeMemoryCategory(cat string) string {
	switch strings.ToLower(strings.TrimSpace(cat)) {
	case "preference", "偏好", "管理员偏好":
		return "preference"
	case "topology", "拓扑", "架构拓扑":
		return "topology"
	case "incident", "故障", "故障根因":
		return "incident"
	case "change", "变更", "重要变更":
		return "change"
	case "lesson", "经验", "运维经验":
		return "lesson"
	default:
		return "lesson"
	}
}

func normalizeMemoryScope(scope string, serverIDs []string) string {
	sc := strings.ToLower(strings.TrimSpace(scope))
	if sc == "server" && len(serverIDs) > 0 {
		return "server"
	}
	if sc == "" && len(serverIDs) > 0 {
		return "server"
	}
	return "global"
}

func cloneMemoryEntry(m AIMemoryEntry) AIMemoryEntry {
	cp := m
	cp.ServerIDs = slices.Clone(m.ServerIDs)
	if cp.ServerIDs == nil {
		cp.ServerIDs = []string{}
	}
	cp.Tags = slices.Clone(m.Tags)
	if cp.Tags == nil {
		cp.Tags = []string{}
	}
	if m.LastUsedAt != nil {
		t := *m.LastUsedAt
		cp.LastUsedAt = &t
	}
	return cp
}

func (s *ClientVault) ListAIMemories() ([]AIMemoryEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state == nil {
		return nil, ErrVaultLocked
	}
	out := make([]AIMemoryEntry, len(s.state.AIMemories))
	for i, m := range s.state.AIMemories {
		out[i] = cloneMemoryEntry(m)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Pinned != out[j].Pinned {
			return out[i].Pinned
		}
		if out[i].Importance != out[j].Importance {
			return out[i].Importance > out[j].Importance
		}
		return out[i].UpdatedAt.After(out[j].UpdatedAt)
	})
	return out, nil
}

func (s *ClientVault) UpsertAIMemory(in AIMemoryEntry, isAuto bool, clientIP string) (*AIMemoryEntry, error) {
	cleanTitle := RedactSensitiveText(strings.TrimSpace(in.Title))
	cleanContent := RedactSensitiveText(strings.TrimSpace(in.Content))
	if cleanTitle == "" || cleanContent == "" {
		return nil, fmt.Errorf("%w: 记忆标题与内容不能为空", ErrInvalidInput)
	}
	if len(cleanContent) > 8000 {
		cleanContent = cleanContent[:8000]
	}

	dedupClean := func(items []string) []string {
		out := make([]string, 0, len(items))
		for _, item := range items {
			t := RedactSensitiveText(strings.TrimSpace(item))
			if t != "" && !slices.Contains(out, t) {
				out = append(out, t)
			}
		}
		return out
	}

	serverIDs := dedupClean(in.ServerIDs)
	tags := dedupClean(in.Tags)
	scope := normalizeMemoryScope(in.Scope, serverIDs)
	if scope == "global" {
		serverIDs = []string{}
	}
	cat := normalizeMemoryCategory(in.Category)
	imp := in.Importance
	if imp < 1 || imp > 5 {
		imp = 3
	}
	source := strings.TrimSpace(in.Source)
	if source == "" {
		if isAuto {
			source = "ai"
		} else {
			source = "manual"
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return nil, ErrVaultLocked
	}

	var outEntry AIMemoryEntry
	err := s.mutateLocked(func(st *VaultState) error {
		EnsureStateDefaults(st)
		now := time.Now().UTC()

		// 1. Match by explicit ID
		matchIdx := -1
		if strings.TrimSpace(in.ID) != "" {
			for i := range st.AIMemories {
				if st.AIMemories[i].ID == in.ID {
					matchIdx = i
					break
				}
			}
		}

		// 2. For auto saves, deduplicate by normalized (scope, category, title, server_ids)
		if matchIdx < 0 && isAuto {
			normTitle := strings.ToLower(cleanTitle)
			sortedSids := slices.Clone(serverIDs)
			slices.Sort(sortedSids)
			for i := range st.AIMemories {
				ex := st.AIMemories[i]
				if ex.Scope == scope && ex.Category == cat && strings.ToLower(strings.TrimSpace(ex.Title)) == normTitle {
					exSids := slices.Clone(ex.ServerIDs)
					slices.Sort(exSids)
					if slices.Equal(exSids, sortedSids) {
						matchIdx = i
						break
					}
				}
			}
		}

		if matchIdx >= 0 {
			cur := st.AIMemories[matchIdx]
			cur.Scope = scope
			cur.ServerIDs = serverIDs
			cur.Category = cat
			cur.Title = cleanTitle
			cur.Content = cleanContent
			if isAuto {
				cur.Tags = dedupClean(append(cur.Tags, tags...))
				if imp > cur.Importance {
					cur.Importance = imp
				}
				if in.Pinned {
					cur.Pinned = true
				}
			} else {
				cur.Tags = tags
				cur.Importance = imp
				cur.Pinned = in.Pinned
			}
			if in.SourceSessionID != "" {
				cur.SourceSessionID = in.SourceSessionID
			}
			cur.UpdatedAt = now
			st.AIMemories[matchIdx] = cur
			if !isAuto {
				appendAuditLocked(st, "ai.long_memory_edit", cur.Title, fmt.Sprintf("编辑长期记忆 [%s/%s]", cur.Scope, cur.Category), clientIP, true)
			}
			outEntry = cloneMemoryEntry(cur)
			return nil
		}

		created := AIMemoryEntry{
			ID:              uuid.NewString(),
			Scope:           scope,
			ServerIDs:       serverIDs,
			Category:        cat,
			Title:           cleanTitle,
			Content:         cleanContent,
			Tags:            tags,
			Pinned:          in.Pinned,
			Importance:      imp,
			Source:          source,
			SourceSessionID: in.SourceSessionID,
			UseCount:        0,
			CreatedAt:       now,
			UpdatedAt:       now,
		}
		st.AIMemories = append([]AIMemoryEntry{created}, st.AIMemories...)

		// Enforce bounded memory size by evicting lowest-priority unpinned oldest entries
		if len(st.AIMemories) > maxAIMemoryEntries {
			evictIdx := -1
			for i := len(st.AIMemories) - 1; i >= 0; i-- {
				if !st.AIMemories[i].Pinned {
					if evictIdx < 0 || st.AIMemories[i].Importance < st.AIMemories[evictIdx].Importance {
						evictIdx = i
					}
				}
			}
			if evictIdx >= 0 {
				st.AIMemories = slices.Delete(st.AIMemories, evictIdx, evictIdx+1)
			}
		}

		if !isAuto {
			appendAuditLocked(st, "ai.long_memory_create", created.Title, fmt.Sprintf("新增长期记忆 [%s/%s]", created.Scope, created.Category), clientIP, true)
		}
		outEntry = cloneMemoryEntry(created)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &outEntry, nil
}

func (s *ClientVault) DeleteAIMemory(id, clientIP string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return ErrVaultLocked
	}
	return s.mutateLocked(func(st *VaultState) error {
		for i, m := range st.AIMemories {
			if m.ID == id {
				st.AIMemories = slices.Delete(st.AIMemories, i, i+1)
				appendAuditLocked(st, "ai.long_memory_delete", m.Title, "删除 AI 长期记忆条目", clientIP, true)
				return nil
			}
		}
		return ErrNotFound
	})
}

// TouchAIMemoryUsage increments in-memory usage counters without triggering an extra disk seal;
// updated counters will naturally persist on the next vault write.
func (s *ClientVault) TouchAIMemoryUsage(ids []string) {
	if len(ids) == 0 {
		return
	}
	idSet := make(map[string]bool, len(ids))
	for _, id := range ids {
		if id != "" {
			idSet[id] = true
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return
	}
	now := time.Now().UTC()
	for i := range s.state.AIMemories {
		if idSet[s.state.AIMemories[i].ID] {
			s.state.AIMemories[i].UseCount++
			t := now
			s.state.AIMemories[i].LastUsedAt = &t
		}
	}
}

// --- Monitor Snapshot <-> HostMemory Objective Fact Sync & Live Context Lookup ---

// mergeMonitorSnapshotIntoHostMemoryLocked merges objective telemetry facts (OS/Kernel/Arch,
// active services/containers, listening ports) from a reachable ServerMonitorSnapshot into HostMemory.
// It NEVER overwrites human-authored Summary, DeployPaths, Constraints, or Notes.
// Returns true if HostMemory was created or meaningfully modified.
func mergeMonitorSnapshotIntoHostMemoryLocked(st *VaultState, snap *ServerMonitorSnapshot, now time.Time) bool {
	if st == nil || snap == nil || !snap.Reachable || snap.ServerID == "" {
		return false
	}

	osArch := formatSnapshotOSArch(snap)
	services := extractSnapshotServices(snap)
	portsNote := formatSnapshotPortsNote(snap)

	if osArch == "" && len(services) == 0 && portsNote == "" {
		return false
	}

	for i := range st.HostMemories {
		if st.HostMemories[i].ServerID == snap.ServerID {
			cur := st.HostMemories[i]
			changed := false

			if snap.ServerName != "" && cur.ServerName != snap.ServerName {
				cur.ServerName = snap.ServerName
				changed = true
			}
			if osArch != "" && cur.OSArch != osArch {
				cur.OSArch = osArch
				changed = true
			}
			for _, svc := range services {
				if !slices.Contains(cur.KeyServices, svc) {
					cur.KeyServices = append(cur.KeyServices, svc)
					changed = true
				}
			}
			if portsNote != "" && (cur.PortsNote == "" || strings.HasPrefix(cur.PortsNote, "[监控同步] ")) {
				tagged := "[监控同步] " + portsNote
				if cur.PortsNote != tagged {
					cur.PortsNote = tagged
					changed = true
				}
			}
			if cur.Summary == "" && osArch != "" {
				cur.Summary = fmt.Sprintf("%s 受管服务器（由 7×24 监控自动建立初始画像）", osArch)
				changed = true
			}
			if changed || cur.MonitorSyncedAt == nil {
				t := now
				cur.MonitorSyncedAt = &t
				if changed {
					cur.UpdatedAt = now
				}
				st.HostMemories[i] = cur
				return true
			}
			return false
		}
	}

	// Create an initial objective HostMemory entry from the monitor snapshot
	summary := "受管 Linux 服务器（由 7×24 监控自动建立初始画像）"
	if osArch != "" {
		summary = fmt.Sprintf("%s 节点（由 7×24 监控自动建立初始画像）", osArch)
	}
	taggedPorts := ""
	if portsNote != "" {
		taggedPorts = "[监控同步] " + portsNote
	}
	t := now
	st.HostMemories = append(st.HostMemories, HostMemory{
		ServerID:        snap.ServerID,
		ServerName:      snap.ServerName,
		Summary:         summary,
		OSArch:          osArch,
		KeyServices:     services,
		DeployPaths:     []string{},
		PortsNote:       taggedPorts,
		MonitorSyncedAt: &t,
		UpdatedAt:       now,
	})
	return true
}

func formatSnapshotOSArch(snap *ServerMonitorSnapshot) string {
	parts := make([]string, 0, 3)
	if s := strings.TrimSpace(snap.OS); s != "" {
		parts = append(parts, s)
	}
	if k := strings.TrimSpace(snap.Kernel); k != "" {
		parts = append(parts, "Linux "+k)
	}
	if a := strings.TrimSpace(snap.Arch); a != "" {
		parts = append(parts, a)
	}
	return strings.Join(parts, " / ")
}

func extractSnapshotServices(snap *ServerMonitorSnapshot) []string {
	out := make([]string, 0, 12)
	add := func(name string) {
		n := strings.TrimSpace(strings.TrimSuffix(name, ".service"))
		if n != "" && !slices.Contains(out, n) && len(out) < 20 {
			out = append(out, n)
		}
	}
	for _, svc := range snap.Services {
		if svc.State == "active" || svc.Watched {
			add(svc.Name)
		}
	}
	if snap.Docker.Installed {
		add("docker")
		for _, c := range snap.Docker.Containers {
			if c.State == "running" {
				add("container:" + c.Name)
			}
		}
	}
	return out
}

func formatSnapshotPortsNote(snap *ServerMonitorSnapshot) string {
	if len(snap.ListeningPorts) == 0 {
		return ""
	}
	items := make([]string, 0, min(12, len(snap.ListeningPorts)))
	seen := make(map[string]bool)
	for _, lp := range snap.ListeningPorts {
		if lp.Port <= 0 {
			continue
		}
		proc := strings.TrimSpace(lp.Process)
		scope := "local"
		if lp.PublicExposed {
			scope = "public"
		}
		key := fmt.Sprintf("%d/%s", lp.Port, lp.Proto)
		if seen[key] {
			continue
		}
		seen[key] = true
		label := fmt.Sprintf("%d(%s", lp.Port, scope)
		if proc != "" {
			label += ":" + proc
		}
		label += ")"
		items = append(items, label)
		if len(items) >= 12 {
			break
		}
	}
	return strings.Join(items, ", ")
}

// SyncHostMemoriesFromMonitor manually synchronizes objective facts from the latest 7x24 monitor
// snapshots into HostMemory for a single server (if serverID != "") or all monitored servers.
func (s *ClientVault) SyncHostMemoriesFromMonitor(serverID, clientIP string) ([]HostMemory, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return nil, 0, ErrVaultLocked
	}

	syncedCount := 0
	var out []HostMemory
	err := s.mutateLocked(func(st *VaultState) error {
		EnsureStateDefaults(st)
		ensureMonitorInitialized(st)
		now := time.Now().UTC()
		for sid, snap := range st.Monitor.LatestSnapshots {
			if serverID != "" && sid != serverID {
				continue
			}
			if snap == nil || !snap.Reachable {
				continue
			}
			if mergeMonitorSnapshotIntoHostMemoryLocked(st, snap, now) {
				syncedCount++
			}
		}
		if syncedCount > 0 {
			target := "全部受管主机"
			if serverID != "" {
				target = serverID
				for _, srv := range st.Servers {
					if srv.ID == serverID {
						target = srv.Name
						break
					}
				}
			}
			appendAuditLocked(st, "ai.memory_monitor_sync", target, fmt.Sprintf("从 7×24 监控快照同步更新 %d 台主机画像", syncedCount), clientIP, true)
		}
		out = make([]HostMemory, len(st.HostMemories))
		for i, m := range st.HostMemories {
			cp := m
			cp.KeyServices = slices.Clone(m.KeyServices)
			cp.DeployPaths = slices.Clone(m.DeployPaths)
			if m.MonitorSyncedAt != nil {
				t := *m.MonitorSyncedAt
				cp.MonitorSyncedAt = &t
			}
			out[i] = cp
		}
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	return out, syncedCount, nil
}

// GetLatestMonitorContext returns cloned latest monitor snapshots and active firing alerts
// for the requested serverIDs (or all servers if serverIDs is empty).
func (s *ClientVault) GetLatestMonitorContext(serverIDs []string) (map[string]*ServerMonitorSnapshot, []MonitorAlert, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state == nil {
		return nil, nil, ErrVaultLocked
	}
	snaps := make(map[string]*ServerMonitorSnapshot)
	alerts := make([]MonitorAlert, 0)
	if s.state.Monitor == nil {
		return snaps, alerts, nil
	}

	filter := make(map[string]bool, len(serverIDs))
	for _, id := range serverIDs {
		filter[id] = true
	}

	for sid, snap := range s.state.Monitor.LatestSnapshots {
		if len(filter) > 0 && !filter[sid] {
			continue
		}
		if snap != nil {
			snaps[sid] = cloneSnapshot(snap)
		}
	}
	for _, al := range s.state.Monitor.Alerts {
		if al.Status != AlertStatusFiring {
			continue
		}
		if len(filter) > 0 && !filter[al.ServerID] {
			continue
		}
		alerts = append(alerts, al)
	}
	return snaps, alerts, nil
}

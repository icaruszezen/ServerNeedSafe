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
// persisting any AI memory entry, HostMemory field, or AGENTS.md proposal.
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

// --- Global AGENTS.md Management (stored in secrets.enc) ---

func (s *Store) GetAgentsMD() (AgentsMDConfig, error) {
	s.secMu.RLock()
	defer s.secMu.RUnlock()
	if s.secrets == nil {
		return AgentsMDConfig{}, ErrVaultLocked
	}
	if !s.secrets.AISettings.AgentsMD.Initialized && s.secrets.AISettings.AgentsMD.Revision == 0 && s.secrets.AISettings.AgentsMD.Content == "" {
		return DefaultAgentsMDConfig(time.Now().UTC()), nil
	}
	return s.secrets.AISettings.AgentsMD, nil
}

func (s *Store) UpdateAgentsMD(enabled bool, content string, resetDefault bool, clientIP string) (*AgentsMDConfig, error) {
	if len(content) > maxAgentsMDBytes {
		return nil, fmt.Errorf("%w: AGENTS.md 内容超过上限 (%d KB)", ErrInvalidInput, maxAgentsMDBytes/1024)
	}

	var out AgentsMDConfig
	var actionDetail string
	err := s.mutateSecrets(func(sec *SecretsState) error {
		now := time.Now().UTC()
		cur := sec.AISettings.AgentsMD
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
		sec.AISettings.AgentsMD = AgentsMDConfig{
			Enabled:     enabled,
			Content:     nextContent,
			Revision:    rev,
			Initialized: true,
			UpdatedAt:   now,
		}
		actionDetail = fmt.Sprintf("更新全局 AGENTS.md 规范 (启用=%v, 版本=v%d, %d 字符)", enabled, rev, len([]rune(nextContent)))
		if resetDefault {
			actionDetail = fmt.Sprintf("重置全局 AGENTS.md 为默认 SRE 运维模板 (版本=v%d)", rev)
		}
		out = sec.AISettings.AgentsMD
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.RecordAudit("ai.agents_md_update", "AGENTS.md", actionDetail, clientIP, true)
	return &out, nil
}

// ResolveAgentsMDProposal accepts (merges into global AGENTS.md) or dismisses an AI-generated revision proposal.
func (s *Store) ResolveAgentsMDProposal(proposalID string, accept bool, clientIP string) (*AgentsMDConfig, *AIAgentsMDProposal, error) {
	if !s.IsReady() {
		return nil, nil, ErrVaultLocked
	}

	// Step 1: Read pending proposal under rtMu.RLock
	s.rtMu.RLock()
	var prop AIAgentsMDProposal
	found := false
	if s.aiopsRT != nil {
		for _, cs := range s.aiopsRT.AISessions {
			for _, ap := range cs.AgentsMDProposals {
				if ap.ID == proposalID {
					prop = ap
					found = true
					break
				}
			}
			if found {
				break
			}
		}
	}
	s.rtMu.RUnlock()
	if !found {
		return nil, nil, ErrNotFound
	}
	if prop.Status != "pending" {
		return nil, nil, fmt.Errorf("%w: 该 AGENTS.md 修订提案已处理 (%s)", ErrInvalidInput, prop.Status)
	}

	now := time.Now().UTC()
	var outCfg AgentsMDConfig
	if accept {
		cleanContent := RedactSensitiveText(strings.ReplaceAll(prop.ProposedContent, "\r\n", "\n"))
		if len(cleanContent) > maxAgentsMDBytes {
			return nil, nil, fmt.Errorf("%w: 提议的 AGENTS.md 内容超过上限", ErrInvalidInput)
		}
		err := s.mutateSecrets(func(sec *SecretsState) error {
			rev := sec.AISettings.AgentsMD.Revision + 1
			if rev < 1 {
				rev = 1
			}
			sec.AISettings.AgentsMD = AgentsMDConfig{
				Enabled:     true,
				Content:     cleanContent,
				Revision:    rev,
				Initialized: true,
				UpdatedAt:   now,
			}
			outCfg = sec.AISettings.AgentsMD
			return nil
		})
		if err != nil {
			return nil, nil, err
		}
	} else {
		cfg, err := s.GetAgentsMD()
		if err != nil {
			return nil, nil, err
		}
		outCfg = cfg
	}

	// Step 2: Update proposal status in aiopsRT
	var outProp AIAgentsMDProposal
	s.rtMu.Lock()
	si, pi := -1, -1
	for i := range s.aiopsRT.AISessions {
		for j := range s.aiopsRT.AISessions[i].AgentsMDProposals {
			if s.aiopsRT.AISessions[i].AgentsMDProposals[j].ID == proposalID {
				si, pi = i, j
				break
			}
		}
		if si >= 0 {
			break
		}
	}
	if si < 0 {
		s.rtMu.Unlock()
		return nil, nil, ErrNotFound
	}
	p := s.aiopsRT.AISessions[si].AgentsMDProposals[pi]
	p.ResolvedAt = &now
	if accept {
		p.Status = "accepted"
		s.appendAuditRuntimeLocked("ai.agents_md_merge", "AGENTS.md", fmt.Sprintf("批准合入 AI 提议的 AGENTS.md 修订 (%s, v%d)", p.Summary, outCfg.Revision), clientIP, true)
	} else {
		p.Status = "dismissed"
	}
	s.aiopsRT.AISessions[si].AgentsMDProposals[pi] = p
	s.dirtyAIOps = true
	outProp = p
	s.rtMu.Unlock()
	s.triggerFlush()
	return &outCfg, &outProp, nil
}

// --- Memory & Context Budget Config (stored in secrets.enc) ---

func (s *Store) GetAIMemoryConfig() (AIMemoryConfig, error) {
	s.secMu.RLock()
	defer s.secMu.RUnlock()
	if s.secrets == nil {
		return AIMemoryConfig{}, ErrVaultLocked
	}
	if !s.secrets.AISettings.MemoryConfig.Initialized && s.secrets.AISettings.MemoryConfig.AgentsMDMaxChars == 0 {
		return DefaultAIMemoryConfig(), nil
	}
	return SanitizeAIMemoryConfig(s.secrets.AISettings.MemoryConfig), nil
}

func (s *Store) UpdateAIMemoryConfig(in AIMemoryConfig, clientIP string) (*AIMemoryConfig, error) {
	var out AIMemoryConfig
	err := s.mutateSecrets(func(sec *SecretsState) error {
		clean := SanitizeAIMemoryConfig(in)
		sec.AISettings.MemoryConfig = clean
		out = clean
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.RecordAudit("ai.memory_config", "memory", fmt.Sprintf("更新 AI 记忆与上下文预算配置 (AGENTS预算=%d, 记忆预算=%d, 压缩阈值=%.0f%%)", out.AgentsMDMaxChars, out.MemoryPromptBudgetChars, out.CompactionTriggerRatio*100), clientIP, true)
	return &out, nil
}

// --- Long-Term Cross-Session Memory Entries (stored in aiops_runtime.json) ---

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

func (s *Store) ListAIMemories() ([]AIMemoryEntry, error) {
	if !s.IsReady() {
		return nil, ErrVaultLocked
	}
	s.rtMu.RLock()
	defer s.rtMu.RUnlock()
	if s.aiopsRT == nil {
		return []AIMemoryEntry{}, nil
	}
	out := make([]AIMemoryEntry, len(s.aiopsRT.AIMemories))
	for i, m := range s.aiopsRT.AIMemories {
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

func (s *Store) UpsertAIMemory(in AIMemoryEntry, isAuto bool, clientIP string) (*AIMemoryEntry, error) {
	if !s.IsReady() {
		return nil, ErrVaultLocked
	}
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

	now := time.Now().UTC()
	var outEntry AIMemoryEntry

	s.rtMu.Lock()
	if s.aiopsRT == nil {
		s.aiopsRT = DefaultAIOpsRuntimeState(now)
	}

	matchIdx := -1
	if strings.TrimSpace(in.ID) != "" {
		for i := range s.aiopsRT.AIMemories {
			if s.aiopsRT.AIMemories[i].ID == in.ID {
				matchIdx = i
				break
			}
		}
	}
	if matchIdx < 0 && isAuto {
		normTitle := strings.ToLower(cleanTitle)
		sortedSids := slices.Clone(serverIDs)
		slices.Sort(sortedSids)
		for i := range s.aiopsRT.AIMemories {
			ex := s.aiopsRT.AIMemories[i]
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
		cur := s.aiopsRT.AIMemories[matchIdx]
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
		s.aiopsRT.AIMemories[matchIdx] = cur
		if !isAuto {
			s.appendAuditRuntimeLocked("ai.long_memory_edit", cur.Title, fmt.Sprintf("编辑长期记忆 [%s/%s]", cur.Scope, cur.Category), clientIP, true)
		}
		outEntry = cloneMemoryEntry(cur)
	} else {
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
		s.aiopsRT.AIMemories = append([]AIMemoryEntry{created}, s.aiopsRT.AIMemories...)

		if len(s.aiopsRT.AIMemories) > maxAIMemoryEntries {
			evictIdx := -1
			for i := len(s.aiopsRT.AIMemories) - 1; i >= 0; i-- {
				if !s.aiopsRT.AIMemories[i].Pinned {
					if evictIdx < 0 || s.aiopsRT.AIMemories[i].Importance < s.aiopsRT.AIMemories[evictIdx].Importance {
						evictIdx = i
					}
				}
			}
			if evictIdx >= 0 {
				s.aiopsRT.AIMemories = slices.Delete(s.aiopsRT.AIMemories, evictIdx, evictIdx+1)
			}
		}

		if !isAuto {
			s.appendAuditRuntimeLocked("ai.long_memory_create", created.Title, fmt.Sprintf("新增长期记忆 [%s/%s]", created.Scope, created.Category), clientIP, true)
		}
		outEntry = cloneMemoryEntry(created)
	}
	s.dirtyAIOps = true
	s.rtMu.Unlock()
	s.triggerFlush()
	return &outEntry, nil
}

func (s *Store) DeleteAIMemory(id, clientIP string) error {
	if !s.IsReady() {
		return ErrVaultLocked
	}
	s.rtMu.Lock()
	if s.aiopsRT == nil {
		s.rtMu.Unlock()
		return ErrNotFound
	}
	for i, m := range s.aiopsRT.AIMemories {
		if m.ID == id {
			s.aiopsRT.AIMemories = slices.Delete(s.aiopsRT.AIMemories, i, i+1)
			s.dirtyAIOps = true
			s.appendAuditRuntimeLocked("ai.long_memory_delete", m.Title, "删除 AI 长期记忆条目", clientIP, true)
			s.rtMu.Unlock()
			s.triggerFlush()
			return nil
		}
	}
	s.rtMu.Unlock()
	return ErrNotFound
}

// TouchAIMemoryUsage increments usage counters in runtime state and marks aiops_runtime.json dirty.
func (s *Store) TouchAIMemoryUsage(ids []string) {
	if len(ids) == 0 || !s.IsReady() {
		return
	}
	idSet := make(map[string]bool, len(ids))
	for _, id := range ids {
		if id != "" {
			idSet[id] = true
		}
	}
	s.rtMu.Lock()
	if s.aiopsRT != nil {
		now := time.Now().UTC()
		changed := false
		for i := range s.aiopsRT.AIMemories {
			if idSet[s.aiopsRT.AIMemories[i].ID] {
				s.aiopsRT.AIMemories[i].UseCount++
				t := now
				s.aiopsRT.AIMemories[i].LastUsedAt = &t
				changed = true
			}
		}
		if changed {
			s.dirtyAIOps = true
		}
	}
	s.rtMu.Unlock()
	s.triggerFlush()
}

// --- Monitor Snapshot <-> HostMemory Objective Fact Sync & Live Context Lookup ---

func mergeMonitorSnapshotIntoHostMemorySlice(memories *[]HostMemory, snap *ServerMonitorSnapshot, now time.Time) bool {
	if memories == nil || snap == nil || !snap.Reachable || snap.ServerID == "" {
		return false
	}

	osArch := formatSnapshotOSArch(snap)
	services := extractSnapshotServices(snap)
	portsNote := formatSnapshotPortsNote(snap)

	if osArch == "" && len(services) == 0 && portsNote == "" {
		return false
	}

	list := *memories
	for i := range list {
		if list[i].ServerID == snap.ServerID {
			cur := list[i]
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
				list[i] = cur
				*memories = list
				return true
			}
			return false
		}
	}

	summary := "受管 Linux 服务器（由 7×24 监控自动建立初始画像）"
	if osArch != "" {
		summary = fmt.Sprintf("%s 节点（由 7×24 监控自动建立初始画像）", osArch)
	}
	taggedPorts := ""
	if portsNote != "" {
		taggedPorts = "[监控同步] " + portsNote
	}
	t := now
	*memories = append(list, HostMemory{
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
	osStr := strings.TrimSpace(snap.OS)
	if osStr != "" {
		parts = append(parts, osStr)
	}
	if k := strings.TrimSpace(snap.Kernel); k != "" {
		lowOS := strings.ToLower(osStr)
		kernelPrefix := "Linux "
		if strings.Contains(lowOS, "macos") || strings.Contains(lowOS, "darwin") {
			kernelPrefix = "Darwin "
		}
		parts = append(parts, kernelPrefix+k)
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

// SyncHostMemoriesFromMonitor synchronizes objective facts from the latest 7x24 monitor snapshots into HostMemory.
func (s *Store) SyncHostMemoriesFromMonitor(serverID, clientIP string) ([]HostMemory, int, error) {
	s.secMu.RLock()
	if s.secrets == nil {
		s.secMu.RUnlock()
		return nil, 0, ErrVaultLocked
	}
	targetName := "全部受管主机"
	if serverID != "" {
		targetName = serverID
		for _, srv := range s.secrets.Servers {
			if srv.ID == serverID {
				targetName = srv.Name
				break
			}
		}
	}
	s.secMu.RUnlock()

	now := time.Now().UTC()
	syncedCount := 0

	s.rtMu.Lock()
	if s.monitorRT == nil {
		s.monitorRT = DefaultMonitorRuntimeState()
	}
	if s.aiopsRT == nil {
		s.aiopsRT = DefaultAIOpsRuntimeState(now)
	}
	for sid, snap := range s.monitorRT.LatestSnapshots {
		if serverID != "" && sid != serverID {
			continue
		}
		if snap == nil || !snap.Reachable {
			continue
		}
		if mergeMonitorSnapshotIntoHostMemorySlice(&s.aiopsRT.HostMemories, snap, now) {
			syncedCount++
		}
	}
	if syncedCount > 0 {
		s.dirtyAIOps = true
		s.appendAuditRuntimeLocked("ai.memory_monitor_sync", targetName, fmt.Sprintf("从 7×24 监控快照同步更新 %d 台主机画像", syncedCount), clientIP, true)
	}
	out := cloneHostMemories(s.aiopsRT.HostMemories)
	s.rtMu.Unlock()
	if syncedCount > 0 {
		s.triggerFlush()
	}
	return out, syncedCount, nil
}

// GetLatestMonitorContext returns cloned latest monitor snapshots and active firing alerts
// for the requested serverIDs (or all servers if serverIDs is empty).
func (s *Store) GetLatestMonitorContext(serverIDs []string) (map[string]*ServerMonitorSnapshot, []MonitorAlert, error) {
	if !s.IsReady() {
		return nil, nil, ErrVaultLocked
	}
	s.rtMu.RLock()
	defer s.rtMu.RUnlock()

	snaps := make(map[string]*ServerMonitorSnapshot)
	alerts := make([]MonitorAlert, 0)
	if s.monitorRT == nil {
		return snaps, alerts, nil
	}

	filter := make(map[string]bool, len(serverIDs))
	for _, id := range serverIDs {
		filter[id] = true
	}

	for sid, snap := range s.monitorRT.LatestSnapshots {
		if len(filter) > 0 && !filter[sid] {
			continue
		}
		if snap != nil {
			snaps[sid] = cloneSnapshot(snap)
		}
	}
	for _, al := range s.monitorRT.Alerts {
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

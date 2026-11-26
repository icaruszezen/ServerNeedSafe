package vault

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	maxPatrolRecords = 80
	maxAISessions    = 100
)

// AIProviderMutationInput represents create/update request fields for an LLM provider.
type AIProviderMutationInput struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	Protocol      AIProtocol `json:"protocol"`
	BaseURL       string     `json:"base_url"`
	APIKey        *string    `json:"api_key,omitempty"` // nil = preserve existing key on update
	Model         string     `json:"model"`
	MaxTokens     int        `json:"max_tokens"`
	ContextWindow int        `json:"context_window"` // 0 = auto-infer from model
	SetActive     bool       `json:"set_active"`
}

// GetAISettingsView returns redacted AI settings, provider list, and patrol config.
func (s *Store) GetAISettingsView() (activeProviderID string, defaultMode AIExecutionMode, providers []AIProviderView, patrol PatrolConfigView, err error) {
	s.secMu.RLock()
	defer s.secMu.RUnlock()
	if s.secrets == nil {
		return "", "", nil, PatrolConfigView{}, ErrVaultLocked
	}
	defaultMode = s.secrets.AISettings.DefaultMode
	if defaultMode == "" {
		defaultMode = AIModeStandard
	}
	providers = make([]AIProviderView, len(s.secrets.AISettings.Providers))
	for i, p := range s.secrets.AISettings.Providers {
		providers[i] = p.ToView()
	}
	patrolCfg := s.secrets.AISettings.Patrol
	if patrolCfg.IntervalMinutes <= 0 {
		patrolCfg = DefaultPatrolConfig()
	}
	return s.secrets.AISettings.ActiveProviderID, defaultMode, providers, patrolCfg.ToView(), nil
}

// GetActiveAIProviderSecret returns a copy of the currently active AIProviderConfig including APIKey.
func (s *Store) GetActiveAIProviderSecret() (*AIProviderConfig, error) {
	s.secMu.RLock()
	defer s.secMu.RUnlock()
	if s.secrets == nil {
		return nil, ErrVaultLocked
	}
	activeID := s.secrets.AISettings.ActiveProviderID
	for _, p := range s.secrets.AISettings.Providers {
		if p.ID == activeID {
			cp := p
			return &cp, nil
		}
	}
	if len(s.secrets.AISettings.Providers) > 0 {
		cp := s.secrets.AISettings.Providers[0]
		return &cp, nil
	}
	return nil, ErrNotFound
}

// GetAIProviderSecret returns a copy of a specific AIProviderConfig by ID including APIKey.
func (s *Store) GetAIProviderSecret(id string) (*AIProviderConfig, error) {
	s.secMu.RLock()
	defer s.secMu.RUnlock()
	if s.secrets == nil {
		return nil, ErrVaultLocked
	}
	for _, p := range s.secrets.AISettings.Providers {
		if p.ID == id {
			cp := p
			return &cp, nil
		}
	}
	return nil, ErrNotFound
}

// UpsertAIProvider creates or updates an encrypted LLM provider configuration inside secrets.enc.
func (s *Store) UpsertAIProvider(in AIProviderMutationInput, clientIP string) (*AIProviderView, string, error) {
	in.Name = strings.TrimSpace(in.Name)
	in.BaseURL = strings.TrimSpace(in.BaseURL)
	in.Model = strings.TrimSpace(in.Model)
	if in.Protocol == "" {
		in.Protocol = AIProtocolOpenAI
	}
	if in.Protocol != AIProtocolOpenAI && in.Protocol != AIProtocolAnthropic {
		return nil, "", fmt.Errorf("%w: 不支持的模型协议 %s", ErrInvalidInput, in.Protocol)
	}
	if in.Name == "" || in.BaseURL == "" || in.Model == "" {
		return nil, "", fmt.Errorf("%w: 供应商名称、接口地址与模型名称不能为空", ErrInvalidInput)
	}
	if in.MaxTokens <= 0 || in.MaxTokens > 65536 {
		in.MaxTokens = 4096
	}
	if in.ContextWindow < 0 || in.ContextWindow > 2000000 {
		in.ContextWindow = 0
	}

	var outView AIProviderView
	var outActive string
	auditAction := "ai.provider_create"
	auditDetail := ""

	err := s.mutateSecrets(func(sec *SecretsState) error {
		now := time.Now().UTC()
		if in.ID != "" {
			for i := range sec.AISettings.Providers {
				if sec.AISettings.Providers[i].ID == in.ID {
					existing := sec.AISettings.Providers[i]
					newKey := ""
					if in.APIKey != nil {
						newKey = strings.TrimSpace(*in.APIKey)
					}
					// Guard against silently re-pointing a stored masked API key to another endpoint.
					if newKey == "" && existing.APIKey != "" && (!SameEndpointURL(existing.BaseURL, in.BaseURL) || normalizeAIProtocol(existing.Protocol) != in.Protocol) {
						return fmt.Errorf("%w: 更换接口地址或协议时必须重新填写 API Key", ErrInvalidInput)
					}
					existing.Name = in.Name
					existing.Protocol = in.Protocol
					existing.BaseURL = in.BaseURL
					existing.Model = in.Model
					existing.MaxTokens = in.MaxTokens
					existing.ContextWindow = in.ContextWindow
					existing.UpdatedAt = now
					if newKey != "" {
						existing.APIKey = newKey
					}
					sec.AISettings.Providers[i] = existing
					if in.SetActive || sec.AISettings.ActiveProviderID == "" {
						sec.AISettings.ActiveProviderID = existing.ID
					}
					auditAction = "ai.provider_update"
					auditDetail = fmt.Sprintf("更新大模型配置 (%s / %s)", existing.Protocol, existing.Model)
					outView = existing.ToView()
					outActive = sec.AISettings.ActiveProviderID
					return nil
				}
			}
		}

		newProv := AIProviderConfig{
			ID:            uuid.NewString(),
			Name:          in.Name,
			Protocol:      in.Protocol,
			BaseURL:       in.BaseURL,
			Model:         in.Model,
			MaxTokens:     in.MaxTokens,
			ContextWindow: in.ContextWindow,
			CreatedAt:     now,
			UpdatedAt:     now,
		}
		if in.APIKey != nil {
			newProv.APIKey = strings.TrimSpace(*in.APIKey)
		}
		sec.AISettings.Providers = append(sec.AISettings.Providers, newProv)
		if in.SetActive || sec.AISettings.ActiveProviderID == "" || len(sec.AISettings.Providers) == 1 {
			sec.AISettings.ActiveProviderID = newProv.ID
		}
		auditDetail = fmt.Sprintf("新增大模型配置 (%s / %s)", newProv.Protocol, newProv.Model)
		outView = newProv.ToView()
		outActive = sec.AISettings.ActiveProviderID
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	s.RecordAudit(auditAction, outView.Name, auditDetail, clientIP, true)
	return &outView, outActive, nil
}

// SetActiveAIProvider updates the global single active model and default execution mode.
func (s *Store) SetActiveAIProvider(providerID string, defaultMode AIExecutionMode, clientIP string) error {
	var switchedName string
	err := s.mutateSecrets(func(sec *SecretsState) error {
		if providerID != "" {
			found := false
			for _, p := range sec.AISettings.Providers {
				if p.ID == providerID {
					found = true
					switchedName = p.Name + " (" + p.Model + ")"
					break
				}
			}
			if !found {
				return ErrNotFound
			}
			sec.AISettings.ActiveProviderID = providerID
		}
		if defaultMode == AIModeSuggest || defaultMode == AIModeStandard || defaultMode == AIModeAutonomous {
			sec.AISettings.DefaultMode = defaultMode
		}
		return nil
	})
	if err != nil {
		return err
	}
	if switchedName != "" {
		s.RecordAudit("ai.provider_switch", switchedName, "切换全局激活大模型", clientIP, true)
	}
	return nil
}

// DeleteAIProvider deletes an AI provider and reassigns ActiveProviderID if needed.
func (s *Store) DeleteAIProvider(id, clientIP string) (string, error) {
	var outActive string
	var deletedName string
	err := s.mutateSecrets(func(sec *SecretsState) error {
		for i, p := range sec.AISettings.Providers {
			if p.ID == id {
				deletedName = p.Name
				sec.AISettings.Providers = slices.Delete(sec.AISettings.Providers, i, i+1)
				if sec.AISettings.ActiveProviderID == id {
					if len(sec.AISettings.Providers) > 0 {
						sec.AISettings.ActiveProviderID = sec.AISettings.Providers[0].ID
					} else {
						sec.AISettings.ActiveProviderID = ""
					}
				}
				outActive = sec.AISettings.ActiveProviderID
				return nil
			}
		}
		return ErrNotFound
	})
	if err != nil {
		return "", err
	}
	s.RecordAudit("ai.provider_delete", deletedName, "删除大模型供应商配置", clientIP, true)
	return outActive, nil
}

// --- Host Memories (Objective Server Profiles — stored in aiops_runtime.json) ---

func (s *Store) ListHostMemories() ([]HostMemory, error) {
	if !s.IsReady() {
		return nil, ErrVaultLocked
	}
	s.rtMu.RLock()
	defer s.rtMu.RUnlock()
	if s.aiopsRT == nil {
		return []HostMemory{}, nil
	}
	return cloneHostMemories(s.aiopsRT.HostMemories), nil
}

func (s *Store) UpsertHostMemory(in HostMemory, isAuto bool, clientIP string) (*HostMemory, error) {
	if strings.TrimSpace(in.ServerID) == "" {
		return nil, ErrInvalidInput
	}

	s.secMu.RLock()
	if s.secrets == nil {
		s.secMu.RUnlock()
		return nil, ErrVaultLocked
	}
	srvName := in.ServerName
	for _, srv := range s.secrets.Servers {
		if srv.ID == in.ServerID {
			srvName = srv.Name
			break
		}
	}
	s.secMu.RUnlock()

	dedupStrings := func(items []string) []string {
		out := make([]string, 0, len(items))
		for _, item := range items {
			t := RedactSensitiveText(strings.TrimSpace(item))
			if t != "" && !slices.Contains(out, t) {
				out = append(out, t)
			}
		}
		return out
	}

	cleanSummary := RedactSensitiveText(strings.TrimSpace(in.Summary))
	cleanOSArch := RedactSensitiveText(strings.TrimSpace(in.OSArch))
	cleanPortsNote := RedactSensitiveText(strings.TrimSpace(in.PortsNote))
	cleanConstraints := RedactSensitiveText(strings.TrimSpace(in.Constraints))
	cleanNotes := RedactSensitiveText(strings.TrimSpace(in.Notes))

	now := time.Now().UTC()
	var outMem HostMemory

	s.rtMu.Lock()
	if s.aiopsRT == nil {
		s.aiopsRT = DefaultAIOpsRuntimeState(now)
	}
	found := false
	for i := range s.aiopsRT.HostMemories {
		if s.aiopsRT.HostMemories[i].ServerID == in.ServerID {
			cur := s.aiopsRT.HostMemories[i]
			cur.ServerName = srvName
			if cleanSummary != "" || !isAuto {
				cur.Summary = cleanSummary
			}
			if cleanOSArch != "" || !isAuto {
				cur.OSArch = cleanOSArch
			}
			if cleanPortsNote != "" || !isAuto {
				cur.PortsNote = cleanPortsNote
			}
			if cleanConstraints != "" || !isAuto {
				if isAuto && cur.Constraints != "" && !strings.Contains(cur.Constraints, cleanConstraints) {
					cur.Constraints = cur.Constraints + "\n" + cleanConstraints
				} else {
					cur.Constraints = cleanConstraints
				}
			}
			if cleanNotes != "" || !isAuto {
				if isAuto && cur.Notes != "" && !strings.Contains(cur.Notes, cleanNotes) {
					cur.Notes = cur.Notes + "\n" + cleanNotes
				} else {
					cur.Notes = cleanNotes
				}
			}
			if isAuto {
				cur.KeyServices = dedupStrings(append(cur.KeyServices, in.KeyServices...))
				cur.DeployPaths = dedupStrings(append(cur.DeployPaths, in.DeployPaths...))
				cur.AutoUpdatedCount++
			} else {
				cur.KeyServices = dedupStrings(in.KeyServices)
				cur.DeployPaths = dedupStrings(in.DeployPaths)
			}
			cur.UpdatedAt = now
			s.aiopsRT.HostMemories[i] = cur
			if !isAuto {
				s.appendAuditRuntimeLocked("ai.memory_edit", srvName, "人工编辑主机环境画像记忆", clientIP, true)
			}
			outMem = cur
			found = true
			break
		}
	}
	if !found {
		created := HostMemory{
			ServerID:    in.ServerID,
			ServerName:  srvName,
			Summary:     cleanSummary,
			OSArch:      cleanOSArch,
			KeyServices: dedupStrings(in.KeyServices),
			DeployPaths: dedupStrings(in.DeployPaths),
			PortsNote:   cleanPortsNote,
			Constraints: cleanConstraints,
			Notes:       cleanNotes,
			UpdatedAt:   now,
		}
		if isAuto {
			created.AutoUpdatedCount = 1
		}
		s.aiopsRT.HostMemories = append(s.aiopsRT.HostMemories, created)
		if !isAuto {
			s.appendAuditRuntimeLocked("ai.memory_edit", srvName, "人工录入主机环境画像记忆", clientIP, true)
		}
		outMem = created
	}
	s.dirtyAIOps = true
	s.rtMu.Unlock()
	s.triggerFlush()
	return &outMem, nil
}

func (s *Store) DeleteHostMemory(serverID, clientIP string) error {
	if !s.IsReady() {
		return ErrVaultLocked
	}
	s.rtMu.Lock()
	if s.aiopsRT == nil {
		s.rtMu.Unlock()
		return ErrNotFound
	}
	for i, m := range s.aiopsRT.HostMemories {
		if m.ServerID == serverID {
			s.aiopsRT.HostMemories = slices.Delete(s.aiopsRT.HostMemories, i, i+1)
			s.dirtyAIOps = true
			s.appendAuditRuntimeLocked("ai.memory_delete", m.ServerName, "清除主机环境画像记忆", clientIP, true)
			s.rtMu.Unlock()
			s.triggerFlush()
			return nil
		}
	}
	s.rtMu.Unlock()
	return ErrNotFound
}

// --- AI Runbooks (stored in aiops_runtime.json; linked Snippet synced to secrets.enc only when requested) ---

func (s *Store) ListRunbooks() ([]AIRunbook, error) {
	if !s.IsReady() {
		return nil, ErrVaultLocked
	}
	s.rtMu.RLock()
	defer s.rtMu.RUnlock()
	if s.aiopsRT == nil {
		return []AIRunbook{}, nil
	}
	return cloneRunbooks(s.aiopsRT.Runbooks), nil
}

func (s *Store) syncRunbookSnippet(in *AIRunbook, now time.Time) error {
	if len(in.FixCommands) == 0 {
		return nil
	}
	cmdJoined := strings.Join(in.FixCommands, " && ")
	return s.mutateSecrets(func(sec *SecretsState) error {
		snip := Snippet{
			ID:          in.LinkedSnippetID,
			Title:       "[Runbook] " + in.Title,
			Category:    in.Category,
			Command:     cmdJoined,
			Description: in.Symptom,
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		updatedExisting := false
		if snip.ID != "" {
			for idx := range sec.Snippets {
				if sec.Snippets[idx].ID == snip.ID {
					snip.CreatedAt = sec.Snippets[idx].CreatedAt
					sec.Snippets[idx] = snip
					updatedExisting = true
					break
				}
			}
		}
		if !updatedExisting {
			snip.ID = uuid.NewString()
			sec.Snippets = append(sec.Snippets, snip)
		}
		in.LinkedSnippetID = snip.ID
		return nil
	})
}

func (s *Store) upsertRunbookRuntimeLocked(in AIRunbook, now time.Time, clientIP string) AIRunbook {
	if s.aiopsRT == nil {
		s.aiopsRT = DefaultAIOpsRuntimeState(now)
	}
	if in.Tags == nil {
		in.Tags = []string{}
	}
	if in.DiagnosticSteps == nil {
		in.DiagnosticSteps = []string{}
	}
	if in.FixCommands == nil {
		in.FixCommands = []string{}
	}
	if in.ID != "" {
		for i := range s.aiopsRT.Runbooks {
			if s.aiopsRT.Runbooks[i].ID == in.ID {
				in.CreatedAt = s.aiopsRT.Runbooks[i].CreatedAt
				in.UpdatedAt = now
				s.aiopsRT.Runbooks[i] = in
				s.dirtyAIOps = true
				s.appendAuditRuntimeLocked("ai.runbook_update", in.Title, "更新 AI 排障技能 Runbook", clientIP, true)
				return in
			}
		}
	}
	in.ID = uuid.NewString()
	in.CreatedAt = now
	in.UpdatedAt = now
	s.aiopsRT.Runbooks = append([]AIRunbook{in}, s.aiopsRT.Runbooks...)
	s.dirtyAIOps = true
	s.appendAuditRuntimeLocked("ai.runbook_create", in.Title, "沉淀新增 AI 排障技能 Runbook", clientIP, true)
	return in
}

func (s *Store) UpsertRunbook(in AIRunbook, syncSnippet bool, clientIP string) (*AIRunbook, error) {
	if !s.IsReady() {
		return nil, ErrVaultLocked
	}
	in.Title = strings.TrimSpace(in.Title)
	in.Category = strings.TrimSpace(in.Category)
	if in.Category == "" {
		in.Category = "排障技能"
	}
	if in.Title == "" {
		return nil, fmt.Errorf("%w: Runbook 标题不能为空", ErrInvalidInput)
	}

	now := time.Now().UTC()
	if syncSnippet {
		if err := s.syncRunbookSnippet(&in, now); err != nil {
			return nil, err
		}
	}

	s.rtMu.Lock()
	outRB := s.upsertRunbookRuntimeLocked(in, now, clientIP)
	s.rtMu.Unlock()
	s.triggerFlush()
	return &outRB, nil
}

func (s *Store) DeleteRunbook(id, clientIP string) error {
	if !s.IsReady() {
		return ErrVaultLocked
	}
	s.rtMu.Lock()
	if s.aiopsRT == nil {
		s.rtMu.Unlock()
		return ErrNotFound
	}
	for i, rb := range s.aiopsRT.Runbooks {
		if rb.ID == id {
			s.aiopsRT.Runbooks = slices.Delete(s.aiopsRT.Runbooks, i, i+1)
			s.dirtyAIOps = true
			s.appendAuditRuntimeLocked("ai.runbook_delete", rb.Title, "删除 AI 排障技能 Runbook", clientIP, true)
			s.rtMu.Unlock()
			s.triggerFlush()
			return nil
		}
	}
	s.rtMu.Unlock()
	return ErrNotFound
}

// --- AI Chat Sessions & Proposals (stored in aiops_runtime.json, never touches secrets.enc) ---

func cloneSession(cs AIChatSession) AIChatSession {
	cp := cs
	cp.ServerIDs = slices.Clone(cs.ServerIDs)
	cp.Messages = make([]AIChatMessage, len(cs.Messages))
	for i, m := range cs.Messages {
		mc := m
		mc.ToolCalls = slices.Clone(m.ToolCalls)
		cp.Messages[i] = mc
	}
	cp.PendingApprovals = make([]AIPendingApproval, len(cs.PendingApprovals))
	for i, ap := range cs.PendingApprovals {
		ac := ap
		ac.ServerIDs = slices.Clone(ap.ServerIDs)
		ac.ServerNames = slices.Clone(ap.ServerNames)
		if ap.ResolvedAt != nil {
			t := *ap.ResolvedAt
			ac.ResolvedAt = &t
		}
		cp.PendingApprovals[i] = ac
	}
	cp.RunbookProposals = make([]AIRunbookProposal, len(cs.RunbookProposals))
	for i, rp := range cs.RunbookProposals {
		rc := rp
		rc.DiagnosticSteps = slices.Clone(rp.DiagnosticSteps)
		rc.FixCommands = slices.Clone(rp.FixCommands)
		cp.RunbookProposals[i] = rc
	}
	cp.AgentsMDProposals = make([]AIAgentsMDProposal, len(cs.AgentsMDProposals))
	for i, ap := range cs.AgentsMDProposals {
		ac := ap
		if ap.ResolvedAt != nil {
			t := *ap.ResolvedAt
			ac.ResolvedAt = &t
		}
		cp.AgentsMDProposals[i] = ac
	}
	if cs.CompactedAt != nil {
		t := *cs.CompactedAt
		cp.CompactedAt = &t
	}
	return cp
}

func (s *Store) ListAISessions(scope string) ([]AIChatSessionSummary, error) {
	if !s.IsReady() {
		return nil, ErrVaultLocked
	}
	s.rtMu.RLock()
	defer s.rtMu.RUnlock()
	if s.aiopsRT == nil {
		return []AIChatSessionSummary{}, nil
	}
	out := make([]AIChatSessionSummary, 0, len(s.aiopsRT.AISessions))
	for _, cs := range s.aiopsRT.AISessions {
		if scope != "" && cs.Scope != scope {
			continue
		}
		out = append(out, cs.ToSummary())
	}
	return out, nil
}

func (s *Store) GetAISession(id string) (*AIChatSession, error) {
	if !s.IsReady() {
		return nil, ErrVaultLocked
	}
	s.rtMu.RLock()
	defer s.rtMu.RUnlock()
	if s.aiopsRT == nil {
		return nil, ErrNotFound
	}
	for _, cs := range s.aiopsRT.AISessions {
		if cs.ID == id {
			cp := cloneSession(cs)
			return &cp, nil
		}
	}
	return nil, ErrNotFound
}

func (s *Store) CreateAISession(title, scope string, serverIDs []string, mode AIExecutionMode) (*AIChatSession, error) {
	s.secMu.RLock()
	if s.secrets == nil {
		s.secMu.RUnlock()
		return nil, ErrVaultLocked
	}
	defaultMode := s.secrets.AISettings.DefaultMode
	s.secMu.RUnlock()

	sc := scope
	if sc != "terminal" {
		sc = "center"
	}
	md := mode
	if md != AIModeSuggest && md != AIModeStandard && md != AIModeAutonomous {
		md = defaultMode
		if md == "" {
			md = AIModeStandard
		}
	}
	t := strings.TrimSpace(title)
	if t == "" {
		t = "新建 AI 运维排障会话"
	}
	sids := serverIDs
	if sids == nil {
		sids = []string{}
	}

	now := time.Now().UTC()
	sess := AIChatSession{
		ID:                uuid.NewString(),
		Title:             t,
		Scope:             sc,
		ServerIDs:         slices.Clone(sids),
		Mode:              md,
		Messages:          []AIChatMessage{},
		PendingApprovals:  []AIPendingApproval{},
		RunbookProposals:  []AIRunbookProposal{},
		AgentsMDProposals: []AIAgentsMDProposal{},
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	s.rtMu.Lock()
	if s.aiopsRT == nil {
		s.aiopsRT = DefaultAIOpsRuntimeState(now)
	}
	s.aiopsRT.AISessions = append([]AIChatSession{sess}, s.aiopsRT.AISessions...)
	if len(s.aiopsRT.AISessions) > maxAISessions {
		s.aiopsRT.AISessions = s.aiopsRT.AISessions[:maxAISessions]
	}
	s.dirtyAIOps = true
	s.rtMu.Unlock()
	s.triggerFlush()

	out := cloneSession(sess)
	return &out, nil
}

func (s *Store) SaveAISession(sess AIChatSession) error {
	if !s.IsReady() {
		return ErrVaultLocked
	}
	sess.UpdatedAt = time.Now().UTC()

	s.rtMu.Lock()
	if s.aiopsRT == nil {
		s.aiopsRT = DefaultAIOpsRuntimeState(sess.UpdatedAt)
	}
	updated := false
	for i := range s.aiopsRT.AISessions {
		if s.aiopsRT.AISessions[i].ID == sess.ID {
			s.aiopsRT.AISessions[i] = cloneSession(sess)
			updated = true
			break
		}
	}
	if !updated {
		s.aiopsRT.AISessions = append([]AIChatSession{cloneSession(sess)}, s.aiopsRT.AISessions...)
		if len(s.aiopsRT.AISessions) > maxAISessions {
			s.aiopsRT.AISessions = s.aiopsRT.AISessions[:maxAISessions]
		}
	}
	s.dirtyAIOps = true
	s.rtMu.Unlock()
	s.triggerFlush()
	return nil
}

func (s *Store) DeleteAISession(id, clientIP string) error {
	if !s.IsReady() {
		return ErrVaultLocked
	}
	s.rtMu.Lock()
	if s.aiopsRT == nil {
		s.rtMu.Unlock()
		return ErrNotFound
	}
	for i, cs := range s.aiopsRT.AISessions {
		if cs.ID == id {
			s.aiopsRT.AISessions = slices.Delete(s.aiopsRT.AISessions, i, i+1)
			s.dirtyAIOps = true
			s.appendAuditRuntimeLocked("ai.session_delete", cs.Title, "删除 AI 运维会话记录", clientIP, true)
			s.rtMu.Unlock()
			s.triggerFlush()
			return nil
		}
	}
	s.rtMu.Unlock()
	return ErrNotFound
}

func (s *Store) ResolveRunbookProposal(proposalID string, accept bool, syncSnippet bool, clientIP string) (*AIRunbook, error) {
	if !s.IsReady() {
		return nil, ErrVaultLocked
	}

	// Step 1: Locate proposal under rtMu.RLock
	s.rtMu.RLock()
	var prop AIRunbookProposal
	found := false
	if s.aiopsRT != nil {
		for _, cs := range s.aiopsRT.AISessions {
			for _, rp := range cs.RunbookProposals {
				if rp.ID == proposalID {
					prop = rp
					prop.DiagnosticSteps = slices.Clone(rp.DiagnosticSteps)
					prop.FixCommands = slices.Clone(rp.FixCommands)
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
		return nil, ErrNotFound
	}

	now := time.Now().UTC()
	var rbIn AIRunbook
	if accept {
		title := strings.TrimSpace(prop.Title)
		if title == "" {
			title = "AI 提炼运维 SOP"
		}
		cat := strings.TrimSpace(prop.Category)
		if cat == "" {
			cat = "排障技能"
		}
		rbIn = AIRunbook{
			Title:           title,
			Category:        cat,
			Tags:            []string{"AI提炼"},
			Symptom:         prop.Symptom,
			RootCause:       prop.RootCause,
			DiagnosticSteps: prop.DiagnosticSteps,
			FixCommands:     prop.FixCommands,
			Verification:    prop.Verification,
			SourceSessionID: prop.SessionID,
		}
		if syncSnippet {
			if err := s.syncRunbookSnippet(&rbIn, now); err != nil {
				return nil, err
			}
		}
	}

	// Step 2: Update runtime state
	s.rtMu.Lock()
	foundSessIdx, foundPropIdx := -1, -1
	for si := range s.aiopsRT.AISessions {
		for pi := range s.aiopsRT.AISessions[si].RunbookProposals {
			if s.aiopsRT.AISessions[si].RunbookProposals[pi].ID == proposalID {
				foundSessIdx, foundPropIdx = si, pi
				break
			}
		}
		if foundSessIdx >= 0 {
			break
		}
	}
	if foundSessIdx < 0 {
		s.rtMu.Unlock()
		return nil, ErrNotFound
	}

	var savedRB *AIRunbook
	if !accept {
		s.aiopsRT.AISessions[foundSessIdx].RunbookProposals[foundPropIdx].Status = "dismissed"
		s.dirtyAIOps = true
	} else {
		rb := s.upsertRunbookRuntimeLocked(rbIn, now, clientIP)
		s.aiopsRT.AISessions[foundSessIdx].RunbookProposals[foundPropIdx].Status = "accepted"
		s.aiopsRT.AISessions[foundSessIdx].RunbookProposals[foundPropIdx].SavedRunbookID = rb.ID
		s.dirtyAIOps = true
		savedRB = &rb
	}
	s.rtMu.Unlock()
	s.triggerFlush()
	return savedRB, nil
}

// --- Background Patrol Config (secrets.enc), Baselines & Records (aiops_runtime.json) ---

type WebhookMutationInput struct {
	ID      string  `json:"id"`
	Name    string  `json:"name"`
	Kind    string  `json:"kind"`
	URL     *string `json:"url,omitempty"`
	Secret  *string `json:"secret,omitempty"`
	Enabled bool    `json:"enabled"`
}

type PatrolConfigMutationInput struct {
	Enabled              bool                   `json:"enabled"`
	IntervalMinutes      int                    `json:"interval_minutes"`
	ServerIDs            []string               `json:"server_ids"`
	CPUWarnPercent       float64                `json:"cpu_warn_percent"`
	MemWarnPercent       float64                `json:"mem_warn_percent"`
	DiskWarnPercent      float64                `json:"disk_warn_percent"`
	SSHFailWarnCount     int                    `json:"ssh_fail_warn_count"`
	CheckListeningPorts  bool                   `json:"check_listening_ports"`
	CheckPrivilegedUsers bool                   `json:"check_privileged_users"`
	Webhooks             []WebhookMutationInput `json:"webhooks"`
}

func (s *Store) GetPatrolConfigSecret() (*PatrolConfig, error) {
	s.secMu.RLock()
	defer s.secMu.RUnlock()
	if s.secrets == nil {
		return nil, ErrVaultLocked
	}
	cp := s.secrets.AISettings.Patrol
	if cp.IntervalMinutes <= 0 {
		def := DefaultPatrolConfig()
		cp.IntervalMinutes = def.IntervalMinutes
		cp.CPUWarnPercent = def.CPUWarnPercent
		cp.MemWarnPercent = def.MemWarnPercent
		cp.DiskWarnPercent = def.DiskWarnPercent
		cp.SSHFailWarnCount = def.SSHFailWarnCount
		cp.CheckListeningPorts = def.CheckListeningPorts
		cp.CheckPrivilegedUsers = def.CheckPrivilegedUsers
	}
	cp.ServerIDs = slices.Clone(s.secrets.AISettings.Patrol.ServerIDs)
	if cp.ServerIDs == nil {
		cp.ServerIDs = []string{}
	}
	cp.Webhooks = slices.Clone(s.secrets.AISettings.Patrol.Webhooks)
	if cp.Webhooks == nil {
		cp.Webhooks = []WebhookChannel{}
	}
	return &cp, nil
}

func (s *Store) UpdatePatrolConfig(in PatrolConfigMutationInput, clientIP string) (*PatrolConfigView, error) {
	if in.IntervalMinutes < 5 || in.IntervalMinutes > 1440 {
		in.IntervalMinutes = 60
	}
	if in.CPUWarnPercent < 20 || in.CPUWarnPercent > 100 {
		in.CPUWarnPercent = 85
	}
	if in.MemWarnPercent < 20 || in.MemWarnPercent > 100 {
		in.MemWarnPercent = 85
	}
	if in.DiskWarnPercent < 20 || in.DiskWarnPercent > 100 {
		in.DiskWarnPercent = 85
	}
	if in.SSHFailWarnCount < 1 {
		in.SSHFailWarnCount = 15
	}

	var outView PatrolConfigView
	err := s.mutateSecrets(func(sec *SecretsState) error {
		existingByID := make(map[string]WebhookChannel)
		for _, w := range sec.AISettings.Patrol.Webhooks {
			existingByID[w.ID] = w
		}

		mergedWebhooks := make([]WebhookChannel, 0, len(in.Webhooks))
		for _, win := range in.Webhooks {
			name := strings.TrimSpace(win.Name)
			if name == "" {
				name = "告警通知通道"
			}
			kind := strings.TrimSpace(win.Kind)
			switch kind {
			case "feishu", "dingtalk", "wecom", "custom":
			default:
				kind = "custom"
			}
			var ch WebhookChannel
			if win.ID != "" {
				if old, ok := existingByID[win.ID]; ok {
					ch = old
				}
			}
			if ch.ID == "" {
				ch.ID = uuid.NewString()
			}
			ch.Name = name
			ch.Kind = kind
			ch.Enabled = win.Enabled
			if win.URL != nil && strings.TrimSpace(*win.URL) != "" {
				ch.URL = strings.TrimSpace(*win.URL)
			}
			if win.Secret != nil {
				ch.Secret = strings.TrimSpace(*win.Secret)
			}
			if ch.URL != "" {
				mergedWebhooks = append(mergedWebhooks, ch)
			}
		}

		sids := in.ServerIDs
		if sids == nil {
			sids = []string{}
		}

		sec.AISettings.Patrol = PatrolConfig{
			Enabled:              in.Enabled,
			IntervalMinutes:      in.IntervalMinutes,
			ServerIDs:            slices.Clone(sids),
			CPUWarnPercent:       in.CPUWarnPercent,
			MemWarnPercent:       in.MemWarnPercent,
			DiskWarnPercent:      in.DiskWarnPercent,
			SSHFailWarnCount:     in.SSHFailWarnCount,
			CheckListeningPorts:  in.CheckListeningPorts,
			CheckPrivilegedUsers: in.CheckPrivilegedUsers,
			Webhooks:             mergedWebhooks,
		}
		outView = sec.AISettings.Patrol.ToView()
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.RecordAudit("ai.patrol_config", "patrol", fmt.Sprintf("更新后台定时巡检策略 (启用=%v, 周期=%d分钟)", in.Enabled, in.IntervalMinutes), clientIP, true)
	return &outView, nil
}

func (s *Store) GetPatrolBaseline(serverID string) (*ServerBaselineSnapshot, error) {
	if !s.IsReady() {
		return nil, ErrVaultLocked
	}
	s.rtMu.RLock()
	defer s.rtMu.RUnlock()
	if s.aiopsRT == nil {
		return nil, nil
	}
	for _, b := range s.aiopsRT.PatrolBaselines {
		if b.ServerID == serverID {
			cp := b
			cp.ListeningPorts = slices.Clone(b.ListeningPorts)
			cp.UIDZeroUsers = slices.Clone(b.UIDZeroUsers)
			return &cp, nil
		}
	}
	return nil, nil
}

func (s *Store) SavePatrolBaseline(snap ServerBaselineSnapshot) error {
	if !s.IsReady() {
		return ErrVaultLocked
	}
	snap.UpdatedAt = time.Now().UTC()

	s.rtMu.Lock()
	if s.aiopsRT == nil {
		s.aiopsRT = DefaultAIOpsRuntimeState(snap.UpdatedAt)
	}
	updated := false
	for i := range s.aiopsRT.PatrolBaselines {
		if s.aiopsRT.PatrolBaselines[i].ServerID == snap.ServerID {
			s.aiopsRT.PatrolBaselines[i] = snap
			updated = true
			break
		}
	}
	if !updated {
		s.aiopsRT.PatrolBaselines = append(s.aiopsRT.PatrolBaselines, snap)
	}
	s.dirtyAIOps = true
	s.rtMu.Unlock()
	s.triggerFlush()
	return nil
}

func (s *Store) AppendPatrolRecord(rec PatrolRecord) error {
	if !s.IsReady() {
		return ErrVaultLocked
	}
	s.rtMu.Lock()
	if s.aiopsRT == nil {
		s.aiopsRT = DefaultAIOpsRuntimeState(time.Now().UTC())
	}
	s.aiopsRT.PatrolRecords = append([]PatrolRecord{rec}, s.aiopsRT.PatrolRecords...)
	if len(s.aiopsRT.PatrolRecords) > maxPatrolRecords {
		s.aiopsRT.PatrolRecords = s.aiopsRT.PatrolRecords[:maxPatrolRecords]
	}
	s.dirtyAIOps = true
	s.appendAuditRuntimeLocked(
		"ai.patrol_run",
		fmt.Sprintf("%d 台服务器", rec.TotalServers),
		fmt.Sprintf("执行%s巡检: 状态=%s (异常=%d, 严重=%d)", map[string]string{"scheduled": "后台定时", "manual": "手动即时"}[rec.Trigger], rec.Status, rec.WarningCount, rec.CriticalCount),
		"patrol-daemon",
		true,
	)
	s.rtMu.Unlock()
	s.triggerFlush()
	return nil
}

func (s *Store) ListPatrolRecords(limit int, markRead bool) ([]PatrolRecord, int, error) {
	if !s.IsReady() {
		return nil, 0, ErrVaultLocked
	}
	s.rtMu.Lock()
	if s.aiopsRT == nil {
		s.rtMu.Unlock()
		return []PatrolRecord{}, 0, nil
	}
	unread := 0
	hasUnread := false
	for _, r := range s.aiopsRT.PatrolRecords {
		if r.Unread {
			hasUnread = true
			if !markRead {
				unread++
			}
		}
	}
	if markRead && hasUnread {
		for i := range s.aiopsRT.PatrolRecords {
			s.aiopsRT.PatrolRecords[i].Unread = false
		}
		s.dirtyAIOps = true
	}
	n := len(s.aiopsRT.PatrolRecords)
	if limit > 0 && limit < n {
		n = limit
	}
	out := clonePatrolRecords(s.aiopsRT.PatrolRecords[:n])
	s.rtMu.Unlock()
	if markRead && hasUnread {
		s.triggerFlush()
	}
	return out, unread, nil
}

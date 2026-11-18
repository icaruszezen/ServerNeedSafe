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

// VerifyPassword validates password against the currently unlocked ClientVault's wrapped DEK
// in constant time without altering state or interrupting background SSH/Monitor/Patrol routines.
func (s *ClientVault) VerifyPassword(password string) error {
	if password == "" {
		return ErrInvalidPassword
	}
	s.mu.RLock()
	if len(s.dek) == 0 || s.state == nil || s.header == nil {
		s.mu.RUnlock()
		return ErrVaultLocked
	}
	hdr := *s.header
	hdr.KDFSalt = slices.Clone(s.header.KDFSalt)
	hdr.WrappedDEK = slices.Clone(s.header.WrappedDEK)
	hdr.WrappedDEKNonce = slices.Clone(s.header.WrappedDEKNonce)
	hdr.AuthPublicKey = slices.Clone(s.header.AuthPublicKey)
	expectedDEK := slices.Clone(s.dek)
	minMem := s.minMemoryKiB
	s.mu.RUnlock()
	defer zeroBytes(expectedDEK)

	verifiedDEK, verifiedPriv, err := unwrapDEKV2(password, &hdr, minMem)
	if err != nil {
		return ErrInvalidPassword
	}
	matched := constantTimeEqual(verifiedDEK, expectedDEK)
	zeroBytes(verifiedDEK)
	zeroBytes(verifiedPriv)
	if !matched {
		return ErrInvalidPassword
	}
	s.TouchActivity()
	return nil
}

// AIProviderMutationInput represents create/update request fields for an LLM provider.
type AIProviderMutationInput struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Protocol  AIProtocol `json:"protocol"`
	BaseURL   string     `json:"base_url"`
	APIKey    *string    `json:"api_key,omitempty"` // nil = preserve existing key on update
	Model     string     `json:"model"`
	MaxTokens int        `json:"max_tokens"`
	SetActive bool       `json:"set_active"`
}

// GetAISettingsView returns redacted AI settings, provider list, and patrol config.
func (s *ClientVault) GetAISettingsView() (activeProviderID string, defaultMode AIExecutionMode, providers []AIProviderView, patrol PatrolConfigView, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state == nil {
		return "", "", nil, PatrolConfigView{}, ErrVaultLocked
	}
	EnsureStateDefaults(s.state)
	providers = make([]AIProviderView, len(s.state.AISettings.Providers))
	for i, p := range s.state.AISettings.Providers {
		providers[i] = p.ToView()
	}
	return s.state.AISettings.ActiveProviderID, s.state.AISettings.DefaultMode, providers, s.state.AISettings.Patrol.ToView(), nil
}

// GetActiveAIProviderSecret returns a copy of the currently active AIProviderConfig including APIKey.
func (s *ClientVault) GetActiveAIProviderSecret() (*AIProviderConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state == nil {
		return nil, ErrVaultLocked
	}
	activeID := s.state.AISettings.ActiveProviderID
	for _, p := range s.state.AISettings.Providers {
		if p.ID == activeID {
			cp := p
			return &cp, nil
		}
	}
	if len(s.state.AISettings.Providers) > 0 {
		cp := s.state.AISettings.Providers[0]
		return &cp, nil
	}
	return nil, ErrNotFound
}

// GetAIProviderSecret returns a copy of a specific AIProviderConfig by ID including APIKey.
func (s *ClientVault) GetAIProviderSecret(id string) (*AIProviderConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state == nil {
		return nil, ErrVaultLocked
	}
	for _, p := range s.state.AISettings.Providers {
		if p.ID == id {
			cp := p
			return &cp, nil
		}
	}
	return nil, ErrNotFound
}

// UpsertAIProvider creates or updates an encrypted LLM provider configuration.
func (s *ClientVault) UpsertAIProvider(in AIProviderMutationInput, clientIP string) (*AIProviderView, string, error) {
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

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return nil, "", ErrVaultLocked
	}

	var outView AIProviderView
	var outActive string

	err := s.mutateLocked(func(st *VaultState) error {
		EnsureStateDefaults(st)
		now := time.Now().UTC()
		if in.ID != "" {
			for i := range st.AISettings.Providers {
				if st.AISettings.Providers[i].ID == in.ID {
					existing := st.AISettings.Providers[i]
					newKey := ""
					if in.APIKey != nil {
						newKey = strings.TrimSpace(*in.APIKey)
					}
					// Never silently re-point a stored (masked) API key to a different endpoint or protocol:
					// a hijacked session could otherwise exfiltrate the plaintext key to its own server.
					if newKey == "" && existing.APIKey != "" && (!SameEndpointURL(existing.BaseURL, in.BaseURL) || normalizeAIProtocol(existing.Protocol) != in.Protocol) {
						return fmt.Errorf("%w: 更换接口地址或协议时必须重新填写 API Key", ErrInvalidInput)
					}
					existing.Name = in.Name
					existing.Protocol = in.Protocol
					existing.BaseURL = in.BaseURL
					existing.Model = in.Model
					existing.MaxTokens = in.MaxTokens
					existing.UpdatedAt = now
					if newKey != "" {
						existing.APIKey = newKey
					}
					st.AISettings.Providers[i] = existing
					if in.SetActive || st.AISettings.ActiveProviderID == "" {
						st.AISettings.ActiveProviderID = existing.ID
					}
					appendAuditLocked(st, "ai.provider_update", existing.Name, fmt.Sprintf("更新大模型配置 (%s / %s)", existing.Protocol, existing.Model), clientIP, true)
					outView = existing.ToView()
					outActive = st.AISettings.ActiveProviderID
					return nil
				}
			}
		}

		newProv := AIProviderConfig{
			ID:        uuid.NewString(),
			Name:      in.Name,
			Protocol:  in.Protocol,
			BaseURL:   in.BaseURL,
			Model:     in.Model,
			MaxTokens: in.MaxTokens,
			CreatedAt: now,
			UpdatedAt: now,
		}
		if in.APIKey != nil {
			newProv.APIKey = strings.TrimSpace(*in.APIKey)
		}
		st.AISettings.Providers = append(st.AISettings.Providers, newProv)
		if in.SetActive || st.AISettings.ActiveProviderID == "" || len(st.AISettings.Providers) == 1 {
			st.AISettings.ActiveProviderID = newProv.ID
		}
		appendAuditLocked(st, "ai.provider_create", newProv.Name, fmt.Sprintf("新增大模型配置 (%s / %s)", newProv.Protocol, newProv.Model), clientIP, true)
		outView = newProv.ToView()
		outActive = st.AISettings.ActiveProviderID
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	return &outView, outActive, nil
}

// SetActiveAIProvider updates the global single active model and default execution mode.
func (s *ClientVault) SetActiveAIProvider(providerID string, defaultMode AIExecutionMode, clientIP string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return ErrVaultLocked
	}
	return s.mutateLocked(func(st *VaultState) error {
		EnsureStateDefaults(st)
		if providerID != "" {
			found := false
			var name string
			for _, p := range st.AISettings.Providers {
				if p.ID == providerID {
					found = true
					name = p.Name + " (" + p.Model + ")"
					break
				}
			}
			if !found {
				return ErrNotFound
			}
			st.AISettings.ActiveProviderID = providerID
			appendAuditLocked(st, "ai.provider_switch", name, "切换全局激活大模型", clientIP, true)
		}
		if defaultMode == AIModeSuggest || defaultMode == AIModeStandard || defaultMode == AIModeAutonomous {
			st.AISettings.DefaultMode = defaultMode
		}
		return nil
	})
}

// DeleteAIProvider deletes an AI provider and reassigns ActiveProviderID if needed.
func (s *ClientVault) DeleteAIProvider(id, clientIP string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return "", ErrVaultLocked
	}
	var outActive string
	err := s.mutateLocked(func(st *VaultState) error {
		for i, p := range st.AISettings.Providers {
			if p.ID == id {
				st.AISettings.Providers = slices.Delete(st.AISettings.Providers, i, i+1)
				if st.AISettings.ActiveProviderID == id {
					if len(st.AISettings.Providers) > 0 {
						st.AISettings.ActiveProviderID = st.AISettings.Providers[0].ID
					} else {
						st.AISettings.ActiveProviderID = ""
					}
				}
				appendAuditLocked(st, "ai.provider_delete", p.Name, "删除大模型供应商配置", clientIP, true)
				outActive = st.AISettings.ActiveProviderID
				return nil
			}
		}
		return ErrNotFound
	})
	if err != nil {
		return "", err
	}
	return outActive, nil
}

// --- Host Memories (Objective Server Profiles) ---

func (s *ClientVault) ListHostMemories() ([]HostMemory, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state == nil {
		return nil, ErrVaultLocked
	}
	out := make([]HostMemory, len(s.state.HostMemories))
	for i, m := range s.state.HostMemories {
		cp := m
		cp.KeyServices = slices.Clone(m.KeyServices)
		cp.DeployPaths = slices.Clone(m.DeployPaths)
		out[i] = cp
	}
	return out, nil
}

func (s *ClientVault) UpsertHostMemory(in HostMemory, isAuto bool, clientIP string) (*HostMemory, error) {
	if strings.TrimSpace(in.ServerID) == "" {
		return nil, ErrInvalidInput
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return nil, ErrVaultLocked
	}

	dedupStrings := func(items []string) []string {
		out := make([]string, 0, len(items))
		for _, item := range items {
			t := strings.TrimSpace(item)
			if t != "" && !slices.Contains(out, t) {
				out = append(out, t)
			}
		}
		return out
	}

	var outMem HostMemory
	err := s.mutateLocked(func(st *VaultState) error {
		EnsureStateDefaults(st)
		srvName := in.ServerName
		for _, srv := range st.Servers {
			if srv.ID == in.ServerID {
				srvName = srv.Name
				break
			}
		}

		now := time.Now().UTC()
		for i := range st.HostMemories {
			if st.HostMemories[i].ServerID == in.ServerID {
				cur := st.HostMemories[i]
				cur.ServerName = srvName
				if strings.TrimSpace(in.Summary) != "" {
					cur.Summary = strings.TrimSpace(in.Summary)
				}
				if strings.TrimSpace(in.OSArch) != "" {
					cur.OSArch = strings.TrimSpace(in.OSArch)
				}
				if strings.TrimSpace(in.PortsNote) != "" {
					cur.PortsNote = strings.TrimSpace(in.PortsNote)
				}
				if strings.TrimSpace(in.Notes) != "" || !isAuto {
					cur.Notes = strings.TrimSpace(in.Notes)
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
				st.HostMemories[i] = cur
				if !isAuto {
					appendAuditLocked(st, "ai.memory_edit", srvName, "人工编辑主机环境画像记忆", clientIP, true)
				}
				outMem = cur
				return nil
			}
		}

		created := HostMemory{
			ServerID:    in.ServerID,
			ServerName:  srvName,
			Summary:     strings.TrimSpace(in.Summary),
			OSArch:      strings.TrimSpace(in.OSArch),
			KeyServices: dedupStrings(in.KeyServices),
			DeployPaths: dedupStrings(in.DeployPaths),
			PortsNote:   strings.TrimSpace(in.PortsNote),
			Notes:       strings.TrimSpace(in.Notes),
			UpdatedAt:   now,
		}
		if isAuto {
			created.AutoUpdatedCount = 1
		}
		st.HostMemories = append(st.HostMemories, created)
		outMem = created
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &outMem, nil
}

func (s *ClientVault) DeleteHostMemory(serverID, clientIP string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return ErrVaultLocked
	}
	return s.mutateLocked(func(st *VaultState) error {
		for i, m := range st.HostMemories {
			if m.ServerID == serverID {
				st.HostMemories = slices.Delete(st.HostMemories, i, i+1)
				appendAuditLocked(st, "ai.memory_delete", m.ServerName, "清除主机环境画像记忆", clientIP, true)
				return nil
			}
		}
		return ErrNotFound
	})
}

// --- AI Runbooks ---

func (s *ClientVault) ListRunbooks() ([]AIRunbook, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state == nil {
		return nil, ErrVaultLocked
	}
	EnsureStateDefaults(s.state)
	out := make([]AIRunbook, len(s.state.Runbooks))
	for i, rb := range s.state.Runbooks {
		cp := rb
		cp.Tags = slices.Clone(rb.Tags)
		cp.DiagnosticSteps = slices.Clone(rb.DiagnosticSteps)
		cp.FixCommands = slices.Clone(rb.FixCommands)
		out[i] = cp
	}
	return out, nil
}

func upsertRunbookInState(st *VaultState, in AIRunbook, syncSnippet bool, clientIP string) (AIRunbook, error) {
	EnsureStateDefaults(st)
	now := time.Now().UTC()
	if in.Tags == nil {
		in.Tags = []string{}
	}
	if in.DiagnosticSteps == nil {
		in.DiagnosticSteps = []string{}
	}
	if in.FixCommands == nil {
		in.FixCommands = []string{}
	}

	if syncSnippet && len(in.FixCommands) > 0 {
		cmdJoined := strings.Join(in.FixCommands, " && ")
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
			for idx := range st.Snippets {
				if st.Snippets[idx].ID == snip.ID {
					snip.CreatedAt = st.Snippets[idx].CreatedAt
					st.Snippets[idx] = snip
					updatedExisting = true
					break
				}
			}
		}
		if !updatedExisting {
			snip.ID = uuid.NewString()
			st.Snippets = append(st.Snippets, snip)
		}
		in.LinkedSnippetID = snip.ID
	}

	if in.ID != "" {
		for i := range st.Runbooks {
			if st.Runbooks[i].ID == in.ID {
				in.CreatedAt = st.Runbooks[i].CreatedAt
				in.UpdatedAt = now
				st.Runbooks[i] = in
				appendAuditLocked(st, "ai.runbook_update", in.Title, "更新 AI 排障技能 Runbook", clientIP, true)
				return in, nil
			}
		}
	}

	in.ID = uuid.NewString()
	in.CreatedAt = now
	in.UpdatedAt = now
	st.Runbooks = append([]AIRunbook{in}, st.Runbooks...)
	appendAuditLocked(st, "ai.runbook_create", in.Title, "沉淀新增 AI 排障技能 Runbook", clientIP, true)
	return in, nil
}

func (s *ClientVault) UpsertRunbook(in AIRunbook, syncSnippet bool, clientIP string) (*AIRunbook, error) {
	in.Title = strings.TrimSpace(in.Title)
	in.Category = strings.TrimSpace(in.Category)
	if in.Category == "" {
		in.Category = "排障技能"
	}
	if in.Title == "" {
		return nil, fmt.Errorf("%w: Runbook 标题不能为空", ErrInvalidInput)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return nil, ErrVaultLocked
	}

	var outRB AIRunbook
	err := s.mutateLocked(func(st *VaultState) error {
		rb, uErr := upsertRunbookInState(st, in, syncSnippet, clientIP)
		if uErr != nil {
			return uErr
		}
		outRB = rb
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &outRB, nil
}

func (s *ClientVault) DeleteRunbook(id, clientIP string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return ErrVaultLocked
	}
	return s.mutateLocked(func(st *VaultState) error {
		for i, rb := range st.Runbooks {
			if rb.ID == id {
				st.Runbooks = slices.Delete(st.Runbooks, i, i+1)
				appendAuditLocked(st, "ai.runbook_delete", rb.Title, "删除 AI 排障技能 Runbook", clientIP, true)
				return nil
			}
		}
		return ErrNotFound
	})
}

// --- AI Chat Sessions & Proposals ---

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
	return cp
}

func (s *ClientVault) ListAISessions(scope string) ([]AIChatSessionSummary, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state == nil {
		return nil, ErrVaultLocked
	}
	out := make([]AIChatSessionSummary, 0, len(s.state.AISessions))
	for _, cs := range s.state.AISessions {
		if scope != "" && cs.Scope != scope {
			continue
		}
		out = append(out, cs.ToSummary())
	}
	return out, nil
}

func (s *ClientVault) GetAISession(id string) (*AIChatSession, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state == nil {
		return nil, ErrVaultLocked
	}
	for _, cs := range s.state.AISessions {
		if cs.ID == id {
			cp := cloneSession(cs)
			return &cp, nil
		}
	}
	return nil, ErrNotFound
}

func (s *ClientVault) CreateAISession(title, scope string, serverIDs []string, mode AIExecutionMode) (*AIChatSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return nil, ErrVaultLocked
	}

	var outSess AIChatSession
	err := s.mutateLocked(func(st *VaultState) error {
		EnsureStateDefaults(st)
		sc := scope
		if sc != "terminal" {
			sc = "center"
		}
		md := mode
		if md != AIModeSuggest && md != AIModeStandard && md != AIModeAutonomous {
			md = st.AISettings.DefaultMode
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
			ID:               uuid.NewString(),
			Title:            t,
			Scope:            sc,
			ServerIDs:        slices.Clone(sids),
			Mode:             md,
			Messages:         []AIChatMessage{},
			PendingApprovals: []AIPendingApproval{},
			RunbookProposals: []AIRunbookProposal{},
			CreatedAt:        now,
			UpdatedAt:        now,
		}
		st.AISessions = append([]AIChatSession{sess}, st.AISessions...)
		if len(st.AISessions) > maxAISessions {
			st.AISessions = st.AISessions[:maxAISessions]
		}
		outSess = cloneSession(sess)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &outSess, nil
}

func (s *ClientVault) SaveAISession(sess AIChatSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return ErrVaultLocked
	}
	return s.mutateLocked(func(st *VaultState) error {
		sess.UpdatedAt = time.Now().UTC()
		for i := range st.AISessions {
			if st.AISessions[i].ID == sess.ID {
				st.AISessions[i] = cloneSession(sess)
				return nil
			}
		}
		st.AISessions = append([]AIChatSession{cloneSession(sess)}, st.AISessions...)
		if len(st.AISessions) > maxAISessions {
			st.AISessions = st.AISessions[:maxAISessions]
		}
		return nil
	})
}

func (s *ClientVault) DeleteAISession(id, clientIP string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return ErrVaultLocked
	}
	return s.mutateLocked(func(st *VaultState) error {
		for i, cs := range st.AISessions {
			if cs.ID == id {
				st.AISessions = slices.Delete(st.AISessions, i, i+1)
				appendAuditLocked(st, "ai.session_delete", cs.Title, "删除 AI 运维会话记录", clientIP, true)
				return nil
			}
		}
		return ErrNotFound
	})
}

func (s *ClientVault) ResolveRunbookProposal(proposalID string, accept bool, syncSnippet bool, clientIP string) (*AIRunbook, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return nil, ErrVaultLocked
	}

	var savedRB *AIRunbook
	err := s.mutateLocked(func(st *VaultState) error {
		EnsureStateDefaults(st)
		foundSessIdx := -1
		foundPropIdx := -1
		for si := range st.AISessions {
			for pi := range st.AISessions[si].RunbookProposals {
				if st.AISessions[si].RunbookProposals[pi].ID == proposalID {
					foundSessIdx = si
					foundPropIdx = pi
					break
				}
			}
			if foundSessIdx >= 0 {
				break
			}
		}
		if foundSessIdx < 0 {
			return ErrNotFound
		}

		prop := st.AISessions[foundSessIdx].RunbookProposals[foundPropIdx]
		if !accept {
			prop.Status = "dismissed"
			st.AISessions[foundSessIdx].RunbookProposals[foundPropIdx] = prop
			savedRB = nil
			return nil
		}

		title := strings.TrimSpace(prop.Title)
		if title == "" {
			title = "AI 提炼运维 SOP"
		}
		cat := strings.TrimSpace(prop.Category)
		if cat == "" {
			cat = "排障技能"
		}
		rb, uErr := upsertRunbookInState(st, AIRunbook{
			Title:           title,
			Category:        cat,
			Tags:            []string{"AI提炼"},
			Symptom:         prop.Symptom,
			RootCause:       prop.RootCause,
			DiagnosticSteps: prop.DiagnosticSteps,
			FixCommands:     prop.FixCommands,
			Verification:    prop.Verification,
			SourceSessionID: prop.SessionID,
		}, syncSnippet, clientIP)
		if uErr != nil {
			return uErr
		}
		prop.Status = "accepted"
		prop.SavedRunbookID = rb.ID
		st.AISessions[foundSessIdx].RunbookProposals[foundPropIdx] = prop
		savedRB = &rb
		return nil
	})
	if err != nil {
		return nil, err
	}
	return savedRB, nil
}

// --- Background Patrol Config, Baselines & Records ---

type WebhookMutationInput struct {
	ID      string  `json:"id"`
	Name    string  `json:"name"`
	Kind    string  `json:"kind"`
	URL     *string `json:"url,omitempty"`    // nil or empty on update preserves existing URL
	Secret  *string `json:"secret,omitempty"` // nil on update preserves existing Secret
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

func (s *ClientVault) GetPatrolConfigSecret() (*PatrolConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state == nil {
		return nil, ErrVaultLocked
	}
	EnsureStateDefaults(s.state)
	cp := s.state.AISettings.Patrol
	cp.ServerIDs = slices.Clone(s.state.AISettings.Patrol.ServerIDs)
	cp.Webhooks = slices.Clone(s.state.AISettings.Patrol.Webhooks)
	return &cp, nil
}

func (s *ClientVault) UpdatePatrolConfig(in PatrolConfigMutationInput, clientIP string) (*PatrolConfigView, error) {
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

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return nil, ErrVaultLocked
	}

	var outView PatrolConfigView
	err := s.mutateLocked(func(st *VaultState) error {
		EnsureStateDefaults(st)
		existingByID := make(map[string]WebhookChannel)
		for _, w := range st.AISettings.Patrol.Webhooks {
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

		st.AISettings.Patrol = PatrolConfig{
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
		appendAuditLocked(st, "ai.patrol_config", "patrol", fmt.Sprintf("更新后台定时巡检策略 (启用=%v, 周期=%d分钟)", in.Enabled, in.IntervalMinutes), clientIP, true)
		outView = st.AISettings.Patrol.ToView()
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &outView, nil
}

func (s *ClientVault) GetPatrolBaseline(serverID string) (*ServerBaselineSnapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state == nil {
		return nil, ErrVaultLocked
	}
	for _, b := range s.state.PatrolBaselines {
		if b.ServerID == serverID {
			cp := b
			cp.ListeningPorts = slices.Clone(b.ListeningPorts)
			cp.UIDZeroUsers = slices.Clone(b.UIDZeroUsers)
			return &cp, nil
		}
	}
	return nil, nil
}

func (s *ClientVault) SavePatrolBaseline(snap ServerBaselineSnapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return ErrVaultLocked
	}
	return s.mutateLocked(func(st *VaultState) error {
		EnsureStateDefaults(st)
		snap.UpdatedAt = time.Now().UTC()
		for i := range st.PatrolBaselines {
			if st.PatrolBaselines[i].ServerID == snap.ServerID {
				st.PatrolBaselines[i] = snap
				return nil
			}
		}
		st.PatrolBaselines = append(st.PatrolBaselines, snap)
		return nil
	})
}

func (s *ClientVault) AppendPatrolRecord(rec PatrolRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return ErrVaultLocked
	}
	return s.mutateLocked(func(st *VaultState) error {
		EnsureStateDefaults(st)
		st.PatrolRecords = append([]PatrolRecord{rec}, st.PatrolRecords...)
		if len(st.PatrolRecords) > maxPatrolRecords {
			st.PatrolRecords = st.PatrolRecords[:maxPatrolRecords]
		}
		appendAuditLocked(
			st,
			"ai.patrol_run",
			fmt.Sprintf("%d 台服务器", rec.TotalServers),
			fmt.Sprintf("执行%s巡检: 状态=%s (异常=%d, 严重=%d)", map[string]string{"scheduled": "后台定时", "manual": "手动即时"}[rec.Trigger], rec.Status, rec.WarningCount, rec.CriticalCount),
			"client-zk",
			true,
		)
		return nil
	})
}

func (s *ClientVault) ListPatrolRecords(limit int, markRead bool) ([]PatrolRecord, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return nil, 0, ErrVaultLocked
	}
	unread := 0
	hasUnread := false
	for _, r := range s.state.PatrolRecords {
		if r.Unread {
			hasUnread = true
			if !markRead {
				unread++
			}
		}
	}
	if markRead && hasUnread {
		_ = s.mutateLocked(func(st *VaultState) error {
			for i := range st.PatrolRecords {
				st.PatrolRecords[i].Unread = false
			}
			return nil
		})
	}
	n := len(s.state.PatrolRecords)
	if limit > 0 && limit < n {
		n = limit
	}
	out := make([]PatrolRecord, n)
	for i := 0; i < n; i++ {
		cp := s.state.PatrolRecords[i]
		cp.Findings = slices.Clone(s.state.PatrolRecords[i].Findings)
		cp.AIRecommendations = slices.Clone(s.state.PatrolRecords[i].AIRecommendations)
		out[i] = cp
	}
	return out, unread, nil
}

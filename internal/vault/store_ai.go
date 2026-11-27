package vault

import (
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	maxPatrolRecords = 80
	maxAISessions    = 100
)

// AIProviderMutationInput represents create/update/clone request fields for an LLM provider.
type AIProviderMutationInput struct {
	ID              string            `json:"id"`
	CloneFromID     string            `json:"clone_from_id,omitempty"` // Optional: inherit encrypted APIKey & sensitive headers when endpoint/protocol matches
	Name            string            `json:"name"`
	Protocol        AIProtocol        `json:"protocol"`
	BaseURL         string            `json:"base_url"`
	EndpointMode    AIEndpointMode    `json:"endpoint_mode,omitempty"`
	AuthMode        AIAuthMode        `json:"auth_mode,omitempty"`
	APIKey          *string           `json:"api_key,omitempty"` // nil/empty = preserve existing key on update/clone
	Model           string            `json:"model"`
	MaxTokens       int               `json:"max_tokens,omitempty"`        // Legacy alias of MaxOutputTokens
	MaxOutputTokens *int              `json:"max_output_tokens,omitempty"` // nil = fall back to MaxTokens; 0 = unset/model default; unrestricted positive integer
	MaxInputTokens  int               `json:"max_input_tokens,omitempty"`  // 0 = auto from catalog/ContextWindow; unrestricted positive integer
	ContextWindow   int               `json:"context_window,omitempty"`    // 0 = auto from catalog; unrestricted positive integer
	Temperature     *float64          `json:"temperature,omitempty"`
	TopP            *float64          `json:"top_p,omitempty"`
	ReasoningEffort AIReasoningEffort `json:"reasoning_effort,omitempty"`
	CustomHeaders   *[]AICustomHeader `json:"custom_headers,omitempty"`
	ExtraBodyJSON   string            `json:"extra_body_json,omitempty"`
	SetActive       bool              `json:"set_active"`
}

func validateExtraBodyJSON(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", nil
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(trimmed), &parsed); err != nil || parsed == nil {
		return "", fmt.Errorf("%w: 自定义扩展请求体 (Extra Body) 必须是合法的 JSON 对象（例如 {\"enable_thinking\": true}）", ErrInvalidInput)
	}
	return trimmed, nil
}

func validateOptionalFloat(p *float64, name string) (*float64, error) {
	if p == nil {
		return nil, nil
	}
	if math.IsNaN(*p) || math.IsInf(*p, 0) {
		return nil, fmt.Errorf("%w: 参数 %s 必须是有效数值", ErrInvalidInput, name)
	}
	v := *p
	return &v, nil
}

func sameProviderTarget(a AIProviderConfig, baseURL string, protocol AIProtocol, epMode AIEndpointMode) bool {
	return SameEndpointURL(a.BaseURL, baseURL) &&
		NormalizeAIProtocol(a.Protocol) == NormalizeAIProtocol(protocol) &&
		NormalizeAIEndpointMode(a.EndpointMode) == NormalizeAIEndpointMode(epMode)
}

func mergeProviderCustomHeaders(
	incoming *[]AICustomHeader,
	existing []AICustomHeader,
	endpointChanged bool,
) ([]AICustomHeader, error) {
	existingByLower := make(map[string]AICustomHeader, len(existing))
	hasSensitiveExisting := false
	for _, h := range existing {
		k := strings.TrimSpace(h.Key)
		if k == "" {
			continue
		}
		existingByLower[strings.ToLower(k)] = h
		if IsSensitiveHeaderKey(k) && strings.TrimSpace(h.Value) != "" {
			hasSensitiveExisting = true
		}
	}

	if incoming == nil {
		if len(existing) == 0 {
			return nil, nil
		}
		if endpointChanged && hasSensitiveExisting {
			return nil, fmt.Errorf("%w: 更换接口地址或协议时必须重新填写或清空包含敏感值的自定义请求头", ErrInvalidInput)
		}
		return slices.Clone(existing), nil
	}

	out := make([]AICustomHeader, 0, len(*incoming))
	seen := make(map[string]int, len(*incoming))
	for _, h := range *incoming {
		k := strings.TrimSpace(h.Key)
		v := strings.TrimSpace(h.Value)
		if k == "" {
			continue
		}
		if strings.ContainsAny(k, "\r\n:") || strings.ContainsAny(v, "\r\n") {
			return nil, fmt.Errorf("%w: 自定义请求头 %q 包含非法换行或冒号字符", ErrInvalidInput, k)
		}
		lower := strings.ToLower(k)
		if v == "" && IsSensitiveHeaderKey(k) {
			if prev, ok := existingByLower[lower]; ok && prev.Value != "" {
				if endpointChanged {
					return nil, fmt.Errorf("%w: 更换接口地址或协议时必须重新填写敏感自定义请求头 %s", ErrInvalidInput, k)
				}
				v = prev.Value
			}
		}
		if idx, exists := seen[lower]; exists {
			out[idx] = AICustomHeader{Key: k, Value: v}
		} else {
			seen[lower] = len(out)
			out = append(out, AICustomHeader{Key: k, Value: v})
		}
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
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

// GetActiveAIProviderSecret returns a deep copy of the currently active AIProviderConfig including secrets.
func (s *Store) GetActiveAIProviderSecret() (*AIProviderConfig, error) {
	s.secMu.RLock()
	defer s.secMu.RUnlock()
	if s.secrets == nil {
		return nil, ErrVaultLocked
	}
	activeID := s.secrets.AISettings.ActiveProviderID
	for _, p := range s.secrets.AISettings.Providers {
		if p.ID == activeID {
			cp := CloneAIProviderConfig(p)
			return &cp, nil
		}
	}
	if len(s.secrets.AISettings.Providers) > 0 {
		cp := CloneAIProviderConfig(s.secrets.AISettings.Providers[0])
		return &cp, nil
	}
	return nil, ErrNotFound
}

// GetAIProviderSecret returns a deep copy of a specific AIProviderConfig by ID including secrets.
func (s *Store) GetAIProviderSecret(id string) (*AIProviderConfig, error) {
	s.secMu.RLock()
	defer s.secMu.RUnlock()
	if s.secrets == nil {
		return nil, ErrVaultLocked
	}
	for _, p := range s.secrets.AISettings.Providers {
		if p.ID == id {
			cp := CloneAIProviderConfig(p)
			return &cp, nil
		}
	}
	return nil, ErrNotFound
}

// UpsertAIProvider creates, updates, or clones an encrypted LLM provider configuration inside secrets.enc.
func (s *Store) UpsertAIProvider(in AIProviderMutationInput, clientIP string) (*AIProviderView, string, error) {
	in.Name = strings.TrimSpace(in.Name)
	in.BaseURL = strings.TrimSpace(in.BaseURL)
	in.Model = strings.TrimSpace(in.Model)
	if in.Protocol == "" {
		in.Protocol = AIProtocolOpenAI
	} else {
		in.Protocol = AIProtocol(strings.ToLower(strings.TrimSpace(string(in.Protocol))))
	}
	if !IsValidAIProtocol(in.Protocol) {
		return nil, "", fmt.Errorf("%w: 不支持的模型协议 %s", ErrInvalidInput, in.Protocol)
	}
	if in.Name == "" || in.BaseURL == "" || in.Model == "" {
		return nil, "", fmt.Errorf("%w: 供应商名称、接口地址与模型名称不能为空", ErrInvalidInput)
	}

	epMode := NormalizeAIEndpointMode(in.EndpointMode)
	authMode := NormalizeAIAuthMode(in.AuthMode)
	reasoningEffort := NormalizeAIReasoningEffort(in.ReasoningEffort)

	extraBody, err := validateExtraBodyJSON(in.ExtraBodyJSON)
	if err != nil {
		return nil, "", err
	}
	tempPtr, err := validateOptionalFloat(in.Temperature, "temperature")
	if err != nil {
		return nil, "", err
	}
	topPPtr, err := validateOptionalFloat(in.TopP, "top_p")
	if err != nil {
		return nil, "", err
	}

	// Unrestricted positive integers (0 = unset / follow model default).
	maxOut := 0
	if in.MaxOutputTokens != nil {
		if *in.MaxOutputTokens > 0 {
			maxOut = *in.MaxOutputTokens
		}
	} else if in.MaxTokens > 0 {
		maxOut = in.MaxTokens
	}
	maxIn := max(0, in.MaxInputTokens)
	ctxWin := max(0, in.ContextWindow)

	var outView AIProviderView
	var outActive string
	auditAction := "ai.provider_create"
	auditDetail := ""

	err = s.mutateSecrets(func(sec *SecretsState) error {
		now := time.Now().UTC()
		newKey := ""
		if in.APIKey != nil {
			newKey = strings.TrimSpace(*in.APIKey)
		}

		if in.ID != "" {
			for i := range sec.AISettings.Providers {
				if sec.AISettings.Providers[i].ID == in.ID {
					existing := sec.AISettings.Providers[i]
					endpointChanged := !sameProviderTarget(existing, in.BaseURL, in.Protocol, epMode)
					// Guard against silently re-pointing a stored masked API key to another endpoint.
					if newKey == "" && existing.APIKey != "" && endpointChanged {
						return fmt.Errorf("%w: 更换接口地址、端点模式或协议时必须重新填写 API Key", ErrInvalidInput)
					}
					mergedHeaders, hErr := mergeProviderCustomHeaders(in.CustomHeaders, existing.CustomHeaders, endpointChanged)
					if hErr != nil {
						return hErr
					}

					existing.Name = in.Name
					existing.Protocol = in.Protocol
					existing.BaseURL = in.BaseURL
					existing.EndpointMode = epMode
					existing.AuthMode = authMode
					existing.Model = in.Model
					existing.MaxTokens = maxOut
					existing.MaxOutputTokens = maxOut
					existing.MaxInputTokens = maxIn
					existing.ContextWindow = ctxWin
					existing.Temperature = tempPtr
					existing.TopP = topPPtr
					existing.ReasoningEffort = reasoningEffort
					existing.CustomHeaders = mergedHeaders
					existing.ExtraBodyJSON = extraBody
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

		// Optional clone from existing provider (safely reuses encrypted key & sensitive headers only for identical endpoint/protocol)
		var cloneSource *AIProviderConfig
		if strings.TrimSpace(in.CloneFromID) != "" {
			for i := range sec.AISettings.Providers {
				if sec.AISettings.Providers[i].ID == strings.TrimSpace(in.CloneFromID) {
					cp := CloneAIProviderConfig(sec.AISettings.Providers[i])
					cloneSource = &cp
					break
				}
			}
			if cloneSource == nil {
				return fmt.Errorf("%w: 源模型配置不存在，无法复制", ErrNotFound)
			}
		}

		resolvedKey := newKey
		var existingHeaders []AICustomHeader
		endpointChanged := false
		if cloneSource != nil {
			endpointChanged = !sameProviderTarget(*cloneSource, in.BaseURL, in.Protocol, epMode)
			existingHeaders = cloneSource.CustomHeaders
			if resolvedKey == "" && cloneSource.APIKey != "" {
				if endpointChanged {
					return fmt.Errorf("%w: 复制配置并更换接口地址、端点模式或协议时必须重新填写 API Key", ErrInvalidInput)
				}
				resolvedKey = cloneSource.APIKey
			}
		}
		mergedHeaders, hErr := mergeProviderCustomHeaders(in.CustomHeaders, existingHeaders, endpointChanged)
		if hErr != nil {
			return hErr
		}

		newProv := AIProviderConfig{
			ID:              uuid.NewString(),
			Name:            in.Name,
			Protocol:        in.Protocol,
			BaseURL:         in.BaseURL,
			EndpointMode:    epMode,
			AuthMode:        authMode,
			APIKey:          resolvedKey,
			Model:           in.Model,
			MaxTokens:       maxOut,
			MaxOutputTokens: maxOut,
			MaxInputTokens:  maxIn,
			ContextWindow:   ctxWin,
			Temperature:     tempPtr,
			TopP:            topPPtr,
			ReasoningEffort: reasoningEffort,
			CustomHeaders:   mergedHeaders,
			ExtraBodyJSON:   extraBody,
			CreatedAt:       now,
			UpdatedAt:       now,
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
		if m.Usage != nil {
			u := *m.Usage
			mc.Usage = &u
		}
		if m.ProviderState != nil {
			ps := *m.ProviderState
			ps.AnthropicThinking = slices.Clone(m.ProviderState.AnthropicThinking)
			if m.ProviderState.GeminiToolSignatures != nil {
				ps.GeminiToolSignatures = maps.Clone(m.ProviderState.GeminiToolSignatures)
			}
			if m.ProviderState.GeminiToolIDs != nil {
				ps.GeminiToolIDs = maps.Clone(m.ProviderState.GeminiToolIDs)
			}
			ps.ResponsesReasoningRaw = slices.Clone(m.ProviderState.ResponsesReasoningRaw)
			mc.ProviderState = &ps
		}
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
	slices.SortStableFunc(out, func(a, b AIChatSessionSummary) int {
		if a.UpdatedAt.After(b.UpdatedAt) {
			return -1
		}
		if b.UpdatedAt.After(a.UpdatedAt) {
			return 1
		}
		return 0
	})
	return out, nil
}

// ListSessionApprovals flattens HITL approvals across all built-in AI sessions (center & terminal),
// ordering pending approvals first and newest entries first.
func (s *Store) ListSessionApprovals(limit int) ([]SessionApprovalItem, int, error) {
	if !s.IsReady() {
		return nil, 0, ErrVaultLocked
	}
	s.rtMu.RLock()
	defer s.rtMu.RUnlock()
	if s.aiopsRT == nil {
		return []SessionApprovalItem{}, 0, nil
	}
	items := make([]SessionApprovalItem, 0, 16)
	pendingCount := 0
	for _, cs := range s.aiopsRT.AISessions {
		scope := cs.Scope
		if scope != "terminal" {
			scope = "center"
		}
		for _, ap := range cs.PendingApprovals {
			ac := ap
			ac.ServerIDs = slices.Clone(ap.ServerIDs)
			ac.ServerNames = slices.Clone(ap.ServerNames)
			if ap.ResolvedAt != nil {
				t := *ap.ResolvedAt
				ac.ResolvedAt = &t
			}
			if ac.SessionID == "" {
				ac.SessionID = cs.ID
			}
			if ac.Status == "pending" {
				pendingCount++
			}
			items = append(items, SessionApprovalItem{
				AIPendingApproval: ac,
				SessionTitle:      cs.Title,
				SessionScope:      scope,
				SessionServerIDs:  slices.Clone(cs.ServerIDs),
			})
		}
	}
	slices.SortStableFunc(items, func(a, b SessionApprovalItem) int {
		aPending := a.Status == "pending"
		bPending := b.Status == "pending"
		if aPending != bPending {
			if aPending {
				return -1
			}
			return 1
		}
		if a.CreatedAt.After(b.CreatedAt) {
			return -1
		}
		if b.CreatedAt.After(a.CreatedAt) {
			return 1
		}
		return 0
	})
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	return items, pendingCount, nil
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
			cp := cloneSession(sess)
			if i > 0 {
				s.aiopsRT.AISessions = slices.Delete(s.aiopsRT.AISessions, i, i+1)
				s.aiopsRT.AISessions = append([]AIChatSession{cp}, s.aiopsRT.AISessions...)
			} else {
				s.aiopsRT.AISessions[0] = cp
			}
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

	// Step 1: Atomically verify pending status and claim "resolving" under rtMu.Lock
	// so concurrent requests cannot create duplicate Runbooks or Snippets.
	s.rtMu.Lock()
	var prop AIRunbookProposal
	found := false
	alreadyResolved := ""
	if s.aiopsRT != nil {
		for si := range s.aiopsRT.AISessions {
			for pi := range s.aiopsRT.AISessions[si].RunbookProposals {
				rp := &s.aiopsRT.AISessions[si].RunbookProposals[pi]
				if rp.ID == proposalID {
					found = true
					if rp.Status != "pending" {
						alreadyResolved = rp.Status
						break
					}
					rp.Status = "resolving"
					prop = *rp
					prop.DiagnosticSteps = slices.Clone(rp.DiagnosticSteps)
					prop.FixCommands = slices.Clone(rp.FixCommands)
					break
				}
			}
			if found {
				break
			}
		}
	}
	s.rtMu.Unlock()
	if !found {
		return nil, ErrNotFound
	}
	if alreadyResolved != "" {
		return nil, fmt.Errorf("%w: 该 Runbook 技能提案已处理 (%s)", ErrInvalidInput, alreadyResolved)
	}

	rollbackPending := func() {
		s.rtMu.Lock()
		if s.aiopsRT != nil {
			for si := range s.aiopsRT.AISessions {
				for pi := range s.aiopsRT.AISessions[si].RunbookProposals {
					if s.aiopsRT.AISessions[si].RunbookProposals[pi].ID == proposalID &&
						s.aiopsRT.AISessions[si].RunbookProposals[pi].Status == "resolving" {
						s.aiopsRT.AISessions[si].RunbookProposals[pi].Status = "pending"
						break
					}
				}
			}
		}
		s.rtMu.Unlock()
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
				rollbackPending()
				return nil, err
			}
		}
	}

	// Step 2: Commit final runtime state
	s.rtMu.Lock()
	foundSessIdx, foundPropIdx := -1, -1
	if s.aiopsRT != nil {
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
	Enabled                 bool                   `json:"enabled"`
	IntervalMinutes         int                    `json:"interval_minutes"`
	ServerIDs               []string               `json:"server_ids"`
	CPUWarnPercent          float64                `json:"cpu_warn_percent"`
	MemWarnPercent          float64                `json:"mem_warn_percent"`
	DiskWarnPercent         float64                `json:"disk_warn_percent"`
	SSHFailWarnCount        int                    `json:"ssh_fail_warn_count"`
	CheckListeningPorts     bool                   `json:"check_listening_ports"`
	CheckPrivilegedUsers    bool                   `json:"check_privileged_users"`
	AnalysisMode            PatrolAnalysisMode     `json:"analysis_mode"`
	ExternalFallbackMinutes int                    `json:"external_fallback_minutes"`
	NotifyPendingApprovals  *bool                  `json:"notify_pending_approvals,omitempty"`
	Webhooks                []WebhookMutationInput `json:"webhooks"`
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
		cp.AnalysisMode = def.AnalysisMode
		cp.ExternalFallbackMinutes = def.ExternalFallbackMinutes
		cp.NotifyPendingApprovals = def.NotifyPendingApprovals
	}
	cp.AnalysisMode = NormalizePatrolAnalysisMode(cp.AnalysisMode)
	if cp.ExternalFallbackMinutes <= 0 {
		cp.ExternalFallbackMinutes = 15
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
	analysisMode := NormalizePatrolAnalysisMode(in.AnalysisMode)
	fallbackMins := in.ExternalFallbackMinutes
	if fallbackMins < 1 || fallbackMins > 1440 {
		fallbackMins = 15
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
			var old WebhookChannel
			hasOld := false
			if win.ID != "" {
				if prev, ok := existingByID[win.ID]; ok {
					ch = prev
					old = prev
					hasOld = true
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
			} else if hasOld && old.Secret != "" {
				sameDest := SameEndpointURL(ch.URL, old.URL) && ch.Kind == old.Kind
				if !sameDest {
					return fmt.Errorf("%w: 更换 Webhook 地址或类型时必须重新填写签名密钥", ErrInvalidInput)
				}
			}
			if ch.URL != "" {
				mergedWebhooks = append(mergedWebhooks, ch)
			}
		}

		sids := in.ServerIDs
		if sids == nil {
			sids = []string{}
		}

		notifyApprovals := sec.AISettings.Patrol.NotifyPendingApprovals
		if in.NotifyPendingApprovals != nil {
			notifyApprovals = *in.NotifyPendingApprovals
		}

		sec.AISettings.Patrol = PatrolConfig{
			Enabled:                 in.Enabled,
			IntervalMinutes:         in.IntervalMinutes,
			ServerIDs:               slices.Clone(sids),
			CPUWarnPercent:          in.CPUWarnPercent,
			MemWarnPercent:          in.MemWarnPercent,
			DiskWarnPercent:         in.DiskWarnPercent,
			SSHFailWarnCount:        in.SSHFailWarnCount,
			CheckListeningPorts:     in.CheckListeningPorts,
			CheckPrivilegedUsers:    in.CheckPrivilegedUsers,
			AnalysisMode:            analysisMode,
			ExternalFallbackMinutes: fallbackMins,
			NotifyPendingApprovals:  notifyApprovals,
			Webhooks:                mergedWebhooks,
		}
		outView = sec.AISettings.Patrol.ToView()
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.RecordAudit("ai.patrol_config", "patrol", fmt.Sprintf("更新后台定时巡检策略 (启用=%v, 周期=%d分钟, 研判引擎=%s)", in.Enabled, in.IntervalMinutes, analysisMode), clientIP, true)
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
	s.aiopsRT.PatrolRecords = append([]PatrolRecord{cloneSinglePatrolRecord(rec)}, s.aiopsRT.PatrolRecords...)
	if len(s.aiopsRT.PatrolRecords) > maxPatrolRecords {
		s.aiopsRT.PatrolRecords = s.aiopsRT.PatrolRecords[:maxPatrolRecords]
	}
	s.dirtyAIOps = true
	triggerLabel := map[string]string{
		"scheduled":    "后台定时",
		"manual":       "手动即时",
		"external_mcp": "外部 AI (MCP)",
	}[rec.Trigger]
	if triggerLabel == "" {
		triggerLabel = rec.Trigger
	}
	s.appendAuditRuntimeLocked(
		"ai.patrol_run",
		fmt.Sprintf("%d 台服务器", rec.TotalServers),
		fmt.Sprintf("执行%s巡检: 状态=%s (异常=%d, 严重=%d)", triggerLabel, rec.Status, rec.WarningCount, rec.CriticalCount),
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

// ResolveAIProviderForTransientCall merges caller-supplied overrides with an optional stored provider ID
// (or CloneFromID) while strictly enforcing that stored API keys and sensitive custom headers are NEVER
// forwarded to a different BaseURL, Protocol, or EndpointMode.
func (s *Store) ResolveAIProviderForTransientCall(in AIProviderMutationInput) (*AIProviderConfig, error) {
	var cfg AIProviderConfig
	var hasStored bool
	sourceID := strings.TrimSpace(in.ID)
	if sourceID == "" {
		sourceID = strings.TrimSpace(in.CloneFromID)
	}
	if sourceID != "" {
		if stored, err := s.GetAIProviderSecret(sourceID); err == nil && stored != nil {
			cfg = *stored
			hasStored = true
		}
	}

	storedBaseURL := cfg.BaseURL
	storedProto := NormalizeAIProtocol(cfg.Protocol)
	storedEpMode := NormalizeAIEndpointMode(cfg.EndpointMode)
	storedHeaders := slices.Clone(cfg.CustomHeaders)
	storedKey := cfg.APIKey

	if in.Protocol != "" {
		proto := AIProtocol(strings.ToLower(strings.TrimSpace(string(in.Protocol))))
		if !IsValidAIProtocol(proto) {
			return nil, fmt.Errorf("%w: 不支持的模型协议 %s", ErrInvalidInput, in.Protocol)
		}
		cfg.Protocol = proto
	} else if !hasStored {
		cfg.Protocol = AIProtocolOpenAI
	} else {
		cfg.Protocol = storedProto
	}

	if strings.TrimSpace(in.BaseURL) != "" {
		cfg.BaseURL = strings.TrimSpace(in.BaseURL)
	}
	if in.EndpointMode != "" {
		cfg.EndpointMode = NormalizeAIEndpointMode(in.EndpointMode)
	} else if !hasStored {
		cfg.EndpointMode = AIEndpointModeAuto
	} else {
		cfg.EndpointMode = storedEpMode
	}
	if in.AuthMode != "" {
		cfg.AuthMode = NormalizeAIAuthMode(in.AuthMode)
	} else if !hasStored {
		cfg.AuthMode = AIAuthModeAuto
	}
	if strings.TrimSpace(in.Model) != "" {
		cfg.Model = strings.TrimSpace(in.Model)
	}
	if in.MaxOutputTokens != nil {
		v := max(0, *in.MaxOutputTokens)
		cfg.MaxOutputTokens = v
		cfg.MaxTokens = v
	} else if in.MaxTokens > 0 {
		cfg.MaxOutputTokens = in.MaxTokens
		cfg.MaxTokens = in.MaxTokens
	}
	if in.MaxInputTokens > 0 {
		cfg.MaxInputTokens = in.MaxInputTokens
	}
	if in.ContextWindow > 0 {
		cfg.ContextWindow = in.ContextWindow
	}
	if in.Temperature != nil {
		v, err := validateOptionalFloat(in.Temperature, "temperature")
		if err != nil {
			return nil, err
		}
		cfg.Temperature = v
	}
	if in.TopP != nil {
		v, err := validateOptionalFloat(in.TopP, "top_p")
		if err != nil {
			return nil, err
		}
		cfg.TopP = v
	}
	if in.ReasoningEffort != "" {
		cfg.ReasoningEffort = NormalizeAIReasoningEffort(in.ReasoningEffort)
	}
	if strings.TrimSpace(in.ExtraBodyJSON) != "" {
		extra, err := validateExtraBodyJSON(in.ExtraBodyJSON)
		if err != nil {
			return nil, err
		}
		cfg.ExtraBodyJSON = extra
	}

	endpointChanged := hasStored && !(SameEndpointURL(storedBaseURL, cfg.BaseURL) &&
		storedProto == NormalizeAIProtocol(cfg.Protocol) &&
		storedEpMode == NormalizeAIEndpointMode(cfg.EndpointMode))

	suppliedKey := ""
	if in.APIKey != nil {
		suppliedKey = strings.TrimSpace(*in.APIKey)
	}
	if suppliedKey != "" {
		cfg.APIKey = suppliedKey
	} else if hasStored && storedKey != "" && endpointChanged {
		cfg.APIKey = ""
		return nil, fmt.Errorf("%w: 更换接口地址、端点模式或协议时必须重新填写 API Key", ErrInvalidInput)
	}

	mergedHeaders, err := mergeProviderCustomHeaders(in.CustomHeaders, storedHeaders, endpointChanged)
	if err != nil {
		cfg.APIKey = ""
		return nil, err
	}
	cfg.CustomHeaders = mergedHeaders
	return &cfg, nil
}

// GetModelCatalogCache returns a deep copy of the cached online model metadata catalog from aiops_runtime.json.
func (s *Store) GetModelCatalogCache() *AIModelCatalogCache {
	if !s.IsReady() {
		return nil
	}
	s.rtMu.RLock()
	defer s.rtMu.RUnlock()
	if s.aiopsRT == nil || s.aiopsRT.ModelCatalog == nil {
		return nil
	}
	src := s.aiopsRT.ModelCatalog
	cp := &AIModelCatalogCache{
		Source: src.Source,
		Models: make([]AIModelCatalogEntry, len(src.Models)),
	}
	if src.SyncedAt != nil {
		t := *src.SyncedAt
		cp.SyncedAt = &t
	}
	for i, m := range src.Models {
		mc := m
		if m.SupportsTemperature != nil {
			v := *m.SupportsTemperature
			mc.SupportsTemperature = &v
		}
		cp.Models[i] = mc
	}
	return cp
}

// SaveModelCatalogCache persists synced public model metadata into aiops_runtime.json.
func (s *Store) SaveModelCatalogCache(cache AIModelCatalogCache) error {
	if !s.IsReady() {
		return ErrVaultLocked
	}
	now := time.Now().UTC()
	cp := AIModelCatalogCache{
		Source: strings.TrimSpace(cache.Source),
		Models: make([]AIModelCatalogEntry, len(cache.Models)),
	}
	if cache.SyncedAt != nil {
		t := *cache.SyncedAt
		cp.SyncedAt = &t
	} else {
		cp.SyncedAt = &now
	}
	for i, m := range cache.Models {
		mc := m
		if m.SupportsTemperature != nil {
			v := *m.SupportsTemperature
			mc.SupportsTemperature = &v
		}
		cp.Models[i] = mc
	}

	s.rtMu.Lock()
	if s.aiopsRT == nil {
		s.aiopsRT = DefaultAIOpsRuntimeState(now)
	}
	s.aiopsRT.ModelCatalog = &cp
	s.dirtyAIOps = true
	s.rtMu.Unlock()
	s.triggerFlush()
	return nil
}

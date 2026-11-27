package vault

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	maxExternalApprovals = 120
	mcpTokenPrefixLit    = "sns_mcp_"
)

// MCPConfigMutationInput updates MCP gateway enablement, desktop loopback listener settings, and public URL hint.
type MCPConfigMutationInput struct {
	Enabled                *bool   `json:"enabled,omitempty"`
	DesktopLoopbackEnabled *bool   `json:"desktop_loopback_enabled,omitempty"`
	DesktopLoopbackPort    *int    `json:"desktop_loopback_port,omitempty"`
	PublicEndpointHint     *string `json:"public_endpoint_hint,omitempty"`
}

// CreateMCPTokenInput creates a revocable scoped MCP token.
type CreateMCPTokenInput struct {
	Name           string        `json:"name"`
	ClientHint     string        `json:"client_hint,omitempty"`
	Scope          MCPTokenScope `json:"scope"`
	AllowedServers []string      `json:"allowed_servers,omitempty"`
}

// UpdateMCPTokenInput mutates an existing MCP token's metadata, scope, allowlist, or enabled state.
type UpdateMCPTokenInput struct {
	Name           *string        `json:"name,omitempty"`
	ClientHint     *string        `json:"client_hint,omitempty"`
	Scope          *MCPTokenScope `json:"scope,omitempty"`
	AllowedServers *[]string      `json:"allowed_servers,omitempty"`
	Enabled        *bool          `json:"enabled,omitempty"`
}

// PatrolAnalysisUpdate carries an external or fallback AI root-cause report to enrich a PatrolRecord.
type PatrolAnalysisUpdate struct {
	AnalysisState     string
	AISource          string
	ExternalClient    string
	AIModel           string
	AISummary         string
	AIRootCause       string
	AIRecommendations []string
	DeepEvidence      []string
	AIWebhookNotified *bool
	MarkUnread        *bool
	OnlyIfNotAnalyzed bool
}

func hashMCPToken(raw string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(raw)))
	return hex.EncodeToString(sum[:])
}

func generateRawMCPToken() (raw string, prefix string, err error) {
	buf := make([]byte, 24) // 192-bit cryptographic entropy -> 48 hex chars
	if _, err = rand.Read(buf); err != nil {
		return "", "", err
	}
	hexStr := hex.EncodeToString(buf)
	raw = mcpTokenPrefixLit + hexStr
	prefix = mcpTokenPrefixLit + hexStr[:6] + "••••" + hexStr[len(hexStr)-4:]
	return raw, prefix, nil
}

func normalizeMCPClientHint(hint string) string {
	switch strings.ToLower(strings.TrimSpace(hint)) {
	case "claude_code", "claude-code", "claude":
		return "claude_code"
	case "codex":
		return "codex"
	case "antigravity":
		return "antigravity"
	case "cursor":
		return "cursor"
	default:
		return "custom"
	}
}

// GetMCPConfigSecret returns a deep copy of MCPConfig including TokenHash (for internal auth & loopback startup).
func (s *Store) GetMCPConfigSecret() (*MCPConfig, error) {
	s.secMu.RLock()
	defer s.secMu.RUnlock()
	if s.secrets == nil {
		return nil, ErrVaultLocked
	}
	cp := s.secrets.AISettings.MCP
	if cp.DesktopLoopbackPort < 1024 || cp.DesktopLoopbackPort > 65535 {
		cp.DesktopLoopbackPort = DefaultMCPConfig().DesktopLoopbackPort
	}
	cp.Tokens = cloneMCPTokens(s.secrets.AISettings.MCP.Tokens)
	return &cp, nil
}

// GetMCPConfigView returns redacted MCP config with merged live token usage telemetry from aiops_runtime.json.
func (s *Store) GetMCPConfigView() (*MCPConfigView, error) {
	cfg, err := s.GetMCPConfigSecret()
	if err != nil {
		return nil, err
	}

	s.rtMu.RLock()
	usageMap := make(map[string]MCPTokenRuntimeUsage)
	if s.aiopsRT != nil {
		for k, v := range s.aiopsRT.MCPTokenUsage {
			cp := v
			if v.LastUsedAt != nil {
				t := *v.LastUsedAt
				cp.LastUsedAt = &t
			}
			usageMap[k] = cp
		}
	}
	s.rtMu.RUnlock()

	views := make([]MCPTokenView, len(cfg.Tokens))
	for i, t := range cfg.Tokens {
		allowed := slices.Clone(t.AllowedServers)
		if allowed == nil {
			allowed = []string{}
		}
		u := usageMap[t.ID]
		views[i] = MCPTokenView{
			ID:             t.ID,
			Name:           t.Name,
			ClientHint:     t.ClientHint,
			Scope:          NormalizeMCPTokenScope(t.Scope),
			TokenPrefix:    t.TokenPrefix,
			AllowedServers: allowed,
			Enabled:        t.Enabled,
			CreatedAt:      t.CreatedAt,
			LastUsedAt:     u.LastUsedAt,
			LastClientName: u.LastClientName,
			LastClientIP:   u.LastClientIP,
			CallCount:      u.CallCount,
		}
	}
	return &MCPConfigView{
		Enabled:                cfg.Enabled,
		DesktopLoopbackEnabled: cfg.DesktopLoopbackEnabled,
		DesktopLoopbackPort:    cfg.DesktopLoopbackPort,
		PublicEndpointHint:     cfg.PublicEndpointHint,
		Tokens:                 views,
	}, nil
}

// UpdateMCPConfig persists MCP gateway toggle, desktop loopback settings, and optional endpoint hint into secrets.enc.
func (s *Store) UpdateMCPConfig(in MCPConfigMutationInput, clientIP string) (*MCPConfigView, error) {
	err := s.mutateSecrets(func(sec *SecretsState) error {
		if in.Enabled != nil {
			sec.AISettings.MCP.Enabled = *in.Enabled
		}
		if in.DesktopLoopbackEnabled != nil {
			sec.AISettings.MCP.DesktopLoopbackEnabled = *in.DesktopLoopbackEnabled
		}
		if in.DesktopLoopbackPort != nil {
			p := *in.DesktopLoopbackPort
			if p < 1024 || p > 65535 {
				return fmt.Errorf("%w: 本地 MCP 回环端口必须在 1024-65535 之间", ErrInvalidInput)
			}
			sec.AISettings.MCP.DesktopLoopbackPort = p
		}
		if sec.AISettings.MCP.DesktopLoopbackPort < 1024 || sec.AISettings.MCP.DesktopLoopbackPort > 65535 {
			sec.AISettings.MCP.DesktopLoopbackPort = DefaultMCPConfig().DesktopLoopbackPort
		}
		if in.PublicEndpointHint != nil {
			hint := strings.TrimRight(strings.TrimSpace(*in.PublicEndpointHint), "/")
			if len(hint) > 256 {
				return fmt.Errorf("%w: 公网接入地址提示过长", ErrInvalidInput)
			}
			sec.AISettings.MCP.PublicEndpointHint = hint
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	view, err := s.GetMCPConfigView()
	if err != nil {
		return nil, err
	}
	s.RecordAudit("ai.mcp_config", "mcp", fmt.Sprintf("更新外部 AI MCP 网关配置 (启用=%v, 桌面回环=%v:%d)", view.Enabled, view.DesktopLoopbackEnabled, view.DesktopLoopbackPort), clientIP, true)
	return view, nil
}

// CreateMCPToken issues a new scoped persistent MCP token (returning the raw secret ONCE).
func (s *Store) CreateMCPToken(in CreateMCPTokenInput, clientIP string) (*MCPTokenView, string, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return nil, "", fmt.Errorf("%w: 请填写 MCP Token 名称", ErrInvalidInput)
	}
	if len([]rune(name)) > 64 {
		return nil, "", fmt.Errorf("%w: Token 名称不能超过 64 个字符", ErrInvalidInput)
	}
	rawTok, prefix, err := generateRawMCPToken()
	if err != nil {
		return nil, "", err
	}
	scope := NormalizeMCPTokenScope(in.Scope)
	hint := normalizeMCPClientHint(in.ClientHint)

	allowed := make([]string, 0, len(in.AllowedServers))
	for _, sid := range in.AllowedServers {
		sid = strings.TrimSpace(sid)
		if sid != "" && !slices.Contains(allowed, sid) {
			allowed = append(allowed, sid)
		}
	}

	now := time.Now().UTC()
	tok := MCPToken{
		ID:             uuid.NewString(),
		Name:           name,
		ClientHint:     hint,
		Scope:          scope,
		TokenHash:      hashMCPToken(rawTok),
		TokenPrefix:    prefix,
		AllowedServers: allowed,
		Enabled:        true,
		CreatedAt:      now,
	}

	err = s.mutateSecrets(func(sec *SecretsState) error {
		sec.AISettings.MCP.Tokens = append([]MCPToken{tok}, sec.AISettings.MCP.Tokens...)
		// Automatically enable MCP gateway on server mode when creating the first token for smooth UX
		if !sec.AISettings.MCP.Enabled {
			sec.AISettings.MCP.Enabled = true
		}
		return nil
	})
	if err != nil {
		return nil, "", err
	}

	s.RecordAudit("ai.mcp_token_create", tok.Name, fmt.Sprintf("签发外部 AI MCP 令牌 (%s · 权限=%s)", tok.TokenPrefix, tok.Scope), clientIP, true)
	view := &MCPTokenView{
		ID:             tok.ID,
		Name:           tok.Name,
		ClientHint:     tok.ClientHint,
		Scope:          tok.Scope,
		TokenPrefix:    tok.TokenPrefix,
		AllowedServers: allowed,
		Enabled:        tok.Enabled,
		CreatedAt:      tok.CreatedAt,
	}
	return view, rawTok, nil
}

// UpdateMCPToken updates an existing MCP token's name, scope, allowlist, or enabled state.
func (s *Store) UpdateMCPToken(id string, in UpdateMCPTokenInput, clientIP string) (*MCPTokenView, error) {
	var updatedName string
	err := s.mutateSecrets(func(sec *SecretsState) error {
		for i := range sec.AISettings.MCP.Tokens {
			if sec.AISettings.MCP.Tokens[i].ID == id {
				t := sec.AISettings.MCP.Tokens[i]
				if in.Name != nil {
					n := strings.TrimSpace(*in.Name)
					if n == "" || len([]rune(n)) > 64 {
						return fmt.Errorf("%w: Token 名称不合法", ErrInvalidInput)
					}
					t.Name = n
				}
				if in.ClientHint != nil {
					t.ClientHint = normalizeMCPClientHint(*in.ClientHint)
				}
				if in.Scope != nil {
					t.Scope = NormalizeMCPTokenScope(*in.Scope)
				}
				if in.AllowedServers != nil {
					clean := make([]string, 0, len(*in.AllowedServers))
					for _, sid := range *in.AllowedServers {
						sid = strings.TrimSpace(sid)
						if sid != "" && !slices.Contains(clean, sid) {
							clean = append(clean, sid)
						}
					}
					t.AllowedServers = clean
				}
				if in.Enabled != nil {
					t.Enabled = *in.Enabled
				}
				sec.AISettings.MCP.Tokens[i] = t
				updatedName = t.Name
				return nil
			}
		}
		return ErrNotFound
	})
	if err != nil {
		return nil, err
	}
	s.RecordAudit("ai.mcp_token_update", updatedName, "更新外部 AI MCP 令牌权限或启停状态", clientIP, true)
	view, err := s.GetMCPConfigView()
	if err != nil {
		return nil, err
	}
	for _, t := range view.Tokens {
		if t.ID == id {
			cp := t
			return &cp, nil
		}
	}
	return nil, ErrNotFound
}

// DeleteMCPToken revokes and permanently deletes an MCP token.
func (s *Store) DeleteMCPToken(id, clientIP string) error {
	var deletedName string
	err := s.mutateSecrets(func(sec *SecretsState) error {
		for i, t := range sec.AISettings.MCP.Tokens {
			if t.ID == id {
				deletedName = t.Name
				sec.AISettings.MCP.Tokens = slices.Delete(sec.AISettings.MCP.Tokens, i, i+1)
				return nil
			}
		}
		return ErrNotFound
	})
	if err != nil {
		return err
	}
	s.rtMu.Lock()
	if s.aiopsRT != nil && s.aiopsRT.MCPTokenUsage != nil {
		delete(s.aiopsRT.MCPTokenUsage, id)
		s.dirtyAIOps = true
	}
	s.rtMu.Unlock()
	s.triggerFlush()
	s.RecordAudit("ai.mcp_token_delete", deletedName, "吊销并删除外部 AI MCP 令牌", clientIP, true)
	return nil
}

// AuthenticateMCPToken validates a raw Bearer token in constant time against all enabled MCP tokens.
// Returns (token, gatewayEnabled, err).
func (s *Store) AuthenticateMCPToken(rawToken string) (*MCPToken, bool, error) {
	rawToken = strings.TrimSpace(rawToken)
	if !strings.HasPrefix(rawToken, mcpTokenPrefixLit) || len(rawToken) < 24 {
		return nil, false, ErrInvalidPassword
	}
	candHash := hashMCPToken(rawToken)

	s.secMu.RLock()
	defer s.secMu.RUnlock()
	if s.secrets == nil {
		return nil, false, ErrVaultLocked
	}
	cfg := s.secrets.AISettings.MCP
	var matched *MCPToken
	for _, t := range cfg.Tokens {
		if subtle.ConstantTimeCompare([]byte(t.TokenHash), []byte(candHash)) == 1 {
			if t.Enabled {
				cp := t
				cp.AllowedServers = slices.Clone(t.AllowedServers)
				matched = &cp
			}
		}
	}
	if matched == nil {
		return nil, cfg.Enabled, ErrInvalidPassword
	}
	return matched, cfg.Enabled, nil
}

// RecordMCPTokenUsage records high-frequency token usage telemetry in aiops_runtime.json without touching secrets.enc.
func (s *Store) RecordMCPTokenUsage(tokenID, clientName, clientIP string) {
	if strings.TrimSpace(tokenID) == "" || !s.IsReady() {
		return
	}
	now := time.Now().UTC()
	s.rtMu.Lock()
	if s.aiopsRT == nil {
		s.aiopsRT = DefaultAIOpsRuntimeState(now)
	}
	if s.aiopsRT.MCPTokenUsage == nil {
		s.aiopsRT.MCPTokenUsage = make(map[string]MCPTokenRuntimeUsage)
	}
	cur := s.aiopsRT.MCPTokenUsage[tokenID]
	cur.LastUsedAt = &now
	if strings.TrimSpace(clientName) != "" {
		cur.LastClientName = strings.TrimSpace(clientName)
	}
	if strings.TrimSpace(clientIP) != "" {
		cur.LastClientIP = strings.TrimSpace(clientIP)
	}
	cur.CallCount++
	s.aiopsRT.MCPTokenUsage[tokenID] = cur
	s.dirtyAIOps = true
	s.rtMu.Unlock()
	s.triggerFlush()
}

// --- Patrol Queue Operations (aiops_runtime.json) ---

// GetPatrolRecord fetches a single PatrolRecord by ID.
func (s *Store) GetPatrolRecord(id string) (*PatrolRecord, error) {
	if !s.IsReady() {
		return nil, ErrVaultLocked
	}
	s.rtMu.RLock()
	defer s.rtMu.RUnlock()
	if s.aiopsRT == nil {
		return nil, ErrNotFound
	}
	for _, rec := range s.aiopsRT.PatrolRecords {
		if rec.ID == id {
			cp := cloneSinglePatrolRecord(rec)
			return &cp, nil
		}
	}
	return nil, ErrNotFound
}

// ListPendingExternalPatrols returns patrol records waiting for external AI analysis (pending_external or claimed).
func (s *Store) ListPendingExternalPatrols(limit int) ([]PatrolRecord, error) {
	if !s.IsReady() {
		return nil, ErrVaultLocked
	}
	s.rtMu.RLock()
	defer s.rtMu.RUnlock()
	if s.aiopsRT == nil {
		return []PatrolRecord{}, nil
	}
	out := make([]PatrolRecord, 0)
	for _, rec := range s.aiopsRT.PatrolRecords {
		if rec.AnalysisState == "pending_external" || rec.AnalysisState == "claimed" {
			out = append(out, cloneSinglePatrolRecord(rec))
			if limit > 0 && len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

// ListExpiredExternalPatrols returns pending/claimed patrol records whose ExternalDeadlineAt has passed.
func (s *Store) ListExpiredExternalPatrols(now time.Time) ([]PatrolRecord, error) {
	if !s.IsReady() {
		return nil, ErrVaultLocked
	}
	s.rtMu.RLock()
	defer s.rtMu.RUnlock()
	if s.aiopsRT == nil {
		return nil, nil
	}
	var expired []PatrolRecord
	for _, rec := range s.aiopsRT.PatrolRecords {
		if (rec.AnalysisState == "pending_external" || rec.AnalysisState == "claimed") &&
			!rec.AIAnalyzed &&
			rec.ExternalDeadlineAt != nil &&
			!now.Before(*rec.ExternalDeadlineAt) {
			expired = append(expired, cloneSinglePatrolRecord(rec))
		}
	}
	return expired, nil
}

// ClaimPatrolRecord marks a patrol record as actively claimed by an external AI client.
func (s *Store) ClaimPatrolRecord(id, clientName, clientIP string) (*PatrolRecord, error) {
	if !s.IsReady() {
		return nil, ErrVaultLocked
	}
	now := time.Now().UTC()
	claimer := strings.TrimSpace(clientName)
	if claimer == "" {
		claimer = "External MCP AI"
	}

	s.rtMu.Lock()
	if s.aiopsRT == nil {
		s.rtMu.Unlock()
		return nil, ErrNotFound
	}
	for i := range s.aiopsRT.PatrolRecords {
		if s.aiopsRT.PatrolRecords[i].ID == id {
			rec := &s.aiopsRT.PatrolRecords[i]
			if !rec.AIAnalyzed {
				rec.AnalysisState = "claimed"
				rec.ClaimedBy = claimer
				rec.ClaimedAt = &now
				s.dirtyAIOps = true
				s.appendAuditRuntimeLocked("mcp.patrol_claim", rec.ID, fmt.Sprintf("外部 AI (%s) 认领巡检分析任务", claimer), clientIP, true)
			}
			cp := cloneSinglePatrolRecord(*rec)
			s.rtMu.Unlock()
			s.triggerFlush()
			return &cp, nil
		}
	}
	s.rtMu.Unlock()
	return nil, ErrNotFound
}

// UpdatePatrolRecordAnalysis writes AI analysis results (external MCP or fallback built-in) into an existing PatrolRecord.
func (s *Store) UpdatePatrolRecordAnalysis(id string, upd PatrolAnalysisUpdate, clientIP string) (*PatrolRecord, error) {
	if !s.IsReady() {
		return nil, ErrVaultLocked
	}
	now := time.Now().UTC()
	cleanSummary := RedactSensitiveText(strings.TrimSpace(upd.AISummary))
	cleanRoot := RedactSensitiveText(strings.TrimSpace(upd.AIRootCause))
	cleanRecs := make([]string, 0, len(upd.AIRecommendations))
	for _, r := range upd.AIRecommendations {
		r = RedactSensitiveText(strings.TrimSpace(r))
		if r != "" {
			cleanRecs = append(cleanRecs, r)
		}
	}
	cleanEvidence := make([]string, 0, len(upd.DeepEvidence))
	for _, ev := range upd.DeepEvidence {
		ev = RedactSensitiveText(strings.TrimSpace(ev))
		if ev != "" {
			cleanEvidence = append(cleanEvidence, ev)
		}
	}

	s.rtMu.Lock()
	if s.aiopsRT == nil {
		s.rtMu.Unlock()
		return nil, ErrNotFound
	}
	for i := range s.aiopsRT.PatrolRecords {
		if s.aiopsRT.PatrolRecords[i].ID == id {
			rec := &s.aiopsRT.PatrolRecords[i]
			if upd.OnlyIfNotAnalyzed && rec.AIAnalyzed {
				s.rtMu.Unlock()
				return nil, fmt.Errorf("%w: 该巡检记录已完成 AI 研判", ErrInvalidInput)
			}
			rec.AIAnalyzed = true
			rec.AIAnalyzedAt = &now
			if upd.AnalysisState != "" {
				rec.AnalysisState = upd.AnalysisState
			} else {
				rec.AnalysisState = "completed"
			}
			if upd.AISource != "" {
				rec.AISource = upd.AISource
			}
			if strings.TrimSpace(upd.ExternalClient) != "" {
				rec.ExternalClient = strings.TrimSpace(upd.ExternalClient)
			}
			if strings.TrimSpace(upd.AIModel) != "" {
				rec.AIModel = strings.TrimSpace(upd.AIModel)
			}
			if cleanSummary != "" {
				rec.AISummary = cleanSummary
			}
			if cleanRoot != "" {
				rec.AIRootCause = cleanRoot
			}
			if len(cleanRecs) > 0 {
				rec.AIRecommendations = cleanRecs
			}
			if len(cleanEvidence) > 0 {
				rec.DeepEvidence = cleanEvidence
			}
			if upd.AIWebhookNotified != nil {
				rec.AIWebhookNotified = *upd.AIWebhookNotified
				if *upd.AIWebhookNotified {
					rec.WebhookNotified = true
				}
			}
			if upd.MarkUnread != nil {
				rec.Unread = *upd.MarkUnread
			}
			s.dirtyAIOps = true
			sourceLabel := rec.ExternalClient
			if sourceLabel == "" {
				sourceLabel = rec.AIModel
			}
			s.appendAuditRuntimeLocked(
				"ai.patrol_analysis_submit",
				rec.ID,
				fmt.Sprintf("回写巡检 AI 研判报告 (来源=%s, 客户端=%s)", rec.AISource, sourceLabel),
				clientIP,
				true,
			)
			cp := cloneSinglePatrolRecord(*rec)
			s.rtMu.Unlock()
			s.triggerFlush()
			return &cp, nil
		}
	}
	s.rtMu.Unlock()
	return nil, ErrNotFound
}

// MarkPatrolWebhookNotified marks an existing patrol record as webhook-notified without
// mutating AIAnalyzedAt or emitting a duplicate analysis audit entry.
func (s *Store) MarkPatrolWebhookNotified(id string) {
	if !s.IsReady() || strings.TrimSpace(id) == "" {
		return
	}
	s.rtMu.Lock()
	changed := false
	if s.aiopsRT != nil {
		for i := range s.aiopsRT.PatrolRecords {
			if s.aiopsRT.PatrolRecords[i].ID == id {
				s.aiopsRT.PatrolRecords[i].AIWebhookNotified = true
				s.aiopsRT.PatrolRecords[i].WebhookNotified = true
				s.dirtyAIOps = true
				changed = true
				break
			}
		}
	}
	s.rtMu.Unlock()
	if changed {
		s.triggerFlush()
	}
}

// --- External AI HITL Approval Queue (aiops_runtime.json) ---

// ListExternalApprovals returns external AI change plans filtered by optional status
// ("pending"/"running"/"active"/"completed"/"partial_failed"/"failed"/"cancelled"/"rejected"/"approved"/"all").
func (s *Store) ListExternalApprovals(status string, limit int) ([]ExternalApproval, int, error) {
	if !s.IsReady() {
		return nil, 0, ErrVaultLocked
	}
	s.rtMu.RLock()
	defer s.rtMu.RUnlock()
	if s.aiopsRT == nil {
		return []ExternalApproval{}, 0, nil
	}
	pending := 0
	out := make([]ExternalApproval, 0, len(s.aiopsRT.ExternalApprovals))
	filter := strings.ToLower(strings.TrimSpace(status))
	for _, raw := range s.aiopsRT.ExternalApprovals {
		ap := cloneExternalApproval(raw)
		NormalizeExternalApproval(&ap)
		if ap.Status == "pending" {
			pending++
		}
		if !matchExternalApprovalStatus(ap.Status, filter) {
			continue
		}
		if limit <= 0 || len(out) < limit {
			out = append(out, ap)
		}
	}
	return out, pending, nil
}

func matchExternalApprovalStatus(actual, filter string) bool {
	if filter == "" || filter == "all" {
		return true
	}
	switch filter {
	case "active":
		return actual == "pending" || actual == "running"
	case "approved":
		return actual == "completed" || actual == "partial_failed" || actual == "failed" || actual == "cancelled" || actual == "running" || actual == "approved"
	default:
		return actual == filter
	}
}

// GetExternalApproval fetches a single external HITL approval plan by ID.
func (s *Store) GetExternalApproval(id string) (*ExternalApproval, error) {
	if !s.IsReady() {
		return nil, ErrVaultLocked
	}
	s.rtMu.RLock()
	defer s.rtMu.RUnlock()
	if s.aiopsRT == nil {
		return nil, ErrNotFound
	}
	for _, ap := range s.aiopsRT.ExternalApprovals {
		if ap.ID == id {
			cp := cloneExternalApproval(ap)
			NormalizeExternalApproval(&cp)
			return &cp, nil
		}
	}
	return nil, ErrNotFound
}

// CreateExternalApproval enqueues a new external AI change plan awaiting admin approval.
func (s *Store) CreateExternalApproval(ap ExternalApproval, clientIP string) (*ExternalApproval, error) {
	if !s.IsReady() {
		return nil, ErrVaultLocked
	}
	now := time.Now().UTC()
	if ap.ID == "" {
		ap.ID = uuid.NewString()
	}
	if ap.CreatedAt.IsZero() {
		ap.CreatedAt = now
	}
	ap.Status = "pending"
	ap.Title = RedactSensitiveText(strings.TrimSpace(ap.Title))
	ap.Reason = RedactSensitiveText(strings.TrimSpace(ap.Reason))
	for i := range ap.Steps {
		ap.Steps[i].Title = RedactSensitiveText(strings.TrimSpace(ap.Steps[i].Title))
		ap.Steps[i].Reason = RedactSensitiveText(strings.TrimSpace(ap.Steps[i].Reason))
	}
	NormalizeExternalApproval(&ap)

	s.rtMu.Lock()
	if s.aiopsRT == nil {
		s.aiopsRT = DefaultAIOpsRuntimeState(now)
	}
	s.aiopsRT.ExternalApprovals = append([]ExternalApproval{cloneExternalApproval(ap)}, s.aiopsRT.ExternalApprovals...)
	if len(s.aiopsRT.ExternalApprovals) > maxExternalApprovals {
		s.aiopsRT.ExternalApprovals = s.aiopsRT.ExternalApprovals[:maxExternalApprovals]
	}
	s.dirtyAIOps = true
	auditDetail := fmt.Sprintf("外部 AI (%s) 提交待审批变更计划「%s」(%d 步, 可执行 %d, 已拦截 %d): %.80s",
		ap.ClientName, ap.Title, ap.TotalSteps, ap.ExecutableSteps, ap.BlockedSteps, ap.Reason)
	s.appendAuditRuntimeLocked(
		"mcp.approval_propose",
		strings.Join(ap.ServerNames, ","),
		auditDetail,
		clientIP,
		true,
	)
	s.rtMu.Unlock()
	s.triggerFlush()
	cp := cloneExternalApproval(ap)
	return &cp, nil
}

// UpdateExternalApproval updates an existing external HITL approval record after admin decision/execution.
func (s *Store) UpdateExternalApproval(ap ExternalApproval) error {
	if !s.IsReady() {
		return ErrVaultLocked
	}
	NormalizeExternalApproval(&ap)
	s.rtMu.Lock()
	if s.aiopsRT == nil {
		s.rtMu.Unlock()
		return ErrNotFound
	}
	for i := range s.aiopsRT.ExternalApprovals {
		if s.aiopsRT.ExternalApprovals[i].ID == ap.ID {
			s.aiopsRT.ExternalApprovals[i] = cloneExternalApproval(ap)
			s.dirtyAIOps = true
			s.rtMu.Unlock()
			s.triggerFlush()
			return nil
		}
	}
	s.rtMu.Unlock()
	return ErrNotFound
}

// CountExternalPending returns counts of pending external patrol tasks and pending external HITL approvals for UI badges.
func (s *Store) CountExternalPending() (pendingPatrols int, pendingApprovals int) {
	if !s.IsReady() {
		return 0, 0
	}
	s.rtMu.RLock()
	defer s.rtMu.RUnlock()
	if s.aiopsRT == nil {
		return 0, 0
	}
	for _, rec := range s.aiopsRT.PatrolRecords {
		if rec.AnalysisState == "pending_external" || rec.AnalysisState == "claimed" {
			pendingPatrols++
		}
	}
	for _, ap := range s.aiopsRT.ExternalApprovals {
		if ap.Status == "pending" {
			pendingApprovals++
		}
	}
	return pendingPatrols, pendingApprovals
}

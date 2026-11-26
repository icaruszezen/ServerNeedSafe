package aiops

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/icaruszezen/ServerNeedSafe/internal/sshmanager"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

// ExternalPatrolReportInput submits a root-cause report from an external AI client (Claude Code / Codex / Antigravity / Cursor).
type ExternalPatrolReportInput struct {
	PatrolRecordID  string
	Summary         string
	RootCause       string
	Recommendations []string
	DeepEvidence    []string
	ExternalClient  string
	AIModel         string
	DispatchWebhook *bool
	ClientIP        string
}

// ExternalApprovalProposalInput encapsulates a mutating SSH command or SFTP file edit submitted via MCP for HITL approval.
type ExternalApprovalProposalInput struct {
	PatrolRecordID string
	TokenID        string
	TokenName      string
	ClientName     string
	ToolName       string // "exec_ssh_command" or "sftp_write_file"
	ServerIDs      []string
	Command        string
	FilePath       string
	NewContent     string
	Reason         string
	ClientIP       string
}

// SubmitExternalPatrolReport persists an external AI's root-cause analysis onto a PatrolRecord
// and optionally dispatches the enriched Stage 2 AI report to configured Webhooks.
func (s *Service) SubmitExternalPatrolReport(ctx context.Context, in ExternalPatrolReportInput) (*vault.PatrolRecord, error) {
	if !s.store.IsReady() {
		return nil, vault.ErrVaultLocked
	}
	recID := strings.TrimSpace(in.PatrolRecordID)
	if recID == "" {
		return nil, fmt.Errorf("%w: patrol_record_id 不能为空", vault.ErrInvalidInput)
	}
	if strings.TrimSpace(in.Summary) == "" {
		return nil, fmt.Errorf("%w: summary 巡检摘要不能为空", vault.ErrInvalidInput)
	}
	existing, err := s.store.GetPatrolRecord(recID)
	if err != nil {
		return nil, err
	}

	clientName := strings.TrimSpace(in.ExternalClient)
	if clientName == "" {
		clientName = "External MCP AI"
	}
	modelName := strings.TrimSpace(in.AIModel)
	if modelName == "" {
		modelName = clientName
	}

	markUnread := existing.Status != "healthy"
	updated, err := s.store.UpdatePatrolRecordAnalysis(recID, vault.PatrolAnalysisUpdate{
		AnalysisState:     "completed",
		AISource:          "external_mcp",
		ExternalClient:    clientName,
		AIModel:           modelName,
		AISummary:         in.Summary,
		AIRootCause:       in.RootCause,
		AIRecommendations: in.Recommendations,
		DeepEvidence:      in.DeepEvidence,
		MarkUnread:        &markUnread,
	}, in.ClientIP)
	if err != nil {
		return nil, err
	}

	shouldNotify := updated.Status != "healthy"
	if in.DispatchWebhook != nil {
		shouldNotify = *in.DispatchWebhook
	}
	if shouldNotify {
		if cfg, cErr := s.store.GetPatrolConfigSecret(); cErr == nil && cfg != nil && len(cfg.Webhooks) > 0 {
			notified := s.dispatchPatrolWebhooks(ctx, cfg.Webhooks, *updated)
			if notified {
				updated, _ = s.store.UpdatePatrolRecordAnalysis(recID, vault.PatrolAnalysisUpdate{
					AnalysisState:     updated.AnalysisState,
					AISource:          updated.AISource,
					ExternalClient:    updated.ExternalClient,
					AIModel:           updated.AIModel,
					AIWebhookNotified: &notified,
				}, in.ClientIP)
			}
		}
	}

	s.notifyPersist()
	return updated, nil
}

// CreateExternalApprovalProposal validates, safety-checks, computes Unified Diff if applicable,
// enqueues a HITL approval item, and optionally notifies configured Webhooks.
// External MCP mutations NEVER auto-execute remotely.
func (s *Service) CreateExternalApprovalProposal(ctx context.Context, in ExternalApprovalProposalInput) (*vault.ExternalApproval, error) {
	if !s.store.IsReady() {
		return nil, vault.ErrVaultLocked
	}
	if len(in.ServerIDs) == 0 {
		return nil, fmt.Errorf("%w: 至少需要指定一台目标服务器 server_id", vault.ErrInvalidInput)
	}

	nameLookup := s.serverNameLookup()
	serverNames := make([]string, 0, len(in.ServerIDs))
	for _, sid := range in.ServerIDs {
		name, ok := nameLookup[sid]
		if !ok {
			return nil, fmt.Errorf("%w: 目标服务器 %s 不存在", vault.ErrNotFound, sid)
		}
		serverNames = append(serverNames, name)
	}

	clientName := nonEmpty(strings.TrimSpace(in.ClientName), "External MCP AI")
	ap := vault.ExternalApproval{
		ID:             uuid.NewString(),
		PatrolRecordID: strings.TrimSpace(in.PatrolRecordID),
		TokenID:        in.TokenID,
		TokenName:      in.TokenName,
		ClientName:     clientName,
		ToolName:       in.ToolName,
		ServerIDs:      slices.Clone(in.ServerIDs),
		ServerNames:    serverNames,
		RiskLevel:      "high",
		Reason:         strings.TrimSpace(in.Reason),
		Status:         "pending",
		CreatedAt:      time.Now().UTC(),
	}

	switch in.ToolName {
	case "exec_ssh_command":
		cmd := strings.TrimSpace(in.Command)
		if cmd == "" {
			return nil, fmt.Errorf("%w: 拟执行的命令不能为空", vault.ErrInvalidInput)
		}
		risk, why := ClassifyCommand(cmd)
		if risk == RiskBlocked {
			s.store.RecordAudit("mcp.blocked", strings.Join(serverNames, ","), fmt.Sprintf("外部 AI (%s) 提议的高危命令被硬熔断拦截: %.80s (%s)", clientName, cmd, why), in.ClientIP, false)
			return nil, fmt.Errorf("安全熔断器硬拦截: %s", why)
		}
		if risk == RiskReadOnly {
			ap.RiskLevel = "medium"
		}
		if ap.Reason == "" {
			ap.Reason = why
		}
		ap.Command = cmd

	case "sftp_write_file":
		if len(in.ServerIDs) != 1 {
			return nil, fmt.Errorf("%w: 文件修改提案每次仅支持指定一台目标服务器", vault.ErrInvalidInput)
		}
		cleanPath := strings.TrimSpace(in.FilePath)
		if cleanPath == "" {
			return nil, fmt.Errorf("%w: 远程文件路径 path 不能为空", vault.ErrInvalidInput)
		}
		if cleanPath == "/etc/shadow" || cleanPath == "/etc/gshadow" || cleanPath == "/etc/passwd" || cleanPath == "/etc/sudoers" {
			s.store.RecordAudit("mcp.blocked", serverNames[0]+":"+cleanPath, fmt.Sprintf("外部 AI (%s) 尝试提议覆写系统核心鉴权文件 %s 被硬拦截", clientName, cleanPath), in.ClientIP, false)
			return nil, fmt.Errorf("安全熔断器禁止 AI 修改系统核心鉴权文件 (%s)", cleanPath)
		}
		oldContent, _ := s.ssh.SFTPReadText(in.ServerIDs[0], cleanPath, in.ClientIP)
		ap.FilePath = cleanPath
		ap.NewContent = in.NewContent
		ap.DiffPreview = BuildUnifiedDiff(cleanPath, oldContent, in.NewContent)
		if ap.Reason == "" {
			ap.Reason = fmt.Sprintf("修改远程配置文件 %s", cleanPath)
		}

	default:
		return nil, fmt.Errorf("%w: 不支持的外部审批工具类型 %s", vault.ErrInvalidInput, in.ToolName)
	}

	saved, err := s.store.CreateExternalApproval(ap, in.ClientIP)
	if err != nil {
		return nil, err
	}

	if cfg, cErr := s.store.GetPatrolConfigSecret(); cErr == nil && cfg != nil && cfg.NotifyPendingApprovals && len(cfg.Webhooks) > 0 {
		notified := false
		for _, wh := range cfg.Webhooks {
			if !wh.Enabled || wh.URL == "" {
				continue
			}
			if wErr := SendExternalApprovalWebhook(ctx, s.llm.Transport(), wh, *saved); wErr == nil {
				notified = true
			}
		}
		if notified {
			saved.WebhookNotified = true
			_ = s.store.UpdateExternalApproval(*saved)
		}
	}

	s.notifyPersist()
	return saved, nil
}

// ResolveExternalApproval processes an administrator's Approve/Reject decision on an external MCP HITL proposal.
// When approved, the command or SFTP write executes immediately, records audit & approved-change memory, and stores
// the execution output so the external AI can query get_approval_status for post-fix verification.
func (s *Service) ResolveExternalApproval(ctx context.Context, approvalID string, approve bool, clientIP string) (*vault.ExternalApproval, error) {
	if !s.store.IsReady() {
		return nil, vault.ErrVaultLocked
	}
	ap, err := s.store.GetExternalApproval(strings.TrimSpace(approvalID))
	if err != nil {
		return nil, err
	}
	if ap.Status != "pending" {
		return nil, fmt.Errorf("该外部 AI 变更审批项已处理 (%s)", ap.Status)
	}

	now := time.Now().UTC()
	ap.ResolvedAt = &now

	if !approve {
		ap.Status = "rejected"
		if err := s.store.UpdateExternalApproval(*ap); err != nil {
			return nil, err
		}
		s.store.RecordAudit("mcp.approval_reject", strings.Join(ap.ServerNames, ","), fmt.Sprintf("管理员拒绝外部 AI (%s) 变更请求: %s", ap.ClientName, ap.Reason), clientIP, true)
		s.notifyPersist()
		return ap, nil
	}

	start := time.Now()
	var out string
	var execErr error

	switch ap.ToolName {
	case "exec_ssh_command":
		risk, why := ClassifyCommand(ap.Command)
		if risk == RiskBlocked {
			execErr = fmt.Errorf("安全熔断器拦截: %s", why)
		} else {
			results := s.ssh.BatchExecute(ap.ServerIDs, ap.Command, 45*time.Second, clientIP)
			out = formatBatchExecResults(results)
			for _, r := range results {
				if r.Error != "" || r.ExitCode != 0 {
					execErr = fmt.Errorf("部分主机执行返回非零退出码或连接错误")
					break
				}
			}
			s.store.RecordAudit("mcp.approved_exec", strings.Join(ap.ServerNames, ","), fmt.Sprintf("管理员批准执行外部 AI (%s) 命令: %.75s", ap.ClientName, ap.Command), clientIP, execErr == nil)
		}

	case "sftp_write_file":
		if len(ap.ServerIDs) == 0 {
			execErr = fmt.Errorf("缺少目标服务器 ID")
		} else if ap.FilePath == "/etc/shadow" || ap.FilePath == "/etc/gshadow" || ap.FilePath == "/etc/passwd" || ap.FilePath == "/etc/sudoers" {
			execErr = fmt.Errorf("安全熔断器禁止修改系统核心鉴权文件 (%s)", ap.FilePath)
		} else if err := s.ssh.SFTPWriteText(ap.ServerIDs[0], ap.FilePath, ap.NewContent, clientIP); err != nil {
			execErr = err
		} else {
			out = fmt.Sprintf("已写入文件 %s\n%s", ap.FilePath, ap.DiffPreview)
			s.store.RecordAudit("mcp.approved_sftp_write", strings.Join(ap.ServerNames, ",")+":"+ap.FilePath, fmt.Sprintf("管理员审阅 Diff 后批准外部 AI (%s) 修改远程文件", ap.ClientName), clientIP, true)
		}

	default:
		execErr = fmt.Errorf("不支持的审批工具类型: %s", ap.ToolName)
	}

	ap.Status = "approved"
	ap.DurationMs = time.Since(start).Milliseconds()
	ap.ExecutionOut = truncateStr(out, 12000)
	if execErr != nil {
		ap.ExecutionError = execErr.Error()
	}

	if err := s.store.UpdateExternalApproval(*ap); err != nil {
		return nil, err
	}

	if execErr == nil {
		s.maybeRecordExternalApprovedChangeMemory(*ap, clientIP)
	}
	s.notifyPersist()
	return ap, nil
}

func (s *Service) maybeRecordExternalApprovedChangeMemory(ap vault.ExternalApproval, clientIP string) {
	memCfg, err := s.store.GetAIMemoryConfig()
	if err != nil || !memCfg.AutoRecordApprovedChanges {
		return
	}
	targets := nonEmpty(strings.Join(ap.ServerNames, ", "), "目标主机")
	var title string
	var content strings.Builder
	if ap.ToolName == "sftp_write_file" {
		title = fmt.Sprintf("外部AI变更：%s (%s)", ap.FilePath, targets)
		content.WriteString(fmt.Sprintf("管理员批准外部 AI (%s) 在 [%s] 修改了远程配置文件 `%s`。\n变更说明：%s", ap.ClientName, targets, ap.FilePath, nonEmpty(ap.Reason, "无")))
		if strings.TrimSpace(ap.DiffPreview) != "" {
			diffBrief, _ := truncateRunes(strings.TrimSpace(ap.DiffPreview), 420)
			content.WriteString("\n变更摘要：\n" + diffBrief)
		}
	} else {
		cmdBrief, _ := truncateRunes(strings.TrimSpace(ap.Command), 64)
		title = fmt.Sprintf("外部AI变更：%s (%s)", cmdBrief, targets)
		content.WriteString(fmt.Sprintf("管理员批准外部 AI (%s) 在 [%s] 执行了命令：`%s`\n变更说明：%s", ap.ClientName, targets, strings.TrimSpace(ap.Command), nonEmpty(ap.Reason, "无")))
	}
	scope := "global"
	if len(ap.ServerIDs) > 0 {
		scope = "server"
	}
	_, _ = s.store.UpsertAIMemory(vault.AIMemoryEntry{
		Scope:      scope,
		ServerIDs:  ap.ServerIDs,
		Category:   "change",
		Title:      title,
		Content:    content.String(),
		Tags:       []string{"MCP审批", ap.ClientName, ap.ToolName},
		Importance: 4,
		Source:     "approval",
	}, true, clientIP)
}

// SearchMemory exposes the unified hybrid memory search to internal callers such as the MCP gateway.
func (s *Service) SearchMemory(query, serverID, category string, limit int) (string, []string) {
	if limit <= 0 || limit > 20 {
		limit = 8
	}
	out, hitIDs := s.executeSearchMemory(query, serverID, category, limit)
	if len(hitIDs) > 0 {
		s.store.TouchAIMemoryUsage(hitIDs)
	}
	return out, hitIDs
}

// GetRunbookText exposes formatted Runbook SOP retrieval to internal callers such as the MCP gateway.
func (s *Service) GetRunbookText(runbookID, query string) (string, bool) {
	return s.executeGetRunbook(runbookID, query)
}

// FormatBatchExecOutput exposes consistent SSH batch result formatting for MCP read-only forensics.
func FormatBatchExecOutput(results []sshmanager.BatchExecResult) string {
	return formatBatchExecResults(results)
}

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

const (
	MaxExternalPlanSteps       = 20
	DefaultExternalStepTimeout = 45
	MaxExternalStepTimeout     = 300
)

// ExternalApprovalStepInput defines one ordered SSH command or SFTP file edit inside an external MCP change plan.
type ExternalApprovalStepInput struct {
	Title           string
	ToolName        string // "exec_ssh_command" or "sftp_write_file"
	ServerIDs       []string
	Command         string
	TimeoutSec      int
	FilePath        string
	NewContent      string
	Reason          string
	ContinueOnError bool
}

// ExternalChangePlanInput encapsulates an ordered multi-step change plan submitted via MCP for HITL approval.
type ExternalChangePlanInput struct {
	Title          string
	Reason         string
	PatrolRecordID string
	TokenID        string
	TokenName      string
	ClientName     string
	Steps          []ExternalApprovalStepInput
	ClientIP       string
}

// ResolveExternalApprovalInput captures an administrator's Approve/Reject decision and optional per-step selection.
type ResolveExternalApprovalInput struct {
	Approve         bool
	SelectedStepIDs *[]string // nil => select all non-blocked steps; non-nil => execute only listed non-blocked steps
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
		var webhooks []vault.WebhookChannel
		if cfg, cErr := s.store.GetPatrolConfigSecret(); cErr == nil && cfg != nil {
			webhooks = cfg.Webhooks
		}
		notified := s.dispatchPatrolWebhooks(ctx, webhooks, *updated)
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

	s.notifyPersist()
	return updated, nil
}

// CreateExternalChangePlan validates an ordered list of SSH/SFTP steps, marks safety-blocked steps as locked
// (never executable, visible to admin in red), computes chained Unified Diffs for SFTP edits, enqueues a single
// HITL change plan, and optionally sends one aggregated Webhook notification.
// External MCP mutations NEVER auto-execute remotely.
func (s *Service) CreateExternalChangePlan(ctx context.Context, in ExternalChangePlanInput) (*vault.ExternalApproval, error) {
	if !s.store.IsReady() {
		return nil, vault.ErrVaultLocked
	}
	if len(in.Steps) == 0 {
		return nil, fmt.Errorf("%w: steps 变更步骤列表不能为空，至少包含 1 个步骤", vault.ErrInvalidInput)
	}
	if len(in.Steps) > MaxExternalPlanSteps {
		return nil, fmt.Errorf("%w: 单次变更计划最多包含 %d 个步骤（当前 %d 步）", vault.ErrInvalidInput, MaxExternalPlanSteps, len(in.Steps))
	}

	nameLookup := s.serverNameLookup()
	clientName := nonEmpty(strings.TrimSpace(in.ClientName), "External MCP AI")
	stagedFiles := make(map[string]string) // key: serverID + "\x00" + cleanPath -> latest proposed content
	steps := make([]vault.ExternalApprovalStep, 0, len(in.Steps))

	for idx, stepIn := range in.Steps {
		stepNum := idx + 1
		cleanSIDs := make([]string, 0, len(stepIn.ServerIDs))
		for _, sid := range stepIn.ServerIDs {
			sid = strings.TrimSpace(sid)
			if sid != "" && !slices.Contains(cleanSIDs, sid) {
				cleanSIDs = append(cleanSIDs, sid)
			}
		}
		if len(cleanSIDs) == 0 {
			return nil, fmt.Errorf("%w: 第 %d 步至少需要指定一台目标服务器 server_id", vault.ErrInvalidInput, stepNum)
		}
		stepServerNames := make([]string, 0, len(cleanSIDs))
		for _, sid := range cleanSIDs {
			name, ok := nameLookup[sid]
			if !ok {
				return nil, fmt.Errorf("%w: 第 %d 步的目标服务器 %s 不存在", vault.ErrNotFound, stepNum, sid)
			}
			stepServerNames = append(stepServerNames, name)
		}

		st := vault.ExternalApprovalStep{
			ID:              uuid.NewString(),
			Index:           stepNum,
			Title:           strings.TrimSpace(stepIn.Title),
			ToolName:        strings.TrimSpace(stepIn.ToolName),
			ServerIDs:       cleanSIDs,
			ServerNames:     stepServerNames,
			Reason:          strings.TrimSpace(stepIn.Reason),
			ContinueOnError: stepIn.ContinueOnError,
		}

		switch st.ToolName {
		case "exec_ssh_command":
			cmd := strings.TrimSpace(stepIn.Command)
			if cmd == "" {
				return nil, fmt.Errorf("%w: 第 %d 步拟执行的 SSH 命令不能为空", vault.ErrInvalidInput, stepNum)
			}
			timeoutSec := stepIn.TimeoutSec
			if timeoutSec <= 0 {
				timeoutSec = DefaultExternalStepTimeout
			} else if timeoutSec > MaxExternalStepTimeout {
				timeoutSec = MaxExternalStepTimeout
			}
			st.Command = cmd
			st.TimeoutSec = timeoutSec

			risk, why := ClassifyCommand(cmd)
			if risk == RiskBlocked {
				st.RiskLevel = "blocked"
				st.Blocked = true
				st.BlockedReason = why
				st.Selected = false
				st.Status = "blocked"
				s.store.RecordAudit(
					"mcp.blocked",
					strings.Join(stepServerNames, ","),
					fmt.Sprintf("外部 AI (%s) 变更计划第 %d 步高危命令被硬熔断锁定: %.80s (%s)", clientName, stepNum, cmd, why),
					in.ClientIP,
					false,
				)
			} else {
				st.RiskLevel = "high"
				if risk == RiskReadOnly {
					st.RiskLevel = "medium"
				}
				st.Selected = true
				st.Status = "pending"
			}
			if st.Reason == "" {
				st.Reason = why
			}
			if st.Title == "" {
				brief, _ := truncateRunes(cmd, 48)
				st.Title = brief
			}

		case "sftp_write_file":
			if len(cleanSIDs) != 1 {
				return nil, fmt.Errorf("%w: 第 %d 步文件修改仅支持指定一台目标服务器", vault.ErrInvalidInput, stepNum)
			}
			cleanPath := strings.TrimSpace(stepIn.FilePath)
			if cleanPath == "" {
				return nil, fmt.Errorf("%w: 第 %d 步远程文件路径 path 不能为空", vault.ErrInvalidInput, stepNum)
			}
			st.FilePath = cleanPath
			if IsBlockedWritePath(cleanPath) {
				why := fmt.Sprintf("安全熔断器禁止 AI 修改系统核心鉴权或保险库文件 (%s)", cleanPath)
				st.RiskLevel = "blocked"
				st.Blocked = true
				st.BlockedReason = why
				st.Selected = false
				st.Status = "blocked"
				s.store.RecordAudit(
					"mcp.blocked",
					stepServerNames[0]+":"+cleanPath,
					fmt.Sprintf("外部 AI (%s) 变更计划第 %d 步尝试修改受保护文件 %s 被硬熔断锁定", clientName, stepNum, cleanPath),
					in.ClientIP,
					false,
				)
			} else {
				fileKey := cleanSIDs[0] + "\x00" + cleanPath
				oldContent, hasStaged := stagedFiles[fileKey]
				if !hasStaged {
					oldContent, _ = s.ssh.SFTPReadText(cleanSIDs[0], cleanPath, in.ClientIP)
				}
				st.NewContent = stepIn.NewContent
				st.DiffPreview = BuildUnifiedDiff(cleanPath, oldContent, stepIn.NewContent)
				stagedFiles[fileKey] = stepIn.NewContent
				st.RiskLevel = "high"
				st.Selected = true
				st.Status = "pending"
			}
			if st.Reason == "" {
				st.Reason = fmt.Sprintf("修改远程配置文件 %s", cleanPath)
			}
			if st.Title == "" {
				st.Title = fmt.Sprintf("修改配置 %s", cleanPath)
			}

		default:
			return nil, fmt.Errorf("%w: 第 %d 步包含不支持的操作类型 %q（仅支持 exec_ssh_command 或 sftp_write_file）", vault.ErrInvalidInput, stepNum, st.ToolName)
		}

		steps = append(steps, st)
	}

	planTitle := strings.TrimSpace(in.Title)
	if planTitle == "" {
		if len(steps) == 1 {
			planTitle = steps[0].Title
		} else {
			planTitle = fmt.Sprintf("%d 步变更执行计划", len(steps))
		}
	}
	planReason := strings.TrimSpace(in.Reason)
	if planReason == "" && len(steps) > 0 {
		planReason = steps[0].Reason
	}

	ap := vault.ExternalApproval{
		ID:             uuid.NewString(),
		Title:          planTitle,
		PatrolRecordID: strings.TrimSpace(in.PatrolRecordID),
		TokenID:        in.TokenID,
		TokenName:      in.TokenName,
		ClientName:     clientName,
		ToolName:       "change_plan",
		Reason:         planReason,
		Steps:          steps,
		Status:         "pending",
		CreatedAt:      time.Now().UTC(),
	}
	ap.RecalculateSummary()

	saved, err := s.store.CreateExternalApproval(ap, in.ClientIP)
	if err != nil {
		return nil, err
	}

	notified := false
	if cfg, cErr := s.store.GetPatrolConfigSecret(); cErr == nil && cfg != nil && cfg.NotifyPendingApprovals && len(cfg.Webhooks) > 0 {
		for _, wh := range cfg.Webhooks {
			if !wh.Enabled || wh.URL == "" {
				continue
			}
			if wErr := SendExternalApprovalWebhook(ctx, s.llm.Transport(), wh, *saved); wErr == nil {
				notified = true
			}
		}
	}
	s.mu.Lock()
	apHook := s.approvalNotifyHook
	s.mu.Unlock()
	if apHook != nil && apHook(ctx, *saved) {
		notified = true
	}
	if notified {
		saved.WebhookNotified = true
		_ = s.store.UpdateExternalApproval(*saved)
	}

	s.notifyPersist()
	return saved, nil
}

// ResolveExternalApproval processes an administrator's Approve/Reject decision on an external MCP change plan.
// Rejecting transitions the plan immediately to "rejected".
// Approving validates selected non-blocked steps, marks the plan "running", and launches a background goroutine
// that executes selected steps strictly in AI-submitted order while persisting real-time per-step status/output.
func (s *Service) ResolveExternalApproval(ctx context.Context, approvalID string, in ResolveExternalApprovalInput, clientIP string) (*vault.ExternalApproval, error) {
	if !s.store.IsReady() {
		return nil, vault.ErrVaultLocked
	}
	trimmedID := strings.TrimSpace(approvalID)
	unlock := s.lockExternalApproval(trimmedID)

	ap, err := s.store.GetExternalApproval(trimmedID)
	if err != nil {
		unlock()
		return nil, err
	}
	if ap.Status != "pending" {
		unlock()
		return nil, fmt.Errorf("%w: 该外部 AI 变更计划已处理 (%s)", vault.ErrInvalidInput, ap.Status)
	}

	now := time.Now().UTC()

	if !in.Approve {
		ap.Status = "rejected"
		ap.ResolvedAt = &now
		for i := range ap.Steps {
			if !ap.Steps[i].Blocked {
				ap.Steps[i].Selected = false
				ap.Steps[i].Status = "rejected"
			}
		}
		ap.RecalculateSummary()
		if err := s.store.UpdateExternalApproval(*ap); err != nil {
			unlock()
			return nil, err
		}
		s.store.RecordAudit(
			"mcp.approval_reject",
			strings.Join(ap.ServerNames, ","),
			fmt.Sprintf("管理员拒绝外部 AI (%s) 变更计划「%s」(%d 步): %s", ap.ClientName, ap.Title, ap.TotalSteps, ap.Reason),
			clientIP,
			true,
		)
		unlock()
		s.notifyExternalApprovalChanged(trimmedID)
		s.notifyPersist()
		return ap, nil
	}

	if ap.ExecutableSteps == 0 {
		unlock()
		return nil, fmt.Errorf("%w: 该变更计划中所有步骤均触发安全熔断被锁定，无法批准执行，请拒绝此计划", vault.ErrInvalidInput)
	}

	// Build selection set while strictly excluding any blocked step (defense-in-depth).
	selectedSet := make(map[string]bool, len(ap.Steps))
	if in.SelectedStepIDs == nil {
		for _, st := range ap.Steps {
			if !st.Blocked {
				selectedSet[st.ID] = true
			}
		}
	} else {
		for _, id := range *in.SelectedStepIDs {
			selectedSet[strings.TrimSpace(id)] = true
		}
	}

	selectedCount := 0
	for i := range ap.Steps {
		st := &ap.Steps[i]
		if st.Blocked {
			st.Selected = false
			st.Status = "blocked"
			continue
		}
		if selectedSet[st.ID] {
			st.Selected = true
			st.Status = "pending"
			selectedCount++
		} else {
			st.Selected = false
			st.Status = "skipped"
			st.ExecutionError = "管理员审批前取消勾选，已跳过"
		}
	}
	if selectedCount == 0 {
		unlock()
		return nil, fmt.Errorf("%w: 请至少勾选 1 个可执行步骤后再批准，或直接拒绝整份计划", vault.ErrInvalidInput)
	}

	ap.Status = "running"
	ap.StartedAt = &now
	ap.ResolvedAt = nil
	ap.ExecutionOut = ""
	ap.ExecutionError = ""
	ap.RecalculateSummary()

	if err := s.store.UpdateExternalApproval(*ap); err != nil {
		unlock()
		return nil, err
	}
	s.store.RecordAudit(
		"mcp.approval_start",
		strings.Join(ap.ServerNames, ","),
		fmt.Sprintf("管理员批准外部 AI (%s) 变更计划「%s」，开始按序执行 %d/%d 步", ap.ClientName, ap.Title, selectedCount, ap.TotalSteps),
		clientIP,
		true,
	)

	runCtx, cancel := context.WithCancel(context.Background())
	s.registerExternalExecCancel(trimmedID, cancel)
	s.extExecWG.Add(1)
	go s.runExternalApprovalPlan(runCtx, cancel, trimmedID, clientIP)

	unlock()
	s.notifyExternalApprovalChanged(trimmedID)
	s.notifyPersist()
	return ap, nil
}

// CancelExternalApproval cancels an actively running external MCP change plan and marks remaining steps cancelled.
func (s *Service) CancelExternalApproval(approvalID string, clientIP string) (*vault.ExternalApproval, error) {
	if !s.store.IsReady() {
		return nil, vault.ErrVaultLocked
	}
	trimmedID := strings.TrimSpace(approvalID)
	ap, err := s.store.GetExternalApproval(trimmedID)
	if err != nil {
		return nil, err
	}
	if ap.Status != "running" {
		return nil, fmt.Errorf("%w: 该变更计划当前未在执行中 (%s)", vault.ErrInvalidInput, ap.Status)
	}

	ch, unsub := s.subscribeExternalApproval(trimmedID)
	defer unsub()

	invoked := s.invokeExternalExecCancel(trimmedID)
	s.store.RecordAudit(
		"mcp.approval_cancel",
		strings.Join(ap.ServerNames, ","),
		fmt.Sprintf("管理员请求中止正在执行的外部 AI (%s) 变更计划「%s」", ap.ClientName, ap.Title),
		clientIP,
		true,
	)

	if invoked {
		// Wait briefly so fast cancellations return the finalized cancelled snapshot immediately.
		deadline := time.NewTimer(250 * time.Millisecond)
		defer deadline.Stop()
		for {
			latest, gErr := s.store.GetExternalApproval(trimmedID)
			if gErr == nil && vault.IsExternalApprovalTerminal(latest.Status) {
				return latest, nil
			}
			select {
			case <-ch:
			case <-deadline.C:
				if latest != nil {
					return latest, nil
				}
				return ap, nil
			}
		}
	}

	// Fallback: no active cancel handle (e.g. orphaned running state) -> mark cancelled directly.
	unlock := s.lockExternalApproval(trimmedID)
	defer unlock()
	latest, err := s.store.GetExternalApproval(trimmedID)
	if err != nil {
		return nil, err
	}
	if latest.Status == "running" {
		now := time.Now().UTC()
		for i := range latest.Steps {
			st := &latest.Steps[i]
			if st.Status == "running" || (st.Status == "pending" && st.Selected && !st.Blocked) {
				st.Status = "cancelled"
				st.ExecutionError = "管理员中止执行"
				st.CompletedAt = &now
			}
		}
		latest.Status = "cancelled"
		latest.ExecutionError = "管理员已中止执行"
		latest.ResolvedAt = &now
		latest.RecalculateSummary()
		_ = s.store.UpdateExternalApproval(*latest)
		s.notifyExternalApprovalChanged(trimmedID)
		s.notifyPersist()
	}
	return latest, nil
}

// WaitForExternalApproval blocks until the approval plan reaches a terminal state or the bounded timeout expires.
// Returns (approvalSnapshot, timedOut, err). Timeout returns timedOut=true and err=nil so MCP clients can handle cleanly.
func (s *Service) WaitForExternalApproval(ctx context.Context, approvalID string, timeout time.Duration) (*vault.ExternalApproval, bool, error) {
	if !s.store.IsReady() {
		return nil, false, vault.ErrVaultLocked
	}
	trimmedID := strings.TrimSpace(approvalID)
	if timeout <= 0 {
		timeout = 30 * time.Second
	} else if timeout > 120*time.Second {
		timeout = 120 * time.Second
	}

	ch, unsub := s.subscribeExternalApproval(trimmedID)
	defer unsub()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		ap, err := s.store.GetExternalApproval(trimmedID)
		if err != nil {
			return nil, false, err
		}
		if vault.IsExternalApprovalTerminal(ap.Status) {
			return ap, false, nil
		}
		select {
		case <-ch:
			continue
		case <-timer.C:
			latest, gErr := s.store.GetExternalApproval(trimmedID)
			if gErr != nil {
				return ap, true, nil
			}
			return latest, !vault.IsExternalApprovalTerminal(latest.Status), nil
		case <-ctx.Done():
			latest, _ := s.store.GetExternalApproval(trimmedID)
			if latest == nil {
				latest = ap
			}
			return latest, true, nil
		case <-s.stopCh:
			latest, _ := s.store.GetExternalApproval(trimmedID)
			if latest == nil {
				latest = ap
			}
			return latest, true, nil
		}
	}
}

func (s *Service) runExternalApprovalPlan(runCtx context.Context, cancel context.CancelFunc, approvalID, clientIP string) {
	defer s.extExecWG.Done()
	defer func() {
		cancel()
		s.unregisterExternalExecCancel(approvalID)
	}()

	planStart := time.Now()
	wasCancelled := false

	// Read step count snapshot
	initAP, err := s.store.GetExternalApproval(approvalID)
	if err != nil {
		return
	}
	stepCount := len(initAP.Steps)

	for i := 0; i < stepCount; i++ {
		// Brief lock to inspect step i and transition to running (or cancel remaining)
		unlock := s.lockExternalApproval(approvalID)
		ap, err := s.store.GetExternalApproval(approvalID)
		if err != nil {
			unlock()
			return
		}
		if i >= len(ap.Steps) {
			unlock()
			break
		}
		st := &ap.Steps[i]
		if st.Blocked || !st.Selected || st.Status != "pending" {
			unlock()
			continue
		}
		if runCtx.Err() != nil {
			wasCancelled = true
			now := time.Now().UTC()
			for k := i; k < len(ap.Steps); k++ {
				if !ap.Steps[k].Blocked && ap.Steps[k].Selected && ap.Steps[k].Status == "pending" {
					ap.Steps[k].Status = "cancelled"
					ap.Steps[k].ExecutionError = "管理员中止执行，未运行"
					ap.Steps[k].CompletedAt = &now
				}
			}
			ap.RecalculateSummary()
			_ = s.store.UpdateExternalApproval(*ap)
			unlock()
			s.notifyExternalApprovalChanged(approvalID)
			break
		}

		stepStartNow := time.Now().UTC()
		st.Status = "running"
		st.StartedAt = &stepStartNow
		ap.RecalculateSummary()
		stepSnapshot := *st
		clientName := ap.ClientName
		_ = s.store.UpdateExternalApproval(*ap)
		unlock()
		s.notifyExternalApprovalChanged(approvalID)

		// Execute step outside the approval lock so cancellation & status reads stay instantaneous
		stepTimer := time.Now()
		out, execErr := s.executeExternalApprovalStep(runCtx, stepSnapshot, clientName, clientIP)
		stepDurMs := time.Since(stepTimer).Milliseconds()

		// Persist step result under lock
		unlock = s.lockExternalApproval(approvalID)
		ap, err = s.store.GetExternalApproval(approvalID)
		if err != nil {
			unlock()
			return
		}
		doneNow := time.Now().UTC()
		st = &ap.Steps[i]
		st.CompletedAt = &doneNow
		st.DurationMs = stepDurMs
		st.ExecutionOut = truncateStr(out, 12000)

		stopFollowing := false
		if runCtx.Err() != nil {
			wasCancelled = true
			st.Status = "cancelled"
			if execErr != nil {
				st.ExecutionError = execErr.Error()
			} else {
				st.ExecutionError = "管理员中止执行"
			}
			for k := i + 1; k < len(ap.Steps); k++ {
				if !ap.Steps[k].Blocked && ap.Steps[k].Selected && ap.Steps[k].Status == "pending" {
					ap.Steps[k].Status = "cancelled"
					ap.Steps[k].ExecutionError = "管理员中止执行，后续步骤未运行"
					ap.Steps[k].CompletedAt = &doneNow
				}
			}
			stopFollowing = true
		} else if execErr != nil {
			st.Status = "failed"
			st.ExecutionError = execErr.Error()
			if !st.ContinueOnError {
				for k := i + 1; k < len(ap.Steps); k++ {
					if !ap.Steps[k].Blocked && ap.Steps[k].Selected && ap.Steps[k].Status == "pending" {
						ap.Steps[k].Status = "skipped"
						ap.Steps[k].ExecutionError = fmt.Sprintf("前置第 %d 步执行失败，按遇错即停策略跳过", st.Index)
						ap.Steps[k].CompletedAt = &doneNow
					}
				}
				stopFollowing = true
			}
		} else {
			st.Status = "succeeded"
			st.ExecutionError = ""
		}

		ap.RecalculateSummary()
		_ = s.store.UpdateExternalApproval(*ap)
		unlock()
		s.notifyExternalApprovalChanged(approvalID)

		if stopFollowing {
			break
		}
	}

	// Finalize plan state
	unlock := s.lockExternalApproval(approvalID)
	ap, err := s.store.GetExternalApproval(approvalID)
	if err != nil {
		unlock()
		return
	}
	endNow := time.Now().UTC()
	ap.DurationMs = time.Since(planStart).Milliseconds()
	ap.ResolvedAt = &endNow
	ap.RecalculateSummary()

	switch {
	case wasCancelled || runCtx.Err() != nil:
		ap.Status = "cancelled"
		ap.ExecutionError = fmt.Sprintf("已中止执行（完成 %d 步，失败 %d 步）", ap.CompletedSteps, ap.FailedSteps)
	case ap.FailedSteps == 0:
		ap.Status = "completed"
		ap.ExecutionError = ""
	case ap.CompletedSteps > 0:
		ap.Status = "partial_failed"
		ap.ExecutionError = fmt.Sprintf("部分步骤执行失败（成功 %d 步，失败 %d 步，跳过 %d 步）", ap.CompletedSteps, ap.FailedSteps, ap.SkippedSteps)
	default:
		ap.Status = "failed"
		ap.ExecutionError = fmt.Sprintf("执行失败（失败 %d 步，跳过 %d 步）", ap.FailedSteps, ap.SkippedSteps)
	}
	ap.ExecutionOut = buildExternalPlanSummaryOutput(*ap)

	_ = s.store.UpdateExternalApproval(*ap)
	finalAP := *ap
	unlock()

	if finalAP.CompletedSteps > 0 {
		s.maybeRecordExternalApprovedChangeMemory(finalAP, clientIP)
	}
	s.notifyExternalApprovalChanged(approvalID)
	s.notifyPersist()
}

func (s *Service) executeExternalApprovalStep(ctx context.Context, st vault.ExternalApprovalStep, clientName, clientIP string) (string, error) {
	if st.Blocked {
		return "", fmt.Errorf("安全熔断器硬拦截: %s", nonEmpty(st.BlockedReason, "禁止执行被锁定步骤"))
	}
	if ctx.Err() != nil {
		return "", fmt.Errorf("管理员中止执行")
	}

	switch st.ToolName {
	case "exec_ssh_command":
		risk, why := ClassifyCommand(st.Command)
		if risk == RiskBlocked {
			return "", fmt.Errorf("安全熔断器拦截: %s", why)
		}
		timeoutSec := st.TimeoutSec
		if timeoutSec <= 0 {
			timeoutSec = DefaultExternalStepTimeout
		} else if timeoutSec > MaxExternalStepTimeout {
			timeoutSec = MaxExternalStepTimeout
		}
		results := s.ssh.BatchExecuteContext(ctx, st.ServerIDs, st.Command, time.Duration(timeoutSec)*time.Second, clientIP)
		out := formatBatchExecResults(results)
		var execErr error
		if ctx.Err() != nil {
			execErr = fmt.Errorf("管理员中止执行")
		} else {
			for _, r := range results {
				if r.Error != "" || r.ExitCode != 0 {
					if r.ExitCode != 0 {
						execErr = fmt.Errorf("主机 %s 返回退出码 %d: %s", nonEmpty(r.ServerName, r.ServerID), r.ExitCode, nonEmpty(r.Error, "命令执行失败"))
					} else {
						execErr = fmt.Errorf("主机 %s 执行异常: %s", nonEmpty(r.ServerName, r.ServerID), r.Error)
					}
					break
				}
			}
		}
		s.store.RecordAudit(
			"mcp.approved_exec",
			strings.Join(st.ServerNames, ","),
			fmt.Sprintf("管理员批准执行外部 AI (%s) 计划第 %d 步命令: %.75s", clientName, st.Index, st.Command),
			clientIP,
			execErr == nil,
		)
		return out, execErr

	case "sftp_write_file":
		if len(st.ServerIDs) == 0 {
			return "", fmt.Errorf("缺少目标服务器 ID")
		}
		if IsBlockedWritePath(st.FilePath) {
			return "", fmt.Errorf("安全熔断器禁止修改系统核心鉴权或保险库文件 (%s)", st.FilePath)
		}
		writeErrCh := make(chan error, 1)
		go func() {
			writeErrCh <- s.ssh.SFTPWriteText(st.ServerIDs[0], st.FilePath, st.NewContent, clientIP)
		}()
		select {
		case err := <-writeErrCh:
			if err != nil {
				s.store.RecordAudit(
					"mcp.approved_sftp_write",
					strings.Join(st.ServerNames, ",")+":"+st.FilePath,
					fmt.Sprintf("管理员批准执行外部 AI (%s) 计划第 %d 步修改远程文件失败: %v", clientName, st.Index, err),
					clientIP,
					false,
				)
				return "", err
			}
			out := fmt.Sprintf("已写入文件 %s\n%s", st.FilePath, st.DiffPreview)
			s.store.RecordAudit(
				"mcp.approved_sftp_write",
				strings.Join(st.ServerNames, ",")+":"+st.FilePath,
				fmt.Sprintf("管理员审阅 Diff 后批准外部 AI (%s) 计划第 %d 步修改远程文件", clientName, st.Index),
				clientIP,
				true,
			)
			return out, nil
		case <-ctx.Done():
			return "", fmt.Errorf("管理员中止执行")
		}

	default:
		return "", fmt.Errorf("不支持的审批步骤类型: %s", st.ToolName)
	}
}

func buildExternalPlanSummaryOutput(ap vault.ExternalApproval) string {
	var sb strings.Builder
	for _, st := range ap.Steps {
		sb.WriteString(fmt.Sprintf("[%d/%d %s] %s", st.Index, ap.TotalSteps, st.Status, nonEmpty(st.Title, st.ToolName)))
		if st.DurationMs > 0 {
			sb.WriteString(fmt.Sprintf(" (%dms)", st.DurationMs))
		}
		sb.WriteString("\n")
		if st.ExecutionError != "" {
			sb.WriteString("  Error: " + st.ExecutionError + "\n")
		}
		if strings.TrimSpace(st.ExecutionOut) != "" {
			brief, _ := truncateRunes(strings.TrimSpace(st.ExecutionOut), 400)
			sb.WriteString("  " + strings.ReplaceAll(brief, "\n", "\n  ") + "\n")
		}
	}
	return truncateStr(strings.TrimSpace(sb.String()), 12000)
}

func (s *Service) maybeRecordExternalApprovedChangeMemory(ap vault.ExternalApproval, clientIP string) {
	memCfg, err := s.store.GetAIMemoryConfig()
	if err != nil || !memCfg.AutoRecordApprovedChanges {
		return
	}
	targets := nonEmpty(strings.Join(ap.ServerNames, ", "), "目标主机")
	titleBrief, _ := truncateRunes(strings.TrimSpace(ap.Title), 56)
	title := fmt.Sprintf("外部AI变更计划：%s (%s)", nonEmpty(titleBrief, "变更执行"), targets)

	var content strings.Builder
	content.WriteString(fmt.Sprintf("管理员批准外部 AI (%s) 在 [%s] 按序执行变更计划「%s」（状态：%s，成功 %d/%d 步）。\n变更说明：%s",
		ap.ClientName, targets, ap.Title, ap.Status, ap.CompletedSteps, ap.TotalSteps, nonEmpty(ap.Reason, "无")))
	for _, st := range ap.Steps {
		if st.Status != "succeeded" {
			continue
		}
		if st.ToolName == "sftp_write_file" {
			content.WriteString(fmt.Sprintf("\n- 第 %d 步 [SFTP] `%s` (%s)", st.Index, st.FilePath, strings.Join(st.ServerNames, ", ")))
		} else {
			cmdBrief, _ := truncateRunes(strings.TrimSpace(st.Command), 80)
			content.WriteString(fmt.Sprintf("\n- 第 %d 步 [SSH] `%s` (%s)", st.Index, cmdBrief, strings.Join(st.ServerNames, ", ")))
		}
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
		Tags:       []string{"MCP审批", ap.ClientName, "change_plan"},
		Importance: 4,
		Source:     "approval",
	}, true, clientIP)
}

// SearchMemory exposes the unified hybrid memory search to internal callers such as the MCP gateway.
func (s *Service) SearchMemory(query, serverID, category string, limit int) (string, []string) {
	return s.SearchMemoryScoped(query, serverID, category, limit, nil)
}

// SearchMemoryScoped searches long-term memories and host memories while enforcing an optional server allowlist.
// When allowedServers is non-empty, only global memories and entries/hosts belonging to allowedServers are returned.
func (s *Service) SearchMemoryScoped(query, serverID, category string, limit int, allowedServers []string) (string, []string) {
	if limit <= 0 || limit > 20 {
		limit = 8
	}
	out, hitIDs := s.executeSearchMemory(query, serverID, category, limit, allowedServers)
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

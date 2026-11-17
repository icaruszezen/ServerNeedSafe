package aiops

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/icaruszezen/ServerNeedSafe/internal/sshmanager"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

const maxReActIterations = 8

// StreamEvent is serialized as JSON over SSE (text/event-stream) to the browser.
type StreamEvent struct {
	Type     string                   `json:"type"` // "delta", "tool_start", "tool_result", "approval_required", "memory_updated", "runbook_proposed", "session_sync", "done", "error"
	Delta    string                   `json:"delta,omitempty"`
	Tool     *vault.AIToolCallRecord  `json:"tool,omitempty"`
	Approval *vault.AIPendingApproval `json:"approval,omitempty"`
	Memory   *vault.HostMemory        `json:"memory,omitempty"`
	Proposal *vault.AIRunbookProposal `json:"proposal,omitempty"`
	Session  *vault.AIChatSession     `json:"session,omitempty"`
	Error    string                   `json:"error,omitempty"`
}

// ChatRequest encapsulates a user prompt sent from either AIOpsCenter or TerminalCopilot.
type ChatRequest struct {
	SessionID       string                `json:"session_id"`
	Message         string                `json:"message"`
	ServerIDs       []string              `json:"server_ids,omitempty"`
	Mode            vault.AIExecutionMode `json:"mode,omitempty"`
	TerminalContext string                `json:"terminal_context,omitempty"`
	ClientIP        string                `json:"-"`
}

// Service coordinates the pure-Go AI Ops ReAct agent, HITL gating, hybrid memory, and background patrol.
type Service struct {
	store *vault.Store
	ssh   *sshmanager.Manager
	llm   *LLMClient

	mu            sync.Mutex
	patrolRunning bool
	lastPatrolAt  *time.Time
	nextPatrolAt  *time.Time
	patrolWakeCh  chan struct{}
	stopCh        chan struct{}
	onPersist     func()
}

func NewService(store *vault.Store, sshMgr *sshmanager.Manager) *Service {
	svc := &Service{
		store:        store,
		ssh:          sshMgr,
		llm:          NewLLMClient(),
		patrolWakeCh: make(chan struct{}, 1),
		stopCh:       make(chan struct{}),
	}

	// When vault is sealed (Store.Lock), immediately clear next schedule
	store.RegisterOnLock(func() {
		svc.mu.Lock()
		svc.nextPatrolAt = nil
		svc.mu.Unlock()
	})

	// When vault is unlocked at startup, wake up patrol scheduler immediately
	store.RegisterOnUnlock(func() {
		svc.NotifyPatrolConfigUpdated()
	})

	go svc.patrolSchedulerLoop()
	return svc
}

func (s *Service) SetOnPersist(fn func()) {
	s.mu.Lock()
	s.onPersist = fn
	s.mu.Unlock()
}

func (s *Service) notifyPersist() {
	s.mu.Lock()
	fn := s.onPersist
	s.mu.Unlock()
	if fn != nil {
		fn()
	}
}

func (s *Service) Close() {
	select {
	case <-s.stopCh:
	default:
		close(s.stopCh)
	}
}

func (s *Service) LLM() *LLMClient {
	return s.llm
}

// RunChatStream appends a user turn and runs the ReAct tool-calling loop, streaming SSE events via emit.
func (s *Service) RunChatStream(ctx context.Context, req ChatRequest, emit func(StreamEvent)) error {
	msgText := strings.TrimSpace(req.Message)
	if msgText == "" {
		return fmt.Errorf("请输入运维指令或问题描述")
	}

	prov, err := s.store.GetActiveAIProviderSecret()
	if err != nil || prov == nil {
		return fmt.Errorf("尚未配置可用的大模型供应商，请先前往「模型与网关配置」添加并激活模型")
	}

	sess, err := s.store.GetAISession(req.SessionID)
	if err != nil {
		return err
	}

	// Reject new turns if session still has unresolved pending approvals; auto-reject stale ones if user sends new instruction
	now := time.Now().UTC()
	for i := range sess.PendingApprovals {
		if sess.PendingApprovals[i].Status == "pending" {
			sess.PendingApprovals[i].Status = "rejected"
			sess.PendingApprovals[i].ResolvedAt = &now
			sess.Messages = append(sess.Messages, vault.AIChatMessage{
				ID:         uuid.NewString(),
				Role:       "tool",
				ToolCallID: sess.PendingApprovals[i].ToolCallID,
				ToolName:   sess.PendingApprovals[i].ToolName,
				Content:    "管理员未批准该待定变更操作，已跳过并发送了新指令。",
				IsError:    true,
				Timestamp:  now,
			})
		}
	}

	if len(req.ServerIDs) > 0 {
		sess.ServerIDs = slices.Clone(req.ServerIDs)
	}
	if req.Mode == vault.AIModeSuggest || req.Mode == vault.AIModeStandard || req.Mode == vault.AIModeAutonomous {
		sess.Mode = req.Mode
	}

	// Auto-generate concise title on first user message
	if len(sess.Messages) == 0 && (sess.Title == "" || strings.HasPrefix(sess.Title, "新建")) {
		sess.Title = summarizeTitle(msgText)
	}

	userContent := msgText
	if strings.TrimSpace(req.TerminalContext) != "" {
		termSnippet := truncateStr(strings.TrimSpace(req.TerminalContext), 6000)
		userContent = fmt.Sprintf("%s\n\n[附：当前活跃 SSH 终端最近输出回显]\n```text\n%s\n```", msgText, termSnippet)
	}

	sess.Messages = append(sess.Messages, vault.AIChatMessage{
		ID:        uuid.NewString(),
		Role:      "user",
		Content:   userContent,
		Timestamp: now,
	})
	if err := s.store.SaveAISession(*sess); err != nil {
		return err
	}

	return s.continueAgentLoop(ctx, sess, *prov, req.ClientIP, emit)
}

// ResolveApprovalStream processes an administrator's Approve or Reject decision on a paused tool call
// and automatically resumes the ReAct loop once all pending approvals for the turn are resolved.
func (s *Service) ResolveApprovalStream(
	ctx context.Context,
	sessionID string,
	approvalID string,
	approve bool,
	clientIP string,
	emit func(StreamEvent),
) error {
	sess, err := s.store.GetAISession(sessionID)
	if err != nil {
		return err
	}

	apIdx := -1
	for i := range sess.PendingApprovals {
		if sess.PendingApprovals[i].ID == approvalID {
			apIdx = i
			break
		}
	}
	if apIdx < 0 {
		return vault.ErrNotFound
	}

	ap := sess.PendingApprovals[apIdx]
	if ap.Status != "pending" {
		return fmt.Errorf("该审批项已处理 (%s)", ap.Status)
	}

	now := time.Now().UTC()
	ap.ResolvedAt = &now

	var toolOut string
	var isErr bool
	var recStatus string
	var durMs int64

	if !approve {
		ap.Status = "rejected"
		recStatus = "rejected"
		isErr = true
		toolOut = fmt.Sprintf("管理员已拒绝执行该变更操作 (%s: %s)。请勿重复强行执行，可提供替代安全方案或解释手动执行步骤。", ap.ToolName, ap.Reason)
		s.store.RecordAudit("ai.approval_reject", strings.Join(ap.ServerNames, ","), fmt.Sprintf("拒绝 AI 变更请求: %s", ap.Reason), clientIP, true)
	} else {
		ap.Status = "approved"
		start := time.Now()
		out, execErr := s.executeApprovedAction(ap, clientIP)
		durMs = time.Since(start).Milliseconds()
		if execErr != nil {
			isErr = true
			recStatus = "error"
			toolOut = fmt.Sprintf("审批通过但远程执行返回错误: %v\n%s", execErr, out)
		} else {
			recStatus = "completed"
			toolOut = out
		}
		ap.ExecutionOut = truncateStr(toolOut, 8000)
	}

	sess.PendingApprovals[apIdx] = ap
	updateAssistantToolRecordStatus(sess, ap.ToolCallID, recStatus, truncateStr(toolOut, 4000), durMs)

	sess.Messages = append(sess.Messages, vault.AIChatMessage{
		ID:         uuid.NewString(),
		Role:       "tool",
		ToolCallID: ap.ToolCallID,
		ToolName:   ap.ToolName,
		Content:    truncateStr(toolOut, 12000),
		IsError:    isErr,
		Timestamp:  time.Now().UTC(),
	})

	if err := s.store.SaveAISession(*sess); err != nil {
		return err
	}

	emit(StreamEvent{
		Type: "tool_result",
		Tool: &vault.AIToolCallRecord{
			ID:         ap.ToolCallID,
			Name:       ap.ToolName,
			Status:     recStatus,
			Output:     truncateStr(toolOut, 4000),
			DurationMs: durMs,
		},
	})

	// Check if there are still unresolved approvals in this session before resuming LLM
	for _, item := range sess.PendingApprovals {
		if item.Status == "pending" {
			emit(StreamEvent{Type: "session_sync", Session: sess})
			emit(StreamEvent{Type: "done", Session: sess})
			return nil
		}
	}

	prov, err := s.store.GetActiveAIProviderSecret()
	if err != nil || prov == nil {
		emit(StreamEvent{Type: "session_sync", Session: sess})
		emit(StreamEvent{Type: "done", Session: sess})
		return nil
	}

	return s.continueAgentLoop(ctx, sess, *prov, clientIP, emit)
}

func (s *Service) continueAgentLoop(
	ctx context.Context,
	sess *vault.AIChatSession,
	prov vault.AIProviderConfig,
	clientIP string,
	emit func(StreamEvent),
) error {
	tools := s.agentToolsSchema()

	for step := 0; step < maxReActIterations; step++ {
		sysPrompt := s.buildSystemPrompt(sess)

		turn, err := s.llm.StreamChat(ctx, prov, sysPrompt, sess.Messages, tools, func(chunk string) {
			emit(StreamEvent{Type: "delta", Delta: chunk})
		})
		if err != nil {
			emit(StreamEvent{Type: "error", Error: err.Error()})
			return err
		}

		assistantMsg := vault.AIChatMessage{
			ID:        uuid.NewString(),
			Role:      "assistant",
			Content:   turn.Content,
			Timestamp: time.Now().UTC(),
		}

		if len(turn.ToolCalls) == 0 {
			sess.Messages = append(sess.Messages, assistantMsg)
			_ = s.store.SaveAISession(*sess)
			emit(StreamEvent{Type: "session_sync", Session: sess})
			emit(StreamEvent{Type: "done", Session: sess})
			return nil
		}

		// Reserve records on assistant message first
		records := make([]vault.AIToolCallRecord, len(turn.ToolCalls))
		for i, tc := range turn.ToolCalls {
			records[i] = vault.AIToolCallRecord{
				ID:        tc.ID,
				Name:      tc.Name,
				Arguments: tc.Arguments,
				Status:    "running",
			}
		}
		assistantMsg.ToolCalls = records
		sess.Messages = append(sess.Messages, assistantMsg)
		assistantIdx := len(sess.Messages) - 1

		pausedForApproval := false

		for i, tc := range turn.ToolCalls {
			emit(StreamEvent{
				Type: "tool_start",
				Tool: &vault.AIToolCallRecord{
					ID:        tc.ID,
					Name:      tc.Name,
					Arguments: tc.Arguments,
					Status:    "running",
				},
			})

			res := s.dispatchToolCall(sess, tc, clientIP, emit)
			sess.Messages[assistantIdx].ToolCalls[i] = res.record

			if res.approval != nil {
				pausedForApproval = true
				sess.PendingApprovals = append(sess.PendingApprovals, *res.approval)
				emit(StreamEvent{
					Type:     "approval_required",
					Approval: res.approval,
				})
				continue
			}

			sess.Messages = append(sess.Messages, vault.AIChatMessage{
				ID:         uuid.NewString(),
				Role:       "tool",
				ToolCallID: tc.ID,
				ToolName:   tc.Name,
				Content:    truncateStr(res.toolOutput, 12000),
				IsError:    res.isError,
				Timestamp:  time.Now().UTC(),
			})
			emit(StreamEvent{
				Type: "tool_result",
				Tool: &res.record,
			})
		}

		if err := s.store.SaveAISession(*sess); err != nil {
			return err
		}

		if pausedForApproval {
			emit(StreamEvent{Type: "session_sync", Session: sess})
			emit(StreamEvent{Type: "done", Session: sess})
			return nil
		}
	}

	_ = s.store.SaveAISession(*sess)
	emit(StreamEvent{Type: "session_sync", Session: sess})
	emit(StreamEvent{Type: "done", Session: sess})
	return nil
}

type toolDispatchOutcome struct {
	record     vault.AIToolCallRecord
	toolOutput string
	isError    bool
	approval   *vault.AIPendingApproval
}

func (s *Service) dispatchToolCall(
	sess *vault.AIChatSession,
	tc LLMToolCall,
	clientIP string,
	emit func(StreamEvent),
) toolDispatchOutcome {
	start := time.Now()
	rec := vault.AIToolCallRecord{
		ID:        tc.ID,
		Name:      tc.Name,
		Arguments: tc.Arguments,
	}

	serverNameMap := s.serverNameLookup()

	switch tc.Name {
	case "probe_server":
		var args struct {
			ServerID string `json:"server_id"`
		}
		_ = json.Unmarshal([]byte(tc.Arguments), &args)
		if args.ServerID == "" && len(sess.ServerIDs) > 0 {
			args.ServerID = sess.ServerIDs[0]
		}
		srvName := serverNameMap[args.ServerID]
		rec.Summary = fmt.Sprintf("采集实时负载与系统遥测 (%s)", nonEmpty(srvName, args.ServerID))
		rec.RiskLevel = string(RiskReadOnly)

		if sess.Mode == vault.AIModeSuggest {
			ap := &vault.AIPendingApproval{
				ID:            uuid.NewString(),
				SessionID:     sess.ID,
				ToolCallID:    tc.ID,
				ToolName:      tc.Name,
				ServerIDs:     []string{args.ServerID},
				ServerNames:   []string{nonEmpty(srvName, args.ServerID)},
				RiskLevel:     "medium",
				Reason:        "当前处于「参谋模式」，远程探针需人工确认后执行",
				ArgumentsJSON: tc.Arguments,
				Status:        "pending",
				CreatedAt:     time.Now().UTC(),
			}
			rec.Status = "pending_approval"
			return toolDispatchOutcome{record: rec, approval: ap}
		}

		probe, err := s.ssh.ProbeServer(args.ServerID, "", clientIP)
		rec.DurationMs = time.Since(start).Milliseconds()
		if err != nil {
			rec.Status = "error"
			rec.Output = err.Error()
			return toolDispatchOutcome{record: rec, toolOutput: "探针执行失败: " + err.Error(), isError: true}
		}
		b, _ := json.MarshalIndent(probe, "", "  ")
		rec.Status = "completed"
		rec.Output = string(b)
		return toolDispatchOutcome{record: rec, toolOutput: string(b)}

	case "exec_ssh_command":
		var args struct {
			ServerIDs  []string `json:"server_ids"`
			Command    string   `json:"command"`
			Reason     string   `json:"reason"`
			TimeoutSec int      `json:"timeout_sec"`
		}
		_ = json.Unmarshal([]byte(tc.Arguments), &args)
		if len(args.ServerIDs) == 0 && len(sess.ServerIDs) > 0 {
			args.ServerIDs = slices.Clone(sess.ServerIDs)
		}
		names := make([]string, 0, len(args.ServerIDs))
		for _, id := range args.ServerIDs {
			names = append(names, nonEmpty(serverNameMap[id], id))
		}

		risk, riskWhy := ClassifyCommand(args.Command)
		rec.RiskLevel = string(risk)
		rec.Summary = fmt.Sprintf("[%s] %s", strings.Join(names, ", "), truncateStr(args.Command, 72))

		if risk == RiskBlocked {
			rec.Status = "blocked"
			rec.Output = riskWhy
			s.store.RecordAudit("ai.blocked", strings.Join(names, ","), fmt.Sprintf("安全熔断拦截命令: %.80s (%s)", args.Command, riskWhy), clientIP, false)
			return toolDispatchOutcome{
				record:     rec,
				toolOutput: "安全熔断器拦截: " + riskWhy,
				isError:    true,
			}
		}

		needApproval := false
		switch sess.Mode {
		case vault.AIModeSuggest:
			needApproval = true
		case vault.AIModeStandard:
			needApproval = (risk != RiskReadOnly)
		case vault.AIModeAutonomous:
			needApproval = false
		default:
			needApproval = (risk != RiskReadOnly)
		}

		if needApproval {
			reasonText := strings.TrimSpace(args.Reason)
			if reasonText == "" {
				reasonText = riskWhy
			} else if risk == RiskMutating {
				reasonText = fmt.Sprintf("%s（%s）", reasonText, riskWhy)
			}
			ap := &vault.AIPendingApproval{
				ID:            uuid.NewString(),
				SessionID:     sess.ID,
				ToolCallID:    tc.ID,
				ToolName:      tc.Name,
				ServerIDs:     args.ServerIDs,
				ServerNames:   names,
				RiskLevel:     ternaryStr(risk == RiskMutating, "high", "medium"),
				Reason:        reasonText,
				Command:       args.Command,
				ArgumentsJSON: tc.Arguments,
				Status:        "pending",
				CreatedAt:     time.Now().UTC(),
			}
			rec.Status = "pending_approval"
			return toolDispatchOutcome{record: rec, approval: ap}
		}

		timeout := time.Duration(args.TimeoutSec) * time.Second
		if timeout <= 0 || timeout > 90*time.Second {
			timeout = 25 * time.Second
		}
		results := s.ssh.BatchExecute(args.ServerIDs, args.Command, timeout, clientIP)
		s.store.RecordAudit("ai.exec", strings.Join(names, ","), fmt.Sprintf("AI 执行命令(%s): %.70s", risk, args.Command), clientIP, true)

		rec.DurationMs = time.Since(start).Milliseconds()
		outStr := formatBatchExecResults(results)
		rec.Status = "completed"
		rec.Output = truncateStr(outStr, 4000)
		return toolDispatchOutcome{record: rec, toolOutput: outStr}

	case "sftp_list_dir":
		var args struct {
			ServerID string `json:"server_id"`
			Path     string `json:"path"`
		}
		_ = json.Unmarshal([]byte(tc.Arguments), &args)
		if args.ServerID == "" && len(sess.ServerIDs) > 0 {
			args.ServerID = sess.ServerIDs[0]
		}
		srvName := nonEmpty(serverNameMap[args.ServerID], args.ServerID)
		rec.RiskLevel = string(RiskReadOnly)
		rec.Summary = fmt.Sprintf("浏览远程目录 %s:%s", srvName, nonEmpty(args.Path, "~"))

		if sess.Mode == vault.AIModeSuggest {
			ap := &vault.AIPendingApproval{
				ID:            uuid.NewString(),
				SessionID:     sess.ID,
				ToolCallID:    tc.ID,
				ToolName:      tc.Name,
				ServerIDs:     []string{args.ServerID},
				ServerNames:   []string{srvName},
				RiskLevel:     "medium",
				Reason:        "参谋模式下读取远程目录需确认",
				FilePath:      args.Path,
				ArgumentsJSON: tc.Arguments,
				Status:        "pending",
				CreatedAt:     time.Now().UTC(),
			}
			rec.Status = "pending_approval"
			return toolDispatchOutcome{record: rec, approval: ap}
		}

		listResp, err := s.ssh.SFTPList(args.ServerID, args.Path, clientIP)
		rec.DurationMs = time.Since(start).Milliseconds()
		if err != nil {
			rec.Status = "error"
			rec.Output = err.Error()
			return toolDispatchOutcome{record: rec, toolOutput: err.Error(), isError: true}
		}
		b, _ := json.MarshalIndent(listResp, "", "  ")
		rec.Status = "completed"
		rec.Output = truncateStr(string(b), 4000)
		return toolDispatchOutcome{record: rec, toolOutput: string(b)}

	case "sftp_read_file":
		var args struct {
			ServerID string `json:"server_id"`
			Path     string `json:"path"`
		}
		_ = json.Unmarshal([]byte(tc.Arguments), &args)
		if args.ServerID == "" && len(sess.ServerIDs) > 0 {
			args.ServerID = sess.ServerIDs[0]
		}
		srvName := nonEmpty(serverNameMap[args.ServerID], args.ServerID)
		rec.RiskLevel = string(RiskReadOnly)
		rec.Summary = fmt.Sprintf("读取配置文件 %s:%s", srvName, args.Path)

		if strings.TrimSpace(args.Path) == "/etc/shadow" || strings.TrimSpace(args.Path) == "/etc/gshadow" {
			rec.RiskLevel = string(RiskBlocked)
			rec.Status = "blocked"
			rec.Output = "禁止直接读取系统密码哈希文件 (/etc/shadow)"
			return toolDispatchOutcome{record: rec, toolOutput: rec.Output, isError: true}
		}

		if sess.Mode == vault.AIModeSuggest {
			ap := &vault.AIPendingApproval{
				ID:            uuid.NewString(),
				SessionID:     sess.ID,
				ToolCallID:    tc.ID,
				ToolName:      tc.Name,
				ServerIDs:     []string{args.ServerID},
				ServerNames:   []string{srvName},
				RiskLevel:     "medium",
				Reason:        "参谋模式下读取远程文件需确认",
				FilePath:      args.Path,
				ArgumentsJSON: tc.Arguments,
				Status:        "pending",
				CreatedAt:     time.Now().UTC(),
			}
			rec.Status = "pending_approval"
			return toolDispatchOutcome{record: rec, approval: ap}
		}

		content, err := s.ssh.SFTPReadText(args.ServerID, args.Path, clientIP)
		rec.DurationMs = time.Since(start).Milliseconds()
		if err != nil {
			rec.Status = "error"
			rec.Output = err.Error()
			return toolDispatchOutcome{record: rec, toolOutput: err.Error(), isError: true}
		}
		trimmed := truncateStr(content, 20000)
		rec.Status = "completed"
		rec.Output = truncateStr(trimmed, 3000)
		return toolDispatchOutcome{record: rec, toolOutput: trimmed}

	case "sftp_write_file":
		var args struct {
			ServerID string `json:"server_id"`
			Path     string `json:"path"`
			Content  string `json:"content"`
			Reason   string `json:"reason"`
		}
		_ = json.Unmarshal([]byte(tc.Arguments), &args)
		if args.ServerID == "" && len(sess.ServerIDs) > 0 {
			args.ServerID = sess.ServerIDs[0]
		}
		srvName := nonEmpty(serverNameMap[args.ServerID], args.ServerID)
		rec.RiskLevel = string(RiskMutating)
		rec.Summary = fmt.Sprintf("修改远程文件 %s:%s", srvName, args.Path)

		cleanPath := strings.TrimSpace(args.Path)
		if cleanPath == "/etc/shadow" || cleanPath == "/etc/passwd" || cleanPath == "/etc/sudoers" {
			rec.RiskLevel = string(RiskBlocked)
			rec.Status = "blocked"
			rec.Output = fmt.Sprintf("安全熔断器禁止 AI 直接覆写系统核心鉴权文件 (%s)", cleanPath)
			s.store.RecordAudit("ai.blocked", srvName+":"+cleanPath, rec.Output, clientIP, false)
			return toolDispatchOutcome{record: rec, toolOutput: rec.Output, isError: true}
		}

		oldContent, _ := s.ssh.SFTPReadText(args.ServerID, cleanPath, clientIP)
		diff := BuildUnifiedDiff(cleanPath, oldContent, args.Content)

		if sess.Mode != vault.AIModeAutonomous {
			ap := &vault.AIPendingApproval{
				ID:            uuid.NewString(),
				SessionID:     sess.ID,
				ToolCallID:    tc.ID,
				ToolName:      tc.Name,
				ServerIDs:     []string{args.ServerID},
				ServerNames:   []string{srvName},
				RiskLevel:     "high",
				Reason:        nonEmpty(args.Reason, fmt.Sprintf("写入修改远程文件 %s", cleanPath)),
				FilePath:      cleanPath,
				NewContent:    args.Content,
				DiffPreview:   diff,
				ArgumentsJSON: tc.Arguments,
				Status:        "pending",
				CreatedAt:     time.Now().UTC(),
			}
			rec.Status = "pending_approval"
			rec.Output = diff
			return toolDispatchOutcome{record: rec, approval: ap}
		}

		if err := s.ssh.SFTPWriteText(args.ServerID, cleanPath, args.Content, clientIP); err != nil {
			rec.DurationMs = time.Since(start).Milliseconds()
			rec.Status = "error"
			rec.Output = err.Error()
			return toolDispatchOutcome{record: rec, toolOutput: err.Error(), isError: true}
		}
		s.store.RecordAudit("ai.sftp_write", srvName+":"+cleanPath, "自治模式下 AI 写入远程配置文件", clientIP, true)
		rec.DurationMs = time.Since(start).Milliseconds()
		rec.Status = "completed"
		rec.Output = diff
		return toolDispatchOutcome{
			record:     rec,
			toolOutput: fmt.Sprintf("已成功写入 %s:%s\n%s", srvName, cleanPath, diff),
		}

	case "update_host_memory":
		var args struct {
			ServerID    string   `json:"server_id"`
			Summary     string   `json:"summary"`
			OSArch      string   `json:"os_arch"`
			KeyServices []string `json:"key_services"`
			DeployPaths []string `json:"deploy_paths"`
			PortsNote   string   `json:"ports_note"`
		}
		_ = json.Unmarshal([]byte(tc.Arguments), &args)
		if args.ServerID == "" && len(sess.ServerIDs) > 0 {
			args.ServerID = sess.ServerIDs[0]
		}
		srvName := nonEmpty(serverNameMap[args.ServerID], args.ServerID)
		rec.RiskLevel = string(RiskReadOnly)
		rec.Summary = fmt.Sprintf("自动增量更新主机环境画像 (%s)", srvName)

		mem, err := s.store.UpsertHostMemory(vault.HostMemory{
			ServerID:    args.ServerID,
			ServerName:  srvName,
			Summary:     args.Summary,
			OSArch:      args.OSArch,
			KeyServices: args.KeyServices,
			DeployPaths: args.DeployPaths,
			PortsNote:   args.PortsNote,
		}, true, clientIP)
		rec.DurationMs = time.Since(start).Milliseconds()
		if err != nil {
			rec.Status = "error"
			rec.Output = err.Error()
			return toolDispatchOutcome{record: rec, toolOutput: err.Error(), isError: true}
		}
		emit(StreamEvent{Type: "memory_updated", Memory: mem})
		rec.Status = "completed"
		rec.Output = fmt.Sprintf("已将 %s 的客观环境特征增量保存至加密保险库", srvName)
		return toolDispatchOutcome{record: rec, toolOutput: rec.Output}

	case "propose_runbook":
		var args struct {
			Title           string   `json:"title"`
			Category        string   `json:"category"`
			Symptom         string   `json:"symptom"`
			RootCause       string   `json:"root_cause"`
			DiagnosticSteps []string `json:"diagnostic_steps"`
			FixCommands     []string `json:"fix_commands"`
			Verification    string   `json:"verification"`
		}
		_ = json.Unmarshal([]byte(tc.Arguments), &args)
		rec.RiskLevel = string(RiskReadOnly)
		rec.Summary = fmt.Sprintf("提炼排障技能草稿: %s", args.Title)

		prop := vault.AIRunbookProposal{
			ID:              uuid.NewString(),
			SessionID:       sess.ID,
			Title:           nonEmpty(args.Title, "排障经验 Runbook"),
			Category:        nonEmpty(args.Category, "故障恢复"),
			Symptom:         args.Symptom,
			RootCause:       args.RootCause,
			DiagnosticSteps: args.DiagnosticSteps,
			FixCommands:     args.FixCommands,
			Verification:    args.Verification,
			Status:          "pending",
			CreatedAt:       time.Now().UTC(),
		}
		sess.RunbookProposals = append(sess.RunbookProposals, prop)
		emit(StreamEvent{Type: "runbook_proposed", Proposal: &prop})
		rec.DurationMs = time.Since(start).Milliseconds()
		rec.Status = "completed"
		rec.Output = fmt.Sprintf("已生成 Runbook 建议卡片《%s》，等待管理员一键确认入库", prop.Title)
		return toolDispatchOutcome{record: rec, toolOutput: rec.Output}

	default:
		rec.Status = "error"
		rec.Output = "未知工具名称: " + tc.Name
		return toolDispatchOutcome{record: rec, toolOutput: rec.Output, isError: true}
	}
}

func (s *Service) executeApprovedAction(ap vault.AIPendingApproval, clientIP string) (string, error) {
	switch ap.ToolName {
	case "probe_server":
		if len(ap.ServerIDs) == 0 {
			return "", fmt.Errorf("缺少目标服务器 ID")
		}
		p, err := s.ssh.ProbeServer(ap.ServerIDs[0], "", clientIP)
		if err != nil {
			return "", err
		}
		b, _ := json.MarshalIndent(p, "", "  ")
		return string(b), nil

	case "exec_ssh_command":
		risk, why := ClassifyCommand(ap.Command)
		if risk == RiskBlocked {
			return "", fmt.Errorf("安全熔断器拦截: %s", why)
		}
		results := s.ssh.BatchExecute(ap.ServerIDs, ap.Command, 45*time.Second, clientIP)
		s.store.RecordAudit("ai.approved_exec", strings.Join(ap.ServerNames, ","), fmt.Sprintf("管理员批准执行 AI 命令: %.75s", ap.Command), clientIP, true)
		return formatBatchExecResults(results), nil

	case "sftp_list_dir":
		if len(ap.ServerIDs) == 0 {
			return "", fmt.Errorf("缺少目标服务器 ID")
		}
		resp, err := s.ssh.SFTPList(ap.ServerIDs[0], ap.FilePath, clientIP)
		if err != nil {
			return "", err
		}
		b, _ := json.MarshalIndent(resp, "", "  ")
		return string(b), nil

	case "sftp_read_file":
		if len(ap.ServerIDs) == 0 {
			return "", fmt.Errorf("缺少目标服务器 ID")
		}
		return s.ssh.SFTPReadText(ap.ServerIDs[0], ap.FilePath, clientIP)

	case "sftp_write_file":
		if len(ap.ServerIDs) == 0 {
			return "", fmt.Errorf("缺少目标服务器 ID")
		}
		if err := s.ssh.SFTPWriteText(ap.ServerIDs[0], ap.FilePath, ap.NewContent, clientIP); err != nil {
			return "", err
		}
		s.store.RecordAudit("ai.approved_sftp_write", strings.Join(ap.ServerNames, ",")+":"+ap.FilePath, "管理员审阅 Diff 后批准 AI 修改远程文件", clientIP, true)
		return fmt.Sprintf("已写入文件 %s\n%s", ap.FilePath, ap.DiffPreview), nil

	default:
		return "", fmt.Errorf("不支持的审批工具类型: %s", ap.ToolName)
	}
}

func (s *Service) buildSystemPrompt(sess *vault.AIChatSession) string {
	servers, _ := s.store.ListServers()
	memories, _ := s.store.ListHostMemories()
	runbooks, _ := s.store.ListRunbooks()

	memMap := make(map[string]vault.HostMemory)
	for _, m := range memories {
		memMap[m.ServerID] = m
	}

	var sb strings.Builder
	sb.WriteString(`你是 ServerNeedSafe 内置的资深 Linux SRE 与服务器安全运维智能体（AI Ops Agent）。
请遵循以下核心行为准则：
1. 证据驱动：排查故障或执行安全审计时，优先调用只读探针（probe_server、exec_ssh_command 只读命令、sftp_read_file）收集真实指标、日志与配置证据，切勿凭空猜测。
2. 最小变更与安全加固：修改配置文件优先使用 sftp_write_file（系统会自动向管理员展示 Unified Diff 对比）；服务重载前先校验语法（如 nginx -t / sshd -t）。
3. 客观环境画像自进化：当你在排查中发现了目标服务器的客观架构信息（如核心服务组件、项目部署目录、监听端口用途、OS版本），主动调用 update_host_memory 增量记录，方便后续会话直接复用。
4. 排障技能沉淀（Runbook）：当你成功定位并解决了一个典型故障或完成了一套有价值的加固流程时，调用 propose_runbook 生成结构化 SOP 建议卡片供管理员一键归档。
5. 输出简洁专业：使用清晰的中文 Markdown 结构呈现根因结论、关键证据和命令说明。
`)

	switch sess.Mode {
	case vault.AIModeSuggest:
		sb.WriteString("\n【当前会话执行模式：参谋模式 (suggest)】请直接结合已有信息给出精准的排查思路与命令建议；非必要不主动触发远程工具调用。\n")
	case vault.AIModeAutonomous:
		sb.WriteString("\n【当前会话执行模式：自治执行模式 (autonomous)】非毁灭性的排障与修复操作将自动执行，请务必谨慎评估每一步副作用并在变更后验证服务状态。\n")
	default:
		sb.WriteString("\n【当前会话执行模式：标准受控模式 (standard)】只读命令会自动放行执行；任何修改文件、重启服务、删除或未知复合指令都会自动挂起并弹出审批卡片由管理员确认。\n")
	}

	sb.WriteString("\n### 当前纳管与选定的目标服务器上下文（已严格隔离凭据密钥）\n")
	selectedSet := make(map[string]bool)
	for _, id := range sess.ServerIDs {
		selectedSet[id] = true
	}

	listedCount := 0
	for _, srv := range servers {
		if len(selectedSet) > 0 && !selectedSet[srv.ID] {
			continue
		}
		listedCount++
		sb.WriteString(fmt.Sprintf("- **%s** (`server_id`: `%s`) | 分组: %s | 地址: `%s@%s:%d` | OS: %s\n",
			srv.Name, srv.ID, srv.Group, srv.Username, srv.Host, srv.Port, nonEmpty(srv.LastOSInfo, "未知")))
		if mem, ok := memMap[srv.ID]; ok {
			sb.WriteString(fmt.Sprintf("  - 已记忆环境画像: %s | 关键组件: %s | 部署路径: %s | 端口备注: %s\n",
				nonEmpty(mem.Summary, "无"),
				strings.Join(mem.KeyServices, ", "),
				strings.Join(mem.DeployPaths, ", "),
				nonEmpty(mem.PortsNote, "无"),
			))
		}
	}
	if listedCount == 0 {
		sb.WriteString("- 当前会话尚未绑定特定目标服务器（若需远程操作，请提示管理员在顶部勾选目标主机）。\n")
	}

	if len(runbooks) > 0 {
		sb.WriteString("\n### 保险库已沉淀的可复用排障技能 (Runbook 参考)\n")
		limit := min(8, len(runbooks))
		for i := 0; i < limit; i++ {
			rb := runbooks[i]
			sb.WriteString(fmt.Sprintf("- 《%s》[%s] 适用症状: %s | 参考修复命令: `%s`\n",
				rb.Title, rb.Category, rb.Symptom, strings.Join(rb.FixCommands, " ; ")))
		}
	}

	return sb.String()
}

func (s *Service) agentToolsSchema() []ToolDefinition {
	return []ToolDefinition{
		{
			Name:        "probe_server",
			Description: "无损探测指定受管服务器的连通延迟、OS内核版本、CPU核数与负载、内存及根分区磁盘使用率。",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"server_id": map[string]any{
						"type":        "string",
						"description": "目标服务器的 server_id",
					},
				},
				"required": []string{"server_id"},
			},
		},
		{
			Name:        "exec_ssh_command",
			Description: "在一台或多台目标服务器上执行非交互式 Shell 命令。只读查看指令会自动执行；修改状态指令在受控模式下会进入管理员审批。",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"server_ids": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "要执行命令的目标 server_id 列表",
					},
					"command": map[string]any{
						"type":        "string",
						"description": "要执行的单行非交互式 Linux Shell 命令（例如 journalctl -n 50 --no-pager）",
					},
					"reason": map[string]any{
						"type":        "string",
						"description": "简要说明执行该命令的诊断或修复目的（将展示在审计与审批卡片上）",
					},
					"timeout_sec": map[string]any{
						"type":        "integer",
						"description": "超时秒数（默认 25 秒，最大 90 秒）",
					},
				},
				"required": []string{"server_ids", "command", "reason"},
			},
		},
		{
			Name:        "sftp_list_dir",
			Description: "通过 SFTP 安全列出目标服务器指定目录下的文件、权限与大小。",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"server_id": map[string]any{"type": "string", "description": "目标服务器 server_id"},
					"path":      map[string]any{"type": "string", "description": "目录路径，如 /etc/nginx"},
				},
				"required": []string{"server_id", "path"},
			},
		},
		{
			Name:        "sftp_read_file",
			Description: "通过 SFTP 读取目标服务器上的文本配置文件或日志文件内容。",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"server_id": map[string]any{"type": "string", "description": "目标服务器 server_id"},
					"path":      map[string]any{"type": "string", "description": "远程文件完整路径，如 /etc/ssh/sshd_config"},
				},
				"required": []string{"server_id", "path"},
			},
		},
		{
			Name:        "sftp_write_file",
			Description: "通过 SFTP 修改或创建远程服务器上的文本配置文件。系统会自动计算修改前后 Unified Diff 供管理员审阅批准。",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"server_id": map[string]any{"type": "string", "description": "目标服务器 server_id"},
					"path":      map[string]any{"type": "string", "description": "远程文件完整路径"},
					"content":   map[string]any{"type": "string", "description": "完整的修改后文件文本内容"},
					"reason":    map[string]any{"type": "string", "description": "本次修改配置的原因与影响说明"},
				},
				"required": []string{"server_id", "path", "content", "reason"},
			},
		},
		{
			Name:        "update_host_memory",
			Description: "自动增量更新某台服务器的客观环境画像记忆（运行的核心服务、项目部署路径、端口拓扑、系统架构摘要），后续对话将自动携带该记忆。",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"server_id":    map[string]any{"type": "string", "description": "目标服务器 server_id"},
					"summary":      map[string]any{"type": "string", "description": "主机角色与业务环境一句话摘要"},
					"os_arch":      map[string]any{"type": "string", "description": "发行版、内核与架构"},
					"key_services": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "运行的关键服务或组件列表，如 nginx, docker, postgres"},
					"deploy_paths": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "关键配置或应用部署目录，如 /opt/app, /etc/nginx/conf.d"},
					"ports_note":   map[string]any{"type": "string", "description": "重要监听端口与用途说明"},
				},
				"required": []string{"server_id"},
			},
		},
		{
			Name:        "propose_runbook",
			Description: "当成功定位或修复一个运维/安全问题后，提炼结构化排障技能草稿卡片，供管理员一键确认沉淀到加密技能库。",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"title":            map[string]any{"type": "string", "description": "Runbook 技能标题"},
					"category":         map[string]any{"type": "string", "description": "分类，如 安全加固 / 故障恢复 / 性能优化"},
					"symptom":          map[string]any{"type": "string", "description": "触发该 SOP 的典型故障表象或告警特征"},
					"root_cause":       map[string]any{"type": "string", "description": "问题根因总结"},
					"diagnostic_steps": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "标准排查核验步骤"},
					"fix_commands":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "可复用的修复或巡检 Shell 命令列表"},
					"verification":     map[string]any{"type": "string", "description": "修复后的验证方法"},
				},
				"required": []string{"title", "symptom", "diagnostic_steps", "fix_commands"},
			},
		},
	}
}

func (s *Service) serverNameLookup() map[string]string {
	m := make(map[string]string)
	servers, err := s.store.ListServers()
	if err != nil {
		return m
	}
	for _, srv := range servers {
		m[srv.ID] = srv.Name
	}
	return m
}

func formatBatchExecResults(results []sshmanager.BatchExecResult) string {
	var sb strings.Builder
	for _, r := range results {
		sb.WriteString(fmt.Sprintf("=== 主机: %s (%s) | 退出码: %d | 耗时: %dms ===\n", r.ServerName, r.Host, r.ExitCode, r.DurationMs))
		if r.Error != "" {
			sb.WriteString("错误: " + r.Error + "\n")
		}
		if strings.TrimSpace(r.Stdout) != "" {
			sb.WriteString("[STDOUT]\n" + r.Stdout + "\n")
		}
		if strings.TrimSpace(r.Stderr) != "" {
			sb.WriteString("[STDERR]\n" + r.Stderr + "\n")
		}
	}
	return strings.TrimSpace(sb.String())
}

func updateAssistantToolRecordStatus(sess *vault.AIChatSession, toolCallID, status, output string, durMs int64) {
	for i := len(sess.Messages) - 1; i >= 0; i-- {
		if sess.Messages[i].Role != "assistant" {
			continue
		}
		for j := range sess.Messages[i].ToolCalls {
			if sess.Messages[i].ToolCalls[j].ID == toolCallID {
				sess.Messages[i].ToolCalls[j].Status = status
				sess.Messages[i].ToolCalls[j].Output = output
				if durMs > 0 {
					sess.Messages[i].ToolCalls[j].DurationMs = durMs
				}
				return
			}
		}
	}
}

func summarizeTitle(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.TrimSpace(s)
	runes := []rune(s)
	if len(runes) <= 24 {
		return s
	}
	return string(runes[:24]) + "..."
}

func truncateStr(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	return s[:maxBytes] + "\n... [输出过长已截断]"
}

func nonEmpty(val, fallback string) string {
	if strings.TrimSpace(val) != "" {
		return val
	}
	return fallback
}

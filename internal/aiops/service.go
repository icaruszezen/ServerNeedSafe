package aiops

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/icaruszezen/ServerNeedSafe/internal/sshmanager"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

const maxReActIterations = 8

// StreamEvent is serialized as JSON over SSE (text/event-stream) to the browser.
type StreamEvent struct {
	Type             string                    `json:"type"` // "delta", "tool_start", "tool_result", "approval_required", "memory_updated", "memory_saved", "runbook_proposed", "agents_md_proposed", "context_compacted", "session_sync", "done", "error"
	Delta            string                    `json:"delta,omitempty"`
	Tool             *vault.AIToolCallRecord   `json:"tool,omitempty"`
	Approval         *vault.AIPendingApproval  `json:"approval,omitempty"`
	Memory           *vault.HostMemory         `json:"memory,omitempty"`
	MemoryEntry      *vault.AIMemoryEntry      `json:"memory_entry,omitempty"`
	Proposal         *vault.AIRunbookProposal  `json:"proposal,omitempty"`
	AgentsMDProposal *vault.AIAgentsMDProposal `json:"agents_md_proposal,omitempty"`
	Compaction       *CompactionInfo           `json:"compaction,omitempty"`
	Session          *vault.AIChatSession      `json:"session,omitempty"`
	Error            string                    `json:"error,omitempty"`
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

	mu               sync.Mutex
	patrolRunning    bool
	lastPatrolAt     *time.Time
	nextPatrolAt     *time.Time
	patrolWakeCh     chan struct{}
	stopCh           chan struct{}
	onPersist        func()
	sessionLocksMu   sync.Mutex
	sessionLocks     map[string]*sync.Mutex
	extApprovalMu    sync.Mutex
	extApprovalLocks map[string]*sync.Mutex
	extExecMu        sync.Mutex
	extExecCancel    map[string]context.CancelFunc
	extExecWG        sync.WaitGroup
	extSubMu         sync.Mutex
	extSubs          map[string]map[chan struct{}]struct{}
}

func NewService(store *vault.Store, sshMgr *sshmanager.Manager) *Service {
	svc := &Service{
		store:            store,
		ssh:              sshMgr,
		llm:              NewLLMClient(),
		patrolWakeCh:     make(chan struct{}, 1),
		stopCh:           make(chan struct{}),
		sessionLocks:     make(map[string]*sync.Mutex),
		extApprovalLocks: make(map[string]*sync.Mutex),
		extExecCancel:    make(map[string]context.CancelFunc),
		extSubs:          make(map[string]map[chan struct{}]struct{}),
	}

	// When store becomes ready at startup/setup, wake up patrol scheduler immediately
	store.RegisterOnReady(func() {
		svc.NotifyPatrolConfigUpdated()
	})

	go svc.patrolSchedulerLoop()
	return svc
}

func (s *Service) lockSession(sessionID string) func() {
	s.sessionLocksMu.Lock()
	if s.sessionLocks == nil {
		s.sessionLocks = make(map[string]*sync.Mutex)
	}
	m, ok := s.sessionLocks[sessionID]
	if !ok {
		m = &sync.Mutex{}
		s.sessionLocks[sessionID] = m
	}
	s.sessionLocksMu.Unlock()
	m.Lock()
	return m.Unlock
}

func (s *Service) lockExternalApproval(approvalID string) func() {
	s.extApprovalMu.Lock()
	if s.extApprovalLocks == nil {
		s.extApprovalLocks = make(map[string]*sync.Mutex)
	}
	m, ok := s.extApprovalLocks[approvalID]
	if !ok {
		m = &sync.Mutex{}
		s.extApprovalLocks[approvalID] = m
	}
	s.extApprovalMu.Unlock()
	m.Lock()
	return m.Unlock
}

// UpdateSession safely updates a session's execution mode, target servers, or title while serialized
// against concurrent chat streams, approval resolutions, and context compactions on the same session.
func (s *Service) UpdateSession(sessionID string, mode vault.AIExecutionMode, serverIDs *[]string, title *string) (*vault.AIChatSession, error) {
	unlock := s.lockSession(sessionID)
	defer unlock()

	sess, err := s.store.GetAISession(sessionID)
	if err != nil {
		return nil, err
	}
	if mode == vault.AIModeSuggest || mode == vault.AIModeStandard || mode == vault.AIModeAutonomous {
		sess.Mode = mode
	}
	if serverIDs != nil {
		sess.ServerIDs = slices.Clone(*serverIDs)
	}
	if title != nil && strings.TrimSpace(*title) != "" {
		sess.Title = strings.TrimSpace(*title)
	}
	if err := s.store.SaveAISession(*sess); err != nil {
		return nil, err
	}
	return sess, nil
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
	s.extExecMu.Lock()
	for id, cancel := range s.extExecCancel {
		if cancel != nil {
			cancel()
		}
		delete(s.extExecCancel, id)
	}
	s.extExecMu.Unlock()
	s.extExecWG.Wait()

	s.extSubMu.Lock()
	for _, subs := range s.extSubs {
		for ch := range subs {
			select {
			case ch <- struct{}{}:
			default:
			}
		}
	}
	s.extSubMu.Unlock()
}

func (s *Service) registerExternalExecCancel(approvalID string, cancel context.CancelFunc) {
	s.extExecMu.Lock()
	if s.extExecCancel == nil {
		s.extExecCancel = make(map[string]context.CancelFunc)
	}
	s.extExecCancel[approvalID] = cancel
	s.extExecMu.Unlock()
}

func (s *Service) unregisterExternalExecCancel(approvalID string) {
	s.extExecMu.Lock()
	delete(s.extExecCancel, approvalID)
	s.extExecMu.Unlock()
}

func (s *Service) invokeExternalExecCancel(approvalID string) bool {
	s.extExecMu.Lock()
	cancel := s.extExecCancel[approvalID]
	s.extExecMu.Unlock()
	if cancel == nil {
		return false
	}
	cancel()
	return true
}

func (s *Service) subscribeExternalApproval(approvalID string) (chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	s.extSubMu.Lock()
	if s.extSubs == nil {
		s.extSubs = make(map[string]map[chan struct{}]struct{})
	}
	if s.extSubs[approvalID] == nil {
		s.extSubs[approvalID] = make(map[chan struct{}]struct{})
	}
	s.extSubs[approvalID][ch] = struct{}{}
	s.extSubMu.Unlock()

	unsub := func() {
		s.extSubMu.Lock()
		if subs := s.extSubs[approvalID]; subs != nil {
			delete(subs, ch)
			if len(subs) == 0 {
				delete(s.extSubs, approvalID)
			}
		}
		s.extSubMu.Unlock()
	}
	return ch, unsub
}

func (s *Service) notifyExternalApprovalChanged(approvalID string) {
	s.extSubMu.Lock()
	subs := s.extSubs[approvalID]
	for ch := range subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	s.extSubMu.Unlock()
}

func (s *Service) LLM() *LLMClient {
	return s.llm
}

// RunChatStream appends a user turn and runs the ReAct tool-calling loop, streaming SSE events via emit.
func (s *Service) RunChatStream(ctx context.Context, req ChatRequest, emit func(StreamEvent)) error {
	if emit == nil {
		emit = func(StreamEvent) {}
	}
	msgText := strings.TrimSpace(req.Message)
	if msgText == "" {
		return fmt.Errorf("请输入运维指令或问题描述")
	}

	prov, err := s.store.GetActiveAIProviderSecret()
	if err != nil || prov == nil {
		return fmt.Errorf("尚未配置可用的大模型供应商，请先前往「模型与网关配置」添加并激活模型")
	}

	unlock := s.lockSession(req.SessionID)
	defer unlock()

	sess, err := s.store.GetAISession(req.SessionID)
	if err != nil {
		return err
	}

	// Auto-reject stale pending approvals when user sends a new instruction, keeping assistant tool records in sync
	now := time.Now().UTC()
	for i := range sess.PendingApprovals {
		if sess.PendingApprovals[i].Status == "pending" {
			const rejectReason = "管理员未批准该待定变更操作，已跳过并发送了新指令。"
			sess.PendingApprovals[i].Status = "rejected"
			sess.PendingApprovals[i].ResolvedAt = &now
			updateAssistantToolRecordStatus(sess, sess.PendingApprovals[i].ToolCallID, "rejected", rejectReason, 0)
			sess.Messages = append(sess.Messages, vault.AIChatMessage{
				ID:         uuid.NewString(),
				Role:       "tool",
				ToolCallID: sess.PendingApprovals[i].ToolCallID,
				ToolName:   sess.PendingApprovals[i].ToolName,
				Content:    rejectReason,
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
	if emit == nil {
		emit = func(StreamEvent) {}
	}
	unlock := s.lockSession(sessionID)
	defer unlock()

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

	if approve && !isErr {
		if savedMem := s.maybeRecordApprovedChangeMemory(sess, ap, clientIP); savedMem != nil {
			emit(StreamEvent{Type: "memory_saved", MemoryEntry: savedMem})
		}
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

func (s *Service) maybeRecordApprovedChangeMemory(sess *vault.AIChatSession, ap vault.AIPendingApproval, clientIP string) *vault.AIMemoryEntry {
	memCfg, err := s.store.GetAIMemoryConfig()
	if err != nil || !memCfg.AutoRecordApprovedChanges {
		return nil
	}
	if ap.ToolName != "exec_ssh_command" && ap.ToolName != "sftp_write_file" {
		return nil
	}
	var title string
	var content strings.Builder
	targets := nonEmpty(strings.Join(ap.ServerNames, ", "), "目标主机")
	if ap.ToolName == "sftp_write_file" {
		title = fmt.Sprintf("配置变更：%s (%s)", ap.FilePath, targets)
		content.WriteString(fmt.Sprintf("管理员审批通过并在 [%s] 修改了远程配置文件 `%s`。\n变更说明：%s", targets, ap.FilePath, nonEmpty(ap.Reason, "无")))
		if strings.TrimSpace(ap.DiffPreview) != "" {
			diffBrief, _ := truncateRunes(strings.TrimSpace(ap.DiffPreview), 420)
			content.WriteString("\n变更摘要：\n" + diffBrief)
		}
	} else {
		cmdBrief, _ := truncateRunes(strings.TrimSpace(ap.Command), 64)
		title = fmt.Sprintf("远程变更：%s (%s)", cmdBrief, targets)
		content.WriteString(fmt.Sprintf("管理员审批通过并在 [%s] 执行了命令：`%s`\n变更说明：%s", targets, strings.TrimSpace(ap.Command), nonEmpty(ap.Reason, "无")))
	}
	scope := "global"
	if len(ap.ServerIDs) > 0 {
		scope = "server"
	}
	saved, err := s.store.UpsertAIMemory(vault.AIMemoryEntry{
		Scope:           scope,
		ServerIDs:       ap.ServerIDs,
		Category:        "change",
		Title:           title,
		Content:         content.String(),
		Tags:            []string{"HITL审批", ap.ToolName},
		Importance:      4,
		Source:          "approval",
		SourceSessionID: sess.ID,
	}, true, clientIP)
	if err != nil {
		return nil
	}
	return saved
}

func (s *Service) continueAgentLoop(
	ctx context.Context,
	sess *vault.AIChatSession,
	prov vault.AIProviderConfig,
	clientIP string,
	emit func(StreamEvent),
) error {
	if emit == nil {
		emit = func(StreamEvent) {}
	}
	tools := s.agentToolsSchema()
	memCfg, _ := s.store.GetAIMemoryConfig()
	if memCfg.CompactionKeepRecent <= 0 {
		memCfg = vault.DefaultAIMemoryConfig()
	}

	for step := 0; step < maxReActIterations; step++ {
		// Automatically compact older turns into a non-destructive rolling summary when nearing context window
		if compInfo, compErr := s.runCompactionOnSession(ctx, sess, &prov, memCfg.CompactionKeepRecent, false); compErr == nil && compInfo != nil && compInfo.Triggered {
			emit(StreamEvent{Type: "context_compacted", Compaction: compInfo})
		}

		assembled := s.assembleSessionPrompt(sess)
		if step == 0 && len(assembled.InjectedMemoryIDs) > 0 {
			s.store.TouchAIMemoryUsage(assembled.InjectedMemoryIDs)
		}

		ctxWin := EffectiveContextWindow(prov)
		outReserve := prov.MaxTokens
		if outReserve <= 0 {
			outReserve = 4096
		}
		maxHistTokens := ctxWin - assembled.Inspection.EstimatedSystemTokens - assembled.Inspection.EstimatedSummaryTokens - outReserve - 1024
		if maxHistTokens < 4096 {
			maxHistTokens = 4096
		}
		effectiveHistory := buildEffectiveHistoryForLLM(sess, maxHistTokens)

		turn, err := s.llm.StreamChat(ctx, prov, assembled.SystemPrompt, effectiveHistory, tools, func(chunk string) {
			emit(StreamEvent{Type: "delta", Delta: chunk})
		})
		if err != nil {
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

	const limitNotice = "已达到单轮最大自动工具调用步数上限（8 步），以上为目前采集到的全部诊断与执行结果。如需继续深度排查或执行后续操作，请发送进一步指令。"
	emit(StreamEvent{Type: "delta", Delta: limitNotice})
	sess.Messages = append(sess.Messages, vault.AIChatMessage{
		ID:        uuid.NewString(),
		Role:      "assistant",
		Content:   limitNotice,
		Timestamp: time.Now().UTC(),
	})
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
		hasTransportErr := false
		for _, r := range results {
			if r.Error != "" {
				hasTransportErr = true
				break
			}
		}
		s.store.RecordAudit("ai.exec", strings.Join(names, ","), fmt.Sprintf("AI 执行命令(%s): %.70s", risk, args.Command), clientIP, !hasTransportErr)

		rec.DurationMs = time.Since(start).Milliseconds()
		outStr := formatBatchExecResults(results)
		if hasTransportErr {
			rec.Status = "error"
		} else {
			rec.Status = "completed"
		}
		rec.Output = truncateStr(outStr, 4000)
		return toolDispatchOutcome{record: rec, toolOutput: outStr, isError: hasTransportErr}

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

		if IsBlockedReadPath(args.Path) {
			rec.RiskLevel = string(RiskBlocked)
			rec.Status = "blocked"
			rec.Output = fmt.Sprintf("安全护栏禁止读取敏感凭据/密钥文件 (%s)", strings.TrimSpace(args.Path))
			s.store.RecordAudit("ai.blocked", srvName+":"+strings.TrimSpace(args.Path), rec.Output, clientIP, false)
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
		if IsBlockedWritePath(cleanPath) {
			rec.RiskLevel = string(RiskBlocked)
			rec.Status = "blocked"
			rec.Output = fmt.Sprintf("安全熔断器禁止 AI 直接覆写系统核心鉴权或保险库文件 (%s)", cleanPath)
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
			Constraints string   `json:"constraints"`
			Notes       string   `json:"notes"`
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
			Constraints: args.Constraints,
			Notes:       args.Notes,
		}, true, clientIP)
		rec.DurationMs = time.Since(start).Milliseconds()
		if err != nil {
			rec.Status = "error"
			rec.Output = err.Error()
			return toolDispatchOutcome{record: rec, toolOutput: err.Error(), isError: true}
		}
		emit(StreamEvent{Type: "memory_updated", Memory: mem})
		rec.Status = "completed"
		rec.Output = fmt.Sprintf("已将 %s 的主机环境特征增量保存至加密保险库", srvName)
		return toolDispatchOutcome{record: rec, toolOutput: rec.Output}

	case "save_memory":
		var args struct {
			ID         string   `json:"id"`
			Scope      string   `json:"scope"`
			ServerIDs  []string `json:"server_ids"`
			Category   string   `json:"category"`
			Title      string   `json:"title"`
			Content    string   `json:"content"`
			Tags       []string `json:"tags"`
			Importance int      `json:"importance"`
			Pinned     bool     `json:"pinned"`
		}
		_ = json.Unmarshal([]byte(tc.Arguments), &args)
		if strings.EqualFold(strings.TrimSpace(args.Scope), "server") && len(args.ServerIDs) == 0 && len(sess.ServerIDs) > 0 {
			args.ServerIDs = slices.Clone(sess.ServerIDs)
		}
		rec.RiskLevel = string(RiskReadOnly)
		rec.Summary = fmt.Sprintf("沉淀长期记忆: %s", nonEmpty(args.Title, "未命名记忆"))

		saved, err := s.store.UpsertAIMemory(vault.AIMemoryEntry{
			ID:              args.ID,
			Scope:           args.Scope,
			ServerIDs:       args.ServerIDs,
			Category:        args.Category,
			Title:           args.Title,
			Content:         args.Content,
			Tags:            args.Tags,
			Importance:      args.Importance,
			Pinned:          args.Pinned,
			Source:          "ai",
			SourceSessionID: sess.ID,
		}, true, clientIP)
		rec.DurationMs = time.Since(start).Milliseconds()
		if err != nil {
			rec.Status = "error"
			rec.Output = err.Error()
			return toolDispatchOutcome{record: rec, toolOutput: err.Error(), isError: true}
		}
		emit(StreamEvent{Type: "memory_saved", MemoryEntry: saved})
		rec.Status = "completed"
		rec.Output = fmt.Sprintf("已保存长期记忆 [%s/%s]《%s》(id: %s)", saved.Scope, memoryCategoryLabel(saved.Category), saved.Title, saved.ID)
		return toolDispatchOutcome{record: rec, toolOutput: rec.Output}

	case "delete_memory":
		var args struct {
			MemoryID string `json:"memory_id"`
			Reason   string `json:"reason"`
		}
		_ = json.Unmarshal([]byte(tc.Arguments), &args)
		rec.RiskLevel = string(RiskReadOnly)
		rec.Summary = fmt.Sprintf("清理过期长期记忆 (%s)", args.MemoryID)

		if err := s.store.DeleteAIMemory(strings.TrimSpace(args.MemoryID), clientIP); err != nil {
			rec.DurationMs = time.Since(start).Milliseconds()
			rec.Status = "error"
			rec.Output = err.Error()
			return toolDispatchOutcome{record: rec, toolOutput: "删除长期记忆失败: " + err.Error(), isError: true}
		}
		rec.DurationMs = time.Since(start).Milliseconds()
		rec.Status = "completed"
		rec.Output = fmt.Sprintf("已删除过期长期记忆 %s（原因: %s）", args.MemoryID, nonEmpty(args.Reason, "事实已更新"))
		return toolDispatchOutcome{record: rec, toolOutput: rec.Output}

	case "search_memory":
		var args struct {
			Query    string `json:"query"`
			ServerID string `json:"server_id"`
			Category string `json:"category"`
			Limit    int    `json:"limit"`
		}
		_ = json.Unmarshal([]byte(tc.Arguments), &args)
		if args.Limit <= 0 || args.Limit > 20 {
			args.Limit = 8
		}
		rec.RiskLevel = string(RiskReadOnly)
		rec.Summary = fmt.Sprintf("检索历史运维记忆 (%s)", nonEmpty(args.Query, "全部"))

		out, hitIDs := s.executeSearchMemory(args.Query, args.ServerID, args.Category, args.Limit, nil)
		if len(hitIDs) > 0 {
			s.store.TouchAIMemoryUsage(hitIDs)
		}
		rec.DurationMs = time.Since(start).Milliseconds()
		rec.Status = "completed"
		rec.Output = truncateStr(out, 3000)
		return toolDispatchOutcome{record: rec, toolOutput: out}

	case "get_runbook":
		var args struct {
			RunbookID string `json:"runbook_id"`
			Query     string `json:"query"`
		}
		_ = json.Unmarshal([]byte(tc.Arguments), &args)
		rec.RiskLevel = string(RiskReadOnly)
		rec.Summary = fmt.Sprintf("调阅排障 Runbook 详情 (%s)", nonEmpty(args.RunbookID, args.Query))

		out, found := s.executeGetRunbook(args.RunbookID, args.Query)
		rec.DurationMs = time.Since(start).Milliseconds()
		if !found {
			rec.Status = "error"
			rec.Output = out
			return toolDispatchOutcome{record: rec, toolOutput: out, isError: true}
		}
		rec.Status = "completed"
		rec.Output = truncateStr(out, 3000)
		return toolDispatchOutcome{record: rec, toolOutput: out}

	case "propose_agents_md_update":
		var args struct {
			Reason         string `json:"reason"`
			Summary        string `json:"summary"`
			UpdatedContent string `json:"updated_content"`
		}
		_ = json.Unmarshal([]byte(tc.Arguments), &args)
		rec.RiskLevel = string(RiskReadOnly)
		rec.Summary = fmt.Sprintf("提议修订全局 AGENTS.md: %s", nonEmpty(args.Summary, "规范更新"))

		cleanNew := vault.RedactSensitiveText(strings.ReplaceAll(strings.TrimSpace(args.UpdatedContent), "\r\n", "\n"))
		if cleanNew == "" {
			rec.DurationMs = time.Since(start).Milliseconds()
			rec.Status = "error"
			rec.Output = "提议的 AGENTS.md 内容不能为空"
			return toolDispatchOutcome{record: rec, toolOutput: rec.Output, isError: true}
		}
		curAgentsMD, _ := s.store.GetAgentsMD()
		diff := BuildUnifiedDiff("AGENTS.md", curAgentsMD.Content, cleanNew)
		prop := vault.AIAgentsMDProposal{
			ID:              uuid.NewString(),
			SessionID:       sess.ID,
			Reason:          nonEmpty(vault.RedactSensitiveText(strings.TrimSpace(args.Reason)), "沉淀团队全局运维规范"),
			Summary:         nonEmpty(vault.RedactSensitiveText(strings.TrimSpace(args.Summary)), "更新全局 AGENTS.md 运维规范"),
			ProposedContent: cleanNew,
			DiffPreview:     diff,
			Status:          "pending",
			CreatedAt:       time.Now().UTC(),
		}
		sess.AgentsMDProposals = append(sess.AgentsMDProposals, prop)
		emit(StreamEvent{Type: "agents_md_proposed", AgentsMDProposal: &prop})
		rec.DurationMs = time.Since(start).Milliseconds()
		rec.Status = "completed"
		rec.Output = fmt.Sprintf("已生成全局 AGENTS.md 修订提案卡片（%s），等待管理员审阅 Diff 后一键合入\n%s", prop.Summary, truncateStr(diff, 1200))
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

func (s *Service) executeSearchMemory(query, serverID, category string, limit int, allowedServers []string) (string, []string) {
	longMems, _ := s.store.ListAIMemories()
	hostMems, _ := s.store.ListHostMemories()
	srvNames := s.serverNameLookup()

	terms := strings.Fields(strings.ToLower(strings.TrimSpace(query)))
	catFilter := strings.ToLower(strings.TrimSpace(category))
	srvFilter := strings.TrimSpace(serverID)

	allowedSet := make(map[string]bool, len(allowedServers))
	for _, sid := range allowedServers {
		allowedSet[sid] = true
	}
	isMemAllowed := func(m vault.AIMemoryEntry) bool {
		if len(allowedSet) == 0 || m.Scope != "server" {
			return true
		}
		for _, sid := range m.ServerIDs {
			if allowedSet[sid] {
				return true
			}
		}
		return false
	}

	matchTerms := func(haystack string) int {
		if len(terms) == 0 {
			return 1
		}
		low := strings.ToLower(haystack)
		hits := 0
		for _, t := range terms {
			if strings.Contains(low, t) {
				hits++
			}
		}
		return hits
	}

	type memHit struct {
		entry vault.AIMemoryEntry
		score int
	}
	var hits []memHit
	for _, m := range longMems {
		if !isMemAllowed(m) {
			continue
		}
		if catFilter != "" && strings.ToLower(m.Category) != catFilter {
			continue
		}
		if srvFilter != "" && m.Scope == "server" && !slices.Contains(m.ServerIDs, srvFilter) {
			continue
		}
		hay := m.Title + " " + m.Content + " " + strings.Join(m.Tags, " ") + " " + memoryCategoryLabel(m.Category)
		h := matchTerms(hay)
		if h > 0 {
			sc := h*100 + m.Importance*10
			if m.Pinned {
				sc += 40
			}
			hits = append(hits, memHit{entry: m, score: sc})
		}
	}
	slices.SortStableFunc(hits, func(a, b memHit) int {
		if a.score != b.score {
			if a.score > b.score {
				return -1
			}
			return 1
		}
		if a.entry.UpdatedAt.After(b.entry.UpdatedAt) {
			return -1
		}
		return 1
	})

	var sb strings.Builder
	var hitIDs []string
	if len(hits) > 0 {
		n := min(limit, len(hits))
		sb.WriteString(fmt.Sprintf("=== 命中长期运维记忆 (%d/%d 条) ===\n", n, len(hits)))
		for i := 0; i < n; i++ {
			m := hits[i].entry
			hitIDs = append(hitIDs, m.ID)
			var scopeDesc string
			if m.Scope == "server" && len(m.ServerIDs) > 0 {
				var names []string
				for _, sid := range m.ServerIDs {
					if len(allowedSet) > 0 && !allowedSet[sid] {
						continue
					}
					names = append(names, nonEmpty(srvNames[sid], sid))
				}
				scopeDesc = "主机:" + strings.Join(names, ",")
			} else {
				scopeDesc = "全局"
			}
			sb.WriteString(fmt.Sprintf("- [%s | %s | 重要度:%d | %s] 《%s》 (id: `%s`)\n  %s\n",
				scopeDesc, memoryCategoryLabel(m.Category), m.Importance, m.UpdatedAt.Format("2006-01-02"),
				m.Title, m.ID, m.Content))
		}
	}

	var matchedHosts []vault.HostMemory
	if catFilter == "" {
		for _, hm := range hostMems {
			if len(allowedSet) > 0 && !allowedSet[hm.ServerID] {
				continue
			}
			if srvFilter != "" && hm.ServerID != srvFilter {
				continue
			}
			hay := hm.ServerName + " " + hm.Summary + " " + hm.OSArch + " " +
				strings.Join(hm.KeyServices, " ") + " " + strings.Join(hm.DeployPaths, " ") + " " +
				hm.PortsNote + " " + hm.Constraints + " " + hm.Notes
			if matchTerms(hay) > 0 {
				matchedHosts = append(matchedHosts, hm)
			}
		}
	}
	if len(matchedHosts) > 0 {
		n := min(5, len(matchedHosts))
		sb.WriteString(fmt.Sprintf("\n=== 命中主机环境画像 (%d/%d 台) ===\n", n, len(matchedHosts)))
		for i := 0; i < n; i++ {
			hm := matchedHosts[i]
			sb.WriteString(fmt.Sprintf("- %s (`%s`): %s | 服务: %s | 路径: %s | 端口: %s | 约束: %s | 备注: %s\n",
				hm.ServerName, hm.ServerID, nonEmpty(hm.Summary, "无"),
				nonEmpty(strings.Join(hm.KeyServices, ","), "无"),
				nonEmpty(strings.Join(hm.DeployPaths, ","), "无"),
				nonEmpty(hm.PortsNote, "无"),
				nonEmpty(hm.Constraints, "无"),
				nonEmpty(hm.Notes, "无"),
			))
		}
	}

	if sb.Len() == 0 {
		return "未检索到匹配的长期记忆或主机画像记录。", nil
	}
	return strings.TrimSpace(sb.String()), hitIDs
}

func (s *Service) executeGetRunbook(runbookID, query string) (string, bool) {
	runbooks, _ := s.store.ListRunbooks()
	idClean := strings.TrimSpace(runbookID)
	qClean := strings.ToLower(strings.TrimSpace(query))

	var matched []vault.AIRunbook
	for _, rb := range runbooks {
		if idClean != "" && rb.ID == idClean {
			matched = []vault.AIRunbook{rb}
			break
		}
		if qClean != "" {
			hay := strings.ToLower(rb.Title + " " + rb.Category + " " + rb.Symptom + " " + rb.RootCause + " " + strings.Join(rb.Tags, " "))
			if strings.Contains(hay, qClean) {
				matched = append(matched, rb)
			}
		}
	}
	if len(matched) == 0 && idClean == "" && qClean == "" {
		matched = runbooks
	}
	if len(matched) == 0 {
		return "未找到匹配的 Runbook 排障技能。", false
	}

	var sb strings.Builder
	limit := min(3, len(matched))
	for i := 0; i < limit; i++ {
		rb := matched[i]
		sb.WriteString(fmt.Sprintf("### 《%s》 (`%s` | %s)\n", rb.Title, rb.ID, rb.Category))
		sb.WriteString("- **适用症状**: " + rb.Symptom + "\n")
		if rb.RootCause != "" {
			sb.WriteString("- **典型根因**: " + rb.RootCause + "\n")
		}
		if len(rb.DiagnosticSteps) > 0 {
			sb.WriteString("- **诊断步骤**:\n")
			for idx, st := range rb.DiagnosticSteps {
				sb.WriteString(fmt.Sprintf("  %d. %s\n", idx+1, st))
			}
		}
		if len(rb.FixCommands) > 0 {
			sb.WriteString("- **推荐修复命令**:\n")
			for _, cmd := range rb.FixCommands {
				sb.WriteString("  - `" + cmd + "`\n")
			}
		}
		if rb.Verification != "" {
			sb.WriteString("- **验证方法**: " + rb.Verification + "\n")
		}
		sb.WriteString("\n")
	}
	return strings.TrimSpace(sb.String()), true
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
		out := formatBatchExecResults(results)
		var execErr error
		for _, r := range results {
			if r.Error != "" || r.ExitCode != 0 {
				execErr = fmt.Errorf("部分或全部主机命令执行失败（存在连接错误或非零退出码）")
				break
			}
		}
		s.store.RecordAudit("ai.approved_exec", strings.Join(ap.ServerNames, ","), fmt.Sprintf("管理员批准执行 AI 命令: %.75s", ap.Command), clientIP, execErr == nil)
		return out, execErr

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
		if IsBlockedReadPath(ap.FilePath) {
			return "", fmt.Errorf("安全护栏禁止读取敏感凭据/密钥文件 (%s)", ap.FilePath)
		}
		return s.ssh.SFTPReadText(ap.ServerIDs[0], ap.FilePath, clientIP)

	case "sftp_write_file":
		if len(ap.ServerIDs) == 0 {
			return "", fmt.Errorf("缺少目标服务器 ID")
		}
		if IsBlockedWritePath(ap.FilePath) {
			return "", fmt.Errorf("安全熔断器禁止修改系统核心鉴权或保险库文件 (%s)", ap.FilePath)
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
	return s.assembleSessionPrompt(sess).SystemPrompt
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
			Description: "自动增量更新某台服务器的客观环境画像与避坑约束（核心服务、部署路径、端口用途、系统架构、运维禁忌、备注），后续对话与巡检将自动携带。",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"server_id":    map[string]any{"type": "string", "description": "目标服务器 server_id"},
					"summary":      map[string]any{"type": "string", "description": "主机角色与业务环境一句话摘要"},
					"os_arch":      map[string]any{"type": "string", "description": "发行版、内核与架构"},
					"key_services": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "运行的关键服务或组件列表，如 nginx, docker, postgres"},
					"deploy_paths": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "关键配置或应用部署目录，如 /opt/app, /etc/nginx/conf.d"},
					"ports_note":   map[string]any{"type": "string", "description": "重要监听端口与用途说明"},
					"constraints":  map[string]any{"type": "string", "description": "该主机专属的运维禁忌与避坑红线（例如不可直接重启主库）"},
					"notes":        map[string]any{"type": "string", "description": "其他补充运维备注（严禁含密码或密钥）"},
				},
				"required": []string{"server_id"},
			},
		},
		{
			Name:        "save_memory",
			Description: "沉淀或更新一条跨会话长期记忆（管理员偏好、架构拓扑依赖、历史故障根因、重要变更结论或运维经验），系统会自动按标题去重合并并屏蔽敏感凭据。",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id":         map[string]any{"type": "string", "description": "可选：更新已有记忆时填写其 id"},
					"scope":      map[string]any{"type": "string", "enum": []string{"global", "server"}, "description": "记忆作用范围：global(全局) 或 server(指定主机)"},
					"server_ids": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "当 scope=server 时关联的 server_id 列表"},
					"category":   map[string]any{"type": "string", "enum": []string{"preference", "topology", "incident", "change", "lesson"}, "description": "记忆分类"},
					"title":      map[string]any{"type": "string", "description": "简明准确的记忆标题（25字以内）"},
					"content":    map[string]any{"type": "string", "description": "具体可复用的事实、偏好或故障结论（严禁记录任何明文密码/私钥/API Key）"},
					"tags":       map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "检索标签，如 nginx, backup, maintenance"},
					"importance": map[string]any{"type": "integer", "description": "重要度 1-5（默认 3，关键红线或高频偏好填 4-5）"},
					"pinned":     map[string]any{"type": "boolean", "description": "是否置顶强制注入每次对话"},
				},
				"required": []string{"category", "title", "content"},
			},
		},
		{
			Name:        "delete_memory",
			Description: "清理一条已过时、错误或被新架构取代的长期记忆条目。",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"memory_id": map[string]any{"type": "string", "description": "要删除的长期记忆 ID"},
					"reason":    map[string]any{"type": "string", "description": "删除原因说明"},
				},
				"required": []string{"memory_id"},
			},
		},
		{
			Name:        "search_memory",
			Description: "按关键词、分类或主机 ID 深度检索全部长期记忆库与主机画像（用于召回未直接注入 System Prompt 的历史变更、故障根因或跨机信息）。",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query":     map[string]any{"type": "string", "description": "检索关键词（支持多词空格分隔，留空则返回高优列表）"},
					"server_id": map[string]any{"type": "string", "description": "可选：按特定服务器过滤"},
					"category":  map[string]any{"type": "string", "description": "可选：preference / topology / incident / change / lesson"},
					"limit":     map[string]any{"type": "integer", "description": "返回最大条数（默认 8，最大 20）"},
				},
			},
		},
		{
			Name:        "get_runbook",
			Description: "按 ID 或关键词调阅保险库中某条排障技能 Runbook 的完整诊断步骤、修复命令与验证方案。",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"runbook_id": map[string]any{"type": "string", "description": "Runbook ID（来自索引列表）"},
					"query":      map[string]any{"type": "string", "description": "或者按标题/症状/标签模糊检索"},
				},
			},
		},
		{
			Name:        "propose_agents_md_update",
			Description: "向管理员提议修订全局 AGENTS.md 运维规范文档（不会直接生效，系统将生成 Unified Diff 提案卡片由管理员审阅并一键合入）。",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"summary":         map[string]any{"type": "string", "description": "本次规范修订的简短标题"},
					"reason":          map[string]any{"type": "string", "description": "为什么建议将该条沉淀到全局 AGENTS.md"},
					"updated_content": map[string]any{"type": "string", "description": "完整的修订后 AGENTS.md Markdown 全文"},
				},
				"required": []string{"summary", "reason", "updated_content"},
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

// TruncateUTF8Bytes truncates s to at most maxBytes bytes without splitting a multi-byte UTF-8 character.
func TruncateUTF8Bytes(s string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	if len(s) <= maxBytes {
		return s
	}
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

func truncateStr(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	return TruncateUTF8Bytes(s, maxBytes) + "\n... [输出过长已截断]"
}

func nonEmpty(val, fallback string) string {
	if strings.TrimSpace(val) != "" {
		return val
	}
	return fallback
}

import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertTriangle,
  ArrowUpRight,
  Ban,
  Bot,
  CheckCircle2,
  ClipboardCheck,
  Clock,
  FileCode2,
  ListOrdered,
  Loader2,
  Lock,
  MessageSquare,
  PlugZap,
  Radar,
  RefreshCw,
  RotateCcw,
  Search,
  ShieldAlert,
  ShieldCheck,
  SkipForward,
  StopCircle,
  Terminal,
  TerminalSquare,
  X,
  XCircle,
} from 'lucide-react';
import { api } from '../api';
import type {
  ExternalApproval,
  ExternalApprovalStatus,
  ExternalApprovalStep,
  ExternalApprovalStepStatus,
  ServerView,
  SessionApprovalItem,
} from '../types';
import { UnifiedDiffViewer } from './AIMessageWidgets';

type StatusFilter = 'active' | 'completed' | 'issue' | 'all';
type SourceFilter = 'all' | 'mcp' | 'builtin';

export interface ApprovalCountsSnapshot {
  pendingExternal: number;
  runningExternal: number;
  pendingSession: number;
}

export interface ApprovalCenterProps {
  servers: ServerView[];
  onApprovalCountsChange?: (counts: ApprovalCountsSnapshot) => void;
  onOpenMCPConfig: () => void;
  onOpenPatrol: () => void;
  onJumpCenterSession: (sessionId: string) => void;
  onJumpTerminalCopilot: (serverId: string, sessionId: string) => void;
  onNotify: (msg: string) => void;
}

const PLAN_STATUS_META: Record<
  ExternalApprovalStatus,
  { label: string; chipClass: string; cardClass: string }
> = {
  pending: { label: '待审阅批准', chipClass: 'amber', cardClass: '' },
  running: { label: '按序执行中', chipClass: 'teal', cardClass: 'resolved-running' },
  completed: { label: '全部执行完成', chipClass: 'teal', cardClass: 'resolved-approved' },
  approved: { label: '已批准执行', chipClass: 'teal', cardClass: 'resolved-approved' },
  partial_failed: { label: '部分步骤失败', chipClass: 'danger', cardClass: 'resolved-failed' },
  failed: { label: '执行失败', chipClass: 'danger', cardClass: 'resolved-failed' },
  cancelled: { label: '已中止执行', chipClass: 'amber', cardClass: 'resolved-rejected' },
  rejected: { label: '管理员已拒绝', chipClass: '', cardClass: 'resolved-rejected' },
};

const STEP_STATUS_META: Record<
  ExternalApprovalStepStatus,
  { label: string; chipClass: string }
> = {
  pending: { label: '待执行', chipClass: '' },
  blocked: { label: '安全拦截锁定', chipClass: 'danger' },
  running: { label: '执行中...', chipClass: 'teal' },
  succeeded: { label: '执行成功', chipClass: 'teal' },
  failed: { label: '执行失败', chipClass: 'danger' },
  skipped: { label: '已跳过', chipClass: '' },
  cancelled: { label: '已中止', chipClass: 'amber' },
  rejected: { label: '已拒绝', chipClass: '' },
};

const SESSION_APPROVAL_STATUS_META: Record<
  string,
  { label: string; chipClass: string; cardClass: string }
> = {
  pending: { label: '待对话内授权', chipClass: 'amber', cardClass: '' },
  approved: { label: '已批准执行', chipClass: 'teal', cardClass: 'resolved-approved' },
  rejected: { label: '管理员已拒绝', chipClass: '', cardClass: 'resolved-rejected' },
};

function getNormalizedSteps(ap: ExternalApproval): ExternalApprovalStep[] {
  if (ap.steps && ap.steps.length > 0) {
    return ap.steps;
  }
  const toolName =
    ap.tool_name === 'sftp_write_file' || ap.file_path ? 'sftp_write_file' : 'exec_ssh_command';
  const stepStatus: ExternalApprovalStepStatus =
    ap.status === 'rejected'
      ? 'rejected'
      : ap.status === 'approved' || ap.status === 'completed'
      ? ap.execution_error
        ? 'failed'
        : 'succeeded'
      : ap.status === 'failed'
      ? 'failed'
      : 'pending';
  return [
    {
      id: `${ap.id}-step-1`,
      index: 1,
      title:
        ap.title ||
        (toolName === 'sftp_write_file' ? `修改配置 ${ap.file_path || ''}` : ap.command || '远程命令'),
      tool_name: toolName,
      server_ids: ap.server_ids || [],
      server_names: ap.server_names || [],
      risk_level: ap.risk_level || 'high',
      reason: ap.reason,
      command: ap.command,
      file_path: ap.file_path,
      diff_preview: ap.diff_preview,
      selected: ap.status !== 'rejected',
      status: stepStatus,
      execution_out: ap.execution_out,
      execution_error: ap.execution_error,
      duration_ms: ap.duration_ms,
      completed_at: ap.resolved_at,
    },
  ];
}

function getSessionApprovalTitle(item: SessionApprovalItem): string {
  if (item.tool_name === 'sftp_write_file' || item.file_path) {
    return item.file_path ? `修改远程文件 ${item.file_path}` : 'SFTP 文件写入变更';
  }
  if (item.tool_name === 'exec_ssh_command' || item.command) {
    return '执行远程 SSH 变更命令';
  }
  return item.tool_name || '内置 AI 状态变更操作';
}

type UnifiedItem =
  | { kind: 'mcp'; id: string; createdAtMs: number; priority: number; data: ExternalApproval }
  | { kind: 'builtin'; id: string; createdAtMs: number; priority: number; data: SessionApprovalItem };

function parseTimeMs(iso?: string): number {
  if (!iso) return 0;
  const ms = new Date(iso).getTime();
  return Number.isFinite(ms) ? ms : 0;
}

function matchesExternalStatus(
  ap: ExternalApproval,
  filter: StatusFilter,
  pinnedIds: string[]
): boolean {
  switch (filter) {
    case 'active':
      return ap.status === 'pending' || ap.status === 'running' || pinnedIds.includes(ap.id);
    case 'completed':
      return ap.status === 'completed' || ap.status === 'approved';
    case 'issue':
      return (
        ap.status === 'partial_failed' ||
        ap.status === 'failed' ||
        ap.status === 'cancelled' ||
        ap.status === 'rejected'
      );
    case 'all':
    default:
      return true;
  }
}

function matchesSessionStatus(item: SessionApprovalItem, filter: StatusFilter): boolean {
  switch (filter) {
    case 'active':
      return item.status === 'pending';
    case 'completed':
      return item.status === 'approved';
    case 'issue':
      return item.status === 'rejected';
    case 'all':
    default:
      return true;
  }
}

export const ApprovalCenter: React.FC<ApprovalCenterProps> = ({
  servers,
  onApprovalCountsChange,
  onOpenMCPConfig,
  onOpenPatrol,
  onJumpCenterSession,
  onJumpTerminalCopilot,
  onNotify,
}) => {
  const [externalApprovals, setExternalApprovals] = useState<ExternalApproval[]>([]);
  const [sessionApprovals, setSessionApprovals] = useState<SessionApprovalItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const [statusFilter, setStatusFilter] = useState<StatusFilter>('active');
  const [sourceFilter, setSourceFilter] = useState<SourceFilter>('all');
  const [serverFilter, setServerFilter] = useState<string>('');
  const [searchQuery, setSearchQuery] = useState<string>('');

  const [resolvingId, setResolvingId] = useState<string>('');
  const [cancellingId, setCancellingId] = useState<string>('');
  const [stepSelectionMap, setStepSelectionMap] = useState<Record<string, Record<string, boolean>>>(
    {}
  );
  // Keep MCP plans approved/cancelled in this session visible under "active" filter so live results don't vanish abruptly
  const [pinnedPlanIds, setPinnedPlanIds] = useState<string[]>([]);

  const mountedRef = useRef(true);
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  const syncCounts = useCallback(
    (pendingExternal: number, runningExternal: number, pendingSession: number) => {
      onApprovalCountsChange?.({
        pendingExternal,
        runningExternal,
        pendingSession,
      });
    },
    [onApprovalCountsChange]
  );

  const loadApprovals = useCallback(
    async (silent = false) => {
      if (!silent) setRefreshing(true);
      try {
        const res = await api.listUnifiedApprovals(120);
        if (!mountedRef.current) return;
        setExternalApprovals(res.external_approvals || []);
        setSessionApprovals(res.session_approvals || []);
        syncCounts(
          res.pending_external_count || 0,
          res.running_external_count || 0,
          res.pending_session_count || 0
        );
      } catch (err: any) {
        if (!silent && mountedRef.current) {
          onNotify(err?.message || '加载执行审批队列失败');
        }
      } finally {
        if (mountedRef.current) {
          setLoading(false);
          if (!silent) setRefreshing(false);
        }
      }
    },
    [onNotify, syncCounts]
  );

  useEffect(() => {
    void loadApprovals(true);
  }, [loadApprovals]);

  const stats = useMemo(() => {
    let pendingExt = 0;
    let runningExt = 0;
    let completedExt = 0;
    let failedOrCancelledExt = 0;
    let rejectedExt = 0;

    for (const ap of externalApprovals) {
      switch (ap.status) {
        case 'pending':
          pendingExt++;
          break;
        case 'running':
          runningExt++;
          break;
        case 'completed':
        case 'approved':
          completedExt++;
          break;
        case 'partial_failed':
        case 'failed':
        case 'cancelled':
          failedOrCancelledExt++;
          break;
        case 'rejected':
          rejectedExt++;
          break;
      }
    }

    let pendingSess = 0;
    let approvedSess = 0;
    let rejectedSess = 0;

    for (const item of sessionApprovals) {
      if (item.status === 'pending') pendingSess++;
      else if (item.status === 'approved') approvedSess++;
      else if (item.status === 'rejected') rejectedSess++;
    }

    const activeExtCount = externalApprovals.filter(
      (ap) => ap.status === 'pending' || ap.status === 'running' || pinnedPlanIds.includes(ap.id)
    ).length;

    return {
      pendingExt,
      runningExt,
      completedExt,
      failedOrCancelledExt,
      rejectedExt,
      pendingSess,
      approvedSess,
      rejectedSess,
      pendingTotal: pendingExt + pendingSess,
      activeTotal: activeExtCount + pendingSess,
      completedTotal: completedExt + approvedSess,
      issueTotal: failedOrCancelledExt + rejectedExt + rejectedSess,
      rejectedTotal: rejectedExt + rejectedSess,
      allTotal: externalApprovals.length + sessionApprovals.length,
    };
  }, [externalApprovals, sessionApprovals, pinnedPlanIds]);

  // Fast 1.5s polling while any MCP plan is actively running; gentle 5s polling when idle; pause when tab is hidden
  useEffect(() => {
    const intervalMs = stats.runningExt > 0 ? 1500 : 5000;
    const timer = window.setInterval(() => {
      if (document.hidden) return;
      void loadApprovals(true);
    }, intervalMs);

    const onVisibility = () => {
      if (!document.hidden) {
        void loadApprovals(true);
      }
    };
    document.addEventListener('visibilitychange', onVisibility);
    return () => {
      window.clearInterval(timer);
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, [stats.runningExt, loadApprovals]);

  const serverNameById = useMemo(() => {
    const m: Record<string, string> = {};
    for (const srv of servers) m[srv.id] = srv.name;
    return m;
  }, [servers]);

  const serverOptions = useMemo(() => {
    const map = new Map<string, string>();
    for (const srv of servers) {
      map.set(srv.id, `${srv.name} (${srv.host})`);
    }
    for (const ap of externalApprovals) {
      (ap.server_ids || []).forEach((id, idx) => {
        if (id && !map.has(id)) {
          map.set(id, ap.server_names?.[idx] || id);
        }
      });
    }
    for (const item of sessionApprovals) {
      (item.server_ids || []).forEach((id, idx) => {
        if (id && !map.has(id)) {
          map.set(id, item.server_names?.[idx] || id);
        }
      });
    }
    return Array.from(map.entries()).map(([id, label]) => ({ id, label }));
  }, [servers, externalApprovals, sessionApprovals]);

  const unifiedItems = useMemo<UnifiedItem[]>(() => {
    const q = searchQuery.trim().toLowerCase();
    const list: UnifiedItem[] = [];

    if (sourceFilter === 'all' || sourceFilter === 'mcp') {
      for (const ap of externalApprovals) {
        if (!matchesExternalStatus(ap, statusFilter, pinnedPlanIds)) continue;
        const steps = getNormalizedSteps(ap);
        if (serverFilter) {
          const hasServer =
            (ap.server_ids || []).includes(serverFilter) ||
            steps.some((st) => (st.server_ids || []).includes(serverFilter));
          if (!hasServer) continue;
        }
        if (q) {
          const haystack = [
            ap.id,
            ap.title,
            ap.reason,
            ap.client_name,
            ap.token_name,
            ap.command,
            ap.file_path,
            ap.patrol_record_id,
            ...(ap.server_names || []),
            ...steps.flatMap((st) => [
              st.title,
              st.reason,
              st.command,
              st.file_path,
              ...(st.server_names || []),
            ]),
          ]
            .filter(Boolean)
            .join(' ')
            .toLowerCase();
          if (!haystack.includes(q)) continue;
        }
        const priority =
          ap.status === 'running'
            ? 0
            : ap.status === 'pending'
            ? 1
            : pinnedPlanIds.includes(ap.id)
            ? 2
            : 3;
        list.push({
          kind: 'mcp',
          id: `mcp:${ap.id}`,
          createdAtMs: parseTimeMs(ap.created_at),
          priority,
          data: ap,
        });
      }
    }

    if (sourceFilter === 'all' || sourceFilter === 'builtin') {
      for (const item of sessionApprovals) {
        if (!matchesSessionStatus(item, statusFilter)) continue;
        if (serverFilter) {
          const hasServer =
            (item.server_ids || []).includes(serverFilter) ||
            (item.session_server_ids || []).includes(serverFilter);
          if (!hasServer) continue;
        }
        if (q) {
          const haystack = [
            item.id,
            item.session_id,
            item.session_title,
            item.session_scope,
            item.tool_name,
            item.reason,
            item.command,
            item.file_path,
            ...(item.server_names || []),
          ]
            .filter(Boolean)
            .join(' ')
            .toLowerCase();
          if (!haystack.includes(q)) continue;
        }
        const priority = item.status === 'pending' ? 1 : 3;
        list.push({
          kind: 'builtin',
          id: `builtin:${item.session_id}:${item.id}`,
          createdAtMs: parseTimeMs(item.created_at),
          priority,
          data: item,
        });
      }
    }

    list.sort((a, b) => {
      if (a.priority !== b.priority) return a.priority - b.priority;
      return b.createdAtMs - a.createdAtMs;
    });
    return list;
  }, [externalApprovals, sessionApprovals, sourceFilter, statusFilter, serverFilter, searchQuery, pinnedPlanIds]);

  const isStepChecked = (planId: string, step: ExternalApprovalStep): boolean => {
    if (step.blocked) return false;
    const planOverrides = stepSelectionMap[planId];
    if (planOverrides && step.id in planOverrides) {
      return Boolean(planOverrides[step.id]);
    }
    return step.selected !== false;
  };

  const toggleStepSelection = (planId: string, step: ExternalApprovalStep) => {
    if (step.blocked) return;
    setStepSelectionMap((prev) => {
      const cur = prev[planId] || {};
      const nextVal = !(step.id in cur ? cur[step.id] : step.selected !== false);
      return {
        ...prev,
        [planId]: {
          ...cur,
          [step.id]: nextVal,
        },
      };
    });
  };

  const setAllExecutableSteps = (ap: ExternalApproval, checked: boolean) => {
    const steps = getNormalizedSteps(ap);
    const nextPlanMap: Record<string, boolean> = {};
    for (const st of steps) {
      nextPlanMap[st.id] = st.blocked ? false : checked;
    }
    setStepSelectionMap((prev) => ({
      ...prev,
      [ap.id]: nextPlanMap,
    }));
  };

  const handleResolveExternalApproval = async (ap: ExternalApproval, approve: boolean) => {
    const steps = getNormalizedSteps(ap);
    const selectedStepIds = approve
      ? steps.filter((st) => !st.blocked && isStepChecked(ap.id, st)).map((st) => st.id)
      : undefined;

    if (approve && (!selectedStepIds || selectedStepIds.length === 0)) {
      onNotify('请至少勾选 1 个可执行步骤，或点击拒绝整份计划');
      return;
    }

    setResolvingId(ap.id);
    try {
      const res = await api.resolveExternalApproval(ap.id, approve, selectedStepIds);
      setExternalApprovals(res.approvals || []);
      syncCounts(res.pending_count || 0, res.running_count || 0, stats.pendingSess);
      if (approve) {
        setPinnedPlanIds((prev) => (prev.includes(ap.id) ? prev : [...prev, ap.id]));
        onNotify(
          `已批准变更计划「${ap.title || '外部 AI 计划'}」（共 ${selectedStepIds?.length || 0} 步），正在后台按序执行...`
        );
      } else {
        onNotify(`已拒绝外部 AI (${ap.client_name}) 的变更计划`);
      }
    } catch (err: any) {
      onNotify(err?.message || '处理外部 AI 变更计划失败');
    } finally {
      setResolvingId('');
    }
  };

  const handleCancelExternalApproval = async (ap: ExternalApproval) => {
    setCancellingId(ap.id);
    try {
      const res = await api.cancelExternalApproval(ap.id);
      setExternalApprovals(res.approvals || []);
      syncCounts(res.pending_count || 0, res.running_count || 0, stats.pendingSess);
      onNotify(`已请求中止变更计划「${ap.title || '外部 AI 计划'}」的后续执行`);
    } catch (err: any) {
      onNotify(err?.message || '中止变更计划失败');
    } finally {
      setCancellingId('');
    }
  };

  const hasExtraFilters = Boolean(sourceFilter !== 'all' || serverFilter || searchQuery.trim());

  const resetFilters = () => {
    setStatusFilter('active');
    setSourceFilter('all');
    setServerFilter('');
    setSearchQuery('');
  };

  const renderExternalCard = (ap: ExternalApproval) => {
    const steps = getNormalizedSteps(ap);
    const totalSteps = ap.total_steps ?? steps.length;
    const blockedCount = ap.blocked_steps ?? steps.filter((s) => s.blocked).length;
    const executableSteps = steps.filter((s) => !s.blocked);
    const isPending = ap.status === 'pending';
    const isRunning = ap.status === 'running';
    const statusMeta = PLAN_STATUS_META[ap.status] || PLAN_STATUS_META.pending;

    const checkedExecutableSteps = executableSteps.filter((st) => isStepChecked(ap.id, st));
    const selectedCount = checkedExecutableSteps.length;
    const doneStepsCount = steps.filter(
      (s) =>
        s.status === 'succeeded' ||
        s.status === 'failed' ||
        s.status === 'skipped' ||
        s.status === 'cancelled' ||
        s.status === 'blocked'
    ).length;
    const progressPct =
      totalSteps > 0 ? Math.min(100, Math.round((doneStepsCount / totalSteps) * 100)) : 0;

    return (
      <div
        key={`mcp-${ap.id}`}
        className={`ai-approval-card ${statusMeta.cardClass}`}
        data-external-approval-id={ap.id}
      >
        <div className="ai-approval-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', minWidth: 0 }}>
            {isRunning ? (
              <Loader2 size={16} className="spin-icon" style={{ color: 'var(--accent-teal)', flexShrink: 0 }} />
            ) : isPending ? (
              blockedCount > 0 ? (
                <AlertTriangle size={16} style={{ color: 'var(--danger-text)', flexShrink: 0 }} />
              ) : (
                <ShieldAlert size={16} style={{ color: 'var(--amber-text)', flexShrink: 0 }} />
              )
            ) : ap.status === 'completed' || ap.status === 'approved' ? (
              <CheckCircle2 size={16} style={{ color: 'var(--accent-teal)', flexShrink: 0 }} />
            ) : ap.status === 'partial_failed' || ap.status === 'failed' ? (
              <XCircle size={16} style={{ color: 'var(--danger-text)', flexShrink: 0 }} />
            ) : (
              <XCircle size={16} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />
            )}
            <strong style={{ fontSize: 14 }}>
              {ap.title || (totalSteps > 1 ? `${totalSteps} 步变更执行计划` : '外部 AI 变更提案')}
            </strong>
            <span className={`tag-chip ${statusMeta.chipClass}`}>{statusMeta.label}</span>
            <span className="tag-chip teal">
              <PlugZap size={10.5} style={{ marginRight: 3 }} />
              MCP · {ap.client_name || 'External MCP'}
            </span>
            <span className="tag-chip mono" style={{ fontSize: 11 }}>
              共 {totalSteps} 步
            </span>
            {blockedCount > 0 && (
              <span className="tag-chip danger" style={{ fontSize: 11 }}>
                <Ban size={11} style={{ marginRight: 3 }} />
                含 {blockedCount} 步安全拦截锁定
              </span>
            )}
            <span className="tag-chip mono" style={{ fontSize: 11 }}>
              令牌: {ap.token_name}
            </span>
            {ap.patrol_record_id && (
              <button
                type="button"
                className="tag-chip amber mono ap-clickable-chip"
                style={{ fontSize: 11 }}
                onClick={onOpenPatrol}
                title="点击前往「AI 智能运维 → 后台巡检与告警」查看关联巡检记录"
              >
                <Radar size={10.5} style={{ marginRight: 3 }} />
                关联巡检: {ap.patrol_record_id.slice(0, 8)}
              </button>
            )}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <span className="mono" style={{ fontSize: 11.5, color: 'var(--text-secondary)' }}>
              目标: {(ap.server_names || []).join(', ') || '未指定主机'}
            </span>
            <span className="mono" style={{ fontSize: 11, color: 'var(--text-muted)' }}>
              {new Date(ap.created_at).toLocaleString('zh-CN')}
            </span>
          </div>
        </div>

        <div className="ai-approval-body">
          <div style={{ fontSize: 13, color: 'var(--text-primary)', lineHeight: 1.55 }}>
            <strong>整体变更说明：</strong>
            {ap.reason}
          </div>

          {/* Execution progress bar for running or finished plans */}
          {(isRunning || (!isPending && ap.status !== 'rejected')) && (
            <div className="mcp-plan-progress-box">
              <div className="mcp-plan-progress-meta">
                <span>
                  {isRunning
                    ? ap.current_step_index
                      ? `正在按序执行第 ${ap.current_step_index} / ${totalSteps} 步...`
                      : '正在调度按序执行...'
                    : `执行汇总：成功 ${ap.completed_steps || 0} 步 · 失败 ${ap.failed_steps || 0} 步 · 跳过/中止 ${ap.skipped_steps || 0} 步${
                        blockedCount > 0 ? ` · 拦截锁定 ${blockedCount} 步` : ''
                      }`}
                </span>
                <span className="mono" style={{ color: 'var(--text-muted)' }}>
                  {ap.duration_ms ? `总耗时 ${ap.duration_ms}ms` : `${progressPct}%`}
                </span>
              </div>
              <div className="mcp-plan-progress-track">
                <div
                  className={`mcp-plan-progress-fill ${
                    ap.status === 'failed' || ap.status === 'partial_failed'
                      ? 'is-danger'
                      : ap.status === 'cancelled'
                      ? 'is-amber'
                      : ''
                  }`}
                  style={{ width: `${isRunning ? Math.max(8, progressPct) : 100}%` }}
                />
              </div>
            </div>
          )}

          {/* Pending step selection toolbar */}
          {isPending && (
            <div className="mcp-plan-toolbar">
              <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                按 AI 给出的顺序依次执行（默认遇错即停）· 已勾选{' '}
                <strong>
                  {selectedCount} / {executableSteps.length}
                </strong>{' '}
                个可执行步骤
              </span>
              {executableSteps.length > 1 && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <button
                    type="button"
                    className="btn btn-ghost btn-sm"
                    onClick={() => setAllExecutableSteps(ap, true)}
                  >
                    全选可执行
                  </button>
                  <button
                    type="button"
                    className="btn btn-ghost btn-sm"
                    onClick={() => setAllExecutableSteps(ap, false)}
                  >
                    清空勾选
                  </button>
                </div>
              )}
            </div>
          )}

          {/* Ordered Steps List */}
          <div className="mcp-plan-steps">
            {steps.map((st, idx) => {
              const checked = isStepChecked(ap.id, st);
              const stepMeta = STEP_STATUS_META[st.status] || STEP_STATUS_META.pending;
              const stepCls = [
                'mcp-plan-step',
                st.blocked ? 'is-blocked' : '',
                st.status === 'running' ? 'is-running' : '',
                st.status === 'succeeded' ? 'is-succeeded' : '',
                st.status === 'failed' ? 'is-failed' : '',
                st.status === 'skipped' || st.status === 'cancelled' || st.status === 'rejected'
                  ? 'is-muted'
                  : '',
                isPending && !st.blocked && !checked ? 'is-unchecked' : '',
              ]
                .filter(Boolean)
                .join(' ');

              return (
                <div key={st.id} className={stepCls} data-step-id={st.id} data-step-status={st.status}>
                  <div className="mcp-plan-step-head">
                    <div className="mcp-plan-step-left">
                      {isPending && (
                        <label
                          className={`mcp-step-checkbox-wrap ${st.blocked ? 'is-disabled' : ''}`}
                          title={
                            st.blocked
                              ? '该步骤已触发安全熔断锁定，禁止勾选执行'
                              : checked
                              ? '取消勾选以跳过本步'
                              : '勾选以纳入本次按序执行'
                          }
                        >
                          <input
                            type="checkbox"
                            checked={checked}
                            disabled={Boolean(st.blocked)}
                            onChange={() => toggleStepSelection(ap.id, st)}
                          />
                        </label>
                      )}
                      <span className={`mcp-step-index ${st.blocked ? 'is-blocked' : ''}`}>
                        #{st.index || idx + 1}
                      </span>
                      <strong style={{ fontSize: 13 }}>
                        {st.title ||
                          (st.tool_name === 'sftp_write_file' ? `修改 ${st.file_path}` : '执行远程命令')}
                      </strong>
                      <span className="tag-chip" style={{ fontSize: 11 }}>
                        {st.tool_name === 'sftp_write_file' ? 'SFTP 配置' : 'SSH 命令'}
                      </span>
                      {st.continue_on_error && (
                        <span
                          className="tag-chip amber"
                          style={{ fontSize: 10.5 }}
                          title="该步骤失败时仍会继续执行后续步骤"
                        >
                          <SkipForward size={10} style={{ marginRight: 3 }} />
                          遇错继续
                        </span>
                      )}
                      {st.timeout_sec && st.tool_name === 'exec_ssh_command' && st.timeout_sec !== 45 ? (
                        <span className="tag-chip mono" style={{ fontSize: 10.5 }}>
                          <Clock size={10} style={{ marginRight: 3 }} />
                          {st.timeout_sec}s
                        </span>
                      ) : null}
                    </div>

                    <div className="mcp-plan-step-right">
                      <span className="mono" style={{ fontSize: 11.5, color: 'var(--text-secondary)' }}>
                        {(st.server_names || []).join(', ')}
                      </span>
                      <span className={`tag-chip ${stepMeta.chipClass}`} style={{ fontSize: 11 }}>
                        {st.status === 'running' && (
                          <Loader2 size={10} className="spin-icon" style={{ marginRight: 4 }} />
                        )}
                        {st.blocked && <Lock size={10} style={{ marginRight: 3 }} />}
                        {stepMeta.label}
                        {st.duration_ms ? ` · ${st.duration_ms}ms` : ''}
                      </span>
                    </div>
                  </div>

                  {st.reason && st.reason !== ap.reason && (
                    <div style={{ fontSize: 12.5, color: 'var(--text-secondary)' }}>{st.reason}</div>
                  )}

                  {st.blocked && (
                    <div className="mcp-step-blocked-banner">
                      <Ban size={14} style={{ flexShrink: 0, marginTop: 1 }} />
                      <div>
                        <strong>安全熔断锁定（强制不可勾选与执行）：</strong>
                        <span>{st.blocked_reason || '命中安全黑名单，已被系统硬拦截'}</span>
                      </div>
                    </div>
                  )}

                  {st.command && (
                    <div className={`copilot-cmd-box ${st.blocked ? 'is-blocked-cmd' : ''}`}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 7, minWidth: 0, flex: 1 }}>
                        <Terminal
                          size={13}
                          style={{ color: st.blocked ? '#f87171' : '#2dd4bf', flexShrink: 0 }}
                        />
                        <code style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                          {st.command}
                        </code>
                      </div>
                    </div>
                  )}

                  {st.file_path && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                      <div
                        className="mono"
                        style={{
                          fontSize: 12,
                          color: st.blocked ? 'var(--danger-text)' : 'var(--text-secondary)',
                          display: 'flex',
                          alignItems: 'center',
                          gap: 6,
                        }}
                      >
                        <FileCode2 size={13} /> 目标远程文件：{st.file_path}
                      </div>
                      {!st.blocked && st.diff_preview && (
                        <UnifiedDiffViewer diff={st.diff_preview} />
                      )}
                    </div>
                  )}

                  {(st.execution_error || st.execution_out) && (
                    <div className="mcp-step-output-box">
                      {st.execution_error && (
                        <div
                          style={{
                            color:
                              st.status === 'skipped' || st.status === 'cancelled'
                                ? 'var(--text-muted)'
                                : 'var(--danger-text)',
                            fontSize: 12,
                            marginBottom: st.execution_out ? 6 : 0,
                          }}
                        >
                          {st.status === 'skipped' || st.status === 'cancelled'
                            ? `说明：${st.execution_error}`
                            : `执行异常：${st.execution_error}`}
                        </div>
                      )}
                      {st.execution_out && (
                        <pre className="mcp-code-block compact">{st.execution_out}</pre>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {/* Plan Footer Actions */}
          {isPending ? (
            <div className="ai-approval-actions">
              <button
                type="button"
                className="btn btn-teal btn-sm"
                disabled={
                  resolvingId === ap.id || executableSteps.length === 0 || selectedCount === 0
                }
                onClick={() => void handleResolveExternalApproval(ap, true)}
              >
                <ShieldCheck size={13} />
                {resolvingId === ap.id
                  ? '正在启动按序执行...'
                  : executableSteps.length === 0
                  ? '全部步骤已安全拦截，无法批准'
                  : selectedCount === executableSteps.length && blockedCount === 0
                  ? `一键批准全部 ${selectedCount} 步并按序执行`
                  : `批准已选 ${selectedCount} 步并按序执行`}
              </button>
              <button
                type="button"
                className="btn btn-sm"
                style={{ color: 'var(--danger-text)' }}
                disabled={resolvingId === ap.id}
                onClick={() => void handleResolveExternalApproval(ap, false)}
              >
                <XCircle size={13} /> 拒绝整份计划
              </button>
              {blockedCount > 0 && executableSteps.length > 0 && (
                <span style={{ fontSize: 12, color: 'var(--danger-text)' }}>
                  注：{blockedCount} 个红框锁定步骤将强制跳过，不会执行
                </span>
              )}
            </div>
          ) : isRunning ? (
            <div className="ai-approval-actions" style={{ justifyContent: 'space-between' }}>
              <span
                style={{
                  fontSize: 12.5,
                  color: 'var(--accent-teal)',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 6,
                }}
              >
                <Loader2 size={13} className="spin-icon" />
                后台按序执行中，页面每 1.5 秒自动同步各步状态与实时回显...
              </span>
              <button
                type="button"
                className="btn btn-sm"
                style={{ color: 'var(--danger-text)', borderColor: 'var(--danger-border)' }}
                disabled={cancellingId === ap.id}
                onClick={() => void handleCancelExternalApproval(ap)}
              >
                <StopCircle size={13} />
                {cancellingId === ap.id ? '正在中止...' : '中止剩余执行'}
              </button>
            </div>
          ) : (
            <div className="mcp-plan-terminal-footer">
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                <strong>{statusMeta.label}</strong>
                {ap.duration_ms ? (
                  <span className="mono" style={{ color: 'var(--text-muted)' }}>
                    总耗时 {ap.duration_ms}ms
                  </span>
                ) : null}
                {ap.resolved_at && (
                  <span className="mono" style={{ color: 'var(--text-muted)' }}>
                    {new Date(ap.resolved_at).toLocaleString('zh-CN')}
                  </span>
                )}
                <span style={{ color: 'var(--text-muted)' }}>
                  · 外部 AI 可通过 get_approval_status(&quot;{ap.id}&quot;) 或 wait_for_approval 读取每步结果
                </span>
              </div>
              {ap.execution_error && (
                <div style={{ color: 'var(--danger-text)', marginTop: 4 }}>{ap.execution_error}</div>
              )}
            </div>
          )}
        </div>
      </div>
    );
  };

  const renderBuiltinCard = (item: SessionApprovalItem) => {
    const isPending = item.status === 'pending';
    const isTerminal = item.session_scope === 'terminal';
    const statusMeta =
      SESSION_APPROVAL_STATUS_META[item.status] || SESSION_APPROVAL_STATUS_META.pending;

    const targetServerIds =
      item.server_ids && item.server_ids.length > 0
        ? item.server_ids
        : item.session_server_ids || [];
    const targetServerId = targetServerIds[0] || '';
    const resolvedServerNames =
      item.server_names && item.server_names.length > 0
        ? item.server_names
        : targetServerIds.map((id) => serverNameById[id] || id);

    const handleJump = () => {
      if (isTerminal) {
        if (!targetServerId) {
          onNotify('该终端 Copilot 会话未关联有效目标主机，请在终端工作台中打开对应主机查看');
          return;
        }
        onJumpTerminalCopilot(targetServerId, item.session_id);
      } else {
        onJumpCenterSession(item.session_id);
      }
    };

    return (
      <div
        key={`builtin-${item.session_id}-${item.id}`}
        className={`ai-approval-card ${statusMeta.cardClass}`}
        data-session-approval-id={item.id}
      >
        <div className="ai-approval-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', minWidth: 0 }}>
            {isPending ? (
              <ShieldAlert size={16} style={{ color: 'var(--amber-text)', flexShrink: 0 }} />
            ) : item.status === 'approved' ? (
              <CheckCircle2 size={16} style={{ color: 'var(--accent-teal)', flexShrink: 0 }} />
            ) : (
              <XCircle size={16} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />
            )}
            <strong style={{ fontSize: 14 }}>{getSessionApprovalTitle(item)}</strong>
            <span className={`tag-chip ${statusMeta.chipClass}`}>{statusMeta.label}</span>
            <span className="tag-chip">
              {isTerminal ? (
                <>
                  <TerminalSquare size={10.5} style={{ marginRight: 3 }} />
                  内置 AI · 终端 Copilot
                </>
              ) : (
                <>
                  <Bot size={10.5} style={{ marginRight: 3 }} />
                  内置 AI · 智能排障
                </>
              )}
            </span>
            {item.risk_level && (
              <span className={`tag-chip ${item.risk_level === 'high' ? 'danger' : 'amber'}`} style={{ fontSize: 11 }}>
                {item.risk_level === 'high' ? '高风险变更' : '中风险变更'}
              </span>
            )}
            <span className="tag-chip" style={{ fontSize: 11 }}>
              <MessageSquare size={10.5} style={{ marginRight: 3 }} />
              {item.session_title || '未命名会话'}
            </span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <span className="mono" style={{ fontSize: 11.5, color: 'var(--text-secondary)' }}>
              目标: {resolvedServerNames.join(', ') || '目标服务器'}
            </span>
            <span className="mono" style={{ fontSize: 11, color: 'var(--text-muted)' }}>
              {new Date(item.created_at).toLocaleString('zh-CN')}
            </span>
          </div>
        </div>

        <div className="ai-approval-body">
          <div style={{ fontSize: 13, color: 'var(--text-primary)', lineHeight: 1.55 }}>
            <strong>变更说明：</strong>
            {item.reason}
          </div>

          {item.command && (
            <div className="copilot-cmd-box">
              <div style={{ display: 'flex', alignItems: 'center', gap: 7, minWidth: 0, flex: 1 }}>
                <Terminal size={13} style={{ color: '#2dd4bf', flexShrink: 0 }} />
                <code style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>{item.command}</code>
              </div>
            </div>
          )}

          {item.file_path && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              <div
                className="mono"
                style={{
                  fontSize: 12,
                  color: 'var(--text-secondary)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6,
                }}
              >
                <FileCode2 size={13} /> 目标远程文件：{item.file_path}
              </div>
              {item.diff_preview && <UnifiedDiffViewer diff={item.diff_preview} />}
            </div>
          )}

          {item.execution_out && (
            <div className="mcp-step-output-box">
              <pre className="mcp-code-block compact">{item.execution_out}</pre>
            </div>
          )}

          <div className={isPending ? 'ai-approval-actions ap-builtin-footer' : 'mcp-plan-terminal-footer ap-builtin-footer'}>
            <div className="ap-builtin-note">
              {isPending ? (
                <>
                  <span>
                    该审批关联内置 AI 流式对话上下文，跳转至原会话批准或拒绝后 AI 将自动续写诊断结论
                  </span>
                </>
              ) : (
                <>
                  <strong>{statusMeta.label}</strong>
                  {item.resolved_at && (
                    <span className="mono" style={{ color: 'var(--text-muted)' }}>
                      · {new Date(item.resolved_at).toLocaleString('zh-CN')}
                    </span>
                  )}
                </>
              )}
            </div>
            <button
              type="button"
              className={`btn btn-sm ${isPending ? 'btn-teal' : ''}`}
              onClick={handleJump}
            >
              {isTerminal ? (
                <>
                  <TerminalSquare size={13} />
                  {isPending ? '打开终端 Copilot 审批' : '前往终端 Copilot 回看'}
                </>
              ) : (
                <>
                  <Bot size={13} />
                  {isPending ? '前往排障会话审批' : '回看原排障会话'}
                </>
              )}
              <ArrowUpRight size={13} />
            </button>
          </div>
        </div>
      </div>
    );
  };

  return (
    <div className="workspace-surface" id="approval-center-view">
      {/* Page Header */}
      <div className="page-header" style={{ flexWrap: 'wrap', rowGap: 10 }}>
        <div className="page-header-title">
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <h2>执行审批中心</h2>
            {stats.runningExt > 0 && (
              <span className="tag-chip teal">
                <Loader2 size={11} className="spin-icon" style={{ marginRight: 4 }} />
                {stats.runningExt} 份计划执行中
              </span>
            )}
            {stats.pendingTotal > 0 ? (
              <span className="tag-chip amber">{stats.pendingTotal} 项待审阅批准</span>
            ) : stats.runningExt === 0 ? (
              <span className="tag-chip teal">当前无待审批变更</span>
            ) : null}
          </div>
          <p>
            集中审阅外部 AI (MCP) 有序变更计划与内置 AI 会话变更提案，支持按步勾选、Diff 核验、实时执行监控与只读审计留痕
          </p>
        </div>

        <div className="page-header-actions">
          <button
            type="button"
            id="approval-open-mcp-config-btn"
            className="btn btn-sm"
            onClick={onOpenMCPConfig}
          >
            <PlugZap size={14} /> MCP 接入配置
          </button>
          <button
            type="button"
            id="approval-refresh-btn"
            className="btn btn-sm"
            disabled={refreshing}
            onClick={() => void loadApprovals(false)}
          >
            <RefreshCw size={14} className={refreshing ? 'spin-icon' : ''} /> 刷新
          </button>
        </div>
      </div>

      <div className="page-body">
        {/* Clickable 4-Card KPI Overview */}
        <div className="mon-kpi-grid al-kpi-grid">
          <div
            className={`mon-kpi-card clickable ${
              statusFilter === 'active' && sourceFilter === 'all' ? 'al-kpi-selected' : ''
            }`}
            onClick={() => {
              setStatusFilter('active');
              setSourceFilter('all');
            }}
          >
            <div className="mon-kpi-top">
              <span>待审阅批准</span>
              <ShieldAlert
                size={15}
                style={{ color: stats.pendingTotal > 0 ? 'var(--amber-text)' : 'var(--text-muted)' }}
              />
            </div>
            <div
              className="mon-kpi-value tabular"
              style={{ color: stats.pendingTotal > 0 ? 'var(--amber-text)' : undefined }}
            >
              {stats.pendingTotal}
            </div>
            <div className="mon-kpi-foot">
              MCP 变更计划 {stats.pendingExt} · 内置 AI 会话 {stats.pendingSess}
            </div>
          </div>

          <div
            className={`mon-kpi-card clickable ${
              statusFilter === 'active' && sourceFilter === 'mcp' ? 'al-kpi-selected' : ''
            }`}
            onClick={() => {
              setStatusFilter('active');
              setSourceFilter('mcp');
            }}
          >
            <div className="mon-kpi-top">
              <span>按序执行中</span>
              {stats.runningExt > 0 ? (
                <Loader2 size={15} className="spin-icon" style={{ color: 'var(--accent-teal)' }} />
              ) : (
                <ListOrdered size={15} style={{ color: 'var(--accent-teal)' }} />
              )}
            </div>
            <div
              className="mon-kpi-value tabular"
              style={{ color: stats.runningExt > 0 ? 'var(--accent-teal)' : undefined }}
            >
              {stats.runningExt}
            </div>
            <div className="mon-kpi-foot">MCP 计划执行时自动 1.5 秒同步进度与输出</div>
          </div>

          <div
            className={`mon-kpi-card clickable ${
              statusFilter === 'completed' ? 'al-kpi-selected' : ''
            }`}
            onClick={() =>
              setStatusFilter((prev) => (prev === 'completed' ? 'active' : 'completed'))
            }
          >
            <div className="mon-kpi-top">
              <span>已完成执行</span>
              <CheckCircle2 size={15} style={{ color: 'var(--status-online)' }} />
            </div>
            <div className="mon-kpi-value tabular">{stats.completedTotal}</div>
            <div className="mon-kpi-foot">
              MCP 完成 {stats.completedExt} · 内置 AI 已批准 {stats.approvedSess}
            </div>
          </div>

          <div
            className={`mon-kpi-card clickable ${statusFilter === 'issue' ? 'al-kpi-selected' : ''}`}
            onClick={() => setStatusFilter((prev) => (prev === 'issue' ? 'active' : 'issue'))}
          >
            <div className="mon-kpi-top">
              <span>异常 / 中止 / 已拒绝</span>
              <XCircle
                size={15}
                style={{
                  color: stats.failedOrCancelledExt > 0 ? 'var(--danger-text)' : 'var(--text-muted)',
                }}
              />
            </div>
            <div
              className="mon-kpi-value tabular"
              style={{
                color: stats.failedOrCancelledExt > 0 ? 'var(--danger-text)' : undefined,
              }}
            >
              {stats.issueTotal}
            </div>
            <div className="mon-kpi-foot">
              失败/中止 {stats.failedOrCancelledExt} · 已拒绝 {stats.rejectedTotal}
            </div>
          </div>
        </div>

        {/* Multi-Dimensional Filter Toolbar */}
        <div className="al-toolbar">
          <div className="al-toolbar-row">
            <div className="group-pills" role="tablist" aria-label="审批状态筛选">
              {(
                [
                  ['active', `待审批 / 执行中 (${stats.activeTotal})`],
                  ['completed', `已完成 (${stats.completedTotal})`],
                  ['issue', `异常 / 已拒绝 (${stats.issueTotal})`],
                  ['all', `全部历史 (${stats.allTotal})`],
                ] as [StatusFilter, string][]
              ).map(([key, label]) => (
                <button
                  key={key}
                  type="button"
                  role="tab"
                  aria-selected={statusFilter === key}
                  className={`group-pill ${statusFilter === key ? 'active' : ''}`}
                  onClick={() => setStatusFilter(key)}
                >
                  {label}
                </button>
              ))}
            </div>

            {hasExtraFilters && (
              <button type="button" className="btn btn-ghost btn-sm" onClick={resetFilters}>
                <RotateCcw size={13} /> 重置筛选
              </button>
            )}
          </div>

          <div className="al-toolbar-row secondary">
            <div className="group-pills" aria-label="审批来源筛选">
              {(
                [
                  ['all', '全部来源'],
                  ['mcp', `MCP 外部 AI (${externalApprovals.length})`],
                  ['builtin', `内置 AI 对话 (${sessionApprovals.length})`],
                ] as [SourceFilter, string][]
              ).map(([key, label]) => (
                <button
                  key={key}
                  type="button"
                  className={`group-pill ${sourceFilter === key ? 'active' : ''}`}
                  onClick={() => setSourceFilter(key)}
                >
                  {label}
                </button>
              ))}
            </div>

            <div className="al-filter-controls">
              <select
                id="approval-server-filter-select"
                className="select al-filter-select server"
                value={serverFilter}
                onChange={(e) => setServerFilter(e.target.value)}
                aria-label="按服务器筛选"
              >
                <option value="">全部服务器节点</option>
                {serverOptions.map((opt) => (
                  <option key={opt.id} value={opt.id}>
                    {opt.label}
                  </option>
                ))}
              </select>

              <div className="input-with-icon al-search-box">
                <span className="input-icon-left">
                  <Search size={13.5} />
                </span>
                <input
                  id="approval-search-input"
                  className="input al-search-input"
                  placeholder="搜索标题、变更说明、命令、路径、客户端或会话..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                />
                {searchQuery && (
                  <button
                    type="button"
                    className="al-search-clear"
                    onClick={() => setSearchQuery('')}
                    aria-label="清空搜索"
                  >
                    <X size={13} />
                  </button>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Approval List */}
        {loading ? (
          <div className="empty-state">
            <div style={{ color: 'var(--text-muted)' }}>正在加载执行审批记录...</div>
          </div>
        ) : unifiedItems.length === 0 ? (
          <div className="empty-state" style={{ padding: '48px 20px' }}>
            <div className="empty-state-icon">
              <ClipboardCheck size={24} style={{ color: 'var(--accent-teal)' }} />
            </div>
            <h3>
              {hasExtraFilters
                ? '当前筛选条件下没有匹配的审批记录'
                : statusFilter === 'active'
                ? '当前没有等待审批或执行中的变更计划'
                : '暂无对应状态的执行审批历史'}
            </h3>
            <p>
              {hasExtraFilters
                ? '请尝试放宽来源、目标主机或关键词过滤条件。'
                : statusFilter === 'active'
                ? '当 Claude Code / Codex / Antigravity / Cursor 通过 MCP 调用 propose_change_plan 提交有序变更计划，或内置 AI 对话产生需人工授权的操作时，都会自动汇聚到这里等待您审阅批准。'
                : '所有已审批、已完成或已拒绝的变更记录均会自动保留在此供只读审计回溯。'}
            </p>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', justifyContent: 'center', marginTop: 14 }}>
              {hasExtraFilters ? (
                <button type="button" className="btn btn-sm btn-primary" onClick={resetFilters}>
                  <RotateCcw size={13} /> 重置筛选条件
                </button>
              ) : (
                <>
                  {statusFilter === 'active' && stats.allTotal > 0 && (
                    <button
                      type="button"
                      className="btn btn-sm"
                      onClick={() => setStatusFilter('all')}
                    >
                      查看全部历史 ({stats.allTotal})
                    </button>
                  )}
                  <button type="button" className="btn btn-sm btn-teal" onClick={onOpenMCPConfig}>
                    <PlugZap size={13} /> 前往 MCP 接入配置
                  </button>
                </>
              )}
            </div>
          </div>
        ) : (
          <div className="ap-center-list" id="approval-center-list">
            {unifiedItems.map((entry) =>
              entry.kind === 'mcp' ? renderExternalCard(entry.data) : renderBuiltinCard(entry.data)
            )}
          </div>
        )}
      </div>
    </div>
  );
};

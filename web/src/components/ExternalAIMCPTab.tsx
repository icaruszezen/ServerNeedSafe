import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  PlugZap,
  KeyRound,
  Copy,
  Check,
  Download,
  Trash2,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  XCircle,
  Terminal,
  FileCode2,
  RefreshCw,
  Plus,
  Server as ServerIcon,
  Radar,
  Lock,
  Sparkles,
  BookOpen,
  ChevronDown,
  ChevronRight,
  ExternalLink,
  X,
  Loader2,
  StopCircle,
  Ban,
  AlertTriangle,
  ListOrdered,
  Clock,
  SkipForward,
} from 'lucide-react';
import { api } from '../api';
import { copyTextToClipboard } from '../utils/clipboard';
import type {
  AIOverviewResponse,
  ExternalApproval,
  ExternalApprovalStatus,
  ExternalApprovalStep,
  ExternalApprovalStepStatus,
  MCPConfigView,
  MCPRuntimeStatus,
  MCPTokenScope,
  MCPTokenView,
  ServerView,
} from '../types';
import { UnifiedDiffViewer } from './AIMessageWidgets';

type ClientPresetKey = 'claude_code' | 'codex' | 'antigravity' | 'cursor';

const CLIENT_PRESETS: {
  key: ClientPresetKey;
  label: string;
  configPath: string;
  tip: string;
}[] = [
  {
    key: 'claude_code',
    label: 'Claude Code',
    configPath: 'CLI 命令 或 项目根目录 .mcp.json',
    tip: '支持一条 CLI 命令直接接入；连上后可直接输入 /mcp 查看 serverneedsafe 工具与内置巡检 Prompts。',
  },
  {
    key: 'codex',
    label: 'Codex',
    configPath: '~/.codex/config.toml',
    tip: 'Codex CLI 原生支持 Streamable HTTP MCP 服务端，也适合结合系统 cron / codex exec 实现低成本定时接管。',
  },
  {
    key: 'antigravity',
    label: 'Antigravity',
    configPath: 'MCP Servers 配置 (mcp_config.json)',
    tip: '在 Antigravity 的 MCP Servers 面板中粘贴以下配置即可接入，可搭配下方 SKILL.md 作为常驻巡检技能。',
  },
  {
    key: 'cursor',
    label: 'Cursor',
    configPath: '.cursor/mcp.json 或 ~/.cursor/mcp.json',
    tip: '保存后在 Cursor Settings → Tools & MCP 中确认绿色在线状态，在 Agent 模式直接让它接管巡检。',
  },
];

const CLIENT_HINT_LABELS: Record<string, string> = {
  claude_code: 'Claude Code',
  codex: 'Codex',
  antigravity: 'Antigravity',
  cursor: 'Cursor',
  custom: '通用 MCP',
};

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
      title: ap.title || (toolName === 'sftp_write_file' ? `修改配置 ${ap.file_path || ''}` : ap.command || '远程命令'),
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

interface ExternalAIMCPTabProps {
  overview: AIOverviewResponse | null;
  servers: ServerView[];
  onReloadOverview: () => Promise<void>;
  onJumpPatrol: () => void;
  onNotify: (msg: string) => void;
}

export const ExternalAIMCPTab: React.FC<ExternalAIMCPTabProps> = ({
  overview,
  servers,
  onReloadOverview,
  onJumpPatrol,
  onNotify,
}) => {
  const [mcpConfig, setMcpConfig] = useState<MCPConfigView | null>(overview?.mcp_config || null);
  const [mcpRuntime, setMcpRuntime] = useState<MCPRuntimeStatus | null>(
    overview?.mcp_runtime || null
  );
  const [approvals, setApprovals] = useState<ExternalApproval[]>(
    overview?.external_approvals || []
  );
  const [skillMarkdown, setSkillMarkdown] = useState<string>(overview?.skill_markdown || '');
  const [loading, setLoading] = useState(!overview?.mcp_config);

  // Gateway settings draft
  const [publicEndpointHint, setPublicEndpointHint] = useState(
    overview?.mcp_config?.public_endpoint_hint || ''
  );
  const [desktopPortStr, setDesktopPortStr] = useState(
    String(overview?.mcp_config?.desktop_loopback_port || 18900)
  );
  const [savingConfig, setSavingConfig] = useState(false);

  // New Token form
  const [tokenName, setTokenName] = useState('');
  const [tokenClientHint, setTokenClientHint] = useState<string>('claude_code');
  const [tokenScope, setTokenScope] = useState<MCPTokenScope>('ops_propose');
  const [tokenAllowedServers, setTokenAllowedServers] = useState<string[]>([]);
  const [creatingToken, setCreatingToken] = useState(false);
  const [justCreatedToken, setJustCreatedToken] = useState<{
    id: string;
    name: string;
    rawToken: string;
    clientHint: string;
  } | null>(null);

  // Approval Queue UI state
  const [approvalFilter, setApprovalFilter] = useState<'active' | 'all'>('active');
  const [resolvingId, setResolvingId] = useState<string>('');
  const [cancellingId, setCancellingId] = useState<string>('');
  const [stepSelectionMap, setStepSelectionMap] = useState<Record<string, Record<string, boolean>>>(
    {}
  );
  // Keep plans resolved/approved in this session visible under the "active" filter so live results don't vanish abruptly
  const [pinnedPlanIds, setPinnedPlanIds] = useState<string[]>([]);
  const lastPendingCountRef = useRef<number>(overview?.pending_external_approvals || 0);

  // Client Config Generator & Skill Preview state
  const [selectedClient, setSelectedClient] = useState<ClientPresetKey>('claude_code');
  const [copiedKey, setCopiedKey] = useState<string>('');
  const [showSkillPreview, setShowSkillPreview] = useState(false);

  const serverNameMap = useMemo(() => {
    const m: Record<string, string> = {};
    for (const srv of servers) m[srv.id] = srv.name;
    return m;
  }, [servers]);

  const refreshMCPOverview = async () => {
    try {
      const res = await api.getMCPOverview();
      setMcpConfig(res.mcp_config);
      setMcpRuntime(res.mcp_runtime);
      setApprovals(res.external_approvals || []);
      setSkillMarkdown(res.skill_markdown || '');
      setPublicEndpointHint(res.mcp_config.public_endpoint_hint || '');
      setDesktopPortStr(String(res.mcp_config.desktop_loopback_port || 18900));
    } catch (err: any) {
      onNotify(err?.message || '加载外部 AI MCP 配置失败');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (overview?.mcp_config) {
      setMcpConfig(overview.mcp_config);
      setMcpRuntime(overview.mcp_runtime || null);
      setApprovals(overview.external_approvals || []);
      setSkillMarkdown(overview.skill_markdown || '');
      setPublicEndpointHint(overview.mcp_config.public_endpoint_hint || '');
      setDesktopPortStr(String(overview.mcp_config.desktop_loopback_port || 18900));
      setLoading(false);
    } else {
      void refreshMCPOverview();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [overview]);

  const isDesktopMode = mcpRuntime?.deploy_mode === 'desktop';
  const effectiveURL = useMemo(() => {
    if (mcpRuntime?.effective_endpoint_url) return mcpRuntime.effective_endpoint_url;
    if (typeof window !== 'undefined' && window.location?.origin) {
      return `${window.location.origin}/api/mcp`;
    }
    return 'http://127.0.0.1:18899/api/mcp';
  }, [mcpRuntime]);

  const activeTokenPlaceholder = justCreatedToken?.rawToken || 'sns_mcp_请替换为刚签发的令牌';

  const generatedSnippets = useMemo(() => {
    const url = effectiveURL;
    const tok = activeTokenPlaceholder;

    const claudeCLI = `claude mcp add --transport http serverneedsafe "${url}" \\\n  --header "Authorization: Bearer ${tok}"`;
    const claudeJSON = JSON.stringify(
      {
        mcpServers: {
          serverneedsafe: {
            type: 'http',
            url,
            headers: {
              Authorization: `Bearer ${tok}`,
            },
          },
        },
      },
      null,
      2
    );

    const codexToml = `[mcp_servers.serverneedsafe]\nurl = "${url}"\nhttp_headers = { "Authorization" = "Bearer ${tok}" }`;

    const antigravityJSON = JSON.stringify(
      {
        mcpServers: {
          serverneedsafe: {
            serverUrl: url,
            headers: {
              Authorization: `Bearer ${tok}`,
            },
          },
        },
      },
      null,
      2
    );

    const cursorJSON = JSON.stringify(
      {
        mcpServers: {
          serverneedsafe: {
            url,
            headers: {
              Authorization: `Bearer ${tok}`,
            },
          },
        },
      },
      null,
      2
    );

    return {
      claude_code: { primary: claudeCLI, secondary: claudeJSON },
      codex: { primary: codexToml, secondary: '' },
      antigravity: { primary: antigravityJSON, secondary: '' },
      cursor: { primary: cursorJSON, secondary: '' },
    };
  }, [effectiveURL, activeTokenPlaceholder]);

  const copyText = async (key: string, text: string, label: string) => {
    try {
      await copyTextToClipboard(text);
      setCopiedKey(key);
      onNotify(`已复制${label}`);
      setTimeout(() => setCopiedKey((cur) => (cur === key ? '' : cur)), 1800);
    } catch {
      onNotify('浏览器剪贴板写入失败，请手动选中复制');
    }
  };

  const downloadSkillFile = () => {
    const blob = new Blob([skillMarkdown], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'SKILL.md';
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    onNotify('已下载标准巡检 SKILL.md 技能文件');
  };

  const parseDesktopPort = (): number | null => {
    const n = Number(desktopPortStr.trim());
    if (!Number.isInteger(n) || n < 1024 || n > 65535) {
      onNotify('本地 MCP 回环端口必须在 1024 - 65535 之间');
      return null;
    }
    return n;
  };

  const handleToggleGateway = async (nextEnabled: boolean) => {
    let portVal = 18900;
    if (isDesktopMode && nextEnabled) {
      const parsed = parseDesktopPort();
      if (parsed === null) return;
      portVal = parsed;
    }
    setSavingConfig(true);
    try {
      const payload = isDesktopMode
        ? { desktop_loopback_enabled: nextEnabled, ...(nextEnabled ? { desktop_loopback_port: portVal } : {}) }
        : { enabled: nextEnabled };
      const res = await api.updateMCPConfig(payload);
      setMcpConfig(res.mcp_config);
      setMcpRuntime(res.mcp_runtime);
      setSkillMarkdown(res.skill_markdown);
      onNotify(
        isDesktopMode
          ? nextEnabled
            ? `已开启桌面版独立 MCP 回环接入 (${res.mcp_runtime.effective_endpoint_url})`
            : '已关闭桌面版独立 MCP 回环端口'
          : nextEnabled
          ? '已开启服务端外部 AI MCP 网关 (/api/mcp)'
          : '已暂停服务端外部 AI MCP 网关'
      );
      await onReloadOverview();
    } catch (err: any) {
      onNotify(err?.message || '更新 MCP 开关失败');
    } finally {
      setSavingConfig(false);
    }
  };

  const handleSaveEndpointSettings = async (e: React.FormEvent) => {
    e.preventDefault();
    let portVal = 18900;
    if (isDesktopMode) {
      const parsed = parseDesktopPort();
      if (parsed === null) return;
      portVal = parsed;
    }
    setSavingConfig(true);
    try {
      const res = await api.updateMCPConfig(
        isDesktopMode
          ? { desktop_loopback_port: portVal }
          : { public_endpoint_hint: publicEndpointHint.trim() }
      );
      setMcpConfig(res.mcp_config);
      setMcpRuntime(res.mcp_runtime);
      setSkillMarkdown(res.skill_markdown);
      onNotify('MCP 接入地址设置已加密保存');
      await onReloadOverview();
    } catch (err: any) {
      onNotify(err?.message || '保存接入设置失败');
    } finally {
      setSavingConfig(false);
    }
  };

  const handleCreateToken = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanName = tokenName.trim();
    if (!cleanName) {
      onNotify('请填写令牌名称（如 MacBook Claude Code）');
      return;
    }
    setCreatingToken(true);
    try {
      const res = await api.createMCPToken({
        name: cleanName,
        client_hint: tokenClientHint,
        scope: tokenScope,
        allowed_servers: tokenAllowedServers,
      });
      setMcpConfig(res.mcp_config);
      setMcpRuntime(res.mcp_runtime);
      setJustCreatedToken({
        id: res.token.id,
        name: res.token.name,
        rawToken: res.raw_token,
        clientHint: tokenClientHint,
      });
      if (
        tokenClientHint === 'claude_code' ||
        tokenClientHint === 'codex' ||
        tokenClientHint === 'antigravity' ||
        tokenClientHint === 'cursor'
      ) {
        setSelectedClient(tokenClientHint);
      }
      setTokenName('');
      setTokenAllowedServers([]);
      onNotify('持久化 MCP 令牌签发成功！请立即复制保存，页面刷新后将不再显示明文');
      await onReloadOverview();
    } catch (err: any) {
      onNotify(err?.message || '签发 MCP 令牌失败');
    } finally {
      setCreatingToken(false);
    }
  };

  const handleToggleToken = async (tok: MCPTokenView) => {
    try {
      const res = await api.updateMCPToken(tok.id, { enabled: !tok.enabled });
      setMcpConfig(res.mcp_config);
      onNotify(tok.enabled ? `已暂停令牌「${tok.name}」` : `已恢复启用令牌「${tok.name}」`);
      await onReloadOverview();
    } catch (err: any) {
      onNotify(err?.message || '更新令牌状态失败');
    }
  };

  const handleDeleteToken = async (tok: MCPTokenView) => {
    try {
      const res = await api.deleteMCPToken(tok.id);
      setMcpConfig(res.mcp_config);
      setJustCreatedToken((cur) => (cur?.id === tok.id ? null : cur));
      onNotify(`已永久吊销令牌「${tok.name}」`);
      await onReloadOverview();
    } catch (err: any) {
      onNotify(err?.message || '吊销令牌失败');
    }
  };

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

  const handleResolveApproval = async (ap: ExternalApproval, approve: boolean) => {
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
      setApprovals(res.approvals || []);
      lastPendingCountRef.current = res.pending_count;
      if (approve) {
        setPinnedPlanIds((prev) => (prev.includes(ap.id) ? prev : [...prev, ap.id]));
        onNotify(
          `已批准变更计划「${ap.title || '外部 AI 计划'}」（共 ${selectedStepIds?.length || 0} 步），正在后台按序执行...`
        );
      } else {
        onNotify(`已拒绝外部 AI (${ap.client_name}) 的变更计划`);
      }
      await onReloadOverview();
    } catch (err: any) {
      onNotify(err?.message || '处理外部 AI 变更计划失败');
    } finally {
      setResolvingId('');
    }
  };

  const handleCancelApproval = async (ap: ExternalApproval) => {
    setCancellingId(ap.id);
    try {
      const res = await api.cancelExternalApproval(ap.id);
      setApprovals(res.approvals || []);
      onNotify(`已请求中止变更计划「${ap.title || '外部 AI 计划'}」的后续执行`);
      await onReloadOverview();
    } catch (err: any) {
      onNotify(err?.message || '中止变更计划失败');
    } finally {
      setCancellingId('');
    }
  };

  const pendingApprovals = useMemo(
    () => approvals.filter((a) => a.status === 'pending'),
    [approvals]
  );
  const runningApprovals = useMemo(
    () => approvals.filter((a) => a.status === 'running'),
    [approvals]
  );
  const activeApprovals = useMemo(
    () =>
      approvals.filter(
        (a) => a.status === 'pending' || a.status === 'running' || pinnedPlanIds.includes(a.id)
      ),
    [approvals, pinnedPlanIds]
  );
  const visibleApprovals = useMemo(
    () => (approvalFilter === 'active' ? activeApprovals : approvals),
    [approvalFilter, activeApprovals, approvals]
  );

  // Auto-poll external approvals while this tab is open: fast 1.5s while any plan is running, gentle 5s when idle
  useEffect(() => {
    const intervalMs = runningApprovals.length > 0 ? 1500 : 5000;
    let disposed = false;
    const timer = window.setInterval(async () => {
      try {
        const res = await api.listExternalApprovals('all', 60);
        if (disposed) return;
        setApprovals(res.approvals || []);
        if (res.pending_count !== lastPendingCountRef.current) {
          lastPendingCountRef.current = res.pending_count;
          void onReloadOverview();
        }
      } catch {
        // ignore transient polling failures
      }
    }, intervalMs);
    return () => {
      disposed = true;
      window.clearInterval(timer);
    };
  }, [runningApprovals.length, onReloadOverview]);

  const pendingPatrolsCount = overview?.patrol_status?.pending_external_count || 0;
  const patrolAnalysisMode = overview?.patrol_config?.analysis_mode || 'builtin';
  const gatewayActive = isDesktopMode
    ? Boolean(mcpConfig?.desktop_loopback_enabled && mcpRuntime?.desktop_loopback_running)
    : Boolean(mcpConfig?.enabled);

  if (loading && !mcpConfig) {
    return (
      <div className="page-body">
        <div className="empty-state">
          <div style={{ color: 'var(--text-muted)' }}>正在加载外部 AI MCP 接管配置...</div>
        </div>
      </div>
    );
  }

  return (
    <div className="page-body">
      {/* Top Connectivity & Status Banner */}
      <div className="patrol-status-banner mcp-status-banner">
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 14, minWidth: 0, flex: 1 }}>
          <div
            style={{
              width: 44,
              height: 44,
              borderRadius: 11,
              background: gatewayActive ? 'var(--accent-teal-soft)' : 'var(--bg-muted)',
              color: gatewayActive ? 'var(--accent-teal)' : 'var(--text-muted)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              flexShrink: 0,
            }}
          >
            <PlugZap size={21} />
          </div>
          <div style={{ minWidth: 0, flex: 1 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
              <strong style={{ fontSize: 15 }}>
                外部 AI 接管网关 (MCP Streamable HTTP)
              </strong>
              <span className={`tag-chip ${gatewayActive ? 'teal' : ''}`}>
                {gatewayActive
                  ? isDesktopMode
                    ? `桌面回环运行中 · ${mcpRuntime?.desktop_loopback_addr}`
                    : '服务端 /api/mcp 已开启'
                  : isDesktopMode
                  ? '桌面回环默认关闭（强隔离）'
                  : 'MCP 网关已暂停'}
              </span>
              <span className="tag-chip">
                <Lock size={11} style={{ marginRight: 3 }} /> SSH 凭据物理隔离 · 0 密钥出库
              </span>
            </div>
            <div style={{ fontSize: 12.5, color: 'var(--text-muted)', marginTop: 4, lineHeight: 1.55 }}>
              原生兼容 <strong>Claude Code · Codex · Antigravity · Cursor</strong>。本地 AI 通过持久化作用域
              MCP Token 认领巡检队列、执行白名单只读 SSH/SFTP 钻取取证、回写巡检报告并沉淀主机记忆；所有线上变更提案均强制进入下方
              HITL 审批队列，绝不盲目自动执行。
            </div>
            {mcpRuntime?.desktop_loopback_error && (
              <div style={{ fontSize: 12, color: 'var(--danger-text)', marginTop: 6 }}>
                桌面回环端口启动异常：{mcpRuntime.desktop_loopback_error}
              </div>
            )}
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginTop: 8, maxWidth: '100%' }}>
              <span
                className="tag-chip mono"
                style={{
                  fontSize: 11.5,
                  maxWidth: '100%',
                  height: 'auto',
                  whiteSpace: 'normal',
                  wordBreak: 'break-all',
                  padding: '3px 8px',
                }}
              >
                端点: {effectiveURL}
              </span>
              <button
                type="button"
                className="btn btn-sm"
                onClick={() => void copyText('endpoint', effectiveURL, ' MCP 端点地址')}
              >
                {copiedKey === 'endpoint' ? <Check size={12} /> : <Copy size={12} />} 复制地址
              </button>
              <button type="button" className="btn btn-sm" onClick={onJumpPatrol}>
                <Radar size={12} /> 巡检引擎：
                {patrolAnalysisMode === 'external'
                  ? '纯外部 AI 接管'
                  : patrolAnalysisMode === 'external_with_fallback'
                  ? `外部优先 (${overview?.patrol_config?.external_fallback_minutes || 15}m 兜底)`
                  : '内置模型（点此切换）'}
                {pendingPatrolsCount > 0 && (
                  <span className="nav-badge live" style={{ marginLeft: 4 }}>
                    {pendingPatrolsCount} 待研判
                  </span>
                )}
              </button>
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <button
            type="button"
            className="btn btn-sm"
            onClick={() => void refreshMCPOverview()}
            title="刷新 MCP 令牌与审批队列"
          >
            <RefreshCw size={13} /> 刷新状态
          </button>
          <button
            type="button"
            id="mcp-toggle-gateway-btn"
            className={`btn ${gatewayActive ? '' : 'btn-teal'}`}
            disabled={savingConfig}
            onClick={() => void handleToggleGateway(!gatewayActive)}
          >
            {gatewayActive
              ? isDesktopMode
                ? '关闭桌面回环 MCP'
                : '暂停 MCP 网关'
              : isDesktopMode
              ? '开启桌面回环 MCP'
              : '启用 MCP 网关'}
          </button>
        </div>
      </div>

      {/* SECTION 1: External AI HITL Change Plan Approval Queue */}
      <section className="mcp-section-card" id="mcp-approval-queue-section">
        <div className="mcp-section-head">
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <ListOrdered
              size={17}
              style={{
                color:
                  runningApprovals.length > 0
                    ? 'var(--accent-teal)'
                    : pendingApprovals.length > 0
                    ? 'var(--amber-text)'
                    : 'var(--accent-teal)',
              }}
            />
            <h3 style={{ fontSize: 15, fontWeight: 640 }}>外部 AI 变更计划审批队列 (HITL)</h3>
            {runningApprovals.length > 0 && (
              <span className="tag-chip teal">
                <Loader2 size={11} className="spin-icon" style={{ marginRight: 4 }} />
                {runningApprovals.length} 份计划按序执行中
              </span>
            )}
            {pendingApprovals.length > 0 ? (
              <span className="tag-chip amber">{pendingApprovals.length} 份待审阅批准</span>
            ) : runningApprovals.length === 0 ? (
              <span className="tag-chip teal">当前无待审批变更</span>
            ) : null}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <button
              type="button"
              className={`btn btn-sm ${approvalFilter === 'active' ? 'btn-primary' : ''}`}
              onClick={() => setApprovalFilter('active')}
            >
              待审批 / 执行中 ({pendingApprovals.length + runningApprovals.length})
            </button>
            <button
              type="button"
              className={`btn btn-sm ${approvalFilter === 'all' ? 'btn-primary' : ''}`}
              onClick={() => setApprovalFilter('all')}
            >
              全部历史 ({approvals.length})
            </button>
          </div>
        </div>

        {visibleApprovals.length === 0 ? (
          <div className="mcp-empty-inline">
            {approvalFilter === 'active'
              ? '暂无等待审批的外部 AI 变更计划。当 Claude Code / Codex / Antigravity / Cursor 调用 propose_change_plan 提交有序步骤列表时，全部步骤与 Unified Diff 会自动实时呈现在这里，支持一键批准按序执行。'
              : '尚无外部 AI 提交的变更计划审批记录。'}
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            {visibleApprovals.map((ap) => {
              const steps = getNormalizedSteps(ap);
              const totalSteps = ap.total_steps ?? steps.length;
              const blockedCount = ap.blocked_steps ?? steps.filter((s) => s.blocked).length;
              const executableSteps = steps.filter((s) => !s.blocked);
              const isPending = ap.status === 'pending';
              const isRunning = ap.status === 'running';
              const statusMeta = PLAN_STATUS_META[ap.status] || PLAN_STATUS_META.pending;

              const checkedExecutableSteps = executableSteps.filter((st) =>
                isStepChecked(ap.id, st)
              );
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
                  key={ap.id}
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
                      <span className="tag-chip mono" style={{ fontSize: 11 }}>
                        共 {totalSteps} 步
                      </span>
                      {blockedCount > 0 && (
                        <span className="tag-chip danger" style={{ fontSize: 11 }}>
                          <Ban size={11} style={{ marginRight: 3 }} />
                          含 {blockedCount} 步安全拦截锁定
                        </span>
                      )}
                      <span className="tag-chip teal">{ap.client_name || 'External MCP'}</span>
                      <span className="tag-chip mono" style={{ fontSize: 11 }}>
                        令牌: {ap.token_name}
                      </span>
                      {ap.patrol_record_id && (
                        <span className="tag-chip amber mono" style={{ fontSize: 11 }}>
                          关联巡检: {ap.patrol_record_id.slice(0, 8)}
                        </span>
                      )}
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                      <span className="mono" style={{ fontSize: 11.5, color: 'var(--text-secondary)' }}>
                        目标: {(ap.server_names || []).join(', ')}
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

                    {/* Ordered Steps List (always expanded for full visibility) */}
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
                                  <span className="tag-chip amber" style={{ fontSize: 10.5 }} title="该步骤失败时仍会继续执行后续步骤">
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
                              <div style={{ fontSize: 12.5, color: 'var(--text-secondary)' }}>
                                {st.reason}
                              </div>
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
                            resolvingId === ap.id ||
                            executableSteps.length === 0 ||
                            selectedCount === 0
                          }
                          onClick={() => void handleResolveApproval(ap, true)}
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
                          onClick={() => void handleResolveApproval(ap, false)}
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
                        <span style={{ fontSize: 12.5, color: 'var(--accent-teal)', display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                          <Loader2 size={13} className="spin-icon" />
                          后台按序执行中，页面每 1.5 秒自动同步各步状态与实时回显...
                        </span>
                        <button
                          type="button"
                          className="btn btn-sm"
                          style={{ color: 'var(--danger-text)', borderColor: 'var(--danger-border)' }}
                          disabled={cancellingId === ap.id}
                          onClick={() => void handleCancelApproval(ap)}
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
                          <div style={{ color: 'var(--danger-text)', marginTop: 4 }}>
                            {ap.execution_error}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </section>

      {/* SECTION 2: Persistent Scoped MCP Tokens + Endpoint Settings */}
      <div className="mcp-two-col-grid">
        {/* Left: Create Token & Endpoint Settings */}
        <section className="mcp-section-card">
          <div className="mcp-section-head">
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <KeyRound size={16} style={{ color: 'var(--accent-teal)' }} />
              <h3 style={{ fontSize: 14.5, fontWeight: 640 }}>签发持久化 MCP 接入令牌</h3>
            </div>
          </div>

          <form onSubmit={handleCreateToken} style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div className="field-row">
              <div className="field">
                <label className="field-label">令牌名称</label>
                <input
                  id="mcp-token-name-input"
                  className="input"
                  placeholder="例如：MacBook Claude Code / 办公室 Cursor"
                  value={tokenName}
                  onChange={(e) => setTokenName(e.target.value)}
                />
              </div>
              <div className="field">
                <label className="field-label">目标本地 AI 客户端</label>
                <select
                  id="mcp-token-client-select"
                  className="select"
                  value={tokenClientHint}
                  onChange={(e) => setTokenClientHint(e.target.value)}
                >
                  <option value="claude_code">Claude Code</option>
                  <option value="codex">Codex CLI</option>
                  <option value="antigravity">Antigravity</option>
                  <option value="cursor">Cursor</option>
                  <option value="custom">通用 MCP 客户端</option>
                </select>
              </div>
            </div>

            <div className="field">
              <label className="field-label">权限作用域 (Scope)</label>
              <select
                id="mcp-token-scope-select"
                className="select"
                value={tokenScope}
                onChange={(e) => setTokenScope(e.target.value as MCPTokenScope)}
              >
                <option value="ops_propose">
                  巡检 + 只读深度取证 + 受控变更提案 (ops_propose · 变更强制走 Web 端 HITL 审批)
                </option>
                <option value="patrol_readonly">
                  纯只读巡检与记忆闭环 (patrol_readonly · 禁止提交任何变更提案)
                </option>
              </select>
            </div>

            {servers.length > 0 && (
              <div className="field">
                <label className="field-label">
                  允许访问的主机范围（不勾选 = 全部受管主机，勾选则仅限白名单主机）
                </label>
                <div className="mcp-server-chips">
                  {servers.map((srv) => {
                    const checked = tokenAllowedServers.includes(srv.id);
                    return (
                      <button
                        key={srv.id}
                        type="button"
                        className={`mcp-server-chip ${checked ? 'active' : ''}`}
                        onClick={() =>
                          setTokenAllowedServers((prev) =>
                            checked ? prev.filter((id) => id !== srv.id) : [...prev, srv.id]
                          )
                        }
                      >
                        <ServerIcon size={11} />
                        {srv.name}
                      </button>
                    );
                  })}
                </div>
              </div>
            )}

            <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
              <button
                type="submit"
                id="mcp-create-token-btn"
                className="btn btn-primary"
                disabled={creatingToken || !tokenName.trim()}
              >
                <Plus size={14} /> {creatingToken ? '签发中...' : '生成持久化 MCP 令牌'}
              </button>
            </div>
          </form>

          {justCreatedToken && (
            <div className="mcp-new-token-banner" id="mcp-new-token-banner">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                <strong style={{ fontSize: 13, color: 'var(--accent-teal)' }}>
                  新令牌「{justCreatedToken.name}」已签发（明文仅展示一次，已自动填入下方四端配置！）
                </strong>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <button
                    type="button"
                    className="btn btn-teal btn-sm"
                    onClick={() =>
                      void copyText('raw-token', justCreatedToken.rawToken, ' MCP 令牌明文')
                    }
                  >
                    {copiedKey === 'raw-token' ? <Check size={12} /> : <Copy size={12} />} 复制令牌
                  </button>
                  <button
                    type="button"
                    className="btn btn-ghost btn-sm btn-icon"
                    title="收起明文令牌提示"
                    aria-label="收起明文令牌提示"
                    onClick={() => setJustCreatedToken(null)}
                  >
                    <X size={13} />
                  </button>
                </div>
              </div>
              <code className="mcp-raw-token-code">{justCreatedToken.rawToken}</code>
            </div>
          )}

          {/* Endpoint Hint / Desktop Loopback Port Settings */}
          <form
            onSubmit={handleSaveEndpointSettings}
            style={{
              marginTop: 16,
              paddingTop: 14,
              borderTop: '1px solid var(--border-subtle)',
              display: 'flex',
              alignItems: 'flex-end',
              gap: 10,
              flexWrap: 'wrap',
            }}
          >
            {isDesktopMode ? (
              <div className="field" style={{ flex: '1 1 180px', minWidth: 0 }}>
                <label className="field-label">桌面版独立回环 MCP 端口（仅绑定 127.0.0.1）</label>
                <input
                  type="number"
                  min={1024}
                  max={65535}
                  className="input mono"
                  value={desktopPortStr}
                  onChange={(e) => setDesktopPortStr(e.target.value)}
                />
              </div>
            ) : (
              <div className="field" style={{ flex: '1 1 220px', minWidth: 0 }}>
                <label className="field-label">
                  外部访问地址提示（可选，反代/域名部署时填写，如 https://ops.example.com）
                </label>
                <input
                  className="input mono"
                  placeholder="留空则自动使用当前浏览器访问域名"
                  value={publicEndpointHint}
                  onChange={(e) => setPublicEndpointHint(e.target.value)}
                />
              </div>
            )}
            <button type="submit" className="btn btn-sm" disabled={savingConfig}>
              保存地址配置
            </button>
          </form>
        </section>

        {/* Right: Existing Token List */}
        <section className="mcp-section-card">
          <div className="mcp-section-head">
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <ShieldCheck size={16} style={{ color: 'var(--accent-teal)' }} />
              <h3 style={{ fontSize: 14.5, fontWeight: 640 }}>
                已签发令牌 ({mcpConfig?.tokens?.length || 0})
              </h3>
            </div>
            <span style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>
              仅存 SHA-256 哈希于 secrets.enc · 重启不失效
            </span>
          </div>

          {!mcpConfig?.tokens?.length ? (
            <div className="mcp-empty-inline">
              尚未签发任何 MCP 令牌。请在左侧为你的 Claude Code、Codex、Antigravity 或 Cursor 创建一个独立令牌，支持按客户端单独吊销和主机白名单隔离。
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {mcpConfig.tokens.map((tok) => (
                <div
                  key={tok.id}
                  className={`mcp-token-item ${tok.enabled ? '' : 'disabled'}`}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 8, flexWrap: 'wrap' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 7, flexWrap: 'wrap' }}>
                      <strong style={{ fontSize: 13.5 }}>{tok.name}</strong>
                      <span className="tag-chip">
                        {CLIENT_HINT_LABELS[tok.client_hint || 'custom'] || tok.client_hint}
                      </span>
                      <span className={`tag-chip ${tok.scope === 'ops_propose' ? 'amber' : 'teal'}`}>
                        {tok.scope === 'ops_propose' ? '巡检 + HITL 变更提案' : '只读巡检'}
                      </span>
                      {!tok.enabled && <span className="tag-chip">已停用</span>}
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <button
                        type="button"
                        className="btn btn-sm"
                        onClick={() => void handleToggleToken(tok)}
                      >
                        {tok.enabled ? '暂停' : '启用'}
                      </button>
                      <button
                        type="button"
                        className="btn btn-ghost btn-sm btn-icon"
                        style={{ color: 'var(--danger-text)' }}
                        title="永久吊销该令牌"
                        onClick={() => void handleDeleteToken(tok)}
                      >
                        <Trash2 size={13.5} />
                      </button>
                    </div>
                  </div>

                  <div className="mono mcp-token-meta">
                    <span>前缀: {tok.token_prefix}</span>
                    <span>
                      范围:{' '}
                      {tok.allowed_servers?.length
                        ? tok.allowed_servers.map((id) => serverNameMap[id] || id).join(', ')
                        : '全部主机'}
                    </span>
                    <span>调用次数: {tok.call_count || 0}</span>
                    {tok.last_used_at ? (
                      <span>
                        最近活跃: {new Date(tok.last_used_at).toLocaleString('zh-CN')}
                        {tok.last_client_name ? ` (${tok.last_client_name})` : ''}
                      </span>
                    ) : (
                      <span>尚未连接</span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>

      {/* SECTION 3: 4-Client One-Click MCP Config Generator + Standard Patrol SKILL.md */}
      <section className="mcp-section-card" id="mcp-client-config-section">
        <div className="mcp-section-head">
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <Sparkles size={16} style={{ color: 'var(--accent-teal)' }} />
            <h3 style={{ fontSize: 15, fontWeight: 640 }}>
              四端一键接入配置 &amp; 标准巡检 SKILL.md
            </h3>
            <span className="tag-chip teal">内置 20+ 运维工具 · 4 个资源 · 3 个巡检 Prompts</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <button
              type="button"
              className="btn btn-sm"
              onClick={() => void copyText('skill-md', skillMarkdown, '标准巡检 SKILL.md')}
            >
              {copiedKey === 'skill-md' ? <Check size={12} /> : <Copy size={12} />} 复制 SKILL.md
            </button>
            <button type="button" className="btn btn-teal btn-sm" onClick={downloadSkillFile}>
              <Download size={12} /> 下载 SKILL.md
            </button>
          </div>
        </div>

        {/* 4-Client Selector Tabs */}
        <div className="mcp-client-tabs" role="tablist">
          {CLIENT_PRESETS.map((preset) => (
            <button
              key={preset.key}
              type="button"
              role="tab"
              aria-selected={selectedClient === preset.key}
              className={`mcp-client-tab ${selectedClient === preset.key ? 'active' : ''}`}
              onClick={() => setSelectedClient(preset.key)}
            >
              {preset.label}
            </button>
          ))}
        </div>

        {(() => {
          const activePreset = CLIENT_PRESETS.find((p) => p.key === selectedClient) || CLIENT_PRESETS[0];
          const snips = generatedSnippets[selectedClient];
          return (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 8 }}>
                <div style={{ fontSize: 12.5, color: 'var(--text-secondary)' }}>
                  <strong>配置位置：</strong>
                  <span className="mono">{activePreset.configPath}</span>
                  <span style={{ color: 'var(--text-muted)', marginLeft: 8 }}>{activePreset.tip}</span>
                </div>
                <button
                  type="button"
                  className="btn btn-primary btn-sm"
                  onClick={() =>
                    void copyText(`cfg-${selectedClient}`, snips.primary, ` ${activePreset.label} 接入配置`)
                  }
                >
                  {copiedKey === `cfg-${selectedClient}` ? <Check size={12} /> : <Copy size={12} />} 复制
                  {selectedClient === 'claude_code' ? ' CLI 命令' : '配置'}
                </button>
              </div>
              <pre className="mcp-code-block">{snips.primary}</pre>

              {snips.secondary && (
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                    <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                      或者直接写入项目根目录 <code className="mono">.mcp.json</code>：
                    </span>
                    <button
                      type="button"
                      className="btn btn-sm"
                      onClick={() =>
                        void copyText(`cfg2-${selectedClient}`, snips.secondary, ' .mcp.json 配置')
                      }
                    >
                      {copiedKey === `cfg2-${selectedClient}` ? <Check size={12} /> : <Copy size={12} />} 复制 JSON
                    </button>
                  </div>
                  <pre className="mcp-code-block">{snips.secondary}</pre>
                </div>
              )}
            </div>
          );
        })()}

        {/* Built-in MCP Prompts & Quick Usage Cheatsheet */}
        <div className="mcp-prompts-strip">
          <div className="mcp-prompt-pill">
            <strong className="mono">patrol_triage</strong>
            <span>认领后台定时巡检待研判异常单，只读钻取日志并回写深度报告</span>
          </div>
          <div className="mcp-prompt-pill">
            <strong className="mono">full_security_patrol</strong>
            <span>主动触发全集群只读安全体检、基线比对并沉淀主机记忆</span>
          </div>
          <div className="mcp-prompt-pill">
            <strong className="mono">host_deep_audit</strong>
            <span>对单台目标主机深度体检 SSH 配置、公网端口、容器与磁盘日志</span>
          </div>
        </div>

        {/* Collapsible SKILL.md Preview */}
        <div style={{ marginTop: 12 }}>
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            onClick={() => setShowSkillPreview(!showSkillPreview)}
          >
            {showSkillPreview ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
            <BookOpen size={13} /> {showSkillPreview ? '收起' : '展开'}标准巡检 SKILL.md 规范全文（可放入 ~/.claude/skills/ 或项目技能目录）
          </button>
          {showSkillPreview && (
            <pre className="mcp-code-block" style={{ marginTop: 8, maxHeight: 320 }}>
              {skillMarkdown}
            </pre>
          )}
        </div>

        <div style={{ marginTop: 10, fontSize: 12, color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
          <ExternalLink size={12} />
          <span>
            定时无人值守提示：在「后台巡检与告警」设置中将研判引擎切换为<strong>外部 AI 接管</strong>或<strong>外部优先+超时回退</strong>，配合本地系统 cron / Claude Code{' '}
            <code className="mono">/loop</code> 定期调用 <code className="mono">patrol_triage</code> 即可用本地订阅实现 7×24 全自动深度巡检。
          </span>
        </div>
      </section>
    </div>
  );
};

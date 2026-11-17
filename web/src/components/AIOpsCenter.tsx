import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Bot,
  Plus,
  Send,
  Trash2,
  ShieldCheck,
  Radar,
  BrainCircuit,
  Cpu,
  Play,
  Sliders,
  CheckCircle2,
  AlertTriangle,
  Sparkles,
  BookOpen,
  Server as ServerIcon,
  Bell,
  Edit3,
  RefreshCw,
  ArrowUpRight,
  KeyRound,
} from 'lucide-react';
import { api } from '../api';
import type {
  AIChatSession,
  AIChatSessionSummary,
  AIExecutionMode,
  AIOverviewResponse,
  AIProtocol,
  AIProviderView,
  AIRunbook,
  AIToolCallRecord,
  HostMemory,
  PatrolRecord,
  ProviderPreset,
  ServerView,
} from '../types';
import {
  FormattedMarkdownText,
  HITLApprovalCard,
  RunbookProposalCard,
  ShellSnippetActionBar,
  ToolTraceStep,
  extractShellSnippets,
} from './AIMessageWidgets';

type CenterTab = 'diagnosis' | 'patrol' | 'memory' | 'providers';

interface AIOpsCenterProps {
  servers: ServerView[];
  onRefreshWorkspace: () => Promise<void>;
  onBadgeChange?: (unreadCount: number) => void;
  onNotify: (msg: string) => void;
}

interface WebhookDraft {
  id: string;
  name: string;
  kind: 'feishu' | 'dingtalk' | 'wecom' | 'custom';
  url: string;
  urlMasked?: string;
  secret: string;
  hasSecret?: boolean;
  enabled: boolean;
}

const QUICK_DIAGNOSTIC_PROMPTS = [
  {
    label: '全面安全基线体检',
    prompt:
      '请对所选服务器执行一次非破坏性的安全基线与负载体检（检查负载、内存磁盘、异常监听端口、近1小时 SSH 失败登录、UID=0 特权账户与失败的 systemd 服务），归档主机环境画像并给出加固建议。',
  },
  {
    label: 'CPU / 内存飙高排查',
    prompt:
      '请排查所选服务器当前 CPU 与内存占用最高的进程及线程栈线索，分析是否存在异常飙高或内存泄漏风险，并给出处置方案。',
  },
  {
    label: 'SSH 爆破与监听审计',
    prompt:
      '请审计所选服务器的 SSH 登录安全配置 (/etc/ssh/sshd_config)、近期失败登录来源 IP 以及公网暴露监听端口，若需加固配置请生成变更对比供我审批。',
  },
  {
    label: '磁盘空间占满分析',
    prompt:
      '请定位所选服务器根分区与 /var 目录下的大文件及膨胀日志，评估哪些日志可安全清理或轮转，在执行任何清理前先提交审批。',
  },
];

export const AIOpsCenter: React.FC<AIOpsCenterProps> = ({
  servers,
  onRefreshWorkspace,
  onBadgeChange,
  onNotify,
}) => {
  const [subTab, setSubTab] = useState<CenterTab>('diagnosis');
  const [overview, setOverview] = useState<AIOverviewResponse | null>(null);
  const [loading, setLoading] = useState(true);

  // Active Chat Session State
  const [activeSessionId, setActiveSessionId] = useState<string>('');
  const [activeSession, setActiveSession] = useState<AIChatSession | null>(null);
  const [selectedServerIds, setSelectedServerIds] = useState<string[]>([]);
  const [sessionMode, setSessionMode] = useState<AIExecutionMode>('standard');
  const [promptInput, setPromptInput] = useState('');
  const [streaming, setStreaming] = useState(false);
  const [streamDelta, setStreamDelta] = useState('');
  const [streamTools, setStreamTools] = useState<AIToolCallRecord[]>([]);
  const chatEndRef = useRef<HTMLDivElement | null>(null);

  // Patrol Config & Execution State
  const [runningPatrol, setRunningPatrol] = useState(false);
  const [showPatrolConfigModal, setShowPatrolConfigModal] = useState(false);
  const [patrolEnabled, setPatrolEnabled] = useState(false);
  const [patrolInterval, setPatrolInterval] = useState(60);
  const [patrolServerIds, setPatrolServerIds] = useState<string[]>([]);
  const [cpuWarn, setCpuWarn] = useState(85);
  const [memWarn, setMemWarn] = useState(85);
  const [diskWarn, setDiskWarn] = useState(85);
  const [sshFailWarn, setSshFailWarn] = useState(15);
  const [checkPorts, setCheckPorts] = useState(true);
  const [checkPrivUsers, setCheckPrivUsers] = useState(true);
  const [webhookDrafts, setWebhookDrafts] = useState<WebhookDraft[]>([]);
  const [testingWebhookIdx, setTestingWebhookIdx] = useState<number | null>(null);

  // Memory & Runbook Editor Modals
  const [editingMemory, setEditingMemory] = useState<{
    server_id: string;
    summary: string;
    os_arch: string;
    key_services_csv: string;
    deploy_paths_csv: string;
    ports_note: string;
    notes: string;
  } | null>(null);

  const [editingRunbook, setEditingRunbook] = useState<{
    id?: string;
    title: string;
    category: string;
    symptom: string;
    root_cause: string;
    diagnostic_steps_text: string;
    fix_commands_text: string;
    verification: string;
    sync_snippet: boolean;
  } | null>(null);

  // Provider Form State
  const [provForm, setProvForm] = useState<{
    id: string;
    name: string;
    protocol: AIProtocol;
    base_url: string;
    api_key: string;
    model: string;
    max_tokens: number;
    set_active: boolean;
  }>({
    id: '',
    name: 'DeepSeek 官方接口',
    protocol: 'openai',
    base_url: 'https://api.deepseek.com/v1',
    api_key: '',
    model: 'deepseek-chat',
    max_tokens: 4096,
    set_active: true,
  });
  const [testingProvId, setTestingProvId] = useState<string>('');
  const [testResultBanner, setTestResultBanner] = useState<{
    ok: boolean;
    text: string;
  } | null>(null);

  const syncPatrolDraftFromOverview = useCallback((ov: AIOverviewResponse) => {
    const pc = ov.patrol_config;
    setPatrolEnabled(pc.enabled);
    setPatrolInterval(pc.interval_minutes || 60);
    setPatrolServerIds(pc.server_ids || []);
    setCpuWarn(pc.cpu_warn_percent || 85);
    setMemWarn(pc.mem_warn_percent || 85);
    setDiskWarn(pc.disk_warn_percent || 85);
    setSshFailWarn(pc.ssh_fail_warn_count || 15);
    setCheckPorts(pc.check_listening_ports);
    setCheckPrivUsers(pc.check_privileged_users);
    setWebhookDrafts(
      (pc.webhooks || []).map((w) => ({
        id: w.id,
        name: w.name,
        kind: w.kind,
        url: '',
        urlMasked: w.url_masked,
        secret: '',
        hasSecret: w.has_secret,
        enabled: w.enabled,
      }))
    );
  }, []);

  const loadOverview = useCallback(
    async (preferSessionId?: string) => {
      try {
        const ov = await api.getAIOverview('center');
        setOverview(ov);
        syncPatrolDraftFromOverview(ov);

        const pendingApprovalsCount = (ov.sessions || []).reduce(
          (acc, s) => acc + (s.pending_approval_count || 0),
          0
        );
        onBadgeChange?.((ov.patrol_status?.unread_alerts || 0) + pendingApprovalsCount);

        const targetId =
          preferSessionId ||
          activeSessionId ||
          (ov.sessions && ov.sessions.length > 0 ? ov.sessions[0].id : '');
        if (targetId) {
          setActiveSessionId(targetId);
          const { session } = await api.getAISession(targetId);
          setActiveSession(session);
          setSelectedServerIds(
            session.server_ids?.length
              ? session.server_ids
              : servers.length > 0
              ? [servers[0].id]
              : []
          );
          setSessionMode(session.mode || ov.default_mode || 'standard');
        } else if (servers.length > 0 && selectedServerIds.length === 0) {
          setSelectedServerIds([servers[0].id]);
        }
      } catch (err: any) {
        onNotify(err?.message || '加载 AI 运维中心数据失败');
      } finally {
        setLoading(false);
      }
    },
    [activeSessionId, onBadgeChange, onNotify, selectedServerIds.length, servers, syncPatrolDraftFromOverview]
  );

  useEffect(() => {
    void loadOverview();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (subTab === 'patrol' && overview?.patrol_status?.unread_alerts) {
      void api.listPatrolRecords(30, true).then((res) => {
        setOverview((prev) =>
          prev
            ? {
                ...prev,
                patrol_records: res.records,
                patrol_status: res.patrol_status,
              }
            : prev
        );
        const pendingCnt = (overview?.sessions || []).reduce(
          (acc, s) => acc + (s.pending_approval_count || 0),
          0
        );
        onBadgeChange?.(pendingCnt);
      });
    }
  }, [subTab, overview?.patrol_status?.unread_alerts, overview?.sessions, onBadgeChange]);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [activeSession?.messages.length, streamDelta, streamTools.length]);

  const activeProvider = useMemo(() => {
    if (!overview?.providers?.length) return null;
    return (
      overview.providers.find((p) => p.id === overview.active_provider_id) ||
      overview.providers[0]
    );
  }, [overview]);

  const handleSelectSession = async (summary: AIChatSessionSummary) => {
    setActiveSessionId(summary.id);
    try {
      const { session } = await api.getAISession(summary.id);
      setActiveSession(session);
      setSelectedServerIds(session.server_ids || []);
      setSessionMode(session.mode || 'standard');
    } catch (err: any) {
      onNotify(err?.message || '读取会话详情失败');
    }
  };

  const handleCreateSession = async (
    initialTitle = '新建 AI 运维排障会话',
    serverIds?: string[]
  ): Promise<AIChatSession | null> => {
    try {
      const sids =
        serverIds ??
        (selectedServerIds.length > 0
          ? selectedServerIds
          : servers.length > 0
          ? [servers[0].id]
          : []);
      const { session } = await api.createAISession({
        title: initialTitle,
        scope: 'center',
        server_ids: sids,
        mode: sessionMode,
      });
      setActiveSessionId(session.id);
      setActiveSession(session);
      setSelectedServerIds(sids);
      await loadOverview(session.id);
      return session;
    } catch (err: any) {
      onNotify(err?.message || '创建会话失败');
      return null;
    }
  };

  const handleDeleteSession = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      await api.deleteAISession(id);
      if (activeSessionId === id) {
        setActiveSessionId('');
        setActiveSession(null);
      }
      await loadOverview('');
      onNotify('已删除排障会话记录');
    } catch (err: any) {
      onNotify(err?.message || '删除会话失败');
    }
  };

  const handleChangeMode = async (nextMode: AIExecutionMode) => {
    setSessionMode(nextMode);
    if (activeSession) {
      try {
        const { session } = await api.updateAISessionMode(activeSession.id, {
          mode: nextMode,
          server_ids: selectedServerIds,
        });
        setActiveSession(session);
      } catch {
        // ignore transient
      }
    }
  };

  const toggleServerTarget = async (srvId: string) => {
    const next = selectedServerIds.includes(srvId)
      ? selectedServerIds.filter((id) => id !== srvId)
      : [...selectedServerIds, srvId];
    setSelectedServerIds(next);
    if (activeSession) {
      try {
        const { session } = await api.updateAISessionMode(activeSession.id, {
          mode: sessionMode,
          server_ids: next,
        });
        setActiveSession(session);
      } catch {
        // ignore
      }
    }
  };

  const processStreamEvents = useCallback(
    (ev: any) => {
      switch (ev.type) {
        case 'delta':
          if (ev.delta) {
            setStreamDelta((prev) => prev + ev.delta);
          }
          break;
        case 'tool_start':
          if (ev.tool) {
            setStreamTools((prev) => {
              const idx = prev.findIndex((t) => t.id === ev.tool.id);
              if (idx >= 0) {
                const cp = [...prev];
                cp[idx] = ev.tool;
                return cp;
              }
              return [...prev, ev.tool];
            });
          }
          break;
        case 'tool_result':
          if (ev.tool) {
            setStreamTools((prev) =>
              prev.map((t) => (t.id === ev.tool.id ? ev.tool : t))
            );
          }
          break;
        case 'memory_updated':
          if (ev.memory) {
            onNotify(`AI 已自动更新「${ev.memory.server_name}」主机环境画像`);
          }
          break;
        case 'runbook_proposed':
          if (ev.proposal) {
            onNotify(`AI 已提炼排障技能草案《${ev.proposal.title}》，请确认是否归档`);
          }
          break;
        case 'session_sync':
          if (ev.session) {
            setActiveSession(ev.session);
            setStreamDelta('');
            setStreamTools([]);
          }
          break;
        case 'error':
          if (ev.error) {
            onNotify(ev.error);
          }
          break;
      }
    },
    [onNotify]
  );

  const handleSendMessage = async (overridePrompt?: string, overrideServerIds?: string[]) => {
    const text = (overridePrompt ?? promptInput).trim();
    if (!text || streaming) return;

    if (!activeProvider) {
      onNotify('请先在「模型与网关配置」中添加并激活大模型 API');
      setSubTab('providers');
      return;
    }

    let sess = activeSession;
    const targetServers = overrideServerIds ?? selectedServerIds;
    if (!sess) {
      sess = await handleCreateSession(text.slice(0, 24), targetServers);
      if (!sess) return;
    }

    if (!overridePrompt) setPromptInput('');
    setStreaming(true);
    setStreamDelta('');
    setStreamTools([]);

    try {
      await api.streamAIChat(
        sess.id,
        {
          message: text,
          server_ids: targetServers,
          mode: sessionMode,
        },
        processStreamEvents
      );
      await loadOverview(sess.id);
    } catch (err: any) {
      onNotify(err?.message || 'AI 诊断对话中断');
    } finally {
      setStreaming(false);
      setStreamDelta('');
      setStreamTools([]);
    }
  };

  const handleResolveApproval = async (approvalId: string, approve: boolean) => {
    if (!activeSession || streaming) return;
    setStreaming(true);
    setStreamDelta('');
    setStreamTools([]);
    try {
      await api.streamAIApproval(
        activeSession.id,
        approvalId,
        approve,
        processStreamEvents
      );
      await loadOverview(activeSession.id);
    } catch (err: any) {
      onNotify(err?.message || '处理变更审批失败');
    } finally {
      setStreaming(false);
      setStreamDelta('');
      setStreamTools([]);
    }
  };

  const handleResolveProposal = async (
    proposalId: string,
    accept: boolean,
    syncSnippet: boolean
  ) => {
    try {
      await api.resolveRunbookProposal(proposalId, accept, syncSnippet);
      onNotify(
        accept
          ? syncSnippet
            ? '已保存至 Runbook 技能库并同步生成快捷指令'
            : '已加密保存至 Runbook 技能库'
          : '已忽略该技能草案'
      );
      if (syncSnippet) await onRefreshWorkspace();
      await loadOverview(activeSession?.id);
    } catch (err: any) {
      onNotify(err?.message || '操作失败');
    }
  };

  // --- Patrol Actions ---
  const handleRunPatrolNow = async () => {
    setRunningPatrol(true);
    try {
      const res = await api.runPatrolNow(true);
      onNotify(
        `全量只读安全巡检已完成：正常 ${res.record.healthy_count} 台，预警 ${res.record.warning_count} 台，严重 ${res.record.critical_count} 台`
      );
      await loadOverview(activeSessionId);
    } catch (err: any) {
      onNotify(err?.message || '执行巡检失败');
    } finally {
      setRunningPatrol(false);
    }
  };

  const handleSavePatrolConfig = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.updatePatrolConfig({
        enabled: patrolEnabled,
        interval_minutes: patrolInterval,
        server_ids: patrolServerIds,
        cpu_warn_percent: cpuWarn,
        mem_warn_percent: memWarn,
        disk_warn_percent: diskWarn,
        ssh_fail_warn_count: sshFailWarn,
        check_listening_ports: checkPorts,
        check_privileged_users: checkPrivUsers,
        webhooks: webhookDrafts.map((w) => ({
          id: w.id,
          name: w.name,
          kind: w.kind,
          url: w.url.trim() ? w.url.trim() : undefined,
          secret: w.secret.trim() ? w.secret.trim() : undefined,
          enabled: w.enabled,
        })),
      });
      setShowPatrolConfigModal(false);
      onNotify('后台定时巡检与告警通道配置已加密保存');
      await loadOverview(activeSessionId);
    } catch (err: any) {
      onNotify(err?.message || '保存巡检配置失败');
    }
  };

  const handleInvestigatePatrolRecord = async (rec: PatrolRecord) => {
    const affectedIds = rec.findings
      .filter((f) => (f.anomalies && f.anomalies.length > 0) || !f.reachable)
      .map((f) => f.server_id);
    const sids = affectedIds.length > 0 ? affectedIds : servers.map((s) => s.id);
    const anomalyLines = rec.findings
      .filter((f) => (f.anomalies && f.anomalies.length > 0) || !f.reachable)
      .map((f) => `- ${f.server_name} (${f.host}): ${(f.anomalies || []).join('；')}`)
      .join('\n');

    setSubTab('diagnosis');
    const sess = await handleCreateSession('巡检异常深入排障', sids);
    if (sess) {
      setSelectedServerIds(sids);
      setPromptInput(
        `后台巡检发现以下异常，请深入诊断根因并在必要时提交修复变更方案供我审批：\n${anomalyLines}`
      );
    }
  };

  // --- Provider Actions ---
  const applyPreset = (preset: ProviderPreset) => {
    setProvForm({
      id: '',
      name: preset.name,
      protocol: preset.protocol,
      base_url: preset.base_url,
      api_key: '',
      model: preset.default_model,
      max_tokens: 4096,
      set_active: true,
    });
    setTestResultBanner(null);
  };

  const editExistingProvider = (p: AIProviderView) => {
    setProvForm({
      id: p.id,
      name: p.name,
      protocol: p.protocol,
      base_url: p.base_url,
      api_key: '',
      model: p.model,
      max_tokens: p.max_tokens || 4096,
      set_active: overview?.active_provider_id === p.id,
    });
    setTestResultBanner(null);
  };

  const handleSaveProvider = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.upsertAIProvider({
        id: provForm.id || undefined,
        name: provForm.name,
        protocol: provForm.protocol,
        base_url: provForm.base_url,
        api_key: provForm.api_key || undefined,
        model: provForm.model,
        max_tokens: provForm.max_tokens,
        set_active: provForm.set_active,
      });
      setProvForm((prev) => ({ ...prev, id: '', api_key: '' }));
      onNotify('大模型供应商配置已通过 XChaCha20-Poly1305 加密保存');
      await loadOverview(activeSessionId);
    } catch (err: any) {
      onNotify(err?.message || '保存模型配置失败');
    }
  };

  const handleTestProvider = async (target?: AIProviderView) => {
    const id = target ? target.id : provForm.id;
    setTestingProvId(id || '__form__');
    setTestResultBanner(null);
    try {
      const res = await api.testAIProvider({
        id: id || undefined,
        protocol: target ? target.protocol : provForm.protocol,
        base_url: target ? target.base_url : provForm.base_url,
        api_key: target ? undefined : provForm.api_key || undefined,
        model: target ? target.model : provForm.model,
      });
      const msg = `连通成功 · 响应延迟 ${res.latency_ms}ms · 回复：「${res.reply}」`;
      setTestResultBanner({ ok: true, text: msg });
      onNotify(msg);
    } catch (err: any) {
      const msg = err?.message || '模型接口连通测试失败';
      setTestResultBanner({ ok: false, text: msg });
      onNotify(msg);
    } finally {
      setTestingProvId('');
    }
  };

  // --- Memory & Runbook Save Handlers ---
  const handleSaveMemoryModal = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingMemory) return;
    try {
      await api.upsertHostMemory(editingMemory.server_id, {
        summary: editingMemory.summary,
        os_arch: editingMemory.os_arch,
        key_services: editingMemory.key_services_csv
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean),
        deploy_paths: editingMemory.deploy_paths_csv
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean),
        ports_note: editingMemory.ports_note,
        notes: editingMemory.notes,
      });
      setEditingMemory(null);
      onNotify('主机环境画像记忆已更新');
      await loadOverview(activeSessionId);
    } catch (err: any) {
      onNotify(err?.message || '更新主机记忆失败');
    }
  };

  const handleSaveRunbookModal = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingRunbook) return;
    try {
      await api.upsertRunbook({
        id: editingRunbook.id,
        title: editingRunbook.title,
        category: editingRunbook.category,
        symptom: editingRunbook.symptom,
        root_cause: editingRunbook.root_cause,
        diagnostic_steps: editingRunbook.diagnostic_steps_text
          .split('\n')
          .map((s) => s.trim())
          .filter(Boolean),
        fix_commands: editingRunbook.fix_commands_text
          .split('\n')
          .map((s) => s.trim())
          .filter(Boolean),
        verification: editingRunbook.verification,
        sync_snippet: editingRunbook.sync_snippet,
      });
      if (editingRunbook.sync_snippet) await onRefreshWorkspace();
      setEditingRunbook(null);
      onNotify('排障技能 Runbook 已加密归档');
      await loadOverview(activeSessionId);
    } catch (err: any) {
      onNotify(err?.message || '保存 Runbook 失败');
    }
  };

  const launchRunbookDiagnosis = async (rb: AIRunbook) => {
    setSubTab('diagnosis');
    const sess = await handleCreateSession(`执行技能：${rb.title}`);
    if (sess) {
      setPromptInput(
        `请参考排障技能《${rb.title}》对目标主机进行诊断：\n- 适用症状：${rb.symptom}\n- 推荐排查步骤：${(
          rb.diagnostic_steps || []
        ).join('；')}`
      );
    }
  };

  // Map tool_call_id -> AIPendingApproval for inline rendering inside conversation
  const approvalByToolCallId = useMemo(() => {
    const map = new Map<string, any>();
    for (const ap of activeSession?.pending_approvals || []) {
      map.set(ap.tool_call_id, ap);
    }
    return map;
  }, [activeSession?.pending_approvals]);

  return (
    <div className="workspace-surface" id="aiops-center-view">
      {/* Page Header */}
      <div className="page-header">
        <div className="page-header-title">
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <h2>AI 智能运维与安全诊断中心</h2>
            {activeProvider ? (
              <button
                type="button"
                className="tag-chip teal"
                style={{ border: 'none', cursor: 'pointer' }}
                onClick={() => setSubTab('providers')}
                title="点击切换或管理全局激活大模型"
              >
                <Sparkles size={11.5} style={{ marginRight: 4 }} />
                {activeProvider.name} · {activeProvider.model}
              </button>
            ) : (
              <button
                type="button"
                className="tag-chip amber"
                style={{ border: 'none', cursor: 'pointer' }}
                onClick={() => setSubTab('providers')}
              >
                尚未配置大模型 · 点击接入
              </button>
            )}
          </div>
          <p>
            零外部运行时纯原生引擎 · SSH 凭据严格隔离不出境 · 变更支持 Git Diff 预览与人工授权
          </p>
        </div>

        <div className="ai-subnav" role="tablist" aria-label="AI 运维功能分区">
          <button
            type="button"
            id="ai-tab-diagnosis"
            className={`ai-subnav-btn ${subTab === 'diagnosis' ? 'active' : ''}`}
            onClick={() => setSubTab('diagnosis')}
          >
            <Bot size={14} /> 智能排障与体检
          </button>
          <button
            type="button"
            id="ai-tab-patrol"
            className={`ai-subnav-btn ${subTab === 'patrol' ? 'active' : ''}`}
            onClick={() => setSubTab('patrol')}
          >
            <Radar size={14} /> 后台巡检与告警
            {(overview?.patrol_status?.unread_alerts || 0) > 0 && (
              <span className="nav-badge live">{overview?.patrol_status?.unread_alerts}</span>
            )}
          </button>
          <button
            type="button"
            id="ai-tab-memory"
            className={`ai-subnav-btn ${subTab === 'memory' ? 'active' : ''}`}
            onClick={() => setSubTab('memory')}
          >
            <BrainCircuit size={14} /> 主机记忆与技能库
            <span className="nav-badge">
              {(overview?.host_memories?.length || 0) + (overview?.runbooks?.length || 0)}
            </span>
          </button>
          <button
            type="button"
            id="ai-tab-providers"
            className={`ai-subnav-btn ${subTab === 'providers' ? 'active' : ''}`}
            onClick={() => setSubTab('providers')}
          >
            <Cpu size={14} /> 模型与网关配置
          </button>
        </div>
      </div>

      {/* TAB 1: Intelligent Troubleshooting & Security Checkup */}
      {subTab === 'diagnosis' && (
        <div className="ai-workbench">
          <aside className="ai-session-rail">
            <div className="ai-session-rail-header">
              <button
                type="button"
                id="ai-new-session-btn"
                className="btn btn-primary btn-block"
                onClick={() => void handleCreateSession()}
              >
                <Plus size={14} /> 新建排障会话
              </button>
            </div>
            <div className="ai-session-list">
              {!overview?.sessions?.length ? (
                <div style={{ padding: '20px 10px', textAlign: 'center', fontSize: 12, color: 'var(--text-muted)' }}>
                  暂无排障记录，发送问题即可自动创建加密会话
                </div>
              ) : (
                overview.sessions.map((s) => (
                  <div
                    key={s.id}
                    className={`ai-session-item ${activeSessionId === s.id ? 'active' : ''}`}
                    onClick={() => void handleSelectSession(s)}
                    role="button"
                    tabIndex={0}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 6 }}>
                      <span className="ai-session-item-title">{s.title}</span>
                      <button
                        type="button"
                        className="btn btn-ghost btn-sm btn-icon"
                        style={{ width: 22, height: 22, opacity: 0.65 }}
                        onClick={(e) => void handleDeleteSession(s.id, e)}
                        title="删除此会话"
                      >
                        <Trash2 size={12} />
                      </button>
                    </div>
                    <div className="ai-session-item-meta">
                      <span>{new Date(s.updated_at).toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' })}</span>
                      {s.pending_approval_count > 0 ? (
                        <span className="tag-chip amber" style={{ fontSize: 10.5, padding: '1px 6px' }}>
                          {s.pending_approval_count} 待授权
                        </span>
                      ) : (
                        <span>{s.message_count} 条记录</span>
                      )}
                    </div>
                  </div>
                ))
              )}
            </div>
          </aside>

          <section className="ai-chat-main">
            {/* Target Servers & 3-Tier HITL Execution Mode Bar */}
            <div className="ai-context-toolbar">
              <div className="ai-server-pills">
                <span style={{ fontSize: 12, color: 'var(--text-muted)', fontWeight: 560 }}>
                  诊断目标主机：
                </span>
                {servers.length === 0 ? (
                  <span style={{ fontSize: 12, color: 'var(--amber-text)' }}>
                    尚未添加服务器资产
                  </span>
                ) : (
                  <>
                    {servers.map((srv) => {
                      const sel = selectedServerIds.includes(srv.id);
                      return (
                        <button
                          key={srv.id}
                          type="button"
                          className={`ai-server-chip ${sel ? 'selected' : ''}`}
                          onClick={() => void toggleServerTarget(srv.id)}
                        >
                          <ServerIcon size={11.5} />
                          <span>{srv.name}</span>
                        </button>
                      );
                    })}
                    {servers.length > 1 && (
                      <button
                        type="button"
                        className="btn btn-ghost btn-sm"
                        style={{ height: 25, fontSize: 11.5 }}
                        onClick={() => {
                          const allIds =
                            selectedServerIds.length === servers.length
                              ? [servers[0].id]
                              : servers.map((s) => s.id);
                          setSelectedServerIds(allIds);
                        }}
                      >
                        {selectedServerIds.length === servers.length ? '仅选首台' : '全选集群'}
                      </button>
                    )}
                  </>
                )}
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>执行安全级别：</span>
                <div className="ai-mode-pill-group" role="radiogroup" aria-label="AI 执行权限模式">
                  <button
                    type="button"
                    className={`ai-mode-pill ${sessionMode === 'suggest' ? 'active' : ''}`}
                    onClick={() => void handleChangeMode('suggest')}
                    title="仅分析与生成命令方案，任何远程动作均需人工确认"
                  >
                    参谋模式
                  </button>
                  <button
                    type="button"
                    className={`ai-mode-pill ${sessionMode === 'standard' ? 'active' : ''}`}
                    onClick={() => void handleChangeMode('standard')}
                    title="推荐：只读探针自动采集，任何远程变更与配置写入均展示 Diff 等待审批"
                  >
                    <ShieldCheck size={12} style={{ color: 'var(--accent-teal)' }} />
                    标准受控
                  </button>
                  <button
                    type="button"
                    className={`ai-mode-pill autonomous ${sessionMode === 'autonomous' ? 'active' : ''}`}
                    onClick={() => void handleChangeMode('autonomous')}
                    title="自动执行排障与常规修复，但毁灭性命令 (rm -rf /、mkfs 等) 仍被底层硬拦截"
                  >
                    自治执行
                  </button>
                </div>
              </div>
            </div>

            {/* Conversation Stream */}
            <div className="ai-messages-scroll">
              {loading ? (
                <div className="empty-state">正在读取加密会话与排障上下文...</div>
              ) : !activeSession || activeSession.messages.length === 0 ? (
                <div className="empty-state" style={{ margin: 'auto' }}>
                  <div className="empty-state-icon">
                    <Bot size={22} style={{ color: 'var(--accent-teal)' }} />
                  </div>
                  <h3>原生加密 AI 运维排障助手已就绪</h3>
                  <p>
                    自动调用只读 SSH 探针与 SFTP 读取分析线上配置，遇到服务重启或配置文件修改时自动生成 Git Unified Diff 供您一键审批。
                  </p>
                  <div
                    style={{
                      display: 'grid',
                      gridTemplateColumns: 'repeat(2, minmax(0, 260px))',
                      gap: 10,
                      marginTop: 6,
                    }}
                  >
                    {QUICK_DIAGNOSTIC_PROMPTS.map((q) => (
                      <button
                        key={q.label}
                        type="button"
                        className="preset-card"
                        onClick={() => void handleSendMessage(q.prompt)}
                      >
                        <span style={{ fontWeight: 600, fontSize: 13, color: 'var(--text-primary)' }}>
                          {q.label}
                        </span>
                        <span style={{ fontSize: 11.5, color: 'var(--text-muted)', lineHeight: 1.4 }}>
                          {q.prompt.slice(0, 44)}...
                        </span>
                      </button>
                    ))}
                  </div>
                </div>
              ) : (
                <>
                  {activeSession.messages
                    .filter((m) => m.role === 'user' || m.role === 'assistant')
                    .map((msg) => {
                      if (msg.role === 'user') {
                        return (
                          <div key={msg.id} className="ai-msg-row user">
                            <div className="ai-msg-bubble">{msg.content}</div>
                          </div>
                        );
                      }
                      const linkedApprovals = (msg.tool_calls || [])
                        .map((tc) => approvalByToolCallId.get(tc.id))
                        .filter(Boolean);
                      const snippets = extractShellSnippets(msg.content || '');

                      return (
                        <div key={msg.id} className="ai-msg-row assistant">
                          {msg.tool_calls && msg.tool_calls.length > 0 && (
                            <div className="ai-tool-trace-list">
                              {msg.tool_calls.map((tc) => (
                                <ToolTraceStep key={tc.id} tool={tc} />
                              ))}
                            </div>
                          )}

                          {msg.content && (
                            <div className="ai-msg-bubble">
                              <FormattedMarkdownText text={msg.content} />
                            </div>
                          )}

                          {snippets.length > 0 && (
                            <ShellSnippetActionBar commands={snippets} onNotify={onNotify} />
                          )}

                          {linkedApprovals.map((ap) => (
                            <HITLApprovalCard
                              key={ap.id}
                              approval={ap}
                              busy={streaming}
                              onDecide={(id, ok) => void handleResolveApproval(id, ok)}
                            />
                          ))}
                        </div>
                      );
                    })}

                  {/* Render Runbook Proposals attached to this session */}
                  {(activeSession.runbook_proposals || []).map((prop) => (
                    <div key={prop.id} className="ai-msg-row assistant">
                      <RunbookProposalCard
                        proposal={prop}
                        busy={streaming}
                        onResolve={(id, accept, sync) => void handleResolveProposal(id, accept, sync)}
                      />
                    </div>
                  ))}

                  {/* Live Streaming Turn */}
                  {streaming && (
                    <div className="ai-msg-row assistant">
                      {streamTools.length > 0 && (
                        <div className="ai-tool-trace-list">
                          {streamTools.map((tc) => (
                            <ToolTraceStep key={tc.id} tool={tc} />
                          ))}
                        </div>
                      )}
                      <div className="ai-msg-bubble">
                        {streamDelta || '正在连接远程探针并推理诊断方案...'}
                      </div>
                    </div>
                  )}
                  <div ref={chatEndRef} />
                </>
              )}
            </div>

            {/* Bottom Prompt Composer */}
            <div className="ai-composer">
              <div className="ai-quick-prompts">
                {QUICK_DIAGNOSTIC_PROMPTS.map((q) => (
                  <button
                    key={q.label}
                    type="button"
                    className="ai-quick-prompt-btn"
                    disabled={streaming}
                    onClick={() => void handleSendMessage(q.prompt)}
                  >
                    {q.label}
                  </button>
                ))}
              </div>
              <form
                className="ai-composer-box"
                onSubmit={(e) => {
                  e.preventDefault();
                  void handleSendMessage();
                }}
              >
                <textarea
                  id="ai-center-prompt-input"
                  className="ai-composer-textarea"
                  rows={2}
                  placeholder="描述服务器故障现象、安全加固需求或配置检查目标（Enter 发送，Shift+Enter 换行）..."
                  value={promptInput}
                  onChange={(e) => setPromptInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && !e.shiftKey) {
                      e.preventDefault();
                      void handleSendMessage();
                    }
                  }}
                />
                <button
                  type="submit"
                  id="ai-center-send-btn"
                  className="btn btn-primary"
                  style={{ height: 44, padding: '0 18px' }}
                  disabled={streaming || !promptInput.trim()}
                >
                  <Send size={14} />
                  {streaming ? '诊断中...' : '发送指令'}
                </button>
              </form>
            </div>
          </section>
        </div>
      )}

      {/* TAB 2: Scheduled Background Patrol & Multi-Channel Webhook Alerts */}
      {subTab === 'patrol' && (
        <div className="page-body">
          <div className="patrol-status-banner">
            <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
              <div
                style={{
                  width: 42,
                  height: 42,
                  borderRadius: 10,
                  background: overview?.patrol_config.enabled
                    ? 'var(--accent-teal-soft)'
                    : 'var(--bg-muted)',
                  color: overview?.patrol_config.enabled
                    ? 'var(--accent-teal)'
                    : 'var(--text-muted)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
              >
                <Radar size={20} />
              </div>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <strong style={{ fontSize: 15 }}>
                    {overview?.patrol_config.enabled
                      ? `定时无人值守巡检已开启（每 ${overview.patrol_config.interval_minutes} 分钟）`
                      : '后台定时巡检当前未开启'}
                  </strong>
                  <span className="tag-chip teal">只读安全探针 · 零自动变更</span>
                </div>
                <div style={{ fontSize: 12.5, color: 'var(--text-muted)', marginTop: 2 }}>
                  前端界面锁定（Ctrl+Shift+L）后后台巡检与告警推送继续运行；仅在「彻底封存保险库」擦除内存密钥时停止。
                  {overview?.patrol_status.last_run_at && (
                    <span style={{ marginLeft: 10 }}>
                      上次巡检：{new Date(overview.patrol_status.last_run_at).toLocaleString('zh-CN')}
                    </span>
                  )}
                </div>
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <button
                type="button"
                className="btn"
                onClick={() => setShowPatrolConfigModal(true)}
              >
                <Sliders size={14} /> 巡检阈值与告警通道 ({overview?.patrol_config.webhooks?.length || 0})
              </button>
              <button
                type="button"
                id="ai-run-patrol-now-btn"
                className="btn btn-teal"
                disabled={runningPatrol}
                onClick={() => void handleRunPatrolNow()}
              >
                <Play size={14} />
                {runningPatrol ? '正在并发巡检并研判...' : '立即执行全量巡检'}
              </button>
            </div>
          </div>

          {!overview?.patrol_records?.length ? (
            <div className="empty-state">
              <div className="empty-state-icon">
                <Radar size={22} />
              </div>
              <h3>暂无历史安全巡检报告</h3>
              <p>
                点击右上角「立即执行全量巡检」即可对集群执行只读健康与入侵指标扫描（CPU/内存/磁盘、监听端口基线突变、SSH 爆破激增、UID=0 特权账号），并在发现异常时唤醒大模型输出根因报告。
              </p>
            </div>
          ) : (
            <div>
              {overview.patrol_records.map((rec) => (
                <article key={rec.id} className={`patrol-record-card ${rec.status}`}>
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      flexWrap: 'wrap',
                      gap: 10,
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      {rec.status === 'healthy' ? (
                        <CheckCircle2 size={16} style={{ color: 'var(--status-online)' }} />
                      ) : (
                        <AlertTriangle
                          size={16}
                          style={{
                            color:
                              rec.status === 'critical'
                                ? 'var(--danger-text)'
                                : 'var(--amber-text)',
                          }}
                        />
                      )}
                      <strong style={{ fontSize: 14 }}>
                        {rec.status === 'critical'
                          ? '严重安全 / 负载告警'
                          : rec.status === 'warning'
                          ? '潜在风险预警'
                          : '集群全量健康通过'}
                      </strong>
                      <span className="tag-chip">
                        {rec.trigger === 'scheduled' ? '后台定时触发' : '管理员手动触发'}
                      </span>
                      <span className="mono" style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                        {new Date(rec.completed_at).toLocaleString('zh-CN')}
                      </span>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                      <span style={{ fontSize: 12.5, color: 'var(--text-secondary)' }}>
                        共 {rec.total_servers} 台（正常 {rec.healthy_count} · 预警 {rec.warning_count} · 严重{' '}
                        {rec.critical_count}）
                      </span>
                      {rec.webhook_notified && (
                        <span className="tag-chip teal">
                          <Bell size={11} style={{ marginRight: 3 }} /> 已推送告警
                        </span>
                      )}
                      {rec.status !== 'healthy' && (
                        <button
                          type="button"
                          className="btn btn-sm"
                          onClick={() => void handleInvestigatePatrolRecord(rec)}
                        >
                          <ArrowUpRight size={13} /> 带入排障会话处置
                        </button>
                      )}
                    </div>
                  </div>

                  {/* Per-server Findings */}
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(290px, 1fr))', gap: 8 }}>
                    {rec.findings.map((f) => (
                      <div
                        key={f.server_id}
                        style={{
                          padding: '9px 12px',
                          borderRadius: 7,
                          background: 'var(--bg-subtle)',
                          border: '1px solid var(--border-subtle)',
                          fontSize: 12,
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', fontWeight: 600 }}>
                          <span>{f.server_name}</span>
                          <span className="mono" style={{ color: 'var(--text-muted)' }}>
                            {f.host}
                          </span>
                        </div>
                        {f.reachable && (
                          <div className="mono" style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
                            CPU负载 {f.cpu_load_percent ?? 0}% · 内存 {f.mem_percent ?? 0}% · 磁盘 {f.disk_percent ?? 0}% · 1h爆破{' '}
                            {f.ssh_fail_count_1h ?? 0}次
                          </div>
                        )}
                        {f.anomalies && f.anomalies.length > 0 ? (
                          <div style={{ color: 'var(--amber-text)', marginTop: 4, fontWeight: 550 }}>
                            {f.anomalies.join('；')}
                          </div>
                        ) : (
                          <div style={{ color: 'var(--status-online)', marginTop: 4 }}>各项指标与基线一致</div>
                        )}
                      </div>
                    ))}
                  </div>

                  {/* On-demand AI Root Cause Summary */}
                  {rec.ai_summary && (
                    <div
                      style={{
                        padding: '11px 14px',
                        borderRadius: 8,
                        background: 'var(--accent-teal-soft)',
                        border: '1px solid var(--accent-teal-border)',
                        fontSize: 12.5,
                      }}
                    >
                      <div style={{ fontWeight: 620, marginBottom: 4, color: 'var(--accent-teal)' }}>
                        AI 根因诊断摘要：{rec.ai_summary}
                      </div>
                      {rec.ai_root_cause && (
                        <div style={{ color: 'var(--text-secondary)', marginBottom: 6 }}>
                          {rec.ai_root_cause}
                        </div>
                      )}
                      {rec.ai_recommendations && rec.ai_recommendations.length > 0 && (
                        <ul style={{ margin: 0, paddingLeft: 18, color: 'var(--text-primary)' }}>
                          {rec.ai_recommendations.map((item, idx) => (
                            <li key={idx}>{item}</li>
                          ))}
                        </ul>
                      )}
                    </div>
                  )}
                </article>
              ))}
            </div>
          )}
        </div>
      )}

      {/* TAB 3: Hybrid Host Memories & Troubleshooting Runbooks */}
      {subTab === 'memory' && (
        <div className="page-body">
          <div className="security-grid">
            {/* Left Column: Per-Server Objective Environment Memories */}
            <section className="sec-panel">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                <h3>
                  <BrainCircuit size={16} style={{ color: 'var(--accent-teal)' }} />
                  主机环境画像记忆 ({overview?.host_memories?.length || 0})
                </h3>
                {servers.length > 0 && (
                  <button
                    type="button"
                    className="btn btn-sm"
                    onClick={() =>
                      setEditingMemory({
                        server_id: servers[0].id,
                        summary: '',
                        os_arch: '',
                        key_services_csv: '',
                        deploy_paths_csv: '',
                        ports_note: '',
                        notes: '',
                      })
                    }
                  >
                    <Plus size={13} /> 手工录入画像
                  </button>
                )}
              </div>
              <p className="sec-panel-desc">
                AI 在排障过程中自动增量归档每台服务器的发行版、核心服务与配置路径，下次会话零重复探测。全部加密存储于 vault.sns。
              </p>

              {!overview?.host_memories?.length ? (
                <div style={{ padding: '28px 12px', textAlign: 'center', color: 'var(--text-muted)', fontSize: 12.5 }}>
                  暂无主机记忆，发起一次「全面安全基线体检」后 AI 将自动建立画像
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                  {overview.host_memories.map((m: HostMemory) => (
                    <div
                      key={m.server_id}
                      style={{
                        padding: '12px 14px',
                        borderRadius: 8,
                        border: '1px solid var(--border-default)',
                        background: 'var(--bg-subtle)',
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <strong>{m.server_name}</strong>
                          {m.os_arch && <span className="tag-chip">{m.os_arch}</span>}
                          {m.auto_updated_count > 0 && (
                            <span className="tag-chip teal">AI 自学习 {m.auto_updated_count} 次</span>
                          )}
                        </div>
                        <div style={{ display: 'flex', gap: 4 }}>
                          <button
                            type="button"
                            className="btn btn-ghost btn-sm btn-icon"
                            onClick={() =>
                              setEditingMemory({
                                server_id: m.server_id,
                                summary: m.summary,
                                os_arch: m.os_arch || '',
                                key_services_csv: (m.key_services || []).join(', '),
                                deploy_paths_csv: (m.deploy_paths || []).join(', '),
                                ports_note: m.ports_note || '',
                                notes: m.notes || '',
                              })
                            }
                            title="编辑主机记忆"
                          >
                            <Edit3 size={13.5} />
                          </button>
                          <button
                            type="button"
                            className="btn btn-ghost btn-sm btn-icon"
                            style={{ color: 'var(--danger-text)' }}
                            onClick={async () => {
                              await api.deleteHostMemory(m.server_id);
                              onNotify('已清空该主机环境画像');
                              await loadOverview(activeSessionId);
                            }}
                            title="清空记忆"
                          >
                            <Trash2 size={13.5} />
                          </button>
                        </div>
                      </div>
                      <div style={{ fontSize: 12.5, marginTop: 6, color: 'var(--text-secondary)' }}>
                        {m.summary}
                      </div>
                      {(m.key_services?.length > 0 || m.deploy_paths?.length > 0) && (
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5, marginTop: 8 }}>
                          {(m.key_services || []).map((svc) => (
                            <span key={svc} className="tag-chip teal">
                              {svc}
                            </span>
                          ))}
                          {(m.deploy_paths || []).map((dp) => (
                            <span key={dp} className="tag-chip mono">
                              {dp}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </section>

            {/* Right Column: Troubleshooting Runbooks (Hermes-inspired Skill Library) */}
            <section className="sec-panel">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                <h3>
                  <BookOpen size={16} style={{ color: 'var(--accent-teal)' }} />
                  排障技能 Runbook 库 ({overview?.runbooks?.length || 0})
                </h3>
                <button
                  type="button"
                  className="btn btn-sm"
                  onClick={() =>
                    setEditingRunbook({
                      title: '',
                      category: '安全加固',
                      symptom: '',
                      root_cause: '',
                      diagnostic_steps_text: '',
                      fix_commands_text: '',
                      verification: '',
                      sync_snippet: true,
                    })
                  }
                >
                  <Plus size={13} /> 新建 Runbook
                </button>
              </div>
              <p className="sec-panel-desc">
                复杂故障解决后由 AI 提炼草案并经管理员确认入库，AI 对话将自动检索匹配相关 SOP 技能，亦可一键同步至快捷指令。
              </p>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {(overview?.runbooks || []).map((rb) => (
                  <div
                    key={rb.id}
                    style={{
                      padding: '12px 14px',
                      borderRadius: 8,
                      border: '1px solid var(--border-default)',
                      background: 'var(--bg-subtle)',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 7, flexWrap: 'wrap' }}>
                        <strong>{rb.title}</strong>
                        <span className="tag-chip teal">{rb.category}</span>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                        <button
                          type="button"
                          className="btn btn-sm"
                          style={{ height: 25, fontSize: 11.5 }}
                          onClick={() => void launchRunbookDiagnosis(rb)}
                        >
                          <Play size={11} /> 发起排障
                        </button>
                        <button
                          type="button"
                          className="btn btn-ghost btn-sm btn-icon"
                          onClick={() =>
                            setEditingRunbook({
                              id: rb.id,
                              title: rb.title,
                              category: rb.category,
                              symptom: rb.symptom,
                              root_cause: rb.root_cause,
                              diagnostic_steps_text: (rb.diagnostic_steps || []).join('\n'),
                              fix_commands_text: (rb.fix_commands || []).join('\n'),
                              verification: rb.verification || '',
                              sync_snippet: Boolean(rb.linked_snippet_id),
                            })
                          }
                        >
                          <Edit3 size={13.5} />
                        </button>
                        <button
                          type="button"
                          className="btn btn-ghost btn-sm btn-icon"
                          style={{ color: 'var(--danger-text)' }}
                          onClick={async () => {
                            await api.deleteRunbook(rb.id);
                            onNotify('已删除该 Runbook');
                            await loadOverview(activeSessionId);
                          }}
                        >
                          <Trash2 size={13.5} />
                        </button>
                      </div>
                    </div>
                    <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 6 }}>
                      <strong>适用症状：</strong>
                      {rb.symptom}
                    </div>
                    {rb.fix_commands?.length > 0 && (
                      <div className="copilot-cmd-box" style={{ marginTop: 8 }}>
                        <code style={{ whiteSpace: 'pre-wrap' }}>{rb.fix_commands.join(' && ')}</code>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </section>
          </div>
        </div>
      )}

      {/* TAB 4: LLM Provider & Gateway Configuration */}
      {subTab === 'providers' && (
        <div className="page-body">
          <div style={{ marginBottom: 10, fontWeight: 620, fontSize: 13.5 }}>
            一键填入主流云厂商 / 本地私有模型预设
          </div>
          <div className="preset-grid">
            {(overview?.presets || []).map((preset) => (
              <button
                key={preset.id}
                type="button"
                className="preset-card"
                onClick={() => applyPreset(preset)}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', width: '100%' }}>
                  <strong style={{ fontSize: 13.5, color: 'var(--text-primary)' }}>{preset.name}</strong>
                  <span className="tag-chip mono" style={{ fontSize: 10.5 }}>
                    {preset.protocol === 'anthropic' ? 'Anthropic 原生' : 'OpenAI 兼容'}
                  </span>
                </div>
                <span className="mono" style={{ fontSize: 11.5, color: 'var(--accent-teal)' }}>
                  默认模型: {preset.default_model}
                </span>
                <span style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>{preset.description}</span>
              </button>
            ))}
          </div>

          <div className="security-grid">
            {/* Provider Form */}
            <section className="sec-panel">
              <h3>
                <KeyRound size={16} style={{ color: 'var(--accent-teal)' }} />
                {provForm.id ? '编辑已保存的大模型配置' : '接入新大模型供应商'}
              </h3>
              <p className="sec-panel-desc">
                API Key 写入时直接进入加密保险库（XChaCha20-Poly1305），界面与日志永不回显明文。
              </p>

              {testResultBanner && (
                <div
                  className={`alert ${testResultBanner.ok ? '' : 'alert-error'}`}
                  style={
                    testResultBanner.ok
                      ? {
                          background: 'var(--accent-teal-soft)',
                          border: '1px solid var(--accent-teal-border)',
                          color: 'var(--accent-teal)',
                          marginBottom: 12,
                        }
                      : { marginBottom: 12 }
                  }
                >
                  <span>{testResultBanner.text}</span>
                </div>
              )}

              <form onSubmit={handleSaveProvider}>
                <div className="field-row">
                  <div className="field">
                    <label className="field-label">配置显示名称</label>
                    <input
                      className="input"
                      value={provForm.name}
                      onChange={(e) => setProvForm({ ...provForm, name: e.target.value })}
                      placeholder="例如：生产 DeepSeek 专线"
                      required
                    />
                  </div>
                  <div className="field">
                    <label className="field-label">接口通信协议</label>
                    <select
                      className="select"
                      value={provForm.protocol}
                      onChange={(e) =>
                        setProvForm({ ...provForm, protocol: e.target.value as AIProtocol })
                      }
                    >
                      <option value="openai">OpenAI Chat Completions 兼容 (/v1/chat/completions)</option>
                      <option value="anthropic">Anthropic Messages 原生 (/v1/messages)</option>
                    </select>
                  </div>
                </div>

                <div className="field">
                  <label className="field-label">API Base URL</label>
                  <input
                    className="input mono"
                    value={provForm.base_url}
                    onChange={(e) => setProvForm({ ...provForm, base_url: e.target.value })}
                    placeholder="https://api.deepseek.com/v1 或 http://127.0.0.1:11434/v1"
                    required
                  />
                </div>

                <div className="field-row">
                  <div className="field">
                    <label className="field-label">模型标识 (Model ID)</label>
                    <input
                      className="input mono"
                      value={provForm.model}
                      onChange={(e) => setProvForm({ ...provForm, model: e.target.value })}
                      placeholder="deepseek-chat / claude-sonnet-4-5 / qwen-max"
                      required
                    />
                  </div>
                  <div className="field">
                    <label className="field-label">单轮最大输出 Tokens</label>
                    <input
                      type="number"
                      className="input mono"
                      min={256}
                      max={32768}
                      value={provForm.max_tokens}
                      onChange={(e) =>
                        setProvForm({ ...provForm, max_tokens: Number(e.target.value) || 4096 })
                      }
                    />
                  </div>
                </div>

                <div className="field">
                  <label className="field-label">
                    API Key 密钥 {provForm.id ? '（留空则保留原加密密钥不变）' : '（本地 Ollama 可留空）'}
                  </label>
                  <input
                    type="password"
                    className="input mono"
                    value={provForm.api_key}
                    onChange={(e) => setProvForm({ ...provForm, api_key: e.target.value })}
                    placeholder={provForm.id ? '已加密存储，如需更换请输入新密钥' : 'sk-...'}
                    autoComplete="off"
                  />
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 8 }}>
                  <button type="submit" className="btn btn-primary">
                    {provForm.id ? '更新模型配置' : '加密保存并设为激活'}
                  </button>
                  <button
                    type="button"
                    className="btn"
                    disabled={testingProvId === '__form__'}
                    onClick={() => void handleTestProvider()}
                  >
                    <RefreshCw size={13.5} />
                    {testingProvId === '__form__' ? '正在握手自检...' : '测试连接延迟'}
                  </button>
                  {provForm.id && (
                    <button
                      type="button"
                      className="btn btn-ghost"
                      onClick={() =>
                        setProvForm({
                          id: '',
                          name: '',
                          protocol: 'openai',
                          base_url: '',
                          api_key: '',
                          model: '',
                          max_tokens: 4096,
                          set_active: true,
                        })
                      }
                    >
                      取消编辑
                    </button>
                  )}
                </div>
              </form>
            </section>

            {/* Saved Providers & Global Active Selector */}
            <section className="sec-panel">
              <h3>
                <Cpu size={16} />
                已加密保存的模型列表 ({overview?.providers?.length || 0})
              </h3>
              <p className="sec-panel-desc">
                采用单全局激活模型路由：排障对话、终端副驾驶与后台异常研判统一调用当前激活模型。
              </p>

              {!overview?.providers?.length ? (
                <div style={{ padding: '32px 12px', textAlign: 'center', color: 'var(--text-muted)', fontSize: 12.5 }}>
                  暂未保存任何大模型供应商，可点击上方预设卡片快速配置
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                  {overview.providers.map((p) => {
                    const isActive = overview.active_provider_id === p.id;
                    return (
                      <div
                        key={p.id}
                        style={{
                          padding: '12px 14px',
                          borderRadius: 8,
                          border: `1px solid ${
                            isActive ? 'var(--accent-teal-border)' : 'var(--border-default)'
                          }`,
                          background: isActive ? 'var(--accent-teal-soft)' : 'var(--bg-subtle)',
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8 }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 7, flexWrap: 'wrap' }}>
                            <strong>{p.name}</strong>
                            <span className="tag-chip mono">{p.model}</span>
                            {isActive && <span className="tag-chip teal">当前全局激活</span>}
                          </div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                            {!isActive && (
                              <button
                                type="button"
                                className="btn btn-teal btn-sm"
                                onClick={async () => {
                                  await api.setActiveAIProvider(p.id);
                                  onNotify(`已切换全局激活模型为 ${p.name}`);
                                  await loadOverview(activeSessionId);
                                }}
                              >
                                设为激活
                              </button>
                            )}
                            <button
                              type="button"
                              className="btn btn-sm"
                              disabled={testingProvId === p.id}
                              onClick={() => void handleTestProvider(p)}
                            >
                              {testingProvId === p.id ? '测试中...' : '测速'}
                            </button>
                            <button
                              type="button"
                              className="btn btn-ghost btn-sm btn-icon"
                              onClick={() => editExistingProvider(p)}
                              title="编辑配置"
                            >
                              <Edit3 size={13.5} />
                            </button>
                            <button
                              type="button"
                              className="btn btn-ghost btn-sm btn-icon"
                              style={{ color: 'var(--danger-text)' }}
                              onClick={async () => {
                                await api.deleteAIProvider(p.id);
                                onNotify('已删除模型供应商配置');
                                await loadOverview(activeSessionId);
                              }}
                              title="删除"
                            >
                              <Trash2 size={13.5} />
                            </button>
                          </div>
                        </div>
                        <div
                          className="mono"
                          style={{
                            fontSize: 11.5,
                            color: 'var(--text-muted)',
                            marginTop: 6,
                            display: 'flex',
                            justifyContent: 'space-between',
                          }}
                        >
                          <span>
                            [{p.protocol}] {p.base_url}
                          </span>
                          <span>密钥: {p.has_api_key ? p.api_key_preview : '未设置(免密本地)'}</span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </section>
          </div>
        </div>
      )}

      {/* Modal: Patrol & Multi-Channel Webhook Config */}
      {showPatrolConfigModal && (
        <div className="modal-backdrop" onClick={() => setShowPatrolConfigModal(false)}>
          <div className="modal-panel wide" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>后台定时巡检策略与外部告警 Webhook</h3>
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                onClick={() => setShowPatrolConfigModal(false)}
              >
                关闭
              </button>
            </div>
            <form onSubmit={handleSavePatrolConfig}>
              <div className="modal-body">
                <div className="field-row">
                  <div className="field">
                    <label className="field-label">定时自动巡检状态</label>
                    <select
                      className="select"
                      value={patrolEnabled ? '1' : '0'}
                      onChange={(e) => setPatrolEnabled(e.target.value === '1')}
                    >
                      <option value="1">启用后台定时只读安全巡检</option>
                      <option value="0">暂停定时自动巡检（仍可手动执行）</option>
                    </select>
                  </div>
                  <div className="field">
                    <label className="field-label">巡检执行周期</label>
                    <select
                      className="select"
                      value={patrolInterval}
                      onChange={(e) => setPatrolInterval(Number(e.target.value))}
                    >
                      <option value={5}>每 5 分钟（高频值守）</option>
                      <option value={15}>每 15 分钟</option>
                      <option value={30}>每 30 分钟</option>
                      <option value={60}>每 60 分钟（推荐）</option>
                      <option value={180}>每 3 小时</option>
                      <option value={720}>每 12 小时</option>
                    </select>
                  </div>
                </div>

                <div className="field-row">
                  <div className="field">
                    <label className="field-label">CPU 负载预警阈值 (%)</label>
                    <input
                      type="number"
                      className="input mono"
                      value={cpuWarn}
                      onChange={(e) => setCpuWarn(Number(e.target.value) || 85)}
                    />
                  </div>
                  <div className="field">
                    <label className="field-label">内存使用预警阈值 (%)</label>
                    <input
                      type="number"
                      className="input mono"
                      value={memWarn}
                      onChange={(e) => setMemWarn(Number(e.target.value) || 85)}
                    />
                  </div>
                </div>

                <div className="field-row">
                  <div className="field">
                    <label className="field-label">根分区磁盘预警阈值 (%)</label>
                    <input
                      type="number"
                      className="input mono"
                      value={diskWarn}
                      onChange={(e) => setDiskWarn(Number(e.target.value) || 85)}
                    />
                  </div>
                  <div className="field">
                    <label className="field-label">1 小时内 SSH 失败登录告警次数</label>
                    <input
                      type="number"
                      className="input mono"
                      value={sshFailWarn}
                      onChange={(e) => setSshFailWarn(Number(e.target.value) || 15)}
                    />
                  </div>
                </div>

                <div style={{ display: 'flex', gap: 18, margin: '8px 0 16px' }}>
                  <label style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 13 }}>
                    <input
                      type="checkbox"
                      checked={checkPorts}
                      onChange={(e) => setCheckPorts(e.target.checked)}
                    />
                    对比基线检测新开放监听端口
                  </label>
                  <label style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 13 }}>
                    <input
                      type="checkbox"
                      checked={checkPrivUsers}
                      onChange={(e) => setCheckPrivUsers(e.target.checked)}
                    />
                    审计非 root 的 UID=0 隐藏特权账号
                  </label>
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                  <strong>外部告警 Webhook 通道（飞书 / 钉钉 / 企微 / 自定义签名）</strong>
                  <button
                    type="button"
                    className="btn btn-sm"
                    onClick={() =>
                      setWebhookDrafts((prev) => [
                        ...prev,
                        {
                          id: '',
                          name: '运维告警群',
                          kind: 'feishu',
                          url: '',
                          secret: '',
                          enabled: true,
                        },
                      ])
                    }
                  >
                    <Plus size={13} /> 添加告警通道
                  </button>
                </div>

                {webhookDrafts.map((wh, idx) => (
                  <div
                    key={idx}
                    style={{
                      padding: 12,
                      borderRadius: 8,
                      border: '1px solid var(--border-default)',
                      background: 'var(--bg-subtle)',
                      marginBottom: 8,
                    }}
                  >
                    <div className="field-row">
                      <div className="field">
                        <label className="field-label">通道名称</label>
                        <input
                          className="input"
                          value={wh.name}
                          onChange={(e) => {
                            const cp = [...webhookDrafts];
                            cp[idx] = { ...wh, name: e.target.value };
                            setWebhookDrafts(cp);
                          }}
                        />
                      </div>
                      <div className="field">
                        <label className="field-label">平台类型</label>
                        <select
                          className="select"
                          value={wh.kind}
                          onChange={(e) => {
                            const cp = [...webhookDrafts];
                            cp[idx] = { ...wh, kind: e.target.value as WebhookDraft['kind'] };
                            setWebhookDrafts(cp);
                          }}
                        >
                          <option value="feishu">飞书群机器人 (Feishu Card)</option>
                          <option value="dingtalk">钉钉群机器人 (DingTalk HMAC)</option>
                          <option value="wecom">企业微信群机器人 (WeCom Markdown)</option>
                          <option value="custom">自定义 JSON Webhook (X-SNS-Signature)</option>
                        </select>
                      </div>
                    </div>
                    <div className="field-row">
                      <div className="field">
                        <label className="field-label">
                          Webhook URL {wh.urlMasked ? `（已保存 ${wh.urlMasked}，留空保留）` : ''}
                        </label>
                        <input
                          className="input mono"
                          value={wh.url}
                          placeholder={wh.urlMasked || 'https://open.feishu.cn/open-apis/bot/v2/hook/...'}
                          onChange={(e) => {
                            const cp = [...webhookDrafts];
                            cp[idx] = { ...wh, url: e.target.value };
                            setWebhookDrafts(cp);
                          }}
                        />
                      </div>
                      <div className="field">
                        <label className="field-label">
                          加签密钥 Secret（可选{wh.hasSecret ? ' · 已加密保存' : ''}）
                        </label>
                        <input
                          type="password"
                          className="input mono"
                          value={wh.secret}
                          placeholder={wh.hasSecret ? '留空保留原加签密钥' : '可选签名密钥'}
                          onChange={(e) => {
                            const cp = [...webhookDrafts];
                            cp[idx] = { ...wh, secret: e.target.value };
                            setWebhookDrafts(cp);
                          }}
                        />
                      </div>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <label style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 12.5 }}>
                        <input
                          type="checkbox"
                          checked={wh.enabled}
                          onChange={(e) => {
                            const cp = [...webhookDrafts];
                            cp[idx] = { ...wh, enabled: e.target.checked };
                            setWebhookDrafts(cp);
                          }}
                        />
                        启用此通道推送
                      </label>
                      <div style={{ display: 'flex', gap: 6 }}>
                        <button
                          type="button"
                          className="btn btn-sm"
                          disabled={testingWebhookIdx === idx}
                          onClick={async () => {
                            setTestingWebhookIdx(idx);
                            try {
                              await api.testWebhook({
                                id: wh.id || undefined,
                                name: wh.name,
                                kind: wh.kind,
                                url: wh.url || undefined,
                                secret: wh.secret || undefined,
                              });
                              onNotify('测试告警已成功投递至该 Webhook 通道');
                            } catch (err: any) {
                              onNotify(err?.message || 'Webhook 测试投递失败');
                            } finally {
                              setTestingWebhookIdx(null);
                            }
                          }}
                        >
                          {testingWebhookIdx === idx ? '发送中...' : '发送测试通知'}
                        </button>
                        <button
                          type="button"
                          className="btn btn-ghost btn-sm"
                          style={{ color: 'var(--danger-text)' }}
                          onClick={() =>
                            setWebhookDrafts((prev) => prev.filter((_, i) => i !== idx))
                          }
                        >
                          移除
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
              <div className="modal-footer">
                <button
                  type="button"
                  className="btn"
                  onClick={() => setShowPatrolConfigModal(false)}
                >
                  取消
                </button>
                <button type="submit" className="btn btn-primary">
                  加密保存巡检与告警配置
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: Edit Host Memory */}
      {editingMemory && (
        <div className="modal-backdrop" onClick={() => setEditingMemory(null)}>
          <div className="modal-panel" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>维护主机客观环境画像记忆</h3>
              <button type="button" className="btn btn-ghost btn-sm" onClick={() => setEditingMemory(null)}>
                关闭
              </button>
            </div>
            <form onSubmit={handleSaveMemoryModal}>
              <div className="modal-body">
                <div className="field">
                  <label className="field-label">目标服务器</label>
                  <select
                    className="select"
                    value={editingMemory.server_id}
                    onChange={(e) =>
                      setEditingMemory({ ...editingMemory, server_id: e.target.value })
                    }
                  >
                    {servers.map((s) => (
                      <option key={s.id} value={s.id}>
                        {s.name} ({s.host})
                      </option>
                    ))}
                  </select>
                </div>
                <div className="field">
                  <label className="field-label">业务角色与职责摘要</label>
                  <input
                    className="input"
                    value={editingMemory.summary}
                    onChange={(e) =>
                      setEditingMemory({ ...editingMemory, summary: e.target.value })
                    }
                    placeholder="例如：生产核心 Nginx 反向代理网关 + Docker 业务节点"
                    required
                  />
                </div>
                <div className="field">
                  <label className="field-label">系统发行版与内核架构</label>
                  <input
                    className="input mono"
                    value={editingMemory.os_arch}
                    onChange={(e) =>
                      setEditingMemory({ ...editingMemory, os_arch: e.target.value })
                    }
                    placeholder="Debian 12 / Linux 6.1 x86_64"
                  />
                </div>
                <div className="field">
                  <label className="field-label">核心服务组件（逗号分隔）</label>
                  <input
                    className="input mono"
                    value={editingMemory.key_services_csv}
                    onChange={(e) =>
                      setEditingMemory({ ...editingMemory, key_services_csv: e.target.value })
                    }
                    placeholder="nginx, postgresql, redis, docker"
                  />
                </div>
                <div className="field">
                  <label className="field-label">关键配置与业务部署路径（逗号分隔）</label>
                  <input
                    className="input mono"
                    value={editingMemory.deploy_paths_csv}
                    onChange={(e) =>
                      setEditingMemory({ ...editingMemory, deploy_paths_csv: e.target.value })
                    }
                    placeholder="/etc/nginx/conf.d, /srv/app, /var/log/nginx"
                  />
                </div>
              </div>
              <div className="modal-footer">
                <button type="button" className="btn" onClick={() => setEditingMemory(null)}>
                  取消
                </button>
                <button type="submit" className="btn btn-primary">
                  加密保存主机画像
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: Create/Edit Runbook */}
      {editingRunbook && (
        <div className="modal-backdrop" onClick={() => setEditingRunbook(null)}>
          <div className="modal-panel wide" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>{editingRunbook.id ? '编辑排障技能 Runbook' : '新建排障技能 Runbook'}</h3>
              <button type="button" className="btn btn-ghost btn-sm" onClick={() => setEditingRunbook(null)}>
                关闭
              </button>
            </div>
            <form onSubmit={handleSaveRunbookModal}>
              <div className="modal-body">
                <div className="field-row">
                  <div className="field">
                    <label className="field-label">技能标题</label>
                    <input
                      className="input"
                      value={editingRunbook.title}
                      onChange={(e) =>
                        setEditingRunbook({ ...editingRunbook, title: e.target.value })
                      }
                      required
                    />
                  </div>
                  <div className="field">
                    <label className="field-label">所属分类</label>
                    <input
                      className="input"
                      value={editingRunbook.category}
                      onChange={(e) =>
                        setEditingRunbook({ ...editingRunbook, category: e.target.value })
                      }
                    />
                  </div>
                </div>
                <div className="field">
                  <label className="field-label">适用故障症状</label>
                  <input
                    className="input"
                    value={editingRunbook.symptom}
                    onChange={(e) =>
                      setEditingRunbook({ ...editingRunbook, symptom: e.target.value })
                    }
                    required
                  />
                </div>
                <div className="field">
                  <label className="field-label">典型根因说明</label>
                  <input
                    className="input"
                    value={editingRunbook.root_cause}
                    onChange={(e) =>
                      setEditingRunbook({ ...editingRunbook, root_cause: e.target.value })
                    }
                  />
                </div>
                <div className="field">
                  <label className="field-label">只读诊断步骤（每行一条命令或说明）</label>
                  <textarea
                    className="input mono"
                    rows={3}
                    style={{ height: 'auto', padding: 10 }}
                    value={editingRunbook.diagnostic_steps_text}
                    onChange={(e) =>
                      setEditingRunbook({
                        ...editingRunbook,
                        diagnostic_steps_text: e.target.value,
                      })
                    }
                  />
                </div>
                <div className="field">
                  <label className="field-label">推荐处置命令（每行一条命令）</label>
                  <textarea
                    className="input mono"
                    rows={3}
                    style={{ height: 'auto', padding: 10 }}
                    value={editingRunbook.fix_commands_text}
                    onChange={(e) =>
                      setEditingRunbook({
                        ...editingRunbook,
                        fix_commands_text: e.target.value,
                      })
                    }
                  />
                </div>
                <label style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 13 }}>
                  <input
                    type="checkbox"
                    checked={editingRunbook.sync_snippet}
                    onChange={(e) =>
                      setEditingRunbook({ ...editingRunbook, sync_snippet: e.target.checked })
                    }
                  />
                  同时将该技能的推荐处置命令同步至「快捷指令」库
                </label>
              </div>
              <div className="modal-footer">
                <button type="button" className="btn" onClick={() => setEditingRunbook(null)}>
                  取消
                </button>
                <button type="submit" className="btn btn-primary">
                  加密保存 Runbook
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

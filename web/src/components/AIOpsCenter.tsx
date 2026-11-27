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
  Server as ServerIcon,
  Bell,
  ArrowUpRight,
  MessageSquare,
  X,
  Layers,
  Minimize2,
  PlugZap,
  Clock,
  Square,
} from 'lucide-react';
import { api } from '../api';
import type {
  AIChatSession,
  AIChatSessionSummary,
  AIExecutionMode,
  AIOverviewResponse,
  AIRunbook,
  AIToolCallRecord,
  PatrolAnalysisMode,
  PatrolRecord,
  ServerView,
  SessionContextInspection,
} from '../types';
import {
  AgentsMDProposalCard,
  CompactionDivider,
  ContextInspectorModal,
  FormattedMarkdownText,
  HITLApprovalCard,
  MessageUsagePill,
  ReasoningTraceBlock,
  RunbookProposalCard,
  ShellSnippetActionBar,
  ToolTraceStep,
  extractShellSnippets,
} from './AIMessageWidgets';
import { AIMemoryAgentsTab, type MemorySubSection } from './AIMemoryAgentsTab';
import { ExternalAIMCPTab } from './ExternalAIMCPTab';
import { AIProviderConfigTab } from './AIProviderConfigTab';

export type CenterTab = 'diagnosis' | 'patrol' | 'mcp' | 'memory' | 'providers';

export interface AIDiagnosisDraft {
  serverId: string;
  prompt: string;
  nonce: number;
}

interface AIOpsCenterProps {
  servers: ServerView[];
  initialTab?: CenterTab;
  initialMemorySection?: MemorySubSection;
  initialDraft?: AIDiagnosisDraft | null;
  onConsumeInitialTab?: () => void;
  onConsumeInitialDraft?: () => void;
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
  initialTab,
  initialMemorySection,
  initialDraft,
  onConsumeInitialTab,
  onConsumeInitialDraft,
  onRefreshWorkspace,
  onBadgeChange,
  onNotify,
}) => {
  const [subTab, setSubTab] = useState<CenterTab>(initialTab || 'diagnosis');
  const [memorySubSection, setMemorySubSection] = useState<MemorySubSection>(
    initialMemorySection || 'agents_md'
  );
  const [overview, setOverview] = useState<AIOverviewResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [mobileSessionsOpen, setMobileSessionsOpen] = useState(false);

  // Active Chat Session State
  const [activeSessionId, setActiveSessionId] = useState<string>('');
  const [activeSession, setActiveSession] = useState<AIChatSession | null>(null);
  const [selectedServerIds, setSelectedServerIds] = useState<string[]>(
    initialDraft?.serverId ? [initialDraft.serverId] : []
  );
  const [sessionMode, setSessionMode] = useState<AIExecutionMode>('standard');
  const [promptInput, setPromptInput] = useState(initialDraft?.prompt || '');
  const [streaming, setStreaming] = useState(false);
  const [pendingUserMessage, setPendingUserMessage] = useState('');
  const [streamDelta, setStreamDelta] = useState('');
  const [streamReasoning, setStreamReasoning] = useState('');
  const [streamTools, setStreamTools] = useState<AIToolCallRecord[]>([]);
  const chatEndRef = useRef<HTMLDivElement | null>(null);
  const streamAbortRef = useRef<AbortController | null>(null);
  const preferBlankDraftRef = useRef<boolean>(Boolean(initialDraft));
  const consumedDraftNonceRef = useRef<number>(0);

  useEffect(() => {
    if (initialTab) {
      setSubTab(initialTab);
      if (initialMemorySection) {
        setMemorySubSection(initialMemorySection);
      }
      onConsumeInitialTab?.();
    }
  }, [initialTab, initialMemorySection, onConsumeInitialTab]);

  useEffect(() => {
    if (initialDraft && consumedDraftNonceRef.current !== initialDraft.nonce) {
      consumedDraftNonceRef.current = initialDraft.nonce;
      preferBlankDraftRef.current = true;
      setSubTab('diagnosis');
      setActiveSessionId('');
      setActiveSession(null);
      if (initialDraft.serverId) {
        setSelectedServerIds([initialDraft.serverId]);
      }
      setPromptInput(initialDraft.prompt);
      onConsumeInitialDraft?.();
    }
  }, [initialDraft, onConsumeInitialDraft]);

  useEffect(() => {
    return () => {
      streamAbortRef.current?.abort();
      streamAbortRef.current = null;
    };
  }, []);

  // Context Inspector & Rolling Compaction State
  const [contextInspection, setContextInspection] = useState<SessionContextInspection | null>(null);
  const [showContextInspector, setShowContextInspector] = useState(false);
  const [loadingContext, setLoadingContext] = useState(false);
  const [compactingContext, setCompactingContext] = useState(false);

  // Patrol Config & Execution State
  const [runningPatrol, setRunningPatrol] = useState(false);
  const [showPatrolConfigModal, setShowPatrolConfigModal] = useState(false);
  const [patrolEnabled, setPatrolEnabled] = useState(false);
  const [patrolInterval, setPatrolInterval] = useState(60);
  const [patrolServerIds, setPatrolServerIds] = useState<string[]>([]);
  const [cpuWarnStr, setCpuWarnStr] = useState('85');
  const [memWarnStr, setMemWarnStr] = useState('85');
  const [diskWarnStr, setDiskWarnStr] = useState('85');
  const [sshFailWarnStr, setSshFailWarnStr] = useState('15');
  const [checkPorts, setCheckPorts] = useState(true);
  const [checkPrivUsers, setCheckPrivUsers] = useState(true);
  const [patrolAnalysisMode, setPatrolAnalysisMode] = useState<PatrolAnalysisMode>('builtin');
  const [patrolFallbackStr, setPatrolFallbackStr] = useState('15');
  const [notifyPendingApprovals, setNotifyPendingApprovals] = useState(true);
  const [webhookDrafts, setWebhookDrafts] = useState<WebhookDraft[]>([]);
  const [testingWebhookIdx, setTestingWebhookIdx] = useState<number | null>(null);
  const [switchingProvider, setSwitchingProvider] = useState(false);

  const syncPatrolDraftFromOverview = useCallback((ov: AIOverviewResponse) => {
    const pc = ov.patrol_config;
    setPatrolEnabled(pc.enabled);
    setPatrolInterval(pc.interval_minutes || 60);
    setPatrolServerIds(pc.server_ids || []);
    setCpuWarnStr(String(pc.cpu_warn_percent || 85));
    setMemWarnStr(String(pc.mem_warn_percent || 85));
    setDiskWarnStr(String(pc.disk_warn_percent || 85));
    setSshFailWarnStr(String(pc.ssh_fail_warn_count || 15));
    setCheckPorts(pc.check_listening_ports);
    setCheckPrivUsers(pc.check_privileged_users);
    setPatrolAnalysisMode(pc.analysis_mode || 'builtin');
    setPatrolFallbackStr(String(pc.external_fallback_minutes || 15));
    setNotifyPendingApprovals(pc.notify_pending_approvals ?? true);
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

  useEffect(() => {
    if (!showPatrolConfigModal) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setShowPatrolConfigModal(false);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [showPatrolConfigModal]);

  const loadOverview = useCallback(
    async (preferSessionId?: string | null) => {
      try {
        const ov = await api.getAIOverview('center');
        setOverview(ov);
        syncPatrolDraftFromOverview(ov);

        const pendingApprovalsCount = (ov.sessions || []).reduce(
          (acc, s) => acc + (s.pending_approval_count || 0),
          0
        );
        const pendingExtApprovals = ov.pending_external_approvals || 0;
        onBadgeChange?.(
          (ov.patrol_status?.unread_alerts || 0) + pendingApprovalsCount + pendingExtApprovals
        );

        if (preferBlankDraftRef.current && !preferSessionId) {
          preferBlankDraftRef.current = false;
          setActiveSessionId('');
          setActiveSession(null);
          setSessionMode(ov.default_mode || 'standard');
        } else {
          const firstAvailableId =
            ov.sessions && ov.sessions.length > 0 ? ov.sessions[0].id : '';
          const targetId =
            preferSessionId === null
              ? firstAvailableId
              : preferSessionId || activeSessionId || firstAvailableId;
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
          } else {
            setActiveSessionId('');
            setActiveSession(null);
            if (servers.length > 0 && selectedServerIds.length === 0) {
              setSelectedServerIds([servers[0].id]);
            }
          }
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
    if (!mobileSessionsOpen) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setMobileSessionsOpen(false);
      }
    };
    const onResize = () => {
      if (window.innerWidth > 768) {
        setMobileSessionsOpen(false);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    window.addEventListener('resize', onResize);
    return () => {
      window.removeEventListener('keydown', onKeyDown);
      window.removeEventListener('resize', onResize);
    };
  }, [mobileSessionsOpen]);

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
        const pendingExtApprovals = overview?.pending_external_approvals || 0;
        onBadgeChange?.(pendingCnt + pendingExtApprovals);
      });
    }
  }, [
    subTab,
    overview?.patrol_status?.unread_alerts,
    overview?.sessions,
    overview?.pending_external_approvals,
    onBadgeChange,
  ]);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [activeSession?.messages.length, streamDelta, streamReasoning, streamTools.length]);

  const activeProvider = useMemo(() => {
    if (!overview?.providers?.length) return null;
    return (
      overview.providers.find((p) => p.id === overview.active_provider_id) ||
      overview.providers[0]
    );
  }, [overview]);

  const refreshSessionContext = useCallback(async (sessionId?: string) => {
    const sid = sessionId ?? activeSessionId;
    if (!sid) {
      setContextInspection(null);
      return;
    }
    setLoadingContext(true);
    try {
      const { context } = await api.inspectAISessionContext(sid);
      setContextInspection(context);
    } catch {
      // ignore transient
    } finally {
      setLoadingContext(false);
    }
  }, [activeSessionId]);

  const activeServerIdsKey = (activeSession?.server_ids || []).join(',');
  useEffect(() => {
    if (activeSession?.id) {
      void refreshSessionContext(activeSession.id);
    } else {
      setContextInspection(null);
    }
  }, [activeSession?.id, activeSession?.messages.length, activeSession?.compaction_count, activeServerIdsKey, refreshSessionContext]);

  const handleCompactSession = async (reset = false) => {
    if (!activeSession || compactingContext) return;
    setCompactingContext(true);
    try {
      const res = await api.compactAISession(activeSession.id, reset);
      setActiveSession(res.session);
      setContextInspection(res.context);
      if (reset) {
        onNotify('已清空历史滚动摘要，恢复全量上下文窗口');
      } else if (res.compaction.triggered) {
        onNotify(
          `无损滚动压缩完成（${res.compaction.mode === 'llm' ? '模型摘要' : '本地摘要'}）：估算占用 ${res.compaction.estimated_tokens_before} → ${res.compaction.estimated_tokens_after} tokens`
        );
      } else {
        onNotify('当前对话轮次较少，暂无需压缩');
      }
      await loadOverview(activeSession.id);
    } catch (err: any) {
      onNotify(err?.message || '上下文压缩失败');
    } finally {
      setCompactingContext(false);
    }
  };

  const handleResolveAgentsProposal = async (proposalId: string, accept: boolean) => {
    try {
      await api.resolveAgentsMDProposal(proposalId, accept);
      onNotify(
        accept
          ? '已批准并合入全局 AGENTS.md，新规范已加密生效'
          : '已忽略该 AGENTS.md 修订建议'
      );
      await loadOverview(activeSession?.id);
      if (activeSession?.id) {
        void refreshSessionContext(activeSession.id);
      }
    } catch (err: any) {
      onNotify(err?.message || '处理 AGENTS.md 修订提案失败');
    }
  };

  const handleSelectSession = async (summary: AIChatSessionSummary) => {
    if (streaming) {
      streamAbortRef.current?.abort();
    }
    setMobileSessionsOpen(false);
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
    if (streaming) {
      streamAbortRef.current?.abort();
    }
    setMobileSessionsOpen(false);
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
    const deletingActive = activeSessionId === id;
    if (deletingActive && streaming) {
      streamAbortRef.current?.abort();
    }
    try {
      await api.deleteAISession(id);
      if (deletingActive) {
        setActiveSessionId('');
        setActiveSession(null);
      }
      await loadOverview(deletingActive ? null : activeSessionId);
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

  const updateSelectedServers = async (next: string[]) => {
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

  const toggleServerTarget = async (srvId: string) => {
    const next = selectedServerIds.includes(srvId)
      ? selectedServerIds.filter((id) => id !== srvId)
      : [...selectedServerIds, srvId];
    await updateSelectedServers(next);
  };

  const processStreamEvents = useCallback(
    (ev: any) => {
      switch (ev.type) {
        case 'delta':
          if (ev.delta) {
            setStreamDelta((prev) => prev + ev.delta);
          }
          break;
        case 'reasoning_delta':
          if (ev.reasoning_delta) {
            setStreamReasoning((prev) => prev + ev.reasoning_delta);
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
        case 'memory_saved':
          if (ev.memory_entry) {
            onNotify(`已沉淀长期运维记忆《${ev.memory_entry.title}》`);
          }
          break;
        case 'runbook_proposed':
          if (ev.proposal) {
            onNotify(`AI 已提炼排障技能草案《${ev.proposal.title}》，请确认是否归档`);
          }
          break;
        case 'agents_md_proposed':
          if (ev.agents_md_proposal) {
            onNotify(`AI 提议修订全局 AGENTS.md：《${ev.agents_md_proposal.summary}》，请审阅 Diff`);
          }
          break;
        case 'context_compacted':
          if (ev.compaction?.triggered) {
            onNotify(
              `长会话已自动无损压缩前 ${ev.compaction.compacted_until_count} 条历史（${ev.compaction.estimated_tokens_before} → ${ev.compaction.estimated_tokens_after} tokens）`
            );
          }
          break;
        case 'session_sync':
          if (ev.session) {
            setActiveSession(ev.session);
            setPendingUserMessage('');
            setStreamDelta('');
            setStreamReasoning('');
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
    setPendingUserMessage(text);
    setStreaming(true);
    setStreamDelta('');
    setStreamReasoning('');
    setStreamTools([]);

    const ac = new AbortController();
    streamAbortRef.current = ac;

    try {
      await api.streamAIChat(
        sess.id,
        {
          message: text,
          server_ids: targetServers,
          mode: sessionMode,
        },
        processStreamEvents,
        ac.signal
      );
      await loadOverview(sess.id);
    } catch (err: any) {
      if (err?.name === 'AbortError') {
        onNotify('已停止本次 AI 生成');
      } else {
        onNotify(err?.message || 'AI 诊断对话中断');
      }
      await loadOverview(sess.id);
    } finally {
      if (streamAbortRef.current === ac) {
        streamAbortRef.current = null;
      }
      setStreaming(false);
      setPendingUserMessage('');
      setStreamDelta('');
      setStreamReasoning('');
      setStreamTools([]);
    }
  };

  const handleResolveApproval = async (approvalId: string, approve: boolean) => {
    if (!activeSession || streaming) return;
    const sessId = activeSession.id;
    setStreaming(true);
    setStreamDelta('');
    setStreamReasoning('');
    setStreamTools([]);
    const ac = new AbortController();
    streamAbortRef.current = ac;
    try {
      await api.streamAIApproval(
        sessId,
        approvalId,
        approve,
        processStreamEvents,
        ac.signal
      );
      await loadOverview(sessId);
    } catch (err: any) {
      if (err?.name === 'AbortError') {
        onNotify('已停止本次 AI 生成');
      } else {
        onNotify(err?.message || '处理变更审批失败');
      }
      await loadOverview(sessId);
    } finally {
      if (streamAbortRef.current === ac) {
        streamAbortRef.current = null;
      }
      setStreaming(false);
      setStreamDelta('');
      setStreamReasoning('');
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
    const clampNum = (raw: string, fallback: number, lo: number, hi: number) => {
      const n = Number(raw);
      if (!Number.isFinite(n)) return fallback;
      return Math.min(hi, Math.max(lo, n));
    };
    try {
      await api.updatePatrolConfig({
        enabled: patrolEnabled,
        interval_minutes: patrolInterval,
        server_ids: patrolServerIds,
        cpu_warn_percent: clampNum(cpuWarnStr, 85, 20, 100),
        mem_warn_percent: clampNum(memWarnStr, 85, 20, 100),
        disk_warn_percent: clampNum(diskWarnStr, 85, 20, 100),
        ssh_fail_warn_count: Math.round(clampNum(sshFailWarnStr, 15, 1, 10000)),
        check_listening_ports: checkPorts,
        check_privileged_users: checkPrivUsers,
        analysis_mode: patrolAnalysisMode,
        external_fallback_minutes: Math.round(clampNum(patrolFallbackStr, 15, 1, 1440)),
        notify_pending_approvals: notifyPendingApprovals,
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
      onNotify('后台定时巡检与外部 AI 研判策略已加密保存');
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

  const handleQuickSwitchProvider = async (providerId: string) => {
    if (!providerId || providerId === overview?.active_provider_id || switchingProvider) return;
    setSwitchingProvider(true);
    try {
      await api.setActiveAIProvider(providerId);
      const target = overview?.providers?.find((p) => p.id === providerId);
      onNotify(`已切换全局激活模型为 ${target ? `${target.name} · ${target.model}` : providerId}`);
      await loadOverview(activeSessionId);
      if (activeSession?.id) {
        void refreshSessionContext(activeSession.id);
      }
    } catch (err: any) {
      onNotify(err?.message || '切换激活模型失败');
    } finally {
      setSwitchingProvider(false);
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
      <div className="page-header" style={{ flexWrap: 'wrap', rowGap: 10 }}>
        <div className="page-header-title" style={{ minWidth: 'min(320px, 100%)' }}>
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              flexWrap: 'wrap',
              minWidth: 0,
              maxWidth: '100%',
            }}
          >
            <h2>AI 智能运维与安全诊断中心</h2>
            {activeProvider ? (
              (overview?.providers?.length || 0) > 1 ? (
                <div className="ai-provider-quick-switcher">
                  <Sparkles size={11.5} style={{ color: 'var(--accent-teal)', flexShrink: 0 }} />
                  <select
                    aria-label="快捷切换全局激活大模型"
                    className="ai-provider-quick-select"
                    value={activeProvider.id}
                    disabled={switchingProvider || streaming}
                    onChange={(e) => void handleQuickSwitchProvider(e.target.value)}
                    title="直接切换全局激活大模型"
                  >
                    {(overview?.providers || []).map((p) => (
                      <option key={p.id} value={p.id}>
                        {p.name} · {p.model}
                      </option>
                    ))}
                  </select>
                  <button
                    type="button"
                    className="btn btn-ghost btn-sm btn-icon"
                    style={{ width: 22, height: 22 }}
                    onClick={() => setSubTab('providers')}
                    title="管理模型与网关配置"
                  >
                    <Sliders size={11.5} />
                  </button>
                </div>
              ) : (
                <button
                  type="button"
                  className="tag-chip teal"
                  style={{
                    border: 'none',
                    cursor: 'pointer',
                    maxWidth: 'min(100%, 310px)',
                    minWidth: 0,
                    flexShrink: 1,
                  }}
                  onClick={() => setSubTab('providers')}
                  title={`${activeProvider.name} · ${activeProvider.model}（点击切换或管理全局激活大模型）`}
                >
                  <Sparkles size={11.5} style={{ marginRight: 4, flexShrink: 0 }} />
                  <span
                    style={{
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                      minWidth: 0,
                    }}
                  >
                    {activeProvider.name} · {activeProvider.model}
                  </span>
                </button>
              )
            ) : (
              overview?.mcp_runtime?.deploy_mode === 'desktop'
                ? Boolean(
                    overview?.mcp_config?.desktop_loopback_enabled &&
                      overview?.mcp_runtime?.desktop_loopback_running
                  )
                : Boolean(overview?.mcp_config?.enabled)
            ) ? (
              <button
                type="button"
                className="tag-chip teal"
                style={{ border: 'none', cursor: 'pointer', maxWidth: '100%', minWidth: 0, flexShrink: 1 }}
                onClick={() => setSubTab('mcp')}
                title="外部 AI (MCP) 网关已启用，点击管理令牌与客户端配置"
              >
                <PlugZap size={11.5} style={{ marginRight: 4, flexShrink: 0 }} />
                外部 AI (MCP) 已接入 · 可选配内置模型
              </button>
            ) : (
              <button
                type="button"
                className="tag-chip amber"
                style={{ border: 'none', cursor: 'pointer', maxWidth: '100%', minWidth: 0, flexShrink: 1 }}
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
            id="ai-tab-mcp"
            className={`ai-subnav-btn ${subTab === 'mcp' ? 'active' : ''}`}
            onClick={() => setSubTab('mcp')}
          >
            <PlugZap size={14} /> 外部 AI 接管 (MCP)
            {((overview?.pending_external_approvals || 0) +
              (overview?.patrol_status?.pending_external_count || 0)) > 0 && (
              <span className="nav-badge live">
                {(overview?.pending_external_approvals || 0) +
                  (overview?.patrol_status?.pending_external_count || 0)}
              </span>
            )}
          </button>
          <button
            type="button"
            id="ai-tab-memory"
            className={`ai-subnav-btn ${subTab === 'memory' ? 'active' : ''}`}
            onClick={() => setSubTab('memory')}
          >
            <BrainCircuit size={14} /> AGENTS.md 与记忆中心
            <span className="nav-badge">
              {(overview?.memories?.length || 0) +
                (overview?.host_memories?.length || 0) +
                (overview?.runbooks?.length || 0)}
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
          {mobileSessionsOpen && (
            <div
              className="ai-session-rail-backdrop"
              onClick={() => setMobileSessionsOpen(false)}
              aria-hidden="true"
            />
          )}

          <aside
            id="ai-session-rail"
            className={`ai-session-rail ${mobileSessionsOpen ? 'mobile-open' : ''}`}
          >
            <div className="ai-session-rail-header">
              <button
                type="button"
                id="ai-new-session-btn"
                className="btn btn-primary btn-block"
                style={{ flex: 1 }}
                onClick={() => void handleCreateSession()}
              >
                <Plus size={14} /> 新建排障会话
              </button>
              <button
                type="button"
                className="btn btn-ghost btn-sm btn-icon ai-session-rail-close-btn"
                onClick={() => setMobileSessionsOpen(false)}
                aria-label="关闭会话列表"
              >
                <X size={15} />
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
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        void handleSelectSession(s);
                      }
                    }}
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
                      ) : (s.pending_agents_md_proposal_count || 0) > 0 ? (
                        <span className="tag-chip teal" style={{ fontSize: 10.5, padding: '1px 6px' }}>
                          AGENTS 提案
                        </span>
                      ) : (
                        <span>
                          {s.message_count} 条{s.compaction_count ? ` · 压缩×${s.compaction_count}` : ''}
                        </span>
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
                <button
                  type="button"
                  id="ai-mobile-sessions-btn"
                  className="ai-mobile-sessions-btn"
                  onClick={() => setMobileSessionsOpen((prev) => !prev)}
                  aria-expanded={mobileSessionsOpen}
                  aria-controls="ai-session-rail"
                >
                  <MessageSquare size={13} />
                  <span>会话 ({overview?.sessions?.length || 0})</span>
                </button>
                <span style={{ fontSize: 12, color: 'var(--text-muted)', fontWeight: 560, flexShrink: 0 }}>
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
                          title={srv.name}
                          onClick={() => void toggleServerTarget(srv.id)}
                        >
                          <ServerIcon size={11.5} style={{ flexShrink: 0 }} />
                          <span
                            style={{
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap',
                              minWidth: 0,
                            }}
                          >
                            {srv.name}
                          </span>
                        </button>
                      );
                    })}
                    {servers.length > 1 && (
                      <button
                        type="button"
                        className="btn btn-ghost btn-sm"
                        style={{ height: 25, fontSize: 11.5, flexShrink: 0 }}
                        onClick={() => {
                          const allIds =
                            selectedServerIds.length === servers.length
                              ? [servers[0].id]
                              : servers.map((s) => s.id);
                          void updateSelectedServers(allIds);
                        }}
                      >
                        {selectedServerIds.length === servers.length ? '仅选首台' : '全选集群'}
                      </button>
                    )}
                  </>
                )}
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                {activeSession && (
                  <>
                    <button
                      type="button"
                      id="ai-context-inspector-btn"
                      className={`ai-ctx-pill-btn ${contextInspection?.needs_compaction ? 'warn' : ''}`}
                      onClick={() => {
                        setShowContextInspector(true);
                        void refreshSessionContext(activeSession.id);
                      }}
                      title="透视当前注入的 AGENTS.md、长期记忆、实时监控快照与上下文 Token 占用"
                    >
                      <Layers size={12.5} />
                      <span>上下文透视</span>
                      {contextInspection && (
                        <span className="mono ai-ctx-pct">
                          {contextInspection.usage_percent.toFixed(0)}%
                        </span>
                      )}
                    </button>
                    {activeSession.messages.length >= 4 && (
                      <button
                        type="button"
                        id="ai-toolbar-compact-btn"
                        className="btn btn-ghost btn-sm"
                        style={{ height: 27, fontSize: 11.5 }}
                        disabled={compactingContext || streaming}
                        onClick={() => void handleCompactSession(false)}
                        title="无损滚动压缩早期历史，保留完整审计记录"
                      >
                        <Minimize2 size={12} />
                        {compactingContext ? '压缩中...' : '压缩'}
                      </button>
                    )}
                  </>
                )}
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
                <span className="ai-mode-hint">
                  {sessionMode === 'suggest'
                    ? '仅建议方案 · 所有操作需人工确认'
                    : sessionMode === 'standard'
                    ? '只读自动采集 · 变更展示 Diff 待审批'
                    : '自动修复常规问题 · 高危命令底层硬拦截'}
                </span>
              </div>
            </div>

            {/* Conversation Stream */}
            <div className="ai-messages-scroll">
              {loading ? (
                <div className="empty-state">正在读取加密会话与排障上下文...</div>
              ) : (!activeSession || activeSession.messages.length === 0) &&
                !streaming &&
                !pendingUserMessage ? (
                <div className="empty-state" style={{ margin: 'auto' }}>
                  <div className="empty-state-icon">
                    <Bot size={22} style={{ color: 'var(--accent-teal)' }} />
                  </div>
                  <h3>原生加密 AI 运维排障助手已就绪</h3>
                  <p>
                    自动注入全局 AGENTS.md 运维宪章、主机画像 2.0、高优长期记忆与 7×24 实时监控态势；涉及变更时生成 Git Unified Diff 供您一键审批。
                  </p>
                  <div className="ai-empty-prompts-grid">
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
                  {activeSession && (() => {
                    const compactedUntil = activeSession.compacted_until_count || 0;
                    const visibleItems = activeSession.messages
                      .map((msg, rawIdx) => ({ msg, rawIdx }))
                      .filter((x) => x.msg.role === 'user' || x.msg.role === 'assistant');
                    let dividerShown = false;

                    return visibleItems.map(({ msg, rawIdx }) => {
                      const showDividerBefore =
                        !dividerShown && compactedUntil > 0 && rawIdx >= compactedUntil;
                      if (showDividerBefore) {
                        dividerShown = true;
                      }

                      if (msg.role === 'user') {
                        return (
                          <React.Fragment key={msg.id}>
                            {showDividerBefore && (
                              <CompactionDivider
                                compactedUntilCount={compactedUntil}
                                compactionCount={activeSession.compaction_count}
                                onInspect={() => setShowContextInspector(true)}
                              />
                            )}
                            <div className="ai-msg-row user">
                              <div className="ai-msg-bubble">{msg.content}</div>
                            </div>
                          </React.Fragment>
                        );
                      }
                      const linkedApprovals = (msg.tool_calls || [])
                        .map((tc) => approvalByToolCallId.get(tc.id))
                        .filter(Boolean);
                      const snippets = extractShellSnippets(msg.content || '');

                      return (
                        <React.Fragment key={msg.id}>
                          {showDividerBefore && (
                            <CompactionDivider
                              compactedUntilCount={compactedUntil}
                              compactionCount={activeSession.compaction_count}
                              onInspect={() => setShowContextInspector(true)}
                            />
                          )}
                          <div className="ai-msg-row assistant">
                            {msg.reasoning_content && (
                              <ReasoningTraceBlock text={msg.reasoning_content} />
                            )}
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

                            {msg.usage && <MessageUsagePill usage={msg.usage} />}

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
                        </React.Fragment>
                      );
                    });
                  })()}

                  {/* Render AGENTS.md Revision Proposals attached to this session */}
                  {(activeSession?.agents_md_proposals || []).map((prop) => (
                    <div key={prop.id} className="ai-msg-row assistant">
                      <AgentsMDProposalCard
                        proposal={prop}
                        busy={streaming}
                        onResolve={(id, accept) => void handleResolveAgentsProposal(id, accept)}
                      />
                    </div>
                  ))}

                  {/* Render Runbook Proposals attached to this session */}
                  {(activeSession?.runbook_proposals || []).map((prop) => (
                    <div key={prop.id} className="ai-msg-row assistant">
                      <RunbookProposalCard
                        proposal={prop}
                        busy={streaming}
                        onResolve={(id, accept, sync) => void handleResolveProposal(id, accept, sync)}
                      />
                    </div>
                  ))}

                  {/* Optimistic Pending User Prompt (immediately visible even on Turn 1) */}
                  {pendingUserMessage && (
                    <div className="ai-msg-row user">
                      <div className="ai-msg-bubble">{pendingUserMessage}</div>
                    </div>
                  )}

                  {/* Live Streaming Turn */}
                  {streaming && (
                    <div className="ai-msg-row assistant">
                      {streamReasoning && (
                        <ReasoningTraceBlock text={streamReasoning} streaming={!streamDelta} />
                      )}
                      {streamTools.length > 0 && (
                        <div className="ai-tool-trace-list">
                          {streamTools.map((tc) => (
                            <ToolTraceStep key={tc.id} tool={tc} />
                          ))}
                        </div>
                      )}
                      <div className="ai-msg-bubble">
                        {streamDelta ? (
                          <FormattedMarkdownText text={streamDelta} />
                        ) : streamReasoning ? (
                          <span style={{ color: 'var(--text-muted)' }}>
                            深度思考进行中，即将输出诊断结果...
                          </span>
                        ) : (
                          <span style={{ color: 'var(--text-muted)' }}>
                            正在连接远程探针并推理诊断方案...
                          </span>
                        )}
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
                    if (
                      e.key === 'Enter' &&
                      !e.shiftKey &&
                      !e.nativeEvent.isComposing &&
                      e.keyCode !== 229
                    ) {
                      e.preventDefault();
                      void handleSendMessage();
                    }
                  }}
                />
                {streaming ? (
                  <button
                    type="button"
                    id="ai-center-stop-btn"
                    className="btn ai-composer-send-btn"
                    style={{ height: 44, padding: '0 18px', color: 'var(--danger-text)' }}
                    onClick={() => streamAbortRef.current?.abort()}
                  >
                    <Square size={13} />
                    停止生成
                  </button>
                ) : (
                  <button
                    type="submit"
                    id="ai-center-send-btn"
                    className="btn btn-primary ai-composer-send-btn"
                    style={{ height: 44, padding: '0 18px' }}
                    disabled={!promptInput.trim()}
                  >
                    <Send size={14} />
                    发送指令
                  </button>
                )}
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
                  flexShrink: 0,
                }}
              >
                <Radar size={20} />
              </div>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                  <strong style={{ fontSize: 15 }}>
                    {overview?.patrol_config.enabled
                      ? `定时无人值守巡检已开启（每 ${overview.patrol_config.interval_minutes} 分钟）`
                      : '后台定时巡检当前未开启'}
                  </strong>
                  <span className="tag-chip teal">只读安全探针 · 零自动变更</span>
                  <span
                    className={`tag-chip ${
                      overview?.patrol_config.analysis_mode &&
                      overview.patrol_config.analysis_mode !== 'builtin'
                        ? 'amber'
                        : ''
                    }`}
                  >
                    <PlugZap size={11} style={{ marginRight: 3 }} />
                    {overview?.patrol_config.analysis_mode === 'external'
                      ? '研判引擎：外部 AI 接管 (MCP)'
                      : overview?.patrol_config.analysis_mode === 'external_with_fallback'
                      ? `研判引擎：外部 AI 优先 (${overview.patrol_config.external_fallback_minutes || 15}m 兜底)`
                      : '研判引擎：内置大模型'}
                  </span>
                  {(overview?.patrol_status?.pending_external_count || 0) > 0 && (
                    <span className="tag-chip amber">
                      <Clock size={11} style={{ marginRight: 3 }} />
                      {overview?.patrol_status?.pending_external_count} 条待外部 AI 研判
                    </span>
                  )}
                </div>
                <div style={{ fontSize: 12.5, color: 'var(--text-muted)', marginTop: 2 }}>
                  后台 7×24 守护运行，支持由本地 Claude Code / Codex / Antigravity / Cursor 通过 MCP 接管深度研判。
                  {overview?.patrol_status.last_run_at && (
                    <span style={{ marginLeft: 10 }}>
                      上次巡检：{new Date(overview.patrol_status.last_run_at).toLocaleString('zh-CN')}
                    </span>
                  )}
                </div>
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
              <button
                type="button"
                className="btn"
                onClick={() => setSubTab('mcp')}
              >
                <PlugZap size={14} /> 外部 AI 接入 (MCP)
              </button>
              <button
                type="button"
                className="btn"
                onClick={() => {
                  if (overview) syncPatrolDraftFromOverview(overview);
                  setShowPatrolConfigModal(true);
                }}
              >
                <Sliders size={14} /> 巡检策略与告警通道 ({overview?.patrol_config.webhooks?.length || 0})
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
                点击右上角「立即执行全量巡检」即可对集群执行只读健康与入侵指标扫描（CPU/内存/磁盘、监听端口基线突变、SSH 爆破激增、UID=0 特权账号），并由内置大模型或外部 MCP AI 输出根因报告。
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
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
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
                        {rec.trigger === 'scheduled'
                          ? '后台定时触发'
                          : rec.trigger === 'external_mcp'
                          ? '外部 AI 主动触发 (MCP)'
                          : '管理员手动触发'}
                      </span>
                      {rec.ai_source === 'external_mcp' && rec.ai_analyzed && (
                        <span className="tag-chip teal">
                          <PlugZap size={11} style={{ marginRight: 3 }} />
                          由 {rec.external_client || '外部 AI'} 深度研判
                          {rec.ai_model && rec.ai_model !== rec.external_client ? ` · ${rec.ai_model}` : ''}
                        </span>
                      )}
                      {rec.analysis_state === 'pending_external' && (
                        <span className="tag-chip amber">
                          <Clock size={11} style={{ marginRight: 3 }} /> 等待外部 AI 接管研判
                        </span>
                      )}
                      {rec.analysis_state === 'claimed' && (
                        <span className="tag-chip teal">
                          <Sparkles size={11} style={{ marginRight: 3 }} /> {rec.claimed_by || '外部 AI'} 钻取排查中
                        </span>
                      )}
                      {rec.analysis_state === 'fallback_completed' && (
                        <span className="tag-chip">外部超时 · 内置模型兜底</span>
                      )}
                      <span className="mono" style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                        {new Date(rec.completed_at).toLocaleString('zh-CN')}
                      </span>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                      <span style={{ fontSize: 12.5, color: 'var(--text-secondary)' }}>
                        共 {rec.total_servers} 台（正常 {rec.healthy_count} · 预警 {rec.warning_count} · 严重{' '}
                        {rec.critical_count}）
                      </span>
                      {rec.webhook_notified && (
                        <span className="tag-chip teal">
                          <Bell size={11} style={{ marginRight: 3 }} />
                          {rec.ai_webhook_notified ? '已推深度报告' : '已推送告警'}
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
                  <div className="patrol-findings-grid">
                    {rec.findings.map((f) => (
                      <div
                        key={f.server_id}
                        style={{
                          padding: '9px 12px',
                          borderRadius: 7,
                          background: 'var(--bg-subtle)',
                          border: '1px solid var(--border-subtle)',
                          fontSize: 12,
                          minWidth: 0,
                          maxWidth: '100%',
                        }}
                      >
                        <div
                          style={{
                            display: 'flex',
                            justifyContent: 'space-between',
                            alignItems: 'flex-start',
                            flexWrap: 'wrap',
                            gap: 4,
                            fontWeight: 600,
                            minWidth: 0,
                          }}
                        >
                          <span style={{ minWidth: 0, maxWidth: '100%', overflowWrap: 'anywhere', wordBreak: 'break-word' }}>
                            {f.server_name}
                          </span>
                          <span
                            className="mono"
                            style={{
                              color: 'var(--text-muted)',
                              minWidth: 0,
                              maxWidth: '100%',
                              overflowWrap: 'anywhere',
                              wordBreak: 'break-all',
                            }}
                          >
                            {f.host}
                          </span>
                        </div>
                        {f.reachable && (
                          <div
                            className="mono"
                            style={{
                              fontSize: 11,
                              color: 'var(--text-muted)',
                              marginTop: 4,
                              overflowWrap: 'anywhere',
                              wordBreak: 'break-word',
                            }}
                          >
                            CPU负载 {f.cpu_load_percent ?? 0}% · 内存 {f.mem_percent ?? 0}% · 磁盘 {f.disk_percent ?? 0}% · 1h爆破{' '}
                            {f.ssh_fail_count_1h ?? 0}次
                          </div>
                        )}
                        {f.anomalies && f.anomalies.length > 0 ? (
                          <div
                            style={{
                              color: 'var(--amber-text)',
                              marginTop: 4,
                              fontWeight: 550,
                              minWidth: 0,
                              maxWidth: '100%',
                              overflowWrap: 'anywhere',
                              wordBreak: 'break-word',
                            }}
                          >
                            {f.anomalies.join('；')}
                          </div>
                        ) : (
                          <div style={{ color: 'var(--status-online)', marginTop: 4 }}>各项指标与基线一致</div>
                        )}
                      </div>
                    ))}
                  </div>

                  {/* Pending External AI Queue Callout */}
                  {(rec.analysis_state === 'pending_external' || rec.analysis_state === 'claimed') &&
                    !rec.ai_summary && (
                      <div className="mcp-patrol-pending-box">
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 8 }}>
                          <span>
                            {rec.analysis_state === 'claimed'
                              ? `外部 AI (${rec.claimed_by || 'MCP'}) 已认领此巡检单（ID: ${rec.id.slice(0, 8)}），正在通过只读 SSH/SFTP 钻取日志与进程取证...`
                              : `此巡检单（ID: ${rec.id.slice(0, 8)}）已进入外部 AI 待研判队列。在 Claude Code / Codex / Antigravity / Cursor 中运行 patrol_triage 即可接管深度分析并回写报告。`}
                            {rec.external_deadline_at && (
                              <span className="mono" style={{ marginLeft: 8, opacity: 0.85 }}>
                                超时自动兜底：{new Date(rec.external_deadline_at).toLocaleTimeString('zh-CN')}
                              </span>
                            )}
                          </span>
                          <button
                            type="button"
                            className="btn btn-sm"
                            onClick={() => setSubTab('mcp')}
                          >
                            <PlugZap size={12} /> 查看 MCP 接入指南
                          </button>
                        </div>
                      </div>
                    )}

                  {/* On-demand AI Root Cause Summary */}
                  {rec.ai_summary && (
                    <div
                      style={{
                        padding: '11px 14px',
                        borderRadius: 8,
                        background: 'var(--accent-teal-soft)',
                        border: '1px solid var(--accent-teal-border)',
                        fontSize: 12.5,
                        minWidth: 0,
                        maxWidth: '100%',
                        overflowWrap: 'anywhere',
                        wordBreak: 'break-word',
                      }}
                    >
                      <div style={{ fontWeight: 620, marginBottom: 4, color: 'var(--accent-teal)', display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                        <span>
                          {rec.ai_source === 'external_mcp'
                            ? `${rec.external_client || '外部 AI'} 深度研判摘要：`
                            : 'AI 根因诊断摘要：'}
                          {rec.ai_summary}
                        </span>
                      </div>
                      {rec.ai_root_cause && (
                        <div style={{ color: 'var(--text-secondary)', marginBottom: 6 }}>
                          {rec.ai_root_cause}
                        </div>
                      )}
                      {rec.deep_evidence && rec.deep_evidence.length > 0 && (
                        <div
                          style={{
                            marginBottom: 8,
                            padding: '7px 10px',
                            borderRadius: 6,
                            background: 'var(--bg-surface)',
                            border: '1px solid var(--border-subtle)',
                          }}
                        >
                          <div style={{ fontSize: 11.5, fontWeight: 620, color: 'var(--text-secondary)', marginBottom: 3 }}>
                            只读钻取关键取证线索：
                          </div>
                          <ul style={{ margin: 0, paddingLeft: 16, fontSize: 12, color: 'var(--text-primary)' }}>
                            {rec.deep_evidence.map((ev, idx) => (
                              <li key={idx} className="mono" style={{ fontSize: 11.5 }}>
                                {ev}
                              </li>
                            ))}
                          </ul>
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

      {/* TAB 2.5: External AI Takeover (MCP Gateway, Persistent Scoped Tokens & External HITL Queue) */}
      {subTab === 'mcp' && (
        <ExternalAIMCPTab
          overview={overview}
          servers={servers}
          onReloadOverview={() => loadOverview(activeSessionId)}
          onJumpPatrol={() => setSubTab('patrol')}
          onNotify={onNotify}
        />
      )}

      {/* TAB 3: Integrated Global AGENTS.md & Memory Center */}
      {subTab === 'memory' && (
        <AIMemoryAgentsTab
          overview={overview}
          servers={servers}
          initialSection={memorySubSection}
          onReloadOverview={() => loadOverview(activeSessionId)}
          onRefreshWorkspace={onRefreshWorkspace}
          onLaunchRunbook={launchRunbookDiagnosis}
          onNotify={onNotify}
        />
      )}

      {/* TAB 4: LLM Provider & Gateway Configuration */}
      {subTab === 'providers' && (
        <AIProviderConfigTab
          overview={overview}
          onReloadOverview={() => loadOverview(activeSessionId)}
          onNotify={onNotify}
        />
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
                    <label className="field-label">AI 巡检研判引擎模式</label>
                    <select
                      id="patrol-analysis-mode-select"
                      className="select"
                      value={patrolAnalysisMode}
                      onChange={(e) => setPatrolAnalysisMode(e.target.value as PatrolAnalysisMode)}
                    >
                      <option value="builtin">内置 HTTP 大模型（按需唤醒配置供应商）</option>
                      <option value="external">纯外部 AI 接管 (MCP · 异常先推速报并入队，零内置 API 消耗)</option>
                      <option value="external_with_fallback">外部 AI 优先 + 超时自动回退内置模型</option>
                    </select>
                  </div>
                  <div className="field">
                    <label className="field-label">
                      外部 AI 超时兜底等待时间 (分钟){patrolAnalysisMode !== 'external_with_fallback' ? '（仅兜底模式生效）' : ''}
                    </label>
                    <input
                      type="number"
                      min={1}
                      max={1440}
                      className="input mono"
                      disabled={patrolAnalysisMode !== 'external_with_fallback'}
                      value={patrolFallbackStr}
                      onChange={(e) => setPatrolFallbackStr(e.target.value)}
                    />
                  </div>
                </div>

                {servers.length > 0 && (
                  <div className="field" style={{ marginBottom: 12 }}>
                    <label className="field-label">
                      巡检目标服务器范围（不勾选 = 巡检全部纳管服务器，勾选则仅巡检选定主机）
                    </label>
                    <div className="mcp-server-chips">
                      {servers.map((srv) => {
                        const checked = patrolServerIds.includes(srv.id);
                        return (
                          <button
                            key={srv.id}
                            type="button"
                            className={`mcp-server-chip ${checked ? 'active' : ''}`}
                            onClick={() =>
                              setPatrolServerIds((prev) =>
                                checked ? prev.filter((id) => id !== srv.id) : [...prev, srv.id]
                              )
                            }
                          >
                            <ServerIcon size={11} />
                            {srv.name}
                          </button>
                        );
                      })}
                      {patrolServerIds.length > 0 && (
                        <button
                          type="button"
                          className="btn btn-ghost btn-sm"
                          style={{ height: 26, fontSize: 11.5 }}
                          onClick={() => setPatrolServerIds([])}
                        >
                          清空（恢复全量）
                        </button>
                      )}
                    </div>
                  </div>
                )}

                <div className="field-row">
                  <div className="field">
                    <label className="field-label">CPU 负载预警阈值 (%, 20–100)</label>
                    <input
                      type="number"
                      min={20}
                      max={100}
                      className="input mono"
                      value={cpuWarnStr}
                      onChange={(e) => setCpuWarnStr(e.target.value)}
                    />
                  </div>
                  <div className="field">
                    <label className="field-label">内存使用预警阈值 (%, 20–100)</label>
                    <input
                      type="number"
                      min={20}
                      max={100}
                      className="input mono"
                      value={memWarnStr}
                      onChange={(e) => setMemWarnStr(e.target.value)}
                    />
                  </div>
                </div>

                <div className="field-row">
                  <div className="field">
                    <label className="field-label">根分区磁盘预警阈值 (%, 20–100)</label>
                    <input
                      type="number"
                      min={20}
                      max={100}
                      className="input mono"
                      value={diskWarnStr}
                      onChange={(e) => setDiskWarnStr(e.target.value)}
                    />
                  </div>
                  <div className="field">
                    <label className="field-label">1 小时内 SSH 失败登录告警次数 (≥1)</label>
                    <input
                      type="number"
                      min={1}
                      max={10000}
                      className="input mono"
                      value={sshFailWarnStr}
                      onChange={(e) => setSshFailWarnStr(e.target.value)}
                    />
                  </div>
                </div>

                <div style={{ display: 'flex', gap: 18, margin: '8px 0 16px', flexWrap: 'wrap' }}>
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
                  <label style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 13 }}>
                    <input
                      type="checkbox"
                      checked={notifyPendingApprovals}
                      onChange={(e) => setNotifyPendingApprovals(e.target.checked)}
                    />
                    外部 AI 提交待审批变更提案时推送 Webhook 提醒
                  </label>
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 8, marginBottom: 8 }}>
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
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 8 }}>
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

      {/* Modal: Session Context Inspector & Manual Compaction */}
      {showContextInspector && (
        <ContextInspectorModal
          inspection={contextInspection}
          loading={loadingContext}
          compacting={compactingContext}
          onRefresh={() => void refreshSessionContext(activeSession?.id)}
          onCompact={(reset) => void handleCompactSession(Boolean(reset))}
          onClose={() => setShowContextInspector(false)}
          onOpenAgentsMD={() => {
            setMemorySubSection('agents_md');
            setSubTab('memory');
          }}
        />
      )}
    </div>
  );
};

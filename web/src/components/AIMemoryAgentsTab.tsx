import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  FileText,
  BrainCircuit,
  Server as ServerIcon,
  BookOpen,
  Plus,
  Edit3,
  Trash2,
  Play,
  Save,
  RotateCcw,
  Upload,
  Download,
  Pin,
  Search,
  RefreshCw,
  AlertTriangle,
  Sliders,
  ShieldCheck,
  ChevronDown,
  ChevronRight,
  Sparkles,
  Eye,
  EyeOff,
  Code2,
  Columns2,
} from 'lucide-react';
import { api } from '../api';
import type {
  AIMemoryCategory,
  AIMemoryConfig,
  AIMemoryEntry,
  AIOverviewResponse,
  AIRunbook,
  HostMemory,
  ServerView,
} from '../types';
import {
  FormattedMarkdownText,
  MEMORY_CATEGORY_LABELS,
  MEMORY_SOURCE_LABELS,
} from './AIMessageWidgets';
import { createSensitiveMasker } from '../utils/sensitiveMask';

export type MemorySubSection = 'agents_md' | 'memories' | 'hosts' | 'runbooks';

interface AIMemoryAgentsTabProps {
  overview: AIOverviewResponse | null;
  servers: ServerView[];
  initialSection?: MemorySubSection;
  initialMaskSensitive?: boolean;
  onReloadOverview: () => Promise<void>;
  onRefreshWorkspace: () => Promise<void>;
  onLaunchRunbook: (rb: AIRunbook) => Promise<void>;
  onNotify: (msg: string) => void;
}

const DEFAULT_MEMORY_CONFIG: AIMemoryConfig = {
  agents_md_max_chars: 6000,
  memory_prompt_budget_chars: 4500,
  compaction_trigger_ratio: 0.7,
  compaction_keep_recent: 6,
  auto_sync_monitor_to_memory: true,
  auto_record_approved_changes: true,
};

export const AIMemoryAgentsTab: React.FC<AIMemoryAgentsTabProps> = ({
  overview,
  servers,
  initialSection = 'agents_md',
  initialMaskSensitive = false,
  onReloadOverview,
  onRefreshWorkspace,
  onLaunchRunbook,
  onNotify,
}) => {
  const [section, setSection] = useState<MemorySubSection>(initialSection);
  // One-click sensitive server info masking (OFF by default)
  const [maskSensitive, setMaskSensitive] = useState(initialMaskSensitive);

  useEffect(() => {
    setSection(initialSection);
  }, [initialSection]);

  // --- Global AGENTS.md Editor State ---
  const [agentsEnabled, setAgentsEnabled] = useState(overview?.agents_md?.enabled ?? true);
  const [agentsContent, setAgentsContent] = useState(overview?.agents_md?.content || '');
  const [agentsDirty, setAgentsDirty] = useState(false);
  const [savingAgents, setSavingAgents] = useState(false);
  const [editorMode, setEditorMode] = useState<'split' | 'edit' | 'preview'>('split');
  const [showBudgetConfig, setShowBudgetConfig] = useState(false);
  const [budgetDraft, setBudgetDraft] = useState<AIMemoryConfig>(DEFAULT_MEMORY_CONFIG);
  const [budgetNumStr, setBudgetNumStr] = useState({
    agents_md_max_chars: String(DEFAULT_MEMORY_CONFIG.agents_md_max_chars),
    memory_prompt_budget_chars: String(DEFAULT_MEMORY_CONFIG.memory_prompt_budget_chars),
    compaction_trigger_pct: String(Math.round(DEFAULT_MEMORY_CONFIG.compaction_trigger_ratio * 100)),
    compaction_keep_recent: String(DEFAULT_MEMORY_CONFIG.compaction_keep_recent),
  });
  const [savingBudget, setSavingBudget] = useState(false);
  const mdImportInputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    if (overview?.agents_md && !agentsDirty) {
      setAgentsEnabled(overview.agents_md.enabled);
      setAgentsContent(overview.agents_md.content || '');
    }
  }, [overview?.agents_md, agentsDirty]);

  useEffect(() => {
    if (overview?.memory_config) {
      setBudgetDraft(overview.memory_config);
      setBudgetNumStr({
        agents_md_max_chars: String(overview.memory_config.agents_md_max_chars),
        memory_prompt_budget_chars: String(overview.memory_config.memory_prompt_budget_chars),
        compaction_trigger_pct: String(Math.round(overview.memory_config.compaction_trigger_ratio * 100)),
        compaction_keep_recent: String(overview.memory_config.compaction_keep_recent),
      });
    }
  }, [overview?.memory_config]);

  // --- Long-Term Memories Filter & Modal State ---
  const [memSearch, setMemSearch] = useState('');
  const [memScopeFilter, setMemScopeFilter] = useState<'all' | 'global' | 'server'>('all');
  const [memCatFilter, setMemCatFilter] = useState<string>('all');
  const [memServerFilter, setMemServerFilter] = useState<string>('all');
  const [editingEntry, setEditingEntry] = useState<{
    id?: string;
    scope: 'global' | 'server';
    server_ids: string[];
    category: AIMemoryCategory;
    title: string;
    content: string;
    tags_csv: string;
    importance: number;
    pinned: boolean;
  } | null>(null);

  // --- Host Memory 2.0 State ---
  const [syncingMonitorId, setSyncingMonitorId] = useState<string | null>(null);
  const [editingHostMemory, setEditingHostMemory] = useState<{
    is_new?: boolean;
    server_id: string;
    summary: string;
    os_arch: string;
    key_services_csv: string;
    deploy_paths_csv: string;
    ports_note: string;
    constraints: string;
    notes: string;
  } | null>(null);

  // --- Runbook State ---
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

  useEffect(() => {
    if (!editingEntry && !editingHostMemory && !editingRunbook) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setEditingEntry(null);
        setEditingHostMemory(null);
        setEditingRunbook(null);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [editingEntry, editingHostMemory, editingRunbook]);

  const hostMemoryByServerId = useMemo(() => {
    const map = new Map<string, HostMemory>();
    for (const hm of overview?.host_memories || []) {
      map.set(hm.server_id, hm);
    }
    return map;
  }, [overview?.host_memories]);

  const buildHostMemoryFormState = (serverId: string, isNew: boolean) => {
    const existing = hostMemoryByServerId.get(serverId);
    if (existing) {
      return {
        is_new: isNew,
        server_id: serverId,
        summary: existing.summary || '',
        os_arch: existing.os_arch || '',
        key_services_csv: (existing.key_services || []).join(', '),
        deploy_paths_csv: (existing.deploy_paths || []).join(', '),
        ports_note: existing.ports_note || '',
        constraints: existing.constraints || '',
        notes: existing.notes || '',
      };
    }
    return {
      is_new: isNew,
      server_id: serverId,
      summary: '',
      os_arch: '',
      key_services_csv: '',
      deploy_paths_csv: '',
      ports_note: '',
      constraints: '',
      notes: '',
    };
  };

  const serverNameById = useMemo(() => {
    const map = new Map<string, string>();
    for (const s of servers) map.set(s.id, s.name);
    return map;
  }, [servers]);

  const sensitiveMasker = useMemo(
    () =>
      createSensitiveMasker({
        servers,
        hostMemories: overview?.host_memories,
      }),
    [servers, overview?.host_memories]
  );

  const displayText = (raw: string | undefined | null): string => {
    const str = raw || '';
    return maskSensitive ? sensitiveMasker.maskText(str) : str;
  };

  const displayPortsNote = (raw: string | undefined | null): string => {
    const str = raw || '';
    return maskSensitive ? sensitiveMasker.maskPortsNote(str) : str;
  };

  const displayDeployPath = (raw: string): string =>
    maskSensitive ? sensitiveMasker.maskDeployPath(raw) : raw;

  const displayServiceName = (raw: string): string =>
    maskSensitive ? sensitiveMasker.maskServiceName(raw) : raw;

  const displayServerName = (raw: string): string =>
    maskSensitive ? sensitiveMasker.maskServerName(raw) : raw;

  const maskedAgentsSource = useMemo(
    () => (maskSensitive ? sensitiveMasker.maskText(agentsContent) : agentsContent),
    [maskSensitive, sensitiveMasker, agentsContent]
  );

  const maskedAgentsMarkdown = useMemo(
    () => (maskSensitive ? sensitiveMasker.maskMarkdownWithSentinel(agentsContent) : null),
    [maskSensitive, sensitiveMasker, agentsContent]
  );

  const handleToggleMaskSensitive = () => {
    setMaskSensitive((prev) => {
      const next = !prev;
      if (next) {
        setEditingEntry(null);
        setEditingHostMemory(null);
        setEditingRunbook(null);
      }
      return next;
    });
  };

  const notifyEditBlockedByMask = (actionLabel = '编辑') => {
    onNotify(`已开启关键信息屏蔽模式，请先关闭屏蔽后再${actionLabel}，以防明文暴露或误覆盖`);
  };

  const filteredMemories = useMemo(() => {
    const list = overview?.memories || [];
    const q = memSearch.trim().toLowerCase();
    return list.filter((m) => {
      if (memScopeFilter !== 'all' && m.scope !== memScopeFilter) return false;
      if (memCatFilter !== 'all' && m.category !== memCatFilter) return false;
      if (memServerFilter !== 'all') {
        if (m.scope !== 'server' || !(m.server_ids || []).includes(memServerFilter)) return false;
      }
      if (q) {
        const title = maskSensitive ? sensitiveMasker.maskText(m.title) : m.title;
        const content = maskSensitive ? sensitiveMasker.maskText(m.content) : m.content;
        const tags = (m.tags || [])
          .map((t) => (maskSensitive ? sensitiveMasker.maskText(t) : t))
          .join(' ');
        const hay = `${title} ${content} ${tags} ${
          MEMORY_CATEGORY_LABELS[m.category] || m.category
        }`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [
    overview?.memories,
    memSearch,
    memScopeFilter,
    memCatFilter,
    memServerFilter,
    maskSensitive,
    sensitiveMasker,
  ]);

  // --- AGENTS.md Handlers ---
  const handleSaveAgentsMD = async () => {
    if (maskSensitive) {
      notifyEditBlockedByMask('保存 AGENTS.md');
      return;
    }
    setSavingAgents(true);
    try {
      await api.updateAgentsMD({
        enabled: agentsEnabled,
        content: agentsContent,
      });
      setAgentsDirty(false);
      onNotify('全局 AGENTS.md 已通过 XChaCha20-Poly1305 加密保存并生效');
      await onReloadOverview();
    } catch (err: any) {
      onNotify(err?.message || '保存全局 AGENTS.md 失败');
    } finally {
      setSavingAgents(false);
    }
  };

  const handleResetAgentsMD = async () => {
    if (maskSensitive) {
      notifyEditBlockedByMask('重置 AGENTS.md');
      return;
    }
    setSavingAgents(true);
    try {
      const res = await api.updateAgentsMD({
        enabled: true,
        content: '',
        reset_default: true,
      });
      setAgentsEnabled(res.agents_md.enabled);
      setAgentsContent(res.agents_md.content);
      setAgentsDirty(false);
      onNotify('已重置为内置 SRE 默认运维规范模板');
      await onReloadOverview();
    } catch (err: any) {
      onNotify(err?.message || '重置 AGENTS.md 模板失败');
    } finally {
      setSavingAgents(false);
    }
  };

  const handleExportAgentsMD = () => {
    const exportContent = maskSensitive ? maskedAgentsSource : agentsContent;
    const blob = new Blob([exportContent], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = maskSensitive ? 'AGENTS.masked.md' : 'AGENTS.md';
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    onNotify(
      maskSensitive
        ? '已导出脱敏版 AGENTS.masked.md（服务器关键信息已替换为 ***）'
        : '已导出 AGENTS.md 文件'
    );
  };

  const handleImportAgentsMD = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = '';
    if (maskSensitive) {
      notifyEditBlockedByMask('导入 AGENTS.md');
      return;
    }
    if (!file) return;
    if (file.size > 64 * 1024) {
      onNotify('导入的 Markdown 文件超过 64 KB 上限');
      return;
    }
    const text = await file.text();
    setAgentsContent(text);
    setAgentsDirty(true);
    onNotify(`已载入 ${file.name}，请核对后点击「加密保存 AGENTS.md」生效`);
  };

  const handleSaveBudgetConfig = async (e: React.FormEvent) => {
    e.preventDefault();
    const agentsMax = Number(budgetNumStr.agents_md_max_chars);
    const memBudget = Number(budgetNumStr.memory_prompt_budget_chars);
    const triggerPct = Number(budgetNumStr.compaction_trigger_pct);
    const keepRecent = Number(budgetNumStr.compaction_keep_recent);

    const payload: AIMemoryConfig = {
      ...budgetDraft,
      agents_md_max_chars: Number.isFinite(agentsMax)
        ? Math.min(30000, Math.max(1000, Math.round(agentsMax)))
        : DEFAULT_MEMORY_CONFIG.agents_md_max_chars,
      memory_prompt_budget_chars: Number.isFinite(memBudget)
        ? Math.min(24000, Math.max(1000, Math.round(memBudget)))
        : DEFAULT_MEMORY_CONFIG.memory_prompt_budget_chars,
      compaction_trigger_ratio: Number.isFinite(triggerPct)
        ? Math.min(0.9, Math.max(0.4, triggerPct / 100))
        : DEFAULT_MEMORY_CONFIG.compaction_trigger_ratio,
      compaction_keep_recent: Number.isFinite(keepRecent)
        ? Math.min(20, Math.max(2, Math.round(keepRecent)))
        : DEFAULT_MEMORY_CONFIG.compaction_keep_recent,
    };

    setSavingBudget(true);
    try {
      await api.updateAIMemoryConfig(payload);
      onNotify('记忆与上下文预算策略已加密保存');
      await onReloadOverview();
    } catch (err: any) {
      onNotify(err?.message || '保存预算配置失败');
    } finally {
      setSavingBudget(false);
    }
  };

  // --- Long-Term Memory Handlers ---
  const handleSaveMemoryEntry = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingEntry) return;
    if (editingEntry.scope === 'server' && editingEntry.server_ids.length === 0) {
      onNotify('主机专属记忆请至少勾选一台关联服务器，或切换为「全局记忆」');
      return;
    }
    try {
      await api.upsertAIMemory({
        id: editingEntry.id,
        scope: editingEntry.scope,
        server_ids: editingEntry.scope === 'server' ? editingEntry.server_ids : [],
        category: editingEntry.category,
        title: editingEntry.title,
        content: editingEntry.content,
        tags: editingEntry.tags_csv
          .split(',')
          .map((t) => t.trim())
          .filter(Boolean),
        importance: editingEntry.importance,
        pinned: editingEntry.pinned,
        source: 'manual',
      });
      setEditingEntry(null);
      onNotify('长期运维记忆已加密保存');
      await onReloadOverview();
    } catch (err: any) {
      onNotify(err?.message || '保存长期记忆失败');
    }
  };

  const handleTogglePinMemory = async (m: AIMemoryEntry) => {
    try {
      await api.upsertAIMemory({
        ...m,
        pinned: !m.pinned,
      });
      const shownTitle = displayText(m.title);
      onNotify(
        !m.pinned ? `已置顶记忆《${shownTitle}》，每次对话优先注入` : `已取消置顶《${shownTitle}》`
      );
      await onReloadOverview();
    } catch (err: any) {
      onNotify(err?.message || '更新置顶状态失败');
    }
  };

  // --- Host Memory 2.0 Handlers ---
  const handleSyncMonitorHostMemory = async (serverId = '') => {
    setSyncingMonitorId(serverId || '__all__');
    try {
      const res = await api.syncHostMemoryFromMonitor(serverId);
      if (res.synced_count > 0) {
        onNotify(`已从 7×24 监控快照增量同步 ${res.synced_count} 台主机客观画像`);
      } else {
        onNotify('监控快照暂无新增客观字段变化（或尚未采集监控数据）');
      }
      await onReloadOverview();
    } catch (err: any) {
      onNotify(err?.message || '同步监控画像失败');
    } finally {
      setSyncingMonitorId(null);
    }
  };

  const handleSaveHostMemoryModal = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingHostMemory) return;
    try {
      await api.upsertHostMemory(editingHostMemory.server_id, {
        summary: editingHostMemory.summary,
        os_arch: editingHostMemory.os_arch,
        key_services: editingHostMemory.key_services_csv
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean),
        deploy_paths: editingHostMemory.deploy_paths_csv
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean),
        ports_note: editingHostMemory.ports_note,
        constraints: editingHostMemory.constraints,
        notes: editingHostMemory.notes,
      });
      setEditingHostMemory(null);
      onNotify('主机环境画像与运维红线已更新');
      await onReloadOverview();
    } catch (err: any) {
      onNotify(err?.message || '更新主机画像失败');
    }
  };

  // --- Runbook Handlers ---
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
      await onReloadOverview();
    } catch (err: any) {
      onNotify(err?.message || '保存 Runbook 失败');
    }
  };

  const agentsCharCount = Array.from(agentsContent).length;
  const agentsMaxChars = overview?.memory_config?.agents_md_max_chars || 6000;
  const agentsOverBudget = agentsCharCount > agentsMaxChars;

  return (
    <div className="page-body" id="ai-memory-agents-center">
      {/* Unified 4-Section Switcher + One-Click Sensitive Info Mask Toggle */}
      <div className="ai-memory-subtabs-bar">
        <div className="ai-memory-subtabs" role="tablist" aria-label="AGENTS.md 与记忆中心分区">
          <button
            type="button"
            id="ai-mem-subtab-agents"
            className={`ai-memory-subtab-btn ${section === 'agents_md' ? 'active' : ''}`}
            onClick={() => setSection('agents_md')}
          >
            <FileText size={14} />
            <span>全局 AGENTS.md</span>
            <span className={`tag-chip ${agentsEnabled ? 'teal' : ''}`} style={{ fontSize: 10.5 }}>
              {agentsEnabled ? `v${overview?.agents_md?.revision || 1}` : '已关闭'}
            </span>
          </button>

          <button
            type="button"
            id="ai-mem-subtab-memories"
            className={`ai-memory-subtab-btn ${section === 'memories' ? 'active' : ''}`}
            onClick={() => setSection('memories')}
          >
            <BrainCircuit size={14} />
            <span>长期记忆库</span>
            <span className="nav-badge">{overview?.memories?.length || 0}</span>
          </button>

          <button
            type="button"
            id="ai-mem-subtab-hosts"
            className={`ai-memory-subtab-btn ${section === 'hosts' ? 'active' : ''}`}
            onClick={() => setSection('hosts')}
          >
            <ServerIcon size={14} />
            <span>主机画像 2.0</span>
            <span className="nav-badge">{overview?.host_memories?.length || 0}</span>
          </button>

          <button
            type="button"
            id="ai-mem-subtab-runbooks"
            className={`ai-memory-subtab-btn ${section === 'runbooks' ? 'active' : ''}`}
            onClick={() => setSection('runbooks')}
          >
            <BookOpen size={14} />
            <span>Runbook 技能库</span>
            <span className="nav-badge">{overview?.runbooks?.length || 0}</span>
          </button>
        </div>

        <button
          type="button"
          id="ai-memory-mask-sensitive-btn"
          className={`ai-mask-toggle-btn ${maskSensitive ? 'active' : ''}`}
          aria-pressed={maskSensitive}
          onClick={handleToggleMaskSensitive}
          title={
            maskSensitive
              ? '当前已屏蔽服务器路径、端口、IP 与敏感词汇/信息，点击恢复明文显示'
              : '开启后，Agent 与记忆中心内涉及服务器的路径、端口、IP、主机地址及敏感信息将只显示 ***（仅影响展示，不修改原始数据）'
          }
        >
          <EyeOff size={14} />
          <span>{maskSensitive ? '已屏蔽关键信息' : '一键屏蔽关键信息'}</span>
          {maskSensitive && <span className="ai-mask-pill-badge">***</span>}
        </button>
      </div>

      {maskSensitive && (
        <div className="ai-mask-active-banner" id="ai-memory-mask-banner" role="status">
          <div className="ai-mask-active-banner-text">
            <EyeOff size={14} style={{ flexShrink: 0 }} />
            <span>
              <strong>关键信息屏蔽已开启：</strong>
              涉及服务器的路径、端口、IP、主机地址、敏感词汇及凭据信息均仅显示为{' '}
              <code className="mono">***</code>（仅影响当前页面展示与导出，底层加密资产不受改动）。
            </span>
          </div>
          <button
            type="button"
            id="ai-memory-unmask-btn"
            className="btn btn-sm"
            onClick={() => setMaskSensitive(false)}
          >
            <Eye size={12.5} /> 恢复显示
          </button>
        </div>
      )}

      {/* SECTION 1: Global AGENTS.md Editor + Advanced Context Budget */}
      {section === 'agents_md' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          <section className="sec-panel">
            <div className="ai-agents-header-row">
              <div>
                <h3 style={{ marginBottom: 4 }}>
                  <FileText size={16} style={{ color: 'var(--accent-teal)' }} />
                  全局 AGENTS.md 运维智能体宪章
                  <span className="tag-chip mono" style={{ fontSize: 11 }}>
                    v{overview?.agents_md?.revision || 1}
                  </span>
                  {agentsDirty && <span className="tag-chip amber">未保存修改</span>}
                </h3>
                <p className="sec-panel-desc" style={{ marginBottom: 0 }}>
                  单一全局规范，加密存储于 <code className="mono">secrets.enc</code>，统一作用于「AI 诊断中心」「SSH 终端副驾驶」与「后台定时巡检」。
                </p>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                <label className="ai-toggle-pill">
                  <input
                    type="checkbox"
                    checked={agentsEnabled}
                    disabled={maskSensitive}
                    onChange={(e) => {
                      if (maskSensitive) return;
                      setAgentsEnabled(e.target.checked);
                      setAgentsDirty(true);
                    }}
                  />
                  <span>{agentsEnabled ? '已启用注入' : '已暂停注入'}</span>
                </label>

                <div className="ai-mode-pill-group" role="group" aria-label="编辑器视图模式">
                  <button
                    type="button"
                    className={`ai-mode-pill ${editorMode === 'edit' ? 'active' : ''}`}
                    onClick={() => setEditorMode('edit')}
                    title="纯编辑模式"
                  >
                    <Code2 size={12} /> 编辑
                  </button>
                  <button
                    type="button"
                    className={`ai-mode-pill ${editorMode === 'split' ? 'active' : ''}`}
                    onClick={() => setEditorMode('split')}
                    title="左右分屏实时预览"
                  >
                    <Columns2 size={12} /> 分屏
                  </button>
                  <button
                    type="button"
                    className={`ai-mode-pill ${editorMode === 'preview' ? 'active' : ''}`}
                    onClick={() => setEditorMode('preview')}
                    title="Markdown 渲染预览"
                  >
                    <Eye size={12} /> 预览
                  </button>
                </div>
              </div>
            </div>

            {/* Security Guardrail Notice */}
            <div className="ai-guardrail-notice">
              <ShieldCheck size={14} style={{ color: 'var(--accent-teal)', flexShrink: 0 }} />
              <span>
                <strong>安全边界不可覆盖：</strong>
                底层 HITL 人工审批、毁灭性命令硬熔断与 SSH 凭据物理隔离优先级永远高于 AGENTS.md；AI 仅能提交带 Diff 的规范修订提案，无权直接篡改本文档。
              </span>
            </div>

            {/* Action Toolbar */}
            <div className="ai-agents-toolbar">
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                <button
                  type="button"
                  id="ai-agents-save-btn"
                  className="btn btn-primary btn-sm"
                  disabled={savingAgents || maskSensitive}
                  title={maskSensitive ? '已开启关键信息屏蔽，请先关闭后再保存' : undefined}
                  onClick={() => void handleSaveAgentsMD()}
                >
                  <Save size={13.5} />
                  {savingAgents ? '正在加密保存...' : '加密保存 AGENTS.md'}
                </button>
                <button
                  type="button"
                  className="btn btn-sm"
                  disabled={savingAgents || maskSensitive}
                  title={maskSensitive ? '已开启关键信息屏蔽，请先关闭后再重置' : undefined}
                  onClick={() => void handleResetAgentsMD()}
                >
                  <RotateCcw size={13} /> 重置 SRE 默认模板
                </button>
                <input
                  ref={mdImportInputRef}
                  type="file"
                  accept=".md,.markdown,.txt"
                  style={{ display: 'none' }}
                  onChange={(e) => void handleImportAgentsMD(e)}
                />
                <button
                  type="button"
                  className="btn btn-sm"
                  disabled={maskSensitive}
                  title={maskSensitive ? '已开启关键信息屏蔽，请先关闭后再导入' : undefined}
                  onClick={() => mdImportInputRef.current?.click()}
                >
                  <Upload size={13} /> 导入 .md
                </button>
                <button type="button" className="btn btn-sm" onClick={handleExportAgentsMD}>
                  <Download size={13} /> {maskSensitive ? '导出脱敏 AGENTS.md' : '导出 AGENTS.md'}
                </button>
              </div>

              <div className="mono" style={{ fontSize: 11.5, color: agentsOverBudget ? 'var(--amber-text)' : 'var(--text-muted)' }}>
                {agentsCharCount.toLocaleString()} / {agentsMaxChars.toLocaleString()} 字符预算
                {agentsOverBudget && '（超出部分将按预算截断）'}
              </div>
            </div>

            {/* Markdown Editor / Split / Preview */}
            <div className={`ai-agents-editor-grid mode-${editorMode}`}>
              {editorMode !== 'preview' && (
                <div className="ai-agents-pane">
                  <div className="ai-agents-pane-head">
                    <span>Markdown 源码 (AGENTS.md)</span>
                    {maskSensitive ? (
                      <span className="tag-chip amber" style={{ fontSize: 10.5 }}>
                        关键信息已屏蔽 · 只读保护
                      </span>
                    ) : (
                      <span className="mono">单机差异请维护于「主机画像 2.0」</span>
                    )}
                  </div>
                  <textarea
                    id="ai-agents-md-textarea"
                    className={`ai-agents-textarea mono ${maskSensitive ? 'masked-readonly' : ''}`}
                    value={maskSensitive ? maskedAgentsSource : agentsContent}
                    readOnly={maskSensitive}
                    onChange={(e) => {
                      if (maskSensitive) return;
                      setAgentsContent(e.target.value);
                      setAgentsDirty(true);
                    }}
                    placeholder="# 输入适用于全部受管服务器的运维规范、诊断偏好、安全红线与输出要求..."
                    spellCheck={false}
                  />
                </div>
              )}

              {editorMode !== 'edit' && (
                <div className="ai-agents-pane">
                  <div className="ai-agents-pane-head">
                    <span>实时渲染预览{maskSensitive ? '（已屏蔽关键信息）' : ''}</span>
                    <span>
                      {overview?.agents_md?.updated_at
                        ? `上次保存：${new Date(overview.agents_md.updated_at).toLocaleString('zh-CN')}`
                        : '尚未保存'}
                    </span>
                  </div>
                  <div className="ai-agents-preview-body">
                    {agentsContent.trim() ? (
                      maskSensitive && maskedAgentsMarkdown ? (
                        <FormattedMarkdownText
                          text={maskedAgentsMarkdown.masked}
                          maskSentinel={maskedAgentsMarkdown.sentinel}
                        />
                      ) : (
                        <FormattedMarkdownText text={agentsContent} />
                      )
                    ) : (
                      <div style={{ color: 'var(--text-muted)', fontSize: 12.5 }}>
                        当前 AGENTS.md 为空，点击「重置 SRE 默认模板」可快速填入推荐规范。
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          </section>

          {/* Collapsible Context & Memory Budget Advanced Settings */}
          <section className="sec-panel">
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                cursor: 'pointer',
              }}
              onClick={() => setShowBudgetConfig((v) => !v)}
            >
              <h3 style={{ margin: 0 }}>
                {showBudgetConfig ? <ChevronDown size={15} /> : <ChevronRight size={15} />}
                <Sliders size={15} style={{ color: 'var(--accent-teal)' }} />
                高级上下文预算与自动记忆联动策略
              </h3>
              <span className="mono" style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>
                压缩阈值 {Math.round(budgetDraft.compaction_trigger_ratio * 100)}% · 保留最近{' '}
                {budgetDraft.compaction_keep_recent} 条 · 监控同步{' '}
                {budgetDraft.auto_sync_monitor_to_memory ? '开' : '关'} · 变更记忆{' '}
                {budgetDraft.auto_record_approved_changes ? '开' : '关'}
              </span>
            </div>

            {showBudgetConfig && (
              <form onSubmit={handleSaveBudgetConfig} style={{ marginTop: 14 }}>
                <div className="field-row">
                  <div className="field">
                    <label className="field-label">AGENTS.md 最大注入字符预算 (1000–30000)</label>
                    <input
                      type="number"
                      className="input mono"
                      min={1000}
                      max={30000}
                      value={budgetNumStr.agents_md_max_chars}
                      onChange={(e) =>
                        setBudgetNumStr((prev) => ({ ...prev, agents_md_max_chars: e.target.value }))
                      }
                    />
                  </div>
                  <div className="field">
                    <label className="field-label">长期记忆直注字符预算 (1000–24000)</label>
                    <input
                      type="number"
                      className="input mono"
                      min={1000}
                      max={24000}
                      value={budgetNumStr.memory_prompt_budget_chars}
                      onChange={(e) =>
                        setBudgetNumStr((prev) => ({
                          ...prev,
                          memory_prompt_budget_chars: e.target.value,
                        }))
                      }
                    />
                  </div>
                </div>

                <div className="field-row">
                  <div className="field">
                    <label className="field-label">自动滚动压缩触发阈值 (% 窗口占比，40–90)</label>
                    <input
                      type="number"
                      className="input mono"
                      min={40}
                      max={90}
                      value={budgetNumStr.compaction_trigger_pct}
                      onChange={(e) =>
                        setBudgetNumStr((prev) => ({
                          ...prev,
                          compaction_trigger_pct: e.target.value,
                        }))
                      }
                    />
                  </div>
                  <div className="field">
                    <label className="field-label">压缩后保留最近完整消息条数 (2–20)</label>
                    <input
                      type="number"
                      className="input mono"
                      min={2}
                      max={20}
                      value={budgetNumStr.compaction_keep_recent}
                      onChange={(e) =>
                        setBudgetNumStr((prev) => ({
                          ...prev,
                          compaction_keep_recent: e.target.value,
                        }))
                      }
                    />
                  </div>
                </div>

                <div style={{ display: 'flex', gap: 20, flexWrap: 'wrap', margin: '8px 0 14px' }}>
                  <label style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 13 }}>
                    <input
                      type="checkbox"
                      checked={budgetDraft.auto_sync_monitor_to_memory}
                      onChange={(e) =>
                        setBudgetDraft({
                          ...budgetDraft,
                          auto_sync_monitor_to_memory: e.target.checked,
                        })
                      }
                    />
                    7×24 监控采集到新快照时自动增量同步主机客观画像（绝不覆盖手写备注与红线）
                  </label>
                  <label style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 13 }}>
                    <input
                      type="checkbox"
                      checked={budgetDraft.auto_record_approved_changes}
                      onChange={(e) =>
                        setBudgetDraft({
                          ...budgetDraft,
                          auto_record_approved_changes: e.target.checked,
                        })
                      }
                    />
                    HITL 审批通过执行远程变更（SSH 命令 / SFTP 写配置）后自动沉淀「重要变更」长期记忆
                  </label>
                </div>

                <button type="submit" className="btn btn-primary btn-sm" disabled={savingBudget}>
                  <Save size={13} />
                  {savingBudget ? '保存中...' : '加密保存预算与联动策略'}
                </button>
              </form>
            )}
          </section>
        </div>
      )}

      {/* SECTION 2: Long-Term Cross-Session Memory Store */}
      {section === 'memories' && (
        <section className="sec-panel">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10, marginBottom: 8 }}>
            <div>
              <h3 style={{ marginBottom: 3 }}>
                <BrainCircuit size={16} style={{ color: 'var(--accent-teal)' }} />
                跨会话长期运维记忆库 ({overview?.memories?.length || 0})
              </h3>
              <p className="sec-panel-desc" style={{ marginBottom: 0 }}>
                按「置顶 + 目标主机强相关 + 重要度」自动预算注入 System Prompt，全部长尾记忆均支持 AI 通过{' '}
                <code className="mono">search_memory</code> 按需召回。所有写入自动执行私钥/Token 脱敏。
              </p>
            </div>
            <button
              type="button"
              id="ai-add-memory-btn"
              className="btn btn-primary btn-sm"
              onClick={() => {
                if (maskSensitive) {
                  notifyEditBlockedByMask('新增长期记忆');
                  return;
                }
                setEditingEntry({
                  scope: 'global',
                  server_ids: servers.length > 0 ? [servers[0].id] : [],
                  category: 'preference',
                  title: '',
                  content: '',
                  tags_csv: '',
                  importance: 4,
                  pinned: false,
                });
              }}
            >
              <Plus size={13.5} /> 新增长期记忆
            </button>
          </div>

          {/* Search & Filter Bar */}
          <div className="ai-mem-filter-bar">
            <div style={{ position: 'relative', flex: '1 1 220px', minWidth: 180 }}>
              <Search
                size={13.5}
                style={{
                  position: 'absolute',
                  left: 10,
                  top: '50%',
                  transform: 'translateY(-50%)',
                  color: 'var(--text-muted)',
                }}
              />
              <input
                className="input"
                style={{ paddingLeft: 30, height: 33 }}
                placeholder="检索标题、内容或标签..."
                value={memSearch}
                onChange={(e) => setMemSearch(e.target.value)}
              />
            </div>

            <select
              className="select"
              style={{ width: 'auto', minWidth: 112, height: 33 }}
              value={memScopeFilter}
              onChange={(e) => {
                const next = e.target.value as 'all' | 'global' | 'server';
                setMemScopeFilter(next);
                if (next === 'global') setMemServerFilter('all');
              }}
            >
              <option value="all">全部范围</option>
              <option value="global">仅全局</option>
              <option value="server">仅主机专属</option>
            </select>

            <select
              className="select"
              style={{ width: 'auto', minWidth: 126, height: 33 }}
              value={memCatFilter}
              onChange={(e) => setMemCatFilter(e.target.value)}
            >
              <option value="all">全部分类</option>
              <option value="preference">管理员偏好</option>
              <option value="topology">架构拓扑</option>
              <option value="incident">故障根因</option>
              <option value="change">重要变更</option>
              <option value="lesson">运维经验</option>
            </select>

            {servers.length > 0 && (
              <select
                className="select"
                style={{ width: 'auto', minWidth: 140, height: 33 }}
                value={memServerFilter}
                onChange={(e) => setMemServerFilter(e.target.value)}
              >
                <option value="all">全部关联主机</option>
                {servers.map((s) => (
                  <option key={s.id} value={s.id}>
                    {displayServerName(s.name)}
                  </option>
                ))}
              </select>
            )}
          </div>

          {filteredMemories.length === 0 ? (
            <div className="empty-state" style={{ padding: '36px 16px' }}>
              <Sparkles size={20} style={{ color: 'var(--accent-teal)', marginBottom: 6 }} />
              <h3>暂无匹配的长期运维记忆</h3>
              <p>
                在 AI 排障对话、审批执行配置变更时系统会自动沉淀长期记忆；您也可以点击右上角手动录入团队偏好、集群拓扑或维护窗口约定。
              </p>
            </div>
          ) : (
            <div className="ai-mem-card-grid">
              {filteredMemories.map((m) => (
                <article
                  key={m.id}
                  className={`ai-mem-entry-card ${m.pinned ? 'pinned' : ''}`}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 8 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap', minWidth: 0 }}>
                      {m.pinned && (
                        <span className="tag-chip teal" title="置顶记忆将在每次对话优先注入">
                          <Pin size={10.5} style={{ marginRight: 3 }} /> 置顶
                        </span>
                      )}
                      <strong style={{ fontSize: 13.5, wordBreak: 'break-word' }}>
                        {displayText(m.title)}
                      </strong>
                    </div>

                    <div style={{ display: 'flex', gap: 3, flexShrink: 0 }}>
                      <button
                        type="button"
                        className="btn btn-ghost btn-sm btn-icon"
                        style={m.pinned ? { color: 'var(--accent-teal)' } : undefined}
                        onClick={() => void handleTogglePinMemory(m)}
                        title={m.pinned ? '取消置顶' : '置顶记忆（每次对话必注）'}
                      >
                        <Pin size={13.5} />
                      </button>
                      <button
                        type="button"
                        className="btn btn-ghost btn-sm btn-icon"
                        onClick={() => {
                          if (maskSensitive) {
                            notifyEditBlockedByMask('编辑长期记忆');
                            return;
                          }
                          setEditingEntry({
                            id: m.id,
                            scope: m.scope === 'server' ? 'server' : 'global',
                            server_ids: m.server_ids || [],
                            category: (m.category as AIMemoryCategory) || 'lesson',
                            title: m.title,
                            content: m.content,
                            tags_csv: (m.tags || []).join(', '),
                            importance: m.importance || 3,
                            pinned: m.pinned,
                          });
                        }}
                        title={maskSensitive ? '屏蔽模式下已暂停编辑' : '编辑长期记忆'}
                      >
                        <Edit3 size={13.5} />
                      </button>
                      <button
                        type="button"
                        className="btn btn-ghost btn-sm btn-icon"
                        style={{ color: 'var(--danger-text)' }}
                        onClick={async () => {
                          try {
                            await api.deleteAIMemory(m.id);
                            onNotify(`已删除长期记忆《${displayText(m.title)}》`);
                            await onReloadOverview();
                          } catch (err: any) {
                            onNotify(err?.message || '删除长期记忆失败');
                          }
                        }}
                        title="删除记忆"
                      >
                        <Trash2 size={13.5} />
                      </button>
                    </div>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: 5, flexWrap: 'wrap', marginTop: 6 }}>
                    <span className="tag-chip teal">
                      {MEMORY_CATEGORY_LABELS[m.category] || m.category}
                    </span>
                    <span className="tag-chip">
                      {m.scope === 'global'
                        ? '全局生效'
                        : `主机：${(m.server_ids || [])
                            .map((id) => displayServerName(serverNameById.get(id) || id))
                            .join(', ')}`}
                    </span>
                    <span className="tag-chip">重要度 {m.importance}/5</span>
                    <span className="tag-chip">
                      {MEMORY_SOURCE_LABELS[m.source] || m.source}
                    </span>
                  </div>

                  <div className="ai-mem-entry-content">{displayText(m.content)}</div>

                  <div className="ai-mem-entry-foot">
                    <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap' }}>
                      {(m.tags || []).map((t) => (
                        <span key={t} className="tag-chip mono" style={{ fontSize: 10.5 }}>
                          #{displayText(t)}
                        </span>
                      ))}
                    </div>
                    <span className="mono" style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                      命中 {m.use_count || 0} 次 · {new Date(m.updated_at).toLocaleDateString('zh-CN')}
                    </span>
                  </div>
                </article>
              ))}
            </div>
          )}
        </section>
      )}

      {/* SECTION 3: Enhanced HostMemory 2.0 (Objective Facts + Constraints + Monitor Sync) */}
      {section === 'hosts' && (
        <section className="sec-panel">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10, marginBottom: 8 }}>
            <div>
              <h3 style={{ marginBottom: 3 }}>
                <ServerIcon size={16} style={{ color: 'var(--accent-teal)' }} />
                主机环境画像与运维红线 ({overview?.host_memories?.length || 0})
              </h3>
              <p className="sec-panel-desc" style={{ marginBottom: 0 }}>
                单机架构差异、端口用途、部署路径与避坑红线（Constraints）集中维护于此；7×24 监控快照可自动/一键增量补齐客观字段，绝不覆盖手写备注。
              </p>
            </div>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              {servers.length > 0 && (
                <>
                  <button
                    type="button"
                    id="ai-sync-all-monitor-mem-btn"
                    className="btn btn-teal btn-sm"
                    disabled={syncingMonitorId !== null}
                    onClick={() => void handleSyncMonitorHostMemory('')}
                  >
                    <RefreshCw size={13} />
                    {syncingMonitorId === '__all__' ? '正在同步监控快照...' : '一键从监控快照同步'}
                  </button>
                  <button
                    type="button"
                    id="ai-add-host-mem-btn"
                    className="btn btn-sm"
                    onClick={() => {
                      if (maskSensitive) {
                        notifyEditBlockedByMask('录入主机画像');
                        return;
                      }
                      const unprofiled = servers.find((s) => !hostMemoryByServerId.has(s.id));
                      const targetId = unprofiled ? unprofiled.id : servers[0].id;
                      setEditingHostMemory(buildHostMemoryFormState(targetId, true));
                    }}
                  >
                    <Plus size={13} /> 手工录入画像
                  </button>
                </>
              )}
            </div>
          </div>

          {!overview?.host_memories?.length ? (
            <div className="empty-state" style={{ padding: '36px 16px' }}>
              <ServerIcon size={22} style={{ color: 'var(--accent-teal)', marginBottom: 6 }} />
              <h3>暂无主机环境画像</h3>
              <p>
                执行一次「7×24 监控采集」或点击「一键从监控快照同步」即可自动建立客观画像，也可手工录入单机运维红线与备注。
              </p>
            </div>
          ) : (
            <div className="ai-mem-card-grid">
              {overview.host_memories.map((m: HostMemory) => (
                <article key={m.server_id} className="ai-mem-entry-card">
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 8 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap', minWidth: 0 }}>
                      <strong style={{ fontSize: 14, wordBreak: 'break-word' }}>
                        {displayServerName(m.server_name)}
                      </strong>
                      {m.os_arch && <span className="tag-chip">{displayText(m.os_arch)}</span>}
                      {m.auto_updated_count > 0 && (
                        <span className="tag-chip teal">AI 自学习 {m.auto_updated_count} 次</span>
                      )}
                      {m.monitor_synced_at && (
                        <span className="tag-chip" title={`上次从监控快照同步：${new Date(m.monitor_synced_at).toLocaleString('zh-CN')}`}>
                          监控已同步
                        </span>
                      )}
                    </div>
                    <div style={{ display: 'flex', gap: 3, flexShrink: 0 }}>
                      <button
                        type="button"
                        className="btn btn-ghost btn-sm btn-icon"
                        disabled={syncingMonitorId !== null}
                        onClick={() => void handleSyncMonitorHostMemory(m.server_id)}
                        title="从该主机最新监控快照同步客观字段"
                      >
                        <RefreshCw size={13} />
                      </button>
                      <button
                        type="button"
                        className="btn btn-ghost btn-sm btn-icon"
                        onClick={() => {
                          if (maskSensitive) {
                            notifyEditBlockedByMask('编辑主机画像');
                            return;
                          }
                          setEditingHostMemory({
                            is_new: false,
                            server_id: m.server_id,
                            summary: m.summary,
                            os_arch: m.os_arch || '',
                            key_services_csv: (m.key_services || []).join(', '),
                            deploy_paths_csv: (m.deploy_paths || []).join(', '),
                            ports_note: m.ports_note || '',
                            constraints: m.constraints || '',
                            notes: m.notes || '',
                          });
                        }}
                        title={maskSensitive ? '屏蔽模式下已暂停编辑' : '编辑主机画像与红线'}
                      >
                        <Edit3 size={13.5} />
                      </button>
                      <button
                        type="button"
                        className="btn btn-ghost btn-sm btn-icon"
                        style={{ color: 'var(--danger-text)' }}
                        onClick={async () => {
                          try {
                            await api.deleteHostMemory(m.server_id);
                            onNotify('已清空该主机环境画像');
                            await onReloadOverview();
                          } catch (err: any) {
                            onNotify(err?.message || '清空主机画像失败');
                          }
                        }}
                        title="清空画像"
                      >
                        <Trash2 size={13.5} />
                      </button>
                    </div>
                  </div>

                  {m.summary && (
                    <div style={{ fontSize: 12.5, marginTop: 6, color: 'var(--text-secondary)', wordBreak: 'break-word' }}>
                      {displayText(m.summary)}
                    </div>
                  )}

                  {m.constraints && (
                    <div className="ai-constraint-banner" style={{ marginTop: 8 }}>
                      <AlertTriangle size={13} style={{ flexShrink: 0 }} />
                      <span>
                        <strong>运维红线 / 避坑禁忌：</strong>
                        {displayText(m.constraints)}
                      </span>
                    </div>
                  )}

                  {m.ports_note && (
                    <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 7, wordBreak: 'break-word' }}>
                      <strong>端口用途：</strong>
                      <span className="mono">{displayPortsNote(m.ports_note)}</span>
                    </div>
                  )}

                  {m.notes && (
                    <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 5, wordBreak: 'break-word', whiteSpace: 'pre-wrap' }}>
                      <strong>补充备注：</strong>
                      {displayText(m.notes)}
                    </div>
                  )}

                  {(m.key_services?.length > 0 || m.deploy_paths?.length > 0) && (
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5, marginTop: 9 }}>
                      {(m.key_services || []).map((svc) => (
                        <span key={svc} className="tag-chip teal">
                          {displayServiceName(svc)}
                        </span>
                      ))}
                      {(m.deploy_paths || []).map((dp) => (
                        <span key={dp} className="tag-chip mono">
                          {displayDeployPath(dp)}
                        </span>
                      ))}
                    </div>
                  )}
                </article>
              ))}
            </div>
          )}
        </section>
      )}

      {/* SECTION 4: Troubleshooting Runbooks */}
      {section === 'runbooks' && (
        <section className="sec-panel">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10, marginBottom: 8 }}>
            <div>
              <h3 style={{ marginBottom: 3 }}>
                <BookOpen size={16} style={{ color: 'var(--accent-teal)' }} />
                排障技能 Runbook 库 ({overview?.runbooks?.length || 0})
              </h3>
              <p className="sec-panel-desc" style={{ marginBottom: 0 }}>
                System Prompt 自动挂载全部 Runbook 轻量索引，排查命中相关症状时 AI 通过{' '}
                <code className="mono">get_runbook</code> 按需调阅完整诊断步骤、修复命令与验证方案。
              </p>
            </div>
            <button
              type="button"
              className="btn btn-primary btn-sm"
              onClick={() => {
                if (maskSensitive) {
                  notifyEditBlockedByMask('新建 Runbook');
                  return;
                }
                setEditingRunbook({
                  title: '',
                  category: '安全加固',
                  symptom: '',
                  root_cause: '',
                  diagnostic_steps_text: '',
                  fix_commands_text: '',
                  verification: '',
                  sync_snippet: true,
                });
              }}
            >
              <Plus size={13} /> 新建 Runbook
            </button>
          </div>

          <div className="ai-mem-card-grid">
            {(overview?.runbooks || []).map((rb) => (
              <article key={rb.id} className="ai-mem-entry-card">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 8 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 7, flexWrap: 'wrap', minWidth: 0 }}>
                    <strong style={{ fontSize: 13.5, wordBreak: 'break-word' }}>
                      {displayText(rb.title)}
                    </strong>
                    <span className="tag-chip teal">{displayText(rb.category)}</span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 4, flexShrink: 0 }}>
                    <button
                      type="button"
                      className="btn btn-sm"
                      style={{ height: 25, fontSize: 11.5 }}
                      onClick={() => void onLaunchRunbook(rb)}
                    >
                      <Play size={11} /> 发起排障
                    </button>
                    <button
                      type="button"
                      className="btn btn-ghost btn-sm btn-icon"
                      onClick={() => {
                        if (maskSensitive) {
                          notifyEditBlockedByMask('编辑 Runbook');
                          return;
                        }
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
                        });
                      }}
                      title={maskSensitive ? '屏蔽模式下已暂停编辑' : '编辑 Runbook'}
                    >
                      <Edit3 size={13.5} />
                    </button>
                    <button
                      type="button"
                      className="btn btn-ghost btn-sm btn-icon"
                      style={{ color: 'var(--danger-text)' }}
                      onClick={async () => {
                        try {
                          await api.deleteRunbook(rb.id);
                          onNotify('已删除该 Runbook');
                          await onReloadOverview();
                        } catch (err: any) {
                          onNotify(err?.message || '删除 Runbook 失败');
                        }
                      }}
                    >
                      <Trash2 size={13.5} />
                    </button>
                  </div>
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 6, wordBreak: 'break-word' }}>
                  <strong>适用症状：</strong>
                  {displayText(rb.symptom)}
                </div>
                {rb.root_cause && (
                  <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 4, wordBreak: 'break-word' }}>
                    <strong>典型根因：</strong>
                    {displayText(rb.root_cause)}
                  </div>
                )}
                {rb.fix_commands?.length > 0 && (
                  <div className="copilot-cmd-box" style={{ marginTop: 8 }}>
                    <code style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                      {displayText(rb.fix_commands.join(' && '))}
                    </code>
                  </div>
                )}
              </article>
            ))}
          </div>
        </section>
      )}

      {/* Modal: Create/Edit Long-Term Memory Entry */}
      {editingEntry && (
        <div className="modal-backdrop" onClick={() => setEditingEntry(null)}>
          <div className="modal-panel wide" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>{editingEntry.id ? '编辑长期运维记忆' : '新增长期运维记忆'}</h3>
              <button type="button" className="btn btn-ghost btn-sm" onClick={() => setEditingEntry(null)}>
                关闭
              </button>
            </div>
            <form onSubmit={handleSaveMemoryEntry}>
              <div className="modal-body">
                <div className="field-row">
                  <div className="field">
                    <label className="field-label">记忆作用范围</label>
                    <select
                      className="select"
                      value={editingEntry.scope}
                      onChange={(e) =>
                        setEditingEntry({
                          ...editingEntry,
                          scope: e.target.value as 'global' | 'server',
                        })
                      }
                    >
                      <option value="global">全局记忆（适用于所有受管主机）</option>
                      <option value="server">主机专属记忆（仅在选中目标主机时直注）</option>
                    </select>
                  </div>
                  <div className="field">
                    <label className="field-label">记忆分类</label>
                    <select
                      className="select"
                      value={editingEntry.category}
                      onChange={(e) =>
                        setEditingEntry({
                          ...editingEntry,
                          category: e.target.value as AIMemoryCategory,
                        })
                      }
                    >
                      <option value="preference">管理员偏好 (preference)</option>
                      <option value="topology">架构拓扑 (topology)</option>
                      <option value="incident">故障根因 (incident)</option>
                      <option value="change">重要变更 (change)</option>
                      <option value="lesson">运维经验 (lesson)</option>
                    </select>
                  </div>
                </div>

                {editingEntry.scope === 'server' && servers.length > 0 && (
                  <div className="field">
                    <label className="field-label">关联服务器（可多选）</label>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                      {servers.map((srv) => {
                        const checked = editingEntry.server_ids.includes(srv.id);
                        return (
                          <button
                            key={srv.id}
                            type="button"
                            className={`ai-server-chip ${checked ? 'selected' : ''}`}
                            onClick={() => {
                              const next = checked
                                ? editingEntry.server_ids.filter((id) => id !== srv.id)
                                : [...editingEntry.server_ids, srv.id];
                              setEditingEntry({ ...editingEntry, server_ids: next });
                            }}
                          >
                            <ServerIcon size={11.5} />
                            <span>{srv.name}</span>
                          </button>
                        );
                      })}
                    </div>
                  </div>
                )}

                <div className="field">
                  <label className="field-label">记忆标题</label>
                  <input
                    className="input"
                    value={editingEntry.title}
                    onChange={(e) => setEditingEntry({ ...editingEntry, title: e.target.value })}
                    placeholder="例如：生产窗口变更前先备份配置且禁止在高峰期重启主库"
                    required
                  />
                </div>

                <div className="field">
                  <label className="field-label">记忆正文（严禁填写密码、私钥或 API Key，系统将自动脱敏）</label>
                  <textarea
                    className="input"
                    rows={4}
                    style={{ height: 'auto', padding: 10, lineHeight: 1.55 }}
                    value={editingEntry.content}
                    onChange={(e) => setEditingEntry({ ...editingEntry, content: e.target.value })}
                    placeholder="详细描述偏好规则、服务间依赖拓扑、历史故障根因或关键变更说明..."
                    required
                  />
                </div>

                <div className="field-row">
                  <div className="field">
                    <label className="field-label">检索标签（逗号分隔）</label>
                    <input
                      className="input mono"
                      value={editingEntry.tags_csv}
                      onChange={(e) => setEditingEntry({ ...editingEntry, tags_csv: e.target.value })}
                      placeholder="nginx, redis, maintenance"
                    />
                  </div>
                  <div className="field">
                    <label className="field-label">重要度等级 (1–5)</label>
                    <select
                      className="select"
                      value={editingEntry.importance}
                      onChange={(e) =>
                        setEditingEntry({ ...editingEntry, importance: Number(e.target.value) || 3 })
                      }
                    >
                      <option value={5}>5 - 极高（核心红线 / 必读架构）</option>
                      <option value={4}>4 - 高（高频偏好 / 重要变更）</option>
                      <option value={3}>3 - 中（常规经验与排障结论）</option>
                      <option value={2}>2 - 低（背景参考）</option>
                      <option value={1}>1 - 存档（仅按需检索）</option>
                    </select>
                  </div>
                </div>

                <label style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 13 }}>
                  <input
                    type="checkbox"
                    checked={editingEntry.pinned}
                    onChange={(e) => setEditingEntry({ ...editingEntry, pinned: e.target.checked })}
                  />
                  置顶该记忆（不受排序淘汰影响，优先注入每次会话与后台巡检）
                </label>
              </div>
              <div className="modal-footer">
                <button type="button" className="btn" onClick={() => setEditingEntry(null)}>
                  取消
                </button>
                <button type="submit" className="btn btn-primary">
                  加密保存长期记忆
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: Edit Host Memory 2.0 (All fields including ports_note, constraints, notes) */}
      {editingHostMemory && (
        <div className="modal-backdrop" onClick={() => setEditingHostMemory(null)}>
          <div className="modal-panel wide" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>维护主机环境画像与运维红线</h3>
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                onClick={() => setEditingHostMemory(null)}
              >
                关闭
              </button>
            </div>
            <form onSubmit={handleSaveHostMemoryModal}>
              <div className="modal-body">
                <div className="field-row">
                  <div className="field">
                    <label className="field-label">
                      目标服务器{editingHostMemory.is_new && hostMemoryByServerId.has(editingHostMemory.server_id) ? '（已载入现有画像）' : ''}
                    </label>
                    <select
                      className="select"
                      disabled={!editingHostMemory.is_new}
                      value={editingHostMemory.server_id}
                      onChange={(e) =>
                        setEditingHostMemory(buildHostMemoryFormState(e.target.value, true))
                      }
                    >
                      {servers.map((s) => (
                        <option key={s.id} value={s.id}>
                          {s.name} ({s.host}){hostMemoryByServerId.has(s.id) ? ' · 已有画像' : ''}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div className="field">
                    <label className="field-label">系统发行版与内核架构</label>
                    <input
                      className="input mono"
                      value={editingHostMemory.os_arch}
                      onChange={(e) =>
                        setEditingHostMemory({ ...editingHostMemory, os_arch: e.target.value })
                      }
                      placeholder="Debian 12 / Linux 6.1 x86_64"
                    />
                  </div>
                </div>

                <div className="field">
                  <label className="field-label">业务角色与职责摘要</label>
                  <input
                    className="input"
                    value={editingHostMemory.summary}
                    onChange={(e) =>
                      setEditingHostMemory({ ...editingHostMemory, summary: e.target.value })
                    }
                    placeholder="例如：生产核心 Nginx 反向代理网关 + Docker 业务节点"
                    required
                  />
                </div>

                <div className="field-row">
                  <div className="field">
                    <label className="field-label">核心服务组件（逗号分隔）</label>
                    <input
                      className="input mono"
                      value={editingHostMemory.key_services_csv}
                      onChange={(e) =>
                        setEditingHostMemory({
                          ...editingHostMemory,
                          key_services_csv: e.target.value,
                        })
                      }
                      placeholder="nginx, postgresql, redis, docker"
                    />
                  </div>
                  <div className="field">
                    <label className="field-label">关键配置与部署路径（逗号分隔）</label>
                    <input
                      className="input mono"
                      value={editingHostMemory.deploy_paths_csv}
                      onChange={(e) =>
                        setEditingHostMemory({
                          ...editingHostMemory,
                          deploy_paths_csv: e.target.value,
                        })
                      }
                      placeholder="/etc/nginx/conf.d, /srv/app, /var/log/nginx"
                    />
                  </div>
                </div>

                <div className="field">
                  <label className="field-label">重要监听端口与业务用途说明 (ports_note)</label>
                  <input
                    className="input mono"
                    value={editingHostMemory.ports_note}
                    onChange={(e) =>
                      setEditingHostMemory({ ...editingHostMemory, ports_note: e.target.value })
                    }
                    placeholder="443(公网HTTPS入口), 8080(内部管理API), 5432(仅内网PostgreSQL)"
                  />
                </div>

                <div className="field">
                  <label className="field-label">⚠️ 该主机专属运维红线 / 避坑禁忌 (constraints)</label>
                  <textarea
                    className="input"
                    rows={2}
                    style={{ height: 'auto', padding: 10, lineHeight: 1.5 }}
                    value={editingHostMemory.constraints}
                    onChange={(e) =>
                      setEditingHostMemory({ ...editingHostMemory, constraints: e.target.value })
                    }
                    placeholder="例如：工作日 09:00-21:00 严禁直接 restart postgresql；修改 nginx 必须先执行 nginx -t 并保留备份"
                  />
                </div>

                <div className="field">
                  <label className="field-label">管理员补充备注 (notes)</label>
                  <textarea
                    className="input"
                    rows={2}
                    style={{ height: 'auto', padding: 10, lineHeight: 1.5 }}
                    value={editingHostMemory.notes}
                    onChange={(e) =>
                      setEditingHostMemory({ ...editingHostMemory, notes: e.target.value })
                    }
                    placeholder="例如：上游依赖 db-primary-01，凌晨 03:00 执行 pg_dump 定时备份期间磁盘 IO 会短暂升高"
                  />
                </div>
              </div>
              <div className="modal-footer">
                <button type="button" className="btn" onClick={() => setEditingHostMemory(null)}>
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
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                onClick={() => setEditingRunbook(null)}
              >
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
                <div className="field">
                  <label className="field-label">修复后验证方法</label>
                  <input
                    className="input"
                    value={editingRunbook.verification}
                    onChange={(e) =>
                      setEditingRunbook({ ...editingRunbook, verification: e.target.value })
                    }
                    placeholder="例如：curl -I 检查响应码为 200 且 error.log 无新报错"
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

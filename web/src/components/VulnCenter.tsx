import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Bot,
  Check,
  CheckCheck,
  CheckCircle2,
  Clock,
  Copy,
  ExternalLink,
  Eye,
  EyeOff,
  Flame,
  Globe,
  Pause,
  Play,
  Plus,
  RefreshCw,
  Search,
  Settings2,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  Star,
  Trash2,
  X,
} from 'lucide-react';
import { api } from '../api';
import { copyTextToClipboard } from '../utils/clipboard';
import type {
  ServerView,
  VulnAdvisory,
  VulnAIAnalysis,
  VulnAppCategoryInfo,
  VulnAppDefinition,
  VulnAppPreset,
  VulnCustomApp,
  VulnKPIStats,
  VulnOverviewResponse,
  VulnRuntimeStatus,
  VulnSettingsView,
  VulnSeverity,
} from '../types';

export interface VulnCenterProps {
  servers: ServerView[];
  onUnreadHighChange?: (count: number) => void;
  onDiagnoseWithAI: (serverId: string, prompt: string) => void;
  onOpenQQBotNotifications?: () => void;
  onNotify: (msg: string) => void;
}

const SEVERITY_META: Record<
  VulnSeverity,
  { label: string; short: string; order: number }
> = {
  critical: { label: '严重 Critical', short: '严重', order: 1 },
  high: { label: '高危 High', short: '高危', order: 2 },
  medium: { label: '中危 Medium', short: '中危', order: 3 },
  low: { label: '低危 Low', short: '低危', order: 4 },
  unknown: { label: '未评级', short: '未评级', order: 5 },
};

const ALL_SEVERITIES: VulnSeverity[] = ['critical', 'high', 'medium', 'low', 'unknown'];

const OSV_ECOSYSTEM_OPTIONS = [
  'Go',
  'npm',
  'PyPI',
  'Maven',
  'Packagist',
  'Debian',
  'Ubuntu',
  'Alpine',
  'crates.io',
  'RubyGems',
  'NuGet',
  'Linux',
];

function formatRelTime(iso?: string): string {
  if (!iso) return '—';
  const ts = new Date(iso).getTime();
  if (!Number.isFinite(ts) || ts <= 0) return '—';
  const diffSec = Math.floor((Date.now() - ts) / 1000);
  if (diffSec < 0) return new Date(ts).toLocaleDateString('zh-CN');
  if (diffSec < 60) return '刚刚';
  const mins = Math.floor(diffSec / 60);
  if (mins < 60) return `${mins} 分钟前`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs} 小时前`;
  const days = Math.floor(hrs / 24);
  if (days < 30) return `${days} 天前`;
  return new Date(ts).toLocaleDateString('zh-CN');
}

function formatFullDateTime(iso?: string): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (!Number.isFinite(d.getTime()) || d.getFullYear() < 1990) return '—';
  return d.toLocaleString('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function advisoryDisplayTime(a: VulnAdvisory): string {
  const pub = a.published_at && new Date(a.published_at).getFullYear() >= 1990 ? a.published_at : '';
  const mod = a.modified_at && new Date(a.modified_at).getFullYear() >= 1990 ? a.modified_at : '';
  if (pub && mod) {
    return new Date(mod).getTime() > new Date(pub).getTime() ? mod : pub;
  }
  return pub || mod || a.first_seen_at;
}

export const VulnCenter: React.FC<VulnCenterProps> = ({
  servers,
  onUnreadHighChange,
  onDiagnoseWithAI,
  onOpenQQBotNotifications,
  onNotify,
}) => {
  // Core Overview State
  const [advisories, setAdvisories] = useState<VulnAdvisory[]>([]);
  const [totalMatched, setTotalMatched] = useState(0);
  const [hasMore, setHasMore] = useState(false);
  const [ticker, setTicker] = useState<VulnAdvisory[]>([]);
  const [kpi, setKPI] = useState<VulnKPIStats | null>(null);
  const [settings, setSettings] = useState<VulnSettingsView | null>(null);
  const [catalog, setCatalog] = useState<VulnAppDefinition[]>([]);
  const [categories, setCategories] = useState<VulnAppCategoryInfo[]>([]);
  const [presets, setPresets] = useState<VulnAppPreset[]>([]);
  const [runtime, setRuntime] = useState<VulnRuntimeStatus | null>(null);

  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [syncingManual, setSyncingManual] = useState(false);

  // Rolling update banner state
  const [pendingNewCount, setPendingNewCount] = useState(0);
  const [freshHighlightIds, setFreshHighlightIds] = useState<Record<string, boolean>>({});
  const lastLoadedAtRef = useRef<string>(new Date().toISOString());
  const prevKnownIdsRef = useRef<Set<string>>(new Set());
  const [tickerPaused, setTickerPaused] = useState(false);

  // Multi-dimensional filters
  const [triageState, setTriageState] = useState<'all' | 'unread' | 'starred' | 'ignored'>('all');
  const [selectedApps, setSelectedApps] = useState<string[]>([]);
  const [selectedSeverities, setSelectedSeverities] = useState<VulnSeverity[]>([]);
  const [kevOnly, setKevOnly] = useState(false);
  const [fixedOnly, setFixedOnly] = useState(false);
  const [daysFilter, setDaysFilter] = useState<number>(0);
  const [searchInput, setSearchInput] = useState('');
  const [searchQuery, setSearchQuery] = useState('');

  // Detail Drawer & AI Analysis state
  const [activeAdvisory, setActiveAdvisory] = useState<VulnAdvisory | null>(null);
  const [aiExplainingId, setAiExplainingId] = useState<string>('');
  const [aiError, setAiError] = useState<string>('');
  const [aiTargetServerId, setAiTargetServerId] = useState<string>('');
  const [copiedId, setCopiedId] = useState<string>('');

  // Self-select Watched Apps Modal
  const [appPickerOpen, setAppPickerOpen] = useState(false);
  const [pickerTab, setPickerTab] = useState<'builtin' | 'custom'>('builtin');
  const [pickerSearch, setPickerSearch] = useState('');
  const [draftWatchedIds, setDraftWatchedIds] = useState<string[]>([]);
  const [draftCustomApps, setDraftCustomApps] = useState<VulnCustomApp[]>([]);
  const [savingApps, setSavingApps] = useState(false);
  const [newCustomKind, setNewCustomKind] = useState<'github_repo' | 'osv_package'>('github_repo');
  const [newCustomName, setNewCustomName] = useState('');
  const [newCustomRepo, setNewCustomRepo] = useState('');
  const [newCustomEco, setNewCustomEco] = useState('Go');
  const [newCustomPkg, setNewCustomPkg] = useState('');
  const [addingCustom, setAddingCustom] = useState(false);

  // Sync / Network / Webhook Settings Modal
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [settingsTab, setSettingsTab] = useState<'sources' | 'sync'>('sources');
  const [cfgEnabled, setCfgEnabled] = useState(true);
  const [cfgInterval, setCfgInterval] = useState(30);
  const [cfgRetention, setCfgRetention] = useState(90);
  const [cfgProxy, setCfgProxy] = useState('');
  const [cfgClearProxy, setCfgClearProxy] = useState(false);
  const [cfgToken, setCfgToken] = useState('');
  const [cfgClearToken, setCfgClearToken] = useState(false);
  const [cfgNotifyWebhook, setCfgNotifyWebhook] = useState(false);
  const [cfgNotifyMinSev, setCfgNotifyMinSev] = useState<VulnSeverity>('critical');
  const [cfgNotifyKEVOnly, setCfgNotifyKEVOnly] = useState(false);
  const [cfgReusePatrolWH, setCfgReusePatrolWH] = useState(true);
  const [cfgCustomWH, setCfgCustomWH] = useState('');
  const [cfgClearWH, setCfgClearWH] = useState(false);
  const [savingSettings, setSavingSettings] = useState(false);
  const [testingWebhook, setTestingWebhook] = useState(false);

  // Debounce search input
  useEffect(() => {
    const t = window.setTimeout(() => {
      setSearchQuery(searchInput.trim());
    }, 220);
    return () => window.clearTimeout(t);
  }, [searchInput]);

  // Default AI target server to first available server
  useEffect(() => {
    if (!aiTargetServerId && servers.length > 0) {
      setAiTargetServerId(servers[0].id);
    }
  }, [aiTargetServerId, servers]);

  const applyOverviewResponse = useCallback(
    (res: VulnOverviewResponse, append = false, markFresh = false) => {
      const incoming = res.advisories || [];
      if (markFresh && prevKnownIdsRef.current.size > 0) {
        const freshMap: Record<string, boolean> = {};
        for (const item of incoming) {
          if (!prevKnownIdsRef.current.has(item.id)) {
            freshMap[item.id] = true;
          }
        }
        if (Object.keys(freshMap).length > 0) {
          setFreshHighlightIds(freshMap);
          window.setTimeout(() => setFreshHighlightIds({}), 9000);
        }
      }
      if (append) {
        setAdvisories((prev) => {
          const seen = new Set(prev.map((x) => x.id));
          const merged = [...prev];
          for (const item of incoming) {
            if (!seen.has(item.id)) merged.push(item);
          }
          return merged;
        });
      } else {
        setAdvisories(incoming);
        prevKnownIdsRef.current = new Set(incoming.map((x) => x.id));
        lastLoadedAtRef.current = new Date().toISOString();
        setPendingNewCount(0);
      }

      setTotalMatched(res.total_matched || 0);
      setHasMore(Boolean(res.has_more));
      setTicker(res.ticker || []);
      setKPI(res.kpi || null);
      setSettings(res.settings || null);
      setCatalog(res.catalog || []);
      setCategories(res.categories || []);
      setPresets(res.presets || []);
      setRuntime(res.runtime || null);
      onUnreadHighChange?.(res.kpi?.unread_critical_high || 0);

      // Keep active drawer synced with freshest data
      setActiveAdvisory((cur) => {
        if (!cur) return null;
        const found = incoming.find((x) => x.id === cur.id) || (res.ticker || []).find((x) => x.id === cur.id);
        return found ? { ...cur, ...found } : cur;
      });
    },
    [onUnreadHighChange]
  );

  const loadOverview = useCallback(
    async (opts?: { silent?: boolean; append?: boolean; offset?: number; markFresh?: boolean }) => {
      const append = Boolean(opts?.append);
      if (append) {
        setLoadingMore(true);
      } else if (!opts?.silent) {
        setLoading(true);
      }
      try {
        const res = await api.getVulnOverview({
          apps: selectedApps,
          severities: selectedSeverities,
          state: triageState,
          kev_only: kevOnly,
          fixed_only: fixedOnly,
          days: daysFilter,
          search: searchQuery,
          limit: 40,
          offset: opts?.offset || 0,
        });
        applyOverviewResponse(res, append, Boolean(opts?.markFresh));
      } catch (err: any) {
        if (!opts?.silent) {
          onNotify(err?.message || '加载漏洞监测数据失败');
        }
      } finally {
        setLoading(false);
        setLoadingMore(false);
      }
    },
    [
      selectedApps,
      selectedSeverities,
      triageState,
      kevOnly,
      fixedOnly,
      daysFilter,
      searchQuery,
      applyOverviewResponse,
      onNotify,
    ]
  );

  useEffect(() => {
    void loadOverview();
  }, [loadOverview]);

  // Silent rolling-update polling every 45s while page stays open (or every 4s while backend is actively syncing)
  useEffect(() => {
    const isSyncing = Boolean(runtime?.syncing);
    const intervalMs = isSyncing ? 4000 : 45000;
    const timer = window.setInterval(async () => {
      try {
        const probe = await api.getVulnOverview({
          state: triageState,
          since: lastLoadedAtRef.current,
          limit: 1,
        });
        setRuntime(probe.runtime || null);
        if (probe.kpi) {
          setKPI(probe.kpi);
          onUnreadHighChange?.(probe.kpi.unread_critical_high || 0);
        }
        if (probe.ticker) {
          setTicker(probe.ticker);
        }
        if (isSyncing && !probe.runtime?.syncing) {
          // Background sync just finished — refresh list smoothly and highlight newly arrived advisories!
          void loadOverview({ silent: true, markFresh: true });
        } else if ((probe.new_since_count || 0) > 0) {
          setPendingNewCount(probe.new_since_count);
        }
      } catch {
        // Ignore transient background poll errors
      }
    }, intervalMs);
    return () => window.clearInterval(timer);
  }, [runtime?.syncing, triageState, loadOverview, onUnreadHighChange]);

  // Close drawer / modals on Escape
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        if (appPickerOpen) setAppPickerOpen(false);
        else if (settingsOpen) setSettingsOpen(false);
        else if (activeAdvisory) setActiveAdvisory(null);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [appPickerOpen, settingsOpen, activeAdvisory]);

  const watchedCatalogApps = useMemo(
    () => catalog.filter((a) => a.watched),
    [catalog]
  );

  const handleManualSync = async () => {
    if (syncingManual || runtime?.syncing) return;
    setSyncingManual(true);
    try {
      const res = await api.syncVulnsNow();
      setRuntime(res.runtime || null);
      if (res.ok) {
        onNotify(
          res.new_count > 0
            ? `官方漏洞同步完成：新增 ${res.new_count} 条最新漏洞动态（本次共拉取 ${res.fetched_count} 条）`
            : `官方漏洞同步完成：已检查最新官方源（共 ${res.fetched_count} 条记录）`
        );
      } else {
        onNotify(res.error || '部分官方数据源同步异常，请点击「同步配置」查看诊断详情');
      }
      await loadOverview({ silent: true, markFresh: true });
    } catch (err: any) {
      onNotify(err?.message || '触发漏洞同步失败');
    } finally {
      setSyncingManual(false);
    }
  };

  const handleOpenDetail = async (adv: VulnAdvisory) => {
    setActiveAdvisory(adv);
    setAiError('');
    if (!adv.is_read) {
      try {
        const res = await api.updateVulnState({ id: adv.id, read: true });
        onUnreadHighChange?.(res.vuln_unread_high);
        setAdvisories((prev) =>
          prev.map((x) => (x.id === adv.id ? { ...x, is_read: true, is_new: false } : x))
        );
        setActiveAdvisory((cur) => (cur && cur.id === adv.id ? { ...cur, is_read: true, is_new: false } : cur));
        setKPI((prev) =>
          prev
            ? {
                ...prev,
                unread_total: Math.max(0, prev.unread_total - 1),
                unread_critical_high: res.vuln_unread_high,
              }
            : prev
        );
      } catch {
        // Non-blocking read mark
      }
    }
  };

  const handleToggleState = async (
    adv: VulnAdvisory,
    patch: { read?: boolean; starred?: boolean; ignored?: boolean },
    e?: React.MouseEvent
  ) => {
    e?.stopPropagation();
    try {
      const res = await api.updateVulnState({ id: adv.id, ...patch });
      onUnreadHighChange?.(res.vuln_unread_high);
      if (patch.ignored !== undefined) {
        onNotify(patch.ignored ? `已忽略 ${adv.id}` : `已恢复显示 ${adv.id}`);
        if (activeAdvisory?.id === adv.id && patch.ignored) {
          setActiveAdvisory(null);
        }
        await loadOverview({ silent: true });
        return;
      }
      setAdvisories((prev) =>
        prev.map((x) =>
          x.id === adv.id
            ? {
                ...x,
                is_read: patch.read !== undefined ? patch.read : x.is_read,
                is_starred: patch.starred !== undefined ? patch.starred : x.is_starred,
                is_new: patch.read ? false : x.is_new,
              }
            : x
        )
      );
      setActiveAdvisory((cur) =>
        cur && cur.id === adv.id
          ? {
              ...cur,
              is_read: patch.read !== undefined ? patch.read : cur.is_read,
              is_starred: patch.starred !== undefined ? patch.starred : cur.is_starred,
              is_new: patch.read ? false : cur.is_new,
            }
          : cur
      );
      if (patch.starred !== undefined) {
        setKPI((prev) =>
          prev
            ? { ...prev, starred_total: Math.max(0, prev.starred_total + (patch.starred ? 1 : -1)) }
            : prev
        );
      }
    } catch (err: any) {
      onNotify(err?.message || '更新状态失败');
    }
  };

  const handleMarkAllRead = async () => {
    try {
      const res = await api.markAllVulnsRead();
      onUnreadHighChange?.(res.vuln_unread_high);
      onNotify('已将当前全部漏洞动态标记为已读');
      await loadOverview({ silent: true });
    } catch (err: any) {
      onNotify(err?.message || '标记全部已读失败');
    }
  };

  const handleCopyText = async (text: string, key: string) => {
    try {
      await copyTextToClipboard(text);
      setCopiedId(key);
      window.setTimeout(() => setCopiedId((cur) => (cur === key ? '' : cur)), 1800);
      onNotify(`已复制 ${text}`);
    } catch {
      onNotify('复制失败，请手动选中文本复制');
    }
  };

  const handleExplainWithAI = async (adv: VulnAdvisory, force = false) => {
    if (aiExplainingId) return;
    setAiExplainingId(adv.id);
    setAiError('');
    try {
      const res = await api.explainVuln(adv.id, force);
      const analysis: VulnAIAnalysis = res.analysis;
      setActiveAdvisory((cur) => (cur && cur.id === adv.id ? { ...cur, ai_analysis: analysis } : cur));
      setAdvisories((prev) =>
        prev.map((x) => (x.id === adv.id ? { ...x, ai_analysis: analysis } : x))
      );
      onNotify('AI 中文解读与修复建议已生成并本地缓存');
    } catch (err: any) {
      const msg = err?.message || '调用 AI 解读失败';
      setAiError(msg);
      onNotify(msg);
    } finally {
      setAiExplainingId('');
    }
  };

  const handleJumpAIOpsCheck = (adv: VulnAdvisory) => {
    const targetId = aiTargetServerId || servers[0]?.id || '';
    const appLabel = (adv.app_names || []).join(' / ') || '相关应用';
    const fixLabel = adv.fixed_version || '官方最新补丁版本';
    const prompt = [
      `请使用只读命令排查当前受管服务器是否安装或运行了受漏洞 ${adv.id} 影响的 ${appLabel}：`,
      `- 漏洞等级：${SEVERITY_META[adv.severity]?.label || adv.severity}${adv.cvss_score ? ` (CVSS ${adv.cvss_score.toFixed(1)})` : ''}${adv.is_kev ? ' · 已知在野利用 (CISA KEV)' : ''}`,
      `- 漏洞标题：${adv.title}`,
      adv.affected_text ? `- 受影响版本：${adv.affected_text}` : '',
      `- 官方修复版本：${fixLabel}`,
      '',
      '请先核查本机对应软件版本与运行状态，判断是否命中该漏洞；若受影响，请给出安全可回滚的升级或缓解方案（不要自动执行变更）。',
    ]
      .filter(Boolean)
      .join('\n');
    setActiveAdvisory(null);
    onDiagnoseWithAI(targetId, prompt);
  };

  // --- Self-select Watched Apps Modal Helpers ---

  const openAppPicker = () => {
    setDraftWatchedIds(settings?.watched_app_ids ? [...settings.watched_app_ids] : []);
    setDraftCustomApps(settings?.custom_apps ? settings.custom_apps.map((c) => ({ ...c })) : []);
    setPickerSearch('');
    setPickerTab('builtin');
    setAppPickerOpen(true);
  };

  const toggleDraftBuiltinApp = (appId: string) => {
    setDraftWatchedIds((prev) =>
      prev.includes(appId) ? prev.filter((id) => id !== appId) : [...prev, appId]
    );
  };

  const toggleDraftCategory = (catId: string, selectAll: boolean) => {
    const idsInCat = catalog.filter((a) => !a.is_custom && a.category === catId).map((a) => a.id);
    setDraftWatchedIds((prev) => {
      const set = new Set(prev);
      for (const id of idsInCat) {
        if (selectAll) set.add(id);
        else set.delete(id);
      }
      return Array.from(set);
    });
  };

  const applyPresetToDraft = (preset: VulnAppPreset) => {
    setDraftWatchedIds([...preset.app_ids]);
    onNotify(`已勾选预设「${preset.name}」（共 ${preset.app_ids.length} 款），点击保存立即生效`);
  };

  const handleSaveWatchedApps = async () => {
    setSavingApps(true);
    try {
      const res = await api.updateVulnConfig({
        watched_app_ids: draftWatchedIds,
        custom_apps: draftCustomApps,
      });
      setSettings(res.settings);
      setRuntime(res.runtime || null);
      // Drop any active app filter that is no longer watched
      const activeSet = new Set([
        ...draftWatchedIds,
        ...draftCustomApps.filter((c) => c.enabled).map((c) => c.id),
      ]);
      setSelectedApps((prev) => prev.filter((id) => activeSet.has(id)));
      setAppPickerOpen(false);

      if (res.newly_enabled && res.newly_enabled.length > 0) {
        onNotify(`已保存监看清单，正在后台增量同步新增的 ${res.newly_enabled.length} 款应用官方漏洞...`);
      } else {
        onNotify(`已更新监看清单（当前共监看 ${activeSet.size} 款应用）`);
      }
      await loadOverview({ silent: true, markFresh: true });
    } catch (err: any) {
      onNotify(err?.message || '保存监看应用配置失败');
    } finally {
      setSavingApps(false);
    }
  };

  const handleAddCustomApp = async (e: React.FormEvent) => {
    e.preventDefault();
    setAddingCustom(true);
    try {
      const res = await api.upsertCustomVulnApp({
        name: newCustomName.trim(),
        kind: newCustomKind,
        repo: newCustomKind === 'github_repo' ? newCustomRepo.trim() : undefined,
        ecosystem: newCustomKind === 'osv_package' ? newCustomEco : undefined,
        package_name: newCustomKind === 'osv_package' ? newCustomPkg.trim() : undefined,
        enabled: true,
      });
      setSettings(res.settings);
      setDraftCustomApps(res.settings.custom_apps || []);
      setRuntime(res.runtime || null);
      setNewCustomName('');
      setNewCustomRepo('');
      setNewCustomPkg('');
      onNotify(`已添加并启用自定义监看源「${res.app.name}」，正在后台同步...`);
      await loadOverview({ silent: true });
    } catch (err: any) {
      onNotify(err?.message || '添加自定义应用失败');
    } finally {
      setAddingCustom(false);
    }
  };

  const handleDeleteCustomApp = async (id: string, name: string) => {
    try {
      const res = await api.deleteCustomVulnApp(id);
      setSettings(res.settings);
      setDraftCustomApps(res.settings.custom_apps || []);
      setSelectedApps((prev) => prev.filter((x) => x !== id));
      onNotify(`已删除自定义应用「${name}」`);
      await loadOverview({ silent: true });
    } catch (err: any) {
      onNotify(err?.message || '删除自定义应用失败');
    }
  };

  // --- Sync / Source Health / Proxy Settings Modal ---

  const openSettingsModal = (initialTab: 'sources' | 'sync' = 'sources') => {
    if (settings) {
      setCfgEnabled(settings.enabled);
      setCfgInterval(settings.sync_interval_minutes || 30);
      setCfgRetention(settings.retention_days || 90);
      setCfgNotifyWebhook(settings.notify_webhook);
      setCfgNotifyMinSev(settings.notify_min_severity || 'critical');
      setCfgNotifyKEVOnly(settings.notify_kev_only);
      setCfgReusePatrolWH(settings.reuse_ai_patrol_webhook);
    }
    setCfgProxy('');
    setCfgClearProxy(false);
    setCfgToken('');
    setCfgClearToken(false);
    setCfgCustomWH('');
    setCfgClearWH(false);
    setSettingsTab(initialTab);
    setSettingsOpen(true);
  };

  const handleSaveSettings = async (e: React.FormEvent) => {
    e.preventDefault();
    setSavingSettings(true);
    try {
      const res = await api.updateVulnConfig({
        enabled: cfgEnabled,
        sync_interval_minutes: cfgInterval,
        retention_days: cfgRetention,
        ...(cfgProxy.trim() ? { http_proxy_url: cfgProxy.trim() } : {}),
        ...(cfgClearProxy ? { clear_http_proxy: true } : {}),
        ...(cfgToken.trim() ? { github_token: cfgToken.trim() } : {}),
        ...(cfgClearToken ? { clear_github_token: true } : {}),
        notify_webhook: cfgNotifyWebhook,
        notify_min_severity: cfgNotifyMinSev,
        notify_kev_only: cfgNotifyKEVOnly,
        reuse_ai_patrol_webhook: cfgReusePatrolWH,
        ...(cfgCustomWH.trim() ? { custom_webhook_url: cfgCustomWH.trim() } : {}),
        ...(cfgClearWH ? { clear_custom_webhook: true } : {}),
      });
      setSettings(res.settings);
      setRuntime(res.runtime || null);
      setSettingsOpen(false);
      onNotify('漏洞监测同步与通知策略已加密保存');
    } catch (err: any) {
      onNotify(err?.message || '保存设置失败');
    } finally {
      setSavingSettings(false);
    }
  };

  const handleTestWebhook = async () => {
    setTestingWebhook(true);
    try {
      await api.testVulnWebhook({
        custom_webhook_url: cfgCustomWH.trim() || undefined,
        reuse_ai_patrol_webhook: cfgReusePatrolWH,
      });
      onNotify('测试通知已发送，请检查飞书 / 钉钉 / 企业微信或目标 Webhook');
    } catch (err: any) {
      onNotify(err?.message || '测试 Webhook 失败');
    } finally {
      setTestingWebhook(false);
    }
  };

  // Multi-select filter toggle helpers
  const toggleSeverityFilter = (sev: VulnSeverity) => {
    setSelectedSeverities((prev) =>
      prev.includes(sev) ? prev.filter((s) => s !== sev) : [...prev, sev]
    );
  };

  const toggleAppFilter = (appId: string) => {
    setSelectedApps((prev) =>
      prev.includes(appId) ? prev.filter((a) => a !== appId) : [...prev, appId]
    );
  };

  const hasActiveFilters =
    selectedApps.length > 0 ||
    selectedSeverities.length > 0 ||
    kevOnly ||
    fixedOnly ||
    daysFilter > 0 ||
    searchQuery.length > 0 ||
    triageState !== 'all';

  const resetAllFilters = () => {
    setTriageState('all');
    setSelectedApps([]);
    setSelectedSeverities([]);
    setKevOnly(false);
    setFixedOnly(false);
    setDaysFilter(0);
    setSearchInput('');
    setSearchQuery('');
  };

  const builtinByCategory = useMemo(() => {
    const q = pickerSearch.trim().toLowerCase();
    const groups: { cat: VulnAppCategoryInfo; apps: VulnAppDefinition[] }[] = [];
    for (const cat of categories) {
      if (cat.id === 'custom') continue;
      const list = catalog.filter((a) => {
        if (a.is_custom || a.category !== cat.id) return false;
        if (!q) return true;
        return (
          a.name.toLowerCase().includes(q) ||
          a.vendor.toLowerCase().includes(q) ||
          a.description.toLowerCase().includes(q) ||
          a.id.toLowerCase().includes(q)
        );
      });
      if (list.length > 0) {
        groups.push({ cat, apps: list });
      }
    }
    return groups;
  }, [catalog, categories, pickerSearch]);

  const draftTotalWatched =
    draftWatchedIds.length + draftCustomApps.filter((c) => c.enabled).length;

  const isBusySync = syncingManual || Boolean(runtime?.syncing);

  return (
    <div className="page-container" id="vuln-center-page">
      {/* Page Header */}
      <header className="page-header">
        <div className="page-header-left">
          <div className="page-title-row">
            <h1 className="page-title">
              <ShieldAlert size={20} style={{ color: 'var(--danger-text)', flexShrink: 0 }} />
              漏洞监测
            </h1>
            <span className="pill pill-teal mono" style={{ fontSize: 11.5 }}>
              已监看 {watchedCatalogApps.length} / {catalog.length || 35} 款
            </span>
            {isBusySync && (
              <span className="pill pill-amber" style={{ fontSize: 11.5 }}>
                <RefreshCw size={11} className="spin" /> 正在同步官方源…
              </span>
            )}
          </div>
          <p className="page-subtitle">
            滚动追踪各大主流应用官方最新安全公告与补丁修复版本 · 默认仅监看 4 款核心底座，可随时按需自选扩展
          </p>
        </div>

        <div className="page-header-actions vuln-header-actions">
          <button
            type="button"
            id="vuln-watch-apps-btn"
            className="btn btn-teal btn-sm"
            onClick={openAppPicker}
          >
            <SlidersHorizontal size={14} />
            自选监看应用 ({watchedCatalogApps.length})
          </button>
          {(kpi?.unread_total || 0) > 0 && (
            <button
              type="button"
              className="btn btn-sm"
              onClick={() => void handleMarkAllRead()}
              title="将所有已同步漏洞标记为已读"
            >
              <CheckCheck size={14} /> 全部已读
            </button>
          )}
          <button
            type="button"
            id="vuln-settings-btn"
            className="btn btn-sm"
            onClick={() => openSettingsModal('sources')}
          >
            <Settings2 size={14} /> 同步与源诊断
          </button>
          <button
            type="button"
            id="vuln-sync-now-btn"
            className="btn btn-primary btn-sm"
            disabled={isBusySync}
            onClick={() => void handleManualSync()}
          >
            <RefreshCw size={14} className={isBusySync ? 'spin' : ''} />
            {isBusySync ? '同步中…' : '立即同步'}
          </button>
        </div>
      </header>

      <div className="page-body vuln-page-body">
        {/* Top Live Rolling Ticker Banner */}
        <section className="vuln-ticker-bar" aria-label="最新官方漏洞修复动态实时滚动播报">
          <div className="vuln-ticker-label">
            <span className="vuln-live-dot" />
            <span>滚动快讯</span>
          </div>

          <div
            className={`vuln-ticker-viewport ${tickerPaused ? 'is-paused' : ''}`}
            title="悬停自动暂停，点击条目直达详情"
          >
            {ticker.length > 0 ? (
              <div
                className="vuln-ticker-track"
                style={{
                  animationDuration: `${Math.max(24, ticker.length * 7)}s`,
                }}
              >
                {[...ticker, ...ticker].map((item, idx) => (
                  <button
                    key={`${item.id}-${idx}`}
                    type="button"
                    className="vuln-ticker-item"
                    onClick={() => void handleOpenDetail(item)}
                  >
                    <span className={`vuln-sev-chip sev-${item.severity}`}>
                      {SEVERITY_META[item.severity]?.short || '未知'}
                    </span>
                    {item.is_kev && <span className="vuln-kev-mini">KEV</span>}
                    <span className="vuln-ticker-app">{item.app_names?.[0] || '应用'}</span>
                    <span className="mono vuln-ticker-id">{item.id}</span>
                    <span className="vuln-ticker-title">{item.title}</span>
                    {item.fixed_version && (
                      <span className="vuln-ticker-fix mono">修复 {item.fixed_version}</span>
                    )}
                  </button>
                ))}
              </div>
            ) : (
              <div className="vuln-ticker-empty">
                {isBusySync
                  ? '正在从 OSV.dev、GitHub Security Advisories、OpenSSL / Nginx 官方源及 CISA KEV 实时拉取最新漏洞修复动态…'
                  : '暂无可播报的漏洞动态，点击右上角「立即同步」拉取最新官方安全公告'}
              </div>
            )}
          </div>

          {ticker.length > 0 && (
            <button
              type="button"
              className="btn btn-xs btn-ghost vuln-ticker-toggle"
              onClick={() => setTickerPaused((p) => !p)}
              title={tickerPaused ? '继续滚动播报' : '暂停滚动播报'}
              aria-label={tickerPaused ? '继续滚动播报' : '暂停滚动播报'}
            >
              {tickerPaused ? <Play size={12} /> : <Pause size={12} />}
            </button>
          )}
        </section>

        {/* KPI Posture Row */}
        <section className="vuln-kpi-grid" aria-label="漏洞态势总览">
          <button
            type="button"
            className={`vuln-kpi-card kpi-critical ${selectedSeverities.length === 1 && selectedSeverities[0] === 'critical' ? 'active' : ''}`}
            onClick={() => {
              setKevOnly(false);
              setSelectedSeverities((prev) =>
                prev.length === 1 && prev[0] === 'critical' ? [] : ['critical']
              );
            }}
          >
            <div className="vuln-kpi-top">
              <span>严重 Critical</span>
              <ShieldAlert size={15} />
            </div>
            <div className="vuln-kpi-val mono">{kpi?.critical ?? 0}</div>
            <div className="vuln-kpi-sub">CVSS ≥ 9.0 · 优先紧急处置</div>
          </button>

          <button
            type="button"
            className={`vuln-kpi-card kpi-high ${selectedSeverities.length === 1 && selectedSeverities[0] === 'high' ? 'active' : ''}`}
            onClick={() => {
              setKevOnly(false);
              setSelectedSeverities((prev) =>
                prev.length === 1 && prev[0] === 'high' ? [] : ['high']
              );
            }}
          >
            <div className="vuln-kpi-top">
              <span>高危 High</span>
              <AlertTriangle size={15} />
            </div>
            <div className="vuln-kpi-val mono">{kpi?.high ?? 0}</div>
            <div className="vuln-kpi-sub">CVSS 7.0–8.9 · 尽快排期修复</div>
          </button>

          <button
            type="button"
            className={`vuln-kpi-card kpi-kev ${kevOnly ? 'active' : ''}`}
            onClick={() => setKevOnly((prev) => !prev)}
          >
            <div className="vuln-kpi-top">
              <span>在野利用 (CISA KEV)</span>
              <Flame size={15} />
            </div>
            <div className="vuln-kpi-val mono">{kpi?.kev ?? 0}</div>
            <div className="vuln-kpi-sub">已确认存在真实攻击利用</div>
          </button>

          <button
            type="button"
            className={`vuln-kpi-card kpi-fix ${daysFilter === 7 ? 'active' : ''}`}
            onClick={() => setDaysFilter((prev) => (prev === 7 ? 0 : 7))}
          >
            <div className="vuln-kpi-top">
              <span>近 7 天动态</span>
              <CheckCircle2 size={15} />
            </div>
            <div className="vuln-kpi-val mono">{kpi?.recent_7d ?? 0}</div>
            <div className="vuln-kpi-sub">
              已出官方修复 {kpi?.has_fix ?? 0} / {kpi?.total ?? 0}
            </div>
          </button>

          <button
            type="button"
            className="vuln-kpi-card kpi-sources"
            onClick={() => openSettingsModal('sources')}
          >
            <div className="vuln-kpi-top">
              <span>官方源健康度</span>
              <Activity size={15} />
            </div>
            <div className="vuln-kpi-val mono">
              {kpi?.sources_ok ?? 0}
              <span style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-muted)' }}>
                /{kpi?.sources_total ?? 0}
              </span>
            </div>
            <div className="vuln-kpi-sub">
              {runtime?.last_sync_at ? `更新于 ${formatRelTime(runtime.last_sync_at)}` : '等待首次同步'}
            </div>
          </button>
        </section>

        {/* New Arrivals Live Update Notification Bar */}
        {pendingNewCount > 0 && (
          <div className="vuln-new-banner" role="status">
            <div className="vuln-new-banner-left">
              <Sparkles size={15} />
              <span>
                后台刚刚同步到 <strong>{pendingNewCount}</strong> 条最新官方漏洞修复动态
              </span>
            </div>
            <button
              type="button"
              className="btn btn-xs btn-teal"
              onClick={() => void loadOverview({ silent: true, markFresh: true })}
            >
              立即置顶刷新
            </button>
          </div>
        )}

        {/* Multi-Dimensional Filter Panel */}
        <section className="card vuln-filter-card" aria-label="漏洞筛选器">
          {/* Row 1: Triage tabs + Search + Time Range + Quick Switches */}
          <div className="vuln-filter-row">
            <div className="vuln-triage-tabs" role="tablist" aria-label="值守状态筛选">
              {(
                [
                  ['all', `全部 (${kpi?.total ?? 0})`],
                  ['unread', `未读 (${kpi?.unread_total ?? 0})`],
                  ['starred', `星标 (${kpi?.starred_total ?? 0})`],
                  ['ignored', '已忽略'],
                ] as const
              ).map(([key, label]) => (
                <button
                  key={key}
                  type="button"
                  role="tab"
                  aria-selected={triageState === key}
                  className={`vuln-triage-tab ${triageState === key ? 'active' : ''}`}
                  onClick={() => setTriageState(key)}
                >
                  {label}
                </button>
              ))}
            </div>

            <div className="vuln-filter-controls">
              <div className="vuln-search-box">
                <Search size={14} className="vuln-search-icon" />
                <input
                  type="search"
                  className="input vuln-search-input"
                  placeholder="搜索 CVE / GHSA / 应用名 / 修复版本…"
                  value={searchInput}
                  onChange={(e) => setSearchInput(e.target.value)}
                />
              </div>

              <select
                className="input vuln-days-select"
                aria-label="时间范围筛选"
                value={daysFilter}
                onChange={(e) => setDaysFilter(Number(e.target.value))}
              >
                <option value={0}>全部时间</option>
                <option value={1}>近 24 小时</option>
                <option value={7}>近 7 天</option>
                <option value={30}>近 30 天</option>
                <option value={90}>近 90 天</option>
              </select>

              <button
                type="button"
                className={`vuln-toggle-pill ${kevOnly ? 'active-danger' : ''}`}
                onClick={() => setKevOnly((v) => !v)}
              >
                <Flame size={13} /> 仅看在野利用
              </button>

              <button
                type="button"
                className={`vuln-toggle-pill ${fixedOnly ? 'active-teal' : ''}`}
                onClick={() => setFixedOnly((v) => !v)}
              >
                <ShieldCheck size={13} /> 仅看已出修复
              </button>
            </div>
          </div>

          {/* Row 2: Severity Multi-Select Pills */}
          <div className="vuln-chip-row">
            <span className="vuln-chip-label">漏洞等级</span>
            <div className="vuln-chip-group">
              <button
                type="button"
                className={`vuln-filter-chip ${selectedSeverities.length === 0 ? 'active' : ''}`}
                onClick={() => setSelectedSeverities([])}
              >
                全部等级
              </button>
              {ALL_SEVERITIES.map((sev) => {
                const active = selectedSeverities.includes(sev);
                const cnt =
                  sev === 'critical'
                    ? kpi?.critical
                    : sev === 'high'
                    ? kpi?.high
                    : sev === 'medium'
                    ? kpi?.medium
                    : sev === 'low'
                    ? kpi?.low
                    : kpi?.unknown;
                return (
                  <button
                    key={sev}
                    type="button"
                    className={`vuln-filter-chip sev-chip-filter sev-${sev} ${active ? 'active' : ''}`}
                    onClick={() => toggleSeverityFilter(sev)}
                  >
                    <span className={`vuln-sev-dot sev-${sev}`} />
                    {SEVERITY_META[sev].label}
                    {typeof cnt === 'number' && <span className="mono vuln-chip-count">{cnt}</span>}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Row 3: Watched Apps Multi-Select Pills + Self-Select Shortcut */}
          <div className="vuln-chip-row">
            <span className="vuln-chip-label">监看应用</span>
            <div className="vuln-chip-group">
              <button
                type="button"
                className={`vuln-filter-chip ${selectedApps.length === 0 ? 'active' : ''}`}
                onClick={() => setSelectedApps([])}
              >
                全部已监看 ({watchedCatalogApps.length})
              </button>
              {watchedCatalogApps.map((app) => {
                const active = selectedApps.includes(app.id);
                return (
                  <button
                    key={app.id}
                    type="button"
                    className={`vuln-filter-chip ${active ? 'active-teal' : ''}`}
                    onClick={() => toggleAppFilter(app.id)}
                  >
                    {app.name}
                    {app.is_custom && <span className="vuln-custom-tag">自定义</span>}
                  </button>
                );
              })}
              <button
                type="button"
                className="vuln-filter-chip vuln-add-more-chip"
                onClick={openAppPicker}
              >
                <Plus size={12} /> 自选更多应用
              </button>
              {hasActiveFilters && (
                <button
                  type="button"
                  className="btn btn-xs btn-ghost"
                  onClick={resetAllFilters}
                  style={{ marginLeft: 'auto' }}
                >
                  <X size={12} /> 重置筛选
                </button>
              )}
            </div>
          </div>
        </section>

        {/* Source error notice if all sources failed */}
        {runtime?.last_error && (
          <div className="vuln-error-banner" role="alert">
            <AlertTriangle size={15} style={{ flexShrink: 0 }} />
            <div style={{ flex: 1, minWidth: 0 }}>
              <strong>最近一次同步遇到网络异常：</strong>
              {runtime.last_error}
            </div>
            <button
              type="button"
              className="btn btn-xs"
              onClick={() => openSettingsModal('sync')}
            >
              配置代理 / Token
            </button>
          </div>
        )}

        {/* Advisory Rolling Stream */}
        <section className="vuln-feed-section" aria-label="官方漏洞修复动态列表">
          <div className="vuln-feed-meta">
            <span>
              当前匹配 <strong className="mono">{totalMatched}</strong> 条官方漏洞记录（按发布/修复时间倒序滚动更新）
            </span>
            {runtime?.last_sync_at && (
              <span className="mono" style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>
                <Clock size={11.5} style={{ verticalAlign: '-1px', marginRight: 4 }} />
                最近同步：{formatFullDateTime(runtime.last_sync_at)}
              </span>
            )}
          </div>

          {loading ? (
            <div className="card vuln-empty-card">
              <RefreshCw size={24} className="spin" style={{ color: 'var(--accent-teal)' }} />
              <div style={{ fontWeight: 600 }}>正在加载漏洞情报流…</div>
            </div>
          ) : watchedCatalogApps.length === 0 ? (
            <div className="card vuln-empty-card">
              <SlidersHorizontal size={28} style={{ color: 'var(--text-muted)' }} />
              <div style={{ fontWeight: 600, fontSize: 15 }}>当前未勾选任何监看应用</div>
              <p style={{ color: 'var(--text-muted)', fontSize: 13, maxWidth: 440 }}>
                请点击下方按钮打开「自选监看应用」面板，勾选你关心的基础组件、数据库或开发框架，或添加自定义 GitHub 仓库。
              </p>
              <button type="button" className="btn btn-teal btn-sm" onClick={openAppPicker}>
                <Plus size={14} /> 立即自选监看应用
              </button>
            </div>
          ) : advisories.length === 0 ? (
            <div className="card vuln-empty-card">
              <ShieldCheck size={28} style={{ color: 'var(--accent-teal)' }} />
              <div style={{ fontWeight: 600, fontSize: 15 }}>
                {hasActiveFilters ? '当前筛选条件下暂无匹配的漏洞记录' : '尚未拉取到漏洞数据'}
              </div>
              <p style={{ color: 'var(--text-muted)', fontSize: 13, maxWidth: 460 }}>
                {hasActiveFilters
                  ? '可尝试放宽等级、应用或时间范围条件，或重置全部筛选查看完整动态。'
                  : '点击「立即同步」即可从 OSV.dev、GitHub Security Advisories、各厂商官方公告与 CISA KEV 拉取最新修复动态。'}
              </p>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', justifyContent: 'center' }}>
                {hasActiveFilters ? (
                  <button type="button" className="btn btn-sm" onClick={resetAllFilters}>
                    重置全部筛选
                  </button>
                ) : (
                  <button
                    type="button"
                    className="btn btn-primary btn-sm"
                    disabled={isBusySync}
                    onClick={() => void handleManualSync()}
                  >
                    <RefreshCw size={14} className={isBusySync ? 'spin' : ''} /> 立即同步官方源
                  </button>
                )}
              </div>
            </div>
          ) : (
            <>
              <div className="vuln-feed-list">
                {advisories.map((adv) => {
                  const displayTime = advisoryDisplayTime(adv);
                  const isFresh = Boolean(freshHighlightIds[adv.id]);
                  return (
                    <article
                      key={adv.id}
                      className={`vuln-card sev-${adv.severity} ${!adv.is_read ? 'is-unread' : ''} ${isFresh ? 'is-fresh' : ''} ${adv.is_ignored ? 'is-ignored' : ''}`}
                      onClick={() => void handleOpenDetail(adv)}
                    >
                      <div className="vuln-card-head">
                        <div className="vuln-card-badges">
                          <span className={`vuln-sev-badge sev-${adv.severity}`}>
                            {SEVERITY_META[adv.severity]?.label || '未评级'}
                          </span>
                          {adv.cvss_score ? (
                            <span className={`vuln-cvss-pill mono sev-${adv.severity}`}>
                              CVSS {adv.cvss_score.toFixed(1)}
                            </span>
                          ) : null}
                          {adv.is_kev && (
                            <span className="vuln-kev-badge" title="已被 CISA 收录为确认在野利用漏洞">
                              <Flame size={11.5} /> 在野利用 KEV
                            </span>
                          )}
                          {adv.is_new && <span className="vuln-new-badge">NEW</span>}

                          <button
                            type="button"
                            className="vuln-id-copy mono"
                            title="点击复制漏洞编号"
                            onClick={(e) => {
                              e.stopPropagation();
                              void handleCopyText(adv.id, adv.id);
                            }}
                          >
                            {adv.id}
                            {copiedId === adv.id ? <Check size={11} /> : <Copy size={11} />}
                          </button>

                          {(adv.app_names || []).map((name, idx) => (
                            <span key={`${adv.id}-app-${idx}`} className="vuln-app-pill">
                              {name}
                            </span>
                          ))}
                        </div>

                        <div className="vuln-card-meta-right">
                          <span className="vuln-time-text mono" title={formatFullDateTime(displayTime)}>
                            {formatRelTime(displayTime)}
                          </span>
                          <div className="vuln-quick-actions" onClick={(e) => e.stopPropagation()}>
                            <button
                              type="button"
                              className={`vuln-icon-btn ${adv.is_starred ? 'starred' : ''}`}
                              title={adv.is_starred ? '取消星标关注' : '星标关注'}
                              aria-label={adv.is_starred ? '取消星标关注' : '星标关注'}
                              onClick={(e) => void handleToggleState(adv, { starred: !adv.is_starred }, e)}
                            >
                              <Star size={14} fill={adv.is_starred ? 'currentColor' : 'none'} />
                            </button>
                            <button
                              type="button"
                              className="vuln-icon-btn"
                              title={adv.is_read ? '标为未读' : '标为已读'}
                              aria-label={adv.is_read ? '标为未读' : '标为已读'}
                              onClick={(e) => void handleToggleState(adv, { read: !adv.is_read }, e)}
                            >
                              {adv.is_read ? <EyeOff size={14} /> : <Eye size={14} />}
                            </button>
                            <button
                              type="button"
                              className="vuln-icon-btn"
                              title={adv.is_ignored ? '取消忽略' : '忽略（不适用）'}
                              aria-label={adv.is_ignored ? '取消忽略' : '忽略'}
                              onClick={(e) => void handleToggleState(adv, { ignored: !adv.is_ignored }, e)}
                            >
                              <X size={14} />
                            </button>
                          </div>
                        </div>
                      </div>

                      <h3 className="vuln-card-title">{adv.title}</h3>
                      {adv.ai_analysis?.summary_zh ? (
                        <p className="vuln-card-summary vuln-ai-preview">
                          <Sparkles size={12.5} style={{ flexShrink: 0, marginTop: 2 }} />
                          <span>{adv.ai_analysis.summary_zh}</span>
                        </p>
                      ) : adv.summary && adv.summary !== adv.title ? (
                        <p className="vuln-card-summary">{adv.summary}</p>
                      ) : null}

                      <div className="vuln-card-foot">
                        <div className="vuln-patch-strip">
                          {adv.affected_text && (
                            <span className="vuln-affected-pill mono" title={`受影响版本: ${adv.affected_text}`}>
                              受影响: {adv.affected_text}
                            </span>
                          )}
                          {adv.has_fix ? (
                            <span className="vuln-fixed-pill mono">
                              <CheckCircle2 size={12} />
                              官方已修复{adv.fixed_version ? `: ${adv.fixed_version}` : ''}
                            </span>
                          ) : (
                            <span className="vuln-unfixed-pill">
                              <Clock size={12} /> 暂无明确补丁版本
                            </span>
                          )}
                          <span className="vuln-source-pill">
                            <Globe size={11.5} /> {adv.primary_source || adv.sources?.[0] || '官方源'}
                          </span>
                          {adv.ai_analysis && (
                            <span className="vuln-ai-cached-pill">
                              <Sparkles size={11} /> 已含 AI 解读
                            </span>
                          )}
                        </div>

                        <div className="vuln-card-links" onClick={(e) => e.stopPropagation()}>
                          {adv.official_url && (
                            <a
                              href={adv.official_url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="btn btn-xs btn-ghost"
                            >
                              官方公告 <ExternalLink size={11.5} />
                            </a>
                          )}
                          <button
                            type="button"
                            className="btn btn-xs"
                            onClick={() => void handleOpenDetail(adv)}
                          >
                            详情与修复
                          </button>
                        </div>
                      </div>
                    </article>
                  );
                })}
              </div>

              {hasMore && (
                <div className="vuln-load-more-row">
                  <button
                    type="button"
                    className="btn btn-sm"
                    disabled={loadingMore}
                    onClick={() =>
                      void loadOverview({
                        silent: true,
                        append: true,
                        offset: advisories.length,
                      })
                    }
                  >
                    {loadingMore ? (
                      <>
                        <RefreshCw size={13} className="spin" /> 加载更多…
                      </>
                    ) : (
                      `加载更多（已展示 ${advisories.length} / ${totalMatched} 条）`
                    )}
                  </button>
                </div>
              )}
            </>
          )}
        </section>
      </div>

      {/* Advisory Detail Slide-Over Drawer */}
      {activeAdvisory && (
        <div
          className="vuln-drawer-backdrop"
          role="dialog"
          aria-modal="true"
          aria-label={`漏洞详情 ${activeAdvisory.id}`}
          onClick={() => setActiveAdvisory(null)}
        >
          <div className="vuln-drawer" onClick={(e) => e.stopPropagation()}>
            <div className="vuln-drawer-header">
              <div style={{ minWidth: 0 }}>
                <div className="vuln-card-badges" style={{ marginBottom: 6 }}>
                  <span className={`vuln-sev-badge sev-${activeAdvisory.severity}`}>
                    {SEVERITY_META[activeAdvisory.severity]?.label}
                  </span>
                  {activeAdvisory.cvss_score ? (
                    <span className={`vuln-cvss-pill mono sev-${activeAdvisory.severity}`}>
                      CVSS {activeAdvisory.cvss_score.toFixed(1)}
                    </span>
                  ) : null}
                  {activeAdvisory.is_kev && (
                    <span className="vuln-kev-badge">
                      <Flame size={11.5} /> CISA KEV 在野利用
                    </span>
                  )}
                  <span className="mono" style={{ fontWeight: 700, fontSize: 13 }}>
                    {activeAdvisory.id}
                  </span>
                </div>
                <h2 className="vuln-drawer-title">{activeAdvisory.title}</h2>
              </div>
              <button
                type="button"
                className="btn btn-sm btn-ghost btn-icon"
                aria-label="关闭详情抽屉"
                onClick={() => setActiveAdvisory(null)}
              >
                <X size={16} />
              </button>
            </div>

            <div className="vuln-drawer-body">
              {/* Quick Triage & Official Link Action Bar */}
              <div className="vuln-drawer-actions">
                <button
                  type="button"
                  className={`btn btn-sm ${activeAdvisory.is_starred ? 'btn-teal' : ''}`}
                  onClick={() =>
                    void handleToggleState(activeAdvisory, { starred: !activeAdvisory.is_starred })
                  }
                >
                  <Star size={13.5} fill={activeAdvisory.is_starred ? 'currentColor' : 'none'} />
                  {activeAdvisory.is_starred ? '已星标关注' : '星标关注'}
                </button>
                <button
                  type="button"
                  className="btn btn-sm"
                  onClick={() =>
                    void handleToggleState(activeAdvisory, { ignored: !activeAdvisory.is_ignored })
                  }
                >
                  <X size={13.5} />
                  {activeAdvisory.is_ignored ? '取消忽略' : '忽略（不适用）'}
                </button>
                {activeAdvisory.official_url && (
                  <a
                    href={activeAdvisory.official_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="btn btn-sm btn-primary"
                  >
                    打开官方安全公告 <ExternalLink size={13} />
                  </a>
                )}
              </div>

              {/* CISA KEV Urgent Callout */}
              {activeAdvisory.is_kev && (
                <div className="vuln-kev-callout">
                  <div className="vuln-kev-callout-head">
                    <Flame size={15} />
                    <strong>CISA 已知在野利用漏洞 (KEV)</strong>
                    {activeAdvisory.kev_due_date && (
                      <span className="mono">建议整改期限：{activeAdvisory.kev_due_date}</span>
                    )}
                  </div>
                  {activeAdvisory.kev_action && <p>{activeAdvisory.kev_action}</p>}
                </div>
              )}

              {/* Structured Metadata Grid */}
              <div className="vuln-meta-grid">
                <div className="vuln-meta-cell">
                  <span className="vuln-meta-k">涉及应用</span>
                  <span className="vuln-meta-v">
                    {(activeAdvisory.app_names || []).join('、') || '—'}
                  </span>
                </div>
                <div className="vuln-meta-cell">
                  <span className="vuln-meta-k">官方修复版本</span>
                  <span className="vuln-meta-v mono" style={{ color: activeAdvisory.has_fix ? 'var(--accent-teal)' : 'var(--amber-text)' }}>
                    {activeAdvisory.fixed_version || (activeAdvisory.has_fix ? '已发布官方补丁' : '暂未公布明确修复版本')}
                  </span>
                </div>
                <div className="vuln-meta-cell">
                  <span className="vuln-meta-k">发布 / 更新时间</span>
                  <span className="vuln-meta-v mono">
                    {formatFullDateTime(activeAdvisory.published_at)}
                    {activeAdvisory.modified_at && activeAdvisory.modified_at !== activeAdvisory.published_at
                      ? `（更新 ${formatFullDateTime(activeAdvisory.modified_at)}）`
                      : ''}
                  </span>
                </div>
                <div className="vuln-meta-cell">
                  <span className="vuln-meta-k">情报来源</span>
                  <span className="vuln-meta-v">{(activeAdvisory.sources || []).join(' · ')}</span>
                </div>
                {activeAdvisory.cvss_vector && (
                  <div className="vuln-meta-cell vuln-meta-span2">
                    <span className="vuln-meta-k">CVSS 向量</span>
                    <span className="vuln-meta-v mono" style={{ fontSize: 12, wordBreak: 'break-all' }}>
                      {activeAdvisory.cvss_vector}
                    </span>
                  </div>
                )}
                {activeAdvisory.cwe_ids && activeAdvisory.cwe_ids.length > 0 && (
                  <div className="vuln-meta-cell vuln-meta-span2">
                    <span className="vuln-meta-k">CWE 弱点分类</span>
                    <span className="vuln-meta-v mono">{activeAdvisory.cwe_ids.join(', ')}</span>
                  </div>
                )}
              </div>

              {/* Affected & Fixed Version Ranges Table */}
              {activeAdvisory.affected_ranges && activeAdvisory.affected_ranges.length > 0 && (
                <div className="vuln-section-block">
                  <h4 className="vuln-section-title">受影响版本区间与官方修复版本</h4>
                  <div className="vuln-ranges-list">
                    {activeAdvisory.affected_ranges.map((r, i) => (
                      <div key={i} className="vuln-range-item">
                        <div className="mono" style={{ fontWeight: 600, fontSize: 12.5 }}>
                          {r.ecosystem ? `[${r.ecosystem}] ` : ''}
                          {r.package_name || activeAdvisory.package_name || activeAdvisory.app_names?.[0]}
                        </div>
                        <div className="vuln-range-vals mono">
                          {r.range_text && <span className="vuln-affected-pill">{r.range_text}</span>}
                          {r.fixed && <span className="vuln-fixed-pill">修复: {r.fixed}</span>}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* On-Demand AI Chinese Interpretation Card */}
              <div className="vuln-ai-box">
                <div className="vuln-ai-box-head">
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontWeight: 600 }}>
                    <Sparkles size={15} style={{ color: 'var(--accent-teal)' }} />
                    AI 中文解读与升级指南
                  </div>
                  <button
                    type="button"
                    className="btn btn-xs btn-teal"
                    disabled={aiExplainingId === activeAdvisory.id}
                    onClick={() =>
                      void handleExplainWithAI(activeAdvisory, Boolean(activeAdvisory.ai_analysis))
                    }
                  >
                    <RefreshCw
                      size={12}
                      className={aiExplainingId === activeAdvisory.id ? 'spin' : ''}
                    />
                    {aiExplainingId === activeAdvisory.id
                      ? 'AI 分析中…'
                      : activeAdvisory.ai_analysis
                      ? '重新解读'
                      : '一键生成中文解读'}
                  </button>
                </div>

                {aiError && <div className="vuln-ai-error">{aiError}</div>}

                {activeAdvisory.ai_analysis ? (
                  <div className="vuln-ai-content">
                    <div className="vuln-ai-summary">{activeAdvisory.ai_analysis.summary_zh}</div>
                    {activeAdvisory.ai_analysis.impact_zh && (
                      <div className="vuln-ai-sub">
                        <strong>影响与风险评估：</strong>
                        {activeAdvisory.ai_analysis.impact_zh}
                      </div>
                    )}
                    {activeAdvisory.ai_analysis.fix_steps_zh &&
                      activeAdvisory.ai_analysis.fix_steps_zh.length > 0 && (
                        <div className="vuln-ai-sub">
                          <strong>推荐升级与缓解步骤：</strong>
                          <ol className="vuln-ai-steps">
                            {activeAdvisory.ai_analysis.fix_steps_zh.map((step, idx) => (
                              <li key={idx}>{step}</li>
                            ))}
                          </ol>
                        </div>
                      )}
                    {activeAdvisory.ai_analysis.verification_cmd && (
                      <div className="vuln-ai-cmd">
                        <span className="mono">{activeAdvisory.ai_analysis.verification_cmd}</span>
                        <button
                          type="button"
                          className="btn btn-xs btn-ghost"
                          onClick={() =>
                            void handleCopyText(
                              activeAdvisory.ai_analysis!.verification_cmd!,
                              'ai-cmd'
                            )
                          }
                        >
                          {copiedId === 'ai-cmd' ? <Check size={12} /> : <Copy size={12} />}
                          复制核查命令
                        </button>
                      </div>
                    )}
                    {activeAdvisory.ai_analysis.raw_markdown && !activeAdvisory.ai_analysis.impact_zh && (
                      <pre className="vuln-detail-pre">{activeAdvisory.ai_analysis.raw_markdown}</pre>
                    )}
                    <div className="vuln-ai-foot mono">
                      模型：{activeAdvisory.ai_analysis.model || '已配置 AI'} · 生成于{' '}
                      {formatFullDateTime(activeAdvisory.ai_analysis.generated_at)}（已本地缓存）
                    </div>
                  </div>
                ) : (
                  <p style={{ fontSize: 12.5, color: 'var(--text-muted)', marginTop: 6 }}>
                    点击上方按钮将调用站内已配置的 AI 模型，为你提炼本漏洞的中文核心风险、升级步骤与只读版本核查命令（生成后自动缓存，无需重复消耗 Token）。
                  </p>
                )}
              </div>

              {/* Jump to AI Ops Host Check */}
              <div className="vuln-aiops-jump">
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontWeight: 600, fontSize: 13 }}>
                  <Bot size={15} style={{ color: 'var(--accent-teal)' }} />
                  联动 AI 智能运维排查受管主机
                </div>
                <div className="vuln-aiops-jump-row">
                  {servers.length > 0 ? (
                    <select
                      className="input"
                      style={{ flex: 1, minWidth: 160 }}
                      value={aiTargetServerId}
                      onChange={(e) => setAiTargetServerId(e.target.value)}
                      aria-label="选择待排查的受管主机"
                    >
                      {servers.map((srv) => (
                        <option key={srv.id} value={srv.id}>
                          {srv.name} ({srv.host})
                        </option>
                      ))}
                    </select>
                  ) : (
                    <span style={{ fontSize: 12.5, color: 'var(--text-muted)', flex: 1 }}>
                      尚未添加受管主机，仍可携带漏洞上下文前往 AI 运维咨询
                    </span>
                  )}
                  <button
                    type="button"
                    className="btn btn-sm btn-primary"
                    onClick={() => handleJumpAIOpsCheck(activeAdvisory)}
                  >
                    <Bot size={14} /> 去 AI 运维排查受影响版本
                  </button>
                </div>
              </div>

              {/* Official English Details */}
              {(activeAdvisory.details || activeAdvisory.summary) && (
                <div className="vuln-section-block">
                  <h4 className="vuln-section-title">官方原始安全公告说明</h4>
                  <pre className="vuln-detail-pre">
                    {activeAdvisory.details || activeAdvisory.summary}
                  </pre>
                </div>
              )}

              {/* Official References */}
              {activeAdvisory.references && activeAdvisory.references.length > 0 && (
                <div className="vuln-section-block">
                  <h4 className="vuln-section-title">官方补丁与参考链接</h4>
                  <ul className="vuln-ref-list">
                    {activeAdvisory.references.map((ref, i) => (
                      <li key={i}>
                        <a href={ref.url} target="_blank" rel="noopener noreferrer">
                          <span className="vuln-ref-type mono">{ref.type || 'LINK'}</span>
                          <span className="vuln-ref-url">{ref.label || ref.url}</span>
                          <ExternalLink size={12} style={{ flexShrink: 0 }} />
                        </a>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Self-Select Watched Apps Modal */}
      {appPickerOpen && (
        <div
          className="modal-backdrop"
          role="dialog"
          aria-modal="true"
          aria-label="自选监看应用管理"
          onClick={() => setAppPickerOpen(false)}
        >
          <div className="modal-card vuln-picker-modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div>
                <h3 className="modal-title">自选监看应用管理</h3>
                <p style={{ fontSize: 12.5, color: 'var(--text-muted)', marginTop: 2 }}>
                  默认仅监看 4 款核心底座，可按需勾选全栈软件或添加自定义 GitHub 仓库 / OSV 包；保存后新增应用立即拉取，取消勾选立即隐藏。
                </p>
              </div>
              <button
                type="button"
                className="btn btn-sm btn-ghost btn-icon"
                onClick={() => setAppPickerOpen(false)}
                aria-label="关闭弹窗"
              >
                <X size={16} />
              </button>
            </div>

            <div className="vuln-modal-tabs">
              <button
                type="button"
                className={`vuln-modal-tab ${pickerTab === 'builtin' ? 'active' : ''}`}
                onClick={() => setPickerTab('builtin')}
              >
                内置全栈应用目录 ({draftWatchedIds.length}/{catalog.filter((c) => !c.is_custom).length})
              </button>
              <button
                type="button"
                className={`vuln-modal-tab ${pickerTab === 'custom' ? 'active' : ''}`}
                onClick={() => setPickerTab('custom')}
              >
                自定义订阅源 ({draftCustomApps.length})
              </button>
            </div>

            <div className="modal-body vuln-picker-body">
              {pickerTab === 'builtin' ? (
                <>
                  {/* Scene Presets */}
                  <div className="vuln-preset-strip">
                    <span className="vuln-chip-label">快捷场景预设</span>
                    <div className="vuln-chip-group">
                      {presets.map((p) => (
                        <button
                          key={p.id}
                          type="button"
                          className="vuln-filter-chip"
                          title={p.description}
                          onClick={() => applyPresetToDraft(p)}
                        >
                          {p.name}
                        </button>
                      ))}
                      <button
                        type="button"
                        className="vuln-filter-chip"
                        onClick={() => setDraftWatchedIds([])}
                      >
                        全部清空
                      </button>
                    </div>
                  </div>

                  {/* Search inside picker */}
                  <div className="vuln-search-box" style={{ marginBottom: 14 }}>
                    <Search size={14} className="vuln-search-icon" />
                    <input
                      type="search"
                      className="input vuln-search-input"
                      placeholder="按应用名、厂商或描述快速查找（如 Docker、Redis、Spring、Next.js…）"
                      value={pickerSearch}
                      onChange={(e) => setPickerSearch(e.target.value)}
                    />
                  </div>

                  {/* 6 Domain Categories */}
                  {builtinByCategory.map(({ cat, apps }) => {
                    const selectedInCat = apps.filter((a) => draftWatchedIds.includes(a.id)).length;
                    return (
                      <div key={cat.id} className="vuln-cat-block">
                        <div className="vuln-cat-head">
                          <div className="vuln-cat-title">
                            {cat.label}
                            <span className="mono vuln-cat-count">
                              {selectedInCat}/{apps.length}
                            </span>
                          </div>
                          <div style={{ display: 'flex', gap: 6 }}>
                            <button
                              type="button"
                              className="btn btn-xs btn-ghost"
                              onClick={() => toggleDraftCategory(cat.id, true)}
                            >
                              全选本类
                            </button>
                            <button
                              type="button"
                              className="btn btn-xs btn-ghost"
                              onClick={() => toggleDraftCategory(cat.id, false)}
                            >
                              清空
                            </button>
                          </div>
                        </div>

                        <div className="vuln-app-grid">
                          {apps.map((app) => {
                            const checked = draftWatchedIds.includes(app.id);
                            return (
                              <button
                                key={app.id}
                                type="button"
                                className={`vuln-app-option ${checked ? 'selected' : ''}`}
                                onClick={() => toggleDraftBuiltinApp(app.id)}
                              >
                                <div className="vuln-app-opt-top">
                                  <span className="vuln-app-opt-name">
                                    {app.name}
                                    {app.default_watched && (
                                      <span className="vuln-core-pill">默认核心</span>
                                    )}
                                  </span>
                                  <span className={`vuln-check-box ${checked ? 'checked' : ''}`}>
                                    {checked && <Check size={11} />}
                                  </span>
                                </div>
                                <div className="vuln-app-opt-desc">{app.description}</div>
                                <div className="vuln-app-opt-sources">
                                  {app.vendor_feed_id && <span>官方 Feed</span>}
                                  {app.github_repos && app.github_repos.length > 0 && <span>GHSA</span>}
                                  {app.osv_packages && app.osv_packages.length > 0 && <span>OSV</span>}
                                </div>
                              </button>
                            );
                          })}
                        </div>
                      </div>
                    );
                  })}
                </>
              ) : (
                <div className="vuln-custom-pane">
                  <form className="vuln-custom-form" onSubmit={(e) => void handleAddCustomApp(e)}>
                    <div className="vuln-custom-form-title">添加自定义官方漏洞订阅源</div>
                    <div className="vuln-form-grid">
                      <label className="field-label">
                        <span>来源类型</span>
                        <select
                          className="input"
                          value={newCustomKind}
                          onChange={(e) =>
                            setNewCustomKind(e.target.value as 'github_repo' | 'osv_package')
                          }
                        >
                          <option value="github_repo">GitHub 仓库官方安全公告 (GHSA)</option>
                          <option value="osv_package">OSV.dev 生态软件包</option>
                        </select>
                      </label>
                      <label className="field-label">
                        <span>应用显示名称</span>
                        <input
                          className="input"
                          placeholder={newCustomKind === 'github_repo' ? '例如：Nacos / 1Panel' : '例如：Gin / FastAPI'}
                          value={newCustomName}
                          onChange={(e) => setNewCustomName(e.target.value)}
                          required
                        />
                      </label>
                      {newCustomKind === 'github_repo' ? (
                        <label className="field-label vuln-span2">
                          <span>GitHub 仓库（owner/repo 或完整链接）</span>
                          <input
                            className="input mono"
                            placeholder="例如：alibaba/nacos 或 https://github.com/1Panel-dev/1Panel"
                            value={newCustomRepo}
                            onChange={(e) => setNewCustomRepo(e.target.value)}
                            required
                          />
                        </label>
                      ) : (
                        <>
                          <label className="field-label">
                            <span>OSV 生态 (Ecosystem)</span>
                            <select
                              className="input"
                              value={newCustomEco}
                              onChange={(e) => setNewCustomEco(e.target.value)}
                            >
                              {OSV_ECOSYSTEM_OPTIONS.map((eco) => (
                                <option key={eco} value={eco}>
                                  {eco}
                                </option>
                              ))}
                            </select>
                          </label>
                          <label className="field-label">
                            <span>包名称 (Package)</span>
                            <input
                              className="input mono"
                              placeholder="例如：github.com/gin-gonic/gin 或 fastapi"
                              value={newCustomPkg}
                              onChange={(e) => setNewCustomPkg(e.target.value)}
                              required
                            />
                          </label>
                        </>
                      )}
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 10 }}>
                      <button type="submit" className="btn btn-sm btn-teal" disabled={addingCustom}>
                        <Plus size={14} /> {addingCustom ? '添加中…' : '添加并立即开始监看'}
                      </button>
                    </div>
                  </form>

                  <div className="vuln-custom-list">
                    <div className="vuln-custom-form-title">已添加的自定义应用 ({draftCustomApps.length})</div>
                    {draftCustomApps.length === 0 ? (
                      <div style={{ fontSize: 12.5, color: 'var(--text-muted)', padding: '12px 0' }}>
                        尚未添加任何自定义应用，可通过上方表单订阅任意开源项目的官方安全公告。
                      </div>
                    ) : (
                      draftCustomApps.map((ca) => (
                        <div key={ca.id} className="vuln-custom-item">
                          <label style={{ display: 'flex', alignItems: 'center', gap: 10, minWidth: 0, flex: 1, cursor: 'pointer' }}>
                            <input
                              type="checkbox"
                              checked={ca.enabled}
                              onChange={(e) =>
                                setDraftCustomApps((prev) =>
                                  prev.map((x) =>
                                    x.id === ca.id ? { ...x, enabled: e.target.checked } : x
                                  )
                                )
                              }
                            />
                            <div style={{ minWidth: 0 }}>
                              <div style={{ fontWeight: 600, fontSize: 13.5 }}>{ca.name}</div>
                              <div className="mono" style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>
                                {ca.kind === 'github_repo'
                                  ? `GitHub: ${ca.repo}`
                                  : `OSV [${ca.ecosystem}]: ${ca.package_name}`}
                              </div>
                            </div>
                          </label>
                          <button
                            type="button"
                            className="btn btn-xs btn-ghost"
                            title="删除该自定义应用"
                            onClick={() => void handleDeleteCustomApp(ca.id, ca.name)}
                          >
                            <Trash2 size={13} style={{ color: 'var(--danger-text)' }} />
                          </button>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              )}
            </div>

            <div className="modal-footer">
              <span style={{ fontSize: 12.5, color: 'var(--text-muted)', marginRight: 'auto' }}>
                当前已选 <strong className="mono">{draftTotalWatched}</strong> 款监看应用
              </span>
              <button type="button" className="btn btn-sm" onClick={() => setAppPickerOpen(false)}>
                取消
              </button>
              <button
                type="button"
                id="vuln-save-watched-btn"
                className="btn btn-sm btn-primary"
                disabled={savingApps}
                onClick={() => void handleSaveWatchedApps()}
              >
                {savingApps ? '保存并同步中…' : '保存监看清单'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Sync Settings & Source Health Diagnostics Modal */}
      {settingsOpen && (
        <div
          className="modal-backdrop"
          role="dialog"
          aria-modal="true"
          aria-label="漏洞监测同步配置与数据源健康"
          onClick={() => setSettingsOpen(false)}
        >
          <div className="modal-card vuln-settings-modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div>
                <h3 className="modal-title">同步策略与官方数据源诊断</h3>
                <p style={{ fontSize: 12.5, color: 'var(--text-muted)', marginTop: 2 }}>
                  代理与 GitHub Token 加密存储于 secrets.enc，漏洞数据独立落盘至 vuln_runtime.json。
                </p>
              </div>
              <button
                type="button"
                className="btn btn-sm btn-ghost btn-icon"
                onClick={() => setSettingsOpen(false)}
                aria-label="关闭弹窗"
              >
                <X size={16} />
              </button>
            </div>

            <div className="vuln-modal-tabs">
              <button
                type="button"
                className={`vuln-modal-tab ${settingsTab === 'sources' ? 'active' : ''}`}
                onClick={() => setSettingsTab('sources')}
              >
                数据源健康状态 ({runtime?.source_status?.length || 0})
              </button>
              <button
                type="button"
                className={`vuln-modal-tab ${settingsTab === 'sync' ? 'active' : ''}`}
                onClick={() => setSettingsTab('sync')}
              >
                同步频率、代理与 Webhook
              </button>
            </div>

            {settingsTab === 'sources' ? (
              <div className="modal-body">
                {runtime?.source_status && runtime.source_status.length > 0 ? (
                  <div className="vuln-source-list">
                    {runtime.source_status.map((st) => (
                      <div key={st.id} className="vuln-source-row">
                        <div style={{ minWidth: 0, flex: 1 }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                            <span className={`pill ${st.ok ? 'pill-teal' : 'pill-danger'}`}>
                              {st.ok ? '正常' : '异常'}
                            </span>
                            <strong style={{ fontSize: 13.5 }}>{st.name}</strong>
                            <span className="mono" style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>
                              {st.item_count} 条 · {st.duration_ms}ms
                            </span>
                          </div>
                          {st.last_error && (
                            <div style={{ fontSize: 12, color: 'var(--danger-text)', marginTop: 4 }}>
                              {st.last_error}
                            </div>
                          )}
                          <div className="mono" style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 3 }}>
                            最近同步：{formatFullDateTime(st.last_sync_at)}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div style={{ textAlign: 'center', padding: '24px 0', color: 'var(--text-muted)', fontSize: 13 }}>
                    尚未执行过同步，点击主页面「立即同步」即可检测各官方源连通状态。
                  </div>
                )}
              </div>
            ) : (
              <form onSubmit={(e) => void handleSaveSettings(e)}>
                <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                  <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13.5, fontWeight: 500 }}>
                    <input
                      type="checkbox"
                      checked={cfgEnabled}
                      onChange={(e) => setCfgEnabled(e.target.checked)}
                    />
                    启用 7×24 后台定时自动同步官方漏洞源
                  </label>

                  <div className="vuln-form-grid">
                    <label className="field-label">
                      <span>后台同步周期</span>
                      <select
                        className="input"
                        value={cfgInterval}
                        onChange={(e) => setCfgInterval(Number(e.target.value))}
                      >
                        <option value={10}>每 10 分钟</option>
                        <option value={30}>每 30 分钟（推荐）</option>
                        <option value={60}>每 1 小时</option>
                        <option value={180}>每 3 小时</option>
                        <option value={360}>每 6 小时</option>
                        <option value={720}>每 12 小时</option>
                      </select>
                    </label>
                    <label className="field-label">
                      <span>本地历史保留窗口</span>
                      <select
                        className="input"
                        value={cfgRetention}
                        onChange={(e) => setCfgRetention(Number(e.target.value))}
                      >
                        <option value={30}>近 30 天</option>
                        <option value={90}>近 90 天（推荐）</option>
                        <option value={180}>近 180 天</option>
                        <option value={365}>近 365 天</option>
                      </select>
                    </label>
                  </div>

                  <div className="vuln-form-grid">
                    <label className="field-label">
                      <span>
                        可选 HTTP / SOCKS5 代理{' '}
                        {settings?.has_http_proxy && !cfgClearProxy && (
                          <strong style={{ color: 'var(--accent-teal)' }}>
                            （已配置：{settings.http_proxy_display}）
                          </strong>
                        )}
                      </span>
                      <div style={{ display: 'flex', gap: 6 }}>
                        <input
                          className="input mono"
                          placeholder={
                            settings?.has_http_proxy && !cfgClearProxy
                              ? '留空保持原配置，或输入新代理覆盖'
                              : '例如 http://127.0.0.1:7890'
                          }
                          value={cfgProxy}
                          onChange={(e) => {
                            setCfgProxy(e.target.value);
                            setCfgClearProxy(false);
                          }}
                        />
                        {settings?.has_http_proxy && !cfgClearProxy && (
                          <button
                            type="button"
                            className="btn btn-xs"
                            onClick={() => {
                              setCfgProxy('');
                              setCfgClearProxy(true);
                            }}
                          >
                            清空
                          </button>
                        )}
                      </div>
                    </label>

                    <label className="field-label">
                      <span>
                        可选 GitHub Token（提升 GHSA 速率）{' '}
                        {settings?.has_github_token && !cfgClearToken && (
                          <strong style={{ color: 'var(--accent-teal)' }}>（已加密保存）</strong>
                        )}
                      </span>
                      <div style={{ display: 'flex', gap: 6 }}>
                        <input
                          type="password"
                          className="input mono"
                          placeholder={
                            settings?.has_github_token && !cfgClearToken
                              ? '留空保持原 Token'
                              : 'ghp_... / github_pat_...'
                          }
                          value={cfgToken}
                          onChange={(e) => {
                            setCfgToken(e.target.value);
                            setCfgClearToken(false);
                          }}
                        />
                        {settings?.has_github_token && !cfgClearToken && (
                          <button
                            type="button"
                            className="btn btn-xs"
                            onClick={() => {
                              setCfgToken('');
                              setCfgClearToken(true);
                            }}
                          >
                            清空
                          </button>
                        )}
                      </div>
                    </label>
                  </div>

                  <div className="vuln-webhook-box">
                    <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13.5, fontWeight: 600 }}>
                      <input
                        type="checkbox"
                        checked={cfgNotifyWebhook}
                        onChange={(e) => setCfgNotifyWebhook(e.target.checked)}
                      />
                      新发现严重 / 在野利用漏洞时主动 Webhook 推送（默认关闭）
                    </label>

                    {cfgNotifyWebhook && (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginTop: 10 }}>
                        <div className="vuln-form-grid">
                          <label className="field-label">
                            <span>最低推送等级</span>
                            <select
                              className="input"
                              value={cfgNotifyMinSev}
                              onChange={(e) => setCfgNotifyMinSev(e.target.value as VulnSeverity)}
                            >
                              <option value="critical">仅严重 (Critical) 及在野利用 KEV</option>
                              <option value="high">高危 (High) 及以上 + 在野利用 KEV</option>
                            </select>
                          </label>
                          <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, alignSelf: 'end', paddingBottom: 8 }}>
                            <input
                              type="checkbox"
                              checked={cfgNotifyKEVOnly}
                              onChange={(e) => setCfgNotifyKEVOnly(e.target.checked)}
                            />
                            仅推送 CISA KEV 在野利用漏洞
                          </label>
                        </div>

                        <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13 }}>
                          <input
                            type="checkbox"
                            checked={cfgReusePatrolWH}
                            onChange={(e) => setCfgReusePatrolWH(e.target.checked)}
                          />
                          复用「AI 定时巡检」中已启用的飞书 / 钉钉 / 企业微信 Webhook
                        </label>

                        <label className="field-label">
                          <span>
                            可选专用 Webhook URL{' '}
                            {settings?.has_custom_webhook && !cfgClearWH && (
                              <strong style={{ color: 'var(--accent-teal)' }}>
                                （已配置：{settings.custom_webhook_display}）
                              </strong>
                            )}
                          </span>
                          <div style={{ display: 'flex', gap: 6 }}>
                            <input
                              className="input mono"
                              placeholder="https://open.feishu.cn/open-apis/bot/v2/hook/..."
                              value={cfgCustomWH}
                              onChange={(e) => {
                                setCfgCustomWH(e.target.value);
                                setCfgClearWH(false);
                              }}
                            />
                            {settings?.has_custom_webhook && !cfgClearWH && (
                              <button
                                type="button"
                                className="btn btn-xs"
                                onClick={() => {
                                  setCfgCustomWH('');
                                  setCfgClearWH(true);
                                }}
                              >
                                清空
                              </button>
                            )}
                            <button
                              type="button"
                              className="btn btn-xs btn-teal"
                              disabled={testingWebhook}
                              onClick={() => void handleTestWebhook()}
                            >
                              {testingWebhook ? '发送中…' : '测试推送'}
                            </button>
                          </div>
                        </label>
                      </div>
                    )}
                    {onOpenQQBotNotifications && (
                      <div className="qqbot-shortcut-strip" style={{ marginTop: 10 }}>
                        <span>
                          也支持通过 <strong>QQ 机器人 WebSocket</strong> 推送高危 / CISA KEV 漏洞动态
                        </span>
                        <button
                          type="button"
                          className="btn btn-xs btn-teal"
                          onClick={() => {
                            setSettingsOpen(false);
                            onOpenQQBotNotifications();
                          }}
                        >
                          配置 QQ 机器人通知
                        </button>
                      </div>
                    )}
                  </div>
                </div>

                <div className="modal-footer">
                  <button
                    type="button"
                    className="btn btn-sm"
                    onClick={() => setSettingsOpen(false)}
                  >
                    取消
                  </button>
                  <button type="submit" className="btn btn-sm btn-primary" disabled={savingSettings}>
                    {savingSettings ? '保存中…' : '保存配置'}
                  </button>
                </div>
              </form>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

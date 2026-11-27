import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertTriangle,
  Bell,
  BookOpenCheck,
  Bot,
  Check,
  CheckCheck,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Clock,
  Copy,
  Eye,
  Filter,
  Layers,
  List,
  Play,
  RefreshCw,
  Search,
  Server,
  Settings2,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Terminal,
  Trash2,
  Wrench,
  X,
} from 'lucide-react';
import { api } from '../api';
import { buildAlertMCPPrompt } from '../utils/alertMcpPrompt';
import { copyTextToClipboard } from '../utils/clipboard';
import type {
  AlertQuickAction,
  AlertSummaryStats,
  MonitorAlert,
  ServerView,
} from '../types';
import { formatDateTime } from './MonitorCharts';

export interface AlertTargetNavigation {
  serverId: string;
  nonce: number;
}

export interface AlertCenterProps {
  servers: ServerView[];
  initialTarget?: AlertTargetNavigation | null;
  onClearInitialTarget?: () => void;
  onFiringCountChange?: (count: number) => void;
  onActiveByServerChange?: (byServer: Record<string, number>) => void;
  onOpenMonitorDetail: (serverId: string) => void;
  onOpenMonitorPolicy: () => void;
  onOpenVaultSecurity: () => void;
  onRunTerminalCommand: (server: ServerView, command: string, autoExecute: boolean) => void;
  onDiagnoseWithAI: (serverId: string, prompt: string) => void;
  onOpenRunbook?: () => void;
  onNotify: (msg: string) => void;
}

const ALERT_CATEGORIES: { key: string; label: string }[] = [
  { key: 'all', label: '全部分类' },
  { key: 'availability', label: '可用性与连接' },
  { key: 'compute', label: '计算与内存' },
  { key: 'storage', label: '存储与硬件' },
  { key: 'services', label: '服务与容器' },
  { key: 'network', label: '网络与端口' },
  { key: 'security', label: '安全与入侵' },
];

function categoryLabel(cat?: string): string {
  const found = ALERT_CATEGORIES.find((c) => c.key === cat);
  return found ? found.label : '其他告警';
}

function formatAlertHeadline(title: string, serverName: string): string {
  const trimmed = (title || '').trim();
  const srv = (serverName || '').trim();
  if (!trimmed || !srv) return trimmed;
  const exactPrefix = `[${srv}]`;
  if (trimmed.startsWith(exactPrefix)) {
    const rest = trimmed.slice(exactPrefix.length).trim();
    if (rest.length >= 4) return rest;
  }
  return trimmed;
}

function formatDuration(startIso?: string, endIso?: string): string {
  if (!startIso) return '—';
  const startMs = new Date(startIso).getTime();
  const endMs = endIso ? new Date(endIso).getTime() : Date.now();
  if (!Number.isFinite(startMs) || !Number.isFinite(endMs) || endMs < startMs) {
    return '刚刚';
  }
  const totalSec = Math.floor((endMs - startMs) / 1000);
  if (totalSec < 60) return `${Math.max(1, totalSec)} 秒`;
  const totalMin = Math.floor(totalSec / 60);
  if (totalMin < 60) return `${totalMin} 分钟`;
  const hours = Math.floor(totalMin / 60);
  const mins = totalMin % 60;
  if (hours < 24) return mins > 0 ? `${hours} 小时 ${mins} 分` : `${hours} 小时`;
  const days = Math.floor(hours / 24);
  const remH = hours % 24;
  return remH > 0 ? `${days} 天 ${remH} 小时` : `${days} 天`;
}

export const AlertCenter: React.FC<AlertCenterProps> = ({
  servers,
  initialTarget,
  onClearInitialTarget,
  onFiringCountChange,
  onActiveByServerChange,
  onOpenMonitorDetail,
  onOpenMonitorPolicy,
  onOpenVaultSecurity,
  onRunTerminalCommand,
  onDiagnoseWithAI,
  onOpenRunbook,
  onNotify,
}) => {
  const [alerts, setAlerts] = useState<MonitorAlert[]>([]);
  const [globalSummary, setGlobalSummary] = useState<AlertSummaryStats | null>(null);
  const [scopedSummary, setScopedSummary] = useState<AlertSummaryStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  // Filters & view state
  const [statusFilter, setStatusFilter] = useState<string>('active');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [categoryFilter, setCategoryFilter] = useState<string>('all');
  const [serverFilter, setServerFilter] = useState<string>(initialTarget?.serverId || '');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [groupMode, setGroupMode] = useState<'timeline' | 'server'>('timeline');

  // Expanded alert cards & collapsed server groups
  const [expandedIds, setExpandedIds] = useState<Record<string, boolean>>({});
  const [collapsedServers, setCollapsedServers] = useState<Record<string, boolean>>({});
  const autoExpandedServerRef = useRef<string>(initialTarget?.serverId || '');
  const consumedTargetNonceRef = useRef<number>(0);

  // In-flight action trackers
  const [busyAlertId, setBusyAlertId] = useState<string>('');
  const [bulkAcking, setBulkAcking] = useState(false);
  const [clearingResolved, setClearingResolved] = useState(false);
  const [recheckingServerId, setRecheckingServerId] = useState<string>('');
  const [copiedCmdKey, setCopiedCmdKey] = useState<string>('');
  const [copiedMcpAlertId, setCopiedMcpAlertId] = useState<string>('');
  const copiedMcpTimerRef = useRef<number | null>(null);

  useEffect(() => {
    return () => {
      if (copiedMcpTimerRef.current !== null) {
        window.clearTimeout(copiedMcpTimerRef.current);
      }
    };
  }, []);

  const serverById = useMemo(() => {
    const map: Record<string, ServerView> = {};
    for (const s of servers) {
      map[s.id] = s;
    }
    return map;
  }, [servers]);

  // Handle deep-link jump from MonitorCenter, ServerManager, or sidebar reset
  useEffect(() => {
    if (initialTarget && consumedTargetNonceRef.current !== initialTarget.nonce) {
      consumedTargetNonceRef.current = initialTarget.nonce;
      setServerFilter(initialTarget.serverId);
      setStatusFilter('active');
      setSeverityFilter('all');
      setCategoryFilter('all');
      setSearchQuery('');
      autoExpandedServerRef.current = initialTarget.serverId;
      onClearInitialTarget?.();
    }
  }, [initialTarget, onClearInitialTarget]);

  const loadAlerts = useCallback(
    async (silent = false) => {
      if (!silent) setLoading(true);
      else setRefreshing(true);
      try {
        const statusParam = statusFilter === 'all' ? '' : statusFilter;
        const res = await api.listMonitorAlerts(statusParam, serverFilter, 400, {
          severity: severityFilter,
          category: categoryFilter,
          search: searchQuery,
        });
        const list = res.alerts || [];
        setAlerts(list);
        if (res.summary) {
          setGlobalSummary(res.summary);
          onFiringCountChange?.(res.summary.total_active || 0);
          onActiveByServerChange?.(res.summary.active_by_server || {});
        }
        setScopedSummary(res.scoped_summary || null);

        // Auto-expand first alert when jumping to a single server's alerts
        if (autoExpandedServerRef.current && autoExpandedServerRef.current === serverFilter) {
          if (list.length > 0) {
            setExpandedIds({ [list[0].id]: true });
          } else if (
            statusFilter === 'active' &&
            res.scoped_summary &&
            res.scoped_summary.total_active === 0 &&
            res.scoped_summary.resolved > 0
          ) {
            // If user clicked a server with only resolved history, show all cleanly
            setStatusFilter('all');
          }
          autoExpandedServerRef.current = '';
        }
      } catch {
        // Handled globally on 401
      } finally {
        setLoading(false);
        setRefreshing(false);
      }
    },
    [
      statusFilter,
      serverFilter,
      severityFilter,
      categoryFilter,
      searchQuery,
      onFiringCountChange,
      onActiveByServerChange,
    ]
  );

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void loadAlerts(false);
    }, searchQuery ? 180 : 0);
    return () => window.clearTimeout(timer);
  }, [loadAlerts, searchQuery]);

  // Live background refresh while AlertCenter is open
  useEffect(() => {
    const timer = window.setInterval(() => {
      void loadAlerts(true);
    }, 8000);
    return () => window.clearInterval(timer);
  }, [loadAlerts]);

  const activeSummary = serverFilter && scopedSummary ? scopedSummary : globalSummary;
  const selectedServerObj = serverFilter ? serverById[serverFilter] : undefined;

  const firingIdsInView = useMemo(
    () => alerts.filter((a) => a.status === 'firing').map((a) => a.id),
    [alerts]
  );

  const viewBreakdown = useMemo(() => {
    let critical = 0;
    let warning = 0;
    let resolved = 0;
    for (const al of alerts) {
      if (al.status === 'resolved') resolved++;
      else if (al.severity === 'critical') critical++;
      else warning++;
    }
    return { critical, warning, resolved };
  }, [alerts]);

  const expandableAlertIds = useMemo(
    () => alerts.filter((a) => Boolean(a.advice)).map((a) => a.id),
    [alerts]
  );

  const allExpanded = useMemo(
    () => expandableAlertIds.length > 0 && expandableAlertIds.every((id) => Boolean(expandedIds[id])),
    [expandableAlertIds, expandedIds]
  );

  const toggleExpandAll = () => {
    if (allExpanded) {
      setExpandedIds({});
    } else {
      const next: Record<string, boolean> = {};
      for (const id of expandableAlertIds) {
        next[id] = true;
      }
      setExpandedIds(next);
    }
  };

  const groupedAlerts = useMemo(() => {
    const map = new Map<
      string,
      {
        serverId: string;
        serverName: string;
        host: string;
        criticalCount: number;
        warningCount: number;
        firingCount: number;
        items: MonitorAlert[];
      }
    >();
    for (const al of alerts) {
      let grp = map.get(al.server_id);
      if (!grp) {
        grp = {
          serverId: al.server_id,
          serverName: al.server_name,
          host: al.host,
          criticalCount: 0,
          warningCount: 0,
          firingCount: 0,
          items: [],
        };
        map.set(al.server_id, grp);
      }
      grp.items.push(al);
      if (al.status !== 'resolved') {
        if (al.severity === 'critical') grp.criticalCount++;
        else grp.warningCount++;
      }
      if (al.status === 'firing') grp.firingCount++;
    }
    return Array.from(map.values()).sort((a, b) => {
      if (b.criticalCount !== a.criticalCount) return b.criticalCount - a.criticalCount;
      if (b.warningCount !== a.warningCount) return b.warningCount - a.warningCount;
      return b.items.length - a.items.length;
    });
  }, [alerts]);

  const toggleExpand = (id: string) => {
    setExpandedIds((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const handleCopyCommand = async (key: string, cmd: string) => {
    try {
      await copyTextToClipboard(cmd);
      setCopiedCmdKey(key);
      onNotify('指令已复制到剪贴板');
      window.setTimeout(() => {
        setCopiedCmdKey((prev) => (prev === key ? '' : prev));
      }, 1800);
    } catch {
      onNotify('复制失败，请手动选中命令复制');
    }
  };

  const handleAckAlert = async (alertId: string) => {
    setBusyAlertId(alertId);
    try {
      await api.ackMonitorAlert(alertId);
      onNotify('已确认知晓该条告警');
      await loadAlerts(true);
    } catch (err: any) {
      onNotify(err?.message || '确认告警失败');
    } finally {
      setBusyAlertId('');
    }
  };

  const handleBulkAck = async (ids?: string[], targetServerId?: string) => {
    setBulkAcking(true);
    try {
      const res = await api.ackMonitorAlertsBulk({
        ids: ids && ids.length > 0 ? ids : undefined,
        server_id: targetServerId || serverFilter || undefined,
      });
      if (res.acknowledged > 0) {
        onNotify(`已批量确认知晓 ${res.acknowledged} 条触发中告警`);
      } else {
        onNotify('当前没有待确认的触发中告警');
      }
      await loadAlerts(true);
    } catch (err: any) {
      onNotify(err?.message || '批量确认失败');
    } finally {
      setBulkAcking(false);
    }
  };

  const handleResolveAlert = async (alertId: string) => {
    setBusyAlertId(alertId);
    try {
      await api.resolveMonitorAlert(alertId);
      onNotify('已人工标记为已解决（若下次采集仍超限将自动重新触发）');
      await loadAlerts(true);
    } catch (err: any) {
      onNotify(err?.message || '标记已解决失败');
    } finally {
      setBusyAlertId('');
    }
  };

  const handleClearResolved = async () => {
    setClearingResolved(true);
    try {
      const res = await api.clearResolvedMonitorAlerts(serverFilter);
      onNotify(
        res.removed > 0
          ? `已清理 ${res.removed} 条已恢复告警记录`
          : '当前没有可清理的已恢复告警记录'
      );
      await loadAlerts(true);
    } catch (err: any) {
      onNotify(err?.message || '清理已恢复记录失败');
    } finally {
      setClearingResolved(false);
    }
  };

  const handleRecheckServer = async (serverId: string) => {
    setRecheckingServerId(serverId);
    try {
      const res = await api.collectServerMonitor(serverId);
      await loadAlerts(true);
      if (res.snapshot.reachable) {
        onNotify(
          `已完成 [${res.snapshot.server_name}] 复测采集（健康分 ${res.snapshot.health_score}）`
        );
      } else {
        onNotify(`节点 [${res.snapshot.server_name}] 仍不可达：${res.snapshot.error || '连接失败'}`);
      }
    } catch (err: any) {
      onNotify(err?.message || '单机复测采集失败');
    } finally {
      setRecheckingServerId('');
    }
  };

  const handleQuickAction = async (al: MonitorAlert, action: AlertQuickAction) => {
    if (action.kind === 'open_vault_known_hosts') {
      onOpenVaultSecurity();
      return;
    }
    setBusyAlertId(al.id);
    try {
      if (action.kind === 'accept_port_baseline') {
        const res = await api.acceptPortBaseline(al.server_id);
        onNotify(`已采纳 [${al.server_name}] 端口基线（${res.port_baseline.length} 个端口），漂移告警已消除`);
        await loadAlerts(true);
      } else if (action.kind === 'ignore_port_drift_process' && action.target) {
        const res = await api.updatePortDriftIgnore({
          server_id: al.server_id,
          scope: action.scope === 'global' ? 'global' : 'server',
          action: 'add',
          process: action.target,
        });
        onNotify(
          `已将进程 ${res.result.applied_rule} 加入 [${al.server_name}] 端口漂移忽略白名单${
            res.result.resolved_alerts > 0 ? '，告警已消除' : ''
          }`
        );
        await loadAlerts(true);
      } else if (action.kind === 'ignore_port_drift_port' && action.target) {
        const res = await api.updatePortDriftIgnore({
          server_id: al.server_id,
          scope: action.scope === 'global' ? 'global' : 'server',
          action: 'add',
          port: action.target,
        });
        onNotify(
          `已将端口 ${res.result.applied_rule} 加入 [${al.server_name}] 端口漂移忽略白名单${
            res.result.resolved_alerts > 0 ? '，告警已消除' : ''
          }`
        );
        await loadAlerts(true);
      } else if (action.kind === 'accept_security_baseline') {
        await api.acceptSecurityBaseline(al.server_id);
        onNotify(`已采纳 [${al.server_name}] 安全基线，对应漂移告警已消除`);
        await loadAlerts(true);
      }
    } catch (err: any) {
      onNotify(err?.message || '执行快捷处置失败');
    } finally {
      setBusyAlertId('');
    }
  };

  const handleSendToTerminal = (al: MonitorAlert, command: string, risk: 'readonly' | 'mutating') => {
    const srv = serverById[al.server_id];
    if (!srv) {
      onNotify('未在主机资产中找到对应服务器，可能已被删除');
      return;
    }
    const autoExecute = risk === 'readonly';
    onRunTerminalCommand(srv, command, autoExecute);
  };

  const handleTriggerAI = (al: MonitorAlert) => {
    const prompt =
      al.advice?.ai_prompt ||
      `请协助排查服务器「${al.server_name}」(${al.host}) 的监控告警：${al.title}（${al.rule_name}，实测 ${al.metric_text}）。详情：${al.detail}`;
    onDiagnoseWithAI(al.server_id, prompt);
  };

  const handleCopyMCPPrompt = async (al: MonitorAlert) => {
    const prompt = buildAlertMCPPrompt(al, serverById[al.server_id]);
    try {
      await copyTextToClipboard(prompt);
      setCopiedMcpAlertId(al.id);
      if (copiedMcpTimerRef.current !== null) {
        window.clearTimeout(copiedMcpTimerRef.current);
      }
      copiedMcpTimerRef.current = window.setTimeout(() => {
        setCopiedMcpAlertId((prev) => (prev === al.id ? '' : prev));
        copiedMcpTimerRef.current = null;
      }, 2000);
      onNotify('已复制外部 MCP AI 诊断文案，可直接粘贴至 Claude Code / Codex / Antigravity / Cursor');
    } catch {
      onNotify('复制失败，请检查浏览器剪贴板权限');
    }
  };

  const renderAlertCard = (al: MonitorAlert) => {
    const isExpanded = Boolean(expandedIds[al.id]);
    const advice = al.advice;
    const isResolved = al.status === 'resolved';
    const isBusy = busyAlertId === al.id;
    const isRechecking = recheckingServerId === al.server_id;
    const isMcpCopied = copiedMcpAlertId === al.id;
    const tone = isResolved ? 'resolved' : al.severity === 'critical' ? 'critical' : 'warning';
    const cmdCount = advice?.commands?.length || 0;
    const quickCount = advice?.quick_actions?.length || 0;
    const runbookCount = advice?.runbooks?.length || 0;
    const headline = formatAlertHeadline(al.title, al.server_name);

    return (
      <article
        key={al.id}
        id={`alert-card-${al.id}`}
        className={`al-card tone-${tone} status-${al.status} ${isExpanded ? 'expanded' : ''}`}
      >
        {/* Top Summary Clickable Region */}
        <div
          className="al-card-main"
          onClick={() => toggleExpand(al.id)}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault();
              toggleExpand(al.id);
            }
          }}
        >
          {/* Zone 1: Semantic Header Strip — Distinct Card Top Anchor */}
          <div className="al-card-top">
            <div className="al-card-badges">
              {isResolved ? (
                <>
                  <span className="al-sev-badge resolved">
                    <CheckCircle2 size={12} /> 已恢复
                  </span>
                  <span
                    className={`al-origin-sev ${al.severity === 'critical' ? 'critical' : 'warning'}`}
                  >
                    {al.severity === 'critical' ? '原严重' : '原警告'}
                  </span>
                </>
              ) : (
                <>
                  <span className={`al-sev-badge ${al.severity === 'critical' ? 'critical' : 'warning'}`}>
                    {al.severity === 'critical' ? (
                      <>
                        <ShieldAlert size={12} /> 严重
                      </>
                    ) : (
                      <>
                        <AlertTriangle size={12} /> 警告
                      </>
                    )}
                  </span>
                  {al.status === 'firing' ? (
                    <span className={`al-status-flag firing ${tone}`}>
                      <span className="al-live-dot" aria-hidden="true" />
                      触发中
                    </span>
                  ) : (
                    <span className="al-status-flag acknowledged">
                      <Check size={12} />
                      已知晓
                    </span>
                  )}
                </>
              )}

              {groupMode === 'timeline' && (
                <button
                  type="button"
                  className="al-server-pill"
                  onClick={(e) => {
                    e.stopPropagation();
                    setServerFilter(al.server_id);
                  }}
                  title={`仅查看 ${al.server_name} (${al.host}) 的告警`}
                >
                  <Server size={12} />
                  <span className="al-server-pill-name">{al.server_name}</span>
                  {al.host && <span className="mono al-server-pill-host">{al.host}</span>}
                </button>
              )}

              <span className="al-cat-label">{categoryLabel(al.category)}</span>
            </div>

            <div className="al-card-top-right" onClick={(e) => e.stopPropagation()}>
              <div
                className="al-time-meta tabular"
                title={`首次触发：${formatDateTime(al.triggered_at)}`}
              >
                <Clock size={12} />
                <span>
                  {isResolved
                    ? `耗时 ${formatDuration(al.triggered_at, al.resolved_at)}`
                    : `持续 ${formatDuration(al.triggered_at)}`}
                </span>
                <span className="al-meta-sep" aria-hidden="true">
                  ·
                </span>
                <span title="连续或累计触发次数">触发 {al.occurrences} 次</span>
              </div>
              <button
                type="button"
                className={`btn btn-sm al-expand-btn ${isExpanded ? 'is-open' : ''}`}
                onClick={() => toggleExpand(al.id)}
                aria-expanded={isExpanded}
              >
                {isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                <span>{isExpanded ? '收起建议' : '修复建议'}</span>
              </button>
            </div>
          </div>

          {/* Zone 2: Core Content — Headline, Rule Detail, Metric Callout & Compact Advice */}
          <div className="al-card-content">
            <div className="al-card-body">
              <div className="al-card-text">
                <div className="al-card-title">{headline}</div>
                <div className="al-card-detail">
                  <span className="al-rule-tag">{al.rule_name}</span>
                  <span className="al-detail-desc">{al.detail}</span>
                </div>
              </div>

              <div className={`al-metric-box tone-${tone} mono`}>
                <div className="al-metric-head">
                  <span className="al-metric-label">{isResolved ? '恢复前指标' : '当前实测'}</span>
                  <strong className={`al-metric-val ${tone}`}>{al.metric_text || '—'}</strong>
                </div>
                <div className="al-metric-foot">
                  {al.threshold_text && (
                    <div className="al-metric-row">
                      <span className="al-metric-sub-label">阈值</span>
                      <span className="al-metric-thresh">{al.threshold_text}</span>
                    </div>
                  )}
                  <div className="al-metric-time">
                    {isResolved
                      ? `恢复 ${formatDateTime(al.resolved_at)}`
                      : `最近 ${formatDateTime(al.last_seen_at)}`}
                  </div>
                </div>
              </div>
            </div>

            {/* Smart Remediation Preview Bar (calm left-accented insight strip) */}
            {advice && (
              <div className="al-advice-preview">
                <div className="al-advice-preview-text">
                  <Wrench size={13.5} className="al-advice-icon" />
                  <span className="al-advice-summary">
                    <strong className="al-advice-label">处置建议</strong>
                    {advice.summary}
                  </span>
                </div>
                {(cmdCount > 0 || quickCount > 0 || runbookCount > 0) && (
                  <div className="al-advice-preview-pills">
                    {quickCount > 0 && <span className="al-advice-badge quick">含一键处置</span>}
                    {cmdCount > 0 && <span className="al-advice-badge cmd">{cmdCount} 条指令</span>}
                    {runbookCount > 0 && (
                      <span className="al-advice-badge runbook">{runbookCount} 篇 Runbook</span>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Zone 3: Grounded Action Footer — Distinct Card Bottom Anchor */}
          <div className="al-card-actions" onClick={(e) => e.stopPropagation()}>
            <div className="al-card-actions-left">
              {al.status === 'firing' && (
                <button
                  type="button"
                  className="btn btn-sm al-btn-primary-action"
                  disabled={isBusy}
                  onClick={() => void handleAckAlert(al.id)}
                >
                  <Check size={13} /> 确认知晓
                </button>
              )}
              {!isResolved && (
                <button
                  type="button"
                  className={`btn btn-sm ${
                    al.status === 'acknowledged' ? 'al-btn-primary-action' : 'btn-ghost al-btn-quiet'
                  }`}
                  disabled={isBusy}
                  onClick={() => void handleResolveAlert(al.id)}
                  title="人工标记解决并关闭当前告警，若下次采集仍超限会重新触发"
                >
                  <CheckCircle2 size={13} /> 标记已解决
                </button>
              )}
              <button
                type="button"
                className="btn btn-sm btn-ghost al-btn-quiet"
                disabled={isRechecking}
                onClick={() => void handleRecheckServer(al.server_id)}
                title="立即触发单机全维采集以验证修复是否生效"
              >
                <RefreshCw size={12.5} className={isRechecking ? 'spin-icon' : ''} />
                {isRechecking ? '复测中...' : '立即复测'}
              </button>
            </div>

            <div className="al-card-actions-right">
              <button
                type="button"
                className="btn btn-sm btn-ghost al-btn-quiet"
                onClick={() => onOpenMonitorDetail(al.server_id)}
              >
                <Eye size={13} /> 单机透视
              </button>
              <button
                type="button"
                className={`btn btn-sm al-btn-mcp-copy ${isMcpCopied ? 'is-copied' : ''}`}
                data-action="copy-mcp-prompt"
                onClick={() => void handleCopyMCPPrompt(al)}
                title="一键复制面向外部 MCP AI（Claude Code / Codex / Antigravity / Cursor）的告警排障提示词，粘贴即用"
                aria-label={`一键复制「${headline}」的外部 MCP AI 诊断文案`}
              >
                {isMcpCopied ? <Check size={13} /> : <Copy size={13} />}
                <span>{isMcpCopied ? '已复制 MCP 文案' : '复制 MCP 文案'}</span>
              </button>
              <button
                type="button"
                className="btn btn-sm btn-teal"
                onClick={() => handleTriggerAI(al)}
                title="跳转至 AI 智能运维，自动选中该主机并预填告警排障提示词（不会自动发送）"
              >
                <Bot size={13} /> AI 深度诊断
              </button>
            </div>
          </div>
        </div>

        {/* Expanded Smart Remediation Drawer */}
        {isExpanded && advice && (
          <div className="al-remediation-panel">
            {/* Root cause + Snapshot Evidence */}
            <div className="al-rem-grid">
              <div className="al-rem-block">
                <div className="al-rem-heading">
                  <Sparkles size={13.5} /> 根因分析与处置指引
                  {advice.context_aware && (
                    <span className="tag-chip teal" style={{ marginLeft: 'auto', fontSize: 10.5 }}>
                      已结合主机实时快照
                    </span>
                  )}
                </div>
                {advice.root_cause && <p className="al-rem-rootcause">{advice.root_cause}</p>}
                {advice.steps && advice.steps.length > 0 && (
                  <ol className="al-rem-steps">
                    {advice.steps.map((st, idx) => (
                      <li key={idx}>{st}</li>
                    ))}
                  </ol>
                )}
              </div>

              <div className="al-rem-block">
                <div className="al-rem-heading">
                  <ShieldAlert size={13.5} /> 节点现场证据与快捷处置
                </div>
                {advice.evidence && advice.evidence.length > 0 ? (
                  <ul className="al-evidence-list">
                    {advice.evidence.map((ev, idx) => (
                      <li key={idx} className="mono">
                        {ev}
                      </li>
                    ))}
                  </ul>
                ) : (
                  <div className="al-evidence-empty">
                    首次触发时间：{formatDateTime(al.triggered_at)} · 最近检测：
                    {formatDateTime(al.last_seen_at)}
                    {al.acknowledged_at ? ` · 确认于 ${formatDateTime(al.acknowledged_at)}` : ''}
                  </div>
                )}

                {advice.quick_actions && advice.quick_actions.length > 0 && (
                  <div className="al-quick-actions">
                    {advice.quick_actions.map((qa, idx) => (
                      <div key={idx} className="al-quick-action-row">
                        <div className="al-quick-action-info">
                          <strong>{qa.label}</strong>
                          {qa.description && <span>{qa.description}</span>}
                        </div>
                        <button
                          type="button"
                          className="btn btn-sm btn-primary"
                          disabled={isBusy}
                          onClick={() => void handleQuickAction(al, qa)}
                        >
                          <ShieldCheck size={13} /> {qa.label}
                        </button>
                      </div>
                    ))}
                  </div>
                )}

                {advice.runbooks && advice.runbooks.length > 0 && (
                  <div className="al-runbook-refs">
                    <div className="al-runbook-refs-title">
                      <BookOpenCheck size={13} /> 已沉淀关联排障 Runbook
                    </div>
                    {advice.runbooks.map((rb) => (
                      <div key={rb.id} className="al-runbook-chip-row">
                        <div>
                          <strong>{rb.title}</strong>
                          {rb.symptom && <div className="al-runbook-symptom">{rb.symptom}</div>}
                        </div>
                        {onOpenRunbook && (
                          <button type="button" className="btn btn-sm btn-ghost" onClick={onOpenRunbook}>
                            查看知识库
                          </button>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* Smart Command List */}
            {advice.commands && advice.commands.length > 0 && (
              <div className="al-cmd-section">
                <div className="al-rem-heading">
                  <Terminal size={13.5} /> 智能排查与修复指令（只读可直接运行 · 变更类仅填入终端由你回车确认）
                </div>
                <div className="al-cmd-list">
                  {advice.commands.map((cmd, idx) => {
                    const cmdKey = `${al.id}-${idx}`;
                    const isMutating = cmd.risk === 'mutating';
                    const isCopied = copiedCmdKey === cmdKey;
                    const hasServer = Boolean(serverById[al.server_id]);
                    return (
                      <div
                        key={cmdKey}
                        className={`al-cmd-card ${isMutating ? 'mutating' : 'readonly'}`}
                      >
                        <div className="al-cmd-head">
                          <div className="al-cmd-meta">
                            <span className={`tag-chip ${isMutating ? 'amber' : 'teal'}`}>
                              {isMutating ? '状态变更 · 需回车确认' : '只读排查'}
                            </span>
                            <strong className="al-cmd-label">{cmd.label}</strong>
                          </div>
                          <div className="al-cmd-btns">
                            <button
                              type="button"
                              className="btn btn-sm"
                              onClick={() => void handleCopyCommand(cmdKey, cmd.command)}
                            >
                              {isCopied ? <Check size={12.5} /> : <Copy size={12.5} />}
                              {isCopied ? '已复制' : '复制'}
                            </button>
                            <button
                              type="button"
                              className={`btn btn-sm ${isMutating ? '' : 'btn-primary'}`}
                              disabled={!hasServer}
                              onClick={() => handleSendToTerminal(al, cmd.command, cmd.risk)}
                              title={
                                isMutating
                                  ? '打开该机 SSH 终端并将命令填入命令行（不自动回车，防止误操作）'
                                  : '打开该机 SSH 终端并自动执行只读排查指令'
                              }
                            >
                              {isMutating ? <Terminal size={12.5} /> : <Play size={12.5} />}
                              {isMutating ? '填入终端确认' : '在终端执行'}
                            </button>
                          </div>
                        </div>
                        {cmd.description && <div className="al-cmd-desc">{cmd.description}</div>}
                        <pre className="al-cmd-code mono">{cmd.command}</pre>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        )}
      </article>
    );
  };

  return (
    <div className="workspace-surface" id="alert-center-view">
      {/* Page Header */}
      <div className="page-header">
        <div className="page-header-title">
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
            <h2>告警信息</h2>
            {(globalSummary?.total_active || 0) > 0 ? (
              <span className="tag-chip danger tabular">
                <Bell size={11.5} /> {globalSummary?.total_active} 条未恢复
              </span>
            ) : (
              <span className="tag-chip teal">
                <ShieldCheck size={11.5} /> 全网零活跃告警
              </span>
            )}
          </div>
          <p>
            集中展示所有服务器监控告警与事件记录，结合实时主机快照自动提供根因线索、风险分级修复指令，以及内置 AI 深度诊断与外部 MCP 提示词一键复制
          </p>
        </div>

        <div className="page-header-actions">
          <button
            type="button"
            className="btn btn-sm"
            onClick={onOpenMonitorPolicy}
            title="前往状态监控配置告警规则阈值与 Webhook 推送通道"
          >
            <Settings2 size={13.5} /> 阈值与推送策略
          </button>
          <button
            type="button"
            className="btn btn-sm"
            disabled={refreshing}
            onClick={() => void loadAlerts(true)}
          >
            <RefreshCw size={13.5} className={refreshing ? 'spin-icon' : ''} /> 刷新
          </button>
          <button
            type="button"
            className="btn btn-sm"
            disabled={clearingResolved || (activeSummary?.resolved || 0) === 0}
            onClick={() => void handleClearResolved()}
            title={serverFilter ? '清理当前筛选服务器的已恢复记录' : '清理全部已恢复历史告警'}
          >
            <Trash2 size={13.5} /> 清理已恢复
            {(activeSummary?.resolved || 0) > 0 ? ` (${activeSummary?.resolved})` : ''}
          </button>
          {firingIdsInView.length > 0 && (
            <button
              type="button"
              id="alerts-bulk-ack-btn"
              className="btn btn-primary btn-sm"
              disabled={bulkAcking}
              onClick={() => void handleBulkAck(firingIdsInView, serverFilter)}
            >
              <CheckCheck size={14} />
              {bulkAcking ? '确认中...' : `批量确认知晓 (${firingIdsInView.length})`}
            </button>
          )}
        </div>
      </div>

      <div className="page-body">
        {/* Server Scoped Context Banner (when jumped from MonitorCenter / ServerManager) */}
        {serverFilter && (
          <div className="al-server-banner" id="alert-server-filter-banner">
            <div className="al-server-banner-left">
              <Filter size={14.5} style={{ color: 'var(--accent-teal)', flexShrink: 0 }} />
              <span>
                当前仅查看服务器{' '}
                <strong>{selectedServerObj?.name || serverFilter}</strong>
                {selectedServerObj && (
                  <span className="mono" style={{ color: 'var(--text-muted)', marginLeft: 6 }}>
                    {selectedServerObj.host}:{selectedServerObj.port}
                  </span>
                )}
              </span>
              {scopedSummary && (
                <span
                  className={`tag-chip ${scopedSummary.total_active > 0 ? 'danger' : 'teal'} tabular`}
                >
                  {scopedSummary.total_active} 条活跃 / {scopedSummary.resolved} 条已恢复
                </span>
              )}
            </div>
            <div className="al-server-banner-actions">
              <button
                type="button"
                className="btn btn-sm"
                disabled={recheckingServerId === serverFilter}
                onClick={() => void handleRecheckServer(serverFilter)}
              >
                <RefreshCw
                  size={12.5}
                  className={recheckingServerId === serverFilter ? 'spin-icon' : ''}
                />
                立即复测采集
              </button>
              <button
                type="button"
                className="btn btn-sm"
                onClick={() => onOpenMonitorDetail(serverFilter)}
              >
                <Eye size={13} /> 返回单机深度透视
              </button>
              <button
                type="button"
                className="btn btn-sm btn-ghost"
                onClick={() => setServerFilter('')}
              >
                <X size={13.5} /> 显示全部主机
              </button>
            </div>
          </div>
        )}

        {/* 4-Column KPI Summary Strip */}
        <div className="al-kpi-grid">
          <div
            className={`mon-kpi-card clickable ${
              (activeSummary?.total_active || 0) > 0 ? 'alerting' : ''
            } ${statusFilter === 'active' && severityFilter === 'all' ? 'al-kpi-selected' : ''}`}
            onClick={() => {
              setStatusFilter('active');
              setSeverityFilter('all');
            }}
          >
            <div className="mon-kpi-top">
              <span>{serverFilter ? '本机未恢复活跃告警' : '全网未恢复活跃告警'}</span>
              <Bell
                size={15}
                style={{
                  color:
                    (activeSummary?.total_active || 0) > 0
                      ? 'var(--danger-text)'
                      : 'var(--text-muted)',
                }}
              />
            </div>
            <div
              className="mon-kpi-value tabular"
              style={{
                color:
                  (activeSummary?.total_active || 0) > 0 ? 'var(--danger-text)' : undefined,
              }}
            >
              {activeSummary?.total_active ?? 0}
            </div>
            <div className="mon-kpi-foot">
              触发中 {activeSummary?.firing ?? 0} · 已知晓 {activeSummary?.acknowledged ?? 0}
            </div>
          </div>

          <div
            className={`mon-kpi-card clickable ${
              severityFilter === 'critical' ? 'al-kpi-selected' : ''
            }`}
            onClick={() => {
              setStatusFilter('active');
              setSeverityFilter((prev) => (prev === 'critical' ? 'all' : 'critical'));
            }}
          >
            <div className="mon-kpi-top">
              <span>严重告警 (CRITICAL)</span>
              <ShieldAlert
                size={15}
                style={{
                  color:
                    (activeSummary?.critical_active || 0) > 0
                      ? 'var(--danger-text)'
                      : 'var(--text-muted)',
                }}
              />
            </div>
            <div
              className="mon-kpi-value tabular"
              style={{
                color:
                  (activeSummary?.critical_active || 0) > 0 ? 'var(--danger-text)' : undefined,
              }}
            >
              {activeSummary?.critical_active ?? 0}
            </div>
            <div className="mon-kpi-foot">需优先排查处置 · 点击仅看严重项</div>
          </div>

          <div
            className={`mon-kpi-card clickable ${
              severityFilter === 'warning' ? 'al-kpi-selected' : ''
            }`}
            onClick={() => {
              setStatusFilter('active');
              setSeverityFilter((prev) => (prev === 'warning' ? 'all' : 'warning'));
            }}
          >
            <div className="mon-kpi-top">
              <span>警告提醒 (WARNING)</span>
              <AlertTriangle
                size={15}
                style={{
                  color:
                    (activeSummary?.warning_active || 0) > 0
                      ? 'var(--amber-text)'
                      : 'var(--text-muted)',
                }}
              />
            </div>
            <div
              className="mon-kpi-value tabular"
              style={{
                color:
                  (activeSummary?.warning_active || 0) > 0 ? 'var(--amber-text)' : undefined,
              }}
            >
              {activeSummary?.warning_active ?? 0}
            </div>
            <div className="mon-kpi-foot">负载趋势与基线预警 · 点击仅看警告项</div>
          </div>

          <div
            className={`mon-kpi-card clickable ${
              statusFilter === 'resolved' ? 'al-kpi-selected' : ''
            }`}
            onClick={() =>
              setStatusFilter((prev) => (prev === 'resolved' ? 'active' : 'resolved'))
            }
          >
            <div className="mon-kpi-top">
              <span>{serverFilter ? '已恢复历史记录' : '受影响主机 / 已恢复'}</span>
              <CheckCircle2 size={15} style={{ color: 'var(--status-online)' }} />
            </div>
            <div className="mon-kpi-value tabular">
              {serverFilter ? (
                activeSummary?.resolved ?? 0
              ) : (
                <>
                  {activeSummary?.affected_servers ?? 0}
                  <span className="mon-kpi-denom"> / {servers.length} 台</span>
                </>
              )}
            </div>
            <div className="mon-kpi-foot">
              已恢复记录 {activeSummary?.resolved ?? 0} 条 · 点击切换查看已恢复
            </div>
          </div>
        </div>

        {/* Multi-Dimensional Filter Toolbar */}
        <div className="al-toolbar">
          <div className="al-toolbar-row">
            <div className="group-pills">
              {[
                ['active', `未恢复活跃 (${activeSummary?.total_active ?? 0})`],
                ['firing', `触发中 (${activeSummary?.firing ?? 0})`],
                ['acknowledged', `已知晓 (${activeSummary?.acknowledged ?? 0})`],
                ['resolved', `已恢复 (${activeSummary?.resolved ?? 0})`],
                ['all', '全部记录'],
              ].map(([k, label]) => (
                <button
                  key={k}
                  type="button"
                  className={`group-pill ${statusFilter === k ? 'active' : ''}`}
                  onClick={() => setStatusFilter(k)}
                >
                  {label}
                </button>
              ))}
            </div>

            <div className="mon-view-toggle" title="切换时间流或按主机聚合视图">
              <button
                type="button"
                className={`mon-toggle-icon ${groupMode === 'timeline' ? 'active' : ''}`}
                onClick={() => setGroupMode('timeline')}
                title="按时间流展示"
              >
                <List size={14} />
              </button>
              <button
                type="button"
                className={`mon-toggle-icon ${groupMode === 'server' ? 'active' : ''}`}
                onClick={() => setGroupMode('server')}
                title="按服务器分组聚合"
              >
                <Layers size={14} />
              </button>
            </div>
          </div>

          <div className="al-toolbar-row secondary">
            <div className="group-pills">
              {[
                ['all', '全部级别'],
                ['critical', '仅严重'],
                ['warning', '仅警告'],
              ].map(([k, label]) => (
                <button
                  key={k}
                  type="button"
                  className={`group-pill ${severityFilter === k ? 'active' : ''}`}
                  onClick={() => setSeverityFilter(k)}
                >
                  {label}
                </button>
              ))}
            </div>

            <div className="al-filter-controls">
              <select
                className="select al-filter-select"
                value={categoryFilter}
                onChange={(e) => setCategoryFilter(e.target.value)}
                aria-label="按规则分类筛选"
              >
                {ALERT_CATEGORIES.map((c) => {
                  const cnt =
                    c.key === 'all'
                      ? undefined
                      : activeSummary?.active_by_category?.[c.key] || 0;
                  return (
                    <option key={c.key} value={c.key}>
                      {c.label}
                      {cnt && cnt > 0 ? ` (${cnt})` : ''}
                    </option>
                  );
                })}
              </select>

              <select
                id="alert-server-filter-select"
                className="select al-filter-select server"
                value={serverFilter}
                onChange={(e) => setServerFilter(e.target.value)}
                aria-label="按服务器筛选"
              >
                <option value="">全部服务器节点</option>
                {servers.map((srv) => {
                  const cnt = globalSummary?.active_by_server?.[srv.id] || 0;
                  return (
                    <option key={srv.id} value={srv.id}>
                      {srv.name} ({srv.host})
                      {cnt > 0 ? ` · ${cnt} 告警` : ''}
                    </option>
                  );
                })}
              </select>

              <div className="input-with-icon al-search-box">
                <span className="input-icon-left">
                  <Search size={13.5} />
                </span>
                <input
                  className="input al-search-input"
                  placeholder="搜索告警标题、详情、主机名或指标..."
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

        {/* Main Alert List / Grouped List */}
        {loading && alerts.length === 0 ? (
          <div className="empty-state">正在加载监控告警与智能修复建议...</div>
        ) : alerts.length === 0 ? (
          <div className="empty-state" style={{ padding: '48px 20px' }}>
            <div className="empty-state-icon">
              <CheckCircle2 size={24} style={{ color: 'var(--status-online)' }} />
            </div>
            <h3>
              {serverFilter
                ? `服务器「${selectedServerObj?.name || serverFilter}」当前没有匹配的告警记录`
                : '当前筛选条件下没有匹配的监控告警'}
            </h3>
            <p>
              {statusFilter === 'active'
                ? '纳管主机各项资源阈值、守护服务与安全基线均处于正常范围内；如需回看既往事件可切换至「全部记录」。'
                : '请尝试放宽状态、级别、分类或搜索关键词过滤条件。'}
            </p>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', justifyContent: 'center' }}>
              {statusFilter !== 'all' && (
                <button
                  type="button"
                  className="btn btn-sm"
                  onClick={() => setStatusFilter('all')}
                >
                  查看全部历史告警
                </button>
              )}
              {(severityFilter !== 'all' ||
                categoryFilter !== 'all' ||
                searchQuery ||
                serverFilter) && (
                <button
                  type="button"
                  className="btn btn-sm btn-primary"
                  onClick={() => {
                    setSeverityFilter('all');
                    setCategoryFilter('all');
                    setSearchQuery('');
                    setServerFilter('');
                  }}
                >
                  重置全部筛选
                </button>
              )}
            </div>
          </div>
        ) : (
          <>
            {/* Compact Feed Context & Bulk Expand Strip */}
            <div className="al-list-bar">
              <div className="al-list-bar-summary tabular">
                <span>
                  共 <strong>{alerts.length}</strong> 条匹配告警
                </span>
                {viewBreakdown.critical > 0 && (
                  <span className="al-list-dot-stat critical">
                    <span className="al-stat-dot" aria-hidden="true" />
                    严重 {viewBreakdown.critical}
                  </span>
                )}
                {viewBreakdown.warning > 0 && (
                  <span className="al-list-dot-stat warning">
                    <span className="al-stat-dot" aria-hidden="true" />
                    警告 {viewBreakdown.warning}
                  </span>
                )}
                {viewBreakdown.resolved > 0 && (
                  <span className="al-list-dot-stat resolved">
                    <span className="al-stat-dot" aria-hidden="true" />
                    已恢复 {viewBreakdown.resolved}
                  </span>
                )}
              </div>
              {expandableAlertIds.length > 0 && (
                <button
                  type="button"
                  className="btn btn-sm btn-ghost al-list-toggle-all"
                  onClick={toggleExpandAll}
                >
                  {allExpanded ? <ChevronDown size={13.5} /> : <ChevronRight size={13.5} />}
                  <span>{allExpanded ? '收起全部建议' : '展开全部建议'}</span>
                </button>
              )}
            </div>

            {groupMode === 'server' ? (
              <div className="al-server-groups">
                {groupedAlerts.map((grp) => {
                  const collapsed = Boolean(collapsedServers[grp.serverId]);
                  const firingIds = grp.items
                    .filter((i) => i.status === 'firing')
                    .map((i) => i.id);
                  return (
                    <section key={grp.serverId} className="al-server-group">
                      <div
                        className="al-server-group-head"
                        onClick={() =>
                          setCollapsedServers((prev) => ({
                            ...prev,
                            [grp.serverId]: !prev[grp.serverId],
                          }))
                        }
                      >
                        <div className="al-server-group-title">
                          {collapsed ? <ChevronRight size={15} /> : <ChevronDown size={15} />}
                          <Server size={15} style={{ color: 'var(--accent-teal)' }} />
                          <strong>{grp.serverName}</strong>
                          <span className="mono al-group-host">{grp.host}</span>
                          {grp.criticalCount > 0 && (
                            <span className="al-sev-badge critical compact tabular">
                              严重 {grp.criticalCount}
                            </span>
                          )}
                          {grp.warningCount > 0 && (
                            <span className="al-sev-badge warning compact tabular">
                              警告 {grp.warningCount}
                            </span>
                          )}
                          <span className="al-group-count tabular">共 {grp.items.length} 条</span>
                        </div>

                        <div
                          className="al-server-group-actions"
                          onClick={(e) => e.stopPropagation()}
                        >
                          {firingIds.length > 0 && (
                            <button
                              type="button"
                              className="btn btn-sm"
                              disabled={bulkAcking}
                              onClick={() => void handleBulkAck(firingIds, grp.serverId)}
                            >
                              <CheckCheck size={13} /> 确认本机 ({firingIds.length})
                            </button>
                          )}
                          <button
                            type="button"
                            className="btn btn-sm btn-ghost al-btn-quiet"
                            onClick={() => onOpenMonitorDetail(grp.serverId)}
                          >
                            <Eye size={13} /> 单机透视
                          </button>
                        </div>
                      </div>
                      {!collapsed && (
                        <div className="al-card-stack">
                          {grp.items.map((al) => renderAlertCard(al))}
                        </div>
                      )}
                    </section>
                  );
                })}
              </div>
            ) : (
              <div className="al-card-stack">{alerts.map((al) => renderAlertCard(al))}</div>
            )}
          </>
        )}
      </div>
    </div>
  );
};

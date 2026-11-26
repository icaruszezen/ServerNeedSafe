import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Bell,
  CheckCircle2,
  Clock,
  Cpu,
  Download,
  Eye,
  HardDrive,
  Layers,
  LayoutGrid,
  List,
  Lock,
  Network,
  RefreshCw,
  Save,
  Search,
  Server,
  Settings2,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  Trash2,
} from 'lucide-react';
import { api, ApiError } from '../api';
import type {
  HostKeyUntrustedInfo,
  MonitorAlert,
  MonitorAlertRule,
  MonitorHealthLevel,
  MonitorOverviewResponse,
  MonitorRuntimeStatus,
  MonitorSettings,
  ServerMonitorCardItem,
  ServerMonitorDetail,
  ServerView,
} from '../types';
import { HostKeyModal } from './HostKeyModal';
import {
  formatBytesRate,
  formatBytesTotal,
  formatDateTime,
  formatTimeShort,
  HealthScoreGauge,
  MiniSparkline,
  TimeSeriesChart,
} from './MonitorCharts';

type MonitorSubTab = 'overview' | 'detail' | 'alerts' | 'policy';
type DetailSectionTab = 'metrics' | 'procs_ports' | 'services_security';

interface MonitorCenterProps {
  servers: ServerView[];
  initialServerId?: string;
  onClearInitialServer?: () => void;
  onConnectTerminal: (server: ServerView, openSftp?: boolean) => void;
  onNavigateServers: () => void;
  onFiringCountChange?: (count: number) => void;
  onNotify: (msg: string) => void;
}

function healthLabel(level?: MonitorHealthLevel): string {
  switch (level) {
    case 'healthy':
      return '运行健康';
    case 'warning':
      return '负载预警';
    case 'critical':
      return '严重告警';
    case 'offline':
      return '离线不可达';
    default:
      return '待首次采集';
  }
}

function healthBadgeClass(level?: MonitorHealthLevel): string {
  switch (level) {
    case 'healthy':
      return 'teal';
    case 'warning':
      return 'amber';
    case 'critical':
    case 'offline':
      return 'danger';
    default:
      return '';
  }
}

function barToneClass(pct: number, warn = 75, crit = 90): string {
  if (pct >= crit) return 'crit';
  if (pct >= warn) return 'warn';
  return 'ok';
}

export const MonitorCenter: React.FC<MonitorCenterProps> = ({
  servers,
  initialServerId,
  onClearInitialServer,
  onConnectTerminal,
  onNavigateServers,
  onFiringCountChange,
  onNotify,
}) => {
  const [subTab, setSubTab] = useState<MonitorSubTab>('overview');
  const [detailTab, setDetailTab] = useState<DetailSectionTab>('metrics');
  const [viewMode, setViewMode] = useState<'grid' | 'table'>('grid');

  // Overview state
  const [overview, setOverview] = useState<MonitorOverviewResponse | null>(null);
  const [loadingOverview, setLoadingOverview] = useState(true);
  const [collectingAll, setCollectingAll] = useState(false);
  const [collectingServerId, setCollectingServerId] = useState('');
  const [healthFilter, setHealthFilter] = useState<'all' | 'abnormal' | 'healthy' | 'offline'>('all');
  const [groupFilter, setGroupFilter] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  // Node Detail state
  const [selectedServerId, setSelectedServerId] = useState<string>('');
  const [historyRange, setHistoryRange] = useState<string>('1h');
  const [nodeDetail, setNodeDetail] = useState<ServerMonitorDetail | null>(null);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [runtime, setRuntime] = useState<MonitorRuntimeStatus | null>(null);

  // Alerts tab state
  const [alertsList, setAlertsList] = useState<MonitorAlert[]>([]);
  const [alertStatusFilter, setAlertStatusFilter] = useState<string>('active');
  const [alertServerFilter, setAlertServerFilter] = useState<string>('');
  const [loadingAlerts, setLoadingAlerts] = useState(false);

  // Policy tab state
  const [policySettings, setPolicySettings] = useState<MonitorSettings | null>(null);
  const [policyRules, setPolicyRules] = useState<MonitorAlertRule[]>([]);
  const [savingPolicy, setSavingPolicy] = useState(false);
  const [confirmClearAll, setConfirmClearAll] = useState(false);

  // HostKey verification modal on manual single-node collect
  const [hostKeyPrompt, setHostKeyPrompt] = useState<{
    serverId: string;
    info: HostKeyUntrustedInfo;
  } | null>(null);

  const loadOverview = useCallback(async () => {
    try {
      const res = await api.getMonitorOverview();
      setOverview(res);
      setRuntime(res.runtime);
      if (onFiringCountChange) {
        onFiringCountChange(res.kpi.firing_alerts || 0);
      }
      if (!selectedServerId && res.nodes.length > 0) {
        setSelectedServerId(res.nodes[0].server.id);
      }
    } catch {
      // handled by global 401 listener if locked
    } finally {
      setLoadingOverview(false);
    }
  }, [onFiringCountChange, selectedServerId]);

  const loadServerDetail = useCallback(
    async (srvId: string, range: string, silent = false) => {
      if (!srvId) return;
      if (!silent) setLoadingDetail(true);
      try {
        const res = await api.getServerMonitorDetail(srvId, range);
        setNodeDetail(res.detail);
        setRuntime(res.runtime);
      } catch {
        // ignore
      } finally {
        if (!silent) setLoadingDetail(false);
      }
    },
    []
  );

  const loadAlerts = useCallback(
    async (statusF = alertStatusFilter, srvF = alertServerFilter) => {
      setLoadingAlerts(true);
      try {
        const statusParam = statusF === 'all' ? '' : statusF;
        const res = await api.listMonitorAlerts(statusParam, srvF, 400);
        setAlertsList(res.alerts || []);
      } catch {
        // ignore
      } finally {
        setLoadingAlerts(false);
      }
    },
    [alertServerFilter, alertStatusFilter]
  );

  const loadPolicy = useCallback(async () => {
    try {
      const res = await api.getMonitorPolicy();
      setPolicySettings(res.settings);
      setPolicyRules(res.rules || []);
      setRuntime(res.runtime);
    } catch {
      // ignore
    }
  }, []);

  // Handle deep-link jump from ServerManager
  useEffect(() => {
    if (initialServerId) {
      setSelectedServerId(initialServerId);
      setSubTab('detail');
      if (onClearInitialServer) onClearInitialServer();
    }
  }, [initialServerId, onClearInitialServer]);

  // Initial & tab-driven loads
  useEffect(() => {
    void loadOverview();
  }, [loadOverview]);

  useEffect(() => {
    if (subTab === 'detail' && selectedServerId) {
      void loadServerDetail(selectedServerId, historyRange);
    } else if (subTab === 'alerts') {
      void loadAlerts(alertStatusFilter, alertServerFilter);
    } else if (subTab === 'policy' && !policySettings) {
      void loadPolicy();
    }
  }, [
    subTab,
    selectedServerId,
    historyRange,
    alertStatusFilter,
    alertServerFilter,
    loadServerDetail,
    loadAlerts,
    loadPolicy,
    policySettings,
  ]);

  // Periodic live auto-refresh while MonitorCenter is mounted
  useEffect(() => {
    const timer = window.setInterval(() => {
      void loadOverview();
      if (subTab === 'detail' && selectedServerId) {
        void loadServerDetail(selectedServerId, historyRange, true);
      } else if (subTab === 'alerts') {
        void loadAlerts(alertStatusFilter, alertServerFilter);
      }
    }, 8000);
    return () => window.clearInterval(timer);
  }, [
    subTab,
    selectedServerId,
    historyRange,
    alertStatusFilter,
    alertServerFilter,
    loadOverview,
    loadServerDetail,
    loadAlerts,
  ]);

  const handleCollectAll = async () => {
    if (servers.length === 0) return;
    setCollectingAll(true);
    try {
      const res = await api.collectAllMonitor();
      setRuntime(res.runtime);
      await loadOverview();
      if (subTab === 'detail' && selectedServerId) {
        await loadServerDetail(selectedServerId, historyRange, true);
      } else if (subTab === 'alerts') {
        await loadAlerts();
      }
      onNotify(`已完成 ${res.count} 台服务器全维状态采集并加密归档`);
    } catch (err: any) {
      onNotify(err?.message || '批量状态采集失败');
    } finally {
      setCollectingAll(false);
    }
  };

  const handleCollectSingle = async (serverId: string, trustFp = '') => {
    setCollectingServerId(serverId);
    try {
      const res = await api.collectServerMonitor(serverId, trustFp);
      setRuntime(res.runtime);
      await loadOverview();
      if (selectedServerId === serverId) {
        await loadServerDetail(serverId, historyRange, true);
      }
      if (res.snapshot.reachable) {
        onNotify(`已采集 [${res.snapshot.server_name}] 最新状态 (评分 ${res.snapshot.health_score})`);
      } else {
        onNotify(`节点 [${res.snapshot.server_name}] 不可达：${res.snapshot.error || '连接失败'}`);
      }
    } catch (err) {
      if (err instanceof ApiError && err.code === 'HOST_KEY_UNTRUSTED' && err.hostKeyInfo) {
        setHostKeyPrompt({ serverId, info: err.hostKeyInfo });
      } else {
        onNotify((err as Error)?.message || '单机采集失败');
      }
    } finally {
      setCollectingServerId('');
    }
  };

  const handleOpenServerInspector = (serverId: string) => {
    setSelectedServerId(serverId);
    setSubTab('detail');
  };

  const handleExport = async (format: 'csv' | 'json', serverId = '') => {
    try {
      const { blob, filename } = await api.exportMonitorBlob(format, serverId, 'all');
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      onNotify(`已导出监控历史文件 ${filename}`);
    } catch (err: any) {
      onNotify(err?.message || '导出失败');
    }
  };

  const handleAcceptPortBaseline = async (serverId: string) => {
    try {
      const res = await api.acceptPortBaseline(serverId);
      onNotify(`已更新公网监听端口安全基线 (${res.port_baseline.length} 个端口)`);
      await Promise.all([
        loadServerDetail(serverId, historyRange, true),
        loadOverview(),
      ]);
    } catch (err: any) {
      onNotify(err?.message || '更新端口基线失败');
    }
  };

  const handleAckAlert = async (alertId: string) => {
    try {
      await api.ackMonitorAlert(alertId);
      onNotify('已确认该条告警记录');
      await Promise.all([loadAlerts(), loadOverview()]);
      if (subTab === 'detail' && selectedServerId) {
        await loadServerDetail(selectedServerId, historyRange, true);
      }
    } catch (err: any) {
      onNotify(err?.message || '确认告警失败');
    }
  };

  const handleClearResolvedAlerts = async () => {
    try {
      const res = await api.clearResolvedMonitorAlerts();
      onNotify(`已清理 ${res.removed} 条已恢复告警记录`);
      await Promise.all([loadAlerts(), loadOverview()]);
    } catch (err: any) {
      onNotify(err?.message || '清理告警记录失败');
    }
  };

  const handleSavePolicy = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!policySettings) return;
    setSavingPolicy(true);
    try {
      const res = await api.updateMonitorPolicy(policySettings, policyRules);
      setPolicySettings(res.settings);
      setPolicyRules(res.rules);
      setRuntime(res.runtime);
      await loadOverview();
      onNotify('监控调度周期与告警阈值策略已加密保存');
    } catch (err: any) {
      onNotify(err?.message || '保存监控策略失败');
    } finally {
      setSavingPolicy(false);
    }
  };

  const handleClearHistory = async (serverId = '') => {
    try {
      await api.clearMonitorHistory(serverId);
      setConfirmClearAll(false);
      await loadOverview();
      if (selectedServerId) {
        await loadServerDetail(selectedServerId, historyRange, true);
      }
      onNotify(serverId ? '已清空该服务器的历史监控时序数据' : '已清空全部服务器历史监控数据');
    } catch (err: any) {
      onNotify(err?.message || '清空监控历史失败');
    }
  };

  const groups = useMemo(() => {
    const s = new Set<string>();
    for (const srv of servers) {
      if (srv.group) s.add(srv.group);
    }
    return Array.from(s);
  }, [servers]);

  const filteredNodes = useMemo((): ServerMonitorCardItem[] => {
    if (!overview?.nodes) return [];
    const q = searchQuery.trim().toLowerCase();
    return overview.nodes.filter((item) => {
      const lvl = item.snapshot?.health_level || 'unknown';
      if (healthFilter === 'healthy' && lvl !== 'healthy') return false;
      if (healthFilter === 'offline' && lvl !== 'offline') return false;
      if (
        healthFilter === 'abnormal' &&
        lvl !== 'warning' &&
        lvl !== 'critical' &&
        lvl !== 'offline' &&
        item.active_alerts === 0
      ) {
        return false;
      }
      if (groupFilter !== 'ALL' && item.server.group !== groupFilter) return false;
      if (!q) return true;
      return (
        item.server.name.toLowerCase().includes(q) ||
        item.server.host.toLowerCase().includes(q) ||
        (item.snapshot?.hostname || '').toLowerCase().includes(q) ||
        (item.snapshot?.os || '').toLowerCase().includes(q)
      );
    });
  }, [overview?.nodes, healthFilter, groupFilter, searchQuery]);

  const kpi = overview?.kpi;
  const activeRuntime = runtime || overview?.runtime;
  const snap = nodeDetail?.snapshot;
  const detailServerObj = useMemo(
    () => servers.find((s) => s.id === selectedServerId) || nodeDetail?.server,
    [servers, selectedServerId, nodeDetail?.server]
  );

  // Detect drifted public ports on current node detail
  const driftedPublicPorts = useMemo(() => {
    if (!snap?.listening_ports || !nodeDetail?.port_baseline || nodeDetail.port_baseline.length === 0) {
      return [];
    }
    const baseSet = new Set(nodeDetail.port_baseline);
    return snap.listening_ports.filter((lp) => {
      if (!lp.public_exposed) return false;
      const proto = lp.proto.toLowerCase().startsWith('udp') ? 'udp' : 'tcp';
      return !baseSet.has(`${proto}/${lp.port}`);
    });
  }, [snap?.listening_ports, nodeDetail?.port_baseline]);

  return (
    <div className="workspace-surface" id="monitor-center-view">
      {/* Page Header */}
      <div className="page-header">
        <div className="page-header-title">
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <h2>服务器全维状态监控中心</h2>
            {activeRuntime?.enabled ? (
              <span className="tag-chip teal">
                <span className="status-dot" style={{ width: 6, height: 6 }} />
                {activeRuntime.collecting
                  ? `采集中 (${activeRuntime.in_flight_count})`
                  : `定时巡检每 ${activeRuntime.interval_sec || 60}s`}
              </span>
            ) : (
              <span className="tag-chip amber">后台定时已暂停</span>
            )}
          </div>
          <p>
            已持久化 <strong className="tabular">{kpi?.total_samples || 0}</strong> 个全维时序样本点
            {activeRuntime?.last_sweep_at
              ? ` · 最近巡检 ${formatTimeShort(activeRuntime.last_sweep_at)}`
              : ''}
            {activeRuntime?.next_sweep_at && activeRuntime.enabled
              ? ` · 下次自动采集 ${formatTimeShort(activeRuntime.next_sweep_at)}`
              : ''}
            {' · 覆盖 CPU / 内存 / 多分区与 I/O / 网卡与 Socket / 进程 / 端口基线 / 服务容器 / 安全审计'}
          </p>
        </div>

        <div className="page-header-actions">
          <button
            type="button"
            className="btn btn-sm"
            onClick={() => void handleExport('csv')}
            disabled={!kpi || kpi.total_samples === 0}
            title="导出全部节点历史监控时序 CSV 报表"
          >
            <Download size={13.5} /> 导出 CSV
          </button>
          <button
            type="button"
            className="btn btn-sm"
            onClick={() => void handleExport('json')}
            disabled={!kpi || kpi.total_servers === 0}
            title="导出完整监控快照与时序 JSON"
          >
            <Download size={13.5} /> 导出 JSON
          </button>
          <button
            type="button"
            id="monitor-collect-all-btn"
            className="btn btn-primary"
            disabled={collectingAll || servers.length === 0}
            onClick={() => void handleCollectAll()}
          >
            <RefreshCw size={14} className={collectingAll ? 'spin-icon' : ''} />
            {collectingAll ? '正在并发采集全网节点...' : '立即全量采集'}
          </button>
        </div>
      </div>

      {/* Primary Sub-Navigation Bar */}
      <div className="mon-subnav-bar">
        <div className="mon-subnav-tabs" role="tablist">
          <button
            type="button"
            id="mon-tab-overview"
            className={`mon-subtab-btn ${subTab === 'overview' ? 'active' : ''}`}
            onClick={() => setSubTab('overview')}
          >
            <LayoutGrid size={14} /> 集群态势总览
            <span className="mon-tab-count tabular">{servers.length}</span>
          </button>

          <button
            type="button"
            id="mon-tab-detail"
            className={`mon-subtab-btn ${subTab === 'detail' ? 'active' : ''}`}
            onClick={() => {
              if (!selectedServerId && servers[0]) {
                setSelectedServerId(servers[0].id);
              }
              setSubTab('detail');
            }}
          >
            <Activity size={14} /> 单机深度透视与曲线
          </button>

          <button
            type="button"
            id="mon-tab-alerts"
            className={`mon-subtab-btn ${subTab === 'alerts' ? 'active' : ''}`}
            onClick={() => setSubTab('alerts')}
          >
            <Bell size={14} /> 告警与事件记录
            {(kpi?.firing_alerts || 0) > 0 && (
              <span className="mon-tab-count danger tabular">{kpi?.firing_alerts}</span>
            )}
          </button>

          <button
            type="button"
            id="mon-tab-policy"
            className={`mon-subtab-btn ${subTab === 'policy' ? 'active' : ''}`}
            onClick={() => setSubTab('policy')}
          >
            <Settings2 size={14} /> 定时周期与阈值策略
          </button>
        </div>

        <div className="mon-encryption-note">
          <Lock size={12} /> 监控数据独立落盘至 monitor_runtime.json · 与凭据加密解耦
        </div>
      </div>

      <div className="page-body">
        {servers.length === 0 ? (
          <div className="empty-state">
            <div className="empty-state-icon">
              <Activity size={22} />
            </div>
            <h3>尚未添加需要监控的服务器</h3>
            <p>
              请先在「主机资产」中添加至少一台 SSH 服务器。添加后后台守护引擎将按设定周期自动 7×24 采集并持久化各项指标与趋势曲线。
            </p>
            <button type="button" className="btn btn-primary" onClick={onNavigateServers}>
              <Server size={14} /> 前往添加服务器
            </button>
          </div>
        ) : (
          <>
            {/* ================================================================
                TAB 1: FLEET OVERVIEW DASHBOARD
               ================================================================ */}
            {subTab === 'overview' && (
              <div id="monitor-overview-pane">
                {/* 6-Column Fleet KPI Summary */}
                <div className="mon-kpi-grid">
                  <div className="mon-kpi-card">
                    <div className="mon-kpi-top">
                      <span>在线节点 / 纳管总数</span>
                      <Server size={15} style={{ color: 'var(--accent-teal)' }} />
                    </div>
                    <div className="mon-kpi-value tabular">
                      {kpi?.online_servers ?? 0}
                      <span className="mon-kpi-denom"> / {kpi?.total_servers ?? servers.length}</span>
                    </div>
                    <div className="mon-kpi-foot">
                      <span style={{ color: 'var(--status-online)' }}>
                        健康 {kpi?.healthy_servers ?? 0}
                      </span>
                      <span>·</span>
                      <span style={{ color: 'var(--amber-text)' }}>
                        预警 {kpi?.warning_servers ?? 0}
                      </span>
                      <span>·</span>
                      <span style={{ color: 'var(--danger-text)' }}>
                        严重/离线 {(kpi?.critical_servers ?? 0) + (kpi?.offline_servers ?? 0)}
                      </span>
                    </div>
                  </div>

                  <div className="mon-kpi-card">
                    <div className="mon-kpi-top">
                      <span>集群平均健康分</span>
                      <ShieldCheck size={15} style={{ color: 'var(--accent-teal)' }} />
                    </div>
                    <div className="mon-kpi-value tabular">
                      {kpi?.online_servers ? kpi.avg_health_score : '—'}
                      {kpi?.online_servers ? <span className="mon-kpi-denom"> / 100</span> : null}
                    </div>
                    <div className="mon-kpi-foot">
                      平均 SSH 握手延迟 <strong className="tabular">{kpi?.avg_latency_ms ?? 0} ms</strong>
                    </div>
                  </div>

                  <div className="mon-kpi-card">
                    <div className="mon-kpi-top">
                      <span>集群平均 CPU 负载</span>
                      <Cpu size={15} style={{ color: 'var(--text-secondary)' }} />
                    </div>
                    <div className="mon-kpi-value tabular">
                      {kpi?.online_servers ? `${kpi.avg_cpu_percent.toFixed(1)}%` : '—'}
                    </div>
                    <div className="mon-progress-track" style={{ marginTop: 6 }}>
                      <div
                        className={`mon-progress-fill ${barToneClass(kpi?.avg_cpu_percent || 0)}`}
                        style={{ width: `${Math.min(100, kpi?.avg_cpu_percent || 0)}%` }}
                      />
                    </div>
                  </div>

                  <div className="mon-kpi-card">
                    <div className="mon-kpi-top">
                      <span>集群平均物理内存</span>
                      <Layers size={15} style={{ color: 'var(--text-secondary)' }} />
                    </div>
                    <div className="mon-kpi-value tabular">
                      {kpi?.online_servers ? `${kpi.avg_mem_percent.toFixed(1)}%` : '—'}
                    </div>
                    <div className="mon-progress-track" style={{ marginTop: 6 }}>
                      <div
                        className={`mon-progress-fill ${barToneClass(kpi?.avg_mem_percent || 0, 80, 92)}`}
                        style={{ width: `${Math.min(100, kpi?.avg_mem_percent || 0)}%` }}
                      />
                    </div>
                  </div>

                  <div className="mon-kpi-card">
                    <div className="mon-kpi-top">
                      <span>实时总网络与磁盘吞吐</span>
                      <Network size={15} style={{ color: 'var(--accent-teal)' }} />
                    </div>
                    <div className="mon-kpi-dual tabular">
                      <div>↓ {formatBytesRate(kpi?.total_net_rx_bps)}</div>
                      <div>↑ {formatBytesRate(kpi?.total_net_tx_bps)}</div>
                    </div>
                    <div className="mon-kpi-foot tabular">
                      磁盘 R {formatBytesRate(kpi?.total_disk_read_bps)} · W{' '}
                      {formatBytesRate(kpi?.total_disk_write_bps)}
                    </div>
                  </div>

                  <div
                    className={`mon-kpi-card clickable ${(kpi?.firing_alerts || 0) > 0 ? 'alerting' : ''}`}
                    onClick={() => setSubTab('alerts')}
                  >
                    <div className="mon-kpi-top">
                      <span>未恢复活跃告警</span>
                      <AlertTriangle
                        size={15}
                        style={{
                          color:
                            (kpi?.firing_alerts || 0) > 0
                              ? 'var(--danger-text)'
                              : 'var(--text-muted)',
                        }}
                      />
                    </div>
                    <div
                      className="mon-kpi-value tabular"
                      style={{
                        color:
                          (kpi?.firing_alerts || 0) > 0 ? 'var(--danger-text)' : undefined,
                      }}
                    >
                      {kpi?.firing_alerts ?? 0}
                    </div>
                    <div className="mon-kpi-foot">
                      严重 {kpi?.critical_alerts ?? 0} 条 · 警告 {kpi?.warning_alerts ?? 0} 条 · 点击处置
                    </div>
                  </div>
                </div>

                {/* Filter & View Mode Toolbar */}
                <div className="mon-toolbar">
                  <div className="group-pills">
                    {(
                      [
                        ['all', `全部 (${overview?.nodes.length || 0})`],
                        [
                          'abnormal',
                          `异常/预警 (${
                            (kpi?.warning_servers || 0) +
                            (kpi?.critical_servers || 0) +
                            (kpi?.offline_servers || 0)
                          })`,
                        ],
                        ['healthy', `健康 (${kpi?.healthy_servers || 0})`],
                        ['offline', `离线 (${kpi?.offline_servers || 0})`],
                      ] as const
                    ).map(([k, label]) => (
                      <button
                        key={k}
                        type="button"
                        className={`group-pill ${healthFilter === k ? 'active' : ''}`}
                        onClick={() => setHealthFilter(k)}
                      >
                        {label}
                      </button>
                    ))}
                  </div>

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
                    <select
                      className="select mon-filter-select"
                      value={groupFilter}
                      onChange={(e) => setGroupFilter(e.target.value)}
                    >
                      <option value="ALL">全部分组</option>
                      {groups.map((g) => (
                        <option key={g} value={g}>
                          {g}
                        </option>
                      ))}
                    </select>

                    <div className="input-with-icon mon-search-box">
                      <span className="input-icon-left">
                        <Search size={13.5} />
                      </span>
                      <input
                        className="input mon-search-input"
                        placeholder="搜索节点名、IP、主机名或系统..."
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                      />
                    </div>

                    <div className="mon-view-toggle">
                      <button
                        type="button"
                        className={`mon-toggle-icon ${viewMode === 'grid' ? 'active' : ''}`}
                        onClick={() => setViewMode('grid')}
                        title="卡片矩阵视图"
                      >
                        <LayoutGrid size={14} />
                      </button>
                      <button
                        type="button"
                        className={`mon-toggle-icon ${viewMode === 'table' ? 'active' : ''}`}
                        onClick={() => setViewMode('table')}
                        title="紧凑表格视图"
                      >
                        <List size={14} />
                      </button>
                    </div>
                  </div>
                </div>

                {loadingOverview && !overview ? (
                  <div className="empty-state">正在加载监控运行状态...</div>
                ) : filteredNodes.length === 0 ? (
                  <div className="empty-state" style={{ padding: '40px 20px' }}>
                    <h3>当前筛选条件下没有匹配的节点</h3>
                    <p>请切换健康状态过滤条件或清空搜索关键词。</p>
                  </div>
                ) : viewMode === 'grid' ? (
                  <div className="mon-node-grid">
                    {filteredNodes.map((item) => {
                      const s = item.snapshot;
                      const lvl: MonitorHealthLevel = s?.health_level || 'unknown';
                      const maxDisk = s ? Math.max(s.max_part_percent || 0, s.disk_percent || 0) : 0;
                      const isCollecting = collectingServerId === item.server.id;

                      return (
                        <article
                          key={item.server.id}
                          className={`mon-node-card level-${lvl}`}
                          id={`mon-node-card-${item.server.id}`}
                        >
                          <div className="mon-node-head">
                            <div className="mon-node-head-main">
                              <HealthScoreGauge score={s?.health_score || 0} level={lvl} size={46} />
                              <div style={{ flex: '1 1 0%', minWidth: 0 }}>
                                <div className="mon-node-title-row">
                                  <span
                                    className="mon-node-name"
                                    onClick={() => handleOpenServerInspector(item.server.id)}
                                    title="点击查看单机深度透视与历史曲线"
                                  >
                                    {item.server.name}
                                  </span>
                                  <span className={`tag-chip ${healthBadgeClass(lvl)}`}>
                                    {healthLabel(lvl)}
                                  </span>
                                  {item.active_alerts > 0 && (
                                    <span className="tag-chip danger tabular">
                                      {item.active_alerts} 告警
                                    </span>
                                  )}
                                </div>
                                <div className="mon-node-sub mono">
                                  {item.server.host}:{item.server.port}
                                  {s?.hostname ? ` · ${s.hostname}` : ''}
                                </div>
                              </div>
                            </div>
                            <span className="tag-chip mon-node-group-chip" title={item.server.group}>
                              {item.server.group}
                            </span>
                          </div>

                          {/* OS / Uptime / SLA Strip */}
                          <div className="mon-node-sysstrip">
                            <span>{s?.os || item.server.last_os_info || '等待首次连接采样'}</span>
                            {s?.reachable && (
                              <span className="tabular">
                                {s.cpu_cores || 1} 核 · 运行 {s.uptime || '—'} · SLA{' '}
                                {item.sla.availability_pct}%
                              </span>
                            )}
                          </div>

                          {s && !s.reachable ? (
                            <div
                              className="alert alert-error"
                              style={{ margin: '4px 0', padding: '8px 10px', minWidth: 0 }}
                            >
                              <span style={{ minWidth: 0, overflowWrap: 'anywhere', wordBreak: 'break-word' }}>
                                {s.error || 'SSH 握手或采集超时，主机不可达'}
                              </span>
                            </div>
                          ) : s ? (
                            <>
                              {/* 4-Metric Resource Bars */}
                              <div className="mon-bars-grid">
                                <div className="mon-bar-item">
                                  <div className="mon-bar-label">
                                    <span>CPU ({s.load_1.toFixed(2)})</span>
                                    <strong className="tabular">{s.cpu_percent.toFixed(1)}%</strong>
                                  </div>
                                  <div className="mon-progress-track">
                                    <div
                                      className={`mon-progress-fill ${barToneClass(s.cpu_percent, 80, 92)}`}
                                      style={{ width: `${Math.min(100, s.cpu_percent)}%` }}
                                    />
                                  </div>
                                </div>

                                <div className="mon-bar-item">
                                  <div className="mon-bar-label">
                                    <span>
                                      内存 ({Math.round(s.mem_used_mb / 1024 * 10) / 10}/
                                      {Math.round(s.mem_total_mb / 1024 * 10) / 10}G)
                                    </span>
                                    <strong className="tabular">{s.mem_percent.toFixed(1)}%</strong>
                                  </div>
                                  <div className="mon-progress-track">
                                    <div
                                      className={`mon-progress-fill ${barToneClass(s.mem_percent, 85, 94)}`}
                                      style={{ width: `${Math.min(100, s.mem_percent)}%` }}
                                    />
                                  </div>
                                </div>

                                <div className="mon-bar-item">
                                  <div className="mon-bar-label">
                                    <span>磁盘 ({s.max_part_mount || '/'})</span>
                                    <strong className="tabular">{maxDisk.toFixed(1)}%</strong>
                                  </div>
                                  <div className="mon-progress-track">
                                    <div
                                      className={`mon-progress-fill ${barToneClass(maxDisk, 80, 90)}`}
                                      style={{ width: `${Math.min(100, maxDisk)}%` }}
                                    />
                                  </div>
                                </div>

                                <div className="mon-bar-item">
                                  <div className="mon-bar-label">
                                    <span>Swap / Inode</span>
                                    <strong className="tabular">
                                      {s.swap_percent.toFixed(0)}% / {s.max_inode_percent.toFixed(0)}%
                                    </strong>
                                  </div>
                                  <div className="mon-progress-track">
                                    <div
                                      className={`mon-progress-fill ${barToneClass(
                                        Math.max(s.swap_percent, s.max_inode_percent),
                                        75,
                                        90
                                      )}`}
                                      style={{
                                        width: `${Math.min(
                                          100,
                                          Math.max(s.swap_percent, s.max_inode_percent)
                                        )}%`,
                                      }}
                                    />
                                  </div>
                                </div>
                              </div>

                              {/* Live Rates & Subsystem Summary Strip */}
                              <div className="mon-rate-strip tabular">
                                <span>
                                  网速 ↓{formatBytesRate(s.net_rx_bps)} ↑{formatBytesRate(s.net_tx_bps)}
                                </span>
                                <span>SSH {s.latency_ms}ms</span>
                                <span>TCP {s.tcp_established}</span>
                                <span>
                                  端口 {s.listening_ports?.length || 0}
                                  {s.docker.installed ? ` · 容器 ${s.docker.running}` : ''}
                                </span>
                              </div>
                            </>
                          ) : (
                            <div className="mon-await-box">
                              尚未生成监控快照，点击下方「采集」或等待后台自动巡检
                            </div>
                          )}

                          {/* Sparkline Trend */}
                          <div className="mon-sparkline-box">
                            <div className="mon-sparkline-meta">
                              <span>CPU 时序趋势 ({item.sparkline.length} 点)</span>
                              <span className="mono">
                                {s?.collected_at ? formatTimeShort(s.collected_at) : '—'}
                              </span>
                            </div>
                            <MiniSparkline
                              points={item.sparkline}
                              accessor={(p) => p.cpu}
                              fixedMax={100}
                              color={
                                lvl === 'critical'
                                  ? '#dc2626'
                                  : lvl === 'warning'
                                  ? '#d97706'
                                  : '#0d9488'
                              }
                            />
                          </div>

                          {/* Card Footer Actions */}
                          <div className="mon-node-foot">
                            <button
                              type="button"
                              className="btn btn-sm"
                              disabled={isCollecting}
                              onClick={() => void handleCollectSingle(item.server.id)}
                            >
                              <RefreshCw size={12.5} className={isCollecting ? 'spin-icon' : ''} />
                              {isCollecting ? '采集中...' : '立即采集'}
                            </button>

                            <div style={{ display: 'flex', gap: 6 }}>
                              <button
                                type="button"
                                className="btn btn-sm"
                                onClick={() => onConnectTerminal(item.server, false)}
                                title="打开交互式 SSH 终端"
                              >
                                <Terminal size={12.5} /> 终端
                              </button>
                              <button
                                type="button"
                                className="btn btn-sm btn-primary"
                                onClick={() => handleOpenServerInspector(item.server.id)}
                              >
                                <Eye size={12.5} /> 深度透视
                              </button>
                            </div>
                          </div>
                        </article>
                      );
                    })}
                  </div>
                ) : (
                  /* Compact Table View */
                  <div className="mon-panel-card" style={{ padding: 0, overflow: 'hidden' }}>
                    <div style={{ overflowX: 'auto', WebkitOverflowScrolling: 'touch' }}>
                      <table className="data-table mon-compact-fleet-table">
                        <thead>
                          <tr>
                            <th>节点名称 / 地址</th>
                            <th>健康状态</th>
                            <th>CPU / Load1</th>
                            <th>物理内存</th>
                            <th>最高分区磁盘</th>
                            <th>网络吞吐 (↓/↑)</th>
                            <th>连接/进程</th>
                            <th>SSH 延迟</th>
                            <th>SLA 在线率</th>
                            <th style={{ textAlign: 'right' }}>操作</th>
                          </tr>
                        </thead>
                        <tbody>
                          {filteredNodes.map((item) => {
                            const s = item.snapshot;
                            const lvl = s?.health_level || 'unknown';
                            const maxDisk = s
                              ? Math.max(s.max_part_percent || 0, s.disk_percent || 0)
                              : 0;
                            return (
                              <tr key={item.server.id}>
                                <td>
                                  <div
                                    style={{
                                      fontWeight: 600,
                                      cursor: 'pointer',
                                      overflow: 'hidden',
                                      textOverflow: 'ellipsis',
                                      whiteSpace: 'nowrap',
                                    }}
                                    onClick={() => handleOpenServerInspector(item.server.id)}
                                    title={item.server.name}
                                  >
                                    {item.server.name}
                                  </div>
                                  <div className="mono" style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>
                                    {item.server.host}:{item.server.port}
                                  </div>
                                </td>
                                <td>
                                  <span className={`tag-chip ${healthBadgeClass(lvl)}`}>
                                    {s?.reachable ? `${s.health_score}分 · ` : ''}
                                    {healthLabel(lvl)}
                                  </span>
                                </td>
                                <td className="tabular">
                                  {s?.reachable
                                    ? `${s.cpu_percent.toFixed(1)}% (${s.load_1.toFixed(2)})`
                                    : '—'}
                                </td>
                                <td className="tabular">
                                  {s?.reachable ? `${s.mem_percent.toFixed(1)}%` : '—'}
                                </td>
                                <td className="tabular">
                                  {s?.reachable ? `${maxDisk.toFixed(1)}% (${s.max_part_mount || '/'})` : '—'}
                                </td>
                                <td className="tabular">
                                  {s?.reachable
                                    ? `↓${formatBytesRate(s.net_rx_bps)} / ↑${formatBytesRate(s.net_tx_bps)}`
                                    : '—'}
                                </td>
                                <td className="tabular">
                                  {s?.reachable
                                    ? `TCP ${s.tcp_established} · 进程 ${s.procs_total}`
                                    : '—'}
                                </td>
                                <td className="tabular">{s?.reachable ? `${s.latency_ms} ms` : '—'}</td>
                                <td className="tabular">{item.sla.availability_pct}%</td>
                                <td style={{ textAlign: 'right' }}>
                                  <div style={{ display: 'inline-flex', gap: 6 }}>
                                    <button
                                      type="button"
                                      className="btn btn-sm"
                                      onClick={() => void handleCollectSingle(item.server.id)}
                                    >
                                      采集
                                    </button>
                                    <button
                                      type="button"
                                      className="btn btn-sm btn-primary"
                                      onClick={() => handleOpenServerInspector(item.server.id)}
                                    >
                                      详情
                                    </button>
                                  </div>
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* ================================================================
                TAB 2: NODE DEEP INSPECTOR & HISTORICAL CHARTS
               ================================================================ */}
            {subTab === 'detail' && (
              <div id="monitor-detail-pane">
                {/* Node & Time Range Selector Bar */}
                <div className="mon-detail-topbar">
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 10,
                      flexWrap: 'wrap',
                      minWidth: 0,
                      maxWidth: '100%',
                    }}
                  >
                    <label style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--text-secondary)' }}>
                      透视节点:
                    </label>
                    <select
                      id="mon-detail-server-select"
                      className="select mon-detail-select"
                      value={selectedServerId}
                      onChange={(e) => setSelectedServerId(e.target.value)}
                    >
                      {servers.map((srv) => (
                        <option key={srv.id} value={srv.id}>
                          {srv.name} ({srv.host}:{srv.port})
                        </option>
                      ))}
                    </select>

                    <div className="group-pills">
                      {[
                        ['15m', '15分钟'],
                        ['1h', '1小时'],
                        ['6h', '6小时'],
                        ['24h', '24小时'],
                        ['all', '全部记录'],
                      ].map(([val, label]) => (
                        <button
                          key={val}
                          type="button"
                          className={`group-pill ${historyRange === val ? 'active' : ''}`}
                          onClick={() => setHistoryRange(val)}
                        >
                          {label}
                        </button>
                      ))}
                    </div>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                    <button
                      type="button"
                      className="btn btn-sm"
                      disabled={!selectedServerId || collectingServerId === selectedServerId}
                      onClick={() => void handleCollectSingle(selectedServerId)}
                    >
                      <RefreshCw
                        size={13}
                        className={collectingServerId === selectedServerId ? 'spin-icon' : ''}
                      />
                      {collectingServerId === selectedServerId ? '正在采集...' : '立即采集本机'}
                    </button>
                    <button
                      type="button"
                      className="btn btn-sm"
                      disabled={!selectedServerId}
                      onClick={() => void handleExport('csv', selectedServerId)}
                    >
                      <Download size={13} /> 导出本机 CSV
                    </button>
                    {detailServerObj && (
                      <button
                        type="button"
                        className="btn btn-sm btn-primary"
                        onClick={() => onConnectTerminal(detailServerObj, false)}
                      >
                        <Terminal size={13} /> 打开 SSH 终端
                      </button>
                    )}
                  </div>
                </div>

                {loadingDetail && !nodeDetail ? (
                  <div className="empty-state">正在解密加载单机深度监控档案...</div>
                ) : !nodeDetail ? (
                  <div className="empty-state">请选择一台主机查看监控详情</div>
                ) : (
                  <>
                    {/* System Identity & SLA Banner */}
                    <div className="mon-identity-banner">
                      <div className="mon-identity-main">
                        <HealthScoreGauge
                          score={snap?.health_score || 0}
                          level={snap?.health_level || 'unknown'}
                          size={58}
                        />
                        <div style={{ minWidth: 0, flex: '1 1 0%' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', minWidth: 0 }}>
                            <h3
                              style={{
                                fontSize: 16.5,
                                fontWeight: 650,
                                minWidth: 0,
                                maxWidth: '100%',
                                overflowWrap: 'anywhere',
                                wordBreak: 'break-word',
                              }}
                            >
                              {nodeDetail.server.name}
                            </h3>
                            <span className={`tag-chip ${healthBadgeClass(snap?.health_level)}`}>
                              {healthLabel(snap?.health_level)}
                            </span>
                            {snap?.virtualization && (
                              <span className="tag-chip">{snap.virtualization.toUpperCase()}</span>
                            )}
                            {snap?.ntp_synced && <span className="tag-chip teal">NTP 时钟已同步</span>}
                            {snap?.security?.reboot_required && (
                              <span className="tag-chip amber">需要重启内核</span>
                            )}
                            {(snap?.cpu_temp_c || 0) > 0 && (
                              <span className="tag-chip">{snap?.cpu_temp_c}°C</span>
                            )}
                          </div>
                          <div className="mon-identity-meta">
                            <span>
                              主机名: <strong className="mono">{snap?.hostname || '—'}</strong>
                            </span>
                            <span>
                              系统: <strong>{snap?.os || '—'}</strong> ({snap?.kernel || '—'} /{' '}
                              {snap?.arch || '—'})
                            </span>
                            <span>
                              CPU: <strong>{snap?.cpu_model || '通用处理器'}</strong> (
                              {snap?.cpu_cores || 1} 核)
                            </span>
                            <span>
                              持续运行: <strong className="tabular">{snap?.uptime || '—'}</strong>
                            </span>
                            {snap?.server_time && (
                              <span>
                                节点时钟:{' '}
                                <strong className="mono">
                                  {snap.server_time} {snap.timezone || ''}
                                </strong>
                              </span>
                            )}
                          </div>
                        </div>
                      </div>

                      <div className="mon-sla-strip tabular">
                        <div className="mon-sla-cell">
                          <span>SLA 可用率</span>
                          <strong>{nodeDetail.sla.availability_pct}%</strong>
                        </div>
                        <div className="mon-sla-cell">
                          <span>平均 / 峰值延迟</span>
                          <strong>
                            {nodeDetail.sla.avg_latency_ms} / {nodeDetail.sla.max_latency_ms} ms
                          </strong>
                        </div>
                        <div className="mon-sla-cell">
                          <span>峰值 CPU / 内存</span>
                          <strong>
                            {nodeDetail.sla.max_cpu_percent}% / {nodeDetail.sla.max_mem_percent}%
                          </strong>
                        </div>
                        <div className="mon-sla-cell">
                          <span>时序采样点</span>
                          <strong>{nodeDetail.series.length} 点</strong>
                        </div>
                      </div>
                    </div>

                    {snap && !snap.reachable && (
                      <div className="alert alert-error" style={{ marginBottom: 16 }}>
                        <AlertTriangle size={15} />
                        <span>
                          最近一次采集 ({formatDateTime(snap.collected_at)}) 失败：{snap.error}
                        </span>
                      </div>
                    )}

                    {/* Detail Dimension Switcher */}
                    <div className="mon-detail-subtabs">
                      <button
                        type="button"
                        id="mon-detail-subtab-metrics"
                        className={`mon-subpill ${detailTab === 'metrics' ? 'active' : ''}`}
                        onClick={() => setDetailTab('metrics')}
                      >
                        <Activity size={13.5} /> 历史时序曲线、存储分区与网络矩阵
                      </button>
                      <button
                        type="button"
                        id="mon-detail-subtab-procs"
                        className={`mon-subpill ${detailTab === 'procs_ports' ? 'active' : ''}`}
                        onClick={() => setDetailTab('procs_ports')}
                      >
                        <Cpu size={13.5} /> 进程排行与监听端口基线 (
                        {snap?.listening_ports?.length || 0} 端口)
                        {driftedPublicPorts.length > 0 && (
                          <span className="tag-chip danger" style={{ padding: '0 5px' }}>
                            +{driftedPublicPorts.length} 新暴露
                          </span>
                        )}
                      </button>
                      <button
                        type="button"
                        id="mon-detail-subtab-security"
                        className={`mon-subpill ${detailTab === 'services_security' ? 'active' : ''}`}
                        onClick={() => setDetailTab('services_security')}
                      >
                        <ShieldAlert size={13.5} /> 守护服务、Docker 容器与安全审计
                      </button>
                    </div>

                    {/* SUB-SECTION A: 6 Interactive Time-Series Charts + Disks + NICs/Sockets */}
                    {detailTab === 'metrics' && (
                      <div>
                        <div className="mon-charts-grid">
                          <TimeSeriesChart
                            title="CPU 使用率多维分解"
                            subtitle="Total / User / System / Disk IOWait"
                            points={nodeDetail.series}
                            unit="percent"
                            fixedMax={100}
                            series={[
                              {
                                key: 'cpu',
                                label: '总计',
                                color: '#0d9488',
                                fillOpacity: 0.12,
                                accessor: (p) => p.cpu,
                              },
                              {
                                key: 'user',
                                label: 'User',
                                color: '#0284c7',
                                accessor: (p) => p.cpu_u || 0,
                              },
                              {
                                key: 'sys',
                                label: 'Sys',
                                color: '#64748b',
                                accessor: (p) => p.cpu_s || 0,
                              },
                              {
                                key: 'io',
                                label: 'IOWait',
                                color: '#d97706',
                                dashed: true,
                                accessor: (p) => p.cpu_io || 0,
                              },
                            ]}
                          />

                          <TimeSeriesChart
                            title="物理内存、Swap 与文件句柄趋势"
                            subtitle={
                              snap
                                ? `已用 ${snap.mem_used_mb}MB / 总计 ${snap.mem_total_mb}MB (缓存 ${snap.mem_cached_mb}MB)`
                                : 'Memory / Swap / FD%'
                            }
                            points={nodeDetail.series}
                            unit="percent"
                            fixedMax={100}
                            series={[
                              {
                                key: 'mem',
                                label: '物理内存',
                                color: '#0284c7',
                                fillOpacity: 0.12,
                                accessor: (p) => p.mem || 0,
                              },
                              {
                                key: 'swap',
                                label: 'Swap',
                                color: '#d97706',
                                accessor: (p) => p.swap || 0,
                              },
                              {
                                key: 'fd',
                                label: 'FD句柄',
                                color: '#0d9488',
                                dashed: true,
                                accessor: (p) => p.fd_pct || 0,
                              },
                            ]}
                          />

                          <TimeSeriesChart
                            title="网络接口实时吞吐速率"
                            subtitle={
                              snap
                                ? `累计收 ${formatBytesTotal(snap.net_rx_total_bytes)} / 发 ${formatBytesTotal(snap.net_tx_total_bytes)}`
                                : 'Inbound Rx / Outbound Tx'
                            }
                            points={nodeDetail.series}
                            unit="bps"
                            series={[
                              {
                                key: 'rx',
                                label: '入站 Rx',
                                color: '#0d9488',
                                fillOpacity: 0.12,
                                accessor: (p) => p.rx_bps || 0,
                              },
                              {
                                key: 'tx',
                                label: '出站 Tx',
                                color: '#0284c7',
                                accessor: (p) => p.tx_bps || 0,
                              },
                            ]}
                          />

                          <TimeSeriesChart
                            title="磁盘块设备读写速率"
                            subtitle={
                              snap ? `实时 IOPS: ${snap.disk_iops} ops/s` : 'Block Read / Write B/s'
                            }
                            points={nodeDetail.series}
                            unit="bps"
                            series={[
                              {
                                key: 'dr',
                                label: '磁盘读',
                                color: '#0284c7',
                                fillOpacity: 0.1,
                                accessor: (p) => p.dr_bps || 0,
                              },
                              {
                                key: 'dw',
                                label: '磁盘写',
                                color: '#d97706',
                                fillOpacity: 0.1,
                                accessor: (p) => p.dw_bps || 0,
                              },
                            ]}
                          />

                          <TimeSeriesChart
                            title="系统平均负载趋势 (Load Average)"
                            subtitle={
                              snap
                                ? `单核归一化负载: ${snap.load_per_core}x · 上下文切换 ${snap.context_sw_sec || 0}/s`
                                : '1m / 5m / 15m Load'
                            }
                            points={nodeDetail.series}
                            unit="load"
                            series={[
                              {
                                key: 'l1',
                                label: '1分钟',
                                color: '#0d9488',
                                fillOpacity: 0.11,
                                accessor: (p) => p.l1 || 0,
                              },
                              {
                                key: 'l5',
                                label: '5分钟',
                                color: '#0284c7',
                                accessor: (p) => p.l5 || 0,
                              },
                              {
                                key: 'l15',
                                label: '15分钟',
                                color: '#64748b',
                                dashed: true,
                                accessor: (p) => p.l15 || 0,
                              },
                            ]}
                          />

                          <TimeSeriesChart
                            title="SSH 链路握手延迟"
                            subtitle="端到端握手响应耗时 (含跳板机隧道)"
                            points={nodeDetail.series}
                            unit="ms"
                            series={[
                              {
                                key: 'lat',
                                label: 'SSH延迟',
                                color: '#d97706',
                                fillOpacity: 0.12,
                                accessor: (p) => p.lat || 0,
                              },
                            ]}
                          />
                        </div>

                        {/* Disk Partitions & Network Socket Matrix */}
                        {snap && snap.reachable && (
                          <div className="mon-two-col" style={{ marginTop: 16 }}>
                            <div className="mon-panel-card">
                              <div className="mon-panel-head">
                                <h4>
                                  <HardDrive size={15} /> 文件系统挂载分区与 Inode 容量明细
                                </h4>
                                <span className="mono" style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>
                                  FD {snap.fd_used}/{snap.fd_max} · OOM Kills: {snap.oom_kills}
                                </span>
                              </div>
                              {snap.disks && snap.disks.length > 0 ? (
                                <div style={{ overflowX: 'auto' }}>
                                  <table className="data-table">
                                    <thead>
                                      <tr>
                                        <th>挂载点</th>
                                        <th>设备 / 类型</th>
                                        <th>已用 / 总计</th>
                                        <th style={{ minWidth: 92 }}>空间使用率</th>
                                        <th>Inode</th>
                                      </tr>
                                    </thead>
                                    <tbody>
                                      {snap.disks.map((d) => (
                                        <tr key={d.mount_point}>
                                          <td className="mono" style={{ fontWeight: 600 }}>
                                            {d.mount_point}
                                          </td>
                                          <td className="mono" style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                                            {d.device} ({d.fs_type})
                                          </td>
                                          <td className="tabular">
                                            {d.used_gb} / {d.total_gb} GB
                                          </td>
                                          <td>
                                            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                                              <div className="mon-progress-track" style={{ flex: 1 }}>
                                                <div
                                                  className={`mon-progress-fill ${barToneClass(
                                                    d.used_percent,
                                                    80,
                                                    90
                                                  )}`}
                                                  style={{ width: `${Math.min(100, d.used_percent)}%` }}
                                                />
                                              </div>
                                              <span className="tabular" style={{ fontSize: 12, width: 42 }}>
                                                {d.used_percent}%
                                              </span>
                                            </div>
                                          </td>
                                          <td className="tabular">
                                            <span
                                              className={`tag-chip ${
                                                d.inode_percent >= 90
                                                  ? 'danger'
                                                  : d.inode_percent >= 80
                                                  ? 'amber'
                                                  : ''
                                              }`}
                                            >
                                              {d.inode_percent}%
                                            </span>
                                          </td>
                                        </tr>
                                      ))}
                                    </tbody>
                                  </table>
                                </div>
                              ) : (
                                <div className="mon-empty-inline">未采集到挂载分区记录</div>
                              )}
                            </div>

                            <div className="mon-panel-card">
                              <div className="mon-panel-head">
                                <h4>
                                  <Network size={15} /> 网卡接口流量与内核 TCP/UDP 状态矩阵
                                </h4>
                                <span className="mono" style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>
                                  错包/丢包: {snap.net_packet_errors}
                                </span>
                              </div>

                              {/* Socket State Matrix */}
                              <div className="mon-socket-matrix tabular">
                                <div className="mon-sock-cell">
                                  <span>ESTABLISHED</span>
                                  <strong>{snap.tcp_established}</strong>
                                </div>
                                <div className="mon-sock-cell">
                                  <span>TIME_WAIT</span>
                                  <strong>{snap.tcp_time_wait}</strong>
                                </div>
                                <div className="mon-sock-cell">
                                  <span>CLOSE_WAIT</span>
                                  <strong
                                    style={{
                                      color:
                                        snap.tcp_close_wait >= 200 ? 'var(--amber-text)' : undefined,
                                    }}
                                  >
                                    {snap.tcp_close_wait}
                                  </strong>
                                </div>
                                <div className="mon-sock-cell">
                                  <span>SYN_RECV</span>
                                  <strong>{snap.tcp_syn_recv}</strong>
                                </div>
                                <div className="mon-sock-cell">
                                  <span>TCP LISTEN</span>
                                  <strong>{snap.tcp_listen}</strong>
                                </div>
                                <div className="mon-sock-cell">
                                  <span>UDP SOCK</span>
                                  <strong>{snap.udp_sockets}</strong>
                                </div>
                              </div>

                              {snap.interfaces && snap.interfaces.length > 0 && (
                                <div style={{ overflowX: 'auto', marginTop: 10 }}>
                                  <table className="data-table">
                                    <thead>
                                      <tr>
                                        <th>网卡</th>
                                        <th>IPv4 / 状态</th>
                                        <th>实时 ↓Rx / ↑Tx</th>
                                        <th>累计流量</th>
                                        <th>错包/丢包</th>
                                      </tr>
                                    </thead>
                                    <tbody>
                                      {snap.interfaces.map((nic) => (
                                        <tr key={nic.name}>
                                          <td className="mono" style={{ fontWeight: 600 }}>
                                            {nic.name}
                                          </td>
                                          <td className="mono" style={{ fontSize: 12 }}>
                                            {nic.ipv4 || '—'}{' '}
                                            {nic.state && (
                                              <span
                                                className={`tag-chip ${
                                                  nic.state === 'up' ? 'teal' : ''
                                                }`}
                                              >
                                                {nic.state}
                                              </span>
                                            )}
                                          </td>
                                          <td className="tabular">
                                            ↓{formatBytesRate(nic.rx_bps)} / ↑
                                            {formatBytesRate(nic.tx_bps)}
                                          </td>
                                          <td className="tabular" style={{ fontSize: 12 }}>
                                            {formatBytesTotal(nic.rx_bytes)} /{' '}
                                            {formatBytesTotal(nic.tx_bytes)}
                                          </td>
                                          <td className="tabular">
                                            {nic.rx_errors +
                                              nic.tx_errors +
                                              nic.rx_drops +
                                              nic.tx_drops}
                                          </td>
                                        </tr>
                                      ))}
                                    </tbody>
                                  </table>
                                </div>
                              )}
                            </div>
                          </div>
                        )}
                      </div>
                    )}

                    {/* SUB-SECTION B: Processes & Listening Ports + Public Baseline */}
                    {detailTab === 'procs_ports' && snap && (
                      <div>
                        {/* Process State Strip */}
                        <div className="mon-proc-summary tabular">
                          <div className="mon-proc-pill">
                            <span>总进程数</span>
                            <strong>{snap.procs_total}</strong>
                          </div>
                          <div className="mon-proc-pill">
                            <span>运行中 (R)</span>
                            <strong style={{ color: 'var(--accent-teal)' }}>{snap.procs_running}</strong>
                          </div>
                          <div className="mon-proc-pill">
                            <span>休眠等待 (S/I)</span>
                            <strong>{snap.procs_sleeping}</strong>
                          </div>
                          <div className="mon-proc-pill">
                            <span>I/O 不可中断阻塞 (D)</span>
                            <strong
                              style={{ color: snap.procs_blocked > 0 ? 'var(--amber-text)' : undefined }}
                            >
                              {snap.procs_blocked}
                            </strong>
                          </div>
                          <div className="mon-proc-pill">
                            <span>僵尸进程 (Z)</span>
                            <strong
                              style={{ color: snap.procs_zombie > 0 ? 'var(--danger-text)' : undefined }}
                            >
                              {snap.procs_zombie}
                            </strong>
                          </div>
                        </div>

                        <div className="mon-two-col" style={{ marginBottom: 16 }}>
                          <div className="mon-panel-card">
                            <div className="mon-panel-head">
                              <h4>Top CPU 消耗进程</h4>
                            </div>
                            <div style={{ overflowX: 'auto' }}>
                              <table className="data-table">
                                <thead>
                                  <tr>
                                    <th>PID</th>
                                    <th>用户</th>
                                    <th>CPU%</th>
                                    <th>MEM%</th>
                                    <th>RSS</th>
                                    <th>进程命令</th>
                                  </tr>
                                </thead>
                                <tbody>
                                  {(snap.top_cpu_procs || []).map((p) => (
                                    <tr key={`cpu-${p.pid}-${p.command}`}>
                                      <td className="mono">{p.pid}</td>
                                      <td>{p.user}</td>
                                      <td className="tabular" style={{ fontWeight: 600 }}>
                                        {p.cpu_percent}%
                                      </td>
                                      <td className="tabular">{p.mem_percent}%</td>
                                      <td className="tabular">{p.rss_mb} MB</td>
                                      <td className="mono">{p.command}</td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            </div>
                          </div>

                          <div className="mon-panel-card">
                            <div className="mon-panel-head">
                              <h4>Top 物理内存消耗进程</h4>
                            </div>
                            <div style={{ overflowX: 'auto' }}>
                              <table className="data-table">
                                <thead>
                                  <tr>
                                    <th>PID</th>
                                    <th>用户</th>
                                    <th>RSS 内存</th>
                                    <th>MEM%</th>
                                    <th>运行时长</th>
                                    <th>进程命令</th>
                                  </tr>
                                </thead>
                                <tbody>
                                  {(snap.top_mem_procs || []).map((p) => (
                                    <tr key={`mem-${p.pid}-${p.command}`}>
                                      <td className="mono">{p.pid}</td>
                                      <td>{p.user}</td>
                                      <td className="tabular" style={{ fontWeight: 600 }}>
                                        {p.rss_mb} MB
                                      </td>
                                      <td className="tabular">{p.mem_percent}%</td>
                                      <td className="mono" style={{ fontSize: 12 }}>
                                        {p.elapsed || '—'}
                                      </td>
                                      <td className="mono">{p.command}</td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            </div>
                          </div>
                        </div>

                        {/* Listening Ports & Public Exposure Baseline */}
                        <div className="mon-panel-card">
                          <div className="mon-panel-head" style={{ flexWrap: 'wrap', gap: 10 }}>
                            <div>
                              <h4>TCP / UDP 监听端口审计与公网暴露安全基线</h4>
                              <p style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>
                                当前信任的公网暴露基线：{' '}
                                <span className="mono">
                                  {nodeDetail.port_baseline.length > 0
                                    ? nodeDetail.port_baseline.join(', ')
                                    : '将在首次采集公网端口时自动锁定'}
                                </span>
                              </p>
                            </div>
                            <button
                              type="button"
                              className={`btn btn-sm ${
                                driftedPublicPorts.length > 0 ? 'btn-primary' : ''
                              }`}
                              onClick={() => void handleAcceptPortBaseline(nodeDetail.server.id)}
                            >
                              <ShieldCheck size={13.5} />
                              {driftedPublicPorts.length > 0
                                ? `采纳当前端口为安全基线 (+${driftedPublicPorts.length} 新增)`
                                : '更新公网端口基线'}
                            </button>
                          </div>

                          <div style={{ overflowX: 'auto' }}>
                            <table className="data-table">
                              <thead>
                                <tr>
                                  <th>协议</th>
                                  <th>监听绑定地址</th>
                                  <th>端口号</th>
                                  <th>暴露面评估</th>
                                  <th>安全基线状态</th>
                                  <th>PID / 所属守护进程</th>
                                </tr>
                              </thead>
                              <tbody>
                                {(snap.listening_ports || []).map((lp, idx) => {
                                  const protoKey = lp.proto.toLowerCase().startsWith('udp')
                                    ? 'udp'
                                    : 'tcp';
                                  const inBaseline = nodeDetail.port_baseline.includes(
                                    `${protoKey}/${lp.port}`
                                  );
                                  return (
                                    <tr key={`${lp.proto}-${lp.bind_addr}-${lp.port}-${idx}`}>
                                      <td className="mono">{lp.proto.toUpperCase()}</td>
                                      <td className="mono">{lp.bind_addr}</td>
                                      <td className="mono" style={{ fontWeight: 650 }}>
                                        {lp.port}
                                        {lp.watched && (
                                          <span
                                            className="tag-chip teal"
                                            style={{ marginLeft: 6 }}
                                          >
                                            必监端口
                                          </span>
                                        )}
                                      </td>
                                      <td>
                                        {lp.public_exposed ? (
                                          <span className="tag-chip amber">公网全网卡暴露</span>
                                        ) : (
                                          <span className="tag-chip">本地回环/内网</span>
                                        )}
                                      </td>
                                      <td>
                                        {!lp.public_exposed ? (
                                          <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>
                                            仅内网安全
                                          </span>
                                        ) : inBaseline ? (
                                          <span className="tag-chip teal">已纳入基线</span>
                                        ) : (
                                          <span className="tag-chip danger">基线外新暴露!</span>
                                        )}
                                      </td>
                                      <td className="mono">
                                        {lp.process
                                          ? `${lp.process}${lp.pid ? ` (pid=${lp.pid})` : ''}`
                                          : '—'}
                                      </td>
                                    </tr>
                                  );
                                })}
                              </tbody>
                            </table>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* SUB-SECTION C: Systemd Services, Docker Containers & Security Posture */}
                    {detailTab === 'services_security' && snap && (
                      <div className="mon-two-col">
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                          {/* Systemd Services */}
                          <div className="mon-panel-card">
                            <div className="mon-panel-head">
                              <h4>Systemd 守护服务状态</h4>
                              <span
                                className={`tag-chip ${
                                  snap.systemd_failed_count > 0 ? 'danger' : 'teal'
                                }`}
                              >
                                {snap.systemd_failed_count > 0
                                  ? `${snap.systemd_failed_count} 个故障单元`
                                  : '无 Failed 单元'}
                              </span>
                            </div>

                            {snap.systemd_failed_units && snap.systemd_failed_units.length > 0 && (
                              <div className="alert alert-error" style={{ marginBottom: 12 }}>
                                <span>
                                  故障单元：{snap.systemd_failed_units.join(', ')}
                                </span>
                              </div>
                            )}

                            {snap.services && snap.services.length > 0 ? (
                              <div className="mon-service-chips">
                                {snap.services.map((svc) => (
                                  <div
                                    key={svc.name}
                                    className={`mon-svc-badge ${
                                      svc.state === 'active' ? 'active' : 'down'
                                    }`}
                                  >
                                    <span className="mono" style={{ fontWeight: 600 }}>
                                      {svc.name}
                                    </span>
                                    <span>
                                      {svc.state}
                                      {svc.watched ? ' · 必监' : ''}
                                    </span>
                                  </div>
                                ))}
                              </div>
                            ) : (
                              <div className="mon-empty-inline">
                                未检测到 Systemd 服务列表（容器环境或非 systemd 发行版）
                              </div>
                            )}
                          </div>

                          {/* Docker Engine */}
                          <div className="mon-panel-card">
                            <div className="mon-panel-head">
                              <h4>Docker 容器运行健康</h4>
                              {snap.docker.installed ? (
                                <span className="mono" style={{ fontSize: 12 }}>
                                  运行中 {snap.docker.running} · 已停止 {snap.docker.stopped} · 异常{' '}
                                  {snap.docker.unhealthy}
                                </span>
                              ) : (
                                <span className="tag-chip">未安装或无权限</span>
                              )}
                            </div>

                            {snap.docker.installed &&
                            snap.docker.containers &&
                            snap.docker.containers.length > 0 ? (
                              <div style={{ overflowX: 'auto' }}>
                                <table className="data-table">
                                  <thead>
                                    <tr>
                                      <th>容器名</th>
                                      <th>镜像</th>
                                      <th>运行状态</th>
                                    </tr>
                                  </thead>
                                  <tbody>
                                    {snap.docker.containers.map((c) => (
                                      <tr key={c.id || c.name}>
                                        <td className="mono" style={{ fontWeight: 600 }}>
                                          {c.name}
                                        </td>
                                        <td className="mono" style={{ fontSize: 12 }}>
                                          {c.image}
                                        </td>
                                        <td>
                                          <span
                                            className={`tag-chip ${
                                              c.health === 'unhealthy' || c.state === 'restarting'
                                                ? 'danger'
                                                : c.state === 'running'
                                                ? 'teal'
                                                : ''
                                            }`}
                                          >
                                            {c.status}
                                          </span>
                                        </td>
                                      </tr>
                                    ))}
                                  </tbody>
                                </table>
                              </div>
                            ) : (
                              <div className="mon-empty-inline">
                                {snap.docker.installed
                                  ? '主机上当前没有容器实例'
                                  : '主机未运行 Docker 守护进程'}
                              </div>
                            )}
                          </div>
                        </div>

                        {/* Host Security Posture & SSH Brute-Force Audit */}
                        <div className="mon-panel-card">
                          <div className="mon-panel-head">
                            <h4>
                              <ShieldAlert size={15} /> 主机安全基线与 SSH 登录爆破审计
                            </h4>
                          </div>

                          <div className="kv-list" style={{ marginBottom: 14 }}>
                            <div className="kv-row">
                              <span className="kv-key">主机防火墙状态</span>
                              <span className="kv-val">
                                <span
                                  className={`tag-chip ${
                                    snap.security.firewall_status === 'active'
                                      ? 'teal'
                                      : snap.security.firewall_status === 'inactive'
                                      ? 'amber'
                                      : ''
                                  }`}
                                >
                                  {snap.security.firewall_status.toUpperCase()}
                                  {snap.security.firewall_detail
                                    ? ` (${snap.security.firewall_detail})`
                                    : ''}
                                </span>
                              </span>
                            </div>
                            <div className="kv-row">
                              <span className="kv-key">强制访问控制 (MAC)</span>
                              <span className="kv-val">{snap.security.mac_framework || '未启用'}</span>
                            </div>
                            <div className="kv-row">
                              <span className="kv-key">UID=0 特权账号列表</span>
                              <span className="kv-val">
                                {(snap.security.uid_zero_users || ['root']).join(', ')}
                              </span>
                            </div>
                            <div className="kv-row">
                              <span className="kv-key">内核安全更新重启需求</span>
                              <span className="kv-val">
                                {snap.security.reboot_required ? (
                                  <span className="tag-chip amber">需要重启生效</span>
                                ) : (
                                  <span className="tag-chip teal">无需重启</span>
                                )}
                              </span>
                            </div>
                            <div className="kv-row">
                              <span className="kv-key">近期 SSH 登录失败爆破计数</span>
                              <span className="kv-val">
                                <span
                                  className={`tag-chip ${
                                    snap.security.ssh_failed_recent >= 50
                                      ? 'danger'
                                      : snap.security.ssh_failed_recent >= 15
                                      ? 'amber'
                                      : 'teal'
                                  }`}
                                >
                                  {snap.security.ssh_failed_recent} 次失败尝试
                                </span>
                              </span>
                            </div>
                            {snap.security.top_failed_ips && snap.security.top_failed_ips.length > 0 && (
                              <div className="kv-row">
                                <span className="kv-key">高频攻击来源 IP</span>
                                <span className="kv-val">
                                  {snap.security.top_failed_ips.join(', ')}
                                </span>
                              </div>
                            )}
                            {snap.fingerprint && (
                              <div className="kv-row">
                                <span className="kv-key">SSH 主机密钥指纹</span>
                                <span className="kv-val" style={{ fontSize: 11.5 }}>
                                  {snap.fingerprint}
                                </span>
                              </div>
                            )}
                          </div>

                          <h4 style={{ fontSize: 13, fontWeight: 630, marginBottom: 8 }}>
                            当前在线交互式终端会话 (who)
                          </h4>
                          {snap.security.active_users && snap.security.active_users.length > 0 ? (
                            <div style={{ overflowX: 'auto', WebkitOverflowScrolling: 'touch' }}>
                              <table className="data-table">
                                <thead>
                                  <tr>
                                    <th>登录用户</th>
                                    <th>终端 TTY</th>
                                    <th>来源 IP</th>
                                    <th>登录时间</th>
                                  </tr>
                                </thead>
                                <tbody>
                                  {snap.security.active_users.map((u, idx) => (
                                    <tr key={`${u.user}-${u.tty}-${idx}`}>
                                      <td className="mono" style={{ fontWeight: 600, whiteSpace: 'nowrap' }}>
                                        {u.user}
                                      </td>
                                      <td className="mono" style={{ whiteSpace: 'nowrap' }}>{u.tty}</td>
                                      <td className="mono" style={{ whiteSpace: 'nowrap' }}>{u.from_ip || '本地'}</td>
                                      <td className="mono" style={{ fontSize: 12, whiteSpace: 'nowrap' }}>
                                        {u.login_time || '—'}
                                      </td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            </div>
                          ) : (
                            <div className="mon-empty-inline">当前无活跃的交互式 PTS/TTY 登录会话</div>
                          )}
                        </div>
                      </div>
                    )}
                  </>
                )}
              </div>
            )}

            {/* ================================================================
                TAB 3: ALERTS & INCIDENT CENTER
               ================================================================ */}
            {subTab === 'alerts' && (
              <div id="monitor-alerts-pane">
                <div className="mon-toolbar" style={{ marginTop: 0 }}>
                  <div className="group-pills">
                    {[
                      ['active', '未恢复活跃告警'],
                      ['firing', '触发中 (Firing)'],
                      ['acknowledged', '已确认 (Ack)'],
                      ['resolved', '已自动恢复'],
                      ['all', '全部历史记录'],
                    ].map(([k, label]) => (
                      <button
                        key={k}
                        type="button"
                        className={`group-pill ${alertStatusFilter === k ? 'active' : ''}`}
                        onClick={() => setAlertStatusFilter(k)}
                      >
                        {label}
                      </button>
                    ))}
                  </div>

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
                    <select
                      className="select mon-alert-server-select"
                      value={alertServerFilter}
                      onChange={(e) => setAlertServerFilter(e.target.value)}
                    >
                      <option value="">全部服务器节点</option>
                      {servers.map((srv) => (
                        <option key={srv.id} value={srv.id}>
                          {srv.name} ({srv.host})
                        </option>
                      ))}
                    </select>

                    <button
                      type="button"
                      className="btn btn-sm"
                      onClick={() => void handleClearResolvedAlerts()}
                    >
                      <Trash2 size={13} /> 清理已恢复记录
                    </button>
                  </div>
                </div>

                {loadingAlerts && alertsList.length === 0 ? (
                  <div className="empty-state">正在读取加密告警事件日志...</div>
                ) : alertsList.length === 0 ? (
                  <div className="empty-state">
                    <div className="empty-state-icon">
                      <CheckCircle2 size={22} style={{ color: 'var(--status-online)' }} />
                    </div>
                    <h3>当前没有匹配的监控告警事件</h3>
                    <p>所有纳管主机各项资源阈值、守护服务与安全基线均处于正常范围内。</p>
                  </div>
                ) : (
                  <div className="mon-panel-card" style={{ padding: 0, overflow: 'hidden' }}>
                    <div style={{ overflowX: 'auto' }}>
                      <table className="data-table mon-alerts-table">
                        <thead>
                          <tr>
                            <th>级别 / 状态</th>
                            <th>关联节点</th>
                            <th>告警规则与事件详情</th>
                            <th>当前指标 / 阈值</th>
                            <th>累计次数</th>
                            <th>触发 / 恢复时间</th>
                            <th style={{ textAlign: 'right' }}>处置</th>
                          </tr>
                        </thead>
                        <tbody>
                          {alertsList.map((al) => (
                            <tr key={al.id}>
                              <td data-label="级别 / 状态">
                                <div className="mon-alert-badges">
                                  <span
                                    className={`tag-chip ${
                                      al.severity === 'critical' ? 'danger' : 'amber'
                                    }`}
                                  >
                                    {al.severity === 'critical' ? '严重 CRITICAL' : '警告 WARNING'}
                                  </span>
                                  <span
                                    className={`tag-chip ${
                                      al.status === 'resolved'
                                        ? 'teal'
                                        : al.status === 'acknowledged'
                                        ? ''
                                        : 'danger'
                                    }`}
                                  >
                                    {al.status === 'firing'
                                      ? '触发中'
                                      : al.status === 'acknowledged'
                                      ? '已知晓'
                                      : '已自动恢复'}
                                  </span>
                                </div>
                              </td>
                              <td data-label="关联节点">
                                <div style={{ minWidth: 0 }}>
                                  <div
                                    style={{
                                      fontWeight: 600,
                                      cursor: 'pointer',
                                      color: 'var(--accent-teal)',
                                      overflowWrap: 'anywhere',
                                      wordBreak: 'break-word',
                                    }}
                                    onClick={() => handleOpenServerInspector(al.server_id)}
                                  >
                                    {al.server_name}
                                  </div>
                                  <div
                                    className="mono mon-alert-host"
                                    style={{ fontSize: 11.5, color: 'var(--text-muted)' }}
                                  >
                                    {al.host}
                                  </div>
                                </div>
                              </td>
                              <td data-label="告警详情" className="mon-alert-detail-cell">
                                <div style={{ fontWeight: 600, marginBottom: 2 }}>{al.title}</div>
                                <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                                  [{al.rule_name}] {al.detail}
                                </div>
                              </td>
                              <td data-label="当前指标 / 阈值" className="mono" style={{ fontSize: 12 }}>
                                <div>
                                  <div>
                                    实测: <strong>{al.metric_text}</strong>
                                  </div>
                                  {al.threshold_text && (
                                    <div style={{ color: 'var(--text-muted)' }}>
                                      条件: {al.threshold_text}
                                    </div>
                                  )}
                                </div>
                              </td>
                              <td data-label="累计次数" className="tabular">{al.occurrences} 次</td>
                              <td data-label="触发 / 恢复时间" className="mono" style={{ fontSize: 11.5 }}>
                                <div>
                                  <div>触发: {formatDateTime(al.triggered_at)}</div>
                                  {al.resolved_at ? (
                                    <div style={{ color: 'var(--status-online)' }}>
                                      恢复: {formatDateTime(al.resolved_at)}
                                    </div>
                                  ) : (
                                    <div style={{ color: 'var(--text-muted)' }}>
                                      持续: {formatDateTime(al.last_seen_at)}
                                    </div>
                                  )}
                                </div>
                              </td>
                              <td data-label="处置" className="mon-alert-actions-cell" style={{ textAlign: 'right' }}>
                                <div style={{ display: 'inline-flex', gap: 6, flexWrap: 'wrap' }}>
                                  {al.status === 'firing' && (
                                    <button
                                      type="button"
                                      className="btn btn-sm"
                                      onClick={() => void handleAckAlert(al.id)}
                                    >
                                      确认知晓
                                    </button>
                                  )}
                                  <button
                                    type="button"
                                    className="btn btn-sm"
                                    onClick={() => handleOpenServerInspector(al.server_id)}
                                  >
                                    透视
                                  </button>
                                </div>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* ================================================================
                TAB 4: SCHEDULE & MULTI-DIMENSIONAL ALERT POLICY EDITOR
               ================================================================ */}
            {subTab === 'policy' && policySettings && (
              <form id="monitor-policy-pane" onSubmit={handleSavePolicy}>
                <div className="mon-two-col" style={{ marginBottom: 18 }}>
                  {/* Scheduler & Retention Card */}
                  <div className="mon-panel-card">
                    <div className="mon-panel-head">
                      <h4>
                        <Clock size={15} /> 定时巡检调度与时序存储配置
                      </h4>
                      <label className="mon-switch-label">
                        <input
                          type="checkbox"
                          checked={policySettings.enabled}
                          onChange={(e) =>
                            setPolicySettings({ ...policySettings, enabled: e.target.checked })
                          }
                        />
                        <span>启用后台定时自动采集</span>
                      </label>
                    </div>

                    <div className="field-row">
                      <div className="field">
                        <label className="field-label">
                          <span>默认采集间隔 (秒)</span>
                          <span className="field-hint">支持 10 ~ 86400 秒</span>
                        </label>
                        <input
                          type="number"
                          className="input mono"
                          min={10}
                          max={86400}
                          value={policySettings.interval_sec}
                          onChange={(e) =>
                            setPolicySettings({
                              ...policySettings,
                              interval_sec: Number(e.target.value) || 60,
                            })
                          }
                        />
                        <div style={{ display: 'flex', gap: 6, marginTop: 6, flexWrap: 'wrap' }}>
                          {[15, 30, 60, 120, 300].map((sec) => (
                            <button
                              key={sec}
                              type="button"
                              className={`group-pill ${
                                policySettings.interval_sec === sec ? 'active' : ''
                              }`}
                              style={{ padding: '2px 8px', fontSize: 11.5 }}
                              onClick={() =>
                                setPolicySettings({ ...policySettings, interval_sec: sec })
                              }
                            >
                              {sec}s
                            </button>
                          ))}
                        </div>
                      </div>

                      <div className="field">
                        <label className="field-label">
                          <span>单机保存样本点数 (环形缓冲)</span>
                          <span className="field-hint">
                            约{' '}
                            {(
                              (policySettings.retention_points * policySettings.interval_sec) /
                              3600
                            ).toFixed(1)}{' '}
                            小时趋势
                          </span>
                        </label>
                        <input
                          type="number"
                          className="input mono"
                          min={30}
                          max={5000}
                          value={policySettings.retention_points}
                          onChange={(e) =>
                            setPolicySettings({
                              ...policySettings,
                              retention_points: Number(e.target.value) || 720,
                            })
                          }
                        />
                      </div>
                    </div>

                    <div className="field-row">
                      <div className="field">
                        <label className="field-label">单机 SSH 采集超时 (秒)</label>
                        <input
                          type="number"
                          className="input mono"
                          min={5}
                          max={120}
                          value={policySettings.timeout_sec}
                          onChange={(e) =>
                            setPolicySettings({
                              ...policySettings,
                              timeout_sec: Number(e.target.value) || 15,
                            })
                          }
                        />
                      </div>

                      <div className="field">
                        <label className="field-label">最大并发采集工作协程</label>
                        <input
                          type="number"
                          className="input mono"
                          min={1}
                          max={20}
                          value={policySettings.concurrency}
                          onChange={(e) =>
                            setPolicySettings({
                              ...policySettings,
                              concurrency: Number(e.target.value) || 6,
                            })
                          }
                        />
                      </div>
                    </div>

                    <div className="field" style={{ marginBottom: 0 }}>
                      <label className="field-label">
                        <span>告警推送 Webhook 地址 (选填，加密存储)</span>
                        <span className="field-hint">支持飞书/钉钉/企微或通用 JSON Webhook</span>
                      </label>
                      <input
                        className="input mono"
                        placeholder="https://open.feishu.cn/open-apis/bot/v2/hook/..."
                        value={policySettings.webhook_url || ''}
                        onChange={(e) =>
                          setPolicySettings({ ...policySettings, webhook_url: e.target.value })
                        }
                      />
                    </div>
                  </div>

                  {/* Deep Telemetry Dimension Switches */}
                  <div className="mon-panel-card">
                    <div className="mon-panel-head">
                      <h4>
                        <ShieldCheck size={15} /> 全方位采集维度与无人值守开关
                      </h4>
                    </div>

                    <div className="mon-toggle-list">
                      <label className="mon-check-row">
                        <input
                          type="checkbox"
                          checked={policySettings.collect_processes}
                          onChange={(e) =>
                            setPolicySettings({
                              ...policySettings,
                              collect_processes: e.target.checked,
                            })
                          }
                        />
                        <div>
                          <strong>采集进程状态分布与 Top CPU/内存进程</strong>
                          <p>包含总进程、运行态、D 态阻塞、Z 态僵尸进程及高占用进程明细</p>
                        </div>
                      </label>

                      <label className="mon-check-row">
                        <input
                          type="checkbox"
                          checked={policySettings.collect_ports_and_services}
                          onChange={(e) =>
                            setPolicySettings({
                              ...policySettings,
                              collect_ports_and_services: e.target.checked,
                            })
                          }
                        />
                        <div>
                          <strong>采集监听端口、Systemd 服务与 Docker 容器健康</strong>
                          <p>自动审计 ss/netstat 监听套接字、故障服务单元与容器异常重启</p>
                        </div>
                      </label>

                      <label className="mon-check-row">
                        <input
                          type="checkbox"
                          checked={policySettings.detect_port_drift}
                          onChange={(e) =>
                            setPolicySettings({
                              ...policySettings,
                              detect_port_drift: e.target.checked,
                            })
                          }
                        />
                        <div>
                          <strong>开启公网暴露监听端口安全基线漂移检测</strong>
                          <p>当发现安全基线以外新开放的 0.0.0.0 / [::] 端口时立即触发告警</p>
                        </div>
                      </label>

                      <label className="mon-check-row">
                        <input
                          type="checkbox"
                          checked={policySettings.collect_security}
                          onChange={(e) =>
                            setPolicySettings({
                              ...policySettings,
                              collect_security: e.target.checked,
                            })
                          }
                        />
                        <div>
                          <strong>采集主机安全态势与 SSH 登录爆破日志</strong>
                          <p>包含防火墙状态、UID=0 特权账户、在线终端会话与近期失败登录源 IP</p>
                        </div>
                      </label>

                      <div
                        className="mon-check-row"
                        style={{
                          background: 'var(--accent-teal-soft)',
                          borderColor: 'var(--accent-teal-border)',
                          cursor: 'default',
                        }}
                      >
                        <div>
                          <strong style={{ color: 'var(--accent-teal)' }}>
                            7×24 全天候后台独立采集（与 Web 会话及加密解耦）
                          </strong>
                          <p>
                            监控时序、告警与基线已独立持久化至非加密运行态文件，无论浏览器关闭、Web 会话过期或修改管理员密码，后台采集均持续运行且不触发凭据重加密。
                          </p>
                        </div>
                      </div>
                    </div>

                    <div
                      style={{
                        marginTop: 14,
                        paddingTop: 12,
                        borderTop: '1px solid var(--border-subtle)',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        flexWrap: 'wrap',
                        gap: 8,
                      }}
                    >
                      <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                        维护操作：清空所有已归档的历史监控样本
                      </span>
                      {!confirmClearAll ? (
                        <button
                          type="button"
                          className="btn btn-sm btn-danger"
                          onClick={() => setConfirmClearAll(true)}
                        >
                          <Trash2 size={13} /> 清空全部监控历史
                        </button>
                      ) : (
                        <div style={{ display: 'flex', gap: 6 }}>
                          <button
                            type="button"
                            className="btn btn-sm"
                            onClick={() => setConfirmClearAll(false)}
                          >
                            取消
                          </button>
                          <button
                            type="button"
                            className="btn btn-sm btn-danger"
                            onClick={() => void handleClearHistory('')}
                          >
                            确认清空
                          </button>
                        </div>
                      )}
                    </div>
                  </div>
                </div>

                {/* 18-Rule Alert Matrix Editor */}
                <div className="mon-panel-card">
                  <div className="mon-panel-head">
                    <div>
                      <h4>18 项多维告警阈值与连续防抖规则矩阵</h4>
                      <p style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>
                        支持配置警告阈值 (Warning)、严重阈值 (Critical) 及连续超限次数防抖，恢复正常后自动销警
                      </p>
                    </div>
                    <button
                      type="submit"
                      id="save-monitor-policy-btn"
                      className="btn btn-primary"
                      disabled={savingPolicy}
                    >
                      <Save size={14} />
                      {savingPolicy ? '正在加密保存...' : '加密保存监控策略'}
                    </button>
                  </div>

                  <div style={{ overflowX: 'auto' }}>
                    <table className="data-table mon-policy-table">
                      <thead>
                        <tr>
                          <th style={{ width: 64 }}>启用</th>
                          <th>规则名称与监控说明</th>
                          <th style={{ width: 140 }}>警告阈值 (Warning)</th>
                          <th style={{ width: 140 }}>严重阈值 (Critical)</th>
                          <th style={{ width: 140 }}>连续超限防抖</th>
                        </tr>
                      </thead>
                      <tbody>
                        {policyRules.map((rule, idx) => (
                          <tr key={rule.kind}>
                            <td data-label="启用状态">
                              <input
                                type="checkbox"
                                checked={rule.enabled}
                                onChange={(e) => {
                                  const next = [...policyRules];
                                  next[idx] = { ...rule, enabled: e.target.checked };
                                  setPolicyRules(next);
                                }}
                              />
                            </td>
                            <td data-label="告警规则" className="mon-policy-rule-cell">
                              <div style={{ fontWeight: 600 }}>{rule.name}</div>
                              <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                                {rule.description}
                              </div>
                            </td>
                            <td data-label="警告阈值 (Warning)">
                              {rule.state_based ? (
                                <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                                  状态触发型
                                </span>
                              ) : (
                                <div style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
                                  <input
                                    type="number"
                                    step="any"
                                    className="input mono mon-rule-input"
                                    value={rule.warning_threshold}
                                    onChange={(e) => {
                                      const next = [...policyRules];
                                      next[idx] = {
                                        ...rule,
                                        warning_threshold: Number(e.target.value),
                                      };
                                      setPolicyRules(next);
                                    }}
                                  />
                                  <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                                    {rule.unit}
                                  </span>
                                </div>
                              )}
                            </td>
                            <td data-label="严重阈值 (Critical)">
                              {rule.state_based ? (
                                <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                                  异常即告警
                                </span>
                              ) : (
                                <div style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
                                  <input
                                    type="number"
                                    step="any"
                                    className="input mono mon-rule-input"
                                    value={rule.critical_threshold}
                                    onChange={(e) => {
                                      const next = [...policyRules];
                                      next[idx] = {
                                        ...rule,
                                        critical_threshold: Number(e.target.value),
                                      };
                                      setPolicyRules(next);
                                    }}
                                  />
                                  <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                                    {rule.unit}
                                  </span>
                                </div>
                              )}
                            </td>
                            <td data-label="连续超限防抖">
                              <div style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
                                <input
                                  type="number"
                                  min={1}
                                  max={20}
                                  className="input mono mon-rule-input debounce"
                                  value={rule.consecutive_count}
                                  onChange={(e) => {
                                    const next = [...policyRules];
                                    next[idx] = {
                                      ...rule,
                                      consecutive_count: Math.max(1, Number(e.target.value) || 1),
                                    };
                                    setPolicyRules(next);
                                  }}
                                />
                                <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>次</span>
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </form>
            )}
          </>
        )}
      </div>

      {/* Host Key Verification Modal on Manual Collect */}
      {hostKeyPrompt && (
        <HostKeyModal
          info={hostKeyPrompt.info}
          onCancel={() => setHostKeyPrompt(null)}
          onTrustAndRetry={(fp) => {
            const { serverId } = hostKeyPrompt;
            setHostKeyPrompt(null);
            void handleCollectSingle(serverId, fp);
          }}
        />
      )}
    </div>
  );
};

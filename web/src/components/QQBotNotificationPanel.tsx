import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Copy,
  KeyRound,
  Link2,
  MessageSquare,
  PlugZap,
  Plus,
  Radio,
  RefreshCw,
  Save,
  Send,
  ShieldCheck,
  Trash2,
  Users,
  Wifi,
  WifiOff,
} from 'lucide-react';
import { api } from '../api';
import { copyTextToClipboard } from '../utils/clipboard';
import {
  formatIntentMaskHex,
  hasIntentBit,
  maskQQIdentifier,
  QQ_INTENT_GROUP_AND_C2C,
  qqGatewayStateMeta,
  qqPushCategoryLabel,
  qqTargetTypeLabel,
  toggleIntentBit,
} from '../utils/qqbotIntents';
import type {
  QQBotDiscoveredTarget,
  QQBotOverviewResponse,
  QQBotProbeResult,
  QQBotTarget,
  QQBotTargetType,
} from '../types';
import { formatDateTime } from './MonitorCharts';

export interface QQBotNotificationPanelProps {
  onStatusChange?: (status: { enabled: boolean; state: string; connected: boolean }) => void;
  onNotify: (msg: string) => void;
}

export const QQBotNotificationPanel: React.FC<QQBotNotificationPanelProps> = ({
  onStatusChange,
  onNotify,
}) => {
  const [overview, setOverview] = useState<QQBotOverviewResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  // Config form drafts
  const [enabled, setEnabled] = useState(false);
  const [appId, setAppId] = useState('');
  const [appSecret, setAppSecret] = useState('');
  const [clearAppSecret, setClearAppSecret] = useState(false);
  const [sandbox, setSandbox] = useState(false);
  const [apiBaseUrl, setApiBaseUrl] = useState('');
  const [tokenBaseUrl, setTokenBaseUrl] = useState('');
  const [intents, setIntents] = useState<number>(QQ_INTENT_GROUP_AND_C2C);
  const [shardId, setShardId] = useState<number>(0);
  const [shardCount, setShardCount] = useState<number>(1);
  const [messageFormat, setMessageFormat] = useState<'text' | 'markdown'>('text');
  const [pushMode, setPushMode] = useState<'proactive' | 'passive_prefer'>('proactive');
  const [allowBotCommands, setAllowBotCommands] = useState(true);
  const [notifyMonitor, setNotifyMonitor] = useState(true);
  const [notifyPatrol, setNotifyPatrol] = useState(true);
  const [notifyApprovals, setNotifyApprovals] = useState(true);
  const [notifyVulns, setNotifyVulns] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [configHydrated, setConfigHydrated] = useState(false);

  // Action busy states
  const [saving, setSaving] = useState(false);
  const [probing, setProbing] = useState(false);
  const [probeResult, setProbeResult] = useState<QQBotProbeResult | null>(null);
  const [reconnecting, setReconnecting] = useState(false);
  const [testingTargetId, setTestingTargetId] = useState<string | null>(null);
  const [generatingBindCode, setGeneratingBindCode] = useState(false);
  const [copiedBindCmd, setCopiedBindCmd] = useState(false);
  const [clearingLogs, setClearingLogs] = useState(false);

  // Manual target add form
  const [newTargetType, setNewTargetType] = useState<QQBotTargetType>('group');
  const [newTargetName, setNewTargetName] = useState('');
  const [newTargetId, setNewTargetId] = useState('');
  const [newGuildId, setNewGuildId] = useState('');
  const [addingTarget, setAddingTarget] = useState(false);
  const [mutatingTargetId, setMutatingTargetId] = useState('');

  // Diagnostic bottom log tabs
  const [diagTab, setDiagTab] = useState<'push' | 'events'>('push');

  const hydrateDraftsFromOverview = useCallback((ov: QQBotOverviewResponse) => {
    const s = ov.settings;
    setEnabled(Boolean(s.enabled));
    setAppId(s.app_id || '');
    setAppSecret('');
    setClearAppSecret(false);
    setSandbox(Boolean(s.sandbox));
    setApiBaseUrl(s.api_base_url || '');
    setTokenBaseUrl(s.token_base_url || '');
    setIntents(s.intents || QQ_INTENT_GROUP_AND_C2C);
    setShardId(s.shard_id || 0);
    setShardCount(s.shard_count || 1);
    setMessageFormat(s.message_format === 'markdown' ? 'markdown' : 'text');
    setPushMode(s.push_mode === 'passive_prefer' ? 'passive_prefer' : 'proactive');
    setAllowBotCommands(Boolean(s.allow_bot_commands));
    setNotifyMonitor(Boolean(s.notify_monitor_alerts));
    setNotifyPatrol(Boolean(s.notify_ai_patrol));
    setNotifyApprovals(Boolean(s.notify_external_approvals));
    setNotifyVulns(Boolean(s.notify_vuln_advisories));
    setConfigHydrated(true);
  }, []);

  const loadOverview = useCallback(
    async (silent = false, resyncDrafts = false) => {
      if (!silent) setRefreshing(true);
      try {
        const ov = await api.getQQBotOverview();
        setOverview(ov);
        onStatusChange?.({
          enabled: Boolean(ov.settings.enabled),
          state: ov.runtime.state,
          connected: Boolean(ov.runtime.connected),
        });
        if (!configHydrated || resyncDrafts) {
          hydrateDraftsFromOverview(ov);
        }
      } catch (err: any) {
        if (!silent) {
          onNotify(err?.message || '加载 QQ 机器人 WebSocket 配置失败');
        }
      } finally {
        setLoading(false);
        setRefreshing(false);
      }
    },
    [configHydrated, hydrateDraftsFromOverview, onNotify, onStatusChange]
  );

  useEffect(() => {
    void loadOverview(false, true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Poll live WebSocket runtime status & newly discovered targets every 6s while visible
  useEffect(() => {
    const timer = window.setInterval(() => {
      if (document.hidden) return;
      void loadOverview(true, false);
    }, 6000);
    return () => window.clearInterval(timer);
  }, [loadOverview]);

  const boundTargetKeySet = useMemo(() => {
    const set = new Set<string>();
    for (const t of overview?.settings?.targets || []) {
      set.add(`${t.target_type}:${t.target_id}`);
    }
    return set;
  }, [overview?.settings?.targets]);

  const handleSaveConfig = async (e: React.FormEvent) => {
    e.preventDefault();
    if (intents === 0) {
      onNotify('请至少勾选一项 QQ 开放平台 WebSocket 事件订阅 Intents');
      return;
    }
    setSaving(true);
    try {
      const res = await api.updateQQBotConfig({
        enabled,
        app_id: appId.trim(),
        ...(appSecret.trim() ? { app_secret: appSecret.trim() } : {}),
        clear_app_secret: clearAppSecret,
        sandbox,
        api_base_url: apiBaseUrl.trim(),
        token_base_url: tokenBaseUrl.trim(),
        intents,
        shard_id: Math.max(0, shardId),
        shard_count: Math.max(1, Math.min(64, shardCount)),
        message_format: messageFormat,
        push_mode: pushMode,
        allow_bot_commands: allowBotCommands,
        notify_monitor_alerts: notifyMonitor,
        notify_ai_patrol: notifyPatrol,
        notify_external_approvals: notifyApprovals,
        notify_vuln_advisories: notifyVulns,
      });
      setAppSecret('');
      setClearAppSecret(false);
      onStatusChange?.({
        enabled: Boolean(res.settings.enabled),
        state: res.runtime.state,
        connected: Boolean(res.runtime.connected),
      });
      onNotify(
        res.settings.enabled
          ? 'QQ 机器人 WebSocket 配置已加密保存，后台正在建立/刷新长连接'
          : 'QQ 机器人配置已加密保存（WebSocket 已停用）'
      );
      window.setTimeout(() => void loadOverview(true, true), 600);
    } catch (err: any) {
      onNotify(err?.message || '保存 QQ 机器人配置失败');
    } finally {
      setSaving(false);
    }
  };

  const handleProbeHandshake = async () => {
    setProbing(true);
    setProbeResult(null);
    try {
      const res = await api.probeQQBot({
        app_id: appId.trim() || undefined,
        ...(appSecret.trim() ? { app_secret: appSecret.trim() } : {}),
        sandbox,
        api_base_url: apiBaseUrl.trim(),
        token_base_url: tokenBaseUrl.trim(),
      });
      setProbeResult(res.probe);
      onNotify(
        `WebSocket 握手探测成功 (${res.probe.latency_ms}ms · 心跳周期 ${Math.round(
          (res.probe.heartbeat_interval_ms || 45000) / 1000
        )}s)`
      );
    } catch (err: any) {
      onNotify(err?.message || 'QQ WebSocket 握手探测失败');
    } finally {
      setProbing(false);
    }
  };

  const handleReconnect = async () => {
    setReconnecting(true);
    try {
      await api.reconnectQQBot();
      onNotify('已触发 QQ 机器人 WebSocket 重新连接');
      window.setTimeout(() => void loadOverview(true, false), 800);
    } catch (err: any) {
      onNotify(err?.message || '重连失败');
    } finally {
      setReconnecting(false);
    }
  };

  const handleGenerateBindCode = async () => {
    setGeneratingBindCode(true);
    try {
      const res = await api.generateQQBotBindCode();
      setOverview((prev) => (prev ? { ...prev, runtime: res.runtime } : prev));
      onNotify(`已生成一次性绑定码 ${res.bind_code.code}（10 分钟内有效）`);
    } catch (err: any) {
      onNotify(err?.message || '生成绑定码失败');
    } finally {
      setGeneratingBindCode(false);
    }
  };

  const handleCopyBindCommand = async (code: string) => {
    try {
      await copyTextToClipboard(`/bind ${code}`);
      setCopiedBindCmd(true);
      onNotify(`已复制绑定指令 /bind ${code}`);
      window.setTimeout(() => setCopiedBindCmd(false), 1800);
    } catch {
      onNotify('复制失败，请手动复制绑定指令');
    }
  };

  const handleAddTarget = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTargetId.trim()) {
      onNotify('请填写目标 OpenID 或子频道 Channel ID');
      return;
    }
    setAddingTarget(true);
    try {
      const res = await api.upsertQQBotTarget({
        name: newTargetName.trim(),
        target_type: newTargetType,
        target_id: newTargetId.trim(),
        guild_id: newTargetType === 'channel' ? newGuildId.trim() : undefined,
        enabled: true,
      });
      setOverview((prev) => (prev ? { ...prev, settings: res.settings } : prev));
      setNewTargetName('');
      setNewTargetId('');
      setNewGuildId('');
      onNotify(`已绑定推送目标「${res.target.name}」`);
    } catch (err: any) {
      onNotify(err?.message || '添加推送目标失败');
    } finally {
      setAddingTarget(false);
    }
  };

  const handleBindDiscovered = async (dt: QQBotDiscoveredTarget) => {
    setMutatingTargetId(`disc:${dt.target_type}:${dt.target_id}`);
    try {
      const res = await api.upsertQQBotTarget({
        name: dt.label || `${qqTargetTypeLabel(dt.target_type)} ${maskQQIdentifier(dt.target_id)}`,
        target_type: dt.target_type,
        target_id: dt.target_id,
        guild_id: dt.guild_id,
        enabled: true,
      });
      setOverview((prev) => (prev ? { ...prev, settings: res.settings } : prev));
      onNotify(`已一键绑定目标「${res.target.name}」`);
    } catch (err: any) {
      onNotify(err?.message || '一键绑定失败');
    } finally {
      setMutatingTargetId('');
    }
  };

  const handleToggleTargetEnabled = async (t: QQBotTarget) => {
    setMutatingTargetId(t.id);
    try {
      const res = await api.upsertQQBotTarget({
        id: t.id,
        name: t.name,
        target_type: t.target_type,
        target_id: t.target_id,
        guild_id: t.guild_id,
        enabled: !t.enabled,
      });
      setOverview((prev) => (prev ? { ...prev, settings: res.settings } : prev));
    } catch (err: any) {
      onNotify(err?.message || '更新目标开关失败');
    } finally {
      setMutatingTargetId('');
    }
  };

  const handleDeleteTarget = async (t: QQBotTarget) => {
    setMutatingTargetId(t.id);
    try {
      const res = await api.deleteQQBotTarget(t.id);
      setOverview((prev) => (prev ? { ...prev, settings: res.settings } : prev));
      onNotify(`已移除推送目标「${t.name}」`);
    } catch (err: any) {
      onNotify(err?.message || '移除目标失败');
    } finally {
      setMutatingTargetId('');
    }
  };

  const handleTestPush = async (targetId?: string) => {
    const key = targetId || '__all__';
    setTestingTargetId(key);
    try {
      const res = await api.testQQBotPush({
        app_id: appId.trim() || undefined,
        ...(appSecret.trim() ? { app_secret: appSecret.trim() } : {}),
        sandbox,
        api_base_url: apiBaseUrl.trim(),
        token_base_url: tokenBaseUrl.trim(),
        message_format: messageFormat,
        push_mode: pushMode,
        target_id: targetId || undefined,
      });
      onNotify(
        `测试通知已送达（成功 ${res.summary.sent} / 总计 ${res.summary.total}）`
      );
      void loadOverview(true, false);
    } catch (err: any) {
      onNotify(err?.message || '测试推送失败');
      void loadOverview(true, false);
    } finally {
      setTestingTargetId(null);
    }
  };

  const handleClearLogs = async () => {
    setClearingLogs(true);
    try {
      await api.clearQQBotLogs(false);
      onNotify('已清空 QQ 机器人网关事件与推送日志');
      await loadOverview(true, false);
    } catch (err: any) {
      onNotify(err?.message || '清空日志失败');
    } finally {
      setClearingLogs(false);
    }
  };

  if (loading && !overview) {
    return (
      <div className="mon-panel-card" style={{ padding: 28, textAlign: 'center', color: 'var(--text-muted)' }}>
        正在加载 QQ 开放平台 WebSocket 事件通知引擎...
      </div>
    );
  }

  const runtime = overview?.runtime;
  const settings = overview?.settings;
  const stateMeta = qqGatewayStateMeta(runtime?.state);
  const targets = settings?.targets || [];
  const discovered = overview?.discovered_targets || [];
  const recentEvents = overview?.recent_events || [];
  const pushHistory = overview?.push_history || [];
  const intentCatalog = overview?.intent_catalog || [];

  return (
    <div className="qqbot-root" id="qqbot-notification-panel">
      {/* Live Gateway Status Hero */}
      <section className="mon-panel-card qqbot-hero-card">
        <div className="qqbot-hero-top">
          <div className="qqbot-hero-identity">
            <div className={`qqbot-state-badge tone-${stateMeta.tone}`}>
              {stateMeta.online ? <Wifi size={13.5} /> : <WifiOff size={13.5} />}
              <span>{stateMeta.label}</span>
            </div>
            <div className="qqbot-hero-meta">
              <div className="qqbot-hero-title">
                <strong>QQ 开放平台 WebSocket 网关 (API v2)</strong>
                {runtime?.bot_username && (
                  <span className="tag-chip teal">
                    机器人：{runtime.bot_username}
                    {runtime.bot_user_id ? ` (${maskQQIdentifier(runtime.bot_user_id)})` : ''}
                  </span>
                )}
                {settings?.sandbox && <span className="tag-chip amber">沙箱环境</span>}
              </div>
              <p className="qqbot-hero-desc">
                通过客户端主动出站 WSS 长连接接入（OpCode 10 Hello → OpCode 2 Identify → OpCode 1 心跳 → OpCode 6 Resume 断线续传），无需公网域名、HTTPS 证书或开放入站端口，适合内网、Docker 与 Windows 桌面端 7×24 使用。
              </p>
            </div>
          </div>

          <div className="qqbot-hero-actions">
            <button
              type="button"
              id="qqbot-probe-btn"
              className="btn btn-sm"
              disabled={probing}
              onClick={() => void handleProbeHandshake()}
              title="校验 AppID/AppSecret 获取 AccessToken、查询 /gateway/bot 并验证 OpCode 10 Hello 握手"
            >
              <PlugZap size={13.5} />
              {probing ? '探测中...' : '探测握手'}
            </button>
            <button
              type="button"
              id="qqbot-reconnect-btn"
              className="btn btn-sm"
              disabled={reconnecting || !settings?.enabled}
              onClick={() => void handleReconnect()}
            >
              <RefreshCw size={13.5} className={reconnecting ? 'spin-icon' : ''} />
              立即重连
            </button>
            <button
              type="button"
              id="qqbot-test-push-btn"
              className="btn btn-sm btn-teal"
              disabled={testingTargetId !== null || targets.filter((t) => t.enabled).length === 0}
              onClick={() => void handleTestPush()}
              title="向所有已启用的 QQ 推送目标发送测试通知"
            >
              <Send size={13.5} />
              {testingTargetId === '__all__' ? '发送中...' : '全目标测试推送'}
            </button>
            <button
              type="button"
              className="btn btn-sm btn-ghost"
              disabled={refreshing}
              onClick={() => void loadOverview(false, false)}
              title="刷新实时状态与自动发现列表"
            >
              <RefreshCw size={13.5} className={refreshing ? 'spin-icon' : ''} />
            </button>
          </div>
        </div>

        {/* Gateway Error Diagnostic Banner */}
        {runtime?.last_error && (
          <div className="alert alert-error qqbot-error-banner" role="alert">
            <AlertTriangle size={15} style={{ flexShrink: 0, marginTop: 1 }} />
            <div style={{ minWidth: 0 }}>
              <strong>网关异常诊断：</strong>
              <span>{runtime.last_error}</span>
            </div>
          </div>
        )}

        {/* Probe Handshake Success Banner */}
        {probeResult && (
          <div className="qqbot-probe-banner">
            <CheckCircle2 size={15} style={{ color: 'var(--accent-teal)', flexShrink: 0 }} />
            <span>
              握手探测通过：网关 <span className="mono">{probeResult.gateway_url}</span> · 耗时{' '}
              <strong className="mono">{probeResult.latency_ms}ms</strong> · 心跳周期{' '}
              <strong className="mono">
                {Math.round((probeResult.heartbeat_interval_ms || 45000) / 1000)}s
              </strong>
              {probeResult.recommended_shards ? ` · 建议分片 ${probeResult.recommended_shards}` : ''}
              {probeResult.session_total
                ? ` · 24h 会话余量 ${probeResult.session_remaining}/${probeResult.session_total}`
                : ''}
            </span>
          </div>
        )}

        {/* 4-column Live Telemetry Strip */}
        <div className="qqbot-kpi-grid">
          <div className="qqbot-kpi-cell">
            <span className="qqbot-kpi-label">心跳周期 / RTT</span>
            <strong className="qqbot-kpi-val mono">
              {runtime?.heartbeat_interval_ms
                ? `${Math.round(runtime.heartbeat_interval_ms / 1000)}s`
                : '—'}
              {runtime?.heartbeat_latency_ms ? ` · ${runtime.heartbeat_latency_ms}ms` : ''}
            </strong>
            <span className="qqbot-kpi-sub">
              {runtime?.last_heartbeat_ack_at
                ? `最近 ACK ${formatDateTime(runtime.last_heartbeat_ack_at)}`
                : '等待 OpCode 11 ACK'}
            </span>
          </div>

          <div className="qqbot-kpi-cell">
            <span className="qqbot-kpi-label">会话序号 / Resume</span>
            <strong className="qqbot-kpi-val mono">
              seq {runtime?.last_seq || 0} · 分片 [{runtime?.shard?.[0] ?? 0}/{runtime?.shard?.[1] ?? 1}]
            </strong>
            <span className="qqbot-kpi-sub">
              恢复 {runtime?.resume_count || 0} 次 · 重连 {runtime?.reconnect_count || 0} 次
            </span>
          </div>

          <div className="qqbot-kpi-cell">
            <span className="qqbot-kpi-label">网关收到事件</span>
            <strong className="qqbot-kpi-val mono">{runtime?.events_received || 0}</strong>
            <span className="qqbot-kpi-sub">
              已自动发现 {discovered.length} 个会话目标
            </span>
          </div>

          <div className="qqbot-kpi-cell">
            <span className="qqbot-kpi-label">事件通知投递</span>
            <strong className="qqbot-kpi-val mono">
              成功 {runtime?.push_success_count || 0} · 失败 {runtime?.push_failure_count || 0}
            </strong>
            <span className="qqbot-kpi-sub">
              {runtime?.last_push_at
                ? `最近投递 ${formatDateTime(runtime.last_push_at)}`
                : '尚未发送事件通知'}
            </span>
          </div>
        </div>
      </section>

      {/* Main Two-Column Workbench */}
      <div className="qqbot-two-col">
        {/* LEFT COLUMN: Credentials, Subscriptions & Intents */}
        <form className="mon-panel-card qqbot-config-card" onSubmit={handleSaveConfig}>
          <div className="mon-panel-head" style={{ flexWrap: 'wrap', gap: 10 }}>
            <h4>
              <KeyRound size={15} /> QQ 开放平台接入与订阅配置
            </h4>
            <label className="mon-switch-label">
              <input
                type="checkbox"
                id="qqbot-enable-toggle"
                checked={enabled}
                onChange={(e) => setEnabled(e.target.checked)}
              />
              <span>启用 7×24 WebSocket 长连接</span>
            </label>
          </div>

          <div className="field-row">
            <div className="field">
              <label className="field-label">
                <span>机器人 AppID</span>
                <span className="field-hint">来自 q.qq.com 开发管理端</span>
              </label>
              <input
                id="qqbot-appid-input"
                className="input mono"
                placeholder="例如 102030405"
                value={appId}
                onChange={(e) => setAppId(e.target.value)}
              />
            </div>

            <div className="field">
              <label className="field-label">
                <span>
                  机器人 AppSecret{' '}
                  {settings?.has_app_secret && !clearAppSecret && (
                    <strong style={{ color: 'var(--accent-teal)' }}>
                      （已加密 {settings.app_secret_preview}）
                    </strong>
                  )}
                </span>
                {settings?.has_app_secret && !clearAppSecret && (
                  <button
                    type="button"
                    className="btn btn-xs btn-ghost"
                    style={{ padding: '0 6px', height: 20, fontSize: 11 }}
                    onClick={() => {
                      setAppSecret('');
                      setClearAppSecret(true);
                    }}
                  >
                    清空密钥
                  </button>
                )}
              </label>
              <input
                id="qqbot-secret-input"
                type="password"
                className="input mono"
                placeholder={
                  settings?.has_app_secret && !clearAppSecret
                    ? '留空保留已加密保存的 AppSecret'
                    : '填写 QQ 开放平台 AppSecret（将使用 XChaCha20 加密）'
                }
                value={appSecret}
                onChange={(e) => {
                  setAppSecret(e.target.value);
                  setClearAppSecret(false);
                }}
              />
            </div>
          </div>

          <div className="field-row">
            <div className="field">
              <label className="field-label">消息格式</label>
              <select
                className="select"
                value={messageFormat}
                onChange={(e) =>
                  setMessageFormat(e.target.value === 'markdown' ? 'markdown' : 'text')
                }
              >
                <option value="text">纯文本消息 (msg_type=0 · 全场景最稳妥)</option>
                <option value="markdown">Markdown 富文本 (msg_type=2 · 失败自动降级纯文本)</option>
              </select>
            </div>

            <div className="field">
              <label className="field-label">推送策略</label>
              <select
                className="select"
                value={pushMode}
                onChange={(e) =>
                  setPushMode(e.target.value === 'passive_prefer' ? 'passive_prefer' : 'proactive')
                }
              >
                <option value="proactive">主动推送（推荐 · 受限失败时自动借用近期被动窗口）</option>
                <option value="passive_prefer">优先复用近期被动回复窗口（节省主动配额）</option>
              </select>
            </div>
          </div>

          <div className="qqbot-inline-checks">
            <label className="qqbot-check-item">
              <input
                type="checkbox"
                checked={sandbox}
                onChange={(e) => setSandbox(e.target.checked)}
              />
              <span>使用沙箱环境 (sandbox.api.sgroup.qq.com)</span>
            </label>
            <label className="qqbot-check-item">
              <input
                type="checkbox"
                checked={allowBotCommands}
                onChange={(e) => setAllowBotCommands(e.target.checked)}
              />
              <span>启用 QQ 指令回复 (/bind、/id、已绑定目标 /status 与 /alerts)</span>
            </label>
          </div>

          {/* Event Notification Domain Subscriptions */}
          <div className="qqbot-section-block">
            <div className="qqbot-section-title">
              <Radio size={14} /> 订阅推送的 ServerNeedSafe 事件类型
            </div>
            <div className="qqbot-sub-grid">
              <label className="qqbot-sub-tile">
                <input
                  type="checkbox"
                  checked={notifyMonitor}
                  onChange={(e) => setNotifyMonitor(e.target.checked)}
                />
                <div>
                  <strong>状态监控告警与恢复</strong>
                  <span>主机离线、CPU/内存/磁盘超限、端口漂移、入侵特征触发与恢复</span>
                </div>
              </label>

              <label className="qqbot-sub-tile">
                <input
                  type="checkbox"
                  checked={notifyPatrol}
                  onChange={(e) => setNotifyPatrol(e.target.checked)}
                />
                <div>
                  <strong>AI 后台定时巡检异常</strong>
                  <span>后台只读巡检发现风险及外部 MCP / 内置 AI 深度根因研判报告</span>
                </div>
              </label>

              <label className="qqbot-sub-tile">
                <input
                  type="checkbox"
                  checked={notifyApprovals}
                  onChange={(e) => setNotifyApprovals(e.target.checked)}
                />
                <div>
                  <strong>外部 AI (MCP) 待审批变更</strong>
                  <span>外部 AI 提交 HITL 变更计划等待管理员审核执行时立即提醒</span>
                </div>
              </label>

              <label className="qqbot-sub-tile">
                <input
                  type="checkbox"
                  checked={notifyVulns}
                  onChange={(e) => setNotifyVulns(e.target.checked)}
                />
                <div>
                  <strong>高危 / KEV 漏洞监测动态</strong>
                  <span>监测清单中的主流应用出现新严重/高危或 CISA KEV 公告时推送</span>
                </div>
              </label>
            </div>
          </div>

          {/* Official QQ Gateway Intents Bitmask */}
          <div className="qqbot-section-block">
            <div className="qqbot-section-title-row">
              <span className="qqbot-section-title">
                <ShieldCheck size={14} /> WebSocket 事件订阅 Intents 位图
              </span>
              <span className="tag-chip mono">
                intents = {intents} ({formatIntentMaskHex(intents)})
              </span>
            </div>
            <div className="qqbot-intents-list">
              {intentCatalog.map((item) => {
                const checked = hasIntentBit(intents, item.value);
                return (
                  <label key={item.key} className="qqbot-intent-row">
                    <input
                      type="checkbox"
                      checked={checked}
                      onChange={(e) =>
                        setIntents((prev) => toggleIntentBit(prev, item.value, e.target.checked))
                      }
                    />
                    <div style={{ minWidth: 0 }}>
                      <div className="qqbot-intent-head">
                        <strong>{item.name}</strong>
                        <span className="mono qqbot-intent-code">
                          {item.key} (1&lt;&lt;{item.bit})
                        </span>
                        {item.recommended && <span className="tag-chip teal">推荐</span>}
                        {item.private_only && <span className="tag-chip amber">仅私域</span>}
                      </div>
                      <p>{item.description}</p>
                    </div>
                  </label>
                );
              })}
            </div>
            <div className="qqbot-hint-note">
              提示：按 QQ 开放平台规范，勾选未开通权限的 Intent 会导致网关返回关闭码 <span className="mono">4014</span> 并断开连接；普通 QQ 群/单聊机器人默认仅需勾选「QQ 单聊与群聊事件」。
            </div>
          </div>

          {/* Collapsible Advanced: Sharding & Custom Proxy Base URL */}
          <div className="qqbot-advanced-wrap">
            <button
              type="button"
              className="btn btn-sm btn-ghost qqbot-advanced-toggle"
              onClick={() => setShowAdvanced((v) => !v)}
            >
              {showAdvanced ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
              高级参数（分片 Shard 与自定义 OpenAPI / Token 代理地址）
            </button>
            {showAdvanced && (
              <div className="qqbot-advanced-body">
                <div className="field-row">
                  <div className="field">
                    <label className="field-label">分片编号 (Shard ID)</label>
                    <input
                      type="number"
                      min={0}
                      max={Math.max(0, shardCount - 1)}
                      className="input mono"
                      value={shardId}
                      onChange={(e) => setShardId(Math.max(0, Number(e.target.value) || 0))}
                    />
                  </div>
                  <div className="field">
                    <label className="field-label">分片总数 (Num Shards)</label>
                    <input
                      type="number"
                      min={1}
                      max={64}
                      className="input mono"
                      value={shardCount}
                      onChange={(e) => setShardCount(Math.max(1, Number(e.target.value) || 1))}
                    />
                  </div>
                </div>
                <div className="field">
                  <label className="field-label">
                    <span>自定义 OpenAPI 地址（可选）</span>
                    <span className="field-hint">
                      当前生效：{settings?.effective_api_base_url || 'https://api.bot.qq.com'}
                    </span>
                  </label>
                  <input
                    className="input mono"
                    placeholder="留空默认 https://api.bot.qq.com（沙箱模式下为 sandbox.api.sgroup.qq.com）"
                    value={apiBaseUrl}
                    onChange={(e) => setApiBaseUrl(e.target.value)}
                  />
                </div>
                <div className="field" style={{ marginBottom: 0 }}>
                  <label className="field-label">
                    <span>自定义 AccessToken 地址（可选）</span>
                    <span className="field-hint">留空默认跟随 OpenAPI 地址</span>
                  </label>
                  <input
                    className="input mono"
                    placeholder="留空默认 https://api.bot.qq.com"
                    value={tokenBaseUrl}
                    onChange={(e) => setTokenBaseUrl(e.target.value)}
                  />
                </div>
              </div>
            )}
          </div>

          <div className="qqbot-form-footer">
            <button
              type="submit"
              id="qqbot-save-config-btn"
              className="btn btn-primary"
              disabled={saving}
            >
              <Save size={14} />
              {saving ? '正在加密保存...' : '加密保存并应用 WebSocket 配置'}
            </button>
          </div>
        </form>

        {/* RIGHT COLUMN: Bind Code, Bound Targets & Auto-Discovered Targets */}
        <div className="qqbot-right-stack">
          {/* Quick One-Time Bind Code Card */}
          <section className="mon-panel-card">
            <div className="mon-panel-head" style={{ flexWrap: 'wrap', gap: 8 }}>
              <h4>
                <Link2 size={15} /> 快速免查 OpenID 绑定（推荐）
              </h4>
              <button
                type="button"
                id="qqbot-gen-bind-code-btn"
                className="btn btn-sm btn-teal"
                disabled={generatingBindCode}
                onClick={() => void handleGenerateBindCode()}
              >
                <KeyRound size={13} />
                {generatingBindCode ? '生成中...' : '生成一次性绑定码'}
              </button>
            </div>

            {runtime?.active_bind_code ? (
              <div className="qqbot-bind-code-box">
                <div className="qqbot-bind-code-main">
                  <span className="qqbot-bind-code-label">在 QQ 单聊或群聊中 @机器人 发送：</span>
                  <code className="qqbot-bind-code-cmd mono">
                    /bind {runtime.active_bind_code.code}
                  </code>
                </div>
                <div className="qqbot-bind-code-actions">
                  <span style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>
                    有效期至 {formatDateTime(runtime.active_bind_code.expires_at)}（单次有效）
                  </span>
                  <button
                    type="button"
                    className="btn btn-sm"
                    onClick={() => void handleCopyBindCommand(runtime.active_bind_code!.code)}
                  >
                    {copiedBindCmd ? <Check size={13} /> : <Copy size={13} />}
                    {copiedBindCmd ? '已复制' : '复制指令'}
                  </button>
                </div>
              </div>
            ) : (
              <p className="qqbot-muted-help">
                QQ 机器人 API v2 使用 32 位加密 <span className="mono">openid</span> 而非 QQ 号/群号。启用上方 WebSocket 长连接后，点击「生成一次性绑定码」并在目标 QQ 群 @机器人 或单聊发送 <span className="mono">/bind 验证码</span>，即可自动完成安全绑定；也可直接给机器人发任意消息，从下方「自动发现列表」一键添加。
              </p>
            )}
          </section>

          {/* Bound Push Targets Card */}
          <section className="mon-panel-card">
            <div className="mon-panel-head" style={{ flexWrap: 'wrap', gap: 8 }}>
              <h4>
                <Users size={15} /> 已绑定推送目标 ({targets.length})
              </h4>
              <span className="tag-chip">
                已启用 {targets.filter((t) => t.enabled).length} 个
              </span>
            </div>

            {targets.length === 0 ? (
              <div className="qqbot-empty-box">
                尚未绑定任何 QQ 通知目标。可使用上方 <span className="mono">/bind</span> 指令自动绑定，或在下方手动录入 OpenID / Channel ID。
              </div>
            ) : (
              <div className="qqbot-target-list">
                {targets.map((t) => (
                  <div key={t.id} className={`qqbot-target-item ${t.enabled ? '' : 'disabled'}`}>
                    <div className="qqbot-target-info">
                      <div className="qqbot-target-head">
                        <span className="tag-chip teal">{qqTargetTypeLabel(t.target_type)}</span>
                        <strong>{t.name}</strong>
                      </div>
                      <div className="qqbot-target-id mono" title={t.target_id}>
                        {t.target_id}
                        {t.guild_id ? ` · guild:${t.guild_id}` : ''}
                      </div>
                    </div>
                    <div className="qqbot-target-actions">
                      <label className="qqbot-mini-switch" title="启用/暂停该目标推送">
                        <input
                          type="checkbox"
                          checked={t.enabled}
                          disabled={mutatingTargetId === t.id}
                          onChange={() => void handleToggleTargetEnabled(t)}
                        />
                        <span>{t.enabled ? '启用' : '暂停'}</span>
                      </label>
                      <button
                        type="button"
                        className="btn btn-xs"
                        disabled={testingTargetId !== null}
                        onClick={() => void handleTestPush(t.id)}
                      >
                        <Send size={12} />
                        {testingTargetId === t.id ? '发送中...' : '测试'}
                      </button>
                      <button
                        type="button"
                        className="btn btn-xs btn-ghost"
                        style={{ color: 'var(--danger-text)' }}
                        disabled={mutatingTargetId === t.id}
                        onClick={() => void handleDeleteTarget(t)}
                        aria-label={`移除 ${t.name}`}
                      >
                        <Trash2 size={12.5} />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Manual Add Target Form */}
            <form className="qqbot-add-target-form" onSubmit={handleAddTarget}>
              <div className="qqbot-add-target-row">
                <select
                  className="select"
                  value={newTargetType}
                  onChange={(e) => setNewTargetType(e.target.value as QQBotTargetType)}
                  aria-label="目标类型"
                >
                  <option value="group">QQ 群 (group_openid)</option>
                  <option value="c2c">QQ 单聊 (user_openid)</option>
                  <option value="channel">QQ 频道子频道 (channel_id)</option>
                </select>
                <input
                  className="input"
                  placeholder="备注名称（如 运维告警群）"
                  value={newTargetName}
                  onChange={(e) => setNewTargetName(e.target.value)}
                />
              </div>
              <div className="qqbot-add-target-row">
                <input
                  className="input mono"
                  placeholder={
                    newTargetType === 'group'
                      ? '输入 32 位 group_openid'
                      : newTargetType === 'c2c'
                      ? '输入 32 位 user_openid'
                      : '输入子频道 channel_id'
                  }
                  value={newTargetId}
                  onChange={(e) => setNewTargetId(e.target.value)}
                />
                {newTargetType === 'channel' && (
                  <input
                    className="input mono"
                    placeholder="可选 guild_id"
                    value={newGuildId}
                    onChange={(e) => setNewGuildId(e.target.value)}
                  />
                )}
                <button
                  type="submit"
                  className="btn btn-sm btn-primary"
                  disabled={addingTarget}
                  style={{ flexShrink: 0 }}
                >
                  <Plus size={13.5} /> 手动绑定
                </button>
              </div>
            </form>
          </section>

          {/* Auto-Discovered Targets via WebSocket */}
          <section className="mon-panel-card">
            <div className="mon-panel-head" style={{ flexWrap: 'wrap', gap: 8 }}>
              <h4>
                <MessageSquare size={15} /> WebSocket 自动发现的会话 ({discovered.length})
              </h4>
              <span style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>
                收到任意 QQ 单聊/群 @/入群/加好友事件后自动记录
              </span>
            </div>

            {discovered.length === 0 ? (
              <div className="qqbot-empty-box">
                暂未捕获到入站会话。WebSocket 在线后，在 QQ 给机器人发一条消息或在群里 @机器人，对应的 OpenID 将实时出现在这里供您一键绑定。
              </div>
            ) : (
              <div className="qqbot-discovered-list">
                {discovered.slice(0, 12).map((dt) => {
                  const key = `${dt.target_type}:${dt.target_id}`;
                  const alreadyBound = boundTargetKeySet.has(key);
                  return (
                    <div key={key} className="qqbot-discovered-row">
                      <div style={{ minWidth: 0, flex: 1 }}>
                        <div className="qqbot-target-head">
                          <span className="tag-chip">{qqTargetTypeLabel(dt.target_type)}</span>
                          <strong>{dt.label || maskQQIdentifier(dt.target_id)}</strong>
                          {dt.proactive_rejected && (
                            <span className="tag-chip danger">已关闭主动推送</span>
                          )}
                          {alreadyBound && <span className="tag-chip teal">已绑定</span>}
                        </div>
                        <div className="qqbot-target-id mono">{dt.target_id}</div>
                        <div className="qqbot-discovered-meta">
                          <span>事件: {dt.last_event_type || '—'}</span>
                          <span>活跃: {formatDateTime(dt.last_seen_at)}</span>
                          {dt.last_message_preview && (
                            <span>最近消息: {dt.last_message_preview}</span>
                          )}
                        </div>
                      </div>
                      {!alreadyBound && (
                        <button
                          type="button"
                          className="btn btn-xs btn-teal"
                          disabled={mutatingTargetId === `disc:${key}`}
                          onClick={() => void handleBindDiscovered(dt)}
                        >
                          <Plus size={12} /> 一键绑定
                        </button>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </section>
        </div>
      </div>

      {/* Bottom Diagnostics: Push Delivery Log & Recent Gateway Events */}
      <section className="mon-panel-card">
        <div className="mon-panel-head" style={{ flexWrap: 'wrap', gap: 10 }}>
          <div className="group-pills" style={{ margin: 0 }}>
            <button
              type="button"
              className={`group-pill ${diagTab === 'push' ? 'active' : ''}`}
              onClick={() => setDiagTab('push')}
            >
              <Send size={12.5} /> 推送投递记录 ({pushHistory.length})
            </button>
            <button
              type="button"
              className={`group-pill ${diagTab === 'events' ? 'active' : ''}`}
              onClick={() => setDiagTab('events')}
            >
              <Activity size={12.5} /> WebSocket 网关事件流 ({recentEvents.length})
            </button>
          </div>
          <button
            type="button"
            className="btn btn-xs btn-ghost"
            disabled={clearingLogs || (pushHistory.length === 0 && recentEvents.length === 0)}
            onClick={() => void handleClearLogs()}
          >
            <Trash2 size={12.5} /> 清空日志
          </button>
        </div>

        {diagTab === 'push' ? (
          pushHistory.length === 0 ? (
            <div className="qqbot-empty-box">
              暂无事件通知投递记录。绑定推送目标后点击「测试推送」，或等待监控告警 / AI 巡检触发自动推送。
            </div>
          ) : (
            <div className="qqbot-log-list">
              {pushHistory.map((p) => (
                <div key={p.id} className="qqbot-log-row">
                  <div className="qqbot-log-head">
                    <span className={`tag-chip ${p.success ? 'teal' : 'danger'}`}>
                      {p.success ? '成功' : '失败'}
                    </span>
                    <span className="tag-chip">{qqPushCategoryLabel(p.category)}</span>
                    <span className="tag-chip">
                      {p.mode === 'passive' ? '被动回复窗口' : '主动推送'}
                    </span>
                    <strong>{p.title}</strong>
                    <span className="qqbot-log-time mono">{formatDateTime(p.sent_at)}</span>
                  </div>
                  <div className="qqbot-log-sub">
                    <span>
                      目标：{p.target_name || maskQQIdentifier(p.target_id)} (
                      {qqTargetTypeLabel(p.target_type)} · <span className="mono">{maskQQIdentifier(p.target_id)}</span>)
                    </span>
                    {p.error && <span style={{ color: 'var(--danger-text)' }}>错误：{p.error}</span>}
                  </div>
                </div>
              ))}
            </div>
          )
        ) : recentEvents.length === 0 ? (
          <div className="qqbot-empty-box">
            暂无网关事件日志。启用 WebSocket 连接后，READY / RESUMED / 心跳重建 / 单聊与群聊 Dispatch 事件将实时记录于此。
          </div>
        ) : (
          <div className="qqbot-log-list">
            {recentEvents.map((ev) => (
              <div key={`${ev.id}-${ev.received_at}`} className="qqbot-log-row">
                <div className="qqbot-log-head">
                  <span className="tag-chip mono">op={ev.op}</span>
                  <span className="tag-chip teal mono">{ev.event_type}</span>
                  {ev.seq ? <span className="tag-chip mono">s={ev.seq}</span> : null}
                  {ev.sender && <strong>{ev.sender}</strong>}
                  <span className="qqbot-log-time mono">{formatDateTime(ev.received_at)}</span>
                </div>
                <div className="qqbot-log-sub">
                  {ev.target_id && (
                    <span className="mono">
                      [{qqTargetTypeLabel(ev.target_type)}] {maskQQIdentifier(ev.target_id)}
                    </span>
                  )}
                  {ev.summary && <span>{ev.summary}</span>}
                </div>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
};

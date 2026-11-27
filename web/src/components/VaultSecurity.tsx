import React, { useCallback, useEffect, useState } from 'react';
import {
  Lock,
  Download,
  Upload,
  KeyRound,
  Settings,
  Fingerprint,
  FileClock,
  Trash2,
  RefreshCw,
  Cloud,
  ArrowUpRight,
  ArrowDownLeft,
  Database,
  ShieldCheck,
  Activity,
  ArrowUpCircle,
  Globe,
  Gauge,
  RotateCcw,
} from 'lucide-react';
import { api } from '../api';
import type {
  AppSettings,
  UpdateMirrorMode,
  UpdateOverviewResponse,
  UpdateSettings,
  VaultSecurityOverview,
} from '../types';

interface VaultSecurityProps {
  updateOverview: UpdateOverviewResponse | null;
  onUpdateOverviewChange: (ov: UpdateOverviewResponse) => void;
  onOpenUpdateModal: () => void;
  onSettingsChanged: (s: AppSettings) => void;
  onLogoutSession: () => Promise<void>;
  onRevokeAllSessions: () => Promise<void>;
  onNotify: (msg: string) => void;
}

function formatBytes(n?: number): string {
  const v = n || 0;
  if (v < 1024) return `${v} B`;
  if (v < 1024 * 1024) return `${(v / 1024).toFixed(1)} KB`;
  return `${(v / (1024 * 1024)).toFixed(2)} MB`;
}

export const VaultSecurity: React.FC<VaultSecurityProps> = ({
  updateOverview,
  onUpdateOverviewChange,
  onOpenUpdateModal,
  onSettingsChanged,
  onLogoutSession,
  onRevokeAllSessions,
  onNotify,
}) => {
  const [data, setData] = useState<VaultSecurityOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [settingsForm, setSettingsForm] = useState<AppSettings>({
    auto_lock_minutes: 0,
    host_key_policy: 'tofu',
    terminal_font_size: 14,
    terminal_scrollback: 5000,
    show_hidden_files: true,
    remote_sync_url: '',
  });

  // Version Auto-Check & China Mirror Settings
  const [updateForm, setUpdateForm] = useState<UpdateSettings>({
    auto_check_enabled: true,
    check_interval_hours: 6,
    mirror_mode: 'auto',
    custom_mirror_url: '',
    include_prerelease: false,
    skipped_version: '',
  });
  const [savingUpdateCfg, setSavingUpdateCfg] = useState(false);
  const [checkingUpdate, setCheckingUpdate] = useState(false);
  const [probingMirrors, setProbingMirrors] = useState(false);

  // Admin Login Password Update
  const [oldPass, setOldPass] = useState('');
  const [newPass, setNewPass] = useState('');
  const [confirmPass, setConfirmPass] = useState('');
  const [updatingPass, setUpdatingPass] = useState(false);

  // Portable Encrypted Backup Export
  const [exportPass, setExportPass] = useState('');
  const [exportPassConfirm, setExportPassConfirm] = useState('');
  const [exportIncludeRuntime, setExportIncludeRuntime] = useState(true);
  const [exporting, setExporting] = useState(false);

  // Import Backup
  const [importFile, setImportFile] = useState<File | null>(null);
  const [importPass, setImportPass] = useState('');
  const [importIncludeRuntime, setImportIncludeRuntime] = useState(true);
  const [importing, setImporting] = useState(false);

  // Cross-Instance Sync (Desktop <-> Server)
  const [syncUrl, setSyncUrl] = useState('');
  const [syncRemotePass, setSyncRemotePass] = useState('');
  const [syncIncludeRuntime, setSyncIncludeRuntime] = useState(false);
  const [syncing, setSyncing] = useState<'push' | 'pull' | null>(null);

  const loadOverview = useCallback(async () => {
    setLoading(true);
    try {
      const [res, upd] = await Promise.all([
        api.getVaultSecurity(),
        api.getUpdateStatus().catch(() => null),
      ]);
      setData(res);
      setSettingsForm(res.settings);
      setSyncUrl((prev) => prev || res.settings.remote_sync_url || '');
      if (upd) {
        onUpdateOverviewChange(upd);
        setUpdateForm({
          auto_check_enabled: upd.settings.auto_check_enabled !== false,
          check_interval_hours: upd.settings.check_interval_hours || 6,
          mirror_mode: (upd.settings.mirror_mode as UpdateMirrorMode) || 'auto',
          custom_mirror_url: upd.settings.custom_mirror_url || '',
          include_prerelease: Boolean(upd.settings.include_prerelease),
          skipped_version: upd.settings.skipped_version || '',
        });
      }
    } catch (err: any) {
      onNotify(err?.message || '读取安全与存储中心状态失败');
    } finally {
      setLoading(false);
    }
  }, [onNotify, onUpdateOverviewChange]);

  useEffect(() => {
    void loadOverview();
  }, [loadOverview]);

  useEffect(() => {
    if (!updateOverview?.settings) return;
    setUpdateForm({
      auto_check_enabled: updateOverview.settings.auto_check_enabled !== false,
      check_interval_hours: updateOverview.settings.check_interval_hours || 6,
      mirror_mode: (updateOverview.settings.mirror_mode as UpdateMirrorMode) || 'auto',
      custom_mirror_url: updateOverview.settings.custom_mirror_url || '',
      include_prerelease: Boolean(updateOverview.settings.include_prerelease),
      skipped_version: updateOverview.settings.skipped_version || '',
    });
  }, [updateOverview?.settings]);

  const handleSaveUpdateSettings = async (e: React.FormEvent) => {
    e.preventDefault();
    setSavingUpdateCfg(true);
    try {
      const res = await api.updateUpdateConfig({
        auto_check_enabled: updateForm.auto_check_enabled !== false,
        check_interval_hours: Number(updateForm.check_interval_hours) || 6,
        mirror_mode: updateForm.mirror_mode || 'auto',
        custom_mirror_url: (updateForm.custom_mirror_url || '').trim(),
        include_prerelease: Boolean(updateForm.include_prerelease),
        skipped_version: updateForm.skipped_version || '',
      });
      onUpdateOverviewChange(res.status);
      onNotify('版本检测与国内加速策略已保存');
    } catch (err: any) {
      onNotify(err?.message || '保存更新配置失败');
    } finally {
      setSavingUpdateCfg(false);
    }
  };

  const handleManualCheckUpdate = async () => {
    setCheckingUpdate(true);
    try {
      const ov = await api.checkUpdateNow(true);
      onUpdateOverviewChange(ov);
      if (ov.last_error) {
        onNotify(`检查更新失败：${ov.last_error}`);
      } else if (ov.update_available && ov.latest_release) {
        onNotify(`发现新版本 ${ov.latest_release.tag_name}`);
      } else {
        onNotify(`当前版本 (${ov.current.version}) 已是最新`);
      }
    } catch (err: any) {
      onNotify(err?.message || '检查更新失败');
    } finally {
      setCheckingUpdate(false);
    }
  };

  const handleProbeMirrors = async () => {
    setProbingMirrors(true);
    try {
      const res = await api.probeUpdateMirrors();
      onUpdateOverviewChange(res.status);
      const reachable = res.mirrors.filter((m) => m.reachable).length;
      onNotify(`线路测速完成：${reachable}/${res.mirrors.length} 条线路可用`);
    } catch (err: any) {
      onNotify(err?.message || '测速失败');
    } finally {
      setProbingMirrors(false);
    }
  };

  const handleClearSkippedVersion = async () => {
    try {
      const res = await api.skipUpdateVersion('');
      onUpdateOverviewChange(res.status);
      onNotify('已取消忽略版本，重新恢复提醒');
    } catch (err: any) {
      onNotify(err?.message || '操作失败');
    }
  };

  const handleSaveSettings = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const nextSettings: AppSettings = {
        ...settingsForm,
        remote_sync_url: syncUrl.trim() || settingsForm.remote_sync_url || '',
      };
      const res = await api.updateSettings(nextSettings);
      onSettingsChanged(res.settings);
      onNotify('会话策略与终端偏好已加密保存');
      await loadOverview();
    } catch (err: any) {
      onNotify(err?.message || '保存设置失败');
    }
  };

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (newPass.length < 8) {
      onNotify('新管理员密码长度至少需要 8 位');
      return;
    }
    if (newPass !== confirmPass) {
      onNotify('两次输入的新密码不一致');
      return;
    }
    setUpdatingPass(true);
    try {
      await api.changePassword(oldPass, newPass);
      setOldPass('');
      setNewPass('');
      setConfirmPass('');
      onNotify('管理员登录密码已更新，其他设备会话已注销（7×24 监控与巡检不受影响）');
      await loadOverview();
    } catch (err: any) {
      onNotify(err?.message || '修改管理员密码失败');
    } finally {
      setUpdatingPass(false);
    }
  };

  const handleExport = async (e: React.FormEvent) => {
    e.preventDefault();
    if (exportPass.length < 8) {
      onNotify('请设置至少 8 位的备份加密口令');
      return;
    }
    if (exportPass !== exportPassConfirm) {
      onNotify('两次输入的备份口令不一致');
      return;
    }
    setExporting(true);
    try {
      const { blob, filename } = await api.exportVaultBlob(exportPass, exportIncludeRuntime);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      setExportPass('');
      setExportPassConfirm('');
      onNotify(
        exportIncludeRuntime
          ? '已导出口令加密全量备份 (.sns)'
          : '已导出口令加密核心配置与 AI 记忆备份 (.sns)'
      );
      await loadOverview();
    } catch (err: any) {
      onNotify(err?.message || '导出加密备份失败');
    } finally {
      setExporting(false);
    }
  };

  const handleImport = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!importFile || !importPass) {
      onNotify('请选择 .sns 备份文件并输入对应的备份口令');
      return;
    }
    setImporting(true);
    try {
      const res = await api.importVault(importFile, importPass, {
        includeRuntime: importIncludeRuntime,
      });
      onSettingsChanged(res.settings);
      setImportFile(null);
      setImportPass('');
      onNotify('加密备份已校验恢复（当前管理员密码与 7×24 后台服务保持运行）');
      await loadOverview();
    } catch (err: any) {
      onNotify(err?.message || '恢复备份失败');
    } finally {
      setImporting(false);
    }
  };

  const handleSyncPush = async () => {
    if (!syncUrl.trim() || !syncRemotePass.trim()) {
      onNotify('请填写远端服务地址与远端管理员密码');
      return;
    }
    setSyncing('push');
    try {
      const { summary } = await api.syncPush(
        syncUrl.trim(),
        syncRemotePass,
        syncIncludeRuntime
      );
      setSyncRemotePass('');
      onNotify(
        `已推送至远端 (${summary.include_runtime ? '含运行数据' : '仅核心配置与 AI 记忆'} · Rev #${summary.revision}, ${formatBytes(summary.bytes)})`
      );
      await loadOverview();
    } catch (err: any) {
      onNotify(err?.message || '推送同步失败');
    } finally {
      setSyncing(null);
    }
  };

  const handleSyncPull = async () => {
    if (!syncUrl.trim() || !syncRemotePass.trim()) {
      onNotify('请填写远端服务地址与远端管理员密码');
      return;
    }
    setSyncing('pull');
    try {
      const { summary } = await api.syncPull(
        syncUrl.trim(),
        syncRemotePass,
        syncIncludeRuntime
      );
      setSyncRemotePass('');
      onNotify(
        `已从远端拉取合并 (${summary.include_runtime ? '含运行数据' : '仅核心配置与 AI 记忆'} · Rev #${summary.revision})`
      );
      await loadOverview();
    } catch (err: any) {
      onNotify(err?.message || '拉取同步失败');
    } finally {
      setSyncing(null);
    }
  };

  const handleRemoveKnownHost = async (addr: string) => {
    try {
      await api.deleteKnownHost(addr);
      onNotify(`已移除信任指纹 ${addr}`);
      await loadOverview();
    } catch (err: any) {
      onNotify(err?.message || '移除失败');
    }
  };

  const ttlDays = Math.max(1, Math.round((data?.session_ttl_hours || 168) / 24));

  return (
    <div className="workspace-surface" id="vault-security-view">
      <div className="page-header">
        <div className="page-header-title">
          <h2>安全存储、备份同步与审计中心</h2>
          <p>
            敏感凭据独立加密 (<code className="mono">secrets.enc</code>) + 高频运行态分文件防抖落盘（7×24 后台零锁定）
          </p>
        </div>
        <div className="page-header-actions">
          <button type="button" className="btn" onClick={() => void loadOverview()}>
            <RefreshCw size={14} /> 刷新状态
          </button>
          <button
            type="button"
            className="btn"
            onClick={() => void onLogoutSession()}
            title="仅退出当前浏览器会话，后台 7×24 监控与 AI 巡检不受影响"
          >
            <Lock size={14} /> 退出当前会话
          </button>
          <button
            type="button"
            className="btn btn-danger"
            onClick={() => void onRevokeAllSessions()}
            title="注销所有设备上的已登录管理会话并断开交互终端，后台 7×24 监控与巡检持续运行"
          >
            <Lock size={14} /> 注销全部设备会话
          </button>
        </div>
      </div>

      <div className="page-body">
        {loading && !data ? (
          <div className="empty-state">正在读取分层加密存储状态与审计记录...</div>
        ) : (
          <>
            {/* Split-Storage & 7x24 Decoupled Architecture Overview */}
            <section className="sec-panel" style={{ marginBottom: 18 }} id="split-storage-overview-panel">
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  flexWrap: 'wrap',
                  gap: 8,
                  marginBottom: 6,
                }}
              >
                <h3 style={{ margin: 0 }}>
                  <Database size={16} style={{ color: 'var(--accent-teal)' }} />
                  分层加密与 7×24 免锁架构状态 (v{data?.encryption.format_version || 3})
                </h3>
                <span className="tag-chip teal">
                  <Activity size={12} style={{ marginRight: 4 }} />
                  监控/巡检与加密完全解耦 · 启动自动挂载 · 永不锁定
                </span>
              </div>
              <p className="sec-panel-desc" style={{ marginBottom: 12 }}>
                SSH 密码/私钥、凭据库、AI API Key 与 Webhook 密钥独立使用{' '}
                <code className="mono">XChaCha20-Poly1305</code> 加密落盘于{' '}
                <code className="mono">secrets.enc</code>，主密钥与管理员登录密码完全解耦；高频监控时序、告警、AI 对话、巡检记录与审计日志拆分到独立普通 JSON 文件防抖持久化，采集写入绝不触发凭据重加密。本平台建议部署在内网或受控安全主机。
              </p>
              <div className="security-grid" style={{ marginBottom: 0 }}>
                <div className="kv-list">
                  <div className="kv-row">
                    <span className="kv-key">敏感凭据加密库 (secrets.enc)</span>
                    <span className="kv-val mono" style={{ color: 'var(--accent-teal)' }}>
                      {formatBytes(data?.storage?.secrets_size_bytes)} · Rev #{data?.encryption.revision ?? 1}
                    </span>
                  </div>
                  <div className="kv-row">
                    <span className="kv-key">数据加密主密钥来源</span>
                    <span className="kv-val mono" style={{ fontSize: 12 }}>
                      {data?.storage?.master_key_mode === 'env'
                        ? '环境变量 SNS_MASTER_KEY（与数据目录分离）'
                        : `本地自动密钥 ${data?.storage?.master_key_path || 'master.key'} (0600)`}
                    </span>
                  </div>
                  <div className="kv-row">
                    <span className="kv-key">加密套件与登录密码哈希</span>
                    <span className="kv-val">
                      XChaCha20-Poly1305 · Argon2id (16 MiB 轻量快速)
                    </span>
                  </div>
                </div>
                <div className="kv-list">
                  <div className="kv-row">
                    <span className="kv-key">7×24 后台监控与巡检状态</span>
                    <span className="kv-val" style={{ color: 'var(--accent-teal)', fontWeight: 550 }}>
                      {data?.daemon_running ? '持续运行中（与 Web 登录/改密完全解耦）' : '初始化中'}
                    </span>
                  </div>
                  <div className="kv-row">
                    <span className="kv-key">独立运行态分文件体积</span>
                    <span className="kv-val mono" style={{ fontSize: 12 }}>
                      监控 {formatBytes(data?.storage?.monitor_size_bytes)} · AI {formatBytes(data?.storage?.aiops_size_bytes)} · 漏洞 {formatBytes(data?.storage?.vuln_size_bytes)} · 审计 {formatBytes(data?.storage?.audit_size_bytes)}
                    </span>
                  </div>
                  <div className="kv-row">
                    <span className="kv-key">数据目录 / 活跃会话与终端</span>
                    <span className="kv-val">
                      <code className="mono" style={{ fontSize: 11.5 }}>{data?.data_dir}</code> · {data?.active_sessions ?? 1} 会话（{ttlDays} 天有效） · {data?.active_ssh_tabs ?? 0} 终端
                    </span>
                  </div>
                </div>
              </div>
            </section>

            {/* Version Auto-Detection & China-Accelerated Self-Update Panel */}
            <section className="sec-panel" style={{ marginBottom: 18 }} id="system-update-panel">
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  flexWrap: 'wrap',
                  gap: 10,
                  marginBottom: 8,
                }}
              >
                <h3 style={{ margin: 0 }}>
                  <ArrowUpCircle size={16} style={{ color: 'var(--accent-teal)' }} />
                  版本检测与国内加速自动更新
                </h3>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                  <button
                    type="button"
                    id="vault-check-update-btn"
                    className="btn btn-sm"
                    disabled={checkingUpdate}
                    onClick={() => void handleManualCheckUpdate()}
                  >
                    <RefreshCw size={13.5} className={checkingUpdate ? 'spin' : ''} />
                    {checkingUpdate ? '正在检测...' : '立即检查更新'}
                  </button>
                  <button
                    type="button"
                    id="vault-probe-mirrors-btn"
                    className="btn btn-sm"
                    disabled={probingMirrors}
                    onClick={() => void handleProbeMirrors()}
                  >
                    <Gauge size={13.5} />
                    {probingMirrors ? '测速中...' : '测试加速线路'}
                  </button>
                  <button
                    type="button"
                    className={`btn btn-sm ${updateOverview?.update_available ? 'btn-teal' : 'btn-primary'}`}
                    onClick={onOpenUpdateModal}
                  >
                    <ArrowUpCircle size={13.5} />
                    {updateOverview?.update_available && updateOverview.latest_release
                      ? `查看更新 (${updateOverview.latest_release.tag_name})`
                      : '查看版本详情'}
                  </button>
                </div>
              </div>

              <p className="sec-panel-desc" style={{ marginBottom: 12 }}>
                自动定时探测 GitHub 仓库最新 Release，并发测速官方直连与多组国内 GitHub 加速镜像自动择优；Windows 桌面版与 Linux 独立二进制支持强制{' '}
                <code className="mono">SHA256SUMS.txt</code> 校验、自检与一键自动替换重启，Docker 容器提供宿主机国内镜像升级指引。
              </p>

              <div className="security-grid" style={{ marginBottom: 14 }}>
                <div className="kv-list">
                  <div className="kv-row">
                    <span className="kv-key">当前版本 / 构建</span>
                    <span className="kv-val mono">
                      {updateOverview?.current.version || 'dev'}
                      {updateOverview?.current.commit ? ` (${updateOverview.current.commit.slice(0, 8)})` : ''}
                    </span>
                  </div>
                  <div className="kv-row">
                    <span className="kv-key">GitHub 最新版本</span>
                    <span
                      className="kv-val mono"
                      style={{
                        color: updateOverview?.update_available ? 'var(--accent-teal)' : undefined,
                        fontWeight: updateOverview?.update_available ? 600 : undefined,
                      }}
                    >
                      {updateOverview?.latest_release
                        ? `${updateOverview.latest_release.tag_name}${updateOverview.update_available ? '（有新版本）' : '（最新）'}`
                        : '尚未检测'}
                    </span>
                  </div>
                  <div className="kv-row">
                    <span className="kv-key">最近检测时间</span>
                    <span className="kv-val" style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                      {updateOverview?.last_checked_at
                        ? new Date(updateOverview.last_checked_at).toLocaleString('zh-CN')
                        : '—'}
                    </span>
                  </div>
                </div>

                <div className="kv-list">
                  <div className="kv-row">
                    <span className="kv-key">运行环境与更新方式</span>
                    <span className="kv-val" style={{ fontSize: 12.5 }}>
                      {updateOverview?.capabilities.in_docker
                        ? 'Docker 容器（检测提示 + 宿主机升级命令）'
                        : updateOverview?.capabilities.can_self_update
                          ? `支持一键自更新 (${updateOverview.capabilities.asset_name})`
                          : updateOverview?.capabilities.cannot_update_reason || '仅检测提示'}
                    </span>
                  </div>
                  <div className="kv-row">
                    <span className="kv-key">当前优选加速线路</span>
                    <span className="kv-val" style={{ fontSize: 12.5 }}>
                      <Globe size={12.5} style={{ verticalAlign: 'middle', marginRight: 5, color: 'var(--accent-teal)' }} />
                      {updateOverview?.active_mirror
                        ? `${updateOverview.active_mirror.name}${updateOverview.active_mirror.latency_ms > 0 ? ` (${updateOverview.active_mirror.latency_ms} ms)` : ''}`
                        : '等待探测'}
                    </span>
                  </div>
                  <div className="kv-row">
                    <span className="kv-key">已忽略版本</span>
                    <span className="kv-val" style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                      <span className="mono">{updateOverview?.settings.skipped_version || '无'}</span>
                      {updateOverview?.settings.skipped_version && (
                        <button
                          type="button"
                          className="btn btn-sm btn-ghost"
                          style={{ height: 22, padding: '0 6px', fontSize: 11.5 }}
                          onClick={() => void handleClearSkippedVersion()}
                        >
                          <RotateCcw size={11.5} /> 恢复提醒
                        </button>
                      )}
                    </span>
                  </div>
                </div>
              </div>

              <form onSubmit={handleSaveUpdateSettings}>
                <div className="field-row">
                  <div className="field">
                    <label className="field-label">GitHub 线路与国内加速策略</label>
                    <select
                      className="select"
                      value={updateForm.mirror_mode || 'auto'}
                      onChange={(e) =>
                        setUpdateForm({
                          ...updateForm,
                          mirror_mode: e.target.value as UpdateMirrorMode,
                        })
                      }
                    >
                      <option value="auto">自动竞速择优（推荐：并发测速官方直连与多组国内镜像）</option>
                      <option value="direct">仅使用 GitHub 官方直连</option>
                      <option value="custom">仅使用下方指定的国内加速镜像</option>
                    </select>
                  </div>

                  <div className="field">
                    <label className="field-label">后台自动检测周期</label>
                    <select
                      className="select"
                      value={updateForm.check_interval_hours || 6}
                      onChange={(e) =>
                        setUpdateForm({
                          ...updateForm,
                          check_interval_hours: Number(e.target.value) || 6,
                        })
                      }
                    >
                      <option value={1}>每 1 小时</option>
                      <option value={6}>每 6 小时（默认）</option>
                      <option value={12}>每 12 小时</option>
                      <option value={24}>每 24 小时</option>
                      <option value={72}>每 3 天</option>
                    </select>
                  </div>
                </div>

                <div className="field">
                  <label className="field-label">
                    自定义国内 GitHub 加速前缀（可选；在「自动」模式下将加入竞速池，在「指定」模式下独占使用）
                  </label>
                  <input
                    type="text"
                    className="input mono"
                    placeholder="例如 https://gh-proxy.com/ 或 https://mirror.example.cn/?u={url}"
                    value={updateForm.custom_mirror_url || ''}
                    onChange={(e) =>
                      setUpdateForm({
                        ...updateForm,
                        custom_mirror_url: e.target.value,
                      })
                    }
                  />
                  {updateOverview?.builtin_mirrors && updateOverview.builtin_mirrors.length > 0 && (
                    <div className="update-preset-row">
                      <span style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>常用国内加速预设：</span>
                      {updateOverview.builtin_mirrors
                        .filter((m) => Boolean(m.prefix))
                        .map((m) => (
                          <button
                            key={m.id}
                            type="button"
                            className={`mcp-server-chip ${updateForm.custom_mirror_url === m.prefix ? 'active' : ''}`}
                            onClick={() =>
                              setUpdateForm({
                                ...updateForm,
                                custom_mirror_url: m.prefix,
                              })
                            }
                          >
                            {m.name}
                          </button>
                        ))}
                    </div>
                  )}
                </div>

                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 18, alignItems: 'center', marginBottom: 12 }}>
                  <label
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: 7,
                      fontSize: 12.5,
                      color: 'var(--text-secondary)',
                      cursor: 'pointer',
                    }}
                  >
                    <input
                      type="checkbox"
                      checked={updateForm.auto_check_enabled !== false}
                      onChange={(e) =>
                        setUpdateForm({
                          ...updateForm,
                          auto_check_enabled: e.target.checked,
                        })
                      }
                    />
                    启用后台定时自动检测新版本
                  </label>

                  <label
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: 7,
                      fontSize: 12.5,
                      color: 'var(--text-secondary)',
                      cursor: 'pointer',
                    }}
                  >
                    <input
                      type="checkbox"
                      checked={Boolean(updateForm.include_prerelease)}
                      onChange={(e) =>
                        setUpdateForm({
                          ...updateForm,
                          include_prerelease: e.target.checked,
                        })
                      }
                    />
                    接收预发布版本 (Pre-release / RC)
                  </label>
                </div>

                <button type="submit" className="btn btn-primary" disabled={savingUpdateCfg}>
                  {savingUpdateCfg ? '正在保存更新策略...' : '保存版本检测与加速设置'}
                </button>
              </form>

              {updateOverview?.mirrors && updateOverview.mirrors.length > 0 && (
                <div style={{ marginTop: 14, overflowX: 'auto' }}>
                  <table className="data-table update-mirror-table">
                    <thead>
                      <tr>
                        <th>线路名称</th>
                        <th>区域</th>
                        <th>加速前缀</th>
                        <th>探测结果与延迟</th>
                      </tr>
                    </thead>
                    <tbody>
                      {updateOverview.mirrors.map((m) => (
                        <tr key={m.id + m.prefix}>
                          <td style={{ fontWeight: 550, whiteSpace: 'nowrap' }}>{m.name}</td>
                          <td>
                            <span className={`tag-chip ${m.region === 'cn' ? 'teal' : ''}`}>
                              {m.region === 'cn' ? '国内加速' : '官方直连'}
                            </span>
                          </td>
                          <td className="mono" style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                            {m.prefix || 'https://github.com/ (Direct)'}
                          </td>
                          <td className="mono" style={{ fontSize: 12, whiteSpace: 'nowrap' }}>
                            {m.reachable ? (
                              <span style={{ color: 'var(--accent-teal)', fontWeight: 600 }}>
                                可用 · {m.latency_ms} ms
                              </span>
                            ) : (
                              <span style={{ color: 'var(--danger-text)' }}>
                                不可用{m.error ? ` (${m.error})` : ''}
                              </span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </section>

            <div className="security-grid">
              {/* Web Session & Terminal Preferences */}
              <section className="sec-panel">
                <h3>
                  <Settings size={16} />
                  Web 会话策略与终端偏好
                </h3>
                <p className="sec-panel-desc">
                  管理控制台单次会话最长 {ttlDays} 天有效（可通过 <code className="mono">SNS_SESSION_TTL</code> 调整）；默认关闭空闲自动退出，亦可按需开启。会话过期绝不影响后台 7×24 监控与巡检。
                </p>
                <form onSubmit={handleSaveSettings}>
                  <div className="field-row">
                    <div className="field">
                      <label className="field-label">Web 控制台无操作自动退出时间</label>
                      <select
                        className="select"
                        value={settingsForm.auto_lock_minutes}
                        onChange={(e) =>
                          setSettingsForm({
                            ...settingsForm,
                            auto_lock_minutes: Number(e.target.value),
                          })
                        }
                      >
                        <option value={0}>不启用空闲退出（默认，受 {ttlDays} 天会话有效期约束）</option>
                        <option value={15}>15 分钟</option>
                        <option value={30}>30 分钟</option>
                        <option value={60}>60 分钟</option>
                        <option value={120}>120 分钟</option>
                      </select>
                    </div>
                    <div className="field">
                      <label className="field-label">终端字体大小 (px)</label>
                      <input
                        type="number"
                        className="input mono"
                        min={11}
                        max={24}
                        value={settingsForm.terminal_font_size}
                        onChange={(e) =>
                          setSettingsForm({
                            ...settingsForm,
                            terminal_font_size: Number(e.target.value) || 14,
                          })
                        }
                      />
                    </div>
                  </div>
                  <div className="field">
                    <label className="field-label">SSH 主机公钥指纹校验策略</label>
                    <select
                      className="select"
                      value={settingsForm.host_key_policy}
                      onChange={(e) =>
                        setSettingsForm({
                          ...settingsForm,
                          host_key_policy: e.target.value as 'tofu' | 'ask_new',
                        })
                      }
                    >
                      <option value="tofu">
                        首次信任固定 (TOFU)，若指纹变更立即阻断告警（推荐）
                      </option>
                      <option value="ask_new">
                        严格手动核验：首次连接任何未知主机均弹窗确认指纹
                      </option>
                    </select>
                  </div>
                  <button type="submit" className="btn btn-primary">
                    保存安全与偏好设置
                  </button>
                </form>
              </section>

              {/* Change Admin Login Password */}
              <section className="sec-panel" id="admin-password-panel">
                <h3>
                  <KeyRound size={16} />
                  修改管理员登录密码
                </h3>
                <p className="sec-panel-desc">
                  管理员密码仅用于 Web 控制台登录鉴权，与数据加密主密钥解耦。修改密码会即时注销其他设备的 Web 会话，但不会重加密凭据，也不中断后台监控与 AI 巡检。
                </p>
                <form onSubmit={handleChangePassword}>
                  <div className="field">
                    <label className="field-label">当前管理员密码</label>
                    <input
                      type="password"
                      className="input"
                      value={oldPass}
                      onChange={(e) => setOldPass(e.target.value)}
                      required
                    />
                  </div>
                  <div className="field-row">
                    <div className="field">
                      <label className="field-label">新管理员密码</label>
                      <input
                        type="password"
                        className="input"
                        value={newPass}
                        onChange={(e) => setNewPass(e.target.value)}
                        placeholder="至少 8 位"
                        required
                      />
                    </div>
                    <div className="field">
                      <label className="field-label">确认新密码</label>
                      <input
                        type="password"
                        className="input"
                        value={confirmPass}
                        onChange={(e) => setConfirmPass(e.target.value)}
                        required
                      />
                    </div>
                  </div>
                  <button type="submit" className="btn btn-primary" disabled={updatingPass}>
                    {updatingPass ? '正在更新密码哈希...' : '更新管理员登录密码'}
                  </button>
                </form>
              </section>

              {/* Portable Password-Encrypted Backup Export */}
              <section className="sec-panel" id="backup-export-panel">
                <h3>
                  <Download size={16} style={{ color: 'var(--accent-teal)' }} />
                  导出口令加密备份包 (.sns)
                </h3>
                <p className="sec-panel-desc">
                  使用您指定的临时或常用加密口令将主机凭据、密钥库、AI 供应商与 AI 记忆/Runbook 加密打包为便携 <code className="mono">.sns</code> 文件（不含本地 <code className="mono">master.key</code>），可安全跨机迁移。
                </p>
                <form onSubmit={handleExport}>
                  <div className="field-row">
                    <div className="field">
                      <label className="field-label">备份加密口令（至少 8 位）</label>
                      <input
                        id="backup-export-password"
                        type="password"
                        className="input"
                        placeholder="设置本次备份包加密口令"
                        value={exportPass}
                        onChange={(e) => setExportPass(e.target.value)}
                        required
                      />
                    </div>
                    <div className="field">
                      <label className="field-label">确认备份口令</label>
                      <input
                        id="backup-export-password-confirm"
                        type="password"
                        className="input"
                        placeholder="再次输入备份口令"
                        value={exportPassConfirm}
                        onChange={(e) => setExportPassConfirm(e.target.value)}
                        required
                      />
                    </div>
                  </div>
                  <label
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 8,
                      fontSize: 12.5,
                      color: 'var(--text-secondary)',
                      marginBottom: 12,
                      cursor: 'pointer',
                    }}
                  >
                    <input
                      type="checkbox"
                      checked={exportIncludeRuntime}
                      onChange={(e) => setExportIncludeRuntime(e.target.checked)}
                    />
                    同时打包监控历史时序、告警、AI 对话与巡检记录（取消勾选可导出极小体积核心配置包）
                  </label>
                  <button type="submit" className="btn btn-teal" disabled={exporting}>
                    <Download size={14} />
                    {exporting ? '正在加密打包 .sns...' : '导出口令加密备份 (.sns)'}
                  </button>
                </form>
              </section>

              {/* Simplified Cross-Instance Sync */}
              <section className="sec-panel" id="remote-sync-panel">
                <h3>
                  <Cloud size={16} style={{ color: 'var(--accent-teal)' }} />
                  跨端配置与记忆同步（桌面端 ↔ 服务端）
                </h3>
                <p className="sec-panel-desc">
                  通过远端管理员密码直连鉴权同步主机配置、凭据、AI 记忆与 Runbook。默认<strong>不覆盖</strong>对端正在积累的 7×24 监控历史与巡检日志。
                </p>
                <div className="field">
                  <label className="field-label">远端 ServerNeedSafe 服务地址</label>
                  <input
                    className="input mono"
                    placeholder="http://192.168.1.10:18899 或 https://sns.example.com"
                    value={syncUrl}
                    onChange={(e) => setSyncUrl(e.target.value)}
                  />
                </div>
                <div className="field">
                  <label className="field-label">远端实例管理员密码</label>
                  <input
                    type="password"
                    className="input"
                    placeholder="输入远端 ServerNeedSafe 的管理员登录密码"
                    value={syncRemotePass}
                    onChange={(e) => setSyncRemotePass(e.target.value)}
                  />
                </div>
                <label
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 8,
                    fontSize: 12.5,
                    color: 'var(--text-secondary)',
                    marginBottom: 12,
                    cursor: 'pointer',
                  }}
                >
                  <input
                    type="checkbox"
                    checked={syncIncludeRuntime}
                    onChange={(e) => setSyncIncludeRuntime(e.target.checked)}
                  />
                  同时覆盖运行态数据（监控历史、告警、AI 对话与巡检记录；默认关闭以保护服务端 7×24 历史）
                </label>
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                  <button
                    type="button"
                    className="btn btn-primary"
                    disabled={syncing !== null}
                    onClick={() => void handleSyncPush()}
                  >
                    <ArrowUpRight size={14} />
                    {syncing === 'push' ? '正在推送同步...' : '推送至远端'}
                  </button>
                  <button
                    type="button"
                    className="btn"
                    disabled={syncing !== null}
                    onClick={() => void handleSyncPull()}
                  >
                    <ArrowDownLeft size={14} />
                    {syncing === 'pull' ? '正在拉取合并...' : '从远端拉取'}
                  </button>
                </div>
              </section>

              {/* Restore Encrypted Backup */}
              <section className="sec-panel" style={{ gridColumn: '1 / -1' }}>
                <h3>
                  <Upload size={16} />
                  恢复 / 迁移加密备份包 (.sns)
                </h3>
                <p className="sec-panel-desc">
                  支持导入新版口令加密备份包及老版 <code className="mono">SNSVAULT v1 / v2</code> 备份文件；导入后保留本机管理员密码，并立即生效于后台 7×24 监控与巡检。
                </p>
                <form onSubmit={handleImport}>
                  <div className="field-row">
                    <div className="field">
                      <label className="field-label">选择 .sns 加密备份文件</label>
                      <input
                        type="file"
                        accept=".sns,application/octet-stream"
                        className="input"
                        style={{ paddingTop: 6 }}
                        onChange={(e) => setImportFile(e.target.files?.[0] || null)}
                      />
                    </div>
                    <div className="field">
                      <label className="field-label">备份包加密口令</label>
                      <input
                        type="password"
                        className="input"
                        value={importPass}
                        onChange={(e) => setImportPass(e.target.value)}
                        placeholder="导出备份时设置的加密口令（老备份填原密码）"
                      />
                    </div>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
                    <label
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 8,
                        fontSize: 12.5,
                        color: 'var(--text-secondary)',
                        cursor: 'pointer',
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={importIncludeRuntime}
                        onChange={(e) => setImportIncludeRuntime(e.target.checked)}
                      />
                      同时恢复备份中的监控历史、告警与 AI 对话/巡检记录
                    </label>
                    <button type="submit" className="btn" disabled={importing}>
                      <Upload size={14} />
                      {importing ? '正在解密校验并导入...' : '验证口令并恢复数据'}
                    </button>
                  </div>
                </form>
              </section>
            </div>

            {/* Trusted KnownHosts Table */}
            <section className="sec-panel" style={{ marginBottom: 18 }}>
              <h3>
                <Fingerprint size={16} />
                已信任固定的 SSH 主机指纹 ({data?.known_hosts?.length || 0})
              </h3>
              <p className="sec-panel-desc">
                主机公钥指纹加密保存在 <code className="mono">secrets.enc</code> 内，每次 SSH 终端、SFTP、状态采集与 AI 巡检握手时强制校验，阻断中间人劫持。
              </p>
              <div style={{ overflowX: 'auto' }}>
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>主机名称</th>
                      <th>地址端口</th>
                      <th>密钥类型</th>
                      <th>SHA-256 指纹</th>
                      <th>最近核验时间</th>
                      <th style={{ textAlign: 'right' }}>操作</th>
                    </tr>
                  </thead>
                  <tbody>
                    {!data?.known_hosts?.length ? (
                      <tr>
                        <td
                          colSpan={6}
                          style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 20 }}
                        >
                          暂无固定的主机指纹记录，首次连接服务器时将自动记录
                        </td>
                      </tr>
                    ) : (
                      data.known_hosts.map((kh) => (
                        <tr key={kh.address}>
                          <td style={{ fontWeight: 550, whiteSpace: 'nowrap' }}>{kh.server_name}</td>
                          <td className="mono" style={{ whiteSpace: 'nowrap' }}>{kh.address}</td>
                          <td className="mono" style={{ whiteSpace: 'nowrap' }}>{kh.key_type}</td>
                          <td className="mono" style={{ fontSize: 12, color: 'var(--accent-teal)', whiteSpace: 'nowrap' }}>
                            {kh.fingerprint}
                          </td>
                          <td style={{ color: 'var(--text-muted)', fontSize: 12, whiteSpace: 'nowrap' }}>
                            {new Date(kh.last_verified_at).toLocaleString('zh-CN')}
                          </td>
                          <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                            <button
                              type="button"
                              className="btn btn-ghost btn-sm btn-icon"
                              style={{ color: 'var(--danger-text)' }}
                              onClick={() => void handleRemoveKnownHost(kh.address)}
                              title="移除该信任记录"
                            >
                              <Trash2 size={14} />
                            </button>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </section>

            {/* Security Audit Logs */}
            <section className="sec-panel">
              <h3>
                <FileClock size={16} />
                操作与安全审计日志 (最近 {data?.audit_logs?.length || 0} 条)
              </h3>
              <p className="sec-panel-desc">
                登录鉴权、密码修改、主机与凭据变更、SSH/SFTP、巡检与备份同步操作独立写入{' '}
                <code className="mono">audit_logs.json</code> 防抖持久化，不干扰敏感资产加密库。
              </p>
              <div style={{ maxHeight: 320, overflowY: 'auto', overflowX: 'auto', WebkitOverflowScrolling: 'touch' }}>
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>时间</th>
                      <th>事件类型</th>
                      <th>操作对象</th>
                      <th>详情说明</th>
                      <th>来源 IP</th>
                    </tr>
                  </thead>
                  <tbody>
                    {!data?.audit_logs?.length ? (
                      <tr>
                        <td colSpan={5} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 20 }}>
                          <ShieldCheck size={14} style={{ verticalAlign: 'middle', marginRight: 6 }} />
                          暂无审计记录
                        </td>
                      </tr>
                    ) : (
                      data.audit_logs.map((log) => (
                        <tr key={log.id}>
                          <td
                            className="mono"
                            style={{ fontSize: 12, whiteSpace: 'nowrap', color: 'var(--text-muted)' }}
                          >
                            {new Date(log.timestamp).toLocaleString('zh-CN')}
                          </td>
                          <td>
                            <span className={`tag-chip ${log.success ? 'teal' : 'amber'}`}>
                              {log.action}
                            </span>
                          </td>
                          <td className="mono" style={{ fontSize: 12 }}>
                            {log.target || '—'}
                          </td>
                          <td style={{ fontSize: 12.5 }}>{log.detail}</td>
                          <td className="mono" style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                            {log.client_ip || '127.0.0.1'}
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </section>
          </>
        )}
      </div>
    </div>
  );
};

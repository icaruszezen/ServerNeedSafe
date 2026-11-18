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
  Cpu,
  Sliders,
} from 'lucide-react';
import { api } from '../api';
import type { AppSettings, VaultSecurityOverview } from '../types';

interface VaultSecurityProps {
  onSettingsChanged: (s: AppSettings) => void;
  onLogoutSession: () => Promise<void>;
  onRevokeAllSessions: () => Promise<void>;
  onNotify: (msg: string) => void;
}

const KDF_PROFILES = [
  {
    memoryKiB: 16384,
    time: 2,
    threads: 2,
    label: '16 MiB · 极速轻量档（低配云主机 / 快速验证）',
  },
  {
    memoryKiB: 32768,
    time: 3,
    threads: 4,
    label: '32 MiB · 均衡档（兼顾低内存与高抗暴力破解）',
  },
  {
    memoryKiB: 65536,
    time: 3,
    threads: 4,
    label: '64 MiB · 标准安全档（默认推荐，Go 原生 ~45ms）',
  },
  {
    memoryKiB: 131072,
    time: 4,
    threads: 4,
    label: '128 MiB · 金融级高强抗 GPU 爆破档',
  },
];

export const VaultSecurity: React.FC<VaultSecurityProps> = ({
  onSettingsChanged,
  onLogoutSession,
  onRevokeAllSessions,
  onNotify,
}) => {
  const [data, setData] = useState<VaultSecurityOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [settingsForm, setSettingsForm] = useState<AppSettings>({
    auto_lock_minutes: 30,
    host_key_policy: 'tofu',
    terminal_font_size: 14,
    terminal_scrollback: 5000,
    show_hidden_files: true,
    remote_sync_url: '',
  });

  // Argon2id KDF Profile Tuning
  const [selectedKdfMem, setSelectedKdfMem] = useState<number>(65536);
  const [kdfPassword, setKdfPassword] = useState('');
  const [updatingKdf, setUpdatingKdf] = useState(false);

  // Password Rotation
  const [oldPass, setOldPass] = useState('');
  const [newPass, setNewPass] = useState('');
  const [confirmPass, setConfirmPass] = useState('');
  const [rotating, setRotating] = useState(false);

  // Import Backup
  const [importFile, setImportFile] = useState<File | null>(null);
  const [importPass, setImportPass] = useState('');
  const [importCurrentPass, setImportCurrentPass] = useState('');
  const [importing, setImporting] = useState(false);

  // Remote Cloud Sync
  const [syncUrl, setSyncUrl] = useState('');
  const [syncRemotePass, setSyncRemotePass] = useState('');
  const [syncLocalPass, setSyncLocalPass] = useState('');
  const [syncing, setSyncing] = useState<'push' | 'pull' | null>(null);

  const loadOverview = useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.getVaultSecurity();
      setData(res);
      setSettingsForm(res.settings);
      if (res.encryption?.kdf_memory_kib) {
        setSelectedKdfMem(res.encryption.kdf_memory_kib);
      }
      setSyncUrl((prev) => prev || res.settings.remote_sync_url || '');
    } catch (err: any) {
      onNotify(err?.message || '读取安全中心状态失败');
    } finally {
      setLoading(false);
    }
  }, [onNotify]);

  useEffect(() => {
    void loadOverview();
  }, [loadOverview]);

  const handleSaveSettings = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const nextSettings: AppSettings = {
        ...settingsForm,
        remote_sync_url: syncUrl.trim() || settingsForm.remote_sync_url || '',
      };
      const res = await api.updateSettings(nextSettings);
      onSettingsChanged(res.settings);
      onNotify('会话超时策略与终端偏好已加密保存');
      await loadOverview();
    } catch (err: any) {
      onNotify(err?.message || '保存设置失败');
    }
  };

  const handleUpdateKdf = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!kdfPassword) {
      onNotify('请输入当前管理员密码以验证并重封装密钥');
      return;
    }
    const profile =
      KDF_PROFILES.find((p) => p.memoryKiB === selectedKdfMem) || KDF_PROFILES[2];
    setUpdatingKdf(true);
    try {
      await api.updateVaultKDF({
        password: kdfPassword,
        kdf_memory_kib: profile.memoryKiB,
        kdf_time: profile.time,
        kdf_threads: profile.threads,
      });
      setKdfPassword('');
      onNotify(
        `已切换 Argon2id 强度至 ${Math.round(profile.memoryKiB / 1024)} MiB 并同步更新自动挂载密钥`
      );
      await loadOverview();
    } catch (err: any) {
      onNotify(err?.message || '调整 Argon2id 档位失败');
    } finally {
      setUpdatingKdf(false);
    }
  };

  const handleRotatePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (newPass.length < 8) {
      onNotify('新管理员密码长度至少需要 8 位');
      return;
    }
    if (newPass !== confirmPass) {
      onNotify('两次输入的新密码不一致');
      return;
    }
    setRotating(true);
    try {
      await api.changePassword(oldPass, newPass);
      setOldPass('');
      setNewPass('');
      setConfirmPass('');
      onNotify('管理员主密码、DEK 与 .vault.key 已完成原子轮换，其他设备会话已注销');
      await loadOverview();
    } catch (err: any) {
      onNotify(err?.message || '修改管理员密码失败');
    } finally {
      setRotating(false);
    }
  };

  const handleExport = async () => {
    try {
      const { blob, filename } = await api.exportVaultBlob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      onNotify('已导出纯密码保护加密备份包 (.sns)');
    } catch (err: any) {
      onNotify(err?.message || '导出失败');
    }
  };

  const handleImport = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!importFile || !importPass) {
      onNotify('请选择 .sns 备份文件并输入对应密码');
      return;
    }
    setImporting(true);
    try {
      const res = await api.importVault(importFile, importPass, {
        currentAdminPassword: importCurrentPass || undefined,
        clearAnchor: true,
      });
      onSettingsChanged(res.settings);
      setImportFile(null);
      setImportPass('');
      setImportCurrentPass('');
      onNotify('加密备份已校验恢复并自动更新 7×24 挂载密钥');
      await loadOverview();
    } catch (err: any) {
      onNotify(err?.message || '恢复备份失败');
    } finally {
      setImporting(false);
    }
  };

  const handleSyncPush = async () => {
    if (!syncUrl.trim()) {
      onNotify('请输入远端同步服务地址 (例如 https://vault.example.com)');
      return;
    }
    setSyncing('push');
    try {
      const { summary } = await api.syncPush(syncUrl.trim(), syncRemotePass);
      setSyncRemotePass('');
      onNotify(
        `已推送加密容器至远端 (Rev #${summary.revision}, ${(summary.bytes / 1024).toFixed(1)} KB)`
      );
      await loadOverview();
    } catch (err: any) {
      onNotify(err?.message || '推送密文同步失败');
    } finally {
      setSyncing(null);
    }
  };

  const handleSyncPull = async () => {
    if (!syncUrl.trim()) {
      onNotify('请输入远端同步服务地址');
      return;
    }
    setSyncing('pull');
    try {
      const { summary } = await api.syncPull(syncUrl.trim(), syncRemotePass, syncLocalPass);
      setSyncRemotePass('');
      setSyncLocalPass('');
      onNotify(`已从远端拉取并合并加密容器 (Rev #${summary.revision})`);
      await loadOverview();
    } catch (err: any) {
      onNotify(err?.message || '从远端拉取密文失败');
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

  return (
    <div className="workspace-surface" id="vault-security-view">
      <div className="page-header">
        <div className="page-header-title">
          <h2>安全保险库、密钥档位与审计中心</h2>
          <p>
            XChaCha20-Poly1305 落盘加密 (<code className="mono">vault.sns</code>) + 7×24 守护进程自动挂载密钥 (
            <code className="mono">.vault.key</code>)
          </p>
        </div>
        <div className="page-header-actions">
          <button type="button" className="btn" onClick={() => void loadOverview()}>
            <RefreshCw size={14} /> 刷新状态
          </button>
          <button type="button" className="btn btn-teal" onClick={() => void handleExport()}>
            <Download size={14} /> 导出加密备份 (.sns)
          </button>
          <button
            type="button"
            className="btn"
            onClick={() => void onLogoutSession()}
            title="仅退出当前浏览器会话，后台 7×24 监控与 AI 巡检保持运行"
          >
            <Lock size={14} /> 锁定当前会话
          </button>
          <button
            type="button"
            className="btn btn-danger"
            onClick={() => void onRevokeAllSessions()}
            title="注销所有设备上的已登录管理会话，后台 7×24 守护继续运行"
          >
            <Lock size={14} /> 注销全部设备会话
          </button>
        </div>
      </div>

      <div className="page-body">
        {loading && !data ? (
          <div className="empty-state">正在读取保险库加密元数据与审计记录...</div>
        ) : (
          <>
            {/* Dual-Key Encrypted Storage & 7x24 Daemon Overview Banner */}
            <section className="sec-panel" style={{ marginBottom: 18 }} id="zk-isolation-proof-panel">
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
                  <Cpu size={16} style={{ color: 'var(--accent-teal)' }} />
                  7×24 守护加密架构状态 (SNSVAULT v{data?.encryption.format_version || 2})
                </h3>
                <span className="tag-chip teal">
                  重启 &lt;1ms 自动挂载 · HttpOnly 安全会话 · 备份纯密码封装
                </span>
              </div>
              <p className="sec-panel-desc" style={{ marginBottom: 12 }}>
                <code className="mono">vault.sns</code> 全程使用管理员密码派生的 KEK 与 XChaCha20-Poly1305 加密；本地{' '}
                <code className="mono">0600</code> 权限的 <code className="mono">.vault.key</code>（或环境变量{' '}
                <code className="mono">SNS_MASTER_KEY</code>）支撑容器重启无感恢复 7×24 监控与巡检，且绝不进入导出的{' '}
                <code className="mono">.sns</code> 备份文件。
              </p>
              <div className="security-grid" style={{ marginBottom: 0 }}>
                <div className="kv-list">
                  <div className="kv-row">
                    <span className="kv-key">保险库唯一标识 (Vault ID)</span>
                    <span className="kv-val mono" style={{ fontSize: 12 }}>
                      {data?.encryption.vault_id || '—'}
                    </span>
                  </div>
                  <div className="kv-row">
                    <span className="kv-key">加密容器路径 / 版本号</span>
                    <span className="kv-val mono" style={{ color: 'var(--accent-teal)' }}>
                      {data?.vault_path} · Rev #{data?.encryption.revision ?? 1}
                    </span>
                  </div>
                  <div className="kv-row">
                    <span className="kv-key">Ed25519 签名公钥指纹</span>
                    <span className="kv-val mono" style={{ fontSize: 11.5 }}>
                      {data?.encryption.auth_pubkey_sha256
                        ? `${data.encryption.auth_pubkey_sha256.slice(0, 24)}…`
                        : '—'}
                    </span>
                  </div>
                </div>
                <div className="kv-list">
                  <div className="kv-row">
                    <span className="kv-key">7×24 自动挂载密钥状态</span>
                    <span className="kv-val mono" style={{ fontSize: 11.5, color: 'var(--accent-teal)' }}>
                      {data?.auto_unlock_enabled
                        ? `已就绪 (${data.key_seal_path || '.vault.key'})`
                        : '待生成'}
                    </span>
                  </div>
                  {data?.auto_unlock_enabled && data?.auto_unlock_mode && (
                    <div className="kv-row">
                      <span className="kv-key">自动挂载密钥封装方式</span>
                      <span
                        className="kv-val"
                        style={{
                          fontSize: 12,
                          color: data.auto_unlock_mode === 'env' ? 'var(--accent-teal)' : 'var(--amber-text)',
                        }}
                        title={
                          data.auto_unlock_mode === 'env'
                            ? '.vault.key 仅含密文，解封主密钥来自进程环境变量 SNS_MASTER_KEY'
                            : '解封主密钥与 DEK 同存于 .vault.key，仅受 0600 文件权限保护：数据目录整体泄露即可解密保险库'
                        }
                      >
                        {data.auto_unlock_mode === 'env'
                          ? '外部主密钥 SNS_MASTER_KEY（与数据目录分离）'
                          : '⚠ 文件内主密钥（数据目录泄露即可解密，建议配置 SNS_MASTER_KEY）'}
                      </span>
                    </div>
                  )}
                  <div className="kv-row">
                    <span className="kv-key">密码学套件 (KDF / AEAD)</span>
                    <span className="kv-val">
                      Argon2id ({Math.round((data?.encryption.kdf_memory_kib || 65536) / 1024)} MiB /{' '}
                      {data?.encryption.kdf_time || 3} 轮) · XChaCha20-Poly1305
                    </span>
                  </div>
                  <div className="kv-row">
                    <span className="kv-key">存储体积 / 活跃会话与终端</span>
                    <span className="kv-val">
                      {((data?.encryption.vault_size_bytes || 0) / 1024).toFixed(1)} KB ·{' '}
                      {data?.active_sessions ?? 1} 个管理会话 · {data?.active_ssh_tabs ?? 0} 个活跃终端
                    </span>
                  </div>
                </div>
              </div>
            </section>

            <div className="security-grid">
              {/* Security Policy Settings */}
              <section className="sec-panel">
                <h3>
                  <Settings size={16} />
                  Web 会话安全策略与终端偏好
                </h3>
                <p className="sec-panel-desc">
                  管理控制台单次会话最长 8 小时有效；空闲超时仅自动注销浏览器会话，不会中断后台 7×24 监控与 AI 定时巡检。
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
                        <option value={5}>5 分钟（高敏感环境）</option>
                        <option value={15}>15 分钟</option>
                        <option value={30}>30 分钟（默认推荐）</option>
                        <option value={60}>60 分钟</option>
                        <option value={0}>不启用空闲锁定（仅受 8h 会话上限约束）</option>
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

              {/* Argon2id KDF Strength Selector */}
              <section className="sec-panel" id="vault-kdf-tuning-panel">
                <h3>
                  <Sliders size={16} style={{ color: 'var(--accent-teal)' }} />
                  Argon2id 密钥派生强度档位调节
                </h3>
                <p className="sec-panel-desc">
                  调整密码登录及导出备份包 <code className="mono">.sns</code> 的抗离线暴力破解强度。Go 原生多线程下{' '}
                  <code className="mono">64 MiB</code> 仅需约 45ms。
                </p>
                <form onSubmit={handleUpdateKdf}>
                  <div className="field">
                    <label className="field-label">选择 Argon2id 内存与迭代档位</label>
                    <select
                      id="kdf-profile-select"
                      className="select"
                      value={selectedKdfMem}
                      onChange={(e) => setSelectedKdfMem(Number(e.target.value))}
                    >
                      {KDF_PROFILES.map((p) => (
                        <option key={p.memoryKiB} value={p.memoryKiB}>
                          {p.label}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div className="field">
                    <label className="field-label">输入当前管理员密码以重封装容器</label>
                    <input
                      id="kdf-password-input"
                      type="password"
                      className="input"
                      placeholder="验证当前管理员密码后立即生效"
                      value={kdfPassword}
                      onChange={(e) => setKdfPassword(e.target.value)}
                      required
                    />
                  </div>
                  <button type="submit" className="btn btn-primary" disabled={updatingKdf}>
                    {updatingKdf ? '正在重派生并原子更新密钥...' : '应用 Argon2id 强度档位'}
                  </button>
                </form>
              </section>

              {/* Rotate Master Password */}
              <section className="sec-panel">
                <h3>
                  <KeyRound size={16} />
                  轮换管理员主密码与加密主密钥
                </h3>
                <p className="sec-panel-desc">
                  重新生成 256 位随机盐、全新 DEK 与 Ed25519 签名密钥对，同步更新 <code className="mono">vault.sns</code> 与{' '}
                  <code className="mono">.vault.key</code> 并自动踢出其他会话。
                </p>
                <form onSubmit={handleRotatePassword}>
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
                  <button type="submit" className="btn btn-primary" disabled={rotating}>
                    {rotating ? '正在重加密整个保险库...' : '更新密码并轮换全部密钥'}
                  </button>
                </form>
              </section>

              {/* Remote Cloud Sync */}
              <section className="sec-panel" id="zk-remote-sync-panel">
                <h3>
                  <Cloud size={16} style={{ color: 'var(--accent-teal)' }} />
                  跨端加密密文云同步
                </h3>
                <p className="sec-panel-desc">
                  在本地 Windows 桌面端与远端 <code className="mono">sns-server</code> 之间同步经过 Ed25519 签名的{' '}
                  <code className="mono">SNSVAULT v2</code> 加密容器。
                </p>
                <div className="field">
                  <label className="field-label">远端 ServerNeedSafe 服务地址</label>
                  <input
                    className="input mono"
                    placeholder="https://sns.example.com"
                    value={syncUrl}
                    onChange={(e) => setSyncUrl(e.target.value)}
                  />
                </div>
                <div className="field-row">
                  <div className="field">
                    <label className="field-label">远端保险库密码（推送同源库可留空，拉取必填）</label>
                    <input
                      type="password"
                      className="input"
                      placeholder="输入远端加密保险库密码"
                      value={syncRemotePass}
                      onChange={(e) => setSyncRemotePass(e.target.value)}
                    />
                  </div>
                  <div className="field">
                    <label className="field-label">本地原密码（仅拉取覆盖不同密码库时填）</label>
                    <input
                      type="password"
                      className="input"
                      placeholder="可选覆盖授权密码"
                      value={syncLocalPass}
                      onChange={(e) => setSyncLocalPass(e.target.value)}
                    />
                  </div>
                </div>
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                  <button
                    type="button"
                    className="btn btn-primary"
                    disabled={syncing !== null}
                    onClick={() => void handleSyncPush()}
                  >
                    <ArrowUpRight size={14} />
                    {syncing === 'push' ? '正在推送加密容器...' : '推送密文至远端'}
                  </button>
                  <button
                    type="button"
                    className="btn"
                    disabled={syncing !== null}
                    onClick={() => void handleSyncPull()}
                  >
                    <ArrowDownLeft size={14} />
                    {syncing === 'pull' ? '正在拉取并合并...' : '从远端拉取合并'}
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
                  支持在 Docker 服务端与 Windows 桌面端之间无缝迁移纯密码保护的 <code className="mono">.sns</code> 备份包（兼容 v1 / v2 格式），导入后自动刷新本地守护挂载密钥。
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
                      <label className="field-label">备份包对应的管理员密码</label>
                      <input
                        type="password"
                        className="input"
                        value={importPass}
                        onChange={(e) => setImportPass(e.target.value)}
                        placeholder="备份创建时的管理员密码"
                      />
                    </div>
                    <div className="field">
                      <label className="field-label">当前库原密码（密码相同时留空）</label>
                      <input
                        type="password"
                        className="input"
                        value={importCurrentPass}
                        onChange={(e) => setImportCurrentPass(e.target.value)}
                        placeholder="跨密码覆盖校验"
                      />
                    </div>
                  </div>
                  <button type="submit" className="btn" disabled={importing}>
                    <Upload size={14} />
                    {importing ? '正在解密校验并导入...' : '验证密码并导入覆盖'}
                  </button>
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
                主机公钥指纹加密保存在 <code className="mono">vault.sns</code> 内，每次 SSH 终端、SFTP、状态采集与 AI 巡检握手时强制校验，阻断中间人劫持。
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
                          <td style={{ fontWeight: 550 }}>{kh.server_name}</td>
                          <td className="mono">{kh.address}</td>
                          <td className="mono">{kh.key_type}</td>
                          <td className="mono" style={{ fontSize: 12, color: 'var(--accent-teal)' }}>
                            {kh.fingerprint}
                          </td>
                          <td style={{ color: 'var(--text-muted)', fontSize: 12 }}>
                            {new Date(kh.last_verified_at).toLocaleString('zh-CN')}
                          </td>
                          <td style={{ textAlign: 'right' }}>
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

            {/* Encrypted Security Audit Logs */}
            <section className="sec-panel">
              <h3>
                <FileClock size={16} />
                加密安全审计日志 (最近 {data?.audit_logs?.length || 0} 条)
              </h3>
              <p className="sec-panel-desc">
                登录鉴权、密码与 KDF 轮换、SSH/SFTP 操作与备份导出均使用 XChaCha20-Poly1305 随保险库加密落盘。
              </p>
              <div style={{ maxHeight: 320, overflowY: 'auto' }}>
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
                    {(data?.audit_logs || []).map((log) => (
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
                    ))}
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

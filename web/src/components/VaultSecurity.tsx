import React, { useCallback, useEffect, useState } from 'react';
import {
  ShieldCheck,
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
} from 'lucide-react';
import { api } from '../api';
import { zkClient, type WasmIntegrityState } from '../zk/zkClient';
import type { AppSettings, VaultSecurityOverview } from '../types';

interface VaultSecurityProps {
  onSettingsChanged: (s: AppSettings) => void;
  onLockVault: () => Promise<void>;
  onNotify: (msg: string) => void;
}

export const VaultSecurity: React.FC<VaultSecurityProps> = ({
  onSettingsChanged,
  onLockVault,
  onNotify,
}) => {
  const [data, setData] = useState<VaultSecurityOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [wasmIntegrity, setWasmIntegrity] = useState<WasmIntegrityState>(() =>
    zkClient.getIntegrityState()
  );
  const [settingsForm, setSettingsForm] = useState<AppSettings>({
    auto_lock_minutes: 30,
    host_key_policy: 'tofu',
    terminal_font_size: 14,
    terminal_scrollback: 5000,
    show_hidden_files: true,
    remote_sync_url: '',
  });

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

  // Remote Zero-Knowledge Cloud Sync
  const [syncUrl, setSyncUrl] = useState('');
  const [syncRemotePass, setSyncRemotePass] = useState('');
  const [syncLocalPass, setSyncLocalPass] = useState('');
  const [syncing, setSyncing] = useState<'push' | 'pull' | null>(null);

  useEffect(() => {
    return zkClient.subscribeIntegrity(setWasmIntegrity);
  }, []);

  const loadOverview = useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.getVaultSecurity();
      setData(res);
      setSettingsForm(res.settings);
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
      onNotify('安全策略与偏好设置已在客户端加密并同步');
      await loadOverview();
    } catch (err: any) {
      onNotify(err?.message || '保存设置失败');
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
      onNotify('管理员密码已在客户端完成重派生，DEK 与 Ed25519 密钥对已原子轮换');
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
      onNotify('已导出零知识加密数据包 (.sns)');
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
      onNotify('加密备份已在客户端校验并恢复');
      await loadOverview();
    } catch (err: any) {
      onNotify(err?.message || '恢复备份失败');
    } finally {
      setImporting(false);
    }
  };

  const handleSyncPush = async () => {
    if (!syncUrl.trim()) {
      onNotify('请输入远端零知识同步服务地址 (例如 https://vault.example.com)');
      return;
    }
    setSyncing('push');
    try {
      const { summary } = await api.syncPush(syncUrl.trim(), syncRemotePass);
      setSyncRemotePass('');
      onNotify(`已零知识推送密文至远端 (Rev #${summary.revision}, ${(summary.bytes / 1024).toFixed(1)} KB)`);
      await loadOverview();
    } catch (err: any) {
      onNotify(err?.message || '推送密文同步失败');
    } finally {
      setSyncing(null);
    }
  };

  const handleSyncPull = async () => {
    if (!syncUrl.trim()) {
      onNotify('请输入远端零知识同步服务地址');
      return;
    }
    setSyncing('pull');
    try {
      const { summary } = await api.syncPull(syncUrl.trim(), syncRemotePass, syncLocalPass);
      setSyncRemotePass('');
      setSyncLocalPass('');
      onNotify(`已从远端拉取并在本地解密合并 (Rev #${summary.revision})`);
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
          <h2>零知识安全保险库与隔离审计中心</h2>
          <p>
            客户端 Web Worker WASM 端到端加密 · 即使部署服务器 root 权限沦陷亦无法获取任何应用数据
          </p>
        </div>
        <div className="page-header-actions">
          <button type="button" className="btn" onClick={() => void loadOverview()}>
            <RefreshCw size={14} /> 刷新状态
          </button>
          <button type="button" className="btn btn-teal" onClick={() => void handleExport()}>
            <Download size={14} /> 导出加密数据包 (.sns)
          </button>
          <button type="button" className="btn btn-danger" onClick={() => void onLockVault()}>
            <Lock size={14} /> 立即销毁内存并锁定
          </button>
        </div>
      </div>

      <div className="page-body">
        {loading && !data ? (
          <div className="empty-state">正在从客户端 WASM 加密区读取安全元数据...</div>
        ) : (
          <>
            {/* Zero-Knowledge Root-Breach Isolation Proof Banner */}
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
                  零知识抗服务器 Root 泄露隔离证明 (SNSVAULT v{data?.encryption.format_version || 2})
                </h3>
                <span className="tag-chip teal">
                  服务端零明文 · 服务端零密钥 · 端到端 SSHv2/SFTP
                </span>
              </div>
              <p className="sec-panel-desc" style={{ marginBottom: 12 }}>
                所有密码派生 (Argon2id)、载荷加解密 (XChaCha20-Poly1305) 与 SSH/SFTP 协议栈均在浏览器独立进程沙箱中执行；服务端仅存储盲密文并转发加密字节流。
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
                    <span className="kv-key">单调递增防回滚版本号</span>
                    <span className="kv-val mono" style={{ color: 'var(--accent-teal)' }}>
                      Revision #{data?.encryption.revision ?? 1}（本地锚点 #{data?.anchor?.min_revision ?? 1}）
                    </span>
                  </div>
                  <div className="kv-row">
                    <span className="kv-key">Ed25519 零知识认证公钥指纹</span>
                    <span className="kv-val mono" style={{ fontSize: 11.5 }}>
                      {data?.encryption.auth_pubkey_sha256
                        ? `${data.encryption.auth_pubkey_sha256.slice(0, 24)}…`
                        : '—'}
                    </span>
                  </div>
                </div>
                <div className="kv-list">
                  <div className="kv-row">
                    <span className="kv-key">客户端 WASM 引擎自校验</span>
                    <span className="kv-val mono" style={{ fontSize: 11.5, color: 'var(--accent-teal)' }}>
                      {wasmIntegrity.verified
                        ? `SHA-256 已验证 (${wasmIntegrity.sha256.slice(0, 16)}…)`
                        : '运行中'}
                    </span>
                  </div>
                  <div className="kv-row">
                    <span className="kv-key">密码学套件 (KDF / AEAD)</span>
                    <span className="kv-val">
                      Argon2id ({Math.round((data?.encryption.kdf_memory_kib || 65536) / 1024)} MiB) · XChaCha20 + 4KiB 填充
                    </span>
                  </div>
                  <div className="kv-row">
                    <span className="kv-key">盲存储体积 / 活跃盲 TCP 隧道</span>
                    <span className="kv-val">
                      {((data?.encryption.vault_size_bytes || 0) / 1024).toFixed(1)} KB · {data?.active_relays ?? 0} 条加密流
                    </span>
                  </div>
                </div>
              </div>
            </section>

            <div className="security-grid">
              {/* Remote Zero-Knowledge Vault Sync */}
              <section className="sec-panel" id="zk-remote-sync-panel">
                <h3>
                  <Cloud size={16} style={{ color: 'var(--accent-teal)' }} />
                  跨端零知识密文云同步
                </h3>
                <p className="sec-panel-desc">
                  在本地桌面端与远端 <code className="mono">sns-server</code> 之间同步盲密文容器；远端服务器全程无密钥，仅做签名核验与密文托管。
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
                    {syncing === 'push' ? '正在推送盲密文...' : '推送密文至远端'}
                  </button>
                  <button
                    type="button"
                    className="btn"
                    disabled={syncing !== null}
                    onClick={() => void handleSyncPull()}
                  >
                    <ArrowDownLeft size={14} />
                    {syncing === 'pull' ? '正在拉取并本地合并...' : '从远端拉取合并'}
                  </button>
                </div>
              </section>

              {/* Security Policy Settings */}
              <section className="sec-panel">
                <h3>
                  <Settings size={16} />
                  安全策略与终端偏好
                </h3>
                <p className="sec-panel-desc">
                  配置客户端空闲自动销毁 Web Worker 内存策略与 SSH 主机密钥校验级别。
                </p>
                <form onSubmit={handleSaveSettings}>
                  <div className="field-row">
                    <div className="field">
                      <label className="field-label">无操作自动销毁内存并锁定 (分钟)</label>
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
                        <option value={5}>5 分钟（极高安全）</option>
                        <option value={15}>15 分钟</option>
                        <option value={30}>30 分钟（推荐）</option>
                        <option value={60}>60 分钟</option>
                        <option value={0}>从不自动锁定</option>
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
                    加密保存策略设置
                  </button>
                </form>
              </section>

              {/* Rotate Master Password */}
              <section className="sec-panel">
                <h3>
                  <KeyRound size={16} />
                  轮换管理员主密码与认证密钥对
                </h3>
                <p className="sec-panel-desc">
                  在客户端重新生成 256 位随机盐、全新 DEK 与全新 Ed25519 认证密钥对，并使用新旧双签名完成服务端原子切换。
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
                    {rotating ? '正在客户端重加密整个保险库...' : '更新密码并轮换全部密钥'}
                  </button>
                </form>
              </section>

              {/* Restore Encrypted Backup */}
              <section className="sec-panel">
                <h3>
                  <Upload size={16} />
                  恢复 / 迁移加密备份包 (.sns)
                </h3>
                <p className="sec-panel-desc">
                  支持在 Docker 服务端与 Windows 纯本地桌面端之间无缝迁移，自动将旧版 v1 备份升级为 v2 零知识容器。
                </p>
                <form onSubmit={handleImport}>
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
                  <div className="field-row">
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
                        placeholder="跨密码覆盖时授权签名"
                      />
                    </div>
                  </div>
                  <button type="submit" className="btn" disabled={importing}>
                    <Upload size={14} />
                    {importing ? '正在客户端解密校验并导入...' : '本地验证并导入覆盖'}
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
                主机公钥指纹加密保存在零知识保险库内，由客户端 WASM 在每次 SSH 握手时直接校验，彻底杜绝服务端或网络中间人劫持。
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
                        <td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 20 }}>
                          暂无固定的主机指纹记录，首次端到端连接服务器时将自动记录
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
                零知识加密安全审计日志 (最近 {data?.audit_logs?.length || 0} 条)
              </h3>
              <p className="sec-panel-desc">
                审计日志在客户端生成并随整个保险库使用 XChaCha20-Poly1305 全量加密，部署服务器磁盘与 stdout 日志中不留任何主机 IP、用户名或操作痕迹。
              </p>
              <div style={{ maxHeight: 320, overflowY: 'auto' }}>
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>时间</th>
                      <th>事件类型</th>
                      <th>操作对象</th>
                      <th>详情说明</th>
                      <th>执行上下文</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(data?.audit_logs || []).map((log) => (
                      <tr key={log.id}>
                        <td className="mono" style={{ fontSize: 12, whiteSpace: 'nowrap', color: 'var(--text-muted)' }}>
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
                          {log.client_ip || 'client-zk'}
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

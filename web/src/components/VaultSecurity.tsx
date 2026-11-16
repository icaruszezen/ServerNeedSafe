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
} from 'lucide-react';
import { api, setSessionToken } from '../api';
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
  const [settingsForm, setSettingsForm] = useState<AppSettings>({
    auto_lock_minutes: 30,
    host_key_policy: 'tofu',
    terminal_font_size: 14,
    terminal_scrollback: 5000,
    show_hidden_files: true,
  });

  // Password Rotation
  const [oldPass, setOldPass] = useState('');
  const [newPass, setNewPass] = useState('');
  const [confirmPass, setConfirmPass] = useState('');
  const [rotating, setRotating] = useState(false);

  // Import Backup
  const [importFile, setImportFile] = useState<File | null>(null);
  const [importPass, setImportPass] = useState('');
  const [importing, setImporting] = useState(false);

  const loadOverview = useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.getVaultSecurity();
      setData(res);
      setSettingsForm(res.settings);
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
      const res = await api.updateSettings(settingsForm);
      onSettingsChanged(res.settings);
      onNotify('安全策略与偏好设置已加密保存');
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
      const res = await api.changePassword(oldPass, newPass);
      setSessionToken(res.token);
      setOldPass('');
      setNewPass('');
      setConfirmPass('');
      onNotify('管理员密码已更新，主密钥已完成轮换重加密');
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
      onNotify('已导出全量加密备份包 (.sns)');
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
      const res = await api.importVault(importFile, importPass);
      setSessionToken(res.token);
      onSettingsChanged(res.settings);
      setImportFile(null);
      setImportPass('');
      onNotify('加密备份已成功校验并恢复');
      await loadOverview();
    } catch (err: any) {
      onNotify(err?.message || '恢复备份失败');
    } finally {
      setImporting(false);
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
          <h2>安全保险库与加密审计中心</h2>
          <p>零知识全量加密存储架构 · 密钥仅驻留内存并在锁定时立即清零擦除</p>
        </div>
        <div className="page-header-actions">
          <button type="button" className="btn" onClick={() => void loadOverview()}>
            <RefreshCw size={14} /> 刷新状态
          </button>
          <button type="button" className="btn btn-teal" onClick={() => void handleExport()}>
            <Download size={14} /> 导出加密数据包 (.sns)
          </button>
          <button type="button" className="btn btn-danger" onClick={() => void onLockVault()}>
            <Lock size={14} /> 立即锁定保险库
          </button>
        </div>
      </div>

      <div className="page-body">
        {loading && !data ? (
          <div className="empty-state">正在加载加密保险库安全元数据...</div>
        ) : (
          <>
            <div className="security-grid">
              {/* Cryptographic Engine Spec */}
              <section className="sec-panel">
                <h3>
                  <ShieldCheck size={16} style={{ color: 'var(--accent-teal)' }} />
                  加密存储引擎状态
                </h3>
                <p className="sec-panel-desc">
                  所有服务器 IP、账号、SSH 私钥、快捷指令与审计日志均封装在单一 AEAD 认证加密容器中。
                </p>
                <div className="kv-list">
                  <div className="kv-row">
                    <span className="kv-key">运行模式</span>
                    <span className="kv-val">
                      {data?.deploy_mode === 'desktop' ? 'Windows 本地独立桌面应用' : 'Docker / Web 服务端部署'}
                    </span>
                  </div>
                  <div className="kv-row">
                    <span className="kv-key">密钥派生算法 (KDF)</span>
                    <span className="kv-val">
                      Argon2id ({Math.round((data?.encryption.kdf_memory_kib || 65536) / 1024)} MiB, t=
                      {data?.encryption.kdf_time}, p={data?.encryption.kdf_threads})
                    </span>
                  </div>
                  <div className="kv-row">
                    <span className="kv-key">主密钥信封封装</span>
                    <span className="kv-val">AES-256-GCM (256-bit DEK)</span>
                  </div>
                  <div className="kv-row">
                    <span className="kv-key">全量载荷加密算法</span>
                    <span className="kv-val">XChaCha20-Poly1305 + 4KiB 随机填充</span>
                  </div>
                  <div className="kv-row">
                    <span className="kv-key">加密容器体积</span>
                    <span className="kv-val">
                      {((data?.encryption.vault_size_bytes || 0) / 1024).toFixed(1)} KB
                    </span>
                  </div>
                  <div className="kv-row">
                    <span className="kv-key">加密文件路径</span>
                    <span className="kv-val" style={{ fontSize: 11.5 }}>
                      {data?.vault_path}
                    </span>
                  </div>
                </div>
              </section>

              {/* Security Policy Settings */}
              <section className="sec-panel">
                <h3>
                  <Settings size={16} />
                  安全策略与终端偏好
                </h3>
                <p className="sec-panel-desc">配置空闲自动锁定内存擦除策略与 SSH 主机密钥校验级别。</p>
                <form onSubmit={handleSaveSettings}>
                  <div className="field-row">
                    <div className="field">
                      <label className="field-label">无操作自动锁定 (分钟)</label>
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
                    保存策略设置
                  </button>
                </form>
              </section>

              {/* Rotate Master Password */}
              <section className="sec-panel">
                <h3>
                  <KeyRound size={16} />
                  轮换管理员主密码
                </h3>
                <p className="sec-panel-desc">
                  修改密码将重新生成随机盐与全新 256 位数据主密钥 (DEK)，并对整个数据包原子重加密。
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
                    {rotating ? '正在重加密整个保险库...' : '更新密码并轮换密钥'}
                  </button>
                </form>
              </section>

              {/* Restore Encrypted Backup */}
              <section className="sec-panel">
                <h3>
                  <Upload size={16} />
                  恢复 / 迁移加密备份包
                </h3>
                <p className="sec-panel-desc">
                  支持在 Docker 服务端与 Windows 本地桌面应用之间无缝迁移 <code className="mono">.sns</code> 加密数据包。
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
                  <div className="field">
                    <label className="field-label">备份包对应的管理员密码</label>
                    <input
                      type="password"
                      className="input"
                      value={importPass}
                      onChange={(e) => setImportPass(e.target.value)}
                      placeholder="输入备份创建时的管理员密码"
                    />
                  </div>
                  <button type="submit" className="btn" disabled={importing}>
                    <Upload size={14} />
                    {importing ? '正在解密校验并导入...' : '验证并导入覆盖'}
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
                用于防范 SSH 中间人劫持攻击。若远程服务器重装系统导致公钥变更，可在此移除旧指纹记录。
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
                所有审计轨迹均加密保存在保险库内部，外部系统日志不记录敏感主机 IP 或账号信息。
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
                          {log.client_ip || 'local'}
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

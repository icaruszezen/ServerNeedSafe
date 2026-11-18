import React, { useState } from 'react';
import {
  ShieldCheck,
  Lock,
  Eye,
  EyeOff,
  Upload,
  Server,
  Monitor,
  AlertCircle,
  KeyRound,
  Activity,
} from 'lucide-react';
import { api, ApiError } from '../api';
import type { AppSettings, AuthStatusResponse } from '../types';

interface AuthGateProps {
  status: AuthStatusResponse;
  onAuthenticated: (settings?: AppSettings, updatedStatus?: AuthStatusResponse) => void;
  theme: 'light' | 'dark';
  onToggleTheme: () => void;
}

function calcPasswordStrength(pw: string): { level: number; label: string } {
  if (!pw) return { level: 0, label: '' };
  let score = 0;
  if (pw.length >= 8) score++;
  if (pw.length >= 12) score++;
  if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) score++;
  if (/\d/.test(pw) && /[^A-Za-z0-9]/.test(pw)) score++;
  const labels = ['弱', '偏弱（建议至少 8 位）', '中等', '强', '极强'];
  return { level: Math.max(1, score), label: labels[Math.max(1, score)] };
}

export const AuthGate: React.FC<AuthGateProps> = ({
  status,
  onAuthenticated,
  theme,
  onToggleTheme,
}) => {
  const isSetup = status.vault_status === 'uninitialized';
  const serverHasVault = Boolean(status.initialized) || status.vault_status === 'locked';

  const [tab, setTab] = useState<'primary' | 'restore'>('primary');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [currentAdminPassword, setCurrentAdminPassword] = useState('');
  const [showPass, setShowPass] = useState(false);
  const [capsLock, setCapsLock] = useState(false);
  const [restoreFile, setRestoreFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const strength = calcPasswordStrength(password);

  const handleKeyEvent = (e: React.KeyboardEvent) => {
    if (e.getModifierState) {
      setCapsLock(e.getModifierState('CapsLock'));
    }
  };

  const handleSubmitPrimary = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (isSetup) {
      if (password.length < 8) {
        setError('管理员密码长度至少需要 8 位字符');
        return;
      }
      if (password !== confirmPassword) {
        setError('两次输入的管理员密码不一致');
        return;
      }
    } else if (!password) {
      setError('请输入管理员密码');
      return;
    }

    setLoading(true);
    try {
      const res = isSetup
        ? await api.setupVault(password)
        : await api.loginVault(password);
      setPassword('');
      setConfirmPassword('');
      onAuthenticated(res.settings, res.status);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError('身份验证失败，请检查管理员密码或网络连接');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleSubmitRestore = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    if (!restoreFile) {
      setError('请选择 .sns 加密备份文件');
      return;
    }
    if (!password) {
      setError('请输入该备份包对应的管理员密码');
      return;
    }
    setLoading(true);
    try {
      const res = await api.importVault(restoreFile, password, {
        currentAdminPassword: currentAdminPassword || undefined,
        clearAnchor: true,
      });
      setPassword('');
      setCurrentAdminPassword('');
      onAuthenticated(res.settings, res.status);
    } catch (err: any) {
      setError(err?.message || '解密恢复失败，请确认管理员密码是否正确');
    } finally {
      setLoading(false);
    }
  };

  const memMiB = Math.round((status.encryption?.kdf_memory_kib || 65536) / 1024);

  return (
    <main className="auth-viewport">
      <div className="auth-card" id="auth-gate-card">
        <div className="auth-brand">
          <div className="auth-logo">
            <ShieldCheck size={22} />
          </div>
          <div className="auth-brand-text" style={{ flex: 1 }}>
            <h1>ServerNeedSafe</h1>
            <span>多服务器加密运维终端 · 7×24 状态监控与 AI 智能巡检守护</span>
          </div>
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            onClick={onToggleTheme}
            id="auth-theme-toggle-btn"
            title="切换浅色/深色外观"
          >
            {theme === 'light' ? '深色' : '浅色'}
          </button>
        </div>

        <div className="auth-spec-strip" style={{ flexWrap: 'wrap', gap: 6 }}>
          <span className="auth-spec-badge">
            <Lock size={13} />
            Argon2id ({memMiB} MiB) · XChaCha20-Poly1305
          </span>
          {!isSetup && (
            <span
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 4,
                color: status.daemon_running ? 'var(--accent-teal)' : 'var(--amber-text)',
                fontSize: 11.5,
                fontWeight: 550,
              }}
            >
              <Activity size={13} />
              {status.daemon_running
                ? '7×24 后台监控与巡检运行中'
                : '待首次密码升级挂载 (.vault.key)'}
            </span>
          )}
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
            {status.deploy_mode === 'desktop' ? (
              <>
                <Monitor size={13} /> 本地桌面端
              </>
            ) : (
              <>
                <Server size={13} /> 服务端守护模式
              </>
            )}
          </span>
        </div>

        {status.migration_pending && (
          <div
            style={{
              marginBottom: 14,
              padding: '10px 13px',
              borderRadius: 'var(--radius-sm)',
              background: 'var(--accent-teal-soft)',
              border: '1px solid var(--accent-teal-border)',
              color: 'var(--accent-teal)',
              fontSize: 12.5,
              lineHeight: 1.55,
            }}
          >
            <strong>检测到现有 SNSVAULT v2 加密库 · 首次登录自动升级 7×24 守护挂载</strong>
            <div style={{ color: 'var(--text-secondary)', marginTop: 2 }}>
              验证一次管理员密码后，系统将自动生成严格权限 (<code className="mono">0600</code>) 的本地自动挂载密钥{' '}
              <code className="mono">.vault.key</code>，后续服务重启无需人工干预即可立即恢复 7×24 监控与定时巡检。
            </div>
          </div>
        )}

        <div className="auth-mode-switch">
          <button
            type="button"
            id="auth-tab-primary"
            className={`auth-mode-btn ${tab === 'primary' ? 'active' : ''}`}
            onClick={() => {
              setTab('primary');
              setError('');
            }}
          >
            {isSetup ? '初始化加密保险库' : '登录 Web 管理控制台'}
          </button>
          <button
            type="button"
            id="auth-tab-restore"
            className={`auth-mode-btn ${tab === 'restore' ? 'active' : ''}`}
            onClick={() => {
              setTab('restore');
              setError('');
            }}
          >
            从加密备份恢复
          </button>
        </div>

        {error && (
          <div className="alert alert-error" role="alert">
            <AlertCircle size={16} style={{ flexShrink: 0, marginTop: 1 }} />
            <span>{error}</span>
          </div>
        )}

        {tab === 'primary' ? (
          <form onSubmit={handleSubmitPrimary} id="auth-primary-form">
            <div className="field">
              <label className="field-label" htmlFor="admin-password-input">
                <span>{isSetup ? '设置管理员主密码' : '输入管理员密码'}</span>
                {capsLock && (
                  <span style={{ color: 'var(--amber-text)', fontSize: 11.5 }}>
                    大写锁定已开启
                  </span>
                )}
              </label>
              <div className="input-with-icon">
                <span className="input-icon-left">
                  <KeyRound size={15} />
                </span>
                <input
                  id="admin-password-input"
                  className="input"
                  type={showPass ? 'text' : 'password'}
                  placeholder={
                    isSetup
                      ? '至少 8 位字符，用于加密保险库及登录管理后台'
                      : '输入管理员密码登录控制台'
                  }
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  onKeyUp={handleKeyEvent}
                  onKeyDown={handleKeyEvent}
                  autoFocus
                  autoComplete={isSetup ? 'new-password' : 'current-password'}
                  style={{ paddingRight: 38 }}
                />
                <span className="input-icon-right">
                  <button
                    type="button"
                    className="btn btn-ghost btn-sm btn-icon"
                    onClick={() => setShowPass(!showPass)}
                    tabIndex={-1}
                    aria-label="显示或隐藏密码"
                  >
                    {showPass ? <EyeOff size={15} /> : <Eye size={15} />}
                  </button>
                </span>
              </div>

              {isSetup && password && (
                <>
                  <div className="strength-meter">
                    {[1, 2, 3, 4].map((idx) => (
                      <div
                        key={idx}
                        className={`strength-bar ${
                          idx <= strength.level ? `level-${strength.level}` : ''
                        }`}
                      />
                    ))}
                  </div>
                  <span className="field-hint">密码强度：{strength.label}</span>
                </>
              )}
            </div>

            {isSetup && (
              <div className="field">
                <label className="field-label" htmlFor="admin-password-confirm">
                  确认管理员主密码
                </label>
                <div className="input-with-icon">
                  <span className="input-icon-left">
                    <Lock size={15} />
                  </span>
                  <input
                    id="admin-password-confirm"
                    className="input"
                    type={showPass ? 'text' : 'password'}
                    placeholder="再次输入管理员主密码"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    autoComplete="new-password"
                  />
                </div>
              </div>
            )}

            <button
              type="submit"
              id="auth-submit-btn"
              className="btn btn-primary btn-block"
              disabled={loading}
              style={{ marginTop: 6 }}
            >
              {loading
                ? '正在校验密码并签发安全会话...'
                : isSetup
                ? '创建加密保险库并启动 7×24 守护'
                : '验证密码并进入控制台'}
            </button>
          </form>
        ) : (
          <form onSubmit={handleSubmitRestore} id="auth-restore-form">
            <div className="field">
              <label className="field-label" htmlFor="restore-file-input">
                选择加密数据包 (.sns，兼容 v1 / v2 格式)
              </label>
              <input
                id="restore-file-input"
                type="file"
                accept=".sns,application/octet-stream"
                className="input"
                style={{ paddingTop: 6 }}
                onChange={(e) => setRestoreFile(e.target.files?.[0] || null)}
              />
            </div>

            <div className="field">
              <label className="field-label" htmlFor="restore-password-input">
                该备份包的管理员密码
              </label>
              <input
                id="restore-password-input"
                type="password"
                className="input"
                placeholder="输入备份创建时的管理员密码"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>

            {serverHasVault && (
              <div className="field">
                <label className="field-label" htmlFor="restore-current-password-input">
                  当前服务器原管理员密码（若与备份密码一致可留空）
                </label>
                <input
                  id="restore-current-password-input"
                  type="password"
                  className="input"
                  placeholder="用于校验覆盖权限，防止未授权替换"
                  value={currentAdminPassword}
                  onChange={(e) => setCurrentAdminPassword(e.target.value)}
                />
              </div>
            )}

            <button
              type="submit"
              id="auth-restore-btn"
              className="btn btn-primary btn-block"
              disabled={loading}
            >
              <Upload size={15} />
              {loading ? '正在解密校验并挂载备份...' : '验证密码并恢复保险库'}
            </button>
          </form>
        )}

        <div className="auth-footer-note">
          <strong>双层加密存储与 7×24 守护说明：</strong>
          主机凭据、SSH 私钥、监控时序与审计日志全程使用 <code className="mono">XChaCha20-Poly1305</code> 加密保存在{' '}
          <code className="mono">vault.sns</code> 中；未登录访客无法读取任何主机元数据。导出备份{' '}
          <code className="mono">.sns</code> 仅含纯密码封装密文，跨机迁移安全无损。
        </div>
      </div>
    </main>
  );
};

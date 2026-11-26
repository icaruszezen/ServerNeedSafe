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
  const [restoreIncludeRuntime, setRestoreIncludeRuntime] = useState(true);
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
      setError('请输入该备份包对应的加密口令');
      return;
    }
    setLoading(true);
    try {
      const res = await api.importVault(restoreFile, password, {
        currentAdminPassword: currentAdminPassword || undefined,
        includeRuntime: restoreIncludeRuntime,
      });
      setPassword('');
      setCurrentAdminPassword('');
      onAuthenticated(res.settings, res.status);
    } catch (err: any) {
      setError(err?.message || '解密恢复失败，请确认备份口令是否正确');
    } finally {
      setLoading(false);
    }
  };

  const ttlDays = Math.max(1, Math.round((status.session_ttl_hours || 168) / 24));

  return (
    <main className="auth-viewport">
      <div className="auth-card" id="auth-gate-card">
        <div className="auth-brand">
          <div className="auth-logo">
            <ShieldCheck size={22} />
          </div>
          <div className="auth-brand-text" style={{ flex: 1 }}>
            <h1>ServerNeedSafe</h1>
            <span>多服务器安全运维终端 · 7×24 状态监控与 AI 智能巡检</span>
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
            XChaCha20-Poly1305 凭据加密 · 运行态独立持久化
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
                : '检测到旧版加密库，登录一次即自动迁移'}
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

        {status.legacy_migration_pending && (
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
            <strong>检测到旧版 vault.sns · 首次登录自动升级至免锁分层存储</strong>
            <div style={{ color: 'var(--text-secondary)', marginTop: 2 }}>
              验证一次原管理员密码后，系统将自动拆分迁移为独立加密的{' '}
              <code className="mono">secrets.enc</code> 与非加密运行态文件，此后进程重启即刻启动 7×24 监控与巡检，不再需要人工解锁。
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
            {isSetup ? '初始化管理员密码' : '登录管理控制台'}
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
                <span>{isSetup ? '设置管理员登录密码' : '输入管理员密码'}</span>
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
                      ? '至少 8 位字符，仅用于 Web 管理后台登录鉴权'
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
                  确认管理员密码
                </label>
                <div className="input-with-icon">
                  <span className="input-icon-left">
                    <Lock size={15} />
                  </span>
                  <input
                    id="admin-password-confirm"
                    className="input"
                    type={showPass ? 'text' : 'password'}
                    placeholder="再次输入管理员密码"
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
                ? '正在验证并签发安全会话...'
                : isSetup
                ? '完成初始化并进入工作台'
                : '登录进入管理控制台'}
            </button>
          </form>
        ) : (
          <form onSubmit={handleSubmitRestore} id="auth-restore-form">
            <div className="field">
              <label className="field-label" htmlFor="restore-file-input">
                选择加密备份文件 (.sns，兼容 v1 / v2 / v3 格式)
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
                备份加密口令
              </label>
              <input
                id="restore-password-input"
                type="password"
                className="input"
                placeholder="输入导出备份时设置的加密口令"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>

            {serverHasVault && (
              <div className="field">
                <label className="field-label" htmlFor="restore-current-password-input">
                  当前服务器管理员密码（若与备份口令一致可留空）
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

            <label
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                fontSize: 12.5,
                color: 'var(--text-secondary)',
                marginBottom: 14,
                cursor: 'pointer',
              }}
            >
              <input
                type="checkbox"
                checked={restoreIncludeRuntime}
                onChange={(e) => setRestoreIncludeRuntime(e.target.checked)}
              />
              同时恢复备份中的监控历史、告警与 AI 对话/巡检记录（如有）
            </label>

            <button
              type="submit"
              id="auth-restore-btn"
              className="btn btn-primary btn-block"
              disabled={loading}
            >
              <Upload size={15} />
              {loading ? '正在解密校验并恢复数据...' : '验证口令并恢复备份'}
            </button>
          </form>
        )}

        <div className="auth-footer-note">
          <strong>分层加密与内网可信部署说明：</strong>
          主机 SSH 密码/私钥、凭据库、AI API Key 与 Webhook 密钥经独立本地密钥加密保存于{' '}
          <code className="mono">secrets.enc</code>，与登录密码彻底解耦；监控时序、巡检记录与审计独立持久化，保障 7×24 后台任务零锁定、零中断（单次登录会话默认有效 {ttlDays} 天）。建议部署于内网或受控安全主机。
        </div>
      </div>
    </main>
  );
};

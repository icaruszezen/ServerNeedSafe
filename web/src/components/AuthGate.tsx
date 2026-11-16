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
} from 'lucide-react';
import { api, ApiError, setSessionToken } from '../api';
import type { AppSettings, AuthStatusResponse } from '../types';

interface AuthGateProps {
  status: AuthStatusResponse;
  onAuthenticated: (settings?: AppSettings) => void;
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
  const [tab, setTab] = useState<'primary' | 'restore'>('primary');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
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
        : await api.unlockVault(password);
      setSessionToken(res.token);
      setPassword('');
      setConfirmPassword('');
      onAuthenticated(res.settings);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError('验证失败，请检查服务连接状态');
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
      const res = await api.importVault(restoreFile, password);
      setSessionToken(res.token);
      setPassword('');
      onAuthenticated(res.settings);
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
            <span>多服务器安全管理与零知识加密保险库</span>
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

        <div className="auth-spec-strip">
          <span className="auth-spec-badge">
            <Lock size={13} />
            Argon2id ({memMiB} MiB) · XChaCha20-Poly1305
          </span>
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
            {status.deploy_mode === 'desktop' ? (
              <>
                <Monitor size={13} /> 本地桌面端
              </>
            ) : (
              <>
                <Server size={13} /> Web 服务端
              </>
            )}
          </span>
        </div>

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
            {isSetup ? '初始化管理员密码' : '验证管理员密码'}
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
                  placeholder={isSetup ? '至少 8 位字符，建议包含大小写、数字与符号' : '请输入管理员密码以解锁加密数据'}
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
                ? '正在派生密钥并校验加密容器...'
                : isSetup
                ? '创建加密保险库并进入系统'
                : '验证密码并解锁进入'}
            </button>
          </form>
        ) : (
          <form onSubmit={handleSubmitRestore} id="auth-restore-form">
            <div className="field">
              <label className="field-label" htmlFor="restore-file-input">
                选择加密数据包 (.sns)
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

            <button
              type="submit"
              id="auth-restore-btn"
              className="btn btn-primary btn-block"
              disabled={loading}
            >
              <Upload size={15} />
              {loading ? '正在验证并解密恢复...' : '验证并恢复保险库'}
            </button>
          </form>
        )}

        <div className="auth-footer-note">
          {isSetup ? (
            <>
              <strong>零知识安全声明：</strong>
              主密钥由管理员密码实时通过 Argon2id 派生，磁盘不存储任何密码哈希或明文密钥。请务必牢记管理员密码，遗忘后任何人都无法恢复加密数据。
            </>
          ) : (
            <>
              所有服务器地址、SSH 私钥、口令与操作记录均使用全量认证加密存储。即使数据包文件泄露，未持有管理员密码的攻击者也无法读取任何应用数据。
            </>
          )}
        </div>
      </div>
    </main>
  );
};

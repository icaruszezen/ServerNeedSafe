import React, { useEffect, useState } from 'react';
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
  Cpu,
  AlertTriangle,
} from 'lucide-react';
import { api, ApiError } from '../api';
import { zkClient, type WasmIntegrityState } from '../zk/zkClient';
import type { AppSettings, AuthStatusResponse } from '../types';

interface AuthGateProps {
  status: AuthStatusResponse;
  screenLocked?: boolean;
  onSealVault?: () => Promise<void>;
  onAuthenticated: (settings?: AppSettings, updatedStatus?: AuthStatusResponse) => void;
  onRefreshStatus?: () => Promise<void>;
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
  screenLocked = false,
  onSealVault,
  onAuthenticated,
  onRefreshStatus,
  theme,
  onToggleTheme,
}) => {
  const isSetup = !screenLocked && status.vault_status === 'uninitialized';
  const serverHasVault = screenLocked || Boolean(status.initialized) || status.vault_status === 'locked';

  const [tab, setTab] = useState<'primary' | 'restore'>('primary');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [currentAdminPassword, setCurrentAdminPassword] = useState('');
  const [clearAnchorOnRestore, setClearAnchorOnRestore] = useState(false);
  const [showPass, setShowPass] = useState(false);
  const [capsLock, setCapsLock] = useState(false);
  const [restoreFile, setRestoreFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [wasmIntegrity, setWasmIntegrity] = useState<WasmIntegrityState>(() =>
    zkClient.getIntegrityState()
  );

  useEffect(() => {
    return zkClient.subscribeIntegrity(setWasmIntegrity);
  }, []);

  const strength = calcPasswordStrength(password);

  const handleKeyEvent = (e: React.KeyboardEvent) => {
    if (e.getModifierState) {
      setCapsLock(e.getModifierState('CapsLock'));
    }
  };

  const handleClearAnchor = async () => {
    setError('');
    await api.clearLocalAnchor();
    await onRefreshStatus?.();
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
        : screenLocked
        ? await api.verifyUnlockPassword(password)
        : await api.unlockVault(password);
      setPassword('');
      setConfirmPassword('');
      onAuthenticated(res.settings, res.status);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError('客户端零知识验证失败，请检查管理员密码或服务状态');
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
        clearAnchor: clearAnchorOnRestore,
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
  const unexpectedWipeDetected = isSetup && Boolean(status.anchor?.vault_id);

  return (
    <main className="auth-viewport">
      <div className="auth-card" id="auth-gate-card">
        <div className="auth-brand">
          <div className="auth-logo">
            <ShieldCheck size={22} />
          </div>
          <div className="auth-brand-text" style={{ flex: 1 }}>
            <h1>ServerNeedSafe</h1>
            <span>客户端零知识端到端加密 (E2EE) · 抗服务器 Root 泄露架构</span>
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
            Argon2id ({memMiB} MiB) · XChaCha20-Poly1305 · Ed25519
          </span>
          <span
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 4,
              color: wasmIntegrity.verified ? 'var(--accent-teal)' : 'var(--text-muted)',
              fontSize: 11.5,
            }}
            title={
              wasmIntegrity.sha256
                ? `WASM SHA-256: ${wasmIntegrity.sha256}`
                : '客户端密码学 WASM 模块自检'
            }
          >
            <Cpu size={13} />
            {wasmIntegrity.verified
              ? `WASM 哈希已自检 (${wasmIntegrity.sha256.slice(0, 8)}…)`
              : 'WASM 零知识引擎就绪'}
          </span>
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
            {status.deploy_mode === 'desktop' ? (
              <>
                <Monitor size={13} /> 本地桌面端
              </>
            ) : (
              <>
                <Server size={13} /> 零知识服务端
              </>
            )}
          </span>
        </div>

        {screenLocked && (
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
            <strong>界面已安全锁定 · WASM 零知识隔离后台持续值守中</strong>
            <div style={{ color: 'var(--text-secondary)', marginTop: 2 }}>
              已打开的 SSH 终端会话、状态监控采集{status.patrol_enabled ? '与 AI 定时安全巡检' : ''}在独立 Web Worker 内存中保持运行；输入管理员密码即可无损恢复工作台。
            </div>
          </div>
        )}

        {unexpectedWipeDetected && (
          <div
            className="alert alert-error"
            role="alert"
            style={{ flexDirection: 'column', alignItems: 'flex-start', gap: 8 }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontWeight: 600 }}>
              <AlertTriangle size={15} />
              <span>防抹除 / 防回滚安全锚点告警</span>
            </div>
            <div style={{ fontSize: 12.5, lineHeight: 1.5 }}>
              当前浏览器曾锚定加密库 <code className="mono">{status.anchor?.vault_id}</code>（版本{' '}
              <code className="mono">#{status.anchor?.min_revision}</code>），但服务端目前处于未初始化状态。为防止被入侵的服务器诱导您重新输入密码，客户端已自动拦截。若这是您主动重置环境，请先确认清除本地锚点。
            </div>
            <button
              type="button"
              className="btn btn-sm"
              onClick={() => void handleClearAnchor()}
            >
              确认系本人重置服务，清除本地防回滚锚点
            </button>
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
            {isSetup
              ? '初始化零知识保险库'
              : screenLocked
              ? '验证密码恢复工作台'
              : '客户端解密并解锁'}
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
                <span>{isSetup ? '设置管理员主密码（仅在本地派生，绝不上传）' : '输入管理员密码（仅在本地 WASM 解密）'}</span>
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
                      ? '至少 8 位字符，建议包含大小写、数字与符号'
                      : '在本地派生 KEK 解密保险库并完成零知识挑战签名'
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
              disabled={loading || unexpectedWipeDetected}
              style={{ marginTop: 6 }}
            >
              {loading
                ? '正在客户端 WASM 派生密钥并验证签名...'
                : isSetup
                ? '在本地生成加密容器并初始化系统'
                : screenLocked
                ? '验证密码并恢复工作台'
                : '零知识挑战签名并本地解密进入'}
            </button>

            {screenLocked && onSealVault && (
              <button
                type="button"
                id="auth-seal-vault-btn"
                className="btn btn-danger btn-block"
                disabled={loading}
                style={{ marginTop: 8 }}
                onClick={() => void onSealVault()}
              >
                <Lock size={14} /> 彻底封存保险库（销毁 WASM 内存并停止后台巡检）
              </button>
            )}
          </form>
        ) : (
          <form onSubmit={handleSubmitRestore} id="auth-restore-form">
            <div className="field">
              <label className="field-label" htmlFor="restore-file-input">
                选择加密数据包 (.sns，自动兼容 v1 / v2 格式)
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
                placeholder="输入备份创建时的管理员密码（本地解密校验）"
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
                  placeholder="用于生成 Ed25519 覆盖授权签名，防止未授权篡改"
                  value={currentAdminPassword}
                  onChange={(e) => setCurrentAdminPassword(e.target.value)}
                />
              </div>
            )}

            {status.anchor?.vault_id && (
              <label
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 8,
                  fontSize: 12.5,
                  color: 'var(--text-muted)',
                  marginBottom: 12,
                  cursor: 'pointer',
                }}
              >
                <input
                  type="checkbox"
                  checked={clearAnchorOnRestore}
                  onChange={(e) => setClearAnchorOnRestore(e.target.checked)}
                />
                允许替换为全新 Vault ID（重置本地防回滚锚点）
              </label>
            )}

            <button
              type="submit"
              id="auth-restore-btn"
              className="btn btn-primary btn-block"
              disabled={loading}
            >
              <Upload size={15} />
              {loading ? '正在客户端本地解密升级并签名上传...' : '本地解密校验并恢复保险库'}
            </button>
          </form>
        )}

        <div className="auth-footer-note">
          <strong>零知识抗服务器 Root 泄露保证：</strong>
          管理员密码、主密钥 (DEK/KEK)、SSH 私钥与终端/SFTP 明文<strong>绝不离开浏览器独立 Web Worker WASM 内存</strong>。服务端仅存储盲密文容器并验证 Ed25519 零知识挑战签名——即使部署服务器的{' '}
          <code className="mono">root</code> 权限完全沦陷，攻击者在不知道管理员密码的情况下也无法获取任何应用数据。
        </div>
      </div>
    </main>
  );
};

import React, { useRef, useState } from 'react';
import {
  KeyRound,
  Plus,
  Sparkles,
  Copy,
  Send,
  Trash2,
  Lock,
  X,
  Check,
  Upload,
  FileText,
} from 'lucide-react';
import { api } from '../api';
import type { CredentialView, ServerView } from '../types';
import { PrivateKeyField } from './PrivateKeyField';
import {
  readPublicKeyFile,
  type ParsedPrivateKeyFile,
  type ParsedPublicKeyFile,
} from '../utils/sshKeyFile';
import { copyTextToClipboard } from '../utils/clipboard';

interface KeychainManagerProps {
  credentials: CredentialView[];
  servers: ServerView[];
  onRefresh: () => Promise<void>;
  onNotify: (msg: string) => void;
}

export const KeychainManager: React.FC<KeychainManagerProps> = ({
  credentials,
  servers,
  onRefresh,
  onNotify,
}) => {
  const [addModalOpen, setAddModalOpen] = useState(false);
  const [genModalOpen, setGenModalOpen] = useState(false);
  const [deployTargetCred, setDeployTargetCred] = useState<CredentialView | null>(null);
  const [deployServerId, setDeployServerId] = useState('');
  const [deploying, setDeploying] = useState(false);
  const [copiedId, setCopiedId] = useState('');

  // Manual / File Import Credential Form
  const [name, setName] = useState('');
  const [kind, setKind] = useState<'private_key' | 'password'>('private_key');
  const [usernameHint, setUsernameHint] = useState('root');
  const [password, setPassword] = useState('');
  const [privateKey, setPrivateKey] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [publicKey, setPublicKey] = useState('');
  const [notes, setNotes] = useState('');
  const [uploadedPrivKey, setUploadedPrivKey] = useState<ParsedPrivateKeyFile | null>(null);
  const [uploadedPubKey, setUploadedPubKey] = useState<ParsedPublicKeyFile | null>(null);
  const [pubFileError, setPubFileError] = useState('');
  const pubFileInputRef = useRef<HTMLInputElement | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  // Key Generator Form
  const [genAlgo, setGenAlgo] = useState<'ed25519' | 'rsa-4096'>('ed25519');
  const [genSaveName, setGenSaveName] = useState('');
  const [genComment, setGenComment] = useState('sns-admin@secops');
  const [genPassphrase, setGenPassphrase] = useState('');
  const [generating, setGenerating] = useState(false);

  const openImportModal = () => {
    setName('');
    setKind('private_key');
    setUsernameHint('root');
    setPassword('');
    setPrivateKey('');
    setPassphrase('');
    setPublicKey('');
    setNotes('');
    setUploadedPrivKey(null);
    setUploadedPubKey(null);
    setPubFileError('');
    setError('');
    setAddModalOpen(true);
  };

  const handleSelectPubFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = '';
    if (!file) return;
    setPubFileError('');
    try {
      const parsed = await readPublicKeyFile(file);
      setUploadedPubKey(parsed);
      setPublicKey(parsed.content);
    } catch (err: any) {
      setPubFileError(err?.message || '读取公钥文件失败');
    }
  };

  const handleCreateManual = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSaving(true);
    try {
      if (kind === 'private_key' && uploadedPrivKey && privateKey === uploadedPrivKey.content) {
        const res = await api.importCredentialFile({
          file: uploadedPrivKey.file,
          publicKeyFile:
            uploadedPubKey && publicKey === uploadedPubKey.content ? uploadedPubKey.file : null,
          name,
          passphrase,
          publicKey,
          usernameHint,
          notes,
        });
        setAddModalOpen(false);
        const algoSuffix = res.credential.key_algorithm
          ? ` (${res.credential.key_algorithm.toUpperCase()})`
          : '';
        onNotify(`已从文件加密导入密钥凭据 ${res.credential.name}${algoSuffix}`);
      } else {
        const res = await api.createCredential({
          name,
          kind,
          username_hint: usernameHint,
          password: kind === 'password' ? password : '',
          private_key: kind === 'private_key' ? privateKey : '',
          passphrase: kind === 'private_key' ? passphrase : '',
          public_key: kind === 'private_key' ? publicKey : '',
          notes,
        });
        setAddModalOpen(false);
        onNotify(`已加密存入凭据 ${res.credential.name}`);
      }
      await onRefresh();
    } catch (err: any) {
      setError(err?.message || '保存凭据失败');
    } finally {
      setSaving(false);
    }
  };

  const handleGenerateKey = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!genSaveName.trim()) {
      setError('请输入密钥凭据保存名称');
      return;
    }
    setError('');
    setGenerating(true);
    try {
      const res = await api.generateKeyPair({
        algorithm: genAlgo,
        comment: genComment,
        passphrase: genPassphrase,
        save_name: genSaveName.trim(),
        username_hint: 'root',
        notes: `由 ServerNeedSafe 内置安全生成器创建 (${genAlgo.toUpperCase()})`,
      });
      setGenModalOpen(false);
      onNotify(`已生成并加密保存 ${res.algorithm.toUpperCase()} 密钥对`);
      await onRefresh();
    } catch (err: any) {
      setError(err?.message || '生成密钥对失败');
    } finally {
      setGenerating(false);
    }
  };

  const handleCopyPub = async (cred: CredentialView) => {
    if (!cred.public_key) return;
    try {
      await copyTextToClipboard(cred.public_key);
      setCopiedId(cred.id);
      onNotify('公钥已复制到剪贴板');
      setTimeout(() => setCopiedId(''), 1800);
    } catch {
      onNotify('浏览器剪贴板写入失败，请手动选中复制');
    }
  };

  const handleDeploy = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!deployTargetCred || !deployServerId) return;
    setDeploying(true);
    setError('');
    try {
      await api.deployPublicKey({
        server_id: deployServerId,
        credential_id: deployTargetCred.id,
      });
      onNotify('公钥已安全写入目标服务器 ~/.ssh/authorized_keys');
      setDeployTargetCred(null);
    } catch (err: any) {
      setError(err?.message || '公钥下发失败');
    } finally {
      setDeploying(false);
    }
  };

  const handleDelete = async (cred: CredentialView) => {
    try {
      await api.deleteCredential(cred.id);
      onNotify(`已删除凭据 ${cred.name}`);
      await onRefresh();
    } catch (err: any) {
      onNotify(err?.message || '无法删除该凭据');
    }
  };

  return (
    <div className="workspace-surface" id="keychain-manager-view">
      <div className="page-header">
        <div className="page-header-title">
          <h2>SSH 密钥与凭据保险库</h2>
          <p>统一托管可复用的 SSH 私钥与登录凭据，私钥在内存中解密使用，永不落盘明文</p>
        </div>
        <div className="page-header-actions">
          <button
            type="button"
            id="open-keygen-btn"
            className="btn btn-teal"
            onClick={() => {
              setGenSaveName(`Prod-Ed25519-${credentials.length + 1}`);
              setGenPassphrase('');
              setError('');
              setGenModalOpen(true);
            }}
          >
            <Sparkles size={14} /> 生成安全 SSH 密钥对
          </button>
          <button
            type="button"
            id="open-add-cred-btn"
            className="btn btn-primary"
            onClick={openImportModal}
          >
            <Plus size={15} /> 导入现有凭据
          </button>
        </div>
      </div>

      <div className="page-body">
        {credentials.length === 0 ? (
          <div className="empty-state">
            <div className="empty-state-icon">
              <KeyRound size={22} />
            </div>
            <h3>凭据保险库暂为空</h3>
            <p>
              推荐一键生成高强度 Ed25519 密钥对并自动下发公钥至服务器，或直接上传本地 SSH 私钥文件加密托管。
            </p>
            <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', justifyContent: 'center' }}>
              <button
                type="button"
                className="btn btn-primary"
                onClick={() => {
                  setGenSaveName('Master-Ed25519-Key');
                  setGenModalOpen(true);
                }}
              >
                <Sparkles size={14} /> 立即生成 Ed25519 密钥对
              </button>
              <button
                type="button"
                className="btn"
                onClick={openImportModal}
              >
                <Upload size={14} /> 上传密钥文件导入
              </button>
            </div>
          </div>
        ) : (
          <div className="server-grid">
            {credentials.map((cred) => (
              <div key={cred.id} className="server-card">
                <div className="server-card-top">
                  <div className="server-identity">
                    <div className="server-icon-box connected">
                      {cred.kind === 'private_key' ? <KeyRound size={18} /> : <Lock size={18} />}
                    </div>
                    <div style={{ minWidth: 0 }}>
                      <div className="server-name" title={cred.name}>{cred.name}</div>
                      <div className="server-endpoint">
                        {cred.kind === 'private_key'
                          ? `${(cred.key_algorithm || 'SSH Key').toUpperCase()}${
                              cred.has_passphrase ? ' · 含私钥口令' : ''
                            }`
                          : '加密密码凭据'}
                      </div>
                    </div>
                  </div>
                  <button
                    type="button"
                    className="btn btn-ghost btn-sm btn-icon"
                    style={{ color: 'var(--danger-text)' }}
                    onClick={() => void handleDelete(cred)}
                    title="删除凭据"
                  >
                    <Trash2 size={14} />
                  </button>
                </div>

                {cred.fingerprint && (
                  <div
                    className="mono"
                    style={{
                      fontSize: 11.5,
                      padding: '7px 10px',
                      background: 'var(--bg-subtle)',
                      borderRadius: 6,
                      color: 'var(--text-secondary)',
                      wordBreak: 'break-all',
                    }}
                  >
                    {cred.fingerprint}
                  </div>
                )}

                {cred.notes && (
                  <div style={{ fontSize: 12, color: 'var(--text-muted)', wordBreak: 'break-word' }}>
                    {cred.notes}
                  </div>
                )}

                <div className="server-card-footer">
                  <span style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>
                    创建于 {new Date(cred.created_at).toLocaleDateString('zh-CN')}
                  </span>
                  <div style={{ display: 'flex', gap: 6 }}>
                    {cred.public_key && (
                      <>
                        <button
                          type="button"
                          className="btn btn-sm"
                          onClick={() => void handleCopyPub(cred)}
                        >
                          {copiedId === cred.id ? <Check size={13} /> : <Copy size={13} />}
                          复制公钥
                        </button>
                        {servers.length > 0 && (
                          <button
                            type="button"
                            className="btn btn-sm btn-primary"
                            onClick={() => {
                              setError('');
                              setDeployServerId(servers[0]?.id || '');
                              setDeployTargetCred(cred);
                            }}
                          >
                            <Send size={12.5} /> 下发公钥
                          </button>
                        )}
                      </>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Generate SSH Key Pair Modal */}
      {genModalOpen && (
        <div className="modal-backdrop">
          <form className="modal-panel" onSubmit={handleGenerateKey} id="keygen-modal">
            <div className="modal-header">
              <h3>生成高强度 SSH 密钥对</h3>
              <button
                type="button"
                className="btn btn-ghost btn-sm btn-icon"
                onClick={() => setGenModalOpen(false)}
              >
                <X size={16} />
              </button>
            </div>
            <div className="modal-body">
              {error && <div className="alert alert-error">{error}</div>}
              <div className="field">
                <label className="field-label">凭据保存名称 *</label>
                <input
                  id="keygen-name-input"
                  className="input"
                  value={genSaveName}
                  onChange={(e) => setGenSaveName(e.target.value)}
                  placeholder="例如：香港生产集群通用密钥"
                  required
                />
              </div>
              <div className="field">
                <label className="field-label">加密算法</label>
                <div className="auth-mode-switch" style={{ marginBottom: 4 }}>
                  <button
                    type="button"
                    className={`auth-mode-btn ${genAlgo === 'ed25519' ? 'active' : ''}`}
                    onClick={() => setGenAlgo('ed25519')}
                  >
                    Ed25519（现代首选 · 极速安全）
                  </button>
                  <button
                    type="button"
                    className={`auth-mode-btn ${genAlgo === 'rsa-4096' ? 'active' : ''}`}
                    onClick={() => setGenAlgo('rsa-4096')}
                  >
                    RSA-4096（传统高兼容）
                  </button>
                </div>
              </div>
              <div className="field">
                <label className="field-label">公钥注释标识 (Comment)</label>
                <input
                  className="input mono"
                  value={genComment}
                  onChange={(e) => setGenComment(e.target.value)}
                />
              </div>
              <div className="field">
                <label className="field-label">附加私钥口令保护 (Passphrase，选填)</label>
                <input
                  type="password"
                  className="input"
                  placeholder="可选：为私钥再叠加一层独立口令保护"
                  value={genPassphrase}
                  onChange={(e) => setGenPassphrase(e.target.value)}
                />
              </div>
            </div>
            <div className="modal-footer">
              <button type="button" className="btn" onClick={() => setGenModalOpen(false)}>
                取消
              </button>
              <button type="submit" id="keygen-submit-btn" className="btn btn-primary" disabled={generating}>
                {generating ? '正在内存生成密钥对...' : '生成并存入加密保险库'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Import Manual Credential Modal */}
      {addModalOpen && (
        <div className="modal-backdrop">
          <form className="modal-panel" id="import-cred-modal" onSubmit={handleCreateManual}>
            <div className="modal-header">
              <h3>导入 SSH 私钥或密码凭据</h3>
              <button
                type="button"
                className="btn btn-ghost btn-sm btn-icon"
                onClick={() => setAddModalOpen(false)}
              >
                <X size={16} />
              </button>
            </div>
            <div className="modal-body">
              {error && <div className="alert alert-error">{error}</div>}
              <div className="field">
                <label className="field-label" htmlFor="cred-name-input">
                  <span>凭据名称 *</span>
                  <span className="field-hint">上传文件后如留空将自动填充文件名</span>
                </label>
                <input
                  id="cred-name-input"
                  className="input"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="例如：AWS 运维跳板机私钥"
                  required
                />
              </div>
              <div className="field">
                <label className="field-label">凭据类型</label>
                <div className="auth-mode-switch" style={{ marginBottom: 4 }}>
                  <button
                    type="button"
                    className={`auth-mode-btn ${kind === 'private_key' ? 'active' : ''}`}
                    onClick={() => setKind('private_key')}
                  >
                    SSH 私钥
                  </button>
                  <button
                    type="button"
                    className={`auth-mode-btn ${kind === 'password' ? 'active' : ''}`}
                    onClick={() => setKind('password')}
                  >
                    密码口令
                  </button>
                </div>
              </div>
              {kind === 'private_key' ? (
                <>
                  <PrivateKeyField
                    idPrefix="cred-privkey"
                    textareaId="cred-privkey-input"
                    label="SSH 私钥文件 / PEM 内容 *"
                    value={privateKey}
                    onChange={(nextVal) => {
                      setPrivateKey(nextVal);
                      if (!nextVal.trim()) {
                        setUploadedPrivKey(null);
                      }
                    }}
                    uploadedFile={uploadedPrivKey}
                    onFileLoaded={(parsed) => {
                      setUploadedPrivKey(parsed);
                      setPrivateKey(parsed.content);
                      setName((prev) => (prev.trim() ? prev : parsed.suggestedName));
                      setError('');
                    }}
                    onClearFile={() => {
                      setUploadedPrivKey(null);
                      setPrivateKey('');
                    }}
                    onPublicKeyFileLoaded={(parsedPub) => {
                      setUploadedPubKey(parsedPub);
                      setPublicKey(parsedPub.content);
                      setPubFileError('');
                    }}
                    required
                  />
                  <div className="field">
                    <label className="field-label" htmlFor="cred-passphrase-input">
                      <span>私钥口令 (Passphrase，{uploadedPrivKey?.encrypted ? '此私钥已加密，必填' : '选填'})</span>
                    </label>
                    <input
                      id="cred-passphrase-input"
                      type="password"
                      className="input"
                      placeholder={
                        uploadedPrivKey?.encrypted
                          ? '检测到私钥已加密，请输入解密口令'
                          : '若私钥未设置口令保护请留空'
                      }
                      value={passphrase}
                      onChange={(e) => setPassphrase(e.target.value)}
                    />
                  </div>
                  <div className="field">
                    <div className="field-label">
                      <label htmlFor="cred-pubkey-input">
                        对应公钥 (选填，留空将自动从私钥推导)
                      </label>
                      <div className="key-pub-upload-inline">
                        <input
                          ref={pubFileInputRef}
                          id="cred-pubkey-file-input"
                          type="file"
                          style={{ display: 'none' }}
                          onChange={(e) => void handleSelectPubFile(e)}
                        />
                        {uploadedPubKey && (
                          <span className="tag-chip teal key-pub-chip" title={uploadedPubKey.fileName}>
                            <FileText size={11} />
                            <span className="key-pub-chip-name mono">{uploadedPubKey.fileName}</span>
                            <button
                              type="button"
                              className="key-pub-chip-clear"
                              title="清除公钥文件"
                              onClick={() => {
                                setUploadedPubKey(null);
                                setPublicKey('');
                                setPubFileError('');
                              }}
                            >
                              <X size={11} />
                            </button>
                          </span>
                        )}
                        <button
                          type="button"
                          id="cred-pubkey-choose-file-btn"
                          className="btn btn-sm key-inline-upload-btn"
                          onClick={() => {
                            setPubFileError('');
                            pubFileInputRef.current?.click();
                          }}
                        >
                          <Upload size={11.5} /> 上传 .pub
                        </button>
                      </div>
                    </div>
                    <input
                      id="cred-pubkey-input"
                      className="input mono"
                      value={publicKey}
                      onChange={(e) => {
                        setPublicKey(e.target.value);
                        if (!e.target.value.trim()) {
                          setUploadedPubKey(null);
                        }
                      }}
                      placeholder="留空自动提取；或上传 .pub / 粘贴 ssh-ed25519 AAAA..."
                    />
                    {pubFileError && (
                      <div className="key-upload-error" role="alert">
                        <span>{pubFileError}</span>
                      </div>
                    )}
                  </div>
                </>
              ) : (
                <div className="field">
                  <label className="field-label">SSH 密码 *</label>
                  <input
                    type="password"
                    className="input"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                  />
                </div>
              )}
              <div className="field">
                <label className="field-label">默认用户名提示 / 备注</label>
                <input
                  className="input"
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  placeholder="用途说明"
                />
              </div>
            </div>
            <div className="modal-footer">
              <button type="button" className="btn" onClick={() => setAddModalOpen(false)}>
                取消
              </button>
              <button type="submit" id="cred-submit-btn" className="btn btn-primary" disabled={saving}>
                {saving ? '正在校验并加密保存...' : '保存凭据'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Deploy Public Key to Server Modal */}
      {deployTargetCred && (
        <div className="modal-backdrop">
          <form className="modal-panel" style={{ maxWidth: 440 }} onSubmit={handleDeploy}>
            <div className="modal-header">
              <h3>下发公钥至远程服务器</h3>
              <button
                type="button"
                className="btn btn-ghost btn-sm btn-icon"
                onClick={() => setDeployTargetCred(null)}
              >
                <X size={16} />
              </button>
            </div>
            <div className="modal-body">
              {error && <div className="alert alert-error">{error}</div>}
              <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 14 }}>
                将密钥 <strong>{deployTargetCred.name}</strong> 的公钥自动追加至目标主机的{' '}
                <code className="mono">~/.ssh/authorized_keys</code> 并修正 <code className="mono">0600</code> 安全权限。
              </p>
              <div className="field">
                <label className="field-label">选择目标服务器</label>
                <select
                  className="select"
                  value={deployServerId}
                  onChange={(e) => setDeployServerId(e.target.value)}
                >
                  {servers.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.name} ({s.username}@{s.host}:{s.port})
                    </option>
                  ))}
                </select>
              </div>
            </div>
            <div className="modal-footer">
              <button type="button" className="btn" onClick={() => setDeployTargetCred(null)}>
                取消
              </button>
              <button type="submit" className="btn btn-primary" disabled={deploying}>
                {deploying ? '正在通过 SSH 部署公钥...' : '立即部署'}
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
};

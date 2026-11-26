import React, { useMemo, useState } from 'react';
import {
  Server,
  Plus,
  Search,
  Terminal,
  FolderOpen,
  Activity,
  Edit2,
  Trash2,
  Star,
  KeyRound,
  Lock,
  GitBranch,
  X,
  FolderPlus,
} from 'lucide-react';
import { api, ApiError } from '../api';
import type {
  AuthType,
  CredentialView,
  HostKeyUntrustedInfo,
  ServerMutationPayload,
  ServerProbeResult,
  ServerView,
} from '../types';
import { HostKeyModal } from './HostKeyModal';
import { SftpPanel } from './SftpPanel';

interface ServerManagerProps {
  servers: ServerView[];
  groups: string[];
  credentials: CredentialView[];
  activeServerIds: Set<string>;
  showHiddenFiles?: boolean;
  onRefresh: () => Promise<void>;
  onConnectTerminal: (server: ServerView, openSftp?: boolean) => void;
  onOpenMonitor?: (serverId: string) => void;
  onNotify: (msg: string) => void;
}

const emptyForm: ServerMutationPayload = {
  name: '',
  group: '生产环境',
  tags: [],
  host: '',
  port: 22,
  username: 'root',
  auth_type: 'password',
  password: '',
  private_key: '',
  passphrase: '',
  credential_id: '',
  jump_server_id: '',
  default_path: '',
  notes: '',
  pinned: false,
  keep_alive_sec: 30,
  monitor_enabled: true,
  custom_interval_sec: 0,
  watched_services: [],
  watched_ports: [],
};

export const ServerManager: React.FC<ServerManagerProps> = ({
  servers,
  groups,
  credentials,
  activeServerIds,
  showHiddenFiles = true,
  onRefresh,
  onConnectTerminal,
  onOpenMonitor,
  onNotify,
}) => {
  const [selectedGroup, setSelectedGroup] = useState<string>('ALL');
  const [search, setSearch] = useState('');
  const [modalOpen, setModalOpen] = useState(false);
  const [editingServer, setEditingServer] = useState<ServerView | null>(null);
  const [form, setForm] = useState<ServerMutationPayload>(emptyForm);
  const [tagsText, setTagsText] = useState('');
  const [watchedServicesText, setWatchedServicesText] = useState('');
  const [watchedPortsText, setWatchedPortsText] = useState('');
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState('');

  // Probes & Modals
  const [probingId, setProbingId] = useState<string>('');
  const [probeMap, setProbeMap] = useState<Record<string, ServerProbeResult>>({});
  const [probeErrorMap, setProbeErrorMap] = useState<Record<string, string>>({});
  const [hostKeyPrompt, setHostKeyPrompt] = useState<{
    serverId: string;
    info: HostKeyUntrustedInfo;
  } | null>(null);

  const [groupModalOpen, setGroupModalOpen] = useState(false);
  const [newGroupName, setNewGroupName] = useState('');
  const [deletingServer, setDeletingServer] = useState<ServerView | null>(null);
  const [standaloneSftpServer, setStandaloneSftpServer] = useState<ServerView | null>(null);

  const serverNameById = useMemo(() => {
    const map: Record<string, string> = {};
    for (const s of servers) map[s.id] = s.name;
    return map;
  }, [servers]);

  const credentialNameById = useMemo(() => {
    const map: Record<string, string> = {};
    for (const c of credentials) map[c.id] = c.name;
    return map;
  }, [credentials]);

  const filteredServers = useMemo(() => {
    const q = search.trim().toLowerCase();
    return [...servers]
      .filter((s) => {
        if (selectedGroup !== 'ALL' && s.group !== selectedGroup) return false;
        if (!q) return true;
        return (
          s.name.toLowerCase().includes(q) ||
          s.host.toLowerCase().includes(q) ||
          s.username.toLowerCase().includes(q) ||
          s.group.toLowerCase().includes(q) ||
          s.tags.some((t) => t.toLowerCase().includes(q))
        );
      })
      .sort((a, b) => {
        if (a.pinned !== b.pinned) return a.pinned ? -1 : 1;
        return a.name.localeCompare(b.name, 'zh-CN');
      });
  }, [servers, selectedGroup, search]);

  const openCreateModal = () => {
    setEditingServer(null);
    setForm({
      ...emptyForm,
      group: selectedGroup !== 'ALL' ? selectedGroup : groups[0] || '生产环境',
      credential_id: credentials[0]?.id || '',
    });
    setTagsText('');
    setWatchedServicesText('');
    setWatchedPortsText('');
    setFormError('');
    setModalOpen(true);
  };

  const openEditModal = (srv: ServerView) => {
    setEditingServer(srv);
    setForm({
      name: srv.name,
      group: srv.group,
      tags: srv.tags || [],
      host: srv.host,
      port: srv.port,
      username: srv.username,
      auth_type: srv.auth_type,
      password: '',
      private_key: '',
      passphrase: '',
      credential_id: srv.credential_id || '',
      jump_server_id: srv.jump_server_id || '',
      default_path: srv.default_path || '',
      notes: srv.notes || '',
      pinned: srv.pinned,
      keep_alive_sec: srv.keep_alive_sec || 30,
      monitor_enabled: srv.monitor_enabled !== false,
      custom_interval_sec: srv.custom_interval_sec || 0,
      watched_services: srv.watched_services || [],
      watched_ports: srv.watched_ports || [],
    });
    setTagsText((srv.tags || []).join(', '));
    setWatchedServicesText((srv.watched_services || []).join(', '));
    setWatchedPortsText((srv.watched_ports || []).join(', '));
    setFormError('');
    setModalOpen(true);
  };

  const handleSaveServer = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError('');
    setSaving(true);
    try {
      const parsedPorts = watchedPortsText
        .split(/[,，\s]+/)
        .map((p) => Number(p.trim()))
        .filter((n) => Number.isInteger(n) && n > 0 && n <= 65535);
      const parsedSvcs = watchedServicesText
        .split(/[,，\s]+/)
        .map((s) => s.trim())
        .filter(Boolean);

      const payload: ServerMutationPayload = {
        ...form,
        tags: tagsText
          .split(/[,，]/)
          .map((t) => t.trim())
          .filter(Boolean),
        watched_services: parsedSvcs,
        watched_ports: parsedPorts,
      };

      // On update, omit blank secret fields so existing encrypted secrets remain untouched
      if (editingServer) {
        if (!payload.password) delete payload.password;
        if (!payload.private_key) delete payload.private_key;
        if (!payload.passphrase) delete payload.passphrase;
        await api.updateServer(editingServer.id, payload);
        onNotify(`已更新服务器 ${payload.name}`);
      } else {
        await api.createServer(payload);
        onNotify(`已加密保存服务器 ${payload.name}`);
      }
      setModalOpen(false);
      await onRefresh();
    } catch (err: any) {
      setFormError(err?.message || '保存服务器配置失败');
    } finally {
      setSaving(false);
    }
  };

  const handleProbe = async (srv: ServerView, trustFp = '') => {
    setProbingId(srv.id);
    setProbeErrorMap((prev) => {
      const cp = { ...prev };
      delete cp[srv.id];
      return cp;
    });
    try {
      const { probe } = await api.probeServer(srv.id, trustFp);
      setProbeMap((prev) => ({ ...prev, [srv.id]: probe }));
      await onRefresh();
    } catch (err) {
      if (err instanceof ApiError && err.code === 'HOST_KEY_UNTRUSTED' && err.hostKeyInfo) {
        setHostKeyPrompt({ serverId: srv.id, info: err.hostKeyInfo });
      } else {
        setProbeErrorMap((prev) => ({
          ...prev,
          [srv.id]: (err as Error)?.message || '连接探测失败',
        }));
      }
    } finally {
      setProbingId('');
    }
  };

  const handleAddGroup = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newGroupName.trim()) return;
    try {
      await api.addGroup(newGroupName.trim());
      setGroupModalOpen(false);
      setNewGroupName('');
      await onRefresh();
      onNotify(`已新建分组 ${newGroupName.trim()}`);
    } catch (err: any) {
      onNotify(err?.message || '创建分组失败');
    }
  };

  const handleConfirmDelete = async () => {
    if (!deletingServer) return;
    try {
      await api.deleteServer(deletingServer.id);
      onNotify(`已删除服务器 ${deletingServer.name}`);
      setDeletingServer(null);
      await onRefresh();
    } catch (err: any) {
      onNotify(err?.message || '删除失败');
      setDeletingServer(null);
    }
  };

  return (
    <div className="workspace-surface" id="server-manager-view">
      <div className="page-header">
        <div className="page-header-title">
          <h2>服务器资产管理</h2>
          <p>
            已加密托管 <strong className="tabular">{servers.length}</strong> 台服务器 · 支持密码、SSH 私钥、凭据库引用与多级跳板机隧道
          </p>
        </div>
        <div className="page-header-actions">
          <div className="input-with-icon server-search-box">
            <span className="input-icon-left">
              <Search size={14} />
            </span>
            <input
              id="server-search-input"
              className="input"
              style={{ height: 34 }}
              placeholder="搜索名称、IP、账号或标签..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
          <button
            type="button"
            className="btn"
            onClick={() => {
              setNewGroupName('');
              setGroupModalOpen(true);
            }}
          >
            <FolderPlus size={14} /> 新建分组
          </button>
          <button
            type="button"
            id="add-server-btn"
            className="btn btn-primary"
            onClick={openCreateModal}
          >
            <Plus size={15} /> 添加服务器
          </button>
        </div>
      </div>

      <div className="page-body">
        <div className="filter-bar">
          <div className="group-pills">
            <button
              type="button"
              className={`group-pill ${selectedGroup === 'ALL' ? 'active' : ''}`}
              onClick={() => setSelectedGroup('ALL')}
            >
              全部主机 <span className="tabular">({servers.length})</span>
            </button>
            {groups.map((g) => {
              const cnt = servers.filter((s) => s.group === g).length;
              return (
                <button
                  key={g}
                  type="button"
                  className={`group-pill ${selectedGroup === g ? 'active' : ''}`}
                  onClick={() => setSelectedGroup(g)}
                >
                  {g} <span className="tabular">({cnt})</span>
                </button>
              );
            })}
          </div>
        </div>

        {filteredServers.length === 0 ? (
          <div className="empty-state">
            <div className="empty-state-icon">
              <Server size={22} />
            </div>
            <h3>{servers.length === 0 ? '尚未添加任何 SSH 服务器' : '没有匹配的服务器结果'}</h3>
            <p>
              {servers.length === 0
                ? '添加您的第一台云服务器或内网节点，所有连接地址、账号、密码及私钥均通过独立主密钥加密保存于 secrets.enc。'
                : '请尝试切换分组或清空搜索条件。'}
            </p>
            {servers.length === 0 && (
              <button type="button" className="btn btn-primary" onClick={openCreateModal}>
                <Plus size={15} /> 立即添加服务器
              </button>
            )}
          </div>
        ) : (
          <div className="server-grid">
            {filteredServers.map((srv) => {
              const isConnected = activeServerIds.has(srv.id);
              const liveProbe = probeMap[srv.id];
              const probeErr = probeErrorMap[srv.id];

              return (
                <article className="server-card" key={srv.id} id={`server-card-${srv.id}`}>
                  <div className="server-card-top">
                    <div className="server-identity">
                      <div className={`server-icon-box ${isConnected ? 'connected' : ''}`}>
                        <Server size={18} />
                      </div>
                      <div style={{ minWidth: 0 }}>
                        <div className="server-name-row">
                          <span className="server-name" title={srv.name}>
                            {srv.name}
                          </span>
                          {srv.pinned && (
                            <Star
                              size={13}
                              fill="currentColor"
                              style={{ color: 'var(--amber-text)', flexShrink: 0 }}
                            />
                          )}
                          {isConnected && (
                            <span className="tag-chip teal" style={{ padding: '1px 6px' }}>
                              会话在线
                            </span>
                          )}
                        </div>
                        <div className="server-endpoint">
                          {srv.username}@{srv.host}:{srv.port}
                        </div>
                      </div>
                    </div>

                    <div style={{ display: 'flex', gap: 2 }}>
                      <button
                        type="button"
                        className="btn btn-ghost btn-sm btn-icon"
                        onClick={() => openEditModal(srv)}
                        title="编辑配置"
                      >
                        <Edit2 size={13.5} />
                      </button>
                      <button
                        type="button"
                        className="btn btn-ghost btn-sm btn-icon"
                        style={{ color: 'var(--danger-text)' }}
                        onClick={() => setDeletingServer(srv)}
                        title="删除服务器"
                      >
                        <Trash2 size={13.5} />
                      </button>
                    </div>
                  </div>

                  <div className="server-meta-strip">
                    <span className="tag-chip">{srv.group}</span>
                    <span className="tag-chip">
                      {srv.auth_type === 'password' ? (
                        <>
                          <Lock size={11} /> 密码认证
                        </>
                      ) : srv.auth_type === 'private_key' ? (
                        <>
                          <KeyRound size={11} /> SSH 私钥
                        </>
                      ) : (
                        <>
                          <KeyRound size={11} />{' '}
                          {credentialNameById[srv.credential_id || ''] || '凭据库密钥'}
                        </>
                      )}
                    </span>
                    {srv.jump_server_id && (
                      <span className="tag-chip amber">
                        <GitBranch size={11} /> 跳板:{' '}
                        {serverNameById[srv.jump_server_id] || '已关联'}
                      </span>
                    )}
                    {srv.last_latency_ms ? (
                      <span className="tag-chip teal">{srv.last_latency_ms} ms</span>
                    ) : null}
                    {srv.tags.map((t) => (
                      <span key={t} className="tag-chip">
                        #{t}
                      </span>
                    ))}
                  </div>

                  {srv.last_os_info && !liveProbe && (
                    <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                      系统环境：{srv.last_os_info}
                    </div>
                  )}

                  {srv.notes && !liveProbe && (
                    <div
                      style={{
                        fontSize: 12,
                        color: 'var(--text-muted)',
                        whiteSpace: 'nowrap',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                      }}
                    >
                      备注：{srv.notes}
                    </div>
                  )}

                  {liveProbe && (
                    <div className="server-telemetry-mini">
                      <div className="telemetry-cell">
                        <span>系统负载</span>
                        <strong>{liveProbe.load_avg || liveProbe.os || '正常'}</strong>
                      </div>
                      <div className="telemetry-cell">
                        <span>内存占用</span>
                        <strong>
                          {liveProbe.mem_total_mb ? `${liveProbe.mem_percent}%` : '—'}
                        </strong>
                      </div>
                      <div className="telemetry-cell">
                        <span>根分区磁盘</span>
                        <strong>
                          {liveProbe.disk_total_gb ? `${liveProbe.disk_percent}%` : '—'}
                        </strong>
                      </div>
                    </div>
                  )}

                  {probeErr && (
                    <div className="alert alert-error" style={{ marginBottom: 0, padding: '6px 10px' }}>
                      <span>{probeErr}</span>
                    </div>
                  )}

                  <div className="server-card-footer">
                    <div style={{ display: 'flex', gap: 6 }}>
                      <button
                        type="button"
                        className="btn btn-sm"
                        disabled={probingId === srv.id}
                        onClick={() => void handleProbe(srv)}
                      >
                        <Activity size={13} />
                        {probingId === srv.id ? '探测中...' : '连通探测'}
                      </button>
                      {onOpenMonitor && (
                        <button
                          type="button"
                          className="btn btn-sm"
                          onClick={() => onOpenMonitor(srv.id)}
                          title="查看全维监控指标与历史趋势曲线"
                        >
                          监控详情
                        </button>
                      )}
                    </div>

                    <div style={{ display: 'flex', gap: 6 }}>
                      <button
                        type="button"
                        className="btn btn-sm"
                        onClick={() => setStandaloneSftpServer(srv)}
                        title="打开 SFTP 远程文件管理器"
                      >
                        <FolderOpen size={13} /> SFTP
                      </button>
                      <button
                        type="button"
                        className="btn btn-sm btn-primary"
                        onClick={() => onConnectTerminal(srv, false)}
                      >
                        <Terminal size={13} /> SSH 终端
                      </button>
                    </div>
                  </div>
                </article>
              );
            })}
          </div>
        )}
      </div>

      {/* Add / Edit Server Modal */}
      {modalOpen && (
        <div className="modal-backdrop">
          <form className="modal-panel wide" onSubmit={handleSaveServer} id="server-form-modal">
            <div className="modal-header">
              <h3>{editingServer ? `编辑服务器 — ${editingServer.name}` : '添加 SSH 服务器'}</h3>
              <button
                type="button"
                className="btn btn-ghost btn-sm btn-icon"
                onClick={() => setModalOpen(false)}
              >
                <X size={16} />
              </button>
            </div>
            <div className="modal-body">
              {formError && <div className="alert alert-error">{formError}</div>}

              <div className="field-row">
                <div className="field">
                  <label className="field-label">服务器显示名称 *</label>
                  <input
                    id="srv-name-input"
                    className="input"
                    placeholder="例如：生产核心网关-01"
                    value={form.name}
                    onChange={(e) => setForm({ ...form, name: e.target.value })}
                    required
                  />
                </div>
                <div className="field">
                  <label className="field-label">所属分组</label>
                  <input
                    id="srv-group-input"
                    list="server-groups-datalist"
                    className="input"
                    value={form.group}
                    onChange={(e) => setForm({ ...form, group: e.target.value })}
                    placeholder="选择或输入新分组"
                  />
                  <datalist id="server-groups-datalist">
                    {groups.map((g) => (
                      <option key={g} value={g} />
                    ))}
                  </datalist>
                </div>
              </div>

              <div className="field-row">
                <div className="field">
                  <label className="field-label">主机地址 (IP / 域名) *</label>
                  <input
                    id="srv-host-input"
                    className="input mono"
                    placeholder="192.168.1.10 或 example.com"
                    value={form.host}
                    onChange={(e) => setForm({ ...form, host: e.target.value })}
                    required
                  />
                </div>
                <div className="field-row" style={{ marginBottom: 0 }}>
                  <div className="field">
                    <label className="field-label">SSH 端口 *</label>
                    <input
                      id="srv-port-input"
                      type="number"
                      className="input mono"
                      min={1}
                      max={65535}
                      value={form.port}
                      onChange={(e) => setForm({ ...form, port: Number(e.target.value) || 22 })}
                      required
                    />
                  </div>
                  <div className="field">
                    <label className="field-label">登录用户名 *</label>
                    <input
                      id="srv-user-input"
                      className="input mono"
                      placeholder="root"
                      value={form.username}
                      onChange={(e) => setForm({ ...form, username: e.target.value })}
                      required
                    />
                  </div>
                </div>
              </div>

              <div className="field">
                <label className="field-label">SSH 身份认证方式</label>
                <div className="auth-mode-switch" style={{ marginBottom: 8 }}>
                  {(
                    [
                      ['password', '密码认证'],
                      ['private_key', '独立 SSH 私钥'],
                      ['credential', '引用凭据库密钥'],
                    ] as [AuthType, string][]
                  ).map(([val, label]) => (
                    <button
                      key={val}
                      type="button"
                      className={`auth-mode-btn ${form.auth_type === val ? 'active' : ''}`}
                      onClick={() => setForm({ ...form, auth_type: val })}
                    >
                      {label}
                    </button>
                  ))}
                </div>
              </div>

              {form.auth_type === 'password' && (
                <div className="field">
                  <label className="field-label">
                    <span>SSH 登录密码</span>
                    {editingServer?.has_password && (
                      <span className="field-hint">已加密保存，留空则保持不变</span>
                    )}
                  </label>
                  <input
                    id="srv-password-input"
                    type="password"
                    className="input"
                    placeholder={editingServer?.has_password ? '••••••••（留空不修改）' : '输入远程服务器登录密码'}
                    value={form.password || ''}
                    onChange={(e) => setForm({ ...form, password: e.target.value })}
                  />
                </div>
              )}

              {form.auth_type === 'private_key' && (
                <>
                  <div className="field">
                    <label className="field-label">
                      <span>PEM / OpenSSH 私钥内容</span>
                      {editingServer?.has_private_key && (
                        <span className="field-hint">已加密保存，留空则保持不变</span>
                      )}
                    </label>
                    <textarea
                      id="srv-privkey-input"
                      className="textarea mono code-textarea"
                      placeholder="-----BEGIN OPENSSH PRIVATE KEY----- ..."
                      value={form.private_key || ''}
                      onChange={(e) => setForm({ ...form, private_key: e.target.value })}
                    />
                  </div>
                  <div className="field">
                    <label className="field-label">私钥保护口令 (Passphrase，选填)</label>
                    <input
                      type="password"
                      className="input"
                      placeholder="若私钥无口令保护请留空"
                      value={form.passphrase || ''}
                      onChange={(e) => setForm({ ...form, passphrase: e.target.value })}
                    />
                  </div>
                </>
              )}

              {form.auth_type === 'credential' && (
                <div className="field">
                  <label className="field-label">选择加密凭据库中的密钥/口令</label>
                  <select
                    className="select"
                    value={form.credential_id}
                    onChange={(e) => setForm({ ...form, credential_id: e.target.value })}
                  >
                    <option value="">-- 请选择已保存的加密凭据 --</option>
                    {credentials.map((c) => (
                      <option key={c.id} value={c.id}>
                        {c.name} ({c.kind === 'private_key' ? c.key_algorithm || 'SSH 私钥' : '密码凭据'})
                      </option>
                    ))}
                  </select>
                </div>
              )}

              <div className="field-row">
                <div className="field">
                  <label className="field-label">SSH 跳板机 / 堡垒机 (ProxyJump，选填)</label>
                  <select
                    className="select"
                    value={form.jump_server_id}
                    onChange={(e) => setForm({ ...form, jump_server_id: e.target.value })}
                  >
                    <option value="">直连（不使用跳板机）</option>
                    {servers
                      .filter((s) => s.id !== editingServer?.id)
                      .map((s) => (
                        <option key={s.id} value={s.id}>
                          {s.name} ({s.host}:{s.port})
                        </option>
                      ))}
                  </select>
                </div>
                <div className="field">
                  <label className="field-label">默认远程目录 (选填)</label>
                  <input
                    className="input mono"
                    placeholder="例如 /data/www 或留空使用主目录"
                    value={form.default_path}
                    onChange={(e) => setForm({ ...form, default_path: e.target.value })}
                  />
                </div>
              </div>

              <div className="field-row">
                <div className="field">
                  <label className="field-label">标签 (多个以逗号分隔)</label>
                  <input
                    className="input"
                    placeholder="nginx, k8s-master, hk-bgp"
                    value={tagsText}
                    onChange={(e) => setTagsText(e.target.value)}
                  />
                </div>
                <div className="field">
                  <label className="field-label">备注说明</label>
                  <input
                    className="input"
                    placeholder="用途、内网段或负责人备注"
                    value={form.notes}
                    onChange={(e) => setForm({ ...form, notes: e.target.value })}
                  />
                </div>
              </div>

              {/* Per-Server Monitoring Configuration */}
              <div
                style={{
                  background: 'var(--bg-subtle)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-sm)',
                  padding: '12px 14px',
                  marginBottom: 14,
                }}
              >
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    marginBottom: 10,
                    flexWrap: 'wrap',
                    gap: 8,
                  }}
                >
                  <span style={{ fontSize: 12.5, fontWeight: 620 }}>
                    状态监控与关键业务守护配置
                  </span>
                  <label
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: 6,
                      fontSize: 12.5,
                      cursor: 'pointer',
                    }}
                  >
                    <input
                      type="checkbox"
                      checked={form.monitor_enabled !== false}
                      onChange={(e) =>
                        setForm({ ...form, monitor_enabled: e.target.checked })
                      }
                    />
                    启用后台定时巡检记录
                  </label>
                </div>

                <div className="field-row" style={{ marginBottom: 0 }}>
                  <div className="field" style={{ marginBottom: 0 }}>
                    <label className="field-label">
                      <span>独立采集周期 (秒)</span>
                      <span className="field-hint">0 表示跟随全局</span>
                    </label>
                    <input
                      type="number"
                      min={0}
                      max={86400}
                      className="input mono"
                      value={form.custom_interval_sec || 0}
                      onChange={(e) =>
                        setForm({
                          ...form,
                          custom_interval_sec: Math.max(0, Number(e.target.value) || 0),
                        })
                      }
                    />
                  </div>
                  <div className="field" style={{ marginBottom: 0 }}>
                    <label className="field-label">必监守护服务 (停止即告警)</label>
                    <input
                      className="input mono"
                      placeholder="例如 nginx, postgresql, docker"
                      value={watchedServicesText}
                      onChange={(e) => setWatchedServicesText(e.target.value)}
                    />
                  </div>
                </div>

                <div className="field" style={{ marginTop: 10, marginBottom: 0 }}>
                  <label className="field-label">必监监听端口 (未处于 LISTEN 即告警，逗号分隔)</label>
                  <input
                    className="input mono"
                    placeholder="例如 80, 443, 5432, 6379"
                    value={watchedPortsText}
                    onChange={(e) => setWatchedPortsText(e.target.value)}
                  />
                </div>
              </div>

              <label
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 8,
                  fontSize: 13,
                  cursor: 'pointer',
                }}
              >
                <input
                  type="checkbox"
                  checked={form.pinned}
                  onChange={(e) => setForm({ ...form, pinned: e.target.checked })}
                />
                星标置顶此服务器
              </label>
            </div>
            <div className="modal-footer">
              <button type="button" className="btn" onClick={() => setModalOpen(false)}>
                取消
              </button>
              <button type="submit" id="srv-save-submit-btn" className="btn btn-primary" disabled={saving}>
                {saving ? '正在加密写入保险库...' : editingServer ? '保存更新' : '加密保存服务器'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Create Group Modal */}
      {groupModalOpen && (
        <div className="modal-backdrop">
          <form className="modal-panel" style={{ maxWidth: 380 }} onSubmit={handleAddGroup}>
            <div className="modal-header">
              <h3>新建服务器分组</h3>
              <button
                type="button"
                className="btn btn-ghost btn-sm btn-icon"
                onClick={() => setGroupModalOpen(false)}
              >
                <X size={15} />
              </button>
            </div>
            <div className="modal-body">
              <div className="field" style={{ marginBottom: 0 }}>
                <label className="field-label">分组名称</label>
                <input
                  className="input"
                  placeholder="例如：海外节点 / GPU 算力池"
                  value={newGroupName}
                  onChange={(e) => setNewGroupName(e.target.value)}
                  autoFocus
                  required
                />
              </div>
            </div>
            <div className="modal-footer">
              <button type="button" className="btn" onClick={() => setGroupModalOpen(false)}>
                取消
              </button>
              <button type="submit" className="btn btn-primary">
                创建分组
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Delete Confirm Modal */}
      {deletingServer && (
        <div className="modal-backdrop">
          <div className="modal-panel" style={{ maxWidth: 420 }}>
            <div className="modal-header">
              <h3>确认删除服务器资产</h3>
              <button
                type="button"
                className="btn btn-ghost btn-sm btn-icon"
                onClick={() => setDeletingServer(null)}
              >
                <X size={15} />
              </button>
            </div>
            <div className="modal-body">
              <p style={{ fontSize: 13.5 }}>
                确定要从加密保险库中移除服务器 <strong>{deletingServer.name}</strong> (
                <code className="mono">
                  {deletingServer.host}:{deletingServer.port}
                </code>
                ) 吗？
              </p>
            </div>
            <div className="modal-footer">
              <button type="button" className="btn" onClick={() => setDeletingServer(null)}>
                取消
              </button>
              <button type="button" className="btn btn-danger" onClick={() => void handleConfirmDelete()}>
                确认删除
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Standalone Full SFTP Modal */}
      {standaloneSftpServer && (
        <div className="modal-backdrop">
          <div className="modal-panel wide sftp-standalone-modal">
            <SftpPanel
              serverId={standaloneSftpServer.id}
              serverName={standaloneSftpServer.name}
              showHiddenDefault={showHiddenFiles}
              onNotify={onNotify}
              onClose={() => setStandaloneSftpServer(null)}
            />
          </div>
        </div>
      )}

      {/* Host Key Verification Modal */}
      {hostKeyPrompt && (
        <HostKeyModal
          info={hostKeyPrompt.info}
          onCancel={() => setHostKeyPrompt(null)}
          onTrustAndRetry={(fp) => {
            const srv = servers.find((s) => s.id === hostKeyPrompt.serverId);
            setHostKeyPrompt(null);
            if (srv) void handleProbe(srv, fp);
          }}
        />
      )}
    </div>
  );
};

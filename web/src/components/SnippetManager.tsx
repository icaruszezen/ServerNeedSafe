import React, { useState } from 'react';
import {
  Zap,
  Plus,
  Play,
  Edit2,
  Trash2,
  CheckCircle2,
  XCircle,
  X,
} from 'lucide-react';
import { api } from '../api';
import type { BatchExecResult, ServerView, Snippet } from '../types';

interface SnippetManagerProps {
  snippets: Snippet[];
  servers: ServerView[];
  onRefresh: () => Promise<void>;
  onNotify: (msg: string) => void;
}

export const SnippetManager: React.FC<SnippetManagerProps> = ({
  snippets,
  servers,
  onRefresh,
  onNotify,
}) => {
  const [editing, setEditing] = useState<Partial<Snippet> | null>(null);
  const [saving, setSaving] = useState(false);

  // Batch Runner State
  const [batchSnippet, setBatchSnippet] = useState<Snippet | null>(null);
  const [selectedServerIds, setSelectedServerIds] = useState<string[]>([]);
  const [runningBatch, setRunningBatch] = useState(false);
  const [batchResults, setBatchResults] = useState<BatchExecResult[] | null>(null);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editing?.title || !editing?.command) return;
    setSaving(true);
    try {
      await api.upsertSnippet(editing);
      setEditing(null);
      onNotify('快捷指令已加密保存');
      await onRefresh();
    } catch (err: any) {
      onNotify(err?.message || '保存失败');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await api.deleteSnippet(id);
      onNotify('快捷指令已删除');
      await onRefresh();
    } catch (err: any) {
      onNotify(err?.message || '删除失败');
    }
  };

  const openBatchModal = (sn: Snippet) => {
    setBatchSnippet(sn);
    setSelectedServerIds(servers.map((s) => s.id));
    setBatchResults(null);
  };

  const toggleServerCheck = (id: string) => {
    setSelectedServerIds((prev) =>
      prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]
    );
  };

  const handleRunBatch = async () => {
    if (!batchSnippet || selectedServerIds.length === 0) return;
    setRunningBatch(true);
    setBatchResults(null);
    try {
      const { results } = await api.batchExec(selectedServerIds, batchSnippet.command, 25);
      setBatchResults(results);
    } catch (err: any) {
      onNotify(err?.message || '批量执行失败');
    } finally {
      setRunningBatch(false);
    }
  };

  return (
    <div className="workspace-surface" id="snippet-manager-view">
      <div className="page-header">
        <div className="page-header-title">
          <h2>安全巡检与快捷指令库</h2>
          <p>预置高频运维排查脚本，支持在终端一键注入或跨多台服务器并发执行</p>
        </div>
        <div className="page-header-actions">
          <button
            type="button"
            className="btn btn-primary"
            onClick={() =>
              setEditing({
                title: '',
                category: '安全巡检',
                command: '',
                description: '',
              })
            }
          >
            <Plus size={15} /> 新建指令
          </button>
        </div>
      </div>

      <div className="page-body">
        <div className="server-grid">
          {snippets.map((sn) => (
            <div key={sn.id} className="server-card">
              <div className="server-card-top">
                <div className="server-identity">
                  <div className="server-icon-box">
                    <Zap size={17} />
                  </div>
                  <div>
                    <div className="server-name">{sn.title}</div>
                    <span className="tag-chip" style={{ marginTop: 4 }}>
                      {sn.category}
                    </span>
                  </div>
                </div>
                <div style={{ display: 'flex', gap: 3 }}>
                  <button
                    type="button"
                    className="btn btn-ghost btn-sm btn-icon"
                    onClick={() => setEditing({ ...sn })}
                  >
                    <Edit2 size={13.5} />
                  </button>
                  <button
                    type="button"
                    className="btn btn-ghost btn-sm btn-icon"
                    style={{ color: 'var(--danger-text)' }}
                    onClick={() => void handleDelete(sn.id)}
                  >
                    <Trash2 size={13.5} />
                  </button>
                </div>
              </div>

              {sn.description && (
                <div style={{ fontSize: 12.5, color: 'var(--text-secondary)' }}>
                  {sn.description}
                </div>
              )}

              <pre
                className="mono"
                style={{
                  padding: '9px 11px',
                  borderRadius: 7,
                  background: 'var(--bg-subtle)',
                  border: '1px solid var(--border-subtle)',
                  fontSize: 11.5,
                  overflowX: 'auto',
                  color: 'var(--text-primary)',
                }}
              >
                {sn.command}
              </pre>

              <div className="server-card-footer">
                <span style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>
                  可在终端工具栏直接调用
                </span>
                <button
                  type="button"
                  className="btn btn-sm btn-primary"
                  disabled={servers.length === 0}
                  onClick={() => openBatchModal(sn)}
                >
                  <Play size={12.5} /> 多主机并发执行
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Create / Edit Snippet Modal */}
      {editing && (
        <div className="modal-backdrop">
          <form className="modal-panel" onSubmit={handleSave}>
            <div className="modal-header">
              <h3>{editing.id ? '编辑快捷指令' : '新建快捷指令'}</h3>
              <button
                type="button"
                className="btn btn-ghost btn-sm btn-icon"
                onClick={() => setEditing(null)}
              >
                <X size={16} />
              </button>
            </div>
            <div className="modal-body">
              <div className="field-row">
                <div className="field">
                  <label className="field-label">指令名称 *</label>
                  <input
                    className="input"
                    value={editing.title || ''}
                    onChange={(e) => setEditing({ ...editing, title: e.target.value })}
                    required
                  />
                </div>
                <div className="field">
                  <label className="field-label">分类</label>
                  <input
                    className="input"
                    value={editing.category || ''}
                    onChange={(e) => setEditing({ ...editing, category: e.target.value })}
                    placeholder="安全巡检 / 日常运维"
                  />
                </div>
              </div>
              <div className="field">
                <label className="field-label">Shell 命令内容 *</label>
                <textarea
                  className="textarea mono"
                  value={editing.command || ''}
                  onChange={(e) => setEditing({ ...editing, command: e.target.value })}
                  required
                />
              </div>
              <div className="field">
                <label className="field-label">用途描述</label>
                <input
                  className="input"
                  value={editing.description || ''}
                  onChange={(e) => setEditing({ ...editing, description: e.target.value })}
                />
              </div>
            </div>
            <div className="modal-footer">
              <button type="button" className="btn" onClick={() => setEditing(null)}>
                取消
              </button>
              <button type="submit" className="btn btn-primary" disabled={saving}>
                保存指令
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Multi-Server Batch Exec Modal */}
      {batchSnippet && (
        <div className="modal-backdrop">
          <div className="modal-panel wide" style={{ maxHeight: '88vh' }}>
            <div className="modal-header">
              <h3>多服务器并发执行 — {batchSnippet.title}</h3>
              <button
                type="button"
                className="btn btn-ghost btn-sm btn-icon"
                onClick={() => setBatchSnippet(null)}
              >
                <X size={16} />
              </button>
            </div>
            <div className="modal-body">
              <div className="field">
                <label className="field-label">待执行命令</label>
                <pre
                  className="mono"
                  style={{
                    padding: '9px 12px',
                    borderRadius: 7,
                    background: 'var(--bg-subtle)',
                    border: '1px solid var(--border-default)',
                    fontSize: 12,
                    overflowX: 'auto',
                  }}
                >
                  {batchSnippet.command}
                </pre>
              </div>

              <div className="field">
                <label className="field-label">
                  <span>选择目标服务器 ({selectedServerIds.length}/{servers.length})</span>
                </label>
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                  {servers.map((srv) => {
                    const checked = selectedServerIds.includes(srv.id);
                    return (
                      <label
                        key={srv.id}
                        className={`group-pill ${checked ? 'active' : ''}`}
                        style={{ cursor: 'pointer' }}
                      >
                        <input
                          type="checkbox"
                          checked={checked}
                          onChange={() => toggleServerCheck(srv.id)}
                          style={{ display: 'none' }}
                        />
                        {srv.name} ({srv.host})
                      </label>
                    );
                  })}
                </div>
              </div>

              {batchResults && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginTop: 14 }}>
                  {batchResults.map((r) => (
                    <div
                      key={r.server_id}
                      style={{
                        border: '1px solid var(--border-default)',
                        borderRadius: 8,
                        overflow: 'hidden',
                      }}
                    >
                      <div
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          padding: '8px 12px',
                          background: 'var(--bg-subtle)',
                          fontSize: 12.5,
                        }}
                      >
                        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontWeight: 600 }}>
                          {r.success ? (
                            <CheckCircle2 size={15} style={{ color: 'var(--status-online)' }} />
                          ) : (
                            <XCircle size={15} style={{ color: 'var(--danger-text)' }} />
                          )}
                          {r.server_name} ({r.host})
                        </span>
                        <span className="mono" style={{ color: 'var(--text-muted)', fontSize: 11.5 }}>
                          耗时 {r.duration_ms}ms · Exit {r.exit_code}
                        </span>
                      </div>
                      <pre
                        className="mono"
                        style={{
                          padding: '10px 12px',
                          background: '#0d1016',
                          color: '#e2e8f0',
                          fontSize: 11.5,
                          maxHeight: 200,
                          overflow: 'auto',
                        }}
                      >
                        {r.error ? `[错误] ${r.error}\n` : ''}
                        {r.stdout || r.stderr || '(无标准输出)'}
                      </pre>
                    </div>
                  ))}
                </div>
              )}
            </div>
            <div className="modal-footer">
              <button type="button" className="btn" onClick={() => setBatchSnippet(null)}>
                关闭
              </button>
              <button
                type="button"
                className="btn btn-primary"
                disabled={runningBatch || selectedServerIds.length === 0}
                onClick={() => void handleRunBatch()}
              >
                <Play size={13.5} />
                {runningBatch
                  ? `正在并发执行 (${selectedServerIds.length} 台主机)...`
                  : '开始并发执行'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

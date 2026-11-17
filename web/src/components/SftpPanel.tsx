import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  Folder,
  FileText,
  ArrowUp,
  Home,
  RefreshCw,
  Upload,
  FolderPlus,
  Download,
  Edit3,
  Trash2,
  Shield,
  FilePlus,
  X,
  Save,
} from 'lucide-react';
import { api } from '../api';
import type { SFTPFileEntry } from '../types';

interface SftpPanelProps {
  serverId: string;
  serverName: string;
  showHiddenDefault?: boolean;
  onNotify: (msg: string) => void;
  onClose?: () => void;
}

function formatBytes(bytes: number): string {
  if (bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const idx = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const val = bytes / Math.pow(1024, idx);
  return `${idx === 0 ? val : val.toFixed(1)} ${units[idx]}`;
}

export const SftpPanel: React.FC<SftpPanelProps> = ({
  serverId,
  serverName,
  showHiddenDefault = true,
  onNotify,
  onClose,
}) => {
  const [currentPath, setCurrentPath] = useState('');
  const [pathInput, setPathInput] = useState('');
  const [homePath, setHomePath] = useState('');
  const [entries, setEntries] = useState<SFTPFileEntry[]>([]);
  const [showHidden, setShowHidden] = useState(showHiddenDefault);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  // Inline action modals (avoid native browser prompt/confirm)
  const [dialogMode, setDialogMode] = useState<
    | null
    | { kind: 'mkdir' }
    | { kind: 'newfile' }
    | { kind: 'rename'; entry: SFTPFileEntry }
    | { kind: 'chmod'; entry: SFTPFileEntry }
    | { kind: 'delete'; entry: SFTPFileEntry }
  >(null);
  const [dialogInput, setDialogInput] = useState('');

  // Inline text file editor
  const [editorState, setEditorState] = useState<{
    path: string;
    content: string;
    saving: boolean;
  } | null>(null);

  const uploadInputRef = useRef<HTMLInputElement | null>(null);

  const loadDirectory = useCallback(
    async (targetPath: string) => {
      setLoading(true);
      setError('');
      try {
        const res = await api.sftpList(serverId, targetPath);
        setCurrentPath(res.current_path);
        setPathInput(res.current_path);
        setHomePath(res.home_path);
        setEntries(res.entries || []);
      } catch (err: any) {
        setError(err?.message || '读取远程目录失败');
      } finally {
        setLoading(false);
      }
    },
    [serverId]
  );

  useEffect(() => {
    void loadDirectory('');
  }, [loadDirectory]);

  const navigateUp = () => {
    if (!currentPath || currentPath === '/') return;
    const idx = currentPath.lastIndexOf('/');
    const parent = idx <= 0 ? '/' : currentPath.slice(0, idx);
    void loadDirectory(parent);
  };

  const handleUploadChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = '';
    if (!file) return;
    setLoading(true);
    setError('');
    try {
      await api.sftpUpload(serverId, currentPath, file);
      onNotify(`已上传 ${file.name}`);
      await loadDirectory(currentPath);
    } catch (err: any) {
      setError(err?.message || '上传失败');
      setLoading(false);
    }
  };

  const handleDownload = async (entry: SFTPFileEntry) => {
    setError('');
    try {
      const { blob, filename } = await api.sftpDownloadBlob(serverId, entry.path);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename || entry.name;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      onNotify(`已通过端到端加密隧道下载 ${entry.name}`);
    } catch (err: any) {
      setError(err?.message || '端到端加密下载文件失败');
    }
  };

  const handleOpenTextEditor = async (entry: SFTPFileEntry) => {
    setError('');
    try {
      const res = await api.sftpRead(serverId, entry.path);
      setEditorState({ path: res.path, content: res.content, saving: false });
    } catch (err: any) {
      setError(err?.message || '打开文本文件失败');
    }
  };

  const handleSaveEditor = async () => {
    if (!editorState) return;
    setEditorState({ ...editorState, saving: true });
    try {
      await api.sftpWrite(serverId, editorState.path, editorState.content);
      onNotify(`已保存 ${editorState.path}`);
      setEditorState(null);
      await loadDirectory(currentPath);
    } catch (err: any) {
      setError(err?.message || '保存远程文件失败');
      setEditorState((prev) => (prev ? { ...prev, saving: false } : null));
    }
  };

  const handleDialogConfirm = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!dialogMode) return;
    const base = currentPath === '/' ? '' : currentPath;
    try {
      if (dialogMode.kind === 'mkdir') {
        if (!dialogInput.trim()) return;
        await api.sftpMkdir(serverId, `${base}/${dialogInput.trim()}`);
        onNotify(`已创建目录 ${dialogInput.trim()}`);
      } else if (dialogMode.kind === 'newfile') {
        if (!dialogInput.trim()) return;
        const target = `${base}/${dialogInput.trim()}`;
        await api.sftpWrite(serverId, target, '');
        setDialogMode(null);
        await loadDirectory(currentPath);
        setEditorState({ path: target, content: '', saving: false });
        return;
      } else if (dialogMode.kind === 'rename') {
        if (!dialogInput.trim()) return;
        const parent = dialogMode.entry.path.slice(0, dialogMode.entry.path.lastIndexOf('/')) || '';
        await api.sftpRename(serverId, dialogMode.entry.path, `${parent}/${dialogInput.trim()}`);
        onNotify('重命名成功');
      } else if (dialogMode.kind === 'chmod') {
        await api.sftpChmod(serverId, dialogMode.entry.path, dialogInput.trim());
        onNotify(`权限已更新为 ${dialogInput.trim()}`);
      } else if (dialogMode.kind === 'delete') {
        await api.sftpDelete(serverId, dialogMode.entry.path);
        onNotify(`已删除 ${dialogMode.entry.name}`);
      }
      setDialogMode(null);
      await loadDirectory(currentPath);
    } catch (err: any) {
      setError(err?.message || 'SFTP 操作失败');
      setDialogMode(null);
    }
  };

  const visibleEntries = entries.filter((item) => showHidden || !item.name.startsWith('.'));

  return (
    <div className="sftp-container" id={`sftp-panel-${serverId}`}>
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '10px 14px',
          borderBottom: '1px solid var(--border-subtle)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0 }}>
          <strong style={{ fontSize: 13.5 }}>SFTP 安全文件管理</strong>
          <span className="tag-chip">{serverName}</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <button
            type="button"
            className="btn btn-sm"
            onClick={() => setShowHidden(!showHidden)}
            title="显示或隐藏以点号开头的文件"
          >
            {showHidden ? '隐藏 .*' : '显示 .*'}
          </button>
          {onClose && (
            <button type="button" className="btn btn-ghost btn-sm btn-icon" onClick={onClose}>
              <X size={15} />
            </button>
          )}
        </div>
      </div>

      <div className="sftp-bar">
        <button
          type="button"
          className="btn btn-sm btn-icon"
          onClick={navigateUp}
          title="返回上级目录"
        >
          <ArrowUp size={14} />
        </button>
        <button
          type="button"
          className="btn btn-sm btn-icon"
          onClick={() => void loadDirectory(homePath || '~')}
          title="主目录"
        >
          <Home size={14} />
        </button>
        <form
          style={{ display: 'flex', flex: 1, minWidth: 150 }}
          onSubmit={(e) => {
            e.preventDefault();
            void loadDirectory(pathInput);
          }}
        >
          <input
            className="sftp-path-input"
            value={pathInput}
            onChange={(e) => setPathInput(e.target.value)}
            placeholder="/root"
          />
        </form>
        <button
          type="button"
          className="btn btn-sm btn-icon"
          onClick={() => void loadDirectory(currentPath)}
          title="刷新"
        >
          <RefreshCw size={13} />
        </button>
        <input
          ref={uploadInputRef}
          type="file"
          style={{ display: 'none' }}
          onChange={handleUploadChange}
        />
        <button
          type="button"
          className="btn btn-sm btn-primary"
          onClick={() => uploadInputRef.current?.click()}
        >
          <Upload size={13} /> 上传
        </button>
        <button
          type="button"
          className="btn btn-sm"
          onClick={() => {
            setDialogInput('');
            setDialogMode({ kind: 'mkdir' });
          }}
          title="新建文件夹"
        >
          <FolderPlus size={13} />
        </button>
        <button
          type="button"
          className="btn btn-sm"
          onClick={() => {
            setDialogInput('');
            setDialogMode({ kind: 'newfile' });
          }}
          title="新建空白文本文件"
        >
          <FilePlus size={13} />
        </button>
      </div>

      {error && (
        <div className="alert alert-error" style={{ margin: '10px 14px 0' }}>
          <span style={{ flex: 1 }}>{error}</span>
          <button type="button" className="btn btn-ghost btn-sm btn-icon" onClick={() => setError('')}>
            <X size={13} />
          </button>
        </div>
      )}

      <div className="sftp-table-wrap">
        <table className="data-table">
          <thead>
            <tr>
              <th>名称</th>
              <th>大小</th>
              <th>权限</th>
              <th style={{ textAlign: 'right' }}>操作</th>
            </tr>
          </thead>
          <tbody>
            {loading && entries.length === 0 ? (
              <tr>
                <td colSpan={4} style={{ textAlign: 'center', padding: 28, color: 'var(--text-muted)' }}>
                  正在通过加密 SSH 隧道读取目录...
                </td>
              </tr>
            ) : visibleEntries.length === 0 ? (
              <tr>
                <td colSpan={4} style={{ textAlign: 'center', padding: 28, color: 'var(--text-muted)' }}>
                  当前目录为空
                </td>
              </tr>
            ) : (
              visibleEntries.map((entry) => (
                <tr key={entry.path}>
                  <td>
                    <div
                      className="sftp-name-cell"
                      onClick={() => {
                        if (entry.is_dir) {
                          void loadDirectory(entry.path);
                        } else {
                          void handleOpenTextEditor(entry);
                        }
                      }}
                    >
                      {entry.is_dir ? (
                        <Folder size={15} style={{ color: 'var(--accent-teal)', flexShrink: 0 }} />
                      ) : (
                        <FileText size={15} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />
                      )}
                      <span style={{ wordBreak: 'break-all' }}>{entry.name}</span>
                    </div>
                  </td>
                  <td className="mono" style={{ fontSize: 12, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                    {entry.is_dir ? '—' : formatBytes(entry.size)}
                  </td>
                  <td className="mono" style={{ fontSize: 11.5, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                    {entry.octal_perm}
                  </td>
                  <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                    <div style={{ display: 'inline-flex', gap: 3 }}>
                      {!entry.is_dir && (
                        <>
                          <button
                            type="button"
                            className="btn btn-ghost btn-sm btn-icon"
                            title="在线文本编辑"
                            onClick={() => void handleOpenTextEditor(entry)}
                          >
                            <Edit3 size={13} />
                          </button>
                          <button
                            type="button"
                            className="btn btn-ghost btn-sm btn-icon"
                            title="下载文件"
                            onClick={() => void handleDownload(entry)}
                          >
                            <Download size={13} />
                          </button>
                        </>
                      )}
                      <button
                        type="button"
                        className="btn btn-ghost btn-sm btn-icon"
                        title="修改权限 (chmod)"
                        onClick={() => {
                          setDialogInput(entry.octal_perm);
                          setDialogMode({ kind: 'chmod', entry });
                        }}
                      >
                        <Shield size={13} />
                      </button>
                      <button
                        type="button"
                        className="btn btn-ghost btn-sm btn-icon"
                        title="重命名"
                        onClick={() => {
                          setDialogInput(entry.name);
                          setDialogMode({ kind: 'rename', entry });
                        }}
                      >
                        <span style={{ fontSize: 11, fontWeight: 600 }}>Aa</span>
                      </button>
                      <button
                        type="button"
                        className="btn btn-ghost btn-sm btn-icon"
                        title="删除"
                        style={{ color: 'var(--danger-text)' }}
                        onClick={() => setDialogMode({ kind: 'delete', entry })}
                      >
                        <Trash2 size={13} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Action Sub-Modal */}
      {dialogMode && (
        <div className="modal-backdrop">
          <form className="modal-panel" style={{ maxWidth: 400 }} onSubmit={handleDialogConfirm}>
            <div className="modal-header">
              <h3>
                {dialogMode.kind === 'mkdir' && '新建远程目录'}
                {dialogMode.kind === 'newfile' && '新建远程文本文件'}
                {dialogMode.kind === 'rename' && `重命名 ${dialogMode.entry.name}`}
                {dialogMode.kind === 'chmod' && `修改权限 (${dialogMode.entry.name})`}
                {dialogMode.kind === 'delete' && '确认删除远程路径'}
              </h3>
              <button
                type="button"
                className="btn btn-ghost btn-sm btn-icon"
                onClick={() => setDialogMode(null)}
              >
                <X size={15} />
              </button>
            </div>
            <div className="modal-body">
              {dialogMode.kind === 'delete' ? (
                <p style={{ fontSize: 13.5 }}>
                  确定要永久删除远程路径 <code className="mono">{dialogMode.entry.path}</code> 吗？此操作不可撤销。
                </p>
              ) : (
                <div className="field" style={{ marginBottom: 0 }}>
                  <label className="field-label">
                    {dialogMode.kind === 'chmod' ? '八进制权限值 (如 0644 / 0755)' : '输入名称'}
                  </label>
                  <input
                    className="input"
                    value={dialogInput}
                    onChange={(e) => setDialogInput(e.target.value)}
                    autoFocus
                  />
                </div>
              )}
            </div>
            <div className="modal-footer">
              <button type="button" className="btn" onClick={() => setDialogMode(null)}>
                取消
              </button>
              <button
                type="submit"
                className={`btn ${dialogMode.kind === 'delete' ? 'btn-danger' : 'btn-primary'}`}
              >
                {dialogMode.kind === 'delete' ? '确认删除' : '确定'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Inline Remote Text Editor Modal */}
      {editorState && (
        <div className="modal-backdrop">
          <div className="modal-panel wide">
            <div className="modal-header">
              <div>
                <h3>在线安全文件编辑</h3>
                <span className="mono" style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                  {editorState.path}
                </span>
              </div>
              <button
                type="button"
                className="btn btn-ghost btn-sm btn-icon"
                onClick={() => setEditorState(null)}
              >
                <X size={16} />
              </button>
            </div>
            <div className="modal-body">
              <textarea
                className="textarea mono"
                style={{ minHeight: 380, fontSize: 12.5, lineHeight: 1.55 }}
                value={editorState.content}
                onChange={(e) => setEditorState({ ...editorState, content: e.target.value })}
                spellCheck={false}
              />
            </div>
            <div className="modal-footer">
              <button type="button" className="btn" onClick={() => setEditorState(null)}>
                取消
              </button>
              <button
                type="button"
                className="btn btn-primary"
                disabled={editorState.saving}
                onClick={() => void handleSaveEditor()}
              >
                <Save size={14} />
                {editorState.saving ? '正在写入远程主机...' : '保存修改'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

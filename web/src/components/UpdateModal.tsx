import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  AlertTriangle,
  ArrowUpCircle,
  Check,
  CheckCircle2,
  Container,
  Copy,
  Download,
  ExternalLink,
  Globe,
  RefreshCw,
  RotateCcw,
  Settings,
  ShieldCheck,
  X,
} from 'lucide-react';
import { ApiError, api } from '../api';
import { copyTextToClipboard } from '../utils/clipboard';
import type { UpdateJobStage, UpdateOverviewResponse } from '../types';

interface UpdateModalProps {
  open: boolean;
  overview: UpdateOverviewResponse | null;
  onClose: () => void;
  onOverviewChange: (ov: UpdateOverviewResponse) => void;
  onOpenSettings: () => void;
  onNotify: (msg: string) => void;
}

const ACTIVE_JOB_STAGES = new Set<UpdateJobStage>([
  'probing',
  'downloading',
  'verifying',
  'self_checking',
  'replacing',
  'restarting',
]);

function formatSize(bytes?: number): string {
  const n = bytes || 0;
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

function formatSpeed(bps?: number): string {
  const n = bps || 0;
  if (n <= 0) return '';
  return `${formatSize(n)}/s`;
}

function stageLabel(stage?: UpdateJobStage): string {
  switch (stage) {
    case 'probing':
      return '1/5 探测国内最优线路';
    case 'verifying':
      return '2/5 获取并校验 SHA256SUMS';
    case 'downloading':
      return '3/5 加速流式下载新版本';
    case 'self_checking':
      return '4/5 新二进制格式与启动自检';
    case 'replacing':
      return '5/5 备份旧版并原子替换';
    case 'restarting':
      return '正在刷盘并优雅重启服务';
    case 'completed':
      return '更新完成';
    case 'failed':
      return '更新失败';
    default:
      return '就绪';
  }
}

function checksumSourceText(src?: string): string {
  switch (src) {
    case 'official_github':
      return 'GitHub 官方校验清单';
    case 'cross_verified_mirrors':
      return '多镜像独立交叉一致';
    case 'custom_mirror':
      return '自定义加速镜像';
    default:
      return src || '';
  }
}

export const UpdateModal: React.FC<UpdateModalProps> = ({
  open,
  overview,
  onClose,
  onOverviewChange,
  onOpenSettings,
  onNotify,
}) => {
  const [checking, setChecking] = useState(false);
  const [startingUpdate, setStartingUpdate] = useState(false);
  const [sshConfirmCount, setSshConfirmCount] = useState<number>(0);
  const [waitingReconnect, setWaitingReconnect] = useState(false);
  const [reconnectedVersion, setReconnectedVersion] = useState<string>('');
  const [copiedKey, setCopiedKey] = useState<string>('');
  const [errorMsg, setErrorMsg] = useState<string>('');
  const reconnectTimerRef = useRef<number | null>(null);

  const jobStage = overview?.job?.stage || 'idle';
  const isJobRunning = ACTIVE_JOB_STAGES.has(jobStage);

  const stopReconnectPoll = useCallback(() => {
    if (reconnectTimerRef.current !== null) {
      window.clearInterval(reconnectTimerRef.current);
      reconnectTimerRef.current = null;
    }
  }, []);

  const beginReconnectPoll = useCallback(
    (targetVersion: string) => {
      if (reconnectTimerRef.current !== null) return;
      setWaitingReconnect(true);
      const started = Date.now();
      reconnectTimerRef.current = window.setInterval(async () => {
        // Give up only after 90s
        if (Date.now() - started > 90_000) {
          stopReconnectPoll();
          setWaitingReconnect(false);
          setErrorMsg('等待新版本重启超时，请手动刷新页面确认服务状态');
          return;
        }
        try {
          const h = await api.getHealth();
          if (h.ok) {
            const ver = h.version || '';
            // If we waited at least 1.5s and either version changed or server came back healthy
            if (Date.now() - started > 1500 && (!targetVersion || ver === targetVersion || ver !== overview?.current.version)) {
              stopReconnectPoll();
              setReconnectedVersion(ver || targetVersion);
              onNotify(`服务已重启并上线 ${ver || targetVersion}，即将自动刷新页面`);
              window.setTimeout(() => {
                window.location.reload();
              }, 1200);
            }
          }
        } catch {
          // Expected while server is restarting
        }
      }, 1200);
    },
    [onNotify, overview?.current.version, stopReconnectPoll]
  );

  useEffect(() => {
    return () => {
      stopReconnectPoll();
    };
  }, [stopReconnectPoll]);

  // Poll backend update status while a self-update job is active
  useEffect(() => {
    if (!open || !isJobRunning) return;
    if (jobStage === 'restarting') {
      beginReconnectPoll(overview?.job?.target_version || overview?.latest_release?.tag_name || '');
      return;
    }

    const timer = window.setInterval(async () => {
      try {
        const next = await api.getUpdateStatus();
        onOverviewChange(next);
        if (next.job?.stage === 'restarting') {
          beginReconnectPoll(next.job.target_version || next.latest_release?.tag_name || '');
        }
      } catch {
        // Server likely already entering restart
        if (jobStage === 'replacing' || jobStage === 'self_checking') {
          beginReconnectPoll(overview?.job?.target_version || overview?.latest_release?.tag_name || '');
        }
      }
    }, 650);

    return () => window.clearInterval(timer);
  }, [
    open,
    isJobRunning,
    jobStage,
    overview?.job?.target_version,
    overview?.latest_release?.tag_name,
    onOverviewChange,
    beginReconnectPoll,
  ]);

  if (!open) return null;

  const handleCheckNow = async () => {
    setChecking(true);
    setErrorMsg('');
    try {
      const res = await api.checkUpdateNow(true);
      onOverviewChange(res);
      if (res.last_error) {
        setErrorMsg(res.last_error);
      } else if (res.update_available && res.latest_release) {
        onNotify(`检测到新版本 ${res.latest_release.tag_name}`);
      } else {
        onNotify('已完成检测，当前已是最新版本');
      }
    } catch (err: any) {
      setErrorMsg(err?.message || '检查更新失败');
    } finally {
      setChecking(false);
    }
  };

  const handleApplyUpdate = async (confirmDisconnectSSH = false) => {
    setStartingUpdate(true);
    setErrorMsg('');
    try {
      const res = await api.applyUpdate(confirmDisconnectSSH);
      setSshConfirmCount(0);
      onOverviewChange(res.status);
    } catch (err: any) {
      if (err instanceof ApiError && err.code === 'ACTIVE_SSH_SESSIONS') {
        setSshConfirmCount(err.activeSSHTabs || overview?.active_ssh_tabs || 1);
      } else {
        setErrorMsg(err?.message || '启动自动更新失败');
      }
    } finally {
      setStartingUpdate(false);
    }
  };

  const handleSkipVersion = async (tag: string) => {
    try {
      const res = await api.skipUpdateVersion(tag);
      onOverviewChange(res.status);
      onNotify(tag ? `已忽略版本 ${tag} 的提醒` : '已恢复版本更新提醒');
      if (tag) onClose();
    } catch (err: any) {
      onNotify(err?.message || '操作失败');
    }
  };

  const handleCopy = async (key: string, text: string) => {
    try {
      await copyTextToClipboard(text);
      setCopiedKey(key);
      onNotify('升级命令已复制到剪贴板');
      window.setTimeout(() => setCopiedKey((prev) => (prev === key ? '' : prev)), 1800);
    } catch {
      onNotify('复制失败，请手动选中命令复制');
    }
  };

  const rel = overview?.latest_release;
  const caps = overview?.capabilities;
  const job = overview?.job;
  const activeMirror = overview?.active_mirror;

  const deployLabel = caps?.in_docker
    ? 'Docker 容器'
    : caps?.deploy_mode === 'desktop'
      ? `Windows 桌面版 (${caps.goarch})`
      : `独立服务端 (${caps?.goos || 'linux'}/${caps?.goarch || 'amd64'})`;

  return (
    <div
      className="modal-backdrop"
      role="dialog"
      aria-modal="true"
      aria-labelledby="update-modal-title"
      onClick={(e) => {
        if (e.target === e.currentTarget && !isJobRunning && !waitingReconnect) {
          onClose();
        }
      }}
    >
      <div className="modal-panel wide" id="system-update-modal">
        <div className="modal-header">
          <h3 id="update-modal-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <ArrowUpCircle size={18} style={{ color: 'var(--accent-teal)' }} />
            版本检查与自动更新
          </h3>
          <button
            type="button"
            className="btn btn-ghost btn-sm btn-icon"
            onClick={onClose}
            disabled={isJobRunning || waitingReconnect}
            title="关闭"
          >
            <X size={16} />
          </button>
        </div>

        <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          {/* Version Summary Strip */}
          <div className="update-summary-grid">
            <div className="update-summary-cell">
              <span className="update-summary-label">当前运行版本</span>
              <div className="update-summary-val mono">
                {overview?.current.version || 'dev'}
                {overview?.current.is_dev && <span className="tag-chip amber">开发版</span>}
              </div>
              <span className="update-summary-sub">{deployLabel}</span>
            </div>

            <div className="update-summary-cell">
              <span className="update-summary-label">GitHub 最新版本</span>
              <div className="update-summary-val mono">
                {rel ? rel.tag_name : '尚未检测'}
                {rel?.prerelease && <span className="tag-chip amber">Pre-release</span>}
                {overview?.update_available && <span className="tag-chip teal">可更新</span>}
                {rel && !overview?.update_available && !overview?.current.is_dev && (
                  <span className="tag-chip">已是最新</span>
                )}
              </div>
              <span className="update-summary-sub">
                {rel?.published_at
                  ? `发布于 ${new Date(rel.published_at).toLocaleString('zh-CN')}`
                  : overview?.last_checked_at
                    ? `最近检测 ${new Date(overview.last_checked_at).toLocaleString('zh-CN')}`
                    : '点击下方按钮立即检查'}
              </span>
            </div>

            <div className="update-summary-cell">
              <span className="update-summary-label">当前优选加速线路</span>
              <div className="update-summary-val" style={{ fontSize: 13 }}>
                <Globe size={13.5} style={{ color: 'var(--accent-teal)', flexShrink: 0 }} />
                <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {activeMirror ? activeMirror.name : '自动择优待探测'}
                </span>
              </div>
              <span className="update-summary-sub mono">
                {activeMirror?.reachable && activeMirror.latency_ms > 0
                  ? `${activeMirror.latency_ms} ms · ${activeMirror.region === 'cn' ? '国内加速' : '官方直连'}`
                  : overview?.settings.mirror_mode === 'direct'
                    ? '仅官方直连模式'
                    : overview?.settings.mirror_mode === 'custom'
                      ? '自定义镜像模式'
                      : '自动竞速 + 容灾回退'}
              </span>
            </div>
          </div>

          {/* Errors */}
          {(errorMsg || overview?.last_error) && (
            <div className="alert alert-error">
              <AlertTriangle size={15} style={{ flexShrink: 0, marginTop: 1 }} />
              <span>{errorMsg || overview?.last_error}</span>
            </div>
          )}

          {/* Active SSH Terminal Confirmation Prompt */}
          {sshConfirmCount > 0 && !isJobRunning && (
            <div className="alert alert-warn" style={{ flexDirection: 'column', alignItems: 'stretch', gap: 10 }}>
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8 }}>
                <AlertTriangle size={16} style={{ flexShrink: 0, marginTop: 2 }} />
                <div>
                  <strong>当前存在 {sshConfirmCount} 个活跃 SSH 终端会话</strong>
                  <div style={{ fontSize: 12.5, marginTop: 2 }}>
                    自动更新在完成下载与 SHA-256 校验后将重启 ServerNeedSafe 进程，所有交互式 SSH 终端连接会被中断（7×24 后台监控与巡检将在新版本启动后自动恢复）。
                  </div>
                </div>
              </div>
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
                <button type="button" className="btn btn-sm" onClick={() => setSshConfirmCount(0)}>
                  暂不更新
                </button>
                <button
                  type="button"
                  id="update-confirm-ssh-disconnect-btn"
                  className="btn btn-sm btn-primary"
                  disabled={startingUpdate}
                  onClick={() => void handleApplyUpdate(true)}
                >
                  确认断开终端并立即更新
                </button>
              </div>
            </div>
          )}

          {/* Real-time Self-Update Job Progress */}
          {(isJobRunning || jobStage === 'failed' || jobStage === 'completed' || waitingReconnect) && (
            <div className={`update-progress-card ${jobStage === 'failed' ? 'error' : ''}`}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontWeight: 600, fontSize: 13 }}>
                  {reconnectedVersion ? (
                    <CheckCircle2 size={15} style={{ color: 'var(--status-online)' }} />
                  ) : jobStage === 'failed' ? (
                    <AlertTriangle size={15} style={{ color: 'var(--danger-text)' }} />
                  ) : (
                    <RefreshCw size={14} className="spin" style={{ color: 'var(--accent-teal)' }} />
                  )}
                  <span>
                    {reconnectedVersion
                      ? `新版本 ${reconnectedVersion} 已上线，正在刷新界面...`
                      : waitingReconnect
                        ? '服务正在优雅重启，等待新版本恢复响应...'
                        : stageLabel(job?.stage)}
                  </span>
                </div>
                {job?.stage === 'downloading' && (
                  <span className="mono" style={{ fontSize: 12, color: 'var(--accent-teal)' }}>
                    {job.total_bytes > 0
                      ? `${job.progress_percent.toFixed(1)}% · ${formatSize(job.downloaded_bytes)} / ${formatSize(job.total_bytes)}`
                      : formatSize(job.downloaded_bytes)}
                    {job.speed_bps > 0 ? ` · ${formatSpeed(job.speed_bps)}` : ''}
                  </span>
                )}
              </div>

              {(isJobRunning || waitingReconnect) && (
                <div className="update-progress-track">
                  <div
                    className={`update-progress-fill ${
                      job?.stage !== 'downloading' || !job?.total_bytes ? 'indeterminate' : ''
                    }`}
                    style={{
                      width:
                        job?.stage === 'downloading' && job.total_bytes > 0
                          ? `${Math.max(4, Math.min(100, job.progress_percent))}%`
                          : '45%',
                    }}
                  />
                </div>
              )}

              <div style={{ fontSize: 12.5, color: 'var(--text-secondary)' }}>
                {job?.message || (job?.error ? `失败原因：${job.error}` : '')}
              </div>

              {(job?.mirror_name || job?.expected_sha256) && (
                <div className="update-progress-meta mono">
                  {job.mirror_name && <span>下载线路：{job.mirror_name}</span>}
                  {job.checksum_source && <span>校验来源：{checksumSourceText(job.checksum_source)}</span>}
                  {job.expected_sha256 && <span>SHA-256：{job.expected_sha256.slice(0, 16)}…</span>}
                </div>
              )}
            </div>
          )}

          {/* Docker Guided Upgrade Commands */}
          {caps?.in_docker && overview?.docker_commands && (
            <div className="update-docker-card">
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                <Container size={16} style={{ color: 'var(--accent-teal)' }} />
                <strong style={{ fontSize: 13.5 }}>Docker 宿主机一键升级命令（含国内 GHCR 加速）</strong>
              </div>
              <p style={{ fontSize: 12.5, color: 'var(--text-muted)', marginBottom: 12 }}>
                为坚持非 Root 容器最小权限与镜像不可变原则，容器内不直接改写二进制；请在宿主机项目目录执行以下任一命令升级（`/data` 加密凭据与监控历史完全保留）：
              </p>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {overview.docker_commands.china_mirrors.map((m, idx) => (
                  <div key={m.image} className="update-docker-cmd-item">
                    <div className="update-docker-cmd-head">
                      <span style={{ fontWeight: 560, fontSize: 12.5 }}>{m.name}</span>
                      <button
                        type="button"
                        className="btn btn-sm btn-ghost"
                        onClick={() => void handleCopy(`cn-${idx}`, m.command)}
                      >
                        {copiedKey === `cn-${idx}` ? <Check size={13} /> : <Copy size={13} />}
                        {copiedKey === `cn-${idx}` ? '已复制' : '复制命令'}
                      </button>
                    </div>
                    <pre className="mcp-code-block compact">{m.command}</pre>
                  </div>
                ))}

                <div className="update-docker-cmd-item">
                  <div className="update-docker-cmd-head">
                    <span style={{ fontWeight: 560, fontSize: 12.5 }}>GitHub 官方 GHCR 直连升级</span>
                    <button
                      type="button"
                      className="btn btn-sm btn-ghost"
                      onClick={() => void handleCopy('official', overview.docker_commands!.official_pull)}
                    >
                      {copiedKey === 'official' ? <Check size={13} /> : <Copy size={13} />}
                      {copiedKey === 'official' ? '已复制' : '复制命令'}
                    </button>
                  </div>
                  <pre className="mcp-code-block compact">{overview.docker_commands.official_pull}</pre>
                </div>
              </div>
            </div>
          )}

          {/* Non-Docker Cannot Self-Update Notice (e.g. dev build or read-only dir) */}
          {caps && !caps.in_docker && !caps.can_self_update && caps.cannot_update_reason && (
            <div className="alert alert-info">
              <ShieldCheck size={15} style={{ flexShrink: 0, marginTop: 1 }} />
              <span>{caps.cannot_update_reason}</span>
            </div>
          )}

          {/* Release Notes */}
          {rel && (
            <div>
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  marginBottom: 6,
                }}
              >
                <span style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--text-secondary)' }}>
                  更新日志 ({rel.name || rel.tag_name})
                </span>
                {rel.html_url && (
                  <a
                    href={rel.html_url}
                    target="_blank"
                    rel="noreferrer"
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: 4,
                      fontSize: 12,
                      color: 'var(--accent-teal)',
                      textDecoration: 'none',
                    }}
                  >
                    在 GitHub 查看 Release <ExternalLink size={12} />
                  </a>
                )}
              </div>
              <div className="update-notes-box">
                {rel.body ? rel.body : '本次发布未附带详细文字说明，可前往 GitHub Release 页面查看完整提交记录。'}
              </div>
            </div>
          )}

          {caps?.can_self_update && (
            <div style={{ fontSize: 12, color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 6 }}>
              <ShieldCheck size={13.5} style={{ color: 'var(--accent-teal)', flexShrink: 0 }} />
              <span>
                强制安全机制：下载前验证 <code className="mono">SHA256SUMS.txt</code>（优先直连官方或跨多镜像交叉一致）+ 新二进制 <code className="mono">--version</code> 自检 + 旧版自动备份回滚。
              </span>
            </div>
          )}
        </div>

        <div className="modal-footer" style={{ justifyContent: 'space-between', flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <button
              type="button"
              className="btn btn-sm"
              disabled={checking || isJobRunning || waitingReconnect}
              onClick={() => void handleCheckNow()}
            >
              <RefreshCw size={13.5} className={checking ? 'spin' : ''} />
              {checking ? '正在检测...' : '重新检测'}
            </button>
            <button
              type="button"
              className="btn btn-sm btn-ghost"
              disabled={isJobRunning || waitingReconnect}
              onClick={() => {
                onClose();
                onOpenSettings();
              }}
            >
              <Settings size={13.5} /> 加速线路与更新设置
            </button>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            {rel && overview?.update_available && !isJobRunning && !waitingReconnect && (
              overview.skipped ? (
                <button
                  type="button"
                  className="btn btn-sm"
                  onClick={() => void handleSkipVersion('')}
                >
                  <RotateCcw size={13.5} /> 取消忽略
                </button>
              ) : (
                <button
                  type="button"
                  className="btn btn-sm"
                  onClick={() => void handleSkipVersion(rel.tag_name)}
                >
                  忽略此版本
                </button>
              )
            )}

            {caps?.can_self_update && overview?.update_available && (
              <button
                type="button"
                id="update-apply-now-btn"
                className="btn btn-primary"
                disabled={startingUpdate || isJobRunning || waitingReconnect}
                onClick={() => void handleApplyUpdate(false)}
              >
                <Download size={14} />
                {isJobRunning || waitingReconnect ? '正在更新...' : `一键自动更新至 ${rel?.tag_name}`}
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

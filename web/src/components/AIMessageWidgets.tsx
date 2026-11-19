import React, { useState } from 'react';
import {
  ShieldAlert,
  CheckCircle2,
  XCircle,
  Terminal,
  FileCode2,
  ChevronDown,
  ChevronRight,
  BookOpenCheck,
  Sparkles,
  Play,
  Copy,
} from 'lucide-react';
import type {
  AIPendingApproval,
  AIRunbookProposal,
  AIToolCallRecord,
} from '../types';

const TOOL_LABELS: Record<string, string> = {
  probe_server: '主机连通与负载探针',
  exec_ssh_command: 'SSH 远程命令调用',
  sftp_list_dir: 'SFTP 目录结构列举',
  sftp_read_file: 'SFTP 读取远程文件',
  sftp_write_file: 'SFTP 修改远程配置',
  update_host_memory: '归档主机环境画像',
  propose_runbook: '提炼排障技能草案',
};

export const UnifiedDiffViewer: React.FC<{ diff: string }> = ({ diff }) => {
  const lines = diff.replace(/\r\n/g, '\n').split('\n');
  return (
    <div className="diff-viewer" role="region" aria-label="配置文件变更对比">
      {lines.map((line, idx) => {
        let cls = 'diff-line';
        if (line.startsWith('--- ') || line.startsWith('+++ ')) {
          cls += ' meta';
        } else if (line.startsWith('@@')) {
          cls += ' hunk';
        } else if (line.startsWith('+')) {
          cls += ' add';
        } else if (line.startsWith('-')) {
          cls += ' del';
        }
        return (
          <div key={idx} className={cls}>
            {line || ' '}
          </div>
        );
      })}
    </div>
  );
};

export const ToolTraceStep: React.FC<{ tool: AIToolCallRecord }> = ({ tool }) => {
  const [expanded, setExpanded] = useState(false);

  let argSummary = '';
  try {
    const parsed = JSON.parse(tool.arguments || '{}');
    if (parsed.command) argSummary = parsed.command;
    else if (parsed.path) argSummary = parsed.path;
    else if (parsed.title) argSummary = parsed.title;
    else if (parsed.summary) argSummary = parsed.summary;
  } catch {
    argSummary = '';
  }

  const statusBadge = () => {
    switch (tool.status) {
      case 'running':
        return <span className="tag-chip teal">执行中...</span>;
      case 'completed':
      case 'approved':
        return <span className="tag-chip teal">已完成</span>;
      case 'pending_approval':
        return <span className="tag-chip amber">待人工授权</span>;
      case 'rejected':
        return <span className="tag-chip">已拒绝</span>;
      case 'blocked':
        return (
          <span
            className="tag-chip"
            style={{ background: 'var(--danger-soft)', color: 'var(--danger-text)' }}
          >
            高危硬拦截
          </span>
        );
      default:
        return <span className="tag-chip amber">执行异常</span>;
    }
  };

  return (
    <div className="ai-tool-step">
      <div
        className="ai-tool-step-head"
        onClick={() => setExpanded(!expanded)}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') setExpanded(!expanded);
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 7, minWidth: 0, flex: 1 }}>
          {expanded ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
          <span style={{ fontWeight: 600 }}>{TOOL_LABELS[tool.name] || tool.name}</span>
          {argSummary && (
            <span
              className="mono"
              style={{
                color: 'var(--text-muted)',
                fontSize: 11.5,
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap',
              }}
            >
              {argSummary}
            </span>
          )}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>
          {typeof tool.duration_ms === 'number' && tool.duration_ms > 0 && (
            <span className="mono" style={{ color: 'var(--text-muted)', fontSize: 11 }}>
              {tool.duration_ms}ms
            </span>
          )}
          {statusBadge()}
        </div>
      </div>

      {expanded && (
        <div className="ai-tool-step-body">
          {tool.arguments && (
            <div style={{ color: '#94a3b8', marginBottom: tool.output ? 8 : 0 }}>
              参数: {tool.arguments}
            </div>
          )}
          {tool.output ? (
            <div>{tool.output}</div>
          ) : (
            <div style={{ color: '#64748b' }}>暂无额外输出回显</div>
          )}
        </div>
      )}
    </div>
  );
};

interface HITLApprovalCardProps {
  approval: AIPendingApproval;
  busy?: boolean;
  onDecide: (approvalId: string, approve: boolean) => void;
  onInjectTerminal?: (cmd: string) => void;
}

export const HITLApprovalCard: React.FC<HITLApprovalCardProps> = ({
  approval,
  busy,
  onDecide,
  onInjectTerminal,
}) => {
  const isPending = approval.status === 'pending';
  const isApproved = approval.status === 'approved';
  const cardCls = `ai-approval-card ${
    isApproved ? 'resolved-approved' : approval.status === 'rejected' ? 'resolved-rejected' : ''
  }`;

  return (
    <div className={cardCls} data-approval-id={approval.id}>
      <div className="ai-approval-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontWeight: 620, fontSize: 13 }}>
          {isPending ? (
            <ShieldAlert size={16} style={{ color: 'var(--amber-text)' }} />
          ) : isApproved ? (
            <CheckCircle2 size={16} style={{ color: 'var(--accent-teal)' }} />
          ) : (
            <XCircle size={16} style={{ color: 'var(--text-muted)' }} />
          )}
          <span>
            {isPending
              ? '高风险 / 远程状态变更待人工授权'
              : isApproved
              ? '管理员已批准并完成远程执行'
              : '管理员已拒绝该变更操作'}
          </span>
        </div>
        <span className="mono" style={{ fontSize: 11.5, color: 'var(--text-secondary)' }}>
          目标: {(approval.server_names || []).join(', ') || '目标服务器'}
        </span>
      </div>

      <div className="ai-approval-body">
        <div style={{ fontSize: 12.5, color: 'var(--text-secondary)' }}>
          <strong>变更说明：</strong>
          {approval.reason}
        </div>

        {approval.command && (
          <div className="copilot-cmd-box">
            <div style={{ display: 'flex', alignItems: 'center', gap: 7, minWidth: 0, flex: 1 }}>
              <Terminal size={13} style={{ color: '#2dd4bf', flexShrink: 0 }} />
              <code style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                {approval.command}
              </code>
            </div>
            {onInjectTerminal && (
              <button
                type="button"
                className="btn btn-sm copilot-cmd-btn"
                onClick={() => onInjectTerminal(approval.command!)}
                title="将该命令直接发送到当前交互终端手动执行"
              >
                <Play size={11} /> 注入终端
              </button>
            )}
          </div>
        )}

        {approval.file_path && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            <div
              className="mono"
              style={{
                fontSize: 12,
                color: 'var(--text-secondary)',
                display: 'flex',
                alignItems: 'center',
                gap: 6,
                wordBreak: 'break-all',
              }}
            >
              <FileCode2 size={14} style={{ color: 'var(--accent-teal)', flexShrink: 0 }} />
              <span>目标配置文件: {approval.file_path}</span>
            </div>
            {approval.diff_preview && <UnifiedDiffViewer diff={approval.diff_preview} />}
          </div>
        )}

        {approval.execution_out && (
          <div className="ai-tool-step-body" style={{ borderRadius: 6 }}>
            {approval.execution_out}
          </div>
        )}

        {isPending && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 2, flexWrap: 'wrap' }}>
            <button
              type="button"
              className="btn btn-teal btn-sm"
              disabled={busy}
              onClick={() => onDecide(approval.id, true)}
            >
              <CheckCircle2 size={13.5} /> 批准并远程执行
            </button>
            <button
              type="button"
              className="btn btn-sm"
              disabled={busy}
              onClick={() => onDecide(approval.id, false)}
            >
              <XCircle size={13.5} /> 拒绝变更
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

interface RunbookProposalCardProps {
  proposal: AIRunbookProposal;
  busy?: boolean;
  onResolve: (proposalId: string, accept: boolean, syncSnippet: boolean) => void;
}

export const RunbookProposalCard: React.FC<RunbookProposalCardProps> = ({
  proposal,
  busy,
  onResolve,
}) => {
  const isPending = proposal.status === 'pending';
  return (
    <div className="ai-proposal-card">
      <div className="ai-proposal-header">
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 7, minWidth: 0 }}>
          <BookOpenCheck size={15} style={{ color: 'var(--accent-teal)', flexShrink: 0 }} />
          <span style={{ wordBreak: 'break-word' }}>排障经验沉淀草案：{proposal.title}</span>
        </span>
        <span className="tag-chip teal">{proposal.category || '排障技能'}</span>
      </div>
      <div style={{ padding: '12px 14px', display: 'flex', flexDirection: 'column', gap: 8, fontSize: 12.5 }}>
        <div>
          <strong>故障现象：</strong>
          {proposal.symptom}
        </div>
        <div>
          <strong>根因定位：</strong>
          {proposal.root_cause}
        </div>
        {proposal.fix_commands?.length > 0 && (
          <div className="copilot-cmd-box">
            <code style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
              {proposal.fix_commands.join(' && ')}
            </code>
          </div>
        )}
        {isPending ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 4, flexWrap: 'wrap' }}>
            <button
              type="button"
              className="btn btn-teal btn-sm"
              disabled={busy}
              onClick={() => onResolve(proposal.id, true, true)}
            >
              <Sparkles size={13} /> 保存为 Runbook 并同步至快捷指令
            </button>
            <button
              type="button"
              className="btn btn-sm"
              disabled={busy}
              onClick={() => onResolve(proposal.id, true, false)}
            >
              仅保存至技能库
            </button>
            <button
              type="button"
              className="btn btn-ghost btn-sm"
              disabled={busy}
              onClick={() => onResolve(proposal.id, false, false)}
            >
              忽略
            </button>
          </div>
        ) : (
          <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
            {proposal.status === 'accepted'
              ? '已加密归档至保险库 Runbook 技能库'
              : '已忽略该排障技能草案'}
          </div>
        )}
      </div>
    </div>
  );
};

export function extractShellSnippets(content: string): string[] {
  const regex = /```(?:bash|sh|shell|zsh)?\n([\s\S]*?)```/g;
  const out: string[] = [];
  let match: RegExpExecArray | null;
  while ((match = regex.exec(content)) !== null) {
    const cleaned = match[1].trim();
    if (cleaned && cleaned.length < 600) {
      out.push(cleaned);
    }
  }
  return out;
}

export const ShellSnippetActionBar: React.FC<{
  commands: string[];
  onInject?: (cmd: string) => void;
  onNotify?: (msg: string) => void;
}> = ({ commands, onInject, onNotify }) => {
  if (!commands.length) return null;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
      {commands.slice(0, 3).map((cmd, idx) => (
        <div key={idx} className="copilot-cmd-box copilot-snippet-row">
          <code className="copilot-snippet-code" title={cmd}>
            $ {cmd}
          </code>
          <div className="copilot-cmd-actions">
            <button
              type="button"
              className="btn btn-sm copilot-cmd-btn"
              onClick={() => {
                void navigator.clipboard?.writeText(cmd);
                onNotify?.('命令已复制到剪贴板');
              }}
            >
              <Copy size={11} /> 复制
            </button>
            {onInject && (
              <button
                type="button"
                className="btn btn-teal btn-sm copilot-cmd-btn"
                onClick={() => onInject(cmd)}
              >
                <Play size={11} /> 注入当前终端
              </button>
            )}
          </div>
        </div>
      ))}
    </div>
  );
};

function renderInlineFormatting(text: string): React.ReactNode[] {
  const parts = text.split(/(\*\*[^*]+\*\*|`[^`\n]+`)/g);
  return parts.map((part, idx) => {
    if (part.startsWith('**') && part.endsWith('**') && part.length > 4) {
      return <strong key={idx}>{part.slice(2, -2)}</strong>;
    }
    if (part.startsWith('`') && part.endsWith('`') && part.length > 2) {
      return (
        <code
          key={idx}
          className="mono"
          style={{
            padding: '1px 5px',
            borderRadius: 4,
            background: 'var(--bg-muted)',
            border: '1px solid var(--border-subtle)',
            fontSize: '0.91em',
          }}
        >
          {part.slice(1, -1)}
        </code>
      );
    }
    return <React.Fragment key={idx}>{part}</React.Fragment>;
  });
}

export const FormattedMarkdownText: React.FC<{ text: string }> = ({ text }) => {
  const segments = text.split(/(```[\s\S]*?```)/g);
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
      {segments.map((seg, idx) => {
        if (seg.startsWith('```') && seg.endsWith('```')) {
          const inner = seg.replace(/^```[a-zA-Z0-9_-]*\n?/, '').replace(/```$/, '').trim();
          return (
            <pre
              key={idx}
              className="mono"
              style={{
                margin: '2px 0',
                padding: '9px 12px',
                borderRadius: 7,
                background: '#0f172a',
                color: '#e2e8f0',
                fontSize: 12,
                lineHeight: 1.55,
                overflowX: 'auto',
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-all',
              }}
            >
              <code>{inner}</code>
            </pre>
          );
        }
        const trimmed = seg.trim();
        if (!trimmed) return null;
        return (
          <div key={idx} style={{ whiteSpace: 'pre-wrap', lineHeight: 1.62 }}>
            {renderInlineFormatting(trimmed)}
          </div>
        );
      })}
    </div>
  );
};


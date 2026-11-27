import React, { useEffect, useState } from 'react';
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
  FileText,
  Layers,
  Minimize2,
  RotateCcw,
  RefreshCw,
  Pin,
  AlertTriangle,
  Activity,
  BrainCircuit,
} from 'lucide-react';
import type {
  AIAgentsMDProposal,
  AIPendingApproval,
  AIRunbookProposal,
  AITokenUsage,
  AIToolCallRecord,
  SessionContextInspection,
} from '../types';
import { copyTextToClipboard } from '../utils/clipboard';

const TOOL_LABELS: Record<string, string> = {
  probe_server: '主机连通与负载探针',
  exec_ssh_command: 'SSH 远程命令调用',
  sftp_list_dir: 'SFTP 目录结构列举',
  sftp_read_file: 'SFTP 读取远程文件',
  sftp_write_file: 'SFTP 修改远程配置',
  update_host_memory: '归档主机环境画像',
  save_memory: '沉淀长期运维记忆',
  delete_memory: '清理过期长期记忆',
  search_memory: '深度检索历史记忆',
  get_runbook: '调阅 Runbook 详情',
  propose_agents_md_update: '提议修订 AGENTS.md',
  propose_runbook: '提炼排障技能草案',
};

export const MEMORY_CATEGORY_LABELS: Record<string, string> = {
  preference: '管理员偏好',
  topology: '架构拓扑',
  incident: '故障根因',
  change: '重要变更',
  lesson: '运维经验',
};

export const MEMORY_SOURCE_LABELS: Record<string, string> = {
  manual: '人工录入',
  ai: 'AI 自学习',
  approval: '审批变更自动沉淀',
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

export const ReasoningTraceBlock: React.FC<{
  text: string;
  streaming?: boolean;
  defaultOpen?: boolean;
}> = ({ text, streaming = false, defaultOpen = false }) => {
  const [expanded, setExpanded] = useState(defaultOpen || streaming);

  useEffect(() => {
    if (streaming) {
      setExpanded(true);
    }
  }, [streaming]);

  if (!text) return null;

  return (
    <div className={`ai-reasoning-box ${streaming ? 'streaming' : ''}`}>
      <button
        type="button"
        className="ai-reasoning-head"
        onClick={() => setExpanded((prev) => !prev)}
        aria-expanded={expanded}
      >
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
          {expanded ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
          <BrainCircuit size={13} style={{ color: 'var(--accent-teal)' }} />
          <span>{streaming ? '深度思考中...' : '思考过程'}</span>
        </span>
        <span className="mono" style={{ fontSize: 11, color: 'var(--text-muted)' }}>
          {text.length.toLocaleString()} 字
        </span>
      </button>
      {expanded && <div className="ai-reasoning-body">{text}</div>}
    </div>
  );
};

export const MessageUsagePill: React.FC<{ usage?: AITokenUsage | null }> = ({ usage }) => {
  if (!usage) return null;
  const parts: string[] = [];
  if (usage.input_tokens) parts.push(`输入 ${usage.input_tokens.toLocaleString()}`);
  if (usage.output_tokens) parts.push(`输出 ${usage.output_tokens.toLocaleString()}`);
  if (usage.reasoning_tokens) parts.push(`思考 ${usage.reasoning_tokens.toLocaleString()}`);
  if (usage.cached_input_tokens) parts.push(`缓存命中 ${usage.cached_input_tokens.toLocaleString()}`);
  if (parts.length === 0 && usage.total_tokens) {
    parts.push(`总计 ${usage.total_tokens.toLocaleString()}`);
  }
  if (parts.length === 0) return null;

  return (
    <div className="ai-usage-pill mono" title="本次流式响应上游模型实际统计的 Token 用量">
      <Activity size={10.5} />
      <span>{parts.join(' · ')} tok</span>
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
    else if (parsed.query) argSummary = parsed.query;
    else if (parsed.runbook_id) argSummary = parsed.runbook_id;
    else if (parsed.memory_id) argSummary = parsed.memory_id;
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
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            setExpanded(!expanded);
          }
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
  const regex = /```(?:bash|sh|shell|zsh)[ \t]*\r?\n([\s\S]*?)```/gi;
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
              onClick={async () => {
                try {
                  await copyTextToClipboard(cmd);
                  onNotify?.('命令已复制到剪贴板');
                } catch {
                  onNotify?.('浏览器剪贴板写入失败，请手动选中复制');
                }
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

function restoreMaskSentinel(str: string, maskSentinel?: string): string {
  if (!maskSentinel) return str;
  return str.split(maskSentinel).join('***');
}

function renderInlineFormatting(text: string, maskSentinel?: string): React.ReactNode[] {
  const parts = text.split(/(`[^`\n]+`|\*\*\*|\*\*(?!\*)[^*\n]+?(?<!\*)\*\*)/g);
  return parts.map((part, idx) => {
    if (part === '***') {
      return <React.Fragment key={idx}>***</React.Fragment>;
    }
    if (part.startsWith('**') && part.endsWith('**') && part.length > 4) {
      return <strong key={idx}>{restoreMaskSentinel(part.slice(2, -2), maskSentinel)}</strong>;
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
          {restoreMaskSentinel(part.slice(1, -1), maskSentinel)}
        </code>
      );
    }
    return <React.Fragment key={idx}>{restoreMaskSentinel(part, maskSentinel)}</React.Fragment>;
  });
}

export const FormattedMarkdownText: React.FC<{ text: string; maskSentinel?: string }> = ({
  text,
  maskSentinel,
}) => {
  // Support an in-progress (unclosed) fenced code block cleanly during SSE streaming
  const normalized = text.replace(/\r\n/g, '\n');
  const fenceMatches = normalized.match(/```/g);
  const renderText =
    fenceMatches && fenceMatches.length % 2 === 1 ? `${normalized}\n\`\`\`` : normalized;
  const segments = renderText.split(/(```[\s\S]*?```)/g);
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
              <code>{restoreMaskSentinel(inner, maskSentinel)}</code>
            </pre>
          );
        }
        const trimmed = seg.trim();
        if (!trimmed) return null;
        const lines = trimmed.split('\n');
        return (
          <div key={idx} style={{ display: 'flex', flexDirection: 'column', gap: 3, lineHeight: 1.62 }}>
            {lines.map((line, li) => {
              const h1 = line.match(/^#\s+(.+)$/);
              if (h1) {
                return (
                  <div
                    key={li}
                    style={{
                      fontSize: 15.5,
                      fontWeight: 700,
                      color: 'var(--text-primary)',
                      paddingBottom: 4,
                      marginTop: li > 0 ? 6 : 0,
                      borderBottom: '1px solid var(--border-subtle)',
                    }}
                  >
                    {renderInlineFormatting(h1[1], maskSentinel)}
                  </div>
                );
              }
              const h2 = line.match(/^##\s+(.+)$/);
              if (h2) {
                return (
                  <div
                    key={li}
                    style={{
                      fontSize: 14,
                      fontWeight: 680,
                      color: 'var(--text-primary)',
                      marginTop: li > 0 ? 8 : 2,
                    }}
                  >
                    {renderInlineFormatting(h2[1], maskSentinel)}
                  </div>
                );
              }
              const h3 = line.match(/^###\s+(.+)$/);
              if (h3) {
                return (
                  <div
                    key={li}
                    style={{
                      fontSize: 13.2,
                      fontWeight: 650,
                      color: 'var(--accent-teal)',
                      marginTop: li > 0 ? 6 : 2,
                    }}
                  >
                    {renderInlineFormatting(h3[1], maskSentinel)}
                  </div>
                );
              }
              const quote = line.match(/^>\s?(.*)$/);
              if (quote) {
                return (
                  <div
                    key={li}
                    style={{
                      borderLeft: '3px solid var(--accent-teal-border)',
                      paddingLeft: 10,
                      color: 'var(--text-secondary)',
                      whiteSpace: 'pre-wrap',
                    }}
                  >
                    {renderInlineFormatting(quote[1], maskSentinel)}
                  </div>
                );
              }
              if (line.trim() === '') {
                return <div key={li} style={{ height: 4 }} />;
              }
              return (
                <div key={li} style={{ whiteSpace: 'pre-wrap' }}>
                  {renderInlineFormatting(line, maskSentinel)}
                </div>
              );
            })}
          </div>
        );
      })}
    </div>
  );
};

interface AgentsMDProposalCardProps {
  proposal: AIAgentsMDProposal;
  busy?: boolean;
  onResolve: (proposalId: string, accept: boolean) => void;
}

export const AgentsMDProposalCard: React.FC<AgentsMDProposalCardProps> = ({
  proposal,
  busy,
  onResolve,
}) => {
  const isPending = proposal.status === 'pending';
  const isAccepted = proposal.status === 'accepted';
  return (
    <div
      className={`ai-proposal-card ai-agents-proposal-card ${
        isAccepted ? 'resolved-approved' : proposal.status === 'dismissed' ? 'resolved-rejected' : ''
      }`}
      data-agents-proposal-id={proposal.id}
    >
      <div className="ai-proposal-header">
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 7, minWidth: 0 }}>
          <FileText size={15} style={{ color: 'var(--accent-teal)', flexShrink: 0 }} />
          <span style={{ wordBreak: 'break-word' }}>
            全局 AGENTS.md 规范修订建议：{proposal.summary}
          </span>
        </span>
        <span className={`tag-chip ${isPending ? 'amber' : isAccepted ? 'teal' : ''}`}>
          {isPending ? '待审阅合入' : isAccepted ? '已合入生效' : '已忽略'}
        </span>
      </div>
      <div style={{ padding: '12px 14px', display: 'flex', flexDirection: 'column', gap: 9, fontSize: 12.5 }}>
        <div style={{ color: 'var(--text-secondary)' }}>
          <strong>修订原因：</strong>
          {proposal.reason}
        </div>
        {proposal.diff_preview && <UnifiedDiffViewer diff={proposal.diff_preview} />}
        {isPending ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 2, flexWrap: 'wrap' }}>
            <button
              type="button"
              className="btn btn-teal btn-sm"
              disabled={busy}
              onClick={() => onResolve(proposal.id, true)}
            >
              <CheckCircle2 size={13.5} /> 批准并合入全局 AGENTS.md
            </button>
            <button
              type="button"
              className="btn btn-ghost btn-sm"
              disabled={busy}
              onClick={() => onResolve(proposal.id, false)}
            >
              <XCircle size={13.5} /> 忽略此建议
            </button>
          </div>
        ) : (
          <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
            {isAccepted
              ? '已加密合入全局 AGENTS.md，后续所有会话与后台巡检立即生效'
              : '已忽略该 AGENTS.md 修订建议，现有规范保持不变'}
          </div>
        )}
      </div>
    </div>
  );
};

export const CompactionDivider: React.FC<{
  compactedUntilCount: number;
  compactionCount?: number;
  onInspect: () => void;
}> = ({ compactedUntilCount, compactionCount, onInspect }) => (
  <div className="ai-compaction-divider" role="separator">
    <span className="ai-compaction-line" />
    <button
      type="button"
      className="ai-compaction-pill"
      onClick={onInspect}
      title="点击打开上下文透视查看无损滚动摘要全文"
    >
      <Minimize2 size={11.5} />
      <span>
        以上 {compactedUntilCount} 条历史已无损压缩为滚动摘要
        {compactionCount && compactionCount > 1 ? `（第 ${compactionCount} 次）` : ''}
      </span>
    </button>
    <span className="ai-compaction-line" />
  </div>
);

interface ContextInspectorModalProps {
  inspection: SessionContextInspection | null;
  loading?: boolean;
  compacting?: boolean;
  onRefresh: () => void;
  onCompact: (reset?: boolean) => void;
  onClose: () => void;
  onOpenAgentsMD?: () => void;
}

export const ContextInspectorModal: React.FC<ContextInspectorModalProps> = ({
  inspection,
  loading,
  compacting,
  onRefresh,
  onCompact,
  onClose,
  onOpenAgentsMD,
}) => {
  const [summaryExpanded, setSummaryExpanded] = useState(true);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  const usagePct = Math.min(100, Math.max(0, inspection?.usage_percent ?? 0));
  const barTone =
    usagePct >= 75 ? 'var(--danger-text)' : usagePct >= 55 ? 'var(--amber-text)' : 'var(--accent-teal)';

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div
        className="modal-panel wide"
        id="ai-context-inspector-modal"
        style={{ maxWidth: 820 }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Layers size={16} style={{ color: 'var(--accent-teal)' }} />
            <h3 style={{ margin: 0 }}>对话上下文透视与滚动压缩 (Context Inspector)</h3>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <button
              type="button"
              className="btn btn-ghost btn-sm"
              disabled={loading}
              onClick={onRefresh}
              title="重新测算当前注入上下文"
            >
              <RefreshCw size={13} /> 刷新
            </button>
            <button type="button" className="btn btn-ghost btn-sm" onClick={onClose}>
              关闭
            </button>
          </div>
        </div>

        <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          {loading && !inspection ? (
            <div style={{ padding: '28px 12px', textAlign: 'center', color: 'var(--text-muted)' }}>
              正在测算当前会话注入上下文与 Token 预算...
            </div>
          ) : !inspection ? (
            <div style={{ padding: '28px 12px', textAlign: 'center', color: 'var(--text-muted)' }}>
              当前暂无活跃会话，发送首条指令或新建会话后即可透视注入上下文。
            </div>
          ) : (
            <>
              {/* Token Budget & Compaction Meter */}
              <div className="ai-ctx-card">
                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    flexWrap: 'wrap',
                    gap: 8,
                    marginBottom: 8,
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                    <strong style={{ fontSize: 13 }}>上下文窗口占用估算</strong>
                    {inspection.model && (
                      <span className="tag-chip mono" style={{ fontSize: 11 }}>
                        {inspection.provider_name ? `${inspection.provider_name} · ` : ''}
                        {inspection.model}
                      </span>
                    )}
                    {inspection.needs_compaction && (
                      <span className="tag-chip amber">建议压缩上下文</span>
                    )}
                  </div>
                  <span className="mono" style={{ fontSize: 12, fontWeight: 620, color: barTone }}>
                    ~{inspection.estimated_total_tokens.toLocaleString()} /{' '}
                    {(inspection.max_input_tokens || inspection.context_window_tokens).toLocaleString()} tokens ({usagePct.toFixed(1)}%)
                  </span>
                </div>

                <div className="ai-ctx-progress-track">
                  <div
                    className="ai-ctx-progress-fill"
                    style={{ width: `${usagePct}%`, background: barTone }}
                  />
                </div>

                <div className="ai-ctx-token-breakdown">
                  <span>System + AGENTS.md + 记忆: ~{inspection.estimated_system_tokens.toLocaleString()} tok</span>
                  <span>滚动摘要: ~{inspection.estimated_summary_tokens.toLocaleString()} tok</span>
                  <span>未压缩对话 ({inspection.uncompacted_messages}/{inspection.total_messages} 条): ~{inspection.estimated_history_tokens.toLocaleString()} tok</span>
                  <span>自动压缩阈值: ~{inspection.compaction_threshold_tokens.toLocaleString()} tok</span>
                  <span>总上下文窗口: {inspection.context_window_tokens.toLocaleString()} tok</span>
                  {inspection.max_input_tokens ? (
                    <span>最大输入预算: {inspection.max_input_tokens.toLocaleString()} tok</span>
                  ) : null}
                  {inspection.max_output_tokens ? (
                    <span>单轮最大输出: {inspection.max_output_tokens.toLocaleString()} tok</span>
                  ) : null}
                </div>

                {(inspection.last_usage || inspection.session_total_usage) && (
                  <div
                    className="ai-ctx-token-breakdown"
                    style={{
                      marginTop: 8,
                      paddingTop: 8,
                      borderTop: '1px dashed var(--border-subtle)',
                    }}
                  >
                    {inspection.last_usage && (
                      <span>
                        <strong>最近一轮真实用量:</strong> 输入 {(inspection.last_usage.input_tokens || 0).toLocaleString()} · 输出 {(inspection.last_usage.output_tokens || 0).toLocaleString()}
                        {inspection.last_usage.reasoning_tokens ? ` · 思考 ${inspection.last_usage.reasoning_tokens.toLocaleString()}` : ''}
                        {inspection.last_usage.cached_input_tokens ? ` · 缓存 ${inspection.last_usage.cached_input_tokens.toLocaleString()}` : ''} tok
                      </span>
                    )}
                    {inspection.session_total_usage && (
                      <span>
                        <strong>会话累计真实用量:</strong> 输入 {(inspection.session_total_usage.input_tokens || 0).toLocaleString()} · 输出 {(inspection.session_total_usage.output_tokens || 0).toLocaleString()}
                        {inspection.session_total_usage.reasoning_tokens ? ` · 思考 ${inspection.session_total_usage.reasoning_tokens.toLocaleString()}` : ''}
                        {inspection.session_total_usage.cached_input_tokens ? ` · 缓存 ${inspection.session_total_usage.cached_input_tokens.toLocaleString()}` : ''} tok
                      </span>
                    )}
                  </div>
                )}

                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 10, flexWrap: 'wrap' }}>
                  <button
                    type="button"
                    id="ai-ctx-compact-now-btn"
                    className="btn btn-teal btn-sm"
                    disabled={compacting || inspection.uncompacted_messages < 4}
                    onClick={() => onCompact(false)}
                  >
                    <Minimize2 size={13} />
                    {compacting ? '正在压缩生成摘要...' : '立即无损压缩历史上下文'}
                  </button>
                  {inspection.compacted_summary && (
                    <button
                      type="button"
                      className="btn btn-ghost btn-sm"
                      disabled={compacting}
                      onClick={() => onCompact(true)}
                    >
                      <RotateCcw size={13} /> 清空摘要恢复全量历史
                    </button>
                  )}
                  <span style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>
                    原始完整消息永久保存在加密保险库中，压缩仅优化发给大模型的有效上下文。
                  </span>
                </div>
              </div>

              {/* Global AGENTS.md & Summary Row */}
              <div className="ai-ctx-grid">
                <div className="ai-ctx-card">
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8 }}>
                    <strong style={{ fontSize: 13, display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                      <FileText size={14} style={{ color: 'var(--accent-teal)' }} />
                      全局 AGENTS.md 运维宪章
                    </strong>
                    <span className={`tag-chip ${inspection.agents_md_enabled ? 'teal' : ''}`}>
                      {inspection.agents_md_enabled
                        ? `已注入 · v${inspection.agents_md_revision || 1}`
                        : '未启用'}
                    </span>
                  </div>
                  <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 6 }}>
                    {inspection.agents_md_enabled ? (
                      <>
                        当前注入 <span className="mono">{inspection.agents_md_chars}</span> /{' '}
                        <span className="mono">{inspection.agents_md_max_chars}</span> 字符
                        {inspection.agents_md_truncated && (
                          <span style={{ color: 'var(--amber-text)', marginLeft: 6 }}>
                            （超出预算已截断）
                          </span>
                        )}
                      </>
                    ) : (
                      '已关闭或内容为空，仅应用系统级安全护栏。'
                    )}
                  </div>
                  {onOpenAgentsMD && (
                    <button
                      type="button"
                      className="btn btn-sm"
                      style={{ marginTop: 8 }}
                      onClick={() => {
                        onClose();
                        onOpenAgentsMD();
                      }}
                    >
                      前往编辑全局 AGENTS.md
                    </button>
                  )}
                </div>

                <div className="ai-ctx-card">
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8 }}>
                    <strong style={{ fontSize: 13, display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                      <BrainCircuit size={14} style={{ color: 'var(--accent-teal)' }} />
                      长期记忆与技能索引
                    </strong>
                    <span className="tag-chip teal">
                      直注 {inspection.injected_memories.length} / 总计 {inspection.total_memories_count} 条
                    </span>
                  </div>
                  <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 6 }}>
                    记忆预算使用 <span className="mono">{inspection.memory_used_chars}</span> /{' '}
                    <span className="mono">{inspection.memory_budget_chars}</span> 字符 · Runbook 技能索引{' '}
                    <span className="mono">{inspection.runbook_count}</span> 项（AI 可通过{' '}
                    <code className="mono">search_memory</code> / <code className="mono">get_runbook</code> 按需深度召回）
                  </div>
                </div>
              </div>

              {/* Target Hosts & Live Telemetry */}
              <div className="ai-ctx-card">
                <strong style={{ fontSize: 13, display: 'inline-flex', alignItems: 'center', gap: 6, marginBottom: 8 }}>
                  <Activity size={14} style={{ color: 'var(--accent-teal)' }} />
                  目标主机画像与 7×24 实时监控态势 ({inspection.host_memories.length} 台 · 活跃告警{' '}
                  {inspection.firing_alerts_count} 条)
                </strong>
                {inspection.host_memories.length === 0 ? (
                  <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>当前会话未绑定特定服务器。</div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                    {inspection.host_memories.map((hm) => {
                      const live = inspection.live_monitors.find((m) => m.server_id === hm.server_id);
                      return (
                        <div key={hm.server_id} className="ai-ctx-host-row">
                          <div style={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: 6 }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                              <strong style={{ fontSize: 12.5 }}>{hm.server_name}</strong>
                              {hm.os_arch && <span className="tag-chip">{hm.os_arch}</span>}
                              {!hm.has_memory && <span className="tag-chip">暂无主机画像</span>}
                              {hm.has_constraints && (
                                <span className="tag-chip amber">
                                  <AlertTriangle size={10.5} style={{ marginRight: 3 }} /> 含避坑红线
                                </span>
                              )}
                            </div>
                            {live && (
                              <span className="mono" style={{ fontSize: 11.5, color: 'var(--text-secondary)' }}>
                                {live.reachable
                                  ? `CPU ${live.cpu_percent.toFixed(1)}% · 内存 ${live.mem_percent.toFixed(1)}% · 磁盘 ${live.disk_percent.toFixed(1)}% · ${live.latency_ms}ms`
                                  : '离线不可达'}
                                {live.alert_count > 0 ? ` · ${live.alert_count} 告警` : ''}
                              </span>
                            )}
                          </div>
                          {hm.summary && (
                            <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 3 }}>
                              {hm.summary}
                            </div>
                          )}
                          {hm.constraints && (
                            <div className="ai-constraint-banner" style={{ marginTop: 5 }}>
                              <AlertTriangle size={12} style={{ flexShrink: 0 }} />
                              <span>运维红线：{hm.constraints}</span>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              {/* Injected Long-Term Memories */}
              {inspection.injected_memories.length > 0 && (
                <div className="ai-ctx-card">
                  <strong style={{ fontSize: 13, marginBottom: 8, display: 'block' }}>
                    本次自动注入的高优长期记忆 ({inspection.injected_memories.length} 条)
                  </strong>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    {inspection.injected_memories.map((m) => (
                      <div key={m.id} className="ai-ctx-mem-row">
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                          {m.pinned && <Pin size={11.5} style={{ color: 'var(--accent-teal)' }} />}
                          <strong style={{ fontSize: 12.5 }}>{m.title}</strong>
                          <span className="tag-chip teal" style={{ fontSize: 10.5 }}>
                            {MEMORY_CATEGORY_LABELS[m.category] || m.category}
                          </span>
                          <span className="tag-chip" style={{ fontSize: 10.5 }}>
                            {m.scope === 'global' ? '全局' : '主机专属'}
                          </span>
                          <span className="tag-chip" style={{ fontSize: 10.5 }}>
                            {MEMORY_SOURCE_LABELS[m.source] || m.source}
                          </span>
                        </div>
                        <div style={{ fontSize: 11.5, color: 'var(--text-secondary)', marginTop: 3 }}>
                          {m.preview}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Rolling Compacted Summary Preview */}
              {inspection.compacted_summary && (
                <div className="ai-ctx-card">
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      cursor: 'pointer',
                    }}
                    onClick={() => setSummaryExpanded((v) => !v)}
                  >
                    <strong style={{ fontSize: 13, display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                      {summaryExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                      当前无损滚动压缩摘要（涵盖前 {inspection.compacted_until_count} 条历史）
                    </strong>
                    {inspection.compacted_at && (
                      <span className="mono" style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                        更新于 {new Date(inspection.compacted_at).toLocaleString('zh-CN')}
                      </span>
                    )}
                  </div>
                  {summaryExpanded && (
                    <div
                      style={{
                        marginTop: 8,
                        padding: '10px 12px',
                        borderRadius: 7,
                        background: 'var(--bg-subtle)',
                        border: '1px solid var(--border-subtle)',
                        fontSize: 12.5,
                        maxHeight: 240,
                        overflowY: 'auto',
                      }}
                    >
                      <FormattedMarkdownText text={inspection.compacted_summary} />
                    </div>
                  )}
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
};



import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Bot,
  X,
  Send,
  Plus,
  Sparkles,
  TerminalSquare,
  ShieldCheck,
} from 'lucide-react';
import { api } from '../api';
import type {
  AIChatSession,
  AIExecutionMode,
  AIToolCallRecord,
} from '../types';
import {
  FormattedMarkdownText,
  HITLApprovalCard,
  RunbookProposalCard,
  ShellSnippetActionBar,
  ToolTraceStep,
  extractShellSnippets,
} from './AIMessageWidgets';

interface TerminalCopilotPanelProps {
  serverId: string;
  serverName: string;
  getTerminalContext: () => string;
  onInjectCommand: (cmd: string) => void;
  onNavigateAIConfig: () => void;
  onNotify: (msg: string) => void;
  onClose: () => void;
}

export const TerminalCopilotPanel: React.FC<TerminalCopilotPanelProps> = ({
  serverId,
  serverName,
  getTerminalContext,
  onInjectCommand,
  onNavigateAIConfig,
  onNotify,
  onClose,
}) => {
  const [hasProvider, setHasProvider] = useState<boolean>(true);
  const [session, setSession] = useState<AIChatSession | null>(null);
  const [mode, setMode] = useState<AIExecutionMode>('standard');
  const [attachPtyContext, setAttachPtyContext] = useState(true);
  const [input, setInput] = useState('');
  const [streaming, setStreaming] = useState(false);
  const [streamDelta, setStreamDelta] = useState('');
  const [streamTools, setStreamTools] = useState<AIToolCallRecord[]>([]);
  const bottomRef = useRef<HTMLDivElement | null>(null);

  const loadBoundSession = useCallback(async () => {
    try {
      const ov = await api.getAIOverview('terminal');
      setHasProvider((ov.providers || []).length > 0);
      const matched = (ov.sessions || []).find((s) =>
        (s.server_ids || []).includes(serverId)
      );
      if (matched) {
        const detail = await api.getAISession(matched.id);
        setSession(detail.session);
        setMode(detail.session.mode || 'standard');
      } else {
        setSession(null);
        setMode(ov.default_mode || 'standard');
      }
    } catch {
      // ignore transient
    }
  }, [serverId]);

  useEffect(() => {
    void loadBoundSession();
  }, [loadBoundSession]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [session?.messages.length, streamDelta, streamTools.length]);

  const startFreshSession = async () => {
    try {
      const res = await api.createAISession({
        title: `终端副驾驶 · ${serverName}`,
        scope: 'terminal',
        server_ids: [serverId],
        mode,
      });
      setSession(res.session);
      return res.session;
    } catch (err: any) {
      onNotify(err?.message || '创建终端副驾驶会话失败');
      return null;
    }
  };

  const handleStreamEvent = useCallback(
    (ev: any) => {
      switch (ev.type) {
        case 'delta':
          if (ev.delta) setStreamDelta((prev) => prev + ev.delta);
          break;
        case 'tool_start':
          if (ev.tool) {
            setStreamTools((prev) => {
              const i = prev.findIndex((t) => t.id === ev.tool.id);
              if (i >= 0) {
                const cp = [...prev];
                cp[i] = ev.tool;
                return cp;
              }
              return [...prev, ev.tool];
            });
          }
          break;
        case 'tool_result':
          if (ev.tool) {
            setStreamTools((prev) => prev.map((t) => (t.id === ev.tool.id ? ev.tool : t)));
          }
          break;
        case 'session_sync':
          if (ev.session) {
            setSession(ev.session);
            setStreamDelta('');
            setStreamTools([]);
          }
          break;
        case 'error':
          if (ev.error) onNotify(ev.error);
          break;
      }
    },
    [onNotify]
  );

  const sendCopilotPrompt = async (overrideMsg?: string, forceAttachPty = false) => {
    const text = (overrideMsg ?? input).trim();
    if (!text || streaming) return;
    if (!hasProvider) {
      onNotify('请先配置并激活大模型 API');
      onNavigateAIConfig();
      return;
    }

    let cur = session;
    if (!cur) {
      cur = await startFreshSession();
      if (!cur) return;
    }

    if (!overrideMsg) setInput('');
    setStreaming(true);
    setStreamDelta('');
    setStreamTools([]);

    const ptyText = attachPtyContext || forceAttachPty ? getTerminalContext() : '';

    try {
      await api.streamAIChat(
        cur.id,
        {
          message: text,
          server_ids: [serverId],
          mode,
          terminal_context: ptyText || undefined,
        },
        handleStreamEvent
      );
    } catch (err: any) {
      onNotify(err?.message || '终端副驾驶响应中断');
    } finally {
      setStreaming(false);
      setStreamDelta('');
      setStreamTools([]);
    }
  };

  const handleApproval = async (approvalId: string, approve: boolean) => {
    if (!session || streaming) return;
    setStreaming(true);
    setStreamDelta('');
    setStreamTools([]);
    try {
      await api.streamAIApproval(session.id, approvalId, approve, handleStreamEvent);
    } catch (err: any) {
      onNotify(err?.message || '审批执行失败');
    } finally {
      setStreaming(false);
      setStreamDelta('');
      setStreamTools([]);
    }
  };

  const approvalByToolCallId = useMemo(() => {
    const map = new Map<string, any>();
    for (const ap of session?.pending_approvals || []) {
      map.set(ap.tool_call_id, ap);
    }
    return map;
  }, [session?.pending_approvals]);

  return (
    <div className="copilot-container" id="terminal-copilot-drawer">
      <div className="copilot-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: 7, minWidth: 0 }}>
          <Bot size={15} style={{ color: 'var(--accent-teal)', flexShrink: 0 }} />
          <strong
            style={{
              fontSize: 13,
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
            }}
          >
            AI 副驾驶 · {serverName}
          </strong>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 4, flexWrap: 'wrap', maxWidth: '100%' }}>
          <div className="ai-mode-pill-group">
            {(['suggest', 'standard', 'autonomous'] as AIExecutionMode[]).map((m) => (
              <button
                key={m}
                type="button"
                className={`ai-mode-pill copilot-mode-pill ${m === 'autonomous' ? 'autonomous' : ''} ${
                  mode === m ? 'active' : ''
                }`}
                onClick={async () => {
                  setMode(m);
                  if (session) {
                    const updated = await api.updateAISessionMode(session.id, { mode: m });
                    setSession(updated.session);
                  }
                }}
              >
                {m === 'suggest' ? '参谋' : m === 'standard' ? '受控' : '自治'}
              </button>
            ))}
          </div>

          <button
            type="button"
            className="btn btn-ghost btn-sm btn-icon"
            onClick={() => void startFreshSession()}
            title="新建当前主机副驾驶对话"
          >
            <Plus size={14} />
          </button>
          <button
            type="button"
            className="btn btn-ghost btn-sm btn-icon"
            onClick={onClose}
            title="关闭 AI 副驾驶侧栏"
          >
            <X size={14} />
          </button>
        </div>
      </div>

      {/* Quick Context Action Bar */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 6,
          padding: '7px 12px',
          borderBottom: '1px solid var(--border-subtle)',
          background: 'var(--bg-surface)',
          flexWrap: 'wrap',
        }}
      >
        <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap' }}>
          <button
            type="button"
            className="ai-quick-prompt-btn"
            disabled={streaming}
            onClick={() =>
              void sendCopilotPrompt(
                '请分析当前终端最近输出中的报错或异常原因，并给出精确的修复命令。',
                true
              )
            }
          >
            <Sparkles size={11} style={{ marginRight: 3 }} />
            解释终端最新报错
          </button>
          <button
            type="button"
            className="ai-quick-prompt-btn"
            disabled={streaming}
            onClick={() =>
              void sendCopilotPrompt('请探测该主机的实时负载、监听端口与异常进程，给出健康小结。')
            }
          >
            快速探针诊断
          </button>
        </div>

        <label
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 4,
            fontSize: 11,
            color: 'var(--text-muted)',
            cursor: 'pointer',
          }}
          title="开启后将自动附带当前终端最近回显文本作为上下文（绝不包含 SSH 密码或私钥）"
        >
          <input
            type="checkbox"
            checked={attachPtyContext}
            onChange={(e) => setAttachPtyContext(e.target.checked)}
          />
          附带终端回显
        </label>
      </div>

      {/* Messages Viewport */}
      <div
        style={{
          flex: 1,
          minHeight: 0,
          overflowY: 'auto',
          padding: '12px 14px',
          display: 'flex',
          flexDirection: 'column',
          gap: 12,
        }}
      >
        {!hasProvider ? (
          <div className="empty-state" style={{ padding: '36px 14px' }}>
            <Bot size={22} style={{ marginBottom: 8, color: 'var(--amber-text)' }} />
            <h3>尚未接入大模型</h3>
            <p>配置 OpenAI 兼容、DeepSeek、通义千问、Anthropic Claude 或本地 Ollama 后即可启用终端副驾驶。</p>
            <button type="button" className="btn btn-primary btn-sm" onClick={onNavigateAIConfig}>
              前往配置大模型
            </button>
          </div>
        ) : !session || session.messages.length === 0 ? (
          <div className="empty-state" style={{ padding: '36px 14px' }}>
            <TerminalSquare size={22} style={{ marginBottom: 8, color: 'var(--accent-teal)' }} />
            <h3>同屏感知终端上下文</h3>
            <p>
              可直接询问命令写法、一键解析左侧 PTY 终端报错，或将 AI 生成的 Shell 命令一键注入当前终端执行。
            </p>
            <div style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 11.5, color: 'var(--accent-teal)' }}>
              <ShieldCheck size={13} /> 当前模式：{mode === 'suggest' ? '参谋模式' : mode === 'standard' ? '标准受控' : '自治执行'}
            </div>
          </div>
        ) : (
          <>
            {session.messages
              .filter((m) => m.role === 'user' || m.role === 'assistant')
              .map((msg) => {
                if (msg.role === 'user') {
                  // Hide verbose attached PTY block in compact bubble display
                  const cleanUserText = msg.content.split('\n\n[附：当前活跃 SSH 终端最近输出回显]')[0];
                  return (
                    <div key={msg.id} className="ai-msg-row user" style={{ maxWidth: '88%' }}>
                      <div className="ai-msg-bubble" style={{ fontSize: 12.5, padding: '8px 12px' }}>
                        {cleanUserText}
                      </div>
                    </div>
                  );
                }

                const linkedApprovals = (msg.tool_calls || [])
                  .map((tc) => approvalByToolCallId.get(tc.id))
                  .filter(Boolean);
                const snippets = extractShellSnippets(msg.content || '');

                return (
                  <div key={msg.id} className="ai-msg-row assistant">
                    {msg.tool_calls && msg.tool_calls.length > 0 && (
                      <div className="ai-tool-trace-list">
                        {msg.tool_calls.map((tc) => (
                          <ToolTraceStep key={tc.id} tool={tc} />
                        ))}
                      </div>
                    )}
                    {msg.content && (
                      <div className="ai-msg-bubble" style={{ fontSize: 12.5, padding: '9px 12px' }}>
                        <FormattedMarkdownText text={msg.content} />
                      </div>
                    )}
                    {snippets.length > 0 && (
                      <ShellSnippetActionBar
                        commands={snippets}
                        onInject={(cmd) => {
                          onInjectCommand(cmd);
                          onNotify('已将命令注入左侧当前终端');
                        }}
                        onNotify={onNotify}
                      />
                    )}
                    {linkedApprovals.map((ap) => (
                      <HITLApprovalCard
                        key={ap.id}
                        approval={ap}
                        busy={streaming}
                        onDecide={(id, ok) => void handleApproval(id, ok)}
                        onInjectTerminal={(cmd) => {
                          onInjectCommand(cmd);
                          onNotify('已将待执行命令发送至当前终端');
                        }}
                      />
                    ))}
                  </div>
                );
              })}

            {(session.runbook_proposals || []).map((prop) => (
              <RunbookProposalCard
                key={prop.id}
                proposal={prop}
                busy={streaming}
                onResolve={async (id, accept, sync) => {
                  await api.resolveRunbookProposal(id, accept, sync);
                  onNotify(accept ? '已保存至 Runbook 技能库' : '已忽略草案');
                  await loadBoundSession();
                }}
              />
            ))}

            {streaming && (
              <div className="ai-msg-row assistant">
                {streamTools.length > 0 && (
                  <div className="ai-tool-trace-list">
                    {streamTools.map((tc) => (
                      <ToolTraceStep key={tc.id} tool={tc} />
                    ))}
                  </div>
                )}
                <div className="ai-msg-bubble" style={{ fontSize: 12.5, padding: '9px 12px' }}>
                  {streamDelta || '正在分析终端上下文...'}
                </div>
              </div>
            )}
            <div ref={bottomRef} />
          </>
        )}
      </div>

      {/* Compact Composer */}
      <form
        className="copilot-composer-form"
        onSubmit={(e) => {
          e.preventDefault();
          void sendCopilotPrompt();
        }}
      >
        <input
          id="terminal-copilot-input"
          className="input copilot-composer-input"
          placeholder="自然语言转命令或排查当前终端问题..."
          value={input}
          onChange={(e) => setInput(e.target.value)}
        />
        <button
          type="submit"
          className="btn btn-primary btn-sm copilot-composer-send"
          disabled={streaming || !input.trim()}
        >
          <Send size={13} />
        </button>
      </form>
    </div>
  );
};

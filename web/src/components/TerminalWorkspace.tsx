import React, { useCallback, useEffect, useRef, useState } from 'react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { WebLinksAddon } from '@xterm/addon-web-links';
import { SearchAddon } from '@xterm/addon-search';
import '@xterm/xterm/css/xterm.css';
import {
  Terminal as TerminalIcon,
  X,
  Plus,
  FolderOpen,
  RotateCw,
  Zap,
  Activity,
  Search,
  Server,
} from 'lucide-react';
import { api, ApiError } from '../api';
import { zkClient } from '../zk/zkClient';
import type {
  AppSettings,
  HostKeyUntrustedInfo,
  OpenTerminalTab,
  ServerProbeResult,
  ServerView,
  Snippet,
} from '../types';
import { SftpPanel } from './SftpPanel';
import { HostKeyModal } from './HostKeyModal';

interface TerminalWorkspaceProps {
  tabs: OpenTerminalTab[];
  activeTabId: string;
  isVisible: boolean;
  servers: ServerView[];
  snippets: Snippet[];
  settings?: AppSettings;
  defaultOpenSftp?: boolean;
  onConsumeDefaultSftp?: () => void;
  onSelectTab: (tabId: string) => void;
  onCloseTab: (tabId: string) => void;
  onOpenServerTab: (server: ServerView) => void;
  onNavigateServers: () => void;
  onNotify: (msg: string) => void;
}

interface SinglePaneHandle {
  sendCommand: (cmd: string) => void;
  reconnect: (trustFp?: string) => void;
  searchNext: (query: string) => void;
  fit: () => void;
}

interface SinglePaneProps {
  tab: OpenTerminalTab;
  isActive: boolean;
  isWorkspaceVisible: boolean;
  fontSize: number;
  scrollback: number;
  onStatusChange: (
    tabId: string,
    state: 'connecting' | 'connected' | 'closed' | 'error',
    fingerprint?: string,
    latencyMs?: number
  ) => void;
  onHostKeyChallenge: (tabId: string, info: HostKeyUntrustedInfo) => void;
  registerHandle: (tabId: string, handle: SinglePaneHandle | null) => void;
}

const SingleTerminalPane: React.FC<SinglePaneProps> = ({
  tab,
  isActive,
  isWorkspaceVisible,
  fontSize,
  scrollback,
  onStatusChange,
  onHostKeyChallenge,
  registerHandle,
}) => {
  const mountRef = useRef<HTMLDivElement | null>(null);
  const termRef = useRef<Terminal | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const searchRef = useRef<SearchAddon | null>(null);
  const connectedRef = useRef(false);
  const connectSeqRef = useRef(0);

  const connectSession = useCallback(
    async (trustFp = '') => {
      const seq = ++connectSeqRef.current;
      connectedRef.current = false;

      const term = termRef.current;
      const fit = fitRef.current;
      if (!term || !fit) return;

      try {
        fit.fit();
      } catch {
        // Ignore fit before layout
      }

      onStatusChange(tab.tabId, 'connecting');
      term.writeln(
        `\x1b[38;5;245m[ServerNeedSafe 零知识终端] 正在客户端 WASM 发起端到端 SSHv2 握手 → ${tab.server.username}@${tab.server.host}:${tab.server.port} ...\x1b[0m`
      );

      try {
        const cols = term.cols || 120;
        const rows = term.rows || 34;
        const { ready } = await api.openTerminalSession({
          tab_id: tab.tabId,
          server_id: tab.server.id,
          cols,
          rows,
          trust_fingerprint: trustFp || tab.trustFingerprint || '',
        });
        if (seq !== connectSeqRef.current) return;

        connectedRef.current = true;
        onStatusChange(tab.tabId, 'connected', ready.fingerprint, ready.latency_ms);
        try {
          fit.fit();
          zkClient.resizeTerminal(tab.tabId, term.cols, term.rows);
        } catch {
          // ignore
        }
        term.focus();
      } catch (err: any) {
        if (seq !== connectSeqRef.current) return;
        connectedRef.current = false;
        if (err instanceof ApiError && err.code === 'HOST_KEY_UNTRUSTED' && err.hostKeyInfo) {
          onStatusChange(tab.tabId, 'error');
          onHostKeyChallenge(tab.tabId, err.hostKeyInfo);
          return;
        }
        onStatusChange(tab.tabId, 'error');
        term.writeln(`\r\n\x1b[31m[端到端 SSH 连接失败] ${err?.message || '请求失败'}\x1b[0m`);
      }
    },
    [tab, onStatusChange, onHostKeyChallenge]
  );

  useEffect(() => {
    const container = mountRef.current;
    if (!container) return;

    const term = new Terminal({
      cursorBlink: true,
      fontSize,
      scrollback,
      fontFamily:
        '"JetBrains Mono", "Cascadia Mono", "SF Mono", "Consolas", "Liberation Mono", monospace',
      lineHeight: 1.24,
      theme: {
        background: '#0d1016',
        foreground: '#e2e8f0',
        cursor: '#2dd4bf',
        selectionBackground: 'rgba(45, 212, 191, 0.26)',
        black: '#1e293b',
        red: '#f87171',
        green: '#34d399',
        yellow: '#fbbf24',
        blue: '#60a5fa',
        magenta: '#c084fc',
        cyan: '#22d3ee',
        white: '#f1f5f9',
        brightBlack: '#64748b',
        brightRed: '#fca5a5',
        brightGreen: '#6ee7b7',
        brightYellow: '#fde68a',
        brightBlue: '#93c5fd',
        brightMagenta: '#d8b4fe',
        brightCyan: '#67e8f9',
        brightWhite: '#ffffff',
      },
    });

    const fitAddon = new FitAddon();
    const searchAddon = new SearchAddon();
    term.loadAddon(fitAddon);
    term.loadAddon(searchAddon);
    term.loadAddon(new WebLinksAddon());
    term.open(container);

    termRef.current = term;
    fitRef.current = fitAddon;
    searchRef.current = searchAddon;

    const unsubWorker = zkClient.subscribeTerminal(tab.tabId, {
      onOutput: (chunk) => {
        term.write(chunk);
      },
      onExit: (message) => {
        connectedRef.current = false;
        onStatusChange(tab.tabId, 'closed');
        term.writeln(`\r\n\x1b[33m[${message || '会话已结束'}]\x1b[0m`);
      },
    });

    const dataSub = term.onData((data) => {
      if (connectedRef.current) {
        zkClient.sendTerminalInput(tab.tabId, data);
      }
    });

    const ro = new ResizeObserver(() => {
      if (!container.offsetWidth || !container.offsetHeight) return;
      try {
        fitAddon.fit();
        if (connectedRef.current) {
          zkClient.resizeTerminal(tab.tabId, term.cols, term.rows);
        }
      } catch {
        // Ignore transient resize errors
      }
    });
    ro.observe(container);

    registerHandle(tab.tabId, {
      sendCommand: (cmd: string) => {
        if (connectedRef.current) {
          zkClient.sendTerminalInput(tab.tabId, cmd.endsWith('\n') ? cmd : `${cmd}\n`);
          term.focus();
        }
      },
      reconnect: (trustFp?: string) => {
        term.clear();
        void connectSession(trustFp);
      },
      searchNext: (query: string) => {
        if (query) searchAddon.findNext(query);
      },
      fit: () => {
        try {
          fitAddon.fit();
        } catch {
          // ignore
        }
      },
    });

    void connectSession();

    return () => {
      connectSeqRef.current++;
      connectedRef.current = false;
      registerHandle(tab.tabId, null);
      ro.disconnect();
      dataSub.dispose();
      unsubWorker();
      zkClient.closeTerminal(tab.tabId);
      term.dispose();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab.tabId]);

  useEffect(() => {
    if (termRef.current) {
      termRef.current.options.fontSize = fontSize;
      try {
        fitRef.current?.fit();
      } catch {
        // ignore
      }
    }
  }, [fontSize]);

  useEffect(() => {
    if (isActive && isWorkspaceVisible) {
      const id = requestAnimationFrame(() => {
        try {
          fitRef.current?.fit();
          termRef.current?.focus();
        } catch {
          // ignore
        }
      });
      return () => cancelAnimationFrame(id);
    }
  }, [isActive, isWorkspaceVisible]);

  return (
    <div className={`terminal-pane-instance ${isActive ? '' : 'hidden'}`}>
      <div className="xterm-mount" ref={mountRef} />
    </div>
  );
};

export const TerminalWorkspace: React.FC<TerminalWorkspaceProps> = ({
  tabs,
  activeTabId,
  isVisible,
  servers,
  snippets,
  settings,
  defaultOpenSftp,
  onConsumeDefaultSftp,
  onSelectTab,
  onCloseTab,
  onOpenServerTab,
  onNavigateServers,
  onNotify,
}) => {
  const handlesRef = useRef<Record<string, SinglePaneHandle | null>>({});
  const [tabMeta, setTabMeta] = useState<
    Record<
      string,
      {
        status: 'connecting' | 'connected' | 'closed' | 'error';
        fingerprint?: string;
        latencyMs?: number;
      }
    >
  >({});
  const [telemetryByServer, setTelemetryByServer] = useState<Record<string, ServerProbeResult>>({});
  const [showSftp, setShowSftp] = useState(false);
  const [showQuickMenu, setShowQuickMenu] = useState(false);
  const [showNewTabMenu, setShowNewTabMenu] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [pendingHostKey, setPendingHostKey] = useState<{
    tabId: string;
    info: HostKeyUntrustedInfo;
  } | null>(null);

  useEffect(() => {
    if (defaultOpenSftp) {
      setShowSftp(true);
      onConsumeDefaultSftp?.();
    }
  }, [defaultOpenSftp, onConsumeDefaultSftp]);

  const activeTab = tabs.find((t) => t.tabId === activeTabId) || tabs[0];

  const refreshTelemetry = useCallback(async (serverId: string) => {
    try {
      const { probe } = await api.probeServer(serverId);
      setTelemetryByServer((prev) => ({ ...prev, [serverId]: probe }));
    } catch {
      // Telemetry is non-blocking
    }
  }, []);

  const handleStatusChange = useCallback(
    (
      tabId: string,
      status: 'connecting' | 'connected' | 'closed' | 'error',
      fingerprint?: string,
      latencyMs?: number
    ) => {
      setTabMeta((prev) => ({
        ...prev,
        [tabId]: {
          status,
          fingerprint: fingerprint || prev[tabId]?.fingerprint,
          latencyMs: latencyMs || prev[tabId]?.latencyMs,
        },
      }));
      if (status === 'connected') {
        const found = tabs.find((t) => t.tabId === tabId);
        if (found) {
          void refreshTelemetry(found.server.id);
        }
      }
    },
    [tabs, refreshTelemetry]
  );

  useEffect(() => {
    if (activeTab) {
      const id = setTimeout(() => {
        handlesRef.current[activeTab.tabId]?.fit();
      }, 60);
      return () => clearTimeout(id);
    }
  }, [showSftp, activeTab]);

  if (tabs.length === 0) {
    return (
      <div className="workspace-surface">
        <div className="page-header">
          <div className="page-header-title">
            <h2>SSH 加密终端工作台</h2>
            <p>支持多标签并发 PTY 终端会话、实时负载遥测与同屏 SFTP 文件传输</p>
          </div>
        </div>
        <div className="page-body" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <div className="empty-state">
            <div className="empty-state-icon">
              <TerminalIcon size={22} />
            </div>
            <h3>暂无打开的 SSH 终端会话</h3>
            <p>从下方快速选择一台已加密保存的服务器开启交互式终端，或前往主机资产管理添加新服务器。</p>
            {servers.length > 0 ? (
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', justifyContent: 'center' }}>
                {servers.slice(0, 6).map((srv) => (
                  <button
                    key={srv.id}
                    type="button"
                    className="btn btn-primary"
                    onClick={() => onOpenServerTab(srv)}
                  >
                    <TerminalIcon size={14} /> 连接 {srv.name}
                  </button>
                ))}
              </div>
            ) : (
              <button type="button" className="btn btn-primary" onClick={onNavigateServers}>
                <Server size={14} /> 前往添加服务器资产
              </button>
            )}
          </div>
        </div>
      </div>
    );
  }

  const currentMeta = activeTab ? tabMeta[activeTab.tabId] : undefined;
  const currentTelemetry = activeTab ? telemetryByServer[activeTab.server.id] : undefined;

  return (
    <div className="workspace-surface" id="terminal-workspace">
      <div className="terminal-stage">
        {/* Top Multi-Tab Bar */}
        <div className="terminal-tabbar">
          <div className="terminal-tabs-scroll">
            {tabs.map((t) => {
              const st = tabMeta[t.tabId]?.status || 'connecting';
              const dotColor =
                st === 'connected'
                  ? '#10b981'
                  : st === 'connecting'
                  ? '#f59e0b'
                  : '#ef4444';
              return (
                <div
                  key={t.tabId}
                  className={`term-tab ${activeTab?.tabId === t.tabId ? 'active' : ''}`}
                  onClick={() => onSelectTab(t.tabId)}
                >
                  <span
                    style={{
                      width: 7,
                      height: 7,
                      borderRadius: '50%',
                      background: dotColor,
                      flexShrink: 0,
                    }}
                  />
                  <span>{t.server.name}</span>
                  <button
                    type="button"
                    className="term-tab-close"
                    onClick={(e) => {
                      e.stopPropagation();
                      onCloseTab(t.tabId);
                    }}
                    title="关闭此终端会话"
                  >
                    <X size={13} />
                  </button>
                </div>
              );
            })}

            <div style={{ position: 'relative' }}>
              <button
                type="button"
                className="term-tool-btn"
                onClick={() => setShowNewTabMenu(!showNewTabMenu)}
                title="新建终端标签页"
              >
                <Plus size={13} />
              </button>
              {showNewTabMenu && (
                <div
                  style={{
                    position: 'absolute',
                    top: 34,
                    left: 0,
                    zIndex: 40,
                    minWidth: 210,
                    background: 'var(--bg-elevated)',
                    color: 'var(--text-primary)',
                    border: '1px solid var(--border-default)',
                    borderRadius: 8,
                    boxShadow: 'var(--shadow-md)',
                    padding: 5,
                  }}
                >
                  {servers.map((s) => (
                    <button
                      key={s.id}
                      type="button"
                      className="nav-item"
                      style={{ padding: '6px 9px', fontSize: 12.5 }}
                      onClick={() => {
                        setShowNewTabMenu(false);
                        onOpenServerTab(s);
                      }}
                    >
                      <span>{s.name}</span>
                      <span className="mono" style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                        {s.host}
                      </span>
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Right Terminal Action Controls */}
          <div className="terminal-toolbar-right">
            {searchOpen && (
              <form
                style={{ display: 'flex', alignItems: 'center', gap: 4 }}
                onSubmit={(e) => {
                  e.preventDefault();
                  if (activeTab) {
                    handlesRef.current[activeTab.tabId]?.searchNext(searchQuery);
                  }
                }}
              >
                <input
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="搜索终端输出..."
                  style={{
                    height: 26,
                    width: 140,
                    padding: '0 8px',
                    borderRadius: 5,
                    border: '1px solid rgba(255,255,255,0.18)',
                    background: '#0b0e14',
                    color: '#fff',
                    fontSize: 12,
                  }}
                  autoFocus
                />
              </form>
            )}
            <button
              type="button"
              className={`term-tool-btn ${searchOpen ? 'active' : ''}`}
              onClick={() => setSearchOpen(!searchOpen)}
              title="搜索终端内容"
            >
              <Search size={13} />
            </button>

            <div style={{ position: 'relative' }}>
              <button
                type="button"
                className={`term-tool-btn ${showQuickMenu ? 'active' : ''}`}
                onClick={() => setShowQuickMenu(!showQuickMenu)}
                id="term-quick-snippet-btn"
              >
                <Zap size={13} /> 快捷指令
              </button>
              {showQuickMenu && (
                <div
                  style={{
                    position: 'absolute',
                    top: 34,
                    right: 0,
                    zIndex: 40,
                    width: 290,
                    maxHeight: 320,
                    overflowY: 'auto',
                    background: 'var(--bg-elevated)',
                    color: 'var(--text-primary)',
                    border: '1px solid var(--border-default)',
                    borderRadius: 8,
                    boxShadow: 'var(--shadow-md)',
                    padding: 6,
                  }}
                >
                  {snippets.map((sn) => (
                    <button
                      key={sn.id}
                      type="button"
                      className="nav-item"
                      style={{
                        flexDirection: 'column',
                        alignItems: 'flex-start',
                        gap: 2,
                        padding: '7px 9px',
                      }}
                      onClick={() => {
                        setShowQuickMenu(false);
                        if (activeTab) {
                          handlesRef.current[activeTab.tabId]?.sendCommand(sn.command);
                        }
                      }}
                    >
                      <span style={{ fontWeight: 600, fontSize: 12.5 }}>{sn.title}</span>
                      <span
                        className="mono"
                        style={{
                          fontSize: 11,
                          color: 'var(--text-muted)',
                          whiteSpace: 'nowrap',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          width: '100%',
                        }}
                      >
                        {sn.command}
                      </span>
                    </button>
                  ))}
                </div>
              )}
            </div>

            <button
              type="button"
              className="term-tool-btn"
              onClick={() => {
                if (activeTab) {
                  handlesRef.current[activeTab.tabId]?.reconnect();
                }
              }}
              title="重新连接当前会话"
            >
              <RotateCw size={13} /> 重连
            </button>

            <button
              type="button"
              id="term-toggle-sftp-btn"
              className={`term-tool-btn ${showSftp ? 'active' : ''}`}
              onClick={() => setShowSftp(!showSftp)}
            >
              <FolderOpen size={13} /> SFTP 文件
            </button>
          </div>
        </div>

        {/* Live Server Security & Telemetry Bar */}
        {activeTab && (
          <div className="terminal-infobar">
            <div className="terminal-infobar-group">
              <span style={{ color: '#e2e8f0' }}>
                {activeTab.server.username}@{activeTab.server.host}:{activeTab.server.port}
              </span>
              {currentMeta?.latencyMs ? <span>延迟 {currentMeta.latencyMs}ms</span> : null}
              {currentTelemetry?.os ? <span>{currentTelemetry.os}</span> : null}
              {currentTelemetry?.load_avg ? <span>负载 {currentTelemetry.load_avg}</span> : null}
              {currentTelemetry?.mem_total_mb ? (
                <span>
                  内存 {currentTelemetry.mem_percent}% ({currentTelemetry.mem_used_mb}/
                  {currentTelemetry.mem_total_mb}MB)
                </span>
              ) : null}
              {currentTelemetry?.disk_total_gb ? (
                <span>磁盘 {currentTelemetry.disk_percent}%</span>
              ) : null}
            </div>
            <div className="terminal-infobar-group">
              {currentMeta?.fingerprint && (
                <span title="已验证的远程主机 SSH 公钥指纹" style={{ color: '#5eead4' }}>
                  {currentMeta.fingerprint.slice(0, 32)}...
                </span>
              )}
              <button
                type="button"
                onClick={() => void refreshTelemetry(activeTab.server.id)}
                style={{
                  background: 'transparent',
                  border: 'none',
                  color: '#94a3b8',
                  cursor: 'pointer',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 4,
                  fontSize: 11,
                }}
                title="刷新实时指标"
              >
                <Activity size={12} /> 刷新指标
              </button>
            </div>
          </div>
        )}

        {/* Terminal PTY Canvas + Optional Side-by-Side SFTP Explorer */}
        <div className="terminal-split-body">
          <div className="terminal-panes-stack">
            {tabs.map((tab) => (
              <SingleTerminalPane
                key={tab.tabId}
                tab={tab}
                isActive={activeTab?.tabId === tab.tabId}
                isWorkspaceVisible={isVisible}
                fontSize={settings?.terminal_font_size || 14}
                scrollback={settings?.terminal_scrollback || 5000}
                onStatusChange={handleStatusChange}
                onHostKeyChallenge={(tid, info) => setPendingHostKey({ tabId: tid, info })}
                registerHandle={(tid, h) => {
                  handlesRef.current[tid] = h;
                }}
              />
            ))}
          </div>

          {showSftp && activeTab && (
            <aside className="terminal-side-drawer">
              <SftpPanel
                serverId={activeTab.server.id}
                serverName={activeTab.server.name}
                showHiddenDefault={settings?.show_hidden_files ?? true}
                onNotify={onNotify}
                onClose={() => setShowSftp(false)}
              />
            </aside>
          )}
        </div>
      </div>

      {pendingHostKey && (
        <HostKeyModal
          info={pendingHostKey.info}
          onCancel={() => setPendingHostKey(null)}
          onTrustAndRetry={(fp) => {
            const targetTab = pendingHostKey.tabId;
            setPendingHostKey(null);
            handlesRef.current[targetTab]?.reconnect(fp);
          }}
        />
      )}
    </div>
  );
};

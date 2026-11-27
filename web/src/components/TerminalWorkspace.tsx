import React, { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
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
  Bot,
  GitBranch,
} from 'lucide-react';
import { api, ApiError, terminalClient } from '../api';
import type {
  AppSettings,
  DialRouteInfo,
  HostKeyUntrustedInfo,
  OpenTerminalTab,
  ServerProbeResult,
  ServerView,
  Snippet,
} from '../types';
import { SftpPanel } from './SftpPanel';
import { TerminalCopilotPanel } from './TerminalCopilotPanel';
import { HostKeyModal } from './HostKeyModal';
import type { CenterTab } from './AIOpsCenter';
import type { MemorySubSection } from './AIMemoryAgentsTab';

// Strip ANSI escape codes from rolling terminal text buffer before attaching as AI context
function stripAnsi(str: string): string {
  // eslint-disable-next-line no-control-regex
  return str.replace(/\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])/g, '');
}

export interface PendingTerminalCommand {
  tabId: string;
  serverId: string;
  command: string;
  autoExecute: boolean;
  nonce: number;
}

export interface PendingCopilotTarget {
  serverId: string;
  sessionId?: string;
  nonce: number;
}

interface TerminalWorkspaceProps {
  tabs: OpenTerminalTab[];
  activeTabId: string;
  isVisible: boolean;
  servers: ServerView[];
  snippets: Snippet[];
  settings?: AppSettings;
  defaultOpenSftp?: boolean;
  onConsumeDefaultSftp?: () => void;
  copilotTarget?: PendingCopilotTarget | null;
  onConsumeCopilotTarget?: () => void;
  pendingCommand?: PendingTerminalCommand | null;
  onConsumePendingCommand?: () => void;
  onSelectTab: (tabId: string) => void;
  onCloseTab: (tabId: string) => void;
  onOpenServerTab: (server: ServerView) => void;
  onNavigateServers: () => void;
  onNavigateAICenter?: (tab?: CenterTab, memorySection?: MemorySubSection) => void;
  onRefreshWorkspace?: () => Promise<void>;
  onApprovalMutated?: () => void;
  onNotify: (msg: string) => void;
}

interface SinglePaneHandle {
  sendCommand: (cmd: string) => void;
  sendRaw: (seq: string) => void;
  focus: () => void;
  reconnect: (trustFp?: string) => void;
  searchNext: (query: string) => void;
  fit: () => void;
  getRecentOutput: () => string;
}

interface SinglePaneProps {
  tab: OpenTerminalTab;
  isActive: boolean;
  isWorkspaceVisible: boolean;
  fontSize: number;
  scrollback: number;
  consumeModifiers: (data: string) => string;
  onStatusChange: (
    tabId: string,
    state: 'connecting' | 'connected' | 'closed' | 'error',
    fingerprint?: string,
    latencyMs?: number,
    route?: DialRouteInfo
  ) => void;
  onHostKeyChallenge: (tabId: string, info: HostKeyUntrustedInfo) => void;
  registerHandle: (tabId: string, handle: SinglePaneHandle | null) => void;
}

function resolvePaneFontSize(baseSize: number, containerWidth: number): number {
  if (containerWidth > 0 && containerWidth < 460 && baseSize >= 13) {
    return Math.max(12, baseSize - 2);
  }
  return baseSize;
}

const SingleTerminalPane: React.FC<SinglePaneProps> = ({
  tab,
  isActive,
  isWorkspaceVisible,
  fontSize,
  scrollback,
  consumeModifiers,
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
  const autoReconnectAttemptsRef = useRef(0);
  const autoReconnectTimerRef = useRef<number | null>(null);
  const recentOutputRef = useRef<string>('');
  const fontSizeRef = useRef(fontSize);
  const consumeModifiersRef = useRef(consumeModifiers);

  fontSizeRef.current = fontSize;
  consumeModifiersRef.current = consumeModifiers;

  const connectSession = useCallback(
    async (trustFp = '') => {
      if (autoReconnectTimerRef.current !== null) {
        window.clearTimeout(autoReconnectTimerRef.current);
        autoReconnectTimerRef.current = null;
      }
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
        `\x1b[38;5;245m[ServerNeedSafe 加密终端] 正在建立 SSHv2 会话 → ${tab.server.username}@${tab.server.host}:${tab.server.port} ...\x1b[0m`
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
        autoReconnectAttemptsRef.current = 0;
        onStatusChange(tab.tabId, 'connected', ready.fingerprint, ready.latency_ms, ready.route);
        try {
          fit.fit();
          terminalClient.resizeTerminal(tab.tabId, term.cols, term.rows);
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
        term.writeln(`\r\n\x1b[31m[SSH 连接失败] ${err?.message || '请求失败'}\x1b[0m`);
      }
    },
    [tab, onStatusChange, onHostKeyChallenge]
  );

  const connectSessionRef = useRef(connectSession);
  connectSessionRef.current = connectSession;

  useEffect(() => {
    const container = mountRef.current;
    if (!container) return;

    const initialFontSize = resolvePaneFontSize(
      fontSizeRef.current,
      container.clientWidth || window.innerWidth
    );

    const term = new Terminal({
      cursorBlink: true,
      fontSize: initialFontSize,
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

    const decoder = new TextDecoder('utf-8', { fatal: false });

    const unsubSocket = terminalClient.subscribeTerminal(tab.tabId, {
      onProgress: (ev) => {
        if (!ev.message) return;
        if (ev.stage === 'failed') {
          term.writeln(`\x1b[33m[跳板退避] ${ev.message}\x1b[0m`);
        } else if (ev.stage === 'skipped') {
          term.writeln(`\x1b[38;5;214m[跳板冷却] ${ev.message}\x1b[0m`);
        } else if (ev.stage === 'connected') {
          term.writeln(`\x1b[32m[链路就绪] ${ev.message}\x1b[0m`);
        } else {
          term.writeln(`\x1b[38;5;245m[链路尝试] ${ev.message}\x1b[0m`);
        }
      },
      onOutput: (chunk) => {
        term.write(chunk);
        try {
          const decoded = stripAnsi(decoder.decode(chunk, { stream: true }));
          if (decoded) {
            const combined = recentOutputRef.current + decoded;
            recentOutputRef.current =
              combined.length > 7000 ? combined.slice(combined.length - 7000) : combined;
          }
        } catch {
          // ignore decode edge cases
        }
      },
      onExit: (message, info) => {
        connectedRef.current = false;
        term.writeln(`\r\n\x1b[33m[${message || '会话已结束'}]\x1b[0m`);
        if (info?.auto_reconnect && autoReconnectAttemptsRef.current < 1) {
          autoReconnectAttemptsRef.current += 1;
          onStatusChange(tab.tabId, 'connecting');
          term.writeln(
            `\x1b[36m[自动退避重连] 已保留原有输出历史，正在尝试切换至下一跳板或直连重新建立会话...\x1b[0m`
          );
          autoReconnectTimerRef.current = window.setTimeout(() => {
            autoReconnectTimerRef.current = null;
            void connectSessionRef.current();
          }, 400);
          return;
        }
        onStatusChange(tab.tabId, 'closed');
      },
    });

    const dataSub = term.onData((data) => {
      if (connectedRef.current) {
        const transformed = consumeModifiersRef.current(data);
        terminalClient.sendTerminalInput(tab.tabId, transformed);
      }
    });

    const syncFitAndResize = () => {
      if (!container.offsetWidth || !container.offsetHeight) return;
      try {
        const nextFs = resolvePaneFontSize(fontSizeRef.current, container.offsetWidth);
        if (term.options.fontSize !== nextFs) {
          term.options.fontSize = nextFs;
        }
        fitAddon.fit();
        if (connectedRef.current) {
          terminalClient.resizeTerminal(tab.tabId, term.cols, term.rows);
        }
      } catch {
        // Ignore transient resize errors
      }
    };

    const ro = new ResizeObserver(syncFitAndResize);
    ro.observe(container);

    const vv = window.visualViewport;
    vv?.addEventListener('resize', syncFitAndResize);

    // Touch-drag scrollback support for mobile screens
    let touchLastY: number | null = null;
    let touchRemainder = 0;
    const onTouchStart = (ev: TouchEvent) => {
      if (ev.touches.length === 1) {
        touchLastY = ev.touches[0].clientY;
        touchRemainder = 0;
      }
    };
    const onTouchMove = (ev: TouchEvent) => {
      if (ev.touches.length !== 1 || touchLastY === null) return;
      const curY = ev.touches[0].clientY;
      const deltaPx = touchLastY - curY + touchRemainder;
      const linePx = Math.max(14, (term.options.fontSize || 12) * 1.24);
      const lines = Math.trunc(deltaPx / linePx);
      if (lines !== 0) {
        term.scrollLines(lines);
        touchRemainder = deltaPx - lines * linePx;
        touchLastY = curY;
      }
    };
    const onTouchEnd = () => {
      touchLastY = null;
      touchRemainder = 0;
    };
    container.addEventListener('touchstart', onTouchStart, { passive: true });
    container.addEventListener('touchmove', onTouchMove, { passive: true });
    container.addEventListener('touchend', onTouchEnd, { passive: true });

    registerHandle(tab.tabId, {
      sendCommand: (cmd: string) => {
        if (connectedRef.current) {
          terminalClient.sendTerminalInput(tab.tabId, cmd.endsWith('\n') ? cmd : `${cmd}\n`);
          term.focus();
        }
      },
      sendRaw: (seq: string) => {
        if (connectedRef.current && seq) {
          terminalClient.sendTerminalInput(tab.tabId, seq);
        }
      },
      focus: () => {
        term.focus();
      },
      reconnect: (trustFp?: string) => {
        autoReconnectAttemptsRef.current = 0;
        term.clear();
        recentOutputRef.current = '';
        void connectSessionRef.current(trustFp);
      },
      searchNext: (query: string) => {
        if (query) searchAddon.findNext(query);
      },
      fit: () => {
        syncFitAndResize();
      },
      getRecentOutput: () => recentOutputRef.current,
    });

    void connectSession();

    return () => {
      if (autoReconnectTimerRef.current !== null) {
        window.clearTimeout(autoReconnectTimerRef.current);
        autoReconnectTimerRef.current = null;
      }
      connectSeqRef.current++;
      connectedRef.current = false;
      recentOutputRef.current = '';
      registerHandle(tab.tabId, null);
      vv?.removeEventListener('resize', syncFitAndResize);
      container.removeEventListener('touchstart', onTouchStart);
      container.removeEventListener('touchmove', onTouchMove);
      container.removeEventListener('touchend', onTouchEnd);
      ro.disconnect();
      dataSub.dispose();
      unsubSocket();
      terminalClient.closeTerminal(tab.tabId);
      term.dispose();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab.tabId]);

  useEffect(() => {
    if (termRef.current && mountRef.current) {
      termRef.current.options.fontSize = resolvePaneFontSize(
        fontSize,
        mountRef.current.offsetWidth || window.innerWidth
      );
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
  copilotTarget,
  onConsumeCopilotTarget,
  pendingCommand,
  onConsumePendingCommand,
  onSelectTab,
  onCloseTab,
  onOpenServerTab,
  onNavigateServers,
  onNavigateAICenter,
  onRefreshWorkspace,
  onApprovalMutated,
  onNotify,
}) => {
  const handlesRef = useRef<Record<string, SinglePaneHandle | null>>({});
  const consumedCommandNonceRef = useRef<number>(0);
  const [copilotSessionTarget, setCopilotSessionTarget] = useState<{
    serverId: string;
    sessionId: string;
    nonce: number;
  } | null>(null);
  const [tabMeta, setTabMeta] = useState<
    Record<
      string,
      {
        status: 'connecting' | 'connected' | 'closed' | 'error';
        fingerprint?: string;
        latencyMs?: number;
        route?: DialRouteInfo;
      }
    >
  >({});
  const [telemetryByServer, setTelemetryByServer] = useState<Record<string, ServerProbeResult>>({});
  const [sideDrawer, setSideDrawer] = useState<'none' | 'sftp' | 'ai'>('none');
  const [showQuickMenu, setShowQuickMenu] = useState(false);
  const [showNewTabMenu, setShowNewTabMenu] = useState(false);
  const [dropdownStyle, setDropdownStyle] = useState<React.CSSProperties>({});
  const tabbarRef = useRef<HTMLDivElement | null>(null);
  const newTabBtnRef = useRef<HTMLButtonElement | null>(null);
  const quickBtnRef = useRef<HTMLButtonElement | null>(null);
  const newTabMenuRef = useRef<HTMLDivElement | null>(null);
  const quickMenuRef = useRef<HTMLDivElement | null>(null);
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [ctrlLatch, setCtrlLatch] = useState(false);
  const [altLatch, setAltLatch] = useState(false);
  const ctrlLatchRef = useRef(false);
  const altLatchRef = useRef(false);
  const [pendingHostKey, setPendingHostKey] = useState<{
    tabId: string;
    info: HostKeyUntrustedInfo;
  } | null>(null);

  // Dispatch queued remediation command once target terminal tab is connected
  useEffect(() => {
    if (!pendingCommand || consumedCommandNonceRef.current === pendingCommand.nonce) {
      return;
    }
    const meta = tabMeta[pendingCommand.tabId];
    if (!meta) return;
    if (meta.status === 'error' || meta.status === 'closed') {
      consumedCommandNonceRef.current = pendingCommand.nonce;
      onConsumePendingCommand?.();
      return;
    }
    if (meta.status !== 'connected') return;

    const handle = handlesRef.current[pendingCommand.tabId];
    if (!handle) return;

    consumedCommandNonceRef.current = pendingCommand.nonce;
    const { command, autoExecute } = pendingCommand;
    const timer = window.setTimeout(() => {
      if (autoExecute) {
        handle.sendCommand(command);
        onNotify('已在 SSH 终端执行只读排查指令');
      } else {
        handle.sendRaw(command);
        handle.focus();
        onNotify('已将变更指令填入终端命令行，请核对无误后按回车执行');
      }
      onConsumePendingCommand?.();
    }, 240);
    return () => window.clearTimeout(timer);
  }, [pendingCommand, tabMeta, onConsumePendingCommand, onNotify]);

  const clearModifierLatches = useCallback(() => {
    ctrlLatchRef.current = false;
    altLatchRef.current = false;
    setCtrlLatch(false);
    setAltLatch(false);
  }, []);

  const toggleCtrlLatch = useCallback(() => {
    setCtrlLatch((prev) => {
      const next = !prev;
      ctrlLatchRef.current = next;
      return next;
    });
  }, []);

  const toggleAltLatch = useCallback(() => {
    setAltLatch((prev) => {
      const next = !prev;
      altLatchRef.current = next;
      return next;
    });
  }, []);

  const consumeModifiers = useCallback(
    (raw: string): string => {
      const hasCtrl = ctrlLatchRef.current;
      const hasAlt = altLatchRef.current;
      if (!hasCtrl && !hasAlt) return raw;

      let out = raw;
      if (hasCtrl && raw.length === 1) {
        const upper = raw.toUpperCase().charCodeAt(0);
        if (upper >= 64 && upper <= 95) {
          out = String.fromCharCode(upper - 64);
        } else if (raw === ' ') {
          out = '\x00';
        }
      }
      if (hasAlt) {
        out = `\x1b${out}`;
      }

      clearModifierLatches();
      return out;
    },
    [clearModifierLatches]
  );

  const applyDropdownPosition = useCallback((kind: 'newtab' | 'snippets') => {
    const triggerEl = kind === 'newtab' ? newTabBtnRef.current : quickBtnRef.current;
    if (!triggerEl) return;

    const vw = window.innerWidth;
    const vh = window.innerHeight;
    const btnRect = triggerEl.getBoundingClientRect();
    const tabbarRect = tabbarRef.current?.getBoundingClientRect();

    if (vw <= 640) {
      const anchorBottom = tabbarRect ? Math.max(btnRect.bottom, tabbarRect.bottom) : btnRect.bottom;
      const top = Math.min(Math.round(anchorBottom + 6), Math.max(48, vh - 140));
      setDropdownStyle({
        position: 'fixed',
        top,
        left: 12,
        right: 12,
        width: 'auto',
        maxHeight: Math.max(120, vh - top - 16),
      });
      return;
    }

    const menuWidth = kind === 'newtab' ? 250 : 290;
    const anchorBottom =
      vw <= 768 && tabbarRect ? Math.max(btnRect.bottom, tabbarRect.bottom) : btnRect.bottom;
    const top = Math.min(Math.round(anchorBottom + 6), Math.max(44, vh - 150));
    const idealLeft =
      kind === 'newtab' ? Math.round(btnRect.left) : Math.round(btnRect.right - menuWidth);
    const clampedLeft = Math.max(12, Math.min(idealLeft, Math.max(12, vw - menuWidth - 12)));

    setDropdownStyle({
      position: 'fixed',
      top,
      left: clampedLeft,
      right: 'auto',
      width: Math.min(menuWidth, vw - 24),
      maxHeight: Math.max(120, Math.min(320, vh - top - 16)),
    });
  }, []);

  const updateOpenDropdownPosition = useCallback(() => {
    const kind = showNewTabMenu ? 'newtab' : showQuickMenu ? 'snippets' : null;
    if (!kind) return;
    applyDropdownPosition(kind);
  }, [showNewTabMenu, showQuickMenu, applyDropdownPosition]);

  useLayoutEffect(() => {
    if (!showNewTabMenu && !showQuickMenu) return;
    updateOpenDropdownPosition();

    const onPointerDown = (ev: PointerEvent) => {
      const target = ev.target as Node | null;
      if (!target) return;
      if (
        newTabBtnRef.current?.contains(target) ||
        quickBtnRef.current?.contains(target) ||
        newTabMenuRef.current?.contains(target) ||
        quickMenuRef.current?.contains(target)
      ) {
        return;
      }
      setShowNewTabMenu(false);
      setShowQuickMenu(false);
    };

    const onKeyDown = (ev: KeyboardEvent) => {
      if (ev.key === 'Escape') {
        ev.stopPropagation();
        setShowNewTabMenu(false);
        setShowQuickMenu(false);
      }
    };

    const onReposition = () => updateOpenDropdownPosition();

    document.addEventListener('pointerdown', onPointerDown);
    document.addEventListener('keydown', onKeyDown, true);
    window.addEventListener('resize', onReposition);
    window.addEventListener('scroll', onReposition, true);
    return () => {
      document.removeEventListener('pointerdown', onPointerDown);
      document.removeEventListener('keydown', onKeyDown, true);
      window.removeEventListener('resize', onReposition);
      window.removeEventListener('scroll', onReposition, true);
    };
  }, [showNewTabMenu, showQuickMenu, updateOpenDropdownPosition]);

  useEffect(() => {
    if (defaultOpenSftp) {
      setSideDrawer('sftp');
      onConsumeDefaultSftp?.();
    }
  }, [defaultOpenSftp, onConsumeDefaultSftp]);

  useEffect(() => {
    if (copilotTarget) {
      setSideDrawer('ai');
      setCopilotSessionTarget({
        serverId: copilotTarget.serverId,
        sessionId: copilotTarget.sessionId || '',
        nonce: copilotTarget.nonce,
      });
      onConsumeCopilotTarget?.();
    }
  }, [copilotTarget, onConsumeCopilotTarget]);

  useEffect(() => {
    clearModifierLatches();
  }, [activeTabId, isVisible, sideDrawer, clearModifierLatches]);

  const activeTab = tabs.find((t) => t.tabId === activeTabId) || tabs[0];

  const handleVirtualKey = useCallback(
    (seq: string, bypassLatch = false) => {
      if (!activeTab) {
        clearModifierLatches();
        return;
      }
      const handle = handlesRef.current[activeTab.tabId];
      const payload = bypassLatch ? seq : consumeModifiers(seq);
      if (bypassLatch) {
        clearModifierLatches();
      }
      if (!handle) return;
      handle.sendRaw(payload);
      handle.focus();
    },
    [activeTab, consumeModifiers, clearModifierLatches]
  );

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
      latencyMs?: number,
      route?: DialRouteInfo
    ) => {
      setTabMeta((prev) => ({
        ...prev,
        [tabId]: {
          status,
          fingerprint: fingerprint || prev[tabId]?.fingerprint,
          latencyMs: latencyMs || prev[tabId]?.latencyMs,
          route: route || prev[tabId]?.route,
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
  }, [sideDrawer, activeTab]);

  if (tabs.length === 0) {
    return (
      <div className="workspace-surface">
        <div className="page-header">
          <div className="page-header-title">
            <h2>SSH 加密终端工作台</h2>
            <p>支持多标签并发 PTY 终端会话、实时负载遥测、同屏 SFTP 文件传输与 AI 副驾驶</p>
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
        <div className="terminal-tabbar" ref={tabbarRef}>
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

            <button
              ref={newTabBtnRef}
              type="button"
              id="term-new-tab-btn"
              className={`term-tool-btn ${showNewTabMenu ? 'active' : ''}`}
              aria-expanded={showNewTabMenu}
              onClick={() => {
                setShowQuickMenu(false);
                if (!showNewTabMenu) {
                  applyDropdownPosition('newtab');
                }
                setShowNewTabMenu((prev) => !prev);
              }}
              title="新建终端标签页"
            >
              <Plus size={13} />
            </button>
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
                  className="term-search-input"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="搜索终端输出..."
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

            <button
              ref={quickBtnRef}
              type="button"
              className={`term-tool-btn ${showQuickMenu ? 'active' : ''}`}
              aria-expanded={showQuickMenu}
              onClick={() => {
                setShowNewTabMenu(false);
                if (!showQuickMenu) {
                  applyDropdownPosition('snippets');
                }
                setShowQuickMenu((prev) => !prev);
              }}
              id="term-quick-snippet-btn"
            >
              <Zap size={13} /> 快捷指令
            </button>

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
              className={`term-tool-btn ${sideDrawer === 'sftp' ? 'active' : ''}`}
              onClick={() => setSideDrawer(sideDrawer === 'sftp' ? 'none' : 'sftp')}
            >
              <FolderOpen size={13} /> SFTP 文件
            </button>

            <button
              type="button"
              id="term-toggle-copilot-btn"
              className={`term-tool-btn ${sideDrawer === 'ai' ? 'active' : ''}`}
              onClick={() => setSideDrawer(sideDrawer === 'ai' ? 'none' : 'ai')}
              title="开启同屏 AI 终端副驾驶（读取终端报错、主机记忆与变更审批）"
            >
              <Bot size={13} /> AI 副驾驶
            </button>
          </div>
        </div>

        {/* Hoisted Popover Menus (outside overflow-x: auto scroll strips) */}
        {showNewTabMenu && (
          <div
            ref={newTabMenuRef}
            className="term-dropdown-menu term-dropdown-newtab"
            style={dropdownStyle}
            role="menu"
          >
            {servers.map((s) => (
              <button
                key={s.id}
                type="button"
                className="nav-item"
                style={{
                  padding: '6px 9px',
                  fontSize: 12.5,
                  gap: 8,
                  minWidth: 0,
                  maxWidth: '100%',
                  overflow: 'hidden',
                }}
                onClick={() => {
                  setShowNewTabMenu(false);
                  onOpenServerTab(s);
                }}
              >
                <span
                  style={{
                    flex: '1 1 55%',
                    minWidth: 0,
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                    textAlign: 'left',
                  }}
                  title={s.name}
                >
                  {s.name}
                </span>
                <span
                  className="mono"
                  style={{
                    flex: '0 1 42%',
                    maxWidth: '45%',
                    minWidth: 0,
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                    fontSize: 11,
                    color: 'var(--text-tertiary, var(--text-muted))',
                    textAlign: 'right',
                  }}
                  title={s.host}
                >
                  {s.host}
                </span>
              </button>
            ))}
          </div>
        )}

        {showQuickMenu && (
          <div
            ref={quickMenuRef}
            className="term-dropdown-menu term-dropdown-snippets"
            style={dropdownStyle}
            role="menu"
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

        {/* Live Server Security & Telemetry Bar */}
        {activeTab && (
          <div className="terminal-infobar">
            <div className="terminal-infobar-group">
              <span style={{ color: '#e2e8f0' }}>
                {activeTab.server.username}@{activeTab.server.host}:{activeTab.server.port}
              </span>
              {currentMeta?.route?.label && (
                <span
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: 4,
                    color: currentMeta.route.fallback_used
                      ? '#fbbf24'
                      : !currentMeta.route.direct
                      ? '#93c5fd'
                      : '#94a3b8',
                  }}
                  title={
                    currentMeta.route.skipped_jumps && currentMeta.route.skipped_jumps.length > 0
                      ? `已跳过异常/冷却跳板: ${currentMeta.route.skipped_jumps.join('、')}`
                      : `当前 SSH 连接线路：${currentMeta.route.label}`
                  }
                >
                  <GitBranch size={11} />
                  {currentMeta.route.label}
                </span>
              )}
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

        {/* Terminal PTY Canvas + Optional Side-by-Side SFTP Explorer or AI Co-pilot */}
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
                consumeModifiers={consumeModifiers}
                onStatusChange={handleStatusChange}
                onHostKeyChallenge={(tid, info) => setPendingHostKey({ tabId: tid, info })}
                registerHandle={(tid, h) => {
                  handlesRef.current[tid] = h;
                }}
              />
            ))}
          </div>

          {sideDrawer === 'sftp' && activeTab && (
            <aside className="terminal-side-drawer">
              <SftpPanel
                serverId={activeTab.server.id}
                serverName={activeTab.server.name}
                showHiddenDefault={settings?.show_hidden_files ?? true}
                onNotify={onNotify}
                onClose={() => setSideDrawer('none')}
              />
            </aside>
          )}

          {sideDrawer === 'ai' && activeTab && (
            <aside className="terminal-side-drawer">
              <TerminalCopilotPanel
                serverId={activeTab.server.id}
                serverName={activeTab.server.name}
                preferredSessionId={
                  copilotSessionTarget && copilotSessionTarget.serverId === activeTab.server.id
                    ? copilotSessionTarget.sessionId
                    : undefined
                }
                preferredSessionNonce={
                  copilotSessionTarget && copilotSessionTarget.serverId === activeTab.server.id
                    ? copilotSessionTarget.nonce
                    : undefined
                }
                getTerminalContext={() =>
                  handlesRef.current[activeTab.tabId]?.getRecentOutput() || ''
                }
                onInjectCommand={(cmd) => {
                  handlesRef.current[activeTab.tabId]?.sendCommand(cmd);
                }}
                onNavigateAIConfig={() => {
                  onNavigateAICenter?.('providers');
                }}
                onOpenAgentsMD={() => {
                  onNavigateAICenter?.('memory', 'agents_md');
                }}
                onRefreshWorkspace={onRefreshWorkspace}
                onApprovalMutated={onApprovalMutated}
                onNotify={onNotify}
                onClose={() => setSideDrawer('none')}
              />
            </aside>
          )}
        </div>

        {/* Mobile Touch Virtual Key Strip (<= 768px) */}
        {activeTab && (
          <div
            className={`mobile-terminal-keybar ${sideDrawer !== 'none' ? 'hidden-under-drawer' : ''}`}
            id="mobile-terminal-keybar"
            role="toolbar"
            aria-label="移动端终端虚拟功能键"
          >
            <button
              type="button"
              className="term-vkey-btn"
              data-vkey="esc"
              onMouseDown={(e) => e.preventDefault()}
              onClick={() => handleVirtualKey('\x1b', true)}
            >
              ESC
            </button>
            <button
              type="button"
              className="term-vkey-btn"
              data-vkey="tab"
              onMouseDown={(e) => e.preventDefault()}
              onClick={() => handleVirtualKey('\t', true)}
            >
              TAB
            </button>
            <button
              type="button"
              className={`term-vkey-btn ${ctrlLatch ? 'active' : ''}`}
              data-vkey="ctrl"
              aria-pressed={ctrlLatch}
              onMouseDown={(e) => e.preventDefault()}
              onClick={() => {
                toggleCtrlLatch();
                handlesRef.current[activeTab.tabId]?.focus();
              }}
            >
              CTRL
            </button>
            <button
              type="button"
              className={`term-vkey-btn ${altLatch ? 'active' : ''}`}
              data-vkey="alt"
              aria-pressed={altLatch}
              onMouseDown={(e) => e.preventDefault()}
              onClick={() => {
                toggleAltLatch();
                handlesRef.current[activeTab.tabId]?.focus();
              }}
            >
              ALT
            </button>
            <button
              type="button"
              className="term-vkey-btn"
              data-vkey="ctrl-c"
              onMouseDown={(e) => e.preventDefault()}
              onClick={() => handleVirtualKey('\x03', true)}
            >
              ^C
            </button>
            <button
              type="button"
              className="term-vkey-btn"
              data-vkey="ctrl-d"
              onMouseDown={(e) => e.preventDefault()}
              onClick={() => handleVirtualKey('\x04', true)}
            >
              ^D
            </button>
            <button
              type="button"
              className="term-vkey-btn"
              data-vkey="ctrl-l"
              onMouseDown={(e) => e.preventDefault()}
              onClick={() => handleVirtualKey('\x0c', true)}
            >
              ^L
            </button>
            <button
              type="button"
              className="term-vkey-btn"
              data-vkey="up"
              aria-label="上一条命令"
              onMouseDown={(e) => e.preventDefault()}
              onClick={() => handleVirtualKey('\x1b[A', true)}
            >
              ↑
            </button>
            <button
              type="button"
              className="term-vkey-btn"
              data-vkey="down"
              aria-label="下一条命令"
              onMouseDown={(e) => e.preventDefault()}
              onClick={() => handleVirtualKey('\x1b[B', true)}
            >
              ↓
            </button>
            <button
              type="button"
              className="term-vkey-btn"
              data-vkey="left"
              aria-label="光标左移"
              onMouseDown={(e) => e.preventDefault()}
              onClick={() => handleVirtualKey('\x1b[D', true)}
            >
              ←
            </button>
            <button
              type="button"
              className="term-vkey-btn"
              data-vkey="right"
              aria-label="光标右移"
              onMouseDown={(e) => e.preventDefault()}
              onClick={() => handleVirtualKey('\x1b[C', true)}
            >
              →
            </button>
            <button
              type="button"
              className="term-vkey-btn"
              data-vkey="slash"
              onMouseDown={(e) => e.preventDefault()}
              onClick={() => handleVirtualKey('/')}
            >
              /
            </button>
            <button
              type="button"
              className="term-vkey-btn"
              data-vkey="dash"
              onMouseDown={(e) => e.preventDefault()}
              onClick={() => handleVirtualKey('-')}
            >
              -
            </button>
            <button
              type="button"
              className="term-vkey-btn"
              data-vkey="pipe"
              onMouseDown={(e) => e.preventDefault()}
              onClick={() => handleVirtualKey('|')}
            >
              |
            </button>
            <button
              type="button"
              className="term-vkey-btn"
              data-vkey="tilde"
              onMouseDown={(e) => e.preventDefault()}
              onClick={() => handleVirtualKey('~')}
            >
              ~
            </button>
          </div>
        )}
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

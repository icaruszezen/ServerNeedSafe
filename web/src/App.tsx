import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  ShieldCheck,
  Server,
  Activity,
  Terminal,
  Bot,
  KeyRound,
  Zap,
  Shield,
  Lock,
  Sun,
  Moon,
} from 'lucide-react';
import { api, registerOnUnauthorized, setSessionToken } from './api';
import { zkClient } from './zk/zkClient';
import type {
  AppSettings,
  AuthStatusResponse,
  CredentialView,
  OpenTerminalTab,
  ServerView,
  Snippet,
} from './types';
import { AuthGate } from './components/AuthGate';
import { ServerManager } from './components/ServerManager';
import { MonitorCenter } from './components/MonitorCenter';
import { TerminalWorkspace } from './components/TerminalWorkspace';
import { AIOpsCenter } from './components/AIOpsCenter';
import { KeychainManager } from './components/KeychainManager';
import { SnippetManager } from './components/SnippetManager';
import { VaultSecurity } from './components/VaultSecurity';

type NavKey = 'servers' | 'monitor' | 'terminals' | 'ai' | 'keychain' | 'snippets' | 'vault';

export const App: React.FC = () => {
  const [theme, setTheme] = useState<'light' | 'dark'>(() => {
    const saved = localStorage.getItem('sns_ui_theme');
    return saved === 'dark' ? 'dark' : 'light';
  });

  const [bootLoading, setBootLoading] = useState(true);
  const [authStatus, setAuthStatus] = useState<AuthStatusResponse | null>(null);
  const [uiLocked, setUiLocked] = useState(false);
  const [settings, setSettings] = useState<AppSettings | undefined>(undefined);
  const [activeNav, setActiveNav] = useState<NavKey>('servers');
  const [monitorTargetId, setMonitorTargetId] = useState<string>('');
  const [firingAlertsCount, setFiringAlertsCount] = useState<number>(0);
  const [patrolUnreadCount, setPatrolUnreadCount] = useState<number>(0);

  // Decrypted Workspace State (exists strictly in memory while unlocked)
  const [servers, setServers] = useState<ServerView[]>([]);
  const [groups, setGroups] = useState<string[]>([]);
  const [credentials, setCredentials] = useState<CredentialView[]>([]);
  const [snippets, setSnippets] = useState<Snippet[]>([]);
  const [backendActiveServerIds, setBackendActiveServerIds] = useState<string[]>([]);

  // Multi-tab interactive SSH terminal state
  const [terminalTabs, setTerminalTabs] = useState<OpenTerminalTab[]>([]);
  const [activeTabId, setActiveTabId] = useState<string>('');
  const [openSftpOnNextTab, setOpenSftpOnNextTab] = useState(false);

  // Toast notifications
  const [toasts, setToasts] = useState<{ id: number; msg: string }[]>([]);

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('sns_ui_theme', theme);
  }, [theme]);

  const notify = useCallback((msg: string) => {
    const id = Date.now() + Math.random();
    setToasts((prev) => [...prev, { id, msg }]);
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 3000);
  }, []);

  const clearUnlockedMemory = useCallback(() => {
    setUiLocked(false);
    setServers([]);
    setGroups([]);
    setCredentials([]);
    setSnippets([]);
    setTerminalTabs([]);
    setActiveTabId('');
    setMonitorTargetId('');
    setFiringAlertsCount(0);
    setPatrolUnreadCount(0);
    setActiveNav('servers');
  }, []);

  const checkStatus = useCallback(async () => {
    try {
      const st = await api.getAuthStatus();
      setAuthStatus(st);
      if (st.settings) setSettings(st.settings);
      if (!st.authenticated) {
        clearUnlockedMemory();
      }
    } catch {
      // Retryable network transient
    } finally {
      setBootLoading(false);
    }
  }, [clearUnlockedMemory]);

  const loadWorkspaceData = useCallback(async () => {
    try {
      const [srvRes, credRes, snipRes, monRes, aiRes] = await Promise.all([
        api.listServers(),
        api.listCredentials(),
        api.listSnippets(),
        api.getMonitorOverview().catch(() => null),
        api.getAIOverview('center').catch(() => null),
      ]);
      setServers(srvRes.servers || []);
      setGroups(srvRes.groups || []);
      setBackendActiveServerIds((srvRes.active_sessions || []).map((s) => s.server_id));
      setCredentials(credRes.credentials || []);
      setSnippets(snipRes.snippets || []);
      if (monRes) {
        setFiringAlertsCount(monRes.kpi.firing_alerts || 0);
      }
      if (aiRes) {
        setPatrolUnreadCount(aiRes.patrol_status?.unread_alerts || 0);
      }
    } catch {
      // Handled by global 401 listener if session expired
    }
  }, []);

  useEffect(() => {
    registerOnUnauthorized(() => {
      clearUnlockedMemory();
      void checkStatus();
    });
    zkClient.setOnAutoLocked(() => {
      clearUnlockedMemory();
      notify('因无操作超时，客户端零知识加密内存已自动销毁锁定');
      void checkStatus();
    });
    void checkStatus();
    return () => {
      zkClient.setOnAutoLocked(null);
    };
  }, [checkStatus, clearUnlockedMemory, notify]);

  useEffect(() => {
    if (authStatus?.authenticated && !uiLocked) {
      void loadWorkspaceData();
    }
  }, [authStatus?.authenticated, uiLocked, loadWorkspaceData]);

  // Screen lock keeps the isolated WASM Worker alive so Monitor & Scheduled AI Patrol stay running
  const handleLockScreen = useCallback(() => {
    setUiLocked(true);
    void api
      .getAuthStatus()
      .then((st) => setAuthStatus(st))
      .catch(() => {});
  }, []);

  // Full Vault Seal destroys WASM linear memory and wipes DEK / session keys
  const handleSealVault = useCallback(async () => {
    try {
      await api.lockVault();
    } catch {
      // ignore
    }
    setSessionToken('');
    clearUnlockedMemory();
    await checkStatus();
  }, [checkStatus, clearUnlockedMemory]);

  // Global keyboard shortcut: Ctrl+Shift+L locks screen immediately
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key.toLowerCase() === 'l') {
        e.preventDefault();
        if (authStatus?.authenticated && !uiLocked) {
          handleLockScreen();
        }
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [authStatus?.authenticated, uiLocked, handleLockScreen]);

  const handleConnectTerminal = (srv: ServerView, openSftp = false) => {
    const tabId = `tab-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
    setTerminalTabs((prev) => [...prev, { tabId, server: srv }]);
    setActiveTabId(tabId);
    if (openSftp) setOpenSftpOnNextTab(true);
    setActiveNav('terminals');
  };

  const handleOpenMonitor = (serverId: string) => {
    setMonitorTargetId(serverId);
    setActiveNav('monitor');
  };

  const handleCloseTab = (tabId: string) => {
    zkClient.closeTerminal(tabId);
    setTerminalTabs((prev) => {
      const next = prev.filter((t) => t.tabId !== tabId);
      if (activeTabId === tabId) {
        setActiveTabId(next[next.length - 1]?.tabId || '');
      }
      return next;
    });
  };

  const activeServerIds = useMemo(() => {
    const ids = new Set<string>(backendActiveServerIds);
    for (const t of terminalTabs) ids.add(t.server.id);
    return ids;
  }, [backendActiveServerIds, terminalTabs]);

  if (bootLoading || !authStatus) {
    return (
      <div className="auth-viewport">
        <div style={{ color: 'var(--text-muted)', fontSize: 13.5 }}>
          正在启动客户端零知识密码学隔离环境 (WASM)...
        </div>
      </div>
    );
  }

  if (!authStatus.authenticated || uiLocked) {
    return (
      <AuthGate
        status={authStatus}
        screenLocked={uiLocked && authStatus.authenticated}
        onSealVault={handleSealVault}
        theme={theme}
        onToggleTheme={() => setTheme(theme === 'light' ? 'dark' : 'light')}
        onRefreshStatus={checkStatus}
        onAuthenticated={(s, updatedStatus) => {
          setUiLocked(false);
          if (s) setSettings(s);
          setAuthStatus(
            updatedStatus || { ...authStatus, vault_status: 'unlocked', authenticated: true }
          );
        }}
      />
    );
  }

  return (
    <div className="app-shell" id="authenticated-app-shell">
      {/* Left Architectural Navigation Rail */}
      <aside className="sidebar">
        <div className="sidebar-brand">
          <div className="sidebar-logo">
            <ShieldCheck size={18} />
          </div>
          <div>
            <div className="sidebar-title">ServerNeedSafe</div>
            <div className="sidebar-subtitle">
              <span className="status-dot" /> 保险库已解锁
            </div>
          </div>
        </div>

        <nav className="sidebar-nav" aria-label="主导航">
          <div className="nav-section-label">SSH 运维与可观测</div>
          <button
            type="button"
            id="nav-servers-btn"
            className={`nav-item ${activeNav === 'servers' ? 'active' : ''}`}
            onClick={() => setActiveNav('servers')}
          >
            <span className="nav-item-left">
              <Server size={16} /> 主机资产
            </span>
            <span className="nav-badge">{servers.length}</span>
          </button>

          <button
            type="button"
            id="nav-monitor-btn"
            className={`nav-item ${activeNav === 'monitor' ? 'active' : ''}`}
            onClick={() => setActiveNav('monitor')}
          >
            <span className="nav-item-left">
              <Activity size={16} /> 状态监控
            </span>
            {firingAlertsCount > 0 ? (
              <span className="nav-badge danger">{firingAlertsCount}</span>
            ) : servers.length > 0 ? (
              <span className="nav-badge live">
                {servers.filter((s) => s.monitor_enabled !== false).length}
              </span>
            ) : null}
          </button>

          <button
            type="button"
            id="nav-terminals-btn"
            className={`nav-item ${activeNav === 'terminals' ? 'active' : ''}`}
            onClick={() => setActiveNav('terminals')}
          >
            <span className="nav-item-left">
              <Terminal size={16} /> 终端工作台
            </span>
            {terminalTabs.length > 0 && (
              <span className="nav-badge live">{terminalTabs.length}</span>
            )}
          </button>

          <button
            type="button"
            id="nav-ai-btn"
            className={`nav-item ${activeNav === 'ai' ? 'active' : ''}`}
            onClick={() => setActiveNav('ai')}
          >
            <span className="nav-item-left">
              <Bot size={16} /> AI 智能运维
            </span>
            {patrolUnreadCount > 0 && (
              <span className="nav-badge danger">{patrolUnreadCount}</span>
            )}
          </button>

          <button
            type="button"
            id="nav-keychain-btn"
            className={`nav-item ${activeNav === 'keychain' ? 'active' : ''}`}
            onClick={() => setActiveNav('keychain')}
          >
            <span className="nav-item-left">
              <KeyRound size={16} /> 凭据与密钥
            </span>
            <span className="nav-badge">{credentials.length}</span>
          </button>

          <button
            type="button"
            id="nav-snippets-btn"
            className={`nav-item ${activeNav === 'snippets' ? 'active' : ''}`}
            onClick={() => setActiveNav('snippets')}
          >
            <span className="nav-item-left">
              <Zap size={16} /> 快捷指令
            </span>
            <span className="nav-badge">{snippets.length}</span>
          </button>

          <div className="nav-section-label">数据加密与合规</div>
          <button
            type="button"
            id="nav-vault-btn"
            className={`nav-item ${activeNav === 'vault' ? 'active' : ''}`}
            onClick={() => setActiveNav('vault')}
          >
            <span className="nav-item-left">
              <Shield size={16} /> 安全保险库
            </span>
          </button>
        </nav>

        <div className="sidebar-footer">
          <div className="sidebar-vault-pill" title="客户端 WASM 零知识隔离 · 服务端零明文零密钥">
            <span>零知识 E2EE</span>
            <span className="mono" style={{ fontSize: 10.5 }}>
              WASM · XChaCha20
            </span>
          </div>
          <div className="sidebar-actions">
            <button
              type="button"
              id="sidebar-theme-btn"
              className="btn btn-sm"
              style={{ flex: 1 }}
              onClick={() => setTheme(theme === 'light' ? 'dark' : 'light')}
              title="切换界面主题"
            >
              {theme === 'light' ? <Moon size={13.5} /> : <Sun size={13.5} />}
              {theme === 'light' ? '深色' : '浅色'}
            </button>
            <button
              type="button"
              id="sidebar-lock-btn"
              className="btn btn-sm btn-danger"
              style={{ flex: 1.25 }}
              onClick={handleLockScreen}
              title="锁定操作界面，保持后台状态监控与 AI 定时巡检持续运行 (Ctrl+Shift+L)"
            >
              <Lock size={13} /> 锁定界面
            </button>
          </div>
        </div>
      </aside>

      {/* Main Content Stage */}
      <main className="main-stage">
        {activeNav === 'servers' && (
          <ServerManager
            servers={servers}
            groups={groups}
            credentials={credentials}
            activeServerIds={activeServerIds}
            showHiddenFiles={settings?.show_hidden_files}
            onRefresh={loadWorkspaceData}
            onConnectTerminal={handleConnectTerminal}
            onOpenMonitor={handleOpenMonitor}
            onNotify={notify}
          />
        )}

        {activeNav === 'monitor' && (
          <MonitorCenter
            servers={servers}
            initialServerId={monitorTargetId}
            onClearInitialServer={() => setMonitorTargetId('')}
            onConnectTerminal={handleConnectTerminal}
            onNavigateServers={() => setActiveNav('servers')}
            onFiringCountChange={setFiringAlertsCount}
            onNotify={notify}
          />
        )}

        {/* Keep TerminalWorkspace mounted whenever tabs exist or terminals view is active */}
        {(activeNav === 'terminals' || terminalTabs.length > 0) && (
          <div
            style={{
              display: activeNav === 'terminals' ? 'flex' : 'none',
              flex: 1,
              minHeight: 0,
            }}
          >
            <TerminalWorkspace
              tabs={terminalTabs}
              activeTabId={activeTabId}
              isVisible={activeNav === 'terminals'}
              servers={servers}
              snippets={snippets}
              settings={settings}
              defaultOpenSftp={openSftpOnNextTab}
              onConsumeDefaultSftp={() => setOpenSftpOnNextTab(false)}
              onSelectTab={setActiveTabId}
              onCloseTab={handleCloseTab}
              onOpenServerTab={(srv) => handleConnectTerminal(srv, false)}
              onNavigateServers={() => setActiveNav('servers')}
              onNavigateAICenter={() => setActiveNav('ai')}
              onNotify={notify}
            />
          </div>
        )}

        {activeNav === 'ai' && (
          <AIOpsCenter
            servers={servers}
            onBadgeChange={setPatrolUnreadCount}
            onRefreshWorkspace={loadWorkspaceData}
            onNotify={notify}
          />
        )}

        {activeNav === 'keychain' && (
          <KeychainManager
            credentials={credentials}
            servers={servers}
            onRefresh={loadWorkspaceData}
            onNotify={notify}
          />
        )}

        {activeNav === 'snippets' && (
          <SnippetManager
            snippets={snippets}
            servers={servers}
            onRefresh={loadWorkspaceData}
            onNotify={notify}
          />
        )}

        {activeNav === 'vault' && (
          <VaultSecurity
            onSettingsChanged={(s) => setSettings(s)}
            onLockScreen={handleLockScreen}
            onLockVault={handleSealVault}
            onNotify={notify}
          />
        )}
      </main>

      {toasts.length > 0 && (
        <div className="toast-stack" aria-live="polite">
          {toasts.map((t) => (
            <div key={t.id} className="toast-item">
              <ShieldCheck size={15} style={{ color: '#2dd4bf' }} />
              <span>{t.msg}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

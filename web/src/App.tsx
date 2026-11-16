import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  ShieldCheck,
  Server,
  Terminal,
  KeyRound,
  Zap,
  Shield,
  Lock,
  Sun,
  Moon,
} from 'lucide-react';
import { api, registerOnUnauthorized, setSessionToken } from './api';
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
import { TerminalWorkspace } from './components/TerminalWorkspace';
import { KeychainManager } from './components/KeychainManager';
import { SnippetManager } from './components/SnippetManager';
import { VaultSecurity } from './components/VaultSecurity';

type NavKey = 'servers' | 'terminals' | 'keychain' | 'snippets' | 'vault';

export const App: React.FC = () => {
  const [theme, setTheme] = useState<'light' | 'dark'>(() => {
    const saved = localStorage.getItem('sns_ui_theme');
    return saved === 'dark' ? 'dark' : 'light';
  });

  const [bootLoading, setBootLoading] = useState(true);
  const [authStatus, setAuthStatus] = useState<AuthStatusResponse | null>(null);
  const [settings, setSettings] = useState<AppSettings | undefined>(undefined);
  const [activeNav, setActiveNav] = useState<NavKey>('servers');

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
    setServers([]);
    setGroups([]);
    setCredentials([]);
    setSnippets([]);
    setTerminalTabs([]);
    setActiveTabId('');
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
      const [srvRes, credRes, snipRes] = await Promise.all([
        api.listServers(),
        api.listCredentials(),
        api.listSnippets(),
      ]);
      setServers(srvRes.servers || []);
      setGroups(srvRes.groups || []);
      setBackendActiveServerIds((srvRes.active_sessions || []).map((s) => s.server_id));
      setCredentials(credRes.credentials || []);
      setSnippets(snipRes.snippets || []);
    } catch {
      // Handled by global 401 listener if session expired
    }
  }, []);

  useEffect(() => {
    registerOnUnauthorized(() => {
      clearUnlockedMemory();
      void checkStatus();
    });
    void checkStatus();
  }, [checkStatus, clearUnlockedMemory]);

  useEffect(() => {
    if (authStatus?.authenticated) {
      void loadWorkspaceData();
    }
  }, [authStatus?.authenticated, loadWorkspaceData]);

  const handleLockVault = useCallback(async () => {
    try {
      await api.lockVault();
    } catch {
      // ignore
    }
    setSessionToken('');
    clearUnlockedMemory();
    await checkStatus();
  }, [checkStatus, clearUnlockedMemory]);

  // Global keyboard shortcut: Ctrl+Shift+L locks vault immediately
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key.toLowerCase() === 'l') {
        e.preventDefault();
        if (authStatus?.authenticated) {
          void handleLockVault();
        }
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [authStatus?.authenticated, handleLockVault]);

  const handleConnectTerminal = (srv: ServerView, openSftp = false) => {
    const tabId = `tab-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
    setTerminalTabs((prev) => [...prev, { tabId, server: srv }]);
    setActiveTabId(tabId);
    if (openSftp) setOpenSftpOnNextTab(true);
    setActiveNav('terminals');
  };

  const handleCloseTab = (tabId: string) => {
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
          正在加载安全加密环境...
        </div>
      </div>
    );
  }

  if (!authStatus.authenticated) {
    return (
      <AuthGate
        status={authStatus}
        theme={theme}
        onToggleTheme={() => setTheme(theme === 'light' ? 'dark' : 'light')}
        onAuthenticated={(s) => {
          if (s) setSettings(s);
          setAuthStatus({ ...authStatus, vault_status: 'unlocked', authenticated: true });
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
          <div className="nav-section-label">SSH 运维管理</div>
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
          <div className="sidebar-vault-pill">
            <span>全量加密存储</span>
            <span className="mono" style={{ fontSize: 10.5 }}>
              XChaCha20
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
              onClick={() => void handleLockVault()}
              title="立即擦除内存密钥并锁定保险库 (Ctrl+Shift+L)"
            >
              <Lock size={13} /> 立即锁定
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
              onNotify={notify}
            />
          </div>
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
            onLockVault={handleLockVault}
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

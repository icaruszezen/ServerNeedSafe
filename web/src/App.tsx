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
  Menu,
  X,
  ArrowUpCircle,
} from 'lucide-react';
import { api, registerOnUnauthorized, terminalClient } from './api';
import type {
  AppSettings,
  AuthStatusResponse,
  CredentialView,
  OpenTerminalTab,
  ServerView,
  Snippet,
  UpdateOverviewResponse,
} from './types';
import { AuthGate } from './components/AuthGate';
import { ServerManager } from './components/ServerManager';
import { MonitorCenter } from './components/MonitorCenter';
import { TerminalWorkspace } from './components/TerminalWorkspace';
import { AIOpsCenter, type CenterTab } from './components/AIOpsCenter';
import type { MemorySubSection } from './components/AIMemoryAgentsTab';
import { KeychainManager } from './components/KeychainManager';
import { SnippetManager } from './components/SnippetManager';
import { VaultSecurity } from './components/VaultSecurity';
import { UpdateModal } from './components/UpdateModal';

type NavKey = 'servers' | 'monitor' | 'terminals' | 'ai' | 'keychain' | 'snippets' | 'vault';

const NAV_KEY_LABELS: Record<NavKey, string> = {
  servers: '主机资产',
  monitor: '状态监控',
  terminals: '终端工作台',
  ai: 'AI 智能运维',
  keychain: '凭据与密钥',
  snippets: '快捷指令',
  vault: '安全保险库',
};

export const App: React.FC = () => {
  const [theme, setTheme] = useState<'light' | 'dark'>(() => {
    const saved = localStorage.getItem('sns_ui_theme');
    return saved === 'dark' ? 'dark' : 'light';
  });

  const [bootLoading, setBootLoading] = useState(true);
  const [authStatus, setAuthStatus] = useState<AuthStatusResponse | null>(null);
  const [settings, setSettings] = useState<AppSettings | undefined>(undefined);
  const [activeNav, setActiveNav] = useState<NavKey>('servers');
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [monitorTargetId, setMonitorTargetId] = useState<string>('');
  const [aiInitialTab, setAiInitialTab] = useState<CenterTab | undefined>(undefined);
  const [aiInitialMemorySection, setAiInitialMemorySection] = useState<MemorySubSection | undefined>(undefined);
  const [firingAlertsCount, setFiringAlertsCount] = useState<number>(0);
  const [patrolUnreadCount, setPatrolUnreadCount] = useState<number>(0);

  // Workspace State (populated in 1 RTT once session is authenticated)
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

  // Release auto-detection & update modal state
  const [updateOverview, setUpdateOverview] = useState<UpdateOverviewResponse | null>(null);
  const [updateModalOpen, setUpdateModalOpen] = useState(false);
  const [updateBannerDismissedTag, setUpdateBannerDismissedTag] = useState<string>('');

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('sns_ui_theme', theme);
    const metaTheme = document.querySelector('meta[name="theme-color"]');
    if (metaTheme) {
      metaTheme.setAttribute('content', theme === 'dark' ? '#0b0d11' : '#f5f6f8');
    }
  }, [theme]);

  useEffect(() => {
    const syncMetaFromAttr = () => {
      const attr = document.documentElement.getAttribute('data-theme');
      const metaTheme = document.querySelector('meta[name="theme-color"]');
      if (metaTheme && (attr === 'dark' || attr === 'light')) {
        metaTheme.setAttribute('content', attr === 'dark' ? '#0b0d11' : '#f5f6f8');
      }
    };
    const obs = new MutationObserver(syncMetaFromAttr);
    obs.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
    return () => obs.disconnect();
  }, []);

  const notify = useCallback((msg: string) => {
    const id = Date.now() + Math.random();
    setToasts((prev) => [...prev, { id, msg }]);
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 3000);
  }, []);

  const clearUnlockedMemory = useCallback(() => {
    terminalClient.closeAll();
    setServers([]);
    setGroups([]);
    setCredentials([]);
    setSnippets([]);
    setTerminalTabs([]);
    setActiveTabId('');
    setMonitorTargetId('');
    setFiringAlertsCount(0);
    setPatrolUnreadCount(0);
    setUpdateOverview(null);
    setUpdateModalOpen(false);
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
      const boot = await api.getWorkspaceBootstrap();
      setServers(boot.servers || []);
      setGroups(boot.groups || []);
      setBackendActiveServerIds((boot.active_sessions || []).map((s) => s.server_id));
      setCredentials(boot.credentials || []);
      setSnippets(boot.snippets || []);
      setFiringAlertsCount(boot.firing_alerts || 0);
      setPatrolUnreadCount(boot.patrol_unread || 0);
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

  const loadUpdateOverview = useCallback(async () => {
    try {
      const ov = await api.getUpdateStatus();
      setUpdateOverview(ov);
    } catch {
      // Ignore transient network errors
    }
  }, []);

  useEffect(() => {
    if (authStatus?.authenticated) {
      void loadWorkspaceData();
      void loadUpdateOverview();
      // Sync background release check results periodically while console stays open
      const timer = window.setInterval(() => {
        void loadUpdateOverview();
      }, 5 * 60 * 1000);
      return () => window.clearInterval(timer);
    }
  }, [authStatus?.authenticated, loadWorkspaceData, loadUpdateOverview]);

  useEffect(() => {
    if (!mobileNavOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setMobileNavOpen(false);
    };
    const onResize = () => {
      if (window.innerWidth > 768) setMobileNavOpen(false);
    };
    window.addEventListener('keydown', onKey);
    window.addEventListener('resize', onResize);
    return () => {
      window.removeEventListener('keydown', onKey);
      window.removeEventListener('resize', onResize);
    };
  }, [mobileNavOpen]);

  // Logout current Web admin session while keeping 7x24 monitoring & AI patrol daemon running
  const handleLogoutSession = useCallback(async () => {
    setMobileNavOpen(false);
    await api.logoutSession();
    clearUnlockedMemory();
    await checkStatus();
  }, [checkStatus, clearUnlockedMemory]);

  // Revoke ALL active Web sessions across devices while keeping 7x24 monitoring & AI patrol daemon running
  const handleRevokeAllSessions = useCallback(async () => {
    setMobileNavOpen(false);
    await api.revokeAllSessions();
    clearUnlockedMemory();
    await checkStatus();
  }, [checkStatus, clearUnlockedMemory]);

  // Global keyboard shortcut: Ctrl+Shift+L locks Web console session immediately
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key.toLowerCase() === 'l') {
        e.preventDefault();
        if (authStatus?.authenticated) {
          void handleLogoutSession();
        }
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [authStatus?.authenticated, handleLogoutSession]);

  const handleConnectTerminal = (srv: ServerView, openSftp = false) => {
    const tabId = `tab-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
    setTerminalTabs((prev) => [...prev, { tabId, server: srv }]);
    setActiveTabId(tabId);
    if (openSftp) setOpenSftpOnNextTab(true);
    setMobileNavOpen(false);
    setActiveNav('terminals');
  };

  const handleOpenMonitor = (serverId: string) => {
    setMonitorTargetId(serverId);
    setMobileNavOpen(false);
    setActiveNav('monitor');
  };

  const handleCloseTab = (tabId: string) => {
    terminalClient.closeTerminal(tabId);
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

  const currentVersionLabel =
    updateOverview?.current?.version || authStatus?.version?.version || 'dev';
  const latestTag = updateOverview?.latest_release?.tag_name || '';
  const hasVisibleUpdate = Boolean(
    updateOverview?.update_available && !updateOverview?.skipped && latestTag
  );
  const showUpdateBanner =
    hasVisibleUpdate && updateBannerDismissedTag !== latestTag;

  const handleOpenUpdateModal = useCallback(() => {
    setMobileNavOpen(false);
    setUpdateModalOpen(true);
    void loadUpdateOverview();
  }, [loadUpdateOverview]);

  const handleSkipBannerVersion = useCallback(
    async (tag: string) => {
      try {
        const res = await api.skipUpdateVersion(tag);
        setUpdateOverview(res.status);
        notify(`已忽略版本 ${tag} 的更新提示`);
      } catch (err: any) {
        notify(err?.message || '忽略版本失败');
      }
    },
    [notify]
  );

  if (bootLoading || !authStatus) {
    return (
      <div className="auth-viewport">
        <div style={{ color: 'var(--text-muted)', fontSize: 13.5 }}>
          正在连接 ServerNeedSafe 管理服务...
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
        onAuthenticated={(s, updatedStatus) => {
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
      {/* Mobile Sticky Top Header Bar (<= 768px) */}
      <header className="mobile-topbar" id="mobile-topbar">
        <div className="mobile-topbar-left">
          <button
            type="button"
            id="mobile-menu-toggle-btn"
            className="mobile-menu-btn"
            aria-label={mobileNavOpen ? '关闭导航菜单' : '打开导航菜单'}
            aria-expanded={mobileNavOpen}
            aria-controls="app-sidebar"
            onClick={() => setMobileNavOpen((prev) => !prev)}
          >
            {mobileNavOpen ? <X size={18} /> : <Menu size={18} />}
          </button>

          <div className="mobile-topbar-brand">
            <div className="mobile-topbar-logo">
              <ShieldCheck size={16} />
            </div>
            <div className="mobile-topbar-titles">
              <span className="mobile-topbar-section">{NAV_KEY_LABELS[activeNav]}</span>
              <span className="mobile-topbar-status">
                <span className="status-dot" style={{ width: 6, height: 6 }} />
                7×24 守护运行中
              </span>
            </div>
          </div>
        </div>

        <div className="mobile-topbar-actions">
          {hasVisibleUpdate && (
            <button
              type="button"
              id="mobile-update-btn"
              className="nav-badge live"
              style={{ border: 'none', cursor: 'pointer', padding: '2px 8px' }}
              onClick={handleOpenUpdateModal}
              title={`发现新版本 ${latestTag}`}
            >
              ↑ {latestTag}
            </button>
          )}
          {firingAlertsCount > 0 && (
            <button
              type="button"
              className="nav-badge danger"
              style={{ border: 'none', cursor: 'pointer', padding: '2px 8px' }}
              onClick={() => {
                setMobileNavOpen(false);
                setActiveNav('monitor');
              }}
              title="查看未恢复监控告警"
            >
              {firingAlertsCount} 告警
            </button>
          )}
          <button
            type="button"
            id="mobile-theme-btn"
            className="mobile-topbar-icon-btn"
            onClick={() => setTheme(theme === 'light' ? 'dark' : 'light')}
            title="切换界面主题"
            aria-label="切换界面主题"
          >
            {theme === 'light' ? <Moon size={15} /> : <Sun size={15} />}
          </button>
          <button
            type="button"
            id="mobile-lock-btn"
            className="mobile-topbar-icon-btn"
            onClick={() => void handleLogoutSession()}
            title="锁定控制台 (Ctrl+Shift+L)"
            aria-label="锁定控制台"
          >
            <Lock size={15} />
          </button>
        </div>
      </header>

      {mobileNavOpen && (
        <div
          className="mobile-drawer-backdrop"
          onClick={() => setMobileNavOpen(false)}
          aria-hidden="true"
        />
      )}

      {/* Left Architectural Navigation Rail / Mobile Slide-Over Drawer */}
      <aside
        id="app-sidebar"
        className={`sidebar ${mobileNavOpen ? 'mobile-open' : ''}`}
      >
        <div className="sidebar-brand">
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, minWidth: 0 }}>
            <div className="sidebar-logo">
              <ShieldCheck size={18} />
            </div>
            <div>
              <div className="sidebar-title">ServerNeedSafe</div>
              <div className="sidebar-subtitle">
                <span className="status-dot" /> 7×24 守护运行中
              </div>
            </div>
          </div>
          <button
            type="button"
            className="mobile-sidebar-close-btn"
            onClick={() => setMobileNavOpen(false)}
            aria-label="关闭导航菜单"
          >
            <X size={16} />
          </button>
        </div>

        <nav className="sidebar-nav" aria-label="主导航">
          <div className="nav-section-label">SSH 运维与可观测</div>
          <button
            type="button"
            id="nav-servers-btn"
            className={`nav-item ${activeNav === 'servers' ? 'active' : ''}`}
            onClick={() => {
              setActiveNav('servers');
              setMobileNavOpen(false);
            }}
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
            onClick={() => {
              setActiveNav('monitor');
              setMobileNavOpen(false);
            }}
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
            onClick={() => {
              setActiveNav('terminals');
              setMobileNavOpen(false);
            }}
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
            onClick={() => {
              setActiveNav('ai');
              setMobileNavOpen(false);
            }}
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
            onClick={() => {
              setActiveNav('keychain');
              setMobileNavOpen(false);
            }}
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
            onClick={() => {
              setActiveNav('snippets');
              setMobileNavOpen(false);
            }}
          >
            <span className="nav-item-left">
              <Zap size={16} /> 快捷指令
            </span>
            <span className="nav-badge">{snippets.length}</span>
          </button>

          <div className="nav-section-label">数据加密与安全</div>
          <button
            type="button"
            id="nav-vault-btn"
            className={`nav-item ${activeNav === 'vault' ? 'active' : ''}`}
            onClick={() => {
              setActiveNav('vault');
              setMobileNavOpen(false);
            }}
          >
            <span className="nav-item-left">
              <Shield size={16} /> 安全保险库
            </span>
          </button>
        </nav>

        <div className="sidebar-footer">
          <button
            type="button"
            id="sidebar-version-btn"
            className={`sidebar-version-btn ${hasVisibleUpdate ? 'has-update' : ''}`}
            onClick={handleOpenUpdateModal}
            title={
              hasVisibleUpdate
                ? `发现新版本 ${latestTag}，点击查看更新日志并一键更新`
                : `当前版本 ${currentVersionLabel}，点击检查 GitHub 新版本`
            }
          >
            <span className="sidebar-version-left">
              <ArrowUpCircle size={13.5} />
              <span className="mono">{currentVersionLabel}</span>
            </span>
            {hasVisibleUpdate ? (
              <span className="sidebar-update-pill">新版本 {latestTag}</span>
            ) : (
              <span className="mono" style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>
                7×24 · 检查更新
              </span>
            )}
          </button>
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
              onClick={() => void handleLogoutSession()}
              title="退出当前 Web 管理会话，后台 7×24 状态监控与 AI 定时巡检保持运行 (Ctrl+Shift+L)"
            >
              <Lock size={13} /> 锁定控制台
            </button>
          </div>
        </div>
      </aside>

      {/* Main Content Stage */}
      <main className="main-stage">
        {showUpdateBanner && (
          <div className="update-banner" id="global-update-banner" role="status">
            <div className="update-banner-left">
              <ArrowUpCircle size={15} style={{ color: 'var(--accent-teal)', flexShrink: 0 }} />
              <span>
                发现 ServerNeedSafe 新版本 <strong className="mono">{latestTag}</strong>
                {updateOverview?.active_mirror?.name && (
                  <span className="update-banner-mirror">
                    （已选线路：{updateOverview.active_mirror.name}）
                  </span>
                )}
              </span>
            </div>
            <div className="update-banner-actions">
              <button
                type="button"
                className="btn btn-sm btn-teal"
                onClick={handleOpenUpdateModal}
              >
                查看并更新
              </button>
              <button
                type="button"
                className="btn btn-sm btn-ghost"
                onClick={() => void handleSkipBannerVersion(latestTag)}
              >
                忽略此版本
              </button>
              <button
                type="button"
                className="btn btn-sm btn-ghost btn-icon"
                aria-label="暂时收起更新提醒"
                onClick={() => setUpdateBannerDismissedTag(latestTag)}
              >
                <X size={14} />
              </button>
            </div>
          </div>
        )}

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
              onNavigateAICenter={(tab, memSec) => {
                setAiInitialTab(tab);
                setAiInitialMemorySection(memSec);
                setActiveNav('ai');
              }}
              onRefreshWorkspace={loadWorkspaceData}
              onNotify={notify}
            />
          </div>
        )}

        {activeNav === 'ai' && (
          <AIOpsCenter
            servers={servers}
            initialTab={aiInitialTab}
            initialMemorySection={aiInitialMemorySection}
            onConsumeInitialTab={() => {
              setAiInitialTab(undefined);
              setAiInitialMemorySection(undefined);
            }}
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
            updateOverview={updateOverview}
            onUpdateOverviewChange={setUpdateOverview}
            onOpenUpdateModal={handleOpenUpdateModal}
            onSettingsChanged={(s) => setSettings(s)}
            onLogoutSession={handleLogoutSession}
            onRevokeAllSessions={handleRevokeAllSessions}
            onNotify={notify}
          />
        )}
      </main>

      <UpdateModal
        open={updateModalOpen}
        overview={updateOverview}
        onClose={() => setUpdateModalOpen(false)}
        onOverviewChange={setUpdateOverview}
        onOpenSettings={() => {
          setActiveNav('vault');
          window.setTimeout(() => {
            document.getElementById('system-update-panel')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
          }, 80);
        }}
        onNotify={notify}
      />

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

import type {
  AgentsMDConfig,
  AIAgentsMDProposal,
  AIChatSession,
  AIChatSessionSummary,
  AIExecutionMode,
  AIMemoryConfig,
  AIMemoryEntry,
  AIOverviewResponse,
  AIProtocol,
  AIProviderView,
  AIRunbook,
  AIStreamEvent,
  AppSettings,
  AuthStatusResponse,
  BatchExecResult,
  CompactionInfo,
  CredentialView,
  EncryptionInfo,
  ExternalApproval,
  HostKeyUntrustedInfo,
  HostMemory,
  MCPConfigView,
  MCPOverviewResponse,
  MCPRuntimeStatus,
  MCPTokenScope,
  MCPTokenView,
  MirrorProbeResult,
  MonitorAlert,
  MonitorAlertRule,
  MonitorOverviewResponse,
  MonitorPolicyResponse,
  MonitorRuntimeStatus,
  MonitorSettings,
  PatrolConfigView,
  PatrolRecord,
  PatrolStatusView,
  ServerMonitorDetailResponse,
  ServerMonitorSnapshot,
  ServerMutationPayload,
  ServerProbeResult,
  ServerView,
  SessionContextInspection,
  SFTPListResponse,
  Snippet,
  SyncSummary,
  TerminalReadyInfo,
  UpdateOverviewResponse,
  UpdateSettings,
  VaultSecurityOverview,
  WorkspaceBootstrapResponse,
} from './types';

export class ApiError extends Error {
  status: number;
  code: string;
  hostKeyInfo?: HostKeyUntrustedInfo;
  retryAfterSec?: number;
  activeSSHTabs?: number;

  constructor(
    message: string,
    status: number,
    code = 'ERROR',
    hostKeyInfo?: HostKeyUntrustedInfo,
    retryAfterSec?: number,
    activeSSHTabs?: number
  ) {
    super(message);
    this.status = status;
    this.code = code;
    this.hostKeyInfo = hostKeyInfo;
    this.retryAfterSec = retryAfterSec;
    this.activeSSHTabs = activeSSHTabs;
  }
}

let onUnauthorizedCallback: (() => void) | null = null;

export function registerOnUnauthorized(fn: () => void): void {
  onUnauthorizedCallback = fn;
}

interface ErrorResponsePayload {
  error?: string;
  code?: string;
  host_key?: HostKeyUntrustedInfo;
  retry_after_sec?: number;
  active_ssh_tabs?: number;
}

async function parseErrorResponse(res: Response): Promise<never> {
  let payload: ErrorResponsePayload = {};
  try {
    payload = (await res.json()) as ErrorResponsePayload;
  } catch {
    // non-JSON body
  }
  const code = payload.code || 'HTTP_ERROR';
  const msg = payload.error || `请求失败 (HTTP ${res.status})`;
  if (res.status === 401 && (code === 'UNAUTHORIZED' || code === 'VAULT_NOT_INIT')) {
    onUnauthorizedCallback?.();
  }
  throw new ApiError(
    msg,
    res.status,
    code,
    payload.host_key,
    payload.retry_after_sec,
    payload.active_ssh_tabs
  );
}

async function requestJSON<T>(
  method: string,
  path: string,
  body?: unknown,
  signal?: AbortSignal
): Promise<T> {
  const headers: Record<string, string> = {};
  let reqBody: BodyInit | undefined;
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
    reqBody = JSON.stringify(body);
  }
  const res = await fetch(path, {
    method,
    headers,
    body: reqBody,
    credentials: 'same-origin',
    signal,
  });
  if (!res.ok) {
    await parseErrorResponse(res);
  }
  return (await res.json()) as T;
}

function parseFilenameFromHeaders(res: Response, fallback: string): string {
  const xFile = res.headers.get('X-Filename');
  if (xFile) return xFile;
  const cd = res.headers.get('Content-Disposition') || '';
  const match = cd.match(/filename="?([^";]+)"?/i);
  return match?.[1] || fallback;
}

async function postSSEStream(
  path: string,
  payload: Record<string, unknown>,
  onEvent: (ev: AIStreamEvent) => void,
  signal?: AbortSignal
): Promise<void> {
  const res = await fetch(path, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'text/event-stream',
    },
    body: JSON.stringify(payload),
    credentials: 'same-origin',
    signal,
  });
  if (!res.ok) {
    await parseErrorResponse(res);
  }
  if (!res.body) return;

  const reader = res.body.getReader();
  const decoder = new TextDecoder('utf-8');
  let buffer = '';

  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });

      let sepIdx: number;
      while ((sepIdx = buffer.indexOf('\n\n')) !== -1) {
        const rawBlock = buffer.slice(0, sepIdx);
        buffer = buffer.slice(sepIdx + 2);
        for (const line of rawBlock.split('\n')) {
          const trimmed = line.trim();
          if (trimmed.startsWith('data:')) {
            const jsonStr = trimmed.slice(5).trim();
            if (!jsonStr) continue;
            try {
              onEvent(JSON.parse(jsonStr) as AIStreamEvent);
            } catch {
              // ignore malformed chunk
            }
          }
        }
      }
    }
  } finally {
    reader.releaseLock();
  }
}

// ============================================================================
// Native WebSocket Interactive SSH PTY Terminal Client (/api/ws/terminal)
// ============================================================================

interface TerminalCallbacks {
  onOutput: (chunk: Uint8Array) => void;
  onExit: (message: string) => void;
}

class TerminalWebSocketClient {
  private sockets = new Map<string, WebSocket>();
  private subscribers = new Map<string, TerminalCallbacks>();
  private encoder = new TextEncoder();

  subscribeTerminal(tabId: string, cb: TerminalCallbacks): () => void {
    this.subscribers.set(tabId, cb);
    return () => {
      if (this.subscribers.get(tabId) === cb) {
        this.subscribers.delete(tabId);
      }
    };
  }

  openSession(params: {
    tab_id: string;
    server_id: string;
    cols: number;
    rows: number;
    trust_fingerprint?: string;
  }): Promise<{ ready: TerminalReadyInfo }> {
    this.closeTerminal(params.tab_id);

    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const qs = new URLSearchParams({
      server_id: params.server_id,
      cols: String(params.cols || 120),
      rows: String(params.rows || 34),
    });
    if (params.trust_fingerprint) {
      qs.set('trust_fingerprint', params.trust_fingerprint);
    }

    const wsUrl = `${proto}//${window.location.host}/api/ws/terminal?${qs.toString()}`;
    const ws = new WebSocket(wsUrl);
    ws.binaryType = 'arraybuffer';
    this.sockets.set(params.tab_id, ws);

    return new Promise<{ ready: TerminalReadyInfo }>((resolve, reject) => {
      let settled = false;

      ws.onmessage = (ev: MessageEvent) => {
        if (ev.data instanceof ArrayBuffer) {
          const sub = this.subscribers.get(params.tab_id);
          if (sub) {
            sub.onOutput(new Uint8Array(ev.data));
          }
          return;
        }
        if (typeof ev.data === 'string') {
          try {
            const msg = JSON.parse(ev.data) as {
              type: string;
              ready?: TerminalReadyInfo;
              error?: string;
              message?: string;
              host_key?: HostKeyUntrustedInfo;
            };
            if (msg.type === 'ready' && msg.ready) {
              settled = true;
              resolve({ ready: msg.ready });
              return;
            }
            if (msg.type === 'host_key_untrusted') {
              settled = true;
              this.closeTerminal(params.tab_id);
              reject(
                new ApiError(
                  msg.error || 'SSH 主机指纹待确认',
                  409,
                  'HOST_KEY_UNTRUSTED',
                  msg.host_key
                )
              );
              return;
            }
            if (msg.type === 'error') {
              if (!settled) {
                settled = true;
                this.closeTerminal(params.tab_id);
                reject(new ApiError(msg.error || '终端连接失败', 400, 'SSH_CONNECT_FAILED'));
              } else {
                this.subscribers.get(params.tab_id)?.onExit(msg.error || '连接异常中断');
              }
              return;
            }
            if (msg.type === 'exit') {
              this.subscribers.get(params.tab_id)?.onExit(msg.message || '远程终端会话已退出');
            }
          } catch {
            // ignore non-JSON frame
          }
        }
      };

      ws.onerror = () => {
        if (!settled) {
          settled = true;
          this.sockets.delete(params.tab_id);
          reject(new ApiError('建立终端 WebSocket 通道失败，请确认登录会话有效', 502, 'WS_ERROR'));
        }
      };

      ws.onclose = () => {
        if (this.sockets.get(params.tab_id) === ws) {
          this.sockets.delete(params.tab_id);
        }
        if (!settled) {
          settled = true;
          reject(new ApiError('终端连接已关闭', 400, 'WS_CLOSED'));
        } else {
          this.subscribers.get(params.tab_id)?.onExit('终端连接已关闭');
        }
      };
    });
  }

  sendTerminalInput(tabId: string, data: string): void {
    const ws = this.sockets.get(tabId);
    if (ws && ws.readyState === WebSocket.OPEN && data) {
      ws.send(this.encoder.encode(data));
    }
  }

  resizeTerminal(tabId: string, cols: number, rows: number): void {
    const ws = this.sockets.get(tabId);
    if (ws && ws.readyState === WebSocket.OPEN && cols > 0 && rows > 0) {
      ws.send(JSON.stringify({ type: 'resize', cols, rows }));
    }
  }

  closeTerminal(tabId: string): void {
    const ws = this.sockets.get(tabId);
    if (ws) {
      this.sockets.delete(tabId);
      ws.onclose = null;
      ws.onerror = null;
      ws.onmessage = null;
      try {
        ws.close();
      } catch {
        // ignore
      }
    }
  }

  closeAll(): void {
    for (const tabId of Array.from(this.sockets.keys())) {
      this.closeTerminal(tabId);
    }
  }
}

export const terminalClient = new TerminalWebSocketClient();

export const api = {
  getAuthStatus: () => requestJSON<AuthStatusResponse>('GET', '/api/auth/status'),

  setupVault: (password: string) =>
    requestJSON<{
      ok: boolean;
      token: string;
      settings: AppSettings;
      status: AuthStatusResponse;
    }>('POST', '/api/auth/setup', { password }),

  loginVault: (password: string) =>
    requestJSON<{
      ok: boolean;
      token: string;
      settings: AppSettings;
      status: AuthStatusResponse;
    }>('POST', '/api/auth/login', { password }),

  unlockVault: (password: string) =>
    requestJSON<{
      ok: boolean;
      token: string;
      settings: AppSettings;
      status: AuthStatusResponse;
    }>('POST', '/api/auth/login', { password }),

  logoutSession: async (): Promise<{ ok: boolean }> => {
    terminalClient.closeAll();
    try {
      await requestJSON<{ ok: boolean }>('POST', '/api/auth/logout', {});
    } catch {
      // ignore if session already expired
    }
    return { ok: true };
  },

  revokeAllSessions: async (): Promise<{ ok: boolean }> => {
    terminalClient.closeAll();
    try {
      await requestJSON<{ ok: boolean }>('POST', '/api/auth/lock', {});
    } catch {
      // ignore
    }
    return { ok: true };
  },

  changePassword: (old_password: string, new_password: string) =>
    requestJSON<{ ok: boolean; token: string; encryption: EncryptionInfo }>(
      'POST',
      '/api/auth/password',
      { old_password, new_password }
    ),

  exportVaultBlob: async (
    backupPassword: string,
    includeRuntime = false
  ): Promise<{ blob: Blob; filename: string }> => {
    const res = await fetch('/api/vault/export', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        backup_password: backupPassword,
        include_runtime: includeRuntime,
      }),
      credentials: 'same-origin',
    });
    if (!res.ok) {
      await parseErrorResponse(res);
    }
    const blob = await res.blob();
    const filename = parseFilenameFromHeaders(res, 'ServerNeedSafe-backup.sns');
    return { blob, filename };
  },

  importVault: async (
    file: File,
    password: string,
    opts?: { currentAdminPassword?: string; includeRuntime?: boolean }
  ) => {
    const form = new FormData();
    form.append('file', file);
    form.append('password', password);
    if (opts?.currentAdminPassword) {
      form.append('current_admin_password', opts.currentAdminPassword);
    }
    if (opts?.includeRuntime !== undefined) {
      form.append('include_runtime', opts.includeRuntime ? 'true' : 'false');
    }
    const res = await fetch('/api/vault/import/file', {
      method: 'POST',
      body: form,
      credentials: 'same-origin',
    });
    if (!res.ok) {
      await parseErrorResponse(res);
    }
    return (await res.json()) as {
      ok: boolean;
      token: string;
      settings: AppSettings;
      status: AuthStatusResponse;
    };
  },

  getVaultSecurity: () => requestJSON<VaultSecurityOverview>('GET', '/api/vault/security'),

  updateSettings: (settings: AppSettings) =>
    requestJSON<{ ok: boolean; settings: AppSettings }>('PUT', '/api/vault/settings', settings),

  deleteKnownHost: (address: string) =>
    requestJSON<{ ok: boolean }>(
      'DELETE',
      `/api/vault/known-hosts?address=${encodeURIComponent(address)}`
    ),

  syncPush: (remote_url: string, remote_password: string, include_runtime = false) =>
    requestJSON<{ summary: SyncSummary }>('POST', '/api/vault/sync/push', {
      remote_url,
      remote_password,
      include_runtime,
    }),

  syncPull: (remote_url: string, remote_password: string, include_runtime = false) =>
    requestJSON<{ summary: SyncSummary }>('POST', '/api/vault/sync/pull', {
      remote_url,
      remote_password,
      include_runtime,
    }),

  // Single-RTT Workspace Bootstrap & Server/Group CRUD
  getWorkspaceBootstrap: () =>
    requestJSON<WorkspaceBootstrapResponse>('GET', '/api/workspace/bootstrap'),

  listServers: () =>
    requestJSON<{
      servers: ServerView[];
      groups: string[];
      active_sessions: { id: string; server_id: string; server_name: string; started_at: string }[];
    }>('GET', '/api/servers'),

  createServer: (payload: ServerMutationPayload) =>
    requestJSON<{ server: ServerView }>('POST', '/api/servers', payload),

  updateServer: (id: string, payload: ServerMutationPayload) =>
    requestJSON<{ server: ServerView }>('PUT', `/api/servers/${encodeURIComponent(id)}`, payload),

  deleteServer: (id: string) =>
    requestJSON<{ ok: boolean }>('DELETE', `/api/servers/${encodeURIComponent(id)}`),

  probeServer: (id: string, trustFingerprint = '') =>
    requestJSON<{ probe: ServerProbeResult }>(
      'POST',
      `/api/servers/${encodeURIComponent(id)}/probe`,
      { trust_fingerprint: trustFingerprint }
    ),

  addGroup: (name: string) =>
    requestJSON<{ groups: string[] }>('POST', '/api/groups', { name }),

  deleteGroup: (name: string) =>
    requestJSON<{ groups: string[] }>(
      'DELETE',
      `/api/groups?name=${encodeURIComponent(name)}`
    ),

  // Credentials & SSH Keys
  listCredentials: () =>
    requestJSON<{ credentials: CredentialView[] }>('GET', '/api/credentials'),

  createCredential: (payload: Record<string, unknown>) =>
    requestJSON<{ credential: CredentialView }>('POST', '/api/credentials', payload),

  importCredentialFile: async (payload: {
    file: File;
    publicKeyFile?: File | null;
    name?: string;
    passphrase?: string;
    publicKey?: string;
    usernameHint?: string;
    notes?: string;
  }) => {
    const form = new FormData();
    form.append('private_key_file', payload.file);
    if (payload.publicKeyFile) {
      form.append('public_key_file', payload.publicKeyFile);
    } else if (payload.publicKey?.trim()) {
      form.append('public_key', payload.publicKey.trim());
    }
    if (payload.name?.trim()) {
      form.append('name', payload.name.trim());
    }
    if (payload.passphrase) {
      form.append('passphrase', payload.passphrase);
    }
    if (payload.usernameHint?.trim()) {
      form.append('username_hint', payload.usernameHint.trim());
    }
    if (payload.notes?.trim()) {
      form.append('notes', payload.notes.trim());
    }
    const res = await fetch('/api/credentials/import-file', {
      method: 'POST',
      body: form,
      credentials: 'same-origin',
    });
    if (!res.ok) {
      await parseErrorResponse(res);
    }
    return (await res.json()) as {
      credential: CredentialView;
      imported_filename?: string;
    };
  },

  updateCredential: (id: string, payload: Record<string, unknown>) =>
    requestJSON<{ credential: CredentialView }>(
      'PUT',
      `/api/credentials/${encodeURIComponent(id)}`,
      payload
    ),

  deleteCredential: (id: string) =>
    requestJSON<{ ok: boolean }>('DELETE', `/api/credentials/${encodeURIComponent(id)}`),

  generateKeyPair: (payload: {
    algorithm: string;
    comment: string;
    passphrase: string;
    save_name: string;
    username_hint: string;
    notes: string;
  }) =>
    requestJSON<{
      algorithm: string;
      public_key: string;
      private_key?: string;
      fingerprint: string;
      credential?: CredentialView;
    }>('POST', '/api/ssh/keygen', payload),

  deployPublicKey: (payload: { server_id: string; credential_id?: string; public_key?: string }) =>
    requestJSON<{ ok: boolean }>('POST', '/api/ssh/deploy-key', payload),

  // Snippets & Batch Execution
  listSnippets: () => requestJSON<{ snippets: Snippet[] }>('GET', '/api/snippets'),

  upsertSnippet: (snippet: Partial<Snippet>) =>
    requestJSON<{ snippet: Snippet }>('POST', '/api/snippets', snippet),

  deleteSnippet: (id: string) =>
    requestJSON<{ ok: boolean }>('DELETE', `/api/snippets/${encodeURIComponent(id)}`),

  batchExec: (server_ids: string[], command: string, timeout_sec = 25) =>
    requestJSON<{ results: BatchExecResult[] }>('POST', '/api/ssh/batch-exec', {
      server_ids,
      command,
      timeout_sec,
    }),

  // Interactive SSH Terminal over Native WebSocket
  openTerminalSession: (payload: {
    tab_id: string;
    server_id: string;
    cols: number;
    rows: number;
    trust_fingerprint?: string;
  }) => terminalClient.openSession(payload),

  // SFTP File Management
  sftpList: (serverId: string, dirPath = '') =>
    requestJSON<SFTPListResponse>('POST', '/api/sftp/list', {
      server_id: serverId,
      path: dirPath,
    }),

  sftpRead: (serverId: string, filePath: string) =>
    requestJSON<{ path: string; content: string }>('POST', '/api/sftp/read', {
      server_id: serverId,
      path: filePath,
    }),

  sftpWrite: (serverId: string, filePath: string, content: string) =>
    requestJSON<{ ok: boolean }>('POST', '/api/sftp/write', {
      server_id: serverId,
      path: filePath,
      content,
    }),

  sftpUpload: async (serverId: string, dir: string, file: File) => {
    const form = new FormData();
    form.append('server_id', serverId);
    form.append('dir', dir);
    form.append('filename', file.name);
    form.append('file', file);
    const res = await fetch('/api/sftp/upload', {
      method: 'POST',
      body: form,
      credentials: 'same-origin',
    });
    if (!res.ok) {
      await parseErrorResponse(res);
    }
    return (await res.json()) as { ok: boolean; path: string; bytes: number };
  },

  sftpDownloadBlob: async (
    serverId: string,
    filePath: string
  ): Promise<{ blob: Blob; filename: string }> => {
    const res = await fetch('/api/sftp/download', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ server_id: serverId, path: filePath }),
      credentials: 'same-origin',
    });
    if (!res.ok) {
      await parseErrorResponse(res);
    }
    const blob = await res.blob();
    const filename = parseFilenameFromHeaders(res, 'download.bin');
    return { blob, filename };
  },

  sftpMkdir: (serverId: string, path: string) =>
    requestJSON<{ ok: boolean }>('POST', '/api/sftp/mkdir', { server_id: serverId, path }),

  sftpRename: (serverId: string, old_path: string, new_path: string) =>
    requestJSON<{ ok: boolean }>('POST', '/api/sftp/rename', {
      server_id: serverId,
      old_path,
      new_path,
    }),

  sftpDelete: (serverId: string, path: string) =>
    requestJSON<{ ok: boolean }>('POST', '/api/sftp/delete', { server_id: serverId, path }),

  sftpChmod: (serverId: string, path: string, mode: string) =>
    requestJSON<{ ok: boolean }>('POST', '/api/sftp/chmod', {
      server_id: serverId,
      path,
      mode,
    }),

  // 7x24 Server Status Monitoring & Time-Series Telemetry
  getMonitorOverview: () =>
    requestJSON<MonitorOverviewResponse>('GET', '/api/monitor/overview'),

  getServerMonitorDetail: (id: string, range = '1h') =>
    requestJSON<ServerMonitorDetailResponse>(
      'GET',
      `/api/monitor/detail?id=${encodeURIComponent(id)}&range=${encodeURIComponent(range)}`
    ),

  collectAllMonitor: (server_ids: string[] = []) =>
    requestJSON<{
      ok: boolean;
      count: number;
      snapshots: ServerMonitorSnapshot[];
      runtime: MonitorRuntimeStatus;
    }>('POST', '/api/monitor/collect-all', { server_ids }),

  collectServerMonitor: (id: string, trust_fingerprint = '') =>
    requestJSON<{
      ok: boolean;
      snapshot: ServerMonitorSnapshot;
      runtime: MonitorRuntimeStatus;
    }>('POST', '/api/monitor/collect-server', { id, trust_fingerprint }),

  acceptPortBaseline: (id: string) =>
    requestJSON<{ ok: boolean; port_baseline: string[] }>('POST', '/api/monitor/port-baseline', {
      id,
    }),

  listMonitorAlerts: (status = '', server_id = '', limit = 300) => {
    const qs = new URLSearchParams({ limit: String(limit) });
    if (status) qs.set('status', status);
    if (server_id) qs.set('server_id', server_id);
    return requestJSON<{ alerts: MonitorAlert[] }>('GET', `/api/monitor/alerts?${qs.toString()}`);
  },

  ackMonitorAlert: (id: string) =>
    requestJSON<{ ok: boolean; alert: MonitorAlert }>('POST', '/api/monitor/alerts/ack', { id }),

  clearResolvedMonitorAlerts: () =>
    requestJSON<{ ok: boolean; removed: number }>('POST', '/api/monitor/alerts/clear-resolved', {}),

  getMonitorPolicy: () => requestJSON<MonitorPolicyResponse>('GET', '/api/monitor/policy'),

  updateMonitorPolicy: (settings: MonitorSettings, rules: MonitorAlertRule[]) =>
    requestJSON<MonitorPolicyResponse & { ok: boolean }>('PUT', '/api/monitor/policy', {
      settings,
      rules,
    }),

  clearMonitorHistory: (server_id = '') =>
    requestJSON<{ ok: boolean }>('POST', '/api/monitor/clear-history', { server_id }),

  exportMonitorBlob: async (
    format: 'csv' | 'json',
    server_id = '',
    range = 'all'
  ): Promise<{ blob: Blob; filename: string }> => {
    const qs = new URLSearchParams({ format, range });
    if (server_id) qs.set('server_id', server_id);
    const res = await fetch(`/api/monitor/export?${qs.toString()}`, {
      method: 'GET',
      credentials: 'same-origin',
    });
    if (!res.ok) {
      await parseErrorResponse(res);
    }
    const blob = await res.blob();
    const filename = parseFilenameFromHeaders(res, `ServerNeedSafe-monitor.${format}`);
    return { blob, filename };
  },

  // 7x24 AI Ops, SSE Streaming, Hybrid Memory, Runbooks & Scheduled Patrol
  getAIOverview: (scope = '') =>
    requestJSON<AIOverviewResponse>(
      'GET',
      `/api/ai/overview${scope ? `?scope=${encodeURIComponent(scope)}` : ''}`
    ),

  upsertAIProvider: (payload: {
    id?: string;
    name: string;
    protocol: AIProtocol;
    base_url: string;
    api_key?: string;
    model: string;
    max_tokens?: number;
    context_window?: number;
    set_active?: boolean;
  }) =>
    requestJSON<{ provider: AIProviderView; active_provider_id: string }>(
      'POST',
      '/api/ai/providers',
      payload
    ),

  setActiveAIProvider: (provider_id: string, default_mode?: AIExecutionMode) =>
    requestJSON<{ ok: boolean; active_provider_id: string; default_mode: AIExecutionMode }>(
      'PUT',
      '/api/ai/active-provider',
      { provider_id, default_mode }
    ),

  deleteAIProvider: (id: string) =>
    requestJSON<{ ok: boolean; active_provider_id: string }>(
      'DELETE',
      `/api/ai/providers/${encodeURIComponent(id)}`
    ),

  testAIProvider: (payload: {
    id?: string;
    protocol: AIProtocol;
    base_url: string;
    api_key?: string;
    model: string;
  }) =>
    requestJSON<{ ok: boolean; latency_ms: number; reply: string }>(
      'POST',
      '/api/ai/test-provider',
      payload
    ),

  updateAgentsMD: (payload: { enabled: boolean; content: string; reset_default?: boolean }) =>
    requestJSON<{ ok: boolean; agents_md: AgentsMDConfig }>('PUT', '/api/ai/agents-md', payload),

  updateAIMemoryConfig: (payload: AIMemoryConfig) =>
    requestJSON<{ ok: boolean; memory_config: AIMemoryConfig }>(
      'PUT',
      '/api/ai/memory-config',
      payload
    ),

  resolveAgentsMDProposal: (proposal_id: string, accept: boolean) =>
    requestJSON<{ ok: boolean; agents_md: AgentsMDConfig; proposal: AIAgentsMDProposal }>(
      'POST',
      '/api/ai/agents-md-proposals/resolve',
      { proposal_id, accept }
    ),

  listAISessions: (scope = '') =>
    requestJSON<{ sessions: AIChatSessionSummary[] }>(
      'GET',
      `/api/ai/sessions${scope ? `?scope=${encodeURIComponent(scope)}` : ''}`
    ),

  createAISession: (payload: {
    title?: string;
    scope?: 'center' | 'terminal';
    server_ids?: string[];
    mode?: AIExecutionMode;
  }) => requestJSON<{ session: AIChatSession }>('POST', '/api/ai/sessions', payload),

  getAISession: (id: string) =>
    requestJSON<{ session: AIChatSession }>('GET', `/api/ai/sessions/${encodeURIComponent(id)}`),

  updateAISessionMode: (
    id: string,
    payload: { mode?: AIExecutionMode; server_ids?: string[]; title?: string }
  ) =>
    requestJSON<{ session: AIChatSession }>(
      'PUT',
      `/api/ai/sessions/${encodeURIComponent(id)}`,
      payload
    ),

  deleteAISession: (id: string) =>
    requestJSON<{ ok: boolean }>('DELETE', `/api/ai/sessions/${encodeURIComponent(id)}`),

  inspectAISessionContext: (id: string) =>
    requestJSON<{ context: SessionContextInspection }>(
      'GET',
      `/api/ai/sessions/${encodeURIComponent(id)}/context`
    ),

  compactAISession: (id: string, reset = false) =>
    requestJSON<{
      ok: boolean;
      session: AIChatSession;
      compaction: CompactionInfo;
      context: SessionContextInspection;
    }>('POST', `/api/ai/sessions/${encodeURIComponent(id)}/compact`, { reset }),

  streamAIChat: (
    sessionId: string,
    payload: {
      message: string;
      server_ids?: string[];
      mode?: AIExecutionMode;
      terminal_context?: string;
    },
    onEvent: (ev: AIStreamEvent) => void,
    signal?: AbortSignal
  ) =>
    postSSEStream(
      '/api/ai/chat/stream',
      {
        session_id: sessionId,
        ...payload,
      },
      onEvent,
      signal
    ),

  streamAIApproval: (
    sessionId: string,
    approvalId: string,
    approve: boolean,
    onEvent: (ev: AIStreamEvent) => void,
    signal?: AbortSignal
  ) =>
    postSSEStream(
      '/api/ai/approval/stream',
      {
        session_id: sessionId,
        approval_id: approvalId,
        approve,
      },
      onEvent,
      signal
    ),

  upsertHostMemory: (serverId: string, payload: Partial<HostMemory>) =>
    requestJSON<{ memory: HostMemory }>(
      'PUT',
      `/api/ai/host-memory/${encodeURIComponent(serverId)}`,
      payload
    ),

  deleteHostMemory: (serverId: string) =>
    requestJSON<{ ok: boolean }>(
      'DELETE',
      `/api/ai/host-memory/${encodeURIComponent(serverId)}`
    ),

  syncHostMemoryFromMonitor: (server_id = '') =>
    requestJSON<{ ok: boolean; synced_count: number; host_memories: HostMemory[] }>(
      'POST',
      '/api/ai/host-memory/sync-monitor',
      { server_id }
    ),

  listAIMemories: () =>
    requestJSON<{ memories: AIMemoryEntry[] }>('GET', '/api/ai/memories'),

  upsertAIMemory: (payload: Partial<AIMemoryEntry>) =>
    requestJSON<{ memory: AIMemoryEntry }>('POST', '/api/ai/memories', payload),

  deleteAIMemory: (id: string) =>
    requestJSON<{ ok: boolean }>('DELETE', `/api/ai/memories/${encodeURIComponent(id)}`),

  resolveRunbookProposal: (proposalId: string, accept: boolean, sync_snippet = false) =>
    requestJSON<{ ok: boolean; runbook?: AIRunbook }>(
      'POST',
      '/api/ai/runbook-proposals/resolve',
      {
        proposal_id: proposalId,
        accept,
        sync_snippet,
      }
    ),

  upsertRunbook: (payload: Partial<AIRunbook> & { sync_snippet?: boolean }) =>
    requestJSON<{ runbook: AIRunbook }>('POST', '/api/ai/runbooks', payload),

  deleteRunbook: (id: string) =>
    requestJSON<{ ok: boolean }>('DELETE', `/api/ai/runbooks/${encodeURIComponent(id)}`),

  updatePatrolConfig: (payload: Record<string, unknown>) =>
    requestJSON<{ patrol_config: PatrolConfigView; patrol_status: PatrolStatusView }>(
      'PUT',
      '/api/ai/patrol/config',
      payload
    ),

  listPatrolRecords: (limit = 30, markRead = false) =>
    requestJSON<{
      records: PatrolRecord[];
      unread_alerts: number;
      patrol_status: PatrolStatusView;
    }>('GET', `/api/ai/patrol/records?limit=${limit}&mark_read=${markRead ? 'true' : 'false'}`),

  runPatrolNow: (force_ai = true) =>
    requestJSON<{ record: PatrolRecord; patrol_status: PatrolStatusView }>(
      'POST',
      '/api/ai/patrol/run',
      { force_ai }
    ),

  testWebhook: (payload: {
    id?: string;
    name?: string;
    kind: string;
    url?: string;
    secret?: string;
  }) => requestJSON<{ ok: boolean }>('POST', '/api/ai/test-webhook', payload),

  // External AI Takeover (MCP Gateway, Persistent Scoped Tokens & External HITL Approvals)
  getMCPOverview: () => requestJSON<MCPOverviewResponse>('GET', '/api/ai/mcp/overview'),

  updateMCPConfig: (payload: {
    enabled?: boolean;
    desktop_loopback_enabled?: boolean;
    desktop_loopback_port?: number;
    public_endpoint_hint?: string;
  }) =>
    requestJSON<{
      ok: boolean;
      mcp_config: MCPConfigView;
      mcp_runtime: MCPRuntimeStatus;
      skill_markdown: string;
    }>('PUT', '/api/ai/mcp/config', payload),

  createMCPToken: (payload: {
    name: string;
    client_hint?: string;
    scope: MCPTokenScope;
    allowed_servers?: string[];
  }) =>
    requestJSON<{
      ok: boolean;
      token: MCPTokenView;
      raw_token: string;
      mcp_config: MCPConfigView;
      mcp_runtime: MCPRuntimeStatus;
    }>('POST', '/api/ai/mcp/tokens', payload),

  updateMCPToken: (
    id: string,
    payload: {
      name?: string;
      client_hint?: string;
      scope?: MCPTokenScope;
      allowed_servers?: string[];
      enabled?: boolean;
    }
  ) =>
    requestJSON<{
      ok: boolean;
      token: MCPTokenView;
      mcp_config: MCPConfigView;
    }>('PUT', `/api/ai/mcp/tokens/${encodeURIComponent(id)}`, payload),

  deleteMCPToken: (id: string) =>
    requestJSON<{ ok: boolean; mcp_config: MCPConfigView }>(
      'DELETE',
      `/api/ai/mcp/tokens/${encodeURIComponent(id)}`
    ),

  listExternalApprovals: (status = 'all', limit = 60) =>
    requestJSON<{ approvals: ExternalApproval[]; pending_count: number }>(
      'GET',
      `/api/ai/external-approvals?status=${encodeURIComponent(status)}&limit=${limit}`
    ),

  resolveExternalApproval: (id: string, approve: boolean) =>
    requestJSON<{
      ok: boolean;
      approval: ExternalApproval;
      approvals: ExternalApproval[];
      pending_count: number;
    }>('POST', `/api/ai/external-approvals/${encodeURIComponent(id)}/resolve`, { approve }),

  // GitHub Release Auto-Detection, China Mirror Probing & Self-Update
  getHealth: () =>
    requestJSON<{ ok: boolean; version?: string; mode?: string; daemon_running?: boolean }>(
      'GET',
      '/api/health'
    ),

  getUpdateStatus: () => requestJSON<UpdateOverviewResponse>('GET', '/api/system/update/status'),

  checkUpdateNow: (force_probe = false) =>
    requestJSON<UpdateOverviewResponse>('POST', '/api/system/update/check', { force_probe }),

  probeUpdateMirrors: () =>
    requestJSON<{ ok: boolean; mirrors: MirrorProbeResult[]; status: UpdateOverviewResponse }>(
      'POST',
      '/api/system/update/mirrors/probe',
      {}
    ),

  updateUpdateConfig: (payload: UpdateSettings) =>
    requestJSON<{ ok: boolean; settings: UpdateSettings; status: UpdateOverviewResponse }>(
      'PUT',
      '/api/system/update/config',
      payload
    ),

  skipUpdateVersion: (version: string) =>
    requestJSON<{ ok: boolean; settings: UpdateSettings; status: UpdateOverviewResponse }>(
      'POST',
      '/api/system/update/skip',
      { version }
    ),

  applyUpdate: (confirm_disconnect_ssh = false) =>
    requestJSON<{ ok: boolean; status: UpdateOverviewResponse }>(
      'POST',
      '/api/system/update/apply',
      { confirm_disconnect_ssh }
    ),
};

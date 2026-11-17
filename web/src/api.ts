import type {
  AIChatSession,
  AIChatSessionSummary,
  AIExecutionMode,
  AIOverviewResponse,
  AIProtocol,
  AIProviderView,
  AIRunbook,
  AIStreamEvent,
  AppSettings,
  AuthStatusResponse,
  BatchExecResult,
  CredentialView,
  HostKeyUntrustedInfo,
  HostMemory,
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
  SFTPListResponse,
  Snippet,
  SyncSummary,
  TerminalReadyInfo,
  VaultAnchor,
  VaultSecurityOverview,
} from './types';
import { clearLocalAnchorStorage, zkClient, ZkRpcError } from './zk/zkClient';

const LEGACY_SESSION_KEY = 'sns_session_token';

export class ApiError extends Error {
  status: number;
  code: string;
  hostKeyInfo?: HostKeyUntrustedInfo;
  retryAfterSec?: number;

  constructor(
    message: string,
    status: number,
    code = 'ERROR',
    hostKeyInfo?: HostKeyUntrustedInfo,
    retryAfterSec?: number
  ) {
    super(message);
    this.status = status;
    this.code = code;
    this.hostKeyInfo = hostKeyInfo;
    this.retryAfterSec = retryAfterSec;
  }
}

// In Zero-Knowledge E2EE mode, session tokens live exclusively inside the isolated
// Dedicated Web Worker WASM heap and are NEVER persisted to sessionStorage/localStorage.
export function getSessionToken(): string {
  try {
    sessionStorage.removeItem(LEGACY_SESSION_KEY);
  } catch {
    // ignore
  }
  return '';
}

export function setSessionToken(_token: string): void {
  try {
    sessionStorage.removeItem(LEGACY_SESSION_KEY);
  } catch {
    // ignore
  }
}

let onUnauthorizedCallback: (() => void) | null = null;

export function registerOnUnauthorized(fn: () => void): void {
  onUnauthorizedCallback = fn;
}

function mapZkError(err: unknown): never {
  if (err instanceof ZkRpcError) {
    if (err.code === 'VAULT_LOCKED' || err.code === 'UNAUTHORIZED') {
      onUnauthorizedCallback?.();
    }
    throw new ApiError(
      err.message,
      err.status,
      err.code,
      err.hostKeyInfo,
      err.retryAfterSec
    );
  }
  if (err instanceof ApiError) {
    throw err;
  }
  throw new ApiError((err as Error)?.message || '零知识引擎调用失败', 500, 'WASM_CALL_ERROR');
}

async function zkCall<T>(action: string, payload?: unknown, binary?: Uint8Array): Promise<T> {
  try {
    return await zkClient.call<T>(action, payload, binary);
  } catch (err) {
    mapZkError(err);
  }
}

async function zkCallWithBytes<T>(
  action: string,
  payload?: unknown,
  binary?: Uint8Array
): Promise<{ data: T; bytes?: Uint8Array }> {
  try {
    return await zkClient.callWithBytes<T>(action, payload, binary);
  } catch (err) {
    mapZkError(err);
  }
}

async function zkCallAIStream(
  action: 'streamAIChat' | 'streamAIApproval',
  payload: Record<string, unknown>,
  onEvent: (ev: AIStreamEvent) => void,
  signal?: AbortSignal
): Promise<void> {
  try {
    await zkClient.callAIStream<AIStreamEvent>(action, payload, onEvent, signal);
  } catch (err) {
    mapZkError(err);
  }
}

export const api = {
  getAuthStatus: () => zkCall<AuthStatusResponse>('getAuthStatus'),

  setupVault: async (password: string) => {
    const res = await zkCall<{
      status: AuthStatusResponse;
      settings: AppSettings;
      anchor?: VaultAnchor;
    }>('setupVault', { password });
    return { token: '', settings: res.settings, status: res.status, anchor: res.anchor };
  },

  unlockVault: async (password: string) => {
    const res = await zkCall<{
      status: AuthStatusResponse;
      settings: AppSettings;
      anchor?: VaultAnchor;
    }>('unlockVault', { password });
    return { token: '', settings: res.settings, status: res.status, anchor: res.anchor };
  },

  verifyUnlockPassword: async (password: string) => {
    const res = await zkCall<{
      status: AuthStatusResponse;
      settings: AppSettings;
      anchor?: VaultAnchor;
    }>('verifyUnlockPassword', { password });
    return { token: '', settings: res.settings, status: res.status, anchor: res.anchor };
  },

  lockVault: async (): Promise<{ ok: boolean }> => {
    try {
      await zkClient.call('lockVault');
    } catch {
      // ignore if already locked
    } finally {
      zkClient.destroyWorkerMemory();
    }
    return { ok: true };
  },

  logoutSession: async (): Promise<{ ok: boolean }> => {
    try {
      await zkClient.call('logoutSession');
    } catch {
      // ignore
    } finally {
      zkClient.destroyWorkerMemory();
    }
    return { ok: true };
  },

  clearLocalAnchor: async (): Promise<void> => {
    clearLocalAnchorStorage();
    try {
      await zkClient.call('clearAnchor');
    } catch {
      // ignore
    }
  },

  changePassword: async (old_password: string, new_password: string) => {
    const res = await zkCall<{ ok: boolean; anchor?: VaultAnchor }>('changePassword', {
      old_password,
      new_password,
    });
    return { ok: res.ok, token: '' };
  },

  exportVaultBlob: async (): Promise<{ blob: Blob; filename: string }> => {
    const { data, bytes } = await zkCallWithBytes<{ filename: string }>('exportVault');
    if (!bytes || bytes.byteLength === 0) {
      throw new ApiError('导出加密数据包为空', 500, 'EMPTY_EXPORT');
    }
    const copy = new Uint8Array(bytes.byteLength);
    copy.set(bytes);
    const blob = new Blob([copy.buffer], { type: 'application/octet-stream' });
    return { blob, filename: data.filename || 'ServerNeedSafe-backup.sns' };
  },

  importVault: async (
    file: File,
    password: string,
    opts?: { currentAdminPassword?: string; clearAnchor?: boolean }
  ) => {
    const buf = await file.arrayBuffer();
    const u8 = new Uint8Array(buf);
    try {
      const res = await zkCall<{
        ok: boolean;
        status: AuthStatusResponse;
        settings: AppSettings;
        anchor?: VaultAnchor;
      }>(
        'importVault',
        {
          password,
          current_admin_password: opts?.currentAdminPassword || '',
          clear_anchor: Boolean(opts?.clearAnchor),
        },
        u8
      );
      return { ok: res.ok, token: '', settings: res.settings, status: res.status };
    } finally {
      u8.fill(0);
    }
  },

  getVaultSecurity: () => zkCall<VaultSecurityOverview>('getVaultSecurity'),

  updateSettings: (settings: AppSettings) =>
    zkCall<{ settings: AppSettings }>('updateSettings', settings),

  deleteKnownHost: (address: string) =>
    zkCall<{ ok: boolean }>('deleteKnownHost', { address }),

  // Remote Zero-Knowledge Vault Sync (server <-> desktop or server <-> server)
  syncPush: (remote_url: string, remote_password = '') =>
    zkCall<{ summary: SyncSummary; anchor?: VaultAnchor }>('syncPush', {
      remote_url,
      remote_password,
    }),

  syncPull: (remote_url: string, remote_password = '', current_local_password = '') =>
    zkCall<{ summary: SyncSummary; anchor?: VaultAnchor }>('syncPull', {
      remote_url,
      remote_password,
      current_local_password,
    }),

  // Servers & Groups
  listServers: () =>
    zkCall<{
      servers: ServerView[];
      groups: string[];
      active_sessions: { id: string; server_id: string; server_name: string; started_at: string }[];
    }>('listServers'),

  createServer: (payload: ServerMutationPayload) =>
    zkCall<{ server: ServerView }>('createServer', payload),

  updateServer: (id: string, payload: ServerMutationPayload) =>
    zkCall<{ server: ServerView }>('updateServer', { id, payload }),

  deleteServer: (id: string) =>
    zkCall<{ ok: boolean }>('deleteServer', { id }),

  probeServer: (id: string, trustFingerprint = '') =>
    zkCall<{ probe: ServerProbeResult }>('probeServer', {
      id,
      trust_fingerprint: trustFingerprint,
    }),

  addGroup: (name: string) =>
    zkCall<{ groups: string[] }>('addGroup', { name }),

  deleteGroup: (name: string) =>
    zkCall<{ groups: string[] }>('deleteGroup', { name }),

  // Credentials & SSH Keys
  listCredentials: () =>
    zkCall<{ credentials: CredentialView[] }>('listCredentials'),

  createCredential: (payload: Record<string, any>) =>
    zkCall<{ credential: CredentialView }>('createCredential', payload),

  updateCredential: (id: string, payload: Record<string, any>) =>
    zkCall<{ credential: CredentialView }>('updateCredential', { id, payload }),

  deleteCredential: (id: string) =>
    zkCall<{ ok: boolean }>('deleteCredential', { id }),

  generateKeyPair: (payload: {
    algorithm: string;
    comment: string;
    passphrase: string;
    save_name: string;
    username_hint: string;
    notes: string;
  }) =>
    zkCall<{
      algorithm: string;
      public_key: string;
      private_key?: string;
      fingerprint: string;
      credential?: CredentialView;
    }>('generateKeyPair', payload),

  deployPublicKey: (payload: { server_id: string; credential_id?: string; public_key?: string }) =>
    zkCall<{ ok: boolean }>('deployPublicKey', payload),

  // Snippets & Batch Execution
  listSnippets: () => zkCall<{ snippets: Snippet[] }>('listSnippets'),

  upsertSnippet: (snippet: Partial<Snippet>) =>
    zkCall<{ snippet: Snippet }>('upsertSnippet', snippet),

  deleteSnippet: (id: string) =>
    zkCall<{ ok: boolean }>('deleteSnippet', { id }),

  batchExec: (server_ids: string[], command: string, timeout_sec = 25) =>
    zkCall<{ results: BatchExecResult[] }>('batchExec', {
      server_ids,
      command,
      timeout_sec,
    }),

  // Client-side E2EE SSH Terminal inside Dedicated WASM Worker over blind TCP relay
  openTerminalSession: (payload: {
    tab_id: string;
    server_id: string;
    cols: number;
    rows: number;
    trust_fingerprint?: string;
  }) => zkCall<{ ready: TerminalReadyInfo }>('openTerminal', payload),

  // Client-side E2EE SFTP over blind TCP relay (server never sees filenames, paths, or bytes)
  sftpList: (serverId: string, dirPath = '') =>
    zkCall<SFTPListResponse>('sftpList', { server_id: serverId, path: dirPath }),

  sftpRead: (serverId: string, filePath: string) =>
    zkCall<{ path: string; content: string }>('sftpRead', {
      server_id: serverId,
      path: filePath,
    }),

  sftpWrite: (serverId: string, filePath: string, content: string) =>
    zkCall<{ ok: boolean }>('sftpWrite', {
      server_id: serverId,
      path: filePath,
      content,
    }),

  sftpUpload: async (serverId: string, dir: string, file: File) => {
    const buf = await file.arrayBuffer();
    const u8 = new Uint8Array(buf);
    try {
      return await zkCall<{ ok: boolean; path: string; bytes: number }>(
        'sftpUpload',
        { server_id: serverId, dir, filename: file.name },
        u8
      );
    } finally {
      u8.fill(0);
    }
  },

  sftpDownloadBlob: async (
    serverId: string,
    filePath: string
  ): Promise<{ blob: Blob; filename: string }> => {
    const { data, bytes } = await zkCallWithBytes<{ filename: string }>('sftpDownload', {
      server_id: serverId,
      path: filePath,
    });
    const raw = bytes ? new Uint8Array(bytes) : new Uint8Array(0);
    const blob = new Blob([raw.buffer], { type: 'application/octet-stream' });
    return { blob, filename: data.filename || 'download.bin' };
  },

  sftpMkdir: (serverId: string, path: string) =>
    zkCall<{ ok: boolean }>('sftpMkdir', { server_id: serverId, path }),

  sftpRename: (serverId: string, old_path: string, new_path: string) =>
    zkCall<{ ok: boolean }>('sftpRename', { server_id: serverId, old_path, new_path }),

  sftpDelete: (serverId: string, path: string) =>
    zkCall<{ ok: boolean }>('sftpDelete', { server_id: serverId, path }),

  sftpChmod: (serverId: string, path: string, mode: string) =>
    zkCall<{ ok: boolean }>('sftpChmod', { server_id: serverId, path, mode }),

  // Client-side E2EE Server Status Monitoring & Time-Series Telemetry (zero server plaintext)
  getMonitorOverview: () => zkCall<MonitorOverviewResponse>('getMonitorOverview'),

  getServerMonitorDetail: (id: string, range = '1h') =>
    zkCall<ServerMonitorDetailResponse>('getServerMonitorDetail', { id, range }),

  collectAllMonitor: (server_ids: string[] = []) =>
    zkCall<{
      ok: boolean;
      count: number;
      snapshots: ServerMonitorSnapshot[];
      runtime: MonitorRuntimeStatus;
    }>('collectAllMonitor', { server_ids }),

  collectServerMonitor: (id: string, trust_fingerprint = '') =>
    zkCall<{
      ok: boolean;
      snapshot: ServerMonitorSnapshot;
      runtime: MonitorRuntimeStatus;
    }>('collectServerMonitor', { id, trust_fingerprint }),

  acceptPortBaseline: (id: string) =>
    zkCall<{ ok: boolean; port_baseline: string[] }>('acceptPortBaseline', { id }),

  listMonitorAlerts: (status = '', server_id = '', limit = 300) =>
    zkCall<{ alerts: MonitorAlert[] }>('listMonitorAlerts', { status, server_id, limit }),

  ackMonitorAlert: (id: string) =>
    zkCall<{ ok: boolean; alert: MonitorAlert }>('ackMonitorAlert', { id }),

  clearResolvedMonitorAlerts: () =>
    zkCall<{ ok: boolean; removed: number }>('clearResolvedMonitorAlerts'),

  getMonitorPolicy: () => zkCall<MonitorPolicyResponse>('getMonitorPolicy'),

  updateMonitorPolicy: (settings: MonitorSettings, rules: MonitorAlertRule[]) =>
    zkCall<MonitorPolicyResponse & { ok: boolean }>('updateMonitorPolicy', { settings, rules }),

  clearMonitorHistory: (server_id = '') =>
    zkCall<{ ok: boolean }>('clearMonitorHistory', { server_id }),

  exportMonitorBlob: async (
    format: 'csv' | 'json',
    server_id = '',
    range = 'all'
  ): Promise<{ blob: Blob; filename: string }> => {
    const { data, bytes } = await zkCallWithBytes<{
      filename: string;
      content_type: string;
    }>('exportMonitorHistory', { format, server_id, range });
    const raw = bytes ? new Uint8Array(bytes) : new Uint8Array(0);
    const copy = new Uint8Array(raw.byteLength);
    copy.set(raw);
    const mime =
      data.content_type ||
      (format === 'csv' ? 'text/csv; charset=utf-8' : 'application/json; charset=utf-8');
    const blob = new Blob([copy.buffer], { type: mime });
    return { blob, filename: data.filename || `ServerNeedSafe-monitor.${format}` };
  },

  // Client-side Zero-Knowledge AI Ops, Hybrid Memory, Runbooks & Scheduled Patrol
  getAIOverview: (scope = '') =>
    zkCall<AIOverviewResponse>('getAIOverview', { scope }),

  upsertAIProvider: (payload: {
    id?: string;
    name: string;
    protocol: AIProtocol;
    base_url: string;
    api_key?: string;
    model: string;
    max_tokens?: number;
    set_active?: boolean;
  }) =>
    zkCall<{ provider: AIProviderView; active_provider_id: string }>('upsertAIProvider', payload),

  setActiveAIProvider: (provider_id: string, default_mode?: AIExecutionMode) =>
    zkCall<{ ok: boolean; active_provider_id: string; default_mode: AIExecutionMode }>(
      'setActiveAIProvider',
      { provider_id, default_mode }
    ),

  deleteAIProvider: (id: string) =>
    zkCall<{ ok: boolean; active_provider_id: string }>('deleteAIProvider', { id }),

  testAIProvider: (payload: {
    id?: string;
    protocol: AIProtocol;
    base_url: string;
    api_key?: string;
    model: string;
  }) => zkCall<{ ok: boolean; latency_ms: number; reply: string }>('testAIProvider', payload),

  listAISessions: (scope = '') =>
    zkCall<{ sessions: AIChatSessionSummary[] }>('listAISessions', { scope }),

  createAISession: (payload: {
    title?: string;
    scope?: 'center' | 'terminal';
    server_ids?: string[];
    mode?: AIExecutionMode;
  }) => zkCall<{ session: AIChatSession }>('createAISession', payload),

  getAISession: (id: string) =>
    zkCall<{ session: AIChatSession }>('getAISession', { id }),

  updateAISessionMode: (
    id: string,
    payload: { mode?: AIExecutionMode; server_ids?: string[]; title?: string }
  ) => zkCall<{ session: AIChatSession }>('updateAISessionMode', { id, ...payload }),

  deleteAISession: (id: string) =>
    zkCall<{ ok: boolean }>('deleteAISession', { id }),

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
    zkCallAIStream(
      'streamAIChat',
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
    zkCallAIStream(
      'streamAIApproval',
      {
        session_id: sessionId,
        approval_id: approvalId,
        approve,
      },
      onEvent,
      signal
    ),

  upsertHostMemory: (serverId: string, payload: Partial<HostMemory>) =>
    zkCall<{ memory: HostMemory }>('upsertHostMemory', { ...payload, server_id: serverId }),

  deleteHostMemory: (serverId: string) =>
    zkCall<{ ok: boolean }>('deleteHostMemory', { server_id: serverId }),

  resolveRunbookProposal: (proposalId: string, accept: boolean, sync_snippet = false) =>
    zkCall<{ ok: boolean; runbook?: AIRunbook }>('resolveRunbookProposal', {
      proposal_id: proposalId,
      accept,
      sync_snippet,
    }),

  upsertRunbook: (payload: Partial<AIRunbook> & { sync_snippet?: boolean }) =>
    zkCall<{ runbook: AIRunbook }>('upsertRunbook', payload),

  deleteRunbook: (id: string) =>
    zkCall<{ ok: boolean }>('deleteRunbook', { id }),

  updatePatrolConfig: (payload: Record<string, any>) =>
    zkCall<{ patrol_config: PatrolConfigView; patrol_status: PatrolStatusView }>(
      'updatePatrolConfig',
      payload
    ),

  listPatrolRecords: (limit = 30, markRead = false) =>
    zkCall<{
      records: PatrolRecord[];
      unread_alerts: number;
      patrol_status: PatrolStatusView;
    }>('listPatrolRecords', { limit, mark_read: markRead }),

  runPatrolNow: (force_ai = true) =>
    zkCall<{ record: PatrolRecord; patrol_status: PatrolStatusView }>('runPatrolNow', { force_ai }),

  testWebhook: (payload: {
    id?: string;
    name?: string;
    kind: string;
    url?: string;
    secret?: string;
  }) => zkCall<{ ok: boolean }>('testAIWebhook', payload),
};

import type {
  AppSettings,
  AuthStatusResponse,
  BatchExecResult,
  CredentialView,
  HostKeyUntrustedInfo,
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
};

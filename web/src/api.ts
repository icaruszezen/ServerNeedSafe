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
  VaultSecurityOverview,
} from './types';

const SESSION_KEY = 'sns_session_token';

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

export function getSessionToken(): string {
  return sessionStorage.getItem(SESSION_KEY) || '';
}

export function setSessionToken(token: string): void {
  if (token) {
    sessionStorage.setItem(SESSION_KEY, token);
  } else {
    sessionStorage.removeItem(SESSION_KEY);
  }
}

let onUnauthorizedCallback: (() => void) | null = null;

export function registerOnUnauthorized(fn: () => void): void {
  onUnauthorizedCallback = fn;
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers || {});
  const token = getSessionToken();
  if (token) {
    headers.set('Authorization', `Bearer ${token}`);
  }
  if (init.body && !(init.body instanceof FormData) && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }

  const res = await fetch(path, { ...init, headers });
  let data: any = null;
  const contentType = res.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    data = await res.json().catch(() => null);
  }

  if (!res.ok) {
    const code = data?.code || 'HTTP_ERROR';
    if (res.status === 401 && !path.startsWith('/api/auth/')) {
      setSessionToken('');
      if (onUnauthorizedCallback) onUnauthorizedCallback();
    }
    throw new ApiError(
      data?.error || `请求失败 (${res.status})`,
      res.status,
      code,
      data?.host_key_info,
      data?.retry_after_sec
    );
  }
  return data as T;
}

export const api = {
  getAuthStatus: () => request<AuthStatusResponse>('/api/auth/status'),

  setupVault: (password: string) =>
    request<{ token: string; settings: AppSettings }>('/api/auth/setup', {
      method: 'POST',
      body: JSON.stringify({ password }),
    }),

  unlockVault: (password: string) =>
    request<{ token: string; settings: AppSettings }>('/api/auth/unlock', {
      method: 'POST',
      body: JSON.stringify({ password }),
    }),

  lockVault: () =>
    request<{ ok: boolean }>('/api/auth/lock', { method: 'POST' }),

  logoutSession: () =>
    request<{ ok: boolean }>('/api/auth/logout', { method: 'POST' }),

  changePassword: (old_password: string, new_password: string) =>
    request<{ ok: boolean; token: string }>('/api/auth/password', {
      method: 'POST',
      body: JSON.stringify({ old_password, new_password }),
    }),

  exportVaultBlob: async (): Promise<{ blob: Blob; filename: string }> => {
    const token = getSessionToken();
    const res = await fetch('/api/vault/export', {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    if (!res.ok) {
      throw new ApiError('导出加密数据包失败', res.status);
    }
    const disp = res.headers.get('Content-Disposition') || '';
    const match = disp.match(/filename="?([^"]+)"?/i);
    const filename = match?.[1] || 'ServerNeedSafe-backup.sns';
    const blob = await res.blob();
    return { blob, filename };
  },

  importVault: (file: File, password: string) => {
    const fd = new FormData();
    fd.append('file', file);
    fd.append('password', password);
    return request<{ ok: boolean; token: string; settings: AppSettings }>('/api/vault/import', {
      method: 'POST',
      body: fd,
    });
  },

  getVaultSecurity: () => request<VaultSecurityOverview>('/api/vault/security'),

  updateSettings: (settings: AppSettings) =>
    request<{ settings: AppSettings }>('/api/vault/settings', {
      method: 'PUT',
      body: JSON.stringify(settings),
    }),

  deleteKnownHost: (address: string) =>
    request<{ ok: boolean }>(`/api/vault/known-hosts?address=${encodeURIComponent(address)}`, {
      method: 'DELETE',
    }),

  // Servers & Groups
  listServers: () =>
    request<{
      servers: ServerView[];
      groups: string[];
      active_sessions: { id: string; server_id: string; server_name: string; started_at: string }[];
    }>('/api/servers'),

  createServer: (payload: ServerMutationPayload) =>
    request<{ server: ServerView }>('/api/servers', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  updateServer: (id: string, payload: ServerMutationPayload) =>
    request<{ server: ServerView }>(`/api/servers/${encodeURIComponent(id)}`, {
      method: 'PUT',
      body: JSON.stringify(payload),
    }),

  deleteServer: (id: string) =>
    request<{ ok: boolean }>(`/api/servers/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    }),

  probeServer: (id: string, trustFingerprint = '') =>
    request<{ probe: ServerProbeResult }>(`/api/servers/${encodeURIComponent(id)}/probe`, {
      method: 'POST',
      body: JSON.stringify({ trust_fingerprint: trustFingerprint }),
    }),

  addGroup: (name: string) =>
    request<{ groups: string[] }>('/api/groups', {
      method: 'POST',
      body: JSON.stringify({ name }),
    }),

  deleteGroup: (name: string) =>
    request<{ groups: string[] }>(`/api/groups?name=${encodeURIComponent(name)}`, {
      method: 'DELETE',
    }),

  // Credentials & SSH Keys
  listCredentials: () =>
    request<{ credentials: CredentialView[] }>('/api/credentials'),

  createCredential: (payload: Record<string, any>) =>
    request<{ credential: CredentialView }>('/api/credentials', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  updateCredential: (id: string, payload: Record<string, any>) =>
    request<{ credential: CredentialView }>(`/api/credentials/${encodeURIComponent(id)}`, {
      method: 'PUT',
      body: JSON.stringify(payload),
    }),

  deleteCredential: (id: string) =>
    request<{ ok: boolean }>(`/api/credentials/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    }),

  generateKeyPair: (payload: {
    algorithm: string;
    comment: string;
    passphrase: string;
    save_name: string;
    username_hint: string;
    notes: string;
  }) =>
    request<{
      algorithm: string;
      public_key: string;
      private_key?: string;
      fingerprint: string;
      credential?: CredentialView;
    }>('/api/keys/generate', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  deployPublicKey: (payload: { server_id: string; credential_id?: string; public_key?: string }) =>
    request<{ ok: boolean }>('/api/keys/deploy', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  // Snippets & Batch Execution
  listSnippets: () => request<{ snippets: Snippet[] }>('/api/snippets'),

  upsertSnippet: (snippet: Partial<Snippet>) =>
    request<{ snippet: Snippet }>('/api/snippets', {
      method: 'POST',
      body: JSON.stringify(snippet),
    }),

  deleteSnippet: (id: string) =>
    request<{ ok: boolean }>(`/api/snippets/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    }),

  batchExec: (server_ids: string[], command: string, timeout_sec = 25) =>
    request<{ results: BatchExecResult[] }>('/api/snippets/batch-exec', {
      method: 'POST',
      body: JSON.stringify({ server_ids, command, timeout_sec }),
    }),

  // Tickets & SFTP
  issueTicket: (purpose: 'ws_ssh' | 'sftp_download', server_id: string, path = '') =>
    request<{ ticket: string }>('/api/ws/ticket', {
      method: 'POST',
      body: JSON.stringify({ purpose, server_id, path }),
    }),

  sftpList: (serverId: string, dirPath = '') =>
    request<SFTPListResponse>(
      `/api/sftp/${encodeURIComponent(serverId)}/list?path=${encodeURIComponent(dirPath)}`
    ),

  sftpRead: (serverId: string, filePath: string) =>
    request<{ path: string; content: string }>(
      `/api/sftp/${encodeURIComponent(serverId)}/read?path=${encodeURIComponent(filePath)}`
    ),

  sftpWrite: (serverId: string, filePath: string, content: string) =>
    request<{ ok: boolean }>(`/api/sftp/${encodeURIComponent(serverId)}/write`, {
      method: 'POST',
      body: JSON.stringify({ path: filePath, content }),
    }),

  sftpUpload: (serverId: string, dir: string, file: File) => {
    const fd = new FormData();
    fd.append('dir', dir);
    fd.append('file', file);
    return request<{ ok: boolean; path: string; bytes: number }>(
      `/api/sftp/${encodeURIComponent(serverId)}/upload`,
      { method: 'POST', body: fd }
    );
  },

  sftpMkdir: (serverId: string, path: string) =>
    request<{ ok: boolean }>(`/api/sftp/${encodeURIComponent(serverId)}/mkdir`, {
      method: 'POST',
      body: JSON.stringify({ path }),
    }),

  sftpRename: (serverId: string, old_path: string, new_path: string) =>
    request<{ ok: boolean }>(`/api/sftp/${encodeURIComponent(serverId)}/rename`, {
      method: 'POST',
      body: JSON.stringify({ old_path, new_path }),
    }),

  sftpDelete: (serverId: string, path: string) =>
    request<{ ok: boolean }>(`/api/sftp/${encodeURIComponent(serverId)}/delete`, {
      method: 'POST',
      body: JSON.stringify({ path }),
    }),

  sftpChmod: (serverId: string, path: string, mode: string) =>
    request<{ ok: boolean }>(`/api/sftp/${encodeURIComponent(serverId)}/chmod`, {
      method: 'POST',
      body: JSON.stringify({ path, mode }),
    }),
};

export function buildSSHWebSocketURL(
  serverId: string,
  ticket: string,
  cols: number,
  rows: number,
  trustFingerprint = ''
): string {
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const params = new URLSearchParams({
    ticket,
    cols: String(cols),
    rows: String(rows),
  });
  if (trustFingerprint) {
    params.set('trust_fingerprint', trustFingerprint);
  }
  return `${proto}//${window.location.host}/api/ws/ssh/${encodeURIComponent(serverId)}?${params.toString()}`;
}

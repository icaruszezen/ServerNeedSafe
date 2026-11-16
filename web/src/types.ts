export type VaultStatus = 'uninitialized' | 'locked' | 'unlocked';
export type AuthType = 'password' | 'private_key' | 'credential';
export type HostKeyPolicy = 'tofu' | 'ask_new';

export interface EncryptionInfo {
  format_version: number;
  kdf_algo: string;
  kdf_time: number;
  kdf_memory_kib: number;
  kdf_threads: number;
  wrap_algo: string;
  cipher_algo: string;
  vault_size_bytes: number;
}

export interface AppSettings {
  auto_lock_minutes: number;
  host_key_policy: HostKeyPolicy;
  terminal_font_size: number;
  terminal_scrollback: number;
  show_hidden_files: boolean;
}

export interface AuthStatusResponse {
  vault_status: VaultStatus;
  authenticated: boolean;
  deploy_mode: 'server' | 'desktop';
  vault_path: string;
  encryption: EncryptionInfo;
  settings?: AppSettings;
}

export interface ServerView {
  id: string;
  name: string;
  group: string;
  tags: string[];
  host: string;
  port: number;
  username: string;
  auth_type: AuthType;
  has_password: boolean;
  has_private_key: boolean;
  has_passphrase: boolean;
  credential_id?: string;
  jump_server_id?: string;
  default_path?: string;
  notes?: string;
  pinned: boolean;
  keep_alive_sec: number;
  last_connected_at?: string;
  last_latency_ms?: number;
  last_os_info?: string;
  created_at: string;
  updated_at: string;
}

export interface ServerMutationPayload {
  name: string;
  group: string;
  tags: string[];
  host: string;
  port: number;
  username: string;
  auth_type: AuthType;
  password?: string;
  private_key?: string;
  passphrase?: string;
  credential_id: string;
  jump_server_id: string;
  default_path: string;
  notes: string;
  pinned: boolean;
  keep_alive_sec: number;
}

export interface HostKeyUntrustedInfo {
  reason: 'unknown' | 'mismatch';
  address: string;
  server_name: string;
  key_type: string;
  presented_fingerprint: string;
  presented_public_key: string;
  expected_fingerprint?: string;
}

export interface ServerProbeResult {
  server_id: string;
  server_name: string;
  reachable: boolean;
  latency_ms: number;
  fingerprint?: string;
  hostname?: string;
  os?: string;
  kernel?: string;
  arch?: string;
  uptime?: string;
  cpu_cores?: number;
  load_avg?: string;
  mem_used_mb?: number;
  mem_total_mb?: number;
  mem_percent?: number;
  disk_used_gb?: number;
  disk_total_gb?: number;
  disk_percent?: number;
}

export interface CredentialView {
  id: string;
  name: string;
  kind: 'password' | 'private_key';
  username_hint?: string;
  has_password: boolean;
  has_private_key: boolean;
  has_passphrase: boolean;
  public_key?: string;
  fingerprint?: string;
  key_algorithm?: string;
  notes?: string;
  created_at: string;
  updated_at: string;
}

export interface Snippet {
  id: string;
  title: string;
  category: string;
  command: string;
  description?: string;
  created_at?: string;
  updated_at?: string;
}

export interface BatchExecResult {
  server_id: string;
  server_name: string;
  host: string;
  success: boolean;
  exit_code: number;
  stdout: string;
  stderr: string;
  duration_ms: number;
  error?: string;
}

export interface SFTPFileEntry {
  name: string;
  path: string;
  size: number;
  mode: string;
  octal_perm: string;
  mod_time: string;
  is_dir: boolean;
  is_symlink: boolean;
}

export interface SFTPListResponse {
  current_path: string;
  home_path: string;
  entries: SFTPFileEntry[];
}

export interface KnownHost {
  address: string;
  server_name: string;
  key_type: string;
  fingerprint: string;
  public_key_b64: string;
  first_seen_at: string;
  last_verified_at: string;
}

export interface AuditEntry {
  id: string;
  timestamp: string;
  action: string;
  target?: string;
  detail?: string;
  client_ip?: string;
  success: boolean;
}

export interface VaultSecurityOverview {
  deploy_mode: string;
  vault_path: string;
  encryption: EncryptionInfo;
  settings: AppSettings;
  known_hosts: KnownHost[];
  audit_logs: AuditEntry[];
  active_sessions: number;
  active_ssh_tabs: number;
}

export interface OpenTerminalTab {
  tabId: string;
  server: ServerView;
  trustFingerprint?: string;
}

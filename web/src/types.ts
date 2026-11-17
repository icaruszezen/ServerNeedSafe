export type VaultStatus = 'uninitialized' | 'locked' | 'unlocked';
export type AuthType = 'password' | 'private_key' | 'credential';
export type HostKeyPolicy = 'tofu' | 'ask_new';

export interface VaultAnchor {
  vault_id: string;
  min_revision: number;
  auth_pubkey_sha256: string;
  min_kdf_memory_kib: number;
  min_kdf_time: number;
  updated_at: string;
}

export interface SyncSummary {
  direction: 'push' | 'pull';
  remote_url: string;
  vault_id: string;
  revision: number;
  bytes: number;
}

export interface EncryptionInfo {
  format_version: number;
  vault_id?: string;
  revision?: number;
  kdf_algo: string;
  kdf_time: number;
  kdf_memory_kib: number;
  kdf_threads: number;
  wrap_algo: string;
  cipher_algo: string;
  auth_algo?: string;
  auth_pubkey_sha256?: string;
  zero_knowledge?: boolean;
  vault_size_bytes: number;
}

export interface AppSettings {
  auto_lock_minutes: number;
  host_key_policy: HostKeyPolicy;
  terminal_font_size: number;
  terminal_scrollback: number;
  show_hidden_files: boolean;
  remote_sync_url?: string;
}

export interface AuthStatusResponse {
  initialized?: boolean;
  vault_status: VaultStatus;
  authenticated: boolean;
  deploy_mode: 'server' | 'desktop';
  zero_knowledge?: boolean;
  vault_path: string;
  encryption: EncryptionInfo;
  settings?: AppSettings;
  anchor?: VaultAnchor;
  active_sessions?: number;
  active_relays?: number;
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
  monitor_enabled?: boolean;
  custom_interval_sec?: number;
  watched_services?: string[];
  watched_ports?: number[];
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
  monitor_enabled?: boolean;
  custom_interval_sec?: number;
  watched_services?: string[];
  watched_ports?: number[];
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
  zero_knowledge?: boolean;
  encryption: EncryptionInfo;
  settings: AppSettings;
  known_hosts: KnownHost[];
  audit_logs: AuditEntry[];
  active_sessions: number;
  active_relays?: number;
  active_ssh_tabs: number;
  anchor?: VaultAnchor;
}

export interface TerminalReadyInfo {
  session_id: string;
  server_id: string;
  server_name: string;
  fingerprint: string;
  latency_ms: number;
}

export interface OpenTerminalTab {
  tabId: string;
  server: ServerView;
  trustFingerprint?: string;
}

// ============================================================================
// Comprehensive Server Status Monitoring & Time-Series Types
// ============================================================================

export type MonitorHealthLevel = 'healthy' | 'warning' | 'critical' | 'offline' | 'unknown';
export type AlertSeverity = 'info' | 'warning' | 'critical';
export type AlertStatus = 'firing' | 'acknowledged' | 'resolved';

export interface MonitorSettings {
  enabled: boolean;
  interval_sec: number;
  timeout_sec: number;
  concurrency: number;
  retention_points: number;
  max_alert_records: number;
  collect_processes: boolean;
  collect_ports_and_services: boolean;
  collect_security: boolean;
  detect_port_drift: boolean;
  unattended_while_unlocked: boolean;
  webhook_url?: string;
}

export interface MonitorAlertRule {
  kind: string;
  name: string;
  description: string;
  unit?: string;
  enabled: boolean;
  state_based: boolean;
  warning_threshold: number;
  critical_threshold: number;
  consecutive_count: number;
}

export interface MonitorRuntimeStatus {
  running: boolean;
  collecting: boolean;
  vault_unlocked: boolean;
  enabled: boolean;
  interval_sec: number;
  in_flight_count: number;
  last_sweep_at?: string;
  next_sweep_at?: string;
}

export interface DiskPartitionStat {
  mount_point: string;
  device: string;
  fs_type: string;
  total_gb: number;
  used_gb: number;
  avail_gb: number;
  used_percent: number;
  inode_percent: number;
}

export interface NetInterfaceStat {
  name: string;
  ipv4?: string;
  state?: string;
  rx_bytes: number;
  tx_bytes: number;
  rx_bps: number;
  tx_bps: number;
  rx_packets: number;
  tx_packets: number;
  rx_errors: number;
  tx_errors: number;
  rx_drops: number;
  tx_drops: number;
}

export interface ProcessStat {
  pid: number;
  user: string;
  cpu_percent: number;
  mem_percent: number;
  rss_mb: number;
  state: string;
  elapsed?: string;
  command: string;
}

export interface ListeningPortStat {
  proto: string;
  bind_addr: string;
  port: number;
  public_exposed: boolean;
  watched: boolean;
  pid?: number;
  process?: string;
}

export interface ServiceStat {
  name: string;
  state: string;
  sub_state?: string;
  watched: boolean;
}

export interface ContainerStat {
  id?: string;
  name: string;
  image: string;
  state: string;
  status: string;
  health?: string;
}

export interface DockerSummary {
  installed: boolean;
  running: number;
  stopped: number;
  unhealthy: number;
  containers?: ContainerStat[];
}

export interface LoggedInUserStat {
  user: string;
  tty: string;
  from_ip?: string;
  login_time?: string;
}

export interface SecurityPostureStat {
  active_users?: LoggedInUserStat[];
  ssh_failed_recent: number;
  top_failed_ips?: string[];
  firewall_status: string;
  firewall_detail?: string;
  mac_framework?: string;
  uid_zero_users?: string[];
  reboot_required: boolean;
  pending_updates: number;
}

export interface MonitorSamplePoint {
  ts: string;
  ok: boolean;
  score: number;
  lat: number;
  cpu: number;
  cpu_u?: number;
  cpu_s?: number;
  cpu_io?: number;
  cpu_st?: number;
  l1?: number;
  l5?: number;
  l15?: number;
  mem?: number;
  mem_u?: number;
  swap?: number;
  disk?: number;
  inode?: number;
  dr_bps?: number;
  dw_bps?: number;
  d_iops?: number;
  rx_bps?: number;
  tx_bps?: number;
  tcp_est?: number;
  tcp_tw?: number;
  tcp_cw?: number;
  tcp_syn?: number;
  p_tot?: number;
  p_run?: number;
  p_zom?: number;
  p_blk?: number;
  fd_pct?: number;
  temp_c?: number;
  ssh_fail?: number;
}

export interface ServerMonitorSnapshot {
  server_id: string;
  server_name: string;
  group: string;
  host: string;
  port: number;
  collected_at: string;
  duration_ms: number;
  reachable: boolean;
  health_level: MonitorHealthLevel;
  health_score: number;
  error?: string;
  fingerprint?: string;

  hostname?: string;
  os?: string;
  kernel?: string;
  arch?: string;
  cpu_model?: string;
  cpu_cores?: number;
  virtualization?: string;
  uptime?: string;
  uptime_sec?: number;
  boot_time?: string;
  server_time?: string;
  timezone?: string;
  ntp_synced: boolean;

  latency_ms: number;
  cpu_percent: number;
  cpu_user_pct: number;
  cpu_system_pct: number;
  cpu_iowait_pct: number;
  cpu_steal_pct: number;
  load_1: number;
  load_5: number;
  load_15: number;
  load_per_core: number;
  context_sw_sec?: number;
  cpu_temp_c?: number;

  mem_total_mb: number;
  mem_used_mb: number;
  mem_available_mb: number;
  mem_cached_mb: number;
  mem_buffers_mb: number;
  mem_percent: number;
  swap_total_mb: number;
  swap_used_mb: number;
  swap_percent: number;
  fd_used: number;
  fd_max: number;
  fd_percent: number;
  oom_kills: number;

  disk_total_gb: number;
  disk_used_gb: number;
  disk_percent: number;
  max_part_mount?: string;
  max_part_percent: number;
  max_inode_mount?: string;
  max_inode_percent: number;
  disk_read_bps: number;
  disk_write_bps: number;
  disk_iops: number;
  disks?: DiskPartitionStat[];

  net_rx_bps: number;
  net_tx_bps: number;
  net_rx_total_bytes: number;
  net_tx_total_bytes: number;
  net_packet_errors: number;
  tcp_established: number;
  tcp_syn_recv: number;
  tcp_time_wait: number;
  tcp_close_wait: number;
  tcp_listen: number;
  udp_sockets: number;
  interfaces?: NetInterfaceStat[];

  procs_total: number;
  procs_running: number;
  procs_sleeping: number;
  procs_zombie: number;
  procs_blocked: number;
  top_cpu_procs?: ProcessStat[];
  top_mem_procs?: ProcessStat[];
  listening_ports?: ListeningPortStat[];
  services?: ServiceStat[];
  systemd_failed_count: number;
  systemd_failed_units?: string[];
  docker: DockerSummary;
  security: SecurityPostureStat;
}

export interface MonitorAlert {
  id: string;
  dedup_key: string;
  server_id: string;
  server_name: string;
  host: string;
  rule_kind: string;
  rule_name: string;
  severity: AlertSeverity;
  status: AlertStatus;
  title: string;
  detail: string;
  metric_text: string;
  threshold_text?: string;
  occurrences: number;
  triggered_at: string;
  last_seen_at: string;
  acknowledged_at?: string;
  resolved_at?: string;
}

export interface ServerSLASummary {
  total_samples: number;
  online_samples: number;
  availability_pct: number;
  avg_latency_ms: number;
  max_latency_ms: number;
  avg_cpu_percent: number;
  max_cpu_percent: number;
  avg_mem_percent: number;
  max_mem_percent: number;
  max_disk_percent: number;
}

export interface FleetMonitorKPI {
  total_servers: number;
  monitored_servers: number;
  online_servers: number;
  healthy_servers: number;
  warning_servers: number;
  critical_servers: number;
  offline_servers: number;
  unknown_servers: number;
  avg_health_score: number;
  avg_cpu_percent: number;
  avg_mem_percent: number;
  avg_disk_percent: number;
  avg_latency_ms: number;
  total_net_rx_bps: number;
  total_net_tx_bps: number;
  total_disk_read_bps: number;
  total_disk_write_bps: number;
  firing_alerts: number;
  critical_alerts: number;
  warning_alerts: number;
  total_samples: number;
}

export interface ServerMonitorCardItem {
  server: ServerView;
  snapshot?: ServerMonitorSnapshot;
  sparkline: MonitorSamplePoint[];
  sla: ServerSLASummary;
  active_alerts: number;
}

export interface MonitorOverviewResponse {
  settings: MonitorSettings;
  kpi: FleetMonitorKPI;
  nodes: ServerMonitorCardItem[];
  alerts: MonitorAlert[];
  runtime: MonitorRuntimeStatus;
}

export interface ServerMonitorDetail {
  server: ServerView;
  snapshot?: ServerMonitorSnapshot;
  series: MonitorSamplePoint[];
  sla: ServerSLASummary;
  port_baseline: string[];
  alerts: MonitorAlert[];
}

export interface ServerMonitorDetailResponse {
  detail: ServerMonitorDetail;
  runtime: MonitorRuntimeStatus;
}

export interface MonitorPolicyResponse {
  settings: MonitorSettings;
  rules: MonitorAlertRule[];
  runtime: MonitorRuntimeStatus;
}

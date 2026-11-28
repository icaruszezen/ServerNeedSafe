export type VaultStatus = 'uninitialized' | 'locked' | 'unlocked';
export type AuthType = 'password' | 'private_key' | 'credential';
export type HostKeyPolicy = 'tofu' | 'ask_new';

export interface SyncSummary {
  direction: 'push' | 'pull';
  remote_url: string;
  vault_id: string;
  revision: number;
  bytes: number;
  include_runtime?: boolean;
}

export interface StorageFilesInfo {
  data_dir: string;
  secrets_path: string;
  secrets_size_bytes: number;
  master_key_mode: 'file' | 'env' | string;
  master_key_path?: string;
  monitor_size_bytes: number;
  aiops_size_bytes: number;
  audit_size_bytes: number;
  vuln_size_bytes?: number;
  runtime_total_bytes: number;
}

export interface EncryptionInfo {
  format_version: number;
  vault_id?: string;
  revision?: number;
  cipher_algo: string;
  password_hash_algo?: string;
  master_key_mode?: string;
  vault_size_bytes: number;
}

export interface VersionInfo {
  version: string;
  commit?: string;
  build_time?: string;
  go_version?: string;
  goos?: string;
  goarch?: string;
  repo?: string;
  is_dev?: boolean;
}

export type UpdateMirrorMode = 'auto' | 'direct' | 'custom';

export interface UpdateSettings {
  auto_check_enabled?: boolean;
  check_interval_hours?: number;
  mirror_mode?: UpdateMirrorMode;
  custom_mirror_url?: string;
  include_prerelease?: boolean;
  skipped_version?: string;
}

export interface AppSettings {
  auto_lock_minutes: number;
  host_key_policy: HostKeyPolicy;
  terminal_font_size: number;
  terminal_scrollback: number;
  show_hidden_files: boolean;
  remote_sync_url?: string;
  update?: UpdateSettings;
}

export interface AuthStatusResponse {
  initialized?: boolean;
  vault_status: VaultStatus;
  authenticated: boolean;
  deploy_mode: 'server' | 'desktop';
  version?: VersionInfo;
  daemon_running?: boolean;
  legacy_migration_pending?: boolean;
  session_ttl_hours?: number;
  encryption: EncryptionInfo;
  storage?: StorageFilesInfo;
  settings?: AppSettings;
  patrol_enabled?: boolean;
  active_sessions?: number;
  active_ssh_tabs?: number;
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
  jump_server_ids?: string[];
  jump_fallback_direct?: boolean;
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
  ignored_port_drift_processes?: string[];
  ignored_port_drift_ports?: string[];
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
  jump_server_ids: string[];
  jump_fallback_direct: boolean;
  default_path: string;
  notes: string;
  pinned: boolean;
  keep_alive_sec: number;
  monitor_enabled?: boolean;
  custom_interval_sec?: number;
  watched_services?: string[];
  watched_ports?: number[];
  ignored_port_drift_processes?: string[];
  ignored_port_drift_ports?: string[];
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

export interface DialRouteInfo {
  direct: boolean;
  jump_server_ids?: string[];
  jump_server_names?: string[];
  fallback_used: boolean;
  skipped_jumps?: string[];
  label: string;
}

export interface ServerProbeResult {
  server_id: string;
  server_name: string;
  reachable: boolean;
  latency_ms: number;
  fingerprint?: string;
  route_label?: string;
  route_fallback?: boolean;
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
  route_label?: string;
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
  data_dir: string;
  secrets_path: string;
  daemon_running?: boolean;
  session_ttl_hours?: number;
  encryption: EncryptionInfo;
  storage: StorageFilesInfo;
  settings: AppSettings;
  known_hosts: KnownHost[];
  audit_logs: AuditEntry[];
  active_sessions: number;
  active_ssh_tabs: number;
}

export interface WorkspaceBootstrapResponse {
  servers: ServerView[];
  groups: string[];
  credentials: CredentialView[];
  snippets: Snippet[];
  active_sessions: { id: string; server_id: string; server_name: string; started_at: string }[];
  firing_alerts: number;
  active_alerts_by_server?: Record<string, number>;
  patrol_unread: number;
  pending_external_patrols?: number;
  pending_external_approvals?: number;
  running_external_approvals?: number;
  pending_session_approvals?: number;
  pending_approvals_total?: number;
  vuln_unread_high?: number;
}

export interface TerminalReadyInfo {
  session_id: string;
  server_id: string;
  server_name: string;
  fingerprint: string;
  latency_ms: number;
  route?: DialRouteInfo;
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
  slow_interval_sec: number;
  timeout_sec: number;
  concurrency: number;
  retention_points: number;
  max_alert_records: number;
  collect_processes: boolean;
  collect_ports_and_services: boolean;
  collect_security: boolean;
  detect_port_drift: boolean;
  port_drift_ignore_ephemeral_udp: boolean;
  port_drift_ignore_processes?: string[];
  port_drift_ignore_ports?: string[];
  use_ssh_connection_pool: boolean;
  reuse_ai_patrol_webhooks: boolean;
  include_remote_mounts: boolean;
  unattended_while_unlocked: boolean;
  webhook_url?: string;
  policy_version?: number;
}

export interface MonitorAlertRule {
  kind: string;
  category?: string;
  name: string;
  description: string;
  unit?: string;
  enabled: boolean;
  state_based: boolean;
  manual_resolve?: boolean;
  lower_is_worse?: boolean;
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
  slow_interval_sec?: number;
  in_flight_count: number;
  pooled_connections?: number;
  last_sweep_at?: string;
  next_sweep_at?: string;
  last_webhook_at?: string;
  last_webhook_error?: string;
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
  exposure_scope?: string;
  watched: boolean;
  pid?: number;
  process?: string;
  drift_ignored?: boolean;
  ignore_reason?: string;
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
  daemon_down?: boolean;
  running: number;
  stopped: number;
  unhealthy: number;
  exited_abnormal?: number;
  truncated?: boolean;
  containers?: ContainerStat[];
}

export interface LoggedInUserStat {
  user: string;
  tty: string;
  from_ip?: string;
  login_time?: string;
}

export interface SuspiciousProcStat {
  pid: number;
  user: string;
  reason: string;
  severity: string;
  command: string;
  exe_path?: string;
}

export interface OutboundConnStat {
  remote_ip: string;
  remote_port: number;
  pid?: number;
  process?: string;
  reason?: string;
}

export interface SSHLoginEvent {
  user: string;
  from_ip: string;
  method?: string;
  timestamp?: string;
  session_id?: string;
}

export interface ServerSecurityBaseline {
  file_hashes?: Record<string, string>;
  persistence_hash?: string;
  known_ssh_login_ips?: string[];
  updated_at?: string;
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
  file_hashes?: Record<string, string>;
  file_drifts?: string[];
  persistence_hash?: string;
  persistence_drifts?: string[];
  suspicious_procs?: SuspiciousProcStat[];
  suspicious_outbound?: OutboundConnStat[];
  recent_ssh_logins?: SSHLoginEvent[];
  new_ssh_login_ips?: string[];
  ssh_weak_configs?: string[];
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
  last_slow_collected_at?: string;
  collection_tier?: string;
  duration_ms: number;
  reachable: boolean;
  health_level: MonitorHealthLevel;
  health_score: number;
  error?: string;
  partial_error?: string;
  host_key_changed?: boolean;
  host_key_mismatch_detail?: string;
  fingerprint?: string;
  route_label?: string;
  route_fallback?: boolean;
  connection_reused?: boolean;

  hostname?: string;
  os?: string;
  kernel?: string;
  arch?: string;
  cpu_model?: string;
  cpu_cores?: number;
  virtualization?: string;
  uptime?: string;
  uptime_sec?: number;
  unexpected_reboot?: boolean;
  boot_time?: string;
  server_time?: string;
  timezone?: string;
  ntp_synced: boolean;
  clock_offset_sec?: number;

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
  oom_kills_delta?: number;
  kernel_error_count?: number;
  kernel_errors?: string[];

  disk_total_gb: number;
  disk_used_gb: number;
  disk_percent: number;
  max_part_mount?: string;
  max_part_percent: number;
  max_inode_mount?: string;
  max_inode_percent: number;
  disk_full_forecast_hours?: number;
  disk_full_forecast_mount?: string;
  read_only_mounts?: string[];
  remote_mounts?: string[];
  raid_degraded?: string[];
  disk_read_bps: number;
  disk_write_bps: number;
  disk_iops: number;
  disks?: DiskPartitionStat[];

  net_rx_bps: number;
  net_tx_bps: number;
  net_rx_total_bytes: number;
  net_tx_total_bytes: number;
  net_packet_errors: number;
  net_packet_errors_delta?: number;
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
  ports_truncated?: boolean;
  services?: ServiceStat[];
  systemd_failed_count: number;
  systemd_failed_units?: string[];
  docker: DockerSummary;
  security: SecurityPostureStat;
}

export interface AlertCommandSuggestion {
  label: string;
  description?: string;
  command: string;
  risk: 'readonly' | 'mutating';
}

export interface AlertQuickAction {
  kind:
    | 'accept_port_baseline'
    | 'ignore_port_drift_process'
    | 'ignore_port_drift_port'
    | 'accept_security_baseline'
    | 'trust_ssh_login_ip'
    | 'open_vault_known_hosts'
    | string;
  label: string;
  description?: string;
  target?: string;
  scope?: 'server' | 'global' | string;
}

export interface SSHLoginIPBaselineResult {
  server_id: string;
  action: 'add' | 'remove' | string;
  ip: string;
  resolved_alerts: number;
  security_baseline?: ServerSecurityBaseline;
}

export interface PortDriftIgnoreResult {
  scope: 'server' | 'global' | string;
  action: 'add' | 'remove' | string;
  server_id?: string;
  applied_rule: string;
  rule_type: 'process' | 'port' | string;
  resolved_alerts: number;
  global_ignore_processes: string[];
  global_ignore_ports: string[];
  server_ignore_processes?: string[];
  server_ignore_ports?: string[];
}

export interface AlertRunbookRef {
  id: string;
  title: string;
  category?: string;
  symptom?: string;
}

export interface AlertAdvice {
  summary: string;
  root_cause?: string;
  evidence?: string[];
  steps?: string[];
  commands?: AlertCommandSuggestion[];
  quick_actions?: AlertQuickAction[];
  runbooks?: AlertRunbookRef[];
  ai_prompt?: string;
  mcp_prompt?: string;
  context_aware?: boolean;
}

export interface MonitorAlert {
  id: string;
  dedup_key: string;
  server_id: string;
  server_name: string;
  host: string;
  rule_kind: string;
  rule_name: string;
  category?: string;
  severity: AlertSeverity;
  status: AlertStatus;
  manual_resolve?: boolean;
  title: string;
  detail: string;
  metric_text: string;
  threshold_text?: string;
  occurrences: number;
  triggered_at: string;
  last_seen_at: string;
  acknowledged_at?: string;
  resolved_at?: string;
  advice?: AlertAdvice;
}

export interface AlertSummaryStats {
  total_active: number;
  firing: number;
  acknowledged: number;
  resolved: number;
  critical_active: number;
  warning_active: number;
  affected_servers: number;
  active_by_server: Record<string, number>;
  active_by_category: Record<string, number>;
}

export interface MonitorAlertsListResponse {
  alerts: MonitorAlert[];
  summary?: AlertSummaryStats;
  scoped_summary?: AlertSummaryStats;
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
  security_baseline?: ServerSecurityBaseline;
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
  default_port_drift_ignore_processes?: string[];
}

// ============================================================================
// Client-Side Zero-Knowledge AI Ops, Hybrid Memory, Runbooks & Scheduled Patrol
// ============================================================================

export type AIProtocol = 'openai' | 'openai_responses' | 'anthropic' | 'gemini';
export type AIEndpointMode = 'auto' | 'exact';
export type AIAuthMode = 'auto' | 'bearer' | 'x-api-key' | 'x-goog-api-key' | 'query_key' | 'none';
export type AIReasoningEffort = '' | 'off' | 'low' | 'medium' | 'high' | 'max';
export type AIExecutionMode = 'suggest' | 'standard' | 'autonomous';

export interface AICustomHeader {
  key: string;
  value: string;
}

export interface AICustomHeaderView {
  key: string;
  value_preview: string;
  is_sensitive: boolean;
  has_value: boolean;
}

export interface AITokenUsage {
  input_tokens?: number;
  output_tokens?: number;
  reasoning_tokens?: number;
  cached_input_tokens?: number;
  total_tokens?: number;
}

export interface AIModelCatalogEntry {
  id: string;
  name?: string;
  vendor?: string;
  protocol?: AIProtocol;
  context_window?: number;
  max_input_tokens?: number;
  max_output_tokens?: number;
  supports_reasoning?: boolean;
  supports_temperature?: boolean;
  supports_tools?: boolean;
  interleaved_reasoning_key?: string;
  release_date?: string;
  source?: string;
}

export interface AIModelCatalogOverview {
  source: string;
  synced_at?: string;
  builtin_count: number;
  synced_count: number;
  models: AIModelCatalogEntry[];
}

export interface AIProviderView {
  id: string;
  name: string;
  protocol: AIProtocol;
  base_url: string;
  endpoint_mode?: AIEndpointMode;
  auth_mode?: AIAuthMode;
  has_api_key: boolean;
  api_key_preview?: string;
  model: string;
  max_tokens: number;
  max_output_tokens?: number;
  max_input_tokens?: number;
  context_window?: number;
  temperature?: number | null;
  top_p?: number | null;
  reasoning_effort?: AIReasoningEffort;
  custom_headers?: AICustomHeaderView[];
  extra_body_json?: string;
  created_at: string;
  updated_at: string;
}

export interface ProviderPreset {
  id: string;
  name: string;
  protocol: AIProtocol;
  base_url: string;
  endpoint_mode?: AIEndpointMode;
  auth_mode?: AIAuthMode;
  default_model: string;
  context_window?: number;
  max_input_tokens?: number;
  max_output_tokens?: number;
  description: string;
}

export interface WebhookChannelView {
  id: string;
  name: string;
  kind: 'feishu' | 'dingtalk' | 'wecom' | 'custom';
  url_masked: string;
  has_secret: boolean;
  enabled: boolean;
}

export type PatrolAnalysisMode = 'builtin' | 'external' | 'external_with_fallback';
export type MCPTokenScope = 'patrol_readonly' | 'ops_propose';

export interface PatrolConfigView {
  enabled: boolean;
  interval_minutes: number;
  server_ids: string[];
  cpu_warn_percent: number;
  mem_warn_percent: number;
  disk_warn_percent: number;
  ssh_fail_warn_count: number;
  check_listening_ports: boolean;
  check_privileged_users: boolean;
  analysis_mode?: PatrolAnalysisMode;
  external_fallback_minutes?: number;
  notify_pending_approvals?: boolean;
  webhooks: WebhookChannelView[];
}

export interface PatrolStatusView {
  running: boolean;
  vault_ready: boolean;
  analysis_mode?: PatrolAnalysisMode;
  last_run_at?: string;
  next_run_at?: string;
  unread_alerts: number;
  pending_external_count?: number;
  pending_approvals_count?: number;
}

export interface PatrolFinding {
  server_id: string;
  server_name: string;
  host: string;
  reachable: boolean;
  severity?: 'healthy' | 'warning' | 'critical';
  latency_ms?: number;
  cpu_load_percent?: number;
  mem_percent?: number;
  disk_percent?: number;
  ssh_fail_count_1h?: number;
  new_ports?: string[];
  metrics_summary?: string;
  anomalies?: string[];
}

export interface PatrolRecord {
  id: string;
  trigger: 'scheduled' | 'manual' | 'external_mcp';
  started_at: string;
  completed_at: string;
  status: 'healthy' | 'warning' | 'critical';
  total_servers: number;
  healthy_count: number;
  warning_count: number;
  critical_count: number;
  findings: PatrolFinding[];
  analysis_state?: '' | 'none' | 'pending_external' | 'claimed' | 'completed' | 'fallback_completed';
  ai_source?: 'builtin' | 'external_mcp' | string;
  external_client?: string;
  claimed_by?: string;
  claimed_at?: string;
  external_deadline_at?: string;
  ai_analyzed: boolean;
  ai_analyzed_at?: string;
  ai_model?: string;
  ai_summary?: string;
  ai_root_cause?: string;
  ai_recommendations?: string[];
  deep_evidence?: string[];
  webhook_notified: boolean;
  ai_webhook_notified?: boolean;
  unread: boolean;
}

export interface MCPTokenView {
  id: string;
  name: string;
  client_hint?: 'claude_code' | 'codex' | 'antigravity' | 'cursor' | 'custom' | string;
  scope: MCPTokenScope;
  token_prefix: string;
  allowed_servers: string[];
  enabled: boolean;
  created_at: string;
  last_used_at?: string;
  last_client_name?: string;
  last_client_ip?: string;
  call_count: number;
}

export interface MCPConfigView {
  enabled: boolean;
  desktop_loopback_enabled: boolean;
  desktop_loopback_port: number;
  public_endpoint_hint?: string;
  tokens: MCPTokenView[];
}

export interface MCPRuntimeStatus {
  deploy_mode: 'server' | 'desktop' | string;
  server_endpoint_path: string;
  effective_endpoint_url: string;
  desktop_loopback_running: boolean;
  desktop_loopback_addr?: string;
  desktop_loopback_error?: string;
}

export type ExternalApprovalStepStatus =
  | 'pending'
  | 'blocked'
  | 'running'
  | 'succeeded'
  | 'failed'
  | 'skipped'
  | 'cancelled'
  | 'rejected';

export type ExternalApprovalStatus =
  | 'pending'
  | 'running'
  | 'completed'
  | 'partial_failed'
  | 'failed'
  | 'cancelled'
  | 'rejected'
  | 'approved';

export interface ExternalApprovalStep {
  id: string;
  index: number;
  title?: string;
  tool_name: 'exec_ssh_command' | 'sftp_write_file' | string;
  server_ids: string[];
  server_names: string[];
  risk_level: string;
  reason?: string;
  command?: string;
  timeout_sec?: number;
  file_path?: string;
  new_content?: string;
  diff_preview?: string;
  continue_on_error?: boolean;
  blocked?: boolean;
  blocked_reason?: string;
  selected: boolean;
  status: ExternalApprovalStepStatus;
  execution_out?: string;
  execution_error?: string;
  duration_ms?: number;
  started_at?: string;
  completed_at?: string;
}

export interface ExternalApproval {
  id: string;
  title?: string;
  patrol_record_id?: string;
  token_id: string;
  token_name: string;
  client_name: string;
  tool_name?: 'change_plan' | 'exec_ssh_command' | 'sftp_write_file' | string;
  server_ids: string[];
  server_names: string[];
  risk_level: string;
  reason: string;
  command?: string;
  file_path?: string;
  new_content?: string;
  diff_preview?: string;
  steps?: ExternalApprovalStep[];
  total_steps?: number;
  executable_steps?: number;
  blocked_steps?: number;
  completed_steps?: number;
  failed_steps?: number;
  skipped_steps?: number;
  current_step_index?: number;
  status: ExternalApprovalStatus;
  execution_out?: string;
  execution_error?: string;
  duration_ms?: number;
  webhook_notified?: boolean;
  created_at: string;
  started_at?: string;
  resolved_at?: string;
}

export interface MCPOverviewResponse {
  mcp_config: MCPConfigView;
  mcp_runtime: MCPRuntimeStatus;
  external_approvals: ExternalApproval[];
  pending_approvals_count: number;
  running_approvals_count?: number;
  pending_patrols_count: number;
  skill_markdown: string;
}

export interface SessionApprovalItem extends AIPendingApproval {
  session_title: string;
  session_scope: 'center' | 'terminal' | string;
  session_server_ids?: string[];
}

export interface UnifiedApprovalsResponse {
  external_approvals: ExternalApproval[];
  session_approvals: SessionApprovalItem[];
  pending_external_count: number;
  running_external_count: number;
  pending_session_count: number;
  pending_total: number;
}

export interface ApprovalSummaryResponse {
  pending_external_count: number;
  running_external_count: number;
  pending_session_count: number;
  pending_total: number;
  patrol_unread: number;
}

export interface AgentsMDConfig {
  enabled: boolean;
  content: string;
  revision: number;
  updated_at: string;
}

export interface AIMemoryConfig {
  agents_md_max_chars: number;
  memory_prompt_budget_chars: number;
  compaction_trigger_ratio: number;
  compaction_keep_recent: number;
  auto_sync_monitor_to_memory: boolean;
  auto_record_approved_changes: boolean;
}

export interface HostMemory {
  server_id: string;
  server_name: string;
  summary: string;
  os_arch?: string;
  key_services: string[];
  deploy_paths: string[];
  ports_note?: string;
  constraints?: string;
  notes?: string;
  auto_updated_count: number;
  monitor_synced_at?: string;
  updated_at: string;
}

export type AIMemoryCategory = 'preference' | 'topology' | 'incident' | 'change' | 'lesson';

export interface AIMemoryEntry {
  id: string;
  scope: 'global' | 'server';
  server_ids: string[];
  category: AIMemoryCategory;
  title: string;
  content: string;
  tags: string[];
  pinned: boolean;
  importance: number;
  source: 'manual' | 'ai' | 'approval' | string;
  source_session_id?: string;
  use_count: number;
  last_used_at?: string;
  created_at: string;
  updated_at: string;
}

export interface AIAgentsMDProposal {
  id: string;
  session_id: string;
  reason: string;
  summary: string;
  proposed_content: string;
  diff_preview: string;
  status: 'pending' | 'accepted' | 'dismissed';
  created_at: string;
  resolved_at?: string;
}

export interface AIRunbook {
  id: string;
  title: string;
  category: string;
  tags: string[];
  symptom: string;
  root_cause: string;
  diagnostic_steps: string[];
  fix_commands: string[];
  verification?: string;
  linked_snippet_id?: string;
  source_session_id?: string;
  created_at: string;
  updated_at: string;
}

export interface AIToolCallRecord {
  id: string;
  name: string;
  arguments: string;
  summary?: string;
  risk_level: 'readonly' | 'mutating' | 'blocked';
  status: 'running' | 'completed' | 'pending_approval' | 'approved' | 'rejected' | 'blocked' | 'error';
  output?: string;
  duration_ms?: number;
}

export interface AIPendingApproval {
  id: string;
  session_id: string;
  tool_call_id: string;
  tool_name: string;
  risk_level: string;
  reason: string;
  server_ids: string[];
  server_names: string[];
  command?: string;
  file_path?: string;
  new_content?: string;
  diff_preview?: string;
  status: 'pending' | 'approved' | 'rejected';
  execution_out?: string;
  created_at: string;
  resolved_at?: string;
}

export interface AIRunbookProposal {
  id: string;
  session_id: string;
  title: string;
  category: string;
  symptom: string;
  root_cause: string;
  diagnostic_steps: string[];
  fix_commands: string[];
  verification?: string;
  status: 'pending' | 'accepted' | 'dismissed';
  saved_runbook_id?: string;
  created_at: string;
}

export interface AIChatMessage {
  id: string;
  role: 'user' | 'assistant' | 'tool';
  content: string;
  reasoning_content?: string;
  usage?: AITokenUsage;
  tool_calls?: AIToolCallRecord[];
  tool_call_id?: string;
  tool_name?: string;
  is_error?: boolean;
  timestamp: string;
}

export interface AIChatSessionSummary {
  id: string;
  title: string;
  scope: 'center' | 'terminal';
  server_ids: string[];
  mode: AIExecutionMode;
  message_count: number;
  pending_approval_count: number;
  pending_agents_md_proposal_count?: number;
  compaction_count?: number;
  updated_at: string;
}

export interface AIChatSession {
  id: string;
  title: string;
  scope: 'center' | 'terminal';
  server_ids: string[];
  mode: AIExecutionMode;
  messages: AIChatMessage[];
  pending_approvals: AIPendingApproval[];
  runbook_proposals: AIRunbookProposal[];
  agents_md_proposals?: AIAgentsMDProposal[];
  compacted_summary?: string;
  compacted_until_count?: number;
  compacted_at?: string;
  compaction_count?: number;
  created_at: string;
  updated_at: string;
}

export interface ContextHostItem {
  server_id: string;
  server_name: string;
  has_memory: boolean;
  summary?: string;
  os_arch?: string;
  key_services?: string[];
  has_constraints: boolean;
  constraints?: string;
  ports_note?: string;
  monitor_synced_at?: string;
}

export interface ContextMemoryItem {
  id: string;
  scope: 'global' | 'server' | string;
  category: AIMemoryCategory | string;
  title: string;
  preview: string;
  pinned: boolean;
  importance: number;
  source: string;
  server_ids?: string[];
}

export interface ContextMonitorItem {
  server_id: string;
  server_name: string;
  reachable: boolean;
  health_level: string;
  cpu_percent: number;
  mem_percent: number;
  disk_percent: number;
  latency_ms: number;
  alert_count: number;
  collected_at: string;
}

export interface CompactionInfo {
  triggered: boolean;
  mode: 'llm' | 'fallback' | 'noop' | 'reset';
  compacted_until_count: number;
  total_messages: number;
  compaction_count: number;
  summary_chars: number;
  estimated_tokens_before: number;
  estimated_tokens_after: number;
  compacted_at?: string;
}

export interface SessionContextInspection {
  session_id: string;
  provider_name?: string;
  model?: string;
  agents_md_enabled: boolean;
  agents_md_revision: number;
  agents_md_chars: number;
  agents_md_max_chars: number;
  agents_md_truncated: boolean;
  host_memories: ContextHostItem[];
  injected_memories: ContextMemoryItem[];
  total_memories_count: number;
  memory_budget_chars: number;
  memory_used_chars: number;
  live_monitors: ContextMonitorItem[];
  firing_alerts_count: number;
  runbook_count: number;
  total_messages: number;
  uncompacted_messages: number;
  compacted_until_count: number;
  compaction_count: number;
  compacted_at?: string;
  compacted_summary?: string;
  estimated_system_tokens: number;
  estimated_summary_tokens: number;
  estimated_history_tokens: number;
  estimated_total_tokens: number;
  context_window_tokens: number;
  max_input_tokens?: number;
  max_output_tokens?: number;
  compaction_threshold_tokens: number;
  usage_percent: number;
  needs_compaction: boolean;
  last_usage?: AITokenUsage;
  session_total_usage?: AITokenUsage;
}

export interface AIOverviewResponse {
  active_provider_id: string;
  default_mode: AIExecutionMode;
  providers: AIProviderView[];
  presets: ProviderPreset[];
  model_catalog?: AIModelCatalogOverview;
  agents_md: AgentsMDConfig;
  agents_md_template: string;
  memory_config: AIMemoryConfig;
  patrol_config: PatrolConfigView;
  patrol_status: PatrolStatusView;
  patrol_records: PatrolRecord[];
  mcp_config?: MCPConfigView;
  mcp_runtime?: MCPRuntimeStatus;
  external_approvals?: ExternalApproval[];
  pending_external_approvals?: number;
  skill_markdown?: string;
  host_memories: HostMemory[];
  memories: AIMemoryEntry[];
  runbooks: AIRunbook[];
  sessions: AIChatSessionSummary[];
}

export interface AIStreamEvent {
  type:
    | 'delta'
    | 'reasoning_delta'
    | 'tool_start'
    | 'tool_result'
    | 'approval_required'
    | 'memory_updated'
    | 'memory_saved'
    | 'runbook_proposed'
    | 'agents_md_proposed'
    | 'context_compacted'
    | 'session_sync'
    | 'done'
    | 'error';
  delta?: string;
  reasoning_delta?: string;
  usage?: AITokenUsage;
  tool?: AIToolCallRecord;
  approval?: AIPendingApproval;
  memory?: HostMemory;
  memory_entry?: AIMemoryEntry;
  proposal?: AIRunbookProposal;
  agents_md_proposal?: AIAgentsMDProposal;
  compaction?: CompactionInfo;
  session?: AIChatSession;
  error?: string;
}

// ============================================================================
// GitHub Release Auto-Detection, China Acceleration Mirrors & Self-Update Types
// ============================================================================

export interface MirrorNode {
  id: string;
  name: string;
  prefix: string;
  region: 'global' | 'cn' | string;
  supports_api?: boolean;
  is_custom?: boolean;
}

export interface MirrorProbeResult {
  id: string;
  name: string;
  prefix: string;
  region: 'global' | 'cn' | string;
  is_custom?: boolean;
  reachable: boolean;
  latency_ms: number;
  error?: string;
  checked_at?: string;
}

export interface ReleaseAsset {
  name: string;
  size: number;
  download_url: string;
}

export interface ReleaseInfo {
  tag_name: string;
  name: string;
  body: string;
  html_url: string;
  published_at?: string;
  prerelease: boolean;
  assets: ReleaseAsset[];
  source: string;
}

export interface UpdateCapabilities {
  deploy_mode: 'server' | 'desktop' | string;
  in_docker: boolean;
  can_self_update: boolean;
  cannot_update_reason?: string;
  executable_path?: string;
  asset_name?: string;
  goos: string;
  goarch: string;
}

export type UpdateJobStage =
  | 'idle'
  | 'probing'
  | 'downloading'
  | 'verifying'
  | 'self_checking'
  | 'replacing'
  | 'restarting'
  | 'completed'
  | 'failed';

export interface UpdateJobState {
  stage: UpdateJobStage;
  target_version?: string;
  asset_name?: string;
  mirror_id?: string;
  mirror_name?: string;
  downloaded_bytes: number;
  total_bytes: number;
  speed_bps: number;
  progress_percent: number;
  expected_sha256?: string;
  checksum_source?: string;
  message?: string;
  error?: string;
  started_at?: string;
  updated_at?: string;
}

export interface DockerMirrorCommand {
  name: string;
  image: string;
  command: string;
}

export interface DockerUpgradeCommands {
  tag: string;
  official_image: string;
  official_pull: string;
  compose_upgrade: string;
  china_mirrors: DockerMirrorCommand[];
}

export interface UpdateOverviewResponse {
  ok?: boolean;
  error?: string;
  current: VersionInfo;
  capabilities: UpdateCapabilities;
  settings: UpdateSettings;
  latest_release?: ReleaseInfo;
  update_available: boolean;
  skipped: boolean;
  checking: boolean;
  last_checked_at?: string;
  next_check_at?: string;
  last_error?: string;
  active_mirror?: MirrorProbeResult;
  mirrors: MirrorProbeResult[];
  builtin_mirrors: MirrorNode[];
  job: UpdateJobState;
  docker_commands?: DockerUpgradeCommands;
  active_ssh_tabs?: number;
}

// ============================================================================
// 7x24 Vulnerability Monitor (Official Security Advisory Rolling Feed)
// ============================================================================

export type VulnSeverity = 'critical' | 'high' | 'medium' | 'low' | 'unknown';

export interface VulnCustomApp {
  id: string;
  name: string;
  category: string;
  kind: 'github_repo' | 'osv_package';
  repo?: string;
  ecosystem?: string;
  package_name?: string;
  enabled: boolean;
  created_at?: string;
}

export interface VulnSettingsView {
  enabled: boolean;
  sync_interval_minutes: number;
  retention_days: number;
  max_records: number;
  watched_app_ids: string[];
  custom_apps: VulnCustomApp[];
  has_http_proxy: boolean;
  http_proxy_display?: string;
  has_github_token: boolean;
  notify_webhook: boolean;
  notify_min_severity: VulnSeverity;
  notify_kev_only: boolean;
  reuse_ai_patrol_webhook: boolean;
  has_custom_webhook: boolean;
  custom_webhook_display?: string;
}

export interface VulnSettingsUpdatePayload {
  enabled?: boolean;
  sync_interval_minutes?: number;
  retention_days?: number;
  max_records?: number;
  watched_app_ids?: string[];
  custom_apps?: VulnCustomApp[];
  http_proxy_url?: string;
  clear_http_proxy?: boolean;
  github_token?: string;
  clear_github_token?: boolean;
  notify_webhook?: boolean;
  notify_min_severity?: VulnSeverity;
  notify_kev_only?: boolean;
  reuse_ai_patrol_webhook?: boolean;
  custom_webhook_url?: string;
  clear_custom_webhook?: boolean;
}

export interface VulnAffectedRange {
  ecosystem?: string;
  package_name?: string;
  introduced?: string;
  fixed?: string;
  last_affected?: string;
  range_text?: string;
  fixed_versions?: string[];
}

export interface VulnReference {
  type?: string;
  url: string;
  label?: string;
}

export interface VulnAIAnalysis {
  summary_zh: string;
  impact_zh?: string;
  fix_steps_zh?: string[];
  verification_cmd?: string;
  raw_markdown?: string;
  model?: string;
  generated_at: string;
}

export interface VulnAdvisory {
  id: string;
  cve_id?: string;
  ghsa_id?: string;
  aliases?: string[];
  app_ids: string[];
  app_names: string[];
  categories: string[];
  title: string;
  summary: string;
  details?: string;
  severity: VulnSeverity;
  cvss_score?: number;
  cvss_vector?: string;
  cwe_ids?: string[];
  ecosystem?: string;
  package_name?: string;
  cpe_hints?: string[];
  affected_text?: string;
  fixed_version?: string;
  fixed_versions?: string[];
  has_fix: boolean;
  affected_ranges?: VulnAffectedRange[];
  is_kev: boolean;
  kev_date_added?: string;
  kev_due_date?: string;
  kev_action?: string;
  sources: string[];
  primary_source: string;
  official_url?: string;
  references?: VulnReference[];
  published_at: string;
  modified_at: string;
  first_seen_at: string;
  last_synced_at: string;
  is_read: boolean;
  is_starred: boolean;
  is_ignored: boolean;
  is_new: boolean;
  ai_analysis?: VulnAIAnalysis;
}

export interface VulnSourceStatus {
  id: string;
  name: string;
  kind: string;
  url?: string;
  ok: boolean;
  item_count: number;
  duration_ms: number;
  last_sync_at?: string;
  last_error?: string;
}

export interface VulnAppCategoryInfo {
  id: string;
  label: string;
  order: number;
}

export interface VulnAppPreset {
  id: string;
  name: string;
  description: string;
  app_ids: string[];
}

export interface VulnAppDefinition {
  id: string;
  name: string;
  category: string;
  category_label: string;
  vendor: string;
  description: string;
  homepage?: string;
  default_watched: boolean;
  is_custom?: boolean;
  watched: boolean;
  osv_packages?: { ecosystem: string; name: string }[];
  github_repos?: string[];
  vendor_feed_id?: string;
}

export interface VulnKPIStats {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
  kev: number;
  has_fix: number;
  recent_7d: number;
  unread_total: number;
  unread_critical_high: number;
  starred_total: number;
  sources_ok: number;
  sources_total: number;
}

export interface VulnRuntimeStatus {
  syncing: boolean;
  last_sync_at?: string;
  next_sync_at?: string;
  last_error?: string;
  last_new_count: number;
  source_status: VulnSourceStatus[];
  watched_count: number;
  catalog_total: number;
}

export interface VulnOverviewResponse {
  advisories: VulnAdvisory[];
  total_matched: number;
  has_more: boolean;
  new_since_count: number;
  ticker: VulnAdvisory[];
  kpi: VulnKPIStats;
  settings: VulnSettingsView;
  catalog: VulnAppDefinition[];
  categories: VulnAppCategoryInfo[];
  presets: VulnAppPreset[];
  runtime: VulnRuntimeStatus;
}

export interface VulnSyncResult {
  ok: boolean;
  fetched_count: number;
  new_count: number;
  error?: string;
  runtime: VulnRuntimeStatus;
}

// ============================================================================
// QQ Open Platform API v2 WebSocket Event Notification Types
// ============================================================================

export type QQBotTargetType = 'c2c' | 'group' | 'channel';

export type QQBotGatewayState =
  | 'disabled'
  | 'connecting'
  | 'identifying'
  | 'resuming'
  | 'connected'
  | 'reconnecting'
  | 'error'
  | 'stopped_error';

export interface QQBotTarget {
  id: string;
  name: string;
  target_type: QQBotTargetType;
  target_id: string;
  guild_id?: string;
  enabled: boolean;
  created_at: string;
}

export interface QQBotSettingsView {
  enabled: boolean;
  app_id: string;
  has_app_secret: boolean;
  app_secret_preview?: string;
  sandbox: boolean;
  api_base_url?: string;
  token_base_url?: string;
  effective_api_base_url: string;
  effective_token_base_url: string;
  intents: number;
  shard_id: number;
  shard_count: number;
  message_format: 'text' | 'markdown';
  push_mode: 'proactive' | 'passive_prefer';
  allow_bot_commands: boolean;
  notify_monitor_alerts: boolean;
  notify_ai_patrol: boolean;
  notify_external_approvals: boolean;
  notify_vuln_advisories: boolean;
  targets: QQBotTarget[];
}

export interface QQBotSettingsUpdatePayload {
  enabled?: boolean;
  app_id?: string;
  app_secret?: string;
  clear_app_secret?: boolean;
  sandbox?: boolean;
  api_base_url?: string;
  token_base_url?: string;
  intents?: number;
  shard_id?: number;
  shard_count?: number;
  message_format?: 'text' | 'markdown';
  push_mode?: 'proactive' | 'passive_prefer';
  allow_bot_commands?: boolean;
  notify_monitor_alerts?: boolean;
  notify_ai_patrol?: boolean;
  notify_external_approvals?: boolean;
  notify_vuln_advisories?: boolean;
}

export interface QQBotBindCodeInfo {
  code: string;
  expires_at: string;
}

export interface QQBotRuntimeStatus {
  state: QQBotGatewayState;
  connected: boolean;
  gateway_url?: string;
  bot_user_id?: string;
  bot_username?: string;
  session_id_masked?: string;
  last_seq: number;
  shard: [number, number];
  recommended_shards?: number;
  session_total?: number;
  session_remaining?: number;
  heartbeat_interval_ms?: number;
  heartbeat_latency_ms?: number;
  last_heartbeat_ack_at?: string;
  connected_since?: string;
  reconnect_count: number;
  resume_count: number;
  events_received: number;
  push_success_count: number;
  push_failure_count: number;
  last_push_at?: string;
  last_push_error?: string;
  last_error?: string;
  active_bind_code?: QQBotBindCodeInfo;
}

export interface QQBotDiscoveredTarget {
  target_type: QQBotTargetType;
  target_id: string;
  guild_id?: string;
  label?: string;
  last_event_type?: string;
  last_message_preview?: string;
  proactive_rejected?: boolean;
  last_seen_at: string;
  hit_count: number;
}

export interface QQBotEventRecord {
  id: string;
  seq?: number;
  op: number;
  event_type: string;
  target_type?: QQBotTargetType;
  target_id?: string;
  sender?: string;
  summary?: string;
  received_at: string;
}

export interface QQBotPushRecord {
  id: string;
  category: string;
  title: string;
  target_type: QQBotTargetType;
  target_id: string;
  target_name?: string;
  mode: string;
  success: boolean;
  error?: string;
  sent_at: string;
}

export interface QQBotIntentOption {
  key: string;
  name: string;
  bit: number;
  value: number;
  description: string;
  recommended?: boolean;
  private_only?: boolean;
}

export interface QQBotProbeResult {
  ok: boolean;
  latency_ms: number;
  gateway_url: string;
  recommended_shards?: number;
  session_total?: number;
  session_remaining?: number;
  heartbeat_interval_ms?: number;
}

export interface QQBotTargetDeliveryResult {
  target_id: string;
  target_type: QQBotTargetType;
  target_name: string;
  mode: string;
  success: boolean;
  audit_pending?: boolean;
  fallback_plain?: boolean;
  error?: string;
}

export interface QQBotDispatchSummary {
  total: number;
  sent: number;
  failed: number;
  results: QQBotTargetDeliveryResult[];
}

export interface QQBotOverviewResponse {
  settings: QQBotSettingsView;
  runtime: QQBotRuntimeStatus;
  discovered_targets: QQBotDiscoveredTarget[];
  recent_events: QQBotEventRecord[];
  push_history: QQBotPushRecord[];
  intent_catalog: QQBotIntentOption[];
}





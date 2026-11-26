package vault

import "time"

// MonitorHealthLevel classifies the overall health state of a monitored server.
type MonitorHealthLevel string

const (
	HealthHealthy  MonitorHealthLevel = "healthy"
	HealthWarning  MonitorHealthLevel = "warning"
	HealthCritical MonitorHealthLevel = "critical"
	HealthOffline  MonitorHealthLevel = "offline"
	HealthUnknown  MonitorHealthLevel = "unknown"
)

// AlertSeverity defines the urgency of a monitoring alert.
type AlertSeverity string

const (
	SeverityInfo     AlertSeverity = "info"
	SeverityWarning  AlertSeverity = "warning"
	SeverityCritical AlertSeverity = "critical"
)

// AlertStatus tracks the lifecycle of an alert incident.
type AlertStatus string

const (
	AlertStatusFiring       AlertStatus = "firing"
	AlertStatusAcknowledged AlertStatus = "acknowledged"
	AlertStatusResolved     AlertStatus = "resolved"
)

// CurrentMonitorPolicyVersion tracks schema migrations for MonitorSettings defaults.
const CurrentMonitorPolicyVersion = 2

// MonitorSettings controls periodic background telemetry collection and retention.
// Stored 100% encrypted inside SecretsState.
type MonitorSettings struct {
	Enabled                 bool   `json:"enabled"`                    // Enable scheduled background polling
	IntervalSec             int    `json:"interval_sec"`               // Default fast-tier polling interval in seconds (10..86400)
	SlowIntervalSec         int    `json:"slow_interval_sec"`          // Slow-tier static/security/audit interval in seconds (60..3600)
	TimeoutSec              int    `json:"timeout_sec"`                // Per-server SSH probe timeout in seconds (5..120)
	Concurrency             int    `json:"concurrency"`                // Max concurrent SSH collectors (1..20)
	RetentionPoints         int    `json:"retention_points"`           // Max time-series samples kept per server (30..5000)
	MaxAlertRecords         int    `json:"max_alert_records"`          // Max alert incidents retained (50..2000)
	CollectProcesses        bool   `json:"collect_processes"`          // Collect top CPU/Mem processes & zombie/blocked stats
	CollectPortsAndServices bool   `json:"collect_ports_and_services"` // Collect listening ports, systemd & Docker
	CollectSecurity         bool   `json:"collect_security"`           // Collect SSH brute-force, logged-in users, firewall, FIM & intrusion cues
	DetectPortDrift         bool   `json:"detect_port_drift"`          // Alert on newly exposed listening ports outside baseline
	UseSSHConnectionPool    bool   `json:"use_ssh_connection_pool"`    // Reuse pooled SSH & jump-host connections across sweeps
	ReuseAIPatrolWebhooks   bool   `json:"reuse_ai_patrol_webhooks"`   // Also forward monitor alerts to enabled AI patrol webhook channels
	IncludeRemoteMounts     bool   `json:"include_remote_mounts"`      // Advanced: include NFS/CIFS mounts in df (disabled by default to avoid D-state hangs)
	UnattendedWhileUnlocked bool   `json:"unattended_while_unlocked"`  // Keep daemon polling when web sessions idle-expire
	WebhookURL              string `json:"webhook_url,omitempty"`      // Optional encrypted webhook URL for alert notifications
	PolicyVersion           int    `json:"policy_version,omitempty"`   // Internal schema version for one-time default upgrades
}

// MonitorAlertRule configures warning/critical thresholds and anti-flap consecutive breach counts.
type MonitorAlertRule struct {
	Kind              string  `json:"kind"`
	Category          string  `json:"category,omitempty"` // availability, compute, storage, services, network, security
	Name              string  `json:"name"`
	Description       string  `json:"description"`
	Unit              string  `json:"unit,omitempty"`
	Enabled           bool    `json:"enabled"`
	StateBased        bool    `json:"state_based"`
	LowerIsWorse      bool    `json:"lower_is_worse,omitempty"` // True when smaller positive value is worse (e.g. disk_will_fill hours)
	WarningThreshold  float64 `json:"warning_threshold"`
	CriticalThreshold float64 `json:"critical_threshold"`
	ConsecutiveCount  int     `json:"consecutive_count"`
}

// DiskPartitionStat records capacity and inode usage for a mounted filesystem.
type DiskPartitionStat struct {
	MountPoint   string  `json:"mount_point"`
	Device       string  `json:"device"`
	FSType       string  `json:"fs_type"`
	TotalGB      float64 `json:"total_gb"`
	UsedGB       float64 `json:"used_gb"`
	AvailGB      float64 `json:"avail_gb"`
	UsedPercent  float64 `json:"used_percent"`
	InodePercent float64 `json:"inode_percent"`
}

// NetInterfaceStat records traffic counters, live throughput, and error/drop counters per NIC.
type NetInterfaceStat struct {
	Name      string `json:"name"`
	IPv4      string `json:"ipv4,omitempty"`
	State     string `json:"state,omitempty"`
	RxBytes   int64  `json:"rx_bytes"`
	TxBytes   int64  `json:"tx_bytes"`
	RxBps     int64  `json:"rx_bps"`
	TxBps     int64  `json:"tx_bps"`
	RxPackets int64  `json:"rx_packets"`
	TxPackets int64  `json:"tx_packets"`
	RxErrors  int64  `json:"rx_errors"`
	TxErrors  int64  `json:"tx_errors"`
	RxDrops   int64  `json:"rx_drops"`
	TxDrops   int64  `json:"tx_drops"`
}

// ProcessStat captures resource consumption of an active remote process.
type ProcessStat struct {
	PID        int     `json:"pid"`
	User       string  `json:"user"`
	CPUPercent float64 `json:"cpu_percent"`
	MemPercent float64 `json:"mem_percent"`
	RSSMB      float64 `json:"rss_mb"`
	State      string  `json:"state"`
	Elapsed    string  `json:"elapsed,omitempty"`
	Command    string  `json:"command"`
}

// ListeningPortStat describes an active TCP/UDP listening socket on the remote server.
type ListeningPortStat struct {
	Proto         string `json:"proto"`                    // tcp, tcp6, udp, udp6
	BindAddr      string `json:"bind_addr"`                // e.g. 0.0.0.0, 127.0.0.1, [::], 10.0.0.5
	Port          int    `json:"port"`                     // e.g. 22, 80, 443
	PublicExposed bool   `json:"public_exposed"`           // Non-loopback/non-link-local exposed listener
	ExposureScope string `json:"exposure_scope,omitempty"` // wildcard, public_ip, private_ip, loopback, link_local
	Watched       bool   `json:"watched"`                  // Explicitly watched by server config
	PID           int    `json:"pid,omitempty"`
	Process       string `json:"process,omitempty"`
}

// ServiceStat captures the runtime state of a systemd unit or daemon service.
type ServiceStat struct {
	Name     string `json:"name"`
	State    string `json:"state"`               // active, inactive, failed, not-found
	SubState string `json:"sub_state,omitempty"` // running, exited, dead
	Watched  bool   `json:"watched"`
}

// ContainerStat captures a Docker/OCI container status on the monitored host.
type ContainerStat struct {
	ID     string `json:"id,omitempty"`
	Name   string `json:"name"`
	Image  string `json:"image"`
	State  string `json:"state"`  // running, exited, restarting, paused, dead
	Status string `json:"status"` // e.g. Up 3 days (healthy) / Exited (137) 5 minutes ago
	Health string `json:"health,omitempty"`
}

// DockerSummary summarizes container engine health on the remote host.
type DockerSummary struct {
	Installed      bool            `json:"installed"`
	DaemonDown     bool            `json:"daemon_down,omitempty"`
	Running        int             `json:"running"`
	Stopped        int             `json:"stopped"`
	Unhealthy      int             `json:"unhealthy"`
	ExitedAbnormal int             `json:"exited_abnormal,omitempty"`
	Truncated      bool            `json:"truncated,omitempty"`
	Containers     []ContainerStat `json:"containers,omitempty"`
}

// LoggedInUserStat represents an active interactive user session (TTY/PTS) on the host.
type LoggedInUserStat struct {
	User      string `json:"user"`
	TTY       string `json:"tty"`
	FromIP    string `json:"from_ip,omitempty"`
	LoginTime string `json:"login_time,omitempty"`
}

// SuspiciousProcStat records a deterministic high-risk process finding (without AI).
type SuspiciousProcStat struct {
	PID      int    `json:"pid"`
	User     string `json:"user"`
	Reason   string `json:"reason"`   // miner_signature, reverse_shell, tmp_exec, deleted_exec
	Severity string `json:"severity"` // warning, critical
	Command  string `json:"command"`
	ExePath  string `json:"exe_path,omitempty"`
}

// OutboundConnStat records an established outbound connection to a high-risk/suspicious port.
type OutboundConnStat struct {
	RemoteIP   string `json:"remote_ip"`
	RemotePort int    `json:"remote_port"`
	PID        int    `json:"pid,omitempty"`
	Process    string `json:"process,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

// SSHLoginEvent records a recent successful SSH login parsed from auth logs.
type SSHLoginEvent struct {
	User      string `json:"user"`
	FromIP    string `json:"from_ip"`
	Method    string `json:"method,omitempty"`
	Timestamp string `json:"timestamp,omitempty"`
}

// ServerSecurityBaseline stores operator-trusted deterministic security fingerprints for drift alerts.
type ServerSecurityBaseline struct {
	FileHashes       map[string]string `json:"file_hashes,omitempty"`
	PersistenceHash  string            `json:"persistence_hash,omitempty"`
	KnownSSHLoginIPs []string          `json:"known_ssh_login_ips,omitempty"`
	UpdatedAt        time.Time         `json:"updated_at,omitempty"`
}

// SecurityPostureStat captures security-relevant host telemetry.
type SecurityPostureStat struct {
	ActiveUsers        []LoggedInUserStat   `json:"active_users,omitempty"`
	SSHFailedRecent    int                  `json:"ssh_failed_recent"`
	TopFailedIPs       []string             `json:"top_failed_ips,omitempty"`
	FirewallStatus     string               `json:"firewall_status"`           // active, inactive, unknown
	FirewallDetail     string               `json:"firewall_detail,omitempty"` // ufw / firewalld / nftables / iptables / macos-alf
	MACFramework       string               `json:"mac_framework,omitempty"`   // selinux / apparmor / sip
	UIDZeroUsers       []string             `json:"uid_zero_users,omitempty"`
	RebootRequired     bool                 `json:"reboot_required"`
	PendingUpdates     int                  `json:"pending_updates"`
	FileHashes         map[string]string    `json:"file_hashes,omitempty"`
	FileDrifts         []string             `json:"file_drifts,omitempty"`
	PersistenceHash    string               `json:"persistence_hash,omitempty"`
	PersistenceDrifts  []string             `json:"persistence_drifts,omitempty"`
	SuspiciousProcs    []SuspiciousProcStat `json:"suspicious_procs,omitempty"`
	SuspiciousOutbound []OutboundConnStat   `json:"suspicious_outbound,omitempty"`
	RecentSSHLogins    []SSHLoginEvent      `json:"recent_ssh_logins,omitempty"`
	NewSSHLoginIPs     []string             `json:"new_ssh_login_ips,omitempty"`
	SSHWeakConfigs     []string             `json:"ssh_weak_configs,omitempty"`
}

// MonitorSamplePoint is a compact time-series record persisted in the ring buffer per server.
type MonitorSamplePoint struct {
	Timestamp       time.Time `json:"ts"`
	Reachable       bool      `json:"ok"`
	HealthScore     int       `json:"score"`
	LatencyMs       int64     `json:"lat"`
	CPUPercent      float64   `json:"cpu"`
	CPUUserPct      float64   `json:"cpu_u,omitempty"`
	CPUSystemPct    float64   `json:"cpu_s,omitempty"`
	CPUIowaitPct    float64   `json:"cpu_io,omitempty"`
	CPUStealPct     float64   `json:"cpu_st,omitempty"`
	Load1           float64   `json:"l1,omitempty"`
	Load5           float64   `json:"l5,omitempty"`
	Load15          float64   `json:"l15,omitempty"`
	MemPercent      float64   `json:"mem,omitempty"`
	MemUsedMB       int64     `json:"mem_u,omitempty"`
	SwapPercent     float64   `json:"swap,omitempty"`
	DiskPercent     float64   `json:"disk,omitempty"`
	InodePercent    float64   `json:"inode,omitempty"`
	DiskReadBps     int64     `json:"dr_bps,omitempty"`
	DiskWriteBps    int64     `json:"dw_bps,omitempty"`
	DiskIOPS        int64     `json:"d_iops,omitempty"`
	NetRxBps        int64     `json:"rx_bps,omitempty"`
	NetTxBps        int64     `json:"tx_bps,omitempty"`
	TCPEstablished  int       `json:"tcp_est,omitempty"`
	TCPTimeWait     int       `json:"tcp_tw,omitempty"`
	TCPCloseWait    int       `json:"tcp_cw,omitempty"`
	TCPSynRecv      int       `json:"tcp_syn,omitempty"`
	ProcsTotal      int       `json:"p_tot,omitempty"`
	ProcsRunning    int       `json:"p_run,omitempty"`
	ProcsZombie     int       `json:"p_zom,omitempty"`
	ProcsBlocked    int       `json:"p_blk,omitempty"`
	FDPercent       float64   `json:"fd_pct,omitempty"`
	CPUTempC        float64   `json:"temp_c,omitempty"`
	SSHFailedRecent int       `json:"ssh_fail,omitempty"`
}

// ServerMonitorSnapshot stores the latest comprehensive all-around state of a server.
type ServerMonitorSnapshot struct {
	ServerID              string             `json:"server_id"`
	ServerName            string             `json:"server_name"`
	Group                 string             `json:"group"`
	Host                  string             `json:"host"`
	Port                  int                `json:"port"`
	CollectedAt           time.Time          `json:"collected_at"`
	LastSlowCollectedAt   *time.Time         `json:"last_slow_collected_at,omitempty"`
	CollectionTier        string             `json:"collection_tier,omitempty"` // "full" or "fast"
	DurationMs            int64              `json:"duration_ms"`
	Reachable             bool               `json:"reachable"`
	HealthLevel           MonitorHealthLevel `json:"health_level"`
	HealthScore           int                `json:"health_score"`
	Error                 string             `json:"error,omitempty"`
	PartialError          string             `json:"partial_error,omitempty"`
	HostKeyChanged        bool               `json:"host_key_changed,omitempty"`
	HostKeyMismatchDetail string             `json:"host_key_mismatch_detail,omitempty"`
	Fingerprint           string             `json:"fingerprint,omitempty"`
	RouteLabel            string             `json:"route_label,omitempty"`
	RouteFallback         bool               `json:"route_fallback,omitempty"`
	ConnectionReused      bool               `json:"connection_reused,omitempty"`

	// System Identity & Clock
	Hostname         string `json:"hostname,omitempty"`
	OS               string `json:"os,omitempty"`
	Kernel           string `json:"kernel,omitempty"`
	Arch             string `json:"arch,omitempty"`
	CPUModel         string `json:"cpu_model,omitempty"`
	CPUCores         int    `json:"cpu_cores,omitempty"`
	Virtualization   string `json:"virtualization,omitempty"`
	Uptime           string `json:"uptime,omitempty"`
	UptimeSec        int64  `json:"uptime_sec,omitempty"`
	UnexpectedReboot bool   `json:"unexpected_reboot,omitempty"`
	BootTime         string `json:"boot_time,omitempty"`
	ServerTime       string `json:"server_time,omitempty"`
	Timezone         string `json:"timezone,omitempty"`
	NTPSynced        bool   `json:"ntp_synced"`
	ClockOffsetSec   int64  `json:"clock_offset_sec,omitempty"`

	// Handshake & Compute
	LatencyMs    int64   `json:"latency_ms"`
	CPUPercent   float64 `json:"cpu_percent"`
	CPUUserPct   float64 `json:"cpu_user_pct"`
	CPUSystemPct float64 `json:"cpu_system_pct"`
	CPUIowaitPct float64 `json:"cpu_iowait_pct"`
	CPUStealPct  float64 `json:"cpu_steal_pct"`
	Load1        float64 `json:"load_1"`
	Load5        float64 `json:"load_5"`
	Load15       float64 `json:"load_15"`
	LoadPerCore  float64 `json:"load_per_core"`
	ContextSwSec int64   `json:"context_sw_sec,omitempty"`
	CPUTempC     float64 `json:"cpu_temp_c,omitempty"`

	// Raw cumulative counters for accurate cross-interval delta (zero self-observation bias)
	RawCPUTicks        []uint64 `json:"raw_cpu_ticks,omitempty"`
	RawContextSwitches uint64   `json:"raw_context_switches,omitempty"`
	RawSampleUptime    float64  `json:"raw_sample_uptime,omitempty"`
	RawServerEpoch     int64    `json:"raw_server_epoch,omitempty"`

	// Memory, Swap & Kernel Resources
	MemTotalMB       int64    `json:"mem_total_mb"`
	MemUsedMB        int64    `json:"mem_used_mb"`
	MemAvailableMB   int64    `json:"mem_available_mb"`
	MemCachedMB      int64    `json:"mem_cached_mb"`
	MemBuffersMB     int64    `json:"mem_buffers_mb"`
	MemPercent       float64  `json:"mem_percent"`
	SwapTotalMB      int64    `json:"swap_total_mb"`
	SwapUsedMB       int64    `json:"swap_used_mb"`
	SwapPercent      float64  `json:"swap_percent"`
	FDUsed           int64    `json:"fd_used"`
	FDMax            int64    `json:"fd_max"`
	FDPercent        float64  `json:"fd_percent"`
	OOMKills         int64    `json:"oom_kills"`
	OOMKillsDelta    int64    `json:"oom_kills_delta,omitempty"`
	KernelErrorCount int      `json:"kernel_error_count,omitempty"`
	KernelErrors     []string `json:"kernel_errors,omitempty"`

	// Storage Summary, Hardware Health & Block I/O
	DiskTotalGB           float64             `json:"disk_total_gb"`
	DiskUsedGB            float64             `json:"disk_used_gb"`
	DiskPercent           float64             `json:"disk_percent"`
	MaxPartMount          string              `json:"max_part_mount,omitempty"`
	MaxPartPercent        float64             `json:"max_part_percent"`
	MaxInodeMount         string              `json:"max_inode_mount,omitempty"`
	MaxInodePercent       float64             `json:"max_inode_percent"`
	DiskFullForecastHours float64             `json:"disk_full_forecast_hours,omitempty"`
	DiskFullForecastMount string              `json:"disk_full_forecast_mount,omitempty"`
	ReadOnlyMounts        []string            `json:"read_only_mounts,omitempty"`
	RemoteMounts          []string            `json:"remote_mounts,omitempty"`
	RAIDDegraded          []string            `json:"raid_degraded,omitempty"`
	DiskReadBps           int64               `json:"disk_read_bps"`
	DiskWriteBps          int64               `json:"disk_write_bps"`
	DiskIOPS              int64               `json:"disk_iops"`
	DiskTotalReadB        int64               `json:"disk_total_read_b,omitempty"`
	DiskTotalWriteB       int64               `json:"disk_total_write_b,omitempty"`
	DiskTotalIOOps        int64               `json:"disk_total_io_ops,omitempty"`
	Disks                 []DiskPartitionStat `json:"disks,omitempty"`

	// Network Throughput & Socket Matrix
	NetRxBps             int64              `json:"net_rx_bps"`
	NetTxBps             int64              `json:"net_tx_bps"`
	NetRxTotalBytes      int64              `json:"net_rx_total_bytes"`
	NetTxTotalBytes      int64              `json:"net_tx_total_bytes"`
	NetPacketErrors      int64              `json:"net_packet_errors"`
	NetPacketErrorsDelta int64              `json:"net_packet_errors_delta,omitempty"`
	TCPEstablished       int                `json:"tcp_established"`
	TCPSynRecv           int                `json:"tcp_syn_recv"`
	TCPTimeWait          int                `json:"tcp_time_wait"`
	TCPCloseWait         int                `json:"tcp_close_wait"`
	TCPListen            int                `json:"tcp_listen"`
	UDPSockets           int                `json:"udp_sockets"`
	Interfaces           []NetInterfaceStat `json:"interfaces,omitempty"`

	// Processes, Ports, Services, Containers & Security
	ProcsTotal         int                 `json:"procs_total"`
	ProcsRunning       int                 `json:"procs_running"`
	ProcsSleeping      int                 `json:"procs_sleeping"`
	ProcsZombie        int                 `json:"procs_zombie"`
	ProcsBlocked       int                 `json:"procs_blocked"`
	TopCPUProcs        []ProcessStat       `json:"top_cpu_procs,omitempty"`
	TopMemProcs        []ProcessStat       `json:"top_mem_procs,omitempty"`
	ListeningPorts     []ListeningPortStat `json:"listening_ports,omitempty"`
	PortsTruncated     bool                `json:"ports_truncated,omitempty"`
	Services           []ServiceStat       `json:"services,omitempty"`
	SystemdFailedCount int                 `json:"systemd_failed_count"`
	SystemdFailedUnits []string            `json:"systemd_failed_units,omitempty"`
	Docker             DockerSummary       `json:"docker"`
	Security           SecurityPostureStat `json:"security"`
}

// ToSamplePoint extracts a compact time-series point from a deep snapshot.
func (s *ServerMonitorSnapshot) ToSamplePoint() MonitorSamplePoint {
	diskPct := s.MaxPartPercent
	if diskPct <= 0 {
		diskPct = s.DiskPercent
	}
	return MonitorSamplePoint{
		Timestamp:       s.CollectedAt,
		Reachable:       s.Reachable,
		HealthScore:     s.HealthScore,
		LatencyMs:       s.LatencyMs,
		CPUPercent:      s.CPUPercent,
		CPUUserPct:      s.CPUUserPct,
		CPUSystemPct:    s.CPUSystemPct,
		CPUIowaitPct:    s.CPUIowaitPct,
		CPUStealPct:     s.CPUStealPct,
		Load1:           s.Load1,
		Load5:           s.Load5,
		Load15:          s.Load15,
		MemPercent:      s.MemPercent,
		MemUsedMB:       s.MemUsedMB,
		SwapPercent:     s.SwapPercent,
		DiskPercent:     diskPct,
		InodePercent:    s.MaxInodePercent,
		DiskReadBps:     s.DiskReadBps,
		DiskWriteBps:    s.DiskWriteBps,
		DiskIOPS:        s.DiskIOPS,
		NetRxBps:        s.NetRxBps,
		NetTxBps:        s.NetTxBps,
		TCPEstablished:  s.TCPEstablished,
		TCPTimeWait:     s.TCPTimeWait,
		TCPCloseWait:    s.TCPCloseWait,
		TCPSynRecv:      s.TCPSynRecv,
		ProcsTotal:      s.ProcsTotal,
		ProcsRunning:    s.ProcsRunning,
		ProcsZombie:     s.ProcsZombie,
		ProcsBlocked:    s.ProcsBlocked,
		FDPercent:       s.FDPercent,
		CPUTempC:        s.CPUTempC,
		SSHFailedRecent: s.Security.SSHFailedRecent,
	}
}

// MonitorAlert records a triggered, acknowledged, or resolved monitoring alert event.
type MonitorAlert struct {
	ID             string        `json:"id"`
	DedupKey       string        `json:"dedup_key"` // server_id|rule_kind|sub_target
	ServerID       string        `json:"server_id"`
	ServerName     string        `json:"server_name"`
	Host           string        `json:"host"`
	RuleKind       string        `json:"rule_kind"`
	RuleName       string        `json:"rule_name"`
	Severity       AlertSeverity `json:"severity"`
	Status         AlertStatus   `json:"status"`
	Title          string        `json:"title"`
	Detail         string        `json:"detail"`
	MetricText     string        `json:"metric_text"`
	ThresholdText  string        `json:"threshold_text,omitempty"`
	Occurrences    int           `json:"occurrences"`
	TriggeredAt    time.Time     `json:"triggered_at"`
	LastSeenAt     time.Time     `json:"last_seen_at"`
	AcknowledgedAt *time.Time    `json:"acknowledged_at,omitempty"`
	ResolvedAt     *time.Time    `json:"resolved_at,omitempty"`
}

// ServerSLASummary aggregates historical availability & peak metrics for a server.
type ServerSLASummary struct {
	TotalSamples    int     `json:"total_samples"`
	OnlineSamples   int     `json:"online_samples"`
	AvailabilityPct float64 `json:"availability_pct"`
	AvgLatencyMs    int64   `json:"avg_latency_ms"`
	MaxLatencyMs    int64   `json:"max_latency_ms"`
	AvgCPUPercent   float64 `json:"avg_cpu_percent"`
	MaxCPUPercent   float64 `json:"max_cpu_percent"`
	AvgMemPercent   float64 `json:"avg_mem_percent"`
	MaxMemPercent   float64 `json:"max_mem_percent"`
	MaxDiskPercent  float64 `json:"max_disk_percent"`
}

// MonitorVaultData is the legacy encrypted monitoring store inside VaultState.
type MonitorVaultData struct {
	Settings          MonitorSettings                   `json:"settings"`
	Rules             []MonitorAlertRule                `json:"rules"`
	LatestSnapshots   map[string]*ServerMonitorSnapshot `json:"latest_snapshots"`
	HistoryByServer   map[string][]MonitorSamplePoint   `json:"history_by_server"`
	Alerts            []MonitorAlert                    `json:"alerts"`
	BreachStreaks     map[string]int                    `json:"breach_streaks,omitempty"`
	PortBaselines     map[string][]string               `json:"port_baselines,omitempty"`
	SecurityBaselines map[string]ServerSecurityBaseline `json:"security_baselines,omitempty"`
}

// DefaultMonitorSettings returns production-grade defaults for scheduled monitoring.
func DefaultMonitorSettings() MonitorSettings {
	return MonitorSettings{
		Enabled:                 true,
		IntervalSec:             60,
		SlowIntervalSec:         300,
		TimeoutSec:              15,
		Concurrency:             6,
		RetentionPoints:         720,
		MaxAlertRecords:         500,
		CollectProcesses:        true,
		CollectPortsAndServices: true,
		CollectSecurity:         true,
		DetectPortDrift:         true,
		UseSSHConnectionPool:    true,
		ReuseAIPatrolWebhooks:   false,
		IncludeRemoteMounts:     false,
		UnattendedWhileUnlocked: true,
		PolicyVersion:           CurrentMonitorPolicyVersion,
	}
}

// DefaultMonitorAlertRules defines the built-in comprehensive zero-AI multi-dimensional alert policy (L1+L2+L3).
func DefaultMonitorAlertRules() []MonitorAlertRule {
	return []MonitorAlertRule{
		// --- Availability & Connectivity ---
		{
			Kind:             "offline",
			Category:         "availability",
			Name:             "主机离线 / SSH 不可达",
			Description:      "定时采集连续无法建立 SSH 连接或脚本严重超时",
			Enabled:          true,
			StateBased:       true,
			ConsecutiveCount: 2,
		},
		{
			Kind:             "host_key_changed",
			Category:         "availability",
			Name:             "SSH 主机密钥指纹突变（疑似 MITM / 重装）",
			Description:      "远端 SSH 主机指纹与已信任指纹不一致，已自动拦截连接",
			Enabled:          true,
			StateBased:       true,
			ConsecutiveCount: 1,
		},
		{
			Kind:             "unexpected_reboot",
			Category:         "availability",
			Name:             "主机非预期重启检测",
			Description:      "检测到目标主机 Uptime 运行时间显著回落（疑似宕机重启）",
			Enabled:          true,
			StateBased:       true,
			ConsecutiveCount: 1,
		},
		{
			Kind:              "latency_high",
			Category:          "availability",
			Name:              "SSH 链路探测延迟过高",
			Description:       "到目标主机（含跳板机隧道）的保活或握手响应耗时异常",
			Unit:              "ms",
			Enabled:           true,
			WarningThreshold:  350,
			CriticalThreshold: 900,
			ConsecutiveCount:  2,
		},

		// --- Compute, Memory & Kernel ---
		{
			Kind:              "cpu_high",
			Category:          "compute",
			Name:              "CPU 总使用率过高",
			Description:       "主机跨周期平均 CPU 使用率持续高于阈值（消除采集中断偏差）",
			Unit:              "%",
			Enabled:           true,
			WarningThreshold:  80,
			CriticalThreshold: 92,
			ConsecutiveCount:  2,
		},
		{
			Kind:              "cpu_steal_high",
			Category:          "compute",
			Name:              "云主机 CPU Steal 抢占过高",
			Description:       "虚拟化宿主机超售导致 CPU 算力被抢占，引发应用抖动",
			Unit:              "%",
			Enabled:           true,
			WarningThreshold:  15,
			CriticalThreshold: 30,
			ConsecutiveCount:  2,
		},
		{
			Kind:              "iowait_high",
			Category:          "compute",
			Name:              "磁盘 I/O 等待率过高",
			Description:       "CPU 等待磁盘 I/O 占比过高，通常指示存储瓶颈",
			Unit:              "%",
			Enabled:           true,
			WarningThreshold:  28,
			CriticalThreshold: 50,
			ConsecutiveCount:  2,
		},
		{
			Kind:              "load_high",
			Category:          "compute",
			Name:              "单核归一化负载过高",
			Description:       "1 分钟系统负载除以逻辑 CPU 核心数 (Load1 / Cores)",
			Unit:              "x",
			Enabled:           true,
			WarningThreshold:  1.5,
			CriticalThreshold: 3.0,
			ConsecutiveCount:  2,
		},
		{
			Kind:              "mem_high",
			Category:          "compute",
			Name:              "物理内存占用率过高",
			Description:       "基于 MemAvailable 计算的实际内存占用百分比",
			Unit:              "%",
			Enabled:           true,
			WarningThreshold:  85,
			CriticalThreshold: 94,
			ConsecutiveCount:  1,
		},
		{
			Kind:              "swap_high",
			Category:          "compute",
			Name:              "Swap 交换空间占用过高",
			Description:       "Swap 交换分区大量使用可能导致系统抖动变慢",
			Unit:              "%",
			Enabled:           true,
			WarningThreshold:  60,
			CriticalThreshold: 85,
			ConsecutiveCount:  2,
		},
		{
			Kind:              "oom_kill",
			Category:          "compute",
			Name:              "内核 OOM Killer 击杀进程",
			Description:       "两次采样周期内检测到 /proc/vmstat oom_kill 计数新增",
			Unit:              "次",
			Enabled:           true,
			WarningThreshold:  1,
			CriticalThreshold: 1,
			ConsecutiveCount:  1,
		},
		{
			Kind:              "fd_high",
			Category:          "compute",
			Name:              "内核文件句柄占用过高",
			Description:       "系统已分配文件描述符占 fs.file-max 比例过高",
			Unit:              "%",
			Enabled:           true,
			WarningThreshold:  75,
			CriticalThreshold: 90,
			ConsecutiveCount:  1,
		},
		{
			Kind:              "zombie_procs",
			Category:          "compute",
			Name:              "僵尸进程 (Zombie) 堆积",
			Description:       "父进程未回收的 Z 状态僵尸进程数量超过阈值",
			Unit:              "个",
			Enabled:           true,
			WarningThreshold:  5,
			CriticalThreshold: 20,
			ConsecutiveCount:  2,
		},
		{
			Kind:              "blocked_procs",
			Category:          "compute",
			Name:              "D 态不可中断阻塞进程堆积",
			Description:       "处于不可中断睡眠（D/U 态）的进程数异常，常指示磁盘或 NFS 卡死",
			Unit:              "个",
			Enabled:           true,
			WarningThreshold:  5,
			CriticalThreshold: 15,
			ConsecutiveCount:  2,
		},
		{
			Kind:              "temp_high",
			Category:          "compute",
			Name:              "硬件 CPU 温度过高",
			Description:       "物理机或边缘节点热传感器温度超过安全阈值",
			Unit:              "°C",
			Enabled:           true,
			WarningThreshold:  78,
			CriticalThreshold: 88,
			ConsecutiveCount:  2,
		},

		// --- Storage & Hardware Stability ---
		{
			Kind:              "disk_high",
			Category:          "storage",
			Name:              "本地磁盘分区容量不足",
			Description:       "任意真实本地挂载分区（按 df 真实可用容量比）使用率超过阈值",
			Unit:              "%",
			Enabled:           true,
			WarningThreshold:  80,
			CriticalThreshold: 90,
			ConsecutiveCount:  1,
		},
		{
			Kind:              "inode_high",
			Category:          "storage",
			Name:              "文件系统 Inode 耗尽风险",
			Description:       "任意本地分区 Inode 索引节点占用率过高，耗尽后无法新建文件",
			Unit:              "%",
			Enabled:           true,
			WarningThreshold:  80,
			CriticalThreshold: 92,
			ConsecutiveCount:  1,
		},
		{
			Kind:             "disk_readonly",
			Category:         "storage",
			Name:             "文件系统异常重挂载为只读 (RO)",
			Description:      "检测到 ext4/xfs/btrfs 等可写分区变为只读挂载，常由底层磁盘/文件系统损坏触发",
			Enabled:          true,
			StateBased:       true,
			ConsecutiveCount: 1,
		},
		{
			Kind:              "disk_will_fill",
			Category:          "storage",
			Name:              "磁盘容量增长过快预计耗尽",
			Description:       "基于历史采样趋势线性回归预测（零远端开销），预计剩余耗尽小时数低于阈值",
			Unit:              "h",
			Enabled:           true,
			LowerIsWorse:      true,
			WarningThreshold:  24,
			CriticalThreshold: 6,
			ConsecutiveCount:  2,
		},
		{
			Kind:             "raid_degraded",
			Category:         "storage",
			Name:             "软 RAID 阵列降级 / 磁盘故障",
			Description:      "从 /proc/mdstat 检测到 mdadm 阵列存在离线或损坏成员盘",
			Enabled:          true,
			StateBased:       true,
			ConsecutiveCount: 1,
		},
		{
			Kind:              "kernel_error",
			Category:          "storage",
			Name:              "内核硬件 / 存储 / NFS 严重错误",
			Description:       "慢层内核日志捕获 I/O error、EXT4/XFS 损坏、NFS 无响应、MCE 或 Call Trace",
			Unit:              "条",
			Enabled:           true,
			WarningThreshold:  1,
			CriticalThreshold: 5,
			ConsecutiveCount:  1,
		},

		// --- Services & Containers ---
		{
			Kind:             "systemd_failed",
			Category:         "services",
			Name:             "Systemd 服务故障或守护服务停止",
			Description:      "必监守护服务非 active 与系统 failed 单元独立评估，互不遮蔽",
			Enabled:          true,
			StateBased:       true,
			ConsecutiveCount: 1,
		},
		{
			Kind:             "docker_unhealthy",
			Category:         "services",
			Name:             "Docker 容器异常健康 / 崩退 / 引擎失联",
			Description:      "检测到 unhealthy、restarting、dead、非 0 退出码崩退容器或 Docker Daemon 失联",
			Enabled:          true,
			StateBased:       true,
			ConsecutiveCount: 1,
		},

		// --- Network & Listening Ports ---
		{
			Kind:              "tcp_close_wait",
			Category:          "network",
			Name:              "TCP 异常半关闭 / 半连接堆积",
			Description:       "CLOSE_WAIT + SYN_RECV 套接字数异常（零锁 ss 采集），提示连接泄漏或 SYN 泛洪",
			Unit:              "个",
			Enabled:           true,
			WarningThreshold:  200,
			CriticalThreshold: 800,
			ConsecutiveCount:  2,
		},
		{
			Kind:              "net_errors_spike",
			Category:          "network",
			Name:              "网卡错包 / 丢包增量突增",
			Description:       "单次采样周期内业务网卡 RX/TX 错误与丢包增量超过阈值",
			Unit:              "包",
			Enabled:           true,
			WarningThreshold:  50,
			CriticalThreshold: 500,
			ConsecutiveCount:  2,
		},
		{
			Kind:             "watched_port_down",
			Category:         "network",
			Name:             "关键守护端口未监听",
			Description:      "主机配置的必监端口未在 TCP/UDP 监听列表中发现（含截断保护）",
			Enabled:          true,
			StateBased:       true,
			ConsecutiveCount: 1,
		},
		{
			Kind:             "port_drift",
			Category:         "network",
			Name:             "新增对外暴露监听端口漂移",
			Description:      "相较安全基线发现新开放的非 loopback 对外监听端口（覆盖绑定具体网卡 IP）",
			Enabled:          true,
			StateBased:       true,
			ConsecutiveCount: 1,
		},

		// --- Security & Intrusion (Zero-AI Deterministic) ---
		{
			Kind:              "ssh_bruteforce",
			Category:          "security",
			Name:              "SSH 登录认证失败高频爆破",
			Description:       "近 15 分钟精准时间窗内去重统计 SSH 失败登录次数（支持 IPv4/IPv6）",
			Unit:              "次",
			Enabled:           true,
			WarningThreshold:  25,
			CriticalThreshold: 100,
			ConsecutiveCount:  1,
		},
		{
			Kind:             "uid_zero_backdoor",
			Category:         "security",
			Name:             "发现非 root 的 UID=0 超级特权账户",
			Description:      "系统账户表中存在除 root 外的 UID=0 账号，极高概率为提权后门",
			Enabled:          true,
			StateBased:       true,
			ConsecutiveCount: 1,
		},
		{
			Kind:             "firewall_inactive",
			Category:         "security",
			Name:             "主机防火墙已关闭 / 退化",
			Description:      "检测到已安装的 ufw/firewalld/macos-alf 防火墙明确处于 inactive 关闭状态",
			Enabled:          true,
			StateBased:       true,
			ConsecutiveCount: 1,
		},
		{
			Kind:             "security_file_drift",
			Category:         "security",
			Name:             "关键安全文件 / 持久化基线漂移 (FIM)",
			Description:      "authorized_keys、passwd、shadow、sudoers、sshd_config、ld.so.preload 或 crontab 哈希变化",
			Enabled:          true,
			StateBased:       true,
			ConsecutiveCount: 1,
		},
		{
			Kind:             "suspicious_process",
			Category:         "security",
			Name:             "可疑进程特征（/tmp 运行、挖矿或反弹 Shell）",
			Description:      "确定性识别从 /tmp、/dev/shm 执行的进程及已知挖矿/反弹 Shell 特征",
			Enabled:          true,
			StateBased:       true,
			ConsecutiveCount: 1,
		},
		{
			Kind:             "suspicious_outbound",
			Category:         "security",
			Name:             "异常高危外联端口 / 可疑出站连接",
			Description:      "检测到已建立至常见矿池或反向 Shell 高危端口的外联连接（默认关闭防业务误报，按需开启）",
			Enabled:          false,
			StateBased:       true,
			ConsecutiveCount: 1,
		},
		{
			Kind:             "ssh_new_login_ip",
			Category:         "security",
			Name:             "新来源 IP 成功登录 SSH",
			Description:      "检测到不在已知基线 IP 列表中的外部 IP 成功 SSH 登录（默认关闭防办公网浮动 IP 误报）",
			Enabled:          false,
			StateBased:       true,
			ConsecutiveCount: 1,
		},
		{
			Kind:              "clock_ntp_drift",
			Category:          "security",
			Name:              "主机时钟偏移过大",
			Description:       "目标机 UTC 时间与监控端偏差超过阈值，影响 TLS/TOTP 与分布式日志审计（按需开启）",
			Unit:              "s",
			Enabled:           false,
			WarningThreshold:  10,
			CriticalThreshold: 60,
			ConsecutiveCount:  2,
		},
	}
}

// DefaultMonitorVaultData initializes clean legacy monitoring storage.
func DefaultMonitorVaultData() *MonitorVaultData {
	return &MonitorVaultData{
		Settings:          DefaultMonitorSettings(),
		Rules:             DefaultMonitorAlertRules(),
		LatestSnapshots:   make(map[string]*ServerMonitorSnapshot),
		HistoryByServer:   make(map[string][]MonitorSamplePoint),
		Alerts:            []MonitorAlert{},
		BreachStreaks:     make(map[string]int),
		PortBaselines:     make(map[string][]string),
		SecurityBaselines: make(map[string]ServerSecurityBaseline),
	}
}

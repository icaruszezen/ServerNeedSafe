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

// MonitorSettings controls periodic background telemetry collection and retention.
// Stored 100% encrypted inside VaultState.
type MonitorSettings struct {
	Enabled                 bool   `json:"enabled"`                   // Enable scheduled background polling
	IntervalSec             int    `json:"interval_sec"`              // Default polling interval in seconds (15..3600)
	TimeoutSec              int    `json:"timeout_sec"`               // Per-server SSH probe timeout in seconds (5..60)
	Concurrency             int    `json:"concurrency"`               // Max concurrent SSH collectors (1..20)
	RetentionPoints         int    `json:"retention_points"`          // Max time-series samples kept per server (60..2880)
	MaxAlertRecords         int    `json:"max_alert_records"`         // Max alert incidents retained (50..2000)
	CollectProcesses        bool   `json:"collect_processes"`         // Collect top CPU/Mem processes & zombie stats
	CollectPortsAndServices bool   `json:"collect_ports_and_services"` // Collect listening ports, systemd & Docker
	CollectSecurity         bool   `json:"collect_security"`          // Collect SSH brute-force, logged-in users, firewall
	DetectPortDrift         bool   `json:"detect_port_drift"`         // Alert on newly exposed public listening ports
	UnattendedWhileUnlocked bool   `json:"unattended_while_unlocked"` // Keep daemon polling when web sessions idle-expire
	WebhookURL              string `json:"webhook_url,omitempty"`     // Optional encrypted webhook URL for alert notifications
}

// MonitorAlertRule configures warning/critical thresholds and anti-flap consecutive breach counts.
type MonitorAlertRule struct {
	Kind              string  `json:"kind"`
	Name              string  `json:"name"`
	Description       string  `json:"description"`
	Unit              string  `json:"unit,omitempty"`
	Enabled           bool    `json:"enabled"`
	StateBased        bool    `json:"state_based"`
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
	Proto         string `json:"proto"`          // tcp, tcp6, udp, udp6
	BindAddr      string `json:"bind_addr"`      // e.g. 0.0.0.0, 127.0.0.1, [::]
	Port          int    `json:"port"`           // e.g. 22, 80, 443
	PublicExposed bool   `json:"public_exposed"` // Bound to wildcard 0.0.0.0 / :: / *
	Watched       bool   `json:"watched"`        // Explicitly watched by server config
	PID           int    `json:"pid,omitempty"`
	Process       string `json:"process,omitempty"`
}

// ServiceStat captures the runtime state of a systemd unit or daemon service.
type ServiceStat struct {
	Name     string `json:"name"`
	State    string `json:"state"`              // active, inactive, failed, not-found
	SubState string `json:"sub_state,omitempty"` // running, exited, dead
	Watched  bool   `json:"watched"`
}

// ContainerStat captures a Docker/OCI container status on the monitored host.
type ContainerStat struct {
	ID     string `json:"id,omitempty"`
	Name   string `json:"name"`
	Image  string `json:"image"`
	State  string `json:"state"`  // running, exited, restarting, paused, dead
	Status string `json:"status"` // e.g. Up 3 days (healthy)
	Health string `json:"health,omitempty"`
}

// DockerSummary summarizes container engine health on the remote host.
type DockerSummary struct {
	Installed  bool            `json:"installed"`
	Running    int             `json:"running"`
	Stopped    int             `json:"stopped"`
	Unhealthy  int             `json:"unhealthy"`
	Containers []ContainerStat `json:"containers,omitempty"`
}

// LoggedInUserStat represents an active interactive user session (TTY/PTS) on the host.
type LoggedInUserStat struct {
	User      string `json:"user"`
	TTY       string `json:"tty"`
	FromIP    string `json:"from_ip,omitempty"`
	LoginTime string `json:"login_time,omitempty"`
}

// SecurityPostureStat captures security-relevant host telemetry.
type SecurityPostureStat struct {
	ActiveUsers     []LoggedInUserStat `json:"active_users,omitempty"`
	SSHFailedRecent int                `json:"ssh_failed_recent"`
	TopFailedIPs    []string           `json:"top_failed_ips,omitempty"`
	FirewallStatus  string             `json:"firewall_status"`           // active, inactive, unknown
	FirewallDetail  string             `json:"firewall_detail,omitempty"` // ufw / firewalld / nftables / iptables
	MACFramework    string             `json:"mac_framework,omitempty"`   // selinux / apparmor / none
	UIDZeroUsers    []string           `json:"uid_zero_users,omitempty"`
	RebootRequired  bool               `json:"reboot_required"`
	PendingUpdates  int                `json:"pending_updates"`
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
	ServerID    string             `json:"server_id"`
	ServerName  string             `json:"server_name"`
	Group       string             `json:"group"`
	Host        string             `json:"host"`
	Port        int                `json:"port"`
	CollectedAt time.Time          `json:"collected_at"`
	DurationMs  int64              `json:"duration_ms"`
	Reachable   bool               `json:"reachable"`
	HealthLevel MonitorHealthLevel `json:"health_level"`
	HealthScore int                `json:"health_score"`
	Error       string             `json:"error,omitempty"`
	Fingerprint string             `json:"fingerprint,omitempty"`

	// System Identity & Clock
	Hostname       string `json:"hostname,omitempty"`
	OS             string `json:"os,omitempty"`
	Kernel         string `json:"kernel,omitempty"`
	Arch           string `json:"arch,omitempty"`
	CPUModel       string `json:"cpu_model,omitempty"`
	CPUCores       int    `json:"cpu_cores,omitempty"`
	Virtualization string `json:"virtualization,omitempty"`
	Uptime         string `json:"uptime,omitempty"`
	UptimeSec      int64  `json:"uptime_sec,omitempty"`
	BootTime       string `json:"boot_time,omitempty"`
	ServerTime     string `json:"server_time,omitempty"`
	Timezone       string `json:"timezone,omitempty"`
	NTPSynced      bool   `json:"ntp_synced"`

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

	// Memory, Swap & Kernel Resources
	MemTotalMB     int64   `json:"mem_total_mb"`
	MemUsedMB      int64   `json:"mem_used_mb"`
	MemAvailableMB int64   `json:"mem_available_mb"`
	MemCachedMB    int64   `json:"mem_cached_mb"`
	MemBuffersMB   int64   `json:"mem_buffers_mb"`
	MemPercent     float64 `json:"mem_percent"`
	SwapTotalMB    int64   `json:"swap_total_mb"`
	SwapUsedMB     int64   `json:"swap_used_mb"`
	SwapPercent    float64 `json:"swap_percent"`
	FDUsed         int64   `json:"fd_used"`
	FDMax          int64   `json:"fd_max"`
	FDPercent      float64 `json:"fd_percent"`
	OOMKills       int64   `json:"oom_kills"`

	// Storage Summary & Block I/O
	DiskTotalGB       float64             `json:"disk_total_gb"`
	DiskUsedGB        float64             `json:"disk_used_gb"`
	DiskPercent       float64             `json:"disk_percent"`
	MaxPartMount      string              `json:"max_part_mount,omitempty"`
	MaxPartPercent    float64             `json:"max_part_percent"`
	MaxInodeMount     string              `json:"max_inode_mount,omitempty"`
	MaxInodePercent   float64             `json:"max_inode_percent"`
	DiskReadBps       int64               `json:"disk_read_bps"`
	DiskWriteBps      int64               `json:"disk_write_bps"`
	DiskIOPS          int64               `json:"disk_iops"`
	DiskTotalReadB    int64               `json:"disk_total_read_b,omitempty"`
	DiskTotalWriteB   int64               `json:"disk_total_write_b,omitempty"`
	DiskTotalIOOps    int64               `json:"disk_total_io_ops,omitempty"`
	Disks             []DiskPartitionStat `json:"disks,omitempty"`

	// Network Throughput & Socket Matrix
	NetRxBps        int64              `json:"net_rx_bps"`
	NetTxBps        int64              `json:"net_tx_bps"`
	NetRxTotalBytes int64              `json:"net_rx_total_bytes"`
	NetTxTotalBytes int64              `json:"net_tx_total_bytes"`
	NetPacketErrors int64              `json:"net_packet_errors"`
	TCPEstablished  int                `json:"tcp_established"`
	TCPSynRecv      int                `json:"tcp_syn_recv"`
	TCPTimeWait     int                `json:"tcp_time_wait"`
	TCPCloseWait    int                `json:"tcp_close_wait"`
	TCPListen       int                `json:"tcp_listen"`
	UDPSockets      int                `json:"udp_sockets"`
	Interfaces      []NetInterfaceStat `json:"interfaces,omitempty"`

	// Processes, Ports, Services, Containers & Security
	ProcsTotal         int                 `json:"procs_total"`
	ProcsRunning       int                 `json:"procs_running"`
	ProcsSleeping      int                 `json:"procs_sleeping"`
	ProcsZombie        int                 `json:"procs_zombie"`
	ProcsBlocked       int                 `json:"procs_blocked"`
	TopCPUProcs        []ProcessStat       `json:"top_cpu_procs,omitempty"`
	TopMemProcs        []ProcessStat       `json:"top_mem_procs,omitempty"`
	ListeningPorts     []ListeningPortStat `json:"listening_ports,omitempty"`
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

// MonitorVaultData is the root encrypted monitoring store inside VaultState.
type MonitorVaultData struct {
	Settings        MonitorSettings                   `json:"settings"`
	Rules           []MonitorAlertRule                `json:"rules"`
	LatestSnapshots map[string]*ServerMonitorSnapshot `json:"latest_snapshots"`
	HistoryByServer map[string][]MonitorSamplePoint   `json:"history_by_server"`
	Alerts          []MonitorAlert                    `json:"alerts"`
	BreachStreaks   map[string]int                    `json:"breach_streaks,omitempty"`
	PortBaselines   map[string][]string               `json:"port_baselines,omitempty"`
}

// DefaultMonitorSettings returns production-grade defaults for scheduled monitoring.
func DefaultMonitorSettings() MonitorSettings {
	return MonitorSettings{
		Enabled:                 true,
		IntervalSec:             60,
		TimeoutSec:              15,
		Concurrency:             6,
		RetentionPoints:         720,
		MaxAlertRecords:         500,
		CollectProcesses:        true,
		CollectPortsAndServices: true,
		CollectSecurity:         true,
		DetectPortDrift:         true,
		UnattendedWhileUnlocked: true,
	}
}

// DefaultMonitorAlertRules defines the built-in comprehensive multi-dimensional alert policy.
func DefaultMonitorAlertRules() []MonitorAlertRule {
	return []MonitorAlertRule{
		{
			Kind:             "offline",
			Name:             "主机离线 / SSH 不可达",
			Description:      "定时采集无法建立 SSH 握手连接或超时",
			Enabled:          true,
			StateBased:       true,
			ConsecutiveCount: 1,
		},
		{
			Kind:              "cpu_high",
			Name:              "CPU 总使用率过高",
			Description:       "主机总体实时 CPU 使用率持续高于阈值",
			Unit:              "%",
			Enabled:           true,
			WarningThreshold:  80,
			CriticalThreshold: 92,
			ConsecutiveCount:  2,
		},
		{
			Kind:              "iowait_high",
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
			Name:              "Swap 交换空间占用过高",
			Description:       "Swap 交换分区大量使用可能导致系统抖动变慢",
			Unit:              "%",
			Enabled:           true,
			WarningThreshold:  60,
			CriticalThreshold: 85,
			ConsecutiveCount:  2,
		},
		{
			Kind:              "disk_high",
			Name:              "磁盘挂载分区容量不足",
			Description:       "任意真实挂载分区空间使用率超过阈值",
			Unit:              "%",
			Enabled:           true,
			WarningThreshold:  80,
			CriticalThreshold: 90,
			ConsecutiveCount:  1,
		},
		{
			Kind:              "inode_high",
			Name:              "文件系统 Inode 耗尽风险",
			Description:       "任意分区 Inode 索引节点占用率过高，耗尽后将无法新建文件",
			Unit:              "%",
			Enabled:           true,
			WarningThreshold:  80,
			CriticalThreshold: 92,
			ConsecutiveCount:  1,
		},
		{
			Kind:              "fd_high",
			Name:              "内核文件句柄占用过高",
			Description:       "系统已分配文件描述符占 fs.file-max 比例过高",
			Unit:              "%",
			Enabled:           true,
			WarningThreshold:  75,
			CriticalThreshold: 90,
			ConsecutiveCount:  1,
		},
		{
			Kind:              "latency_high",
			Name:              "SSH 链路探测延迟过高",
			Description:       "到目标主机（含跳板机隧道）的握手响应耗时异常",
			Unit:              "ms",
			Enabled:           true,
			WarningThreshold:  350,
			CriticalThreshold: 900,
			ConsecutiveCount:  2,
		},
		{
			Kind:              "zombie_procs",
			Name:              "僵尸进程 (Zombie) 堆积",
			Description:       "父进程未回收的 Z 状态僵尸进程数量超过阈值",
			Unit:              "个",
			Enabled:           true,
			WarningThreshold:  5,
			CriticalThreshold: 20,
			ConsecutiveCount:  2,
		},
		{
			Kind:              "tcp_close_wait",
			Name:              "TCP 异常半关闭/半连接堆积",
			Description:       "CLOSE_WAIT + SYN_RECV 套接字数异常，提示连接泄漏或 SYN 泛洪",
			Unit:              "个",
			Enabled:           true,
			WarningThreshold:  200,
			CriticalThreshold: 800,
			ConsecutiveCount:  2,
		},
		{
			Kind:             "systemd_failed",
			Name:             "Systemd 服务故障或守护服务停止",
			Description:      "存在 failed 状态的系统单元或指定守护服务未处于 active 状态",
			Enabled:          true,
			StateBased:       true,
			ConsecutiveCount: 1,
		},
		{
			Kind:             "docker_unhealthy",
			Name:             "Docker 容器异常健康告警",
			Description:      "检测到处于 unhealthy 或 restarting 崩溃循环的容器",
			Enabled:          true,
			StateBased:       true,
			ConsecutiveCount: 1,
		},
		{
			Kind:             "watched_port_down",
			Name:             "关键守护端口未监听",
			Description:      "主机配置的必监端口未在 TCP/UDP 监听列表中发现",
			Enabled:          true,
			StateBased:       true,
			ConsecutiveCount: 1,
		},
		{
			Kind:             "port_drift",
			Name:             "新增公网暴露监听端口告警",
			Description:      "相较安全基线发现新的 0.0.0.0 / [::] 对外监听端口",
			Enabled:          true,
			StateBased:       true,
			ConsecutiveCount: 1,
		},
		{
			Kind:              "ssh_bruteforce",
			Name:              "SSH 登录认证失败高频告警",
			Description:       "近期认证日志中检测到大量失败的 SSH 爆破尝试",
			Unit:              "次",
			Enabled:           true,
			WarningThreshold:  25,
			CriticalThreshold: 100,
			ConsecutiveCount:  1,
		},
		{
			Kind:              "temp_high",
			Name:              "硬件 CPU 温度过高",
			Description:       "物理机或边缘节点热传感器温度超过安全阈值",
			Unit:              "°C",
			Enabled:           true,
			WarningThreshold:  78,
			CriticalThreshold: 88,
			ConsecutiveCount:  2,
		},
	}
}

// DefaultMonitorVaultData initializes clean encrypted monitoring storage.
func DefaultMonitorVaultData() *MonitorVaultData {
	return &MonitorVaultData{
		Settings:        DefaultMonitorSettings(),
		Rules:           DefaultMonitorAlertRules(),
		LatestSnapshots: make(map[string]*ServerMonitorSnapshot),
		HistoryByServer: make(map[string][]MonitorSamplePoint),
		Alerts:          []MonitorAlert{},
		BreachStreaks:   make(map[string]int),
		PortBaselines:   make(map[string][]string),
	}
}

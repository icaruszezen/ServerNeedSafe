package vault

import (
	"fmt"
	"math"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// FleetMonitorKPI summarizes cluster-wide health and telemetry across all managed servers.
type FleetMonitorKPI struct {
	TotalServers     int     `json:"total_servers"`
	MonitoredServers int     `json:"monitored_servers"`
	OnlineServers    int     `json:"online_servers"`
	HealthyServers   int     `json:"healthy_servers"`
	WarningServers   int     `json:"warning_servers"`
	CriticalServers  int     `json:"critical_servers"`
	OfflineServers   int     `json:"offline_servers"`
	UnknownServers   int     `json:"unknown_servers"`
	AvgHealthScore   int     `json:"avg_health_score"`
	AvgCPUPercent    float64 `json:"avg_cpu_percent"`
	AvgMemPercent    float64 `json:"avg_mem_percent"`
	AvgDiskPercent   float64 `json:"avg_disk_percent"`
	AvgLatencyMs     int64   `json:"avg_latency_ms"`
	TotalNetRxBps    int64   `json:"total_net_rx_bps"`
	TotalNetTxBps    int64   `json:"total_net_tx_bps"`
	TotalDiskReadBps int64   `json:"total_disk_read_bps"`
	TotalDiskWriteBps int64  `json:"total_disk_write_bps"`
	FiringAlerts     int     `json:"firing_alerts"`
	CriticalAlerts   int     `json:"critical_alerts"`
	WarningAlerts    int     `json:"warning_alerts"`
	TotalSamples     int     `json:"total_samples"`
}

// ServerMonitorCardItem pairs a ServerView with its latest snapshot, sparkline history, SLA, and active alert count.
type ServerMonitorCardItem struct {
	Server       ServerView             `json:"server"`
	Snapshot     *ServerMonitorSnapshot `json:"snapshot,omitempty"`
	Sparkline    []MonitorSamplePoint   `json:"sparkline"`
	SLA          ServerSLASummary       `json:"sla"`
	ActiveAlerts int                    `json:"active_alerts"`
}

// MonitorOverviewData is the payload returned for the Monitor Center overview dashboard.
type MonitorOverviewData struct {
	Settings MonitorSettings         `json:"settings"`
	KPI      FleetMonitorKPI         `json:"kpi"`
	Nodes    []ServerMonitorCardItem `json:"nodes"`
	Alerts   []MonitorAlert          `json:"alerts"`
}

// ServerMonitorDetail holds full historical time-series, deep latest snapshot, SLA, and alerts for one server.
type ServerMonitorDetail struct {
	Server       ServerView             `json:"server"`
	Snapshot     *ServerMonitorSnapshot `json:"snapshot,omitempty"`
	Series       []MonitorSamplePoint   `json:"series"`
	SLA          ServerSLASummary       `json:"sla"`
	PortBaseline []string               `json:"port_baseline"`
	Alerts       []MonitorAlert          `json:"alerts"`
}

// CandidateBreach represents a single detected rule violation during snapshot evaluation.
type CandidateBreach struct {
	DedupKey       string
	RuleKind       string
	RuleName       string
	Severity       AlertSeverity
	Title          string
	Detail         string
	MetricText     string
	ThresholdText  string
	ConsecutiveReq int
}

func sanitizeMonitorSettings(in MonitorSettings) MonitorSettings {
	if in.IntervalSec < 10 {
		in.IntervalSec = 10
	} else if in.IntervalSec > 86400 {
		in.IntervalSec = 86400
	}
	if in.TimeoutSec < 5 {
		in.TimeoutSec = 5
	} else if in.TimeoutSec > 120 {
		in.TimeoutSec = 120
	}
	if in.Concurrency < 1 {
		in.Concurrency = 1
	} else if in.Concurrency > 20 {
		in.Concurrency = 20
	}
	if in.RetentionPoints < 30 {
		in.RetentionPoints = 30
	} else if in.RetentionPoints > 5000 {
		in.RetentionPoints = 5000
	}
	if in.MaxAlertRecords < 50 {
		in.MaxAlertRecords = 50
	} else if in.MaxAlertRecords > 2000 {
		in.MaxAlertRecords = 2000
	}
	in.WebhookURL = strings.TrimSpace(in.WebhookURL)
	return in
}

func mergeMonitorAlertRules(existing []MonitorAlertRule) []MonitorAlertRule {
	defaults := DefaultMonitorAlertRules()
	existingByKind := make(map[string]MonitorAlertRule, len(existing))
	for _, r := range existing {
		if r.ConsecutiveCount < 1 {
			r.ConsecutiveCount = 1
		}
		existingByKind[r.Kind] = r
	}
	merged := make([]MonitorAlertRule, 0, len(defaults))
	for _, def := range defaults {
		if ex, ok := existingByKind[def.Kind]; ok {
			ex.Name = def.Name
			ex.Description = def.Description
			ex.Unit = def.Unit
			ex.StateBased = def.StateBased
			if ex.ConsecutiveCount < 1 {
				ex.ConsecutiveCount = 1
			} else if ex.ConsecutiveCount > 20 {
				ex.ConsecutiveCount = 20
			}
			merged = append(merged, ex)
		} else {
			merged = append(merged, def)
		}
	}
	return merged
}

func ensureMonitorInitialized(state *VaultState) {
	if state == nil {
		return
	}
	if state.Monitor == nil {
		state.Monitor = DefaultMonitorVaultData()
		return
	}
	m := state.Monitor
	if m.Settings.IntervalSec == 0 && m.Settings.RetentionPoints == 0 {
		m.Settings = DefaultMonitorSettings()
	} else {
		m.Settings = sanitizeMonitorSettings(m.Settings)
	}
	if m.LatestSnapshots == nil {
		m.LatestSnapshots = make(map[string]*ServerMonitorSnapshot)
	}
	if m.HistoryByServer == nil {
		m.HistoryByServer = make(map[string][]MonitorSamplePoint)
	}
	if m.Alerts == nil {
		m.Alerts = []MonitorAlert{}
	}
	if m.BreachStreaks == nil {
		m.BreachStreaks = make(map[string]int)
	}
	if m.PortBaselines == nil {
		m.PortBaselines = make(map[string][]string)
	}
	m.Rules = mergeMonitorAlertRules(m.Rules)
}

func cloneSnapshot(in *ServerMonitorSnapshot) *ServerMonitorSnapshot {
	if in == nil {
		return nil
	}
	cp := *in
	cp.Disks = slices.Clone(in.Disks)
	cp.Interfaces = slices.Clone(in.Interfaces)
	cp.TopCPUProcs = slices.Clone(in.TopCPUProcs)
	cp.TopMemProcs = slices.Clone(in.TopMemProcs)
	cp.ListeningPorts = slices.Clone(in.ListeningPorts)
	cp.Services = slices.Clone(in.Services)
	cp.SystemdFailedUnits = slices.Clone(in.SystemdFailedUnits)
	cp.Docker.Containers = slices.Clone(in.Docker.Containers)
	cp.Security.ActiveUsers = slices.Clone(in.Security.ActiveUsers)
	cp.Security.TopFailedIPs = slices.Clone(in.Security.TopFailedIPs)
	cp.Security.UIDZeroUsers = slices.Clone(in.Security.UIDZeroUsers)
	return &cp
}

func cloneMonitorVaultData(in *MonitorVaultData) *MonitorVaultData {
	if in == nil {
		return nil
	}
	cp := &MonitorVaultData{
		Settings:        in.Settings,
		Rules:           slices.Clone(in.Rules),
		LatestSnapshots: make(map[string]*ServerMonitorSnapshot, len(in.LatestSnapshots)),
		HistoryByServer: make(map[string][]MonitorSamplePoint, len(in.HistoryByServer)),
		Alerts:          make([]MonitorAlert, len(in.Alerts)),
		BreachStreaks:   make(map[string]int, len(in.BreachStreaks)),
		PortBaselines:   make(map[string][]string, len(in.PortBaselines)),
	}
	for k, v := range in.LatestSnapshots {
		cp.LatestSnapshots[k] = cloneSnapshot(v)
	}
	for k, v := range in.HistoryByServer {
		cp.HistoryByServer[k] = slices.Clone(v)
	}
	for i, al := range in.Alerts {
		alCp := al
		if al.AcknowledgedAt != nil {
			t := *al.AcknowledgedAt
			alCp.AcknowledgedAt = &t
		}
		if al.ResolvedAt != nil {
			t := *al.ResolvedAt
			alCp.ResolvedAt = &t
		}
		cp.Alerts[i] = alCp
	}
	for k, v := range in.BreachStreaks {
		cp.BreachStreaks[k] = v
	}
	for k, v := range in.PortBaselines {
		cp.PortBaselines[k] = slices.Clone(v)
	}
	return cp
}

func round1(v float64) float64 {
	return math.Round(v*10) / 10
}

func computeSLA(points []MonitorSamplePoint) ServerSLASummary {
	var sla ServerSLASummary
	sla.TotalSamples = len(points)
	if len(points) == 0 {
		return sla
	}
	var sumLat int64
	var sumCPU, sumMem float64
	for _, p := range points {
		if p.Reachable {
			sla.OnlineSamples++
			sumLat += p.LatencyMs
			if p.LatencyMs > sla.MaxLatencyMs {
				sla.MaxLatencyMs = p.LatencyMs
			}
			sumCPU += p.CPUPercent
			if p.CPUPercent > sla.MaxCPUPercent {
				sla.MaxCPUPercent = p.CPUPercent
			}
			sumMem += p.MemPercent
			if p.MemPercent > sla.MaxMemPercent {
				sla.MaxMemPercent = p.MemPercent
			}
			if p.DiskPercent > sla.MaxDiskPercent {
				sla.MaxDiskPercent = p.DiskPercent
			}
		}
	}
	sla.AvailabilityPct = round1(float64(sla.OnlineSamples) * 100.0 / float64(sla.TotalSamples))
	if sla.OnlineSamples > 0 {
		sla.AvgLatencyMs = sumLat / int64(sla.OnlineSamples)
		sla.AvgCPUPercent = round1(sumCPU / float64(sla.OnlineSamples))
		sla.AvgMemPercent = round1(sumMem / float64(sla.OnlineSamples))
	}
	sla.MaxCPUPercent = round1(sla.MaxCPUPercent)
	sla.MaxMemPercent = round1(sla.MaxMemPercent)
	sla.MaxDiskPercent = round1(sla.MaxDiskPercent)
	return sla
}

// ComputeSnapshotHealth calculates the 0-100 health score and classification for a snapshot.
func ComputeSnapshotHealth(snap *ServerMonitorSnapshot, breaches []CandidateBreach) {
	if snap == nil {
		return
	}
	if !snap.Reachable {
		snap.HealthScore = 0
		snap.HealthLevel = HealthOffline
		return
	}

	score := 100.0
	// Progressive resource pressure deductions
	if snap.CPUPercent > 65 {
		score -= (snap.CPUPercent - 65) * 0.7
	}
	if snap.CPUIowaitPct > 15 {
		score -= (snap.CPUIowaitPct - 15) * 0.6
	}
	if snap.LoadPerCore > 1.0 {
		score -= math.Min(25, (snap.LoadPerCore-1.0)*8.0)
	}
	if snap.MemPercent > 75 {
		score -= (snap.MemPercent - 75) * 0.9
	}
	if snap.SwapPercent > 40 {
		score -= (snap.SwapPercent - 40) * 0.25
	}
	maxDisk := snap.MaxPartPercent
	if maxDisk <= 0 {
		maxDisk = snap.DiskPercent
	}
	if maxDisk > 75 {
		score -= (maxDisk - 75) * 0.9
	}
	if snap.MaxInodePercent > 75 {
		score -= (snap.MaxInodePercent - 75) * 0.8
	}
	if snap.ProcsZombie > 0 {
		score -= math.Min(12, float64(snap.ProcsZombie)*1.2)
	}
	if snap.SystemdFailedCount > 0 {
		score -= math.Min(20, float64(snap.SystemdFailedCount)*7)
	}
	if snap.Docker.Unhealthy > 0 {
		score -= math.Min(18, float64(snap.Docker.Unhealthy)*8)
	}
	if snap.LatencyMs > 300 {
		score -= math.Min(12, float64(snap.LatencyMs-300)/80.0)
	}

	hasCrit := false
	hasWarn := false
	for _, b := range breaches {
		if b.Severity == SeverityCritical {
			hasCrit = true
			score -= 12
		} else if b.Severity == SeverityWarning {
			hasWarn = true
			score -= 5
		}
	}

	finalScore := int(math.Round(score))
	if finalScore < 5 {
		finalScore = 5
	}
	if finalScore > 100 {
		finalScore = 100
	}
	snap.HealthScore = finalScore

	switch {
	case hasCrit || finalScore < 60:
		snap.HealthLevel = HealthCritical
	case hasWarn || finalScore < 85:
		snap.HealthLevel = HealthWarning
	default:
		snap.HealthLevel = HealthHealthy
	}
}

func extractPublicPortKeys(ports []ListeningPortStat) []string {
	seen := make(map[string]struct{})
	for _, p := range ports {
		if !p.PublicExposed || p.Port <= 0 {
			continue
		}
		baseProto := "tcp"
		if strings.HasPrefix(strings.ToLower(p.Proto), "udp") {
			baseProto = "udp"
		}
		key := fmt.Sprintf("%s/%d", baseProto, p.Port)
		seen[key] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func evaluateSnapshotRules(
	snap *ServerMonitorSnapshot,
	srv ServerConfig,
	rules []MonitorAlertRule,
	driftedPorts []ListeningPortStat,
) []CandidateBreach {
	ruleMap := make(map[string]MonitorAlertRule, len(rules))
	for _, r := range rules {
		if r.Enabled {
			ruleMap[r.Kind] = r
		}
	}

	var out []CandidateBreach
	addThresholdBreach := func(kind string, val float64, subKey, titlePrefix, detailFmt string) {
		r, ok := ruleMap[kind]
		if !ok || r.StateBased {
			return
		}
		var sev AlertSeverity
		var thresh float64
		if r.CriticalThreshold > 0 && val >= r.CriticalThreshold {
			sev = SeverityCritical
			thresh = r.CriticalThreshold
		} else if r.WarningThreshold > 0 && val >= r.WarningThreshold {
			sev = SeverityWarning
			thresh = r.WarningThreshold
		} else {
			return
		}
		dedup := fmt.Sprintf("%s|%s|%s", srv.ID, kind, subKey)
		metricTxt := fmt.Sprintf("%.1f%s", val, r.Unit)
		threshTxt := fmt.Sprintf(">= %.1f%s", thresh, r.Unit)
		if r.Unit == "ms" || r.Unit == "个" || r.Unit == "次" {
			metricTxt = fmt.Sprintf("%.0f %s", val, r.Unit)
			threshTxt = fmt.Sprintf(">= %.0f %s", thresh, r.Unit)
		}
		out = append(out, CandidateBreach{
			DedupKey:       dedup,
			RuleKind:       kind,
			RuleName:       r.Name,
			Severity:       sev,
			Title:          titlePrefix,
			Detail:         detailFmt,
			MetricText:     metricTxt,
			ThresholdText:  threshTxt,
			ConsecutiveReq: max(1, r.ConsecutiveCount),
		})
	}

	if !snap.Reachable {
		if r, ok := ruleMap["offline"]; ok {
			errMsg := snap.Error
			if errMsg == "" {
				errMsg = "SSH 连接超时或不可达"
			}
			out = append(out, CandidateBreach{
				DedupKey:       fmt.Sprintf("%s|offline|", srv.ID),
				RuleKind:       "offline",
				RuleName:       r.Name,
				Severity:       SeverityCritical,
				Title:          fmt.Sprintf("主机 [%s] 离线不可达", srv.Name),
				Detail:         fmt.Sprintf("定时状态采集无法连接 %s:%d — %s", srv.Host, srv.Port, errMsg),
				MetricText:     "离线",
				ThresholdText:  "SSH 可达",
				ConsecutiveReq: max(1, r.ConsecutiveCount),
			})
		}
		return out
	}

	// 1. CPU, IOWait, Normalized Load
	addThresholdBreach("cpu_high", snap.CPUPercent, "",
		fmt.Sprintf("[%s] CPU 总使用率达到 %.1f%%", srv.Name, snap.CPUPercent),
		fmt.Sprintf("User %.1f%% / Sys %.1f%% / IOWait %.1f%%", snap.CPUUserPct, snap.CPUSystemPct, snap.CPUIowaitPct),
	)
	addThresholdBreach("iowait_high", snap.CPUIowaitPct, "",
		fmt.Sprintf("[%s] 磁盘 I/O 等待率达到 %.1f%%", srv.Name, snap.CPUIowaitPct),
		fmt.Sprintf("当前磁盘读 %d B/s，写 %d B/s，阻塞进程 %d 个", snap.DiskReadBps, snap.DiskWriteBps, snap.ProcsBlocked),
	)
	if snap.CPUCores > 0 && snap.LoadPerCore > 0 {
		addThresholdBreach("load_high", snap.LoadPerCore, "",
			fmt.Sprintf("[%s] 单核平均负载达到 %.2fx (%d 核)", srv.Name, snap.LoadPerCore, snap.CPUCores),
			fmt.Sprintf("系统 Load Avg: %.2f / %.2f / %.2f", snap.Load1, snap.Load5, snap.Load15),
		)
	}

	// 2. Memory, Swap, File Descriptors
	addThresholdBreach("mem_high", snap.MemPercent, "",
		fmt.Sprintf("[%s] 物理内存占用达到 %.1f%%", srv.Name, snap.MemPercent),
		fmt.Sprintf("已用 %d MB / 总计 %d MB (可用 %d MB)", snap.MemUsedMB, snap.MemTotalMB, snap.MemAvailableMB),
	)
	if snap.SwapTotalMB > 0 {
		addThresholdBreach("swap_high", snap.SwapPercent, "",
			fmt.Sprintf("[%s] Swap 交换空间占用达到 %.1f%%", srv.Name, snap.SwapPercent),
			fmt.Sprintf("Swap 已用 %d MB / 总计 %d MB", snap.SwapUsedMB, snap.SwapTotalMB),
		)
	}
	if snap.FDMax > 0 {
		addThresholdBreach("fd_high", snap.FDPercent, "",
			fmt.Sprintf("[%s] 内核文件句柄使用率 %.1f%%", srv.Name, snap.FDPercent),
			fmt.Sprintf("已分配 %d / 上限 %d", snap.FDUsed, snap.FDMax),
		)
	}

	// 3. Disk Partitions & Inodes
	diskChecked := false
	for _, d := range snap.Disks {
		diskChecked = true
		addThresholdBreach("disk_high", d.UsedPercent, d.MountPoint,
			fmt.Sprintf("[%s] 分区 %s 容量使用率 %.1f%%", srv.Name, d.MountPoint, d.UsedPercent),
			fmt.Sprintf("设备 %s (%s) 已用 %.1f GB / 总计 %.1f GB，剩余 %.1f GB", d.Device, d.FSType, d.UsedGB, d.TotalGB, d.AvailGB),
		)
		if d.InodePercent > 0 {
			addThresholdBreach("inode_high", d.InodePercent, d.MountPoint,
				fmt.Sprintf("[%s] 分区 %s Inode 占用率 %.1f%%", srv.Name, d.MountPoint, d.InodePercent),
				fmt.Sprintf("挂载点 %s (%s) Inode 节点即将耗尽", d.MountPoint, d.Device),
			)
		}
	}
	if !diskChecked && snap.DiskPercent > 0 {
		addThresholdBreach("disk_high", snap.DiskPercent, "/",
			fmt.Sprintf("[%s] 根分区容量使用率 %.1f%%", srv.Name, snap.DiskPercent),
			fmt.Sprintf("已用 %.1f GB / 总计 %.1f GB", snap.DiskUsedGB, snap.DiskTotalGB),
		)
	}

	// 4. Latency, Zombies, TCP Socket Accumulation, SSH Brute-Force, Temperature
	addThresholdBreach("latency_high", float64(snap.LatencyMs), "",
		fmt.Sprintf("[%s] SSH 探测响应延迟 %d ms", srv.Name, snap.LatencyMs),
		fmt.Sprintf("目标节点 %s:%d 握手与指令采样耗时偏高", srv.Host, srv.Port),
	)
	addThresholdBreach("zombie_procs", float64(snap.ProcsZombie), "",
		fmt.Sprintf("[%s] 存在 %d 个僵尸进程 (Zombie)", srv.Name, snap.ProcsZombie),
		fmt.Sprintf("总进程 %d，运行中 %d，阻塞 %d，僵尸 %d", snap.ProcsTotal, snap.ProcsRunning, snap.ProcsBlocked, snap.ProcsZombie),
	)
	abnormalTCP := snap.TCPCloseWait + snap.TCPSynRecv
	addThresholdBreach("tcp_close_wait", float64(abnormalTCP), "",
		fmt.Sprintf("[%s] TCP 半关闭/半连接套接字堆积 (%d 个)", srv.Name, abnormalTCP),
		fmt.Sprintf("CLOSE_WAIT=%d, SYN_RECV=%d, ESTABLISHED=%d, TIME_WAIT=%d", snap.TCPCloseWait, snap.TCPSynRecv, snap.TCPEstablished, snap.TCPTimeWait),
	)
	if snap.Security.SSHFailedRecent > 0 {
		ipHint := ""
		if len(snap.Security.TopFailedIPs) > 0 {
			ipHint = "，高频来源: " + strings.Join(snap.Security.TopFailedIPs, ", ")
		}
		addThresholdBreach("ssh_bruteforce", float64(snap.Security.SSHFailedRecent), "",
			fmt.Sprintf("[%s] 检测到 %d 次 SSH 登录失败尝试", srv.Name, snap.Security.SSHFailedRecent),
			fmt.Sprintf("近期安全认证日志捕获频繁失败记录%s", ipHint),
		)
	}
	if snap.CPUTempC > 0 {
		addThresholdBreach("temp_high", snap.CPUTempC, "",
			fmt.Sprintf("[%s] CPU 硬件温度达到 %.1f°C", srv.Name, snap.CPUTempC),
			"物理热传感器温度偏高，请检查机房散热或风扇状态",
		)
	}

	// 5. Systemd Failed Units & Explicitly Watched Services
	if r, ok := ruleMap["systemd_failed"]; ok {
		var downWatched []string
		for _, svc := range snap.Services {
			if svc.Watched && svc.State != "active" {
				downWatched = append(downWatched, fmt.Sprintf("%s(%s)", svc.Name, svc.State))
			}
		}
		if len(downWatched) > 0 {
			out = append(out, CandidateBreach{
				DedupKey:       fmt.Sprintf("%s|systemd_failed|watched", srv.ID),
				RuleKind:       "systemd_failed",
				RuleName:       r.Name,
				Severity:       SeverityCritical,
				Title:          fmt.Sprintf("[%s] 关键守护服务未运行: %s", srv.Name, strings.Join(downWatched, ", ")),
				Detail:         fmt.Sprintf("主机配置的必监服务处于非活跃状态：%s", strings.Join(downWatched, "、")),
				MetricText:     fmt.Sprintf("%d 个停止", len(downWatched)),
				ThresholdText:  "全部 active",
				ConsecutiveReq: max(1, r.ConsecutiveCount),
			})
		} else if snap.SystemdFailedCount > 0 {
			units := strings.Join(snap.SystemdFailedUnits, ", ")
			if units == "" {
				units = fmt.Sprintf("%d 个单元故障", snap.SystemdFailedCount)
			}
			out = append(out, CandidateBreach{
				DedupKey:       fmt.Sprintf("%s|systemd_failed|units", srv.ID),
				RuleKind:       "systemd_failed",
				RuleName:       r.Name,
				Severity:       SeverityWarning,
				Title:          fmt.Sprintf("[%s] Systemd 存在 %d 个故障服务单元", srv.Name, snap.SystemdFailedCount),
				Detail:         fmt.Sprintf("故障单元列表: %s", units),
				MetricText:     fmt.Sprintf("%d failed", snap.SystemdFailedCount),
				ThresholdText:  "0 failed",
				ConsecutiveReq: max(1, r.ConsecutiveCount),
			})
		}
	}

	// 6. Docker Unhealthy / Restarting Containers
	if r, ok := ruleMap["docker_unhealthy"]; ok && snap.Docker.Installed && snap.Docker.Unhealthy > 0 {
		var badNames []string
		for _, c := range snap.Docker.Containers {
			if c.Health == "unhealthy" || c.State == "restarting" || c.State == "dead" {
				badNames = append(badNames, fmt.Sprintf("%s(%s)", c.Name, c.Status))
			}
		}
		out = append(out, CandidateBreach{
			DedupKey:       fmt.Sprintf("%s|docker_unhealthy|", srv.ID),
			RuleKind:       "docker_unhealthy",
			RuleName:       r.Name,
			Severity:       SeverityWarning,
			Title:          fmt.Sprintf("[%s] %d 个 Docker 容器状态异常", srv.Name, snap.Docker.Unhealthy),
			Detail:         fmt.Sprintf("异常容器: %s", strings.Join(badNames, ", ")),
			MetricText:     fmt.Sprintf("%d 异常", snap.Docker.Unhealthy),
			ThresholdText:  "全部健康",
			ConsecutiveReq: max(1, r.ConsecutiveCount),
		})
	}

	// 7. Explicitly Watched Ports
	if r, ok := ruleMap["watched_port_down"]; ok && len(srv.WatchedPorts) > 0 && len(snap.ListeningPorts) > 0 {
		listeningSet := make(map[int]bool, len(snap.ListeningPorts))
		for _, lp := range snap.ListeningPorts {
			listeningSet[lp.Port] = true
		}
		var missing []string
		for _, wp := range srv.WatchedPorts {
			if !listeningSet[wp] {
				missing = append(missing, fmt.Sprintf("%d", wp))
			}
		}
		if len(missing) > 0 {
			out = append(out, CandidateBreach{
				DedupKey:       fmt.Sprintf("%s|watched_port_down|", srv.ID),
				RuleKind:       "watched_port_down",
				RuleName:       r.Name,
				Severity:       SeverityCritical,
				Title:          fmt.Sprintf("[%s] 关键业务端口未监听: %s", srv.Name, strings.Join(missing, ", ")),
				Detail:         fmt.Sprintf("主机配置的必监端口 [%s] 当前未处于 LISTEN 状态", strings.Join(missing, ", ")),
				MetricText:     fmt.Sprintf("%d 端口离线", len(missing)),
				ThresholdText:  "处于 LISTEN",
				ConsecutiveReq: max(1, r.ConsecutiveCount),
			})
		}
	}

	// 8. Newly Exposed Public Listening Ports (Baseline Drift)
	if r, ok := ruleMap["port_drift"]; ok && len(driftedPorts) > 0 {
		var desc []string
		for _, dp := range driftedPorts {
			proc := dp.Process
			if proc == "" {
				proc = "未知进程"
			}
			desc = append(desc, fmt.Sprintf("%s/%d (%s)", dp.Proto, dp.Port, proc))
		}
		out = append(out, CandidateBreach{
			DedupKey:       fmt.Sprintf("%s|port_drift|", srv.ID),
			RuleKind:       "port_drift",
			RuleName:       r.Name,
			Severity:       SeverityWarning,
			Title:          fmt.Sprintf("[%s] 发现 %d 个新暴露公网端口", srv.Name, len(driftedPorts)),
			Detail:         fmt.Sprintf("相较安全基线新增对外监听端口: %s（若属正常变更可在监控详情采纳基线）", strings.Join(desc, ", ")),
			MetricText:     fmt.Sprintf("+%d 端口", len(driftedPorts)),
			ThresholdText:  "匹配端口基线",
			ConsecutiveReq: max(1, r.ConsecutiveCount),
		})
	}

	return out
}

// ListAllServerConfigs returns deep copies of all ServerConfigs and monitor settings for scheduled monitoring.
func (s *Store) ListAllServerConfigs() ([]ServerConfig, MonitorSettings, error) {
	s.secMu.RLock()
	defer s.secMu.RUnlock()
	if s.secrets == nil {
		return nil, MonitorSettings{}, ErrVaultLocked
	}
	out := make([]ServerConfig, len(s.secrets.Servers))
	for i, srv := range s.secrets.Servers {
		cp := srv
		cp.Tags = slices.Clone(srv.Tags)
		cp.WatchedServices = slices.Clone(srv.WatchedServices)
		cp.WatchedPorts = slices.Clone(srv.WatchedPorts)
		out[i] = cp
	}
	return out, s.secrets.MonitorSettings, nil
}

// GetPreviousMonitorSnapshot returns a copy of the last recorded snapshot for rate delta calculation.
func (s *Store) GetPreviousMonitorSnapshot(serverID string) (*ServerMonitorSnapshot, error) {
	if !s.IsReady() {
		return nil, ErrVaultLocked
	}
	s.rtMu.RLock()
	defer s.rtMu.RUnlock()
	if s.monitorRT == nil {
		return nil, nil
	}
	return cloneSnapshot(s.monitorRT.LatestSnapshots[serverID]), nil
}

// RecordMonitorSnapshots persists collected server snapshots, time-series samples, alerts, port baselines,
// and per-server runtime metadata strictly into non-secret runtime state (monitor_runtime.json) with
// debounced atomic flushing. It NEVER rewrites secrets.enc or blocks credential operations.
func (s *Store) RecordMonitorSnapshots(snapshots []*ServerMonitorSnapshot) (triggered []MonitorAlert, resolved []MonitorAlert, webhookURL string, err error) {
	if len(snapshots) == 0 {
		return nil, nil, "", nil
	}

	s.secMu.RLock()
	if s.secrets == nil {
		s.secMu.RUnlock()
		return nil, nil, "", ErrVaultLocked
	}
	monSettings := s.secrets.MonitorSettings
	rules := slices.Clone(s.secrets.MonitorRules)
	autoSyncMem := s.secrets.AISettings.MemoryConfig.AutoSyncMonitorToMemory
	srvByID := make(map[string]ServerConfig, len(s.secrets.Servers))
	for _, srv := range s.secrets.Servers {
		cp := srv
		cp.WatchedServices = slices.Clone(srv.WatchedServices)
		cp.WatchedPorts = slices.Clone(srv.WatchedPorts)
		srvByID[srv.ID] = cp
	}
	s.secMu.RUnlock()

	webhookURL = monSettings.WebhookURL
	now := time.Now().UTC()

	s.rtMu.Lock()
	if s.monitorRT == nil {
		s.monitorRT = DefaultMonitorRuntimeState()
	}
	ensureMonitorRuntimeDefaults(s.monitorRT)
	mon := s.monitorRT

	if s.aiopsRT == nil {
		s.aiopsRT = DefaultAIOpsRuntimeState(now)
	}
	ensureAIOpsRuntimeDefaults(s.aiopsRT)

	aiMemChanged := false

	for _, rawIncoming := range snapshots {
		if rawIncoming == nil {
			continue
		}
		srvCfg, exists := srvByID[rawIncoming.ServerID]
		if !exists {
			continue
		}
		incoming := cloneSnapshot(rawIncoming)
		incoming.ServerName = srvCfg.Name
		incoming.Group = srvCfg.Group
		incoming.Host = srvCfg.Host
		incoming.Port = srvCfg.Port
		if incoming.CollectedAt.IsZero() {
			incoming.CollectedAt = now
		}

		// Mark watched ports on incoming snapshot
		if len(srvCfg.WatchedPorts) > 0 {
			for i := range incoming.ListeningPorts {
				if slices.Contains(srvCfg.WatchedPorts, incoming.ListeningPorts[i].Port) {
					incoming.ListeningPorts[i].Watched = true
				}
			}
		}

		// Port baseline comparison
		var driftedPorts []ListeningPortStat
		if incoming.Reachable && monSettings.CollectPortsAndServices && len(incoming.ListeningPorts) > 0 {
			curPublicKeys := extractPublicPortKeys(incoming.ListeningPorts)
			baseKeys, hasBaseline := mon.PortBaselines[srvCfg.ID]
			if !hasBaseline {
				mon.PortBaselines[srvCfg.ID] = curPublicKeys
			} else if monSettings.DetectPortDrift {
				baseSet := make(map[string]bool, len(baseKeys))
				for _, k := range baseKeys {
					baseSet[k] = true
				}
				for _, lp := range incoming.ListeningPorts {
					if !lp.PublicExposed || lp.Port <= 0 {
						continue
					}
					proto := "tcp"
					if strings.HasPrefix(strings.ToLower(lp.Proto), "udp") {
						proto = "udp"
					}
					key := fmt.Sprintf("%s/%d", proto, lp.Port)
					if !baseSet[key] {
						driftedPorts = append(driftedPorts, lp)
					}
				}
			}
		}

		// Evaluate breaches & health score
		breaches := evaluateSnapshotRules(incoming, srvCfg, rules, driftedPorts)
		ComputeSnapshotHealth(incoming, breaches)
		*rawIncoming = *cloneSnapshot(incoming)

		// Update lightweight per-server runtime metadata strictly inside monitor_runtime.json
		if incoming.Reachable {
			meta := mon.ServerRuntime[srvCfg.ID]
			if incoming.LatencyMs > 0 {
				meta.LastLatencyMs = incoming.LatencyMs
			}
			osLabel := strings.TrimSpace(incoming.OS)
			if osLabel == "" && incoming.Kernel != "" {
				osLabel = "Linux " + incoming.Kernel
			}
			if osLabel != "" {
				meta.LastOSInfo = osLabel
			}
			mon.ServerRuntime[srvCfg.ID] = meta

			if autoSyncMem {
				if mergeMonitorSnapshotIntoHostMemorySlice(&s.aiopsRT.HostMemories, incoming, now) {
					aiMemChanged = true
				}
			}
		}

		// Persist latest snapshot & compact ring-buffered sample
		mon.LatestSnapshots[srvCfg.ID] = cloneSnapshot(incoming)
		series := append(mon.HistoryByServer[srvCfg.ID], incoming.ToSamplePoint())
		maxPts := monSettings.RetentionPoints
		if maxPts < 30 {
			maxPts = 30
		}
		if len(series) > maxPts {
			series = slices.Clone(series[len(series)-maxPts:])
		}
		mon.HistoryByServer[srvCfg.ID] = series

		// Update breach streaks & firing/resolved alerts for this server
		activeBreachMap := make(map[string]CandidateBreach, len(breaches))
		for _, b := range breaches {
			activeBreachMap[b.DedupKey] = b
			mon.BreachStreaks[b.DedupKey]++
			if mon.BreachStreaks[b.DedupKey] < b.ConsecutiveReq {
				continue
			}

			foundExisting := false
			for idx := range mon.Alerts {
				al := &mon.Alerts[idx]
				if al.DedupKey == b.DedupKey && al.Status != AlertStatusResolved {
					al.LastSeenAt = incoming.CollectedAt
					al.Occurrences++
					al.ServerName = srvCfg.Name
					al.Host = fmt.Sprintf("%s:%d", srvCfg.Host, srvCfg.Port)
					al.Title = b.Title
					al.Detail = b.Detail
					al.MetricText = b.MetricText
					al.ThresholdText = b.ThresholdText
					if b.Severity == SeverityCritical && al.Severity != SeverityCritical {
						al.Severity = SeverityCritical
					}
					foundExisting = true
					break
				}
			}
			if !foundExisting {
				newAlert := MonitorAlert{
					ID:            uuid.NewString(),
					DedupKey:      b.DedupKey,
					ServerID:      srvCfg.ID,
					ServerName:    srvCfg.Name,
					Host:          fmt.Sprintf("%s:%d", srvCfg.Host, srvCfg.Port),
					RuleKind:      b.RuleKind,
					RuleName:      b.RuleName,
					Severity:      b.Severity,
					Status:        AlertStatusFiring,
					Title:         b.Title,
					Detail:        b.Detail,
					MetricText:    b.MetricText,
					ThresholdText: b.ThresholdText,
					Occurrences:   mon.BreachStreaks[b.DedupKey],
					TriggeredAt:   incoming.CollectedAt,
					LastSeenAt:    incoming.CollectedAt,
				}
				mon.Alerts = append([]MonitorAlert{newAlert}, mon.Alerts...)
				triggered = append(triggered, newAlert)
			}
		}

		// Clear non-breached streaks for this server
		prefix := srvCfg.ID + "|"
		for k := range mon.BreachStreaks {
			if strings.HasPrefix(k, prefix) {
				if _, stillBreached := activeBreachMap[k]; !stillBreached {
					if incoming.Reachable || strings.HasPrefix(k, srvCfg.ID+"|offline|") {
						delete(mon.BreachStreaks, k)
					}
				}
			}
		}

		// Auto-resolve active alerts whose condition has recovered
		for idx := range mon.Alerts {
			al := &mon.Alerts[idx]
			if al.ServerID != srvCfg.ID || al.Status == AlertStatusResolved {
				continue
			}
			if _, stillBreached := activeBreachMap[al.DedupKey]; stillBreached {
				continue
			}
			if !incoming.Reachable && al.RuleKind != "offline" {
				continue
			}
			resTime := incoming.CollectedAt
			al.Status = AlertStatusResolved
			al.ResolvedAt = &resTime
			al.LastSeenAt = resTime
			resolved = append(resolved, *al)
		}
	}

	// Enforce MaxAlertRecords cap while keeping active alerts intact
	maxAlerts := monSettings.MaxAlertRecords
	if maxAlerts < 50 {
		maxAlerts = 50
	}
	if len(mon.Alerts) > maxAlerts {
		trimmed := make([]MonitorAlert, 0, maxAlerts)
		for _, a := range mon.Alerts {
			if a.Status != AlertStatusResolved && len(trimmed) < maxAlerts {
				trimmed = append(trimmed, a)
			}
		}
		for _, a := range mon.Alerts {
			if a.Status == AlertStatusResolved && len(trimmed) < maxAlerts {
				trimmed = append(trimmed, a)
			}
		}
		sort.SliceStable(trimmed, func(i, j int) bool {
			return trimmed[i].TriggeredAt.After(trimmed[j].TriggeredAt)
		})
		mon.Alerts = trimmed
	}

	s.dirtyMonitor = true
	if aiMemChanged {
		s.dirtyAIOps = true
	}
	s.rtMu.Unlock()
	s.triggerFlush()
	return triggered, resolved, webhookURL, nil
}

// GetMonitorOverview builds the fleet monitoring dashboard state by joining server configs with runtime telemetry.
func (s *Store) GetMonitorOverview() (*MonitorOverviewData, error) {
	s.secMu.RLock()
	if s.secrets == nil {
		s.secMu.RUnlock()
		return nil, ErrVaultLocked
	}
	monSettings := s.secrets.MonitorSettings
	serverViews := make([]ServerView, len(s.secrets.Servers))
	for i, srv := range s.secrets.Servers {
		serverViews[i] = srv.ToView()
	}
	s.secMu.RUnlock()

	s.rtMu.RLock()
	defer s.rtMu.RUnlock()
	mon := s.monitorRT
	if mon == nil {
		mon = DefaultMonitorRuntimeState()
	}

	activeAlertsBySrv := make(map[string]int)
	var kpi FleetMonitorKPI
	kpi.TotalServers = len(serverViews)

	for _, al := range mon.Alerts {
		if al.Status != AlertStatusResolved {
			kpi.FiringAlerts++
			activeAlertsBySrv[al.ServerID]++
			if al.Severity == SeverityCritical {
				kpi.CriticalAlerts++
			} else {
				kpi.WarningAlerts++
			}
		}
	}

	nodes := make([]ServerMonitorCardItem, 0, len(serverViews))
	var sumScore int
	var sumCPU, sumMem, sumDisk float64
	var sumLat int64

	for _, view := range serverViews {
		if meta, ok := mon.ServerRuntime[view.ID]; ok {
			applyServerRuntimeMeta(&view, meta)
		}
		if view.MonitorEnabled {
			kpi.MonitoredServers++
		}
		snap := cloneSnapshot(mon.LatestSnapshots[view.ID])
		fullSeries := mon.HistoryByServer[view.ID]
		kpi.TotalSamples += len(fullSeries)

		sparkStart := 0
		if len(fullSeries) > 30 {
			sparkStart = len(fullSeries) - 30
		}
		spark := slices.Clone(fullSeries[sparkStart:])
		if spark == nil {
			spark = []MonitorSamplePoint{}
		}
		sla := computeSLA(fullSeries)

		if snap == nil {
			kpi.UnknownServers++
		} else if !snap.Reachable {
			kpi.OfflineServers++
		} else {
			kpi.OnlineServers++
			sumScore += snap.HealthScore
			sumCPU += snap.CPUPercent
			sumMem += snap.MemPercent
			dPct := snap.MaxPartPercent
			if dPct <= 0 {
				dPct = snap.DiskPercent
			}
			sumDisk += dPct
			sumLat += snap.LatencyMs
			kpi.TotalNetRxBps += snap.NetRxBps
			kpi.TotalNetTxBps += snap.NetTxBps
			kpi.TotalDiskReadBps += snap.DiskReadBps
			kpi.TotalDiskWriteBps += snap.DiskWriteBps

			switch snap.HealthLevel {
			case HealthCritical:
				kpi.CriticalServers++
			case HealthWarning:
				kpi.WarningServers++
			default:
				kpi.HealthyServers++
			}
		}

		nodes = append(nodes, ServerMonitorCardItem{
			Server:       view,
			Snapshot:     snap,
			Sparkline:    spark,
			SLA:          sla,
			ActiveAlerts: activeAlertsBySrv[view.ID],
		})
	}

	levelRank := func(item ServerMonitorCardItem) int {
		if item.Snapshot == nil {
			return 3
		}
		switch item.Snapshot.HealthLevel {
		case HealthCritical:
			return 0
		case HealthOffline:
			return 1
		case HealthWarning:
			return 2
		default:
			return 4
		}
	}
	sort.SliceStable(nodes, func(i, j int) bool {
		if nodes[i].Server.Pinned != nodes[j].Server.Pinned {
			return nodes[i].Server.Pinned
		}
		ri, rj := levelRank(nodes[i]), levelRank(nodes[j])
		if ri != rj {
			return ri < rj
		}
		return nodes[i].Server.Name < nodes[j].Server.Name
	})

	if kpi.OnlineServers > 0 {
		kpi.AvgHealthScore = sumScore / kpi.OnlineServers
		kpi.AvgCPUPercent = round1(sumCPU / float64(kpi.OnlineServers))
		kpi.AvgMemPercent = round1(sumMem / float64(kpi.OnlineServers))
		kpi.AvgDiskPercent = round1(sumDisk / float64(kpi.OnlineServers))
		kpi.AvgLatencyMs = sumLat / int64(kpi.OnlineServers)
	}

	alertLimit := min(100, len(mon.Alerts))
	alertsOut := slices.Clone(mon.Alerts[:alertLimit])
	if alertsOut == nil {
		alertsOut = []MonitorAlert{}
	}

	return &MonitorOverviewData{
		Settings: monSettings,
		KPI:      kpi,
		Nodes:    nodes,
		Alerts:   alertsOut,
	}, nil
}

// GetServerMonitorDetail returns deep snapshot, time-filtered historical series, SLA, and alerts for one server.
func (s *Store) GetServerMonitorDetail(serverID string, rangeDur time.Duration) (*ServerMonitorDetail, error) {
	s.secMu.RLock()
	if s.secrets == nil {
		s.secMu.RUnlock()
		return nil, ErrVaultLocked
	}
	var targetView *ServerView
	for i := range s.secrets.Servers {
		if s.secrets.Servers[i].ID == serverID {
			v := s.secrets.Servers[i].ToView()
			targetView = &v
			break
		}
	}
	s.secMu.RUnlock()
	if targetView == nil {
		return nil, ErrNotFound
	}

	s.rtMu.RLock()
	defer s.rtMu.RUnlock()
	mon := s.monitorRT
	if mon == nil {
		mon = DefaultMonitorRuntimeState()
	}

	if meta, ok := mon.ServerRuntime[serverID]; ok {
		applyServerRuntimeMeta(targetView, meta)
	}

	snap := cloneSnapshot(mon.LatestSnapshots[serverID])
	allPoints := mon.HistoryByServer[serverID]

	var filtered []MonitorSamplePoint
	if rangeDur > 0 && len(allPoints) > 0 {
		cutoff := time.Now().UTC().Add(-rangeDur)
		for _, pt := range allPoints {
			if !pt.Timestamp.Before(cutoff) {
				filtered = append(filtered, pt)
			}
		}
	} else {
		filtered = slices.Clone(allPoints)
	}
	if filtered == nil {
		filtered = []MonitorSamplePoint{}
	}

	var srvAlerts []MonitorAlert
	for _, al := range mon.Alerts {
		if al.ServerID == serverID {
			srvAlerts = append(srvAlerts, al)
		}
	}
	if srvAlerts == nil {
		srvAlerts = []MonitorAlert{}
	}

	baseline := slices.Clone(mon.PortBaselines[serverID])
	if baseline == nil {
		baseline = []string{}
	}

	return &ServerMonitorDetail{
		Server:       *targetView,
		Snapshot:     snap,
		Series:       filtered,
		SLA:          computeSLA(filtered),
		PortBaseline: baseline,
		Alerts:       srvAlerts,
	}, nil
}

// GetMonitorPolicy returns current monitor settings and alert rules from secrets.enc.
func (s *Store) GetMonitorPolicy() (MonitorSettings, []MonitorAlertRule, error) {
	s.secMu.RLock()
	defer s.secMu.RUnlock()
	if s.secrets == nil {
		return MonitorSettings{}, nil, ErrVaultLocked
	}
	return s.secrets.MonitorSettings, slices.Clone(s.secrets.MonitorRules), nil
}

// UpdateMonitorPolicy validates and saves updated schedule settings and alert rules.
func (s *Store) UpdateMonitorPolicy(settings MonitorSettings, rules []MonitorAlertRule, clientIP string) (MonitorSettings, []MonitorAlertRule, error) {
	var outSettings MonitorSettings
	var outRules []MonitorAlertRule
	err := s.mutateSecrets(func(sec *SecretsState) error {
		sec.MonitorSettings = sanitizeMonitorSettings(settings)
		if len(rules) > 0 {
			sec.MonitorRules = mergeMonitorAlertRules(rules)
		}
		outSettings = sec.MonitorSettings
		outRules = slices.Clone(sec.MonitorRules)
		return nil
	})
	if err != nil {
		return MonitorSettings{}, nil, err
	}

	// Trim existing runtime series if RetentionPoints was lowered
	s.rtMu.Lock()
	if s.monitorRT != nil {
		trimmed := false
		for sid, pts := range s.monitorRT.HistoryByServer {
			if len(pts) > outSettings.RetentionPoints {
				s.monitorRT.HistoryByServer[sid] = slices.Clone(pts[len(pts)-outSettings.RetentionPoints:])
				trimmed = true
			}
		}
		if trimmed {
			s.dirtyMonitor = true
		}
	}
	s.appendAuditRuntimeLocked("monitor.policy_update", "monitor", fmt.Sprintf("更新状态监控策略 (周期 %ds, 保留 %d 点)", outSettings.IntervalSec, outSettings.RetentionPoints), clientIP, true)
	s.rtMu.Unlock()
	s.triggerFlush()
	return outSettings, outRules, nil
}

// ListMonitorAlerts returns filtered alert incidents.
func (s *Store) ListMonitorAlerts(statusFilter, serverID string, limit int) ([]MonitorAlert, error) {
	if !s.IsReady() {
		return nil, ErrVaultLocked
	}
	s.rtMu.RLock()
	defer s.rtMu.RUnlock()
	mon := s.monitorRT
	if mon == nil {
		return []MonitorAlert{}, nil
	}

	var out []MonitorAlert
	for _, al := range mon.Alerts {
		if serverID != "" && al.ServerID != serverID {
			continue
		}
		switch statusFilter {
		case "active":
			if al.Status == AlertStatusResolved {
				continue
			}
		case string(AlertStatusFiring), string(AlertStatusAcknowledged), string(AlertStatusResolved):
			if string(al.Status) != statusFilter {
				continue
			}
		}
		out = append(out, al)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	if out == nil {
		out = []MonitorAlert{}
	}
	return out, nil
}

// AcknowledgeMonitorAlert marks an active firing alert as acknowledged (runtime-only, never touches secrets.enc).
func (s *Store) AcknowledgeMonitorAlert(alertID, clientIP string) (*MonitorAlert, error) {
	if !s.IsReady() {
		return nil, ErrVaultLocked
	}

	s.rtMu.Lock()
	if s.monitorRT == nil {
		s.rtMu.Unlock()
		return nil, ErrNotFound
	}
	for i := range s.monitorRT.Alerts {
		al := &s.monitorRT.Alerts[i]
		if al.ID == alertID {
			if al.Status == AlertStatusFiring {
				now := time.Now().UTC()
				al.Status = AlertStatusAcknowledged
				al.AcknowledgedAt = &now
				s.dirtyMonitor = true
				s.appendAuditRuntimeLocked("monitor.alert_ack", al.ServerName, al.Title, clientIP, true)
			}
			cp := *al
			s.rtMu.Unlock()
			s.triggerFlush()
			return &cp, nil
		}
	}
	s.rtMu.Unlock()
	return nil, ErrNotFound
}

// ClearResolvedMonitorAlerts removes all resolved alert incidents (runtime-only).
func (s *Store) ClearResolvedMonitorAlerts(clientIP string) (int, error) {
	if !s.IsReady() {
		return 0, ErrVaultLocked
	}

	s.rtMu.Lock()
	if s.monitorRT == nil {
		s.rtMu.Unlock()
		return 0, nil
	}
	before := len(s.monitorRT.Alerts)
	kept := make([]MonitorAlert, 0, before)
	for _, al := range s.monitorRT.Alerts {
		if al.Status != AlertStatusResolved {
			kept = append(kept, al)
		}
	}
	removed := before - len(kept)
	if removed > 0 {
		s.monitorRT.Alerts = kept
		s.dirtyMonitor = true
		s.appendAuditRuntimeLocked("monitor.alerts_clear", "alerts", fmt.Sprintf("清理已恢复历史告警 %d 条", removed), clientIP, true)
	}
	s.rtMu.Unlock()
	if removed > 0 {
		s.triggerFlush()
	}
	return removed, nil
}

// AcceptServerPortBaseline pins the server's current public listening ports as its trusted port baseline.
func (s *Store) AcceptServerPortBaseline(serverID, clientIP string) ([]string, error) {
	if !s.IsReady() {
		return nil, ErrVaultLocked
	}

	s.rtMu.Lock()
	if s.monitorRT == nil {
		s.rtMu.Unlock()
		return nil, ErrNotFound
	}
	snap := s.monitorRT.LatestSnapshots[serverID]
	if snap == nil {
		s.rtMu.Unlock()
		return nil, ErrNotFound
	}
	newBase := extractPublicPortKeys(snap.ListeningPorts)
	s.monitorRT.PortBaselines[serverID] = newBase
	delete(s.monitorRT.BreachStreaks, fmt.Sprintf("%s|port_drift|", serverID))

	now := time.Now().UTC()
	for i := range s.monitorRT.Alerts {
		al := &s.monitorRT.Alerts[i]
		if al.ServerID == serverID && al.RuleKind == "port_drift" && al.Status != AlertStatusResolved {
			al.Status = AlertStatusResolved
			al.ResolvedAt = &now
		}
	}
	s.dirtyMonitor = true
	s.appendAuditRuntimeLocked("monitor.port_baseline", snap.ServerName, fmt.Sprintf("确认并更新公网监听端口安全基线 (%d 个端口)", len(newBase)), clientIP, true)
	outBase := slices.Clone(newBase)
	s.rtMu.Unlock()
	s.triggerFlush()
	return outBase, nil
}

// ClearMonitorHistory purges historical monitoring records for one server or all servers.
func (s *Store) ClearMonitorHistory(serverID, clientIP string) error {
	if !s.IsReady() {
		return ErrVaultLocked
	}

	s.rtMu.Lock()
	if s.monitorRT != nil {
		if serverID != "" {
			delete(s.monitorRT.HistoryByServer, serverID)
			delete(s.monitorRT.LatestSnapshots, serverID)
			s.appendAuditRuntimeLocked("monitor.history_clear", serverID, "清空单台主机历史监控时序数据", clientIP, true)
		} else {
			clear(s.monitorRT.HistoryByServer)
			clear(s.monitorRT.LatestSnapshots)
			clear(s.monitorRT.BreachStreaks)
			s.appendAuditRuntimeLocked("monitor.history_clear", "all", "清空全部服务器历史监控时序数据", clientIP, true)
		}
		s.dirtyMonitor = true
	}
	s.rtMu.Unlock()
	s.triggerFlush()
	return nil
}


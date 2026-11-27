package vault

import (
	"fmt"
	"maps"
	"math"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// FleetMonitorKPI summarizes cluster-wide health and telemetry across all managed servers.
type FleetMonitorKPI struct {
	TotalServers      int     `json:"total_servers"`
	MonitoredServers  int     `json:"monitored_servers"`
	OnlineServers     int     `json:"online_servers"`
	HealthyServers    int     `json:"healthy_servers"`
	WarningServers    int     `json:"warning_servers"`
	CriticalServers   int     `json:"critical_servers"`
	OfflineServers    int     `json:"offline_servers"`
	UnknownServers    int     `json:"unknown_servers"`
	AvgHealthScore    int     `json:"avg_health_score"`
	AvgCPUPercent     float64 `json:"avg_cpu_percent"`
	AvgMemPercent     float64 `json:"avg_mem_percent"`
	AvgDiskPercent    float64 `json:"avg_disk_percent"`
	AvgLatencyMs      int64   `json:"avg_latency_ms"`
	TotalNetRxBps     int64   `json:"total_net_rx_bps"`
	TotalNetTxBps     int64   `json:"total_net_tx_bps"`
	TotalDiskReadBps  int64   `json:"total_disk_read_bps"`
	TotalDiskWriteBps int64   `json:"total_disk_write_bps"`
	FiringAlerts      int     `json:"firing_alerts"`
	CriticalAlerts    int     `json:"critical_alerts"`
	WarningAlerts     int     `json:"warning_alerts"`
	TotalSamples      int     `json:"total_samples"`
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

// ServerMonitorDetail holds full historical time-series, deep latest snapshot, SLA, baselines, and alerts for one server.
type ServerMonitorDetail struct {
	Server           ServerView              `json:"server"`
	Snapshot         *ServerMonitorSnapshot  `json:"snapshot,omitempty"`
	Series           []MonitorSamplePoint    `json:"series"`
	SLA              ServerSLASummary        `json:"sla"`
	PortBaseline     []string                `json:"port_baseline"`
	SecurityBaseline *ServerSecurityBaseline `json:"security_baseline,omitempty"`
	Alerts           []MonitorAlert          `json:"alerts"`
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
	if in.SlowIntervalSec <= 0 {
		in.SlowIntervalSec = 300
	} else if in.SlowIntervalSec < 60 {
		in.SlowIntervalSec = 60
	} else if in.SlowIntervalSec > 3600 {
		in.SlowIntervalSec = 3600
	}
	if in.SlowIntervalSec < in.IntervalSec {
		in.SlowIntervalSec = min(3600, max(60, in.IntervalSec))
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
	in.PortDriftIgnoreProcesses = SanitizePortDriftProcessPatterns(in.PortDriftIgnoreProcesses)
	in.PortDriftIgnorePorts = SanitizePortDriftPortSpecs(in.PortDriftIgnorePorts)
	in.PolicyVersion = CurrentMonitorPolicyVersion
	return cloneMonitorSettings(in)
}

func validateMonitorSettings(in MonitorSettings) error {
	if _, err := ValidatePortDriftProcessPatternsStrict(in.PortDriftIgnoreProcesses); err != nil {
		return err
	}
	if _, err := ValidatePortDriftPortSpecsStrict(in.PortDriftIgnorePorts); err != nil {
		return err
	}
	return nil
}

func validateMonitorAlertRules(rules []MonitorAlertRule) error {
	defaults := DefaultMonitorAlertRules()
	defByKind := make(map[string]MonitorAlertRule, len(defaults))
	for _, d := range defaults {
		defByKind[d.Kind] = d
	}
	for _, r := range rules {
		def, ok := defByKind[r.Kind]
		if !ok || def.StateBased {
			continue
		}
		if r.WarningThreshold < 0 || r.CriticalThreshold < 0 {
			return fmt.Errorf("%w: 规则「%s」的阈值不能为负数", ErrInvalidInput, def.Name)
		}
		if r.WarningThreshold > 0 && r.CriticalThreshold > 0 {
			if def.LowerIsWorse {
				if r.CriticalThreshold > r.WarningThreshold {
					return fmt.Errorf("%w: 规则「%s」的严重阈值 (%.1f%s) 不能高于警告阈值 (%.1f%s)",
						ErrInvalidInput, def.Name, r.CriticalThreshold, def.Unit, r.WarningThreshold, def.Unit)
				}
			} else if r.WarningThreshold > r.CriticalThreshold {
				return fmt.Errorf("%w: 规则「%s」的警告阈值 (%.1f%s) 不能高于严重阈值 (%.1f%s)",
					ErrInvalidInput, def.Name, r.WarningThreshold, def.Unit, r.CriticalThreshold, def.Unit)
			}
		}
	}
	return nil
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
			ex.Category = def.Category
			ex.Name = def.Name
			ex.Description = def.Description
			ex.Unit = def.Unit
			ex.StateBased = def.StateBased
			ex.LowerIsWorse = def.LowerIsWorse
			if ex.ConsecutiveCount < 1 {
				ex.ConsecutiveCount = 1
			} else if ex.ConsecutiveCount > 20 {
				ex.ConsecutiveCount = 20
			}
			if !def.StateBased {
				if ex.WarningThreshold < 0 {
					ex.WarningThreshold = 0
				}
				if ex.CriticalThreshold < 0 {
					ex.CriticalThreshold = 0
				}
				if ex.WarningThreshold > 0 && ex.CriticalThreshold > 0 {
					if def.LowerIsWorse && ex.CriticalThreshold > ex.WarningThreshold {
						ex.WarningThreshold = ex.CriticalThreshold
					} else if !def.LowerIsWorse && ex.WarningThreshold > ex.CriticalThreshold {
						ex.CriticalThreshold = ex.WarningThreshold
					}
				}
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
		if m.Settings.PolicyVersion < 2 {
			if m.Settings.SlowIntervalSec <= 0 {
				m.Settings.SlowIntervalSec = 300
			}
			m.Settings.UseSSHConnectionPool = true
		}
		if m.Settings.PolicyVersion < 3 {
			m.Settings.PortDriftIgnoreEphemeralUDP = true
			if len(m.Settings.PortDriftIgnoreProcesses) == 0 {
				m.Settings.PortDriftIgnoreProcesses = DefaultPortDriftIgnoreProcesses()
			}
		}
		m.Settings.PolicyVersion = CurrentMonitorPolicyVersion
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
	if m.SecurityBaselines == nil {
		m.SecurityBaselines = make(map[string]ServerSecurityBaseline)
	}
	m.Rules = mergeMonitorAlertRules(m.Rules)
}

func cloneSecurityBaseline(in ServerSecurityBaseline) ServerSecurityBaseline {
	cp := ServerSecurityBaseline{
		PersistenceHash:  in.PersistenceHash,
		KnownSSHLoginIPs: slices.Clone(in.KnownSSHLoginIPs),
		UpdatedAt:        in.UpdatedAt,
	}
	if in.FileHashes != nil {
		cp.FileHashes = make(map[string]string, len(in.FileHashes))
		maps.Copy(cp.FileHashes, in.FileHashes)
	}
	return cp
}

func cloneSnapshot(in *ServerMonitorSnapshot) *ServerMonitorSnapshot {
	if in == nil {
		return nil
	}
	cp := *in
	if in.LastSlowCollectedAt != nil {
		t := *in.LastSlowCollectedAt
		cp.LastSlowCollectedAt = &t
	}
	cp.RawCPUTicks = slices.Clone(in.RawCPUTicks)
	cp.Disks = slices.Clone(in.Disks)
	cp.ReadOnlyMounts = slices.Clone(in.ReadOnlyMounts)
	cp.RemoteMounts = slices.Clone(in.RemoteMounts)
	cp.RAIDDegraded = slices.Clone(in.RAIDDegraded)
	cp.KernelErrors = slices.Clone(in.KernelErrors)
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
	if in.Security.FileHashes != nil {
		cp.Security.FileHashes = make(map[string]string, len(in.Security.FileHashes))
		maps.Copy(cp.Security.FileHashes, in.Security.FileHashes)
	}
	cp.Security.FileDrifts = slices.Clone(in.Security.FileDrifts)
	cp.Security.PersistenceDrifts = slices.Clone(in.Security.PersistenceDrifts)
	cp.Security.SuspiciousProcs = slices.Clone(in.Security.SuspiciousProcs)
	cp.Security.SuspiciousOutbound = slices.Clone(in.Security.SuspiciousOutbound)
	cp.Security.RecentSSHLogins = slices.Clone(in.Security.RecentSSHLogins)
	cp.Security.NewSSHLoginIPs = slices.Clone(in.Security.NewSSHLoginIPs)
	cp.Security.SSHWeakConfigs = slices.Clone(in.Security.SSHWeakConfigs)
	return &cp
}

func cloneMonitorVaultData(in *MonitorVaultData) *MonitorVaultData {
	if in == nil {
		return nil
	}
	cp := &MonitorVaultData{
		Settings:          cloneMonitorSettings(in.Settings),
		Rules:             slices.Clone(in.Rules),
		LatestSnapshots:   make(map[string]*ServerMonitorSnapshot, len(in.LatestSnapshots)),
		HistoryByServer:   make(map[string][]MonitorSamplePoint, len(in.HistoryByServer)),
		Alerts:            make([]MonitorAlert, len(in.Alerts)),
		BreachStreaks:     make(map[string]int, len(in.BreachStreaks)),
		PortBaselines:     make(map[string][]string, len(in.PortBaselines)),
		SecurityBaselines: make(map[string]ServerSecurityBaseline, len(in.SecurityBaselines)),
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
	for k, v := range in.SecurityBaselines {
		cp.SecurityBaselines[k] = cloneSecurityBaseline(v)
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

// computeDiskWillFillForecast performs deterministic OLS linear regression on recent reachable
// disk history points to estimate hours until 100% capacity with zero remote SSH overhead.
func computeDiskWillFillForecast(history []MonitorSamplePoint, curPoint MonitorSamplePoint) float64 {
	if !curPoint.Reachable || curPoint.DiskPercent < 50.0 || curPoint.DiskPercent >= 100.0 {
		return 0
	}
	cutoff := curPoint.Timestamp.Add(-6 * time.Hour)
	pts := make([]MonitorSamplePoint, 0, min(len(history)+1, 128))
	for _, p := range history {
		if p.Reachable && p.DiskPercent > 0 && !p.Timestamp.Before(cutoff) && !p.Timestamp.After(curPoint.Timestamp) {
			pts = append(pts, p)
		}
	}
	pts = append(pts, curPoint)
	if len(pts) < 10 {
		return 0
	}
	firstTS := pts[0].Timestamp
	spanHours := curPoint.Timestamp.Sub(firstTS).Hours()
	if spanHours < (10.0 / 60.0) { // require >= 10 minutes span to prevent burst noise
		return 0
	}

	var sumX, sumY float64
	n := float64(len(pts))
	xs := make([]float64, len(pts))
	ys := make([]float64, len(pts))
	for i, p := range pts {
		x := p.Timestamp.Sub(firstTS).Hours()
		y := p.DiskPercent
		xs[i] = x
		ys[i] = y
		sumX += x
		sumY += y
	}
	meanX := sumX / n
	meanY := sumY / n

	var sxx, sxy, syy float64
	for i := range xs {
		dx := xs[i] - meanX
		dy := ys[i] - meanY
		sxx += dx * dx
		sxy += dx * dy
		syy += dy * dy
	}
	if sxx <= 1e-9 || syy <= 1e-9 {
		return 0
	}
	slopePerHour := sxy / sxx
	if slopePerHour < 0.5 { // ignore negligible <0.5%/hour drift
		return 0
	}
	r2 := (sxy * sxy) / (sxx * syy)
	if r2 < 0.5 { // require steady upward trend rather than random oscillations
		return 0
	}
	remaining := 100.0 - curPoint.DiskPercent
	hours := remaining / slopePerHour
	if hours <= 0 || math.IsNaN(hours) || math.IsInf(hours, 0) || hours > 720 {
		return 0
	}
	return round1(hours)
}

// ComputeSnapshotHealth calculates the 0-100 health score and classification for a snapshot.
// Callers must pass only debounced/effective breaches so HealthLevel aligns strictly with active alerts.
func ComputeSnapshotHealth(snap *ServerMonitorSnapshot, effectiveBreaches []CandidateBreach) {
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
	if snap.CPUStealPct > 10 {
		score -= (snap.CPUStealPct - 10) * 0.6
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
	if snap.ProcsBlocked > 2 {
		score -= math.Min(15, float64(snap.ProcsBlocked-2)*2.0)
	}
	if snap.SystemdFailedCount > 0 {
		score -= math.Min(20, float64(snap.SystemdFailedCount)*7)
	}
	if snap.Docker.Unhealthy > 0 || snap.Docker.ExitedAbnormal > 0 {
		score -= math.Min(18, float64(snap.Docker.Unhealthy+snap.Docker.ExitedAbnormal)*8)
	}
	if snap.Docker.DaemonDown {
		score -= 20
	}
	if len(snap.ReadOnlyMounts) > 0 || len(snap.RAIDDegraded) > 0 {
		score -= 30
	}
	if snap.OOMKillsDelta > 0 {
		score -= 20
	}
	if snap.LatencyMs > 300 {
		score -= math.Min(12, float64(snap.LatencyMs-300)/80.0)
	}

	hasCrit := false
	hasWarn := false
	for _, b := range effectiveBreaches {
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
	return ExtractEligiblePublicPortKeys(ports)
}

func isRuleSuppressedByCollectionToggles(ruleKind string, settings MonitorSettings) bool {
	switch ruleKind {
	case "zombie_procs", "blocked_procs":
		return !settings.CollectProcesses
	case "systemd_failed", "docker_unhealthy", "watched_port_down":
		return !settings.CollectPortsAndServices
	case "port_drift":
		return !settings.CollectPortsAndServices || !settings.DetectPortDrift
	case "ssh_bruteforce", "uid_zero_backdoor", "firewall_inactive", "security_file_drift",
		"suspicious_process", "suspicious_outbound", "ssh_new_login_ip":
		return !settings.CollectSecurity
	default:
		return false
	}
}

func evaluateSnapshotRules(
	snap *ServerMonitorSnapshot,
	srv ServerConfig,
	settings MonitorSettings,
	rules []MonitorAlertRule,
	driftedPorts []ListeningPortStat,
) []CandidateBreach {
	ruleMap := make(map[string]MonitorAlertRule, len(rules))
	for _, r := range rules {
		if r.Enabled && !isRuleSuppressedByCollectionToggles(r.Kind, settings) {
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
		if r.LowerIsWorse {
			if val <= 0 {
				return
			}
			if r.CriticalThreshold > 0 && val <= r.CriticalThreshold {
				sev = SeverityCritical
				thresh = r.CriticalThreshold
			} else if r.WarningThreshold > 0 && val <= r.WarningThreshold {
				sev = SeverityWarning
				thresh = r.WarningThreshold
			} else {
				return
			}
		} else {
			if r.CriticalThreshold > 0 && val >= r.CriticalThreshold {
				sev = SeverityCritical
				thresh = r.CriticalThreshold
			} else if r.WarningThreshold > 0 && val >= r.WarningThreshold {
				sev = SeverityWarning
				thresh = r.WarningThreshold
			} else {
				return
			}
		}

		dedup := fmt.Sprintf("%s|%s|%s", srv.ID, kind, subKey)
		op := ">="
		if r.LowerIsWorse {
			op = "<="
		}
		metricTxt := fmt.Sprintf("%.1f%s", val, r.Unit)
		threshTxt := fmt.Sprintf("%s %.1f%s", op, thresh, r.Unit)
		if r.Unit == "ms" || r.Unit == "个" || r.Unit == "次" || r.Unit == "包" || r.Unit == "条" || r.Unit == "s" {
			metricTxt = fmt.Sprintf("%.0f %s", val, r.Unit)
			threshTxt = fmt.Sprintf("%s %.0f %s", op, thresh, r.Unit)
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
		if snap.HostKeyChanged {
			if r, ok := ruleMap["host_key_changed"]; ok {
				detail := snap.HostKeyMismatchDetail
				if detail == "" {
					detail = snap.Error
				}
				if detail == "" {
					detail = fmt.Sprintf("主机 %s:%d 的 SSH 主机指纹发生异常变更，已拦截连接", srv.Host, srv.Port)
				}
				out = append(out, CandidateBreach{
					DedupKey:       fmt.Sprintf("%s|host_key_changed|", srv.ID),
					RuleKind:       "host_key_changed",
					RuleName:       r.Name,
					Severity:       SeverityCritical,
					Title:          fmt.Sprintf("高危：[%s] SSH 主机密钥指纹发生变更", srv.Name),
					Detail:         detail,
					MetricText:     "指纹突变",
					ThresholdText:  "匹配已知指纹",
					ConsecutiveReq: max(1, r.ConsecutiveCount),
				})
			}
			return out
		}

		if r, ok := ruleMap["offline"]; ok {
			errMsg := snap.Error
			if errMsg == "" {
				errMsg = snap.PartialError
			}
			if errMsg == "" {
				errMsg = "SSH 连接超时或不可达"
			}
			out = append(out, CandidateBreach{
				DedupKey:       fmt.Sprintf("%s|offline|", srv.ID),
				RuleKind:       "offline",
				RuleName:       r.Name,
				Severity:       SeverityCritical,
				Title:          fmt.Sprintf("主机 [%s] 离线不可达", srv.Name),
				Detail:         fmt.Sprintf("定时状态采集无法完成 %s:%d — %s", srv.Host, srv.Port, errMsg),
				MetricText:     "离线",
				ThresholdText:  "SSH 可达",
				ConsecutiveReq: max(1, r.ConsecutiveCount),
			})
		}
		return out
	}

	// 1. Availability: Unexpected Reboot & Latency
	if snap.UnexpectedReboot {
		if r, ok := ruleMap["unexpected_reboot"]; ok {
			out = append(out, CandidateBreach{
				DedupKey:       fmt.Sprintf("%s|unexpected_reboot|", srv.ID),
				RuleKind:       "unexpected_reboot",
				RuleName:       r.Name,
				Severity:       SeverityWarning,
				Title:          fmt.Sprintf("[%s] 检测到主机发生非预期重启", srv.Name),
				Detail:         fmt.Sprintf("目标主机当前运行时间回落至 %s（BootTime: %s），请核实是否宕机或内核崩溃", snap.Uptime, snap.BootTime),
				MetricText:     snap.Uptime,
				ThresholdText:  "Uptime 持续递增",
				ConsecutiveReq: max(1, r.ConsecutiveCount),
			})
		}
	}
	addThresholdBreach("latency_high", float64(snap.LatencyMs), "",
		fmt.Sprintf("[%s] SSH 探测响应延迟 %d ms", srv.Name, snap.LatencyMs),
		fmt.Sprintf("目标节点 %s:%d 握手或保活探测耗时偏高", srv.Host, srv.Port),
	)

	// 2. Compute: CPU, Steal, IOWait, Load
	addThresholdBreach("cpu_high", snap.CPUPercent, "",
		fmt.Sprintf("[%s] CPU 总使用率达到 %.1f%%", srv.Name, snap.CPUPercent),
		fmt.Sprintf("User %.1f%% / Sys %.1f%% / IOWait %.1f%% / Steal %.1f%%", snap.CPUUserPct, snap.CPUSystemPct, snap.CPUIowaitPct, snap.CPUStealPct),
	)
	if snap.CPUStealPct > 0 {
		addThresholdBreach("cpu_steal_high", snap.CPUStealPct, "",
			fmt.Sprintf("[%s] 云主机 CPU Steal 抢占达到 %.1f%%", srv.Name, snap.CPUStealPct),
			fmt.Sprintf("虚拟化宿主机算力竞争严重（Steal %.1f%%，总 CPU %.1f%%）", snap.CPUStealPct, snap.CPUPercent),
		)
	}
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

	// 3. Memory, Swap, OOM Kill, File Descriptors, Processes, Temp
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
	if snap.OOMKillsDelta > 0 {
		addThresholdBreach("oom_kill", float64(snap.OOMKillsDelta), "",
			fmt.Sprintf("[%s] 内核触发 %d 次 OOM Killer 进程击杀", srv.Name, snap.OOMKillsDelta),
			fmt.Sprintf("本周期新增 OOM Kill %d 次（累计 %d 次），当前内存占用 %.1f%%", snap.OOMKillsDelta, snap.OOMKills, snap.MemPercent),
		)
	}
	if snap.FDMax > 0 {
		addThresholdBreach("fd_high", snap.FDPercent, "",
			fmt.Sprintf("[%s] 内核文件句柄使用率 %.1f%%", srv.Name, snap.FDPercent),
			fmt.Sprintf("已分配 %d / 上限 %d", snap.FDUsed, snap.FDMax),
		)
	}
	addThresholdBreach("zombie_procs", float64(snap.ProcsZombie), "",
		fmt.Sprintf("[%s] 存在 %d 个僵尸进程 (Zombie)", srv.Name, snap.ProcsZombie),
		fmt.Sprintf("总进程 %d，运行中 %d，阻塞 %d，僵尸 %d", snap.ProcsTotal, snap.ProcsRunning, snap.ProcsBlocked, snap.ProcsZombie),
	)
	addThresholdBreach("blocked_procs", float64(snap.ProcsBlocked), "",
		fmt.Sprintf("[%s] 存在 %d 个不可中断阻塞进程 (D 态)", srv.Name, snap.ProcsBlocked),
		fmt.Sprintf("总进程 %d，D 态阻塞 %d 个，可能由磁盘故障或 NFS 远端挂载卡死引发", snap.ProcsTotal, snap.ProcsBlocked),
	)
	if snap.CPUTempC > 0 {
		addThresholdBreach("temp_high", snap.CPUTempC, "",
			fmt.Sprintf("[%s] CPU 硬件温度达到 %.1f°C", srv.Name, snap.CPUTempC),
			"物理热传感器温度偏高，请检查机房散热或风扇状态",
		)
	}

	// 4. Storage Capacity, Inodes, Read-Only Remount, Disk Will Fill, RAID, Kernel Errors
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
	if r, ok := ruleMap["disk_readonly"]; ok && len(snap.ReadOnlyMounts) > 0 {
		out = append(out, CandidateBreach{
			DedupKey:       fmt.Sprintf("%s|disk_readonly|", srv.ID),
			RuleKind:       "disk_readonly",
			RuleName:       r.Name,
			Severity:       SeverityCritical,
			Title:          fmt.Sprintf("[%s] 检测到 %d 个文件系统重挂载为只读 (RO)", srv.Name, len(snap.ReadOnlyMounts)),
			Detail:         fmt.Sprintf("只读挂载点：%s（通常由底层磁盘 I/O 错误或文件系统损坏触发，业务写入将失败）", strings.Join(snap.ReadOnlyMounts, ", ")),
			MetricText:     fmt.Sprintf("%d 只读", len(snap.ReadOnlyMounts)),
			ThresholdText:  "可读写 (RW)",
			ConsecutiveReq: max(1, r.ConsecutiveCount),
		})
	}
	if snap.DiskFullForecastHours > 0 {
		mnt := snap.DiskFullForecastMount
		if mnt == "" {
			mnt = "/"
		}
		addThresholdBreach("disk_will_fill", snap.DiskFullForecastHours, "",
			fmt.Sprintf("[%s] 分区 %s 预计约 %.1f 小时后耗尽", srv.Name, mnt, snap.DiskFullForecastHours),
			fmt.Sprintf("根据近期磁盘使用率增长趋势线性预测，当前最高分区占用 %.1f%%，请及时清理日志或扩容", max(snap.MaxPartPercent, snap.DiskPercent)),
		)
	}
	if r, ok := ruleMap["raid_degraded"]; ok && len(snap.RAIDDegraded) > 0 {
		out = append(out, CandidateBreach{
			DedupKey:       fmt.Sprintf("%s|raid_degraded|", srv.ID),
			RuleKind:       "raid_degraded",
			RuleName:       r.Name,
			Severity:       SeverityCritical,
			Title:          fmt.Sprintf("[%s] 软 RAID 阵列降级故障", srv.Name),
			Detail:         fmt.Sprintf("异常阵列状态：%s", strings.Join(snap.RAIDDegraded, "；")),
			MetricText:     fmt.Sprintf("%d 阵列异常", len(snap.RAIDDegraded)),
			ThresholdText:  "全部在线",
			ConsecutiveReq: max(1, r.ConsecutiveCount),
		})
	}
	if snap.KernelErrorCount > 0 {
		sampleErr := strings.Join(snap.KernelErrors[:min(3, len(snap.KernelErrors))], " | ")
		addThresholdBreach("kernel_error", float64(snap.KernelErrorCount), "",
			fmt.Sprintf("[%s] 内核日志检测到 %d 条严重硬件/存储/NFS 错误", srv.Name, snap.KernelErrorCount),
			sampleErr,
		)
	}

	// 5. Network Sockets, Errors & Listening Ports
	abnormalTCP := snap.TCPCloseWait + snap.TCPSynRecv
	addThresholdBreach("tcp_close_wait", float64(abnormalTCP), "",
		fmt.Sprintf("[%s] TCP 半关闭/半连接套接字堆积 (%d 个)", srv.Name, abnormalTCP),
		fmt.Sprintf("CLOSE_WAIT=%d, SYN_RECV=%d, ESTABLISHED=%d, TIME_WAIT=%d", snap.TCPCloseWait, snap.TCPSynRecv, snap.TCPEstablished, snap.TCPTimeWait),
	)
	if snap.NetPacketErrorsDelta > 0 {
		addThresholdBreach("net_errors_spike", float64(snap.NetPacketErrorsDelta), "",
			fmt.Sprintf("[%s] 网卡本周期新增 %d 个错包/丢包", srv.Name, snap.NetPacketErrorsDelta),
			fmt.Sprintf("累计错包/丢包 %d，请检查网卡链路、MTU 或交换机端口", snap.NetPacketErrors),
		)
	}

	// 6. Systemd Failed Units & Explicitly Watched Services (INDEPENDENT checks — no else-if masking!)
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
		}
		if snap.SystemdFailedCount > 0 {
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

	// 7. Docker Daemon Down & Unhealthy / Restarting / Exited-Abnormal Containers
	if r, ok := ruleMap["docker_unhealthy"]; ok && snap.Docker.Installed {
		if snap.Docker.DaemonDown {
			out = append(out, CandidateBreach{
				DedupKey:       fmt.Sprintf("%s|docker_unhealthy|daemon", srv.ID),
				RuleKind:       "docker_unhealthy",
				RuleName:       r.Name,
				Severity:       SeverityCritical,
				Title:          fmt.Sprintf("[%s] Docker 守护进程 (dockerd) 无响应或已停止", srv.Name),
				Detail:         "目标主机已安装 Docker，但本周期无法通过 docker ps/info 获取容器状态，请检查 docker 服务或权限",
				MetricText:     "Daemon 异常",
				ThresholdText:  "Daemon 运行中",
				ConsecutiveReq: max(1, r.ConsecutiveCount),
			})
		}
		totalBad := snap.Docker.Unhealthy + snap.Docker.ExitedAbnormal
		if totalBad > 0 {
			var badNames []string
			for _, c := range snap.Docker.Containers {
				if isAbnormalContainer(c) {
					badNames = append(badNames, fmt.Sprintf("%s(%s)", c.Name, c.Status))
				}
			}
			out = append(out, CandidateBreach{
				DedupKey:       fmt.Sprintf("%s|docker_unhealthy|", srv.ID),
				RuleKind:       "docker_unhealthy",
				RuleName:       r.Name,
				Severity:       SeverityWarning,
				Title:          fmt.Sprintf("[%s] %d 个 Docker 容器状态异常", srv.Name, totalBad),
				Detail:         fmt.Sprintf("异常或非 0 退出容器: %s", strings.Join(badNames, ", ")),
				MetricText:     fmt.Sprintf("%d 异常", totalBad),
				ThresholdText:  "全部健康",
				ConsecutiveReq: max(1, r.ConsecutiveCount),
			})
		}
	}

	// 8. Explicitly Watched Ports (protected against truncated port lists)
	if r, ok := ruleMap["watched_port_down"]; ok && len(srv.WatchedPorts) > 0 && len(snap.ListeningPorts) > 0 && !snap.PortsTruncated {
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

	// 9. Newly Exposed Listening Ports (Baseline Drift — deduplicated across tcp/tcp6,
	//    pre-filtered for ephemeral UDP, ignore allowlists, and per-port anti-flap streaks)
	if r, ok := ruleMap["port_drift"]; ok && len(driftedPorts) > 0 {
		out = append(out, BuildPortDriftCandidateBreach(srv, r, driftedPorts, 1))
	}

	// 10. Security Posture & Zero-AI Intrusion Detection (L1 + L3)
	if snap.Security.SSHFailedRecent > 0 {
		ipHint := ""
		if len(snap.Security.TopFailedIPs) > 0 {
			ipHint = "，高频来源: " + strings.Join(snap.Security.TopFailedIPs, ", ")
		}
		addThresholdBreach("ssh_bruteforce", float64(snap.Security.SSHFailedRecent), "",
			fmt.Sprintf("[%s] 近 15 分钟检测到 %d 次 SSH 登录失败尝试", srv.Name, snap.Security.SSHFailedRecent),
			fmt.Sprintf("精准时间窗内认证日志捕获频繁失败记录%s", ipHint),
		)
	}
	if r, ok := ruleMap["uid_zero_backdoor"]; ok {
		var nonRootUID0 []string
		for _, u := range snap.Security.UIDZeroUsers {
			if u != "" && u != "root" {
				nonRootUID0 = append(nonRootUID0, u)
			}
		}
		if len(nonRootUID0) > 0 {
			out = append(out, CandidateBreach{
				DedupKey:       fmt.Sprintf("%s|uid_zero_backdoor|", srv.ID),
				RuleKind:       "uid_zero_backdoor",
				RuleName:       r.Name,
				Severity:       SeverityCritical,
				Title:          fmt.Sprintf("高危：[%s] 发现非 root 的 UID=0 超级特权账户 (%s)", srv.Name, strings.Join(nonRootUID0, ", ")),
				Detail:         fmt.Sprintf("/etc/passwd 或目录服务中检测到非 root 的 UID=0 账户：%s，疑似提权后门", strings.Join(nonRootUID0, ", ")),
				MetricText:     strings.Join(nonRootUID0, ", "),
				ThresholdText:  "仅 root 为 UID=0",
				ConsecutiveReq: max(1, r.ConsecutiveCount),
			})
		}
	}
	if r, ok := ruleMap["firewall_inactive"]; ok && strings.EqualFold(snap.Security.FirewallStatus, "inactive") {
		fwName := snap.Security.FirewallDetail
		if fwName == "" {
			fwName = "主机防火墙"
		}
		out = append(out, CandidateBreach{
			DedupKey:       fmt.Sprintf("%s|firewall_inactive|", srv.ID),
			RuleKind:       "firewall_inactive",
			RuleName:       r.Name,
			Severity:       SeverityWarning,
			Title:          fmt.Sprintf("[%s] 防火墙 (%s) 处于关闭状态", srv.Name, fwName),
			Detail:         fmt.Sprintf("检测到已安装的 %s 明确处于 inactive 状态，请核实是否为误关闭或安全基线变更", fwName),
			MetricText:     "inactive",
			ThresholdText:  "active",
			ConsecutiveReq: max(1, r.ConsecutiveCount),
		})
	}
	if r, ok := ruleMap["security_file_drift"]; ok && (len(snap.Security.FileDrifts) > 0 || len(snap.Security.PersistenceDrifts) > 0) {
		var parts []string
		if len(snap.Security.FileDrifts) > 0 {
			parts = append(parts, "敏感文件变更: "+strings.Join(snap.Security.FileDrifts, ", "))
		}
		if len(snap.Security.PersistenceDrifts) > 0 {
			parts = append(parts, "持久化项变更: "+strings.Join(snap.Security.PersistenceDrifts, ", "))
		}
		out = append(out, CandidateBreach{
			DedupKey:       fmt.Sprintf("%s|security_file_drift|", srv.ID),
			RuleKind:       "security_file_drift",
			RuleName:       r.Name,
			Severity:       SeverityCritical,
			Title:          fmt.Sprintf("高危：[%s] 关键安全文件或持久化配置基线发生漂移", srv.Name),
			Detail:         fmt.Sprintf("%s（若属正常变更可在节点详情页点击「采纳安全基线」）", strings.Join(parts, "；")),
			MetricText:     fmt.Sprintf("%d 项漂移", len(snap.Security.FileDrifts)+len(snap.Security.PersistenceDrifts)),
			ThresholdText:  "匹配安全基线",
			ConsecutiveReq: max(1, r.ConsecutiveCount),
		})
	}
	if r, ok := ruleMap["suspicious_process"]; ok && len(snap.Security.SuspiciousProcs) > 0 {
		sev := SeverityWarning
		var items []string
		for _, sp := range snap.Security.SuspiciousProcs {
			if sp.Severity == string(SeverityCritical) {
				sev = SeverityCritical
			}
			items = append(items, fmt.Sprintf("PID %d(%s:%s %s)", sp.PID, sp.User, sp.Reason, sp.Command))
		}
		out = append(out, CandidateBreach{
			DedupKey:       fmt.Sprintf("%s|suspicious_process|", srv.ID),
			RuleKind:       "suspicious_process",
			RuleName:       r.Name,
			Severity:       sev,
			Title:          fmt.Sprintf("[%s] 检测到 %d 个可疑进程特征", srv.Name, len(snap.Security.SuspiciousProcs)),
			Detail:         fmt.Sprintf("疑似异常进程：%s", strings.Join(items[:min(5, len(items))], "；")),
			MetricText:     fmt.Sprintf("%d 进程", len(snap.Security.SuspiciousProcs)),
			ThresholdText:  "0 可疑进程",
			ConsecutiveReq: max(1, r.ConsecutiveCount),
		})
	}
	if r, ok := ruleMap["suspicious_outbound"]; ok && len(snap.Security.SuspiciousOutbound) > 0 {
		var conns []string
		for _, oc := range snap.Security.SuspiciousOutbound {
			proc := oc.Process
			if proc == "" {
				proc = "unknown"
			}
			conns = append(conns, fmt.Sprintf("%s:%d(%s)", oc.RemoteIP, oc.RemotePort, proc))
		}
		out = append(out, CandidateBreach{
			DedupKey:       fmt.Sprintf("%s|suspicious_outbound|", srv.ID),
			RuleKind:       "suspicious_outbound",
			RuleName:       r.Name,
			Severity:       SeverityWarning,
			Title:          fmt.Sprintf("[%s] 检测到 %d 条高危端口外联连接", srv.Name, len(snap.Security.SuspiciousOutbound)),
			Detail:         fmt.Sprintf("外联目标：%s", strings.Join(conns[:min(6, len(conns))], ", ")),
			MetricText:     fmt.Sprintf("%d 连接", len(snap.Security.SuspiciousOutbound)),
			ThresholdText:  "无高危外联",
			ConsecutiveReq: max(1, r.ConsecutiveCount),
		})
	}
	if r, ok := ruleMap["ssh_new_login_ip"]; ok && len(snap.Security.NewSSHLoginIPs) > 0 {
		out = append(out, CandidateBreach{
			DedupKey:       fmt.Sprintf("%s|ssh_new_login_ip|", srv.ID),
			RuleKind:       "ssh_new_login_ip",
			RuleName:       r.Name,
			Severity:       SeverityWarning,
			Title:          fmt.Sprintf("[%s] 检测到新来源 IP 成功登录 SSH: %s", srv.Name, strings.Join(snap.Security.NewSSHLoginIPs, ", ")),
			Detail:         fmt.Sprintf("不在已知登录基线中的来源 IP 已成功通过 SSH 认证：%s（如为本人操作可点击「采纳安全基线」）", strings.Join(snap.Security.NewSSHLoginIPs, ", ")),
			MetricText:     fmt.Sprintf("+%d 新IP", len(snap.Security.NewSSHLoginIPs)),
			ThresholdText:  "匹配已知登录 IP",
			ConsecutiveReq: max(1, r.ConsecutiveCount),
		})
	}
	if absOff := math.Abs(float64(snap.ClockOffsetSec)); absOff > 0 {
		addThresholdBreach("clock_ntp_drift", absOff, "",
			fmt.Sprintf("[%s] 主机时钟偏移 %.0f 秒", srv.Name, absOff),
			fmt.Sprintf("目标机时间与监控端 UTC 偏差 %+d 秒（NTP 同步状态: %v）", snap.ClockOffsetSec, snap.NTPSynced),
		)
	}

	return out
}

func isAbnormalContainer(c ContainerStat) bool {
	if c.Health == "unhealthy" || c.State == "restarting" || c.State == "dead" {
		return true
	}
	if c.State == "exited" {
		low := strings.ToLower(c.Status)
		if strings.Contains(low, "exited (") && !strings.Contains(low, "exited (0)") {
			return true
		}
	}
	return false
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
		cp.JumpServerIDs = slices.Clone(srv.EffectiveJumpServerIDs())
		cp.WatchedServices = slices.Clone(srv.WatchedServices)
		cp.WatchedPorts = slices.Clone(srv.WatchedPorts)
		cp.IgnoredPortDriftProcesses = slices.Clone(srv.IgnoredPortDriftProcesses)
		cp.IgnoredPortDriftPorts = slices.Clone(srv.IgnoredPortDriftPorts)
		out[i] = cp
	}
	return out, cloneMonitorSettings(s.secrets.MonitorSettings), nil
}

// GetEnabledAIPatrolWebhooks returns enabled AI patrol WebhookChannels so monitor alerts can optionally reuse them.
func (s *Store) GetEnabledAIPatrolWebhooks() []WebhookChannel {
	s.secMu.RLock()
	defer s.secMu.RUnlock()
	if s.secrets == nil {
		return nil
	}
	var out []WebhookChannel
	for _, wh := range s.secrets.AISettings.Patrol.Webhooks {
		if wh.Enabled && strings.TrimSpace(wh.URL) != "" {
			out = append(out, wh)
		}
	}
	return out
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

// mergeSlowTierFromPrev copies cached slow-tier static & security fields from prev into a fast-tier snapshot
// so LatestSnapshot stays complete and slow-tier alerts never flap or false-resolve between slow sweeps.
func mergeSlowTierFromPrev(incoming, prev *ServerMonitorSnapshot) {
	if incoming == nil || prev == nil || !prev.Reachable {
		return
	}
	if incoming.Hostname == "" {
		incoming.Hostname = prev.Hostname
	}
	if incoming.OS == "" {
		incoming.OS = prev.OS
	}
	if incoming.Kernel == "" {
		incoming.Kernel = prev.Kernel
	}
	if incoming.Arch == "" {
		incoming.Arch = prev.Arch
	}
	if incoming.CPUModel == "" {
		incoming.CPUModel = prev.CPUModel
	}
	if incoming.CPUCores <= 0 {
		incoming.CPUCores = prev.CPUCores
	}
	if incoming.Virtualization == "" {
		incoming.Virtualization = prev.Virtualization
	}
	if incoming.Timezone == "" {
		incoming.Timezone = prev.Timezone
	}
	if incoming.LastSlowCollectedAt == nil && prev.LastSlowCollectedAt != nil {
		t := *prev.LastSlowCollectedAt
		incoming.LastSlowCollectedAt = &t
	}
	if !incoming.NTPSynced && prev.NTPSynced {
		incoming.NTPSynced = prev.NTPSynced
	}
	if incoming.ClockOffsetSec == 0 && prev.ClockOffsetSec != 0 {
		incoming.ClockOffsetSec = prev.ClockOffsetSec
	}
	if len(incoming.RAIDDegraded) == 0 && len(prev.RAIDDegraded) > 0 {
		incoming.RAIDDegraded = slices.Clone(prev.RAIDDegraded)
	}
	if incoming.KernelErrorCount == 0 && prev.KernelErrorCount > 0 {
		incoming.KernelErrorCount = prev.KernelErrorCount
		incoming.KernelErrors = slices.Clone(prev.KernelErrors)
	}
	// Preserve cached IPv4 & State per interface when fast-tier omits `ip -4 addr` / Darwin `ifconfig`
	if len(prev.Interfaces) > 0 && len(incoming.Interfaces) > 0 {
		prevIP := make(map[string]string, len(prev.Interfaces))
		prevState := make(map[string]string, len(prev.Interfaces))
		for _, nic := range prev.Interfaces {
			if nic.IPv4 != "" {
				prevIP[nic.Name] = nic.IPv4
			}
			if nic.State != "" {
				prevState[nic.Name] = nic.State
			}
		}
		for i := range incoming.Interfaces {
			if incoming.Interfaces[i].IPv4 == "" {
				incoming.Interfaces[i].IPv4 = prevIP[incoming.Interfaces[i].Name]
			}
			if incoming.Interfaces[i].State == "" {
				incoming.Interfaces[i].State = prevState[incoming.Interfaces[i].Name]
			}
		}
	}
	// Preserve slow-tier security posture fields
	if incoming.Security.FirewallStatus == "" || incoming.Security.FirewallStatus == "unknown" {
		if prev.Security.FirewallStatus != "" {
			incoming.Security.FirewallStatus = prev.Security.FirewallStatus
			incoming.Security.FirewallDetail = prev.Security.FirewallDetail
		}
	}
	if incoming.Security.MACFramework == "" {
		incoming.Security.MACFramework = prev.Security.MACFramework
	}
	if len(incoming.Security.UIDZeroUsers) == 0 {
		incoming.Security.UIDZeroUsers = slices.Clone(prev.Security.UIDZeroUsers)
	}
	if !incoming.Security.RebootRequired && prev.Security.RebootRequired {
		incoming.Security.RebootRequired = prev.Security.RebootRequired
	}
	if incoming.Security.PendingUpdates == 0 {
		incoming.Security.PendingUpdates = prev.Security.PendingUpdates
	}
	if len(incoming.Security.ActiveUsers) == 0 {
		incoming.Security.ActiveUsers = slices.Clone(prev.Security.ActiveUsers)
	}
	if incoming.Security.SSHFailedRecent == 0 && prev.Security.SSHFailedRecent > 0 {
		incoming.Security.SSHFailedRecent = prev.Security.SSHFailedRecent
		incoming.Security.TopFailedIPs = slices.Clone(prev.Security.TopFailedIPs)
	}
	if len(incoming.Security.FileHashes) == 0 && len(prev.Security.FileHashes) > 0 {
		incoming.Security.FileHashes = make(map[string]string, len(prev.Security.FileHashes))
		maps.Copy(incoming.Security.FileHashes, prev.Security.FileHashes)
	}
	if incoming.Security.PersistenceHash == "" {
		incoming.Security.PersistenceHash = prev.Security.PersistenceHash
	}
	if len(incoming.Security.SuspiciousProcs) == 0 {
		incoming.Security.SuspiciousProcs = slices.Clone(prev.Security.SuspiciousProcs)
	}
	if len(incoming.Security.SuspiciousOutbound) == 0 {
		incoming.Security.SuspiciousOutbound = slices.Clone(prev.Security.SuspiciousOutbound)
	}
	if len(incoming.Security.RecentSSHLogins) == 0 {
		incoming.Security.RecentSSHLogins = slices.Clone(prev.Security.RecentSSHLogins)
	}
	if len(incoming.Security.SSHWeakConfigs) == 0 {
		incoming.Security.SSHWeakConfigs = slices.Clone(prev.Security.SSHWeakConfigs)
	}
}

func collectCurrentLoginIPs(sec SecurityPostureStat) []string {
	seen := make(map[string]struct{})
	for _, ev := range sec.RecentSSHLogins {
		if ip := strings.TrimSpace(ev.FromIP); ip != "" {
			seen[ip] = struct{}{}
		}
	}
	for _, u := range sec.ActiveUsers {
		if ip := strings.TrimSpace(u.FromIP); ip != "" {
			seen[ip] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for ip := range seen {
		out = append(out, ip)
	}
	sort.Strings(out)
	return out
}

// RecordMonitorSnapshots persists collected server snapshots, time-series samples, alerts, port & security baselines,
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
	monSettings := cloneMonitorSettings(s.secrets.MonitorSettings)
	rules := slices.Clone(s.secrets.MonitorRules)
	autoSyncMem := s.secrets.AISettings.MemoryConfig.AutoSyncMonitorToMemory
	srvByID := make(map[string]ServerConfig, len(s.secrets.Servers))
	for _, srv := range s.secrets.Servers {
		cp := srv
		cp.WatchedServices = slices.Clone(srv.WatchedServices)
		cp.WatchedPorts = slices.Clone(srv.WatchedPorts)
		cp.IgnoredPortDriftProcesses = slices.Clone(srv.IgnoredPortDriftProcesses)
		cp.IgnoredPortDriftPorts = slices.Clone(srv.IgnoredPortDriftPorts)
		srvByID[srv.ID] = cp
	}
	s.secMu.RUnlock()

	ruleEnabledMap := make(map[string]bool, len(rules))
	portDriftConsecutiveReq := 1
	for _, r := range rules {
		ruleEnabledMap[r.Kind] = r.Enabled && !isRuleSuppressedByCollectionToggles(r.Kind, monSettings)
		if r.Kind == "port_drift" {
			portDriftConsecutiveReq = max(1, r.ConsecutiveCount)
		}
	}

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
		prevSnap := mon.LatestSnapshots[srvCfg.ID]
		incoming := cloneSnapshot(rawIncoming)
		incoming.ServerName = srvCfg.Name
		incoming.Group = srvCfg.Group
		incoming.Host = srvCfg.Host
		incoming.Port = srvCfg.Port
		if incoming.CollectedAt.IsZero() {
			incoming.CollectedAt = now
		}

		// Fast-tier snapshots reuse cached slow-tier static & security fields
		if incoming.Reachable && incoming.CollectionTier == "fast" && prevSnap != nil {
			mergeSlowTierFromPrev(incoming, prevSnap)
		}

		// Compute cross-snapshot deltas for reboot, OOM kills & NIC errors
		if incoming.Reachable && prevSnap != nil && prevSnap.Reachable {
			if prevSnap.UptimeSec > 120 && incoming.UptimeSec > 0 && incoming.UptimeSec+60 < prevSnap.UptimeSec {
				incoming.UnexpectedReboot = true
			}
			if incoming.OOMKills >= prevSnap.OOMKills {
				incoming.OOMKillsDelta = incoming.OOMKills - prevSnap.OOMKills
			}
			if incoming.NetPacketErrors >= prevSnap.NetPacketErrors {
				incoming.NetPacketErrorsDelta = incoming.NetPacketErrors - prevSnap.NetPacketErrors
			}
		}

		// Zero-overhead deterministic disk time-to-full forecast from retained time-series
		if incoming.Reachable {
			curPt := incoming.ToSamplePoint()
			if hrs := computeDiskWillFillForecast(mon.HistoryByServer[srvCfg.ID], curPt); hrs > 0 {
				incoming.DiskFullForecastHours = hrs
				if incoming.MaxPartMount != "" {
					incoming.DiskFullForecastMount = incoming.MaxPartMount
				} else {
					incoming.DiskFullForecastMount = "/"
				}
			}
		}

		// Mark watched ports on incoming snapshot
		if len(srvCfg.WatchedPorts) > 0 {
			for i := range incoming.ListeningPorts {
				if slices.Contains(srvCfg.WatchedPorts, incoming.ListeningPorts[i].Port) {
					incoming.ListeningPorts[i].Watched = true
				}
			}
		}

		// Annotate ephemeral UDP & allowlisted dynamic-port processes on incoming snapshot
		if incoming.Reachable && len(incoming.ListeningPorts) > 0 {
			AnnotateListeningPorts(incoming.ListeningPorts, monSettings, srvCfg)
		}

		// Port baseline comparison (deduplicated across tcp/tcp6 & udp/udp6, with per-port anti-flap tracking)
		var driftedPorts []ListeningPortStat
		portStreakPrefix := srvCfg.ID + "|port_drift_port|"
		if incoming.Reachable && monSettings.CollectPortsAndServices && len(incoming.ListeningPorts) > 0 {
			curPublicKeys := ExtractEligiblePublicPortKeys(incoming.ListeningPorts)
			baseKeys, hasBaseline := mon.PortBaselines[srvCfg.ID]
			if !hasBaseline {
				mon.PortBaselines[srvCfg.ID] = curPublicKeys
			} else if monSettings.DetectPortDrift {
				rawDrifted := ComputeDriftedPorts(incoming.ListeningPorts, baseKeys)
				activeDriftKeys := make(map[string]bool, len(rawDrifted))
				for _, dp := range rawDrifted {
					key := fmt.Sprintf("%s/%d", NormalizeBaseProto(dp.Proto), dp.Port)
					streakKey := portStreakPrefix + key
					activeDriftKeys[streakKey] = true
					mon.BreachStreaks[streakKey]++
					if mon.BreachStreaks[streakKey] >= portDriftConsecutiveReq {
						driftedPorts = append(driftedPorts, dp)
					}
				}
				for k := range mon.BreachStreaks {
					if strings.HasPrefix(k, portStreakPrefix) && !activeDriftKeys[k] {
						delete(mon.BreachStreaks, k)
					}
				}
			} else {
				for k := range mon.BreachStreaks {
					if strings.HasPrefix(k, portStreakPrefix) {
						delete(mon.BreachStreaks, k)
					}
				}
			}
		}

		// Security baseline comparison (FIM file hashes, crontab/systemd persistence hash, known SSH login IPs)
		if incoming.Reachable && monSettings.CollectSecurity {
			secBase, hasSecBase := mon.SecurityBaselines[srvCfg.ID]
			baseUpdated := false

			if len(incoming.Security.FileHashes) > 0 {
				if len(secBase.FileHashes) == 0 {
					secBase.FileHashes = make(map[string]string, len(incoming.Security.FileHashes))
					maps.Copy(secBase.FileHashes, incoming.Security.FileHashes)
					baseUpdated = true
				} else {
					var drifts []string
					for path, baseHash := range secBase.FileHashes {
						curHash, ok := incoming.Security.FileHashes[path]
						if !ok {
							drifts = append(drifts, path+" (缺失/不可读)")
						} else if curHash != baseHash {
							drifts = append(drifts, path+" (内容已变更)")
						}
					}
					for path := range incoming.Security.FileHashes {
						if _, ok := secBase.FileHashes[path]; !ok {
							drifts = append(drifts, path+" (新增)")
						}
					}
					sort.Strings(drifts)
					incoming.Security.FileDrifts = drifts
				}
			}

			if incoming.Security.PersistenceHash != "" {
				if secBase.PersistenceHash == "" {
					secBase.PersistenceHash = incoming.Security.PersistenceHash
					baseUpdated = true
				} else if incoming.Security.PersistenceHash != secBase.PersistenceHash {
					incoming.Security.PersistenceDrifts = []string{"crontab / systemd 持久化配置指纹变化"}
				}
			}

			if len(incoming.Security.RecentSSHLogins) > 0 || len(incoming.Security.ActiveUsers) > 0 {
				curIPs := collectCurrentLoginIPs(incoming.Security)
				if !hasSecBase && len(secBase.KnownSSHLoginIPs) == 0 {
					secBase.KnownSSHLoginIPs = curIPs
					baseUpdated = true
				} else if len(incoming.Security.RecentSSHLogins) > 0 {
					knownSet := make(map[string]bool, len(secBase.KnownSSHLoginIPs))
					for _, ip := range secBase.KnownSSHLoginIPs {
						knownSet[ip] = true
					}
					var newIPs []string
					for _, ev := range incoming.Security.RecentSSHLogins {
						ip := strings.TrimSpace(ev.FromIP)
						if ip != "" && !knownSet[ip] && !slices.Contains(newIPs, ip) {
							newIPs = append(newIPs, ip)
						}
					}
					sort.Strings(newIPs)
					incoming.Security.NewSSHLoginIPs = newIPs
				}
			}

			if baseUpdated {
				secBase.UpdatedAt = incoming.CollectedAt
				mon.SecurityBaselines[srvCfg.ID] = secBase
			}
		}

		// Evaluate candidate breaches
		breaches := evaluateSnapshotRules(incoming, srvCfg, monSettings, rules, driftedPorts)

		// Update breach streaks, apply strict consecutive debounce, handle escalation & de-escalation
		activeBreachMap := make(map[string]CandidateBreach, len(breaches))
		effectiveBreaches := make([]CandidateBreach, 0, len(breaches))
		for _, b := range breaches {
			activeBreachMap[b.DedupKey] = b
			mon.BreachStreaks[b.DedupKey]++
			if mon.BreachStreaks[b.DedupKey] < b.ConsecutiveReq {
				continue
			}
			effectiveBreaches = append(effectiveBreaches, b)

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
						// Escalate Warning -> Critical: reactivate even if acknowledged & notify webhook!
						al.Severity = SeverityCritical
						al.Status = AlertStatusFiring
						al.AcknowledgedAt = nil
						triggered = append(triggered, *al)
					} else if b.Severity == SeverityWarning && al.Severity == SeverityCritical {
						// De-escalate Critical -> Warning cleanly without duplicate webhook spam
						al.Severity = SeverityWarning
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

		// Compute snapshot health strictly using debounced effective breaches
		ComputeSnapshotHealth(incoming, effectiveBreaches)
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

		// Clear non-breached streaks for this server (per-port port_drift_port| streaks are managed above)
		prefix := srvCfg.ID + "|"
		for k := range mon.BreachStreaks {
			if strings.HasPrefix(k, prefix) {
				if strings.HasPrefix(k, portStreakPrefix) {
					continue
				}
				if _, stillBreached := activeBreachMap[k]; !stillBreached {
					if incoming.Reachable ||
						strings.HasPrefix(k, srvCfg.ID+"|offline|") ||
						strings.HasPrefix(k, srvCfg.ID+"|host_key_changed|") {
						delete(mon.BreachStreaks, k)
					}
				}
			}
		}

		// Auto-resolve active alerts whose condition has recovered (never resolve host metrics on unreachable/partial failure!)
		for idx := range mon.Alerts {
			al := &mon.Alerts[idx]
			if al.ServerID != srvCfg.ID || al.Status == AlertStatusResolved {
				continue
			}
			if _, stillBreached := activeBreachMap[al.DedupKey]; stillBreached {
				continue
			}
			if !incoming.Reachable && al.RuleKind != "offline" && al.RuleKind != "host_key_changed" {
				continue
			}
			resTime := incoming.CollectedAt
			al.Status = AlertStatusResolved
			al.ResolvedAt = &resTime
			al.LastSeenAt = resTime
			// Only send recovery notification if rule is actually enabled; disabled rules close silently
			if ruleEnabledMap[al.RuleKind] {
				resolved = append(resolved, *al)
			}
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

// SilenceServerMonitorAlerts silently resolves active alerts and clears breach streaks for a disabled server.
func (s *Store) SilenceServerMonitorAlerts(serverID string) {
	if !s.IsReady() || serverID == "" {
		return
	}
	now := time.Now().UTC()
	s.rtMu.Lock()
	if s.monitorRT != nil {
		changed := false
		prefix := serverID + "|"
		for k := range s.monitorRT.BreachStreaks {
			if strings.HasPrefix(k, prefix) {
				delete(s.monitorRT.BreachStreaks, k)
				changed = true
			}
		}
		for i := range s.monitorRT.Alerts {
			al := &s.monitorRT.Alerts[i]
			if al.ServerID == serverID && al.Status != AlertStatusResolved {
				al.Status = AlertStatusResolved
				al.ResolvedAt = &now
				al.LastSeenAt = now
				changed = true
			}
		}
		if changed {
			s.dirtyMonitor = true
		}
	}
	s.rtMu.Unlock()
	s.triggerFlush()
}

// GetMonitorOverview builds the fleet monitoring dashboard state by joining server configs with runtime telemetry.
func (s *Store) GetMonitorOverview() (*MonitorOverviewData, error) {
	s.secMu.RLock()
	if s.secrets == nil {
		s.secMu.RUnlock()
		return nil, ErrVaultLocked
	}
	monSettings := cloneMonitorSettings(s.secrets.MonitorSettings)
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

// GetServerMonitorDetail returns deep snapshot, time-filtered historical series, SLA, baselines, and alerts for one server.
func (s *Store) GetServerMonitorDetail(serverID string, rangeDur time.Duration) (*ServerMonitorDetail, error) {
	s.secMu.RLock()
	if s.secrets == nil {
		s.secMu.RUnlock()
		return nil, ErrVaultLocked
	}
	monSettings := cloneMonitorSettings(s.secrets.MonitorSettings)
	var targetView *ServerView
	var targetCfg ServerConfig
	for i := range s.secrets.Servers {
		if s.secrets.Servers[i].ID == serverID {
			targetCfg = s.secrets.Servers[i]
			targetCfg.IgnoredPortDriftProcesses = slices.Clone(targetCfg.IgnoredPortDriftProcesses)
			targetCfg.IgnoredPortDriftPorts = slices.Clone(targetCfg.IgnoredPortDriftPorts)
			v := targetCfg.ToView()
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
	if snap != nil && len(snap.ListeningPorts) > 0 {
		AnnotateListeningPorts(snap.ListeningPorts, monSettings, targetCfg)
	}
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

	var secBase *ServerSecurityBaseline
	if sb, ok := mon.SecurityBaselines[serverID]; ok {
		cp := cloneSecurityBaseline(sb)
		secBase = &cp
	}

	return &ServerMonitorDetail{
		Server:           *targetView,
		Snapshot:         snap,
		Series:           filtered,
		SLA:              computeSLA(filtered),
		PortBaseline:     baseline,
		SecurityBaseline: secBase,
		Alerts:           srvAlerts,
	}, nil
}

// GetMonitorPolicy returns current monitor settings and alert rules from secrets.enc.
func (s *Store) GetMonitorPolicy() (MonitorSettings, []MonitorAlertRule, error) {
	s.secMu.RLock()
	defer s.secMu.RUnlock()
	if s.secrets == nil {
		return MonitorSettings{}, nil, ErrVaultLocked
	}
	return cloneMonitorSettings(s.secrets.MonitorSettings), slices.Clone(s.secrets.MonitorRules), nil
}

// UpdateMonitorPolicy validates and saves updated schedule settings and alert rules,
// and silently closes any active alerts belonging to newly disabled rules or dimensions.
func (s *Store) UpdateMonitorPolicy(settings MonitorSettings, rules []MonitorAlertRule, clientIP string) (MonitorSettings, []MonitorAlertRule, error) {
	if err := validateMonitorSettings(settings); err != nil {
		return MonitorSettings{}, nil, err
	}
	if len(rules) > 0 {
		if err := validateMonitorAlertRules(rules); err != nil {
			return MonitorSettings{}, nil, err
		}
	}

	var outSettings MonitorSettings
	var outRules []MonitorAlertRule
	var allServers []ServerConfig
	err := s.mutateSecrets(func(sec *SecretsState) error {
		sec.MonitorSettings = sanitizeMonitorSettings(settings)
		if len(rules) > 0 {
			sec.MonitorRules = mergeMonitorAlertRules(rules)
		}
		outSettings = cloneMonitorSettings(sec.MonitorSettings)
		outRules = slices.Clone(sec.MonitorRules)
		allServers = cloneServersWithoutRuntime(sec.Servers)
		return nil
	})
	if err != nil {
		return MonitorSettings{}, nil, err
	}

	activeKinds := make(map[string]bool, len(outRules))
	for _, r := range outRules {
		activeKinds[r.Kind] = r.Enabled && !isRuleSuppressedByCollectionToggles(r.Kind, outSettings)
	}

	// Trim existing runtime series if RetentionPoints was lowered & silently close disabled rule alerts
	now := time.Now().UTC()
	s.rtMu.Lock()
	if s.monitorRT != nil {
		dirty := false
		for sid, pts := range s.monitorRT.HistoryByServer {
			if len(pts) > outSettings.RetentionPoints {
				s.monitorRT.HistoryByServer[sid] = slices.Clone(pts[len(pts)-outSettings.RetentionPoints:])
				dirty = true
			}
		}
		for k := range s.monitorRT.BreachStreaks {
			parts := strings.SplitN(k, "|", 3)
			if len(parts) >= 2 {
				kindKey := parts[1]
				if kindKey == "port_drift_port" {
					kindKey = "port_drift"
				}
				if !activeKinds[kindKey] {
					delete(s.monitorRT.BreachStreaks, k)
					dirty = true
				}
			}
		}
		for i := range s.monitorRT.Alerts {
			al := &s.monitorRT.Alerts[i]
			if al.Status != AlertStatusResolved && !activeKinds[al.RuleKind] {
				al.Status = AlertStatusResolved
				al.ResolvedAt = &now
				al.LastSeenAt = now
				dirty = true
			}
		}
		if activeKinds["port_drift"] {
			if s.reconcilePortDriftRuntimeLocked(outSettings, outRules, allServers, now) > 0 {
				dirty = true
			}
		}
		if dirty {
			s.dirtyMonitor = true
		}
	}
	s.appendAuditRuntimeLocked("monitor.policy_update", "monitor",
		fmt.Sprintf("更新状态监控策略 (快层 %ds / 慢层 %ds / 保留 %d 点 / 连接池=%v)",
			outSettings.IntervalSec, outSettings.SlowIntervalSec, outSettings.RetentionPoints, outSettings.UseSSHConnectionPool),
		clientIP, true)
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

// AcknowledgeMonitorAlertsBulk marks multiple firing alerts (by ID list, server ID, or all) as acknowledged.
func (s *Store) AcknowledgeMonitorAlertsBulk(alertIDs []string, serverID, clientIP string) (int, error) {
	if !s.IsReady() {
		return 0, ErrVaultLocked
	}
	idSet := make(map[string]bool, len(alertIDs))
	for _, id := range alertIDs {
		if trimmed := strings.TrimSpace(id); trimmed != "" {
			idSet[trimmed] = true
		}
	}

	s.rtMu.Lock()
	if s.monitorRT == nil {
		s.rtMu.Unlock()
		return 0, nil
	}
	now := time.Now().UTC()
	acked := 0
	for i := range s.monitorRT.Alerts {
		al := &s.monitorRT.Alerts[i]
		if al.Status != AlertStatusFiring {
			continue
		}
		if len(idSet) > 0 && !idSet[al.ID] {
			continue
		}
		if serverID != "" && al.ServerID != serverID {
			continue
		}
		al.Status = AlertStatusAcknowledged
		al.AcknowledgedAt = &now
		acked++
	}
	if acked > 0 {
		s.dirtyMonitor = true
		target := "alerts"
		if serverID != "" {
			target = serverID
		}
		s.appendAuditRuntimeLocked("monitor.alert_ack_bulk", target, fmt.Sprintf("批量确认知晓监控告警 %d 条", acked), clientIP, true)
	}
	s.rtMu.Unlock()
	if acked > 0 {
		s.triggerFlush()
	}
	return acked, nil
}

// ResolveMonitorAlert manually marks an active alert as resolved and resets its breach streak.
// If the underlying condition remains breached on the next collection sweep, the rule will re-trigger cleanly.
func (s *Store) ResolveMonitorAlert(alertID, clientIP string) (*MonitorAlert, error) {
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
			if al.Status != AlertStatusResolved {
				now := time.Now().UTC()
				al.Status = AlertStatusResolved
				al.ResolvedAt = &now
				al.LastSeenAt = now
				delete(s.monitorRT.BreachStreaks, al.DedupKey)
				s.dirtyMonitor = true
				s.appendAuditRuntimeLocked("monitor.alert_resolve", al.ServerName, "人工标记已解决: "+al.Title, clientIP, true)
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
	return s.ClearResolvedMonitorAlertsForServer("", clientIP)
}

// ClearResolvedMonitorAlertsForServer removes resolved alert incidents globally or scoped to one server.
func (s *Store) ClearResolvedMonitorAlertsForServer(serverID, clientIP string) (int, error) {
	if !s.IsReady() {
		return 0, ErrVaultLocked
	}
	serverID = strings.TrimSpace(serverID)

	s.rtMu.Lock()
	if s.monitorRT == nil {
		s.rtMu.Unlock()
		return 0, nil
	}
	before := len(s.monitorRT.Alerts)
	kept := make([]MonitorAlert, 0, before)
	for _, al := range s.monitorRT.Alerts {
		if al.Status == AlertStatusResolved && (serverID == "" || al.ServerID == serverID) {
			continue
		}
		kept = append(kept, al)
	}
	removed := before - len(kept)
	if removed > 0 {
		s.monitorRT.Alerts = kept
		s.dirtyMonitor = true
		target := "alerts"
		if serverID != "" {
			target = serverID
		}
		s.appendAuditRuntimeLocked("monitor.alerts_clear", target, fmt.Sprintf("清理已恢复历史告警 %d 条", removed), clientIP, true)
	}
	s.rtMu.Unlock()
	if removed > 0 {
		s.triggerFlush()
	}
	return removed, nil
}

// GetLatestMonitorSnapshotsMap returns cloned latest monitor snapshots keyed by server ID.
func (s *Store) GetLatestMonitorSnapshotsMap() map[string]*ServerMonitorSnapshot {
	if !s.IsReady() {
		return map[string]*ServerMonitorSnapshot{}
	}
	s.rtMu.RLock()
	defer s.rtMu.RUnlock()
	if s.monitorRT == nil || len(s.monitorRT.LatestSnapshots) == 0 {
		return map[string]*ServerMonitorSnapshot{}
	}
	out := make(map[string]*ServerMonitorSnapshot, len(s.monitorRT.LatestSnapshots))
	for k, v := range s.monitorRT.LatestSnapshots {
		out[k] = cloneSnapshot(v)
	}
	return out
}

// GetPortBaselinesMap returns cloned trusted port baselines keyed by server ID.
func (s *Store) GetPortBaselinesMap() map[string][]string {
	if !s.IsReady() {
		return map[string][]string{}
	}
	s.rtMu.RLock()
	defer s.rtMu.RUnlock()
	if s.monitorRT == nil || len(s.monitorRT.PortBaselines) == 0 {
		return map[string][]string{}
	}
	out := make(map[string][]string, len(s.monitorRT.PortBaselines))
	for k, v := range s.monitorRT.PortBaselines {
		out[k] = slices.Clone(v)
	}
	return out
}

// reconcilePortDriftRuntimeLocked re-evaluates snapshot ignore flags and active port_drift alerts
// immediately after monitor policy or per-server ignore rules change. Caller must hold s.rtMu.Lock().
func (s *Store) reconcilePortDriftRuntimeLocked(settings MonitorSettings, rules []MonitorAlertRule, servers []ServerConfig, now time.Time) int {
	if s.monitorRT == nil {
		return 0
	}
	var portDriftRule MonitorAlertRule
	for _, r := range rules {
		if r.Kind == "port_drift" {
			portDriftRule = r
			break
		}
	}
	if portDriftRule.Kind == "" {
		portDriftRule = MonitorAlertRule{Kind: "port_drift", Name: "新增对外暴露监听端口漂移"}
	}

	resolvedCnt := 0
	for _, srv := range servers {
		snap := s.monitorRT.LatestSnapshots[srv.ID]
		if snap == nil || len(snap.ListeningPorts) == 0 {
			continue
		}
		AnnotateListeningPorts(snap.ListeningPorts, settings, srv)
		s.dirtyMonitor = true

		baseKeys, hasBase := s.monitorRT.PortBaselines[srv.ID]
		if !hasBase {
			continue
		}
		remaining := ComputeDriftedPorts(snap.ListeningPorts, baseKeys)
		portPrefix := srv.ID + "|port_drift_port|"
		remainingKeys := make(map[string]bool, len(remaining))
		for _, dp := range remaining {
			remainingKeys[portPrefix+fmt.Sprintf("%s/%d", NormalizeBaseProto(dp.Proto), dp.Port)] = true
		}
		for k := range s.monitorRT.BreachStreaks {
			if strings.HasPrefix(k, portPrefix) && !remainingKeys[k] {
				delete(s.monitorRT.BreachStreaks, k)
			}
		}

		for i := range s.monitorRT.Alerts {
			al := &s.monitorRT.Alerts[i]
			if al.ServerID != srv.ID || al.RuleKind != "port_drift" || al.Status == AlertStatusResolved {
				continue
			}
			if len(remaining) == 0 {
				al.Status = AlertStatusResolved
				al.ResolvedAt = &now
				al.LastSeenAt = now
				delete(s.monitorRT.BreachStreaks, fmt.Sprintf("%s|port_drift|", srv.ID))
				resolvedCnt++
			} else {
				breach := BuildPortDriftCandidateBreach(srv, portDriftRule, remaining, 1)
				al.Title = breach.Title
				al.Detail = breach.Detail
				al.MetricText = breach.MetricText
				al.LastSeenAt = now
			}
		}
	}
	return resolvedCnt
}

// ReconcilePortDriftForServer re-annotates a server's latest snapshot and reconciles active port_drift alerts.
func (s *Store) ReconcilePortDriftForServer(serverID string) {
	if !s.IsReady() || strings.TrimSpace(serverID) == "" {
		return
	}
	s.secMu.RLock()
	if s.secrets == nil {
		s.secMu.RUnlock()
		return
	}
	monSettings := cloneMonitorSettings(s.secrets.MonitorSettings)
	rules := slices.Clone(s.secrets.MonitorRules)
	var target *ServerConfig
	for i := range s.secrets.Servers {
		if s.secrets.Servers[i].ID == serverID {
			cp := s.secrets.Servers[i]
			cp.IgnoredPortDriftProcesses = slices.Clone(cp.IgnoredPortDriftProcesses)
			cp.IgnoredPortDriftPorts = slices.Clone(cp.IgnoredPortDriftPorts)
			target = &cp
			break
		}
	}
	s.secMu.RUnlock()
	if target == nil {
		return
	}

	s.rtMu.Lock()
	if s.monitorRT != nil {
		s.reconcilePortDriftRuntimeLocked(monSettings, rules, []ServerConfig{*target}, time.Now().UTC())
	}
	s.rtMu.Unlock()
	s.triggerFlush()
}

// UpdatePortDriftIgnoreRule adds or removes a process or port/range ignore rule globally or per server,
// and immediately reconciles affected snapshots and active port_drift alerts.
func (s *Store) UpdatePortDriftIgnoreRule(req PortDriftIgnoreMutation, clientIP string) (*PortDriftIgnoreResult, error) {
	scope := strings.ToLower(strings.TrimSpace(req.Scope))
	if scope == "" {
		scope = "server"
	}
	if scope != "server" && scope != "global" {
		return nil, fmt.Errorf("%w: scope 仅支持 server 或 global", ErrInvalidInput)
	}
	action := strings.ToLower(strings.TrimSpace(req.Action))
	if action == "" {
		action = "add"
	}
	if action != "add" && action != "remove" {
		return nil, fmt.Errorf("%w: action 仅支持 add 或 remove", ErrInvalidInput)
	}

	rawProc := strings.TrimSpace(req.Process)
	rawPort := strings.TrimSpace(req.Port)
	if (rawProc == "" && rawPort == "") || (rawProc != "" && rawPort != "") {
		return nil, fmt.Errorf("%w: 请指定要忽略的进程名或端口规则（二选一）", ErrInvalidInput)
	}

	var ruleType, canonical string
	var err error
	if rawProc != "" {
		ruleType = "process"
		canonical, err = ValidatePortDriftProcessPattern(rawProc)
	} else {
		ruleType = "port"
		canonical, err = ValidatePortDriftPortSpec(rawPort)
	}
	if err != nil {
		return nil, err
	}

	serverID := strings.TrimSpace(req.ServerID)
	if scope == "server" && serverID == "" {
		return nil, fmt.Errorf("%w: 本机级忽略规则必须提供 server_id", ErrInvalidInput)
	}

	mutateList := func(list []string, item string, remove bool) []string {
		out := make([]string, 0, len(list)+1)
		exists := false
		for _, cur := range list {
			if strings.EqualFold(strings.TrimSpace(cur), item) {
				exists = true
				if remove {
					continue
				}
			}
			out = append(out, cur)
		}
		if !remove && !exists {
			out = append(out, item)
		}
		return out
	}

	var outSettings MonitorSettings
	var outRules []MonitorAlertRule
	var affectedServers []ServerConfig
	var targetName string
	var srvIgnoreProcs, srvIgnorePorts []string

	err = s.mutateSecrets(func(sec *SecretsState) error {
		if scope == "global" {
			if ruleType == "process" {
				sec.MonitorSettings.PortDriftIgnoreProcesses = mutateList(sec.MonitorSettings.PortDriftIgnoreProcesses, canonical, action == "remove")
			} else {
				sec.MonitorSettings.PortDriftIgnorePorts = mutateList(sec.MonitorSettings.PortDriftIgnorePorts, canonical, action == "remove")
			}
			sec.MonitorSettings = sanitizeMonitorSettings(sec.MonitorSettings)
			outSettings = cloneMonitorSettings(sec.MonitorSettings)
			outRules = slices.Clone(sec.MonitorRules)
			affectedServers = cloneServersWithoutRuntime(sec.Servers)
			targetName = "全局策略"
			return nil
		}

		idx := -1
		for i := range sec.Servers {
			if sec.Servers[i].ID == serverID {
				idx = i
				break
			}
		}
		if idx < 0 {
			return ErrNotFound
		}
		srv := sec.Servers[idx]
		if ruleType == "process" {
			srv.IgnoredPortDriftProcesses = SanitizePortDriftProcessPatterns(mutateList(srv.IgnoredPortDriftProcesses, canonical, action == "remove"))
		} else {
			srv.IgnoredPortDriftPorts = SanitizePortDriftPortSpecs(mutateList(srv.IgnoredPortDriftPorts, canonical, action == "remove"))
		}
		srv.UpdatedAt = time.Now().UTC()
		sec.Servers[idx] = srv

		outSettings = cloneMonitorSettings(sec.MonitorSettings)
		outRules = slices.Clone(sec.MonitorRules)
		srvCp := srv
		srvCp.IgnoredPortDriftProcesses = slices.Clone(srv.IgnoredPortDriftProcesses)
		srvCp.IgnoredPortDriftPorts = slices.Clone(srv.IgnoredPortDriftPorts)
		affectedServers = []ServerConfig{srvCp}
		targetName = srv.Name
		srvIgnoreProcs = slices.Clone(srv.IgnoredPortDriftProcesses)
		srvIgnorePorts = slices.Clone(srv.IgnoredPortDriftPorts)
		return nil
	})
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	s.rtMu.Lock()
	resolvedCnt := 0
	if s.monitorRT != nil {
		resolvedCnt = s.reconcilePortDriftRuntimeLocked(outSettings, outRules, affectedServers, now)
	}
	actionVerb := "新增"
	if action == "remove" {
		actionVerb = "移除"
	}
	ruleLabel := "进程"
	if ruleType == "port" {
		ruleLabel = "端口"
	}
	s.appendAuditRuntimeLocked("monitor.port_drift_ignore", targetName,
		fmt.Sprintf("%s端口漂移忽略%s规则: %s（作用域: %s）", actionVerb, ruleLabel, canonical, scope), clientIP, true)
	s.rtMu.Unlock()
	s.triggerFlush()

	if srvIgnoreProcs == nil {
		srvIgnoreProcs = []string{}
	}
	if srvIgnorePorts == nil {
		srvIgnorePorts = []string{}
	}
	return &PortDriftIgnoreResult{
		Scope:                 scope,
		Action:                action,
		ServerID:              serverID,
		AppliedRule:           canonical,
		RuleType:              ruleType,
		ResolvedAlerts:        resolvedCnt,
		GlobalIgnoreProcesses: outSettings.PortDriftIgnoreProcesses,
		GlobalIgnorePorts:     outSettings.PortDriftIgnorePorts,
		ServerIgnoreProcesses: srvIgnoreProcs,
		ServerIgnorePorts:     srvIgnorePorts,
	}, nil
}

// AcceptServerPortBaseline pins the server's current exposed listening ports as its trusted port baseline.
func (s *Store) AcceptServerPortBaseline(serverID, clientIP string) ([]string, error) {
	if !s.IsReady() {
		return nil, ErrVaultLocked
	}

	s.secMu.RLock()
	if s.secrets == nil {
		s.secMu.RUnlock()
		return nil, ErrVaultLocked
	}
	monSettings := cloneMonitorSettings(s.secrets.MonitorSettings)
	var srvCfg ServerConfig
	for i := range s.secrets.Servers {
		if s.secrets.Servers[i].ID == serverID {
			srvCfg = s.secrets.Servers[i]
			srvCfg.IgnoredPortDriftProcesses = slices.Clone(srvCfg.IgnoredPortDriftProcesses)
			srvCfg.IgnoredPortDriftPorts = slices.Clone(srvCfg.IgnoredPortDriftPorts)
			break
		}
	}
	s.secMu.RUnlock()

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
	AnnotateListeningPorts(snap.ListeningPorts, monSettings, srvCfg)
	newBase := ExtractEligiblePublicPortKeys(snap.ListeningPorts)
	s.monitorRT.PortBaselines[serverID] = newBase
	delete(s.monitorRT.BreachStreaks, fmt.Sprintf("%s|port_drift|", serverID))
	portPrefix := serverID + "|port_drift_port|"
	for k := range s.monitorRT.BreachStreaks {
		if strings.HasPrefix(k, portPrefix) {
			delete(s.monitorRT.BreachStreaks, k)
		}
	}

	now := time.Now().UTC()
	for i := range s.monitorRT.Alerts {
		al := &s.monitorRT.Alerts[i]
		if al.ServerID == serverID && al.RuleKind == "port_drift" && al.Status != AlertStatusResolved {
			al.Status = AlertStatusResolved
			al.ResolvedAt = &now
		}
	}
	s.dirtyMonitor = true
	s.appendAuditRuntimeLocked("monitor.port_baseline", snap.ServerName, fmt.Sprintf("确认并更新对外监听端口安全基线 (%d 个端口)", len(newBase)), clientIP, true)
	outBase := slices.Clone(newBase)
	s.rtMu.Unlock()
	s.triggerFlush()
	return outBase, nil
}

// AcceptServerSecurityBaseline pins the server's current critical file hashes, persistence hash, and SSH login IPs.
func (s *Store) AcceptServerSecurityBaseline(serverID, clientIP string) (*ServerSecurityBaseline, error) {
	if !s.IsReady() {
		return nil, ErrVaultLocked
	}

	s.rtMu.Lock()
	if s.monitorRT == nil {
		s.rtMu.Unlock()
		return nil, ErrNotFound
	}
	ensureMonitorRuntimeDefaults(s.monitorRT)
	snap := s.monitorRT.LatestSnapshots[serverID]
	if snap == nil {
		s.rtMu.Unlock()
		return nil, ErrNotFound
	}

	now := time.Now().UTC()
	existing := s.monitorRT.SecurityBaselines[serverID]
	nextBase := cloneSecurityBaseline(existing)
	if len(snap.Security.FileHashes) > 0 {
		nextBase.FileHashes = make(map[string]string, len(snap.Security.FileHashes))
		maps.Copy(nextBase.FileHashes, snap.Security.FileHashes)
	}
	if snap.Security.PersistenceHash != "" {
		nextBase.PersistenceHash = snap.Security.PersistenceHash
	}
	for _, ip := range collectCurrentLoginIPs(snap.Security) {
		if !slices.Contains(nextBase.KnownSSHLoginIPs, ip) {
			nextBase.KnownSSHLoginIPs = append(nextBase.KnownSSHLoginIPs, ip)
		}
	}
	sort.Strings(nextBase.KnownSSHLoginIPs)
	nextBase.UpdatedAt = now

	s.monitorRT.SecurityBaselines[serverID] = nextBase
	snap.Security.FileDrifts = nil
	snap.Security.PersistenceDrifts = nil
	snap.Security.NewSSHLoginIPs = nil

	delete(s.monitorRT.BreachStreaks, fmt.Sprintf("%s|security_file_drift|", serverID))
	delete(s.monitorRT.BreachStreaks, fmt.Sprintf("%s|ssh_new_login_ip|", serverID))
	for i := range s.monitorRT.Alerts {
		al := &s.monitorRT.Alerts[i]
		if al.ServerID == serverID &&
			(al.RuleKind == "security_file_drift" || al.RuleKind == "ssh_new_login_ip") &&
			al.Status != AlertStatusResolved {
			al.Status = AlertStatusResolved
			al.ResolvedAt = &now
		}
	}
	s.dirtyMonitor = true
	s.appendAuditRuntimeLocked("monitor.security_baseline", snap.ServerName,
		fmt.Sprintf("确认并更新主机安全基线 (%d 个关键文件, %d 个已知登录 IP)", len(nextBase.FileHashes), len(nextBase.KnownSSHLoginIPs)),
		clientIP, true)
	out := cloneSecurityBaseline(nextBase)
	s.rtMu.Unlock()
	s.triggerFlush()
	return &out, nil
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

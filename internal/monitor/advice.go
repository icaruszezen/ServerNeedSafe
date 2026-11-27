package monitor

import (
	"fmt"
	"net"
	"regexp"
	"slices"
	"strings"

	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

// AlertCommandSuggestion represents a single copyable / terminal-actionable shell command.
type AlertCommandSuggestion struct {
	Label       string `json:"label"`
	Description string `json:"description,omitempty"`
	Command     string `json:"command"`
	Risk        string `json:"risk"` // "readonly" or "mutating"
}

// AlertQuickAction represents a built-in UI quick-remediation action for an alert.
type AlertQuickAction struct {
	Kind        string `json:"kind"` // "accept_port_baseline", "ignore_port_drift_process", "ignore_port_drift_port", "accept_security_baseline", "open_vault_known_hosts"
	Label       string `json:"label"`
	Description string `json:"description,omitempty"`
	Target      string `json:"target,omitempty"` // Optional rule target (e.g. process name or proto/port for drift ignore)
	Scope       string `json:"scope,omitempty"`  // Optional rule scope ("server" or "global")
}

// AlertRunbookRef points to an existing user-saved AI Runbook relevant to an alert.
type AlertRunbookRef struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Category string `json:"category,omitempty"`
	Symptom  string `json:"symptom,omitempty"`
}

// AlertAdvice provides deterministic, snapshot-aware root-cause analysis and remediation commands.
type AlertAdvice struct {
	Summary      string                   `json:"summary"`
	RootCause    string                   `json:"root_cause,omitempty"`
	Evidence     []string                 `json:"evidence,omitempty"`
	Steps        []string                 `json:"steps,omitempty"`
	Commands     []AlertCommandSuggestion `json:"commands,omitempty"`
	QuickActions []AlertQuickAction       `json:"quick_actions,omitempty"`
	Runbooks     []AlertRunbookRef        `json:"runbooks,omitempty"`
	AIPrompt     string                   `json:"ai_prompt,omitempty"`
	ContextAware bool                     `json:"context_aware"`
}

// EnrichedMonitorAlert embeds MonitorAlert with rule category and live remediation advice.
type EnrichedMonitorAlert struct {
	vault.MonitorAlert
	Category string       `json:"category"`
	Advice   *AlertAdvice `json:"advice,omitempty"`
}

// AlertSummaryStats aggregates live alert counts for KPI cards and filter chips.
type AlertSummaryStats struct {
	TotalActive      int            `json:"total_active"`
	Firing           int            `json:"firing"`
	Acknowledged     int            `json:"acknowledged"`
	Resolved         int            `json:"resolved"`
	CriticalActive   int            `json:"critical_active"`
	WarningActive    int            `json:"warning_active"`
	AffectedServers  int            `json:"affected_servers"`
	ActiveByServer   map[string]int `json:"active_by_server"`
	ActiveByCategory map[string]int `json:"active_by_category"`
}

var (
	ruleCategoryIndex = buildRuleCategoryIndex()
	safeIdentifierRe  = regexp.MustCompile(`^[a-zA-Z0-9._@:/+-]{1,128}$`)
)

func buildRuleCategoryIndex() map[string]string {
	rules := vault.DefaultMonitorAlertRules()
	idx := make(map[string]string, len(rules))
	for _, r := range rules {
		if r.Category != "" {
			idx[r.Kind] = r.Category
		} else {
			idx[r.Kind] = "other"
		}
	}
	return idx
}

// RuleCategoryForKind returns the canonical category key for a monitoring rule kind.
func RuleCategoryForKind(kind string) string {
	if cat, ok := ruleCategoryIndex[kind]; ok {
		return cat
	}
	return "other"
}

// BuildAlertSummary aggregates alert statistics across all alerts (or scoped to serverID if non-empty).
func BuildAlertSummary(alerts []vault.MonitorAlert, serverID string) AlertSummaryStats {
	stats := AlertSummaryStats{
		ActiveByServer:   make(map[string]int),
		ActiveByCategory: make(map[string]int),
	}
	for _, al := range alerts {
		if serverID != "" && al.ServerID != serverID {
			continue
		}
		switch al.Status {
		case vault.AlertStatusFiring:
			stats.Firing++
			stats.TotalActive++
		case vault.AlertStatusAcknowledged:
			stats.Acknowledged++
			stats.TotalActive++
		case vault.AlertStatusResolved:
			stats.Resolved++
		}
		if al.Status != vault.AlertStatusResolved {
			if al.Severity == vault.SeverityCritical {
				stats.CriticalActive++
			} else {
				stats.WarningActive++
			}
			stats.ActiveByServer[al.ServerID]++
			cat := RuleCategoryForKind(al.RuleKind)
			stats.ActiveByCategory[cat]++
		}
	}
	stats.AffectedServers = len(stats.ActiveByServer)
	return stats
}

// EnrichAlerts decorates raw MonitorAlerts with category and deterministic snapshot-aware advice.
func EnrichAlerts(
	alerts []vault.MonitorAlert,
	snapshots map[string]*vault.ServerMonitorSnapshot,
	runbooks []vault.AIRunbook,
) []EnrichedMonitorAlert {
	return EnrichAlertsWithBaselines(alerts, snapshots, nil, runbooks)
}

// EnrichAlertsWithBaselines decorates raw MonitorAlerts using live snapshots and trusted port baselines
// so port_drift advice pinpoints exact newly exposed sockets and dynamic-port processes.
func EnrichAlertsWithBaselines(
	alerts []vault.MonitorAlert,
	snapshots map[string]*vault.ServerMonitorSnapshot,
	portBaselines map[string][]string,
	runbooks []vault.AIRunbook,
) []EnrichedMonitorAlert {
	out := make([]EnrichedMonitorAlert, 0, len(alerts))
	for _, al := range alerts {
		var snap *vault.ServerMonitorSnapshot
		if snapshots != nil {
			snap = snapshots[al.ServerID]
		}
		var base []string
		if portBaselines != nil {
			base = portBaselines[al.ServerID]
		}
		out = append(out, EnrichedMonitorAlert{
			MonitorAlert: al,
			Category:     RuleCategoryForKind(al.RuleKind),
			Advice:       BuildAlertAdviceWithPortBaseline(al, snap, base, runbooks),
		})
	}
	return out
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func sanitizeSafeToken(s string) string {
	trimmed := strings.TrimSpace(s)
	if safeIdentifierRe.MatchString(trimmed) {
		return trimmed
	}
	return ""
}

func sanitizeIP(raw string) string {
	ipStr := strings.TrimSpace(raw)
	if ipStr == "" {
		return ""
	}
	if idx := strings.IndexByte(ipStr, '('); idx > 0 {
		ipStr = strings.TrimSpace(ipStr[:idx])
	}
	if idx := strings.IndexByte(ipStr, ' '); idx > 0 {
		ipStr = strings.TrimSpace(ipStr[:idx])
	}
	if ip := net.ParseIP(ipStr); ip != nil {
		return ip.String()
	}
	return ""
}

func isMacOSSnap(snap *vault.ServerMonitorSnapshot) bool {
	if snap == nil {
		return false
	}
	low := strings.ToLower(snap.OS + " " + snap.Kernel)
	return strings.Contains(low, "darwin") || strings.Contains(low, "macos") || strings.Contains(low, "mac os")
}

func extractDedupSubKey(dedupKey string) string {
	parts := strings.SplitN(dedupKey, "|", 3)
	if len(parts) == 3 {
		return strings.TrimSpace(parts[2])
	}
	return ""
}

func truncateText(s string, maxRunes int) string {
	s = strings.TrimSpace(s)
	runes := []rune(s)
	if len(runes) <= maxRunes {
		return s
	}
	return string(runes[:maxRunes]) + "…"
}

func formatBpsHuman(bps int64) string {
	if bps < 1024 {
		return fmt.Sprintf("%d B/s", bps)
	}
	kb := float64(bps) / 1024
	if kb < 1024 {
		return fmt.Sprintf("%.1f KB/s", kb)
	}
	mb := kb / 1024
	if mb < 1024 {
		return fmt.Sprintf("%.1f MB/s", mb)
	}
	return fmt.Sprintf("%.2f GB/s", mb/1024)
}

func buildFirewallBlockCommand(snap *vault.ServerMonitorSnapshot, ip string) *AlertCommandSuggestion {
	validIP := sanitizeIP(ip)
	if validIP == "" {
		return nil
	}
	fw := ""
	if snap != nil {
		fw = strings.ToLower(snap.Security.FirewallDetail)
	}
	switch {
	case strings.Contains(fw, "ufw"):
		return &AlertCommandSuggestion{
			Label:       fmt.Sprintf("使用 UFW 封禁高频来源 %s", validIP),
			Description: "插入最高优先级拒绝规则阻断该来源 IP 全部入站流量",
			Command:     fmt.Sprintf("sudo ufw insert 1 deny from %s to any", validIP),
			Risk:        "mutating",
		}
	case strings.Contains(fw, "firewalld"):
		family := "ipv4"
		if strings.Contains(validIP, ":") {
			family = "ipv6"
		}
		return &AlertCommandSuggestion{
			Label:       fmt.Sprintf("使用 firewalld 封禁来源 %s", validIP),
			Description: "添加富规则拉黑该 IP 并重载防火墙",
			Command:     fmt.Sprintf("sudo firewall-cmd --permanent --add-rich-rule='rule family=\"%s\" source address=\"%s\" reject' && sudo firewall-cmd --reload", family, validIP),
			Risk:        "mutating",
		}
	case isMacOSSnap(snap):
		return &AlertCommandSuggestion{
			Label:       "查看 macOS pf 防火墙状态",
			Description: "确认当前 pf 防火墙规则后再决定是否追加阻断表",
			Command:     "pfctl -s info",
			Risk:        "readonly",
		}
	default:
		iptBin := "iptables"
		if strings.Contains(validIP, ":") {
			iptBin = "ip6tables"
		}
		return &AlertCommandSuggestion{
			Label:       fmt.Sprintf("使用 %s 临时封禁 %s", iptBin, validIP),
			Description: "在 INPUT 链首部丢弃该来源 IP 数据包（重启前有效）",
			Command:     fmt.Sprintf("sudo %s -I INPUT -s %s -j DROP", iptBin, validIP),
			Risk:        "mutating",
		}
	}
}

func matchRelevantRunbooks(al vault.MonitorAlert, runbooks []vault.AIRunbook) []AlertRunbookRef {
	if len(runbooks) == 0 {
		return nil
	}
	keywordsByKind := map[string][]string{
		"offline":             {"offline", "ssh", "离线", "失联", "网络", "连接"},
		"host_key_changed":    {"host key", "指纹", "ssh", "mitm"},
		"unexpected_reboot":   {"reboot", "重启", "宕机", "panic", "崩溃"},
		"latency_high":        {"latency", "延迟", "网络", "丢包", "跳板"},
		"cpu_high":            {"cpu", "负载", "高占用", "线程"},
		"cpu_steal_high":      {"steal", "cpu", "超售", "虚拟化"},
		"iowait_high":         {"iowait", "io", "磁盘", "存储"},
		"load_high":           {"load", "负载", "cpu", "阻塞"},
		"mem_high":            {"内存", "mem", "memory", "oom", "泄漏"},
		"swap_high":           {"swap", "内存", "交换"},
		"oom_kill":            {"oom", "内存", "killer"},
		"fd_high":             {"fd", "句柄", "open files", "ulimit", "file-max"},
		"zombie_procs":        {"zombie", "僵尸", "进程"},
		"blocked_procs":       {"d态", "阻塞", "nfs", "io", "uninterruptible"},
		"temp_high":           {"温度", "散热", "temp", "风扇"},
		"disk_high":           {"磁盘", "disk", "空间", "满", "日志", "清理"},
		"inode_high":          {"inode", "小文件", "磁盘"},
		"disk_readonly":       {"只读", "read-only", "fsck", "remount", "ext4", "xfs"},
		"disk_will_fill":      {"磁盘", "disk", "日志", "增长", "清理"},
		"raid_degraded":       {"raid", "mdadm", "阵列", "磁盘"},
		"kernel_error":        {"kernel", "内核", "dmesg", "硬件", "i/o error"},
		"systemd_failed":      {"systemd", "服务", "systemctl", "daemon"},
		"docker_unhealthy":    {"docker", "容器", "container", "unhealthy"},
		"tcp_close_wait":      {"close_wait", "syn_recv", "tcp", "socket", "连接泄漏"},
		"net_errors_spike":    {"网卡", "丢包", "错包", "mtu", "nic"},
		"watched_port_down":   {"端口", "port", "listen", "服务"},
		"port_drift":          {"端口", "暴露", "port", "基线"},
		"ssh_bruteforce":      {"ssh", "爆破", "fail2ban", "brute", "登录失败"},
		"uid_zero_backdoor":   {"uid=0", "后门", "特权", "入侵", "passwd"},
		"firewall_inactive":   {"防火墙", "firewall", "ufw", "iptables"},
		"security_file_drift": {"fim", "篡改", "基线", "authorized_keys", "crontab", "入侵"},
		"suspicious_process":  {"挖矿", "反弹", "木马", "可疑进程", "入侵"},
		"suspicious_outbound": {"外联", "木马", "矿池", "入侵"},
		"ssh_new_login_ip":    {"登录", "ssh", "异常ip", "安全"},
		"clock_ntp_drift":     {"ntp", "chrony", "时钟", "时间"},
	}

	kws := keywordsByKind[al.RuleKind]
	if len(kws) == 0 {
		return nil
	}
	var refs []AlertRunbookRef
	for _, rb := range runbooks {
		haystack := strings.ToLower(strings.Join([]string{
			rb.Title, rb.Category, rb.Symptom, rb.RootCause, strings.Join(rb.Tags, " "),
		}, " "))
		matched := false
		for _, kw := range kws {
			if strings.Contains(haystack, strings.ToLower(kw)) {
				matched = true
				break
			}
		}
		if matched {
			refs = append(refs, AlertRunbookRef{
				ID:       rb.ID,
				Title:    rb.Title,
				Category: rb.Category,
				Symptom:  truncateText(rb.Symptom, 90),
			})
			if len(refs) >= 3 {
				break
			}
		}
	}
	return refs
}

func buildAlertAIPrompt(al vault.MonitorAlert, advice *AlertAdvice) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("请协助排查服务器「%s」(%s) 的监控告警：\n", al.ServerName, al.Host))
	sb.WriteString(fmt.Sprintf("- 告警标题：%s\n", al.Title))
	sb.WriteString(fmt.Sprintf("- 规则类型：%s (%s)\n", al.RuleName, al.RuleKind))
	sb.WriteString(fmt.Sprintf("- 严重级别：%s · 当前状态：%s · 累计触发 %d 次\n", al.Severity, al.Status, al.Occurrences))
	if al.MetricText != "" {
		sb.WriteString(fmt.Sprintf("- 实测指标：%s", al.MetricText))
		if al.ThresholdText != "" {
			sb.WriteString(fmt.Sprintf("（阈值条件：%s）", al.ThresholdText))
		}
		sb.WriteString("\n")
	}
	if al.Detail != "" {
		sb.WriteString(fmt.Sprintf("- 告警详情：%s\n", al.Detail))
	}
	if advice != nil && len(advice.Evidence) > 0 {
		sb.WriteString("- 最新监控快照线索：\n")
		for _, ev := range advice.Evidence {
			sb.WriteString("  * " + ev + "\n")
		}
	}
	sb.WriteString("\n请先使用只读探针核实根因与影响范围，再给出安全、可回滚的分步修复方案；涉及修改系统状态的操作请先提交人工审批。")
	return sb.String()
}

// BuildAlertAdvice generates deterministic, context-aware remediation guidance for all 34 alert rule kinds.
func BuildAlertAdvice(al vault.MonitorAlert, snap *vault.ServerMonitorSnapshot, runbooks []vault.AIRunbook) *AlertAdvice {
	return BuildAlertAdviceWithPortBaseline(al, snap, nil, runbooks)
}

// BuildAlertAdviceWithPortBaseline generates deterministic remediation guidance with exact port-baseline diff context.
func BuildAlertAdviceWithPortBaseline(al vault.MonitorAlert, snap *vault.ServerMonitorSnapshot, portBaseline []string, runbooks []vault.AIRunbook) *AlertAdvice {
	mac := isMacOSSnap(snap)
	adv := &AlertAdvice{
		ContextAware: snap != nil && snap.Reachable,
	}

	switch al.RuleKind {
	// =========================================================================
	// 1. Availability & Connectivity
	// =========================================================================
	case "offline":
		adv.Summary = "SSH 采集连续超时或不可达，建议核查目标机电源/网络、防火墙放行与跳板链路状态"
		adv.RootCause = "可能是目标服务器宕机、云安全组/防火墙拦截 SSH 端口、sshd 服务异常、或中转跳板机失联。"
		if snap != nil {
			if snap.RouteLabel != "" {
				adv.Evidence = append(adv.Evidence, fmt.Sprintf("最近探测链路：%s", snap.RouteLabel))
			}
			if snap.Error != "" {
				adv.Evidence = append(adv.Evidence, fmt.Sprintf("最近连接错误：%s", truncateText(snap.Error, 160)))
			}
		}
		adv.Steps = []string{
			"优先通过云厂商控制台 VNC / 带外管理确认主机是否在线及系统是否卡死",
			"核查安全组 / 主机防火墙是否误封 SSH 端口或监控源 IP",
			"若配置了跳板机链路，检查跳板机连通性或开启「跳板失败后直连退避」",
		}
		adv.Commands = []AlertCommandSuggestion{
			{
				Label:       "登录后核查 sshd 服务与最近关机日志",
				Description: "通过 VNC 或恢复连接后检查 SSH 服务状态与最近重启记录",
				Command:     "systemctl status sshd || systemctl status ssh; last -n 5 reboot",
				Risk:        "readonly",
			},
			{
				Label:       "重启 SSH 守护进程",
				Description: "若 sshd 异常卡死，通过控制台尝试重载服务",
				Command:     "sudo systemctl restart sshd || sudo systemctl restart ssh",
				Risk:        "mutating",
			},
		}

	case "host_key_changed":
		adv.Summary = "远端 SSH 主机指纹与已信任记录不一致（已安全拦截），请先核实是否重装系统或存在中间人劫持"
		adv.RootCause = "重装系统、更换云主机 EIP、重建容器或遭遇 MITM 中间人攻击均会导致主机公钥指纹突变。"
		if snap != nil && snap.HostKeyMismatchDetail != "" {
			adv.Evidence = append(adv.Evidence, truncateText(snap.HostKeyMismatchDetail, 180))
		}
		adv.Steps = []string{
			"通过云控制台或独立可信渠道核对目标机当前 /etc/ssh/ssh_host_*_key.pub 指纹",
			"若确认属于合法重装或迁移，前往「安全保险库 → 已信任主机指纹」移除旧指纹后再重新连接信任",
			"若非预期变更，切勿信任新指纹，立即排查网络路由、DNS 与公网 IP 绑定情况",
		}
		adv.Commands = []AlertCommandSuggestion{
			{
				Label:       "在目标机控制台核验本机 SSH 公钥指纹",
				Description: "打印目标机所有 SSH Host Key 的 SHA256 指纹与告警指纹逐位比对",
				Command:     "for f in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -lf \"$f\"; done",
				Risk:        "readonly",
			},
		}
		adv.QuickActions = append(adv.QuickActions, AlertQuickAction{
			Kind:        "open_vault_known_hosts",
			Label:       "核查已信任主机指纹",
			Description: "跳转到「安全保险库」查看或删除该主机的旧 SSH 指纹",
		})

	case "unexpected_reboot":
		adv.Summary = "主机运行时间回落，建议排查内核崩溃 (Kernel Panic)、宿主机迁移或异常掉电日志"
		adv.RootCause = "内核崩溃、OOM 级联死机、云宿主机热迁移失败或运维人员未报备重启均会导致 Uptime 回落。"
		if snap != nil {
			if snap.BootTime != "" {
				adv.Evidence = append(adv.Evidence, fmt.Sprintf("最近启动时间：%s（已运行 %s）", snap.BootTime, snap.Uptime))
			}
			if snap.OOMKills > 0 {
				adv.Evidence = append(adv.Evidence, fmt.Sprintf("累计 OOM Kill 次数：%d", snap.OOMKills))
			}
		}
		adv.Steps = []string{
			"查看最近启动历史与重启前最后一条内核/系统日志，判断是优雅关机还是硬掉电",
			"核对业务守护服务、Docker 容器及挂载盘在重启后是否均已自启恢复",
		}
		if mac {
			adv.Commands = []AlertCommandSuggestion{
				{
					Label:       "查看 macOS 启动与关机原因日志",
					Description: "查询最近重启时间及电源/关机原因码",
					Command:     "last -n 10 reboot; log show --predicate 'eventMessage contains \"Previous shutdown cause\"' --last 24h",
					Risk:        "readonly",
				},
			}
		} else {
			adv.Commands = []AlertCommandSuggestion{
				{
					Label:       "查看最近重启记录与上次启动末尾日志",
					Description: "对比 reboot/crash 记录并拉取上一次启动 (-b -1) 末尾日志",
					Command:     "last -x -n 10 reboot shutdown; journalctl -b -1 -n 60 --no-pager 2>/dev/null || dmesg -T | tail -n 50",
					Risk:        "readonly",
				},
				{
					Label:       "检查重启后故障 Systemd 单元",
					Description: "确认是否有关键服务重启后未能自动拉起",
					Command:     "systemctl --failed --no-pager",
					Risk:        "readonly",
				},
			}
		}

	case "latency_high":
		adv.Summary = "SSH 链路响应延迟偏高，建议排查跨区网络抖动、跳板机负载及目标机 CPU 调度拥塞"
		adv.RootCause = "跨运营商路由丢包、跳板机带宽打满、目标机高负载或 sshd DNS 反向解析 (UseDNS yes) 都会显著拉高延迟。"
		if snap != nil {
			if snap.RouteLabel != "" {
				adv.Evidence = append(adv.Evidence, fmt.Sprintf("当前连接线路：%s（延迟 %d ms）", snap.RouteLabel, snap.LatencyMs))
			}
			if snap.CPUPercent > 70 {
				adv.Evidence = append(adv.Evidence, fmt.Sprintf("目标机 CPU 偏高：%.1f%%（Load1 %.2f）", snap.CPUPercent, snap.Load1))
			}
		}
		adv.Steps = []string{
			"确认目标机 sshd_config 中 UseDNS no 与 GSSAPIAuthentication no 以避免握手卡顿",
			"排查网卡丢包率、出口带宽打满以及跳板机延迟情况",
		}
		adv.Commands = []AlertCommandSuggestion{
			{
				Label:       "检查 sshd 握手慢配置项 (UseDNS / GSSAPI)",
				Description: "核对 sshd 有效配置是否存在阻塞登录的反向解析",
				Command:     "sshd -T 2>/dev/null | grep -E '^(usedns|gssapiauthentication)' || grep -E 'UseDNS|GSSAPI' /etc/ssh/sshd_config",
				Risk:        "readonly",
			},
			{
				Label:       "查看网卡实时流量与错误计数",
				Description: "定位是否存在链路拥塞或持续丢包",
				Command:     "ip -s link show",
				Risk:        "readonly",
			},
		}

	// =========================================================================
	// 2. Compute, Memory & Kernel
	// =========================================================================
	case "cpu_high":
		topProc := firstTopCPUProc(snap)
		if topProc != nil {
			adv.Summary = fmt.Sprintf("高负载进程 %s (PID %d, CPU %.1f%%)，建议先排查线程栈与近期变更", truncateText(topProc.Command, 32), topProc.PID, topProc.CPUPercent)
			for i, p := range snap.TopCPUProcs {
				if i >= 3 {
					break
				}
				adv.Evidence = append(adv.Evidence, fmt.Sprintf("Top CPU #%d: PID %d (%s) CPU %.1f%% / Mem %.1f%% — %s", i+1, p.PID, p.User, p.CPUPercent, p.MemPercent, truncateText(p.Command, 70)))
			}
		} else {
			adv.Summary = "CPU 持续高占用，建议立即定位 Top 进程与线程热点，区分业务突发、死循环或异常挖矿进程"
		}
		adv.RootCause = "常见原因包括突发流量、应用代码死循环/GC 风暴、数据库全表扫描，或未授权计算任务占用算力。"
		adv.Steps = []string{
			"先确认高占用进程归属（业务进程 vs 计划任务 vs 异常未知进程）",
			"若为已知业务进程，采集线程热点或堆栈后平滑限流/重启；若为异常进程，留存证据后终止",
		}
		if mac {
			adv.Commands = append(adv.Commands, AlertCommandSuggestion{
				Label:       "查看实时 CPU 占用 Top 15 进程 (macOS)",
				Description: "按 CPU 降序输出进程详情",
				Command:     "ps aux -r | head -n 16",
				Risk:        "readonly",
			})
		} else {
			adv.Commands = append(adv.Commands, AlertCommandSuggestion{
				Label:       "查看 CPU 占用 Top 15 进程与命令行",
				Description: "按 CPU 使用率降序查看完整启动参数",
				Command:     "ps -eo pid,ppid,user,%cpu,%mem,stat,etime,args --sort=-%cpu | head -n 16",
				Risk:        "readonly",
			})
			if topProc != nil && topProc.PID > 1 {
				adv.Commands = append(adv.Commands,
					AlertCommandSuggestion{
						Label:       fmt.Sprintf("定位进程 PID %d 的高 CPU 线程", topProc.PID),
						Description: "查看该进程内部消耗 CPU 最高的线程 TID 与状态",
						Command:     fmt.Sprintf("ps -Lp %d -o pid,tid,%%cpu,stat,comm --sort=-%%cpu | head -n 15", topProc.PID),
						Risk:        "readonly",
					},
					AlertCommandSuggestion{
						Label:       fmt.Sprintf("温和终止进程 PID %d (SIGTERM)", topProc.PID),
						Description: "确认属于失控或异常进程后发送 SIGTERM 停止（请先核实进程归属）",
						Command:     fmt.Sprintf("kill -15 %d", topProc.PID),
						Risk:        "mutating",
					},
				)
			}
		}

	case "cpu_steal_high":
		adv.Summary = "云宿主机 CPU 算力被邻居抢占 (Steal 过高)，宿主机可能超售或突发实例积分耗尽"
		adv.RootCause = "虚拟化层宿主机物理核竞争激烈，或 T/突发性能实例 CPU 积分归零，导致虚拟机就绪任务长时间等待宿主机调度。"
		if snap != nil {
			adv.Evidence = append(adv.Evidence, fmt.Sprintf("CPU Steal %.1f%% / 总 CPU %.1f%% / 虚拟化 %s", snap.CPUStealPct, snap.CPUPercent, fallbackStr(snap.Virtualization, "云主机")))
		}
		adv.Steps = []string{
			"检查云控制台是否属于突发性能实例（如 t3/t6）且 CPU 积分已耗尽",
			"若持续 Steal > 15%，通过云厂商停止再启动（热迁换宿主机）或升级至独享计算型规格",
		}
		adv.Commands = []AlertCommandSuggestion{
			{
				Label:       "持续 5 秒观测 CPU Steal (%st) 波动",
				Description: "使用 vmstat 按秒采样查看 st 列变化",
				Command:     "vmstat 1 5",
				Risk:        "readonly",
			},
		}

	case "iowait_high":
		adv.Summary = "CPU 等待磁盘 I/O 占比过高，建议立即排查高读写进程、磁盘吞吐瓶颈与阻塞队列"
		adv.RootCause = "大量随机读写、未加索引的数据库查询、日志刷盘风暴、备份任务或底层云盘 IOPS 触顶会直接推高 IOWait。"
		if snap != nil {
			adv.Evidence = append(adv.Evidence, fmt.Sprintf("IOWait %.1f%% · 磁盘读 %s / 写 %s · IOPS %d · D 态阻塞 %d 个", snap.CPUIowaitPct, formatBpsHuman(snap.DiskReadBps), formatBpsHuman(snap.DiskWriteBps), snap.DiskIOPS, snap.ProcsBlocked))
		}
		adv.Steps = []string{
			"使用 iostat / pidstat 定位是哪块块设备和哪个进程打满了磁盘 IOPS",
			"对备份/压缩/日志归档等离线任务使用 ionice 降级 I/O 优先级",
		}
		adv.Commands = []AlertCommandSuggestion{
			{
				Label:       "查看磁盘设备队列深度与读写等待",
				Description: "输出各块设备 await 与 %util 利用率",
				Command:     "iostat -xz 1 3 2>/dev/null || vmstat 1 3",
				Risk:        "readonly",
			},
			{
				Label:       "定位高磁盘 I/O 进程与 D 态阻塞进程",
				Description: "排查正在密集读写磁盘或阻塞在 I/O 的进程",
				Command:     "ps -eo pid,user,stat,%cpu,wchan:24,args | awk '$3 ~ /D/ || NR==1' | head -n 25",
				Risk:        "readonly",
			},
		}

	case "load_high":
		adv.Summary = "单核归一化负载过高，建议区分是 CPU 算力饱和 (R 态) 还是磁盘/NFS I/O 阻塞 (D 态)"
		adv.RootCause = "Linux Load Average 同时计入可运行 (R) 和不可中断等待 (D) 进程；高 Load + 低 CPU 往往指向磁盘/NFS 卡顿。"
		if snap != nil {
			adv.Evidence = append(adv.Evidence, fmt.Sprintf("Load %.2f / %.2f / %.2f（%d 核 · %.2fx）· CPU %.1f%% · R=%d / D=%d", snap.Load1, snap.Load5, snap.Load15, snap.CPUCores, snap.LoadPerCore, snap.CPUPercent, snap.ProcsRunning, snap.ProcsBlocked))
		}
		adv.Steps = []string{
			"对照当前 CPU% 与 D 态进程数：CPU 高则查计算热点，D 态多则查磁盘与网络挂载",
			"按需对突发任务限流或排查上游重试风暴",
		}
		adv.Commands = []AlertCommandSuggestion{
			{
				Label:       "查看 R 态运行与 D 态阻塞进程分布",
				Description: "快速判断高 Load 是由计算竞争还是 I/O 阻塞引起",
				Command:     "ps -eo pid,user,stat,%cpu,%mem,wchan:20,args --sort=-%cpu | head -n 20",
				Risk:        "readonly",
			},
			{
				Label:       "检查系统综合运行队列 (vmstat)",
				Description: "观察 r(运行队列)、b(阻塞队列) 与 si/so(换页)",
				Command:     "vmstat 1 5",
				Risk:        "readonly",
			},
		}

	case "mem_high":
		topMem := firstTopMemProc(snap)
		if topMem != nil {
			adv.Summary = fmt.Sprintf("物理内存紧张，最高占用进程 %s (PID %d, %.1f%% / %.0f MB)，建议核查内存泄漏或缓存配置", truncateText(topMem.Command, 32), topMem.PID, topMem.MemPercent, topMem.RSSMB)
			for i, p := range snap.TopMemProcs {
				if i >= 3 {
					break
				}
				adv.Evidence = append(adv.Evidence, fmt.Sprintf("Top Mem #%d: PID %d (%s) %.1f%% (%.0f MB RSS) — %s", i+1, p.PID, p.User, p.MemPercent, p.RSSMB, truncateText(p.Command, 70)))
			}
		} else {
			adv.Summary = "物理内存占用逼近上限，存在 OOM Killer 击杀业务进程风险，建议尽快排查内存大户"
		}
		adv.RootCause = "应用内存泄漏、JVM/Redis/MySQL 缓冲池配置过高、并发连接数激增或容器未设置合理内存上限。"
		adv.Steps = []string{
			"核对 Top 内存进程 RSS 与历史趋势，判断是持续缓慢泄漏还是配置上限过大",
			"为关键容器/服务设置 MemoryMax 限额，必要时低峰期滚动重启泄漏进程并抓取 heap dump",
		}
		if mac {
			adv.Commands = append(adv.Commands, AlertCommandSuggestion{
				Label:       "查看内存占用 Top 15 进程 (macOS)",
				Description: "按物理内存降序排查大户进程",
				Command:     "ps aux -m | head -n 16",
				Risk:        "readonly",
			})
		} else {
			adv.Commands = append(adv.Commands,
				AlertCommandSuggestion{
					Label:       "查看物理内存明细与 Top 15 内存进程",
					Description: "核对可用内存、Slab 缓存及高 RSS 进程",
					Command:     "free -h && ps -eo pid,user,%mem,rss,vsz,args --sort=-rss | head -n 16",
					Risk:        "readonly",
				},
				AlertCommandSuggestion{
					Label:       "检查内核 Slab 缓存占用 (防内核泄漏)",
					Description: "排查是否存在 dentry/inode 等内核缓存异常膨胀",
					Command:     "cat /proc/meminfo | grep -E 'MemTotal|MemAvailable|Cached|Slab|SReclaimable|SUnreclaim|AnonPages'",
					Risk:        "readonly",
				},
			)
		}

	case "swap_high":
		adv.Summary = "Swap 交换分区大量使用，频繁换页会导致业务响应抖动变慢，建议排查占用 Swap 的进程"
		adv.RootCause = "物理内存曾出现持续吃紧或 vm.swappiness 配置过高，导致匿名页被换出到磁盘。"
		if snap != nil {
			adv.Evidence = append(adv.Evidence, fmt.Sprintf("Swap 已用 %d / %d MB (%.1f%%) · 物理内存 %.1f%%", snap.SwapUsedMB, snap.SwapTotalMB, snap.SwapPercent, snap.MemPercent))
		}
		adv.Steps = []string{
			"找出占用 Swap 最多的进程并观察 vmstat si/so 是否持续发生换页抖动",
			"在物理内存充足前提下可调低 vm.swappiness（如 10）或滚动重启高 Swap 进程释放",
		}
		adv.Commands = []AlertCommandSuggestion{
			{
				Label:       "定位占用 Swap 最高的 Top 15 进程",
				Description: "统计各进程 /proc/<pid>/status 中的 VmSwap 大小",
				Command:     "for f in /proc/[0-9]*/status; do awk '/^Name:/{n=$2} /^Pid:/{p=$2} /^VmSwap:/{if($2>0) printf \"%8d kB  PID=%-6s %s\\n\",$2,p,n}' \"$f\" 2>/dev/null; done | sort -rn | head -n 15",
				Risk:        "readonly",
			},
			{
				Label:       "查看当前 swappiness 与换页速率",
				Description: "检查内核倾向与 si/so 实时换入换出",
				Command:     "sysctl vm.swappiness && vmstat 1 3",
				Risk:        "readonly",
			},
		}

	case "oom_kill":
		adv.Summary = "内核 OOM Killer 已触发进程强杀，建议立即查明被杀进程并评估内存限额或扩容"
		adv.RootCause = "系统或 Cgroup 内存彻底耗尽，Linux 内核为保活系统强制 SIGKILL 了内存评分最高的进程。"
		if snap != nil {
			adv.Evidence = append(adv.Evidence, fmt.Sprintf("本周期新增 OOM Kill %d 次（累计 %d 次）· 当前内存 %.1f%%", snap.OOMKillsDelta, snap.OOMKills, snap.MemPercent))
		}
		adv.Steps = []string{
			"第一时间从 dmesg / journalctl 确认被击杀的具体进程名、PID 及是否属容器 Cgroup OOM",
			"确认受影响业务服务是否已自动拉起，随后排查内存泄漏或调整容器内存限制/扩容主机内存",
		}
		adv.Commands = []AlertCommandSuggestion{
			{
				Label:       "检索内核 OOM Killer 击杀记录",
				Description: "列出被击杀的进程名、PID 及触发时的内存上下文",
				Command:     "dmesg -T | grep -iE 'out of memory|killed process|oom-killer' | tail -n 30",
				Risk:        "readonly",
			},
			{
				Label:       "检查当前内存占用 Top 10 进程",
				Description: "识别当前可能再次触发 OOM 的高内存进程",
				Command:     "ps -eo pid,user,%mem,rss,args --sort=-rss | head -n 11",
				Risk:        "readonly",
			},
		}

	case "fd_high":
		adv.Summary = "内核文件句柄使用率过高，耗尽后将导致新连接拒绝 (Too many open files)，建议排查句柄泄漏进程"
		adv.RootCause = "应用未正确关闭 Socket/文件流，或高并发代理/数据库进程数增长超过了系统 fs.file-max 上限。"
		if snap != nil {
			adv.Evidence = append(adv.Evidence, fmt.Sprintf("已分配 FD %d / 上限 %d (%.1f%%)", snap.FDUsed, snap.FDMax, snap.FDPercent))
		}
		adv.Steps = []string{
			"统计打开文件描述符最多的进程，核查其打开的句柄类型（Socket 还是未关闭文件）",
			"若属正常业务高并发增长，调高 /etc/sysctl.conf 的 fs.file-max 及服务 LimitNOFILE",
		}
		adv.Commands = []AlertCommandSuggestion{
			{
				Label:       "统计打开文件句柄最多的 Top 15 进程",
				Description: "遍历 /proc/<pid>/fd 快速找出句柄大户",
				Command:     "for p in /proc/[0-9]*; do pid=${p#/proc/}; cnt=$(ls -1 \"$p/fd\" 2>/dev/null | wc -l); [ \"$cnt\" -gt 50 ] && printf \"%7d  PID=%-6s %s\\n\" \"$cnt\" \"$pid\" \"$(cat $p/comm 2>/dev/null)\"; done | sort -rn | head -n 15",
				Risk:        "readonly",
			},
			{
				Label:       "查看系统当前 file-nr 与 file-max 配置",
				Description: "核对内核已分配句柄数与上限",
				Command:     "cat /proc/sys/fs/file-nr && sysctl fs.file-max",
				Risk:        "readonly",
			},
		}

	case "zombie_procs":
		adv.Summary = "检测到大量僵尸进程 (Z 态)，说明父进程未回收子进程退出状态，需排查父进程而非直接 kill 僵尸进程"
		adv.RootCause = "僵尸进程已退出仅残留进程表项（直接 kill -9 无效），常见于父进程未调用 wait() 或容器内 PID 1 未处理信号回收。"
		if snap != nil {
			adv.Evidence = append(adv.Evidence, fmt.Sprintf("当前僵尸进程 %d 个（总进程 %d 个）", snap.ProcsZombie, snap.ProcsTotal))
		}
		adv.Steps = []string{
			"查出僵尸进程对应的父进程 (PPID) 及所属服务或容器",
			"向父进程发送 SIGCHLD 或平滑重启父进程以回收残留子进程（容器场景建议使用 tini / --init）",
		}
		adv.Commands = []AlertCommandSuggestion{
			{
				Label:       "列出僵尸进程及其父进程 (PPID) 统计",
				Description: "找出产生最多僵尸进程的父进程 PID 与命令",
				Command:     "ps -eo stat,pid,ppid,user,args | awk '$1 ~ /^Z/ {print}' | head -n 30",
				Risk:        "readonly",
			},
			{
				Label:       "按父进程聚合僵尸进程数量",
				Description: "快速锁定需要重启或修复的罪魁父进程",
				Command:     "ps -eo stat,ppid | awk '$1 ~ /^Z/ {c[$2]++} END {for (p in c) print c[p], p}' | sort -rn | head -n 10",
				Risk:        "readonly",
			},
		}

	case "blocked_procs":
		adv.Summary = "存在大量不可中断阻塞进程 (D 态)，通常指向本地磁盘卡死或远程 NFS/CIFS 挂载无响应"
		adv.RootCause = "进程陷入内核态 I/O 等待（无法被 kill -9 终止），高发于故障磁盘坏道、云盘 I/O 挂起或断联的 hard NFS 挂载。"
		if snap != nil {
			adv.Evidence = append(adv.Evidence, fmt.Sprintf("D 态阻塞进程 %d 个 · IOWait %.1f%%", snap.ProcsBlocked, snap.CPUIowaitPct))
			if len(snap.RemoteMounts) > 0 {
				adv.Evidence = append(adv.Evidence, "已检测到远程挂载点："+strings.Join(snap.RemoteMounts, ", "))
			}
		}
		adv.Steps = []string{
			"检查所有 D 态进程的内核等待函数 (wchan) 与内核日志 dmesg",
			"若卡在 NFS/CIFS 挂载点，先恢复对端存储服务或执行懒卸载 (umount -l)",
		}
		adv.Commands = []AlertCommandSuggestion{
			{
				Label:       "查看所有 D 态阻塞进程及内核等待点 (wchan)",
				Description: "通过 wchan 判断是卡在磁盘块设备还是 NFS 网络存储",
				Command:     "ps -eo pid,user,stat,wchan:28,args | awk '$3 ~ /D/ || NR==1'",
				Risk:        "readonly",
			},
			{
				Label:       "检查内核 I/O 超时与 NFS 失联日志",
				Description: "查看是否存在 hung_task 或 nfs server not responding",
				Command:     "dmesg -T | grep -iE 'blocked for more than|hung_task|nfs|i/o error|reset' | tail -n 30",
				Risk:        "readonly",
			},
		}

	case "temp_high":
		adv.Summary = "物理节点 CPU 硬件温度偏高，建议排查风扇散热、机房环境温度及持续满载进程"
		adv.RootCause = "散热器积灰、风扇故障、机柜通风不良或高算力任务长时间满载导致热堆积，过高温度会触发降频甚至热关机。"
		if snap != nil && snap.CPUTempC > 0 {
			adv.Evidence = append(adv.Evidence, fmt.Sprintf("当前传感器温度 %.1f°C · CPU 使用率 %.1f%%", snap.CPUTempC, snap.CPUPercent))
		}
		adv.Steps = []string{
			"查看所有热传感器读数与风扇转速（sensors / ipmitool）",
			"排查高 CPU 占用进程，必要时降低负载并联系机房巡检散热硬件",
		}
		adv.Commands = []AlertCommandSuggestion{
			{
				Label:       "查看全部硬件温度与风扇传感器",
				Description: "读取 lm-sensors 或热区文件温度信息",
				Command:     "sensors 2>/dev/null || paste <(cat /sys/class/thermal/thermal_zone*/type 2>/dev/null) <(cat /sys/class/thermal/thermal_zone*/temp 2>/dev/null)",
				Risk:        "readonly",
			},
			{
				Label:       "查看当前高 CPU 负载进程",
				Description: "确认是否存在异常满载推高发热",
				Command:     "ps -eo pid,user,%cpu,args --sort=-%cpu | head -n 12",
				Risk:        "readonly",
			},
		}

	// =========================================================================
	// 3. Storage & Hardware Stability
	// =========================================================================
	case "disk_high", "disk_will_fill":
		mount := extractDedupSubKey(al.DedupKey)
		if mount == "" && snap != nil {
			if al.RuleKind == "disk_will_fill" && snap.DiskFullForecastMount != "" {
				mount = snap.DiskFullForecastMount
			} else if snap.MaxPartMount != "" {
				mount = snap.MaxPartMount
			}
		}
		if mount == "" {
			mount = "/"
		}
		if snap != nil {
			for _, d := range snap.Disks {
				if d.MountPoint == mount || (mount == "/" && len(snap.Disks) == 1) {
					adv.Evidence = append(adv.Evidence, fmt.Sprintf("分区 %s (%s, %s)：已用 %.1f / %.1f GB (%.1f%%)，仅剩 %.1f GB", d.MountPoint, d.Device, d.FSType, d.UsedGB, d.TotalGB, d.UsedPercent, d.AvailGB))
					break
				}
			}
			if snap.DiskFullForecastHours > 0 {
				adv.Evidence = append(adv.Evidence, fmt.Sprintf("线性增长预测：按当前增速约 %.1f 小时后写满", snap.DiskFullForecastHours))
			}
		}
		if al.RuleKind == "disk_will_fill" {
			adv.Summary = fmt.Sprintf("分区 %s 容量增长过快，建议立即定位正在持续膨胀的日志、临时文件或 Docker 镜像层", mount)
		} else {
			adv.Summary = fmt.Sprintf("分区 %s 空间即将耗尽，建议优先定位大目录、已删除未释放句柄及系统/容器日志", mount)
		}
		adv.RootCause = "应用日志未配置 logrotate、systemd journal 堆积、Docker 容器日志与废弃镜像膨胀，或已删除大文件仍被进程占用句柄。"
		adv.Steps = []string{
			fmt.Sprintf("先定位分区 %s 内占用最大的前 15 个目录，以及已删除但句柄未释放的幽灵大文件", mount),
			"优先清理可安全回收的 journald 历史日志、旧归档日志或 Docker 悬空资源；禁止直接 rm 正在写入的活跃日志（建议用 truncate -s 0）",
			"清理后检查并完善 logrotate / Docker daemon.json 日志大小限制",
		}
		quotedMount := shellQuote(mount)
		adv.Commands = append(adv.Commands,
			AlertCommandSuggestion{
				Label:       fmt.Sprintf("定位分区 %s 占用最大的 Top 15 目录", mount),
				Description: "使用 -x 仅扫描当前挂载分区，避免跨分区扫描",
				Command:     fmt.Sprintf("du -xh -d 2 %s 2>/dev/null | sort -rh | head -n 15", quotedMount),
				Risk:        "readonly",
			},
			AlertCommandSuggestion{
				Label:       "排查已删除但仍被进程占用空间的文件 (deleted)",
				Description: "若 df 与 du 统计差距大，通常存在未释放文件句柄",
				Command:     "lsof +L1 2>/dev/null | awk 'NR==1 || $7 > 52428800' | head -n 25",
				Risk:        "readonly",
			},
		)
		if !mac {
			adv.Commands = append(adv.Commands, AlertCommandSuggestion{
				Label:       "安全裁剪 systemd journald 历史日志至 200MB",
				Description: "仅清理旧归档日志，不影响当前正在运行的业务进程",
				Command:     "sudo journalctl --vacuum-size=200M",
				Risk:        "mutating",
			})
		}
		if snap != nil && snap.Docker.Installed {
			adv.Commands = append(adv.Commands,
				AlertCommandSuggestion{
					Label:       "查看 Docker 磁盘空间占用明细",
					Description: "检查镜像、停止容器与构建缓存占用情况",
					Command:     "docker system df",
					Risk:        "readonly",
				},
				AlertCommandSuggestion{
					Label:       "清理 Docker 未使用的构建缓存与悬空镜像",
					Description: "仅清理无标签悬空资源，不删除正在使用的容器卷",
					Command:     "docker image prune -f && docker builder prune -f",
					Risk:        "mutating",
				},
			)
		}

	case "inode_high":
		mount := extractDedupSubKey(al.DedupKey)
		if mount == "" && snap != nil && snap.MaxInodeMount != "" {
			mount = snap.MaxInodeMount
		}
		if mount == "" {
			mount = "/"
		}
		adv.Summary = fmt.Sprintf("分区 %s 的 Inode 索引节点接近耗尽，即使磁盘还有空间也会报 No space left on device", mount)
		adv.RootCause = "通常是临时目录 (/tmp)、邮件队列 (/var/spool)、PHP Session 或缓存目录堆积了数十万个微小文件。"
		if snap != nil {
			for _, d := range snap.Disks {
				if d.MountPoint == mount {
					adv.Evidence = append(adv.Evidence, fmt.Sprintf("分区 %s Inode 占用 %.1f%%（容量占用 %.1f%%）", d.MountPoint, d.InodePercent, d.UsedPercent))
					break
				}
			}
		}
		adv.Steps = []string{
			fmt.Sprintf("统计分区 %s 下文件数量最多的子目录，精准定位小文件风暴来源", mount),
			"使用 find 分批安全清理过期临时文件/缓存（避免 rm * 参数过长），并排查生成源头",
		}
		quotedMount := shellQuote(mount)
		if mac {
			adv.Commands = []AlertCommandSuggestion{
				{
					Label:       fmt.Sprintf("排查分区 %s Inode 使用与大目录 (macOS)", mount),
					Description: "查看 Inode 占用并统计一级子目录大小",
					Command:     fmt.Sprintf("df -hi %s && du -xh -d 2 %s 2>/dev/null | sort -rh | head -n 15", quotedMount, quotedMount),
					Risk:        "readonly",
				},
			}
		} else {
			adv.Commands = []AlertCommandSuggestion{
				{
					Label:       fmt.Sprintf("排查分区 %s 下文件数最多的目录", mount),
					Description: "统计一级/二级子目录文件数排行以定位小文件堆积点",
					Command:     fmt.Sprintf("df -hi %s && find %s -xdev -printf '%%h\\n' 2>/dev/null | sort | uniq -c | sort -rn | head -n 15", quotedMount, quotedMount),
					Risk:        "readonly",
				},
			}
		}

	case "disk_readonly":
		roMounts := ""
		if snap != nil && len(snap.ReadOnlyMounts) > 0 {
			roMounts = strings.Join(snap.ReadOnlyMounts, ", ")
			adv.Evidence = append(adv.Evidence, "检测到只读挂载点："+roMounts)
		}
		adv.Summary = "文件系统已被内核强制保护性重挂载为只读 (RO)，写入均会失败，务必先查硬件错误再做修复"
		adv.RootCause = "底层磁盘坏道、云盘瞬断或文件系统元数据损坏触发了 errors=remount-ro 内核保护机制。"
		adv.Steps = []string{
			"切勿盲目直接 remount rw，先检查 dmesg 内核磁盘/文件系统错误与云盘健康状态",
			"优先对关键业务数据做快照或只读备份，随后在维护窗口卸载分区执行 fsck / xfs_repair",
		}
		adv.Commands = []AlertCommandSuggestion{
			{
				Label:       "核查当前只读挂载点与内核磁盘报错",
				Description: "确认受影响设备及触发 remount-ro 的具体内核报错",
				Command:     "mount | grep -E '\\(ro,|\\(ro\\)' && dmesg -T | grep -iE 'remount|ext4|xfs|i/o error|blk_update_request' | tail -n 30",
				Risk:        "readonly",
			},
			{
				Label:       "检查块设备挂载与文件系统类型",
				Description: "核对挂载设备与 UUID 信息供维护窗口 fsck 使用",
				Command:     "lsblk -f",
				Risk:        "readonly",
			},
		}

	case "raid_degraded":
		adv.Summary = "软 RAID 阵列已降级，冗余能力丧失，请立即定位故障成员盘并准备热备/更换磁盘"
		adv.RootCause = "/proc/mdstat 检测到阵列中存在离线 (F) 或缺失成员盘，若再损坏一块盘将导致数据不可逆丢失。"
		if snap != nil && len(snap.RAIDDegraded) > 0 {
			for _, rd := range snap.RAIDDegraded {
				adv.Evidence = append(adv.Evidence, "异常阵列："+rd)
			}
		}
		adv.Steps = []string{
			"查看 /proc/mdstat 与 mdadm --detail 确认具体故障盘符与阵列健康度",
			"核查业务备份完整性，联系机房/云运维更换故障盘后重新加入阵列同步 (rebuild)",
		}
		adv.Commands = []AlertCommandSuggestion{
			{
				Label:       "查看软 RAID 阵列详细状态与故障成员盘",
				Description: "读取 /proc/mdstat 与全部 md 设备详情",
				Command:     "cat /proc/mdstat && sudo mdadm --detail --scan && lsblk -o NAME,SIZE,MODEL,SERIAL,FSTYPE,MOUNTPOINT",
				Risk:        "readonly",
			},
		}

	case "kernel_error":
		adv.Summary = "内核日志捕获硬件、磁盘 I/O 或文件系统严重错误，建议立即核查错误上下文并做好容灾备份"
		adv.RootCause = "磁盘坏道、内存 ECC/MCE 硬件故障、EXT4/XFS 元数据异常、NFS 失联或驱动内核态 Bug。"
		if snap != nil && len(snap.KernelErrors) > 0 {
			for i, ke := range snap.KernelErrors {
				if i >= 3 {
					break
				}
				adv.Evidence = append(adv.Evidence, truncateText(ke, 150))
			}
		}
		adv.Steps = []string{
			"拉取带时间戳的内核日志完整上下文，区分存储错误、内存硬件错误还是网络文件系统异常",
			"若确认底层硬件或云盘异常，尽快迁移业务并创建数据快照",
		}
		adv.Commands = []AlertCommandSuggestion{
			{
				Label:       "查看近期内核严重错误完整日志",
				Description: "筛选 dmesg 中高严重级别错误与 Call Trace",
				Command:     "dmesg -T --level=emerg,alert,crit,err | tail -n 50",
				Risk:        "readonly",
			},
		}

	// =========================================================================
	// 4. Services & Containers
	// =========================================================================
	case "systemd_failed":
		var targetUnits []string
		subKey := extractDedupSubKey(al.DedupKey)
		if snap != nil {
			if subKey == "watched" {
				for _, svc := range snap.Services {
					if svc.Watched && svc.State != "active" {
						adv.Evidence = append(adv.Evidence, fmt.Sprintf("必监服务 %s 当前状态：%s (%s)", svc.Name, svc.State, svc.SubState))
						if tok := sanitizeSafeToken(svc.Name); tok != "" {
							targetUnits = append(targetUnits, tok)
						}
					}
				}
			}
			for _, u := range snap.SystemdFailedUnits {
				adv.Evidence = append(adv.Evidence, fmt.Sprintf("Failed 单元：%s", u))
				if tok := sanitizeSafeToken(u); tok != "" && !slices.Contains(targetUnits, tok) {
					targetUnits = append(targetUnits, tok)
				}
			}
		}
		if len(targetUnits) > 0 {
			adv.Summary = fmt.Sprintf("服务单元 %s 处于异常/停止状态，建议先查日志确认报错原因再尝试重启恢复", strings.Join(targetUnits[:min(3, len(targetUnits))], ", "))
		} else {
			adv.Summary = "存在故障或已停止的 Systemd 守护服务，建议先查看单元日志定位退出原因"
		}
		adv.RootCause = "配置文件语法错误、端口被占用、依赖资源不可用、进程 OOM 被杀或二进制权限变更。"
		adv.Steps = []string{
			"先查看异常服务的 status 与 journalctl 最近错误日志，避免盲目重启掩盖配置/端口冲突问题",
			"修复根因后执行 systemctl restart 拉起服务并复测验证",
		}
		if len(targetUnits) > 0 {
			u := targetUnits[0]
			qu := shellQuote(u)
			adv.Commands = append(adv.Commands,
				AlertCommandSuggestion{
					Label:       fmt.Sprintf("查看 %s 服务状态与最近 50 行日志", u),
					Description: "排查服务退出码与具体错误堆栈",
					Command:     fmt.Sprintf("systemctl status %s --no-pager -l && journalctl -u %s -n 50 --no-pager", qu, qu),
					Risk:        "readonly",
				},
				AlertCommandSuggestion{
					Label:       fmt.Sprintf("尝试重启服务 %s 并验证活跃状态", u),
					Description: "确认日志无致命配置错误后重启拉起该服务",
					Command:     fmt.Sprintf("sudo systemctl restart %s && systemctl is-active %s", qu, qu),
					Risk:        "mutating",
				},
			)
		} else {
			adv.Commands = append(adv.Commands, AlertCommandSuggestion{
				Label:       "列出全部失败的 Systemd 服务单元",
				Description: "汇总当前所有处于 failed 状态的服务",
				Command:     "systemctl --failed --no-pager",
				Risk:        "readonly",
			})
		}

	case "docker_unhealthy":
		subKey := extractDedupSubKey(al.DedupKey)
		if subKey == "daemon" || (snap != nil && snap.Docker.DaemonDown) {
			adv.Summary = "Docker 守护进程 (dockerd) 无响应或已停止，建议检查 docker 服务状态、磁盘空间与套接字权限"
			adv.RootCause = "dockerd 崩溃、daemon.json 配置格式错误、/var/lib/docker 磁盘写满或当前 SSH 用户无权访问 /var/run/docker.sock。"
			adv.Steps = []string{
				"检查 docker.service 状态及日志，确认是否因配置变更或磁盘写满导致启动失败",
				"修复后启动 docker 服务并核查业务容器是否全部恢复运行",
			}
			adv.Commands = []AlertCommandSuggestion{
				{
					Label:       "查看 Docker Daemon 服务状态与错误日志",
					Description: "排查 dockerd 停止或无响应的根因",
					Command:     "systemctl status docker --no-pager -l && journalctl -u docker -n 40 --no-pager",
					Risk:        "readonly",
				},
				{
					Label:       "启动 / 重启 Docker 守护进程",
					Description: "确认磁盘与配置正常后尝试拉起 dockerd",
					Command:     "sudo systemctl restart docker && docker ps",
					Risk:        "mutating",
				},
			}
		} else {
			var badNames []string
			if snap != nil {
				for _, c := range snap.Docker.Containers {
					if c.Health == "unhealthy" || c.State == "restarting" || c.State == "dead" ||
						(c.State == "exited" && strings.Contains(strings.ToLower(c.Status), "exited (") && !strings.Contains(strings.ToLower(c.Status), "exited (0)")) {
						adv.Evidence = append(adv.Evidence, fmt.Sprintf("容器 %s (%s)：状态 %s", c.Name, c.Image, c.Status))
						if tok := sanitizeSafeToken(c.Name); tok != "" {
							badNames = append(badNames, tok)
						}
					}
				}
			}
			if len(badNames) > 0 {
				adv.Summary = fmt.Sprintf("容器 %s 运行异常（不健康/崩退/循环重启），建议优先查看容器日志与 OOM 退出码", strings.Join(badNames[:min(3, len(badNames))], ", "))
			} else {
				adv.Summary = "检测到异常或非 0 退出的 Docker 容器，建议排查容器日志、健康检查失败输出与退出码"
			}
			adv.RootCause = "常见退出码：137 表示 OOM 内存超限被杀，139 表示段错误，1 表示应用启动报错或依赖不可达；unhealthy 多因健康检查接口超时。"
			adv.Steps = []string{
				"查看异常容器最近日志与 docker inspect 状态（确认 OOMKilled 与 ExitCode）",
				"排除应用配置或内存限制问题后重启容器并复测状态",
			}
			if len(badNames) > 0 {
				cn := badNames[0]
				qcn := shellQuote(cn)
				adv.Commands = append(adv.Commands,
					AlertCommandSuggestion{
						Label:       fmt.Sprintf("查看容器 %s 最近 80 行日志", cn),
						Description: "快速定位应用异常堆栈或启动报错",
						Command:     fmt.Sprintf("docker logs --tail 80 %s", qcn),
						Risk:        "readonly",
					},
					AlertCommandSuggestion{
						Label:       fmt.Sprintf("检查容器 %s 退出码、OOM 与健康检查详情", cn),
						Description: "核实是否因 OOMKilled 或健康检查脚本报错引发",
						Command:     fmt.Sprintf("docker inspect --format '{{json .State}}' %s", qcn),
						Risk:        "readonly",
					},
					AlertCommandSuggestion{
						Label:       fmt.Sprintf("重启异常容器 %s", cn),
						Description: "定位确认属瞬时故障后尝试重启恢复",
						Command:     fmt.Sprintf("docker restart %s && docker ps --filter name=%s", qcn, qcn),
						Risk:        "mutating",
					},
				)
			} else {
				adv.Commands = append(adv.Commands, AlertCommandSuggestion{
					Label:       "列出所有异常状态容器",
					Description: "查看非正常运行的容器名称与退出码",
					Command:     "docker ps -a --format 'table {{.Names}}\\t{{.Status}}\\t{{.Image}}'",
					Risk:        "readonly",
				})
			}
		}

	// =========================================================================
	// 5. Network & Listening Ports
	// =========================================================================
	case "tcp_close_wait":
		adv.Summary = "TCP 半关闭 (CLOSE_WAIT) 或半连接 (SYN_RECV) 套接字堆积，提示应用连接未释放或遭受 SYN 泛洪"
		adv.RootCause = "CLOSE_WAIT 堆积几乎总是应用代码未正确 close() 对端已断开的连接；SYN_RECV 激增则提示 SYN Flood 攻击或后端队列过小。"
		if snap != nil {
			adv.Evidence = append(adv.Evidence, fmt.Sprintf("CLOSE_WAIT=%d · SYN_RECV=%d · ESTABLISHED=%d · TIME_WAIT=%d", snap.TCPCloseWait, snap.TCPSynRecv, snap.TCPEstablished, snap.TCPTimeWait))
		}
		adv.Steps = []string{
			"区分是 CLOSE_WAIT 主导（定位未关闭连接的业务进程）还是 SYN_RECV 主导（核查来源 IP 与 syncookies）",
			"针对连接泄漏进程排查 HTTP/DB 连接池配置并平滑重启；针对 SYN 泛洪开启 net.ipv4.tcp_syncookies=1",
		}
		adv.Commands = []AlertCommandSuggestion{
			{
				Label:       "定位持有 CLOSE_WAIT 最多的进程与目标端口",
				Description: "按进程聚合 CLOSE_WAIT 套接字数量",
				Command:     "ss -antp state close-wait | head -n 30",
				Risk:        "readonly",
			},
			{
				Label:       "统计 TCP 各状态与 SYN_RECV 来源 IP",
				Description: "判断是否遭受 SYN Flood 并列出高频来源",
				Command:     "ss -s && ss -ant state syn-recv | awk 'NR>1{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -n 10",
				Risk:        "readonly",
			},
		}

	case "net_errors_spike":
		adv.Summary = "业务网卡错包/丢包增量突增，建议检查网卡 Ring Buffer、MTU 配置与物理链路质量"
		adv.RootCause = "网卡接收缓冲 (RX ring) 溢出、双工模式/MTU 不匹配、软中断 (softirq) 瓶颈或底层虚拟网卡限流。"
		if snap != nil {
			for _, nic := range snap.Interfaces {
				if nic.RxErrors+nic.TxErrors+nic.RxDrops+nic.TxDrops > 0 {
					adv.Evidence = append(adv.Evidence, fmt.Sprintf("网卡 %s (%s)：错包 RX %d / TX %d · 丢包 RX %d / TX %d", nic.Name, nic.IPv4, nic.RxErrors, nic.TxErrors, nic.RxDrops, nic.TxDrops))
				}
			}
		}
		adv.Steps = []string{
			"确认具体发生丢包/错包的网卡名称，以及属于 RX 丢包还是 TX 错包",
			"结合 ethtool -S 检查硬件队列统计，必要时调大 Ring Buffer 或核查宿主机带宽限速",
		}
		adv.Commands = []AlertCommandSuggestion{
			{
				Label:       "查看各网卡详细错包/丢包统计",
				Description: "定位具体出现错误增量的网络接口",
				Command:     "ip -s -s link show",
				Risk:        "readonly",
			},
			{
				Label:       "检查 TCP/UDP 协议栈丢包计数器",
				Description: "排查是否因套接字缓冲区不足导致的软丢包",
				Command:     "netstat -s 2>/dev/null | grep -iE 'drop|error|overflow|retrans' | head -n 25 || nstat -az | grep -iE 'Drop|Err|Retrans|Overflow' | head -n 25",
				Risk:        "readonly",
			},
		}

	case "watched_port_down":
		adv.Summary = "配置的关键业务端口当前未监听，对应服务进程可能已崩溃或绑定地址异常"
		adv.RootCause = "关键守护进程崩溃退出、重启失败、配置中修改了监听端口或仅绑定了错误网卡。"
		adv.Steps = []string{
			"核对对应业务进程是否在运行，以及当前实际监听的全部端口",
			"查看对应服务的错误日志后恢复拉起并复测监控状态",
		}
		adv.Commands = []AlertCommandSuggestion{
			{
				Label:       "查看当前主机全部 TCP/UDP 监听端口及归属进程",
				Description: "核对关键业务端口是否确实缺失或改绑到了其他端口",
				Command:     "ss -tulnp 2>/dev/null || netstat -tulnp",
				Risk:        "readonly",
			},
			{
				Label:       "查看失败的 Systemd 服务与异常 Docker 容器",
				Description: "快速关联可能崩溃的服务或容器",
				Command:     "systemctl --failed --no-pager; docker ps -a --filter status=exited --format 'table {{.Names}}\\t{{.Status}}' 2>/dev/null",
				Risk:        "readonly",
			},
		}

	case "port_drift":
		adv.Summary = "发现新增对外暴露的监听端口：若为固定新服务可一键「采纳当前端口基线」，若为动态轮换端口应用（如远程桌面/P2P/代理）可一键「忽略该进程漂移」"
		adv.RootCause = "常见原因包括新发布服务绑定 0.0.0.0、远程桌面/P2P/代理程序自动分配并频繁轮换动态端口，或恶意程序开启未授权后门监听。"
		var driftedPorts []vault.ListeningPortStat
		ignoredDynamicCnt := 0
		if snap != nil {
			for _, lp := range snap.ListeningPorts {
				if lp.PublicExposed && lp.DriftIgnored {
					ignoredDynamicCnt++
				}
			}
			if len(portBaseline) > 0 {
				driftedPorts = vault.ComputeDriftedPorts(snap.ListeningPorts, portBaseline)
			} else {
				for _, lp := range snap.ListeningPorts {
					if lp.PublicExposed && !lp.DriftIgnored {
						driftedPorts = append(driftedPorts, lp)
					}
				}
			}
			for i, lp := range driftedPorts {
				if i >= 6 {
					break
				}
				proc := fallbackStr(lp.Process, "未知进程")
				pidHint := ""
				if lp.PID > 0 {
					pidHint = fmt.Sprintf(" (PID %d)", lp.PID)
				}
				adv.Evidence = append(adv.Evidence, fmt.Sprintf("新增漂移：%s/%d 绑定 %s — 进程 %s%s", lp.Proto, lp.Port, lp.BindAddr, proc, pidHint))
			}
			if ignoredDynamicCnt > 0 {
				adv.Evidence = append(adv.Evidence, fmt.Sprintf("另有 %d 个临时高端口 UDP 或白名单动态端口已自动免打扰过滤", ignoredDynamicCnt))
			}
		}
		adv.Steps = []string{
			"先核查新增端口所属进程与二进制路径，确认是合法固定服务、动态端口应用，还是异常未授权监听",
			"若属固定对外业务端口变更，点击下方「采纳当前端口基线」更新基线并关闭告警",
			"若属会反复更换随机端口的应用（如 RustDesk / ToDesk / P2P / 代理），直接点击下方「忽略进程漂移」将其加入白名单，或在「监控策略」中配置全局忽略规则",
		}
		if mac {
			adv.Commands = []AlertCommandSuggestion{
				{
					Label:       "核查 macOS 对外监听端口及归属进程",
					Description: "列出 TCP LISTEN 端口与 UDP 未连接套接字以核对进程归属",
					Command:     "lsof -nP -iTCP -sTCP:LISTEN; netstat -anv -p udp | awk '$5 == \"*.*\"'",
					Risk:        "readonly",
				},
			}
		} else {
			adv.Commands = []AlertCommandSuggestion{
				{
					Label:       "核查全部对外暴露监听端口及进程路径",
					Description: "列出非 127.0.0.1 监听套接字与对应进程信息",
					Command:     "ss -tulnp | grep -vE '127\\.0\\.0\\.1|\\[::1\\]'",
					Risk:        "readonly",
				},
			}
		}
		adv.QuickActions = append(adv.QuickActions, AlertQuickAction{
			Kind:        "accept_port_baseline",
			Label:       "采纳当前端口基线",
			Description: "确认新增监听端口属合法固定服务变更，立即更新端口基线并消除此告警",
		})
		seenIgnoreProcs := make(map[string]bool)
		addedIgnoreActions := 0
		for _, lp := range driftedPorts {
			if addedIgnoreActions >= 3 {
				break
			}
			proc := strings.TrimSpace(lp.Process)
			if proc != "" {
				cleanPat, err := vault.ValidatePortDriftProcessPattern(proc)
				if err == nil && !seenIgnoreProcs[strings.ToLower(cleanPat)] {
					seenIgnoreProcs[strings.ToLower(cleanPat)] = true
					adv.QuickActions = append(adv.QuickActions, AlertQuickAction{
						Kind:        "ignore_port_drift_process",
						Label:       fmt.Sprintf("忽略进程 %s 漂移", cleanPat),
						Description: fmt.Sprintf("将该动态端口进程加入本机端口漂移白名单，后续 %s 轮换监听端口不再误报", cleanPat),
						Target:      cleanPat,
						Scope:       "server",
					})
					addedIgnoreActions++
				}
			} else if lp.Port > 0 {
				spec := fmt.Sprintf("%s/%d", vault.NormalizeBaseProto(lp.Proto), lp.Port)
				if !seenIgnoreProcs[spec] {
					seenIgnoreProcs[spec] = true
					adv.QuickActions = append(adv.QuickActions, AlertQuickAction{
						Kind:        "ignore_port_drift_port",
						Label:       fmt.Sprintf("忽略端口 %s", spec),
						Description: fmt.Sprintf("将 %s 加入本机端口漂移忽略白名单", spec),
						Target:      spec,
						Scope:       "server",
					})
					addedIgnoreActions++
				}
			}
		}

	// =========================================================================
	// 6. Security & Intrusion (Zero-AI Deterministic)
	// =========================================================================
	case "ssh_bruteforce":
		topIP := ""
		if snap != nil {
			if len(snap.Security.TopFailedIPs) > 0 {
				adv.Evidence = append(adv.Evidence, "高频失败来源 IP："+strings.Join(snap.Security.TopFailedIPs, ", "))
				topIP = sanitizeIP(snap.Security.TopFailedIPs[0])
			}
			if len(snap.Security.SSHWeakConfigs) > 0 {
				adv.Evidence = append(adv.Evidence, "检测到 SSH 弱安全配置："+strings.Join(snap.Security.SSHWeakConfigs, ", "))
			}
		}
		if topIP != "" {
			adv.Summary = fmt.Sprintf("检测到高频 SSH 暴力破解（首要来源 %s），建议立即封禁恶意 IP 并禁用密码登录/部署 Fail2ban", topIP)
		} else {
			adv.Summary = "近 15 分钟检测到高频 SSH 登录失败爆破，建议核查攻击源 IP、封禁恶意来源并启用纯密钥登录"
		}
		adv.RootCause = "公网暴露的 22 端口正遭受自动化字典爆破扫描，若仍开启 PasswordAuthentication 存在凭据沦陷风险。"
		adv.Steps = []string{
			"查看认证日志确认高频攻击来源 IP 以及是否存在异常成功登录记录",
			"对高频恶意 IP 实施防火墙封禁，并长期加固：禁用 SSH 密码登录、部署 fail2ban 或限制白名单访问",
		}
		adv.Commands = append(adv.Commands,
			AlertCommandSuggestion{
				Label:       "统计近期 SSH 登录失败 Top 15 来源 IP 与成功记录",
				Description: "快速核查攻击来源并确认是否已被撞库攻破",
				Command:     "(journalctl -u ssh -u sshd --since '1 hour ago' --no-pager 2>/dev/null || tail -n 500 /var/log/auth.log /var/log/secure 2>/dev/null) | grep -E 'Failed password|Accepted ' | tail -n 40",
				Risk:        "readonly",
			},
			AlertCommandSuggestion{
				Label:       "审计当前 sshd 安全加固配置",
				Description: "检查 PermitRootLogin、PasswordAuthentication 与 PubkeyAuthentication",
				Command:     "sshd -T 2>/dev/null | grep -E '^(permitrootlogin|passwordauthentication|pubkeyauthentication|maxauthtries|port) '",
				Risk:        "readonly",
			},
		)
		if topIP != "" {
			if blk := buildFirewallBlockCommand(snap, topIP); blk != nil {
				adv.Commands = append(adv.Commands, *blk)
			}
		}

	case "uid_zero_backdoor":
		var backdoors []string
		if snap != nil {
			for _, u := range snap.Security.UIDZeroUsers {
				if u != "" && u != "root" {
					adv.Evidence = append(adv.Evidence, fmt.Sprintf("高危特权账号：%s (UID=0)", u))
					if tok := sanitizeSafeToken(u); tok != "" {
						backdoors = append(backdoors, tok)
					}
				}
			}
		}
		adv.Summary = "高危安全告警：发现非 root 的 UID=0 超级特权账户，极高概率为提权后门，请立即核实并锁定清除"
		adv.RootCause = "攻击者入侵后常在 /etc/passwd 中写入 UID=0 的隐藏账号以维持 root 级持久权限。"
		adv.Steps = []string{
			"立即核查 /etc/passwd 中所有 UID=0 账号、创建时间、登录记录及关联进程",
			"确认非授权账号后先锁定密码并禁止登录（usermod -L -s /sbin/nologin），审计清理后再删除账号并轮换全部密钥",
		}
		adv.Commands = append(adv.Commands, AlertCommandSuggestion{
			Label:       "核查全部 UID=0 账户及其活跃会话与进程",
			Description: "列出 /etc/passwd 中第 3 列为 0 的所有条目与登录历史",
			Command:     "awk -F: '$3 == 0 {print}' /etc/passwd && last -n 15",
			Risk:        "readonly",
		})
		if len(backdoors) > 0 {
			u := shellQuote(backdoors[0])
			adv.Commands = append(adv.Commands, AlertCommandSuggestion{
				Label:       fmt.Sprintf("立即锁定可疑特权账户 %s 并禁止 Shell 登录", backdoors[0]),
				Description: "阻断该账户继续登录同时保留现场以便溯源取证",
				Command:     fmt.Sprintf("sudo usermod -L -s /sbin/nologin %s", u),
				Risk:        "mutating",
			})
		}

	case "firewall_inactive":
		fw := ""
		if snap != nil {
			fw = strings.ToLower(snap.Security.FirewallDetail)
			adv.Evidence = append(adv.Evidence, fmt.Sprintf("防火墙组件：%s · 当前状态：%s", fallbackStr(snap.Security.FirewallDetail, "主机防火墙"), snap.Security.FirewallStatus))
		}
		adv.Summary = "主机防火墙处于关闭状态，端口直接暴露风险显著增加，启用前务必先确认 SSH 端口已放行防失联"
		adv.RootCause = "防火墙服务被人工临时关闭后忘记恢复、系统升级重置或异常停机。"
		adv.Steps = []string{
			"启用防火墙前，务必先检查已有规则确保当前 SSH 端口（及关键业务端口）已放行，防止把自己锁在外面",
			"确认放行规则无误后再启用并设为开机自启",
		}
		switch {
		case strings.Contains(fw, "ufw"):
			adv.Commands = []AlertCommandSuggestion{
				{
					Label:       "查看 UFW 现有放行规则（启用前先核对 SSH 端口）",
					Description: "确认 SSH 端口已在规则列表中避免启用后断连",
					Command:     "sudo ufw show added",
					Risk:        "readonly",
				},
				{
					Label:       "放行 SSH 并重新启用 UFW 防火墙",
					Description: "先确保放行 OpenSSH/22 端口后再开启 UFW（如使用自定义 SSH 端口请先修改端口号）",
					Command:     "sudo ufw allow 22/tcp && sudo ufw --force enable && sudo ufw status verbose",
					Risk:        "mutating",
				},
			}
		case strings.Contains(fw, "firewalld"):
			adv.Commands = []AlertCommandSuggestion{
				{
					Label:       "查看 firewalld 服务与默认区域规则",
					Description: "核对默认区域已放行的服务和端口",
					Command:     "systemctl status firewalld --no-pager; sudo firewall-cmd --list-all 2>/dev/null",
					Risk:        "readonly",
				},
				{
					Label:       "重新启动并设为开机自启 firewalld",
					Description: "默认区域通常已包含 ssh 服务，启动后立即核查放行列表",
					Command:     "sudo systemctl enable --now firewalld && sudo firewall-cmd --list-all",
					Risk:        "mutating",
				},
			}
		case mac:
			adv.Commands = []AlertCommandSuggestion{
				{
					Label:       "查看 macOS 应用层防火墙状态",
					Description: "核对 socketfilterfw 当前配置",
					Command:     "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate",
					Risk:        "readonly",
				},
				{
					Label:       "启用 macOS 应用层防火墙",
					Description: "开启全局防火墙保护",
					Command:     "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on",
					Risk:        "mutating",
				},
			}
		default:
			adv.Commands = []AlertCommandSuggestion{
				{
					Label:       "检查主机防火墙服务与规则状态",
					Description: "排查 ufw / firewalld / nftables / iptables 状态",
					Command:     "ufw status verbose 2>/dev/null || firewall-cmd --state 2>/dev/null || sudo iptables -L -n --line-numbers",
					Risk:        "readonly",
				},
			}
		}

	case "security_file_drift":
		if snap != nil {
			for _, fd := range snap.Security.FileDrifts {
				adv.Evidence = append(adv.Evidence, "关键文件漂移："+fd)
			}
			for _, pd := range snap.Security.PersistenceDrifts {
				adv.Evidence = append(adv.Evidence, "持久化项漂移："+pd)
			}
		}
		adv.Summary = "关键安全文件或定时持久化配置哈希发生变化，请核查是否属合法运维变更，确认无误可一键「采纳安全基线」"
		adv.RootCause = "运维更新了 authorized_keys/sshd_config/crontab，或攻击者植入了 SSH 后门公钥、sudoers 提权项、ld.so.preload 劫持或恶意计划任务。"
		adv.Steps = []string{
			"核对变更文件的最后修改时间 (mtime) 及内容，重点检查 ~/.ssh/authorized_keys、/etc/sudoers、/etc/ld.so.preload 与 crontab",
			"若确认为本人或团队正常变更，点击下方「采纳安全基线」更新指纹即可消除告警；若属异常篡改请立即应急止损",
		}
		adv.Commands = []AlertCommandSuggestion{
			{
				Label:       "核查关键安全文件最近修改时间与内容",
				Description: "查看 /etc/passwd、sudoers、sshd_config 与 ld.so.preload 状态",
				Command:     "stat -c '%y %n' /etc/passwd /etc/shadow /etc/sudoers /etc/ssh/sshd_config /etc/ld.so.preload /root/.ssh/authorized_keys 2>/dev/null; ls -la /etc/cron.d /var/spool/cron/crontabs 2>/dev/null",
				Risk:        "readonly",
			},
			{
				Label:       "列出当前用户与系统计划任务 (Crontab)",
				Description: "排查是否被植入未知定时拉起脚本",
				Command:     "crontab -l 2>/dev/null; cat /etc/crontab 2>/dev/null | grep -v '^#'",
				Risk:        "readonly",
			},
		}
		adv.QuickActions = append(adv.QuickActions, AlertQuickAction{
			Kind:        "accept_security_baseline",
			Label:       "采纳当前安全基线",
			Description: "确认文件与持久化变更属合法维护操作，立即更新安全基线并消除此告警",
		})

	case "suspicious_process":
		var firstPID int
		if snap != nil {
			for i, sp := range snap.Security.SuspiciousProcs {
				if i == 0 && sp.PID > 1 {
					firstPID = sp.PID
				}
				if i < 5 {
					adv.Evidence = append(adv.Evidence, fmt.Sprintf("PID %d (%s · %s)：%s", sp.PID, sp.User, sp.Reason, truncateText(sp.Command, 80)))
				}
			}
		}
		adv.Summary = "检测到高危可疑进程特征（/tmp 运行、已删二进制或挖矿/反弹 Shell），建议先溯源取证再隔离终止"
		adv.RootCause = "入侵脚本常在 /tmp 或 /dev/shm 释放并执行恶意程序，或运行后删除磁盘二进制文件逃避常规检查。"
		adv.Steps = []string{
			"切勿只杀进程不查持久化！先记录该进程的可执行文件路径 (/proc/<pid>/exe)、父进程、打开的网络连接及启动目录",
			"同步核查 crontab、systemd 定时器与 authorized_keys 清除持久化后门，再终止可疑进程",
		}
		if firstPID > 1 {
			adv.Commands = append(adv.Commands,
				AlertCommandSuggestion{
					Label:       fmt.Sprintf("取证排查可疑进程 PID %d 的路径、父进程与外联", firstPID),
					Description: "查看进程树、/proc 映射路径和实时网络连接",
					Command:     fmt.Sprintf("ps -fp %d; ls -l /proc/%d/exe /proc/%d/cwd 2>/dev/null; ss -antp | grep 'pid=%d,'", firstPID, firstPID, firstPID, firstPID),
					Risk:        "readonly",
				},
				AlertCommandSuggestion{
					Label:       fmt.Sprintf("强制终止可疑进程 PID %d (SIGKILL)", firstPID),
					Description: "确认属于恶意进程且完成取证后立即终止",
					Command:     fmt.Sprintf("sudo kill -9 %d", firstPID),
					Risk:        "mutating",
				},
			)
		} else {
			adv.Commands = append(adv.Commands, AlertCommandSuggestion{
				Label:       "排查 /tmp、/dev/shm 及已删除二进制运行进程",
				Description: "全量核查异常执行路径的活跃进程",
				Command:     "ls -l /proc/[0-9]*/exe 2>/dev/null | grep -E '/tmp/|/dev/shm/|\\(deleted\\)'",
				Risk:        "readonly",
			})
		}

	case "suspicious_outbound":
		if snap != nil {
			for i, oc := range snap.Security.SuspiciousOutbound {
				if i >= 5 {
					break
				}
				adv.Evidence = append(adv.Evidence, fmt.Sprintf("外联 %s:%d — 进程 %s (PID %d · %s)", oc.RemoteIP, oc.RemotePort, fallbackStr(oc.Process, "unknown"), oc.PID, oc.Reason))
			}
		}
		adv.Summary = "检测到连接至高危/矿池特征端口的异常外联，建议核查发起进程归属，必要时阻断外联并排查入侵"
		adv.RootCause = "可能是恶意挖矿/C2 回连外联，也可能是业务合法连接第三方非标端口服务。"
		adv.Steps = []string{
			"核对发起外联的进程 PID、命令行参数及所属业务",
			"若确认为恶意外联，记录远端 IP/端口后在防火墙阻断出站并排查入侵入口；若为合法业务可关闭该可选规则",
		}
		adv.Commands = []AlertCommandSuggestion{
			{
				Label:       "列出当前全部已建立的 TCP 外联及归属进程",
				Description: "核对异常远端 IP、端口及对应本地进程命令行",
				Command:     "ss -antp state established | head -n 40",
				Risk:        "readonly",
			},
		}

	case "ssh_new_login_ip":
		if snap != nil && len(snap.Security.NewSSHLoginIPs) > 0 {
			adv.Evidence = append(adv.Evidence, "新来源登录 IP："+strings.Join(snap.Security.NewSSHLoginIPs, ", "))
			for i, ev := range snap.Security.RecentSSHLogins {
				if i >= 3 {
					break
				}
				adv.Evidence = append(adv.Evidence, fmt.Sprintf("近期成功登录：%s@%s (%s · %s)", ev.User, ev.FromIP, ev.Method, ev.Timestamp))
			}
		}
		adv.Summary = "检测到未在已知基线中的新来源 IP 成功登录 SSH，请核实是否为本人操作，确认合法可一键「采纳安全基线」"
		adv.RootCause = "办公网络/家庭宽带 IP 变动、使用新跳板节点登录，或 SSH 凭据/私钥已泄露被第三方登录。"
		adv.Steps = []string{
			"核对新 IP 归属地、登录时间、使用账号以及该会话执行过的命令历史",
			"若确认属于本人合法登录，点击下方「采纳安全基线」加入信任列表；若非本人操作，立即踢出会话并更换密码与全部 SSH 密钥",
		}
		adv.Commands = []AlertCommandSuggestion{
			{
				Label:       "查看当前活跃 SSH 会话与最近登录历史",
				Description: "核对来源 IP、登录终端与会话存活状态",
				Command:     "w && last -n 15",
				Risk:        "readonly",
			},
		}
		adv.QuickActions = append(adv.QuickActions, AlertQuickAction{
			Kind:        "accept_security_baseline",
			Label:       "采纳当前安全基线",
			Description: "将本次新来源登录 IP 纳入已知安全基线并消除告警",
		})

	case "clock_ntp_drift":
		adv.Summary = "主机系统时钟偏移过大，可能导致 TLS 证书校验、TOTP 令牌或分布式日志时序错乱，建议检查 NTP 同步"
		adv.RootCause = "chronyd / systemd-timesyncd 服务未运行、UDP 123 端口被防火墙拦截或虚拟机休眠恢复后时钟步进异常。"
		if snap != nil {
			adv.Evidence = append(adv.Evidence, fmt.Sprintf("时钟偏差 %+d 秒 · NTP 已同步：%v · 节点时间：%s", snap.ClockOffsetSec, snap.NTPSynced, snap.ServerTime))
		}
		adv.Steps = []string{
			"检查 timedatectl / chronyc 同步源状态及 UDP 123 连通性",
			"启动或强制步进同步 NTP 服务，观察时钟偏差回落至 1 秒以内",
		}
		adv.Commands = []AlertCommandSuggestion{
			{
				Label:       "检查系统时钟与 NTP 同步源状态",
				Description: "查看时间服务运行状态与上游 NTP 服务器偏差",
				Command:     "timedatectl status 2>/dev/null; chronyc tracking 2>/dev/null || ntpq -p 2>/dev/null",
				Risk:        "readonly",
			},
			{
				Label:       "触发时钟立即校正并重载同步服务",
				Description: "通过 chronyc makestep 或重启 timesyncd 校正时钟偏差",
				Command:     "sudo chronyc -a makestep 2>/dev/null || sudo systemctl restart systemd-timesyncd",
				Risk:        "mutating",
			},
		}

	default:
		adv.Summary = "监控指标触发阈值，建议结合主机深度透视与实时日志排查异常根因"
		adv.RootCause = al.Detail
		adv.Steps = []string{
			"点击「单机深度透视」查看该节点近 1 小时指标趋势与异常发生时间点",
			"通过 SSH 终端或「AI 深度诊断」进一步排查关联服务与系统日志",
		}
		adv.Commands = []AlertCommandSuggestion{
			{
				Label:       "查看主机基础负载与近期系统错误日志",
				Description: "快速概览系统运行状态",
				Command:     "uptime && free -h && df -h",
				Risk:        "readonly",
			},
		}
	}

	adv.Runbooks = matchRelevantRunbooks(al, runbooks)
	adv.AIPrompt = buildAlertAIPrompt(al, adv)
	return adv
}

func firstTopCPUProc(snap *vault.ServerMonitorSnapshot) *vault.ProcessStat {
	if snap == nil || len(snap.TopCPUProcs) == 0 {
		return nil
	}
	return &snap.TopCPUProcs[0]
}

func firstTopMemProc(snap *vault.ServerMonitorSnapshot) *vault.ProcessStat {
	if snap == nil || len(snap.TopMemProcs) == 0 {
		return nil
	}
	return &snap.TopMemProcs[0]
}

func fallbackStr(val, fb string) string {
	if strings.TrimSpace(val) != "" {
		return val
	}
	return fb
}

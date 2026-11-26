package monitor

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/sshmanager"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
	"golang.org/x/crypto/ssh"
)

func setupTestMonitorStore(t *testing.T) (*vault.Store, *vault.ServerView) {
	t.Helper()
	store, err := vault.NewStore(filepath.Join(t.TempDir(), "vault.sns"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	if err := store.Setup("StrongAuditPass#2026", "127.0.0.1"); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	pass := "NodePass!1"
	srv, err := store.CreateServer(vault.ServerMutationInput{
		Name:            "Prod-Linux-01",
		Group:           "生产环境",
		Host:            "127.0.0.1",
		Port:            22,
		Username:        "root",
		AuthType:        vault.AuthPassword,
		Password:        &pass,
		WatchedServices: []string{"postgresql", "redis-server"},
		WatchedPorts:    []int{443, 5432},
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("CreateServer: %v", err)
	}
	return store, srv
}

func TestPartialTimeoutTruncationNeverFalseResolvesAlerts(t *testing.T) {
	var mode atomic.Int32 // 0 = high mem/disk firing, 1 = truncated half-output timeout/error
	host, port, stop := startCustomSSHServer(t, "root", "NodePass!1", func(cmd string) (string, uint32) {
		if mode.Load() == 0 {
			return `
===SNS_SEC:SAMPLE_T0===
UP=1000.0
CPU=cpu 100 0 50 850 0 0 0 0
===SNS_SEC:SYS===
HOSTNAME=prod-01
CORES=4
UPTIME_SEC=1000
===SNS_SEC:MEM===
MemTotal=16000000
MemAvailable=800000
===SNS_SEC:DISK===
FS=/dev/vda1|ext4|100000000|95000000|0|100%|/
===SNS_SEC:SAMPLE_T1===
UP=1000.25
CPU=cpu 110 0 55 935 0 0 0 0
===SNS_END===
`, 0
		}
		// Simulate NFS hang / mid-script timeout: SAMPLE_T0 & SYS emitted, NO ===SNS_END===, non-zero exit
		return "===SNS_SEC:SAMPLE_T0===\nUP=1060.0\n===SNS_SEC:SYS===\nHOSTNAME=prod-01\n", 124
	})
	defer stop()

	store, err := vault.NewStore(filepath.Join(t.TempDir(), "vault.sns"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()
	if err := store.Setup("StrongAuditPass#2026", "127.0.0.1"); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	pass := "NodePass!1"
	srv, err := store.CreateServer(vault.ServerMutationInput{
		Name:     "NFS-Prod",
		Group:    "生产环境",
		Host:     host,
		Port:     port,
		Username: "root",
		AuthType: vault.AuthPassword,
		Password: &pass,
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("CreateServer: %v", err)
	}

	sshMgr := sshmanager.NewManager(store)
	eng := NewEngine(store, sshMgr)
	defer eng.Close()

	// 1. Healthy reachability with critical mem (95%) and ext4 5%-reserved full disk (used/(used+avail)=100%)
	snap0, err := eng.CollectServerNow(context.Background(), srv.ID, "", "127.0.0.1")
	if err != nil || !snap0.Reachable || snap0.DiskPercent != 100.0 {
		t.Fatalf("expected reachable 100%% disk snapshot, got %+v err=%v", snap0, err)
	}
	active0, _ := store.ListMonitorAlerts("active", srv.ID, 0)
	if len(active0) < 2 {
		t.Fatalf("expected mem_high + disk_high active alerts, got %+v", active0)
	}

	// 2. Truncated mid-script failure MUST NOT resolve active mem/disk alerts!
	mode.Store(1)
	snap1, err := eng.CollectServerNow(context.Background(), srv.ID, "", "127.0.0.1")
	if err != nil {
		t.Fatalf("CollectServerNow truncated: %v", err)
	}
	if snap1.Reachable || snap1.PartialError == "" {
		t.Fatalf("expected Reachable=false and PartialError set on truncated output, got %+v", snap1)
	}

	active1, _ := store.ListMonitorAlerts("active", srv.ID, 0)
	foundMem, foundDisk := false, false
	for _, a := range active1 {
		if a.RuleKind == "mem_high" {
			foundMem = true
		}
		if a.RuleKind == "disk_high" {
			foundDisk = true
		}
	}
	if !foundMem || !foundDisk {
		t.Fatalf("BUG: truncated snapshot falsely resolved active alerts! remaining=%+v", active1)
	}
}

func TestStrictDebounceHealthLevelEscalationAndDeescalation(t *testing.T) {
	store, srv := setupTestMonitorStore(t)
	now := time.Now().UTC()

	makeCPUSnap := func(ts time.Time, cpu float64) *vault.ServerMonitorSnapshot {
		return &vault.ServerMonitorSnapshot{
			ServerID:    srv.ID,
			CollectedAt: ts,
			Reachable:   true,
			CPUCores:    4,
			CPUPercent:  cpu,
			MemPercent:  30,
			DiskPercent: 30,
		}
	}

	// Probe 1: single 96% CPU spike (cpu_high ConsecutiveCount=2) -> must NOT fire AND must NOT be HealthCritical!
	s1 := makeCPUSnap(now, 96.0)
	trig1, _, _, err := store.RecordMonitorSnapshots([]*vault.ServerMonitorSnapshot{s1})
	if err != nil {
		t.Fatalf("probe 1: %v", err)
	}
	if len(trig1) != 0 {
		t.Fatalf("expected 0 triggered alerts on 1st CPU spike, got %+v", trig1)
	}
	if s1.HealthLevel == vault.HealthCritical {
		t.Fatalf("BUG: single un-debounced CPU spike prematurely marked HealthLevel=critical (score=%d)", s1.HealthScore)
	}

	// Probe 2: 85% (Warning, 2nd consecutive breach) -> fires Warning!
	s2 := makeCPUSnap(now.Add(60*time.Second), 85.0)
	trig2, _, _, err := store.RecordMonitorSnapshots([]*vault.ServerMonitorSnapshot{s2})
	if err != nil || len(trig2) != 1 || trig2[0].Severity != vault.SeverityWarning {
		t.Fatalf("expected Warning cpu_high on 2nd breach, got trig=%+v err=%v", trig2, err)
	}

	// Acknowledge Warning alert
	ackAl, err := store.AcknowledgeMonitorAlert(trig2[0].ID, "127.0.0.1")
	if err != nil || ackAl.Status != vault.AlertStatusAcknowledged {
		t.Fatalf("ack failed: %+v err=%v", ackAl, err)
	}

	// Probe 3: escalates to 97% (Critical) -> MUST reactivate to firing, upgrade to Critical, and emit escalation webhook trigger!
	s3 := makeCPUSnap(now.Add(120*time.Second), 97.0)
	trig3, _, _, err := store.RecordMonitorSnapshots([]*vault.ServerMonitorSnapshot{s3})
	if err != nil {
		t.Fatalf("probe 3: %v", err)
	}
	if len(trig3) != 1 || trig3[0].Severity != vault.SeverityCritical || trig3[0].Status != vault.AlertStatusFiring {
		t.Fatalf("expected Critical reactivation trigger on Warning->Critical escalation, got %+v", trig3)
	}
	if s3.HealthLevel != vault.HealthCritical {
		t.Fatalf("expected HealthCritical once critical alert is active, got %s", s3.HealthLevel)
	}

	// Probe 4: drops back to 84% (Warning) -> MUST de-escalate to Warning without duplicate webhook trigger!
	s4 := makeCPUSnap(now.Add(180*time.Second), 84.0)
	trig4, res4, _, err := store.RecordMonitorSnapshots([]*vault.ServerMonitorSnapshot{s4})
	if err != nil || len(trig4) != 0 || len(res4) != 0 {
		t.Fatalf("expected clean de-escalation without webhook spam, got trig=%+v res=%+v err=%v", trig4, res4, err)
	}
	active4, _ := store.ListMonitorAlerts("active", srv.ID, 0)
	if len(active4) != 1 || active4[0].Severity != vault.SeverityWarning {
		t.Fatalf("expected alert severity downgraded to warning, got %+v", active4)
	}
}

func TestSystemdNoMaskingDockerDaemonDownAndPortExposureFixes(t *testing.T) {
	store, srv := setupTestMonitorStore(t)
	now := time.Now().UTC()

	// Seed clean port baseline (tcp/22, tcp/443, tcp/5432)
	baseSnap := &vault.ServerMonitorSnapshot{ServerID: srv.ID, CollectedAt: now, Reachable: true}
	ParseDeepTelemetry(`
===SNS_SEC:PORTS===
tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=100))
tcp LISTEN 0 128 [::]:443 [::]:* users:(("nginx",pid=101))
tcp LISTEN 0 128 127.0.0.1:5432 0.0.0.0:* users:(("postgres",pid=102))
udp UNCONN 0 0 [fe80::1%eth0]:5353 [::]:* users:(("avahi",pid=103))
===SNS_END===
`, baseSnap, nil)
	// Verify link-local & loopback NOT exposed, wildcard exposed
	for _, lp := range baseSnap.ListeningPorts {
		if lp.Port == 5432 && (lp.PublicExposed || lp.ExposureScope != "loopback") {
			t.Fatalf("expected 127.0.0.1:5432 loopback/non-exposed, got %+v", lp)
		}
		if lp.Port == 5353 && (lp.PublicExposed || lp.ExposureScope != "link_local") {
			t.Fatalf("expected fe80::1:5353 link_local/non-exposed, got %+v", lp)
		}
	}
	_, _, _, _ = store.RecordMonitorSnapshots([]*vault.ServerMonitorSnapshot{baseSnap})

	// Next probe:
	// - watched service down AND failed unit present (both must fire!)
	// - Docker Exited (137) triggers abnormal, Exited (0) does NOT
	// - Rogue listener bound directly to specific public IP 203.0.113.55:4444 + dual-stack 0.0.0.0:9999 & [::]:9999
	snap2 := &vault.ServerMonitorSnapshot{ServerID: srv.ID, CollectedAt: now.Add(60 * time.Second), Reachable: true}
	ParseDeepTelemetry(`
===SNS_SEC:SYSTEMD===
FAILED_UNIT=backup-sync.service
SVC=postgresql|active|watched
SVC=redis-server|inactive|watched
===SNS_SEC:DOCKER===
DOCKER_BIN=1
DOCKER_OK=1
CTR=aaa111|job-clean|alpine|exited|Exited (0) 2 hours ago
CTR=bbb222|worker-oom|app:v1|exited|Exited (137) 1 minute ago
===SNS_SEC:PORTS===
tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=100))
tcp LISTEN 0 128 [::]:443 [::]:* users:(("nginx",pid=101))
tcp LISTEN 0 128 127.0.0.1:5432 0.0.0.0:* users:(("postgres",pid=102))
tcp LISTEN 0 128 203.0.113.55:4444 0.0.0.0:* users:(("implant",pid=9001))
tcp LISTEN 0 128 0.0.0.0:9999 0.0.0.0:* users:(("rogue",pid=9002))
tcp6 LISTEN 0 128 [::]:9999 [::]:* users:(("rogue",pid=9002))
===SNS_END===
`, snap2, baseSnap)

	if snap2.Docker.ExitedAbnormal != 1 {
		t.Fatalf("expected exactly 1 abnormal exited container (137, not 0), got %+v", snap2.Docker)
	}
	var foundPublicIP bool
	for _, lp := range snap2.ListeningPorts {
		if lp.Port == 4444 && lp.PublicExposed && lp.ExposureScope == "public_ip" {
			foundPublicIP = true
		}
	}
	if !foundPublicIP {
		t.Fatalf("expected specific public IP bind 203.0.113.55:4444 classified as public_ip/exposed, got %+v", snap2.ListeningPorts)
	}

	trig, _, _, err := store.RecordMonitorSnapshots([]*vault.ServerMonitorSnapshot{snap2})
	if err != nil {
		t.Fatalf("RecordMonitorSnapshots: %v", err)
	}
	keys := make(map[string]vault.MonitorAlert)
	for _, a := range trig {
		keys[a.DedupKey] = a
	}
	if _, ok := keys[srv.ID+"|systemd_failed|watched"]; !ok {
		t.Fatalf("missing systemd_failed|watched alert: %+v", trig)
	}
	if _, ok := keys[srv.ID+"|systemd_failed|units"]; !ok {
		t.Fatalf("BUG: systemd_failed|units was masked by watched service alert! got %+v", trig)
	}
	if _, ok := keys[srv.ID+"|docker_unhealthy|"]; !ok {
		t.Fatalf("missing docker_unhealthy for Exited(137) container: %+v", trig)
	}
	driftAl, ok := keys[srv.ID+"|port_drift|"]
	if !ok {
		t.Fatalf("missing port_drift alert for specific-IP + dual-stack ports: %+v", trig)
	}
	// Dual-stack tcp/9999 + tcp6/9999 deduplicated -> total drifted ports = 2 (4444 + 9999), NOT 3!
	if driftAl.MetricText != "+2 端口" {
		t.Fatalf("expected +2 deduplicated drifted ports (4444 & 9999), got %q (%s)", driftAl.MetricText, driftAl.Detail)
	}

	// Verify Docker DaemonDown triggers Critical docker_unhealthy|daemon AND PortsTruncated suppresses false watched_port_down!
	snap3 := &vault.ServerMonitorSnapshot{ServerID: srv.ID, CollectedAt: now.Add(120 * time.Second), Reachable: true}
	ParseDeepTelemetry(`
===SNS_SEC:DOCKER===
DOCKER_BIN=1
DOCKER_DOWN=1
===SNS_SEC:PORTS===
tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=100))
PORTS_TRUNC=1
===SNS_END===
`, snap3, snap2)
	trig3, _, _, _ := store.RecordMonitorSnapshots([]*vault.ServerMonitorSnapshot{snap3})
	hasDaemonDown := false
	hasFalseWatchedPortDown := false
	for _, a := range trig3 {
		if a.DedupKey == srv.ID+"|docker_unhealthy|daemon" && a.Severity == vault.SeverityCritical {
			hasDaemonDown = true
		}
		if a.RuleKind == "watched_port_down" {
			hasFalseWatchedPortDown = true
		}
	}
	if !hasDaemonDown {
		t.Fatalf("expected Critical docker_unhealthy|daemon alert, got %+v", trig3)
	}
	if hasFalseWatchedPortDown {
		t.Fatalf("BUG: watched_port_down falsely fired despite PORTS_TRUNC=1!")
	}
}

func TestDisabledRuleThresholdValidationAndDisabledServerSilentClose(t *testing.T) {
	store, srv := setupTestMonitorStore(t)
	now := time.Now().UTC()

	// 1. Validate inverted thresholds are rejected
	settings, rules, err := store.GetMonitorPolicy()
	if err != nil {
		t.Fatalf("GetMonitorPolicy: %v", err)
	}
	badRules := append([]vault.MonitorAlertRule(nil), rules...)
	for i := range badRules {
		if badRules[i].Kind == "cpu_high" {
			badRules[i].WarningThreshold = 95
			badRules[i].CriticalThreshold = 80
		}
	}
	if _, _, err := store.UpdateMonitorPolicy(settings, badRules, "127.0.0.1"); !errors.Is(err, vault.ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput for inverted cpu_high thresholds, got %v", err)
	}

	// Inverted lower_is_worse (disk_will_fill Critical > Warning) rejected
	badLower := append([]vault.MonitorAlertRule(nil), rules...)
	for i := range badLower {
		if badLower[i].Kind == "disk_will_fill" {
			badLower[i].WarningThreshold = 6
			badLower[i].CriticalThreshold = 24
		}
	}
	if _, _, err := store.UpdateMonitorPolicy(settings, badLower, "127.0.0.1"); !errors.Is(err, vault.ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput for inverted disk_will_fill thresholds, got %v", err)
	}

	// 2. Trigger mem_high + disk_high, then disable mem_high -> mem_high closes silently immediately!
	_, _, _, _ = store.RecordMonitorSnapshots([]*vault.ServerMonitorSnapshot{
		{ServerID: srv.ID, CollectedAt: now, Reachable: true, MemPercent: 96, DiskPercent: 95, MaxPartPercent: 95},
	})
	for i := range rules {
		if rules[i].Kind == "mem_high" {
			rules[i].Enabled = false
		}
	}
	if _, _, err := store.UpdateMonitorPolicy(settings, rules, "127.0.0.1"); err != nil {
		t.Fatalf("UpdateMonitorPolicy disable mem_high: %v", err)
	}
	active, _ := store.ListMonitorAlerts("active", srv.ID, 0)
	for _, a := range active {
		if a.RuleKind == "mem_high" {
			t.Fatalf("expected disabled mem_high alert to be silently closed, still active: %+v", a)
		}
	}

	// 3. Disable monitoring on server -> remaining disk_high alert must silently close!
	monOff := false
	_, err = store.UpdateServer(srv.ID, vault.ServerMutationInput{
		Name:           srv.Name,
		Group:          srv.Group,
		Host:           srv.Host,
		Port:           srv.Port,
		Username:       srv.Username,
		AuthType:       srv.AuthType,
		MonitorEnabled: &monOff,
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("UpdateServer monitor off: %v", err)
	}
	activeAfterDisable, _ := store.ListMonitorAlerts("active", srv.ID, 0)
	if len(activeAfterDisable) != 0 {
		t.Fatalf("expected all alerts silently closed when server MonitorDisabled=true, got %+v", activeAfterDisable)
	}
}

func TestL1L2L3ZeroAIDangerRulesDiskForecastAndSecurityBaseline(t *testing.T) {
	store, srv := setupTestMonitorStore(t)
	baseTime := time.Now().UTC().Add(-2 * time.Hour)

	// Seed 11 ascending historical disk samples (60% -> 82% over 110m = +12%/hr -> ~1.5h to full!)
	for i := 0; i < 11; i++ {
		ts := baseTime.Add(time.Duration(i*10) * time.Minute)
		diskPct := 60.0 + float64(i)*2.0
		s := &vault.ServerMonitorSnapshot{
			ServerID:       srv.ID,
			CollectedAt:    ts,
			Reachable:      true,
			CPUCores:       4,
			UptimeSec:      int64(50000 + i*600),
			OOMKills:       3, // Pre-existing historical OOM kills should NOT alert on first sight
			DiskPercent:    diskPct,
			MaxPartPercent: diskPct,
			MaxPartMount:   "/var/lib/data",
			Security: vault.SecurityPostureStat{
				FirewallStatus:  "unknown", // unknown must NOT alert firewall_inactive!
				UIDZeroUsers:    []string{"root"},
				FileHashes:      map[string]string{"/root/.ssh/authorized_keys": "aaaa1111"},
				PersistenceHash: "pers1111",
				RecentSSHLogins: []vault.SSHLoginEvent{{User: "root", FromIP: "10.0.0.5", Method: "publickey"}},
			},
		}
		trig, _, _, err := store.RecordMonitorSnapshots([]*vault.ServerMonitorSnapshot{s})
		if err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
		for _, a := range trig {
			if a.RuleKind == "oom_kill" || a.RuleKind == "firewall_inactive" || a.RuleKind == "security_file_drift" {
				t.Fatalf("unexpected false alert during baseline seed %d: %+v", i, a)
			}
		}
	}

	// Probe 12: trigger ALL L1 + L2 + L3 rules simultaneously!
	tsDanger := baseTime.Add(110 * time.Minute)
	dangerSnap := &vault.ServerMonitorSnapshot{
		ServerID:    srv.ID,
		CollectedAt: tsDanger,
		Reachable:   true,
	}
	ParseDeepTelemetry(`
===SNS_SEC:SAMPLE_T0===
UP=120.0
CPU=cpu 1000 0 100 100 0 0 0 800
NET=eth0 1000 10 100 50 1000 10 100 50
===SNS_SEC:SAMPLE_T1===
UP=120.5
CPU=cpu 1010 0 105 120 0 0 0 865
NET=eth0 2000 20 100 50 2000 20 100 50
===SNS_SEC:SYS===
HOSTNAME=prod-01
CORES=4
UPTIME_SEC=120
===SNS_SEC:MEM===
MemTotal=16000000
MemAvailable=8000000
OOM_KILL=5
===SNS_SEC:DISK===
FS=/dev/vdb|ext4|100000000|84000000|16000000|84%|/var/lib/data
===SNS_SEC:MOUNTS===
RO_MNT=/var/lib/data|ext4
REMOTE_MNT=/mnt/nfs-share|nfs4
===SNS_SEC:PROC===
PSTAT=200 2 180 0 18
===SNS_SEC:HW===
RAID_BAD=md0:[2/1] [U_]
KERR_CNT=3
KERR=EXT4-fs error (device vdb): remounting filesystem read-only
===SNS_SEC:SEC===
UID0=root
UID0=backdoor0
FW=inactive|ufw
SSH_FAIL_CNT=40
SSH_FAIL_IP=2001:db8::99(40)
SSH_LOGIN=root|203.0.113.88|password|Nov 27 00:10
===SNS_SEC:SEC_DEEP===
FIM=/root/.ssh/authorized_keys|bbbb2222
PERSIST_HASH=pers2222
SUSP_PROC=8888|www-data|miner_signature|critical|./xmrig --url stratum+tcp://pool:3333|
OUTB=198.51.100.77|3333|8888|xmrig|miner_pool_port
===SNS_END===
`, dangerSnap, nil)

	// Enable opt-in L3 rules (suspicious_outbound, ssh_new_login_ip) to verify they fire when turned on,
	// while also verifying consecutive_count=2 rules fire on 2nd consecutive sample.
	settings, rules, _ := store.GetMonitorPolicy()
	for i := range rules {
		switch rules[i].Kind {
		case "suspicious_outbound", "ssh_new_login_ip":
			rules[i].Enabled = true
		case "disk_will_fill", "cpu_steal_high", "blocked_procs", "net_errors_spike":
			rules[i].ConsecutiveCount = 1
		}
	}
	if _, _, err := store.UpdateMonitorPolicy(settings, rules, "127.0.0.1"); err != nil {
		t.Fatalf("UpdateMonitorPolicy: %v", err)
	}

	_, _, _, err := store.RecordMonitorSnapshots([]*vault.ServerMonitorSnapshot{dangerSnap})
	if err != nil {
		t.Fatalf("RecordMonitorSnapshots danger: %v", err)
	}
	activeAlerts, err := store.ListMonitorAlerts("active", srv.ID, 0)
	if err != nil {
		t.Fatalf("ListMonitorAlerts: %v", err)
	}
	fired := make(map[string]vault.AlertSeverity)
	for _, a := range activeAlerts {
		fired[a.RuleKind] = a.Severity
	}

	expected := []string{
		"unexpected_reboot",
		"oom_kill",
		"cpu_steal_high",
		"blocked_procs",
		"net_errors_spike",
		"disk_readonly",
		"disk_will_fill",
		"raid_degraded",
		"kernel_error",
		"uid_zero_backdoor",
		"firewall_inactive",
		"security_file_drift",
		"suspicious_process",
		"suspicious_outbound",
		"ssh_new_login_ip",
		"ssh_bruteforce",
	}
	for _, kind := range expected {
		if _, ok := fired[kind]; !ok {
			t.Errorf("expected zero-AI rule %q to fire, fired=%v (forecast=%.1fh)", kind, fired, dangerSnap.DiskFullForecastHours)
		}
	}
	if dangerSnap.DiskFullForecastHours <= 0 || dangerSnap.DiskFullForecastHours > 4 {
		t.Fatalf("expected ~1.3h disk forecast, got %.1fh", dangerSnap.DiskFullForecastHours)
	}

	// Accept Security Baseline -> resolves security_file_drift and ssh_new_login_ip!
	secBase, err := store.AcceptServerSecurityBaseline(srv.ID, "127.0.0.1")
	if err != nil || secBase.FileHashes["/root/.ssh/authorized_keys"] != "bbbb2222" {
		t.Fatalf("AcceptServerSecurityBaseline failed: %+v err=%v", secBase, err)
	}
	activeAfterAccept, _ := store.ListMonitorAlerts("active", srv.ID, 0)
	for _, a := range activeAfterAccept {
		if a.RuleKind == "security_file_drift" || a.RuleKind == "ssh_new_login_ip" {
			t.Fatalf("expected %s resolved after accepting security baseline", a.RuleKind)
		}
	}
}

func TestCrossIntervalCPUDiffAndFastSlowTierMerge(t *testing.T) {
	store, srv := setupTestMonitorStore(t)
	t0 := time.Now().UTC().Add(-60 * time.Second)

	// 1. Full tier establishes raw CPU ticks & static/security fields
	fullSnap := &vault.ServerMonitorSnapshot{
		ServerID:            srv.ID,
		CollectedAt:         t0,
		LastSlowCollectedAt: &t0,
		CollectionTier:      string(TierFull),
		Reachable:           true,
	}
	ParseDeepTelemetry(`
===SNS_SEC:SAMPLE_T0===
UP=5000.0
CPU=cpu 10000 0 2000 88000 0 0 0 0
CTXT=100000
===SNS_SEC:SAMPLE_T1===
UP=5000.25
CPU=cpu 10010 0 2005 88085 0 0 0 0
CTXT=100500
===SNS_SEC:SYS===
HOSTNAME=prod-fast-test
OS=Ubuntu 24.04 LTS
CORES=4
===SNS_SEC:IFACE===
IP4=eth0|10.0.0.9
OPER=eth0|up
===SNS_SEC:SEC===
FW=active|ufw
UID0=root
===SNS_END===
`, fullSnap, nil)
	_, _, _, _ = store.RecordMonitorSnapshots([]*vault.ServerMonitorSnapshot{fullSnap})

	// 2. Fast tier 60s later: NO SAMPLE_T1, NO static OS/FW/IP4! Must compute CPU from prev.RawCPUTicks -> cur T0 AND preserve static/security fields!
	prev, _ := store.GetPreviousMonitorSnapshot(srv.ID)
	fastSnap := &vault.ServerMonitorSnapshot{
		ServerID:       srv.ID,
		CollectedAt:    t0.Add(60 * time.Second),
		CollectionTier: string(TierFast),
		Reachable:      true,
	}
	// Delta from T1 (10010, 0, 2005, 88085) -> +600 user, +200 sys, +200 idle (total=1000 -> 80.0% CPU!)
	ParseDeepTelemetry(`
===SNS_SEC:SAMPLE_T0===
UP=5060.0
CPU=cpu 10610 0 2205 88285 0 0 0 0
CTXT=160500
NET=eth0 100000 100 0 0 100000 100 0 0
===SNS_SEC:IFACE===
OPER=eth0|up
===SNS_END===
`, fastSnap, prev)

	if fastSnap.CPUPercent != 80.0 || fastSnap.CPUUserPct != 60.0 || fastSnap.CPUSystemPct != 20.0 {
		t.Fatalf("expected cross-interval CPU 80.0%% (60%% user / 20%% sys), got %.1f%% (%.1f/%.1f)",
			fastSnap.CPUPercent, fastSnap.CPUUserPct, fastSnap.CPUSystemPct)
	}
	if fastSnap.ContextSwSec != 1000 {
		t.Fatalf("expected cross-interval ContextSwSec=1000/s, got %d", fastSnap.ContextSwSec)
	}

	_, _, _, err := store.RecordMonitorSnapshots([]*vault.ServerMonitorSnapshot{fastSnap})
	if err != nil {
		t.Fatalf("RecordMonitorSnapshots fast: %v", err)
	}
	if fastSnap.OS != "Ubuntu 24.04 LTS" || fastSnap.Security.FirewallStatus != "active" {
		t.Fatalf("expected fast tier to preserve slow-tier OS & FirewallStatus, got os=%q fw=%q",
			fastSnap.OS, fastSnap.Security.FirewallStatus)
	}
}

func TestSSHConnectionPoolReuseTransparentReconnectAndHostKeyMismatch(t *testing.T) {
	var acceptCount atomic.Int32
	var forceDropNext atomic.Bool
	var mu sync.Mutex
	var activeConns []net.Conn

	newSigner := func() ssh.Signer {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("gen key: %v", err)
		}
		s, err := ssh.NewSignerFromKey(priv)
		if err != nil {
			t.Fatalf("signer: %v", err)
		}
		return s
	}

	var curSigner atomic.Value
	curSigner.Store(newSigner())

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			acceptCount.Add(1)
			mu.Lock()
			activeConns = append(activeConns, conn)
			mu.Unlock()

			go func(nc net.Conn) {
				cfg := &ssh.ServerConfig{
					PasswordCallback: func(c ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
						if c.User() == "root" && string(p) == "PoolPass!1" {
							return nil, nil
						}
						return nil, errors.New("bad auth")
					},
				}
				cfg.AddHostKey(curSigner.Load().(ssh.Signer))
				_, chans, reqs, err := ssh.NewServerConn(nc, cfg)
				if err != nil {
					_ = nc.Close()
					return
				}
				// Reply to keepalive@openssh.com requests properly!
				go func() {
					for req := range reqs {
						if req.WantReply {
							_ = req.Reply(true, nil)
						}
					}
				}()
				for newChan := range chans {
					if newChan.ChannelType() != "session" {
						_ = newChan.Reject(ssh.UnknownChannelType, "unsupported")
						continue
					}
					ch, chReqs, err := newChan.Accept()
					if err != nil {
						continue
					}
					go func(in <-chan *ssh.Request) {
						for req := range in {
							if req.Type == "exec" {
								if req.WantReply {
									_ = req.Reply(true, nil)
								}
								_, _ = io.WriteString(ch, `
===SNS_SEC:SAMPLE_T0===
UP=500.0
CPU=cpu 100 0 20 880 0 0 0 0
===SNS_SEC:SYS===
HOSTNAME=pool-host
CORES=2
UPTIME_SEC=500
===SNS_SEC:MEM===
MemTotal=4096000
MemAvailable=3000000
===SNS_SEC:SAMPLE_T1===
UP=500.25
CPU=cpu 105 0 22 973 0 0 0 0
===SNS_END===
`)
								_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: 0}))
								_ = ch.Close()
								if forceDropNext.Swap(false) {
									_ = nc.Close()
								}
								return
							}
							if req.WantReply {
								_ = req.Reply(true, nil)
							}
						}
					}(chReqs)
				}
			}(conn)
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	store, err := vault.NewStore(filepath.Join(t.TempDir(), "vault.sns"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()
	if err := store.Setup("StrongPoolPass#2026", "127.0.0.1"); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	pass := "PoolPass!1"
	srv, err := store.CreateServer(vault.ServerMutationInput{
		Name:     "Pool-Node",
		Group:    "生产环境",
		Host:     "127.0.0.1",
		Port:     addr.Port,
		Username: "root",
		AuthType: vault.AuthPassword,
		Password: &pass,
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("CreateServer: %v", err)
	}

	sshMgr := sshmanager.NewManager(store)
	eng := NewEngine(store, sshMgr)
	defer eng.Close()

	// 1. Three consecutive sweeps with pooling enabled -> only ONE TCP accept!
	s1, err := eng.CollectServerNow(context.Background(), srv.ID, "", "127.0.0.1")
	if err != nil || !s1.Reachable || s1.ConnectionReused {
		t.Fatalf("sweep 1 expected fresh reachable conn, got %+v err=%v", s1, err)
	}
	s2, err := eng.CollectServerNow(context.Background(), srv.ID, "", "127.0.0.1")
	if err != nil || !s2.Reachable || !s2.ConnectionReused {
		t.Fatalf("sweep 2 expected reused pooled conn, got %+v err=%v", s2, err)
	}
	s3, err := eng.CollectServerNow(context.Background(), srv.ID, "", "127.0.0.1")
	if err != nil || !s3.Reachable || !s3.ConnectionReused {
		t.Fatalf("sweep 3 expected reused pooled conn, got %+v err=%v", s3, err)
	}
	if acceptCount.Load() != 1 {
		t.Fatalf("expected exactly 1 TCP SSH connection across 3 pooled sweeps, got %d", acceptCount.Load())
	}

	// 2. Forcibly drop server-side TCP socket -> next sweep transparently redials with Reachable=true!
	mu.Lock()
	for _, c := range activeConns {
		_ = c.Close()
	}
	activeConns = nil
	mu.Unlock()
	time.Sleep(30 * time.Millisecond)

	s4, err := eng.CollectServerNow(context.Background(), srv.ID, "", "127.0.0.1")
	if err != nil || !s4.Reachable {
		t.Fatalf("expected transparent redial after server-side disconnect, got %+v err=%v", s4, err)
	}
	if acceptCount.Load() != 2 {
		t.Fatalf("expected acceptCount=2 after transparent reconnect, got %d", acceptCount.Load())
	}

	// 3. Rotate host key & evict pool -> non-interactive batch sweep must detect host_key_changed (NOT generic offline)!
	curSigner.Store(newSigner())
	eng.EvictServerConnection(srv.ID)

	snaps, err := eng.CollectAllNow(context.Background(), []string{srv.ID}, "127.0.0.1")
	if err != nil || len(snaps) != 1 {
		t.Fatalf("CollectAllNow host key mismatch: snaps=%+v err=%v", snaps, err)
	}
	if !snaps[0].HostKeyChanged {
		t.Fatalf("expected HostKeyChanged=true on MITM/rotated key, got %+v", snaps[0])
	}
	alerts, _ := store.ListMonitorAlerts("active", srv.ID, 0)
	foundHK := false
	for _, a := range alerts {
		if a.RuleKind == "host_key_changed" && a.Severity == vault.SeverityCritical {
			foundHK = true
		}
		if a.RuleKind == "offline" {
			t.Fatalf("host key mismatch should not trigger generic offline alert: %+v", a)
		}
	}
	if !foundHK {
		t.Fatalf("expected Critical host_key_changed alert, got %+v", alerts)
	}
}

func TestMultiPlatformWebhookFormatsRetryAndAIPatrolReuse(t *testing.T) {
	// 1. Platform auto-detection & schema validation
	if p := detectWebhookPlatform("https://oapi.dingtalk.com/robot/send?access_token=abc"); p != "dingtalk" {
		t.Fatalf("expected dingtalk, got %s", p)
	}
	if p := detectWebhookPlatform("https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=xyz"); p != "wecom" {
		t.Fatalf("expected wecom, got %s", p)
	}
	if p := detectWebhookPlatform("https://open.feishu.cn/open-apis/bot/v2/hook/123"); p != "feishu" {
		t.Fatalf("expected feishu, got %s", p)
	}

	sample := []vault.MonitorAlert{{RuleKind: "oom_kill", Severity: vault.SeverityCritical, Title: "OOM", Detail: "killed"}}
	title, sum, md, color := formatAlertNotificationBodies(sample, nil)

	for _, tc := range []struct {
		platform string
		key      string
		val      string
	}{
		{"dingtalk", "msgtype", "markdown"},
		{"wecom", "msgtype", "markdown"},
		{"feishu", "msg_type", "interactive"},
		{"generic", "source", "ServerNeedSafe"},
	} {
		b, err := buildMonitorWebhookPayload(tc.platform, title, sum, md, color, sample, nil)
		if err != nil {
			t.Fatalf("%s payload err: %v", tc.platform, err)
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil || m[tc.key] != tc.val {
			t.Fatalf("%s payload mismatch: %s", tc.platform, string(b))
		}
	}

	// 2. Retry on transient HTTP 500 + AI Patrol signed custom channel forwarding
	var primaryAttempts atomic.Int32
	primarySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if primaryAttempts.Add(1) < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("temporary error"))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer primarySrv.Close()

	const aiSecret = "top-hmac-secret"
	var aiSigValid atomic.Bool
	aiChSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		sig := r.Header.Get("X-SNS-Signature")
		mac := hmac.New(sha256.New, []byte(aiSecret))
		_, _ = mac.Write(body)
		if sig == "sha256="+hex.EncodeToString(mac.Sum(nil)) && strings.Contains(string(body), "ServerNeedSafe") {
			aiSigValid.Store(true)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer aiChSrv.Close()

	store, _ := setupTestMonitorStore(t)
	// Configure an enabled AI patrol custom webhook channel
	aiURL := aiChSrv.URL
	aiSec := aiSecret
	if _, err := store.UpdatePatrolConfig(vault.PatrolConfigMutationInput{
		Enabled:         false,
		IntervalMinutes: 30,
		Webhooks: []vault.WebhookMutationInput{
			{ID: "wh-1", Name: "OpsHMAC", Kind: "custom", URL: &aiURL, Secret: &aiSec, Enabled: true},
		},
	}, "127.0.0.1"); err != nil {
		t.Fatalf("UpdatePatrolConfig: %v", err)
	}

	sshMgr := sshmanager.NewManager(store)
	eng := NewEngine(store, sshMgr)
	eng.webhookRetryWait = 10 * time.Millisecond
	defer eng.Close()

	eng.dispatchWebhook(primarySrv.URL, store.GetEnabledAIPatrolWebhooks(), sample, nil)

	if primaryAttempts.Load() != 3 {
		t.Fatalf("expected 3 attempts (2 retries) on transient 500, got %d", primaryAttempts.Load())
	}
	if !aiSigValid.Load() {
		t.Fatalf("expected forwarded AI patrol custom webhook with valid X-SNS-Signature HMAC")
	}
	st := eng.Status()
	if st.LastWebhookError != "" || st.LastWebhookAt == nil {
		t.Fatalf("expected clean webhook runtime status after retry success, got %+v", st)
	}
}

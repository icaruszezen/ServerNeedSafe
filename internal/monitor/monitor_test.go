package monitor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/sshmanager"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
	"golang.org/x/crypto/ssh"
)

func startCustomSSHServer(
	t *testing.T,
	user, pass string,
	execHandler func(cmd string) (stdout string, exitCode uint32),
) (host string, port int, stop func()) {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
			if c.User() == user && string(p) == pass {
				return nil, nil
			}
			return nil, errors.New("invalid credentials")
		},
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(nc net.Conn) {
				_, chans, reqs, err := ssh.NewServerConn(nc, cfg)
				if err != nil {
					_ = nc.Close()
					return
				}
				go ssh.DiscardRequests(reqs)
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
								var payload struct{ Command string }
								_ = ssh.Unmarshal(req.Payload, &payload)
								if req.WantReply {
									_ = req.Reply(true, nil)
								}
								out, code := execHandler(payload.Command)
								_, _ = io.WriteString(ch, out)
								_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: code}))
								_ = ch.Close()
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
	return "127.0.0.1", addr.Port, func() { _ = ln.Close() }
}

const sampleTelemetryRaw = `
===SNS_SEC:SAMPLE_T0===
UP=10000.00
CPU=cpu  1000 50 400 8000 300 20 30 200 0 0
CTXT=500000
NET=eth0 1000000 1000 0 0 2000000 1500 1 2
BIO=nvme0n1 500 4000 800 8000
===SNS_SEC:SYS===
HOSTNAME=prod-db-secret-node
OS=Ubuntu 24.04.1 LTS
KERNEL=6.8.0-45-generic
ARCH=x86_64
CORES=4
CPU_MODEL=AMD EPYC 9654 96-Core Processor
VIRT=kvm
UPTIME_SEC=176520
LOAD=5.20 3.80 2.10 4/512
SERVER_TIME=2026-11-16 18:30:00
TIMEZONE=UTC
NTP=yes
TEMP_C=64.5
===SNS_SEC:MEM===
MemTotal=16384000
MemFree=1024000
MemAvailable=2048000
Buffers=512000
Cached=1536000
SReclaimable=256000
SwapTotal=4096000
SwapFree=1024000
FILE_NR=4096 65536
OOM_KILL=2
===SNS_SEC:DISK===
FS=/dev/nvme0n1p1|ext4|104857600|89128960|15728640|85%|/
FS=/dev/nvme1n1|xfs|524288000|482344960|41943040|92%|/var/lib/postgresql
===SNS_SEC:INODE===
INODE=/|22%
INODE=/var/lib/postgresql|84%
===SNS_SEC:IFACE===
IP4=eth0|10.24.8.15
OPER=eth0|up
===SNS_SEC:SOCK===
TCP_01=142
TCP_03=15
TCP_06=88
TCP_08=240
TCP_0A=9
UDP_ALL=14
===SNS_SEC:PROC===
PSTAT=312 4 299 7 2
TOP_CPU=1842|postgres|185.4|42.1|6891520|R|12:04:11|postgres-secret-worker
TOP_MEM=1842|postgres|185.4|42.1|6891520|R|12:04:11|postgres-secret-worker
===SNS_SEC:PORTS===
tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=812,fd=3))
tcp LISTEN 0 511 [::]:443 [::]:* users:(("nginx",pid=1204,fd=6))
tcp LISTEN 0 244 127.0.0.1:5432 0.0.0.0:* users:(("postgres",pid=1840,fd=5))
udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=510,fd=13))
===SNS_SEC:SYSTEMD===
FAILED_UNIT=● backup-agent.service
SVC=postgresql|active|watched
SVC=redis-server|inactive|watched
SVC=nginx|active|auto
===SNS_SEC:DOCKER===
DOCKER_OK=1
CTR=abcdef1234567890|pgbouncer-pool|edoburu/pgbouncer:latest|running|Up 4 days (healthy)
CTR=9876543210fedcba|metrics-sidecar|prom/exporter:v1|running|Up 2 hours (unhealthy)
===SNS_SEC:SEC===
WHO=opsadmin|pts/0|2026-11-16 17:00|(198.51.100.42)
UID0=root
REBOOT_REQ=1
FW=active|ufw
MAC=AppArmor:Y
SSH_FAIL_CNT=64
SSH_FAIL_IP=203.0.113.77(48)
SSH_FAIL_IP=198.51.100.99(16)
===SNS_SEC:SAMPLE_T1===
UP=10000.50
CPU=cpu  1045 55 415 8010 315 22 28 210 0 0
CTXT=502500
NET=eth0 1250000 1200 0 0 2500000 1800 1 2
BIO=nvme0n1 550 6000 900 12000
`

func TestParseDeepTelemetryAllSections(t *testing.T) {
	now := time.Date(2026, 11, 16, 18, 30, 0, 0, time.UTC)
	snap := &vault.ServerMonitorSnapshot{
		ServerID:    "srv-1",
		CollectedAt: now,
		Reachable:   true,
	}

	ParseDeepTelemetry(sampleTelemetryRaw, snap, nil)

	if snap.Hostname != "prod-db-secret-node" || snap.CPUCores != 4 || snap.Virtualization != "kvm" {
		t.Fatalf("unexpected system identity: %+v", snap)
	}
	// Total CPU delta = 100 (idle delta = 10 -> 90.0% busy; user+nice = 50 -> 50.0%; sys+irq+softirq = 15 -> 15.0%; iowait = 15 -> 15.0%; steal = 10 -> 10.0%)
	if snap.CPUPercent != 90.0 || snap.CPUUserPct != 50.0 || snap.CPUIowaitPct != 15.0 || snap.CPUStealPct != 10.0 {
		t.Fatalf("unexpected CPU breakdown: total=%.1f user=%.1f sys=%.1f io=%.1f steal=%.1f",
			snap.CPUPercent, snap.CPUUserPct, snap.CPUSystemPct, snap.CPUIowaitPct, snap.CPUStealPct)
	}
	if snap.LoadPerCore != 1.3 || snap.ContextSwSec != 5000 || snap.CPUTempC != 64.5 {
		t.Fatalf("unexpected load/ctxt/temp: loadPerCore=%.1f ctxt=%d temp=%.1f", snap.LoadPerCore, snap.ContextSwSec, snap.CPUTempC)
	}
	// MemTotal 16000 MB, Available 2000 MB -> Used 14000 MB (87.5%)
	if snap.MemTotalMB != 16000 || snap.MemUsedMB != 14000 || snap.MemPercent != 87.5 || snap.SwapPercent != 75.0 || snap.OOMKills != 2 {
		t.Fatalf("unexpected memory/swap stats: %+v", snap)
	}
	// Disks: / (85%) and /var/lib/postgresql (92%, inode 84%)
	if len(snap.Disks) != 2 || snap.MaxPartPercent != 92.0 || snap.MaxInodePercent != 84.0 {
		t.Fatalf("unexpected disk partitions: %+v", snap.Disks)
	}
	// Disk I/O over dt=0.5s: read (6000-4000)*512 / 0.5 = 2,048,000 B/s; write (12000-8000)*512 / 0.5 = 4,096,000 B/s; IOPS = (150)/0.5 = 300
	if snap.DiskReadBps != 2048000 || snap.DiskWriteBps != 4096000 || snap.DiskIOPS != 300 {
		t.Fatalf("unexpected disk IO rates: r=%d w=%d iops=%d", snap.DiskReadBps, snap.DiskWriteBps, snap.DiskIOPS)
	}
	// Network eth0 over dt=0.5s: rx=(250000)/0.5=500000 B/s, tx=(500000)/0.5=1000000 B/s
	if snap.NetRxBps != 500000 || snap.NetTxBps != 1000000 || snap.TCPEstablished != 142 || snap.TCPCloseWait != 240 {
		t.Fatalf("unexpected network/socket stats: rx=%d tx=%d est=%d cw=%d", snap.NetRxBps, snap.NetTxBps, snap.TCPEstablished, snap.TCPCloseWait)
	}
	if snap.ProcsTotal != 312 || snap.ProcsZombie != 7 || len(snap.TopCPUProcs) != 1 {
		t.Fatalf("unexpected process stats: tot=%d zom=%d top=%+v", snap.ProcsTotal, snap.ProcsZombie, snap.TopCPUProcs)
	}
	if len(snap.ListeningPorts) != 4 || !snap.ListeningPorts[0].PublicExposed || snap.ListeningPorts[3].PublicExposed {
		t.Fatalf("unexpected listening ports: %+v", snap.ListeningPorts)
	}
	if snap.SystemdFailedCount != 1 || snap.Docker.Running != 2 || snap.Docker.Unhealthy != 1 {
		t.Fatalf("unexpected systemd/docker stats: failed=%d docker=%+v", snap.SystemdFailedCount, snap.Docker)
	}
	if snap.Security.SSHFailedRecent != 64 || !snap.Security.RebootRequired || snap.Security.FirewallStatus != "active" {
		t.Fatalf("unexpected security posture: %+v", snap.Security)
	}
}

func TestMonitorEngineRealSSHScheduledAlertsPortDriftAndZeroKnowledge(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sns")
	store, err := vault.NewStore(vaultPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := store.Setup("StrongMonitorPass#2026", "127.0.0.1"); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	// 1. Real Linux shell SSH server to verify end-to-end live telemetry script execution
	realHost, realPort, stopReal := startCustomSSHServer(t, "ops", "RealPass!1", func(cmd string) (string, uint32) {
		// Speed up the 250ms sleep in unit test while keeping genuine /bin/sh execution
		fastCmd := strings.ReplaceAll(cmd, "sleep 0.25 2>/dev/null || sleep 1", "sleep 0.05 2>/dev/null || true")
		out, runErr := exec.Command("/bin/sh", "-c", fastCmd).Output()
		if runErr != nil {
			return string(out), 1
		}
		return string(out), 0
	})
	defer stopReal()

	// 2. Controllable synthetic telemetry SSH server to test alert streaks, port drift & recovery
	var syntheticMode atomic.Int32 // 0 = healthy baseline, 1 = high CPU/disk + drifted port 9999, 2 = recovered
	synHost, synPort, stopSyn := startCustomSSHServer(t, "root", "SynPass!1", func(cmd string) (string, uint32) {
		mode := syntheticMode.Load()
		switch mode {
		case 0:
			return `
===SNS_SEC:SAMPLE_T0===
UP=100.0
CPU=cpu 100 0 50 850 0 0 0 0
===SNS_SEC:SYS===
HOSTNAME=canary-secret-host-alpha
OS=Debian GNU/Linux 12
CORES=4
LOAD=0.40 0.30 0.20 1/120
===SNS_SEC:MEM===
MemTotal=8192000
MemAvailable=6144000
===SNS_SEC:DISK===
FS=/dev/vda1|ext4|52428800|15728640|36700160|30%|/
===SNS_SEC:PORTS===
tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=500,fd=3))
tcp LISTEN 0 128 0.0.0.0:443 0.0.0.0:* users:(("caddy",pid=610,fd=4))
===SNS_SEC:SAMPLE_T1===
UP=100.25
CPU=cpu 110 0 55 935 0 0 0 0
`, 0
		case 1:
			return sampleTelemetryRaw + "\n===SNS_SEC:PORTS===\ntcp LISTEN 0 128 0.0.0.0:9999 0.0.0.0:* users:((\"rogue-miner\",pid=9001,fd=4))\n", 0
		default:
			return `
===SNS_SEC:SAMPLE_T0===
UP=200.0
CPU=cpu 200 0 80 1720 0 0 0 0
===SNS_SEC:SYS===
HOSTNAME=canary-secret-host-alpha
OS=Debian GNU/Linux 12
CORES=4
LOAD=0.20 0.25 0.20 1/120
===SNS_SEC:MEM===
MemTotal=8192000
MemAvailable=6500000
===SNS_SEC:DISK===
FS=/dev/vda1|ext4|52428800|15728640|36700160|30%|/
===SNS_SEC:PORTS===
tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=500,fd=3))
tcp LISTEN 0 128 0.0.0.0:443 0.0.0.0:* users:(("caddy",pid=610,fd=4))
===SNS_SEC:SYSTEMD===
SVC=postgresql|active|watched
SVC=redis-server|active|watched
===SNS_SEC:SAMPLE_T1===
UP=200.25
CPU=cpu 205 0 85 1810 0 0 0 0
`, 0
		}
	})
	defer stopSyn()

	// Setup local webhook receiver
	var webhookHits atomic.Int32
	webhookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err == nil && body["source"] == "ServerNeedSafe" {
			webhookHits.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer webhookSrv.Close()

	settings, rules, err := store.GetMonitorPolicy()
	if err != nil {
		t.Fatalf("GetMonitorPolicy: %v", err)
	}
	settings.WebhookURL = webhookSrv.URL
	settings.IntervalSec = 10
	if _, _, err := store.UpdateMonitorPolicy(settings, rules, "127.0.0.1"); err != nil {
		t.Fatalf("UpdateMonitorPolicy: %v", err)
	}

	realPass := "RealPass!1"
	realSrv, err := store.CreateServer(vault.ServerMutationInput{
		Name:     "Local-Linux-Live",
		Group:    "生产环境",
		Host:     realHost,
		Port:     realPort,
		Username: "ops",
		AuthType: vault.AuthPassword,
		Password: &realPass,
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("CreateServer real: %v", err)
	}

	synPass := "SynPass!1"
	synSrv, err := store.CreateServer(vault.ServerMutationInput{
		Name:            "Canary-DB-Node",
		Group:           "数据库集群",
		Host:            synHost,
		Port:            synPort,
		Username:        "root",
		AuthType:        vault.AuthPassword,
		Password:        &synPass,
		WatchedServices: []string{"postgresql", "redis-server"},
		WatchedPorts:    []int{443},
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("CreateServer syn: %v", err)
	}

	sshMgr := sshmanager.NewManager(store)
	engine := NewEngine(store, sshMgr)
	engine.tickInterval = 80 * time.Millisecond
	engine.Start()
	defer engine.Close()

	// Wait for automatic initial sweep upon engine start!
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		ov, err := store.GetMonitorOverview()
		if err == nil && ov.KPI.OnlineServers == 2 {
			break
		}
		time.Sleep(80 * time.Millisecond)
	}

	ov, err := store.GetMonitorOverview()
	if err != nil {
		t.Fatalf("GetMonitorOverview: %v", err)
	}
	if ov.KPI.OnlineServers != 2 {
		t.Fatalf("expected 2 online servers from automatic initial sweep, got %+v", ov.KPI)
	}

	realDetail, err := store.GetServerMonitorDetail(realSrv.ID, time.Hour)
	if err != nil || realDetail.Snapshot == nil || !realDetail.Snapshot.Reachable || realDetail.Snapshot.CPUCores < 1 || realDetail.Snapshot.MemTotalMB <= 0 {
		t.Fatalf("real Linux SSH collection failed: %+v, err=%v", realDetail, err)
	}

	// Verify initial baseline ports pinned on synSrv (tcp/22, tcp/443) and 0 active alerts
	synDetail0, err := store.GetServerMonitorDetail(synSrv.ID, time.Hour)
	if err != nil || len(synDetail0.PortBaseline) != 2 || len(synDetail0.Alerts) != 0 {
		t.Fatalf("expected 2 baseline ports and 0 alerts, got baseline=%v alerts=%v", synDetail0.PortBaseline, synDetail0.Alerts)
	}

	// Switch synthetic node to overload + rogue port 9999 + watched service redis-server down
	syntheticMode.Store(1)

	// 1st probe in mode 1: immediate 1-streak rules fire (mem_high, disk_high, port_drift, systemd_failed, ssh_bruteforce, docker_unhealthy),
	// while cpu_high (ConsecutiveCount=2) waits for 2nd consecutive breach!
	snap1, err := engine.CollectServerNow(context.Background(), synSrv.ID, "", "127.0.0.1")
	if err != nil || snap1.HealthLevel != vault.HealthCritical {
		t.Fatalf("expected critical snapshot on 1st overload probe, got %+v, err=%v", snap1, err)
	}

	alertsAfter1, _ := store.ListMonitorAlerts("active", synSrv.ID, 0)
	hasCPUHigh1 := false
	hasPortDrift1 := false
	for _, a := range alertsAfter1 {
		if a.RuleKind == "cpu_high" {
			hasCPUHigh1 = true
		}
		if a.RuleKind == "port_drift" {
			hasPortDrift1 = true
		}
	}
	if hasCPUHigh1 {
		t.Fatalf("cpu_high (ConsecutiveCount=2) should NOT fire on 1st single spike")
	}
	if !hasPortDrift1 {
		t.Fatalf("expected port_drift alert for newly exposed 0.0.0.0:9999")
	}

	// 2nd consecutive overload probe: cpu_high now fires!
	if _, err := engine.CollectServerNow(context.Background(), synSrv.ID, "", "127.0.0.1"); err != nil {
		t.Fatalf("2nd CollectServerNow: %v", err)
	}
	alertsAfter2, _ := store.ListMonitorAlerts("active", synSrv.ID, 0)
	hasCPUHigh2 := false
	for _, a := range alertsAfter2 {
		if a.RuleKind == "cpu_high" {
			hasCPUHigh2 = true
		}
	}
	if !hasCPUHigh2 {
		t.Fatalf("expected cpu_high to fire on 2nd consecutive breach")
	}

	// Accept port baseline -> resolves port_drift immediately
	newBase, err := store.AcceptServerPortBaseline(synSrv.ID, "127.0.0.1")
	if err != nil || len(newBase) == 0 {
		t.Fatalf("AcceptServerPortBaseline failed: %v", err)
	}

	// Recover synthetic node (mode 2) -> all remaining resource & service alerts auto-resolve!
	syntheticMode.Store(2)
	snapRec, err := engine.CollectServerNow(context.Background(), synSrv.ID, "", "127.0.0.1")
	if err != nil || snapRec.HealthLevel != vault.HealthHealthy {
		t.Fatalf("expected healthy snapshot after recovery, got %+v, err=%v", snapRec, err)
	}
	activeAfterRec, _ := store.ListMonitorAlerts("active", synSrv.ID, 0)
	if len(activeAfterRec) != 0 {
		t.Fatalf("expected all active alerts auto-resolved after recovery, still active: %+v", activeAfterRec)
	}

	// Verify webhook received notifications
	waitHook := time.Now().Add(2 * time.Second)
	for time.Now().Before(waitHook) && webhookHits.Load() == 0 {
		time.Sleep(30 * time.Millisecond)
	}
	if webhookHits.Load() == 0 {
		t.Fatalf("expected webhook notifications to be delivered")
	}

	// Verify ZERO-KNOWLEDGE disk encryption: raw vault.sns must contain ZERO plaintext telemetry secrets!
	rawBytes, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatalf("ReadFile vault.sns: %v", err)
	}
	forbiddenLeaks := []string{
		"prod-db-secret-node",
		"canary-secret-host-alpha",
		"postgres-secret-worker",
		"rogue-miner",
		"203.0.113.77",
		webhookSrv.URL,
	}
	for _, needle := range forbiddenLeaks {
		if bytes.Contains(rawBytes, []byte(needle)) {
			t.Fatalf("SECURITY VIOLATION: plaintext monitor data %q leaked in vault.sns!", needle)
		}
	}

	// Verify Vault Lock immediately scrubs memory & pauses engine
	store.Lock("unit test lock", "127.0.0.1")
	stLocked := engine.Status()
	if stLocked.VaultUnlocked || stLocked.NextSweepAt != nil {
		t.Fatalf("expected engine paused with nil NextSweepAt when vault locked, got %+v", stLocked)
	}
	if _, err := store.GetMonitorOverview(); !errors.Is(err, vault.ErrVaultLocked) {
		t.Fatalf("expected ErrVaultLocked when reading monitor overview while locked, got %v", err)
	}
}

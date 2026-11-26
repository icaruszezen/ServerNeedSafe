package monitor

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/sshmanager"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

func writeExecutableStub(t *testing.T, dir, name, body string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatalf("write stub %s: %v", name, err)
	}
}

// buildFakeDarwinBinDir creates a realistic Apple Silicon Mac mini CLI fixture directory
// so we execute the real generated shell/awk telemetry script end-to-end without skipping a single pipeline.
func buildFakeDarwinBinDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	stateFile := filepath.Join(dir, "sample_count")

	writeExecutableStub(t, dir, "uname", `
case "$1" in
  -s) echo "Darwin" ;;
  -r) echo "24.3.0" ;;
  -m) echo "arm64" ;;
  -n) echo "zezendeMac-mini.local" ;;
  *) echo "Darwin" ;;
esac`)

	writeExecutableStub(t, dir, "hostname", `echo "zezendeMac-mini.local"`)

	writeExecutableStub(t, dir, "sw_vers", `
case "$1" in
  -productName) echo "macOS" ;;
  -productVersion) echo "15.3.1" ;;
  -buildVersion) echo "24D70" ;;
esac`)

	writeExecutableStub(t, dir, "sysctl", `
case "$2" in
  hw.ncpu) echo "10" ;;
  machdep.cpu.brand_string) echo "Apple M4" ;;
  kern.hv_vmm_present) echo "0" ;;
  kern.boottime) echo "{ sec = 1795500000, usec = 123456 } Tue Nov 24 14:00:00 2026" ;;
  vm.loadavg) echo "{ 2.40 1.95 1.70 }" ;;
  hw.memsize) echo "25769803776" ;;
  hw.pagesize) echo "16384" ;;
  vm.swapusage) echo "total = 2048.00M  used = 512.00M  free = 1536.00M  (encrypted)" ;;
  kern.num_files) echo "12288" ;;
  kern.maxfiles) echo "245760" ;;
esac`)

	writeExecutableStub(t, dir, "date", `
case "$1" in
  +%s) echo "1795704000" ;;
  '+%Y-%m-%d %H:%M:%S') echo "2026-11-26 22:40:00" ;;
  '+%Z') echo "CST" ;;
  *) echo "2026-11-26" ;;
esac`)

	// Emit T0=1795704000.000 on first perl call and T1=1795704001.000 on second call (dt=1.0s)
	writeExecutableStub(t, dir, "perl", `
CNT=$(cat "`+stateFile+`" 2>/dev/null || echo 0)
CNT=$((CNT + 1))
echo "$CNT" > "`+stateFile+`"
if [ "$CNT" -eq 1 ]; then
  echo "1795704000.000"
else
  echo "1795704001.000"
fi`)

	// Apple Silicon 16384-byte page vm_stat fixture (24 GiB total = 1572864 pages)
	// App = anon(500000) - purgeable(50000) = 450000; wired = 200000; compressor = 136432 -> used = 786432 pages = 12 GiB (50.0%)
	writeExecutableStub(t, dir, "vm_stat", `cat <<'EOF'
Mach Virtual Memory Statistics: (page size of 16384 bytes)
Pages free:                               100000.
Pages active:                             450000.
Pages inactive:                           300000.
Pages speculative:                         20000.
Pages wired down:                         200000.
Pages purgeable:                           50000.
File-backed pages:                        250000.
Anonymous pages:                          500000.
Pages stored in compressor:               260000.
Pages occupied by compressor:             136432.
EOF`)

	writeExecutableStub(t, dir, "mount", `cat <<'EOF'
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
devfs on /dev (devfs, local, nobrowse)
/dev/disk3s5 on /System/Volumes/Data (apfs, local, journaled, nobrowse)
/dev/disk3s6 on /System/Volumes/VM (apfs, local, noexec, journaled, noatime, nobrowse)
/dev/disk4s1 on /Volumes/Backup (2026) SSD (apfs, local, nodev, nosuid, journaled)
map auto_home on /System/Volumes/Data/home (autofs, automounted, nobrowse)
EOF`)

	writeExecutableStub(t, dir, "df", `cat <<'EOF'
Filesystem     1024-blocks      Used Available Capacity iused      ifree %iused  Mounted on
/dev/disk3s1s1   524288000  10485760 262144000     4%  412345 2621440000    1%   /
devfs                  202       202         0   100%     700          0  100%   /dev
/dev/disk3s6     524288000        20 262144000     1%       1 2621440000    0%   /System/Volumes/VM
/dev/disk3s5     524288000 241172480 262144000    48% 2500000 2621440000    3%   /System/Volumes/Data
map auto_home            0         0         0   100%       0          0     -   /System/Volumes/Data/home
/dev/disk4s1    1048576000 314572800 734003200    30%  500000 4294967295    2%   /Volumes/Backup (2026) SSD
EOF`)

	writeExecutableStub(t, dir, "ifconfig", `cat <<'EOF'
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
	inet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	ether a4:5e:60:aa:bb:cc
	inet 192.168.50.111 netmask 0xffffff00 broadcast 192.168.50.255
	status: active
utun3: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1280
	inet 100.64.0.11 --> 100.64.0.11 netmask 0xffffffff
EOF`)

	// netstat serves -ibn (with T0 vs T1 incrementing byte counters), -an -p tcp/udp, and -anv -p tcp/udp
	writeExecutableStub(t, dir, "netstat", `
CNT=$(cat "`+stateFile+`" 2>/dev/null || echo 1)
if [ "$1" = "-ibn" ]; then
  if [ "$CNT" -le 1 ]; then
    cat <<'EOF'
Name  Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes  Coll
lo0   16384 <Link#1>                        100000     0   99999999   100000     0   99999999     0
en0   1500  <Link#4>      a4:5e:60:aa:bb:cc 500000     1 1000000000   400000     2  500000000     0
en0   1500  192.168.50    192.168.50.111    500000     - 1000000000   400000     -  500000000     -
awdl0 1500  <Link#8>      de:ad:be:ef:00:01    500     0     500000      500     0     500000     0
utun3 1280  <Link#12>                         2000     0    1000000     1500     0     800000     0
utun4 1280  <Link#13>                            0     0          0        0     0          0     0
EOF
  else
    cat <<'EOF'
Name  Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes  Coll
lo0   16384 <Link#1>                        150000     0  199999999   150000     0  199999999     0
en0   1500  <Link#4>      a4:5e:60:aa:bb:cc 501000     1 1000500000   400800     2  500250000     0
en0   1500  192.168.50    192.168.50.111    501000     - 1000500000   400800     -  500250000     -
awdl0 1500  <Link#8>      de:ad:be:ef:00:01    600     0     600000      600     0     600000     0
utun3 1280  <Link#12>                         2100     0    1050000     1600     0     825000     0
utun4 1280  <Link#13>                            0     0          0        0     0          0     0
EOF
  fi
elif [ "$1" = "-an" ] && [ "$3" = "tcp" ]; then
  cat <<'EOF'
Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)
tcp4       0      0  192.168.50.111.22      192.168.50.5.52001     ESTABLISHED
tcp4       0      0  192.168.50.111.443     192.168.50.5.52002     ESTABLISHED
tcp4       0      0  127.0.0.1.8080         127.0.0.1.53111        TIME_WAIT
tcp4       0      0  127.0.0.1.5432         127.0.0.1.53112        CLOSE_WAIT
tcp4       0      0  *.22                   *.*                    LISTEN
tcp6       0      0  *.22                   *.*                    LISTEN
tcp4       0      0  127.0.0.1.18899        *.*                    LISTEN
EOF
elif [ "$1" = "-an" ] && [ "$3" = "udp" ]; then
  cat <<'EOF'
Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)
udp4       0      0  *.5353                 *.*
udp6       0      0  fe80::1%lo0.5353       *.*
EOF
elif [ "$1" = "-anv" ] && [ "$3" = "tcp" ]; then
  cat <<'EOF'
Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)     rhiwat shiwat pid   epid state options
tcp4       0      0  *.22                   *.*                    LISTEN      131072 131072 812   0    0x0   0x0
tcp6       0      0  *.22                   *.*                    LISTEN      131072 131072 812   0    0x0   0x0
tcp4       0      0  127.0.0.1.18899        *.*                    LISTEN      131072 131072 2401  0    0x0   0x0
tcp46      0      0  *.8443                 *.*                    LISTEN      131072 131072 0     0    0x0   0x0 caddy:3001
EOF
elif [ "$1" = "-anv" ] && [ "$3" = "udp" ]; then
  cat <<'EOF'
Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        rhiwat shiwat pid   epid
udp6       0      0  fe80::1%lo0.5353       *.*                    131072 131072 180   0
EOF
fi`)

	writeExecutableStub(t, dir, "ioreg", `
CNT=$(cat "`+stateFile+`" 2>/dev/null || echo 1)
if [ "$CNT" -le 1 ]; then
  echo '    | |   "Statistics" = {"Operations (Write)"=1000,"Bytes (Read)"=104857600,"Operations (Read)"=2000,"Bytes (Write)"=52428800}'
else
  echo '    | |   "Statistics" = {"Operations (Write)"=1120,"Bytes (Read)"=109051904,"Operations (Read)"=2080,"Bytes (Write)"=54525952}'
fi`)

	writeExecutableStub(t, dir, "top", `cat <<'EOF'
Processes: 410 total, 3 running, 407 sleeping, 2048 threads
Load Avg: 2.40, 1.95, 1.70
CPU usage: 45.00% user, 25.00% sys, 30.00% idle
Processes: 410 total, 2 running, 408 sleeping, 2048 threads
Load Avg: 2.40, 1.95, 1.70
CPU usage: 14.50% user, 6.20% sys, 79.30% idle
EOF`)

	writeExecutableStub(t, dir, "ps", `
if [ "$1" = "-axo" ] && [ "$2" = "stat=" ]; then
  printf "R\nR\nS\nU\nZ\nI\n"
elif [ "$1" = "-axo" ] && [ "$2" = "pid=,comm=" ]; then
  printf "180 /usr/sbin/mDNSResponder\n812 /usr/sbin/sshd\n2401 /Applications/OrbStack.app/Contents/MacOS/OrbStack Helper\n3001 /opt/homebrew/bin/caddy\n"
elif [ "$1" = "-axr" ]; then
  printf "2401 zezen 28.4 3.2 524288 R 02:14:10 /Applications/OrbStack.app/Contents/MacOS/OrbStack Helper\n3001 zezen 4.1 0.5 65536 S 1-03:10:00 /opt/homebrew/bin/caddy\n"
elif [ "$1" = "-axm" ]; then
  printf "2401 zezen 28.4 3.2 524288 R 02:14:10 /Applications/OrbStack.app/Contents/MacOS/OrbStack Helper\n"
fi`)

	writeExecutableStub(t, dir, "lsof", `cat <<'EOF'
COMMAND  PID  USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
caddy   3001 zezen   12u  IPv4 0x1234      0t0  TCP *:8443 (LISTEN)
EOF`)

	writeExecutableStub(t, dir, "launchctl", `cat <<'EOF'
PID	Status	Label
-	0	com.apple.Spotlight
-	1	com.apple.some-noisy-agent
4412	0	homebrew.mxcl.redis
-	78	homebrew.mxcl.postgresql@16
EOF`)

	writeExecutableStub(t, dir, "pgrep", `
case "$2" in
  timed|sshd|caddy) exit 0 ;;
  *) exit 1 ;;
esac`)

	writeExecutableStub(t, dir, "docker", `
if [ "$1" = "info" ]; then exit 0; fi
if [ "$1" = "ps" ]; then
  echo "1122334455667788|serverneedsafe|ghcr.io/icaruszezen/serverneedsafe:latest|running|Up 3 hours (healthy)"
fi`)

	writeExecutableStub(t, dir, "who", `cat <<'EOF'
zezen    console      Nov 25 09:30
zezen    ttys001      Nov 26 22:35 (192.168.50.5)
EOF`)

	writeExecutableStub(t, dir, "dscl", `cat <<'EOF'
root                     0
zezen                    501
daemon                   1
EOF`)

	writeExecutableStub(t, dir, "defaults", `echo "1"`)
	writeExecutableStub(t, dir, "csrutil", `echo "System Integrity Protection status: enabled."`)
	writeExecutableStub(t, dir, "log", `cat <<'EOF'
2026-11-26 22:10:01.000000+0800 localhost sshd-session[901]: Failed password for invalid user admin from 198.51.100.23 port 44120 ssh2
2026-11-26 22:10:03.000000+0800 localhost sshd-session[902]: Invalid user test from 198.51.100.23 port 44121
EOF`)

	return dir
}

func TestMacOSDeepTelemetryEndToEndScriptExecutionAndParse(t *testing.T) {
	fakeBin := buildFakeDarwinBinDir(t)

	settings := vault.DefaultMonitorSettings()
	script := buildDeepTelemetryScript(settings, []string{"redis", "postgresql@16"})

	// Prepend fake Darwin stubs ahead of system PATH so POSIX tools (awk/grep/sed/sort) run natively
	// while Darwin OS commands resolve to our realistic Apple Silicon Mac mini fixtures.
	testScript := strings.Replace(
		script,
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"PATH="+fakeBin+":/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		1,
	)

	outBytes, err := exec.Command("/bin/sh", "-c", testScript).CombinedOutput()
	if err != nil {
		t.Fatalf("Darwin telemetry script execution failed: %v\noutput:\n%s", err, string(outBytes))
	}
	rawOut := string(outBytes)

	now := time.Date(2026, 11, 26, 14, 40, 0, 0, time.UTC)
	snap := &vault.ServerMonitorSnapshot{
		ServerID:    "srv-macmini",
		ServerName:  "macmini",
		CollectedAt: now,
		Reachable:   true,
	}
	ParseDeepTelemetry(rawOut, snap, nil)

	// 1. System identity & load
	if snap.Hostname != "zezendeMac-mini.local" || snap.OS != "macOS 15.3.1 (24D70)" || snap.Kernel != "24.3.0" || snap.Arch != "arm64" {
		t.Fatalf("unexpected macOS system identity: host=%q os=%q kernel=%q arch=%q", snap.Hostname, snap.OS, snap.Kernel, snap.Arch)
	}
	if snap.CPUCores != 10 || snap.CPUModel != "Apple M4" || snap.Virtualization != "" || !snap.NTPSynced {
		t.Fatalf("unexpected macOS hardware/clock: cores=%d model=%q virt=%q ntp=%v", snap.CPUCores, snap.CPUModel, snap.Virtualization, snap.NTPSynced)
	}
	if snap.UptimeSec != 204000 || snap.Uptime != "2d 8h 40m" {
		t.Fatalf("unexpected macOS uptime: sec=%d human=%q", snap.UptimeSec, snap.Uptime)
	}
	if snap.Load1 != 2.40 || snap.Load5 != 1.95 || snap.Load15 != 1.70 || snap.LoadPerCore != 0.2 {
		t.Fatalf("unexpected macOS load: %.2f / %.2f / %.2f (perCore=%.1f)", snap.Load1, snap.Load5, snap.Load15, snap.LoadPerCore)
	}

	// 2. CPU from second top sample (14.50% user, 6.20% sys, 79.30% idle -> 20.7% total)
	if snap.CPUPercent != 20.7 || snap.CPUUserPct != 14.5 || snap.CPUSystemPct != 6.2 {
		t.Fatalf("unexpected macOS CPU breakdown: total=%.1f user=%.1f sys=%.1f", snap.CPUPercent, snap.CPUUserPct, snap.CPUSystemPct)
	}

	// 3. Memory (24 GiB total = 24576 MB, 50% used = 12288 MB), Swap (2048 MB total, 512 MB used = 25%), FD (12288/245760 = 5%)
	if snap.MemTotalMB != 24576 || snap.MemUsedMB != 12288 || snap.MemPercent != 50.0 {
		t.Fatalf("unexpected macOS memory: used=%d total=%d pct=%.1f", snap.MemUsedMB, snap.MemTotalMB, snap.MemPercent)
	}
	if snap.SwapTotalMB != 2048 || snap.SwapUsedMB != 512 || snap.SwapPercent != 25.0 {
		t.Fatalf("unexpected macOS swap: used=%d total=%d pct=%.1f", snap.SwapUsedMB, snap.SwapTotalMB, snap.SwapPercent)
	}
	if snap.FDUsed != 12288 || snap.FDMax != 245760 || snap.FDPercent != 5.0 {
		t.Fatalf("unexpected macOS FD stats: %d/%d (%.1f%%)", snap.FDUsed, snap.FDMax, snap.FDPercent)
	}

	// 4. APFS Disks & Inodes: / reflects real APFS container usage (50% = 250/500 GB, max inode 3%), plus "/Volumes/Backup SSD" (30%)
	if len(snap.Disks) != 2 {
		t.Fatalf("expected 2 real macOS disks (/ and /Volumes/Backup SSD), got %+v", snap.Disks)
	}
	if snap.DiskPercent != 50.0 || snap.DiskTotalGB != 500.0 || snap.DiskUsedGB != 250.0 || snap.MaxInodePercent != 3.0 {
		t.Fatalf("unexpected macOS root APFS disk metrics: used=%.1f total=%.1f pct=%.1f maxInode=%.1f disks=%+v",
			snap.DiskUsedGB, snap.DiskTotalGB, snap.DiskPercent, snap.MaxInodePercent, snap.Disks)
	}
	if snap.Disks[1].MountPoint != "/Volumes/Backup (2026) SSD" || snap.Disks[1].FSType != "apfs" || snap.Disks[1].UsedPercent != 30.0 {
		t.Fatalf("expected external volume with spaces and parentheses preserved, got %+v", snap.Disks[1])
	}

	// 5. Disk I/O rates from ioreg over dt=1.0s: read +4MB/s (4194304), write +2MB/s (2097152), IOPS = 80+120 = 200
	if snap.DiskReadBps != 4194304 || snap.DiskWriteBps != 2097152 || snap.DiskIOPS != 200 {
		t.Fatalf("unexpected macOS disk I/O rates: r=%d w=%d iops=%d", snap.DiskReadBps, snap.DiskWriteBps, snap.DiskIOPS)
	}

	// 6. Network interfaces (lo0 & awdl0 & zero-traffic utun4 excluded; en0 + active utun3 included) & sockets
	if len(snap.Interfaces) != 2 {
		t.Fatalf("expected 2 active macOS interfaces (en0, utun3), got %+v", snap.Interfaces)
	}
	// en0 delta = +500KB/s rx, +250KB/s tx; utun3 delta = +50KB/s rx, +25KB/s tx -> total = 550000 rx, 275000 tx
	if snap.NetRxBps != 550000 || snap.NetTxBps != 275000 {
		t.Fatalf("unexpected macOS net throughput: rx=%d tx=%d ifaces=%+v", snap.NetRxBps, snap.NetTxBps, snap.Interfaces)
	}
	if snap.Interfaces[0].Name != "en0" || snap.Interfaces[0].IPv4 != "192.168.50.111" || snap.Interfaces[0].State != "up" {
		t.Fatalf("unexpected en0 interface metadata: %+v", snap.Interfaces[0])
	}
	if snap.TCPEstablished != 2 || snap.TCPTimeWait != 1 || snap.TCPCloseWait != 1 || snap.TCPListen != 3 || snap.UDPSockets != 2 {
		t.Fatalf("unexpected macOS socket matrix: est=%d tw=%d cw=%d lis=%d udp=%d",
			snap.TCPEstablished, snap.TCPTimeWait, snap.TCPCloseWait, snap.TCPListen, snap.UDPSockets)
	}

	// 7. Processes (U state counted as blocked; basename preserved with spaces!)
	if snap.ProcsTotal != 6 || snap.ProcsRunning != 2 || snap.ProcsBlocked != 1 || snap.ProcsZombie != 1 {
		t.Fatalf("unexpected macOS process states: tot=%d run=%d blk=%d zom=%d",
			snap.ProcsTotal, snap.ProcsRunning, snap.ProcsBlocked, snap.ProcsZombie)
	}
	if len(snap.TopCPUProcs) < 2 || snap.TopCPUProcs[0].Command != "OrbStack Helper" || snap.TopCPUProcs[0].RSSMB != 512.0 {
		t.Fatalf("unexpected macOS top CPU procs: %+v", snap.TopCPUProcs)
	}

	// 8. Listening ports (TCP + UDP + IPv6 scope stripping + process resolution)
	if len(snap.ListeningPorts) != 5 {
		t.Fatalf("expected 5 listening ports (tcp/22, tcp6/22, udp6/5353, tcp/8443, tcp/18899), got %+v", snap.ListeningPorts)
	}
	foundSSH, foundCaddy, foundMDNS := false, false, false
	for _, lp := range snap.ListeningPorts {
		if lp.Port == 22 && lp.Proto == "tcp" && lp.PublicExposed && lp.Process == "sshd" && lp.PID == 812 {
			foundSSH = true
		}
		if lp.Port == 8443 && lp.PublicExposed && lp.Process == "caddy" && lp.PID == 3001 {
			foundCaddy = true
		}
		if lp.Port == 5353 && lp.Proto == "udp6" && lp.BindAddr == "[fe80::1]" && !lp.PublicExposed && lp.Process == "mDNSResponder" {
			foundMDNS = true
		}
	}
	if !foundSSH || !foundCaddy || !foundMDNS {
		t.Fatalf("missing expected macOS listening ports (ssh=%v caddy=%v mdns=%v): %+v", foundSSH, foundCaddy, foundMDNS, snap.ListeningPorts)
	}

	// 9. Launchd / Homebrew services (noisy com.apple.* ignored; crashed homebrew.mxcl.postgresql@16 caught!)
	if snap.SystemdFailedCount != 1 || len(snap.SystemdFailedUnits) != 1 || snap.SystemdFailedUnits[0] != "postgresql@16" {
		t.Fatalf("expected only failed homebrew service postgresql@16 (not com.apple.*), got count=%d units=%+v", snap.SystemdFailedCount, snap.SystemdFailedUnits)
	}
	if !snap.Docker.Installed || snap.Docker.Running != 1 || len(snap.Docker.Containers) != 1 || snap.Docker.Containers[0].Name != "serverneedsafe" {
		t.Fatalf("unexpected macOS Docker summary: %+v", snap.Docker)
	}

	// 10. Security posture (who 3-field date, dscl UID0, ALF firewall, SIP MAC, unified log SSH failures)
	if len(snap.Security.ActiveUsers) != 2 || snap.Security.ActiveUsers[1].FromIP != "192.168.50.5" || snap.Security.ActiveUsers[1].LoginTime != "Nov 26 22:35" {
		t.Fatalf("unexpected macOS active users: %+v", snap.Security.ActiveUsers)
	}
	if snap.Security.FirewallStatus != "active" || snap.Security.FirewallDetail != "macos-alf" || snap.Security.MACFramework != "SIP:enabled" {
		t.Fatalf("unexpected macOS firewall/MAC: %+v", snap.Security)
	}
	if snap.Security.SSHFailedRecent != 2 || len(snap.Security.TopFailedIPs) != 1 || snap.Security.TopFailedIPs[0] != "198.51.100.23(2)" {
		t.Fatalf("unexpected macOS SSH brute-force audit: %+v", snap.Security)
	}
}

func TestMonitorEngineWithFakeMacOSSSHServer(t *testing.T) {
	fakeBin := buildFakeDarwinBinDir(t)

	host, port, stop := startCustomSSHServer(t, "zezen", "MacPass!1", func(cmd string) (string, uint32) {
		testCmd := strings.Replace(
			cmd,
			"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			"PATH="+fakeBin+":/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			1,
		)
		out, err := exec.Command("/bin/sh", "-c", testCmd).Output()
		if err != nil {
			return string(out), 1
		}
		return string(out), 0
	})
	defer stop()

	store, err := vault.NewStore(filepath.Join(t.TempDir(), "vault.sns"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()
	if err := store.Setup("StrongMacMonitorPass#2026", "127.0.0.1"); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	pass := "MacPass!1"
	srv, err := store.CreateServer(vault.ServerMutationInput{
		Name:     "macmini",
		Group:    "本地服务器",
		Host:     host,
		Port:     port,
		Username: "zezen",
		AuthType: vault.AuthPassword,
		Password: &pass,
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("CreateServer: %v", err)
	}

	sshMgr := sshmanager.NewManager(store)
	engine := NewEngine(store, sshMgr)

	snap, err := engine.CollectServerNow(context.Background(), srv.ID, "", "127.0.0.1")
	if err != nil {
		t.Fatalf("CollectServerNow macmini: %v", err)
	}
	if !snap.Reachable || snap.OS != "macOS 15.3.1 (24D70)" || snap.CPUCores != 10 || snap.MemTotalMB != 24576 || snap.DiskTotalGB != 500.0 || snap.CPUPercent != 20.7 {
		t.Fatalf("unexpected macmini collected snapshot: %+v", snap)
	}

	// Verify HostMemory auto-sync records Darwin kernel prefix (never "Linux 24.3.0")
	mems, err := store.ListHostMemories()
	if err != nil || len(mems) != 1 {
		t.Fatalf("expected 1 synced host memory, got %+v err=%v", mems, err)
	}
	if !strings.Contains(mems[0].OSArch, "Darwin 24.3.0") || strings.Contains(mems[0].OSArch, "Linux ") {
		t.Fatalf("expected Darwin kernel in HostMemory OSArch, got %q", mems[0].OSArch)
	}
}

func TestMacOSFastTierTelemetryExecutionAndInterfaceStatePreservation(t *testing.T) {
	fakeBin := buildFakeDarwinBinDir(t)
	settings := vault.DefaultMonitorSettings()

	runScript := func(script string) string {
		t.Helper()
		testScript := strings.Replace(
			script,
			"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			"PATH="+fakeBin+":/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			1,
		)
		shells := []string{"/bin/sh"}
		if bashPath, err := exec.LookPath("bash"); err == nil {
			shells = append(shells, bashPath)
		}
		var lastOut string
		for _, sh := range shells {
			outBytes, err := exec.Command(sh, "-c", testScript).CombinedOutput()
			if err != nil {
				t.Fatalf("Darwin script failed under %s: %v\noutput:\n%s", sh, err, string(outBytes))
			}
			lastOut = string(outBytes)
			if !strings.Contains(lastOut, "===SNS_END===") {
				t.Fatalf("Darwin script missing ===SNS_END=== under %s:\n%s", sh, lastOut)
			}
		}
		return lastOut
	}

	store, err := vault.NewStore(filepath.Join(t.TempDir(), "vault.sns"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()
	if err := store.Setup("StrongMacFastPass#2026", "127.0.0.1"); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	pass := "MacPass!1"
	srv, err := store.CreateServer(vault.ServerMutationInput{
		Name:     "macmini-fast",
		Group:    "本地服务器",
		Host:     "127.0.0.1",
		Port:     22,
		Username: "zezen",
		AuthType: vault.AuthPassword,
		Password: &pass,
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("CreateServer: %v", err)
	}

	// 1. Full tier establishes OS, IPv4, interface operational State, and security posture
	t0 := time.Date(2026, 11, 26, 14, 40, 0, 0, time.UTC)
	fullOut := runScript(buildTelemetryScript(settings, []string{"redis"}, TierFull, false))
	fullSnap := &vault.ServerMonitorSnapshot{
		ServerID:            srv.ID,
		ServerName:          srv.Name,
		CollectedAt:         t0,
		LastSlowCollectedAt: &t0,
		CollectionTier:      string(TierFull),
		Reachable:           true,
	}
	ParseDeepTelemetry(fullOut, fullSnap, nil)
	if _, _, _, err := store.RecordMonitorSnapshots([]*vault.ServerMonitorSnapshot{fullSnap}); err != nil {
		t.Fatalf("RecordMonitorSnapshots full: %v", err)
	}

	// 2. Fast tier omits Darwin ifconfig; must execute cleanly in /bin/sh & bash AND preserve en0 IPv4 + State="up"
	fastOut := runScript(buildTelemetryScript(settings, []string{"redis"}, TierFast, true))
	fastSnap := &vault.ServerMonitorSnapshot{
		ServerID:       srv.ID,
		ServerName:     srv.Name,
		CollectedAt:    t0.Add(60 * time.Second),
		CollectionTier: string(TierFast),
		Reachable:      true,
	}
	ParseDeepTelemetry(fastOut, fastSnap, fullSnap)
	if _, _, _, err := store.RecordMonitorSnapshots([]*vault.ServerMonitorSnapshot{fastSnap}); err != nil {
		t.Fatalf("RecordMonitorSnapshots fast: %v", err)
	}

	if fastSnap.OS != "macOS 15.3.1 (24D70)" || fastSnap.Security.FirewallStatus != "active" {
		t.Fatalf("expected fast tier to preserve macOS static/security fields, got os=%q fw=%q", fastSnap.OS, fastSnap.Security.FirewallStatus)
	}
	var foundEn0 bool
	for _, nic := range fastSnap.Interfaces {
		if nic.Name == "en0" {
			foundEn0 = true
			if nic.IPv4 != "192.168.50.111" || nic.State != "up" {
				t.Fatalf("expected fast-tier macOS en0 to preserve IPv4 and State='up', got %+v", nic)
			}
		}
	}
	if !foundEn0 {
		t.Fatalf("expected en0 interface in fast-tier macOS snapshot, got %+v", fastSnap.Interfaces)
	}
}

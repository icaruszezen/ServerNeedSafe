package aiops

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/icaruszezen/ServerNeedSafe/internal/sshmanager"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

func TestMacOSCommandClassifierSafety(t *testing.T) {
	readOnlyCases := []string{
		"sw_vers",
		"vm_stat",
		"pagesize",
		"memory_pressure",
		"memory_pressure -Q",
		"sysctl -n hw.memsize",
		"top -l 2 -n 0",
		"top -l1 -n 10",
		"launchctl list",
		"launchctl print gui/501/homebrew.mxcl.redis",
		"diskutil list",
		"diskutil info /",
		"diskutil apfs list",
		"scutil --dns",
		"networksetup -listallhardwareports",
		"pmset -g batt",
		"log show --style syslog --last 1h --predicate 'process == \"sshd\"'",
		"dscl . -list /Users UniqueID",
		"defaults read /Library/Preferences/com.apple.alf globalstate",
		"plutil -lint /Library/LaunchDaemons/test.plist",
		"csrutil status",
		"pfctl -s info",
		"brew list && brew services list",
		"/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate",
		"ioreg -c IOBlockStorageDriver -r -k Statistics -w 0",
		"system_profiler SPHardwareDataType",
		"lsof -nP -iTCP -sTCP:LISTEN",
	}
	for _, cmd := range readOnlyCases {
		risk, reason := ClassifyCommand(cmd)
		if risk != RiskReadOnly {
			t.Fatalf("expected RiskReadOnly for macOS command %q, got %s (%s)", cmd, risk, reason)
		}
	}

	mutatingCases := []string{
		"top -l 0",
		"memory_pressure -S -l critical",
		"launchctl kickstart -k gui/501/homebrew.mxcl.redis",
		"launchctl bootout system /Library/LaunchDaemons/foo.plist",
		"diskutil unmount /Volumes/Backup",
		"scutil --set HostName hacked",
		"networksetup -setdnsservers Wi-Fi 1.1.1.1",
		"networksetup -listallhardwareports -setdnsservers Wi-Fi 1.1.1.1",
		"pmset -a disablesleep 1",
		"pmset -g sleepnow",
		"log stream --predicate 'process == \"sshd\"'",
		"log erase --all",
		"dscl . -create /Users/evil",
		"dscl . -list /Users -delete /Users/evil",
		"defaults write com.apple.finder AppleShowAllFiles -bool true",
		"plutil -replace Foo -string Bar /tmp/a.plist",
		"csrutil disable",
		"pfctl -e",
		"pfctl -s info -d",
		"brew install htop",
		"brew services restart nginx",
		"/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate off",
	}
	for _, cmd := range mutatingCases {
		risk, reason := ClassifyCommand(cmd)
		if risk != RiskMutating {
			t.Fatalf("expected RiskMutating for macOS command %q, got %s (%s)", cmd, risk, reason)
		}
	}

	blockedCases := []string{
		"diskutil eraseDisk APFS Untitled disk0",
		"diskutil eraseVolume APFS Data disk3s5",
		"diskutil zeroDisk disk2",
		"diskutil apfs deleteContainer disk3",
		"dd if=/dev/zero of=/dev/disk0 bs=1m",
		"dd if=/dev/zero of=/dev/rdisk3 bs=1m",
		"echo wipe > /dev/disk0",
	}
	for _, cmd := range blockedCases {
		risk, reason := ClassifyCommand(cmd)
		if risk != RiskBlocked {
			t.Fatalf("expected RiskBlocked for catastrophic macOS command %q, got %s (%s)", cmd, risk, reason)
		}
	}
}

func TestMacOSPatrolReadOnlyScriptExecutionAndEvaluate(t *testing.T) {
	fakeBin := t.TempDir()
	writeStub := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(fakeBin, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatalf("write stub %s: %v", name, err)
		}
	}

	writeStub("uname", `echo "Darwin"`)
	writeStub("sysctl", `
case "$2" in
  hw.ncpu) echo "8" ;;
  vm.loadavg) echo "{ 3.20 2.50 2.10 }" ;;
  hw.memsize) echo "17179869184" ;;
  hw.pagesize) echo "16384" ;;
esac`)
	// Used = 629145 pages * 16KB / 16 GiB = 60.0%
	writeStub("vm_stat", `cat <<'EOF'
Mach Virtual Memory Statistics: (page size of 16384 bytes)
Pages wired down:                         200000.
Pages purgeable:                           20000.
Anonymous pages:                          350000.
Pages occupied by compressor:              99145.
EOF`)
	writeStub("df", `cat <<'EOF'
Filesystem     1024-blocks      Used Available Capacity  Mounted on
/dev/disk3s1s1   524288000  10485760 209715200     4%    /
EOF`)
	writeStub("log", `cat <<'EOF'
2026-11-26 22:10:01 localhost sshd-session[1]: Failed password for invalid user root from 198.51.100.1 port 50000
EOF`)
	writeStub("dscl", `printf "root 0\nzezen 501\n"`)
	writeStub("netstat", `
if [ "$3" = "tcp" ]; then
  printf "tcp4 0 0 *.22 *.* LISTEN\ntcp4 0 0 127.0.0.1.18899 *.* LISTEN\n"
else
  printf "udp4 0 0 *.5353 *.*\nudp4 0 0 *.63446 *.*\n"
fi`)
	writeStub("launchctl", `printf "PID\tStatus\tLabel\n-\t1\tcom.apple.ignoreme\n-\t78\thomebrew.mxcl.redis\n"`)

	cmd := exec.Command("/bin/sh", "-c", patrolReadOnlyShellScript)
	cmd.Env = append(os.Environ(), "PATH="+fakeBin+":/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("macOS patrol script failed: %v\n%s", err, string(out))
	}

	store, err := vault.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()
	if err := store.Setup("StrongPatrolPass!2026", "127.0.0.1"); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	svc := NewService(store, sshmanager.NewManager(store))
	defer svc.Close()

	cfg := vault.DefaultPatrolConfig()
	finding := svc.evaluateServerPatrol(vault.ServerView{
		ID:   "srv-mac",
		Name: "macmini",
		Host: "192.168.50.111",
		Port: 22,
	}, &cfg, string(out), true, 45, "")

	if finding.CPULoadPercent != 40.0 || finding.MemPercent != 60.0 || finding.DiskPercent != 60.0 || finding.SSHFailCount1h != 1 {
		t.Fatalf("unexpected macOS patrol metrics: %+v\nraw:\n%s", finding, string(out))
	}
	if finding.Severity != "warning" || len(finding.Anomalies) != 1 || !strings.Contains(finding.Anomalies[0], "redis") {
		t.Fatalf("expected warning anomaly for failed homebrew redis service, got: %+v", finding)
	}
	base, err := store.GetPatrolBaseline("srv-mac")
	if err != nil || base == nil || len(base.ListeningPorts) != 3 {
		t.Fatalf("expected 3 baseline listening ports (22, 5353, 18899), got %+v err=%v", base, err)
	}
}

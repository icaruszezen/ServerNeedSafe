package vault

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPortDriftPatternAndPortSpecValidationAndMatching(t *testing.T) {
	validProcs := map[string]string{
		"rustdesk*":       "rustdesk*",
		"  UDP:xray* ":    "udp:xray*",
		"TCP:rapportd":    "tcp:rapportd",
		"OrbStack Helper": "OrbStack Helper",
		"ToDesk_Service":  "ToDesk_Service",
	}
	for in, want := range validProcs {
		got, err := ValidatePortDriftProcessPattern(in)
		if err != nil || got != want {
			t.Fatalf("ValidatePortDriftProcessPattern(%q) = (%q, %v), want (%q, nil)", in, got, err, want)
		}
	}

	invalidProcs := []string{"", "   ", "*", "***", "udp:", "tcp:*", "bad;rm -rf /", strings.Repeat("a", 81)}
	for _, in := range invalidProcs {
		if got, err := ValidatePortDriftProcessPattern(in); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("expected ErrInvalidInput for process pattern %q, got (%q, %v)", in, got, err)
		}
	}

	validPorts := map[string]string{
		"5353":            "5353",
		"UDP/5353":        "udp/5353",
		"tcp/49152-65535": "tcp/49152-65535",
		"10000-20000":     "10000-20000",
		"udp/9000-9000":   "udp/9000",
	}
	for in, want := range validPorts {
		got, err := ValidatePortDriftPortSpec(in)
		if err != nil || got != want {
			t.Fatalf("ValidatePortDriftPortSpec(%q) = (%q, %v), want (%q, nil)", in, got, err, want)
		}
	}

	invalidPorts := []string{"", "0", "65536", "icmp/80", "2000-1000", "tcp/abc", "udp/1-70000"}
	for _, in := range invalidPorts {
		if got, err := ValidatePortDriftPortSpec(in); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("expected ErrInvalidInput for port spec %q, got (%q, %v)", in, got, err)
		}
	}

	if !MatchPortDriftProcessPattern("rustdesk*", "udp", "RustDesk") {
		t.Fatal("expected rustdesk* to match RustDesk case-insensitively")
	}
	if !MatchPortDriftProcessPattern("udp:xray*", "udp6", "xray-linux-amd6") {
		t.Fatal("expected udp:xray* to match udp6 xray-linux-amd6")
	}
	if MatchPortDriftProcessPattern("udp:xray*", "tcp", "xray-linux-amd6") {
		t.Fatal("udp:xray* must NOT match TCP listener of xray-linux-amd6")
	}
	if MatchPortDriftProcessPattern("rustdesk*", "udp", "") {
		t.Fatal("process pattern must NEVER match unnamed process")
	}

	if !MatchPortDriftPortSpec("udp/10000-20000", "udp6", 15000) {
		t.Fatal("expected udp/10000-20000 to match udp6/15000")
	}
	if MatchPortDriftPortSpec("udp/10000-20000", "tcp", 15000) {
		t.Fatal("udp/10000-20000 must NOT match tcp/15000")
	}
	if !MatchPortDriftPortSpec("50000-51000", "tcp6", 50500) {
		t.Fatal("expected proto-agnostic range 50000-51000 to match tcp6/50500")
	}
}

func TestPortDriftSuppressesRealWorldDynamicAppsWhileCatchingRogueTCP(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "vault.sns"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()
	if err := store.Setup("StrongPortDriftPass#2026", "127.0.0.1"); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	pass := "NodePass!1"
	srv, err := store.CreateServer(ServerMutationInput{
		Name:     "macmini",
		Group:    "本地服务器",
		Host:     "192.168.50.111",
		Port:     22,
		Username: "zezen",
		AuthType: AuthPassword,
		Password: &pass,
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("CreateServer: %v", err)
	}

	t0 := time.Now().UTC()
	// Sweep 1: Baseline with SSH, RustDesk static+dynamic, rapportd dynamic TCP, replicatord dynamic UDP, and Tailscale overlay
	snap1 := &ServerMonitorSnapshot{
		ServerID:    srv.ID,
		CollectedAt: t0,
		Reachable:   true,
		ListeningPorts: []ListeningPortStat{
			{Proto: "tcp", BindAddr: "0.0.0.0", Port: 22, PublicExposed: true, ExposureScope: "wildcard", Process: "sshd", PID: 100},
			{Proto: "tcp", BindAddr: "0.0.0.0", Port: 443, PublicExposed: true, ExposureScope: "wildcard", Process: "xray-linux-amd6", PID: 200},
			{Proto: "udp", BindAddr: "0.0.0.0", Port: 52395, PublicExposed: true, ExposureScope: "wildcard", Process: "RustDesk", PID: 300},
			{Proto: "tcp", BindAddr: "0.0.0.0", Port: 49203, PublicExposed: true, ExposureScope: "wildcard", Process: "rapportd", PID: 400},
			{Proto: "tcp", BindAddr: "100.96.0.101", Port: 34789, PublicExposed: false, ExposureScope: "vpn_overlay", Process: "tailscaled", PID: 500},
		},
	}
	if _, _, _, err := store.RecordMonitorSnapshots([]*ServerMonitorSnapshot{snap1}); err != nil {
		t.Fatalf("sweep 1: %v", err)
	}

	// Verify dynamic/ignored ports did NOT pollute PortBaseline (only tcp/22 and tcp/443!)
	detail1, err := store.GetServerMonitorDetail(srv.ID, time.Hour)
	if err != nil {
		t.Fatalf("GetServerMonitorDetail: %v", err)
	}
	if len(detail1.PortBaseline) != 2 || detail1.PortBaseline[0] != "tcp/22" || detail1.PortBaseline[1] != "tcp/443" {
		t.Fatalf("expected clean baseline [tcp/22 tcp/443] without dynamic ports, got %v", detail1.PortBaseline)
	}

	// Sweep 2: RustDesk rotates UDP to 63446, ToDesk binds 51523, syslogd binds 62302, hbbs binds 51239,
	// xray opens transient low UDP 9127 & 10040, rapportd rotates TCP to 51200, and an unknown process opens ephemeral UDP 58888.
	// NONE of these should trigger port_drift!
	snap2 := &ServerMonitorSnapshot{
		ServerID:    srv.ID,
		CollectedAt: t0.Add(60 * time.Second),
		Reachable:   true,
		ListeningPorts: []ListeningPortStat{
			{Proto: "tcp", BindAddr: "0.0.0.0", Port: 22, PublicExposed: true, ExposureScope: "wildcard", Process: "sshd", PID: 100},
			{Proto: "tcp", BindAddr: "0.0.0.0", Port: 443, PublicExposed: true, ExposureScope: "wildcard", Process: "xray-linux-amd6", PID: 200},
			{Proto: "udp", BindAddr: "0.0.0.0", Port: 63446, PublicExposed: true, ExposureScope: "wildcard", Process: "RustDesk", PID: 300},
			{Proto: "udp", BindAddr: "0.0.0.0", Port: 51523, PublicExposed: true, ExposureScope: "wildcard", Process: "ToDesk", PID: 301},
			{Proto: "udp", BindAddr: "0.0.0.0", Port: 62302, PublicExposed: true, ExposureScope: "wildcard", Process: "syslogd", PID: 302},
			{Proto: "udp", BindAddr: "0.0.0.0", Port: 51239, PublicExposed: true, ExposureScope: "wildcard", Process: "hbbs", PID: 303},
			{Proto: "udp", BindAddr: "0.0.0.0", Port: 9127, PublicExposed: true, ExposureScope: "wildcard", Process: "xray-linux-amd6", PID: 200},
			{Proto: "udp", BindAddr: "0.0.0.0", Port: 10040, PublicExposed: true, ExposureScope: "wildcard", Process: "xray-linux-amd6", PID: 200},
			{Proto: "tcp", BindAddr: "0.0.0.0", Port: 51200, PublicExposed: true, ExposureScope: "wildcard", Process: "rapportd", PID: 401},
			{Proto: "udp", BindAddr: "0.0.0.0", Port: 58888, PublicExposed: true, ExposureScope: "wildcard", Process: "", PID: 0},
		},
	}
	trig2, _, _, err := store.RecordMonitorSnapshots([]*ServerMonitorSnapshot{snap2})
	if err != nil {
		t.Fatalf("sweep 2: %v", err)
	}
	for _, al := range trig2 {
		if al.RuleKind == "port_drift" {
			t.Fatalf("unexpected false port_drift on dynamic/ephemeral ports: %+v", al)
		}
	}

	// Sweep 3: Real security events MUST still trigger immediately:
	// - xray opens an unexpected new TCP port 8888 (udp:xray* must NOT hide TCP!)
	// - rogue backdoor opens tcp/55555 (IgnoreEphemeralUDP must NOT hide high TCP!)
	snap3 := &ServerMonitorSnapshot{
		ServerID:    srv.ID,
		CollectedAt: t0.Add(120 * time.Second),
		Reachable:   true,
		ListeningPorts: []ListeningPortStat{
			{Proto: "tcp", BindAddr: "0.0.0.0", Port: 22, PublicExposed: true, ExposureScope: "wildcard", Process: "sshd", PID: 100},
			{Proto: "tcp", BindAddr: "0.0.0.0", Port: 443, PublicExposed: true, ExposureScope: "wildcard", Process: "xray-linux-amd6", PID: 200},
			{Proto: "tcp", BindAddr: "0.0.0.0", Port: 8888, PublicExposed: true, ExposureScope: "wildcard", Process: "xray-linux-amd6", PID: 200},
			{Proto: "tcp", BindAddr: "0.0.0.0", Port: 55555, PublicExposed: true, ExposureScope: "wildcard", Process: "implant", PID: 999},
		},
	}
	trig3, _, _, err := store.RecordMonitorSnapshots([]*ServerMonitorSnapshot{snap3})
	if err != nil {
		t.Fatalf("sweep 3: %v", err)
	}
	var driftAl *MonitorAlert
	for i := range trig3 {
		if trig3[i].RuleKind == "port_drift" {
			driftAl = &trig3[i]
			break
		}
	}
	if driftAl == nil || driftAl.MetricText != "+2 端口" {
		t.Fatalf("expected port_drift (+2 端口) for xray tcp/8888 & implant tcp/55555, got %+v", trig3)
	}
}

func TestPortDriftPerPortConsecutiveDebounceAndIgnoreReconciliation(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "vault.sns"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()
	if err := store.Setup("StrongDebouncePass#2026", "127.0.0.1"); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	pass := "NodePass!1"
	srv, err := store.CreateServer(ServerMutationInput{
		Name:     "edge-01",
		Group:    "边缘与网关",
		Host:     "10.0.0.5",
		Port:     22,
		Username: "root",
		AuthType: AuthPassword,
		Password: &pass,
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("CreateServer: %v", err)
	}

	// Raise port_drift ConsecutiveCount to 2 to verify per-port streak tracking prevents rotating transient sockets from accumulating streak.
	settings, rules, err := store.GetMonitorPolicy()
	if err != nil {
		t.Fatalf("GetMonitorPolicy: %v", err)
	}
	for i := range rules {
		if rules[i].Kind == "port_drift" {
			rules[i].ConsecutiveCount = 2
		}
	}
	if _, _, err := store.UpdateMonitorPolicy(settings, rules, "127.0.0.1"); err != nil {
		t.Fatalf("UpdateMonitorPolicy: %v", err)
	}

	t0 := time.Now().UTC()
	// Seed baseline [tcp/22]
	_, _, _, _ = store.RecordMonitorSnapshots([]*ServerMonitorSnapshot{{
		ServerID:    srv.ID,
		CollectedAt: t0,
		Reachable:   true,
		ListeningPorts: []ListeningPortStat{
			{Proto: "tcp", BindAddr: "0.0.0.0", Port: 22, PublicExposed: true, ExposureScope: "wildcard", Process: "sshd"},
		},
	}})

	// Sweep 1: transient udp/9127 by unlisted custom-p2p -> streak 1 (<2) -> NO alert
	trig1, _, _, _ := store.RecordMonitorSnapshots([]*ServerMonitorSnapshot{{
		ServerID:    srv.ID,
		CollectedAt: t0.Add(60 * time.Second),
		Reachable:   true,
		ListeningPorts: []ListeningPortStat{
			{Proto: "tcp", BindAddr: "0.0.0.0", Port: 22, PublicExposed: true, ExposureScope: "wildcard", Process: "sshd"},
			{Proto: "udp", BindAddr: "0.0.0.0", Port: 9127, PublicExposed: true, ExposureScope: "wildcard", Process: "custom-p2p"},
		},
	}})
	if len(trig1) != 0 {
		t.Fatalf("expected 0 alerts on 1st appearance of udp/9127, got %+v", trig1)
	}

	// Sweep 2: udp/9127 vanished, rotated to DIFFERENT port udp/10040 -> must NOT accumulate cross-port streak -> STILL 0 alerts!
	trig2, _, _, _ := store.RecordMonitorSnapshots([]*ServerMonitorSnapshot{{
		ServerID:    srv.ID,
		CollectedAt: t0.Add(120 * time.Second),
		Reachable:   true,
		ListeningPorts: []ListeningPortStat{
			{Proto: "tcp", BindAddr: "0.0.0.0", Port: 22, PublicExposed: true, ExposureScope: "wildcard", Process: "sshd"},
			{Proto: "udp", BindAddr: "0.0.0.0", Port: 10040, PublicExposed: true, ExposureScope: "wildcard", Process: "custom-p2p"},
			{Proto: "tcp", BindAddr: "0.0.0.0", Port: 7777, PublicExposed: true, ExposureScope: "wildcard", Process: "app-b"},
		},
	}})
	if len(trig2) != 0 {
		t.Fatalf("BUG: rotating port udp/9127 -> udp/10040 falsely accumulated cross-port streak! got %+v", trig2)
	}

	// Sweep 3: udp/10040 AND tcp/7777 both persist -> streak=2 -> FIRES (+2 端口)!
	trig3, _, _, _ := store.RecordMonitorSnapshots([]*ServerMonitorSnapshot{{
		ServerID:    srv.ID,
		CollectedAt: t0.Add(180 * time.Second),
		Reachable:   true,
		ListeningPorts: []ListeningPortStat{
			{Proto: "tcp", BindAddr: "0.0.0.0", Port: 22, PublicExposed: true, ExposureScope: "wildcard", Process: "sshd"},
			{Proto: "udp", BindAddr: "0.0.0.0", Port: 10040, PublicExposed: true, ExposureScope: "wildcard", Process: "custom-p2p"},
			{Proto: "tcp", BindAddr: "0.0.0.0", Port: 7777, PublicExposed: true, ExposureScope: "wildcard", Process: "app-b"},
		},
	}})
	if len(trig3) != 1 || trig3[0].RuleKind != "port_drift" || trig3[0].MetricText != "+2 端口" {
		t.Fatalf("expected port_drift (+2 端口) on 2nd consecutive persistence, got %+v", trig3)
	}

	// Ignore custom-p2p at server scope -> active alert immediately shrinks to +1 端口 (app-b only)
	res1, err := store.UpdatePortDriftIgnoreRule(PortDriftIgnoreMutation{
		ServerID: srv.ID,
		Scope:    "server",
		Action:   "add",
		Process:  "custom-p2p",
	}, "127.0.0.1")
	if err != nil || res1.ResolvedAlerts != 0 || len(res1.ServerIgnoreProcesses) != 1 {
		t.Fatalf("expected partial reconciliation after ignoring custom-p2p, got %+v err=%v", res1, err)
	}
	activeAfter1, _ := store.ListMonitorAlerts("active", srv.ID, 0)
	if len(activeAfter1) != 1 || activeAfter1[0].MetricText != "+1 端口" || strings.Contains(activeAfter1[0].Detail, "custom-p2p") {
		t.Fatalf("expected active alert updated to +1 端口 (app-b only), got %+v", activeAfter1)
	}

	// Ignore tcp/7777 via global port rule -> active alert immediately resolves!
	res2, err := store.UpdatePortDriftIgnoreRule(PortDriftIgnoreMutation{
		Scope:  "global",
		Action: "add",
		Port:   "tcp/7777",
	}, "127.0.0.1")
	if err != nil || res2.ResolvedAlerts != 1 {
		t.Fatalf("expected 1 resolved alert after ignoring tcp/7777, got %+v err=%v", res2, err)
	}
	activeAfter2, _ := store.ListMonitorAlerts("active", srv.ID, 0)
	if len(activeAfter2) != 0 {
		t.Fatalf("expected 0 active alerts after ignoring all drifted ports, got %+v", activeAfter2)
	}

	// Remove server ignore rule cleanly
	res3, err := store.UpdatePortDriftIgnoreRule(PortDriftIgnoreMutation{
		ServerID: srv.ID,
		Scope:    "server",
		Action:   "remove",
		Process:  "custom-p2p",
	}, "127.0.0.1")
	if err != nil || len(res3.ServerIgnoreProcesses) != 0 {
		t.Fatalf("expected server ignore rule removed cleanly, got %+v err=%v", res3, err)
	}
}

func TestMonitorPolicyV2ToV3MigrationPreservesExplicitEmptyOverride(t *testing.T) {
	sec := DefaultSecretsState("vid-mig")
	sec.MonitorSettings.PolicyVersion = 2
	sec.MonitorSettings.PortDriftIgnoreEphemeralUDP = false
	sec.MonitorSettings.PortDriftIgnoreProcesses = nil

	ensureSecretsDefaults(sec)
	if sec.MonitorSettings.PolicyVersion != CurrentMonitorPolicyVersion ||
		!sec.MonitorSettings.PortDriftIgnoreEphemeralUDP ||
		len(sec.MonitorSettings.PortDriftIgnoreProcesses) == 0 {
		t.Fatalf("expected v2 -> v3 migration to enable ephemeral UDP filter & default ignore processes, got %+v", sec.MonitorSettings)
	}

	// Once at v3, explicitly disabling ephemeral UDP & clearing process list must be preserved!
	sec.MonitorSettings.PortDriftIgnoreEphemeralUDP = false
	sec.MonitorSettings.PortDriftIgnoreProcesses = []string{}
	ensureSecretsDefaults(sec)
	if sec.MonitorSettings.PortDriftIgnoreEphemeralUDP || len(sec.MonitorSettings.PortDriftIgnoreProcesses) != 0 {
		t.Fatalf("explicit v3 override was overwritten by defaults: %+v", sec.MonitorSettings)
	}
}

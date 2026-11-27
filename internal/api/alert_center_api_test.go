package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/monitor"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

func TestAlertCenterAPIEndpointsAndAdviceEnrichment(t *testing.T) {
	store, err := vault.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := store.Setup("StrongAdminPass123!", "127.0.0.1"); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	srv1, err := store.CreateServer(vault.ServerMutationInput{
		Name:     "prod-web-01",
		Group:    "生产环境",
		Host:     "10.10.0.1",
		Port:     22,
		Username: "root",
		AuthType: vault.AuthPassword,
		Password: ptrStr("secret"),
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("CreateServer srv1: %v", err)
	}
	srv2, err := store.CreateServer(vault.ServerMutationInput{
		Name:     "prod-db-01",
		Group:    "生产环境",
		Host:     "10.10.0.2",
		Port:     22,
		Username: "root",
		AuthType: vault.AuthPassword,
		Password: ptrStr("secret"),
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("CreateServer srv2: %v", err)
	}

	now := time.Now().UTC()
	// Trigger alerts on both servers (cpu_high has consecutive=2, mem_high=1, disk_high=1, ssh_bruteforce=1)
	snap1 := &vault.ServerMonitorSnapshot{
		ServerID:       srv1.ID,
		Reachable:      true,
		CollectedAt:    now,
		OS:             "Ubuntu 24.04",
		MemPercent:     96.0,
		MemTotalMB:     8192,
		MemUsedMB:      7864,
		MemAvailableMB: 328,
		DiskPercent:    93.5,
		MaxPartMount:   "/var/log",
		MaxPartPercent: 93.5,
		Disks: []vault.DiskPartitionStat{
			{MountPoint: "/var/log", Device: "/dev/vdb1", FSType: "ext4", TotalGB: 100, UsedGB: 93.5, AvailGB: 6.5, UsedPercent: 93.5},
		},
		TopMemProcs: []vault.ProcessStat{
			{PID: 2048, User: "www-data", MemPercent: 62.5, RSSMB: 5120, Command: "node server.js"},
		},
	}
	snap2 := &vault.ServerMonitorSnapshot{
		ServerID:    srv2.ID,
		Reachable:   true,
		CollectedAt: now,
		OS:          "Debian 12",
		Security: vault.SecurityPostureStat{
			SSHFailedRecent: 120,
			TopFailedIPs:    []string{"203.0.113.88"},
			FirewallStatus:  "active",
			FirewallDetail:  "ufw",
		},
	}
	if _, _, _, err := store.RecordMonitorSnapshots([]*vault.ServerMonitorSnapshot{snap1, snap2}); err != nil {
		t.Fatalf("RecordMonitorSnapshots: %v", err)
	}

	apiSrv := NewServer(Config{
		DeployMode:             "server",
		Store:                  store,
		DisableAutoUpdateCheck: true,
	})
	defer apiSrv.Close()

	// Login to obtain admin session token
	loginBody, _ := json.Marshal(map[string]string{"password": "StrongAdminPass123!"})
	loginReq := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(loginBody))
	loginRec := httptest.NewRecorder()
	apiSrv.Handler().ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("login failed: %d %s", loginRec.Code, loginRec.Body.String())
	}
	var loginResp struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(loginRec.Body.Bytes(), &loginResp)
	authHeader := "Bearer " + loginResp.Token

	doJSON := func(method, path string, body any) *httptest.ResponseRecorder {
		var buf bytes.Buffer
		if body != nil {
			_ = json.NewEncoder(&buf).Encode(body)
		}
		req := httptest.NewRequest(method, path, &buf)
		req.Header.Set("Authorization", authHeader)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		rec := httptest.NewRecorder()
		apiSrv.Handler().ServeHTTP(rec, req)
		return rec
	}

	// 1. Bootstrap reports active_alerts_by_server
	bootRec := doJSON(http.MethodGet, "/api/workspace/bootstrap", nil)
	if bootRec.Code != http.StatusOK {
		t.Fatalf("bootstrap failed: %d", bootRec.Code)
	}
	var bootPayload struct {
		FiringAlerts         int            `json:"firing_alerts"`
		ActiveAlertsByServer map[string]int `json:"active_alerts_by_server"`
	}
	_ = json.Unmarshal(bootRec.Body.Bytes(), &bootPayload)
	if bootPayload.FiringAlerts != 3 {
		t.Fatalf("expected 3 firing_alerts, got %d", bootPayload.FiringAlerts)
	}
	if bootPayload.ActiveAlertsByServer[srv1.ID] != 2 || bootPayload.ActiveAlertsByServer[srv2.ID] != 1 {
		t.Fatalf("unexpected active_alerts_by_server: %+v", bootPayload.ActiveAlertsByServer)
	}

	// 2. GET /api/monitor/alerts scoped to srv1 with enriched advice & summaries
	listRec := doJSON(http.MethodGet, "/api/monitor/alerts?status=active&server_id="+srv1.ID, nil)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list alerts failed: %d %s", listRec.Code, listRec.Body.String())
	}
	var listPayload struct {
		Alerts        []monitor.EnrichedMonitorAlert `json:"alerts"`
		Summary       monitor.AlertSummaryStats      `json:"summary"`
		ScopedSummary *monitor.AlertSummaryStats     `json:"scoped_summary"`
	}
	_ = json.Unmarshal(listRec.Body.Bytes(), &listPayload)
	if len(listPayload.Alerts) != 2 {
		t.Fatalf("expected 2 alerts for srv1, got %d", len(listPayload.Alerts))
	}
	if listPayload.Summary.TotalActive != 3 || listPayload.ScopedSummary == nil || listPayload.ScopedSummary.TotalActive != 2 {
		t.Fatalf("unexpected summaries: global=%+v scoped=%+v", listPayload.Summary, listPayload.ScopedSummary)
	}
	for _, al := range listPayload.Alerts {
		if al.Advice == nil || al.Advice.Summary == "" || len(al.Advice.Commands) == 0 {
			t.Fatalf("expected enriched advice on alert %s, got %+v", al.RuleKind, al.Advice)
		}
		if al.Advice.MCPPrompt == "" {
			t.Fatalf("expected enriched mcp_prompt on alert %s, got %+v", al.RuleKind, al.Advice)
		}
		if al.Category == "" {
			t.Fatalf("expected category on alert %s", al.RuleKind)
		}
	}

	// 3. Category filter (security -> returns only srv2 ssh_bruteforce)
	secRec := doJSON(http.MethodGet, "/api/monitor/alerts?status=active&category=security", nil)
	var secPayload struct {
		Alerts []monitor.EnrichedMonitorAlert `json:"alerts"`
	}
	_ = json.Unmarshal(secRec.Body.Bytes(), &secPayload)
	if len(secPayload.Alerts) != 1 || secPayload.Alerts[0].RuleKind != "ssh_bruteforce" {
		t.Fatalf("expected 1 security alert (ssh_bruteforce), got %+v", secPayload.Alerts)
	}

	// 4. Bulk acknowledge srv1 alerts
	ackRec := doJSON(http.MethodPost, "/api/monitor/alerts/ack-bulk", map[string]any{
		"server_id": srv1.ID,
	})
	if ackRec.Code != http.StatusOK {
		t.Fatalf("ack-bulk failed: %d %s", ackRec.Code, ackRec.Body.String())
	}
	var ackPayload struct {
		Acknowledged int `json:"acknowledged"`
	}
	_ = json.Unmarshal(ackRec.Body.Bytes(), &ackPayload)
	if ackPayload.Acknowledged != 2 {
		t.Fatalf("expected 2 acknowledged for srv1, got %d", ackPayload.Acknowledged)
	}

	// 5. Manually resolve one alert on srv1 and one alert on srv2
	res1Rec := doJSON(http.MethodPost, "/api/monitor/alerts/resolve", map[string]string{
		"id": listPayload.Alerts[0].ID,
	})
	if res1Rec.Code != http.StatusOK {
		t.Fatalf("resolve alert1 failed: %d %s", res1Rec.Code, res1Rec.Body.String())
	}
	res2Rec := doJSON(http.MethodPost, "/api/monitor/alerts/resolve", map[string]string{
		"id": secPayload.Alerts[0].ID,
	})
	if res2Rec.Code != http.StatusOK {
		t.Fatalf("resolve alert2 failed: %d %s", res2Rec.Code, res2Rec.Body.String())
	}

	// 6. Scoped clear-resolved for srv1 only removes srv1's resolved alert, preserving srv2's
	clrRec := doJSON(http.MethodPost, "/api/monitor/alerts/clear-resolved", map[string]string{
		"server_id": srv1.ID,
	})
	if clrRec.Code != http.StatusOK {
		t.Fatalf("clear-resolved failed: %d %s", clrRec.Code, clrRec.Body.String())
	}
	var clrPayload struct {
		Removed int `json:"removed"`
	}
	_ = json.Unmarshal(clrRec.Body.Bytes(), &clrPayload)
	if clrPayload.Removed != 1 {
		t.Fatalf("expected 1 removed resolved alert for srv1, got %d", clrPayload.Removed)
	}

	remResolved, _ := store.ListMonitorAlerts("resolved", "", 0)
	if len(remResolved) != 1 || remResolved[0].ServerID != srv2.ID {
		t.Fatalf("expected srv2 resolved alert to remain, got %+v", remResolved)
	}

	// 7. Port drift alert quick-action ignore API end-to-end
	_, _, _, _ = store.RecordMonitorSnapshots([]*vault.ServerMonitorSnapshot{{
		ServerID:    srv1.ID,
		Reachable:   true,
		CollectedAt: now.Add(time.Minute),
		OS:          "Ubuntu 24.04",
		ListeningPorts: []vault.ListeningPortStat{
			{Proto: "tcp", BindAddr: "0.0.0.0", Port: 22, PublicExposed: true, ExposureScope: "wildcard", Process: "sshd", PID: 10},
		},
	}})
	_, _, _, _ = store.RecordMonitorSnapshots([]*vault.ServerMonitorSnapshot{{
		ServerID:    srv1.ID,
		Reachable:   true,
		CollectedAt: now.Add(2 * time.Minute),
		OS:          "Ubuntu 24.04",
		ListeningPorts: []vault.ListeningPortStat{
			{Proto: "tcp", BindAddr: "0.0.0.0", Port: 22, PublicExposed: true, ExposureScope: "wildcard", Process: "sshd", PID: 10},
			{Proto: "tcp", BindAddr: "0.0.0.0", Port: 49876, PublicExposed: true, ExposureScope: "wildcard", Process: "CustomRotator", PID: 99},
		},
	}})

	driftListRec := doJSON(http.MethodGet, "/api/monitor/alerts?status=active&server_id="+srv1.ID+"&category=network", nil)
	if driftListRec.Code != http.StatusOK {
		t.Fatalf("list port_drift alert failed: %d %s", driftListRec.Code, driftListRec.Body.String())
	}
	var driftListPayload struct {
		Alerts []monitor.EnrichedMonitorAlert `json:"alerts"`
	}
	_ = json.Unmarshal(driftListRec.Body.Bytes(), &driftListPayload)
	if len(driftListPayload.Alerts) != 1 || driftListPayload.Alerts[0].RuleKind != "port_drift" {
		t.Fatalf("expected 1 active port_drift alert, got %+v", driftListPayload.Alerts)
	}
	qa := driftListPayload.Alerts[0].Advice.QuickActions
	if len(qa) < 2 || qa[1].Kind != "ignore_port_drift_process" || qa[1].Target != "CustomRotator" {
		t.Fatalf("expected ignore_port_drift_process quick action for CustomRotator, got %+v", qa)
	}

	ignoreRec := doJSON(http.MethodPost, "/api/monitor/port-drift/ignore", map[string]any{
		"server_id": srv1.ID,
		"scope":     "server",
		"action":    "add",
		"process":   "CustomRotator",
	})
	if ignoreRec.Code != http.StatusOK {
		t.Fatalf("port-drift ignore API failed: %d %s", ignoreRec.Code, ignoreRec.Body.String())
	}
	var ignorePayload struct {
		OK     bool                        `json:"ok"`
		Result vault.PortDriftIgnoreResult `json:"result"`
	}
	_ = json.Unmarshal(ignoreRec.Body.Bytes(), &ignorePayload)
	if !ignorePayload.OK || ignorePayload.Result.ResolvedAlerts != 1 || ignorePayload.Result.AppliedRule != "CustomRotator" {
		t.Fatalf("unexpected ignore API payload: %+v", ignorePayload)
	}

	policyRec := doJSON(http.MethodGet, "/api/monitor/policy", nil)
	if policyRec.Code != http.StatusOK {
		t.Fatalf("get policy failed: %d", policyRec.Code)
	}
	var policyPayload struct {
		Settings           vault.MonitorSettings `json:"settings"`
		DefaultIgnoreProcs []string              `json:"default_port_drift_ignore_processes"`
	}
	_ = json.Unmarshal(policyRec.Body.Bytes(), &policyPayload)
	if !policyPayload.Settings.PortDriftIgnoreEphemeralUDP || len(policyPayload.DefaultIgnoreProcs) == 0 {
		t.Fatalf("expected ephemeral UDP default & default_port_drift_ignore_processes in policy API, got %+v", policyPayload)
	}
}

func ptrStr(s string) *string { return &s }

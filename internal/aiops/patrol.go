package aiops

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

// PatrolStatusView reports live background scheduler state to the UI.
type PatrolStatusView struct {
	Running      bool       `json:"running"`
	VaultReady   bool       `json:"vault_ready"`
	LastRunAt    *time.Time `json:"last_run_at,omitempty"`
	NextRunAt    *time.Time `json:"next_run_at,omitempty"`
	UnreadAlerts int        `json:"unread_alerts"`
}

const patrolReadOnlyShellScript = `
CORES=$(nproc 2>/dev/null || grep -c '^processor' /proc/cpuinfo 2>/dev/null || echo 1)
LOAD1=$(awk '{print $1}' /proc/loadavg 2>/dev/null || echo 0)
MEM_LINE=$(awk '/^MemTotal:/ {t=$2} /^MemAvailable:/ {a=$2} END {if(t>0){printf "%.1f", (t-a)*100/t} else {print "0"}}' /proc/meminfo 2>/dev/null || echo 0)
DISK_LINE=$((df -Pk / 2>/dev/null || df -Pk . 2>/dev/null) | awk 'NR==2 && NF>=5 {gsub(/%/,"",$(NF-1)); print $(NF-1)}' || echo 0)
printf "METRIC_CORES=%s\nMETRIC_LOAD1=%s\nMETRIC_MEM=%s\nMETRIC_DISK=%s\n" "$CORES" "$LOAD1" "$MEM_LINE" "$DISK_LINE"

SSH_FAILS=0
if command -v journalctl >/dev/null 2>&1; then
  SSH_FAILS=$(journalctl -u ssh -u sshd --since "1 hour ago" --no-pager 2>/dev/null | grep -Ec "Failed password|Invalid user|authentication failure" || true)
elif [ -r /var/log/auth.log ]; then
  SSH_FAILS=$(tail -n 400 /var/log/auth.log 2>/dev/null | grep -Ec "Failed password|Invalid user" || true)
elif [ -r /var/log/secure ]; then
  SSH_FAILS=$(tail -n 400 /var/log/secure 2>/dev/null | grep -Ec "Failed password|Invalid user" || true)
fi
printf "METRIC_SSH_FAILS=%s\n" "${SSH_FAILS:-0}"

UID0=$(awk -F: '($3 == 0) {print $1}' /etc/passwd 2>/dev/null | tr '\n' ',' | sed 's/,$//')
printf "METRIC_UID0=%s\n" "$UID0"

PORTS=$( (ss -tulnH 2>/dev/null || netstat -tuln 2>/dev/null | awk 'NR>2') | awk '{print $1 ":" $5}' | sed 's/.*:\([0-9][0-9]*\)$/\1/' | sort -u | tr '\n' ',' | sed 's/,$//' )
printf "METRIC_PORTS=%s\n" "$PORTS"

FAILED_UNITS=""
if command -v systemctl >/dev/null 2>&1; then
  FAILED_UNITS=$(systemctl --failed --no-legend --plain 2>/dev/null | awk '{print $1}' | head -n 5 | tr '\n' ',' | sed 's/,$//')
fi
printf "METRIC_FAILED_UNITS=%s\n" "$FAILED_UNITS"
`

func (s *Service) patrolSchedulerLoop() {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-s.patrolWakeCh:
		case <-ticker.C:
		}

		if s.store.Status() != vault.StatusUnlocked {
			continue
		}
		cfg, err := s.store.GetPatrolConfigSecret()
		if err != nil || !cfg.Enabled {
			s.mu.Lock()
			s.nextPatrolAt = nil
			s.mu.Unlock()
			continue
		}

		interval := time.Duration(cfg.IntervalMinutes) * time.Minute
		if interval < 5*time.Minute {
			interval = 5 * time.Minute
		}

		s.mu.Lock()
		if s.patrolRunning {
			s.mu.Unlock()
			continue
		}
		now := time.Now().UTC()
		if s.nextPatrolAt == nil {
			next := now.Add(interval)
			if s.lastPatrolAt != nil {
				candidate := s.lastPatrolAt.Add(interval)
				if candidate.After(now) {
					next = candidate
				} else {
					next = now
				}
			}
			s.nextPatrolAt = &next
		}
		due := !now.Before(*s.nextPatrolAt)
		s.mu.Unlock()

		if due {
			_, _ = s.RunPatrolNow(context.Background(), "scheduled", false)
		}
	}
}

// NotifyPatrolConfigUpdated wakes up the patrol loop to recalculate next execution schedule immediately.
func (s *Service) NotifyPatrolConfigUpdated() {
	s.mu.Lock()
	s.nextPatrolAt = nil
	s.mu.Unlock()
	select {
	case s.patrolWakeCh <- struct{}{}:
	default:
	}
}

// GetPatrolStatus returns current background patrol scheduler status (which stays active across UI screen-locks).
func (s *Service) GetPatrolStatus() PatrolStatusView {
	vaultReady := s.store.Status() == vault.StatusUnlocked
	var unread int
	if vaultReady {
		_, unread, _ = s.store.ListPatrolRecords(1, false)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st := PatrolStatusView{
		Running:      s.patrolRunning,
		VaultReady:   vaultReady,
		UnreadAlerts: unread,
	}
	if s.lastPatrolAt != nil {
		t := *s.lastPatrolAt
		st.LastRunAt = &t
	}
	if vaultReady && s.nextPatrolAt != nil {
		t := *s.nextPatrolAt
		st.NextRunAt = &t
	}
	return st
}

// RunPatrolNow executes a strictly read-only inspection across configured servers,
// invokes the active LLM on-demand if anomalies exist (or forceAI is true), and dispatches webhooks.
func (s *Service) RunPatrolNow(ctx context.Context, trigger string, forceAI bool) (*vault.PatrolRecord, error) {
	if s.store.Status() != vault.StatusUnlocked {
		return nil, vault.ErrVaultLocked
	}
	cfg, err := s.store.GetPatrolConfigSecret()
	if err != nil {
		return nil, err
	}
	servers, err := s.store.ListServers()
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	if s.patrolRunning {
		s.mu.Unlock()
		return nil, fmt.Errorf("当前已有巡检任务正在运行中，请稍候")
	}
	s.patrolRunning = true
	s.mu.Unlock()

	defer func() {
		now := time.Now().UTC()
		s.mu.Lock()
		s.patrolRunning = false
		s.lastPatrolAt = &now
		if cfg.Enabled {
			next := now.Add(time.Duration(max(5, cfg.IntervalMinutes)) * time.Minute)
			s.nextPatrolAt = &next
		} else {
			s.nextPatrolAt = nil
		}
		s.mu.Unlock()
	}()

	// Filter target servers
	targets := make([]vault.ServerView, 0, len(servers))
	for _, srv := range servers {
		if len(cfg.ServerIDs) == 0 || slices.Contains(cfg.ServerIDs, srv.ID) {
			targets = append(targets, srv)
		}
	}

	startedAt := time.Now().UTC()
	findings := make([]vault.PatrolFinding, len(targets))

	if len(targets) > 0 {
		targetIDs := make([]string, len(targets))
		for i, srv := range targets {
			targetIDs[i] = srv.ID
		}
		execResults := s.ssh.BatchExecute(targetIDs, patrolReadOnlyShellScript, 20*time.Second, "patrol-engine")

		var wg sync.WaitGroup
		for i, srv := range targets {
			wg.Add(1)
			go func(idx int, server vault.ServerView, er string, reachable bool, latencyMs int64, errMsg string) {
				defer wg.Done()
				findings[idx] = s.evaluateServerPatrol(server, cfg, er, reachable, latencyMs, errMsg)
			}(i, srv, execResults[i].Stdout, execResults[i].Error == "", execResults[i].DurationMs, execResults[i].Error)
		}
		wg.Wait()
	}

	healthyCnt, warnCnt, critCnt := 0, 0, 0
	overall := "healthy"
	for _, f := range findings {
		switch f.Severity {
		case "critical":
			critCnt++
		case "warning":
			warnCnt++
		default:
			healthyCnt++
		}
	}
	if critCnt > 0 {
		overall = "critical"
	} else if warnCnt > 0 {
		overall = "warning"
	}

	rec := vault.PatrolRecord{
		ID:            uuid.NewString(),
		StartedAt:     startedAt,
		CompletedAt:   time.Now().UTC(),
		Trigger:       trigger,
		TotalServers:  len(targets),
		HealthyCount:  healthyCnt,
		WarningCount:  warnCnt,
		CriticalCount: critCnt,
		Status:        overall,
		Findings:      findings,
		Unread:        overall != "healthy",
	}

	// Stage 2: Wake up active LLM ONLY when anomalies are detected or explicitly requested
	if (overall != "healthy" || forceAI) && len(targets) > 0 {
		if prov, pErr := s.store.GetActiveAIProviderSecret(); pErr == nil && prov != nil {
			s.enrichPatrolWithLLM(ctx, *prov, &rec)
		}
	}

	rec.CompletedAt = time.Now().UTC()

	// Dispatch webhooks if warning or critical
	if overall != "healthy" {
		notified := false
		for _, wh := range cfg.Webhooks {
			if !wh.Enabled || wh.URL == "" {
				continue
			}
			if wErr := SendPatrolAlertWebhook(ctx, s.llm.Transport(), wh, rec); wErr == nil {
				notified = true
			}
		}
		rec.WebhookNotified = notified
	}

	if err := s.store.AppendPatrolRecord(rec); err != nil {
		return nil, err
	}
	s.notifyPersist()
	return &rec, nil
}

func (s *Service) evaluateServerPatrol(
	srv vault.ServerView,
	cfg *vault.PatrolConfig,
	rawOut string,
	reachable bool,
	latencyMs int64,
	errMsg string,
) vault.PatrolFinding {
	finding := vault.PatrolFinding{
		ServerID:  srv.ID,
		ServerName: srv.Name,
		Host:      fmt.Sprintf("%s:%d", srv.Host, srv.Port),
		Reachable: reachable,
		LatencyMs: latencyMs,
		Severity:  "healthy",
		Anomalies: []string{},
	}

	if !reachable {
		finding.Severity = "critical"
		finding.MetricsSummary = "SSH 探针连接不可达"
		finding.Anomalies = append(finding.Anomalies, fmt.Sprintf("SSH 巡检拨号失败: %s", errMsg))
		return finding
	}

	kv := make(map[string]string)
	for _, line := range strings.Split(rawOut, "\n") {
		line = strings.TrimSpace(line)
		if idx := strings.IndexByte(line, '='); idx > 0 {
			kv[line[:idx]] = strings.TrimSpace(line[idx+1:])
		}
	}

	cores, _ := strconv.Atoi(kv["METRIC_CORES"])
	if cores <= 0 {
		cores = 1
	}
	load1, _ := strconv.ParseFloat(kv["METRIC_LOAD1"], 64)
	cpuPct := float64(int((load1/float64(cores))*1000)) / 10.0
	memPct, _ := strconv.ParseFloat(kv["METRIC_MEM"], 64)
	diskPct, _ := strconv.ParseFloat(kv["METRIC_DISK"], 64)
	sshFails, _ := strconv.Atoi(kv["METRIC_SSH_FAILS"])

	finding.CPULoadPercent = cpuPct
	finding.MemPercent = memPct
	finding.DiskPercent = diskPct
	finding.SSHFailCount1h = sshFails
	finding.MetricsSummary = fmt.Sprintf("CPU负载 %.1f%% · 内存 %.1f%% · 磁盘 %.1f%% · 近1h登录失败 %d 次", cpuPct, memPct, diskPct, sshFails)

	bumpSeverity := func(level string) {
		if level == "critical" {
			finding.Severity = "critical"
		} else if level == "warning" && finding.Severity == "healthy" {
			finding.Severity = "warning"
		}
	}

	if cpuPct >= cfg.CPUWarnPercent {
		bumpSeverity(ternaryStr(cpuPct >= 95, "critical", "warning"))
		finding.Anomalies = append(finding.Anomalies, fmt.Sprintf("CPU 归一化负载偏高 (%.1f%% >= %.0f%%)", cpuPct, cfg.CPUWarnPercent))
	}
	if memPct >= cfg.MemWarnPercent {
		bumpSeverity(ternaryStr(memPct >= 95, "critical", "warning"))
		finding.Anomalies = append(finding.Anomalies, fmt.Sprintf("内存使用率越界 (%.1f%% >= %.0f%%)", memPct, cfg.MemWarnPercent))
	}
	if diskPct >= cfg.DiskWarnPercent {
		bumpSeverity(ternaryStr(diskPct >= 95, "critical", "warning"))
		finding.Anomalies = append(finding.Anomalies, fmt.Sprintf("根分区磁盘空间告警 (%.1f%% >= %.0f%%)", diskPct, cfg.DiskWarnPercent))
	}
	if sshFails >= cfg.SSHFailWarnCount {
		bumpSeverity(ternaryStr(sshFails >= cfg.SSHFailWarnCount*3, "critical", "warning"))
		finding.Anomalies = append(finding.Anomalies, fmt.Sprintf("近 1 小时检测到 %d 次 SSH 失败认证尝试（疑似口令爆破）", sshFails))
	}

	ports := splitCSVNonEmpty(kv["METRIC_PORTS"])
	uid0 := splitCSVNonEmpty(kv["METRIC_UID0"])
	failedUnits := splitCSVNonEmpty(kv["METRIC_FAILED_UNITS"])

	if len(failedUnits) > 0 {
		bumpSeverity("warning")
		finding.Anomalies = append(finding.Anomalies, fmt.Sprintf("存在异常退出的 systemd 服务: %s", strings.Join(failedUnits, ", ")))
	}

	baseline, _ := s.store.GetPatrolBaseline(srv.ID)
	if cfg.CheckPrivilegedUsers {
		for _, u := range uid0 {
			if u != "root" {
				bumpSeverity("critical")
				finding.Anomalies = append(finding.Anomalies, fmt.Sprintf("发现非 root 的 UID=0 超级特权账户: %s", u))
			}
		}
	}

	if cfg.CheckListeningPorts && baseline != nil && len(baseline.ListeningPorts) > 0 {
		var newPorts []string
		for _, p := range ports {
			if !slices.Contains(baseline.ListeningPorts, p) {
				newPorts = append(newPorts, p)
			}
		}
		if len(newPorts) > 0 {
			bumpSeverity("warning")
			finding.NewPorts = newPorts
			finding.Anomalies = append(finding.Anomalies, fmt.Sprintf("相比基线新增监听端口: %s", strings.Join(newPorts, ", ")))
		}
	}

	_ = s.store.SavePatrolBaseline(vault.ServerBaselineSnapshot{
		ServerID:       srv.ID,
		ListeningPorts: ports,
		UIDZeroUsers:   uid0,
	})
	return finding
}

func (s *Service) enrichPatrolWithLLM(ctx context.Context, prov vault.AIProviderConfig, rec *vault.PatrolRecord) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()

	serverIDs := make([]string, 0, len(rec.Findings))
	for _, f := range rec.Findings {
		if f.ServerID != "" {
			serverIDs = append(serverIDs, f.ServerID)
		}
	}
	patrolCtx := s.BuildPatrolContextBlock(serverIDs)

	evidenceBytes, _ := json.MarshalIndent(rec.Findings, "", "  ")
	sysPrompt := `你是 ServerNeedSafe 的资深 Linux SRE 与主机安全分析专家。
后台只读巡检刚刚采集到受管服务器的遥测与安全基线比对数据。请结合提供的全局 AGENTS.md 运维规范、受检主机环境画像（含已知端口用途与避坑红线）及长期运维记忆进行研判，避免将已知正常业务端口或预期缓存内存误报为异常。
请严格仅输出一个合法的 JSON 对象（不要使用 Markdown 代码块包裹，不要附加任何解释性前后缀），格式如下：
{
  "summary": "一句话总结本次巡检的核心健康或风险结论（80字以内）",
  "root_cause": "结合异常指标、主机画像、历史变更记忆与安全基线，分析最可能的根因与风险影响",
  "recommendations": ["具体可执行的只读核查或安全修复建议 1", "建议 2", "建议 3"]
}`

	var userBody strings.Builder
	if patrolCtx != "" {
		userBody.WriteString(patrolCtx)
		userBody.WriteString("\n\n")
	}
	userBody.WriteString(fmt.Sprintf("巡检总体状态: %s\n各主机巡检证据 JSON:\n%s", rec.Status, string(evidenceBytes)))

	turn, err := s.llm.StreamChat(ctx, prov, sysPrompt, []vault.AIChatMessage{
		{
			Role:    "user",
			Content: userBody.String(),
		},
	}, nil, nil)
	if err != nil || turn == nil {
		return
	}

	rec.AIAnalyzed = true
	rec.AIModel = prov.Model

	raw := strings.TrimSpace(turn.Content)
	raw = strings.TrimPrefix(raw, "```json")
	raw = strings.TrimPrefix(raw, "```")
	raw = strings.TrimSuffix(raw, "```")
	raw = strings.TrimSpace(raw)

	var parsed struct {
		Summary         string   `json:"summary"`
		RootCause       string   `json:"root_cause"`
		Recommendations []string `json:"recommendations"`
	}
	if json.Unmarshal([]byte(raw), &parsed) == nil && parsed.Summary != "" {
		rec.AISummary = parsed.Summary
		rec.AIRootCause = parsed.RootCause
		rec.AIRecommendations = parsed.Recommendations
	} else {
		rec.AISummary = truncateStr(raw, 400)
	}
}

func splitCSVNonEmpty(s string) []string {
	if strings.TrimSpace(s) == "" {
		return []string{}
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" && !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out
}

func ternaryStr(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}

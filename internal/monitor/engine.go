package monitor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/sshmanager"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

// RuntimeStatus reports the live scheduler state of the background monitoring engine.
type RuntimeStatus struct {
	Running       bool       `json:"running"`
	Collecting    bool       `json:"collecting"`
	VaultUnlocked bool       `json:"vault_unlocked"`
	Enabled       bool       `json:"enabled"`
	IntervalSec   int        `json:"interval_sec"`
	InFlightCount int        `json:"in_flight_count"`
	LastSweepAt   *time.Time `json:"last_sweep_at,omitempty"`
	NextSweepAt   *time.Time `json:"next_sweep_at,omitempty"`
}

// Engine schedules periodic agentless SSH telemetry sweeps, persists encrypted snapshots &
// time-series samples inside vault.Store, evaluates multi-dimensional alerts, and dispatches webhooks.
type Engine struct {
	store  *vault.Store
	sshMgr *sshmanager.Manager

	mu           sync.Mutex
	started      bool
	closed       bool
	stopCh       chan struct{}
	wakeCh       chan struct{}
	unlockCancel context.CancelFunc
	lastPolled   map[string]time.Time
	inFlight     map[string]int
	lastSweepAt  *time.Time
	nextSweepAt  *time.Time
	tickInterval time.Duration

	webhookPost func(urlClean string, body []byte) error
	onPersist   func()
}

// NewEngine creates a new monitoring engine wired to store ready hooks.
func NewEngine(store *vault.Store, sshMgr *sshmanager.Manager) *Engine {
	e := &Engine{
		store:        store,
		sshMgr:       sshMgr,
		stopCh:       make(chan struct{}),
		wakeCh:       make(chan struct{}, 1),
		lastPolled:   make(map[string]time.Time),
		inFlight:     make(map[string]int),
		tickInterval: 1 * time.Second,
		webhookPost:  defaultWebhookPost,
	}

	if store != nil {
		store.RegisterOnReady(e.onStoreReady)
	}
	return e
}

// SetOnPersist registers a callback invoked after background sweeps persist snapshots.
func (e *Engine) SetOnPersist(fn func()) {
	e.mu.Lock()
	e.onPersist = fn
	e.mu.Unlock()
}

// Start launches the background periodic monitoring scheduler goroutine (idempotent).
func (e *Engine) Start() {
	e.mu.Lock()
	if e.started || e.closed {
		e.mu.Unlock()
		return
	}
	e.started = true
	if e.store != nil && e.store.IsReady() && e.unlockCancel == nil {
		_, cancel := context.WithCancel(context.Background())
		e.unlockCancel = cancel
	}
	e.mu.Unlock()

	go e.schedulerLoop()
	e.Wake()
}

// Close stops the background scheduler and cancels any in-flight probes.
func (e *Engine) Close() {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return
	}
	e.closed = true
	cancel := e.unlockCancel
	e.unlockCancel = nil
	close(e.stopCh)
	e.mu.Unlock()

	if cancel != nil {
		cancel()
	}
}

// Wake nudges the scheduler to re-evaluate intervals and due servers immediately.
func (e *Engine) Wake() {
	select {
	case e.wakeCh <- struct{}{}:
	default:
	}
}

func (e *Engine) onStoreReady() {
	e.mu.Lock()
	if e.unlockCancel != nil {
		e.unlockCancel()
	}
	clear(e.lastPolled)
	e.mu.Unlock()
	e.Wake()
}

// Status returns the current runtime status of the background monitoring engine.
func (e *Engine) Status() RuntimeStatus {
	vaultReady := e.store != nil && e.store.IsReady()
	var settings vault.MonitorSettings
	if vaultReady {
		if s, _, err := e.store.GetMonitorPolicy(); err == nil {
			settings = s
		}
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	inFlightCnt := len(e.inFlight)
	st := RuntimeStatus{
		Running:       e.started && !e.closed,
		Collecting:    inFlightCnt > 0,
		VaultUnlocked: vaultReady,
		Enabled:       settings.Enabled,
		IntervalSec:   settings.IntervalSec,
		InFlightCount: inFlightCnt,
	}
	if e.lastSweepAt != nil {
		t := *e.lastSweepAt
		st.LastSweepAt = &t
	}
	if vaultReady && settings.Enabled && e.nextSweepAt != nil {
		t := *e.nextSweepAt
		st.NextSweepAt = &t
	}
	return st
}

func effectiveServerInterval(srv vault.ServerConfig, globalSec int) time.Duration {
	sec := globalSec
	if srv.CustomIntervalSec >= 10 {
		sec = srv.CustomIntervalSec
	}
	if sec < 10 {
		sec = 10
	}
	return time.Duration(sec) * time.Second
}

func (e *Engine) schedulerLoop() {
	e.mu.Lock()
	tickDur := e.tickInterval
	e.mu.Unlock()
	if tickDur <= 0 {
		tickDur = time.Second
	}

	ticker := time.NewTicker(tickDur)
	defer ticker.Stop()

	for {
		select {
		case <-e.stopCh:
			return
		case <-e.wakeCh:
			e.evaluateDueSweep()
		case <-ticker.C:
			e.evaluateDueSweep()
		}
	}
}

func (e *Engine) evaluateDueSweep() {
	if e.store == nil || e.sshMgr == nil || !e.store.IsReady() {
		e.mu.Lock()
		e.nextSweepAt = nil
		e.mu.Unlock()
		return
	}

	servers, settings, err := e.store.ListAllServerConfigs()
	if err != nil || !settings.Enabled {
		e.mu.Lock()
		e.nextSweepAt = nil
		e.mu.Unlock()
		return
	}

	now := time.Now().UTC()
	var dueServers []vault.ServerConfig
	var earliestNext time.Time

	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return
	}
	for _, srv := range servers {
		if srv.MonitorDisabled {
			continue
		}
		interval := effectiveServerInterval(srv, settings.IntervalSec)
		lastAt, seen := e.lastPolled[srv.ID]
		if !seen {
			if prev, pErr := e.store.GetPreviousMonitorSnapshot(srv.ID); pErr == nil && prev != nil && !prev.CollectedAt.IsZero() {
				lastAt = prev.CollectedAt
				e.lastPolled[srv.ID] = lastAt
			}
		}

		var nextDue time.Time
		if lastAt.IsZero() {
			nextDue = now
		} else {
			nextDue = lastAt.Add(interval)
		}

		if e.inFlight[srv.ID] > 0 {
			later := now.Add(interval)
			if earliestNext.IsZero() || later.Before(earliestNext) {
				earliestNext = later
			}
			continue
		}

		if !now.Before(nextDue) {
			dueServers = append(dueServers, srv)
			nextAfter := now.Add(interval)
			if earliestNext.IsZero() || nextAfter.Before(earliestNext) {
				earliestNext = nextAfter
			}
		} else {
			if earliestNext.IsZero() || nextDue.Before(earliestNext) {
				earliestNext = nextDue
			}
		}
	}

	if earliestNext.IsZero() {
		e.nextSweepAt = nil
	} else {
		t := earliestNext
		e.nextSweepAt = &t
	}

	if len(dueServers) == 0 {
		e.mu.Unlock()
		return
	}

	// Acquire in-flight markers & create/reuse unlock cancellation context
	acquired := make([]vault.ServerConfig, 0, len(dueServers))
	for _, srv := range dueServers {
		if e.inFlight[srv.ID] == 0 {
			e.inFlight[srv.ID]++
			e.lastPolled[srv.ID] = now
			acquired = append(acquired, srv)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	prevCancel := e.unlockCancel
	e.unlockCancel = func() {
		cancel()
		if prevCancel != nil {
			prevCancel()
		}
	}
	e.mu.Unlock()

	if len(acquired) == 0 {
		cancel()
		return
	}

	go func(targets []vault.ServerConfig, sweepSettings vault.MonitorSettings) {
		defer func() {
			cancel()
			fin := time.Now().UTC()
			e.mu.Lock()
			for _, srv := range targets {
				e.releaseInFlightLocked(srv.ID)
			}
			e.lastSweepAt = &fin
			e.mu.Unlock()
		}()

		snaps := e.collectBatch(ctx, targets, sweepSettings, false, "scheduler")
		if ctx.Err() != nil || len(snaps) == 0 {
			return
		}
		triggered, resolved, webhookURL, recErr := e.store.RecordMonitorSnapshots(snaps)
		if recErr == nil {
			e.mu.Lock()
			persistHook := e.onPersist
			e.mu.Unlock()
			if persistHook != nil {
				persistHook()
			}
			if webhookURL != "" && (len(triggered) > 0 || len(resolved) > 0) {
				go e.dispatchWebhook(webhookURL, triggered, resolved)
			}
		}
	}(acquired, settings)
}

func (e *Engine) acquireInFlight(serverID string) {
	e.mu.Lock()
	e.inFlight[serverID]++
	e.lastPolled[serverID] = time.Now().UTC()
	e.mu.Unlock()
}

func (e *Engine) releaseInFlight(serverID string) {
	e.mu.Lock()
	e.releaseInFlightLocked(serverID)
	e.mu.Unlock()
}

func (e *Engine) releaseInFlightLocked(serverID string) {
	if e.inFlight[serverID] <= 1 {
		delete(e.inFlight, serverID)
	} else {
		e.inFlight[serverID]--
	}
}

// CollectServerNow immediately probes a single server (even if its background schedule is paused),
// records the resulting snapshot & sample point in the encrypted vault, and returns the updated snapshot.
func (e *Engine) CollectServerNow(ctx context.Context, serverID, trustFingerprint, clientIP string) (*vault.ServerMonitorSnapshot, error) {
	if e.store == nil || e.sshMgr == nil {
		return nil, errors.New("监控引擎未初始化")
	}
	servers, settings, err := e.store.ListAllServerConfigs()
	if err != nil {
		return nil, err
	}

	var target *vault.ServerConfig
	for i := range servers {
		if servers[i].ID == serverID {
			target = &servers[i]
			break
		}
	}
	if target == nil {
		return nil, vault.ErrNotFound
	}

	e.acquireInFlight(serverID)
	defer e.releaseInFlight(serverID)

	snap, err := e.probeSingleServer(ctx, *target, settings, trustFingerprint, clientIP, true)
	if err != nil {
		return nil, err
	}

	triggered, resolved, webhookURL, recErr := e.store.RecordMonitorSnapshots([]*vault.ServerMonitorSnapshot{snap})
	if recErr != nil {
		return nil, recErr
	}

	now := time.Now().UTC()
	e.mu.Lock()
	e.lastPolled[serverID] = now
	e.lastSweepAt = &now
	e.mu.Unlock()
	e.Wake()

	if webhookURL != "" && (len(triggered) > 0 || len(resolved) > 0) {
		go e.dispatchWebhook(webhookURL, triggered, resolved)
	}

	// Return freshly stored snapshot with computed health score & port baseline flags
	if detail, dErr := e.store.GetServerMonitorDetail(serverID, 5*time.Minute); dErr == nil && detail.Snapshot != nil {
		return detail.Snapshot, nil
	}
	return snap, nil
}

// CollectAllNow immediately collects telemetry across the specified server IDs (or all monitor-enabled
// servers if serverIDs is empty) using the configured bounded worker pool.
func (e *Engine) CollectAllNow(ctx context.Context, serverIDs []string, clientIP string) ([]*vault.ServerMonitorSnapshot, error) {
	if e.store == nil || e.sshMgr == nil {
		return nil, errors.New("监控引擎未初始化")
	}
	servers, settings, err := e.store.ListAllServerConfigs()
	if err != nil {
		return nil, err
	}

	var targets []vault.ServerConfig
	if len(serverIDs) > 0 {
		for _, srv := range servers {
			if slices.Contains(serverIDs, srv.ID) {
				targets = append(targets, srv)
			}
		}
	} else {
		for _, srv := range servers {
			if !srv.MonitorDisabled {
				targets = append(targets, srv)
			}
		}
		// Fallback: if all servers were disabled, manual "collect all" still probes all servers
		if len(targets) == 0 {
			targets = servers
		}
	}

	if len(targets) == 0 {
		return []*vault.ServerMonitorSnapshot{}, nil
	}

	now := time.Now().UTC()
	e.mu.Lock()
	for _, srv := range targets {
		e.inFlight[srv.ID]++
		e.lastPolled[srv.ID] = now
	}
	e.mu.Unlock()

	defer func() {
		fin := time.Now().UTC()
		e.mu.Lock()
		for _, srv := range targets {
			e.releaseInFlightLocked(srv.ID)
			e.lastPolled[srv.ID] = fin
		}
		e.lastSweepAt = &fin
		e.mu.Unlock()
		e.Wake()
	}()

	snaps := e.collectBatch(ctx, targets, settings, false, clientIP)
	if len(snaps) == 0 {
		return []*vault.ServerMonitorSnapshot{}, nil
	}

	triggered, resolved, webhookURL, recErr := e.store.RecordMonitorSnapshots(snaps)
	if recErr != nil {
		return nil, recErr
	}
	if webhookURL != "" && (len(triggered) > 0 || len(resolved) > 0) {
		go e.dispatchWebhook(webhookURL, triggered, resolved)
	}
	return snaps, nil
}

func (e *Engine) collectBatch(
	ctx context.Context,
	targets []vault.ServerConfig,
	settings vault.MonitorSettings,
	interactive bool,
	clientIP string,
) []*vault.ServerMonitorSnapshot {
	workers := settings.Concurrency
	if workers < 1 {
		workers = 1
	} else if workers > 20 {
		workers = 20
	}

	results := make([]*vault.ServerMonitorSnapshot, len(targets))
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup

	for idx, srv := range targets {
		wg.Add(1)
		go func(i int, target vault.ServerConfig) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
			}
			defer func() { <-sem }()

			if ctx.Err() != nil {
				return
			}
			snap, err := e.probeSingleServer(ctx, target, settings, "", clientIP, interactive)
			if err == nil && snap != nil {
				results[i] = snap
			}
		}(idx, srv)
	}
	wg.Wait()

	out := make([]*vault.ServerMonitorSnapshot, 0, len(targets))
	for _, s := range results {
		if s != nil {
			out = append(out, s)
		}
	}
	return out
}

func (e *Engine) probeSingleServer(
	ctx context.Context,
	srv vault.ServerConfig,
	settings vault.MonitorSettings,
	trustFingerprint string,
	clientIP string,
	interactive bool,
) (*vault.ServerMonitorSnapshot, error) {
	timeoutSec := settings.TimeoutSec
	if timeoutSec < 5 {
		timeoutSec = 15
	}
	probeTimeout := time.Duration(timeoutSec) * time.Second

	startTotal := time.Now()
	nowUTC := startTotal.UTC()

	prevSnap, _ := e.store.GetPreviousMonitorSnapshot(srv.ID)

	dialTimeout := probeTimeout
	if dl, ok := ctx.Deadline(); ok {
		if rem := time.Until(dl); rem > 0 && rem < dialTimeout {
			dialTimeout = rem
		}
	}

	dialStart := time.Now()
	client, err := e.sshMgr.Dial(srv.ID, sshmanager.DialOptions{
		TrustFingerprint: trustFingerprint,
		ClientIP:         clientIP,
		Timeout:          dialTimeout,
	})
	if err != nil {
		if errors.Is(err, vault.ErrVaultLocked) || errors.Is(err, vault.ErrNotFound) {
			return nil, err
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var hkErr *sshmanager.HostKeyUntrustedError
		if interactive && errors.As(err, &hkErr) {
			return nil, err
		}
		return &vault.ServerMonitorSnapshot{
			ServerID:    srv.ID,
			ServerName:  srv.Name,
			Group:       srv.Group,
			Host:        srv.Host,
			Port:        srv.Port,
			CollectedAt: nowUTC,
			DurationMs:  max(1, time.Since(startTotal).Milliseconds()),
			Reachable:   false,
			HealthLevel: vault.HealthOffline,
			HealthScore: 0,
			Error:       err.Error(),
		}, nil
	}
	defer client.Close()

	handshakeLatencyMs := max(1, time.Since(dialStart).Milliseconds())

	sess, err := client.NewSession()
	if err != nil {
		return &vault.ServerMonitorSnapshot{
			ServerID:    srv.ID,
			ServerName:  srv.Name,
			Group:       srv.Group,
			Host:        srv.Host,
			Port:        srv.Port,
			CollectedAt: nowUTC,
			DurationMs:  max(1, time.Since(startTotal).Milliseconds()),
			Reachable:   false,
			HealthLevel:   vault.HealthOffline,
			HealthScore:   0,
			Fingerprint:   client.Fingerprint,
			RouteLabel:    client.Route.Label,
			RouteFallback: client.Route.FallbackUsed,
			Error:         fmt.Sprintf("创建远程监控会话失败: %v", err),
		}, nil
	}
	defer sess.Close()

	script := buildDeepTelemetryScript(settings, srv.WatchedServices)
	var stdoutBuf, stderrBuf bytes.Buffer
	sess.Stdout = &stdoutBuf
	sess.Stderr = &stderrBuf

	cmdCtx, cmdCancel := context.WithTimeout(ctx, probeTimeout)
	defer cmdCancel()

	doneCh := make(chan error, 1)
	go func() {
		doneCh <- sess.Run(script)
	}()

	var runErr error
	select {
	case runErr = <-doneCh:
	case <-cmdCtx.Done():
		_ = sess.Close()
		_ = client.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		runErr = fmt.Errorf("采集脚本执行超时 (%ds)", timeoutSec)
	}

	rawOut := stdoutBuf.String()
	if !strings.Contains(rawOut, "===SNS_SEC:") && runErr != nil {
		errDetail := strings.TrimSpace(stderrBuf.String())
		if errDetail != "" {
			errDetail = fmt.Sprintf("%v: %s", runErr, errDetail)
		} else {
			errDetail = runErr.Error()
		}
		return &vault.ServerMonitorSnapshot{
			ServerID:    srv.ID,
			ServerName:  srv.Name,
			Group:       srv.Group,
			Host:        srv.Host,
			Port:        srv.Port,
			CollectedAt: nowUTC,
			DurationMs:  max(1, time.Since(startTotal).Milliseconds()),
			LatencyMs:   handshakeLatencyMs,
			Reachable:   false,
			HealthLevel:   vault.HealthOffline,
			HealthScore:   0,
			Fingerprint:   client.Fingerprint,
			RouteLabel:    client.Route.Label,
			RouteFallback: client.Route.FallbackUsed,
			Error:         errDetail,
		}, nil
	}

	snap := &vault.ServerMonitorSnapshot{
		ServerID:      srv.ID,
		ServerName:    srv.Name,
		Group:         srv.Group,
		Host:          srv.Host,
		Port:          srv.Port,
		CollectedAt:   nowUTC,
		LatencyMs:     handshakeLatencyMs,
		Reachable:     true,
		Fingerprint:   client.Fingerprint,
		RouteLabel:    client.Route.Label,
		RouteFallback: client.Route.FallbackUsed,
	}

	ParseDeepTelemetry(rawOut, snap, prevSnap)
	snap.DurationMs = max(1, time.Since(startTotal).Milliseconds())
	return snap, nil
}

func (e *Engine) dispatchWebhook(webhookURL string, triggered, resolved []vault.MonitorAlert) {
	urlClean := strings.TrimSpace(webhookURL)
	if !strings.HasPrefix(urlClean, "http://") && !strings.HasPrefix(urlClean, "https://") {
		return
	}

	var lines []string
	if len(triggered) > 0 {
		lines = append(lines, fmt.Sprintf("【触发告警 %d 条】", len(triggered)))
		for _, a := range triggered {
			lines = append(lines, fmt.Sprintf("- [%s] %s (%s)", strings.ToUpper(string(a.Severity)), a.Title, a.Detail))
		}
	}
	if len(resolved) > 0 {
		lines = append(lines, fmt.Sprintf("【恢复通知 %d 条】", len(resolved)))
		for _, a := range resolved {
			lines = append(lines, fmt.Sprintf("- [RESOLVED] %s", a.Title))
		}
	}
	summaryText := "ServerNeedSafe 服务器监控通知\n" + strings.Join(lines, "\n")

	payload := map[string]any{
		"source":          "ServerNeedSafe",
		"timestamp":       time.Now().UTC().Format(time.RFC3339),
		"triggered_count": len(triggered),
		"resolved_count":  len(resolved),
		"triggered":       triggered,
		"resolved":        resolved,
		"text":            summaryText,
		"msg_type":        "text",
		"content": map[string]string{
			"text": summaryText,
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return
	}

	if e.webhookPost != nil {
		_ = e.webhookPost(urlClean, body)
	}
}

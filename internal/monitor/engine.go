package monitor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/sshmanager"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// RuntimeStatus reports the live scheduler, SSH pool, and webhook health state of the monitoring engine.
type RuntimeStatus struct {
	Running           bool       `json:"running"`
	Collecting        bool       `json:"collecting"`
	VaultUnlocked     bool       `json:"vault_unlocked"`
	Enabled           bool       `json:"enabled"`
	IntervalSec       int        `json:"interval_sec"`
	SlowIntervalSec   int        `json:"slow_interval_sec"`
	InFlightCount     int        `json:"in_flight_count"`
	PooledConnections int        `json:"pooled_connections"`
	LastSweepAt       *time.Time `json:"last_sweep_at,omitempty"`
	NextSweepAt       *time.Time `json:"next_sweep_at,omitempty"`
	LastWebhookAt     *time.Time `json:"last_webhook_at,omitempty"`
	LastWebhookError  string     `json:"last_webhook_error,omitempty"`
}

// Engine schedules periodic agentless SSH telemetry sweeps, persists snapshots &
// time-series samples inside monitor_runtime.json, evaluates multi-dimensional alerts,
// reuses SSH/jump connections safely, and dispatches multi-platform webhooks.
type Engine struct {
	store  *vault.Store
	sshMgr *sshmanager.Manager
	pool   *sshConnPool

	mu               sync.Mutex
	started          bool
	closed           bool
	stopCh           chan struct{}
	wakeCh           chan struct{}
	epochCtx         context.Context
	epochCancel      context.CancelFunc
	lastPolled       map[string]time.Time
	lastSlowAt       map[string]time.Time
	inFlight         map[string]chan struct{}
	lastSweepAt      *time.Time
	nextSweepAt      *time.Time
	lastPoolCleanup  time.Time
	lastWebhookAt    *time.Time
	lastWebhookError string
	tickInterval     time.Duration
	webhookRetryWait time.Duration

	webhookPost    func(urlClean string, body []byte) error
	onPersist      func()
	alertEventHook func(ctx context.Context, triggered, resolved []vault.MonitorAlert)
}

// NewEngine creates a new monitoring engine wired to store ready hooks and SSH connection pooling.
func NewEngine(store *vault.Store, sshMgr *sshmanager.Manager) *Engine {
	epochCtx, epochCancel := context.WithCancel(context.Background())
	e := &Engine{
		store:            store,
		sshMgr:           sshMgr,
		pool:             newSSHConnPool(sshMgr),
		stopCh:           make(chan struct{}),
		wakeCh:           make(chan struct{}, 1),
		epochCtx:         epochCtx,
		epochCancel:      epochCancel,
		lastPolled:       make(map[string]time.Time),
		lastSlowAt:       make(map[string]time.Time),
		inFlight:         make(map[string]chan struct{}),
		tickInterval:     1 * time.Second,
		webhookRetryWait: 500 * time.Millisecond,
		webhookPost:      defaultWebhookPost,
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
	if e.epochCtx == nil {
		e.epochCtx, e.epochCancel = context.WithCancel(context.Background())
	}
	e.mu.Unlock()

	go e.schedulerLoop()
	e.Wake()
}

// Close stops the background scheduler, cancels all in-flight probes, and closes all pooled SSH connections.
func (e *Engine) Close() {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return
	}
	e.closed = true
	cancel := e.epochCancel
	e.epochCancel = nil
	close(e.stopCh)
	e.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if e.pool != nil {
		e.pool.EvictAll()
	}
}

// Wake nudges the scheduler to re-evaluate intervals and due servers immediately.
func (e *Engine) Wake() {
	select {
	case e.wakeCh <- struct{}{}:
	default:
	}
}

// EvictServerConnection drops any pooled SSH / jump connection associated with serverID (call after server edit/delete).
func (e *Engine) EvictServerConnection(serverID string) {
	if e.pool != nil {
		e.pool.Evict(serverID)
	}
}

// OnPolicyUpdated reconciles engine resources (e.g. closing pooled connections if pooling was turned off) and wakes scheduler.
func (e *Engine) OnPolicyUpdated(settings vault.MonitorSettings) {
	if !settings.UseSSHConnectionPool && e.pool != nil {
		e.pool.EvictAll()
	}
	e.Wake()
}

func (e *Engine) onStoreReady() {
	e.mu.Lock()
	oldCancel := e.epochCancel
	e.epochCtx, e.epochCancel = context.WithCancel(context.Background())
	clear(e.lastPolled)
	clear(e.lastSlowAt)
	e.mu.Unlock()

	if oldCancel != nil {
		oldCancel()
	}
	if e.pool != nil {
		e.pool.EvictAll()
	}
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

	pooled := 0
	if e.pool != nil {
		pooled = e.pool.Count()
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	inFlightCnt := len(e.inFlight)
	st := RuntimeStatus{
		Running:           e.started && !e.closed,
		Collecting:        inFlightCnt > 0,
		VaultUnlocked:     vaultReady,
		Enabled:           settings.Enabled,
		IntervalSec:       settings.IntervalSec,
		SlowIntervalSec:   settings.SlowIntervalSec,
		InFlightCount:     inFlightCnt,
		PooledConnections: pooled,
		LastWebhookError:  e.lastWebhookError,
	}
	if e.lastSweepAt != nil {
		t := *e.lastSweepAt
		st.LastSweepAt = &t
	}
	if vaultReady && settings.Enabled && e.nextSweepAt != nil {
		t := *e.nextSweepAt
		st.NextSweepAt = &t
	}
	if e.lastWebhookAt != nil {
		t := *e.lastWebhookAt
		st.LastWebhookAt = &t
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

func effectiveSlowInterval(settings vault.MonitorSettings, fastInterval time.Duration) time.Duration {
	sec := settings.SlowIntervalSec
	if sec < 60 {
		sec = 300
	}
	d := time.Duration(sec) * time.Second
	if d < fastInterval {
		return fastInterval
	}
	return d
}

// serverInitialJitter spreads initial due times across larger fleets (>3 nodes) to avoid thundering-herd spikes.
func serverInitialJitter(serverID string, totalServers int, interval time.Duration) time.Duration {
	if totalServers <= 3 {
		return 0
	}
	maxJitter := min(4*time.Second, interval/4)
	if maxJitter <= 0 {
		return 0
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(serverID))
	ms := int64(h.Sum32()) % maxJitter.Milliseconds()
	return time.Duration(ms) * time.Millisecond
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

	// Periodically evict idle pooled SSH connections
	e.mu.Lock()
	shouldCleanupPool := now.Sub(e.lastPoolCleanup) >= 60*time.Second
	if shouldCleanupPool {
		e.lastPoolCleanup = now
	}
	e.mu.Unlock()
	if shouldCleanupPool && e.pool != nil {
		maxIdle := max(5*time.Minute, time.Duration(settings.IntervalSec)*3*time.Second)
		e.pool.CleanupIdle(maxIdle)
	}

	var dueServers []vault.ServerConfig
	var earliestNext time.Time

	// Count active monitored servers for jitter decision
	monitoredCount := 0
	for _, srv := range servers {
		if !srv.MonitorDisabled {
			monitoredCount++
		}
	}

	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return
	}
	parentCtx := e.epochCtx
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
				if prev.LastSlowCollectedAt != nil && !prev.LastSlowCollectedAt.IsZero() {
					e.lastSlowAt[srv.ID] = *prev.LastSlowCollectedAt
				}
			} else if jitter := serverInitialJitter(srv.ID, monitoredCount, interval); jitter > 0 {
				// Schedule first poll staggered by jitter without permanently delaying subsequent cycles
				staggeredLast := now.Add(-interval + jitter)
				lastAt = staggeredLast
				e.lastPolled[srv.ID] = lastAt
			}
		}

		var nextDue time.Time
		if lastAt.IsZero() {
			nextDue = now
		} else {
			nextDue = lastAt.Add(interval)
		}

		if _, busy := e.inFlight[srv.ID]; busy {
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

	acquired := make([]vault.ServerConfig, 0, len(dueServers))
	for _, srv := range dueServers {
		if _, busy := e.inFlight[srv.ID]; !busy {
			e.inFlight[srv.ID] = make(chan struct{})
			e.lastPolled[srv.ID] = now
			acquired = append(acquired, srv)
		}
	}
	e.mu.Unlock()

	if len(acquired) == 0 {
		return
	}

	// Derive a per-sweep child context from epochCtx (NO nested closure chain -> zero memory leak!)
	sweepCtx, sweepCancel := context.WithCancel(parentCtx)

	go func(targets []vault.ServerConfig, sweepSettings vault.MonitorSettings) {
		defer func() {
			sweepCancel()
			fin := time.Now().UTC()
			e.mu.Lock()
			for _, srv := range targets {
				e.releaseInFlightLocked(srv.ID)
			}
			e.lastSweepAt = &fin
			e.mu.Unlock()
		}()

		snaps := e.collectBatch(sweepCtx, targets, sweepSettings, false, false, "scheduler")
		if sweepCtx.Err() != nil || len(snaps) == 0 {
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
			e.maybeDispatchNotifications(sweepSettings, webhookURL, triggered, resolved)
		}
	}(acquired, settings)
}

// acquireServerSlot enforces strict per-server serialization so manual and scheduled probes never overlap.
func (e *Engine) acquireServerSlot(ctx context.Context, serverID string) error {
	for {
		e.mu.Lock()
		ch, busy := e.inFlight[serverID]
		if !busy {
			e.inFlight[serverID] = make(chan struct{})
			e.lastPolled[serverID] = time.Now().UTC()
			e.mu.Unlock()
			return nil
		}
		e.mu.Unlock()

		select {
		case <-ch:
			// Previous sweep finished; retry acquiring slot
		case <-ctx.Done():
			return ctx.Err()
		case <-e.stopCh:
			return errors.New("监控引擎已停止")
		}
	}
}

func (e *Engine) releaseInFlight(serverID string) {
	e.mu.Lock()
	e.releaseInFlightLocked(serverID)
	e.mu.Unlock()
}

func (e *Engine) releaseInFlightLocked(serverID string) {
	if ch, ok := e.inFlight[serverID]; ok {
		delete(e.inFlight, serverID)
		close(ch)
	}
}

func (e *Engine) shouldRunFullTier(srv vault.ServerConfig, settings vault.MonitorSettings, prevSnap *vault.ServerMonitorSnapshot, forceFull bool) bool {
	if forceFull || prevSnap == nil || !prevSnap.Reachable {
		return true
	}
	fastInt := effectiveServerInterval(srv, settings.IntervalSec)
	slowInt := effectiveSlowInterval(settings, fastInt)

	e.mu.Lock()
	lastSlow := e.lastSlowAt[srv.ID]
	e.mu.Unlock()
	if lastSlow.IsZero() && prevSnap.LastSlowCollectedAt != nil {
		lastSlow = *prevSnap.LastSlowCollectedAt
	}
	if lastSlow.IsZero() {
		return true
	}
	return time.Since(lastSlow) >= slowInt
}

// CollectServerNow immediately probes a single server (full tier, even if its background schedule is paused),
// serialized cleanly against any in-flight scheduled sweep, records the snapshot, and returns it.
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

	if err := e.acquireServerSlot(ctx, serverID); err != nil {
		return nil, err
	}
	defer e.releaseInFlight(serverID)

	snap, err := e.probeSingleServer(ctx, *target, settings, trustFingerprint, clientIP, true, true)
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

	e.maybeDispatchNotifications(settings, webhookURL, triggered, resolved)

	if detail, dErr := e.store.GetServerMonitorDetail(serverID, 5*time.Minute); dErr == nil && detail.Snapshot != nil {
		return detail.Snapshot, nil
	}
	return snap, nil
}

// CollectAllNow immediately collects full-tier telemetry across the specified server IDs (or all monitor-enabled
// servers if serverIDs is empty) using the configured bounded worker pool, serialized per server.
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
		if len(targets) == 0 {
			targets = servers
		}
	}

	if len(targets) == 0 {
		return []*vault.ServerMonitorSnapshot{}, nil
	}

	// Acquire per-server slots cleanly so manual CollectAll never overlaps an active scheduled sweep on the same server.
	acquired := make([]vault.ServerConfig, 0, len(targets))
	for _, srv := range targets {
		if err := e.acquireServerSlot(ctx, srv.ID); err != nil {
			for _, acq := range acquired {
				e.releaseInFlight(acq.ID)
			}
			return nil, err
		}
		acquired = append(acquired, srv)
	}

	defer func() {
		fin := time.Now().UTC()
		e.mu.Lock()
		for _, srv := range acquired {
			e.releaseInFlightLocked(srv.ID)
			e.lastPolled[srv.ID] = fin
		}
		e.lastSweepAt = &fin
		e.mu.Unlock()
		e.Wake()
	}()

	snaps := e.collectBatch(ctx, acquired, settings, false, true, clientIP)
	if len(snaps) == 0 {
		return []*vault.ServerMonitorSnapshot{}, nil
	}

	triggered, resolved, webhookURL, recErr := e.store.RecordMonitorSnapshots(snaps)
	if recErr != nil {
		return nil, recErr
	}
	e.maybeDispatchNotifications(settings, webhookURL, triggered, resolved)
	return snaps, nil
}

func (e *Engine) collectBatch(
	ctx context.Context,
	targets []vault.ServerConfig,
	settings vault.MonitorSettings,
	interactive bool,
	forceFull bool,
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
			snap, err := e.probeSingleServer(ctx, target, settings, "", clientIP, interactive, forceFull)
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
	forceFull bool,
) (*vault.ServerMonitorSnapshot, error) {
	timeoutSec := settings.TimeoutSec
	if timeoutSec < 5 {
		timeoutSec = 15
	}
	probeTimeout := time.Duration(timeoutSec) * time.Second

	startTotal := time.Now()
	nowUTC := startTotal.UTC()

	prevSnap, _ := e.store.GetPreviousMonitorSnapshot(srv.ID)
	runFull := e.shouldRunFullTier(srv, settings, prevSnap, forceFull)
	tier := TierFast
	if runFull {
		tier = TierFull
	}
	hasPrevCPU := prevSnap != nil && prevSnap.Reachable && len(prevSnap.RawCPUTicks) >= 4 &&
		!prevSnap.CollectedAt.IsZero() && nowUTC.Sub(prevSnap.CollectedAt) >= 3*time.Second && nowUTC.Sub(prevSnap.CollectedAt) <= time.Hour

	dialTimeout := probeTimeout
	if dl, ok := ctx.Deadline(); ok {
		if rem := time.Until(dl); rem > 0 && rem < dialTimeout {
			dialTimeout = rem
		}
	}

	client, latencyMs, reused, release, err := e.pool.Acquire(srv, dialTimeout, trustFingerprint, clientIP, settings.UseSSHConnectionPool)
	if err != nil {
		if errors.Is(err, vault.ErrVaultLocked) || errors.Is(err, vault.ErrNotFound) {
			return nil, err
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var hkErr *sshmanager.HostKeyUntrustedError
		if errors.As(err, &hkErr) {
			if interactive {
				return nil, err
			}
			if hkErr.Reason == "mismatch" {
				return &vault.ServerMonitorSnapshot{
					ServerID:              srv.ID,
					ServerName:            srv.Name,
					Group:                 srv.Group,
					Host:                  srv.Host,
					Port:                  srv.Port,
					CollectedAt:           nowUTC,
					CollectionTier:        string(tier),
					DurationMs:            max(1, time.Since(startTotal).Milliseconds()),
					Reachable:             false,
					HealthLevel:           vault.HealthOffline,
					HealthScore:           0,
					HostKeyChanged:        true,
					HostKeyMismatchDetail: hkErr.Error(),
					Error:                 hkErr.Error(),
				}, nil
			}
		}
		return &vault.ServerMonitorSnapshot{
			ServerID:       srv.ID,
			ServerName:     srv.Name,
			Group:          srv.Group,
			Host:           srv.Host,
			Port:           srv.Port,
			CollectedAt:    nowUTC,
			CollectionTier: string(tier),
			DurationMs:     max(1, time.Since(startTotal).Milliseconds()),
			Reachable:      false,
			HealthLevel:    vault.HealthOffline,
			HealthScore:    0,
			Error:          err.Error(),
		}, nil
	}

	connBroken := false
	defer func() {
		release(connBroken)
	}()

	sess, err := client.NewSession()
	if err != nil && reused {
		// Reused pooled SSH transport dropped between keepalive and session open: redial once transparently!
		connBroken = true
		release(true)
		connBroken = false

		client, latencyMs, reused, release, err = e.pool.Acquire(srv, dialTimeout, trustFingerprint, clientIP, false)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return &vault.ServerMonitorSnapshot{
				ServerID:       srv.ID,
				ServerName:     srv.Name,
				Group:          srv.Group,
				Host:           srv.Host,
				Port:           srv.Port,
				CollectedAt:    nowUTC,
				CollectionTier: string(tier),
				DurationMs:     max(1, time.Since(startTotal).Milliseconds()),
				Reachable:      false,
				HealthLevel:    vault.HealthOffline,
				HealthScore:    0,
				Error:          err.Error(),
			}, nil
		}
		sess, err = client.NewSession()
	}

	if err != nil {
		connBroken = true
		return &vault.ServerMonitorSnapshot{
			ServerID:       srv.ID,
			ServerName:     srv.Name,
			Group:          srv.Group,
			Host:           srv.Host,
			Port:           srv.Port,
			CollectedAt:    nowUTC,
			CollectionTier: string(tier),
			DurationMs:     max(1, time.Since(startTotal).Milliseconds()),
			Reachable:      false,
			HealthLevel:    vault.HealthOffline,
			HealthScore:    0,
			Fingerprint:    client.Fingerprint,
			RouteLabel:     client.Route.Label,
			RouteFallback:  client.Route.FallbackUsed,
			Error:          fmt.Sprintf("创建远程监控会话失败: %v", err),
		}, nil
	}
	defer sess.Close()

	script := buildTelemetryScript(settings, srv.WatchedServices, tier, hasPrevCPU)
	var stdoutBuf, stderrBuf lockedBuffer
	sess.Stdout = &stdoutBuf
	sess.Stderr = &stderrBuf

	cmdCtx, cmdCancel := context.WithTimeout(ctx, probeTimeout)
	defer cmdCancel()

	doneCh := make(chan error, 1)
	go func() {
		doneCh <- sess.Run(script)
	}()

	var runErr error
	timedOut := false
	select {
	case runErr = <-doneCh:
	case <-cmdCtx.Done():
		timedOut = true
		connBroken = true
		_ = sess.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		runErr = fmt.Errorf("采集脚本执行超时 (%ds)", timeoutSec)
	}

	rawOut := stdoutBuf.String()
	// Integrity check: real scripts emit ===SNS_END===; synthetic test fixtures without ===SNS_END===
	// still exit cleanly (runErr == nil) and emit ===SNS_SEC:SAMPLE_T1===.
	// Any mid-script timeout or truncation MUST NOT be treated as a healthy zeroed snapshot (prevents false alert resolution!).
	hasCompleteSentinel := strings.Contains(rawOut, "===SNS_END===") ||
		(!timedOut && runErr == nil && strings.Contains(rawOut, "===SNS_SEC:SAMPLE_T1==="))

	if timedOut || !hasCompleteSentinel {
		connBroken = true
		errDetail := strings.TrimSpace(stderrBuf.String())
		switch {
		case runErr != nil && errDetail != "":
			errDetail = fmt.Sprintf("%v: %s", runErr, errDetail)
		case runErr != nil:
			errDetail = runErr.Error()
		case errDetail != "":
			errDetail = fmt.Sprintf("采集输出不完整（缺少结束哨兵）: %s", errDetail)
		default:
			errDetail = "采集脚本输出被截断或不完整（已拒绝写入零值以防误销警）"
		}
		return &vault.ServerMonitorSnapshot{
			ServerID:       srv.ID,
			ServerName:     srv.Name,
			Group:          srv.Group,
			Host:           srv.Host,
			Port:           srv.Port,
			CollectedAt:    nowUTC,
			CollectionTier: string(tier),
			DurationMs:     max(1, time.Since(startTotal).Milliseconds()),
			LatencyMs:      latencyMs,
			Reachable:      false,
			HealthLevel:    vault.HealthOffline,
			HealthScore:    0,
			Fingerprint:    client.Fingerprint,
			RouteLabel:     client.Route.Label,
			RouteFallback:  client.Route.FallbackUsed,
			PartialError:   errDetail,
			Error:          errDetail,
		}, nil
	}

	snap := &vault.ServerMonitorSnapshot{
		ServerID:         srv.ID,
		ServerName:       srv.Name,
		Group:            srv.Group,
		Host:             srv.Host,
		Port:             srv.Port,
		CollectedAt:      nowUTC,
		CollectionTier:   string(tier),
		LatencyMs:        latencyMs,
		Reachable:        true,
		Fingerprint:      client.Fingerprint,
		RouteLabel:       client.Route.Label,
		RouteFallback:    client.Route.FallbackUsed,
		ConnectionReused: reused,
	}
	if runFull {
		ts := nowUTC
		snap.LastSlowCollectedAt = &ts
		e.mu.Lock()
		e.lastSlowAt[srv.ID] = ts
		e.mu.Unlock()
	}

	ParseDeepTelemetry(rawOut, snap, prevSnap)
	snap.DurationMs = max(1, time.Since(startTotal).Milliseconds())
	return snap, nil
}

// SetAlertEventHook registers an optional asynchronous event notification listener (e.g. QQ Bot WebSocket).
func (e *Engine) SetAlertEventHook(fn func(ctx context.Context, triggered, resolved []vault.MonitorAlert)) {
	e.mu.Lock()
	e.alertEventHook = fn
	e.mu.Unlock()
}

func (e *Engine) maybeDispatchNotifications(settings vault.MonitorSettings, webhookURL string, triggered, resolved []vault.MonitorAlert) {
	if len(triggered) == 0 && len(resolved) == 0 {
		return
	}
	e.mu.Lock()
	hook := e.alertEventHook
	e.mu.Unlock()
	if hook != nil {
		trigCopy := slices.Clone(triggered)
		resCopy := slices.Clone(resolved)
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			hook(ctx, trigCopy, resCopy)
		}()
	}

	urlClean := strings.TrimSpace(webhookURL)
	var extraChannels []vault.WebhookChannel
	if settings.ReuseAIPatrolWebhooks && e.store != nil {
		extraChannels = e.store.GetEnabledAIPatrolWebhooks()
	}
	if urlClean == "" && len(extraChannels) == 0 {
		return
	}
	go e.dispatchWebhook(urlClean, extraChannels, triggered, resolved)
}

func (e *Engine) dispatchWebhook(webhookURL string, extraChannels []vault.WebhookChannel, triggered, resolved []vault.MonitorAlert) {
	title, summaryText, markdownText, feishuColor := formatAlertNotificationBodies(triggered, resolved)
	var lastErr error
	deliveredAny := false

	// 1. Primary MonitorSettings.WebhookURL (auto-detect Feishu/DingTalk/WeCom/Generic + retries)
	urlClean := strings.TrimSpace(webhookURL)
	if strings.HasPrefix(urlClean, "http://") || strings.HasPrefix(urlClean, "https://") {
		platform := detectWebhookPlatform(urlClean)
		body, err := buildMonitorWebhookPayload(platform, title, summaryText, markdownText, feishuColor, triggered, resolved)
		if err == nil && e.webhookPost != nil {
			err = e.postWithRetry(urlClean, body)
		}
		if err != nil {
			lastErr = err
		} else {
			deliveredAny = true
		}
	}

	// 2. Optional reuse of enabled AI Patrol multi-channel webhooks
	for _, ch := range extraChannels {
		var chErr error
		for attempt := 0; attempt < 3; attempt++ {
			if attempt > 0 {
				e.sleepRetry(attempt)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			chErr = sendSignedWebhookChannel(ctx, ch, title, summaryText, markdownText, feishuColor, triggered, resolved)
			cancel()
			if chErr == nil {
				break
			}
		}
		if chErr != nil {
			lastErr = fmt.Errorf("通道 [%s]: %w", ch.Name, chErr)
		} else {
			deliveredAny = true
		}
	}

	now := time.Now().UTC()
	e.mu.Lock()
	if deliveredAny {
		e.lastWebhookAt = &now
	}
	if lastErr != nil {
		e.lastWebhookError = lastErr.Error()
	} else if deliveredAny {
		e.lastWebhookError = ""
	}
	e.mu.Unlock()

	if lastErr != nil && e.store != nil {
		e.store.RecordAudit("monitor.webhook_failed", "webhook", fmt.Sprintf("监控告警推送失败: %v", lastErr), "monitor-engine", false)
	}
}

func (e *Engine) postWithRetry(urlClean string, body []byte) error {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			e.sleepRetry(attempt)
		}
		if err := e.webhookPost(urlClean, body); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	return lastErr
}

func (e *Engine) sleepRetry(attempt int) {
	base := e.webhookRetryWait
	if base <= 0 {
		base = 500 * time.Millisecond
	}
	d := base * time.Duration(1<<(attempt-1))
	select {
	case <-time.After(d):
	case <-e.stopCh:
	}
}

// TestWebhook sends a synthetic test notification to the specified Webhook URL (and optional AI patrol channels).
func (e *Engine) TestWebhook(ctx context.Context, webhookURL string, reuseAIPatrol bool, clientIP string) error {
	urlClean := strings.TrimSpace(webhookURL)
	var extraChannels []vault.WebhookChannel
	if reuseAIPatrol && e.store != nil {
		extraChannels = e.store.GetEnabledAIPatrolWebhooks()
	}
	if urlClean == "" && len(extraChannels) == 0 {
		return fmt.Errorf("%w: 请先填写监控 Webhook 地址或勾选复用 AI 巡检通道", vault.ErrInvalidInput)
	}

	sampleAlert := []vault.MonitorAlert{
		{
			RuleKind:   "test",
			RuleName:   "连通性测试",
			Severity:   vault.SeverityInfo,
			Status:     vault.AlertStatusFiring,
			Title:      "ServerNeedSafe 状态监控 Webhook 连通性测试",
			Detail:     "如果您收到本条消息，说明当前监控告警 Webhook 协议适配与推送链路工作正常",
			MetricText: "OK",
		},
	}
	title, summaryText, markdownText, _ := formatAlertNotificationBodies(sampleAlert, nil)
	title = "ServerNeedSafe · 监控 Webhook 连通性测试"

	var errs []string
	if urlClean != "" {
		if !strings.HasPrefix(urlClean, "http://") && !strings.HasPrefix(urlClean, "https://") {
			return fmt.Errorf("%w: Webhook 地址必须以 http:// 或 https:// 开头", vault.ErrInvalidInput)
		}
		platform := detectWebhookPlatform(urlClean)
		body, err := buildMonitorWebhookPayload(platform, title, summaryText, markdownText, "blue", sampleAlert, nil)
		if err != nil {
			return err
		}
		if err := postWebhookWithHeaders(ctx, urlClean, body, nil); err != nil {
			errs = append(errs, fmt.Sprintf("主 Webhook (%s): %v", platform, err))
		}
	}
	for _, ch := range extraChannels {
		if err := sendSignedWebhookChannel(ctx, ch, title, summaryText, markdownText, "blue", sampleAlert, nil); err != nil {
			errs = append(errs, fmt.Sprintf("复用通道 [%s]: %v", ch.Name, err))
		}
	}

	if len(errs) > 0 {
		errMsg := strings.Join(errs, "；")
		if e.store != nil {
			e.store.RecordAudit("monitor.webhook_test", "webhook", "测试推送失败: "+errMsg, clientIP, false)
		}
		return errors.New(errMsg)
	}
	if e.store != nil {
		e.store.RecordAudit("monitor.webhook_test", "webhook", "监控 Webhook 连通性测试发送成功", clientIP, true)
	}
	return nil
}

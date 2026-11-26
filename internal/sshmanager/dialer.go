package sshmanager

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
	"golang.org/x/crypto/ssh"
)

const (
	defaultDialTimeout        = 12 * time.Second
	defaultFallbackHopTimeout = 6 * time.Second
	minFallbackHopTimeout     = 2 * time.Second
	defaultJumpCooldownTTL    = 60 * time.Second
	maxJumpHops               = 5
)

// DialTCPFunc abstracts raw TCP transport creation (e.g. blind WebSocket TCP relay in WASM/client mode,
// or direct OS TCP socket in native tests).
type DialTCPFunc func(ctx context.Context, addr string, timeout time.Duration) (net.Conn, error)

// HostKeyUntrustedError is returned when connecting to a host whose SSH host key
// is either unknown (under strict ask_new policy) or has changed (MITM protection).
type HostKeyUntrustedError struct {
	Reason               string `json:"reason"` // "unknown" or "mismatch"
	Address              string `json:"address"`
	ServerName           string `json:"server_name"`
	KeyType              string `json:"key_type"`
	PresentedFingerprint string `json:"presented_fingerprint"`
	PresentedPublicKey   string `json:"presented_public_key"`
	ExpectedFingerprint  string `json:"expected_fingerprint,omitempty"`
}

func (e *HostKeyUntrustedError) Error() string {
	if e.Reason == "mismatch" {
		return fmt.Sprintf("警告：服务器 [%s] (%s) 的 SSH 主机密钥指纹发生变化（原指纹 %s，当前 %s），已拦截连接以防范中间人攻击",
			e.ServerName, e.Address, e.ExpectedFingerprint, e.PresentedFingerprint)
	}
	return fmt.Sprintf("首次连接服务器 [%s] (%s)，请核验并信任其 SSH 主机指纹：%s (%s)",
		e.ServerName, e.Address, e.PresentedFingerprint, e.KeyType)
}

// DialRouteInfo describes the actual SSH transport path that succeeded when dialing a target server.
type DialRouteInfo struct {
	Direct          bool     `json:"direct"`
	JumpServerIDs   []string `json:"jump_server_ids,omitempty"`
	JumpServerNames []string `json:"jump_server_names,omitempty"`
	FallbackUsed    bool     `json:"fallback_used"`
	SkippedJumps    []string `json:"skipped_jumps,omitempty"`
	Label           string   `json:"label"`
}

// DialProgressEvent reports live route selection and fallback progress during connection setup.
type DialProgressEvent struct {
	Stage   string `json:"stage"` // "trying", "failed", "skipped", "connected"
	Message string `json:"message"`
}

func formatDialRouteLabel(direct bool, jumpNames []string, fallbackUsed bool) string {
	if direct || len(jumpNames) == 0 {
		if fallbackUsed {
			return "直连 (跳板退避)"
		}
		return "直连"
	}
	chain := strings.Join(jumpNames, " → ")
	if fallbackUsed {
		return fmt.Sprintf("经由: %s (已退避)", chain)
	}
	return fmt.Sprintf("经由: %s", chain)
}

// ManagedSSHClient wraps an ssh.Client along with any underlying Jump Host ssh.Clients
// so closing the client cleanly tears down the entire tunnel chain.
type ManagedSSHClient struct {
	*ssh.Client
	Server             *vault.ServerConfig
	Fingerprint        string
	Route              DialRouteInfo
	ImmediateJumpID    string
	HasAlternateRoutes bool
	jumpClient         *ManagedSSHClient
	closers            []func() error
	closeOnce          sync.Once
}

// IsImmediateJumpAlive sends a short-timeout keepalive probe to the immediate jump host
// to distinguish a jump-node outage from a target-side disconnect.
func (m *ManagedSSHClient) IsImmediateJumpAlive(timeout time.Duration) bool {
	if m == nil || m.jumpClient == nil || m.jumpClient.Client == nil {
		return false
	}
	if timeout <= 0 {
		timeout = 1500 * time.Millisecond
	}
	resCh := make(chan bool, 1)
	go func() {
		_, _, err := m.jumpClient.SendRequest("keepalive@openssh.com", true, nil)
		resCh <- err == nil
	}()
	select {
	case ok := <-resCh:
		return ok
	case <-time.After(timeout):
		return false
	}
}

func (m *ManagedSSHClient) Close() error {
	var firstErr error
	m.closeOnce.Do(func() {
		if m.Client != nil {
			if err := m.Client.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		for i := len(m.closers) - 1; i >= 0; i-- {
			if err := m.closers[i](); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	})
	return firstErr
}

// Manager coordinates end-to-end client-side SSH dialing, interactive PTY sessions, SFTP operations, and probes.
type Manager struct {
	store              *vault.Store
	dialTCP            DialTCPFunc
	mu                 sync.Mutex
	activeSessions     map[string]*TerminalSession
	cooldownMu         sync.Mutex
	jumpCooldowns      map[string]time.Time
	jumpCooldownTTL    time.Duration
	fallbackHopTimeout time.Duration
}

func NewManager(store *vault.Store) *Manager {
	return &Manager{
		store:              store,
		activeSessions:     make(map[string]*TerminalSession),
		jumpCooldowns:      make(map[string]time.Time),
		jumpCooldownTTL:    defaultJumpCooldownTTL,
		fallbackHopTimeout: defaultFallbackHopTimeout,
	}
}

// SetDialTCPFunc configures a custom raw TCP transport (such as the zero-knowledge WebSocket TCP relay).
func (m *Manager) SetDialTCPFunc(fn DialTCPFunc) {
	m.mu.Lock()
	m.dialTCP = fn
	m.mu.Unlock()
}

// SetJumpCooldownTTL customizes the in-memory failed jump host cooldown duration (useful for tests).
func (m *Manager) SetJumpCooldownTTL(d time.Duration) {
	m.cooldownMu.Lock()
	if d <= 0 {
		m.jumpCooldownTTL = defaultJumpCooldownTTL
	} else {
		m.jumpCooldownTTL = d
	}
	m.cooldownMu.Unlock()
}

// SetFallbackHopTimeout customizes the per-hop fallback timeout duration (useful for tests).
func (m *Manager) SetFallbackHopTimeout(d time.Duration) {
	m.cooldownMu.Lock()
	if d <= 0 {
		m.fallbackHopTimeout = defaultFallbackHopTimeout
	} else {
		m.fallbackHopTimeout = d
	}
	m.cooldownMu.Unlock()
}

func jumpNodeCooldownKey(jumpID string) string {
	return "node:" + jumpID
}

func jumpEdgeCooldownKey(jumpID, targetID string) string {
	return "edge:" + jumpID + "->" + targetID
}

// MarkJumpNodeFailed marks a jump server as globally unhealthy for the cooldown TTL.
func (m *Manager) MarkJumpNodeFailed(jumpID string) {
	if strings.TrimSpace(jumpID) == "" {
		return
	}
	m.cooldownMu.Lock()
	ttl := m.jumpCooldownTTL
	if ttl <= 0 {
		ttl = defaultJumpCooldownTTL
	}
	m.jumpCooldowns[jumpNodeCooldownKey(jumpID)] = time.Now().Add(ttl)
	m.cooldownMu.Unlock()
}

// MarkJumpEdgeFailed marks a specific jump->target path as unhealthy for the cooldown TTL.
func (m *Manager) MarkJumpEdgeFailed(jumpID, targetID string) {
	if strings.TrimSpace(jumpID) == "" || strings.TrimSpace(targetID) == "" {
		return
	}
	m.cooldownMu.Lock()
	ttl := m.jumpCooldownTTL
	if ttl <= 0 {
		ttl = defaultJumpCooldownTTL
	}
	m.jumpCooldowns[jumpEdgeCooldownKey(jumpID, targetID)] = time.Now().Add(ttl)
	m.cooldownMu.Unlock()
}

func (m *Manager) clearJumpCooldown(jumpID, targetID string) {
	if strings.TrimSpace(jumpID) == "" {
		return
	}
	m.cooldownMu.Lock()
	delete(m.jumpCooldowns, jumpNodeCooldownKey(jumpID))
	if strings.TrimSpace(targetID) != "" {
		delete(m.jumpCooldowns, jumpEdgeCooldownKey(jumpID, targetID))
	}
	m.cooldownMu.Unlock()
}

func (m *Manager) isJumpInCooldown(jumpID, targetID string, now time.Time) (bool, time.Duration) {
	m.cooldownMu.Lock()
	defer m.cooldownMu.Unlock()
	var maxRem time.Duration
	for _, key := range []string{jumpNodeCooldownKey(jumpID), jumpEdgeCooldownKey(jumpID, targetID)} {
		if exp, ok := m.jumpCooldowns[key]; ok {
			if now.Before(exp) {
				if rem := exp.Sub(now); rem > maxRem {
					maxRem = rem
				}
			} else {
				delete(m.jumpCooldowns, key)
			}
		}
	}
	return maxRem > 0, maxRem
}

func (m *Manager) getFallbackHopTimeout() time.Duration {
	m.cooldownMu.Lock()
	d := m.fallbackHopTimeout
	m.cooldownMu.Unlock()
	if d <= 0 {
		return defaultFallbackHopTimeout
	}
	return d
}

func (m *Manager) openRawTCP(addr string, timeout time.Duration) (net.Conn, error) {
	m.mu.Lock()
	fn := m.dialTCP
	m.mu.Unlock()

	if fn != nil {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		return fn(ctx, addr, timeout)
	}
	return net.DialTimeout("tcp", addr, timeout)
}

// DialOptions customizes dial behavior (e.g. trusting a presented host key fingerprint or streaming fallback progress).
type DialOptions struct {
	TrustFingerprint string // If non-empty and matches presented fingerprint, pins it in KnownHosts
	ClientIP         string
	Timeout          time.Duration
	OnProgress       func(DialProgressEvent)
}

func emitDialProgress(fn func(DialProgressEvent), stage, msg string) {
	if fn != nil && msg != "" {
		fn(DialProgressEvent{Stage: stage, Message: msg})
	}
}

func isSSHAuthError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "unable to authenticate")
}

func cloneVisitedMap(in map[string]bool) map[string]bool {
	out := make(map[string]bool, len(in)+1)
	for k, v := range in {
		out[k] = v
	}
	return out
}

type dialCandidate struct {
	isDirect    bool
	jumpID      string
	jumpName    string
	isPrimary   bool
	inCooldown  bool
	cooldownRem time.Duration
}

// Dial connects to the target server (through any configured JumpHost fallback chain) and verifies host keys end-to-end.
func (m *Manager) Dial(serverID string, opts DialOptions) (*ManagedSSHClient, error) {
	visited := make(map[string]bool)
	return m.dialChain(serverID, opts, visited, 0)
}

func (m *Manager) dialChain(serverID string, opts DialOptions, visited map[string]bool, depth int) (*ManagedSSHClient, error) {
	if depth > maxJumpHops {
		return nil, errors.New("SSH 跳板机链路层级超过上限 (最多 5 层)")
	}
	if visited[serverID] {
		return nil, errors.New("检测到循环的 SSH 跳板机配置链路")
	}
	branchVisited := cloneVisitedMap(visited)
	branchVisited[serverID] = true

	srv, err := m.store.GetServerSecret(serverID)
	if err != nil {
		return nil, err
	}

	authMethods, err := m.buildAuthMethods(srv)
	if err != nil {
		return nil, err
	}

	settings, err := m.store.GetSettings()
	if err != nil {
		return nil, err
	}

	targetAddr := net.JoinHostPort(srv.Host, strconv.Itoa(srv.Port))

	buildTargetSSHConfig := func(timeout time.Duration) (*ssh.ClientConfig, *string, *error) {
		var capturedFingerprint string
		var hostKeyErr error

		hostKeyCallback := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			fp := ssh.FingerprintSHA256(key)
			pubB64 := base64.StdEncoding.EncodeToString(key.Marshal())
			capturedFingerprint = fp

			existing, err := m.store.GetKnownHost(targetAddr)
			if err != nil {
				hostKeyErr = err
				return err
			}

			// Explicit user approval for this exact fingerprint
			if opts.TrustFingerprint != "" && opts.TrustFingerprint == fp {
				err := m.store.TrustKnownHost(vault.KnownHost{
					Address:      targetAddr,
					ServerName:   srv.Name,
					KeyType:      key.Type(),
					Fingerprint:  fp,
					PublicKeyB64: pubB64,
				}, opts.ClientIP)
				if err != nil {
					hostKeyErr = err
					return err
				}
				return nil
			}

			if existing != nil {
				if existing.Fingerprint != fp || existing.PublicKeyB64 != pubB64 {
					hkErr := &HostKeyUntrustedError{
						Reason:               "mismatch",
						Address:              targetAddr,
						ServerName:           srv.Name,
						KeyType:              key.Type(),
						PresentedFingerprint: fp,
						PresentedPublicKey:   pubB64,
						ExpectedFingerprint:  existing.Fingerprint,
					}
					hostKeyErr = hkErr
					return hkErr
				}
				m.store.TouchKnownHostVerified(targetAddr)
				return nil
			}

			// Unknown host key
			if settings.HostKeyPolicy == vault.HostKeyTOFU {
				if err := m.store.TrustKnownHost(vault.KnownHost{
					Address:      targetAddr,
					ServerName:   srv.Name,
					KeyType:      key.Type(),
					Fingerprint:  fp,
					PublicKeyB64: pubB64,
				}, opts.ClientIP); err != nil {
					hostKeyErr = err
					return err
				}
				return nil
			}

			hkErr := &HostKeyUntrustedError{
				Reason:               "unknown",
				Address:              targetAddr,
				ServerName:           srv.Name,
				KeyType:              key.Type(),
				PresentedFingerprint: fp,
				PresentedPublicKey:   pubB64,
			}
			hostKeyErr = hkErr
			return hkErr
		}

		cfg := &ssh.ClientConfig{
			User:            srv.Username,
			Auth:            authMethods,
			HostKeyCallback: hostKeyCallback,
			Timeout:         timeout,
		}
		return cfg, &capturedFingerprint, &hostKeyErr
	}

	dialDirect := func(timeout time.Duration, fallbackUsed bool, skippedJumps []string, hasAlt bool) (*ManagedSSHClient, error) {
		sshCfg, capturedFP, hostKeyErr := buildTargetSSHConfig(timeout)
		rawConn, err := m.openRawTCP(targetAddr, timeout)
		if err != nil {
			return nil, fmt.Errorf("无法连接到主机 %s: %w", targetAddr, err)
		}
		_ = rawConn.SetDeadline(time.Now().Add(timeout))
		c, chans, reqs, err := ssh.NewClientConn(rawConn, targetAddr, sshCfg)
		if err != nil {
			_ = rawConn.Close()
			if *hostKeyErr != nil {
				return nil, *hostKeyErr
			}
			return nil, fmt.Errorf("SSH 握手或认证失败 (%s): %w", targetAddr, err)
		}
		_ = rawConn.SetDeadline(time.Time{})
		route := DialRouteInfo{
			Direct:       true,
			FallbackUsed: fallbackUsed,
			SkippedJumps: slices.Clone(skippedJumps),
			Label:        formatDialRouteLabel(true, nil, fallbackUsed),
		}
		return &ManagedSSHClient{
			Client:             ssh.NewClient(c, chans, reqs),
			Server:             srv,
			Fingerprint:        *capturedFP,
			Route:              route,
			HasAlternateRoutes: hasAlt,
		}, nil
	}

	jumpIDs := srv.EffectiveJumpServerIDs()

	// Pure direct connection when no jump hosts are configured
	if len(jumpIDs) == 0 {
		timeout := opts.Timeout
		if timeout <= 0 {
			timeout = defaultDialTimeout
		}
		return dialDirect(timeout, false, nil, false)
	}

	// Build candidate list in configured priority order (+ optional direct fallback at tail).
	totalConfiguredRoutes := len(jumpIDs)
	if srv.JumpFallbackDirect {
		totalConfiguredRoutes++
	}
	hasAltRoutes := totalConfiguredRoutes > 1
	progressFn := opts.OnProgress
	if depth > 0 || !hasAltRoutes {
		progressFn = nil
	}

	now := time.Now()
	activeCandidates := make([]dialCandidate, 0, totalConfiguredRoutes)
	cooledCandidates := make([]dialCandidate, 0, len(jumpIDs))
	skippedNames := make([]string, 0, len(jumpIDs))

	for i, jid := range jumpIDs {
		jName := jid
		if jSrv, jErr := m.store.GetServerSecret(jid); jErr == nil && jSrv != nil && jSrv.Name != "" {
			jName = jSrv.Name
		}
		inCD, rem := m.isJumpInCooldown(jid, srv.ID, now)
		cand := dialCandidate{
			jumpID:      jid,
			jumpName:    jName,
			isPrimary:   i == 0,
			inCooldown:  inCD,
			cooldownRem: rem,
		}
		if hasAltRoutes && inCD {
			cooledCandidates = append(cooledCandidates, cand)
			skippedNames = append(skippedNames, jName)
			emitDialProgress(progressFn, "skipped", fmt.Sprintf("跳板机 [%s] 处于故障冷却期（剩余 %ds），自动跳过", jName, max(1, int(rem.Seconds()))))
		} else {
			activeCandidates = append(activeCandidates, cand)
		}
	}
	if srv.JumpFallbackDirect {
		activeCandidates = append(activeCandidates, dialCandidate{
			isDirect:  true,
			jumpName:  "直连",
			isPrimary: false,
		})
	}

	// Try non-cooled candidates first; if all of them fail, force-probe cooled-down jumps in priority order as a safety net.
	orderedAttempts := append(activeCandidates, cooledCandidates...)

	hasExplicitBudget := opts.Timeout > 0
	var overallDeadline time.Time
	if hasExplicitBudget {
		overallDeadline = time.Now().Add(opts.Timeout)
	}
	fallbackHopCap := m.getFallbackHopTimeout()

	computeHopTimeout := func(remainingCount int) time.Duration {
		if !hasAltRoutes {
			if hasExplicitBudget {
				rem := time.Until(overallDeadline)
				if rem <= 0 {
					return 0
				}
				return rem
			}
			return defaultDialTimeout
		}
		if !hasExplicitBudget {
			return fallbackHopCap
		}
		rem := time.Until(overallDeadline)
		if rem <= 0 {
			return 0
		}
		if remainingCount <= 1 {
			if rem > fallbackHopCap {
				return fallbackHopCap
			}
			return rem
		}
		fair := rem / time.Duration(remainingCount)
		if fair < minFallbackHopTimeout {
			fair = min(minFallbackHopTimeout, rem)
		}
		if fair > fallbackHopCap {
			fair = fallbackHopCap
		}
		return fair
	}

	var attemptErrors []string
	var lastSingleErr error

	for idx, cand := range orderedAttempts {
		remainingCount := len(orderedAttempts) - idx
		hopTimeout := computeHopTimeout(remainingCount)
		if hopTimeout <= 0 {
			attemptErrors = append(attemptErrors, fmt.Sprintf("%s: 连接总超时预算已耗尽", cand.jumpName))
			break
		}

		isFallback := !cand.isPrimary || len(skippedNames) > 0 || idx > 0
		hasMore := idx < len(orderedAttempts)-1

		if cand.isDirect {
			emitDialProgress(progressFn, "trying", "所有优先跳板均不可用，正在尝试退避至直连...")
			client, dErr := dialDirect(hopTimeout, true, skippedNames, hasAltRoutes)
			if dErr == nil {
				emitDialProgress(progressFn, "connected", fmt.Sprintf("已通过 [%s] 建立 SSH 连接", client.Route.Label))
				return client, nil
			}
			// Target HostKey error or explicit Target auth error: abort immediately
			var hkErr *HostKeyUntrustedError
			if errors.As(dErr, &hkErr) {
				return nil, hkErr
			}
			if isSSHAuthError(dErr) {
				return nil, dErr
			}
			attemptErrors = append(attemptErrors, fmt.Sprintf("直连: %v", dErr))
			lastSingleErr = dErr
			if hasMore {
				emitDialProgress(progressFn, "failed", fmt.Sprintf("直连失败 (%v)，继续重探冷却中的跳板机...", dErr))
			}
			continue
		}

		if cand.inCooldown {
			emitDialProgress(progressFn, "trying", fmt.Sprintf("所有优先链路均失败，正在强制重探冷却中的跳板机 [%s]...", cand.jumpName))
		} else {
			emitDialProgress(progressFn, "trying", fmt.Sprintf("正在尝试经由跳板机 [%s] 建立隧道...", cand.jumpName))
		}

		client, kind, jErr := m.dialViaSingleJump(srv, targetAddr, cand.jumpID, opts, branchVisited, depth, hopTimeout, buildTargetSSHConfig, isFallback, skippedNames, hasAltRoutes)
		if jErr == nil {
			m.clearJumpCooldown(cand.jumpID, srv.ID)
			emitDialProgress(progressFn, "connected", fmt.Sprintf("已通过 [%s] 建立 SSH 连接", client.Route.Label))
			return client, nil
		}

		// Target HostKey error -> always abort immediately and bubble up HostKeyUntrustedError
		if kind == jumpErrTargetHostKey {
			return nil, jErr
		}
		// Target explicit SSH auth error -> fail fast, no pointless retry across other jump hosts
		if kind == jumpErrTargetAuth {
			return nil, jErr
		}
		// Preserve exact single-jump HostKeyUntrustedError popup behavior when no fallback alternatives exist
		if !hasAltRoutes {
			var hkErr *HostKeyUntrustedError
			if errors.As(jErr, &hkErr) {
				return nil, hkErr
			}
		}

		// Record failure into short-lived in-memory cooldown
		if kind == jumpErrJumpDial {
			m.MarkJumpNodeFailed(cand.jumpID)
		} else {
			m.MarkJumpEdgeFailed(cand.jumpID, srv.ID)
		}

		if !slices.Contains(skippedNames, cand.jumpName) {
			skippedNames = append(skippedNames, cand.jumpName)
		}
		attemptErrors = append(attemptErrors, fmt.Sprintf("跳板[%s]: %v", cand.jumpName, jErr))
		lastSingleErr = jErr

		if hasMore {
			emitDialProgress(progressFn, "failed", fmt.Sprintf("跳板机 [%s] 不可用 (%v)，自动退避至下一链路...", cand.jumpName, jErr))
		}
	}

	if !hasAltRoutes && lastSingleErr != nil {
		return nil, lastSingleErr
	}
	return nil, fmt.Errorf("所有 SSH 跳板链路均连接失败（已尝试 %d 条链路）：%s", len(attemptErrors), strings.Join(attemptErrors, "；"))
}

type jumpErrorKind int

const (
	jumpErrNone jumpErrorKind = iota
	jumpErrJumpDial
	jumpErrForward
	jumpErrTargetNetwork
	jumpErrTargetHostKey
	jumpErrTargetAuth
)

func (m *Manager) dialViaSingleJump(
	srv *vault.ServerConfig,
	targetAddr string,
	jumpID string,
	opts DialOptions,
	branchVisited map[string]bool,
	depth int,
	hopTimeout time.Duration,
	buildTargetSSHConfig func(timeout time.Duration) (*ssh.ClientConfig, *string, *error),
	fallbackUsed bool,
	skippedJumps []string,
	hasAltRoutes bool,
) (*ManagedSSHClient, jumpErrorKind, error) {
	attemptDeadline := time.Now().Add(hopTimeout)

	jumpOpts := DialOptions{
		ClientIP: opts.ClientIP,
		Timeout:  hopTimeout,
	}
	jumpClient, err := m.dialChain(jumpID, jumpOpts, branchVisited, depth+1)
	if err != nil {
		return nil, jumpErrJumpDial, fmt.Errorf("连接跳板机失败: %w", err)
	}

	rem := time.Until(attemptDeadline)
	if rem <= 0 {
		_ = jumpClient.Close()
		return nil, jumpErrForward, fmt.Errorf("通过跳板机转发至 %s 超时: %w", targetAddr, context.DeadlineExceeded)
	}

	fwdCtx, fwdCancel := context.WithTimeout(context.Background(), rem)
	tunneledConn, err := jumpClient.DialContext(fwdCtx, "tcp", targetAddr)
	fwdCancel()
	if err != nil {
		_ = jumpClient.Close()
		return nil, jumpErrForward, fmt.Errorf("通过跳板机转发至 %s 失败: %w", targetAddr, err)
	}

	rem = time.Until(attemptDeadline)
	if rem <= 0 {
		_ = tunneledConn.Close()
		_ = jumpClient.Close()
		return nil, jumpErrTargetNetwork, fmt.Errorf("通过跳板机进行 SSH 握手超时 (%s): %w", targetAddr, context.DeadlineExceeded)
	}

	sshCfg, capturedFP, hostKeyErr := buildTargetSSHConfig(rem)

	// ssh.Channel ignores SetDeadline; enforce strict handshake timeout via mutex-guarded timer.
	var hsMu sync.Mutex
	hsFinished := false
	timedOut := false
	hsTimer := time.AfterFunc(rem, func() {
		hsMu.Lock()
		if !hsFinished {
			timedOut = true
			_ = tunneledConn.Close()
		}
		hsMu.Unlock()
	})
	c, chans, reqs, err := ssh.NewClientConn(tunneledConn, targetAddr, sshCfg)
	hsTimer.Stop()
	hsMu.Lock()
	hsFinished = true
	wasTimedOut := timedOut
	hsMu.Unlock()
	if wasTimedOut && err == nil {
		_ = c.Close()
		err = context.DeadlineExceeded
	}
	if err != nil {
		_ = tunneledConn.Close()
		_ = jumpClient.Close()
		if *hostKeyErr != nil {
			return nil, jumpErrTargetHostKey, *hostKeyErr
		}
		if wasTimedOut {
			return nil, jumpErrTargetNetwork, fmt.Errorf("通过跳板机进行 SSH 握手超时 (%s): %w", targetAddr, context.DeadlineExceeded)
		}
		if isSSHAuthError(err) {
			return nil, jumpErrTargetAuth, fmt.Errorf("通过跳板机进行 SSH 认证失败 (%s): %w", targetAddr, err)
		}
		return nil, jumpErrTargetNetwork, fmt.Errorf("通过跳板机进行 SSH 握手失败 (%s): %w", targetAddr, err)
	}

	// Compose full traversal jump chain (outer -> immediate jump)
	chainIDs := append(slices.Clone(jumpClient.Route.JumpServerIDs), jumpClient.Server.ID)
	chainNames := append(slices.Clone(jumpClient.Route.JumpServerNames), jumpClient.Server.Name)
	combinedFallback := fallbackUsed || jumpClient.Route.FallbackUsed
	combinedSkipped := slices.Clone(skippedJumps)
	for _, sk := range jumpClient.Route.SkippedJumps {
		if !slices.Contains(combinedSkipped, sk) {
			combinedSkipped = append(combinedSkipped, sk)
		}
	}

	route := DialRouteInfo{
		Direct:          false,
		JumpServerIDs:   chainIDs,
		JumpServerNames: chainNames,
		FallbackUsed:    combinedFallback,
		SkippedJumps:    combinedSkipped,
		Label:           formatDialRouteLabel(false, chainNames, combinedFallback),
	}

	return &ManagedSSHClient{
		Client:             ssh.NewClient(c, chans, reqs),
		Server:             srv,
		Fingerprint:        *capturedFP,
		Route:              route,
		ImmediateJumpID:    jumpID,
		HasAlternateRoutes: hasAltRoutes,
		jumpClient:         jumpClient,
		closers:            []func() error{jumpClient.Close},
	}, jumpErrNone, nil
}

func (m *Manager) buildAuthMethods(srv *vault.ServerConfig) ([]ssh.AuthMethod, error) {
	switch srv.AuthType {
	case vault.AuthPassword:
		if srv.Password == "" {
			return nil, errors.New("该服务器未配置 SSH 登录密码")
		}
		return passwordAuthMethods(srv.Password), nil

	case vault.AuthPrivateKey:
		if strings.TrimSpace(srv.PrivateKey) == "" {
			return nil, errors.New("该服务器未配置 SSH 私钥")
		}
		signer, err := parsePrivateKeySigner(srv.PrivateKey, srv.Passphrase)
		if err != nil {
			return nil, err
		}
		return []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil

	case vault.AuthCredential:
		if srv.CredentialID == "" {
			return nil, errors.New("该服务器未绑定凭据库密钥")
		}
		cred, err := m.store.GetCredentialSecret(srv.CredentialID)
		if err != nil {
			return nil, fmt.Errorf("读取关联加密凭据失败: %w", err)
		}
		if cred.Kind == vault.AuthPassword {
			if cred.Password == "" {
				return nil, errors.New("关联凭据未设置密码")
			}
			return passwordAuthMethods(cred.Password), nil
		}
		signer, err := parsePrivateKeySigner(cred.PrivateKey, cred.Passphrase)
		if err != nil {
			return nil, err
		}
		return []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil

	default:
		return nil, fmt.Errorf("未知的 SSH 认证方式: %s", srv.AuthType)
	}
}

func passwordAuthMethods(secret string) []ssh.AuthMethod {
	return []ssh.AuthMethod{
		ssh.Password(secret),
		ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
			answers := make([]string, len(questions))
			for i := range questions {
				answers[i] = secret
			}
			return answers, nil
		}),
	}
}

func parsePrivateKeySigner(pemStr, passphrase string) (ssh.Signer, error) {
	pemBytes := []byte(NormalizeKeyText(pemStr) + "\n")
	defer vault.ZeroBytes(pemBytes)
	if passphrase != "" {
		passBytes := []byte(passphrase)
		defer vault.ZeroBytes(passBytes)
		signer, err := ssh.ParsePrivateKeyWithPassphrase(pemBytes, passBytes)
		if err != nil {
			return nil, fmt.Errorf("解析加密 SSH 私钥失败（请检查私钥格式或私钥口令）: %w", err)
		}
		return signer, nil
	}
	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		var passMissing *ssh.PassphraseMissingError
		if errors.As(err, &passMissing) {
			return nil, errors.New("该 SSH 私钥受口令保护，请提供私钥口令 (Passphrase)")
		}
		return nil, fmt.Errorf("解析 SSH 私钥失败: %w", err)
	}
	return signer, nil
}

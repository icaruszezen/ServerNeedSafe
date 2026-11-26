package monitor

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/sshmanager"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

type pooledServerConn struct {
	client     *sshmanager.ManagedSSHClient
	configHash string
	lastUsed   time.Time
	inUse      bool
	evicted    bool
}

// sshConnPool maintains persistent, config-fingerprinted SSH clients for periodic telemetry sweeps.
// It eliminates repetitive SSH handshakes and auth.log spam on target hosts while automatically
// evicting stale, broken, idle, or reconfigured connections.
type sshConnPool struct {
	sshMgr  *sshmanager.Manager
	mu      sync.Mutex
	entries map[string]*pooledServerConn
}

func newSSHConnPool(sshMgr *sshmanager.Manager) *sshConnPool {
	return &sshConnPool{
		sshMgr:  sshMgr,
		entries: make(map[string]*pooledServerConn),
	}
}

func serverConnFingerprint(srv vault.ServerConfig) string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%s|%d|%s|%s|%s|%s|%s|%s|%s|%v",
		srv.Host, srv.Port, srv.Username, srv.AuthType,
		srv.Password, srv.PrivateKey, srv.Passphrase, srv.CredentialID,
		strings.Join(srv.EffectiveJumpServerIDs(), ","), srv.JumpFallbackDirect,
	)
	return hex.EncodeToString(h.Sum(nil))
}

func probeKeepAliveRTT(client *sshmanager.ManagedSSHClient, timeout time.Duration) (int64, bool) {
	if client == nil || client.Client == nil {
		return 0, false
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	start := time.Now()
	resCh := make(chan error, 1)
	go func() {
		_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
		resCh <- err
	}()
	select {
	case err := <-resCh:
		if err != nil {
			return 0, false
		}
		return max(1, time.Since(start).Milliseconds()), true
	case <-time.After(timeout):
		return 0, false
	}
}

// Acquire returns a healthy ManagedSSHClient (reusing a pooled client when enabled & alive),
// its measured latency (keepalive RTT when reused, dial handshake when fresh), whether it was reused,
// and a release callback(broken bool) that must always be called when the sweep finishes.
func (p *sshConnPool) Acquire(
	srv vault.ServerConfig,
	dialTimeout time.Duration,
	trustFingerprint string,
	clientIP string,
	usePool bool,
) (client *sshmanager.ManagedSSHClient, latencyMs int64, reused bool, release func(broken bool), err error) {
	if !usePool || trustFingerprint != "" {
		// Explicit host-key trust or pooling disabled -> evict cached conn if any & dial statelessly
		if trustFingerprint != "" {
			p.Evict(srv.ID)
		}
		dialStart := time.Now()
		c, dErr := p.sshMgr.Dial(srv.ID, sshmanager.DialOptions{
			TrustFingerprint: trustFingerprint,
			ClientIP:         clientIP,
			Timeout:          dialTimeout,
			ReuseJumpPool:    usePool,
		})
		if dErr != nil {
			return nil, 0, false, func(bool) {}, dErr
		}
		return c, max(1, time.Since(dialStart).Milliseconds()), false, func(bool) {
			_ = c.Close()
		}, nil
	}

	cfgHash := serverConnFingerprint(srv)
	var candidate *pooledServerConn
	var staleToClose *sshmanager.ManagedSSHClient

	p.mu.Lock()
	if ent, ok := p.entries[srv.ID]; ok {
		if ent.configHash != cfgHash {
			delete(p.entries, srv.ID)
			ent.evicted = true
			if !ent.inUse {
				staleToClose = ent.client
			}
		} else if !ent.inUse {
			ent.inUse = true
			ent.lastUsed = time.Now()
			candidate = ent
		}
	}
	p.mu.Unlock()

	if staleToClose != nil {
		_ = staleToClose.Close()
	}

	makeRelease := func(ent *pooledServerConn) func(broken bool) {
		var once sync.Once
		return func(broken bool) {
			var toClose *sshmanager.ManagedSSHClient
			once.Do(func() {
				p.mu.Lock()
				ent.inUse = false
				ent.lastUsed = time.Now()
				if broken || ent.evicted {
					if cur, ok := p.entries[srv.ID]; ok && cur == ent {
						delete(p.entries, srv.ID)
					}
					ent.evicted = true
					toClose = ent.client
				}
				p.mu.Unlock()
			})
			if toClose != nil {
				_ = toClose.Close()
			}
		}
	}

	// Verify pooled candidate with fast keepalive RTT before handing it out
	if candidate != nil {
		kaTimeout := min(3*time.Second, max(800*time.Millisecond, dialTimeout/2))
		if rtt, alive := probeKeepAliveRTT(candidate.client, kaTimeout); alive {
			return candidate.client, rtt, true, makeRelease(candidate), nil
		}
		// Stale pooled connection -> evict silently and dial fresh
		makeRelease(candidate)(true)
	}

	dialStart := time.Now()
	fresh, dErr := p.sshMgr.Dial(srv.ID, sshmanager.DialOptions{
		ClientIP:      clientIP,
		Timeout:       dialTimeout,
		ReuseJumpPool: true,
	})
	if dErr != nil {
		return nil, 0, false, func(bool) {}, dErr
	}
	hsMs := max(1, time.Since(dialStart).Milliseconds())

	newEnt := &pooledServerConn{
		client:     fresh,
		configHash: cfgHash,
		lastUsed:   time.Now(),
		inUse:      true,
	}

	var replaced *sshmanager.ManagedSSHClient
	p.mu.Lock()
	if old, ok := p.entries[srv.ID]; ok {
		old.evicted = true
		if !old.inUse {
			replaced = old.client
		}
	}
	p.entries[srv.ID] = newEnt
	p.mu.Unlock()

	if replaced != nil {
		_ = replaced.Close()
	}

	return fresh, hsMs, false, makeRelease(newEnt), nil
}

// Evict removes and closes (when idle) any cached connection for serverID, plus any shared jump entry.
func (p *sshConnPool) Evict(serverID string) {
	if serverID == "" {
		return
	}
	var toClose *sshmanager.ManagedSSHClient
	p.mu.Lock()
	if ent, ok := p.entries[serverID]; ok {
		delete(p.entries, serverID)
		ent.evicted = true
		if !ent.inUse {
			toClose = ent.client
		}
	}
	p.mu.Unlock()
	if toClose != nil {
		_ = toClose.Close()
	}
	if p.sshMgr != nil {
		p.sshMgr.EvictPooledJump(serverID)
	}
}

// EvictAll closes all cached target and jump connections (e.g. on engine close or pool disable).
func (p *sshConnPool) EvictAll() {
	var toClose []*sshmanager.ManagedSSHClient
	p.mu.Lock()
	for id, ent := range p.entries {
		delete(p.entries, id)
		ent.evicted = true
		if !ent.inUse {
			toClose = append(toClose, ent.client)
		}
	}
	p.mu.Unlock()
	for _, c := range toClose {
		_ = c.Close()
	}
	if p.sshMgr != nil {
		p.sshMgr.ClosePooledJumps()
	}
}

// CleanupIdle evicts connections that have been idle longer than maxIdle.
func (p *sshConnPool) CleanupIdle(maxIdle time.Duration) {
	if maxIdle <= 0 {
		maxIdle = 5 * time.Minute
	}
	cutoff := time.Now().Add(-maxIdle)
	var toClose []*sshmanager.ManagedSSHClient
	p.mu.Lock()
	for id, ent := range p.entries {
		if !ent.inUse && ent.lastUsed.Before(cutoff) {
			delete(p.entries, id)
			ent.evicted = true
			toClose = append(toClose, ent.client)
		}
	}
	p.mu.Unlock()
	for _, c := range toClose {
		_ = c.Close()
	}
	if p.sshMgr != nil {
		p.sshMgr.CleanupIdleJumps(maxIdle)
	}
}

// Count returns the number of currently pooled target SSH connections.
func (p *sshConnPool) Count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.entries)
}

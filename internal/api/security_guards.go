package api

import (
	"errors"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

const (
	// maxConcurrentPasswordKDF bounds how many memory-hard Argon2id password derivations the daemon runs
	// at once for UNAUTHENTICATED endpoints (login / setup / backup restore). Since v2.1.0 password
	// verification happens server-side (64 MiB+ per attempt), so without a bound a burst of parallel
	// login requests could exhaust RAM before the brute-force counter ever records a failure.
	maxConcurrentPasswordKDF = 2
	// passwordKDFQueueWait is how long a request waits for a free Argon2id slot before getting HTTP 429.
	passwordKDFQueueWait = 10 * time.Second
)

// sessionGoneTerminalMsg is sent to an interactive SSH terminal before it is closed because the admin
// session that opened it was revoked or expired.
const sessionGoneTerminalMsg = "管理会话已失效（已锁定、注销或超时），SSH 终端已安全断开，请重新登录"

// acquirePasswordKDFSlot reserves one Argon2id slot. When the daemon is saturated it writes HTTP 429
// and returns ok=false. Callers MUST invoke release() when ok=true.
func (s *Server) acquirePasswordKDFSlot(w http.ResponseWriter, r *http.Request) (release func(), ok bool) {
	timer := time.NewTimer(passwordKDFQueueWait)
	defer timer.Stop()
	select {
	case s.kdfSlots <- struct{}{}:
		return func() { <-s.kdfSlots }, true
	case <-r.Context().Done():
		return nil, false
	case <-timer.C:
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error":           "服务端密码校验队列繁忙（Argon2id 内存硬派生并发已达上限），请稍后重试",
			"code":            "KDF_BUSY",
			"retry_after_sec": 3,
		})
		return nil, false
	}
}

// isCookieSessionRequestAllowed decides whether the HttpOnly admin session COOKIE may authenticate r.
//
// SameSite=Strict only blocks cross-SITE requests; it does NOT stop cross-ORIGIN requests from the same
// site (sibling sub-domains, other ports on the same host, other apps behind the same reverse proxy).
// The API also reflects arbitrary Origins for bearer-token based remote vault sync, and JSON bodies are
// decoded without Content-Type checks, so a same-site attacker page could otherwise fire "simple"
// cross-origin POSTs (lock, settings, deletes, batch SSH exec ...) that ride on the admin cookie.
// Cookie authentication is therefore only honoured for same-origin requests; bearer tokens are unaffected.
func isCookieSessionRequestAllowed(r *http.Request) bool {
	switch strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site"))) {
	case "", "same-origin", "none":
	default:
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		if origin == "null" || !isSameOriginRequest(r, origin) {
			return false
		}
	}
	return true
}

// isTrustedProxyPeer reports whether the direct TCP peer is a local reverse proxy (loopback or a
// private/Docker bridge address), the only case in which X-Real-IP / X-Forwarded-For may be trusted.
func isTrustedProxyPeer(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate()
}

// persistAutoUnlockKey re-wraps the mounted DEK into .vault.key and LOGS failures instead of silently
// discarding them (a stale seal otherwise only surfaces as a mysterious "migration pending" after restart).
func (s *Server) persistAutoUnlockKey(trigger string) {
	if s.cfg.KeyMgr == nil || s.cfg.Store == nil {
		return
	}
	if err := s.cfg.KeyMgr.SaveFromStore(s.cfg.Store); err != nil {
		if errors.Is(err, vault.ErrSealDowngrade) || errors.Is(err, vault.ErrWeakMasterKey) {
			log.Printf("[ServerNeedSafe] 安全警告（%s）：未更新自动挂载密钥 .vault.key：%v", trigger, err)
			return
		}
		log.Printf("[ServerNeedSafe] 写入自动挂载密钥 .vault.key 失败（%s）：%v", trigger, err)
	}
}

// autoUnlockMode reports how .vault.key is protected ("env" = SNS_MASTER_KEY, "file" = key stored in the
// data directory, "" = no seal), so the security panel can surface the weaker file mode.
func (s *Server) autoUnlockMode() string {
	if s.cfg.KeyMgr == nil {
		return ""
	}
	return s.cfg.KeyMgr.SealMode()
}

// dropStaleAutoUnlockKey deletes .vault.key when it no longer belongs to the vault currently on disk
// (or unconditionally when force=true, e.g. after a remote DEK rotation), so an obsolete wrapped DEK
// never lingers in the data directory.
func (s *Server) dropStaleAutoUnlockKey(trigger string, force bool) {
	if s.cfg.KeyMgr == nil || !s.cfg.KeyMgr.HasLocalKey() {
		return
	}
	if !force {
		params, err := s.cfg.BlindStore.PublicChallengeParams()
		if err != nil || params.VaultID == s.cfg.KeyMgr.SealVaultID() {
			return
		}
	}
	if err := s.cfg.KeyMgr.Remove(); err != nil {
		log.Printf("[ServerNeedSafe] 清理过期自动挂载密钥 .vault.key 失败（%s）：%v", trigger, err)
		return
	}
	log.Printf("[ServerNeedSafe] 已清理与当前保险库不匹配的过期自动挂载密钥 .vault.key（%s）", trigger)
}

// reloadDaemonAfterRemoteWrite re-synchronises the in-memory 7x24 daemon after vault.sns was replaced
// by a remote zero-knowledge client (signed PUT / import). Previously only TryAutoUnlock was attempted
// and its failure was ignored, so a daemon without a usable .vault.key kept serving (and later
// re-persisting!) its STALE in-memory state, silently discarding the remote write on the next save.
//
// Order: (1) same vault + same DEK → reload newer revision with the in-memory DEK; (2) otherwise try
// the .vault.key seal; (3) otherwise lock the daemon (until the next password login) and delete a seal
// that belongs to a different vault.
func (s *Server) reloadDaemonAfterRemoteWrite(trigger, clientIP string) {
	if s.cfg.Store == nil {
		return
	}
	wake := func() {
		if s.cfg.Monitor != nil {
			s.cfg.Monitor.Wake()
		}
		if s.cfg.AI != nil {
			s.cfg.AI.NotifyPatrolConfigUpdated()
		}
	}

	if s.isDaemonUnlocked() {
		refreshed, err := s.cfg.Store.RefreshFromBackend()
		if err == nil {
			if refreshed {
				wake()
			}
			return
		}
		log.Printf("[ServerNeedSafe] %s后无法用内存 DEK 重新载入保险库，尝试 .vault.key 重新挂载：%v", trigger, err)
	}

	if s.cfg.KeyMgr != nil {
		unlocked, mig, err := s.cfg.KeyMgr.TryAutoUnlock(s.cfg.Store, s.cfg.BlindStore)
		if err != nil {
			log.Printf("[ServerNeedSafe] %s后 .vault.key 自动挂载失败：%v", trigger, err)
		}
		s.setMigrationPending(mig)
		if unlocked {
			wake()
			return
		}
	}

	if s.isDaemonUnlocked() {
		s.cfg.Store.Lock(trigger+"后内存状态已过期，等待管理员重新登录挂载", clientIP)
	}
	s.setMigrationPending(true)
	s.dropStaleAutoUnlockKey(trigger, false)
}

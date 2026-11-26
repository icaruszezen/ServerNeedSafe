package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

const DefaultSessionTTL = 7 * 24 * time.Hour

var (
	ErrUnauthorized = errors.New("未登录管理后台或会话已过期")
	ErrRateLimited  = errors.New("密码验证失败次数过多，请稍后再试")
)

type Session struct {
	Token       string
	AuthVersion uint64
	CreatedAt   time.Time
	LastSeenAt  time.Time
	ClientIP    string
	UserAgent   string
}

// Manager manages authenticated Web sessions bound to AuthVersion, brute-force rate limiting,
// and local Windows desktop instance loopback isolation.
type Manager struct {
	mu              sync.Mutex
	sessions        map[string]*Session
	sessionTTL      time.Duration
	failedCount     int
	lockedUntil     time.Time
	desktopBootCode string
	desktopCookie   string
}

func NewManager(sessionTTL time.Duration, enableDesktopGuard bool) (*Manager, error) {
	if sessionTTL <= 0 {
		sessionTTL = DefaultSessionTTL
	}
	m := &Manager{
		sessions:   make(map[string]*Session),
		sessionTTL: sessionTTL,
	}
	if enableDesktopGuard {
		boot, err := randomHex(32)
		if err != nil {
			return nil, err
		}
		cookieSecret, err := randomHex(32)
		if err != nil {
			return nil, err
		}
		m.desktopBootCode = boot
		m.desktopCookie = cookieSecret
	}
	return m, nil
}

func randomHex(numBytes int) (string, error) {
	b := make([]byte, numBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// DesktopGuardEnabled returns true when running as the pure-local desktop application.
func (m *Manager) DesktopGuardEnabled() bool {
	return m.desktopCookie != ""
}

func (m *Manager) DesktopBootCode() string {
	return m.desktopBootCode
}

func (m *Manager) VerifyDesktopBootCode(code string) (cookieVal string, ok bool) {
	if m.desktopBootCode == "" {
		return "", false
	}
	if subtle.ConstantTimeCompare([]byte(code), []byte(m.desktopBootCode)) == 1 {
		return m.desktopCookie, true
	}
	return "", false
}

func (m *Manager) VerifyDesktopCookie(val string) bool {
	if m.desktopCookie == "" {
		return true
	}
	return subtle.ConstantTimeCompare([]byte(val), []byte(m.desktopCookie)) == 1
}

// CheckRateLimit verifies whether login attempts are currently throttled.
func (m *Manager) CheckRateLimit() (retryAfterSec int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	if now.Before(m.lockedUntil) {
		rem := int(m.lockedUntil.Sub(now).Seconds()) + 1
		return rem, fmt.Errorf("%w（剩余 %d 秒）", ErrRateLimited, rem)
	}
	return 0, nil
}

// RecordAuthFailure increments brute-force counter and applies exponential lockout after 5 failures.
func (m *Manager) RecordAuthFailure() (failedCount int, lockedForSec int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failedCount++
	if m.failedCount >= 5 {
		shift := m.failedCount - 5
		if shift > 4 {
			shift = 4
		}
		dur := time.Duration(15*(1<<shift)) * time.Second
		if dur > 5*time.Minute {
			dur = 5 * time.Minute
		}
		m.lockedUntil = time.Now().Add(dur)
		return m.failedCount, int(dur.Seconds())
	}
	return m.failedCount, 0
}

// ResetAuthFailures clears brute-force counters after a successful login.
func (m *Manager) ResetAuthFailures() {
	m.mu.Lock()
	m.failedCount = 0
	m.lockedUntil = time.Time{}
	m.mu.Unlock()
}

// CreateSession issues a new cryptographically random 256-bit session token bound to authVersion.
func (m *Manager) CreateSession(authVersion uint64, clientIP, userAgent string) (*Session, error) {
	tok, err := randomHex(32)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	sess := &Session{
		Token:       tok,
		AuthVersion: authVersion,
		CreatedAt:   now,
		LastSeenAt:  now,
		ClientIP:    clientIP,
		UserAgent:   userAgent,
	}
	m.mu.Lock()
	m.pruneExpiredLocked(now)
	m.sessions[tok] = sess
	m.mu.Unlock()
	return sess, nil
}

// SessionTTL returns the configured maximum lifetime of a single authenticated session.
func (m *Manager) SessionTTL() time.Duration {
	return m.sessionTTL
}

// ValidateSession verifies a bearer/cookie token against max sessionTTL and expectedAuthVersion.
func (m *Manager) ValidateSession(token string, expectedAuthVersion uint64) (*Session, error) {
	return m.ValidateSessionWithIdle(token, expectedAuthVersion, 0, true)
}

// ValidateSessionWithIdle enforces BOTH maximum session lifetime (CreatedAt + sessionTTL, default 7d)
// AND optional idle inactivity timeout (LastSeenAt + idleTimeout, default 0/disabled).
// Web session expiration ONLY invalidates the web session token; background 7x24 tasks stay running.
func (m *Manager) ValidateSessionWithIdle(token string, expectedAuthVersion uint64, idleTimeout time.Duration, touch bool) (*Session, error) {
	if token == "" {
		return nil, ErrUnauthorized
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().UTC()
	sess, ok := m.sessions[token]
	if !ok {
		return nil, ErrUnauthorized
	}
	if now.Sub(sess.CreatedAt) > m.sessionTTL {
		delete(m.sessions, token)
		return nil, ErrUnauthorized
	}
	if idleTimeout > 0 && now.Sub(sess.LastSeenAt) > idleTimeout {
		delete(m.sessions, token)
		return nil, ErrUnauthorized
	}
	if expectedAuthVersion > 0 && sess.AuthVersion != expectedAuthVersion {
		delete(m.sessions, token)
		return nil, ErrUnauthorized
	}
	if touch {
		sess.LastSeenAt = now
	}
	cp := *sess
	return &cp, nil
}

// RevokeSession removes a single session token.
func (m *Manager) RevokeSession(token string) {
	m.mu.Lock()
	delete(m.sessions, token)
	m.mu.Unlock()
}

// RevokeAll invalidates every active Web session (used when locking console or changing password).
func (m *Manager) RevokeAll() {
	m.mu.Lock()
	clear(m.sessions)
	m.mu.Unlock()
}

// ActiveSessionCount returns the number of active non-expired sessions.
func (m *Manager) ActiveSessionCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneExpiredLocked(time.Now().UTC())
	return len(m.sessions)
}

func (m *Manager) pruneExpiredLocked(now time.Time) {
	for k, s := range m.sessions {
		if now.Sub(s.CreatedAt) > m.sessionTTL {
			delete(m.sessions, k)
		}
	}
}

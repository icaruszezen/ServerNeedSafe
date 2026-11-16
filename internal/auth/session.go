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

var (
	ErrUnauthorized = errors.New("未通过管理员密码验证或会话已过期")
	ErrRateLimited  = errors.New("密码连续错误次数过多，请稍后再试")
)

type Session struct {
	Token        string
	CreatedAt    time.Time
	LastSeenAt   time.Time
	ClientIP     string
	UserAgent    string
}

type oneTimeTicket struct {
	Purpose   string
	ServerID  string
	Path      string
	ExpiresAt time.Time
}

// Manager manages authenticated in-memory sessions, one-time WS/download tickets,
// brute-force password rate limiting, and optional local desktop instance protection.
type Manager struct {
	mu              sync.Mutex
	sessions        map[string]*Session
	tickets         map[string]*oneTimeTicket
	sessionTTL      time.Duration
	failedCount     int
	lockedUntil     time.Time
	desktopBootCode string
	desktopCookie   string
}

func NewManager(sessionTTL time.Duration, enableDesktopGuard bool) (*Manager, error) {
	if sessionTTL <= 0 {
		sessionTTL = 8 * time.Hour
	}
	m := &Manager{
		sessions:   make(map[string]*Session),
		tickets:    make(map[string]*oneTimeTicket),
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

// CheckRateLimit verifies whether password authentication is currently throttled.
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

// ResetAuthFailures clears brute-force counters after valid password verification.
func (m *Manager) ResetAuthFailures() {
	m.mu.Lock()
	m.failedCount = 0
	m.lockedUntil = time.Time{}
	m.mu.Unlock()
}

// CreateSession issues a new cryptographically random 256-bit bearer token.
func (m *Manager) CreateSession(clientIP, userAgent string) (*Session, error) {
	tok, err := randomHex(32)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	sess := &Session{
		Token:      tok,
		CreatedAt:  now,
		LastSeenAt: now,
		ClientIP:   clientIP,
		UserAgent:  userAgent,
	}
	m.mu.Lock()
	m.pruneExpiredLocked(now)
	m.sessions[tok] = sess
	m.mu.Unlock()
	return sess, nil
}

// ValidateSession verifies a bearer token and refreshes its LastSeenAt timestamp.
func (m *Manager) ValidateSession(token string) (*Session, error) {
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
	if now.Sub(sess.LastSeenAt) > m.sessionTTL {
		delete(m.sessions, token)
		return nil, ErrUnauthorized
	}
	sess.LastSeenAt = now
	cp := *sess
	return &cp, nil
}

// RevokeSession removes a single session token.
func (m *Manager) RevokeSession(token string) {
	m.mu.Lock()
	delete(m.sessions, token)
	m.mu.Unlock()
}

// RevokeAll invalidates every active session and ticket (used when locking vault or rotating password).
func (m *Manager) RevokeAll() {
	m.mu.Lock()
	clear(m.sessions)
	clear(m.tickets)
	m.mu.Unlock()
}

// ActiveSessionCount returns the number of active non-expired sessions.
func (m *Manager) ActiveSessionCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneExpiredLocked(time.Now().UTC())
	return len(m.sessions)
}

// IssueTicket creates a single-use 60-second ticket for WebSocket upgrade or SFTP file stream download.
func (m *Manager) IssueTicket(purpose, serverID, path string) (string, error) {
	code, err := randomHex(24)
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	m.pruneExpiredLocked(time.Now().UTC())
	m.tickets[code] = &oneTimeTicket{
		Purpose:   purpose,
		ServerID:  serverID,
		Path:      path,
		ExpiresAt: time.Now().UTC().Add(60 * time.Second),
	}
	m.mu.Unlock()
	return code, nil
}

// ConsumeTicket atomically validates and deletes a single-use ticket.
func (m *Manager) ConsumeTicket(code, expectedPurpose, expectedServerID string) (path string, err error) {
	if code == "" {
		return "", ErrUnauthorized
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	t, ok := m.tickets[code]
	delete(m.tickets, code)
	if !ok {
		return "", ErrUnauthorized
	}
	if time.Now().UTC().After(t.ExpiresAt) {
		return "", ErrUnauthorized
	}
	if t.Purpose != expectedPurpose || (expectedServerID != "" && t.ServerID != expectedServerID) {
		return "", ErrUnauthorized
	}
	return t.Path, nil
}

func (m *Manager) pruneExpiredLocked(now time.Time) {
	for k, s := range m.sessions {
		if now.Sub(s.LastSeenAt) > m.sessionTTL {
			delete(m.sessions, k)
		}
	}
	for k, t := range m.tickets {
		if now.After(t.ExpiresAt) {
			delete(m.tickets, k)
		}
	}
}

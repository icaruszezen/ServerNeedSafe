package auth

import (
	"errors"
	"testing"
	"time"
)

func TestSessionLifecycleRateLimitAndDesktopGuard(t *testing.T) {
	mgr, err := NewManager(2*time.Second, true)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if !mgr.DesktopGuardEnabled() {
		t.Fatalf("expected DesktopGuardEnabled")
	}

	cookieVal, ok := mgr.VerifyDesktopBootCode(mgr.DesktopBootCode())
	if !ok || !mgr.VerifyDesktopCookie(cookieVal) {
		t.Fatalf("desktop guard verification failed")
	}
	if mgr.VerifyDesktopCookie("forged-cookie") {
		t.Fatalf("expected forged desktop cookie to fail")
	}

	// Rate limit after 5 failures
	for i := 1; i <= 5; i++ {
		cnt, _ := mgr.RecordAuthFailure()
		if cnt != i {
			t.Fatalf("expected count %d, got %d", i, cnt)
		}
	}
	if retry, err := mgr.CheckRateLimit(); !errors.Is(err, ErrRateLimited) || retry <= 0 {
		t.Fatalf("expected ErrRateLimited, got retry=%d err=%v", retry, err)
	}
	mgr.ResetAuthFailures()
	if _, err := mgr.CheckRateLimit(); err != nil {
		t.Fatalf("expected rate limit cleared, got %v", err)
	}

	// Session bound to AuthVersion
	sess, err := mgr.CreateSession(1, "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if _, err := mgr.ValidateSession(sess.Token, 1); err != nil {
		t.Fatalf("ValidateSession: %v", err)
	}
	// Changing password increments AuthVersion -> old session must be rejected immediately!
	if _, err := mgr.ValidateSession(sess.Token, 2); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected incremented AuthVersion to invalidate session, got %v", err)
	}

	sess2, _ := mgr.CreateSession(2, "127.0.0.1", "TestAgent")
	mgr.RevokeAll()
	if _, err := mgr.ValidateSession(sess2.Token, 2); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected revoked session to fail, got %v", err)
	}

	// Idle timeout check
	sess3, err := mgr.CreateSession(2, "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("CreateSession sess3: %v", err)
	}
	time.Sleep(60 * time.Millisecond)
	if _, err := mgr.ValidateSessionWithIdle(sess3.Token, 2, 25*time.Millisecond, true); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected idle timeout to invalidate session, got %v", err)
	}

	// Default TTL when 0 passed should be 7 days (168h)
	defMgr, err := NewManager(0, false)
	if err != nil {
		t.Fatalf("NewManager default: %v", err)
	}
	if defMgr.SessionTTL() != DefaultSessionTTL {
		t.Fatalf("expected default TTL %v, got %v", DefaultSessionTTL, defMgr.SessionTTL())
	}
}

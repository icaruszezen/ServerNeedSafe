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

	// Session + One-time ticket
	sess, err := mgr.CreateSession("127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if _, err := mgr.ValidateSession(sess.Token); err != nil {
		t.Fatalf("ValidateSession: %v", err)
	}

	ticket, err := mgr.IssueTicket("ws_ssh", "srv-1", "")
	if err != nil {
		t.Fatalf("IssueTicket: %v", err)
	}
	if _, err := mgr.ConsumeTicket(ticket, "ws_ssh", "srv-1"); err != nil {
		t.Fatalf("ConsumeTicket first use: %v", err)
	}
	if _, err := mgr.ConsumeTicket(ticket, "ws_ssh", "srv-1"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected replay of one-time ticket to fail, got %v", err)
	}

	mgr.RevokeAll()
	if _, err := mgr.ValidateSession(sess.Token); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected revoked session to fail, got %v", err)
	}
}

package auth

import (
	"errors"
	"testing"
	"time"
)

func TestSessionLifecycleChallengeRateLimitAndDesktopGuard(t *testing.T) {
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

	// Single-use zero-knowledge challenge
	ch, err := mgr.IssueChallenge()
	if err != nil || len(ch.Nonce) != 64 {
		t.Fatalf("IssueChallenge failed: %+v, err=%v", ch, err)
	}
	nonce, err := mgr.ConsumeChallenge(ch.ID)
	if err != nil || nonce != ch.Nonce {
		t.Fatalf("ConsumeChallenge first use failed: nonce=%s err=%v", nonce, err)
	}
	if _, err := mgr.ConsumeChallenge(ch.ID); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected replay of challenge to fail, got %v", err)
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

	// Session bound to AuthPubSHA256 + Metadata-free One-time ticket
	pubFP := "abc123fingerprint"
	sess, err := mgr.CreateSession(pubFP, "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if _, err := mgr.ValidateSession(sess.Token, pubFP); err != nil {
		t.Fatalf("ValidateSession: %v", err)
	}
	// Rotating password changes AuthPubSHA256 -> old session must be rejected immediately!
	if _, err := mgr.ValidateSession(sess.Token, "rotated_fingerprint"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected rotated fingerprint to invalidate session, got %v", err)
	}

	sess2, _ := mgr.CreateSession(pubFP, "127.0.0.1", "TestAgent")
	ticket, err := mgr.IssueTicket("tcp_relay", pubFP)
	if err != nil {
		t.Fatalf("IssueTicket: %v", err)
	}
	if err := mgr.ConsumeTicket(ticket, "tcp_relay", pubFP); err != nil {
		t.Fatalf("ConsumeTicket first use: %v", err)
	}
	if err := mgr.ConsumeTicket(ticket, "tcp_relay", pubFP); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected replay of one-time ticket to fail, got %v", err)
	}

	mgr.RevokeAll()
	if _, err := mgr.ValidateSession(sess2.Token, pubFP); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected revoked session to fail, got %v", err)
	}

	// Idle timeout vs Max TTL check
	sess3, err := mgr.CreateSession(pubFP, "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("CreateSession sess3: %v", err)
	}
	time.Sleep(60 * time.Millisecond)
	if _, err := mgr.ValidateSessionWithIdle(sess3.Token, pubFP, 25*time.Millisecond, true); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected idle timeout to invalidate session, got %v", err)
	}
}


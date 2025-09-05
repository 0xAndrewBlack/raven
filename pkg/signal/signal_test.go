package signal

import "testing"

func TestSetGetAction(t *testing.T) {
	s := New()
	act := &SigAction{Handler: 0xDEADBEEF, Flags: SA_RESTART, Mask: 0xFF}
	old := s.SetAction(SIGINT, act)
	if old == nil {
		t.Fatal("expected old action")
	}
	if old.Handler != 0 {
		t.Fatalf("expected SIG_DFL for old handler, got 0x%x", old.Handler)
	}

	got := s.GetAction(SIGINT)
	if got.Handler != 0xDEADBEEF {
		t.Fatalf("expected 0xDEADBEEF, got 0x%x", got.Handler)
	}
}

func TestSigKillCannotBeCaught(t *testing.T) {
	s := New()
	act := &SigAction{Handler: 0x1234}
	old := s.SetAction(SIGKILL, act)
	if old != nil {
		t.Fatal("SIGKILL should not be catchable")
	}
}

func TestSetMask(t *testing.T) {
	s := New()
	// SIG_SETMASK
	old := s.SetMask(2, 0xFF)
	if old != 0 {
		t.Fatalf("expected old mask 0, got 0x%x", old)
	}
	// SIG_BLOCK more bits (0x200 = bit 9, which is SIGPWR area, not SIGKILL)
	old = s.SetMask(0, 0x200)
	if old != 0xFF {
		t.Fatalf("expected old mask 0xFF, got 0x%x", old)
	}
	// Now mask should be 0x2FF
	// SIG_UNBLOCK
	old = s.SetMask(1, 0x0F)
	if old != 0x2FF {
		t.Fatalf("expected old mask 0x2FF, got 0x%x", old)
	}
}

func TestRaisAndDequeue(t *testing.T) {
	s := New()
	s.Raise(SIGINT)
	s.Raise(SIGTERM)

	sig := s.DequeueSignal()
	if sig != SIGINT {
		t.Fatalf("expected SIGINT (2), got %d", sig)
	}
	sig = s.DequeueSignal()
	if sig != SIGTERM {
		t.Fatalf("expected SIGTERM (15), got %d", sig)
	}
	sig = s.DequeueSignal()
	if sig != 0 {
		t.Fatalf("expected 0 (no pending), got %d", sig)
	}
}

func TestBlockedSignalNotDequeued(t *testing.T) {
	s := New()
	s.SetMask(2, 1<<(SIGINT-1)) // block SIGINT
	s.Raise(SIGINT)
	sig := s.DequeueSignal()
	if sig != 0 {
		t.Fatalf("SIGINT should be blocked, got %d", sig)
	}
	// Unblock
	s.SetMask(1, 1<<(SIGINT-1))
	sig = s.DequeueSignal()
	if sig != SIGINT {
		t.Fatalf("expected SIGINT after unblock, got %d", sig)
	}
}

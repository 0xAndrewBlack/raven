//go:build guest_windows

package ntapi

import (
	"testing"
	"time"

	"github.com/mirkobrombin/Raven/pkg/ntobj"
)

// These tests cover the handle types after their migration onto the in-process
// object manager (pkg/ntobj): behavior preservation plus the atomic WaitAll path
// used by WaitForMultipleObjects.

func TestEventHandleSetWaitAutoReset(t *testing.T) {
	e := NewEvent(false, false) // auto-reset, unsignaled
	if e.WaitTimeout(0) {
		t.Fatal("unsignaled auto event should not be signaled")
	}
	e.Set()
	if !e.WaitTimeout(0) {
		t.Fatal("event should be signaled after Set")
	}
	// auto-reset consumed it
	if e.WaitTimeout(0) {
		t.Fatal("auto-reset event should have cleared after one wait")
	}
}

func TestEventHandleManualPeek(t *testing.T) {
	e := NewEvent(true, true) // manual, signaled
	if !e.PeekSignaled() {
		t.Fatal("peek should report signaled")
	}
	if !e.IsManualReset() {
		t.Fatal("should be manual-reset")
	}
	// Peek does not consume.
	if !e.WaitTimeout(0) || !e.WaitTimeout(0) {
		t.Fatal("manual event should stay signaled")
	}
}

func TestSemaphoreHandleCountAndRelease(t *testing.T) {
	s := NewSemaphore(1, 3)
	if s.Count() != 1 || s.MaxCount() != 3 {
		t.Fatalf("count/max = %d/%d, want 1/3", s.Count(), s.MaxCount())
	}
	if s.WaitTimeout(0) != ntobj.WaitObject0 {
		t.Fatal("should acquire the one available count")
	}
	if s.WaitTimeout(0) != ntobj.WaitTimeout {
		t.Fatal("should be empty now")
	}
	if _, ok := s.Release(2); !ok || s.Count() != 2 {
		t.Fatalf("release failed, count=%d", s.Count())
	}
	if _, ok := s.Release(5); ok {
		t.Fatal("release beyond max should fail")
	}
}

func TestMutantHandleRecursionAndRelease(t *testing.T) {
	m := NewMutant(0)
	if m.WaitTimeout(7, 0) != ntobj.WaitObject0 {
		t.Fatal("tid7 should acquire unowned mutant")
	}
	if m.WaitTimeout(7, 0) != ntobj.WaitObject0 {
		t.Fatal("tid7 recursive acquire should succeed")
	}
	if m.Count() != 2 {
		t.Fatalf("recursion = %d, want 2", m.Count())
	}
	// Another thread cannot take it (poll).
	if m.WaitTimeout(8, 0) != ntobj.WaitTimeout {
		t.Fatal("tid8 should not acquire owned mutant")
	}
	m.Release(7)
	m.Release(7)
	if !m.IsSignaled() {
		t.Fatal("mutant should be free after balanced releases")
	}
}

// TestWaitAllAtomicThroughHandles exercises the exact path WaitForMultipleObjects
// uses: WaitableFor over a HandleTable + ObjMgr.Wait with waitAll. It must not
// consume the first auto-reset event until the second is also signaled.
func TestWaitAllAtomicThroughHandles(t *testing.T) {
	ht := NewHandleTable()
	ea := NewEvent(false, false)
	eb := NewEvent(false, false)
	ha := ht.Alloc(ea)
	hb := ht.Alloc(eb)

	wa := ht.WaitableFor(ha)
	wb := ht.WaitableFor(hb)
	if wa == nil || wb == nil {
		t.Fatal("WaitableFor returned nil for event handles")
	}

	done := make(chan uint32, 1)
	go func() { done <- ObjMgr.Wait([]ntobj.Waitable{wa, wb}, true, 1, -1) }()

	ea.Set()
	select {
	case <-done:
		t.Fatal("WaitAll returned after only one event signaled (lost-wakeup bug)")
	case <-time.After(60 * time.Millisecond):
	}
	eb.Set()
	select {
	case r := <-done:
		if r != ntobj.WaitObject0 {
			t.Fatalf("WaitAll result = 0x%x", r)
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("WaitAll did not complete after both events signaled")
	}
	// Both auto-reset events consumed exactly once.
	if ea.WaitTimeout(0) || eb.WaitTimeout(0) {
		t.Fatal("events should be cleared after atomic WaitAll")
	}
}

func TestWaitableForNonWaitableReturnsNil(t *testing.T) {
	ht := NewHandleTable()
	h := ht.Alloc(&FileHandle{FD: -1})
	if ht.WaitableFor(h) != nil {
		t.Fatal("WaitableFor should be nil for a file handle")
	}
}

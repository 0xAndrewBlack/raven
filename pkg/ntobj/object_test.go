package ntobj

import (
	"sync/atomic"
	"testing"
	"time"
)

// waitAsync runs a Wait in a goroutine and reports the result on a channel.
func waitAsync(m *Manager, objs []Waitable, all bool, tid uint64, to time.Duration) <-chan uint32 {
	ch := make(chan uint32, 1)
	go func() { ch <- m.Wait(objs, all, tid, to) }()
	return ch
}

func mustRecv(t *testing.T, ch <-chan uint32, want uint32, within time.Duration) {
	t.Helper()
	select {
	case got := <-ch:
		if got != want {
			t.Fatalf("wait result = 0x%x, want 0x%x", got, want)
		}
	case <-time.After(within):
		t.Fatalf("wait did not return within %v (want 0x%x)", within, want)
	}
}

func mustBlock(t *testing.T, ch <-chan uint32, for_ time.Duration) {
	t.Helper()
	select {
	case got := <-ch:
		t.Fatalf("wait unexpectedly returned 0x%x while it should have blocked", got)
	case <-time.After(for_):
	}
}

const inf = time.Duration(-1)

func TestEventAutoResetWakesExactlyOne(t *testing.T) {
	m := New()
	e := NewEvent(false, false) // auto-reset, unsignaled
	c1 := waitAsync(m, []Waitable{e}, false, 1, inf)
	c2 := waitAsync(m, []Waitable{e}, false, 2, inf)
	time.Sleep(20 * time.Millisecond) // let both block

	m.Signal(func() { e.Set() })

	// Exactly one of the two should wake; the other stays blocked.
	woken := 0
	timeout := time.After(200 * time.Millisecond)
	for woken < 1 {
		select {
		case <-c1:
			woken++
		case <-c2:
			woken++
		case <-timeout:
			t.Fatal("no waiter woke on auto-reset set")
		}
	}
	// The remaining waiter must still be blocked (auto-reset released only one).
	select {
	case <-c1:
		t.Fatal("second waiter woke too - auto-reset released more than one")
	case <-c2:
		t.Fatal("second waiter woke too - auto-reset released more than one")
	case <-time.After(80 * time.Millisecond):
	}
}

func TestEventManualResetWakesAll(t *testing.T) {
	m := New()
	e := NewEvent(true, false) // manual-reset
	c1 := waitAsync(m, []Waitable{e}, false, 1, inf)
	c2 := waitAsync(m, []Waitable{e}, false, 2, inf)
	time.Sleep(20 * time.Millisecond)

	m.Signal(func() { e.Set() })

	mustRecv(t, c1, WaitObject0, 200*time.Millisecond)
	mustRecv(t, c2, WaitObject0, 200*time.Millisecond)

	// Still signaled: a fresh poll succeeds immediately.
	if r := m.Wait([]Waitable{e}, false, 3, 0); r != WaitObject0 {
		t.Fatalf("manual event not still signaled: 0x%x", r)
	}
}

func TestSemaphoreReleasesUpToCount(t *testing.T) {
	m := New()
	s := NewSemaphore(0, 5)
	c1 := waitAsync(m, []Waitable{s}, false, 1, inf)
	c2 := waitAsync(m, []Waitable{s}, false, 2, inf)
	c3 := waitAsync(m, []Waitable{s}, false, 3, inf)
	time.Sleep(20 * time.Millisecond)

	m.Signal(func() { s.Release(2) }) // wake exactly two

	got := 0
	deadline := time.After(200 * time.Millisecond)
	for got < 2 {
		select {
		case <-c1:
			got++
		case <-c2:
			got++
		case <-c3:
			got++
		case <-deadline:
			t.Fatalf("only %d waiters woke, want 2", got)
		}
	}
	// One waiter remains; count must be 0.
	if c := func() int32 { var v int32; m.Signal(func() { v = s.Count() }); return v }(); c != 0 {
		t.Fatalf("semaphore count = %d, want 0", c)
	}
}

func TestMutantRecursionAndContention(t *testing.T) {
	m := New()
	mu := NewMutant(0)

	if r := m.Wait([]Waitable{mu}, false, 1, inf); r != WaitObject0 {
		t.Fatalf("tid1 acquire: 0x%x", r)
	}
	if r := m.Wait([]Waitable{mu}, false, 1, inf); r != WaitObject0 {
		t.Fatalf("tid1 recursive acquire: 0x%x", r)
	}

	// tid2 must block while tid1 owns it.
	c2 := waitAsync(m, []Waitable{mu}, false, 2, inf)
	mustBlock(t, c2, 60*time.Millisecond)

	// One release still leaves tid1 owning (recursion was 2).
	m.Signal(func() { mu.Release(1) })
	mustBlock(t, c2, 60*time.Millisecond)

	// Final release hands ownership to tid2.
	m.Signal(func() { mu.Release(1) })
	mustRecv(t, c2, WaitObject0, 200*time.Millisecond)
	if mu.Owner() != 2 {
		t.Fatalf("owner = %d, want 2", mu.Owner())
	}
}

func TestMutantAbandoned(t *testing.T) {
	m := New()
	mu := NewMutant(1) // owned by tid1
	c2 := waitAsync(m, []Waitable{mu}, false, 2, inf)
	mustBlock(t, c2, 40*time.Millisecond)

	m.Signal(func() { mu.Abandon(1) }) // tid1 "terminated"
	mustRecv(t, c2, WaitAbandoned0, 200*time.Millisecond)
}

// TestWaitAllIsAtomic is the core correctness test: it must NOT consume an
// auto-reset object until ALL objects are simultaneously signaled. The old
// "wait for all in sequence" approach would consume A, block on B, and lose A.
func TestWaitAllIsAtomic(t *testing.T) {
	m := New()
	a := NewEvent(false, false) // auto-reset
	b := NewEvent(false, false) // auto-reset

	c := waitAsync(m, []Waitable{a, b}, true /*waitAll*/, 1, inf)

	m.Signal(func() { a.Set() }) // only A is signaled
	mustBlock(t, c, 80*time.Millisecond)
	// A must NOT have been consumed (the bug). Now signal B.
	m.Signal(func() { b.Set() })
	mustRecv(t, c, WaitObject0, 200*time.Millisecond)

	// Both auto-reset events must now be cleared (consumed exactly once, together).
	if r := m.Wait([]Waitable{a}, false, 2, 0); r != WaitTimeout {
		t.Fatalf("A still signaled after WaitAll: 0x%x", r)
	}
	if r := m.Wait([]Waitable{b}, false, 2, 0); r != WaitTimeout {
		t.Fatalf("B still signaled after WaitAll: 0x%x", r)
	}
}

func TestWaitAnyReturnsIndex(t *testing.T) {
	m := New()
	e0 := NewEvent(true, false)
	e1 := NewEvent(true, false)
	e2 := NewEvent(true, false)
	m.Signal(func() { e1.Set() })
	if r := m.Wait([]Waitable{e0, e1, e2}, false, 1, inf); r != WaitObject0+1 {
		t.Fatalf("WaitAny index = 0x%x, want 0x%x", r, WaitObject0+1)
	}
}

func TestTimeout(t *testing.T) {
	m := New()
	e := NewEvent(false, false)
	start := time.Now()
	if r := m.Wait([]Waitable{e}, false, 1, 50*time.Millisecond); r != WaitTimeout {
		t.Fatalf("result = 0x%x, want WAIT_TIMEOUT", r)
	}
	if d := time.Since(start); d < 40*time.Millisecond {
		t.Fatalf("returned too early: %v", d)
	}
}

func TestZeroTimeoutIsPoll(t *testing.T) {
	m := New()
	e := NewEvent(true, true) // signaled
	if r := m.Wait([]Waitable{e}, false, 1, 0); r != WaitObject0 {
		t.Fatalf("poll of signaled event: 0x%x", r)
	}
	e2 := NewEvent(true, false)
	if r := m.Wait([]Waitable{e2}, false, 1, 0); r != WaitTimeout {
		t.Fatalf("poll of unsignaled event: 0x%x, want timeout", r)
	}
}

func TestRefCountLifetime(t *testing.T) {
	m := New()
	var closed int32
	o := m.Create(NewEvent(true, false), func() { atomic.AddInt32(&closed, 1) })
	if o.Refs() != 1 {
		t.Fatalf("initial refs = %d", o.Refs())
	}
	m.AddRef(o) // e.g. NtDuplicateObject
	if o.Refs() != 2 {
		t.Fatalf("after AddRef refs = %d", o.Refs())
	}
	if n := m.Release(o); n != 1 {
		t.Fatalf("after first Release refs = %d", n)
	}
	if atomic.LoadInt32(&closed) != 0 {
		t.Fatal("onClose fired while a reference remained")
	}
	if n := m.Release(o); n != 0 {
		t.Fatalf("after second Release refs = %d", n)
	}
	if atomic.LoadInt32(&closed) != 1 {
		t.Fatal("onClose did not fire at refcount 0")
	}
}

func TestNamedNamespace(t *testing.T) {
	m := New()
	o1, existed := m.CreateNamed(`\BaseNamedObjects\Foo`, NewEvent(true, false), nil)
	if existed {
		t.Fatal("first CreateNamed reported existed=true")
	}
	o2, existed := m.CreateNamed(`\BaseNamedObjects\Foo`, NewEvent(true, false), nil)
	if !existed {
		t.Fatal("second CreateNamed reported existed=false")
	}
	if o1 != o2 {
		t.Fatal("named CreateNamed returned a different object")
	}
	if o1.Refs() != 2 {
		t.Fatalf("refs after re-create = %d, want 2", o1.Refs())
	}
	o3 := m.Open(`\BaseNamedObjects\Foo`)
	if o3 != o1 || o1.Refs() != 3 {
		t.Fatalf("Open did not return the same object / bump refs (refs=%d)", o1.Refs())
	}
	// Drain references; the name must disappear at refcount 0.
	m.Release(o1)
	m.Release(o2)
	m.Release(o3)
	if m.Open(`\BaseNamedObjects\Foo`) != nil {
		t.Fatal("name still resolvable after all references released")
	}
}

// TestSignaledObjectMultiWaitNoSpuriousConsume ensures WaitAny consumes only the
// one object it returns, leaving the others untouched.
func TestWaitAnyConsumesOnlyOne(t *testing.T) {
	m := New()
	a := NewEvent(false, true) // auto, signaled
	b := NewEvent(false, true) // auto, signaled
	r := m.Wait([]Waitable{a, b}, false, 1, inf)
	if r != WaitObject0 {
		t.Fatalf("WaitAny = 0x%x, want index 0", r)
	}
	// a consumed, b must remain signaled.
	if got := m.Wait([]Waitable{b}, false, 1, 0); got != WaitObject0 {
		t.Fatalf("b was wrongly consumed: 0x%x", got)
	}
	if got := m.Wait([]Waitable{a}, false, 1, 0); got != WaitTimeout {
		t.Fatalf("a not consumed: 0x%x", got)
	}
}

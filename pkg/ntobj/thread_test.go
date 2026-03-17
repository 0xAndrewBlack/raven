package ntobj

import (
	"testing"
	"time"
)

func TestThreadWaitOnExit(t *testing.T) {
	m := New()
	th := NewThread(7)

	// A waiter on a running thread blocks.
	c := waitAsync(m, []Waitable{th}, false, 1, inf)
	mustBlock(t, c, 50*time.Millisecond)

	m.Signal(func() { th.Exit(42) })
	mustRecv(t, c, WaitObject0, 200*time.Millisecond)

	// Exit is a permanent signal: later waits succeed immediately.
	if r := m.Wait([]Waitable{th}, false, 2, 0); r != WaitObject0 {
		t.Fatalf("post-exit wait = 0x%x, want signaled", r)
	}
	if code, exited := th.ExitCode(); !exited || code != 42 {
		t.Fatalf("exit code = %d exited=%v, want 42/true", code, exited)
	}
}

func TestThreadSuspendResumeCounts(t *testing.T) {
	m := New()
	th := NewThread(1)
	var p1, p2, p3 int32
	m.Signal(func() { p1 = th.Suspend() }) // 0 -> 1
	m.Signal(func() { p2 = th.Suspend() }) // 1 -> 2
	m.Signal(func() { p3 = th.Resume() })  // 2 -> 1
	if p1 != 0 || p2 != 1 || p3 != 2 {
		t.Fatalf("suspend/resume prev counts = %d,%d,%d want 0,1,2", p1, p2, p3)
	}
	if th.SuspendCount() != 1 || th.IsRunnable() {
		t.Fatalf("count=%d runnable=%v want 1/false", th.SuspendCount(), th.IsRunnable())
	}
	m.Signal(func() { th.Resume() }) // 1 -> 0
	if !th.IsRunnable() {
		t.Fatal("thread should be runnable after counts return to 0")
	}
	// Resume below zero stays at zero.
	m.Signal(func() { th.Resume() })
	if th.SuspendCount() != 0 {
		t.Fatalf("suspend count went negative: %d", th.SuspendCount())
	}
}

func TestProcessTerminateExitsThreadsAndWaiters(t *testing.T) {
	m := New()
	p := NewProcess(100)
	t1, t2 := NewThread(1), NewThread(2)
	m.Signal(func() { p.AddThread(t1); p.AddThread(t2) })

	cp := waitAsync(m, []Waitable{p}, false, 9, inf)
	ct1 := waitAsync(m, []Waitable{t1}, false, 9, inf)
	mustBlock(t, cp, 40*time.Millisecond)

	m.Signal(func() { p.Terminate(3) })

	mustRecv(t, cp, WaitObject0, 200*time.Millisecond)  // process signaled
	mustRecv(t, ct1, WaitObject0, 200*time.Millisecond) // its threads too
	if code, exited := t2.ExitCode(); !exited || code != 3 {
		t.Fatalf("thread2 exit = %d/%v, want 3/true", code, exited)
	}
}

// A process handle composes with WaitAll alongside an event (e.g. "wait for the
// child to exit AND a ready event").
func TestProcessInWaitAll(t *testing.T) {
	m := New()
	p := NewProcess(1)
	ev := NewEvent(true, false)
	c := waitAsync(m, []Waitable{p, ev}, true, 1, inf)

	m.Signal(func() { p.Terminate(0) })
	mustBlock(t, c, 40*time.Millisecond) // event still unsignaled
	m.Signal(func() { ev.Set() })
	mustRecv(t, c, WaitObject0, 200*time.Millisecond)
}

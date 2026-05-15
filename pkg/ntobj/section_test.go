package ntobj

import (
	"testing"
	"time"
)

func TestMessageQueueWaitable(t *testing.T) {
	m := New()
	q := NewMessageQueue()

	// Empty queue: a waiter blocks.
	c := waitAsync(m, []Waitable{q}, false, 1, inf)
	mustBlock(t, c, 50*time.Millisecond)

	// Posting a message wakes it; the wait does NOT consume the message.
	m.Signal(func() { q.Post() })
	mustRecv(t, c, WaitObject0, 200*time.Millisecond)
	if q.Pending() != 1 {
		t.Fatalf("pending = %d, want 1 (wait must not consume)", q.Pending())
	}
	// Draining clears it; then it blocks again.
	var drained int
	m.Signal(func() { drained = q.Drain() })
	if drained != 1 || q.Pending() != 0 {
		t.Fatalf("drain = %d, pending = %d", drained, q.Pending())
	}
	if r := m.Wait([]Waitable{q}, false, 1, 0); r != WaitTimeout {
		t.Fatalf("drained queue should not be signaled: 0x%x", r)
	}
}

// MsgWaitForMultipleObjects pattern: wake on input OR a handle.
func TestMessageQueueInWaitAny(t *testing.T) {
	m := New()
	q := NewMessageQueue()
	ev := NewEvent(true, false)
	c := waitAsync(m, []Waitable{ev, q}, false, 1, inf)
	mustBlock(t, c, 40*time.Millisecond)
	m.Signal(func() { q.Post() }) // input arrives -> index 1
	mustRecv(t, c, WaitObject0+1, 200*time.Millisecond)
}

func TestAlertableWaitRunsAPC(t *testing.T) {
	m := New()
	ev := NewEvent(false, false) // never signaled
	ran := make(chan int, 1)

	go func() {
		code, apcs := m.WaitEx([]Waitable{ev}, false, 5, inf, true /*alertable*/)
		for _, fn := range apcs {
			fn()
		}
		ran <- int(code)
	}()
	time.Sleep(20 * time.Millisecond)

	m.QueueAPC(5, func() { ran <- 777 })

	// First receive is the APC callback's value, then the wait code.
	got1 := <-ran
	got2 := <-ran
	if got1 != 777 {
		t.Fatalf("APC did not run first: got %d", got1)
	}
	if uint32(got2) != WaitIOCompletion {
		t.Fatalf("alertable wait code = 0x%x, want WAIT_IO_COMPLETION", got2)
	}
}

func TestAlertableNonAlertableIgnoresAPC(t *testing.T) {
	m := New()
	ev := NewEvent(false, true) // signaled
	// Non-alertable wait must ignore a queued APC and just satisfy the object.
	m.QueueAPC(1, func() {})
	if r := m.Wait([]Waitable{ev}, false, 1, 0); r != WaitObject0 {
		t.Fatalf("non-alertable wait = 0x%x, want object signaled", r)
	}
}

func TestRecursiveAlertableWaitSeesNextAPC(t *testing.T) {
	m := New()
	const tid = uint64(12)
	order := make([]int, 0, 2)
	m.QueueAPC(tid, func() {
		order = append(order, 1)
		code, nested := m.WaitEx(nil, false, tid, 0, true)
		if code != WaitIOCompletion || len(nested) != 1 {
			t.Fatalf("nested wait = %#x/%d", code, len(nested))
		}
		nested[0]()
	})
	m.QueueAPC(tid, func() { order = append(order, 2) })

	code, queued := m.WaitEx(nil, false, tid, 0, true)
	if code != WaitIOCompletion || len(queued) != 1 {
		t.Fatalf("outer wait = %#x/%d", code, len(queued))
	}
	queued[0]()
	if len(order) != 2 || order[0] != 1 || order[1] != 2 {
		t.Fatalf("recursive APC order = %v", order)
	}
}

func TestDiscardAPCsRemovesThreadQueue(t *testing.T) {
	m := New()
	const tid = uint64(13)
	m.QueueAPC(tid, func() {})
	m.QueueAPC(tid, func() {})
	if discarded := m.DiscardAPCs(tid); discarded != 2 {
		t.Fatalf("discarded APCs = %d", discarded)
	}
	code, queued := m.WaitEx(nil, false, tid, 0, true)
	if code != WaitTimeout || len(queued) != 0 {
		t.Fatalf("post-discard wait = %#x/%d", code, len(queued))
	}
}

func TestSectionNamedRefcount(t *testing.T) {
	m := New()
	s1, existed := m.CreateNamed(`\BaseNamedObjects\Shm`, NewSection(0x1000, 0x04, false, -1), nil)
	if existed {
		t.Fatal("first create reported existed")
	}
	s2, existed := m.CreateNamed(`\BaseNamedObjects\Shm`, NewSection(0x1000, 0x04, false, -1), nil)
	if !existed || s1 != s2 {
		t.Fatal("second create should return the same shared section")
	}
	sec := s1.Payload().(*Section)
	if sec.Size != 0x1000 {
		t.Fatalf("section size = %#x", sec.Size)
	}
	m.Signal(func() { sec.AddView(); sec.AddView() })
	if sec.Views() != 2 {
		t.Fatalf("views = %d, want 2", sec.Views())
	}
	if m.Release(s1) != 1 || m.Release(s2) != 0 {
		t.Fatal("refcount did not drop to zero across two opens")
	}
	if m.Open(`\BaseNamedObjects\Shm`) != nil {
		t.Fatal("section name should be gone after last release")
	}
}

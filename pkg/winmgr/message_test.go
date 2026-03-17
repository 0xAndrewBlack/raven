package winmgr

import (
	"testing"
	"time"
)

func TestPostPeekGetFIFO(t *testing.T) {
	q := NewQueue()
	q.Post(MSG{HWND: 1, Message: 0x100})
	q.Post(MSG{HWND: 1, Message: 0x101})
	// PeekMessage without remove returns the first repeatedly.
	if m, ok := q.PeekMessage(0, 0, 0, PM_NOREMOVE); !ok || m.Message != 0x100 {
		t.Fatal("peek no-remove failed")
	}
	if q.PendingCount() != 2 {
		t.Fatal("no-remove peek consumed a message")
	}
	m1, _ := q.GetMessage(0, 0, 0)
	m2, _ := q.GetMessage(0, 0, 0)
	if m1.Message != 0x100 || m2.Message != 0x101 {
		t.Fatalf("FIFO order wrong: %x %x", m1.Message, m2.Message)
	}
}

func TestMessageFilter(t *testing.T) {
	q := NewQueue()
	q.Post(MSG{HWND: 5, Message: 0x200})
	q.Post(MSG{HWND: 9, Message: 0x201})
	// Filter by hwnd.
	if m, ok := q.PeekMessage(9, 0, 0, PM_REMOVE); !ok || m.Message != 0x201 {
		t.Fatal("hwnd filter failed")
	}
	// Filter by message range.
	q.Post(MSG{HWND: 5, Message: 0x400})
	if m, ok := q.PeekMessage(0, 0x300, 0x500, PM_REMOVE); !ok || m.Message != 0x400 {
		t.Fatal("range filter failed")
	}
}

func TestQuitMessage(t *testing.T) {
	q := NewQueue()
	q.Post(MSG{Message: 0x100})
	q.PostQuit(7)
	// Posted messages drain before WM_QUIT.
	if m, ok := q.GetMessage(0, 0, 0); !ok || m.Message != 0x100 {
		t.Fatal("posted message should come before WM_QUIT")
	}
	// Then WM_QUIT -> GetMessage returns false with the exit code.
	m, ok := q.GetMessage(0, 0, 0)
	if ok || m.Message != WM_QUIT || int32(uint32(m.WParam)) != 7 {
		t.Fatalf("WM_QUIT wrong: ok=%v msg=%x code=%d", ok, m.Message, int32(uint32(m.WParam)))
	}
}

func TestPaintGenerated(t *testing.T) {
	q := NewQueue()
	q.Invalidate(42)
	// WM_PAINT is generated and NOT removed by GetMessage.
	if m, ok := q.PeekMessage(0, 0, 0, PM_REMOVE); !ok || m.Message != WM_PAINT || m.HWND != 42 {
		t.Fatal("WM_PAINT not generated")
	}
	if _, ok := q.PeekMessage(0, 0, 0, PM_NOREMOVE); !ok {
		t.Fatal("WM_PAINT should persist until Validate")
	}
	q.Validate(42)
	if _, ok := q.PeekMessage(0, 0, 0, PM_NOREMOVE); ok {
		t.Fatal("WM_PAINT should be gone after Validate")
	}
}

func TestTimerGeneratesWMTimer(t *testing.T) {
	q := NewQueue()
	now := time.Now()
	q.now = func() time.Time { return now }
	q.SetTimer(3, 1, 100*time.Millisecond, 0)
	// Not due yet.
	if _, ok := q.PeekMessage(0, 0, 0, PM_NOREMOVE); ok {
		t.Fatal("timer fired early")
	}
	now = now.Add(150 * time.Millisecond) // advance virtual clock
	m, ok := q.PeekMessage(0, 0, 0, PM_REMOVE)
	if !ok || m.Message != WM_TIMER || m.WParam != 1 || m.HWND != 3 {
		t.Fatalf("WM_TIMER wrong: %+v", m)
	}
	// Periodic: not due again immediately.
	if _, ok := q.PeekMessage(0, 0, 0, PM_NOREMOVE); ok {
		t.Fatal("timer should have rescheduled")
	}
	now = now.Add(150 * time.Millisecond)
	if _, ok := q.PeekMessage(0, 0, 0, PM_NOREMOVE); !ok {
		t.Fatal("timer did not fire again")
	}
	q.KillTimer(3, 1)
	if _, ok := q.PeekMessage(0, 0, 0, PM_NOREMOVE); ok {
		t.Fatal("killed timer still firing")
	}
}

func TestMessagePriority(t *testing.T) {
	q := NewQueue()
	now := time.Now()
	q.now = func() time.Time { return now }
	q.Invalidate(1)                       // WM_PAINT pending
	q.SetTimer(1, 1, time.Millisecond, 0) // timer
	now = now.Add(time.Second)            // timer due
	q.Post(MSG{HWND: 1, Message: 0x300})  // posted
	// Posted beats paint and timer.
	if m, _ := q.GetMessage(0, 0, 0); m.Message != 0x300 {
		t.Fatalf("posted should win, got %x", m.Message)
	}
	// Then paint beats timer.
	if m, ok := q.PeekMessage(0, 0, 0, PM_NOREMOVE); !ok || m.Message != WM_PAINT {
		t.Fatalf("paint should beat timer, got %x", m.Message)
	}
}

func TestGetMessageBlocksUntilPost(t *testing.T) {
	q := NewQueue()
	got := make(chan MSG, 1)
	go func() { m, _ := q.GetMessage(0, 0, 0); got <- m }()
	select {
	case <-got:
		t.Fatal("GetMessage returned before any message")
	case <-time.After(40 * time.Millisecond):
	}
	q.Post(MSG{Message: 0x123})
	select {
	case m := <-got:
		if m.Message != 0x123 {
			t.Fatalf("woke with wrong message %x", m.Message)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("GetMessage did not wake on Post")
	}
}

func TestInterThreadSendMessage(t *testing.T) {
	q := NewQueue()
	// Target thread: dispatch sent messages, replying msg*2.
	go func() {
		for {
			if m, reply, ok := q.TakeSent(); ok {
				reply(m.WParam * 2)
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()
	if r := q.SendTo(MSG{Message: 0x1, WParam: 21}); r != 42 {
		t.Fatalf("SendTo reply = %d, want 42", r)
	}
}

func TestMenuHitTest(t *testing.T) {
	tbl := NewMenuTable()
	h := tbl.Create()
	tbl.Append(h, &MenuItem{ID: 1, Text: "New"})
	tbl.Append(h, &MenuItem{Flags: MF_SEPARATOR})
	tbl.Append(h, &MenuItem{ID: 2, Text: "Exit", Flags: MF_GRAYED})
	m := tbl.Get(h)
	total := m.Layout(20, 6) // 20 + 6 + 20
	if total != 46 {
		t.Fatalf("layout total = %d, want 46", total)
	}
	if i := m.HitTest(5); i != 0 || m.Items[i].ID != 1 {
		t.Fatalf("hit at y=5 = %d", i)
	}
	if i := m.HitTest(23); i != 1 || !(m.Items[i].Flags&MF_SEPARATOR != 0) {
		t.Fatalf("hit at y=23 should be separator, got %d", i)
	}
	if i := m.HitTest(30); i != 2 || m.Items[i].Enabled() {
		t.Fatalf("hit at y=30 should be the grayed Exit, got %d", i)
	}
	if m.HitTest(999) != -1 {
		t.Fatal("out-of-range hit should be -1")
	}
}

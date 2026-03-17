package winmgr

import (
	"sync"
	"time"
)

// Common window messages used by the queue's generated-message logic.
const (
	WM_PAINT uint32 = 0x000F
	WM_QUIT  uint32 = 0x0012
	WM_TIMER uint32 = 0x0113
)

// PeekMessage removal flags.
const (
	PM_NOREMOVE uint32 = 0x0000
	PM_REMOVE   uint32 = 0x0001
)

// MSG mirrors the Win32 MSG structure (kernel side; no guest pointers).
type MSG struct {
	HWND    HWND
	Message uint32
	WParam  uint64
	LParam  uint64
	Time    uint32
	PtX     int32
	PtY     int32
}

type timerKey struct {
	hwnd HWND
	id   uint64
}

type timerEntry struct {
	elapse time.Duration
	due    time.Time
	proc   uint64 // optional TIMERPROC guest address (0 = post WM_TIMER)
}

type sentMsg struct {
	msg   MSG
	reply chan uint64
}

// Queue is a thread's input/message queue (one per GUI thread). It implements
// the GetMessage/PeekMessage retrieval order: sent messages, then posted (FIFO),
// then WM_QUIT, then generated WM_PAINT, then WM_TIMER.
type Queue struct {
	mu       sync.Mutex
	cond     *sync.Cond
	posted   []MSG
	sent     []sentMsg
	quit     bool
	quitCode int32
	paint    map[HWND]bool
	timers   map[timerKey]*timerEntry
	now      func() time.Time
}

// NewQueue creates an empty message queue.
func NewQueue() *Queue {
	q := &Queue{
		paint:  make(map[HWND]bool),
		timers: make(map[timerKey]*timerEntry),
		now:    time.Now,
	}
	q.cond = sync.NewCond(&q.mu)
	return q
}

// Post appends a message to the FIFO and wakes a waiter.
func (q *Queue) Post(m MSG) {
	q.mu.Lock()
	q.posted = append(q.posted, m)
	q.cond.Broadcast()
	q.mu.Unlock()
}

// PostQuit posts WM_QUIT with the given exit code (PostQuitMessage).
func (q *Queue) PostQuit(code int32) {
	q.mu.Lock()
	q.quit = true
	q.quitCode = code
	q.cond.Broadcast()
	q.mu.Unlock()
}

// Invalidate marks a window as needing a WM_PAINT (generated until validated).
func (q *Queue) Invalidate(h HWND) {
	q.mu.Lock()
	q.paint[h] = true
	q.cond.Broadcast()
	q.mu.Unlock()
}

// Validate clears a window's pending WM_PAINT (BeginPaint/ValidateRect).
func (q *Queue) Validate(h HWND) {
	q.mu.Lock()
	delete(q.paint, h)
	q.mu.Unlock()
}

// SetTimer creates/replaces a timer. proc is an optional TIMERPROC (0 = post
// WM_TIMER to the queue).
func (q *Queue) SetTimer(h HWND, id uint64, elapse time.Duration, proc uint64) {
	q.mu.Lock()
	q.timers[timerKey{h, id}] = &timerEntry{elapse: elapse, due: q.now().Add(elapse), proc: proc}
	q.mu.Unlock()
}

// KillTimer removes a timer; returns false if not found.
func (q *Queue) KillTimer(h HWND, id uint64) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	k := timerKey{h, id}
	if _, ok := q.timers[k]; !ok {
		return false
	}
	delete(q.timers, k)
	return true
}

// matches reports whether msg passes a GetMessage/PeekMessage filter.
func matches(m MSG, hwnd HWND, min, max uint32) bool {
	if hwnd != 0 && m.HWND != hwnd {
		return false
	}
	if min == 0 && max == 0 {
		return true
	}
	return m.Message >= min && m.Message <= max
}

// selectLocked picks the next deliverable message per Win32 priority. remove
// controls whether the message is consumed. Returns (msg, ok). Sent messages are
// reported via their own path (drainSentLocked) and are not returned here.
func (q *Queue) selectLocked(hwnd HWND, min, max uint32, remove bool) (MSG, bool) {
	// 1. Posted messages (FIFO).
	for i, m := range q.posted {
		if matches(m, hwnd, min, max) {
			if remove {
				q.posted = append(q.posted[:i:i], q.posted[i+1:]...)
			}
			return m, true
		}
	}
	// 2. WM_QUIT (only when nothing posted remains).
	if q.quit && matches(MSG{Message: WM_QUIT}, hwnd, min, max) {
		m := MSG{Message: WM_QUIT, WParam: uint64(uint32(q.quitCode))}
		// WM_QUIT is consumed by GetMessage (so it returns false once).
		if remove {
			q.quit = false
		}
		return m, true
	}
	// 3. Generated WM_PAINT (not removed here; cleared by Validate).
	for h := range q.paint {
		m := MSG{HWND: h, Message: WM_PAINT}
		if matches(m, hwnd, min, max) {
			return m, true
		}
	}
	// 4. Generated WM_TIMER for elapsed timers (lowest priority).
	now := q.now()
	for k, t := range q.timers {
		if !now.Before(t.due) {
			m := MSG{HWND: k.hwnd, Message: WM_TIMER, WParam: k.id, LParam: t.proc}
			if matches(m, hwnd, min, max) {
				if remove {
					t.due = now.Add(t.elapse) // reschedule periodic timer
				}
				return m, true
			}
		}
	}
	return MSG{}, false
}

// PeekMessage returns the next matching message without blocking. With PM_REMOVE
// it consumes posted/quit messages. Sent messages are dispatched first via the
// returned slice of pending sends (caller invokes their WndProc and Reply()).
func (q *Queue) PeekMessage(hwnd HWND, min, max, flags uint32) (MSG, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.selectLocked(hwnd, min, max, flags&PM_REMOVE != 0)
}

// GetMessage blocks until a matching message is available, removes it, and
// returns ok=false when the message is WM_QUIT (the signal to exit the loop).
func (q *Queue) GetMessage(hwnd HWND, min, max uint32) (MSG, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for {
		if m, ok := q.selectLocked(hwnd, min, max, true); ok {
			return m, m.Message != WM_QUIT
		}
		q.cond.Wait()
	}
}

// HasSent reports whether inter-thread sent messages are pending.
func (q *Queue) HasSent() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.sent) > 0
}

// TakeSent pops the next inter-thread sent message for the caller to dispatch to
// its WndProc; reply must be returned via ReplySent.
func (q *Queue) TakeSent() (MSG, func(uint64), bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.sent) == 0 {
		return MSG{}, nil, false
	}
	s := q.sent[0]
	q.sent = q.sent[1:]
	return s.msg, func(r uint64) { s.reply <- r }, true
}

// SendTo delivers a synchronous message to this queue's thread and blocks for
// the WndProc result. The target thread must dispatch via TakeSent and call the
// returned reply func. (Same-thread SendMessage should call the WndProc directly
// rather than using this path.)
func (q *Queue) SendTo(m MSG) uint64 {
	reply := make(chan uint64, 1)
	q.mu.Lock()
	q.sent = append(q.sent, sentMsg{msg: m, reply: reply})
	q.cond.Broadcast()
	q.mu.Unlock()
	return <-reply
}

// PendingCount returns the number of posted messages (diagnostics/tests).
func (q *Queue) PendingCount() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.posted)
}

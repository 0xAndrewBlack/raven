package ntapi

import (
	"sync"
	"sync/atomic"
	"time"
)

// TpPool is a Win32 thread pool (PTP_POOL).
// Wine reference: dlls/ntdll/threadpool.c struct threadpool
type TpPool struct {
	MinThreads int32
	MaxThreads int32
}

func (h *TpPool) handleType() string { return "tp_pool" }

// TpWork is a Win32 thread pool work item (PTP_WORK).
// Wine reference: threadpool.c struct threadpool_object (type=TP_OBJECT_TYPE_WORK)
type TpWork struct {
	Callback uint64 // guest PFTWORKERCALLBACK function pointer
	Context  uint64 // guest PVOID context

	Mu      sync.Mutex
	Pending sync.WaitGroup // tracks in-flight callbacks
	closed  int32          // atomic: 1 = shutdown
}

func (h *TpWork) handleType() string { return "tp_work" }

// IsClosed returns whether the work item has been shut down.
func (w *TpWork) IsClosed() bool { return atomic.LoadInt32(&w.closed) != 0 }

// Shutdown marks the work item as closed (prevents new submissions).
func (w *TpWork) Shutdown() { atomic.StoreInt32(&w.closed, 1) }

// WaitAll blocks until all submitted callbacks complete.
func (w *TpWork) WaitAll() { w.Pending.Wait() }

// Submit increments the pending counter and returns a done func the caller
// must invoke when the callback finishes. Returns false if the work is closed.
func (w *TpWork) Submit() (done func(), ok bool) {
	if w.IsClosed() {
		return nil, false
	}
	w.Pending.Add(1)
	return func() { w.Pending.Done() }, true
}

// TpTimer is a Win32 thread pool timer (PTP_TIMER).
// Wine reference: threadpool.c struct threadpool_object (type=TP_OBJECT_TYPE_TIMER)
type TpTimer struct {
	Callback uint64 // guest PFTIMERCALLBACK function pointer
	Context  uint64 // guest PVOID context

	Mu     sync.Mutex
	Set    bool          // true if SetThreadpoolTimer has armed the timer
	Period time.Duration // 0 = one-shot
	StopCh chan struct{} // closed to cancel a running timer goroutine

	Pending sync.WaitGroup // tracks in-flight callbacks
	closed  int32          // atomic: 1 = shutdown
}

func (h *TpTimer) handleType() string { return "tp_timer" }

// IsSet returns whether the timer is armed.
func (t *TpTimer) IsSet() bool {
	t.Mu.Lock()
	defer t.Mu.Unlock()
	return t.Set
}

// Stop cancels any running timer goroutine.
func (t *TpTimer) Stop() {
	t.Mu.Lock()
	defer t.Mu.Unlock()
	t.Set = false
	if t.StopCh != nil {
		close(t.StopCh)
		t.StopCh = nil
	}
}

// Shutdown marks the timer as closed.
func (t *TpTimer) Shutdown() {
	t.Stop()
	atomic.StoreInt32(&t.closed, 1)
}

// IsClosed returns whether the timer has been shut down.
func (t *TpTimer) IsClosed() bool { return atomic.LoadInt32(&t.closed) != 0 }

// WaitAll blocks until all pending timer callbacks complete.
func (t *TpTimer) WaitAll() { t.Pending.Wait() }

// Arm sets up the timer with the given delay and period. The fire function is
// called each time the timer fires; it runs in its own goroutine.
// Call Stop() first to cancel any previously armed timer.
func (t *TpTimer) Arm(delay, period time.Duration, fire func()) {
	t.Mu.Lock()
	t.Set = true
	t.Period = period
	stopCh := make(chan struct{})
	t.StopCh = stopCh
	t.Mu.Unlock()

	t.Pending.Add(1)
	go func() {
		defer t.Pending.Done()
		if delay > 0 {
			select {
			case <-stopCh:
				return
			case <-time.After(delay):
			}
		}
		for {
			if t.IsClosed() {
				return
			}
			fire()
			if period == 0 {
				t.Mu.Lock()
				t.Set = false
				t.Mu.Unlock()
				return
			}
			select {
			case <-stopCh:
				return
			case <-time.After(period):
			}
		}
	}()
}

// TpWait is a Win32 thread pool wait object (PTP_WAIT).
// Wine reference: threadpool.c struct threadpool_object (type=TP_OBJECT_TYPE_WAIT)
type TpWait struct {
	Callback uint64 // guest PFWAITCALLBACK function pointer
	Context  uint64 // guest PVOID context

	Mu     sync.Mutex
	Handle Handle        // kernel object to wait on
	StopCh chan struct{} // closed to cancel a running wait goroutine

	Pending sync.WaitGroup // tracks in-flight callbacks
	closed  int32          // atomic: 1 = shutdown
}

func (h *TpWait) handleType() string { return "tp_wait" }

// Stop cancels any running wait goroutine.
func (w *TpWait) Stop() {
	w.Mu.Lock()
	defer w.Mu.Unlock()
	if w.StopCh != nil {
		close(w.StopCh)
		w.StopCh = nil
	}
}

// Shutdown marks the wait object as closed.
func (w *TpWait) Shutdown() {
	w.Stop()
	atomic.StoreInt32(&w.closed, 1)
}

// IsClosed returns whether the wait object has been shut down.
func (w *TpWait) IsClosed() bool { return atomic.LoadInt32(&w.closed) != 0 }

// WaitAll blocks until all pending wait callbacks complete.
func (w *TpWait) WaitAll() { w.Pending.Wait() }

// ArmStopCh prepares the wait object for a new wait, returning the stop channel.
func (w *TpWait) ArmStopCh(h Handle) chan struct{} {
	w.Mu.Lock()
	defer w.Mu.Unlock()
	w.Handle = h
	stopCh := make(chan struct{})
	w.StopCh = stopCh
	return stopCh
}

// TrackCallback increments the pending counter and returns a done func.
func (w *TpWait) TrackCallback() func() {
	w.Pending.Add(1)
	return func() { w.Pending.Done() }
}

// TpIo is a Win32 thread pool I/O object (PTP_IO).
// Wine reference: threadpool.c struct threadpool_object (type=TP_OBJECT_TYPE_IO)
type TpIo struct {
	File     Handle
	Callback uint64 // guest PIO_APC_ROUTINE-like callback pointer
	Context  uint64 // guest PVOID context

	Pending sync.WaitGroup // tracks in-flight callbacks
	started int32          // atomic count of StartThreadpoolIo calls
	closed  int32          // atomic: 1 = shutdown
}

func (h *TpIo) handleType() string { return "tp_io" }

// IsClosed returns whether the I/O object has been shut down.
func (t *TpIo) IsClosed() bool { return atomic.LoadInt32(&t.closed) != 0 }

// Shutdown marks the I/O object as closed and clears pending starts.
func (t *TpIo) Shutdown() {
	atomic.StoreInt32(&t.closed, 1)
	atomic.StoreInt32(&t.started, 0)
}

// Start records a StartThreadpoolIo call.
func (t *TpIo) Start() bool {
	if t.IsClosed() {
		return false
	}
	atomic.AddInt32(&t.started, 1)
	return true
}

// CancelPending clears any unconsumed StartThreadpoolIo bookkeeping.
func (t *TpIo) CancelPending() {
	atomic.StoreInt32(&t.started, 0)
}

// WaitAll blocks until all in-flight callbacks complete.
func (t *TpIo) WaitAll() { t.Pending.Wait() }

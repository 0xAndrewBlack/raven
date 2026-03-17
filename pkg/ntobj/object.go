// Package ntobj implements the in-process NT object manager - the architectural
// replacement for Wine's out-of-process wineserver. It owns:
//
//   - object lifetime via reference counting (NtClose / NtDuplicateObject),
//   - the named-object namespace (\BaseNamedObjects\...),
//   - the wait engine with correct Win32 semantics: WaitAny, atomic WaitAll
//     (no lost wakeups on auto-reset objects), timeouts, and abandoned mutants.
//
// Everything is serialized on a single manager mutex with one broadcast
// condition variable. This is intentionally simple and obviously correct;
// performance (avoiding the thundering herd) is a later optimization. Because it
// is pure Go with no guest/CPU dependencies, it is fully unit-testable on its
// own - unlike the loader/emulator paths that need real binaries.
package ntobj

import (
	"sync"
	"time"
)

// Win32 wait return codes.
const (
	WaitObject0      uint32 = 0x00000000
	WaitAbandoned0   uint32 = 0x00000080
	WaitTimeout      uint32 = 0x00000102
	WaitIOCompletion uint32 = 0x000000C0
	WaitFailed       uint32 = 0xFFFFFFFF
)

// Waitable is implemented by every kernel object that a thread can wait on.
// All methods are invoked with the owning Manager's lock held, so
// implementations must not lock or block.
type Waitable interface {
	// signaled reports whether the object is currently acquirable by thread tid.
	signaled(tid uint64) bool
	// satisfy performs the state change of a successful wait (auto-reset event
	// clears, semaphore decrements, mutant takes ownership). It is only called
	// when signaled(tid) is true - and for WaitAll only when every object is
	// simultaneously signaled. It reports whether the wait was satisfied by an
	// abandoned mutant.
	satisfy(tid uint64) (abandoned bool)
}

// Manager is the object manager instance (one per emulated machine/session).
type Manager struct {
	mu    sync.Mutex
	cond  *sync.Cond
	names map[string]*Object
}

// New creates an empty object manager.
func New() *Manager {
	m := &Manager{names: make(map[string]*Object)}
	m.cond = sync.NewCond(&m.mu)
	return m
}

// Object is a reference-counted kernel object. The payload carries the
// type-specific behavior; it may also implement Waitable.
type Object struct {
	mgr     *Manager
	name    string
	refs    int32
	payload interface{}
	onClose func()
}

// Payload returns the type-specific object behind this Object.
func (o *Object) Payload() interface{} { return o.payload }

// Name returns the object's namespace name ("" if anonymous).
func (o *Object) Name() string { return o.name }

// Refs returns the current reference count (for tests/diagnostics).
func (o *Object) Refs() int32 {
	o.mgr.mu.Lock()
	defer o.mgr.mu.Unlock()
	return o.refs
}

// Create makes a new anonymous object with refcount 1. onClose (may be nil) runs
// when the last reference is released.
func (m *Manager) Create(payload interface{}, onClose func()) *Object {
	return &Object{mgr: m, refs: 1, payload: payload, onClose: onClose}
}

// CreateNamed returns the object registered under name, creating it if absent.
// If the name already existed, the existing object is returned with its refcount
// incremented and existed=true (mirrors CreateEvent/Mutex returning
// ERROR_ALREADY_EXISTS). An empty name behaves like Create.
func (m *Manager) CreateNamed(name string, payload interface{}, onClose func()) (obj *Object, existed bool) {
	if name == "" {
		return m.Create(payload, onClose), false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if o, ok := m.names[name]; ok {
		o.refs++
		return o, true
	}
	o := &Object{mgr: m, name: name, refs: 1, payload: payload, onClose: onClose}
	m.names[name] = o
	return o, false
}

// Open looks up a named object and increments its refcount, or returns nil.
func (m *Manager) Open(name string) *Object {
	m.mu.Lock()
	defer m.mu.Unlock()
	if o, ok := m.names[name]; ok {
		o.refs++
		return o
	}
	return nil
}

// AddRef increments the reference count (NtDuplicateObject / handle inherit).
func (m *Manager) AddRef(o *Object) {
	m.mu.Lock()
	o.refs++
	m.mu.Unlock()
}

// Release decrements the reference count (NtClose). When it reaches zero the
// object is removed from the namespace and onClose is invoked. Returns the
// remaining count.
func (m *Manager) Release(o *Object) int32 {
	m.mu.Lock()
	o.refs--
	n := o.refs
	if n <= 0 {
		if o.name != "" {
			delete(m.names, o.name)
		}
	}
	m.mu.Unlock()
	if n <= 0 && o.onClose != nil {
		o.onClose()
	}
	return n
}

// Signal runs fn (which mutates object state under the lock) and then wakes all
// waiters. Object operations (SetEvent, ReleaseSemaphore, ...) funnel through
// here so a single, consistent locking discipline governs every transition.
func (m *Manager) Signal(fn func()) {
	m.mu.Lock()
	fn()
	m.cond.Broadcast()
	m.mu.Unlock()
}

// Wait blocks until one (waitAll=false) or all (waitAll=true) of the given
// objects are signaled and atomically satisfies them, or until the timeout
// elapses. timeout < 0 means INFINITE. Returns a Win32 wait code:
// WaitObject0(+index) / WaitAbandoned0(+index) / WaitTimeout.
//
// The WaitAll path is atomic: objects are satisfied only when ALL are
// simultaneously signaled, so an auto-reset object is never consumed while the
// thread goes on to block on another - the lost-wakeup bug of sequential waits.
func (m *Manager) Wait(objs []Waitable, waitAll bool, tid uint64, timeout time.Duration) uint32 {
	infinite := timeout < 0
	deadline := time.Now().Add(timeout)

	// A timer broadcasts at the deadline so the timed-out waiter wakes to return.
	var timer *time.Timer
	if !infinite {
		timer = time.AfterFunc(timeout, func() { m.cond.Broadcast() })
		defer timer.Stop()
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	for {
		if waitAll {
			all := true
			for _, o := range objs {
				if !o.signaled(tid) {
					all = false
					break
				}
			}
			if all {
				abandoned := false
				for _, o := range objs {
					if o.satisfy(tid) {
						abandoned = true
					}
				}
				if abandoned {
					return WaitAbandoned0
				}
				return WaitObject0
			}
		} else {
			for i, o := range objs {
				if o.signaled(tid) {
					ab := o.satisfy(tid)
					if ab {
						return WaitAbandoned0 + uint32(i)
					}
					return WaitObject0 + uint32(i)
				}
			}
		}

		if !infinite && !time.Now().Before(deadline) {
			return WaitTimeout
		}
		m.cond.Wait()
	}
}

// ---------------------------------------------------------------------------
// Concrete waitable object types.
// ---------------------------------------------------------------------------

// Event is a Win32 event. Manual-reset events stay signaled until Reset; an
// auto-reset event releases exactly one waiter and then clears.
type Event struct {
	manual bool
	state  bool
}

// NewEvent creates an event payload.
func NewEvent(manualReset, initial bool) *Event { return &Event{manual: manualReset, state: initial} }

func (e *Event) signaled(uint64) bool { return e.state }
func (e *Event) satisfy(uint64) bool {
	if !e.manual {
		e.state = false
	}
	return false
}

// Set/Reset/Pulse mutate state; call them via Manager.Signal.
func (e *Event) Set()   { e.state = true }
func (e *Event) Reset() { e.state = false }

// Semaphore is a counting semaphore with an upper bound.
type Semaphore struct {
	count int32
	max   int32
}

// NewSemaphore creates a semaphore payload.
func NewSemaphore(initial, max int32) *Semaphore { return &Semaphore{count: initial, max: max} }

func (s *Semaphore) signaled(uint64) bool { return s.count > 0 }
func (s *Semaphore) satisfy(uint64) bool  { s.count--; return false }

// Release adds n to the count (clamped to max) and returns the previous count
// and whether the addition fit. Call via Manager.Signal.
func (s *Semaphore) Release(n int32) (prev int32, ok bool) {
	prev = s.count
	if s.count+n > s.max {
		return prev, false
	}
	s.count += n
	return prev, true
}

// Count returns the current count (caller must hold the manager lock, e.g. via
// Signal or a test helper).
func (s *Semaphore) Count() int32 { return s.count }

// Mutant is a Win32 mutex: recursive ownership by a single thread, with
// abandoned semantics when the owner exits without releasing.
type Mutant struct {
	owner     uint64 // 0 = unowned
	recursion int32
	abandoned bool
}

// NewMutant creates a mutant payload, optionally initially owned by tid (0 = not).
func NewMutant(owner uint64) *Mutant {
	m := &Mutant{}
	if owner != 0 {
		m.owner = owner
		m.recursion = 1
	}
	return m
}

func (mu *Mutant) signaled(tid uint64) bool { return mu.owner == 0 || mu.owner == tid }
func (mu *Mutant) satisfy(tid uint64) bool {
	if mu.owner == tid {
		mu.recursion++
		return false
	}
	// owner == 0: take ownership
	mu.owner = tid
	mu.recursion = 1
	if mu.abandoned {
		mu.abandoned = false
		return true
	}
	return false
}

// Release drops one level of ownership; returns false if tid is not the owner.
// Call via Manager.Signal so waiters are woken when ownership is fully dropped.
func (mu *Mutant) Release(tid uint64) bool {
	if mu.owner != tid || mu.recursion == 0 {
		return false
	}
	mu.recursion--
	if mu.recursion == 0 {
		mu.owner = 0
	}
	return true
}

// Abandon marks the mutant abandoned if tid owned it (owner thread terminated
// without releasing). Call via Manager.Signal.
func (mu *Mutant) Abandon(tid uint64) {
	if mu.owner == tid {
		mu.owner = 0
		mu.recursion = 0
		mu.abandoned = true
	}
}

// Owner returns the current owning tid (0 = unowned).
func (mu *Mutant) Owner() uint64 { return mu.owner }

// Latch is a one-shot manual signal used for thread/process termination: once
// Signaled it stays signaled forever and satisfies all current and future
// waiters (NtWaitForSingleObject on a thread/process handle).
type Latch struct{ done bool }

// NewLatch creates an unsignaled latch.
func NewLatch() *Latch { return &Latch{} }

func (l *Latch) signaled(uint64) bool { return l.done }
func (l *Latch) satisfy(uint64) bool  { return false }

// Signal marks the latch permanently signaled. Call via Manager.Signal.
func (l *Latch) Signal() { l.done = true }

// IsSignaled reports the latch state (manager lock held).
func (l *Latch) IsSignaled() bool { return l.done }

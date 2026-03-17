package ntobj

// Thread and Process are the waitable NT objects for the process/thread layer
// . The actual execution is goroutine-backed elsewhere; here they
// provide the kernel-object behavior the wait engine needs:
//
//   - a handle waits as "signaled" forever once the thread/process has exited
//     (NtWaitForSingleObject on a thread/process handle), carrying the exit code,
//   - suspend/resume counts (NtSuspendThread / NtResumeThread).
//
// They reuse Latch for the one-shot exit signal, so they compose with WaitAll /
// WaitAny exactly like every other waitable object.

// Thread is a waitable thread object.
type Thread struct {
	tid          uint64
	latch        Latch
	exitCode     uint32
	exited       bool
	suspendCount int32
}

// NewThread creates a running (not suspended, not exited) thread object.
func NewThread(tid uint64) *Thread { return &Thread{tid: tid} }

// TID returns the thread id.
func (t *Thread) TID() uint64 { return t.tid }

func (t *Thread) signaled(uint64) bool { return t.latch.done }
func (t *Thread) satisfy(uint64) bool  { return false } // thread exit is a permanent signal

// Exit marks the thread terminated with the given code and signals all current
// and future waiters. Call via Manager.Signal.
func (t *Thread) Exit(code uint32) {
	if t.exited {
		return
	}
	t.exited = true
	t.exitCode = code
	t.latch.Signal()
}

// ExitCode reports the exit code and whether the thread has exited.
func (t *Thread) ExitCode() (code uint32, exited bool) { return t.exitCode, t.exited }

// Suspend increments the suspend count and returns the previous value
// (NtSuspendThread returns the previous suspend count). Call via Manager.Signal.
func (t *Thread) Suspend() int32 {
	prev := t.suspendCount
	t.suspendCount++
	return prev
}

// Resume decrements the suspend count (not below zero) and returns the previous
// value (NtResumeThread returns the previous suspend count). Call via Signal.
func (t *Thread) Resume() int32 {
	prev := t.suspendCount
	if t.suspendCount > 0 {
		t.suspendCount--
	}
	return prev
}

// SuspendCount returns the current suspend count (manager lock held).
func (t *Thread) SuspendCount() int32 { return t.suspendCount }

// IsRunnable reports whether the thread is neither exited nor suspended.
func (t *Thread) IsRunnable() bool { return !t.exited && t.suspendCount == 0 }

// Process is a waitable process object: signaled forever once it exits.
type Process struct {
	pid      uint64
	latch    Latch
	exitCode uint32
	exited   bool
	threads  []*Thread
}

// NewProcess creates a running process object.
func NewProcess(pid uint64) *Process { return &Process{pid: pid} }

// PID returns the process id.
func (p *Process) PID() uint64 { return p.pid }

func (p *Process) signaled(uint64) bool { return p.latch.done }
func (p *Process) satisfy(uint64) bool  { return false }

// AddThread registers a thread with the process (manager lock held).
func (p *Process) AddThread(t *Thread) { p.threads = append(p.threads, t) }

// Threads returns the registered threads (manager lock held).
func (p *Process) Threads() []*Thread { return p.threads }

// Terminate marks the process exited with the given code, exits all of its
// not-yet-exited threads, and signals waiters. Call via Manager.Signal.
func (p *Process) Terminate(code uint32) {
	if p.exited {
		return
	}
	p.exited = true
	p.exitCode = code
	for _, t := range p.threads {
		t.Exit(code)
	}
	p.latch.Signal()
}

// ExitCode reports the exit code and whether the process has exited.
func (p *Process) ExitCode() (code uint32, exited bool) { return p.exitCode, p.exited }

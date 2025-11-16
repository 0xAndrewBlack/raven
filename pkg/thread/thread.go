package thread

import (
	"errors"
	"sync"

	"github.com/mirkobrombin/Raven/pkg/arch"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/x64"

	ravelog "github.com/mirkobrombin/Raven/pkg/log"
)

// Thread represents a guest hardware thread (hart).
type Thread struct {
	ID  int
	CPU arch.CPU
}

// FutexWaiter represents a goroutine waiting on a futex.
type FutexWaiter struct {
	addr uint64
	ch   chan struct{}
}

// Manager handles thread creation via clone().
type Manager struct {
	mu      sync.Mutex
	threads []*Thread
	nextID  int
	mem     *mmu.MMU
	handler arch.SyscallHandler
	wg      sync.WaitGroup

	// Thread stack tracking: base → end (base+size). Protects stacks from
	// premature munmap by the parent (Rust/glibc frees the stack right after
	// clone3, before the child goroutine has had a chance to run).
	stackMu sync.Mutex
	stacks  map[uint64]uint64 // base → base+size

	// Futex state
	futexMu      sync.Mutex
	futexWaiters []FutexWaiter
}

// NewManager creates a thread manager sharing the given MMU and syscall handler.
func NewManager(mem *mmu.MMU, handler arch.SyscallHandler) *Manager {
	return &Manager{
		mem:     mem,
		handler: handler,
		nextID:  2,
		stacks:  make(map[uint64]uint64),
	}
}

// MainThread registers an existing CPU as the initial thread (tid=1, matching PID).
func (m *Manager) MainThread(c arch.CPU) *Thread {
	c.SetSyscallHandler(m.handler)
	t := &Thread{ID: 1, CPU: c}
	m.threads = append(m.threads, t)
	return t
}

// Clone creates a new thread (goroutine) starting at childPC with a new stack.
// Shares the same MMU (as Linux clone with CLONE_VM).
// tls is the thread-local storage base address (0 = inherit parent's TLS).
// stackBase/stackSize: the stack region allocated by the parent for this thread.
// If non-zero, it is registered as a protected stack so that a premature
// munmap by the parent (common in Rust/glibc clone patterns) is silently
// ignored until the thread has had a chance to run.
func (m *Manager) Clone(parentCPU arch.CPU, childPC, childSP, tls, stackBase, stackSize uint64) (int, error) {
	m.mu.Lock()
	tid := m.nextID
	m.nextID++
	m.mu.Unlock()

	c := parentCPU.CloneForThread()
	c.SetPC(childPC)
	c.SetSP(childSP)
	if tls != 0 {
		c.SetTLS(tls)
	}
	c.SetSyscallHandler(m.handler)
	c.SetSyscallReturn(0) // child returns 0

	if stackBase != 0 && stackSize != 0 {
		m.registerStack(stackBase, stackSize)
	}

	t := &Thread{ID: tid, CPU: c}
	m.mu.Lock()
	m.threads = append(m.threads, t)
	m.mu.Unlock()

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		ravelog.Logf("[govm] thread %d start: PC=0x%x SP=0x%x TLS=0x%x\n",
			tid, c.GetPC(), c.GetSP(), c.GetTLS())
		if err := c.Run(); err != nil {
			ravelog.Logf("[govm] thread %d crashed: %v (PC=0x%x SP=0x%x TLS=0x%x)\n",
				tid, err, c.GetPC(), c.GetSP(), c.GetTLS())
		}
		// When the thread exits, unregister its stack so future munmaps succeed.
		if stackBase != 0 && stackSize != 0 {
			m.unregisterStack(stackBase)
		}
	}()

	return tid, nil
}

// registerStack marks [base, base+size) as a live thread stack.
func (m *Manager) registerStack(base, size uint64) {
	m.stackMu.Lock()
	m.stacks[base] = base + size
	m.stackMu.Unlock()
}

// unregisterStack removes the stack entry for base.
func (m *Manager) unregisterStack(base uint64) {
	m.stackMu.Lock()
	delete(m.stacks, base)
	m.stackMu.Unlock()
}

// IsThreadStack returns true if [addr, addr+length) overlaps any live thread stack.
// Used by sysMunmap to skip premature stack frees from the parent thread.
func (m *Manager) IsThreadStack(addr, length uint64) bool {
	end := addr + length
	m.stackMu.Lock()
	defer m.stackMu.Unlock()
	for base, stackEnd := range m.stacks {
		// Overlap check: not (end <= base || addr >= stackEnd)
		if !(end <= base || addr >= stackEnd) {
			return true
		}
	}
	return false
}

// FutexWait blocks the current goroutine until FutexWake is called on the same address.
func (m *Manager) FutexWait(addr uint64, expectedVal uint32) {
	ch := make(chan struct{}, 1)
	m.futexMu.Lock()
	m.futexWaiters = append(m.futexWaiters, FutexWaiter{addr: addr, ch: ch})
	m.futexMu.Unlock()
	<-ch // block until woken
}

// FutexWake wakes up to `count` waiters on the given address. Returns the number woken.
func (m *Manager) FutexWake(addr uint64, count int) int {
	m.futexMu.Lock()
	defer m.futexMu.Unlock()

	woken := 0
	remaining := m.futexWaiters[:0]
	for _, w := range m.futexWaiters {
		if w.addr == addr && woken < count {
			close(w.ch)
			woken++
		} else {
			remaining = append(remaining, w)
		}
	}
	m.futexWaiters = remaining
	return woken
}

// SetChildTLS sets the thread-local storage pointer for a child thread.
func (m *Manager) SetChildTLS(tid int, tls uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.threads {
		if t.ID == tid {
			t.CPU.SetTLS(tls)
			return
		}
	}
}

// GetTID returns the thread ID for the given CPU, or 1 if not found.
func (m *Manager) GetTID(c arch.CPU) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.threads {
		if t.CPU == c {
			return t.ID
		}
	}
	return 1 // default to main thread TID
}

// Wait blocks until all spawned threads finish.
func (m *Manager) Wait() {
	m.wg.Wait()
}

// CloneWin32Thread creates a new thread for Win32 CreateThread semantics.
// It sets the first argument register (RCX on x64) to lpParam.
// tebAddr, if non-zero, is the guest address of a per-thread TEB; the
// thread's GS segment register is pointed there.
// The returned channel is closed when the thread exits.
func (m *Manager) CloneWin32Thread(parentCPU arch.CPU, startAddr, lpParam, stackBase, stackSize, tebAddr uint64) (int, chan struct{}, error) {
	m.mu.Lock()
	tid := m.nextID
	m.nextID++
	m.mu.Unlock()

	c := parentCPU.CloneForThread()
	c.SetPC(startAddr)
	// x64 ABI: at function entry RSP must be 8 mod 16 (as if arrived via CALL,
	// which pushed an 8-byte return address onto a previously 16-aligned stack).
	sp := stackBase + stackSize - 8
	c.SetSP(sp)
	// Write null return address so a bare ret from the thread function faults at
	// address 0x0 (which we treat as clean normal exit in the Run loop).
	m.mem.Write64Raw(sp, 0)
	// Set RCX = lpParam (Win32 calling convention: first arg in RCX)
	if xc, ok := c.(*x64.CPU); ok {
		xc.WriteReg(x64.RCX, lpParam)
		if tebAddr != 0 {
			xc.SetGSBase(tebAddr)
		}
	}
	c.SetSyscallHandler(m.handler)

	if stackBase != 0 && stackSize != 0 {
		m.registerStack(stackBase, stackSize)
	}

	t := &Thread{ID: tid, CPU: c}
	m.mu.Lock()
	m.threads = append(m.threads, t)
	m.mu.Unlock()

	done := make(chan struct{})
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		defer close(done)
		ravelog.Logf("[govm] win32-thread %d start: PC=0x%x SP=0x%x\n", tid, c.GetPC(), c.GetSP())
		if err := c.Run(); err != nil {
			// A fetch fault at address 0x0 means the thread function returned
			// through the null sentinel return address - treat as clean exit.
			var f *mmu.Fault
			if errors.As(err, &f) && f.Addr == 0 {
				ravelog.Logf("[govm] win32-thread %d exited normally (returned)\n", tid)
			} else {
				ravelog.Logf("[govm] win32-thread %d exited: %v\n", tid, err)
			}
		}
		if stackBase != 0 {
			m.unregisterStack(stackBase)
		}
	}()

	return tid, done, nil
}

// CloneWin32ThreadEx is like CloneWin32Thread but accepts up to four
// arguments that are mapped to x64 registers RCX, RDX, R8, R9 (Microsoft
// x64 calling convention). Used for thread-pool callbacks with multiple params.
func (m *Manager) CloneWin32ThreadEx(parentCPU arch.CPU, startAddr, stackBase, stackSize, tebAddr uint64, args ...uint64) (int, chan struct{}, error) {
	m.mu.Lock()
	tid := m.nextID
	m.nextID++
	m.mu.Unlock()

	c := parentCPU.CloneForThread()
	c.SetPC(startAddr)
	sp := stackBase + stackSize - 8
	c.SetSP(sp)
	m.mem.Write64Raw(sp, 0)
	if xc, ok := c.(*x64.CPU); ok {
		regs := [4]int{x64.RCX, x64.RDX, x64.R8, x64.R9}
		for i := 0; i < len(args) && i < 4; i++ {
			xc.WriteReg(regs[i], args[i])
		}
		if tebAddr != 0 {
			xc.SetGSBase(tebAddr)
		}
	}
	c.SetSyscallHandler(m.handler)

	if stackBase != 0 && stackSize != 0 {
		m.registerStack(stackBase, stackSize)
	}

	t := &Thread{ID: tid, CPU: c}
	m.mu.Lock()
	m.threads = append(m.threads, t)
	m.mu.Unlock()

	done := make(chan struct{})
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		defer close(done)
		ravelog.Logf("[govm] win32-thread %d start: PC=0x%x SP=0x%x\n", tid, c.GetPC(), c.GetSP())
		if err := c.Run(); err != nil {
			var f *mmu.Fault
			if errors.As(err, &f) && f.Addr == 0 {
				ravelog.Logf("[govm] win32-thread %d exited normally (returned)\n", tid)
			} else {
				ravelog.Logf("[govm] win32-thread %d exited: %v\n", tid, err)
			}
		}
		if stackBase != 0 {
			m.unregisterStack(stackBase)
		}
	}()

	return tid, done, nil
}
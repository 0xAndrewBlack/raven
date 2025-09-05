package thread

import (
	"fmt"
	"sync"

	"github.com/mirkobrombin/go-vm/pkg/cpu"
	"github.com/mirkobrombin/go-vm/pkg/mmu"
)

// Thread represents a guest hardware thread (hart).
type Thread struct {
	ID  int
	CPU *cpu.CPU
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
	handler cpu.SyscallHandler
	wg      sync.WaitGroup

	// Futex state
	futexMu      sync.Mutex
	futexWaiters []FutexWaiter
}

// NewManager creates a thread manager sharing the given MMU and syscall handler.
func NewManager(mem *mmu.MMU, handler cpu.SyscallHandler) *Manager {
	return &Manager{
		mem:     mem,
		handler: handler,
		nextID:  1,
	}
}

// MainThread creates the initial thread (tid=0) with the given entry and stack.
func (m *Manager) MainThread(entry, sp uint64) *Thread {
	c := cpu.New(m.mem)
	c.SetPC(entry)
	c.SetSP(sp)
	c.Syscall = m.handler
	t := &Thread{ID: 0, CPU: c}
	m.threads = append(m.threads, t)
	return t
}

// Clone creates a new thread (goroutine) starting at childPC with a new stack.
// Shares the same MMU (as Linux clone with CLONE_VM).
func (m *Manager) Clone(parentCPU *cpu.CPU, childPC, childSP uint64) (int, error) {
	m.mu.Lock()
	tid := m.nextID
	m.nextID++
	m.mu.Unlock()

	c := cpu.New(m.mem)
	// Copy register state from parent
	c.X = parentCPU.X
	// Copy FPU state
	parentFPU := parentCPU.FPUState()
	childFPU := c.FPUState()
	childFPU.F = parentFPU.F
	childFPU.FCSR = parentFPU.FCSR

	c.SetPC(childPC)
	c.SetSP(childSP)
	c.Syscall = m.handler
	// Child returns 0 in a0
	c.X[10] = 0

	t := &Thread{ID: tid, CPU: c}
	m.mu.Lock()
	m.threads = append(m.threads, t)
	m.mu.Unlock()

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		if err := c.Run(); err != nil {
			fmt.Printf("[govm] thread %d exited: %v\n", tid, err)
		}
	}()

	return tid, nil
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

// SetChildTLS sets the tp register (x4) for a child thread identified by tid.
func (m *Manager) SetChildTLS(tid int, tls uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.threads {
		if t.ID == tid {
			t.CPU.X[4] = tls // tp register
			return
		}
	}
}

// Wait blocks until all spawned threads finish.
func (m *Manager) Wait() {
	m.wg.Wait()
}

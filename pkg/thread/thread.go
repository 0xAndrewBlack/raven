package thread

import (
"fmt"
"sync"

"github.com/mirkobrombin/go-vm/pkg/arch"
"github.com/mirkobrombin/go-vm/pkg/mmu"
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

// Futex state
futexMu      sync.Mutex
futexWaiters []FutexWaiter
}

// NewManager creates a thread manager sharing the given MMU and syscall handler.
func NewManager(mem *mmu.MMU, handler arch.SyscallHandler) *Manager {
return &Manager{
mem:     mem,
handler: handler,
nextID:  1,
}
}

// MainThread registers an existing CPU as the initial thread (tid=0).
func (m *Manager) MainThread(c arch.CPU) *Thread {
c.SetSyscallHandler(m.handler)
t := &Thread{ID: 0, CPU: c}
m.threads = append(m.threads, t)
return t
}

// Clone creates a new thread (goroutine) starting at childPC with a new stack.
// Shares the same MMU (as Linux clone with CLONE_VM).
func (m *Manager) Clone(parentCPU arch.CPU, childPC, childSP uint64) (int, error) {
m.mu.Lock()
tid := m.nextID
m.nextID++
m.mu.Unlock()

c := parentCPU.CloneForThread()
c.SetPC(childPC)
c.SetSP(childSP)
c.SetSyscallHandler(m.handler)
c.SetSyscallReturn(0) // child returns 0

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

// Wait blocks until all spawned threads finish.
func (m *Manager) Wait() {
m.wg.Wait()
}

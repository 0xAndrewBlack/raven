//go:build guest_windows

package ntapi

import (
	"errors"
	"fmt"
	"sync"

	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/x64"
)

var (
	ErrNoActiveUserCallback = errors.New("no active user callback")
	ErrUserCallbackWrongCPU = errors.New("active user callback belongs to a different CPU")
)

const StatusNoCallbackActive uint32 = 0xC0000258

type userCallbackState struct {
	snapshot   x64.Snapshot
	mode32     bool
	completion UserCallbackCompletion
}

type UserCallbackCompletion func(cpu *x64.CPU, callbackReturn UserCallbackReturn)

// UserCallbackManager owns nested callback state for each CPU.
// Its zero value is ready for use.
type UserCallbackManager struct {
	mu        sync.Mutex
	stacks    map[*x64.CPU][]userCallbackState
	completed map[*x64.CPU][]UserCallbackReturn
}

// Begin saves the current CPU state, builds the architecture-specific callback
// frame, and transfers control to the user callback dispatcher.
func (m *UserCallbackManager) Begin(cpu *x64.CPU, mem *mmu.MMU, dispatcher uint64, callbackIndex uint32, input []byte) (UserCallbackFrame, error) {
	return m.BeginWithCompletion(cpu, mem, dispatcher, callbackIndex, input, nil)
}

func (m *UserCallbackManager) BeginWithCompletion(cpu *x64.CPU, mem *mmu.MMU, dispatcher uint64, callbackIndex uint32, input []byte, completion UserCallbackCompletion) (UserCallbackFrame, error) {
	if cpu == nil {
		return UserCallbackFrame{}, fmt.Errorf("begin user callback: nil CPU")
	}
	if mem == nil {
		return UserCallbackFrame{}, fmt.Errorf("begin user callback: nil memory")
	}
	if dispatcher == 0 {
		return UserCallbackFrame{}, fmt.Errorf("begin user callback: nil dispatcher")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	snapshot := cpu.Snapshot()
	var (
		frame UserCallbackFrame
		err   error
	)
	if cpu.Mode32 {
		if dispatcher > uint64(^uint32(0)) {
			return UserCallbackFrame{}, fmt.Errorf("begin PE32 user callback: dispatcher 0x%x exceeds 32-bit address space", dispatcher)
		}
		frame, err = BuildUserCallbackFrame32(mem, cpu.GetSP(), callbackIndex, input)
	} else {
		frame, err = BuildUserCallbackFrame64(mem, cpu.GetSP(), callbackIndex, input, cpu.GetPC())
	}
	if err != nil {
		return UserCallbackFrame{}, fmt.Errorf("begin user callback: %w", err)
	}

	if m.stacks == nil {
		m.stacks = make(map[*x64.CPU][]userCallbackState)
	}
	m.stacks[cpu] = append(m.stacks[cpu], userCallbackState{
		snapshot:   snapshot,
		mode32:     cpu.Mode32,
		completion: completion,
	})
	cpu.SetSP(frame.StackPointer)
	cpu.SetPC(dispatcher)
	return frame, nil
}

// NtCallbackReturn completes the innermost callback for cpu and restores the
// execution state that was active before Begin.
func (m *UserCallbackManager) NtCallbackReturn(cpu *x64.CPU, result, resultLength, callbackStatus uint64) (UserCallbackReturn, error) {
	if cpu == nil {
		return UserCallbackReturn{}, fmt.Errorf("NtCallbackReturn: nil CPU")
	}

	m.mu.Lock()

	stack := m.stacks[cpu]
	if len(stack) == 0 {
		hasOtherCallbacks := len(m.stacks) != 0
		m.mu.Unlock()
		if hasOtherCallbacks {
			return UserCallbackReturn{}, fmt.Errorf("NtCallbackReturn: %w", ErrUserCallbackWrongCPU)
		}
		return UserCallbackReturn{}, fmt.Errorf("NtCallbackReturn: %w", ErrNoActiveUserCallback)
	}

	state := stack[len(stack)-1]
	stack = stack[:len(stack)-1]
	if len(stack) == 0 {
		delete(m.stacks, cpu)
	} else {
		m.stacks[cpu] = stack
	}

	var callbackReturn UserCallbackReturn
	if state.mode32 {
		callbackReturn = ParseUserCallbackReturn32(result, resultLength, callbackStatus)
	} else {
		callbackReturn = ParseUserCallbackReturn64(result, resultLength, callbackStatus)
	}
	if state.completion == nil {
		if m.completed == nil {
			m.completed = make(map[*x64.CPU][]UserCallbackReturn)
		}
		m.completed[cpu] = append(m.completed[cpu], callbackReturn)
	}
	cpu.Restore(state.snapshot)
	m.mu.Unlock()
	if state.completion != nil {
		state.completion(cpu, callbackReturn)
	}
	return callbackReturn, nil
}

// TakeReturn removes the oldest completed return for cpu.
func (m *UserCallbackManager) TakeReturn(cpu *x64.CPU) (UserCallbackReturn, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	returns := m.completed[cpu]
	if len(returns) == 0 {
		return UserCallbackReturn{}, false
	}
	callbackReturn := returns[0]
	if len(returns) == 1 {
		delete(m.completed, cpu)
	} else {
		m.completed[cpu] = returns[1:]
	}
	return callbackReturn, true
}

// Depth returns the number of active callbacks owned by cpu.
func (m *UserCallbackManager) Depth(cpu *x64.CPU) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.stacks[cpu])
}

// BeginUserCallback starts a callback owned by this dispatcher.
func (d *Dispatcher) BeginUserCallback(cpu *x64.CPU, dispatcher uint64, callbackIndex uint32, input []byte) (UserCallbackFrame, error) {
	if d == nil || d.ctx == nil {
		return UserCallbackFrame{}, fmt.Errorf("begin user callback: nil dispatcher")
	}
	return d.userCallbacks.Begin(cpu, d.ctx.Mem, dispatcher, callbackIndex, input)
}

func (d *Dispatcher) BeginUserCallbackWithCompletion(cpu *x64.CPU, dispatcher uint64, callbackIndex uint32, input []byte, completion UserCallbackCompletion) (UserCallbackFrame, error) {
	if d == nil || d.ctx == nil {
		return UserCallbackFrame{}, fmt.Errorf("begin user callback: nil dispatcher")
	}
	return d.userCallbacks.BeginWithCompletion(cpu, d.ctx.Mem, dispatcher, callbackIndex, input, completion)
}

// TakeUserCallbackReturn removes the oldest completed callback result for cpu.
func (d *Dispatcher) TakeUserCallbackReturn(cpu *x64.CPU) (UserCallbackReturn, bool) {
	if d == nil {
		return UserCallbackReturn{}, false
	}
	return d.userCallbacks.TakeReturn(cpu)
}

func (d *Dispatcher) handleNtCallbackReturn(ctx *TrapContext) uint32 {
	cpu, ok := ctx.CPU.(*x64.CPU)
	if !ok {
		return StatusInvalidParameter
	}

	result := ctx.Arg(0)
	resultLength := ctx.Arg(1)
	callbackStatus := ctx.Arg(2)
	callbackReturn, err := d.userCallbacks.NtCallbackReturn(cpu, result, resultLength, callbackStatus)
	if err != nil {
		if errors.Is(err, ErrNoActiveUserCallback) || errors.Is(err, ErrUserCallbackWrongCPU) {
			return StatusNoCallbackActive
		}
		return StatusInvalidParameter
	}

	ctx.ReturnOverridden = true
	ctx.PCRedirected = true
	return callbackReturn.Status
}

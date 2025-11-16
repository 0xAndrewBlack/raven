// Package x64jit provides JIT compilation for the x86-64 CPU emulator.
package x64

import (
	"github.com/mirkobrombin/Raven/pkg/jit"
	"github.com/mirkobrombin/Raven/pkg/mmu"
)

// JITCompiler wraps the JIT cache and provides CPU integration.
type JITCompiler struct {
	cache *jit.Cache
	cpu   *CPU
}

// NewJITCompiler creates a JIT compiler for the given CPU.
func NewJITCompiler(cpu *CPU, mem *mmu.MMU) *JITCompiler {
	return &JITCompiler{
		cache: jit.NewCache(mem),
		cpu:   cpu,
	}
}

// Enable hooks up the JIT compiler to the CPU's PreStep hook.
func (j *JITCompiler) Enable() {
	j.cpu.PreStep = j.step
}

// Disable removes the JIT hook.
func (j *JITCompiler) Disable() {
	j.cpu.PreStep = nil
}

// step is called before each instruction.
// It returns true if the JIT handled the block.
func (j *JITCompiler) step(c *CPU) bool {
	fn := j.cache.Lookup(c.RIP)
	if fn == nil {
		return false
	}

	// Create JIT state from CPU
	state := &jit.State{
		Regs:   &c.Regs,
		RIP:    &c.RIP,
		Rflags: &c.Rflags,
		Mem:    c.mem,
		XMM:    &c.XMM,
		FSBase: c.fsBase,
		GSBase: c.gsBase,
	}

	// Execute compiled block
	err := fn(state)
	if err != nil {
		// JIT error - fall back to interpreter
		return false
	}

	// Update segment bases from state (they might have changed)
	c.fsBase = state.FSBase
	c.gsBase = state.GSBase

	// If trap was set, return to interpreter for syscall/vmcall handling
	if state.Trap {
		return false
	}

	return true
}

// Invalidate removes compiled code for the given address range.
func (j *JITCompiler) Invalidate(addr uint64) {
	j.cache.Invalidate(addr)
}

// Stats returns compilation statistics.
func (j *JITCompiler) Stats() (compiledBlocks int, hotBlocks int) {
	// Would need to expose stats from jit.Cache
	return 0, 0
}

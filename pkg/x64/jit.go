// Package x64jit provides JIT compilation for the x86-64 CPU emulator.
package x64

import (
	"os"

	ravelog "github.com/mirkobrombin/Raven/pkg/log"

	"github.com/mirkobrombin/Raven/pkg/jit"
	"github.com/mirkobrombin/Raven/pkg/mmu"
)

// JITCompiler wraps the JIT cache and provides CPU integration.
type JITCompiler struct {
	cache             *jit.Cache
	cpu               *CPU
	fast              [8192]jitFastEntry
	state             jit.State
	mappingGeneration uint64
}

type jitFastEntry struct {
	rip   uint64
	block *jit.Block
	hits  uint8
	valid bool
}

// NewJITCompiler creates a JIT compiler for the given CPU.
func NewJITCompiler(cpu *CPU, mem *mmu.MMU) *JITCompiler {
	compiler := &JITCompiler{
		cache: jit.NewCacheMode(mem, cpu.Mode32),
		cpu:   cpu,
	}
	compiler.state = jit.State{
		Regs:   &cpu.Regs,
		RIP:    &cpu.RIP,
		Rflags: &cpu.Rflags,
		Mem:    mem,
		XMM:    &cpu.XMM,
		FPUST:  &cpu.fpuST,
		FPUTop: &cpu.fpuTop,
		FPUCW:  &cpu.fpuCW,
		FPUSW:  &cpu.fpuSW,
		FPUTW:   &cpu.fpuTW,
		Mode32:  cpu.Mode32,
		Instret: &cpu.instret,
	}
	compiler.mappingGeneration = mem.MappingGeneration()
	if os.Getenv("RAVEN_JIT_NATIVE") != "" {
		if compiler.cache.EnableNativeCodegen() {
			ravelog.Logf("[jit] native x86-64 codegen enabled\n")
		} else {
			ravelog.Logf("[jit] native codegen unavailable, using closure backend\n")
		}
	}
	return compiler
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
	mappingGeneration := c.mem.MappingGeneration()
	if mappingGeneration&1 != 0 {
		return false
	}
	if mappingGeneration != j.mappingGeneration {
		j.cache.Reset()
		clear(j.fast[:])
		j.state.InvalidatePageCache()
		j.mappingGeneration = mappingGeneration
	}
	rip := c.RIP
	entry := &j.fast[(rip>>1)&uint64(len(j.fast)-1)]
	if entry.valid && entry.rip == rip {
		if entry.hits < jit.CompileThreshold {
			entry.hits++
			return false
		}
		if entry.hits > jit.CompileThreshold && entry.block == nil {
			return false
		}
		return j.execute(c, entry)
	}
	// Never evict a compiled block head for a colliding new RIP: every
	// interpreted instruction passes through here, and letting mid-block
	// RIPs displace hot entries makes the whole table thrash.
	if entry.valid && entry.block != nil {
		return false
	}
	*entry = jitFastEntry{rip: rip, hits: 1, valid: true}
	return false
}

func (j *JITCompiler) execute(c *CPU, entry *jitFastEntry) bool {
	block := entry.block
	if block == nil {
		if entry.hits == jit.CompileThreshold {
			entry.block = j.cache.Compile(c.RIP)
			entry.hits++
			block = entry.block
		}
	} else if !block.Valid() {
		// The code pages backing this block were written since compilation:
		// drop it and let the hot path recompile from the fresh bytes.
		j.cache.Drop(entry.rip)
		entry.block = nil
		entry.hits = jit.CompileThreshold - 1
		return false
	}
	if block == nil {
		return false
	}

	// Create JIT state from CPU
	state := &j.state
	state.FSBase = c.fsBase
	state.GSBase = c.gsBase
	state.Fallback = false
	state.Trap = false

	// Execute compiled block
	err := block.Run(state)
	if err != nil {
		// JIT error, fall back to interpreter
		return false
	}

	if !state.Trap && !state.Fallback {
		// Block chaining: keep running already-compiled successors without
		// bouncing through the per-instruction PreStep machinery. Bounded so
		// interrupts and mapping changes still get a look-in.
		for chained := 0; chained < 64; chained++ {
			next := &j.fast[(c.RIP>>1)&uint64(len(j.fast)-1)]
			if !next.valid || next.rip != c.RIP || next.block == nil {
				break
			}
			if !next.block.Valid() {
				j.cache.Drop(next.rip)
				next.block = nil
				next.hits = jit.CompileThreshold - 1
				break
			}
			if err := next.block.Run(state); err != nil {
				break
			}
			if state.Trap || state.Fallback {
				break
			}
		}
	}

	// Update segment bases from state (they might have changed)
	c.fsBase = state.FSBase
	c.gsBase = state.GSBase

	// If trap was set, return to interpreter for syscall/vmcall handling
	if state.Trap {
		return false
	}
	if state.Fallback {
		return false
	}

	return true
}

// Invalidate removes compiled code for the given address range.
func (j *JITCompiler) Invalidate(addr uint64) {
	j.cache.Invalidate(addr)
	page := addr &^ (mmu.PageSize - 1)
	for i := range j.fast {
		if j.fast[i].valid && j.fast[i].rip&^(mmu.PageSize-1) == page {
			j.fast[i] = jitFastEntry{}
		}
	}
}

// Stats returns compilation statistics.
func (j *JITCompiler) Stats() (compiledBlocks int, hotBlocks int) {
	// Would need to expose stats from jit.Cache
	return 0, 0
}

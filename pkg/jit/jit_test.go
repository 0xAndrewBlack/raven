package jit_test

import (
	"testing"

	"github.com/mirkobrombin/Raven/pkg/jit"
	"github.com/mirkobrombin/Raven/pkg/mmu"
)

func newTestMMU() *mmu.MMU {
	m := mmu.New()
	// Map a test page at 0x1000
	m.MapRange(0x1000, 0x1000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	return m
}

func writeCode(m *mmu.MMU, addr uint64, code []byte) {
	for i, b := range code {
		page := (addr + uint64(i)) &^ (mmu.PageSize - 1)
		m.MapRange(page, page, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
		m.Write8(addr+uint64(i), b)
	}
}

// Test MOV reg, imm
func TestJIT_MovRegImm(t *testing.T) {
	m := newTestMMU()
	// MOV RAX, 42 (0xB8 0x2A 0x00 0x00 0x00)
	writeCode(m, 0x1000, []byte{0xB8, 0x2A, 0x00, 0x00, 0x00})
	// MOV RBX, 100 (0xBB 0x64 0x00 0x00 0x00)
	writeCode(m, 0x1005, []byte{0xBB, 0x64, 0x00, 0x00, 0x00})
	// RET (0xC3)
	writeCode(m, 0x100A, []byte{0xC3})

	cache := jit.NewCache(m)

	// Force compilation by calling Lookup multiple times
	var fn jit.CompiledBlock
	for i := 0; i < jit.CompileThreshold+5; i++ {
		fn = cache.Lookup(0x1000)
	}

	if fn == nil {
		t.Fatal("JIT did not compile the block")
	}

	regs := [16]uint64{}
	rflags := uint64(0)
	state := &jit.State{
		Regs:   &regs,
		RIP:    new(uint64),
		Rflags: &rflags,
		Mem:    m,
		XMM:    &[16][2]uint64{},
	}
	*state.RIP = 0x1000

	err := fn(state)
	if err != nil {
		t.Fatalf("JIT execution failed: %v", err)
	}

	if regs[0] != 42 { // RAX
		t.Errorf("RAX = %d, want 42", regs[0])
	}
	if regs[3] != 100 { // RBX
		t.Errorf("RBX = %d, want 100", regs[3])
	}
}

// Test ADD reg, reg
func TestJIT_AddRegReg(t *testing.T) {
	m := newTestMMU()
	// MOV RAX, 10 (0xB8 0x0A 0x00 0x00 0x00)
	writeCode(m, 0x2000, []byte{0xB8, 0x0A, 0x00, 0x00, 0x00})
	// MOV RBX, 32 (0xBB 0x20 0x00 0x00 0x00)
	writeCode(m, 0x2005, []byte{0xBB, 0x20, 0x00, 0x00, 0x00})
	// ADD RAX, RBX (0x48 0x01 0xD8)
	writeCode(m, 0x200A, []byte{0x48, 0x01, 0xD8})
	// RET (0xC3)
	writeCode(m, 0x200D, []byte{0xC3})

	cache := jit.NewCache(m)

	var fn jit.CompiledBlock
	for i := 0; i < jit.CompileThreshold+5; i++ {
		fn = cache.Lookup(0x2000)
	}

	if fn == nil {
		t.Fatal("JIT did not compile the block")
	}

	regs := [16]uint64{}
	rflags := uint64(0)
	state := &jit.State{
		Regs:   &regs,
		RIP:    new(uint64),
		Rflags: &rflags,
		Mem:    m,
		XMM:    &[16][2]uint64{},
	}
	*state.RIP = 0x2000

	err := fn(state)
	if err != nil {
		t.Fatalf("JIT execution failed: %v", err)
	}

	if regs[0] != 42 { // RAX = 10 + 32
		t.Errorf("RAX = %d, want 42", regs[0])
	}
}

// Test TEST instruction and flags
func TestJIT_Jcc(t *testing.T) {
	m := newTestMMU()
	// MOV RAX, 5 (0xB8 0x05 0x00 0x00 0x00)
	writeCode(m, 0x3000, []byte{0xB8, 0x05, 0x00, 0x00, 0x00})
	// TEST RAX, RAX (0x48 0x85 0xC0) - clears ZF (5 & 5 != 0)
	writeCode(m, 0x3005, []byte{0x48, 0x85, 0xC0})
	// RET (0xC3)
	writeCode(m, 0x3008, []byte{0xC3})

	cache := jit.NewCache(m)

	var fn jit.CompiledBlock
	// Execute multiple times to trigger compilation
	for i := 0; i < jit.CompileThreshold+5; i++ {
		fn = cache.Lookup(0x3000)
	}

	if fn == nil {
		t.Fatal("JIT did not compile the block")
	}

	regs := [16]uint64{}
	rflags := uint64(0)
	state := &jit.State{
		Regs:   &regs,
		RIP:    new(uint64),
		Rflags: &rflags,
		Mem:    m,
		XMM:    &[16][2]uint64{},
	}
	*state.RIP = 0x3000

	err := fn(state)
	if err != nil {
		t.Fatalf("JIT execution failed: %v", err)
	}

	// Check ZF was cleared by TEST (5 & 5 = 5 != 0)
	const flagZF = 1 << 6
	if rflags&flagZF != 0 {
		t.Error("ZF should be cleared after TEST 5, 5")
	}
	if regs[0] != 5 {
		t.Errorf("RAX = %d, want 5", regs[0])
	}
}

// Test memory load/store
func TestJIT_MovRegMem(t *testing.T) {
	m := newTestMMU()
	// Map memory at 0x5000
	m.MapRange(0x5000, 0x5000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	// Write value 12345 to memory at 0x5000
	m.Write64(0x5000, 12345)

	// MOV RBX, 0x5000 (0x48 0xBB 0x00 0x50 0x00 0x00 0x00 0x00 0x00)
	writeCode(m, 0x4000, []byte{0x48, 0xBB, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00})
	// MOV RAX, [RBX] (0x48 0x8B 0x03)
	writeCode(m, 0x4009, []byte{0x48, 0x8B, 0x03})
	// RET (0xC3)
	writeCode(m, 0x400C, []byte{0xC3})

	cache := jit.NewCache(m)

	var fn jit.CompiledBlock
	for i := 0; i < jit.CompileThreshold+5; i++ {
		fn = cache.Lookup(0x4000)
	}

	if fn == nil {
		t.Fatal("JIT did not compile the block")
	}

	regs := [16]uint64{}
	rflags := uint64(0)
	state := &jit.State{
		Regs:   &regs,
		RIP:    new(uint64),
		Rflags: &rflags,
		Mem:    m,
		XMM:    &[16][2]uint64{},
	}
	*state.RIP = 0x4000

	err := fn(state)
	if err != nil {
		t.Fatalf("JIT execution failed: %v", err)
	}

	if regs[0] != 12345 { // RAX
		t.Errorf("RAX = %d, want 12345", regs[0])
	}
}

// Test PUSH/POP
func TestJIT_PushPop(t *testing.T) {
	m := newTestMMU()
	// MOV RAX, 0xDEADBEEF (0x48 0xB8 0xEF 0xBE 0xAD 0xDE 0x00 0x00 0x00 0x00)
	writeCode(m, 0x6000, []byte{0x48, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0x00, 0x00, 0x00, 0x00})
	// PUSH RAX (0x50)
	writeCode(m, 0x600A, []byte{0x50})
	// POP RBX (0x5B)
	writeCode(m, 0x600B, []byte{0x5B})
	// RET (0xC3)
	writeCode(m, 0x600C, []byte{0xC3})

	cache := jit.NewCache(m)

	var fn jit.CompiledBlock
	for i := 0; i < jit.CompileThreshold+5; i++ {
		fn = cache.Lookup(0x6000)
	}

	if fn == nil {
		t.Fatal("JIT did not compile the block")
	}

	regs := [16]uint64{}
	regs[4] = 0x8000 // Initialize RSP
	rflags := uint64(0)
	state := &jit.State{
		Regs:   &regs,
		RIP:    new(uint64),
		Rflags: &rflags,
		Mem:    m,
		XMM:    &[16][2]uint64{},
	}
	*state.RIP = 0x6000

	err := fn(state)
	if err != nil {
		t.Fatalf("JIT execution failed: %v", err)
	}

	if regs[3] != 0xDEADBEEF { // RBX
		t.Errorf("RBX = 0x%x, want 0xDEADBEEF", regs[3])
	}
}

// Test LEA
func TestJIT_Lea(t *testing.T) {
	m := newTestMMU()
	// MOV RBX, 0x1000 (0x48 0xBB 0x00 0x10 0x00 0x00 0x00 0x00 0x00 0x00)
	writeCode(m, 0x7000, []byte{0x48, 0xBB, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	// LEA RAX, [RBX+0x20] (0x48 0x8D 0x43 0x20)
	writeCode(m, 0x700A, []byte{0x48, 0x8D, 0x43, 0x20})
	// RET (0xC3)
	writeCode(m, 0x700E, []byte{0xC3})

	cache := jit.NewCache(m)

	var fn jit.CompiledBlock
	for i := 0; i < jit.CompileThreshold+5; i++ {
		fn = cache.Lookup(0x7000)
	}

	if fn == nil {
		t.Fatal("JIT did not compile the block")
	}

	regs := [16]uint64{}
	rflags := uint64(0)
	state := &jit.State{
		Regs:   &regs,
		RIP:    new(uint64),
		Rflags: &rflags,
		Mem:    m,
		XMM:    &[16][2]uint64{},
	}
	*state.RIP = 0x7000

	err := fn(state)
	if err != nil {
		t.Fatalf("JIT execution failed: %v", err)
	}

	if regs[0] != 0x1020 { // RAX = RBX + 0x20
		t.Errorf("RAX = 0x%x, want 0x1020", regs[0])
	}
}

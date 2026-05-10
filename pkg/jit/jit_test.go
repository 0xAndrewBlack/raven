package jit_test

import (
	"math"
	"testing"

	"github.com/mirkobrombin/Raven/pkg/jit"
	"github.com/mirkobrombin/Raven/pkg/mmu"
)

func newTestMMU() *mmu.MMU {
	m := mmu.New()
	m.MapRange(0, 0x1000, mmu.PermRead|mmu.PermWrite)
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
	var fn *jit.Block
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

	err := fn.Run(state)
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

	var fn *jit.Block
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

	err := fn.Run(state)
	if err != nil {
		t.Fatalf("JIT execution failed: %v", err)
	}

	if regs[0] != 42 { // RAX = 10 + 32
		t.Errorf("RAX = %d, want 42", regs[0])
	}
}

// Test TEST instruction and flags
func TestJITALUMemoryRegister(t *testing.T) {
	tests := []struct {
		name    string
		opcode  byte
		initial uint32
		operand uint32
		want    uint32
		wantZF  bool
	}{
		{name: "add", opcode: 0x01, initial: 10, operand: 32, want: 42},
		{name: "and", opcode: 0x21, initial: 0xf3, operand: 0x0f, want: 3},
		{name: "sub", opcode: 0x29, initial: 40, operand: 40, want: 0, wantZF: true},
		{name: "cmp", opcode: 0x39, initial: 42, operand: 42, want: 42, wantZF: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newTestMMU()
			m.MapRange(0x5000, 0x5000, mmu.PermRead|mmu.PermWrite)
			if err := m.Write32(0x5000, tt.initial); err != nil {
				t.Fatal(err)
			}
			writeCode(m, 0x2000, []byte{
				0xBB, 0x00, 0x50, 0x00, 0x00,
				0xB8, byte(tt.operand), byte(tt.operand >> 8), byte(tt.operand >> 16), byte(tt.operand >> 24),
				tt.opcode, 0x03,
				0xCC,
			})

			cache := jit.NewCacheMode(m, true)
			var block *jit.Block
			for i := 0; i < jit.CompileThreshold+5; i++ {
				block = cache.Lookup(0x2000)
			}
			if block == nil {
				t.Fatal("JIT did not compile the block")
			}

			regs := [16]uint64{}
			rip := uint64(0x2000)
			rflags := uint64(0)
			state := &jit.State{
				Regs:   &regs,
				RIP:    &rip,
				Rflags: &rflags,
				Mem:    m,
				XMM:    &[16][2]uint64{},
				Mode32: true,
			}
			if err := block.Run(state); err != nil {
				t.Fatalf("JIT execution failed: %v", err)
			}

			got, err := m.Read32(0x5000)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("memory = %#x, want %#x", got, tt.want)
			}
			const flagZF = 1 << 6
			if (rflags&flagZF != 0) != tt.wantZF {
				t.Errorf("ZF set = %t, want %t", rflags&flagZF != 0, tt.wantZF)
			}
			if tt.name == "cmp" && got != tt.initial {
				t.Errorf("CMP modified memory: got %#x, initial %#x", got, tt.initial)
			}
		})
	}
}

func TestJIT_Jcc(t *testing.T) {
	m := newTestMMU()
	// MOV RAX, 5 (0xB8 0x05 0x00 0x00 0x00)
	writeCode(m, 0x3000, []byte{0xB8, 0x05, 0x00, 0x00, 0x00})
	// TEST RAX, RAX (0x48 0x85 0xC0) - clears ZF (5 & 5 != 0)
	writeCode(m, 0x3005, []byte{0x48, 0x85, 0xC0})
	// RET (0xC3)
	writeCode(m, 0x3008, []byte{0xC3})

	cache := jit.NewCache(m)

	var fn *jit.Block
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

	err := fn.Run(state)
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

	var fn *jit.Block
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

	err := fn.Run(state)
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

	var fn *jit.Block
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

	err := fn.Run(state)
	if err != nil {
		t.Fatalf("JIT execution failed: %v", err)
	}

	if regs[3] != 0xDEADBEEF { // RBX
		t.Errorf("RBX = 0x%x, want 0xDEADBEEF", regs[3])
	}
}

func TestJITMode32PushPopAndAbsoluteAddress(t *testing.T) {
	m := mmu.New()
	m.MapRange(0x1000, 0x9000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	writeCode(m, 0x1000, []byte{
		0xB8, 0xEF, 0xBE, 0xAD, 0xDE,
		0x50,
		0x5B,
		0x8B, 0x0D, 0x00, 0x30, 0x00, 0x00,
		0xC3,
	})
	if err := m.Write32(0x3000, 0x12345678); err != nil {
		t.Fatal(err)
	}

	cache := jit.NewCacheMode(m, true)
	var fn *jit.Block
	for i := 0; i < jit.CompileThreshold+5; i++ {
		fn = cache.Lookup(0x1000)
	}
	if fn == nil {
		t.Fatal("JIT did not compile the PE32 block")
	}

	regs := [16]uint64{}
	regs[4] = 0x9000
	rflags := uint64(0)
	rip := uint64(0x1000)
	state := &jit.State{
		Regs: &regs, RIP: &rip, Rflags: &rflags, Mem: m,
		XMM: &[16][2]uint64{}, Mode32: true,
	}
	if err := fn.Run(state); err != nil {
		t.Fatal(err)
	}
	if regs[3] != 0xDEADBEEF {
		t.Fatalf("EBX = %#x, want %#x", regs[3], uint64(0xDEADBEEF))
	}
	if regs[1] != 0x12345678 {
		t.Fatalf("ECX = %#x, want absolute memory value", regs[1])
	}
	if regs[4] != 0x9004 {
		t.Fatalf("ESP = %#x, want 0x9004 after RET", regs[4])
	}
}

func TestJITMode32UnsupportedOpcodeRequestsFallback(t *testing.T) {
	m := mmu.New()
	m.MapRange(0x1000, mmu.PageSize, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	writeCode(m, 0x1000, []byte{0x40})
	cache := jit.NewCacheMode(m, true)
	var fn *jit.Block
	for i := 0; i < jit.CompileThreshold+5; i++ {
		fn = cache.Lookup(0x1000)
	}
	if fn != nil {
		t.Fatal("fallback-only block was cached as executable")
	}
}

func TestJITMode32OperandSizeOverrideRequestsFallback(t *testing.T) {
	m := mmu.New()
	m.MapRange(0x1000, mmu.PageSize, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	writeCode(m, 0x1000, []byte{0x66, 0x8B, 0xC1})
	cache := jit.NewCacheMode(m, true)
	var block *jit.Block
	for i := 0; i < jit.CompileThreshold+5; i++ {
		block = cache.Lookup(0x1000)
	}
	if block != nil {
		t.Fatal("operand-size fallback was cached as executable")
	}
}

func TestJITMode32LegacyHighByteRegistersRequestFallback(t *testing.T) {
	tests := []struct {
		name string
		code []byte
	}{
		{name: "mov ah immediate", code: []byte{0xB4, 0x7F}},
		{name: "add al ah", code: []byte{0x00, 0xE0}},
		{name: "movzx eax ah", code: []byte{0x0F, 0xB6, 0xC4}},
		{name: "setz ah", code: []byte{0x0F, 0x94, 0xC4}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			m := mmu.New()
			m.MapRange(0x1000, mmu.PageSize, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
			writeCode(m, 0x1000, test.code)
			cache := jit.NewCacheMode(m, true)
			var block *jit.Block
			for i := 0; i < jit.CompileThreshold+5; i++ {
				block = cache.Lookup(0x1000)
			}
			if block != nil {
				t.Fatal("legacy high-byte fallback was cached as executable")
			}
		})
	}
}

func TestJITTrapInstructionsRemainAtInterpreterBoundary(t *testing.T) {
	tests := []struct {
		name string
		trap []byte
	}{
		{name: "syscall", trap: []byte{0x0F, 0x05}},
		{name: "vmcall", trap: []byte{0x0F, 0x01, 0xC1}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			m := mmu.New()
			m.MapRange(0x1000, mmu.PageSize, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
			code := append([]byte{0xB8, 0x2A, 0, 0, 0}, test.trap...)
			writeCode(m, 0x1000, code)
			cache := jit.NewCacheMode(m, true)
			var block *jit.Block
			for i := 0; i < jit.CompileThreshold+5; i++ {
				block = cache.Lookup(0x1000)
			}
			if block == nil {
				t.Fatal("JIT did not compile boundary block")
			}
			regs := [16]uint64{}
			rip := uint64(0x1000)
			rflags := uint64(2)
			state := &jit.State{
				Regs: &regs, RIP: &rip, Rflags: &rflags, Mem: m,
				XMM: &[16][2]uint64{}, Mode32: true,
			}
			if err := block.Run(state); err != nil {
				t.Fatal(err)
			}
			if !state.Fallback || state.Trap || rip != 0x1005 || regs[0] != 42 {
				t.Fatalf("fallback=%v trap=%v RIP=%#x EAX=%#x", state.Fallback, state.Trap, rip, regs[0])
			}
		})
	}
}

func TestJITDecodeErrorFallsBackAtInstructionStart(t *testing.T) {
	m := mmu.New()
	m.MapRange(0x1000, mmu.PageSize, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	if err := m.Write8(0x1FFF, 0x90); err != nil {
		t.Fatal(err)
	}
	cache := jit.NewCacheMode(m, true)
	var block *jit.Block
	for i := 0; i < jit.CompileThreshold+5; i++ {
		block = cache.Lookup(0x1FFF)
	}
	if block == nil {
		t.Fatal("JIT did not compile partial block")
	}
	regs := [16]uint64{}
	rip := uint64(0x1FFF)
	rflags := uint64(2)
	state := &jit.State{Regs: &regs, RIP: &rip, Rflags: &rflags, Mem: m, XMM: &[16][2]uint64{}, Mode32: true}
	if err := block.Run(state); err != nil {
		t.Fatal(err)
	}
	if !state.Fallback || rip != 0x2000 {
		t.Fatalf("fallback=%v RIP=%#x", state.Fallback, rip)
	}
}

func TestJITStackFaultsPreserveStackPointer(t *testing.T) {
	tests := []struct {
		name string
		code []byte
	}{
		{name: "push", code: []byte{0x50}},
		{name: "pop", code: []byte{0x58}},
		{name: "call", code: []byte{0xE8, 0, 0, 0, 0}},
		{name: "ret", code: []byte{0xC3}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			m := mmu.New()
			m.MapRange(0x1000, mmu.PageSize, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
			writeCode(m, 0x1000, test.code)
			cache := jit.NewCacheMode(m, true)
			var block *jit.Block
			for i := 0; i < jit.CompileThreshold+5; i++ {
				block = cache.Lookup(0x1000)
			}
			if block == nil {
				t.Fatal("JIT did not compile stack block")
			}
			regs := [16]uint64{}
			regs[4] = 0x9000
			rip := uint64(0x1000)
			rflags := uint64(2)
			state := &jit.State{Regs: &regs, RIP: &rip, Rflags: &rflags, Mem: m, XMM: &[16][2]uint64{}, Mode32: true}
			if err := block.Run(state); err == nil {
				t.Fatal("stack access unexpectedly succeeded")
			}
			if regs[4] != 0x9000 {
				t.Fatalf("ESP=%#x after fault", regs[4])
			}
		})
	}
}

func TestJITStackFaultResumesAtFaultingInstruction(t *testing.T) {
	m := mmu.New()
	m.MapRange(0x1000, mmu.PageSize, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	writeCode(m, 0x1000, []byte{0x01, 0xC0, 0x50})
	cache := jit.NewCacheMode(m, true)
	var block *jit.Block
	for i := 0; i < jit.CompileThreshold+5; i++ {
		block = cache.Lookup(0x1000)
	}
	if block == nil {
		t.Fatal("JIT did not compile stack block")
	}
	regs := [16]uint64{}
	regs[0] = 1
	regs[4] = 0x9000
	rip := uint64(0x1000)
	rflags := uint64(2)
	state := &jit.State{Regs: &regs, RIP: &rip, Rflags: &rflags, Mem: m, XMM: &[16][2]uint64{}, Mode32: true}
	if err := block.Run(state); err == nil {
		t.Fatal("stack access unexpectedly succeeded")
	}
	if rip != 0x1002 || regs[0] != 2 || regs[4] != 0x9000 {
		t.Fatalf("RIP=%#x EAX=%#x ESP=%#x", rip, regs[0], regs[4])
	}
}

func TestJITInvalidateClearsNegativeCache(t *testing.T) {
	m := mmu.New()
	m.MapRange(0x1000, mmu.PageSize, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	writeCode(m, 0x1000, []byte{0x40})
	cache := jit.NewCacheMode(m, true)
	for i := 0; i < jit.CompileThreshold+5; i++ {
		if block := cache.Lookup(0x1000); block != nil {
			t.Fatal("unsupported instruction compiled")
		}
	}
	writeCode(m, 0x1000, []byte{0xB8, 0x2A, 0, 0, 0, 0xEB, 0})
	cache.Invalidate(0x1000)
	var block *jit.Block
	for i := 0; i < jit.CompileThreshold+5; i++ {
		block = cache.Lookup(0x1000)
	}
	if block == nil {
		t.Fatal("updated code remained negatively cached")
	}
}

func TestJITMode32FullBlockAdvancesInstructionPointer(t *testing.T) {
	m := mmu.New()
	m.Mode32 = true
	m.MapRange(0x1000, 0x1000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	for i := 0; i < jit.MaxBlockInsns+1; i++ {
		if err := m.Write8(0x1000+uint64(i), 0x90); err != nil {
			t.Fatal(err)
		}
	}

	cache := jit.NewCacheMode(m, true)
	var block *jit.Block
	for i := 0; i < jit.CompileThreshold+5; i++ {
		block = cache.Lookup(0x1000)
	}
	if block == nil {
		t.Fatal("JIT did not compile the full PE32 block")
	}
	regs := [16]uint64{}
	rip := uint64(0x1000)
	rflags := uint64(2)
	state := &jit.State{
		Regs: &regs, RIP: &rip, Rflags: &rflags, Mem: m,
		XMM: &[16][2]uint64{}, Mode32: true,
	}
	if err := block.Run(state); err != nil {
		t.Fatal(err)
	}
	if want := uint64(0x1000 + jit.MaxBlockInsns); rip != want {
		t.Fatalf("RIP=%#x, want %#x", rip, want)
	}
}

func TestJITMode32NegativeImmediateUsesOperandWidthForCarry(t *testing.T) {
	m := mmu.New()
	m.MapRange(0x1000, mmu.PageSize, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	writeCode(m, 0x1000, []byte{
		0xB8, 0xFF, 0xFF, 0xFF, 0xFF,
		0x83, 0xE8, 0xFF,
		0xC3,
	})
	cache := jit.NewCacheMode(m, true)
	var block *jit.Block
	for i := 0; i < jit.CompileThreshold+5; i++ {
		block = cache.Lookup(0x1000)
	}
	regs := [16]uint64{}
	regs[4] = 0x2000
	m.MapRange(0x2000, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	if err := m.Write32(0x2000, 0); err != nil {
		t.Fatal(err)
	}
	rip := uint64(0x1000)
	rflags := uint64(2)
	state := &jit.State{
		Regs: &regs, RIP: &rip, Rflags: &rflags, Mem: m,
		XMM: &[16][2]uint64{}, Mode32: true,
	}
	if err := block.Run(state); err != nil {
		t.Fatal(err)
	}
	if regs[0] != 0 {
		t.Fatalf("EAX=%#x, want zero", regs[0])
	}
	if rflags&1 != 0 {
		t.Fatalf("CF set after 0xffffffff - 0xffffffff: RFLAGS=%#x", rflags)
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

	var fn *jit.Block
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

	err := fn.Run(state)
	if err != nil {
		t.Fatalf("JIT execution failed: %v", err)
	}

	if regs[0] != 0x1020 { // RAX = RBX + 0x20
		t.Errorf("RAX = 0x%x, want 0x1020", regs[0])
	}
}

func TestJITTestImmediateDoesNotModifyAccumulator(t *testing.T) {
	m := mmu.New()
	m.MapPage(0x8000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	writeCode(m, 0x8000, []byte{0xA9, 0xFF, 0, 0, 0, 0xEB, 0xFE})
	cache := jit.NewCacheMode(m, true)
	fn := cache.Compile(0x8000)
	if fn == nil {
		t.Fatal("JIT did not compile TEST EAX, imm32")
	}
	regs := [16]uint64{0x100}
	rip := uint64(0x8000)
	rflags := uint64(0)
	state := &jit.State{Regs: &regs, RIP: &rip, Rflags: &rflags, Mem: m, XMM: &[16][2]uint64{}, Mode32: true}
	if err := fn.Run(state); err != nil {
		t.Fatal(err)
	}
	if regs[0] != 0x100 {
		t.Fatalf("EAX=%#x, want %#x", regs[0], uint64(0x100))
	}
	if rflags&(1<<6) == 0 {
		t.Fatalf("RFLAGS=%#x, zero flag is clear", rflags)
	}
}

func TestJITArithmeticUpdatesAuxiliaryCarry(t *testing.T) {
	m := mmu.New()
	m.MapPage(0x9000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	writeCode(m, 0x9000, []byte{0xB8, 0x0F, 0, 0, 0, 0x83, 0xC0, 1, 0xEB, 0xFE})
	cache := jit.NewCacheMode(m, true)
	fn := cache.Compile(0x9000)
	if fn == nil {
		t.Fatal("JIT did not compile ADD EAX, imm8")
	}
	regs := [16]uint64{}
	rip := uint64(0x9000)
	rflags := uint64(0)
	state := &jit.State{Regs: &regs, RIP: &rip, Rflags: &rflags, Mem: m, XMM: &[16][2]uint64{}, Mode32: true}
	if err := fn.Run(state); err != nil {
		t.Fatal(err)
	}
	if regs[0] != 0x10 || rflags&(1<<4) == 0 {
		t.Fatalf("EAX=%#x RFLAGS=%#x", regs[0], rflags)
	}
}

// TestJITX87ControlWordAndIntOps certifies that the closure JIT executes the
// x87 forms that MSVC emits around float->int conversions (FLDCW/FNSTCW, the
// 0xDA integer-arithmetic group, and FNSTSW m16) with the same results as the
// interpreter, instead of bailing to the interpreter mid-block. The sequence
// loads 3.9, switches the control word to truncate, adds integer 10 (FIADD,
// 0xDA), stores the truncated result (FIST), and reads the status word.
func TestJITX87ControlWordAndIntOps(t *testing.T) {
	m := mmu.New()
	m.MapRange(0, 0x1000, mmu.PermRead|mmu.PermWrite)
	m.MapRange(0x1000, 0x1000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)

	// Data operands in the low RW page.
	m.Write32(0x100, 0x407CCCCD) // float32 3.9
	m.Write16(0x104, 0x0F7F)     // control word: RC=11 (truncate toward zero)
	m.Write32(0x10C, 10)         // int32 operand for FIADD

	code := []byte{
		0xD9, 0x05, 0x00, 0x01, 0x00, 0x00, // FLD  dword [0x100]
		0xD9, 0x2D, 0x04, 0x01, 0x00, 0x00, // FLDCW word  [0x104]
		0xDA, 0x05, 0x0C, 0x01, 0x00, 0x00, // FIADD dword [0x10C]  (st0 = 3.9 + 10 = 13.9)
		0xDB, 0x15, 0x08, 0x01, 0x00, 0x00, // FIST dword [0x108]   (truncate -> 13)
		0xDD, 0x3D, 0x10, 0x01, 0x00, 0x00, // FNSTSW word [0x110]
		0xC3, // RET
	}
	writeCode(m, 0x1000, code)

	cache := jit.NewCacheMode(m, true)
	var block *jit.Block
	for i := 0; i < jit.CompileThreshold+5; i++ {
		block = cache.Lookup(0x1000)
	}
	if block == nil {
		t.Fatal("JIT did not compile the x87 block")
	}

	regs := [16]uint64{}
	rip := uint64(0x1000)
	rflags := uint64(2)
	st := [8]float64{}
	top := 0
	cw := uint16(0x037F)
	sw := uint16(0)
	tw := uint16(0xFFFF)
	state := &jit.State{
		Regs: &regs, RIP: &rip, Rflags: &rflags, Mem: m,
		XMM: &[16][2]uint64{}, Mode32: true,
		FPUST: &st, FPUTop: &top, FPUCW: &cw, FPUSW: &sw, FPUTW: &tw,
	}
	if err := block.Run(state); err != nil {
		t.Fatal(err)
	}

	// FLDCW must have taken effect (truncate mode) and 0xDA FIADD must have run
	// inside the compiled block: 3.9 + 10 = 13.9, truncated to 13.
	got, err := m.Read32(0x108)
	if err != nil {
		t.Fatal(err)
	}
	if int32(got) != 13 {
		t.Fatalf("FIST result = %d, want 13 (FLDCW-truncate + 0xDA FIADD in closure)", int32(got))
	}
	if cw != 0x0F7F {
		t.Fatalf("control word = %#x, want 0x0F7F (FLDCW not applied)", cw)
	}
	// st0 (float32 3.95 + 10) must survive FIST (no pop).
	if v := st[top&7]; v < 13.9 || v > 14.0 {
		t.Fatalf("st0 = %v, want ~13.95 (FIST must not pop)", v)
	}
}

func TestJITMMXPackedUnpack(t *testing.T) {
	const (
		dst = uint64(0x0706050403020100)
		src = uint64(0x1716151413121110)
	)
	tests := []struct {
		name   string
		opcode byte
		bits   uint
		high   bool
	}{
		{name: "low bytes", opcode: 0x60, bits: 8},
		{name: "low words", opcode: 0x61, bits: 16},
		{name: "low dwords", opcode: 0x62, bits: 32},
		{name: "high bytes", opcode: 0x68, bits: 8, high: true},
		{name: "high words", opcode: 0x69, bits: 16, high: true},
		{name: "high dwords", opcode: 0x6A, bits: 32, high: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			m := mmu.New()
			m.MapPage(0xA000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
			writeCode(m, 0xA000, []byte{0x0F, test.opcode, 0xC1, 0xEB, 0xFE})
			cache := jit.NewCacheMode(m, true)
			block := cache.Compile(0xA000)
			if block == nil {
				t.Fatal("MMX unpack block did not compile")
			}

			regs := [16]uint64{}
			rip := uint64(0xA000)
			rflags := uint64(2)
			st := [8]float64{}
			st[0] = math.Float64frombits(dst)
			st[1] = math.Float64frombits(src)
			top := 0
			tag := uint16(0xffff)
			state := &jit.State{
				Regs: &regs, RIP: &rip, Rflags: &rflags, Mem: m,
				XMM: &[16][2]uint64{}, Mode32: true,
				FPUST: &st, FPUTop: &top, FPUTW: &tag,
			}
			if err := block.Run(state); err != nil {
				t.Fatal(err)
			}

			var want uint64
			lanes := uint(64) / test.bits
			start := uint(0)
			if test.high {
				start = lanes / 2
			}
			mask := uint64(1)<<test.bits - 1
			for i := uint(0); i < lanes/2; i++ {
				want |= dst >> ((start + i) * test.bits) & mask << (i * test.bits * 2)
				want |= src >> ((start + i) * test.bits) & mask << (i*test.bits*2 + test.bits)
			}
			if got := math.Float64bits(st[0]); got != want {
				t.Fatalf("MM0=%#016x, want %#016x", got, want)
			}
			if top != 0 || tag != 0 {
				t.Fatalf("FPU top=%d tag=%#x, want MMX state", top, tag)
			}
		})
	}
}

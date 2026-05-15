package jit

import (
	"testing"

	"github.com/mirkobrombin/Raven/pkg/mmu"
)

// TestNativeBlockMatchesClosure compiles the same decoded block with the
// closure backend and the native backend and requires identical CPU state.
func TestNativeBlockMatchesClosure(t *testing.T) {
	blocks := [][]byte{
		{
			0x48, 0xC7, 0xC0, 0x07, 0x00, 0x00, 0x00, // mov rax, 7
			0x48, 0xC7, 0xC1, 0x05, 0x00, 0x00, 0x00, // mov rcx, 5
			0x48, 0x01, 0xC8, // add rax, rcx
			0xEB, 0xFE, // jmp $
		},
		{
			0x48, 0xC7, 0xC0, 0x2A, 0x00, 0x00, 0x00, // mov rax, 42
			0x48, 0x83, 0xE8, 0x2A, // sub rax, 42
			0x0F, 0x84, 0x10, 0x00, 0x00, 0x00, // jz +0x10
		},
		{
			0x48, 0xC7, 0xC3, 0x0FF, 0x00, 0x00, 0x00, // mov rbx, 0xff
			0x48, 0x81, 0xF3, 0x0F0, 0x00, 0x00, 0x00, // xor rbx, 0xf0
			0x48, 0x3D, 0x01, 0x00, 0x00, 0x00, // cmp rax, 1
			0x0F, 0x85, 0x20, 0x00, 0x00, 0x00, // jnz +0x20
		},
	}
	for i, code := range blocks {
		t.Run(string(rune('A'+i)), func(t *testing.T) {
			nativeVsClosure(t, code)
		})
	}
}

func nativeVsClosure(t *testing.T, code []byte) {
	m := mmu.New()
	m.MapPage(0x1000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	for i, b := range code {
		if err := m.Write8(0x1000+uint64(i), b); err != nil {
			t.Fatal(err)
		}
	}
	cache := NewCache(m)
	insns, _, err := cache.decode(0x1000)
	if err != nil {
		t.Fatal(err)
	}

	runState := func(exec func(*State)) ([16]uint64, uint64, uint64) {
		var regs [16]uint64
		var rflags, rip uint64 = 0x202, 0x1000
		s := &State{Regs: &regs, RIP: &rip, Rflags: &rflags, Mem: m}
		exec(s)
		return regs, rflags, rip
	}

	fn := cache.emit(insns)
	if fn == nil {
		t.Fatal("closure emit failed")
	}
	wantRegs, wantFlags, wantRIP := runState(func(s *State) {
		if err := fn(s); err != nil {
			t.Fatal(err)
		}
	})

	exec, err := newExecBuf()
	if err != nil {
		t.Skipf("exec memory unavailable: %v", err)
	}
	cache.exec = exec
	entry, _, _, _ := cache.compileNative(insns)
	if entry == 0 {
		t.Fatal("native compile rejected a supported block")
	}
	gotRegs, gotFlags, gotRIP := runState(func(s *State) { runNative(entry, s, nil) })

	if gotRegs != wantRegs {
		t.Fatalf("regs = %v, want %v", gotRegs, wantRegs)
	}
	if gotRIP != wantRIP {
		t.Fatalf("rip = %#x, want %#x", gotRIP, wantRIP)
	}
	const observable = uint64(0x8D5) // CF|PF|AF|ZF|SF|OF
	if gotFlags&observable != wantFlags&observable {
		t.Fatalf("flags = %#x, want %#x", gotFlags&observable, wantFlags&observable)
	}
}

// TestNativeCacheMatchesClosureCache runs an arithmetic loop through the full
// Lookup path with and without native codegen and requires identical results.
func TestNativeCacheMatchesClosureCache(t *testing.T) {
	// A register-only countdown loop the native backend fully supports:
	//   mov eax, 100        ; loop counter
	//   mov ecx, 0          ; accumulator
	// L: add ecx, eax
	//   sub eax, 1
	//   jnz L
	//   (fall through to opEnd)
	prog := []byte{
		0xB8, 0x64, 0x00, 0x00, 0x00, // mov eax, 100
		0xB9, 0x00, 0x00, 0x00, 0x00, // mov ecx, 0
		0x01, 0xC1, // add ecx, eax
		0x83, 0xE8, 0x01, // sub eax, 1
		0x75, 0xF9, // jnz -7 (back to add)
		0x90, // nop (block tail)
		0xCC, // explicit interpreter boundary
	}
	run := func(native bool) [16]uint64 {
		m := mmu.New()
		m.MapPage(0x2000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
		for i, b := range prog {
			m.Write8(0x2000+uint64(i), b)
		}
		cache := NewCacheMode(m, true)
		if native && !cache.EnableNativeCodegen() {
			t.Skip("native codegen unavailable")
		}
		var regs [16]uint64
		var rflags, rip uint64 = 0x202, 0x2000
		s := &State{Regs: &regs, RIP: &rip, Rflags: &rflags, Mem: m, Mode32: true}
		// Drive it like the CPU would: look up the block at RIP, run it,
		// repeat until we leave the program region. Force-compile so the
		// native path is exercised from the first iteration.
		for steps := 0; steps < 100000; steps++ {
			if rip < 0x2000 || rip >= 0x2000+uint64(len(prog)) {
				break
			}
			b := cache.Compile(rip)
			if b == nil {
				// Unsupported single instruction: advance past it minimally
				// by decoding one; for this program that never happens.
				t.Fatalf("no block at %#x", rip)
			}
			s.Fallback = false
			if err := b.Run(s); err != nil {
				t.Fatal(err)
			}
			if s.Fallback {
				break
			}
		}
		return regs
	}
	got := run(true)
	want := run(false)
	if got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("native regs eax=%d ecx=%d, closure eax=%d ecx=%d",
			got[0], got[1], want[0], want[1])
	}
	// 100+99+...+1 = 5050
	if want[1] != 5050 {
		t.Fatalf("accumulator = %d, want 5050", want[1])
	}
}

// TestNativeMemoryMatchesClosure exercises native flat-memory load/store and
// the permission-fault fallback, comparing against the closure backend.
func TestNativeMemoryMatchesClosure(t *testing.T) {
	// Program (Mode32):
	//   mov eax, [ebx+4]     ; load
	//   add eax, 1
	//   mov [ebx+8], eax     ; store
	//   nop                  ; block tail
	prog := []byte{
		0x8B, 0x43, 0x04, // mov eax, [ebx+4]
		0x83, 0xC0, 0x01, // add eax, 1
		0x89, 0x43, 0x08, // mov [ebx+8], eax
		0x90,
		0xCC,
	}
	run := func(native bool) (eax uint64, stored uint32, ok bool) {
		m := mmu.New()
		if native {
			if err := m.EnableFlatBacking(); err != nil {
				return 0, 0, false
			}
		}
		m.Mode32 = true
		m.MapPage(0x3000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
		m.MapPage(0x10000, mmu.PermRead|mmu.PermWrite) // data page (ebx=0x10000)
		for i, b := range prog {
			m.Write8(0x3000+uint64(i), b)
		}
		m.Write32(0x10004, 41) // [ebx+4] = 41
		cache := NewCacheMode(m, true)
		if native && !cache.EnableNativeCodegen() {
			return 0, 0, false
		}
		var regs [16]uint64
		regs[3] = 0x10000 // ebx
		var rflags, rip uint64 = 0x202, 0x3000
		s := &State{Regs: &regs, RIP: &rip, Rflags: &rflags, Mem: m, Mode32: true}
		b := cache.Compile(0x3000)
		if b == nil {
			t.Fatal("no block")
		}
		if native && b.native == 0 {
			t.Fatal("native backend rejected the memory block")
		}
		if err := b.Run(s); err != nil {
			t.Fatal(err)
		}
		v, _ := m.Read32(0x10008)
		return regs[0], v, true
	}
	nEax, nStored, nok := run(true)
	if !nok {
		t.Skip("flat backing / native codegen unavailable")
	}
	cEax, cStored, _ := run(false)
	if nEax != cEax || nStored != cStored {
		t.Fatalf("native eax=%d stored=%d, closure eax=%d stored=%d", nEax, nStored, cEax, cStored)
	}
	if cEax != 42 || cStored != 42 {
		t.Fatalf("expected eax=42 stored=42, got eax=%d stored=%d", cEax, cStored)
	}
}

// TestNativeMemoryFaultsToInterpreter verifies a native block that hits an
// unmapped page returns Fallback with RIP at the faulting instruction rather
// than crashing the host.
func TestNativeMemoryFaultsToInterpreter(t *testing.T) {
	m := mmu.New()
	if err := m.EnableFlatBacking(); err != nil {
		t.Skip("flat backing unavailable")
	}
	m.Mode32 = true
	m.MapPage(0x3000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	prog := []byte{
		0x8B, 0x43, 0x00, // mov eax, [ebx]   (ebx points at an unmapped page)
		0x90,
	}
	for i, b := range prog {
		m.Write8(0x3000+uint64(i), b)
	}
	cache := NewCacheMode(m, true)
	if !cache.EnableNativeCodegen() {
		t.Skip("native codegen unavailable")
	}
	var regs [16]uint64
	regs[3] = 0x50000 // unmapped
	var rflags, rip uint64 = 0x202, 0x3000
	s := &State{Regs: &regs, RIP: &rip, Rflags: &rflags, Mem: m, Mode32: true}
	b := cache.Compile(0x3000)
	if b == nil || b.native == 0 {
		t.Fatal("expected a native block")
	}
	if err := b.Run(s); err != nil {
		t.Fatal(err)
	}
	if !s.Fallback {
		t.Fatal("expected Fallback on unmapped access")
	}
	if rip != 0x3000 {
		t.Fatalf("fault RIP = %#x, want 0x3000", rip)
	}
}

func TestNativePrefixFallsBackAtUnsupportedInstruction(t *testing.T) {
	m := mmu.New()
	m.MapPage(0x4000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	prog := []byte{
		0xB8, 0x2A, 0x00, 0x00, 0x00, // mov eax, 42
		0xD9, 0xEE, // fldz
		0x90,
	}
	for i, b := range prog {
		m.Write8(0x4000+uint64(i), b)
	}
	cache := NewCacheMode(m, true)
	if !cache.EnableNativeCodegen() {
		t.Skip("native codegen unavailable")
	}
	var regs [16]uint64
	var rflags, rip, instret uint64 = 0x202, 0x4000, 0
	s := &State{
		Regs:    &regs,
		RIP:     &rip,
		Rflags:  &rflags,
		Mem:     m,
		Mode32:  true,
		Instret: &instret,
	}
	b := cache.Compile(0x4000)
	if b == nil || b.native == 0 {
		t.Fatal("expected a native prefix")
	}
	if err := b.Run(s); err != nil {
		t.Fatal(err)
	}
	if regs[0] != 42 {
		t.Fatalf("eax = %d, want 42", regs[0])
	}
	if !s.Fallback {
		t.Fatal("expected fallback at unsupported instruction")
	}
	if rip != 0x4005 {
		t.Fatalf("fallback RIP = %#x, want 0x4005", rip)
	}
	if instret != 1 {
		t.Fatalf("instret = %d, want 1", instret)
	}
}

func TestCacheResetPreservesUnchangedCodeMappings(t *testing.T) {
	m := mmu.New()
	m.MapPage(0x5000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	for i, b := range []byte{0xB8, 0x2A, 0, 0, 0, 0xEB, 0xFE} {
		m.Write8(0x5000+uint64(i), b)
	}
	cache := NewCacheMode(m, true)
	before := cache.Compile(0x5000)
	if before == nil {
		t.Fatal("expected compiled block")
	}

	m.MapPage(0x9000, mmu.PermRead|mmu.PermWrite)
	cache.Reset()
	after := cache.Compile(0x5000)
	if after != before {
		t.Fatal("unrelated mapping discarded compiled block")
	}
}

func TestCacheResetDropsRemappedCode(t *testing.T) {
	m := mmu.New()
	m.MapPage(0x6000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	for i, b := range []byte{0xB8, 0x2A, 0, 0, 0, 0xEB, 0xFE} {
		m.Write8(0x6000+uint64(i), b)
	}
	cache := NewCacheMode(m, true)
	before := cache.Compile(0x6000)
	if before == nil {
		t.Fatal("expected compiled block")
	}

	m.MapPage(0x6000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	cache.Reset()
	after := cache.Compile(0x6000)
	if after == nil {
		t.Fatal("expected recompiled block")
	}
	if after == before {
		t.Fatal("remapped code retained stale compiled block")
	}
}

func TestJITRegisterShiftBlocks(t *testing.T) {
	tests := []struct {
		name      string
		code      []byte
		ecx       uint64
		want      uint64
		wantCarry bool
	}{
		{name: "shl-one", code: []byte{0xD1, 0xE0}, want: 0x00000002, wantCarry: true},
		{name: "shr-one", code: []byte{0xD1, 0xE8}, want: 0x40000000, wantCarry: true},
		{name: "sar-one", code: []byte{0xD1, 0xF8}, want: 0xC0000000, wantCarry: true},
		{name: "rol-one", code: []byte{0xD1, 0xC0}, want: 0x00000003, wantCarry: true},
		{name: "ror-one", code: []byte{0xD1, 0xC8}, want: 0xC0000000, wantCarry: true},
		{name: "shl-immediate", code: []byte{0xC1, 0xE0, 0x02}, want: 0x00000004},
		{name: "shr-cl", code: []byte{0xD3, 0xE8}, ecx: 3, want: 0x10000000},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			m := mmu.New()
			m.MapPage(0x7000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
			code := append(append([]byte(nil), test.code...), 0xEB, 0xFE)
			for i, b := range code {
				m.Write8(0x7000+uint64(i), b)
			}
			cache := NewCacheMode(m, true)
			block := cache.Compile(0x7000)
			if block == nil {
				t.Fatal("shift block did not compile")
			}
			var regs [16]uint64
			regs[0] = 0x80000001
			regs[1] = test.ecx
			var rflags, rip uint64 = 0x202, 0x7000
			state := &State{Regs: &regs, RIP: &rip, Rflags: &rflags, Mem: m, Mode32: true}
			if err := block.Run(state); err != nil {
				t.Fatal(err)
			}
			if regs[0] != test.want {
				t.Fatalf("eax = %#x, want %#x", regs[0], test.want)
			}
			if got := rflags&flagCF != 0; got != test.wantCarry {
				t.Fatalf("carry = %v, want %v", got, test.wantCarry)
			}
		})
	}
}

func TestStateFlatMemoryAccess(t *testing.T) {
	m := mmu.New()
	if err := m.EnableFlatBacking(); err != nil {
		t.Skipf("flat backing unavailable: %v", err)
	}
	m.Mode32 = true
	m.MapRange(0x8000, mmu.PageSize*2, mmu.PermRead|mmu.PermWrite)
	state := &State{Mem: m, Mode32: true}

	if err := state.write32(0x8FFE, 0x78563412); err != nil {
		t.Fatal(err)
	}
	if got, err := state.read32(0x8FFE); err != nil || got != 0x78563412 {
		t.Fatalf("cross-page read = %#x, err = %v", got, err)
	}
	if got, err := m.Read32(0x8FFE); err != nil || got != 0x78563412 {
		t.Fatalf("MMU read after flat write = %#x, err = %v", got, err)
	}
}

func TestStateFlatWritePreservesCodeInvalidation(t *testing.T) {
	m := mmu.New()
	if err := m.EnableFlatBacking(); err != nil {
		t.Skipf("flat backing unavailable: %v", err)
	}
	m.Mode32 = true
	m.MapPage(0xA000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	page, _, err := m.LookupRead(0xA000, mmu.PermExecute)
	if err != nil {
		t.Fatal(err)
	}
	before := page.CodeVersion.Load()
	state := &State{Mem: m, Mode32: true}
	if err := state.write32(0xA000, 0x12345678); err != nil {
		t.Fatal(err)
	}
	if after := page.CodeVersion.Load(); after <= before {
		t.Fatalf("code version = %d, want greater than %d", after, before)
	}
}

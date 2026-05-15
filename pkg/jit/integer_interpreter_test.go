package jit_test

import (
	"testing"

	"github.com/mirkobrombin/Raven/pkg/jit"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/x64"
)

type integerDifferentialResult struct {
	regs  [16]uint64
	flags uint64
	rip   uint64
}

func runIntegerInterpreter(t *testing.T, code []byte, regs [16]uint64, flags uint64) integerDifferentialResult {
	t.Helper()
	mem := mmu.New()
	mem.MapPage(0x1000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	for i, opcode := range append(append([]byte(nil), code...), 0xF4) {
		if err := mem.Write8(0x1000+uint64(i), opcode); err != nil {
			t.Fatal(err)
		}
	}
	cpu := x64.New(mem)
	cpu.Regs = regs
	cpu.Rflags = flags
	cpu.RIP = 0x1000
	if err := cpu.Run(); err != nil {
		t.Fatal(err)
	}
	return integerDifferentialResult{regs: cpu.Regs, flags: cpu.Rflags, rip: cpu.RIP}
}

func runIntegerJIT(t *testing.T, code []byte, regs [16]uint64, flags uint64) integerDifferentialResult {
	t.Helper()
	mem := mmu.New()
	mem.MapPage(0x1000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	for i, opcode := range append(append([]byte(nil), code...), 0xF4) {
		if err := mem.Write8(0x1000+uint64(i), opcode); err != nil {
			t.Fatal(err)
		}
	}
	cache := jit.NewCache(mem)
	if !cache.EnableNativeCodegen() {
		t.Skip("native codegen unavailable")
	}
	block := cache.Compile(0x1000)
	if block == nil {
		t.Fatal("integer differential fixture did not compile")
	}
	rip := uint64(0x1000)
	instret := uint64(0)
	state := &jit.State{
		Regs: &regs, RIP: &rip, Rflags: &flags, Mem: mem,
		XMM: &[16][2]uint64{}, Instret: &instret,
	}
	if err := block.Run(state); err != nil {
		t.Fatal(err)
	}
	if instret != 1 || !state.Fallback {
		t.Fatalf("instret=%d fallback=%v", instret, state.Fallback)
	}
	return integerDifferentialResult{regs: regs, flags: flags, rip: rip}
}

func TestIntegerPipelineMatchesInterpreter(t *testing.T) {
	const arithmeticFlags = uint64(1<<0 | 1<<2 | 1<<4 | 1<<6 | 1<<7 | 1<<11)
	tests := []struct {
		name     string
		code     []byte
		regs     [16]uint64
		flagMask uint64
	}{
		{name: "MOVSX byte to word", code: []byte{0x66, 0x0F, 0xBE, 0xC1}, regs: [16]uint64{0: 0xAAAAAAAAAAAAAAAA, 1: 0x80}, flagMask: ^uint64(0)},
		{name: "MOVSX word to qword", code: []byte{0x48, 0x0F, 0xBF, 0xC1}, regs: [16]uint64{0: 1, 1: 0x8000}, flagMask: ^uint64(0)},
		{name: "XCHG word", code: []byte{0x66, 0x87, 0xC8}, regs: [16]uint64{0: 0xAAAAAAAA1234, 1: 0xBBBBBBBBFEDC}, flagMask: ^uint64(0)},
		{name: "XCHG dword", code: []byte{0x87, 0xC8}, regs: [16]uint64{0: 0xAAAAAAAA12345678, 1: 0xBBBBBBBBFEDCBA98}, flagMask: ^uint64(0)},
		{name: "NOT qword", code: []byte{0x48, 0xF7, 0xD0}, regs: [16]uint64{0: 0x8000000000000001}, flagMask: ^uint64(0)},
		{name: "NEG byte", code: []byte{0xF6, 0xD8}, regs: [16]uint64{0: 0xAAAAAAAAAAAAAA80}, flagMask: arithmeticFlags},
		{name: "NEG dword", code: []byte{0xF7, 0xD8}, regs: [16]uint64{0: 0xAAAAAAAA80000000}, flagMask: arithmeticFlags},
		{name: "INC word", code: []byte{0x66, 0xFF, 0xC0}, regs: [16]uint64{0: 0xAAAAAAAAAAAA7FFF}, flagMask: arithmeticFlags},
		{name: "DEC qword", code: []byte{0x48, 0xFF, 0xC8}, regs: [16]uint64{0: 0x8000000000000000}, flagMask: arithmeticFlags},
		{name: "IMUL3 dword", code: []byte{0x6B, 0xC1, 0x80}, regs: [16]uint64{0: 0xAAAAAAAAAAAAAAAA, 1: 0x7FFFFFFF}},
		{name: "SHL byte", code: []byte{0xC0, 0xE0, 0x07}, regs: [16]uint64{0: 0xAAAAAAAAAAAAAA81}, flagMask: 1<<0 | 1<<2 | 1<<6 | 1<<7},
		{name: "ROR word", code: []byte{0x66, 0xC1, 0xC8, 0x0F}, regs: [16]uint64{0: 0xAAAAAAAAAAAA8001}},
		{name: "DIV dword", code: []byte{0xF7, 0xF1}, regs: [16]uint64{0: 100, 1: 7}},
		{name: "IDIV dword", code: []byte{0xF7, 0xF9}, regs: [16]uint64{0: 0xFFFFFF9C, 1: 7, 2: 0xFFFFFFFF}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			const flags = uint64(0xA53)
			interpreter := runIntegerInterpreter(t, test.code, test.regs, flags)
			compiled := runIntegerJIT(t, test.code, test.regs, flags)
			if compiled.regs != interpreter.regs {
				t.Fatalf("JIT regs=%#v interpreter regs=%#v", compiled.regs, interpreter.regs)
			}
			if compiled.flags&test.flagMask != interpreter.flags&test.flagMask {
				t.Fatalf("JIT flags=%#x interpreter flags=%#x mask=%#x",
					compiled.flags, interpreter.flags, test.flagMask)
			}
			if compiled.rip != 0x1000+uint64(len(test.code)) {
				t.Fatalf("JIT RIP=%#x", compiled.rip)
			}
		})
	}
}

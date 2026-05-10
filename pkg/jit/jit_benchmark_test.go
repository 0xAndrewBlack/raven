package jit

import (
	"testing"

	"github.com/mirkobrombin/Raven/pkg/mmu"
)

var benchmarkCompiledBlock CompiledBlock

func benchmarkPE32RegisterBlock(b *testing.B, native bool) {
	b.Helper()

	m := mmu.New()
	m.Mode32 = true
	m.MapPage(0x1000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)

	code := make([]byte, 0, 6*32+2)
	for range 32 {
		code = append(code, 0x01, 0xC8) // add eax, ecx
		code = append(code, 0x31, 0xD0) // xor eax, edx
		code = append(code, 0x29, 0xD8) // sub eax, ebx
	}
	code = append(code, 0xEB, 0xFE) // jmp $
	for i, opcode := range code {
		if err := m.Write8(0x1000+uint64(i), opcode); err != nil {
			b.Fatal(err)
		}
	}

	cache := NewCacheMode(m, true)
	if native && !cache.EnableNativeCodegen() {
		b.Skip("native codegen unavailable")
	}
	block := cache.Compile(0x1000)
	if block == nil {
		b.Fatal("failed to compile benchmark block")
	}
	if native && block.native == 0 {
		b.Fatal("native backend rejected benchmark block")
	}

	regs := [16]uint64{0: 1, 1: 3, 2: 5, 3: 7}
	rip := uint64(0x1000)
	rflags := uint64(0x202)
	instret := uint64(0)
	state := &State{
		Regs:    &regs,
		RIP:     &rip,
		Rflags:  &rflags,
		Mem:     m,
		Mode32:  true,
		Instret: &instret,
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(code)))
	b.ResetTimer()
	for range b.N {
		if err := block.Run(state); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()

	if instret == 0 {
		b.Fatal("benchmark block retired no instructions")
	}
}

func BenchmarkBlockRunPE32(b *testing.B) {
	b.Run("Closure", func(b *testing.B) {
		benchmarkPE32RegisterBlock(b, false)
	})
	b.Run("Native", func(b *testing.B) {
		benchmarkPE32RegisterBlock(b, true)
	})
}

func BenchmarkEmitPE32(b *testing.B) {
	m := mmu.New()
	cache := NewCacheMode(m, true)
	insns := make([]insn, 0, 97)
	for range 32 {
		insns = append(insns,
			insn{kind: opALURegReg, size: 4, dst: 0, src: 1, alu: aluADD},
			insn{kind: opALURegReg, size: 4, dst: 0, src: 2, alu: aluXOR},
			insn{kind: opALURegReg, size: 4, dst: 0, src: 3, alu: aluSUB},
		)
	}
	insns = append(insns, insn{kind: opJmp, target: 0x1000})

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		benchmarkCompiledBlock = cache.emit(insns)
		if benchmarkCompiledBlock == nil {
			b.Fatal("failed to emit benchmark block")
		}
	}
	benchmarkCompiledBlock = nil
}

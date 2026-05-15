package x64

import (
	"testing"

	"github.com/mirkobrombin/Raven/pkg/jit"
	"github.com/mirkobrombin/Raven/pkg/mmu"
)

func TestJITFastCachePromotesHotBlock(t *testing.T) {
	mem := mmu.New()
	const addr = uint64(0x4000)
	mem.MapPage(addr, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	code := []byte{0xB8, 0x2A, 0, 0, 0, 0xEB, 0xFE}
	for i, value := range code {
		if err := mem.Write8(addr+uint64(i), value); err != nil {
			t.Fatal(err)
		}
	}
	cpu := New(mem)
	cpu.Mode32 = true
	compiler := NewJITCompiler(cpu, mem)
	for i := 0; i < jit.CompileThreshold; i++ {
		cpu.RIP = addr
		if compiler.step(cpu) {
			t.Fatalf("block executed before hot threshold on iteration %d", i)
		}
	}
	cpu.RIP = addr
	if !compiler.step(cpu) {
		t.Fatal("hot block was not executed")
	}
	if cpu.Regs[RAX] != 42 || cpu.RIP != addr+5 {
		t.Fatalf("EAX=%d RIP=%#x", cpu.Regs[RAX], cpu.RIP)
	}
}

func TestJITFastCacheKeepsUnsupportedAddressDisabled(t *testing.T) {
	mem := mmu.New()
	const addr = uint64(0x5000)
	mem.MapPage(addr, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	for i, value := range []byte{0x0F, 0x0B} {
		if err := mem.Write8(addr+uint64(i), value); err != nil {
			t.Fatal(err)
		}
	}
	cpu := New(mem)
	cpu.Mode32 = true
	compiler := NewJITCompiler(cpu, mem)
	for i := 0; i < jit.CompileThreshold+10; i++ {
		cpu.RIP = addr
		if compiler.step(cpu) {
			t.Fatal("unsupported address was executed by JIT")
		}
	}
	entry := &compiler.fast[(addr>>1)&uint64(len(compiler.fast)-1)]
	if !entry.valid || entry.rip != addr || entry.block != nil || entry.hits != jit.CompileThreshold+1 {
		t.Fatalf("negative cache entry = %+v", *entry)
	}
}

func TestJITFastCacheObservesExecutableCodeWrite(t *testing.T) {
	mem := mmu.New()
	const addr = uint64(0x5800)
	mem.MapPage(addr, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	writeMovImmediate := func(value byte) {
		code := []byte{0xB8, value, 0, 0, 0, 0xEB, 0xFE}
		for i, opcode := range code {
			if err := mem.Write8(addr+uint64(i), opcode); err != nil {
				t.Fatal(err)
			}
		}
	}
	writeMovImmediate(42)
	cpu := New(mem)
	cpu.Mode32 = true
	compiler := NewJITCompiler(cpu, mem)
	for i := 0; i <= jit.CompileThreshold; i++ {
		cpu.RIP = addr
		compiler.step(cpu)
	}
	if cpu.Regs[RAX] != 42 {
		t.Fatalf("EAX=%d, want 42", cpu.Regs[RAX])
	}
	writeMovImmediate(43)
	for i := 0; i <= jit.CompileThreshold; i++ {
		cpu.RIP = addr
		compiler.step(cpu)
	}
	if cpu.Regs[RAX] != 43 {
		t.Fatalf("stale JIT block left EAX=%d, want 43", cpu.Regs[RAX])
	}
}

func TestJITADCAndSBBKeepCarryAcrossOperandOverflow(t *testing.T) {
	for _, test := range []struct {
		name   string
		opcode byte
	}{
		{"adc", 0x10},
		{"sbb", 0x18},
	} {
		t.Run(test.name, func(t *testing.T) {
			newCPU := func() (*CPU, *mmu.MMU) {
				mem := mmu.New()
				mem.MapPage(0x7000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
				for i, value := range []byte{test.opcode, 0xC0, 0xEB, 0xFE} {
					if err := mem.Write8(0x7000+uint64(i), value); err != nil {
						t.Fatal(err)
					}
				}
				cpu := New(mem)
				cpu.Mode32 = true
				cpu.RIP = 0x7000
				cpu.Regs[RAX] = 0xFF
				cpu.Rflags = flagCF
				return cpu, mem
			}
			interpreted, _ := newCPU()
			compiled, mem := newCPU()
			if err := interpreted.step(); err != nil {
				t.Fatal(err)
			}
			compiler := NewJITCompiler(compiled, mem)
			block := compiler.cache.Compile(compiled.RIP)
			if block == nil {
				t.Fatal("block was not compiled")
			}
			if err := block.Run(&compiler.state); err != nil {
				t.Fatal(err)
			}
			if compiled.Regs[RAX]&0xff != interpreted.Regs[RAX]&0xff || compiled.Rflags != interpreted.Rflags {
				t.Fatalf("JIT AL=%#x RFLAGS=%#x, interpreter AL=%#x RFLAGS=%#x",
					compiled.Regs[RAX]&0xff, compiled.Rflags, interpreted.Regs[RAX]&0xff, interpreted.Rflags)
			}
			if compiled.Rflags&flagCF == 0 {
				t.Fatal("carry flag is clear")
			}
		})
	}
}

func BenchmarkJITFastCachedBlock(b *testing.B) {
	mem := mmu.New()
	const addr = uint64(0x6000)
	mem.MapPage(addr, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	code := []byte{0xB8, 0x2A, 0, 0, 0, 0xEB, 0xFE}
	for i, value := range code {
		if err := mem.Write8(addr+uint64(i), value); err != nil {
			b.Fatal(err)
		}
	}
	cpu := New(mem)
	cpu.Mode32 = true
	compiler := NewJITCompiler(cpu, mem)
	for i := 0; i <= jit.CompileThreshold; i++ {
		cpu.RIP = addr
		compiler.step(cpu)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cpu.RIP = addr
		if !compiler.step(cpu) {
			b.Fatal("cached block was not executed")
		}
	}
}

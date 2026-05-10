package x64

import (
	"math"
	"testing"

	"github.com/mirkobrombin/Raven/pkg/mmu"
)

func TestJITX87MatchesInterpreter(t *testing.T) {
	tests := []struct {
		name string
		code []byte
		data uint64
	}{
		{"fadd-m32", []byte{0xD8, 0x45, 0}, uint64(math.Float32bits(3.25))},
		{"fmul-m32", []byte{0xD8, 0x4D, 0}, uint64(math.Float32bits(3.25))},
		{"fsub-m32", []byte{0xD8, 0x65, 0}, uint64(math.Float32bits(3.25))},
		{"fsubr-m32", []byte{0xD8, 0x6D, 0}, uint64(math.Float32bits(3.25))},
		{"fld-m32", []byte{0xD9, 0x45, 0}, uint64(math.Float32bits(3.25))},
		{"fstp-m32", []byte{0xD9, 0x5D, 0}, 0},
		{"fild-m32", []byte{0xDB, 0x45, 0}, 3},
		{"fistp-m32", []byte{0xDB, 0x5D, 0}, 0},
		{"fdivr-m64", []byte{0xDC, 0x7D, 0}, math.Float64bits(3.25)},
		{"fsqrt", []byte{0xD9, 0xFA}, 0},
		{"faddp", []byte{0xDE, 0xC1}, 0},
		{"fsubp", []byte{0xDE, 0xE9}, 0},
		{"fcom-m32", []byte{0xD8, 0x55, 0}, uint64(math.Float32bits(3.25))},
		{"fcomp-m32", []byte{0xD8, 0x5D, 0}, uint64(math.Float32bits(4.0))},
		{"fcom-m64", []byte{0xDC, 0x55, 0}, math.Float64bits(5.5)},
		{"fcomp-m64", []byte{0xDC, 0x5D, 0}, math.Float64bits(4.0)},
		{"fld-m64", []byte{0xDD, 0x45, 0}, math.Float64bits(6.75)},
		{"fst-m64", []byte{0xDD, 0x55, 0}, 0},
		{"fstp-m64", []byte{0xDD, 0x5D, 0}, 0},
		{"fild-m16", []byte{0xDF, 0x45, 0}, 0xFFFE},
		{"fist-m16", []byte{0xDF, 0x55, 0}, 0},
		{"fistp-m16", []byte{0xDF, 0x5D, 0}, 0},
		{"fild-m64", []byte{0xDF, 0x6D, 0}, 12345},
		{"fistp-m64", []byte{0xDF, 0x7D, 0}, 0},
		{"fadd-st-sti", []byte{0xD8, 0xC1}, 0},
		{"fmul-st-sti", []byte{0xD8, 0xC9}, 0},
		{"fcom-sti", []byte{0xD8, 0xD1}, 0},
		{"fcomp-sti", []byte{0xD8, 0xD9}, 0},
		{"fsub-st-sti", []byte{0xD8, 0xE1}, 0},
		{"fsubr-st-sti", []byte{0xD8, 0xE9}, 0},
		{"fdiv-st-sti", []byte{0xD8, 0xF1}, 0},
		{"fdivr-st-sti", []byte{0xD8, 0xF9}, 0},
		{"fld-sti", []byte{0xD9, 0xC1}, 0},
		{"fxch", []byte{0xD9, 0xC9}, 0},
		{"fchs", []byte{0xD9, 0xE0}, 0},
		{"fabs", []byte{0xD9, 0xE1}, 0},
		{"ftst", []byte{0xD9, 0xE4}, 0},
		{"fxam", []byte{0xD9, 0xE5}, 0},
		{"fld1", []byte{0xD9, 0xE8}, 0},
		{"fldpi", []byte{0xD9, 0xEB}, 0},
		{"fldz", []byte{0xD9, 0xEE}, 0},
		{"f2xm1", []byte{0xD9, 0xF0}, 0},
		{"fyl2x", []byte{0xD9, 0xF1}, 0},
		{"fptan", []byte{0xD9, 0xF2}, 0},
		{"fpatan", []byte{0xD9, 0xF3}, 0},
		{"fxtract", []byte{0xD9, 0xF4}, 0},
		{"fprem1", []byte{0xD9, 0xF5}, 0},
		{"fdecstp", []byte{0xD9, 0xF6}, 0},
		{"fincstp", []byte{0xD9, 0xF7}, 0},
		{"fprem", []byte{0xD9, 0xF8}, 0},
		{"fyl2xp1", []byte{0xD9, 0xF9}, 0},
		{"fsincos", []byte{0xD9, 0xFB}, 0},
		{"frndint", []byte{0xD9, 0xFC}, 0},
		{"fscale", []byte{0xD9, 0xFD}, 0},
		{"fsin", []byte{0xD9, 0xFE}, 0},
		{"fcos", []byte{0xD9, 0xFF}, 0},
		{"fadd-sti-st", []byte{0xDC, 0xC1}, 0},
		{"fmul-sti-st", []byte{0xDC, 0xC9}, 0},
		{"fsubr-sti-st", []byte{0xDC, 0xE1}, 0},
		{"fsub-sti-st", []byte{0xDC, 0xE9}, 0},
		{"fdivr-sti-st", []byte{0xDC, 0xF1}, 0},
		{"fdiv-sti-st", []byte{0xDC, 0xF9}, 0},
		{"ffree", []byte{0xDD, 0xC1}, 0},
		{"fst-sti", []byte{0xDD, 0xD1}, 0},
		{"fstp-sti", []byte{0xDD, 0xD9}, 0},
		{"fucom-sti", []byte{0xDD, 0xE1}, 0},
		{"fucomp-sti", []byte{0xDD, 0xE9}, 0},
		{"fcompp", []byte{0xDE, 0xD9}, 0},
		{"fnstsw-ax", []byte{0xDF, 0xE0}, 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			interpreted, interpretedMem := newX87TestCPU(t, test.code, test.data)
			compiled, compiledMem := newX87TestCPU(t, test.code, test.data)
			if err := interpreted.step(); err != nil {
				t.Fatal(err)
			}
			compiler := NewJITCompiler(compiled, compiledMem)
			block := compiler.cache.Compile(compiled.RIP)
			if block == nil {
				t.Fatal("x87 block was not compiled")
			}
			if err := block.Run(&compiler.state); err != nil {
				t.Fatal(err)
			}
			if compiled.fpuST != interpreted.fpuST || compiled.fpuTop != interpreted.fpuTop || compiled.fpuTW != interpreted.fpuTW {
				t.Fatalf("compiled FPU state differs: ST=%v top=%d tag=%#x, want ST=%v top=%d tag=%#x",
					compiled.fpuST, compiled.fpuTop, compiled.fpuTW, interpreted.fpuST, interpreted.fpuTop, interpreted.fpuTW)
			}
			if compiled.fpuSW != interpreted.fpuSW {
				t.Fatalf("compiled FPU status word=%#x, want %#x", compiled.fpuSW, interpreted.fpuSW)
			}
			if compiled.Regs[RAX] != interpreted.Regs[RAX] {
				t.Fatalf("compiled RAX=%#x, want %#x", compiled.Regs[RAX], interpreted.Regs[RAX])
			}
			got, err := compiledMem.Read64(0x9000)
			if err != nil {
				t.Fatal(err)
			}
			want, err := interpretedMem.Read64(0x9000)
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Fatalf("memory=%#x, want %#x", got, want)
			}
		})
	}
}

func newX87TestCPU(t *testing.T, instruction []byte, data uint64) (*CPU, *mmu.MMU) {
	t.Helper()
	mem := mmu.New()
	mem.MapPage(0x8000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	mem.MapPage(0x9000, mmu.PermRead|mmu.PermWrite)
	code := append(append([]byte{}, instruction...), 0xEB, 0xFE)
	for i, value := range code {
		if err := mem.Write8(0x8000+uint64(i), value); err != nil {
			t.Fatal(err)
		}
	}
	if err := mem.Write64(0x9000, data); err != nil {
		t.Fatal(err)
	}
	cpu := New(mem)
	cpu.Mode32 = true
	cpu.RIP = 0x8000
	cpu.Regs[RBP] = 0x9000
	cpu.fpuST[0] = 4
	cpu.fpuST[1] = 2
	cpu.fpuTop = 0
	cpu.fpuTW = 0
	cpu.fpuSW = 0x0102 // pre-set C1 + an exception flag so FNSTSW/CC ops are observable
	return cpu, mem
}

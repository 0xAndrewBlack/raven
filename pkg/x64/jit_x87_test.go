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
			if !x87StacksEqual(compiled.fpuST, interpreted.fpuST) || compiled.fpuTop != interpreted.fpuTop || compiled.fpuTW != interpreted.fpuTW {
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

func TestJITX87FISTM32OutOfRangeParity(t *testing.T) {
	for _, test := range []struct {
		name  string
		code  []byte
		value float64
	}{
		{"fist-positive", []byte{0xDB, 0x55, 0}, math.Ldexp(1, 31)},
		{"fist-negative", []byte{0xDB, 0x55, 0}, -math.Ldexp(1, 31) - 1},
		{"fistp-positive", []byte{0xDB, 0x5D, 0}, math.Ldexp(1, 31)},
		{"fistp-negative", []byte{0xDB, 0x5D, 0}, -math.Ldexp(1, 31) - 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			interpreted, compiled, interpretedMem, compiledMem := runX87ParityCase(t, test.code, 0, func(cpu *CPU) {
				cpu.fpuSetST0(test.value)
				cpu.fpuSW = 0
			})
			assertX87Parity(t, compiled, interpreted, compiledMem, interpretedMem)
			for name, mem := range map[string]*mmu.MMU{"interpreter": interpretedMem, "jit": compiledMem} {
				got, err := mem.Read32(0x9000)
				if err != nil {
					t.Fatal(err)
				}
				if got != 0x80000000 {
					t.Fatalf("%s result=%#x, want indefinite integer", name, got)
				}
			}
			if interpreted.fpuSW&fpuExcInvalid == 0 || compiled.fpuSW&fpuExcInvalid == 0 {
				t.Fatalf("invalid exception missing: interpreter=%#x jit=%#x", interpreted.fpuSW, compiled.fpuSW)
			}
		})
	}
}

func TestJITX87FISTPM64BoundaryParity(t *testing.T) {
	for _, test := range []struct {
		name        string
		value       float64
		wantInvalid bool
	}{
		{"largest-valid", math.Nextafter(math.Ldexp(1, 63), 0), false},
		{"positive-overflow", math.Ldexp(1, 63), true},
		{"negative-limit", -math.Ldexp(1, 63), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			interpreted, compiled, interpretedMem, compiledMem := runX87ParityCase(t, []byte{0xDF, 0x7D, 0}, 0, func(cpu *CPU) {
				cpu.fpuSetST0(test.value)
				cpu.fpuSW = 0
			})
			assertX87Parity(t, compiled, interpreted, compiledMem, interpretedMem)
			if (compiled.fpuSW&fpuExcInvalid != 0) != test.wantInvalid {
				t.Fatalf("status=%#x, want invalid=%v", compiled.fpuSW, test.wantInvalid)
			}
			if test.wantInvalid {
				got, err := compiledMem.Read64(0x9000)
				if err != nil {
					t.Fatal(err)
				}
				if got != 1<<63 {
					t.Fatalf("result=%#x, want indefinite integer", got)
				}
			}
		})
	}
}

func TestJITX87StoreMemoryFaultRestoresFPUState(t *testing.T) {
	compiled, mem := newX87TestCPU(t, []byte{0xD9, 0x5D, 0}, 0)
	compiled.Regs[RBP] = 0x9FFF
	compiled.fpuSetST0(1 + math.Ldexp(1, -30))
	if err := mem.Write8(0x9FFF, 0xA5); err != nil {
		t.Fatal(err)
	}
	beforeST := compiled.fpuST
	beforeTop := compiled.fpuTop
	beforeCW := compiled.fpuCW
	beforeSW := compiled.fpuSW
	beforeTW := compiled.fpuTW
	compiler := NewJITCompiler(compiled, mem)
	block := compiler.cache.Compile(compiled.RIP)
	if block == nil {
		t.Fatal("x87 block was not compiled")
	}
	if err := block.Run(&compiler.state); err == nil {
		t.Fatal("unmapped x87 store did not fault")
	}
	if !x87StacksEqual(compiled.fpuST, beforeST) || compiled.fpuTop != beforeTop ||
		compiled.fpuCW != beforeCW || compiled.fpuSW != beforeSW || compiled.fpuTW != beforeTW {
		t.Fatalf("fault changed FPU state: ST=%v top=%d cw=%#x sw=%#x tw=%#x",
			compiled.fpuST, compiled.fpuTop, compiled.fpuCW, compiled.fpuSW, compiled.fpuTW)
	}
	if got, err := mem.Read8(0x9FFF); err != nil || got != 0xA5 {
		t.Fatalf("faulting store changed mapped prefix=%#x err=%v", got, err)
	}
}

func TestJITX87EmptyStackControlParity(t *testing.T) {
	for _, test := range []struct {
		name    string
		code    []byte
		wantTop int
		wantSW  uint16
	}{
		{"fxch-st0", []byte{0xD9, 0xC8}, 0, fpuExcInvalid | fpuStackFault},
		{"fdecstp", []byte{0xD9, 0xF6}, 7, 0},
		{"fincstp", []byte{0xD9, 0xF7}, 1, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			interpreted, compiled, interpretedMem, compiledMem := runX87ParityCase(t, test.code, 0, func(cpu *CPU) {
				cpu.fpuCW = 0x037F
				cpu.fpuSW = 0x0200
				cpu.fpuTW = 0xFFFF
			})
			assertX87Parity(t, compiled, interpreted, compiledMem, interpretedMem)
			if compiled.fpuTop != test.wantTop || compiled.fpuSW != test.wantSW {
				t.Fatalf("top=%d status=%#x, want top=%d status=%#x",
					compiled.fpuTop, compiled.fpuSW, test.wantTop, test.wantSW)
			}
		})
	}
}

func TestJITX87EmptyFXCHUnmaskedRollback(t *testing.T) {
	for name, useJIT := range map[string]bool{"interpreter": false, "jit": true} {
		t.Run(name, func(t *testing.T) {
			cpu, mem := newX87TestCPU(t, []byte{0xD9, 0xC8}, 0)
			cpu.fpuCW = 0x037E
			cpu.fpuSW = 0x0200
			cpu.fpuTW = 0xFFFF
			beforeST := cpu.fpuST
			var err error
			if useJIT {
				compiler := NewJITCompiler(cpu, mem)
				block := compiler.cache.Compile(cpu.RIP)
				if block == nil {
					t.Fatal("x87 block was not compiled")
				}
				err = block.Run(&compiler.state)
			} else {
				err = cpu.step()
			}
			if err == nil {
				t.Fatal("empty FXCH ST(0) did not raise unmasked invalid exception")
			}
			if !x87StacksEqual(cpu.fpuST, beforeST) || cpu.fpuTop != 0 || cpu.fpuTW != 0xFFFF {
				t.Fatalf("unmasked FXCH changed stack: ST=%v top=%d tags=%#x", cpu.fpuST, cpu.fpuTop, cpu.fpuTW)
			}
			if cpu.fpuSW != fpuExcInvalid|fpuStackFault|fpuErrorSummary {
				t.Fatalf("status=%#x, want IE|SF|ES with C1 clear", cpu.fpuSW)
			}
		})
	}
}

func TestJITX87PrecisionControlParity(t *testing.T) {
	for _, test := range []struct {
		name  string
		code  []byte
		setup func(*CPU)
		check func(*testing.T, *CPU)
	}{
		{
			name: "fadd-pc24",
			code: []byte{0xD8, 0xC1},
			setup: func(cpu *CPU) {
				cpu.fpuSetST0(1)
				cpu.fpuSetSTi(1, math.Ldexp(1, -30))
			},
			check: func(t *testing.T, cpu *CPU) {
				assertX87Value(t, cpu.fpuST0(), 1)
				if cpu.fpuSW&fpuExcPrecision == 0 {
					t.Fatalf("single-precision FADD did not set precision exception: status=%#x", cpu.fpuSW)
				}
			},
		},
		{
			name: "f2xm1",
			code: []byte{0xD9, 0xF0},
			setup: func(cpu *CPU) {
				cpu.fpuSetST0(0.5)
			},
			check: func(t *testing.T, cpu *CPU) {
				assertX87Value(t, cpu.fpuST0(), math.Exp2(0.5)-1)
			},
		},
		{
			name: "fptan",
			code: []byte{0xD9, 0xF2},
			setup: func(cpu *CPU) {
				cpu.fpuSetST0(0.5)
			},
			check: func(t *testing.T, cpu *CPU) {
				assertX87Value(t, cpu.fpuST0(), 1)
				assertX87Value(t, cpu.fpuSTi(1), math.Tan(0.5))
			},
		},
		{
			name: "fpatan",
			code: []byte{0xD9, 0xF3},
			setup: func(cpu *CPU) {
				cpu.fpuSetST0(0.5)
				cpu.fpuSetSTi(1, 0.75)
			},
			check: func(t *testing.T, cpu *CPU) {
				assertX87Value(t, cpu.fpuST0(), math.Atan2(0.75, 0.5))
			},
		},
		{
			name: "fsincos",
			code: []byte{0xD9, 0xFB},
			setup: func(cpu *CPU) {
				cpu.fpuSetST0(0.5)
			},
			check: func(t *testing.T, cpu *CPU) {
				sine, cosine := math.Sincos(0.5)
				assertX87Value(t, cpu.fpuST0(), cosine)
				assertX87Value(t, cpu.fpuSTi(1), sine)
			},
		},
		{
			name: "fscale",
			code: []byte{0xD9, 0xFD},
			setup: func(cpu *CPU) {
				cpu.fpuSetST0(1 + math.Ldexp(1, -30))
				cpu.fpuSetSTi(1, 1)
			},
			check: func(t *testing.T, cpu *CPU) {
				assertX87Value(t, cpu.fpuST0(), 2+math.Ldexp(1, -29))
			},
		},
		{
			name: "fsin",
			code: []byte{0xD9, 0xFE},
			setup: func(cpu *CPU) {
				cpu.fpuSetST0(0.5)
			},
			check: func(t *testing.T, cpu *CPU) {
				assertX87Value(t, cpu.fpuST0(), math.Sin(0.5))
			},
		},
		{
			name: "fcos",
			code: []byte{0xD9, 0xFF},
			setup: func(cpu *CPU) {
				cpu.fpuSetST0(0.5)
			},
			check: func(t *testing.T, cpu *CPU) {
				assertX87Value(t, cpu.fpuST0(), math.Cos(0.5))
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			interpreted, compiled, interpretedMem, compiledMem := runX87ParityCase(t, test.code, 0, func(cpu *CPU) {
				cpu.fpuCW &^= 3 << 8
				cpu.fpuSW = 0
				test.setup(cpu)
			})
			assertX87Parity(t, compiled, interpreted, compiledMem, interpretedMem)
			test.check(t, interpreted)
			test.check(t, compiled)
		})
	}
}

func TestJITX87FXTRACTSpecialParity(t *testing.T) {
	signalingNaN := math.Float64frombits(0x7FF0000000000001)
	quietNaN := math.Float64frombits(0x7FF8000000000001)
	for _, test := range []struct {
		name        string
		value       float64
		wantSig     float64
		wantExp     float64
		wantInvalid bool
		wantZero    bool
	}{
		{"+zero", 0, 0, math.Inf(-1), false, true},
		{"-zero", math.Copysign(0, -1), math.Copysign(0, -1), math.Inf(-1), false, true},
		{"+infinity", math.Inf(1), math.Inf(1), math.Inf(1), false, false},
		{"-infinity", math.Inf(-1), math.Inf(-1), math.Inf(1), false, false},
		{"quiet-nan", quietNaN, quietNaN, quietNaN, false, false},
		{"signaling-nan", signalingNaN, quietNaN, quietNaN, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			interpreted, compiled, interpretedMem, compiledMem := runX87ParityCase(t, []byte{0xD9, 0xF4}, 0, func(cpu *CPU) {
				cpu.fpuSetST0(test.value)
				cpu.fpuSW = 0x0200
			})
			assertX87Parity(t, compiled, interpreted, compiledMem, interpretedMem)
			for name, cpu := range map[string]*CPU{"interpreter": interpreted, "jit": compiled} {
				if !x87FloatEqual(cpu.fpuST0(), test.wantSig) || !x87FloatEqual(cpu.fpuSTi(1), test.wantExp) {
					t.Fatalf("%s significand=%v exponent=%v, want %v and %v",
						name, cpu.fpuST0(), cpu.fpuSTi(1), test.wantSig, test.wantExp)
				}
				if (cpu.fpuSW&fpuExcInvalid != 0) != test.wantInvalid ||
					(cpu.fpuSW&fpuExcZero != 0) != test.wantZero {
					t.Fatalf("%s status=%#x, want invalid=%v zero=%v",
						name, cpu.fpuSW, test.wantInvalid, test.wantZero)
				}
				if cpu.fpuSW&0x0200 != 0 {
					t.Fatalf("%s FXTRACT left C1 set: status=%#x", name, cpu.fpuSW)
				}
			}
		})
	}
}

func runX87ParityCase(t *testing.T, code []byte, data uint64, setup func(*CPU)) (*CPU, *CPU, *mmu.MMU, *mmu.MMU) {
	t.Helper()
	interpreted, interpretedMem := newX87TestCPU(t, code, data)
	compiled, compiledMem := newX87TestCPU(t, code, data)
	setup(interpreted)
	setup(compiled)
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
	return interpreted, compiled, interpretedMem, compiledMem
}

func assertX87Parity(t *testing.T, got, want *CPU, gotMem, wantMem *mmu.MMU) {
	t.Helper()
	if !x87StacksEqual(got.fpuST, want.fpuST) || got.fpuTop != want.fpuTop || got.fpuTW != want.fpuTW {
		t.Fatalf("compiled FPU state differs: ST=%v top=%d tag=%#x, want ST=%v top=%d tag=%#x",
			got.fpuST, got.fpuTop, got.fpuTW, want.fpuST, want.fpuTop, want.fpuTW)
	}
	if got.fpuCW != want.fpuCW || got.fpuSW != want.fpuSW {
		t.Fatalf("compiled FPU control/status=%#x/%#x, want %#x/%#x", got.fpuCW, got.fpuSW, want.fpuCW, want.fpuSW)
	}
	if got.Regs[RAX] != want.Regs[RAX] {
		t.Fatalf("compiled RAX=%#x, want %#x", got.Regs[RAX], want.Regs[RAX])
	}
	gotValue, err := gotMem.Read64(0x9000)
	if err != nil {
		t.Fatal(err)
	}
	wantValue, err := wantMem.Read64(0x9000)
	if err != nil {
		t.Fatal(err)
	}
	if gotValue != wantValue {
		t.Fatalf("memory=%#x, want %#x", gotValue, wantValue)
	}
}

func x87StacksEqual(a, b [8]float64) bool {
	for i := range a {
		if math.Float64bits(a[i]) != math.Float64bits(b[i]) {
			return false
		}
	}
	return true
}

func x87FloatEqual(got, want float64) bool {
	return math.Float64bits(got) == math.Float64bits(want)
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
	cpu.fpuTW = 0xFFF0
	cpu.fpuSW = 0x0302 // pre-set C0, C1, and an exception flag
	return cpu, mem
}

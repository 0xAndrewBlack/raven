package x64

import (
	"fmt"
	"math"
	"math/rand"
	"testing"

	"github.com/mirkobrombin/Raven/pkg/mmu"
)

func TestX87ReferenceStackAndTags(t *testing.T) {
	cpu := New(mmu.New())
	cpu.fpuInit()
	for i := 0; i < 8; i++ {
		cpu.fpuPush(float64(i + 1))
	}
	if cpu.fpuTop != 0 || cpu.fpuTW != 0 {
		t.Fatalf("full stack top=%d tag=%#x", cpu.fpuTop, cpu.fpuTW)
	}
	cpu.fpuPush(9)
	if !math.IsNaN(cpu.fpuST0()) || cpu.fpuSW&fpuExcInvalid == 0 || cpu.fpuSW&fpuStackFault == 0 {
		t.Fatalf("overflow value=%v sw=%#x", cpu.fpuST0(), cpu.fpuSW)
	}
	cpu.fpuInit()
	cpu.fpuPush(0)
	zeroTag := (cpu.fpuTW >> uint(cpu.fpuTop*2)) & 3
	if zeroTag != 1 {
		t.Fatalf("zero tag=%#x", zeroTag)
	}
	cpu.fpuPush(math.Inf(1))
	specialTag := (cpu.fpuTW >> uint(cpu.fpuTop*2)) & 3
	if specialTag != 2 {
		t.Fatalf("special tag=%#x", specialTag)
	}
	cpu.fpuPush(math.SmallestNonzeroFloat64)
	denormalTag := (cpu.fpuTW >> uint(cpu.fpuTop*2)) & 3
	if denormalTag != 2 {
		t.Fatalf("denormal tag=%#x", denormalTag)
	}
	cpu.fpuPop()
	cpu.fpuPop()
	cpu.fpuPop()
	cpu.fpuPop()
	if cpu.fpuSW&fpuStackFault == 0 || cpu.fpuTop != 1 {
		t.Fatalf("underflow top=%d sw=%#x", cpu.fpuTop, cpu.fpuSW)
	}
}

func TestX87ReferenceIntegerConversion(t *testing.T) {
	cases := []struct {
		name  string
		value float64
		cw    uint16
		want  int64
	}{
		{"nearest_even", 2.5, 0x037F, 2},
		{"down_negative", -2.25, 0x077F, -3},
		{"up_positive", 2.25, 0x0B7F, 3},
		{"truncate", -2.75, 0x0F7F, -2},
		{"indefinite_nan", math.NaN(), 0x037F, -1 << 31},
		{"indefinite_large", math.Inf(1), 0x037F, -1 << 31},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cpu := New(mmu.New())
			cpu.fpuCW = tc.cw
			got := fpuConvertInt(tc.value, 32, false, cpu)
			if got != tc.want {
				t.Fatalf("got %d want %d", got, tc.want)
			}
		})
	}
}

func TestX87ReferenceFloat80(t *testing.T) {
	cases := []struct {
		name string
		lo   uint64
		hi   uint16
		want float64
	}{
		{"positive_zero", 0, 0, 0},
		{"negative_zero", 0, 0x8000, math.Copysign(0, -1)},
		{"one", 0x8000000000000000, 0x3FFF, 1},
		{"negative", 0xF700000000000000, 0xC005, -123.5},
		{"smallest_float64", 0x8000000000000000, 0x3BCD, math.SmallestNonzeroFloat64},
		{"extended_subnormal", 1, 0, 0},
		{"negative_extended_subnormal", 1, 0x8000, math.Copysign(0, -1)},
		{"positive_infinity", 0x8000000000000000, 0x7FFF, math.Inf(1)},
		{"negative_infinity", 0x8000000000000000, 0xFFFF, math.Inf(-1)},
		{"nan", 0xC000000000000000, 0x7FFF, math.NaN()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := float80ToFloat64Value(tc.lo, tc.hi)
			if math.IsNaN(tc.want) {
				if !math.IsNaN(got) {
					t.Fatalf("got %v", got)
				}
				return
			}
			if math.Float64bits(got) != math.Float64bits(tc.want) {
				t.Fatalf("got bits=%#x want %#x", math.Float64bits(got), math.Float64bits(tc.want))
			}
		})
	}
}

func TestX87ReferenceEnvironmentLogicalOrder(t *testing.T) {
	cpu := New(mmu.New())
	cpu.fpuInit()
	cpu.fpuPush(11)
	cpu.fpuPush(22)
	cpu.fpuTop = 5
	cpu.fpuSW = 5 << 11
	mem := mmu.New()
	if err := mem.MapPage(0x9000, mmu.PermRead|mmu.PermWrite); err != nil {
		t.Fatal(err)
	}
	cpu.mem = mem
	if err := cpu.fpuStoreSaveImage(0x9000, &prefixState{}); err != nil {
		t.Fatal(err)
	}
	copyCPU := New(mem)
	if err := copyCPU.fpuRestore(0x9000, &prefixState{}); err != nil {
		t.Fatal(err)
	}
	if copyCPU.fpuTop != 5 || copyCPU.fpuTW != cpu.fpuTW {
		t.Fatalf("restored top=%d tag=%#x", copyCPU.fpuTop, copyCPU.fpuTW)
	}
	if copyCPU.fpuST[copyCPU.fpuPhys(0)] != cpu.fpuST[cpu.fpuPhys(0)] || copyCPU.fpuST[copyCPU.fpuPhys(1)] != cpu.fpuST[cpu.fpuPhys(1)] {
		t.Fatalf("logical stack order changed")
	}
}

func TestX87ReferenceSinglePrecisionControl(t *testing.T) {
	cpu := New(mmu.New())
	cpu.fpuInit()
	cpu.fpuCW = (cpu.fpuCW &^ (3 << 8)) | (0 << 8)
	value := 1.0 + math.Ldexp(1, -30)
	cpu.fpuPush(value)
	cpu.fpuSetST0(value)
	if cpu.fpuST0() != value {
		t.Fatalf("register load was precision-rounded: %v", cpu.fpuST0())
	}
	cpu.fpuSetST0Result(value)
	if cpu.fpuST0() != float64(float32(value)) {
		t.Fatalf("single precision result=%v", cpu.fpuST0())
	}
	for _, tc := range []struct {
		name string
		cw   uint16
		want float64
	}{
		{"down positive", 1 << 10, float64(math.Nextafter32(1, float32(math.Inf(-1))))},
		{"up negative", 2 << 10, float64(math.Nextafter32(-1, float32(math.Inf(1))))},
		{"truncate positive", 3 << 10, float64(math.Nextafter32(1, float32(math.Inf(-1))))},
		{"truncate negative", 3 << 10, float64(math.Nextafter32(-1, float32(math.Inf(1))))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := 1.0 - math.Ldexp(1, -25)
			if tc.name == "up negative" || tc.name == "truncate negative" {
				input = -input
			}
			if got := fpuRoundFloat32(input, tc.cw); got != tc.want {
				t.Fatalf("rounded=%v want=%v", got, tc.want)
			}
		})
	}
}

func TestX87ReferenceMemoryFaultIsAtomic(t *testing.T) {
	mem := mmu.New()
	if err := mem.MapPage(0x8000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute); err != nil {
		t.Fatal(err)
	}
	if err := mem.MapPage(0x9000, mmu.PermRead|mmu.PermWrite); err != nil {
		t.Fatal(err)
	}
	code := []byte{0xD9, 0x5D, 0x00}
	for i, b := range code {
		if err := mem.Write8(0x8000+uint64(i), b); err != nil {
			t.Fatal(err)
		}
	}
	if err := mem.Write8(0x9FFF, 0xA5); err != nil {
		t.Fatal(err)
	}
	cpu := New(mem)
	cpu.Mode32 = true
	cpu.RIP = 0x8000
	cpu.Regs[RBP] = 0x9FFF
	cpu.fpuST[0] = 3.25
	cpu.fpuTW = 0
	if err := cpu.step(); err == nil {
		t.Fatal("cross-page store did not fault")
	}
	got, err := mem.Read8(0x9FFF)
	if err != nil {
		t.Fatal(err)
	}
	if got != 0xA5 {
		t.Fatalf("partial store changed byte to %#x", got)
	}
	if cpu.RIP != 0x8003 {
		t.Fatalf("fault RIP=%#x", cpu.RIP)
	}
	if cpu.GetInstret() != 0 {
		t.Fatalf("fault retired instruction count=%d", cpu.GetInstret())
	}
}

func TestX87ReferenceRoundingRandomized(t *testing.T) {
	rng := rand.New(rand.NewSource(0x87))
	for i := 0; i < 50; i++ {
		value := rng.Float64()*2000 - 1000
		for _, mode := range []uint16{0, 1, 2, 3} {
			cw := uint16(0x037F) | mode<<10
			got := fpuRoundFloat(value, cw)
			var want float64
			switch mode {
			case 0:
				want = math.RoundToEven(value)
			case 1:
				want = math.Floor(value)
			case 2:
				want = math.Ceil(value)
			default:
				want = math.Trunc(value)
			}
			if got != want {
				t.Fatalf("value=%v mode=%d got=%v want=%v", value, mode, got, want)
			}
		}
	}
}

func TestX87ReferenceExceptionMasks(t *testing.T) {
	cpu := New(mmu.New())
	cpu.fpuInit()
	cpu.fpuPush(1)
	masked := cpu.fpuDivide(cpu.fpuST0(), 0)
	if !math.IsInf(masked, 1) || cpu.fpuSW&fpuExcZero == 0 || cpu.fpuSW&fpuErrorSummary != 0 {
		t.Fatalf("masked divide result=%v sw=%#x", masked, cpu.fpuSW)
	}
	cpu, _ = newX87ReferenceCPU(t, []byte{0xD8, 0xF1}, 0)
	cpu.fpuCW &^= fpuExcZero
	cpu.fpuSetST0(1)
	cpu.fpuSetSTi(1, 0)
	if err := cpu.step(); err == nil {
		t.Fatal("unmasked divide did not fault")
	}
	if cpu.fpuSW&fpuExcZero == 0 || cpu.fpuSW&fpuErrorSummary == 0 {
		t.Fatalf("unmasked divide sw=%#x", cpu.fpuSW)
	}
	cpu = New(mmu.New())
	cpu.fpuInit()
	cpu.fpuCW &^= fpuExcPrecision
	if !cpu.fpuSignal(fpuExcInvalid|fpuExcPrecision, false) || cpu.fpuSW&fpuErrorSummary == 0 {
		t.Fatalf("mixed mask did not expose unmasked exception sw=%#x", cpu.fpuSW)
	}
}

func TestX87ReferenceSignedZeroAndSpecialArithmetic(t *testing.T) {
	cpu := New(mmu.New())
	cpu.fpuInit()
	got := cpu.fpuAdd(1, -1)
	if math.Signbit(got) {
		t.Fatalf("nearest cancellation sign=%v", got)
	}
	cpu.fpuCW |= 1 << 10
	got = cpu.fpuSubtract(1, 1)
	if !math.Signbit(got) {
		t.Fatalf("downward cancellation sign=%v", got)
	}
	if !math.IsInf(cpu.fpuDivide(math.Inf(1), 0), 1) || cpu.fpuSW&fpuExcZero != 0 {
		t.Fatalf("infinity divide status=%#x", cpu.fpuSW)
	}
	signaling := math.Float64frombits(0x7FF0000000000001)
	cpu.fpuAdd(signaling, 1)
	if cpu.fpuSW&fpuExcInvalid == 0 {
		t.Fatalf("signaling NaN arithmetic status=%#x", cpu.fpuSW)
	}
}

func TestX87ReferenceFXTRACTAndRemainder(t *testing.T) {
	cpu, _ := newX87ReferenceCPU(t, []byte{0xD9, 0xF4}, 0)
	cpu.fpuSetST0(6)
	if err := cpu.step(); err != nil {
		t.Fatal(err)
	}
	assertX87Value(t, cpu.fpuST0(), 1.5)
	assertX87Value(t, cpu.fpuSTi(1), 2)

	cpu, _ = newX87ReferenceCPU(t, []byte{0xD9, 0xF8}, 0)
	cpu.fpuSetST0(5)
	cpu.fpuSetSTi(1, 2)
	if err := cpu.step(); err != nil {
		t.Fatal(err)
	}
	assertX87Value(t, cpu.fpuST0(), 1)
	assertX87CC(t, cpu, 0, 0, 1)
}

func TestX87ReferenceQuietAndSignalingNaNCompare(t *testing.T) {
	quiet := math.Float64frombits(0x7FF8000000000001)
	signaling := math.Float64frombits(0x7FF0000000000001)
	for _, tc := range []struct {
		name  string
		code  []byte
		value float64
		quiet bool
	}{
		{"fcom-quiet", []byte{0xD8, 0xD1}, quiet, false},
		{"fucom-quiet", []byte{0xDD, 0xE1}, quiet, true},
		{"fucom-signaling", []byte{0xDD, 0xE1}, signaling, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cpu, _ := newX87ReferenceCPU(t, tc.code, 0)
			cpu.fpuSetST0(tc.value)
			if err := cpu.step(); err != nil {
				t.Fatal(err)
			}
			if cpu.fpuSW&0x4500 != 0x4500 {
				t.Fatalf("unordered CC=%#x", cpu.fpuSW&0x4700)
			}
			wantInvalid := !tc.quiet || fpuSignalingNaN(tc.value)
			if (cpu.fpuSW&fpuExcInvalid != 0) != wantInvalid {
				t.Fatalf("invalid=%v want %v sw=%#x", cpu.fpuSW&fpuExcInvalid != 0, wantInvalid, cpu.fpuSW)
			}
		})
	}
}

func TestX87ReferenceCompareFlags(t *testing.T) {
	cpu, _ := newX87ReferenceCPU(t, []byte{0xDB, 0xF1}, 0)
	cpu.Rflags = flagCF | flagPF | flagZF | flagOF | flagSF | flagAF
	if err := cpu.step(); err != nil {
		t.Fatal(err)
	}
	if cpu.Rflags&(flagCF|flagPF|flagZF|flagOF|flagSF|flagAF) != 0 {
		t.Fatalf("FCOMI flags=%#x", cpu.Rflags)
	}
	cpu, _ = newX87ReferenceCPU(t, []byte{0xDF, 0xF1}, 0)
	cpu.Rflags = flagCF | flagPF | flagZF | flagOF | flagSF | flagAF
	if err := cpu.step(); err != nil {
		t.Fatal(err)
	}
	if cpu.fpuTop != 7 || cpu.Rflags&(flagCF|flagPF|flagZF|flagOF|flagSF|flagAF) != 0 {
		t.Fatalf("FCOMIP top=%d flags=%#x", cpu.fpuTop, cpu.Rflags)
	}
}

func TestX87ReferenceEnvironmentExecutionModes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mode32 bool
		prefix bool
		size   uint64
	}{
		{"pe32-default", true, false, 28},
		{"pe32-66", true, true, 14},
		{"pe64-default", false, false, 28},
		{"pe64-66", false, true, 14},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code := []byte{0xD9, 0x75, 0}
			if tc.prefix {
				code = append([]byte{0x66}, code...)
			}
			cpu, mem := newX87ReferenceCPU(t, code, 0)
			cpu.Mode32 = tc.mode32
			for i := uint64(0); i < 32; i++ {
				if err := mem.Write8(0x9000+i, 0xA5); err != nil {
					t.Fatal(err)
				}
			}
			if err := cpu.step(); err != nil {
				t.Fatal(err)
			}
			value, err := mem.Read8(0x9000 + tc.size)
			if err != nil {
				t.Fatal(err)
			}
			if value != 0xA5 {
				t.Fatalf("env wrote byte %d", tc.size)
			}
		})
	}
}

func TestX87ReferenceControlAndSaveSideEffects(t *testing.T) {
	cpu := New(mmu.New())
	cpu.fpuInit()
	cpu.fpuLoadCW(0xFFFF)
	if cpu.fpuCW != 0x0F7F {
		t.Fatalf("FLDCW reserved bits cw=%#x", cpu.fpuCW)
	}
	cpu, mem := newX87ReferenceCPU(t, []byte{0xD9, 0x75, 0}, 0)
	cpu.fpuCW = 0
	cpu.fpuSW = fpuExcInvalid | fpuErrorSummary
	if err := cpu.step(); err != nil {
		t.Fatal(err)
	}
	if cpu.fpuCW&0x3F != 0x3F || cpu.fpuSW&fpuErrorSummary != 0 {
		t.Fatalf("FNSTENV side effects cw=%#x sw=%#x", cpu.fpuCW, cpu.fpuSW)
	}
	cpu, mem = newX87ReferenceCPU(t, []byte{0xDD, 0x75, 0}, 0)
	cpu.fpuCW = 0x0200
	if err := mem.Write8(0x9000+108, 0x5A); err != nil {
		t.Fatal(err)
	}
	if err := cpu.step(); err != nil {
		t.Fatal(err)
	}
	if cpu.fpuCW != 0x037F || cpu.fpuTop != 0 || cpu.fpuTW != 0xFFFF {
		t.Fatalf("FNSAVE reset cw=%#x top=%d tag=%#x", cpu.fpuCW, cpu.fpuTop, cpu.fpuTW)
	}
	if value, err := mem.Read8(0x9000 + 108); err != nil || value != 0x5A {
		t.Fatalf("save image wrote past 108 bytes: %#x err=%v", value, err)
	}
	cpu, _ = newX87ReferenceCPU(t, []byte{0xDF, 0xE0}, 0)
	cpu.fpuTop = 5
	cpu.fpuSW = 0x4521
	cpu.Regs[RAX] = 0xFFFF0000
	if err := cpu.step(); err != nil {
		t.Fatal(err)
	}
	if cpu.Regs[RAX]&0xFFFF != uint64(0x4521|5<<11) {
		t.Fatalf("FNSTSW AX=%#x", cpu.Regs[RAX]&0xFFFF)
	}
	cpu, _ = newX87ReferenceCPU(t, []byte{0xDB, 0xE2}, 0)
	cpu.fpuSW = fpuExcInvalid | fpuErrorSummary | 0x4700 | 0x8000
	if err := cpu.step(); err != nil {
		t.Fatal(err)
	}
	if cpu.fpuSW&0x80FF != 0 || cpu.fpuSW&0x4700 != 0x4700 {
		t.Fatalf("FNCLEX status=%#x", cpu.fpuSW)
	}
}

func TestX87ReferenceIntegerBoundaries(t *testing.T) {
	max32 := math.Ldexp(1, 31) - 1
	for _, tc := range []struct {
		name  string
		value float64
		bits  int
		want  int64
	}{
		{"min16", -32768, 16, -32768},
		{"max16", 32767, 16, 32767},
		{"below16", -32769, 16, -32768},
		{"above16", 32768, 16, -32768},
		{"max32", max32, 32, 2147483647},
		{"above32", math.Ldexp(1, 31), 32, -2147483648},
		{"min64", -9223372036854775808.0, 64, -9223372036854775808},
		{"above64", 9223372036854775808.0, 64, -9223372036854775808},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cpu := New(mmu.New())
			got := fpuConvertInt(tc.value, tc.bits, true, cpu)
			if got != tc.want {
				t.Fatalf("got %d want %d", got, tc.want)
			}
		})
	}
}

func TestX87ReferenceStoreConversionFaultsAreAtomic(t *testing.T) {
	cpu, mem := newX87ReferenceCPU(t, []byte{0xD9, 0x55, 0x00}, 0)
	cpu.fpuSetST0(1 + math.Ldexp(1, -30))
	if err := cpu.step(); err != nil {
		t.Fatal(err)
	}
	stored, err := mem.Read32(0x9000)
	if err != nil {
		t.Fatal(err)
	}
	if math.Float32frombits(stored) != 1 || cpu.fpuSW&fpuExcPrecision == 0 {
		t.Fatalf("masked m32 store value=%v sw=%#x", math.Float32frombits(stored), cpu.fpuSW)
	}

	cpu, mem = newX87ReferenceCPU(t, []byte{0xD9, 0x55, 0x00}, 0xA5A5A5A5A5A5A5A5)
	cpu.fpuCW &^= fpuExcPrecision
	cpu.fpuSetST0(1 + math.Ldexp(1, -30))
	if err := cpu.step(); err == nil {
		t.Fatal("unmasked m32 store did not fault")
	}
	if got, err := mem.Read32(0x9000); err != nil || got != 0xA5A5A5A5 {
		t.Fatalf("unmasked m32 store changed memory=%#x err=%v", got, err)
	}

	cpu, mem = newX87ReferenceCPU(t, []byte{0xDB, 0x55, 0x00}, 0x5A5A5A5A)
	cpu.fpuCW &^= fpuExcInvalid
	cpu.fpuSetST0(math.Inf(1))
	if err := cpu.step(); err == nil {
		t.Fatal("unmasked FIST did not fault")
	}
	if got, err := mem.Read32(0x9000); err != nil || got != 0x5A5A5A5A {
		t.Fatalf("unmasked FIST changed memory=%#x err=%v", got, err)
	}

	cpu, mem = newX87ReferenceCPU(t, []byte{0xDB, 0x55, 0x00}, 0xC3C3C3C3)
	cpu.fpuCW &^= fpuExcInvalid
	cpu.fpuSW |= fpuExcInvalid
	cpu.fpuSetST0(math.Inf(1))
	if err := cpu.step(); err == nil {
		t.Fatal("sticky unmasked FIST did not fault")
	}
	if got, err := mem.Read32(0x9000); err != nil || got != 0xC3C3C3C3 {
		t.Fatalf("sticky unmasked FIST changed memory=%#x err=%v", got, err)
	}
}

func TestX87ReferenceRandomizedExecutedAdd(t *testing.T) {
	rng := rand.New(rand.NewSource(0xD8))
	for i := 0; i < 50; i++ {
		a := rng.Float64()*1000 - 500
		b := rng.Float64()*1000 - 500
		cpu, _ := newX87ReferenceCPU(t, []byte{0xD8, 0xC1}, 0)
		cpu.fpuSetST0(a)
		cpu.fpuSetSTi(1, b)
		if err := cpu.step(); err != nil {
			t.Fatal(err)
		}
		if cpu.fpuST0() != a+b {
			t.Fatalf("case %d got=%v want=%v", i, cpu.fpuST0(), a+b)
		}
	}
}

func TestX87ReferenceStickyUnmaskedExceptionAndPartialRemainder(t *testing.T) {
	cpu, _ := newX87ReferenceCPU(t, []byte{0xD8, 0xF1}, 0)
	cpu.fpuCW &^= fpuExcZero
	cpu.fpuSW = fpuExcZero
	cpu.fpuSetSTi(1, 0)
	if err := cpu.step(); err == nil {
		t.Fatal("sticky unmasked divide did not fault")
	}

	cpu, _ = newX87ReferenceCPU(t, []byte{0xD9, 0xF8}, 0)
	cpu.fpuSetST0(math.Ldexp(1, 70))
	cpu.fpuSetSTi(1, 3)
	if err := cpu.step(); err != nil {
		t.Fatal(err)
	}
	if cpu.fpuSW&0x0400 == 0 {
		t.Fatalf("partial FPREM C2 status=%#x", cpu.fpuSW)
	}
	cpu.fpuSW = 0
	cpu.fpuSetPremCC(-3)
	if cpu.fpuSW&0x4700 != 0x0300 {
		t.Fatalf("negative quotient CC=%#x", cpu.fpuSW&0x4700)
	}
}

func TestX87ReferenceTranscendentalNaNStatus(t *testing.T) {
	quiet := math.Float64frombits(0x7FF8000000000001)
	signaling := math.Float64frombits(0x7FF0000000000001)
	for _, value := range []float64{quiet, signaling} {
		cpu, _ := newX87ReferenceCPU(t, []byte{0xD9, 0xFE}, 0)
		cpu.fpuSetST0(value)
		if err := cpu.step(); err != nil && value == quiet {
			t.Fatal(err)
		}
		if value == quiet && cpu.fpuSW&(fpuExcInvalid|0x0400) != 0 {
			t.Fatalf("quiet NaN status=%#x", cpu.fpuSW)
		}
		if value == signaling && cpu.fpuSW&fpuExcInvalid == 0 {
			t.Fatalf("signaling NaN status=%#x", cpu.fpuSW)
		}
	}
}

func TestX87ReferencePublicRunRetirement(t *testing.T) {
	cpu, _ := newX87ReferenceCPU(t, []byte{0xD8, 0xC1, 0xF4}, 0)
	if err := cpu.Run(); err != nil {
		t.Fatal(err)
	}
	if cpu.GetInstret() != 2 || cpu.RIP != 0x8003 {
		t.Fatalf("Run RIP=%#x Instret=%d", cpu.RIP, cpu.GetInstret())
	}
	assertX87Value(t, cpu.fpuST0(), 8)
}

func TestX87ReferenceRegisterOpcodeMatrix(t *testing.T) {
	cases := []struct {
		name    string
		code    []byte
		wantTop int
		check   func(*testing.T, *CPU)
	}{
		{"D8 FADD", []byte{0xD8, 0xC1}, 6, func(t *testing.T, c *CPU) { assertX87Value(t, c.fpuST0(), 8) }},
		{"D8 FMUL", []byte{0xD8, 0xC9}, 6, func(t *testing.T, c *CPU) { assertX87Value(t, c.fpuST0(), 12) }},
		{"D8 FCOM", []byte{0xD8, 0xD1}, 6, func(t *testing.T, c *CPU) { assertX87CC(t, c, 0, 0, 0) }},
		{"D8 FCOMP", []byte{0xD8, 0xD9}, 7, nil},
		{"D8 FSUB", []byte{0xD8, 0xE1}, 6, func(t *testing.T, c *CPU) { assertX87Value(t, c.fpuST0(), 4) }},
		{"D8 FSUBR", []byte{0xD8, 0xE9}, 6, func(t *testing.T, c *CPU) { assertX87Value(t, c.fpuST0(), -4) }},
		{"D8 FDIV", []byte{0xD8, 0xF1}, 6, func(t *testing.T, c *CPU) { assertX87Value(t, c.fpuST0(), 3) }},
		{"D8 FDIVR", []byte{0xD8, 0xF9}, 6, func(t *testing.T, c *CPU) { assertX87Value(t, c.fpuST0(), 1.0/3.0) }},
		{"D9 FLD", []byte{0xD9, 0xC1}, 5, nil},
		{"D9 FXCH", []byte{0xD9, 0xC9}, 6, func(t *testing.T, c *CPU) { assertX87Value(t, c.fpuST0(), 2) }},
		{"D9 FCHS", []byte{0xD9, 0xE0}, 6, func(t *testing.T, c *CPU) { assertX87Value(t, c.fpuST0(), -6) }},
		{"D9 FABS", []byte{0xD9, 0xE1}, 6, func(t *testing.T, c *CPU) { assertX87Value(t, c.fpuST0(), 6) }},
		{"D9 FTST", []byte{0xD9, 0xE4}, 6, func(t *testing.T, c *CPU) { assertX87CC(t, c, 0, 0, 0) }},
		{"D9 FXAM", []byte{0xD9, 0xE5}, 6, nil},
		{"D9 FLD1", []byte{0xD9, 0xE8}, 5, nil},
		{"D9 FLDL2T", []byte{0xD9, 0xE9}, 5, nil},
		{"D9 FLDL2E", []byte{0xD9, 0xEA}, 5, nil},
		{"D9 FLDPI", []byte{0xD9, 0xEB}, 5, nil},
		{"D9 FLDLN2", []byte{0xD9, 0xEC}, 5, nil},
		{"D9 FLDLG2", []byte{0xD9, 0xED}, 5, nil},
		{"D9 FLDZ", []byte{0xD9, 0xEE}, 5, func(t *testing.T, c *CPU) {
			if c.fpuTW>>uint(c.fpuTop*2)&3 != 1 {
				t.Fatal("FLDZ tag")
			}
		}},
		{"D9 F2XM1", []byte{0xD9, 0xF0}, 6, nil},
		{"D9 FYL2X", []byte{0xD9, 0xF1}, 7, nil},
		{"D9 FPTAN", []byte{0xD9, 0xF2}, 5, nil},
		{"D9 FPATAN", []byte{0xD9, 0xF3}, 7, nil},
		{"D9 FXTRACT", []byte{0xD9, 0xF4}, 5, nil},
		{"D9 FPREM1", []byte{0xD9, 0xF5}, 6, nil},
		{"D9 FDECSTP", []byte{0xD9, 0xF6}, 5, nil},
		{"D9 FINCSTP", []byte{0xD9, 0xF7}, 7, nil},
		{"D9 FPREM", []byte{0xD9, 0xF8}, 6, nil},
		{"D9 FYL2XP1", []byte{0xD9, 0xF9}, 7, nil},
		{"D9 FSQRT", []byte{0xD9, 0xFA}, 6, nil},
		{"D9 FSINCOS", []byte{0xD9, 0xFB}, 5, nil},
		{"D9 FRNDINT", []byte{0xD9, 0xFC}, 6, nil},
		{"D9 FSCALE", []byte{0xD9, 0xFD}, 6, nil},
		{"D9 FSIN", []byte{0xD9, 0xFE}, 6, nil},
		{"D9 FCOS", []byte{0xD9, 0xFF}, 6, nil},
		{"DA FCMOVB", []byte{0xDA, 0xC1}, 6, func(t *testing.T, c *CPU) { assertX87Value(t, c.fpuST0(), 2) }},
		{"DA FCMOVE", []byte{0xDA, 0xC9}, 6, func(t *testing.T, c *CPU) { assertX87Value(t, c.fpuST0(), 2) }},
		{"DA FCMOVBE", []byte{0xDA, 0xD1}, 6, func(t *testing.T, c *CPU) { assertX87Value(t, c.fpuST0(), 2) }},
		{"DA FCMOVU", []byte{0xDA, 0xD9}, 6, func(t *testing.T, c *CPU) { assertX87Value(t, c.fpuST0(), 2) }},
		{"DA FUCOMPP", []byte{0xDA, 0xE9}, 0, nil},
		{"DB FCMOVNB", []byte{0xDB, 0xC1}, 6, nil},
		{"DB FCMOVNE", []byte{0xDB, 0xC9}, 6, nil},
		{"DB FCMOVNBE", []byte{0xDB, 0xD1}, 6, nil},
		{"DB FCMOVNU", []byte{0xDB, 0xD9}, 6, nil},
		{"DB FNCLEX", []byte{0xDB, 0xE2}, 6, nil},
		{"DB FNINIT", []byte{0xDB, 0xE3}, 0, nil},
		{"DB FUCOMI", []byte{0xDB, 0xE9}, 6, nil},
		{"DB FCOMI", []byte{0xDB, 0xF1}, 6, nil},
		{"DC FADD", []byte{0xDC, 0xC1}, 6, func(t *testing.T, c *CPU) { assertX87Value(t, c.fpuSTi(1), 8) }},
		{"DC FMUL", []byte{0xDC, 0xC9}, 6, func(t *testing.T, c *CPU) { assertX87Value(t, c.fpuSTi(1), 12) }},
		{"DC FSUBR", []byte{0xDC, 0xE1}, 6, func(t *testing.T, c *CPU) { assertX87Value(t, c.fpuSTi(1), 4) }},
		{"DC FSUB", []byte{0xDC, 0xE9}, 6, func(t *testing.T, c *CPU) { assertX87Value(t, c.fpuSTi(1), -4) }},
		{"DC FDIVR", []byte{0xDC, 0xF1}, 6, func(t *testing.T, c *CPU) { assertX87Value(t, c.fpuSTi(1), 3) }},
		{"DC FDIV", []byte{0xDC, 0xF9}, 6, func(t *testing.T, c *CPU) { assertX87Value(t, c.fpuSTi(1), 1.0/3.0) }},
		{"DD FFREE", []byte{0xDD, 0xC1}, 6, nil},
		{"DD FST", []byte{0xDD, 0xD1}, 6, nil},
		{"DD FSTP", []byte{0xDD, 0xD9}, 7, nil},
		{"DD FUCOM", []byte{0xDD, 0xE1}, 6, nil},
		{"DD FUCOMP", []byte{0xDD, 0xE9}, 7, nil},
		{"DE FADDP", []byte{0xDE, 0xC1}, 7, nil},
		{"DE FMULP", []byte{0xDE, 0xC9}, 7, nil},
		{"DE FCOMPP", []byte{0xDE, 0xD9}, 0, nil},
		{"DE FSUBRP", []byte{0xDE, 0xE1}, 7, nil},
		{"DE FSUBP", []byte{0xDE, 0xE9}, 7, nil},
		{"DE FDIVRP", []byte{0xDE, 0xF1}, 7, nil},
		{"DE FDIVP", []byte{0xDE, 0xF9}, 7, nil},
		{"DF FNSTSW", []byte{0xDF, 0xE0}, 6, nil},
		{"DF FUCOMIP", []byte{0xDF, 0xE9}, 7, nil},
		{"DF FCOMIP", []byte{0xDF, 0xF1}, 7, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cpu, _ := newX87ReferenceCPU(t, tc.code, 0)
			cpu.Rflags = flagCF | flagPF | flagZF
			if err := cpu.step(); err != nil {
				t.Fatal(err)
			}
			if cpu.RIP != 0x8000+uint64(len(tc.code)) {
				t.Fatalf("RIP=%#x", cpu.RIP)
			}
			if cpu.fpuTop != tc.wantTop {
				t.Fatalf("TOP=%d want %d", cpu.fpuTop, tc.wantTop)
			}
			if tc.check != nil {
				tc.check(t, cpu)
			}
		})
	}
}

func TestX87ReferenceAllDecodedRegisterForms(t *testing.T) {
	count := 0
	for op := byte(0xD8); op <= 0xDF; op++ {
		for reg := 0; reg < 8; reg++ {
			for rm := 0; rm < 8; rm++ {
				if !x87RegFormImplemented(op, reg, rm) {
					continue
				}
				count++
				cpu, _ := newX87ReferenceCPU(t, []byte{op, byte(0xC0 | reg<<3 | rm)}, 0)
				if err := cpu.step(); err != nil {
					t.Fatalf("form %02X /%d rm=%d: %v", op, reg, rm, err)
				}
				if cpu.RIP != 0x8002 {
					t.Fatalf("form %02X /%d rm=%d RIP=%#x", op, reg, rm, cpu.RIP)
				}
			}
		}
	}
	if count == 0 {
		t.Fatal("register form matrix was empty")
	}
}

func TestX87ReferenceMemoryOpcodeMatrix(t *testing.T) {
	forms := map[byte][]int{
		0xD8: {0, 1, 2, 3, 4, 5, 6, 7},
		0xD9: {0, 2, 3, 4, 5, 6, 7},
		0xDA: {0, 1, 2, 3, 4, 5, 6, 7},
		0xDB: {0, 1, 2, 3, 5, 7},
		0xDC: {0, 1, 2, 3, 4, 5, 6, 7},
		0xDD: {0, 1, 2, 3, 4, 6, 7},
		0xDE: {0, 1, 2, 3, 4, 5, 6, 7},
		0xDF: {0, 1, 2, 3, 5, 7},
	}
	for op, regs := range forms {
		for _, reg := range regs {
			name := fmt.Sprintf("%02X/%d", op, reg)
			t.Run(name, func(t *testing.T) {
				code := []byte{op, byte(0x45 | reg<<3), 0}
				cpu, mem := newX87ReferenceCPU(t, code, 0)
				if op == 0xDB && reg == 5 {
					writeX87Reference80(t, mem, 0x9000, 1)
				}
				flagsBefore := cpu.Rflags
				if err := cpu.step(); err != nil {
					t.Fatal(err)
				}
				if cpu.RIP != 0x8003 {
					t.Fatalf("RIP=%#x", cpu.RIP)
				}
				if cpu.Rflags != flagsBefore {
					t.Fatalf("memory form changed EFLAGS=%#x", cpu.Rflags)
				}
				wantTop := 6
				popped := (op == 0xD8 || op == 0xDA || op == 0xDC || op == 0xDE) && reg == 3
				popped = popped || op == 0xD9 && reg == 3
				popped = popped || (op == 0xDB || op == 0xDF) && (reg == 1 || reg == 3 || reg == 7)
				popped = popped || op == 0xDD && (reg == 1 || reg == 3)
				if op == 0xD9 && reg == 0 || (op == 0xDB || op == 0xDF) && (reg == 0 || reg == 5) || op == 0xDD && reg == 0 {
					wantTop = 5
				}
				if op == 0xD9 && reg == 4 || op == 0xDD && (reg == 4 || reg == 6) {
					wantTop = 0
				}
				if popped {
					wantTop = 7
				}
				if cpu.fpuTop != wantTop {
					t.Fatalf("TOP=%d want %d", cpu.fpuTop, wantTop)
				}
				if popped && (cpu.fpuTW>>(6*2))&3 != 3 {
					t.Fatalf("popped physical tag=%#x", (cpu.fpuTW>>(6*2))&3)
				}
				if (op == 0xD9 && reg == 0) || (op == 0xDB && (reg == 0 || reg == 5)) || op == 0xDD && reg == 0 || op == 0xDF && (reg == 0 || reg == 5) {
					if cpu.fpuEmpty(0) || cpu.fpuST0() != 0 && !(op == 0xDB && reg == 5) {
						t.Fatalf("load result=%v tag=%#x", cpu.fpuST0(), cpu.fpuTW)
					}
				}
				if (op == 0xD8 || op == 0xDA || op == 0xDC || op == 0xDE) && (reg == 2 || reg == 3) {
					assertX87CC(t, cpu, 0, 0, 0)
				}
			})
		}
	}
}

func TestX87ReferenceRejectsAllUndecodedForms(t *testing.T) {
	for op := byte(0xD8); op <= 0xDF; op++ {
		for reg := 0; reg < 8; reg++ {
			for rm := 0; rm < 8; rm++ {
				if x87RegFormImplemented(op, reg, rm) {
					continue
				}
				cpu, _ := newX87ReferenceCPU(t, []byte{op, byte(0xC0 | reg<<3 | rm)}, 0)
				if err := cpu.step(); err == nil {
					t.Fatalf("register form %02X /%d rm=%d was accepted", op, reg, rm)
				}
			}
		}
		for reg := 0; reg < 8; reg++ {
			cpu, _ := newX87ReferenceCPU(t, []byte{op, byte(0x45 | reg<<3), 0}, 0)
			if cpu.x87MemSize(op, reg, &prefixState{}) != 0 {
				continue
			}
			if err := cpu.step(); err == nil {
				t.Fatalf("memory form %02X /%d was accepted", op, reg)
			}
		}
	}
}

func assertX87Value(t *testing.T, got, want float64) {
	t.Helper()
	if got != want {
		t.Fatalf("value=%v want %v", got, want)
	}
}

func assertX87CC(t *testing.T, c *CPU, c0, c2, c3 uint16) {
	t.Helper()
	got := uint16(0)
	if c.fpuSW&0x0100 != 0 {
		got |= 1
	}
	if c.fpuSW&0x0400 != 0 {
		got |= 2
	}
	if c.fpuSW&0x4000 != 0 {
		got |= 4
	}
	want := c0 | c2<<1 | c3<<2
	if got != want {
		t.Fatalf("CC=%d want %d", got, want)
	}
}

func newX87ReferenceCPU(t *testing.T, code []byte, data uint64) (*CPU, *mmu.MMU) {
	t.Helper()
	mem := mmu.New()
	if err := mem.MapPage(0x8000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute); err != nil {
		t.Fatal(err)
	}
	if err := mem.MapPage(0x9000, mmu.PermRead|mmu.PermWrite); err != nil {
		t.Fatal(err)
	}
	for i, b := range code {
		if err := mem.Write8(0x8000+uint64(i), b); err != nil {
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
	cpu.fpuInit()
	cpu.fpuPush(2)
	cpu.fpuPush(6)
	return cpu, mem
}

func writeX87Reference80(t *testing.T, mem *mmu.MMU, addr uint64, value float64) {
	t.Helper()
	lo, hi := float64ToFloat80(value)
	if err := mem.Write64(addr, lo); err != nil {
		t.Fatal(err)
	}
	if err := mem.Write16(addr+8, hi); err != nil {
		t.Fatal(err)
	}
}

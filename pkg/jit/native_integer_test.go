package jit

import (
	"fmt"
	"testing"

	"github.com/mirkobrombin/Raven/pkg/mmu"
)

type nativeIntegerResult struct {
	regs     [16]uint64
	flags    uint64
	rip      uint64
	instret  uint64
	fallback bool
}

func runNativeIntegerFixture(
	t testing.TB,
	code []byte,
	initialRegs [16]uint64,
	initialFlags uint64,
	native bool,
) nativeIntegerResult {
	t.Helper()

	mem := mmu.New()
	mem.MapPage(0x1000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	for i, opcode := range code {
		if err := mem.Write8(0x1000+uint64(i), opcode); err != nil {
			t.Fatal(err)
		}
	}

	cache := NewCache(mem)
	if native && !cache.EnableNativeCodegen() {
		t.Skip("native codegen unavailable")
	}
	block := cache.Compile(0x1000)
	if block == nil {
		t.Fatal("integer fixture did not compile")
	}
	if native && block.native == 0 {
		t.Fatal("native backend rejected integer fixture")
	}

	regs := initialRegs
	flags := initialFlags
	rip := uint64(0x1000)
	instret := uint64(0)
	state := &State{
		Regs:    &regs,
		RIP:     &rip,
		Rflags:  &flags,
		Mem:     mem,
		Instret: &instret,
	}
	if err := block.Run(state); err != nil {
		t.Fatal(err)
	}
	return nativeIntegerResult{
		regs:     regs,
		flags:    flags,
		rip:      rip,
		instret:  instret,
		fallback: state.Fallback,
	}
}

func compareNativeIntegerFixture(
	t *testing.T,
	code []byte,
	regs [16]uint64,
	flags uint64,
) nativeIntegerResult {
	t.Helper()

	closure := runNativeIntegerFixture(t, code, regs, flags, false)
	native := runNativeIntegerFixture(t, code, regs, flags, true)
	if native != closure {
		t.Fatalf("native result = %+v, closure result = %+v", native, closure)
	}
	return native
}

func TestNativeIntegerTestMatchesClosure(t *testing.T) {
	tests := []struct {
		name  string
		code  []byte
		regs  [16]uint64
		flags uint64
	}{
		{
			name: "register 16 zero",
			code: []byte{0x66, 0x85, 0xC8, 0xEB, 0xFE},
			regs: [16]uint64{
				0: 0xFFFF00000000FF00,
				1: 0x12340000000000FF,
			},
			flags: 0xA12,
		},
		{
			name: "register 32 sign and parity",
			code: []byte{0x85, 0xC8, 0xEB, 0xFE},
			regs: [16]uint64{
				0: 0xAAAAAAAA80000003,
				1: 0x55555555FFFFFFFF,
			},
			flags: 0x212,
		},
		{
			name: "register 64",
			code: []byte{0x48, 0x85, 0xC8, 0xEB, 0xFE},
			regs: [16]uint64{
				0: 0x8000000000000001,
				1: 0xFFFFFFFFFFFFFFFF,
			},
			flags: 0xA53,
		},
		{
			name:  "immediate 32",
			code:  []byte{0xA9, 0x0F, 0x00, 0x00, 0x80, 0xEB, 0xFE},
			regs:  [16]uint64{0: 0xDEADBEEF8000000F},
			flags: 0xA12,
		},
		{
			name:  "immediate 64 sign extended",
			code:  []byte{0x48, 0xA9, 0x00, 0x00, 0x00, 0x80, 0xEB, 0xFE},
			regs:  [16]uint64{0: 0x8000000000000000},
			flags: 0x253,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := compareNativeIntegerFixture(t, test.code, test.regs, test.flags)
			if result.regs != test.regs {
				t.Fatalf("TEST changed registers: got=%#v want=%#v", result.regs, test.regs)
			}
			if result.flags&flagAF != test.flags&flagAF {
				t.Fatalf("AF changed: got=%#x want=%#x", result.flags, test.flags)
			}
			if result.instret != 2 {
				t.Fatalf("instret=%d, want 2", result.instret)
			}
		})
	}
}

func TestNativeIntegerMovzxMatchesClosure(t *testing.T) {
	tests := []struct {
		name string
		code []byte
		want uint64
	}{
		{name: "byte to dword", code: []byte{0x0F, 0xB6, 0xC1, 0xEB, 0xFE}, want: 0x80},
		{name: "word to dword", code: []byte{0x0F, 0xB7, 0xC1, 0xEB, 0xFE}, want: 0xFF80},
		{name: "byte to qword", code: []byte{0x48, 0x0F, 0xB6, 0xC1, 0xEB, 0xFE}, want: 0x80},
		{name: "word to qword", code: []byte{0x48, 0x0F, 0xB7, 0xC1, 0xEB, 0xFE}, want: 0xFF80},
		{name: "byte to word", code: []byte{0x66, 0x0F, 0xB6, 0xC1, 0xEB, 0xFE}, want: 0xAAAAAAAAAAAA0080},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			regs := [16]uint64{
				0: 0xAAAAAAAAAAAAAAAA,
				1: 0x123456789ABCFF80,
			}
			result := compareNativeIntegerFixture(t, test.code, regs, 0xA53)
			if result.regs[0] != test.want {
				t.Fatalf("RAX=%#x, want %#x", result.regs[0], test.want)
			}
			if result.flags != 0xA53 {
				t.Fatalf("flags=%#x, want 0xA53", result.flags)
			}
		})
	}
}

func TestNativeIntegerMovsxMatchesClosure(t *testing.T) {
	tests := []struct {
		name string
		code []byte
		want uint64
	}{
		{name: "byte to word", code: []byte{0x66, 0x0F, 0xBE, 0xC1, 0xEB, 0xFE}, want: 0xAAAAAAAAAAAAFF80},
		{name: "byte to dword", code: []byte{0x0F, 0xBE, 0xC1, 0xEB, 0xFE}, want: 0xFFFFFF80},
		{name: "byte to qword", code: []byte{0x48, 0x0F, 0xBE, 0xC1, 0xEB, 0xFE}, want: 0xFFFFFFFFFFFFFF80},
		{name: "word to dword", code: []byte{0x0F, 0xBF, 0xC1, 0xEB, 0xFE}, want: 0xFFFFFF80},
		{name: "word to qword", code: []byte{0x48, 0x0F, 0xBF, 0xC1, 0xEB, 0xFE}, want: 0xFFFFFFFFFFFFFF80},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			regs := [16]uint64{
				0: 0xAAAAAAAAAAAAAAAA,
				1: 0x123456789ABCFF80,
			}
			result := compareNativeIntegerFixture(t, test.code, regs, 0xA53)
			if result.regs[0] != test.want || result.flags != 0xA53 {
				t.Fatalf("RAX=%#x flags=%#x", result.regs[0], result.flags)
			}
		})
	}
}

func TestNativeIntegerConditionsMatchClosure(t *testing.T) {
	flagCases := []uint64{
		0x202,
		0x202 | flagCF,
		0x202 | flagPF,
		0x202 | flagZF,
		0x202 | flagSF,
		0x202 | flagOF,
		0x202 | flagCF | flagZF | flagSF | flagOF,
	}
	for cc := ccO; cc <= ccG; cc++ {
		for _, flags := range flagCases {
			name := fmt.Sprintf("cc%d/flags_%x", cc, flags)
			t.Run(name, func(t *testing.T) {
				regs := [16]uint64{
					0: 0xAAAAAAAA12345678,
					1: 0xBBBBBBBB87654321,
					2: 0xCCCCCCCCDEADBEEF,
				}

				setCode := []byte{0x0F, 0x90 | byte(cc), 0xC2, 0xEB, 0xFE}
				setResult := compareNativeIntegerFixture(t, setCode, regs, flags)
				if setResult.flags != flags {
					t.Fatalf("SETcc flags=%#x, want %#x", setResult.flags, flags)
				}
				if setResult.regs[2]&^uint64(0xFF) != regs[2]&^uint64(0xFF) {
					t.Fatalf("SETcc changed upper destination bytes: %#x", setResult.regs[2])
				}

				for _, cmov := range []struct {
					name string
					code []byte
				}{
					{name: "word", code: []byte{0x66, 0x0F, 0x40 | byte(cc), 0xC1, 0xEB, 0xFE}},
					{name: "dword", code: []byte{0x0F, 0x40 | byte(cc), 0xC1, 0xEB, 0xFE}},
					{name: "qword", code: []byte{0x48, 0x0F, 0x40 | byte(cc), 0xC1, 0xEB, 0xFE}},
				} {
					t.Run(cmov.name, func(t *testing.T) {
						result := compareNativeIntegerFixture(t, cmov.code, regs, flags)
						if result.flags != flags {
							t.Fatalf("CMOVcc flags=%#x, want %#x", result.flags, flags)
						}
					})
				}
			})
		}
	}

	regs := [16]uint64{
		0: 0xAAAAAAAA12345678,
		1: 0xBBBBBBBB87654321,
	}
	t.Run("CMOV dword true zero extends", func(t *testing.T) {
		result := compareNativeIntegerFixture(
			t, []byte{0x0F, 0x44, 0xC1, 0xEB, 0xFE}, regs, 0x202|flagZF)
		if result.regs[0] != 0x87654321 {
			t.Fatalf("RAX=%#x", result.regs[0])
		}
	})
	t.Run("CMOV dword false zero extends destination", func(t *testing.T) {
		result := compareNativeIntegerFixture(
			t, []byte{0x0F, 0x44, 0xC1, 0xEB, 0xFE}, regs, 0x202)
		if result.regs[0] != uint64(uint32(regs[0])) {
			t.Fatalf("RAX=%#x, want %#x", result.regs[0], uint64(uint32(regs[0])))
		}
	})
}

func TestNativeIntegerXchgCdqAndIMulMatchClosure(t *testing.T) {
	for _, test := range []struct {
		name  string
		code  []byte
		want0 uint64
		want1 uint64
	}{
		{name: "byte", code: []byte{0x86, 0xC8, 0xEB, 0xFE}, want0: 0x0123456789ABCD10, want1: 0xFEDCBA98765432EF},
		{name: "word", code: []byte{0x66, 0x87, 0xC8, 0xEB, 0xFE}, want0: 0x0123456789AB3210, want1: 0xFEDCBA987654CDEF},
		{name: "dword", code: []byte{0x87, 0xC8, 0xEB, 0xFE}, want0: 0x76543210, want1: 0x89ABCDEF},
		{name: "qword", code: []byte{0x48, 0x91, 0xEB, 0xFE}, want0: 0xFEDCBA9876543210, want1: 0x0123456789ABCDEF},
	} {
		t.Run("XCHG "+test.name, func(t *testing.T) {
			regs := [16]uint64{
				0: 0x0123456789ABCDEF,
				1: 0xFEDCBA9876543210,
			}
			result := compareNativeIntegerFixture(t, test.code, regs, 0xA53)
			if result.regs[0] != test.want0 || result.regs[1] != test.want1 || result.flags != 0xA53 {
				t.Fatalf("XCHG result=%+v", result)
			}
		})
	}

	for _, test := range []struct {
		name  string
		code  []byte
		want0 uint64
		want8 uint64
	}{
		{
			name:  "dword REX.B opcode 90",
			code:  []byte{0x41, 0x90, 0xEB, 0xFE},
			want0: 0x76543210,
			want8: 0x89ABCDEF,
		},
		{
			name:  "qword REX.B opcode 90",
			code:  []byte{0x49, 0x90, 0xEB, 0xFE},
			want0: 0xFEDCBA9876543210,
			want8: 0x0123456789ABCDEF,
		},
	} {
		t.Run("XCHG "+test.name, func(t *testing.T) {
			regs := [16]uint64{
				0: 0x0123456789ABCDEF,
				8: 0xFEDCBA9876543210,
			}
			result := compareNativeIntegerFixture(t, test.code, regs, 0xA53)
			if result.regs[0] != test.want0 || result.regs[8] != test.want8 || result.flags != 0xA53 {
				t.Fatalf("XCHG result=%+v", result)
			}
		})
	}

	for _, test := range []struct {
		name string
		code []byte
		rax  uint64
		want uint64
	}{
		{name: "CDQ positive", code: []byte{0x99, 0xEB, 0xFE}, rax: 0xAAAAAAAA7FFFFFFF, want: 0},
		{name: "CDQ negative", code: []byte{0x99, 0xEB, 0xFE}, rax: 0xAAAAAAAA80000000, want: 0xFFFFFFFF},
		{name: "CQO positive", code: []byte{0x48, 0x99, 0xEB, 0xFE}, rax: 0x7FFFFFFFFFFFFFFF, want: 0},
		{name: "CQO negative", code: []byte{0x48, 0x99, 0xEB, 0xFE}, rax: 0x8000000000000000, want: ^uint64(0)},
	} {
		t.Run(test.name, func(t *testing.T) {
			regs := [16]uint64{0: test.rax, 2: 0x123456789ABCDEF0}
			result := compareNativeIntegerFixture(t, test.code, regs, 0xA53)
			if result.regs[2] != test.want || result.flags != 0xA53 {
				t.Fatalf("RDX=%#x flags=%#x", result.regs[2], result.flags)
			}
		})
	}

	for _, test := range []struct {
		name string
		code []byte
		rax  uint64
		rcx  uint64
		want uint64
	}{
		{
			name: "word preserves upper",
			code: []byte{0x66, 0x0F, 0xAF, 0xC1, 0xEB, 0xFE},
			rax:  0xAAAAAAAAAAAA8000,
			rcx:  0xBBBBBBBBBBBB0002,
			want: 0xAAAAAAAAAAAA0000,
		},
		{
			name: "dword zero extends",
			code: []byte{0x0F, 0xAF, 0xC1, 0xEB, 0xFE},
			rax:  0xAAAAAAAA80000000,
			rcx:  0xBBBBBBBB00000002,
			want: 0,
		},
		{
			name: "qword wraps",
			code: []byte{0x48, 0x0F, 0xAF, 0xC1, 0xEB, 0xFE},
			rax:  0x8000000000000001,
			rcx:  3,
			want: 0x8000000000000003,
		},
	} {
		t.Run("IMUL "+test.name, func(t *testing.T) {
			regs := [16]uint64{0: test.rax, 1: test.rcx}
			flags := uint64(0xA53 | flagCF | flagOF)
			result := compareNativeIntegerFixture(t, test.code, regs, flags)
			if result.regs[0] != test.want {
				t.Fatalf("RAX=%#x, want %#x", result.regs[0], test.want)
			}
			if result.flags != flags {
				t.Fatalf("flags=%#x, want %#x", result.flags, flags)
			}
		})
	}

	t.Run("IMUL clears overflow flags", func(t *testing.T) {
		regs := [16]uint64{0: 7, 1: 5}
		flags := uint64(0xA53 | flagCF | flagOF)
		result := compareNativeIntegerFixture(t,
			[]byte{0x48, 0x0F, 0xAF, 0xC1, 0xEB, 0xFE}, regs, flags)
		if result.regs[0] != 35 {
			t.Fatalf("RAX=%#x, want %#x", result.regs[0], uint64(35))
		}
		if result.flags != flags&^(flagCF|flagOF) {
			t.Fatalf("flags=%#x, want %#x", result.flags, flags&^(flagCF|flagOF))
		}
	})
}

func nativeIntegerShiftCode(size int, op shiftOp, count byte, useCL bool) []byte {
	var code []byte
	if size == 2 {
		code = append(code, 0x66)
	}
	if size == 8 {
		code = append(code, 0x48)
	}
	if useCL {
		if size == 1 {
			code = append(code, 0xD2)
		} else {
			code = append(code, 0xD3)
		}
		code = append(code, 0xC0|byte(op)<<3)
	} else {
		if size == 1 {
			code = append(code, 0xC0)
		} else {
			code = append(code, 0xC1)
		}
		code = append(code, 0xC0|byte(op)<<3, count)
	}
	return append(code, 0xEB, 0xFE)
}

func TestNativeIntegerShiftsMatchClosure(t *testing.T) {
	operations := []struct {
		name string
		op   shiftOp
	}{
		{name: "ROL", op: shROL},
		{name: "ROR", op: shROR},
		{name: "SHL", op: shSHL},
		{name: "SHR", op: shSHR},
		{name: "SAR", op: shSAR},
	}
	values := map[int]uint64{
		1: 0xAAAAAAAAAAAA0081,
		2: 0xAAAAAAAAAAAA8001,
		4: 0xAAAAAAAA80000001,
		8: 0x8000000000000001,
	}
	for _, size := range []int{1, 2, 4, 8} {
		width := byte(size * 8)
		counts := []byte{0, 1, width - 1, width, width + 1, 0xFF}
		for _, operation := range operations {
			for _, count := range counts {
				for _, useCL := range []bool{false, true} {
					mode := "imm"
					if useCL {
						mode = "CL"
					}
					name := fmt.Sprintf("%s/%d/%s/%d", operation.name, width, mode, count)
					t.Run(name, func(t *testing.T) {
						regs := [16]uint64{0: values[size], 1: uint64(count)}
						code := nativeIntegerShiftCode(size, operation.op, count, useCL)
						closure := runNativeIntegerFixture(t, code, regs, 0xA53, false)
						native := runNativeIntegerFixture(t, code, regs, 0xA53, true)
						if native.regs != closure.regs || native.rip != closure.rip ||
							native.instret != closure.instret || native.fallback != closure.fallback {
							t.Fatalf("native result = %+v, closure result = %+v", native, closure)
						}
						masked := uint64(count) & 0x1F
						if size == 8 {
							masked = uint64(count) & 0x3F
						}
						effective := masked
						undefined := uint64(0)
						if operation.op == shROL || operation.op == shROR {
							effective %= uint64(width)
							if effective != 0 && masked != 1 {
								undefined |= flagOF
							}
						} else if effective != 0 {
							undefined |= flagAF
							if masked != 1 {
								undefined |= flagOF
							}
							if masked > uint64(width) {
								undefined |= flagCF
							}
						}
						if native.flags&^undefined != closure.flags&^undefined {
							t.Fatalf("native flags=%#x closure flags=%#x undefined=%#x",
								native.flags, closure.flags, undefined)
						}
						if native.instret != 2 || native.fallback {
							t.Fatalf("instret=%d fallback=%v", native.instret, native.fallback)
						}
					})
				}
			}
		}
	}
}

func TestNativeIntegerHighByteRestrictions(t *testing.T) {
	for _, code := range [][]byte{
		{0x84, 0xC4},
		{0x86, 0xC4},
		{0x0F, 0xB6, 0xC4},
		{0x0F, 0x94, 0xC4},
		{0xD0, 0xE4},
		{0xF6, 0xD4},
		{0xF6, 0xDC},
		{0xF6, 0xF4},
		{0xFE, 0xC4},
	} {
		mem := mmu.New()
		mem.MapPage(0x1000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
		for i, opcode := range code {
			if err := mem.Write8(0x1000+uint64(i), opcode); err != nil {
				t.Fatal(err)
			}
		}
		cache := NewCache(mem)
		if !cache.EnableNativeCodegen() {
			t.Skip("native codegen unavailable")
		}
		if block := cache.Compile(0x1000); block != nil {
			t.Fatal("legacy high-byte form unexpectedly compiled")
		}
	}

	regs := [16]uint64{4: 0x123456789ABCDE80}
	result := compareNativeIntegerFixture(
		t,
		[]byte{0x40, 0x0F, 0xB6, 0xC4, 0xEB, 0xFE},
		regs,
		0x202,
	)
	if result.regs[0] != 0x80 {
		t.Fatalf("REX MOVZX RAX=%#x", result.regs[0])
	}
}

func TestNativeIntegerRejectsUnsafeForms(t *testing.T) {
	cache := NewCache(mmu.New())
	exec, err := newExecBuf()
	if err != nil {
		t.Skipf("exec memory unavailable: %v", err)
	}
	cache.exec = exec

	tests := []struct {
		name string
		insn insn
	}{
		{name: "MOVZX memory", insn: insn{kind: opMovzx, size: 4, srcSize: 1, dst: 0, src: -1}},
		{name: "MOVSX equal widths", insn: insn{kind: opMovsx, size: 2, srcSize: 2, dst: 0, src: 1}},
		{name: "SETcc memory", insn: insn{kind: opSetcc, size: 1, dst: -1, cc: ccZ}},
		{name: "CMOVcc memory", insn: insn{kind: opCmovcc, size: 4, dst: 0, src: -1, cc: ccZ}},
		{name: "XCHG invalid width", insn: insn{kind: opXchg, size: 3, dst: 0, src: 1}},
		{name: "register out of range", insn: insn{kind: opMovzx, size: 4, srcSize: 1, dst: 0, src: 16}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if entry, _, _, _ := cache.compileNative([]insn{test.insn}); entry != 0 {
				t.Fatal("unsafe form was accepted")
			}
		})
	}
}

func TestNativeIntegerUnsupportedPrefixFallback(t *testing.T) {
	mem := mmu.New()
	cache := NewCache(mem)
	exec, err := newExecBuf()
	if err != nil {
		t.Skipf("exec memory unavailable: %v", err)
	}
	cache.exec = exec
	insns := []insn{
		{kind: opNop, rip: 0x1000, nextRIP: 0x1001},
		{kind: opX87, size: 1, rip: 0x1001, nextRIP: 0x1003},
	}
	entry, retired, _, _ := cache.compileNative(insns)
	if entry == 0 || retired != 1 {
		t.Fatalf("entry=%#x retired=%d", entry, retired)
	}
	regs := [16]uint64{}
	rip := uint64(0x1000)
	flags := uint64(0x202)
	instret := uint64(0)
	state := &State{Regs: &regs, RIP: &rip, Rflags: &flags, Mem: mem, Instret: &instret}
	block := &Block{native: entry, ninsn: retired}
	if err := block.Run(state); err != nil {
		t.Fatal(err)
	}
	if !state.Fallback || instret != 1 || rip != 0x1001 {
		t.Fatalf("fallback=%v instret=%d RIP=%#x", state.Fallback, instret, rip)
	}
}

func TestNativeIntegerOpKindAcceptance(t *testing.T) {
	fixtures := []struct {
		kind opKind
		code []byte
	}{
		{kind: opTest, code: []byte{0x85, 0xC8, 0xEB, 0xFE}},
		{kind: opTestImm, code: []byte{0xA9, 0x01, 0x00, 0x00, 0x00, 0xEB, 0xFE}},
		{kind: opXchg, code: []byte{0x48, 0x91, 0xEB, 0xFE}},
		{kind: opCdq, code: []byte{0x99, 0xEB, 0xFE}},
		{kind: opMovzx, code: []byte{0x0F, 0xB6, 0xC1, 0xEB, 0xFE}},
		{kind: opMovsx, code: []byte{0x0F, 0xBE, 0xC1, 0xEB, 0xFE}},
		{kind: opSetcc, code: []byte{0x0F, 0x94, 0xC2, 0xEB, 0xFE}},
		{kind: opCmovcc, code: []byte{0x48, 0x0F, 0x44, 0xC1, 0xEB, 0xFE}},
		{kind: opIMul, code: []byte{0x48, 0x0F, 0xAF, 0xC1, 0xEB, 0xFE}},
		{kind: opIMul3, code: []byte{0x48, 0x6B, 0xC1, 0x03, 0xEB, 0xFE}},
		{kind: opShift, code: []byte{0x48, 0xD1, 0xE0, 0xEB, 0xFE}},
		{kind: opNot, code: []byte{0x48, 0xF7, 0xD0, 0xEB, 0xFE}},
		{kind: opNeg, code: []byte{0x48, 0xF7, 0xD8, 0xEB, 0xFE}},
		{kind: opInc, code: []byte{0x48, 0xFF, 0xC0, 0xEB, 0xFE}},
		{kind: opDec, code: []byte{0x48, 0xFF, 0xC8, 0xEB, 0xFE}},
		{kind: opDiv, code: []byte{0x48, 0xF7, 0xF1, 0xEB, 0xFE}},
		{kind: opIDiv, code: []byte{0x48, 0xF7, 0xF9, 0xEB, 0xFE}},
	}

	acceptedKinds := make(map[opKind]struct{})
	for _, fixture := range fixtures {
		mem := mmu.New()
		mem.MapPage(0x1000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
		for i, opcode := range fixture.code {
			if err := mem.Write8(0x1000+uint64(i), opcode); err != nil {
				t.Fatal(err)
			}
		}
		cache := NewCache(mem)
		if !cache.EnableNativeCodegen() {
			t.Skip("native codegen unavailable")
		}
		block := cache.Compile(0x1000)
		if block == nil {
			t.Fatalf("op kind %d did not decode", fixture.kind)
		}
		if block.native != 0 {
			acceptedKinds[fixture.kind] = struct{}{}
		}
	}
	if len(acceptedKinds) != 17 {
		t.Fatalf("accepted op kinds=%d/17", len(acceptedKinds))
	}
	t.Log("native decoded integer op-kind acceptance: 17/17")
}

func BenchmarkNativeIntegerMixed(b *testing.B) {
	code := make([]byte, 0, 16*24+2)
	for range 16 {
		code = append(code,
			0x85, 0xC8,
			0x0F, 0x95, 0xC2,
			0x0F, 0x45, 0xC1,
			0x0F, 0xB6, 0xD2,
			0x0F, 0xAF, 0xC1,
			0xD1, 0xE0,
			0x48, 0x91,
			0x48, 0x99,
			0x0F, 0xBE, 0xD2,
			0xF7, 0xD2,
			0xF7, 0xDA,
			0xFF, 0xC2,
			0xFF, 0xCA,
			0x6B, 0xD2, 0x03,
			0x66, 0x87, 0xD1,
		)
	}
	code = append(code, 0xEB, 0xFE)
	initialRegs := [16]uint64{0: 0x80000001, 1: 0xFFFFFFFF}
	for _, native := range []bool{false, true} {
		name := "Closure"
		if native {
			name = "Native"
		}
		b.Run(name, func(b *testing.B) {
			mem := mmu.New()
			mem.MapPage(0x1000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
			for i, opcode := range code {
				if err := mem.Write8(0x1000+uint64(i), opcode); err != nil {
					b.Fatal(err)
				}
			}
			cache := NewCache(mem)
			if native && !cache.EnableNativeCodegen() {
				b.Skip("native codegen unavailable")
			}
			block := cache.Compile(0x1000)
			if block == nil || native && block.native == 0 {
				b.Fatal("integer benchmark block was not accepted")
			}
			regs := initialRegs
			state := &State{
				Regs:   &regs,
				RIP:    new(uint64),
				Rflags: new(uint64),
				Mem:    mem,
			}
			*state.RIP = 0x1000
			*state.Rflags = 0x202
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if err := block.Run(state); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

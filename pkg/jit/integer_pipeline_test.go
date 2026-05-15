package jit

import (
	"strings"
	"testing"

	"github.com/mirkobrombin/Raven/pkg/mmu"
)

func TestNativeIntegerUnaryAndIMul3MatchClosure(t *testing.T) {
	unary := []struct {
		name string
		code []byte
	}{
		{name: "NOT byte", code: []byte{0xF6, 0xD0, 0xEB, 0xFE}},
		{name: "NOT word", code: []byte{0x66, 0xF7, 0xD0, 0xEB, 0xFE}},
		{name: "NOT dword", code: []byte{0xF7, 0xD0, 0xEB, 0xFE}},
		{name: "NOT qword", code: []byte{0x48, 0xF7, 0xD0, 0xEB, 0xFE}},
		{name: "NEG byte", code: []byte{0xF6, 0xD8, 0xEB, 0xFE}},
		{name: "NEG word", code: []byte{0x66, 0xF7, 0xD8, 0xEB, 0xFE}},
		{name: "NEG dword", code: []byte{0xF7, 0xD8, 0xEB, 0xFE}},
		{name: "NEG qword", code: []byte{0x48, 0xF7, 0xD8, 0xEB, 0xFE}},
		{name: "INC byte", code: []byte{0xFE, 0xC0, 0xEB, 0xFE}},
		{name: "INC word", code: []byte{0x66, 0xFF, 0xC0, 0xEB, 0xFE}},
		{name: "INC dword", code: []byte{0xFF, 0xC0, 0xEB, 0xFE}},
		{name: "INC qword", code: []byte{0x48, 0xFF, 0xC0, 0xEB, 0xFE}},
		{name: "DEC byte", code: []byte{0xFE, 0xC8, 0xEB, 0xFE}},
		{name: "DEC word", code: []byte{0x66, 0xFF, 0xC8, 0xEB, 0xFE}},
		{name: "DEC dword", code: []byte{0xFF, 0xC8, 0xEB, 0xFE}},
		{name: "DEC qword", code: []byte{0x48, 0xFF, 0xC8, 0xEB, 0xFE}},
	}
	values := []uint64{0, 1, 0x7F, 0x80, 0x7FFF, 0x8000, 0x7FFFFFFF, 0x80000000, ^uint64(0)}
	for _, test := range unary {
		for _, value := range values {
			t.Run(test.name, func(t *testing.T) {
				regs := [16]uint64{0: value}
				result := compareNativeIntegerFixture(t, test.code, regs, 0xA53)
				if result.instret != 2 || result.fallback {
					t.Fatalf("instret=%d fallback=%v", result.instret, result.fallback)
				}
			})
		}
	}

	imul3 := []struct {
		name string
		code []byte
	}{
		{name: "word imm8", code: []byte{0x66, 0x6B, 0xC1, 0x80, 0xEB, 0xFE}},
		{name: "word imm16", code: []byte{0x66, 0x69, 0xC1, 0x00, 0x40, 0xEB, 0xFE}},
		{name: "dword imm8", code: []byte{0x6B, 0xC1, 0x80, 0xEB, 0xFE}},
		{name: "dword imm32", code: []byte{0x69, 0xC1, 0x00, 0x00, 0x00, 0x40, 0xEB, 0xFE}},
		{name: "qword imm8", code: []byte{0x48, 0x6B, 0xC1, 0x80, 0xEB, 0xFE}},
		{name: "qword imm32", code: []byte{0x48, 0x69, 0xC1, 0x00, 0x00, 0x00, 0x40, 0xEB, 0xFE}},
	}
	for _, test := range imul3 {
		for _, value := range values {
			t.Run(test.name, func(t *testing.T) {
				regs := [16]uint64{0: 0xAAAAAAAAAAAAAAAA, 1: value}
				compareNativeIntegerFixture(t, test.code, regs, 0x252)
			})
		}
	}
}

type integerClosureResult struct {
	regs    [16]uint64
	flags   uint64
	rip     uint64
	instret uint64
	err     error
}

func runIntegerClosure(t *testing.T, code []byte, regs [16]uint64, flags uint64) integerClosureResult {
	t.Helper()
	mem := mmu.New()
	mem.MapPage(0x1000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	for i, opcode := range code {
		if err := mem.Write8(0x1000+uint64(i), opcode); err != nil {
			t.Fatal(err)
		}
	}
	cache := NewCache(mem)
	block := cache.Compile(0x1000)
	if block == nil {
		t.Fatal("integer closure fixture did not compile")
	}
	rip := uint64(0x1000)
	instret := uint64(0)
	state := &State{Regs: &regs, RIP: &rip, Rflags: &flags, Mem: mem, Instret: &instret}
	err := block.Run(state)
	return integerClosureResult{regs: regs, flags: flags, rip: rip, instret: instret, err: err}
}

func TestIntegerDivisionResultsAndFaultAtomicity(t *testing.T) {
	success := []struct {
		name string
		code []byte
		regs [16]uint64
		want [16]uint64
	}{
		{
			name: "DIV byte",
			code: []byte{0xF6, 0xF1, 0xEB, 0xFE},
			regs: [16]uint64{0: 0x0100, 1: 3},
			want: [16]uint64{0: 0x0155, 1: 3},
		},
		{
			name: "DIV word",
			code: []byte{0x66, 0xF7, 0xF1, 0xEB, 0xFE},
			regs: [16]uint64{0: 0, 1: 3, 2: 1},
			want: [16]uint64{0: 0x5555, 1: 3, 2: 1},
		},
		{
			name: "DIV dword",
			code: []byte{0xF7, 0xF1, 0xEB, 0xFE},
			regs: [16]uint64{0: 0, 1: 3, 2: 1},
			want: [16]uint64{0: 0x55555555, 1: 3, 2: 1},
		},
		{
			name: "DIV qword",
			code: []byte{0x48, 0xF7, 0xF1, 0xEB, 0xFE},
			regs: [16]uint64{0: 0, 1: 3, 2: 1},
			want: [16]uint64{0: 0x5555555555555555, 1: 3, 2: 1},
		},
		{
			name: "IDIV byte negative",
			code: []byte{0xF6, 0xF9, 0xEB, 0xFE},
			regs: [16]uint64{0: 0xFF00, 1: 3},
			want: [16]uint64{0: 0xFFAB, 1: 3},
		},
		{
			name: "IDIV word negative",
			code: []byte{0x66, 0xF7, 0xF9, 0xEB, 0xFE},
			regs: [16]uint64{0: 0, 1: 3, 2: 0xFFFF},
			want: [16]uint64{0: 0xAAAB, 1: 3, 2: 0xFFFF},
		},
		{
			name: "IDIV dword negative",
			code: []byte{0xF7, 0xF9, 0xEB, 0xFE},
			regs: [16]uint64{0: 0, 1: 3, 2: 0xFFFFFFFF},
			want: [16]uint64{0: 0xAAAAAAAB, 1: 3, 2: 0xFFFFFFFF},
		},
		{
			name: "IDIV qword negative",
			code: []byte{0x48, 0xF7, 0xF9, 0xEB, 0xFE},
			regs: [16]uint64{0: 0, 1: 3, 2: ^uint64(0)},
			want: [16]uint64{0: 0xAAAAAAAAAAAAAAAB, 1: 3, 2: ^uint64(0)},
		},
		{
			name: "IDIV qword minimum",
			code: []byte{0x48, 0xF7, 0xF9, 0xEB, 0xFE},
			regs: [16]uint64{0: 0x8000000000000000, 1: 1, 2: ^uint64(0)},
			want: [16]uint64{0: 0x8000000000000000, 1: 1, 2: 0},
		},
	}
	for _, test := range success {
		t.Run(test.name, func(t *testing.T) {
			result := runIntegerClosure(t, test.code, test.regs, 0xA53)
			if result.err != nil {
				t.Fatal(result.err)
			}
			if result.regs != test.want || result.flags != 0xA53 || result.instret != 2 {
				t.Fatalf("result=%+v wantRegs=%#v", result, test.want)
			}
		})
	}

	faults := []struct {
		name string
		code []byte
		regs [16]uint64
		text string
	}{
		{name: "DIV byte zero", code: []byte{0xF6, 0xF1}, regs: [16]uint64{0: 1}, text: "division by zero"},
		{name: "DIV word overflow", code: []byte{0x66, 0xF7, 0xF1}, regs: [16]uint64{0: 0, 1: 1, 2: 1}, text: "quotient overflow"},
		{name: "DIV dword overflow", code: []byte{0xF7, 0xF1}, regs: [16]uint64{0: 0, 1: 1, 2: 1}, text: "quotient overflow"},
		{name: "DIV qword overflow", code: []byte{0x48, 0xF7, 0xF1}, regs: [16]uint64{0: 0, 1: 1, 2: 1}, text: "quotient overflow"},
		{name: "IDIV byte overflow", code: []byte{0xF6, 0xF9}, regs: [16]uint64{0: 0x8000, 1: 0xFF}, text: "quotient overflow"},
		{name: "IDIV word overflow", code: []byte{0x66, 0xF7, 0xF9}, regs: [16]uint64{0: 0, 1: 0xFFFF, 2: 0x8000}, text: "quotient overflow"},
		{name: "IDIV dword overflow", code: []byte{0xF7, 0xF9}, regs: [16]uint64{0: 0, 1: 0xFFFFFFFF, 2: 0x80000000}, text: "quotient overflow"},
		{name: "IDIV qword overflow", code: []byte{0x48, 0xF7, 0xF9}, regs: [16]uint64{0: 0, 1: ^uint64(0), 2: 0x8000000000000000}, text: "quotient overflow"},
		{name: "IDIV qword minimum by minus one", code: []byte{0x48, 0xF7, 0xF9}, regs: [16]uint64{0: 0x8000000000000000, 1: ^uint64(0), 2: ^uint64(0)}, text: "quotient overflow"},
		{name: "IDIV qword positive 2^63", code: []byte{0x48, 0xF7, 0xF9}, regs: [16]uint64{0: 0x8000000000000000, 1: 1, 2: 0}, text: "quotient overflow"},
	}
	for _, test := range faults {
		t.Run(test.name, func(t *testing.T) {
			result := runIntegerClosure(t, test.code, test.regs, 0xA53)
			if result.err == nil || !strings.Contains(result.err.Error(), test.text) {
				t.Fatalf("error=%v, want %q", result.err, test.text)
			}
			if result.regs != test.regs || result.flags != 0xA53 ||
				result.rip != 0x1000 || result.instret != 0 {
				t.Fatalf("fault changed state: %+v", result)
			}
		})
	}
}

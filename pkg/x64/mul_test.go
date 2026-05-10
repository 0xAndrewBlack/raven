package x64

import (
	"testing"

	"github.com/mirkobrombin/Raven/pkg/mmu"
)

func runGroup3Multiply(t *testing.T, code []byte, rax, operand uint64, flags uint64) *CPU {
	t.Helper()
	mem := mmu.New()
	mem.MapRange(0x1000, mmu.PageSize, mmu.PermRead|mmu.PermExecute)
	if err := mem.WriteBytesRaw(0x1000, code); err != nil {
		t.Fatal(err)
	}

	cpu := New(mem)
	cpu.RIP = 0x1000
	cpu.Regs[RAX] = rax
	cpu.Regs[RDI] = operand
	cpu.Rflags = flags
	if err := cpu.step(); err != nil {
		t.Fatal(err)
	}
	return cpu
}

func TestMULUpdatesCarryAndOverflow(t *testing.T) {
	tests := []struct {
		name     string
		code     []byte
		rax      uint64
		operand  uint64
		wantRAX  uint64
		wantRDX  uint64
		wantFlag bool
	}{
		{name: "byte fits", code: []byte{0x40, 0xF6, 0xE7}, rax: 2, operand: 3, wantRAX: 6},
		{name: "byte overflows", code: []byte{0x40, 0xF6, 0xE7}, rax: 0xFF, operand: 2, wantRAX: 0x1FE, wantFlag: true},
		{name: "word fits", code: []byte{0x66, 0xF7, 0xE7}, rax: 2, operand: 3, wantRAX: 6},
		{name: "word overflows", code: []byte{0x66, 0xF7, 0xE7}, rax: 0xFFFF, operand: 2, wantRAX: 0xFFFE, wantRDX: 1, wantFlag: true},
		{name: "dword fits", code: []byte{0xF7, 0xE7}, rax: 2, operand: 3, wantRAX: 6},
		{name: "dword overflows", code: []byte{0xF7, 0xE7}, rax: 0xFFFFFFFF, operand: 2, wantRAX: 0xFFFFFFFE, wantRDX: 1, wantFlag: true},
		{name: "qword fits", code: []byte{0x48, 0xF7, 0xE7}, rax: 2, operand: 1024, wantRAX: 2048},
		{name: "qword overflows", code: []byte{0x48, 0xF7, 0xE7}, rax: ^uint64(0), operand: 2, wantRAX: ^uint64(0) - 1, wantRDX: 1, wantFlag: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			initialFlags := uint64(0)
			if !tt.wantFlag {
				initialFlags = flagCF | flagOF
			}
			cpu := runGroup3Multiply(t, tt.code, tt.rax, tt.operand, initialFlags)
			if cpu.Regs[RAX] != tt.wantRAX || cpu.Regs[RDX] != tt.wantRDX {
				t.Fatalf("RDX:RAX = 0x%x:0x%x, want 0x%x:0x%x", cpu.Regs[RDX], cpu.Regs[RAX], tt.wantRDX, tt.wantRAX)
			}
			if got := cpu.Rflags&flagCF != 0; got != tt.wantFlag {
				t.Fatalf("CF set = %v, want %v", got, tt.wantFlag)
			}
			if got := cpu.Rflags&flagOF != 0; got != tt.wantFlag {
				t.Fatalf("OF set = %v, want %v", got, tt.wantFlag)
			}
		})
	}
}

func TestIMULUpdatesCarryAndOverflow(t *testing.T) {
	tests := []struct {
		name     string
		code     []byte
		rax      uint64
		operand  uint64
		wantRAX  uint64
		wantRDX  uint64
		wantFlag bool
	}{
		{name: "byte negative fits", code: []byte{0x40, 0xF6, 0xEF}, rax: 0xFE, operand: 2, wantRAX: 0xFFFC},
		{name: "byte overflows", code: []byte{0x40, 0xF6, 0xEF}, rax: 0x7F, operand: 2, wantRAX: 0xFE, wantFlag: true},
		{name: "word negative fits", code: []byte{0x66, 0xF7, 0xEF}, rax: 0xFFFE, operand: 2, wantRAX: 0xFFFC, wantRDX: 0xFFFF},
		{name: "word overflows", code: []byte{0x66, 0xF7, 0xEF}, rax: 0x7FFF, operand: 2, wantRAX: 0xFFFE, wantFlag: true},
		{name: "dword negative fits", code: []byte{0xF7, 0xEF}, rax: 0xFFFFFFFE, operand: 2, wantRAX: 0xFFFFFFFC, wantRDX: 0xFFFFFFFF},
		{name: "dword overflows", code: []byte{0xF7, 0xEF}, rax: 0x7FFFFFFF, operand: 2, wantRAX: 0xFFFFFFFE, wantFlag: true},
		{name: "qword negative fits", code: []byte{0x48, 0xF7, 0xEF}, rax: ^uint64(1), operand: 2, wantRAX: ^uint64(3), wantRDX: ^uint64(0)},
		{name: "qword overflows", code: []byte{0x48, 0xF7, 0xEF}, rax: uint64(^uint64(0) >> 1), operand: 2, wantRAX: ^uint64(0) - 1, wantFlag: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			initialFlags := uint64(0)
			if !tt.wantFlag {
				initialFlags = flagCF | flagOF
			}
			cpu := runGroup3Multiply(t, tt.code, tt.rax, tt.operand, initialFlags)
			if cpu.Regs[RAX] != tt.wantRAX || cpu.Regs[RDX] != tt.wantRDX {
				t.Fatalf("RDX:RAX = 0x%x:0x%x, want 0x%x:0x%x", cpu.Regs[RDX], cpu.Regs[RAX], tt.wantRDX, tt.wantRAX)
			}
			if got := cpu.Rflags&flagCF != 0; got != tt.wantFlag {
				t.Fatalf("CF set = %v, want %v", got, tt.wantFlag)
			}
			if got := cpu.Rflags&flagOF != 0; got != tt.wantFlag {
				t.Fatalf("OF set = %v, want %v", got, tt.wantFlag)
			}
		})
	}
}

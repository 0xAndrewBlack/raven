package x64

import (
	"testing"

	"github.com/mirkobrombin/Raven/pkg/mmu"
)

func runImmediateInstruction(t *testing.T, code []byte, rdi uint64) *CPU {
	t.Helper()
	mem := mmu.New()
	mem.MapRange(0x1000, mmu.PageSize, mmu.PermRead|mmu.PermExecute)
	if err := mem.WriteBytesRaw(0x1000, code); err != nil {
		t.Fatal(err)
	}
	cpu := New(mem)
	cpu.RIP = 0x1000
	cpu.Regs[RDI] = rdi
	if err := cpu.step(); err != nil {
		t.Fatal(err)
	}
	return cpu
}

func TestGroup1SignExtendsImmediateToQword(t *testing.T) {
	tests := []struct {
		name    string
		code    []byte
		initial uint64
		want    uint64
		wantZF  bool
	}{
		{name: "imm8 add", code: []byte{0x48, 0x83, 0xC7, 0xFF}, want: ^uint64(0)},
		{name: "imm32 compare", code: []byte{0x48, 0x81, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, initial: ^uint64(0), want: ^uint64(0), wantZF: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cpu := runImmediateInstruction(t, tt.code, tt.initial)
			if cpu.Regs[RDI] != tt.want {
				t.Fatalf("RDI = 0x%x, want 0x%x", cpu.Regs[RDI], tt.want)
			}
			if got := cpu.Rflags&flagZF != 0; got != tt.wantZF {
				t.Fatalf("ZF set = %v, want %v", got, tt.wantZF)
			}
		})
	}
}

func TestGroup3TestSignExtendsImmediateToQword(t *testing.T) {
	cpu := runImmediateInstruction(t,
		[]byte{0x48, 0xF7, 0xC7, 0x00, 0x00, 0x00, 0x80},
		0xFFFFFFFF00000000,
	)
	if cpu.Rflags&flagZF != 0 {
		t.Fatal("TEST incorrectly zero-extended its imm32 operand")
	}
}

func TestGroup3TestByteWithREX(t *testing.T) {
	tests := []struct {
		name   string
		value  uint64
		wantZF bool
	}{
		{name: "bit set", value: 0x1FF},
		{name: "bit clear", value: 0x1FB, wantZF: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cpu := runImmediateInstruction(t, []byte{0x40, 0xF6, 0xC7, 0x04}, tt.value)
			if got := cpu.Rflags&flagZF != 0; got != tt.wantZF {
				t.Fatalf("ZF set = %v, want %v", got, tt.wantZF)
			}
		})
	}
}

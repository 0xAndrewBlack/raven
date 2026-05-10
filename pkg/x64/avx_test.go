package x64

import (
	"bytes"
	"testing"

	"github.com/mirkobrombin/Raven/pkg/mmu"
)

func TestVMOVDQU256LoadStore(t *testing.T) {
	mem := mmu.New()
	mem.MapRange(0x1000, mmu.PageSize, mmu.PermRead|mmu.PermExecute)
	mem.MapRange(0x2000, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	mem.MapRange(0x3000, mmu.PageSize, mmu.PermRead|mmu.PermWrite)

	code := []byte{
		0xC5, 0xFE, 0x6F, 0x02, // vmovdqu ymm0, [rdx]
		0xC5, 0xFE, 0x7F, 0x01, // vmovdqu [rcx], ymm0
	}
	source := make([]byte, 32)
	for i := range source {
		source[i] = byte(i + 1)
	}
	if err := mem.WriteBytesRaw(0x1000, code); err != nil {
		t.Fatal(err)
	}
	if err := mem.WriteBytes(0x2000, source); err != nil {
		t.Fatal(err)
	}

	cpu := New(mem)
	cpu.RIP = 0x1000
	cpu.Regs[RDX] = 0x2000
	cpu.Regs[RCX] = 0x3000
	if err := cpu.step(); err != nil {
		t.Fatal(err)
	}
	if err := cpu.step(); err != nil {
		t.Fatal(err)
	}

	got, err := mem.ReadBytes(0x3000, len(source))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, source) {
		t.Fatalf("VMOVDQU copied %x, want %x", got, source)
	}
}

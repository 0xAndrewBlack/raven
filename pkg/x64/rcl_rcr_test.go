package x64

import (
	"testing"

	"github.com/mirkobrombin/Raven/pkg/mmu"
)

func runShift(t *testing.T, code []byte, eax uint64, cfIn bool) (out uint64, cf, of bool) {
	t.Helper()
	mem := mmu.New()
	mem.MapPage(0x1000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	full := append(append([]byte{}, code...), 0xEB, 0xFE)
	for i, b := range full {
		mem.Write8(0x1000+uint64(i), b)
	}
	c := New(mem)
	c.Mode32 = true
	c.RIP = 0x1000
	c.Regs[RAX] = eax
	if cfIn {
		c.Rflags |= flagCF
	} else {
		c.Rflags &^= flagCF
	}
	if err := c.step(); err != nil {
		t.Fatal(err)
	}
	return c.Regs[RAX] & 0xFFFFFFFF, c.Rflags&flagCF != 0, c.Rflags&flagOF != 0
}

func TestRCLRCR(t *testing.T) {
	// RCL eax, 1  (D1 D0)
	// eax=0x80000000, CF=0 -> result=0 (top bit into CF), CF=1
	if out, cf, _ := runShift(t, []byte{0xD1, 0xD0}, 0x80000000, false); out != 0 || !cf {
		t.Fatalf("RCL 0x80000000 CF0: out=%#x cf=%v, want 0 cf=true", out, cf)
	}
	// eax=0x40000000, CF=1 -> result=0x80000001, CF=0
	if out, cf, _ := runShift(t, []byte{0xD1, 0xD0}, 0x40000000, true); out != 0x80000001 || cf {
		t.Fatalf("RCL 0x40000000 CF1: out=%#x cf=%v, want 0x80000001 cf=false", out, cf)
	}
	// RCR eax, 1  (D1 D8)
	// eax=1, CF=0 -> result=0, CF=1
	if out, cf, _ := runShift(t, []byte{0xD1, 0xD8}, 1, false); out != 0 || !cf {
		t.Fatalf("RCR 1 CF0: out=%#x cf=%v, want 0 cf=true", out, cf)
	}
	// eax=0, CF=1 -> result=0x80000000, CF=0
	if out, cf, _ := runShift(t, []byte{0xD1, 0xD8}, 0, true); out != 0x80000000 || cf {
		t.Fatalf("RCR 0 CF1: out=%#x cf=%v, want 0x80000000 cf=false", out, cf)
	}
	// RCR eax, CL with CL=4 (D3 D8), eax=0xF0, CF=0
	// 33-bit rotate of {CF=0, 0xF0} right by 4: low nibble 0 rotates out.
	c := New(mmu.New())
	_ = c
}

func TestIDIV16(t *testing.T) {
	// idiv bx (F7 FB): DX:AX / BX signed, quotient->AX rem->DX (16-bit)
	mem := mmu.New()
	mem.MapPage(0x1000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	code := []byte{0x66, 0xF7, 0xFB, 0xEB, 0xFE} // idiv bx (operand-size 16)
	for i, b := range code {
		mem.Write8(0x1000+uint64(i), b)
	}
	c := New(mem)
	c.Mode32 = true
	c.RIP = 0x1000
	// DX:AX = 0x0001_0000 = 65536 ; BX = 7  -> 65536/7 = 9362 r 2
	c.Regs[RDX] = 1
	c.Regs[RAX] = 0
	c.Regs[RBX] = 7
	if err := c.step(); err != nil {
		t.Fatal(err)
	}
	if q := c.Regs[RAX] & 0xFFFF; q != 9362 {
		t.Fatalf("IDIV16 quotient=%d, want 9362", q)
	}
	if r := c.Regs[RDX] & 0xFFFF; r != 2 {
		t.Fatalf("IDIV16 remainder=%d, want 2", r)
	}
	// negative: DX:AX = -100 (0xFFFFFF9C), BX = 3 -> -33 r -1
	c.RIP = 0x1000
	c.Regs[RDX] = 0xFFFF
	c.Regs[RAX] = 0xFF9C
	c.Regs[RBX] = 3
	if err := c.step(); err != nil {
		t.Fatal(err)
	}
	if q := int16(c.Regs[RAX] & 0xFFFF); q != -33 {
		t.Fatalf("IDIV16 neg quotient=%d, want -33", q)
	}
	if r := int16(c.Regs[RDX] & 0xFFFF); r != -1 {
		t.Fatalf("IDIV16 neg remainder=%d, want -1", r)
	}
}

func TestCMPXCHG8B(t *testing.T) {
	mem := mmu.New()
	mem.MapPage(0x1000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	mem.MapPage(0x2000, mmu.PermRead|mmu.PermWrite)
	// cmpxchg8b [esi]  (0F C7 0E)
	code := []byte{0x0F, 0xC7, 0x0E, 0xEB, 0xFE}
	for i, b := range code {
		mem.Write8(0x1000+uint64(i), b)
	}
	// Case 1: match. mem = 0x1122334455667788, EDX:EAX = same -> store ECX:EBX, ZF=1
	mem.Write64(0x2000, 0x1122334455667788)
	c := New(mem)
	c.Mode32 = true
	c.RIP = 0x1000
	c.Regs[RSI] = 0x2000
	c.Regs[RAX] = 0x55667788
	c.Regs[RDX] = 0x11223344
	c.Regs[RBX] = 0xAABBCCDD
	c.Regs[RCX] = 0x99887766
	if err := c.step(); err != nil {
		t.Fatal(err)
	}
	if c.Rflags&flagZF == 0 {
		t.Fatal("CMPXCHG8B match: ZF should be set")
	}
	v, _ := mem.Read64(0x2000)
	if v != 0x99887766AABBCCDD {
		t.Fatalf("CMPXCHG8B match: mem=%#x, want 0x99887766AABBCCDD", v)
	}
	// Case 2: mismatch. reload EDX:EAX, ZF=0
	c.RIP = 0x1000
	c.Regs[RAX] = 0
	c.Regs[RDX] = 0
	if err := c.step(); err != nil {
		t.Fatal(err)
	}
	if c.Rflags&flagZF != 0 {
		t.Fatal("CMPXCHG8B mismatch: ZF should be clear")
	}
	if (c.Regs[RAX]&0xFFFFFFFF) != 0xAABBCCDD || (c.Regs[RDX]&0xFFFFFFFF) != 0x99887766 {
		t.Fatalf("CMPXCHG8B mismatch reload: EAX=%#x EDX=%#x", c.Regs[RAX], c.Regs[RDX])
	}
}

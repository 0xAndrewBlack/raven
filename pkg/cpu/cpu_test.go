package cpu

import (
	"testing"

	"github.com/mirkobrombin/go-vm/pkg/mmu"
)

func TestADDI(t *testing.T) {
	m := setupMem(t)
	c := New(m)

	// addi x1, x0, 42  →  0x02A00093
	writeInstr(t, m, 0x1000, 0x02A00093)

	c.SetPC(0x1000)
	if err := c.Step(); err != nil {
		t.Fatal(err)
	}
	if c.X[1] != 42 {
		t.Fatalf("expected x1=42, got %d", c.X[1])
	}
	if c.PC != 0x1004 {
		t.Fatalf("expected PC=0x1004, got 0x%x", c.PC)
	}
}

func TestADD(t *testing.T) {
	m := setupMem(t)
	c := New(m)

	// add x3, x1, x2  →  0x002081B3
	c.X[1] = 10
	c.X[2] = 20
	writeInstr(t, m, 0x1000, 0x002081B3)

	c.SetPC(0x1000)
	if err := c.Step(); err != nil {
		t.Fatal(err)
	}
	if c.X[3] != 30 {
		t.Fatalf("expected x3=30, got %d", c.X[3])
	}
}

func TestBEQ(t *testing.T) {
	m := setupMem(t)
	c := New(m)

	// beq x1, x2, +8  →  0x00208463
	c.X[1] = 5
	c.X[2] = 5
	writeInstr(t, m, 0x1000, 0x00208463)

	c.SetPC(0x1000)
	if err := c.Step(); err != nil {
		t.Fatal(err)
	}
	if c.PC != 0x1008 {
		t.Fatalf("expected PC=0x1008 (taken), got 0x%x", c.PC)
	}
}

func TestBNE_NotTaken(t *testing.T) {
	m := setupMem(t)
	c := New(m)

	// bne x1, x2, +8  →  0x00209463
	c.X[1] = 5
	c.X[2] = 5
	writeInstr(t, m, 0x1000, 0x00209463)

	c.SetPC(0x1000)
	if err := c.Step(); err != nil {
		t.Fatal(err)
	}
	if c.PC != 0x1004 {
		t.Fatalf("expected PC=0x1004 (not taken), got 0x%x", c.PC)
	}
}

func TestLUI(t *testing.T) {
	m := setupMem(t)
	c := New(m)

	// lui x5, 0xDEADB  →  0xDEADB2B7
	writeInstr(t, m, 0x1000, 0xDEADB2B7)

	c.SetPC(0x1000)
	if err := c.Step(); err != nil {
		t.Fatal(err)
	}
	expected := uint64(0xFFFFFFFFDEADB000)
	if c.X[5] != expected {
		t.Fatalf("expected x5=0x%x, got 0x%x", expected, c.X[5])
	}
}

func TestECALL(t *testing.T) {
	m := setupMem(t)
	c := New(m)

	called := false
	c.Syscall = func(cpu *CPU) {
		called = true
	}

	// ecall → 0x00000073
	writeInstr(t, m, 0x1000, 0x00000073)
	c.SetPC(0x1000)
	if err := c.Step(); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("syscall handler not called")
	}
}

// --- helpers ---

func setupMem(t *testing.T) *mmu.MMU {
	t.Helper()
	mem := mmu.New()
	mem.MapRange(0x1000, 0x1000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	return mem
}

func writeInstr(t *testing.T, mem *mmu.MMU, addr uint64, instr uint32) {
	t.Helper()
	if err := mem.Write32(addr, instr); err != nil {
		t.Fatal(err)
	}
}

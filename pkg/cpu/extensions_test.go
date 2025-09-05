package cpu

import (
	"testing"

	"github.com/mirkobrombin/go-vm/pkg/mmu"
)

func TestCompressed_CADDI(t *testing.T) {
	m := setupMem(t)
	c := New(m)
	c.X[10] = 100

	// C.ADDI x10, 5 → quadrant 1, funct3=0
	// Encoding: [12]=0, [11:7]=01010(x10), [6:2]=00101(5), [1:0]=01
	// = 0 | 01010 | 00101 | 01  = 0000_0101_0001_0101 = 0x0515
	instr := uint16(0x0515)
	writeInstr16(t, m, 0x1000, instr)

	c.SetPC(0x1000)
	if err := c.Step(); err != nil {
		t.Fatal(err)
	}
	if c.X[10] != 105 {
		t.Fatalf("expected x10=105, got %d", c.X[10])
	}
	if c.PC != 0x1002 {
		t.Fatalf("expected PC=0x1002, got 0x%x", c.PC)
	}
}

func TestCompressed_CLI(t *testing.T) {
	m := setupMem(t)
	c := New(m)

	// C.LI x11, 7 → quadrant 1, funct3=010
	// Encoding: [12]=0, [11:7]=01011(x11), [6:2]=00111(7), [1:0]=01
	// funct3=010 → bits [15:13]=010
	// = 010 | 0 | 01011 | 00111 | 01 = 0100_0101_1001_1101 = 0x459D
	instr := uint16(0x459D)
	writeInstr16(t, m, 0x1000, instr)

	c.SetPC(0x1000)
	if err := c.Step(); err != nil {
		t.Fatal(err)
	}
	if c.X[11] != 7 {
		t.Fatalf("expected x11=7, got %d", c.X[11])
	}
}

func TestCompressed_CMV(t *testing.T) {
	m := setupMem(t)
	c := New(m)
	c.X[15] = 0xCAFE

	// C.MV x10, x15 → quadrant 2, funct3=100, bit12=0
	// Encoding: [15:13]=100, [12]=0, [11:7]=01010(x10), [6:2]=01111(x15), [1:0]=10
	// = 100 | 0 | 01010 | 01111 | 10 = 1000_0101_0011_1110 = 0x853E
	instr := uint16(0x853E)
	writeInstr16(t, m, 0x1000, instr)

	c.SetPC(0x1000)
	if err := c.Step(); err != nil {
		t.Fatal(err)
	}
	if c.X[10] != 0xCAFE {
		t.Fatalf("expected x10=0xCAFE, got 0x%x", c.X[10])
	}
}

func TestAtomic_AMOADD_D(t *testing.T) {
	m := mmu.New()
	m.MapRange(0x2000, 0x1000, mmu.PermRead|mmu.PermWrite)
	m.MapRange(0x1000, 0x1000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	m.Write64(0x2000, 100)

	c := New(m)
	c.X[1] = 0x2000 // address
	c.X[2] = 50     // value to add

	// amoadd.d x3, x2, (x1)
	// opcode=0x2F, funct3=011(64-bit), funct5=00000
	// rd=3, rs1=1, rs2=2
	// = 00000 | 00 | 00010 | 00001 | 011 | 00011 | 0101111
	// = 0000_0000_0010_0000_1011_0001_1010_1111 = 0x002081AF
	// Actually let me encode correctly:
	// [31:27]=00000 (funct5 AMOADD), [26:25]=00 (aq/rl), [24:20]=00010 (rs2=x2)
	// [19:15]=00001 (rs1=x1), [14:12]=011 (funct3=64-bit), [11:7]=00011 (rd=x3)
	// [6:0]=0101111 (AMO opcode)
	instr := uint32(0x00000000)
	instr |= 0x2F                    // opcode
	instr |= 3 << 7                  // rd = x3
	instr |= 3 << 12                 // funct3 = 011 (64-bit)
	instr |= 1 << 15                 // rs1 = x1
	instr |= 2 << 20                 // rs2 = x2
	instr |= 0x00 << 27             // funct5 = AMOADD (00000)

	writeInstr(t, m, 0x1000, instr)
	c.SetPC(0x1000)
	if err := c.Step(); err != nil {
		t.Fatal(err)
	}
	// rd should get old value (100)
	if c.X[3] != 100 {
		t.Fatalf("expected x3=100 (old value), got %d", c.X[3])
	}
	// memory should now be 150
	val, _ := m.Read64(0x2000)
	if val != 150 {
		t.Fatalf("expected mem[0x2000]=150, got %d", val)
	}
}

func TestAtomic_LR_SC(t *testing.T) {
	m := mmu.New()
	m.MapRange(0x2000, 0x1000, mmu.PermRead|mmu.PermWrite)
	m.MapRange(0x1000, 0x1000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	m.Write64(0x2000, 42)

	c := New(m)
	c.X[1] = 0x2000

	// LR.D x3, (x1): funct5=00010, rs2=0
	lrd := uint32(0x2F) | (3 << 7) | (3 << 12) | (1 << 15) | (0 << 20) | (0x02 << 27)
	writeInstr(t, m, 0x1000, lrd)
	c.SetPC(0x1000)
	if err := c.Step(); err != nil {
		t.Fatal(err)
	}
	if c.X[3] != 42 {
		t.Fatalf("LR.D: expected x3=42, got %d", c.X[3])
	}

	// SC.D x4, x5, (x1): funct5=00011
	c.X[5] = 99
	scd := uint32(0x2F) | (4 << 7) | (3 << 12) | (1 << 15) | (5 << 20) | (0x03 << 27)
	writeInstr(t, m, 0x1004, scd)
	c.SetPC(0x1004)
	if err := c.Step(); err != nil {
		t.Fatal(err)
	}
	if c.X[4] != 0 {
		t.Fatalf("SC.D should succeed (x4=0), got %d", c.X[4])
	}
	val, _ := m.Read64(0x2000)
	if val != 99 {
		t.Fatalf("SC.D: expected mem=99, got %d", val)
	}
}

// --- helpers ---

func writeInstr16(t *testing.T, mem *mmu.MMU, addr uint64, instr uint16) {
	t.Helper()
	if err := mem.Write16(addr, instr); err != nil {
		t.Fatal(err)
	}
}

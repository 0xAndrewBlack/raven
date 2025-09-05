package cpu

import (
	"math"
	"testing"

	"github.com/mirkobrombin/go-vm/pkg/mmu"
)

// encodeR builds an R-type RISC-V instruction.
func encodeR(funct7, rs2, rs1, funct3, rd, opcode uint32) uint32 {
	return (funct7 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode
}

func fpuWriteInstr(mem *mmu.MMU, addr uint64, instr uint32) {
	mem.Write8(addr, uint8(instr))
	mem.Write8(addr+1, uint8(instr>>8))
	mem.Write8(addr+2, uint8(instr>>16))
	mem.Write8(addr+3, uint8(instr>>24))
}

// --- FPU tests ---

func TestFADD_S(t *testing.T) {
	mem := mmu.New()
	c := New(mem)

	c.writeFS(1, 3.5)
	c.writeFS(2, 1.25)

	// FADD.S f3, f1, f2
	instr := encodeR(0x00, 2, 1, 0, 3, 0x53)
	mem.MapRange(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	fpuWriteInstr(mem, 0, instr)
	c.PC = 0
	err := c.Step()
	if err != nil {
		t.Fatal(err)
	}

	got := c.readFS(3)
	if got != 4.75 {
		t.Fatalf("FADD.S: expected 4.75, got %f", got)
	}
}

func TestFMUL_D(t *testing.T) {
	mem := mmu.New()
	c := New(mem)

	c.writeFD(1, 2.5)
	c.writeFD(2, 4.0)

	// FMUL.D f3, f1, f2 (funct7=0x09)
	instr := encodeR(0x09, 2, 1, 0, 3, 0x53)
	mem.MapRange(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	fpuWriteInstr(mem, 0, instr)
	c.PC = 0
	err := c.Step()
	if err != nil {
		t.Fatal(err)
	}

	got := c.readFD(3)
	if got != 10.0 {
		t.Fatalf("FMUL.D: expected 10.0, got %f", got)
	}
}

func TestFCVT_W_S(t *testing.T) {
	mem := mmu.New()
	c := New(mem)

	c.writeFS(1, 42.7)

	// FCVT.W.S x5, f1, rm=RTZ(1) → funct7=0x60, rs2=0
	instr := encodeR(0x60, 0, 1, 1, 5, 0x53)
	mem.MapRange(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	fpuWriteInstr(mem, 0, instr)
	c.PC = 0
	err := c.Step()
	if err != nil {
		t.Fatal(err)
	}

	got := int32(c.readReg(5))
	if got != 42 {
		t.Fatalf("FCVT.W.S: expected 42, got %d", got)
	}
}

func TestFCLASS_D(t *testing.T) {
	tests := []struct {
		name string
		val  float64
		want uint64
	}{
		{"+normal", 1.0, 1 << 6},
		{"-normal", -1.0, 1 << 1},
		{"+zero", 0.0, 1 << 4},
		{"+inf", math.Inf(1), 1 << 7},
		{"-inf", math.Inf(-1), 1 << 0},
		{"NaN", math.NaN(), 1 << 9},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := fclassD(tt.val)
			if got != tt.want {
				t.Fatalf("fclassD(%v): got 0x%x, want 0x%x", tt.val, got, tt.want)
			}
		})
	}
}

func TestFMV_X_W(t *testing.T) {
	mem := mmu.New()
	c := New(mem)

	c.writeFS(1, 1.0) // 1.0f = 0x3F800000

	// FMV.X.W x5, f1 → funct7=0x70, rs2=0, funct3=0
	instr := encodeR(0x70, 0, 1, 0, 5, 0x53)
	mem.MapRange(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	fpuWriteInstr(mem, 0, instr)
	c.PC = 0
	err := c.Step()
	if err != nil {
		t.Fatal(err)
	}

	got := c.readReg(5)
	expected := uint64(0x3F800000)
	if got != expected {
		t.Fatalf("FMV.X.W: expected 0x%x, got 0x%x", expected, got)
	}
}

func TestNaNBoxing(t *testing.T) {
	mem := mmu.New()
	c := New(mem)

	// Write raw 64-bit value that's NOT properly NaN-boxed
	c.fpu.F[5] = 0x0000000040000000

	val := c.readFS(5)
	if !math.IsNaN(float64(val)) {
		t.Fatalf("Expected canonical NaN for unboxed value, got %f", val)
	}
}

// --- CSR tests ---

func TestCSR_FCSR(t *testing.T) {
	mem := mmu.New()
	c := New(mem)
	mem.MapRange(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)

	c.fpu.FCSR = 0x15

	// CSRRS x5, fcsr(0x003), x0
	instr := (0x003 << 20) | (0 << 15) | (2 << 12) | (5 << 7) | 0x73
	fpuWriteInstr(mem, 0, uint32(instr))
	c.PC = 0
	err := c.Step()
	if err != nil {
		t.Fatal(err)
	}

	if c.readReg(5) != 0x15 {
		t.Fatalf("CSR read FCSR: expected 0x15, got 0x%x", c.readReg(5))
	}
}

func TestCSR_ReadTime(t *testing.T) {
	mem := mmu.New()
	c := New(mem)
	mem.MapRange(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)

	// CSRRS x5, time(0xC01), x0
	instr := (0xC01 << 20) | (0 << 15) | (2 << 12) | (5 << 7) | 0x73
	fpuWriteInstr(mem, 0, uint32(instr))
	c.PC = 0
	err := c.Step()
	if err != nil {
		t.Fatal(err)
	}

	if c.readReg(5) == 0 {
		t.Fatal("CSR TIME: expected non-zero value")
	}
}

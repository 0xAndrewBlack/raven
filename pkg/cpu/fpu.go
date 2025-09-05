package cpu

import (
	"fmt"
	"math"
)

// FPU state attached to the CPU.
// F registers are stored as uint64 - the raw IEEE 754 bits.
// For single-precision, the upper 32 bits are NaN-boxed (all 1s).
type FPU struct {
	F    [32]uint64 // f0-f31
	FCSR uint32     // fflags[4:0] | frm[7:5]
}

// Rounding modes
const (
	RNE uint32 = 0 // Round to Nearest, ties to Even
	RTZ uint32 = 1 // Round towards Zero
	RDN uint32 = 2 // Round Down (towards -inf)
	RUP uint32 = 3 // Round Up (towards +inf)
	RMM uint32 = 4 // Round to Nearest, ties to Max Magnitude
)

// Exception flags
const (
	FlagNX uint32 = 1 << 0 // Inexact
	FlagUF uint32 = 1 << 1 // Underflow
	FlagOF uint32 = 1 << 2 // Overflow
	FlagDZ uint32 = 1 << 3 // Divide by Zero
	FlagNV uint32 = 1 << 4 // Invalid Operation
)

func (f *FPU) fflags() uint32     { return f.FCSR & 0x1F }
func (f *FPU) frm() uint32        { return (f.FCSR >> 5) & 0x7 }
func (f *FPU) setFlags(fl uint32) { f.FCSR |= fl & 0x1F }

// NaN-boxing helpers: single-precision values in F regs must have upper 32 bits = all 1s.
func nanBoxS(v uint32) uint64 {
	return 0xFFFFFFFF00000000 | uint64(v)
}

func unboxS(v uint64) float32 {
	if v>>32 != 0xFFFFFFFF {
		return float32(math.NaN()) // not properly NaN-boxed → canonical NaN
	}
	return math.Float32frombits(uint32(v))
}

func f64bits(f float64) uint64  { return math.Float64bits(f) }
func f64from(b uint64) float64  { return math.Float64frombits(b) }
func f32bits(f float32) uint32  { return math.Float32bits(f) }
func f32from(b uint32) float32  { return math.Float32frombits(b) }

// readFS reads a single-precision value from register.
func (c *CPU) readFS(r uint32) float32 { return unboxS(c.fpu.F[r]) }

// writeFS writes a single-precision value, NaN-boxed.
func (c *CPU) writeFS(r uint32, v float32) { c.fpu.F[r] = nanBoxS(f32bits(v)) }

// readFD reads a double-precision value.
func (c *CPU) readFD(r uint32) float64 { return f64from(c.fpu.F[r]) }

// writeFD writes a double-precision value.
func (c *CPU) writeFD(r uint32, v float64) { c.fpu.F[r] = f64bits(v) }

// --- Opcode 0x07: FP Loads ---

func (c *CPU) execFPLoad(instr uint32) error {
	rd := (instr >> 7) & 0x1F
	rs1 := (instr >> 15) & 0x1F
	funct3 := (instr >> 12) & 0x7
	imm := signExtend(uint64(instr>>20), 12)
	addr := c.readReg(rs1) + uint64(imm)

	switch funct3 {
	case 0x2: // FLW
		val, err := c.Mem.Read32(addr)
		if err != nil {
			return err
		}
		c.fpu.F[rd] = nanBoxS(val)
	case 0x3: // FLD
		val, err := c.Mem.Read64(addr)
		if err != nil {
			return err
		}
		c.fpu.F[rd] = val
	default:
		return fmt.Errorf("unknown FP load funct3=0x%x at PC=0x%x", funct3, c.PC)
	}

	c.PC += 4
	return nil
}

// --- Opcode 0x27: FP Stores ---

func (c *CPU) execFPStore(instr uint32) error {
	rs1 := (instr >> 15) & 0x1F
	rs2 := (instr >> 20) & 0x1F
	funct3 := (instr >> 12) & 0x7
	imm := immS(instr)
	addr := c.readReg(rs1) + uint64(imm)

	switch funct3 {
	case 0x2: // FSW
		if err := c.Mem.Write32(addr, uint32(c.fpu.F[rs2])); err != nil {
			return err
		}
	case 0x3: // FSD
		if err := c.Mem.Write64(addr, c.fpu.F[rs2]); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown FP store funct3=0x%x at PC=0x%x", funct3, c.PC)
	}

	c.PC += 4
	return nil
}

// --- Opcode 0x53: FP computational ---

func (c *CPU) execFPOp(instr uint32) error {
	funct7 := instr >> 25
	rs1 := (instr >> 15) & 0x1F
	rs2 := (instr >> 20) & 0x1F
	rd := (instr >> 7) & 0x1F
	rm := (instr >> 12) & 0x7 // rounding mode (7 = dynamic → use frm)

	_ = rm // we use Go's default rounding for now

	switch funct7 {
	// --- Single-precision ---
	case 0x00: // FADD.S
		r := c.readFS(rs1) + c.readFS(rs2)
		c.writeFS(rd, r)
	case 0x04: // FSUB.S
		r := c.readFS(rs1) - c.readFS(rs2)
		c.writeFS(rd, r)
	case 0x08: // FMUL.S
		r := c.readFS(rs1) * c.readFS(rs2)
		c.writeFS(rd, r)
	case 0x0C: // FDIV.S
		a, b := c.readFS(rs1), c.readFS(rs2)
		if b == 0 {
			c.fpu.setFlags(FlagDZ)
		}
		c.writeFS(rd, a/b)
	case 0x2C: // FSQRT.S
		a := c.readFS(rs1)
		if a < 0 {
			c.fpu.setFlags(FlagNV)
		}
		c.writeFS(rd, float32(math.Sqrt(float64(a))))
	case 0x10: // FSGNJ*.S
		c.execFsgnjS(instr, rs1, rs2, rd)
	case 0x14: // FMIN/FMAX.S
		c.execFminmaxS(instr, rs1, rs2, rd)
	case 0x50: // FEQ/FLT/FLE.S (comparison → integer rd)
		c.execFcmpS(instr, rs1, rs2, rd)
	case 0x60: // FCVT.W.S / FCVT.WU.S / FCVT.L.S / FCVT.LU.S
		c.execFcvtFromS(instr, rs1, rd)
	case 0x68: // FCVT.S.W / FCVT.S.WU / FCVT.S.L / FCVT.S.LU
		c.execFcvtToS(instr, rs1, rd)
	case 0x70: // FMV.X.W / FCLASS.S
		funct3 := (instr >> 12) & 0x7
		if funct3 == 0 {
			// FMV.X.W: move bits from f[rs1] to x[rd], sign-extended
			bits := uint32(c.fpu.F[rs1])
			c.writeReg(rd, uint64(int64(int32(bits))))
		} else {
			// FCLASS.S
			c.writeReg(rd, fclassS(c.readFS(rs1)))
		}
	case 0x78: // FMV.W.X: move bits from x[rs1] to f[rd]
		c.fpu.F[rd] = nanBoxS(uint32(c.readReg(rs1)))

	// --- Double-precision ---
	case 0x01: // FADD.D
		r := c.readFD(rs1) + c.readFD(rs2)
		c.writeFD(rd, r)
	case 0x05: // FSUB.D
		r := c.readFD(rs1) - c.readFD(rs2)
		c.writeFD(rd, r)
	case 0x09: // FMUL.D
		r := c.readFD(rs1) * c.readFD(rs2)
		c.writeFD(rd, r)
	case 0x0D: // FDIV.D
		a, b := c.readFD(rs1), c.readFD(rs2)
		if b == 0 {
			c.fpu.setFlags(FlagDZ)
		}
		c.writeFD(rd, a/b)
	case 0x2D: // FSQRT.D
		a := c.readFD(rs1)
		if a < 0 {
			c.fpu.setFlags(FlagNV)
		}
		c.writeFD(rd, math.Sqrt(a))
	case 0x11: // FSGNJ*.D
		c.execFsgnjD(instr, rs1, rs2, rd)
	case 0x15: // FMIN/FMAX.D
		c.execFminmaxD(instr, rs1, rs2, rd)
	case 0x51: // FEQ/FLT/FLE.D
		c.execFcmpD(instr, rs1, rs2, rd)
	case 0x61: // FCVT.W.D / FCVT.WU.D / FCVT.L.D / FCVT.LU.D
		c.execFcvtFromD(instr, rs1, rd)
	case 0x69: // FCVT.D.W / FCVT.D.WU / FCVT.D.L / FCVT.D.LU
		c.execFcvtToD(instr, rs1, rd)
	case 0x71: // FMV.X.D / FCLASS.D
		funct3 := (instr >> 12) & 0x7
		if funct3 == 0 {
			c.writeReg(rd, c.fpu.F[rs1]) // FMV.X.D
		} else {
			c.writeReg(rd, fclassD(c.readFD(rs1))) // FCLASS.D
		}
	case 0x79: // FMV.D.X
		c.fpu.F[rd] = c.readReg(rs1)
	case 0x20: // FCVT.S.D
		c.writeFS(rd, float32(c.readFD(rs1)))
	case 0x21: // FCVT.D.S
		c.writeFD(rd, float64(c.readFS(rs1)))

	default:
		return fmt.Errorf("unimplemented FP funct7=0x%02x at PC=0x%x (instr=0x%08x)", funct7, c.PC, instr)
	}

	c.PC += 4
	return nil
}

// --- FMADD/FMSUB/FNMSUB/FNMADD (opcodes 0x43, 0x47, 0x4B, 0x4F) ---

func (c *CPU) execFPFused(instr uint32, opcode uint32) error {
	rd := (instr >> 7) & 0x1F
	rs1 := (instr >> 15) & 0x1F
	rs2 := (instr >> 20) & 0x1F
	rs3 := (instr >> 27) & 0x1F
	fmt2 := (instr >> 25) & 0x3 // 0=S, 1=D

	if fmt2 == 0 { // single-precision
		a := float64(c.readFS(rs1))
		b := float64(c.readFS(rs2))
		d := float64(c.readFS(rs3))
		var r float64
		switch opcode {
		case 0x43: // FMADD.S
			r = a*b + d
		case 0x47: // FMSUB.S
			r = a*b - d
		case 0x4B: // FNMSUB.S
			r = -(a*b) + d
		case 0x4F: // FNMADD.S
			r = -(a*b) - d
		}
		c.writeFS(rd, float32(r))
	} else { // double-precision
		a := c.readFD(rs1)
		b := c.readFD(rs2)
		d := c.readFD(rs3)
		var r float64
		switch opcode {
		case 0x43:
			r = math.FMA(a, b, d)
		case 0x47:
			r = math.FMA(a, b, -d)
		case 0x4B:
			r = math.FMA(-a, b, d)
		case 0x4F:
			r = math.FMA(-a, b, -d)
		}
		c.writeFD(rd, r)
	}

	c.PC += 4
	return nil
}

// --- Sign injection (FSGNJ, FSGNJN, FSGNJX) ---

func (c *CPU) execFsgnjS(instr uint32, rs1, rs2, rd uint32) {
	funct3 := (instr >> 12) & 0x7
	a := f32bits(c.readFS(rs1))
	b := f32bits(c.readFS(rs2))
	var r uint32
	switch funct3 {
	case 0: // FSGNJ.S
		r = (a & 0x7FFFFFFF) | (b & 0x80000000)
	case 1: // FSGNJN.S
		r = (a & 0x7FFFFFFF) | (^b & 0x80000000)
	case 2: // FSGNJX.S
		r = a ^ (b & 0x80000000)
	}
	c.writeFS(rd, f32from(r))
}

func (c *CPU) execFsgnjD(instr uint32, rs1, rs2, rd uint32) {
	funct3 := (instr >> 12) & 0x7
	a := c.fpu.F[rs1]
	b := c.fpu.F[rs2]
	var r uint64
	switch funct3 {
	case 0:
		r = (a & 0x7FFFFFFFFFFFFFFF) | (b & 0x8000000000000000)
	case 1:
		r = (a & 0x7FFFFFFFFFFFFFFF) | (^b & 0x8000000000000000)
	case 2:
		r = a ^ (b & 0x8000000000000000)
	}
	c.fpu.F[rd] = r
}

// --- Min/Max ---

func (c *CPU) execFminmaxS(instr uint32, rs1, rs2, rd uint32) {
	funct3 := (instr >> 12) & 0x7
	a, b := c.readFS(rs1), c.readFS(rs2)
	aNaN, bNaN := math.IsNaN(float64(a)), math.IsNaN(float64(b))
	if aNaN && bNaN {
		c.writeFS(rd, float32(math.NaN()))
		c.fpu.setFlags(FlagNV)
		return
	}
	if aNaN {
		c.writeFS(rd, b)
		return
	}
	if bNaN {
		c.writeFS(rd, a)
		return
	}
	switch funct3 {
	case 0: // FMIN.S
		if a < b || (a == 0 && b == 0 && math.Signbit(float64(a))) {
			c.writeFS(rd, a)
		} else {
			c.writeFS(rd, b)
		}
	case 1: // FMAX.S
		if a > b || (a == 0 && b == 0 && !math.Signbit(float64(a))) {
			c.writeFS(rd, a)
		} else {
			c.writeFS(rd, b)
		}
	}
}

func (c *CPU) execFminmaxD(instr uint32, rs1, rs2, rd uint32) {
	funct3 := (instr >> 12) & 0x7
	a, b := c.readFD(rs1), c.readFD(rs2)
	aNaN, bNaN := math.IsNaN(a), math.IsNaN(b)
	if aNaN && bNaN {
		c.writeFD(rd, math.NaN())
		c.fpu.setFlags(FlagNV)
		return
	}
	if aNaN {
		c.writeFD(rd, b)
		return
	}
	if bNaN {
		c.writeFD(rd, a)
		return
	}
	switch funct3 {
	case 0:
		if a < b || (a == 0 && b == 0 && math.Signbit(a)) {
			c.writeFD(rd, a)
		} else {
			c.writeFD(rd, b)
		}
	case 1:
		if a > b || (a == 0 && b == 0 && !math.Signbit(a)) {
			c.writeFD(rd, a)
		} else {
			c.writeFD(rd, b)
		}
	}
}

// --- Compare → integer ---

func (c *CPU) execFcmpS(instr uint32, rs1, rs2, rd uint32) {
	funct3 := (instr >> 12) & 0x7
	a, b := c.readFS(rs1), c.readFS(rs2)
	var r uint64
	switch funct3 {
	case 0: // FLE.S
		if math.IsNaN(float64(a)) || math.IsNaN(float64(b)) {
			c.fpu.setFlags(FlagNV)
		} else if a <= b {
			r = 1
		}
	case 1: // FLT.S
		if math.IsNaN(float64(a)) || math.IsNaN(float64(b)) {
			c.fpu.setFlags(FlagNV)
		} else if a < b {
			r = 1
		}
	case 2: // FEQ.S
		if !math.IsNaN(float64(a)) && !math.IsNaN(float64(b)) && a == b {
			r = 1
		}
	}
	c.writeReg(rd, r)
}

func (c *CPU) execFcmpD(instr uint32, rs1, rs2, rd uint32) {
	funct3 := (instr >> 12) & 0x7
	a, b := c.readFD(rs1), c.readFD(rs2)
	var r uint64
	switch funct3 {
	case 0: // FLE.D
		if math.IsNaN(a) || math.IsNaN(b) {
			c.fpu.setFlags(FlagNV)
		} else if a <= b {
			r = 1
		}
	case 1: // FLT.D
		if math.IsNaN(a) || math.IsNaN(b) {
			c.fpu.setFlags(FlagNV)
		} else if a < b {
			r = 1
		}
	case 2: // FEQ.D
		if !math.IsNaN(a) && !math.IsNaN(b) && a == b {
			r = 1
		}
	}
	c.writeReg(rd, r)
}

// --- Float → Int conversions ---

func (c *CPU) execFcvtFromS(instr uint32, rs1, rd uint32) {
	rs2field := (instr >> 20) & 0x1F
	a := float64(c.readFS(rs1))
	var r uint64
	switch rs2field {
	case 0: // FCVT.W.S
		r = uint64(int64(int32(clampToI32(a, &c.fpu))))
	case 1: // FCVT.WU.S
		r = uint64(int64(int32(clampToU32(a, &c.fpu))))
	case 2: // FCVT.L.S
		r = uint64(clampToI64(a, &c.fpu))
	case 3: // FCVT.LU.S
		r = clampToU64(a, &c.fpu)
	}
	c.writeReg(rd, r)
}

func (c *CPU) execFcvtToS(instr uint32, rs1, rd uint32) {
	rs2field := (instr >> 20) & 0x1F
	switch rs2field {
	case 0: // FCVT.S.W
		c.writeFS(rd, float32(int32(c.readReg(rs1))))
	case 1: // FCVT.S.WU
		c.writeFS(rd, float32(uint32(c.readReg(rs1))))
	case 2: // FCVT.S.L
		c.writeFS(rd, float32(int64(c.readReg(rs1))))
	case 3: // FCVT.S.LU
		c.writeFS(rd, float32(c.readReg(rs1)))
	}
}

func (c *CPU) execFcvtFromD(instr uint32, rs1, rd uint32) {
	rs2field := (instr >> 20) & 0x1F
	a := c.readFD(rs1)
	var r uint64
	switch rs2field {
	case 0: // FCVT.W.D
		r = uint64(int64(int32(clampToI32(a, &c.fpu))))
	case 1: // FCVT.WU.D
		r = uint64(int64(int32(clampToU32(a, &c.fpu))))
	case 2: // FCVT.L.D
		r = uint64(clampToI64(a, &c.fpu))
	case 3: // FCVT.LU.D
		r = clampToU64(a, &c.fpu)
	}
	c.writeReg(rd, r)
}

func (c *CPU) execFcvtToD(instr uint32, rs1, rd uint32) {
	rs2field := (instr >> 20) & 0x1F
	switch rs2field {
	case 0: // FCVT.D.W
		c.writeFD(rd, float64(int32(c.readReg(rs1))))
	case 1: // FCVT.D.WU
		c.writeFD(rd, float64(uint32(c.readReg(rs1))))
	case 2: // FCVT.D.L
		c.writeFD(rd, float64(int64(c.readReg(rs1))))
	case 3: // FCVT.D.LU
		c.writeFD(rd, float64(c.readReg(rs1)))
	}
}

// --- FCLASS ---

func fclassS(f float32) uint64 {
	bits := f32bits(f)
	sign := bits >> 31
	exp := (bits >> 23) & 0xFF
	frac := bits & 0x7FFFFF

	if exp == 0xFF {
		if frac != 0 {
			if frac&(1<<22) != 0 {
				return 1 << 9 // quiet NaN
			}
			return 1 << 8 // signaling NaN
		}
		if sign != 0 {
			return 1 << 0 // -inf
		}
		return 1 << 7 // +inf
	}
	if exp == 0 {
		if frac == 0 {
			if sign != 0 {
				return 1 << 3 // -0
			}
			return 1 << 4 // +0
		}
		if sign != 0 {
			return 1 << 2 // -subnormal
		}
		return 1 << 5 // +subnormal
	}
	if sign != 0 {
		return 1 << 1 // -normal
	}
	return 1 << 6 // +normal
}

func fclassD(f float64) uint64 {
	bits := f64bits(f)
	sign := bits >> 63
	exp := (bits >> 52) & 0x7FF
	frac := bits & 0xFFFFFFFFFFFFF

	if exp == 0x7FF {
		if frac != 0 {
			if frac&(1<<51) != 0 {
				return 1 << 9
			}
			return 1 << 8
		}
		if sign != 0 {
			return 1 << 0
		}
		return 1 << 7
	}
	if exp == 0 {
		if frac == 0 {
			if sign != 0 {
				return 1 << 3
			}
			return 1 << 4
		}
		if sign != 0 {
			return 1 << 2
		}
		return 1 << 5
	}
	if sign != 0 {
		return 1 << 1
	}
	return 1 << 6
}

// --- Clamping helpers for float→int ---

func clampToI32(f float64, fpu *FPU) int32 {
	if math.IsNaN(f) {
		fpu.setFlags(FlagNV)
		return math.MaxInt32
	}
	if f >= float64(math.MaxInt32) {
		fpu.setFlags(FlagNV)
		return math.MaxInt32
	}
	if f <= float64(math.MinInt32) {
		fpu.setFlags(FlagNV)
		return math.MinInt32
	}
	return int32(f)
}

func clampToU32(f float64, fpu *FPU) uint32 {
	if math.IsNaN(f) || f < 0 {
		fpu.setFlags(FlagNV)
		if math.IsNaN(f) {
			return math.MaxUint32
		}
		return 0
	}
	if f >= float64(math.MaxUint32) {
		fpu.setFlags(FlagNV)
		return math.MaxUint32
	}
	return uint32(f)
}

func clampToI64(f float64, fpu *FPU) int64 {
	if math.IsNaN(f) {
		fpu.setFlags(FlagNV)
		return math.MaxInt64
	}
	if f >= float64(math.MaxInt64) {
		fpu.setFlags(FlagNV)
		return math.MaxInt64
	}
	if f <= float64(math.MinInt64) {
		fpu.setFlags(FlagNV)
		return math.MinInt64
	}
	return int64(f)
}

func clampToU64(f float64, fpu *FPU) uint64 {
	if math.IsNaN(f) || f < 0 {
		fpu.setFlags(FlagNV)
		if math.IsNaN(f) {
			return math.MaxUint64
		}
		return 0
	}
	if f >= float64(math.MaxUint64) {
		fpu.setFlags(FlagNV)
		return math.MaxUint64
	}
	return uint64(f)
}

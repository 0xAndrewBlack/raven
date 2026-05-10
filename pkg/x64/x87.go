package x64

import (
	"math"
)

// x87 FPU state embedded in CPU.
// ST(0)-ST(7) are a circular stack, fpuTop indexes ST(0).
// CW = control word, SW = status word.

// fpuInit initializes the FPU to its default state (as after FINIT).
func (c *CPU) fpuInit() {
	c.fpuCW = 0x037F // all exceptions masked, double precision, round to nearest
	c.fpuSW = 0
	c.fpuTop = 0
	c.fpuTW = 0xFFFF // all registers empty
	for i := range c.fpuST {
		c.fpuST[i] = 0
	}
}

// fpuPhys converts a logical ST(i) index to a physical register index.
func (c *CPU) fpuPhys(i int) int {
	return (c.fpuTop + i) & 7
}

// fpuPush pushes a value onto the FPU stack.
func (c *CPU) fpuPush(val float64) {
	c.fpuTop = (c.fpuTop - 1) & 7
	c.fpuST[c.fpuTop] = val
	// Mark register as valid (clear the 2-bit tag for this register)
	c.fpuTW &^= 3 << (uint(c.fpuTop) * 2)
}

// fpuPop pops the top of the FPU stack.
func (c *CPU) fpuPop() float64 {
	val := c.fpuST[c.fpuTop]
	// Mark register as empty
	c.fpuTW |= 3 << (uint(c.fpuTop) * 2)
	c.fpuTop = (c.fpuTop + 1) & 7
	return val
}

// fpuST0 returns ST(0).
func (c *CPU) fpuST0() float64 {
	return c.fpuST[c.fpuTop]
}

// fpuSTi returns ST(i).
func (c *CPU) fpuSTi(i int) float64 {
	return c.fpuST[c.fpuPhys(i)]
}

// fpuSetSTi sets ST(i).
func (c *CPU) fpuSetSTi(i int, val float64) {
	c.fpuST[c.fpuPhys(i)] = val
}

// fpuSetST0 sets ST(0).
func (c *CPU) fpuSetST0(val float64) {
	c.fpuST[c.fpuTop] = val
}

// fpuUpdateSW sets the C0-C3 condition code bits from a comparison result.
// cmp: -1 (less), 0 (equal), +1 (greater), 2 (unordered/NaN)
func (c *CPU) fpuSetCC(cmp int) {
	c.fpuSW &^= 0x4500 // clear C0, C2, C3
	switch cmp {
	case -1: // ST(0) < source
		c.fpuSW |= 0x0100 // C0=1
	case 0: // ST(0) == source
		c.fpuSW |= 0x4000 // C3=1
	case 1: // ST(0) > source
		// C0=C2=C3=0 (already cleared)
	default: // unordered (NaN)
		c.fpuSW |= 0x4500 // C0=C2=C3=1
	}
}

// fpuCompare compares two float64 values, returning -1, 0, 1, or 2 for NaN.
func fpuCompare(a, b float64) int {
	if math.IsNaN(a) || math.IsNaN(b) {
		return 2
	}
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

// fpuReadMem32 reads a 32-bit float from guest memory.
func (c *CPU) fpuReadMem32(addr uint64) float64 {
	v, _ := c.mem.Read32(addr)
	return float64(math.Float32frombits(v))
}

// fpuReadMem64 reads a 64-bit float from guest memory.
func (c *CPU) fpuReadMem64(addr uint64) float64 {
	v, _ := c.mem.Read64(addr)
	return math.Float64frombits(v)
}

// fpuReadMemInt16 reads a 16-bit signed integer from guest memory.
func (c *CPU) fpuReadMemInt16(addr uint64) float64 {
	v, _ := c.mem.Read16(addr)
	return float64(int16(v))
}

// fpuReadMemInt32 reads a 32-bit signed integer from guest memory.
func (c *CPU) fpuReadMemInt32(addr uint64) float64 {
	v, _ := c.mem.Read32(addr)
	return float64(int32(v))
}

// fpuReadMemInt64 reads a 64-bit signed integer from guest memory.
func (c *CPU) fpuReadMemInt64(addr uint64) float64 {
	v, _ := c.mem.Read64(addr)
	return float64(int64(v))
}

// execX87 dispatches x87 FPU opcodes 0xD8-0xDF.
func (c *CPU) execX87(op byte, pfx *prefixState) error {
	m, err := c.decodeModRM(pfx)
	if err != nil {
		return err
	}
	c.recordX87Opcode(op, m.raw)

	// Memory vs register form
	if m.mod != 3 {
		addr, _, err := c.resolveRMAddr(m, pfx)
		if err != nil {
			return err
		}
		return c.execX87mem(op, m.reg, addr)
	}
	return c.execX87reg(op, m.reg, m.rm)
}

// execX87mem handles x87 ops with memory operand.
func (c *CPU) execX87mem(op byte, reg int, addr uint64) error {
	switch op {
	case 0xD8: // float32 arithmetic
		val := c.fpuReadMem32(addr)
		switch reg {
		case 0: // FADD m32
			c.fpuSetST0(c.fpuST0() + val)
		case 1: // FMUL m32
			c.fpuSetST0(c.fpuST0() * val)
		case 2: // FCOM m32
			c.fpuSetCC(fpuCompare(c.fpuST0(), val))
		case 3: // FCOMP m32
			c.fpuSetCC(fpuCompare(c.fpuST0(), val))
			c.fpuPop()
		case 4: // FSUB m32
			c.fpuSetST0(c.fpuST0() - val)
		case 5: // FSUBR m32
			c.fpuSetST0(val - c.fpuST0())
		case 6: // FDIV m32
			c.fpuSetST0(c.fpuST0() / val)
		case 7: // FDIVR m32
			c.fpuSetST0(val / c.fpuST0())
		}
	case 0xD9: // load/store/control float32
		switch reg {
		case 0: // FLD m32
			c.fpuPush(c.fpuReadMem32(addr))
		case 2: // FST m32
			c.mem.Write32(addr, math.Float32bits(float32(c.fpuST0())))
		case 3: // FSTP m32
			c.mem.Write32(addr, math.Float32bits(float32(c.fpuST0())))
			c.fpuPop()
		case 4: // FLDENV
			// skip - rarely used
		case 5: // FLDCW m16
			v, _ := c.mem.Read16(addr)
			c.fpuCW = v
		case 6: // FNSTENV
			// skip
		case 7: // FNSTCW m16
			c.mem.Write16(addr, c.fpuCW)
		}
	case 0xDA: // int32 arithmetic
		val := c.fpuReadMemInt32(addr)
		switch reg {
		case 0: // FIADD m32
			c.fpuSetST0(c.fpuST0() + val)
		case 1: // FIMUL m32
			c.fpuSetST0(c.fpuST0() * val)
		case 2: // FICOM m32
			c.fpuSetCC(fpuCompare(c.fpuST0(), val))
		case 3: // FICOMP m32
			c.fpuSetCC(fpuCompare(c.fpuST0(), val))
			c.fpuPop()
		case 4: // FISUB m32
			c.fpuSetST0(c.fpuST0() - val)
		case 5: // FISUBR m32
			c.fpuSetST0(val - c.fpuST0())
		case 6: // FIDIV m32
			c.fpuSetST0(c.fpuST0() / val)
		case 7: // FIDIVR m32
			c.fpuSetST0(val / c.fpuST0())
		}
	case 0xDB:
		switch reg {
		case 0: // FILD m32
			c.fpuPush(c.fpuReadMemInt32(addr))
		case 1: // FISTTP m32
			v := int32(c.fpuST0())
			c.mem.Write32(addr, uint32(v))
			c.fpuPop()
		case 2: // FIST m32
			v := fpuRoundToInt(c.fpuST0(), c.fpuCW)
			c.mem.Write32(addr, uint32(int32(v)))
		case 3: // FISTP m32
			v := fpuRoundToInt(c.fpuST0(), c.fpuCW)
			c.mem.Write32(addr, uint32(int32(v)))
			c.fpuPop()
		case 5: // FLD m80 (extended precision - load as float64)
			lo, _ := c.mem.Read64(addr)
			hi, _ := c.mem.Read16(addr + 8)
			c.fpuPush(float80ToFloat64(lo, hi))
		case 7: // FSTP m80 (store extended)
			lo, hi := float64ToFloat80(c.fpuST0())
			c.mem.Write64(addr, lo)
			c.mem.Write16(addr+8, hi)
			c.fpuPop()
		}
	case 0xDC: // float64 arithmetic
		val := c.fpuReadMem64(addr)
		switch reg {
		case 0: // FADD m64
			c.fpuSetST0(c.fpuST0() + val)
		case 1: // FMUL m64
			c.fpuSetST0(c.fpuST0() * val)
		case 2: // FCOM m64
			c.fpuSetCC(fpuCompare(c.fpuST0(), val))
		case 3: // FCOMP m64
			c.fpuSetCC(fpuCompare(c.fpuST0(), val))
			c.fpuPop()
		case 4: // FSUB m64
			c.fpuSetST0(c.fpuST0() - val)
		case 5: // FSUBR m64
			c.fpuSetST0(val - c.fpuST0())
		case 6: // FDIV m64
			c.fpuSetST0(c.fpuST0() / val)
		case 7: // FDIVR m64
			c.fpuSetST0(val / c.fpuST0())
		}
	case 0xDD:
		switch reg {
		case 0: // FLD m64
			c.fpuPush(c.fpuReadMem64(addr))
		case 1: // FISTTP m64
			v := int64(c.fpuST0())
			c.mem.Write64(addr, uint64(v))
			c.fpuPop()
		case 2: // FST m64
			c.mem.Write64(addr, math.Float64bits(c.fpuST0()))
		case 3: // FSTP m64
			c.mem.Write64(addr, math.Float64bits(c.fpuST0()))
			c.fpuPop()
		case 4: // FRSTOR
			// skip
		case 6: // FNSAVE
			// skip
		case 7: // FNSTSW m16
			sw := c.fpuSW | uint16(c.fpuTop<<11)
			c.mem.Write16(addr, sw)
		}
	case 0xDE: // int16 arithmetic + special
		val := c.fpuReadMemInt16(addr)
		switch reg {
		case 0: // FIADD m16
			c.fpuSetST0(c.fpuST0() + val)
		case 1: // FIMUL m16
			c.fpuSetST0(c.fpuST0() * val)
		case 2: // FICOM m16
			c.fpuSetCC(fpuCompare(c.fpuST0(), val))
		case 3: // FICOMP m16
			c.fpuSetCC(fpuCompare(c.fpuST0(), val))
			c.fpuPop()
		case 4: // FISUB m16
			c.fpuSetST0(c.fpuST0() - val)
		case 5: // FISUBR m16
			c.fpuSetST0(val - c.fpuST0())
		case 6: // FIDIV m16
			c.fpuSetST0(c.fpuST0() / val)
		case 7: // FIDIVR m16
			c.fpuSetST0(val / c.fpuST0())
		}
	case 0xDF:
		switch reg {
		case 0: // FILD m16
			c.fpuPush(c.fpuReadMemInt16(addr))
		case 1: // FISTTP m16
			v := int16(c.fpuST0())
			c.mem.Write16(addr, uint16(v))
			c.fpuPop()
		case 2: // FIST m16
			v := fpuRoundToInt(c.fpuST0(), c.fpuCW)
			c.mem.Write16(addr, uint16(int16(v)))
		case 3: // FISTP m16
			v := fpuRoundToInt(c.fpuST0(), c.fpuCW)
			c.mem.Write16(addr, uint16(int16(v)))
			c.fpuPop()
		case 5: // FILD m64
			c.fpuPush(c.fpuReadMemInt64(addr))
		case 7: // FISTP m64
			v := fpuRoundToInt(c.fpuST0(), c.fpuCW)
			c.mem.Write64(addr, uint64(v))
			c.fpuPop()
		}
	}
	return nil
}

// execX87reg handles x87 ops with register operand (mod==3).
func (c *CPU) execX87reg(op byte, reg int, rm int) error {
	i := rm // ST(i)
	switch op {
	case 0xD8: // register arithmetic: ST(0) op= ST(i)
		switch reg {
		case 0: // FADD ST(0), ST(i)
			c.fpuSetST0(c.fpuST0() + c.fpuSTi(i))
		case 1: // FMUL ST(0), ST(i)
			c.fpuSetST0(c.fpuST0() * c.fpuSTi(i))
		case 2: // FCOM ST(i)
			c.fpuSetCC(fpuCompare(c.fpuST0(), c.fpuSTi(i)))
		case 3: // FCOMP ST(i)
			c.fpuSetCC(fpuCompare(c.fpuST0(), c.fpuSTi(i)))
			c.fpuPop()
		case 4: // FSUB ST(0), ST(i)
			c.fpuSetST0(c.fpuST0() - c.fpuSTi(i))
		case 5: // FSUBR ST(0), ST(i)
			c.fpuSetST0(c.fpuSTi(i) - c.fpuST0())
		case 6: // FDIV ST(0), ST(i)
			c.fpuSetST0(c.fpuST0() / c.fpuSTi(i))
		case 7: // FDIVR ST(0), ST(i)
			c.fpuSetST0(c.fpuSTi(i) / c.fpuST0())
		}
	case 0xD9:
		switch {
		case reg == 0: // FLD ST(i)
			c.fpuPush(c.fpuSTi(i))
		case reg == 1 && i == 0: // FXCH ST(0) (nop)
		case reg == 1: // FXCH ST(i)
			c.fpuST[c.fpuPhys(0)], c.fpuST[c.fpuPhys(i)] = c.fpuST[c.fpuPhys(i)], c.fpuST[c.fpuPhys(0)]
		case reg == 4 && i == 0: // FCHS (D9 E0)
			c.fpuSetST0(-c.fpuST0())
		case reg == 4 && i == 1: // FABS (D9 E1)
			c.fpuSetST0(math.Abs(c.fpuST0()))
		case reg == 4 && i == 4: // FTST (D9 E4)
			c.fpuSetCC(fpuCompare(c.fpuST0(), 0))
		case reg == 4 && i == 5: // FXAM (D9 E5)
			val := c.fpuST0()
			c.fpuSW &^= 0x4700
			if math.IsNaN(val) {
				c.fpuSW |= 0x0100 // C0=1 → NaN
			} else if math.IsInf(val, 0) {
				c.fpuSW |= 0x0500 // C0=C2=1 → infinity
			} else if val == 0 {
				c.fpuSW |= 0x4000 // C3=1 → zero
			} else {
				c.fpuSW |= 0x0400 // C2=1 → normal
			}
			if math.Signbit(val) {
				c.fpuSW |= 0x0200 // C1=1 → negative
			}
		case reg == 5 && i == 0: // FLD1 (D9 E8)
			c.fpuPush(1.0)
		case reg == 5 && i == 1: // FLDL2T (D9 E9)
			c.fpuPush(math.Log2(10))
		case reg == 5 && i == 2: // FLDL2E (D9 EA)
			c.fpuPush(math.Log2E)
		case reg == 5 && i == 3: // FLDPI (D9 EB)
			c.fpuPush(math.Pi)
		case reg == 5 && i == 4: // FLDLN2 (D9 EC)
			c.fpuPush(math.Ln2)
		case reg == 5 && i == 5: // FLDLG2 (D9 ED)
			c.fpuPush(math.Log10(2))
		case reg == 5 && i == 6: // FLDZ (D9 EE)
			c.fpuPush(0)
		case reg == 6 && i == 0: // F2XM1 (D9 F0)
			c.fpuSetST0(math.Exp2(c.fpuST0()) - 1)
		case reg == 6 && i == 1: // FYL2X (D9 F1)
			y := c.fpuSTi(1)
			x := c.fpuST0()
			c.fpuPop()
			c.fpuSetST0(y * math.Log2(x))
		case reg == 6 && i == 2: // FPTAN
			c.fpuSetST0(math.Tan(c.fpuST0()))
			c.fpuPush(1.0)
		case reg == 6 && i == 3: // FPATAN: ST(1) = atan2(ST(1), ST(0)), pop
			y := c.fpuSTi(1)
			x := c.fpuST0()
			c.fpuPop()
			c.fpuSetST0(math.Atan2(y, x))
		case reg == 6 && i == 5: // FPREM1
			c.fpuSetST0(math.Remainder(c.fpuST0(), c.fpuSTi(1)))
		case reg == 6 && i == 6: // FDECSTP
			c.fpuTop = (c.fpuTop - 1) & 7
		case reg == 6 && i == 7: // FINCSTP
			c.fpuTop = (c.fpuTop + 1) & 7
		case reg == 7 && i == 0: // FPREM
			st0 := c.fpuST0()
			st1 := c.fpuSTi(1)
			if st1 != 0 {
				c.fpuSetST0(st0 - math.Trunc(st0/st1)*st1)
			}
		case reg == 7 && i == 1: // FYL2XP1: ST(1) = ST(1) * log2(ST(0)+1), pop
			y := c.fpuSTi(1)
			x := c.fpuST0()
			c.fpuPop()
			c.fpuSetST0(y * math.Log2(x+1))
		case reg == 7 && i == 2: // FSQRT
			c.fpuSetST0(math.Sqrt(c.fpuST0()))
		case reg == 7 && i == 3: // FSINCOS
			s, cos := math.Sincos(c.fpuST0())
			c.fpuSetST0(s)
			c.fpuPush(cos)
		case reg == 7 && i == 4: // FRNDINT
			c.fpuSetST0(float64(fpuRoundToInt(c.fpuST0(), c.fpuCW)))
		case reg == 7 && i == 5: // FSCALE: ST(0) = ST(0) * 2^trunc(ST(1))
			c.fpuSetST0(math.Ldexp(c.fpuST0(), int(c.fpuSTi(1))))
		case reg == 7 && i == 6: // FSIN
			c.fpuSetST0(math.Sin(c.fpuST0()))
		case reg == 7 && i == 7: // FCOS
			c.fpuSetST0(math.Cos(c.fpuST0()))
		case reg == 6 && i == 4: // FXTRACT (D9 F4)
			frac, exp := math.Frexp(c.fpuST0())
			c.fpuSetST0(float64(exp - 1))
			c.fpuPush(frac * 2) // significand in [1,2)
		}
	case 0xDA:
		switch {
		case reg == 5 && i == 1: // FUCOMPP
			c.fpuSetCC(fpuCompare(c.fpuST0(), c.fpuSTi(1)))
			c.fpuPop()
			c.fpuPop()
		default:
			// DA C0+i..DF: FCMOV* - conditional moves
			cond := false
			switch reg {
			case 0: // FCMOVB (CF=1)
				cond = c.Rflags&flagCF != 0
			case 1: // FCMOVE (ZF=1)
				cond = c.Rflags&flagZF != 0
			case 2: // FCMOVBE (CF=1 || ZF=1)
				cond = c.Rflags&(flagCF|flagZF) != 0
			case 3: // FCMOVU (PF=1)
				cond = c.Rflags&flagPF != 0
			}
			if cond {
				c.fpuSetST0(c.fpuSTi(i))
			}
		}
	case 0xDB:
		switch {
		case reg == 4 && i == 2: // FNCLEX
			c.fpuSW &^= 0x80FF // clear exception flags
		case reg == 4 && i == 3: // FNINIT
			c.fpuInit()
		case reg == 5: // FUCOMI ST(0), ST(i)
			cmp := fpuCompare(c.fpuST0(), c.fpuSTi(i))
			c.Rflags &^= flagCF | flagZF | flagPF
			switch cmp {
			case -1:
				c.Rflags |= flagCF
			case 0:
				c.Rflags |= flagZF
			case 2:
				c.Rflags |= flagCF | flagZF | flagPF
			}
		case reg == 6: // FCOMI ST(0), ST(i)
			cmp := fpuCompare(c.fpuST0(), c.fpuSTi(i))
			c.Rflags &^= flagCF | flagZF | flagPF
			switch cmp {
			case -1:
				c.Rflags |= flagCF
			case 0:
				c.Rflags |= flagZF
			case 2:
				c.Rflags |= flagCF | flagZF | flagPF
			}
		default:
			// FCMOVNB, FCMOVNE, FCMOVNBE, FCMOVNU
			cond := false
			switch reg {
			case 0: // FCMOVNB (CF=0)
				cond = c.Rflags&flagCF == 0
			case 1: // FCMOVNE (ZF=0)
				cond = c.Rflags&flagZF == 0
			case 2: // FCMOVNBE (CF=0 && ZF=0)
				cond = c.Rflags&(flagCF|flagZF) == 0
			case 3: // FCMOVNU (PF=0)
				cond = c.Rflags&flagPF == 0
			}
			if cond {
				c.fpuSetST0(c.fpuSTi(i))
			}
		}
	case 0xDC: // register: ST(i) op= ST(0) (reversed direction)
		switch reg {
		case 0: // FADD ST(i), ST(0)
			c.fpuSetSTi(i, c.fpuSTi(i)+c.fpuST0())
		case 1: // FMUL ST(i), ST(0)
			c.fpuSetSTi(i, c.fpuSTi(i)*c.fpuST0())
		case 4: // FSUBR ST(i), ST(0)
			c.fpuSetSTi(i, c.fpuST0()-c.fpuSTi(i))
		case 5: // FSUB ST(i), ST(0)
			c.fpuSetSTi(i, c.fpuSTi(i)-c.fpuST0())
		case 6: // FDIVR ST(i), ST(0)
			c.fpuSetSTi(i, c.fpuST0()/c.fpuSTi(i))
		case 7: // FDIV ST(i), ST(0)
			c.fpuSetSTi(i, c.fpuSTi(i)/c.fpuST0())
		}
	case 0xDD:
		switch reg {
		case 0: // FFREE ST(i)
			c.fpuTW |= 3 << (uint(c.fpuPhys(i)) * 2)
		case 2: // FST ST(i)
			c.fpuSetSTi(i, c.fpuST0())
		case 3: // FSTP ST(i)
			c.fpuSetSTi(i, c.fpuST0())
			c.fpuPop()
		case 4: // FUCOM ST(i)
			c.fpuSetCC(fpuCompare(c.fpuST0(), c.fpuSTi(i)))
		case 5: // FUCOMP ST(i)
			c.fpuSetCC(fpuCompare(c.fpuST0(), c.fpuSTi(i)))
			c.fpuPop()
		}
	case 0xDE: // register: ST(i) op= ST(0), pop
		switch reg {
		case 0: // FADDP ST(i), ST(0)
			c.fpuSetSTi(i, c.fpuSTi(i)+c.fpuST0())
			c.fpuPop()
		case 1: // FMULP ST(i), ST(0)
			c.fpuSetSTi(i, c.fpuSTi(i)*c.fpuST0())
			c.fpuPop()
		case 3 & 0x07: // FCOMPP (DE D9 specifically: reg=3, rm=1)
			if i == 1 {
				c.fpuSetCC(fpuCompare(c.fpuST0(), c.fpuSTi(1)))
				c.fpuPop()
				c.fpuPop()
			}
		case 4: // FSUBRP ST(i), ST(0)
			c.fpuSetSTi(i, c.fpuST0()-c.fpuSTi(i))
			c.fpuPop()
		case 5: // FSUBP ST(i), ST(0)
			c.fpuSetSTi(i, c.fpuSTi(i)-c.fpuST0())
			c.fpuPop()
		case 6: // FDIVRP ST(i), ST(0)
			c.fpuSetSTi(i, c.fpuST0()/c.fpuSTi(i))
			c.fpuPop()
		case 7: // FDIVP ST(i), ST(0)
			c.fpuSetSTi(i, c.fpuSTi(i)/c.fpuST0())
			c.fpuPop()
		}
	case 0xDF:
		switch {
		case reg == 4 && i == 0: // FNSTSW AX
			sw := c.fpuSW | uint16(c.fpuTop<<11)
			c.Regs[RAX] = (c.Regs[RAX] &^ 0xFFFF) | uint64(sw)
		case reg == 5: // FUCOMIP ST(0), ST(i)
			cmp := fpuCompare(c.fpuST0(), c.fpuSTi(i))
			c.Rflags &^= flagCF | flagZF | flagPF
			switch cmp {
			case -1:
				c.Rflags |= flagCF
			case 0:
				c.Rflags |= flagZF
			case 2:
				c.Rflags |= flagCF | flagZF | flagPF
			}
			c.fpuPop()
		case reg == 6: // FCOMIP ST(0), ST(i)
			cmp := fpuCompare(c.fpuST0(), c.fpuSTi(i))
			c.Rflags &^= flagCF | flagZF | flagPF
			switch cmp {
			case -1:
				c.Rflags |= flagCF
			case 0:
				c.Rflags |= flagZF
			case 2:
				c.Rflags |= flagCF | flagZF | flagPF
			}
			c.fpuPop()
		}
	}
	return nil
}

// fpuRoundToInt rounds a float64 to int64 using the FPU rounding mode in CW.
func fpuRoundToInt(val float64, cw uint16) int64 {
	mode := (cw >> 10) & 3
	switch mode {
	case 0: // Round to nearest even
		return int64(math.RoundToEven(val))
	case 1: // Round down (toward -∞)
		return int64(math.Floor(val))
	case 2: // Round up (toward +∞)
		return int64(math.Ceil(val))
	case 3: // Truncate (toward 0)
		return int64(math.Trunc(val))
	}
	return int64(val)
}

// float80ToFloat64 converts an 80-bit extended precision float to float64.
// lo = lower 64 bits (mantissa), hi = upper 16 bits (sign + exponent).
func float80ToFloat64(lo uint64, hi uint16) float64 {
	sign := hi >> 15
	exp := int(hi&0x7FFF) - 16383
	if exp == -16383 { // zero or denormal
		if lo == 0 {
			if sign != 0 {
				return math.Copysign(0, -1)
			}
			return 0
		}
		// Denormal - just return 0 (good enough approximation)
		return 0
	}
	if exp == 16384 { // infinity or NaN
		if lo == 0x8000000000000000 {
			if sign != 0 {
				return math.Inf(-1)
			}
			return math.Inf(1)
		}
		return math.NaN()
	}
	// Normal: (-1)^sign * 2^exp * (mantissa / 2^63)
	f := math.Ldexp(float64(lo), exp-63)
	if sign != 0 {
		f = -f
	}
	return f
}

// float64ToFloat80 converts float64 to 80-bit extended (lo mantissa, hi sign+exp).
func float64ToFloat80(f float64) (uint64, uint16) {
	if f == 0 {
		if math.Signbit(f) {
			return 0, 0x8000
		}
		return 0, 0
	}
	if math.IsInf(f, 1) {
		return 0x8000000000000000, 0x7FFF
	}
	if math.IsInf(f, -1) {
		return 0x8000000000000000, 0xFFFF
	}
	if math.IsNaN(f) {
		return 0xC000000000000000, 0x7FFF
	}
	var sign uint16
	if f < 0 {
		sign = 0x8000
		f = -f
	}
	frac, exp := math.Frexp(f)
	// frac is in [0.5, 1.0), exp is biased so f = frac * 2^exp
	// Extended: mantissa = frac * 2^64 (with explicit integer bit)
	mantissa := uint64(frac * math.Exp2(64))
	biasedExp := uint16(exp-1+16383) & 0x7FFF
	return mantissa, sign | biasedExp
}

package x64

import (
	"encoding/binary"
	"fmt"
	"math"
	"sync"

	"github.com/mirkobrombin/Raven/pkg/mmu"
)

type x87SignalContext struct {
	unmasked bool
}

var x87SignalContexts sync.Map

// x87 FPU state embedded in CPU.
// ST(0)-ST(7) are a circular stack, fpuTop indexes ST(0).
// CW = control word, SW = status word.

// fpuInit initializes the FPU to its default state (as after FINIT).
func (c *CPU) fpuInit() {
	c.fpuCW = 0x037F // all exceptions masked, extended precision, round to nearest
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

const (
	fpuExcInvalid   = 1 << 0
	fpuExcDenormal  = 1 << 1
	fpuExcZero      = 1 << 2
	fpuExcOverflow  = 1 << 3
	fpuExcUnderflow = 1 << 4
	fpuExcPrecision = 1 << 5
	fpuStackFault   = 1 << 6
	fpuErrorSummary = 1 << 7
)

func fpuTagForValue(v float64) uint16 {
	if v == 0 {
		return 1
	}
	if math.IsNaN(v) || math.IsInf(v, 0) || math.Abs(v) < math.Float64frombits(1<<52) {
		return 2
	}
	return 0
}

func (c *CPU) fpuSetTag(phys int, tag uint16) {
	shift := uint(phys * 2)
	c.fpuTW = (c.fpuTW &^ (3 << shift)) | ((tag & 3) << shift)
}

func (c *CPU) fpuSignal(mask uint16, c1 bool) bool {
	c.fpuSW |= mask
	exceptionBits := mask & 0x3F
	unmasked := exceptionBits != 0 && c.fpuCW&exceptionBits != exceptionBits
	c.fpuRefreshES()
	if unmasked {
		if context, ok := x87SignalContexts.Load(c); ok {
			context.(*x87SignalContext).unmasked = true
		}
	}
	if c1 {
		c.fpuSW |= 1 << 9
	} else {
		c.fpuSW &^= 1 << 9
	}
	return unmasked
}

func (c *CPU) fpuEmpty(i int) bool {
	return (c.fpuTW>>(uint(c.fpuPhys(i))*2))&3 == 3
}

func (c *CPU) fpuPhysicalEmpty(phys int) bool {
	return (c.fpuTW>>(uint(phys)*2))&3 == 3
}

func (c *CPU) fpuLoadCW(value uint16) {
	c.fpuCW = (value & 0x0F3F) | 0x0040
	c.fpuRefreshES()
}

func (c *CPU) fpuRefreshES() {
	if c.fpuSW&0x3F&^c.fpuCW != 0 {
		c.fpuSW |= fpuErrorSummary
	} else {
		c.fpuSW &^= fpuErrorSummary
	}
}

// fpuPush pushes a value onto the FPU stack.
func (c *CPU) fpuPush(val float64) {
	next := (c.fpuTop - 1) & 7
	if !c.fpuPhysicalEmpty(next) {
		if c.fpuSignal(fpuExcInvalid|fpuStackFault, true) {
			return
		}
		val = math.NaN()
	}
	c.fpuTop = next
	c.fpuST[c.fpuTop] = val
	c.fpuSetTag(c.fpuTop, fpuTagForValue(val))
}

// fpuPop pops the top of the FPU stack.
func (c *CPU) fpuPop() float64 {
	if c.fpuEmpty(0) {
		if c.fpuSignal(fpuExcInvalid|fpuStackFault, false) {
			return math.NaN()
		}
		c.fpuTop = (c.fpuTop + 1) & 7
		return math.NaN()
	}
	val := c.fpuST[c.fpuTop]
	c.fpuSetTag(c.fpuTop, 3)
	c.fpuTop = (c.fpuTop + 1) & 7
	return val
}

// fpuST0 returns ST(0).
func (c *CPU) fpuST0() float64 {
	if c.fpuEmpty(0) {
		c.fpuSignal(fpuExcInvalid|fpuStackFault, false)
		return math.NaN()
	}
	return c.fpuST[c.fpuTop]
}

// fpuSTi returns ST(i).
func (c *CPU) fpuSTi(i int) float64 {
	if c.fpuEmpty(i) {
		c.fpuSignal(fpuExcInvalid|fpuStackFault, false)
		return math.NaN()
	}
	return c.fpuST[c.fpuPhys(i)]
}

// fpuSetSTi sets ST(i) without applying arithmetic precision control.
func (c *CPU) fpuSetSTi(i int, val float64) {
	phys := c.fpuPhys(i)
	c.fpuST[phys] = val
	c.fpuSetTag(phys, fpuTagForValue(val))
}

func (c *CPU) fpuSetSTiResult(i int, val float64) {
	phys := c.fpuPhys(i)
	rounded := fpuRoundPrecision(val, c.fpuCW)
	if rounded != val && !math.IsNaN(val) {
		c.fpuSignal(fpuExcPrecision, false)
		if rounded == 0 {
			c.fpuSignal(fpuExcUnderflow, false)
		}
		if math.IsInf(rounded, 0) && !math.IsInf(val, 0) {
			c.fpuSignal(fpuExcOverflow, false)
		}
	}
	val = rounded
	c.fpuST[phys] = val
	c.fpuSetTag(phys, fpuTagForValue(val))
}

// fpuSetST0 sets ST(0) without applying arithmetic precision control.
func (c *CPU) fpuSetST0(val float64) {
	c.fpuST[c.fpuTop] = val
	c.fpuSetTag(c.fpuTop, fpuTagForValue(val))
}

func (c *CPU) fpuSetST0Result(val float64) {
	rounded := fpuRoundPrecision(val, c.fpuCW)
	if rounded != val && !math.IsNaN(val) {
		c.fpuSignal(fpuExcPrecision, false)
		if rounded == 0 {
			c.fpuSignal(fpuExcUnderflow, false)
		}
		if math.IsInf(rounded, 0) && !math.IsInf(val, 0) {
			c.fpuSignal(fpuExcOverflow, false)
		}
	}
	val = rounded
	c.fpuST[c.fpuTop] = val
	c.fpuSetTag(c.fpuTop, fpuTagForValue(val))
}

// fpuUpdateSW sets the C0-C3 condition code bits from a comparison result.
// cmp: -1 (less), 0 (equal), +1 (greater), 2 (unordered/NaN)
func (c *CPU) fpuSetCC(cmp int) {
	c.fpuSW &^= 0x4700 // clear C0, C1, C2, C3
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

func fpuSignalingNaN(v float64) bool {
	bits := math.Float64bits(v)
	return math.IsNaN(v) && bits&(1<<51) == 0
}

func (c *CPU) fpuCompareValues(a, b float64, quiet bool) int {
	if math.IsNaN(a) || math.IsNaN(b) {
		if !quiet || fpuSignalingNaN(a) || fpuSignalingNaN(b) {
			c.fpuSignal(fpuExcInvalid, false)
		}
		return 2
	}
	return fpuCompare(a, b)
}

func (c *CPU) fpuArithmeticNaN(a, b float64) {
	if fpuSignalingNaN(a) || fpuSignalingNaN(b) {
		c.fpuSignal(fpuExcInvalid, false)
	}
}

func fpuSignedZero(cw uint16) float64 {
	if (cw>>10)&3 == 1 {
		return math.Copysign(0, -1)
	}
	return 0
}

func (c *CPU) fpuDivide(a, b float64) float64 {
	if math.IsNaN(a) || math.IsNaN(b) {
		c.fpuArithmeticNaN(a, b)
		return a / b
	}
	if b == 0 {
		if a == 0 {
			c.fpuSignal(fpuExcInvalid, false)
		} else if !math.IsInf(a, 0) {
			c.fpuSignal(fpuExcZero, false)
		}
	}
	if math.IsInf(a, 0) && math.IsInf(b, 0) {
		c.fpuSignal(fpuExcInvalid, false)
	}
	result := a / b
	if math.IsInf(result, 0) && !math.IsInf(a, 0) && !math.IsInf(b, 0) {
		c.fpuSignal(fpuExcOverflow, false)
	}
	if result == 0 && a != 0 && b != 0 && !math.IsInf(a, 0) && !math.IsInf(b, 0) {
		c.fpuSignal(fpuExcUnderflow, false)
	}
	return result
}

func (c *CPU) fpuAdd(a, b float64) float64 {
	if math.IsNaN(a) || math.IsNaN(b) {
		c.fpuArithmeticNaN(a, b)
		return a + b
	}
	if math.IsInf(a, 0) && math.IsInf(b, 0) && math.Signbit(a) != math.Signbit(b) {
		c.fpuSignal(fpuExcInvalid, false)
	}
	result := a + b
	if result == 0 && a != 0 && b != 0 && a != -b {
		c.fpuSignal(fpuExcUnderflow, false)
	}
	if result == 0 && !math.IsInf(a, 0) && !math.IsInf(b, 0) {
		return fpuSignedZero(c.fpuCW)
	}
	if math.IsInf(result, 0) && !math.IsInf(a, 0) && !math.IsInf(b, 0) {
		c.fpuSignal(fpuExcOverflow, false)
	}
	return result
}

func (c *CPU) fpuSubtract(a, b float64) float64 {
	if math.IsNaN(a) || math.IsNaN(b) {
		c.fpuArithmeticNaN(a, b)
		return a - b
	}
	if math.IsInf(a, 0) && math.IsInf(b, 0) && math.Signbit(a) == math.Signbit(b) {
		c.fpuSignal(fpuExcInvalid, false)
	}
	result := a - b
	if result == 0 && a != 0 && b != 0 && a != b {
		c.fpuSignal(fpuExcUnderflow, false)
	}
	if result == 0 && !math.IsInf(a, 0) && !math.IsInf(b, 0) {
		return fpuSignedZero(c.fpuCW)
	}
	if math.IsInf(result, 0) && !math.IsInf(a, 0) && !math.IsInf(b, 0) {
		c.fpuSignal(fpuExcOverflow, false)
	}
	return result
}

func (c *CPU) fpuMultiply(a, b float64) float64 {
	if math.IsNaN(a) || math.IsNaN(b) {
		c.fpuArithmeticNaN(a, b)
		return a * b
	}
	if (a == 0 && math.IsInf(b, 0)) || (b == 0 && math.IsInf(a, 0)) {
		c.fpuSignal(fpuExcInvalid, false)
	}
	result := a * b
	if math.IsInf(result, 0) && !math.IsInf(a, 0) && !math.IsInf(b, 0) {
		c.fpuSignal(fpuExcOverflow, false)
	}
	if result == 0 && a != 0 && b != 0 && !math.IsInf(a, 0) && !math.IsInf(b, 0) {
		c.fpuSignal(fpuExcUnderflow, false)
	}
	return result
}

func fpuRoundFloat32(val float64, cw uint16) float64 {
	nearest := float32(val)
	rounded := float64(nearest)
	if rounded == val || math.IsNaN(val) {
		return rounded
	}
	switch (cw >> 10) & 3 {
	case 1:
		if rounded > val {
			nearest = math.Nextafter32(nearest, float32(math.Inf(-1)))
		}
	case 2:
		if rounded < val {
			nearest = math.Nextafter32(nearest, float32(math.Inf(1)))
		}
	case 3:
		if (val > 0 && rounded > val) || (val < 0 && rounded < val) {
			target := float32(math.Inf(-1))
			if val < 0 {
				target = float32(math.Inf(1))
			}
			nearest = math.Nextafter32(nearest, target)
		}
	}
	return float64(nearest)
}

func (c *CPU) fpuStoreFloat32(val float64) (uint32, bool) {
	rounded := fpuRoundFloat32(val, c.fpuCW)
	fault := false
	if rounded != val && !math.IsNaN(val) {
		fault = c.fpuSignal(fpuExcPrecision, false) || fault
		if rounded == 0 {
			fault = c.fpuSignal(fpuExcUnderflow, false) || fault
		}
		if math.IsInf(rounded, 0) && !math.IsInf(val, 0) {
			fault = c.fpuSignal(fpuExcOverflow, false) || fault
		}
	}
	return math.Float32bits(float32(rounded)), fault
}

func (c *CPU) fpuSetC2(value bool) {
	if value {
		c.fpuSW |= 0x0400
	} else {
		c.fpuSW &^= 0x0400
	}
}

func (c *CPU) fpuSetPremCC(quotient float64) {
	c.fpuSW &^= 0x4700
	if math.IsNaN(quotient) || math.IsInf(quotient, 0) {
		return
	}
	var bits uint64
	if math.Abs(quotient) < math.Ldexp(1, 63) {
		bits = uint64(int64(quotient)) & 7
	} else {
		remainder := math.Mod(quotient, 8)
		if remainder < 0 {
			remainder += 8
		}
		bits = uint64(remainder)
	}
	if bits&4 != 0 {
		c.fpuSW |= 0x0100
	}
	if bits&1 != 0 {
		c.fpuSW |= 0x0200
	}
	if bits&2 != 0 {
		c.fpuSW |= 0x4000
	}
}

func (c *CPU) fpuPrem(st0, st1 float64, nearest bool) {
	if math.IsNaN(st0) || math.IsNaN(st1) {
		if fpuSignalingNaN(st0) || fpuSignalingNaN(st1) {
			c.fpuSignal(fpuExcInvalid, false)
		}
		c.fpuSetST0(math.NaN())
		return
	}
	if math.IsInf(st0, 0) || st1 == 0 {
		c.fpuSignal(fpuExcInvalid, false)
		return
	}
	if math.IsInf(st1, 0) {
		c.fpuSetC2(false)
		c.fpuSetPremCC(0)
		return
	}
	mantissa0, exp0 := math.Frexp(st0)
	mantissa1, exp1 := math.Frexp(st1)
	distance := exp0 - exp1
	if distance >= 64 {
		scale := distance - 63
		quotient := math.Trunc(math.Ldexp(mantissa0/mantissa1, 63))
		c.fpuSetC2(true)
		c.fpuSetST0(st0 - math.Ldexp(st1, scale)*quotient)
		return
	}
	quotient := math.Trunc(st0 / st1)
	if nearest {
		quotient = math.RoundToEven(st0 / st1)
	}
	c.fpuSetC2(false)
	c.fpuSetST0(st0 - quotient*st1)
	c.fpuSetPremCC(quotient)
}

func fpuTrigRange(v float64) bool {
	return !math.IsNaN(v) && math.Abs(v) < math.Ldexp(1, 63)
}

// fpuReadMem32 reads a 32-bit float from guest memory.
func (c *CPU) fpuReadMem32(addr uint64) (float64, error) {
	v, err := c.mem.Read32(addr)
	if err != nil {
		return 0, err
	}
	return float64(math.Float32frombits(v)), nil
}

// fpuReadMem64 reads a 64-bit float from guest memory.
func (c *CPU) fpuReadMem64(addr uint64) (float64, error) {
	v, err := c.mem.Read64(addr)
	if err != nil {
		return 0, err
	}
	return math.Float64frombits(v), nil
}

// fpuReadMemInt16 reads a 16-bit signed integer from guest memory.
func (c *CPU) fpuReadMemInt16(addr uint64) (float64, error) {
	v, err := c.mem.Read16(addr)
	if err != nil {
		return 0, err
	}
	return float64(int16(v)), nil
}

// fpuReadMemInt32 reads a 32-bit signed integer from guest memory.
func (c *CPU) fpuReadMemInt32(addr uint64) (float64, error) {
	v, err := c.mem.Read32(addr)
	if err != nil {
		return 0, err
	}
	return float64(int32(v)), nil
}

// fpuReadMemInt64 reads a 64-bit signed integer from guest memory.
func (c *CPU) fpuReadMemInt64(addr uint64) (float64, error) {
	v, err := c.mem.Read64(addr)
	if err != nil {
		return 0, err
	}
	return float64(int64(v)), nil
}

// execX87 dispatches x87 FPU opcodes 0xD8-0xDF.
func (c *CPU) execX87(op byte, pfx *prefixState) error {
	signalContext := &x87SignalContext{}
	x87SignalContexts.Store(c, signalContext)
	defer x87SignalContexts.Delete(c)
	statusBefore := c.fpuSW
	stackBefore := c.fpuST
	topBefore := c.fpuTop
	tagBefore := c.fpuTW
	flagsBefore := c.Rflags
	m, err := c.decodeModRM(pfx)
	if err != nil {
		return err
	}
	c.recordX87Opcode(op, m.raw)

	// Memory vs register form
	if m.mod != 3 {
		addr, _, resolveErr := c.resolveRMAddr(m, pfx)
		if resolveErr != nil {
			return resolveErr
		}
		err = c.execX87mem(op, m.reg, addr, pfx)
	} else {
		err = c.execX87reg(op, m.reg, m.rm)
	}
	if err != nil {
		return err
	}
	if signalContext.unmasked {
		exceptionBits := c.fpuSW & (0xFF | 1<<9)
		c.fpuST = stackBefore
		c.fpuTop = topBefore
		c.fpuTW = tagBefore
		c.Rflags = flagsBefore
		c.fpuSW = (statusBefore &^ (0xFF | 1<<9)) | exceptionBits | fpuErrorSummary
		return fmt.Errorf("unmasked x87 exception at RIP=0x%x", c.RIP)
	}
	return nil
}

// execX87mem handles x87 ops with memory operand.
func (c *CPU) execX87mem(op byte, reg int, addr uint64, pfx *prefixState) error {
	size := c.x87MemSize(op, reg, pfx)
	if size == 0 {
		return fmt.Errorf("unimplemented x87 memory form %02X /%d", op, reg)
	}
	if addr > ^uint64(0)-(size-1) {
		return fmt.Errorf("x87 memory range overflows address space")
	}
	perms := uint8(mmu.PermRead)
	if c.x87MemWrites(op, reg, pfx) {
		perms = mmu.PermWrite
	}
	for off := uint64(0); off < size; off++ {
		if _, _, err := c.mem.LookupRead(addr+off, perms); err != nil {
			return err
		}
	}
	if x87MemNeedsST0(op, reg) && c.fpuEmpty(0) && c.fpuCW&fpuExcInvalid == 0 {
		c.fpuSignal(fpuExcInvalid|fpuStackFault, false)
		return nil
	}
	switch op {
	case 0xD8: // float32 arithmetic
		val, err := c.fpuReadMem32(addr)
		if err != nil {
			return err
		}
		switch reg {
		case 0: // FADD m32
			c.fpuSetST0Result(c.fpuAdd(c.fpuST0(), val))
		case 1: // FMUL m32
			c.fpuSetST0Result(c.fpuMultiply(c.fpuST0(), val))
		case 2: // FCOM m32
			c.fpuSetCC(c.fpuCompareValues(c.fpuST0(), val, false))
		case 3: // FCOMP m32
			c.fpuSetCC(c.fpuCompareValues(c.fpuST0(), val, false))
			c.fpuPop()
		case 4: // FSUB m32
			c.fpuSetST0Result(c.fpuSubtract(c.fpuST0(), val))
		case 5: // FSUBR m32
			c.fpuSetST0Result(c.fpuSubtract(val, c.fpuST0()))
		case 6: // FDIV m32
			c.fpuSetST0Result(c.fpuDivide(c.fpuST0(), val))
		case 7: // FDIVR m32
			c.fpuSetST0Result(c.fpuDivide(val, c.fpuST0()))
		}
	case 0xD9: // load/store/control float32
		switch reg {
		case 0: // FLD m32
			val, err := c.fpuReadMem32(addr)
			if err != nil {
				return err
			}
			c.fpuPush(val)
		case 2: // FST m32
			bits, fault := c.fpuStoreFloat32(c.fpuST0())
			if fault {
				return fmt.Errorf("unmasked x87 store precision exception")
			}
			if err := c.mem.Write32(addr, bits); err != nil {
				return err
			}
		case 3: // FSTP m32
			bits, fault := c.fpuStoreFloat32(c.fpuST0())
			if fault {
				return fmt.Errorf("unmasked x87 store precision exception")
			}
			if err := c.mem.Write32(addr, bits); err != nil {
				return err
			}
			c.fpuPop()
		case 4: // FLDENV
			return c.fpuLoadEnv(addr, pfx)
		case 5: // FLDCW m16
			v, err := c.mem.Read16(addr)
			if err != nil {
				return err
			}
			c.fpuLoadCW(v)
		case 6: // FNSTENV
			if err := c.fpuStoreEnv(addr, pfx); err != nil {
				return err
			}
			c.fpuCW |= 0x003F
			c.fpuRefreshES()
			return nil
		case 7: // FNSTCW m16
			return c.mem.Write16(addr, c.fpuCW)
		}
	case 0xDA: // int32 arithmetic
		val, err := c.fpuReadMemInt32(addr)
		if err != nil {
			return err
		}
		switch reg {
		case 0: // FIADD m32
			c.fpuSetST0Result(c.fpuAdd(c.fpuST0(), val))
		case 1: // FIMUL m32
			c.fpuSetST0Result(c.fpuMultiply(c.fpuST0(), val))
		case 2: // FICOM m32
			c.fpuSetCC(c.fpuCompareValues(c.fpuST0(), val, false))
		case 3: // FICOMP m32
			c.fpuSetCC(c.fpuCompareValues(c.fpuST0(), val, false))
			c.fpuPop()
		case 4: // FISUB m32
			c.fpuSetST0Result(c.fpuSubtract(c.fpuST0(), val))
		case 5: // FISUBR m32
			c.fpuSetST0Result(c.fpuSubtract(val, c.fpuST0()))
		case 6: // FIDIV m32
			c.fpuSetST0Result(c.fpuDivide(c.fpuST0(), val))
		case 7: // FIDIVR m32
			c.fpuSetST0Result(c.fpuDivide(val, c.fpuST0()))
		}
	case 0xDB:
		switch reg {
		case 0: // FILD m32
			val, err := c.fpuReadMemInt32(addr)
			if err != nil {
				return err
			}
			c.fpuPush(val)
		case 1: // FISTTP m32
			v, fault := fpuConvertIntForStore(c.fpuST0(), 32, true, c)
			if fault {
				return fmt.Errorf("unmasked x87 integer conversion exception")
			}
			if err := c.mem.Write32(addr, uint32(v)); err != nil {
				return err
			}
			c.fpuPop()
		case 2: // FIST m32
			v, fault := fpuConvertIntForStore(c.fpuST0(), 32, false, c)
			if fault {
				return fmt.Errorf("unmasked x87 integer conversion exception")
			}
			if err := c.mem.Write32(addr, uint32(v)); err != nil {
				return err
			}
		case 3: // FISTP m32
			v, fault := fpuConvertIntForStore(c.fpuST0(), 32, false, c)
			if fault {
				return fmt.Errorf("unmasked x87 integer conversion exception")
			}
			if err := c.mem.Write32(addr, uint32(v)); err != nil {
				return err
			}
			c.fpuPop()
		case 5: // FLD m80 (extended precision - load as float64)
			lo, err := c.mem.Read64(addr)
			if err != nil {
				return err
			}
			hi, err := c.mem.Read16(addr + 8)
			if err != nil {
				return err
			}
			c.fpuPush(float80ToFloat64(lo, hi))
		case 7: // FSTP m80 (store extended)
			lo, hi := float64ToFloat80(c.fpuST0())
			if err := c.mem.Write64(addr, lo); err != nil {
				return err
			}
			if err := c.mem.Write16(addr+8, hi); err != nil {
				return err
			}
			c.fpuPop()
		}
	case 0xDC: // float64 arithmetic
		val, err := c.fpuReadMem64(addr)
		if err != nil {
			return err
		}
		switch reg {
		case 0: // FADD m64
			c.fpuSetST0Result(c.fpuAdd(c.fpuST0(), val))
		case 1: // FMUL m64
			c.fpuSetST0Result(c.fpuMultiply(c.fpuST0(), val))
		case 2: // FCOM m64
			c.fpuSetCC(c.fpuCompareValues(c.fpuST0(), val, false))
		case 3: // FCOMP m64
			c.fpuSetCC(c.fpuCompareValues(c.fpuST0(), val, false))
			c.fpuPop()
		case 4: // FSUB m64
			c.fpuSetST0Result(c.fpuSubtract(c.fpuST0(), val))
		case 5: // FSUBR m64
			c.fpuSetST0Result(c.fpuSubtract(val, c.fpuST0()))
		case 6: // FDIV m64
			c.fpuSetST0Result(c.fpuDivide(c.fpuST0(), val))
		case 7: // FDIVR m64
			c.fpuSetST0Result(c.fpuDivide(val, c.fpuST0()))
		}
	case 0xDD:
		switch reg {
		case 0: // FLD m64
			val, err := c.fpuReadMem64(addr)
			if err != nil {
				return err
			}
			c.fpuPush(val)
		case 1: // FISTTP m64
			v, fault := fpuConvertIntForStore(c.fpuST0(), 64, true, c)
			if fault {
				return fmt.Errorf("unmasked x87 integer conversion exception")
			}
			if err := c.mem.Write64(addr, uint64(v)); err != nil {
				return err
			}
			c.fpuPop()
		case 2: // FST m64
			if err := c.mem.Write64(addr, math.Float64bits(c.fpuST0())); err != nil {
				return err
			}
		case 3: // FSTP m64
			if err := c.mem.Write64(addr, math.Float64bits(c.fpuST0())); err != nil {
				return err
			}
			c.fpuPop()
		case 4: // FRSTOR
			return c.fpuRestore(addr, pfx)
		case 6: // FNSAVE
			if err := c.fpuStoreSaveImage(addr, pfx); err != nil {
				return err
			}
			c.fpuInit()
		case 7: // FNSTSW m16
			sw := c.fpuSW | uint16(c.fpuTop<<11)
			return c.mem.Write16(addr, sw)
		}
	case 0xDE: // int16 arithmetic + special
		val, err := c.fpuReadMemInt16(addr)
		if err != nil {
			return err
		}
		switch reg {
		case 0: // FIADD m16
			c.fpuSetST0Result(c.fpuAdd(c.fpuST0(), val))
		case 1: // FIMUL m16
			c.fpuSetST0Result(c.fpuMultiply(c.fpuST0(), val))
		case 2: // FICOM m16
			c.fpuSetCC(c.fpuCompareValues(c.fpuST0(), val, false))
		case 3: // FICOMP m16
			c.fpuSetCC(c.fpuCompareValues(c.fpuST0(), val, false))
			c.fpuPop()
		case 4: // FISUB m16
			c.fpuSetST0Result(c.fpuSubtract(c.fpuST0(), val))
		case 5: // FISUBR m16
			c.fpuSetST0Result(c.fpuSubtract(val, c.fpuST0()))
		case 6: // FIDIV m16
			c.fpuSetST0Result(c.fpuDivide(c.fpuST0(), val))
		case 7: // FIDIVR m16
			c.fpuSetST0Result(c.fpuDivide(val, c.fpuST0()))
		}
	case 0xDF:
		switch reg {
		case 0: // FILD m16
			val, err := c.fpuReadMemInt16(addr)
			if err != nil {
				return err
			}
			c.fpuPush(val)
		case 1: // FISTTP m16
			v, fault := fpuConvertIntForStore(c.fpuST0(), 16, true, c)
			if fault {
				return fmt.Errorf("unmasked x87 integer conversion exception")
			}
			if err := c.mem.Write16(addr, uint16(v)); err != nil {
				return err
			}
			c.fpuPop()
		case 2: // FIST m16
			v, fault := fpuConvertIntForStore(c.fpuST0(), 16, false, c)
			if fault {
				return fmt.Errorf("unmasked x87 integer conversion exception")
			}
			if err := c.mem.Write16(addr, uint16(v)); err != nil {
				return err
			}
		case 3: // FISTP m16
			v, fault := fpuConvertIntForStore(c.fpuST0(), 16, false, c)
			if fault {
				return fmt.Errorf("unmasked x87 integer conversion exception")
			}
			if err := c.mem.Write16(addr, uint16(v)); err != nil {
				return err
			}
			c.fpuPop()
		case 5: // FILD m64
			val, err := c.fpuReadMemInt64(addr)
			if err != nil {
				return err
			}
			c.fpuPush(val)
		case 7: // FISTP m64
			v, fault := fpuConvertIntForStore(c.fpuST0(), 64, false, c)
			if fault {
				return fmt.Errorf("unmasked x87 integer conversion exception")
			}
			if err := c.mem.Write64(addr, uint64(v)); err != nil {
				return err
			}
			c.fpuPop()
		}
	}
	return nil
}

func x87MemNeedsST0(op byte, reg int) bool {
	switch op {
	case 0xD8, 0xDA, 0xDC, 0xDE:
		return true
	case 0xD9:
		return reg == 2 || reg == 3
	case 0xDB, 0xDF:
		return reg == 1 || reg == 2 || reg == 3 || reg == 7
	case 0xDD:
		return reg == 1 || reg == 2 || reg == 3
	}
	return false
}

func (c *CPU) x87EnvWide(pfx *prefixState) bool {
	return pfx == nil || !pfx.op66
}

func (c *CPU) x87MemSize(op byte, reg int, pfx *prefixState) uint64 {
	switch op {
	case 0xD8:
		return 4
	case 0xD9:
		switch reg {
		case 0:
			return 4
		case 2, 3:
			return 4
		case 5, 7:
			return 2
		case 4, 6:
			if c.x87EnvWide(pfx) {
				return 28
			}
			return 14
		}
	case 0xDA:
		return 4
	case 0xDB:
		switch reg {
		case 0, 1, 2, 3:
			return 4
		case 5, 7:
			return 10
		}
	case 0xDC:
		return 8
	case 0xDD:
		switch reg {
		case 0, 1, 2, 3:
			return 8
		case 7:
			return 2
		case 4, 6:
			if c.x87EnvWide(pfx) {
				return 108
			}
			return 94
		}
	case 0xDE:
		return 2
	case 0xDF:
		switch reg {
		case 0, 1, 2, 3:
			return 2
		case 5, 7:
			return 8
		}
	}
	return 0
}

func (c *CPU) x87MemWrites(op byte, reg int, pfx *prefixState) bool {
	switch op {
	case 0xD9:
		return reg == 2 || reg == 3 || reg == 6 || reg == 7
	case 0xDB:
		return reg == 1 || reg == 2 || reg == 3 || reg == 7
	case 0xDD:
		return reg == 1 || reg == 2 || reg == 3 || reg == 6 || reg == 7
	case 0xDF:
		return reg == 1 || reg == 2 || reg == 3 || reg == 7
	}
	return false
}

func (c *CPU) fpuEnvBytes(pfx *prefixState) []byte {
	wide := c.x87EnvWide(pfx)
	base := 14
	if wide {
		base = 28
	}
	b := make([]byte, base)
	if wide {
		binary.LittleEndian.PutUint16(b[0:], c.fpuCW)
		binary.LittleEndian.PutUint16(b[4:], c.fpuSW|uint16(c.fpuTop)<<11)
		binary.LittleEndian.PutUint16(b[8:], c.fpuTW)
	} else {
		binary.LittleEndian.PutUint16(b[0:], c.fpuCW)
		binary.LittleEndian.PutUint16(b[2:], c.fpuSW|uint16(c.fpuTop)<<11)
		binary.LittleEndian.PutUint16(b[4:], c.fpuTW)
	}
	return b
}

func (c *CPU) fpuSaveImage(pfx *prefixState) []byte {
	env := c.fpuEnvBytes(pfx)
	b := make([]byte, len(env)+80)
	copy(b, env)
	off := len(env)
	for i := 0; i < 8; i++ {
		lo, hi := float64ToFloat80(c.fpuST[c.fpuPhys(i)])
		binary.LittleEndian.PutUint64(b[off:], lo)
		binary.LittleEndian.PutUint16(b[off+8:], hi)
		off += 10
	}
	return b
}

func (c *CPU) fpuStoreEnv(addr uint64, pfx *prefixState) error {
	b := c.fpuEnvBytes(pfx)
	return c.mem.WriteBytes(addr, b)
}

func (c *CPU) fpuStoreSaveImage(addr uint64, pfx *prefixState) error {
	b := c.fpuSaveImage(pfx)
	return c.mem.WriteBytes(addr, b)
}

func (c *CPU) fpuLoadEnv(addr uint64, pfx *prefixState) error {
	size := 14
	if c.x87EnvWide(pfx) {
		size = 28
	}
	b := make([]byte, size)
	for i := range b {
		v, err := c.mem.Read8(addr + uint64(i))
		if err != nil {
			return err
		}
		b[i] = v
	}
	if c.x87EnvWide(pfx) {
		c.fpuLoadCW(binary.LittleEndian.Uint16(b[0:]))
		c.fpuSW = binary.LittleEndian.Uint16(b[4:]) &^ (7 << 11)
		c.fpuTop = int(binary.LittleEndian.Uint16(b[4:])>>11) & 7
		c.fpuTW = binary.LittleEndian.Uint16(b[8:])
	} else {
		c.fpuLoadCW(binary.LittleEndian.Uint16(b[0:]))
		c.fpuSW = binary.LittleEndian.Uint16(b[2:]) &^ (7 << 11)
		c.fpuTop = int(binary.LittleEndian.Uint16(b[2:])>>11) & 7
		c.fpuTW = binary.LittleEndian.Uint16(b[4:])
	}
	return nil
}

func (c *CPU) fpuRestore(addr uint64, pfx *prefixState) error {
	if err := c.fpuLoadEnv(addr, pfx); err != nil {
		return err
	}
	base := uint64(14)
	if c.x87EnvWide(pfx) {
		base = 28
	}
	for i := 0; i < 8; i++ {
		lo, err := c.mem.Read64(addr + base + uint64(i*10))
		if err != nil {
			return err
		}
		hi, err := c.mem.Read16(addr + base + uint64(i*10+8))
		if err != nil {
			return err
		}
		c.fpuST[c.fpuPhys(i)] = float80ToFloat64Value(lo, hi)
	}
	return nil
}

// execX87reg handles x87 ops with register operand (mod==3).
func (c *CPU) execX87reg(op byte, reg int, rm int) error {
	if !x87RegFormImplemented(op, reg, rm) {
		return fmt.Errorf("unimplemented x87 register form %02X /%d rm=%d", op, reg, rm)
	}
	if x87RegNeedsST0(op, reg, rm, c) && c.fpuEmpty(0) && c.fpuCW&fpuExcInvalid == 0 {
		c.fpuSignal(fpuExcInvalid|fpuStackFault, false)
		return nil
	}
	i := rm // ST(i)
	switch op {
	case 0xD8: // register arithmetic: ST(0) op= ST(i)
		switch reg {
		case 0: // FADD ST(0), ST(i)
			c.fpuSetST0Result(c.fpuAdd(c.fpuST0(), c.fpuSTi(i)))
		case 1: // FMUL ST(0), ST(i)
			c.fpuSetST0Result(c.fpuMultiply(c.fpuST0(), c.fpuSTi(i)))
		case 2: // FCOM ST(i)
			c.fpuSetCC(c.fpuCompareValues(c.fpuST0(), c.fpuSTi(i), false))
		case 3: // FCOMP ST(i)
			c.fpuSetCC(c.fpuCompareValues(c.fpuST0(), c.fpuSTi(i), false))
			c.fpuPop()
		case 4: // FSUB ST(0), ST(i)
			c.fpuSetST0Result(c.fpuSubtract(c.fpuST0(), c.fpuSTi(i)))
		case 5: // FSUBR ST(0), ST(i)
			c.fpuSetST0Result(c.fpuSubtract(c.fpuSTi(i), c.fpuST0()))
		case 6: // FDIV ST(0), ST(i)
			c.fpuSetST0Result(c.fpuDivide(c.fpuST0(), c.fpuSTi(i)))
		case 7: // FDIVR ST(0), ST(i)
			c.fpuSetST0Result(c.fpuDivide(c.fpuSTi(i), c.fpuST0()))
		}
	case 0xD9:
		switch {
		case reg == 0: // FLD ST(i)
			c.fpuPush(c.fpuSTi(i))
		case reg == 1 && i == 0: // FXCH ST(0)
			if c.fpuEmpty(0) {
				c.fpuSignal(fpuExcInvalid|fpuStackFault, false)
			} else {
				c.fpuSW &^= 0x0200
			}
		case reg == 1: // FXCH ST(i)
			p0, pi := c.fpuPhys(0), c.fpuPhys(i)
			if c.fpuPhysicalEmpty(p0) || c.fpuPhysicalEmpty(pi) {
				c.fpuSignal(fpuExcInvalid|fpuStackFault, false)
			}
			c.fpuSW &^= 0x0200
			c.fpuST[p0], c.fpuST[pi] = c.fpuST[pi], c.fpuST[p0]
			t0 := (c.fpuTW >> uint(p0*2)) & 3
			ti := (c.fpuTW >> uint(pi*2)) & 3
			c.fpuSetTag(p0, ti)
			c.fpuSetTag(pi, t0)
		case reg == 4 && i == 0: // FCHS (D9 E0)
			c.fpuSetST0(-c.fpuST0())
		case reg == 4 && i == 1: // FABS (D9 E1)
			c.fpuSetST0(math.Abs(c.fpuST0()))
		case reg == 4 && i == 4: // FTST (D9 E4)
			c.fpuSetCC(c.fpuCompareValues(c.fpuST0(), 0, false))
		case reg == 4 && i == 5: // FXAM (D9 E5)
			val := c.fpuST0()
			c.fpuSW &^= 0x4700
			if math.IsNaN(val) {
				c.fpuSW |= 0x0100 // C0=1 -> NaN
			} else if math.IsInf(val, 0) {
				c.fpuSW |= 0x0500 // C0=C2=1 -> infinity
			} else if val == 0 {
				c.fpuSW |= 0x4000 // C3=1 -> zero
			} else {
				c.fpuSW |= 0x0400 // C2=1 -> normal
			}
			if math.Signbit(val) {
				c.fpuSW |= 0x0200 // C1=1 -> negative
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
			x := c.fpuST0()
			if math.IsNaN(x) {
				c.fpuSignal(fpuExcInvalid, false)
			} else if x < -1 || x > 1 {
				c.fpuSetC2(true)
			} else {
				c.fpuSetC2(false)
				c.fpuSetST0(math.Exp2(x) - 1)
			}
		case reg == 6 && i == 1: // FYL2X (D9 F1)
			y := c.fpuSTi(1)
			x := c.fpuST0()
			if x < 0 {
				c.fpuSignal(fpuExcInvalid, false)
			}
			if fpuSignalingNaN(x) || fpuSignalingNaN(y) {
				c.fpuSignal(fpuExcInvalid, false)
			}
			if x == 0 {
				c.fpuSignal(fpuExcZero, false)
			}
			c.fpuPop()
			c.fpuSetST0(y * math.Log2(x))
		case reg == 6 && i == 2: // FPTAN
			x := c.fpuST0()
			if math.IsNaN(x) {
				if fpuSignalingNaN(x) {
					c.fpuSignal(fpuExcInvalid, false)
				}
				c.fpuSetC2(false)
				c.fpuSetST0(x)
			} else if math.IsInf(x, 0) {
				c.fpuSignal(fpuExcInvalid, false)
			} else if fpuTrigRange(x) {
				c.fpuSetC2(false)
				c.fpuSetST0(math.Tan(x))
				c.fpuPush(1.0)
			} else {
				c.fpuSetC2(true)
			}
		case reg == 6 && i == 3: // FPATAN: ST(1) = atan2(ST(1), ST(0)), pop
			y := c.fpuSTi(1)
			x := c.fpuST0()
			c.fpuPop()
			c.fpuSetST0(math.Atan2(y, x))
		case reg == 6 && i == 5: // FPREM1
			c.fpuPrem(c.fpuST0(), c.fpuSTi(1), true)
		case reg == 6 && i == 6: // FDECSTP
			c.fpuTop = (c.fpuTop - 1) & 7
			c.fpuSW &^= 0x0200
		case reg == 6 && i == 7: // FINCSTP
			c.fpuTop = (c.fpuTop + 1) & 7
			c.fpuSW &^= 0x0200
		case reg == 7 && i == 0: // FPREM
			c.fpuPrem(c.fpuST0(), c.fpuSTi(1), false)
		case reg == 7 && i == 1: // FYL2XP1: ST(1) = ST(1) * log2(ST(0)+1), pop
			y := c.fpuSTi(1)
			x := c.fpuST0()
			if fpuSignalingNaN(x) || fpuSignalingNaN(y) {
				c.fpuSignal(fpuExcInvalid, false)
			} else if x <= -1 {
				if x == -1 {
					c.fpuSignal(fpuExcZero, false)
				} else {
					c.fpuSignal(fpuExcInvalid, false)
				}
			}
			c.fpuPop()
			c.fpuSetST0(y * math.Log2(x+1))
		case reg == 7 && i == 2: // FSQRT
			x := c.fpuST0()
			if x < 0 || fpuSignalingNaN(x) {
				c.fpuSignal(fpuExcInvalid, false)
			}
			c.fpuSetST0Result(math.Sqrt(x))
		case reg == 7 && i == 3: // FSINCOS
			x := c.fpuST0()
			if math.IsNaN(x) {
				if fpuSignalingNaN(x) {
					c.fpuSignal(fpuExcInvalid, false)
				}
				c.fpuSetC2(false)
				c.fpuSetST0(x)
			} else if math.IsInf(x, 0) {
				c.fpuSignal(fpuExcInvalid, false)
			} else if fpuTrigRange(x) {
				c.fpuSetC2(false)
				s, cos := math.Sincos(x)
				c.fpuSetST0(s)
				c.fpuPush(cos)
			} else {
				c.fpuSetC2(true)
			}
		case reg == 7 && i == 4: // FRNDINT
			c.fpuSetST0(fpuRoundFloat(c.fpuST0(), c.fpuCW))
		case reg == 7 && i == 5: // FSCALE: ST(0) = ST(0) * 2^trunc(ST(1))
			c.fpuSetST0(math.Ldexp(c.fpuST0(), int(c.fpuSTi(1))))
		case reg == 7 && i == 6: // FSIN
			x := c.fpuST0()
			if math.IsNaN(x) {
				if fpuSignalingNaN(x) {
					c.fpuSignal(fpuExcInvalid, false)
				}
				c.fpuSetC2(false)
				c.fpuSetST0(x)
			} else if math.IsInf(x, 0) {
				c.fpuSignal(fpuExcInvalid, false)
			} else if fpuTrigRange(x) {
				c.fpuSetC2(false)
				c.fpuSetST0(math.Sin(x))
			} else {
				c.fpuSetC2(true)
			}
		case reg == 7 && i == 7: // FCOS
			x := c.fpuST0()
			if math.IsNaN(x) {
				if fpuSignalingNaN(x) {
					c.fpuSignal(fpuExcInvalid, false)
				}
				c.fpuSetC2(false)
				c.fpuSetST0(x)
			} else if math.IsInf(x, 0) {
				c.fpuSignal(fpuExcInvalid, false)
			} else if fpuTrigRange(x) {
				c.fpuSetC2(false)
				c.fpuSetST0(math.Cos(x))
			} else {
				c.fpuSetC2(true)
			}
		case reg == 6 && i == 4: // FXTRACT (D9 F4)
			x := c.fpuST0()
			c.fpuSW &^= 0x0200
			switch {
			case x == 0:
				c.fpuSignal(fpuExcZero, false)
				c.fpuSetST0(math.Inf(-1))
				c.fpuPush(math.Copysign(0, x))
			case math.IsNaN(x):
				if fpuSignalingNaN(x) {
					c.fpuSignal(fpuExcInvalid, false)
					x = math.Float64frombits(math.Float64bits(x) | 1<<51)
				}
				c.fpuSetST0(x)
				c.fpuPush(x)
			case math.IsInf(x, 0):
				c.fpuSetST0(math.Inf(1))
				c.fpuPush(x)
			default:
				frac, exp := math.Frexp(x)
				c.fpuSetST0(float64(exp - 1))
				c.fpuPush(frac * 2)
			}
		}
	case 0xDA:
		switch {
		case reg == 5 && i == 1: // FUCOMPP
			c.fpuSetCC(c.fpuCompareValues(c.fpuST0(), c.fpuSTi(1), true))
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
			c.fpuSW &^= 0x80FF // clear exception, stack-fault, summary, and busy flags
		case reg == 4 && i == 3: // FNINIT
			c.fpuInit()
		case reg == 5: // FUCOMI ST(0), ST(i)
			cmp := c.fpuCompareValues(c.fpuST0(), c.fpuSTi(i), true)
			c.Rflags &^= flagCF | flagZF | flagPF | flagOF | flagSF | flagAF
			switch cmp {
			case -1:
				c.Rflags |= flagCF
			case 0:
				c.Rflags |= flagZF
			case 2:
				c.Rflags |= flagCF | flagZF | flagPF
			}
		case reg == 6: // FCOMI ST(0), ST(i)
			cmp := c.fpuCompareValues(c.fpuST0(), c.fpuSTi(i), false)
			c.Rflags &^= flagCF | flagZF | flagPF | flagOF | flagSF | flagAF
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
			c.fpuSetSTiResult(i, c.fpuAdd(c.fpuSTi(i), c.fpuST0()))
		case 1: // FMUL ST(i), ST(0)
			c.fpuSetSTiResult(i, c.fpuMultiply(c.fpuSTi(i), c.fpuST0()))
		case 4: // FSUBR ST(i), ST(0)
			c.fpuSetSTiResult(i, c.fpuSubtract(c.fpuST0(), c.fpuSTi(i)))
		case 5: // FSUB ST(i), ST(0)
			c.fpuSetSTiResult(i, c.fpuSubtract(c.fpuSTi(i), c.fpuST0()))
		case 6: // FDIVR ST(i), ST(0)
			c.fpuSetSTiResult(i, c.fpuDivide(c.fpuST0(), c.fpuSTi(i)))
		case 7: // FDIV ST(i), ST(0)
			c.fpuSetSTiResult(i, c.fpuDivide(c.fpuSTi(i), c.fpuST0()))
		}
	case 0xDD:
		switch reg {
		case 0: // FFREE ST(i)
			c.fpuSetTag(c.fpuPhys(i), 3)
		case 2: // FST ST(i)
			c.fpuSetSTi(i, c.fpuST0())
		case 3: // FSTP ST(i)
			c.fpuSetSTi(i, c.fpuST0())
			c.fpuPop()
		case 4: // FUCOM ST(i)
			c.fpuSetCC(c.fpuCompareValues(c.fpuST0(), c.fpuSTi(i), true))
		case 5: // FUCOMP ST(i)
			c.fpuSetCC(c.fpuCompareValues(c.fpuST0(), c.fpuSTi(i), true))
			c.fpuPop()
		}
	case 0xDE: // register: ST(i) op= ST(0), pop
		switch reg {
		case 0: // FADDP ST(i), ST(0)
			c.fpuSetSTiResult(i, c.fpuAdd(c.fpuSTi(i), c.fpuST0()))
			c.fpuPop()
		case 1: // FMULP ST(i), ST(0)
			c.fpuSetSTiResult(i, c.fpuMultiply(c.fpuSTi(i), c.fpuST0()))
			c.fpuPop()
		case 3 & 0x07: // FCOMPP (DE D9 specifically: reg=3, rm=1)
			if i == 1 {
				c.fpuSetCC(c.fpuCompareValues(c.fpuST0(), c.fpuSTi(1), false))
				c.fpuPop()
				c.fpuPop()
			}
		case 4: // FSUBRP ST(i), ST(0)
			c.fpuSetSTiResult(i, c.fpuSubtract(c.fpuST0(), c.fpuSTi(i)))
			c.fpuPop()
		case 5: // FSUBP ST(i), ST(0)
			c.fpuSetSTiResult(i, c.fpuSubtract(c.fpuSTi(i), c.fpuST0()))
			c.fpuPop()
		case 6: // FDIVRP ST(i), ST(0)
			c.fpuSetSTiResult(i, c.fpuDivide(c.fpuST0(), c.fpuSTi(i)))
			c.fpuPop()
		case 7: // FDIVP ST(i), ST(0)
			c.fpuSetSTiResult(i, c.fpuDivide(c.fpuSTi(i), c.fpuST0()))
			c.fpuPop()
		}
	case 0xDF:
		switch {
		case reg == 4 && i == 0: // FNSTSW AX
			sw := c.fpuSW | uint16(c.fpuTop<<11)
			c.Regs[RAX] = (c.Regs[RAX] &^ 0xFFFF) | uint64(sw)
		case reg == 5: // FUCOMIP ST(0), ST(i)
			cmp := c.fpuCompareValues(c.fpuST0(), c.fpuSTi(i), true)
			c.Rflags &^= flagCF | flagZF | flagPF | flagOF | flagSF | flagAF
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
			cmp := c.fpuCompareValues(c.fpuST0(), c.fpuSTi(i), false)
			c.Rflags &^= flagCF | flagZF | flagPF | flagOF | flagSF | flagAF
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

func x87RegNeedsST0(op byte, reg int, rm int, c *CPU) bool {
	switch op {
	case 0xD8, 0xDC, 0xDE:
		return true
	case 0xD9:
		return reg == 0 && c.fpuEmpty(rm) || reg == 1 || reg == 4 || reg == 6 && rm < 6 || reg == 7
	case 0xDA:
		switch reg {
		case 5:
			return rm == 1
		case 0:
			return c.Rflags&flagCF != 0
		case 1:
			return c.Rflags&flagZF != 0
		case 2:
			return c.Rflags&(flagCF|flagZF) != 0
		case 3:
			return c.Rflags&flagPF != 0
		}
	case 0xDB:
		switch reg {
		case 5, 6:
			return true
		case 0:
			return c.Rflags&flagCF == 0
		case 1:
			return c.Rflags&flagZF == 0
		case 2:
			return c.Rflags&(flagCF|flagZF) == 0
		case 3:
			return c.Rflags&flagPF == 0
		}
	case 0xDD:
		return reg >= 2 && reg <= 5
	case 0xDF:
		return reg == 5 || reg == 6
	}
	return false
}

func x87RegFormImplemented(op byte, reg int, rm int) bool {
	switch op {
	case 0xD8:
		return reg < 8
	case 0xD9:
		switch reg {
		case 0, 1, 6, 7:
			return true
		case 4:
			return rm == 0 || rm == 1 || rm == 4 || rm == 5
		case 5:
			return rm < 7
		}
	case 0xDA:
		return reg < 4 || reg == 5 && rm == 1
	case 0xDB:
		return reg < 4 || reg == 4 && (rm == 2 || rm == 3) || reg == 5 || reg == 6
	case 0xDC:
		return reg == 0 || reg == 1 || reg >= 4
	case 0xDD:
		return reg == 0 || reg >= 2 && reg <= 5
	case 0xDE:
		return reg == 0 || reg == 1 || reg >= 4 || reg == 3 && rm == 1
	case 0xDF:
		return reg == 4 && rm == 0 || reg == 5 || reg == 6
	}
	return false
}

// fpuRoundPrecision applies the representable precision selected by CW.
func fpuRoundPrecision(val float64, cw uint16) float64 {
	switch (cw >> 8) & 3 {
	case 0:
		return fpuRoundFloat32(val, cw)
	case 2, 3:
		return val
	default:
		return val
	}
}

func fpuRoundToInt(val float64, cw uint16) int64 {
	rounded := fpuRoundFloat(val, cw)
	if math.IsNaN(rounded) || math.IsInf(rounded, 0) || rounded >= float64(1<<63) || rounded < -float64(1<<63) {
		return -1 << 63
	}
	return int64(rounded)
}

func fpuRoundFloat(val float64, cw uint16) float64 {
	mode := (cw >> 10) & 3
	switch mode {
	case 0: // Round to nearest even
		return math.RoundToEven(val)
	case 1: // Round down (toward -infinity)
		return math.Floor(val)
	case 2: // Round up (toward +infinity)
		return math.Ceil(val)
	case 3: // Truncate (toward 0)
		return math.Trunc(val)
	}
	return val
}

func fpuConvertInt(val float64, bits int, trunc bool, c *CPU) int64 {
	if math.IsNaN(val) || math.IsInf(val, 0) {
		c.fpuSignal(fpuExcInvalid, false)
		if bits == 16 {
			return -32768
		}
		if bits == 32 {
			return -1 << 31
		}
		return -1 << 63
	}
	if !trunc {
		val = fpuRoundFloat(val, c.fpuCW)
	} else {
		val = math.Trunc(val)
	}
	min := -math.Ldexp(1, bits-1)
	max := math.Ldexp(1, bits-1) - 1
	outOfRange := val < min || val > max
	if bits == 64 {
		outOfRange = val < -math.Ldexp(1, 63) || val >= math.Ldexp(1, 63)
	}
	if outOfRange {
		c.fpuSignal(fpuExcInvalid, false)
		if bits == 16 {
			return -32768
		}
		if bits == 32 {
			return -1 << 31
		}
		return -1 << 63
	}
	return int64(val)
}

func fpuConvertIntForStore(val float64, bits int, trunc bool, c *CPU) (int64, bool) {
	rounded := val
	if trunc {
		rounded = math.Trunc(val)
	} else {
		rounded = fpuRoundFloat(val, c.fpuCW)
	}
	invalid := math.IsNaN(rounded) || math.IsInf(rounded, 0)
	if !invalid {
		min := -math.Ldexp(1, bits-1)
		max := math.Ldexp(1, bits-1) - 1
		if bits == 64 {
			invalid = rounded < -math.Ldexp(1, 63) || rounded >= math.Ldexp(1, 63)
		} else {
			invalid = rounded < min || rounded > max
		}
	}
	converted := fpuConvertInt(val, bits, trunc, c)
	return converted, invalid && c.fpuCW&fpuExcInvalid == 0
}

// float80ToFloat64 converts an 80-bit extended precision float to float64.
// lo = lower 64 bits (mantissa), hi = upper 16 bits (sign + exponent).
func float80ToFloat64(lo uint64, hi uint16) float64 {
	return float80ToFloat64Value(lo, hi)
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

// float80ToFloat64Value converts the 80-bit value to Raven's float64 storage.
// Extended subnormals below the float64 range become signed zero, while normal
// values that fit the float64 exponent range retain their sign and value.
func float80ToFloat64Value(lo uint64, hi uint16) float64 {
	sign := hi>>15 != 0
	signValue := 1.0
	if sign {
		signValue = -1
	}
	expField := hi & 0x7FFF
	if expField == 0 {
		if lo == 0 {
			return math.Copysign(0, signValue)
		}
		return math.Copysign(0, signValue)
	}
	if expField == 0x7FFF {
		if lo == 0x8000000000000000 {
			return math.Copysign(math.Inf(1), signValue)
		}
		return math.NaN()
	}
	if lo&0x8000000000000000 == 0 {
		return math.NaN()
	}
	v := math.Ldexp(float64(lo), int(expField)-16383-63)
	return math.Copysign(v, signValue)
}

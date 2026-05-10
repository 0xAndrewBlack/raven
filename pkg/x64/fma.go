package x64

import (
	"fmt"
	"math"
)

func (c *CPU) execVEXScalarFMA(vex *vexState, pfx *prefixState, opcode byte, startRIP uint64) error {
	if vex.pp != 1 {
		return fmt.Errorf("invalid scalar FMA encoding at RIP=0x%x", startRIP)
	}

	m, err := c.decodeModRM(pfx)
	if err != nil {
		return err
	}

	dst := m.reg
	src1 := vex.vvvv
	isDouble := vex.W
	var src2Bits uint64
	if m.mod == 3 {
		src2Bits = c.XMM[m.rm][0]
	} else {
		addr, _, err := c.resolveRMAddr(m, pfx)
		if err != nil {
			return err
		}
		if isDouble {
			src2Bits, err = c.mem.Read64(addr)
		} else {
			var value uint32
			value, err = c.mem.Read32(addr)
			src2Bits = uint64(value)
		}
		if err != nil {
			return err
		}
	}

	order := (opcode >> 4) - 9
	operation := (opcode - 9) & 0x0F
	if order > 2 || operation != 0 && operation != 2 && operation != 4 && operation != 6 {
		return fmt.Errorf("unsupported scalar FMA opcode 0x%02X at RIP=0x%x", opcode, startRIP)
	}

	if isDouble {
		a := math.Float64frombits(c.XMM[dst][0])
		b := math.Float64frombits(c.XMM[src1][0])
		d := math.Float64frombits(src2Bits)
		c.XMM[dst][0] = math.Float64bits(scalarFMA64(order, operation, a, b, d))
	} else {
		a := math.Float32frombits(uint32(c.XMM[dst][0]))
		b := math.Float32frombits(uint32(c.XMM[src1][0]))
		d := math.Float32frombits(uint32(src2Bits))
		result := uint64(math.Float32bits(scalarFMA32(order, operation, a, b, d)))
		c.XMM[dst][0] = c.XMM[dst][0]&0xFFFFFFFF00000000 | result
	}
	c.YMM_hi[dst] = [2]uint64{}
	return nil
}

func scalarFMA64(order, operation byte, a, b, c float64) float64 {
	x, y, z := scalarFMAOperands(order, a, b, c)
	switch operation {
	case 0:
		return math.FMA(x, y, z)
	case 2:
		return math.FMA(x, y, -z)
	case 4:
		return math.FMA(-x, y, z)
	default:
		return math.FMA(-x, y, -z)
	}
}

func scalarFMA32(order, operation byte, a, b, c float32) float32 {
	x, y, z := scalarFMAOperands(order, float64(a), float64(b), float64(c))
	switch operation {
	case 0:
		return float32(math.FMA(x, y, z))
	case 2:
		return float32(math.FMA(x, y, -z))
	case 4:
		return float32(math.FMA(-x, y, z))
	default:
		return float32(math.FMA(-x, y, -z))
	}
}

func scalarFMAOperands(order byte, a, b, c float64) (float64, float64, float64) {
	switch order {
	case 0:
		return a, c, b
	case 1:
		return a, b, c
	default:
		return b, c, a
	}
}

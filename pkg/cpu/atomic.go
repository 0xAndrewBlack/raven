package cpu

import "fmt"

// execAtomic handles the A-extension instructions (opcode 0x2F).
// In a single-hart emulator, LR/SC are trivially correct and
// AMO ops are simple read-modify-write.
func (c *CPU) execAtomic(instr uint32) error {
	funct3 := (instr >> 12) & 0x7
	funct5 := instr >> 27
	rd := (instr >> 7) & 0x1F
	rs1 := (instr >> 15) & 0x1F
	rs2 := (instr >> 20) & 0x1F

	addr := c.readReg(rs1)

	switch funct3 {
	case 0x2: // 32-bit atomics
		return c.execAtomic32(funct5, rd, rs2, addr)
	case 0x3: // 64-bit atomics
		return c.execAtomic64(funct5, rd, rs2, addr)
	default:
		return fmt.Errorf("unknown atomic funct3=0x%x at PC=0x%x", funct3, c.PC)
	}
}

func (c *CPU) execAtomic32(funct5, rd, rs2 uint32, addr uint64) error {
	switch funct5 {
	case 0x02: // LR.W
		val, err := c.Mem.Read32(addr)
		if err != nil {
			return err
		}
		c.writeReg(rd, uint64(int64(int32(val))))
		c.reservation = addr
		c.hasReservation = true

	case 0x03: // SC.W
		if c.hasReservation && c.reservation == addr {
			if err := c.Mem.Write32(addr, uint32(c.readReg(rs2))); err != nil {
				return err
			}
			c.writeReg(rd, 0) // success
		} else {
			c.writeReg(rd, 1) // failure
		}
		c.hasReservation = false

	default:
		// AMO.W operations
		old, err := c.Mem.Read32(addr)
		if err != nil {
			return err
		}
		src := uint32(c.readReg(rs2))
		var result uint32

		switch funct5 {
		case 0x01: // AMOSWAP.W
			result = src
		case 0x00: // AMOADD.W
			result = old + src
		case 0x04: // AMOXOR.W
			result = old ^ src
		case 0x0C: // AMOAND.W
			result = old & src
		case 0x08: // AMOOR.W
			result = old | src
		case 0x10: // AMOMIN.W
			if int32(old) < int32(src) {
				result = old
			} else {
				result = src
			}
		case 0x14: // AMOMAX.W
			if int32(old) > int32(src) {
				result = old
			} else {
				result = src
			}
		case 0x18: // AMOMINU.W
			if old < src {
				result = old
			} else {
				result = src
			}
		case 0x1C: // AMOMAXU.W
			if old > src {
				result = old
			} else {
				result = src
			}
		default:
			return fmt.Errorf("unknown AMO.W funct5=0x%02x at PC=0x%x", funct5, c.PC)
		}

		if err := c.Mem.Write32(addr, result); err != nil {
			return err
		}
		c.writeReg(rd, uint64(int64(int32(old))))
	}

	c.PC += 4
	return nil
}

func (c *CPU) execAtomic64(funct5, rd, rs2 uint32, addr uint64) error {
	switch funct5 {
	case 0x02: // LR.D
		val, err := c.Mem.Read64(addr)
		if err != nil {
			return err
		}
		c.writeReg(rd, val)
		c.reservation = addr
		c.hasReservation = true

	case 0x03: // SC.D
		if c.hasReservation && c.reservation == addr {
			if err := c.Mem.Write64(addr, c.readReg(rs2)); err != nil {
				return err
			}
			c.writeReg(rd, 0) // success
		} else {
			c.writeReg(rd, 1) // failure
		}
		c.hasReservation = false

	default:
		// AMO.D operations
		old, err := c.Mem.Read64(addr)
		if err != nil {
			return err
		}
		src := c.readReg(rs2)
		var result uint64

		switch funct5 {
		case 0x01: // AMOSWAP.D
			result = src
		case 0x00: // AMOADD.D
			result = old + src
		case 0x04: // AMOXOR.D
			result = old ^ src
		case 0x0C: // AMOAND.D
			result = old & src
		case 0x08: // AMOOR.D
			result = old | src
		case 0x10: // AMOMIN.D
			if int64(old) < int64(src) {
				result = old
			} else {
				result = src
			}
		case 0x14: // AMOMAX.D
			if int64(old) > int64(src) {
				result = old
			} else {
				result = src
			}
		case 0x18: // AMOMINU.D
			if old < src {
				result = old
			} else {
				result = src
			}
		case 0x1C: // AMOMAXU.D
			if old > src {
				result = old
			} else {
				result = src
			}
		default:
			return fmt.Errorf("unknown AMO.D funct5=0x%02x at PC=0x%x", funct5, c.PC)
		}

		if err := c.Mem.Write64(addr, result); err != nil {
			return err
		}
		c.writeReg(rd, old)
	}

	c.PC += 4
	return nil
}

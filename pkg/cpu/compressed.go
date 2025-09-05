package cpu

import "fmt"

// stepCompressed decodes and executes a 16-bit RVC instruction.
// Reference: RISC-V ISA Manual, Chapter 16 (RV64C)
func (c *CPU) stepCompressed(instr uint16) error {
	op := instr & 0x3   // quadrant
	funct3 := (instr >> 13) & 0x7

	switch op {
	case 0x0: // Quadrant 0
		return c.execCQ0(instr, funct3)
	case 0x1: // Quadrant 1
		return c.execCQ1(instr, funct3)
	case 0x2: // Quadrant 2
		return c.execCQ2(instr, funct3)
	}
	return fmt.Errorf("invalid compressed quadrant %d at PC=0x%x", op, c.PC)
}

// --- Quadrant 0 ---

func (c *CPU) execCQ0(instr uint16, funct3 uint16) error {
	switch funct3 {
	case 0x0: // C.ADDI4SPN
		rd := crdp(instr)
		// nzuimm encoded in bits [12:5], [4:2] → scaled by 4
		imm := uint64(ciwImm(instr))
		if imm == 0 {
			return fmt.Errorf("illegal C.ADDI4SPN imm=0 at PC=0x%x", c.PC)
		}
		c.writeReg(rd, c.readReg(2)+imm)
		c.PC += 2

	case 0x1: // C.FLD
		rs1 := crsp(instr)
		rd := crdp(instr)
		offset := uint64(cldImm(instr))
		val, err := c.Mem.Read64(c.readReg(rs1) + offset)
		if err != nil {
			return err
		}
		c.fpu.F[rd] = val
		c.PC += 2

	case 0x2: // C.LW
		rs1 := crsp(instr)
		rd := crdp(instr)
		offset := uint64(clwImm(instr))
		val, err := c.Mem.Read32(c.readReg(rs1) + offset)
		if err != nil {
			return err
		}
		c.writeReg(rd, uint64(int64(int32(val))))
		c.PC += 2

	case 0x3: // C.LD
		rs1 := crsp(instr)
		rd := crdp(instr)
		offset := uint64(cldImm(instr))
		val, err := c.Mem.Read64(c.readReg(rs1) + offset)
		if err != nil {
			return err
		}
		c.writeReg(rd, val)
		c.PC += 2

	case 0x5: // C.FSD
		rs1 := crsp(instr)
		rs2 := crdp(instr)
		offset := uint64(cldImm(instr))
		if err := c.Mem.Write64(c.readReg(rs1)+offset, c.fpu.F[rs2]); err != nil {
			return err
		}
		c.PC += 2

	case 0x6: // C.SW
		rs1 := crsp(instr)
		rs2 := crdp(instr)
		offset := uint64(clwImm(instr))
		if err := c.Mem.Write32(c.readReg(rs1)+offset, uint32(c.readReg(rs2))); err != nil {
			return err
		}
		c.PC += 2

	case 0x7: // C.SD
		rs1 := crsp(instr)
		rs2 := crdp(instr)
		offset := uint64(cldImm(instr))
		if err := c.Mem.Write64(c.readReg(rs1)+offset, c.readReg(rs2)); err != nil {
			return err
		}
		c.PC += 2

	default:
		return fmt.Errorf("unimplemented CQ0 funct3=0x%x at PC=0x%x", funct3, c.PC)
	}
	return nil
}

// --- Quadrant 1 ---

func (c *CPU) execCQ1(instr uint16, funct3 uint16) error {
	switch funct3 {
	case 0x0: // C.NOP / C.ADDI
		rd := uint32((instr >> 7) & 0x1F)
		imm := cimmCI(instr)
		c.writeReg(rd, uint64(int64(c.readReg(rd))+int64(imm)))
		c.PC += 2

	case 0x1: // C.ADDIW
		rd := uint32((instr >> 7) & 0x1F)
		imm := cimmCI(instr)
		result := int32(c.readReg(rd)) + int32(imm)
		c.writeReg(rd, uint64(int64(result)))
		c.PC += 2

	case 0x2: // C.LI
		rd := uint32((instr >> 7) & 0x1F)
		imm := cimmCI(instr)
		c.writeReg(rd, uint64(imm))
		c.PC += 2

	case 0x3: // C.LUI / C.ADDI16SP
		rd := uint32((instr >> 7) & 0x1F)
		if rd == 2 {
			// C.ADDI16SP
			imm := caddi16spImm(instr)
			c.writeReg(2, uint64(int64(c.readReg(2))+int64(imm)))
		} else {
			// C.LUI
			imm := cluiImm(instr)
			c.writeReg(rd, uint64(imm))
		}
		c.PC += 2

	case 0x4: // ALU group (C.SRLI, C.SRAI, C.ANDI, C.SUB, C.XOR, C.OR, C.AND, C.SUBW, C.ADDW)
		return c.execCQ1Alu(instr)

	case 0x5: // C.J
		imm := cjImm(instr)
		c.PC = uint64(int64(c.PC) + int64(imm))

	case 0x6: // C.BEQZ
		rs1 := crsp(instr)
		imm := cbImm(instr)
		if c.readReg(rs1) == 0 {
			c.PC = uint64(int64(c.PC) + int64(imm))
		} else {
			c.PC += 2
		}

	case 0x7: // C.BNEZ
		rs1 := crsp(instr)
		imm := cbImm(instr)
		if c.readReg(rs1) != 0 {
			c.PC = uint64(int64(c.PC) + int64(imm))
		} else {
			c.PC += 2
		}
	}
	return nil
}

func (c *CPU) execCQ1Alu(instr uint16) error {
	funct2 := (instr >> 10) & 0x3
	rd := crsp(instr) // also rs1

	switch funct2 {
	case 0x0: // C.SRLI
		shamt := cshamt(instr)
		c.writeReg(rd, c.readReg(rd)>>shamt)
		c.PC += 2

	case 0x1: // C.SRAI
		shamt := cshamt(instr)
		c.writeReg(rd, uint64(int64(c.readReg(rd))>>shamt))
		c.PC += 2

	case 0x2: // C.ANDI
		imm := cimmCI(instr)
		c.writeReg(rd, c.readReg(rd)&uint64(imm))
		c.PC += 2

	case 0x3: // register-register ops
		rs2 := crdp(instr)
		funct1 := (instr >> 12) & 0x1
		funct2b := (instr >> 5) & 0x3

		if funct1 == 0 {
			switch funct2b {
			case 0x0: // C.SUB
				c.writeReg(rd, c.readReg(rd)-c.readReg(rs2))
			case 0x1: // C.XOR
				c.writeReg(rd, c.readReg(rd)^c.readReg(rs2))
			case 0x2: // C.OR
				c.writeReg(rd, c.readReg(rd)|c.readReg(rs2))
			case 0x3: // C.AND
				c.writeReg(rd, c.readReg(rd)&c.readReg(rs2))
			}
		} else {
			switch funct2b {
			case 0x0: // C.SUBW
				result := int32(c.readReg(rd)) - int32(c.readReg(rs2))
				c.writeReg(rd, uint64(int64(result)))
			case 0x1: // C.ADDW
				result := int32(c.readReg(rd)) + int32(c.readReg(rs2))
				c.writeReg(rd, uint64(int64(result)))
			default:
				return fmt.Errorf("reserved CQ1 ALU funct2b=%d at PC=0x%x", funct2b, c.PC)
			}
		}
		c.PC += 2
	}
	return nil
}

// --- Quadrant 2 ---

func (c *CPU) execCQ2(instr uint16, funct3 uint16) error {
	switch funct3 {
	case 0x0: // C.SLLI
		rd := uint32((instr >> 7) & 0x1F)
		shamt := cshamt(instr)
		c.writeReg(rd, c.readReg(rd)<<shamt)
		c.PC += 2

	case 0x1: // C.FLDSP
		rd := uint32((instr >> 7) & 0x1F)
		offset := cldspImm(instr)
		val, err := c.Mem.Read64(c.readReg(2) + uint64(offset))
		if err != nil {
			return err
		}
		c.fpu.F[rd] = val
		c.PC += 2

	case 0x2: // C.LWSP
		rd := uint32((instr >> 7) & 0x1F)
		offset := clwspImm(instr)
		val, err := c.Mem.Read32(c.readReg(2) + uint64(offset))
		if err != nil {
			return err
		}
		c.writeReg(rd, uint64(int64(int32(val))))
		c.PC += 2

	case 0x3: // C.LDSP
		rd := uint32((instr >> 7) & 0x1F)
		offset := cldspImm(instr)
		val, err := c.Mem.Read64(c.readReg(2) + uint64(offset))
		if err != nil {
			return err
		}
		c.writeReg(rd, val)
		c.PC += 2

	case 0x4: // C.JR / C.MV / C.EBREAK / C.JALR / C.ADD
		bit12 := (instr >> 12) & 0x1
		rd := uint32((instr >> 7) & 0x1F)
		rs2 := uint32((instr >> 2) & 0x1F)

		if bit12 == 0 {
			if rs2 == 0 {
				// C.JR
				target := c.readReg(rd) & ^uint64(1)
				c.PC = target
			} else {
				// C.MV
				c.writeReg(rd, c.readReg(rs2))
				c.PC += 2
			}
		} else {
			if rd == 0 && rs2 == 0 {
				// C.EBREAK
				c.running = false
			} else if rs2 == 0 {
				// C.JALR
				t := c.readReg(rd) & ^uint64(1)
				c.writeReg(1, c.PC+2)
				c.PC = t
			} else {
				// C.ADD
				c.writeReg(rd, c.readReg(rd)+c.readReg(rs2))
				c.PC += 2
			}
		}

	case 0x5: // C.FSDSP
		rs2 := uint32((instr >> 2) & 0x1F)
		offset := csdspImm(instr)
		if err := c.Mem.Write64(c.readReg(2)+uint64(offset), c.fpu.F[rs2]); err != nil {
			return err
		}
		c.PC += 2

	case 0x6: // C.SWSP
		rs2 := uint32((instr >> 2) & 0x1F)
		offset := cswspImm(instr)
		if err := c.Mem.Write32(c.readReg(2)+uint64(offset), uint32(c.readReg(rs2))); err != nil {
			return err
		}
		c.PC += 2

	case 0x7: // C.SDSP
		rs2 := uint32((instr >> 2) & 0x1F)
		offset := csdspImm(instr)
		if err := c.Mem.Write64(c.readReg(2)+uint64(offset), c.readReg(rs2)); err != nil {
			return err
		}
		c.PC += 2

	default:
		return fmt.Errorf("unimplemented CQ2 funct3=0x%x at PC=0x%x", funct3, c.PC)
	}
	return nil
}

// --- Compressed immediate extraction helpers ---

// crdp returns the "prime" destination register (bits [4:2] → x8-x15).
func crdp(instr uint16) uint32 {
	return uint32((instr>>2)&0x7) + 8
}

// crsp returns the "prime" source register (bits [9:7] → x8-x15).
func crsp(instr uint16) uint32 {
	return uint32((instr>>7)&0x7) + 8
}

// cimmCI extracts the sign-extended 6-bit CI-format immediate.
func cimmCI(instr uint16) int64 {
	imm := int64((instr >> 2) & 0x1F)
	if instr&(1<<12) != 0 {
		imm |= ^int64(0x1F) // sign-extend bit 5
	}
	return imm
}

// cshamt extracts the 6-bit shift amount from CI-format.
func cshamt(instr uint16) uint64 {
	return uint64((instr>>2)&0x1F) | uint64((instr>>12)&1)<<5
}

// ciwImm extracts C.ADDI4SPN immediate (CIW-format): scaled by 4.
func ciwImm(instr uint16) uint32 {
	// [5:4] ← instr[12:11], [9:6] ← instr[10:7], [2] ← instr[6], [3] ← instr[5]
	return (uint32((instr>>6)&1) << 2) |
		(uint32((instr>>5)&1) << 3) |
		(uint32((instr>>11)&0x3) << 4) |
		(uint32((instr>>7)&0xF) << 6)
}

// clwImm extracts CL-format offset for LW/SW (scaled by 4).
func clwImm(instr uint16) uint32 {
	// offset[5:3] ← instr[12:10], offset[2] ← instr[6], offset[6] ← instr[5]
	return (uint32((instr>>6)&1) << 2) |
		(uint32((instr>>10)&0x7) << 3) |
		(uint32((instr>>5)&1) << 6)
}

// cldImm extracts CL-format offset for LD/SD (scaled by 8).
func cldImm(instr uint16) uint32 {
	// offset[5:3] ← instr[12:10], offset[7:6] ← instr[6:5]
	return (uint32((instr>>10)&0x7) << 3) |
		(uint32((instr>>5)&0x3) << 6)
}

// caddi16spImm extracts the C.ADDI16SP immediate (scaled by 16).
func caddi16spImm(instr uint16) int64 {
	imm := int64(0)
	imm |= int64((instr>>6)&1) << 4
	imm |= int64((instr>>2)&1) << 5
	imm |= int64((instr>>5)&1) << 6
	imm |= int64((instr>>3)&0x3) << 7
	imm |= int64((instr>>12)&1) << 9
	if imm&(1<<9) != 0 {
		imm |= ^int64(0x1FF) // sign-extend
	}
	return imm
}

// cluiImm extracts C.LUI immediate.
func cluiImm(instr uint16) int64 {
	imm := int64((instr>>2)&0x1F) << 12
	if instr&(1<<12) != 0 {
		imm |= ^int64(0x1FFFF) // sign-extend bit 17
	}
	return imm
}

// cjImm extracts C.J immediate (11-bit signed, scaled by 2).
func cjImm(instr uint16) int64 {
	// [11] ← instr[12], [4] ← instr[11], [9:8] ← instr[10:9], [10] ← instr[8],
	// [6] ← instr[7], [7] ← instr[6], [3:1] ← instr[5:3], [5] ← instr[2]
	imm := int64(0)
	imm |= int64((instr>>3)&0x7) << 1
	imm |= int64((instr>>2)&1) << 5
	imm |= int64((instr>>7)&1) << 6
	imm |= int64((instr>>6)&1) << 7
	imm |= int64((instr>>9)&0x3) << 8
	imm |= int64((instr>>8)&1) << 10
	imm |= int64((instr>>11)&1) << 4
	if instr&(1<<12) != 0 {
		imm |= ^int64(0x7FF) // sign-extend bit 11
	}
	return imm
}

// cbImm extracts C.BEQZ/C.BNEZ branch offset (8-bit signed, scaled by 2).
func cbImm(instr uint16) int64 {
	imm := int64(0)
	imm |= int64((instr>>3)&0x3) << 1
	imm |= int64((instr>>10)&0x3) << 3
	imm |= int64((instr>>2)&1) << 5
	imm |= int64((instr>>5)&0x3) << 6
	if instr&(1<<12) != 0 {
		imm |= ^int64(0xFF) // sign-extend bit 8
	}
	return imm
}

// clwspImm extracts C.LWSP offset (zero-extended, scaled by 4).
func clwspImm(instr uint16) uint32 {
	return (uint32((instr>>4)&0x7) << 2) |
		(uint32((instr>>12)&1) << 5) |
		(uint32((instr>>2)&0x3) << 6)
}

// cldspImm extracts C.LDSP offset (zero-extended, scaled by 8).
func cldspImm(instr uint16) uint32 {
	return (uint32((instr>>5)&0x3) << 3) |
		(uint32((instr>>12)&1) << 5) |
		(uint32((instr>>2)&0x7) << 6)
}

// cswspImm extracts C.SWSP offset (zero-extended, scaled by 4).
func cswspImm(instr uint16) uint32 {
	return (uint32((instr>>9)&0xF) << 2) |
		(uint32((instr>>7)&0x3) << 6)
}

// csdspImm extracts C.SDSP offset (zero-extended, scaled by 8).
func csdspImm(instr uint16) uint32 {
	return (uint32((instr>>10)&0x7) << 3) |
		(uint32((instr>>7)&0x7) << 6)
}

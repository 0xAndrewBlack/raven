package cpu

import "time"

// CSR addresses (user-level)
const (
	CSR_FFLAGS    = 0x001
	CSR_FRM       = 0x002
	CSR_FCSR      = 0x003
	CSR_CYCLE     = 0xC00
	CSR_TIME      = 0xC01
	CSR_INSTRET   = 0xC02
	CSR_CYCLEH    = 0xC80
	CSR_TIMEH     = 0xC81
	CSR_INSTRETH  = 0xC82
)

// CSRFile holds the CSR state for one hart.
type CSRFile struct {
	startTime time.Time
}

func (c *CPU) initCSR() {
	if c.csr.startTime.IsZero() {
		c.csr.startTime = time.Now()
	}
}

// readCSR returns the value of a CSR.
func (c *CPU) readCSR(addr uint32) uint64 {
	c.initCSR()
	switch addr {
	case CSR_FFLAGS:
		return uint64(c.fpu.fflags())
	case CSR_FRM:
		return uint64(c.fpu.frm())
	case CSR_FCSR:
		return uint64(c.fpu.FCSR)
	case CSR_CYCLE, CSR_INSTRET:
		return c.Instret
	case CSR_TIME:
		return uint64(time.Since(c.csr.startTime).Nanoseconds())
	case CSR_CYCLEH, CSR_INSTRETH:
		return c.Instret >> 32
	case CSR_TIMEH:
		return uint64(time.Since(c.csr.startTime).Nanoseconds()) >> 32
	default:
		return 0
	}
}

// writeCSR sets a CSR value.
func (c *CPU) writeCSR(addr uint32, val uint64) {
	switch addr {
	case CSR_FFLAGS:
		c.fpu.FCSR = (c.fpu.FCSR & 0xE0) | uint32(val&0x1F)
	case CSR_FRM:
		c.fpu.FCSR = (c.fpu.FCSR & 0x1F) | (uint32(val&0x7) << 5)
	case CSR_FCSR:
		c.fpu.FCSR = uint32(val & 0xFF)
	}
}

// execCSR handles CSRRW, CSRRS, CSRRC and their immediate variants.
func (c *CPU) execCSR(instr uint32, funct3 uint32) {
	rd := (instr >> 7) & 0x1F
	csrAddr := instr >> 20
	rs1 := (instr >> 15) & 0x1F

	old := c.readCSR(csrAddr)

	switch funct3 {
	case 1: // CSRRW
		c.writeCSR(csrAddr, c.readReg(rs1))
		c.writeReg(rd, old)
	case 2: // CSRRS
		if rs1 != 0 {
			c.writeCSR(csrAddr, old|c.readReg(rs1))
		}
		c.writeReg(rd, old)
	case 3: // CSRRC
		if rs1 != 0 {
			c.writeCSR(csrAddr, old & ^c.readReg(rs1))
		}
		c.writeReg(rd, old)
	case 5: // CSRRWI
		zimm := uint64(rs1) // rs1 field is the immediate
		c.writeCSR(csrAddr, zimm)
		c.writeReg(rd, old)
	case 6: // CSRRSI
		zimm := uint64(rs1)
		if zimm != 0 {
			c.writeCSR(csrAddr, old|zimm)
		}
		c.writeReg(rd, old)
	case 7: // CSRRCI
		zimm := uint64(rs1)
		if zimm != 0 {
			c.writeCSR(csrAddr, old & ^zimm)
		}
		c.writeReg(rd, old)
	}
	c.PC += 4
}

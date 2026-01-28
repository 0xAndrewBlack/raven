package cpu

import (
	"fmt"

	"github.com/mirkobrombin/Raven/pkg/arch"
	"github.com/mirkobrombin/Raven/pkg/mmu"
)

// CPU represents a single RISC-V RV64GC hardware thread.
type CPU struct {
	X  [32]uint64 // general-purpose registers (x0 is hardwired to 0)
	PC uint64

	Mem     *mmu.MMU
	Syscall arch.SyscallHandler

	// Floating-point unit (F+D extensions)
	fpu FPU

	// CSR registers
	csr CSRFile

	// LR/SC reservation
	reservation    uint64
	hasReservation bool

	// Instruction counter for rdinstret
	Instret uint64

	running bool
}

// Verify interface compliance.
var _ arch.CPU = (*CPU)(nil)

// New creates a CPU bound to the given MMU.
func New(mem *mmu.MMU) *CPU {
	return &CPU{
		Mem: mem,
	}
}

// FPUState returns a pointer to the FPU for external access (e.g. thread cloning).
func (c *CPU) FPUState() *FPU { return &c.fpu }

func (c *CPU) GetPC() uint64    { return c.PC }
func (c *CPU) SetPC(addr uint64) { c.PC = addr }
func (c *CPU) GetSP() uint64    { return c.X[2] }
func (c *CPU) SetSP(addr uint64) { c.X[2] = addr }
func (c *CPU) GetTLS() uint64   { return c.X[4] }
func (c *CPU) SetTLS(v uint64)  { c.X[4] = v }

func (c *CPU) SyscallNum() uint64       { return c.X[17] }
func (c *CPU) SyscallArgs() [6]uint64   { return [6]uint64{c.X[10], c.X[11], c.X[12], c.X[13], c.X[14], c.X[15]} }
func (c *CPU) SetSyscallReturn(v uint64) { c.X[10] = v }
func (c *CPU) SyscallReturnPC() uint64  { return c.PC + 4 }

func (c *CPU) GetMem() *mmu.MMU    { return c.Mem }
func (c *CPU) GetInstret() uint64  { return c.Instret }
func (c *CPU) GetArch() arch.Arch  { return arch.ArchRISCV64 }

func (c *CPU) SetSyscallHandler(h arch.SyscallHandler) { c.Syscall = h }

// CloneForThread creates a copy of this CPU sharing the same MMU,
// with register and FPU state duplicated.
func (c *CPU) CloneForThread() arch.CPU {
	n := New(c.Mem)
	n.X = c.X
	n.fpu.F = c.fpu.F
	n.fpu.FCSR = c.fpu.FCSR
	return n
}

// readReg reads a register, enforcing x0 == 0.
func (c *CPU) readReg(r uint32) uint64 {
	if r == 0 {
		return 0
	}
	return c.X[r]
}

// writeReg writes a register (writes to x0 are discarded).
func (c *CPU) writeReg(r uint32, v uint64) {
	if r != 0 {
		c.X[r] = v
	}
}

// Run executes the fetch-decode-execute loop until exit or error.
func (c *CPU) Run() error {
	c.running = true
	for c.running {
		if err := c.Step(); err != nil {
			return err
		}
		c.Instret++
	}
	return nil
}

// Stop halts the CPU loop.
func (c *CPU) Stop() {
	c.running = false
}

// Resume resets the stopped state so Run() can continue after a nested Stop().
func (c *CPU) Resume() {
	c.running = true
}

// Step executes a single instruction (32-bit or 16-bit compressed).
func (c *CPU) Step() error {
	// Fetch first 16 bits to detect compressed vs normal
	half, err := c.Mem.Fetch16(c.PC)
	if err != nil {
		return fmt.Errorf("fetch @ 0x%x: %w", c.PC, err)
	}

	// RV64C: if bits [1:0] != 0b11, this is a 16-bit compressed instruction
	if half&0x3 != 0x3 {
		return c.stepCompressed(half)
	}

	// Normal 32-bit instruction
	instr, err := c.Mem.Fetch32(c.PC)
	if err != nil {
		return fmt.Errorf("fetch32 @ 0x%x: %w", c.PC, err)
	}

	return c.stepFull(instr)
}

// stepFull executes a 32-bit instruction.
func (c *CPU) stepFull(instr uint32) error {
	opcode := instr & 0x7F

	switch opcode {
	case 0x37: // LUI
		rd := (instr >> 7) & 0x1F
		imm := uint64(int64(int32(instr & 0xFFFFF000)))
		c.writeReg(rd, imm)
		c.PC += 4

	case 0x17: // AUIPC
		rd := (instr >> 7) & 0x1F
		imm := uint64(int64(int32(instr & 0xFFFFF000)))
		c.writeReg(rd, c.PC+imm)
		c.PC += 4

	case 0x6F: // JAL
		rd := (instr >> 7) & 0x1F
		imm := immJ(instr)
		c.writeReg(rd, c.PC+4)
		c.PC = uint64(int64(c.PC) + int64(imm))

	case 0x67: // JALR
		rd := (instr >> 7) & 0x1F
		rs1 := (instr >> 15) & 0x1F
		imm := signExtend(uint64(instr>>20), 12)
		target := (c.readReg(rs1) + uint64(imm)) & ^uint64(1)
		c.writeReg(rd, c.PC+4)
		c.PC = target

	case 0x63: // Branch
		if err := c.execBranch(instr); err != nil {
			return err
		}

	case 0x03: // Load
		if err := c.execLoad(instr); err != nil {
			return err
		}

	case 0x23: // Store
		if err := c.execStore(instr); err != nil {
			return err
		}

	case 0x13: // OP-IMM (ADDI, SLTI, etc.)
		c.execOpImm(instr)

	case 0x1B: // OP-IMM-32 (ADDIW, SLLIW, SRLIW, SRAIW)
		c.execOpImm32(instr)

	case 0x33: // OP (ADD, SUB, etc.)
		c.execOp(instr)

	case 0x3B: // OP-32 (ADDW, SUBW, SLLW, SRLW, SRAW)
		c.execOp32(instr)

	case 0x73: // SYSTEM (ECALL, EBREAK, CSR)
		funct3 := (instr >> 12) & 0x7
		if funct3 == 0 {
			immField := instr >> 20
			if immField == 0 {
				// ECALL
				if c.Syscall != nil {
					c.Syscall(c)
				}
				c.PC += 4
			} else if immField == 1 {
				// EBREAK - treat as halt
				c.running = false
			} else if immField == 0x105 {
				// WFI - no-op in user mode
				c.PC += 4
			} else {
				return fmt.Errorf("unknown SYSTEM instruction 0x%08x at PC=0x%x", instr, c.PC)
			}
		} else {
			c.execCSR(instr, funct3)
		}

	case 0x07: // FP Load (FLW/FLD)
		if err := c.execFPLoad(instr); err != nil {
			return err
		}

	case 0x27: // FP Store (FSW/FSD)
		if err := c.execFPStore(instr); err != nil {
			return err
		}

	case 0x53: // FP computational (OP-FP)
		if err := c.execFPOp(instr); err != nil {
			return err
		}

	case 0x43: // FMADD
		if err := c.execFPFused(instr, 0x43); err != nil {
			return err
		}
	case 0x47: // FMSUB
		if err := c.execFPFused(instr, 0x47); err != nil {
			return err
		}
	case 0x4B: // FNMSUB
		if err := c.execFPFused(instr, 0x4B); err != nil {
			return err
		}
	case 0x4F: // FNMADD
		if err := c.execFPFused(instr, 0x4F); err != nil {
			return err
		}

	case 0x0F: // FENCE - no-op in single-hart emulation
		c.PC += 4

	case 0x2F: // AMO (atomic memory operations - A extension)
		if err := c.execAtomic(instr); err != nil {
			return err
		}

	default:
		return fmt.Errorf("unimplemented opcode 0x%02x at PC=0x%x (instr=0x%08x)", opcode, c.PC, instr)
	}

	return nil
}

// --- Branch ---

func (c *CPU) execBranch(instr uint32) error {
	rs1 := (instr >> 15) & 0x1F
	rs2 := (instr >> 20) & 0x1F
	funct3 := (instr >> 12) & 0x7
	imm := immB(instr)

	v1 := c.readReg(rs1)
	v2 := c.readReg(rs2)
	var taken bool

	switch funct3 {
	case 0x0: // BEQ
		taken = v1 == v2
	case 0x1: // BNE
		taken = v1 != v2
	case 0x4: // BLT
		taken = int64(v1) < int64(v2)
	case 0x5: // BGE
		taken = int64(v1) >= int64(v2)
	case 0x6: // BLTU
		taken = v1 < v2
	case 0x7: // BGEU
		taken = v1 >= v2
	default:
		return fmt.Errorf("unknown branch funct3=0x%x at PC=0x%x", funct3, c.PC)
	}

	if taken {
		c.PC = uint64(int64(c.PC) + int64(imm))
	} else {
		c.PC += 4
	}
	return nil
}

// --- Loads ---

func (c *CPU) execLoad(instr uint32) error {
	rd := (instr >> 7) & 0x1F
	rs1 := (instr >> 15) & 0x1F
	funct3 := (instr >> 12) & 0x7
	imm := signExtend(uint64(instr>>20), 12)
	addr := c.readReg(rs1) + uint64(imm)

	var val uint64
	switch funct3 {
	case 0x0: // LB
		b, err := c.Mem.Read8(addr)
		if err != nil {
			return err
		}
		val = uint64(int64(int8(b)))
	case 0x1: // LH
		h, err := c.Mem.Read16(addr)
		if err != nil {
			return err
		}
		val = uint64(int64(int16(h)))
	case 0x2: // LW
		w, err := c.Mem.Read32(addr)
		if err != nil {
			return err
		}
		val = uint64(int64(int32(w)))
	case 0x3: // LD
		d, err := c.Mem.Read64(addr)
		if err != nil {
			return err
		}
		val = d
	case 0x4: // LBU
		b, err := c.Mem.Read8(addr)
		if err != nil {
			return err
		}
		val = uint64(b)
	case 0x5: // LHU
		h, err := c.Mem.Read16(addr)
		if err != nil {
			return err
		}
		val = uint64(h)
	case 0x6: // LWU
		w, err := c.Mem.Read32(addr)
		if err != nil {
			return err
		}
		val = uint64(w)
	default:
		return fmt.Errorf("unknown load funct3=0x%x at PC=0x%x", funct3, c.PC)
	}

	c.writeReg(rd, val)
	c.PC += 4
	return nil
}

// --- Stores ---

func (c *CPU) execStore(instr uint32) error {
	rs1 := (instr >> 15) & 0x1F
	rs2 := (instr >> 20) & 0x1F
	funct3 := (instr >> 12) & 0x7
	imm := immS(instr)
	addr := c.readReg(rs1) + uint64(imm)
	val := c.readReg(rs2)

	switch funct3 {
	case 0x0: // SB
		return c.storeAndAdvance(func() error { return c.Mem.Write8(addr, uint8(val)) })
	case 0x1: // SH
		return c.storeAndAdvance(func() error { return c.Mem.Write16(addr, uint16(val)) })
	case 0x2: // SW
		return c.storeAndAdvance(func() error { return c.Mem.Write32(addr, uint32(val)) })
	case 0x3: // SD
		return c.storeAndAdvance(func() error { return c.Mem.Write64(addr, val) })
	default:
		return fmt.Errorf("unknown store funct3=0x%x at PC=0x%x", funct3, c.PC)
	}
}

func (c *CPU) storeAndAdvance(fn func() error) error {
	if err := fn(); err != nil {
		return err
	}
	c.PC += 4
	return nil
}

// --- OP-IMM (register-immediate ALU) ---

func (c *CPU) execOpImm(instr uint32) {
	rd := (instr >> 7) & 0x1F
	rs1 := (instr >> 15) & 0x1F
	funct3 := (instr >> 12) & 0x7
	imm := signExtend(uint64(instr>>20), 12)
	v1 := c.readReg(rs1)

	var result uint64
	switch funct3 {
	case 0x0: // ADDI
		result = v1 + uint64(imm)
	case 0x2: // SLTI
		if int64(v1) < int64(imm) {
			result = 1
		}
	case 0x3: // SLTIU
		if v1 < uint64(imm) {
			result = 1
		}
	case 0x4: // XORI
		result = v1 ^ uint64(imm)
	case 0x6: // ORI
		result = v1 | uint64(imm)
	case 0x7: // ANDI
		result = v1 & uint64(imm)
	case 0x1: // SLLI
		shamt := (instr >> 20) & 0x3F
		result = v1 << shamt
	case 0x5: // SRLI / SRAI
		shamt := (instr >> 20) & 0x3F
		if instr&(1<<30) != 0 {
			result = uint64(int64(v1) >> shamt) // SRAI
		} else {
			result = v1 >> shamt // SRLI
		}
	}

	c.writeReg(rd, result)
	c.PC += 4
}

// --- OP-IMM-32 (32-bit register-immediate ALU) ---

func (c *CPU) execOpImm32(instr uint32) {
	rd := (instr >> 7) & 0x1F
	rs1 := (instr >> 15) & 0x1F
	funct3 := (instr >> 12) & 0x7
	v1 := int32(c.readReg(rs1))

	var result int32
	switch funct3 {
	case 0x0: // ADDIW
		imm := int32(signExtend(uint64(instr>>20), 12))
		result = v1 + imm
	case 0x1: // SLLIW
		shamt := (instr >> 20) & 0x1F
		result = v1 << shamt
	case 0x5: // SRLIW / SRAIW
		shamt := (instr >> 20) & 0x1F
		if instr&(1<<30) != 0 {
			result = v1 >> shamt // SRAIW (arithmetic)
		} else {
			result = int32(uint32(v1) >> shamt) // SRLIW (logical)
		}
	}

	c.writeReg(rd, uint64(int64(result)))
	c.PC += 4
}

// --- OP (register-register ALU) ---

func (c *CPU) execOp(instr uint32) {
	rd := (instr >> 7) & 0x1F
	rs1 := (instr >> 15) & 0x1F
	rs2 := (instr >> 20) & 0x1F
	funct3 := (instr >> 12) & 0x7
	funct7 := instr >> 25

	v1 := c.readReg(rs1)
	v2 := c.readReg(rs2)

	var result uint64
	switch funct3 {
	case 0x0:
		if funct7 == 0x01 { // MUL (M extension)
			result = v1 * v2
		} else if funct7 == 0x20 {
			result = v1 - v2 // SUB
		} else {
			result = v1 + v2 // ADD
		}
	case 0x1:
		if funct7 == 0x01 { // MULH
			result = uint64(mulh(int64(v1), int64(v2)))
		} else {
			result = v1 << (v2 & 0x3F) // SLL
		}
	case 0x2:
		if funct7 == 0x01 { // MULHSU
			result = uint64(mulhsu(int64(v1), v2))
		} else {
			// SLT
			if int64(v1) < int64(v2) {
				result = 1
			}
		}
	case 0x3:
		if funct7 == 0x01 { // MULHU
			result = mulhu(v1, v2)
		} else {
			// SLTU
			if v1 < v2 {
				result = 1
			}
		}
	case 0x4:
		if funct7 == 0x01 { // DIV
			if v2 == 0 {
				result = ^uint64(0)
			} else if int64(v1) == -1<<63 && int64(v2) == -1 {
				result = v1
			} else {
				result = uint64(int64(v1) / int64(v2))
			}
		} else {
			result = v1 ^ v2 // XOR
		}
	case 0x5:
		if funct7 == 0x01 { // DIVU
			if v2 == 0 {
				result = ^uint64(0)
			} else {
				result = v1 / v2
			}
		} else if funct7 == 0x20 {
			result = uint64(int64(v1) >> (v2 & 0x3F)) // SRA
		} else {
			result = v1 >> (v2 & 0x3F) // SRL
		}
	case 0x6:
		if funct7 == 0x01 { // REM
			if v2 == 0 {
				result = v1
			} else if int64(v1) == -1<<63 && int64(v2) == -1 {
				result = 0
			} else {
				result = uint64(int64(v1) % int64(v2))
			}
		} else {
			result = v1 | v2 // OR
		}
	case 0x7:
		if funct7 == 0x01 { // REMU
			if v2 == 0 {
				result = v1
			} else {
				result = v1 % v2
			}
		} else {
			result = v1 & v2 // AND
		}
	}

	c.writeReg(rd, result)
	c.PC += 4
}

// --- OP-32 (register-register 32-bit ALU) ---

func (c *CPU) execOp32(instr uint32) {
	rd := (instr >> 7) & 0x1F
	rs1 := (instr >> 15) & 0x1F
	rs2 := (instr >> 20) & 0x1F
	funct3 := (instr >> 12) & 0x7
	funct7 := instr >> 25

	v1 := int32(c.readReg(rs1))
	v2 := int32(c.readReg(rs2))

	var result int32
	switch funct3 {
	case 0x0:
		if funct7 == 0x01 { // MULW
			result = v1 * v2
		} else if funct7 == 0x20 {
			result = v1 - v2 // SUBW
		} else {
			result = v1 + v2 // ADDW
		}
	case 0x1: // SLLW
		result = v1 << (uint32(v2) & 0x1F)
	case 0x4: // DIVW
		if funct7 == 0x01 {
			if v2 == 0 {
				result = -1
			} else if v1 == -1<<31 && v2 == -1 {
				result = v1
			} else {
				result = v1 / v2
			}
		}
	case 0x5:
		if funct7 == 0x01 { // DIVUW
			u1, u2 := uint32(v1), uint32(v2)
			if u2 == 0 {
				result = -1
			} else {
				result = int32(u1 / u2)
			}
		} else if funct7 == 0x20 {
			result = v1 >> (uint32(v2) & 0x1F) // SRAW
		} else {
			result = int32(uint32(v1) >> (uint32(v2) & 0x1F)) // SRLW
		}
	case 0x6: // REMW
		if funct7 == 0x01 {
			if v2 == 0 {
				result = v1
			} else if v1 == -1<<31 && v2 == -1 {
				result = 0
			} else {
				result = v1 % v2
			}
		}
	case 0x7: // REMUW
		if funct7 == 0x01 {
			u1, u2 := uint32(v1), uint32(v2)
			if u2 == 0 {
				result = int32(u1)
			} else {
				result = int32(u1 % u2)
			}
		}
	}

	c.writeReg(rd, uint64(int64(result)))
	c.PC += 4
}

// --- Immediate extraction helpers ---

func signExtend(val uint64, bits int) int64 {
	shift := 64 - bits
	return int64(val<<shift) >> shift
}

func immB(instr uint32) int64 {
	imm := uint32(0)
	imm |= ((instr >> 31) & 1) << 12
	imm |= ((instr >> 7) & 1) << 11
	imm |= ((instr >> 25) & 0x3F) << 5
	imm |= ((instr >> 8) & 0xF) << 1
	return signExtend(uint64(imm), 13)
}

func immS(instr uint32) int64 {
	imm := ((instr >> 25) << 5) | ((instr >> 7) & 0x1F)
	return signExtend(uint64(imm), 12)
}

func immJ(instr uint32) int64 {
	imm := uint32(0)
	imm |= ((instr >> 31) & 1) << 20
	imm |= ((instr >> 21) & 0x3FF) << 1
	imm |= ((instr >> 20) & 1) << 11
	imm |= ((instr >> 12) & 0xFF) << 12
	return signExtend(uint64(imm), 21)
}

// --- M-extension helpers ---

func mulh(a, b int64) int64 {
	// High 64 bits of signed 64×64 multiplication
	neg := (a < 0) != (b < 0)
	ua, ub := uint64(a), uint64(b)
	if a < 0 {
		ua = uint64(-a)
	}
	if b < 0 {
		ub = uint64(-b)
	}
	hi := mulhu(ua, ub)
	if neg {
		// negate 128-bit result: ~hi (low part is irrelevant for high word logic,
		// but we need to account for carry from low)
		lo := ua * ub
		if lo == 0 {
			hi = -hi
		} else {
			hi = ^hi
		}
	}
	return int64(hi)
}

func mulhsu(a int64, b uint64) int64 {
	neg := a < 0
	ua := uint64(a)
	if neg {
		ua = uint64(-a)
	}
	hi := mulhu(ua, b)
	if neg {
		lo := ua * b
		if lo == 0 {
			hi = -hi
		} else {
			hi = ^hi
		}
	}
	return int64(hi)
}

func mulhu(a, b uint64) uint64 {
	aHi, aLo := a>>32, a&0xFFFFFFFF
	bHi, bLo := b>>32, b&0xFFFFFFFF
	mid1 := aHi * bLo
	mid2 := aLo * bHi
	lo := aLo * bLo
	hi := aHi * bHi

	carry := (lo>>32 + (mid1 & 0xFFFFFFFF) + (mid2 & 0xFFFFFFFF)) >> 32
	hi += (mid1 >> 32) + (mid2 >> 32) + carry
	return hi
}

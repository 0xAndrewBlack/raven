// Package jit provides a basic-block JIT compiler for the x86-64 emulator.
//
// Instead of generating native machine code, it "compiles" hot basic blocks
// into Go closures that manipulate CPU state directly, eliminating the
// per-instruction decode overhead of the interpreter.
//
// Architecture:
//   - BlockCache maps guest virtual addresses to compiled Go functions.
//   - HotCounter tracks execution counts; blocks exceeding a threshold
//     are compiled on the next execution.
//   - CompiledBlock is a Go closure that executes a sequence of pre-decoded
//     instructions, returning the next RIP (or an error).
package jit

import (
	"math"
	"math/bits"
	"sync"

	"github.com/mirkobrombin/Raven/pkg/mmu"
)

// CompileThreshold is how many times a block must execute before compilation.
const CompileThreshold = 16

// MaxBlockInsns limits the number of instructions in a single compiled block.
const MaxBlockInsns = 256

// CompiledBlock executes a pre-compiled basic block.
// It takes the CPU registers, flags, memory and returns the next RIP.
type CompiledBlock func(s *State) error

// State is the JIT execution context - a flat struct for fast access.
type State struct {
	Regs   *[16]uint64
	RIP    *uint64
	Rflags *uint64
	Mem    *mmu.MMU
	XMM    *[16][2]uint64
	FSBase uint64
	GSBase uint64
	// Set to true if a vmcall/syscall was hit - caller must return to interpreter.
	Trap bool
}

// Cache holds compiled blocks and execution counters.
type Cache struct {
	mu       sync.RWMutex
	blocks   map[uint64]CompiledBlock
	counters map[uint64]uint32
	mem      *mmu.MMU
}

// NewCache creates a JIT cache.
func NewCache(mem *mmu.MMU) *Cache {
	return &Cache{
		blocks:   make(map[uint64]CompiledBlock),
		counters: make(map[uint64]uint32),
		mem:      mem,
	}
}

// Lookup returns a compiled block for the given address, or nil.
// It also increments the execution counter.
func (c *Cache) Lookup(addr uint64) CompiledBlock {
	c.mu.RLock()
	if fn, ok := c.blocks[addr]; ok {
		c.mu.RUnlock()
		return fn
	}
	c.mu.RUnlock()

	// Increment counter
	c.mu.Lock()
	c.counters[addr]++
	count := c.counters[addr]
	c.mu.Unlock()

	if count >= CompileThreshold {
		if fn := c.compile(addr); fn != nil {
			c.mu.Lock()
			c.blocks[addr] = fn
			delete(c.counters, addr)
			c.mu.Unlock()
			return fn
		}
	}
	return nil
}

// Invalidate removes any compiled block covering the given address.
func (c *Cache) Invalidate(addr uint64) {
	page := addr &^ (mmu.PageSize - 1)
	c.mu.Lock()
	for k := range c.blocks {
		if k&^(mmu.PageSize-1) == page {
			delete(c.blocks, k)
		}
	}
	c.mu.Unlock()
}

// compile decodes a basic block starting at addr and returns a compiled closure.
func (c *Cache) compile(addr uint64) CompiledBlock {
	insns, err := c.decode(addr)
	if err != nil || len(insns) == 0 {
		return nil
	}
	return c.emit(insns)
}

// =========================================================================
// Instruction representation
// =========================================================================

type opKind uint8

const (
	opNop opKind = iota
	opMovRegImm
	opMovRegReg
	opMovRegMem
	opMovMemReg
	opMovMemImm
	opALURegReg  // ADD/SUB/AND/OR/XOR/CMP
	opALURegImm
	opALURegMem
	opALUMemImm
	opLea
	opPush
	opPop
	opCall
	opRet
	opJmp
	opJcc
	opTest
	opXchg
	opCdq      // CDQ/CQO
	opMovzx
	opMovsx
	opSetcc
	opCmovcc
	opIMul
	opIMul3
	opDiv
	opIDiv
	opShift    // SHL/SHR/SAR/ROL/ROR
	opNot
	opNeg
	opInc
	opDec
	opSyscall
	opVmcall
	opEnd // sentinel: end of block, return to interpreter
)

type aluOp uint8

const (
	aluADD aluOp = iota
	aluOR
	aluADC
	aluSBB
	aluAND
	aluSUB
	aluXOR
	aluCMP
)

type condCode uint8

const (
	ccO  condCode = 0
	ccNO condCode = 1
	ccB  condCode = 2
	ccNB condCode = 3
	ccZ  condCode = 4
	ccNZ condCode = 5
	ccBE condCode = 6
	ccA  condCode = 7
	ccS  condCode = 8
	ccNS condCode = 9
	ccP  condCode = 10
	ccNP condCode = 11
	ccL  condCode = 12
	ccGE condCode = 13
	ccLE condCode = 14
	ccG  condCode = 15
)

type shiftOp uint8

const (
	shSHL shiftOp = 4
	shSHR shiftOp = 5
	shSAR shiftOp = 7
	shROL shiftOp = 0
	shROR shiftOp = 1
)

type insn struct {
	kind    opKind
	size    int     // operand size in bytes (1, 2, 4, 8)
	dst     int     // register index or -1
	src     int     // register index or -1
	imm     int64   // immediate value
	memBase int     // base register for memory operand
	memIdx  int     // index register (-1 if none)
	memScale uint8  // scale (1, 2, 4, 8)
	memDisp int64   // displacement
	alu     aluOp
	cc      condCode
	shift   shiftOp
	nextRIP uint64  // address of next instruction (for block-end insns)
	target  uint64  // branch target address
	useRIP  bool    // memory operand is RIP-relative
}

// RFLAGS bits
const (
	flagCF = 1 << 0
	flagPF = 1 << 2
	flagZF = 1 << 6
	flagSF = 1 << 7
	flagDF = 1 << 10
	flagOF = 1 << 11
)

// =========================================================================
// Basic block decoder
// =========================================================================

type decoder struct {
	mem  *mmu.MMU
	pos  uint64
	insns []insn
}

func (c *Cache) decode(addr uint64) ([]insn, error) {
	d := &decoder{mem: c.mem, pos: addr}
	for len(d.insns) < MaxBlockInsns {
		if err := d.decodeOne(); err != nil {
			// Can't decode - end block here
			if len(d.insns) == 0 {
				return nil, err
			}
			break
		}
		last := d.insns[len(d.insns)-1]
		// Block terminators
		switch last.kind {
		case opRet, opJmp, opCall, opSyscall, opVmcall, opEnd:
			return d.insns, nil
		case opJcc:
			return d.insns, nil
		}
	}
	return d.insns, nil
}

func (d *decoder) fetch8() (byte, error) {
	b, err := d.mem.Read8(d.pos)
	if err != nil {
		return 0, err
	}
	d.pos++
	return b, nil
}

func (d *decoder) fetch16() (uint16, error) {
	v, err := d.mem.Read16(d.pos)
	if err != nil {
		return 0, err
	}
	d.pos += 2
	return v, nil
}

func (d *decoder) fetch32() (uint32, error) {
	v, err := d.mem.Read32(d.pos)
	if err != nil {
		return 0, err
	}
	d.pos += 4
	return v, nil
}

func (d *decoder) fetch64() (uint64, error) {
	v, err := d.mem.Read64(d.pos)
	if err != nil {
		return 0, err
	}
	d.pos += 8
	return v, nil
}

type pfx struct {
	rex    byte
	hasREX bool
	op66   bool
	segFS  bool
	segGS  bool
}

func (p *pfx) rexW() bool { return p.hasREX && p.rex&0x08 != 0 }
func (p *pfx) rexR() bool { return p.hasREX && p.rex&0x04 != 0 }
func (p *pfx) rexX() bool { return p.hasREX && p.rex&0x02 != 0 }
func (p *pfx) rexB() bool { return p.hasREX && p.rex&0x01 != 0 }

func (p *pfx) opSize() int {
	if p.rexW() {
		return 8
	}
	if p.op66 {
		return 2
	}
	return 4
}

func regIdx(field byte, ext bool) int {
	r := int(field & 7)
	if ext {
		r += 8
	}
	return r
}

// decodeModRM decodes ModRM (and SIB if needed), returning register index,
// and either a register index or memory operand details.
func (d *decoder) decodeModRM(p *pfx) (reg int, isReg bool, rm int, base int, idx int, scale uint8, disp int64, useRIP bool, err error) {
	b, e := d.fetch8()
	if e != nil {
		err = e
		return
	}
	mod := (b >> 6) & 3
	regField := (b >> 3) & 7
	rmField := b & 7

	reg = regIdx(regField, p.rexR())

	if mod == 3 {
		isReg = true
		rm = regIdx(rmField, p.rexB())
		return
	}

	// Memory operand
	base = -1
	idx = -1
	scale = 1

	if rmField == 4 { // SIB byte
		sib, e2 := d.fetch8()
		if e2 != nil {
			err = e2
			return
		}
		sibBase := sib & 7
		sibIdx := (sib >> 3) & 7
		sibScale := (sib >> 6) & 3

		if sibIdx != 4 || p.rexX() {
			idx = regIdx(sibIdx, p.rexX())
			scale = 1 << sibScale
		}

		if mod == 0 && sibBase == 5 {
			// [disp32 + idx*scale]
			d32, e3 := d.fetch32()
			if e3 != nil {
				err = e3
				return
			}
			disp = int64(int32(d32))
		} else {
			base = regIdx(sibBase, p.rexB())
		}
	} else if mod == 0 && rmField == 5 {
		// RIP-relative
		d32, e2 := d.fetch32()
		if e2 != nil {
			err = e2
			return
		}
		disp = int64(int32(d32))
		useRIP = true
	} else {
		base = regIdx(rmField, p.rexB())
	}

	// Displacement
	if mod == 1 {
		d8, e2 := d.fetch8()
		if e2 != nil {
			err = e2
			return
		}
		disp = int64(int8(d8))
	} else if mod == 2 {
		d32, e2 := d.fetch32()
		if e2 != nil {
			err = e2
			return
		}
		disp = int64(int32(d32))
	}

	return
}

func (d *decoder) decodeOne() error {
	startPos := d.pos

	// Collect prefixes
	var p pfx
	for {
		b, err := d.fetch8()
		if err != nil {
			return err
		}
		switch {
		case b == 0x66:
			p.op66 = true
		case b == 0xF0: // LOCK
		case b == 0xF2, b == 0xF3: // REP/REPNE
		case b == 0x64:
			p.segFS = true
		case b == 0x65:
			p.segGS = true
		case b == 0x26, b == 0x2E, b == 0x36, b == 0x3E: // segment overrides
		case b == 0x67: // address size override
		case b >= 0x40 && b <= 0x4F:
			p.rex = b
			p.hasREX = true
		default:
			return d.decodeOpcode(b, &p, startPos)
		}
	}
}

func (d *decoder) decodeOpcode(op byte, p *pfx, startPos uint64) error {
	size := p.opSize()

	switch op {
	case 0x90: // NOP
		d.insns = append(d.insns, insn{kind: opNop})
		return nil

	case 0xCC, 0xCD, 0xCE: // INT3, INT, INTO - end block
		d.pos = startPos
		d.insns = append(d.insns, insn{kind: opEnd, nextRIP: startPos})
		return nil

	// MOV r, imm (0xB0-0xBF)
	case 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7:
		reg := regIdx(op-0xB0, p.rexB())
		imm, err := d.fetch8()
		if err != nil {
			return err
		}
		d.insns = append(d.insns, insn{kind: opMovRegImm, size: 1, dst: reg, imm: int64(imm)})
		return nil
	case 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF:
		reg := regIdx(op-0xB8, p.rexB())
		if p.rexW() {
			imm, err := d.fetch64()
			if err != nil {
				return err
			}
			d.insns = append(d.insns, insn{kind: opMovRegImm, size: 8, dst: reg, imm: int64(imm)})
		} else {
			imm, err := d.fetch32()
			if err != nil {
				return err
			}
			d.insns = append(d.insns, insn{kind: opMovRegImm, size: size, dst: reg, imm: int64(int32(imm))})
		}
		return nil

	// PUSH r64 (0x50-0x57)
	case 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57:
		reg := regIdx(op-0x50, p.rexB())
		d.insns = append(d.insns, insn{kind: opPush, size: 8, src: reg})
		return nil

	// POP r64 (0x58-0x5F)
	case 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F:
		reg := regIdx(op-0x58, p.rexB())
		d.insns = append(d.insns, insn{kind: opPop, size: 8, dst: reg})
		return nil

	// RET (0xC3)
	case 0xC3:
		d.insns = append(d.insns, insn{kind: opRet, nextRIP: d.pos})
		return nil

	// RET imm16 (0xC2)
	case 0xC2:
		imm, err := d.fetch16()
		if err != nil {
			return err
		}
		d.insns = append(d.insns, insn{kind: opRet, imm: int64(imm), nextRIP: d.pos})
		return nil

	// CALL rel32 (0xE8)
	case 0xE8:
		rel, err := d.fetch32()
		if err != nil {
			return err
		}
		target := d.pos + uint64(int64(int32(rel)))
		d.insns = append(d.insns, insn{kind: opCall, target: target, nextRIP: d.pos})
		return nil

	// JMP rel8 (0xEB)
	case 0xEB:
		rel, err := d.fetch8()
		if err != nil {
			return err
		}
		target := d.pos + uint64(int64(int8(rel)))
		d.insns = append(d.insns, insn{kind: opJmp, target: target, nextRIP: d.pos})
		return nil

	// JMP rel32 (0xE9)
	case 0xE9:
		rel, err := d.fetch32()
		if err != nil {
			return err
		}
		target := d.pos + uint64(int64(int32(rel)))
		d.insns = append(d.insns, insn{kind: opJmp, target: target, nextRIP: d.pos})
		return nil

	// Jcc rel8 (0x70-0x7F)
	case 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
		0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F:
		rel, err := d.fetch8()
		if err != nil {
			return err
		}
		target := d.pos + uint64(int64(int8(rel)))
		d.insns = append(d.insns, insn{kind: opJcc, cc: condCode(op - 0x70), target: target, nextRIP: d.pos})
		return nil

	// ALU r/m, r (0x00-0x3B range, odd patterns)
	case 0x00, 0x01, 0x08, 0x09, 0x10, 0x11, 0x18, 0x19,
		0x20, 0x21, 0x28, 0x29, 0x30, 0x31, 0x38, 0x39:
		aop := aluOp((op >> 3) & 7)
		isWord := op&1 != 0
		sz := 1
		if isWord {
			sz = size
		}
		reg, isReg, rm, base, idx, scale, disp, useRIP, err := d.decodeModRM(p)
		if err != nil {
			return err
		}
		if isReg {
			d.insns = append(d.insns, insn{kind: opALURegReg, size: sz, dst: rm, src: reg, alu: aop})
		} else {
			// mem, reg - more complex, bail to interpreter for now
			d.insns = append(d.insns, insn{kind: opEnd, nextRIP: startPos})
			_ = base
			_ = idx
			_ = scale
			_ = disp
			_ = useRIP
		}
		return nil

	// ALU r, r/m (0x02-0x3B, even patterns +2/+3)
	case 0x02, 0x03, 0x0A, 0x0B, 0x12, 0x13, 0x1A, 0x1B,
		0x22, 0x23, 0x2A, 0x2B, 0x32, 0x33, 0x3A, 0x3B:
		aop := aluOp((op >> 3) & 7)
		isWord := op&1 != 0
		sz := 1
		if isWord {
			sz = size
		}
		reg, isReg, rm, base, idx, scale, disp, useRIP, err := d.decodeModRM(p)
		if err != nil {
			return err
		}
		if isReg {
			d.insns = append(d.insns, insn{kind: opALURegReg, size: sz, dst: reg, src: rm, alu: aop})
		} else {
			d.insns = append(d.insns, insn{kind: opALURegMem, size: sz, dst: reg, alu: aop,
				memBase: base, memIdx: idx, memScale: scale, memDisp: disp, useRIP: useRIP})
		}
		return nil

	// ALU rAX, imm (0x04/05, 0x0C/0D, 0x14/15, 0x1C/1D, 0x24/25, 0x2C/2D, 0x34/35, 0x3C/3D)
	case 0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D:
		aop := aluOp((op >> 3) & 7)
		imm, err := d.fetch32()
		if err != nil {
			return err
		}
		d.insns = append(d.insns, insn{kind: opALURegImm, size: size, dst: 0 /*RAX*/, alu: aop, imm: int64(int32(imm))})
		return nil
	case 0x04, 0x0C, 0x14, 0x1C, 0x24, 0x2C, 0x34, 0x3C:
		aop := aluOp((op >> 3) & 7)
		imm, err := d.fetch8()
		if err != nil {
			return err
		}
		d.insns = append(d.insns, insn{kind: opALURegImm, size: 1, dst: 0 /*RAX*/, alu: aop, imm: int64(int8(imm))})
		return nil

	// Group 1: ALU r/m, imm8/imm32 (0x80-0x83)
	case 0x81, 0x83:
		reg, isReg, rm, base, idx, scale, disp, useRIP, err := d.decodeModRM(p)
		if err != nil {
			return err
		}
		aop := aluOp(reg)
		var immVal int64
		if op == 0x83 {
			ib, e := d.fetch8()
			if e != nil {
				return e
			}
			immVal = int64(int8(ib))
		} else {
			i32, e := d.fetch32()
			if e != nil {
				return e
			}
			immVal = int64(int32(i32))
		}
		if isReg {
			d.insns = append(d.insns, insn{kind: opALURegImm, size: size, dst: rm, alu: aop, imm: immVal})
		} else {
			d.insns = append(d.insns, insn{kind: opALUMemImm, size: size, alu: aop, imm: immVal,
				memBase: base, memIdx: idx, memScale: scale, memDisp: disp, useRIP: useRIP})
		}
		return nil

	// MOV r/m, r (0x89)
	case 0x89:
		reg, isReg, rm, base, idx, scale, disp, useRIP, err := d.decodeModRM(p)
		if err != nil {
			return err
		}
		if isReg {
			d.insns = append(d.insns, insn{kind: opMovRegReg, size: size, dst: rm, src: reg})
		} else {
			d.insns = append(d.insns, insn{kind: opMovMemReg, size: size, src: reg,
				memBase: base, memIdx: idx, memScale: scale, memDisp: disp, useRIP: useRIP})
		}
		return nil

	// MOV r, r/m (0x8B)
	case 0x8B:
		reg, isReg, rm, base, idx, scale, disp, useRIP, err := d.decodeModRM(p)
		if err != nil {
			return err
		}
		if isReg {
			d.insns = append(d.insns, insn{kind: opMovRegReg, size: size, dst: reg, src: rm})
		} else {
			d.insns = append(d.insns, insn{kind: opMovRegMem, size: size, dst: reg,
				memBase: base, memIdx: idx, memScale: scale, memDisp: disp, useRIP: useRIP})
		}
		return nil

	// MOV r/m, imm (0xC7)
	case 0xC7:
		_, isReg, rm, base, idx, scale, disp, useRIP, err := d.decodeModRM(p)
		if err != nil {
			return err
		}
		imm, err := d.fetch32()
		if err != nil {
			return err
		}
		immVal := int64(int32(imm))
		if isReg {
			d.insns = append(d.insns, insn{kind: opMovRegImm, size: size, dst: rm, imm: immVal})
		} else {
			d.insns = append(d.insns, insn{kind: opMovMemImm, size: size, imm: immVal,
				memBase: base, memIdx: idx, memScale: scale, memDisp: disp, useRIP: useRIP})
		}
		return nil

	// LEA r, m (0x8D)
	case 0x8D:
		reg, _, _, base, idx, scale, disp, useRIP, err := d.decodeModRM(p)
		if err != nil {
			return err
		}
		d.insns = append(d.insns, insn{kind: opLea, size: size, dst: reg,
			memBase: base, memIdx: idx, memScale: scale, memDisp: disp, useRIP: useRIP})
		return nil

	// TEST r/m, r (0x85)
	case 0x85:
		reg, isReg, rm, base, idx, scale, disp, useRIP, err := d.decodeModRM(p)
		if err != nil {
			return err
		}
		if isReg {
			d.insns = append(d.insns, insn{kind: opTest, size: size, dst: rm, src: reg})
		} else {
			_ = base
			_ = idx
			_ = scale
			_ = disp
			_ = useRIP
			d.insns = append(d.insns, insn{kind: opEnd, nextRIP: startPos})
		}
		return nil

	// TEST al/rAX, imm (0xA9)
	case 0xA9:
		imm, err := d.fetch32()
		if err != nil {
			return err
		}
		d.insns = append(d.insns, insn{kind: opALURegImm, size: size, dst: 0, alu: aluAND, imm: int64(int32(imm))})
		return nil

	// XCHG rAX, r (0x91-0x97)
	case 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97:
		reg := regIdx(op-0x90, p.rexB())
		d.insns = append(d.insns, insn{kind: opXchg, size: size, dst: 0, src: reg})
		return nil

	// CDQ/CQO (0x99)
	case 0x99:
		d.insns = append(d.insns, insn{kind: opCdq, size: size})
		return nil

	// 0x0F escape
	case 0x0F:
		return d.decode0F(p, startPos)

	default:
		// Unknown opcode - end block, return to interpreter
		d.pos = startPos
		d.insns = append(d.insns, insn{kind: opEnd, nextRIP: startPos})
		return nil
	}
}

func (d *decoder) decode0F(p *pfx, startPos uint64) error {
	b, err := d.fetch8()
	if err != nil {
		return err
	}
	size := p.opSize()

	switch b {
	// Jcc rel32 (0x0F 0x80-0x8F)
	case 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
		0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F:
		rel, err := d.fetch32()
		if err != nil {
			return err
		}
		target := d.pos + uint64(int64(int32(rel)))
		d.insns = append(d.insns, insn{kind: opJcc, cc: condCode(b - 0x80), target: target, nextRIP: d.pos})
		return nil

	// MOVZX r, r/m8 (0x0F 0xB6)
	case 0xB6:
		reg, isReg, rm, base, idx, scale, disp, useRIP, err := d.decodeModRM(p)
		if err != nil {
			return err
		}
		if isReg {
			d.insns = append(d.insns, insn{kind: opMovzx, size: 1, dst: reg, src: rm})
		} else {
			d.insns = append(d.insns, insn{kind: opMovzx, size: 1, dst: reg,
				memBase: base, memIdx: idx, memScale: scale, memDisp: disp, useRIP: useRIP, src: -1})
		}
		return nil

	// MOVZX r, r/m16 (0x0F 0xB7)
	case 0xB7:
		reg, isReg, rm, base, idx, scale, disp, useRIP, err := d.decodeModRM(p)
		if err != nil {
			return err
		}
		if isReg {
			d.insns = append(d.insns, insn{kind: opMovzx, size: 2, dst: reg, src: rm})
		} else {
			d.insns = append(d.insns, insn{kind: opMovzx, size: 2, dst: reg,
				memBase: base, memIdx: idx, memScale: scale, memDisp: disp, useRIP: useRIP, src: -1})
		}
		return nil

	// MOVSX r, r/m8 (0x0F 0xBE)
	case 0xBE:
		reg, isReg, rm, base, idx, scale, disp, useRIP, err := d.decodeModRM(p)
		if err != nil {
			return err
		}
		if isReg {
			d.insns = append(d.insns, insn{kind: opMovsx, size: 1, dst: reg, src: rm})
		} else {
			d.insns = append(d.insns, insn{kind: opMovsx, size: 1, dst: reg,
				memBase: base, memIdx: idx, memScale: scale, memDisp: disp, useRIP: useRIP, src: -1})
		}
		return nil

	// MOVSX r, r/m16 (0x0F 0xBF)
	case 0xBF:
		reg, isReg, rm, base, idx, scale, disp, useRIP, err := d.decodeModRM(p)
		if err != nil {
			return err
		}
		if isReg {
			d.insns = append(d.insns, insn{kind: opMovsx, size: 2, dst: reg, src: rm})
		} else {
			d.insns = append(d.insns, insn{kind: opMovsx, size: 2, dst: reg,
				memBase: base, memIdx: idx, memScale: scale, memDisp: disp, useRIP: useRIP, src: -1})
		}
		return nil

	// SETcc r/m8 (0x0F 0x90-0x9F)
	case 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
		0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F:
		_, isReg, rm, _, _, _, _, _, err := d.decodeModRM(p)
		if err != nil {
			return err
		}
		if isReg {
			d.insns = append(d.insns, insn{kind: opSetcc, size: 1, dst: rm, cc: condCode(b - 0x90)})
		} else {
			d.insns = append(d.insns, insn{kind: opEnd, nextRIP: startPos})
		}
		return nil

	// CMOVcc r, r/m (0x0F 0x40-0x4F)
	case 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
		0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F:
		reg, isReg, rm, _, _, _, _, _, err := d.decodeModRM(p)
		if err != nil {
			return err
		}
		if isReg {
			d.insns = append(d.insns, insn{kind: opCmovcc, size: size, dst: reg, src: rm, cc: condCode(b - 0x40)})
		} else {
			d.insns = append(d.insns, insn{kind: opEnd, nextRIP: startPos})
		}
		return nil

	// IMUL r, r/m (0x0F 0xAF)
	case 0xAF:
		reg, isReg, rm, _, _, _, _, _, err := d.decodeModRM(p)
		if err != nil {
			return err
		}
		if isReg {
			d.insns = append(d.insns, insn{kind: opIMul, size: size, dst: reg, src: rm})
		} else {
			d.insns = append(d.insns, insn{kind: opEnd, nextRIP: startPos})
		}
		return nil

	// SYSCALL (0x0F 0x05)
	case 0x05:
		d.insns = append(d.insns, insn{kind: opSyscall, nextRIP: d.pos})
		return nil

	// VMCALL-like (0x0F 0x01 ...)
	case 0x01:
		b2, err := d.fetch8()
		if err != nil {
			return err
		}
		if b2 == 0xC1 {
			d.insns = append(d.insns, insn{kind: opVmcall, nextRIP: d.pos})
			return nil
		}
		d.pos = startPos
		d.insns = append(d.insns, insn{kind: opEnd, nextRIP: startPos})
		return nil

	default:
		d.pos = startPos
		d.insns = append(d.insns, insn{kind: opEnd, nextRIP: startPos})
		return nil
	}
}

// =========================================================================
// Code emitter - generates Go closures from decoded instructions
// =========================================================================

func (c *Cache) emit(insns []insn) CompiledBlock {
	return func(s *State) error {
		regs := s.Regs
		mem := s.Mem

		for i := 0; i < len(insns); i++ {
			in := &insns[i]
			switch in.kind {
			case opNop:
				continue

			case opMovRegImm:
				v := uint64(in.imm)
				switch in.size {
				case 1:
					regs[in.dst] = (regs[in.dst] & ^uint64(0xFF)) | (v & 0xFF)
				case 2:
					regs[in.dst] = (regs[in.dst] & ^uint64(0xFFFF)) | (v & 0xFFFF)
				case 4:
					regs[in.dst] = v & 0xFFFFFFFF
				case 8:
					regs[in.dst] = v
				}

			case opMovRegReg:
				v := regs[in.src]
				switch in.size {
				case 1:
					regs[in.dst] = (regs[in.dst] & ^uint64(0xFF)) | (v & 0xFF)
				case 2:
					regs[in.dst] = (regs[in.dst] & ^uint64(0xFFFF)) | (v & 0xFFFF)
				case 4:
					regs[in.dst] = v & 0xFFFFFFFF
				case 8:
					regs[in.dst] = v
				}

			case opMovRegMem:
				addr := resolveAddr(s, in)
				var v uint64
				var err error
				switch in.size {
				case 1:
					var b byte
					b, err = mem.Read8(addr)
					v = uint64(b)
				case 2:
					var w uint16
					w, err = mem.Read16(addr)
					v = uint64(w)
				case 4:
					var d uint32
					d, err = mem.Read32(addr)
					v = uint64(d)
				case 8:
					v, err = mem.Read64(addr)
				}
				if err != nil {
					return err
				}
				switch in.size {
				case 4:
					regs[in.dst] = v // zero-extend 32-bit
				default:
					regs[in.dst] = v
				}

			case opMovMemReg:
				addr := resolveAddr(s, in)
				v := regs[in.src]
				switch in.size {
				case 1:
					mem.Write8(addr, byte(v))
				case 2:
					mem.Write16(addr, uint16(v))
				case 4:
					mem.Write32(addr, uint32(v))
				case 8:
					mem.Write64(addr, v)
				}

			case opMovMemImm:
				addr := resolveAddr(s, in)
				v := uint64(in.imm)
				switch in.size {
				case 1:
					mem.Write8(addr, byte(v))
				case 2:
					mem.Write16(addr, uint16(v))
				case 4:
					mem.Write32(addr, uint32(v))
				case 8:
					mem.Write64(addr, v)
				}

			case opLea:
				addr := resolveAddr(s, in)
				switch in.size {
				case 4:
					regs[in.dst] = addr & 0xFFFFFFFF
				default:
					regs[in.dst] = addr
				}

			case opALURegReg:
				a := truncate(regs[in.dst], in.size)
				b := truncate(regs[in.src], in.size)
				r := doALU(s, in.alu, a, b, in.size)
				if in.alu != aluCMP {
					writeReg(regs, in.dst, r, in.size)
				}

			case opALURegImm:
				a := truncate(regs[in.dst], in.size)
				b := uint64(in.imm)
				if in.size == 8 {
					b = uint64(in.imm) // sign-extend
				}
				r := doALU(s, in.alu, a, b, in.size)
				if in.alu != aluCMP {
					writeReg(regs, in.dst, r, in.size)
				}

			case opALURegMem:
				addr := resolveAddr(s, in)
				a := truncate(regs[in.dst], in.size)
				var bv uint64
				switch in.size {
				case 1:
					bb, _ := mem.Read8(addr)
					bv = uint64(bb)
				case 2:
					bw, _ := mem.Read16(addr)
					bv = uint64(bw)
				case 4:
					bd, _ := mem.Read32(addr)
					bv = uint64(bd)
				case 8:
					bv, _ = mem.Read64(addr)
				}
				r := doALU(s, in.alu, a, bv, in.size)
				if in.alu != aluCMP {
					writeReg(regs, in.dst, r, in.size)
				}

			case opALUMemImm:
				addr := resolveAddr(s, in)
				var a uint64
				switch in.size {
				case 1:
					bb, _ := mem.Read8(addr)
					a = uint64(bb)
				case 2:
					bw, _ := mem.Read16(addr)
					a = uint64(bw)
				case 4:
					bd, _ := mem.Read32(addr)
					a = uint64(bd)
				case 8:
					a, _ = mem.Read64(addr)
				}
				b := uint64(in.imm)
				r := doALU(s, in.alu, a, b, in.size)
				if in.alu != aluCMP {
					switch in.size {
					case 1:
						mem.Write8(addr, byte(r))
					case 2:
						mem.Write16(addr, uint16(r))
					case 4:
						mem.Write32(addr, uint32(r))
					case 8:
						mem.Write64(addr, r)
					}
				}

			case opTest:
				a := truncate(regs[in.dst], in.size)
				b := truncate(regs[in.src], in.size)
				r := a & b
				setLogicFlags(s, r, in.size)

			case opPush:
				sp := regs[4] - 8 // RSP
				regs[4] = sp
				mem.Write64(sp, regs[in.src])

			case opPop:
				sp := regs[4]
				v, _ := mem.Read64(sp)
				regs[4] = sp + 8
				regs[in.dst] = v

			case opCall:
				sp := regs[4] - 8
				regs[4] = sp
				mem.Write64(sp, in.nextRIP) // push return addr
				*s.RIP = in.target
				return nil

			case opRet:
				sp := regs[4]
				ret, _ := mem.Read64(sp)
				regs[4] = sp + 8 + uint64(in.imm)
				*s.RIP = ret
				return nil

			case opJmp:
				*s.RIP = in.target
				return nil

			case opJcc:
				if evalCC(s, in.cc) {
					*s.RIP = in.target
				} else {
					*s.RIP = in.nextRIP
				}
				return nil

			case opXchg:
				regs[in.dst], regs[in.src] = regs[in.src], regs[in.dst]

			case opCdq:
				if in.size == 8 {
					if int64(regs[0]) < 0 {
						regs[2] = ^uint64(0) // RDX = -1
					} else {
						regs[2] = 0
					}
				} else {
					if int32(regs[0]) < 0 {
						regs[2] = uint64(uint32(0xFFFFFFFF))
					} else {
						regs[2] = 0
					}
				}

			case opMovzx:
				var v uint64
				if in.src >= 0 {
					// Register source
					switch in.size {
					case 1:
						v = regs[in.src] & 0xFF
					case 2:
						v = regs[in.src] & 0xFFFF
					}
				} else {
					// Memory source
					addr := resolveAddr(s, in)
					switch in.size {
					case 1:
						b, _ := mem.Read8(addr)
						v = uint64(b)
					case 2:
						w, _ := mem.Read16(addr)
						v = uint64(w)
					}
				}
				regs[in.dst] = v

			case opMovsx:
				var v int64
				if in.src >= 0 {
					switch in.size {
					case 1:
						v = int64(int8(regs[in.src]))
					case 2:
						v = int64(int16(regs[in.src]))
					}
				} else {
					addr := resolveAddr(s, in)
					switch in.size {
					case 1:
						b, _ := mem.Read8(addr)
						v = int64(int8(b))
					case 2:
						w, _ := mem.Read16(addr)
						v = int64(int16(w))
					}
				}
				regs[in.dst] = uint64(v)

			case opSetcc:
				if evalCC(s, in.cc) {
					regs[in.dst] = (regs[in.dst] & ^uint64(0xFF)) | 1
				} else {
					regs[in.dst] = regs[in.dst] & ^uint64(0xFF)
				}

			case opCmovcc:
				if evalCC(s, in.cc) {
					writeReg(regs, in.dst, regs[in.src], in.size)
				}

			case opIMul:
				a := int64(truncate(regs[in.dst], in.size))
				b := int64(truncate(regs[in.src], in.size))
				r := uint64(a * b)
				writeReg(regs, in.dst, r, in.size)
				// Simplified flags
				fl := *s.Rflags &^ (flagCF | flagOF)
				*s.Rflags = fl

			case opSyscall:
				*s.RIP = in.nextRIP
				s.Trap = true
				return nil

			case opVmcall:
				*s.RIP = in.nextRIP
				s.Trap = true
				return nil

			case opEnd:
				*s.RIP = in.nextRIP
				return nil
			}
		}
		return nil
	}
}

// =========================================================================
// Helper functions
// =========================================================================

func resolveAddr(s *State, in *insn) uint64 {
	if in.useRIP {
		return uint64(int64(in.nextRIP) + in.memDisp)
	}
	var addr uint64
	if in.memBase >= 0 {
		addr = s.Regs[in.memBase]
	}
	if in.memIdx >= 0 {
		addr += s.Regs[in.memIdx] * uint64(in.memScale)
	}
	addr = uint64(int64(addr) + in.memDisp)
	return addr
}

func truncate(v uint64, size int) uint64 {
	switch size {
	case 1:
		return v & 0xFF
	case 2:
		return v & 0xFFFF
	case 4:
		return v & 0xFFFFFFFF
	default:
		return v
	}
}

func writeReg(regs *[16]uint64, idx int, val uint64, size int) {
	switch size {
	case 1:
		regs[idx] = (regs[idx] & ^uint64(0xFF)) | (val & 0xFF)
	case 2:
		regs[idx] = (regs[idx] & ^uint64(0xFFFF)) | (val & 0xFFFF)
	case 4:
		regs[idx] = val & 0xFFFFFFFF // zero-extend
	default:
		regs[idx] = val
	}
}

func doALU(s *State, op aluOp, a, b uint64, size int) uint64 {
	var r uint64
	mask := truncate(^uint64(0), size)
	switch op {
	case aluADD:
		r = (a + b) & mask
		setAddFlags(s, a, b, r, size)
	case aluSUB, aluCMP:
		r = (a - b) & mask
		setSubFlags(s, a, b, r, size)
	case aluAND:
		r = a & b
		setLogicFlags(s, r, size)
	case aluOR:
		r = a | b
		setLogicFlags(s, r, size)
	case aluXOR:
		r = a ^ b
		setLogicFlags(s, r, size)
	case aluADC:
		cf := uint64(0)
		if *s.Rflags&flagCF != 0 {
			cf = 1
		}
		r = (a + b + cf) & mask
		setAddFlags(s, a, b+cf, r, size)
	case aluSBB:
		cf := uint64(0)
		if *s.Rflags&flagCF != 0 {
			cf = 1
		}
		r = (a - b - cf) & mask
		setSubFlags(s, a, b+cf, r, size)
	}
	return r
}

func signBit(v uint64, size int) bool {
	switch size {
	case 1:
		return v&0x80 != 0
	case 2:
		return v&0x8000 != 0
	case 4:
		return v&0x80000000 != 0
	default:
		return v&0x8000000000000000 != 0
	}
}

func setAddFlags(s *State, a, b, r uint64, size int) {
	fl := *s.Rflags &^ (flagCF | flagZF | flagSF | flagOF | flagPF)
	mask := truncate(^uint64(0), size)
	if (a+b)&(mask+1) != 0 || (a+b) > mask {
		if a+b != r { // carry
			fl |= flagCF
		}
	}
	if r == 0 {
		fl |= flagZF
	}
	if signBit(r, size) {
		fl |= flagSF
	}
	// Overflow: both operands same sign, result different
	if signBit(a, size) == signBit(b, size) && signBit(a, size) != signBit(r, size) {
		fl |= flagOF
	}
	if bits.OnesCount8(uint8(r)) % 2 == 0 {
		fl |= flagPF
	}
	*s.Rflags = fl
}

func setSubFlags(s *State, a, b, r uint64, size int) {
	fl := *s.Rflags &^ (flagCF | flagZF | flagSF | flagOF | flagPF)
	if b > a {
		fl |= flagCF
	}
	if r == 0 || truncate(r, size) == 0 {
		fl |= flagZF
	}
	if signBit(r, size) {
		fl |= flagSF
	}
	if signBit(a, size) != signBit(b, size) && signBit(a, size) != signBit(r, size) {
		fl |= flagOF
	}
	if bits.OnesCount8(uint8(r)) % 2 == 0 {
		fl |= flagPF
	}
	*s.Rflags = fl
}

func setLogicFlags(s *State, r uint64, size int) {
	fl := *s.Rflags &^ (flagCF | flagZF | flagSF | flagOF | flagPF)
	// CF and OF always cleared for logic ops
	if truncate(r, size) == 0 {
		fl |= flagZF
	}
	if signBit(r, size) {
		fl |= flagSF
	}
	if bits.OnesCount8(uint8(r)) % 2 == 0 {
		fl |= flagPF
	}
	*s.Rflags = fl
}

func evalCC(s *State, cc condCode) bool {
	fl := *s.Rflags
	cf := fl&flagCF != 0
	zf := fl&flagZF != 0
	sf := fl&flagSF != 0
	of := fl&flagOF != 0

	switch cc {
	case ccO:
		return of
	case ccNO:
		return !of
	case ccB:
		return cf
	case ccNB:
		return !cf
	case ccZ:
		return zf
	case ccNZ:
		return !zf
	case ccBE:
		return cf || zf
	case ccA:
		return !cf && !zf
	case ccS:
		return sf
	case ccNS:
		return !sf
	case ccP:
		return fl&flagPF != 0
	case ccNP:
		return fl&flagPF == 0
	case ccL:
		return sf != of
	case ccGE:
		return sf == of
	case ccLE:
		return zf || sf != of
	case ccG:
		return !zf && sf == of
	}
	return false
}

// Suppress unused import warnings
var _ = math.MaxFloat64

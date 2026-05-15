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
	"encoding/binary"
	"fmt"
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

// Block pairs a compiled closure (or generated machine code) with a snapshot
// of the code pages it was decoded from, so self-modifying code invalidates
// it lazily and precisely.
type Block struct {
	fn        CompiledBlock
	pageAddrs []uint64
	pages     []*mmu.PageEntry
	vers      []uint32
	// native, when non-zero, is the entry point of generated machine code
	// that supersedes fn; ninsn is how many guest instructions it retires.
	native      uintptr
	ninsn       int
	nativeMMX   bool
	nativeMem   bool
	nativeTable mmu.NativeTableDescriptor
}

// Valid reports whether none of the block's code pages were written since
// compilation.
func (b *Block) Valid() bool {
	for i, pe := range b.pages {
		if pe.CodeVersion.Load() != b.vers[i] {
			return false
		}
	}
	return true
}

func (b *Block) validForMapping(mem *mmu.MMU) bool {
	if !b.Valid() {
		return false
	}
	for i, addr := range b.pageAddrs {
		pe, _, err := mem.LookupRead(addr, mmu.PermExecute)
		if err != nil || pe != b.pages[i] {
			return false
		}
	}
	return true
}

// Run executes the block: generated machine code when available, otherwise
// the closure interpreter.
func (b *Block) Run(s *State) error {
	if b.native != 0 {
		if b.nativeMMX && (s.FPUST == nil || s.FPUTop == nil || s.FPUTW == nil) ||
			b.nativeMem && s.Mem.WatchCB != nil {
			if b.nativeMem {
				s.InvalidatePageCache()
			}
			return b.fn(s)
		}
		retired, fallback := runNative(b.native, s, &b.nativeTable)
		if s.Instret != nil {
			if fallback {
				*s.Instret += retired
			} else {
				*s.Instret += uint64(b.ninsn)
			}
		}
		return nil
	}
	return b.fn(s)
}

// State is the JIT execution context - a flat struct for fast access.
type State struct {
	Regs     *[16]uint64
	RIP      *uint64
	Rflags   *uint64
	Mem      *mmu.MMU
	XMM      *[16][2]uint64
	FPUST    *[8]float64
	FPUTop   *int
	FPUCW    *uint16
	FPUSW    *uint16
	FPUTW    *uint16
	FSBase   uint64
	GSBase   uint64
	Mode32   bool
	Fallback bool
	// Set to true if a vmcall/syscall was hit; caller must return to interpreter.
	Trap bool
	// Instret, when non-nil, is incremented once per retired instruction so
	// the CPU's counter (and the RDTSC it backs) advances at the same rate
	// as under the interpreter.
	Instret *uint64
	// x87Unmasked is set by the closure x87 helpers when an enabled exception
	// is raised. The executor uses it to restore the pre-instruction state.
	x87Unmasked bool
	// One-entry data-page caches for the block executor's memory helpers.
	// Invalidated by the CPU wrapper whenever the mapping generation moves.
	rdBase      uint64
	rdPage      *mmu.PageEntry
	wrBase      uint64
	wrPage      *mmu.PageEntry
	flatChecked bool
	flat        []byte
	perm        []byte
}

// InvalidatePageCache drops the cached data pages (after a mapping change).
func (s *State) InvalidatePageCache() {
	s.rdPage = nil
	s.wrPage = nil
}

func (s *State) fillRead(addr uint64) {
	if s.Mem.WatchCB != nil {
		return
	}
	base := addr & mmu.PageMask
	if pe, _, err := s.Mem.LookupRead(base, mmu.PermRead); err == nil {
		s.rdPage, s.rdBase = pe, base
	}
}

func (s *State) fillWrite(addr uint64) {
	if s.Mem.WatchCB != nil {
		return
	}
	base := addr & mmu.PageMask
	if pe, _, err := s.Mem.LookupRead(base, mmu.PermRead|mmu.PermWrite); err == nil {
		s.wrPage, s.wrBase = pe, base
	}
}

func (s *State) read8(addr uint64) (uint8, error) {
	if data, ok := s.flatAccess(addr, 1, mmu.PermRead); ok {
		return data[0], nil
	}
	if s.rdPage != nil && addr&mmu.PageMask == s.rdBase {
		return s.rdPage.Data[addr&(mmu.PageSize-1)], nil
	}
	s.fillRead(addr)
	return s.Mem.Read8(addr)
}

func (s *State) read16(addr uint64) (uint16, error) {
	if data, ok := s.flatAccess(addr, 2, mmu.PermRead); ok {
		return binary.LittleEndian.Uint16(data), nil
	}
	off := addr & (mmu.PageSize - 1)
	if s.rdPage != nil && addr&mmu.PageMask == s.rdBase && off <= mmu.PageSize-2 {
		return binary.LittleEndian.Uint16(s.rdPage.Data[off:]), nil
	}
	s.fillRead(addr)
	return s.Mem.Read16(addr)
}

func (s *State) read32(addr uint64) (uint32, error) {
	if data, ok := s.flatAccess(addr, 4, mmu.PermRead); ok {
		return binary.LittleEndian.Uint32(data), nil
	}
	off := addr & (mmu.PageSize - 1)
	if s.rdPage != nil && addr&mmu.PageMask == s.rdBase && off <= mmu.PageSize-4 {
		return binary.LittleEndian.Uint32(s.rdPage.Data[off:]), nil
	}
	s.fillRead(addr)
	return s.Mem.Read32(addr)
}

func (s *State) read64(addr uint64) (uint64, error) {
	if data, ok := s.flatAccess(addr, 8, mmu.PermRead); ok {
		return binary.LittleEndian.Uint64(data), nil
	}
	off := addr & (mmu.PageSize - 1)
	if s.rdPage != nil && addr&mmu.PageMask == s.rdBase && off <= mmu.PageSize-8 {
		return binary.LittleEndian.Uint64(s.rdPage.Data[off:]), nil
	}
	s.fillRead(addr)
	return s.Mem.Read64(addr)
}

func (s *State) write8(addr uint64, v uint8) error {
	if data, ok := s.flatWriteAccess(addr, 1); ok {
		data[0] = v
		return nil
	}
	if s.Mem.WatchCB == nil && s.wrPage != nil && addr&mmu.PageMask == s.wrBase {
		s.wrPage.Data[addr&(mmu.PageSize-1)] = v
		if s.wrPage.Perms&mmu.PermExecute != 0 {
			s.Mem.NoteExecutableWrite(s.wrPage)
		}
		return nil
	}
	s.fillWrite(addr)
	return s.Mem.Write8(addr, v)
}

func (s *State) write16(addr uint64, v uint16) error {
	if data, ok := s.flatWriteAccess(addr, 2); ok {
		binary.LittleEndian.PutUint16(data, v)
		return nil
	}
	off := addr & (mmu.PageSize - 1)
	if s.Mem.WatchCB == nil && s.wrPage != nil && addr&mmu.PageMask == s.wrBase && off <= mmu.PageSize-2 {
		binary.LittleEndian.PutUint16(s.wrPage.Data[off:], v)
		if s.wrPage.Perms&mmu.PermExecute != 0 {
			s.Mem.NoteExecutableWrite(s.wrPage)
		}
		return nil
	}
	s.fillWrite(addr)
	return s.Mem.Write16(addr, v)
}

func (s *State) write32(addr uint64, v uint32) error {
	if data, ok := s.flatWriteAccess(addr, 4); ok {
		binary.LittleEndian.PutUint32(data, v)
		return nil
	}
	off := addr & (mmu.PageSize - 1)
	if s.Mem.WatchCB == nil && s.wrPage != nil && addr&mmu.PageMask == s.wrBase && off <= mmu.PageSize-4 {
		binary.LittleEndian.PutUint32(s.wrPage.Data[off:], v)
		if s.wrPage.Perms&mmu.PermExecute != 0 {
			s.Mem.NoteExecutableWrite(s.wrPage)
		}
		return nil
	}
	s.fillWrite(addr)
	return s.Mem.Write32(addr, v)
}

func (s *State) write64(addr uint64, v uint64) error {
	if data, ok := s.flatWriteAccess(addr, 8); ok {
		binary.LittleEndian.PutUint64(data, v)
		return nil
	}
	off := addr & (mmu.PageSize - 1)
	if s.Mem.WatchCB == nil && s.wrPage != nil && addr&mmu.PageMask == s.wrBase && off <= mmu.PageSize-8 {
		binary.LittleEndian.PutUint64(s.wrPage.Data[off:], v)
		if s.wrPage.Perms&mmu.PermExecute != 0 {
			s.Mem.NoteExecutableWrite(s.wrPage)
		}
		return nil
	}
	s.fillWrite(addr)
	return s.Mem.Write64(addr, v)
}

func (s *State) flatAccess(addr uint64, size uint64, required uint8) ([]byte, bool) {
	if !s.Mode32 || s.Mem.WatchCB != nil || size == 0 {
		return nil, false
	}
	if !s.flatChecked {
		s.initFlat()
	}
	if s.flat == nil || s.perm == nil {
		return nil, false
	}
	lastAddr := addr + size - 1
	if lastAddr >= 1<<32 {
		return nil, false
	}
	first, last := addr>>mmu.PageShift, lastAddr>>mmu.PageShift
	if s.perm[first]&required != required {
		return nil, false
	}
	if first != last && s.perm[last]&required != required {
		return nil, false
	}
	return s.flat[addr : addr+size], true
}

//go:noinline
func (s *State) initFlat() {
	s.flatChecked = true
	s.flat = s.Mem.FlatBase()
	s.perm = s.Mem.PermBitmap()
}

func (s *State) flatWriteAccess(addr uint64, size uint64) ([]byte, bool) {
	if s.Mem.WatchCB != nil {
		return nil, false
	}
	data, ok := s.flatAccess(addr, size, mmu.PermWrite)
	if !ok {
		return nil, false
	}
	first, last := addr>>mmu.PageShift, (addr+size-1)>>mmu.PageShift
	if s.perm[first]&mmu.PermExecute != 0 || s.perm[last]&mmu.PermExecute != 0 {
		return nil, false
	}
	return data, true
}

func (s *State) checkWriteRange(addr uint64, size int) error {
	if size <= 0 {
		return nil
	}
	return s.Mem.ValidateRange(addr, uint64(size), mmu.PermWrite)
}

// Cache holds compiled blocks and execution counters.
type Cache struct {
	mu       sync.RWMutex
	blocks   map[uint64]*Block
	counters map[uint64]uint32
	disabled map[uint64]struct{}
	mem      *mmu.MMU
	mode32   bool
	// exec holds generated machine code when the native backend is on.
	exec *execBuf
	// nativeMem enables native flat-memory load/store codegen (requires
	// Mode32 flat backing or the sparse PE64 native table).
	nativeMem   bool
	nativeTable mmu.NativeTableDescriptor
	// nativeX87 enables native x87 codegen (opt-in, off by default until
	// broadly certified against the interpreter).
	nativeX87 bool
}

// NewCache creates a JIT cache.
func NewCache(mem *mmu.MMU) *Cache {
	return NewCacheMode(mem, false)
}

func NewCacheMode(mem *mmu.MMU, mode32 bool) *Cache {
	return &Cache{
		blocks:   make(map[uint64]*Block),
		counters: make(map[uint64]uint32),
		disabled: make(map[uint64]struct{}),
		mem:      mem,
		mode32:   mode32,
	}
}

// EnableNativeCodegen turns on the machine-code backend for this cache. It
// allocates an executable arena; if that fails (hardened kernels), native
// codegen stays off and the closure backend is used unchanged.
func (c *Cache) EnableNativeCodegen() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.exec != nil {
		return true
	}
	buf, err := newExecBuf()
	if err != nil {
		return false
	}
	c.exec = buf
	if c.mode32 {
		c.nativeMem = c.mem.FlatBase() != nil && c.mem.PermBitmap() != nil
	} else {
		c.nativeTable = c.mem.NativeTable()
		c.nativeMem = nativeDescriptorSupported(c.nativeTable)
	}
	return true
}

// Lookup returns a compiled block for the given address, or nil.
// It also increments the execution counter.
func (c *Cache) Lookup(addr uint64) *Block {
	c.mu.RLock()
	if b, ok := c.blocks[addr]; ok {
		c.mu.RUnlock()
		return b
	}
	if _, ok := c.disabled[addr]; ok {
		c.mu.RUnlock()
		return nil
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()
	if b, ok := c.blocks[addr]; ok {
		return b
	}
	if _, ok := c.disabled[addr]; ok {
		return nil
	}
	c.counters[addr]++
	count := c.counters[addr]
	if count < CompileThreshold {
		return nil
	}
	b := c.compile(addr)
	if b != nil {
		c.blocks[addr] = b
	} else {
		c.disabled[addr] = struct{}{}
	}
	delete(c.counters, addr)
	return b
}

// Compile promotes an address immediately after the caller has established
// that it is hot. The result is cached, including unsupported addresses.
func (c *Cache) Compile(addr uint64) *Block {
	c.mu.Lock()
	defer c.mu.Unlock()
	if b, ok := c.blocks[addr]; ok {
		return b
	}
	if _, ok := c.disabled[addr]; ok {
		return nil
	}
	b := c.compile(addr)
	if b != nil {
		c.blocks[addr] = b
	} else {
		c.disabled[addr] = struct{}{}
	}
	delete(c.counters, addr)
	return b
}

// Drop removes the cached block starting at addr (e.g. after its code pages
// were overwritten) so it can be recompiled from the fresh bytes.
func (c *Cache) Drop(addr uint64) {
	c.mu.Lock()
	delete(c.blocks, addr)
	delete(c.disabled, addr)
	delete(c.counters, addr)
	c.mu.Unlock()
}

func (c *Cache) Reset() {
	c.mu.Lock()
	for addr, block := range c.blocks {
		if !block.validForMapping(c.mem) {
			delete(c.blocks, addr)
		}
	}
	clear(c.counters)
	clear(c.disabled)
	c.mu.Unlock()
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
	for k := range c.disabled {
		if k&^(mmu.PageSize-1) == page {
			delete(c.disabled, k)
		}
	}
	c.mu.Unlock()
}

// compile decodes a basic block starting at addr and returns a compiled block.
func (c *Cache) compile(addr uint64) *Block {
	// Snapshot the code-page versions BEFORE decoding: a write that lands
	// during decode then fails Valid() instead of surviving in a stale block.
	// A block is at most MaxBlockInsns*15 bytes, so it spans at most 3 pages.
	const maxSpan = 3
	var prePages [maxSpan]*mmu.PageEntry
	var preVers [maxSpan]uint32
	for i := 0; i < maxSpan; i++ {
		page := addr&mmu.PageMask + uint64(i)*mmu.PageSize
		if pe, _, err := c.mem.LookupRead(page, 0); err == nil && pe != nil {
			prePages[i] = pe
			preVers[i] = pe.CodeVersion.Load()
		}
	}
	insns, end, err := c.decode(addr)
	if err != nil || len(insns) == 0 || len(insns) == 1 && insns[0].kind == opEnd {
		return nil
	}
	fn := c.emit(insns)
	if fn == nil {
		return nil
	}
	b := &Block{fn: fn}
	// Prefer generated machine code when the native backend accepts the
	// whole block; the closure stays as the fallback path.
	if c.exec != nil {
		if entry, ninsn, usesMMX, usesMemory := c.compileNative(insns); entry != 0 {
			b.native = entry
			b.ninsn = ninsn
			b.nativeMMX = usesMMX
			b.nativeMem = usesMemory
			if usesMemory && !c.mode32 {
				b.nativeTable = c.nativeTable
			}
		}
	}
	if end <= addr {
		end = addr + 1
	}
	for i := 0; i < maxSpan; i++ {
		page := addr&mmu.PageMask + uint64(i)*mmu.PageSize
		if page >= end {
			break
		}
		if prePages[i] == nil {
			continue
		}
		b.pageAddrs = append(b.pageAddrs, page)
		b.pages = append(b.pages, prePages[i])
		b.vers = append(b.vers, preVers[i])
	}
	return b
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
	opALURegReg // ADD/SUB/AND/OR/XOR/CMP
	opALURegImm
	opALURegMem
	opALUMemReg
	opALUMemImm
	opLea
	opPush
	opPop
	opCall
	opRet
	opJmp
	opJcc
	opTest
	opTestImm
	opXchg
	opCdq // CDQ/CQO
	opMovzx
	opMovsx
	opSetcc
	opCmovcc
	opIMul
	opIMul3
	opDiv
	opIDiv
	opShift // SHL/SHR/SAR/ROL/ROR
	opNot
	opNeg
	opInc
	opDec
	opX87
	opMMX
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
	kind     opKind
	rip      uint64
	size     int   // operand size in bytes (1, 2, 4, 8)
	srcSize  int   // source size when it differs from the destination
	dst      int   // register index or -1
	src      int   // register index or -1
	imm      int64 // immediate value
	memBase  int   // base register for memory operand
	memIdx   int   // index register (-1 if none)
	memScale uint8 // scale (1, 2, 4, 8)
	memDisp  int64 // displacement
	alu      aluOp
	cc       condCode
	shift    shiftOp
	nextRIP  uint64 // address of next instruction
	target   uint64 // branch target address
	useRIP   bool   // memory operand is RIP-relative
	opcode   byte
}

// RFLAGS bits
const (
	flagCF = 1 << 0
	flagPF = 1 << 2
	flagAF = 1 << 4
	flagZF = 1 << 6
	flagSF = 1 << 7
	flagDF = 1 << 10
	flagOF = 1 << 11
)

// =========================================================================
// Basic block decoder
// =========================================================================

type decoder struct {
	mem    *mmu.MMU
	pos    uint64
	insns  []insn
	mode32 bool
}

func (c *Cache) decode(addr uint64) ([]insn, uint64, error) {
	d := &decoder{mem: c.mem, pos: addr, mode32: c.mode32}
	for len(d.insns) < MaxBlockInsns {
		instructionStart := d.pos
		firstInstruction := len(d.insns)
		if err := d.decodeOne(); err != nil {
			// Can't decode, end block here
			if len(d.insns) == 0 {
				return nil, d.pos, err
			}
			d.insns = append(d.insns, insn{kind: opEnd, nextRIP: instructionStart})
			d.insns[len(d.insns)-1].rip = instructionStart
			return d.insns, d.pos, nil
		}
		instructionEnd := d.pos
		for i := firstInstruction; i < len(d.insns); i++ {
			d.insns[i].rip = instructionStart
			if d.insns[i].kind != opEnd {
				d.insns[i].nextRIP = instructionEnd
				if d.mode32 {
					d.insns[i].nextRIP &= 0xFFFFFFFF
				}
			}
		}
		last := d.insns[len(d.insns)-1]
		// Block terminators
		switch last.kind {
		case opRet, opJmp, opCall, opSyscall, opVmcall, opEnd:
			return d.insns, d.pos, nil
		case opJcc:
			return d.insns, d.pos, nil
		}
	}
	if len(d.insns) > 0 {
		d.insns = append(d.insns, insn{kind: opJmp, rip: d.pos, target: d.pos, nextRIP: d.pos})
	}
	return d.insns, d.pos, nil
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

func usesLegacyHighByte(reg int, p *pfx) bool {
	return reg >= 4 && reg < 8 && !p.hasREX
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
		useRIP = !d.mode32
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
		case b == 0xF0 || b == 0xF2 || b == 0xF3 || b == 0x64 || b == 0x65 ||
			b == 0x26 || b == 0x2E || b == 0x36 || b == 0x3E || b == 0x67:
			d.pos = startPos
			d.insns = append(d.insns, insn{kind: opEnd, nextRIP: startPos})
			return nil
		case b >= 0x40 && b <= 0x4F:
			if d.mode32 {
				return d.decodeOpcode(b, &p, startPos)
			}
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
		if p.rexB() {
			d.insns = append(d.insns, insn{kind: opXchg, size: size, dst: 0, src: 8})
		} else {
			d.insns = append(d.insns, insn{kind: opNop})
		}
		return nil

	// INC/DEC r32 in 32-bit mode. In 64-bit mode these bytes are REX prefixes.
	case 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47:
		if !d.mode32 {
			d.pos = startPos
			d.insns = append(d.insns, insn{kind: opEnd, nextRIP: startPos})
			return nil
		}
		d.insns = append(d.insns, insn{kind: opInc, size: 4, dst: int(op - 0x40)})
		return nil
	case 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F:
		if !d.mode32 {
			d.pos = startPos
			d.insns = append(d.insns, insn{kind: opEnd, nextRIP: startPos})
			return nil
		}
		d.insns = append(d.insns, insn{kind: opDec, size: 4, dst: int(op - 0x48)})
		return nil

	case 0xCC, 0xCD, 0xCE: // INT3, INT, INTO - end block
		d.pos = startPos
		d.insns = append(d.insns, insn{kind: opEnd, nextRIP: startPos})
		return nil

	// MOV r, imm (0xB0-0xBF)
	case 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7:
		reg := regIdx(op-0xB0, p.rexB())
		if usesLegacyHighByte(reg, p) {
			d.pos = startPos
			d.insns = append(d.insns, insn{kind: opEnd, nextRIP: startPos})
			return nil
		}
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

	// PUSH r16/r32/r64 (0x50-0x57)
	case 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57:
		reg := regIdx(op-0x50, p.rexB())
		stackSize := 4
		if !d.mode32 {
			stackSize = 8
		}
		if p.op66 {
			stackSize = 2
		}
		d.insns = append(d.insns, insn{kind: opPush, size: stackSize, src: reg})
		return nil

	// POP r16/r32/r64 (0x58-0x5F)
	case 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F:
		reg := regIdx(op-0x58, p.rexB())
		stackSize := 4
		if !d.mode32 {
			stackSize = 8
		}
		if p.op66 {
			stackSize = 2
		}
		d.insns = append(d.insns, insn{kind: opPop, size: stackSize, dst: reg})
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
		if d.mode32 {
			target &= 0xFFFFFFFF
		}
		d.insns = append(d.insns, insn{kind: opCall, target: target, nextRIP: d.pos})
		return nil

	// JMP rel8 (0xEB)
	case 0xEB:
		rel, err := d.fetch8()
		if err != nil {
			return err
		}
		target := d.pos + uint64(int64(int8(rel)))
		if d.mode32 {
			target &= 0xFFFFFFFF
		}
		d.insns = append(d.insns, insn{kind: opJmp, target: target, nextRIP: d.pos})
		return nil

	// JMP rel32 (0xE9)
	case 0xE9:
		rel, err := d.fetch32()
		if err != nil {
			return err
		}
		target := d.pos + uint64(int64(int32(rel)))
		if d.mode32 {
			target &= 0xFFFFFFFF
		}
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
		if d.mode32 {
			target &= 0xFFFFFFFF
		}
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
		if sz == 1 && (usesLegacyHighByte(reg, p) || isReg && usesLegacyHighByte(rm, p)) {
			d.pos = startPos
			d.insns = append(d.insns, insn{kind: opEnd, nextRIP: startPos})
			return nil
		}
		if !isReg {
			d.insns = append(d.insns, insn{kind: opALUMemReg, size: sz, src: reg, alu: aop,
				memBase: base, memIdx: idx, memScale: scale, memDisp: disp, useRIP: useRIP})
			return nil
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
		if sz == 1 && (usesLegacyHighByte(reg, p) || isReg && usesLegacyHighByte(rm, p)) {
			d.pos = startPos
			d.insns = append(d.insns, insn{kind: opEnd, nextRIP: startPos})
			return nil
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
	case 0x80, 0x81, 0x83:
		reg, isReg, rm, base, idx, scale, disp, useRIP, err := d.decodeModRM(p)
		if err != nil {
			return err
		}
		aop := aluOp(reg)
		operandSize := size
		if op == 0x80 {
			operandSize = 1
		}
		var immVal int64
		if op == 0x80 {
			ib, e := d.fetch8()
			if e != nil {
				return e
			}
			immVal = int64(ib)
		} else if op == 0x83 {
			ib, e := d.fetch8()
			if e != nil {
				return e
			}
			immVal = int64(int8(ib))
		} else if size == 2 {
			i16, e := d.fetch16()
			if e != nil {
				return e
			}
			immVal = int64(i16)
		} else {
			i32, e := d.fetch32()
			if e != nil {
				return e
			}
			immVal = int64(int32(i32))
		}
		if isReg {
			if operandSize == 1 && usesLegacyHighByte(rm, p) {
				d.pos = startPos
				d.insns = append(d.insns, insn{kind: opEnd, nextRIP: startPos})
				return nil
			}
			d.insns = append(d.insns, insn{kind: opALURegImm, size: operandSize, dst: rm, alu: aop, imm: immVal})
		} else {
			d.insns = append(d.insns, insn{kind: opALUMemImm, size: operandSize, alu: aop, imm: immVal,
				memBase: base, memIdx: idx, memScale: scale, memDisp: disp, useRIP: useRIP})
		}
		return nil

	// Group 2: rotate/shift r/m by 1, CL, or imm8.
	case 0xC0, 0xC1, 0xD0, 0xD1, 0xD2, 0xD3:
		reg, isReg, rm, _, _, _, _, _, err := d.decodeModRM(p)
		if err != nil {
			return err
		}
		sz := size
		if op == 0xC0 || op == 0xD0 || op == 0xD2 {
			sz = 1
		}
		if !isReg || sz == 1 && usesLegacyHighByte(rm, p) ||
			reg != int(shROL) && reg != int(shROR) && reg != int(shSHL) && reg != int(shSHR) && reg != int(shSAR) {
			d.pos = startPos
			d.insns = append(d.insns, insn{kind: opEnd, nextRIP: startPos})
			return nil
		}
		count := int64(1)
		src := -1
		if op == 0xC0 || op == 0xC1 {
			imm, err := d.fetch8()
			if err != nil {
				return err
			}
			count = int64(imm)
		} else if op == 0xD2 || op == 0xD3 {
			count = -1
			src = 1
		}
		d.insns = append(d.insns, insn{kind: opShift, size: sz, dst: rm, src: src, shift: shiftOp(reg), imm: count})
		return nil

	// MOV r/m, r (0x88/0x89)
	case 0x88, 0x89:
		movSize := size
		if op == 0x88 {
			movSize = 1
		}
		reg, isReg, rm, base, idx, scale, disp, useRIP, err := d.decodeModRM(p)
		if err != nil {
			return err
		}
		if movSize == 1 && (usesLegacyHighByte(reg, p) || isReg && usesLegacyHighByte(rm, p)) {
			d.pos = startPos
			d.insns = append(d.insns, insn{kind: opEnd, nextRIP: startPos})
			return nil
		}
		if isReg {
			d.insns = append(d.insns, insn{kind: opMovRegReg, size: movSize, dst: rm, src: reg})
		} else {
			d.insns = append(d.insns, insn{kind: opMovMemReg, size: movSize, src: reg,
				memBase: base, memIdx: idx, memScale: scale, memDisp: disp, useRIP: useRIP})
		}
		return nil

	// MOV r, r/m (0x8A/0x8B)
	case 0x8A, 0x8B:
		movSize := size
		if op == 0x8A {
			movSize = 1
		}
		reg, isReg, rm, base, idx, scale, disp, useRIP, err := d.decodeModRM(p)
		if err != nil {
			return err
		}
		if movSize == 1 && (usesLegacyHighByte(reg, p) || isReg && usesLegacyHighByte(rm, p)) {
			d.pos = startPos
			d.insns = append(d.insns, insn{kind: opEnd, nextRIP: startPos})
			return nil
		}
		if isReg {
			d.insns = append(d.insns, insn{kind: opMovRegReg, size: movSize, dst: reg, src: rm})
		} else {
			d.insns = append(d.insns, insn{kind: opMovRegMem, size: movSize, dst: reg,
				memBase: base, memIdx: idx, memScale: scale, memDisp: disp, useRIP: useRIP})
		}
		return nil

	// MOV r/m, imm (0xC6/0xC7)
	case 0xC6, 0xC7:
		extension, isReg, rm, base, idx, scale, disp, useRIP, err := d.decodeModRM(p)
		if err != nil {
			return err
		}
		if extension&7 != 0 {
			d.pos = startPos
			d.insns = append(d.insns, insn{kind: opEnd, nextRIP: startPos})
			return nil
		}
		movSize := size
		var immVal int64
		if op == 0xC6 {
			movSize = 1
			imm, err := d.fetch8()
			if err != nil {
				return err
			}
			immVal = int64(imm)
		} else if size == 2 {
			imm, err := d.fetch16()
			if err != nil {
				return err
			}
			immVal = int64(imm)
		} else {
			imm, err := d.fetch32()
			if err != nil {
				return err
			}
			immVal = int64(int32(imm))
		}
		if isReg {
			if movSize == 1 && usesLegacyHighByte(rm, p) {
				d.pos = startPos
				d.insns = append(d.insns, insn{kind: opEnd, nextRIP: startPos})
				return nil
			}
			d.insns = append(d.insns, insn{kind: opMovRegImm, size: movSize, dst: rm, imm: immVal})
		} else {
			d.insns = append(d.insns, insn{kind: opMovMemImm, size: movSize, imm: immVal,
				memBase: base, memIdx: idx, memScale: scale, memDisp: disp, useRIP: useRIP})
		}
		return nil

	// LEA r, m (0x8D)
	case 0x8D:
		reg, isReg, _, base, idx, scale, disp, useRIP, err := d.decodeModRM(p)
		if err != nil {
			return err
		}
		if isReg {
			d.pos = startPos
			d.insns = append(d.insns, insn{kind: opEnd, nextRIP: startPos})
			return nil
		}
		d.insns = append(d.insns, insn{kind: opLea, size: size, dst: reg,
			memBase: base, memIdx: idx, memScale: scale, memDisp: disp, useRIP: useRIP})
		return nil

	// TEST r/m, r (0x84/0x85)
	case 0x84, 0x85:
		reg, isReg, rm, base, idx, scale, disp, useRIP, err := d.decodeModRM(p)
		if err != nil {
			return err
		}
		testSize := size
		if op == 0x84 {
			testSize = 1
		}
		if testSize == 1 && (usesLegacyHighByte(reg, p) || isReg && usesLegacyHighByte(rm, p)) {
			d.pos = startPos
			d.insns = append(d.insns, insn{kind: opEnd, nextRIP: startPos})
			return nil
		}
		if isReg {
			d.insns = append(d.insns, insn{kind: opTest, size: testSize, dst: rm, src: reg})
		} else {
			_ = base
			_ = idx
			_ = scale
			_ = disp
			_ = useRIP
			d.insns = append(d.insns, insn{kind: opEnd, nextRIP: startPos})
		}
		return nil

	// TEST AL/rAX, imm (0xA8/0xA9)
	case 0xA8:
		imm, err := d.fetch8()
		if err != nil {
			return err
		}
		d.insns = append(d.insns, insn{kind: opTestImm, size: 1, dst: 0, imm: int64(imm)})
		return nil
	case 0xA9:
		var imm int64
		if size == 2 {
			value, err := d.fetch16()
			if err != nil {
				return err
			}
			imm = int64(value)
		} else {
			value, err := d.fetch32()
			if err != nil {
				return err
			}
			imm = int64(int32(value))
		}
		d.insns = append(d.insns, insn{kind: opTestImm, size: size, dst: 0, imm: imm})
		return nil

	// XCHG r/m, r (0x86/0x87)
	case 0x86, 0x87:
		reg, isReg, rm, _, _, _, _, _, err := d.decodeModRM(p)
		if err != nil {
			return err
		}
		xchgSize := size
		if op == 0x86 {
			xchgSize = 1
		}
		if !isReg || xchgSize == 1 && (usesLegacyHighByte(reg, p) || usesLegacyHighByte(rm, p)) {
			d.pos = startPos
			d.insns = append(d.insns, insn{kind: opEnd, nextRIP: startPos})
			return nil
		}
		d.insns = append(d.insns, insn{kind: opXchg, size: xchgSize, dst: rm, src: reg})
		return nil

	// XCHG rAX, r (0x91-0x97)
	case 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97:
		reg := regIdx(op-0x90, p.rexB())
		d.insns = append(d.insns, insn{kind: opXchg, size: size, dst: 0, src: reg})
		return nil

	// IMUL r, r/m, imm (0x69/0x6B)
	case 0x69, 0x6B:
		reg, isReg, rm, _, _, _, _, _, err := d.decodeModRM(p)
		if err != nil {
			return err
		}
		if !isReg {
			d.pos = startPos
			d.insns = append(d.insns, insn{kind: opEnd, nextRIP: startPos})
			return nil
		}
		var imm int64
		if op == 0x6B {
			value, err := d.fetch8()
			if err != nil {
				return err
			}
			imm = int64(int8(value))
		} else if size == 2 {
			value, err := d.fetch16()
			if err != nil {
				return err
			}
			imm = int64(int16(value))
		} else {
			value, err := d.fetch32()
			if err != nil {
				return err
			}
			imm = int64(int32(value))
		}
		d.insns = append(d.insns, insn{kind: opIMul3, size: size, dst: reg, src: rm, imm: imm})
		return nil

	// Group 3: TEST/NOT/NEG/DIV/IDIV register forms.
	case 0xF6, 0xF7:
		group, isReg, rm, _, _, _, _, _, err := d.decodeModRM(p)
		if err != nil {
			return err
		}
		groupSize := size
		if op == 0xF6 {
			groupSize = 1
		}
		if !isReg || groupSize == 1 && usesLegacyHighByte(rm, p) {
			d.pos = startPos
			d.insns = append(d.insns, insn{kind: opEnd, nextRIP: startPos})
			return nil
		}
		switch group {
		case 0, 1:
			var imm int64
			if groupSize == 1 {
				value, err := d.fetch8()
				if err != nil {
					return err
				}
				imm = int64(value)
			} else if groupSize == 2 {
				value, err := d.fetch16()
				if err != nil {
					return err
				}
				imm = int64(value)
			} else {
				value, err := d.fetch32()
				if err != nil {
					return err
				}
				imm = int64(int32(value))
			}
			d.insns = append(d.insns, insn{kind: opTestImm, size: groupSize, dst: rm, imm: imm})
		case 2:
			d.insns = append(d.insns, insn{kind: opNot, size: groupSize, dst: rm})
		case 3:
			d.insns = append(d.insns, insn{kind: opNeg, size: groupSize, dst: rm})
		case 6:
			d.insns = append(d.insns, insn{kind: opDiv, size: groupSize, src: rm})
		case 7:
			d.insns = append(d.insns, insn{kind: opIDiv, size: groupSize, src: rm})
		default:
			d.pos = startPos
			d.insns = append(d.insns, insn{kind: opEnd, nextRIP: startPos})
		}
		return nil

	// Group 4/5: INC/DEC register forms.
	case 0xFE, 0xFF:
		group, isReg, rm, _, _, _, _, _, err := d.decodeModRM(p)
		if err != nil {
			return err
		}
		groupSize := size
		if op == 0xFE {
			groupSize = 1
		}
		if !isReg || group > 1 || groupSize == 1 && usesLegacyHighByte(rm, p) {
			d.pos = startPos
			d.insns = append(d.insns, insn{kind: opEnd, nextRIP: startPos})
			return nil
		}
		kind := opInc
		if group == 1 {
			kind = opDec
		}
		d.insns = append(d.insns, insn{kind: kind, size: groupSize, dst: rm})
		return nil

	// CDQ/CQO (0x99)
	case 0x99:
		d.insns = append(d.insns, insn{kind: opCdq, size: size})
		return nil

	case 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF:
		if !d.mode32 {
			d.pos = startPos
			d.insns = append(d.insns, insn{kind: opEnd, nextRIP: startPos})
			return nil
		}
		reg, isReg, rm, base, idx, scale, disp, useRIP, err := d.decodeModRM(p)
		if err != nil {
			return err
		}
		if !supportsX87(op, isReg, reg, rm) {
			d.pos = startPos
			d.insns = append(d.insns, insn{kind: opEnd, nextRIP: startPos})
			return nil
		}
		d.insns = append(d.insns, insn{kind: opX87, dst: reg, src: rm, imm: int64(op),
			memBase: base, memIdx: idx, memScale: scale, memDisp: disp, useRIP: useRIP})
		if isReg {
			d.insns[len(d.insns)-1].size = 1
		}
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

func supportsX87(op byte, registerForm bool, reg, rm int) bool {
	if registerForm {
		switch op {
		case 0xD8: // FADD/FMUL/FCOM/FCOMP/FSUB/FSUBR/FDIV/FDIVR ST(0), ST(i)
			return true
		case 0xD9:
			switch reg {
			case 0, 1: // FLD ST(i), FXCH ST(i)
				return true
			case 4: // FCHS, FABS, FTST, FXAM
				return rm == 0 || rm == 1 || rm == 4 || rm == 5
			case 5: // FLD1/FLDL2T/FLDL2E/FLDPI/FLDLN2/FLDLG2/FLDZ
				return rm != 7
			case 6: // F2XM1/FYL2X/FPTAN/FPATAN/FXTRACT/FPREM1/FDECSTP/FINCSTP
				return true
			case 7: // FPREM/FYL2XP1/FSQRT/FSINCOS/FRNDINT/FSCALE/FSIN/FCOS
				return true
			}
			return false
		case 0xDC: // FADD/FMUL/FSUBR/FSUB/FDIVR/FDIV ST(i), ST(0)
			return reg == 0 || reg == 1 || reg >= 4
		case 0xDD: // FFREE/FST/FSTP/FUCOM/FUCOMP ST(i)
			return reg == 0 || reg == 2 || reg == 3 || reg == 4 || reg == 5
		case 0xDE: // FADDP/FMULP/FCOMPP/FSUBRP/FSUBP/FDIVRP/FDIVP
			return reg == 0 || reg == 1 || reg >= 4 || reg == 3 && rm == 1
		case 0xDF: // FNSTSW AX
			return reg == 4 && rm == 0
		}
		return false
	}
	switch op {
	case 0xD8, 0xDC: // arithmetic + FCOM/FCOMP m32/m64
		return true
	case 0xDA: // FIADD/FIMUL/FICOM/FICOMP/FISUB/FISUBR/FIDIV/FIDIVR m32
		return true
	case 0xD9: // FLD/FST/FSTP m32 + FLDCW/FNSTCW m16
		return reg == 0 || reg == 2 || reg == 3 || reg == 5 || reg == 7
	case 0xDB:
		return reg == 0 || reg == 2 || reg == 3
	case 0xDD: // FLD/FST/FSTP m64 + FNSTSW m16
		return reg == 0 || reg == 2 || reg == 3 || reg == 7
	case 0xDF: // FILD/FIST/FISTP m16, FILD/FISTP m64
		return reg == 0 || reg == 2 || reg == 3 || reg == 5 || reg == 7
	}
	return false
}

func (d *decoder) decode0F(p *pfx, startPos uint64) error {
	b, err := d.fetch8()
	if err != nil {
		return err
	}
	size := p.opSize()

	switch b {
	case 0x77:
		if p.op66 {
			d.pos = startPos
			d.insns = append(d.insns, insn{kind: opEnd, nextRIP: startPos})
			return nil
		}
		d.insns = append(d.insns, insn{kind: opMMX, opcode: b})
		return nil

	case 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6E, 0x6F, 0x70,
		0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x7F,
		0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
		0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
		0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF8, 0xF9, 0xFA, 0xFC, 0xFD, 0xFE:
		// MMX only: the 66-prefixed SSE2 forms operate on XMM state the JIT
		// does not model, REX.W changes MOVD width, and REX.R/B would index
		// past the 8 MM registers.
		if p.op66 || p.hasREX {
			d.pos = startPos
			d.insns = append(d.insns, insn{kind: opEnd, nextRIP: startPos})
			return nil
		}
		reg, isReg, rm, base, idx, scale, disp, useRIP, err := d.decodeModRM(p)
		if err != nil {
			return err
		}
		if b == 0x71 || b == 0x72 || b == 0x73 {
			// Shift-by-immediate groups: register target, sub-op in reg.
			if !isReg || reg != 2 && reg != 4 && reg != 6 || b == 0x73 && reg == 4 {
				d.pos = startPos
				d.insns = append(d.insns, insn{kind: opEnd, nextRIP: startPos})
				return nil
			}
		}
		if b == 0xE7 && isReg { // MOVNTQ requires a memory destination
			d.pos = startPos
			d.insns = append(d.insns, insn{kind: opEnd, nextRIP: startPos})
			return nil
		}
		in := insn{kind: opMMX, opcode: b, dst: reg, src: rm,
			memBase: base, memIdx: idx, memScale: scale, memDisp: disp, useRIP: useRIP}
		if isReg {
			in.size = 1
		}
		if b == 0x70 || b == 0x71 || b == 0x72 || b == 0x73 {
			immediate, err := d.fetch8()
			if err != nil {
				return err
			}
			in.imm = int64(immediate)
		}
		d.insns = append(d.insns, in)
		return nil

	// Jcc rel32 (0x0F 0x80-0x8F)
	case 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
		0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F:
		rel, err := d.fetch32()
		if err != nil {
			return err
		}
		target := d.pos + uint64(int64(int32(rel)))
		if d.mode32 {
			target &= 0xFFFFFFFF
		}
		d.insns = append(d.insns, insn{kind: opJcc, cc: condCode(b - 0x80), target: target, nextRIP: d.pos})
		return nil

	// MOVZX r, r/m8 (0x0F 0xB6)
	case 0xB6:
		reg, isReg, rm, base, idx, scale, disp, useRIP, err := d.decodeModRM(p)
		if err != nil {
			return err
		}
		if isReg && usesLegacyHighByte(rm, p) {
			d.pos = startPos
			d.insns = append(d.insns, insn{kind: opEnd, nextRIP: startPos})
			return nil
		}
		if isReg {
			d.insns = append(d.insns, insn{kind: opMovzx, size: p.opSize(), srcSize: 1, dst: reg, src: rm})
		} else {
			d.insns = append(d.insns, insn{kind: opMovzx, size: p.opSize(), srcSize: 1, dst: reg,
				memBase: base, memIdx: idx, memScale: scale, memDisp: disp, useRIP: useRIP, src: -1})
		}
		return nil

	// MOVZX r, r/m16 (0x0F 0xB7)
	case 0xB7:
		if p.opSize() == 2 {
			d.pos = startPos
			d.insns = append(d.insns, insn{kind: opEnd, nextRIP: startPos})
			return nil
		}
		reg, isReg, rm, base, idx, scale, disp, useRIP, err := d.decodeModRM(p)
		if err != nil {
			return err
		}
		if isReg {
			d.insns = append(d.insns, insn{kind: opMovzx, size: p.opSize(), srcSize: 2, dst: reg, src: rm})
		} else {
			d.insns = append(d.insns, insn{kind: opMovzx, size: p.opSize(), srcSize: 2, dst: reg,
				memBase: base, memIdx: idx, memScale: scale, memDisp: disp, useRIP: useRIP, src: -1})
		}
		return nil

	// MOVSX r, r/m8 (0x0F 0xBE)
	case 0xBE:
		reg, isReg, rm, base, idx, scale, disp, useRIP, err := d.decodeModRM(p)
		if err != nil {
			return err
		}
		if isReg && usesLegacyHighByte(rm, p) {
			d.pos = startPos
			d.insns = append(d.insns, insn{kind: opEnd, nextRIP: startPos})
			return nil
		}
		if isReg {
			d.insns = append(d.insns, insn{kind: opMovsx, size: p.opSize(), srcSize: 1, dst: reg, src: rm})
		} else {
			d.insns = append(d.insns, insn{kind: opMovsx, size: p.opSize(), srcSize: 1, dst: reg,
				memBase: base, memIdx: idx, memScale: scale, memDisp: disp, useRIP: useRIP, src: -1})
		}
		return nil

	// MOVSX r, r/m16 (0x0F 0xBF)
	case 0xBF:
		if p.opSize() == 2 {
			d.pos = startPos
			d.insns = append(d.insns, insn{kind: opEnd, nextRIP: startPos})
			return nil
		}
		reg, isReg, rm, base, idx, scale, disp, useRIP, err := d.decodeModRM(p)
		if err != nil {
			return err
		}
		if isReg {
			d.insns = append(d.insns, insn{kind: opMovsx, size: p.opSize(), srcSize: 2, dst: reg, src: rm})
		} else {
			d.insns = append(d.insns, insn{kind: opMovsx, size: p.opSize(), srcSize: 2, dst: reg,
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
		if isReg && usesLegacyHighByte(rm, p) {
			d.pos = startPos
			d.insns = append(d.insns, insn{kind: opEnd, nextRIP: startPos})
			return nil
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
		d.pos = startPos
		d.insns = append(d.insns, insn{kind: opEnd, nextRIP: startPos})
		return nil

	// VMCALL-like (0x0F 0x01 ...)
	case 0x01:
		b2, err := d.fetch8()
		if err != nil {
			return err
		}
		if b2 == 0xC1 {
			d.pos = startPos
			d.insns = append(d.insns, insn{kind: opEnd, nextRIP: startPos})
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
		instret := s.Instret

		for i := 0; i < len(insns); i++ {
			in := &insns[i]
			if in.kind == opEnd {
				*s.RIP = in.nextRIP
				s.Fallback = true
				return nil
			}
			if instret != nil {
				*instret++
			}
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
				*s.RIP = in.rip
				addr := resolveAddr(s, in)
				var v uint64
				var err error
				switch in.size {
				case 1:
					var b byte
					b, err = s.read8(addr)
					v = uint64(b)
				case 2:
					var w uint16
					w, err = s.read16(addr)
					v = uint64(w)
				case 4:
					var d uint32
					d, err = s.read32(addr)
					v = uint64(d)
				case 8:
					v, err = s.read64(addr)
				}
				if err != nil {
					return unretire(instret, err)
				}
				writeReg(regs, in.dst, v, in.size)

			case opMovMemReg:
				*s.RIP = in.rip
				addr := resolveAddr(s, in)
				if err := s.checkWriteRange(addr, in.size); err != nil {
					return unretire(instret, err)
				}
				v := regs[in.src]
				var err error
				switch in.size {
				case 1:
					err = s.write8(addr, byte(v))
				case 2:
					err = s.write16(addr, uint16(v))
				case 4:
					err = s.write32(addr, uint32(v))
				case 8:
					err = s.write64(addr, v)
				}
				if err != nil {
					return unretire(instret, err)
				}

			case opMovMemImm:
				*s.RIP = in.rip
				addr := resolveAddr(s, in)
				if err := s.checkWriteRange(addr, in.size); err != nil {
					return unretire(instret, err)
				}
				v := uint64(in.imm)
				var err error
				switch in.size {
				case 1:
					err = s.write8(addr, byte(v))
				case 2:
					err = s.write16(addr, uint16(v))
				case 4:
					err = s.write32(addr, uint32(v))
				case 8:
					err = s.write64(addr, v)
				}
				if err != nil {
					return unretire(instret, err)
				}

			case opLea:
				addr := resolveAddr(s, in)
				writeReg(regs, in.dst, addr, in.size)

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
				*s.RIP = in.rip
				addr := resolveAddr(s, in)
				a := truncate(regs[in.dst], in.size)
				var bv uint64
				var err error
				switch in.size {
				case 1:
					var bb byte
					bb, err = s.read8(addr)
					bv = uint64(bb)
				case 2:
					var bw uint16
					bw, err = s.read16(addr)
					bv = uint64(bw)
				case 4:
					var bd uint32
					bd, err = s.read32(addr)
					bv = uint64(bd)
				case 8:
					bv, err = s.read64(addr)
				}
				if err != nil {
					return unretire(instret, err)
				}
				r := doALU(s, in.alu, a, bv, in.size)
				if in.alu != aluCMP {
					writeReg(regs, in.dst, r, in.size)
				}

			case opALUMemReg:
				*s.RIP = in.rip
				addr := resolveAddr(s, in)
				var a uint64
				switch in.size {
				case 1:
					bb, err := s.read8(addr)
					if err != nil {
						return unretire(instret, err)
					}
					a = uint64(bb)
				case 2:
					bw, err := s.read16(addr)
					if err != nil {
						return unretire(instret, err)
					}
					a = uint64(bw)
				case 4:
					bd, err := s.read32(addr)
					if err != nil {
						return unretire(instret, err)
					}
					a = uint64(bd)
				case 8:
					var err error
					a, err = s.read64(addr)
					if err != nil {
						return unretire(instret, err)
					}
				}
				b := truncate(regs[in.src], in.size)
				oldFlags := *s.Rflags
				if in.alu != aluCMP {
					if err := s.checkWriteRange(addr, in.size); err != nil {
						return unretire(instret, err)
					}
				}
				r := doALU(s, in.alu, a, b, in.size)
				if in.alu != aluCMP {
					var err error
					switch in.size {
					case 1:
						err = s.write8(addr, byte(r))
					case 2:
						err = s.write16(addr, uint16(r))
					case 4:
						err = s.write32(addr, uint32(r))
					case 8:
						err = s.write64(addr, r)
					}
					if err != nil {
						*s.Rflags = oldFlags
						return unretire(instret, err)
					}
				}

			case opALUMemImm:
				*s.RIP = in.rip
				addr := resolveAddr(s, in)
				var a uint64
				var err error
				switch in.size {
				case 1:
					var bb byte
					bb, err = s.read8(addr)
					a = uint64(bb)
				case 2:
					var bw uint16
					bw, err = s.read16(addr)
					a = uint64(bw)
				case 4:
					var bd uint32
					bd, err = s.read32(addr)
					a = uint64(bd)
				case 8:
					a, err = s.read64(addr)
				}
				if err != nil {
					return unretire(instret, err)
				}
				b := uint64(in.imm)
				oldFlags := *s.Rflags
				if in.alu != aluCMP {
					if err := s.checkWriteRange(addr, in.size); err != nil {
						return unretire(instret, err)
					}
				}
				r := doALU(s, in.alu, a, b, in.size)
				if in.alu != aluCMP {
					var err error
					switch in.size {
					case 1:
						err = s.write8(addr, byte(r))
					case 2:
						err = s.write16(addr, uint16(r))
					case 4:
						err = s.write32(addr, uint32(r))
					case 8:
						err = s.write64(addr, r)
					}
					if err != nil {
						*s.Rflags = oldFlags
						return unretire(instret, err)
					}
				}

			case opTest:
				a := truncate(regs[in.dst], in.size)
				b := truncate(regs[in.src], in.size)
				r := a & b
				setLogicFlags(s, r, in.size)

			case opTestImm:
				a := truncate(regs[in.dst], in.size)
				r := a & truncate(uint64(in.imm), in.size)
				setLogicFlags(s, r, in.size)

			case opPush:
				*s.RIP = in.rip
				sp := regs[4] - uint64(in.size)
				if s.Mode32 {
					sp &= 0xFFFFFFFF
				}
				if err := s.checkWriteRange(sp, in.size); err != nil {
					return unretire(instret, err)
				}
				var err error
				switch in.size {
				case 2:
					err = s.write16(sp, uint16(regs[in.src]))
				case 4:
					err = s.write32(sp, uint32(regs[in.src]))
				case 8:
					err = s.write64(sp, regs[in.src])
				}
				if err != nil {
					return unretire(instret, err)
				}
				regs[4] = sp

			case opPop:
				*s.RIP = in.rip
				sp := regs[4]
				var value uint64
				var err error
				switch in.size {
				case 2:
					var v uint16
					v, err = s.read16(sp)
					value = uint64(v)
				case 4:
					var v uint32
					v, err = s.read32(sp)
					value = uint64(v)
				case 8:
					value, err = s.read64(sp)
				}
				if err != nil {
					return unretire(instret, err)
				}
				nextSP := sp + uint64(in.size)
				if s.Mode32 {
					nextSP &= 0xFFFFFFFF
				}
				regs[4] = nextSP
				writeReg(regs, in.dst, value, in.size)

			case opCall:
				*s.RIP = in.rip
				if s.Mode32 {
					sp := (regs[4] - 4) & 0xFFFFFFFF
					if err := s.checkWriteRange(sp, 4); err != nil {
						return unretire(instret, err)
					}
					if err := s.write32(sp, uint32(in.nextRIP)); err != nil {
						return unretire(instret, err)
					}
					regs[4] = sp
				} else {
					sp := regs[4] - 8
					if err := s.checkWriteRange(sp, 8); err != nil {
						return unretire(instret, err)
					}
					if err := s.write64(sp, in.nextRIP); err != nil {
						return unretire(instret, err)
					}
					regs[4] = sp
				}
				*s.RIP = in.target
				return nil

			case opRet:
				*s.RIP = in.rip
				sp := regs[4]
				var ret uint64
				if s.Mode32 {
					v, err := s.read32(sp)
					if err != nil {
						return unretire(instret, err)
					}
					ret = uint64(v)
					regs[4] = (sp + 4 + uint64(in.imm)) & 0xFFFFFFFF
				} else {
					var err error
					ret, err = s.read64(sp)
					if err != nil {
						return unretire(instret, err)
					}
					regs[4] = sp + 8 + uint64(in.imm)
				}
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
				left := truncate(regs[in.dst], in.size)
				right := truncate(regs[in.src], in.size)
				writeReg(regs, in.dst, right, in.size)
				writeReg(regs, in.src, left, in.size)

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

			case opX87:
				*s.RIP = in.rip
				if err := execX87(s, mem, in); err != nil {
					return unretire(instret, err)
				}

			case opMMX:
				*s.RIP = in.rip
				if err := execMMX(s, in); err != nil {
					return unretire(instret, err)
				}

			case opMovzx:
				var v uint64
				if in.src >= 0 {
					switch in.srcSize {
					case 1:
						v = regs[in.src] & 0xFF
					case 2:
						v = regs[in.src] & 0xFFFF
					}
				} else {
					// Memory source
					*s.RIP = in.rip
					addr := resolveAddr(s, in)
					var err error
					switch in.srcSize {
					case 1:
						var b byte
						b, err = s.read8(addr)
						v = uint64(b)
					case 2:
						var w uint16
						w, err = s.read16(addr)
						v = uint64(w)
					}
					if err != nil {
						return unretire(instret, err)
					}
				}
				writeReg(regs, in.dst, v, in.size)

			case opMovsx:
				var v int64
				if in.src >= 0 {
					switch in.srcSize {
					case 1:
						v = int64(int8(regs[in.src]))
					case 2:
						v = int64(int16(regs[in.src]))
					}
				} else {
					*s.RIP = in.rip
					addr := resolveAddr(s, in)
					var err error
					switch in.srcSize {
					case 1:
						var b byte
						b, err = s.read8(addr)
						v = int64(int8(b))
					case 2:
						var w uint16
						w, err = s.read16(addr)
						v = int64(int16(w))
					}
					if err != nil {
						return unretire(instret, err)
					}
				}
				writeReg(regs, in.dst, uint64(v), in.size)

			case opSetcc:
				if evalCC(s, in.cc) {
					regs[in.dst] = (regs[in.dst] & ^uint64(0xFF)) | 1
				} else {
					regs[in.dst] = regs[in.dst] & ^uint64(0xFF)
				}

			case opCmovcc:
				if in.size == 4 {
					regs[in.dst] &= 0xFFFFFFFF
				}
				if evalCC(s, in.cc) {
					writeReg(regs, in.dst, regs[in.src], in.size)
				}

			case opIMul:
				r, overflow := signedMultiply(regs[in.dst], regs[in.src], in.size)
				writeReg(regs, in.dst, r, in.size)
				setMultiplyFlags(s, overflow)

			case opIMul3:
				r, overflow := signedMultiply(regs[in.src], uint64(in.imm), in.size)
				writeReg(regs, in.dst, r, in.size)
				setMultiplyFlags(s, overflow)

			case opNot:
				writeReg(regs, in.dst, ^truncate(regs[in.dst], in.size), in.size)

			case opNeg:
				value := truncate(regs[in.dst], in.size)
				writeReg(regs, in.dst, doALU(s, aluSUB, 0, value, in.size), in.size)

			case opInc, opDec:
				carry := *s.Rflags & flagCF
				alu := aluADD
				if in.kind == opDec {
					alu = aluSUB
				}
				result := doALU(s, alu, truncate(regs[in.dst], in.size), 1, in.size)
				*s.Rflags = *s.Rflags&^flagCF | carry
				writeReg(regs, in.dst, result, in.size)

			case opDiv, opIDiv:
				*s.RIP = in.rip
				var err error
				if in.kind == opDiv {
					err = divideUnsigned(regs, in.src, in.size)
				} else {
					err = divideSigned(regs, in.src, in.size)
				}
				if err != nil {
					return unretire(instret, fmt.Errorf("%w at RIP=0x%x", err, in.rip))
				}

			case opShift:
				count := uint64(in.imm)
				if in.src == 1 {
					count = regs[1]
				}
				result := shiftRegister(s, truncate(regs[in.dst], in.size), count, in.size, in.shift)
				writeReg(regs, in.dst, result, in.size)

			case opSyscall:
				*s.RIP = in.nextRIP
				s.Trap = true
				return nil

			case opVmcall:
				*s.RIP = in.nextRIP
				s.Trap = true
				return nil

			}
		}
		return nil
	}
}

// =========================================================================
// Helper functions
// =========================================================================

func unretire(instret *uint64, err error) error {
	if instret != nil {
		(*instret)--
	}
	return err
}

func execMMX(s *State, in *insn) error {
	if s.FPUST == nil || s.FPUTop == nil || s.FPUTW == nil {
		return fmt.Errorf("MMX state is unavailable")
	}
	if in.opcode == 0x77 {
		*s.FPUTW = 0xffff
		return nil
	}

	switch in.opcode {
	case 0x6E:
		var value uint64
		if in.size == 1 {
			value = uint64(uint32(s.Regs[in.src]))
		} else {
			v, err := s.read32(resolveAddr(s, in))
			if err != nil {
				return err
			}
			value = uint64(v)
		}
		mmxWrite(s, in.dst, value)
		return nil
	case 0x6F:
		value, err := mmxReadRM(s, in)
		if err != nil {
			return err
		}
		mmxWrite(s, in.dst, value)
		return nil
	case 0x7F, 0xE7:
		value := math.Float64bits(s.FPUST[in.dst])
		if err := mmxWriteRM(s, in, value); err != nil {
			return err
		}
		if in.size != 1 {
			mmxEnter(s)
		}
		return nil
	case 0x71, 0x72, 0x73:
		value := mmxRead(s, in.src)
		bits := uint(16) << (in.opcode - 0x71)
		count := uint(in.imm)
		var result uint64
		switch in.dst {
		case 2: // PSRLW/PSRLD/PSRLQ
			result = mmxMapLanes(value, 0, bits, func(a, _ uint64) uint64 {
				if count >= bits {
					return 0
				}
				return a >> count
			})
		case 4: // PSRAW/PSRAD
			result = mmxMapLanes(value, 0, bits, func(a, _ uint64) uint64 {
				shift := count
				if shift >= bits {
					shift = bits - 1
				}
				return uint64(mmxSigned(a, bits) >> shift)
			})
		case 6: // PSLLW/PSLLD/PSLLQ
			result = mmxMapLanes(value, 0, bits, func(a, _ uint64) uint64 {
				if count >= bits {
					return 0
				}
				return a << count
			})
		}
		mmxWrite(s, in.src, result)
		return nil
	}

	source, err := mmxReadRM(s, in)
	if err != nil {
		return err
	}
	destination := mmxRead(s, in.dst)
	var result uint64
	switch in.opcode {
	case 0x60, 0x61, 0x62, 0x68, 0x69, 0x6A: // PUNPCKL*/PUNPCKH*
		bits := uint(8) << (in.opcode & 3)
		result = mmxUnpack(destination, source, bits, in.opcode >= 0x68)
	case 0x63, 0x67: // PACKSSWB/PACKUSWB
		for i := uint(0); i < 4; i++ {
			for half, value := range []uint64{destination, source} {
				v := mmxSigned(value>>(i*16)&0xffff, 16)
				if in.opcode == 0x63 {
					result |= mmxSaturateSigned(v, 8) << (uint(half)*32 + i*8)
				} else {
					result |= mmxSaturateUnsigned(v, 8) << (uint(half)*32 + i*8)
				}
			}
		}
	case 0x6B: // PACKSSDW
		for i := uint(0); i < 2; i++ {
			result |= mmxSaturateSigned(mmxSigned(destination>>(i*32), 32), 16) << (i * 16)
			result |= mmxSaturateSigned(mmxSigned(source>>(i*32), 32), 16) << ((i + 2) * 16)
		}
	case 0x64, 0x65, 0x66: // PCMPGTB/W/D
		bits := uint(8) << (in.opcode & 3)
		result = mmxMapLanes(destination, source, bits, func(a, b uint64) uint64 {
			if mmxSigned(a, bits) > mmxSigned(b, bits) {
				return uint64(1)<<bits - 1
			}
			return 0
		})
	case 0x70: // PSHUFW
		shuffle := byte(in.imm)
		for i := uint(0); i < 4; i++ {
			result |= source >> (uint(shuffle>>(i*2)&3) * 16) & 0xffff << (i * 16)
		}
	case 0x74, 0x75, 0x76: // PCMPEQB/W/D
		bits := uint(8) << (in.opcode & 3)
		result = mmxMapLanes(destination, source, bits, func(a, b uint64) uint64 {
			if a == b {
				return uint64(1)<<bits - 1
			}
			return 0
		})
	case 0xD1, 0xD2, 0xD3, 0xE1, 0xE2, 0xF1, 0xF2, 0xF3: // shifts by MM/m64 count
		bits := uint(16) << ((in.opcode & 0xf) - 1)
		count := uint(source)
		opcode := in.opcode
		result = mmxMapLanes(destination, 0, bits, func(a, _ uint64) uint64 {
			switch opcode {
			case 0xD1, 0xD2, 0xD3:
				if count >= bits {
					return 0
				}
				return a >> count
			case 0xE1, 0xE2:
				shift := count
				if shift >= bits {
					shift = bits - 1
				}
				return uint64(mmxSigned(a, bits) >> shift)
			default:
				if count >= bits {
					return 0
				}
				return a << count
			}
		})
	case 0xD4: // PADDQ
		result = destination + source
	case 0xD5: // PMULLW
		result = mmxMapLanes(destination, source, 16, func(a, b uint64) uint64 { return a * b })
	case 0xD8, 0xD9, 0xDC, 0xDD: // PSUBUSB/W, PADDUSB/W
		bits := uint(8) << (in.opcode & 1)
		add := in.opcode == 0xDC || in.opcode == 0xDD
		result = mmxMapLanes(destination, source, bits, func(a, b uint64) uint64 {
			if add {
				return mmxSaturateUnsigned(int64(a)+int64(b), bits)
			}
			return mmxSaturateUnsigned(int64(a)-int64(b), bits)
		})
	case 0xDA, 0xDE: // PMINUB/PMAXUB
		opcode := in.opcode
		result = mmxMapLanes(destination, source, 8, func(a, b uint64) uint64 {
			if opcode == 0xDA && b < a || opcode == 0xDE && b > a {
				return b
			}
			return a
		})
	case 0xDB: // PAND
		result = destination & source
	case 0xDF: // PANDN
		result = ^destination & source
	case 0xE0, 0xE3: // PAVGB/PAVGW
		bits := uint(8)
		if in.opcode == 0xE3 {
			bits = 16
		}
		result = mmxMapLanes(destination, source, bits, func(a, b uint64) uint64 { return (a + b + 1) >> 1 })
	case 0xE4: // PMULHUW
		result = mmxMapLanes(destination, source, 16, func(a, b uint64) uint64 { return a * b >> 16 })
	case 0xE5: // PMULHW
		result = mmxMapLanes(destination, source, 16, func(a, b uint64) uint64 {
			return uint64(mmxSigned(a, 16)*mmxSigned(b, 16)) >> 16
		})
	case 0xE8, 0xE9, 0xEC, 0xED: // PSUBSB/W, PADDSB/W
		bits := uint(8)
		if in.opcode == 0xE9 || in.opcode == 0xED {
			bits = 16
		}
		add := in.opcode == 0xEC || in.opcode == 0xED
		result = mmxMapLanes(destination, source, bits, func(a, b uint64) uint64 {
			v := mmxSigned(a, bits) - mmxSigned(b, bits)
			if add {
				v = mmxSigned(a, bits) + mmxSigned(b, bits)
			}
			return mmxSaturateSigned(v, bits)
		})
	case 0xEA, 0xEE: // PMINSW/PMAXSW
		opcode := in.opcode
		result = mmxMapLanes(destination, source, 16, func(a, b uint64) uint64 {
			if opcode == 0xEA && mmxSigned(b, 16) < mmxSigned(a, 16) ||
				opcode == 0xEE && mmxSigned(b, 16) > mmxSigned(a, 16) {
				return b
			}
			return a
		})
	case 0xEB: // POR
		result = destination | source
	case 0xEF: // PXOR
		result = destination ^ source
	case 0xF4: // PMULUDQ
		result = uint64(uint32(destination)) * uint64(uint32(source))
	case 0xF5: // PMADDWD
		for i := uint(0); i < 2; i++ {
			a := mmxSigned(destination>>(i*32), 16)*mmxSigned(source>>(i*32), 16) +
				mmxSigned(destination>>(i*32+16), 16)*mmxSigned(source>>(i*32+16), 16)
			result |= uint64(uint32(a)) << (i * 32)
		}
	case 0xF6: // PSADBW
		for i := uint(0); i < 8; i++ {
			a, b := int64(byte(destination>>uint(i*8))), int64(byte(source>>uint(i*8)))
			if a > b {
				result += uint64(a - b)
			} else {
				result += uint64(b - a)
			}
		}
	case 0xF8, 0xF9, 0xFA, 0xFC, 0xFD, 0xFE: // PSUBB/W/D, PADDB/W/D
		bits := uint(8) << (in.opcode & 3)
		add := in.opcode >= 0xFC
		result = mmxMapLanes(destination, source, bits, func(a, b uint64) uint64 {
			if add {
				return a + b
			}
			return a - b
		})
	default:
		return fmt.Errorf("unsupported MMX opcode 0F %02X", in.opcode)
	}
	mmxWrite(s, in.dst, result)
	return nil
}

func mmxRead(s *State, index int) uint64 {
	mmxEnter(s)
	return math.Float64bits(s.FPUST[index])
}

func mmxEnter(s *State) {
	*s.FPUTop = 0
	*s.FPUTW = 0
}

func mmxWrite(s *State, index int, value uint64) {
	mmxEnter(s)
	s.FPUST[index] = math.Float64frombits(value)
}

func mmxReadRM(s *State, in *insn) (uint64, error) {
	if in.size == 1 {
		return mmxRead(s, in.src), nil
	}
	return s.read64(resolveAddr(s, in))
}

func mmxWriteRM(s *State, in *insn, value uint64) error {
	if in.size == 1 {
		mmxWrite(s, in.src, value)
		return nil
	}
	return s.write64(resolveAddr(s, in), value)
}

func mmxUnpack(dst, src uint64, bits uint, high bool) uint64 {
	if high {
		dst >>= 32
		src >>= 32
	}
	switch bits {
	case 8:
		return mmxSpreadBytes(uint32(dst)) | mmxSpreadBytes(uint32(src))<<8
	case 16:
		return mmxSpreadWords(uint32(dst)) | mmxSpreadWords(uint32(src))<<16
	default:
		return uint64(uint32(dst)) | uint64(uint32(src))<<32
	}
}

func mmxSpreadBytes(value uint32) uint64 {
	v := uint64(value)
	v = (v | v<<16) & 0x0000ffff0000ffff
	return (v | v<<8) & 0x00ff00ff00ff00ff
}

func mmxSpreadWords(value uint32) uint64 {
	v := uint64(value)
	return (v | v<<16) & 0x0000ffff0000ffff
}

func mmxMapLanes(dst, src uint64, bits uint, fn func(uint64, uint64) uint64) uint64 {
	var result uint64
	mask := uint64(1)<<bits - 1
	for shift := uint(0); shift < 64; shift += bits {
		result |= fn(dst>>shift&mask, src>>shift&mask) & mask << shift
	}
	return result
}

func mmxSigned(v uint64, bits uint) int64 {
	shift := 64 - bits
	return int64(v<<shift) >> shift
}

func mmxSaturateSigned(v int64, bits uint) uint64 {
	min, max := -(int64(1) << (bits - 1)), int64(1)<<(bits-1)-1
	if v < min {
		v = min
	} else if v > max {
		v = max
	}
	return uint64(v) & (uint64(1)<<bits - 1)
}

func mmxSaturateUnsigned(v int64, bits uint) uint64 {
	max := int64(1)<<bits - 1
	if v < 0 {
		return 0
	}
	if v > max {
		return uint64(max)
	}
	return uint64(v)
}

const (
	x87JITExcInvalid   uint16 = 1 << 0
	x87JITExcDenormal  uint16 = 1 << 1
	x87JITExcZero      uint16 = 1 << 2
	x87JITExcOverflow  uint16 = 1 << 3
	x87JITExcUnderflow uint16 = 1 << 4
	x87JITExcPrecision uint16 = 1 << 5
	x87JITStackFault   uint16 = 1 << 6
)

func x87JITSignal(s *State, mask uint16, c1 bool) bool {
	*s.FPUSW |= mask
	exceptions := mask & 0x3f
	unmasked := exceptions != 0 && *s.FPUCW&exceptions != exceptions
	if *s.FPUSW&0x3f&^*s.FPUCW != 0 {
		*s.FPUSW |= 0x80
	} else {
		*s.FPUSW &^= 0x80
	}
	if c1 {
		*s.FPUSW |= 0x0200
	} else {
		*s.FPUSW &^= 0x0200
	}
	if unmasked {
		s.x87Unmasked = true
	}
	return unmasked
}

func x87JITTag(s *State, phys int) uint16 {
	return (*s.FPUTW >> uint(phys*2)) & 3
}

func x87JITSetTag(s *State, phys int, tag uint16) {
	shift := uint(phys * 2)
	*s.FPUTW = (*s.FPUTW &^ (3 << shift)) | (tag&3)<<shift
}

func x87JITEmpty(s *State, logical int) bool {
	return x87JITTag(s, (*s.FPUTop+logical)&7) == 3
}

func x87JITValueTag(value float64) uint16 {
	if value == 0 {
		return 1
	}
	if math.IsNaN(value) || math.IsInf(value, 0) || math.Abs(value) < math.Float64frombits(1<<52) {
		return 2
	}
	return 0
}

func x87JITRead(s *State, logical int) float64 {
	phys := (*s.FPUTop + logical) & 7
	if x87JITTag(s, phys) == 3 {
		x87JITSignal(s, x87JITExcInvalid|x87JITStackFault, false)
		return math.NaN()
	}
	return s.FPUST[phys]
}

func x87JITSet(s *State, logical int, value float64) {
	phys := (*s.FPUTop + logical) & 7
	s.FPUST[phys] = value
	x87JITSetTag(s, phys, x87JITValueTag(value))
}

func x87JITRoundFloat32(value float64, cw uint16) float64 {
	nearest := float32(value)
	rounded := float64(nearest)
	if rounded == value || math.IsNaN(value) {
		return rounded
	}
	switch (cw >> 10) & 3 {
	case 1:
		if rounded > value {
			nearest = math.Nextafter32(nearest, float32(math.Inf(-1)))
		}
	case 2:
		if rounded < value {
			nearest = math.Nextafter32(nearest, float32(math.Inf(1)))
		}
	case 3:
		if value > 0 && rounded > value || value < 0 && rounded < value {
			target := float32(math.Inf(-1))
			if value < 0 {
				target = float32(math.Inf(1))
			}
			nearest = math.Nextafter32(nearest, target)
		}
	}
	return float64(nearest)
}

func x87JITRoundPrecision(value float64, cw uint16) float64 {
	if (cw>>8)&3 == 0 {
		return x87JITRoundFloat32(value, cw)
	}
	return value
}

func x87JITSetResult(s *State, logical int, value float64) {
	rounded := x87JITRoundPrecision(value, *s.FPUCW)
	if rounded != value && !math.IsNaN(value) {
		x87JITSignal(s, x87JITExcPrecision, false)
		if rounded == 0 {
			x87JITSignal(s, x87JITExcUnderflow, false)
		}
		if math.IsInf(rounded, 0) && !math.IsInf(value, 0) {
			x87JITSignal(s, x87JITExcOverflow, false)
		}
	}
	x87JITSet(s, logical, rounded)
}

func x87JITPush(s *State, value float64) {
	next := (*s.FPUTop - 1) & 7
	if x87JITTag(s, next) != 3 {
		x87JITSignal(s, x87JITExcInvalid|x87JITStackFault, true)
		if s.x87Unmasked {
			return
		}
		value = math.NaN()
	}
	*s.FPUTop = next
	s.FPUST[next] = value
	x87JITSetTag(s, next, x87JITValueTag(value))
}

func x87JITPop(s *State) float64 {
	if x87JITEmpty(s, 0) {
		x87JITSignal(s, x87JITExcInvalid|x87JITStackFault, false)
		if s.x87Unmasked {
			return math.NaN()
		}
		*s.FPUTop = (*s.FPUTop + 1) & 7
		return math.NaN()
	}
	value := s.FPUST[*s.FPUTop]
	x87JITSetTag(s, *s.FPUTop, 3)
	*s.FPUTop = (*s.FPUTop + 1) & 7
	return value
}

func x87JITSwap(s *State, logical int) {
	p0, pi := *s.FPUTop, (*s.FPUTop+logical)&7
	if x87JITTag(s, p0) == 3 || x87JITTag(s, pi) == 3 {
		x87JITSignal(s, x87JITExcInvalid|x87JITStackFault, false)
	}
	*s.FPUSW &^= 0x0200
	s.FPUST[p0], s.FPUST[pi] = s.FPUST[pi], s.FPUST[p0]
	t0, ti := x87JITTag(s, p0), x87JITTag(s, pi)
	x87JITSetTag(s, p0, ti)
	x87JITSetTag(s, pi, t0)
}

func x87JITSetCC(s *State, cmp int) {
	*s.FPUSW &^= 0x4700
	switch cmp {
	case -1:
		*s.FPUSW |= 0x0100
	case 0:
		*s.FPUSW |= 0x4000
	case 2:
		*s.FPUSW |= 0x4500
	}
}

func x87JITSignalingNaN(value float64) bool {
	return math.IsNaN(value) && math.Float64bits(value)&(1<<51) == 0
}

func x87JITCompareValues(s *State, a, b float64, quiet bool) int {
	if math.IsNaN(a) || math.IsNaN(b) {
		if !quiet || x87JITSignalingNaN(a) || x87JITSignalingNaN(b) {
			x87JITSignal(s, x87JITExcInvalid, false)
		}
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

func x87JITArithmetic(s *State, a, b float64, op int) float64 {
	if math.IsNaN(a) || math.IsNaN(b) {
		if x87JITSignalingNaN(a) || x87JITSignalingNaN(b) {
			x87JITSignal(s, x87JITExcInvalid, false)
		}
	}
	var result float64
	switch op {
	case 0:
		if math.IsInf(a, 0) && math.IsInf(b, 0) && math.Signbit(a) != math.Signbit(b) {
			x87JITSignal(s, x87JITExcInvalid, false)
		}
		result = a + b
		if result == 0 && a != 0 && b != 0 && a != -b {
			x87JITSignal(s, x87JITExcUnderflow, false)
		}
		if result == 0 && !math.IsInf(a, 0) && !math.IsInf(b, 0) && (*s.FPUCW>>10)&3 == 1 {
			return math.Copysign(0, -1)
		}
	case 1:
		if a == 0 && math.IsInf(b, 0) || b == 0 && math.IsInf(a, 0) {
			x87JITSignal(s, x87JITExcInvalid, false)
		}
		result = a * b
	case 4:
		if math.IsInf(a, 0) && math.IsInf(b, 0) && math.Signbit(a) == math.Signbit(b) {
			x87JITSignal(s, x87JITExcInvalid, false)
		}
		result = a - b
		if result == 0 && a != 0 && b != 0 && a != b {
			x87JITSignal(s, x87JITExcUnderflow, false)
		}
		if result == 0 && !math.IsInf(a, 0) && !math.IsInf(b, 0) && (*s.FPUCW>>10)&3 == 1 {
			return math.Copysign(0, -1)
		}
	case 5:
		return x87JITArithmetic(s, b, a, 4)
	case 6:
		if b == 0 {
			if a == 0 {
				x87JITSignal(s, x87JITExcInvalid, false)
			} else if !math.IsInf(a, 0) {
				x87JITSignal(s, x87JITExcZero, false)
			}
		}
		if math.IsInf(a, 0) && math.IsInf(b, 0) {
			x87JITSignal(s, x87JITExcInvalid, false)
		}
		result = a / b
	case 7:
		return x87JITArithmetic(s, b, a, 6)
	default:
		return math.NaN()
	}
	if math.IsInf(result, 0) && !math.IsInf(a, 0) && !math.IsInf(b, 0) {
		x87JITSignal(s, x87JITExcOverflow, false)
	}
	if result == 0 && a != 0 && b != 0 && !math.IsInf(a, 0) && !math.IsInf(b, 0) && op == 6 {
		x87JITSignal(s, x87JITExcUnderflow, false)
	}
	return result
}

func x87JITPrem(s *State, st0, st1 float64, nearest bool) {
	if math.IsNaN(st0) || math.IsNaN(st1) {
		if x87JITSignalingNaN(st0) || x87JITSignalingNaN(st1) {
			x87JITSignal(s, x87JITExcInvalid, false)
		}
		x87JITSet(s, 0, math.NaN())
		return
	}
	if math.IsInf(st0, 0) || st1 == 0 {
		x87JITSignal(s, x87JITExcInvalid, false)
		return
	}
	if math.IsInf(st1, 0) {
		*s.FPUSW &^= 0x4700
		return
	}
	m0, e0 := math.Frexp(st0)
	m1, e1 := math.Frexp(st1)
	if e0-e1 >= 64 {
		scale := e0 - e1 - 63
		quotient := math.Trunc(math.Ldexp(m0/m1, 63))
		*s.FPUSW |= 0x0400
		x87JITSet(s, 0, st0-math.Ldexp(st1, scale)*quotient)
		return
	}
	quotient := math.Trunc(st0 / st1)
	if nearest {
		quotient = math.RoundToEven(st0 / st1)
	}
	*s.FPUSW &^= 0x0400
	x87JITSet(s, 0, st0-quotient*st1)
	*s.FPUSW &^= 0x4700
	var bitsValue uint64
	if math.Abs(quotient) < math.Ldexp(1, 63) {
		bitsValue = uint64(int64(quotient)) & 7
	} else {
		r := math.Mod(quotient, 8)
		if r < 0 {
			r += 8
		}
		bitsValue = uint64(r)
	}
	if bitsValue&4 != 0 {
		*s.FPUSW |= 0x0100
	}
	if bitsValue&1 != 0 {
		*s.FPUSW |= 0x0200
	}
	if bitsValue&2 != 0 {
		*s.FPUSW |= 0x4000
	}
}

func x87JITConvertInt(s *State, value float64, bits int, trunc bool) int64 {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		x87JITSignal(s, x87JITExcInvalid, false)
		if bits == 16 {
			return -1 << 15
		}
		if bits == 32 {
			return -1 << 31
		}
		return -1 << 63
	}
	if trunc {
		value = math.Trunc(value)
	} else {
		value = x87Round(value, s.FPUCW)
	}
	min := -math.Ldexp(1, bits-1)
	max := math.Ldexp(1, bits-1) - 1
	invalid := value < min || value > max
	if bits == 64 {
		invalid = value < -math.Ldexp(1, 63) || value >= math.Ldexp(1, 63)
	}
	if invalid {
		x87JITSignal(s, x87JITExcInvalid, false)
		if bits == 16 {
			return -1 << 15
		}
		if bits == 32 {
			return -1 << 31
		}
		return -1 << 63
	}
	return int64(value)
}

func execX87(s *State, mem *mmu.MMU, in *insn) error {
	if s.FPUST == nil || s.FPUTop == nil || s.FPUCW == nil || s.FPUSW == nil || s.FPUTW == nil {
		return fmt.Errorf("x87 state is unavailable")
	}
	stBefore := *s.FPUST
	topBefore := *s.FPUTop
	cwBefore := *s.FPUCW
	swBefore := *s.FPUSW
	twBefore := *s.FPUTW
	flagsBefore := uint64(0)
	if s.Rflags != nil {
		flagsBefore = *s.Rflags
	}
	restore := func(preserveExceptions bool) {
		exceptionBits := *s.FPUSW & 0x02FF
		*s.FPUST = stBefore
		*s.FPUTop = topBefore
		*s.FPUCW = cwBefore
		*s.FPUSW = swBefore
		*s.FPUTW = twBefore
		if preserveExceptions {
			*s.FPUSW = (swBefore &^ 0x02FF) | exceptionBits | 0x80
		}
		if s.Rflags != nil {
			*s.Rflags = flagsBefore
		}
	}
	s.x87Unmasked = false
	err := execX87Core(s, mem, in)
	if err != nil {
		restore(s.x87Unmasked)
		return err
	}
	if s.x87Unmasked {
		restore(true)
		return fmt.Errorf("unmasked x87 exception")
	}
	return nil
}

func execX87Core(s *State, mem *mmu.MMU, in *insn) error {
	if s.FPUST == nil || s.FPUTop == nil || s.FPUTW == nil {
		return fmt.Errorf("x87 state is unavailable")
	}
	top := s.FPUTop
	phys := func(i int) int { return (*top + i) & 7 }
	push := func(value float64) {
		x87JITPush(s, value)
	}
	pop := func() {
		x87JITPop(s)
	}
	setCC := func(cmp int) error {
		x87JITSetCC(s, cmp)
		return nil
	}
	op := byte(in.imm)
	reg := in.dst
	if in.size == 1 {
		i := in.src
		switch op {
		case 0xD8:
			switch reg {
			case 0:
				x87JITSetResult(s, 0, x87JITArithmetic(s, x87JITRead(s, 0), x87JITRead(s, i), 0))
			case 1:
				x87JITSetResult(s, 0, x87JITArithmetic(s, x87JITRead(s, 0), x87JITRead(s, i), 1))
			case 2:
				return setCC(x87JITCompareValues(s, x87JITRead(s, 0), x87JITRead(s, i), false))
			case 3:
				if err := setCC(x87JITCompareValues(s, x87JITRead(s, 0), x87JITRead(s, i), false)); err != nil {
					return err
				}
				pop()
			case 4:
				x87JITSetResult(s, 0, x87JITArithmetic(s, x87JITRead(s, 0), x87JITRead(s, i), 4))
			case 5:
				x87JITSetResult(s, 0, x87JITArithmetic(s, x87JITRead(s, 0), x87JITRead(s, i), 5))
			case 6:
				x87JITSetResult(s, 0, x87JITArithmetic(s, x87JITRead(s, 0), x87JITRead(s, i), 6))
			case 7:
				x87JITSetResult(s, 0, x87JITArithmetic(s, x87JITRead(s, 0), x87JITRead(s, i), 7))
			}
			return nil
		case 0xD9:
			switch {
			case reg == 0: // FLD ST(i)
				value := x87JITRead(s, i)
				push(value)
			case reg == 1: // FXCH ST(i)
				if i == 0 {
					if x87JITEmpty(s, 0) {
						x87JITSignal(s, x87JITExcInvalid|x87JITStackFault, false)
					} else {
						*s.FPUSW &^= 0x0200
					}
				} else {
					x87JITSwap(s, i)
				}
			case reg == 4 && i == 0: // FCHS
				x87JITSet(s, 0, -x87JITRead(s, 0))
			case reg == 4 && i == 1: // FABS
				x87JITSet(s, 0, math.Abs(x87JITRead(s, 0)))
			case reg == 4 && i == 4: // FTST
				return setCC(x87JITCompareValues(s, x87JITRead(s, 0), 0, false))
			case reg == 4 && i == 5: // FXAM
				if s.FPUSW == nil {
					return fmt.Errorf("x87 status word is unavailable")
				}
				value := x87JITRead(s, 0)
				*s.FPUSW &^= 0x4700
				if math.IsNaN(value) {
					*s.FPUSW |= 0x0100
				} else if math.IsInf(value, 0) {
					*s.FPUSW |= 0x0500
				} else if value == 0 {
					*s.FPUSW |= 0x4000
				} else {
					*s.FPUSW |= 0x0400
				}
				if math.Signbit(value) {
					*s.FPUSW |= 0x0200
				}
			case reg == 5 && i == 0: // FLD1
				push(1.0)
			case reg == 5 && i == 1: // FLDL2T
				push(math.Log2(10))
			case reg == 5 && i == 2: // FLDL2E
				push(math.Log2E)
			case reg == 5 && i == 3: // FLDPI
				push(math.Pi)
			case reg == 5 && i == 4: // FLDLN2
				push(math.Ln2)
			case reg == 5 && i == 5: // FLDLG2
				push(math.Log10(2))
			case reg == 5 && i == 6: // FLDZ
				push(0)
			case reg == 6 && i == 0: // F2XM1
				x := x87JITRead(s, 0)
				if math.IsNaN(x) {
					x87JITSignal(s, x87JITExcInvalid, false)
				} else if x < -1 || x > 1 {
					*s.FPUSW |= 0x0400
				} else {
					*s.FPUSW &^= 0x0400
					x87JITSet(s, 0, math.Exp2(x)-1)
				}
			case reg == 6 && i == 1: // FYL2X
				y, x := x87JITRead(s, 1), x87JITRead(s, 0)
				if x < 0 {
					x87JITSignal(s, x87JITExcInvalid, false)
				}
				if x87JITSignalingNaN(x) || x87JITSignalingNaN(y) {
					x87JITSignal(s, x87JITExcInvalid, false)
				}
				if x == 0 {
					x87JITSignal(s, x87JITExcZero, false)
				}
				pop()
				x87JITSet(s, 0, y*math.Log2(x))
			case reg == 6 && i == 2: // FPTAN
				x := x87JITRead(s, 0)
				if math.IsNaN(x) {
					if x87JITSignalingNaN(x) {
						x87JITSignal(s, x87JITExcInvalid, false)
					}
					*s.FPUSW &^= 0x0400
					x87JITSet(s, 0, x)
				} else if math.IsInf(x, 0) {
					x87JITSignal(s, x87JITExcInvalid, false)
				} else if math.Abs(x) < math.Ldexp(1, 63) {
					*s.FPUSW &^= 0x0400
					x87JITSet(s, 0, math.Tan(x))
					push(1.0)
				} else {
					*s.FPUSW |= 0x0400
				}
			case reg == 6 && i == 3: // FPATAN
				y, x := x87JITRead(s, 1), x87JITRead(s, 0)
				pop()
				x87JITSet(s, 0, math.Atan2(y, x))
			case reg == 6 && i == 4: // FXTRACT
				x := x87JITRead(s, 0)
				*s.FPUSW &^= 0x0200
				switch {
				case x == 0:
					x87JITSignal(s, x87JITExcZero, false)
					x87JITSet(s, 0, math.Inf(-1))
					push(math.Copysign(0, x))
				case math.IsNaN(x):
					if x87JITSignalingNaN(x) {
						x87JITSignal(s, x87JITExcInvalid, false)
						x = math.Float64frombits(math.Float64bits(x) | 1<<51)
					}
					x87JITSet(s, 0, x)
					push(x)
				case math.IsInf(x, 0):
					x87JITSet(s, 0, math.Inf(1))
					push(x)
				default:
					frac, exp := math.Frexp(x)
					x87JITSet(s, 0, float64(exp-1))
					push(frac * 2)
				}
			case reg == 6 && i == 5: // FPREM1
				x87JITPrem(s, x87JITRead(s, 0), x87JITRead(s, 1), true)
			case reg == 6 && i == 6: // FDECSTP
				*top = (*top - 1) & 7
				*s.FPUSW &^= 0x0200
			case reg == 6 && i == 7: // FINCSTP
				*top = (*top + 1) & 7
				*s.FPUSW &^= 0x0200
			case reg == 7 && i == 0: // FPREM
				x87JITPrem(s, x87JITRead(s, 0), x87JITRead(s, 1), false)
			case reg == 7 && i == 1: // FYL2XP1
				y, x := x87JITRead(s, 1), x87JITRead(s, 0)
				if x87JITSignalingNaN(x) || x87JITSignalingNaN(y) {
					x87JITSignal(s, x87JITExcInvalid, false)
				} else if x <= -1 {
					if x == -1 {
						x87JITSignal(s, x87JITExcZero, false)
					} else {
						x87JITSignal(s, x87JITExcInvalid, false)
					}
				}
				pop()
				x87JITSet(s, 0, y*math.Log2(x+1))
			case reg == 7 && i == 2: // FSQRT
				x := x87JITRead(s, 0)
				if x < 0 || x87JITSignalingNaN(x) {
					x87JITSignal(s, x87JITExcInvalid, false)
				}
				x87JITSetResult(s, 0, math.Sqrt(x))
			case reg == 7 && i == 3: // FSINCOS
				x := x87JITRead(s, 0)
				if math.IsNaN(x) {
					if x87JITSignalingNaN(x) {
						x87JITSignal(s, x87JITExcInvalid, false)
					}
					*s.FPUSW &^= 0x0400
					x87JITSet(s, 0, x)
				} else if math.IsInf(x, 0) {
					x87JITSignal(s, x87JITExcInvalid, false)
				} else if math.Abs(x) < math.Ldexp(1, 63) {
					*s.FPUSW &^= 0x0400
					sinValue, cosValue := math.Sincos(x)
					x87JITSet(s, 0, sinValue)
					push(cosValue)
				} else {
					*s.FPUSW |= 0x0400
				}
			case reg == 7 && i == 4: // FRNDINT
				x87JITSet(s, 0, x87Round(x87JITRead(s, 0), s.FPUCW))
			case reg == 7 && i == 5: // FSCALE
				x87JITSet(s, 0, math.Ldexp(x87JITRead(s, 0), int(x87JITRead(s, 1))))
			case reg == 7 && i == 6: // FSIN
				x := x87JITRead(s, 0)
				if math.IsNaN(x) {
					if x87JITSignalingNaN(x) {
						x87JITSignal(s, x87JITExcInvalid, false)
					}
					*s.FPUSW &^= 0x0400
					x87JITSet(s, 0, x)
				} else if math.IsInf(x, 0) {
					x87JITSignal(s, x87JITExcInvalid, false)
				} else if math.Abs(x) < math.Ldexp(1, 63) {
					*s.FPUSW &^= 0x0400
					x87JITSet(s, 0, math.Sin(x))
				} else {
					*s.FPUSW |= 0x0400
				}
			case reg == 7 && i == 7: // FCOS
				x := x87JITRead(s, 0)
				if math.IsNaN(x) {
					if x87JITSignalingNaN(x) {
						x87JITSignal(s, x87JITExcInvalid, false)
					}
					*s.FPUSW &^= 0x0400
					x87JITSet(s, 0, x)
				} else if math.IsInf(x, 0) {
					x87JITSignal(s, x87JITExcInvalid, false)
				} else if math.Abs(x) < math.Ldexp(1, 63) {
					*s.FPUSW &^= 0x0400
					x87JITSet(s, 0, math.Cos(x))
				} else {
					*s.FPUSW |= 0x0400
				}
			default:
				return fmt.Errorf("unsupported x87 register form %02x /%d", op, reg)
			}
			return nil
		case 0xDC:
			left, right := x87JITRead(s, i), x87JITRead(s, 0)
			switch reg {
			case 0:
				x87JITSetResult(s, i, x87JITArithmetic(s, left, right, 0))
			case 1:
				x87JITSetResult(s, i, x87JITArithmetic(s, left, right, 1))
			case 4:
				x87JITSetResult(s, i, x87JITArithmetic(s, right, left, 4))
			case 5:
				x87JITSetResult(s, i, x87JITArithmetic(s, left, right, 4))
			case 6:
				x87JITSetResult(s, i, x87JITArithmetic(s, right, left, 6))
			case 7:
				x87JITSetResult(s, i, x87JITArithmetic(s, left, right, 6))
			default:
				return fmt.Errorf("unsupported x87 register form %02x /%d", op, reg)
			}
			return nil
		case 0xDD:
			switch reg {
			case 0: // FFREE ST(i)
				x87JITSetTag(s, phys(i), 3)
			case 2: // FST ST(i)
				x87JITSet(s, i, x87JITRead(s, 0))
			case 3: // FSTP ST(i)
				x87JITSet(s, i, x87JITRead(s, 0))
				pop()
			case 4: // FUCOM ST(i)
				return setCC(x87JITCompareValues(s, x87JITRead(s, 0), x87JITRead(s, i), true))
			case 5: // FUCOMP ST(i)
				if err := setCC(x87JITCompareValues(s, x87JITRead(s, 0), x87JITRead(s, i), true)); err != nil {
					return err
				}
				pop()
			default:
				return fmt.Errorf("unsupported x87 register form %02x /%d", op, reg)
			}
			return nil
		case 0xDE:
			if reg == 3 && i == 1 { // FCOMPP
				if err := setCC(x87JITCompareValues(s, x87JITRead(s, 0), x87JITRead(s, 1), false)); err != nil {
					return err
				}
				pop()
				pop()
				return nil
			}
			left, right := x87JITRead(s, i), x87JITRead(s, 0)
			switch reg {
			case 0:
				x87JITSetResult(s, i, x87JITArithmetic(s, left, right, 0))
			case 1:
				x87JITSetResult(s, i, x87JITArithmetic(s, left, right, 1))
			case 4:
				x87JITSetResult(s, i, x87JITArithmetic(s, right, left, 4))
			case 5:
				x87JITSetResult(s, i, x87JITArithmetic(s, left, right, 4))
			case 6:
				x87JITSetResult(s, i, x87JITArithmetic(s, right, left, 6))
			case 7:
				x87JITSetResult(s, i, x87JITArithmetic(s, left, right, 6))
			default:
				return fmt.Errorf("unsupported x87 register form %02x /%d", op, reg)
			}
			pop()
			return nil
		case 0xDF:
			if reg == 4 && i == 0 { // FNSTSW AX
				if s.FPUSW == nil || s.Regs == nil {
					return fmt.Errorf("x87 status word is unavailable")
				}
				sw := *s.FPUSW | uint16(*top)<<11
				s.Regs[0] = s.Regs[0]&^0xFFFF | uint64(sw)
				return nil
			}
		}
		return fmt.Errorf("unsupported x87 register form %02x /%d", op, reg)
	}

	addr := resolveAddr(s, in)
	switch op {
	case 0xD8:
		bits, err := s.read32(addr)
		if err != nil {
			return err
		}
		value := float64(math.Float32frombits(bits))
		if reg == 2 || reg == 3 { // FCOM/FCOMP m32
			if err := setCC(x87JITCompareValues(s, x87JITRead(s, 0), value, false)); err != nil {
				return err
			}
			if reg == 3 {
				pop()
			}
			return nil
		}
		x87JITSetResult(s, 0, x87JITArithmetic(s, x87JITRead(s, 0), value, reg))
		return nil
	case 0xD9:
		switch reg {
		case 0:
			bits, err := s.read32(addr)
			if err != nil {
				return err
			}
			push(float64(math.Float32frombits(bits)))
			return nil
		case 2, 3:
			value := x87JITRead(s, 0)
			rounded := x87JITRoundFloat32(value, *s.FPUCW)
			if rounded != value && !math.IsNaN(value) {
				x87JITSignal(s, x87JITExcPrecision, false)
				if rounded == 0 {
					x87JITSignal(s, x87JITExcUnderflow, false)
				}
				if math.IsInf(rounded, 0) && !math.IsInf(value, 0) {
					x87JITSignal(s, x87JITExcOverflow, false)
				}
			}
			if s.x87Unmasked {
				return fmt.Errorf("unmasked x87 store precision exception")
			}
			if err := s.write32(addr, math.Float32bits(float32(rounded))); err != nil {
				return err
			}
			if reg == 3 {
				pop()
			}
			return nil
		case 5: // FLDCW m16
			bits, err := s.read16(addr)
			if err != nil {
				return err
			}
			*s.FPUCW = (bits & 0x0F3F) | 0x0040
			if *s.FPUSW&0x3F&^*s.FPUCW != 0 {
				*s.FPUSW |= 0x80
			} else {
				*s.FPUSW &^= 0x80
			}
			return nil
		case 7: // FNSTCW m16
			if s.FPUCW == nil {
				return fmt.Errorf("x87 control word is unavailable")
			}
			return s.write16(addr, *s.FPUCW)
		}
	case 0xDA: // int32 arithmetic (m32)
		bits, err := s.read32(addr)
		if err != nil {
			return err
		}
		value := float64(int32(bits))
		if reg == 2 || reg == 3 { // FICOM/FICOMP m32
			if err := setCC(x87JITCompareValues(s, x87JITRead(s, 0), value, false)); err != nil {
				return err
			}
			if reg == 3 {
				pop()
			}
			return nil
		}
		x87JITSetResult(s, 0, x87JITArithmetic(s, x87JITRead(s, 0), value, reg))
		return nil
	case 0xDB:
		switch reg {
		case 0:
			value, err := s.read32(addr)
			if err != nil {
				return err
			}
			push(float64(int32(value)))
			return nil
		case 2, 3:
			value := x87JITConvertInt(s, x87JITRead(s, 0), 32, false)
			if s.x87Unmasked {
				return fmt.Errorf("unmasked x87 integer conversion exception")
			}
			if err := s.write32(addr, uint32(value)); err != nil {
				return err
			}
			if reg == 3 {
				pop()
			}
			return nil
		}
	case 0xDC:
		bits, err := s.read64(addr)
		if err != nil {
			return err
		}
		value := math.Float64frombits(bits)
		if reg == 2 || reg == 3 { // FCOM/FCOMP m64
			if err := setCC(x87JITCompareValues(s, x87JITRead(s, 0), value, false)); err != nil {
				return err
			}
			if reg == 3 {
				pop()
			}
			return nil
		}
		x87JITSetResult(s, 0, x87JITArithmetic(s, x87JITRead(s, 0), value, reg))
		return nil
	case 0xDD:
		switch reg {
		case 0: // FLD m64
			bits, err := s.read64(addr)
			if err != nil {
				return err
			}
			push(math.Float64frombits(bits))
			return nil
		case 2, 3: // FST/FSTP m64
			if err := s.write64(addr, math.Float64bits(x87JITRead(s, 0))); err != nil {
				return err
			}
			if reg == 3 {
				pop()
			}
			return nil
		case 7: // FNSTSW m16
			if s.FPUSW == nil {
				return fmt.Errorf("x87 status word is unavailable")
			}
			sw := *s.FPUSW | uint16(*top)<<11
			return s.write16(addr, sw)
		}
	case 0xDF:
		switch reg {
		case 0: // FILD m16
			value, err := s.read16(addr)
			if err != nil {
				return err
			}
			push(float64(int16(value)))
			return nil
		case 2, 3: // FIST/FISTP m16
			value := x87JITRead(s, 0)
			converted := x87JITConvertInt(s, value, 16, false)
			if s.x87Unmasked {
				return fmt.Errorf("unmasked x87 integer conversion exception")
			}
			if err := s.write16(addr, uint16(converted)); err != nil {
				return err
			}
			if reg == 3 {
				pop()
			}
			return nil
		case 5: // FILD m64
			value, err := s.read64(addr)
			if err != nil {
				return err
			}
			push(float64(int64(value)))
			return nil
		case 7: // FISTP m64
			converted := x87JITConvertInt(s, x87JITRead(s, 0), 64, false)
			if s.x87Unmasked {
				return fmt.Errorf("unmasked x87 integer conversion exception")
			}
			if err := s.write64(addr, uint64(converted)); err != nil {
				return err
			}
			pop()
			return nil
		}
	}
	return fmt.Errorf("unsupported x87 memory form %02x /%d", op, reg)
}

// x87Compare mirrors the interpreter's fpuCompare: -1, 0, 1, or 2 for NaN.
func x87Compare(a, b float64) int {
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

func x87Arithmetic(st0 *float64, value float64, reg int) error {
	switch reg {
	case 0:
		*st0 += value
	case 1:
		*st0 *= value
	case 4:
		*st0 -= value
	case 5:
		*st0 = value - *st0
	case 6:
		*st0 /= value
	case 7:
		*st0 = value / *st0
	default:
		return fmt.Errorf("unsupported x87 arithmetic /%d", reg)
	}
	return nil
}

func x87Round(value float64, controlWord *uint16) float64 {
	if controlWord == nil {
		return math.RoundToEven(value)
	}
	switch *controlWord >> 10 & 3 {
	case 0:
		return math.RoundToEven(value)
	case 1:
		return math.Floor(value)
	case 2:
		return math.Ceil(value)
	default:
		return math.Trunc(value)
	}
}

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
	if s.Mode32 {
		addr &= 0xFFFFFFFF
	}
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

func shiftRegister(s *State, value, count uint64, size int, op shiftOp) uint64 {
	nbits := uint64(size * 8)
	if size == 8 {
		count &= 0x3F
	} else {
		count &= 0x1F
	}
	maskedCount := count
	if op == shROL || op == shROR {
		count %= nbits
	}
	if count == 0 {
		return value
	}

	mask := truncate(^uint64(0), size)
	var result uint64
	switch op {
	case shROL:
		result = value<<count | value>>(nbits-count)
		if op == shROL {
			setCarryFlag(s, result)
		}
		if maskedCount == 1 {
			setOverflowFlag(s, (result>>(nbits-1))^(result&1))
		}
	case shROR:
		result = value>>count | value<<(nbits-count)
		setCarryFlag(s, result>>(nbits-1))
		if maskedCount == 1 {
			setOverflowFlag(s, (result>>(nbits-1))^(result>>(nbits-2)))
		}
	case shSHL:
		result = value << count
		setShiftResultFlags(s, result, size)
		setCarryFlag(s, value>>(nbits-count)&1)
		if count == 1 {
			setOverflowFlag(s, result>>(nbits-1)^(*s.Rflags&flagCF))
		}
	case shSHR:
		result = value >> count
		setShiftResultFlags(s, result, size)
		setCarryFlag(s, value>>(count-1)&1)
		if count == 1 {
			setOverflowFlag(s, value>>(nbits-1))
		}
	case shSAR:
		switch size {
		case 1:
			result = uint64(int8(value) >> count)
		case 2:
			result = uint64(int16(value) >> count)
		case 4:
			result = uint64(int32(value) >> count)
		default:
			result = uint64(int64(value) >> count)
		}
		setShiftResultFlags(s, result, size)
		setCarryFlag(s, value>>(count-1)&1)
		if count == 1 {
			setOverflowFlag(s, 0)
		}
	}
	return result & mask
}

func setShiftResultFlags(s *State, result uint64, size int) {
	flags := *s.Rflags &^ (flagCF | flagZF | flagSF | flagPF)
	result = truncate(result, size)
	if result == 0 {
		flags |= flagZF
	}
	if signBit(result, size) {
		flags |= flagSF
	}
	if bits.OnesCount8(uint8(result))%2 == 0 {
		flags |= flagPF
	}
	*s.Rflags = flags
}

func setCarryFlag(s *State, carry uint64) {
	*s.Rflags = *s.Rflags&^flagCF | carry&1
}

func setOverflowFlag(s *State, overflow uint64) {
	*s.Rflags = *s.Rflags&^flagOF | (overflow&1)*flagOF
}

func signedValue(value uint64, size int) int64 {
	switch size {
	case 1:
		return int64(int8(value))
	case 2:
		return int64(int16(value))
	case 4:
		return int64(int32(value))
	default:
		return int64(value)
	}
}

func signedMagnitude(value int64) uint64 {
	if value < 0 {
		return uint64(-(value + 1)) + 1
	}
	return uint64(value)
}

func signedMultiply(left, right uint64, size int) (uint64, bool) {
	a := signedValue(left, size)
	b := signedValue(right, size)
	if size < 8 {
		product := a * b
		bits := uint(size * 8)
		minimum := -int64(1) << (bits - 1)
		maximum := int64(1)<<(bits-1) - 1
		return truncate(uint64(product), size), product < minimum || product > maximum
	}

	negative := a < 0 != (b < 0)
	high, low := bits.Mul64(signedMagnitude(a), signedMagnitude(b))
	overflow := high != 0
	if negative {
		overflow = overflow || low > uint64(1)<<63
		low = -low
	} else {
		overflow = overflow || low > uint64(math.MaxInt64)
	}
	return low, overflow
}

func setMultiplyFlags(s *State, overflow bool) {
	*s.Rflags &^= flagCF | flagOF
	if overflow {
		*s.Rflags |= flagCF | flagOF
	}
}

func divideUnsigned(regs *[16]uint64, source, size int) error {
	divisor := truncate(regs[source], size)
	if divisor == 0 {
		return fmt.Errorf("division by zero")
	}

	var quotient, remainder uint64
	switch size {
	case 1:
		dividend := regs[0] & 0xFFFF
		quotient, remainder = dividend/divisor, dividend%divisor
		if quotient > 0xFF {
			return fmt.Errorf("division quotient overflow")
		}
		regs[0] = regs[0]&^uint64(0xFFFF) | quotient | remainder<<8
		return nil
	case 2:
		dividend := (regs[2]&0xFFFF)<<16 | regs[0]&0xFFFF
		quotient, remainder = dividend/divisor, dividend%divisor
		if quotient > 0xFFFF {
			return fmt.Errorf("division quotient overflow")
		}
	case 4:
		dividend := (regs[2]&0xFFFFFFFF)<<32 | regs[0]&0xFFFFFFFF
		quotient, remainder = dividend/divisor, dividend%divisor
		if quotient > 0xFFFFFFFF {
			return fmt.Errorf("division quotient overflow")
		}
	case 8:
		high, low := regs[2], regs[0]
		if high >= divisor {
			return fmt.Errorf("division quotient overflow")
		}
		quotient, remainder = bits.Div64(high, low, divisor)
	default:
		return fmt.Errorf("unsupported division width %d", size)
	}
	writeReg(regs, 0, quotient, size)
	writeReg(regs, 2, remainder, size)
	return nil
}

func divideSigned(regs *[16]uint64, source, size int) error {
	divisor := signedValue(regs[source], size)
	if divisor == 0 {
		return fmt.Errorf("division by zero")
	}

	if size < 8 {
		var dividend int64
		switch size {
		case 1:
			dividend = int64(int16(regs[0] & 0xFFFF))
		case 2:
			dividend = int64(int32((regs[2]&0xFFFF)<<16 | regs[0]&0xFFFF))
		case 4:
			dividend = int64((regs[2]&0xFFFFFFFF)<<32 | regs[0]&0xFFFFFFFF)
		default:
			return fmt.Errorf("unsupported signed division width %d", size)
		}
		quotient := dividend / divisor
		remainder := dividend % divisor
		bits := uint(size * 8)
		minimum := -int64(1) << (bits - 1)
		maximum := int64(1)<<(bits-1) - 1
		if quotient < minimum || quotient > maximum {
			return fmt.Errorf("division quotient overflow")
		}
		if size == 1 {
			regs[0] = regs[0]&^uint64(0xFFFF) |
				uint64(uint8(quotient)) |
				uint64(uint8(remainder))<<8
			return nil
		}
		writeReg(regs, 0, uint64(quotient), size)
		writeReg(regs, 2, uint64(remainder), size)
		return nil
	}

	high, low := regs[2], regs[0]
	dividendNegative := int64(high) < 0
	if dividendNegative {
		low = ^low + 1
		high = ^high
		if low == 0 {
			high++
		}
	}
	divisorNegative := divisor < 0
	divisorMagnitude := signedMagnitude(divisor)
	if high >= divisorMagnitude {
		return fmt.Errorf("division quotient overflow")
	}
	quotient, remainder := bits.Div64(high, low, divisorMagnitude)
	quotientNegative := dividendNegative != divisorNegative
	if quotientNegative {
		if quotient > uint64(1)<<63 {
			return fmt.Errorf("division quotient overflow")
		}
		quotient = -quotient
	} else if quotient > uint64(math.MaxInt64) {
		return fmt.Errorf("division quotient overflow")
	}
	if dividendNegative {
		remainder = -remainder
	}
	regs[0] = quotient
	regs[2] = remainder
	return nil
}

func doALU(s *State, op aluOp, a, b uint64, size int) uint64 {
	var r uint64
	mask := truncate(^uint64(0), size)
	a &= mask
	b &= mask
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
		carry := b > mask-cf || a > mask-(b+cf&mask)
		setAddFlags(s, a, b, r, size)
		if carry {
			*s.Rflags |= flagCF
		} else {
			*s.Rflags &^= flagCF
		}
	case aluSBB:
		cf := uint64(0)
		if *s.Rflags&flagCF != 0 {
			cf = 1
		}
		r = (a - b - cf) & mask
		borrow := b > mask-cf || a < b+cf
		setSubFlags(s, a, b, r, size)
		if borrow {
			*s.Rflags |= flagCF
		} else {
			*s.Rflags &^= flagCF
		}
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
	fl := *s.Rflags &^ (flagCF | flagPF | flagAF | flagZF | flagSF | flagOF)
	if r < a {
		fl |= flagCF
	}
	if (a^b^r)&0x10 != 0 {
		fl |= flagAF
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
	if bits.OnesCount8(uint8(r))%2 == 0 {
		fl |= flagPF
	}
	*s.Rflags = fl
}

func setSubFlags(s *State, a, b, r uint64, size int) {
	fl := *s.Rflags &^ (flagCF | flagPF | flagAF | flagZF | flagSF | flagOF)
	if b > a {
		fl |= flagCF
	}
	if (a^b^r)&0x10 != 0 {
		fl |= flagAF
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
	if bits.OnesCount8(uint8(r))%2 == 0 {
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
	if bits.OnesCount8(uint8(r))%2 == 0 {
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

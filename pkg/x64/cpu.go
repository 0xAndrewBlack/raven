package x64

import (
"fmt"
"math"
"math/bits"

"github.com/mirkobrombin/go-vm/pkg/arch"
"github.com/mirkobrombin/go-vm/pkg/mmu"
)

// Register indices (matching AMD64 encoding).
const (
RAX = iota
RCX
RDX
RBX
RSP
RBP
RSI
RDI
R8
R9
R10
R11
R12
R13
R14
R15
)

// RFLAGS bits.
const (
flagCF = 1 << 0
flagPF = 1 << 2
flagZF = 1 << 6
flagSF = 1 << 7
flagDF = 1 << 10
flagOF = 1 << 11
)

// CPU implements an x86_64 (AMD64) long-mode emulator.
type CPU struct {
Regs    [16]uint64
RIP     uint64
Rflags  uint64
mem     *mmu.MMU
syscall arch.SyscallHandler
running bool
instret uint64
fsBase  uint64

// SSE/AVX registers (128-bit XMM0-XMM15, stored as two uint64).
xmm [16][2]uint64
}

var _ arch.CPU = (*CPU)(nil)

// New creates an x86_64 CPU bound to the given MMU.
func New(mem *mmu.MMU) *CPU { return &CPU{mem: mem} }

func (c *CPU) Stop()                            { c.running = false }
func (c *CPU) GetPC() uint64                    { return c.RIP }
func (c *CPU) SetPC(v uint64)                   { c.RIP = v }
func (c *CPU) GetSP() uint64                    { return c.Regs[RSP] }
func (c *CPU) SetSP(v uint64)                   { c.Regs[RSP] = v }
func (c *CPU) GetTLS() uint64                   { return c.fsBase }
func (c *CPU) SetTLS(v uint64)                  { c.fsBase = v }
func (c *CPU) SyscallNum() uint64               { return c.Regs[RAX] }
func (c *CPU) SyscallArgs() [6]uint64 {
return [6]uint64{c.Regs[RDI], c.Regs[RSI], c.Regs[RDX], c.Regs[R10], c.Regs[R8], c.Regs[R9]}
}
func (c *CPU) SetSyscallReturn(v uint64)         { c.Regs[RAX] = v }
func (c *CPU) SyscallReturnPC() uint64           { return c.RIP }
func (c *CPU) GetMem() *mmu.MMU                  { return c.mem }
func (c *CPU) GetInstret() uint64                { return c.instret }
func (c *CPU) GetArch() arch.Arch                { return arch.ArchAMD64 }
func (c *CPU) SetSyscallHandler(h arch.SyscallHandler) { c.syscall = h }
func (c *CPU) CloneForThread() arch.CPU {
n := New(c.mem)
n.Regs = c.Regs
n.RIP = c.RIP
n.Rflags = c.Rflags
n.fsBase = c.fsBase
n.xmm = c.xmm
return n
}

// Run executes the fetch-decode-execute loop.
func (c *CPU) Run() error {
c.running = true
for c.running {
rip := c.RIP
if err := c.step(); err != nil {
return fmt.Errorf("at RIP=0x%x: %w", rip, err)
}
c.instret++
}
return nil
}

// =========================================================================
// Instruction decoder
// =========================================================================

// prefix state accumulated while scanning prefix bytes
type prefixState struct {
rex     byte
hasREX  bool
op66    bool // operand-size override → 16-bit
op67    bool // address-size override
repne   bool // F2
repe    bool // F3
segOver byte // not implemented but consumed
}

func (p *prefixState) rexW() bool { return p.hasREX && p.rex&0x08 != 0 }
func (p *prefixState) rexR() bool { return p.hasREX && p.rex&0x04 != 0 }
func (p *prefixState) rexX() bool { return p.hasREX && p.rex&0x02 != 0 }
func (p *prefixState) rexB() bool { return p.hasREX && p.rex&0x01 != 0 }

func (c *CPU) fetch8() (byte, error) {
b, err := c.mem.Read8(c.RIP)
if err != nil {
return 0, err
}
c.RIP++
return b, nil
}

func (c *CPU) fetch16() (uint16, error) {
v, err := c.mem.Read16(c.RIP)
if err != nil {
return 0, err
}
c.RIP += 2
return v, nil
}

func (c *CPU) fetch32() (uint32, error) {
v, err := c.mem.Read32(c.RIP)
if err != nil {
return 0, err
}
c.RIP += 4
return v, nil
}

func (c *CPU) fetch64() (uint64, error) {
v, err := c.mem.Read64(c.RIP)
if err != nil {
return 0, err
}
c.RIP += 8
return v, nil
}

// fetchImm fetches a sign-extended immediate of the given byte-width.
func (c *CPU) fetchImm(width int) (int64, error) {
switch width {
case 1:
b, err := c.fetch8()
return int64(int8(b)), err
case 2:
v, err := c.fetch16()
return int64(int16(v)), err
case 4:
v, err := c.fetch32()
return int64(int32(v)), err
case 8:
v, err := c.fetch64()
return int64(v), err
}
return 0, fmt.Errorf("bad imm width %d", width)
}

// step decodes and executes a single instruction.
func (c *CPU) step() error {
startRIP := c.RIP

// --- Collect prefixes ---
var pfx prefixState
for {
b, err := c.fetch8()
if err != nil {
return fmt.Errorf("fetch @ 0x%x: %w", startRIP, err)
}
switch {
case b == 0x66:
pfx.op66 = true
case b == 0x67:
pfx.op67 = true
case b == 0xF2:
pfx.repne = true
case b == 0xF3:
pfx.repe = true
case b == 0x26 || b == 0x2E || b == 0x36 || b == 0x3E || b == 0x64 || b == 0x65:
pfx.segOver = b
case b == 0xF0: // LOCK prefix - consumed, treated as no-op in emulation
case b >= 0x40 && b <= 0x4F:
pfx.rex = b
pfx.hasREX = true
default:
// Not a prefix - this is the opcode byte
return c.dispatch(b, &pfx, startRIP)
}
}
}

// operandSize returns the effective operand size in bytes.
func operandSize(pfx *prefixState) int {
if pfx.rexW() {
return 8
}
if pfx.op66 {
return 2
}
return 4
}

// regIndex expands a 3-bit register field with REX extension.
func regIndex(field byte, ext bool) int {
r := int(field & 7)
if ext {
r += 8
}
return r
}

// =========================================================================
// ModR/M + SIB decoder
// =========================================================================

type modrm struct {
mod  byte
reg  int // with REX.R applied
rm   int // with REX.B applied
raw  byte
// cached resolution result
resolved bool
cachedAddr  uint64
cachedIsReg bool
}

func (c *CPU) decodeModRM(pfx *prefixState) (*modrm, error) {
b, err := c.fetch8()
if err != nil {
return nil, err
}
m := &modrm{
mod: b >> 6,
reg: regIndex((b>>3)&7, pfx.rexR()),
rm:  regIndex(b&7, pfx.rexB()),
raw: b,
}
return m, nil
}

// resolveRMAddr returns the value for the rm operand. If mod==3 it's a register,
// otherwise it's a memory address (and the caller reads/writes through mem).
// The result is cached so that repeated calls do not re-consume instruction bytes.
func (c *CPU) resolveRMAddr(m *modrm, pfx *prefixState) (addr uint64, isReg bool, err error) {
if m.resolved {
return m.cachedAddr, m.cachedIsReg, nil
}
defer func() {
if err == nil {
m.resolved = true
m.cachedAddr = addr
m.cachedIsReg = isReg
}
}()
if m.mod == 3 {
return 0, true, nil
}
rmField := m.raw & 7
var base uint64
switch {
case rmField == 4: // SIB follows
sib, err2 := c.fetch8()
if err2 != nil {
return 0, false, err2
}
base = c.decodeSIB(sib, m.mod, pfx)
case rmField == 5 && m.mod == 0: // RIP-relative
disp32, err2 := c.fetch32()
if err2 != nil {
return 0, false, err2
}
base = uint64(int64(c.RIP) + int64(int32(disp32)))
if pfx.segOver == 0x64 {
base += c.fsBase
}
return base, false, nil
default:
idx := regIndex(rmField, pfx.rexB())
base = c.Regs[idx]
}

switch m.mod {
case 1:
disp8, err2 := c.fetch8()
if err2 != nil {
return 0, false, err2
}
base = uint64(int64(base) + int64(int8(disp8)))
case 2:
disp32, err2 := c.fetch32()
if err2 != nil {
return 0, false, err2
}
base = uint64(int64(base) + int64(int32(disp32)))
}
if pfx.segOver == 0x64 {
base += c.fsBase
}
return base, false, nil
}

func (c *CPU) decodeSIB(sib byte, mod byte, pfx *prefixState) uint64 {
scale := 1 << ((sib >> 6) & 3)
idxField := (sib >> 3) & 7
baseField := sib & 7

var base uint64
if baseField == 5 && mod == 0 {
// disp32 only - will be added by caller as mod==0 with no extra disp,
// but we need the 32-bit displacement here.
d, _ := c.fetch32()
base = uint64(int64(int32(d)))
} else {
base = c.Regs[regIndex(baseField, pfx.rexB())]
}

idxReg := regIndex(idxField, pfx.rexX())
if idxReg != RSP { // index == RSP means "no index"
base += c.Regs[idxReg] * uint64(scale)
}
return base
}

// readRM reads from the rm operand (register or memory).
func (c *CPU) readRM(m *modrm, pfx *prefixState, size int) (uint64, error) {
addr, isReg, err := c.resolveRMAddr(m, pfx)
if err != nil {
return 0, err
}
if isReg {
if size == 1 {
return c.readByteReg(m.rm, pfx.hasREX), nil
}
return c.readRegSized(m.rm, size), nil
}
return c.readMem(addr, size)
}

// writeRM writes to the rm operand.
func (c *CPU) writeRM(m *modrm, pfx *prefixState, size int, val uint64) error {
addr, isReg, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
if isReg {
if size == 1 {
c.writeByteReg(m.rm, pfx.hasREX, val)
} else {
c.writeRegSized(m.rm, size, val)
}
return nil
}
return c.writeMem(addr, size, val)
}

func (c *CPU) readRegSized(r int, size int) uint64 {
v := c.Regs[r]
switch size {
case 1:
return v & 0xFF
case 2:
return v & 0xFFFF
case 4:
return v & 0xFFFFFFFF
}
return v
}

// readByteReg reads a byte register, handling AH/CH/DH/BH when no REX prefix.
func (c *CPU) readByteReg(r int, hasREX bool) uint64 {
if !hasREX && r >= 4 && r <= 7 {
return (c.Regs[r-4] >> 8) & 0xFF
}
return c.Regs[r] & 0xFF
}

func (c *CPU) writeRegSized(r int, size int, v uint64) {
switch size {
case 1:
c.Regs[r] = (c.Regs[r] & ^uint64(0xFF)) | (v & 0xFF)
case 2:
c.Regs[r] = (c.Regs[r] & ^uint64(0xFFFF)) | (v & 0xFFFF)
case 4:
c.Regs[r] = v & 0xFFFFFFFF // zero-extend to 64
default:
c.Regs[r] = v
}
}

// writeByteReg writes a byte register, handling AH/CH/DH/BH when no REX prefix.
func (c *CPU) writeByteReg(r int, hasREX bool, v uint64) {
if !hasREX && r >= 4 && r <= 7 {
base := r - 4
c.Regs[base] = (c.Regs[base] & ^uint64(0xFF00)) | ((v & 0xFF) << 8)
return
}
c.Regs[r] = (c.Regs[r] & ^uint64(0xFF)) | (v & 0xFF)
}

func (c *CPU) readMem(addr uint64, size int) (uint64, error) {
switch size {
case 1:
b, err := c.mem.Read8(addr)
return uint64(b), err
case 2:
v, err := c.mem.Read16(addr)
return uint64(v), err
case 4:
v, err := c.mem.Read32(addr)
return uint64(v), err
case 8:
return c.mem.Read64(addr)
}
return 0, fmt.Errorf("bad mem size %d", size)
}

func (c *CPU) writeMem(addr uint64, size int, val uint64) error {
switch size {
case 1:
return c.mem.Write8(addr, uint8(val))
case 2:
return c.mem.Write16(addr, uint16(val))
case 4:
return c.mem.Write32(addr, uint32(val))
case 8:
return c.mem.Write64(addr, val)
}
return fmt.Errorf("bad mem size %d", size)
}

// push/pop helpers
func (c *CPU) push64(v uint64) error {
c.Regs[RSP] -= 8
return c.mem.Write64(c.Regs[RSP], v)
}

func (c *CPU) pop64() (uint64, error) {
v, err := c.mem.Read64(c.Regs[RSP])
if err != nil {
return 0, err
}
c.Regs[RSP] += 8
return v, nil
}

// =========================================================================
// Flag helpers
// =========================================================================

func (c *CPU) setArithFlags(result uint64, size int) {
nbits := size * 8
mask := uint64(1)<<nbits - 1
r := result & mask
c.Rflags &^= flagCF | flagZF | flagSF | flagPF | flagOF
if r == 0 {
c.Rflags |= flagZF
}
if r>>(nbits-1) != 0 {
c.Rflags |= flagSF
}
// parity of low byte
if bits.OnesCount8(uint8(r))%2 == 0 {
c.Rflags |= flagPF
}
}

func (c *CPU) setSubFlags(a, b, result uint64, size int) {
nbits := size * 8
mask := uint64(1)<<nbits - 1
c.setArithFlags(result, size)
// CF: borrow
if a&mask < b&mask {
c.Rflags |= flagCF
}
// OF: signed overflow
signA := (a >> (nbits - 1)) & 1
signB := (b >> (nbits - 1)) & 1
signR := (result >> (nbits - 1)) & 1
if signA != signB && signR != signA {
c.Rflags |= flagOF
}
}

func (c *CPU) setAddFlags(a, b, result uint64, size int) {
nbits := size * 8
mask := uint64(1)<<nbits - 1
c.setArithFlags(result, size)
if (result & mask) < (a & mask) {
c.Rflags |= flagCF
}
signA := (a >> (nbits - 1)) & 1
signB := (b >> (nbits - 1)) & 1
signR := (result >> (nbits - 1)) & 1
if signA == signB && signR != signA {
c.Rflags |= flagOF
}
}

func (c *CPU) setFlagsSHLD16(dst, src uint16, count uint64) {
result := uint16((uint32(dst)<<uint(count) | uint32(src)>>(16-uint(count))))
c.setArithFlags(uint64(result), 2)
c.Rflags &^= flagCF
if (dst>>(16-uint(count)))&1 != 0 {
c.Rflags |= flagCF
}
}

func (c *CPU) setFlagsSHLD32(dst, src uint32, count uint64) {
result := uint32((uint64(dst)<<uint(count) | uint64(src)>>(32-uint(count))))
c.setArithFlags(uint64(result), 4)
c.Rflags &^= flagCF
if (dst>>(32-uint(count)))&1 != 0 {
c.Rflags |= flagCF
}
}

func (c *CPU) setFlagsSHLD64(dst, src uint64, count uint64) {
result := dst<<uint(count) | src>>(64-uint(count))
c.setArithFlags(result, 8)
c.Rflags &^= flagCF
if (dst>>(64-uint(count)))&1 != 0 {
c.Rflags |= flagCF
}
}

func (c *CPU) setFlagsSHRD16(dst, src uint16, count uint64) {
result := uint16(dst>>uint(count) | src<<(16-uint(count)))
c.setArithFlags(uint64(result), 2)
c.Rflags &^= flagCF
if (dst>>(uint(count)-1))&1 != 0 {
c.Rflags |= flagCF
}
}

func (c *CPU) setFlagsSHRD32(dst, src uint32, count uint64) {
result := uint32(dst>>uint(count) | src<<(32-uint(count)))
c.setArithFlags(uint64(result), 4)
c.Rflags &^= flagCF
if (dst>>(uint(count)-1))&1 != 0 {
c.Rflags |= flagCF
}
}

func (c *CPU) setFlagsSHRD64(dst, src uint64, count uint64) {
result := dst>>uint(count) | src<<(64-uint(count))
c.setArithFlags(result, 8)
c.Rflags &^= flagCF
if (dst>>(uint(count)-1))&1 != 0 {
c.Rflags |= flagCF
}
}

func (c *CPU) flagCond(cond byte) bool {
switch cond {
case 0x0: // O
return c.Rflags&flagOF != 0
case 0x1: // NO
return c.Rflags&flagOF == 0
case 0x2: // B/C
return c.Rflags&flagCF != 0
case 0x3: // AE/NC
return c.Rflags&flagCF == 0
case 0x4: // E/Z
return c.Rflags&flagZF != 0
case 0x5: // NE/NZ
return c.Rflags&flagZF == 0
case 0x6: // BE
return c.Rflags&(flagCF|flagZF) != 0
case 0x7: // A
return c.Rflags&(flagCF|flagZF) == 0
case 0x8: // S
return c.Rflags&flagSF != 0
case 0x9: // NS
return c.Rflags&flagSF == 0
case 0xA: // P
return c.Rflags&flagPF != 0
case 0xB: // NP
return c.Rflags&flagPF == 0
case 0xC: // L
sf := (c.Rflags >> 7) & 1
of := (c.Rflags >> 11) & 1
return sf != of
case 0xD: // GE
sf := (c.Rflags >> 7) & 1
of := (c.Rflags >> 11) & 1
return sf == of
case 0xE: // LE
sf := (c.Rflags >> 7) & 1
of := (c.Rflags >> 11) & 1
return c.Rflags&flagZF != 0 || sf != of
case 0xF: // G
sf := (c.Rflags >> 7) & 1
of := (c.Rflags >> 11) & 1
return c.Rflags&flagZF == 0 && sf == of
}
return false
}

// =========================================================================
// Main dispatch
// =========================================================================

func (c *CPU) dispatch(op byte, pfx *prefixState, startRIP uint64) error {
size := operandSize(pfx)

switch op {
// --- NOP ---
case 0x90:
return nil

// --- PUSH r64 (0x50-0x57) ---
case 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57:
r := regIndex(op-0x50, pfx.rexB())
return c.push64(c.Regs[r])

// --- POP r64 (0x58-0x5F) ---
case 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F:
r := regIndex(op-0x58, pfx.rexB())
v, err := c.pop64()
if err != nil {
return err
}
c.Regs[r] = v
return nil

// --- PUSH imm8 (0x6A) ---
case 0x6A:
imm, err := c.fetch8()
if err != nil {
return err
}
return c.push64(uint64(int64(int8(imm))))

// --- PUSH imm32 (0x68) ---
case 0x68:
imm, err := c.fetch32()
if err != nil {
return err
}
return c.push64(uint64(int64(int32(imm))))

// --- MOV r, imm64 (0xB8-0xBF) ---
case 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF:
r := regIndex(op-0xB8, pfx.rexB())
if pfx.rexW() {
imm, err := c.fetch64()
if err != nil {
return err
}
c.Regs[r] = imm
} else if pfx.op66 {
imm, err := c.fetch16()
if err != nil {
return err
}
c.Regs[r] = uint64(imm)
} else {
imm, err := c.fetch32()
if err != nil {
return err
}
c.Regs[r] = uint64(imm)
}
return nil

// --- MOV r8, imm8 (0xB0-0xB7) ---
case 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7:
r := regIndex(op-0xB0, pfx.rexB())
imm, err := c.fetch8()
if err != nil {
return err
}
c.writeByteReg(r, pfx.hasREX, uint64(imm))
return nil

// --- RET (0xC3) ---
case 0xC3:
ret, err := c.pop64()
if err != nil {
return err
}
c.RIP = ret
return nil

// --- RET imm16 (0xC2) ---
case 0xC2:
imm, err := c.fetch16()
if err != nil {
return err
}
ret, err := c.pop64()
if err != nil {
return err
}
c.RIP = ret
c.Regs[RSP] += uint64(imm)
return nil

// --- CALL rel32 (0xE8) ---
case 0xE8:
rel, err := c.fetch32()
if err != nil {
return err
}
if err := c.push64(c.RIP); err != nil {
return err
}
c.RIP = uint64(int64(c.RIP) + int64(int32(rel)))
return nil

// --- JMP rel32 (0xE9) ---
case 0xE9:
rel, err := c.fetch32()
if err != nil {
return err
}
c.RIP = uint64(int64(c.RIP) + int64(int32(rel)))
return nil

// --- JMP rel8 (0xEB) ---
case 0xEB:
rel, err := c.fetch8()
if err != nil {
return err
}
c.RIP = uint64(int64(c.RIP) + int64(int8(rel)))
return nil

// --- Jcc rel8 (0x70-0x7F) ---
case 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F:
rel, err := c.fetch8()
if err != nil {
return err
}
if c.flagCond(op - 0x70) {
c.RIP = uint64(int64(c.RIP) + int64(int8(rel)))
}
return nil

// --- SYSCALL (0x0F 0x05) handled in 0x0F ---
// --- Two-byte opcode escape (0x0F) ---
case 0x0F:
return c.dispatch0F(pfx, startRIP)

// --- ADD/OR/ADC/SBB/AND/SUB/XOR/CMP r/m, imm (0x80-0x83) ---
case 0x80, 0x81, 0x82, 0x83:
return c.execGroup1(op, pfx, size)

// --- ADD r/m, r (0x00, 0x01) ---
case 0x00:
return c.execALU_rm_r(pfx, 1, aluADD)
case 0x01:
return c.execALU_rm_r(pfx, size, aluADD)
// --- ADD r, r/m (0x02, 0x03) ---
case 0x02:
return c.execALU_r_rm(pfx, 1, aluADD)
case 0x03:
return c.execALU_r_rm(pfx, size, aluADD)
// --- ADD al/rax, imm (0x04, 0x05) ---
case 0x04:
imm, err := c.fetch8()
if err != nil {
return err
}
a := c.readRegSized(RAX, 1)
r := a + uint64(imm)
c.setAddFlags(a, uint64(imm), r, 1)
c.writeRegSized(RAX, 1, r)
return nil
case 0x05:
immSz := size
if immSz == 8 {
immSz = 4
}
imm, err := c.fetchImm(immSz)
if err != nil {
return err
}
a := c.readRegSized(RAX, size)
r := a + uint64(imm)
c.setAddFlags(a, uint64(imm), r, size)
c.writeRegSized(RAX, size, r)
return nil

// --- OR ---
case 0x08:
return c.execALU_rm_r(pfx, 1, aluOR)
case 0x09:
return c.execALU_rm_r(pfx, size, aluOR)
case 0x0A:
return c.execALU_r_rm(pfx, 1, aluOR)
case 0x0B:
return c.execALU_r_rm(pfx, size, aluOR)
case 0x0C: // OR AL, imm8
imm, err := c.fetch8()
if err != nil {
return err
}
r := c.readRegSized(RAX, 1) | uint64(imm)
c.setArithFlags(r, 1)
c.Rflags &^= flagCF | flagOF
c.writeRegSized(RAX, 1, r)
return nil
case 0x0D: // OR rAX, imm
immSz := size
if immSz == 8 {
immSz = 4
}
imm, err := c.fetchImm(immSz)
if err != nil {
return err
}
r := c.readRegSized(RAX, size) | uint64(imm)
c.setArithFlags(r, size)
c.Rflags &^= flagCF | flagOF
c.writeRegSized(RAX, size, r)
return nil

// --- ADC ---
case 0x10:
return c.execALU_rm_r(pfx, 1, aluADC)
case 0x11:
return c.execALU_rm_r(pfx, size, aluADC)
case 0x12:
return c.execALU_r_rm(pfx, 1, aluADC)
case 0x13:
return c.execALU_r_rm(pfx, size, aluADC)

// --- SBB ---
case 0x18:
return c.execALU_rm_r(pfx, 1, aluSBB)
case 0x19:
return c.execALU_rm_r(pfx, size, aluSBB)
case 0x1A:
return c.execALU_r_rm(pfx, 1, aluSBB)
case 0x1B:
return c.execALU_r_rm(pfx, size, aluSBB)

// --- AND ---
case 0x20:
return c.execALU_rm_r(pfx, 1, aluAND)
case 0x21:
return c.execALU_rm_r(pfx, size, aluAND)
case 0x22:
return c.execALU_r_rm(pfx, 1, aluAND)
case 0x23:
return c.execALU_r_rm(pfx, size, aluAND)
case 0x24: // AND AL, imm8
imm, err := c.fetch8()
if err != nil {
return err
}
r := c.readRegSized(RAX, 1) & uint64(imm)
c.setArithFlags(r, 1)
c.Rflags &^= flagCF | flagOF
c.writeRegSized(RAX, 1, r)
return nil
case 0x25: // AND rAX, imm
immSz := size
if immSz == 8 {
immSz = 4
}
imm, err := c.fetchImm(immSz)
if err != nil {
return err
}
r := c.readRegSized(RAX, size) & uint64(imm)
c.setArithFlags(r, size)
c.Rflags &^= flagCF | flagOF
c.writeRegSized(RAX, size, r)
return nil

// --- SUB ---
case 0x28:
return c.execALU_rm_r(pfx, 1, aluSUB)
case 0x29:
return c.execALU_rm_r(pfx, size, aluSUB)
case 0x2A:
return c.execALU_r_rm(pfx, 1, aluSUB)
case 0x2B:
return c.execALU_r_rm(pfx, size, aluSUB)
case 0x2C: // SUB AL, imm8
imm, err := c.fetch8()
if err != nil {
return err
}
a := c.readRegSized(RAX, 1)
r := a - uint64(imm)
c.setSubFlags(a, uint64(imm), r, 1)
c.writeRegSized(RAX, 1, r)
return nil
case 0x2D: // SUB rAX, imm
immSz := size
if immSz == 8 {
immSz = 4
}
imm, err := c.fetchImm(immSz)
if err != nil {
return err
}
a := c.readRegSized(RAX, size)
r := a - uint64(imm)
c.setSubFlags(a, uint64(imm), r, size)
c.writeRegSized(RAX, size, r)
return nil

// --- XOR ---
case 0x30:
return c.execALU_rm_r(pfx, 1, aluXOR)
case 0x31:
return c.execALU_rm_r(pfx, size, aluXOR)
case 0x32:
return c.execALU_r_rm(pfx, 1, aluXOR)
case 0x33:
return c.execALU_r_rm(pfx, size, aluXOR)
case 0x34: // XOR AL, imm8
imm, err := c.fetch8()
if err != nil {
return err
}
r := c.readRegSized(RAX, 1) ^ uint64(imm)
c.setArithFlags(r, 1)
c.Rflags &^= flagCF | flagOF
c.writeRegSized(RAX, 1, r)
return nil
case 0x35: // XOR rAX, imm
immSz := size
if immSz == 8 {
immSz = 4
}
imm, err := c.fetchImm(immSz)
if err != nil {
return err
}
r := c.readRegSized(RAX, size) ^ uint64(imm)
c.setArithFlags(r, size)
c.Rflags &^= flagCF | flagOF
c.writeRegSized(RAX, size, r)
return nil

// --- CMP ---
case 0x38:
return c.execALU_rm_r(pfx, 1, aluCMP)
case 0x39:
return c.execALU_rm_r(pfx, size, aluCMP)
case 0x3A:
return c.execALU_r_rm(pfx, 1, aluCMP)
case 0x3B:
return c.execALU_r_rm(pfx, size, aluCMP)
case 0x3C: // CMP AL, imm8
imm, err := c.fetch8()
if err != nil {
return err
}
a := c.readRegSized(RAX, 1)
c.setSubFlags(a, uint64(imm), a-uint64(imm), 1)
return nil
case 0x3D: // CMP rAX, imm
immSz := size
if immSz == 8 {
immSz = 4
}
imm, err := c.fetchImm(immSz)
if err != nil {
return err
}
a := c.readRegSized(RAX, size)
c.setSubFlags(a, uint64(imm), a-uint64(imm), size)
return nil

// --- TEST r/m, r (0x84, 0x85) ---
case 0x84:
return c.execTEST(pfx, 1)
case 0x85:
return c.execTEST(pfx, size)

// --- XCHG (0x86, 0x87) ---
case 0x86:
return c.execXCHG(pfx, 1)
case 0x87:
return c.execXCHG(pfx, size)

// --- MOV r/m, r (0x88, 0x89) ---
case 0x88:
return c.execMOV_rm_r(pfx, 1)
case 0x89:
return c.execMOV_rm_r(pfx, size)

// --- MOV r, r/m (0x8A, 0x8B) ---
case 0x8A:
return c.execMOV_r_rm(pfx, 1)
case 0x8B:
return c.execMOV_r_rm(pfx, size)

// --- LEA r, m (0x8D) ---
case 0x8D:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
c.writeRegSized(m.reg, size, addr)
return nil

// --- MOV r/m, imm (0xC6, 0xC7) ---
case 0xC6:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
// Resolve address before fetching immediate (displacement precedes imm in encoding)
if _, _, err := c.resolveRMAddr(m, pfx); err != nil {
return err
}
imm, err := c.fetch8()
if err != nil {
return err
}
return c.writeRM(m, pfx, 1, uint64(imm))
case 0xC7:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
// Resolve address before fetching immediate (displacement precedes imm in encoding)
if _, _, err := c.resolveRMAddr(m, pfx); err != nil {
return err
}
immSz := size
if immSz == 8 {
immSz = 4
}
imm, err := c.fetchImm(immSz)
if err != nil {
return err
}
return c.writeRM(m, pfx, size, uint64(imm))

// --- MOVZX (0x0F B6/B7) handled in 0x0F ---
// --- MOVSX (0x0F BE/BF) handled in 0x0F ---

// --- Shift group (0xC0, 0xC1, 0xD0, 0xD1, 0xD2, 0xD3) ---
case 0xC0:
return c.execShift(pfx, 1, -1)
case 0xC1:
return c.execShift(pfx, size, -1)
case 0xD0:
return c.execShift(pfx, 1, 1)
case 0xD1:
return c.execShift(pfx, size, 1)
case 0xD2:
return c.execShift(pfx, 1, -2)
case 0xD3:
return c.execShift(pfx, size, -2)

// --- x87 FPU stubs (0xD8-0xDF) ---
// Minimally decode the ModRM to skip the instruction bytes.
// busybox uses FLDCW/FNSTCW for FP rounding control; we
// just swallow these silently.
case 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
if m.mod != 3 {
// Memory operand: consume displacement via resolveRMAddr
_, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
}
return nil

// --- MOVSXD (0x63) ---
case 0x63:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
val, err := c.readRM(m, pfx, 4)
if err != nil {
return err
}
c.writeRegSized(m.reg, 8, uint64(int64(int32(val))))
return nil

// --- CDQ/CQO (0x99) ---
case 0x99:
if pfx.rexW() {
// CQO: sign-extend RAX into RDX:RAX
if int64(c.Regs[RAX]) < 0 {
c.Regs[RDX] = ^uint64(0)
} else {
c.Regs[RDX] = 0
}
} else {
// CDQ: sign-extend EAX into EDX:EAX
if int32(c.Regs[RAX]) < 0 {
c.Regs[RDX] = 0xFFFFFFFF
} else {
c.Regs[RDX] = 0
}
}
return nil

// --- CBW/CWDE/CDQE (0x98) ---
case 0x98:
if pfx.rexW() {
c.Regs[RAX] = uint64(int64(int32(c.Regs[RAX])))
} else if pfx.op66 {
c.writeRegSized(RAX, 2, uint64(int16(int8(c.Regs[RAX]))))
} else {
c.writeRegSized(RAX, 4, uint64(int32(int16(c.Regs[RAX]))))
}
return nil

// --- MUL/IMUL/DIV/IDIV group (0xF6, 0xF7) ---
case 0xF6:
return c.execGroup3(pfx, 1)
case 0xF7:
return c.execGroup3(pfx, size)

// --- INC/DEC group (0xFE, 0xFF) ---
case 0xFE:
return c.execGroup45(pfx, 1)
case 0xFF:
return c.execGroup45(pfx, size)

// --- IMUL r, r/m (0x0F AF) handled in 0x0F ---
// --- IMUL r, r/m, imm8 (0x6B) ---
case 0x6B:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
val, err := c.readRM(m, pfx, size)
if err != nil {
return err
}
imm, err := c.fetch8()
if err != nil {
return err
}
result := int64(val) * int64(int8(imm))
c.writeRegSized(m.reg, size, uint64(result))
return nil

// --- IMUL r, r/m, imm32 (0x69) ---
case 0x69:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
val, err := c.readRM(m, pfx, size)
if err != nil {
return err
}
immSz := size
if immSz == 8 {
immSz = 4
}
imm, err := c.fetchImm(immSz)
if err != nil {
return err
}
result := int64(val) * imm
c.writeRegSized(m.reg, size, uint64(result))
return nil

// --- CLC/STC/CLD/STD ---
case 0xF8: // CLC
c.Rflags &^= flagCF
return nil
case 0xF9: // STC
c.Rflags |= flagCF
return nil
case 0xFC: // CLD
c.Rflags &^= flagDF
return nil
case 0xFD: // STD
c.Rflags |= flagDF
return nil

// --- LEAVE (0xC9) ---
case 0xC9:
c.Regs[RSP] = c.Regs[RBP]
v, err := c.pop64()
if err != nil {
return err
}
c.Regs[RBP] = v
return nil

// --- INT3 (0xCC) ---
case 0xCC:
c.running = false
return nil

// --- HLT (0xF4) ---
case 0xF4:
c.running = false
return nil

// --- CPUID (handled as NOP returning zeros) ---
case 0xA2:
// STOSB handled in string ops; CPUID is 0F A2 (handled in 0F)
return c.execSTOS(pfx, 1)

// --- String operations ---
case 0xA4: // MOVSB
return c.execMOVS(pfx, 1)
case 0xA5: // MOVSD/MOVSQ
return c.execMOVS(pfx, size)
case 0xA6: // CMPSB
return c.execCMPS(pfx, 1)
case 0xA7: // CMPSD/CMPSQ
return c.execCMPS(pfx, size)
case 0xAA: // STOSB
return c.execSTOS(pfx, 1)
case 0xAB: // STOSD/STOSQ
return c.execSTOS(pfx, size)
case 0xAC: // LODSB
return c.execLODS(pfx, 1)
case 0xAD: // LODSD/LODSQ
return c.execLODS(pfx, size)
case 0xAE: // SCASB
return c.execSCAS(pfx, 1)
case 0xAF: // SCASD/SCASQ
return c.execSCAS(pfx, size)

// --- MOV moffs (0xA0-0xA3) ---
case 0xA0: // MOV AL, moffs8
addr, err := c.fetch64()
if err != nil {
return err
}
v, err := c.mem.Read8(addr)
if err != nil {
return err
}
c.writeRegSized(RAX, 1, uint64(v))
return nil
case 0xA1: // MOV rAX, moffs
addr, err := c.fetch64()
if err != nil {
return err
}
v, err := c.readMem(addr, size)
if err != nil {
return err
}
c.writeRegSized(RAX, size, v)
return nil
case 0xA8: // TEST AL, imm8
imm, err := c.fetch8()
if err != nil {
return err
}
r := c.readRegSized(RAX, 1) & uint64(imm)
c.setArithFlags(r, 1)
c.Rflags &^= flagCF | flagOF
return nil
case 0xA9: // TEST rAX, imm
immSz := size
if immSz == 8 {
immSz = 4
}
imm, err := c.fetchImm(immSz)
if err != nil {
return err
}
r := c.readRegSized(RAX, size) & uint64(imm)
c.setArithFlags(r, size)
c.Rflags &^= flagCF | flagOF
return nil

// --- NOT/NEG handled in F6/F7 group ---

// --- XCHG rAX, r (0x91-0x97) ---
case 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97:
r := regIndex(op-0x90, pfx.rexB())
c.Regs[RAX], c.Regs[r] = c.Regs[r], c.Regs[RAX]
return nil

// --- LAHF (0x9F) / SAHF (0x9E) ---
case 0x9E: // SAHF
ah := uint8(c.Regs[RAX] >> 8)
c.Rflags = (c.Rflags & ^uint64(0xFF)) | uint64(ah) | 2
return nil
case 0x9F: // LAHF
c.Regs[RAX] = (c.Regs[RAX] & ^uint64(0xFF00)) | (uint64(c.Rflags&0xFF) << 8)
return nil

// --- ENDBR64 is encoded as F3 0F 1E FA - consumed via 0x0F path ---

default:
return fmt.Errorf("unimplemented opcode 0x%02X at RIP=0x%x", op, startRIP)
}
}

// =========================================================================
// Two-byte opcodes (0x0F xx)
// =========================================================================

func (c *CPU) dispatch0F(pfx *prefixState, startRIP uint64) error {
op2, err := c.fetch8()
if err != nil {
return err
}
size := operandSize(pfx)

switch op2 {
// --- SYSCALL ---
case 0x05:
if c.syscall != nil {
c.syscall(c)
}
return nil

// --- Jcc rel32 (0x80-0x8F) ---
case 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F:
rel, err := c.fetch32()
if err != nil {
return err
}
if c.flagCond(op2 - 0x80) {
c.RIP = uint64(int64(c.RIP) + int64(int32(rel)))
}
return nil

// --- SETcc r/m8 (0x90-0x9F) ---
case 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
var val uint64
if c.flagCond(op2 - 0x90) {
val = 1
}
return c.writeRM(m, pfx, 1, val)

// --- CMOVcc r, r/m (0x40-0x4F) ---
case 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
val, err := c.readRM(m, pfx, size)
if err != nil {
return err
}
if c.flagCond(op2 - 0x40) {
c.writeRegSized(m.reg, size, val)
}
return nil

// --- MOVZX r, r/m8 (0xB6) ---
case 0xB6:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
val, err := c.readRM(m, pfx, 1)
if err != nil {
return err
}
c.writeRegSized(m.reg, size, val&0xFF)
return nil

// --- MOVZX r, r/m16 (0xB7) ---
case 0xB7:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
val, err := c.readRM(m, pfx, 2)
if err != nil {
return err
}
c.writeRegSized(m.reg, size, val&0xFFFF)
return nil

// --- MOVSX r, r/m8 (0xBE) ---
case 0xBE:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
val, err := c.readRM(m, pfx, 1)
if err != nil {
return err
}
c.writeRegSized(m.reg, size, uint64(int64(int8(val))))
return nil

// --- MOVSX r, r/m16 (0xBF) ---
case 0xBF:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
val, err := c.readRM(m, pfx, 2)
if err != nil {
return err
}
c.writeRegSized(m.reg, size, uint64(int64(int16(val))))
return nil

// --- IMUL r, r/m (0xAF) ---
case 0xAF:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
val, err := c.readRM(m, pfx, size)
if err != nil {
return err
}
result := c.readRegSized(m.reg, size) * val
c.writeRegSized(m.reg, size, result)
return nil

// --- BSR (0xBD), BSF (0xBC) ---
case 0xBC: // BSF / TZCNT
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
val, err := c.readRM(m, pfx, size)
if err != nil {
return err
}
if val == 0 {
c.Rflags |= flagZF
} else {
c.Rflags &^= flagZF
c.writeRegSized(m.reg, size, uint64(bits.TrailingZeros64(val)))
}
return nil
case 0xBD: // BSR / LZCNT
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
val, err := c.readRM(m, pfx, size)
if err != nil {
return err
}
if val == 0 {
c.Rflags |= flagZF
} else {
c.Rflags &^= flagZF
c.writeRegSized(m.reg, size, uint64(63-bits.LeadingZeros64(val)))
}
return nil

// --- BT r/m, r (0xA3) ---
case 0xA3:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
val, err := c.readRM(m, pfx, size)
if err != nil {
return err
}
bitpos := c.Regs[m.reg] & uint64(size*8-1)
c.Rflags &^= flagCF
if val&(1<<bitpos) != 0 {
c.Rflags |= flagCF
}
return nil

// --- BTS r/m, r (0xAB) ---
case 0xAB:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
val, err := c.readRM(m, pfx, size)
if err != nil {
return err
}
bitpos := c.Regs[m.reg] & uint64(size*8-1)
c.Rflags &^= flagCF
if val&(1<<bitpos) != 0 {
c.Rflags |= flagCF
}
return c.writeRM(m, pfx, size, val|(1<<bitpos))

// --- BTR r/m, r (0xB3) ---
case 0xB3:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
val, err := c.readRM(m, pfx, size)
if err != nil {
return err
}
bitpos := c.Regs[m.reg] & uint64(size*8-1)
c.Rflags &^= flagCF
if val&(1<<bitpos) != 0 {
c.Rflags |= flagCF
}
return c.writeRM(m, pfx, size, val&^(1<<bitpos))

// --- BTC r/m, r (0xBB) ---
case 0xBB:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
val, err := c.readRM(m, pfx, size)
if err != nil {
return err
}
bitpos := c.Regs[m.reg] & uint64(size*8-1)
c.Rflags &^= flagCF
if val&(1<<bitpos) != 0 {
c.Rflags |= flagCF
}
return c.writeRM(m, pfx, size, val^(1<<bitpos))

// --- BT/BTS/BTR/BTC (0xBA group) ---
case 0xBA:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
imm, err := c.fetch8()
if err != nil {
return err
}
val, err := c.readRM(m, pfx, size)
if err != nil {
return err
}
bit := uint64(1) << (imm & 63)
c.Rflags &^= flagCF
if val&bit != 0 {
c.Rflags |= flagCF
}
switch m.reg {
case 4: // BT
case 5: // BTS
return c.writeRM(m, pfx, size, val|bit)
case 6: // BTR
return c.writeRM(m, pfx, size, val&^bit)
case 7: // BTC
return c.writeRM(m, pfx, size, val^bit)
}
return nil

// --- BSWAP (0xC8-0xCF) ---
case 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF:
r := regIndex(op2-0xC8, pfx.rexB())
if pfx.rexW() {
c.Regs[r] = bits.ReverseBytes64(c.Regs[r])
} else {
c.Regs[r] = uint64(bits.ReverseBytes32(uint32(c.Regs[r])))
}
return nil

// --- XADD (0xC0, 0xC1) ---
case 0xC0:
return c.execXADD(pfx, 1)
case 0xC1:
return c.execXADD(pfx, size)

// --- CMPXCHG (0xB0, 0xB1) ---
case 0xB0:
return c.execCMPXCHG(pfx, 1)
case 0xB1:
return c.execCMPXCHG(pfx, size)

// --- NOP variants (0x1F multibyte NOP) ---
case 0x1E, 0x1F:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
_ = m
// Resolve address side effects (consume displacement bytes) but do nothing
_, _, _ = c.resolveRMAddr(m, pfx)
return nil

// --- RDTSC (0x31) ---
case 0x31:
c.Regs[RAX] = c.instret & 0xFFFFFFFF
c.Regs[RDX] = c.instret >> 32
return nil

// --- CPUID (0xA2) ---
case 0xA2:
leaf := c.Regs[RAX]
subleaf := c.Regs[RCX]
_ = subleaf
switch leaf {
case 0: // max leaf + vendor
c.Regs[RAX] = 0xd // max basic leaf
c.Regs[RBX] = 0x756e6547 // "Genu"
c.Regs[RDX] = 0x49656e69 // "ineI"
c.Regs[RCX] = 0x6c65746e // "ntel"
case 1: // family/model/stepping + feature flags
c.Regs[RAX] = 0x000506e3 // family 6, model 94 (Skylake)
c.Regs[RBX] = 0x00100800
c.Regs[RCX] = 0x77dafbbf // SSE3, SSSE3, SSE4.1, SSE4.2, POPCNT (no OSXSAVE/AVX/XSAVE)
c.Regs[RDX] = 0xbfebfbff // FPU, SSE, SSE2, etc.
case 7: // extended features
c.Regs[RAX] = 0
c.Regs[RBX] = 0x00000008 // BMI1 only (no AVX2, no BMI2)
c.Regs[RCX] = 0
c.Regs[RDX] = 0
default:
c.Regs[RAX] = 0
c.Regs[RBX] = 0
c.Regs[RCX] = 0
c.Regs[RDX] = 0
}
return nil

// --- SHLD r/m, r, imm8 (0xA4) / SHLD r/m, r, CL (0xA5) ---
case 0xA4, 0xA5:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
var count uint64
if op2 == 0xA4 {
imm, err := c.fetch8()
if err != nil {
return err
}
count = uint64(imm)
} else {
count = c.Regs[RCX] & 0x3f
}
if count == 0 {
return nil
}
dst, err := c.readRM(m, pfx, size)
if err != nil {
return err
}
src := c.Regs[m.reg]
if size == 2 {
count &= 0x1f
result := uint16((uint32(uint16(dst))<<uint(count) | uint32(uint16(src))>>(16-uint(count))))
c.writeRM(m, pfx, size, uint64(result))
c.setFlagsSHLD16(uint16(dst), uint16(src), count)
} else if size == 4 {
count &= 0x1f
result := uint32((uint64(uint32(dst))<<uint(count) | uint64(uint32(src))>>(32-uint(count))))
c.writeRM(m, pfx, size, uint64(result))
c.setFlagsSHLD32(uint32(dst), uint32(src), count)
} else {
result := dst<<uint(count) | src>>(64-uint(count))
c.writeRM(m, pfx, size, result)
c.setFlagsSHLD64(dst, src, count)
}
return nil

// --- SHRD r/m, r, imm8 (0xAC) / SHRD r/m, r, CL (0xAD) ---
case 0xAC, 0xAD:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
var count uint64
if op2 == 0xAC {
imm, err := c.fetch8()
if err != nil {
return err
}
count = uint64(imm)
} else {
count = c.Regs[RCX] & 0x3f
}
if count == 0 {
return nil
}
dst, err := c.readRM(m, pfx, size)
if err != nil {
return err
}
src := c.Regs[m.reg]
if size == 2 {
count &= 0x1f
result := uint16(uint16(dst)>>uint(count) | uint16(src)<<(16-uint(count)))
c.writeRM(m, pfx, size, uint64(result))
c.setFlagsSHRD16(uint16(dst), uint16(src), count)
} else if size == 4 {
count &= 0x1f
result := uint32(uint32(dst)>>uint(count) | uint32(src)<<(32-uint(count)))
c.writeRM(m, pfx, size, uint64(result))
c.setFlagsSHRD32(uint32(dst), uint32(src), count)
} else {
result := dst>>uint(count) | src<<(64-uint(count))
c.writeRM(m, pfx, size, result)
c.setFlagsSHRD64(dst, src, count)
}
return nil

// --- MOVD/MOVQ xmm ↔ r/m (0x6E, 0x7E) ---
case 0x6E:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
val, err := c.readRM(m, pfx, size)
if err != nil {
return err
}
c.xmm[m.reg] = [2]uint64{val, 0}
return nil
case 0x7E:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
if pfx.repe {
// F3 0F 7E = MOVQ xmm, xmm/m64 (load)
val, err := c.readRM(m, pfx, 8)
if err != nil {
return err
}
c.xmm[m.reg] = [2]uint64{val, 0}
return nil
}
// 66 0F 7E = MOVD/MOVQ xmm → r/m (store)
val := c.xmm[m.reg][0]
return c.writeRM(m, pfx, size, val)

// --- MOVDQU/MOVDQA xmm, m128 (0x6F) ---
case 0x6F:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
if m.mod == 3 {
c.xmm[m.reg] = c.xmm[m.rm]
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
lo, _ := c.mem.Read64(addr)
hi, _ := c.mem.Read64(addr + 8)
c.xmm[m.reg] = [2]uint64{lo, hi}
}
return nil

// --- MOVDQU/MOVDQA m128, xmm (0x7F) ---
case 0x7F:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
if m.mod == 3 {
c.xmm[m.rm] = c.xmm[m.reg]
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
c.mem.Write64(addr, c.xmm[m.reg][0])
c.mem.Write64(addr+8, c.xmm[m.reg][1])
}
return nil

// --- MOVAPS/MOVUPS/MOVSD/MOVSS xmm, xmm/m (0x10, 0x28) ---
case 0x10, 0x28:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
if pfx.repne { // F2: MOVSD (scalar double)
if m.mod == 3 {
c.xmm[m.reg][0] = c.xmm[m.rm][0]
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
lo, _ := c.mem.Read64(addr)
c.xmm[m.reg][0] = lo
c.xmm[m.reg][1] = 0
}
} else if pfx.repe { // F3: MOVSS (scalar single)
if m.mod == 3 {
c.xmm[m.reg][0] = (c.xmm[m.reg][0] & 0xFFFFFFFF00000000) | (c.xmm[m.rm][0] & 0xFFFFFFFF)
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
v, _ := c.mem.Read32(addr)
c.xmm[m.reg][0] = uint64(v)
c.xmm[m.reg][1] = 0
}
} else { // packed 128-bit
if m.mod == 3 {
c.xmm[m.reg] = c.xmm[m.rm]
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
lo, _ := c.mem.Read64(addr)
hi, _ := c.mem.Read64(addr + 8)
c.xmm[m.reg] = [2]uint64{lo, hi}
}
}
return nil

// --- MOVLPS/MOVHPS xmm, m64 (0x12, 0x16) ---
case 0x12:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
if m.mod == 3 {
// MOVHLPS xmm, xmm - move high to low
c.xmm[m.reg][0] = c.xmm[m.rm][1]
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
lo, _ := c.mem.Read64(addr)
c.xmm[m.reg][0] = lo
}
return nil
case 0x16:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
if m.mod == 3 {
// MOVLHPS xmm, xmm - move low to high
c.xmm[m.reg][1] = c.xmm[m.rm][0]
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
hi, _ := c.mem.Read64(addr)
c.xmm[m.reg][1] = hi
}
return nil

// --- MOVLPS/MOVHPS m64, xmm (0x13, 0x17) ---
case 0x13:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
return c.mem.Write64(addr, c.xmm[m.reg][0])
case 0x17:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
return c.mem.Write64(addr, c.xmm[m.reg][1])

// --- MOVAPS/MOVUPS/MOVSD/MOVSS store (0x11, 0x29) ---
case 0x11, 0x29:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
if pfx.repne { // F2: MOVSD store
if m.mod == 3 {
c.xmm[m.rm][0] = c.xmm[m.reg][0]
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
c.mem.Write64(addr, c.xmm[m.reg][0])
}
} else if pfx.repe { // F3: MOVSS store
if m.mod == 3 {
c.xmm[m.rm][0] = (c.xmm[m.rm][0] & 0xFFFFFFFF00000000) | (c.xmm[m.reg][0] & 0xFFFFFFFF)
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
c.mem.Write32(addr, uint32(c.xmm[m.reg][0]))
}
} else { // packed 128-bit
if m.mod == 3 {
c.xmm[m.rm] = c.xmm[m.reg]
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
c.mem.Write64(addr, c.xmm[m.reg][0])
c.mem.Write64(addr+8, c.xmm[m.reg][1])
}
}
return nil

// --- XORPS/XORPD (0x57) ---
case 0x57:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
var src [2]uint64
if m.mod == 3 {
src = c.xmm[m.rm]
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
src[0], _ = c.mem.Read64(addr)
src[1], _ = c.mem.Read64(addr + 8)
}
c.xmm[m.reg][0] ^= src[0]
c.xmm[m.reg][1] ^= src[1]
return nil

// --- Scalar SSE arithmetic (0x58-0x5E) ---
// ADDPS/ADDPD/ADDSS/ADDSD (0x58), MULPS/.../MULSD (0x59),
// CVTPS2PD/.../CVTSD2SS (0x5A),
// SUBPS/SUBPD/SUBSS/SUBSD (0x5C), MINPS/.../MINSD (0x5D),
// DIVPS/DIVPD/DIVSS/DIVSD (0x5E), MAXPS/.../MAXSD (0x5F)
case 0x58, 0x59, 0x5A, 0x5C, 0x5D, 0x5E, 0x5F:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
if pfx.repne { // F2 prefix: scalar double
var srcBits uint64
if m.mod == 3 {
srcBits = c.xmm[m.rm][0]
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
srcBits, _ = c.mem.Read64(addr)
}
dstBits := c.xmm[m.reg][0]
src := math.Float64frombits(srcBits)
dst := math.Float64frombits(dstBits)
var result float64
switch op2 {
case 0x58: result = dst + src
case 0x59: result = dst * src
case 0x5A: // CVTSD2SS - convert double to single, store in low 32 bits
c.xmm[m.reg][0] = (c.xmm[m.reg][0] &^ 0xFFFFFFFF) | uint64(math.Float32bits(float32(src)))
return nil
case 0x5C: result = dst - src
case 0x5D: result = math.Min(dst, src)
case 0x5E: result = dst / src
case 0x5F: result = math.Max(dst, src)
default:
return fmt.Errorf("unhandled F2 0F %02X", op2)
}
c.xmm[m.reg][0] = math.Float64bits(result)
return nil
} else if pfx.repe { // F3 prefix: scalar single
var srcBits uint32
if m.mod == 3 {
srcBits = uint32(c.xmm[m.rm][0])
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
v, _ := c.mem.Read32(addr)
srcBits = uint32(v)
}
dstBits := uint32(c.xmm[m.reg][0])
src := math.Float32frombits(srcBits)
dst := math.Float32frombits(dstBits)
var result float32
switch op2 {
case 0x58: result = dst + src
case 0x59: result = dst * src
case 0x5A: // CVTSS2SD - convert single to double
c.xmm[m.reg][0] = math.Float64bits(float64(src))
return nil
case 0x5C: result = dst - src
case 0x5D: result = float32(math.Min(float64(dst), float64(src)))
case 0x5E: result = dst / src
case 0x5F: result = float32(math.Max(float64(dst), float64(src)))
default:
return fmt.Errorf("unhandled F3 0F %02X", op2)
}
c.xmm[m.reg][0] = (c.xmm[m.reg][0] &^ 0xFFFFFFFF) | uint64(math.Float32bits(result))
return nil
} else if pfx.op66 { // 66 prefix: packed double
var src [2]uint64
if m.mod == 3 {
src = c.xmm[m.rm]
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
src[0], _ = c.mem.Read64(addr)
src[1], _ = c.mem.Read64(addr + 8)
}
d := c.xmm[m.reg]
for i := 0; i < 2; i++ {
sv := math.Float64frombits(src[i])
dv := math.Float64frombits(d[i])
var r float64
switch op2 {
case 0x58: r = dv + sv
case 0x59: r = dv * sv
case 0x5C: r = dv - sv
case 0x5D: r = math.Min(dv, sv)
case 0x5E: r = dv / sv
case 0x5F: r = math.Max(dv, sv)
default:
return fmt.Errorf("unhandled 66 0F %02X", op2)
}
c.xmm[m.reg][i] = math.Float64bits(r)
}
return nil
} else { // no prefix: packed single
var src [2]uint64
if m.mod == 3 {
src = c.xmm[m.rm]
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
src[0], _ = c.mem.Read64(addr)
src[1], _ = c.mem.Read64(addr + 8)
}
d := c.xmm[m.reg]
for q := 0; q < 2; q++ {
var rq uint64
for i := 0; i < 2; i++ {
shift := uint(i * 32)
sv := math.Float32frombits(uint32(src[q] >> shift))
dv := math.Float32frombits(uint32(d[q] >> shift))
var r float32
switch op2 {
case 0x58: r = dv + sv
case 0x59: r = dv * sv
case 0x5C: r = dv - sv
case 0x5D: r = float32(math.Min(float64(dv), float64(sv)))
case 0x5E: r = dv / sv
case 0x5F: r = float32(math.Max(float64(dv), float64(sv)))
default:
return fmt.Errorf("unhandled NP 0F %02X", op2)
}
rq |= uint64(math.Float32bits(r)) << shift
}
c.xmm[m.reg][q] = rq
}
return nil
}

// --- CVTSI2SD / CVTSI2SS (0x2A) ---
case 0x2A:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
val, err := c.readRM(m, pfx, size)
if err != nil {
return err
}
if pfx.repne { // F2: CVTSI2SD
var f float64
if size == 8 {
f = float64(int64(val))
} else {
f = float64(int32(val))
}
c.xmm[m.reg][0] = math.Float64bits(f)
} else { // F3: CVTSI2SS
var f float32
if size == 8 {
f = float32(int64(val))
} else {
f = float32(int32(val))
}
c.xmm[m.reg][0] = (c.xmm[m.reg][0] &^ 0xFFFFFFFF) | uint64(math.Float32bits(f))
}
return nil

// --- CVTTSD2SI / CVTTSS2SI (0x2C) ---
case 0x2C:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
if pfx.repne { // F2: CVTTSD2SI
var srcBits uint64
if m.mod == 3 {
srcBits = c.xmm[m.rm][0]
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
srcBits, _ = c.mem.Read64(addr)
}
f := math.Float64frombits(srcBits)
if size == 8 {
c.Regs[m.reg] = uint64(int64(f))
} else {
c.Regs[m.reg] = uint64(uint32(int32(f)))
}
} else { // F3: CVTTSS2SI
var srcBits uint32
if m.mod == 3 {
srcBits = uint32(c.xmm[m.rm][0])
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
v, _ := c.mem.Read32(addr)
srcBits = uint32(v)
}
f := math.Float32frombits(srcBits)
if size == 8 {
c.Regs[m.reg] = uint64(int64(f))
} else {
c.Regs[m.reg] = uint64(uint32(int32(f)))
}
}
return nil

// --- CVTSD2SI / CVTSS2SI (0x2D) --- (rounded, not truncated)
case 0x2D:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
if pfx.repne { // F2: CVTSD2SI
var srcBits uint64
if m.mod == 3 {
srcBits = c.xmm[m.rm][0]
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
srcBits, _ = c.mem.Read64(addr)
}
f := math.Float64frombits(srcBits)
r := math.RoundToEven(f)
if size == 8 {
c.Regs[m.reg] = uint64(int64(r))
} else {
c.Regs[m.reg] = uint64(uint32(int32(r)))
}
} else { // F3: CVTSS2SI
var srcBits uint32
if m.mod == 3 {
srcBits = uint32(c.xmm[m.rm][0])
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
v, _ := c.mem.Read32(addr)
srcBits = uint32(v)
}
f := math.Float32frombits(srcBits)
r := math.RoundToEven(float64(f))
if size == 8 {
c.Regs[m.reg] = uint64(int64(r))
} else {
c.Regs[m.reg] = uint64(uint32(int32(r)))
}
}
return nil

// --- COMISS/COMISD (0x2F) / UCOMISS/UCOMISD (0x2E) ---
case 0x2E, 0x2F:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
c.Rflags &^= flagCF | flagZF | flagPF | flagOF | flagSF
if pfx.op66 || pfx.repne { // COMISD/UCOMISD (66 or F2 prefix)
var srcBits uint64
if m.mod == 3 {
srcBits = c.xmm[m.rm][0]
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
srcBits, _ = c.mem.Read64(addr)
}
a := math.Float64frombits(c.xmm[m.reg][0])
b := math.Float64frombits(srcBits)
if math.IsNaN(a) || math.IsNaN(b) {
c.Rflags |= flagZF | flagPF | flagCF
} else if a < b {
c.Rflags |= flagCF
} else if a == b {
c.Rflags |= flagZF
}
} else { // COMISS/UCOMISS (no prefix or F3)
var srcBits uint32
if m.mod == 3 {
srcBits = uint32(c.xmm[m.rm][0])
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
v, _ := c.mem.Read32(addr)
srcBits = uint32(v)
}
a := math.Float32frombits(uint32(c.xmm[m.reg][0]))
b := math.Float32frombits(srcBits)
if a != a || b != b { // NaN check
c.Rflags |= flagZF | flagPF | flagCF
} else if a < b {
c.Rflags |= flagCF
} else if a == b {
c.Rflags |= flagZF
}
}
return nil

// --- SQRTSD/SQRTSS/SQRTPS/SQRTPD (0x51) ---
case 0x51:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
if pfx.repne { // F2: SQRTSD
var srcBits uint64
if m.mod == 3 {
srcBits = c.xmm[m.rm][0]
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
srcBits, _ = c.mem.Read64(addr)
}
c.xmm[m.reg][0] = math.Float64bits(math.Sqrt(math.Float64frombits(srcBits)))
} else if pfx.repe { // F3: SQRTSS
var srcBits uint32
if m.mod == 3 {
srcBits = uint32(c.xmm[m.rm][0])
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
v, _ := c.mem.Read32(addr)
srcBits = uint32(v)
}
r := float32(math.Sqrt(float64(math.Float32frombits(srcBits))))
c.xmm[m.reg][0] = (c.xmm[m.reg][0] &^ 0xFFFFFFFF) | uint64(math.Float32bits(r))
}
return nil

// --- ANDPS/ANDPD (0x54), ANDNPS/ANDNPD (0x55), ORPS/ORPD (0x56) ---
case 0x54, 0x55, 0x56:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
var src [2]uint64
if m.mod == 3 {
src = c.xmm[m.rm]
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
src[0], _ = c.mem.Read64(addr)
src[1], _ = c.mem.Read64(addr + 8)
}
switch op2 {
case 0x54: // ANDPS/ANDPD
c.xmm[m.reg][0] &= src[0]
c.xmm[m.reg][1] &= src[1]
case 0x55: // ANDNPS/ANDNPD
c.xmm[m.reg][0] = ^c.xmm[m.reg][0] & src[0]
c.xmm[m.reg][1] = ^c.xmm[m.reg][1] & src[1]
case 0x56: // ORPS/ORPD
c.xmm[m.reg][0] |= src[0]
c.xmm[m.reg][1] |= src[1]
}
return nil

// --- PXOR (0xEF) ---
case 0xEF:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
var src [2]uint64
if m.mod == 3 {
src = c.xmm[m.rm]
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
src[0], _ = c.mem.Read64(addr)
src[1], _ = c.mem.Read64(addr + 8)
}
c.xmm[m.reg][0] ^= src[0]
c.xmm[m.reg][1] ^= src[1]
return nil

// --- PAND (0xDB) ---
case 0xDB:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
var src [2]uint64
if m.mod == 3 {
src = c.xmm[m.rm]
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
src[0], _ = c.mem.Read64(addr)
src[1], _ = c.mem.Read64(addr + 8)
}
c.xmm[m.reg][0] &= src[0]
c.xmm[m.reg][1] &= src[1]
return nil

// --- PANDN (0xDF) ---
case 0xDF:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
var src [2]uint64
if m.mod == 3 {
src = c.xmm[m.rm]
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
src[0], _ = c.mem.Read64(addr)
src[1], _ = c.mem.Read64(addr + 8)
}
c.xmm[m.reg][0] = ^c.xmm[m.reg][0] & src[0]
c.xmm[m.reg][1] = ^c.xmm[m.reg][1] & src[1]
return nil

// --- POR (0xEB) ---
case 0xEB:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
var src [2]uint64
if m.mod == 3 {
src = c.xmm[m.rm]
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
src[0], _ = c.mem.Read64(addr)
src[1], _ = c.mem.Read64(addr + 8)
}
c.xmm[m.reg][0] |= src[0]
c.xmm[m.reg][1] |= src[1]
return nil

// --- MFENCE/LFENCE/SFENCE (0xAE) ---
case 0xAE:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
if m.mod == 3 {
// MFENCE (reg=6), LFENCE (reg=5), SFENCE (reg=7) - all no-ops
return nil
}
// LDMXCSR / STMXCSR - ignore
return nil

// --- PREFETCH (0x18) ---
case 0x18:
m, _ := c.decodeModRM(pfx)
if m.mod != 3 {
c.resolveRMAddr(m, pfx) // consume displacement
}
return nil

// --- PUNPCKLBW xmm, xmm/m128 (0x60) ---
case 0x60:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
var src [2]uint64
if m.mod == 3 {
src = c.xmm[m.rm]
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
src[0], _ = c.mem.Read64(addr)
src[1], _ = c.mem.Read64(addr + 8)
}
d := c.xmm[m.reg]
// Interleave low bytes
var lo, hi uint64
for i := 0; i < 8; i++ {
db := (d[0] >> uint(i*8)) & 0xFF
sb := (src[0] >> uint(i*8)) & 0xFF
if i < 4 {
lo |= db << uint(i*16)
lo |= sb << uint(i*16+8)
} else {
j := i - 4
hi |= db << uint(j*16)
hi |= sb << uint(j*16+8)
}
}
c.xmm[m.reg] = [2]uint64{lo, hi}
return nil

// --- PUNPCKLWD xmm, xmm/m128 (0x61) ---
case 0x61:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
var src [2]uint64
if m.mod == 3 {
src = c.xmm[m.rm]
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
src[0], _ = c.mem.Read64(addr)
src[1], _ = c.mem.Read64(addr + 8)
}
d := c.xmm[m.reg]
// Interleave low words
var lo, hi uint64
for i := 0; i < 4; i++ {
dw := (d[0] >> uint(i*16)) & 0xFFFF
sw := (src[0] >> uint(i*16)) & 0xFFFF
if i < 2 {
lo |= dw << uint(i*32)
lo |= sw << uint(i*32+16)
} else {
j := i - 2
hi |= dw << uint(j*32)
hi |= sw << uint(j*32+16)
}
}
c.xmm[m.reg] = [2]uint64{lo, hi}
return nil

// --- PUNPCKLDQ xmm, xmm/m128 (0x62) ---
case 0x62:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
var src [2]uint64
if m.mod == 3 {
src = c.xmm[m.rm]
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
src[0], _ = c.mem.Read64(addr)
src[1], _ = c.mem.Read64(addr + 8)
}
// Interleave low 32-bit doublewords: dst[0..31]=dst[0..31], dst[32..63]=src[0..31],
// dst[64..95]=dst[32..63], dst[96..127]=src[32..63]
d := c.xmm[m.reg]
d0lo := d[0] & 0xFFFFFFFF
d0hi := (d[0] >> 32) & 0xFFFFFFFF
s0lo := src[0] & 0xFFFFFFFF
s0hi := (src[0] >> 32) & 0xFFFFFFFF
c.xmm[m.reg][0] = d0lo | (s0lo << 32)
c.xmm[m.reg][1] = d0hi | (s0hi << 32)
return nil

// --- PUNPCKLQDQ xmm, xmm/m128 (0x6C) ---
case 0x6C:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
var src [2]uint64
if m.mod == 3 {
src = c.xmm[m.rm]
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
src[0], _ = c.mem.Read64(addr)
src[1], _ = c.mem.Read64(addr + 8)
}
// dst[0..63] = dst[0..63], dst[64..127] = src[0..63]
c.xmm[m.reg][1] = src[0]
return nil

// --- PUNPCKHQDQ xmm, xmm/m128 (0x6D) ---
case 0x6D:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
var src [2]uint64
if m.mod == 3 {
src = c.xmm[m.rm]
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
src[0], _ = c.mem.Read64(addr)
src[1], _ = c.mem.Read64(addr + 8)
}
// dst[0..63] = dst[64..127], dst[64..127] = src[64..127]
c.xmm[m.reg][0] = c.xmm[m.reg][1]
c.xmm[m.reg][1] = src[1]
return nil

// --- PSHUFD xmm, xmm/m128, imm8 (0x70) ---
case 0x70:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
var src [2]uint64
if m.mod == 3 {
src = c.xmm[m.rm]
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
src[0], _ = c.mem.Read64(addr)
src[1], _ = c.mem.Read64(addr + 8)
}
order, err := c.fetch8()
if err != nil {
return err
}
// 4 dwords from src, selected by 2-bit fields in order
dwords := [4]uint32{
uint32(src[0]),
uint32(src[0] >> 32),
uint32(src[1]),
uint32(src[1] >> 32),
}
d0 := dwords[order&3]
d1 := dwords[(order>>2)&3]
d2 := dwords[(order>>4)&3]
d3 := dwords[(order>>6)&3]
c.xmm[m.reg][0] = uint64(d0) | uint64(d1)<<32
c.xmm[m.reg][1] = uint64(d2) | uint64(d3)<<32
return nil

// --- PCMPEQB xmm, xmm/m128 (0x74) ---
case 0x74:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
var src [2]uint64
if m.mod == 3 {
src = c.xmm[m.rm]
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
src[0], _ = c.mem.Read64(addr)
src[1], _ = c.mem.Read64(addr + 8)
}
d := c.xmm[m.reg]
var r0, r1 uint64
for i := 0; i < 8; i++ {
shift := uint(i * 8)
if byte(d[0]>>shift) == byte(src[0]>>shift) {
r0 |= 0xFF << shift
}
if byte(d[1]>>shift) == byte(src[1]>>shift) {
r1 |= 0xFF << shift
}
}
c.xmm[m.reg] = [2]uint64{r0, r1}
return nil

// --- PCMPEQD xmm, xmm/m128 (0x76) ---
case 0x76:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
var src [2]uint64
if m.mod == 3 {
src = c.xmm[m.rm]
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
src[0], _ = c.mem.Read64(addr)
src[1], _ = c.mem.Read64(addr + 8)
}
d := c.xmm[m.reg]
var r0, r1 uint64
for i := 0; i < 2; i++ {
shift := uint(i * 32)
if uint32(d[0]>>shift) == uint32(src[0]>>shift) {
r0 |= 0xFFFFFFFF << shift
}
if uint32(d[1]>>shift) == uint32(src[1]>>shift) {
r1 |= 0xFFFFFFFF << shift
}
}
c.xmm[m.reg] = [2]uint64{r0, r1}
return nil

// --- PMOVMSKB r32, xmm (0xD7) ---
case 0xD7:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
x := c.xmm[m.rm]
var mask uint64
for i := 0; i < 8; i++ {
if x[0]>>(uint(i)*8+7)&1 != 0 {
mask |= 1 << uint(i)
}
}
for i := 0; i < 8; i++ {
if x[1]>>(uint(i)*8+7)&1 != 0 {
mask |= 1 << uint(i+8)
}
}
c.writeRegSized(m.reg, 4, mask)
return nil

// --- MOVQ xmm → xmm/m64 (66 0F D6) ---
case 0xD6:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
val := c.xmm[m.reg][0]
if m.mod == 3 {
c.xmm[m.rm] = [2]uint64{val, 0}
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
c.mem.Write64(addr, val)
}
return nil

// --- MOVMSKPS r32, xmm (0x50) ---
case 0x50:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
x := c.xmm[m.rm]
var mask uint64
for i := 0; i < 2; i++ {
if x[0]>>(uint(i)*32+31)&1 != 0 {
mask |= 1 << uint(i)
}
}
for i := 0; i < 2; i++ {
if x[1]>>(uint(i)*32+31)&1 != 0 {
mask |= 1 << uint(i+2)
}
}
c.writeRegSized(m.reg, 4, mask)
return nil

// --- PCMPGTB xmm, xmm/m128 (0x64) ---
case 0x64:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
var src [2]uint64
if m.mod == 3 {
src = c.xmm[m.rm]
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
src[0], _ = c.mem.Read64(addr)
src[1], _ = c.mem.Read64(addr + 8)
}
d := c.xmm[m.reg]
var r0, r1 uint64
for i := 0; i < 8; i++ {
shift := uint(i * 8)
if int8(d[0]>>shift) > int8(src[0]>>shift) {
r0 |= 0xFF << shift
}
if int8(d[1]>>shift) > int8(src[1]>>shift) {
r1 |= 0xFF << shift
}
}
c.xmm[m.reg] = [2]uint64{r0, r1}
return nil

// --- PCMPGTW xmm, xmm/m128 (0x65) ---
case 0x65:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
var src [2]uint64
if m.mod == 3 {
src = c.xmm[m.rm]
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
src[0], _ = c.mem.Read64(addr)
src[1], _ = c.mem.Read64(addr + 8)
}
d := c.xmm[m.reg]
var r0, r1 uint64
for i := 0; i < 4; i++ {
shift := uint(i * 16)
if int16(d[0]>>shift) > int16(src[0]>>shift) {
r0 |= 0xFFFF << shift
}
if int16(d[1]>>shift) > int16(src[1]>>shift) {
r1 |= 0xFFFF << shift
}
}
c.xmm[m.reg] = [2]uint64{r0, r1}
return nil

// --- PCMPGTD xmm, xmm/m128 (0x66) ---
case 0x66:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
var src [2]uint64
if m.mod == 3 {
src = c.xmm[m.rm]
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
src[0], _ = c.mem.Read64(addr)
src[1], _ = c.mem.Read64(addr + 8)
}
d := c.xmm[m.reg]
var r0, r1 uint64
for i := 0; i < 2; i++ {
shift := uint(i * 32)
if int32(d[0]>>shift) > int32(src[0]>>shift) {
r0 |= 0xFFFFFFFF << shift
}
if int32(d[1]>>shift) > int32(src[1]>>shift) {
r1 |= 0xFFFFFFFF << shift
}
}
c.xmm[m.reg] = [2]uint64{r0, r1}
return nil

// --- PUNPCKHDQ xmm, xmm/m128 (0x6A) ---
case 0x6A:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
var src [2]uint64
if m.mod == 3 {
src = c.xmm[m.rm]
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
src[0], _ = c.mem.Read64(addr)
src[1], _ = c.mem.Read64(addr + 8)
}
d := c.xmm[m.reg]
d1lo := d[1] & 0xFFFFFFFF
d1hi := (d[1] >> 32) & 0xFFFFFFFF
s1lo := src[1] & 0xFFFFFFFF
s1hi := (src[1] >> 32) & 0xFFFFFFFF
c.xmm[m.reg][0] = d1lo | (s1lo << 32)
c.xmm[m.reg][1] = d1hi | (s1hi << 32)
return nil

// --- PSRLDQ / PSLLDQ xmm, imm8 (0x73) ---
case 0x73:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
imm, err := c.fetch8()
if err != nil {
return err
}
count := uint(imm)
switch m.reg {
case 3: // PSRLDQ
if count > 15 {
c.xmm[m.rm] = [2]uint64{0, 0}
} else {
shift := count * 8
lo := c.xmm[m.rm][0]
hi := c.xmm[m.rm][1]
if shift >= 64 {
c.xmm[m.rm][0] = hi >> (shift - 64)
c.xmm[m.rm][1] = 0
} else {
c.xmm[m.rm][0] = (lo >> shift) | (hi << (64 - shift))
c.xmm[m.rm][1] = hi >> shift
}
}
case 7: // PSLLDQ
if count > 15 {
c.xmm[m.rm] = [2]uint64{0, 0}
} else {
shift := count * 8
lo := c.xmm[m.rm][0]
hi := c.xmm[m.rm][1]
if shift >= 64 {
c.xmm[m.rm][1] = lo << (shift - 64)
c.xmm[m.rm][0] = 0
} else {
c.xmm[m.rm][1] = (hi << shift) | (lo >> (64 - shift))
c.xmm[m.rm][0] = lo << shift
}
}
default:
return fmt.Errorf("unimplemented 0F 73 /%d at RIP=0x%x", m.reg, startRIP)
}
return nil

// --- PCMPEQW xmm, xmm/m128 (0x75) ---
case 0x75:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
var src [2]uint64
if m.mod == 3 {
src = c.xmm[m.rm]
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
src[0], _ = c.mem.Read64(addr)
src[1], _ = c.mem.Read64(addr + 8)
}
d := c.xmm[m.reg]
var r0, r1 uint64
for i := 0; i < 4; i++ {
shift := uint(i * 16)
if uint16(d[0]>>shift) == uint16(src[0]>>shift) {
r0 |= 0xFFFF << shift
}
if uint16(d[1]>>shift) == uint16(src[1]>>shift) {
r1 |= 0xFFFF << shift
}
}
c.xmm[m.reg] = [2]uint64{r0, r1}
return nil

// --- PSRLQ xmm, xmm/m128 (0xD3) ---
case 0xD3:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
var src [2]uint64
if m.mod == 3 {
src = c.xmm[m.rm]
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
src[0], _ = c.mem.Read64(addr)
src[1], _ = c.mem.Read64(addr + 8)
}
count := src[0]
if count > 63 {
c.xmm[m.reg] = [2]uint64{0, 0}
} else {
c.xmm[m.reg][0] >>= uint(count)
c.xmm[m.reg][1] >>= uint(count)
}
return nil

// --- PADDQ xmm, xmm/m128 (0xD4) ---
case 0xD4:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
var src [2]uint64
if m.mod == 3 {
src = c.xmm[m.rm]
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
src[0], _ = c.mem.Read64(addr)
src[1], _ = c.mem.Read64(addr + 8)
}
c.xmm[m.reg][0] += src[0]
c.xmm[m.reg][1] += src[1]
return nil

// --- PMINUB xmm, xmm/m128 (0xDA) ---
case 0xDA:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
var src [2]uint64
if m.mod == 3 {
src = c.xmm[m.rm]
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
src[0], _ = c.mem.Read64(addr)
src[1], _ = c.mem.Read64(addr + 8)
}
d := c.xmm[m.reg]
var r0, r1 uint64
for i := 0; i < 8; i++ {
shift := uint(i * 8)
db := byte(d[0] >> shift)
sb := byte(src[0] >> shift)
if sb < db {
db = sb
}
r0 |= uint64(db) << shift
db2 := byte(d[1] >> shift)
sb2 := byte(src[1] >> shift)
if sb2 < db2 {
db2 = sb2
}
r1 |= uint64(db2) << shift
}
c.xmm[m.reg] = [2]uint64{r0, r1}
return nil

// --- PMAXUB xmm, xmm/m128 (0xDE) ---
case 0xDE:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
var src [2]uint64
if m.mod == 3 {
src = c.xmm[m.rm]
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
src[0], _ = c.mem.Read64(addr)
src[1], _ = c.mem.Read64(addr + 8)
}
d := c.xmm[m.reg]
var r0, r1 uint64
for i := 0; i < 8; i++ {
shift := uint(i * 8)
db := byte(d[0] >> shift)
sb := byte(src[0] >> shift)
if sb > db {
db = sb
}
r0 |= uint64(db) << shift
db2 := byte(d[1] >> shift)
sb2 := byte(src[1] >> shift)
if sb2 > db2 {
db2 = sb2
}
r1 |= uint64(db2) << shift
}
c.xmm[m.reg] = [2]uint64{r0, r1}
return nil

// --- PSUBD xmm, xmm/m128 (0xFA) ---
case 0xFA:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
var src [2]uint64
if m.mod == 3 {
src = c.xmm[m.rm]
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
src[0], _ = c.mem.Read64(addr)
src[1], _ = c.mem.Read64(addr + 8)
}
d := c.xmm[m.reg]
var r0, r1 uint64
for i := 0; i < 2; i++ {
shift := uint(i * 32)
r0 |= uint64(uint32(d[0]>>shift)-uint32(src[0]>>shift)) << shift
r1 |= uint64(uint32(d[1]>>shift)-uint32(src[1]>>shift)) << shift
}
c.xmm[m.reg] = [2]uint64{r0, r1}
return nil

// --- PSUBQ xmm, xmm/m128 (0xFB) ---
case 0xFB:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
var src [2]uint64
if m.mod == 3 {
src = c.xmm[m.rm]
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
src[0], _ = c.mem.Read64(addr)
src[1], _ = c.mem.Read64(addr + 8)
}
c.xmm[m.reg][0] -= src[0]
c.xmm[m.reg][1] -= src[1]
return nil

// --- PADDD xmm, xmm/m128 (0xFE) ---
case 0xFE:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
var src [2]uint64
if m.mod == 3 {
src = c.xmm[m.rm]
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
src[0], _ = c.mem.Read64(addr)
src[1], _ = c.mem.Read64(addr + 8)
}
d := c.xmm[m.reg]
var r0, r1 uint64
for i := 0; i < 2; i++ {
shift := uint(i * 32)
r0 |= uint64(uint32(d[0]>>shift)+uint32(src[0]>>shift)) << shift
r1 |= uint64(uint32(d[1]>>shift)+uint32(src[1]>>shift)) << shift
}
c.xmm[m.reg] = [2]uint64{r0, r1}
return nil

// --- PSUBB xmm, xmm/m128 (0xF8) ---
case 0xF8:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
var src [2]uint64
if m.mod == 3 {
src = c.xmm[m.rm]
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
src[0], _ = c.mem.Read64(addr)
src[1], _ = c.mem.Read64(addr + 8)
}
d := c.xmm[m.reg]
var r0, r1 uint64
for i := 0; i < 8; i++ {
shift := uint(i * 8)
r0 |= uint64(byte(d[0]>>shift)-byte(src[0]>>shift)) << shift
r1 |= uint64(byte(d[1]>>shift)-byte(src[1]>>shift)) << shift
}
c.xmm[m.reg] = [2]uint64{r0, r1}
return nil

// --- PSUBW xmm, xmm/m128 (0xF9) ---
case 0xF9:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
var src [2]uint64
if m.mod == 3 {
src = c.xmm[m.rm]
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
src[0], _ = c.mem.Read64(addr)
src[1], _ = c.mem.Read64(addr + 8)
}
d := c.xmm[m.reg]
var r0, r1 uint64
for i := 0; i < 4; i++ {
shift := uint(i * 16)
r0 |= uint64(uint16(d[0]>>shift)-uint16(src[0]>>shift)) << shift
r1 |= uint64(uint16(d[1]>>shift)-uint16(src[1]>>shift)) << shift
}
c.xmm[m.reg] = [2]uint64{r0, r1}
return nil

// --- PADDB xmm, xmm/m128 (0xFC) ---
case 0xFC:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
var src [2]uint64
if m.mod == 3 {
src = c.xmm[m.rm]
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
src[0], _ = c.mem.Read64(addr)
src[1], _ = c.mem.Read64(addr + 8)
}
d := c.xmm[m.reg]
var r0, r1 uint64
for i := 0; i < 8; i++ {
shift := uint(i * 8)
r0 |= uint64(byte(d[0]>>shift)+byte(src[0]>>shift)) << shift
r1 |= uint64(byte(d[1]>>shift)+byte(src[1]>>shift)) << shift
}
c.xmm[m.reg] = [2]uint64{r0, r1}
return nil

// --- PADDW xmm, xmm/m128 (0xFD) ---
case 0xFD:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
var src [2]uint64
if m.mod == 3 {
src = c.xmm[m.rm]
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
src[0], _ = c.mem.Read64(addr)
src[1], _ = c.mem.Read64(addr + 8)
}
d := c.xmm[m.reg]
var r0, r1 uint64
for i := 0; i < 4; i++ {
shift := uint(i * 16)
r0 |= uint64(uint16(d[0]>>shift)+uint16(src[0]>>shift)) << shift
r1 |= uint64(uint16(d[1]>>shift)+uint16(src[1]>>shift)) << shift
}
c.xmm[m.reg] = [2]uint64{r0, r1}
return nil

// --- UNPCKLPS/UNPCKLPD (0x14), UNPCKHPS/UNPCKHPD (0x15) ---
case 0x14:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
var src [2]uint64
if m.mod == 3 {
src = c.xmm[m.rm]
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
src[0], _ = c.mem.Read64(addr)
src[1], _ = c.mem.Read64(addr + 8)
}
if pfx.op66 { // UNPCKLPD
c.xmm[m.reg] = [2]uint64{c.xmm[m.reg][0], src[0]}
} else { // UNPCKLPS
d := c.xmm[m.reg]
lo0 := (d[0] & 0xFFFFFFFF) | (src[0]&0xFFFFFFFF)<<32
lo1 := (d[0] >> 32) | (src[0]&0xFFFFFFFF00000000)
c.xmm[m.reg] = [2]uint64{lo0, lo1}
}
return nil

case 0x15:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
var src [2]uint64
if m.mod == 3 {
src = c.xmm[m.rm]
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
src[0], _ = c.mem.Read64(addr)
src[1], _ = c.mem.Read64(addr + 8)
}
if pfx.op66 { // UNPCKHPD
c.xmm[m.reg] = [2]uint64{c.xmm[m.reg][1], src[1]}
} else { // UNPCKHPS
d := c.xmm[m.reg]
hi0 := (d[1] & 0xFFFFFFFF) | (src[1]&0xFFFFFFFF)<<32
hi1 := (d[1] >> 32) | (src[1]&0xFFFFFFFF00000000)
c.xmm[m.reg] = [2]uint64{hi0, hi1}
}
return nil

// --- SHUFPS/SHUFPD (0xC6) ---
case 0xC6:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
var src [2]uint64
if m.mod == 3 {
src = c.xmm[m.rm]
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
src[0], _ = c.mem.Read64(addr)
src[1], _ = c.mem.Read64(addr + 8)
}
imm, err := c.fetch8()
if err != nil {
return err
}
if pfx.op66 { // SHUFPD
d := c.xmm[m.reg]
var r [2]uint64
if imm&1 == 0 {
r[0] = d[0]
} else {
r[0] = d[1]
}
if imm&2 == 0 {
r[1] = src[0]
} else {
r[1] = src[1]
}
c.xmm[m.reg] = r
} else { // SHUFPS
d := c.xmm[m.reg]
getFloat := func(v [2]uint64, idx byte) uint32 {
switch idx & 3 {
case 0:
return uint32(v[0])
case 1:
return uint32(v[0] >> 32)
case 2:
return uint32(v[1])
default:
return uint32(v[1] >> 32)
}
}
r0 := uint64(getFloat(d, imm)) | uint64(getFloat(d, imm>>2))<<32
r1 := uint64(getFloat(src, imm>>4)) | uint64(getFloat(src, imm>>6))<<32
c.xmm[m.reg] = [2]uint64{r0, r1}
}
return nil

// --- PSHUFD (66 0F 70) / PSHUFHW (F3 0F 70) / PSHUFLW (F2 0F 70) ---
// (already handled 0x70 above, adding missing shuffle variants)

// --- CVTDQ2PS (0F 5B) / CVTPS2DQ (66 0F 5B) / CVTTPS2DQ (F3 0F 5B) ---
case 0x5B:
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
var src [2]uint64
if m.mod == 3 {
src = c.xmm[m.rm]
} else {
addr, _, err := c.resolveRMAddr(m, pfx)
if err != nil {
return err
}
src[0], _ = c.mem.Read64(addr)
src[1], _ = c.mem.Read64(addr + 8)
}
if pfx.op66 { // CVTPS2DQ
var r [2]uint64
for i := 0; i < 2; i++ {
lo := math.Float32frombits(uint32(src[i]))
hi := math.Float32frombits(uint32(src[i] >> 32))
r[i] = uint64(uint32(int32(lo))) | uint64(uint32(int32(hi)))<<32
}
c.xmm[m.reg] = r
} else { // CVTDQ2PS
var r [2]uint64
for i := 0; i < 2; i++ {
lo := float32(int32(src[i]))
hi := float32(int32(src[i] >> 32))
r[i] = uint64(math.Float32bits(lo)) | uint64(math.Float32bits(hi))<<32
}
c.xmm[m.reg] = r
}
return nil

default:
return fmt.Errorf("unimplemented 0F opcode 0x0F 0x%02X at RIP=0x%x", op2, startRIP)
}
}

// =========================================================================
// ALU helpers
// =========================================================================

type aluOp int

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

func (c *CPU) doALU(op aluOp, a, b uint64, size int) (result uint64, writeBack bool) {
switch op {
case aluADD:
result = a + b
c.setAddFlags(a, b, result, size)
return result, true
case aluOR:
result = a | b
c.setArithFlags(result, size)
c.Rflags &^= flagCF | flagOF
return result, true
case aluADC:
cf := (c.Rflags & flagCF) >> 0
result = a + b + cf
c.setAddFlags(a, b+cf, result, size)
return result, true
case aluSBB:
cf := (c.Rflags & flagCF) >> 0
result = a - b - cf
c.setSubFlags(a, b+cf, result, size)
return result, true
case aluAND:
result = a & b
c.setArithFlags(result, size)
c.Rflags &^= flagCF | flagOF
return result, true
case aluSUB:
result = a - b
c.setSubFlags(a, b, result, size)
return result, true
case aluXOR:
result = a ^ b
c.setArithFlags(result, size)
c.Rflags &^= flagCF | flagOF
return result, true
case aluCMP:
result = a - b
c.setSubFlags(a, b, result, size)
return 0, false
}
return 0, false
}

func (c *CPU) execALU_rm_r(pfx *prefixState, size int, op aluOp) error {
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
dst, err := c.readRM(m, pfx, size)
if err != nil {
return err
}
var src uint64
if size == 1 {
src = c.readByteReg(m.reg, pfx.hasREX)
} else {
src = c.readRegSized(m.reg, size)
}
result, wb := c.doALU(op, dst, src, size)
if wb {
return c.writeRM(m, pfx, size, result)
}
return nil
}

func (c *CPU) execALU_r_rm(pfx *prefixState, size int, op aluOp) error {
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
src, err := c.readRM(m, pfx, size)
if err != nil {
return err
}
var dst uint64
if size == 1 {
dst = c.readByteReg(m.reg, pfx.hasREX)
} else {
dst = c.readRegSized(m.reg, size)
}
result, wb := c.doALU(op, dst, src, size)
if wb {
if size == 1 {
c.writeByteReg(m.reg, pfx.hasREX, result)
} else {
c.writeRegSized(m.reg, size, result)
}
}
return nil
}

// Group 1: add/or/adc/sbb/and/sub/xor/cmp r/m, imm
func (c *CPU) execGroup1(op byte, pfx *prefixState, size int) error {
s := size
if op == 0x80 {
s = 1
}
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
dst, err := c.readRM(m, pfx, s)
if err != nil {
return err
}

var immSize int
switch op {
case 0x80, 0x82:
immSize = 1
case 0x81:
immSize = s
if immSize == 8 {
immSize = 4
}
case 0x83:
immSize = 1
}
imm, err := c.fetchImm(immSize)
if err != nil {
return err
}

aluOps := []aluOp{aluADD, aluOR, aluADC, aluSBB, aluAND, aluSUB, aluXOR, aluCMP}
result, wb := c.doALU(aluOps[m.reg], dst, uint64(imm), s)
if wb {
return c.writeRM(m, pfx, s, result)
}
return nil
}

// TEST r/m, r
func (c *CPU) execTEST(pfx *prefixState, size int) error {
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
dst, err := c.readRM(m, pfx, size)
if err != nil {
return err
}
var src uint64
if size == 1 {
src = c.readByteReg(m.reg, pfx.hasREX)
} else {
src = c.readRegSized(m.reg, size)
}
r := dst & src
c.setArithFlags(r, size)
c.Rflags &^= flagCF | flagOF
return nil
}

// XCHG r/m, r
func (c *CPU) execXCHG(pfx *prefixState, size int) error {
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
a, err := c.readRM(m, pfx, size)
if err != nil {
return err
}
if size == 1 {
b := c.readByteReg(m.reg, pfx.hasREX)
c.writeByteReg(m.reg, pfx.hasREX, a)
return c.writeRM(m, pfx, size, b)
}
b := c.readRegSized(m.reg, size)
c.writeRegSized(m.reg, size, a)
return c.writeRM(m, pfx, size, b)
}

// MOV r/m, r
func (c *CPU) execMOV_rm_r(pfx *prefixState, size int) error {
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
var src uint64
if size == 1 {
src = c.readByteReg(m.reg, pfx.hasREX)
} else {
src = c.readRegSized(m.reg, size)
}
return c.writeRM(m, pfx, size, src)
}

// MOV r, r/m
func (c *CPU) execMOV_r_rm(pfx *prefixState, size int) error {
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
val, err := c.readRM(m, pfx, size)
if err != nil {
return err
}
if size == 1 {
c.writeByteReg(m.reg, pfx.hasREX, val)
} else {
c.writeRegSized(m.reg, size, val)
}
return nil
}

// Shift group (C0/C1/D0/D1/D2/D3): ROL/ROR/RCL/RCR/SHL/SHR/SAL/SAR
func (c *CPU) execShift(pfx *prefixState, size int, countMode int) error {
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
val, err := c.readRM(m, pfx, size)
if err != nil {
return err
}

var count uint64
switch countMode {
case -1: // imm8
imm, err := c.fetch8()
if err != nil {
return err
}
count = uint64(imm)
case 1: // count = 1
count = 1
case -2: // count = CL
count = c.Regs[RCX] & 0x3F
}
if count == 0 {
return nil
}

nbits := uint64(size * 8)
count &= nbits - 1
if count == 0 {
return nil
}

var result uint64
switch m.reg {
case 0: // ROL
result = (val << count) | (val >> (nbits - count))
case 1: // ROR
result = (val >> count) | (val << (nbits - count))
case 4: // SHL/SAL
result = val << count
c.setArithFlags(result, size)
if val>>(nbits-count)&1 != 0 {
c.Rflags |= flagCF
} else {
c.Rflags &^= flagCF
}
case 5: // SHR
c.Rflags &^= flagCF
if val>>(count-1)&1 != 0 {
c.Rflags |= flagCF
}
result = val >> count
c.setArithFlags(result, size)
case 7: // SAR
c.Rflags &^= flagCF
if val>>(count-1)&1 != 0 {
c.Rflags |= flagCF
}
switch size {
case 1:
result = uint64(int8(val) >> count)
case 2:
result = uint64(int16(val) >> count)
case 4:
result = uint64(int32(val) >> count)
case 8:
result = uint64(int64(val) >> count)
}
c.setArithFlags(result, size)
default:
return fmt.Errorf("unimplemented shift op %d", m.reg)
}

return c.writeRM(m, pfx, size, result)
}

// Group 3: TEST/NOT/NEG/MUL/IMUL/DIV/IDIV (0xF6/0xF7)
func (c *CPU) execGroup3(pfx *prefixState, size int) error {
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
val, err := c.readRM(m, pfx, size)
if err != nil {
return err
}

switch m.reg {
case 0, 1: // TEST r/m, imm
immSz := size
if immSz == 8 {
immSz = 4
}
if size == 1 {
immSz = 1
}
imm, err := c.fetchImm(immSz)
if err != nil {
return err
}
r := val & uint64(imm)
c.setArithFlags(r, size)
c.Rflags &^= flagCF | flagOF
return nil

case 2: // NOT
return c.writeRM(m, pfx, size, ^val)

case 3: // NEG
result := -val
c.Rflags &^= flagCF
if val != 0 {
c.Rflags |= flagCF
}
c.setArithFlags(result, size)
return c.writeRM(m, pfx, size, result)

case 4: // MUL (unsigned)
a := c.readRegSized(RAX, size)
switch size {
case 1:
result := uint16(uint8(a)) * uint16(uint8(val))
c.Regs[RAX] = (c.Regs[RAX] & ^uint64(0xFFFF)) | uint64(result)
case 2:
result := uint32(uint16(a)) * uint32(uint16(val))
c.writeRegSized(RAX, 2, uint64(result&0xFFFF))
c.writeRegSized(RDX, 2, uint64(result>>16))
case 4:
result := uint64(uint32(a)) * uint64(uint32(val))
c.writeRegSized(RAX, 4, result&0xFFFFFFFF)
c.writeRegSized(RDX, 4, result>>32)
case 8:
hi, lo := bits.Mul64(a, val)
c.Regs[RAX] = lo
c.Regs[RDX] = hi
}
return nil

case 5: // IMUL (single operand)
a := c.readRegSized(RAX, size)
switch size {
case 1:
result := int16(int8(a)) * int16(int8(val))
c.Regs[RAX] = (c.Regs[RAX] & ^uint64(0xFFFF)) | uint64(uint16(result))
case 2:
result := int32(int16(a)) * int32(int16(val))
c.writeRegSized(RAX, 2, uint64(uint16(result)))
c.writeRegSized(RDX, 2, uint64(uint16(result>>16)))
case 4:
result := int64(int32(a)) * int64(int32(val))
c.writeRegSized(RAX, 4, uint64(uint32(result)))
c.writeRegSized(RDX, 4, uint64(uint32(result>>32)))
case 8:
// Signed 128-bit multiply
hi, lo := imul128(int64(a), int64(val))
c.Regs[RAX] = lo
c.Regs[RDX] = hi
}
return nil

case 6: // DIV (unsigned)
a := c.readRegSized(RAX, size)
if val == 0 {
return fmt.Errorf("division by zero at RIP=0x%x", c.RIP)
}
switch size {
case 1:
ax := c.Regs[RAX] & 0xFFFF
c.writeRegSized(RAX, 1, ax/val)
c.Regs[RAX] = (c.Regs[RAX] & ^uint64(0xFF00)) | ((ax % val) << 8)
case 2:
dividend := (c.readRegSized(RDX, 2) << 16) | a
c.writeRegSized(RAX, 2, dividend/val)
c.writeRegSized(RDX, 2, dividend%val)
case 4:
dividend := (c.readRegSized(RDX, 4) << 32) | a
c.writeRegSized(RAX, 4, dividend/val)
c.writeRegSized(RDX, 4, dividend%val)
case 8:
// 128÷64 division
if c.Regs[RDX] == 0 {
c.Regs[RAX] = a / val
c.Regs[RDX] = a % val
} else {
q, r := div128(c.Regs[RDX], a, val)
c.Regs[RAX] = q
c.Regs[RDX] = r
}
}
return nil

case 7: // IDIV (signed)
if val == 0 {
return fmt.Errorf("division by zero at RIP=0x%x", c.RIP)
}
switch size {
case 1:
ax := int16(c.Regs[RAX] & 0xFFFF)
d := int8(val)
c.writeRegSized(RAX, 1, uint64(int8(ax/int16(d))))
c.Regs[RAX] = (c.Regs[RAX] & ^uint64(0xFF00)) | (uint64(uint8(int8(ax%int16(d)))) << 8)
case 4:
dividend := int64(int32(c.readRegSized(RDX, 4)))<<32 | int64(c.readRegSized(RAX, 4))
divisor := int64(int32(val))
c.writeRegSized(RAX, 4, uint64(int32(dividend/divisor)))
c.writeRegSized(RDX, 4, uint64(int32(dividend%divisor)))
case 8:
// Simplified: assume RDX is sign extension of RAX
dividend := int64(c.Regs[RAX])
divisor := int64(val)
c.Regs[RAX] = uint64(dividend / divisor)
c.Regs[RDX] = uint64(dividend % divisor)
}
return nil
}
return fmt.Errorf("unimplemented group 3 op %d", m.reg)
}

// Group 4/5: INC/DEC/CALL/JMP/PUSH (0xFE, 0xFF)
func (c *CPU) execGroup45(pfx *prefixState, size int) error {
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}

switch m.reg {
case 0: // INC
val, err := c.readRM(m, pfx, size)
if err != nil {
return err
}
result := val + 1
saveCF := c.Rflags & flagCF
c.setAddFlags(val, 1, result, size)
c.Rflags = (c.Rflags & ^uint64(flagCF)) | saveCF
return c.writeRM(m, pfx, size, result)

case 1: // DEC
val, err := c.readRM(m, pfx, size)
if err != nil {
return err
}
result := val - 1
saveCF := c.Rflags & flagCF
c.setSubFlags(val, 1, result, size)
c.Rflags = (c.Rflags & ^uint64(flagCF)) | saveCF
return c.writeRM(m, pfx, size, result)

case 2: // CALL r/m64
val, err := c.readRM(m, pfx, 8)
if err != nil {
return err
}
if err := c.push64(c.RIP); err != nil {
return err
}
c.RIP = val
return nil

case 4: // JMP r/m64
val, err := c.readRM(m, pfx, 8)
if err != nil {
return err
}
c.RIP = val
return nil

case 6: // PUSH r/m
val, err := c.readRM(m, pfx, 8)
if err != nil {
return err
}
return c.push64(val)
}

return fmt.Errorf("unimplemented group 5 op %d", m.reg)
}

// XADD
func (c *CPU) execXADD(pfx *prefixState, size int) error {
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
dst, err := c.readRM(m, pfx, size)
if err != nil {
return err
}
var src uint64
if size == 1 {
src = c.readByteReg(m.reg, pfx.hasREX)
} else {
src = c.readRegSized(m.reg, size)
}
sum := dst + src
c.setAddFlags(dst, src, sum, size)
if size == 1 {
c.writeByteReg(m.reg, pfx.hasREX, dst)
} else {
c.writeRegSized(m.reg, size, dst)
}
return c.writeRM(m, pfx, size, sum)
}

// CMPXCHG
func (c *CPU) execCMPXCHG(pfx *prefixState, size int) error {
m, err := c.decodeModRM(pfx)
if err != nil {
return err
}
dst, err := c.readRM(m, pfx, size)
if err != nil {
return err
}
acc := c.readRegSized(RAX, size)
if acc == dst {
c.Rflags |= flagZF
var src uint64
if size == 1 {
src = c.readByteReg(m.reg, pfx.hasREX)
} else {
src = c.readRegSized(m.reg, size)
}
return c.writeRM(m, pfx, size, src)
}
c.Rflags &^= flagZF
c.writeRegSized(RAX, size, dst)
return nil
}

// =========================================================================
// String operations (with REP prefix support)
// =========================================================================

func (c *CPU) execMOVS(pfx *prefixState, size int) error {
for {
v, err := c.readMem(c.Regs[RSI], size)
if err != nil {
return err
}
if err := c.writeMem(c.Regs[RDI], size, v); err != nil {
return err
}
delta := uint64(size)
if c.Rflags&flagDF != 0 {
c.Regs[RSI] -= delta
c.Regs[RDI] -= delta
} else {
c.Regs[RSI] += delta
c.Regs[RDI] += delta
}
if !pfx.repe && !pfx.repne {
return nil
}
c.Regs[RCX]--
if c.Regs[RCX] == 0 {
return nil
}
}
}

func (c *CPU) execSTOS(pfx *prefixState, size int) error {
for {
if err := c.writeMem(c.Regs[RDI], size, c.readRegSized(RAX, size)); err != nil {
return err
}
delta := uint64(size)
if c.Rflags&flagDF != 0 {
c.Regs[RDI] -= delta
} else {
c.Regs[RDI] += delta
}
if !pfx.repe && !pfx.repne {
return nil
}
c.Regs[RCX]--
if c.Regs[RCX] == 0 {
return nil
}
}
}

func (c *CPU) execLODS(pfx *prefixState, size int) error {
v, err := c.readMem(c.Regs[RSI], size)
if err != nil {
return err
}
c.writeRegSized(RAX, size, v)
delta := uint64(size)
if c.Rflags&flagDF != 0 {
c.Regs[RSI] -= delta
} else {
c.Regs[RSI] += delta
}
return nil
}

func (c *CPU) execCMPS(pfx *prefixState, size int) error {
for {
a, err := c.readMem(c.Regs[RSI], size)
if err != nil {
return err
}
b, err := c.readMem(c.Regs[RDI], size)
if err != nil {
return err
}
c.setSubFlags(a, b, a-b, size)
delta := uint64(size)
if c.Rflags&flagDF != 0 {
c.Regs[RSI] -= delta
c.Regs[RDI] -= delta
} else {
c.Regs[RSI] += delta
c.Regs[RDI] += delta
}
if pfx.repe {
c.Regs[RCX]--
if c.Regs[RCX] == 0 || c.Rflags&flagZF == 0 {
return nil
}
continue
}
if pfx.repne {
c.Regs[RCX]--
if c.Regs[RCX] == 0 || c.Rflags&flagZF != 0 {
return nil
}
continue
}
return nil
}
}

func (c *CPU) execSCAS(pfx *prefixState, size int) error {
for {
b, err := c.readMem(c.Regs[RDI], size)
if err != nil {
return err
}
a := c.readRegSized(RAX, size)
c.setSubFlags(a, b, a-b, size)
delta := uint64(size)
if c.Rflags&flagDF != 0 {
c.Regs[RDI] -= delta
} else {
c.Regs[RDI] += delta
}
if pfx.repe {
c.Regs[RCX]--
if c.Regs[RCX] == 0 || c.Rflags&flagZF == 0 {
return nil
}
continue
}
if pfx.repne {
c.Regs[RCX]--
if c.Regs[RCX] == 0 || c.Rflags&flagZF != 0 {
return nil
}
continue
}
return nil
}
}

// =========================================================================
// 128-bit multiply / divide helpers
// =========================================================================

func imul128(a, b int64) (hi, lo uint64) {
neg := (a < 0) != (b < 0)
ua, ub := uint64(a), uint64(b)
if a < 0 {
ua = uint64(-a)
}
if b < 0 {
ub = uint64(-b)
}
hi, lo = bits.Mul64(ua, ub)
if neg {
lo = ^lo
hi = ^hi
lo++
if lo == 0 {
hi++
}
}
return
}

func div128(hi, lo, divisor uint64) (q, r uint64) {
if hi == 0 {
return lo / divisor, lo % divisor
}
// Slow but correct bit-by-bit division
var remainder uint64
for i := 127; i >= 0; i-- {
remainder <<= 1
if i >= 64 {
remainder |= (hi >> (i - 64)) & 1
} else {
remainder |= (lo >> i) & 1
}
if remainder >= divisor {
remainder -= divisor
if i >= 64 {
q |= 0 // quotient > 64 bits, overflow
} else {
q |= 1 << i
}
}
}
return q, remainder
}

// Ensure imports are used.
var _ = math.Float64frombits

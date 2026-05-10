package jit

import (
	"unsafe"
)

// NativeEnv is the register file shared between Go and generated code.
// Generated code receives its address in RDI and addresses every field by
// fixed displacement, so the layout below is ABI: do not reorder.
type NativeEnv struct {
	Regs    [16]uint64 // +0    guest GPRs, RAX..R15 in interpreter order
	Rflags  uint64     // +128
	RIP     uint64     // +136
	Flat    uintptr    // +144  host base of guest flat memory (0 if disabled)
	Status  uint64     // +152  0 = ok, 1 = fall back to interpreter at RIP
	Perm    uintptr    // +160  base of the per-page permission bitmap
	FPUST   *[8]float64
	FPUTop  *int
	FPUTW   *uint16
	Retired uint64
}

const (
	envRegs    = int(unsafe.Offsetof(NativeEnv{}.Regs))
	envRflags  = int(unsafe.Offsetof(NativeEnv{}.Rflags))
	envRIP     = int(unsafe.Offsetof(NativeEnv{}.RIP))
	envFlat    = int(unsafe.Offsetof(NativeEnv{}.Flat))
	envStatus  = int(unsafe.Offsetof(NativeEnv{}.Status))
	envPerm    = int(unsafe.Offsetof(NativeEnv{}.Perm))
	envFPUST   = int(unsafe.Offsetof(NativeEnv{}.FPUST))
	envFPUTop  = int(unsafe.Offsetof(NativeEnv{}.FPUTop))
	envFPUTW   = int(unsafe.Offsetof(NativeEnv{}.FPUTW))
	envRetired = int(unsafe.Offsetof(NativeEnv{}.Retired))
)

// guest page permission bits mirrored from pkg/mmu (PermRead=1, PermWrite=2).
const (
	permRead    = 1
	permWrite   = 2
	permExecute = 4
)

// enterNative jumps into generated code with env in RDI.
// Implemented in native_amd64.s.
//
//go:noescape
func enterNative(code uintptr, env *NativeEnv)

func nativeSliceAddr(b []byte) unsafe.Pointer {
	return unsafe.Pointer(unsafe.SliceData(b))
}

// asm is a minimal x86-64 emitter for the block compiler. Generated code
// follows a strict contract: RDI holds *NativeEnv and is preserved; only
// caller-saved registers are clobbered; stack use is bounded (no calls).
type asm struct {
	buf []byte
}

func (a *asm) db(b ...byte) { a.buf = append(a.buf, b...) }

func (a *asm) d32(v uint32) {
	a.db(byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

func (a *asm) d64(v uint64) {
	a.d32(uint32(v))
	a.d32(uint32(v >> 32))
}

// movRAXImm64: mov rax, imm64
func (a *asm) movRAXImm64(v uint64) { a.db(0x48, 0xB8); a.d64(v) }

// loadReg: mov rax, [rdi + envRegs + 8*idx]
func (a *asm) loadReg(idx int) { a.db(0x48, 0x8B, 0x87); a.d32(uint32(envRegs + 8*idx)) }

// loadRegRCX: mov rcx, [rdi + envRegs + 8*idx]
func (a *asm) loadRegRCX(idx int) { a.db(0x48, 0x8B, 0x8F); a.d32(uint32(envRegs + 8*idx)) }

// storeReg: mov [rdi + envRegs + 8*idx], rax
func (a *asm) storeReg(idx int) { a.db(0x48, 0x89, 0x87); a.d32(uint32(envRegs + 8*idx)) }

// storeRIP: mov qword [rdi + envRIP], imm32-sign-extended via rax
func (a *asm) storeRIPImm(v uint64) {
	a.movRAXImm64(v)
	a.db(0x48, 0x89, 0x87)
	a.d32(uint32(envRIP))
}

// saveFlags: pushfq; pop rdx; mov [rdi+envRflags], rdx (RDX as scratch so
// the ALU result in RAX survives)
func (a *asm) saveFlags() {
	a.db(0x9C, 0x5A, 0x48, 0x89, 0x97)
	a.d32(uint32(envRflags))
}

// loadFlags: mov rdx, [rdi+envRflags]; push rdx; popfq
func (a *asm) loadFlags() {
	a.db(0x48, 0x8B, 0x97)
	a.d32(uint32(envRflags))
	a.db(0x52, 0x9D)
}

func (a *asm) ret() { a.db(0xC3) }

// storeStatus: mov rax, imm; mov [rdi+envStatus], rax
func (a *asm) storeStatus(v uint64) {
	a.movRAXImm64(v)
	a.db(0x48, 0x89, 0x87)
	a.d32(uint32(envStatus))
}

// aluRAXRCX emits "op rax, rcx" for the given guest ALU op, matching the
// closure backend's semantics for 64-bit and 32-bit operand sizes.
// Returns false for ops the native slice does not support yet.
func (a *asm) aluRAXRCX(op aluOp, size int) bool {
	var opcode byte
	switch op {
	case aluADD:
		opcode = 0x01 // add r/m, r
	case aluSUB:
		opcode = 0x29
	case aluAND:
		opcode = 0x21
	case aluOR:
		opcode = 0x09
	case aluXOR:
		opcode = 0x31
	case aluCMP:
		opcode = 0x39
	default:
		return false
	}
	switch size {
	case 8:
		a.db(0x48, opcode, 0xC8) // op rax, rcx
	case 4:
		a.db(opcode, 0xC8) // 32-bit form zero-extends, like the interpreter
	default:
		return false
	}
	return true
}

// aluRAXImm32 emits "op rax, imm32" (sign-extended by the CPU for the
// 64-bit form, exactly like the guest instruction the decoder captured).
func (a *asm) aluRAXImm32(op aluOp, size int, imm int64) bool {
	var ext byte
	switch op {
	case aluADD:
		ext = 0
	case aluOR:
		ext = 1
	case aluAND:
		ext = 4
	case aluSUB:
		ext = 5
	case aluXOR:
		ext = 6
	case aluCMP:
		ext = 7
	default:
		return false
	}
	if imm != int64(int32(imm)) {
		return false
	}
	// ModRM: mod=11, reg=ext (the /digit), rm=000 (rax).
	modrm := 0xC0 | (ext << 3)
	switch size {
	case 8:
		a.db(0x48, 0x81, modrm)
	case 4:
		a.db(0x81, modrm)
	default:
		return false
	}
	a.d32(uint32(int32(imm)))
	return true
}

// jccRIP emits: load guest flags, then conditionally store target or
// fallthrough into env.RIP using the native Jcc with the same condition
// code (guest and host share the flag layout).
func (a *asm) jccRIP(cc condCode, target, next uint64) {
	a.loadFlags()
	// mov rax, target ; mov rcx, next ; cmovNcc rax, rcx ; store RIP
	a.movRAXImm64(target)
	a.db(0x48, 0xB9)
	a.d64(next)
	// CMOVcc rax, rcx with the INVERTED condition picks `next` when the
	// guest condition is false: 0F 4x /r where x = cc^1.
	a.db(0x48, 0x0F, 0x40|(byte(cc)^1), 0xC1)
	a.db(0x48, 0x89, 0x87)
	a.d32(uint32(envRIP))
}

// memAddrR11 computes a Mode32 effective address in R11.
func (a *asm) memAddrR11(in *insn) bool {
	if in.useRIP {
		return false
	}
	if in.memBase >= 0 {
		// mov r11d, [rdi + regs + 8*base]
		a.db(0x44, 0x8B, 0x9F)
		a.d32(uint32(envRegs + 8*in.memBase))
	} else {
		// xor r11d, r11d
		a.db(0x45, 0x31, 0xDB)
	}
	if in.memIdx >= 0 {
		// mov eax, [rdi + regs + 8*index]
		a.db(0x8B, 0x87)
		a.d32(uint32(envRegs + 8*in.memIdx))
		switch in.memScale {
		case 1:
		case 2:
			a.db(0xD1, 0xE0)
		case 4:
			a.db(0xC1, 0xE0, 0x02)
		case 8:
			a.db(0xC1, 0xE0, 0x03)
		default:
			return false
		}
		// add r11d, eax
		a.db(0x41, 0x01, 0xC3)
	}
	if in.memDisp != 0 {
		if in.memDisp != int64(int32(in.memDisp)) {
			return false
		}
		// add r11d, imm32
		a.db(0x41, 0x81, 0xC3)
		a.d32(uint32(int32(in.memDisp)))
	}
	return true
}

func (a *asm) branchOverFault(opcode byte, fault []byte) {
	a.db(opcode, byte(len(fault)))
	a.buf = append(a.buf, fault...)
}

func (a *asm) permCheckPage(bit, forbidden byte, fault []byte) {
	a.db(0x44, 0x89, 0xD8)
	a.db(0xC1, 0xE8, 0x0C)
	a.db(0x48, 0x8B, 0x97)
	a.d32(uint32(envPerm))
	a.db(0x0F, 0xB6, 0x0C, 0x02)
	a.db(0xF6, 0xC1, bit)
	a.branchOverFault(0x75, fault)
	if forbidden != 0 {
		a.db(0xF6, 0xC1, forbidden)
		a.branchOverFault(0x74, fault)
	}
}

// permCheckRange validates every page touched by a Mode32 flat-memory access.
func (a *asm) permCheckRange(bit, forbidden byte, size int, faultRIP uint64, retired int) {
	fault := a.faultEpilogue(faultRIP, retired)
	a.permCheckPage(bit, forbidden, fault)
	if size <= 1 {
		return
	}
	// add r11d, size-1; carry means the access crosses the 4GiB boundary.
	a.db(0x41, 0x83, 0xC3, byte(size-1))
	a.branchOverFault(0x73, fault)
	a.permCheckPage(bit, forbidden, fault)
	// sub r11d, size-1
	a.db(0x41, 0x83, 0xEB, byte(size-1))
}

// faultEpilogue returns code that records a fallback at faultRIP and returns
// to the caller (RIP already reflects the faulting instruction).
func (a *asm) faultEpilogue(faultRIP uint64, retired int) []byte {
	e := &asm{}
	e.storeRIPImm(faultRIP)
	e.storeStatus(1)
	e.movRAXImm64(uint64(retired))
	e.db(0x48, 0x89, 0x87)
	e.d32(uint32(envRetired))
	e.ret()
	return e.buf
}

// flatBaseToRDX: mov rdx, [rdi + envFlat]
func (a *asm) flatBaseToRDX() { a.db(0x48, 0x8B, 0x97); a.d32(uint32(envFlat)) }

func (a *asm) loadMMXValue(index int) {
	a.db(0x48, 0x8B, 0x97)
	a.d32(uint32(envFPUST))
	a.db(0x48, 0x8B, 0x82)
	a.d32(uint32(index * 8))
}

func (a *asm) loadMMX(index int) {
	a.loadMMXValue(index)
	a.markMMX()
}

func (a *asm) storeMMX(index int) {
	a.db(0x48, 0x8B, 0x97)
	a.d32(uint32(envFPUST))
	a.db(0x48, 0x89, 0x82)
	a.d32(uint32(index * 8))
	a.markMMX()
}

func (a *asm) markMMX() {
	a.db(0x48, 0x8B, 0x97)
	a.d32(uint32(envFPUTop))
	a.db(0x48, 0xC7, 0x02)
	a.d32(0)
	a.db(0x48, 0x8B, 0x97)
	a.d32(uint32(envFPUTW))
	a.db(0x66, 0xC7, 0x02, 0x00, 0x00)
}

func (a *asm) emms() {
	a.db(0x48, 0x8B, 0x97)
	a.d32(uint32(envFPUTW))
	a.db(0x66, 0xC7, 0x02, 0xFF, 0xFF)
}

// compileNative translates a decoded block into machine code, returning the
// entry point and the number of guest instructions it retires.
func (c *Cache) compileNative(insns []insn) (uintptr, int, bool, bool) {
	if c.exec == nil {
		return 0, 0, false, false
	}
	a := &asm{}
	retired := 0
	usesMMX := false
	usesMemory := false
	finish := func() (uintptr, int, bool, bool) {
		entry := c.exec.place(a.buf)
		if entry == 0 {
			return 0, 0, false, false
		}
		if c.exec.seal() != nil {
			return 0, 0, false, false
		}
		return entry, retired, usesMMX, usesMemory
	}
	for i := range insns {
		in := &insns[i]
		switch in.kind {
		case opNop:
			retired++

		case opMovRegImm:
			if in.size != 8 && in.size != 4 {
				return 0, 0, false, false
			}
			a.movRAXImm64(truncate(uint64(in.imm), in.size))
			a.storeReg(in.dst)
			retired++

		case opMovRegReg:
			if in.size != 8 && in.size != 4 {
				return 0, 0, false, false
			}
			a.loadReg(in.src)
			if in.size == 4 {
				a.db(0x89, 0xC0) // mov eax, eax (zero-extend)
			}
			a.storeReg(in.dst)
			retired++

		case opALURegReg:
			if in.src < 0 || in.dst < 0 {
				return 0, 0, false, false
			}
			a.loadReg(in.dst)
			a.loadRegRCX(in.src)
			a.loadFlags()
			if !a.aluRAXRCX(in.alu, in.size) {
				return 0, 0, false, false
			}
			a.saveFlags()
			if in.alu != aluCMP {
				a.storeReg(in.dst)
			}
			retired++

		case opALURegImm:
			if in.dst < 0 || in.size != 8 && in.size != 4 {
				return 0, 0, false, false
			}
			a.loadReg(in.dst)
			a.loadFlags()
			if !a.aluRAXImm32(in.alu, in.size, in.imm) {
				return 0, 0, false, false
			}
			a.saveFlags()
			if in.alu != aluCMP {
				a.storeReg(in.dst)
			}
			retired++

		case opMovRegMem:
			if !c.nativeMem || in.size != 4 && in.size != 8 || in.dst < 0 {
				return 0, 0, false, false
			}
			if !a.memAddrR11(in) {
				return 0, 0, false, false
			}
			usesMemory = true
			a.permCheckRange(permRead, 0, in.size, in.rip, retired)
			a.flatBaseToRDX()
			if in.size == 4 {
				a.db(0x42, 0x8B, 0x04, 0x1A) // mov eax, [rdx+r11]
			} else {
				a.db(0x4A, 0x8B, 0x04, 0x1A) // mov rax, [rdx+r11]
			}
			a.storeReg(in.dst)
			retired++

		case opMovMemReg:
			if !c.nativeMem || in.size != 4 && in.size != 8 || in.src < 0 {
				return 0, 0, false, false
			}
			if !a.memAddrR11(in) {
				return 0, 0, false, false
			}
			usesMemory = true
			a.permCheckRange(permWrite, permExecute, in.size, in.rip, retired)
			a.flatBaseToRDX()
			a.loadReg(in.src) // rax = guest source value
			if in.size == 4 {
				a.db(0x42, 0x89, 0x04, 0x1A) // mov [rdx+r11], eax
			} else {
				a.db(0x4A, 0x89, 0x04, 0x1A) // mov [rdx+r11], rax
			}
			retired++

		case opMMX:
			switch in.opcode {
			case 0x77:
				usesMMX = true
				a.emms()
			case 0x6F:
				usesMMX = true
				if in.size == 1 {
					a.loadMMX(in.src)
				} else {
					if !c.nativeMem || !a.memAddrR11(in) {
						return 0, 0, false, false
					}
					usesMemory = true
					a.permCheckRange(permRead, 0, 8, in.rip, retired)
					a.flatBaseToRDX()
					a.db(0x4A, 0x8B, 0x04, 0x1A)
				}
				a.storeMMX(in.dst)
			case 0x7F:
				usesMMX = true
				if in.size == 1 {
					a.loadMMX(in.dst)
					a.storeMMX(in.src)
				} else {
					if !c.nativeMem || !a.memAddrR11(in) {
						return 0, 0, false, false
					}
					usesMemory = true
					a.loadMMXValue(in.dst)
					a.db(0x49, 0x89, 0xC2) // mov r10, rax
					a.permCheckRange(permWrite, permExecute, 8, in.rip, retired)
					a.flatBaseToRDX()
					a.db(0x4C, 0x89, 0xD0) // mov rax, r10
					a.db(0x4A, 0x89, 0x04, 0x1A)
					a.markMMX()
				}
			default:
				if retired == 0 {
					return 0, 0, false, false
				}
				a.buf = append(a.buf, a.faultEpilogue(in.rip, retired)...)
				return finish()
			}
			retired++

		case opJcc:
			retired++
			a.jccRIP(in.cc, in.target, in.nextRIP)
			a.ret()
			return finish()

		case opJmp:
			retired++
			a.storeRIPImm(in.target)
			a.ret()
			return finish()

		case opEnd:
			// opEnd is a sentinel, not a retired instruction; the
			// interpreter re-executes the instruction at nextRIP.
			a.storeRIPImm(in.nextRIP)
			a.storeStatus(1)
			a.movRAXImm64(uint64(retired))
			a.db(0x48, 0x89, 0x87)
			a.d32(uint32(envRetired))
			a.ret()
			return finish()

		default:
			if retired != 0 {
				a.buf = append(a.buf, a.faultEpilogue(in.rip, retired)...)
				return finish()
			}
			return 0, 0, false, false
		}
	}
	return 0, 0, false, false
}

// runNative executes a native block against the shared CPU state. It
// mirrors the closure contract: s.Fallback is set when the block ended at
// an instruction the interpreter must execute.
func runNative(entry uintptr, s *State) (uint64, bool) {
	env := &NativeEnv{
		Rflags: *s.Rflags,
		RIP:    *s.RIP,
		FPUST:  s.FPUST,
		FPUTop: s.FPUTop,
		FPUTW:  s.FPUTW,
	}
	env.Regs = *s.Regs
	if flat := s.Mem.FlatBase(); flat != nil {
		env.Flat = uintptr(nativeSliceAddr(flat))
	}
	if perm := s.Mem.PermBitmap(); perm != nil {
		env.Perm = uintptr(nativeSliceAddr(perm))
	}
	enterNative(entry, env)
	*s.Regs = env.Regs
	*s.Rflags = env.Rflags
	*s.RIP = env.RIP
	if env.Status == 1 {
		s.Fallback = true
		return env.Retired, true
	}
	return 0, false
}

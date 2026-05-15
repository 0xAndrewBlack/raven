package jit

import (
	"runtime"
	"unsafe"

	"github.com/mirkobrombin/Raven/pkg/mmu"
)

// NativeEnv is the register file shared between Go and generated code.
// Generated code receives its address in RDI and addresses every field by
// fixed displacement, so the layout below is ABI: do not reorder.
type NativeEnv struct {
	Regs        [16]uint64 // +0    guest GPRs, RAX..R15 in interpreter order
	Rflags      uint64     // +128
	RIP         uint64     // +136
	Flat        uintptr    // +144  host base of guest flat memory (0 if disabled)
	Status      uint64     // +152  0 = ok, 1 = fall back to interpreter at RIP
	Perm        uintptr    // +160  base of the per-page permission bitmap
	FPUST       *[8]float64
	FPUTop      *int
	FPUTW       *uint16
	Retired     uint64
	Table       uintptr
	Generation  uintptr
	ActiveUsers uintptr
}

const (
	envRegs        = int(unsafe.Offsetof(NativeEnv{}.Regs))
	envRflags      = int(unsafe.Offsetof(NativeEnv{}.Rflags))
	envRIP         = int(unsafe.Offsetof(NativeEnv{}.RIP))
	envFlat        = int(unsafe.Offsetof(NativeEnv{}.Flat))
	envStatus      = int(unsafe.Offsetof(NativeEnv{}.Status))
	envPerm        = int(unsafe.Offsetof(NativeEnv{}.Perm))
	envFPUST       = int(unsafe.Offsetof(NativeEnv{}.FPUST))
	envFPUTop      = int(unsafe.Offsetof(NativeEnv{}.FPUTop))
	envFPUTW       = int(unsafe.Offsetof(NativeEnv{}.FPUTW))
	envRetired     = int(unsafe.Offsetof(NativeEnv{}.Retired))
	envTable       = int(unsafe.Offsetof(NativeEnv{}.Table))
	envGeneration  = int(unsafe.Offsetof(NativeEnv{}.Generation))
	envActiveUsers = int(unsafe.Offsetof(NativeEnv{}.ActiveUsers))
)

// guest page permission bits mirrored from pkg/mmu (PermRead=1, PermWrite=2).
const (
	permRead    = 1
	permWrite   = 2
	permExecute = 4
)

func nativeDescriptorSupported(d mmu.NativeTableDescriptor) bool {
	return d.L1Root != nil && d.Generation != nil && d.ActiveUsers != nil &&
		d.L1EntrySize == 8 && d.L2EntrySize == 8 &&
		d.PointerSize == 8 && d.GenerationSize == 8 && d.ActiveUsersSize == 8 &&
		d.L1Shift == 27 && d.L2Shift == 12 && d.AddressBits == 48 &&
		d.L1Mask == (1<<21)-1 && d.L2Mask == (1<<15)-1 &&
		d.PageOffsetMask == mmu.PageSize-1 &&
		d.PageDataOffset <= uintptr(^uint32(0)) &&
		d.PageDataLengthOffset <= uintptr(^uint32(0)) &&
		d.PagePermissionsOffset <= uintptr(^uint32(0))
}

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
	buf                []byte
	nativeFaults       []nativeFaultGroup
	nativeAccessPinned bool
}

type nativeFaultGroup struct {
	unacquired []int
	acquired   []int
	faultRIP   uint64
	retired    int
}

func (a *asm) db(b ...byte) { a.buf = append(a.buf, b...) }

func (a *asm) d32(v uint32) {
	a.db(byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

func (a *asm) d64(v uint64) {
	a.d32(uint32(v))
	a.d32(uint32(v >> 32))
}

func (a *asm) nativeFaultGroup(faultRIP uint64, retired int) int {
	a.nativeFaults = append(a.nativeFaults, nativeFaultGroup{
		faultRIP: faultRIP,
		retired:  retired,
	})
	return len(a.nativeFaults) - 1
}

func (a *asm) nativeFaultBranch(group int, acquired bool, shortOpcode byte) {
	a.db(0x0F, (shortOpcode^1)+0x10)
	fixup := len(a.buf)
	a.d32(0)
	if acquired {
		a.nativeFaults[group].acquired = append(a.nativeFaults[group].acquired, fixup)
	} else {
		a.nativeFaults[group].unacquired = append(a.nativeFaults[group].unacquired, fixup)
	}
}

func (a *asm) patchNativeFaults() bool {
	patch := func(fixups []int, target int) bool {
		for _, fixup := range fixups {
			displacement := int64(target - (fixup + 4))
			if displacement != int64(int32(displacement)) {
				return false
			}
			value := uint32(int32(displacement))
			a.buf[fixup] = byte(value)
			a.buf[fixup+1] = byte(value >> 8)
			a.buf[fixup+2] = byte(value >> 16)
			a.buf[fixup+3] = byte(value >> 24)
		}
		return true
	}
	for _, group := range a.nativeFaults {
		if len(group.unacquired) != 0 {
			target := len(a.buf)
			a.buf = append(a.buf, a.faultEpilogue(group.faultRIP, group.retired)...)
			if !patch(group.unacquired, target) {
				return false
			}
		}
		if len(group.acquired) != 0 {
			target := len(a.buf)
			a.buf = append(a.buf, a.nativeAccessFault(group.faultRIP, group.retired, true)...)
			if !patch(group.acquired, target) {
				return false
			}
		}
	}
	return true
}

// movRAXImm64: mov rax, imm64
func (a *asm) movRAXImm64(v uint64) { a.db(0x48, 0xB8); a.d64(v) }

// loadReg: mov rax, [rdi + envRegs + 8*idx]
func (a *asm) loadReg(idx int) { a.db(0x48, 0x8B, 0x87); a.d32(uint32(envRegs + 8*idx)) }

// loadRegRCX: mov rcx, [rdi + envRegs + 8*idx]
func (a *asm) loadRegRCX(idx int) { a.db(0x48, 0x8B, 0x8F); a.d32(uint32(envRegs + 8*idx)) }

// loadRegRDX: mov rdx, [rdi + envRegs + 8*idx]
func (a *asm) loadRegRDX(idx int) { a.db(0x48, 0x8B, 0x97); a.d32(uint32(envRegs + 8*idx)) }

// storeReg: mov [rdi + envRegs + 8*idx], rax
func (a *asm) storeReg(idx int) { a.db(0x48, 0x89, 0x87); a.d32(uint32(envRegs + 8*idx)) }

// storeRegRCX: mov [rdi + envRegs + 8*idx], rcx
func (a *asm) storeRegRCX(idx int) { a.db(0x48, 0x89, 0x8F); a.d32(uint32(envRegs + 8*idx)) }

func validNativeReg(index int) bool { return index >= 0 && index < 16 }

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

// loadFlags installs only arithmetic guest flags in the host. Loading guest
// TF, DF, or AC would let guest state trap or corrupt the Go runtime.
func (a *asm) loadFlags() {
	a.db(0x48, 0x8B, 0x97)
	a.d32(uint32(envRflags))
	a.db(0x48, 0x81, 0xE2)
	a.d32(uint32(flagCF | flagPF | flagAF | flagZF | flagSF | flagOF))
	a.db(0x48, 0x83, 0xCA, 0x02)
	a.db(0x52, 0x9D)
}

func (a *asm) beginMergedFlags() {
	// Keep the original flags in R10 so AF and non-arithmetic bits survive.
	a.db(0x4C, 0x8B, 0x97)
	a.d32(uint32(envRflags))
	a.loadFlags()
}

func (a *asm) endMergedFlags(changed, fromHost uint32) {
	a.db(0x9C, 0x5A)       // pushfq; pop rdx
	a.db(0x48, 0x81, 0xE2) // and rdx, fromHost
	a.d32(fromHost)
	a.db(0x49, 0x81, 0xE2) // and r10, ^changed
	a.d32(^changed)
	a.db(0x4C, 0x09, 0xD2) // or rdx, r10
	a.db(0x48, 0x89, 0x97)
	a.d32(uint32(envRflags))
}

func (a *asm) clearFlags(mask uint32) {
	a.db(0x48, 0x8B, 0x97)
	a.d32(uint32(envRflags))
	a.db(0x48, 0x81, 0xE2)
	a.d32(^mask)
	a.db(0x48, 0x89, 0x97)
	a.d32(uint32(envRflags))
}

func (a *asm) ret() { a.db(0xFC, 0xC3) }

func (a *asm) nativeBlockRet() {
	if a.nativeAccessPinned {
		a.releaseNativeAccess()
	}
	a.ret()
}

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
	var wideOpcode byte
	switch op {
	case aluADD:
		wideOpcode = 0x01 // add r/m, r
	case aluOR:
		wideOpcode = 0x09
	case aluADC:
		wideOpcode = 0x11
	case aluSBB:
		wideOpcode = 0x19
	case aluAND:
		wideOpcode = 0x21
	case aluSUB:
		wideOpcode = 0x29
	case aluXOR:
		wideOpcode = 0x31
	case aluCMP:
		wideOpcode = 0x39
	default:
		return false
	}
	switch size {
	case 1:
		a.db(wideOpcode-1, 0xC8)
	case 2:
		a.db(0x66, wideOpcode, 0xC8)
	case 8:
		a.db(0x48, wideOpcode, 0xC8) // op rax, rcx
	case 4:
		a.db(wideOpcode, 0xC8) // 32-bit form zero-extends, like the interpreter
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
	case aluADC:
		ext = 2
	case aluSBB:
		ext = 3
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
	// ModRM: mod=11, reg=ext (the /digit), rm=000 (rax).
	modrm := 0xC0 | (ext << 3)
	switch size {
	case 1:
		a.db(0x80, modrm, byte(imm))
		return true
	case 2:
		a.db(0x66, 0x81, modrm, byte(imm), byte(imm>>8))
		return true
	case 8:
		if imm != int64(int32(imm)) {
			return false
		}
		a.db(0x48, 0x81, modrm)
	case 4:
		a.db(0x81, modrm)
	default:
		return false
	}
	a.d32(uint32(int32(imm)))
	return true
}

func nativeALUFlags(op aluOp) uint32 {
	flags := uint32(flagCF | flagPF | flagZF | flagSF | flagOF)
	switch op {
	case aluADD, aluADC, aluSBB, aluSUB, aluCMP:
		flags |= flagAF
	}
	return flags
}

func (a *asm) testRAXRCX(size int) bool {
	switch size {
	case 1:
		a.db(0x84, 0xC8)
	case 2:
		a.db(0x66, 0x85, 0xC8)
	case 4:
		a.db(0x85, 0xC8)
	case 8:
		a.db(0x48, 0x85, 0xC8)
	default:
		return false
	}
	return true
}

func (a *asm) testRAXImm(size int, imm int64) bool {
	switch size {
	case 1:
		a.db(0xF6, 0xC0, byte(imm))
	case 2:
		a.db(0x66, 0xF7, 0xC0)
		a.db(byte(imm), byte(imm>>8))
	case 4:
		a.db(0xF7, 0xC0)
		a.d32(uint32(imm))
	case 8:
		if imm != int64(int32(imm)) {
			return false
		}
		a.db(0x48, 0xF7, 0xC0)
		a.d32(uint32(int32(imm)))
	default:
		return false
	}
	return true
}

func (a *asm) movExtendRAX(dstSize, srcSize int, signed bool) bool {
	if srcSize != 1 && srcSize != 2 || dstSize != 2 && dstSize != 4 && dstSize != 8 ||
		srcSize >= dstSize {
		return false
	}
	opcode := byte(0xB6)
	if srcSize == 2 {
		opcode = 0xB7
	}
	if signed {
		opcode += 8
	}
	switch dstSize {
	case 2:
		a.db(0x66, 0x0F, opcode, 0xC1)
	case 4:
		a.db(0x0F, opcode, 0xC1)
	case 8:
		a.db(0x48, 0x0F, opcode, 0xC1)
	}
	return true
}

func (a *asm) cmovRAXRCX(cc condCode, size int) bool {
	switch size {
	case 2:
		a.db(0x66, 0x0F, 0x40|byte(cc), 0xC1)
	case 4:
		a.db(0x0F, 0x40|byte(cc), 0xC1)
	case 8:
		a.db(0x48, 0x0F, 0x40|byte(cc), 0xC1)
	default:
		return false
	}
	return true
}

func (a *asm) imulRAXRCX(size int) bool {
	switch size {
	case 2:
		a.db(0x66, 0x0F, 0xAF, 0xC1)
	case 4:
		a.db(0x0F, 0xAF, 0xC1)
	case 8:
		a.db(0x48, 0x0F, 0xAF, 0xC1)
	default:
		return false
	}
	return true
}

func (a *asm) imulRAXRCXImmediate(size int, imm int64) bool {
	if size != 2 && size != 4 && size != 8 {
		return false
	}
	if imm >= -128 && imm <= 127 {
		if size == 2 {
			a.db(0x66)
		} else if size == 8 {
			a.db(0x48)
		}
		a.db(0x6B, 0xC1, byte(int8(imm)))
		return true
	}
	if size == 2 {
		if imm < -32768 || imm > 32767 {
			return false
		}
		a.db(0x66, 0x69, 0xC1, byte(imm), byte(imm>>8))
		return true
	}
	if imm != int64(int32(imm)) {
		return false
	}
	if size == 8 {
		a.db(0x48)
	}
	a.db(0x69, 0xC1)
	a.d32(uint32(int32(imm)))
	return true
}

func (a *asm) xchgRAXRCX(size int) bool {
	switch size {
	case 1:
		a.db(0x86, 0xC8)
	case 2:
		a.db(0x66, 0x87, 0xC8)
	case 4:
		a.db(0x87, 0xC8)
	case 8:
		a.db(0x48, 0x87, 0xC8)
	default:
		return false
	}
	return true
}

func (a *asm) unaryRAX(kind opKind, size int) bool {
	var group byte
	var byteOpcode, wideOpcode byte
	switch kind {
	case opNot:
		group, byteOpcode, wideOpcode = 2, 0xF6, 0xF7
	case opNeg:
		group, byteOpcode, wideOpcode = 3, 0xF6, 0xF7
	case opInc:
		group, byteOpcode, wideOpcode = 0, 0xFE, 0xFF
	case opDec:
		group, byteOpcode, wideOpcode = 1, 0xFE, 0xFF
	default:
		return false
	}
	modrm := byte(0xC0 | group<<3)
	switch size {
	case 1:
		a.db(byteOpcode, modrm)
	case 2:
		a.db(0x66, wideOpcode, modrm)
	case 4:
		a.db(wideOpcode, modrm)
	case 8:
		a.db(0x48, wideOpcode, modrm)
	default:
		return false
	}
	return true
}

func (a *asm) storeDivisionResult(size int) bool {
	switch size {
	case 1:
		a.db(0x66, 0x89, 0x87)
		a.d32(uint32(envRegs))
	case 2:
		a.db(0x66, 0x89, 0x87)
		a.d32(uint32(envRegs))
		a.db(0x66, 0x89, 0x97)
		a.d32(uint32(envRegs + 2*8))
	case 4:
		a.db(0x89, 0xC0)
		a.db(0x89, 0xD2)
		a.storeReg(0)
		a.db(0x48, 0x89, 0x97)
		a.d32(uint32(envRegs + 2*8))
	case 8:
		a.storeReg(0)
		a.db(0x48, 0x89, 0x97)
		a.d32(uint32(envRegs + 2*8))
	default:
		return false
	}
	return true
}

func (a *asm) divideUnsignedReg(size, src int, faultRIP uint64, retired int) bool {
	if !validNativeReg(src) || size != 1 && size != 2 && size != 4 && size != 8 {
		return false
	}
	fault := a.nativeFaultGroup(faultRIP, retired)
	acquired := a.nativeAccessPinned

	a.loadRegRCX(src)
	switch size {
	case 1:
		a.db(0x0F, 0xB6, 0xC9)
	case 2:
		a.db(0x0F, 0xB7, 0xC9)
	case 4:
		a.db(0x89, 0xC9)
	}
	a.db(0x48, 0x85, 0xC9)
	a.nativeFaultBranch(fault, acquired, 0x75)

	a.loadReg(0)
	switch size {
	case 1:
		a.db(0x0F, 0xB6, 0xD4)
		a.db(0x39, 0xCA)
		a.nativeFaultBranch(fault, acquired, 0x72)
		a.db(0xF6, 0xF1)
	case 2:
		a.loadRegRDX(2)
		a.db(0x66, 0x39, 0xCA)
		a.nativeFaultBranch(fault, acquired, 0x72)
		a.db(0x66, 0xF7, 0xF1)
	case 4:
		a.loadRegRDX(2)
		a.db(0x39, 0xCA)
		a.nativeFaultBranch(fault, acquired, 0x72)
		a.db(0xF7, 0xF1)
	case 8:
		a.loadRegRDX(2)
		a.db(0x48, 0x39, 0xCA)
		a.nativeFaultBranch(fault, acquired, 0x72)
		a.db(0x48, 0xF7, 0xF1)
	}
	return a.storeDivisionResult(size)
}

func (a *asm) divideSignedReg(size, src int, faultRIP uint64, retired int) bool {
	if !validNativeReg(src) || size != 1 && size != 2 && size != 4 && size != 8 {
		return false
	}
	fault := a.nativeFaultGroup(faultRIP, retired)
	acquired := a.nativeAccessPinned

	a.loadRegRCX(src)
	switch size {
	case 1:
		a.db(0x48, 0x0F, 0xBE, 0xC9)
	case 2:
		a.db(0x48, 0x0F, 0xBF, 0xC9)
	case 4:
		a.db(0x48, 0x63, 0xC9)
	}
	a.db(0x48, 0x85, 0xC9)
	a.nativeFaultBranch(fault, acquired, 0x75)

	a.loadReg(0)
	switch size {
	case 1:
		a.db(0x48, 0x0F, 0xBF, 0xC0)
	case 2:
		a.db(0x0F, 0xB7, 0xC0)
		a.loadRegRDX(2)
		a.db(0x0F, 0xB7, 0xD2)
		a.db(0xC1, 0xE2, 0x10)
		a.db(0x09, 0xD0)
		a.db(0x48, 0x63, 0xC0)
	case 4:
		a.db(0x89, 0xC0)
		a.loadRegRDX(2)
		a.db(0x89, 0xD2)
		a.db(0x48, 0xC1, 0xE2, 0x20)
		a.db(0x48, 0x09, 0xD0)
	case 8:
		a.loadRegRDX(2)
	}

	a.db(0x49, 0x89, 0xC0)
	if size == 8 {
		a.db(0x49, 0x89, 0xD0)
	}
	a.db(0x49, 0xC1, 0xF8, 0x3F)
	a.db(0x49, 0x89, 0xC9)
	a.db(0x49, 0xC1, 0xF9, 0x3F)
	a.db(0x4C, 0x31, 0xC9)
	a.db(0x4C, 0x29, 0xC9)
	a.db(0x4D, 0x31, 0xC1)

	a.db(0x4C, 0x31, 0xC0)
	if size == 8 {
		a.db(0x4C, 0x31, 0xC2)
		a.db(0x4C, 0x29, 0xC0)
		a.db(0x4C, 0x19, 0xC2)
	} else {
		a.db(0x4C, 0x29, 0xC0)
		a.db(0x31, 0xD2)
	}

	a.db(0x48, 0x39, 0xCA)
	a.nativeFaultBranch(fault, acquired, 0x72)
	a.db(0x48, 0xF7, 0xF1)

	a.db(0x49, 0xBA)
	switch size {
	case 1:
		a.d64(0x7F)
	case 2:
		a.d64(0x7FFF)
	case 4:
		a.d64(0x7FFFFFFF)
	case 8:
		a.d64(uint64(^uint64(0) >> 1))
	}
	a.db(0x4D, 0x29, 0xCA)
	a.db(0x4C, 0x39, 0xD0)
	a.nativeFaultBranch(fault, acquired, 0x76)
	a.db(0x4C, 0x31, 0xC8)
	a.db(0x4C, 0x29, 0xC8)
	a.db(0x4C, 0x31, 0xC2)
	a.db(0x4C, 0x29, 0xC2)
	if size == 1 {
		a.db(0x88, 0xD4)
	}
	return a.storeDivisionResult(size)
}

func (a *asm) shiftRAXImmediate(op shiftOp, size int, count byte) bool {
	modrm := byte(0xC0 | byte(op)<<3)
	switch size {
	case 1:
		a.db(0xC0, modrm, count)
	case 2:
		a.db(0x66, 0xC1, modrm, count)
	case 4:
		a.db(0xC1, modrm, count)
	case 8:
		a.db(0x48, 0xC1, modrm, count)
	default:
		return false
	}
	return true
}

func (a *asm) shiftRAXCL(op shiftOp, size int) bool {
	modrm := byte(0xC0 | byte(op)<<3)
	switch size {
	case 1:
		a.db(0xD2, modrm)
	case 2:
		a.db(0x66, 0xD3, modrm)
	case 4:
		a.db(0xD3, modrm)
	case 8:
		a.db(0x48, 0xD3, modrm)
	default:
		return false
	}
	return true
}

func (a *asm) shortJump(opcode byte) int {
	a.db(opcode, 0)
	return len(a.buf) - 1
}

func (a *asm) patchShortJump(displacement int) bool {
	delta := len(a.buf) - displacement - 1
	if delta > 127 {
		return false
	}
	a.buf[displacement] = byte(delta)
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

// memAddrR11 computes the guest effective address in R11.
func (a *asm) memAddrR11(in *insn, mode32 bool) bool {
	if in.useRIP {
		if mode32 {
			return false
		}
		a.db(0x49, 0xBB)
		a.d64(uint64(int64(in.nextRIP) + in.memDisp))
		return true
	}
	if in.memBase >= 0 {
		if !validNativeReg(in.memBase) {
			return false
		}
		if mode32 {
			a.db(0x44, 0x8B, 0x9F)
		} else {
			a.db(0x4C, 0x8B, 0x9F)
		}
		a.d32(uint32(envRegs + 8*in.memBase))
	} else {
		a.db(0x45, 0x31, 0xDB)
	}
	if in.memIdx >= 0 {
		if !validNativeReg(in.memIdx) {
			return false
		}
		if mode32 {
			a.db(0x8B, 0x87)
		} else {
			a.db(0x48, 0x8B, 0x87)
		}
		a.d32(uint32(envRegs + 8*in.memIdx))
		switch in.memScale {
		case 1:
		case 2:
			if mode32 {
				a.db(0xD1, 0xE0)
			} else {
				a.db(0x48, 0xD1, 0xE0)
			}
		case 4:
			if mode32 {
				a.db(0xC1, 0xE0, 0x02)
			} else {
				a.db(0x48, 0xC1, 0xE0, 0x02)
			}
		case 8:
			if mode32 {
				a.db(0xC1, 0xE0, 0x03)
			} else {
				a.db(0x48, 0xC1, 0xE0, 0x03)
			}
		default:
			return false
		}
		if mode32 {
			a.db(0x41, 0x01, 0xC3)
		} else {
			a.db(0x49, 0x01, 0xC3)
		}
	}
	if in.memDisp != 0 {
		if in.memDisp != int64(int32(in.memDisp)) {
			return false
		}
		if mode32 {
			a.db(0x41, 0x81, 0xC3)
		} else {
			a.db(0x49, 0x81, 0xC3)
		}
		a.d32(uint32(int32(in.memDisp)))
	}
	return true
}

// leaRAX computes an effective address without touching guest memory.
func (a *asm) leaRAX(in *insn, mode32 bool) bool {
	if in.useRIP {
		if mode32 {
			return false
		}
		a.movRAXImm64(uint64(int64(in.nextRIP) + in.memDisp))
		return true
	}
	if in.memBase >= 0 {
		if !validNativeReg(in.memBase) {
			return false
		}
		if mode32 {
			a.db(0x8B, 0x87)
			a.d32(uint32(envRegs + 8*in.memBase))
		} else {
			a.loadReg(in.memBase)
		}
	} else {
		a.db(0x31, 0xC0)
	}
	if in.memIdx >= 0 {
		if !validNativeReg(in.memIdx) {
			return false
		}
		if mode32 {
			a.db(0x8B, 0x8F)
			a.d32(uint32(envRegs + 8*in.memIdx))
		} else {
			a.loadRegRCX(in.memIdx)
		}
		switch in.memScale {
		case 1:
		case 2:
			if mode32 {
				a.db(0xD1, 0xE1)
			} else {
				a.db(0x48, 0xD1, 0xE1)
			}
		case 4:
			if mode32 {
				a.db(0xC1, 0xE1, 0x02)
			} else {
				a.db(0x48, 0xC1, 0xE1, 0x02)
			}
		case 8:
			if mode32 {
				a.db(0xC1, 0xE1, 0x03)
			} else {
				a.db(0x48, 0xC1, 0xE1, 0x03)
			}
		default:
			return false
		}
		if mode32 {
			a.db(0x01, 0xC8)
		} else {
			a.db(0x48, 0x01, 0xC8)
		}
	}
	if in.memDisp != 0 {
		if in.memDisp != int64(int32(in.memDisp)) {
			return false
		}
		if mode32 {
			a.db(0x05)
		} else {
			a.db(0x48, 0x05)
		}
		a.d32(uint32(int32(in.memDisp)))
	}
	return true
}

func (a *asm) storeLeaResult(dst, size int) bool {
	switch size {
	case 2:
		a.loadRegRCX(dst)
		a.db(0x66, 0x89, 0xC1)
		a.db(0x48, 0x89, 0xC8)
	case 4:
		a.db(0x89, 0xC0)
	case 8:
	default:
		return false
	}
	a.storeReg(dst)
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
	a.db(0x89, 0xC8)
	a.db(0x24, bit)
	a.db(0x3C, bit)
	a.branchOverFault(0x74, fault)
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

func (a *asm) loadFlatRAX(size int) bool {
	switch size {
	case 1:
		a.db(0x42, 0x0F, 0xB6, 0x04, 0x1A)
	case 2:
		a.db(0x42, 0x0F, 0xB7, 0x04, 0x1A)
	case 4:
		a.db(0x42, 0x8B, 0x04, 0x1A)
	default:
		return false
	}
	return true
}

func (a *asm) loadFlatRCX(size int) bool {
	switch size {
	case 1:
		a.db(0x42, 0x0F, 0xB6, 0x0C, 0x1A)
	case 2:
		a.db(0x42, 0x0F, 0xB7, 0x0C, 0x1A)
	case 4:
		a.db(0x42, 0x8B, 0x0C, 0x1A)
	default:
		return false
	}
	return true
}

func (a *asm) storeFlatRAX(size int) bool {
	switch size {
	case 1:
		a.db(0x42, 0x88, 0x04, 0x1A)
	case 2:
		a.db(0x66, 0x42, 0x89, 0x04, 0x1A)
	case 4:
		a.db(0x42, 0x89, 0x04, 0x1A)
	default:
		return false
	}
	return true
}

func (a *asm) nativeAccessFault(faultRIP uint64, retired int, acquired bool) []byte {
	e := &asm{}
	if acquired {
		e.releaseNativeAccess()
	}
	e.buf = append(e.buf, e.faultEpilogue(faultRIP, retired)...)
	return e.buf
}

func (a *asm) appendBlockFault(faultRIP uint64, retired int) {
	a.buf = append(a.buf, a.nativeAccessFault(faultRIP, retired, a.nativeAccessPinned)...)
}

func (a *asm) releaseNativeAccess() {
	a.db(0x48, 0x8B, 0x97)
	a.d32(uint32(envActiveUsers))
	a.db(0xF0, 0x48, 0xFF, 0x0A)
}

// sparseResolveR9 pins the native table for the block and resolves R11 to a
// host pointer in R9. The block releases the pin on every exit.
func (a *asm) sparseResolveR9(d mmu.NativeTableDescriptor, required, forbidden byte, size int, faultRIP uint64, retired int) bool {
	if !nativeDescriptorSupported(d) || size < 1 || size > 8 {
		return false
	}
	faultGroup := a.nativeFaultGroup(faultRIP, retired)

	if !a.nativeAccessPinned {
		// Load an even generation, pin the table, then confirm it did not move.
		a.db(0x48, 0x8B, 0x97)
		a.d32(uint32(envGeneration))
		a.db(0x4C, 0x8B, 0x12)
		a.db(0x41, 0xF6, 0xC2, 0x01)
		a.nativeFaultBranch(faultGroup, false, 0x74)
		a.db(0x48, 0x8B, 0x97)
		a.d32(uint32(envActiveUsers))
		a.db(0xF0, 0x48, 0xFF, 0x02)
		a.db(0x48, 0x8B, 0x97)
		a.d32(uint32(envGeneration))
		a.db(0x4C, 0x3B, 0x12)
		a.nativeFaultBranch(faultGroup, true, 0x74)
		a.nativeAccessPinned = true
	}

	// Sign-extending bit 47 must reproduce the original guest address.
	a.db(0x4C, 0x89, 0xD8)
	a.db(0x48, 0xC1, 0xE0, 0x10)
	a.db(0x48, 0xC1, 0xF8, 0x10)
	a.db(0x4C, 0x39, 0xD8)
	a.nativeFaultBranch(faultGroup, true, 0x74)

	// Cross-page accesses leave native code before touching guest memory.
	a.db(0x44, 0x89, 0xD8)
	a.db(0x25)
	a.d32(uint32(d.PageOffsetMask))
	a.db(0x3D)
	a.d32(uint32(mmu.PageSize - size))
	a.nativeFaultBranch(faultGroup, true, 0x76)

	// L1[(addr>>27)&mask] -> L2, then L2[(addr>>12)&mask] -> PageEntry.
	a.db(0x4C, 0x89, 0xD8)
	a.db(0x48, 0xC1, 0xE8, d.L1Shift)
	a.db(0x25)
	a.d32(uint32(d.L1Mask))
	a.db(0x48, 0x8B, 0x97)
	a.d32(uint32(envTable))
	a.db(0x48, 0x8B, 0x04, 0xC2)
	a.db(0x48, 0x85, 0xC0)
	a.nativeFaultBranch(faultGroup, true, 0x75)
	a.db(0x4C, 0x89, 0xD9)
	a.db(0x48, 0xC1, 0xE9, d.L2Shift)
	a.db(0x81, 0xE1)
	a.d32(uint32(d.L2Mask))
	a.db(0x48, 0x8B, 0x04, 0xC8)
	a.db(0x48, 0x85, 0xC0)
	a.nativeFaultBranch(faultGroup, true, 0x75)

	a.db(0x0F, 0xB6, 0x88)
	a.d32(uint32(d.PagePermissionsOffset))
	a.db(0x89, 0xCA)
	a.db(0x80, 0xE2, required)
	a.db(0x80, 0xFA, required)
	a.nativeFaultBranch(faultGroup, true, 0x74)
	if forbidden != 0 {
		a.db(0xF6, 0xC1, forbidden)
		a.nativeFaultBranch(faultGroup, true, 0x74)
	}

	a.db(0x4C, 0x8B, 0x88)
	a.d32(uint32(d.PageDataOffset))
	a.db(0x4D, 0x85, 0xC9)
	a.nativeFaultBranch(faultGroup, true, 0x75)
	a.db(0x48, 0x8B, 0x90)
	a.d32(uint32(d.PageDataLengthOffset))
	a.db(0x44, 0x89, 0xD9)
	a.db(0x81, 0xE1)
	a.d32(uint32(d.PageOffsetMask))
	a.db(0x48, 0x83, 0xC1, byte(size))
	a.db(0x48, 0x39, 0xCA)
	a.nativeFaultBranch(faultGroup, true, 0x73)
	a.db(0x48, 0x83, 0xE9, byte(size))
	a.db(0x49, 0x01, 0xC9)
	return true
}

func (a *asm) loadSparseRAX(size int) bool {
	switch size {
	case 1:
		a.db(0x41, 0x0F, 0xB6, 0x01)
	case 2:
		a.db(0x41, 0x0F, 0xB7, 0x01)
	case 4:
		a.db(0x41, 0x8B, 0x01)
	case 8:
		a.db(0x49, 0x8B, 0x01)
	default:
		return false
	}
	return true
}

func (a *asm) loadSparseRCX(size int) bool {
	switch size {
	case 1:
		a.db(0x41, 0x0F, 0xB6, 0x09)
	case 2:
		a.db(0x41, 0x0F, 0xB7, 0x09)
	case 4:
		a.db(0x41, 0x8B, 0x09)
	case 8:
		a.db(0x49, 0x8B, 0x09)
	default:
		return false
	}
	return true
}

func (a *asm) storeSparseRAX(size int) bool {
	switch size {
	case 1:
		a.db(0x41, 0x88, 0x01)
	case 2:
		a.db(0x66, 0x41, 0x89, 0x01)
	case 4:
		a.db(0x41, 0x89, 0x01)
	case 8:
		a.db(0x49, 0x89, 0x01)
	default:
		return false
	}
	return true
}

func (a *asm) storeSparseR8(size int) bool {
	switch size {
	case 1:
		a.db(0x45, 0x88, 0x01)
	case 2:
		a.db(0x66, 0x45, 0x89, 0x01)
	case 4:
		a.db(0x45, 0x89, 0x01)
	case 8:
		a.db(0x4D, 0x89, 0x01)
	default:
		return false
	}
	return true
}

func (a *asm) storeLoadedReg(dst, size int) bool {
	switch size {
	case 1:
		a.loadRegRCX(dst)
		a.db(0x88, 0xC1)
		a.db(0x48, 0x89, 0xC8)
	case 2:
		a.loadRegRCX(dst)
		a.db(0x66, 0x89, 0xC1)
		a.db(0x48, 0x89, 0xC8)
	case 4:
		a.db(0x89, 0xC0)
	case 8:
	default:
		return false
	}
	a.storeReg(dst)
	return true
}

func (a *asm) storeR11Reg(index int) {
	a.db(0x4C, 0x89, 0x9F)
	a.d32(uint32(envRegs + 8*index))
}

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

func (a *asm) loadMMXSource(in *insn, retired int) bool {
	if in.size == 1 {
		a.loadMMXValue(in.src)
		// mov rcx, rax
		a.db(0x48, 0x89, 0xC1)
		return true
	}
	if !a.memAddrR11(in, true) {
		return false
	}
	a.permCheckRange(permRead, 0, 8, in.rip, retired)
	a.flatBaseToRDX()
	// mov rcx, [rdx+r11]
	a.db(0x4A, 0x8B, 0x0C, 0x1A)
	return true
}

func (a *asm) packedMMX(opcode byte, dst int) {
	// Move the guest operands from RAX/RCX into scratch host MMX registers.
	a.db(0x48, 0x0F, 0x6E, 0xC0)
	a.db(0x48, 0x0F, 0x6E, 0xC9)
	a.db(0x0F, opcode, 0xC1)
	a.db(0x48, 0x0F, 0x7E, 0xC0)
	a.db(0x0F, 0x77)
	a.storeMMX(dst)
}

func (a *asm) shiftMMX(opcode byte, subop int, immediate byte, dst int) {
	a.db(0x48, 0x0F, 0x6E, 0xC0)
	a.db(0x0F, opcode, byte(0xC0|subop<<3), immediate)
	a.db(0x48, 0x0F, 0x7E, 0xC0)
	a.db(0x0F, 0x77)
	a.storeMMX(dst)
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
		if !a.patchNativeFaults() {
			return 0, 0, false, false
		}
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
			if !validNativeReg(in.dst) ||
				in.size != 1 && in.size != 2 && in.size != 4 && in.size != 8 {
				return 0, 0, false, false
			}
			a.movRAXImm64(truncate(uint64(in.imm), in.size))
			if !a.storeLoadedReg(in.dst, in.size) {
				return 0, 0, false, false
			}
			retired++

		case opMovRegReg:
			if !validNativeReg(in.src) || !validNativeReg(in.dst) ||
				in.size != 1 && in.size != 2 && in.size != 4 && in.size != 8 {
				return 0, 0, false, false
			}
			a.loadReg(in.src)
			if !a.storeLoadedReg(in.dst, in.size) {
				return 0, 0, false, false
			}
			retired++

		case opALURegReg:
			if in.src < 0 || in.dst < 0 {
				return 0, 0, false, false
			}
			a.loadReg(in.dst)
			a.loadRegRCX(in.src)
			a.beginMergedFlags()
			if !a.aluRAXRCX(in.alu, in.size) {
				return 0, 0, false, false
			}
			changedFlags := nativeALUFlags(in.alu)
			a.endMergedFlags(changedFlags, changedFlags)
			if in.alu != aluCMP {
				a.storeReg(in.dst)
			}
			retired++

		case opALURegImm:
			if in.dst < 0 {
				return 0, 0, false, false
			}
			a.loadReg(in.dst)
			a.beginMergedFlags()
			if !a.aluRAXImm32(in.alu, in.size, in.imm) {
				return 0, 0, false, false
			}
			changedFlags := nativeALUFlags(in.alu)
			a.endMergedFlags(changedFlags, changedFlags)
			if in.alu != aluCMP {
				a.storeReg(in.dst)
			}
			retired++

		case opLea:
			if !validNativeReg(in.dst) || !a.leaRAX(in, c.mode32) ||
				!a.storeLeaResult(in.dst, in.size) {
				return 0, 0, false, false
			}
			retired++

		case opALURegMem:
			if !c.nativeMem || !validNativeReg(in.dst) ||
				in.size != 1 && in.size != 2 && in.size != 4 && in.size != 8 ||
				!a.memAddrR11(in, c.mode32) {
				return 0, 0, false, false
			}
			usesMemory = true
			if c.mode32 {
				if in.size == 8 {
					return 0, 0, false, false
				}
				a.permCheckRange(permRead, 0, in.size, in.rip, retired)
				a.flatBaseToRDX()
				if !a.loadFlatRCX(in.size) {
					return 0, 0, false, false
				}
			} else {
				if !a.sparseResolveR9(c.nativeTable, permRead, 0, in.size, in.rip, retired) ||
					!a.loadSparseRCX(in.size) {
					return 0, 0, false, false
				}
			}
			a.loadReg(in.dst)
			a.beginMergedFlags()
			if !a.aluRAXRCX(in.alu, in.size) {
				return 0, 0, false, false
			}
			changedFlags := nativeALUFlags(in.alu)
			a.endMergedFlags(changedFlags, changedFlags)
			if in.alu != aluCMP {
				a.storeReg(in.dst)
			}
			retired++

		case opALUMemReg:
			if !c.nativeMem || !validNativeReg(in.src) ||
				in.size != 1 && in.size != 2 && in.size != 4 && in.size != 8 ||
				!a.memAddrR11(in, c.mode32) {
				return 0, 0, false, false
			}
			usesMemory = true
			required := byte(permRead)
			forbidden := byte(0)
			if in.alu != aluCMP {
				required |= permWrite
				forbidden = permExecute
			}
			if c.mode32 {
				if in.size == 8 {
					return 0, 0, false, false
				}
				a.permCheckRange(required, forbidden, in.size, in.rip, retired)
				a.flatBaseToRDX()
				if !a.loadFlatRAX(in.size) {
					return 0, 0, false, false
				}
			} else if !a.sparseResolveR9(c.nativeTable, required, forbidden, in.size, in.rip, retired) ||
				!a.loadSparseRAX(in.size) {
				return 0, 0, false, false
			}
			a.loadRegRCX(in.src)
			a.beginMergedFlags()
			if !a.aluRAXRCX(in.alu, in.size) {
				return 0, 0, false, false
			}
			changedFlags := nativeALUFlags(in.alu)
			a.endMergedFlags(changedFlags, changedFlags)
			if in.alu != aluCMP {
				if c.mode32 {
					a.flatBaseToRDX()
					if !a.storeFlatRAX(in.size) {
						return 0, 0, false, false
					}
				} else if !a.storeSparseRAX(in.size) {
					return 0, 0, false, false
				}
			}
			retired++

		case opALUMemImm:
			if !c.nativeMem || in.size != 1 && in.size != 2 && in.size != 4 && in.size != 8 ||
				!a.memAddrR11(in, c.mode32) {
				return 0, 0, false, false
			}
			usesMemory = true
			required := byte(permRead)
			forbidden := byte(0)
			if in.alu != aluCMP {
				required |= permWrite
				forbidden = permExecute
			}
			if c.mode32 {
				if in.size == 8 {
					return 0, 0, false, false
				}
				a.permCheckRange(required, forbidden, in.size, in.rip, retired)
				a.flatBaseToRDX()
				if !a.loadFlatRAX(in.size) {
					return 0, 0, false, false
				}
			} else if !a.sparseResolveR9(c.nativeTable, required, forbidden, in.size, in.rip, retired) ||
				!a.loadSparseRAX(in.size) {
				return 0, 0, false, false
			}
			a.beginMergedFlags()
			if !a.aluRAXImm32(in.alu, in.size, in.imm) {
				return 0, 0, false, false
			}
			changedFlags := nativeALUFlags(in.alu)
			a.endMergedFlags(changedFlags, changedFlags)
			if in.alu != aluCMP {
				if c.mode32 {
					a.flatBaseToRDX()
					if !a.storeFlatRAX(in.size) {
						return 0, 0, false, false
					}
				} else if !a.storeSparseRAX(in.size) {
					return 0, 0, false, false
				}
			}
			retired++

		case opTest:
			if !validNativeReg(in.src) || !validNativeReg(in.dst) {
				return 0, 0, false, false
			}
			a.loadReg(in.dst)
			a.loadRegRCX(in.src)
			a.beginMergedFlags()
			if !a.testRAXRCX(in.size) {
				return 0, 0, false, false
			}
			const changed = uint32(flagCF | flagPF | flagZF | flagSF | flagOF)
			a.endMergedFlags(changed, changed)
			retired++

		case opTestImm:
			if !validNativeReg(in.dst) {
				return 0, 0, false, false
			}
			a.loadReg(in.dst)
			a.beginMergedFlags()
			if !a.testRAXImm(in.size, in.imm) {
				return 0, 0, false, false
			}
			const changed = uint32(flagCF | flagPF | flagZF | flagSF | flagOF)
			a.endMergedFlags(changed, changed)
			retired++

		case opMovzx:
			if !validNativeReg(in.dst) {
				return 0, 0, false, false
			}
			if in.src >= 0 {
				if !validNativeReg(in.src) {
					return 0, 0, false, false
				}
				a.loadReg(in.dst)
				a.loadRegRCX(in.src)
			} else {
				if !c.nativeMem || !a.memAddrR11(in, c.mode32) {
					return 0, 0, false, false
				}
				usesMemory = true
				if c.mode32 {
					a.permCheckRange(permRead, 0, in.srcSize, in.rip, retired)
					a.flatBaseToRDX()
					if !a.loadFlatRCX(in.srcSize) {
						return 0, 0, false, false
					}
				} else {
					if !a.sparseResolveR9(c.nativeTable, permRead, 0, in.srcSize, in.rip, retired) ||
						!a.loadSparseRCX(in.srcSize) {
						return 0, 0, false, false
					}
				}
				a.loadReg(in.dst)
			}
			if !a.movExtendRAX(in.size, in.srcSize, false) {
				return 0, 0, false, false
			}
			a.storeReg(in.dst)
			retired++

		case opMovsx:
			if !validNativeReg(in.dst) {
				return 0, 0, false, false
			}
			if in.src >= 0 {
				if !validNativeReg(in.src) {
					return 0, 0, false, false
				}
				a.loadReg(in.dst)
				a.loadRegRCX(in.src)
			} else {
				if !c.nativeMem || !a.memAddrR11(in, c.mode32) {
					return 0, 0, false, false
				}
				usesMemory = true
				if c.mode32 {
					a.permCheckRange(permRead, 0, in.srcSize, in.rip, retired)
					a.flatBaseToRDX()
					if !a.loadFlatRCX(in.srcSize) {
						return 0, 0, false, false
					}
				} else {
					if !a.sparseResolveR9(c.nativeTable, permRead, 0, in.srcSize, in.rip, retired) ||
						!a.loadSparseRCX(in.srcSize) {
						return 0, 0, false, false
					}
				}
				a.loadReg(in.dst)
			}
			if !a.movExtendRAX(in.size, in.srcSize, true) {
				return 0, 0, false, false
			}
			a.storeReg(in.dst)
			retired++

		case opSetcc:
			if !validNativeReg(in.dst) || in.size != 1 || in.cc > ccG {
				return 0, 0, false, false
			}
			a.loadReg(in.dst)
			a.loadFlags()
			a.db(0x0F, 0x90|byte(in.cc), 0xC0)
			a.storeReg(in.dst)
			retired++

		case opCmovcc:
			if !validNativeReg(in.src) || !validNativeReg(in.dst) || in.cc > ccG {
				return 0, 0, false, false
			}
			a.loadReg(in.dst)
			a.loadRegRCX(in.src)
			a.loadFlags()
			if !a.cmovRAXRCX(in.cc, in.size) {
				return 0, 0, false, false
			}
			a.storeReg(in.dst)
			retired++

		case opXchg:
			if !validNativeReg(in.src) || !validNativeReg(in.dst) {
				return 0, 0, false, false
			}
			a.loadReg(in.dst)
			a.loadRegRCX(in.src)
			if !a.xchgRAXRCX(in.size) {
				return 0, 0, false, false
			}
			a.storeReg(in.dst)
			a.storeRegRCX(in.src)
			retired++

		case opCdq:
			a.loadReg(0)
			switch in.size {
			case 4:
				a.db(0x99)
			case 8:
				a.db(0x48, 0x99)
			default:
				return 0, 0, false, false
			}
			a.db(0x48, 0x89, 0xD0)
			a.storeReg(2)
			retired++

		case opIMul:
			if !validNativeReg(in.src) || !validNativeReg(in.dst) {
				return 0, 0, false, false
			}
			a.loadReg(in.dst)
			a.loadRegRCX(in.src)
			a.beginMergedFlags()
			if !a.imulRAXRCX(in.size) {
				return 0, 0, false, false
			}
			a.endMergedFlags(flagCF|flagOF, flagCF|flagOF)
			a.storeReg(in.dst)
			retired++

		case opIMul3:
			if !validNativeReg(in.src) || !validNativeReg(in.dst) {
				return 0, 0, false, false
			}
			a.loadReg(in.dst)
			a.loadRegRCX(in.src)
			a.beginMergedFlags()
			if !a.imulRAXRCXImmediate(in.size, in.imm) {
				return 0, 0, false, false
			}
			a.endMergedFlags(flagCF|flagOF, flagCF|flagOF)
			a.storeReg(in.dst)
			retired++

		case opNot:
			if !validNativeReg(in.dst) {
				return 0, 0, false, false
			}
			a.loadReg(in.dst)
			if !a.unaryRAX(in.kind, in.size) {
				return 0, 0, false, false
			}
			a.storeReg(in.dst)
			retired++

		case opNeg:
			if !validNativeReg(in.dst) {
				return 0, 0, false, false
			}
			a.loadReg(in.dst)
			a.beginMergedFlags()
			if !a.unaryRAX(in.kind, in.size) {
				return 0, 0, false, false
			}
			const arithmeticFlags = uint32(flagCF | flagPF | flagAF | flagZF | flagSF | flagOF)
			a.endMergedFlags(arithmeticFlags, arithmeticFlags)
			a.storeReg(in.dst)
			retired++

		case opInc, opDec:
			if !validNativeReg(in.dst) {
				return 0, 0, false, false
			}
			a.loadReg(in.dst)
			a.beginMergedFlags()
			if !a.unaryRAX(in.kind, in.size) {
				return 0, 0, false, false
			}
			const changedFlags = uint32(flagPF | flagAF | flagZF | flagSF | flagOF)
			a.endMergedFlags(changedFlags, changedFlags)
			a.storeReg(in.dst)
			retired++

		case opDiv:
			if !a.divideUnsignedReg(in.size, in.src, in.rip, retired) {
				return 0, 0, false, false
			}
			retired++

		case opIDiv:
			if !a.divideSignedReg(in.size, in.src, in.rip, retired) {
				return 0, 0, false, false
			}
			retired++

		case opShift:
			if !validNativeReg(in.dst) || in.src != -1 && in.src != 1 ||
				in.shift != shROL && in.shift != shROR && in.shift != shSHL &&
					in.shift != shSHR && in.shift != shSAR ||
				in.size != 1 && in.size != 2 && in.size != 4 && in.size != 8 {
				return 0, 0, false, false
			}
			a.loadReg(in.dst)
			rotates := in.shift == shROL || in.shift == shROR
			if in.src == 1 {
				a.loadRegRCX(1)
				// Test the architectural effective count in R11D so a zero
				// count leaves flags untouched.
				a.db(0x41, 0x89, 0xCB)
				countMask := byte(0x1F)
				if in.size == 8 {
					countMask = 0x3F
				}
				if rotates && in.size < 4 {
					countMask = byte(in.size*8 - 1)
				}
				a.db(0x41, 0x83, 0xE3, countMask)
				a.db(0x45, 0x85, 0xDB)
				skip := a.shortJump(0x74)
				a.beginMergedFlags()
				if !a.shiftRAXCL(in.shift, in.size) {
					return 0, 0, false, false
				}
				if rotates {
					a.endMergedFlags(flagCF|flagOF, flagCF|flagOF)
				} else {
					const changed = uint32(flagCF | flagPF | flagZF | flagSF | flagOF)
					a.endMergedFlags(changed, changed)
				}
				if !a.patchShortJump(skip) {
					return 0, 0, false, false
				}
			} else {
				effective := uint64(in.imm)
				if in.size == 8 {
					effective &= 0x3F
				} else {
					effective &= 0x1F
				}
				if rotates {
					effective %= uint64(in.size * 8)
				}
				if effective != 0 {
					a.beginMergedFlags()
					if !a.shiftRAXImmediate(in.shift, in.size, byte(in.imm)) {
						return 0, 0, false, false
					}
					if rotates {
						a.endMergedFlags(flagCF|flagOF, flagCF|flagOF)
					} else {
						const changed = uint32(flagCF | flagPF | flagZF | flagSF | flagOF)
						a.endMergedFlags(changed, changed)
					}
				}
			}
			if in.size == 4 {
				a.db(0x89, 0xC0)
			}
			a.storeReg(in.dst)
			retired++

		case opMovRegMem:
			if !c.nativeMem || !validNativeReg(in.dst) ||
				in.size != 1 && in.size != 2 && in.size != 4 && in.size != 8 {
				return 0, 0, false, false
			}
			if !a.memAddrR11(in, c.mode32) {
				return 0, 0, false, false
			}
			usesMemory = true
			if c.mode32 {
				if in.size == 8 {
					return 0, 0, false, false
				}
				a.permCheckRange(permRead, 0, in.size, in.rip, retired)
				a.flatBaseToRDX()
				if !a.loadFlatRAX(in.size) {
					return 0, 0, false, false
				}
			} else {
				if !a.sparseResolveR9(c.nativeTable, permRead, 0, in.size, in.rip, retired) ||
					!a.loadSparseRAX(in.size) {
					return 0, 0, false, false
				}
			}
			if !a.storeLoadedReg(in.dst, in.size) {
				return 0, 0, false, false
			}
			retired++

		case opMovMemReg:
			if !c.nativeMem || !validNativeReg(in.src) ||
				in.size != 1 && in.size != 2 && in.size != 4 && in.size != 8 {
				return 0, 0, false, false
			}
			if !a.memAddrR11(in, c.mode32) {
				return 0, 0, false, false
			}
			usesMemory = true
			if c.mode32 {
				if in.size == 8 {
					return 0, 0, false, false
				}
				a.permCheckRange(permWrite, permExecute, in.size, in.rip, retired)
				a.flatBaseToRDX()
				a.loadReg(in.src)
				if !a.storeFlatRAX(in.size) {
					return 0, 0, false, false
				}
			} else {
				a.loadReg(in.src)
				a.db(0x49, 0x89, 0xC0)
				if !a.sparseResolveR9(c.nativeTable, permWrite, permExecute, in.size, in.rip, retired) ||
					!a.storeSparseR8(in.size) {
					return 0, 0, false, false
				}
			}
			retired++

		case opMovMemImm:
			if !c.nativeMem ||
				in.size != 1 && in.size != 2 && in.size != 4 && in.size != 8 ||
				!a.memAddrR11(in, c.mode32) {
				return 0, 0, false, false
			}
			usesMemory = true
			if c.mode32 {
				if in.size == 8 {
					return 0, 0, false, false
				}
				a.permCheckRange(permWrite, permExecute, in.size, in.rip, retired)
				a.flatBaseToRDX()
				a.movRAXImm64(uint64(in.imm))
				if !a.storeFlatRAX(in.size) {
					return 0, 0, false, false
				}
			} else {
				a.movRAXImm64(uint64(in.imm))
				a.db(0x49, 0x89, 0xC0)
				if !a.sparseResolveR9(c.nativeTable, permWrite, permExecute, in.size, in.rip, retired) ||
					!a.storeSparseR8(in.size) {
					return 0, 0, false, false
				}
			}
			retired++

		case opPush:
			if !c.nativeMem || !validNativeReg(in.src) ||
				c.mode32 && in.size != 2 && in.size != 4 ||
				!c.mode32 && in.size != 2 && in.size != 8 {
				return 0, 0, false, false
			}
			usesMemory = true
			if c.mode32 {
				a.db(0x44, 0x8B, 0x9F)
			} else {
				a.db(0x4C, 0x8B, 0x9F)
			}
			a.d32(uint32(envRegs + 8*4))
			if c.mode32 {
				a.db(0x41, 0x83, 0xEB, byte(in.size))
			} else {
				a.db(0x49, 0x83, 0xEB, byte(in.size))
			}
			if c.mode32 {
				a.permCheckRange(permWrite, permExecute, in.size, in.rip, retired)
				a.flatBaseToRDX()
				a.loadReg(in.src)
				if !a.storeFlatRAX(in.size) {
					return 0, 0, false, false
				}
			} else {
				a.loadReg(in.src)
				a.db(0x49, 0x89, 0xC0)
				if !a.sparseResolveR9(c.nativeTable, permWrite, permExecute, in.size, in.rip, retired) ||
					!a.storeSparseR8(in.size) {
					return 0, 0, false, false
				}
			}
			a.storeR11Reg(4)
			retired++

		case opPop:
			if !c.nativeMem || !validNativeReg(in.dst) ||
				c.mode32 && in.size != 2 && in.size != 4 ||
				!c.mode32 && in.size != 2 && in.size != 8 {
				return 0, 0, false, false
			}
			usesMemory = true
			if c.mode32 {
				a.db(0x44, 0x8B, 0x9F)
			} else {
				a.db(0x4C, 0x8B, 0x9F)
			}
			a.d32(uint32(envRegs + 8*4))
			if c.mode32 {
				a.permCheckRange(permRead, 0, in.size, in.rip, retired)
				a.flatBaseToRDX()
				if !a.loadFlatRAX(in.size) {
					return 0, 0, false, false
				}
			} else {
				if !a.sparseResolveR9(c.nativeTable, permRead, 0, in.size, in.rip, retired) ||
					!a.loadSparseRAX(in.size) {
					return 0, 0, false, false
				}
			}
			if c.mode32 {
				a.db(0x41, 0x83, 0xC3, byte(in.size))
			} else {
				a.db(0x49, 0x83, 0xC3, byte(in.size))
			}
			a.storeR11Reg(4)
			if !a.storeLoadedReg(in.dst, in.size) {
				return 0, 0, false, false
			}
			retired++

		case opCall:
			if !c.nativeMem {
				return 0, 0, false, false
			}
			usesMemory = true
			if c.mode32 {
				a.db(0x44, 0x8B, 0x9F)
			} else {
				a.db(0x4C, 0x8B, 0x9F)
			}
			a.d32(uint32(envRegs + 8*4))
			stackSize := 4
			if !c.mode32 {
				stackSize = 8
			}
			if c.mode32 {
				a.db(0x41, 0x83, 0xEB, byte(stackSize))
			} else {
				a.db(0x49, 0x83, 0xEB, byte(stackSize))
			}
			if c.mode32 {
				a.permCheckRange(permWrite, permExecute, stackSize, in.rip, retired)
				a.flatBaseToRDX()
				a.movRAXImm64(in.nextRIP)
				if !a.storeFlatRAX(stackSize) {
					return 0, 0, false, false
				}
			} else {
				a.movRAXImm64(in.nextRIP)
				a.db(0x49, 0x89, 0xC0)
				if !a.sparseResolveR9(c.nativeTable, permWrite, permExecute, stackSize, in.rip, retired) ||
					!a.storeSparseR8(stackSize) {
					return 0, 0, false, false
				}
			}
			a.storeR11Reg(4)
			retired++
			a.storeRIPImm(in.target)
			a.nativeBlockRet()
			return finish()

		case opRet:
			if !c.nativeMem {
				return 0, 0, false, false
			}
			usesMemory = true
			if c.mode32 {
				a.db(0x44, 0x8B, 0x9F)
			} else {
				a.db(0x4C, 0x8B, 0x9F)
			}
			a.d32(uint32(envRegs + 8*4))
			stackSize := 4
			if !c.mode32 {
				stackSize = 8
			}
			if c.mode32 {
				a.permCheckRange(permRead, 0, stackSize, in.rip, retired)
				a.flatBaseToRDX()
				if !a.loadFlatRAX(stackSize) {
					return 0, 0, false, false
				}
			} else {
				if !a.sparseResolveR9(c.nativeTable, permRead, 0, stackSize, in.rip, retired) ||
					!a.loadSparseRAX(stackSize) {
					return 0, 0, false, false
				}
			}
			if c.mode32 {
				a.db(0x41, 0x81, 0xC3)
			} else {
				a.db(0x49, 0x81, 0xC3)
			}
			a.d32(uint32(int64(stackSize) + in.imm))
			a.storeR11Reg(4)
			a.db(0x48, 0x89, 0x87)
			a.d32(uint32(envRIP))
			retired++
			a.nativeBlockRet()
			return finish()

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
					if !c.nativeMem || !c.mode32 || !a.memAddrR11(in, true) {
						return 0, 0, false, false
					}
					usesMemory = true
					a.permCheckRange(permRead, 0, 8, in.rip, retired)
					a.flatBaseToRDX()
					a.db(0x4A, 0x8B, 0x04, 0x1A)
				}
				a.storeMMX(in.dst)
			case 0x6E:
				usesMMX = true
				if in.size == 1 {
					a.loadReg(in.src)
					a.db(0x89, 0xC0)
				} else {
					if !c.nativeMem || !c.mode32 || !a.memAddrR11(in, true) {
						return 0, 0, false, false
					}
					usesMemory = true
					a.permCheckRange(permRead, 0, 4, in.rip, retired)
					a.flatBaseToRDX()
					a.db(0x42, 0x8B, 0x04, 0x1A)
				}
				a.storeMMX(in.dst)
			case 0x71, 0x72, 0x73:
				usesMMX = true
				a.loadMMXValue(in.src)
				a.shiftMMX(in.opcode, in.dst, byte(in.imm), in.src)
			case 0x61, 0x6B, 0xE5, 0xFD:
				usesMMX = true
				if in.size != 1 {
					if !c.nativeMem || !c.mode32 {
						return 0, 0, false, false
					}
					usesMemory = true
				}
				if !a.loadMMXSource(in, retired) {
					return 0, 0, false, false
				}
				a.loadMMXValue(in.dst)
				a.packedMMX(in.opcode, in.dst)
			case 0x7F:
				usesMMX = true
				if in.size == 1 {
					a.loadMMX(in.dst)
					a.storeMMX(in.src)
				} else {
					if !c.nativeMem || !c.mode32 || !a.memAddrR11(in, true) {
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
				a.appendBlockFault(in.rip, retired)
				return finish()
			}
			retired++

		case opJcc:
			retired++
			a.jccRIP(in.cc, in.target, in.nextRIP)
			a.nativeBlockRet()
			return finish()

		case opJmp:
			retired++
			a.storeRIPImm(in.target)
			a.nativeBlockRet()
			return finish()

		case opEnd:
			// opEnd is a sentinel, not a retired instruction; the
			// interpreter re-executes the instruction at nextRIP.
			a.storeRIPImm(in.nextRIP)
			a.storeStatus(1)
			a.movRAXImm64(uint64(retired))
			a.db(0x48, 0x89, 0x87)
			a.d32(uint32(envRetired))
			a.nativeBlockRet()
			return finish()

		default:
			if retired != 0 {
				a.appendBlockFault(in.rip, retired)
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
func runNative(entry uintptr, s *State, table *mmu.NativeTableDescriptor) (uint64, bool) {
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
	if table != nil && table.L1Root != nil {
		env.Table = uintptr(table.L1Root)
		env.Generation = uintptr(table.Generation)
		env.ActiveUsers = uintptr(table.ActiveUsers)
	}
	enterNative(entry, env)
	runtime.KeepAlive(table)
	runtime.KeepAlive(s.Mem)
	*s.Regs = env.Regs
	*s.Rflags = env.Rflags
	*s.RIP = env.RIP
	if env.Status == 1 {
		s.Fallback = true
		return env.Retired, true
	}
	return 0, false
}

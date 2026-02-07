//go:build guest_windows

package ntapi

import (
	"encoding/binary"
	"fmt"
	"sort"

	"github.com/mirkobrombin/Raven/pkg/mmu"

	ravelog "github.com/mirkobrombin/Raven/pkg/log"
)

// RUNTIME_FUNCTION represents an x64 exception handling entry from .pdata.
type RuntimeFunction struct {
	BeginAddress uint32
	EndAddress   uint32
	UnwindData   uint32
	EntryAddr    uint64
}

// ExceptionTable is a sorted table of RUNTIME_FUNCTION entries for one PE module.
type ExceptionTable struct {
	ImageBase uint64
	Entries   []RuntimeFunction
}

// ParseExceptionDirectory reads the .pdata section from guest memory.
func ParseExceptionDirectory(mem *mmu.MMU, imageBase uint64, rva, size uint32) *ExceptionTable {
	if rva == 0 || size == 0 {
		return nil
	}
	count := size / 12 // each RUNTIME_FUNCTION is 12 bytes
	et := &ExceptionTable{
		ImageBase: imageBase,
		Entries:   make([]RuntimeFunction, 0, count),
	}
	addr := imageBase + uint64(rva)
	for i := uint32(0); i < count; i++ {
		off := addr + uint64(i)*12
		begin, _ := mem.Read32(off)
		end, _ := mem.Read32(off + 4)
		unwind, _ := mem.Read32(off + 8)
		if begin != 0 {
			et.Entries = append(et.Entries, RuntimeFunction{
				BeginAddress: begin,
				EndAddress:   end,
				UnwindData:   unwind,
				EntryAddr:    off,
			})
		}
	}
	sort.Slice(et.Entries, func(i, j int) bool {
		return et.Entries[i].BeginAddress < et.Entries[j].BeginAddress
	})
	return et
}

// Lookup finds the RUNTIME_FUNCTION covering a given RVA.
func (et *ExceptionTable) Lookup(rva uint32) *RuntimeFunction {
	if et == nil || len(et.Entries) == 0 {
		return nil
	}
	i := sort.Search(len(et.Entries), func(i int) bool {
		return et.Entries[i].EndAddress > rva
	})
	if i < len(et.Entries) && et.Entries[i].BeginAddress <= rva && rva < et.Entries[i].EndAddress {
		return &et.Entries[i]
	}
	return nil
}

// UNWIND_INFO flags
const (
	UnwFlagEHandler  = 0x01
	UnwFlagUHandler  = 0x02
	UnwFlagChainInfo = 0x04
)

// UnwindInfo parsed from guest memory.
type UnwindInfo struct {
	Version       uint8
	Flags         uint8
	SizeOfProlog  uint8
	CountOfCodes  uint8
	FrameRegister uint8
	FrameOffset   uint8
	HandlerRVA    uint32 // valid if Flags & (EHandler|UHandler)
	HandlerData   uint64 // guest addr of handler-specific data
	// Chained: valid if Flags & ChainInfo - points to parent function
	ChainedRF *RuntimeFunction
}

// ParseUnwindInfo reads UNWIND_INFO from guest memory.
func ParseUnwindInfo(mem *mmu.MMU, imageBase uint64, unwindRVA uint32) *UnwindInfo {
	addr := imageBase + uint64(unwindRVA)
	b0, _ := mem.Read8(addr)
	b1, _ := mem.Read8(addr + 1)
	b2, _ := mem.Read8(addr + 2)
	b3, _ := mem.Read8(addr + 3)

	ui := &UnwindInfo{
		Version:       b0 & 0x07,
		Flags:         (b0 >> 3) & 0x1F,
		SizeOfProlog:  b1,
		CountOfCodes:  b2,
		FrameRegister: b3 & 0x0F,
		FrameOffset:   (b3 >> 4) & 0x0F,
	}

	if ui.Flags&(UnwFlagEHandler|UnwFlagUHandler) != 0 {
		codesSize := uint64(ui.CountOfCodes) * 2
		if codesSize%4 != 0 {
			codesSize += 2
		}
		handlerAddr := addr + 4 + codesSize
		ui.HandlerRVA, _ = mem.Read32(handlerAddr)
		ui.HandlerData = handlerAddr + 4
	} else if ui.Flags&UnwFlagChainInfo != 0 {
		// Chained: after unwind codes is a RUNTIME_FUNCTION (12 bytes)
		codesSize := uint64(ui.CountOfCodes) * 2
		if codesSize%4 != 0 {
			codesSize += 2
		}
		chainAddr := addr + 4 + codesSize
		begin, _ := mem.Read32(chainAddr)
		end, _ := mem.Read32(chainAddr + 4)
		unwindData, _ := mem.Read32(chainAddr + 8)
		ui.ChainedRF = &RuntimeFunction{
			BeginAddress: begin,
			EndAddress:   end,
			UnwindData:   unwindData,
		}
	}

	return ui
}

// CxxCatchHandler holds the address of a catch funclet.
type CxxCatchHandler struct {
	FuncletRVA      uint32 // 0 if using fallback unwind
	EstablisherRBP  uint64 // establisher frame (high end, for funclet RDX)
	BodyRSP         uint64 // function body RSP (low end, for continuation)
	CatchObjOffset  int32
	ContinuationRVA uint32 // continuation address after try-catch (from IP-to-state map)
	catchHigh       int32  // internal: catchHigh from try block, for continuation lookup
	// Fallback: when we can't parse FH4, unwind to caller of handler frame
	FallbackRSP uint64
	FallbackRIP uint64
	IsFallback  bool
	// Saved non-volatile registers from unwind (index → value)
	SavedRegs map[int]uint64
}

// CxxDispatchException walks the stack to find a C++ catch handler.
func CxxDispatchException(mem *mmu.MMU, et *ExceptionTable, rsp, rip uint64, trace bool) *CxxCatchHandler {
	if et == nil {
		return nil
	}
	imageBase := et.ImageBase
	imageEnd := imageBase + 0x10000000 // reasonable max

	currentRSP := rsp
	currentRIP := rip

	// Always trace on failure path - retry with trace enabled if first pass fails
	result := cxxDispatch(mem, et, imageBase, imageEnd, rsp, rip, true)
	_ = currentRSP
	_ = currentRIP
	return result
}

func cxxDispatch(mem *mmu.MMU, et *ExceptionTable, imageBase, imageEnd uint64, rsp, rip uint64, trace bool) *CxxCatchHandler {
	if trace {
		ravelog.Logf("[seh] dispatch: RSP=0x%x RIP=0x%x imageBase=0x%x\n", rsp, rip, imageBase)
	}

	// Track saved registers across all frames for proper unwind
	savedRegs := make(map[int]uint64)

	currentRSP := rsp
	currentRIP := rip

	for depth := 0; depth < 64; depth++ {
		// Check if RIP is in the PE image range
		if currentRIP < imageBase || currentRIP >= imageEnd {
			retAddr, err := mem.Read64(currentRSP)
			if err != nil || retAddr == 0 {
				if trace {
					ravelog.Logf("[seh] depth %d: RIP 0x%x out of range, retAddr read failed\n", depth, currentRIP)
				}
				return nil
			}
			if trace {
				ravelog.Logf("[seh] depth %d: RIP 0x%x out of range, following retAddr 0x%x\n", depth, currentRIP, retAddr)
			}
			currentRIP = retAddr
			currentRSP += 8
			continue
		}

		rva := uint32(currentRIP - imageBase)
		rf := et.Lookup(rva)
		if rf == nil {
			retAddr, err := mem.Read64(currentRSP)
			if err != nil || retAddr == 0 {
				return nil
			}
			if trace {
				ravelog.Logf("[seh] depth %d: RVA 0x%x no .pdata, following retAddr 0x%x\n", depth, rva, retAddr)
			}
			currentRIP = retAddr
			currentRSP += 8
			continue
		}

		ui := ParseUnwindInfo(mem, imageBase, rf.UnwindData)
		if ui == nil {
			return nil
		}

		// Walk unwind codes to compute frame size AND collect saved registers
		frameSize := unwindFrame(mem, imageBase+uint64(rf.UnwindData), ui, currentRSP, savedRegs)
		parentRSP := currentRSP + frameSize

		if trace {
			ravelog.Logf("[seh] depth %d: RVA 0x%x func [0x%x-0x%x] flags=0x%x frameSize=%d\n",
				depth, rva, rf.BeginAddress, rf.EndAddress, ui.Flags, frameSize)
		}

		// Follow CHAININFO: accumulate frame size from chained parent.
		// The secondary (chained) record covers part of the prolog but the return
		// address (+8) is counted only by the primary (parent) record. So we
		// subtract 8 from the secondary's frame size before handing off to the primary.
		chainedUI := ui
		chainedRSP := currentRSP + (frameSize - 8) // strip the virtual return-addr slot
		for chainedUI.Flags&UnwFlagChainInfo != 0 && chainedUI.ChainedRF != nil {
			parentUI := ParseUnwindInfo(mem, imageBase, chainedUI.ChainedRF.UnwindData)
			if parentUI == nil {
				break
			}
			parentFrameSize := unwindFrame(mem, imageBase+uint64(chainedUI.ChainedRF.UnwindData), parentUI, chainedRSP, savedRegs)
			if trace {
				ravelog.Logf("[seh] depth %d: chain → func [0x%x-0x%x] flags=0x%x parentFrameSize=%d chainedRSP=0x%x\n",
					depth, chainedUI.ChainedRF.BeginAddress, chainedUI.ChainedRF.EndAddress, parentUI.Flags, parentFrameSize, chainedRSP)
			}
			chainedParentRSP := chainedRSP + parentFrameSize
			if parentUI.Flags&UnwFlagEHandler != 0 {
				// Found the exception handler in the chained parent
				handler := findCxxCatchAll(mem, imageBase, parentUI, chainedUI.ChainedRF.BeginAddress, chainedRSP, currentRIP, chainedParentRSP, trace)
				if handler != nil {
					handler.SavedRegs = make(map[int]uint64, len(savedRegs))
					for k, v := range savedRegs {
						handler.SavedRegs[k] = v
					}
					return handler
				}
			}
			chainedUI = parentUI
			if parentUI.Flags&UnwFlagChainInfo != 0 {
				// Continue chain: strip return-addr slot again for next secondary
				chainedRSP = chainedParentRSP - 8
			} else {
				chainedRSP = chainedParentRSP
			}
		}
		// Update parentRSP to the resolved chained parent RSP if we followed a chain
		if chainedRSP != currentRSP+(frameSize-8) {
			parentRSP = chainedRSP
		}

		if ui.Flags&UnwFlagEHandler != 0 {
			handler := findCxxCatchAll(mem, imageBase, ui, rf.BeginAddress, currentRSP, currentRIP, parentRSP, trace)
			if handler != nil {
				// Attach accumulated saved registers for proper unwind
				handler.SavedRegs = make(map[int]uint64, len(savedRegs))
				for k, v := range savedRegs {
					handler.SavedRegs[k] = v
				}
				return handler
			}
		}

		// Move to parent frame
		retAddr, err := mem.Read64(parentRSP - 8)
		if err != nil || retAddr == 0 {
			if trace {
				ravelog.Logf("[seh] depth %d: parentRSP 0x%x retAddr read failed\n", depth, parentRSP)
			}
			return nil
		}
		if trace {
			ravelog.Logf("[seh] depth %d: → parent retAddr 0x%x parentRSP 0x%x\n", depth, retAddr, parentRSP)
		}
		currentRIP = retAddr
		currentRSP = parentRSP
	}

	return nil
}

// x64 register indices are defined in trap.go (regRAX through regR15)

// unwindFrame walks unwind codes to compute frame size and restore saved registers.
// savedRegs is updated with register values read from the stack.
func unwindFrame(mem *mmu.MMU, unwindInfoAddr uint64, ui *UnwindInfo, rsp uint64, savedRegs map[int]uint64) uint64 {
	var totalSize uint64
	codesAddr := unwindInfoAddr + 4
	pushOffset := rsp // tracks where pushed regs are on the stack

	// First pass: compute total allocation size (excluding pushes) for correct push offsets
	var allocSize uint64
	i := uint8(0)
	for i < ui.CountOfCodes {
		codeAddr := codesAddr + uint64(i)*2
		_, _ = mem.Read8(codeAddr)
		opInfo, _ := mem.Read8(codeAddr + 1)
		op := opInfo & 0x0F
		info := (opInfo >> 4) & 0x0F

		switch op {
		case 0: // UWOP_PUSH_NONVOL
			i++
		case 1: // UWOP_ALLOC_LARGE
			if info == 0 {
				if i+1 < ui.CountOfCodes {
					sizeSlot, _ := mem.Read16(codesAddr + uint64(i+1)*2)
					allocSize += uint64(sizeSlot) * 8
				}
				i += 2
			} else {
				if i+2 < ui.CountOfCodes {
					lo, _ := mem.Read16(codesAddr + uint64(i+1)*2)
					hi, _ := mem.Read16(codesAddr + uint64(i+2)*2)
					allocSize += uint64(lo) | (uint64(hi) << 16)
				}
				i += 3
			}
		case 2: // UWOP_ALLOC_SMALL
			allocSize += uint64(info)*8 + 8
			i++
		default:
			// Other codes don't affect size calculation for push offsets
			switch op {
			case 4, 8: // UWOP_SAVE_NONVOL, UWOP_SAVE_XMM128
				i += 2
			case 5, 9: // UWOP_SAVE_NONVOL_FAR, UWOP_SAVE_XMM128_FAR
				i += 3
			default:
				i++
			}
		}
	}

	// The stack layout (top to bottom) is:
	// [RSP] → allocations → pushed regs → return address
	// pushOffset starts at RSP + allocSize
	pushOffset = rsp + allocSize
	totalSize = allocSize

	// Second pass: read pushed registers and compute total frame size
	i = 0
	var saveBaseRSP uint64 = rsp // base for UWOP_SAVE_NONVOL offsets
	for i < ui.CountOfCodes {
		codeAddr := codesAddr + uint64(i)*2
		_, _ = mem.Read8(codeAddr)
		opInfo, _ := mem.Read8(codeAddr + 1)
		op := opInfo & 0x0F
		info := (opInfo >> 4) & 0x0F

		switch op {
		case 0: // UWOP_PUSH_NONVOL
			reg := int(info)
			val, err := mem.Read64(pushOffset)
			if err == nil {
				savedRegs[reg] = val
			}
			pushOffset += 8
			totalSize += 8
			i++
		case 1: // UWOP_ALLOC_LARGE - already counted
			if info == 0 {
				i += 2
			} else {
				i += 3
			}
		case 2: // UWOP_ALLOC_SMALL - already counted
			i++
		case 3: // UWOP_SET_FPREG
			i++
		case 4: // UWOP_SAVE_NONVOL
			reg := int(info)
			if i+1 < ui.CountOfCodes {
				off, _ := mem.Read16(codesAddr + uint64(i+1)*2)
				val, err := mem.Read64(saveBaseRSP + uint64(off)*8)
				if err == nil {
					savedRegs[reg] = val
				}
			}
			i += 2
		case 5: // UWOP_SAVE_NONVOL_FAR
			reg := int(info)
			if i+2 < ui.CountOfCodes {
				lo, _ := mem.Read16(codesAddr + uint64(i+1)*2)
				hi, _ := mem.Read16(codesAddr + uint64(i+2)*2)
				off := uint64(lo) | (uint64(hi) << 16)
				val, err := mem.Read64(saveBaseRSP + off)
				if err == nil {
					savedRegs[reg] = val
				}
			}
			i += 3
		case 8: // UWOP_SAVE_XMM128
			i += 2
		case 9: // UWOP_SAVE_XMM128_FAR
			i += 3
		case 10: // UWOP_PUSH_MACHFRAME
			if info == 0 {
				totalSize += 40
			} else {
				totalSize += 48
			}
			i++
		default:
			i++
		}
	}
	// Return address is part of the frame
	totalSize += 8
	return totalSize
}

// findCxxCatchAll parses MSVC FuncInfo to find a catch handler.
// All offsets in FuncInfo/TryBlockMap/HandlerType are image-relative RVAs.
// funcBeginRVA is the start RVA of the function from RUNTIME_FUNCTION.
func findCxxCatchAll(mem *mmu.MMU, imageBase uint64, ui *UnwindInfo, funcBeginRVA uint32, rsp, rip, parentRSP uint64, trace bool) *CxxCatchHandler {
	funcInfoRVA, _ := mem.Read32(ui.HandlerData)
	if funcInfoRVA == 0 {
		return nil
	}
	funcInfoAddr := imageBase + uint64(funcInfoRVA)

	// Compute the establisher frame per RtlVirtualUnwind:
	// - With frame register: RSP at handler depth (= FrameReg - FrameOffset*16)
	// - Without: parentRSP (caller's RSP after unwind)
	var establisher uint64
	if ui.FrameRegister != 0 {
		establisher = rsp
	} else {
		establisher = parentRSP
	}

	magic, _ := mem.Read32(funcInfoAddr)
	if trace {
		ravelog.Logf("[seh]   handlerRVA=0x%x funcInfoRVA=0x%x magic=0x%x establisher=0x%x frameReg=%d\n",
			ui.HandlerRVA, funcInfoRVA, magic, establisher, ui.FrameRegister)
	}

	// Accept standard MSVC magic numbers (FH3: __CxxFrameHandler3)
	baseMagic := magic & 0x1FFFFFFF
	if baseMagic < 0x19930520 || baseMagic > 0x19930522 {
		// Try FH4 format (__CxxFrameHandler4)
		handler := parseFH4CatchAll(mem, imageBase, funcInfoAddr, funcBeginRVA, rsp, rip, establisher, trace)
		if handler != nil {
			return handler
		}
		// FH4 parse found no matching catch - fallback: unwind past this frame
		retAddr, err := mem.Read64(parentRSP - 8)
		if err != nil || retAddr == 0 {
			if trace {
				ravelog.Logf("[seh]   FH4 no match, can't read parent retAddr\n")
			}
			return nil
		}
		if trace {
			ravelog.Logf("[seh]   FH4 no match - fallback unwind to retAddr=0x%x RSP=0x%x\n", retAddr, parentRSP)
		}
		return &CxxCatchHandler{
			IsFallback:  true,
			FallbackRSP: parentRSP,
			FallbackRIP: retAddr,
		}
	}

	nTryBlocks, _ := mem.Read32(funcInfoAddr + 12)
	if nTryBlocks == 0 {
		return nil
	}
	// Image-relative RVA to try block map
	tryBlockMapRVA, _ := mem.Read32(funcInfoAddr + 16)
	tryBlockMapAddr := imageBase + uint64(tryBlockMapRVA)

	// IP-to-state map for computing throw state
	nIPMap, _ := mem.Read32(funcInfoAddr + 20)
	ipMapRVA, _ := mem.Read32(funcInfoAddr + 24)
	throwState := int32(-1)
	if nIPMap > 0 && nIPMap < 10000 && ipMapRVA != 0 {
		ipMapAddr := imageBase + uint64(ipMapRVA)
		throwRVA := uint32(rip - imageBase)
		for j := uint32(0); j < nIPMap; j++ {
			ipRVA, _ := mem.Read32(ipMapAddr + uint64(j)*8)
			st := int32(0)
			v, _ := mem.Read32(ipMapAddr + uint64(j)*8 + 4)
			st = int32(v)
			if ipRVA <= throwRVA {
				throwState = st
			}
		}
	}

	if trace {
		ravelog.Logf("[seh]   nTryBlocks=%d throwState=%d\n", nTryBlocks, throwState)
	}

	// Walk try blocks
	for i := uint32(0); i < nTryBlocks && i < 100; i++ {
		entryAddr := tryBlockMapAddr + uint64(i)*20
		tryLow := int32(0)
		tryHigh := int32(0)
		v, _ := mem.Read32(entryAddr)
		tryLow = int32(v)
		v, _ = mem.Read32(entryAddr + 4)
		tryHigh = int32(v)
		nCatches, _ := mem.Read32(entryAddr + 12)
		handlerArrayRVA, _ := mem.Read32(entryAddr + 16)

		if trace {
			ravelog.Logf("[seh]   tryBlock[%d]: low=%d high=%d nCatches=%d handlerArrayRVA=0x%x\n",
				i, tryLow, tryHigh, nCatches, handlerArrayRVA)
		}

		if throwState < tryLow || throwState > tryHigh {
			continue
		}
		if nCatches == 0 || nCatches > 100 || handlerArrayRVA == 0 {
			continue
		}

		handlerArrayAddr := imageBase + uint64(handlerArrayRVA)

		// Walk catch handlers
		for c := uint32(0); c < nCatches; c++ {
			// HandlerType: adjectives(4) pType(4) dispCatchObj(4) addressOfHandler(4) dispFrame(4)
			hAddr := handlerArrayAddr + uint64(c)*20
			typeRVA, _ := mem.Read32(hAddr + 4)
			catchObjDisp, _ := mem.Read32(hAddr + 8)
			handlerRVA, _ := mem.Read32(hAddr + 12)

			if trace {
				ravelog.Logf("[seh]     catch[%d]: typeRVA=0x%x handlerRVA=0x%x\n", c, typeRVA, handlerRVA)
			}

			// catch(...) has typeRVA == 0
			if typeRVA == 0 && handlerRVA != 0 {
				return &CxxCatchHandler{
					FuncletRVA:     handlerRVA,
					EstablisherRBP: establisher,
					BodyRSP:        rsp,
					CatchObjOffset: int32(catchObjDisp),
				}
			}
		}

		// If no catch(...) found but there are typed catch handlers,
		// use the last one as fallback (common pattern: catch(exception&))
		if nCatches > 0 {
			lastH := handlerArrayAddr + uint64(nCatches-1)*20
			handlerRVA, _ := mem.Read32(lastH + 12)
			catchObjDisp, _ := mem.Read32(lastH + 8)
			if handlerRVA != 0 {
				return &CxxCatchHandler{
					FuncletRVA:     handlerRVA,
					EstablisherRBP: establisher,
					BodyRSP:        rsp,
					CatchObjOffset: int32(catchObjDisp),
				}
			}
		}
	}

	return nil
}

// ─── FH4 (__CxxFrameHandler4) compressed format parsing ───

// readFH4Uint reads an FH4 variable-length unsigned integer.
// Returns the value and the number of bytes consumed.
func readFH4Uint(mem *mmu.MMU, addr uint64) (uint32, uint64) {
	b, err := mem.Read8(addr)
	if err != nil {
		return 0, 1
	}
	if (b & 1) == 0 {
		return uint32(b) >> 1, 1
	}
	if (b & 3) == 1 {
		b2, _ := mem.Read8(addr + 1)
		return (uint32(b) >> 2) | (uint32(b2) << 6), 2
	}
	if (b & 7) == 3 {
		b2, _ := mem.Read8(addr + 1)
		b3, _ := mem.Read8(addr + 2)
		return (uint32(b) >> 3) | (uint32(b2) << 5) | (uint32(b3) << 13), 3
	}
	if (b & 15) == 7 {
		b2, _ := mem.Read8(addr + 1)
		b3, _ := mem.Read8(addr + 2)
		b4, _ := mem.Read8(addr + 3)
		return (uint32(b) >> 4) | (uint32(b2) << 4) | (uint32(b3) << 12) | (uint32(b4) << 20), 4
	}
	// 5-byte form: marker byte then raw uint32
	v, _ := mem.Read32(addr + 1)
	return v, 5
}

// readFH4Int reads an FH4 variable-length signed integer (zigzag encoded).
func readFH4Int(mem *mmu.MMU, addr uint64) (int32, uint64) {
	u, n := readFH4Uint(mem, addr)
	return int32(u>>1) ^ -int32(u&1), n
}

// parseFH4CatchAll parses an FH4 FuncInfo structure to find a catch handler.
// FH4 FuncInfo contains a header byte followed by 4-byte image-relative RVAs.
// Compressed integers (counts, states) live at the destination addresses.
func parseFH4CatchAll(mem *mmu.MMU, imageBase uint64, funcInfoAddr uint64,
	funcBeginRVA uint32, rsp, rip, parentRSP uint64, trace bool) *CxxCatchHandler {

	header, _ := mem.Read8(funcInfoAddr)
	offset := uint64(1)

	if trace {
		var hexDump string
		for i := uint64(0); i < 16; i++ {
			b, _ := mem.Read8(funcInfoAddr + i)
			hexDump += fmt.Sprintf("%02x ", b)
		}
		ravelog.Logf("[seh-fh4] header=0x%x at 0x%x funcBeginRVA=0x%x\n  bytes: %s\n", header, funcInfoAddr, funcBeginRVA, hexDump)
	}

	// Header flags
	isCatch := header&1 != 0
	// isSeparated := header & 2 != 0
	hasBBT := header&4 != 0
	hasUnwindMap := header&8 != 0
	hasTryBlockMap := header&0x10 != 0
	// isEHs := header & 0x20 != 0
	// hasNoExcept := header & 0x40 != 0

	if isCatch {
		if trace {
			ravelog.Logf("[seh-fh4] isCatch set - skipping\n")
		}
		return nil
	}

	if hasBBT {
		offset++
	}

	// FH4 FuncInfo layout: header then RVAs only (no inline counts)
	if hasUnwindMap {
		offset += 4 // skip unwindMapRVA
	}

	if !hasTryBlockMap {
		if trace {
			ravelog.Logf("[seh-fh4] no try block map\n")
		}
		return nil
	}

	tryBlockMapRVA, _ := mem.Read32(funcInfoAddr + offset)
	offset += 4

	ipToStateMapRVA, _ := mem.Read32(funcInfoAddr + offset)
	offset += 4

	if trace {
		ravelog.Logf("[seh-fh4] tryBlockMapRVA=0x%x ipToStateMapRVA=0x%x\n", tryBlockMapRVA, ipToStateMapRVA)
	}

	// Sanity check RVAs
	if tryBlockMapRVA == 0 || tryBlockMapRVA > 0x10000000 {
		return nil
	}
	if ipToStateMapRVA > 0x10000000 {
		ipToStateMapRVA = 0
	}

	// Read try block map: starts with numTryBlocks (compressed uint)
	tryBlockMapAddr := imageBase + uint64(tryBlockMapRVA)
	numTryBlocks, n := readFH4Uint(mem, tryBlockMapAddr)
	tryBlockDataAddr := tryBlockMapAddr + n

	if trace {
		ravelog.Logf("[seh-fh4] numTryBlocks=%d\n", numTryBlocks)
	}
	if numTryBlocks == 0 || numTryBlocks > 1000 {
		return nil
	}

	// Compute throw state from IP-to-state map
	throwState := int32(-1)
	var ipMapDataAddr uint64
	var numIPMapEntries uint32
	if ipToStateMapRVA != 0 {
		ipMapAddr := imageBase + uint64(ipToStateMapRVA)
		numIPMap, ipn := readFH4Uint(mem, ipMapAddr)
		ipMapDataAddr = ipMapAddr + ipn
		numIPMapEntries = numIPMap
		if numIPMap > 0 && numIPMap < 100000 {
			throwState = fh4ComputeThrowState(mem, ipMapDataAddr, imageBase, funcBeginRVA, rip, numIPMap, trace)
		}
		if trace {
			ravelog.Logf("[seh-fh4] numIPMap=%d throwState=%d\n", numIPMap, throwState)
		}
	}

	handler := fh4FindCatch(mem, imageBase, tryBlockDataAddr, numTryBlocks, throwState, parentRSP,
		funcBeginRVA, ipMapDataAddr, numIPMapEntries, trace)
	if handler != nil {
		handler.BodyRSP = rsp // function body RSP (for continuation)
		if handler.ContinuationRVA == 0 && ipMapDataAddr != 0 {
			// Compute continuation RVA from IP-to-state map if not found in catch entries
			handler.ContinuationRVA = fh4FindContinuation(mem, ipMapDataAddr, funcBeginRVA, numIPMapEntries, handler)
			if trace {
				ravelog.Logf("[seh-fh4] fallback continuation RVA=0x%x\n", handler.ContinuationRVA)
			}
		}
	}
	return handler
}

// fh4ComputeThrowState walks the FH4 IP-to-state map to find the state at the throw point.
// dataAddr points to the first entry (after the numEntries count has been read).
func fh4ComputeThrowState(mem *mmu.MMU, dataAddr uint64, imageBase uint64,
	funcStartRVA uint32, rip uint64, numEntries uint32, trace bool) int32 {

	addr := dataAddr
	throwRVA := uint32(rip - imageBase)
	state := int32(-1)
	currentIP := funcStartRVA

	for i := uint32(0); i < numEntries; i++ {
		ipDelta, n := readFH4Uint(mem, addr)
		addr += n
		st, n := readFH4Int(mem, addr)
		addr += n

		currentIP += ipDelta
		if currentIP <= throwRVA {
			state = st
		}
		if trace && i < 20 {
			ravelog.Logf("[seh-fh4]   ipMap[%d]: ip=0x%x (delta=%d) state=%d\n", i, currentIP, ipDelta, st)
		}
	}

	return state
}

// fh4FindContinuation scans the IP-to-state map to find the continuation RVA.
// The continuation is the first IP where state drops below the catch region
// (state < catchHigh) after being in the catch region.
func fh4FindContinuation(mem *mmu.MMU, dataAddr uint64, funcStartRVA uint32,
	numEntries uint32, handler *CxxCatchHandler) uint32 {

	addr := dataAddr
	currentIP := funcStartRVA
	inCatchRegion := false

	for i := uint32(0); i < numEntries; i++ {
		ipDelta, n := readFH4Uint(mem, addr)
		addr += n
		st, n := readFH4Int(mem, addr)
		addr += n

		currentIP += ipDelta

		if st >= 0 && st <= handler.catchHigh {
			inCatchRegion = true
		}
		if inCatchRegion && (st < 0 || st > handler.catchHigh) {
			return currentIP
		}
	}
	return 0
}

// fh4IPFromStateIndex looks up an IP from the IP-to-state map by entry index.
func fh4IPFromStateIndex(mem *mmu.MMU, dataAddr uint64, funcStartRVA uint32,
	numEntries uint32, index uint32) uint32 {

	if index >= numEntries {
		return 0
	}
	addr := dataAddr
	currentIP := funcStartRVA

	for i := uint32(0); i <= index; i++ {
		ipDelta, n := readFH4Uint(mem, addr)
		addr += n
		_, n = readFH4Int(mem, addr) // skip state
		addr += n
		currentIP += ipDelta
	}
	return currentIP
}

// fh4FindCatch walks FH4 try block map to find a matching catch handler.
// Try block entries: tryLow(compressed), tryHigh(compressed), catchHigh(compressed), catchHandlersRVA(int32).
// The catch handler count is stored at the destination address, not inline.
func fh4FindCatch(mem *mmu.MMU, imageBase uint64, tryBlockDataAddr uint64,
	numTryBlocks uint32, throwState int32, parentRSP uint64,
	funcBeginRVA uint32, ipMapDataAddr uint64, numIPMapEntries uint32, trace bool) *CxxCatchHandler {

	addr := tryBlockDataAddr

	for i := uint32(0); i < numTryBlocks; i++ {
		tryLow, n := readFH4Uint(mem, addr)
		addr += n
		tryHigh, n := readFH4Uint(mem, addr)
		addr += n
		catchHigh, n := readFH4Uint(mem, addr)
		addr += n
		catchesRVA, _ := mem.Read32(addr)
		addr += 4

		if trace {
			ravelog.Logf("[seh-fh4]   tryBlock[%d]: low=%d high=%d catchHigh=%d catchesRVA=0x%x\n",
				i, tryLow, tryHigh, catchHigh, catchesRVA)
		}

		if throwState < int32(tryLow) || throwState > int32(tryHigh) {
			continue
		}
		if catchesRVA == 0 || catchesRVA > 0x10000000 {
			continue
		}

		// Read numCatches from the catch handlers destination
		catchDestAddr := imageBase + uint64(catchesRVA)
		numCatches, cn := readFH4Uint(mem, catchDestAddr)
		catchDataAddr := catchDestAddr + cn

		if trace {
			ravelog.Logf("[seh-fh4]   numCatches=%d at 0x%x\n", numCatches, catchDestAddr)
		}
		if numCatches == 0 || numCatches > 100 {
			continue
		}

		handler := fh4ParseCatches(mem, imageBase, catchDataAddr, numCatches, parentRSP,
			funcBeginRVA, ipMapDataAddr, numIPMapEntries, trace)
		if handler != nil {
			handler.catchHigh = int32(catchHigh)
			return handler
		}
	}

	return nil
}

// fh4ParseCatches walks FH4 catch handler entries to find a matching handler.
// Prefers catch(...) (no type descriptor), falls back to any typed handler.
// Also extracts continuation addresses from entries with bit5 set.
func fh4ParseCatches(mem *mmu.MMU, imageBase uint64, catchAddr uint64,
	numCatches uint32, parentRSP uint64, funcBeginRVA uint32,
	ipMapDataAddr uint64, numIPMapEntries uint32, trace bool) *CxxCatchHandler {

	addr := catchAddr

	type catchEntry struct {
		hasTypeDesc bool
		handlerRVA  uint32
		catchObj    int32
		contAddr    uint32 // continuation RVA (0 if not present)
	}
	entries := make([]catchEntry, 0, numCatches)

	for c := uint32(0); c < numCatches; c++ {
		hdr, _ := mem.Read8(addr)
		addr++

		hasAdjectives := hdr&1 != 0
		hasTypeDesc := hdr&2 != 0
		hasCatchObj := hdr&4 != 0
		contIsRVA := hdr&8 != 0
		hasHandler := hdr&0x10 != 0
		hasContAddr := hdr&0x20 != 0

		if hasAdjectives {
			_, n := readFH4Uint(mem, addr)
			addr += n
		}

		var typeDescRVA uint32
		if hasTypeDesc {
			typeDescRVA, _ = mem.Read32(addr)
			addr += 4
		}

		var catchObjOffset int32
		if hasCatchObj {
			v, n := readFH4Uint(mem, addr)
			addr += n
			catchObjOffset = int32(v)
		}

		var handlerRVA uint32
		if hasHandler {
			handlerRVA, _ = mem.Read32(addr)
			addr += 4
		}

		// Read continuation address (bit5)
		var contRVA uint32
		if hasContAddr {
			if contIsRVA {
				// Function-relative offset
				off, n := readFH4Uint(mem, addr)
				addr += n
				contRVA = funcBeginRVA + off
			} else {
				// IP-to-state map index → look up the actual IP
				idx, n := readFH4Uint(mem, addr)
				addr += n
				contRVA = fh4IPFromStateIndex(mem, ipMapDataAddr, funcBeginRVA, numIPMapEntries, idx)
			}
		}

		if trace {
			ravelog.Logf("[seh-fh4]     catch[%d]: hdr=0x%x typeDescRVA=0x%x handlerRVA=0x%x catchObj=%d contRVA=0x%x\n",
				c, hdr, typeDescRVA, handlerRVA, catchObjOffset, contRVA)
		}

		entries = append(entries, catchEntry{
			hasTypeDesc: hasTypeDesc,
			handlerRVA:  handlerRVA,
			catchObj:    catchObjOffset,
			contAddr:    contRVA,
		})
	}

	// Collect the best continuation address from all entries
	var bestCont uint32
	for _, e := range entries {
		if e.contAddr != 0 {
			bestCont = e.contAddr
			break
		}
	}

	// Prefer catch(...) - no type descriptor, with handler
	for _, e := range entries {
		if !e.hasTypeDesc && e.handlerRVA != 0 {
			if trace {
				ravelog.Logf("[seh-fh4]   → catch(...) funclet RVA=0x%x establisher=0x%x cont=0x%x\n", e.handlerRVA, parentRSP, bestCont)
			}
			cont := e.contAddr
			if cont == 0 {
				cont = bestCont
			}
			return &CxxCatchHandler{
				FuncletRVA:      e.handlerRVA,
				EstablisherRBP:  parentRSP,
				CatchObjOffset:  e.catchObj,
				ContinuationRVA: cont,
			}
		}
	}

	// Catch-all continuation without funclet = CRT terminate path.
	// Don't dispatch - returning nil lets _CxxThrowException return
	// to its caller, which often continues correctly.
	return nil
}

// FormatCxxException returns a description of a C++ exception dispatch.
func FormatCxxException(handler *CxxCatchHandler, imageBase uint64) string {
	if handler == nil {
		return "no handler found"
	}
	return fmt.Sprintf("catch funclet at RVA 0x%x (VA 0x%x), RBP=0x%x",
		handler.FuncletRVA, imageBase+uint64(handler.FuncletRVA), handler.EstablisherRBP)
}

var _ = binary.LittleEndian

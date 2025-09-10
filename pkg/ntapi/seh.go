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
			et.Entries = append(et.Entries, RuntimeFunction{begin, end, unwind})
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
		ui.ChainedRF = &RuntimeFunction{begin, end, unwindData}
	}

	return ui
}

// CxxCatchHandler holds the address of a catch funclet.
type CxxCatchHandler struct {
	FuncletRVA     uint32 // 0 if using fallback unwind
	EstablisherRBP uint64
	CatchObjOffset int32
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
	result := cxxDispatch(mem, et, imageBase, imageEnd, rsp, rip, trace)
	if result == nil && !trace {
		ravelog.Logf("[seh] no handler found for RIP=0x%x RSP=0x%x - retrying with trace\n", rip, rsp)
		cxxDispatch(mem, et, imageBase, imageEnd, currentRSP, currentRIP, true)
	}
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
				handler := findCxxCatchAll(mem, imageBase, parentUI, chainedRSP, currentRIP, chainedParentRSP, trace)
				if handler != nil {
					if handler.IsFallback {
						handler.SavedRegs = make(map[int]uint64, len(savedRegs))
						for k, v := range savedRegs {
							handler.SavedRegs[k] = v
						}
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
			handler := findCxxCatchAll(mem, imageBase, ui, currentRSP, currentRIP, parentRSP, trace)
			if handler != nil {
				if handler.IsFallback {
					// Attach accumulated saved registers for proper unwind
					handler.SavedRegs = make(map[int]uint64, len(savedRegs))
					for k, v := range savedRegs {
						handler.SavedRegs[k] = v
					}
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
func findCxxCatchAll(mem *mmu.MMU, imageBase uint64, ui *UnwindInfo, rsp, rip, parentRSP uint64, trace bool) *CxxCatchHandler {
	funcInfoRVA, _ := mem.Read32(ui.HandlerData)
	if funcInfoRVA == 0 {
		return nil
	}
	funcInfoAddr := imageBase + uint64(funcInfoRVA)

	magic, _ := mem.Read32(funcInfoAddr)
	if trace {
		ravelog.Logf("[seh]   handlerRVA=0x%x handlerData=0x%x funcInfoRVA=0x%x funcInfoAddr=0x%x magic=0x%x countOfCodes=%d\n",
			ui.HandlerRVA, ui.HandlerData, funcInfoRVA, funcInfoAddr, magic, ui.CountOfCodes)
	}

	// Accept standard MSVC magic numbers
	baseMagic := magic & 0x1FFFFFFF
	if baseMagic < 0x19930520 || baseMagic > 0x19930522 {
		// FH4 or other format we can't parse - return a fallback that
		// unwinds past this frame to its caller
		retAddr, err := mem.Read64(parentRSP - 8)
		if err != nil || retAddr == 0 {
			if trace {
				ravelog.Logf("[seh]   FH4 magic 0x%x - can't read parent retAddr\n", magic)
			}
			return nil
		}
		if trace {
			ravelog.Logf("[seh]   FH4 magic 0x%x - fallback unwind to retAddr=0x%x RSP=0x%x\n",
				magic, retAddr, parentRSP)
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
				// Estimate establisher frame: for functions with frame pointer,
				// RBP was saved; approximate from parentRSP
				rbp := parentRSP - 8

				return &CxxCatchHandler{
					FuncletRVA:     handlerRVA,
					EstablisherRBP: rbp,
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
				rbp := parentRSP - 8
				return &CxxCatchHandler{
					FuncletRVA:     handlerRVA,
					EstablisherRBP: rbp,
					CatchObjOffset: int32(catchObjDisp),
				}
			}
		}
	}

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


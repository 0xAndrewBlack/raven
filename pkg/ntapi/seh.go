//go:build guest_windows

package ntapi

import (
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

// CxxExceptionInfo is the payload of an MSVC C++ exception record.
type CxxExceptionInfo struct {
	Object    uint64
	ThrowInfo uint64
	ImageBase uint64
}

// DestructorAddress resolves the exception object's destructor from ThrowInfo.
func (e *CxxExceptionInfo) DestructorAddress(mem *mmu.MMU) (uint64, error) {
	if e == nil || e.ThrowInfo == 0 {
		return 0, nil
	}
	rva, err := mem.Read32(e.ThrowInfo + 4)
	if err != nil {
		return 0, err
	}
	if rva == 0 {
		return 0, nil
	}
	return e.ImageBase + uint64(rva), nil
}

const (
	CxxCatchableSimpleType       = 0x01
	CxxCatchableByReferenceOnly  = 0x02
	CxxCatchableVirtualBase      = 0x04
	CxxCatchableWinRT            = 0x08
	CxxExceptionFlagWinRT        = 0x10
	CxxConsolidateParameterCount = 10
)

type CxxUnwindActionKind uint8

const (
	CxxUnwindDestructorObject  CxxUnwindActionKind = 1
	CxxUnwindDestructorPointer CxxUnwindActionKind = 2
	CxxUnwindFrame             CxxUnwindActionKind = 3
)

type CxxUnwindAction struct {
	Kind          CxxUnwindActionKind
	ImageBase     uint64
	HandlerRVA    uint32
	Frame         uint64
	ObjectAddress uint64
}

// Arguments returns the object and establisher arguments for an unwind funclet.
func (a CxxUnwindAction) Arguments(mem *mmu.MMU) (uint64, uint64, error) {
	object := a.ObjectAddress
	if a.Kind == CxxUnwindDestructorPointer {
		value, err := mem.Read64(a.ObjectAddress)
		if err != nil {
			return 0, 0, err
		}
		object = value
	}
	return object, a.Frame, nil
}

// CxxCatchHandler describes the selected funclet and the unwind needed first.
type CxxCatchHandler struct {
	ImageBase         uint64
	FuncletRVA        uint32
	ControlPC         uint64
	EstablisherRBP    uint64
	BodyRSP           uint64
	CatchObjOffset    int32
	HasCatchObject    bool
	CatchObject       uint64
	CatchByReference  bool
	CatchObjectSize   uint32
	CatchCopyRVA      uint32
	CatchProperties   uint32
	CatchPointerValue uint64
	ThrowImageBase    uint64
	ContinuationRVA   uint32
	ContinuationRVAs  [2]uint32
	ContinuationCount uint8
	CatchState        int32
	UnwindTargetState int32
	// Saved non-volatile registers from unwind (index -> value)
	SavedRegs     map[int]uint64
	UnwindActions []CxxUnwindAction
}

// WriteCxxCatchObject materializes the selected catch object in the target frame.
func WriteCxxCatchObject(mem *mmu.MMU, handler *CxxCatchHandler, exception *CxxExceptionInfo) error {
	return MaterializeCxxCatchObject(mem, handler, exception, nil)
}

// MaterializeCxxCatchObject copies or constructs the selected catch object.
func MaterializeCxxCatchObject(mem *mmu.MMU, handler *CxxCatchHandler,
	exception *CxxExceptionInfo, guestCall GuestCallFunc) error {

	if handler == nil || (!handler.HasCatchObject && handler.CatchObjOffset == 0) {
		return nil
	}
	object := handler.CatchObject
	if object == 0 && exception != nil {
		object = exception.Object
	}
	destination := uint64(int64(handler.EstablisherRBP) + int64(handler.CatchObjOffset))
	if handler.CatchByReference {
		return mem.Write64(destination, object)
	}
	if handler.CatchObjectSize == 0 {
		return fmt.Errorf("by-value catch has zero object size")
	}
	if handler.CatchCopyRVA != 0 {
		if guestCall == nil {
			return fmt.Errorf("by-value catch copy constructor requires a guest caller")
		}
		copyAddress := handler.ThrowImageBase + uint64(handler.CatchCopyRVA)
		args := []uint64{destination, object}
		if handler.CatchProperties&CxxCatchableVirtualBase != 0 {
			args = append(args, 1)
		}
		if _, err := guestCall(copyAddress, args); err != nil {
			return fmt.Errorf("call catch copy constructor at 0x%x: %w", copyAddress, err)
		}
		return nil
	}
	data, err := mem.ReadBytes(object, int(handler.CatchObjectSize))
	if err != nil {
		return err
	}
	if err := mem.WriteBytes(destination, data); err != nil {
		return err
	}
	if handler.CatchProperties&CxxCatchableSimpleType != 0 &&
		handler.CatchObjectSize == 8 && handler.CatchPointerValue != 0 {
		return mem.Write64(destination, handler.CatchPointerValue)
	}
	return nil
}

// CxxDispatchException walks the stack to find a C++ catch handler.
func CxxDispatchException(mem *mmu.MMU, et *ExceptionTable, rsp, rip uint64, exception *CxxExceptionInfo, trace bool) *CxxCatchHandler {
	if et == nil {
		return nil
	}
	return cxxDispatch(mem, et, rsp, rip, exception, nil, trace)
}

// CxxDispatchExceptionAtState resumes a C++ search from a catch state during rethrow.
func CxxDispatchExceptionAtState(mem *mmu.MMU, et *ExceptionTable, rsp, rip uint64,
	exception *CxxExceptionInfo, state int32, trace bool) *CxxCatchHandler {

	if et == nil {
		return nil
	}
	return cxxDispatch(mem, et, rsp, rip, exception, &state, trace)
}

func cxxDispatch(mem *mmu.MMU, et *ExceptionTable, rsp, rip uint64,
	exception *CxxExceptionInfo, stateOverride *int32, trace bool) *CxxCatchHandler {
	if trace {
		ravelog.Logf("[seh] dispatch: RSP=0x%x RIP=0x%x imageBase=0x%x\n", rsp, rip, et.ImageBase)
	}

	// Track saved registers across all frames for proper unwind
	savedRegs := make(map[int]uint64)
	var unwindActions []CxxUnwindAction

	currentRSP := rsp
	currentRIP := rip

	for depth := 0; depth < 64; depth++ {
		var rf *RuntimeFunction
		imageBase := uint64(0)
		if currentRIP >= et.ImageBase {
			rf = et.Lookup(uint32(currentRIP - et.ImageBase))
			if rf != nil {
				imageBase = et.ImageBase
			}
		}
		if rf == nil {
			rf, imageBase, _ = LookupFunctionEntry(mem, currentRIP, nil)
		}
		if rf == nil {
			retAddr, err := mem.Read64(currentRSP)
			if err != nil || retAddr == 0 {
				if trace {
					ravelog.Logf("[seh] depth %d: RIP 0x%x has no runtime function, retAddr read failed\n", depth, currentRIP)
				}
				return nil
			}
			if trace {
				ravelog.Logf("[seh] depth %d: RIP 0x%x is a leaf, following retAddr 0x%x\n", depth, currentRIP, retAddr)
			}
			currentRIP = retAddr
			currentRSP += 8
			continue
		}

		rva := uint32(currentRIP - imageBase)

		ui := ParseUnwindInfo(mem, imageBase, rf.UnwindData)
		if ui == nil {
			return nil
		}

		// Keep this physical frame's restores separate. If its catch is selected,
		// the frame itself stays active and only restores from inner frames apply.
		frameSavedRegs := make(map[int]uint64)
		parentRSP := unwindFrame(
			mem,
			imageBase+uint64(rf.UnwindData),
			ui,
			currentRSP,
			savedRegs,
			frameSavedRegs,
		)

		if trace {
			ravelog.Logf("[seh] depth %d: RVA 0x%x func [0x%x-0x%x] flags=0x%x parentRSP=0x%x\n",
				depth, rva, rf.BeginAddress, rf.EndAddress, ui.Flags, parentRSP)
		}

		// Follow CHAININFO: accumulate frame size from chained parent.
		// The secondary (chained) record covers part of the prolog but the return
		// address (+8) is counted only by the primary (parent) record. So we
		// subtract 8 from the secondary's frame size before handing off to the primary.
		chainedUI := ui
		chainedRSP := parentRSP - 8
		initialChainedRSP := chainedRSP
		for chainedUI.Flags&UnwFlagChainInfo != 0 && chainedUI.ChainedRF != nil {
			parentUI := ParseUnwindInfo(mem, imageBase, chainedUI.ChainedRF.UnwindData)
			if parentUI == nil {
				break
			}
			chainedParentRSP := unwindFrame(
				mem,
				imageBase+uint64(chainedUI.ChainedRF.UnwindData),
				parentUI,
				chainedRSP,
				savedRegs,
				frameSavedRegs,
			)
			if trace {
				ravelog.Logf("[seh] depth %d: chain -> func [0x%x-0x%x] flags=0x%x parentRSP=0x%x chainedRSP=0x%x\n",
					depth, chainedUI.ChainedRF.BeginAddress, chainedUI.ChainedRF.EndAddress, parentUI.Flags, chainedParentRSP, chainedRSP)
			}
			if parentUI.Flags&UnwFlagEHandler != 0 {
				// Found the exception handler in the chained parent
				handler, frameActions := findCxxCatch(mem, imageBase, parentUI, chainedUI.ChainedRF.BeginAddress, chainedRSP, currentRIP, savedRegs, exception, stateOverride, trace)
				stateOverride = nil
				unwindActions = append(unwindActions, frameActions...)
				if handler != nil {
					handler.SavedRegs = make(map[int]uint64, len(savedRegs))
					for k, v := range savedRegs {
						handler.SavedRegs[k] = v
					}
					handler.UnwindActions = append([]CxxUnwindAction(nil), unwindActions...)
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
		if chainedRSP != initialChainedRSP {
			parentRSP = chainedRSP
		}

		if ui.Flags&UnwFlagEHandler != 0 {
			handler, frameActions := findCxxCatch(mem, imageBase, ui, rf.BeginAddress, currentRSP, currentRIP, savedRegs, exception, stateOverride, trace)
			stateOverride = nil
			unwindActions = append(unwindActions, frameActions...)
			if handler != nil {
				// Attach accumulated saved registers for proper unwind
				handler.SavedRegs = make(map[int]uint64, len(savedRegs))
				for k, v := range savedRegs {
					handler.SavedRegs[k] = v
				}
				handler.UnwindActions = append([]CxxUnwindAction(nil), unwindActions...)
				return handler
			}
		}

		for reg, value := range frameSavedRegs {
			savedRegs[reg] = value
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
			ravelog.Logf("[seh] depth %d: -> parent retAddr 0x%x parentRSP 0x%x\n", depth, retAddr, parentRSP)
		}
		currentRIP = retAddr
		currentRSP = parentRSP
	}

	return nil
}

// x64 register indices are defined in trap.go (regRAX through regR15)

// unwindFrame applies unwind codes and returns the caller's stack pointer.
func unwindFrame(mem *mmu.MMU, unwindInfoAddr uint64, ui *UnwindInfo, rsp uint64,
	registers, savedRegs map[int]uint64) uint64 {

	codesAddr := unwindInfoAddr + 4
	currentRSP := rsp
	i := uint8(0)
	for i < ui.CountOfCodes {
		codeAddr := codesAddr + uint64(i)*2
		_, _ = mem.Read8(codeAddr)
		opInfo, _ := mem.Read8(codeAddr + 1)
		op := opInfo & 0x0F
		info := (opInfo >> 4) & 0x0F

		switch op {
		case 0: // UWOP_PUSH_NONVOL
			reg := int(info)
			val, err := mem.Read64(currentRSP)
			if err == nil {
				savedRegs[reg] = val
			}
			currentRSP += 8
			i++
		case 1: // UWOP_ALLOC_LARGE
			if info == 0 {
				if i+1 < ui.CountOfCodes {
					size, _ := mem.Read16(codesAddr + uint64(i+1)*2)
					currentRSP += uint64(size) * 8
				}
				i += 2
			} else {
				if i+2 < ui.CountOfCodes {
					lo, _ := mem.Read16(codesAddr + uint64(i+1)*2)
					hi, _ := mem.Read16(codesAddr + uint64(i+2)*2)
					currentRSP += uint64(lo) | uint64(hi)<<16
				}
				i += 3
			}
		case 2: // UWOP_ALLOC_SMALL
			currentRSP += uint64(info)*8 + 8
			i++
		case 3: // UWOP_SET_FPREG
			if frameRegister, ok := registers[int(ui.FrameRegister)]; ok {
				currentRSP = frameRegister - uint64(ui.FrameOffset)*16
			}
			i++
		case 4: // UWOP_SAVE_NONVOL
			reg := int(info)
			if i+1 < ui.CountOfCodes {
				off, _ := mem.Read16(codesAddr + uint64(i+1)*2)
				val, err := mem.Read64(currentRSP + uint64(off)*8)
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
				val, err := mem.Read64(currentRSP + off)
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
				currentRSP += 40
			} else {
				currentRSP += 48
			}
			i++
		default:
			i++
		}
	}
	return currentRSP + 8
}

// findCxxCatch parses MSVC FuncInfo to find a catch handler.
// All offsets in FuncInfo/TryBlockMap/HandlerType are image-relative RVAs.
// funcBeginRVA is the start RVA of the function from RUNTIME_FUNCTION.
func findCxxCatch(mem *mmu.MMU, imageBase uint64, ui *UnwindInfo, funcBeginRVA uint32,
	rsp, rip uint64, registers map[int]uint64, exception *CxxExceptionInfo, stateOverride *int32,
	trace bool) (*CxxCatchHandler, []CxxUnwindAction) {
	funcInfoRVA, _ := mem.Read32(ui.HandlerData)
	if funcInfoRVA == 0 {
		return nil, nil
	}
	funcInfoAddr := imageBase + uint64(funcInfoRVA)

	establisher := rsp
	if frameRegister, ok := registers[int(ui.FrameRegister)]; ui.FrameRegister != 0 && ok {
		establisher = frameRegister - uint64(ui.FrameOffset)*16
	}

	magic, _ := mem.Read32(funcInfoAddr)
	if trace {
		ravelog.Logf("[seh]   handlerRVA=0x%x funcInfoRVA=0x%x magic=0x%x establisher=0x%x frameReg=%d\n",
			ui.HandlerRVA, funcInfoRVA, magic, establisher, ui.FrameRegister)
	}

	// Accept standard MSVC magic numbers (FH3: __CxxFrameHandler3)
	baseMagic := magic & 0x1FFFFFFF
	if baseMagic < 0x19930520 || baseMagic > 0x19930522 {
		return parseFH4CatchAll(mem, imageBase, funcInfoAddr, funcBeginRVA, rsp, rip,
			establisher, exception, stateOverride, trace)
	}

	nTryBlocks, _ := mem.Read32(funcInfoAddr + 12)
	if nTryBlocks == 0 {
		return nil, nil
	}
	// Image-relative RVA to try block map
	tryBlockMapRVA, _ := mem.Read32(funcInfoAddr + 16)
	tryBlockMapAddr := imageBase + uint64(tryBlockMapRVA)

	// IP-to-state map for computing throw state
	nIPMap, _ := mem.Read32(funcInfoAddr + 20)
	ipMapRVA, _ := mem.Read32(funcInfoAddr + 24)
	throwState := int32(-1)
	if stateOverride != nil {
		throwState = *stateOverride
	} else if nIPMap > 0 && nIPMap < 10000 && ipMapRVA != 0 {
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
			adjectives, _ := mem.Read32(hAddr)
			typeRVA, _ := mem.Read32(hAddr + 4)
			catchObjDisp, _ := mem.Read32(hAddr + 8)
			handlerRVA, _ := mem.Read32(hAddr + 12)

			if trace {
				ravelog.Logf("[seh]     catch[%d]: adjectives=0x%x typeRVA=0x%x handlerRVA=0x%x\n",
					c, adjectives, typeRVA, handlerRVA)
			}

			catchEntry := fh4CatchEntry{
				flags:        adjectives,
				typeRVA:      typeRVA,
				objectOffset: int32(catchObjDisp),
				hasObject:    typeRVA != 0,
				handlerRVA:   handlerRVA,
			}
			match, err := fh4MatchTypedCatchInfo(mem, imageBase, catchEntry, exception)
			if err != nil {
				if trace {
					ravelog.Logf("[seh]     catch[%d] type metadata error: %v\n", c, err)
				}
				continue
			}
			if !match.matched || handlerRVA == 0 {
				continue
			}
			return &CxxCatchHandler{
				ImageBase:         imageBase,
				FuncletRVA:        handlerRVA,
				ControlPC:         rip,
				EstablisherRBP:    establisher,
				BodyRSP:           rsp,
				CatchObjOffset:    int32(catchObjDisp),
				HasCatchObject:    typeRVA != 0,
				CatchObject:       match.object,
				CatchByReference:  match.byReference,
				CatchObjectSize:   match.size,
				CatchCopyRVA:      match.copyRVA,
				CatchProperties:   match.properties,
				CatchPointerValue: match.pointerValue,
				ThrowImageBase:    match.throwBase,
			}, nil
		}
	}

	return nil, nil
}

// --- FH4 (__CxxFrameHandler4) compressed format parsing ---

// readFH4Uint reads an FH4 variable-length unsigned integer.
// Returns the value and the number of bytes consumed.
func readFH4Uint(mem *mmu.MMU, addr uint64) (uint32, uint64) {
	value, size, _ := readFH4UintChecked(mem, addr)
	return value, size
}

// readFH4Int reads an FH4 state value encoded as decode_uint() - 1.
func readFH4Int(mem *mmu.MMU, addr uint64) (int32, uint64) {
	u, n := readFH4Uint(mem, addr)
	return int32(u) - 1, n
}

const (
	fh4FuncIsCatch     = 0x01
	fh4FuncIsSeparated = 0x02
	fh4FuncHasBBT      = 0x04
	fh4FuncHasUnwind   = 0x08
	fh4FuncHasTry      = 0x10
	fh4FuncValidMask   = 0x7f
)

type fh4FunctionInfo struct {
	header        uint8
	unwindCount   uint32
	unwindData    uint64
	tryCount      uint32
	tryData       uint64
	ipCount       uint32
	ipData        uint64
	catchFrameOff uint32
}

func readFH4UintChecked(mem *mmu.MMU, addr uint64) (uint32, uint64, error) {
	first, err := mem.Read8(addr)
	if err != nil {
		return 0, 0, err
	}
	switch {
	case first&1 == 0:
		return uint32(first) >> 1, 1, nil
	case first&3 == 1:
		second, err := mem.Read8(addr + 1)
		if err != nil {
			return 0, 0, err
		}
		return uint32(first)>>2 | uint32(second)<<6, 2, nil
	case first&7 == 3:
		second, err := mem.Read8(addr + 1)
		if err != nil {
			return 0, 0, err
		}
		third, err := mem.Read8(addr + 2)
		if err != nil {
			return 0, 0, err
		}
		return uint32(first)>>3 | uint32(second)<<5 | uint32(third)<<13, 3, nil
	case first&15 == 7:
		second, err := mem.Read8(addr + 1)
		if err != nil {
			return 0, 0, err
		}
		third, err := mem.Read8(addr + 2)
		if err != nil {
			return 0, 0, err
		}
		fourth, err := mem.Read8(addr + 3)
		if err != nil {
			return 0, 0, err
		}
		return uint32(first)>>4 | uint32(second)<<4 | uint32(third)<<12 | uint32(fourth)<<20, 4, nil
	default:
		value, err := mem.Read32(addr + 1)
		return value, 5, err
	}
}

func fh4ImageAddress(imageBase uint64, rva uint32) (uint64, error) {
	address := imageBase + uint64(rva)
	if address < imageBase {
		return 0, fmt.Errorf("FH4 RVA overflow: 0x%x", rva)
	}
	return address, nil
}

func fh4CountedMap(mem *mmu.MMU, imageBase uint64, rva uint32, limit uint32) (uint32, uint64, error) {
	if rva == 0 {
		return 0, 0, nil
	}
	address, err := fh4ImageAddress(imageBase, rva)
	if err != nil {
		return 0, 0, err
	}
	count, size, err := readFH4UintChecked(mem, address)
	if err != nil {
		return 0, 0, err
	}
	if count > limit {
		return 0, 0, fmt.Errorf("FH4 map count %d exceeds %d", count, limit)
	}
	return count, address + size, nil
}

func parseFH4FunctionInfo(mem *mmu.MMU, imageBase, address uint64, funcBeginRVA uint32) (*fh4FunctionInfo, error) {
	header, err := mem.Read8(address)
	if err != nil {
		return nil, err
	}
	if header & ^uint8(fh4FuncValidMask) != 0 {
		return nil, fmt.Errorf("invalid FH4 function header 0x%x", header)
	}

	info := &fh4FunctionInfo{header: header}
	cursor := address + 1
	if header&fh4FuncHasBBT != 0 {
		_, size, err := readFH4UintChecked(mem, cursor)
		if err != nil {
			return nil, err
		}
		cursor += size
	}
	if header&fh4FuncHasUnwind != 0 {
		unwindRVA, err := mem.Read32(cursor)
		if err != nil {
			return nil, err
		}
		cursor += 4
		info.unwindCount, info.unwindData, err = fh4CountedMap(mem, imageBase, unwindRVA, 1<<20)
		if err != nil {
			return nil, err
		}
	}
	if header&fh4FuncHasTry != 0 {
		tryRVA, err := mem.Read32(cursor)
		if err != nil {
			return nil, err
		}
		cursor += 4
		info.tryCount, info.tryData, err = fh4CountedMap(mem, imageBase, tryRVA, 1<<16)
		if err != nil {
			return nil, err
		}
	}

	ipRVA, err := mem.Read32(cursor)
	if err != nil {
		return nil, err
	}
	cursor += 4
	if header&fh4FuncIsSeparated != 0 {
		mapCount, mapData, err := fh4CountedMap(mem, imageBase, ipRVA, 1<<16)
		if err != nil {
			return nil, err
		}
		ipRVA = 0
		for i := uint32(0); i < mapCount; i++ {
			functionRVA, readErr := mem.Read32(mapData)
			if readErr != nil {
				return nil, readErr
			}
			candidateRVA, readErr := mem.Read32(mapData + 4)
			if readErr != nil {
				return nil, readErr
			}
			mapData += 8
			if functionRVA == funcBeginRVA {
				ipRVA = candidateRVA
				break
			}
		}
		if ipRVA == 0 {
			return nil, fmt.Errorf("FH4 separated IP map missing function RVA 0x%x", funcBeginRVA)
		}
	}
	info.ipCount, info.ipData, err = fh4CountedMap(mem, imageBase, ipRVA, 1<<20)
	if err != nil {
		return nil, err
	}
	if header&fh4FuncIsCatch != 0 {
		info.catchFrameOff, _, err = readFH4UintChecked(mem, cursor)
		if err != nil {
			return nil, err
		}
	}
	return info, nil
}

func parseFH4CatchAll(mem *mmu.MMU, imageBase uint64, funcInfoAddr uint64,
	funcBeginRVA uint32, rsp, rip, establisher uint64, exception *CxxExceptionInfo,
	stateOverride *int32, trace bool) (*CxxCatchHandler, []CxxUnwindAction) {

	info, err := parseFH4FunctionInfo(mem, imageBase, funcInfoAddr, funcBeginRVA)
	if err != nil {
		if trace {
			ravelog.Logf("[seh-fh4] function metadata error: %v\n", err)
		}
		return nil, nil
	}

	frame := establisher
	if info.header&fh4FuncIsCatch != 0 && info.catchFrameOff != 0 {
		outerFrame, readErr := mem.Read64(establisher + uint64(info.catchFrameOff))
		if readErr != nil {
			if trace {
				ravelog.Logf("[seh-fh4] nested catch frame error: %v\n", readErr)
			}
			return nil, nil
		}
		frame = outerFrame
	}

	throwState := int32(-1)
	if stateOverride != nil {
		throwState = *stateOverride
	} else if info.ipCount != 0 {
		throwState, err = fh4ComputeThrowState(mem, info.ipData, imageBase, funcBeginRVA, rip, info.ipCount, trace)
		if err != nil {
			if trace {
				ravelog.Logf("[seh-fh4] IP map error: %v\n", err)
			}
			return nil, nil
		}
	}

	handler, targetState, err := fh4FindMatchingCatch(
		mem,
		imageBase,
		info,
		funcBeginRVA,
		rip,
		throwState,
		frame,
		exception,
		trace,
	)
	if err != nil {
		if trace {
			ravelog.Logf("[seh-fh4] catch metadata error: %v\n", err)
		}
		return nil, nil
	}

	if handler == nil {
		targetState = -1
	}
	actions, err := fh4PlanUnwindActions(mem, info, throwState, targetState, frame, trace)
	if err != nil {
		if trace {
			ravelog.Logf("[seh-fh4] unwind metadata error: %v\n", err)
		}
		return nil, nil
	}
	for index := range actions {
		actions[index].ImageBase = imageBase
	}
	if handler != nil {
		handler.EstablisherRBP = frame
		handler.BodyRSP = rsp
	}
	return handler, actions
}

// CxxPlanFrameUnwind returns the FH4 cleanup actions for one physical frame.
// targetState is -1 for a full frame unwind or the state retained by a target catch.
func CxxPlanFrameUnwind(mem *mmu.MMU, et *ExceptionTable, rsp, rip uint64,
	targetState int32, trace bool) ([]CxxUnwindAction, error) {
	return CxxPlanFrameUnwindAtState(mem, et, rsp, rip, targetState, nil, trace)
}

// CxxPlanFrameUnwindAtState plans one physical frame unwind using an explicit
// logical state when a catch funclet rethrows into its parent frame.
func CxxPlanFrameUnwindAtState(mem *mmu.MMU, et *ExceptionTable, rsp, rip uint64,
	targetState int32, currentStateOverride *int32, trace bool) ([]CxxUnwindAction, error) {

	if mem == nil {
		return nil, nil
	}
	imageBase := uint64(0)
	var function *RuntimeFunction
	if et != nil && rip >= et.ImageBase {
		function = et.Lookup(uint32(rip - et.ImageBase))
		if function != nil {
			imageBase = et.ImageBase
		}
	}
	if function == nil {
		function, imageBase, _ = LookupFunctionEntry(mem, rip, nil)
	}
	if function == nil {
		return nil, nil
	}
	unwindInfo := ParseUnwindInfo(mem, imageBase, function.UnwindData)
	if unwindInfo == nil || unwindInfo.HandlerData == 0 {
		return nil, nil
	}
	functionInfoRVA, err := mem.Read32(unwindInfo.HandlerData)
	if err != nil || functionInfoRVA == 0 {
		return nil, err
	}
	functionInfoAddr, err := fh4ImageAddress(imageBase, functionInfoRVA)
	if err != nil {
		return nil, err
	}
	magic, err := mem.Read32(functionInfoAddr)
	if err != nil {
		return nil, err
	}
	baseMagic := magic & 0x1fffffff
	if baseMagic >= 0x19930520 && baseMagic <= 0x19930522 {
		return nil, nil
	}

	info, err := parseFH4FunctionInfo(mem, imageBase, functionInfoAddr, function.BeginAddress)
	if err != nil {
		return nil, err
	}
	frame := rsp
	if info.header&fh4FuncIsCatch != 0 && info.catchFrameOff != 0 {
		frame, err = mem.Read64(rsp + uint64(info.catchFrameOff))
		if err != nil {
			return nil, err
		}
	}
	currentState := int32(-1)
	if currentStateOverride != nil {
		currentState = *currentStateOverride
	} else if info.ipCount != 0 {
		currentState, err = fh4ComputeThrowState(
			mem,
			info.ipData,
			imageBase,
			function.BeginAddress,
			rip,
			info.ipCount,
			trace,
		)
		if err != nil {
			return nil, err
		}
	}
	actions, err := fh4PlanUnwindActions(mem, info, currentState, targetState, frame, trace)
	if err != nil {
		return nil, err
	}
	for index := range actions {
		actions[index].ImageBase = imageBase
	}
	return actions, nil
}

// fh4ComputeThrowState walks the FH4 IP-to-state map to find the state at the throw point.
// dataAddr points to the first entry (after the numEntries count has been read).
func fh4ComputeThrowState(mem *mmu.MMU, dataAddr uint64, imageBase uint64,
	funcStartRVA uint32, rip uint64, numEntries uint32, trace bool) (int32, error) {

	addr := dataAddr
	throwRVA := uint32(rip - imageBase)
	state := int32(-1)
	currentIP := funcStartRVA

	for i := uint32(0); i < numEntries; i++ {
		ipDelta, n, err := readFH4UintChecked(mem, addr)
		if err != nil {
			return -1, err
		}
		addr += n
		rawState, n, err := readFH4UintChecked(mem, addr)
		if err != nil {
			return -1, err
		}
		st := int32(rawState) - 1
		addr += n

		currentIP += ipDelta
		if currentIP <= throwRVA {
			state = st
		}
		if trace && i < 20 {
			ravelog.Logf("[seh-fh4]   ipMap[%d]: ip=0x%x (delta=%d) state=%d\n", i, currentIP, ipDelta, st)
		}
	}

	return state, nil
}

const (
	fh4CatchHasFlags     = 0x01
	fh4CatchHasType      = 0x02
	fh4CatchHasObject    = 0x04
	fh4CatchSeparated    = 0x08
	fh4CatchOneReturn    = 0x10
	fh4CatchTwoReturns   = 0x20
	fh4CatchReturnMask   = 0x30
	fh4CatchValidMask    = 0x3f
	cxxTypeFlagConst     = 0x01
	cxxTypeFlagVolatile  = 0x02
	cxxTypeFlagReference = 0x08
)

type fh4CatchEntry struct {
	flags        uint32
	typeRVA      uint32
	objectOffset int32
	hasObject    bool
	handlerRVA   uint32
	returnRVAs   [2]uint32
	returnCount  uint8
}

type fh4CatchableType struct {
	properties  uint32
	typeRVA     uint32
	thisOffset  int32
	vbaseOffset int32
	vbaseDisp   int32
	size        uint32
	copyRVA     uint32
}

type fh4CatchMatch struct {
	object       uint64
	byReference  bool
	matched      bool
	size         uint32
	copyRVA      uint32
	properties   uint32
	pointerValue uint64
	throwBase    uint64
}

func parseFH4CatchEntries(mem *mmu.MMU, address uint64, count, funcBeginRVA uint32) ([]fh4CatchEntry, error) {
	entries := make([]fh4CatchEntry, 0, count)
	cursor := address
	for index := uint32(0); index < count; index++ {
		header, err := mem.Read8(cursor)
		if err != nil {
			return nil, err
		}
		cursor++
		if header & ^uint8(fh4CatchValidMask) != 0 {
			return nil, fmt.Errorf("invalid FH4 catch header 0x%x", header)
		}
		returnKind := header & fh4CatchReturnMask
		if returnKind == fh4CatchReturnMask {
			return nil, fmt.Errorf("invalid FH4 catch return encoding 0x%x", header)
		}

		entry := fh4CatchEntry{}
		if header&fh4CatchHasFlags != 0 {
			value, size, err := readFH4UintChecked(mem, cursor)
			if err != nil {
				return nil, err
			}
			entry.flags = value
			cursor += size
		}
		if header&fh4CatchHasType != 0 {
			entry.typeRVA, err = mem.Read32(cursor)
			if err != nil {
				return nil, err
			}
			cursor += 4
		}
		if header&fh4CatchHasObject != 0 {
			entry.hasObject = true
			value, size, err := readFH4UintChecked(mem, cursor)
			if err != nil {
				return nil, err
			}
			entry.objectOffset = int32(value)
			cursor += size
		}

		entry.handlerRVA, err = mem.Read32(cursor)
		if err != nil {
			return nil, err
		}
		cursor += 4

		switch returnKind {
		case fh4CatchOneReturn:
			entry.returnCount = 1
		case fh4CatchTwoReturns:
			entry.returnCount = 2
		}
		for returnIndex := uint8(0); returnIndex < entry.returnCount; returnIndex++ {
			if header&fh4CatchSeparated != 0 {
				entry.returnRVAs[returnIndex], err = mem.Read32(cursor)
				if err != nil {
					return nil, err
				}
				cursor += 4
				continue
			}
			offset, size, readErr := readFH4UintChecked(mem, cursor)
			if readErr != nil {
				return nil, readErr
			}
			cursor += size
			entry.returnRVAs[returnIndex] = funcBeginRVA + offset
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func readFH4CatchableType(mem *mmu.MMU, address uint64) (fh4CatchableType, error) {
	var value fh4CatchableType
	var err error
	if value.properties, err = mem.Read32(address); err != nil {
		return value, err
	}
	if value.typeRVA, err = mem.Read32(address + 4); err != nil {
		return value, err
	}
	raw, err := mem.Read32(address + 8)
	if err != nil {
		return value, err
	}
	value.thisOffset = int32(raw)
	raw, err = mem.Read32(address + 12)
	if err != nil {
		return value, err
	}
	value.vbaseOffset = int32(raw)
	raw, err = mem.Read32(address + 16)
	if err != nil {
		return value, err
	}
	value.vbaseDisp = int32(raw)
	if value.size, err = mem.Read32(address + 20); err != nil {
		return value, err
	}
	if value.copyRVA, err = mem.Read32(address + 24); err != nil {
		return value, err
	}
	return value, nil
}

func fh4TypeName(mem *mmu.MMU, descriptor uint64) (string, error) {
	if descriptor == 0 {
		return "", fmt.Errorf("nil FH4 type descriptor")
	}
	if _, err := mem.Read8(descriptor + 16); err != nil {
		return "", err
	}
	name := mem.ReadCString(descriptor+16, 4096)
	if name == "" {
		return "", fmt.Errorf("empty FH4 type descriptor at 0x%x", descriptor)
	}
	return name, nil
}

func fh4AdjustObject(mem *mmu.MMU, object uint64, catchable fh4CatchableType) (uint64, error) {
	if object == 0 {
		return 0, nil
	}
	adjusted := object
	if catchable.vbaseOffset >= 0 {
		vbaseAddress := adjusted + uint64(int64(catchable.vbaseOffset))
		vbaseTable, err := mem.Read64(vbaseAddress)
		if err != nil {
			return 0, err
		}
		displacementAddress := vbaseTable + uint64(int64(catchable.vbaseDisp))
		raw, err := mem.Read32(displacementAddress)
		if err != nil {
			return 0, err
		}
		adjusted = uint64(int64(vbaseAddress) + int64(int32(raw)))
	}
	return uint64(int64(adjusted) + int64(catchable.thisOffset)), nil
}

func fh4MatchTypedCatch(mem *mmu.MMU, frameImageBase uint64, entry fh4CatchEntry,
	exception *CxxExceptionInfo) (uint64, bool, bool, error) {

	match, err := fh4MatchTypedCatchInfo(mem, frameImageBase, entry, exception)
	return match.object, match.byReference, match.matched, err
}

func fh4MatchTypedCatchInfo(mem *mmu.MMU, frameImageBase uint64, entry fh4CatchEntry,
	exception *CxxExceptionInfo) (fh4CatchMatch, error) {

	if entry.typeRVA == 0 {
		return fh4CatchMatch{matched: true}, nil
	}
	if exception == nil || exception.ThrowInfo == 0 {
		return fh4CatchMatch{}, nil
	}
	throwBase := exception.ImageBase
	if throwBase == 0 {
		throwBase = frameImageBase
	}

	throwFlags, err := mem.Read32(exception.ThrowInfo)
	if err != nil {
		return fh4CatchMatch{}, err
	}
	if throwFlags&cxxTypeFlagConst != 0 && entry.flags&cxxTypeFlagConst == 0 {
		return fh4CatchMatch{}, nil
	}
	if throwFlags&cxxTypeFlagVolatile != 0 && entry.flags&cxxTypeFlagVolatile == 0 {
		return fh4CatchMatch{}, nil
	}
	typeTableRVA, err := mem.Read32(exception.ThrowInfo + 12)
	if err != nil {
		return fh4CatchMatch{}, err
	}
	typeTable, err := fh4ImageAddress(throwBase, typeTableRVA)
	if err != nil {
		return fh4CatchMatch{}, err
	}
	count, err := mem.Read32(typeTable)
	if err != nil {
		return fh4CatchMatch{}, err
	}
	if count > 1<<16 {
		return fh4CatchMatch{}, fmt.Errorf("FH4 catchable type count %d is invalid", count)
	}

	catchDescriptor, err := fh4ImageAddress(frameImageBase, entry.typeRVA)
	if err != nil {
		return fh4CatchMatch{}, err
	}
	catchName, err := fh4TypeName(mem, catchDescriptor)
	if err != nil {
		return fh4CatchMatch{}, err
	}
	byReference := entry.flags&cxxTypeFlagReference != 0

	for index := uint32(0); index < count; index++ {
		catchableRVA, readErr := mem.Read32(typeTable + 4 + uint64(index)*4)
		if readErr != nil {
			return fh4CatchMatch{}, readErr
		}
		catchableAddress, readErr := fh4ImageAddress(throwBase, catchableRVA)
		if readErr != nil {
			return fh4CatchMatch{}, readErr
		}
		catchable, readErr := readFH4CatchableType(mem, catchableAddress)
		if readErr != nil {
			return fh4CatchMatch{}, readErr
		}
		thrownDescriptor, readErr := fh4ImageAddress(throwBase, catchable.typeRVA)
		if readErr != nil {
			return fh4CatchMatch{}, readErr
		}
		thrownName, readErr := fh4TypeName(mem, thrownDescriptor)
		if readErr != nil {
			return fh4CatchMatch{}, readErr
		}
		if catchDescriptor != thrownDescriptor && catchName != thrownName {
			continue
		}
		if catchable.properties&CxxCatchableByReferenceOnly != 0 && !byReference {
			continue
		}
		object := exception.Object
		pointerValue := uint64(0)
		if !byReference && catchable.properties&CxxCatchableSimpleType != 0 && catchable.size == 8 {
			value, readErr := mem.Read64(exception.Object)
			if readErr != nil {
				return fh4CatchMatch{}, readErr
			}
			pointerValue, readErr = fh4AdjustObject(mem, value, catchable)
			if readErr != nil {
				return fh4CatchMatch{}, readErr
			}
		} else {
			var readErr error
			object, readErr = fh4AdjustObject(mem, exception.Object, catchable)
			if readErr != nil {
				return fh4CatchMatch{}, readErr
			}
		}
		return fh4CatchMatch{
			object:       object,
			byReference:  byReference,
			matched:      true,
			size:         catchable.size,
			copyRVA:      catchable.copyRVA,
			properties:   catchable.properties,
			pointerValue: pointerValue,
			throwBase:    throwBase,
		}, nil
	}
	return fh4CatchMatch{}, nil
}

func fh4FindMatchingCatch(mem *mmu.MMU, imageBase uint64, info *fh4FunctionInfo,
	funcBeginRVA uint32, controlPC uint64, throwState int32, frame uint64, exception *CxxExceptionInfo,
	trace bool) (*CxxCatchHandler, int32, error) {

	cursor := info.tryData
	for tryIndex := uint32(0); tryIndex < info.tryCount; tryIndex++ {
		tryLow, size, err := readFH4UintChecked(mem, cursor)
		if err != nil {
			return nil, -1, err
		}
		cursor += size
		tryHigh, size, err := readFH4UintChecked(mem, cursor)
		if err != nil {
			return nil, -1, err
		}
		cursor += size
		catchHigh, size, err := readFH4UintChecked(mem, cursor)
		if err != nil {
			return nil, -1, err
		}
		cursor += size
		catchMapRVA, err := mem.Read32(cursor)
		if err != nil {
			return nil, -1, err
		}
		cursor += 4

		if trace {
			ravelog.Logf("[seh-fh4] try[%d] state=%d range=[%d,%d] catch=%d\n",
				tryIndex, throwState, tryLow, tryHigh, catchHigh)
		}
		if throwState < int32(tryLow) || throwState > int32(tryHigh) || catchMapRVA == 0 {
			continue
		}
		catchCount, catchData, err := fh4CountedMap(mem, imageBase, catchMapRVA, 1<<16)
		if err != nil {
			return nil, -1, err
		}
		entries, err := parseFH4CatchEntries(mem, catchData, catchCount, funcBeginRVA)
		if err != nil {
			return nil, -1, err
		}
		for catchIndex, entry := range entries {
			match, err := fh4MatchTypedCatchInfo(mem, imageBase, entry, exception)
			if err != nil {
				return nil, -1, err
			}
			if !match.matched {
				continue
			}
			if entry.handlerRVA == 0 {
				return nil, -1, fmt.Errorf("FH4 catch %d has no handler", catchIndex)
			}
			handler := &CxxCatchHandler{
				ImageBase:         imageBase,
				FuncletRVA:        entry.handlerRVA,
				ControlPC:         controlPC,
				EstablisherRBP:    frame,
				BodyRSP:           frame,
				CatchObjOffset:    entry.objectOffset,
				HasCatchObject:    entry.hasObject,
				CatchObject:       match.object,
				CatchByReference:  match.byReference,
				CatchObjectSize:   match.size,
				CatchCopyRVA:      match.copyRVA,
				CatchProperties:   match.properties,
				CatchPointerValue: match.pointerValue,
				ThrowImageBase:    match.throwBase,
				ContinuationRVAs:  entry.returnRVAs,
				ContinuationCount: entry.returnCount,
				CatchState:        int32(catchHigh),
				UnwindTargetState: int32(tryLow),
			}
			if entry.returnCount != 0 {
				handler.ContinuationRVA = entry.returnRVAs[0]
			}
			if trace {
				ravelog.Logf("[seh-fh4] matched catch[%d] handler=0x%x type=0x%x returns=%d\n",
					catchIndex, entry.handlerRVA, entry.typeRVA, entry.returnCount)
			}
			return handler, int32(tryLow), nil
		}
	}
	return nil, -1, nil
}

type fh4UnwindEntry struct {
	address      uint64
	previous     uint64
	kind         CxxUnwindActionKind
	handlerRVA   uint32
	objectOffset uint32
}

func parseFH4UnwindEntries(mem *mmu.MMU, info *fh4FunctionInfo) ([]fh4UnwindEntry, error) {
	entries := make([]fh4UnwindEntry, 0, info.unwindCount)
	cursor := info.unwindData
	for index := uint32(0); index < info.unwindCount; index++ {
		address := cursor
		encoded, size, err := readFH4UintChecked(mem, cursor)
		if err != nil {
			return nil, err
		}
		cursor += size
		delta := uint64(encoded >> 2)
		if delta > address {
			return nil, fmt.Errorf("FH4 unwind predecessor underflow at 0x%x", address)
		}
		entry := fh4UnwindEntry{
			address:  address,
			previous: address - delta,
			kind:     CxxUnwindActionKind(encoded & 3),
		}
		switch entry.kind {
		case 0:
		case CxxUnwindDestructorObject, CxxUnwindDestructorPointer:
			entry.handlerRVA, err = mem.Read32(cursor)
			if err != nil {
				return nil, err
			}
			cursor += 4
			entry.objectOffset, size, err = readFH4UintChecked(mem, cursor)
			if err != nil {
				return nil, err
			}
			cursor += size
		case CxxUnwindFrame:
			entry.handlerRVA, err = mem.Read32(cursor)
			if err != nil {
				return nil, err
			}
			cursor += 4
		default:
			return nil, fmt.Errorf("invalid FH4 unwind kind %d", entry.kind)
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func fh4PlanUnwindActions(mem *mmu.MMU, info *fh4FunctionInfo,
	currentState, targetState int32, frame uint64, trace bool) ([]CxxUnwindAction, error) {

	if currentState < 0 || info.unwindCount == 0 {
		return nil, nil
	}
	entries, err := parseFH4UnwindEntries(mem, info)
	if err != nil {
		return nil, err
	}
	if currentState >= int32(len(entries)) {
		return nil, fmt.Errorf("FH4 state %d exceeds unwind map size %d", currentState, len(entries))
	}
	stopAddress := info.unwindData - 1
	if targetState >= 0 {
		if targetState >= int32(len(entries)) {
			return nil, fmt.Errorf("FH4 target state %d exceeds unwind map size %d", targetState, len(entries))
		}
		stopAddress = entries[targetState].address
	}

	byAddress := make(map[uint64]fh4UnwindEntry, len(entries))
	for _, entry := range entries {
		byAddress[entry.address] = entry
	}
	currentAddress := entries[currentState].address
	if trace {
		ravelog.Logf("[seh-fh4] unwind states current=%d target=%d currentAddr=0x%x stopAddr=0x%x\n",
			currentState, targetState, currentAddress, stopAddress)
	}
	seen := make(map[uint64]struct{}, len(entries))
	var actions []CxxUnwindAction
	for currentAddress > stopAddress {
		if _, ok := seen[currentAddress]; ok {
			return nil, fmt.Errorf("FH4 unwind predecessor cycle at 0x%x", currentAddress)
		}
		seen[currentAddress] = struct{}{}
		entry, ok := byAddress[currentAddress]
		if !ok {
			return nil, fmt.Errorf("FH4 unwind predecessor 0x%x is not an entry", currentAddress)
		}
		if entry.handlerRVA != 0 {
			objectAddress := frame
			if entry.kind == CxxUnwindDestructorObject || entry.kind == CxxUnwindDestructorPointer {
				objectAddress += uint64(entry.objectOffset)
			}
			actions = append(actions, CxxUnwindAction{
				Kind:          entry.kind,
				HandlerRVA:    entry.handlerRVA,
				Frame:         frame,
				ObjectAddress: objectAddress,
			})
			if trace {
				ravelog.Logf("[seh-fh4]   cleanup addr=0x%x previous=0x%x kind=%d handler=0x%x object=%d\n",
					currentAddress, entry.previous, entry.kind, entry.handlerRVA, entry.objectOffset)
			}
		} else if trace {
			ravelog.Logf("[seh-fh4]   transition addr=0x%x previous=0x%x\n",
				currentAddress, entry.previous)
		}
		if entry.previous >= currentAddress {
			return nil, fmt.Errorf("invalid FH4 unwind predecessor 0x%x from 0x%x", entry.previous, currentAddress)
		}
		currentAddress = entry.previous
	}
	return actions, nil
}

// FormatCxxException returns a description of a C++ exception dispatch.
func FormatCxxException(handler *CxxCatchHandler, imageBase uint64) string {
	if handler == nil {
		return "no handler found"
	}
	return fmt.Sprintf("catch funclet at RVA 0x%x (VA 0x%x), RBP=0x%x",
		handler.FuncletRVA, imageBase+uint64(handler.FuncletRVA), handler.EstablisherRBP)
}

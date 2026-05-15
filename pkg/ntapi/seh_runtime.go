//go:build guest_windows

package ntapi

import (
	"fmt"
	"sort"
	"sync"

	"github.com/mirkobrombin/Raven/pkg/mmu"

	ravelog "github.com/mirkobrombin/Raven/pkg/log"
)

const (
	ExceptionDispositionContinueExecution = 0
	ExceptionDispositionContinueSearch    = 1
	ExceptionDispositionCollidedUnwind    = 3

	ExceptionContinueExecution = 0xFFFFFFFF
	ExceptionContinueSearch    = 0
	ExceptionExecuteHandler    = 1

	ExceptionFlagUnwinding      = 0x02
	ExceptionFlagExitUnwind     = 0x04
	ExceptionFlagTargetUnwind   = 0x20
	ExceptionFlagCollidedUnwind = 0x40

	StatusUnwind              = 0xC0000027
	StatusInvalidDisposition  = 0xC0000026
	StatusBadStack            = 0xC0000028
	StatusInvalidUnwindTarget = 0xC0000029
	StatusBadFunctionTable    = 0xC00000FF
	StatusUnwindConsolidate   = 0x80000029
)

type functionTableEntry struct {
	baseAddr       uint64
	endAddr        uint64
	tableAddr      uint64
	identifier     uint64
	entries        []RuntimeFunction
	count          int
	callback       uint64
	context        uint64
	callbackLength uint64
}

var (
	sehFunctionTableMu    sync.RWMutex
	staticFunctionTables  []functionTableEntry
	dynamicFunctionTables []functionTableEntry
)

type AMD64Context struct {
	Regs   [16]uint64
	XMM    [16][2]uint64
	Rflags uint64
	Rip    uint64
}

type UnwindError struct {
	Status uint32
	Err    error
}

func (e *UnwindError) Error() string {
	if e == nil {
		return ""
	}
	if e.Err == nil {
		return fmt.Sprintf("unwind failed with NTSTATUS 0x%08x", e.Status)
	}
	return fmt.Sprintf("unwind failed with NTSTATUS 0x%08x: %v", e.Status, e.Err)
}

func (e *UnwindError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

type DispatcherContext struct {
	ControlPc        uint64
	ImageBase        uint64
	FunctionEntry    uint64
	EstablisherFrame uint64
	TargetIp         uint64
	ContextRecord    uint64
	LanguageHandler  uint64
	HandlerData      uint64
	HistoryTable     uint64
	ScopeIndex       uint32
}

func ReadRuntimeFunctionEntry(mem *mmu.MMU, entryAddr uint64) *RuntimeFunction {
	if entryAddr == 0 {
		return nil
	}
	begin, err := mem.Read32(entryAddr)
	if err != nil {
		return nil
	}
	end, err := mem.Read32(entryAddr + 4)
	if err != nil {
		return nil
	}
	unwind, err := mem.Read32(entryAddr + 8)
	if err != nil {
		return nil
	}
	return &RuntimeFunction{
		BeginAddress: begin,
		EndAddress:   end,
		UnwindData:   unwind,
		EntryAddr:    entryAddr,
	}
}

func parseRuntimeFunctionTable(mem *mmu.MMU, tableAddr uint64, count uint32) []RuntimeFunction {
	entries := make([]RuntimeFunction, 0, count)
	for i := uint32(0); i < count; i++ {
		entryAddr := tableAddr + uint64(i)*12
		rf := ReadRuntimeFunctionEntry(mem, entryAddr)
		if rf == nil || rf.BeginAddress == 0 || rf.EndAddress <= rf.BeginAddress {
			continue
		}
		entries = append(entries, *rf)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].BeginAddress < entries[j].BeginAddress
	})
	return entries
}

func RegisterExceptionTable(imageBase, imageSize uint64, table *ExceptionTable) {
	if table == nil || len(table.Entries) == 0 || imageBase == 0 {
		return
	}
	if imageSize == 0 {
		for _, entry := range table.Entries {
			if end := uint64(entry.EndAddress); end > imageSize {
				imageSize = end
			}
		}
	}
	table.ImageBase = imageBase
	entry := functionTableEntry{
		baseAddr:  imageBase,
		endAddr:   imageBase + imageSize,
		tableAddr: table.Entries[0].EntryAddr,
		entries:   append([]RuntimeFunction(nil), table.Entries...),
		count:     len(table.Entries),
	}
	sehFunctionTableMu.Lock()
	defer sehFunctionTableMu.Unlock()
	for i := range staticFunctionTables {
		if staticFunctionTables[i].baseAddr == imageBase {
			staticFunctionTables[i] = entry
			return
		}
	}
	staticFunctionTables = append(staticFunctionTables, entry)
}

func AddDynamicFunctionTable(mem *mmu.MMU, tableAddr uint64, count uint32, baseAddr uint64) bool {
	if mem == nil || tableAddr == 0 || count == 0 || baseAddr == 0 {
		return false
	}
	entries := parseRuntimeFunctionTable(mem, tableAddr, count)
	if len(entries) == 0 {
		return false
	}
	endAddr := baseAddr
	for _, entry := range entries {
		if end := baseAddr + uint64(entry.EndAddress); end > endAddr {
			endAddr = end
		}
	}
	sehFunctionTableMu.Lock()
	defer sehFunctionTableMu.Unlock()
	for i := range dynamicFunctionTables {
		if dynamicFunctionTables[i].tableAddr == tableAddr {
			dynamicFunctionTables[i] = functionTableEntry{
				baseAddr:  baseAddr,
				endAddr:   endAddr,
				tableAddr: tableAddr,
				entries:   entries,
				count:     len(entries),
			}
			return true
		}
	}
	dynamicFunctionTables = append(dynamicFunctionTables, functionTableEntry{
		baseAddr:  baseAddr,
		endAddr:   endAddr,
		tableAddr: tableAddr,
		entries:   entries,
		count:     len(entries),
	})
	return true
}

func DeleteDynamicFunctionTable(tableAddr uint64) bool {
	if tableAddr == 0 {
		return false
	}
	sehFunctionTableMu.Lock()
	defer sehFunctionTableMu.Unlock()
	for i := range dynamicFunctionTables {
		if dynamicFunctionTables[i].tableAddr == tableAddr || dynamicFunctionTables[i].identifier == tableAddr {
			dynamicFunctionTables = append(dynamicFunctionTables[:i], dynamicFunctionTables[i+1:]...)
			return true
		}
	}
	return false
}

func InstallDynamicFunctionTableCallback(identifier, baseAddr, length, callback, context uint64) bool {
	if identifier == 0 || baseAddr == 0 || length == 0 || callback == 0 {
		return false
	}
	entry := functionTableEntry{
		baseAddr:       baseAddr,
		endAddr:        baseAddr + length,
		tableAddr:      identifier,
		identifier:     identifier,
		callback:       callback,
		context:        context,
		callbackLength: length,
	}
	sehFunctionTableMu.Lock()
	defer sehFunctionTableMu.Unlock()
	for i := range dynamicFunctionTables {
		if dynamicFunctionTables[i].identifier == identifier {
			dynamicFunctionTables[i] = entry
			return true
		}
	}
	dynamicFunctionTables = append(dynamicFunctionTables, entry)
	return true
}

func lookupRuntimeFunctionInEntries(entries []RuntimeFunction, rva uint32) *RuntimeFunction {
	if len(entries) == 0 {
		return nil
	}
	i := sort.Search(len(entries), func(i int) bool {
		return entries[i].EndAddress > rva
	})
	if i < len(entries) && entries[i].BeginAddress <= rva && rva < entries[i].EndAddress {
		return &entries[i]
	}
	return nil
}

func LookupFunctionEntry(mem *mmu.MMU, controlPC uint64, guestCall GuestCallFunc) (*RuntimeFunction, uint64, uint64) {
	sehFunctionTableMu.RLock()
	for i := range staticFunctionTables {
		table := &staticFunctionTables[i]
		if controlPC < table.baseAddr || controlPC >= table.endAddr {
			continue
		}
		rva := uint32(controlPC - table.baseAddr)
		if entry := lookupRuntimeFunctionInEntries(table.entries, rva); entry != nil {
			result := *entry
			imageBase := table.baseAddr
			sehFunctionTableMu.RUnlock()
			return &result, imageBase, result.EntryAddr
		}
	}

	candidates := make([]functionTableEntry, 0, len(dynamicFunctionTables))
	for i := range dynamicFunctionTables {
		table := &dynamicFunctionTables[i]
		if controlPC < table.baseAddr || controlPC >= table.endAddr {
			continue
		}
		candidate := *table
		candidate.entries = append([]RuntimeFunction(nil), table.entries...)
		candidates = append(candidates, candidate)
	}
	sehFunctionTableMu.RUnlock()

	for i := range candidates {
		table := &candidates[i]
		if table.callback != 0 && guestCall != nil && mem != nil {
			entryAddr, err := guestCall(table.callback, []uint64{controlPC, table.context})
			if err == nil && entryAddr != 0 {
				if rf := ReadRuntimeFunctionEntry(mem, entryAddr); rf != nil {
					return rf, table.baseAddr, entryAddr
				}
			}
			continue
		}
		rva := uint32(controlPC - table.baseAddr)
		if entry := lookupRuntimeFunctionInEntries(table.entries, rva); entry != nil {
			return entry, table.baseAddr, entry.EntryAddr
		}
	}

	return nil, 0, 0
}

func ReadAMD64Context(mem *mmu.MMU, ctxAddr uint64) (*AMD64Context, error) {
	if ctxAddr == 0 {
		return nil, fmt.Errorf("nil CONTEXT")
	}
	read64 := func(off uint64) (uint64, error) {
		return mem.Read64(ctxAddr + off)
	}
	ctx := &AMD64Context{}
	var err error
	eflags, err := mem.Read32(ctxAddr + 0x44)
	if err != nil {
		return nil, err
	}
	ctx.Rflags = uint64(eflags)
	offsets := []uint64{0x78, 0x80, 0x88, 0x90, 0x98, 0xA0, 0xA8, 0xB0, 0xB8, 0xC0, 0xC8, 0xD0, 0xD8, 0xE0, 0xE8, 0xF0}
	for i, off := range offsets {
		if ctx.Regs[i], err = read64(off); err != nil {
			return nil, err
		}
	}
	if ctx.Rip, err = read64(0xF8); err != nil {
		return nil, err
	}
	for index := range ctx.XMM {
		offset := uint64(0x1A0 + index*16)
		if ctx.XMM[index][0], err = read64(offset); err != nil {
			return nil, err
		}
		if ctx.XMM[index][1], err = read64(offset + 8); err != nil {
			return nil, err
		}
	}
	return ctx, nil
}

func WriteAMD64Context(mem *mmu.MMU, ctxAddr uint64, ctx *AMD64Context) error {
	if ctxAddr == 0 || ctx == nil {
		return fmt.Errorf("invalid CONTEXT write")
	}
	mem.Write32(ctxAddr+0x30, 0x10000B)
	mem.Write32(ctxAddr+0x44, uint32(ctx.Rflags))
	offsets := []uint64{0x78, 0x80, 0x88, 0x90, 0x98, 0xA0, 0xA8, 0xB0, 0xB8, 0xC0, 0xC8, 0xD0, 0xD8, 0xE0, 0xE8, 0xF0}
	for i, off := range offsets {
		mem.Write64(ctxAddr+off, ctx.Regs[i])
	}
	mem.Write64(ctxAddr+0xF8, ctx.Rip)
	for index, value := range ctx.XMM {
		offset := uint64(0x1A0 + index*16)
		mem.Write64(ctxAddr+offset, value[0])
		mem.Write64(ctxAddr+offset+8, value[1])
	}
	return nil
}

func (c *AMD64Context) GetReg(idx uint8) uint64 {
	if int(idx) < len(c.Regs) {
		return c.Regs[idx]
	}
	return 0
}

func (c *AMD64Context) SetReg(idx int, val uint64) {
	if idx >= 0 && idx < len(c.Regs) {
		c.Regs[idx] = val
	}
}

func getEstablisherFrame(mem *mmu.MMU, unwindInfoAddr uint64, ctx *AMD64Context,
	ui *UnwindInfo, codeOffset uint32) uint64 {

	if ui == nil {
		return ctx.Regs[regRSP]
	}
	if ui.FrameRegister == 0 {
		return ctx.Regs[regRSP]
	}
	if codeOffset >= uint32(ui.SizeOfProlog) || ui.Flags&UnwFlagChainInfo != 0 {
		return ctx.GetReg(ui.FrameRegister) - uint64(ui.FrameOffset)*16
	}
	codesAddr := unwindInfoAddr + 4
	for index := uint8(0); index < ui.CountOfCodes; {
		operationOffset, err := mem.Read8(codesAddr + uint64(index)*2)
		if err != nil {
			break
		}
		operationInfo, err := mem.Read8(codesAddr + uint64(index)*2 + 1)
		if err != nil {
			break
		}
		operation := operationInfo & 0x0F
		if operation == 3 && uint32(operationOffset) <= codeOffset {
			return ctx.GetReg(ui.FrameRegister) - uint64(ui.FrameOffset)*16
		}
		index += unwindCodeSlots(operation, operationInfo>>4)
	}
	return ctx.Regs[regRSP]
}

func unwindCodeSlots(op, info uint8) uint8 {
	switch op {
	case 1:
		if info == 0 {
			return 2
		}
		return 3
	case 4, 8:
		return 2
	case 5, 9:
		return 3
	default:
		return 1
	}
}

func applyUnwindCodes(mem *mmu.MMU, unwindInfoAddr uint64, ui *UnwindInfo,
	codeOffset uint32, context *AMD64Context) (bool, error) {

	codesAddr := unwindInfoAddr + 4
	insideProlog := codeOffset < uint32(ui.SizeOfProlog)
	for index := uint8(0); index < ui.CountOfCodes; {
		codeAddr := codesAddr + uint64(index)*2
		operationOffset, err := mem.Read8(codeAddr)
		if err != nil {
			return false, err
		}
		operationInfo, err := mem.Read8(codeAddr + 1)
		if err != nil {
			return false, err
		}
		operation := operationInfo & 0x0F
		info := operationInfo >> 4
		slots := unwindCodeSlots(operation, info)
		if index+slots > ui.CountOfCodes {
			return false, fmt.Errorf("truncated unwind operation %d", operation)
		}
		if insideProlog && uint32(operationOffset) > codeOffset {
			index += slots
			continue
		}

		switch operation {
		case 0: // UWOP_PUSH_NONVOL
			value, err := mem.Read64(context.Regs[regRSP])
			if err != nil {
				return false, err
			}
			context.SetReg(int(info), value)
			context.Regs[regRSP] += 8
		case 1: // UWOP_ALLOC_LARGE
			low, err := mem.Read16(codesAddr + uint64(index+1)*2)
			if err != nil {
				return false, err
			}
			if info == 0 {
				context.Regs[regRSP] += uint64(low) * 8
			} else {
				high, err := mem.Read16(codesAddr + uint64(index+2)*2)
				if err != nil {
					return false, err
				}
				context.Regs[regRSP] += uint64(low) | uint64(high)<<16
			}
		case 2: // UWOP_ALLOC_SMALL
			context.Regs[regRSP] += uint64(info)*8 + 8
		case 3: // UWOP_SET_FPREG
			if ui.FrameRegister == 0 {
				return false, fmt.Errorf("UWOP_SET_FPREG without frame register")
			}
			context.Regs[regRSP] = context.GetReg(ui.FrameRegister) - uint64(ui.FrameOffset)*16
		case 4: // UWOP_SAVE_NONVOL
			offset, err := mem.Read16(codesAddr + uint64(index+1)*2)
			if err != nil {
				return false, err
			}
			value, err := mem.Read64(context.Regs[regRSP] + uint64(offset)*8)
			if err != nil {
				return false, err
			}
			context.SetReg(int(info), value)
		case 5: // UWOP_SAVE_NONVOL_FAR
			low, err := mem.Read16(codesAddr + uint64(index+1)*2)
			if err != nil {
				return false, err
			}
			high, err := mem.Read16(codesAddr + uint64(index+2)*2)
			if err != nil {
				return false, err
			}
			offset := uint64(low) | uint64(high)<<16
			value, err := mem.Read64(context.Regs[regRSP] + offset)
			if err != nil {
				return false, err
			}
			context.SetReg(int(info), value)
		case 8: // UWOP_SAVE_XMM128
			offset, err := mem.Read16(codesAddr + uint64(index+1)*2)
			if err != nil {
				return false, err
			}
			address := context.Regs[regRSP] + uint64(offset)*16
			if context.XMM[info][0], err = mem.Read64(address); err != nil {
				return false, err
			}
			if context.XMM[info][1], err = mem.Read64(address + 8); err != nil {
				return false, err
			}
		case 9: // UWOP_SAVE_XMM128_FAR
			low, err := mem.Read16(codesAddr + uint64(index+1)*2)
			if err != nil {
				return false, err
			}
			high, err := mem.Read16(codesAddr + uint64(index+2)*2)
			if err != nil {
				return false, err
			}
			address := context.Regs[regRSP] + (uint64(low) | uint64(high)<<16)
			if context.XMM[info][0], err = mem.Read64(address); err != nil {
				return false, err
			}
			if context.XMM[info][1], err = mem.Read64(address + 8); err != nil {
				return false, err
			}
		case 10: // UWOP_PUSH_MACHFRAME
			stack := context.Regs[regRSP]
			ripOffset := uint64(0)
			rspOffset := uint64(24)
			if info != 0 {
				ripOffset = 8
				rspOffset = 32
			}
			rip, err := mem.Read64(stack + ripOffset)
			if err != nil {
				return false, err
			}
			rsp, err := mem.Read64(stack + rspOffset)
			if err != nil {
				return false, err
			}
			context.Rip = rip
			context.Regs[regRSP] = rsp
			return true, nil
		default:
			return false, fmt.Errorf("unsupported unwind operation %d", operation)
		}
		index += slots
	}
	return false, nil
}

func tryVirtualUnwindEpilog(mem *mmu.MMU, function *RuntimeFunction, imageBase, controlPC uint64,
	context *AMD64Context) (bool, error) {

	if function == nil || controlPC < imageBase+uint64(function.BeginAddress) ||
		controlPC >= imageBase+uint64(function.EndAddress) {
		return false, nil
	}
	trial := *context
	pc := controlPC
	for instruction := 0; instruction < 32; instruction++ {
		opcode, err := mem.Read8(pc)
		if err != nil {
			return false, nil
		}
		switch {
		case opcode == 0x90:
			pc++
		case opcode == 0x48 || opcode == 0x49:
			second, readErr := mem.Read8(pc + 1)
			if readErr != nil {
				return false, nil
			}
			switch second {
			case 0x83:
				modrm, _ := mem.Read8(pc + 2)
				immediate, immediateErr := mem.Read8(pc + 3)
				if opcode != 0x48 || modrm != 0xC4 || immediateErr != nil {
					return false, nil
				}
				trial.Regs[regRSP] += uint64(immediate)
				pc += 4
			case 0x81:
				modrm, _ := mem.Read8(pc + 2)
				immediate, immediateErr := mem.Read32(pc + 3)
				if opcode != 0x48 || modrm != 0xC4 || immediateErr != nil {
					return false, nil
				}
				trial.Regs[regRSP] += uint64(immediate)
				pc += 7
			case 0x89:
				modrm, _ := mem.Read8(pc + 2)
				if opcode != 0x48 || modrm != 0xEC {
					return false, nil
				}
				trial.Regs[regRSP] = trial.Regs[regRBP]
				pc += 3
			case 0x8D:
				modrm, _ := mem.Read8(pc + 2)
				mode := modrm >> 6
				if (modrm>>3)&7 != 4 || mode == 0 || mode == 3 || modrm&7 == 4 {
					return false, nil
				}
				baseRegister := int(modrm & 7)
				if opcode&1 != 0 {
					baseRegister += 8
				}
				displacement := int64(0)
				if mode == 1 {
					raw, displacementErr := mem.Read8(pc + 3)
					if displacementErr != nil {
						return false, nil
					}
					displacement = int64(int8(raw))
					pc += 4
				} else {
					raw, displacementErr := mem.Read32(pc + 3)
					if displacementErr != nil {
						return false, nil
					}
					displacement = int64(int32(raw))
					pc += 7
				}
				trial.Regs[regRSP] = uint64(int64(trial.Regs[baseRegister]) + displacement)
			default:
				return false, nil
			}
		case opcode >= 0x58 && opcode <= 0x5F:
			register := int(opcode - 0x58)
			if register == regRSP {
				return false, nil
			}
			value, readErr := mem.Read64(trial.Regs[regRSP])
			if readErr != nil {
				return false, readErr
			}
			trial.SetReg(register, value)
			trial.Regs[regRSP] += 8
			pc++
		case opcode == 0x41:
			pop, readErr := mem.Read8(pc + 1)
			if readErr != nil || pop < 0x58 || pop > 0x5F {
				return false, nil
			}
			value, readErr := mem.Read64(trial.Regs[regRSP])
			if readErr != nil {
				return false, readErr
			}
			trial.SetReg(int(pop-0x58)+8, value)
			trial.Regs[regRSP] += 8
			pc += 2
		case opcode == 0xC3 || opcode == 0xC2:
			returnAddress, readErr := mem.Read64(trial.Regs[regRSP])
			if readErr != nil {
				return false, readErr
			}
			trial.Regs[regRSP] += 8
			if opcode == 0xC2 {
				immediate, immediateErr := mem.Read16(pc + 1)
				if immediateErr != nil {
					return false, immediateErr
				}
				trial.Regs[regRSP] += uint64(immediate)
			}
			trial.Rip = returnAddress
			*context = trial
			return true, nil
		case opcode == 0xE9:
			displacement, readErr := mem.Read32(pc + 1)
			if readErr != nil {
				return false, readErr
			}
			target := uint64(int64(pc+5) + int64(int32(displacement)))
			if target >= imageBase+uint64(function.BeginAddress) && target < imageBase+uint64(function.EndAddress) {
				return false, nil
			}
			trial.Rip = target
			*context = trial
			return true, nil
		case opcode == 0xEB:
			displacement, readErr := mem.Read8(pc + 1)
			if readErr != nil {
				return false, readErr
			}
			target := uint64(int64(pc+2) + int64(int8(displacement)))
			if target >= imageBase+uint64(function.BeginAddress) && target < imageBase+uint64(function.EndAddress) {
				return false, nil
			}
			trial.Rip = target
			*context = trial
			return true, nil
		default:
			return false, nil
		}
	}
	return false, nil
}

func VirtualUnwind(mem *mmu.MMU, handlerType uint32, imageBase, controlPC uint64, functionEntry *RuntimeFunction, ctx *AMD64Context) (uint64, uint64, uint64, error) {
	if ctx == nil {
		return 0, 0, 0, fmt.Errorf("nil unwind context")
	}
	if functionEntry == nil {
		establisherFrame := ctx.Regs[regRSP]
		retAddr, err := mem.Read64(establisherFrame)
		if err != nil {
			return 0, 0, establisherFrame, err
		}
		ctx.Regs[regRSP] += 8
		ctx.Rip = retAddr
		return 0, 0, establisherFrame, nil
	}
	epilogEstablisher := ctx.Regs[regRSP]
	if unwound, err := tryVirtualUnwindEpilog(mem, functionEntry, imageBase, controlPC, ctx); err != nil {
		return 0, 0, 0, err
	} else if unwound {
		return 0, 0, epilogEstablisher, nil
	}

	rva := uint32(0)
	if controlPC >= imageBase {
		rva = uint32(controlPC - imageBase)
	}
	ui := ParseUnwindInfo(mem, imageBase, functionEntry.UnwindData)
	if ui == nil {
		return 0, 0, 0, fmt.Errorf("missing unwind info")
	}

	establisherFrame := getEstablisherFrame(
		mem,
		imageBase+uint64(functionEntry.UnwindData),
		ctx,
		ui,
		rva-functionEntry.BeginAddress,
	)
	currentUI := ui
	currentUnwindRVA := functionEntry.UnwindData
	currentCodeOffset := rva - functionEntry.BeginAddress
	var handlerAddr, handlerData uint64
	for {
		machineFrame, err := applyUnwindCodes(
			mem,
			imageBase+uint64(currentUnwindRVA),
			currentUI,
			currentCodeOffset,
			ctx,
		)
		if err != nil {
			return 0, 0, establisherFrame, err
		}
		if machineFrame {
			return 0, 0, establisherFrame, nil
		}
		if currentUI.Flags&UnwFlagChainInfo == 0 || currentUI.ChainedRF == nil {
			if handlerType != 0 && uint32(currentUI.Flags)&handlerType != 0 {
				handlerAddr = imageBase + uint64(currentUI.HandlerRVA)
				handlerData = currentUI.HandlerData
			}
			break
		}
		currentUnwindRVA = currentUI.ChainedRF.UnwindData
		currentUI = ParseUnwindInfo(mem, imageBase, currentUnwindRVA)
		if currentUI == nil {
			return 0, 0, establisherFrame, fmt.Errorf("missing chained unwind info")
		}
		currentCodeOffset = uint32(currentUI.SizeOfProlog)
	}

	retAddr, err := mem.Read64(ctx.Regs[regRSP])
	if err != nil {
		return 0, 0, establisherFrame, err
	}
	ctx.Regs[regRSP] += 8
	ctx.Rip = retAddr
	return handlerAddr, handlerData, establisherFrame, nil
}

// UnwindStack performs the x64 phase-two unwind used by RtlUnwindEx.
// The context remains at the target frame and is redirected to targetIP.
func UnwindStack(mem *mmu.MMU, exceptionRecordAddr, contextRecordAddr uint64,
	targetFrame, targetIP, returnValue, historyTable uint64,
	guestCall GuestCallFunc, trace bool) error {

	if mem == nil || exceptionRecordAddr == 0 || contextRecordAddr == 0 {
		return fmt.Errorf("invalid unwind inputs")
	}
	context, err := ReadAMD64Context(mem, contextRecordAddr)
	if err != nil {
		return err
	}
	exceptionCode, err := mem.Read32(exceptionRecordAddr)
	if err != nil {
		return err
	}
	flags, err := mem.Read32(exceptionRecordAddr + 4)
	if err != nil {
		return err
	}
	flags &^= ExceptionFlagTargetUnwind | ExceptionFlagCollidedUnwind
	flags |= ExceptionFlagUnwinding
	if targetFrame == 0 {
		flags |= ExceptionFlagExitUnwind
	} else {
		flags &^= ExceptionFlagExitUnwind
	}
	if err := mem.Write32(exceptionRecordAddr+4, flags); err != nil {
		return err
	}

	reachedTarget := false
	var lastRip, lastRSP, lastFrame uint64
	for depth := 0; depth < 256; depth++ {
		if context.Rip == 0 || context.Regs[regRSP] == 0 {
			break
		}
		current := *context
		unwound := current
		functionEntry, imageBase, entryAddr := LookupFunctionEntry(mem, current.Rip, guestCall)
		handlerAddr, handlerData, establisherFrame, unwindErr := VirtualUnwind(
			mem,
			UnwFlagUHandler,
			imageBase,
			current.Rip,
			functionEntry,
			&unwound,
		)
		if unwindErr != nil {
			return &UnwindError{
				Status: StatusBadFunctionTable,
				Err:    fmt.Errorf("unwind frame at RIP 0x%x: %w", current.Rip, unwindErr),
			}
		}
		lastRip = current.Rip
		lastRSP = current.Regs[regRSP]
		lastFrame = establisherFrame
		atTarget := targetFrame != 0 && establisherFrame == targetFrame
		if atTarget {
			flags |= ExceptionFlagTargetUnwind
			if err := mem.Write32(exceptionRecordAddr+4, flags); err != nil {
				return err
			}
		}

		if trace {
			ravelog.Logf("[seh] unwind depth=%d rip=0x%x frame=0x%x target=%t handler=0x%x\n",
				depth, current.Rip, establisherFrame, atTarget, handlerAddr)
		}
		if handlerAddr != 0 {
			if guestCall == nil {
				return &UnwindError{
					Status: StatusInvalidDisposition,
					Err:    fmt.Errorf("unwind handler 0x%x requires a guest caller", handlerAddr),
				}
			}
			if err := WriteAMD64Context(mem, contextRecordAddr, &unwound); err != nil {
				return err
			}
			dispatcherContextAddr := mem.Mmap(0, 0x80, mmu.PermRead|mmu.PermWrite)
			dispatcherContext := &DispatcherContext{
				ControlPc:        current.Rip,
				ImageBase:        imageBase,
				FunctionEntry:    entryAddr,
				EstablisherFrame: establisherFrame,
				TargetIp:         targetIP,
				ContextRecord:    contextRecordAddr,
				LanguageHandler:  handlerAddr,
				HandlerData:      handlerData,
				HistoryTable:     historyTable,
			}
			if err := WriteDispatcherContext(mem, dispatcherContextAddr, dispatcherContext); err != nil {
				return err
			}
			defer mem.Munmap(dispatcherContextAddr, 0x80)
			disposition, callErr := guestCall(handlerAddr, []uint64{
				exceptionRecordAddr,
				establisherFrame,
				contextRecordAddr,
				dispatcherContextAddr,
			})
			if callErr != nil {
				return fmt.Errorf("call unwind handler 0x%x: %w", handlerAddr, callErr)
			}
			switch uint32(disposition) {
			case ExceptionDispositionContinueSearch:
				flags &^= ExceptionFlagCollidedUnwind
				if err := mem.Write32(exceptionRecordAddr+4, flags); err != nil {
					return err
				}
			case ExceptionDispositionCollidedUnwind:
				collidedDispatch, err := ReadDispatcherContext(mem, dispatcherContextAddr)
				if err != nil {
					return fmt.Errorf("read collided unwind context: %w", err)
				}
				collidedContextAddr := collidedDispatch.ContextRecord
				if collidedContextAddr == 0 {
					collidedContextAddr = contextRecordAddr
				}
				collidedContext, err := ReadAMD64Context(mem, collidedContextAddr)
				if err != nil {
					return fmt.Errorf("read collided unwind CPU context: %w", err)
				}
				collidedFunction := ReadRuntimeFunctionEntry(mem, collidedDispatch.FunctionEntry)
				collidedImageBase := collidedDispatch.ImageBase
				if collidedFunction == nil {
					collidedFunction, collidedImageBase, _ = LookupFunctionEntry(
						mem,
						collidedDispatch.ControlPc,
						guestCall,
					)
				}
				if collidedFunction == nil {
					return fmt.Errorf("collided unwind has no function entry at 0x%x", collidedDispatch.ControlPc)
				}
				if _, _, _, err := VirtualUnwind(
					mem,
					0,
					collidedImageBase,
					collidedDispatch.ControlPc,
					collidedFunction,
					collidedContext,
				); err != nil {
					return fmt.Errorf("unwind collided frame at 0x%x: %w", collidedDispatch.ControlPc, err)
				}
				flags |= ExceptionFlagCollidedUnwind
				if err := mem.Write32(exceptionRecordAddr+4, flags); err != nil {
					return err
				}
				*context = *collidedContext
				if err := WriteAMD64Context(mem, contextRecordAddr, context); err != nil {
					return err
				}
				continue
			default:
				return &UnwindError{
					Status: StatusInvalidDisposition,
					Err:    fmt.Errorf("disposition 0x%x from handler 0x%x", disposition, handlerAddr),
				}
			}
		}

		if atTarget {
			*context = current
			reachedTarget = true
			break
		}
		if unwound.Rip == current.Rip && unwound.Regs[regRSP] == current.Regs[regRSP] {
			return fmt.Errorf("unwind made no progress at RIP 0x%x", current.Rip)
		}
		*context = unwound
		if err := WriteAMD64Context(mem, contextRecordAddr, context); err != nil {
			return err
		}
		if targetFrame == 0 && context.Rip == 0 {
			break
		}
		if depth == 255 {
			return fmt.Errorf("unwind exceeded frame limit")
		}
	}
	if targetFrame != 0 && !reachedTarget {
		return &UnwindError{
			Status: StatusInvalidUnwindTarget,
			Err: fmt.Errorf(
				"target frame 0x%x was not found (last RIP 0x%x RSP 0x%x frame 0x%x)",
				targetFrame,
				lastRip,
				lastRSP,
				lastFrame,
			),
		}
	}
	if targetFrame == 0 {
		if err := WriteAMD64Context(mem, contextRecordAddr, context); err != nil {
			return err
		}
		return &UnwindError{
			Status: StatusBadStack,
			Err:    fmt.Errorf("exit unwind exhausted the stack"),
		}
	}

	context.Regs[regRAX] = returnValue
	if err := WriteAMD64Context(mem, contextRecordAddr, context); err != nil {
		return err
	}
	if exceptionCode == StatusUnwindConsolidate {
		count, err := mem.Read32(exceptionRecordAddr + 0x18)
		if err != nil {
			return err
		}
		if count < 1 || guestCall == nil {
			return &UnwindError{
				Status: StatusInvalidDisposition,
				Err:    fmt.Errorf("invalid unwind consolidation record"),
			}
		}
		callback, err := mem.Read64(exceptionRecordAddr + 0x20)
		if err != nil || callback == 0 {
			return &UnwindError{
				Status: StatusInvalidDisposition,
				Err:    fmt.Errorf("invalid unwind consolidation callback"),
			}
		}
		continuation, callErr := guestCall(callback, []uint64{exceptionRecordAddr})
		if callErr != nil {
			return &UnwindError{
				Status: StatusInvalidDisposition,
				Err:    fmt.Errorf("call unwind consolidation callback 0x%x: %w", callback, callErr),
			}
		}
		refreshed, err := ReadAMD64Context(mem, contextRecordAddr)
		if err != nil {
			return err
		}
		context = refreshed
		context.Rip = continuation
	} else {
		context.Rip = targetIP
	}
	return WriteAMD64Context(mem, contextRecordAddr, context)
}

func ReadDispatcherContext(mem *mmu.MMU, addr uint64) (*DispatcherContext, error) {
	if addr == 0 {
		return nil, fmt.Errorf("nil dispatcher context")
	}
	read64 := func(off uint64) uint64 {
		v, _ := mem.Read64(addr + off)
		return v
	}
	scopeIndex, _ := mem.Read32(addr + 72)
	return &DispatcherContext{
		ControlPc:        read64(0),
		ImageBase:        read64(8),
		FunctionEntry:    read64(16),
		EstablisherFrame: read64(24),
		TargetIp:         read64(32),
		ContextRecord:    read64(40),
		LanguageHandler:  read64(48),
		HandlerData:      read64(56),
		HistoryTable:     read64(64),
		ScopeIndex:       scopeIndex,
	}, nil
}

func WriteDispatcherContext(mem *mmu.MMU, addr uint64, dc *DispatcherContext) error {
	if addr == 0 || dc == nil {
		return fmt.Errorf("invalid dispatcher context")
	}
	mem.Write64(addr+0, dc.ControlPc)
	mem.Write64(addr+8, dc.ImageBase)
	mem.Write64(addr+16, dc.FunctionEntry)
	mem.Write64(addr+24, dc.EstablisherFrame)
	mem.Write64(addr+32, dc.TargetIp)
	mem.Write64(addr+40, dc.ContextRecord)
	mem.Write64(addr+48, dc.LanguageHandler)
	mem.Write64(addr+56, dc.HandlerData)
	mem.Write64(addr+64, dc.HistoryTable)
	mem.Write32(addr+72, dc.ScopeIndex)
	return nil
}

func DispatchException(mem *mmu.MMU, exceptionRecordAddr, contextRecordAddr uint64, guestCall GuestCallFunc, trace bool) (bool, error) {
	if mem == nil || exceptionRecordAddr == 0 || contextRecordAddr == 0 {
		return false, fmt.Errorf("invalid exception dispatch inputs")
	}
	for depth := 0; depth < 64; depth++ {
		ctx, err := ReadAMD64Context(mem, contextRecordAddr)
		if err != nil {
			return false, err
		}

		functionEntry, imageBase, entryAddr := LookupFunctionEntry(mem, ctx.Rip, guestCall)
		if functionEntry == nil {
			retAddr, err := mem.Read64(ctx.Regs[regRSP])
			if err != nil || retAddr == 0 {
				return false, nil
			}
			ctx.Regs[regRSP] += 8
			ctx.Rip = retAddr
			if err := WriteAMD64Context(mem, contextRecordAddr, ctx); err != nil {
				return false, err
			}
			continue
		}

		unwound := *ctx
		handlerAddr, handlerData, establisherFrame, err := VirtualUnwind(mem, 1, imageBase, ctx.Rip, functionEntry, &unwound)
		if err != nil {
			return false, err
		}
		if trace {
			ravelog.Logf("[seh] dispatch depth=%d rip=0x%x handler=0x%x establisher=0x%x\n", depth, ctx.Rip, handlerAddr, establisherFrame)
		}

		if handlerAddr != 0 && guestCall != nil {
			dispatcherContextAddr := mem.Mmap(0, 0x80, mmu.PermRead|mmu.PermWrite)
			dispatcherContext := &DispatcherContext{
				ControlPc:        ctx.Rip,
				ImageBase:        imageBase,
				FunctionEntry:    entryAddr,
				EstablisherFrame: establisherFrame,
				ContextRecord:    contextRecordAddr,
				LanguageHandler:  handlerAddr,
				HandlerData:      handlerData,
			}
			_ = WriteDispatcherContext(mem, dispatcherContextAddr, dispatcherContext)
			disposition, err := guestCall(handlerAddr, []uint64{
				exceptionRecordAddr,
				establisherFrame,
				contextRecordAddr,
				dispatcherContextAddr,
			})
			if err != nil {
				return false, err
			}
			switch uint32(disposition) {
			case ExceptionDispositionContinueExecution:
				return true, nil
			case ExceptionDispositionContinueSearch:
			default:
				if trace {
					ravelog.Logf("[seh] unexpected handler disposition 0x%x at 0x%x\n", disposition, handlerAddr)
				}
			}
		}

		if err := WriteAMD64Context(mem, contextRecordAddr, &unwound); err != nil {
			return false, err
		}
	}
	return false, nil
}

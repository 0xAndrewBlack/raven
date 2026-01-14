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

	ExceptionContinueExecution = 0xFFFFFFFF
	ExceptionContinueSearch    = 0
	ExceptionExecuteHandler    = 1
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
	Rflags uint64
	Rip    uint64
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
	defer sehFunctionTableMu.RUnlock()

	for i := range staticFunctionTables {
		table := &staticFunctionTables[i]
		if controlPC < table.baseAddr || controlPC >= table.endAddr {
			continue
		}
		rva := uint32(controlPC - table.baseAddr)
		if entry := lookupRuntimeFunctionInEntries(table.entries, rva); entry != nil {
			return entry, table.baseAddr, entry.EntryAddr
		}
	}

	for i := range dynamicFunctionTables {
		table := &dynamicFunctionTables[i]
		if controlPC < table.baseAddr || controlPC >= table.endAddr {
			continue
		}
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
	if ctx.Rflags, err = read64(0x30); err != nil {
		return nil, err
	}
	offsets := []uint64{0x78, 0x80, 0x88, 0x90, 0x98, 0xA0, 0xA8, 0xB0, 0xB8, 0xC0, 0xC8, 0xD0, 0xD8, 0xE0, 0xE8, 0xF0}
	for i, off := range offsets {
		if ctx.Regs[i], err = read64(off); err != nil {
			return nil, err
		}
	}
	if ctx.Rip, err = read64(0xF8); err != nil {
		return nil, err
	}
	return ctx, nil
}

func WriteAMD64Context(mem *mmu.MMU, ctxAddr uint64, ctx *AMD64Context) error {
	if ctxAddr == 0 || ctx == nil {
		return fmt.Errorf("invalid CONTEXT write")
	}
	mem.Write32(ctxAddr+0x00, 0x10000B)
	mem.Write64(ctxAddr+0x30, ctx.Rflags)
	offsets := []uint64{0x78, 0x80, 0x88, 0x90, 0x98, 0xA0, 0xA8, 0xB0, 0xB8, 0xC0, 0xC8, 0xD0, 0xD8, 0xE0, 0xE8, 0xF0}
	for i, off := range offsets {
		mem.Write64(ctxAddr+off, ctx.Regs[i])
	}
	mem.Write64(ctxAddr+0xF8, ctx.Rip)
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

func getEstablisherFrame(ctx *AMD64Context, ui *UnwindInfo, codeOffset uint32) uint64 {
	if ui == nil {
		return ctx.Regs[regRSP]
	}
	if ui.FrameRegister == 0 {
		return ctx.Regs[regRSP]
	}
	if codeOffset >= uint32(ui.SizeOfProlog) || ui.Flags&UnwFlagChainInfo != 0 {
		return ctx.GetReg(ui.FrameRegister) - uint64(ui.FrameOffset)*16
	}
	for i := uint8(0); i < ui.CountOfCodes; i++ {
		codeAddr := 4 + uint64(i)*2
		_ = codeAddr
	}
	return ctx.Regs[regRSP]
}

func VirtualUnwind(mem *mmu.MMU, handlerType uint32, imageBase, controlPC uint64, functionEntry *RuntimeFunction, ctx *AMD64Context) (uint64, uint64, uint64, error) {
	if ctx == nil {
		return 0, 0, 0, fmt.Errorf("nil unwind context")
	}
	if functionEntry == nil {
		retAddr, err := mem.Read64(ctx.Regs[regRSP])
		if err != nil {
			return 0, 0, ctx.Regs[regRSP], err
		}
		ctx.Regs[regRSP] += 8
		ctx.Rip = retAddr
		return 0, 0, ctx.Regs[regRSP], nil
	}

	rva := uint32(0)
	if controlPC >= imageBase {
		rva = uint32(controlPC - imageBase)
	}
	ui := ParseUnwindInfo(mem, imageBase, functionEntry.UnwindData)
	if ui == nil {
		return 0, 0, 0, fmt.Errorf("missing unwind info")
	}

	savedRegs := make(map[int]uint64)
	frameSize := unwindFrame(mem, imageBase+uint64(functionEntry.UnwindData), ui, ctx.Regs[regRSP], savedRegs)
	parentRSP := ctx.Regs[regRSP] + frameSize
	establisherFrame := getEstablisherFrame(ctx, ui, rva-functionEntry.BeginAddress)

	for reg, val := range savedRegs {
		ctx.SetReg(reg, val)
	}

	retAddr, err := mem.Read64(parentRSP - 8)
	if err != nil {
		return 0, 0, establisherFrame, err
	}
	ctx.Regs[regRSP] = parentRSP
	ctx.Rip = retAddr

	var handlerAddr, handlerData uint64
	if handlerType != 0 && ui.Flags&(UnwFlagEHandler|UnwFlagUHandler) != 0 {
		handlerAddr = imageBase + uint64(ui.HandlerRVA)
		handlerData = ui.HandlerData
	}
	return handlerAddr, handlerData, establisherFrame, nil
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

package ntapi

import (
	"fmt"
	"math"
	"os"

	"github.com/mirkobrombin/Raven/pkg/arch"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/vfs"

	ravelog "github.com/mirkobrombin/Raven/pkg/log"
)

// TrapHandler is a function that handles a single NT syscall.
// It receives the CPU state and returns an NTSTATUS code.
type TrapHandler func(ctx *TrapContext) uint32

// TrapContext provides access to guest CPU state and VM subsystems for handlers.
type TrapContext struct {
	CPU     arch.CPU
	Mem     *mmu.MMU
	FS      *vfs.VFS
	Handles *HandleTable
	Reg     *RegistryHive
	State   *ProcessState
	Disp    *Dispatcher
	Trace   bool
	flsSlots   map[uint32]uint64
	flsNextIdx uint32
	// ReturnOverridden is set by handlers that manage RAX directly,
	// preventing the dispatcher from overwriting it with the handler's return.
	ReturnOverridden bool
}

// Arg reads a Windows x64 calling convention argument (RCX, RDX, R8, R9, stack).
func (ctx *TrapContext) Arg(n int) uint64 {
	args := ctx.CPU.SyscallArgs() // [RDI, RSI, RDX, R10, R8, R9]
	// Windows x64 ABI: RCX=arg0, RDX=arg1, R8=arg2, R9=arg3
	// We need to read directly from registers since SyscallArgs() is Linux ABI.
	mem := ctx.CPU.GetMem()
	switch n {
	case 0:
		return readReg(mem, ctx.CPU, regRCX)
	case 1:
		return readReg(mem, ctx.CPU, regRDX)
	case 2:
		return readReg(mem, ctx.CPU, regR8)
	case 3:
		return readReg(mem, ctx.CPU, regR9)
	default:
		// Stack arguments: RSP + 0x28 + (n-4)*8
		// (0x28 = return addr + 4 shadow slots)
		sp := ctx.CPU.GetSP()
		addr := sp + 0x28 + uint64(n-4)*8
		val, err := mem.Read64(addr)
		if err != nil {
			return 0
		}
		_ = args
		return val
	}
}

// SetReturn sets the return value (RAX) and prevents the dispatcher
// from overwriting it with the handler's return code.
func (ctx *TrapContext) SetReturn(val uint64) {
	ctx.CPU.SetSyscallReturn(val)
	ctx.ReturnOverridden = true
}

// FloatArg reads a Windows x64 float argument from XMM0-XMM3.
func (ctx *TrapContext) FloatArg(n int) float64 {
	if xa, ok := ctx.CPU.(XMMAccess); ok && n >= 0 && n < 4 {
		return math.Float64frombits(xa.ReadXMM(n))
	}
	return 0
}

// SetFloatReturn writes a float64 result to XMM0.
func (ctx *TrapContext) SetFloatReturn(val float64) {
	if xa, ok := ctx.CPU.(XMMAccess); ok {
		xa.WriteXMM(0, math.Float64bits(val))
	}
	ctx.ReturnOverridden = true
}

// Register constants for direct access.
const (
	regRAX = 0
	regRCX = 1
	regRDX = 2
	regRBX = 3
	regRSP = 4
	regRBP = 5
	regRSI = 6
	regRDI = 7
	regR8  = 8
	regR9  = 9
	regR10 = 10
	regR11 = 11
)

// readReg reads a register by index from the x64 CPU.
// The CPU interface doesn't expose individual registers, so we use a workaround:
// SyscallArgs returns [RDI, RSI, RDX, R10, R8, R9].
// SyscallNum returns RAX.
// For RCX and R9 we need the RegisterReader interface.
func readReg(mem *mmu.MMU, cpu arch.CPU, reg int) uint64 {
	if rr, ok := cpu.(RegisterReader); ok {
		return rr.ReadReg(reg)
	}
	// Fallback using available interface methods
	args := cpu.SyscallArgs() // [RDI, RSI, RDX, R10, R8, R9]
	switch reg {
	case regRAX:
		return cpu.SyscallNum()
	case regRDI:
		return args[0]
	case regRSI:
		return args[1]
	case regRDX:
		return args[2]
	case regR10:
		return args[3]
	case regR8:
		return args[4]
	case regR9:
		return args[5]
	case regRSP:
		return cpu.GetSP()
	default:
		return 0
	}
}

// RegisterReader is an optional interface for CPUs that expose register reads.
type RegisterReader interface {
	ReadReg(idx int) uint64
}

// RegisterWriter is an optional interface for CPUs that expose register writes.
type RegisterWriter interface {
	WriteReg(idx int, val uint64)
}

// XMMAccess is an optional interface for CPUs that expose XMM register access.
type XMMAccess interface {
	ReadXMM(idx int) uint64
	WriteXMM(idx int, val uint64)
}

// Dispatcher routes vmcall traps to the appropriate handler based on syscall ID.
type Dispatcher struct {
	handlers      map[uint32]TrapHandler
	names         map[uint32]string // for trace logging
	ntdll         *SynthPE
	win32u        *SynthPE
	ctx           *TrapContext
	moduleExports map[uint64]map[string]uint64 // baseAddr → name → addr
	moduleOrdExports map[uint64]map[uint16]uint64 // baseAddr → ordinal → addr
	sysRoot       string // path to Windows system DLL directory
	nlsCache      map[uint32][]byte // cached NLS file data by code page
}

// NewDispatcher creates a trap dispatcher with all registered handlers.
func NewDispatcher(mem *mmu.MMU, fs *vfs.VFS, handles *HandleTable, reg *RegistryHive, state *ProcessState, ntdll, win32u *SynthPE) *Dispatcher {
	d := &Dispatcher{
		handlers:         make(map[uint32]TrapHandler),
		names:            make(map[uint32]string),
		ntdll:            ntdll,
		win32u:           win32u,
		moduleExports:    make(map[uint64]map[string]uint64),
		moduleOrdExports: make(map[uint64]map[uint16]uint64),
		nlsCache:         make(map[uint32][]byte),
		ctx: &TrapContext{
			Mem:        mem,
			FS:         fs,
			Handles:    handles,
			Reg:        reg,
			State:      state,
		},
	}
	d.ctx.Disp = d

	d.registerNtapiHandlers()
	d.registerWin32kHandlers()

	// Register the DllMain return sentinel
	d.register(DllMainReturnID, "_DllMainReturn", func(ctx *TrapContext) uint32 {
		ctx.CPU.Stop()
		return StatusSuccess
	})

	return d
}

// SetTrace enables/disables trace logging.
func (d *Dispatcher) SetTrace(trace bool) {
	d.ctx.Trace = trace
}

// SetSysRoot sets the path to the Windows system DLL directory for NLS file loading.
func (d *Dispatcher) SetSysRoot(path string) {
	d.sysRoot = path
}

// loadNlsFile loads an NLS code page file from the sysroot.
func (d *Dispatcher) loadNlsFile(codePage uint32) ([]byte, error) {
	if data, ok := d.nlsCache[codePage]; ok {
		return data, nil
	}
	if d.sysRoot == "" {
		return nil, fmt.Errorf("no sysroot configured")
	}
	filename := fmt.Sprintf("c_%d.nls", codePage)
	path := d.sysRoot + "/" + filename
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	d.nlsCache[codePage] = data
	return data, nil
}

// RegisterModuleExports registers a loaded module's exports for LdrGetProcedureAddress.
func (d *Dispatcher) RegisterModuleExports(baseAddr uint64, exports map[string]uint64, ordExports map[uint16]uint64) {
	if len(exports) > 0 {
		d.moduleExports[baseAddr] = exports
	}
	if len(ordExports) > 0 {
		d.moduleOrdExports[baseAddr] = ordExports
	}
}

// LookupExportByModule resolves a function address from a module's export table.
func (d *Dispatcher) LookupExportByModule(moduleBase uint64, funcName string, ordinal uint16) uint64 {
	// Check synthetic ntdll/win32u first
	if d.ntdll != nil && moduleBase == d.ntdll.BaseAddr {
		if funcName != "" {
			if addr, ok := d.ntdll.Exports[funcName]; ok {
				return addr
			}
		}
	}
	if d.win32u != nil && moduleBase == d.win32u.BaseAddr {
		if funcName != "" {
			if addr, ok := d.win32u.Exports[funcName]; ok {
				return addr
			}
		}
	}

	// Check registered module exports
	if funcName != "" {
		if exports, ok := d.moduleExports[moduleBase]; ok {
			if addr, ok := exports[funcName]; ok {
				return addr
			}
		}
	}
	if ordinal != 0 {
		if ordExports, ok := d.moduleOrdExports[moduleBase]; ok {
			if addr, ok := ordExports[ordinal]; ok {
				return addr
			}
		}
	}
	return 0
}

// RegisterAutoStubNames registers display names for auto-generated stub DLL
// trap IDs so they appear in trace output. The synth DLL's StubIDs maps
// stub guest addresses to trap IDs.
func (d *Dispatcher) RegisterAutoStubNames(synth *SynthPE) {
	for _, id := range synth.StubIDs {
		for name, addr := range synth.Exports {
			if synth.StubIDs[addr] == id {
				d.names[id] = synth.Name + "!" + name
				break
			}
		}
	}
}

// RegisterAutoStubHandler registers a handler for a specific function in a
// synthetic DLL by looking up its trap ID.
func (d *Dispatcher) RegisterAutoStubHandler(synth *SynthPE, funcName string, h TrapHandler) {
	addr, ok := synth.Exports[funcName]
	if !ok {
		return
	}
	id, ok := synth.StubIDs[addr]
	if !ok {
		return
	}
	d.handlers[id] = h
}

// RegisterDynamicHandler adds a new export to a synthetic DLL and registers
// a handler for it. Used for functions that apps look up via GetProcAddress
// but aren't in the DLL's original import table.
func (d *Dispatcher) RegisterDynamicHandler(mem *mmu.MMU, synth *SynthPE, funcName string, id uint32, h TrapHandler) {
	// Check if already exists as a regular export
	if addr, ok := synth.Exports[funcName]; ok {
		if existingID, ok := synth.StubIDs[addr]; ok {
			d.handlers[existingID] = h
			return
		}
	}
	allocID := synth.AddDynamicExport(mem, funcName, id)
	if allocID == 0 {
		return
	}
	d.handlers[id] = h
	d.names[id] = synth.Name + "!" + funcName
}

// Handle is the vmcall trap entry point, called by the CPU emulator.
func (d *Dispatcher) Handle(cpu arch.CPU) {
	d.ctx.CPU = cpu
	syscallID := uint32(cpu.SyscallNum()) // EAX contains the syscall ID

	handler, ok := d.handlers[syscallID]
	if !ok {
		name := d.names[syscallID]
		if name == "" {
			name = fmt.Sprintf("unknown_0x%04X", syscallID)
		}
		ravelog.Logf("[ntapi] UNIMPLEMENTED: %s (id=0x%04X)\n", name, syscallID)
		// For auto-synth user-mode DLL stubs, return 0 (NULL/FALSE).
		// For NT syscalls, return STATUS_NOT_IMPLEMENTED.
		if syscallID >= AutoSynthIDBase {
			cpu.SetSyscallReturn(0)
		} else {
			cpu.SetSyscallReturn(0xC0000002)
		}
		return
	}

	if d.ctx.Trace {
		name := d.names[syscallID]
		sp := cpu.GetSP()
		if name != "__wine_dbg_header" || sp < 0x7C000000 {
			retAddr, _ := d.ctx.Mem.Read64(sp)
			ravelog.Logf("[trace] → %s (id=0x%04X) sp=0x%x ret=0x%x\n", name, syscallID, sp, retAddr)
		}
	}

	d.ctx.ReturnOverridden = false
	status := handler(d.ctx)
	if !d.ctx.ReturnOverridden {
		cpu.SetSyscallReturn(uint64(status))
	}
}

// register adds a handler for a given syscall ID.
func (d *Dispatcher) register(id uint32, name string, h TrapHandler) {
	d.handlers[id] = h
	d.names[id] = name
}

// RegisterHandler registers a handler for a specific syscall ID.
func (d *Dispatcher) RegisterHandler(id uint32, name string, h TrapHandler) {
	d.handlers[id] = h
	d.names[id] = name
}

// registerNtapiHandlers registers all NTAPI syscall handlers.
func (d *Dispatcher) registerNtapiHandlers() {
	for i, name := range ntapiExports {
		id := ntapiIDBase + uint32(i)
		d.names[id] = name
	}

	// File I/O
	d.register(idOf("NtCreateFile"), "NtCreateFile", handleNtCreateFile)
	d.register(idOf("NtOpenFile"), "NtOpenFile", handleNtOpenFile)
	d.register(idOf("NtReadFile"), "NtReadFile", handleNtReadFile)
	d.register(idOf("NtWriteFile"), "NtWriteFile", handleNtWriteFile)
	d.register(idOf("NtClose"), "NtClose", handleNtClose)
	d.register(idOf("NtQueryInformationFile"), "NtQueryInformationFile", handleNtQueryInformationFile)
	d.register(idOf("NtSetInformationFile"), "NtSetInformationFile", handleNtSetInformationFile)
	d.register(idOf("NtQueryDirectoryFile"), "NtQueryDirectoryFile", handleNtQueryDirectoryFile)
	d.register(idOf("NtQueryVolumeInformationFile"), "NtQueryVolumeInformationFile", handleNtQueryVolumeInformationFile)
	d.register(idOf("NtDeleteFile"), "NtDeleteFile", handleNtDeleteFile)
	d.register(idOf("NtFlushBuffersFile"), "NtFlushBuffersFile", handleNtFlushBuffersFile)
	d.register(idOf("NtDeviceIoControlFile"), "NtDeviceIoControlFile", handleNtDeviceIoControlFile)
	d.register(idOf("NtCreateSection"), "NtCreateSection", handleNtCreateSection)
	d.register(idOf("NtMapViewOfSection"), "NtMapViewOfSection", handleNtMapViewOfSection)
	d.register(idOf("NtUnmapViewOfSection"), "NtUnmapViewOfSection", handleNtUnmapViewOfSection)

	// Registry
	d.register(idOf("NtOpenKey"), "NtOpenKey", handleNtOpenKey)
	d.register(idOf("NtOpenKeyEx"), "NtOpenKeyEx", handleNtOpenKeyEx)
	d.register(idOf("NtCreateKey"), "NtCreateKey", handleNtCreateKey)
	d.register(idOf("NtQueryValueKey"), "NtQueryValueKey", handleNtQueryValueKey)
	d.register(idOf("NtSetValueKey"), "NtSetValueKey", handleNtSetValueKey)
	d.register(idOf("NtDeleteKey"), "NtDeleteKey", handleNtDeleteKey)
	d.register(idOf("NtDeleteValueKey"), "NtDeleteValueKey", handleNtDeleteValueKey)
	d.register(idOf("NtEnumerateKey"), "NtEnumerateKey", handleNtEnumerateKey)
	d.register(idOf("NtEnumerateValueKey"), "NtEnumerateValueKey", handleNtEnumerateValueKey)
	d.register(idOf("NtQueryKey"), "NtQueryKey", handleNtQueryKey)

	// Process / Thread
	d.register(idOf("NtQueryInformationProcess"), "NtQueryInformationProcess", handleNtQueryInformationProcess)
	d.register(idOf("NtQueryInformationThread"), "NtQueryInformationThread", handleNtQueryInformationThread)
	d.register(idOf("NtQuerySystemInformation"), "NtQuerySystemInformation", handleNtQuerySystemInformation)
	d.register(idOf("NtTerminateProcess"), "NtTerminateProcess", handleNtTerminateProcess)

	// Virtual Memory
	d.register(idOf("NtAllocateVirtualMemory"), "NtAllocateVirtualMemory", handleNtAllocateVirtualMemory)
	d.register(idOf("NtFreeVirtualMemory"), "NtFreeVirtualMemory", handleNtFreeVirtualMemory)
	d.register(idOf("NtProtectVirtualMemory"), "NtProtectVirtualMemory", handleNtProtectVirtualMemory)
	d.register(idOf("NtQueryVirtualMemory"), "NtQueryVirtualMemory", handleNtQueryVirtualMemory)

	// Synchronization
	d.register(idOf("NtCreateEvent"), "NtCreateEvent", handleNtCreateEvent)
	d.register(idOf("NtSetEvent"), "NtSetEvent", handleNtSetEvent)
	d.register(idOf("NtResetEvent"), "NtResetEvent", handleNtResetEvent)
	d.register(idOf("NtClearEvent"), "NtClearEvent", handleNtClearEvent)
	d.register(idOf("NtWaitForSingleObject"), "NtWaitForSingleObject", handleNtWaitForSingleObject)
	d.register(idOf("NtWaitForMultipleObjects"), "NtWaitForMultipleObjects", handleNtWaitForMultipleObjects)
	d.register(idOf("NtCreateMutant"), "NtCreateMutant", handleNtCreateMutant)
	d.register(idOf("NtReleaseMutant"), "NtReleaseMutant", handleNtReleaseMutant)
	d.register(idOf("NtDelayExecution"), "NtDelayExecution", handleNtDelayExecution)
	d.register(idOf("NtYieldExecution"), "NtYieldExecution", handleNtYieldExecution)
	d.register(idOf("NtQueryPerformanceCounter"), "NtQueryPerformanceCounter", handleNtQueryPerformanceCounter)
	d.register(idOf("NtQuerySystemTime"), "NtQuerySystemTime", handleNtQuerySystemTime)

	// Critical Sections (implemented in handler, not real kernel calls)
	d.register(idOf("RtlInitializeCriticalSection"), "RtlInitializeCriticalSection", handleRtlInitCritSec)
	d.register(idOf("RtlInitializeCriticalSectionAndSpinCount"), "RtlInitializeCriticalSectionAndSpinCount", handleRtlInitCritSec)
	d.register(idOf("RtlInitializeCriticalSectionEx"), "RtlInitializeCriticalSectionEx", handleRtlInitCritSec)
	d.register(idOf("RtlEnterCriticalSection"), "RtlEnterCriticalSection", handleRtlEnterCritSec)
	d.register(idOf("RtlLeaveCriticalSection"), "RtlLeaveCriticalSection", handleRtlLeaveCritSec)
	d.register(idOf("RtlDeleteCriticalSection"), "RtlDeleteCriticalSection", handleRtlDeleteCritSec)
	d.register(idOf("RtlTryEnterCriticalSection"), "RtlTryEnterCriticalSection", handleRtlTryEnterCritSec)

	// SRW Locks
	d.register(idOf("RtlInitializeSRWLock"), "RtlInitializeSRWLock", handleRtlInitSRWLock)
	d.register(idOf("RtlAcquireSRWLockExclusive"), "RtlAcquireSRWLockExclusive", handleRtlAcquireSRWExcl)
	d.register(idOf("RtlReleaseSRWLockExclusive"), "RtlReleaseSRWLockExclusive", handleRtlReleaseSRWExcl)
	d.register(idOf("RtlAcquireSRWLockShared"), "RtlAcquireSRWLockShared", handleRtlAcquireSRWShared)
	d.register(idOf("RtlReleaseSRWLockShared"), "RtlReleaseSRWLockShared", handleRtlReleaseSRWShared)
	d.register(idOf("RtlTryAcquireSRWLockExclusive"), "RtlTryAcquireSRWLockExclusive", handleRtlTryAcquireSRWExcl)
	d.register(idOf("RtlTryAcquireSRWLockShared"), "RtlTryAcquireSRWLockShared", handleRtlTryAcquireSRWShared)

	// Condition Variables
	d.register(idOf("RtlInitializeConditionVariable"), "RtlInitializeConditionVariable", handleRtlInitCondVar)
	d.register(idOf("RtlWakeConditionVariable"), "RtlWakeConditionVariable", handleRtlWakeCondVar)
	d.register(idOf("RtlWakeAllConditionVariable"), "RtlWakeAllConditionVariable", handleRtlWakeAllCondVar)

	// Heap
	d.register(idOf("RtlAllocateHeap"), "RtlAllocateHeap", handleRtlAllocateHeap)
	d.register(idOf("RtlFreeHeap"), "RtlFreeHeap", handleRtlFreeHeap)
	d.register(idOf("RtlReAllocateHeap"), "RtlReAllocateHeap", handleRtlReAllocateHeap)
	d.register(idOf("RtlSizeHeap"), "RtlSizeHeap", handleRtlSizeHeap)
	d.register(idOf("RtlCreateHeap"), "RtlCreateHeap", handleRtlCreateHeap)
	d.register(idOf("RtlDestroyHeap"), "RtlDestroyHeap", handleRtlDestroyHeap)

	// String utilities
	d.register(idOf("RtlInitUnicodeString"), "RtlInitUnicodeString", handleRtlInitUnicodeString)
	d.register(idOf("RtlFreeUnicodeString"), "RtlFreeUnicodeString", handleNoop)

	// Misc
	d.register(idOf("RtlGetVersion"), "RtlGetVersion", handleRtlGetVersion)
	d.register(idOf("RtlNtStatusToDosError"), "RtlNtStatusToDosError", handleRtlNtStatusToDosError)
	d.register(idOf("RtlSetLastWin32Error"), "RtlSetLastWin32Error", handleRtlSetLastWin32Error)
	d.register(idOf("RtlGetLastWin32Error"), "RtlGetLastWin32Error", handleRtlGetLastWin32Error)
	d.register(idOf("NtDuplicateObject"), "NtDuplicateObject", handleNtDuplicateObject)
	d.register(idOf("NtQueryObject"), "NtQueryObject", handleNtQueryObject)

	// DLL loading
	d.register(idOf("LdrGetDllHandle"), "LdrGetDllHandle", handleLdrGetDllHandle)
	d.register(idOf("LdrGetProcedureAddress"), "LdrGetProcedureAddress", handleLdrGetProcedureAddress)
	d.register(idOf("LdrLoadDll"), "LdrLoadDll", handleLdrLoadDll)
	d.register(idOf("LdrGetDllHandleEx"), "LdrGetDllHandleEx", handleLdrGetDllHandleEx)
	d.register(idOf("LdrAddRefDll"), "LdrAddRefDll", handleLdrAddRefDll)
	d.register(idOf("LdrGetDllPath"), "LdrGetDllPath", handleLdrGetDllPath)
	d.register(idOf("LdrGetDllFullName"), "LdrGetDllFullName", handleLdrGetDllFullName)

	// PEB/TEB
	d.register(idOf("RtlGetCurrentPeb"), "RtlGetCurrentPeb", handleRtlGetCurrentPeb)
	d.register(idOf("RtlAcquirePebLock"), "RtlAcquirePebLock", handleRtlAcquirePebLock)
	d.register(idOf("RtlReleasePebLock"), "RtlReleasePebLock", handleRtlReleasePebLock)

	// String conversions
	d.register(idOf("RtlInitAnsiString"), "RtlInitAnsiString", handleRtlInitAnsiString)
	d.register(idOf("RtlInitUnicodeStringEx"), "RtlInitUnicodeStringEx", handleRtlInitUnicodeStringEx)
	d.register(idOf("RtlMultiByteToUnicodeN"), "RtlMultiByteToUnicodeN", handleRtlMultiByteToUnicodeN)
	d.register(idOf("RtlMultiByteToUnicodeSize"), "RtlMultiByteToUnicodeSize", handleRtlMultiByteToUnicodeSize)
	d.register(idOf("RtlUnicodeToMultiByteN"), "RtlUnicodeToMultiByteN", handleRtlUnicodeToMultiByteN)
	d.register(idOf("RtlUnicodeToMultiByteSize"), "RtlUnicodeToMultiByteSize", handleRtlUnicodeToMultiByteSize)
	d.register(idOf("RtlAnsiStringToUnicodeString"), "RtlAnsiStringToUnicodeString", handleRtlAnsiStringToUnicodeString)
	d.register(idOf("RtlUnicodeStringToAnsiString"), "RtlUnicodeStringToAnsiString", handleRtlUnicodeStringToAnsiString)
	d.register(idOf("RtlUnicodeStringToAnsiSize"), "RtlUnicodeStringToAnsiSize", handleNoop)
	d.register(idOf("RtlFreeAnsiString"), "RtlFreeAnsiString", handleRtlFreeAnsiString)
	d.register(idOf("RtlCreateUnicodeString"), "RtlCreateUnicodeString", handleRtlCreateUnicodeString)
	d.register(idOf("RtlCompareUnicodeStrings"), "RtlCompareUnicodeStrings", handleRtlCompareUnicodeStrings)
	d.register(idOf("RtlUTF8ToUnicodeN"), "RtlUTF8ToUnicodeN", handleRtlUTF8ToUnicodeN)
	d.register(idOf("RtlUnicodeToUTF8N"), "RtlUnicodeToUTF8N", handleRtlUnicodeToUTF8N)
	d.register(idOf("RtlIsNormalizedString"), "RtlIsNormalizedString", handleRtlIsNormalizedString)
	d.register(idOf("RtlNormalizeString"), "RtlNormalizeString", handleRtlNormalizeString)
	d.register(idOf("RtlDuplicateUnicodeString"), "RtlDuplicateUnicodeString", handleNoop)

	// PE image helpers
	d.register(idOf("RtlImageNtHeader"), "RtlImageNtHeader", handleRtlImageNtHeader)
	d.register(idOf("RtlImageDirectoryEntryToData"), "RtlImageDirectoryEntryToData", handleRtlImageDirectoryEntryToData)

	// System info
	d.register(idOf("RtlGetNativeSystemInformation"), "RtlGetNativeSystemInformation", handleRtlGetNativeSystemInformation)
	d.register(idOf("NtGetTickCount"), "NtGetTickCount", handleNtGetTickCount)
	d.register(idOf("NtFlushInstructionCache"), "NtFlushInstructionCache", handleNtFlushInstructionCache)
	d.register(idOf("NtQueryDefaultLocale"), "NtQueryDefaultLocale", handleNtQueryDefaultLocale)
	d.register(idOf("NtQueryDefaultUILanguage"), "NtQueryDefaultUILanguage", handleNtQueryDefaultUILanguage)
	d.register(idOf("NtQueryInstallUILanguage"), "NtQueryInstallUILanguage", handleNtQueryInstallUILanguage)

	// Thread context
	d.register(idOf("NtGetContextThread"), "NtGetContextThread", handleNtGetContextThread)
	d.register(idOf("NtSetContextThread"), "NtSetContextThread", handleNtSetContextThread)
	d.register(idOf("NtResumeThread"), "NtResumeThread", handleNtResumeThread)
	d.register(idOf("NtSuspendThread"), "NtSuspendThread", handleNtSuspendThread)

	// Token / Security
	d.register(idOf("NtOpenProcessToken"), "NtOpenProcessToken", handleNtOpenProcessToken)
	d.register(idOf("NtOpenThreadToken"), "NtOpenThreadToken", handleNtOpenThreadToken)
	d.register(idOf("NtQueryInformationToken"), "NtQueryInformationToken", handleNtQueryInformationToken)
	d.register(idOf("NtSetInformationToken"), "NtSetInformationToken", handleNtSetInformationToken)
	d.register(idOf("NtAdjustPrivilegesToken"), "NtAdjustPrivilegesToken", handleNtAdjustPrivilegesToken)
	d.register(idOf("NtPrivilegeCheck"), "NtPrivilegeCheck", handleNtPrivilegeCheck)
	d.register(idOf("NtAllocateLocallyUniqueId"), "NtAllocateLocallyUniqueId", handleNtAllocateLocallyUniqueId)
	d.register(idOf("NtSetSecurityObject"), "NtSetSecurityObject", handleNtSetSecurityObject)
	d.register(idOf("NtQuerySecurityObject"), "NtQuerySecurityObject", handleNtQuerySecurityObject)

	// Heap extended
	d.register(idOf("RtlGetProcessHeaps"), "RtlGetProcessHeaps", handleRtlGetProcessHeaps)
	d.register(idOf("RtlLockHeap"), "RtlLockHeap", handleRtlLockHeap)
	d.register(idOf("RtlUnlockHeap"), "RtlUnlockHeap", handleRtlUnlockHeap)
	d.register(idOf("RtlValidateHeap"), "RtlValidateHeap", handleRtlValidateHeap)
	d.register(idOf("RtlSetHeapInformation"), "RtlSetHeapInformation", handleRtlSetHeapInformation)
	d.register(idOf("RtlQueryHeapInformation"), "RtlQueryHeapInformation", handleRtlQueryHeapInformation)
	d.register(idOf("RtlGetUserInfoHeap"), "RtlGetUserInfoHeap", handleRtlGetUserInfoHeap)
	d.register(idOf("RtlSetUserValueHeap"), "RtlSetUserValueHeap", handleRtlSetUserValueHeap)
	d.register(idOf("RtlCompactHeap"), "RtlCompactHeap", handleRtlCompactHeap)
	d.register(idOf("RtlWalkHeap"), "RtlWalkHeap", handleRtlWalkHeap)

	// Code page / locale
	d.register(idOf("RtlInitCodePageTable"), "RtlInitCodePageTable", handleRtlInitCodePageTable)
	d.register(idOf("RtlInitNlsTables"), "RtlInitNlsTables", handleRtlInitNlsTables)
	d.register(idOf("RtlResetRtlTranslations"), "RtlResetRtlTranslations", handleRtlResetRtlTranslations)

	// FLS
	d.register(idOf("RtlFlsAlloc"), "RtlFlsAlloc", handleRtlFlsAlloc)
	d.register(idOf("RtlFlsFree"), "RtlFlsFree", handleRtlFlsFree)
	d.register(idOf("RtlFlsGetValue"), "RtlFlsGetValue", handleRtlFlsGetValue)
	d.register(idOf("RtlFlsSetValue"), "RtlFlsSetValue", handleRtlFlsSetValue)
	d.register(idOf("RtlProcessFlsData"), "RtlProcessFlsData", handleRtlProcessFlsData)

	// Process/Thread lifecycle
	d.register(idOf("RtlExitUserProcess"), "RtlExitUserProcess", handleRtlExitUserProcess)
	d.register(idOf("RtlExitUserThread"), "RtlExitUserThread", handleRtlExitUserThread)
	d.register(idOf("RtlNormalizeProcessParams"), "RtlNormalizeProcessParams", handleRtlNormalizeProcessParams)
	d.register(idOf("RtlIsProcessorFeaturePresent"), "RtlIsProcessorFeaturePresent", handleRtlIsProcessorFeaturePresent)
	d.register(idOf("NtOpenProcess"), "NtOpenProcess", handleNtOpenProcess)
	d.register(idOf("NtSetInformationProcess"), "NtSetInformationProcess", handleNtSetInformationProcess)
	d.register(idOf("NtSetInformationThread"), "NtSetInformationThread", handleNtSetInformationThread)

	// Exception handling
	d.register(idOf("RtlCaptureContext"), "RtlCaptureContext", handleRtlCaptureContext)
	d.register(idOf("RtlUnwind"), "RtlUnwind", handleRtlUnwind)
	d.register(idOf("RtlUnwindEx"), "RtlUnwindEx", handleRtlUnwindEx)
	d.register(idOf("RtlLookupFunctionEntry"), "RtlLookupFunctionEntry", handleRtlLookupFunctionEntry)
	d.register(idOf("RtlRestoreContext"), "RtlRestoreContext", handleRtlRestoreContext)
	d.register(idOf("RtlRaiseException"), "RtlRaiseException", handleRtlRaiseException)
	d.register(idOf("RtlRaiseStatus"), "RtlRaiseStatus", handleRtlRaiseStatus)
	d.register(idOf("RtlPcToFileHeader"), "RtlPcToFileHeader", handleRtlPcToFileHeader)
	d.register(idOf("RtlGetEnabledExtendedFeatures"), "RtlGetEnabledExtendedFeatures", handleRtlGetEnabledExtendedFeatures)
	d.register(idOf("RtlSetUnhandledExceptionFilter"), "RtlSetUnhandledExceptionFilter", handleRtlSetUnhandledExceptionFilter)

	// Synchronization extended
	d.register(idOf("NtCreateSemaphore"), "NtCreateSemaphore", handleNtCreateSemaphore)
	d.register(idOf("NtReleaseSemaphore"), "NtReleaseSemaphore", handleNtReleaseSemaphore)
	d.register(idOf("NtOpenEvent"), "NtOpenEvent", handleNtOpenEvent)
	d.register(idOf("NtOpenMutant"), "NtOpenMutant", handleNtOpenMutant)
	d.register(idOf("NtOpenSemaphore"), "NtOpenSemaphore", handleNtOpenSemaphore)
	d.register(idOf("NtOpenSection"), "NtOpenSection", handleNtOpenSection)
	d.register(idOf("NtCreateTimer"), "NtCreateTimer", handleNtCreateTimer)
	d.register(idOf("NtSetTimer"), "NtSetTimer", handleNtSetTimer)
	d.register(idOf("NtCancelTimer"), "NtCancelTimer", handleNtCancelTimer)
	d.register(idOf("RtlSleepConditionVariableCS"), "RtlSleepConditionVariableCS", handleRtlSleepConditionVariableCS)
	d.register(idOf("RtlSleepConditionVariableSRW"), "RtlSleepConditionVariableSRW", handleRtlSleepConditionVariableSRW)
	d.register(idOf("RtlWaitOnAddress"), "RtlWaitOnAddress", handleRtlWaitOnAddress)

	// I/O Completion
	d.register(idOf("NtCreateIoCompletion"), "NtCreateIoCompletion", handleNtCreateIoCompletion)
	d.register(idOf("NtSetIoCompletion"), "NtSetIoCompletion", handleNtSetIoCompletion)
	d.register(idOf("NtRemoveIoCompletion"), "NtRemoveIoCompletion", handleNtRemoveIoCompletion)
	d.register(idOf("NtRemoveIoCompletionEx"), "NtRemoveIoCompletionEx", handleNtRemoveIoCompletionEx)
	d.register(idOf("NtCancelIoFile"), "NtCancelIoFile", handleNtCancelIoFile)
	d.register(idOf("NtCancelIoFileEx"), "NtCancelIoFileEx", handleNtCancelIoFileEx)

	// Object manager
	d.register(idOf("NtCreateDirectoryObject"), "NtCreateDirectoryObject", handleNtCreateDirectoryObject)
	d.register(idOf("NtOpenDirectoryObject"), "NtOpenDirectoryObject", handleNtOpenDirectoryObject)
	d.register(idOf("NtCreateSymbolicLinkObject"), "NtCreateSymbolicLinkObject", handleNtCreateSymbolicLinkObject)
	d.register(idOf("NtOpenSymbolicLinkObject"), "NtOpenSymbolicLinkObject", handleNtOpenSymbolicLinkObject)
	d.register(idOf("NtQuerySymbolicLinkObject"), "NtQuerySymbolicLinkObject", handleNtQuerySymbolicLinkObject)
	d.register(idOf("NtSetInformationObject"), "NtSetInformationObject", handleNtSetInformationObject)
	d.register(idOf("NtCompareObjects"), "NtCompareObjects", handleNtCompareObjects)

	// File I/O extended
	d.register(idOf("NtQueryAttributesFile"), "NtQueryAttributesFile", handleNtQueryAttributesFile)
	d.register(idOf("NtQueryFullAttributesFile"), "NtQueryFullAttributesFile", handleNtQueryFullAttributesFile)
	d.register(idOf("NtLockFile"), "NtLockFile", handleNtLockFile)
	d.register(idOf("NtUnlockFile"), "NtUnlockFile", handleNtUnlockFile)
	d.register(idOf("NtCreateMailslotFile"), "NtCreateMailslotFile", handleNtCreateMailslotFile)
	d.register(idOf("NtCreateNamedPipeFile"), "NtCreateNamedPipeFile", handleNtCreateNamedPipeFile)
	d.register(idOf("NtFsControlFile"), "NtFsControlFile", handleNtFsControlFile)
	d.register(idOf("NtNotifyChangeKey"), "NtNotifyChangeKey", handleNtNotifyChangeKey)
	d.register(idOf("NtNotifyChangeDirectoryFile"), "NtNotifyChangeDirectoryFile", handleNtNotifyChangeDirectoryFile)

	// Path functions
	d.register(idOf("RtlDosPathNameToNtPathName_U"), "RtlDosPathNameToNtPathName_U", handleRtlDosPathNameToNtPathName_U)
	d.register(idOf("RtlDosPathNameToNtPathName_U_WithStatus"), "RtlDosPathNameToNtPathName_U_WithStatus", handleRtlDosPathNameToNtPathName_U_WithStatus)
	d.register(idOf("RtlGetCurrentDirectory_U"), "RtlGetCurrentDirectory_U", handleRtlGetCurrentDirectory_U)
	d.register(idOf("RtlSetCurrentDirectory_U"), "RtlSetCurrentDirectory_U", handleRtlSetCurrentDirectory_U)
	d.register(idOf("RtlGetFullPathName_U"), "RtlGetFullPathName_U", handleRtlGetFullPathName_U)
	d.register(idOf("RtlDetermineDosPathNameType_U"), "RtlDetermineDosPathNameType_U", handleRtlDetermineDosPathNameType_U)

	// Bitmap
	d.register(idOf("RtlInitializeBitMap"), "RtlInitializeBitMap", handleRtlInitializeBitMap)
	d.register(idOf("RtlSetBits"), "RtlSetBits", handleRtlSetBits)
	d.register(idOf("RtlClearBits"), "RtlClearBits", handleRtlClearBits)
	d.register(idOf("RtlAreBitsSet"), "RtlAreBitsSet", handleRtlAreBitsSet)
	d.register(idOf("RtlAreBitsClear"), "RtlAreBitsClear", handleRtlAreBitsClear)

	// Error mode
	d.register(idOf("RtlGetThreadErrorMode"), "RtlGetThreadErrorMode", handleRtlGetThreadErrorMode)
	d.register(idOf("RtlSetThreadErrorMode"), "RtlSetThreadErrorMode", handleRtlSetThreadErrorMode)

	// Environment
	d.register(idOf("RtlCreateEnvironment"), "RtlCreateEnvironment", handleRtlCreateEnvironment)
	d.register(idOf("RtlDestroyEnvironment"), "RtlDestroyEnvironment", handleRtlDestroyEnvironment)
	d.register(idOf("RtlSetEnvironmentVariable"), "RtlSetEnvironmentVariable", handleRtlSetEnvironmentVariable)
	d.register(idOf("RtlQueryEnvironmentVariable_U"), "RtlQueryEnvironmentVariable_U", handleRtlQueryEnvironmentVariable_U)
	d.register(idOf("RtlExpandEnvironmentStrings_U"), "RtlExpandEnvironmentStrings_U", handleRtlExpandEnvironmentStrings_U)
	d.register(idOf("RtlCreateProcessParametersEx"), "RtlCreateProcessParametersEx", handleRtlCreateProcessParametersEx)
	d.register(idOf("RtlDestroyProcessParameters"), "RtlDestroyProcessParameters", handleRtlDestroyProcessParameters)

	// RunOnce
	d.register(idOf("RtlRunOnceBeginInitialize"), "RtlRunOnceBeginInitialize", handleRtlRunOnceBeginInitialize)
	d.register(idOf("RtlRunOnceComplete"), "RtlRunOnceComplete", handleRtlRunOnceComplete)
	d.register(idOf("RtlRunOnceExecuteOnce"), "RtlRunOnceExecuteOnce", handleRtlRunOnceExecuteOnce)

	// Misc system
	d.register(idOf("NtPowerInformation"), "NtPowerInformation", handleNtPowerInformation)
	d.register(idOf("NtQueueApcThread"), "NtQueueApcThread", handleNtQueueApcThread)
	d.register(idOf("NtGetNlsSectionPtr"), "NtGetNlsSectionPtr", handleNtGetNlsSectionPtr)
	d.register(idOf("NtSetSystemInformation"), "NtSetSystemInformation", handleNtSetSystemInformation)
	d.register(idOf("NtSetSystemTime"), "NtSetSystemTime", handleNtSetSystemTime)

	// Security descriptors / SIDs
	d.register(idOf("RtlCreateSecurityDescriptor"), "RtlCreateSecurityDescriptor", handleRtlCreateSecurityDescriptor)
	d.register(idOf("RtlSetDaclSecurityDescriptor"), "RtlSetDaclSecurityDescriptor", handleRtlSetDaclSecurityDescriptor)
	d.register(idOf("RtlCreateAcl"), "RtlCreateAcl", handleRtlCreateAcl)
	d.register(idOf("RtlAddAccessAllowedAce"), "RtlAddAccessAllowedAce", handleRtlAddAccessAllowedAce)
	d.register(idOf("RtlAddAccessAllowedAceEx"), "RtlAddAccessAllowedAceEx", handleRtlAddAccessAllowedAceEx)
	d.register(idOf("RtlAllocateAndInitializeSid"), "RtlAllocateAndInitializeSid", handleRtlAllocateAndInitializeSid)
	d.register(idOf("RtlFreeSid"), "RtlFreeSid", handleRtlFreeSid)
	d.register(idOf("RtlCopySid"), "RtlCopySid", handleRtlCopySid)
	d.register(idOf("RtlEqualSid"), "RtlEqualSid", handleRtlEqualSid)
	d.register(idOf("RtlLengthSid"), "RtlLengthSid", handleRtlLengthSid)
	d.register(idOf("RtlInitializeSid"), "RtlInitializeSid", handleRtlInitializeSid)
	d.register(idOf("RtlValidSid"), "RtlValidSid", handleRtlValidSid)
	d.register(idOf("RtlSubAuthorityCountSid"), "RtlSubAuthorityCountSid", handleRtlSubAuthorityCountSid)
	d.register(idOf("RtlSubAuthoritySid"), "RtlSubAuthoritySid", handleRtlSubAuthoritySid)
	d.register(idOf("RtlIdentifierAuthoritySid"), "RtlIdentifierAuthoritySid", handleRtlIdentifierAuthoritySid)

	// Activation context
	d.register(idOf("RtlActivateActivationContext"), "RtlActivateActivationContext", handleRtlActivateActivationContext)
	d.register(idOf("RtlDeactivateActivationContext"), "RtlDeactivateActivationContext", handleRtlDeactivateActivationContext)
	d.register(idOf("RtlGetActiveActivationContext"), "RtlGetActiveActivationContext", handleRtlGetActiveActivationContext)
	d.register(idOf("RtlAddRefActivationContext"), "RtlAddRefActivationContext", handleRtlAddRefActivationContext)
	d.register(idOf("RtlReleaseActivationContext"), "RtlReleaseActivationContext", handleRtlReleaseActivationContext)
	d.register(idOf("RtlCreateActivationContext"), "RtlCreateActivationContext", handleRtlCreateActivationContext)
	d.register(idOf("RtlQueryActivationContextApplicationSettings"), "RtlQueryActivationContextApplicationSettings", handleRtlQueryActivationContextApplicationSettings)
	d.register(idOf("RtlFindActivationContextSectionString"), "RtlFindActivationContextSectionString", handleRtlFindActivationContextSectionString)
	d.register(idOf("RtlFindActivationContextSectionGuid"), "RtlFindActivationContextSectionGuid", handleRtlFindActivationContextSectionGuid)
	d.register(idOf("RtlZombifyActivationContext"), "RtlZombifyActivationContext", handleRtlZombifyActivationContext)
	d.register(idOf("RtlFreeActivationContextStack"), "RtlFreeActivationContextStack", handleRtlFreeActivationContextStack)
	d.register(idOf("RtlQueryInformationActivationContext"), "RtlQueryInformationActivationContext", handleRtlQueryInformationActivationContext)

	// Thread pool
	d.register(idOf("RtlQueueWorkItem"), "RtlQueueWorkItem", handleRtlQueueWorkItem)
	d.register(idOf("RtlCreateTimer"), "RtlCreateTimer", handleRtlCreateTimer)
	d.register(idOf("RtlDeleteTimer"), "RtlDeleteTimer", handleRtlDeleteTimer)
	d.register(idOf("RtlUpdateTimer"), "RtlUpdateTimer", handleRtlUpdateTimer)
	d.register(idOf("RtlCreateTimerQueue"), "RtlCreateTimerQueue", handleRtlCreateTimerQueue)
	d.register(idOf("RtlDeleteTimerQueueEx"), "RtlDeleteTimerQueueEx", handleRtlDeleteTimerQueueEx)
	d.register(idOf("RtlRegisterWait"), "RtlRegisterWait", handleRtlRegisterWait)
	d.register(idOf("RtlDeregisterWait"), "RtlDeregisterWait", handleRtlDeregisterWait)
	d.register(idOf("RtlDeregisterWaitEx"), "RtlDeregisterWaitEx", handleRtlDeregisterWaitEx)
	d.register(idOf("RtlSetIoCompletionCallback"), "RtlSetIoCompletionCallback", handleRtlSetIoCompletionCallback)

	// GUID / message
	d.register(idOf("RtlGUIDFromString"), "RtlGUIDFromString", handleRtlGUIDFromString)
	d.register(idOf("RtlFindMessage"), "RtlFindMessage", handleRtlFindMessage)
	d.register(idOf("RtlFormatMessage"), "RtlFormatMessage", handleRtlFormatMessage)

	// Locale / language preferences
	d.register(idOf("RtlGetLocaleFileMappingAddress"), "RtlGetLocaleFileMappingAddress", handleRtlGetLocaleFileMappingAddress)
	d.register(idOf("RtlGetProductInfo"), "RtlGetProductInfo", handleRtlGetProductInfo)
	d.register(idOf("RtlGetSystemPreferredUILanguages"), "RtlGetSystemPreferredUILanguages", handleRtlGetSystemPreferredUILanguages)
	d.register(idOf("RtlGetUserPreferredUILanguages"), "RtlGetUserPreferredUILanguages", handleRtlGetUserPreferredUILanguages)
	d.register(idOf("RtlGetProcessPreferredUILanguages"), "RtlGetProcessPreferredUILanguages", handleRtlGetProcessPreferredUILanguages)
	d.register(idOf("RtlGetThreadPreferredUILanguages"), "RtlGetThreadPreferredUILanguages", handleRtlGetThreadPreferredUILanguages)
	d.register(idOf("RtlGetSystemTimePrecise"), "RtlGetSystemTimePrecise", handleRtlGetSystemTimePrecise)
	d.register(idOf("RtlTimeFieldsToTime"), "RtlTimeFieldsToTime", handleRtlTimeFieldsToTime)
	d.register(idOf("RtlTimeToTimeFields"), "RtlTimeToTimeFields", handleRtlTimeToTimeFields)
	d.register(idOf("RtlQueryUnbiasedInterruptTime"), "RtlQueryUnbiasedInterruptTime", handleRtlQueryUnbiasedInterruptTime)

	// WoW64
	d.register(idOf("RtlWow64GetProcessMachines"), "RtlWow64GetProcessMachines", handleRtlWow64GetProcessMachines)
	d.register(idOf("RtlWow64EnableFsRedirection"), "RtlWow64EnableFsRedirection", handleRtlWow64EnableFsRedirection)
	d.register(idOf("RtlWow64EnableFsRedirectionEx"), "RtlWow64EnableFsRedirectionEx", handleRtlWow64EnableFsRedirectionEx)

	// Wine-specific stubs
	d.register(idOf("wine_get_version"), "wine_get_version", handleWineGetVersion)
	d.register(idOf("wine_server_call"), "wine_server_call", handleWineServerCall)
	d.register(idOf("__wine_dbg_get_channel_flags"), "__wine_dbg_get_channel_flags", handleWineDbgGetChannelFlags)
	d.register(idOf("__wine_dbg_header"), "__wine_dbg_header", handleWineDbgHeader)
	d.register(idOf("__wine_dbg_output"), "__wine_dbg_output", handleWineDbgOutput)
	d.register(idOf("__wine_dbg_strdup"), "__wine_dbg_strdup", handleWineDbgStrdup)
	d.register(idOf("wine_nt_to_unix_file_name"), "wine_nt_to_unix_file_name", handleWineNtToUnixFileName)
	d.register(idOf("wine_unix_to_nt_file_name"), "wine_unix_to_nt_file_name", handleWineUnixToNtFileName)

	// ETW stubs
	d.register(idOf("EtwEventRegister"), "EtwEventRegister", handleEtwEventRegister)
	d.register(idOf("EtwEventUnregister"), "EtwEventUnregister", handleEtwEventUnregister)
	d.register(idOf("EtwEventWrite"), "EtwEventWrite", handleEtwEventWrite)
	d.register(idOf("EtwEventEnabled"), "EtwEventEnabled", handleEtwEventEnabled)

	// Debug
	d.register(idOf("DbgBreakPoint"), "DbgBreakPoint", handleDbgBreakPoint)

	// C-runtime stubs in ntdll
	d.register(idOf("_vsnprintf"), "_vsnprintf", handleVsnprintf)
	d.register(idOf("_vsnwprintf"), "_vsnwprintf", handleVsnwprintf)

	// CRT handlers for functions too complex for x64 inline patches
	d.register(idOf("strtol"), "strtol", handleStrtol)
	d.register(idOf("wcstol"), "wcstol", handleWcstol)
	d.register(idOf("wcstoul"), "wcstoul", handleWcstoul)
	d.register(idOf("_strnicmp"), "_strnicmp", handleStrnicmp)
	d.register(idOf("_wcsicmp"), "_wcsicmp", handleWcsicmp)
	d.register(idOf("_wcsnicmp"), "_wcsnicmp", handleWcsnicmp)
	d.register(idOf("isalpha"), "isalpha", handleIsalpha)
	d.register(idOf("islower"), "islower", handleIslower)
	d.register(idOf("isxdigit"), "isxdigit", handleIsxdigit)
	d.register(idOf("strpbrk"), "strpbrk", handleStrpbrk)
	d.register(idOf("wcspbrk"), "wcspbrk", handleWcspbrk)
	d.register(idOf("wcscspn"), "wcscspn", handleWcscspn)
	d.register(idOf("wcsspn"), "wcsspn", handleWcsspn)
	d.register(idOf("wcsstr"), "wcsstr", handleWcsstr)
	d.register(idOf("LdrDisableThreadCalloutsForDll"), "LdrDisableThreadCalloutsForDll", handleLdrDisableThreadCalloutsForDll)
	d.register(idOf("LdrFindResource_U"), "LdrFindResource_U", handleLdrFindResource_U)
	d.register(idOf("LdrFindResourceDirectory_U"), "LdrFindResourceDirectory_U", handleLdrFindResource_U) // same logic
	d.register(idOf("LdrAccessResource"), "LdrAccessResource", handleLdrAccessResource)
	d.register(idOf("RtlFindClearBitsAndSet"), "RtlFindClearBitsAndSet", handleRtlFindClearBitsAndSet)
	d.register(idOf("LdrQueryImageFileExecutionOptions"), "LdrQueryImageFileExecutionOptions", handleLdrQueryImageFileExecutionOptions)
	d.register(idOf("RtlReleasePath"), "RtlReleasePath", handleRtlReleasePath)

	// SList operations
	d.register(idOf("RtlInitializeSListHead"), "RtlInitializeSListHead", handleRtlInitializeSListHead)
	d.register(idOf("RtlInterlockedFlushSList"), "RtlInterlockedFlushSList", handleRtlInterlockedFlushSList)
	d.register(idOf("RtlInterlockedPopEntrySList"), "RtlInterlockedPopEntrySList", handleRtlInterlockedPopEntrySList)
	d.register(idOf("RtlInterlockedPushEntrySList"), "RtlInterlockedPushEntrySList", handleRtlInterlockedPushEntrySList)
	d.register(idOf("RtlQueryDepthSList"), "RtlQueryDepthSList", handleRtlQueryDepthSList)

	// Performance counter
	d.register(idOf("RtlQueryPerformanceCounter"), "RtlQueryPerformanceCounter", handleRtlQueryPerformanceCounter)
	d.register(idOf("RtlQueryPerformanceFrequency"), "RtlQueryPerformanceFrequency", handleRtlQueryPerformanceFrequency)

	// Misc
	d.register(idOf("RtlRandom"), "RtlRandom", handleRtlRandom)
	d.register(idOf("RtlOpenCurrentUser"), "RtlOpenCurrentUser", handleRtlOpenCurrentUser)
	d.register(idOf("RtlQueryDynamicTimeZoneInformation"), "RtlQueryDynamicTimeZoneInformation", handleRtlQueryDynamicTimeZoneInformation)
	d.register(idOf("wine_get_host_version"), "wine_get_host_version", handleWineGetHostVersion)

	d.register(idOf("NtUserInitializeClientPfnArrays"), "NtUserInitializeClientPfnArrays", handleNtUserInitializeClientPfnArrays)
	d.register(idOf("NtUserGetSystemDpiForProcess"), "NtUserGetSystemDpiForProcess", handleNtUserGetSystemDpiForProcess)

	// Atom table
	d.register(idOf("NtAddAtom"), "NtAddAtom", handleNtAddAtom)
	d.register(idOf("NtDeleteAtom"), "NtDeleteAtom", handleNtDeleteAtom)
	d.register(idOf("NtFindAtom"), "NtFindAtom", handleNtFindAtom)
	d.register(idOf("NtQueryInformationAtom"), "NtQueryInformationAtom", handleNtQueryInformationAtom)

	// NtUserCallOneParam / NtUserCallTwoParam
	d.register(idOf("NtUserCallOneParam"), "NtUserCallOneParam", handleNtUserCallOneParam)
	d.register(idOf("NtUserCallTwoParam"), "NtUserCallTwoParam", handleNtUserCallTwoParam)

	// NtGdi* - GDI object stubs
	d.register(idOf("NtGdiCreateBitmap"), "NtGdiCreateBitmap", handleNtGdiCreateBitmap)
	d.register(idOf("NtGdiCreatePatternBrushInternal"), "NtGdiCreatePatternBrushInternal", handleNtGdiCreatePatternBrushInternal)
	d.register(idOf("NtGdiDeleteObjectApp"), "NtGdiDeleteObjectApp", handleNtGdiDeleteObjectApp)
	d.register(idOf("NtGdiSelectBitmap"), "NtGdiSelectBitmap", handleNtGdiSelectBitmap)
	d.register(idOf("NtGdiSelectBrush"), "NtGdiSelectBrush", handleNtGdiSelectBrush)
	d.register(idOf("NtGdiSelectPen"), "NtGdiSelectPen", handleNtGdiSelectPen)
	d.register(idOf("NtGdiSelectFont"), "NtGdiSelectFont", handleNtGdiSelectFont)
	d.register(idOf("NtGdiCreateSolidBrush"), "NtGdiCreateSolidBrush", handleNtGdiCreateSolidBrush)
	d.register(idOf("NtGdiCreatePen"), "NtGdiCreatePen", handleNtGdiCreatePen)
	d.register(idOf("NtGdiCreateRectRgn"), "NtGdiCreateRectRgn", handleNtGdiCreateRectRgn)
	d.register(idOf("NtGdiCreateCompatibleDC"), "NtGdiCreateCompatibleDC", handleNtGdiCreateCompatibleDC)
	d.register(idOf("NtGdiCreateCompatibleBitmap"), "NtGdiCreateCompatibleBitmap", handleNtGdiCreateCompatibleBitmap)
	d.register(idOf("NtGdiHfontCreate"), "NtGdiHfontCreate", handleNtGdiHfontCreate)
	d.register(idOf("NtGdiExtGetObjectW"), "NtGdiExtGetObjectW", handleNtGdiExtGetObjectW)
	d.register(idOf("NtGdiGetDeviceCaps"), "NtGdiGetDeviceCaps", handleNtGdiGetDeviceCaps)
	d.register(idOf("NtGdiGetAndSetDCDword"), "NtGdiGetAndSetDCDword", handleNtGdiGetAndSetDCDword)
	d.register(idOf("NtGdiSaveDC"), "NtGdiSaveDC", handleNtGdiSaveDC)
	d.register(idOf("NtGdiRestoreDC"), "NtGdiRestoreDC", handleNtGdiRestoreDC)
	d.register(idOf("NtGdiCombineRgn"), "NtGdiCombineRgn", handleNtGdiCombineRgn)
	d.register(idOf("NtGdiGetRgnBox"), "NtGdiGetRgnBox", handleNtGdiGetRgnBox)
	d.register(idOf("NtGdiSetRectRgn"), "NtGdiSetRectRgn", handleNtGdiSetRectRgn)
	d.register(idOf("NtGdiOffsetRgn"), "NtGdiOffsetRgn", handleNtGdiOffsetRgn)
	d.register(idOf("NtGdiPatBlt"), "NtGdiPatBlt", handleNtGdiPatBlt)
	d.register(idOf("NtGdiBitBlt"), "NtGdiBitBlt", handleNtGdiBitBlt)
	d.register(idOf("NtGdiOpenDCW"), "NtGdiOpenDCW", handleNtGdiOpenDCW)
	d.register(idOf("NtGdiGetTextMetricsW"), "NtGdiGetTextMetricsW", handleNtGdiGetTextMetricsW)
	d.register(idOf("NtGdiFlush"), "NtGdiFlush", handleNtGdiFlush)
}

// registerWin32kHandlers registers placeholder Win32k handlers.
func (d *Dispatcher) registerWin32kHandlers() {
	for i, name := range win32uExports {
		id := win32uIDBase + uint32(i)
		d.names[id] = name
	}
	// Win32k handlers are registered by the win32k package when available.
}

// RegisterWin32kHandler allows external packages to register Win32k handlers.
func (d *Dispatcher) RegisterWin32kHandler(name string, h TrapHandler) {
	for i, n := range win32uExports {
		if n == name {
			id := win32uIDBase + uint32(i)
			d.handlers[id] = h
			d.names[id] = name
			return
		}
	}
}

// idOf returns the syscall ID for a given NTAPI function name.
func idOf(name string) uint32 {
	for i, n := range ntapiExports {
		if n == name {
			return ntapiIDBase + uint32(i)
		}
	}
	// Check win32u exports
	for i, n := range win32uExports {
		if n == name {
			return win32uIDBase + uint32(i)
		}
	}
	panic(fmt.Sprintf("unknown ntapi export: %s", name))
}

// handleNoop is a no-op handler returning STATUS_SUCCESS.
func handleNoop(ctx *TrapContext) uint32 {
	return StatusSuccess
}

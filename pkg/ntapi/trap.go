package ntapi

import (
	"fmt"

	"github.com/mirkobrombin/go-vm/pkg/arch"
	"github.com/mirkobrombin/go-vm/pkg/mmu"
	"github.com/mirkobrombin/go-vm/pkg/vfs"
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
	Trace   bool
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

// Dispatcher routes vmcall traps to the appropriate handler based on syscall ID.
type Dispatcher struct {
	handlers map[uint32]TrapHandler
	names    map[uint32]string // for trace logging
	ntdll    *SynthPE
	win32u   *SynthPE
	ctx      *TrapContext
}

// NewDispatcher creates a trap dispatcher with all registered handlers.
func NewDispatcher(mem *mmu.MMU, fs *vfs.VFS, handles *HandleTable, reg *RegistryHive, state *ProcessState, ntdll, win32u *SynthPE) *Dispatcher {
	d := &Dispatcher{
		handlers: make(map[uint32]TrapHandler),
		names:    make(map[uint32]string),
		ntdll:    ntdll,
		win32u:   win32u,
		ctx: &TrapContext{
			Mem:     mem,
			FS:      fs,
			Handles: handles,
			Reg:     reg,
			State:   state,
		},
	}

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

// Handle is the vmcall trap entry point, called by the CPU emulator.
func (d *Dispatcher) Handle(cpu arch.CPU) {
	d.ctx.CPU = cpu
	syscallID := uint32(cpu.SyscallNum()) // EAX contains the syscall ID

	handler, ok := d.handlers[syscallID]
	if !ok {
		if d.ctx.Trace {
			name := d.names[syscallID]
			if name == "" {
				name = fmt.Sprintf("unknown_0x%04X", syscallID)
			}
			fmt.Printf("[ntapi] UNIMPLEMENTED: %s (id=0x%04X)\n", name, syscallID)
		}
		// Return STATUS_NOT_IMPLEMENTED
		cpu.SetSyscallReturn(0xC0000002)
		return
	}

	if d.ctx.Trace {
		name := d.names[syscallID]
		fmt.Printf("[ntapi] %s (id=0x%04X)\n", name, syscallID)
	}

	status := handler(d.ctx)
	cpu.SetSyscallReturn(uint64(status))
}

// register adds a handler for a given syscall ID.
func (d *Dispatcher) register(id uint32, name string, h TrapHandler) {
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

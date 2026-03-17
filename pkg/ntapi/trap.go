//go:build guest_windows

package ntapi

import (
	"fmt"
	"math"
	"os"
	"strings"

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
	// TraceSyscall logs every Nt*/NtUser*/NtGdi* seam crossing without the
	// per-instruction noise of Trace. This is the lens for the win32k pivot.
	TraceSyscall bool
	flsSlots     map[uint32]uint64
	flsNextIdx   uint32
	// ReturnOverridden is set by handlers that manage RAX directly,
	// preventing the dispatcher from overwriting it with the handler's return.
	ReturnOverridden bool
	// PCRedirected is set by handlers that redirect the program counter
	// (e.g., sync WndProc dispatch). When set, PE32 stdcall cleanup is skipped
	// because the handler already manages the stack.
	PCRedirected bool
	// maxArgIdx tracks the highest Arg() index accessed for PE32 stdcall cleanup.
	maxArgIdx int
	// i386ArgExtra is added to the PE32 stack arg base. It is 4 when a win32k
	// syscall arrived via the KUSER_SHARED_DATA->SystemCall trampoline (the
	// stub's `call [edx]` pushed one extra return address), and 0 for a direct
	// synth stub. Set per-call by Handle(); reset to 0 otherwise.
	i386ArgExtra uint64
}

// Arg reads a Windows calling convention argument.
// For x64 (PE32+): RCX, RDX, R8, R9, then stack (with shadow space).
// For i386 (PE32): all arguments on stack (stdcall/cdecl).
func (ctx *TrapContext) Arg(n int) uint64 {
	if n > ctx.maxArgIdx {
		ctx.maxArgIdx = n
	}
	if ctx.CPU.GetArch() == arch.ArchI386 {
		// stdcall: args pushed right-to-left, return addr at [ESP]
		// arg0 at [ESP+4], arg1 at [ESP+8], ...
		sp := ctx.CPU.GetSP()
		addr := sp + 4 + ctx.i386ArgExtra + uint64(n)*4 // skip return address(es)
		val, err := ctx.Mem.Read32(addr)
		if err != nil {
			return 0
		}
		return uint64(val)
	}
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
	regR12 = 12
	regR13 = 13
	regR14 = 14
	regR15 = 15
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
	handlers         map[uint32]TrapHandler
	handlersByName   map[string]TrapHandler // funcName → handler, for dynamic re-registration
	names            map[uint32]string      // for trace logging
	ntdll            *SynthPE
	win32u           *SynthPE
	ctx              *TrapContext
	moduleExports    map[uint64]map[string]uint64 // baseAddr → name → addr
	moduleOrdExports map[uint64]map[uint16]uint64 // baseAddr → ordinal → addr
	sysRoot          string                       // path to Windows system DLL directory
	nlsCache         map[uint32][]byte            // cached NLS file data by code page
	cdeclIDs         map[uint32]bool              // IDs that use cdecl (no callee cleanup)
	stdcallArgs      map[uint32]int               // explicit stdcall cleanup: ID → arg count
}

// NewDispatcher creates a trap dispatcher with all registered handlers.
func NewDispatcher(mem *mmu.MMU, fs *vfs.VFS, handles *HandleTable, reg *RegistryHive, state *ProcessState, ntdll, win32u *SynthPE) *Dispatcher {
	d := &Dispatcher{
		handlers:         make(map[uint32]TrapHandler),
		handlersByName:   make(map[string]TrapHandler),
		names:            make(map[uint32]string),
		ntdll:            ntdll,
		win32u:           win32u,
		moduleExports:    make(map[uint64]map[string]uint64),
		moduleOrdExports: make(map[uint64]map[uint16]uint64),
		nlsCache:         make(map[uint32][]byte),
		cdeclIDs:         make(map[uint32]bool),
		stdcallArgs:      make(map[uint32]int),
		ctx: &TrapContext{
			Mem:     mem,
			FS:      fs,
			Handles: handles,
			Reg:     reg,
			State:   state,
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

// SetTraceSyscall enables/disables syscall-seam trace logging: one concise line
// per Nt*/NtUser*/NtGdi* crossing (handler name + id), without instruction noise.
func (d *Dispatcher) SetTraceSyscall(on bool) {
	d.ctx.TraceSyscall = on
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

// MarkCdeclRange marks all IDs in the range [base, base+count) as cdecl.
// Used for msvcrt/ucrtbase functions that use cdecl calling convention.
func (d *Dispatcher) MarkCdeclRange(base uint32, count int) {
	for i := 0; i < count; i++ {
		d.cdeclIDs[base+uint32(i)] = true
	}
}

// SetStdcallArgCount explicitly sets the arg count for a specific syscall ID.
func (d *Dispatcher) SetStdcallArgCount(id uint32, nArgs int) {
	d.stdcallArgs[id] = nArgs
}

// SetStdcallArgCountByName looks up a function name in a SynthPE and sets
// its stdcall arg count.
func (d *Dispatcher) SetStdcallArgCountByName(synth *SynthPE, name string, nArgs int) {
	if addr, ok := synth.Exports[name]; ok {
		if id, ok := synth.StubIDs[addr]; ok {
			d.stdcallArgs[id] = nArgs
		}
	}
}

// ApplyWin32ArgCounts sets stdcall arg counts for all known Win32 APIs in a synth DLL.
func (d *Dispatcher) ApplyWin32ArgCounts(synth *SynthPE) {
	for name, addr := range synth.Exports {
		if nArgs, ok := win32ArgCounts[name]; ok {
			if id, ok := synth.StubIDs[addr]; ok {
				d.stdcallArgs[id] = nArgs
			}
		}
	}
}

// PostRegisterSynthDLL wires up any stubs in synth that were added after the
// initial handler registration pass (e.g., via AddDynamicExport in loadDLLFromVFS).
// For each export that lacks a handler or stdcall arg count, it checks
// handlersByName and win32ArgCounts to fill the gap.
func (d *Dispatcher) PostRegisterSynthDLL(synth *SynthPE) {
	for funcName, addr := range synth.Exports {
		id, ok := synth.StubIDs[addr]
		if !ok {
			continue
		}
		if d.names[id] == "" {
			d.names[id] = synth.Name + "!" + funcName
		}
		if _, hasHandler := d.handlers[id]; !hasHandler {
			if h, ok := d.handlersByName[funcName]; ok {
				d.handlers[id] = h
			}
		}
		if _, hasArgs := d.stdcallArgs[id]; !hasArgs {
			if nArgs, ok := win32ArgCounts[funcName]; ok {
				d.stdcallArgs[id] = nArgs
			}
		}
	}
}

// win32ArgCounts maps Win32 API function names to their stdcall argument counts.
// This is used for PE32 stdcall cleanup - the callee must pop the correct
// number of argument bytes from the stack.
var win32ArgCounts = map[string]int{
	// --- kernel32.dll ---
	"GetModuleHandleA":                      1,
	"GetModuleHandleW":                      1,
	"GetModuleHandleExA":                    3,
	"GetModuleHandleExW":                    3,
	"GetModuleFileNameA":                    3,
	"GetModuleFileNameW":                    3,
	"GetProcAddress":                        2,
	"LoadLibraryA":                          1,
	"LoadLibraryW":                          1,
	"LoadLibraryExA":                        3,
	"LoadLibraryExW":                        3,
	"FreeLibrary":                           1,
	"GetStartupInfoA":                       1,
	"GetStartupInfoW":                       1,
	"GetCommandLineA":                       0,
	"GetCommandLineW":                       0,
	"GetEnvironmentVariableA":               3,
	"GetEnvironmentVariableW":               3,
	"GetEnvironmentStrings":                 0,
	"GetEnvironmentStringsA":                0,
	"GetEnvironmentStringsW":                0,
	"FreeEnvironmentStringsA":               1,
	"FreeEnvironmentStringsW":               1,
	"SetEnvironmentVariableA":               2,
	"SetEnvironmentVariableW":               2,
	"ExpandEnvironmentStringsA":             3,
	"ExpandEnvironmentStringsW":             3,
	"GetCurrentDirectoryA":                  2,
	"GetCurrentDirectoryW":                  2,
	"SetCurrentDirectoryA":                  1,
	"SetCurrentDirectoryW":                  1,
	"GetSystemDirectoryA":                   2,
	"GetSystemDirectoryW":                   2,
	"GetWindowsDirectoryA":                  2,
	"GetWindowsDirectoryW":                  2,
	"GetTempPathA":                          2,
	"GetTempPathW":                          2,
	"GetTempFileNameA":                      4,
	"GetTempFileNameW":                      4,
	"GetVersionExA":                         1,
	"GetVersionExW":                         1,
	"GetVersion":                            0,
	"GetTickCount":                          0,
	"GetTickCount64":                        0,
	"QueryPerformanceCounter":               1,
	"QueryPerformanceFrequency":             1,
	"GetSystemTimeAsFileTime":               1,
	"GetSystemTime":                         1,
	"GetLocalTime":                          1,
	"SystemTimeToFileTime":                  2,
	"FileTimeToSystemTime":                  2,
	"FileTimeToLocalFileTime":               2,
	"GetLastError":                          0,
	"SetLastError":                          1,
	"GetCurrentProcess":                     0,
	"GetCurrentProcessId":                   0,
	"GetCurrentThread":                      0,
	"GetCurrentThreadId":                    0,
	"ExitProcess":                           1,
	"ExitThread":                            1,
	"TerminateProcess":                      2,
	"CreateProcessA":                        10,
	"CreateProcessW":                        10,
	"OpenProcess":                           3,
	"CloseHandle":                           1,
	"DuplicateHandle":                       7,
	"GetHandleInformation":                  2,
	"SetHandleInformation":                  3,
	"CreateThread":                          6,
	"ResumeThread":                          1,
	"SuspendThread":                         1,
	"Sleep":                                 1,
	"SleepEx":                               2,
	"WaitForSingleObject":                   2,
	"WaitForSingleObjectEx":                 3,
	"WaitForMultipleObjects":                4,
	"WaitForMultipleObjectsEx":              5,
	"CreateEventA":                          4,
	"CreateEventW":                          4,
	"SetEvent":                              1,
	"ResetEvent":                            1,
	"CreateMutexA":                          3,
	"CreateMutexW":                          3,
	"ReleaseMutex":                          1,
	"CreateSemaphoreA":                      4,
	"CreateSemaphoreW":                      4,
	"ReleaseSemaphore":                      3,
	"InitializeCriticalSection":             1,
	"InitializeCriticalSectionAndSpinCount": 2,
	"EnterCriticalSection":                  1,
	"LeaveCriticalSection":                  1,
	"DeleteCriticalSection":                 1,
	"TryEnterCriticalSection":               1,
	"InterlockedIncrement":                  1,
	"InterlockedDecrement":                  1,
	"InterlockedExchange":                   2,
	"InterlockedCompareExchange":            3,
	"TlsAlloc":                              0,
	"TlsFree":                               1,
	"TlsGetValue":                           1,
	"TlsSetValue":                           2,
	"FlsAlloc":                              1,
	"FlsFree":                               1,
	"FlsGetValue":                           1,
	"FlsSetValue":                           2,
	"GetStdHandle":                          1,
	"SetStdHandle":                          2,
	"ReadFile":                              5,
	"WriteFile":                             5,
	"CreateFileA":                           7,
	"CreateFileW":                           7,
	"DeleteFileA":                           1,
	"DeleteFileW":                           1,
	"MoveFileA":                             2,
	"MoveFileW":                             2,
	"MoveFileExA":                           3,
	"MoveFileExW":                           3,
	"CopyFileA":                             3,
	"CopyFileW":                             3,
	"GetFileSize":                           2,
	"GetFileSizeEx":                         2,
	"GetFileType":                           1,
	"SetFilePointer":                        4,
	"SetFilePointerEx":                      4,
	"FlushFileBuffers":                      1,
	"SetEndOfFile":                          1,
	"GetFileAttributesA":                    1,
	"GetFileAttributesW":                    1,
	"GetFileAttributesExA":                  3,
	"GetFileAttributesExW":                  3,
	"SetFileAttributesA":                    2,
	"SetFileAttributesW":                    2,
	"FindFirstFileA":                        2,
	"FindFirstFileW":                        2,
	"FindNextFileA":                         2,
	"FindNextFileW":                         2,
	"FindClose":                             1,
	"CreateDirectoryA":                      2,
	"CreateDirectoryW":                      2,
	"RemoveDirectoryA":                      1,
	"RemoveDirectoryW":                      1,
	"GetFullPathNameA":                      4,
	"GetFullPathNameW":                      4,
	"GetLongPathNameA":                      3,
	"GetLongPathNameW":                      3,
	"GetShortPathNameA":                     3,
	"GetShortPathNameW":                     3,
	"GetPrivateProfileIntA":                 4,
	"GetPrivateProfileIntW":                 4,
	"GetPrivateProfileStringA":              6,
	"GetPrivateProfileStringW":              6,
	"WritePrivateProfileStringA":            4,
	"WritePrivateProfileStringW":            4,
	"GetProfileIntA":                        3,
	"GetProfileIntW":                        3,
	"GetProfileStringA":                     5,
	"GetProfileStringW":                     5,
	"WriteProfileStringA":                   3,
	"WriteProfileStringW":                   3,
	"HeapCreate":                            3,
	"HeapDestroy":                           1,
	"HeapAlloc":                             3,
	"HeapReAlloc":                           4,
	"HeapFree":                              3,
	"HeapSize":                              3,
	"GetProcessHeap":                        0,
	"GlobalAlloc":                           2,
	"GlobalFree":                            1,
	"GlobalLock":                            1,
	"GlobalUnlock":                          1,
	"GlobalReAlloc":                         3,
	"GlobalSize":                            1,
	"LocalAlloc":                            2,
	"LocalFree":                             1,
	"LocalLock":                             1,
	"LocalUnlock":                           1,
	"LocalReAlloc":                          3,
	"LocalSize":                             1,
	"VirtualAlloc":                          4,
	"VirtualFree":                           3,
	"VirtualProtect":                        4,
	"VirtualQuery":                          3,
	"GetSystemInfo":                         1,
	"GetNativeSystemInfo":                   1,
	"IsProcessorFeaturePresent":             1,
	"GetLocaleInfoA":                        4,
	"GetLocaleInfoW":                        4,
	"GetUserDefaultLCID":                    0,
	"GetSystemDefaultLCID":                  0,
	"GetACP":                                0,
	"GetOEMCP":                              0,
	"IsValidCodePage":                       1,
	"GetCPInfo":                             2,
	"MultiByteToWideChar":                   6,
	"WideCharToMultiByte":                   8,
	"LCMapStringA":                          6,
	"LCMapStringW":                          6,
	"CompareStringA":                        6,
	"CompareStringW":                        6,
	"GetStringTypeA":                        5,
	"GetStringTypeW":                        4,
	"GetStringTypeExA":                      5,
	"GetStringTypeExW":                      5,
	"GetTimeZoneInformation":                1,
	"GetConsoleMode":                        2,
	"SetConsoleMode":                        2,
	"GetConsoleCP":                          0,
	"GetConsoleOutputCP":                    0,
	"SetConsoleCP":                          1,
	"SetConsoleOutputCP":                    1,
	"WriteConsoleA":                         5,
	"WriteConsoleW":                         5,
	"ReadConsoleA":                          5,
	"ReadConsoleW":                          5,
	"FillConsoleOutputCharacterA":           5,
	"FillConsoleOutputCharacterW":           5,
	"SetConsoleTitleA":                      1,
	"SetConsoleTitleW":                      1,
	"AllocConsole":                          0,
	"FreeConsole":                           0,
	"GetConsoleScreenBufferInfo":            2,
	"SetConsoleTextAttribute":               2,
	"SetConsoleCtrlHandler":                 2,
	"SetUnhandledExceptionFilter":           1,
	"UnhandledExceptionFilter":              1,
	"RaiseException":                        4,
	"RtlUnwind":                             4,
	"IsDebuggerPresent":                     0,
	"OutputDebugStringA":                    1,
	"OutputDebugStringW":                    1,
	"DebugBreak":                            0,
	"GetComputerNameA":                      2,
	"GetComputerNameW":                      2,
	"lstrlenA":                              1,
	"lstrlenW":                              1,
	"lstrcmpA":                              2,
	"lstrcmpW":                              2,
	"lstrcmpiA":                             2,
	"lstrcmpiW":                             2,
	"lstrcpyA":                              2,
	"lstrcpyW":                              2,
	"lstrcpynA":                             3,
	"lstrcpynW":                             3,
	"lstrcatA":                              2,
	"lstrcatW":                              2,
	"FormatMessageA":                        7,
	"FormatMessageW":                        7,
	"LoadResource":                          2,
	"LockResource":                          1,
	"SizeofResource":                        2,
	"FindResourceA":                         3,
	"FindResourceW":                         3,
	"FindResourceExA":                       4,
	"FindResourceExW":                       4,
	"EnumResourceTypesA":                    3,
	"EnumResourceTypesW":                    3,
	"EnumResourceNamesA":                    4,
	"EnumResourceNamesW":                    4,
	"BeginUpdateResourceA":                  2,
	"BeginUpdateResourceW":                  2,
	"UpdateResourceA":                       6,
	"UpdateResourceW":                       6,
	"EndUpdateResourceA":                    2,
	"EndUpdateResourceW":                    2,
	"SetErrorMode":                          1,
	"GetDriveTypeA":                         1,
	"GetDriveTypeW":                         1,
	"GetDiskFreeSpaceA":                     5,
	"GetDiskFreeSpaceW":                     5,
	"GetLogicalDrives":                      0,
	"GetVolumeInformationA":                 8,
	"GetVolumeInformationW":                 8,
	"CreateFileMappingA":                    6,
	"CreateFileMappingW":                    6,
	"MapViewOfFile":                         5,
	"UnmapViewOfFile":                       1,
	"DeviceIoControl":                       8,
	"GetOverlappedResult":                   4,
	"CreatePipe":                            4,
	"PeekNamedPipe":                         6,
	"ConnectNamedPipe":                      2,
	"DisconnectNamedPipe":                   1,
	"CreateNamedPipeA":                      8,
	"CreateNamedPipeW":                      8,
	"GetDateFormatA":                        6,
	"GetDateFormatW":                        6,
	"GetTimeFormatA":                        6,
	"GetTimeFormatW":                        6,
	"GetNumberFormatA":                      6,
	"GetNumberFormatW":                      6,
	"IsDBCSLeadByte":                        1,
	"EnumSystemLocalesA":                    2,
	"EnumSystemLocalesW":                    2,
	"AddAtomA":                              1,
	"AddAtomW":                              1,
	"FindAtomA":                             1,
	"FindAtomW":                             1,
	"GetAtomNameA":                          3,
	"GetAtomNameW":                          3,
	"DeleteAtom":                            1,
	"GlobalAddAtomA":                        1,
	"GlobalAddAtomW":                        1,
	"GlobalFindAtomA":                       1,
	"GlobalFindAtomW":                       1,
	"GlobalGetAtomNameA":                    3,
	"GlobalGetAtomNameW":                    3,
	"GlobalDeleteAtom":                      1,
	"SetFileTime":                           4,
	"GetFileTime":                           4,
	"CompareFileTime":                       2,
	"GetProcessAffinityMask":                3,
	"SetProcessAffinityMask":                2,
	"SetThreadAffinityMask":                 2,
	"GetThreadPriority":                     1,
	"SetThreadPriority":                     2,
	"GetPriorityClass":                      1,
	"SetPriorityClass":                      2,
	"CreateToolhelp32Snapshot":              2,
	"Process32First":                        2,
	"Process32Next":                         2,
	"Process32FirstW":                       2,
	"Process32NextW":                        2,
	"Thread32First":                         2,
	"Thread32Next":                          2,
	"Module32First":                         2,
	"Module32Next":                          2,
	"Module32FirstW":                        2,
	"Module32NextW":                         2,
	"Heap32ListFirst":                       2,
	"Heap32ListNext":                        2,
	"GetThreadContext":                      2,
	"SetThreadContext":                      2,
	"ReadProcessMemory":                     5,
	"WriteProcessMemory":                    5,
	"GetExitCodeProcess":                    2,
	"GetExitCodeThread":                     2,
	"InitializeSListHead":                   1,
	"InterlockedFlushSList":                 1,
	"InterlockedPopEntrySList":              1,
	"InterlockedPushEntrySList":             2,
	"QueryDepthSList":                       1,
	"EncodePointer":                         1,
	"DecodePointer":                         1,
	"IsWow64Process":                        2,

	// --- user32.dll ---
	"RegisterClassA":              1,
	"RegisterClassW":              1,
	"RegisterClassExA":            1,
	"RegisterClassExW":            1,
	"UnregisterClassA":            2,
	"UnregisterClassW":            2,
	"CreateWindowExA":             12,
	"CreateWindowExW":             12,
	"DestroyWindow":               1,
	"ShowWindow":                  2,
	"UpdateWindow":                1,
	"MoveWindow":                  6,
	"SetWindowPos":                7,
	"GetWindowRect":               2,
	"GetClientRect":               2,
	"AdjustWindowRect":            3,
	"AdjustWindowRectEx":          4,
	"SetWindowTextA":              2,
	"SetWindowTextW":              2,
	"GetWindowTextA":              3,
	"GetWindowTextW":              3,
	"GetWindowTextLengthA":        1,
	"GetWindowTextLengthW":        1,
	"GetWindowLongA":              2,
	"GetWindowLongW":              2,
	"SetWindowLongA":              3,
	"SetWindowLongW":              3,
	"GetClassLongA":               2,
	"GetClassLongW":               2,
	"SetClassLongA":               3,
	"SetClassLongW":               3,
	"GetClassNameA":               3,
	"GetClassNameW":               3,
	"GetParent":                   1,
	"SetParent":                   2,
	"FindWindowA":                 2,
	"FindWindowW":                 2,
	"FindWindowExA":               4,
	"FindWindowExW":               4,
	"IsWindow":                    1,
	"IsWindowVisible":             1,
	"IsWindowEnabled":             1,
	"EnableWindow":                2,
	"GetForegroundWindow":         0,
	"SetForegroundWindow":         1,
	"GetActiveWindow":             0,
	"SetActiveWindow":             1,
	"GetFocus":                    0,
	"SetFocus":                    1,
	"GetCapture":                  0,
	"SetCapture":                  1,
	"ReleaseCapture":              0,
	"GetDesktopWindow":            0,
	"GetDC":                       1,
	"GetDCEx":                     3,
	"GetWindowDC":                 1,
	"ReleaseDC":                   2,
	"BeginPaint":                  2,
	"EndPaint":                    2,
	"InvalidateRect":              3,
	"ValidateRect":                2,
	"RedrawWindow":                4,
	"GetUpdateRect":               3,
	"GetMessageA":                 4,
	"GetMessageW":                 4,
	"PeekMessageA":                5,
	"PeekMessageW":                5,
	"TranslateMessage":            1,
	"DispatchMessageA":            1,
	"DispatchMessageW":            1,
	"PostMessageA":                4,
	"PostMessageW":                4,
	"SendMessageA":                4,
	"SendMessageW":                4,
	"PostQuitMessage":             1,
	"DefWindowProcA":              4,
	"DefWindowProcW":              4,
	"CallWindowProcA":             5,
	"CallWindowProcW":             5,
	"MessageBoxA":                 4,
	"MessageBoxW":                 4,
	"MessageBoxExA":               5,
	"MessageBoxExW":               5,
	"DialogBoxParamA":             5,
	"DialogBoxParamW":             5,
	"CreateDialogParamA":          5,
	"CreateDialogParamW":          5,
	"EndDialog":                   2,
	"GetDlgItem":                  2,
	"GetDlgItemTextA":             4,
	"GetDlgItemTextW":             4,
	"SetDlgItemTextA":             3,
	"SetDlgItemTextW":             3,
	"GetDlgItemInt":               4,
	"SetDlgItemInt":               4,
	"SendDlgItemMessageA":         5,
	"SendDlgItemMessageW":         5,
	"CheckDlgButton":              3,
	"IsDlgButtonChecked":          2,
	"CheckRadioButton":            4,
	"GetDlgCtrlID":                1,
	"IsDialogMessageA":            2,
	"IsDialogMessageW":            2,
	"MapDialogRect":               2,
	"LoadIconA":                   2,
	"LoadIconW":                   2,
	"LoadCursorA":                 2,
	"LoadCursorW":                 2,
	"LoadImageA":                  6,
	"LoadImageW":                  6,
	"LoadBitmapA":                 2,
	"LoadBitmapW":                 2,
	"SetCursor":                   1,
	"GetCursor":                   0,
	"ShowCursor":                  1,
	"GetCursorPos":                1,
	"SetCursorPos":                2,
	"ClipCursor":                  1,
	"GetSystemMetrics":            1,
	"SystemParametersInfoA":       4,
	"SystemParametersInfoW":       4,
	"LoadStringA":                 4,
	"LoadStringW":                 4,
	"LoadMenuA":                   2,
	"LoadMenuW":                   2,
	"CreateMenu":                  0,
	"CreatePopupMenu":             0,
	"DestroyMenu":                 1,
	"GetMenu":                     1,
	"SetMenu":                     2,
	"GetSubMenu":                  2,
	"GetMenuItemCount":            1,
	"GetMenuItemID":               2,
	"GetMenuState":                3,
	"GetMenuStringA":              5,
	"GetMenuStringW":              5,
	"AppendMenuA":                 4,
	"AppendMenuW":                 4,
	"InsertMenuA":                 5,
	"InsertMenuW":                 5,
	"InsertMenuItemA":             4,
	"InsertMenuItemW":             4,
	"DeleteMenu":                  3,
	"RemoveMenu":                  3,
	"EnableMenuItem":              3,
	"CheckMenuItem":               3,
	"CheckMenuRadioItem":          5,
	"DrawMenuBar":                 1,
	"TrackPopupMenu":              7,
	"TrackPopupMenuEx":            6,
	"GetMenuInfo":                 2,
	"SetMenuInfo":                 2,
	"GetMenuItemInfoA":            4,
	"GetMenuItemInfoW":            4,
	"SetMenuItemInfoA":            4,
	"SetMenuItemInfoW":            4,
	"LoadAcceleratorsA":           2,
	"LoadAcceleratorsW":           2,
	"TranslateAcceleratorA":       3,
	"TranslateAcceleratorW":       3,
	"DestroyAcceleratorTable":     1,
	"SetTimer":                    4,
	"KillTimer":                   2,
	"SetWindowsHookExA":           4,
	"SetWindowsHookExW":           4,
	"UnhookWindowsHookEx":         1,
	"CallNextHookEx":              4,
	"MapVirtualKeyA":              2,
	"MapVirtualKeyW":              2,
	"MapVirtualKeyExA":            3,
	"MapVirtualKeyExW":            3,
	"GetKeyState":                 1,
	"GetAsyncKeyState":            1,
	"GetKeyboardState":            1,
	"SetKeyboardState":            1,
	"ToAscii":                     5,
	"ToUnicode":                   6,
	"VkKeyScanA":                  1,
	"VkKeyScanW":                  1,
	"GetKeyNameTextA":             3,
	"GetKeyNameTextW":             3,
	"SetRect":                     5,
	"SetRectEmpty":                1,
	"CopyRect":                    2,
	"InflateRect":                 3,
	"OffsetRect":                  3,
	"IntersectRect":               3,
	"UnionRect":                   3,
	"SubtractRect":                3,
	"IsRectEmpty":                 1,
	"PtInRect":                    3,
	"EqualRect":                   2,
	"FillRect":                    3,
	"FrameRect":                   3,
	"DrawEdge":                    4,
	"DrawFrameControl":            4,
	"DrawTextA":                   5,
	"DrawTextW":                   5,
	"DrawTextExA":                 6,
	"DrawTextExW":                 6,
	"ClientToScreen":              2,
	"ScreenToClient":              2,
	"MapWindowPoints":             4,
	"GetSysColor":                 1,
	"GetSysColorBrush":            1,
	"SetSysColors":                3,
	"MsgWaitForMultipleObjects":   5,
	"MsgWaitForMultipleObjectsEx": 5,
	"WaitMessage":                 0,
	"RegisterWindowMessageA":      1,
	"RegisterWindowMessageW":      1,
	"GetClassInfoA":               3,
	"GetClassInfoW":               3,
	"GetClassInfoExA":             3,
	"GetClassInfoExW":             3,
	"ScrollWindow":                5,
	"ScrollWindowEx":              8,
	"GetScrollInfo":               3,
	"SetScrollInfo":               4,
	"GetScrollPos":                2,
	"SetScrollPos":                4,
	"GetScrollRange":              4,
	"SetScrollRange":              5,
	"ShowScrollBar":               3,
	"EnableScrollBar":             3,
	"OpenClipboard":               1,
	"CloseClipboard":              0,
	"EmptyClipboard":              0,
	"GetClipboardData":            1,
	"SetClipboardData":            2,
	"IsClipboardFormatAvailable":  1,
	"RegisterClipboardFormatA":    1,
	"RegisterClipboardFormatW":    1,
	"CountClipboardFormats":       0,
	"EnumClipboardFormats":        1,
	"GetClipboardOwner":           0,
	"CharNextA":                   1,
	"CharNextW":                   1,
	"CharPrevA":                   2,
	"CharPrevW":                   2,
	"CharUpperA":                  1,
	"CharUpperW":                  1,
	"CharLowerA":                  1,
	"CharLowerW":                  1,
	"CharUpperBuffA":              2,
	"CharUpperBuffW":              2,
	"CharLowerBuffA":              2,
	"CharLowerBuffW":              2,
	"wsprintfA":                   0, // cdecl variadic
	"wsprintfW":                   0, // cdecl variadic
	"wvsprintfA":                  3,
	"wvsprintfW":                  3,
	"GetWindow":                   2,
	"GetTopWindow":                1,
	"EnumWindows":                 2,
	"EnumChildWindows":            3,
	"EnumThreadWindows":           3,
	"IsChild":                     2,
	"GetPropA":                    2,
	"GetPropW":                    2,
	"SetPropA":                    3,
	"SetPropW":                    3,
	"RemovePropA":                 2,
	"RemovePropW":                 2,
	"MonitorFromPoint":            2,
	"MonitorFromRect":             2,
	"MonitorFromWindow":           2,
	"GetMonitorInfoA":             2,
	"GetMonitorInfoW":             2,
	"EnumDisplayMonitors":         4,
	"ChangeDisplaySettingsA":      2,
	"ChangeDisplaySettingsW":      2,
	"ChangeDisplaySettingsExA":    5,
	"ChangeDisplaySettingsExW":    5,
	"EnumDisplaySettingsA":        3,
	"EnumDisplaySettingsW":        3,
	"EnumDisplayDevicesA":         4,
	"EnumDisplayDevicesW":         4,
	"CreateIconFromResource":      4,
	"CreateIconFromResourceEx":    7,
	"DestroyIcon":                 1,
	"DestroyCursor":               1,
	"DrawIconEx":                  9,
	"GetIconInfo":                 2,
	"CopyIcon":                    1,
	"GetWindowPlacement":          2,
	"SetWindowPlacement":          2,
	"GetComboBoxInfo":             2,
	"GetListBoxInfo":              1,
	"AnimateWindow":               3,
	"FlashWindow":                 2,
	"FlashWindowEx":               1,
	"MessageBeep":                 1,
	"GetUserObjectInformationA":   5,
	"GetUserObjectInformationW":   5,
	"SendNotifyMessageA":          4,
	"SendNotifyMessageW":          4,
	"SendMessageTimeoutA":         7,
	"SendMessageTimeoutW":         7,
	"BroadcastSystemMessageA":     5,
	"BroadcastSystemMessageW":     5,
	"SetLayeredWindowAttributes":  4,
	"GetLayeredWindowAttributes":  4,
	"UpdateLayeredWindow":         9,
	"PrintWindow":                 3,
	"SetWindowRgn":                3,
	"GetWindowRgn":                2,
	"GetProcessWindowStation":     0,
	"GetThreadDesktop":            1,

	// --- gdi32.dll ---
	"GetDeviceCaps":          2,
	"CreatePen":              3,
	"CreatePenIndirect":      1,
	"ExtCreatePen":           5,
	"CreateSolidBrush":       1,
	"CreateHatchBrush":       2,
	"CreatePatternBrush":     1,
	"CreateBrushIndirect":    1,
	"CreateBitmapIndirect":   1,
	"CreateBitmap":           5,
	"CreateCompatibleBitmap": 3,
	"CreateDIBSection":       6,
	"CreateDIBitmap":         6,
	"SelectObject":           2,
	"DeleteObject":           1,
	"GetObjectA":             3,
	"GetObjectW":             3,
	"GetObjectType":          1,
	"GetCurrentObject":       2,
	"GetStockObject":         1,
	"SetBkColor":             2,
	"GetBkColor":             1,
	"SetBkMode":              2,
	"GetBkMode":              1,
	"SetTextColor":           2,
	"GetTextColor":           1,
	"SetTextAlign":           2,
	"GetTextAlign":           1,
	"TextOutA":               5,
	"TextOutW":               5,
	"ExtTextOutA":            8,
	"ExtTextOutW":            8,
	"GetTextExtentPoint32A":  4,
	"GetTextExtentPoint32W":  4,
	"GetTextExtentExPointA":  7,
	"GetTextExtentExPointW":  7,
	"GetTextMetricsA":        2,
	"GetTextMetricsW":        2,
	"GetTextFaceA":           3,
	"GetTextFaceW":           3,
	"BitBlt":                 9,
	"StretchBlt":             11,
	"PatBlt":                 5,
	"MaskBlt":                12,
	"TransparentBlt":         11,
	"AlphaBlend":             11,
	"CreateCompatibleDC":     1,
	"CreateDCA":              4,
	"CreateDCW":              4,
	"DeleteDC":               1,
	"SaveDC":                 1,
	"RestoreDC":              2,
	"SetMapMode":             2,
	"GetMapMode":             1,
	"SetViewportOrgEx":       4,
	"GetViewportOrgEx":       2,
	"SetViewportExtEx":       4,
	"GetViewportExtEx":       2,
	"SetWindowOrgEx":         4,
	"GetWindowOrgEx":         2,
	"SetWindowExtEx":         4,
	"GetWindowExtEx":         2,
	"DPtoLP":                 3,
	"LPtoDP":                 3,
	"SetROP2":                2,
	"GetROP2":                1,
	"SetPolyFillMode":        2,
	"GetPolyFillMode":        1,
	"MoveToEx":               4,
	"LineTo":                 3,
	"Rectangle":              5,
	"Ellipse":                5,
	"Polygon":                3,
	"Polyline":               3,
	"PolyBezier":             3,
	"PolyBezierTo":           3,
	"Arc":                    9,
	"ArcTo":                  9,
	"Pie":                    9,
	"Chord":                  9,
	"RoundRect":              7,
	"SetPixel":               4,
	"GetPixel":               3,
	"SetPixelV":              4,
	"CreateFontA":            14,
	"CreateFontW":            14,
	"CreateFontIndirectA":    1,
	"CreateFontIndirectW":    1,
	"EnumFontFamiliesA":      4,
	"EnumFontFamiliesW":      4,
	"EnumFontFamiliesExA":    5,
	"EnumFontFamiliesExW":    5,
	"AddFontResourceA":       1,
	"AddFontResourceW":       1,
	"AddFontResourceExA":     3,
	"AddFontResourceExW":     3,
	"RemoveFontResourceA":    1,
	"RemoveFontResourceW":    1,
	"GetDIBits":              7,
	"SetDIBits":              7,
	"SetDIBitsToDevice":      12,
	"StretchDIBits":          13,
	"CreateRectRgn":          4,
	"CreateRectRgnIndirect":  1,
	"CreateEllipticRgn":      4,
	"CreateRoundRectRgn":     6,
	"CreatePolygonRgn":       3,
	"CombineRgn":             4,
	"EqualRgn":               2,
	"GetRgnBox":              2,
	"OffsetRgn":              3,
	"PtInRegion":             3,
	"RectInRegion":           2,
	"SelectClipRgn":          2,
	"ExtSelectClipRgn":       3,
	"GetClipBox":             2,
	"GetClipRgn":             2,
	"IntersectClipRect":      5,
	"ExcludeClipRect":        5,
	"SetStretchBltMode":      2,
	"GetStretchBltMode":      1,
	"CreateMetaFileA":        1,
	"CreateMetaFileW":        1,
	"CloseMetaFile":          1,
	"PlayMetaFile":           2,
	"CreateEnhMetaFileA":     4,
	"CreateEnhMetaFileW":     4,
	"CloseEnhMetaFile":       1,
	"PlayEnhMetaFile":        3,
	"GetEnhMetaFileHeader":   3,
	"DeleteEnhMetaFile":      1,
	"GdiFlush":               0,
	"SetLayout":              2,
	"GetLayout":              1,
	"SetGraphicsMode":        2,
	"GetGraphicsMode":        1,
	"SetWorldTransform":      2,
	"GetWorldTransform":      2,
	"ModifyWorldTransform":   3,
	"BeginPath":              1,
	"EndPath":                1,
	"StrokePath":             1,
	"FillPath":               1,
	"StrokeAndFillPath":      1,
	"CloseFigure":            1,
	"FlattenPath":            1,
	"WidenPath":              1,
	"PathToRegion":           1,
	"GetPath":                4,
	"AbortPath":              1,
	"SetMiterLimit":          3,
	"GetMiterLimit":          2,
	"GetNearestColor":        2,

	// --- advapi32.dll ---
	"RegOpenKeyExA":                5,
	"RegOpenKeyExW":                5,
	"RegCreateKeyExA":              9,
	"RegCreateKeyExW":              9,
	"RegCloseKey":                  1,
	"RegQueryValueExA":             6,
	"RegQueryValueExW":             6,
	"RegSetValueExA":               6,
	"RegSetValueExW":               6,
	"RegDeleteKeyA":                2,
	"RegDeleteKeyW":                2,
	"RegDeleteValueA":              2,
	"RegDeleteValueW":              2,
	"RegEnumKeyExA":                8,
	"RegEnumKeyExW":                8,
	"RegEnumValueA":                8,
	"RegEnumValueW":                8,
	"RegQueryInfoKeyA":             12,
	"RegQueryInfoKeyW":             12,
	"RegFlushKey":                  1,
	"RegNotifyChangeKeyValue":      5,
	"OpenProcessToken":             3,
	"OpenThreadToken":              4,
	"GetTokenInformation":          5,
	"SetTokenInformation":          4,
	"AdjustTokenPrivileges":        6,
	"LookupPrivilegeValueA":        3,
	"LookupPrivilegeValueW":        3,
	"LookupAccountSidA":            7,
	"LookupAccountSidW":            7,
	"LookupAccountNameA":           7,
	"LookupAccountNameW":           7,
	"ConvertSidToStringSidA":       2,
	"ConvertSidToStringSidW":       2,
	"ConvertStringSidToSidA":       2,
	"ConvertStringSidToSidW":       2,
	"IsValidSid":                   1,
	"GetLengthSid":                 1,
	"CopySid":                      3,
	"EqualSid":                     2,
	"AllocateAndInitializeSid":     9,
	"FreeSid":                      1,
	"GetSidSubAuthority":           2,
	"GetSidSubAuthorityCount":      1,
	"InitializeSecurityDescriptor": 2,
	"SetSecurityDescriptorDacl":    4,
	"GetSecurityDescriptorDacl":    4,
	"InitializeAcl":                3,
	"AddAccessAllowedAce":          4,
	"GetUserNameA":                 2,
	"GetUserNameW":                 2,
	"CryptAcquireContextA":         5,
	"CryptAcquireContextW":         5,
	"CryptReleaseContext":          2,
	"CryptGenRandom":               3,
	"CryptCreateHash":              5,
	"CryptHashData":                4,
	"CryptGetHashParam":            5,
	"CryptDestroyHash":             1,
	"CryptDeriveKey":               5,
	"CryptDecrypt":                 6,
	"CryptEncrypt":                 7,
	"CryptDestroyKey":              1,
	"CryptExportKey":               6,
	"CryptImportKey":               6,
	"CryptSetKeyParam":             4,
	"CryptGetKeyParam":             5,

	// --- shell32.dll ---
	"ShellExecuteA":           6,
	"ShellExecuteW":           6,
	"ShellExecuteExA":         1,
	"ShellExecuteExW":         1,
	"ShellAboutA":             4,
	"ShellAboutW":             4,
	"SHGetFolderPathA":        5,
	"SHGetFolderPathW":        5,
	"SHGetSpecialFolderPathA": 4,
	"SHGetSpecialFolderPathW": 4,
	"SHGetPathFromIDListA":    2,
	"SHGetPathFromIDListW":    2,
	"SHBrowseForFolderA":      1,
	"SHBrowseForFolderW":      1,
	"SHFileOperationA":        1,
	"SHFileOperationW":        1,
	"SHGetDesktopFolder":      1,
	"SHCreateDirectoryExA":    3,
	"SHCreateDirectoryExW":    3,
	"DragAcceptFiles":         2,
	"DragQueryFileA":          4,
	"DragQueryFileW":          4,
	"DragFinish":              1,
	"ExtractIconA":            3,
	"ExtractIconW":            3,
	"ExtractIconExA":          5,
	"ExtractIconExW":          5,
	"FindExecutableA":         3,
	"FindExecutableW":         3,

	// --- winmm.dll ---
	"PlaySoundA":             3,
	"PlaySoundW":             3,
	"timeGetTime":            0,
	"timeBeginPeriod":        1,
	"timeEndPeriod":          1,
	"timeSetEvent":           5,
	"timeKillEvent":          1,
	"waveOutOpen":            6,
	"waveOutClose":           1,
	"waveOutWrite":           3,
	"waveOutPrepareHeader":   3,
	"waveOutUnprepareHeader": 3,
	"waveOutReset":           1,
	"waveOutGetNumDevs":      0,
	"waveOutGetDevCapsA":     3,
	"waveOutGetDevCapsW":     3,
	"mciSendCommandA":        4,
	"mciSendCommandW":        4,
	"mciSendStringA":         4,
	"mciSendStringW":         4,
	"mciGetErrorStringA":     3,
	"mciGetErrorStringW":     3,
	"midiOutOpen":            5,
	"midiOutClose":           1,
	"midiOutShortMsg":        2,

	// --- ole32.dll ---
	"CoInitialize":          1,
	"CoInitializeEx":        2,
	"CoUninitialize":        0,
	"CoCreateInstance":      5,
	"CoTaskMemAlloc":        1,
	"CoTaskMemRealloc":      2,
	"CoTaskMemFree":         1,
	"CoRegisterClassObject": 5,
	"CoRevokeClassObject":   1,
	"CLSIDFromProgID":       2,
	"CLSIDFromString":       2,
	"StringFromCLSID":       2,
	"StringFromGUID2":       3,
	"ProgIDFromCLSID":       2,

	// --- oleaut32.dll ---
	"SysAllocString":        1,
	"SysAllocStringLen":     2,
	"SysReAllocString":      2,
	"SysReAllocStringLen":   3,
	"SysFreeString":         1,
	"SysStringLen":          1,
	"SysStringByteLen":      1,
	"VariantInit":           1,
	"VariantClear":          1,
	"VariantCopy":           2,
	"VariantChangeType":     4,
	"VariantChangeTypeEx":   5,
	"SafeArrayCreate":       3,
	"SafeArrayCreateEx":     4,
	"SafeArrayDestroy":      1,
	"SafeArrayGetDim":       1,
	"SafeArrayGetElement":   3,
	"SafeArrayPutElement":   3,
	"SafeArrayAccessData":   2,
	"SafeArrayUnaccessData": 1,
	"SafeArrayGetLBound":    3,
	"SafeArrayGetUBound":    3,

	// --- comctl32.dll ---
	"InitCommonControls":      0,
	"InitCommonControlsEx":    1,
	"ImageList_Create":        5,
	"ImageList_Destroy":       1,
	"ImageList_Add":           3,
	"ImageList_AddMasked":     3,
	"ImageList_Draw":          6,
	"ImageList_DrawEx":        10,
	"ImageList_GetImageCount": 1,
	"ImageList_GetImageInfo":  3,
	"ImageList_SetBkColor":    2,
	"ImageList_GetBkColor":    1,
	"ImageList_ReplaceIcon":   3,
	"PropertySheetA":          1,
	"PropertySheetW":          1,
	"CreateStatusWindowA":     4,
	"CreateStatusWindowW":     4,

	// --- comdlg32.dll ---
	"GetOpenFileNameA":     1,
	"GetOpenFileNameW":     1,
	"GetSaveFileNameA":     1,
	"GetSaveFileNameW":     1,
	"ChooseColorA":         1,
	"ChooseColorW":         1,
	"ChooseFontA":          1,
	"ChooseFontW":          1,
	"FindTextA":            1,
	"FindTextW":            1,
	"ReplaceTextA":         1,
	"ReplaceTextW":         1,
	"PrintDlgA":            1,
	"PrintDlgW":            1,
	"PageSetupDlgA":        1,
	"PageSetupDlgW":        1,
	"CommDlgExtendedError": 0,

	// --- ws2_32.dll ---
	"WSAStartup":      2,
	"WSACleanup":      0,
	"WSAGetLastError": 0,
	"WSASetLastError": 1,
	"socket":          3,
	"closesocket":     1,
	"bind":            3,
	"listen":          2,
	"accept":          3,
	"connect":         3,
	"send":            4,
	"recv":            4,
	"sendto":          6,
	"recvfrom":        6,
	"select":          5,
	"setsockopt":      5,
	"getsockopt":      5,
	"getaddrinfo":     4,
	"freeaddrinfo":    1,
	"getnameinfo":     7,
	"ioctlsocket":     3,
	"shutdown":        2,
	"gethostname":     2,
	"gethostbyname":   1,
	"getpeername":     3,
	"getsockname":     3,
	"inet_addr":       1,
	"inet_ntoa":       1,
	"htons":           1,
	"htonl":           1,
	"ntohs":           1,
	"ntohl":           1,

	// --- shlwapi.dll ---
	"PathFileExistsA":      1,
	"PathFileExistsW":      1,
	"PathFindExtensionA":   1,
	"PathFindExtensionW":   1,
	"PathFindFileNameA":    1,
	"PathFindFileNameW":    1,
	"PathRemoveFileSpecA":  1,
	"PathRemoveFileSpecW":  1,
	"PathAppendA":          2,
	"PathAppendW":          2,
	"PathCombineA":         3,
	"PathCombineW":         3,
	"PathIsRelativeA":      1,
	"PathIsRelativeW":      1,
	"PathIsDirectoryA":     1,
	"PathIsDirectoryW":     1,
	"PathStripPathA":       1,
	"PathStripPathW":       1,
	"PathRemoveExtensionA": 1,
	"PathRemoveExtensionW": 1,
	"PathAddExtensionA":    2,
	"PathAddExtensionW":    2,
	"PathRenameExtensionA": 2,
	"PathRenameExtensionW": 2,
	"StrStrA":              2,
	"StrStrW":              2,
	"StrStrIA":             2,
	"StrStrIW":             2,
	"StrCmpNA":             3,
	"StrCmpNW":             3,
	"StrCmpNIA":            3,
	"StrCmpNIW":            3,
	"StrChrA":              2,
	"StrChrW":              2,
	"StrRChrA":             3,
	"StrRChrW":             3,
	"StrDupA":              1,
	"StrDupW":              1,
	"SHDeleteKeyA":         2,
	"SHDeleteKeyW":         2,
	"SHDeleteValueA":       3,
	"SHDeleteValueW":       3,
	"SHGetValueA":          6,
	"SHGetValueW":          6,
	"SHSetValueA":          6,
	"SHSetValueW":          6,

	// --- version.dll ---
	"GetFileVersionInfoA":     4,
	"GetFileVersionInfoW":     4,
	"GetFileVersionInfoSizeA": 2,
	"GetFileVersionInfoSizeW": 2,
	"VerQueryValueA":          4,
	"VerQueryValueW":          4,

	// --- crypt32.dll ---
	"CertOpenStore":                   5,
	"CertCloseStore":                  2,
	"CertOpenSystemStoreA":            2,
	"CertOpenSystemStoreW":            2,
	"CertFindCertificateInStore":      6,
	"CertFreeCertificateContext":      1,
	"CertDuplicateCertificateContext": 1,
	"CertGetCertificateChain":         8,
	"CertFreeCertificateChain":        1,
	"CryptDecodeObjectEx":             7,
	"CryptEncodeObjectEx":             7,
	"CertGetNameStringA":              5,
	"CertGetNameStringW":              5,
	"PFXImportCertStore":              3,

	// --- winspool.drv ---
	"OpenPrinterA":        3,
	"OpenPrinterW":        3,
	"ClosePrinter":        1,
	"EnumPrintersA":       6,
	"EnumPrintersW":       6,
	"GetDefaultPrinterA":  2,
	"GetDefaultPrinterW":  2,
	"StartDocPrinterA":    3,
	"StartDocPrinterW":    3,
	"EndDocPrinter":       1,
	"StartPagePrinter":    1,
	"EndPagePrinter":      1,
	"WritePrinter":        4,
	"DocumentPropertiesA": 6,
	"DocumentPropertiesW": 6,
	"DeviceCapabilitiesA": 5,
	"DeviceCapabilitiesW": 5,

	// --- imm32.dll ---
	"ImmGetContext":            1,
	"ImmReleaseContext":        2,
	"ImmGetCompositionStringA": 4,
	"ImmGetCompositionStringW": 4,
	"ImmSetCompositionStringA": 5,
	"ImmSetCompositionStringW": 5,
	"ImmGetOpenStatus":         1,
	"ImmSetOpenStatus":         2,
	"ImmGetConversionStatus":   3,
	"ImmSetConversionStatus":   3,
	"ImmIsIME":                 1,
	"ImmNotifyIME":             4,
	"ImmGetDefaultIMEWnd":      1,
	"ImmAssociateContext":      2,
	"ImmAssociateContextEx":    3,
	"ImmInstallIMEA":           2,
	"ImmInstallIMEW":           2,

	// --- msimg32.dll (same as gdi32 exports) ---
	"GradientFill": 6,

	// --- uxtheme.dll ---
	"OpenThemeData":                 2,
	"CloseThemeData":                1,
	"DrawThemeBackground":           6,
	"DrawThemeText":                 8,
	"GetThemeBackgroundContentRect": 6,
	"GetThemePartSize":              6,
	"IsThemeActive":                 0,
	"IsAppThemed":                   0,
	"SetWindowTheme":                3,
	"GetThemeColor":                 5,
	"GetThemeFont":                  6,
	"GetThemeMetric":                5,
	"GetThemeSysColor":              2,
	"GetThemeSysFont":               3,
	"EnableThemeDialogTexture":      2,
	"IsThemeDialogTextureEnabled":   1,

	// --- wininet.dll ---
	"InternetOpenA":              5,
	"InternetOpenW":              5,
	"InternetConnectA":           8,
	"InternetConnectW":           8,
	"InternetCloseHandle":        1,
	"InternetOpenUrlA":           6,
	"InternetOpenUrlW":           6,
	"InternetReadFile":           4,
	"InternetWriteFile":          4,
	"HttpOpenRequestA":           8,
	"HttpOpenRequestW":           8,
	"HttpSendRequestA":           5,
	"HttpSendRequestW":           5,
	"HttpQueryInfoA":             5,
	"HttpQueryInfoW":             5,
	"InternetQueryDataAvailable": 2,
	"InternetSetOptionA":         4,
	"InternetSetOptionW":         4,
	"InternetQueryOptionA":       4,
	"InternetQueryOptionW":       4,

	// --- winhttp.dll ---
	"WinHttpOpen":               5,
	"WinHttpConnect":            4,
	"WinHttpOpenRequest":        7,
	"WinHttpAddRequestHeaders":  4,
	"WinHttpSendRequest":        7,
	"WinHttpReceiveResponse":    2,
	"WinHttpQueryHeaders":       6,
	"WinHttpReadData":           4,
	"WinHttpQueryDataAvailable": 2,
	"WinHttpSetOption":          4,
	"WinHttpQueryOption":        4,
	"WinHttpCloseHandle":        1,
	"WinHttpCrackUrl":           4,
	"WinHttpSetCredentials":     6,

	// --- psapi.dll ---
	"EnumProcesses":        3,
	"EnumProcessModules":   4,
	"GetModuleBaseNameA":   4,
	"GetModuleBaseNameW":   4,
	"GetModuleFileNameExA": 4,
	"GetModuleFileNameExW": 4,
	"GetProcessMemoryInfo": 3,
	"EnumProcessModulesEx": 5,

	// --- gdi32.dll extras (needed for 32-bit installer DLLs) ---
	"SelectPalette":               3,
	"RealizePalette":              1,
	"CreatePalette":               1,
	"CreateScalableFontResourceA": 4,
	"CreateScalableFontResourceW": 4,
	"DeleteMetaFile":              1,
	"SetMetaFileBitsEx":           2,
	"GetTextExtentPointA":         4,
	"GetTextExtentPointW":         4,

	// --- user32.dll extras ---
	"DrawFocusRect":      2,
	"GetDialogBaseUnits": 0,
	"InvalidateRgn":      3,

	// --- user32.dll DDE/misc (needed for 32-bit installer DLLs) ---
	"DdeInitializeA":         4,
	"DdeInitializeW":         4,
	"DdeUninitialize":        1,
	"DdeCreateStringHandleA": 3,
	"DdeCreateStringHandleW": 3,
	"DdeFreeStringHandle":    2,
	"DdeQueryStringA":        5,
	"DdeQueryStringW":        5,
	"DdeNameService":         4,
	"DdeConnect":             4,
	"DdeDisconnect":          1,
	"DdeClientTransaction":   8,
	"DdeGetData":             4,
	"DdeCreateDataHandle":    7,
	"DdeFreeDataHandle":      1,
	"DdePostAdvise":          3,
	"WinHelpA":               4,
	"WinHelpW":               4,
	"OemToCharA":             2,
	"OemToCharW":             2,
	"CharToOemA":             2,
	"CharToOemW":             2,
	"DrawIcon":               4,

	// --- advapi32.dll extras ---
	"RegSetValueA":     5,
	"RegSetValueW":     5,
	"RegQueryValueA":   4,
	"RegQueryValueW":   4,
	"AccessCheck":      8,
	"RevertToSelf":     0,
	"ImpersonateSelf":  1,
	"GetFileSecurityA": 5,
	"GetFileSecurityW": 5,

	// --- version.dll extras ---
	"VerInstallFileA": 8,
	"VerInstallFileW": 8,
	"VerFindFileA":    7,
	"VerFindFileW":    7,

	// --- mpr.dll ---
	"WNetGetConnectionA": 3,
	"WNetGetConnectionW": 3,

	// --- winmm.dll extras ---
	"sndPlaySoundA":     2,
	"sndPlaySoundW":     2,
	"midiOutGetNumDevs": 0,
}

// RegisterAutoStubHandler registers a handler for a specific function in a
// synthetic DLL by looking up its trap ID.
func (d *Dispatcher) RegisterAutoStubHandler(synth *SynthPE, funcName string, h TrapHandler) {
	// Always store by name so dynamic duplicates can inherit this handler.
	d.handlersByName[funcName] = h
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
	if setter, ok := any(d.ctx).(interface{ SetCurrentCPU(arch.CPU) }); ok {
		setter.SetCurrentCPU(cpu)
	}
	syscallID := uint32(cpu.SyscallNum()) // EAX contains the syscall ID
	is32 := d.ctx.State != nil && d.ctx.State.Is32

	// Temporary: trace COM trap IDs
	if syscallID >= 0x10000000 {
		name := d.names[syscallID]
		ravelog.Logf("[COM-TRAP] id=0x%x is32=%v name=%s\n", syscallID, is32, name)
	}

	// Debug: log any stub called from within the zero VirtualAlloc region
	if is32 {
		sp := cpu.GetSP()
		if retAddr, err := d.ctx.Mem.Read32(sp); err == nil {
			if retAddr >= 0x10400000 && retAddr <= 0x10BFFFFF {
				name := d.names[syscallID]
				if name == "" {
					name = fmt.Sprintf("unknown_0x%04X", syscallID)
				}
				ravelog.Logf("[zero-region] stub called from zero-region ret=0x%x: %s\n", retAddr, name)
			}
		}
	}

	if d.ctx.TraceSyscall {
		name := d.names[syscallID]
		if name == "" {
			name = fmt.Sprintf("unknown_0x%04X", syscallID)
		}
		impl := ""
		if _, ok := d.handlers[syscallID]; !ok {
			impl = " [UNIMPL]"
		}
		ravelog.Logf("[syscall] %s (id=0x%04X)%s\n", name, syscallID, impl)
	}

	handler, ok := d.handlers[syscallID]
	if !ok {
		name := d.names[syscallID]
		if name == "" {
			name = fmt.Sprintf("unknown_0x%04X", syscallID)
		}
		// Log missing API to file for tracking
		if syscallID >= AutoSynthIDBase {
			// This is an auto-synth stub - log the missing API
			missingFile, err := os.OpenFile("missing_api.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err == nil {
				fmt.Fprintf(missingFile, "[MISSING] auto-synth!%s (id=0x%04X)\n", name, syscallID)
				missingFile.Close()
			}
		}
		ravelog.Logf("[ntapi] UNIMPLEMENTED: %s (id=0x%04X)\n", name, syscallID)
		// For auto-synth user-mode DLL stubs, return 0 (NULL/FALSE).
		// For NT syscalls, return STATUS_NOT_IMPLEMENTED.
		if syscallID >= AutoSynthIDBase {
			cpu.SetSyscallReturn(0)
		} else {
			cpu.SetSyscallReturn(0xC0000002)
		}
		// PE32 stdcall cleanup for unimplemented stubs:
		// use the arg count table if available.
		if is32 && !d.cdeclIDs[syscallID] {
			if nArgs, ok := d.stdcallArgs[syscallID]; ok && nArgs > 0 {
				d.doStdcallCleanup(cpu, nArgs)
			}
		}
		return
	}

	if d.ctx.Trace {
		name := d.names[syscallID]
		sp := cpu.GetSP()
		if name != "__wine_dbg_header" || sp < 0x7C000000 {
			if is32 {
				retAddr, _ := d.ctx.Mem.Read32(sp)
				ravelog.Logf("[trace] → %s (id=0x%04X) sp=0x%x ret=0x%x\n", name, syscallID, sp, retAddr)
			} else {
				retAddr, _ := d.ctx.Mem.Read64(sp)
				ravelog.Logf("[trace] → %s (id=0x%04X) sp=0x%x ret=0x%x\n", name, syscallID, sp, retAddr)
			}
		}
	}

	// Detect the PE32 win32k path: gdi32/user32 syscall stubs dispatch via
	// `call [KUSER_SHARED_DATA->SystemCall]`, landing in our vmcall trampoline.
	// That `call` pushed one extra return address, so stack args sit 4 bytes
	// higher, and stack cleanup is done by the stub's own `ret N` (not by us).
	viaTramp := false
	if is32 && d.ctx.State != nil && d.ctx.State.Win32kTrampoline != 0 {
		pc := cpu.GetPC()
		t := d.ctx.State.Win32kTrampoline
		if pc >= t && pc <= t+4 {
			viaTramp = true
		}
	}
	if viaTramp {
		d.ctx.i386ArgExtra = 4
	} else {
		d.ctx.i386ArgExtra = 0
	}

	d.ctx.ReturnOverridden = false
	d.ctx.PCRedirected = false
	d.ctx.maxArgIdx = -1
	status := handler(d.ctx)
	if !d.ctx.ReturnOverridden {
		cpu.SetSyscallReturn(uint64(status))
	}

	// Temporary: trace COM cleanup decision
	if syscallID >= 0x10000000 {
		name := d.names[syscallID]
		explicit, hasExplicit := d.stdcallArgs[syscallID]
		ravelog.Logf("[COM-POST] %s is32=%v cdecl=%v pcRedir=%v maxArg=%d explicit=%d(%v)\n",
			name, is32, d.cdeclIDs[syscallID], d.ctx.PCRedirected, d.ctx.maxArgIdx, explicit, hasExplicit)
	}

	// PE32 stdcall cleanup: the callee must pop arguments from the stack.
	// Skip if the handler redirected PC (sync WndProc dispatch manages its own stack).
	// Also skip for the SystemCall-trampoline path: the trampoline's `ret`
	// returns to the real gdi32/user32 stub, whose own `ret N` pops the args.
	if is32 && viaTramp {
		// Emulate the trampoline's `ret` (RET 0): pop the return address back
		// into the real gdi32/user32 stub and set PC, preserving EAX. The stub's
		// own `ret N` then pops the service args. (Like synth stubs, the CPU
		// expects the dispatcher to manage the return PC, so a plain skip would
		// not execute the trampoline's `ret`.)
		d.doStdcallCleanup(cpu, 0)
	} else if is32 && !d.cdeclIDs[syscallID] && !d.ctx.PCRedirected {
		// Prefer explicit arg count (from Win32 API table) over heuristic.
		nArgs := d.ctx.maxArgIdx + 1
		if explicit, ok := d.stdcallArgs[syscallID]; ok {
			nArgs = explicit
		}
		if nArgs > 0 {
			d.doStdcallCleanup(cpu, nArgs)
		}
	} else if is32 {
		name := d.names[syscallID]
		if strings.Contains(name, "com!") || strings.Contains(name, "d3d!") {
			ravelog.Logf("[stdcall-SKIP] %s cdecl=%v pcRedir=%v is32=%v\n", name, d.cdeclIDs[syscallID], d.ctx.PCRedirected, is32)
		}
	}
}

// doStdcallCleanup emulates RET n for PE32 stdcall: pop the return address,
// skip all arguments, and set RIP directly - avoiding any stack writes that
// could clobber output buffers sitting just above the argument area.
func (d *Dispatcher) doStdcallCleanup(cpu arch.CPU, nArgs int) {
	sp := cpu.GetSP()
	retAddr, _ := d.ctx.Mem.Read32(sp)
	newSP := sp + 4 + uint64(nArgs)*4
	ravelog.Logf("[stdcall] nArgs=%d sp=0x%x→0x%x ret=0x%x\n", nArgs, sp, newSP, retAddr)
	cpu.SetSP(newSP)
	cpu.SetPC(uint64(retAddr))
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
	d.register(idOf("NtPulseEvent"), "NtPulseEvent", handleNtPulseEvent)
	d.register(idOf("NtQueryEvent"), "NtQueryEvent", handleNtQueryEvent)
	d.register(idOf("NtQueryMutant"), "NtQueryMutant", handleNtQueryMutant)
	d.register(idOf("NtQuerySemaphore"), "NtQuerySemaphore", handleNtQuerySemaphore)
	d.register(idOf("NtQueryTimerResolution"), "NtQueryTimerResolution", handleNtQueryTimerResolution)
	d.register(idOf("NtWaitForSingleObject"), "NtWaitForSingleObject", handleNtWaitForSingleObject)
	d.register(idOf("NtWaitForMultipleObjects"), "NtWaitForMultipleObjects", handleNtWaitForMultipleObjects)
	d.register(idOf("NtCreateMutant"), "NtCreateMutant", handleNtCreateMutant)
	d.register(idOf("NtReleaseMutant"), "NtReleaseMutant", handleNtReleaseMutant)
	d.register(idOf("NtDelayExecution"), "NtDelayExecution", handleNtDelayExecution)
	d.register(idOf("NtYieldExecution"), "NtYieldExecution", handleNtYieldExecution)
	d.register(idOf("NtQueryPerformanceCounter"), "NtQueryPerformanceCounter", handleNtQueryPerformanceCounter)
	d.register(idOf("NtQuerySystemTime"), "NtQuerySystemTime", handleNtQuerySystemTime)
	// Keyed Events (used by SRW locks, condition variables, critical section fallback)
	d.register(idOf("NtCreateKeyedEvent"), "NtCreateKeyedEvent", handleNtCreateKeyedEvent)
	d.register(idOf("NtOpenKeyedEvent"), "NtOpenKeyedEvent", handleNtOpenKeyedEvent)
	d.register(idOf("NtWaitForKeyedEvent"), "NtWaitForKeyedEvent", handleNtWaitForKeyedEvent)
	d.register(idOf("NtReleaseKeyedEvent"), "NtReleaseKeyedEvent", handleNtReleaseKeyedEvent)
	d.register(idOf("ZwCreateKeyedEvent"), "ZwCreateKeyedEvent", handleNtCreateKeyedEvent)
	d.register(idOf("ZwWaitForKeyedEvent"), "ZwWaitForKeyedEvent", handleNtWaitForKeyedEvent)
	d.register(idOf("ZwReleaseKeyedEvent"), "ZwReleaseKeyedEvent", handleNtReleaseKeyedEvent)
	// UUID allocation
	d.register(idOf("NtAllocateUuids"), "NtAllocateUuids", handleNtAllocateUuids)
	d.register(idOf("ZwAllocateUuids"), "ZwAllocateUuids", handleNtAllocateUuids)

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
	d.register(idOf("NtOpenThread"), "NtOpenThread", handleNtOpenThread)
	d.register(idOf("NtAlertThread"), "NtAlertThread", handleNtAlertThread)
	d.register(idOf("NtAlertResumeThread"), "NtAlertResumeThread", handleNtAlertResumeThread)
	d.register(idOf("NtTestAlert"), "NtTestAlert", handleNtTestAlert)

	// Exception handling
	d.register(idOf("RtlCaptureContext"), "RtlCaptureContext", handleRtlCaptureContext)
	d.register(idOf("RtlUnwind"), "RtlUnwind", handleRtlUnwind)
	d.register(idOf("RtlUnwindEx"), "RtlUnwindEx", handleRtlUnwindEx)
	d.register(idOf("RtlLookupFunctionEntry"), "RtlLookupFunctionEntry", handleRtlLookupFunctionEntry)
	d.register(idOf("RtlRestoreContext"), "RtlRestoreContext", handleRtlRestoreContext)
	d.register(idOf("RtlRaiseException"), "RtlRaiseException", handleRtlRaiseException)
	d.register(idOf("RtlRaiseStatus"), "RtlRaiseStatus", handleRtlRaiseStatus)
	d.register(idOf("RtlAddVectoredExceptionHandler"), "RtlAddVectoredExceptionHandler", handleRtlAddVectoredExceptionHandler)
	d.register(idOf("RtlRemoveVectoredExceptionHandler"), "RtlRemoveVectoredExceptionHandler", handleRtlRemoveVectoredExceptionHandler)
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
	d.register(idOf("NtQueryTimer"), "NtQueryTimer", handleNtQueryTimer)
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
	d.register(idOf("RtlGetNtGlobalFlags"), "RtlGetNtGlobalFlags", handleRtlGetNtGlobalFlags)
	d.register(idOf("RtlGetNtProductType"), "RtlGetNtProductType", handleRtlGetNtProductType)
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
	d.register(idOf("RtlGetDaclSecurityDescriptor"), "RtlGetDaclSecurityDescriptor", handleRtlGetDaclSecurityDescriptor)
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
	d.register(idOf("NtGdiGetStockObject"), "NtGdiGetStockObject", handleNtGdiGetStockObject)
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

	// ── Wave 10: additional NT handlers ──────────────────────────
	// RtlEncode/DecodePointer (used by CRT on Vista+)
	d.register(idOf("RtlEncodePointer"), "RtlEncodePointer", handleRtlEncodePointer)
	d.register(idOf("RtlDecodePointer"), "RtlDecodePointer", handleRtlDecodePointer)
	d.register(idOf("RtlEncodeSystemPointer"), "RtlEncodeSystemPointer", handleRtlEncodeSystemPointer)
	d.register(idOf("RtlDecodeSystemPointer"), "RtlDecodeSystemPointer", handleRtlDecodeSystemPointer)
	// Thread management
	d.register(idOf("NtTerminateThread"), "NtTerminateThread", handleNtTerminateThread)
	d.register(idOf("ZwTerminateThread"), "ZwTerminateThread", handleNtTerminateThread)
	d.register(idOf("NtCreateThread"), "NtCreateThread", handleNtCreateThread)
	d.register(idOf("NtCreateThreadEx"), "NtCreateThreadEx", handleNtCreateThreadEx)
	// Job objects
	d.register(idOf("NtCreateJobObject"), "NtCreateJobObject", handleNtCreateJobObject)
	d.register(idOf("NtOpenJobObject"), "NtOpenJobObject", handleNtOpenJobObject)
	d.register(idOf("NtAssignProcessToJobObject"), "NtAssignProcessToJobObject", handleNtAssignProcessToJobObject)
	d.register(idOf("NtQueryInformationJobObject"), "NtQueryInformationJobObject", handleNtQueryInformationJobObject)
	// SEH / exception unwind (x64)
	d.register(idOf("RtlAddFunctionTable"), "RtlAddFunctionTable", handleRtlAddFunctionTable)
	d.register(idOf("RtlInstallFunctionTableCallback"), "RtlInstallFunctionTableCallback", handleRtlInstallFunctionTableCallback)
	d.register(idOf("RtlDeleteFunctionTable"), "RtlDeleteFunctionTable", handleRtlDeleteFunctionTable)
	d.register(idOf("RtlAddGrowableFunctionTable"), "RtlAddGrowableFunctionTable", handleRtlAddGrowableFunctionTable)
	d.register(idOf("RtlGrowFunctionTable"), "RtlGrowFunctionTable", handleRtlGrowFunctionTable)
	d.register(idOf("RtlDeleteGrowableFunctionTable"), "RtlDeleteGrowableFunctionTable", handleRtlDeleteGrowableFunctionTable)
	d.register(idOf("RtlLookupFunctionEntry"), "RtlLookupFunctionEntry", handleRtlLookupFunctionEntry)
	d.register(idOf("RtlCaptureContext"), "RtlCaptureContext", handleRtlCaptureContext)
	d.register(idOf("RtlVirtualUnwind"), "RtlVirtualUnwind", handleRtlVirtualUnwind)
	// Misc NT
	d.register(idOf("NtAreMappedFilesTheSame"), "NtAreMappedFilesTheSame", handleNtAreMappedFilesTheSame)
	d.register(idOf("NtSetTimerEx"), "NtSetTimerEx", handleNtSetTimerEx)
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

package main

import (
"flag"
"fmt"
"math"
"os"
"path/filepath"
"runtime/pprof"
"sort"
"strconv"
"strings"
"time"

"github.com/mirkobrombin/Raven/pkg/arch"
"github.com/mirkobrombin/Raven/pkg/cpu"
"github.com/mirkobrombin/Raven/pkg/loader"
"github.com/mirkobrombin/Raven/pkg/mmu"
"github.com/mirkobrombin/Raven/pkg/ntapi"
gosyscall "github.com/mirkobrombin/Raven/pkg/syscall"
"github.com/mirkobrombin/Raven/pkg/thread"
"github.com/mirkobrombin/Raven/pkg/vfs"
"github.com/mirkobrombin/Raven/pkg/wl"
"github.com/mirkobrombin/Raven/pkg/win32k"
"github.com/mirkobrombin/Raven/pkg/x64"
	ravelog "github.com/mirkobrombin/Raven/pkg/log"
)

func utf16Decode(s []uint16) []byte {
	var out []byte
	for _, w := range s {
		if w < 0x80 {
			out = append(out, byte(w))
		} else if w < 0x800 {
			out = append(out, byte(0xC0|(w>>6)), byte(0x80|(w&0x3F)))
		} else {
			out = append(out, byte(0xE0|(w>>12)), byte(0x80|((w>>6)&0x3F)), byte(0x80|(w&0x3F)))
		}
	}
	return out
}

func utf16Encode(s string) []uint16 {
	var out []uint16
	for _, r := range s {
		if r <= 0xFFFF {
			out = append(out, uint16(r))
		} else {
			r -= 0x10000
			out = append(out, uint16(0xD800+(r>>10)), uint16(0xDC00+(r&0x3FF)))
		}
	}
	return out
}

func main() {
ravelog.Banner("v0.1.0")

trace := flag.Bool("trace", false, "enable instruction trace to stderr")
memMB := flag.Int("mem", 256, "guest memory limit in MiB (advisory)")
sysroot := flag.String("sysroot", "", "path to Windows system DLL directory (for PE mode)")
regFile := flag.String("registry", "", "path to registry hive JSON file (for PE mode)")
cpuprof := flag.String("cpuprofile", "", "write CPU profile to file")
wayland := flag.Bool("wayland", true, "enable Wayland passthrough (use --wayland=false for headless)")

flag.Usage = func() {
	ravelog.Banner("v0.1.0")
	fmt.Fprintf(os.Stderr, "Usage: raven [flags] <binary> [args...]\n\n")
	fmt.Fprintf(os.Stderr, "Raven - in-process x86-64 Windows PE / ELF emulator\n\n")
	fmt.Fprintf(os.Stderr, "Supports ELF (Linux) and PE (Windows) executables.\n")
	fmt.Fprintf(os.Stderr, "PE mode is auto-detected from the file header (.exe/.dll or MZ magic).\n\n")
	flag.PrintDefaults()
}
flag.Parse()

if *cpuprof != "" {
	f, err := os.Create(*cpuprof)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cpuprofile: %v\n", err)
		os.Exit(1)
	}
	pprof.StartCPUProfile(f)
	defer pprof.StopCPUProfile()
}

args := flag.Args()
if len(args) < 1 {
flag.Usage()
os.Exit(1)
}

_ = memMB // reserved for future use

binPath := args[0]
absPath, _ := filepath.Abs(binPath)
guestArgv := args

// Detect binary format
isPE := detectPE(binPath)

if isPE {
	runPE(absPath, guestArgv, *sysroot, *regFile, *trace, *wayland)
} else {
	runELF(absPath, guestArgv, *trace, *wayland)
}
}
// detectPE checks if a file is a PE binary (MZ magic or .exe/.dll extension).
func detectPE(path string) bool {
ext := strings.ToLower(filepath.Ext(path))
if ext == ".exe" || ext == ".dll" {
return true
}
f, err := os.Open(path)
if err != nil {
return false
}
defer f.Close()
var magic [2]byte
if _, err := f.Read(magic[:]); err != nil {
return false
}
return magic[0] == 'M' && magic[1] == 'Z'
}

// runELF runs a Linux ELF binary (original code path).
func runELF(absPath string, guestArgv []string, trace bool, enableWayland bool) {
	guestEnvp := []string{
		"PATH=/usr/bin:/bin",
		"HOME=/root",
		"TERM=dumb",
		"SHELL=/bin/sh",
		"USER=root",
		"LOGNAME=root",
	}

	if enableWayland {
		xdg := os.Getenv("XDG_RUNTIME_DIR")
		if xdg == "" {
			xdg = "/run/user/1000"
		}
		guestEnvp = append(guestEnvp, "XDG_RUNTIME_DIR="+xdg)
		waylandDisp := os.Getenv("WAYLAND_DISPLAY")
		if waylandDisp == "" {
			waylandDisp = "wayland-0"
		}
		guestEnvp = append(guestEnvp, "WAYLAND_DISPLAY="+waylandDisp)
		// Software GL via Mesa/Gallium - no GPU device needed.
		guestEnvp = append(guestEnvp, "LIBGL_ALWAYS_SOFTWARE=1")
		guestEnvp = append(guestEnvp, "GALLIUM_DRIVER=softpipe")
		// Also expose DISPLAY for apps that fall back to X11 for font/cursor etc.
		if display := os.Getenv("DISPLAY"); display != "" {
			guestEnvp = append(guestEnvp, "DISPLAY="+display)
		}
	}

	mem := mmu.New()
	fs := vfs.New()
	fs.ElfPath = absPath

	if enableWayland {
		xdg := os.Getenv("XDG_RUNTIME_DIR")
		if xdg == "" {
			xdg = "/run/user/1000"
		}
		fs.MkdirAll(xdg)
		waylandDisp := os.Getenv("WAYLAND_DISPLAY")
		if waylandDisp == "" {
			waylandDisp = "wayland-0"
		}
		// Dummy VFS entry so guest can stat/access the socket path.
		fs.CreateFile(filepath.Join(xdg, waylandDisp), nil, 0666)
		// Also expose X11 for libs that probe DISPLAY (fontconfig, cursors, etc.)
		if display := os.Getenv("DISPLAY"); display != "" {
			dispNum := strings.TrimPrefix(display, ":")
			if dot := strings.Index(dispNum, "."); dot >= 0 {
				dispNum = dispNum[:dot]
			}
			x11Dir := "/tmp/.X11-unix"
			fs.MkdirAll(x11Dir)
			fs.CreateFile(filepath.Join(x11Dir, "X"+dispNum), nil, 0666)
		}
	}
fs.HostOut = func(fd int, data []byte) {
if fd == 1 {
os.Stdout.Write(data)
} else {
os.Stderr.Write(data)
}
}
fs.HostIn = func(fd int, buf []byte) int {
n, _ := os.Stdin.Read(buf)
return n
}

result, err := loader.LoadELF(absPath, mem, guestArgv, guestEnvp)
if err != nil {
fmt.Fprintf(os.Stderr, "govm: load error: %v\n", err)
os.Exit(1)
}


var guest arch.CPU
switch result.Arch {
case arch.ArchRISCV64:
c := cpu.New(mem)
c.SetPC(result.EntryPoint)
c.SetSP(result.StackPtr)
if result.TLSAddr != 0 {
c.SetTLS(result.TLSAddr)
}
guest = c
case arch.ArchAMD64:
c := x64.New(mem)
c.SetPC(result.EntryPoint)
c.SetSP(result.StackPtr)
if result.TLSAddr != 0 {
c.SetTLS(result.TLSAddr)
}
	// Fix Lapce double-free: only apply when running Lapce specifically.
	// After glibc realloc moves a buffer the old chunk is freed internally,
	// but Lapce's caller (at 0x55555799d5d3) tries to free the old ptr a
	// second time.  Patch the conditional jump JZ→JMP (0x74→0xeb) at
	// 0x55555799d5d9 so the redundant free is always skipped.
	if strings.Contains(absPath, "lapce") {
		const patchAddr = uint64(0x55555799d5d9)
		pageStart := patchAddr &^ (mmu.PageSize - 1)
		mem.Mprotect(pageStart, mmu.PageSize, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
		if err := mem.Write8(patchAddr, 0xeb); err != nil {
			ravelog.Logf("[PATCH] FAILED to apply double-free fix: %v\n", err)
		}
		mem.Mprotect(pageStart, mmu.PageSize, mmu.PermRead|mmu.PermExecute)
	}
	guest = c
}

sh := gosyscall.NewHandler(mem, fs)
sh.Trace = trace
sh.Arch = result.Arch

tm := thread.NewManager(mem, sh.Handle)
sh.ThreadM = tm

mainThread := tm.MainThread(guest)

if err := mainThread.CPU.Run(); err != nil {
if exitErr, ok := err.(*arch.ExitError); ok {
os.Exit(exitErr.Code)
}
fmt.Fprintf(os.Stderr, "govm: runtime error: %v\n", err)
os.Exit(1)
}

tm.Wait()
}

// runPE runs a Windows PE binary with the NT subsystem.
func runPE(absPath string, guestArgv []string, sysroot, regFile string, trace bool, enableWayland bool) {
mem := mmu.New()
fs := vfs.New()
fs.ElfPath = absPath

fs.HostOut = func(fd int, data []byte) {
if fd == 1 {
os.Stdout.Write(data)
} else {
os.Stderr.Write(data)
}
}
fs.HostIn = func(fd int, buf []byte) int {
n, _ := os.Stdin.Read(buf)
return n
}

// Populate VFS with basic Windows directory structure
fs.MkdirAll("/Windows/System32")
fs.MkdirAll("/Windows/TEMP")
fs.MkdirAll("/Users/user/AppData/Local/Temp")
fs.MkdirAll("/Program Files")

// Populate VFS with the PE's directory contents
peDir := filepath.Dir(absPath)
peDirBase := filepath.Base(peDir)
populateVFSFromHost(fs, peDir, "/"+peDirBase)

// Load the main PE
result, err := loader.LoadPE(absPath, mem, guestArgv, nil)
if err != nil {
fmt.Fprintf(os.Stderr, "govm: PE load error: %v\n", err)
os.Exit(1)
}

// Create NT subsystem components
handles := ntapi.NewHandleTable()
registry := ntapi.NewRegistryHive()

// Load registry from file if specified
if regFile != "" {
if err := registry.Load(regFile); err != nil {
fmt.Fprintf(os.Stderr, "govm: warning: failed to load registry: %v\n", err)
}
}

// Generate synthetic ntdll.dll and win32u.dll
synthNtdll := ntapi.GenerateNtdll(mem)
ntapi.PatchCRTFunctions(synthNtdll, mem)
synthWin32u := ntapi.GenerateWin32u(mem)

// Map KUSER_SHARED_DATA at 0x7FFE0000 (required by Wine DLLs)
// Wine's ntdll syscall stubs check byte at +0x308 to decide syscall vs indirect.
// We keep it 0 so stubs use real syscall instruction (which our CPU intercepts).
kuserAddr := uint64(0x7FFE0000)
kuserSize := uint64(0x1000)
mem.Mmap(kuserAddr, kuserSize, mmu.PermRead|mmu.PermWrite)
// NtMajorVersion (+0x026C) = 10, NtMinorVersion (+0x0270) = 0
mem.Write32(kuserAddr+0x026C, 10)
mem.Write32(kuserAddr+0x0270, 0)
// NtBuildNumber (+0x0260) = 19041 (Windows 10 2004)
mem.Write32(kuserAddr+0x0260, 19041)
// SystemCall byte at +0x0308 = 0 (use syscall instruction, not indirect)
mem.Write8(kuserAddr+0x0308, 0)

// Map the gap between stack top (0x7FFD0000) and KUSER_SHARED_DATA (0x7FFE0000).
// Some DLLs (kernelbase) access memory in this range.
gapAddr := uint64(0x7FFD0000)
gapSize := kuserAddr - gapAddr
mem.MapRange(gapAddr, gapSize, mmu.PermRead|mmu.PermWrite)

// Build module list for PEB_LDR_DATA
modules := []ntapi.ModuleInfo{
{
Name:      filepath.Base(absPath),
FullPath:  ntapi.VFSToNtPath("/" + filepath.Base(absPath)),
BaseAddr:  result.MainModule.BaseAddr,
ImageSize: result.MainModule.ImageSize,
Entry:     result.MainModule.EntryPoint,
},
{
Name:      "ntdll.dll",
FullPath:  `C:\Windows\System32\ntdll.dll`,
BaseAddr:  synthNtdll.BaseAddr,
ImageSize: synthNtdll.ImageSize,
Entry:     synthNtdll.BaseAddr,
},
{
Name:      "win32u.dll",
FullPath:  `C:\Windows\System32\win32u.dll`,
BaseAddr:  synthWin32u.BaseAddr,
ImageSize: synthWin32u.ImageSize,
Entry:     synthWin32u.BaseAddr,
},
}

// Load BYODLL from sysroot
loadedModules := make(map[string]*loader.PEModule)
loadedModules["ntdll.dll"] = ntapi.SynthToModule(synthNtdll)
loadedModules["win32u.dll"] = ntapi.SynthToModule(synthWin32u)

var dllLoadOrder []*loader.PEModule
if sysroot != "" {
modules, loadedModules, dllLoadOrder = loadBYODLLs(mem, sysroot, result.MainModule, modules, loadedModules)
// Pre-initialize ucrtbase's internal debug channel table to prevent
// infinite recursion in __wine_dbg_get_channel_flags. The function at
// ucrtbase+0x3d680 checks a table of 48-byte entries in .bss; entry 17
// is the "default" channel. If its flags DWORD is 0, the function calls
// itself recursively for entry 17, creating infinite recursion.
if ucrt, ok := loadedModules["ucrtbase.dll"]; ok {
	const (
		channelTableRVA = 0xba5a0 // ucrtbase .bss: debug channel table base
		entrySize       = 48      // each channel entry is 48 bytes
		defaultChannel  = 17      // the "default" channel index
		numChannels     = 48      // approximate number of channels
	)
	for i := 0; i < numChannels; i++ {
		entryAddr := ucrt.BaseAddr + channelTableRVA + uint64(i)*entrySize
		mem.Write32(entryAddr, 0x80)            // flags = 0x80 (initialized, no debug output)
		mem.Write64(entryAddr+8, 0)             // CS.DebugInfo = NULL
		mem.Write32(entryAddr+16, 0xFFFFFFFF)   // CS.LockCount = -1 (unlocked)
		mem.Write32(entryAddr+20, 0)            // CS.RecursionCount = 0
	}
	if trace {
		ravelog.Logf("[pe] initialized ucrtbase debug channel table (%d entries)\n", numChannels)
	}
}
}

// Auto-generate synthetic stub DLLs for any unresolved import DLLs
autoSynthDLLs := autoSynthUnresolved(mem, result.MainModule, loadedModules)
for _, synth := range autoSynthDLLs {
	dllKey := strings.ToLower(synth.Name)
	loadedModules[dllKey] = ntapi.SynthToModule(synth)
	modules = append(modules, ntapi.ModuleInfo{
		Name:      synth.Name,
		FullPath:  `C:\Windows\System32\` + synth.Name,
		BaseAddr:  synth.BaseAddr,
		ImageSize: synth.ImageSize,
		Entry:     synth.BaseAddr,
	})
}

// Resolve imports for the main module
loader.ResolveImports(mem, result.MainModule, loadedModules)

// Parse .pdata exception table for SEH dispatch
var exceptionTable *ntapi.ExceptionTable
if result.MainModule.ExceptionDirRVA != 0 {
	exceptionTable = ntapi.ParseExceptionDirectory(mem,
		result.MainModule.BaseAddr,
		result.MainModule.ExceptionDirRVA,
		result.MainModule.ExceptionDirSize)
}

// Patch CRT data exports (variables like _acmdln, _commode, etc.)
patchCRTDataExports(mem, result.MainModule, guestArgv)

// Build command line
cmdLine := strings.Join(guestArgv, " ")

// Stack layout - below KUSER_SHARED_DATA (0x7FFE0000)
stackTop := uint64(0x7FFD0000)
stackSize := uint64(64 * 1024 * 1024)

// Initialize PEB/TEB
procState, err := ntapi.InitProcess(mem, &ntapi.ProcessInit{
ImageBase:   result.MainModule.BaseAddr,
ImageSize:   result.MainModule.ImageSize,
EntryPoint:  result.MainModule.EntryPoint,
CommandLine: cmdLine,
ImagePath:   `C:\` + filepath.Base(absPath),
CurrentDir:  `C:\`,
Environment: []string{
"PATH=C:\\Windows\\System32;C:\\Windows",
"SYSTEMROOT=C:\\Windows",
"TEMP=C:\\Windows\\TEMP",
"TMP=C:\\Windows\\TEMP",
"OS=Windows_NT",
"PROCESSOR_ARCHITECTURE=AMD64",
"NUMBER_OF_PROCESSORS=4",
},
ProcessId:  1000,
ThreadId:   1004,
StackBase:  stackTop,
StackLimit: stackTop - stackSize,
}, modules)
if err != nil {
fmt.Fprintf(os.Stderr, "govm: PEB/TEB init error: %v\n", err)
os.Exit(1)
}

// Initialize NLS code page data in PEB before DllMain
ntapi.InitNlsData(mem, procState.PEBAddr, sysroot)

// Create the trap dispatcher
dispatcher := ntapi.NewDispatcher(mem, fs, handles, registry, procState, synthNtdll, synthWin32u)
dispatcher.SetTrace(trace)
dispatcher.SetSysRoot(sysroot)

// Register no-op stubs for any remaining unresolved ordinal imports so
// cpu-recover never needs to handle them (they just return 0 quietly).
patchUnresolvedOrdinals(mem, dispatcher, result.MainModule)

// Register auto-synth stub names with the dispatcher for trace output
for _, synth := range autoSynthDLLs {
	dispatcher.RegisterAutoStubNames(synth)
}

// Register handlers for critical CRT/Win32 functions
peBasename := filepath.Base(filepath.Dir(absPath))
winImagePath := `C:\` + peBasename + `\` + filepath.Base(absPath)
registerAutoSynthHandlers(mem, dispatcher, autoSynthDLLs, guestArgv, cmdLine, winImagePath, handles, procState, exceptionTable, result.MainModule)

// Set up Win32k subsystem
w32k := win32k.New(mem, handles)
gdi := win32k.NewGDI(mem, w32k)
w32kTrap := win32k.NewTrapDispatcher(w32k, gdi)
w32kTrap.RegisterAll(dispatcher)

// Create x64 CPU
c := x64.New(mem)
c.SetPC(result.EntryPoint)
c.SetSP(result.StackPtr)
c.SetGSBase(procState.TEBAddr) // GS points to TEB (x64 Windows convention)

// Wire up implicit TLS (__declspec(thread)) if the PE has a TLS directory.
// TEB+0x58 (ThreadLocalStoragePointer) must point to an array of per-module
// TLS data blocks, indexed by the module's TLS index.
if result.MainModule.TLSDataAddr != 0 {
	tlsSlotsArray := mem.Mmap(0, 64*8, mmu.PermRead|mmu.PermWrite) // up to 64 modules
	mem.Write64(tlsSlotsArray+0, result.MainModule.TLSDataAddr)     // slot 0 = main module
	mem.Write64(procState.TEBAddr+0x58, tlsSlotsArray)
}

// Allocate FLS data array in guest memory for inline FlsGetValue/FlsSetValue.
// This eliminates vmcall overhead for the hottest CRT path.
const flsMaxSlots = 128
flsDataArray := mem.Mmap(0, flsMaxSlots*8, mmu.PermRead|mmu.PermWrite)
mem.Write64(procState.TEBAddr+ntapi.TebFlsData, flsDataArray)

// Pre-allocate the heap region and wire to TEB for inline HeapAlloc.
const heapInlineSize = 64 * 1024 * 1024 // 64MB
heapRegion := mem.Mmap(0, heapInlineSize, mmu.PermRead|mmu.PermWrite)
mem.Write64(procState.TEBAddr+ntapi.TebHeapBase, heapRegion)
mem.Write64(procState.TEBAddr+ntapi.TebHeapOffset, 0)

// Map a zero-filled null page so that null-pointer dereferences with small
// offsets (like [rcx+0x28] with rcx=0) read/write zero instead of segfaulting.
// Many C++ vtable dispatch patterns null-check the loaded value after reading,
// and some code writes to null-derived pointers after a failed allocation.
mem.MapRange(0, 0x10000, mmu.PermRead|mmu.PermWrite) // force-map pages 0-0xFFFF

// Patch hot Win32 API stubs with inline x64 code to avoid vmcall overhead.
patchHotStubs(mem, autoSynthDLLs, flsDataArray)

if trace && exceptionTable != nil {
	ravelog.Logf("[seh] parsed %d RUNTIME_FUNCTION entries from .pdata\n", len(exceptionTable.Entries))
}

// Set up handlers
c.SetVmcallHandler(dispatcher.Handle) // NT trap handler
c.SetSyscallHandler(func(cpu arch.CPU) {
if trace {
ravelog.Logf("[pe] unexpected Linux syscall %d at RIP=0x%x\n",
cpu.SyscallNum(), cpu.GetPC())
}
cpu.SetSyscallReturn(0xC0000002) // STATUS_NOT_IMPLEMENTED
})

// Thread manager
tm := thread.NewManager(mem, dispatcher.Handle)
mainThread := tm.MainThread(c)

if trace {
ravelog.Logf("[pe] entry=0x%x sp=0x%x teb=0x%x peb=0x%x\n",
result.EntryPoint, result.StackPtr, procState.TEBAddr, procState.PEBAddr)
ravelog.Logf("[pe] ntdll=0x%x win32u=0x%x\n",
synthNtdll.BaseAddr, synthWin32u.BaseAddr)
}

// Call DllMain(DLL_PROCESS_ATTACH) for each loaded BYODLL in dependency order
if len(dllLoadOrder) > 0 {
// Register module exports for LdrGetProcedureAddress
for _, dll := range dllLoadOrder {
	dispatcher.RegisterModuleExports(dll.BaseAddr, dll.Exports, dll.ExportOrds)
}

trampoline := ntapi.AllocTrampoline(mem)
for _, dll := range dllLoadOrder {
if dll.IsDLL && dll.EntryPoint != 0 && dll.EntryPoint != dll.BaseAddr {
if err := ntapi.CallDllMain(c, mem, trampoline, dll.BaseAddr, dll.EntryPoint, trace); err != nil {
if _, isExit := err.(*arch.ExitError); isExit {
fmt.Fprintf(os.Stderr, "govm: DllMain(%s) terminated process\n", dll.Name)
os.Exit(1)
}
fmt.Fprintf(os.Stderr, "govm: warning: DllMain(%s) failed: %v\n", dll.Name, err)
}
}
}
// Restore CPU state for main entry
c.SetPC(result.EntryPoint)
c.SetSP(result.StackPtr)
ravelog.Logf("[pe] DllMain phase complete, starting main entry at 0x%x\n", result.EntryPoint)
}

// Run the PE
if err := mainThread.CPU.Run(); err != nil {
if exitErr, ok := err.(*arch.ExitError); ok {
if regFile != "" {
registry.Save(regFile)
}
pprof.StopCPUProfile()
os.Exit(exitErr.Code)
}
fmt.Fprintf(os.Stderr, "govm: PE runtime error: %v\n", err)
		// Dump registers and stack for debugging
		sp := c.GetSP()
		fmt.Fprintf(os.Stderr, "  RIP=0x%x RSP=0x%x\n", c.GetPC(), sp)
		regNames := []string{"RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI",
			"R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"}
		for i, name := range regNames {
			fmt.Fprintf(os.Stderr, "  %s=0x%x", name, c.ReadReg(i))
			if i%4 == 3 { fmt.Fprintln(os.Stderr) }
		}
		fmt.Fprintln(os.Stderr)
		for i := 0; i < 16; i++ {
			val, _ := mem.Read64(sp + uint64(i*8))
			fmt.Fprintf(os.Stderr, "  [RSP+0x%02x] = 0x%x\n", i*8, val)
		}
if regFile != "" {
registry.Save(regFile)
}
pprof.StopCPUProfile()
os.Exit(1)
}

if regFile != "" {
registry.Save(regFile)
}

tm.Wait()
}

// registerAutoSynthHandlers registers vmcall handlers for critical
// CRT and Win32 functions in auto-generated synthetic DLLs.
func registerAutoSynthHandlers(mem *mmu.MMU, d *ntapi.Dispatcher, dlls []*ntapi.SynthPE, argv []string, cmdLine, imagePath string, handles *ntapi.HandleTable, procState *ntapi.ProcessState, exceptionTable *ntapi.ExceptionTable, mainModule *loader.PEModule) {
	synthByName := make(map[string]*ntapi.SynthPE)
	for _, s := range dlls {
		synthByName[strings.ToLower(s.Name)] = s
	}

	// delayHandlerRegistrars: re-runnable closures that register handlers for each DLL.
	// After delay-load synthesizes a new DLL, we re-run all registrars so the
	// new DLL's handlers get registered.
	var delayHandlerRegistrars []func()

	// Wayland connection for window display (used by user32 handlers below)
	var wlDisplay *wl.Display
	var wlWindow *wl.Window
	var mainHWND uint64   // first top-level window HWND (for message routing)
	var mainTitle string  // title of the main window
	_ = mainTitle
	if wld, err := wl.Connect(); err == nil {
		wlDisplay = wld
		ravelog.Logf("[wl] connected to Wayland compositor\n")
	} else {
		ravelog.Logf("[wl] no Wayland: %v (window display disabled)\n", err)
	}

	readGuestUTF16 := func(addr uint64) string {
		if addr == 0 {
			return ""
		}
		var chars []uint16
		for i := 0; i < 1024; i++ {
			w, err := mem.Read16(addr)
			if err != nil || w == 0 {
				break
			}
			chars = append(chars, w)
			addr += 2
		}
		return string(utf16Decode(chars))
	}
	readGuestString := func(addr uint64) string {
		if addr == 0 {
			return ""
		}
		var out []byte
		for i := 0; i < 1024; i++ {
			b, err := mem.Read8(addr)
			if err != nil || b == 0 {
				break
			}
			out = append(out, b)
			addr++
		}
		return string(out)
	}

	// Menu data structures
	const menuBarHeight int32 = 20
	type menuItem struct {
		flags   uint32
		id      uint64
		text    string
		submenu []menuItem // for popup items (MF_POPUP)
	}
	type menuData struct {
		items []menuItem
	}

	// pickBestLangEntry selects the best language entry from a resource language directory.
	// Prefers: English (0x0409, 0x0809, etc.) or neutral (0x0000), else last resort = first entry.
	pickBestLangEntry := func(langDirAddr, rsrcBase uint64) (dataEntryAddr uint64, ok bool) {
		namedCount, _ := mem.Read16(langDirAddr + 12)
		idCount, _ := mem.Read16(langDirAddr + 14)
		total := int(namedCount) + int(idCount)
		if total == 0 {
			return 0, false
		}
		entryBase := langDirAddr + 16
		var fallback uint64
		for i := 0; i < total; i++ {
			langID, _ := mem.Read32(entryBase + uint64(i)*8)
			eOff, _ := mem.Read32(entryBase + uint64(i)*8 + 4)
			addr := rsrcBase + uint64(eOff&0x7FFFFFFF)
			if i == 0 {
				fallback = addr
			}
			if langID == 0x0000 || langID&0xFF == 0x09 { // neutral or English
				return addr, true
			}
		}
		return fallback, true
	}

	// peLoadStringW loads a string from the PE resource section.
	// RT_STRING resources are grouped in blocks of 16 strings.
	// Block ID = (uID / 16) + 1, index within block = uID % 16.
	// Each entry in a block is: WORD length, WCHAR[length].
	peLoadStringW := func(uID uint32) (string, uint64, int) {
		if mainModule == nil || mainModule.ResourceDirRVA == 0 {
			return "", 0, 0
		}
		rsrcBase := mainModule.BaseAddr + uint64(mainModule.ResourceDirRVA)

		// Navigate resource directory: Type (RT_STRING=6) → Block ID → Language
		// IMAGE_RESOURCE_DIRECTORY: Characteristics(4) + TimeDateStamp(4) + MajorVersion(2) +
		//   MinorVersion(2) + NumberOfNamedEntries(2) + NumberOfIdEntries(2) = 16 bytes
		// IMAGE_RESOURCE_DIRECTORY_ENTRY: Name/ID(4) + OffsetToData(4) = 8 bytes

		readDir := func(addr uint64) (numNamed, numID uint16) {
			nn, _ := mem.Read16(addr + 12)
			ni, _ := mem.Read16(addr + 14)
			return nn, ni
		}

		findEntry := func(dirAddr uint64, id uint32) (uint64, bool) {
			numNamed, numID := readDir(dirAddr)
			total := int(numNamed) + int(numID)
			entryAddr := dirAddr + 16
			for i := 0; i < total; i++ {
				eid, _ := mem.Read32(entryAddr)
				off, _ := mem.Read32(entryAddr + 4)
				if eid == id {
					if off&0x80000000 != 0 {
						return rsrcBase + uint64(off&0x7FFFFFFF), true
					}
					return rsrcBase + uint64(off), true
				}
				entryAddr += 8
			}
			return 0, false
		}

		// Find RT_STRING (type 6)
		typeDir, ok := findEntry(rsrcBase, 6)
		if !ok {
			return "", 0, 0
		}
		// Find block (uID/16 + 1)
		blockID := uID/16 + 1
		blockDir, ok := findEntry(typeDir, blockID)
		if !ok {
			return "", 0, 0
		}
		// Pick best language (prefer English/neutral over Arabic etc.)
		leafAddr, ok := pickBestLangEntry(blockDir, rsrcBase)
		if !ok {
			return "", 0, 0
		}
		// IMAGE_RESOURCE_DATA_ENTRY: OffsetToData(4) + Size(4) + CodePage(4) + Reserved(4)
		dataRVA, _ := mem.Read32(leafAddr)
		dataAddr := mainModule.BaseAddr + uint64(dataRVA)

		// Parse string table: 16 entries, each is WORD length + WCHAR[length]
		idx := uID % 16
		pos := dataAddr
		for i := uint32(0); i <= idx; i++ {
			slen, _ := mem.Read16(pos)
			pos += 2
			if i == idx {
				if slen == 0 {
					return "", 0, 0
				}
				chars := make([]uint16, slen)
				for j := uint16(0); j < slen; j++ {
					chars[j], _ = mem.Read16(pos + uint64(j)*2)
				}
				return string(utf16Decode(chars)), pos, int(slen)
			}
			pos += uint64(slen) * 2
		}
		return "", 0, 0
	}

	// peLoadMenuResource loads a menu resource (RT_MENU=4) from the PE.
	// Returns a menuData with the top-level popup items (for the menu bar).
	peLoadMenuResource := func(menuID uint32) *menuData {
		if mainModule == nil || mainModule.ResourceDirRVA == 0 {
			return nil
		}
		rsrcBase := mainModule.BaseAddr + uint64(mainModule.ResourceDirRVA)

		// Helper to parse IMAGE_RESOURCE_DIRECTORY and find an entry by ID
		findEntry := func(dirAddr uint64, id uint32) (uint64, bool) {
			namedCount, _ := mem.Read16(dirAddr + 12)
			idCount, _ := mem.Read16(dirAddr + 14)
			entryAddr := dirAddr + 16 + uint64(namedCount)*8
			for i := uint16(0); i < idCount; i++ {
				eID, _ := mem.Read32(entryAddr)
				eOff, _ := mem.Read32(entryAddr + 4)
				if eID == id {
					isDir := eOff&0x80000000 != 0
					offset := eOff & 0x7FFFFFFF
					if isDir {
						return rsrcBase + uint64(offset), true
					}
					return rsrcBase + uint64(offset), false
				}
				entryAddr += 8
			}
			return 0, false
		}

		// Navigate: Type(4=MENU) → ID(menuID) → first language
		typeDir, isDir := findEntry(rsrcBase, 4) // RT_MENU
		if !isDir || typeDir == 0 {
			return nil
		}
		idDir, isDir2 := findEntry(typeDir, menuID)
		if idDir == 0 {
			return nil
		}
		// Pick best language (prefer English/neutral)
		var dataEntryAddr uint64
		if isDir2 {
			addr, ok := pickBestLangEntry(idDir, rsrcBase)
			if !ok {
				return nil
			}
			dataEntryAddr = addr
		} else {
			dataEntryAddr = idDir
		}

		// Read IMAGE_RESOURCE_DATA_ENTRY
		dataRVA, _ := mem.Read32(dataEntryAddr)
		dataSize, _ := mem.Read32(dataEntryAddr + 4)
		if dataRVA == 0 || dataSize == 0 {
			return nil
		}
		dataAddr := mainModule.BaseAddr + uint64(dataRVA)

		// Parse menu template
		// Standard menu: WORD version (0), WORD header_offset, then items
		ver, _ := mem.Read16(dataAddr)
		hdrOff, _ := mem.Read16(dataAddr + 2)
		if ver != 0 {
			return nil // Only support standard (non-extended) menus
		}

		md := &menuData{}
		pos := dataAddr + 4 + uint64(hdrOff)
		end := dataAddr + uint64(dataSize)

		// Parse top-level items (recurse into popups)
		var parseItems func(maxItems int) []menuItem
		parseItems = func(maxItems int) []menuItem {
			var items []menuItem
			for len(items) < maxItems && pos < end {
				flags, _ := mem.Read16(pos)
				pos += 2

				item := menuItem{flags: uint32(flags)}
				const mfPopup = 0x0010
				if flags&mfPopup == 0 {
					// Regular item: has a 16-bit ID
					id, _ := mem.Read16(pos)
					pos += 2
					item.id = uint64(id)
				}
				// Read null-terminated UTF-16 string
				var chars []uint16
				for pos < end {
					ch, _ := mem.Read16(pos)
					pos += 2
					if ch == 0 {
						break
					}
					chars = append(chars, ch)
				}
				item.text = string(utf16Decode(chars))

				if flags&mfPopup != 0 {
					// Popup: recursively parse child items
					item.submenu = parseItems(64)
				}

				items = append(items, item)
				if flags&0x0080 != 0 { // MF_END
					break
				}
			}
			return items
		}

		md.items = parseItems(32)
		return md
	}

	// wideprintf formats a wide format string with arguments read from guest memory.
	// args are the uint64 values to substitute (already read from registers/stack).
	wideprintf := func(format string, args []uint64) string {
		var result []rune
		argIdx := 0
		nextArg := func() int64 {
			if argIdx < len(args) {
				v := args[argIdx]
				argIdx++
				return int64(v)
			}
			return 0
		}
		nextPtr := func() uint64 {
			if argIdx < len(args) {
				v := args[argIdx]
				argIdx++
				return v
			}
			return 0
		}

		i := 0
		for i < len(format) {
			if format[i] != '%' {
				result = append(result, rune(format[i]))
				i++
				continue
			}
			i++ // skip '%'
			if i >= len(format) {
				break
			}
			// Flags
			for i < len(format) && (format[i] == '-' || format[i] == '+' || format[i] == '0' || format[i] == ' ' || format[i] == '#') {
				i++
			}
			// Width
			for i < len(format) && format[i] >= '0' && format[i] <= '9' {
				i++
			}
			// Precision
			if i < len(format) && format[i] == '.' {
				i++
				for i < len(format) && format[i] >= '0' && format[i] <= '9' {
					i++
				}
			}
			// Length modifier
			if i < len(format) && format[i] == 'l' {
				i++
				if i < len(format) && format[i] == 'l' {
					i++
				}
			} else if i < len(format) && format[i] == 'h' {
				i++
			} else if i < len(format) && format[i] == 'I' {
				i++
				if i+1 < len(format) && format[i] == '6' && format[i+1] == '4' {
					i += 2
				}
			}
			if i >= len(format) {
				break
			}
			switch format[i] {
			case 'd', 'i':
				v := nextArg()
				for _, r := range fmt.Sprintf("%d", int32(v)) {
					result = append(result, r)
				}
			case 'u':
				v := nextArg()
				for _, r := range fmt.Sprintf("%d", uint32(v)) {
					result = append(result, r)
				}
			case 'x':
				v := nextArg()
				for _, r := range fmt.Sprintf("%x", uint32(v)) {
					result = append(result, r)
				}
			case 'X':
				v := nextArg()
				for _, r := range fmt.Sprintf("%X", uint32(v)) {
					result = append(result, r)
				}
			case 's':
				p := nextPtr()
				for _, r := range readGuestUTF16(p) {
					result = append(result, r)
				}
			case 'c':
				v := nextArg()
				result = append(result, rune(v))
			case '%':
				result = append(result, '%')
			default:
				result = append(result, '%', rune(format[i]))
			}
			i++
		}
		return string(result)
	}

	// --- GDI rendering state ---
	type dcState struct {
		textColor uint32 // COLORREF
		bkColor   uint32
		bkMode    int32 // 1=TRANSPARENT, 2=OPAQUE
		curBrush  uint64
		isScreen bool  // true = renders to Wayland surface; false = memory/offscreen DC
		originX  int32 // client-area origin in window coordinates (ReactOS: GreSetDCOrg)
		originY  int32
	}
	dcMap := make(map[uint64]*dcState)
	brushColors := make(map[uint64]uint32) // brush handle → COLORREF

	// Windows 10 system colors (COLORREF = 0x00BBGGRR)
	sysColors := [31]uint32{
		0x00C8C8C8, // 0  COLOR_SCROLLBAR
		0x00A56E3A, // 1  COLOR_BACKGROUND/DESKTOP
		0x00B99D7F, // 2  COLOR_ACTIVECAPTION
		0x00D4D0C8, // 3  COLOR_INACTIVECAPTION
		0x00F0F0F0, // 4  COLOR_MENU
		0x00FFFFFF, // 5  COLOR_WINDOW
		0x00646464, // 6  COLOR_WINDOWFRAME
		0x00000000, // 7  COLOR_MENUTEXT
		0x00000000, // 8  COLOR_WINDOWTEXT
		0x00FFFFFF, // 9  COLOR_CAPTIONTEXT
		0x00D4D0C8, // 10 COLOR_ACTIVEBORDER
		0x00D4D0C8, // 11 COLOR_INACTIVEBORDER
		0x00808080, // 12 COLOR_APPWORKSPACE
		0x00D77800, // 13 COLOR_HIGHLIGHT
		0x00FFFFFF, // 14 COLOR_HIGHLIGHTTEXT
		0x00F0F0F0, // 15 COLOR_BTNFACE / 3DFACE
		0x00A0A0A0, // 16 COLOR_BTNSHADOW
		0x006D6D6D, // 17 COLOR_GRAYTEXT
		0x00000000, // 18 COLOR_BTNTEXT
		0x00D4D0C8, // 19 COLOR_INACTIVECAPTIONTEXT
		0x00FFFFFF, // 20 COLOR_BTNHIGHLIGHT
		0x00696969, // 21 COLOR_3DDKSHADOW
		0x00E3E3E3, // 22 COLOR_3DLIGHT
		0x00000000, // 23 COLOR_INFOTEXT
		0x00E1FFFF, // 24 COLOR_INFOBK
		0x00000000, // 25 (reserved)
		0x00CC6600, // 26 COLOR_HOTLIGHT
		0x00D77800, // 27 COLOR_GRADIENTACTIVECAPTION
		0x00DBD1C9, // 28 COLOR_GRADIENTINACTIVECAPTION
		0x00D77800, // 29 COLOR_MENUHILIGHT
		0x00F0F0F0, // 30 COLOR_MENUBAR
	}

	screenDC := func() *dcState {
		return &dcState{
			textColor: 0x000000,
			bkColor:   0xFFFFFF,
			bkMode:    2, // OPAQUE
			isScreen:  true,
		}
	}

	getDC := func(h uint64) *dcState {
		if dc, ok := dcMap[h]; ok {
			return dc
		}
		dc := screenDC()
		dcMap[h] = dc
		return dc
	}

	getSysColor := func(idx uint32) uint32 {
		if int(idx) < len(sysColors) {
			return sysColors[idx]
		}
		return 0x00C0C0C0
	}

	// --- msvcrt.dll ---
	if msvcrt, ok := synthByName["msvcrt.dll"]; ok {
		// _initterm: void _initterm(void (**begin)(void), void (**end)(void))
		// No-op - CRT global constructors are skipped in the emulator.
		d.RegisterAutoStubHandler(msvcrt, "_initterm", func(ctx *ntapi.TrapContext) uint32 {
			return 0
		})

		// __getmainargs: int __getmainargs(int *_Argc, char ***_Argv, char ***_Env, int _DoWildCard, _startupinfo *_StartInfo)
		d.RegisterAutoStubHandler(msvcrt, "__getmainargs", func(ctx *ntapi.TrapContext) uint32 {
			pArgc := ctx.Arg(0)
			pArgv := ctx.Arg(1)
			pEnv := ctx.Arg(2)

			// Allocate argv array in guest memory
			argc := len(argv)
			// argv needs: (argc+1) pointers + string data
			totalStrLen := 0
			for _, a := range argv {
				totalStrLen += len(a) + 1
			}
			argvBuf := mem.Mmap(0, uint64(8*(argc+1)+totalStrLen+64), mmu.PermRead|mmu.PermWrite)
			strOff := argvBuf + uint64(8*(argc+1))
			for i, a := range argv {
				mem.Write64(argvBuf+uint64(i*8), strOff)
				mem.WriteBytes(strOff, append([]byte(a), 0))
				strOff += uint64(len(a) + 1)
			}
			mem.Write64(argvBuf+uint64(argc*8), 0) // null terminator

			// Write results
			mem.Write32(pArgc, uint32(argc))
			mem.Write64(pArgv, argvBuf)

			// Empty environment
			envBuf := mem.Mmap(0, 4096, mmu.PermRead|mmu.PermWrite)
			mem.Write64(envBuf, 0) // null-terminated env array
			mem.Write64(pEnv, envBuf)

			return 0
		})

		// __set_app_type, __setusermatherr, __lconv_init: no-ops
		for _, name := range []string{"__set_app_type", "__setusermatherr", "__lconv_init", "_lock", "_unlock", "signal"} {
			d.RegisterAutoStubHandler(msvcrt, name, func(ctx *ntapi.TrapContext) uint32 {
				return 0
			})
		}

		// __C_specific_handler: SEH - return ExceptionContinueSearch (1)
		d.RegisterAutoStubHandler(msvcrt, "__C_specific_handler", func(ctx *ntapi.TrapContext) uint32 {
			return 1
		})

		// ___lc_codepage_func: returns pointer to int (code page)
		d.RegisterAutoStubHandler(msvcrt, "___lc_codepage_func", func(ctx *ntapi.TrapContext) uint32 {
			buf := mem.Mmap(0, 4096, mmu.PermRead|mmu.PermWrite)
			mem.Write32(buf, 65001) // UTF-8
			ctx.SetReturn(buf)
			return 0 // return value is in RAX, overridden above
		})

		// ___mb_cur_max_func: returns pointer to int (__mb_cur_max)
		d.RegisterAutoStubHandler(msvcrt, "___mb_cur_max_func", func(ctx *ntapi.TrapContext) uint32 {
			buf := mem.Mmap(0, 4096, mmu.PermRead|mmu.PermWrite)
			mem.Write32(buf, 1)
			ctx.SetReturn(buf)
			return 0
		})

		// __iob_func: returns pointer to FILE[3] (stdin, stdout, stderr)
		iobBuf := mem.Mmap(0, 4096, mmu.PermRead|mmu.PermWrite)
		d.RegisterAutoStubHandler(msvcrt, "__iob_func", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(iobBuf)
			return 0
		})

		// malloc / calloc / free / _onexit / _cexit / _amsg_exit / abort / exit
		d.RegisterAutoStubHandler(msvcrt, "malloc", func(ctx *ntapi.TrapContext) uint32 {
			size := ctx.Arg(0)
			if size == 0 {
				size = 1
			}
			buf := mem.Mmap(0, size, mmu.PermRead|mmu.PermWrite)
			ctx.SetReturn(buf)
			return 0
		})
		d.RegisterAutoStubHandler(msvcrt, "calloc", func(ctx *ntapi.TrapContext) uint32 {
			count := ctx.Arg(0)
			size := ctx.Arg(1)
			total := count * size
			if total == 0 {
				total = 1
			}
			buf := mem.Mmap(0, total, mmu.PermRead|mmu.PermWrite)
			ctx.SetReturn(buf)
			return 0
		})
		d.RegisterAutoStubHandler(msvcrt, "free", func(ctx *ntapi.TrapContext) uint32 {
			return 0 // no-op (leak)
		})

		// String functions that are safer to implement in Go
		d.RegisterAutoStubHandler(msvcrt, "strlen", func(ctx *ntapi.TrapContext) uint32 {
			s := ctx.Arg(0)
			n := uint64(0)
			for {
				b, err := ctx.Mem.Read8(s + n)
				if err != nil || b == 0 {
					break
				}
				n++
			}
			ctx.SetReturn(n)
			return 0
		})

		d.RegisterAutoStubHandler(msvcrt, "memcpy", func(ctx *ntapi.TrapContext) uint32 {
			dst := ctx.Arg(0)
			src := ctx.Arg(1)
			n := ctx.Arg(2)
			for i := uint64(0); i < n; i++ {
				b, _ := ctx.Mem.Read8(src + i)
				ctx.Mem.Write8(dst+i, b)
			}
			ctx.SetReturn(dst)
			return 0
		})

		d.RegisterAutoStubHandler(msvcrt, "memset", func(ctx *ntapi.TrapContext) uint32 {
			dst := ctx.Arg(0)
			val := byte(ctx.Arg(1))
			n := ctx.Arg(2)
			for i := uint64(0); i < n; i++ {
				ctx.Mem.Write8(dst+i, val)
			}
			ctx.SetReturn(dst)
			return 0
		})

		d.RegisterAutoStubHandler(msvcrt, "memcmp", func(ctx *ntapi.TrapContext) uint32 {
			s1 := ctx.Arg(0)
			s2 := ctx.Arg(1)
			n := ctx.Arg(2)
			for i := uint64(0); i < n; i++ {
				b1, _ := ctx.Mem.Read8(s1 + i)
				b2, _ := ctx.Mem.Read8(s2 + i)
				if b1 < b2 {
					ctx.SetReturn(^uint64(0)) // -1
					return 0
				}
				if b1 > b2 {
					ctx.SetReturn(1)
					return 0
				}
			}
			ctx.SetReturn(0)
			return 0
		})

		d.RegisterAutoStubHandler(msvcrt, "exit", func(ctx *ntapi.TrapContext) uint32 {
			ctx.CPU.Stop()
			return 0
		})
		d.RegisterAutoStubHandler(msvcrt, "abort", func(ctx *ntapi.TrapContext) uint32 {
			ctx.CPU.Stop()
			return 0
		})
		d.RegisterAutoStubHandler(msvcrt, "_cexit", func(ctx *ntapi.TrapContext) uint32 {
			return 0
		})
		d.RegisterAutoStubHandler(msvcrt, "_amsg_exit", func(ctx *ntapi.TrapContext) uint32 {
			ctx.CPU.Stop()
			return 0
		})
		d.RegisterAutoStubHandler(msvcrt, "_onexit", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(ctx.Arg(0))
			return 0
		})
		d.RegisterAutoStubHandler(msvcrt, "_errno", func(ctx *ntapi.TrapContext) uint32 {
			buf := mem.Mmap(0, 4096, mmu.PermRead|mmu.PermWrite)
			ctx.SetReturn(buf)
			return 0
		})

		// strncpy: char* strncpy(char *dst, const char *src, size_t n)
		d.RegisterAutoStubHandler(msvcrt, "strncpy", func(ctx *ntapi.TrapContext) uint32 {
			dst := ctx.Arg(0)
			src := ctx.Arg(1)
			n := ctx.Arg(2)
			i := uint64(0)
			for ; i < n; i++ {
				b, _ := ctx.Mem.Read8(src + i)
				ctx.Mem.Write8(dst+i, b)
				if b == 0 {
					i++
					break
				}
			}
			for ; i < n; i++ {
				ctx.Mem.Write8(dst+i, 0)
			}
			ctx.SetReturn(dst)
			return 0
		})

		// strncat: char* strncat(char *dst, const char *src, size_t n)
		d.RegisterAutoStubHandler(msvcrt, "strncat", func(ctx *ntapi.TrapContext) uint32 {
			dst := ctx.Arg(0)
			src := ctx.Arg(1)
			n := ctx.Arg(2)
			// Find end of dst
			dstEnd := dst
			for {
				b, _ := ctx.Mem.Read8(dstEnd)
				if b == 0 {
					break
				}
				dstEnd++
			}
			for i := uint64(0); i < n; i++ {
				b, _ := ctx.Mem.Read8(src + i)
				if b == 0 {
					break
				}
				ctx.Mem.Write8(dstEnd+i, b)
				ctx.Mem.Write8(dstEnd+i+1, 0) // always null-terminate
			}
			ctx.SetReturn(dst)
			return 0
		})

		// strncmp: int strncmp(const char *s1, const char *s2, size_t n)
		d.RegisterAutoStubHandler(msvcrt, "strncmp", func(ctx *ntapi.TrapContext) uint32 {
			s1 := ctx.Arg(0)
			s2 := ctx.Arg(1)
			n := ctx.Arg(2)
			for i := uint64(0); i < n; i++ {
				b1, _ := ctx.Mem.Read8(s1 + i)
				b2, _ := ctx.Mem.Read8(s2 + i)
				if b1 < b2 {
					ctx.SetReturn(^uint64(0))
					return 0
				}
				if b1 > b2 {
					ctx.SetReturn(1)
					return 0
				}
				if b1 == 0 {
					break
				}
			}
			ctx.SetReturn(0)
			return 0
		})

		// strstr: char* strstr(const char *haystack, const char *needle)
		d.RegisterAutoStubHandler(msvcrt, "strstr", func(ctx *ntapi.TrapContext) uint32 {
			haystack := ctx.Arg(0)
			needle := ctx.Arg(1)
			// Get needle length
			nLen := uint64(0)
			for {
				b, _ := ctx.Mem.Read8(needle + nLen)
				if b == 0 {
					break
				}
				nLen++
			}
			if nLen == 0 {
				ctx.SetReturn(haystack)
				return 0
			}
			for i := uint64(0); ; i++ {
				b, _ := ctx.Mem.Read8(haystack + i)
				if b == 0 {
					break
				}
				match := true
				for j := uint64(0); j < nLen; j++ {
					h, _ := ctx.Mem.Read8(haystack + i + j)
					n, _ := ctx.Mem.Read8(needle + j)
					if h != n {
						match = false
						break
					}
				}
				if match {
					ctx.SetReturn(haystack + i)
					return 0
				}
			}
			ctx.SetReturn(0)
			return 0
		})

		// toupper
		d.RegisterAutoStubHandler(msvcrt, "toupper", func(ctx *ntapi.TrapContext) uint32 {
			c := ctx.Arg(0)
			if c >= 'a' && c <= 'z' {
				c -= 32
			}
			ctx.SetReturn(c)
			return 0
		})

		// fopen / fclose / fputs / fputc / fprintf / fwrite / vfprintf
		d.RegisterAutoStubHandler(msvcrt, "fopen", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // NULL - file open fails
			return 0
		})
		d.RegisterAutoStubHandler(msvcrt, "fclose", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // EOF on error, 0 on success
			return 0
		})
		d.RegisterAutoStubHandler(msvcrt, "fputs", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // success
			return 0
		})
		d.RegisterAutoStubHandler(msvcrt, "fputc", func(ctx *ntapi.TrapContext) uint32 {
			c := ctx.Arg(0)
			ctx.SetReturn(c) // returns the character written
			return 0
		})
		d.RegisterAutoStubHandler(msvcrt, "fprintf", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(msvcrt, "vfprintf", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(msvcrt, "fwrite", func(ctx *ntapi.TrapContext) uint32 {
			count := ctx.Arg(2)
			ctx.SetReturn(count) // pretend all items written
			return 0
		})

		// rand / srand
		d.RegisterAutoStubHandler(msvcrt, "rand", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(42) // deterministic
			return 0
		})
		d.RegisterAutoStubHandler(msvcrt, "srand", func(ctx *ntapi.TrapContext) uint32 {
			return 0
		})

		// getchar
		d.RegisterAutoStubHandler(msvcrt, "getchar", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(10) // newline
			return 0
		})

		// localeconv
		d.RegisterAutoStubHandler(msvcrt, "localeconv", func(ctx *ntapi.TrapContext) uint32 {
			buf := mem.Mmap(0, 4096, mmu.PermRead|mmu.PermWrite)
			// Write minimal lconv with "." as decimal point
			ctx.Mem.Write8(buf+0x100, '.')
			ctx.Mem.Write8(buf+0x101, 0)
			ctx.Mem.Write64(buf, buf+0x100) // decimal_point
			ctx.SetReturn(buf)
			return 0
		})

		// mbstowcs
		d.RegisterAutoStubHandler(msvcrt, "mbstowcs", func(ctx *ntapi.TrapContext) uint32 {
			dst := ctx.Arg(0)
			src := ctx.Arg(1)
			n := ctx.Arg(2)
			i := uint64(0)
			for ; i < n; i++ {
				b, _ := ctx.Mem.Read8(src + i)
				if dst != 0 {
					ctx.Mem.Write16(dst+i*2, uint16(b))
				}
				if b == 0 {
					break
				}
			}
			ctx.SetReturn(i)
			return 0
		})

		// wcslen
		d.RegisterAutoStubHandler(msvcrt, "wcslen", func(ctx *ntapi.TrapContext) uint32 {
			s := ctx.Arg(0)
			n := uint64(0)
			for {
				w, _ := ctx.Mem.Read16(s + n*2)
				if w == 0 {
					break
				}
				n++
			}
			ctx.SetReturn(n)
			return 0
		})

		// wcsstr
		d.RegisterAutoStubHandler(msvcrt, "wcsstr", func(ctx *ntapi.TrapContext) uint32 {
			haystack := ctx.Arg(0)
			needle := ctx.Arg(1)
			nLen := uint64(0)
			for {
				w, _ := ctx.Mem.Read16(needle + nLen*2)
				if w == 0 {
					break
				}
				nLen++
			}
			if nLen == 0 {
				ctx.SetReturn(haystack)
				return 0
			}
			for i := uint64(0); ; i++ {
				w, _ := ctx.Mem.Read16(haystack + i*2)
				if w == 0 {
					break
				}
				match := true
				for j := uint64(0); j < nLen; j++ {
					h, _ := ctx.Mem.Read16(haystack + (i+j)*2)
					n, _ := ctx.Mem.Read16(needle + j*2)
					if h != n {
						match = false
						break
					}
				}
				if match {
					ctx.SetReturn(haystack + i*2)
					return 0
				}
			}
			ctx.SetReturn(0)
			return 0
		})

		// strerror
		d.RegisterAutoStubHandler(msvcrt, "strerror", func(ctx *ntapi.TrapContext) uint32 {
			buf := mem.Mmap(0, 4096, mmu.PermRead|mmu.PermWrite)
			msg := []byte("Unknown error\x00")
			ctx.Mem.WriteBytes(buf, msg)
			ctx.SetReturn(buf)
			return 0
		})
	}

	// --- ucrtbase.dll ---
	if ucrt, ok := synthByName["ucrtbase.dll"]; ok {
		ucrtExit := func(ctx *ntapi.TrapContext) uint32 {
			code := ctx.Arg(0)
			ravelog.Logf("[win32] exit(%d)\n", code)
			if wlDisplay != nil {
				wlDisplay.Close()
			}
			os.Exit(int(code))
			return 0
		}
		d.RegisterAutoStubHandler(ucrt, "exit", ucrtExit)
		d.RegisterAutoStubHandler(ucrt, "_exit", ucrtExit)
		d.RegisterAutoStubHandler(ucrt, "_cexit", func(ctx *ntapi.TrapContext) uint32 {
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "_configure_narrow_argv", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "_initialize_narrow_environment", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "_set_app_type", func(ctx *ntapi.TrapContext) uint32 {
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "_get_initial_narrow_environment", func(ctx *ntapi.TrapContext) uint32 {
			// Return pointer to an empty environment (a NULL pointer)
			envBlock := mem.Mmap(0, 4096, mmu.PermRead|mmu.PermWrite)
			mem.Write64(envBlock, 0) // NULL terminator
			ctx.SetReturn(envBlock)
			return 0
		})
		// __p___argc: returns pointer to argc
		var argcSlot uint64
		d.RegisterAutoStubHandler(ucrt, "__p___argc", func(ctx *ntapi.TrapContext) uint32 {
			if argcSlot == 0 {
				argcSlot = mem.Mmap(0, 4096, mmu.PermRead|mmu.PermWrite)
				mem.Write32(argcSlot, uint32(len(argv)))
			}
			ctx.SetReturn(argcSlot)
			return 0
		})
		// __p___argv: returns pointer to argv (array of char*)
		var argvSlot uint64
		d.RegisterAutoStubHandler(ucrt, "__p___argv", func(ctx *ntapi.TrapContext) uint32 {
			if argvSlot == 0 {
				page := mem.Mmap(0, 4096, mmu.PermRead|mmu.PermWrite)
				// Layout: [ptr to argv array] then [argv[0], argv[1], ..., NULL] then string data
				argvArrayAddr := page + 8
				strOff := argvArrayAddr + uint64((len(argv)+1)*8)
				for i, a := range argv {
					mem.Write64(argvArrayAddr+uint64(i)*8, strOff)
					mem.WriteBytes(strOff, append([]byte(a), 0))
					strOff += uint64(len(a)) + 1
				}
				mem.Write64(argvArrayAddr+uint64(len(argv))*8, 0) // NULL terminator
				mem.Write64(page, argvArrayAddr)
				argvSlot = page
			}
			ctx.SetReturn(argvSlot)
			return 0
		})

		// __stdio_common_vswprintf: wide printf with va_list
		d.RegisterAutoStubHandler(ucrt, "__stdio_common_vswprintf", func(ctx *ntapi.TrapContext) uint32 {
			buf := ctx.Arg(1)
			bufCount := ctx.Arg(2)
			fmtAddr := ctx.Arg(3)
			vaList := ctx.Arg(5)

			if fmtAddr == 0 || buf == 0 || bufCount == 0 {
				if buf != 0 && bufCount > 0 {
					mem.Write16(buf, 0)
				}
				ctx.SetReturn(0)
				return 0
			}

			fmtStr := readGuestUTF16(fmtAddr)
			// Read va_list args (each 8 bytes)
			var args []uint64
			for i := 0; i < 16; i++ {
				v, _ := mem.Read64(vaList + uint64(i)*8)
				args = append(args, v)
			}
			result := wideprintf(fmtStr, args)

			// Write result as UTF-16 to buffer
			runes := []rune(result)
			n := len(runes)
			if bufCount > 0 && uint64(n) >= bufCount {
				n = int(bufCount) - 1
			}
			for i := 0; i < n; i++ {
				mem.Write16(buf+uint64(i)*2, uint16(runes[i]))
			}
			mem.Write16(buf+uint64(n)*2, 0)
			ctx.SetReturn(uint64(n))
			return 0
		})

		// __stdio_common_vsprintf: narrow printf with va_list
		d.RegisterAutoStubHandler(ucrt, "__stdio_common_vsprintf", func(ctx *ntapi.TrapContext) uint32 {
			buf := ctx.Arg(1)
			bufCount := ctx.Arg(2)
			fmtAddr := ctx.Arg(3)
			vaList := ctx.Arg(5)

			if fmtAddr == 0 || buf == 0 || bufCount == 0 {
				if buf != 0 && bufCount > 0 {
					mem.Write8(buf, 0)
				}
				ctx.SetReturn(0)
				return 0
			}

			// Read narrow format string
			var fmtBytes []byte
			for i := 0; i < 4096; i++ {
				b, err := mem.Read8(fmtAddr + uint64(i))
				if err != nil || b == 0 {
					break
				}
				fmtBytes = append(fmtBytes, b)
			}
			fmtStr := string(fmtBytes)
			var args []uint64
			for i := 0; i < 16; i++ {
				v, _ := mem.Read64(vaList + uint64(i)*8)
				args = append(args, v)
			}
			// Reuse wideprintf for formatting (works for narrow too)
			result := wideprintf(fmtStr, args)

			n := len(result)
			if bufCount > 0 && uint64(n) >= bufCount {
				n = int(bufCount) - 1
			}
			for i := 0; i < n; i++ {
				mem.Write8(buf+uint64(i), result[i])
			}
			mem.Write8(buf+uint64(n), 0)
			ctx.SetReturn(uint64(n))
			return 0
		})

		// Wide-char CRT init stubs (same as narrow counterparts)
		d.RegisterAutoStubHandler(ucrt, "_configure_wide_argv", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "_initialize_wide_environment", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "_get_initial_wide_environment", func(ctx *ntapi.TrapContext) uint32 {
			envBlock := mem.Mmap(0, 4096, mmu.PermRead|mmu.PermWrite)
			mem.Write16(envBlock, 0) // empty wide env (double-null terminated)
			mem.Write16(envBlock+2, 0)
			ctx.SetReturn(envBlock)
			return 0
		})

		// __p___wargv: returns pointer to wide argv (WCHAR** pointer-to-pointer)
		var wargvSlot uint64
		d.RegisterAutoStubHandler(ucrt, "__p___wargv", func(ctx *ntapi.TrapContext) uint32 {
			if wargvSlot == 0 {
				page := mem.Mmap(0, 4096, mmu.PermRead|mmu.PermWrite)
				wargvArrayAddr := page + 8
				strOff := wargvArrayAddr + uint64((len(argv)+1)*8)
				for i, a := range argv {
					mem.Write64(wargvArrayAddr+uint64(i)*8, strOff)
					runes := []rune(a)
					for _, r := range runes {
						mem.Write16(strOff, uint16(r))
						strOff += 2
					}
					mem.Write16(strOff, 0) // null-terminate
					strOff += 2
				}
				mem.Write64(wargvArrayAddr+uint64(len(argv))*8, 0)
				mem.Write64(page, wargvArrayAddr)
				wargvSlot = page
			}
			ctx.SetReturn(wargvSlot)
			return 0
		})

		// wcslen: return length of wide string (in WCHARs)
		d.RegisterAutoStubHandler(ucrt, "wcslen", func(ctx *ntapi.TrapContext) uint32 {
			addr := ctx.Arg(0)
			n := uint64(0)
			for {
				w, err := mem.Read16(addr + n*2)
				if err != nil || w == 0 {
					break
				}
				n++
				if n > 0x100000 {
					break
				}
			}
			ctx.SetReturn(n)
			return 0
		})

		// strlen: return length of narrow string
		d.RegisterAutoStubHandler(ucrt, "strlen", func(ctx *ntapi.TrapContext) uint32 {
			addr := ctx.Arg(0)
			n := uint64(0)
			for {
				b, err := mem.Read8(addr + n)
				if err != nil || b == 0 {
					break
				}
				n++
				if n > 0x100000 {
					break
				}
			}
			ctx.SetReturn(n)
			return 0
		})

		// getenv: return NULL (no environment variables)
		d.RegisterAutoStubHandler(ucrt, "getenv", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // NULL = not found
			return 0
		})

		// __acrt_iob_func: returns pointer to CRT FILE* for stdin/stdout/stderr
		var crtIOBBase uint64
		d.RegisterAutoStubHandler(ucrt, "__acrt_iob_func", func(ctx *ntapi.TrapContext) uint32 {
			idx := ctx.Arg(0)
			if crtIOBBase == 0 {
				// Allocate fake FILE structs (each 0x30 bytes = 48, typical UCRT _iobuf)
				crtIOBBase = mem.Mmap(0, 4096, mmu.PermRead|mmu.PermWrite)
			}
			ctx.SetReturn(crtIOBBase + idx*0x30)
			return 0
		})

		// fwrite: write to FILE* - for stderr/stdout we print to host, otherwise discard
		d.RegisterAutoStubHandler(ucrt, "fwrite", func(ctx *ntapi.TrapContext) uint32 {
			ptr := ctx.Arg(0)
			size := ctx.Arg(1)
			count := ctx.Arg(2)
			total := size * count
			if total > 0 && total < 0x100000 {
				buf := make([]byte, total)
				for i := uint64(0); i < total; i++ {
					b, _ := mem.Read8(ptr + i)
					buf[i] = b
				}
				os.Stderr.Write(buf)
			}
			ctx.SetReturn(count)
			return 0
		})

		// fprintf/printf: handled via __stdio_common_vsprintf at lower level, but stub direct calls
		d.RegisterAutoStubHandler(ucrt, "_set_new_mode", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "_crt_atexit", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "_register_onexit_function", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "_initialize_onexit_table", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "_register_thread_local_exe_atexit_callback", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})

		// Memory functions
		d.RegisterAutoStubHandler(ucrt, "malloc", func(ctx *ntapi.TrapContext) uint32 {
			size := ctx.Arg(0)
			if size == 0 {
				size = 1
			}
			size = (size + 15) &^ 15
			addr := mem.Mmap(0, size+16, mmu.PermRead|mmu.PermWrite)
			mem.Write64(addr, size+16) // header: block size
			ctx.SetReturn(addr + 16)
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "calloc", func(ctx *ntapi.TrapContext) uint32 {
			count := ctx.Arg(0)
			size := ctx.Arg(1)
			total := count * size
			if total == 0 {
				total = 1
			}
			total = (total + 15) &^ 15
			addr := mem.Mmap(0, total+16, mmu.PermRead|mmu.PermWrite)
			mem.Write64(addr, total+16)
			// mmap returns zeroed memory
			ctx.SetReturn(addr + 16)
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "free", func(ctx *ntapi.TrapContext) uint32 {
			// no-op for bump allocator
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "realloc", func(ctx *ntapi.TrapContext) uint32 {
			ptr := ctx.Arg(0)
			newSize := ctx.Arg(1)
			if ptr == 0 {
				// realloc(NULL, size) == malloc(size)
				if newSize == 0 {
					newSize = 1
				}
				newSize = (newSize + 15) &^ 15
				addr := mem.Mmap(0, newSize+16, mmu.PermRead|mmu.PermWrite)
				mem.Write64(addr, newSize+16)
				ctx.SetReturn(addr + 16)
				return 0
			}
			// Read old block size
			oldBlockSize, _ := mem.Read64(ptr - 16)
			oldDataSize := oldBlockSize - 16
			if newSize <= oldDataSize {
				ctx.SetReturn(ptr)
				return 0
			}
			// Allocate new block and copy
			newSize = (newSize + 15) &^ 15
			newAddr := mem.Mmap(0, newSize+16, mmu.PermRead|mmu.PermWrite)
			mem.Write64(newAddr, newSize+16)
			for i := uint64(0); i < oldDataSize; i++ {
				b, _ := mem.Read8(ptr + i)
				mem.Write8(newAddr+16+i, b)
			}
			ctx.SetReturn(newAddr + 16)
			return 0
		})

		// String functions
		d.RegisterAutoStubHandler(ucrt, "memset", func(ctx *ntapi.TrapContext) uint32 {
			dst := ctx.Arg(0)
			val := byte(ctx.Arg(1))
			count := ctx.Arg(2)
			if count > 0x1000000 {
				count = 0x1000000
			}
			buf := make([]byte, count)
			for i := range buf {
				buf[i] = val
			}
			ctx.Mem.WriteBytes(dst, buf)
			ctx.SetReturn(dst)
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "memcpy", func(ctx *ntapi.TrapContext) uint32 {
			dst := ctx.Arg(0)
			src := ctx.Arg(1)
			count := ctx.Arg(2)
			if count > 0x1000000 {
				count = 0x1000000
			}
			buf, _ := ctx.Mem.ReadBytes(src, int(count))
			ctx.Mem.WriteBytes(dst, buf)
			ctx.SetReturn(dst)
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "memmove", func(ctx *ntapi.TrapContext) uint32 {
			dst := ctx.Arg(0)
			src := ctx.Arg(1)
			count := ctx.Arg(2)
			if count > 0x1000000 {
				count = 0x1000000
			}
			buf, _ := ctx.Mem.ReadBytes(src, int(count))
			ctx.Mem.WriteBytes(dst, buf)
			ctx.SetReturn(dst)
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "memcmp", func(ctx *ntapi.TrapContext) uint32 {
			s1 := ctx.Arg(0)
			s2 := ctx.Arg(1)
			count := ctx.Arg(2)
			for i := uint64(0); i < count && i < 0x1000000; i++ {
				a, _ := mem.Read8(s1 + i)
				b, _ := mem.Read8(s2 + i)
				if a < b {
					ctx.SetReturn(^uint64(0)) // -1
					return 0
				}
				if a > b {
					ctx.SetReturn(1)
					return 0
				}
			}
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "strcpy", func(ctx *ntapi.TrapContext) uint32 {
			dst := ctx.Arg(0)
			src := ctx.Arg(1)
			i := uint64(0)
			for {
				b, _ := mem.Read8(src + i)
				mem.Write8(dst+i, b)
				if b == 0 {
					break
				}
				i++
				if i > 0x100000 {
					break
				}
			}
			ctx.SetReturn(dst)
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "strncpy", func(ctx *ntapi.TrapContext) uint32 {
			dst := ctx.Arg(0)
			src := ctx.Arg(1)
			count := ctx.Arg(2)
			i := uint64(0)
			for i < count {
				b, _ := mem.Read8(src + i)
				mem.Write8(dst+i, b)
				if b == 0 {
					// zero-fill remaining
					for i++; i < count; i++ {
						mem.Write8(dst+i, 0)
					}
					break
				}
				i++
			}
			ctx.SetReturn(dst)
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "strcmp", func(ctx *ntapi.TrapContext) uint32 {
			s1 := ctx.Arg(0)
			s2 := ctx.Arg(1)
			for i := uint64(0); i < 0x100000; i++ {
				a, _ := mem.Read8(s1 + i)
				b, _ := mem.Read8(s2 + i)
				if a < b {
					ctx.SetReturn(^uint64(0))
					return 0
				}
				if a > b {
					ctx.SetReturn(1)
					return 0
				}
				if a == 0 {
					break
				}
			}
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "wcscpy", func(ctx *ntapi.TrapContext) uint32 {
			dst := ctx.Arg(0)
			src := ctx.Arg(1)
			i := uint64(0)
			for {
				w, _ := mem.Read16(src + i*2)
				mem.Write16(dst+i*2, w)
				if w == 0 {
					break
				}
				i++
				if i > 0x100000 {
					break
				}
			}
			ctx.SetReturn(dst)
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "wcsncpy", func(ctx *ntapi.TrapContext) uint32 {
			dst := ctx.Arg(0)
			src := ctx.Arg(1)
			count := ctx.Arg(2)
			i := uint64(0)
			for i < count {
				w, _ := mem.Read16(src + i*2)
				mem.Write16(dst+i*2, w)
				if w == 0 {
					for i++; i < count; i++ {
						mem.Write16(dst+i*2, 0)
					}
					break
				}
				i++
			}
			ctx.SetReturn(dst)
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "wcscmp", func(ctx *ntapi.TrapContext) uint32 {
			s1 := ctx.Arg(0)
			s2 := ctx.Arg(1)
			for i := uint64(0); i < 0x100000; i++ {
				a, _ := mem.Read16(s1 + i*2)
				b, _ := mem.Read16(s2 + i*2)
				if a < b {
					ctx.SetReturn(^uint64(0))
					return 0
				}
				if a > b {
					ctx.SetReturn(1)
					return 0
				}
				if a == 0 {
					break
				}
			}
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "wcscat", func(ctx *ntapi.TrapContext) uint32 {
			dst := ctx.Arg(0)
			src := ctx.Arg(1)
			// Find end of dst
			end := dst
			for {
				w, _ := mem.Read16(end)
				if w == 0 {
					break
				}
				end += 2
			}
			// Copy src
			for {
				w, _ := mem.Read16(src)
				mem.Write16(end, w)
				if w == 0 {
					break
				}
				src += 2
				end += 2
			}
			ctx.SetReturn(dst)
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "wcschr", func(ctx *ntapi.TrapContext) uint32 {
			s := ctx.Arg(0)
			c := uint16(ctx.Arg(1))
			for i := uint64(0); i < 0x100000; i++ {
				w, _ := mem.Read16(s + i*2)
				if w == c {
					ctx.SetReturn(s + i*2)
					return 0
				}
				if w == 0 {
					break
				}
			}
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "wcsrchr", func(ctx *ntapi.TrapContext) uint32 {
			s := ctx.Arg(0)
			c := uint16(ctx.Arg(1))
			last := uint64(0)
			for i := uint64(0); i < 0x100000; i++ {
				w, _ := mem.Read16(s + i*2)
				if w == c {
					last = s + i*2
				}
				if w == 0 {
					break
				}
			}
			ctx.SetReturn(last)
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "_wcsicmp", func(ctx *ntapi.TrapContext) uint32 {
			s1 := ctx.Arg(0)
			s2 := ctx.Arg(1)
			toLower := func(c uint16) uint16 {
				if c >= 'A' && c <= 'Z' {
					return c + 32
				}
				return c
			}
			for i := uint64(0); i < 0x100000; i++ {
				a, _ := mem.Read16(s1 + i*2)
				b, _ := mem.Read16(s2 + i*2)
				la, lb := toLower(a), toLower(b)
				if la < lb {
					ctx.SetReturn(^uint64(0))
					return 0
				}
				if la > lb {
					ctx.SetReturn(1)
					return 0
				}
				if a == 0 {
					break
				}
			}
			ctx.SetReturn(0)
			return 0
		})

		d.RegisterAutoStubHandler(ucrt, "abort", ucrtExit)
		d.RegisterAutoStubHandler(ucrt, "terminate", func(ctx *ntapi.TrapContext) uint32 {
			ravelog.Logf("[win32] terminate() called - ignoring\n")
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "_c_exit", func(ctx *ntapi.TrapContext) uint32 {
			return 0
		})

		// Wide character classification and conversion
		d.RegisterAutoStubHandler(ucrt, "towlower", func(ctx *ntapi.TrapContext) uint32 {
			c := uint16(ctx.Arg(0))
			if c >= 'A' && c <= 'Z' {
				c += 32
			}
			ctx.SetReturn(uint64(c))
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "towupper", func(ctx *ntapi.TrapContext) uint32 {
			c := uint16(ctx.Arg(0))
			if c >= 'a' && c <= 'z' {
				c -= 32
			}
			ctx.SetReturn(uint64(c))
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "iswspace", func(ctx *ntapi.TrapContext) uint32 {
			c := uint16(ctx.Arg(0))
			if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v' {
				ctx.SetReturn(1)
			} else {
				ctx.SetReturn(0)
			}
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "iswdigit", func(ctx *ntapi.TrapContext) uint32 {
			c := uint16(ctx.Arg(0))
			if c >= '0' && c <= '9' {
				ctx.SetReturn(1)
			} else {
				ctx.SetReturn(0)
			}
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "iswalpha", func(ctx *ntapi.TrapContext) uint32 {
			c := uint16(ctx.Arg(0))
			if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
				ctx.SetReturn(1)
			} else {
				ctx.SetReturn(0)
			}
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "iswalnum", func(ctx *ntapi.TrapContext) uint32 {
			c := uint16(ctx.Arg(0))
			if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
				ctx.SetReturn(1)
			} else {
				ctx.SetReturn(0)
			}
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "iswxdigit", func(ctx *ntapi.TrapContext) uint32 {
			c := uint16(ctx.Arg(0))
			if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
				ctx.SetReturn(1)
			} else {
				ctx.SetReturn(0)
			}
			return 0
		})
		// Narrow char classification
		d.RegisterAutoStubHandler(ucrt, "isspace", func(ctx *ntapi.TrapContext) uint32 {
			c := byte(ctx.Arg(0))
			if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v' {
				ctx.SetReturn(1)
			} else {
				ctx.SetReturn(0)
			}
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "isdigit", func(ctx *ntapi.TrapContext) uint32 {
			c := byte(ctx.Arg(0))
			if c >= '0' && c <= '9' {
				ctx.SetReturn(1)
			} else {
				ctx.SetReturn(0)
			}
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "tolower", func(ctx *ntapi.TrapContext) uint32 {
			c := byte(ctx.Arg(0))
			if c >= 'A' && c <= 'Z' {
				c += 32
			}
			ctx.SetReturn(uint64(c))
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "toupper", func(ctx *ntapi.TrapContext) uint32 {
			c := byte(ctx.Arg(0))
			if c >= 'a' && c <= 'z' {
				c -= 32
			}
			ctx.SetReturn(uint64(c))
			return 0
		})

		// String search/misc
		d.RegisterAutoStubHandler(ucrt, "strcat", func(ctx *ntapi.TrapContext) uint32 {
			dst := ctx.Arg(0)
			src := ctx.Arg(1)
			end := dst
			for {
				b, _ := mem.Read8(end)
				if b == 0 {
					break
				}
				end++
			}
			for {
				b, _ := mem.Read8(src)
				mem.Write8(end, b)
				if b == 0 {
					break
				}
				src++
				end++
			}
			ctx.SetReturn(dst)
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "strstr", func(ctx *ntapi.TrapContext) uint32 {
			haystack := ctx.Arg(0)
			needle := ctx.Arg(1)
			// Read needle string
			var needleBytes []byte
			for i := uint64(0); i < 0x10000; i++ {
				b, _ := mem.Read8(needle + i)
				if b == 0 {
					break
				}
				needleBytes = append(needleBytes, b)
			}
			if len(needleBytes) == 0 {
				ctx.SetReturn(haystack)
				return 0
			}
			for i := uint64(0); i < 0x100000; i++ {
				b, _ := mem.Read8(haystack + i)
				if b == 0 {
					break
				}
				if b == needleBytes[0] {
					match := true
					for j := 1; j < len(needleBytes); j++ {
						c, _ := mem.Read8(haystack + i + uint64(j))
						if c != needleBytes[j] {
							match = false
							break
						}
					}
					if match {
						ctx.SetReturn(haystack + i)
						return 0
					}
				}
			}
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "wcsstr", func(ctx *ntapi.TrapContext) uint32 {
			haystack := ctx.Arg(0)
			needle := ctx.Arg(1)
			var needleChars []uint16
			for i := uint64(0); i < 0x10000; i++ {
				w, _ := mem.Read16(needle + i*2)
				if w == 0 {
					break
				}
				needleChars = append(needleChars, w)
			}
			if len(needleChars) == 0 {
				ctx.SetReturn(haystack)
				return 0
			}
			for i := uint64(0); i < 0x100000; i++ {
				w, _ := mem.Read16(haystack + i*2)
				if w == 0 {
					break
				}
				if w == needleChars[0] {
					match := true
					for j := 1; j < len(needleChars); j++ {
						c, _ := mem.Read16(haystack + (i+uint64(j))*2)
						if c != needleChars[j] {
							match = false
							break
						}
					}
					if match {
						ctx.SetReturn(haystack + i*2)
						return 0
					}
				}
			}
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "_stricmp", func(ctx *ntapi.TrapContext) uint32 {
			s1 := ctx.Arg(0)
			s2 := ctx.Arg(1)
			toLower := func(c byte) byte {
				if c >= 'A' && c <= 'Z' {
					return c + 32
				}
				return c
			}
			for i := uint64(0); i < 0x100000; i++ {
				a, _ := mem.Read8(s1 + i)
				b, _ := mem.Read8(s2 + i)
				la, lb := toLower(a), toLower(b)
				if la < lb {
					ctx.SetReturn(^uint64(0))
					return 0
				}
				if la > lb {
					ctx.SetReturn(1)
					return 0
				}
				if a == 0 {
					break
				}
			}
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "_wcsnicmp", func(ctx *ntapi.TrapContext) uint32 {
			s1 := ctx.Arg(0)
			s2 := ctx.Arg(1)
			count := ctx.Arg(2)
			toLower := func(c uint16) uint16 {
				if c >= 'A' && c <= 'Z' {
					return c + 32
				}
				return c
			}
			for i := uint64(0); i < count; i++ {
				a, _ := mem.Read16(s1 + i*2)
				b, _ := mem.Read16(s2 + i*2)
				la, lb := toLower(a), toLower(b)
				if la < lb {
					ctx.SetReturn(^uint64(0))
					return 0
				}
				if la > lb {
					ctx.SetReturn(1)
					return 0
				}
				if a == 0 {
					break
				}
			}
			ctx.SetReturn(0)
			return 0
		})
		// Number conversion
		d.RegisterAutoStubHandler(ucrt, "_wtoi", func(ctx *ntapi.TrapContext) uint32 {
			s := ctx.Arg(0)
			str := readGuestUTF16(s)
			val := int64(0)
			neg := false
			i := 0
			for i < len(str) && (str[i] == ' ' || str[i] == '\t') {
				i++
			}
			if i < len(str) && str[i] == '-' {
				neg = true
				i++
			} else if i < len(str) && str[i] == '+' {
				i++
			}
			for i < len(str) && str[i] >= '0' && str[i] <= '9' {
				val = val*10 + int64(str[i]-'0')
				i++
			}
			if neg {
				val = -val
			}
			ctx.SetReturn(uint64(val))
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "atoi", func(ctx *ntapi.TrapContext) uint32 {
			s := ctx.Arg(0)
			var str []byte
			for i := uint64(0); i < 32; i++ {
				b, _ := mem.Read8(s + i)
				if b == 0 {
					break
				}
				str = append(str, b)
			}
			val := int64(0)
			neg := false
			i := 0
			for i < len(str) && (str[i] == ' ' || str[i] == '\t') {
				i++
			}
			if i < len(str) && str[i] == '-' {
				neg = true
				i++
			} else if i < len(str) && str[i] == '+' {
				i++
			}
			for i < len(str) && str[i] >= '0' && str[i] <= '9' {
				val = val*10 + int64(str[i]-'0')
				i++
			}
			if neg {
				val = -val
			}
			ctx.SetReturn(uint64(val))
			return 0
		})
		// wcsncat
		d.RegisterAutoStubHandler(ucrt, "wcsncat", func(ctx *ntapi.TrapContext) uint32 {
			dst := ctx.Arg(0)
			src := ctx.Arg(1)
			count := ctx.Arg(2)
			end := dst
			for {
				w, _ := mem.Read16(end)
				if w == 0 {
					break
				}
				end += 2
			}
			for i := uint64(0); i < count; i++ {
				w, _ := mem.Read16(src + i*2)
				mem.Write16(end+i*2, w)
				if w == 0 {
					break
				}
			}
			ctx.SetReturn(dst)
			return 0
		})
		// wcsncmp
		d.RegisterAutoStubHandler(ucrt, "wcsncmp", func(ctx *ntapi.TrapContext) uint32 {
			s1 := ctx.Arg(0)
			s2 := ctx.Arg(1)
			count := ctx.Arg(2)
			for i := uint64(0); i < count; i++ {
				a, _ := mem.Read16(s1 + i*2)
				b, _ := mem.Read16(s2 + i*2)
				if a < b {
					ctx.SetReturn(^uint64(0))
					return 0
				}
				if a > b {
					ctx.SetReturn(1)
					return 0
				}
				if a == 0 {
					break
				}
			}
			ctx.SetReturn(0)
			return 0
		})
		// strchr / strrchr
		d.RegisterAutoStubHandler(ucrt, "strchr", func(ctx *ntapi.TrapContext) uint32 {
			s := ctx.Arg(0)
			c := byte(ctx.Arg(1))
			for i := uint64(0); i < 0x100000; i++ {
				b, _ := mem.Read8(s + i)
				if b == c {
					ctx.SetReturn(s + i)
					return 0
				}
				if b == 0 {
					break
				}
			}
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "strrchr", func(ctx *ntapi.TrapContext) uint32 {
			s := ctx.Arg(0)
			c := byte(ctx.Arg(1))
			last := uint64(0)
			for i := uint64(0); i < 0x100000; i++ {
				b, _ := mem.Read8(s + i)
				if b == c {
					last = s + i
				}
				if b == 0 {
					break
				}
			}
			ctx.SetReturn(last)
			return 0
		})
		// _errno: return pointer to thread-local errno
		var errnoStorage uint64
		d.RegisterAutoStubHandler(ucrt, "_errno", func(ctx *ntapi.TrapContext) uint32 {
			if errnoStorage == 0 {
				errnoStorage = mem.Mmap(0, 4096, mmu.PermRead|mmu.PermWrite)
			}
			ctx.SetReturn(errnoStorage)
			return 0
		})
		// strtol / strtoul / _strtoi64
		d.RegisterAutoStubHandler(ucrt, "strtol", func(ctx *ntapi.TrapContext) uint32 {
			nptr := ctx.Arg(0)
			endptr := ctx.Arg(1)
			base := int(ctx.Arg(2))
			// Read string
			var str []byte
			for i := uint64(0); i < 64; i++ {
				b, _ := mem.Read8(nptr + i)
				if b == 0 {
					break
				}
				str = append(str, b)
			}
			s := strings.TrimSpace(string(str))
			val, _ := strconv.ParseInt(s, base, 64)
			if endptr != 0 {
				mem.Write64(endptr, nptr+uint64(len(str)))
			}
			ctx.SetReturn(uint64(val))
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "strtoul", func(ctx *ntapi.TrapContext) uint32 {
			nptr := ctx.Arg(0)
			endptr := ctx.Arg(1)
			base := int(ctx.Arg(2))
			var str []byte
			for i := uint64(0); i < 64; i++ {
				b, _ := mem.Read8(nptr + i)
				if b == 0 {
					break
				}
				str = append(str, b)
			}
			s := strings.TrimSpace(string(str))
			val, _ := strconv.ParseUint(s, base, 64)
			if endptr != 0 {
				mem.Write64(endptr, nptr+uint64(len(str)))
			}
			ctx.SetReturn(val)
			return 0
		})
	}

	// --- kernel32.dll ---
	if kernel32, ok := synthByName["kernel32.dll"]; ok {
		d.RegisterAutoStubHandler(kernel32, "GetStdHandle", func(ctx *ntapi.TrapContext) uint32 {
			nStdHandle := ctx.Arg(0)
			switch uint32(nStdHandle) {
			case 0xFFFFFFF6: // STD_INPUT_HANDLE
				ctx.SetReturn(0x100) // fake handle
			case 0xFFFFFFF5: // STD_OUTPUT_HANDLE
				ctx.SetReturn(0x101)
			case 0xFFFFFFF4: // STD_ERROR_HANDLE
				ctx.SetReturn(0x102)
			default:
				ctx.SetReturn(^uint64(0)) // INVALID_HANDLE_VALUE
			}
			return 0
		})

		d.RegisterAutoStubHandler(kernel32, "GetLastError", func(ctx *ntapi.TrapContext) uint32 {
			v, _ := ctx.Mem.Read32(procState.TEBAddr + ntapi.TebLastErrorValue)
			ctx.SetReturn(uint64(v))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetLastError", func(ctx *ntapi.TrapContext) uint32 {
			ctx.Mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, uint32(ctx.Arg(0)))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetCurrentProcess", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(^uint64(0)) // -1 = current process pseudo-handle
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "IsDebuggerPresent", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // not being debugged
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetTickCount", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1000) // fake 1 second uptime
			return 0
		})

		d.RegisterAutoStubHandler(kernel32, "GetModuleHandleA", func(ctx *ntapi.TrapContext) uint32 {
			name := ctx.Arg(0)
			if name == 0 {
				// Read ImageBase from PEB
				imageBase, _ := ctx.Mem.Read64(ctx.State.PEBAddr + 0x10)
				ctx.SetReturn(imageBase)
			} else {
				ctx.SetReturn(0)
			}
			return 0
		})

		d.RegisterAutoStubHandler(kernel32, "GetModuleHandleW", func(ctx *ntapi.TrapContext) uint32 {
			name := ctx.Arg(0)
			if name == 0 {
				imageBase, _ := ctx.Mem.Read64(ctx.State.PEBAddr + 0x10)
				ctx.SetReturn(imageBase)
			} else {
				modName := strings.ToLower(readGuestUTF16(name))
				// Return fake handle for known DLLs
				switch modName {
				case "shell32.dll":
					ctx.SetReturn(0xDEAD0001)
				case "comctl32.dll":
					ctx.SetReturn(0xDEAD0002)
				case "user32.dll":
					ctx.SetReturn(0xDEAD0003)
				case "kernel32.dll":
					ctx.SetReturn(0xDEAD0004)
				case "gdi32.dll":
					ctx.SetReturn(0xDEAD0005)
				default:
					ctx.SetReturn(0)
				}
			}
			return 0
		})

		d.RegisterAutoStubHandler(kernel32, "GetModuleHandleExW", func(ctx *ntapi.TrapContext) uint32 {
			// dwFlags=arg0, lpModuleName=arg1, phModule=arg2
			modName := ctx.Arg(1)
			phModule := ctx.Arg(2)
			if modName == 0 {
				imageBase, _ := ctx.Mem.Read64(ctx.State.PEBAddr + 0x10)
				if phModule != 0 {
					ctx.Mem.Write64Raw(phModule, imageBase)
				}
				ctx.SetReturn(1) // TRUE
			} else {
				ctx.SetReturn(0) // FALSE
			}
			return 0
		})

		d.RegisterAutoStubHandler(kernel32, "GetStartupInfoA", func(ctx *ntapi.TrapContext) uint32 {
			// Zero-fill the STARTUPINFOA structure (68 bytes)
			addr := ctx.Arg(0)
			for i := uint64(0); i < 68; i++ {
				ctx.Mem.Write8(addr+i, 0)
			}
			ctx.Mem.Write32(addr, 68) // cb = sizeof(STARTUPINFOA)
			return 0
		})

		// VirtualProtect: pretend success
		d.RegisterAutoStubHandler(kernel32, "VirtualProtect", func(ctx *ntapi.TrapContext) uint32 {
			oldProtect := ctx.Arg(3) // lpflOldProtect
			if oldProtect != 0 {
				ctx.Mem.Write32(oldProtect, 0x40) // PAGE_EXECUTE_READWRITE
			}
			ctx.SetReturn(1) // TRUE
			return 0
		})

		// InitializeCriticalSection / DeleteCriticalSection / EnterCriticalSection / LeaveCriticalSection: no-ops
		for _, name := range []string{"InitializeCriticalSection", "DeleteCriticalSection", "EnterCriticalSection", "LeaveCriticalSection"} {
			d.RegisterAutoStubHandler(kernel32, name, func(ctx *ntapi.TrapContext) uint32 {
				return 0
			})
		}
		d.RegisterAutoStubHandler(kernel32, "InitializeCriticalSectionAndSpinCount", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE = success
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "InitializeCriticalSectionEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})

		d.RegisterAutoStubHandler(kernel32, "GetCurrentThreadId", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1000) // fake thread ID
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetCurrentProcessId", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(4000) // fake process ID
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "QueryPerformanceCounter", func(ctx *ntapi.TrapContext) uint32 {
			ptr := ctx.Arg(0)
			if ptr != 0 {
				ctx.Mem.Write64Raw(ptr, 1000000)
			}
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "QueryPerformanceFrequency", func(ctx *ntapi.TrapContext) uint32 {
			ptr := ctx.Arg(0)
			if ptr != 0 {
				ctx.Mem.Write64Raw(ptr, 10000000) // 10 MHz
			}
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "IsProcessorFeaturePresent", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // feature not present
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "LoadLibraryExW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // NULL = failed
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "LoadLibraryW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "LoadLibraryA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FreeLibrary", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetProcAddress", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // not found
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "UnhandledExceptionFilter", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // EXCEPTION_CONTINUE_SEARCH
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RtlCaptureContext", func(ctx *ntapi.TrapContext) uint32 {
			// Zero-fill the CONTEXT structure (1232 bytes on x64)
			addr := ctx.Arg(0)
			if addr != 0 {
				for i := uint64(0); i < 1232; i += 8 {
					ctx.Mem.Write64Raw(addr+i, 0)
				}
			}
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RtlLookupFunctionEntry", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // no function entry found
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RtlVirtualUnwind", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})

		d.RegisterAutoStubHandler(kernel32, "SetUnhandledExceptionFilter", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // return NULL (no previous filter)
			return 0
		})

		// TLS (Thread Local Storage) emulation
		var tlsNextSlot uint32 = 1 // start at 1, 0 reserved
		tlsValues := make(map[uint32]uint64) // slot → value
		tlsFreeSlots := make(map[uint32]bool)

		d.RegisterAutoStubHandler(kernel32, "TlsAlloc", func(ctx *ntapi.TrapContext) uint32 {
			slot := tlsNextSlot
			tlsNextSlot++
			ctx.SetReturn(uint64(slot))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "TlsGetValue", func(ctx *ntapi.TrapContext) uint32 {
			slot := uint32(ctx.Arg(0))
			ctx.SetReturn(tlsValues[slot])
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "TlsSetValue", func(ctx *ntapi.TrapContext) uint32 {
			slot := uint32(ctx.Arg(0))
			val := ctx.Arg(1)
			tlsValues[slot] = val
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "TlsFree", func(ctx *ntapi.TrapContext) uint32 {
			slot := uint32(ctx.Arg(0))
			delete(tlsValues, slot)
			tlsFreeSlots[slot] = true
			ctx.SetReturn(1) // TRUE
			return 0
		})

		// FLS (Fiber Local Storage) - FlsGetValue/FlsSetValue are patched inline,
		// FlsAlloc still traps to allocate slot indices.
		var flsNextSlot uint32 = 1
		d.RegisterAutoStubHandler(kernel32, "FlsAlloc", func(ctx *ntapi.TrapContext) uint32 {
			slot := flsNextSlot
			flsNextSlot++
			ctx.SetReturn(uint64(slot))
			return 0
		})
		// FlsGetValue/FlsSetValue: patched inline, these are fallback if not patched
		d.RegisterAutoStubHandler(kernel32, "FlsGetValue", func(ctx *ntapi.TrapContext) uint32 {
			slot := uint32(ctx.Arg(0))
			// Read from guest FLS array
			flsArr, _ := ctx.Mem.Read64(procState.TEBAddr + ntapi.TebFlsData)
			val, _ := ctx.Mem.Read64(flsArr + uint64(slot)*8)
			ctx.SetReturn(val)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FlsSetValue", func(ctx *ntapi.TrapContext) uint32 {
			slot := uint32(ctx.Arg(0))
			val := ctx.Arg(1)
			flsArr, _ := ctx.Mem.Read64(procState.TEBAddr + ntapi.TebFlsData)
			ctx.Mem.Write64(flsArr+uint64(slot)*8, val)
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FlsFree", func(ctx *ntapi.TrapContext) uint32 {
			slot := uint32(ctx.Arg(0))
			// Zero the slot in guest memory
			flsArr, _ := ctx.Mem.Read64(procState.TEBAddr + ntapi.TebFlsData)
			ctx.Mem.Write64(flsArr+uint64(slot)*8, 0)
			ctx.SetReturn(1) // TRUE
			return 0
		})

		d.RegisterAutoStubHandler(kernel32, "Sleep", func(ctx *ntapi.TrapContext) uint32 {
			return 0 // no-op
		})

		// Heap emulation - uses the same region wired to TEB for inline HeapAlloc.
		// Each allocation has a 16-byte header: [totalBlockSize:8][reserved:8][userData...]
		const heapHandle = 0xBEEF0001

		d.RegisterAutoStubHandler(kernel32, "GetProcessHeap", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(heapHandle)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "HeapCreate", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(heapHandle)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "HeapDestroy", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "HeapAlloc", func(ctx *ntapi.TrapContext) uint32 {
			// Fallback Go handler (before inline stubs are patched, and for overflow checks)
			size := ctx.Arg(2)
			if size == 0 {
				size = 1
			}
			size = (size + 15) &^ 15 // align to 16
			totalBlock := size + 16  // 16-byte header
			heapBase, _ := ctx.Mem.Read64(procState.TEBAddr + ntapi.TebHeapBase)
			heapOff, _ := ctx.Mem.Read64(procState.TEBAddr + ntapi.TebHeapOffset)
			if heapOff+totalBlock > 64*1024*1024 {
				ctx.SetReturn(0)
				return 0
			}
			addr := heapBase + heapOff
			ctx.Mem.Write64(addr, totalBlock) // header: total block size
			heapOff += totalBlock
			ctx.Mem.Write64(procState.TEBAddr+ntapi.TebHeapOffset, heapOff)
			ctx.SetReturn(addr + 16) // user pointer after header
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "HeapFree", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE (no-op for bump allocator)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "HeapReAlloc", func(ctx *ntapi.TrapContext) uint32 {
			oldPtr := ctx.Arg(2)
			newSize := ctx.Arg(3)
			if newSize == 0 {
				newSize = 1
			}
			newSize = (newSize + 15) &^ 15
			totalBlock := newSize + 16
			heapBase, _ := ctx.Mem.Read64(procState.TEBAddr + ntapi.TebHeapBase)
			heapOff, _ := ctx.Mem.Read64(procState.TEBAddr + ntapi.TebHeapOffset)
			if heapOff+totalBlock > 64*1024*1024 {
				ctx.SetReturn(0)
				return 0
			}
			newAddr := heapBase + heapOff
			ctx.Mem.Write64(newAddr, totalBlock)
			heapOff += totalBlock
			ctx.Mem.Write64(procState.TEBAddr+ntapi.TebHeapOffset, heapOff)
			// Copy old data
			if oldPtr != 0 {
				oldBlockSize, _ := ctx.Mem.Read64(oldPtr - 16)
				oldUserSize := oldBlockSize - 16
				copyLen := oldUserSize
				if newSize < copyLen {
					copyLen = newSize
				}
				for i := uint64(0); i < copyLen; i++ {
					b, _ := ctx.Mem.Read8(oldPtr + i)
					ctx.Mem.Write8(newAddr+16+i, b)
				}
			}
			ctx.SetReturn(newAddr + 16)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "HeapSize", func(ctx *ntapi.TrapContext) uint32 {
			ptr := ctx.Arg(2)
			if ptr == 0 {
				ctx.SetReturn(0xFFFFFFFFFFFFFFFF)
				return 0
			}
			totalBlock, _ := ctx.Mem.Read64(ptr - 16)
			if totalBlock >= 16 {
				ctx.SetReturn(totalBlock - 16)
			} else {
				ctx.SetReturn(0xFFFFFFFFFFFFFFFF)
			}
			return 0
		})

		d.RegisterAutoStubHandler(kernel32, "GetSystemInfo", func(ctx *ntapi.TrapContext) uint32 {
			si := ctx.Arg(0)
			// SYSTEM_INFO on x64 (48 bytes)
			for i := uint64(0); i < 48; i++ {
				ctx.Mem.Write8(si+i, 0)
			}
			ctx.Mem.Write16(si+0, 9)                      // wProcessorArchitecture = AMD64
			ctx.Mem.Write32(si+4, 4096)                    // dwPageSize
			ctx.Mem.Write64(si+8, 0x10000)                 // lpMinimumApplicationAddress
			ctx.Mem.Write64(si+16, 0x00007FFFFFFEFFFF)     // lpMaximumApplicationAddress
			ctx.Mem.Write64(si+24, 1)                      // dwActiveProcessorMask
			ctx.Mem.Write32(si+32, 1)                      // dwNumberOfProcessors
			ctx.Mem.Write32(si+36, 8664)                   // dwProcessorType = AMD X86_64
			ctx.Mem.Write32(si+40, 65536)                  // dwAllocationGranularity
			ctx.Mem.Write16(si+44, 6)                      // wProcessorLevel
			ctx.Mem.Write16(si+46, 0)                      // wProcessorRevision
			return 0
		})

		d.RegisterAutoStubHandler(kernel32, "GetVersionExA", func(ctx *ntapi.TrapContext) uint32 {
			info := ctx.Arg(0)
			// dwOSVersionInfoSize already set by caller; fill key fields
			ctx.Mem.Write32(info+4, 10)  // dwMajorVersion = 10
			ctx.Mem.Write32(info+8, 0)   // dwMinorVersion = 0
			ctx.Mem.Write32(info+12, 19041) // dwBuildNumber
			ctx.Mem.Write32(info+16, 2)  // dwPlatformId = VER_PLATFORM_WIN32_NT
			ctx.SetReturn(1) // TRUE
			return 0
		})

		d.RegisterAutoStubHandler(kernel32, "IsValidCodePage", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE - all code pages are "valid"
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetConsoleMode", func(ctx *ntapi.TrapContext) uint32 {
			lpMode := ctx.Arg(1)
			if lpMode != 0 {
				ctx.Mem.Write32(lpMode, 0x0007) // ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING
			}
			ctx.SetReturn(1) // TRUE = is a console
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetConsoleMode", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetCPInfo", func(ctx *ntapi.TrapContext) uint32 {
			// codePage := ctx.Arg(0) - ignored, always return SBCS info
			lpCPInfo := ctx.Arg(1) // CPINFO*: MaxCharSize(4) + DefaultChar(2) + LeadByte(12)
			if lpCPInfo != 0 {
				ctx.Mem.Write32(lpCPInfo, 1)           // MaxCharSize = 1 (SBCS)
				ctx.Mem.Write8(lpCPInfo+4, 0x3F)       // DefaultChar[0] = '?'
				ctx.Mem.Write8(lpCPInfo+5, 0)          // DefaultChar[1] = 0
				for i := uint64(0); i < 12; i++ {
					ctx.Mem.Write8(lpCPInfo+6+i, 0) // LeadByte = all zeros
				}
			}
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetConsoleCP", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(65001) // UTF-8
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetConsoleOutputCP", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(65001) // UTF-8
			return 0
		})

		d.RegisterAutoStubHandler(kernel32, "GetSystemTimeAsFileTime", func(ctx *ntapi.TrapContext) uint32 {
			// Write a plausible FILETIME (100ns intervals since 1601-01-01)
			ft := ctx.Arg(0)
			// ~2024-01-01 in FILETIME: 0x01DA5E4000000000
			ctx.Mem.Write32(ft, 0)
			ctx.Mem.Write32(ft+4, 0x01DA5E40)
			return 0
		})

		d.RegisterAutoStubHandler(kernel32, "MultiByteToWideChar", func(ctx *ntapi.TrapContext) uint32 {
			srcStr := ctx.Arg(2)
			srcLen := int64(int32(ctx.Arg(3)))
			dstBuf := ctx.Arg(4)
			dstLen := int64(int32(ctx.Arg(5)))

			if srcLen == -1 {
				// Calculate length including null terminator
				srcLen = 0
				for {
					b, _ := ctx.Mem.Read8(srcStr + uint64(srcLen))
					srcLen++
					if b == 0 {
						break
					}
				}
			}
			if dstLen == 0 {
				ctx.SetReturn(uint64(srcLen))
				return 0
			}
			n := srcLen
			if n > dstLen {
				n = dstLen
			}
			for i := int64(0); i < n; i++ {
				b, _ := ctx.Mem.Read8(srcStr + uint64(i))
				ctx.Mem.Write16(dstBuf+uint64(i*2), uint16(b))
			}
			ctx.SetReturn(uint64(n))
			return 0
		})

		d.RegisterAutoStubHandler(kernel32, "WideCharToMultiByte", func(ctx *ntapi.TrapContext) uint32 {
			srcStr := ctx.Arg(2)
			srcLen := int64(int32(ctx.Arg(3)))
			dstBuf := ctx.Arg(4)
			dstLen := int64(int32(ctx.Arg(5)))

			if srcLen == -1 {
				srcLen = 0
				for {
					w, _ := ctx.Mem.Read16(srcStr + uint64(srcLen*2))
					srcLen++
					if w == 0 {
						break
					}
				}
			}
			if dstLen == 0 {
				ctx.SetReturn(uint64(srcLen))
				return 0
			}
			n := srcLen
			if n > dstLen {
				n = dstLen
			}
			for i := int64(0); i < n; i++ {
				w, _ := ctx.Mem.Read16(srcStr + uint64(i*2))
				ctx.Mem.Write8(dstBuf+uint64(i), byte(w))
			}
			ctx.SetReturn(uint64(n))
			return 0
		})

		d.RegisterAutoStubHandler(kernel32, "LocalAlloc", func(ctx *ntapi.TrapContext) uint32 {
			size := ctx.Arg(1)
			if size == 0 {
				size = 1
			}
			buf := mem.Mmap(0, size, mmu.PermRead|mmu.PermWrite)
			ctx.SetReturn(buf)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "LocalFree", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})

		d.RegisterAutoStubHandler(kernel32, "GetModuleFileNameA", func(ctx *ntapi.TrapContext) uint32 {
			hModule := ctx.Arg(0)
			buf := ctx.Arg(1)
			size := ctx.Arg(2)
			var path string
			imageBase, _ := ctx.Mem.Read64(ctx.State.PEBAddr + 0x10)
			if hModule == 0 || hModule == imageBase {
				path = imagePath
			} else {
				path = "C:\\Windows\\System32\\unknown.dll"
			}
			name := []byte(path)
			n := uint64(len(name))
			if n >= size {
				n = size - 1
			}
			for i := uint64(0); i < n; i++ {
				ctx.Mem.Write8(buf+i, name[i])
			}
			ctx.Mem.Write8(buf+n, 0)
			ctx.SetReturn(n)
			return 0
		})

		d.RegisterAutoStubHandler(kernel32, "GetFileAttributesA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0xFFFFFFFF) // INVALID_FILE_ATTRIBUTES = file not found
			return 0
		})

		// ExitProcess: cleanly terminate emulation
		d.RegisterAutoStubHandler(kernel32, "ExitProcess", func(ctx *ntapi.TrapContext) uint32 {
			code := ctx.Arg(0)
			ravelog.Logf("[win32] ExitProcess(%d)\n", code)
			if wlDisplay != nil {
				wlDisplay.Close()
			}
			pprof.StopCPUProfile()
			os.Exit(int(code))
			return 0
		})

		// GetCommandLineA: return pointer to ASCII command line
		var cmdLineAAddr uint64
		d.RegisterAutoStubHandler(kernel32, "GetCommandLineA", func(ctx *ntapi.TrapContext) uint32 {
			if cmdLineAAddr == 0 {
				cl := []byte(cmdLine)
				cmdLineAAddr = ctx.Mem.Mmap(0, uint64(len(cl)+1), mmu.PermRead|mmu.PermWrite)
				ctx.Mem.WriteBytes(cmdLineAAddr, append(cl, 0))
			}
			ctx.SetReturn(cmdLineAAddr)
			return 0
		})

		// GetCommandLineW: return pointer to UTF-16LE command line
		var cmdLineWAddr uint64
		d.RegisterAutoStubHandler(kernel32, "GetCommandLineW", func(ctx *ntapi.TrapContext) uint32 {
			if cmdLineWAddr == 0 {
				utf16 := make([]byte, 0, (len(cmdLine)+1)*2)
				for _, b := range []byte(cmdLine) {
					utf16 = append(utf16, b, 0)
				}
				utf16 = append(utf16, 0, 0) // null terminator
				cmdLineWAddr = ctx.Mem.Mmap(0, uint64(len(utf16)), mmu.PermRead|mmu.PermWrite)
				ctx.Mem.WriteBytes(cmdLineWAddr, utf16)
			}
			ctx.SetReturn(cmdLineWAddr)
			return 0
		})

		// GetStartupInfoW: fill STARTUPINFOW (104 bytes on x64)
		d.RegisterAutoStubHandler(kernel32, "GetStartupInfoW", func(ctx *ntapi.TrapContext) uint32 {
			addr := ctx.Arg(0)
			for i := uint64(0); i < 104; i++ {
				ctx.Mem.Write8(addr+i, 0)
			}
			ctx.Mem.Write32(addr, 104) // cb
			return 0
		})

		// GetFileType: FILE_TYPE_CHAR for std handles, FILE_TYPE_DISK otherwise
		d.RegisterAutoStubHandler(kernel32, "GetFileType", func(ctx *ntapi.TrapContext) uint32 {
			handle := ctx.Arg(0)
			switch handle {
			case 0x100, 0x101, 0x102: // stdin, stdout, stderr
				ctx.SetReturn(0x0002) // FILE_TYPE_CHAR
			default:
				ctx.SetReturn(0x0001) // FILE_TYPE_DISK
			}
			return 0
		})

		// WriteFile: write to stdout/stderr for console handles
		d.RegisterAutoStubHandler(kernel32, "WriteFile", func(ctx *ntapi.TrapContext) uint32 {
			handle := ctx.Arg(0)
			buf := ctx.Arg(1)
			nBytes := ctx.Arg(2)
			lpWritten := ctx.Arg(3)
			data := make([]byte, nBytes)
			for i := uint64(0); i < nBytes; i++ {
				b, _ := ctx.Mem.Read8(buf + i)
				data[i] = b
			}
			switch handle {
			case 0x101: // stdout
				os.Stdout.Write(data)
			case 0x102: // stderr
				os.Stderr.Write(data)
			}
			if lpWritten != 0 {
				ctx.Mem.Write32(lpWritten, uint32(nBytes))
			}
			ctx.SetReturn(1) // TRUE
			return 0
		})

		d.RegisterAutoStubHandler(kernel32, "WriteConsoleW", func(ctx *ntapi.TrapContext) uint32 {
			handle := ctx.Arg(0)
			buf := ctx.Arg(1)
			nChars := ctx.Arg(2)
			lpWritten := ctx.Arg(3)
			data := make([]byte, 0, nChars)
			for i := uint64(0); i < nChars; i++ {
				w, _ := ctx.Mem.Read16(buf + i*2)
				if w < 128 {
					data = append(data, byte(w))
				} else {
					data = append(data, '?')
				}
			}
			switch handle {
			case 0x101:
				os.Stdout.Write(data)
			case 0x102:
				os.Stderr.Write(data)
			}
			if lpWritten != 0 {
				ctx.Mem.Write32(lpWritten, uint32(nChars))
			}
			ctx.SetReturn(1)
			return 0
		})

		// GetACP: return Windows-1252 code page
		d.RegisterAutoStubHandler(kernel32, "GetACP", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1252)
			return 0
		})

		// GetModuleFileNameW: write image path as UTF-16LE
		d.RegisterAutoStubHandler(kernel32, "GetModuleFileNameW", func(ctx *ntapi.TrapContext) uint32 {
			hModule := ctx.Arg(0)
			buf := ctx.Arg(1)
			size := ctx.Arg(2)
			var path string
			imageBase, _ := ctx.Mem.Read64(ctx.State.PEBAddr + 0x10)
			if hModule == 0 || hModule == imageBase {
				path = imagePath
			} else {
				path = "C:\\Windows\\System32\\unknown.dll"
			}
			n := uint64(len(path))
			if n >= size {
				n = size - 1
			}
			for i := uint64(0); i < n; i++ {
				ctx.Mem.Write16(buf+i*2, uint16(path[i]))
			}
			ctx.Mem.Write16(buf+n*2, 0) // null terminator
			ctx.SetReturn(n)
			return 0
		})

		// InitializeSListHead: zero 16 bytes
		d.RegisterAutoStubHandler(kernel32, "InitializeSListHead", func(ctx *ntapi.TrapContext) uint32 {
			addr := ctx.Arg(0)
			if addr != 0 {
				ctx.Mem.Write64(addr, 0)
				ctx.Mem.Write64(addr+8, 0)
			}
			return 0
		})

		// GetEnvironmentStringsW: return pointer to env block from PEB
		d.RegisterAutoStubHandler(kernel32, "GetEnvironmentStringsW", func(ctx *ntapi.TrapContext) uint32 {
			paramsAddr, _ := ctx.Mem.Read64(ctx.State.PEBAddr + ntapi.PebProcessParameters)
			envPtr, _ := ctx.Mem.Read64(paramsAddr + ntapi.ProcessParamsEnvironment)
			ctx.SetReturn(envPtr)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FreeEnvironmentStringsW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})

		// SetConsoleCtrlHandler: no-op
		d.RegisterAutoStubHandler(kernel32, "SetConsoleCtrlHandler", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})

		// EncodePointer/DecodePointer: just return the pointer as-is
		d.RegisterAutoStubHandler(kernel32, "EncodePointer", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(ctx.Arg(0))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "DecodePointer", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(ctx.Arg(0))
			return 0
		})

		// --- String functions ---
		d.RegisterAutoStubHandler(kernel32, "lstrcpynA", func(ctx *ntapi.TrapContext) uint32 {
			dst := ctx.Arg(0)
			src := ctx.Arg(1)
			maxLen := int64(int32(ctx.Arg(2)))
			if maxLen <= 0 {
				ctx.SetReturn(dst)
				return 0
			}
			for i := int64(0); i < maxLen-1; i++ {
				b, _ := ctx.Mem.Read8(src + uint64(i))
				ctx.Mem.Write8(dst+uint64(i), b)
				if b == 0 {
					ctx.SetReturn(dst)
					return 0
				}
			}
			ctx.Mem.Write8(dst+uint64(maxLen-1), 0)
			ctx.SetReturn(dst)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "lstrcpyW", func(ctx *ntapi.TrapContext) uint32 {
			dst := ctx.Arg(0)
			src := ctx.Arg(1)
			for i := uint64(0); ; i += 2 {
				w, _ := ctx.Mem.Read16(src + i)
				ctx.Mem.Write16(dst+i, w)
				if w == 0 {
					break
				}
			}
			ctx.SetReturn(dst)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "lstrcpynW", func(ctx *ntapi.TrapContext) uint32 {
			dst := ctx.Arg(0)
			src := ctx.Arg(1)
			maxLen := int64(int32(ctx.Arg(2)))
			if maxLen <= 0 {
				ctx.SetReturn(dst)
				return 0
			}
			for i := int64(0); i < maxLen-1; i++ {
				w, _ := ctx.Mem.Read16(src + uint64(i*2))
				ctx.Mem.Write16(dst+uint64(i*2), w)
				if w == 0 {
					ctx.SetReturn(dst)
					return 0
				}
			}
			ctx.Mem.Write16(dst+uint64((maxLen-1)*2), 0)
			ctx.SetReturn(dst)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "lstrlenW", func(ctx *ntapi.TrapContext) uint32 {
			s := ctx.Arg(0)
			if s == 0 {
				ctx.SetReturn(0)
				return 0
			}
			n := uint64(0)
			for {
				w, _ := ctx.Mem.Read16(s + n*2)
				if w == 0 {
					break
				}
				n++
			}
			ctx.SetReturn(n)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "lstrcmpW", func(ctx *ntapi.TrapContext) uint32 {
			a := ctx.Arg(0)
			b := ctx.Arg(1)
			for i := uint64(0); ; i += 2 {
				wa, _ := ctx.Mem.Read16(a + i)
				wb, _ := ctx.Mem.Read16(b + i)
				if wa < wb {
					ctx.SetReturn(uint64(0xFFFFFFFFFFFFFFFF)) // -1
					return 0
				}
				if wa > wb {
					ctx.SetReturn(1)
					return 0
				}
				if wa == 0 {
					break
				}
			}
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "lstrcmpiA", func(ctx *ntapi.TrapContext) uint32 {
			a := ctx.Arg(0)
			b := ctx.Arg(1)
			for i := uint64(0); ; i++ {
				ba, _ := ctx.Mem.Read8(a + i)
				bb, _ := ctx.Mem.Read8(b + i)
				la := ba
				if la >= 'A' && la <= 'Z' {
					la += 32
				}
				lb := bb
				if lb >= 'A' && lb <= 'Z' {
					lb += 32
				}
				if la < lb {
					ctx.SetReturn(uint64(0xFFFFFFFFFFFFFFFF))
					return 0
				}
				if la > lb {
					ctx.SetReturn(1)
					return 0
				}
				if la == 0 {
					break
				}
			}
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "lstrcmpiW", func(ctx *ntapi.TrapContext) uint32 {
			a := ctx.Arg(0)
			b := ctx.Arg(1)
			for i := uint64(0); ; i += 2 {
				wa, _ := ctx.Mem.Read16(a + i)
				wb, _ := ctx.Mem.Read16(b + i)
				la := wa
				if la >= 'A' && la <= 'Z' {
					la += 32
				}
				lb := wb
				if lb >= 'A' && lb <= 'Z' {
					lb += 32
				}
				if la < lb {
					ctx.SetReturn(uint64(0xFFFFFFFFFFFFFFFF))
					return 0
				}
				if la > lb {
					ctx.SetReturn(1)
					return 0
				}
				if la == 0 {
					break
				}
			}
			ctx.SetReturn(0)
			return 0
		})

		// --- Directory / path functions ---
		d.RegisterAutoStubHandler(kernel32, "GetCurrentDirectoryW", func(ctx *ntapi.TrapContext) uint32 {
			bufSize := ctx.Arg(0)
			buf := ctx.Arg(1)
			dir := `C:\`
			needed := uint64(len(dir) + 1)
			if bufSize < needed {
				ctx.SetReturn(needed)
				return 0
			}
			for i, ch := range dir {
				ctx.Mem.Write16(buf+uint64(i*2), uint16(ch))
			}
			ctx.Mem.Write16(buf+uint64(len(dir)*2), 0)
			ctx.SetReturn(uint64(len(dir)))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetCurrentDirectoryW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateDirectoryW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetFullPathNameW", func(ctx *ntapi.TrapContext) uint32 {
			fileNamePtr := ctx.Arg(0)
			bufLen := ctx.Arg(1)
			buf := ctx.Arg(2)
			// Read the input filename
			var chars []uint16
			for i := uint64(0); ; i += 2 {
				w, _ := ctx.Mem.Read16(fileNamePtr + i)
				chars = append(chars, w)
				if w == 0 {
					break
				}
			}
			needed := uint64(len(chars))
			if bufLen < needed {
				ctx.SetReturn(needed)
				return 0
			}
			for i, w := range chars {
				ctx.Mem.Write16(buf+uint64(i*2), w)
			}
			ctx.SetReturn(needed - 1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetLongPathNameW", func(ctx *ntapi.TrapContext) uint32 {
			shortPath := ctx.Arg(0)
			buf := ctx.Arg(1)
			bufLen := ctx.Arg(2)
			var chars []uint16
			for i := uint64(0); ; i += 2 {
				w, _ := ctx.Mem.Read16(shortPath + i)
				chars = append(chars, w)
				if w == 0 {
					break
				}
			}
			needed := uint64(len(chars))
			if bufLen < needed {
				ctx.SetReturn(needed)
				return 0
			}
			for i, w := range chars {
				ctx.Mem.Write16(buf+uint64(i*2), w)
			}
			ctx.SetReturn(needed - 1)
			return 0
		})

		// --- Version / system info ---
		d.RegisterAutoStubHandler(kernel32, "GetVersionExW", func(ctx *ntapi.TrapContext) uint32 {
			lpInfo := ctx.Arg(0)
			// OSVERSIONINFOW: major=10, minor=0, build=19045
			ctx.Mem.Write32(lpInfo+4, 10)    // dwMajorVersion
			ctx.Mem.Write32(lpInfo+8, 0)     // dwMinorVersion
			ctx.Mem.Write32(lpInfo+12, 19045) // dwBuildNumber
			ctx.Mem.Write32(lpInfo+16, 2)    // dwPlatformId = VER_PLATFORM_WIN32_NT
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetVersion", func(ctx *ntapi.TrapContext) uint32 {
			// Returns (build << 16) | (minor << 8) | major
			ctx.SetReturn(uint64(19045<<16 | 0<<8 | 10))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetNativeSystemInfo", func(ctx *ntapi.TrapContext) uint32 {
			si := ctx.Arg(0)
			for i := uint64(0); i < 48; i++ {
				ctx.Mem.Write8(si+i, 0)
			}
			ctx.Mem.Write16(si+0, 9)
			ctx.Mem.Write32(si+4, 4096)
			ctx.Mem.Write64(si+8, 0x10000)
			ctx.Mem.Write64(si+16, 0x00007FFFFFFEFFFF)
			ctx.Mem.Write64(si+24, 1)
			ctx.Mem.Write32(si+32, 4)
			ctx.Mem.Write32(si+40, 65536)
			ctx.SetReturn(0)
			return 0
		})

		// --- Sync primitives (single-threaded no-ops) ---
		d.RegisterAutoStubHandler(kernel32, "CreateMutexW", func(ctx *ntapi.TrapContext) uint32 {
			h := handles.Alloc(&ntapi.MutantHandle{})
			ctx.SetReturn(uint64(h))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ReleaseMutex", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "WaitForSingleObject", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // WAIT_OBJECT_0
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "WaitForMultipleObjects", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // WAIT_OBJECT_0
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "AcquireSRWLockExclusive", func(ctx *ntapi.TrapContext) uint32 {
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ReleaseSRWLockExclusive", func(ctx *ntapi.TrapContext) uint32 {
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "TryAcquireSRWLockExclusive", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE (acquired)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "WakeAllConditionVariable", func(ctx *ntapi.TrapContext) uint32 {
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SleepConditionVariableSRW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SleepEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateEventW", func(ctx *ntapi.TrapContext) uint32 {
			h := handles.Alloc(&ntapi.EventHandle{})
			ctx.SetReturn(uint64(h))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetEvent", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ResetEvent", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "InitOnceBeginInitialize", func(ctx *ntapi.TrapContext) uint32 {
			// Single-threaded: always succeed, set fPending=TRUE via arg2 pointer
			pending := ctx.Arg(2)
			if pending != 0 {
				ctx.Mem.Write32(pending, 1) // fPending = TRUE
			}
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "InitOnceComplete", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateThread", func(ctx *ntapi.TrapContext) uint32 {
			// Stub: return a dummy thread handle, don't actually create a thread
			h := handles.Alloc(&ntapi.ThreadHandle{})
			ctx.SetReturn(uint64(h))
			return 0
		})

		// --- File I/O ---
		d.RegisterAutoStubHandler(kernel32, "CreateFileW", func(ctx *ntapi.TrapContext) uint32 {
			namePtr := ctx.Arg(0)
			desiredAccess := ctx.Arg(1)
			creationDisp := ctx.Arg(4) // CREATE_NEW=1, CREATE_ALWAYS=2, OPEN_EXISTING=3, OPEN_ALWAYS=4, TRUNCATE_EXISTING=5
			var fname []uint16
			for i := uint64(0); ; i += 2 {
				w, _ := ctx.Mem.Read16(namePtr + i)
				if w == 0 {
					break
				}
				fname = append(fname, w)
			}
			name := string(utf16Decode(fname))
			if ctx.Trace {
				ravelog.Logf("[win32] CreateFileW: %q access=0x%x disp=%d\n", name, desiredAccess, creationDisp)
			}
			// Convert Windows path to VFS path
			vfsPath := winPathToVFS(name)
			// Fallback: if path like /AppName/file.xml doesn't exist,
			// try replacing first directory component with the PE's dir
			lastBS := strings.LastIndex(imagePath, `\`)
			peWinDir := imagePath
			if lastBS >= 0 {
				peWinDir = imagePath[:lastBS]
			}
			peVfsDir := winPathToVFS(peWinDir)
			var flags int
			switch creationDisp {
			case 1: // CREATE_NEW
				flags = vfs.O_CREAT | vfs.O_RDWR
			case 2: // CREATE_ALWAYS
				flags = vfs.O_CREAT | vfs.O_TRUNC | vfs.O_RDWR
			case 3: // OPEN_EXISTING
				flags = vfs.O_RDONLY
				if desiredAccess&0x40000000 != 0 { // GENERIC_WRITE
					flags = vfs.O_RDWR
				}
			case 4: // OPEN_ALWAYS
				flags = vfs.O_CREAT | vfs.O_RDWR
			case 5: // TRUNCATE_EXISTING
				flags = vfs.O_TRUNC | vfs.O_RDWR
			default:
				flags = vfs.O_RDONLY
			}
			fd, err := ctx.FS.Open(vfsPath, flags)
			if err != nil {
				// Try remapping first directory component to PE directory
				parts := strings.SplitN(strings.TrimPrefix(vfsPath, "/"), "/", 2)
				if len(parts) == 2 {
					altPath := peVfsDir + "/" + parts[1]
					fd2, err2 := ctx.FS.Open(altPath, flags)
					if err2 == nil {
						fd = fd2
						err = nil
						vfsPath = altPath
					}
				}
			}
			if err != nil {
				if ctx.Trace {
					ravelog.Logf("[win32] CreateFileW: %q → INVALID_HANDLE_VALUE (%v)\n", name, err)
				}
				ctx.SetReturn(0xFFFFFFFFFFFFFFFF) // INVALID_HANDLE_VALUE
				procState.LastError = 2 // ERROR_FILE_NOT_FOUND
				return 0
			}
			h := handles.Alloc(&ntapi.FileHandle{FD: fd, Path: vfsPath})
			if ctx.Trace {
				ravelog.Logf("[win32] CreateFileW: %q → handle=0x%x (fd=%d)\n", name, uint64(h), fd)
			}
			ctx.SetReturn(uint64(h))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ReadFile", func(ctx *ntapi.TrapContext) uint32 {
			hFile := ntapi.Handle(ctx.Arg(0))
			bufAddr := ctx.Arg(1)
			nBytesToRead := uint32(ctx.Arg(2))
			lpBytesRead := ctx.Arg(3)
			obj := handles.Get(hFile)
			fh, ok := obj.(*ntapi.FileHandle)
			if !ok {
				if lpBytesRead != 0 {
					ctx.Mem.Write32(lpBytesRead, 0)
				}
				ctx.SetReturn(0) // FALSE
				return 0
			}
			buf := make([]byte, nBytesToRead)
			n, _ := ctx.FS.Read(fh.FD, buf)
			ctx.Mem.WriteBytes(bufAddr, buf[:n])
			if lpBytesRead != 0 {
				ctx.Mem.Write32(lpBytesRead, uint32(n))
			}
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetFilePointerEx", func(ctx *ntapi.TrapContext) uint32 {
			hFile := ntapi.Handle(ctx.Arg(0))
			distance := int64(ctx.Arg(1))
			newPosPtr := ctx.Arg(2)
			method := uint32(ctx.Arg(3)) // 0=BEGIN, 1=CURRENT, 2=END
			obj := handles.Get(hFile)
			fh, ok := obj.(*ntapi.FileHandle)
			if !ok {
				ctx.SetReturn(0) // FALSE
				return 0
			}
			whence := int(method) // maps directly: SEEK_SET=0, SEEK_CUR=1, SEEK_END=2
			newPos, err := ctx.FS.Lseek(fh.FD, distance, whence)
			if err != nil {
				ctx.SetReturn(0)
				return 0
			}
			if newPosPtr != 0 {
				ctx.Mem.Write64(newPosPtr, uint64(newPos))
			}
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetFileSizeEx", func(ctx *ntapi.TrapContext) uint32 {
			hFile := ntapi.Handle(ctx.Arg(0))
			sizePtr := ctx.Arg(1)
			obj := handles.Get(hFile)
			fh, ok := obj.(*ntapi.FileHandle)
			if !ok {
				ctx.SetReturn(0) // FALSE
				return 0
			}
			node := ctx.FS.Stat(fh.FD)
			if node == nil {
				ctx.SetReturn(0)
				return 0
			}
			if sizePtr != 0 {
				ctx.Mem.Write64(sizePtr, uint64(node.Size))
			}
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CloseHandle", func(ctx *ntapi.TrapContext) uint32 {
			h := ntapi.Handle(ctx.Arg(0))
			obj := handles.Get(h)
			if fh, ok := obj.(*ntapi.FileHandle); ok {
				ctx.FS.Close(fh.FD)
			}
			handles.Close(h)
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FlushFileBuffers", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetFileAttributesW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0xFFFFFFFF) // INVALID_FILE_ATTRIBUTES
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetFileAttributesExW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FindFirstFileW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0xFFFFFFFFFFFFFFFF) // INVALID_HANDLE_VALUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FindFirstFileExW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0xFFFFFFFFFFFFFFFF) // INVALID_HANDLE_VALUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FindNextFileW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FindClose", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CopyFileW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CopyFileExW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "DeleteFileW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "MoveFileExW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetFileAttributesW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetStdHandle", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})

		// --- Memory ---
		d.RegisterAutoStubHandler(kernel32, "GlobalAlloc", func(ctx *ntapi.TrapContext) uint32 {
			flags := ctx.Arg(0)
			size := ctx.Arg(1)
			if size == 0 {
				size = 1
			}
			addr := mem.Mmap(0, size, mmu.PermRead|mmu.PermWrite)
			if flags&0x0040 != 0 { // GMEM_ZEROINIT
				for i := uint64(0); i < size; i++ {
					mem.Write8(addr+i, 0)
				}
			}
			ctx.SetReturn(addr)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GlobalLock", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(ctx.Arg(0)) // GlobalLock returns the pointer itself for GMEM_FIXED
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GlobalUnlock", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE = no more locks
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GlobalFree", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // NULL = success
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GlobalSize", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // can't determine
			return 0
		})

		// --- Locale / string classification ---
		d.RegisterAutoStubHandler(kernel32, "GetStringTypeW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetStringTypeExA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetStringTypeExW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "LCMapStringW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // 0 = failure
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "LCMapStringA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "LCMapStringEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetLocaleInfoA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetLocaleInfoW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetLocaleInfoEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CompareStringEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(2) // CSTR_EQUAL
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CompareStringW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(2) // CSTR_EQUAL
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetUserDefaultLCID", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x0409) // en-US
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "IsValidLocale", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "EnumSystemLocalesW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetOEMCP", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(437)
			return 0
		})

		// --- Time functions ---
		d.RegisterAutoStubHandler(kernel32, "GetTimeZoneInformation", func(ctx *ntapi.TrapContext) uint32 {
			tz := ctx.Arg(0)
			for i := uint64(0); i < 172; i++ {
				ctx.Mem.Write8(tz+i, 0)
			}
			ctx.SetReturn(0) // TIME_ZONE_ID_UNKNOWN
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetLocalTime", func(ctx *ntapi.TrapContext) uint32 {
			st := ctx.Arg(0)
			now := time.Now()
			ctx.Mem.Write16(st+0, uint16(now.Year()))
			ctx.Mem.Write16(st+2, uint16(now.Month()))
			ctx.Mem.Write16(st+4, uint16(now.Weekday()))
			ctx.Mem.Write16(st+6, uint16(now.Day()))
			ctx.Mem.Write16(st+8, uint16(now.Hour()))
			ctx.Mem.Write16(st+10, uint16(now.Minute()))
			ctx.Mem.Write16(st+12, uint16(now.Second()))
			ctx.Mem.Write16(st+14, uint16(now.Nanosecond()/1e6))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FileTimeToSystemTime", func(ctx *ntapi.TrapContext) uint32 {
			ft := ctx.Arg(0)
			st := ctx.Arg(1)
			lo, _ := ctx.Mem.Read32(ft)
			hi, _ := ctx.Mem.Read32(ft + 4)
			ticks := int64(hi)<<32 | int64(lo)
			// Convert from 100ns intervals since 1601 to Go time
			t := time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(ticks) * 100)
			ctx.Mem.Write16(st+0, uint16(t.Year()))
			ctx.Mem.Write16(st+2, uint16(t.Month()))
			ctx.Mem.Write16(st+4, uint16(t.Weekday()))
			ctx.Mem.Write16(st+6, uint16(t.Day()))
			ctx.Mem.Write16(st+8, uint16(t.Hour()))
			ctx.Mem.Write16(st+10, uint16(t.Minute()))
			ctx.Mem.Write16(st+12, uint16(t.Second()))
			ctx.Mem.Write16(st+14, uint16(t.Nanosecond()/1e6))
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SystemTimeToTzSpecificLocalTime", func(ctx *ntapi.TrapContext) uint32 {
			src := ctx.Arg(1)
			dst := ctx.Arg(2)
			// Copy SYSTEMTIME (16 bytes) as-is
			for i := uint64(0); i < 16; i++ {
				b, _ := ctx.Mem.Read8(src + i)
				ctx.Mem.Write8(dst+i, b)
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetDateFormatW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetTimeFormatW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetDateFormatEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetTimeFormatEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})

		// --- Exception handling ---
		d.RegisterAutoStubHandler(kernel32, "RtlPcToFileHeader", func(ctx *ntapi.TrapContext) uint32 {
			headerOut := ctx.Arg(1)
			imageBase, _ := ctx.Mem.Read64(procState.PEBAddr + 0x10)
			if headerOut != 0 {
				ctx.Mem.Write64(headerOut, imageBase)
			}
			ctx.SetReturn(imageBase)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RaiseException", func(ctx *ntapi.TrapContext) uint32 {
			code := ctx.Arg(0)
			flags := ctx.Arg(1)
			ravelog.Logf("[win32] RaiseException: code=0x%x flags=0x%x\n", code, flags)
			if code == 0x406D1388 {
				return 0 // MS_VC_EXCEPTION (SetThreadName) - ignore
			}
			if code == 0xe06d7363 {
				// MSVC C++ exception - try SEH dispatch to find catch handler
				rsp := ctx.CPU.GetSP()
				rip := ctx.CPU.GetPC()
				handler := ntapi.CxxDispatchException(ctx.Mem, exceptionTable, rsp, rip, ctx.Trace)
				if handler != nil {
					imageBase := uint64(0)
					if exceptionTable != nil {
						imageBase = exceptionTable.ImageBase
					}

					if handler.IsFallback {
						// FH4 format: can't parse catch blocks, unwind past the handler frame
						ravelog.Logf("[seh] C++ exception → FH4 fallback unwind to RIP=0x%x RSP=0x%x\n",
							handler.FallbackRIP, handler.FallbackRSP)
						if rw, ok := ctx.CPU.(ntapi.RegisterWriter); ok {
							rw.WriteReg(0, 0) // RAX = 0 (error return)
							// Restore saved non-volatile registers
							for reg, val := range handler.SavedRegs {
								rw.WriteReg(reg, val)
							}
						}
						ctx.CPU.SetSP(handler.FallbackRSP)
						ctx.CPU.SetPC(handler.FallbackRIP)
						return 0
					}

					catchAddr := imageBase + uint64(handler.FuncletRVA)
					if ctx.Trace {
						ravelog.Logf("[seh] C++ exception → catch funclet at 0x%x, RBP=0x%x\n",
							catchAddr, handler.EstablisherRBP)
					}
					// Set up the CPU to call the catch funclet:
					// Win64 ABI: RCX = establisher frame pointer (RBP)
					if rw, ok := ctx.CPU.(ntapi.RegisterWriter); ok {
						rw.WriteReg(1, handler.EstablisherRBP) // RCX = establisher frame
					}
					// Jump to the catch funclet
					ctx.CPU.SetPC(catchAddr)
					return 0
				}
				// No handler found - log and continue (best effort)
				ravelog.Logf("[win32] RaiseException: C++ exception (0xe06d7363) - no SEH handler, continuing\n")
				return 0
			}
			fmt.Fprintf(os.Stderr, "govm: RaiseException code=0x%x flags=0x%x - aborting\n", code, flags)
			os.Exit(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RtlUnwindEx", func(ctx *ntapi.TrapContext) uint32 {
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RtlUnwind", func(ctx *ntapi.TrapContext) uint32 {
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "TerminateProcess", func(ctx *ntapi.TrapContext) uint32 {
			code := ctx.Arg(1)
			fmt.Fprintf(os.Stderr, "govm: TerminateProcess code=%d\n", code)
			os.Exit(int(code))
			return 0
		})

		// --- Miscellaneous ---
		d.RegisterAutoStubHandler(kernel32, "MulDiv", func(ctx *ntapi.TrapContext) uint32 {
			a := int64(int32(ctx.Arg(0)))
			b := int64(int32(ctx.Arg(1)))
			c := int64(int32(ctx.Arg(2)))
			if c == 0 {
				ctx.SetReturn(uint64(0xFFFFFFFF)) // -1
				return 0
			}
			result := (a * b) / c
			ctx.SetReturn(uint64(int32(result)))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ExpandEnvironmentStringsW", func(ctx *ntapi.TrapContext) uint32 {
			src := ctx.Arg(0)
			dst := ctx.Arg(1)
			size := ctx.Arg(2)
			// Just copy the string as-is (no expansion)
			n := uint64(0)
			for {
				w, _ := ctx.Mem.Read16(src + n*2)
				if n < size {
					ctx.Mem.Write16(dst+n*2, w)
				}
				n++
				if w == 0 {
					break
				}
			}
			ctx.SetReturn(n)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetEnvironmentVariableW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetDiskFreeSpaceExW", func(ctx *ntapi.TrapContext) uint32 {
			free := ctx.Arg(1)
			total := ctx.Arg(2)
			totalFree := ctx.Arg(3)
			if free != 0 {
				ctx.Mem.Write64(free, 50*1024*1024*1024) // 50 GB
			}
			if total != 0 {
				ctx.Mem.Write64(total, 100*1024*1024*1024)
			}
			if totalFree != 0 {
				ctx.Mem.Write64(totalFree, 50*1024*1024*1024)
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "VerSetConditionMask", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(ctx.Arg(0) | 1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "VerifyVersionInfoW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetApplicationRestartSettings", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // S_FALSE (not registered)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "UnregisterApplicationRestart", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // S_OK
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RegisterApplicationRestart", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // S_OK
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FormatMessageW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // 0 chars written
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FormatMessageA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "LoadResource", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // NULL
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FindResourceW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "LockResource", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SizeofResource", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetTempPathW", func(ctx *ntapi.TrapContext) uint32 {
			buf := ctx.Arg(1)
			tmp := `C:\Windows\TEMP\`
			for i, ch := range tmp {
				ctx.Mem.Write16(buf+uint64(i*2), uint16(ch))
			}
			ctx.Mem.Write16(buf+uint64(len(tmp)*2), 0)
			ctx.SetReturn(uint64(len(tmp)))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "DeleteCriticalSection", func(ctx *ntapi.TrapContext) uint32 {
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "EnterCriticalSection", func(ctx *ntapi.TrapContext) uint32 {
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "LeaveCriticalSection", func(ctx *ntapi.TrapContext) uint32 {
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ReadConsoleW", func(ctx *ntapi.TrapContext) uint32 {
			charsRead := ctx.Arg(3)
			if charsRead != 0 {
				ctx.Mem.Write32(charsRead, 0)
			}
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateFileMappingW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // NULL = failure
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "MapViewOfFile", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "UnmapViewOfFile", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FreeLibraryAndExitThread", func(ctx *ntapi.TrapContext) uint32 {
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ExitThread", func(ctx *ntapi.TrapContext) uint32 {
			return 0
		})

		// IsWow64Process: always return FALSE (native 64-bit)
		d.RegisterAutoStubHandler(kernel32, "IsWow64Process", func(ctx *ntapi.TrapContext) uint32 {
			lpIsWow64 := ctx.Arg(1)
			if lpIsWow64 != 0 {
				mem.Write32(lpIsWow64, 0) // FALSE
			}
			ctx.SetReturn(1) // success
			return 0
		})

		// ResolveDelayLoadedAPI: resolve delay-loaded imports to our synth stubs
		var delayLoadFallback uint64
		// Compute next available auto-synth ID
		nextDelayID := uint32(ntapi.AutoSynthIDBase)
		for _, s := range dlls {
			for _, id := range s.StubIDs {
				if id+1 > nextDelayID {
					nextDelayID = id + 1
				}
			}
		}
		d.RegisterAutoStubHandler(kernel32, "ResolveDelayLoadedAPI", func(ctx *ntapi.TrapContext) uint32 {
			callerBase := ctx.Arg(0)
			pDescriptor := ctx.Arg(1)
			pThunkAddr := ctx.Arg(4)

			dllNameRVA, _ := mem.Read32(pDescriptor + 4)
			iatRVA, _ := mem.Read32(pDescriptor + 0x0C)
			intRVA, _ := mem.Read32(pDescriptor + 0x10)

			// Read DLL name
			var dllName string
			if dllNameRVA != 0 {
				nameAddr := callerBase + uint64(dllNameRVA)
				var buf []byte
				for i := uint64(0); i < 260; i++ {
					b, _ := mem.Read8(nameAddr + i)
					if b == 0 { break }
					buf = append(buf, b)
				}
				dllName = strings.ToLower(string(buf))
			}

			// Find function name from thunk
			iatBase := callerBase + uint64(iatRVA)
			intBase := callerBase + uint64(intRVA)
			var funcName string
			if pThunkAddr >= iatBase {
				idx := (pThunkAddr - iatBase) / 8
				intEntry, _ := mem.Read64(intBase + idx*8)
				if intEntry != 0 && intEntry&(1<<63) == 0 {
					nameAddr := callerBase + intEntry + 2
					var buf []byte
					for i := uint64(0); i < 260; i++ {
						b, _ := mem.Read8(nameAddr + i)
						if b == 0 { break }
						buf = append(buf, b)
					}
					funcName = string(buf)
				}
			}

			if dllName == "" || funcName == "" {
				goto fallback
			}

			// If synth DLL doesn't exist yet, create it from all INT entries
			if _, ok := synthByName[dllName]; !ok {
				var allFuncs []string
				for i := uint64(0); ; i++ {
					entry, _ := mem.Read64(intBase + i*8)
					if entry == 0 { break }
					if entry&(1<<63) != 0 { continue } // ordinal
					addr := callerBase + entry + 2
					var buf []byte
					for j := uint64(0); j < 260; j++ {
						b, _ := mem.Read8(addr + j)
						if b == 0 { break }
						buf = append(buf, b)
					}
					if len(buf) > 0 {
						allFuncs = append(allFuncs, string(buf))
					}
				}
				if len(allFuncs) > 0 {
					synth := ntapi.GenerateSynthDLL(mem, dllName, allFuncs, nextDelayID)
					synthByName[dllName] = synth
					d.RegisterAutoStubNames(synth)
					ravelog.Logf("[pe] delay-synth %s: %d stubs (id base 0x%X) funcs=%v\n",
						dllName, len(allFuncs), nextDelayID, allFuncs)
					nextDelayID += uint32(len(allFuncs))
					// Re-run all handler registrars so newly synthesized DLL gets handlers
					for _, reg := range delayHandlerRegistrars {
						reg()
					}
				}
			}

			if synth, ok := synthByName[dllName]; ok {
				if addr, ok2 := synth.Exports[funcName]; ok2 {
					mem.Write64(pThunkAddr, addr)
					ctx.SetReturn(addr)
					return 0
				}
			}
			ravelog.Logf("[delay] unresolved: %s!%s\n", dllName, funcName)

		fallback:
			if delayLoadFallback == 0 {
				delayLoadFallback = mem.Mmap(0, 4096, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
				mem.Write8(delayLoadFallback, 0x31)
				mem.Write8(delayLoadFallback+1, 0xC0)
				mem.Write8(delayLoadFallback+2, 0xC3)
			}
			if pThunkAddr != 0 {
				mem.Write64(pThunkAddr, delayLoadFallback)
			}
			ctx.SetReturn(delayLoadFallback)
			return 0
		})

		// GetEnvironmentVariableA: return 0 (not found)
		d.RegisterAutoStubHandler(kernel32, "GetEnvironmentVariableA", func(ctx *ntapi.TrapContext) uint32 {
			mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 203) // ERROR_ENVVAR_NOT_FOUND
			ctx.SetReturn(0)
			return 0
		})

		// GetComputerNameW
		d.RegisterAutoStubHandler(kernel32, "GetComputerNameW", func(ctx *ntapi.TrapContext) uint32 {
			lpBuffer := ctx.Arg(0)
			nSize := ctx.Arg(1)
			name := "GOVM"
			if lpBuffer != 0 && nSize != 0 {
				maxLen, _ := mem.Read32(nSize)
				for i, ch := range name {
					if uint32(i) >= maxLen {
						break
					}
					mem.Write16(lpBuffer+uint64(i)*2, uint16(ch))
				}
				mem.Write16(lpBuffer+uint64(len(name))*2, 0)
				mem.Write32(nSize, uint32(len(name)))
			}
			ctx.SetReturn(1)
			return 0
		})
	}

	// --- shlwapi.dll ---
	delayHandlerRegistrars = append(delayHandlerRegistrars, func() {
	if shlwapi, ok := synthByName["shlwapi.dll"]; ok {
		d.RegisterAutoStubHandler(shlwapi, "PathRemoveFileSpecW", func(ctx *ntapi.TrapContext) uint32 {
			path := ctx.Arg(0)
			// Find last backslash and null-terminate there
			lastSlash := uint64(0)
			for i := uint64(0); ; i += 2 {
				w, _ := ctx.Mem.Read16(path + i)
				if w == 0 {
					break
				}
				if w == '\\' || w == '/' {
					lastSlash = i
				}
			}
			if lastSlash > 0 {
				ctx.Mem.Write16(path+lastSlash, 0)
				ctx.SetReturn(1) // TRUE
			} else {
				ctx.SetReturn(0)
			}
			return 0
		})
		// wnsprintfW(lpOut, cchLimitIn, lpFmt, ...) - like snprintf for wide strings
		d.RegisterAutoStubHandler(shlwapi, "wnsprintfW", func(ctx *ntapi.TrapContext) uint32 {
			lpOut := ctx.Arg(0)
			cchLimit := int(int32(ctx.Arg(1)))
			lpFmt := ctx.Arg(2)
			fmtStr := readGuestUTF16(lpFmt)
			var args []uint64
			for i := 3; i < 10; i++ {
				args = append(args, ctx.Arg(i))
			}
			result := wideprintf(fmtStr, args)
			runes := []rune(result)
			n := len(runes)
			if cchLimit > 0 && n >= cchLimit {
				n = cchLimit - 1
			}
			for i := 0; i < n; i++ {
				mem.Write16(lpOut+uint64(i)*2, uint16(runes[i]))
			}
			mem.Write16(lpOut+uint64(n)*2, 0)
			ctx.SetReturn(uint64(n))
			return 0
		})
		// ColorRGBToHLS: convert COLORREF to HLS - store results in out-params
		d.RegisterAutoStubHandler(shlwapi, "ColorRGBToHLS", func(ctx *ntapi.TrapContext) uint32 {
			clr := uint32(ctx.Arg(0))
			pHue := ctx.Arg(1)
			pLum := ctx.Arg(2)
			pSat := ctx.Arg(3)
			r := float64((clr) & 0xFF)
			g := float64((clr >> 8) & 0xFF)
			b := float64((clr >> 16) & 0xFF)
			r /= 255; g /= 255; b /= 255
			maxC := math.Max(math.Max(r, g), b)
			minC := math.Min(math.Min(r, g), b)
			l := (maxC + minC) / 2
			var h, s float64
			if maxC != minC {
				d := maxC - minC
				if l > 0.5 { s = d / (2 - maxC - minC) } else { s = d / (maxC + minC) }
				switch maxC {
				case r: h = (g - b) / d; if g < b { h += 6 }
				case g: h = (b-r)/d + 2
				case b: h = (r-g)/d + 4
				}
				h /= 6
			}
			// Windows HLS: Hue 0-240, Lum 0-240, Sat 0-240
			if pHue != 0 { mem.Write16(pHue, uint16(h*240)) }
			if pLum != 0 { mem.Write16(pLum, uint16(l*240)) }
			if pSat != 0 { mem.Write16(pSat, uint16(s*240)) }
			return 0
		})
		// ColorHLSToRGB: convert Windows HLS (0-240 range) to COLORREF
		d.RegisterAutoStubHandler(shlwapi, "ColorHLSToRGB", func(ctx *ntapi.TrapContext) uint32 {
			wH := float64(ctx.Arg(0)) / 240
			wL := float64(ctx.Arg(1)) / 240
			wS := float64(ctx.Arg(2)) / 240
			hue2rgb := func(p, q, t float64) float64 {
				if t < 0 { t++ }
				if t > 1 { t-- }
				if t < 1.0/6 { return p + (q-p)*6*t }
				if t < 1.0/2 { return q }
				if t < 2.0/3 { return p + (q-p)*(2.0/3-t)*6 }
				return p
			}
			var r, g, b float64
			if wS == 0 {
				r, g, b = wL, wL, wL
			} else {
				var q float64
				if wL < 0.5 { q = wL * (1 + wS) } else { q = wL + wS - wL*wS }
				p := 2*wL - q
				r = hue2rgb(p, q, wH+1.0/3)
				g = hue2rgb(p, q, wH)
				b = hue2rgb(p, q, wH-1.0/3)
			}
			clr := uint32(r*255) | uint32(g*255)<<8 | uint32(b*255)<<16
			ctx.SetReturn(uint64(clr))
			return 0
		})
	}
	})
	delayHandlerRegistrars[len(delayHandlerRegistrars)-1]()
	delayHandlerRegistrars = append(delayHandlerRegistrars, func() {
	if shell32, ok := synthByName["shell32.dll"]; ok {
		d.RegisterAutoStubHandler(shell32, "SHGetFolderPathW", func(ctx *ntapi.TrapContext) uint32 {
			buf := ctx.Arg(3)
			folder := ctx.Arg(1)
			var path string
			switch int32(folder) {
			case 0x1a: // CSIDL_APPDATA
				path = `C:\Users\user\AppData\Roaming`
			case 0x1c: // CSIDL_LOCAL_APPDATA
				path = `C:\Users\user\AppData\Local`
			case 0x0028: // CSIDL_PROFILE
				path = `C:\Users\user`
			default:
				path = `C:\Users\user`
			}
			for i, ch := range path {
				ctx.Mem.Write16(buf+uint64(i*2), uint16(ch))
			}
			ctx.Mem.Write16(buf+uint64(len(path)*2), 0)
			ctx.SetReturn(0) // S_OK
			return 0
		})
		d.RegisterAutoStubHandler(shell32, "DragAcceptFiles", func(ctx *ntapi.TrapContext) uint32 {
			return 0
		})
	}
	})
	delayHandlerRegistrars[len(delayHandlerRegistrars)-1]()

	// --- shcore.dll ---
	delayHandlerRegistrars = append(delayHandlerRegistrars, func() {
	if shcore, ok := synthByName["shcore.dll"]; ok {
		d.RegisterAutoStubHandler(shcore, "CommandLineToArgvW", func(ctx *ntapi.TrapContext) uint32 {
			pNumArgs := ctx.Arg(1)
			// Allocate a minimal wide argv: just the program name
			page := mem.Mmap(0, 4096, mmu.PermRead|mmu.PermWrite)
			// argv[0] = pointer to wide string at page+16, argv[1] = NULL
			strAddr := page + 16
			for i, r := range imagePath {
				mem.Write16(strAddr+uint64(i)*2, uint16(r))
			}
			mem.Write16(strAddr+uint64(len(imagePath))*2, 0)
			mem.Write64(page, strAddr)     // argv[0]
			mem.Write64(page+8, 0)         // NULL terminator
			if pNumArgs != 0 {
				mem.Write32(pNumArgs, 1)
			}
			ctx.SetReturn(page)
			return 0
		})
		d.RegisterAutoStubHandler(shcore, "GetDpiForMonitor", func(ctx *ntapi.TrapContext) uint32 {
			dpiX := ctx.Arg(2)
			dpiY := ctx.Arg(3)
			if dpiX != 0 {
				mem.Write32(dpiX, 96)
			}
			if dpiY != 0 {
				mem.Write32(dpiY, 96)
			}
			ctx.SetReturn(0) // S_OK
			return 0
		})
		d.RegisterAutoStubHandler(shcore, "SetProcessDpiAwareness", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // S_OK
			return 0
		})
	}
	})
	delayHandlerRegistrars[len(delayHandlerRegistrars)-1]()

	// --- rpcrt4.dll ---
	delayHandlerRegistrars = append(delayHandlerRegistrars, func() {
	if rpcrt4, ok := synthByName["rpcrt4.dll"]; ok {
		d.RegisterAutoStubHandler(rpcrt4, "RpcStringFreeW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // RPC_S_OK
			return 0
		})
	}
	})
	delayHandlerRegistrars[len(delayHandlerRegistrars)-1]()

	// --- comdlg32.dll ---
	delayHandlerRegistrars = append(delayHandlerRegistrars, func() {
	if comdlg32, ok := synthByName["comdlg32.dll"]; ok {
		d.RegisterAutoStubHandler(comdlg32, "GetFileTitleW", func(ctx *ntapi.TrapContext) uint32 {
			lpBuffer := ctx.Arg(1)
			cbBuf := ctx.Arg(2)
			if lpBuffer != 0 && cbBuf > 0 {
				mem.Write16(lpBuffer, 0)
			}
			ctx.SetReturn(0)
			return 0
		})
	}
	})
	delayHandlerRegistrars[len(delayHandlerRegistrars)-1]()

	// --- advapi32.dll ---
	// Minimal in-memory registry
	type regKey struct {
		name     string
		subkeys  []uint64 // handles of children
		values   map[string][]byte
	}
	regStore := map[uint64]*regKey{
		0x80000000: {name: "HKEY_CLASSES_ROOT"},
		0x80000001: {name: "HKEY_CURRENT_USER"},
		0x80000002: {name: "HKEY_LOCAL_MACHINE"},
		0x80000003: {name: "HKEY_USERS"},
		0x80000005: {name: "HKEY_CURRENT_CONFIG"},
	}
	var regNextHandle uint64 = 0xBEEF0100
	regAllocHandle := func() uint64 {
		h := regNextHandle
		regNextHandle++
		return h
	}
	// Pre-populate common subkeys
	populateSubkeys := func(parent uint64, names []string) {
		pk := regStore[parent]
		for _, n := range names {
			h := regAllocHandle()
			regStore[h] = &regKey{name: n}
			pk.subkeys = append(pk.subkeys, h)
		}
	}
	populateSubkeys(0x80000002, []string{"SOFTWARE", "SYSTEM", "HARDWARE"}) // HKLM
	populateSubkeys(0x80000001, []string{"SOFTWARE", "Environment"})        // HKCU
	populateSubkeys(0x80000005, []string{"Software"})                       // HKCC

	delayHandlerRegistrars = append(delayHandlerRegistrars, func() {
	if advapi32, ok := synthByName["advapi32.dll"]; ok {
		d.RegisterAutoStubHandler(advapi32, "RegOpenKeyExW", func(ctx *ntapi.TrapContext) uint32 {
			hKey := ctx.Arg(0)
			lpSubKey := ctx.Arg(1)
			phkResult := ctx.Arg(4)

			subKeyName := readGuestUTF16(lpSubKey)

			// Look up parent
			pk, ok := regStore[hKey]
			if !ok {
				ctx.SetReturn(2) // ERROR_FILE_NOT_FOUND
				return 0
			}

			// If subkey is empty, return same handle
			if subKeyName == "" {
				if phkResult != 0 {
					mem.Write64(phkResult, hKey)
				}
				ctx.SetReturn(0)
				return 0
			}

			// Search children by name (case-insensitive)
			lowerName := strings.ToLower(subKeyName)
			for _, ch := range pk.subkeys {
				if ck, ok := regStore[ch]; ok && strings.ToLower(ck.name) == lowerName {
					if phkResult != 0 {
						mem.Write64(phkResult, ch)
					}
					ctx.SetReturn(0) // ERROR_SUCCESS
					return 0
				}
			}

			// Auto-create if opening under a known parent
			h := regAllocHandle()
			regStore[h] = &regKey{name: subKeyName}
			pk.subkeys = append(pk.subkeys, h)
			if phkResult != 0 {
				mem.Write64(phkResult, h)
			}
			ctx.SetReturn(0) // ERROR_SUCCESS
			return 0
		})
		d.RegisterAutoStubHandler(advapi32, "RegOpenKeyW", func(ctx *ntapi.TrapContext) uint32 {
			hKey := ctx.Arg(0)
			lpSubKey := ctx.Arg(1)
			phkResult := ctx.Arg(2)
			subKeyName := readGuestUTF16(lpSubKey)
			pk, ok := regStore[hKey]
			if !ok {
				ctx.SetReturn(2)
				return 0
			}
			if subKeyName == "" {
				if phkResult != 0 {
					mem.Write64(phkResult, hKey)
				}
				ctx.SetReturn(0)
				return 0
			}
			lowerName := strings.ToLower(subKeyName)
			for _, ch := range pk.subkeys {
				if ck, ok := regStore[ch]; ok && strings.ToLower(ck.name) == lowerName {
					if phkResult != 0 {
						mem.Write64(phkResult, ch)
					}
					ctx.SetReturn(0)
					return 0
				}
			}
			h := regAllocHandle()
			regStore[h] = &regKey{name: subKeyName}
			pk.subkeys = append(pk.subkeys, h)
			if phkResult != 0 {
				mem.Write64(phkResult, h)
			}
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(advapi32, "RegCloseKey", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // ERROR_SUCCESS
			return 0
		})
		d.RegisterAutoStubHandler(advapi32, "RegQueryValueExW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(2) // ERROR_FILE_NOT_FOUND
			return 0
		})
		d.RegisterAutoStubHandler(advapi32, "RegSetValueExW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // ERROR_SUCCESS
			return 0
		})
		d.RegisterAutoStubHandler(advapi32, "RegCreateKeyExW", func(ctx *ntapi.TrapContext) uint32 {
			hKey := ctx.Arg(0)
			lpSubKey := ctx.Arg(1)
			phkResult := ctx.Arg(6)
			lpDisposition := ctx.Arg(7)

			subKeyName := readGuestUTF16(lpSubKey)
			pk, ok := regStore[hKey]
			if !ok {
				ctx.SetReturn(2)
				return 0
			}
			// Check existing
			lowerName := strings.ToLower(subKeyName)
			for _, ch := range pk.subkeys {
				if ck, ok := regStore[ch]; ok && strings.ToLower(ck.name) == lowerName {
					if phkResult != 0 {
						mem.Write64(phkResult, ch)
					}
					if lpDisposition != 0 {
						mem.Write32(lpDisposition, 2) // REG_OPENED_EXISTING_KEY
					}
					ctx.SetReturn(0)
					return 0
				}
			}
			// Create new
			h := regAllocHandle()
			regStore[h] = &regKey{name: subKeyName}
			pk.subkeys = append(pk.subkeys, h)
			if phkResult != 0 {
				mem.Write64(phkResult, h)
			}
			if lpDisposition != 0 {
				mem.Write32(lpDisposition, 1) // REG_CREATED_NEW_KEY
			}
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(advapi32, "RegEnumKeyExW", func(ctx *ntapi.TrapContext) uint32 {
			hKey := ctx.Arg(0)
			dwIndex := ctx.Arg(1)
			lpName := ctx.Arg(2)
			lpcchName := ctx.Arg(3)

			pk, ok := regStore[hKey]
			if !ok || int(dwIndex) >= len(pk.subkeys) {
				ctx.SetReturn(259) // ERROR_NO_MORE_ITEMS
				return 0
			}
			childH := pk.subkeys[dwIndex]
			ck, ok := regStore[childH]
			if !ok {
				ctx.SetReturn(259)
				return 0
			}
			// Write name as UTF-16
			nameU16 := utf16Encode(ck.name)
			if lpName != 0 {
				for i, ch := range nameU16 {
					mem.Write16(lpName+uint64(i)*2, ch)
				}
				mem.Write16(lpName+uint64(len(nameU16))*2, 0) // null terminator
			}
			if lpcchName != 0 {
				mem.Write32(lpcchName, uint32(len(nameU16)))
			}
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(advapi32, "RegEnumValueW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(259) // ERROR_NO_MORE_ITEMS
			return 0
		})
		d.RegisterAutoStubHandler(advapi32, "RegQueryInfoKeyW", func(ctx *ntapi.TrapContext) uint32 {
			// RegQueryInfoKeyW(hKey, lpClass, lpcchClass, lpReserved, lpcSubKeys,
			//   lpcbMaxSubKeyLen, lpcbMaxClassLen, lpcValues, lpcbMaxValueNameLen,
			//   lpcbMaxValueLen, lpcbSecurityDescriptor, lpftLastWriteTime)
			hKey := ctx.Arg(0)
			lpcSubKeys := ctx.Arg(4)
			lpcValues := ctx.Arg(8) // stack arg
			// Count subkeys from our registry
			var subkeyCount uint32
			if rk, ok := regStore[hKey]; ok {
				subkeyCount = uint32(len(rk.subkeys))
			}
			if lpcSubKeys != 0 {
				ctx.Mem.Write32(lpcSubKeys, subkeyCount)
			}
			if lpcValues != 0 {
				ctx.Mem.Write32(lpcValues, 0)
			}
			ctx.SetReturn(0) // ERROR_SUCCESS
			return 0
		})
		d.RegisterAutoStubHandler(advapi32, "RegDeleteValueW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(advapi32, "GetUserNameW", func(ctx *ntapi.TrapContext) uint32 {
			buf := ctx.Arg(0)
			size := ctx.Arg(1)
			name := "user"
			if size != 0 {
				ctx.Mem.Write32(size, uint32(len(name)+1))
			}
			for i, ch := range name {
				ctx.Mem.Write16(buf+uint64(i*2), uint16(ch))
			}
			ctx.Mem.Write16(buf+uint64(len(name)*2), 0)
			ctx.SetReturn(1)
			return 0
		})
	}
	})
	delayHandlerRegistrars[len(delayHandlerRegistrars)-1]()

	// Simple handle generator for GDI objects, windows, etc.
	nextGDIHandle := uint64(0xD0010001) // GDI handle space
	gdiAlloc := func() uint64 {
		h := nextGDIHandle
		nextGDIHandle++
		return h
	}

	// Menu data structures (types defined earlier near peLoadMenuResource)
	menus := make(map[uint64]*menuData)          // menu handle → menu data
	hwndMenuBar := make(map[uint64]uint64)       // HWND → menu bar handle
	// Menu bar interaction state
	var openMenuIdx int = -1  // which top-level menu is open (-1 = none)
	var openMenuHwnd uint64   // which window's menu is open
	menuStripAmpersand := func(s string) string {
		out := make([]byte, 0, len(s))
		for i := 0; i < len(s); i++ {
			if s[i] == '&' && i+1 < len(s) {
				continue
			}
			out = append(out, s[i])
		}
		return string(out)
	}

	nextHWND := uint64(0x00050001) // window handle space
	hwndAlloc := func() uint64 {
		h := nextHWND
		nextHWND++
		return h
	}
	nextMsgID := uint32(0xC000) // RegisterWindowMessage range
	nextAtom := uint16(0xC001)  // RegisterClass atom range
	var focusHwnd uint64 // currently focused window (receives keyboard input)

	// WndProc dispatch tables
	atomWndProc := make(map[uint16]uint64)   // class atom → WndProc address
	hwndWndProc := make(map[uint64]uint64)   // HWND → WndProc address
	classNameAtom := make(map[string]uint16) // class name → atom (for lpClassName string lookups)
	classMenuHandle := make(map[uint16]uint64) // class atom → loaded menu handle
	classBrush := make(map[uint16]uint32)      // class atom → hbrBackground (COLOR_xxx+1 index)
	hwndClassAtom := make(map[uint64]uint16)   // HWND → class atom (for brush lookup)

	// Built-in window class tracking for Edit, Static, Button, etc.
	type treeItem struct {
		handle   uint64
		parent   uint64 // parent HTREEITEM (0 = root, TVI_ROOT = 0xFFFF0000)
		text     string
		children []uint64
		expanded bool
		lParam   uint64
	}
	type listColumn struct {
		text  string
		width int32
	}
	type controlState struct {
		className    string
		parentHWND   uint64
		x, y, w, h  int32
		text         string   // WM_SETTEXT / WM_GETTEXT
		visible      bool
		// StatusBar parts
		sbParts      []int32  // right edges
		sbTexts      []string // per-part text
		// Edit state
		editModified bool
		// TreeView state
		tvItems      map[uint64]*treeItem
		tvNextHandle uint64
		tvRoots      []uint64 // root-level items
		// ListView state
		lvColumns    []listColumn
	}
	hwndChildren := make(map[uint64]*controlState)

	// clientAreaOrigin returns the absolute (surface) coordinates of a
	// window's client-area top-left. For mainHWND with a menu bar the
	// client area starts below the menu; for child windows it's their
	// stored (absolute) position.
	clientAreaOrigin := func(hwnd uint64) (int32, int32) {
		if cs, ok := hwndChildren[hwnd]; ok {
			return cs.x, cs.y
		}
		if hwnd == mainHWND {
			if _, hasMenu := hwndMenuBar[mainHWND]; hasMenu {
				return 0, menuBarHeight
			}
		}
		return 0, 0
	}

	// paintTree recursively paints a window's child tree in creation
	// order (sorted by HWND) so that containers are filled before their
	// contents are drawn on top. Assigned after builtinWndProc.
	var paintTree func(parentHwnd uint64)

	// --- comctl32.dll ---
	delayHandlerRegistrars = append(delayHandlerRegistrars, func() {
	if comctl32, ok := synthByName["comctl32.dll"]; ok {
		d.RegisterAutoStubHandler(comctl32, "InitCommonControls", func(ctx *ntapi.TrapContext) uint32 {
			return 0 // void function
		})
		d.RegisterAutoStubHandler(comctl32, "InitCommonControlsEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})

		// CreateStatusWindowW: creates a status bar child window
		d.RegisterAutoStubHandler(comctl32, "CreateStatusWindowW", func(ctx *ntapi.TrapContext) uint32 {
			style := uint32(ctx.Arg(0))
			_ = ctx.Arg(1) // lpszText
			hwndParent := ctx.Arg(2)
			_ = ctx.Arg(3) // wID
			hwnd := hwndAlloc()
			var defW, defH int32 = 800, 600
			if wlWindow != nil { defW, defH = wlWindow.Width, wlWindow.Height }
			const sbHeight int32 = 20
			hwndChildren[hwnd] = &controlState{
				className:  "msctls_statusbar32",
				parentHWND: hwndParent,
				x: 0, y: defH - sbHeight, w: defW, h: sbHeight,
				visible: style&0x10000000 != 0,
			}
			ravelog.Logf("[comctl32] CreateStatusWindowW hwnd=0x%x parent=0x%x\n", hwnd, hwndParent)
			ctx.SetReturn(hwnd)
			return 0
		})

		// ImageList_Create: return a fake handle
		var nextImageList uint64 = 0x90000
		imageListCount := map[uint64]uint64{} // handle → count
		d.RegisterAutoStubHandler(comctl32, "ImageList_Create", func(ctx *ntapi.TrapContext) uint32 {
			nextImageList++
			imageListCount[nextImageList] = 0
			ctx.SetReturn(nextImageList)
			return 0
		})

		// ImageList_AddIcon / ImageList_ReplaceIcon
		d.RegisterAutoStubHandler(comctl32, "ImageList_ReplaceIcon", func(ctx *ntapi.TrapContext) uint32 {
			himl := ctx.Arg(0)
			idx := imageListCount[himl]
			imageListCount[himl]++
			ctx.SetReturn(idx)
			return 0
		})

		// ImageList_SetImageCount
		d.RegisterAutoStubHandler(comctl32, "ImageList_SetImageCount", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})

		// ImageList_GetImageCount
		d.RegisterAutoStubHandler(comctl32, "ImageList_GetImageCount", func(ctx *ntapi.TrapContext) uint32 {
			himl := ctx.Arg(0)
			count := imageListCount[himl]
			ctx.SetReturn(count)
			return 0
		})

		// ImageList_Destroy
		d.RegisterAutoStubHandler(comctl32, "ImageList_Destroy", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
	}
	})
	delayHandlerRegistrars[len(delayHandlerRegistrars)-1]()

	// --- ole32.dll ---
	delayHandlerRegistrars = append(delayHandlerRegistrars, func() {
	if ole32, ok := synthByName["ole32.dll"]; ok {
		d.RegisterAutoStubHandler(ole32, "CoInitializeEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // S_OK
			return 0
		})
		d.RegisterAutoStubHandler(ole32, "CoInitializeSecurity", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // S_OK
			return 0
		})
		d.RegisterAutoStubHandler(ole32, "CoCreateInstance", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x80004005) // E_FAIL - COM not available
			return 0
		})
		d.RegisterAutoStubHandler(ole32, "CoUninitialize", func(ctx *ntapi.TrapContext) uint32 {
			return 0
		})
		d.RegisterAutoStubHandler(ole32, "OleInitialize", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // S_OK
			return 0
		})
		d.RegisterAutoStubHandler(ole32, "OleUninitialize", func(ctx *ntapi.TrapContext) uint32 {
			return 0
		})
	}
	})
	delayHandlerRegistrars[len(delayHandlerRegistrars)-1]()

	// --- oleaut32.dll ---
	delayHandlerRegistrars = append(delayHandlerRegistrars, func() {
	if oleaut32, ok := synthByName["oleaut32.dll"]; ok {
		d.RegisterAutoStubHandler(oleaut32, "SysAllocString", func(ctx *ntapi.TrapContext) uint32 {
			// Allocate a copy of the BSTR in guest memory
			src := ctx.Arg(0)
			if src == 0 {
				ctx.SetReturn(0)
				return 0
			}
			// Count wchar_t length
			n := uint64(0)
			for {
				w, _ := ctx.Mem.Read16(src + n*2)
				if w == 0 {
					break
				}
				n++
			}
			// BSTR layout: 4-byte length prefix + wchar data + null terminator
			buf := mem.Mmap(0, 4+n*2+2, mmu.PermRead|mmu.PermWrite)
			ctx.Mem.Write32(buf, uint32(n*2))
			for i := uint64(0); i < n; i++ {
				w, _ := ctx.Mem.Read16(src + i*2)
				ctx.Mem.Write16(buf+4+i*2, w)
			}
			ctx.SetReturn(buf + 4) // BSTR points past length prefix
			return 0
		})
		d.RegisterAutoStubHandler(oleaut32, "SysFreeString", func(ctx *ntapi.TrapContext) uint32 {
			return 0
		})
	}
	})
	delayHandlerRegistrars[len(delayHandlerRegistrars)-1]()

	// Message queue for synthetic messages (WM_CREATE, WM_SIZE, etc.)
	type queuedMsg struct {
		hwnd    uint64
		message uint32
		wParam  uint64
		lParam  uint64
	}
	var msgQueue []queuedMsg

	// builtinWndProc handles messages for built-in window classes (Edit, StatusBar, etc.)
	// Returns (result, handled).
	var builtinWndProc func(hwnd uint64, msg uint32, wParam, lParam uint64) (uint64, bool)
	builtinWndProc = func(hwnd uint64, msg uint32, wParam, lParam uint64) (uint64, bool) {
		cs, ok := hwndChildren[hwnd]
		if !ok {
			return 0, false
		}

		switch msg {
		case 0x000F: // WM_PAINT
			if wlWindow == nil {
				return 0, true
			}
			switch cs.className {
			case "edit":
				// 3D sunken border
				wlWindow.DrawRect(cs.x, cs.y, cs.x+cs.w, cs.y+1, sysColors[16])   // top shadow
				wlWindow.DrawRect(cs.x, cs.y, cs.x+1, cs.y+cs.h, sysColors[16])   // left shadow
				wlWindow.DrawRect(cs.x+1, cs.y+1, cs.x+cs.w-1, cs.y+2, 0x404040)  // inner top
				wlWindow.DrawRect(cs.x+1, cs.y+1, cs.x+2, cs.y+cs.h-1, 0x404040)  // inner left
				wlWindow.DrawRect(cs.x+cs.w-1, cs.y, cs.x+cs.w, cs.y+cs.h, sysColors[20]) // right highlight
				wlWindow.DrawRect(cs.x, cs.y+cs.h-1, cs.x+cs.w, cs.y+cs.h, sysColors[20]) // bottom highlight
				wlWindow.DrawRect(cs.x+cs.w-2, cs.y+1, cs.x+cs.w-1, cs.y+cs.h-1, 0xDFDFDF) // inner right
				wlWindow.DrawRect(cs.x+1, cs.y+cs.h-2, cs.x+cs.w-1, cs.y+cs.h-1, 0xDFDFDF) // inner bottom
				// White client area
				wlWindow.DrawRect(cs.x+2, cs.y+2, cs.x+cs.w-2, cs.y+cs.h-2, sysColors[5])
				// Draw text content
				if cs.text != "" {
					wlWindow.DrawText(cs.x+4, cs.y+4, cs.text, 0x000000, sysColors[5], true)
				}
				// Text cursor (blinking caret)
				cursorX := cs.x + 4
				if cs.text != "" {
					cursorX += int32(len(cs.text)) * 8
				}
				wlWindow.DrawRect(cursorX, cs.y+4, cursorX+1, cs.y+4+16, 0x000000)
			case "msctls_statusbar32":
				// Top edge: etched line (shadow + highlight)
				wlWindow.DrawRect(cs.x, cs.y, cs.x+cs.w, cs.y+1, sysColors[16])   // shadow
				wlWindow.DrawRect(cs.x, cs.y+1, cs.x+cs.w, cs.y+2, sysColors[20]) // highlight
				// Face
				wlWindow.DrawRect(cs.x, cs.y+2, cs.x+cs.w, cs.y+cs.h, sysColors[15])
				// Draw parts text
				if len(cs.sbParts) > 0 {
					left := cs.x + 2
					for i, rightEdge := range cs.sbParts {
						right := cs.x + rightEdge
						if rightEdge < 0 { right = cs.x + cs.w }
						// Sunken part area
						wlWindow.DrawRect(left, cs.y+3, right-1, cs.y+4, sysColors[16])     // top shadow
						wlWindow.DrawRect(left, cs.y+3, left+1, cs.y+cs.h-2, sysColors[16]) // left shadow
						wlWindow.DrawRect(left, cs.y+cs.h-2, right-1, cs.y+cs.h-1, sysColors[20]) // bottom highlight
						wlWindow.DrawRect(right-2, cs.y+3, right-1, cs.y+cs.h-1, sysColors[20])   // right highlight
						if i < len(cs.sbTexts) && cs.sbTexts[i] != "" {
							wlWindow.DrawText(left+4, cs.y+4, cs.sbTexts[i], 0x000000, sysColors[15], true)
						}
						left = right
					}
				} else if cs.text != "" {
					wlWindow.DrawText(cs.x+4, cs.y+4, cs.text, 0x000000, sysColors[15], true)
				}
				// Sizing grip (small triangular area in bottom-right)
				gripX := cs.x + cs.w - 14
				gripY := cs.y + cs.h - 14
				for i := int32(0); i < 3; i++ {
					ox := gripX + i*4 + 2
					oy := gripY + (2-i)*4 + 2
					wlWindow.DrawRect(ox, oy, ox+2, oy+2, sysColors[20])
					wlWindow.DrawRect(ox+1, oy+1, ox+3, oy+3, sysColors[16])
				}
			case "static":
				wlWindow.DrawRect(cs.x, cs.y, cs.x+cs.w, cs.y+cs.h, sysColors[15])
				if cs.text != "" {
					wlWindow.DrawText(cs.x+2, cs.y+2, cs.text, 0x000000, sysColors[15], true)
				}
			case "button":
				wlWindow.DrawRect(cs.x, cs.y, cs.x+cs.w, cs.y+cs.h, sysColors[15])
				wlWindow.DrawRect(cs.x, cs.y, cs.x+cs.w, cs.y+1, sysColors[20])
				wlWindow.DrawRect(cs.x, cs.y, cs.x+1, cs.y+cs.h, sysColors[20])
				wlWindow.DrawRect(cs.x, cs.y+cs.h-1, cs.x+cs.w, cs.y+cs.h, sysColors[16])
				wlWindow.DrawRect(cs.x+cs.w-1, cs.y, cs.x+cs.w, cs.y+cs.h, sysColors[16])
				if cs.text != "" {
					tx := cs.x + (cs.w-int32(len(cs.text)*8))/2
					ty := cs.y + (cs.h-16)/2
					wlWindow.DrawText(tx, ty, cs.text, 0x000000, sysColors[15], true)
				}
			case "systreeview32":
				// 3D sunken border + white area
				wlWindow.DrawRect(cs.x, cs.y, cs.x+cs.w, cs.y+1, sysColors[16])
				wlWindow.DrawRect(cs.x, cs.y, cs.x+1, cs.y+cs.h, sysColors[16])
				wlWindow.DrawRect(cs.x+cs.w-1, cs.y, cs.x+cs.w, cs.y+cs.h, sysColors[20])
				wlWindow.DrawRect(cs.x, cs.y+cs.h-1, cs.x+cs.w, cs.y+cs.h, sysColors[20])
				wlWindow.DrawRect(cs.x+1, cs.y+1, cs.x+cs.w-1, cs.y+cs.h-1, sysColors[5])
				// Render tree items
				if cs.tvItems != nil {
					ty := cs.y + 2
					const itemHeight int32 = 18
					var renderTree func(items []uint64, indent int32)
					renderTree = func(items []uint64, indent int32) {
						for _, h := range items {
							ti, ok := cs.tvItems[h]
							if !ok || ty > cs.y+cs.h-2 {
								continue
							}
							tx := cs.x + 4 + indent*16
							// Draw expand/collapse marker if has children
							if len(ti.children) > 0 {
								mx := tx - 10
								my := ty + 4
								// Small box with +/-
								wlWindow.DrawRect(mx-4, my-4, mx+5, my+5, sysColors[5])
								wlWindow.DrawRect(mx-4, my-4, mx+5, my-5+1, sysColors[16])
								wlWindow.DrawRect(mx-4, my-4, mx-4+1, my+5, sysColors[16])
								wlWindow.DrawRect(mx+4, my-4, mx+5, my+5, sysColors[16])
								wlWindow.DrawRect(mx-4, my+4, mx+5, my+5, sysColors[16])
								// Horizontal line (always)
								wlWindow.DrawRect(mx-2, my, mx+3, my+1, 0x000000)
								if !ti.expanded {
									// Vertical line (plus sign)
									wlWindow.DrawRect(mx, my-2, mx+1, my+3, 0x000000)
								}
							}
							// Draw item text
							if ti.text != "" {
								wlWindow.DrawText(tx, ty+1, ti.text, 0x000000, sysColors[5], true)
							}
							ty += itemHeight
							if ti.expanded {
								renderTree(ti.children, indent+1)
							}
						}
					}
					renderTree(cs.tvRoots, 1)
				}
			case "syslistview32":
				// 3D sunken border + white area with column header
				wlWindow.DrawRect(cs.x, cs.y, cs.x+cs.w, cs.y+1, sysColors[16])
				wlWindow.DrawRect(cs.x, cs.y, cs.x+1, cs.y+cs.h, sysColors[16])
				wlWindow.DrawRect(cs.x+cs.w-1, cs.y, cs.x+cs.w, cs.y+cs.h, sysColors[20])
				wlWindow.DrawRect(cs.x, cs.y+cs.h-1, cs.x+cs.w, cs.y+cs.h, sysColors[20])
				wlWindow.DrawRect(cs.x+1, cs.y+1, cs.x+cs.w-1, cs.y+cs.h-1, sysColors[5])
				// Header area with column names
				wlWindow.DrawRect(cs.x+1, cs.y+1, cs.x+cs.w-1, cs.y+21, sysColors[15])
				wlWindow.DrawRect(cs.x+1, cs.y+21, cs.x+cs.w-1, cs.y+22, sysColors[16])
				if len(cs.lvColumns) > 0 {
					colX := cs.x + 2
					for _, col := range cs.lvColumns {
						if col.text != "" {
							wlWindow.DrawText(colX+4, cs.y+3, col.text, 0x000000, sysColors[15], true)
						}
						colX += col.width
						// Column separator
						wlWindow.DrawRect(colX-1, cs.y+1, colX, cs.y+21, sysColors[16])
					}
				}
			case "systabcontrol32":
				wlWindow.DrawRect(cs.x, cs.y, cs.x+cs.w, cs.y+cs.h, sysColors[15])
				wlWindow.DrawRect(cs.x, cs.y+24, cs.x+cs.w, cs.y+25, sysColors[16])
			default:
				// For app-defined child windows with a guest WndProc, let it handle WM_PAINT
				if wp, ok := hwndWndProc[hwnd]; ok && wp != 0 {
					// Fill background then let guest paint
					wlWindow.DrawRect(cs.x, cs.y, cs.x+cs.w, cs.y+cs.h, sysColors[15])
					return 0, false
				}
				// Generic control: just fill background
				wlWindow.DrawRect(cs.x, cs.y, cs.x+cs.w, cs.y+cs.h, sysColors[15])
			}
			return 0, true

		case 0x000C: // WM_SETTEXT
			if lParam != 0 {
				cs.text = readGuestUTF16(lParam)
			}
			return 1, true

		case 0x000D: // WM_GETTEXT
			return 0, true // TODO: copy text to buffer

		case 0x0005: // WM_SIZE
			// StatusBar auto-sizes to parent width
			if cs.className == "msctls_statusbar32" && wlWindow != nil {
				const sbHeight int32 = 20
				cs.x = 0
				cs.y = wlWindow.Height - sbHeight
				cs.w = wlWindow.Width
				cs.h = sbHeight
			}
			// If there's a guest WndProc, let it handle WM_SIZE too
			if wp, ok := hwndWndProc[hwnd]; ok && wp != 0 {
				return 0, false
			}
			return 0, true

		case 0x0001: // WM_CREATE
			cs.visible = true
			// If there's a guest WndProc, let it handle WM_CREATE too
			if wp, ok := hwndWndProc[hwnd]; ok && wp != 0 {
				return 0, false
			}
			return 0, true

		case 0x0007: // WM_SETFOCUS
			focusHwnd = hwnd
			return 0, true
		case 0x0008: // WM_KILLFOCUS
			return 0, true
		case 0x0030: // WM_SETFONT
			return 0, true
		}

		// Edit-specific messages
		if cs.className == "edit" {
			switch msg {
			case 0x0102: // WM_CHAR
				ch := rune(wParam)
				if ch == '\b' {
					// Backspace
					if len(cs.text) > 0 {
						runes := []rune(cs.text)
						cs.text = string(runes[:len(runes)-1])
					}
				} else if ch >= 0x20 || ch == '\r' || ch == '\n' || ch == '\t' {
					cs.text += string(ch)
				}
				cs.editModified = true
				// Queue repaint
				msgQueue = append(msgQueue, queuedMsg{mainHWND, 0x000F, 0, 0})
				return 0, true
			case 0x0100: // WM_KEYDOWN
				return 0, true
			case 0x0101: // WM_KEYUP
				return 0, true
			case 0x000C: // WM_SETTEXT
				if lParam != 0 {
					cs.text = readGuestUTF16(lParam)
				}
				return 1, true
			case 0x000D: // WM_GETTEXT
				return uint64(len(cs.text)), true
			case 0x000E: // WM_GETTEXTLENGTH
				return uint64(len(cs.text)), true
			case 0x00B7: // EM_SETMODIFY
				cs.editModified = wParam != 0
				return 0, true
			case 0x00B8: // EM_GETMODIFY
				if cs.editModified { return 1, true }
				return 0, true
			case 0x00B1: // EM_SETSEL
				return 0, true
			case 0x00B0: // EM_GETSEL
				// wParam = *DWORD start, lParam = *DWORD end
				if wParam != 0 { mem.Write32(wParam, 0) }
				if lParam != 0 { mem.Write32(lParam, 0) }
				return 0, true
			case 0x00C5: // EM_SETLIMITTEXT
				return 0, true
			case 0x00D3: // EM_SETMARGINS
				return 0, true
			case 0x00C9: // EM_SETREADONLY
				return 1, true
			case 0x00BB: // EM_GETTHUMB
				return 0, true
			case 0x00B2: // EM_GETRECT
				if lParam != 0 {
					mem.Write32(lParam, 0)
					mem.Write32(lParam+4, 0)
					mem.Write32(lParam+8, uint32(cs.w))
					mem.Write32(lParam+12, uint32(cs.h))
				}
				return 0, true
			case 0x00B3: // EM_SETRECT
				return 0, true
			case 0x00CF: // EM_POSFROMCHAR
				return 0, true
			case 0x00D7: // EM_CHARFROMPOS
				return 0, true
			case 0x00BE: // EM_GETLINECOUNT
				return 1, true
			case 0x00C1: // EM_GETLINE
				return 0, true
			case 0x00B6: // EM_LINEFROMCHAR
				return 0, true
			case 0x00B9: // EM_LINEINDEX
				return 0, true
			case 0x00C4: // EM_LINELENGTH
				return uint64(len(cs.text)), true
			}
		}

		// StatusBar-specific messages (SB_xxx: WM_USER+x)
		if cs.className == "msctls_statusbar32" {
			const wmUser = 0x0400
			switch msg {
			case wmUser + 4: // SB_SETPARTS
				nParts := int(wParam)
				if nParts > 0 && nParts < 256 && lParam != 0 {
					cs.sbParts = make([]int32, nParts)
					cs.sbTexts = make([]string, nParts)
					for i := 0; i < nParts; i++ {
						v, _ := mem.Read32(lParam + uint64(i*4))
						cs.sbParts[i] = int32(v)
					}
				}
				return 1, true
			case wmUser + 11: // SB_SETTEXTW (unicode)
				part := int(wParam & 0xFF)
				// Auto-grow parts array if needed
				for len(cs.sbTexts) <= part {
					cs.sbTexts = append(cs.sbTexts, "")
				}
				for len(cs.sbParts) <= part {
					cs.sbParts = append(cs.sbParts, -1)
				}
				if lParam != 0 {
					cs.sbTexts[part] = readGuestUTF16(lParam)
				}
				return 1, true
			case wmUser + 1: // SB_SETTEXTA
				part := int(wParam & 0xFF)
				for len(cs.sbTexts) <= part {
					cs.sbTexts = append(cs.sbTexts, "")
				}
				for len(cs.sbParts) <= part {
					cs.sbParts = append(cs.sbParts, -1)
				}
				if lParam != 0 {
					// Read ASCII string
					var buf []byte
					for i := uint64(0); i < 256; i++ {
						b, err := mem.Read8(lParam + i)
						if err != nil || b == 0 { break }
						buf = append(buf, b)
					}
					cs.sbTexts[part] = string(buf)
				}
				return 1, true
			case wmUser + 5: // SB_GETPARTS
				return uint64(len(cs.sbParts)), true
			case wmUser + 3: // SB_GETTEXTLENGTHW
				part := int(wParam)
				if part >= 0 && part < len(cs.sbTexts) {
					return uint64(len(cs.sbTexts[part])), true
				}
				return 0, true
			case wmUser + 13: // SB_GETTEXTW
				return 0, true
			case wmUser + 9: // SB_ISSIMPLE
				return 0, true
			case wmUser + 6: // SB_GETBORDERS
				return 0, true
			}
		}

		// TreeView messages (TVM_xxx = TV_FIRST + x, TV_FIRST = 0x1100)
		if cs.className == "systreeview32" {
			const tvFirst = 0x1100
			if cs.tvItems == nil {
				cs.tvItems = make(map[uint64]*treeItem)
				cs.tvNextHandle = 0x10001
			}
			switch msg {
			case tvFirst + 0, tvFirst + 50: // TVM_INSERTITEMA, TVM_INSERTITEMW
				// lParam → TVINSERTSTRUCTW
				if lParam == 0 {
					return 0, true
				}
				hParent, _ := mem.Read64(lParam)
				// hInsertAfter at lParam+8 (ignored for now)
				// TVITEMEXW starts at lParam+16
				itemBase := lParam + 16
				mask, _ := mem.Read32(itemBase)
				// x64 TVITEMEXW layout: mask(4)+pad(4), hItem(8), state(4)+stateMask(4), pszText(8), cchTextMax(4)+iImage(4), iSelectedImage(4)+cChildren(4), lParam(8)
				pszText, _ := mem.Read64(itemBase + 24)
				itemLParam, _ := mem.Read64(itemBase + 48)

				text := ""
				const tvifText = 0x0001
				const lpstrTextcallback = 0xFFFFFFFFFFFFFFFF
				if mask&tvifText != 0 && pszText != 0 && pszText != lpstrTextcallback {
					if msg == tvFirst+50 { // wide
						text = readGuestUTF16(pszText)
					} else { // ansi
						text = readGuestString(pszText)
					}
				}

				h := cs.tvNextHandle
				cs.tvNextHandle++
				ti := &treeItem{handle: h, parent: hParent, text: text, lParam: itemLParam, expanded: true}
				cs.tvItems[h] = ti

				const tviRoot uint64 = 0xFFFFFFFFFFFF0000
				if hParent == 0 || hParent == tviRoot || hParent == 0xFFFF0000 {
					cs.tvRoots = append(cs.tvRoots, h)
				} else if pt, ok := cs.tvItems[hParent]; ok {
					pt.children = append(pt.children, h)
				} else {
					cs.tvRoots = append(cs.tvRoots, h)
				}
				return h, true
			case tvFirst + 2:  // TVM_DELETEITEM
				return 1, true
			case tvFirst + 1:  // TVM_EXPAND
				return 1, true
			case tvFirst + 9:  // TVM_SETIMAGELIST
				return 0, true
			case tvFirst + 8:  // TVM_GETIMAGELIST
				return 0, true
			case tvFirst + 11: // TVM_SELECTITEM
				return 1, true
			case tvFirst + 13: // TVM_GETITEMW
				// lParam → TVITEMEXW, read hItem from offset 8
				if lParam != 0 {
					mask, _ := mem.Read32(lParam)
					hItem, _ := mem.Read64(lParam + 8)
					if ti, ok := cs.tvItems[hItem]; ok {
						const tvifText = 0x0001
						if mask&tvifText != 0 {
							pszText, _ := mem.Read64(lParam + 24)
							cchMax, _ := mem.Read32(lParam + 32)
							if pszText != 0 && cchMax > 0 {
								nameU16 := utf16Encode(ti.text)
								limit := int(cchMax) - 1
								if len(nameU16) > limit {
									nameU16 = nameU16[:limit]
								}
								for i, ch := range nameU16 {
									mem.Write16(pszText+uint64(i)*2, ch)
								}
								mem.Write16(pszText+uint64(len(nameU16))*2, 0)
							}
						}
						return 1, true
					}
				}
				return 0, true
			case tvFirst + 63: // TVM_SETITEMW
				return 1, true
			case tvFirst + 14: // TVM_EDITLABELW
				return 0, true
			case tvFirst + 26: // TVM_GETCOUNT
				return uint64(len(cs.tvItems)), true
			default:
				if msg >= tvFirst && msg < tvFirst+100 {
					return 0, true
				}
			}
		}

		// ListView messages (LVM_xxx = LV_FIRST + x, LV_FIRST = 0x1000)
		if cs.className == "syslistview32" {
			const lvFirst = 0x1000
			switch msg {
			case lvFirst + 0:  // LVM_GETBKCOLOR
				return 0xFFFFFF, true
			case lvFirst + 1:  // LVM_SETBKCOLOR
				return 1, true
			case lvFirst + 2:  // LVM_GETIMAGELIST
				return 0, true
			case lvFirst + 3:  // LVM_SETIMAGELIST
				return 0, true
			case lvFirst + 4:  // LVM_GETITEMCOUNT
				return 0, true
			case lvFirst + 7:  // LVM_INSERTITEMA
				return 0, true
			case lvFirst + 77: // LVM_INSERTITEMW
				return 0, true
			case lvFirst + 8:  // LVM_DELETEITEM
				return 1, true
			case lvFirst + 9:  // LVM_DELETEALLITEMS
				return 1, true
			case lvFirst + 27: // LVM_INSERTCOLUMNA
				if lParam != 0 {
					// LVCOLUMNA: mask(4) pad(4) fmt(4) cx(4) pszText(8) ...
					mask, _ := mem.Read32(lParam)
					cx, _ := mem.Read32(lParam + 8)
					pszText, _ := mem.Read64(lParam + 16)
					text := ""
					if mask&0x0004 != 0 && pszText != 0 { // LVCF_TEXT
						text = readGuestString(pszText)
					}
					width := int32(cx)
					if width == 0 {
						width = 100
					}
					cs.lvColumns = append(cs.lvColumns, listColumn{text: text, width: width})
				}
				return uint64(len(cs.lvColumns) - 1), true
			case lvFirst + 97: // LVM_INSERTCOLUMNW
				if lParam != 0 {
					mask, _ := mem.Read32(lParam)
					cx, _ := mem.Read32(lParam + 8)
					pszText, _ := mem.Read64(lParam + 16)
					text := ""
					if mask&0x0004 != 0 && pszText != 0 { // LVCF_TEXT
						text = readGuestUTF16(pszText)
					}
					width := int32(cx)
					if width == 0 {
						width = 100
					}
					cs.lvColumns = append(cs.lvColumns, listColumn{text: text, width: width})
				}
				return uint64(len(cs.lvColumns) - 1), true
			case lvFirst + 30: // LVM_SETCOLUMNWIDTH
				return 1, true
			case lvFirst + 31: // LVM_CREATEDRAGIMAGE
				return 0, true
			case lvFirst + 54: // LVM_SETEXTENDEDLISTVIEWSTYLE
				return 0, true
			case lvFirst + 55: // LVM_GETEXTENDEDLISTVIEWSTYLE
				return 0, true
			default:
				if msg >= lvFirst && msg < lvFirst+200 {
					return 0, true
				}
			}
		}

		return 0, false
	}

	// Assign paintTree now that builtinWndProc is defined
	paintTree = func(parentHwnd uint64) {
		var children []uint64
		for h, cs := range hwndChildren {
			if cs.parentHWND == parentHwnd && cs.visible {
				children = append(children, h)
			}
		}
		sort.Slice(children, func(i, j int) bool { return children[i] < children[j] })
		for _, h := range children {
			builtinWndProc(h, 0x000F, 0, 0)
			paintTree(h)
		}
	}
	windowLongPtr := make(map[uint64]map[int32]uint64) // HWND → index → value
	// Per-window properties: SetPropW / GetPropW
	windowProps := make(map[uint64]map[string]uint64) // HWND → prop name → value

	// Scratch page for CREATESTRUCT and similar temporary guest-side structs
	scratchPage := mem.Mmap(0, 4096, mmu.PermRead|mmu.PermWrite)
	scratchOff := uint64(0)
	scratchAlloc := func(n uint64) uint64 {
		n = (n + 7) &^ 7 // 8-byte align
		if scratchOff+n > 4096 {
			scratchOff = 0 // wrap
		}
		addr := scratchPage + scratchOff
		scratchOff += n
		return addr
	}

	// Synchronous WndProc dispatch for CreateWindowExW.
	// In real Win32, CreateWindowExW sends WM_NCCREATE/WM_CREATE synchronously
	// before returning the HWND. We implement this with a trampoline vmcall.
	type syncDispatch struct {
		wndProc uint64
		hwnd    uint64
		msg     uint32
		wParam  uint64
		lParam  uint64
	}
	type syncDispatchFrame struct {
		queue   []syncDispatch
		retAddr uint64
		hwnd    uint64
	}
	var syncStack []syncDispatchFrame

	const syncTrampolineID = 0x3FFE
	// Allocate a trampoline: MOV EAX, syncTrampolineID; vmcall; ret
	syncTrampoline := mem.Mmap(0, 4096, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	mem.Write8(syncTrampoline, 0xB8)                          // MOV EAX, imm32
	mem.Write32(syncTrampoline+1, syncTrampolineID)
	mem.Write8(syncTrampoline+5, 0x0F)                        // vmcall
	mem.Write8(syncTrampoline+6, 0x01)
	mem.Write8(syncTrampoline+7, 0xC1)
	mem.Write8(syncTrampoline+8, 0xC3)                        // ret

	d.RegisterHandler(syncTrampolineID, "syncDispatchTrampoline", func(ctx *ntapi.TrapContext) uint32 {
		rw, ok := ctx.CPU.(ntapi.RegisterWriter)
		if !ok {
			return 0
		}
		rr, ok2 := ctx.CPU.(ntapi.RegisterReader)
		if !ok2 {
			return 0
		}
		if len(syncStack) == 0 {
			return 0
		}
		frame := &syncStack[len(syncStack)-1]

		if len(frame.queue) > 0 {
			sd := frame.queue[0]
			frame.queue = frame.queue[1:]

			// Push trampoline as return address
			rsp := rr.ReadReg(4) // RSP
			rsp -= 8
			mem.Write64(rsp, syncTrampoline)
			rw.WriteReg(4, rsp) // update RSP

			// Set up WndProc args (x64 calling convention)
			rw.WriteReg(1, sd.hwnd)          // RCX = hwnd
			rw.WriteReg(2, uint64(sd.msg))   // RDX = msg
			rw.WriteReg(8, sd.wParam)        // R8 = wParam
			rw.WriteReg(9, sd.lParam)        // R9 = lParam

			ctx.CPU.SetPC(sd.wndProc)
			ctx.ReturnOverridden = true
			return 0
		}

		// Queue empty: all sync dispatches done. Pop frame and return HWND.
		retAddr := frame.retAddr
		hwnd := frame.hwnd
		syncStack = syncStack[:len(syncStack)-1]

		rsp := rr.ReadReg(4) // RSP
		rsp -= 8
		mem.Write64(rsp, retAddr)
		rw.WriteReg(4, rsp)
		ctx.SetReturn(hwnd)
		return 0
	})

	// --- user32.dll ---
	delayHandlerRegistrars = append(delayHandlerRegistrars, func() {
	if user32, ok := synthByName["user32.dll"]; ok {
		// LoadStringW: load string resource from PE
		d.RegisterAutoStubHandler(user32, "LoadStringW", func(ctx *ntapi.TrapContext) uint32 {
			uID := uint32(ctx.Arg(1))
			lpBuffer := ctx.Arg(2)
			cchBufferMax := int(int32(ctx.Arg(3)))
			s, guestAddr, slen := peLoadStringW(uID)
			if s != "" {
				ravelog.Logf("[loadstr] id=%d → %q\n", uID, s)
			}
			if s == "" || lpBuffer == 0 {
				ctx.SetReturn(0)
				return 0
			}
			// When cchBufferMax == 0, return a read-only pointer to the resource string
			if cchBufferMax == 0 {
				mem.Write64(lpBuffer, guestAddr)
				ctx.SetReturn(uint64(slen))
				return 0
			}
			runes := []rune(s)
			n := len(runes)
			if n >= cchBufferMax {
				n = cchBufferMax - 1
			}
			for i := 0; i < n; i++ {
				mem.Write16(lpBuffer+uint64(i)*2, uint16(runes[i]))
			}
			mem.Write16(lpBuffer+uint64(n)*2, 0)
			ctx.SetReturn(uint64(n))
			return 0
		})
		d.RegisterAutoStubHandler(user32, "IsDialogMessageW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE - not a dialog message
			return 0
		})
		d.RegisterAutoStubHandler(user32, "GetWindowTextLengthW", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			if cs, ok := hwndChildren[hwnd]; ok && cs.text != "" {
				ctx.SetReturn(uint64(len([]rune(cs.text))))
			} else if hwnd == mainHWND && mainTitle != "" {
				ctx.SetReturn(uint64(len([]rune(mainTitle))))
			} else {
				ctx.SetReturn(0)
			}
			return 0
		})
		d.RegisterAutoStubHandler(user32, "MonitorFromRect", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0xD0000001) // fake monitor handle
			return 0
		})
		d.RegisterAutoStubHandler(user32, "LoadAcceleratorsW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0xA0000001) // fake accelerator table handle
			return 0
		})
		// wsprintfW(lpOut, lpFmt, ...) - varargs format, returns char count
		d.RegisterAutoStubHandler(user32, "wsprintfW", func(ctx *ntapi.TrapContext) uint32 {
			lpOut := ctx.Arg(0)
			lpFmt := ctx.Arg(1)
			fmtStr := readGuestUTF16(lpFmt)
			var args []uint64
			for i := 2; i < 10; i++ {
				args = append(args, ctx.Arg(i))
			}
			result := wideprintf(fmtStr, args)
			for i, r := range result {
				mem.Write16(lpOut+uint64(i)*2, uint16(r))
			}
			mem.Write16(lpOut+uint64(len([]rune(result)))*2, 0)
			ctx.SetReturn(uint64(len([]rune(result))))
			return 0
		})
		d.RegisterAutoStubHandler(user32, "RegisterClassW", func(ctx *ntapi.TrapContext) uint32 {
			// WNDCLASSW layout (x64): style(4)+pad(4), lpfnWndProc(8), cbClsExtra(4)+cbWndExtra(4),
			//   hInstance(8), hIcon(8), hCursor(8), hbrBackground(8), lpszMenuName(8), lpszClassName(8)
			pClass := ctx.Arg(0)
			a := nextAtom
			nextAtom++
			if pClass != 0 {
				wndProc, _ := mem.Read64(pClass + 8)
				atomWndProc[a] = wndProc
				// hbrBackground at offset 48 (same as WNDCLASSEXW: style+pad and cbSize+style both = 8 bytes)
				hBrush, _ := mem.Read64(pClass + 48)
				if hBrush > 0 && hBrush <= 30 {
					classBrush[a] = uint32(hBrush)
				}
				lpMenuName, _ := mem.Read64(pClass + 56)
				lpName, _ := mem.Read64(pClass + 64)
				name := readGuestUTF16(lpName)
				if name != "" {
					classNameAtom[name] = a
				}
				// Load menu from lpszMenuName (same as RegisterClassExW)
				if lpMenuName != 0 && mainModule != nil {
					var menuID uint32
					if lpMenuName < 0x10000 {
						menuID = uint32(lpMenuName)
					} else {
						menuName := readGuestUTF16(lpMenuName)
						if id, err := strconv.ParseUint(menuName, 10, 32); err == nil {
							menuID = uint32(id)
						}
					}
					if menuID != 0 {
						if md := peLoadMenuResource(menuID); md != nil {
							h := gdiAlloc()
							menus[h] = md
							classMenuHandle[a] = h
						}
					}
				}
				ravelog.Logf("[wndclass] RegisterClassW %q atom=0x%x wndProc=0x%x brush=%d\n", name, a, wndProc, hBrush)
			}
			ctx.SetReturn(uint64(a))
			return 0
		})
		d.RegisterAutoStubHandler(user32, "RegisterClassExW", func(ctx *ntapi.TrapContext) uint32 {
			// WNDCLASSEXW layout (x64): cbSize(4)+style(4), lpfnWndProc(8), cbClsExtra(4)+cbWndExtra(4),
			//   hInstance(8), hIcon(8), hCursor(8), hbrBackground(8), lpszMenuName(8), lpszClassName(8), hIconSm(8)
			pClass := ctx.Arg(0)
			a := nextAtom
			nextAtom++
			if pClass != 0 {
				wndProc, _ := mem.Read64(pClass + 8)
				atomWndProc[a] = wndProc
				// hbrBackground at offset 48 (cbSize+style+wndProc+cbClsExtra+cbWndExtra+hInstance+hIcon+hCursor)
				hBrush, _ := mem.Read64(pClass + 48)
				if hBrush > 0 && hBrush <= 30 {
					classBrush[a] = uint32(hBrush)
				}
				lpszMenuName, _ := mem.Read64(pClass + 56)
				lpName, _ := mem.Read64(pClass + 64)
				var name string
				if lpName != 0 && lpName < 0x10000 {
					name = fmt.Sprintf("atom:0x%x", lpName)
				} else {
					name = readGuestUTF16(lpName)
				}
				if name != "" {
					classNameAtom[name] = a
				}
				// Load menu from lpszMenuName
				if lpszMenuName != 0 && mainModule != nil {
					var menuID uint32
					if lpszMenuName < 0x10000 {
						menuID = uint32(lpszMenuName)
					} else {
						menuName := readGuestUTF16(lpszMenuName)
						if id, err := strconv.ParseUint(menuName, 10, 32); err == nil {
							menuID = uint32(id)
						}
					}
					if menuID != 0 {
						if md := peLoadMenuResource(menuID); md != nil {
							h := gdiAlloc()
							menus[h] = md
							classMenuHandle[a] = h
						}
					}
				}
				ravelog.Logf("[wndclass] RegisterClassExW name=%q lpName=0x%x atom=0x%x wndProc=0x%x brush=%d\n", name, lpName, a, wndProc, hBrush)
			}
			ctx.SetReturn(uint64(a))
			return 0
		})
		d.RegisterAutoStubHandler(user32, "RegisterWindowMessageW", func(ctx *ntapi.TrapContext) uint32 {
			id := nextMsgID
			nextMsgID++
			ctx.SetReturn(uint64(id))
			return 0
		})
		d.RegisterAutoStubHandler(user32, "CreateWindowExW", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := hwndAlloc()
			lpClassName := ctx.Arg(1)
			style := uint32(ctx.Arg(3))

			// Associate HWND with WndProc via class name or atom
			var className string
			var classAtomForHwnd uint16
			if lpClassName != 0 && lpClassName < 0x10000 {
				// Integer atom
				classAtomForHwnd = uint16(lpClassName)
				if wp, ok := atomWndProc[classAtomForHwnd]; ok {
					hwndWndProc[hwnd] = wp
				}
				className = fmt.Sprintf("atom:0x%x", lpClassName)
			} else if lpClassName != 0 {
				className = readGuestUTF16(lpClassName)
				if a, ok := classNameAtom[className]; ok {
					classAtomForHwnd = a
					if wp, ok2 := atomWndProc[a]; ok2 {
						hwndWndProc[hwnd] = wp
					}
				}
			}
			if classAtomForHwnd != 0 {
				hwndClassAtom[hwnd] = classAtomForHwnd
			}
			wp := hwndWndProc[hwnd]
			ravelog.Logf("[wndclass] CreateWindowExW class=%q hwnd=0x%x wndProc=0x%x style=0x%x\n", className, hwnd, wp, style)

			const wsChild = 0x40000000
			// Track child windows (built-in classes like Edit, Static, Button)
			if style&wsChild != 0 {
				cx := int32(ctx.Arg(4))
				cy := int32(ctx.Arg(5))
				cw := int32(ctx.Arg(6))
				ch := int32(ctx.Arg(7))
				parentHwnd := ctx.Arg(8) // hWndParent
				if cx < 0 || cx > 0x7FFF { cx = 0 }
				if cy < 0 || cy > 0x7FFF { cy = 0 }
				var defW, defH int32 = 800, 600
				if wlWindow != nil { defW, defH = wlWindow.Width, wlWindow.Height }
				if cw <= 0 || cw > 0x7FFF { cw = defW }
				if ch <= 0 || ch > 0x7FFF { ch = defH }
				lClassName := strings.ToLower(className)
				// Statusbar: auto-position at bottom of parent (absolute)
				if lClassName == "msctls_statusbar32" {
					const sbHeight int32 = 20
					cx, cy = 0, defH-sbHeight
					cw, ch = defW, sbHeight
				} else {
					// Convert from parent-relative to absolute coordinates
					ox, oy := clientAreaOrigin(parentHwnd)
					cx += ox
					cy += oy
				}
				windowName := readGuestUTF16(ctx.Arg(2))
				hwndChildren[hwnd] = &controlState{
					className:  lClassName,
					parentHWND: parentHwnd,
					x: cx, y: cy, w: cw, h: ch,
					text:    windowName,
					visible: style&0x10000000 != 0, // WS_VISIBLE
				}
				// Auto-focus first edit control
				if lClassName == "edit" && focusHwnd == 0 {
					focusHwnd = hwnd
				}
			}

			// Create a real Wayland window for the first top-level window
			if wlDisplay != nil && wlWindow == nil {
				if style&wsChild == 0 {
					title := readGuestUTF16(ctx.Arg(2))
					if title == "" {
						title = "govm"
					}
					var w, h int32 = 800, 600
					if nw := int32(ctx.Arg(6)); nw > 0 && nw < 0x7FFF {
						w = nw
					}
					if nh := int32(ctx.Arg(7)); nh > 0 && nh < 0x7FFF {
						h = nh
					}
					if win, err := wlDisplay.CreateWindow(title, w, h); err == nil {
						wlWindow = win
						mainHWND = hwnd
						mainTitle = title
						ravelog.Logf("[wl] window created: %q %dx%d hwnd=0x%x\n", title, w, h, hwnd)
						// Attach menu bar: first check hMenu parameter, then class menu
						hMenu := ctx.Arg(9)
						ravelog.Logf("[menu] CreateWindowExW hMenu=0x%x menus_has=%v\n", hMenu, menus[hMenu] != nil)
						if hMenu != 0 {
							if _, ok := menus[hMenu]; ok {
								hwndMenuBar[hwnd] = hMenu
							}
						}
						if _, hasMenu := hwndMenuBar[hwnd]; !hasMenu && lpClassName != 0 {
							var classAtom uint16
							if lpClassName < 0x10000 {
								classAtom = uint16(lpClassName)
							} else {
								cn := readGuestUTF16(lpClassName)
								classAtom = classNameAtom[cn]
							}
							if mh, ok := classMenuHandle[classAtom]; ok {
								hwndMenuBar[hwnd] = mh
							}
						}
					} else {
						ravelog.Logf("[wl] CreateWindow failed: %v\n", err)
					}
				}
			}
			// Dispatch WM_NCCREATE + WM_CREATE synchronously for windows with a WndProc
			if wp, hasWP := hwndWndProc[hwnd]; hasWP && wp != 0 {
				// Build CREATESTRUCT in guest memory (80 bytes, x64 layout):
				//   0: lpCreateParams(8) 8: hInstance(8) 16: hMenu(8) 24: hwndParent(8)
				//  32: cy(4) 36: cx(4) 40: y(4) 44: x(4)
				//  48: style(4) 52: pad(4) 56: lpszName(8) 64: lpszClass(8) 72: dwExStyle(4)
				cs := scratchAlloc(80)
				mem.Write64(cs+0, ctx.Arg(11))          // lpCreateParams
				mem.Write64(cs+8, ctx.Arg(10))          // hInstance
				mem.Write64(cs+16, ctx.Arg(9))          // hMenu
				mem.Write64(cs+24, ctx.Arg(8))          // hwndParent
				mem.Write32(cs+32, uint32(ctx.Arg(7)))  // cy (nHeight)
				mem.Write32(cs+36, uint32(ctx.Arg(6)))  // cx (nWidth)
				mem.Write32(cs+40, uint32(ctx.Arg(5)))  // y
				mem.Write32(cs+44, uint32(ctx.Arg(4)))  // x
				mem.Write32(cs+48, style)                // style
				mem.Write32(cs+52, 0)                    // padding
				mem.Write64(cs+56, ctx.Arg(2))          // lpszName
				mem.Write64(cs+64, ctx.Arg(1))          // lpszClass
				mem.Write32(cs+72, uint32(ctx.Arg(0)))  // dwExStyle

				// Synchronous dispatch via trampoline:
				// Queue WM_CREATE (dispatched second), then set up WM_NCCREATE (dispatched first).
				rw, ok := ctx.CPU.(ntapi.RegisterWriter)
				rr, ok2 := ctx.CPU.(ntapi.RegisterReader)
				if ok && ok2 {
					// Save original return address and push a new sync frame
					rsp := rr.ReadReg(4) // RSP
					retAddr, _ := mem.Read64(rsp)
					syncStack = append(syncStack, syncDispatchFrame{
						queue:   []syncDispatch{{wndProc: wp, hwnd: hwnd, msg: 0x0001, wParam: 0, lParam: cs}},
						retAddr: retAddr,
						hwnd:    hwnd,
					})
					mem.Write64(rsp, syncTrampoline) // WndProc RET → trampoline

					// Set up WM_NCCREATE call
					rw.WriteReg(1, hwnd)          // RCX = hwnd
					rw.WriteReg(2, 0x0081)        // RDX = WM_NCCREATE
					rw.WriteReg(8, 0)             // R8 = wParam
					rw.WriteReg(9, cs)            // R9 = lParam (CREATESTRUCT)

					ctx.CPU.SetPC(wp)
					ctx.ReturnOverridden = true
					return 0
				}
				// Fallback: queue messages if register access unavailable
				msgQueue = append(msgQueue,
					queuedMsg{hwnd, 0x0081, 0, cs}, // WM_NCCREATE
					queuedMsg{hwnd, 0x0001, 0, cs}, // WM_CREATE
				)
			}

			ctx.SetReturn(hwnd)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "DestroyWindow", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			ravelog.Logf("[destroy] hwnd=0x%x\n", hwnd)
			delete(hwndChildren, hwnd)
			delete(hwndWndProc, hwnd)
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(user32, "ShowWindow", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			nCmdShow := ctx.Arg(1)
			if hwnd == mainHWND && wlWindow != nil {
				w, h := uint64(wlWindow.Width), uint64(wlWindow.Height)
				msgQueue = append(msgQueue, queuedMsg{hwnd, 0x0005, 0, (h << 16) | w})
				msgQueue = append(msgQueue, queuedMsg{hwnd, 0x000F, 0, 0})
			}
			if cs, ok := hwndChildren[hwnd]; ok {
				cs.visible = nCmdShow != 0 // SW_HIDE = 0
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "UpdateWindow", func(ctx *ntapi.TrapContext) uint32 {
			// Trigger immediate paint for main window
			hwnd := ctx.Arg(0)
			if hwnd == mainHWND && wlWindow != nil {
				msgQueue = append(msgQueue, queuedMsg{hwnd, 0x000F, 0, 0})
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "IsChild", func(ctx *ntapi.TrapContext) uint32 {
			parent := ctx.Arg(0)
			child := ctx.Arg(1)
			if cs, ok := hwndChildren[child]; ok && cs.parentHWND == parent {
				ctx.SetReturn(1) // TRUE
			} else {
				ctx.SetReturn(0)
			}
			return 0
		})
		d.RegisterAutoStubHandler(user32, "FindWindowW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // not found
			return 0
		})
		d.RegisterAutoStubHandler(user32, "FindWindowExW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "GetDC", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			h := gdiAlloc()
			ox, oy := clientAreaOrigin(hwnd)
			dcMap[h] = &dcState{textColor: 0x000000, bkColor: 0xFFFFFF, bkMode: 2, isScreen: true, originX: ox, originY: oy}
			ctx.SetReturn(h)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "ReleaseDC", func(ctx *ntapi.TrapContext) uint32 {
			delete(dcMap, ctx.Arg(1))
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "GetSystemMetrics", func(ctx *ntapi.TrapContext) uint32 {
			idx := ctx.Arg(0)
			val := uint64(0)
			switch idx {
			case 0: // SM_CXSCREEN
				val = 1920
			case 1: // SM_CYSCREEN
				val = 1080
			case 2: // SM_CXVSCROLL
				val = 17
			case 3: // SM_CYHSCROLL
				val = 17
			case 4: // SM_CYCAPTION
				val = 23
			case 5: // SM_CXBORDER
				val = 1
			case 6: // SM_CYBORDER
				val = 1
			case 7: // SM_CXDLGFRAME
				val = 3
			case 8: // SM_CYDLGFRAME
				val = 3
			case 11: // SM_CXVSCROLL
				val = 17
			case 12: // SM_CYHSCROLL
				val = 17
			case 15: // SM_CXFULLSCREEN
				val = 1920
			case 16: // SM_CYFULLSCREEN
				val = 1040
			case 20: // SM_CXHSCROLL (arrow width)
				val = 17
			case 21: // SM_CYVSCROLL (arrow height)
				val = 17
			case 28: // SM_CXMIN
				val = 136
			case 29: // SM_CYMIN
				val = 39
			case 32: // SM_CXFRAME / SM_CXSIZEFRAME
				val = 4
			case 33: // SM_CYFRAME / SM_CYSIZEFRAME
				val = 4
			case 36: // SM_CXMINIMIZED
				val = 160
			case 37: // SM_CYMINIMIZED
				val = 24
			case 43: // SM_PENWINDOWS
				val = 0
			case 67: // SM_CLEANBOOT
				val = 0
			case 70: // SM_CMONITORS
				val = 1
			case 76: // SM_CXMAXIMIZED
				val = 1920
			case 77: // SM_CYMAXIMIZED
				val = 1040
			case 78: // SM_CXMAXTRACK
				val = 1928
			case 79: // SM_CYMAXTRACK
				val = 1088
			case 80: // SM_CXPADDEDBORDER
				val = 4
			default:
				val = 0
			}
			ctx.SetReturn(val)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "GetSysColor", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(uint64(getSysColor(uint32(ctx.Arg(0)))))
			return 0
		})
		d.RegisterAutoStubHandler(user32, "LoadCursorW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x00010001) // dummy cursor handle
			return 0
		})
		d.RegisterAutoStubHandler(user32, "LoadIconW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x00020001) // dummy icon handle
			return 0
		})
		d.RegisterAutoStubHandler(user32, "LoadImageW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x00030001) // dummy handle
			return 0
		})
		d.RegisterAutoStubHandler(user32, "SetWindowPos", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			if ci, ok := hwndChildren[hwnd]; ok {
				flags := uint32(ctx.Arg(6))
				const swpNoMove = 0x0002
				const swpNoSize = 0x0001
				ox, oy := clientAreaOrigin(ci.parentHWND)
				if flags&swpNoMove == 0 {
					x := int32(ctx.Arg(2))
					y := int32(ctx.Arg(3))
					if x >= 0 && x < 0x7FFF { ci.x = x + ox }
					if y >= 0 && y < 0x7FFF { ci.y = y + oy }
				}
				if flags&swpNoSize == 0 {
					w := int32(ctx.Arg(4))
					h := int32(ctx.Arg(5))
					if w > 0 && w < 0x7FFF { ci.w = w }
					if h > 0 && h < 0x7FFF { ci.h = h }
				}
				ravelog.Logf("[setpos] hwnd=0x%x class=%q flags=0x%x → %d,%d %dx%d\n", hwnd, ci.className, flags, ci.x, ci.y, ci.w, ci.h)
				// Queue WM_SIZE for windows with a guest WndProc
				if wp, ok := hwndWndProc[hwnd]; ok && wp != 0 {
					lParam := uint64(uint16(ci.w)) | (uint64(uint16(ci.h)) << 16)
					msgQueue = append(msgQueue, queuedMsg{hwnd, 0x0005, 0, lParam})
				}
			}
			ctx.SetReturn(1)
			return 0
		})

		// DeferWindowPos batch positioning
		type deferredPos struct {
			hwnd  uint64
			x, y  int32
			w, h  int32
			flags uint32
		}
		var deferredPositions []deferredPos
		var nextDWPHandle uint64 = 0xDEF00000

		d.RegisterAutoStubHandler(user32, "BeginDeferWindowPos", func(ctx *ntapi.TrapContext) uint32 {
			deferredPositions = deferredPositions[:0]
			nextDWPHandle++
			ctx.SetReturn(nextDWPHandle)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "DeferWindowPos", func(ctx *ntapi.TrapContext) uint32 {
			hdwp := ctx.Arg(0)
			hwnd := ctx.Arg(1)
			// arg2 = hWndInsertAfter (ignored)
			x := int32(ctx.Arg(3))
			y := int32(ctx.Arg(4))
			cx := int32(ctx.Arg(5))
			cy := int32(ctx.Arg(6))
			flags := uint32(ctx.Arg(7))
			deferredPositions = append(deferredPositions, deferredPos{hwnd: hwnd, x: x, y: y, w: cx, h: cy, flags: flags})
			ctx.SetReturn(hdwp)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "EndDeferWindowPos", func(ctx *ntapi.TrapContext) uint32 {
			const swpNoMove = 0x0002
			const swpNoSize = 0x0001
			for _, dp := range deferredPositions {
				ci, ok := hwndChildren[dp.hwnd]
				if !ok {
					continue
				}
				ox, oy := clientAreaOrigin(ci.parentHWND)
				if dp.flags&swpNoMove == 0 {
					ci.x = dp.x + ox
					ci.y = dp.y + oy
				}
				if dp.flags&swpNoSize == 0 {
					if dp.w > 0 { ci.w = dp.w }
					if dp.h > 0 { ci.h = dp.h }
				}
				ravelog.Logf("[setpos] hwnd=0x%x class=%q flags=0x%x → %d,%d %dx%d\n", dp.hwnd, ci.className, dp.flags, ci.x, ci.y, ci.w, ci.h)
			}
			deferredPositions = deferredPositions[:0]
			ctx.SetReturn(1)
			return 0
		})

		d.RegisterAutoStubHandler(user32, "MoveWindow", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			if ci, ok := hwndChildren[hwnd]; ok {
				ox, oy := clientAreaOrigin(ci.parentHWND)
				ci.x = int32(ctx.Arg(1)) + ox
				ci.y = int32(ctx.Arg(2)) + oy
				ci.w = int32(ctx.Arg(3))
				ci.h = int32(ctx.Arg(4))
				// Queue WM_SIZE for windows with a guest WndProc
				if wp, ok := hwndWndProc[hwnd]; ok && wp != 0 {
					lParam := uint64(uint16(ci.w)) | (uint64(uint16(ci.h)) << 16)
					msgQueue = append(msgQueue, queuedMsg{hwnd, 0x0005, 0, lParam})
				}
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "SetWindowTextW", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			text := readGuestUTF16(ctx.Arg(1))
			if hwnd == mainHWND && text != "" {
				mainTitle = text
			}
			if cs, ok := hwndChildren[hwnd]; ok {
				cs.text = text
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "SetWindowLongPtrW", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			index := int32(ctx.Arg(1))
			newVal := ctx.Arg(2)
			m := windowLongPtr[hwnd]
			if m == nil {
				m = make(map[int32]uint64)
				windowLongPtr[hwnd] = m
			}
			old := m[index]
			m[index] = newVal
			ctx.SetReturn(old)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "GetWindowLongPtrW", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			index := int32(ctx.Arg(1))
			if m, ok := windowLongPtr[hwnd]; ok {
				ctx.SetReturn(m[index])
			} else {
				ctx.SetReturn(0)
			}
			return 0
		})
		d.RegisterAutoStubHandler(user32, "SetWindowLongW", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			index := int32(ctx.Arg(1))
			newVal := ctx.Arg(2)
			m := windowLongPtr[hwnd]
			if m == nil {
				m = make(map[int32]uint64)
				windowLongPtr[hwnd] = m
			}
			old := m[index]
			m[index] = newVal
			ctx.SetReturn(old)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "GetWindowLongW", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			index := int32(ctx.Arg(1))
			if m, ok := windowLongPtr[hwnd]; ok {
				ctx.SetReturn(m[index])
			} else {
				ctx.SetReturn(0)
			}
			return 0
		})
		d.RegisterAutoStubHandler(user32, "SetPropW", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			lpString := ctx.Arg(1)
			hData := ctx.Arg(2)
			var name string
			if lpString < 0x10000 {
				name = fmt.Sprintf("atom:%d", lpString)
			} else {
				name = readGuestUTF16(lpString)
			}
			m := windowProps[hwnd]
			if m == nil {
				m = make(map[string]uint64)
				windowProps[hwnd] = m
			}
			m[name] = hData
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(user32, "GetPropW", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			lpString := ctx.Arg(1)
			var name string
			if lpString < 0x10000 {
				name = fmt.Sprintf("atom:%d", lpString)
			} else {
				name = readGuestUTF16(lpString)
			}
			if m, ok := windowProps[hwnd]; ok {
				ctx.SetReturn(m[name])
			} else {
				ctx.SetReturn(0)
			}
			return 0
		})
		d.RegisterAutoStubHandler(user32, "RemovePropW", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			lpString := ctx.Arg(1)
			var name string
			if lpString < 0x10000 {
				name = fmt.Sprintf("atom:%d", lpString)
			} else {
				name = readGuestUTF16(lpString)
			}
			if m, ok := windowProps[hwnd]; ok {
				old := m[name]
				delete(m, name)
				ctx.SetReturn(old)
			} else {
				ctx.SetReturn(0)
			}
			return 0
		})
		d.RegisterAutoStubHandler(user32, "GetClientRect", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			pRect := ctx.Arg(1)
			if pRect != 0 {
				if ci, ok := hwndChildren[hwnd]; ok {
					ctx.Mem.Write32(pRect, 0)
					ctx.Mem.Write32(pRect+4, 0)
					ctx.Mem.Write32(pRect+8, uint32(ci.w))
					ctx.Mem.Write32(pRect+12, uint32(ci.h))
				} else {
					var w, h int32 = 800, 600
					if wlWindow != nil {
						w, h = wlWindow.Width, wlWindow.Height
					}
					// Subtract menu bar from client area
					clientTop := int32(0)
					if _, hasMenu := hwndMenuBar[hwnd]; hasMenu {
						clientTop = menuBarHeight
					}
					ctx.Mem.Write32(pRect, 0)
					ctx.Mem.Write32(pRect+4, 0)
					ctx.Mem.Write32(pRect+8, uint32(w))
					ctx.Mem.Write32(pRect+12, uint32(h-clientTop))
				}
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "GetWindowRect", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			pRect := ctx.Arg(1)
			if pRect != 0 {
				if ci, ok := hwndChildren[hwnd]; ok {
					ctx.Mem.Write32(pRect, uint32(ci.x))
					ctx.Mem.Write32(pRect+4, uint32(ci.y))
					ctx.Mem.Write32(pRect+8, uint32(ci.x+ci.w))
					ctx.Mem.Write32(pRect+12, uint32(ci.y+ci.h))
				} else if hwnd == mainHWND && wlWindow != nil {
					ctx.Mem.Write32(pRect, 0)
					ctx.Mem.Write32(pRect+4, 0)
					ctx.Mem.Write32(pRect+8, uint32(wlWindow.Width))
					ctx.Mem.Write32(pRect+12, uint32(wlWindow.Height))
				} else {
					ctx.Mem.Write32(pRect, 0)
					ctx.Mem.Write32(pRect+4, 0)
					ctx.Mem.Write32(pRect+8, 800)
					ctx.Mem.Write32(pRect+12, 600)
				}
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "SendMessageW", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			msg := uint32(ctx.Arg(1))
			wParam := ctx.Arg(2)
			lParam := ctx.Arg(3)
			if result, handled := builtinWndProc(hwnd, msg, wParam, lParam); handled {
				ctx.SetReturn(result)
				return 0
			}
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "PostMessageW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(user32, "DefWindowProcW", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			msg := uint32(ctx.Arg(1))
			wParam := ctx.Arg(2)
			lParam := ctx.Arg(3)

			// WM_LBUTTONDOWN: check menu bar click
			if msg == 0x0201 && hwnd == mainHWND && wlWindow != nil {
				my := int32(lParam >> 16)
				mx := int32(lParam & 0xFFFF)
				if menuH, ok := hwndMenuBar[hwnd]; ok {
					if md, ok2 := menus[menuH]; ok2 && my < menuBarHeight {
						x := int32(4)
						for i, item := range md.items {
							if item.flags&0x0800 != 0 {
								continue
							}
							label := menuStripAmpersand(item.text)
							if label == "" {
								continue
							}
							tw := int32(len([]rune(label)))*8 + 12
							if mx >= x && mx < x+tw {
								if openMenuIdx == i && openMenuHwnd == hwnd {
									openMenuIdx = -1 // toggle off
								} else {
									openMenuIdx = i
									openMenuHwnd = hwnd
								}
								_ = md
								msgQueue = append(msgQueue, queuedMsg{mainHWND, 0x000F, 0, 0})
								ctx.SetReturn(0)
								return 0
							}
							x += tw
						}
						// Clicked menu bar but not on any item → close
						openMenuIdx = -1
						msgQueue = append(msgQueue, queuedMsg{mainHWND, 0x000F, 0, 0})
						ctx.SetReturn(0)
						return 0
					}
				}
			}

			// WM_LBUTTONDOWN: check dropdown menu item click
			if msg == 0x0201 && hwnd == mainHWND && openMenuIdx >= 0 && wlWindow != nil {
				my := int32(lParam >> 16)
				mx := int32(lParam & 0xFFFF)
				if menuH, ok := hwndMenuBar[hwnd]; ok {
					if md, ok2 := menus[menuH]; ok2 {
						// Find the open popup's position and items
						x := int32(4)
						for i, item := range md.items {
							if item.flags&0x0800 != 0 {
								continue
							}
							label := menuStripAmpersand(item.text)
							if label == "" {
								continue
							}
							tw := int32(len([]rune(label)))*8 + 12
							if i == openMenuIdx && len(item.submenu) > 0 {
								// Check if click is inside dropdown area
								dropX := x
								dropY := menuBarHeight
								dropW := int32(200)
								dropH := int32(len(item.submenu)) * 20
								if mx >= dropX && mx < dropX+dropW && my >= dropY && my < dropY+dropH {
									itemIdx := int(my-dropY) / 20
									if itemIdx >= 0 && itemIdx < len(item.submenu) {
										si := item.submenu[itemIdx]
										if si.flags&0x0800 == 0 { // not separator
											// Send WM_COMMAND with menu item ID
											msgQueue = append(msgQueue, queuedMsg{mainHWND, 0x0111, si.id, 0})
											openMenuIdx = -1
											msgQueue = append(msgQueue, queuedMsg{mainHWND, 0x000F, 0, 0})
										}
									}
									ctx.SetReturn(0)
									return 0
								}
							}
							x += tw
						}
						// Click outside dropdown → close
						openMenuIdx = -1
						msgQueue = append(msgQueue, queuedMsg{mainHWND, 0x000F, 0, 0})
					}
				}
			}

			// WM_PAINT: draw non-client area (menu bar), erase background, paint children
			if msg == 0x000F && wlWindow != nil {
				if hwnd == mainHWND {
					wlWindow.ResizeIfNeeded()
					w, h := wlWindow.Width, wlWindow.Height
					clientTop := int32(0)

					// Non-client area: draw menu bar
					if menuH, ok := hwndMenuBar[hwnd]; ok {
						if md, ok2 := menus[menuH]; ok2 && len(md.items) > 0 {
							clientTop = menuBarHeight
							wlWindow.DrawRect(0, 0, w, clientTop, sysColors[15])
							wlWindow.DrawRect(0, clientTop-1, w, clientTop, sysColors[16])
							x := int32(4)
							for i, item := range md.items {
								if item.flags&0x0800 != 0 {
									continue
								}
								label := menuStripAmpersand(item.text)
								if label == "" {
									continue
								}
								tw := int32(len([]rune(label)))*8 + 12
								if openMenuIdx == i && openMenuHwnd == hwnd {
									wlWindow.DrawRect(x, 0, x+tw, clientTop-1, sysColors[20])
									wlWindow.DrawText(x+4, 3, label, 0x000000, sysColors[20], true)
								} else {
									wlWindow.DrawText(x+4, 3, label, 0x000000, sysColors[15], true)
								}
								x += tw
							}

							// Draw dropdown if open
							if openMenuIdx >= 0 && openMenuHwnd == hwnd {
								x = int32(4)
								for i, item := range md.items {
									if item.flags&0x0800 != 0 {
										continue
									}
									label := menuStripAmpersand(item.text)
									if label == "" {
										continue
									}
									tw := int32(len([]rune(label)))*8 + 12
									if i == openMenuIdx && len(item.submenu) > 0 {
										dropX := x
										dropY := clientTop
										dropW := int32(200)
										dropH := int32(len(item.submenu)) * 20
										wlWindow.DrawRect(dropX+2, dropY+dropH, dropX+dropW+2, dropY+dropH+2, 0x808080)
										wlWindow.DrawRect(dropX+dropW, dropY+2, dropX+dropW+2, dropY+dropH+2, 0x808080)
										wlWindow.DrawRect(dropX, dropY, dropX+dropW, dropY+dropH, sysColors[15])
										wlWindow.DrawRect(dropX, dropY, dropX+dropW, dropY+1, sysColors[16])
										wlWindow.DrawRect(dropX, dropY, dropX+1, dropY+dropH, sysColors[16])
										wlWindow.DrawRect(dropX, dropY+dropH-1, dropX+dropW, dropY+dropH, sysColors[16])
										wlWindow.DrawRect(dropX+dropW-1, dropY, dropX+dropW, dropY+dropH, sysColors[16])
										for j, si := range item.submenu {
											iy := dropY + int32(j)*20
											if si.flags&0x0800 != 0 {
												wlWindow.DrawRect(dropX+2, iy+9, dropX+dropW-2, iy+10, sysColors[16])
												wlWindow.DrawRect(dropX+2, iy+10, dropX+dropW-2, iy+11, sysColors[20])
											} else {
												sl := menuStripAmpersand(si.text)
												for k := 0; k < len(sl); k++ {
													if sl[k] == '\t' {
														sl = sl[:k]
														break
													}
												}
												wlWindow.DrawText(dropX+20, iy+3, sl, 0x000000, sysColors[15], true)
											}
										}
									}
									x += tw
								}
							}
						}
					}

					// Erase background with class brush (ReactOS: defwnd.c WM_ERASEBKGND)
					bgColor := sysColors[5] // default COLOR_WINDOW
					if a, ok := hwndClassAtom[hwnd]; ok {
						if brushIdx, ok2 := classBrush[a]; ok2 && brushIdx > 0 && int(brushIdx-1) < len(sysColors) {
							bgColor = sysColors[brushIdx-1]
						}
					}
					wlWindow.DrawRect(0, clientTop, w, h, bgColor)

					// Recursively paint all descendant windows
					paintTree(hwnd)
					wlWindow.Commit()
				}
				// For non-mainHWND: ReactOS DefWindowProc just calls BeginPaint+EndPaint
				// In our model, the child is painted by paintTree from the parent
				ctx.SetReturn(0)
				return 0
			}
			// WM_NCCREATE: must return TRUE for window creation to proceed
			if msg == 0x0081 {
				ctx.SetReturn(1)
				return 0
			}
			// WM_ERASEBKGND: fill with class background brush (ReactOS: defwnd.c)
			if msg == 0x0014 && wlWindow != nil {
				bgColor := sysColors[5] // default COLOR_WINDOW
				if a, ok := hwndClassAtom[hwnd]; ok {
					if brushIdx, ok2 := classBrush[a]; ok2 && brushIdx > 0 && int(brushIdx-1) < len(sysColors) {
						bgColor = sysColors[brushIdx-1]
					}
				}
				if cs, ok := hwndChildren[hwnd]; ok {
					wlWindow.DrawRect(cs.x, cs.y, cs.x+cs.w, cs.y+cs.h, bgColor)
				} else if hwnd == mainHWND {
					clientTop := int32(0)
					if _, hasMenu := hwndMenuBar[hwnd]; hasMenu {
						clientTop = menuBarHeight
					}
					w, h := wlWindow.Width, wlWindow.Height
					wlWindow.DrawRect(0, clientTop, w, h, bgColor)
				}
				ctx.SetReturn(1)
				return 0
			}
			_ = wParam
			ctx.SetReturn(0)
			return 0
		})
		// writeMsg writes a Win32 MSG struct to guest memory (correct x64 layout).
		// MSG: HWND(8) message(4) pad(4) WPARAM(8) LPARAM(8) time(4) POINT(8)
		writeMsg := func(pMsg, hwnd uint64, message uint32, wParam, lParam uint64) {
			mem.Write64(pMsg, hwnd)
			mem.Write32(pMsg+8, message)
			mem.Write32(pMsg+12, 0) // padding
			mem.Write64(pMsg+16, wParam)
			mem.Write64(pMsg+24, lParam)
			mem.Write32(pMsg+32, 0) // time
			mem.Write32(pMsg+36, 0) // pt.x
			mem.Write32(pMsg+40, 0) // pt.y
		}
		// GetMessageW: drain message queue first, then block on Wayland events
		d.RegisterAutoStubHandler(user32, "GetMessageW", func(ctx *ntapi.TrapContext) uint32 {
			pMsg := ctx.Arg(0)

			// Drain queued messages first (WM_CREATE, WM_SIZE, etc.)
			if len(msgQueue) > 0 {
				m := msgQueue[0]
				msgQueue = msgQueue[1:]
				if pMsg != 0 {
					writeMsg(pMsg, m.hwnd, m.message, m.wParam, m.lParam)
				}
				ctx.SetReturn(1)
				return 0
			}

			if wlDisplay != nil && wlWindow != nil {
				evt, err := wlDisplay.Dispatch()
				if err != nil || evt == wl.EventClose {
					if pMsg != 0 {
						writeMsg(pMsg, mainHWND, 0x12, 0, 0) // WM_QUIT
					}
					ctx.SetReturn(0)
					return 0
				}
				// Convert keyboard events to Win32 messages
				if evt == wl.EventKey {
					for {
						ke, ok := wlDisplay.PollKey()
						if !ok {
							break
						}
						target := focusHwnd
						if target == 0 {
							target = mainHWND
						}
						if ke.Pressed {
							msgQueue = append(msgQueue, queuedMsg{target, 0x0100, uint64(ke.VK), 0})
							if ke.Char >= 0x20 || ke.Char == '\r' || ke.Char == '\b' || ke.Char == '\t' {
								msgQueue = append(msgQueue, queuedMsg{target, 0x0102, uint64(ke.Char), 0})
							}
						} else {
							msgQueue = append(msgQueue, queuedMsg{target, 0x0101, uint64(ke.VK), 0})
						}
					}
				}
				// Convert mouse events to Win32 messages
				if evt == wl.EventMouse {
					for {
						me, ok := wlDisplay.PollMouse()
						if !ok {
							break
						}
						lParam := uint64(uint16(me.X)) | (uint64(uint16(me.Y)) << 16)
						switch me.Kind {
						case 0: // motion → WM_MOUSEMOVE
							msgQueue = append(msgQueue, queuedMsg{mainHWND, 0x0200, 0, lParam})
						case 1: // button
							const btnLeft = 272
							const btnRight = 273
							const btnMiddle = 274
							switch me.Button {
							case btnLeft:
								if me.Pressed {
									msgQueue = append(msgQueue, queuedMsg{mainHWND, 0x0201, 0x0001, lParam}) // WM_LBUTTONDOWN, MK_LBUTTON
								} else {
									msgQueue = append(msgQueue, queuedMsg{mainHWND, 0x0202, 0, lParam}) // WM_LBUTTONUP
								}
							case btnRight:
								if me.Pressed {
									msgQueue = append(msgQueue, queuedMsg{mainHWND, 0x0204, 0x0002, lParam})
								} else {
									msgQueue = append(msgQueue, queuedMsg{mainHWND, 0x0205, 0, lParam})
								}
							case btnMiddle:
								if me.Pressed {
									msgQueue = append(msgQueue, queuedMsg{mainHWND, 0x0207, 0x0010, lParam})
								} else {
									msgQueue = append(msgQueue, queuedMsg{mainHWND, 0x0208, 0, lParam})
								}
							}
						case 2: // axis → WM_MOUSEWHEEL
							wParam := uint64(int16(me.AxisVal*-120)) << 16
							msgQueue = append(msgQueue, queuedMsg{mainHWND, 0x020A, wParam, lParam})
						}
					}
				}
				// Drain newly queued messages
				if len(msgQueue) > 0 {
					m := msgQueue[0]
					msgQueue = msgQueue[1:]
					if pMsg != 0 {
						writeMsg(pMsg, m.hwnd, m.message, m.wParam, m.lParam)
					}
					ctx.SetReturn(1)
					return 0
				}
				// Synthetic WM_PAINT frame: mainHWND + all visible children with guest WndProcs
				msgQueue = append(msgQueue, queuedMsg{mainHWND, 0x000F, 0, 0})
				for h, cs := range hwndChildren {
					if cs.visible && hwndWndProc[h] != 0 {
						msgQueue = append(msgQueue, queuedMsg{h, 0x000F, 0, 0})
					}
				}
				m := msgQueue[0]
				msgQueue = msgQueue[1:]
				if pMsg != 0 {
					writeMsg(pMsg, m.hwnd, m.message, m.wParam, m.lParam)
				}
				ctx.SetReturn(1)
				return 0
			}
			// No Wayland - return WM_QUIT immediately
			if pMsg != 0 {
				writeMsg(pMsg, mainHWND, 0x12, 0, 0) // WM_QUIT
			}
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "PeekMessageW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // no messages
			return 0
		})
		d.RegisterAutoStubHandler(user32, "TranslateMessage", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "DispatchMessageW", func(ctx *ntapi.TrapContext) uint32 {
			pMsg := ctx.Arg(0)
			if pMsg == 0 {
				ctx.SetReturn(0)
				return 0
			}
			// MSG layout (x64): HWND(8) message(4) pad(4) WPARAM(8) LPARAM(8) ...
			hwnd, _ := mem.Read64(pMsg)
			message, _ := mem.Read32(pMsg + 8)
			wParam, _ := mem.Read64(pMsg + 16)
			lParam, _ := mem.Read64(pMsg + 24)

			// Try built-in control first
			if _, isChild := hwndChildren[hwnd]; isChild {
				result, handled := builtinWndProc(hwnd, message, wParam, lParam)
				if handled {
					ctx.SetReturn(result)
					return 0
				}
			}

			wndProc, ok := hwndWndProc[hwnd]
			if !ok || wndProc == 0 {
				ravelog.Logf("[dispatch] no WndProc for hwnd=0x%x msg=0x%x\n", hwnd, message)
				ctx.SetReturn(0)
				return 0
			}

			rw, ok := ctx.CPU.(ntapi.RegisterWriter)
			if !ok {
				ctx.SetReturn(0)
				return 0
			}

			ravelog.Logf("[dispatch] hwnd=0x%x msg=0x%x → WndProc=0x%x\n", hwnd, message, wndProc)

			// Stack is already correct: [RSP] = caller's return address,
			// [RSP+8..RSP+0x28] = shadow space. WndProc will RET to caller.
			rw.WriteReg(1, hwnd)            // RCX
			rw.WriteReg(2, uint64(message)) // RDX
			rw.WriteReg(8, wParam)          // R8
			rw.WriteReg(9, lParam)          // R9

			ctx.CPU.SetPC(wndProc)
			ctx.ReturnOverridden = true
			return 0
		})
		d.RegisterAutoStubHandler(user32, "TranslateAcceleratorW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // not translated
			return 0
		})
		d.RegisterAutoStubHandler(user32, "GetForegroundWindow", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "SetForegroundWindow", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "IsWindowVisible", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(user32, "IsWindow", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(user32, "SetFocus", func(ctx *ntapi.TrapContext) uint32 {
			prev := focusHwnd
			focusHwnd = ctx.Arg(0)
			ctx.SetReturn(prev)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "GetFocus", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(focusHwnd)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "SetCapture", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "ReleaseCapture", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "EnableWindow", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // was enabled
			return 0
		})
		d.RegisterAutoStubHandler(user32, "SetTimer", func(ctx *ntapi.TrapContext) uint32 {
			id := ctx.Arg(1)
			if id == 0 {
				id = 1
			}
			ctx.SetReturn(id)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "KillTimer", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "InvalidateRect", func(ctx *ntapi.TrapContext) uint32 {
			// Any InvalidateRect triggers a full repaint of mainHWND (which repaints all children)
			msgQueue = append(msgQueue, queuedMsg{mainHWND, 0x000F, 0, 0})
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "BeginPaint", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			pPaint := ctx.Arg(1)
			hdc := gdiAlloc()
			ox, oy := clientAreaOrigin(hwnd)
			dcMap[hdc] = &dcState{textColor: 0x000000, bkColor: 0xFFFFFF, bkMode: 2, isScreen: true, originX: ox, originY: oy}

			var rcLeft, rcTop, rcRight, rcBottom int32

			if wlWindow != nil && hwnd == mainHWND {
				wlWindow.ResizeIfNeeded()
				w, h := wlWindow.Width, wlWindow.Height
				clientTop := int32(0)

				// Non-client area: draw menu bar (ReactOS: WM_NCPAINT draws menu in NC area)
				if menuH, ok := hwndMenuBar[hwnd]; ok {
					if md, ok2 := menus[menuH]; ok2 && len(md.items) > 0 {
						clientTop = menuBarHeight
						wlWindow.DrawRect(0, 0, w, clientTop, sysColors[15])
						wlWindow.DrawRect(0, clientTop-1, w, clientTop, sysColors[16])
						x := int32(4)
						for _, item := range md.items {
							if item.flags&0x0800 != 0 {
								continue
							}
							label := menuStripAmpersand(item.text)
							if label == "" {
								continue
							}
							tw := int32(len([]rune(label))) * 8
							wlWindow.DrawText(x+4, 3, label, 0x000000, sysColors[15], true)
							x += tw + 12
						}
					}
				}

				// WM_ERASEBKGND: fill client area with class brush
				bgColor := sysColors[5] // default COLOR_WINDOW
				if a, ok := hwndClassAtom[hwnd]; ok {
					if brushIdx, ok2 := classBrush[a]; ok2 && brushIdx > 0 && int(brushIdx-1) < len(sysColors) {
						bgColor = sysColors[brushIdx-1]
					}
				}
				wlWindow.DrawRect(0, clientTop, w, h, bgColor)

				rcLeft, rcTop = 0, clientTop
				rcRight, rcBottom = w, h
			} else if cs, ok := hwndChildren[hwnd]; ok && wlWindow != nil {
				// Child window BeginPaint: fill with class brush
				bgColor := sysColors[5]
				if a, ok := hwndClassAtom[hwnd]; ok {
					if brushIdx, ok2 := classBrush[a]; ok2 && brushIdx > 0 && int(brushIdx-1) < len(sysColors) {
						bgColor = sysColors[brushIdx-1]
					}
				}
				wlWindow.DrawRect(cs.x, cs.y, cs.x+cs.w, cs.y+cs.h, bgColor)
				rcLeft, rcTop = 0, 0
				rcRight, rcBottom = cs.w, cs.h
			} else {
				rcRight, rcBottom = 800, 600
				if wlWindow != nil {
					rcRight, rcBottom = wlWindow.Width, wlWindow.Height
				}
			}

			if pPaint != 0 {
				ctx.Mem.Write64(pPaint, hdc)                   // hdc
				ctx.Mem.Write32(pPaint+8, 1)                   // fErase
				ctx.Mem.Write32(pPaint+12, uint32(rcLeft))     // rcPaint.left
				ctx.Mem.Write32(pPaint+16, uint32(rcTop))      // rcPaint.top
				ctx.Mem.Write32(pPaint+20, uint32(rcRight))    // rcPaint.right
				ctx.Mem.Write32(pPaint+24, uint32(rcBottom))   // rcPaint.bottom
			}
			ctx.SetReturn(hdc)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "EndPaint", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			if wlWindow != nil {
				paintTree(hwnd)
				if hwnd == mainHWND {
					wlWindow.Commit()
				}
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "GetDesktopWindow", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x00050000) // desktop window handle
			return 0
		})
		d.RegisterAutoStubHandler(user32, "GetParent", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			if cs, ok := hwndChildren[hwnd]; ok {
				ctx.SetReturn(cs.parentHWND)
			} else {
				ctx.SetReturn(0)
			}
			return 0
		})
		d.RegisterAutoStubHandler(user32, "SetParent", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "GetMenu", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			if h, ok := hwndMenuBar[hwnd]; ok {
				ctx.SetReturn(h)
			} else {
				ctx.SetReturn(0)
			}
			return 0
		})
		d.RegisterAutoStubHandler(user32, "SetMenu", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			hMenu := ctx.Arg(1)
			if hMenu == 0 {
				delete(hwndMenuBar, hwnd)
			} else {
				hwndMenuBar[hwnd] = hMenu
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "CreateMenu", func(ctx *ntapi.TrapContext) uint32 {
			h := gdiAlloc()
			menus[h] = &menuData{}
			ctx.SetReturn(h)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "CreatePopupMenu", func(ctx *ntapi.TrapContext) uint32 {
			h := gdiAlloc()
			menus[h] = &menuData{}
			ctx.SetReturn(h)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "AppendMenuW", func(ctx *ntapi.TrapContext) uint32 {
			hMenu := ctx.Arg(0)
			flags := uint32(ctx.Arg(1))
			idOrSubmenu := ctx.Arg(2)
			lpNewItem := ctx.Arg(3)
			m, ok := menus[hMenu]
			if !ok {
				ctx.SetReturn(0)
				return 0
			}
			item := menuItem{flags: flags, id: idOrSubmenu}
			const mfString = 0x0000
			const mfSeparator = 0x0800
			if flags&mfSeparator == 0 && lpNewItem != 0 {
				item.text = readGuestUTF16(lpNewItem)
			}
			m.items = append(m.items, item)
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "InsertMenuW", func(ctx *ntapi.TrapContext) uint32 {
			hMenu := ctx.Arg(0)
			flags := uint32(ctx.Arg(2))
			idOrSubmenu := ctx.Arg(3)
			lpNewItem := ctx.Arg(4)
			m, ok := menus[hMenu]
			if !ok {
				ctx.SetReturn(0)
				return 0
			}
			item := menuItem{flags: flags, id: idOrSubmenu}
			const mfSeparator = 0x0800
			if flags&mfSeparator == 0 && lpNewItem != 0 {
				item.text = readGuestUTF16(lpNewItem)
			}
			m.items = append(m.items, item)
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "InsertMenuItemW", func(ctx *ntapi.TrapContext) uint32 {
			hMenu := ctx.Arg(0)
			lpmii := ctx.Arg(3) // MENUITEMINFOW*
			m, ok := menus[hMenu]
			if !ok {
				ctx.SetReturn(0)
				return 0
			}
			item := menuItem{}
			if lpmii != 0 {
				// MENUITEMINFOW: cbSize(4) fMask(4) fType(4) fState(4) wID(4) hSubMenu(8@16) ...
				// dwTypeData at offset 40 (x64), cch at offset 48
				fMask, _ := mem.Read32(lpmii + 4)
				fType, _ := mem.Read32(lpmii + 8)
				item.flags = fType
				if fMask&0x40 != 0 { // MIIM_STRING
					dwTypeData, _ := mem.Read64(lpmii + 40)
					if dwTypeData != 0 {
						item.text = readGuestUTF16(dwTypeData)
					}
				}
				if fMask&0x02 != 0 { // MIIM_ID
					wID, _ := mem.Read32(lpmii + 12)
					item.id = uint64(wID)
				}
				if fMask&0x04 != 0 { // MIIM_SUBMENU
					hSub, _ := mem.Read64(lpmii + 16)
					item.id = hSub
					item.flags |= 0x10 // MF_POPUP
				}
			}
			m.items = append(m.items, item)
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "DrawMenuBar", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "MessageBoxA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // IDOK
			return 0
		})
		d.RegisterAutoStubHandler(user32, "MessageBoxW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // IDOK
			return 0
		})
		d.RegisterAutoStubHandler(user32, "SetCursor", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(ctx.Arg(0))
			return 0
		})
		d.RegisterAutoStubHandler(user32, "GetCursorPos", func(ctx *ntapi.TrapContext) uint32 {
			p := ctx.Arg(0)
			if p != 0 {
				ctx.Mem.Write32(p, 0)
				ctx.Mem.Write32(p+4, 0)
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "ScreenToClient", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "ClientToScreen", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "MonitorFromWindow", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x00040001) // dummy monitor handle
			return 0
		})
		d.RegisterAutoStubHandler(user32, "GetMonitorInfoW", func(ctx *ntapi.TrapContext) uint32 {
			pInfo := ctx.Arg(1)
			if pInfo != 0 {
				cbSize, _ := ctx.Mem.Read32(pInfo)
				if cbSize >= 40 {
					ctx.Mem.Write32(pInfo+4, 0)     // rcMonitor.left
					ctx.Mem.Write32(pInfo+8, 0)     // rcMonitor.top
					ctx.Mem.Write32(pInfo+12, 1920) // rcMonitor.right
					ctx.Mem.Write32(pInfo+16, 1080) // rcMonitor.bottom
					ctx.Mem.Write32(pInfo+20, 0)    // rcWork.left
					ctx.Mem.Write32(pInfo+24, 0)    // rcWork.top
					ctx.Mem.Write32(pInfo+28, 1920) // rcWork.right
					ctx.Mem.Write32(pInfo+32, 1040) // rcWork.bottom
					ctx.Mem.Write32(pInfo+36, 1)    // dwFlags = MONITORINFOF_PRIMARY
				}
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "SystemParametersInfoW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "GetKeyboardLayout", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x04090409) // en-US
			return 0
		})
		d.RegisterAutoStubHandler(user32, "MapVirtualKeyW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "GetKeyState", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "GetAsyncKeyState", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "SetWindowsHookExW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x00060001) // dummy hook handle
			return 0
		})
		d.RegisterAutoStubHandler(user32, "UnhookWindowsHookEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "GetDpiForWindow", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(96) // standard DPI
			return 0
		})
		d.RegisterAutoStubHandler(user32, "AdjustWindowRectEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "LockWindowUpdate", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "CheckMenuItem", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // MF_UNCHECKED (previous state)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "SetWindowPlacement", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(user32, "RedrawWindow", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			if hwnd == 0 || hwnd == mainHWND {
				msgQueue = append(msgQueue, queuedMsg{mainHWND, 0x000F, 0, 0})
			}
			ctx.SetReturn(1)
			return 0
		})

		// LoadMenuW: load menu from PE resources (same as LoadMenuIndirectW essentially)
		d.RegisterAutoStubHandler(user32, "LoadMenuW", func(ctx *ntapi.TrapContext) uint32 {
			menuName := ctx.Arg(1)
			if menuName == 0 {
				ctx.SetReturn(0)
				return 0
			}
			// menuName can be an integer resource ID (MAKEINTRESOURCE) or string pointer
			var resID uint32
			if menuName < 0x10000 {
				resID = uint32(menuName)
			} else {
				// It's a string - try reading it as an integer name
				ctx.SetReturn(0)
				return 0
			}
			menu := peLoadMenuResource(resID)
			if menu == nil {
				ravelog.Logf("[menu] LoadMenuW resID=%d → nil\n", resID)
				ctx.SetReturn(0)
				return 0
			}
			hmenu := uint64(0x60000 + resID)
			menus[hmenu] = menu
			ravelog.Logf("[menu] LoadMenuW resID=%d → hmenu=0x%x items=%d\n", resID, hmenu, len(menu.items))
			for i, item := range menu.items {
				ravelog.Logf("[menu]   [%d] %q flags=0x%x submenu=%d\n", i, item.text, item.flags, len(item.submenu))
			}
			ctx.SetReturn(hmenu)
			return 0
		})

		// RegisterClipboardFormatW: return a unique atom
		var nextClipFmt uint64 = 0xC100
		d.RegisterAutoStubHandler(user32, "RegisterClipboardFormatW", func(ctx *ntapi.TrapContext) uint32 {
			nextClipFmt++
			ctx.SetReturn(nextClipFmt)
			return 0
		})

		// DestroyMenu
		d.RegisterAutoStubHandler(user32, "DestroyMenu", func(ctx *ntapi.TrapContext) uint32 {
			hmenu := ctx.Arg(0)
			delete(menus, hmenu)
			ctx.SetReturn(1)
			return 0
		})

		// EnableMenuItem
		d.RegisterAutoStubHandler(user32, "EnableMenuItem", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // previous state
			return 0
		})

		// DrawMenuBar
		d.RegisterAutoStubHandler(user32, "DrawMenuBar", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})

		// GetMenu / SetMenu
		d.RegisterAutoStubHandler(user32, "GetMenu", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			if hm, ok := hwndMenuBar[hwnd]; ok {
				ctx.SetReturn(hm)
			} else {
				ctx.SetReturn(0)
			}
			return 0
		})
		d.RegisterAutoStubHandler(user32, "SetMenu", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			hmenu := ctx.Arg(1)
			if hmenu != 0 {
				hwndMenuBar[hwnd] = hmenu
			} else {
				delete(hwndMenuBar, hwnd)
			}
			ctx.SetReturn(1)
			return 0
		})

		// GetSubMenu
		d.RegisterAutoStubHandler(user32, "GetSubMenu", func(ctx *ntapi.TrapContext) uint32 {
			hmenu := ctx.Arg(0)
			pos := int(ctx.Arg(1))
			if m, ok := menus[hmenu]; ok && pos < len(m.items) {
				// Create a handle for the sub-menu position
				subH := uint64(0x70000 + uint64(pos)<<8 + hmenu&0xFF)
				if _, exists := menus[subH]; !exists {
					menus[subH] = &menuData{}
				}
				ctx.SetReturn(subH)
				return 0
			}
			ctx.SetReturn(0)
			return 0
		})

		// InsertMenuW / AppendMenuW / ModifyMenuW / DeleteMenu
		d.RegisterAutoStubHandler(user32, "InsertMenuW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "AppendMenuW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "ModifyMenuW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "DeleteMenu", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})

		// GetMenuItemCount
		d.RegisterAutoStubHandler(user32, "GetMenuItemCount", func(ctx *ntapi.TrapContext) uint32 {
			hmenu := ctx.Arg(0)
			if m, ok := menus[hmenu]; ok {
				ctx.SetReturn(uint64(len(m.items)))
			} else {
				ctx.SetReturn(0)
			}
			return 0
		})

		// GetMenuItemInfoW - stub with minimal info
		d.RegisterAutoStubHandler(user32, "GetMenuItemInfoW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})

		// SetMenuItemInfoW
		d.RegisterAutoStubHandler(user32, "SetMenuItemInfoW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})

		// GetSystemMenu
		d.RegisterAutoStubHandler(user32, "GetSystemMenu", func(ctx *ntapi.TrapContext) uint32 {
			sysMenu := uint64(0x80000)
			if _, ok := menus[sysMenu]; !ok {
				menus[sysMenu] = &menuData{}
			}
			ctx.SetReturn(sysMenu)
			return 0
		})
		// GetSysColorBrush: return a pseudo-handle encoding the index
		d.RegisterAutoStubHandler(user32, "GetSysColorBrush", func(ctx *ntapi.TrapContext) uint32 {
			idx := ctx.Arg(0)
			h := uint64(0xBBBB_0000) | idx // pseudo-handle
			brushColors[h] = getSysColor(uint32(idx))
			ctx.SetReturn(h)
			return 0
		})
		// FillRect (user32 export, same semantics as gdi32.FillRect)
		d.RegisterAutoStubHandler(user32, "FillRect", func(ctx *ntapi.TrapContext) uint32 {
			if wlWindow == nil {
				ctx.SetReturn(1)
				return 0
			}
			hDC := ctx.Arg(0)
			lpRect := ctx.Arg(1)
			hBrush := ctx.Arg(2)
			if lpRect == 0 {
				ctx.SetReturn(1)
				return 0
			}
			dc := dcMap[hDC]
			if dc != nil && !dc.isScreen {
				ctx.SetReturn(1)
				return 0
			}
			var ox, oy int32
			if dc != nil {
				ox, oy = dc.originX, dc.originY
			}
			left, _ := mem.Read32(lpRect)
			top, _ := mem.Read32(lpRect + 4)
			right, _ := mem.Read32(lpRect + 8)
			bottom, _ := mem.Read32(lpRect + 12)
			var color uint32
			if c, ok := brushColors[hBrush]; ok {
				color = c
			} else if hBrush >= 1 && hBrush <= 31 {
				color = getSysColor(uint32(hBrush - 1))
			} else {
				color = 0xF0F0F0
			}
			wlWindow.DrawRect(int32(left)+ox, int32(top)+oy, int32(right)+ox, int32(bottom)+oy, color)
			ctx.SetReturn(1)
			return 0
		})
		// CreateDialogParamW: modeless dialog creation - return a fake HWND
		d.RegisterAutoStubHandler(user32, "CreateDialogParamW", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := hwndAlloc()
			ctx.SetReturn(hwnd)
			return 0
		})
		// SetMenuItemBitmaps: associate bitmaps with menu items - no-op (no bitmap rendering)
		d.RegisterAutoStubHandler(user32, "SetMenuItemBitmaps", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		// RemoveMenu: remove a menu item - no-op stub
		d.RegisterAutoStubHandler(user32, "RemoveMenu", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		// GetDlgCtrlID: return control ID from HWND - return 0
		d.RegisterAutoStubHandler(user32, "GetDlgCtrlID", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		// DestroyIcon: free an icon handle - no-op stub
		d.RegisterAutoStubHandler(user32, "DestroyIcon", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		// GetMenuStringW: copy menu item text into caller's buffer
		d.RegisterAutoStubHandler(user32, "GetMenuStringW", func(ctx *ntapi.TrapContext) uint32 {
			hMenu := ctx.Arg(0)
			idItem := ctx.Arg(1)
			lpStr := ctx.Arg(2)
			nMaxCount := int(ctx.Arg(3))
			// flags := ctx.Arg(4)  // MF_BYPOSITION or MF_BYCOMMAND
			md, ok := menus[hMenu]
			if !ok || nMaxCount == 0 || lpStr == 0 {
				ctx.SetReturn(0)
				return 0
			}
			for _, item := range md.items {
				if item.id == idItem {
					runes := []rune(item.text)
					n := len(runes)
					if n >= nMaxCount { n = nMaxCount - 1 }
					for i := 0; i < n; i++ {
						mem.Write16(lpStr+uint64(i)*2, uint16(runes[i]))
					}
					mem.Write16(lpStr+uint64(n)*2, 0)
					ctx.SetReturn(uint64(n))
					return 0
				}
			}
			ctx.SetReturn(0)
			return 0
		})
	}
	})
	delayHandlerRegistrars[len(delayHandlerRegistrars)-1]()

	// --- gdi32.dll ---
	delayHandlerRegistrars = append(delayHandlerRegistrars, func() {
	if gdi32, ok := synthByName["gdi32.dll"]; ok {
		d.RegisterAutoStubHandler(gdi32, "CreateSolidBrush", func(ctx *ntapi.TrapContext) uint32 {
			h := gdiAlloc()
			brushColors[h] = uint32(ctx.Arg(0)) // COLORREF
			ctx.SetReturn(h)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "CreatePen", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(gdiAlloc())
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "CreateFontIndirectW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(gdiAlloc())
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "CreateFontW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(gdiAlloc())
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "CreateCompatibleDC", func(ctx *ntapi.TrapContext) uint32 {
			h := gdiAlloc()
			dcMap[h] = &dcState{textColor: 0x000000, bkColor: 0xFFFFFF, bkMode: 2, isScreen: false}
			ctx.SetReturn(h)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "CreateCompatibleBitmap", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(gdiAlloc())
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "CreateDIBSection", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(gdiAlloc())
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "DeleteDC", func(ctx *ntapi.TrapContext) uint32 {
			delete(dcMap, ctx.Arg(0))
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "DeleteObject", func(ctx *ntapi.TrapContext) uint32 {
			h := ctx.Arg(0)
			delete(brushColors, h)
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "SelectObject", func(ctx *ntapi.TrapContext) uint32 {
			hdc := ctx.Arg(0)
			hObj := ctx.Arg(1)
			dc := getDC(hdc)
			prev := dc.curBrush
			// If it's a known brush, select it
			if _, ok := brushColors[hObj]; ok {
				dc.curBrush = hObj
			}
			if prev == 0 {
				prev = gdiAlloc()
			}
			ctx.SetReturn(prev)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GetStockObject", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(gdiAlloc())
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GetObjectW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // size written
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GetDeviceCaps", func(ctx *ntapi.TrapContext) uint32 {
			idx := ctx.Arg(1)
			val := uint64(0)
			switch idx {
			case 8: // HORZRES
				val = 1920
			case 10: // VERTRES
				val = 1080
			case 12: // BITSPIXEL
				val = 32
			case 14: // PLANES
				val = 1
			case 88: // LOGPIXELSX
				val = 96
			case 90: // LOGPIXELSY
				val = 96
			case 118: // DESKTOPHORZRES
				val = 1920
			case 117: // DESKTOPVERTRES
				val = 1080
			default:
				val = 0
			}
			ctx.SetReturn(val)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GetTextMetricsW", func(ctx *ntapi.TrapContext) uint32 {
			pTM := ctx.Arg(1)
			if pTM != 0 {
				ctx.Mem.Write32(pTM, 16)     // tmHeight
				ctx.Mem.Write32(pTM+4, 13)   // tmAscent
				ctx.Mem.Write32(pTM+8, 3)    // tmDescent
				ctx.Mem.Write32(pTM+12, 0)   // tmInternalLeading
				ctx.Mem.Write32(pTM+16, 0)   // tmExternalLeading
				ctx.Mem.Write32(pTM+20, 7)   // tmAveCharWidth
				ctx.Mem.Write32(pTM+24, 14)  // tmMaxCharWidth
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GetTextExtentPoint32W", func(ctx *ntapi.TrapContext) uint32 {
			nLen := ctx.Arg(2)
			pSize := ctx.Arg(3)
			if pSize != 0 {
				ctx.Mem.Write32(pSize, uint32(nLen*8)) // cx
				ctx.Mem.Write32(pSize+4, 16)            // cy
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "SetBkMode", func(ctx *ntapi.TrapContext) uint32 {
			hdc := ctx.Arg(0)
			mode := int32(ctx.Arg(1))
			dc := getDC(hdc)
			prev := dc.bkMode
			dc.bkMode = mode
			ctx.SetReturn(uint64(prev))
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "SetBkColor", func(ctx *ntapi.TrapContext) uint32 {
			hdc := ctx.Arg(0)
			color := uint32(ctx.Arg(1))
			dc := getDC(hdc)
			prev := dc.bkColor
			dc.bkColor = color
			ctx.SetReturn(uint64(prev))
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "SetTextColor", func(ctx *ntapi.TrapContext) uint32 {
			hdc := ctx.Arg(0)
			color := uint32(ctx.Arg(1))
			dc := getDC(hdc)
			prev := dc.textColor
			dc.textColor = color
			ctx.SetReturn(uint64(prev))
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "TextOutW", func(ctx *ntapi.TrapContext) uint32 {
			if wlWindow == nil {
				ctx.SetReturn(1)
				return 0
			}
			hdc := ctx.Arg(0)
			dc := getDC(hdc)
			if !dc.isScreen {
				ctx.SetReturn(1)
				return 0
			}
			x := int32(ctx.Arg(1)) + dc.originX
			y := int32(ctx.Arg(2)) + dc.originY
			lpStr := ctx.Arg(3)
			nLen := int(ctx.Arg(4))
			text := readGuestUTF16(lpStr)
			if nLen > 0 && nLen < len(text) {
				text = text[:nLen]
			}
			wlWindow.DrawText(x, y, text, dc.textColor, dc.bkColor, dc.bkMode == 2)
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "ExtTextOutW", func(ctx *ntapi.TrapContext) uint32 {
			if wlWindow == nil {
				ctx.SetReturn(1)
				return 0
			}
			hdc := ctx.Arg(0)
			dc := getDC(hdc)
			if !dc.isScreen {
				ctx.SetReturn(1)
				return 0
			}
			x := int32(ctx.Arg(1)) + dc.originX
			y := int32(ctx.Arg(2)) + dc.originY
			// arg3 = options, arg4 = lpRect (skip for now)
			lpStr := ctx.Arg(4 + 1) // 5th arg: lpString (stack arg after rect)
			nLen := int(ctx.Arg(4 + 2)) // 6th arg: cbCount
			text := readGuestUTF16(lpStr)
			if nLen > 0 && nLen < len(text) {
				text = text[:nLen]
			}
			wlWindow.DrawText(x, y, text, dc.textColor, dc.bkColor, dc.bkMode == 2)
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "BitBlt", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "PatBlt", func(ctx *ntapi.TrapContext) uint32 {
			if wlWindow == nil {
				ctx.SetReturn(1)
				return 0
			}
			hdc := ctx.Arg(0)
			dc := getDC(hdc)
			if !dc.isScreen {
				ctx.SetReturn(1)
				return 0
			}
			x := int32(ctx.Arg(1)) + dc.originX
			y := int32(ctx.Arg(2)) + dc.originY
			w := int32(ctx.Arg(3))
			h := int32(ctx.Arg(4 + 0)) // 5th arg on stack
			color := uint32(0xF0F0F0)
			if c, ok := brushColors[dc.curBrush]; ok {
				color = c
			}
			wlWindow.DrawRect(x, y, x+w, y+h, color)
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "StretchBlt", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "FillRect", func(ctx *ntapi.TrapContext) uint32 {
			if wlWindow == nil {
				ctx.SetReturn(1)
				return 0
			}
			hDC := ctx.Arg(0)
			lpRect := ctx.Arg(1)
			hBrush := ctx.Arg(2)
			if lpRect == 0 {
				ctx.SetReturn(1)
				return 0
			}
			dc := dcMap[hDC]
			if dc != nil && !dc.isScreen {
				ctx.SetReturn(1)
				return 0
			}
			var ox, oy int32
			if dc != nil {
				ox, oy = dc.originX, dc.originY
			}
			left, _ := mem.Read32(lpRect)
			top, _ := mem.Read32(lpRect + 4)
			right, _ := mem.Read32(lpRect + 8)
			bottom, _ := mem.Read32(lpRect + 12)

			var color uint32
			if c, ok := brushColors[hBrush]; ok {
				color = c
			} else if hBrush >= 1 && hBrush <= 31 {
				color = getSysColor(uint32(hBrush - 1))
			} else {
				color = 0xF0F0F0
			}
			wlWindow.DrawRect(int32(left)+ox, int32(top)+oy, int32(right)+ox, int32(bottom)+oy, color)
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "Rectangle", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "MoveToEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "LineTo", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "SaveDC", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // save level
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "RestoreDC", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "SetMapMode", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // previous mode
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GetCurrentPositionEx", func(ctx *ntapi.TrapContext) uint32 {
			p := ctx.Arg(1)
			if p != 0 {
				ctx.Mem.Write32(p, 0)
				ctx.Mem.Write32(p+4, 0)
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "SetDIBitsToDevice", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // scan lines copied
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GetDIBits", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // scan lines
			return 0
		})
	}
	})
	delayHandlerRegistrars[len(delayHandlerRegistrars)-1]()

	// --- crypt32.dll ---
	delayHandlerRegistrars = append(delayHandlerRegistrars, func() {
	if crypt32, ok := synthByName["crypt32.dll"]; ok {
		d.RegisterAutoStubHandler(crypt32, "CryptQueryObject", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE - no crypto
			return 0
		})
	}
	})
	delayHandlerRegistrars[len(delayHandlerRegistrars)-1]()

	// --- advapi32.dll ---
	delayHandlerRegistrars = append(delayHandlerRegistrars, func() {
	if advapi32, ok := synthByName["advapi32.dll"]; ok {
		d.RegisterAutoStubHandler(advapi32, "AllocateAndInitializeSid", func(ctx *ntapi.TrapContext) uint32 {
			// Allocate a minimal SID in guest memory
			pSid := ctx.Arg(8) // 9th arg (stack arg on Win64)
			if pSid != 0 {
				sidBuf := mem.Mmap(0, 28, mmu.PermRead|mmu.PermWrite)
				ctx.Mem.Write64(pSid, sidBuf)
			}
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(advapi32, "CheckTokenMembership", func(ctx *ntapi.TrapContext) uint32 {
			pIsMember := ctx.Arg(2)
			if pIsMember != 0 {
				ctx.Mem.Write32(pIsMember, 0) // not a member (non-admin)
			}
			ctx.SetReturn(1) // TRUE (success)
			return 0
		})
		d.RegisterAutoStubHandler(advapi32, "FreeSid", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // NULL on success
			return 0
		})
	}
	})
	delayHandlerRegistrars[len(delayHandlerRegistrars)-1]()
}

// autoSynthUnresolved generates synthetic stub DLLs for any DLLs referenced
// in the main module's imports that aren't already in loadedModules.
func autoSynthUnresolved(mem *mmu.MMU, mainMod *loader.PEModule, loaded map[string]*loader.PEModule) []*ntapi.SynthPE {
	// Collect function names per unresolved DLL
	needed := make(map[string][]string) // dll name → function names
	for _, imp := range mainMod.Imports {
		dllKey := strings.ToLower(imp.DLLName)
		if _, ok := loaded[dllKey]; ok {
			continue
		}
		if _, ok := loaded[strings.TrimSuffix(dllKey, ".dll")]; ok {
			continue
		}
		if imp.FuncName != "" {
			needed[dllKey] = append(needed[dllKey], imp.FuncName)
		}
	}

	var result []*ntapi.SynthPE
	nextID := uint32(ntapi.AutoSynthIDBase)
	for dllName, funcs := range needed {
		// Deduplicate function names
		seen := make(map[string]bool)
		var unique []string
		for _, f := range funcs {
			if !seen[f] {
				seen[f] = true
				unique = append(unique, f)
			}
		}
		synth := ntapi.GenerateSynthDLL(mem, dllName, unique, nextID)
		result = append(result, synth)
		nextID += uint32(len(unique))
		ravelog.Logf("[pe] auto-synth %s: %d stubs (id base 0x%X)\n",
			dllName, len(unique), nextID-uint32(len(unique)))
	}
	return result
}

// patchCRTDataExports fixes IAT slots for known msvcrt data exports.
// These are variables (not functions) whose IAT slots must point to
// actual guest memory containing the proper values.
func patchCRTDataExports(mem *mmu.MMU, mainMod *loader.PEModule, argv []string) {
	cmdLine := strings.Join(argv, " ")

	// Allocate a page for CRT data variables
	dataPage := mem.Mmap(0, 4096, mmu.PermRead|mmu.PermWrite)

	// Layout within the data page:
	// +0x000: command line string (null-terminated)
	// +0x200: _acmdln pointer (char* → command line string)
	// +0x208: _commode value (int, 0)
	// +0x210: _fmode value (int, 0)
	// +0x218: __initenv pointer (char** → null)
	// +0x220: _errno value (int, 0)
	// +0x228: __mb_cur_max value (int, 1)

	// Write command line string
	mem.WriteBytes(dataPage+0x000, append([]byte(cmdLine), 0))

	// _acmdln: pointer to the command line string
	mem.Write64(dataPage+0x200, dataPage+0x000)

	// _commode: 0
	mem.Write32(dataPage+0x208, 0)

	// _fmode: 0
	mem.Write32(dataPage+0x210, 0)

	// __initenv: null pointer
	mem.Write64(dataPage+0x218, 0)

	// _errno: 0
	mem.Write32(dataPage+0x220, 0)

	// __mb_cur_max: 1
	mem.Write32(dataPage+0x228, 1)

	// Map of data export names to their addresses
	dataExports := map[string]uint64{
		"_acmdln":   dataPage + 0x200,
		"_commode":  dataPage + 0x208,
		"_fmode":    dataPage + 0x210,
		"__initenv": dataPage + 0x218,
	}

	// Patch IAT slots
	for _, imp := range mainMod.Imports {
		if addr, ok := dataExports[imp.FuncName]; ok {
			mem.Write64Raw(imp.IATSlot, addr)
		}
	}
}

// patchUnresolvedOrdinals finds imports that are still pointing at the
// unresolved-sentinel address and replaces each IAT slot with a tiny vmcall
// trampoline that logs the call and returns 0.  This covers ordinal-only
// imports (e.g. COMCTL32 FlatSB ordinals) that no synthetic DLL exposes.
func patchUnresolvedOrdinals(mem *mmu.MMU, d *ntapi.Dispatcher, mainMod *loader.PEModule) {
	const unresolvedSentinel = 0xDEAD_DEAD_0001_0000
	// ID range reserved for ordinal stubs - well above auto-synth (0x2000+)
	const ordinalIDBase = uint32(0xF000)
	const stubBytes = 9 // B8 xx xx xx xx | 0F 01 C1 | C3

	// Collect unresolved entries
	var unresolved []loader.PEImportEntry
	for _, imp := range mainMod.Imports {
		if !mainMod.Is64 {
			continue
		}
		v, _ := mem.Read64(imp.IATSlot)
		if v == unresolvedSentinel {
			unresolved = append(unresolved, imp)
		}
	}
	if len(unresolved) == 0 {
		return
	}

	// Allocate one page for all stubs
	trampolinePage := mem.Mmap(0, uint64(len(unresolved))*stubBytes+64, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)

	for i, imp := range unresolved {
		id := ordinalIDBase + uint32(i)
		stubAddr := trampolinePage + uint64(i)*stubBytes

		// mov eax, id  (B8 id_lo id_hi 00 00)
		mem.Write8(stubAddr+0, 0xB8)
		mem.Write32(stubAddr+1, id)
		// vmcall  (0F 01 C1)
		mem.Write8(stubAddr+5, 0x0F)
		mem.Write8(stubAddr+6, 0x01)
		mem.Write8(stubAddr+7, 0xC1)
		// ret  (C3)
		mem.Write8(stubAddr+8, 0xC3)

		// Capture for closure
		capturedImp := imp
		d.RegisterHandler(id, fmt.Sprintf("%s!ord%d", capturedImp.DLLName, capturedImp.Ordinal),
			func(ctx *ntapi.TrapContext) uint32 {
				ravelog.Logf("[ordinal] %s!ord%d → 0\n", capturedImp.DLLName, capturedImp.Ordinal)
				return 0
			})

		mem.Write64Raw(imp.IATSlot, stubAddr)
		ravelog.Logf("[ordinal] patched %s!ord%d IAT=0x%x → stub=0x%x\n",
			imp.DLLName, imp.Ordinal, imp.IATSlot, stubAddr)
	}
}

// loadBYODLLs loads real Windows DLLs from the sysroot directory.
// Returns updated module info, loaded modules map, and DLL load order (for DllMain).
// Uses two-pass loading: first map all DLLs into memory, then resolve imports.
// This handles circular dependencies (e.g. user32 ↔ gdi32).
func loadBYODLLs(mem *mmu.MMU, sysroot string, mainMod *loader.PEModule,
modules []ntapi.ModuleInfo, loaded map[string]*loader.PEModule) ([]ntapi.ModuleInfo, map[string]*loader.PEModule, []*loader.PEModule) {

var loadOrder []*loader.PEModule

queue := make([]string, 0)
for _, imp := range mainMod.Imports {
dllName := strings.ToLower(imp.DLLName)
if _, ok := loaded[dllName]; !ok {
queue = append(queue, dllName)
}
}

seen := make(map[string]bool)
for _, name := range queue {
seen[name] = true
}

// Pass 1: Load all DLLs into memory (MapPEFile) without resolving imports
for len(queue) > 0 {
dllName := queue[0]
queue = queue[1:]

if _, ok := loaded[dllName]; ok {
continue
}

// Resolve API sets
resolved := ntapi.ApiSetResolve(dllName)
if resolved != dllName {
if _, ok := loaded[resolved]; ok {
loaded[dllName] = loaded[resolved]
continue
}
dllName = resolved
}

if dllName == "ntdll.dll" || dllName == "win32u.dll" {
continue
}

dllPath := findDLL(sysroot, dllName)
if dllPath == "" {
continue
}

mod, err := loader.MapPEFile(dllPath, mem, 0)
if err != nil {
fmt.Fprintf(os.Stderr, "govm: warning: failed to load %s: %v\n", dllName, err)
continue
}

ravelog.Logf("[pe] BYODLL %s: base=0x%x size=0x%x entry=0x%x\n", mod.Name, mod.BaseAddr, mod.ImageSize, mod.EntryPoint)
loaded[strings.ToLower(mod.Name)] = mod
loadOrder = append(loadOrder, mod)
modules = append(modules, ntapi.ModuleInfo{
Name:      mod.Name,
FullPath:  `C:\Windows\System32\` + mod.Name,
BaseAddr:  mod.BaseAddr,
ImageSize: mod.ImageSize,
Entry:     mod.EntryPoint,
})

// Enqueue transitive deps
for _, imp := range mod.Imports {
depName := strings.ToLower(imp.DLLName)
if !seen[depName] {
seen[depName] = true
queue = append(queue, depName)
}
}
}

// Pass 2: Resolve imports for all loaded DLLs (handles circular deps)
for _, mod := range loadOrder {
loader.ResolveImports(mem, mod, loaded)
}

// Topological sort: DllMain must call dependencies before dependants
sorted := topoSortDLLs(loadOrder, loaded)

return modules, loaded, sorted
}

// topoSortDLLs returns DLLs in dependency-first order for DllMain calling.
func topoSortDLLs(dlls []*loader.PEModule, loaded map[string]*loader.PEModule) []*loader.PEModule {
	byName := make(map[string]*loader.PEModule)
	for _, d := range dlls {
		byName[strings.ToLower(d.Name)] = d
	}

	visited := make(map[string]bool)
	var result []*loader.PEModule
	var visit func(mod *loader.PEModule)
	visit = func(mod *loader.PEModule) {
		name := strings.ToLower(mod.Name)
		if visited[name] {
			return
		}
		visited[name] = true
		for _, imp := range mod.Imports {
			depName := strings.ToLower(imp.DLLName)
			if dep, ok := byName[depName]; ok {
				visit(dep)
			}
		}
		result = append(result, mod)
	}
	for _, d := range dlls {
		visit(d)
	}
	return result
}

// findDLL searches for a DLL file in the sysroot.
func findDLL(sysroot, name string) string {
candidates := []string{
filepath.Join(sysroot, name),
filepath.Join(sysroot, "System32", name),
filepath.Join(sysroot, "system32", name),
filepath.Join(sysroot, "SysWOW64", name),
}
for _, path := range candidates {
if _, err := os.Stat(path); err == nil {
return path
}
}
return ""
}

// populateVFSFromHost recursively copies files from a host directory into the VFS.
// patchHotStubs replaces the hottest Win32 API stubs with inline x64 code
// that executes directly without trapping into Go, eliminating vmcall overhead.
func patchHotStubs(mem *mmu.MMU, dlls []*ntapi.SynthPE, flsDataArray uint64) {
	for _, synth := range dlls {
		if strings.ToLower(synth.Name) != "kernel32.dll" {
			continue
		}
		// GetLastError: mov eax, gs:[0x68]; ret
		synth.PatchStub(mem, "GetLastError", []byte{
			0x65, 0x8B, 0x04, 0x25, 0x68, 0x00, 0x00, 0x00, // mov eax, gs:[0x68]
			0xC3, // ret
		})
		// SetLastError: mov gs:[0x68], ecx; ret
		synth.PatchStub(mem, "SetLastError", []byte{
			0x65, 0x89, 0x0C, 0x25, 0x68, 0x00, 0x00, 0x00, // mov gs:[0x68], ecx
			0xC3, // ret
		})
		// GetCurrentThreadId: mov eax, gs:[0x48]; ret
		synth.PatchStub(mem, "GetCurrentThreadId", []byte{
			0x65, 0x8B, 0x04, 0x25, 0x48, 0x00, 0x00, 0x00, // mov eax, gs:[0x48]
			0xC3, // ret
		})
		// GetCurrentProcessId: mov eax, gs:[0x40]; ret
		synth.PatchStub(mem, "GetCurrentProcessId", []byte{
			0x65, 0x8B, 0x04, 0x25, 0x40, 0x00, 0x00, 0x00, // mov eax, gs:[0x40]
			0xC3, // ret
		})
		// FlsGetValue(index): mov rax, gs:[0x17c8]; mov rax, [rax+rcx*8]; ret
		synth.PatchStub(mem, "FlsGetValue", []byte{
			0x65, 0x48, 0x8B, 0x04, 0x25, 0xC8, 0x17, 0x00, 0x00, // mov rax, gs:[0x17c8]
			0x48, 0x8B, 0x04, 0xC8, // mov rax, [rax+rcx*8]
			0xC3, // ret
		})
		// FlsSetValue(index, value): mov rax, gs:[0x17c8]; mov [rax+rcx*8], rdx; mov eax, 1; ret
		synth.PatchStub(mem, "FlsSetValue", []byte{
			0x65, 0x48, 0x8B, 0x04, 0x25, 0xC8, 0x17, 0x00, 0x00, // mov rax, gs:[0x17c8]
			0x48, 0x89, 0x14, 0xC8, // mov [rax+rcx*8], rdx
			0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
			0xC3, // ret
		})
		// EnterCriticalSection / LeaveCriticalSection: just ret (no-ops, single-threaded)
		synth.PatchStub(mem, "EnterCriticalSection", []byte{0xC3})
		synth.PatchStub(mem, "LeaveCriticalSection", []byte{0xC3})

		// HeapFree: mov eax, 1; ret (no-op for bump allocator)
		synth.PatchStub(mem, "HeapFree", []byte{
			0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
			0xC3, // ret
		})

		// HeapAlloc(hHeap=RCX, flags=RDX, size=R8) → bump allocator with 16-byte header
		// Layout: [totalBlockSize:8][pad:8][userData...]
		synth.PatchStub(mem, "HeapAlloc", []byte{
			0x49, 0x83, 0xC0, 0x0F,                               // add r8, 15
			0x49, 0x83, 0xE0, 0xF0,                               // and r8, -16
			0x49, 0x83, 0xC0, 0x10,                               // add r8, 16 (header)
			0x65, 0x48, 0x8B, 0x04, 0x25, 0x08, 0x18, 0x00, 0x00, // mov rax, gs:[0x1808] (offset)
			0x4A, 0x8D, 0x0C, 0x00,                               // lea rcx, [rax+r8]
			0x65, 0x48, 0x89, 0x0C, 0x25, 0x08, 0x18, 0x00, 0x00, // mov gs:[0x1808], rcx (store new offset)
			0x65, 0x48, 0x03, 0x04, 0x25, 0x00, 0x18, 0x00, 0x00, // add rax, gs:[0x1800] (add base)
			0x4C, 0x89, 0x00,                                     // mov [rax], r8 (header = block size)
			0x48, 0x83, 0xC0, 0x10,                               // add rax, 16 (return user ptr)
			0xC3,                                                  // ret
		})

		break
	}

	// Patch hot ucrtbase stubs with inline x64 code
	for _, synth := range dlls {
		if strings.ToLower(synth.Name) != "ucrtbase.dll" {
			continue
		}

		// wcslen(RCX): scan for 0 WORD, return count in RAX
		// xor eax, eax; .loop: cmp word [rcx+rax*2], 0; je .done; inc rax; jmp .loop; .done: ret
		synth.PatchStub(mem, "wcslen", []byte{
			0x48, 0x31, 0xC0,                   // xor rax, rax
			0x66, 0x83, 0x3C, 0x41, 0x00,       // cmp word [rcx+rax*2], 0
			0x74, 0x04,                           // je +4 (.done)
			0x48, 0xFF, 0xC0,                     // inc rax
			0xEB, 0xF5,                           // jmp -11 (.loop)
			0xC3,                                 // ret
		})

		// strlen(RCX): scan for 0 byte, return count in RAX
		synth.PatchStub(mem, "strlen", []byte{
			0x48, 0x31, 0xC0,                   // xor rax, rax
			0x80, 0x3C, 0x01, 0x00,             // cmp byte [rcx+rax], 0
			0x74, 0x04,                           // je +4 (.done)
			0x48, 0xFF, 0xC0,                     // inc rax
			0xEB, 0xF6,                           // jmp -10 (.loop)
			0xC3,                                 // ret
		})

		// memset(RCX=dst, EDX=val, R8=count): fill and return dst in RAX
		synth.PatchStub(mem, "memset", []byte{
			0x48, 0x89, 0xC8,       // mov rax, rcx  (save dst for return)
			0x4D, 0x85, 0xC0,       // test r8, r8
			0x74, 0x07,             // je .done
			0x88, 0x11,             // mov [rcx], dl
			0x48, 0xFF, 0xC1,       // inc rcx
			0x49, 0xFF, 0xC8,       // dec r8
			0xEB, 0xF5,             // jmp .loop
			0xC3,                   // ret
		})

		// memcpy(RCX=dst, RDX=src, R8=count): copy and return dst in RAX
		synth.PatchStub(mem, "memcpy", []byte{
			0x48, 0x89, 0xC8,       // mov rax, rcx
			0x4D, 0x85, 0xC0,       // test r8, r8
			0x74, 0x09,             // je .done
			0x44, 0x8A, 0x0A,       // mov r9b, [rdx]
			0x44, 0x88, 0x09,       // mov [rcx], r9b
			0x48, 0xFF, 0xC1,       // inc rcx
			0x48, 0xFF, 0xC2,       // inc rdx
			0x49, 0xFF, 0xC8,       // dec r8
			0xEB, 0xF1,             // jmp .loop
			0xC3,                   // ret
		})

		break
	}
}

func populateVFSFromHost(fs *vfs.VFS, hostDir, vfsDir string) {
	entries, err := os.ReadDir(hostDir)
	if err != nil {
		return
	}
	fs.MkdirAll(vfsDir)
	for _, e := range entries {
		hostPath := filepath.Join(hostDir, e.Name())
		vfsPath := vfsDir + "/" + e.Name()
		if e.IsDir() {
			populateVFSFromHost(fs, hostPath, vfsPath)
		} else {
			data, err := os.ReadFile(hostPath)
			if err != nil {
				continue
			}
			// Skip very large files (>16MB) to avoid memory issues
			if len(data) > 16*1024*1024 {
				continue
			}
			fs.CreateFile(vfsPath, data, 0644)
		}
	}
}

// winPathToVFS converts a Windows-style path to a VFS path.
func winPathToVFS(winPath string) string {
	// Replace backslashes with forward slashes
	p := strings.ReplaceAll(winPath, `\`, "/")
	// Remove drive letter prefix (C:/, D:/, etc.)
	if len(p) >= 2 && p[1] == ':' {
		p = p[2:]
	}
	// Ensure leading slash
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}

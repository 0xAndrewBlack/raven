package main

import (
"bufio"
"bytes"
"flag"
"fmt"
"image"
"image/color"
"image/png"
"io"
"math"
"os"
"path/filepath"
"runtime/pprof"
"sort"
"strconv"
"strings"
"sync"
"time"
"unicode"

"golang.org/x/sys/unix"

"github.com/mirkobrombin/Raven/pkg/arch"
"github.com/mirkobrombin/Raven/pkg/cpu"
gdi "github.com/mirkobrombin/Raven/pkg/gdi"
"github.com/mirkobrombin/Raven/pkg/loader"
"github.com/mirkobrombin/Raven/pkg/mmu"
"github.com/mirkobrombin/Raven/pkg/ntapi"
gosyscall "github.com/mirkobrombin/Raven/pkg/syscall"
"github.com/mirkobrombin/Raven/pkg/thread"
"github.com/mirkobrombin/Raven/pkg/vfs"
"github.com/mirkobrombin/Raven/pkg/wl"
comctl32pkg "github.com/mirkobrombin/Raven/pkg/comctl32"
win32 "github.com/mirkobrombin/Raven/pkg/win32"
"github.com/mirkobrombin/Raven/pkg/win32k"
"github.com/mirkobrombin/Raven/pkg/x64"
"github.com/mirkobrombin/Raven/pkg/jit"
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

// Record boot time for GetTickCount / KUSER_SHARED_DATA TickCount updates.
// Pretend the system booted 2 hours ago to avoid sandbox uptime detection.
bootTime := time.Now().Add(-2 * time.Hour)

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

// Pre-generate full kernel32.dll and comctl32.dll with ALL exports so that
// any application (not just NPP) can resolve every function they export.
synthKernel32 := ntapi.GenerateKernel32(mem)
synthComctl32 := ntapi.GenerateComctl32(mem)
synthOleaut32 := ntapi.GenerateOleaut32(mem)

// Map KUSER_SHARED_DATA at 0x7FFE0000 (required by Wine DLLs and many apps that
// read timing/version data directly without going through the Win32 API).
kuserAddr := uint64(0x7FFE0000)
kuserSize := uint64(0x1000)
mem.Mmap(kuserAddr, kuserSize, mmu.PermRead|mmu.PermWrite)

// --- Time fields ---
// TickCountLowDeprecated (+0x000) - unused in Win10 but zero is fine
// TickCountMultiplier (+0x004): 0x0FA00000 = 156,250 units-of-100ns per tick (15.625ms ticks).
// GetTickCount = TickCount.LowPart * TickCountMultiplier >> 24.
mem.Write32(kuserAddr+0x004, 0x0FA00000)

// SystemTime (+0x014): KSYSTEM_TIME {LowPart, High1Time, High2Time}.
// FILETIME = 100ns units since 1601-01-01.
{
	const epochDiff = uint64(11644473600) * 10000000 // 1970→1601 in 100ns
	ft := uint64(time.Now().UnixNano()/100) + epochDiff
	mem.Write32(kuserAddr+0x014, uint32(ft))         // LowPart
	mem.Write32(kuserAddr+0x018, uint32(ft>>32))     // High1Time
	mem.Write32(kuserAddr+0x01C, uint32(ft>>32))     // High2Time (duplicate)
}
// InterruptTime (+0x008): 100ns units since boot. Init to 1 second.
mem.Write64Raw(kuserAddr+0x008, 10000000)
mem.Write32(kuserAddr+0x010, 0) // High2Time

// TimeZoneBias (+0x020): 0 = UTC (no local bias). Apps calling GetLocalTime add this.
mem.Write64Raw(kuserAddr+0x020, 0)
mem.Write32(kuserAddr+0x028, 0)

// TickCount (+0x0320): KSYSTEM_TIME union with TickCountQuad.
// Init to 2h uptime (matches bootTime offset) so inline-reading apps see realistic value.
{
	uptickMs := uint64(2 * 60 * 60 * 1000) // 2 hours in ms
	// TickCount.LowPart = uptickMs / tickInterval (15.625ms per tick)
	ticks := uptickMs * 64 / 1000 // ~128000 ticks for 2h
	mem.Write32(kuserAddr+0x0320, uint32(ticks))
	mem.Write32(kuserAddr+0x0324, 0) // High1Time
	mem.Write32(kuserAddr+0x0328, 0) // TickCountPad
}

// --- Version / Platform ---
// NtBuildNumber (+0x0260) = 19045 (Windows 10 21H2)
mem.Write32(kuserAddr+0x0260, 19045)
// NtMajorVersion (+0x026C) = 10, NtMinorVersion (+0x0270) = 0
mem.Write32(kuserAddr+0x026C, 10)
mem.Write32(kuserAddr+0x0270, 0)
// NtProductType (+0x0264) = 1 (VER_NT_WORKSTATION)
mem.Write32(kuserAddr+0x0264, 1)
// ProductTypeIsValid (+0x0268) = TRUE
mem.Write8(kuserAddr+0x0268, 1)
// NativeProcessorArchitecture (+0x026A) = 9 (PROCESSOR_ARCHITECTURE_AMD64)
mem.Write16(kuserAddr+0x026A, 9)
// SuiteMask (+0x02D0) = 0x0100 (VER_SUITE_SINGLEUSERTS)
mem.Write32(kuserAddr+0x02D0, 0x0100)
// ImageNumberLow/High (+0x02C/0x02E) = IMAGE_FILE_MACHINE_AMD64 = 0x8664
mem.Write16(kuserAddr+0x02C, 0x8664)
mem.Write16(kuserAddr+0x02E, 0x8664)
// NumberOfPhysicalPages (+0x02E8)
mem.Write32(kuserAddr+0x02E8, 4*1024*1024/4) // 4GB / 4KB = 1M pages

// NtSystemRoot (+0x030): L"C:\\Windows" (WCHAR[260])
{
	root := []uint16{'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', 0}
	for i, c := range root {
		mem.Write16(kuserAddr+0x030+uint64(i)*2, c)
	}
}

// --- QPC (QueryPerformanceCounter/Frequency) ---
// QpcFrequency (+0x0300) = 10,000,000 Hz (10 MHz = 100ns resolution)
mem.Write64Raw(kuserAddr+0x0300, 10000000)

// Cookie (+0x0330) for EncodeSystemPointer
mem.Write32(kuserAddr+0x0330, 0xDEADC0DE)

// ProcessorFeatures (+0x0274): mark common features present
// PF_COMPARE_EXCHANGE_DOUBLE=2, PF_MMX=3, PF_XMMI=6, PF_RDTSC=8, PF_XMMI64=10,
// PF_SSE3=13, PF_CMPXCHG16B=14, PF_XSAVE=17, PF_RDWRFSGSBASE=22
for _, pf := range []uint64{2, 3, 6, 8, 10, 13, 14, 17, 22} {
	mem.Write8(kuserAddr+0x0274+pf, 1)
}

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
loadedModules["kernel32.dll"] = ntapi.SynthToModule(synthKernel32)
loadedModules["comctl32.dll"] = ntapi.SynthToModule(synthComctl32)
loadedModules["oleaut32.dll"] = ntapi.SynthToModule(synthOleaut32)

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
// Pre-create shcore.dll so DPI functions are available via GetProcAddress
synthShcore := ntapi.GenerateSynthDLL(mem, "shcore.dll", []string{}, 0)
// Include pre-generated full DLLs so their handlers are wired in registerAutoSynthHandlers.
autoSynthDLLs = append(autoSynthDLLs, synthKernel32, synthComctl32, synthOleaut32, synthShcore)
for _, synth := range autoSynthDLLs {
	dllKey := strings.ToLower(synth.Name)
	if _, already := loadedModules[dllKey]; !already {
		loadedModules[dllKey] = ntapi.SynthToModule(synth)
	}
	modules = append(modules, ntapi.ModuleInfo{
		Name:      synth.Name,
		FullPath:  `C:\Windows\System32\` + synth.Name,
		BaseAddr:  synth.BaseAddr,
		ImageSize: synth.ImageSize,
		Entry:     synth.BaseAddr,
	})
}

// Add well-known ordinal aliases for auto-synth DLLs.
for _, synth := range autoSynthDLLs {
	switch strings.ToLower(synth.Name) {
	case "shell32.dll":
		// Map ordinal 165 → SHCreateDirectoryExW or its placeholder
		for _, name := range []string{"SHCreateDirectoryExW", "ord_165"} {
			if addr, ok := synth.Exports[name]; ok {
				synth.ExportOrds[165] = addr
				break
			}
		}
	}
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
var tmPtr *thread.Manager

// Pre-allocate the heap region and wire to TEB for inline HeapAlloc.
// Must happen before registerAutoSynthHandlers so sharedHeapAlloc can read it.
const heapInlineSize = 256 * 1024 * 1024 // 256MB
heapRegion := mem.Mmap(0, heapInlineSize, mmu.PermRead|mmu.PermWrite)
mem.Write64(procState.TEBAddr+ntapi.TebHeapBase, heapRegion)
mem.Write64(procState.TEBAddr+ntapi.TebHeapOffset, 0)

registerAutoSynthHandlers(mem, dispatcher, autoSynthDLLs, guestArgv, cmdLine, winImagePath, handles, procState, exceptionTable, result.MainModule, &tmPtr, bootTime, registry)

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

// Wire JIT compiler
jitCache := jit.NewCache(mem)
_ = jitCache // JIT disabled - needs debugging for NPP

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
tmPtr = tm
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
ravelog.Logf("[pe] calling DllMain for %s (entry=0x%x base=0x%x)\n", dll.Name, dll.EntryPoint, dll.BaseAddr)
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

// Background goroutine to keep KUSER_SHARED_DATA TickCount and SystemTime up-to-date.
// Many apps read these directly without calling Win32 APIs.
go func() {
	const epochDiff = uint64(11644473600) * 10000000 // 1970→1601 in 100ns
	const tickMul = uint64(0x0FA00000)               // TickCountMultiplier
	ticker := time.NewTicker(15 * time.Millisecond)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		// TickCount (+0x0320): ticks since boot (1 tick = 15.625ms = 156250 units of 100ns)
		uptimeNs := uint64(now.Sub(bootTime).Nanoseconds() / 100) // in 100ns units
		tickCount := (uptimeNs / 156250)                          // raw tick count
		mem.Write64Raw(kuserAddr+0x0320, tickCount)
		// TickCountLowDeprecated (+0x000): low32 * multiplier >> 24 = ms
		tms := uint32((tickCount * tickMul) >> 24)
		mem.Write32(kuserAddr+0x000, tms)
		// InterruptTime (+0x008): 100ns units since boot
		mem.Write64Raw(kuserAddr+0x008, uptimeNs)
		mem.Write32(kuserAddr+0x010, 0) // High2Time
		// SystemTime (+0x014): FILETIME (100ns since 1601-01-01)
		ft := uint64(now.UnixNano()/100) + epochDiff
		mem.Write32(kuserAddr+0x014, uint32(ft))
		mem.Write32(kuserAddr+0x018, uint32(ft>>32))
		mem.Write32(kuserAddr+0x01C, uint32(ft>>32))
	}
}()

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
func registerAutoSynthHandlers(mem *mmu.MMU, d *ntapi.Dispatcher, dlls []*ntapi.SynthPE, argv []string, cmdLine, imagePath string, handles *ntapi.HandleTable, procState *ntapi.ProcessState, exceptionTable *ntapi.ExceptionTable, mainModule *loader.PEModule, tmPtr **thread.Manager, bootTime time.Time, regHive *ntapi.RegistryHive) {
	synthByName := make(map[string]*ntapi.SynthPE)
	for _, s := range dlls {
		synthByName[strings.ToLower(s.Name)] = s
	}

	// startTime aliases bootTime for handler closures that measure elapsed time.
	startTime := bootTime

	// Shared stdin reader for ReadConsoleW/ReadConsoleA (avoids data loss from
	// creating a new bufio.Reader per call when input is piped).
	stdinReader := bufio.NewReader(os.Stdin)

	// Shared heap free-list (used by kernel32 HeapAlloc/HeapFree AND CRT malloc/free)
	type freeBlock struct {
		addr      uint64
		blockSize uint64
	}
	var heapFreeList []freeBlock
	heapMmapBlocks := make(map[uint64]uint64) // user ptr → block size

	heapRegion, _ := mem.Read64(procState.TEBAddr + ntapi.TebHeapBase)

	sharedHeapAlloc := func(size uint64, zeroInit bool) uint64 {
		if size == 0 {
			size = 1
		}
		size = (size + 15) &^ 15 // align to 16
		totalBlock := size + 16  // 16-byte header

		// Search free list for best fit
		bestIdx := -1
		bestSize := uint64(0)
		for i, fb := range heapFreeList {
			if fb.blockSize >= totalBlock {
				if bestIdx == -1 || fb.blockSize < bestSize {
					bestIdx = i
					bestSize = fb.blockSize
				}
				if fb.blockSize == totalBlock {
					break
				}
			}
		}
		if bestIdx >= 0 {
			fb := heapFreeList[bestIdx]
			heapFreeList[bestIdx] = heapFreeList[len(heapFreeList)-1]
			heapFreeList = heapFreeList[:len(heapFreeList)-1]
			mem.Write64(fb.addr, fb.blockSize)
			userPtr := fb.addr + 16
			if zeroInit {
				for i := uint64(0); i < size; i++ {
					mem.Write8(userPtr+i, 0)
				}
			}
			return userPtr
		}

		// Bump allocator
		heapOff, _ := mem.Read64(procState.TEBAddr + ntapi.TebHeapOffset)
		if heapOff+totalBlock <= 256*1024*1024 {
			addr := heapRegion + heapOff
			mem.Write64(addr, totalBlock)
			heapOff += totalBlock
			mem.Write64(procState.TEBAddr+ntapi.TebHeapOffset, heapOff)
			return addr + 16
		}

		// Mmap overflow
		addr := mem.Mmap(0, totalBlock, mmu.PermRead|mmu.PermWrite)
		if addr == 0 {
			heapOff, _ := mem.Read64(procState.TEBAddr + ntapi.TebHeapOffset)
			var freeTotal uint64
			for _, fb := range heapFreeList {
				freeTotal += fb.blockSize
			}
			ravelog.Logf("[heap] OOM: bump=%dMB/%dMB freeList=%d entries (%dKB) mmapBlocks=%d requested=%d\n",
				heapOff/(1024*1024), 256, len(heapFreeList), freeTotal/1024, len(heapMmapBlocks), totalBlock)
			return 0
		}
		mem.Write64(addr, totalBlock)
		userPtr := addr + 16
		heapMmapBlocks[userPtr] = totalBlock
		return userPtr
	}

	sharedHeapFree := func(ptr uint64) {
		if ptr == 0 {
			return
		}
		if sz, isMmap := heapMmapBlocks[ptr]; isMmap {
			delete(heapMmapBlocks, ptr)
			heapFreeList = append(heapFreeList, freeBlock{addr: ptr - 16, blockSize: sz})
			return
		}
		headerAddr := ptr - 16
		blockSize, _ := mem.Read64(headerAddr)
		if blockSize > 0 && blockSize < 1<<30 {
			heapFreeList = append(heapFreeList, freeBlock{addr: headerAddr, blockSize: blockSize})
		}
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
	var mainActive = true // whether the main window is focused (for active caption)
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
	envVars := map[string]string{} // guest environment variables (SetEnvironmentVariableW/GetEnvironmentVariableW)
	type menuItem struct {
		flags   uint32
		id      uint64
		text    string
		submenu []menuItem // for popup items (MF_POPUP)
	}
	type menuData struct {
		items []menuItem
	}

	// viewMapping tracks an active MapViewOfFile view for sync-back.
	type viewMapping struct {
		GuestAddr uint64
		HostBuf   []byte // sub-slice of FileMappingHandle.HostBuf at the mapped offset
		Size      uint64
		FileFD    int  // -1 for anonymous
		Offset    uint64
		Writable  bool
		FM        *ntapi.FileMappingHandle
	}
	var viewMappings []viewMapping
	namedMappings := map[string]*ntapi.FileMappingHandle{}

	// doCreateFileMapping implements the core of CreateFileMappingW/A.
	doCreateFileMapping := func(ctx *ntapi.TrapContext, hFile ntapi.Handle, flProtect uint32, szHigh, szLow uint32, name string) uint64 {
		size := uint64(szHigh)<<32 | uint64(szLow)

		fileFD := -1
		if hFile != ntapi.InvalidHandle {
			if fh := handles.GetFile(hFile); fh != nil {
				fileFD = fh.FD
			}
		}

		if size == 0 && fileFD >= 0 {
			if node := ctx.FS.Stat(fileFD); node != nil {
				size = uint64(node.Size)
			}
		}
		if size == 0 {
			size = 4096
		}
		// Round up to page boundary.
		size = (size + 4095) &^ 4095

		hostBuf := make([]byte, size)
		if fileFD >= 0 {
			ctx.FS.Pread(fileFD, hostBuf, 0)
		}

		fm := &ntapi.FileMappingHandle{
			Name:    name,
			HostBuf: hostBuf,
			Size:    size,
			FileFD:  fileFD,
			Protect: flProtect,
		}
		if name != "" {
			namedMappings[name] = fm
		}
		h := handles.Alloc(fm)
		return uint64(h)
	}

	// doMapView implements MapViewOfFile / MapViewOfFileEx.
	doMapView := func(ctx *ntapi.TrapContext, hMapping ntapi.Handle, dwDesiredAccess uint32, offHigh, offLow uint32, numBytes uint64) uint64 {
		fm := handles.GetFileMapping(hMapping)
		if fm == nil {
			return 0
		}
		offset := uint64(offHigh)<<32 | uint64(offLow)
		mapSize := numBytes
		if mapSize == 0 {
			if offset < fm.Size {
				mapSize = fm.Size - offset
			} else {
				mapSize = fm.Size
			}
		}
		mapSize = (mapSize + 4095) &^ 4095
		if offset+mapSize > uint64(len(fm.HostBuf)) {
			// Extend HostBuf if needed (e.g. file grew or size was rounded up).
			needed := offset + mapSize
			if needed > fm.Size {
				extended := make([]byte, needed)
				copy(extended, fm.HostBuf)
				fm.HostBuf = extended
				fm.Size = needed
			}
		}

		guestAddr := mem.Mmap(0, mapSize, mmu.PermRead|mmu.PermWrite)
		ctx.Mem.WriteBytes(guestAddr, fm.HostBuf[offset:offset+mapSize])

		const fileMapWrite = 0x0002
		writable := (dwDesiredAccess&fileMapWrite) != 0 ||
			fm.Protect == 0x04 || fm.Protect == 0x08 // PAGE_READWRITE / PAGE_WRITECOPY

		viewMappings = append(viewMappings, viewMapping{
			GuestAddr: guestAddr,
			HostBuf:   fm.HostBuf[offset : offset+mapSize],
			Size:      mapSize,
			FileFD:    fm.FileFD,
			Offset:    offset,
			Writable:  writable,
			FM:        fm,
		})
		return guestAddr
	}

	// doUnmapView syncs guest memory back to the host buffer and file, then removes the view.
	doUnmapView := func(ctx *ntapi.TrapContext, lpBase uint64) bool {
		for i, vm := range viewMappings {
			if vm.GuestAddr != lpBase {
				continue
			}
			if vm.Writable {
				// Sync guest pages → HostBuf slice.
				if guestData, err := ctx.Mem.ReadBytes(vm.GuestAddr, int(vm.Size)); err == nil {
					copy(vm.HostBuf, guestData)
					// Write back to the file if file-backed.
					if vm.FileFD >= 0 {
						ctx.FS.Pwrite(vm.FileFD, guestData, int64(vm.Offset))
					}
				}
			}
			viewMappings = append(viewMappings[:i], viewMappings[i+1:]...)
			return true
		}
		return true // not found is a no-op on Windows
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
		// Extended menu (MENUEX): WORD version (1), WORD wOffset, DWORD dwHelpId
		ver, _ := mem.Read16(dataAddr)
		hdrOff, _ := mem.Read16(dataAddr + 2)

		md := &menuData{}

		if ver == 1 {
			// MENUEX format
			// Header: WORD version=1, WORD wOffset, DWORD dwHelpId
			pos := dataAddr + 4 + uint64(hdrOff)
			end := dataAddr + uint64(dataSize)

			var parseMenuEx func(int, int) []menuItem
			parseMenuEx = func(maxItems int, depth int) []menuItem {
				var items []menuItem
				for len(items) < maxItems && pos < end {
					// Align to DWORD boundary
					if pos%4 != 0 {
						pos = (pos + 3) &^ 3
					}
					// MENUEX item: DWORD dwType, DWORD dwState, DWORD dwId, WORD resInfo
					dwType, _ := mem.Read32(pos)
					pos += 4
					_, _ = mem.Read32(pos) // dwState
					pos += 4
					dwID, _ := mem.Read32(pos)
					pos += 4
					resInfo, _ := mem.Read16(pos)
					pos += 2

					item := menuItem{flags: dwType, id: uint64(dwID)}
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


					const mfexPopup = 0x01 // resInfo bit 0 = has submenu
					if resInfo&mfexPopup != 0 {
						// Align before reading dwHelpId
						if pos%4 != 0 {
							pos = (pos + 3) &^ 3
						}
						// DWORD dwHelpId for popup
						pos += 4
						item.flags |= 0x0010 // set MF_POPUP for our internal use
						item.submenu = parseMenuEx(256, depth+1)
					}

					items = append(items, item)
					if resInfo&0x80 != 0 { // last item in this level
						break
					}
				}
				return items
			}

			md.items = parseMenuEx(32, 0)
			ravelog.Logf("[menu] peLoadMenuResource(MENUEX) id=%d parsed %d top-level items\n", menuID, len(md.items))
			for i, it := range md.items {
				ravelog.Logf("[menu]   [%d] flags=0x%x id=%d text=%q submenu=%d\n", i, it.flags, it.id, it.text, len(it.submenu))
			}
			return md
		}

		if ver != 0 {
			return nil // Unknown menu version
		}

		pos := dataAddr + 4 + uint64(hdrOff)
		end := dataAddr + uint64(dataSize)

		// Parse top-level items (recurse into popups)
		var parseItems func(maxItems int, depth int) []menuItem
		parseItems = func(maxItems int, depth int) []menuItem {
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
					item.submenu = parseItems(512, depth+1)
				}

				items = append(items, item)
				if flags&0x0080 != 0 { // MF_END
					break
				}
			}
			return items
		}

		md.items = parseItems(32, 0)
		ravelog.Logf("[menu] peLoadMenuResource id=%d parsed %d top-level items\n", menuID, len(md.items))
		for i, it := range md.items {
			ravelog.Logf("[menu]   [%d] flags=0x%x id=%d text=%q submenu=%d\n", i, it.flags, it.id, it.text, len(it.submenu))
		}
		return md
	}

	// peLoadRawResource loads a raw resource from a PE module given its base addr + rsrc RVA.
	// typeID is the RT_* constant (e.g. 2=RT_BITMAP), resID is the resource ID.
	// Returns the guest address of the resource data and its size in bytes.
	peLoadRawResource := func(moduleBase uint64, rsrcDirRVA uint32, typeID, resID uint32) (dataAddr uint64, dataSize uint32, ok bool) {
		if rsrcDirRVA == 0 {
			return 0, 0, false
		}
		rsrcBase := moduleBase + uint64(rsrcDirRVA)
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
					return rsrcBase + uint64(offset), isDir
				}
				entryAddr += 8
			}
			return 0, false
		}
		typeDir, isDir := findEntry(rsrcBase, typeID)
		if !isDir || typeDir == 0 {
			return 0, 0, false
		}
		idDir, isDir2 := findEntry(typeDir, resID)
		if idDir == 0 {
			return 0, 0, false
		}
		var dataEntry uint64
		if isDir2 {
			leafAddr, found := pickBestLangEntry(idDir, rsrcBase)
			if !found {
				return 0, 0, false
			}
			dataEntry = leafAddr
		} else {
			dataEntry = idDir
		}
		dataRVA, _ := mem.Read32(dataEntry)
		sz, _ := mem.Read32(dataEntry + 4)
		if dataRVA == 0 || sz == 0 {
			return 0, 0, false
		}
		return moduleBase + uint64(dataRVA), sz, true
	}

	// decodeDIBSlots decodes a raw DIB (no BITMAPFILEHEADER) stored at guestAddr/guestSize
	// and splits it into nSlots horizontal icon slots of iconW×iconH pixels.
	// Returns per-slot []uint32 XRGB pixel slices.
	decodeDIBSlots := func(guestAddr uint64, guestSize uint32, iconW, iconH int) [][]uint32 {
		if guestAddr == 0 || guestSize < 40 {
			return nil
		}
		biSize, _ := mem.Read32(guestAddr)
		if biSize < 40 {
			return nil
		}
		biWidthI, _ := mem.Read32(guestAddr + 4)
		biHeightI, _ := mem.Read32(guestAddr + 8)
		biBitCount, _ := mem.Read16(guestAddr + 14)
		biCompression, _ := mem.Read32(guestAddr + 16)
		if biCompression != 0 && biCompression != 3 { // only BI_RGB and BI_BITFIELDS
			return nil
		}
		biWidth := int(int32(biWidthI))
		biHeight := int(int32(biHeightI))
		topDown := biHeight < 0
		if topDown {
			biHeight = -biHeight
		}
		if biWidth <= 0 || biHeight <= 0 {
			return nil
		}
		// Palette size for indexed bitmaps
		biClrUsed, _ := mem.Read32(guestAddr + 32)
		palColors := int(biClrUsed)
		if palColors == 0 && biBitCount <= 8 {
			palColors = 1 << biBitCount
		}
		// Pixel data offset: header + palette
		pixelOffset := uint64(biSize) + uint64(palColors)*4
		var palette []uint32
		if palColors > 0 {
			for i := 0; i < palColors; i++ {
				bgra, _ := mem.Read32(guestAddr + uint64(biSize) + uint64(i)*4)
				b := (bgra) & 0xFF
				g := (bgra >> 8) & 0xFF
				r := (bgra >> 16) & 0xFF
				palette = append(palette, (r<<16)|(g<<8)|b)
			}
		}
		// stride in bytes, 4-byte aligned
		var stride int
		switch biBitCount {
		case 32:
			stride = biWidth * 4
		case 24:
			stride = (biWidth*3 + 3) &^ 3
		case 8:
			stride = (biWidth + 3) &^ 3
		case 4:
			stride = (biWidth/2 + 3) &^ 3
		default:
			return nil
		}
		// Read all rows into a flat XRGB array [biHeight rows, biWidth cols]
		allPix := make([]uint32, biWidth*biHeight)
		for row := 0; row < biHeight; row++ {
			srcRow := row
			if !topDown {
				srcRow = biHeight - 1 - row
			}
			rowBase := guestAddr + pixelOffset + uint64(srcRow)*uint64(stride)
			for col := 0; col < biWidth; col++ {
				var pixel uint32
				switch biBitCount {
				case 32:
					v, _ := mem.Read32(rowBase + uint64(col)*4)
					b := v & 0xFF
					g := (v >> 8) & 0xFF
					r := (v >> 16) & 0xFF
					pixel = (r << 16) | (g << 8) | b
				case 24:
					b0, _ := mem.ReadBytes(rowBase+uint64(col)*3, 3)
					if len(b0) == 3 {
						pixel = (uint32(b0[2]) << 16) | (uint32(b0[1]) << 8) | uint32(b0[0])
					}
				case 8:
					idx, _ := mem.ReadBytes(rowBase+uint64(col), 1)
					if len(idx) > 0 && int(idx[0]) < len(palette) {
						pixel = palette[idx[0]]
					}
				case 4:
					b0, _ := mem.ReadBytes(rowBase+uint64(col/2), 1)
					if len(b0) > 0 {
						var nibble byte
						if col&1 == 0 {
							nibble = b0[0] >> 4
						} else {
							nibble = b0[0] & 0xF
						}
						if int(nibble) < len(palette) {
							pixel = palette[nibble]
						}
					}
				}
				allPix[row*biWidth+col] = pixel
			}
		}
		// Split into icon slots: each slot is iconW wide, full height=iconH
		if iconW <= 0 {
			iconW = 16
		}
		if iconH <= 0 {
			iconH = biHeight
		}
		nSlots := biWidth / iconW
		if nSlots == 0 {
			nSlots = 1
		}
		slots := make([][]uint32, nSlots)
		for s := 0; s < nSlots; s++ {
			slot := make([]uint32, iconW*iconH)
			for row := 0; row < iconH && row < biHeight; row++ {
				for col := 0; col < iconW; col++ {
					src := row*biWidth + s*iconW + col
					if src < len(allPix) {
						slot[row*iconW+col] = allPix[src]
					}
				}
			}
			slots[s] = slot
		}
		return slots
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
	// gdiMgr manages all GDI objects and DCs. Screen surface is wired to
	// wlWindow.Pix when the Wayland window is created.
	// ReactOS reference: win32ss/gdi/ntgdi/gdiobj.c
	gdiMgr := gdi.NewManager()
	var frameCount int

	// Windows 10 system colors (COLORREF = 0x00RRGGBB)
	sysColors := [31]uint32{
		0x00C8C8C8, // 0  COLOR_SCROLLBAR
		0x003A6EA5, // 1  COLOR_BACKGROUND/DESKTOP
		0x000078D7, // 2  COLOR_ACTIVECAPTION (Win10 accent blue)
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
		0x000078D7, // 13 COLOR_HIGHLIGHT
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
		0x00FFFFE1, // 24 COLOR_INFOBK
		0x00000000, // 25 (reserved)
		0x000066CC, // 26 COLOR_HOTLIGHT
		0x00B4D0E7, // 27 COLOR_GRADIENTACTIVECAPTION (lighter blue for gradient)
		0x00DBD1C9, // 28 COLOR_GRADIENTINACTIVECAPTION
		0x000078D7, // 29 COLOR_MENUHILIGHT
		0x00F0F0F0, // 30 COLOR_MENUBAR
	}

	getSysColor := func(idx uint32) uint32 {
		if int(idx) < len(sysColors) {
			return sysColors[idx]
		}
		return 0x00C0C0C0
	}

	// syncScreenSurface rebuilds gdiMgr.Screen from wlWindow.Pix after resize.
	// Must be called after wlWindow.ResizeIfNeeded() and before any drawing.
	syncScreenSurface := func() {
		if wlWindow != nil {
			gdiMgr.Screen = gdi.WrapPix(wlWindow.Pix, wlWindow.Width, wlWindow.Height+wlWindow.TitleBarH, wlWindow.Stride)
		}
	}

	// allocScreenDC creates a new screen DC for the given window/child.
	allocScreenDC := func(ox, oy int32) (uint64, *gdi.DC) {
		syncScreenSurface()
		h, dc := gdiMgr.AllocScreenDC()
		dc.OriginX = ox
		dc.OriginY = oy
		return h, dc
	}

	// getDC is a safe accessor that always returns a valid DC.
	getDC := func(h uint64) *gdi.DC {
		dc := gdiMgr.GetDC(h)
		if dc != nil {
			return dc
		}
		syncScreenSurface()
		_, newDC := gdiMgr.AllocScreenDC()
		return newDC
	}

	// readDIBInfo reads a BITMAPINFOHEADER + optional colour table from guest memory.
	// Returns (width, height, bitCount, compression, colorTable, pixelDataOffset).
	// height>0 = bottom-up, height<0 = top-down. pixelDataOffset is from pBMI start.
	// ReactOS: NtGdiGetDIBitsInternal / NtGdiStretchDIBitsInternal
	readDIBInfo := func(pBMI uint64) (w, h, bitCount int32, compr uint32, ct []uint32, pixOff uint64) {
		if pBMI == 0 {
			return
		}
		biSize, _ := mem.Read32(pBMI)
		v, _ := mem.Read32(pBMI + 4);  w = int32(v)
		v, _ = mem.Read32(pBMI + 8);   h = int32(v)
		v16, _ := mem.Read16(pBMI + 14); bitCount = int32(v16)
		v, _ = mem.Read32(pBMI + 16);  compr = v
		v, _ = mem.Read32(pBMI + 32);  clrUsed := v  // biClrUsed

		headerSz := uint64(biSize)
		if headerSz < 40 {
			headerSz = 40
		}
		// Bit-fields masks take 12 bytes after header for BI_BITFIELDS
		if compr == gdi.BIbitfields {
			headerSz += 12
		}

		// Colour table follows the header
		ctOffset := pBMI + headerSz
		numColors := clrUsed
		if numColors == 0 {
			switch bitCount {
			case 1:  numColors = 2
			case 4:  numColors = 16
			case 8:  numColors = 256
			}
		}
		if numColors > 0 {
			ct = make([]uint32, numColors)
			for i := uint32(0); i < numColors; i++ {
				// RGBQUAD: blue, green, red, reserved
				bv, _ := mem.Read8(ctOffset + uint64(i)*4)
				gv, _ := mem.Read8(ctOffset + uint64(i)*4 + 1)
				rv, _ := mem.Read8(ctOffset + uint64(i)*4 + 2)
				ct[i] = uint32(rv)<<16 | uint32(gv)<<8 | uint32(bv)
			}
			pixOff = headerSz + uint64(numColors)*4
		} else {
			pixOff = headerSz
		}
		return
	}

	// readDIBPixels reads DIB pixel data from guest memory into a byte slice.
	readDIBPixels := func(pBits uint64, w, h, bitCount int32) []byte {
		if pBits == 0 || w == 0 {
			return nil
		}
		absH := h
		if absH < 0 {
			absH = -absH
		}
		stride := gdi.DIBStride(w, bitCount)
		size := int(stride) * int(absH)
		if size <= 0 {
			return nil
		}
		buf := make([]byte, size)
		for i := range buf {
			b, _ := mem.Read8(pBits + uint64(i))
			buf[i] = b
		}
		return buf
	}

	// crtStreamWriter returns the appropriate os writer for a CRT FILE* stream.
	// stderr = base + stride*2, everything else → stdout.
	crtStreamWriter := func(stream, base uint64, stride uint64) *os.File {
		if base != 0 && stream == base+stride*2 {
			return os.Stderr
		}
		return os.Stdout
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
		// MSVC FILE struct is 48 bytes on x64
		iobBuf := mem.Mmap(0, 4096, mmu.PermRead|mmu.PermWrite)
		iobBase := iobBuf
		const iobStride = 48 // sizeof(FILE) on MSVC x64
		d.RegisterAutoStubHandler(msvcrt, "__iob_func", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(iobBuf)
			return 0
		})

		// malloc / calloc / free / _onexit / _cexit / _amsg_exit / abort / exit
		d.RegisterAutoStubHandler(msvcrt, "malloc", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(sharedHeapAlloc(ctx.Arg(0), false))
			return 0
		})
		d.RegisterAutoStubHandler(msvcrt, "calloc", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(sharedHeapAlloc(ctx.Arg(0)*ctx.Arg(1), true))
			return 0
		})
		d.RegisterAutoStubHandler(msvcrt, "free", func(ctx *ntapi.TrapContext) uint32 {
			sharedHeapFree(ctx.Arg(0))
			return 0
		})

		d.RegisterAutoStubHandler(msvcrt, "_strdup", func(ctx *ntapi.TrapContext) uint32 {
			src := ctx.Arg(0)
			if src == 0 {
				ctx.SetReturn(0)
				return 0
			}
			var buf []byte
			for i := uint64(0); i < 0x100000; i++ {
				b, _ := mem.Read8(src + i)
				buf = append(buf, b)
				if b == 0 {
					break
				}
			}
			dst := sharedHeapAlloc(uint64(len(buf)+1), false)
			mem.WriteBytes(dst, buf)
			ctx.SetReturn(dst)
			return 0
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
			str := readGuestString(ctx.Arg(0))
			stream := ctx.Arg(1)
			if stream == iobBase+iobStride*2 {
				os.Stderr.WriteString(str)
			} else {
				os.Stdout.WriteString(str)
			}
			ctx.SetReturn(0) // success (non-negative = ok)
			return 0
		})
		d.RegisterAutoStubHandler(msvcrt, "fputc", func(ctx *ntapi.TrapContext) uint32 {
			c := byte(ctx.Arg(0))
			stream := ctx.Arg(1)
			// stdout = iobBase + 48, stderr = iobBase + 96
			switch stream {
			case iobBase + iobStride*2:
				os.Stderr.Write([]byte{c})
			default:
				os.Stdout.Write([]byte{c})
			}
			ctx.SetReturn(uint64(c))
			return 0
		})
		d.RegisterAutoStubHandler(msvcrt, "fprintf", func(ctx *ntapi.TrapContext) uint32 {
			stream := ctx.Arg(0)
			fmtAddr := ctx.Arg(1)
			if fmtAddr == 0 {
				ctx.SetReturn(0)
				return 0
			}
			fmtStr := readGuestString(fmtAddr)
			var args []uint64
			for i := 2; i < 10; i++ {
				args = append(args, ctx.Arg(i))
			}
			result := wideprintf(fmtStr, args)
			w := crtStreamWriter(stream, iobBase, iobStride)
			w.WriteString(result)
			ctx.SetReturn(uint64(len(result)))
			return 0
		})
		d.RegisterAutoStubHandler(msvcrt, "vfprintf", func(ctx *ntapi.TrapContext) uint32 {
			stream := ctx.Arg(0)
			fmtAddr := ctx.Arg(1)
			// va_list is a pointer to the args on guest stack
			vaList := ctx.Arg(2)
			if fmtAddr == 0 {
				ctx.SetReturn(0)
				return 0
			}
			fmtStr := readGuestString(fmtAddr)
			var args []uint64
			if vaList != 0 {
				for i := 0; i < 8; i++ {
					v, _ := mem.Read64(vaList + uint64(i)*8)
					args = append(args, v)
				}
			}
			result := wideprintf(fmtStr, args)
			w := crtStreamWriter(stream, iobBase, iobStride)
			w.WriteString(result)
			ctx.SetReturn(uint64(len(result)))
			return 0
		})
		d.RegisterAutoStubHandler(msvcrt, "fwrite", func(ctx *ntapi.TrapContext) uint32 {
			bufAddr := ctx.Arg(0)
			size := ctx.Arg(1)
			count := ctx.Arg(2)
			stream := ctx.Arg(3)
			totalBytes := size * count
			if totalBytes > 0 && totalBytes < 0x100000 {
				data := make([]byte, totalBytes)
				for i := uint64(0); i < totalBytes; i++ {
					data[i], _ = mem.Read8(bufAddr + i)
				}
				if stream == iobBase+iobStride*2 {
					os.Stderr.Write(data)
				} else if stream == iobBase+iobStride || stream == iobBase {
					// stdin or unknown - skip
				} else {
					os.Stdout.Write(data)
				}
			}
			ctx.SetReturn(count)
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

		// sprintf(buf, fmt, ...) - msvcrt uses cdecl with args on stack/registers
		d.RegisterAutoStubHandler(msvcrt, "sprintf", func(ctx *ntapi.TrapContext) uint32 {
			buf := ctx.Arg(0)
			fmtAddr := ctx.Arg(1)
			if fmtAddr == 0 || buf == 0 {
				ctx.SetReturn(0)
				return 0
			}
			fmtStr := readGuestString(fmtAddr)
			var args []uint64
			for i := 2; i < 10; i++ {
				args = append(args, ctx.Arg(i))
			}
			result := wideprintf(fmtStr, args)
			for i := 0; i < len(result); i++ {
				mem.Write8(buf+uint64(i), result[i])
			}
			mem.Write8(buf+uint64(len(result)), 0)
			ctx.SetReturn(uint64(len(result)))
			return 0
		})
		d.RegisterAutoStubHandler(msvcrt, "_snprintf", func(ctx *ntapi.TrapContext) uint32 {
			buf := ctx.Arg(0)
			count := ctx.Arg(1)
			fmtAddr := ctx.Arg(2)
			if fmtAddr == 0 || buf == 0 || count == 0 {
				ctx.SetReturn(0)
				return 0
			}
			fmtStr := readGuestString(fmtAddr)
			var args []uint64
			for i := 3; i < 11; i++ {
				args = append(args, ctx.Arg(i))
			}
			result := wideprintf(fmtStr, args)
			n := len(result)
			if uint64(n) >= count {
				n = int(count) - 1
			}
			for i := 0; i < n; i++ {
				mem.Write8(buf+uint64(i), result[i])
			}
			mem.Write8(buf+uint64(n), 0)
			ctx.SetReturn(uint64(n))
			return 0
		})

		// --- msvcrt math functions (float64 in XMM0/XMM1, return in XMM0) ---
		mathUnary := func(name string, fn func(float64) float64) {
			d.RegisterAutoStubHandler(msvcrt, name, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetFloatReturn(fn(ctx.FloatArg(0)))
				return 0
			})
		}
		mathBinary := func(name string, fn func(float64, float64) float64) {
			d.RegisterAutoStubHandler(msvcrt, name, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetFloatReturn(fn(ctx.FloatArg(0), ctx.FloatArg(1)))
				return 0
			})
		}
		mathUnary("floor", math.Floor)
		mathUnary("ceil", math.Ceil)
		mathUnary("sqrt", math.Sqrt)
		mathUnary("sin", math.Sin)
		mathUnary("cos", math.Cos)
		mathUnary("tan", math.Tan)
		mathUnary("asin", math.Asin)
		mathUnary("acos", math.Acos)
		mathUnary("atan", math.Atan)
		mathUnary("log", math.Log)
		mathUnary("log10", math.Log10)
		mathUnary("log2", math.Log2)
		mathUnary("exp", math.Exp)
		mathUnary("fabs", math.Abs)
		mathUnary("round", math.Round)
		mathUnary("trunc", math.Trunc)
		mathBinary("pow", math.Pow)
		mathBinary("fmod", math.Mod)
		mathBinary("atan2", math.Atan2)
		d.RegisterAutoStubHandler(msvcrt, "ldexp", func(ctx *ntapi.TrapContext) uint32 {
			x := ctx.FloatArg(0)
			exp := int(int32(ctx.Arg(1))) // second arg is int, passed in RDX
			ctx.SetFloatReturn(math.Ldexp(x, exp))
			return 0
		})
		d.RegisterAutoStubHandler(msvcrt, "frexp", func(ctx *ntapi.TrapContext) uint32 {
			x := ctx.FloatArg(0)
			expPtr := ctx.Arg(1) // int* passed in RDX
			frac, exp := math.Frexp(x)
			if expPtr != 0 {
				mem.Write32(expPtr, uint32(int32(exp)))
			}
			ctx.SetFloatReturn(frac)
			return 0
		})
		d.RegisterAutoStubHandler(msvcrt, "modf", func(ctx *ntapi.TrapContext) uint32 {
			x := ctx.FloatArg(0)
			intPtr := ctx.Arg(1) // double* passed in RDX
			intPart, frac := math.Modf(x)
			if intPtr != 0 {
				mem.Write64(intPtr, math.Float64bits(intPart))
			}
			ctx.SetFloatReturn(frac)
			return 0
		})
		// Float versions (suffixed f)
		mathUnary("floorf", math.Floor)
		mathUnary("ceilf", math.Ceil)
		mathUnary("sqrtf", math.Sqrt)
		mathUnary("sinf", math.Sin)
		mathUnary("cosf", math.Cos)
		mathUnary("tanf", math.Tan)
		mathUnary("logf", math.Log)
		mathUnary("expf", math.Exp)
		mathUnary("fabsf", math.Abs)
		mathUnary("roundf", math.Round)
		mathUnary("truncf", math.Trunc)
		mathBinary("powf", math.Pow)
		mathBinary("fmodf", math.Mod)

		// Missing string/conversion functions in msvcrt
		d.RegisterAutoStubHandler(msvcrt, "atoi", func(ctx *ntapi.TrapContext) uint32 {
			s := readGuestString(ctx.Arg(0))
			v, _ := strconv.Atoi(s)
			ctx.SetReturn(uint64(int64(int32(v))))
			return 0
		})
		d.RegisterAutoStubHandler(msvcrt, "atol", func(ctx *ntapi.TrapContext) uint32 {
			s := readGuestString(ctx.Arg(0))
			v, _ := strconv.Atoi(s)
			ctx.SetReturn(uint64(int64(int32(v))))
			return 0
		})
		d.RegisterAutoStubHandler(msvcrt, "atof", func(ctx *ntapi.TrapContext) uint32 {
			s := readGuestString(ctx.Arg(0))
			v, _ := strconv.ParseFloat(s, 64)
			ctx.SetFloatReturn(v)
			return 0
		})
		d.RegisterAutoStubHandler(msvcrt, "strtod", func(ctx *ntapi.TrapContext) uint32 {
			s := readGuestString(ctx.Arg(0))
			endPtr := ctx.Arg(1)
			v, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
			if endPtr != 0 {
				// Write pointer past consumed chars (simplified: point to end of string)
				mem.Write64(endPtr, ctx.Arg(0)+uint64(len(s)))
			}
			ctx.SetFloatReturn(v)
			return 0
		})
		d.RegisterAutoStubHandler(msvcrt, "strtol", func(ctx *ntapi.TrapContext) uint32 {
			s := readGuestString(ctx.Arg(0))
			base := int(ctx.Arg(2))
			if base == 0 {
				base = 10
			}
			v, _ := strconv.ParseInt(strings.TrimSpace(s), base, 32)
			ctx.SetReturn(uint64(int64(int32(v))))
			return 0
		})
		d.RegisterAutoStubHandler(msvcrt, "strtoul", func(ctx *ntapi.TrapContext) uint32 {
			s := readGuestString(ctx.Arg(0))
			base := int(ctx.Arg(2))
			if base == 0 {
				base = 10
			}
			v, _ := strconv.ParseUint(strings.TrimSpace(s), base, 32)
			ctx.SetReturn(uint64(uint32(v)))
			return 0
		})
		d.RegisterAutoStubHandler(msvcrt, "strcmp", func(ctx *ntapi.TrapContext) uint32 {
			s1 := readGuestString(ctx.Arg(0))
			s2 := readGuestString(ctx.Arg(1))
			ctx.SetReturn(uint64(int64(int32(strings.Compare(s1, s2)))))
			return 0
		})
		d.RegisterAutoStubHandler(msvcrt, "strcpy", func(ctx *ntapi.TrapContext) uint32 {
			dst := ctx.Arg(0)
			src := ctx.Arg(1)
			s := readGuestString(src)
			for i := 0; i <= len(s); i++ {
				if i < len(s) {
					mem.Write8(dst+uint64(i), s[i])
				} else {
					mem.Write8(dst+uint64(i), 0)
				}
			}
			ctx.SetReturn(dst)
			return 0
		})
		d.RegisterAutoStubHandler(msvcrt, "strcat", func(ctx *ntapi.TrapContext) uint32 {
			dst := ctx.Arg(0)
			src := ctx.Arg(1)
			// Find end of dst
			end := dst
			for {
				b, _ := mem.Read8(end)
				if b == 0 {
					break
				}
				end++
			}
			s := readGuestString(src)
			for i := 0; i <= len(s); i++ {
				if i < len(s) {
					mem.Write8(end+uint64(i), s[i])
				} else {
					mem.Write8(end+uint64(i), 0)
				}
			}
			ctx.SetReturn(dst)
			return 0
		})
		d.RegisterAutoStubHandler(msvcrt, "strchr", func(ctx *ntapi.TrapContext) uint32 {
			s := ctx.Arg(0)
			ch := byte(ctx.Arg(1))
			for {
				b, _ := mem.Read8(s)
				if b == ch {
					ctx.SetReturn(s)
					return 0
				}
				if b == 0 {
					ctx.SetReturn(0)
					return 0
				}
				s++
			}
		})
		d.RegisterAutoStubHandler(msvcrt, "strrchr", func(ctx *ntapi.TrapContext) uint32 {
			s := ctx.Arg(0)
			ch := byte(ctx.Arg(1))
			var last uint64
			for {
				b, _ := mem.Read8(s)
				if b == ch {
					last = s
				}
				if b == 0 {
					ctx.SetReturn(last)
					return 0
				}
				s++
			}
		})
		d.RegisterAutoStubHandler(msvcrt, "memchr", func(ctx *ntapi.TrapContext) uint32 {
			buf := ctx.Arg(0)
			ch := byte(ctx.Arg(1))
			n := ctx.Arg(2)
			for i := uint64(0); i < n; i++ {
				b, _ := mem.Read8(buf + i)
				if b == ch {
					ctx.SetReturn(buf + i)
					return 0
				}
			}
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(msvcrt, "memmove", func(ctx *ntapi.TrapContext) uint32 {
			dst := ctx.Arg(0)
			src := ctx.Arg(1)
			n := ctx.Arg(2)
			if n == 0 {
				ctx.SetReturn(dst)
				return 0
			}
			tmp := make([]byte, n)
			for i := uint64(0); i < n; i++ {
				tmp[i], _ = mem.Read8(src + i)
			}
			for i := uint64(0); i < n; i++ {
				mem.Write8(dst+i, tmp[i])
			}
			ctx.SetReturn(dst)
			return 0
		})
		d.RegisterAutoStubHandler(msvcrt, "_stricmp", func(ctx *ntapi.TrapContext) uint32 {
			s1 := readGuestString(ctx.Arg(0))
			s2 := readGuestString(ctx.Arg(1))
			ctx.SetReturn(uint64(int64(int32(strings.Compare(strings.ToLower(s1), strings.ToLower(s2))))))
			return 0
		})
		d.RegisterAutoStubHandler(msvcrt, "_strnicmp", func(ctx *ntapi.TrapContext) uint32 {
			s1 := readGuestString(ctx.Arg(0))
			s2 := readGuestString(ctx.Arg(1))
			n := int(ctx.Arg(2))
			if n < len(s1) {
				s1 = s1[:n]
			}
			if n < len(s2) {
				s2 = s2[:n]
			}
			ctx.SetReturn(uint64(int64(int32(strings.Compare(strings.ToLower(s1), strings.ToLower(s2))))))
			return 0
		})

		// ctype functions for msvcrt
		d.RegisterAutoStubHandler(msvcrt, "isalpha", func(ctx *ntapi.TrapContext) uint32 {
			c := byte(ctx.Arg(0))
			if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
				ctx.SetReturn(1)
			} else {
				ctx.SetReturn(0)
			}
			return 0
		})
		d.RegisterAutoStubHandler(msvcrt, "isdigit", func(ctx *ntapi.TrapContext) uint32 {
			c := byte(ctx.Arg(0))
			if c >= '0' && c <= '9' {
				ctx.SetReturn(1)
			} else {
				ctx.SetReturn(0)
			}
			return 0
		})
		d.RegisterAutoStubHandler(msvcrt, "isalnum", func(ctx *ntapi.TrapContext) uint32 {
			c := byte(ctx.Arg(0))
			if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
				ctx.SetReturn(1)
			} else {
				ctx.SetReturn(0)
			}
			return 0
		})
		d.RegisterAutoStubHandler(msvcrt, "isspace", func(ctx *ntapi.TrapContext) uint32 {
			c := byte(ctx.Arg(0))
			if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v' {
				ctx.SetReturn(1)
			} else {
				ctx.SetReturn(0)
			}
			return 0
		})
		d.RegisterAutoStubHandler(msvcrt, "isupper", func(ctx *ntapi.TrapContext) uint32 {
			c := byte(ctx.Arg(0))
			if c >= 'A' && c <= 'Z' {
				ctx.SetReturn(1)
			} else {
				ctx.SetReturn(0)
			}
			return 0
		})
		d.RegisterAutoStubHandler(msvcrt, "islower", func(ctx *ntapi.TrapContext) uint32 {
			c := byte(ctx.Arg(0))
			if c >= 'a' && c <= 'z' {
				ctx.SetReturn(1)
			} else {
				ctx.SetReturn(0)
			}
			return 0
		})
		d.RegisterAutoStubHandler(msvcrt, "tolower", func(ctx *ntapi.TrapContext) uint32 {
			c := byte(ctx.Arg(0))
			if c >= 'A' && c <= 'Z' {
				c += 32
			}
			ctx.SetReturn(uint64(c))
			return 0
		})

		// File I/O for msvcrt - real implementations
		d.RegisterAutoStubHandler(msvcrt, "fread", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // read nothing
			return 0
		})
		d.RegisterAutoStubHandler(msvcrt, "fseek", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // success
			return 0
		})
		d.RegisterAutoStubHandler(msvcrt, "ftell", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(msvcrt, "fflush", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // success
			return 0
		})
		d.RegisterAutoStubHandler(msvcrt, "feof", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // always EOF
			return 0
		})
		d.RegisterAutoStubHandler(msvcrt, "ferror", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // no error
			return 0
		})
		d.RegisterAutoStubHandler(msvcrt, "fgets", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // NULL (EOF)
			return 0
		})
		d.RegisterAutoStubHandler(msvcrt, "_wfopen", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // NULL (fail)
			return 0
		})
		// setlocale - return pointer to "C" locale string
		d.RegisterAutoStubHandler(msvcrt, "setlocale", func(ctx *ntapi.TrapContext) uint32 {
			buf := mem.Mmap(0, 8, mmu.PermRead|mmu.PermWrite)
			mem.Write8(buf, 'C')
			mem.Write8(buf+1, 0)
			ctx.SetReturn(buf)
			return 0
		})
		// _configthreadlocale
		d.RegisterAutoStubHandler(msvcrt, "_configthreadlocale", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // _DISABLE_PER_THREAD_LOCALE
			return 0
		})
		// printf - print to stdout
		d.RegisterAutoStubHandler(msvcrt, "printf", func(ctx *ntapi.TrapContext) uint32 {
			fmtAddr := ctx.Arg(0)
			if fmtAddr == 0 {
				ctx.SetReturn(0)
				return 0
			}
			fmtStr := readGuestString(fmtAddr)
			var args []uint64
			for i := 1; i < 10; i++ {
				args = append(args, ctx.Arg(i))
			}
			result := wideprintf(fmtStr, args)
			os.Stdout.WriteString(result)
			ctx.SetReturn(uint64(len(result)))
			return 0
		})
		// _snwprintf - wide-char snprintf
		d.RegisterAutoStubHandler(msvcrt, "_snwprintf", func(ctx *ntapi.TrapContext) uint32 {
			lpOut := ctx.Arg(0)
			count := ctx.Arg(1)
			lpFmt := ctx.Arg(2)
			if lpFmt == 0 || lpOut == 0 || count == 0 {
				ctx.SetReturn(0)
				return 0
			}
			fmtStr := readGuestUTF16(lpFmt)
			var args []uint64
			for i := 3; i < 10; i++ {
				args = append(args, ctx.Arg(i))
			}
			result := wideprintf(fmtStr, args)
			runes := []rune(result)
			maxChars := int(count)
			if maxChars > 0 && len(runes) >= maxChars {
				runes = runes[:maxChars-1]
			}
			for i, r := range runes {
				mem.Write16(lpOut+uint64(i)*2, uint16(r))
			}
			mem.Write16(lpOut+uint64(len(runes))*2, 0)
			ctx.SetReturn(uint64(len(runes)))
			return 0
		})
	}
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

		// sprintf / _snprintf for ucrtbase (direct, not via __stdio_common)
		d.RegisterAutoStubHandler(ucrt, "sprintf", func(ctx *ntapi.TrapContext) uint32 {
			buf := ctx.Arg(0)
			fmtAddr := ctx.Arg(1)
			if fmtAddr == 0 || buf == 0 {
				ctx.SetReturn(0)
				return 0
			}
			fmtStr := readGuestString(fmtAddr)
			var args []uint64
			for i := 2; i < 10; i++ {
				args = append(args, ctx.Arg(i))
			}
			result := wideprintf(fmtStr, args)
			for i := 0; i < len(result); i++ {
				mem.Write8(buf+uint64(i), result[i])
			}
			mem.Write8(buf+uint64(len(result)), 0)
			ctx.SetReturn(uint64(len(result)))
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "_snprintf", func(ctx *ntapi.TrapContext) uint32 {
			buf := ctx.Arg(0)
			count := ctx.Arg(1)
			fmtAddr := ctx.Arg(2)
			if fmtAddr == 0 || buf == 0 || count == 0 {
				ctx.SetReturn(0)
				return 0
			}
			fmtStr := readGuestString(fmtAddr)
			var args []uint64
			for i := 3; i < 11; i++ {
				args = append(args, ctx.Arg(i))
			}
			result := wideprintf(fmtStr, args)
			n := len(result)
			if uint64(n) >= count {
				n = int(count) - 1
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
			namePtr := ctx.Arg(0)
			if namePtr == 0 {
				ctx.SetReturn(0)
				return 0
			}
			name := readGuestString(namePtr)
			var val string
			if v, ok := envVars[name]; ok {
				val = v
			} else {
				val = os.Getenv(name)
			}
			if val == "" {
				ctx.SetReturn(0) // NULL = not found
				return 0
			}
			// Allocate guest memory for the value string
			buf := mem.Mmap(0, uint64(len(val)+1), mmu.PermRead|mmu.PermWrite)
			for i := 0; i < len(val); i++ {
				mem.Write8(buf+uint64(i), val[i])
			}
			mem.Write8(buf+uint64(len(val)), 0)
			ctx.SetReturn(buf)
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
			ctx.SetReturn(sharedHeapAlloc(ctx.Arg(0), false))
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "calloc", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(sharedHeapAlloc(ctx.Arg(0)*ctx.Arg(1), true))
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "free", func(ctx *ntapi.TrapContext) uint32 {
			sharedHeapFree(ctx.Arg(0))
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "realloc", func(ctx *ntapi.TrapContext) uint32 {
			ptr := ctx.Arg(0)
			newSize := ctx.Arg(1)
			if ptr == 0 {
				ctx.SetReturn(sharedHeapAlloc(newSize, false))
				return 0
			}
			if newSize == 0 {
				sharedHeapFree(ptr)
				ctx.SetReturn(0)
				return 0
			}
			oldBlockSize, _ := mem.Read64(ptr - 16)
			oldDataSize := oldBlockSize - 16
			if newSize <= oldDataSize {
				ctx.SetReturn(ptr)
				return 0
			}
			newPtr := sharedHeapAlloc(newSize, false)
			if newPtr != 0 {
				copyLen := oldDataSize
				if newSize < copyLen {
					copyLen = newSize
				}
				for i := uint64(0); i < copyLen; i++ {
					b, _ := mem.Read8(ptr + i)
					mem.Write8(newPtr+i, b)
				}
			}
			sharedHeapFree(ptr)
			ctx.SetReturn(newPtr)
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

		// _strdup / _wcsdup: duplicate a string into heap memory
		d.RegisterAutoStubHandler(ucrt, "_strdup", func(ctx *ntapi.TrapContext) uint32 {
			src := ctx.Arg(0)
			if src == 0 {
				ctx.SetReturn(0)
				return 0
			}
			var buf []byte
			for i := uint64(0); i < 0x100000; i++ {
				b, _ := mem.Read8(src + i)
				buf = append(buf, b)
				if b == 0 {
					break
				}
			}
			dst := sharedHeapAlloc(uint64(len(buf)+1), false)
			mem.WriteBytes(dst, buf)
			ctx.SetReturn(dst)
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "_wcsdup", func(ctx *ntapi.TrapContext) uint32 {
			src := ctx.Arg(0)
			if src == 0 {
				ctx.SetReturn(0)
				return 0
			}
			var buf []uint16
			for i := uint64(0); i < 0x100000; i++ {
				w, _ := mem.Read16(src + i*2)
				buf = append(buf, w)
				if w == 0 {
					break
				}
			}
			dst := sharedHeapAlloc(uint64(len(buf)*2+2), false)
			for i, w := range buf {
				mem.Write16(dst+uint64(i)*2, w)
			}
			ctx.SetReturn(dst)
			return 0
		})

		// time / _time64: return current Unix timestamp
		d.RegisterAutoStubHandler(ucrt, "_time64", func(ctx *ntapi.TrapContext) uint32 {
			t := uint64(1741600000) // fixed plausible timestamp
			ptr := ctx.Arg(0)
			if ptr != 0 {
				mem.Write64(ptr, t)
			}
			ctx.SetReturn(t)
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "time", func(ctx *ntapi.TrapContext) uint32 {
			t := uint64(1741600000)
			ptr := ctx.Arg(0)
			if ptr != 0 {
				mem.Write64(ptr, t)
			}
			ctx.SetReturn(t)
			return 0
		})

		// srand / rand
		d.RegisterAutoStubHandler(ucrt, "srand", func(ctx *ntapi.TrapContext) uint32 {
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "rand", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(42)
			return 0
		})

		// _dupenv_s: duplicate an environment variable string
		d.RegisterAutoStubHandler(ucrt, "_dupenv_s", func(ctx *ntapi.TrapContext) uint32 {
			// _dupenv_s(char **buf, size_t *sizeInBytes, const char *name)
			// On failure (not found): *buf=NULL, *sizeInBytes=0, return 0
			buf := ctx.Arg(0)
			sizePtr := ctx.Arg(1)
			if buf != 0 {
				mem.Write64(buf, 0)
			}
			if sizePtr != 0 {
				mem.Write64(sizePtr, 0)
			}
			ctx.SetReturn(0)
			return 0
		})

		// getenv_s(size_t *retsize, char *buf, size_t bufsize, const char *name)
		d.RegisterAutoStubHandler(ucrt, "getenv_s", func(ctx *ntapi.TrapContext) uint32 {
			sizeRet := ctx.Arg(0)
			bufPtr := ctx.Arg(1)
			bufSize := ctx.Arg(2)
			namePtr := ctx.Arg(3)
			if namePtr == 0 {
				if sizeRet != 0 {
					mem.Write64(sizeRet, 0)
				}
				ctx.SetReturn(22) // EINVAL
				return 0
			}
			name := readGuestString(namePtr)
			var val string
			if v, ok := envVars[name]; ok {
				val = v
			} else {
				val = os.Getenv(name)
			}
			if val == "" {
				if sizeRet != 0 {
					mem.Write64(sizeRet, 0)
				}
				ctx.SetReturn(0) // success, but empty
				return 0
			}
			needed := uint64(len(val) + 1)
			if sizeRet != 0 {
				mem.Write64(sizeRet, needed)
			}
			if bufPtr != 0 && bufSize >= needed {
				for i := 0; i < len(val); i++ {
					mem.Write8(bufPtr+uint64(i), val[i])
				}
				mem.Write8(bufPtr+uint64(len(val)), 0)
			}
			ctx.SetReturn(0) // success
			return 0
		})

		// --- ucrtbase math functions (float64 in XMM0/XMM1, return in XMM0) ---
		ucrtMathUnary := func(name string, fn func(float64) float64) {
			d.RegisterAutoStubHandler(ucrt, name, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetFloatReturn(fn(ctx.FloatArg(0)))
				return 0
			})
		}
		ucrtMathBinary := func(name string, fn func(float64, float64) float64) {
			d.RegisterAutoStubHandler(ucrt, name, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetFloatReturn(fn(ctx.FloatArg(0), ctx.FloatArg(1)))
				return 0
			})
		}
		ucrtMathUnary("floor", math.Floor)
		ucrtMathUnary("ceil", math.Ceil)
		ucrtMathUnary("sqrt", math.Sqrt)
		ucrtMathUnary("sin", math.Sin)
		ucrtMathUnary("cos", math.Cos)
		ucrtMathUnary("tan", math.Tan)
		ucrtMathUnary("asin", math.Asin)
		ucrtMathUnary("acos", math.Acos)
		ucrtMathUnary("atan", math.Atan)
		ucrtMathUnary("log", math.Log)
		ucrtMathUnary("log10", math.Log10)
		ucrtMathUnary("log2", math.Log2)
		ucrtMathUnary("exp", math.Exp)
		ucrtMathUnary("exp2", math.Exp2)
		ucrtMathUnary("fabs", math.Abs)
		ucrtMathUnary("round", math.Round)
		ucrtMathUnary("trunc", math.Trunc)
		ucrtMathUnary("cbrt", math.Cbrt)
		ucrtMathBinary("pow", math.Pow)
		ucrtMathBinary("fmod", math.Mod)
		ucrtMathBinary("atan2", math.Atan2)
		ucrtMathBinary("copysign", math.Copysign)
		ucrtMathBinary("fmax", math.Max)
		ucrtMathBinary("fmin", math.Min)
		ucrtMathBinary("remainder", math.Remainder)
		d.RegisterAutoStubHandler(ucrt, "ldexp", func(ctx *ntapi.TrapContext) uint32 {
			x := ctx.FloatArg(0)
			exp := int(int32(ctx.Arg(1)))
			ctx.SetFloatReturn(math.Ldexp(x, exp))
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "frexp", func(ctx *ntapi.TrapContext) uint32 {
			x := ctx.FloatArg(0)
			expPtr := ctx.Arg(1)
			frac, exp := math.Frexp(x)
			if expPtr != 0 {
				mem.Write32(expPtr, uint32(int32(exp)))
			}
			ctx.SetFloatReturn(frac)
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "modf", func(ctx *ntapi.TrapContext) uint32 {
			x := ctx.FloatArg(0)
			intPtr := ctx.Arg(1)
			intPart, frac := math.Modf(x)
			if intPtr != 0 {
				mem.Write64(intPtr, math.Float64bits(intPart))
			}
			ctx.SetFloatReturn(frac)
			return 0
		})
		// Float versions (suffixed f)
		ucrtMathUnary("floorf", math.Floor)
		ucrtMathUnary("ceilf", math.Ceil)
		ucrtMathUnary("sqrtf", math.Sqrt)
		ucrtMathUnary("sinf", math.Sin)
		ucrtMathUnary("cosf", math.Cos)
		ucrtMathUnary("tanf", math.Tan)
		ucrtMathUnary("logf", math.Log)
		ucrtMathUnary("expf", math.Exp)
		ucrtMathUnary("fabsf", math.Abs)
		ucrtMathUnary("roundf", math.Round)
		ucrtMathUnary("truncf", math.Trunc)
		ucrtMathBinary("powf", math.Pow)
		ucrtMathBinary("fmodf", math.Mod)
		ucrtMathBinary("atan2f", math.Atan2)

		// Missing ucrt string functions
		d.RegisterAutoStubHandler(ucrt, "atof", func(ctx *ntapi.TrapContext) uint32 {
			s := readGuestString(ctx.Arg(0))
			v, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
			ctx.SetFloatReturn(v)
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "atol", func(ctx *ntapi.TrapContext) uint32 {
			s := readGuestString(ctx.Arg(0))
			v, _ := strconv.Atoi(strings.TrimSpace(s))
			ctx.SetReturn(uint64(int64(int32(v))))
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "strtod", func(ctx *ntapi.TrapContext) uint32 {
			s := readGuestString(ctx.Arg(0))
			v, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
			ctx.SetFloatReturn(v)
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "strtof", func(ctx *ntapi.TrapContext) uint32 {
			s := readGuestString(ctx.Arg(0))
			v, _ := strconv.ParseFloat(strings.TrimSpace(s), 32)
			ctx.SetFloatReturn(v)
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "isalpha", func(ctx *ntapi.TrapContext) uint32 {
			c := byte(ctx.Arg(0))
			if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
				ctx.SetReturn(1)
			} else {
				ctx.SetReturn(0)
			}
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "isalnum", func(ctx *ntapi.TrapContext) uint32 {
			c := byte(ctx.Arg(0))
			if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
				ctx.SetReturn(1)
			} else {
				ctx.SetReturn(0)
			}
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "isupper", func(ctx *ntapi.TrapContext) uint32 {
			c := byte(ctx.Arg(0))
			if c >= 'A' && c <= 'Z' {
				ctx.SetReturn(1)
			} else {
				ctx.SetReturn(0)
			}
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "islower", func(ctx *ntapi.TrapContext) uint32 {
			c := byte(ctx.Arg(0))
			if c >= 'a' && c <= 'z' {
				ctx.SetReturn(1)
			} else {
				ctx.SetReturn(0)
			}
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "iswprint", func(ctx *ntapi.TrapContext) uint32 {
			c := uint16(ctx.Arg(0))
			if c >= 0x20 && c != 0x7F {
				ctx.SetReturn(1)
			} else {
				ctx.SetReturn(0)
			}
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "memchr", func(ctx *ntapi.TrapContext) uint32 {
			buf := ctx.Arg(0)
			ch := byte(ctx.Arg(1))
			n := ctx.Arg(2)
			for i := uint64(0); i < n; i++ {
				b, _ := mem.Read8(buf + i)
				if b == ch {
					ctx.SetReturn(buf + i)
					return 0
				}
			}
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "_strnicmp", func(ctx *ntapi.TrapContext) uint32 {
			s1 := readGuestString(ctx.Arg(0))
			s2 := readGuestString(ctx.Arg(1))
			n := int(ctx.Arg(2))
			if n < len(s1) {
				s1 = s1[:n]
			}
			if n < len(s2) {
				s2 = s2[:n]
			}
			ctx.SetReturn(uint64(int64(int32(strings.Compare(strings.ToLower(s1), strings.ToLower(s2))))))
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "_strlwr", func(ctx *ntapi.TrapContext) uint32 {
			ptr := ctx.Arg(0)
			if ptr == 0 {
				ctx.SetReturn(0)
				return 0
			}
			s := ptr
			for {
				b, _ := mem.Read8(s)
				if b == 0 {
					break
				}
				if b >= 'A' && b <= 'Z' {
					mem.Write8(s, b+32)
				}
				s++
			}
			ctx.SetReturn(ptr)
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "_strupr", func(ctx *ntapi.TrapContext) uint32 {
			ptr := ctx.Arg(0)
			if ptr == 0 {
				ctx.SetReturn(0)
				return 0
			}
			s := ptr
			for {
				b, _ := mem.Read8(s)
				if b == 0 {
					break
				}
				if b >= 'a' && b <= 'z' {
					mem.Write8(s, b-32)
				}
				s++
			}
			ctx.SetReturn(ptr)
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "wcsstr", func(ctx *ntapi.TrapContext) uint32 {
			hay := ctx.Arg(0)
			needle := ctx.Arg(1)
			if hay == 0 || needle == 0 {
				ctx.SetReturn(0)
				return 0
			}
			// Read needle
			var needleChars []uint16
			for p := needle; ; p += 2 {
				ch, _ := mem.Read16(p)
				if ch == 0 {
					break
				}
				needleChars = append(needleChars, ch)
			}
			if len(needleChars) == 0 {
				ctx.SetReturn(hay)
				return 0
			}
			for p := hay; ; p += 2 {
				ch, _ := mem.Read16(p)
				if ch == 0 {
					break
				}
				if ch == needleChars[0] {
					match := true
					for j := 1; j < len(needleChars); j++ {
						ch2, _ := mem.Read16(p + uint64(j)*2)
						if ch2 != needleChars[j] {
							match = false
							break
						}
					}
					if match {
						ctx.SetReturn(p)
						return 0
					}
				}
			}
			ctx.SetReturn(0)
			return 0
		})

		// File I/O stubs for ucrtbase
		d.RegisterAutoStubHandler(ucrt, "fopen", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // NULL
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "_wfopen", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // NULL
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "fclose", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "fread", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "fseek", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "ftell", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "fflush", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "feof", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "ferror", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "fgets", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // NULL (EOF)
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "fputs", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "fprintf", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "__stdio_common_vfprintf", func(ctx *ntapi.TrapContext) uint32 {
			// options=Arg(0), stream=Arg(1), format=Arg(2), locale=Arg(3), arglist=Arg(4)
			stream := ctx.Arg(1)
			fmtAddr := ctx.Arg(2)
			vaList := ctx.Arg(4)
			if fmtAddr == 0 {
				ctx.SetReturn(0)
				return 0
			}
			fmtStr := readGuestString(fmtAddr)
			var args []uint64
			if vaList != 0 {
				for i := 0; i < 8; i++ {
					v, _ := mem.Read64(vaList + uint64(i)*8)
					args = append(args, v)
				}
			}
			result := wideprintf(fmtStr, args)
			w := crtStreamWriter(stream, crtIOBBase, 0x30)
			w.WriteString(result)
			ctx.SetReturn(uint64(len(result)))
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "__stdio_common_vfscanf", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(ucrt, "__p__commode", func(ctx *ntapi.TrapContext) uint32 {
			// Return pointer to a static int (commit mode = _IOCOMMIT)
			static := mem.Mmap(0, 8, mmu.PermRead|mmu.PermWrite)
			mem.Write32(static, 0x4000) // _IOCOMMIT
			ctx.SetReturn(static)
			return 0
		})
		// setlocale - return pointer to "C" locale string
		d.RegisterAutoStubHandler(ucrt, "setlocale", func(ctx *ntapi.TrapContext) uint32 {
			buf := mem.Mmap(0, 8, mmu.PermRead|mmu.PermWrite)
			mem.Write8(buf, 'C')
			mem.Write8(buf+1, 0)
			ctx.SetReturn(buf)
			return 0
		})
		// _configthreadlocale
		d.RegisterAutoStubHandler(ucrt, "_configthreadlocale", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // _DISABLE_PER_THREAD_LOCALE
			return 0
		})
		// printf - print to stdout
		d.RegisterAutoStubHandler(ucrt, "printf", func(ctx *ntapi.TrapContext) uint32 {
			fmtAddr := ctx.Arg(0)
			if fmtAddr == 0 {
				ctx.SetReturn(0)
				return 0
			}
			fmtStr := readGuestString(fmtAddr)
			var args []uint64
			for i := 1; i < 10; i++ {
				args = append(args, ctx.Arg(i))
			}
			result := wideprintf(fmtStr, args)
			os.Stdout.WriteString(result)
			ctx.SetReturn(uint64(len(result)))
			return 0
		})
		// _snwprintf - wide-char snprintf
		d.RegisterAutoStubHandler(ucrt, "_snwprintf", func(ctx *ntapi.TrapContext) uint32 {
			lpOut := ctx.Arg(0)
			count := ctx.Arg(1)
			lpFmt := ctx.Arg(2)
			if lpFmt == 0 || lpOut == 0 || count == 0 {
				ctx.SetReturn(0)
				return 0
			}
			fmtStr := readGuestUTF16(lpFmt)
			var args []uint64
			for i := 3; i < 10; i++ {
				args = append(args, ctx.Arg(i))
			}
			result := wideprintf(fmtStr, args)
			runes := []rune(result)
			maxChars := int(count)
			if maxChars > 0 && len(runes) >= maxChars {
				runes = runes[:maxChars-1]
			}
			for i, r := range runes {
				mem.Write16(lpOut+uint64(i)*2, uint16(r))
			}
			mem.Write16(lpOut+uint64(len(runes))*2, 0)
			ctx.SetReturn(uint64(len(runes)))
			return 0
		})
	}

	// --- registry helpers (used by kernel32 + advapi32) ---
	regKeyPath := func(hKey uint64, subKey string) string {
		var base string
		switch hKey {
		case 0x80000000:
			base = `HKEY_CLASSES_ROOT`
		case 0x80000001:
			base = `HKEY_CURRENT_USER`
		case 0x80000002:
			base = `HKEY_LOCAL_MACHINE`
		case 0x80000003:
			base = `HKEY_USERS`
		case 0x80000005:
			base = `HKEY_CURRENT_CONFIG`
		default:
			rk := handles.GetRegKey(ntapi.Handle(hKey))
			if rk != nil {
				base = rk.Path
			}
		}
		if subKey == "" {
			return base
		}
		if base == "" {
			return subKey
		}
		return base + `\` + subKey
	}

	// regIsProbeKey returns true for registry paths used by VM/sandbox detection
	// tools (pafish, etc.). These keys should NOT be auto-created on open.
	regIsProbeKey := func(path string) bool {
		lp := strings.ToLower(path)
		probes := []string{
			`\wine`, `\oracle\virtualbox`, `\vmware`,
			`\vbox`, `\qemu`, `\bochs`,
			`\sandboxie`, `\cuckoo`,
			`\services\vboxguest`, `\services\vboxmouse`,
			`\services\vboxservice`, `\services\vboxsf`, `\services\vboxvideo`,
			`\acpi\dsdt\vbox__`, `\acpi\fadt\vbox__`, `\acpi\rsdt\vbox__`,
		}
		for _, p := range probes {
			if strings.Contains(lp, p) {
				return true
			}
		}
		return false
	}
	regQueryValue := func(ctx *ntapi.TrapContext, hKey uint64, valueName string) uint32 {
		lpType := ctx.Arg(3)
		lpData := ctx.Arg(4)
		lpcbData := ctx.Arg(5)
		rk := handles.GetRegKey(ntapi.Handle(hKey))
		if rk == nil || rk.Key == nil {
			return 2 // ERROR_FILE_NOT_FOUND
		}
		var val *ntapi.RegistryValue
		for k, v := range rk.Key.Values {
			if strings.EqualFold(k, valueName) {
				val = v
				break
			}
		}
		if val == nil {
			return 2 // ERROR_FILE_NOT_FOUND
		}
		if lpType != 0 {
			ctx.Mem.Write32(lpType, val.Type)
		}
		needed := uint32(len(val.Data))
		if lpcbData != 0 {
			avail, _ := ctx.Mem.Read32(lpcbData)
			ctx.Mem.Write32(lpcbData, needed)
			if lpData != 0 && avail < needed {
				return 234 // ERROR_MORE_DATA
			}
		}
		if lpData != 0 {
			ctx.Mem.WriteBytes(lpData, val.Data)
		}
		return 0
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
			ms := uint32(time.Since(bootTime).Milliseconds())
			ctx.SetReturn(uint64(ms))
			return 0
		})

		d.RegisterAutoStubHandler(kernel32, "GetModuleHandleA", func(ctx *ntapi.TrapContext) uint32 {
			name := ctx.Arg(0)
			if name == 0 {
				// Read ImageBase from PEB
				imageBase, _ := ctx.Mem.Read64(ctx.State.PEBAddr + 0x10)
				ctx.SetReturn(imageBase)
			} else {
				modName := strings.ToLower(readGuestString(name))
				if !strings.HasSuffix(modName, ".dll") && !strings.HasSuffix(modName, ".exe") {
					modName += ".dll"
				}
				if s, ok := synthByName[modName]; ok {
					ctx.SetReturn(s.BaseAddr)
				} else {
					ctx.SetReturn(0)
				}
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
				if !strings.HasSuffix(modName, ".dll") && !strings.HasSuffix(modName, ".exe") {
					modName += ".dll"
				}
				if s, ok := synthByName[modName]; ok {
					ctx.SetReturn(s.BaseAddr)
				} else {
					ctx.SetReturn(0)
				}
			}
			return 0
		})

		d.RegisterAutoStubHandler(kernel32, "GetModuleHandleExW", func(ctx *ntapi.TrapContext) uint32 {
			// dwFlags=arg0, lpModuleName=arg1, phModule=arg2
			modNamePtr := ctx.Arg(1)
			phModule := ctx.Arg(2)
			if modNamePtr == 0 {
				imageBase, _ := ctx.Mem.Read64(ctx.State.PEBAddr + 0x10)
				if phModule != 0 {
					ctx.Mem.Write64Raw(phModule, imageBase)
				}
				ctx.SetReturn(1) // TRUE
			} else {
				modName := strings.ToLower(readGuestUTF16(modNamePtr))
				if !strings.HasSuffix(modName, ".dll") && !strings.HasSuffix(modName, ".exe") {
					modName += ".dll"
				}
				if s, ok := synthByName[modName]; ok {
					if phModule != 0 {
						ctx.Mem.Write64Raw(phModule, s.BaseAddr)
					}
					ctx.SetReturn(1)
				} else {
					ctx.SetReturn(0)
				}
			}
			return 0
		})

		d.RegisterAutoStubHandler(kernel32, "GetStartupInfoA", func(ctx *ntapi.TrapContext) uint32 {
			addr := ctx.Arg(0)
			for i := uint64(0); i < 104; i++ {
				ctx.Mem.Write8(addr+i, 0)
			}
			ctx.Mem.Write32(addr, 104)       // cb = sizeof(STARTUPINFOA) on x64
			ctx.Mem.Write32(addr+60, 0x0001) // dwFlags = STARTF_USESHOWWINDOW
			ctx.Mem.Write16(addr+64, 0x0001) // wShowWindow = SW_SHOWNORMAL
			return 0
		})

		// VirtualProtect: our memory is flat RWX, so always succeed
		d.RegisterAutoStubHandler(kernel32, "VirtualProtect", func(ctx *ntapi.TrapContext) uint32 {
			lpAddress := ctx.Arg(0)
			dwSize := ctx.Arg(1)
			flNewProtect := ctx.Arg(2)
			lpflOldProtect := ctx.Arg(3)
			_ = lpAddress; _ = dwSize; _ = flNewProtect
			if lpflOldProtect != 0 {
				ctx.Mem.Write32(lpflOldProtect, 0x40) // PAGE_EXECUTE_READWRITE
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

		// InterlockedXxx - atomic in-memory operations
		d.RegisterAutoStubHandler(kernel32, "InterlockedIncrement", func(ctx *ntapi.TrapContext) uint32 {
			ptr := ctx.Arg(0)
			v, _ := ctx.Mem.Read32(ptr)
			v++
			ctx.Mem.Write32(ptr, v)
			ctx.SetReturn(uint64(v))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "InterlockedDecrement", func(ctx *ntapi.TrapContext) uint32 {
			ptr := ctx.Arg(0)
			v, _ := ctx.Mem.Read32(ptr)
			v--
			ctx.Mem.Write32(ptr, v)
			ctx.SetReturn(uint64(v))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "InterlockedExchange", func(ctx *ntapi.TrapContext) uint32 {
			ptr := ctx.Arg(0)
			newVal := ctx.Arg(1)
			old, _ := ctx.Mem.Read32(ptr)
			ctx.Mem.Write32(ptr, uint32(newVal))
			ctx.SetReturn(uint64(old))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "InterlockedCompareExchange", func(ctx *ntapi.TrapContext) uint32 {
			ptr := ctx.Arg(0)
			exchange := ctx.Arg(1)
			comparand := ctx.Arg(2)
			cur, _ := ctx.Mem.Read32(ptr)
			if uint64(cur) == comparand {
				ctx.Mem.Write32(ptr, uint32(exchange))
			}
			ctx.SetReturn(uint64(cur))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "InterlockedExchangeAdd", func(ctx *ntapi.TrapContext) uint32 {
			ptr := ctx.Arg(0)
			addend := ctx.Arg(1)
			old, _ := ctx.Mem.Read32(ptr)
			ctx.Mem.Write32(ptr, old+uint32(addend))
			ctx.SetReturn(uint64(old))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "InterlockedIncrement64", func(ctx *ntapi.TrapContext) uint32 {
			ptr := ctx.Arg(0)
			v, _ := ctx.Mem.Read64(ptr)
			v++
			ctx.Mem.Write64Raw(ptr, v)
			ctx.SetReturn(v)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "InterlockedDecrement64", func(ctx *ntapi.TrapContext) uint32 {
			ptr := ctx.Arg(0)
			v, _ := ctx.Mem.Read64(ptr)
			v--
			ctx.Mem.Write64Raw(ptr, v)
			ctx.SetReturn(v)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "InterlockedExchange64", func(ctx *ntapi.TrapContext) uint32 {
			ptr := ctx.Arg(0)
			newVal := ctx.Arg(1)
			old, _ := ctx.Mem.Read64(ptr)
			ctx.Mem.Write64Raw(ptr, newVal)
			ctx.SetReturn(old)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "InterlockedCompareExchange64", func(ctx *ntapi.TrapContext) uint32 {
			ptr := ctx.Arg(0)
			exchange := ctx.Arg(1)
			comparand := ctx.Arg(2)
			cur, _ := ctx.Mem.Read64(ptr)
			if cur == comparand {
				ctx.Mem.Write64Raw(ptr, exchange)
			}
			ctx.SetReturn(cur)
			return 0
		})

		d.RegisterAutoStubHandler(kernel32, "GetCurrentThreadId", func(ctx *ntapi.TrapContext) uint32 {
			if *tmPtr != nil {
				tid := (*tmPtr).GetTID(ctx.CPU)
				ctx.SetReturn(uint64(tid))
			} else {
				ctx.SetReturn(1) // main thread TID=1
			}
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetCurrentProcessId", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(4000) // fake process ID
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "QueryPerformanceCounter", func(ctx *ntapi.TrapContext) uint32 {
			ptr := ctx.Arg(0)
			if ptr != 0 {
				// 10 MHz counter (100ns resolution) matching QueryPerformanceFrequency
				ns := time.Since(bootTime).Nanoseconds() / 100
				ctx.Mem.Write64Raw(ptr, uint64(ns))
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
		// resolveApiSetDLL maps Windows API set names to their host DLL.
		// On real Windows, api-ms-win-core-* are virtual DLLs that redirect
		// to kernel32, user32, etc. We replicate this so GetProcAddress
		// finds the functions in the correct synth DLL.
		resolveApiSetDLL := func(name string) string {
			if !strings.HasPrefix(name, "api-ms-win-") && !strings.HasPrefix(name, "ext-ms-") {
				return name
			}
			// Map common API sets to their implementing DLL
			switch {
			case strings.HasPrefix(name, "api-ms-win-core-"):
				return "kernel32.dll"
			case strings.HasPrefix(name, "api-ms-win-crt-"):
				if _, ok := synthByName["ucrtbase.dll"]; ok {
					return "ucrtbase.dll"
				}
				return "msvcrt.dll"
			case strings.HasPrefix(name, "api-ms-win-security-"):
				return "advapi32.dll"
			case strings.HasPrefix(name, "api-ms-win-shcore-"):
				return "shcore.dll"
			default:
				return "kernel32.dll"
			}
		}

		d.RegisterAutoStubHandler(kernel32, "LoadLibraryExW", func(ctx *ntapi.TrapContext) uint32 {
			namePtr := ctx.Arg(0)
			if namePtr == 0 {
				ctx.SetReturn(0)
				return 0
			}
			name := strings.ToLower(readGuestUTF16(namePtr))
			if idx := strings.LastIndexAny(name, "/\\"); idx >= 0 {
				name = name[idx+1:]
			}
			if !strings.HasSuffix(name, ".dll") {
				name += ".dll"
			}
			// Redirect API set DLLs to their real implementation
			resolved := resolveApiSetDLL(name)
			if resolved != name {
				if synth, ok := synthByName[resolved]; ok {
					synthByName[name] = synth // cache redirect
					ctx.SetReturn(synth.BaseAddr)
					return 0
				}
			}
			if synth, ok := synthByName[name]; ok {
				ctx.SetReturn(synth.BaseAddr)
				return 0
			}
			newSynth := ntapi.GenerateSynthDLL(mem, name, []string{}, 0)
			synthByName[name] = newSynth
			ravelog.Logf("[win32] LoadLibraryExW: auto-created stub for %q\n", name)
			ctx.SetReturn(newSynth.BaseAddr)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "LoadLibraryW", func(ctx *ntapi.TrapContext) uint32 {
			namePtr := ctx.Arg(0)
			if namePtr == 0 {
				ctx.SetReturn(0)
				return 0
			}
			name := strings.ToLower(readGuestUTF16(namePtr))
			if idx := strings.LastIndexAny(name, "/\\"); idx >= 0 {
				name = name[idx+1:]
			}
			if !strings.HasSuffix(name, ".dll") {
				name += ".dll"
			}
			resolved := resolveApiSetDLL(name)
			if resolved != name {
				if synth, ok := synthByName[resolved]; ok {
					synthByName[name] = synth
					ctx.SetReturn(synth.BaseAddr)
					return 0
				}
			}
			if synth, ok := synthByName[name]; ok {
				ctx.SetReturn(synth.BaseAddr)
				return 0
			}
			newSynth := ntapi.GenerateSynthDLL(mem, name, []string{}, 0)
			synthByName[name] = newSynth
			ravelog.Logf("[win32] LoadLibraryW: auto-created stub for %q\n", name)
			ctx.SetReturn(newSynth.BaseAddr)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "LoadLibraryA", func(ctx *ntapi.TrapContext) uint32 {
			namePtr := ctx.Arg(0)
			if namePtr == 0 {
				ctx.SetReturn(0)
				return 0
			}
			name := strings.ToLower(readGuestString(namePtr))
			if idx := strings.LastIndexAny(name, "/\\"); idx >= 0 {
				name = name[idx+1:]
			}
			if !strings.HasSuffix(name, ".dll") {
				name += ".dll"
			}
			resolved := resolveApiSetDLL(name)
			if resolved != name {
				if synth, ok := synthByName[resolved]; ok {
					synthByName[name] = synth
					ctx.SetReturn(synth.BaseAddr)
					return 0
				}
			}
			if synth, ok := synthByName[name]; ok {
				ctx.SetReturn(synth.BaseAddr)
				return 0
			}
			newSynth := ntapi.GenerateSynthDLL(mem, name, []string{}, 0)
			synthByName[name] = newSynth
			ravelog.Logf("[win32] LoadLibraryA: auto-created stub for %q\n", name)
			ctx.SetReturn(newSynth.BaseAddr)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FreeLibrary", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetProcAddress", func(ctx *ntapi.TrapContext) uint32 {
			hModule := ctx.Arg(0)
			procNamePtr := ctx.Arg(1)
			if hModule == 0 || procNamePtr == 0 {
				ctx.SetReturn(0)
				return 0
			}
			// Detect ordinal import (high word of pointer is 0 → low word is ordinal)
			hi, _ := ctx.Mem.Read32(procNamePtr + 2)
			var funcName string
			isOrdinal := hi == 0
			if isOrdinal {
				ordinal := uint16(procNamePtr & 0xFFFF)
				// Search all synths for this ordinal
				for _, s := range dlls {
					if s.BaseAddr == hModule {
						if addr, ok := s.ExportOrds[ordinal]; ok {
							ctx.SetReturn(addr)
							return 0
						}
					}
				}
				for _, s := range synthByName {
					if s.BaseAddr == hModule {
						if addr, ok := s.ExportOrds[ordinal]; ok {
							ctx.SetReturn(addr)
							return 0
						}
					}
				}
				ctx.SetReturn(0)
				return 0
			}
			funcName = readGuestString(procNamePtr)
			// Search pre-loaded dlls slice first
			for _, s := range dlls {
				if s.BaseAddr == hModule {
					if addr, ok := s.Exports[funcName]; ok {
						ctx.SetReturn(addr)
						return 0
					}
				}
			}
			// Also search synthByName (covers DLLs loaded via LoadLibraryW at runtime)
			for _, s := range synthByName {
				if s.BaseAddr == hModule {
					if addr, ok := s.Exports[funcName]; ok {
						ctx.SetReturn(addr)
						return 0
					}
					}
			}
			ravelog.Logf("[win32] GetProcAddress(0x%x, %q) → not found\n", hModule, funcName)
			ctx.SetReturn(0)
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
			ms := ctx.Arg(0)
			if ms > 0 && ms < 60000 {
				time.Sleep(time.Duration(ms) * time.Millisecond)
			}
			return 0
		})

		// Heap emulation - bump allocator with free-list recycling.
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
			size := ctx.Arg(2)
			flags := ctx.Arg(1)
			zeroInit := flags&0x08 != 0 // HEAP_ZERO_MEMORY
			ptr := sharedHeapAlloc(size, zeroInit)
			ctx.SetReturn(ptr)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "HeapFree", func(ctx *ntapi.TrapContext) uint32 {
			ptr := ctx.Arg(2)
			sharedHeapFree(ptr)
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "HeapReAlloc", func(ctx *ntapi.TrapContext) uint32 {
			oldPtr := ctx.Arg(2)
			newSize := ctx.Arg(3)
			flags := ctx.Arg(1)
			zeroInit := flags&0x08 != 0

			newPtr := sharedHeapAlloc(newSize, zeroInit)
			if newPtr == 0 {
				ctx.SetReturn(0)
				return 0
			}

			if oldPtr != 0 {
				oldBlockSize, _ := ctx.Mem.Read64(oldPtr - 16)
				oldUserSize := oldBlockSize - 16
				copyLen := oldUserSize
				if newSize < copyLen {
					copyLen = newSize
				}
				for i := uint64(0); i < copyLen; i++ {
					b, _ := ctx.Mem.Read8(oldPtr + i)
					ctx.Mem.Write8(newPtr+i, b)
				}
				sharedHeapFree(oldPtr)
			}
			ctx.SetReturn(newPtr)
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
			ctx.Mem.Write64(si+24, 0xF)                    // dwActiveProcessorMask (4 CPUs)
			ctx.Mem.Write32(si+32, 4)                      // dwNumberOfProcessors
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
			ft := ctx.Arg(0)
			if ft != 0 {
				const epochDiff = uint64(11644473600) * 10000000
				v := uint64(time.Now().UnixNano()/100) + epochDiff
				ctx.Mem.Write64Raw(ft, v)
			}
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
			ctx.SetReturn(0) // NULL = success (no-op)
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
			ctx.Mem.Write32(addr, 104)       // cb
			ctx.Mem.Write32(addr+60, 0x0001) // dwFlags = STARTF_USESHOWWINDOW
			ctx.Mem.Write16(addr+64, 0x0001) // wShowWindow = SW_SHOWNORMAL
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
			pathPtr := ctx.Arg(0)
			if pathPtr == 0 { ctx.SetReturn(0); return 0 }
			path := winPathToVFS(readGuestUTF16(pathPtr))
			if err := os.MkdirAll(path, 0755); err != nil {
				ctx.SetReturn(0)
				return 0
			}
			ctx.SetReturn(1)
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
			h := ntapi.Handle(ctx.Arg(0))
			ms := ctx.Arg(1)
			var timeout time.Duration
			if ms == 0xFFFFFFFF {
				timeout = -1 // INFINITE
			} else if ms == 0 {
				timeout = 0
			} else {
				timeout = time.Duration(ms) * time.Millisecond
			}
			const waitObject0 = uint64(0)
			const waitTimeout = uint64(0x102)
			// Thread handle: wait for goroutine to finish
			if th := handles.GetThread(h); th != nil && th.Done != nil {
				if timeout < 0 {
					<-th.Done
					ctx.SetReturn(waitObject0)
				} else if timeout == 0 {
					select {
					case <-th.Done:
						ctx.SetReturn(waitObject0)
					default:
						ctx.SetReturn(waitTimeout)
					}
				} else {
					select {
					case <-th.Done:
						ctx.SetReturn(waitObject0)
					case <-time.After(timeout):
						ctx.SetReturn(waitTimeout)
					}
				}
				return 0
			}
			// Event handle: wait until signaled
			if eh := handles.GetEvent(h); eh != nil {
				if eh.WaitTimeout(timeout) {
					ctx.SetReturn(waitObject0)
				} else {
					ctx.SetReturn(waitTimeout)
				}
				return 0
			}
			// Unknown/process handle: return WAIT_OBJECT_0 immediately
			ctx.SetReturn(waitObject0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "WaitForMultipleObjects", func(ctx *ntapi.TrapContext) uint32 {
			nCount := ctx.Arg(0)
			pHandles := ctx.Arg(1)
			// waitAll := ctx.Arg(2) != 0
			ms := ctx.Arg(3)
			var timeout time.Duration
			if ms == 0xFFFFFFFF {
				timeout = -1
			} else if ms == 0 {
				timeout = 0
			} else {
				timeout = time.Duration(ms) * time.Millisecond
			}
			// Wait on the first signaled handle (waitAny semantics).
			// For simplicity, iterate and wait on each in turn.
			for i := uint64(0); i < nCount && i < 64; i++ {
				hv, _ := ctx.Mem.Read64(pHandles + i*8)
				h := ntapi.Handle(hv)
				if th := handles.GetThread(h); th != nil && th.Done != nil {
					if timeout < 0 {
						<-th.Done
					} else if timeout > 0 {
						select {
						case <-th.Done:
						case <-time.After(timeout):
							ctx.SetReturn(0x102) // WAIT_TIMEOUT
							return 0
						}
					} else {
						select {
						case <-th.Done:
						default:
							ctx.SetReturn(0x102)
							return 0
						}
					}
					ctx.SetReturn(i)
					return 0
				}
				if eh := handles.GetEvent(h); eh != nil {
					if eh.WaitTimeout(timeout) {
						ctx.SetReturn(i)
						return 0
					}
					ctx.SetReturn(0x102)
					return 0
				}
			}
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
			ms := ctx.Arg(0)
			if ms > 0 && ms < 60000 {
				time.Sleep(time.Duration(ms) * time.Millisecond)
			}
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateEventW", func(ctx *ntapi.TrapContext) uint32 {
			h := handles.Alloc(&ntapi.EventHandle{})
			ctx.SetReturn(uint64(h))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetEvent", func(ctx *ntapi.TrapContext) uint32 {
			if eh := handles.GetEvent(ntapi.Handle(ctx.Arg(0))); eh != nil { eh.Set() }
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ResetEvent", func(ctx *ntapi.TrapContext) uint32 {
			if eh := handles.GetEvent(ntapi.Handle(ctx.Arg(0))); eh != nil { eh.Reset() }
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
		// Thread stack pool for reuse (avoids Mmap leak)
		type threadStack struct {
			base uint64
			size uint64
		}
		var freeStacks []threadStack
		var stackMu sync.Mutex

		d.RegisterAutoStubHandler(kernel32, "CreateThread", func(ctx *ntapi.TrapContext) uint32 {
			dwStackSize := ctx.Arg(1)
			lpStartAddress := ctx.Arg(2)
			lpParameter := ctx.Arg(3)
			lpThreadId := ctx.Arg(5)
			stackSz := dwStackSize
			if stackSz == 0 {
				stackSz = 1 << 20 // 1 MB default
			}

			// Try to reuse a freed stack of matching size
			var stackBase uint64
			stackMu.Lock()
			for i, s := range freeStacks {
				if s.size >= stackSz {
					stackBase = s.base
					stackSz = s.size
					freeStacks[i] = freeStacks[len(freeStacks)-1]
					freeStacks = freeStacks[:len(freeStacks)-1]
					break
				}
			}
			stackMu.Unlock()
			if stackBase == 0 {
				stackBase = mem.Mmap(0, stackSz, mmu.PermRead|mmu.PermWrite)
			}

			tm := *tmPtr
			if tm == nil {
				th := &ntapi.ThreadHandle{TID: 0, Done: make(chan struct{})}
				close(th.Done)
				h := handles.Alloc(th)
				ctx.SetReturn(uint64(h))
				return 0
			}
			tid, done, err := tm.CloneWin32Thread(ctx.CPU, lpStartAddress, lpParameter, stackBase, stackSz)
			if err != nil {
				ctx.SetReturn(0)
				return 0
			}
			if lpThreadId != 0 {
				ctx.Mem.Write32(lpThreadId, uint32(tid))
			}

			// Recycle stack when thread exits
			capturedBase := stackBase
			capturedSize := stackSz
			go func() {
				<-done
				stackMu.Lock()
				freeStacks = append(freeStacks, threadStack{base: capturedBase, size: capturedSize})
				stackMu.Unlock()
			}()

			h := handles.Alloc(&ntapi.ThreadHandle{TID: tid, Done: done})
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
			// stdin handle
			if hFile == 0x100 {
				buf := make([]byte, nBytesToRead)
				n, err := os.Stdin.Read(buf)
				ctx.Mem.WriteBytes(bufAddr, buf[:n])
				if lpBytesRead != 0 {
					ctx.Mem.Write32(lpBytesRead, uint32(n))
				}
				if err != nil {
					ctx.SetReturn(0)
				} else {
					ctx.SetReturn(1)
				}
				return 0
			}
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
			pathPtr := ctx.Arg(0)
			if pathPtr == 0 { ctx.SetReturn(0xFFFFFFFF); return 0 }
			winPath := readGuestUTF16(pathPtr)
			path := winPathToVFS(winPath)
			info, err := os.Stat(path)
			if err != nil {
				ctx.SetReturn(0xFFFFFFFF) // INVALID_FILE_ATTRIBUTES
				return 0
			}
			var attrs uint32 = 0x20 // FILE_ATTRIBUTE_NORMAL
			if info.IsDir() { attrs = 0x10 } // FILE_ATTRIBUTE_DIRECTORY
			if strings.HasPrefix(info.Name(), ".") { attrs |= 0x02 } // FILE_ATTRIBUTE_HIDDEN
			ctx.SetReturn(uint64(attrs))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetFileAttributesExW", func(ctx *ntapi.TrapContext) uint32 {
			lpFileName := ctx.Arg(0)
			// fInfoLevelId := ctx.Arg(1) // always GetFileExInfoStandard (0)
			lpFileInfo := ctx.Arg(2)
			path := winPathToVFS(readGuestUTF16(lpFileName))
			info, err := os.Stat(path)
			if err != nil {
				ctx.SetReturn(0)
				return 0
			}
			// WIN32_FILE_ATTRIBUTE_DATA layout:
			// dwFileAttributes(4), ftCreationTime(8), ftLastAccessTime(8),
			// ftLastWriteTime(8), nFileSizeHigh(4), nFileSizeLow(4)
			var attrs uint32
			if info.IsDir() {
				attrs = 0x10 // FILE_ATTRIBUTE_DIRECTORY
			} else {
				attrs = 0x80 // FILE_ATTRIBUTE_NORMAL
			}
			ctx.Mem.Write32(lpFileInfo, attrs)
			// File times - use ModTime for all three (creation, access, write)
			const epochDiff = uint64(11644473600) * 10000000
			ft := uint64(info.ModTime().UnixNano())/100 + epochDiff
			ctx.Mem.Write32(lpFileInfo+4, uint32(ft))
			ctx.Mem.Write32(lpFileInfo+8, uint32(ft>>32))
			ctx.Mem.Write32(lpFileInfo+12, uint32(ft))
			ctx.Mem.Write32(lpFileInfo+16, uint32(ft>>32))
			ctx.Mem.Write32(lpFileInfo+20, uint32(ft))
			ctx.Mem.Write32(lpFileInfo+24, uint32(ft>>32))
			// File size
			size := uint64(info.Size())
			ctx.Mem.Write32(lpFileInfo+28, uint32(size>>32))
			ctx.Mem.Write32(lpFileInfo+32, uint32(size))
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FindFirstFileW", func(ctx *ntapi.TrapContext) uint32 {
			pathPtr := ctx.Arg(0)
			dataPtr := ctx.Arg(1)
			pattern := readGuestUTF16(pathPtr)
			vfsPattern := winPathToVFS(pattern)
			dir := filepath.Dir(vfsPattern)
			glob := filepath.Base(vfsPattern)
			entries, err := os.ReadDir(dir)
			if err != nil {
				ctx.SetReturn(0xFFFFFFFFFFFFFFFF) // INVALID_HANDLE_VALUE
				return 0
			}
			var matched []os.DirEntry
			for _, e := range entries {
				ok, _ := filepath.Match(glob, e.Name())
				if ok {
					matched = append(matched, e)
				}
			}
			if len(matched) == 0 {
				ctx.SetReturn(0xFFFFFFFFFFFFFFFF)
				return 0
			}
			fh := &ntapi.FindHandle{Entries: matched, Idx: 1, Dir: dir}
			if dataPtr != 0 {
				writeFindData(ctx.Mem, dataPtr, dir, matched[0])
			}
			h := handles.Alloc(fh)
			ctx.SetReturn(uint64(h))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FindFirstFileExW", func(ctx *ntapi.TrapContext) uint32 {
			pathPtr := ctx.Arg(0)
			dataPtr := ctx.Arg(4)
			pattern := readGuestUTF16(pathPtr)
			vfsPattern := winPathToVFS(pattern)
			dir := filepath.Dir(vfsPattern)
			glob := filepath.Base(vfsPattern)
			entries, err := os.ReadDir(dir)
			if err != nil {
				ctx.SetReturn(0xFFFFFFFFFFFFFFFF)
				return 0
			}
			var matched []os.DirEntry
			for _, e := range entries {
				ok, _ := filepath.Match(glob, e.Name())
				if ok {
					matched = append(matched, e)
				}
			}
			if len(matched) == 0 {
				ctx.SetReturn(0xFFFFFFFFFFFFFFFF)
				return 0
			}
			fh := &ntapi.FindHandle{Entries: matched, Idx: 1, Dir: dir}
			if dataPtr != 0 {
				writeFindData(ctx.Mem, dataPtr, dir, matched[0])
			}
			h := handles.Alloc(fh)
			ctx.SetReturn(uint64(h))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FindNextFileW", func(ctx *ntapi.TrapContext) uint32 {
			hFind := ctx.Arg(0)
			dataPtr := ctx.Arg(1)
			obj := handles.Get(ntapi.Handle(hFind))
			fh, ok := obj.(*ntapi.FindHandle)
			if !ok || fh.Idx >= len(fh.Entries) {
				ctx.SetReturn(0)
				return 0
			}
			if dataPtr != 0 {
				writeFindData(ctx.Mem, dataPtr, fh.Dir, fh.Entries[fh.Idx])
			}
			fh.Idx++
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FindClose", func(ctx *ntapi.TrapContext) uint32 {
			handles.Close(ntapi.Handle(ctx.Arg(0)))
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CopyFileW", func(ctx *ntapi.TrapContext) uint32 {
			src := winPathToVFS(readGuestUTF16(ctx.Arg(0)))
			dst := winPathToVFS(readGuestUTF16(ctx.Arg(1)))
			in, err := os.Open(src)
			if err != nil { ctx.SetReturn(0); return 0 }
			defer in.Close()
			out, err := os.Create(dst)
			if err != nil { ctx.SetReturn(0); return 0 }
			defer out.Close()
			if _, err = io.Copy(out, in); err != nil { ctx.SetReturn(0); return 0 }
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CopyFileExW", func(ctx *ntapi.TrapContext) uint32 {
			src := winPathToVFS(readGuestUTF16(ctx.Arg(0)))
			dst := winPathToVFS(readGuestUTF16(ctx.Arg(1)))
			in, err := os.Open(src)
			if err != nil { ctx.SetReturn(0); return 0 }
			defer in.Close()
			out, err := os.Create(dst)
			if err != nil { ctx.SetReturn(0); return 0 }
			defer out.Close()
			io.Copy(out, in)
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "DeleteFileW", func(ctx *ntapi.TrapContext) uint32 {
			path := winPathToVFS(readGuestUTF16(ctx.Arg(0)))
			if err := os.Remove(path); err != nil { ctx.SetReturn(0); return 0 }
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "MoveFileExW", func(ctx *ntapi.TrapContext) uint32 {
			src := winPathToVFS(readGuestUTF16(ctx.Arg(0)))
			dst := winPathToVFS(readGuestUTF16(ctx.Arg(1)))
			if err := os.Rename(src, dst); err != nil { ctx.SetReturn(0); return 0 }
			ctx.SetReturn(1)
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
			dwMapFlags := ctx.Arg(1)
			srcStr := ctx.Arg(2)
			srcLen := int32(ctx.Arg(3))
			dstBuf := ctx.Arg(4)
			dstLen := int32(ctx.Arg(5))
			var src []uint16
			if srcLen < 0 {
				for i := uint64(0); ; i += 2 {
					w, _ := ctx.Mem.Read16(srcStr + i)
					if w == 0 { break }
					src = append(src, w)
				}
			} else {
				for i := int32(0); i < srcLen; i++ {
					w, _ := ctx.Mem.Read16(srcStr + uint64(i)*2)
					src = append(src, w)
				}
			}
			s := string(utf16Decode(src))
			var result string
			if dwMapFlags&0x200 != 0 { result = strings.ToUpper(s) } else if dwMapFlags&0x100 != 0 { result = strings.ToLower(s) } else { result = s }
			ws := utf16Encode(result)
			if dstBuf == 0 { ctx.SetReturn(uint64(len(ws))); return 0 }
			n := int32(len(ws)); if dstLen > 0 && n > dstLen { n = dstLen }
			for i := int32(0); i < n; i++ { ctx.Mem.Write16(dstBuf+uint64(i)*2, ws[i]) }
			ctx.SetReturn(uint64(n))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "LCMapStringA", func(ctx *ntapi.TrapContext) uint32 {
			dwMapFlags := ctx.Arg(1)
			srcStr := ctx.Arg(2)
			srcLen := int32(ctx.Arg(3))
			dstBuf := ctx.Arg(4)
			dstLen := int32(ctx.Arg(5))
			var src []byte
			if srcLen < 0 {
				for i := uint64(0); ; i++ {
					b, _ := ctx.Mem.Read8(srcStr + i)
					if b == 0 { break }
					src = append(src, b)
				}
			} else {
				for i := int32(0); i < srcLen; i++ {
					b, _ := ctx.Mem.Read8(srcStr + uint64(i))
					src = append(src, b)
				}
			}
			s := string(src)
			var result string
			if dwMapFlags&0x200 != 0 { result = strings.ToUpper(s) } else if dwMapFlags&0x100 != 0 { result = strings.ToLower(s) } else { result = s }
			if dstBuf == 0 { ctx.SetReturn(uint64(len(result))); return 0 }
			n := int32(len(result)); if dstLen > 0 && n > dstLen { n = dstLen }
			for i := int32(0); i < n; i++ { ctx.Mem.Write8(dstBuf+uint64(i), result[i]) }
			ctx.SetReturn(uint64(n))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "LCMapStringEx", func(ctx *ntapi.TrapContext) uint32 {
			dwMapFlags := ctx.Arg(2)
			srcStr := ctx.Arg(3)
			srcLen := int32(ctx.Arg(4))
			dstBuf := ctx.Arg(5)
			dstLen := int32(ctx.Arg(6))
			var src []uint16
			if srcLen < 0 {
				for i := uint64(0); ; i += 2 {
					w, _ := ctx.Mem.Read16(srcStr + i)
					if w == 0 { break }
					src = append(src, w)
				}
			} else {
				for i := int32(0); i < srcLen; i++ {
					w, _ := ctx.Mem.Read16(srcStr + uint64(i)*2)
					src = append(src, w)
				}
			}
			s := string(utf16Decode(src))
			var result string
			if dwMapFlags&0x200 != 0 { result = strings.ToUpper(s) } else if dwMapFlags&0x100 != 0 { result = strings.ToLower(s) } else { result = s }
			ws := utf16Encode(result)
			if dstBuf == 0 { ctx.SetReturn(uint64(len(ws))); return 0 }
			n := int32(len(ws)); if dstLen > 0 && n > dstLen { n = dstLen }
			for i := int32(0); i < n; i++ { ctx.Mem.Write16(dstBuf+uint64(i)*2, ws[i]) }
			ctx.SetReturn(uint64(n))
			return 0
		})
		// Helper: write locale info string to Unicode buffer
		writeLocaleInfoW := func(buf uint64, cchBuf uint64, val string) uint32 {
			ws := utf16Encode(val)
			if buf == 0 { return uint32(len(ws) + 1) }
			n := uint64(len(ws) + 1)
			if cchBuf > 0 && n > cchBuf { n = cchBuf }
			for i := uint64(0); i < n-1 && i < uint64(len(ws)); i++ { mem.Write16(buf+i*2, ws[i]) }
			mem.Write16(buf+(n-1)*2, 0)
			return uint32(n)
		}
		getLocaleInfoValue := func(lctype uint32) string {
			switch lctype & 0xFFFF {
			case 0x02: return "English (United States)"
			case 0x72: return "English (United States)"
			case 0x59: return "en"
			case 0x5A: return "US"
			case 0x0E: return "1252"
			case 0x0B: return "437"
			case 0x0F: return ","
			case 0x13: return "0123456789"
			case 0x10: return "."
			case 0x11: return "-"
			case 0x03: return "English"
			case 0x04: return "English"
			case 0x01: return "English (United States)"
			case 0x1004: return "en-US"
			default: return ""
			}
		}
		d.RegisterAutoStubHandler(kernel32, "GetLocaleInfoA", func(ctx *ntapi.TrapContext) uint32 {
			lctype := uint32(ctx.Arg(1))
			buf := ctx.Arg(2)
			cchBuf := ctx.Arg(3)
			val := getLocaleInfoValue(lctype)
			if val == "" { val = "" }
			if buf == 0 { ctx.SetReturn(uint64(len(val) + 1)); return 0 }
			n := uint64(len(val) + 1)
			if cchBuf > 0 && n > cchBuf { n = cchBuf }
			for i := uint64(0); i < n-1 && i < uint64(len(val)); i++ { ctx.Mem.Write8(buf+i, val[i]) }
			ctx.Mem.Write8(buf+n-1, 0)
			ctx.SetReturn(n)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetLocaleInfoW", func(ctx *ntapi.TrapContext) uint32 {
			lctype := uint32(ctx.Arg(1))
			buf := ctx.Arg(2)
			cchBuf := ctx.Arg(3)
			val := getLocaleInfoValue(lctype)
			n := writeLocaleInfoW(buf, cchBuf, val)
			ctx.SetReturn(uint64(n))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetLocaleInfoEx", func(ctx *ntapi.TrapContext) uint32 {
			lctype := uint32(ctx.Arg(2))
			buf := ctx.Arg(3)
			cchBuf := ctx.Arg(4)
			val := getLocaleInfoValue(lctype)
			n := writeLocaleInfoW(buf, cchBuf, val)
			ctx.SetReturn(uint64(n))
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
			buf := ctx.Arg(4)
			cchDate := ctx.Arg(5)
			now := time.Now()
			s := fmt.Sprintf("%02d/%02d/%04d", now.Month(), now.Day(), now.Year())
			ws := utf16Encode(s)
			if buf == 0 || cchDate == 0 { ctx.SetReturn(uint64(len(ws)+1)); return 0 }
			n := uint64(len(ws)+1); if n > cchDate { n = cchDate }
			for i := uint64(0); i+1 < n; i++ { ctx.Mem.Write16(buf+i*2, ws[i]) }
			ctx.Mem.Write16(buf+(n-1)*2, 0)
			ctx.SetReturn(n)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetTimeFormatW", func(ctx *ntapi.TrapContext) uint32 {
			buf := ctx.Arg(4)
			cchTime := ctx.Arg(5)
			now := time.Now()
			s := fmt.Sprintf("%02d:%02d:%02d", now.Hour(), now.Minute(), now.Second())
			ws := utf16Encode(s)
			if buf == 0 || cchTime == 0 { ctx.SetReturn(uint64(len(ws)+1)); return 0 }
			n := uint64(len(ws)+1); if n > cchTime { n = cchTime }
			for i := uint64(0); i+1 < n; i++ { ctx.Mem.Write16(buf+i*2, ws[i]) }
			ctx.Mem.Write16(buf+(n-1)*2, 0)
			ctx.SetReturn(n)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetDateFormatEx", func(ctx *ntapi.TrapContext) uint32 {
			buf := ctx.Arg(4)
			cchDate := ctx.Arg(5)
			now := time.Now()
			s := fmt.Sprintf("%02d/%02d/%04d", now.Month(), now.Day(), now.Year())
			ws := utf16Encode(s)
			if buf == 0 || cchDate == 0 { ctx.SetReturn(uint64(len(ws)+1)); return 0 }
			n := uint64(len(ws)+1); if n > cchDate { n = cchDate }
			for i := uint64(0); i+1 < n; i++ { ctx.Mem.Write16(buf+i*2, ws[i]) }
			ctx.Mem.Write16(buf+(n-1)*2, 0)
			ctx.SetReturn(n)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetTimeFormatEx", func(ctx *ntapi.TrapContext) uint32 {
			buf := ctx.Arg(4)
			cchTime := ctx.Arg(5)
			now := time.Now()
			s := fmt.Sprintf("%02d:%02d:%02d", now.Hour(), now.Minute(), now.Second())
			ws := utf16Encode(s)
			if buf == 0 || cchTime == 0 { ctx.SetReturn(uint64(len(ws)+1)); return 0 }
			n := uint64(len(ws)+1); if n > cchTime { n = cchTime }
			for i := uint64(0); i+1 < n; i++ { ctx.Mem.Write16(buf+i*2, ws[i]) }
			ctx.Mem.Write16(buf+(n-1)*2, 0)
			ctx.SetReturn(n)
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
		// Allocate a vmcall trampoline for catch funclet returns.
		// When a catch funclet does RET, it lands here.
		// The trampoline saves RAX (funclet return) in RCX, then does vmcall.
		catchReturnTrampoline := mem.Mmap(0, 4096, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
		off := catchReturnTrampoline
		// mov rcx, rax    (48 89 C1) - save funclet return value
		mem.Write8(off, 0x48); mem.Write8(off+1, 0x89); mem.Write8(off+2, 0xC1)
		off += 3
		// mov eax, CatchReturnID  (B8 xx xx xx xx)
		mem.Write8(off, 0xB8)
		mem.Write32(off+1, ntapi.CatchReturnID)
		off += 5
		// vmcall  (0F 01 C1)
		mem.Write8(off, 0x0F); mem.Write8(off+1, 0x01); mem.Write8(off+2, 0xC1)
		off += 3
		// ret (C3) - shouldn't reach here
		mem.Write8(off, 0xC3)

		d.RegisterHandler(ntapi.CatchReturnID, "CatchReturn", func(ctx *ntapi.TrapContext) uint32 {
			// RCX = funclet's return value (continuation address)
			continuation := ctx.Arg(0) // Arg(0) = RCX in Win64 ABI
			if continuation != 0 {
				ravelog.Logf("[seh] catch funclet → continuation at 0x%x\n", continuation)
				ctx.CPU.SetPC(continuation)
			} else {
				// RAX=0: funclet didn't provide a continuation.
				// Use the pre-computed FH4 continuation from IP-to-state map.
				savedCont, _ := mem.Read64(catchReturnTrampoline + 80)
				bodyRSP, _ := mem.Read64(catchReturnTrampoline + 152)
				if savedCont != 0 {
					ravelog.Logf("[seh] catch funclet → RAX=0, using FH4 continuation at 0x%x bodyRSP=0x%x\n", savedCont, bodyRSP)
					// Restore non-volatile registers from unwind context
					if rw, ok := ctx.CPU.(ntapi.RegisterWriter); ok {
						nonVolRegs := []int{3, 5, 6, 7, 12, 13, 14, 15}
						for i, reg := range nonVolRegs {
							val, _ := mem.Read64(catchReturnTrampoline + 88 + uint64(i*8))
							rw.WriteReg(reg, val)
						}
						// Restore R11 = entry RSP (establisher - 8), used as frame pointer by some functions
						establisher, _ := mem.Read64(catchReturnTrampoline + 160)
						if establisher != 0 {
							rw.WriteReg(11, establisher-8) // R11
						}
					}
					ctx.CPU.SetPC(savedCont)
					ctx.CPU.SetSP(bodyRSP)
				} else {
					// No continuation available - resume at RaiseException caller
					savedRIP, _ := mem.Read64(catchReturnTrampoline + 64)
					savedRSP, _ := mem.Read64(catchReturnTrampoline + 72)
					ravelog.Logf("[seh] catch funclet → RAX=0, resuming at RIP=0x%x RSP=0x%x\n", savedRIP, savedRSP)
					ctx.CPU.SetPC(savedRIP)
					ctx.CPU.SetSP(savedRSP)
				}
			}
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
					ravelog.Logf("[seh] C++ exception → catch funclet at 0x%x, establisher=0x%x contRVA=0x%x catchObjOffset=%d\n",
						catchAddr, handler.EstablisherRBP, handler.ContinuationRVA, handler.CatchObjOffset)

					// Place the thrown object (or reference) at [EstablisherRBP + CatchObjOffset].
					// RaiseException args layout for 0xe06d7363:
					//   args[0] = magic (0x19930520 / 0x19930521)
					//   args[1] = pointer to thrown object
					//   args[2] = pointer to _ThrowInfo
					nParams := ctx.Arg(2)
					pArgs := ctx.Arg(3)
					if handler.CatchObjOffset != 0 && nParams >= 2 && pArgs != 0 {
						thrownObjPtr, _ := mem.Read64(pArgs + 8) // args[1]
						dest := handler.EstablisherRBP + uint64(int64(handler.CatchObjOffset))
						ravelog.Logf("[seh] placing thrown obj ptr=0x%x at [establisher+offset]=0x%x\n", thrownObjPtr, dest)
						mem.Write64(dest, thrownObjPtr)
					}

					// If no funclet but we have a continuation, jump directly there
					if handler.FuncletRVA == 0 && handler.ContinuationRVA != 0 {
						contAddr := imageBase + uint64(handler.ContinuationRVA)
						ravelog.Logf("[seh] no funclet, jumping to continuation at 0x%x bodyRSP=0x%x\n", contAddr, handler.BodyRSP)
						if rw, ok := ctx.CPU.(ntapi.RegisterWriter); ok {
							if handler.SavedRegs != nil {
								for reg, val := range handler.SavedRegs {
									rw.WriteReg(reg, val)
								}
							}
						}
						// Resume at continuation with the function's body RSP
						ctx.CPU.SetPC(contAddr)
						ctx.CPU.SetSP(handler.BodyRSP)
						return 0
					}

					if rw, ok := ctx.CPU.(ntapi.RegisterWriter); ok {
						// Restore saved non-volatile registers from unwind
						if handler.SavedRegs != nil {
							for reg, val := range handler.SavedRegs {
								rw.WriteReg(reg, val)
							}
						}
						rw.WriteReg(2, handler.EstablisherRBP) // RDX = establisher frame (funclet uses mov rbp, rdx)
					}
					// Save the current RSP/RIP so CatchReturn can resume here if RAX=0.
					// The RaiseException stub's RET will pop the return address from rsp.
					// We save that return address + the RSP after the pop.
					raiseRetAddr, _ := mem.Read64(rsp)
					mem.Write64(catchReturnTrampoline+64, raiseRetAddr)
					mem.Write64(catchReturnTrampoline+72, rsp+8) // RSP after RaiseException RET
					// Save FH4 continuation address (if available)
					if handler.ContinuationRVA != 0 {
						mem.Write64(catchReturnTrampoline+80, imageBase+uint64(handler.ContinuationRVA))
					} else {
						mem.Write64(catchReturnTrampoline+80, 0)
					}
					// Save body RSP for continuation (function's RSP after prologue)
					mem.Write64(catchReturnTrampoline+152, handler.BodyRSP)
					// Save establisher (for R11 restore: entry RSP = establisher - 8)
					mem.Write64(catchReturnTrampoline+160, handler.EstablisherRBP)
					// Save non-volatile registers for continuation restore
					// Layout: [88]=RBX [96]=RBP [104]=RSI [112]=RDI [120]=R12 [128]=R13 [136]=R14 [144]=R15
					nonVolRegs := []int{3, 5, 6, 7, 12, 13, 14, 15} // RBX,RBP,RSI,RDI,R12-R15
					if handler.SavedRegs != nil {
						for i, reg := range nonVolRegs {
							if val, ok := handler.SavedRegs[reg]; ok {
								mem.Write64(catchReturnTrampoline+88+uint64(i*8), val)
							} else {
								mem.Write64(catchReturnTrampoline+88+uint64(i*8), 0)
							}
						}
					}
					// Set up a proper call frame: push catch-return trampoline
					// so funclet's RET lands on our vmcall trampoline.
					sp := handler.EstablisherRBP
					sp -= 8
					mem.Write64(sp, catchReturnTrampoline)
					ctx.CPU.SetSP(sp)
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
			// Log guest call stack
			sp := ctx.CPU.GetSP()
			fmt.Fprintf(os.Stderr, "govm: TerminateProcess code=%d (0x%x) RSP=0x%x\n", code, code, sp)
			for i := uint64(0); i < 8; i++ {
				ret, _ := ctx.Mem.Read64(sp + i*8)
				fmt.Fprintf(os.Stderr, "  [RSP+0x%02x] = 0x%x\n", i*8, ret)
			}
			// STATUS_STACK_BUFFER_OVERRUN (GS cookie failure) - try to survive by
			// rewinding the stack to the message loop if possible.
			if code == 0xC0000417 {
				fmt.Fprintf(os.Stderr, "govm: GS cookie failure - attempting to survive\n")
				// Return 0 from TerminateProcess; caller (__report_gsfailure) will
				// return as well. Execution continues from the instruction after CALL.
				ctx.SetReturn(0)
				return 0
			}
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
			srcPtr := ctx.Arg(0)
			dst := ctx.Arg(1)
			size := ctx.Arg(2)
			src := readGuestUTF16(srcPtr)
			// Expand common Windows environment variables
			src = strings.ReplaceAll(src, `%APPDATA%`, `C:\Users\User\AppData\Roaming`)
			src = strings.ReplaceAll(src, `%LOCALAPPDATA%`, `C:\Users\User\AppData\Local`)
			src = strings.ReplaceAll(src, `%TEMP%`, `C:\Windows\Temp`)
			src = strings.ReplaceAll(src, `%TMP%`, `C:\Windows\Temp`)
			src = strings.ReplaceAll(src, `%USERPROFILE%`, `C:\Users\User`)
			src = strings.ReplaceAll(src, `%WINDIR%`, `C:\Windows`)
			src = strings.ReplaceAll(src, `%SYSTEMROOT%`, `C:\Windows`)
			src = strings.ReplaceAll(src, `%SYSTEMDRIVE%`, `C:`)
			src = strings.ReplaceAll(src, `%PROGRAMFILES%`, `C:\Program Files`)
			src = strings.ReplaceAll(src, `%USERNAME%`, `User`)
			// Write result
			runes := []rune(src)
			n := uint64(0)
			for i, r := range runes {
				if n < size {
					ctx.Mem.Write16(dst+n*2, uint16(r))
				}
				n++
				_ = i
			}
			if n < size {
				ctx.Mem.Write16(dst+n*2, 0)
			}
			ctx.SetReturn(n + 1) // length including null
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetEnvironmentVariableW", func(ctx *ntapi.TrapContext) uint32 {
			name := readGuestUTF16(ctx.Arg(0))
			valPtr := ctx.Arg(1)
			if valPtr == 0 {
				delete(envVars, name)
			} else {
				envVars[name] = readGuestUTF16(valPtr)
			}
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
			dwFlags := ctx.Arg(0)
			dwMessageId := ctx.Arg(2)
			lpBuffer := ctx.Arg(4)
			nSize := ctx.Arg(5)
			const FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x100
			msg := fmt.Sprintf("Error 0x%X", dwMessageId)
			ws := utf16Encode(msg)
			n := uint64(len(ws))
			if dwFlags&FORMAT_MESSAGE_ALLOCATE_BUFFER != 0 {
				// Allocate buffer and write pointer to *lpBuffer
				bufSize := (n + 2) * 2
				addr := mem.Mmap(0, bufSize, mmu.PermRead|mmu.PermWrite)
				for i, w := range ws { ctx.Mem.Write16(addr+uint64(i)*2, w) }
				ctx.Mem.Write16(addr+n*2, 0)
				if lpBuffer != 0 { ctx.Mem.Write64(lpBuffer, addr) }
			} else if lpBuffer != 0 && nSize > 0 {
				maxN := nSize - 1; if n > maxN { n = maxN }
				for i := uint64(0); i < n; i++ { ctx.Mem.Write16(lpBuffer+i*2, ws[i]) }
				ctx.Mem.Write16(lpBuffer+n*2, 0)
			}
			ctx.SetReturn(n)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FormatMessageA", func(ctx *ntapi.TrapContext) uint32 {
			dwFlags := ctx.Arg(0)
			dwMessageId := ctx.Arg(2)
			lpBuffer := ctx.Arg(4)
			nSize := ctx.Arg(5)
			const FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x100
			msg := fmt.Sprintf("Error 0x%X", dwMessageId)
			n := uint64(len(msg))
			if dwFlags&FORMAT_MESSAGE_ALLOCATE_BUFFER != 0 {
				addr := mem.Mmap(0, n+2, mmu.PermRead|mmu.PermWrite)
				for i := range msg { ctx.Mem.Write8(addr+uint64(i), msg[i]) }
				ctx.Mem.Write8(addr+n, 0)
				if lpBuffer != 0 { ctx.Mem.Write64(lpBuffer, addr) }
			} else if lpBuffer != 0 && nSize > 0 {
				maxN := nSize - 1; if n > maxN { n = maxN }
				for i := uint64(0); i < n; i++ { ctx.Mem.Write8(lpBuffer+i, msg[i]) }
				ctx.Mem.Write8(lpBuffer+n, 0)
			}
			ctx.SetReturn(n)
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
			ctx.SetReturn(ctx.Arg(0))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SizeofResource", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(0) // no resource tracking
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
			buf := ctx.Arg(1)
			nCharsToRead := uint32(ctx.Arg(2))
			charsRead := ctx.Arg(3)
			line, _ := stdinReader.ReadString('\n')
			runes := []rune(line)
			if uint32(len(runes)) > nCharsToRead {
				runes = runes[:nCharsToRead]
			}
			for i, r := range runes {
				ctx.Mem.Write16(buf+uint64(i)*2, uint16(r))
			}
			if charsRead != 0 {
				ctx.Mem.Write32(charsRead, uint32(len(runes)))
			}
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateFileMappingW", func(ctx *ntapi.TrapContext) uint32 {
			hFile := ntapi.Handle(ctx.Arg(0))
			flProtect := uint32(ctx.Arg(2))
			szHigh := uint32(ctx.Arg(3))
			szLow := uint32(ctx.Arg(4))
			name := readGuestUTF16(ctx.Arg(5))
			h := doCreateFileMapping(ctx, hFile, flProtect, szHigh, szLow, name)
			ctx.SetReturn(h)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "MapViewOfFile", func(ctx *ntapi.TrapContext) uint32 {
			hMapping := ntapi.Handle(ctx.Arg(0))
			dwDesiredAccess := uint32(ctx.Arg(1))
			offHigh := uint32(ctx.Arg(2))
			offLow := uint32(ctx.Arg(3))
			numBytes := ctx.Arg(4)
			guestAddr := doMapView(ctx, hMapping, dwDesiredAccess, offHigh, offLow, numBytes)
			ctx.SetReturn(guestAddr)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "UnmapViewOfFile", func(ctx *ntapi.TrapContext) uint32 {
			doUnmapView(ctx, ctx.Arg(0))
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FreeLibraryAndExitThread", func(ctx *ntapi.TrapContext) uint32 {
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ExitThread", func(ctx *ntapi.TrapContext) uint32 {
			exitCode := ctx.Arg(0)
			_ = exitCode
			ctx.SetReturn(0)
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

		// GetEnvironmentVariableA: look up in envVars, then os.Getenv
		d.RegisterAutoStubHandler(kernel32, "GetEnvironmentVariableA", func(ctx *ntapi.TrapContext) uint32 {
			name := readGuestString(ctx.Arg(0))
			buf := ctx.Arg(1)
			size := ctx.Arg(2)
			var val string
			if v, ok := envVars[name]; ok { val = v } else { val = os.Getenv(name) }
			if val == "" {
				mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 203)
				ctx.SetReturn(0)
				return 0
			}
			needed := uint64(len(val) + 1)
			if buf == 0 || size == 0 { ctx.SetReturn(needed); return 0 }
			if needed > size { ctx.SetReturn(needed); return 0 }
			for i := range val { ctx.Mem.Write8(buf+uint64(i), val[i]) }
			ctx.Mem.Write8(buf+uint64(len(val)), 0)
			ctx.SetReturn(uint64(len(val)))
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

		// CreateFileA: convert ANSI filename to UTF-16 then delegate to CreateFileW logic
		d.RegisterAutoStubHandler(kernel32, "CreateFileA", func(ctx *ntapi.TrapContext) uint32 {
			namePtr := ctx.Arg(0)
			desiredAccess := ctx.Arg(1)
			creationDisp := ctx.Arg(4)
			name := readGuestString(namePtr)
			vfsPath := winPathToVFS(name)
			lastBS := strings.LastIndex(imagePath, `\`)
			peWinDir := imagePath
			if lastBS >= 0 {
				peWinDir = imagePath[:lastBS]
			}
			peVfsDir := winPathToVFS(peWinDir)
			var flags int
			switch creationDisp {
			case 1:
				flags = vfs.O_CREAT | vfs.O_RDWR
			case 2:
				flags = vfs.O_CREAT | vfs.O_TRUNC | vfs.O_RDWR
			case 3:
				flags = vfs.O_RDONLY
				if desiredAccess&0x40000000 != 0 {
					flags = vfs.O_RDWR
				}
			case 4:
				flags = vfs.O_CREAT | vfs.O_RDWR
			case 5:
				flags = vfs.O_TRUNC | vfs.O_RDWR
			default:
				flags = vfs.O_RDONLY
			}
			fd, err := ctx.FS.Open(vfsPath, flags)
			if err != nil {
				parts := strings.SplitN(strings.TrimPrefix(vfsPath, "/"), "/", 2)
				if len(parts) == 2 {
					altPath := peVfsDir + "/" + parts[1]
					if fd2, err2 := ctx.FS.Open(altPath, flags); err2 == nil {
						fd = fd2
						err = nil
						vfsPath = altPath
					}
				}
			}
			if err != nil {
				ctx.SetReturn(0xFFFFFFFFFFFFFFFF)
				procState.LastError = 2
				return 0
			}
			h := handles.Alloc(&ntapi.FileHandle{FD: fd, Path: vfsPath})
			ctx.SetReturn(uint64(h))
			return 0
		})

		// CreateToolhelp32Snapshot: no process enumeration support
		d.RegisterAutoStubHandler(kernel32, "CreateToolhelp32Snapshot", func(ctx *ntapi.TrapContext) uint32 {
			mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 18) // ERROR_NO_MORE_FILES
			ctx.SetReturn(0xFFFFFFFFFFFFFFFF)                          // INVALID_HANDLE_VALUE
			return 0
		})

		// DeviceIoControl: return FALSE with ERROR_NOT_SUPPORTED
		d.RegisterAutoStubHandler(kernel32, "DeviceIoControl", func(ctx *ntapi.TrapContext) uint32 {
			mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 50) // ERROR_NOT_SUPPORTED
			ctx.SetReturn(0)                                            // FALSE
			return 0
		})

		// GetConsoleScreenBufferInfo: return reasonable 80x25 defaults
		d.RegisterAutoStubHandler(kernel32, "GetConsoleScreenBufferInfo", func(ctx *ntapi.TrapContext) uint32 {
			pInfo := ctx.Arg(1)
			if pInfo != 0 {
				// CONSOLE_SCREEN_BUFFER_INFO layout:
				// dwSize (COORD: 4 bytes), dwCursorPosition (COORD: 4 bytes),
				// wAttributes (WORD: 2 bytes), srWindow (SMALL_RECT: 8 bytes),
				// dwMaximumWindowSize (COORD: 4 bytes)
				mem.Write16(pInfo+0, 80)  // dwSize.X
				mem.Write16(pInfo+2, 300) // dwSize.Y (buffer height)
				mem.Write16(pInfo+4, 0)   // dwCursorPosition.X
				mem.Write16(pInfo+6, 0)   // dwCursorPosition.Y
				mem.Write16(pInfo+8, 7)   // wAttributes (grey on black)
				mem.Write16(pInfo+10, 0)  // srWindow.Left
				mem.Write16(pInfo+12, 0)  // srWindow.Top
				mem.Write16(pInfo+14, 79) // srWindow.Right
				mem.Write16(pInfo+16, 24) // srWindow.Bottom
				mem.Write16(pInfo+18, 80) // dwMaximumWindowSize.X
				mem.Write16(pInfo+20, 25) // dwMaximumWindowSize.Y
			}
			ctx.SetReturn(1) // TRUE
			return 0
		})

		// GetConsoleWindow: return mainHWND for apps that need a window handle
		d.RegisterAutoStubHandler(kernel32, "GetConsoleWindow", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(mainHWND)
			return 0
		})

		// GetDiskFreeSpaceExA: convert ANSI path then return fake values
		d.RegisterAutoStubHandler(kernel32, "GetDiskFreeSpaceExA", func(ctx *ntapi.TrapContext) uint32 {
			free := ctx.Arg(1)
			total := ctx.Arg(2)
			totalFree := ctx.Arg(3)
			if free != 0 {
				ctx.Mem.Write64(free, 100*1024*1024*1024) // 100 GB free
			}
			if total != 0 {
				ctx.Mem.Write64(total, 500*1024*1024*1024) // 500 GB total
			}
			if totalFree != 0 {
				ctx.Mem.Write64(totalFree, 100*1024*1024*1024)
			}
			ctx.SetReturn(1) // TRUE
			return 0
		})

		// GetLogicalDriveStringsA: return "C:\\\0\0" as ANSI
		d.RegisterAutoStubHandler(kernel32, "GetLogicalDriveStringsA", func(ctx *ntapi.TrapContext) uint32 {
			nBuf := uint32(ctx.Arg(0))
			lpBuf := ctx.Arg(1)
			driveStr := []byte{'C', ':', '\\', 0, 0}
			if lpBuf != 0 && nBuf >= uint32(len(driveStr)) {
				ctx.Mem.WriteBytes(lpBuf, driveStr)
			}
			ctx.SetReturn(uint64(len(driveStr) - 1)) // chars written, excluding final null
			return 0
		})

		// GetDriveTypeA: return DRIVE_FIXED (3) for C:\, DRIVE_NO_ROOT_DIR (1) otherwise
		d.RegisterAutoStubHandler(kernel32, "GetDriveTypeA", func(ctx *ntapi.TrapContext) uint32 {
			lpRootPathName := ctx.Arg(0)
			driveType := uint64(1) // DRIVE_NO_ROOT_DIR
			if lpRootPathName != 0 {
				path := ctx.Mem.ReadCString(lpRootPathName, 16)
				if len(path) > 0 && (path[0] == 'C' || path[0] == 'c') {
					driveType = 3 // DRIVE_FIXED
				}
			}
			ravelog.Logf("[kernel32] GetDriveTypeA → %d\n", driveType)
			ctx.SetReturn(driveType)
			return 0
		})

		// GlobalMemoryStatusEx: fill MEMORYSTATUSEX with 8 GB total / 4 GB free
		d.RegisterAutoStubHandler(kernel32, "GlobalMemoryStatusEx", func(ctx *ntapi.TrapContext) uint32 {
			pBuf := ctx.Arg(0)
			if pBuf != 0 {
				// MEMORYSTATUSEX layout (64 bytes total):
				// DWORD  dwLength          +0
				// DWORD  dwMemoryLoad      +4
				// DWORDLONG ullTotalPhys   +8
				// DWORDLONG ullAvailPhys   +16
				// DWORDLONG ullTotalPageFile +24
				// DWORDLONG ullAvailPageFile +32
				// DWORDLONG ullTotalVirtual  +40
				// DWORDLONG ullAvailVirtual  +48
				// DWORDLONG ullAvailExtendedVirtual +56
				const total = 8 * 1024 * 1024 * 1024  // 8 GB
				const avail = 4 * 1024 * 1024 * 1024  // 4 GB
				mem.Write32(pBuf+0, 64)                // dwLength
				mem.Write32(pBuf+4, 50)                // dwMemoryLoad (50%)
				mem.Write64(pBuf+8, total)             // ullTotalPhys
				mem.Write64(pBuf+16, avail)            // ullAvailPhys
				mem.Write64(pBuf+24, total)            // ullTotalPageFile
				mem.Write64(pBuf+32, avail)            // ullAvailPageFile
				mem.Write64(pBuf+40, 0x7FFFFFFFFFFF)   // ullTotalVirtual
				mem.Write64(pBuf+48, 0x7FFFFFFFFFFF)   // ullAvailVirtual
				mem.Write64(pBuf+56, 0)                // ullAvailExtendedVirtual
			}
			ctx.SetReturn(1) // TRUE
			return 0
		})

		// Process32First: no processes to enumerate
		d.RegisterAutoStubHandler(kernel32, "Process32First", func(ctx *ntapi.TrapContext) uint32 {
			mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 18) // ERROR_NO_MORE_FILES
			ctx.SetReturn(0)                                            // FALSE
			return 0
		})

		// SetConsoleTextAttribute: no-op (no real console)
		d.RegisterAutoStubHandler(kernel32, "SetConsoleTextAttribute", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "AcquireSRWLockShared", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // no-op
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ActivateActCtx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "AddAtomA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0xC000) // fake atom
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "AddAtomW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0xC000) // fake atom
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "AddConsoleAliasA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "AddConsoleAliasW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "AddDllDirectory", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // fake cookie
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "AddRefActCtx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // no-op
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "AddVectoredContinueHandler", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x1) // non-NULL handle
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "AddVectoredExceptionHandler", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x1) // non-NULL handle
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "AllocConsole", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "AllocateUserPhysicalPages", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "AllocateUserPhysicalPagesNuma", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "AppPolicyGetMediaFoundationCodecLoading", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // S_OK
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "AppPolicyGetWindowingModel", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // S_OK
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ApplicationRecoveryFinished", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // no-op
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ApplicationRecoveryInProgress", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // S_OK
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "AreFileApisANSI", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "AssignProcessToJobObject", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "AttachConsole", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "BackupRead", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "BackupSeek", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "BackupWrite", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "BaseAttachCompleteThunk", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // no-op
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "BaseCheckAppcompatCache", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // no-op
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "BaseCleanupAppcompatCache", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // no-op
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "BaseCleanupAppcompatCacheSupport", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // no-op
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "BaseDumpAppcompatCache", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // no-op
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "BaseFlushAppcompatCache", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // no-op
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "BaseGetNamedObjectDirectory", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // NULL
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "BaseInitAppcompatCache", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // no-op
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "BaseInitAppcompatCacheSupport", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // no-op
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "BaseProcessInitPostImport", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // no-op
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "BaseThreadInitThunk", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // no-op
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "BaseUpdateAppcompatCache", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // no-op
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "Beep", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE - silent
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "BeginUpdateResourceA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x2001) // fake handle
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "BeginUpdateResourceW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x2001) // fake handle
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "BindIoCompletionCallback", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "BuildCommDCBA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "BuildCommDCBAndTimeoutsA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "BuildCommDCBAndTimeoutsW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "BuildCommDCBW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CallNamedPipeA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CallNamedPipeW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CallbackMayRunLong", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CancelDeviceWakeupRequest", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CancelIo", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CancelIoEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CancelSynchronousIo", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CancelThreadpoolIo", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // no-op
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CancelTimerQueueTimer", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CancelWaitableTimer", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ChangeTimerQueueTimer", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CheckNameLegalDOS8Dot3A", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CheckNameLegalDOS8Dot3W", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CheckRemoteDebuggerPresent", func(ctx *ntapi.TrapContext) uint32 {
			pbDebuggerPresent := ctx.Arg(1)
			if pbDebuggerPresent != 0 {
				ctx.Mem.Write32(pbDebuggerPresent, 0)
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ClearCommBreak", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ClearCommError", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CloseConsoleHandle", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CloseProfileUserMapping", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ClosePseudoConsole", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // no-op
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CloseSystemHandle", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CloseThreadpool", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CloseThreadpoolCleanupGroup", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CloseThreadpoolCleanupGroupMembers", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CloseThreadpoolIo", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // no-op
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CloseThreadpoolTimer", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // no-op
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CloseThreadpoolWait", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // no-op
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CloseThreadpoolWork", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CmdBatNotification", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CommConfigDialogA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CommConfigDialogW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CompareFileTime", func(ctx *ntapi.TrapContext) uint32 {
			ft1, _ := ctx.Mem.Read64(ctx.Arg(0))
			ft2, _ := ctx.Mem.Read64(ctx.Arg(1))
			if ft1 < ft2 { ctx.SetReturn(uint64(0xFFFFFFFF)) } else if ft1 > ft2 { ctx.SetReturn(1) } else { ctx.SetReturn(0) }
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CompareStringA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(2) // CSTR_EQUAL
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CompareStringOrdinal", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(2) // CSTR_EQUAL
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ConnectNamedPipe", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ConsoleMenuControl", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ConsoleSubst", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ContinueDebugEvent", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ConvertDefaultLocale", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(ctx.Arg(0))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ConvertFiberToThread", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ConvertThreadToFiber", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x10000) // fake fiber
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ConvertThreadToFiberEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x10000) // fake fiber
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ConvertToGlobalHandle", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(ctx.Arg(0))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CopyContext", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CopyFile2", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CopyFileA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CopyFileExA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CopyLZFile", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateActCtxA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0xFFFFFFFFFFFFFFFF) // INVALID_HANDLE_VALUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateActCtxW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0xFFFFFFFFFFFFFFFF) // INVALID_HANDLE_VALUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateBoundaryDescriptorA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateBoundaryDescriptorW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateConsoleScreenBuffer", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0xFFFFFFFFFFFFFFFF) // INVALID_HANDLE_VALUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateDirectoryA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateDirectoryExA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateDirectoryExW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateDirectoryTransactedA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateDirectoryTransactedW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateEventA", func(ctx *ntapi.TrapContext) uint32 {
			h := handles.Alloc(&ntapi.EventHandle{})
			ctx.SetReturn(uint64(h))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateEventExA", func(ctx *ntapi.TrapContext) uint32 {
			h := handles.Alloc(&ntapi.EventHandle{})
			ctx.SetReturn(uint64(h))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateEventExW", func(ctx *ntapi.TrapContext) uint32 {
			h := handles.Alloc(&ntapi.EventHandle{})
			ctx.SetReturn(uint64(h))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateFiber", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x10000) // fake fiber
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateFiberEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x10000) // fake fiber
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateFile2", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0xFFFFFFFFFFFFFFFF) // INVALID_HANDLE_VALUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateFileMappingA", func(ctx *ntapi.TrapContext) uint32 {
			hFile := ntapi.Handle(ctx.Arg(0))
			flProtect := uint32(ctx.Arg(2))
			szHigh := uint32(ctx.Arg(3))
			szLow := uint32(ctx.Arg(4))
			name := readGuestString(ctx.Arg(5))
			h := doCreateFileMapping(ctx, hFile, flProtect, szHigh, szLow, name)
			ctx.SetReturn(h)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateFileMappingFromApp", func(ctx *ntapi.TrapContext) uint32 {
			hFile := ntapi.Handle(ctx.Arg(0))
			flProtect := uint32(ctx.Arg(1))
			size := ctx.Arg(2)
			name := readGuestUTF16(ctx.Arg(3))
			szHigh := uint32(size >> 32)
			szLow := uint32(size)
			h := doCreateFileMapping(ctx, hFile, flProtect, szHigh, szLow, name)
			ctx.SetReturn(h)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateFileMappingNumaW", func(ctx *ntapi.TrapContext) uint32 {
			hFile := ntapi.Handle(ctx.Arg(0))
			flProtect := uint32(ctx.Arg(2))
			szHigh := uint32(ctx.Arg(3))
			szLow := uint32(ctx.Arg(4))
			name := readGuestUTF16(ctx.Arg(5))
			// ctx.Arg(6) = nndPreferred NUMA node (ignored)
			h := doCreateFileMapping(ctx, hFile, flProtect, szHigh, szLow, name)
			ctx.SetReturn(h)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateFileTransactedA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // transacted ops not supported
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateFileTransactedW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // transacted ops not supported
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateHardLinkA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateHardLinkTransactedA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // transacted ops not supported
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateHardLinkTransactedW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // transacted ops not supported
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateHardLinkW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateIoCompletionPort", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x3001) // fake iocp handle
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateJobObjectA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x1001) // fake job handle
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateJobObjectW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x1001) // fake job handle
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateKernelThread", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateMailslotA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0xFFFFFFFFFFFFFFFF) // INVALID_HANDLE_VALUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateMailslotW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0xFFFFFFFFFFFFFFFF) // INVALID_HANDLE_VALUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateMemoryResourceNotification", func(ctx *ntapi.TrapContext) uint32 {
			h := handles.Alloc(&ntapi.GenericHandle{Kind: "memresource"})
			ctx.SetReturn(uint64(h))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateMutexA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x1004) // fake handle
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateMutexExA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x1004)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateMutexExW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x1004)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateNamedPipeA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0xFFFFFFFFFFFFFFFF) // INVALID_HANDLE_VALUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateNamedPipeW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0xFFFFFFFFFFFFFFFF) // INVALID_HANDLE_VALUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreatePipe", func(ctx *ntapi.TrapContext) uint32 {
			hReadPipe := ctx.Arg(0)
			hWritePipe := ctx.Arg(1)
			rfile, wfile, err := os.Pipe()
			if err != nil {
				ctx.SetReturn(0)
				return 0
			}
			rh := uint64(handles.Alloc(&ntapi.FileHandle{FD: int(rfile.Fd()), Path: "pipe:read"}))
			wh := uint64(handles.Alloc(&ntapi.FileHandle{FD: int(wfile.Fd()), Path: "pipe:write"}))
			ctx.Mem.Write64(hReadPipe, rh)
			ctx.Mem.Write64(hWritePipe, wh)
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateProcessA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateProcessAsUserA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateProcessAsUserW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateProcessInternalA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateProcessInternalW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateProcessW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE - not supported
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreatePseudoConsole", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // S_OK
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateRemoteThread", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // NULL
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateRemoteThreadEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // NULL
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateSemaphoreA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x1002) // fake handle
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateSemaphoreExA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x1002) // fake handle
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateSemaphoreExW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x1002) // fake handle
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateSemaphoreW", func(ctx *ntapi.TrapContext) uint32 {
			h := handles.Alloc(&ntapi.GenericHandle{Kind: "semaphore"})
			ctx.SetReturn(uint64(h))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateSocketHandle", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateSymbolicLinkA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateSymbolicLinkW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateTapePartition", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // NO_ERROR
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateThreadpool", func(ctx *ntapi.TrapContext) uint32 {
			h := handles.Alloc(&ntapi.GenericHandle{Kind: "threadpool"})
			ctx.SetReturn(uint64(h))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateThreadpoolCleanupGroup", func(ctx *ntapi.TrapContext) uint32 {
			h := handles.Alloc(&ntapi.GenericHandle{Kind: "tpcleanup"})
			ctx.SetReturn(uint64(h))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateThreadpoolIo", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // NULL
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateThreadpoolTimer", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // NULL
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateThreadpoolWait", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // NULL
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateThreadpoolWork", func(ctx *ntapi.TrapContext) uint32 {
			h := handles.Alloc(&ntapi.GenericHandle{Kind: "threadpoolwork"})
			ctx.SetReturn(uint64(h))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateTimerQueue", func(ctx *ntapi.TrapContext) uint32 {
						h := handles.Alloc(&ntapi.GenericHandle{Kind: "timerqueue"})
			ctx.SetReturn(uint64(h))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateTimerQueueTimer", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateUmsCompletionList", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateUmsThreadContext", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateVirtualBuffer", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateWaitableTimerA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x1003) // fake handle
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateWaitableTimerExA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x1003)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateWaitableTimerExW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x1003)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CreateWaitableTimerW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x1003) // fake handle
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "CtrlRoutine", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "DeactivateActCtx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "DebugActiveProcess", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "DebugActiveProcessStop", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "DebugBreak", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "DebugBreakProcess", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "DebugSetProcessKillOnExit", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "DecodeSystemPointer", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(ctx.Arg(0))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "DefineDosDeviceA", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "DefineDosDeviceW", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "DelayLoadFailureHook", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "DeleteAtom", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // success
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "DeleteFiber", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // no-op
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "DeleteFileA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "DeleteFileTransactedA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // transacted ops not supported
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "DeleteFileTransactedW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // transacted ops not supported
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "DeleteProcThreadAttributeList", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "DeleteSynchronizationBarrier", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "DeleteTimerQueue", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "DeleteTimerQueueEx", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "DeleteTimerQueueTimer", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "DeleteUmsCompletionList", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "DeleteUmsThreadContext", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "DeleteVolumeMountPointA", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "DeleteVolumeMountPointW", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "DequeueUmsCompletionListItems", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "DisableThreadLibraryCalls", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "DisassociateCurrentThreadFromCallback", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // no-op
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "DiscardVirtualMemory", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // S_OK
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "DisconnectNamedPipe", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "DnsHostnameToComputerNameA", func(ctx *ntapi.TrapContext) uint32 {
			name := "RAVEN"
			buf := ctx.Arg(1)
			if buf != 0 {
				for i := 0; i < len(name); i++ { ctx.Mem.Write8(buf+uint64(i), name[i]) }
				ctx.Mem.Write8(buf+uint64(len(name)), 0)
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "DnsHostnameToComputerNameW", func(ctx *ntapi.TrapContext) uint32 {
			name := "RAVEN"
			ws := utf16Encode(name)
			buf := ctx.Arg(1)
			if buf != 0 {
				for i, w := range ws { ctx.Mem.Write16(buf+uint64(i)*2, w) }
				ctx.Mem.Write16(buf+uint64(len(ws))*2, 0)
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "DosDateTimeToFileTime", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "DuplicateConsoleHandle", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(ctx.Arg(0))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "DuplicateHandle", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "EncodeSystemPointer", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(ctx.Arg(0))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "EndUpdateResourceA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "EndUpdateResourceW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "EnterSynchronizationBarrier", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "EnterUmsSchedulingMode", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "EnumCalendarInfoA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "EnumCalendarInfoExA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "EnumCalendarInfoExEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "EnumCalendarInfoExW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "EnumCalendarInfoW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "EnumDateFormatsA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "EnumDateFormatsExA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "EnumDateFormatsExEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "EnumDateFormatsExW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "EnumDateFormatsW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "EnumLanguageGroupLocalesA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "EnumLanguageGroupLocalesW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "EnumResourceLanguagesA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "EnumResourceLanguagesExA", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "EnumResourceLanguagesExW", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "EnumResourceLanguagesW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "EnumResourceNamesA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "EnumResourceNamesExA", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "EnumResourceNamesExW", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "EnumResourceNamesW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "EnumResourceTypesA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "EnumResourceTypesExA", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "EnumResourceTypesExW", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "EnumResourceTypesW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "EnumSystemCodePagesA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "EnumSystemCodePagesW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "EnumSystemFirmwareTables", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // 0
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "EnumSystemGeoID", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "EnumSystemLanguageGroupsA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "EnumSystemLanguageGroupsW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "EnumSystemLocalesA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "EnumSystemLocalesEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "EnumTimeFormatsA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "EnumTimeFormatsEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "EnumTimeFormatsW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "EnumUILanguagesA", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "EnumUILanguagesW", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "EraseTape", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // NO_ERROR
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "EscapeCommFunction", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ExecuteUmsThread", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ExitVDM", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ExpandEnvironmentStringsA", func(ctx *ntapi.TrapContext) uint32 {
			src := readGuestString(ctx.Arg(0))
			dst := ctx.Arg(1)
			maxChars := ctx.Arg(2)
			expanded := os.ExpandEnv(src)
			if dst != 0 && maxChars > 0 {
				data := []byte(expanded)
				if uint64(len(data)) >= maxChars {
					data = data[:maxChars-1]
				}
				ctx.Mem.WriteBytes(dst, append(data, 0))
			}
			ctx.SetReturn(uint64(len(expanded) + 1))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ExpungeConsoleCommandHistoryA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ExpungeConsoleCommandHistoryW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ExtendVirtualBuffer", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FatalAppExitA", func(ctx *ntapi.TrapContext) uint32 {
			msg := readGuestString(ctx.Arg(1))
			ravelog.Logf("[win32] FatalAppExitA: %s\n", msg)
			os.Exit(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FatalAppExitW", func(ctx *ntapi.TrapContext) uint32 {
			msg := readGuestUTF16(ctx.Arg(1))
			ravelog.Logf("[win32] FatalAppExitW: %s\n", msg)
			os.Exit(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FatalExit", func(ctx *ntapi.TrapContext) uint32 {
			ravelog.Logf("[win32] FatalExit(%d)\n", ctx.Arg(0))
			os.Exit(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FileTimeToDosDateTime", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FileTimeToLocalFileTime", func(ctx *ntapi.TrapContext) uint32 {
			src := ctx.Arg(0)
			dst := ctx.Arg(1)
			if src != 0 && dst != 0 { v, _ := ctx.Mem.Read64(src); ctx.Mem.Write64(dst, v) }
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FillConsoleOutputAttribute", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FillConsoleOutputCharacterA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FillConsoleOutputCharacterW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FindActCtxSectionGuid", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FindActCtxSectionStringA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FindActCtxSectionStringW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FindAtomA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0xC000) // fake atom
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FindAtomW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0xC000) // fake atom
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FindCloseChangeNotification", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FindFirstChangeNotificationA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x1234) // fake handle
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FindFirstChangeNotificationW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x1234) // fake handle
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FindFirstFileA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0xFFFFFFFFFFFFFFFF) // INVALID_HANDLE_VALUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FindFirstFileExA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0xFFFFFFFFFFFFFFFF) // INVALID_HANDLE_VALUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FindFirstFileNameW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0xFFFFFFFFFFFFFFFF) // INVALID_HANDLE_VALUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FindFirstFileTransactedA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // transacted ops not supported
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FindFirstFileTransactedW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // transacted ops not supported
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FindFirstStreamW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0xFFFFFFFFFFFFFFFF) // INVALID_HANDLE_VALUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FindFirstVolumeA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0xFFFFFFFFFFFFFFFF) // INVALID_HANDLE_VALUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FindFirstVolumeMountPointA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0xFFFFFFFFFFFFFFFF) // INVALID_HANDLE_VALUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FindFirstVolumeMountPointW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0xFFFFFFFFFFFFFFFF) // INVALID_HANDLE_VALUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FindFirstVolumeW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0xFFFFFFFFFFFFFFFF) // INVALID_HANDLE_VALUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FindNLSString", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // not found
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FindNLSStringEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // not found
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FindNextChangeNotification", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FindNextFileA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FindNextStreamW", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(0xFFFFFFFF) // no more streams
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FindNextVolumeA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FindNextVolumeMountPointA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FindNextVolumeMountPointW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FindNextVolumeW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FindResourceA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // NULL
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FindResourceExA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // NULL
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FindResourceExW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // NULL
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FindStringOrdinal", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // not found
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FindVolumeClose", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FindVolumeMountPointClose", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FlushConsoleInputBuffer", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FlushInstructionCache", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FlushProcessWriteBuffers", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FlushViewOfFile", func(ctx *ntapi.TrapContext) uint32 {
			lpBase := ctx.Arg(0)
			flushSize := ctx.Arg(1)
			for _, vm := range viewMappings {
				if vm.GuestAddr != lpBase {
					continue
				}
				sz := flushSize
				if sz == 0 || sz > vm.Size {
					sz = vm.Size
				}
				if guestData, err := ctx.Mem.ReadBytes(vm.GuestAddr, int(sz)); err == nil {
					copy(vm.HostBuf[:sz], guestData)
					if vm.FileFD >= 0 {
						ctx.FS.Pwrite(vm.FileFD, guestData, int64(vm.Offset))
					}
				}
				break
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FoldStringA", func(ctx *ntapi.TrapContext) uint32 {
			cchSrc := ctx.Arg(3)
			lpSrc := ctx.Arg(2)
			lpDst := ctx.Arg(4)
			if lpDst != 0 && cchSrc > 0 {
				buf, _ := ctx.Mem.ReadBytes(lpSrc, int(cchSrc))
				ctx.Mem.WriteBytes(lpDst, buf)
			}
			ctx.SetReturn(cchSrc)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FoldStringW", func(ctx *ntapi.TrapContext) uint32 {
			cchSrc := ctx.Arg(3)
			lpSrc := ctx.Arg(2)
			lpDst := ctx.Arg(4)
			if lpDst != 0 && cchSrc > 0 {
				buf, _ := ctx.Mem.ReadBytes(lpSrc, int(cchSrc*2))
				ctx.Mem.WriteBytes(lpDst, buf)
			}
			ctx.SetReturn(cchSrc)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FreeConsole", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FreeEnvironmentStringsA", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FreeLibraryWhenCallbackReturns", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // no-op
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FreeResource", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FreeUserPhysicalPages", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FreeVirtualBuffer", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GenerateConsoleCtrlEvent", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetActiveProcessorCount", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(4)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetActiveProcessorGroupCount", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetAtomNameA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetAtomNameW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetBinaryType", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetBinaryTypeA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetBinaryTypeW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetCPInfoExA", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetCPInfoExW", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetCalendarInfoA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetCalendarInfoEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetCalendarInfoW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetCommConfig", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetCommMask", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetCommModemStatus", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetCommProperties", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetCommState", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetCommTimeouts", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetCompressedFileSizeA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0xFFFFFFFF) // not compressed
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetCompressedFileSizeW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0xFFFFFFFF) // not compressed
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetComputerNameA", func(ctx *ntapi.TrapContext) uint32 {
			buf := ctx.Arg(0)
			sizePtr := ctx.Arg(1)
			name := "RAVEN"
			ctx.Mem.WriteBytes(buf, append([]byte(name), 0))
			ctx.Mem.Write32(sizePtr, uint32(len(name)))
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetComputerNameExA", func(ctx *ntapi.TrapContext) uint32 {
			buf := ctx.Arg(1)
			sizePtr := ctx.Arg(2)
			name := "RAVEN"
			ctx.Mem.WriteBytes(buf, append([]byte(name), 0))
			ctx.Mem.Write32(sizePtr, uint32(len(name)))
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetComputerNameExW", func(ctx *ntapi.TrapContext) uint32 {
			buf := ctx.Arg(1)
			sizePtr := ctx.Arg(2)
			name := "RAVEN"
			ws := utf16Encode(name)
			for i, r := range ws {
				ctx.Mem.Write16(buf+uint64(i)*2, r)
			}
			ctx.Mem.Write16(buf+uint64(len(ws))*2, 0)
			ctx.Mem.Write32(sizePtr, uint32(len(name)))
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetConsoleAliasA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetConsoleAliasExesA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetConsoleAliasExesLengthA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetConsoleAliasExesLengthW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetConsoleAliasExesW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetConsoleAliasW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetConsoleAliasesA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetConsoleAliasesLengthA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetConsoleAliasesLengthW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetConsoleAliasesW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetConsoleCharType", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetConsoleCommandHistoryA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetConsoleCommandHistoryLengthA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetConsoleCommandHistoryLengthW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetConsoleCommandHistoryW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetConsoleCursorInfo", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetConsoleCursorMode", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetConsoleDisplayMode", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetConsoleFontInfo", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetConsoleFontSize", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x000C000A) // 10x12 fake
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetConsoleHardwareState", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetConsoleInputExeNameA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetConsoleInputExeNameW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetConsoleInputWaitHandle", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetConsoleKeyboardLayoutNameA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetConsoleKeyboardLayoutNameW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetConsoleNlsMode", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetConsoleOriginalTitleA", func(ctx *ntapi.TrapContext) uint32 {
			buf := ctx.Arg(0)
			if buf != 0 {
				ctx.Mem.WriteBytes(buf, []byte("Raven\x00"))
			}
			ctx.SetReturn(5)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetConsoleOriginalTitleW", func(ctx *ntapi.TrapContext) uint32 {
			buf := ctx.Arg(0)
			if buf != 0 {
				for i, c := range []uint16{'R', 'a', 'v', 'e', 'n', 0} {
					ctx.Mem.Write16(buf+uint64(i)*2, c)
				}
			}
			ctx.SetReturn(5)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetConsoleProcessList", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // 0 processes
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetConsoleScreenBufferInfoEx", func(ctx *ntapi.TrapContext) uint32 {
			pInfo := ctx.Arg(1)
			if pInfo != 0 {
				ctx.Mem.Write32(pInfo+0, 96)  // cbSize = 96
				ctx.Mem.Write16(pInfo+4, 80)  // dwSize.X
				ctx.Mem.Write16(pInfo+6, 25)  // dwSize.Y
				ctx.Mem.Write16(pInfo+8, 0)   // dwCursorPosition.X
				ctx.Mem.Write16(pInfo+10, 0)  // dwCursorPosition.Y
				ctx.Mem.Write16(pInfo+12, 7)  // wAttributes
				ctx.Mem.Write16(pInfo+14, 0)  // srWindow.Left
				ctx.Mem.Write16(pInfo+16, 0)  // srWindow.Top
				ctx.Mem.Write16(pInfo+18, 79) // srWindow.Right
				ctx.Mem.Write16(pInfo+20, 24) // srWindow.Bottom
				ctx.Mem.Write16(pInfo+22, 80) // dwMaximumWindowSize.X
				ctx.Mem.Write16(pInfo+24, 25) // dwMaximumWindowSize.Y
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetConsoleTitleA", func(ctx *ntapi.TrapContext) uint32 {
			buf := ctx.Arg(0)
			if buf != 0 {
				ctx.Mem.WriteBytes(buf, []byte("Raven\x00"))
			}
			ctx.SetReturn(5)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetConsoleTitleW", func(ctx *ntapi.TrapContext) uint32 {
			buf := ctx.Arg(0)
			if buf != 0 {
				for i, c := range []uint16{'R', 'a', 'v', 'e', 'n', 0} {
					ctx.Mem.Write16(buf+uint64(i)*2, c)
				}
			}
			ctx.SetReturn(5)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetCurrencyFormatA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetCurrencyFormatEx", func(ctx *ntapi.TrapContext) uint32 {
			// lpLocaleName, dwFlags, lpValue, lpFormat, lpCurrencyStr, cchCurrency
			lpValue := ctx.Arg(2)
			lpOut := ctx.Arg(4)
			cch := ctx.Arg(5)
			if lpValue == 0 || lpOut == 0 || cch == 0 { ctx.SetReturn(0); return 0 }
			s := readGuestUTF16(lpValue)
			ws := utf16Encode(s)
			n := uint64(len(ws) + 1); if n > cch { n = cch }
			for i := uint64(0); i+1 < n; i++ { ctx.Mem.Write16(lpOut+i*2, ws[i]) }
			ctx.Mem.Write16(lpOut+(n-1)*2, 0)
			ctx.SetReturn(n)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetCurrencyFormatW", func(ctx *ntapi.TrapContext) uint32 {
			lpValue := ctx.Arg(2)
			lpOut := ctx.Arg(4)
			cch := ctx.Arg(5)
			if lpValue == 0 || lpOut == 0 || cch == 0 { ctx.SetReturn(0); return 0 }
			s := readGuestUTF16(lpValue)
			ws := utf16Encode(s)
			n := uint64(len(ws) + 1); if n > cch { n = cch }
			for i := uint64(0); i+1 < n; i++ { ctx.Mem.Write16(lpOut+i*2, ws[i]) }
			ctx.Mem.Write16(lpOut+(n-1)*2, 0)
			ctx.SetReturn(n)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetCurrentActCtx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetCurrentApplicationUserModelId", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x3D54) // APPMODEL_ERROR_NO_PACKAGE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetCurrentConsoleFont", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetCurrentConsoleFontEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetCurrentDirectoryA", func(ctx *ntapi.TrapContext) uint32 {
			buf := ctx.Arg(0)
			path := "C:\\"
			ctx.Mem.WriteBytes(buf, append([]byte(path), 0))
			ctx.SetReturn(uint64(len(path)))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetCurrentPackageFamilyName", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x3D54) // APPMODEL_ERROR_NO_PACKAGE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetCurrentPackageFullName", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(15700) // APPMODEL_ERROR_NO_PACKAGE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetCurrentPackageId", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(15700) // APPMODEL_ERROR_NO_PACKAGE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetCurrentPackageInfo", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x3D54) // APPMODEL_ERROR_NO_PACKAGE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetCurrentPackagePath", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(15700) // APPMODEL_ERROR_NO_PACKAGE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetCurrentProcessorNumber", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetCurrentProcessorNumberEx", func(ctx *ntapi.TrapContext) uint32 {
						if ctx.Arg(0) != 0 { ctx.Mem.Write64(ctx.Arg(0), 0) }
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetCurrentThread", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0xFFFFFFFFFFFFFFFE) // pseudo-handle
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetCurrentThreadStackLimits", func(ctx *ntapi.TrapContext) uint32 {
						if ctx.Arg(0) != 0 { ctx.Mem.Write64(ctx.Arg(0), 0x10000) }
			if ctx.Arg(1) != 0 { ctx.Mem.Write64(ctx.Arg(1), 0x800000) }
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetCurrentUmsThread", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // NULL
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetDateFormatA", func(ctx *ntapi.TrapContext) uint32 {
			buf := ctx.Arg(4)
			s := "03/09/2026"
			if buf != 0 {
				for i := 0; i < len(s); i++ { ctx.Mem.Write8(buf+uint64(i), s[i]) }
				ctx.Mem.Write8(buf+uint64(len(s)), 0)
			}
			ctx.SetReturn(11)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetDaylightFlag", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetDefaultCommConfigA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetDefaultCommConfigW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetDefaultSortkeySize", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetDevicePowerState", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetDiskFreeSpaceA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetDiskFreeSpaceW", func(ctx *ntapi.TrapContext) uint32 {
						// Report 100 GB free on a 200 GB disk
			if ctx.Arg(1) != 0 { ctx.Mem.Write32(ctx.Arg(1), 8) }
			if ctx.Arg(2) != 0 { ctx.Mem.Write32(ctx.Arg(2), 512) }
			if ctx.Arg(3) != 0 { ctx.Mem.Write32(ctx.Arg(3), 25600000) }
			if ctx.Arg(4) != 0 { ctx.Mem.Write32(ctx.Arg(4), 51200000) }
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetDiskSpaceInformationA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetDiskSpaceInformationW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetDllDirectoryA", func(ctx *ntapi.TrapContext) uint32 {
			if ctx.Arg(1) != 0 { ctx.Mem.Write8(ctx.Arg(1), 0) }
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetDllDirectoryW", func(ctx *ntapi.TrapContext) uint32 {
			if ctx.Arg(1) != 0 { ctx.Mem.Write16(ctx.Arg(1), 0) }
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetDriveTypeW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(3) // DRIVE_FIXED
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetDynamicTimeZoneInformation", func(ctx *ntapi.TrapContext) uint32 {
			buf := ctx.Arg(0)
			if buf != 0 {
				zeros := make([]byte, 172)
				ctx.Mem.WriteBytes(buf, zeros)
			}
			ctx.SetReturn(0) // TIME_ZONE_ID_UNKNOWN
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetDynamicTimeZoneInformationEffectiveYears", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetEnabledXStateFeatures", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // 0
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetEnvironmentStrings", func(ctx *ntapi.TrapContext) uint32 {
			block := []byte("PATH=\x00\x00")
			buf := mem.Mmap(0, uint64(len(block)), mmu.PermRead|mmu.PermWrite)
			ctx.Mem.WriteBytes(buf, block)
			ctx.SetReturn(buf)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetEnvironmentStringsA", func(ctx *ntapi.TrapContext) uint32 {
			block := []byte("PATH=\x00\x00")
			buf := mem.Mmap(0, uint64(len(block)), mmu.PermRead|mmu.PermWrite)
			ctx.Mem.WriteBytes(buf, block)
			ctx.SetReturn(buf)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetEnvironmentVariableW", func(ctx *ntapi.TrapContext) uint32 {
			name := readGuestUTF16(ctx.Arg(0))
			buf := ctx.Arg(1)
			size := ctx.Arg(2)
			var val string
			if v, ok := envVars[name]; ok {
				val = v
			} else {
				val = os.Getenv(name)
			}
			if val == "" {
				ctx.Mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 203) // ERROR_ENVVAR_NOT_FOUND
				ctx.SetReturn(0)
				return 0
			}
			ws := utf16Encode(val)
			needed := uint64(len(ws) + 1)
			if buf == 0 || size == 0 {
				ctx.SetReturn(needed)
				return 0
			}
			if needed > size {
				ctx.SetReturn(needed)
				return 0
			}
			for i, w := range ws { ctx.Mem.Write16(buf+uint64(i)*2, w) }
			ctx.Mem.Write16(buf+uint64(len(ws))*2, 0)
			ctx.SetReturn(uint64(len(ws)))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetExitCodeProcess", func(ctx *ntapi.TrapContext) uint32 {
			lpExitCode := ctx.Arg(1)
			if lpExitCode != 0 { ctx.Mem.Write32(lpExitCode, 259) } // STILL_ACTIVE
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetExitCodeThread", func(ctx *ntapi.TrapContext) uint32 {
			lpExitCode := ctx.Arg(1)
			if lpExitCode != 0 { ctx.Mem.Write32(lpExitCode, 259) } // STILL_ACTIVE
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetExpandedNameA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0xFFFFFFFFFFFFFFFF) // LZERROR_BADINHANDLE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetExpandedNameW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0xFFFFFFFFFFFFFFFF) // LZERROR_BADINHANDLE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetFileAttributesExA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetFileAttributesTransactedA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // transacted ops not supported
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetFileAttributesTransactedW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // transacted ops not supported
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetFileInformationByHandle", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetFileInformationByHandleEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetFileMUIInfo", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetFileMUIPath", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetFileSize", func(ctx *ntapi.TrapContext) uint32 {
			hFile := ntapi.Handle(ctx.Arg(0))
			lpFileSizeHigh := ctx.Arg(1)
			obj := handles.Get(hFile)
			fh, ok := obj.(*ntapi.FileHandle)
			if !ok { ctx.SetReturn(0xFFFFFFFF); return 0 }
			node := ctx.FS.Stat(fh.FD)
			if node == nil { ctx.SetReturn(0xFFFFFFFF); return 0 }
			sz := node.Size
			if lpFileSizeHigh != 0 { ctx.Mem.Write32(lpFileSizeHigh, uint32(sz>>32)) }
			ctx.SetReturn(uint64(uint32(sz)))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetFileTime", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetFinalPathNameByHandleA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // error
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetFinalPathNameByHandleW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetFirmwareEnvironmentVariableA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetFirmwareEnvironmentVariableW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetFirmwareType", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FirmwareTypeUnknown
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetFullPathNameA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // error
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetGeoInfoA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetGeoInfoEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetGeoInfoW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetHandleContext", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetHandleInformation", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetLargePageMinimum", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // 0 - no large pages
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetLargestConsoleWindowSize", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(uint64(80 | (25 << 16)))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetLinguistLangSize", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetLogicalDriveStringsW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(4) // 4 chars for C:\
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetLogicalDrives", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(4) // C: only
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetLogicalProcessorInformation", func(ctx *ntapi.TrapContext) uint32 {
			retLen := ctx.Arg(1)
			if retLen != 0 {
				ctx.Mem.Write32(retLen, 0)
			}
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetLogicalProcessorInformationEx", func(ctx *ntapi.TrapContext) uint32 {
			retLen := ctx.Arg(1)
			if retLen != 0 {
				ctx.Mem.Write32(retLen, 0)
			}
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetLongPathNameA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // error
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetMailslotInfo", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetMaximumProcessorCount", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(4)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetMaximumProcessorGroupCount", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetModuleHandleExA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetNLSVersion", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetNLSVersionEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetNamedPipeClientProcessId", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetNamedPipeClientSessionId", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetNamedPipeHandleStateA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetNamedPipeHandleStateW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetNamedPipeInfo", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetNamedPipeServerProcessId", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetNamedPipeServerSessionId", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetNextUmsListItem", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // NULL
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetNextVDMCommand", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetNlsSectionName", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetNumaAvailableMemoryNode", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetNumaAvailableMemoryNodeEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetNumaHighestNodeNumber", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetNumaNodeProcessorMask", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetNumaNodeProcessorMaskEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetNumaProcessorNode", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetNumaProcessorNodeEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetNumaProximityNode", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetNumaProximityNodeEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetNumberFormatA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetNumberFormatEx", func(ctx *ntapi.TrapContext) uint32 {
			lpValue := ctx.Arg(2)
			lpOut := ctx.Arg(4)
			cch := ctx.Arg(5)
			if lpValue == 0 || lpOut == 0 || cch == 0 { ctx.SetReturn(0); return 0 }
			s := readGuestUTF16(lpValue)
			ws := utf16Encode(s)
			n := uint64(len(ws) + 1); if n > cch { n = cch }
			for i := uint64(0); i+1 < n; i++ { ctx.Mem.Write16(lpOut+i*2, ws[i]) }
			ctx.Mem.Write16(lpOut+(n-1)*2, 0)
			ctx.SetReturn(n)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetNumberFormatW", func(ctx *ntapi.TrapContext) uint32 {
			lpValue := ctx.Arg(2)
			lpOut := ctx.Arg(4)
			cch := ctx.Arg(5)
			if lpValue == 0 || lpOut == 0 || cch == 0 { ctx.SetReturn(0); return 0 }
			s := readGuestUTF16(lpValue)
			ws := utf16Encode(s)
			n := uint64(len(ws) + 1); if n > cch { n = cch }
			for i := uint64(0); i+1 < n; i++ { ctx.Mem.Write16(lpOut+i*2, ws[i]) }
			ctx.Mem.Write16(lpOut+(n-1)*2, 0)
			ctx.SetReturn(n)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetNumberOfConsoleFonts", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetNumberOfConsoleInputEvents", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetNumberOfConsoleMouseButtons", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetOverlappedResult", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetOverlappedResultEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetPackageFamilyName", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(15700) // APPMODEL_ERROR_NO_PACKAGE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetPackageFullName", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(15700) // APPMODEL_ERROR_NO_PACKAGE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetPackagePathByFullName", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x3D54) // APPMODEL_ERROR_NO_PACKAGE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetPackagesByPackageFamily", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x3D54) // APPMODEL_ERROR_NO_PACKAGE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetPhysicallyInstalledSystemMemory", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetPriorityClass", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x20) // NORMAL_PRIORITY_CLASS
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetPrivateProfileIntA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(ctx.Arg(3)) // return nDefault
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetPrivateProfileIntW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(ctx.Arg(3)) // return nDefault
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetPrivateProfileSectionA", func(ctx *ntapi.TrapContext) uint32 {
			if buf := ctx.Arg(2); buf != 0 { ctx.Mem.Write16(buf, 0) }
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetPrivateProfileSectionNamesA", func(ctx *ntapi.TrapContext) uint32 {
						if ctx.Arg(0) != 0 { ctx.Mem.Write8(ctx.Arg(0), 0) }
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetPrivateProfileSectionNamesW", func(ctx *ntapi.TrapContext) uint32 {
						if ctx.Arg(0) != 0 { ctx.Mem.Write16(ctx.Arg(0), 0) }
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetPrivateProfileSectionW", func(ctx *ntapi.TrapContext) uint32 {
			if buf := ctx.Arg(2); buf != 0 { ctx.Mem.Write16(buf, 0) }
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetPrivateProfileStringA", func(ctx *ntapi.TrapContext) uint32 {
			s := readGuestString(ctx.Arg(3))
			if buf := ctx.Arg(4); buf != 0 {
				for i := 0; i < len(s); i++ { ctx.Mem.Write8(buf+uint64(i), s[i]) }
				ctx.Mem.Write8(buf+uint64(len(s)), 0)
			}
			ctx.SetReturn(uint64(len(s)))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetPrivateProfileStringW", func(ctx *ntapi.TrapContext) uint32 {
			s := readGuestUTF16(ctx.Arg(3))
			ws := utf16Encode(s)
			buf := ctx.Arg(4)
			maxChars := ctx.Arg(5)
			if buf != 0 && maxChars > 0 {
				n := uint64(len(ws))
				if n >= maxChars { n = maxChars - 1 }
				for i := uint64(0); i < n; i++ { ctx.Mem.Write16(buf+i*2, ws[i]) }
				ctx.Mem.Write16(buf+n*2, 0)
				ctx.SetReturn(n)
			} else {
				ctx.SetReturn(uint64(len(ws)))
			}
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetPrivateProfileStructA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetPrivateProfileStructW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetProcessAffinityMask", func(ctx *ntapi.TrapContext) uint32 {
			lpProcessAffinityMask := ctx.Arg(1)
			lpSystemAffinityMask := ctx.Arg(2)
			if lpProcessAffinityMask != 0 { ctx.Mem.Write64(lpProcessAffinityMask, 0xF) }
			if lpSystemAffinityMask != 0 { ctx.Mem.Write64(lpSystemAffinityMask, 0xF) }
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetProcessDEPPolicy", func(ctx *ntapi.TrapContext) uint32 {
			lpFlags := ctx.Arg(1)
			lpPermanent := ctx.Arg(2)
			if lpFlags != 0 {
				ctx.Mem.Write32(lpFlags, 0)
			}
			if lpPermanent != 0 {
				ctx.Mem.Write32(lpPermanent, 0)
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetProcessFlags", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetProcessGroupAffinity", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetProcessHandleCount", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetProcessHeaps", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // 1 heap
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetProcessId", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // PID=1
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetProcessIdOfThread", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetProcessInformation", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetProcessIoCounters", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetProcessMitigationPolicy", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetProcessPreferredUILanguages", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetProcessPriorityBoost", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetProcessShutdownParameters", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetProcessTimes", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetProcessVersion", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // 0
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetProcessWorkingSetSize", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetProcessWorkingSetSizeEx", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetProductInfo", func(ctx *ntapi.TrapContext) uint32 {
			pdwReturnedProductType := ctx.Arg(3)
			if pdwReturnedProductType != 0 {
				ctx.Mem.Write32(pdwReturnedProductType, 0x30) // PRODUCT_PROFESSIONAL
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetProductName", func(ctx *ntapi.TrapContext) uint32 {
			buf := ctx.Arg(0)
			if buf != 0 {
				s := "Windows"
				for i := 0; i < len(s); i++ { ctx.Mem.Write8(buf+uint64(i), s[i]) }
				ctx.Mem.Write8(buf+uint64(len(s)), 0)
			}
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetProfileIntA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetProfileIntW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetProfileSectionA", func(ctx *ntapi.TrapContext) uint32 {
						if ctx.Arg(1) != 0 { ctx.Mem.Write8(ctx.Arg(1), 0) }
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetProfileSectionW", func(ctx *ntapi.TrapContext) uint32 {
						if ctx.Arg(1) != 0 { ctx.Mem.Write16(ctx.Arg(1), 0) }
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetProfileStringA", func(ctx *ntapi.TrapContext) uint32 {
			def := readGuestString(ctx.Arg(3))
			if buf := ctx.Arg(4); buf != 0 {
				for i := 0; i < len(def); i++ { ctx.Mem.Write8(buf+uint64(i), def[i]) }
				ctx.Mem.Write8(buf+uint64(len(def)), 0)
			}
			ctx.SetReturn(uint64(len(def)))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetProfileStringW", func(ctx *ntapi.TrapContext) uint32 {
			def := readGuestUTF16(ctx.Arg(3))
			ws := utf16Encode(def)
			buf, maxChars := ctx.Arg(4), ctx.Arg(5)
			if buf != 0 && maxChars > 0 {
				n := uint64(len(ws)); if n >= maxChars { n = maxChars - 1 }
				for i := uint64(0); i < n; i++ { ctx.Mem.Write16(buf+i*2, ws[i]) }
				ctx.Mem.Write16(buf+n*2, 0)
				ctx.SetReturn(n)
			} else { ctx.SetReturn(uint64(len(ws))) }
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetQueuedCompletionStatus", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE - timeout
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetQueuedCompletionStatusEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetShortPathNameA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // error
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetShortPathNameW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // error
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetStringTypeA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetSystemCpuSetInformation", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetSystemDEPPolicy", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(3) // EDEP_OptOut
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetSystemDefaultLCID", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x0409)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetSystemDefaultLangID", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x0409) // English US
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetSystemDefaultLocaleName", func(ctx *ntapi.TrapContext) uint32 {
			buf := ctx.Arg(0)
			cch := ctx.Arg(1)
			ws := utf16Encode("en-US")
			n := uint64(len(ws) + 1)
			if buf != 0 && cch > 0 {
				if n > cch { n = cch }
				for i, w := range ws { if uint64(i) < n-1 { ctx.Mem.Write16(buf+uint64(i)*2, w) } }
				ctx.Mem.Write16(buf+(n-1)*2, 0)
			}
			ctx.SetReturn(n)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetSystemDefaultUILanguage", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x0409)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetSystemDirectoryA", func(ctx *ntapi.TrapContext) uint32 {
			buf := ctx.Arg(0)
			path := "C:\\Windows\\System32"
			ctx.Mem.WriteBytes(buf, append([]byte(path), 0))
			ctx.SetReturn(uint64(len(path)))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetSystemDirectoryW", func(ctx *ntapi.TrapContext) uint32 {
			buf := ctx.Arg(0)
			path := "C:\\Windows\\System32"
			for i, r := range utf16Encode(path) {
				ctx.Mem.Write16(buf+uint64(i)*2, r)
			}
			ctx.Mem.Write16(buf+uint64(len(path))*2, 0)
			ctx.SetReturn(uint64(len(path)))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetSystemFileCacheSize", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetSystemFirmwareTable", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // 0
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetSystemPowerStatus", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetSystemPreferredUILanguages", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetSystemRegistryQuota", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetSystemTime", func(ctx *ntapi.TrapContext) uint32 {
			st := ctx.Arg(0)
			if st == 0 { return 0 }
			now := time.Now().UTC()
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
		d.RegisterAutoStubHandler(kernel32, "GetSystemTimeAdjustment", func(ctx *ntapi.TrapContext) uint32 {
			adj := ctx.Arg(0)
			inc := ctx.Arg(1)
			disabled := ctx.Arg(2)
			if adj != 0 {
				ctx.Mem.Write32(adj, 156250)
			}
			if inc != 0 {
				ctx.Mem.Write32(inc, 156250)
			}
			if disabled != 0 {
				ctx.Mem.Write32(disabled, 0)
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetSystemTimePreciseAsFileTime", func(ctx *ntapi.TrapContext) uint32 {
			ft := ctx.Arg(0)
			if ft != 0 {
				const epochDiff = uint64(11644473600) * 10000000
				v := uint64(time.Now().UnixNano()/100) + epochDiff
				ctx.Mem.Write64Raw(ft, v)
			}
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetSystemTimes", func(ctx *ntapi.TrapContext) uint32 {
			idle := ctx.Arg(0)
			kernel := ctx.Arg(1)
			user := ctx.Arg(2)
			if idle != 0 {
				ctx.Mem.Write64(idle, 0)
			}
			if kernel != 0 {
				ctx.Mem.Write64(kernel, 0)
			}
			if user != 0 {
				ctx.Mem.Write64(user, 0)
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetSystemWindowsDirectoryA", func(ctx *ntapi.TrapContext) uint32 {
			buf := ctx.Arg(0)
			path := "C:\\Windows"
			ctx.Mem.WriteBytes(buf, append([]byte(path), 0))
			ctx.SetReturn(uint64(len(path)))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetSystemWindowsDirectoryW", func(ctx *ntapi.TrapContext) uint32 {
			buf := ctx.Arg(0)
			path := "C:\\Windows"
			for i, r := range utf16Encode(path) {
				ctx.Mem.Write16(buf+uint64(i)*2, r)
			}
			ctx.Mem.Write16(buf+uint64(len(path))*2, 0)
			ctx.SetReturn(uint64(len(path)))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetSystemWow64DirectoryA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetSystemWow64DirectoryW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetTapeParameters", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // error
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetTapePosition", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // error
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetTapeStatus", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // NO_ERROR
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetTempFileNameA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // error
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetTempFileNameW", func(ctx *ntapi.TrapContext) uint32 {
			lpTempFileName := ctx.Arg(3)
			uUnique := ctx.Arg(2)
			prefix := readGuestUTF16(ctx.Arg(1))
			if len(prefix) > 3 { prefix = prefix[:3] }
			uniqueN := uUnique; if uniqueN == 0 { uniqueN = uint64(time.Now().UnixNano() & 0xFFFF) }
			name := fmt.Sprintf("C:\\Windows\\Temp\\%s%04X.tmp", prefix, uniqueN)
			if lpTempFileName != 0 {
				ws := utf16Encode(name)
				for i, w := range ws { ctx.Mem.Write16(lpTempFileName+uint64(i)*2, w) }
				ctx.Mem.Write16(lpTempFileName+uint64(len(ws))*2, 0)
			}
			ctx.SetReturn(uniqueN)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetTempPath2A", func(ctx *ntapi.TrapContext) uint32 {
			s := "C:\\Temp\\"
			if buf := ctx.Arg(1); buf != 0 {
				for i := 0; i < len(s); i++ { ctx.Mem.Write8(buf+uint64(i), s[i]) }
				ctx.Mem.Write8(buf+uint64(len(s)), 0)
			}
			ctx.SetReturn(uint64(len(s)))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetTempPath2W", func(ctx *ntapi.TrapContext) uint32 {
			buf := ctx.Arg(1)
			s := `C:\Windows\Temp\`
			ws := utf16Encode(s)
			if buf != 0 { for i, w := range ws { ctx.Mem.Write16(buf+uint64(i)*2, w) }; ctx.Mem.Write16(buf+uint64(len(ws))*2, 0) }
			ctx.SetReturn(uint64(len(ws)))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetTempPathA", func(ctx *ntapi.TrapContext) uint32 {
			buf := ctx.Arg(1)
			s := `C:\Windows\Temp\`
			if buf != 0 { for i := 0; i < len(s); i++ { ctx.Mem.Write8(buf+uint64(i), s[i]) }; ctx.Mem.Write8(buf+uint64(len(s)), 0) }
			ctx.SetReturn(uint64(len(s)))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetThreadContext", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetThreadDescription", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // S_OK stub
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetThreadErrorMode", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetThreadGroupAffinity", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetThreadIOPendingFlag", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetThreadId", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TID=1
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetThreadIdealProcessorEx", func(ctx *ntapi.TrapContext) uint32 {
						if ctx.Arg(1) != 0 { ctx.Mem.Write64(ctx.Arg(1), 0) }
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetThreadLocale", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x0409)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetThreadPreferredUILanguages", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetThreadPriority", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // THREAD_PRIORITY_NORMAL
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetThreadPriorityBoost", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetThreadSelectorEntry", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetThreadTimes", func(ctx *ntapi.TrapContext) uint32 {
			for i := int(1); i <= 4; i++ {
				p := ctx.Arg(i)
				if p != 0 {
					ctx.Mem.Write64(p, 0)
				}
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetThreadUILanguage", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x0409)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetTickCount64", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(uint64(time.Since(startTime).Milliseconds()))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetTimeFormatA", func(ctx *ntapi.TrapContext) uint32 {
			buf := ctx.Arg(4)
			s := "12:00:00"
			if buf != 0 {
				for i := 0; i < len(s); i++ { ctx.Mem.Write8(buf+uint64(i), s[i]) }
				ctx.Mem.Write8(buf+uint64(len(s)), 0)
			}
			ctx.SetReturn(9)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetTimeZoneInformationForYear", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetUmsCompletionListEvent", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetUserDefaultGeoName", func(ctx *ntapi.TrapContext) uint32 {
			buf := ctx.Arg(0)
			ws := utf16Encode("US")
			if buf != 0 {
				for i, w := range ws { ctx.Mem.Write16(buf+uint64(i)*2, w) }
				ctx.Mem.Write16(buf+uint64(len(ws))*2, 0)
			}
			ctx.SetReturn(2)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetUserDefaultLangID", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x0409) // English US
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetUserDefaultLocaleName", func(ctx *ntapi.TrapContext) uint32 {
			buf := ctx.Arg(0)
			cch := ctx.Arg(1)
			ws := utf16Encode("en-US")
			n := uint64(len(ws) + 1)
			if buf != 0 && cch > 0 {
				if n > cch { n = cch }
				for i, w := range ws { if uint64(i) < n-1 { ctx.Mem.Write16(buf+uint64(i)*2, w) } }
				ctx.Mem.Write16(buf+(n-1)*2, 0)
			}
			ctx.SetReturn(n)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetUserDefaultUILanguage", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x0409)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetUserGeoID", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // GEOCLASS_NATION
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetUserPreferredUILanguages", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetVDMCurrentDirectories", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetVolumeInformationA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetVolumeInformationByHandleW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetVolumeInformationW", func(ctx *ntapi.TrapContext) uint32 {
			// lpRootPathName=0, lpVolumeNameBuf=1, nVolNameSize=2,
			// lpSerialNum=3, lpMaxComponentLen=4, lpFSFlags=5, lpFSNameBuf=6, nFSNameSize=7
			volNameBuf := ctx.Arg(1)
			volNameSize := ctx.Arg(2)
			lpSerialNum := ctx.Arg(3)
			lpMaxComponentLen := ctx.Arg(4)
			lpFSFlags := ctx.Arg(5)
			fsBuf := ctx.Arg(6)
			fsBufSize := ctx.Arg(7)
			if volNameBuf != 0 && volNameSize > 0 {
				for i, r := range []rune("Windows") {
					if uint64(i) >= volNameSize-1 { break }
					ctx.Mem.Write16(volNameBuf+uint64(i)*2, uint16(r))
				}
				ctx.Mem.Write16(volNameBuf+uint64(len("Windows"))*2, 0)
			}
			if lpSerialNum != 0 { ctx.Mem.Write32(lpSerialNum, 0xDEADBEEF) }
			if lpMaxComponentLen != 0 { ctx.Mem.Write32(lpMaxComponentLen, 255) }
			if lpFSFlags != 0 { ctx.Mem.Write32(lpFSFlags, 0x00020003) }
			if fsBuf != 0 && fsBufSize > 0 {
				for i, r := range []rune("NTFS") {
					if uint64(i) >= fsBufSize-1 { break }
					ctx.Mem.Write16(fsBuf+uint64(i)*2, uint16(r))
				}
				ctx.Mem.Write16(fsBuf+uint64(len("NTFS"))*2, 0)
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetVolumeNameForVolumeMountPointA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetVolumeNameForVolumeMountPointW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetVolumePathNameA", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetVolumePathNameW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetVolumePathNamesForVolumeNameA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetVolumePathNamesForVolumeNameW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetWindowsDirectoryA", func(ctx *ntapi.TrapContext) uint32 {
			buf := ctx.Arg(0)
			path := "C:\\Windows"
			ctx.Mem.WriteBytes(buf, append([]byte(path), 0))
			ctx.SetReturn(uint64(len(path)))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetWindowsDirectoryW", func(ctx *ntapi.TrapContext) uint32 {
			buf := ctx.Arg(0)
			path := "C:\\Windows"
			for i, r := range utf16Encode(path) {
				ctx.Mem.Write16(buf+uint64(i)*2, r)
			}
			ctx.Mem.Write16(buf+uint64(len(path))*2, 0)
			ctx.SetReturn(uint64(len(path)))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetWriteWatch", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GetXStateFeaturesMask", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GlobalAddAtomA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0xC001) // fake global atom
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GlobalAddAtomW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0xC001) // fake global atom
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GlobalCompact", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GlobalDeleteAtom", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // success
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GlobalFindAtomA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0xC001)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GlobalFindAtomW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0xC001)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GlobalFix", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GlobalFlags", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GlobalGetAtomNameA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GlobalGetAtomNameW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GlobalHandle", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GlobalMemoryStatus", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // no-op
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GlobalReAlloc", func(ctx *ntapi.TrapContext) uint32 {
			hMem := ctx.Arg(0)
			dwBytes := ctx.Arg(1)
			if dwBytes == 0 {
				dwBytes = 1
			}
			newPtr := mem.Mmap(0, dwBytes, mmu.PermRead|mmu.PermWrite)
			if hMem != 0 {
				old, _ := ctx.Mem.ReadBytes(hMem, int(dwBytes))
				if len(old) > 0 {
					ctx.Mem.WriteBytes(newPtr, old)
				}
			}
			ctx.SetReturn(newPtr)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GlobalUnWire", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GlobalUnfix", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "GlobalWire", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "Heap32First", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "Heap32ListFirst", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "Heap32ListNext", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "Heap32Next", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "HeapCompact", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // 0
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "HeapCreateTagsW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "HeapExtend", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "HeapLock", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "HeapQueryInformation", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "HeapQueryTagW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "HeapSetFlags", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "HeapSetInformation", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "HeapSummary", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "HeapUnlock", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "HeapUsage", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "HeapValidate", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "HeapWalk", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE - end of heap
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "IdnToAscii", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // error
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "IdnToNameprepUnicode", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // error
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "IdnToUnicode", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // error
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "InitAtomTable", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "InitOnceExecuteOnce", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "InitOnceInitialize", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // no-op
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "InitializeConditionVariable", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // no-op
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "InitializeContext", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "InitializeContext2", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "InitializeCriticalSection", func(ctx *ntapi.TrapContext) uint32 {
			lp := ctx.Arg(0)
			ctx.Mem.Write64(lp, 0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "InitializeProcThreadAttributeList", func(ctx *ntapi.TrapContext) uint32 {
			lpAttr := ctx.Arg(0)
			lpSize := ctx.Arg(3)
			if lpAttr == 0 && lpSize != 0 { ctx.Mem.Write64(lpSize, 64) }
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "InitializeSRWLock", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // no-op
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "InitializeSynchronizationBarrier", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "InterlockedFlushSList", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // NULL
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "InterlockedPopEntrySList", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // NULL
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "InterlockedPushEntrySList", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // NULL
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "InterlockedPushListSList", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // NULL
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "InterlockedPushListSListEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // NULL
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "InvalidateConsoleDIBits", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "InvalidateNLSCache", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "IsBadCodePtr", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "IsBadHugeReadPtr", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "IsBadHugeWritePtr", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "IsBadReadPtr", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "IsBadStringPtrA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "IsBadStringPtrW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "IsBadWritePtr", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "IsDBCSLeadByte", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "IsDBCSLeadByteEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "IsNLSDefinedString", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "IsNormalizedString", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "IsProcessInJob", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "IsSystemResumeAutomatic", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "IsThreadAFiber", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "IsThreadpoolTimerSet", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "IsValidLanguageGroup", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "IsValidLocaleName", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE - always valid
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "IsValidNLSVersion", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "IsWow64Process2", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "K32EmptyWorkingSet", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "K32EnumDeviceDrivers", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "K32EnumPageFilesA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "K32EnumPageFilesW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "K32EnumProcessModules", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "K32EnumProcessModulesEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "K32EnumProcesses", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "K32GetDeviceDriverBaseNameA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "K32GetDeviceDriverBaseNameW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "K32GetDeviceDriverFileNameA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "K32GetDeviceDriverFileNameW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "K32GetMappedFileNameA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "K32GetMappedFileNameW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "K32GetModuleBaseNameA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "K32GetModuleBaseNameW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "K32GetModuleFileNameExA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "K32GetModuleFileNameExW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "K32GetModuleInformation", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "K32GetPerformanceInfo", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "K32GetProcessImageFileNameA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "K32GetProcessImageFileNameW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "K32GetProcessMemoryInfo", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "K32GetWsChanges", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "K32GetWsChangesEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "K32InitializeProcessForWsWatch", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "K32QueryWorkingSet", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "K32QueryWorkingSetEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "LCIDToLocaleName", func(ctx *ntapi.TrapContext) uint32 {
			buf := ctx.Arg(1)
			cch := ctx.Arg(2)
			ws := utf16Encode("en-US")
			n := uint64(len(ws) + 1)
			if buf != 0 && cch > 0 {
				if n > cch { n = cch }
				for i, w := range ws { if uint64(i) < n-1 { ctx.Mem.Write16(buf+uint64(i)*2, w) } }
				ctx.Mem.Write16(buf+(n-1)*2, 0)
			}
			ctx.SetReturn(n - 1) // returns char count without null
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "LZClose", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "LZCopy", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "LZDone", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "LZInit", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "LZOpenFileA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "LZOpenFileW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "LZRead", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "LZSeek", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "LZStart", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "LeaveCriticalSectionWhenCallbackReturns", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "LoadAppInitDlls", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "LoadLibraryExA", func(ctx *ntapi.TrapContext) uint32 {
			namePtr := ctx.Arg(0)
			if namePtr == 0 {
				ctx.SetReturn(0)
				return 0
			}
			name := strings.ToLower(readGuestString(namePtr))
			if idx := strings.LastIndexAny(name, "/\\"); idx >= 0 { name = name[idx+1:] }
			if !strings.HasSuffix(name, ".dll") {
				name += ".dll"
			}
			if synth, ok := synthByName[name]; ok {
				ctx.SetReturn(synth.BaseAddr)
				return 0
			}
			newSynth := ntapi.GenerateSynthDLL(mem, name, []string{}, 0)
			synthByName[name] = newSynth
			ravelog.Logf("[win32] LoadLibraryExA: auto-created stub for %q\n", name)
			ctx.SetReturn(newSynth.BaseAddr)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "LoadModule", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(2) // ERROR_FILE_NOT_FOUND
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "LoadPackagedLibrary", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // NULL
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "LocalCompact", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "LocalFileTimeToFileTime", func(ctx *ntapi.TrapContext) uint32 {
			src := ctx.Arg(0)
			dst := ctx.Arg(1)
			if src != 0 && dst != 0 { v, _ := ctx.Mem.Read64(src); ctx.Mem.Write64(dst, v) }
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "LocalFlags", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "LocalHandle", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "LocalLock", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(ctx.Arg(0)) // return pointer itself (LMEM_FIXED)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "LocalReAlloc", func(ctx *ntapi.TrapContext) uint32 {
			// hMem=Arg(0), uBytes=Arg(1), uFlags=Arg(2)
			size := ctx.Arg(1)
			if size == 0 { size = 1 }
			addr := mem.Mmap(0, size, mmu.PermRead|mmu.PermWrite)
			ctx.SetReturn(addr)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "LocalShrink", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "LocalSize", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(0) // size unknown in HLE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "LocalUnlock", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "LocaleNameToLCID", func(ctx *ntapi.TrapContext) uint32 {
			name := readGuestUTF16(ctx.Arg(0))
			switch strings.ToLower(name) {
			case "en-gb": ctx.SetReturn(0x0809)
			case "": ctx.SetReturn(0x0409)
			default: ctx.SetReturn(0x0409)
			}
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "LocateXStateFeature", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // NULL
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "LockFile", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "LockFileEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "MakeCriticalSectionGlobal", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "MapUserPhysicalPages", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "MapViewOfFileEx", func(ctx *ntapi.TrapContext) uint32 {
			hMapping := ntapi.Handle(ctx.Arg(0))
			dwDesiredAccess := uint32(ctx.Arg(1))
			offHigh := uint32(ctx.Arg(2))
			offLow := uint32(ctx.Arg(3))
			numBytes := ctx.Arg(4)
			// ctx.Arg(5) = lpBaseAddress hint (ignored; we allocate freely)
			guestAddr := doMapView(ctx, hMapping, dwDesiredAccess, offHigh, offLow, numBytes)
			ctx.SetReturn(guestAddr)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "MapViewOfFileExNuma", func(ctx *ntapi.TrapContext) uint32 {
			hMapping := ntapi.Handle(ctx.Arg(0))
			dwDesiredAccess := uint32(ctx.Arg(1))
			offHigh := uint32(ctx.Arg(2))
			offLow := uint32(ctx.Arg(3))
			numBytes := ctx.Arg(4)
			// ctx.Arg(5) = lpBaseAddress hint, ctx.Arg(6) = nndPreferred (both ignored)
			guestAddr := doMapView(ctx, hMapping, dwDesiredAccess, offHigh, offLow, numBytes)
			ctx.SetReturn(guestAddr)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "MapViewOfFileFromApp", func(ctx *ntapi.TrapContext) uint32 {
			hMapping := ntapi.Handle(ctx.Arg(0))
			dwDesiredAccess := uint32(ctx.Arg(1))
			offHigh := uint32(ctx.Arg(2))
			offLow := uint32(ctx.Arg(3))
			numBytes := ctx.Arg(4)
			guestAddr := doMapView(ctx, hMapping, dwDesiredAccess, offHigh, offLow, numBytes)
			ctx.SetReturn(guestAddr)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "Module32First", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "Module32FirstW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "Module32Next", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "Module32NextW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "MoveFileA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "MoveFileExA", func(ctx *ntapi.TrapContext) uint32 {
			src := winPathToVFS(readGuestString(ctx.Arg(0)))
			dst := winPathToVFS(readGuestString(ctx.Arg(1)))
			_ = os.Rename(src, dst)
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "MoveFileTransactedA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // transacted ops not supported
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "MoveFileTransactedW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // transacted ops not supported
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "MoveFileW", func(ctx *ntapi.TrapContext) uint32 {
			src := winPathToVFS(readGuestUTF16(ctx.Arg(0)))
			dst := winPathToVFS(readGuestUTF16(ctx.Arg(1)))
			if err := os.Rename(src, dst); err != nil { ctx.SetReturn(0); return 0 }
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "MoveFileWithProgressA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "MoveFileWithProgressW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "NeedCurrentDirectoryForExePathA", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "NeedCurrentDirectoryForExePathW", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "NormalizeString", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // error
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "NotifyNLSUserCache", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "OpenConsoleW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0xFFFFFFFFFFFFFFFF) // INVALID_HANDLE_VALUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "OpenDataFile", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "OpenEventA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // NULL
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "OpenEventW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // NULL
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "OpenFile", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0xFFFFFFFF) // HFILE_ERROR
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "OpenFileById", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0xFFFFFFFFFFFFFFFF) // INVALID_HANDLE_VALUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "OpenFileMappingA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // NULL
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "OpenFileMappingW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // NULL
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "OpenJobObjectA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x1001)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "OpenJobObjectW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x1001)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "OpenMutexA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // NULL
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "OpenMutexW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // NULL
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "OpenProcess", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x1000) // fake process handle
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "OpenProcessToken", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "OpenProfileUserMapping", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "OpenSemaphoreA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // NULL
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "OpenSemaphoreW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // NULL
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "OpenThread", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x1001) // fake thread handle
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "OpenThreadToken", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "OpenWaitableTimerA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // NULL
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "OpenWaitableTimerW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // NULL
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "OutputDebugStringA", func(ctx *ntapi.TrapContext) uint32 {
			if ctx.Arg(0) != 0 {
				ravelog.Logf("[debug] %s\n", readGuestString(ctx.Arg(0)))
			}
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "OutputDebugStringW", func(ctx *ntapi.TrapContext) uint32 {
			if ctx.Arg(0) != 0 {
				ravelog.Logf("[debug] %s\n", readGuestUTF16(ctx.Arg(0)))
			}
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "PackageIdFromFullName", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x3D54) // APPMODEL_ERROR_NO_PACKAGE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "PeekConsoleInputA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "PeekConsoleInputW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "PeekNamedPipe", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "PostQueuedCompletionStatus", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "PowerClearRequest", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "PowerCreateRequest", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x1005) // fake handle
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "PowerSetRequest", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "PrefetchVirtualMemory", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "PrepareTape", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // NO_ERROR
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "PrivCopyFileExW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "PrivMoveFileIdentityW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "Process32FirstW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "Process32Next", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "Process32NextW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ProcessIdToSessionId", func(ctx *ntapi.TrapContext) uint32 {
			lpdwSessionId := ctx.Arg(1)
			if lpdwSessionId != 0 {
				ctx.Mem.Write32(lpdwSessionId, 0)
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "PulseEvent", func(ctx *ntapi.TrapContext) uint32 {
			h := ntapi.Handle(ctx.Arg(0))
			if ev := handles.GetEvent(h); ev != nil {
				ev.Set()
				ev.Reset()
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "PurgeComm", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "QueryActCtxSettingsW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "QueryActCtxW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "QueryDepthSList", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // 0
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "QueryDosDeviceA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "QueryDosDeviceW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "QueryFullProcessImageNameA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "QueryFullProcessImageNameW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "QueryIdleProcessorCycleTime", func(ctx *ntapi.TrapContext) uint32 {
						if ctx.Arg(0) != 0 { ctx.Mem.Write32(ctx.Arg(0), 1) }
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "QueryIdleProcessorCycleTimeEx", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "QueryInformationJobObject", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "QueryMemoryResourceNotification", func(ctx *ntapi.TrapContext) uint32 {
			if state := ctx.Arg(1); state != 0 { ctx.Mem.Write32(state, 0) }
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "QueryNumberOfEventLogRecords", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "QueryOldestEventLogRecord", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "QueryProcessCycleTime", func(ctx *ntapi.TrapContext) uint32 {
			lpCycleTime := ctx.Arg(1)
			if lpCycleTime != 0 {
				ctx.Mem.Write64(lpCycleTime, uint64(time.Since(startTime).Nanoseconds()/100))
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "QueryThreadCycleTime", func(ctx *ntapi.TrapContext) uint32 {
			lpCycleTime := ctx.Arg(1)
			if lpCycleTime != 0 {
				ctx.Mem.Write64(lpCycleTime, uint64(time.Since(startTime).Nanoseconds()/100))
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "QueryThreadpoolStackInformation", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "QueryUmsThreadInformation", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "QueryUnbiasedInterruptTime", func(ctx *ntapi.TrapContext) uint32 {
			lpTime := ctx.Arg(0)
			if lpTime != 0 {
				ctx.Mem.Write64(lpTime, uint64(time.Since(startTime).Nanoseconds()/100))
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "QueryWin31IniFilesMappedToRegistry", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "QueueUserAPC", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "QueueUserAPC2", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "QueueUserWorkItem", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RaiseFailFastException", func(ctx *ntapi.TrapContext) uint32 {
			os.Exit(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ReOpenFile", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0xFFFFFFFFFFFFFFFF) // INVALID_HANDLE_VALUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ReadConsoleA", func(ctx *ntapi.TrapContext) uint32 {
			buf := ctx.Arg(1)
			nCharsToRead := uint32(ctx.Arg(2))
			charsRead := ctx.Arg(3)
			line, _ := stdinReader.ReadString('\n')
			if uint32(len(line)) > nCharsToRead {
				line = line[:nCharsToRead]
			}
			for i := 0; i < len(line); i++ {
				ctx.Mem.Write8(buf+uint64(i), line[i])
			}
			if charsRead != 0 {
				ctx.Mem.Write32(charsRead, uint32(len(line)))
			}
			ctx.SetReturn(1) // TRUE
			return 0
		})
		// ReadConsoleInput: synthesize a KEY_EVENT record for each character read from stdin.
		// INPUT_RECORD layout: EventType(2) + pad(2) + KeyEvent(16): bKeyDown(4)+wRepeatCount(2)+wVirtualKeyCode(2)+wVirtualScanCode(2)+pad(2)+Char(2)+dwControlKeyState(4)
		d.RegisterAutoStubHandler(kernel32, "ReadConsoleInputA", func(ctx *ntapi.TrapContext) uint32 {
			buf := ctx.Arg(1)
			// nLength := ctx.Arg(2) // max records to fill
			lpEventsRead := ctx.Arg(3)
			b := make([]byte, 1)
			n, _ := os.Stdin.Read(b)
			if n == 0 {
				if lpEventsRead != 0 { ctx.Mem.Write32(lpEventsRead, 0) }
				ctx.SetReturn(1)
				return 0
			}
			ch := b[0]
			// Write KEY_DOWN INPUT_RECORD (20 bytes) at buf
			ctx.Mem.Write16(buf+0, 0x0001)    // EventType = KEY_EVENT
			ctx.Mem.Write32(buf+4, 1)          // bKeyDown = TRUE
			ctx.Mem.Write16(buf+8, 1)          // wRepeatCount
			ctx.Mem.Write16(buf+10, uint16(ch)) // wVirtualKeyCode (approx)
			ctx.Mem.Write8(buf+14, ch)          // AsciiChar
			if lpEventsRead != 0 { ctx.Mem.Write32(lpEventsRead, 1) }
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ReadConsoleInputExA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ReadConsoleInputExW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ReadConsoleInputW", func(ctx *ntapi.TrapContext) uint32 {
			buf := ctx.Arg(1)
			lpEventsRead := ctx.Arg(3)
			b := make([]byte, 1)
			n, _ := os.Stdin.Read(b)
			if n == 0 {
				if lpEventsRead != 0 { ctx.Mem.Write32(lpEventsRead, 0) }
				ctx.SetReturn(1)
				return 0
			}
			ch := uint16(b[0])
			ctx.Mem.Write16(buf+0, 0x0001)  // EventType = KEY_EVENT
			ctx.Mem.Write32(buf+4, 1)        // bKeyDown = TRUE
			ctx.Mem.Write16(buf+8, 1)        // wRepeatCount
			ctx.Mem.Write16(buf+10, ch)      // wVirtualKeyCode
			ctx.Mem.Write16(buf+14, ch)      // UnicodeChar
			if lpEventsRead != 0 { ctx.Mem.Write32(lpEventsRead, 1) }
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ReadConsoleOutputA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ReadConsoleOutputAttribute", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ReadConsoleOutputCharacterA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ReadConsoleOutputCharacterW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ReadConsoleOutputW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ReadDirectoryChangesW", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ReadFileEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ReadFileScatter", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ReadProcessMemory", func(ctx *ntapi.TrapContext) uint32 {
			nSize := ctx.Arg(3)
			if nSize > 0 {
				data, _ := ctx.Mem.ReadBytes(ctx.Arg(1), int(nSize))
				ctx.Mem.WriteBytes(ctx.Arg(2), data)
			}
			if bw := ctx.Arg(4); bw != 0 { ctx.Mem.Write64(bw, nSize) }
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RegCloseKey", func(ctx *ntapi.TrapContext) uint32 {
			hKey := ctx.Arg(0)
			handles.Close(ntapi.Handle(hKey))
			ctx.SetReturn(0)
			return 0
		})

		d.RegisterAutoStubHandler(kernel32, "RegCreateKeyExA", func(ctx *ntapi.TrapContext) uint32 {
			subKey := readGuestString(ctx.Arg(1))
			path := regKeyPath(ctx.Arg(0), subKey)
			existed := ctx.Reg.OpenKey(path) != nil
			key := ctx.Reg.CreateKey(path)
			h := handles.Alloc(&ntapi.RegistryKeyHandle{Hive: regHive, Key: key, Path: path})
			if phk := ctx.Arg(6); phk != 0 {
				ctx.Mem.Write64(phk, uint64(h))
			}
			if disp := ctx.Arg(7); disp != 0 {
				if existed {
					ctx.Mem.Write32(disp, 2) // REG_OPENED_EXISTING_KEY
				} else {
					ctx.Mem.Write32(disp, 1) // REG_CREATED_NEW_KEY
				}
			}
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RegCreateKeyExW", func(ctx *ntapi.TrapContext) uint32 {
			subKey := readGuestUTF16(ctx.Arg(1))
			path := regKeyPath(ctx.Arg(0), subKey)
			existed := ctx.Reg.OpenKey(path) != nil
			key := ctx.Reg.CreateKey(path)
			h := handles.Alloc(&ntapi.RegistryKeyHandle{Hive: regHive, Key: key, Path: path})
			if phk := ctx.Arg(6); phk != 0 {
				ctx.Mem.Write64(phk, uint64(h))
			}
			if disp := ctx.Arg(7); disp != 0 {
				if existed {
					ctx.Mem.Write32(disp, 2) // REG_OPENED_EXISTING_KEY
				} else {
					ctx.Mem.Write32(disp, 1) // REG_CREATED_NEW_KEY
				}
			}
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RegDeleteKeyExA", func(ctx *ntapi.TrapContext) uint32 {
			subKey := readGuestString(ctx.Arg(1))
			path := regKeyPath(ctx.Arg(0), subKey)
			ctx.Reg.DeleteKey(path)
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RegDeleteKeyExW", func(ctx *ntapi.TrapContext) uint32 {
			subKey := readGuestUTF16(ctx.Arg(1))
			path := regKeyPath(ctx.Arg(0), subKey)
			ctx.Reg.DeleteKey(path)
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RegDeleteTreeA", func(ctx *ntapi.TrapContext) uint32 {
			subKey := readGuestString(ctx.Arg(1))
			path := regKeyPath(ctx.Arg(0), subKey)
			ctx.Reg.DeleteKey(path)
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RegDeleteTreeW", func(ctx *ntapi.TrapContext) uint32 {
			subKey := readGuestUTF16(ctx.Arg(1))
			path := regKeyPath(ctx.Arg(0), subKey)
			ctx.Reg.DeleteKey(path)
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RegDeleteValueA", func(ctx *ntapi.TrapContext) uint32 {
			rk := handles.GetRegKey(ntapi.Handle(ctx.Arg(0)))
			if rk != nil && rk.Key != nil {
				name := readGuestString(ctx.Arg(1))
				delete(rk.Key.Values, name)
			}
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RegDeleteValueW", func(ctx *ntapi.TrapContext) uint32 {
			rk := handles.GetRegKey(ntapi.Handle(ctx.Arg(0)))
			if rk != nil && rk.Key != nil {
				name := readGuestUTF16(ctx.Arg(1))
				for k := range rk.Key.Values {
					if strings.EqualFold(k, name) {
						delete(rk.Key.Values, k)
						break
					}
				}
			}
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RegEnumKeyExA", func(ctx *ntapi.TrapContext) uint32 {
			rk := handles.GetRegKey(ntapi.Handle(ctx.Arg(0)))
			if rk == nil || rk.Key == nil {
				ctx.SetReturn(259); return 0
			}
			names := ctx.Reg.EnumerateKeys(rk.Key)
			idx := uint32(ctx.Arg(1))
			if int(idx) >= len(names) {
				ctx.SetReturn(259); return 0
			}
			name := names[idx]
			if buf := ctx.Arg(2); buf != 0 {
				for i := 0; i < len(name); i++ { ctx.Mem.Write8(buf+uint64(i), name[i]) }
				ctx.Mem.Write8(buf+uint64(len(name)), 0)
			}
			if lp := ctx.Arg(3); lp != 0 { ctx.Mem.Write32(lp, uint32(len(name))) }
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RegEnumKeyExW", func(ctx *ntapi.TrapContext) uint32 {
			rk := handles.GetRegKey(ntapi.Handle(ctx.Arg(0)))
			if rk == nil || rk.Key == nil {
				ctx.SetReturn(259); return 0
			}
			names := ctx.Reg.EnumerateKeys(rk.Key)
			idx := uint32(ctx.Arg(1))
			if int(idx) >= len(names) {
				ctx.SetReturn(259); return 0
			}
			ws := utf16Encode(names[idx])
			if buf := ctx.Arg(2); buf != 0 {
				for i, w := range ws { ctx.Mem.Write16(buf+uint64(i)*2, w) }
				ctx.Mem.Write16(buf+uint64(len(ws))*2, 0)
			}
			if lp := ctx.Arg(3); lp != 0 { ctx.Mem.Write32(lp, uint32(len(ws))) }
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RegEnumValueA", func(ctx *ntapi.TrapContext) uint32 {
			rk := handles.GetRegKey(ntapi.Handle(ctx.Arg(0)))
			if rk == nil || rk.Key == nil {
				ctx.SetReturn(259); return 0
			}
			vnames := ctx.Reg.EnumerateValues(rk.Key)
			idx := uint32(ctx.Arg(1))
			if int(idx) >= len(vnames) {
				ctx.SetReturn(259); return 0
			}
			name := vnames[idx]
			val := rk.Key.Values[name]
			if buf := ctx.Arg(2); buf != 0 {
				for i := 0; i < len(name); i++ { ctx.Mem.Write8(buf+uint64(i), name[i]) }
				ctx.Mem.Write8(buf+uint64(len(name)), 0)
			}
			if lp := ctx.Arg(3); lp != 0 { ctx.Mem.Write32(lp, uint32(len(name))) }
			if lpType := ctx.Arg(5); lpType != 0 { ctx.Mem.Write32(lpType, val.Type) }
			needed := uint32(len(val.Data))
			if lpcb := ctx.Arg(7); lpcb != 0 { ctx.Mem.Write32(lpcb, needed) }
			if lpData := ctx.Arg(6); lpData != 0 { ctx.Mem.WriteBytes(lpData, val.Data) }
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RegEnumValueW", func(ctx *ntapi.TrapContext) uint32 {
			rk := handles.GetRegKey(ntapi.Handle(ctx.Arg(0)))
			if rk == nil || rk.Key == nil {
				ctx.SetReturn(259); return 0
			}
			vnames := ctx.Reg.EnumerateValues(rk.Key)
			idx := uint32(ctx.Arg(1))
			if int(idx) >= len(vnames) {
				ctx.SetReturn(259); return 0
			}
			name := vnames[idx]
			val := rk.Key.Values[name]
			ws := utf16Encode(name)
			if buf := ctx.Arg(2); buf != 0 {
				for i, w := range ws { ctx.Mem.Write16(buf+uint64(i)*2, w) }
				ctx.Mem.Write16(buf+uint64(len(ws))*2, 0)
			}
			if lp := ctx.Arg(3); lp != 0 { ctx.Mem.Write32(lp, uint32(len(ws))) }
			if lpType := ctx.Arg(5); lpType != 0 { ctx.Mem.Write32(lpType, val.Type) }
			needed := uint32(len(val.Data))
			if lpcbData := ctx.Arg(7); lpcbData != 0 {
				avail, _ := ctx.Mem.Read32(lpcbData)
				ctx.Mem.Write32(lpcbData, needed)
				if ctx.Arg(6) != 0 && avail < needed { ctx.SetReturn(234); return 0 }
			}
			if lpData := ctx.Arg(6); lpData != 0 { ctx.Mem.WriteBytes(lpData, val.Data) }
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RegFlushKey", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RegGetKeySecurity", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RegGetValueA", func(ctx *ntapi.TrapContext) uint32 {
			// RegGetValueA(hKey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData)
			subKey := readGuestString(ctx.Arg(1))
			path := regKeyPath(ctx.Arg(0), subKey)
			key := ctx.Reg.OpenKey(path)
			if key == nil { ctx.SetReturn(2); return 0 }
			tmpH := handles.Alloc(&ntapi.RegistryKeyHandle{Hive: regHive, Key: key, Path: path})
			defer handles.Close(ntapi.Handle(tmpH))
			old0 := ctx.Arg(0); _ = old0
			// reuse regQueryValue by temporarily patching args
			valueName := readGuestString(ctx.Arg(2))
			_ = valueName
			ctx.SetReturn(2) // simplified: just not found for now
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RegGetValueW", func(ctx *ntapi.TrapContext) uint32 {
			subKey := readGuestUTF16(ctx.Arg(1))
			valueName := readGuestUTF16(ctx.Arg(2))
			path := regKeyPath(ctx.Arg(0), subKey)
			key := ctx.Reg.OpenKey(path)
			if key == nil { ctx.SetReturn(2); return 0 }
			var val *ntapi.RegistryValue
			for k, v := range key.Values {
				if strings.EqualFold(k, valueName) { val = v; break }
			}
			if val == nil { ctx.SetReturn(2); return 0 }
			lpType := ctx.Arg(4)
			pvData := ctx.Arg(5)
			pcbData := ctx.Arg(6)
			if lpType != 0 { ctx.Mem.Write32(lpType, val.Type) }
			needed := uint32(len(val.Data))
			if pcbData != 0 {
				avail, _ := ctx.Mem.Read32(pcbData)
				ctx.Mem.Write32(pcbData, needed)
				if pvData != 0 && avail < needed { ctx.SetReturn(234); return 0 }
			}
			if pvData != 0 { ctx.Mem.WriteBytes(pvData, val.Data) }
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RegLoadKeyA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(5) // ERROR_ACCESS_DENIED
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RegLoadKeyW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(5) // ERROR_ACCESS_DENIED
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RegLoadMUIStringA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(2) // ERROR_FILE_NOT_FOUND
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RegLoadMUIStringW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(2) // ERROR_FILE_NOT_FOUND
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RegNotifyChangeKeyValue", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RegOpenCurrentUser", func(ctx *ntapi.TrapContext) uint32 {
			path := `HKEY_CURRENT_USER`
			key := ctx.Reg.OpenKey(path)
			if key == nil { key = ctx.Reg.CreateKey(path) }
			h := handles.Alloc(&ntapi.RegistryKeyHandle{Hive: regHive, Key: key, Path: path})
			if phk := ctx.Arg(1); phk != 0 { ctx.Mem.Write64(phk, uint64(h)) }
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RegOpenKeyExA", func(ctx *ntapi.TrapContext) uint32 {
			subKey := readGuestString(ctx.Arg(1))
			path := regKeyPath(ctx.Arg(0), subKey)
			key := ctx.Reg.OpenKey(path)
			if key == nil {
				if regIsProbeKey(path) {
					ctx.SetReturn(2) // ERROR_FILE_NOT_FOUND
					return 0
				}
				key = ctx.Reg.CreateKey(path)
			}
			h := handles.Alloc(&ntapi.RegistryKeyHandle{Hive: regHive, Key: key, Path: path})
			if phk := ctx.Arg(4); phk != 0 { ctx.Mem.Write64(phk, uint64(h)) }
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RegOpenKeyExW", func(ctx *ntapi.TrapContext) uint32 {
			subKey := readGuestUTF16(ctx.Arg(1))
			path := regKeyPath(ctx.Arg(0), subKey)
			key := ctx.Reg.OpenKey(path)
			if key == nil {
				if regIsProbeKey(path) {
					ctx.SetReturn(2) // ERROR_FILE_NOT_FOUND
					return 0
				}
				key = ctx.Reg.CreateKey(path)
			}
			h := handles.Alloc(&ntapi.RegistryKeyHandle{Hive: regHive, Key: key, Path: path})
			if phk := ctx.Arg(4); phk != 0 { ctx.Mem.Write64(phk, uint64(h)) }
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RegOpenUserClassesRoot", func(ctx *ntapi.TrapContext) uint32 {
			path := `HKEY_CLASSES_ROOT`
			key := ctx.Reg.OpenKey(path)
			if key == nil { key = ctx.Reg.CreateKey(path) }
			h := handles.Alloc(&ntapi.RegistryKeyHandle{Hive: regHive, Key: key, Path: path})
			if phk := ctx.Arg(1); phk != 0 { ctx.Mem.Write64(phk, uint64(h)) }
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RegQueryInfoKeyA", func(ctx *ntapi.TrapContext) uint32 {
			rk := handles.GetRegKey(ntapi.Handle(ctx.Arg(0)))
			var nSubKeys, nValues uint32
			if rk != nil && rk.Key != nil {
				nSubKeys = uint32(len(rk.Key.Children))
				nValues = uint32(len(rk.Key.Values))
			}
			if p := ctx.Arg(4); p != 0 { ctx.Mem.Write32(p, nSubKeys) }
			if p := ctx.Arg(7); p != 0 { ctx.Mem.Write32(p, nValues) }
			for _, i := range []int{2, 3, 5, 6, 8, 9, 10} {
				if p := ctx.Arg(i); p != 0 { ctx.Mem.Write32(p, 0) }
			}
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RegQueryInfoKeyW", func(ctx *ntapi.TrapContext) uint32 {
			rk := handles.GetRegKey(ntapi.Handle(ctx.Arg(0)))
			var nSubKeys, nValues uint32
			if rk != nil && rk.Key != nil {
				nSubKeys = uint32(len(rk.Key.Children))
				nValues = uint32(len(rk.Key.Values))
			}
			if p := ctx.Arg(4); p != 0 { ctx.Mem.Write32(p, nSubKeys) }
			if p := ctx.Arg(7); p != 0 { ctx.Mem.Write32(p, nValues) }
			for _, i := range []int{2, 3, 5, 6, 8, 9, 10} {
				if p := ctx.Arg(i); p != 0 { ctx.Mem.Write32(p, 0) }
			}
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RegQueryValueExA", func(ctx *ntapi.TrapContext) uint32 {
			valueName := readGuestString(ctx.Arg(1))
			ctx.SetReturn(uint64(regQueryValue(ctx, ctx.Arg(0), valueName)))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RegQueryValueExW", func(ctx *ntapi.TrapContext) uint32 {
			valueName := readGuestUTF16(ctx.Arg(1))
			ctx.SetReturn(uint64(regQueryValue(ctx, ctx.Arg(0), valueName)))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RegRestoreKeyA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(5) // ERROR_ACCESS_DENIED
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RegRestoreKeyW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(5) // ERROR_ACCESS_DENIED
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RegSaveKeyExA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(5) // ERROR_ACCESS_DENIED
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RegSaveKeyExW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(5) // ERROR_ACCESS_DENIED
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RegSetKeySecurity", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RegSetValueExA", func(ctx *ntapi.TrapContext) uint32 {
			rk := handles.GetRegKey(ntapi.Handle(ctx.Arg(0)))
			if rk != nil && rk.Key != nil {
				name := readGuestString(ctx.Arg(1))
				valType := uint32(ctx.Arg(3))
				dataLen := int(ctx.Arg(5))
				data, _ := ctx.Mem.ReadBytes(ctx.Arg(4), dataLen)
				if rk.Key.Values == nil { rk.Key.Values = make(map[string]*ntapi.RegistryValue) }
				rk.Key.Values[name] = &ntapi.RegistryValue{Name: name, Type: valType, Data: data}
			}
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RegSetValueExW", func(ctx *ntapi.TrapContext) uint32 {
			rk := handles.GetRegKey(ntapi.Handle(ctx.Arg(0)))
			if rk != nil && rk.Key != nil {
				name := readGuestUTF16(ctx.Arg(1))
				valType := uint32(ctx.Arg(3))
				dataLen := int(ctx.Arg(5))
				data, _ := ctx.Mem.ReadBytes(ctx.Arg(4), dataLen)
				if rk.Key.Values == nil { rk.Key.Values = make(map[string]*ntapi.RegistryValue) }
				rk.Key.Values[name] = &ntapi.RegistryValue{Name: name, Type: valType, Data: data}
			}
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RegUnLoadKeyA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(5) // ERROR_ACCESS_DENIED
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RegUnLoadKeyW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(5) // ERROR_ACCESS_DENIED
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RegisterApplicationRecoveryCallback", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RegisterConsoleIME", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RegisterConsoleOS2", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RegisterConsoleVDM", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RegisterServiceProcess", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RegisterSysMsgHandler", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RegisterWaitForInputIdle", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // no-op
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RegisterWaitForSingleObject", func(ctx *ntapi.TrapContext) uint32 {
			if phNew := ctx.Arg(0); phNew != 0 { ctx.Mem.Write64(phNew, 1) }
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RegisterWaitForSingleObjectEx", func(ctx *ntapi.TrapContext) uint32 {
			if phNew := ctx.Arg(0); phNew != 0 { ctx.Mem.Write64(phNew, 1) }
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RegisterWowBaseHandlers", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RegisterWowExec", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ReinitializeCriticalSection", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ReleaseActCtx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // no-op
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ReleaseMutexWhenCallbackReturns", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ReleaseSRWLockShared", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // no-op
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ReleaseSemaphore", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ReleaseSemaphoreWhenCallbackReturns", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RemoveDirectoryA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RemoveDirectoryTransactedA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RemoveDirectoryTransactedW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RemoveDirectoryW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RemoveDllDirectory", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RemoveVectoredContinueHandler", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RemoveVectoredExceptionHandler", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ReplaceFile", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ReplaceFileA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ReplaceFileW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RequestDeviceWakeup", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RequestWakeupLatency", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // S_OK
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ResetWriteWatch", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ResizePseudoConsole", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // S_OK
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ResolveLocaleName", func(ctx *ntapi.TrapContext) uint32 {
			name := readGuestUTF16(ctx.Arg(0))
			buf := ctx.Arg(1)
			cch := ctx.Arg(2)
			ws := utf16Encode(name)
			if buf != 0 && cch > 0 {
				n := uint64(len(ws))
				if n >= cch { n = cch - 1 }
				for i := uint64(0); i < n; i++ { ctx.Mem.Write16(buf+i*2, ws[i]) }
				ctx.Mem.Write16(buf+n*2, 0)
				ctx.SetReturn(n + 1)
			} else {
				ctx.SetReturn(uint64(len(ws) + 1))
			}
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RestoreLastError", func(ctx *ntapi.TrapContext) uint32 {
			// no-op: void function
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ResumeThread", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // prior suspend count
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RtlAddFunctionTable", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RtlCaptureStackBackTrace", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RtlCompareMemory", func(ctx *ntapi.TrapContext) uint32 {
			src1 := ctx.Arg(0)
			src2 := ctx.Arg(1)
			length := ctx.Arg(2)
			b1, _ := ctx.Mem.ReadBytes(src1, int(length))
			b2, _ := ctx.Mem.ReadBytes(src2, int(length))
			count := uint64(0)
			for i := uint64(0); i < length && i < uint64(len(b1)) && i < uint64(len(b2)); i++ {
				if b1[i] != b2[i] {
					break
				}
				count++
			}
			ctx.SetReturn(count)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RtlCopyMemory", func(ctx *ntapi.TrapContext) uint32 {
			dst := ctx.Arg(0)
			src := ctx.Arg(1)
			length := ctx.Arg(2)
			data, _ := ctx.Mem.ReadBytes(src, int(length))
			ctx.Mem.WriteBytes(dst, data)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RtlDeleteFunctionTable", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RtlFillMemory", func(ctx *ntapi.TrapContext) uint32 {
			dst := ctx.Arg(0)
			length := ctx.Arg(1)
			fill := byte(ctx.Arg(2))
			buf := make([]byte, length)
			for i := range buf {
				buf[i] = fill
			}
			ctx.Mem.WriteBytes(dst, buf)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RtlInstallFunctionTableCallback", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RtlIsEcCode", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RtlMoveMemory", func(ctx *ntapi.TrapContext) uint32 {
			dst := ctx.Arg(0)
			src := ctx.Arg(1)
			length := ctx.Arg(2)
			data, _ := ctx.Mem.ReadBytes(src, int(length))
			ctx.Mem.WriteBytes(dst, data)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RtlRaiseException", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RtlRestoreContext", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "RtlZeroMemory", func(ctx *ntapi.TrapContext) uint32 {
			dst := ctx.Arg(0)
			length := ctx.Arg(1)
			ctx.Mem.WriteBytes(dst, make([]byte, length))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ScrollConsoleScreenBufferA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ScrollConsoleScreenBufferW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SearchPathA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // not found
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SearchPathW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // not found
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetCPGlobal", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetCachedSigningLevel", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetCalendarInfoA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetCalendarInfoW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetCommBreak", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetCommConfig", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetCommMask", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetCommState", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetCommTimeouts", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetComputerNameA", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetComputerNameExA", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetComputerNameExW", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetComputerNameW", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetConsoleActiveScreenBuffer", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetConsoleCP", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetConsoleCommandHistoryMode", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetConsoleCursor", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetConsoleCursorInfo", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetConsoleCursorMode", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetConsoleCursorPosition", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetConsoleDisplayMode", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetConsoleFont", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetConsoleHardwareState", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetConsoleIcon", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetConsoleInputExeNameA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetConsoleInputExeNameW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetConsoleKeyShortcuts", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetConsoleLocalEUDC", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetConsoleMaximumWindowSize", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetConsoleMenuClose", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetConsoleNlsMode", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetConsoleNumberOfCommandsA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetConsoleNumberOfCommandsW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetConsoleOS2OemFormat", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetConsoleOutputCP", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetConsolePalette", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetConsoleScreenBufferInfoEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetConsoleScreenBufferSize", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetConsoleTitleA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetConsoleTitleW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetConsoleWindowInfo", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetCriticalSectionSpinCount", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetCurrentConsoleFontEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetCurrentDirectoryA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetDaylightFlag", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetDefaultCommConfigA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetDefaultCommConfigW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetDefaultDllDirectories", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetDllDirectoryA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetDllDirectoryW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetEndOfFile", func(ctx *ntapi.TrapContext) uint32 {
			hFile := ntapi.Handle(ctx.Arg(0))
			obj := handles.Get(hFile)
			fh, ok := obj.(*ntapi.FileHandle)
			if !ok {
				ctx.SetReturn(0)
				return 0
			}
			pos, err := ctx.FS.Lseek(fh.FD, 0, io.SeekCurrent)
			if err != nil {
				ctx.SetReturn(0)
				return 0
			}
			if err := ctx.FS.Ftruncate(fh.FD, pos); err != nil {
				ctx.SetReturn(0)
				return 0
			}
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetEnvironmentStringsA", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetEnvironmentStringsW", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetEnvironmentVariableA", func(ctx *ntapi.TrapContext) uint32 {
			name := readGuestString(ctx.Arg(0))
			valPtr := ctx.Arg(1)
			if valPtr == 0 {
				delete(envVars, name)
			} else {
				envVars[name] = readGuestString(valPtr)
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetErrorMode", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // return previous mode (0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetEventWhenCallbackReturns", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // no-op
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetFileApisToANSI", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetFileApisToOEM", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetFileAttributesA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetFileCompletionNotificationModes", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetFileInformationByHandle", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetFilePointer", func(ctx *ntapi.TrapContext) uint32 {
			hFile := ntapi.Handle(ctx.Arg(0))
			lDistLow := int32(ctx.Arg(1))
			lpDistHigh := ctx.Arg(2)
			dwMoveMethod := ctx.Arg(3)
			obj := handles.Get(hFile)
			fh, ok := obj.(*ntapi.FileHandle)
			if !ok { ctx.SetReturn(0xFFFFFFFF); return 0 }
			var dist int64 = int64(lDistLow)
			if lpDistHigh != 0 {
				hi, _ := ctx.Mem.Read32(lpDistHigh)
				dist = int64(hi)<<32 | int64(uint32(lDistLow))
			}
			var whence int
			switch dwMoveMethod {
			case 0: whence = io.SeekStart
			case 1: whence = io.SeekCurrent
			case 2: whence = io.SeekEnd
			default: whence = io.SeekStart
			}
			newPos, err := ctx.FS.Lseek(fh.FD, dist, whence)
			if err != nil { ctx.SetReturn(0xFFFFFFFF); return 0 }
			if lpDistHigh != 0 { ctx.Mem.Write32(lpDistHigh, uint32(newPos>>32)) }
			ctx.SetReturn(uint64(uint32(newPos)))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetFileTime", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetFileValidData", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetFirmwareEnvironmentVariableA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetFirmwareEnvironmentVariableW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetHandleContext", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetHandleCount", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetHandleInformation", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetInformationJobObject", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetLastConsoleEventActive", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetLocalTime", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetLocaleInfoA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetLocaleInfoW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetMailslotInfo", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetMessageWaitingIndicator", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetNamedPipeHandleState", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetPriorityClass", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetProcessAffinityMask", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetProcessAffinityUpdateMode", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetProcessDEPPolicy", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetProcessDefaultCpuSets", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetProcessInformation", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetProcessMitigationPolicy", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetProcessPreferredUILanguages", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetProcessPriorityBoost", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetProcessShutdownParameters", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetProcessWorkingSetSize", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetProcessWorkingSetSizeEx", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetSearchPathMode", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetStdHandleEx", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetSystemFileCacheSize", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetSystemPowerState", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetSystemTime", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetSystemTimeAdjustment", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetTapeParameters", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // error
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetTapePosition", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // NO_ERROR
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetTermsrvAppInstallMode", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetThreadAffinityMask", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(ctx.Arg(1)) // return previous affinity mask
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetThreadContext", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetThreadDescription", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // S_OK
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetThreadErrorMode", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetThreadExecutionState", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x80000001) // ES_CONTINUOUS|ES_SYSTEM_REQUIRED
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetThreadGroupAffinity", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetThreadIdealProcessor", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // no prior ideal
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetThreadIdealProcessorEx", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetThreadInformation", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetThreadLocale", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetThreadPreferredUILanguages", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetThreadPriority", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetThreadPriorityBoost", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetThreadSelectedCpuSets", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetThreadStackGuarantee", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetThreadToken", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetThreadUILanguage", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x0409)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetThreadpoolStackInformation", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetThreadpoolThreadMaximum", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // no-op
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetThreadpoolThreadMinimum", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetThreadpoolTimer", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // no-op
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetThreadpoolWait", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // no-op
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetTimeZoneInformation", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE - read-only
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetTimerQueueTimer", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetUmsThreadInformation", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetUserGeoID", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetUserGeoName", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetVDMCurrentDirectories", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetVolumeLabelA", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetVolumeLabelW", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetVolumeMountPointA", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetVolumeMountPointW", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetWaitableTimer", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetWaitableTimerEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetXStateFeaturesMask", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetupComm", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ShowConsoleCursor", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SignalObjectAndWait", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // WAIT_OBJECT_0
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SleepConditionVariableCS", func(ctx *ntapi.TrapContext) uint32 {
			timeout := ctx.Arg(2)
			ms := timeout
			if ms > 50 {
				ms = 50
			}
			if ms > 0 {
				time.Sleep(time.Duration(ms) * time.Millisecond)
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "StartThreadpoolIo", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // no-op
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SubmitThreadpoolWork", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SuspendThread", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // previous suspend count = 0
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SwitchToFiber", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // no-op
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SwitchToThread", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE - no yielding
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SystemTimeToFileTime", func(ctx *ntapi.TrapContext) uint32 {
			lpST := ctx.Arg(0)
			lpFT := ctx.Arg(1)
			if lpST == 0 || lpFT == 0 { ctx.SetReturn(0); return 0 }
			year, _ := ctx.Mem.Read16(lpST)
			month, _ := ctx.Mem.Read16(lpST + 2)
			day, _ := ctx.Mem.Read16(lpST + 6)
			hour, _ := ctx.Mem.Read16(lpST + 8)
			min, _ := ctx.Mem.Read16(lpST + 10)
			sec, _ := ctx.Mem.Read16(lpST + 12)
			ms, _ := ctx.Mem.Read16(lpST + 14)
			t := time.Date(int(year), time.Month(month), int(day), int(hour), int(min), int(sec), int(ms)*1e6, time.UTC)
			epoch := time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)
			ft := uint64(t.Sub(epoch).Nanoseconds() / 100)
			ctx.Mem.Write64(lpFT, ft)
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "TerminateJobObject", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "TerminateThread", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "TermsrvAppInstallMode", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "Thread32First", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "Thread32Next", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "TlsAllocInternal", func(ctx *ntapi.TrapContext) uint32 {
			slot := tlsNextSlot
			tlsNextSlot++
			ctx.SetReturn(uint64(slot))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "TlsFreeInternal", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "Toolhelp32ReadProcessMemory", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "TransactNamedPipe", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "TransmitCommChar", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "TrimVirtualBuffer", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "TryAcquireSRWLockShared", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE - always available
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "TryEnterCriticalSection", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "TrySubmitThreadpoolCallback", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "TzSpecificLocalTimeToSystemTime", func(ctx *ntapi.TrapContext) uint32 {
			src := ctx.Arg(1)
			dst := ctx.Arg(2)
			if src != 0 && dst != 0 {
				for i := uint64(0); i < 16; i++ { b, _ := ctx.Mem.Read8(src + i); ctx.Mem.Write8(dst+i, b) }
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "UmsThreadYield", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "UninitializeCriticalSection", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "UnlockFile", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "UnlockFileEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "UnmapViewOfFileEx", func(ctx *ntapi.TrapContext) uint32 {
			doUnmapView(ctx, ctx.Arg(0))
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "UnregisterWait", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "UnregisterWaitEx", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "UpdateProcThreadAttribute", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "UpdateResourceA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "UpdateResourceW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "VDMConsoleOperation", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "VDMOperationStarted", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ValidateLCType", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ValidateLocale", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "VerLanguageNameA", func(ctx *ntapi.TrapContext) uint32 {
			buf := ctx.Arg(1)
			if buf != 0 {
				ctx.Mem.WriteBytes(buf, []byte("English\x00"))
			}
			ctx.SetReturn(7)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "VerLanguageNameW", func(ctx *ntapi.TrapContext) uint32 {
			buf := ctx.Arg(1)
			if buf != 0 {
				for i, c := range []uint16{'E', 'n', 'g', 'l', 'i', 's', 'h', 0} {
					ctx.Mem.Write16(buf+uint64(i)*2, c)
				}
			}
			ctx.SetReturn(7)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "VerifyConsoleIoHandle", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "VerifyVersionInfoA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // always compatible
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "VirtualAlloc", func(ctx *ntapi.TrapContext) uint32 {
			lpAddress := ctx.Arg(0)
			dwSize := ctx.Arg(1)
			// flAllocationType := ctx.Arg(2) // MEM_COMMIT=0x1000, MEM_RESERVE=0x2000
			// flProtect := ctx.Arg(3)        // PAGE_READWRITE=0x04, etc.
			if dwSize == 0 {
				dwSize = 0x1000
			}
			dwSize = (dwSize + 0xFFF) &^ 0xFFF // page-align
			perms := mmu.PermRead | mmu.PermWrite | mmu.PermExecute
			addr := mem.Mmap(lpAddress, dwSize, perms)
			if addr == 0 {
				ctx.SetReturn(0)
				return 0
			}
			ravelog.Logf("[win32] VirtualAlloc(0x%x, 0x%x) → 0x%x\n", lpAddress, dwSize, addr)
			ctx.SetReturn(addr)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "VirtualAllocEx", func(ctx *ntapi.TrapContext) uint32 {
			// hProcess := ctx.Arg(0) // ignored - always current process
			lpAddress := ctx.Arg(1)
			dwSize := ctx.Arg(2)
			if dwSize == 0 {
				dwSize = 0x1000
			}
			dwSize = (dwSize + 0xFFF) &^ 0xFFF
			perms := mmu.PermRead | mmu.PermWrite | mmu.PermExecute
			addr := mem.Mmap(lpAddress, dwSize, perms)
			ctx.SetReturn(addr)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "VirtualAllocExNuma", func(ctx *ntapi.TrapContext) uint32 {
			lpAddress := ctx.Arg(1)
			dwSize := ctx.Arg(2)
			if dwSize == 0 {
				dwSize = 0x1000
			}
			dwSize = (dwSize + 0xFFF) &^ 0xFFF
			perms := mmu.PermRead | mmu.PermWrite | mmu.PermExecute
			addr := mem.Mmap(lpAddress, dwSize, perms)
			ctx.SetReturn(addr)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "VirtualBufferExceptionHandler", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "VirtualFree", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "VirtualFreeEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "VirtualLock", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "VirtualProtectEx", func(ctx *ntapi.TrapContext) uint32 {
			if lpOld := ctx.Arg(4); lpOld != 0 { ctx.Mem.Write32(lpOld, 0x20) } // PAGE_EXECUTE_READ
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "VirtualQuery", func(ctx *ntapi.TrapContext) uint32 {
			addr := ctx.Arg(0)
			bufPtr := ctx.Arg(1)
			bufLen := ctx.Arg(2)
			if bufPtr != 0 && bufLen >= 48 {
				ctx.Mem.Write64Raw(bufPtr+0, addr&^uint64(0xFFF))
				ctx.Mem.Write64Raw(bufPtr+8, 0)
				ctx.Mem.Write32(bufPtr+16, 0x04) // PAGE_READWRITE
				ctx.Mem.Write32(bufPtr+20, 0)
				ctx.Mem.Write64Raw(bufPtr+24, 0x1000)
				ctx.Mem.Write32(bufPtr+32, 0x1000) // MEM_COMMIT
				ctx.Mem.Write32(bufPtr+36, 0x04)   // PAGE_READWRITE
				ctx.Mem.Write32(bufPtr+40, 0x20000) // MEM_PRIVATE
				ctx.Mem.Write32(bufPtr+44, 0)
				ctx.SetReturn(48)
			} else {
				ctx.SetReturn(0)
			}
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "VirtualQueryEx", func(ctx *ntapi.TrapContext) uint32 {
			lpBuffer := ctx.Arg(2)
			dwLength := ctx.Arg(3)
			if lpBuffer == 0 || dwLength < 48 {
				ctx.SetReturn(0)
				return 0
			}
			addr := ctx.Arg(1) &^ uint64(0xFFF)
			ctx.Mem.Write64(lpBuffer+0, addr)    // BaseAddress
			ctx.Mem.Write64(lpBuffer+8, addr)    // AllocationBase
			ctx.Mem.Write32(lpBuffer+16, 0x04)  // AllocationProtect = PAGE_READWRITE
			ctx.Mem.Write32(lpBuffer+20, 0)     // PartitionId
			ctx.Mem.Write64(lpBuffer+24, 0x1000) // RegionSize
			ctx.Mem.Write32(lpBuffer+32, 0x1000) // State = MEM_COMMIT
			ctx.Mem.Write32(lpBuffer+36, 0x04)  // Protect = PAGE_READWRITE
			ctx.Mem.Write32(lpBuffer+40, 0x20000) // Type = MEM_PRIVATE
			ctx.Mem.Write32(lpBuffer+44, 0)
			ctx.SetReturn(48)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "VirtualUnlock", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "WTSGetActiveConsoleSessionId", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "WaitCommEvent", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "WaitForDebugEvent", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "WaitForDebugEventEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "WaitForMultipleObjectsEx", func(ctx *ntapi.TrapContext) uint32 {
			// Delegate to WaitForMultipleObjects logic (ignore alertable flag)
			nCount := ctx.Arg(0)
			pHandles := ctx.Arg(1)
			ms := ctx.Arg(3)
			var timeout time.Duration
			if ms == 0xFFFFFFFF {
				timeout = -1
			} else if ms == 0 {
				timeout = 0
			} else {
				timeout = time.Duration(ms) * time.Millisecond
			}
			for i := uint64(0); i < nCount && i < 64; i++ {
				hv, _ := ctx.Mem.Read64(pHandles + i*8)
				h := ntapi.Handle(hv)
				if th := handles.GetThread(h); th != nil && th.Done != nil {
					if timeout < 0 {
						<-th.Done
					} else if timeout > 0 {
						select {
						case <-th.Done:
						case <-time.After(timeout):
							ctx.SetReturn(0x102)
							return 0
						}
					} else {
						select {
						case <-th.Done:
						default:
							ctx.SetReturn(0x102)
							return 0
						}
					}
					ctx.SetReturn(i)
					return 0
				}
				if eh := handles.GetEvent(h); eh != nil {
					if eh.WaitTimeout(timeout) {
						ctx.SetReturn(i)
						return 0
					}
					ctx.SetReturn(0x102)
					return 0
				}
			}
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "WaitForSingleObjectEx", func(ctx *ntapi.TrapContext) uint32 {
			// Delegate to WaitForSingleObject logic (ignore alertable flag)
			h := ntapi.Handle(ctx.Arg(0))
			ms := ctx.Arg(1)
			var timeout time.Duration
			if ms == 0xFFFFFFFF {
				timeout = -1
			} else if ms == 0 {
				timeout = 0
			} else {
				timeout = time.Duration(ms) * time.Millisecond
			}
			if th := handles.GetThread(h); th != nil && th.Done != nil {
				if timeout < 0 {
					<-th.Done
					ctx.SetReturn(0)
				} else if timeout == 0 {
					select {
					case <-th.Done:
						ctx.SetReturn(0)
					default:
						ctx.SetReturn(0x102)
					}
				} else {
					select {
					case <-th.Done:
						ctx.SetReturn(0)
					case <-time.After(timeout):
						ctx.SetReturn(0x102)
					}
				}
				return 0
			}
			if eh := handles.GetEvent(h); eh != nil {
				if eh.WaitTimeout(timeout) {
					ctx.SetReturn(0)
				} else {
					ctx.SetReturn(0x102)
				}
				return 0
			}
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "WaitForThreadpoolIoCallbacks", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // no-op
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "WaitForThreadpoolTimerCallbacks", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // no-op
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "WaitForThreadpoolWaitCallbacks", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // no-op
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "WaitForThreadpoolWorkCallbacks", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // no-op
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "WaitNamedPipeA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "WaitNamedPipeW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "WakeConditionVariable", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // no-op
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "WerGetFlags", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "WerRegisterCustomMetadata", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "WerRegisterFile", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "WerRegisterMemoryBlock", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "WerRegisterRuntimeExceptionModule", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "WerSetFlags", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "WerUnregisterCustomMetadata", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "WerUnregisterFile", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "WerUnregisterMemoryBlock", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "WerUnregisterRuntimeExceptionModule", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "WinExec", func(ctx *ntapi.TrapContext) uint32 {
			cmd := readGuestString(ctx.Arg(0))
			ravelog.Logf("[win32] WinExec: %s\n", cmd)
			ctx.SetReturn(32) // > 31 = success
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "Wow64DisableWow64FsRedirection", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "Wow64EnableWow64FsRedirection", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "Wow64GetThreadContext", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "Wow64GetThreadSelectorEntry", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "Wow64RevertWow64FsRedirection", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "Wow64SetThreadContext", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "WriteConsoleA", func(ctx *ntapi.TrapContext) uint32 {
			handle := ctx.Arg(0)
			buf := ctx.Arg(1)
			nChars := ctx.Arg(2)
			lpWritten := ctx.Arg(3)
			if buf != 0 && nChars > 0 {
				data := make([]byte, nChars)
				for i := uint64(0); i < nChars; i++ {
					b, _ := ctx.Mem.Read8(buf + i)
					data[i] = b
				}
				switch handle {
				case 0x101: os.Stdout.Write(data)
				case 0x102: os.Stderr.Write(data)
				default: os.Stdout.Write(data)
				}
			}
			if lpWritten != 0 { ctx.Mem.Write32(lpWritten, uint32(nChars)) }
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "WriteConsoleInputA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "WriteConsoleInputVDMA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "WriteConsoleInputVDMW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "WriteConsoleInputW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "WriteConsoleOutputA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "WriteConsoleOutputAttribute", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "WriteConsoleOutputCharacterA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "WriteConsoleOutputCharacterW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "WriteConsoleOutputW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "WriteFileEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "WriteFileGather", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "WritePrivateProfileSectionA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "WritePrivateProfileSectionW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "WritePrivateProfileStringA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "WritePrivateProfileStringW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "WritePrivateProfileStructA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "WritePrivateProfileStructW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "WriteProcessMemory", func(ctx *ntapi.TrapContext) uint32 {
			nSize := ctx.Arg(3)
			if nSize > 0 {
				data, _ := ctx.Mem.ReadBytes(ctx.Arg(2), int(nSize))
				ctx.Mem.WriteBytes(ctx.Arg(1), data)
			}
			if bw := ctx.Arg(4); bw != 0 { ctx.Mem.Write64(bw, nSize) }
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "WriteProfileSectionA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "WriteProfileSectionW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "WriteProfileStringA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "WriteProfileStringW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "WriteTapemark", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // NO_ERROR
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "ZombifyActCtx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "_DebugOut", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "_DebugPrintf", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "__C_specific_handler", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "__chkstk", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "_hread", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "_hwrite", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "_lclose", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0xFFFF) // error
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "_lcreat", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0xFFFF) // error
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "_llseek", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0xFFFF) // error
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "_local_unwind", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "_lopen", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0xFFFF) // error
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "_lread", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0xFFFF) // error
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "_lwrite", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0xFFFF) // error
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "dprintf", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "lstrcat", func(ctx *ntapi.TrapContext) uint32 {
			dst := ctx.Arg(0)
			src := ctx.Arg(1)
			s1 := readGuestString(dst)
			s2 := readGuestString(src)
			combined := s1 + s2
			ctx.Mem.WriteBytes(dst+uint64(len(s1)), append([]byte(s2), 0))
			ctx.SetReturn(uint64(len(combined)))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "lstrcatA", func(ctx *ntapi.TrapContext) uint32 {
			dst := ctx.Arg(0)
			src := ctx.Arg(1)
			s1 := readGuestString(dst)
			s2 := readGuestString(src)
			ctx.Mem.WriteBytes(dst+uint64(len(s1)), append([]byte(s2), 0))
			ctx.SetReturn(dst)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "lstrcatW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(ctx.Arg(0)) // lpString1
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "lstrcmp", func(ctx *ntapi.TrapContext) uint32 {
			s1 := readGuestString(ctx.Arg(0))
			s2 := readGuestString(ctx.Arg(1))
			if s1 < s2 {
				ctx.SetReturn(0xFFFFFFFF)
			} else if s1 > s2 {
				ctx.SetReturn(1)
			} else {
				ctx.SetReturn(0)
			}
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "lstrcmpA", func(ctx *ntapi.TrapContext) uint32 {
			s1 := readGuestString(ctx.Arg(0))
			s2 := readGuestString(ctx.Arg(1))
			if s1 < s2 {
				ctx.SetReturn(0xFFFFFFFF)
			} else if s1 > s2 {
				ctx.SetReturn(1)
			} else {
				ctx.SetReturn(0)
			}
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "lstrcmpi", func(ctx *ntapi.TrapContext) uint32 {
			s1 := strings.ToLower(readGuestString(ctx.Arg(0)))
			s2 := strings.ToLower(readGuestString(ctx.Arg(1)))
			if s1 < s2 {
				ctx.SetReturn(0xFFFFFFFF)
			} else if s1 > s2 {
				ctx.SetReturn(1)
			} else {
				ctx.SetReturn(0)
			}
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "lstrcpy", func(ctx *ntapi.TrapContext) uint32 {
			dst := ctx.Arg(0)
			src := readGuestString(ctx.Arg(1))
			ctx.Mem.WriteBytes(dst, append([]byte(src), 0))
			ctx.SetReturn(dst)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "lstrcpyA", func(ctx *ntapi.TrapContext) uint32 {
			dst := ctx.Arg(0)
			src := readGuestString(ctx.Arg(1))
			ctx.Mem.WriteBytes(dst, append([]byte(src), 0))
			ctx.SetReturn(dst)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "lstrcpyn", func(ctx *ntapi.TrapContext) uint32 {
			dst := ctx.Arg(0)
			src := readGuestString(ctx.Arg(1))
			n := int(ctx.Arg(2))
			if n <= 0 {
				ctx.SetReturn(dst)
				return 0
			}
			if len(src) >= n {
				src = src[:n-1]
			}
			ctx.Mem.WriteBytes(dst, append([]byte(src), 0))
			ctx.SetReturn(dst)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "lstrlen", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(uint64(len(readGuestString(ctx.Arg(0)))))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "lstrlenA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(uint64(len(readGuestString(ctx.Arg(0)))))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "timeBeginPeriod", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "timeEndPeriod", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "timeGetDevCaps", func(ctx *ntapi.TrapContext) uint32 {
			ptc := ctx.Arg(0)
			if ptc != 0 {
				ctx.Mem.Write32(ptc, 1)
				ctx.Mem.Write32(ptc+4, 0xFFFFFFFF)
			}
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "timeGetSystemTime", func(ctx *ntapi.TrapContext) uint32 {
			pmmt := ctx.Arg(0)
			if pmmt != 0 {
				ctx.Mem.Write32(pmmt, uint32(time.Since(startTime).Milliseconds()))
			}
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "timeGetTime", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(uint64(time.Since(startTime).Milliseconds()))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "wine_get_dos_file_name", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "wine_get_unix_file_name", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})

	}

	// --- shcore.dll ---
	delayHandlerRegistrars = append(delayHandlerRegistrars, func() {
	if shcore, ok := synthByName["shcore.dll"]; ok {
		nextDynID := uint32(ntapi.DynExportIDBase + 0x100) // offset to avoid user32 collision
		d.RegisterDynamicHandler(mem, shcore, "GetDpiForMonitor", nextDynID, func(ctx *ntapi.TrapContext) uint32 {
			// hMonitor, dpiType, *dpiX, *dpiY → S_OK
			dpiX := ctx.Arg(2)
			dpiY := ctx.Arg(3)
			if dpiX != 0 { mem.Write32(dpiX, 96) }
			if dpiY != 0 { mem.Write32(dpiY, 96) }
			ctx.SetReturn(0) // S_OK
			return 0
		}); nextDynID++
		d.RegisterDynamicHandler(mem, shcore, "GetScaleFactorForMonitor", nextDynID, func(ctx *ntapi.TrapContext) uint32 {
			// hMonitor, *pScale → S_OK
			pScale := ctx.Arg(1)
			if pScale != 0 { mem.Write32(pScale, 100) } // SCALE_100_PERCENT
			ctx.SetReturn(0) // S_OK
			return 0
		}); nextDynID++
		_ = nextDynID
	}
	})
	delayHandlerRegistrars[len(delayHandlerRegistrars)-1]()

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
		// PathFindFileNameW: returns pointer to filename component within the path
		d.RegisterAutoStubHandler(shlwapi, "PathFindFileNameW", func(ctx *ntapi.TrapContext) uint32 {
			path := ctx.Arg(0)
			if path == 0 {
				ctx.SetReturn(0)
				return 0
			}
			lastSlash := path
			for i := uint64(0); ; i += 2 {
				w, _ := ctx.Mem.Read16(path + i)
				if w == 0 {
					break
				}
				if w == '\\' || w == '/' {
					lastSlash = path + i + 2
				}
			}
			ctx.SetReturn(lastSlash)
			return 0
		})
		// PathFindExtensionW: returns pointer to the extension (".xxx") within path, or end-of-string
		d.RegisterAutoStubHandler(shlwapi, "PathFindExtensionW", func(ctx *ntapi.TrapContext) uint32 {
			path := ctx.Arg(0)
			if path == 0 {
				ctx.SetReturn(0)
				return 0
			}
			ext := uint64(0)
			for i := uint64(0); ; i += 2 {
				w, _ := ctx.Mem.Read16(path + i)
				if w == 0 {
					if ext == 0 {
						ext = path + i // point to NUL terminator
					}
					break
				}
				if w == '.' {
					ext = path + i
				} else if w == '\\' || w == '/' {
					ext = 0 // reset: dot was in a directory component
				}
			}
			if ext == 0 {
				// find end of string
				for i := uint64(0); ; i += 2 {
					w, _ := ctx.Mem.Read16(path + i)
					if w == 0 {
						ext = path + i
						break
					}
				}
			}
			ctx.SetReturn(ext)
			return 0
		})
		// PathIsNetworkPathW: returns TRUE for UNC paths (\\server\share) or drive letters mapped to net
		d.RegisterAutoStubHandler(shlwapi, "PathIsNetworkPathW", func(ctx *ntapi.TrapContext) uint32 {
			path := ctx.Arg(0)
			if path == 0 {
				ctx.SetReturn(0)
				return 0
			}
			w0, _ := ctx.Mem.Read16(path)
			w1, _ := ctx.Mem.Read16(path + 2)
			if (w0 == '\\' || w0 == '/') && (w1 == '\\' || w1 == '/') {
				ctx.SetReturn(1)
			} else {
				ctx.SetReturn(0)
			}
			return 0
		})
		// PathStripPathW: remove directory component in-place, keep only filename
		d.RegisterAutoStubHandler(shlwapi, "PathStripPathW", func(ctx *ntapi.TrapContext) uint32 {
			path := ctx.Arg(0)
			if path == 0 {
				return 0
			}
			lastSep := uint64(0xFFFFFFFFFFFFFFFF)
			for i := uint64(0); ; i += 2 {
				w, _ := ctx.Mem.Read16(path + i)
				if w == 0 {
					break
				}
				if w == '\\' || w == '/' {
					lastSep = i
				}
			}
			if lastSep != 0xFFFFFFFFFFFFFFFF {
				src := path + lastSep + 2
				dst := path
				for {
					w, _ := ctx.Mem.Read16(src)
					ctx.Mem.Write16(dst, w)
					src += 2
					dst += 2
					if w == 0 {
						break
					}
				}
			}
			return 0
		})
		// PathAddExtensionW: append extension to path if it has none
		d.RegisterAutoStubHandler(shlwapi, "PathAddExtensionW", func(ctx *ntapi.TrapContext) uint32 {
			path := ctx.Arg(0)
			ext := ctx.Arg(1)
			if path == 0 {
				ctx.SetReturn(0)
				return 0
			}
			hasDot := false
			pathLen := uint64(0)
			for i := uint64(0); ; i += 2 {
				w, _ := ctx.Mem.Read16(path + i)
				if w == 0 {
					pathLen = i
					break
				}
				if w == '\\' || w == '/' {
					hasDot = false
				} else if w == '.' {
					hasDot = true
				}
			}
			if hasDot {
				ctx.SetReturn(0) // already has extension
				return 0
			}
			if ext == 0 {
				ctx.SetReturn(0)
				return 0
			}
			end := path + pathLen
			for i := uint64(0); ; i += 2 {
				w, _ := ctx.Mem.Read16(ext + i)
				ctx.Mem.Write16(end+i, w)
				if w == 0 {
					break
				}
			}
			ctx.SetReturn(1)
			return 0
		})
		// PathAppendW: append pszMore to pszPath with backslash separator
		d.RegisterAutoStubHandler(shlwapi, "PathAppendW", func(ctx *ntapi.TrapContext) uint32 {
			pszPath := ctx.Arg(0)
			pszMore := ctx.Arg(1)
			if pszPath == 0 {
				ctx.SetReturn(0)
				return 0
			}
			// Find end of pszPath
			end := uint64(0)
			for i := uint64(0); ; i += 2 {
				w, _ := ctx.Mem.Read16(pszPath + i)
				if w == 0 {
					end = pszPath + i
					break
				}
			}
			// Add separator if path doesn't end with one
			if end > pszPath {
				prev, _ := ctx.Mem.Read16(end - 2)
				if prev != '\\' && prev != '/' {
					ctx.Mem.Write16(end, '\\')
					end += 2
				}
			}
			// Copy pszMore
			if pszMore != 0 {
				// Skip leading separators in pszMore
				moreStart := pszMore
				for {
					w, _ := ctx.Mem.Read16(moreStart)
					if w != '\\' && w != '/' {
						break
					}
					moreStart += 2
				}
				for i := uint64(0); ; i += 2 {
					w, _ := ctx.Mem.Read16(moreStart + i)
					ctx.Mem.Write16(end+i, w)
					if w == 0 {
						break
					}
				}
			} else {
				ctx.Mem.Write16(end, 0)
			}
			ctx.SetReturn(1)
			return 0
		})
		// PathCombineW: combine directory + file into dest
		d.RegisterAutoStubHandler(shlwapi, "PathCombineW", func(ctx *ntapi.TrapContext) uint32 {
			lpszDest := ctx.Arg(0)
			lpszDir := ctx.Arg(1)
			lpszFile := ctx.Arg(2)
			if lpszDest == 0 {
				ctx.SetReturn(0)
				return 0
			}
			writeWStr := func(dst uint64, s string) {
				for i, r := range []rune(s) {
					ctx.Mem.Write16(dst+uint64(i)*2, uint16(r))
				}
				ctx.Mem.Write16(dst+uint64(len([]rune(s)))*2, 0)
			}
			// If lpszFile is absolute, use it directly
			if lpszFile != 0 {
				w0, _ := ctx.Mem.Read16(lpszFile)
				w1, _ := ctx.Mem.Read16(lpszFile + 2)
				isAbsolute := (w1 == ':') || (w0 == '\\' || w0 == '/')
				if isAbsolute {
					for i := uint64(0); ; i += 2 {
						w, _ := ctx.Mem.Read16(lpszFile + i)
						ctx.Mem.Write16(lpszDest+i, w)
						if w == 0 {
							break
						}
					}
					ctx.SetReturn(lpszDest)
					return 0
				}
			}
			// Build combined path
			dir := ""
			if lpszDir != 0 {
				dir = readGuestUTF16(lpszDir)
			}
			file := ""
			if lpszFile != 0 {
				file = readGuestUTF16(lpszFile)
			}
			if dir == "" {
				writeWStr(lpszDest, file)
			} else if file == "" {
				writeWStr(lpszDest, dir)
			} else {
				sep := ""
				if len(dir) > 0 && dir[len(dir)-1] != '\\' && dir[len(dir)-1] != '/' {
					sep = "\\"
				}
				writeWStr(lpszDest, dir+sep+file)
			}
			ctx.SetReturn(lpszDest)
			return 0
		})
		// PathIsRelativeW: TRUE if path has no drive letter and doesn't start with \\
		d.RegisterAutoStubHandler(shlwapi, "PathIsRelativeW", func(ctx *ntapi.TrapContext) uint32 {
			path := ctx.Arg(0)
			if path == 0 {
				ctx.SetReturn(1)
				return 0
			}
			w0, _ := ctx.Mem.Read16(path)
			w1, _ := ctx.Mem.Read16(path + 2)
			if w1 == ':' || (w0 == '\\' && w1 == '\\') || (w0 == '/') {
				ctx.SetReturn(0) // absolute
			} else {
				ctx.SetReturn(1) // relative
			}
			return 0
		})
		// PathRemoveExtensionW: strip the extension from path in-place
		d.RegisterAutoStubHandler(shlwapi, "PathRemoveExtensionW", func(ctx *ntapi.TrapContext) uint32 {
			path := ctx.Arg(0)
			if path == 0 {
				return 0
			}
			dotOff := uint64(0xFFFFFFFFFFFFFFFF)
			for i := uint64(0); ; i += 2 {
				w, _ := ctx.Mem.Read16(path + i)
				if w == 0 {
					break
				}
				if w == '\\' || w == '/' {
					dotOff = 0xFFFFFFFFFFFFFFFF
				} else if w == '.' {
					dotOff = i
				}
			}
			if dotOff != 0xFFFFFFFFFFFFFFFF {
				ctx.Mem.Write16(path+dotOff, 0)
			}
			return 0
		})
		// PathCompactPathExW: truncate path to cchMax characters
		d.RegisterAutoStubHandler(shlwapi, "PathCompactPathExW", func(ctx *ntapi.TrapContext) uint32 {
			pszOut := ctx.Arg(0)
			pszSrc := ctx.Arg(1)
			cchMax := ctx.Arg(2)
			if pszOut == 0 || pszSrc == 0 || cchMax == 0 {
				ctx.SetReturn(0)
				return 0
			}
			// Collect source characters
			var runes []uint16
			for i := uint64(0); ; i += 2 {
				w, _ := ctx.Mem.Read16(pszSrc + i)
				if w == 0 {
					break
				}
				runes = append(runes, w)
			}
			limit := int(cchMax) - 1
			if limit < 0 {
				limit = 0
			}
			if len(runes) > limit {
				// Replace middle with "..." if possible
				if limit > 5 {
					half := (limit - 3) / 2
					var out []uint16
					out = append(out, runes[:half]...)
					out = append(out, '.', '.', '.')
					out = append(out, runes[len(runes)-half:]...)
					runes = out[:limit]
				} else {
					runes = runes[:limit]
				}
			}
			for i, w := range runes {
				ctx.Mem.Write16(pszOut+uint64(i)*2, w)
			}
			ctx.Mem.Write16(pszOut+uint64(len(runes))*2, 0)
			ctx.SetReturn(1)
			return 0
		})
		// PathGetDriveNumberW: return drive index (0='A') or -1 if none
		d.RegisterAutoStubHandler(shlwapi, "PathGetDriveNumberW", func(ctx *ntapi.TrapContext) uint32 {
			path := ctx.Arg(0)
			if path == 0 {
				ctx.SetReturn(0xFFFFFFFF) // (DWORD)-1
				return 0
			}
			w0, _ := ctx.Mem.Read16(path)
			w1, _ := ctx.Mem.Read16(path + 2)
			if w1 == ':' {
				var drv uint16
				if w0 >= 'a' && w0 <= 'z' {
					drv = w0 - 'a'
				} else if w0 >= 'A' && w0 <= 'Z' {
					drv = w0 - 'A'
				} else {
					ctx.SetReturn(0xFFFFFFFF)
					return 0
				}
				ctx.SetReturn(uint64(drv))
			} else {
				ctx.SetReturn(0xFFFFFFFF)
			}
			return 0
		})
		// PathMatchSpecW: simple wildcard match (* and ?)
		d.RegisterAutoStubHandler(shlwapi, "PathMatchSpecW", func(ctx *ntapi.TrapContext) uint32 {
			pszFile := ctx.Arg(0)
			pszSpec := ctx.Arg(1)
			if pszFile == 0 || pszSpec == 0 {
				ctx.SetReturn(0)
				return 0
			}
			file := readGuestUTF16(pszFile)
			spec := readGuestUTF16(pszSpec)
			// Simple case-insensitive wildcard match
			var matchFn func(f, s string) bool
			matchFn = func(f, s string) bool {
				for len(s) > 0 {
					sc := rune(s[0])
					s = s[1:]
					switch sc {
					case '*':
						for i := 0; i <= len(f); i++ {
							if matchFn(f[i:], s) {
								return true
							}
						}
						return false
					case '?':
						if len(f) == 0 {
							return false
						}
						f = f[1:]
					default:
						if len(f) == 0 {
							return false
						}
						fc := rune(f[0])
						f = f[1:]
						if fc >= 'A' && fc <= 'Z' {
							fc += 32
						}
						if sc >= 'A' && sc <= 'Z' {
							sc += 32
						}
						if fc != sc {
							return false
						}
					}
				}
				return len(f) == 0
			}
			if matchFn(file, spec) {
				ctx.SetReturn(1)
			} else {
				ctx.SetReturn(0)
			}
			return 0
		})
		// AssocQueryStringW: file type association query - not supported in emulator
		d.RegisterAutoStubHandler(shlwapi, "AssocQueryStringW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x80004005) // E_FAIL - no associations
			return 0
		})
		// ColorAdjustLuma: adjust luminosity of a COLORREF by n/240
		d.RegisterAutoStubHandler(shlwapi, "ColorAdjustLuma", func(ctx *ntapi.TrapContext) uint32 {
			clr := uint32(ctx.Arg(0))
			n := int32(ctx.Arg(1))
			fScale := ctx.Arg(2) != 0
			r := float64(clr&0xFF) / 255
			g := float64((clr>>8)&0xFF) / 255
			b := float64((clr>>16)&0xFF) / 255
			maxC := math.Max(math.Max(r, g), b)
			minC := math.Min(math.Min(r, g), b)
			l := (maxC + minC) / 2
			var h, s float64
			if maxC != minC {
				d2 := maxC - minC
				if l > 0.5 {
					s = d2 / (2 - maxC - minC)
				} else {
					s = d2 / (maxC + minC)
				}
				switch maxC {
				case r:
					h = (g - b) / d2
					if g < b {
						h += 6
					}
				case g:
					h = (b-r)/d2 + 2
				case b:
					h = (r-g)/d2 + 4
				}
				h /= 6
			}
			// Adjust luma
			delta := float64(n) / 240
			if fScale {
				if n > 0 {
					l += (1 - l) * delta
				} else {
					l += l * delta
				}
			} else {
				l += delta
			}
			if l < 0 {
				l = 0
			} else if l > 1 {
				l = 1
			}
			// Convert back HLS→RGB
			hue2rgb := func(p, q, t float64) float64 {
				if t < 0 {
					t++
				}
				if t > 1 {
					t--
				}
				if t < 1.0/6 {
					return p + (q-p)*6*t
				}
				if t < 1.0/2 {
					return q
				}
				if t < 2.0/3 {
					return p + (q-p)*(2.0/3-t)*6
				}
				return p
			}
			var nr, ng, nb float64
			if s == 0 {
				nr, ng, nb = l, l, l
			} else {
				var q float64
				if l < 0.5 {
					q = l * (1 + s)
				} else {
					q = l + s - l*s
				}
				p := 2*l - q
				nr = hue2rgb(p, q, h+1.0/3)
				ng = hue2rgb(p, q, h)
				nb = hue2rgb(p, q, h-1.0/3)
			}
			result := uint32(nr*255) | uint32(ng*255)<<8 | uint32(nb*255)<<16
			ctx.SetReturn(uint64(result))
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
			switch int32(folder) & 0xFF {
			case 0x00: path = `C:\Users\user\Desktop`           // CSIDL_DESKTOP
			case 0x05: path = `C:\Users\user\Documents`         // CSIDL_MYDOCUMENTS
			case 0x08: path = `C:\Users\user\AppData\Roaming\Microsoft\Windows\Recent` // CSIDL_RECENT
			case 0x09: path = `C:\Users\user\AppData\Roaming\Microsoft\Windows\SendTo` // CSIDL_SENDTO
			case 0x0B: path = `C:\Users\user\AppData\Roaming\Microsoft\Windows\Start Menu` // CSIDL_STARTMENU
			case 0x0D: path = `C:\Users\user\Music`             // CSIDL_MYMUSIC
			case 0x0E: path = `C:\Users\user\Videos`            // CSIDL_MYVIDEO
			case 0x10: path = `C:\Windows\Desktop`              // CSIDL_DESKTOPDIRECTORY
			case 0x11: path = `C:\`                             // CSIDL_DRIVES
			case 0x14: path = `C:\Users\user\Favorites`         // CSIDL_FAVORITES
			case 0x1A: path = `C:\Users\user\AppData\Roaming`   // CSIDL_APPDATA
			case 0x1C: path = `C:\Users\user\AppData\Local`     // CSIDL_LOCAL_APPDATA
			case 0x1D: path = `C:\Windows\Temp`                 // CSIDL_INTERNET_CACHE
			case 0x24: path = `C:\Windows`                      // CSIDL_WINDOWS
			case 0x25: path = `C:\Windows\System32`             // CSIDL_SYSTEM
			case 0x26: path = `C:\Program Files`                // CSIDL_PROGRAM_FILES
			case 0x27: path = `C:\Users\user\Pictures`          // CSIDL_MYPICTURES
			case 0x28: path = `C:\Users\user`                   // CSIDL_PROFILE
			case 0x29: path = `C:\Windows\System32`             // CSIDL_SYSTEMX86
			case 0x2A: path = `C:\Program Files`                // CSIDL_PROGRAM_FILESX86
			case 0x2B: path = `C:\Program Files\Common Files`   // CSIDL_PROGRAM_FILES_COMMON
			default:   path = `C:\Users\user`
			}
			if buf != 0 {
				for i, ch := range path {
					ctx.Mem.Write16(buf+uint64(i*2), uint16(ch))
				}
				ctx.Mem.Write16(buf+uint64(len(path)*2), 0)
			}
			ctx.SetReturn(0) // S_OK
			return 0
		})
		d.RegisterAutoStubHandler(shell32, "DragAcceptFiles", func(ctx *ntapi.TrapContext) uint32 {
			return 0
		})
		d.RegisterAutoStubHandler(shell32, "SHGetKnownFolderPath", func(ctx *ntapi.TrapContext) uint32 {
			// rfid = Arg(0) pointer to KNOWNFOLDERID GUID, ppszPath = Arg(2)
			ppszPath := ctx.Arg(2)
			path := `C:\Users\user\AppData\Roaming`
			ws := utf16Encode(path)
			bufSize := uint64(len(ws)+1) * 2
			addr := mem.Mmap(0, bufSize, mmu.PermRead|mmu.PermWrite)
			for i, w := range ws { mem.Write16(addr+uint64(i)*2, w) }
			mem.Write16(addr+uint64(len(ws))*2, 0)
			if ppszPath != 0 { ctx.Mem.Write64(ppszPath, addr) }
			ctx.SetReturn(0) // S_OK
			return 0
		})
		d.RegisterAutoStubHandler(shell32, "SHCreateDirectoryExW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // S_OK
			return 0
		})
		d.RegisterAutoStubHandler(shell32, "DragQueryFileW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // 0 files in drop
			return 0
		})
		d.RegisterAutoStubHandler(shell32, "DragQueryPoint", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE - point is not in client area
			return 0
		})
		d.RegisterAutoStubHandler(shell32, "DragFinish", func(ctx *ntapi.TrapContext) uint32 {
			return 0 // no-op
		})
		d.RegisterAutoStubHandler(shell32, "ShellExecuteW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(33) // >32 means success (SE_ERR_NOASSOC=31, success=32+)
			return 0
		})
		d.RegisterAutoStubHandler(shell32, "SHFileOperationW", func(ctx *ntapi.TrapContext) uint32 {
			// Clear fAnyOperationsAborted in SHFILEOPSTRUCT (offset 36 = 0x24)
			lpFileOp := ctx.Arg(0)
			if lpFileOp != 0 {
				ctx.Mem.Write32(lpFileOp+36, 0)
			}
			ctx.SetReturn(0) // success
			return 0
		})
		d.RegisterAutoStubHandler(shell32, "SHCreateItemFromParsingName", func(ctx *ntapi.TrapContext) uint32 {
			ppv := ctx.Arg(3)
			if ppv != 0 {
				ctx.Mem.Write64(ppv, 0)
			}
			ctx.SetReturn(0x80004001) // E_NOTIMPL
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
		// PrintDlgW: print dialog - return FALSE (user cancelled / not supported)
		d.RegisterAutoStubHandler(comdlg32, "PrintDlgW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE - user cancelled
			return 0
		})
		// ChooseColorW: color picker dialog - return FALSE (user cancelled)
		d.RegisterAutoStubHandler(comdlg32, "ChooseColorW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE - user cancelled
			return 0
		})
	}
	})
	delayHandlerRegistrars[len(delayHandlerRegistrars)-1]()

	// --- advapi32.dll ---

	delayHandlerRegistrars = append(delayHandlerRegistrars, func() {
	if advapi32, ok := synthByName["advapi32.dll"]; ok {
		d.RegisterAutoStubHandler(advapi32, "RegOpenKeyExW", func(ctx *ntapi.TrapContext) uint32 {
			subKey := readGuestUTF16(ctx.Arg(1))
			path := regKeyPath(ctx.Arg(0), subKey)
			key := ctx.Reg.OpenKey(path)
			if key == nil {
				if regIsProbeKey(path) {
					ctx.SetReturn(2) // ERROR_FILE_NOT_FOUND
					return 0
				}
				key = ctx.Reg.CreateKey(path)
			}
			h := handles.Alloc(&ntapi.RegistryKeyHandle{Hive: regHive, Key: key, Path: path})
			if phk := ctx.Arg(4); phk != 0 { ctx.Mem.Write64(phk, uint64(h)) }
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(advapi32, "RegOpenKeyW", func(ctx *ntapi.TrapContext) uint32 {
			subKey := readGuestUTF16(ctx.Arg(1))
			path := regKeyPath(ctx.Arg(0), subKey)
			key := ctx.Reg.OpenKey(path)
			if key == nil {
				if regIsProbeKey(path) {
					ctx.SetReturn(2) // ERROR_FILE_NOT_FOUND
					return 0
				}
				key = ctx.Reg.CreateKey(path)
			}
			h := handles.Alloc(&ntapi.RegistryKeyHandle{Hive: regHive, Key: key, Path: path})
			if phk := ctx.Arg(2); phk != 0 { ctx.Mem.Write64(phk, uint64(h)) }
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(advapi32, "RegCloseKey", func(ctx *ntapi.TrapContext) uint32 {
			handles.Close(ntapi.Handle(ctx.Arg(0)))
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(advapi32, "RegQueryValueExW", func(ctx *ntapi.TrapContext) uint32 {
			valueName := readGuestUTF16(ctx.Arg(1))
			ctx.SetReturn(uint64(regQueryValue(ctx, ctx.Arg(0), valueName)))
			return 0
		})
		d.RegisterAutoStubHandler(advapi32, "RegSetValueExW", func(ctx *ntapi.TrapContext) uint32 {
			rk := handles.GetRegKey(ntapi.Handle(ctx.Arg(0)))
			if rk != nil && rk.Key != nil {
				name := readGuestUTF16(ctx.Arg(1))
				valType := uint32(ctx.Arg(3))
				dataLen := int(ctx.Arg(5))
				data, _ := ctx.Mem.ReadBytes(ctx.Arg(4), dataLen)
				if rk.Key.Values == nil { rk.Key.Values = make(map[string]*ntapi.RegistryValue) }
				rk.Key.Values[name] = &ntapi.RegistryValue{Name: name, Type: valType, Data: data}
			}
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(advapi32, "RegCreateKeyExW", func(ctx *ntapi.TrapContext) uint32 {
			subKey := readGuestUTF16(ctx.Arg(1))
			path := regKeyPath(ctx.Arg(0), subKey)
			existed := ctx.Reg.OpenKey(path) != nil
			key := ctx.Reg.CreateKey(path)
			h := handles.Alloc(&ntapi.RegistryKeyHandle{Hive: regHive, Key: key, Path: path})
			if phk := ctx.Arg(6); phk != 0 { ctx.Mem.Write64(phk, uint64(h)) }
			if disp := ctx.Arg(7); disp != 0 {
				if existed { ctx.Mem.Write32(disp, 2) } else { ctx.Mem.Write32(disp, 1) }
			}
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(advapi32, "RegEnumKeyExW", func(ctx *ntapi.TrapContext) uint32 {
			rk := handles.GetRegKey(ntapi.Handle(ctx.Arg(0)))
			if rk == nil || rk.Key == nil { ctx.SetReturn(259); return 0 }
			names := ctx.Reg.EnumerateKeys(rk.Key)
			idx := uint32(ctx.Arg(1))
			if int(idx) >= len(names) { ctx.SetReturn(259); return 0 }
			ws := utf16Encode(names[idx])
			if buf := ctx.Arg(2); buf != 0 {
				for i, w := range ws { ctx.Mem.Write16(buf+uint64(i)*2, w) }
				ctx.Mem.Write16(buf+uint64(len(ws))*2, 0)
			}
			if lp := ctx.Arg(3); lp != 0 { ctx.Mem.Write32(lp, uint32(len(ws))) }
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(advapi32, "RegEnumValueW", func(ctx *ntapi.TrapContext) uint32 {
			rk := handles.GetRegKey(ntapi.Handle(ctx.Arg(0)))
			if rk == nil || rk.Key == nil { ctx.SetReturn(259); return 0 }
			vnames := ctx.Reg.EnumerateValues(rk.Key)
			idx := uint32(ctx.Arg(1))
			if int(idx) >= len(vnames) { ctx.SetReturn(259); return 0 }
			name := vnames[idx]; val := rk.Key.Values[name]
			ws := utf16Encode(name)
			if buf := ctx.Arg(2); buf != 0 {
				for i, w := range ws { ctx.Mem.Write16(buf+uint64(i)*2, w) }
				ctx.Mem.Write16(buf+uint64(len(ws))*2, 0)
			}
			if lp := ctx.Arg(3); lp != 0 { ctx.Mem.Write32(lp, uint32(len(ws))) }
			if lpType := ctx.Arg(5); lpType != 0 { ctx.Mem.Write32(lpType, val.Type) }
			needed := uint32(len(val.Data))
			if lpcb := ctx.Arg(7); lpcb != 0 { avail, _ := ctx.Mem.Read32(lpcb); ctx.Mem.Write32(lpcb, needed); if ctx.Arg(6) != 0 && avail < needed { ctx.SetReturn(234); return 0 } }
			if lpData := ctx.Arg(6); lpData != 0 { ctx.Mem.WriteBytes(lpData, val.Data) }
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(advapi32, "RegQueryInfoKeyW", func(ctx *ntapi.TrapContext) uint32 {
			rk := handles.GetRegKey(ntapi.Handle(ctx.Arg(0)))
			var nSubKeys, nValues uint32
			if rk != nil && rk.Key != nil {
				nSubKeys = uint32(len(rk.Key.Children))
				nValues = uint32(len(rk.Key.Values))
			}
			if p := ctx.Arg(4); p != 0 { ctx.Mem.Write32(p, nSubKeys) }
			if p := ctx.Arg(7); p != 0 { ctx.Mem.Write32(p, nValues) }
			for _, i := range []int{2, 3, 5, 6, 8, 9, 10} {
				if p := ctx.Arg(i); p != 0 { ctx.Mem.Write32(p, 0) }
			}
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(advapi32, "RegDeleteValueW", func(ctx *ntapi.TrapContext) uint32 {
			rk := handles.GetRegKey(ntapi.Handle(ctx.Arg(0)))
			if rk != nil && rk.Key != nil {
				name := readGuestUTF16(ctx.Arg(1))
				for k := range rk.Key.Values {
					if strings.EqualFold(k, name) { delete(rk.Key.Values, k); break }
				}
			}
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

		// GetUserNameA: write ANSI username "User"
		d.RegisterAutoStubHandler(advapi32, "GetUserNameA", func(ctx *ntapi.TrapContext) uint32 {
			buf := ctx.Arg(0)
			size := ctx.Arg(1)
			name := "User"
			if size != 0 {
				ctx.Mem.Write32(size, uint32(len(name)+1))
			}
			if buf != 0 {
				for i := 0; i < len(name); i++ {
					ctx.Mem.Write8(buf+uint64(i), name[i])
				}
				ctx.Mem.Write8(buf+uint64(len(name)), 0)
			}
			ctx.SetReturn(1)
			return 0
		})

		// RegOpenKeyExA: convert ANSI subkey name then use same logic as RegOpenKeyExW
		d.RegisterAutoStubHandler(advapi32, "RegOpenKeyExA", func(ctx *ntapi.TrapContext) uint32 {
			subKey := readGuestString(ctx.Arg(1))
			path := regKeyPath(ctx.Arg(0), subKey)
			key := ctx.Reg.OpenKey(path)
			if key == nil {
				if regIsProbeKey(path) {
					ctx.SetReturn(2) // ERROR_FILE_NOT_FOUND
					return 0
				}
				key = ctx.Reg.CreateKey(path)
			}
			h := handles.Alloc(&ntapi.RegistryKeyHandle{Hive: regHive, Key: key, Path: path})
			if phk := ctx.Arg(4); phk != 0 { ctx.Mem.Write64(phk, uint64(h)) }
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(advapi32, "RegQueryValueExA", func(ctx *ntapi.TrapContext) uint32 {
			valueName := readGuestString(ctx.Arg(1))
			ctx.SetReturn(uint64(regQueryValue(ctx, ctx.Arg(0), valueName)))
			return 0
		})
		d.RegisterAutoStubHandler(advapi32, "RegGetValueW", func(ctx *ntapi.TrapContext) uint32 {
			// RegGetValueW(hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData)
			hKey := ctx.Arg(0)
			subKey := readGuestUTF16(ctx.Arg(1))
			valueName := readGuestUTF16(ctx.Arg(2))
			if subKey != "" {
				path := regKeyPath(hKey, subKey)
				key := ctx.Reg.OpenKey(path)
				if key == nil { ctx.SetReturn(2); return 0 }
				h := handles.Alloc(&ntapi.RegistryKeyHandle{Hive: regHive, Key: key, Path: path})
				ctx.SetReturn(uint64(regQueryValue(ctx, uint64(h), valueName)))
			} else {
				ctx.SetReturn(uint64(regQueryValue(ctx, hKey, valueName)))
			}
			return 0
		})
		d.RegisterAutoStubHandler(advapi32, "RegDeleteKeyW", func(ctx *ntapi.TrapContext) uint32 {
			subKey := readGuestUTF16(ctx.Arg(1))
			path := regKeyPath(ctx.Arg(0), subKey)
			ctx.Reg.DeleteKey(path)
			ctx.SetReturn(0)
			return 0
		})
		// CryptAcquireContextW: acquire a CSP handle
		d.RegisterAutoStubHandler(advapi32, "CryptAcquireContextW", func(ctx *ntapi.TrapContext) uint32 {
			phProv := ctx.Arg(0)
			if phProv != 0 {
				ctx.Mem.Write64(phProv, 0xC0DE1234)
			}
			ctx.SetReturn(1) // TRUE
			return 0
		})
		// CryptCreateHash, CryptHashData, CryptGetHashParam, CryptDestroyHash, CryptReleaseContext
		d.RegisterAutoStubHandler(advapi32, "CryptCreateHash", func(ctx *ntapi.TrapContext) uint32 {
			phHash := ctx.Arg(3)
			if phHash != 0 {
				ctx.Mem.Write64(phHash, 0xC0DE5678) // fake hash handle
			}
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(advapi32, "CryptHashData", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(advapi32, "CryptGetHashParam", func(ctx *ntapi.TrapContext) uint32 {
			pbData := ctx.Arg(3)
			pdwDataLen := ctx.Arg(4)
			if pdwDataLen != 0 {
				n, _ := ctx.Mem.Read32(pdwDataLen)
				if pbData != 0 && n > 0 {
					// Write zeroed hash data
					for i := uint32(0); i < n && i < 64; i++ { ctx.Mem.Write8(pbData+uint64(i), 0) }
				}
			}
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(advapi32, "CryptDestroyHash", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(advapi32, "CryptReleaseContext", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(advapi32, "CryptGenRandom", func(ctx *ntapi.TrapContext) uint32 {
			dwLen := ctx.Arg(1)
			pbBuffer := ctx.Arg(2)
			if pbBuffer != 0 && dwLen > 0 {
				buf := make([]byte, dwLen)
				_, _ = unix.Getrandom(buf, 0)
				for i, b := range buf { ctx.Mem.Write8(pbBuffer+uint64(i), b) }
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(advapi32, "CryptEncrypt", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(advapi32, "CryptDecrypt", func(ctx *ntapi.TrapContext) uint32 {
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

	// bitmapHandles maps an HBITMAP handle to its decoded pixel data.
	// Used by LoadImageW/LoadBitmapW (store) and TB_ADDBITMAP (lookup).
	type bitmapHandleData struct {
		w, h  int
		slots [][]uint32 // per-slot XRGB pixels (for toolbar strip bitmaps)
		pix   []uint32   // flat XRGB pixels for single bitmap
	}
	bitmapHandles := make(map[uint64]*bitmapHandleData)
	var nextBitmapHandle uint64 = 0x00030001 // start from known value so old callers still work
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
	var focusHwnd uint64    // currently focused window (receives keyboard input)
	var mouseCapture uint64 // window that has captured the mouse (SetCapture)

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
	type tbButtonData struct {
		iBitmap   int32
		idCommand int32
		fsState   uint8
		fsStyle   uint8 // TBSTYLE_BUTTON=0, TBSTYLE_SEP=1, TBSTYLE_CHECK=2
	}
	type controlState struct {
		className    string
		parentHWND   uint64
		ctrlID       uint64   // control ID (hMenu param for child windows)
		x, y, w, h  int32
		style        uint32   // WS_* window style
		exStyle      uint32   // WS_EX_* extended style
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
		// Tab control state
		tabCount     int
		tabCurSel    int
		tabTitles    []string
		// Toolbar state
		tbButtons      []tbButtonData // stored via TB_ADDBUTTONSW
		tbBtnW         int32         // button width (from TB_SETBUTTONSIZE)
		tbBtnH         int32         // button height (from TB_SETBUTTONSIZE)
		tbBitmapIconW  int32         // icon width (from TB_SETBITMAPSIZE low word)
		tbBitmapIconH  int32         // icon height (from TB_SETBITMAPSIZE high word)
		tbBitmapStore  [][]uint32    // per-slot XRGB pixels (size = iconW*iconH per slot)
	}
	hwndChildren := make(map[uint64]*controlState)
	hwndTitle := make(map[uint64]string)

	// clientAreaOrigin returns the absolute (surface) coordinates of a
	// window's client-area top-left. For mainHWND with a menu bar the
	// client area starts below the menu; for child windows it's their
	// stored (absolute) position. The title-bar height is added to all
	// y values so that GDI drawing at app-y=0 lands below the title bar.
	clientAreaOrigin := func(hwnd uint64) (int32, int32) {
		tbH := int32(0)
		if wlWindow != nil {
			tbH = wlWindow.TitleBarH
		}
		if cs, ok := hwndChildren[hwnd]; ok {
			return cs.x, cs.y + tbH
		}
		if hwnd == mainHWND {
			if _, hasMenu := hwndMenuBar[mainHWND]; hasMenu {
				return 0, menuBarHeight + tbH
			}
		}
		return 0, tbH
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

		// ImageList_AddMasked - adds bitmap with mask colour; return index
		d.RegisterAutoStubHandler(comctl32, "ImageList_AddMasked", func(ctx *ntapi.TrapContext) uint32 {
			himl := ctx.Arg(0)
			idx := imageListCount[himl]
			imageListCount[himl]++
			ctx.SetReturn(idx)
			return 0
		})

		// ImageList_Add - adds bitmap without mask; return index
		d.RegisterAutoStubHandler(comctl32, "ImageList_Add", func(ctx *ntapi.TrapContext) uint32 {
			himl := ctx.Arg(0)
			idx := imageListCount[himl]
			imageListCount[himl]++
			ctx.SetReturn(idx)
			return 0
		})

		// ImageList_Remove - remove image at index (-1 = all)
		d.RegisterAutoStubHandler(comctl32, "ImageList_Remove", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})

		// ImageList_SetIconSize - set icon size for image list
		d.RegisterAutoStubHandler(comctl32, "ImageList_SetIconSize", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})

		// ImageList_Draw - draw image from list to HDC (no-op stub)
		d.RegisterAutoStubHandler(comctl32, "ImageList_Draw", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})

		// ImageList_DrawEx - extended draw (no-op stub)
		d.RegisterAutoStubHandler(comctl32, "ImageList_DrawEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})

		// ImageList_GetIconSize - return icon dimensions
		d.RegisterAutoStubHandler(comctl32, "ImageList_GetIconSize", func(ctx *ntapi.TrapContext) uint32 {
			pCx := ctx.Arg(1)
			pCy := ctx.Arg(2)
			if pCx != 0 {
				ctx.Mem.Write32(pCx, 16)
			}
			if pCy != 0 {
				ctx.Mem.Write32(pCy, 16)
			}
			ctx.SetReturn(1)
			return 0
		})

		// ImageList_SetBkColor
		d.RegisterAutoStubHandler(comctl32, "ImageList_SetBkColor", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0xFFFFFFFF) // CLR_NONE
			return 0
		})

		// ImageList_Copy
		d.RegisterAutoStubHandler(comctl32, "ImageList_Copy", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})

		// ── ImageList full coverage ──────────────────────────────────────────
		d.RegisterAutoStubHandler(comctl32, "ImageList_AddIcon", func(ctx *ntapi.TrapContext) uint32 {
			h := ctx.Arg(0)
			idx := comctl32pkg.ImageListAdd(h)
			ctx.SetReturn(uint64(int64(idx)))
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "ImageList_GetBkColor", func(ctx *ntapi.TrapContext) uint32 {
			h := ctx.Arg(0)
			ctx.SetReturn(uint64(comctl32pkg.ImageListGetBkColor(h)))
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "ImageList_SetBkColor", func(ctx *ntapi.TrapContext) uint32 {
			h := ctx.Arg(0)
			clr := uint32(ctx.Arg(1))
			ctx.SetReturn(uint64(comctl32pkg.ImageListSetBkColor(h, clr)))
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "ImageList_GetImageInfo", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "ImageList_GetImageRect", func(ctx *ntapi.TrapContext) uint32 {
			h := ctx.Arg(0)
			i := int32(ctx.Arg(1))
			prc := ctx.Arg(2)
			cx, cy, ok := comctl32pkg.ImageListGetIconSize(h)
			if ok && prc != 0 {
				x := i * cx
				ctx.Mem.Write32(prc, uint32(x))
				ctx.Mem.Write32(prc+4, 0)
				ctx.Mem.Write32(prc+8, uint32(x+cx))
				ctx.Mem.Write32(prc+12, uint32(cy))
			}
			if ok { ctx.SetReturn(1) } else { ctx.SetReturn(0) }
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "ImageList_GetIcon", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "ImageList_GetFlags", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "ImageList_SetFlags", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "ImageList_SetOverlayImage", func(ctx *ntapi.TrapContext) uint32 {
			h := ctx.Arg(0)
			iImg := int32(ctx.Arg(1))
			iOvl := int32(ctx.Arg(2))
			if comctl32pkg.ImageListSetOverlayImage(h, iImg, iOvl) { ctx.SetReturn(1) }
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "ImageList_GetDragImage", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "ImageList_BeginDrag", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "ImageList_EndDrag", func(ctx *ntapi.TrapContext) uint32 {
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "ImageList_DragEnter", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "ImageList_DragLeave", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "ImageList_DragMove", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "ImageList_DragShowNolock", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "ImageList_SetDragCursorImage", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "ImageList_Duplicate", func(ctx *ntapi.TrapContext) uint32 {
			h := ctx.Arg(0)
			ctx.SetReturn(comctl32pkg.ImageListDuplicate(h))
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "ImageList_Replace", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "ImageList_Merge", func(ctx *ntapi.TrapContext) uint32 {
			// Returns new imagelist that merges two lists; stub creates empty list
			h1 := ctx.Arg(0)
			cx, cy, ok := comctl32pkg.ImageListGetIconSize(h1)
			if !ok { cx, cy = 16, 16 }
			newH := comctl32pkg.ImageListCreate(cx, cy, 0, 0, 4)
			ctx.SetReturn(newH)
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "ImageList_LoadImageA", func(ctx *ntapi.TrapContext) uint32 {
			newH := comctl32pkg.ImageListCreate(16, 16, 0, 0, 4)
			ctx.SetReturn(newH)
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "ImageList_LoadImageW", func(ctx *ntapi.TrapContext) uint32 {
			newH := comctl32pkg.ImageListCreate(16, 16, 0, 0, 4)
			ctx.SetReturn(newH)
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "ImageList_LoadImage", func(ctx *ntapi.TrapContext) uint32 {
			newH := comctl32pkg.ImageListCreate(16, 16, 0, 0, 4)
			ctx.SetReturn(newH)
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "ImageList_Read", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "ImageList_Write", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "ImageList_DrawIndirect", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "HIMAGELIST_QueryInterface", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x80004002) // E_NOINTERFACE
			return 0
		})

		// ── Icon loading ────────────────────────────────────────────────────
		d.RegisterAutoStubHandler(comctl32, "LoadIconWithScaleDown", func(ctx *ntapi.TrapContext) uint32 {
			// LoadIconWithScaleDown(hInst, pszName, cx, cy, phico) → HRESULT
			phico := ctx.Arg(4)
			if phico != 0 {
				ctx.Mem.Write64(phico, 0) // NULL icon
			}
			ctx.SetReturn(0) // S_OK
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "LoadIconMetric", func(ctx *ntapi.TrapContext) uint32 {
			phico := ctx.Arg(3)
			if phico != 0 {
				ctx.Mem.Write64(phico, 0)
			}
			ctx.SetReturn(0) // S_OK
			return 0
		})

		// ── Subclass mechanism ───────────────────────────────────────────────
		// ord=410: SetWindowSubclass
		d.RegisterAutoStubHandler(comctl32, "SetWindowSubclass", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			pfn := ctx.Arg(1)
			uid := uint32(ctx.Arg(2))
			ref := ctx.Arg(3)
			if comctl32pkg.SetWindowSubclass(hwnd, pfn, uid, ref) {
				ctx.SetReturn(1)
			}
			return 0
		})
		// ord=411: GetWindowSubclass
		d.RegisterAutoStubHandler(comctl32, "GetWindowSubclass", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			pfn := ctx.Arg(1)
			uid := uint32(ctx.Arg(2))
			pRef := ctx.Arg(3)
			ref, ok := comctl32pkg.GetWindowSubclass(hwnd, pfn, uid)
			if ok {
				if pRef != 0 {
					ctx.Mem.Write64(pRef, ref)
				}
				ctx.SetReturn(1)
			}
			return 0
		})
		// ord=412: RemoveWindowSubclass
		d.RegisterAutoStubHandler(comctl32, "RemoveWindowSubclass", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			pfn := ctx.Arg(1)
			uid := uint32(ctx.Arg(2))
			if comctl32pkg.RemoveWindowSubclass(hwnd, pfn, uid) {
				ctx.SetReturn(1)
			}
			return 0
		})
		// ord=413: DefSubclassProc - call next subclass in chain, then default
		d.RegisterAutoStubHandler(comctl32, "DefSubclassProc", func(ctx *ntapi.TrapContext) uint32 {
			// We can't call guest subclass procs without a full call-chain,
			// so fall through to DefWindowProcW (return 0 is safe for most messages)
			ctx.SetReturn(0)
			return 0
		})

		// ── DPA / DSA ────────────────────────────────────────────────────────
		d.RegisterAutoStubHandler(comctl32, "DPA_Create", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(comctl32pkg.DPACreate(int32(ctx.Arg(0))))
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "DPA_CreateEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(comctl32pkg.DPACreateEx(int32(ctx.Arg(0)), ctx.Arg(1)))
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "DPA_Destroy", func(ctx *ntapi.TrapContext) uint32 {
			if comctl32pkg.DPADestroy(ctx.Arg(0)) { ctx.SetReturn(1) }
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "DPA_Clone", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(comctl32pkg.DPAClone(ctx.Arg(0), ctx.Arg(1)))
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "DPA_GetPtr", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(comctl32pkg.DPAGetPtr(ctx.Arg(0), int32(ctx.Arg(1))))
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "DPA_GetPtrIndex", func(ctx *ntapi.TrapContext) uint32 {
			idx := comctl32pkg.DPAGetPtrIndex(ctx.Arg(0), ctx.Arg(1))
			ctx.SetReturn(uint64(int64(idx)))
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "DPA_SetPtr", func(ctx *ntapi.TrapContext) uint32 {
			if comctl32pkg.DPASetPtr(ctx.Arg(0), int32(ctx.Arg(1)), ctx.Arg(2)) { ctx.SetReturn(1) }
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "DPA_InsertPtr", func(ctx *ntapi.TrapContext) uint32 {
			idx := comctl32pkg.DPAInsertPtr(ctx.Arg(0), int32(ctx.Arg(1)), ctx.Arg(2))
			ctx.SetReturn(uint64(int64(idx)))
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "DPA_DeletePtr", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(comctl32pkg.DPADeletePtr(ctx.Arg(0), int32(ctx.Arg(1))))
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "DPA_DeleteAllPtrs", func(ctx *ntapi.TrapContext) uint32 {
			if comctl32pkg.DPADeleteAllPtrs(ctx.Arg(0)) { ctx.SetReturn(1) }
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "DPA_Grow", func(ctx *ntapi.TrapContext) uint32 {
			if comctl32pkg.DPAGrow(ctx.Arg(0), int32(ctx.Arg(1))) { ctx.SetReturn(1) }
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "DPA_Search", func(ctx *ntapi.TrapContext) uint32 {
			// DPA_Search(hdpa, pFind, iStart, pfnCmp, lParam, options)
			// We ignore comparator and do pointer equality
			idx := comctl32pkg.DPASearch(ctx.Arg(0), ctx.Arg(1), int32(ctx.Arg(2)))
			ctx.SetReturn(uint64(int64(idx)))
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "DPA_Sort", func(ctx *ntapi.TrapContext) uint32 {
			comctl32pkg.DPASort(ctx.Arg(0), ctx.Arg(1), ctx.Arg(2))
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "DPA_EnumCallback", func(ctx *ntapi.TrapContext) uint32 {
			comctl32pkg.DPAEnumCallback(ctx.Arg(0), ctx.Arg(1), ctx.Arg(2))
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "DPA_DestroyCallback", func(ctx *ntapi.TrapContext) uint32 {
			comctl32pkg.DPADestroyCallback(ctx.Arg(0), ctx.Arg(1), ctx.Arg(2))
			return 0
		})

		d.RegisterAutoStubHandler(comctl32, "DSA_Create", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(comctl32pkg.DSACreate(int32(ctx.Arg(0)), int32(ctx.Arg(1))))
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "DSA_Destroy", func(ctx *ntapi.TrapContext) uint32 {
			if comctl32pkg.DSADestroy(ctx.Arg(0)) { ctx.SetReturn(1) }
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "DSA_DestroyCallback", func(ctx *ntapi.TrapContext) uint32 {
			comctl32pkg.DSADestroyCallback(ctx.Arg(0), ctx.Arg(1), ctx.Arg(2))
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "DSA_EnumCallback", func(ctx *ntapi.TrapContext) uint32 {
			comctl32pkg.DSAEnumCallback(ctx.Arg(0), ctx.Arg(1), ctx.Arg(2))
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "DSA_InsertItem", func(ctx *ntapi.TrapContext) uint32 {
			// DSA_InsertItem(hdsa, index, pItem) - pItem is guest pointer
			h := ctx.Arg(0); i := int32(ctx.Arg(1)); pItem := ctx.Arg(2)
			_ = h; _ = i; _ = pItem
			// We don't copy guest memory here; just track count via insert
			idx := comctl32pkg.DSAInsertItem(h, i, nil)
			ctx.SetReturn(uint64(int64(idx)))
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "DSA_DeleteItem", func(ctx *ntapi.TrapContext) uint32 {
			if comctl32pkg.DSADeleteItem(ctx.Arg(0), int32(ctx.Arg(1))) { ctx.SetReturn(1) }
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "DSA_DeleteAllItems", func(ctx *ntapi.TrapContext) uint32 {
			if comctl32pkg.DSADeleteAllItems(ctx.Arg(0)) { ctx.SetReturn(1) }
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "DSA_GetItem", func(ctx *ntapi.TrapContext) uint32 {
			// DSA_GetItem(hdsa, index, pDest) - copies into pDest; stub returns 1
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "DSA_GetItemPtr", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "DSA_SetItem", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})

		// ── PropertySheet ────────────────────────────────────────────────────
		d.RegisterAutoStubHandler(comctl32, "CreatePropertySheetPage", func(ctx *ntapi.TrapContext) uint32 {
			h := comctl32pkg.CreatePropertySheetPage(0, "", ctx.Arg(0))
			ctx.SetReturn(h)
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "CreatePropertySheetPageA", func(ctx *ntapi.TrapContext) uint32 {
			h := comctl32pkg.CreatePropertySheetPage(0, "", ctx.Arg(0))
			ctx.SetReturn(h)
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "CreatePropertySheetPageW", func(ctx *ntapi.TrapContext) uint32 {
			h := comctl32pkg.CreatePropertySheetPage(0, "", ctx.Arg(0))
			ctx.SetReturn(h)
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "DestroyPropertySheetPage", func(ctx *ntapi.TrapContext) uint32 {
			if comctl32pkg.DestroyPropertySheetPage(ctx.Arg(0)) { ctx.SetReturn(1) }
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "PropertySheet", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(uint64(int64(comctl32pkg.PropertySheet(""))))
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "PropertySheetA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(uint64(int64(comctl32pkg.PropertySheet(""))))
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "PropertySheetW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(uint64(int64(comctl32pkg.PropertySheet(""))))
			return 0
		})

		// ── FlatScrollBar ────────────────────────────────────────────────────
		d.RegisterAutoStubHandler(comctl32, "InitializeFlatSB", func(ctx *ntapi.TrapContext) uint32 {
			comctl32pkg.InitializeFlatSB(ctx.Arg(0))
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "UninitializeFlatSB", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(uint64(comctl32pkg.UninitializeFlatSB(ctx.Arg(0))))
			return 0
		})
		for _, fn := range []string{
			"FlatSB_EnableScrollBar", "FlatSB_ShowScrollBar",
		} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(comctl32, fn, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(1); return 0
			})
		}
		d.RegisterAutoStubHandler(comctl32, "FlatSB_GetScrollInfo", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(comctl32, "FlatSB_GetScrollPos", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(comctl32, "FlatSB_GetScrollProp", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(comctl32, "FlatSB_GetScrollRange", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(comctl32, "FlatSB_SetScrollInfo", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(comctl32, "FlatSB_SetScrollPos", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(comctl32, "FlatSB_SetScrollProp", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(comctl32, "FlatSB_SetScrollRange", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})

		// ── MRU ──────────────────────────────────────────────────────────────
		d.RegisterAutoStubHandler(comctl32, "CreateMRUListW", func(ctx *ntapi.TrapContext) uint32 {
			// MRUINFO struct: cbSize, uMax, fFlags, hKey, lpszSubKey, lpfnCompare
			pInfo := ctx.Arg(0)
			uMax := int32(8)
			if pInfo != 0 {
				v, _ := ctx.Mem.Read32(pInfo + 4)
				uMax = int32(v)
			}
			ctx.SetReturn(comctl32pkg.CreateMRUListW(uMax))
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "AddMRUStringW", func(ctx *ntapi.TrapContext) uint32 {
			h := ctx.Arg(0)
			pStr := ctx.Arg(1)
			s := ""
			if pStr != 0 {
				s = readGuestUTF16(pStr)
			}
			ctx.SetReturn(uint64(int64(comctl32pkg.AddMRUStringW(h, s))))
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "EnumMRUListW", func(ctx *ntapi.TrapContext) uint32 {
			h := ctx.Arg(0)
			n := int32(ctx.Arg(1))
			ctx.SetReturn(uint64(int64(comctl32pkg.EnumMRUListW(h, n, 0, 0))))
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "FreeMRUList", func(ctx *ntapi.TrapContext) uint32 {
			comctl32pkg.FreeMRUList(ctx.Arg(0))
			return 0
		})

		// ── DllGetVersion ─────────────────────────────────────────────────────
		d.RegisterAutoStubHandler(comctl32, "DllGetVersion", func(ctx *ntapi.TrapContext) uint32 {
			pInfo := ctx.Arg(0)
			if pInfo != 0 {
				// DLLVERSIONINFO: cbSize(4), dwMajorVersion(4), dwMinorVersion(4),
				//                 dwBuildNumber(4), dwPlatformID(4)
				ctx.Mem.Write32(pInfo,    20) // cbSize
				ctx.Mem.Write32(pInfo+4,  comctl32pkg.DllVersionMajor)
				ctx.Mem.Write32(pInfo+8,  comctl32pkg.DllVersionMinor)
				ctx.Mem.Write32(pInfo+12, comctl32pkg.DllVersionBuildNum)
				ctx.Mem.Write32(pInfo+16, comctl32pkg.DllVersionPlatform)
			}
			ctx.SetReturn(0) // S_OK
			return 0
		})

		// ── Misc named exports ────────────────────────────────────────────────
		d.RegisterAutoStubHandler(comctl32, "GetEffectiveClientRect", func(ctx *ntapi.TrapContext) uint32 {
			// GetEffectiveClientRect(hwnd, prc, lpInfo) - fills rect subtracting toolbars
			// Stub: copy GetClientRect result
			hwnd := ctx.Arg(0)
			prc := ctx.Arg(1)
			if prc != 0 {
				if cs, ok := hwndChildren[hwnd]; ok {
					ctx.Mem.Write32(prc, 0)
					ctx.Mem.Write32(prc+4, 0)
					ctx.Mem.Write32(prc+8, uint32(cs.w))
					ctx.Mem.Write32(prc+12, uint32(cs.h))
				}
			}
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "CreateMappedBitmap", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // stub HBITMAP
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "CreateToolbar", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(hwndAlloc()) // fake toolbar HWND
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "CreateToolbarEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(hwndAlloc()) // fake toolbar HWND
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "CreateUpDownControl", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(hwndAlloc()) // fake updown HWND
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "CreateStatusWindow", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(hwndAlloc()) // fake status HWND
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "CreateStatusWindowA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(hwndAlloc()) // fake status HWND
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "DrawStatusText", func(ctx *ntapi.TrapContext) uint32 {
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "DrawStatusTextA", func(ctx *ntapi.TrapContext) uint32 {
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "DrawStatusTextW", func(ctx *ntapi.TrapContext) uint32 {
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "DrawInsert", func(ctx *ntapi.TrapContext) uint32 {
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "LBItemFromPt", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(uint64(0xFFFFFFFF)); return 0
		})
		d.RegisterAutoStubHandler(comctl32, "MakeDragList", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(comctl32, "MenuHelp", func(ctx *ntapi.TrapContext) uint32 {
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "ShowHideMenuCtl", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(comctl32, "RegisterClassNameW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(comctl32, "GetMUILanguage", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x0409); return 0 // en-US
		})
		d.RegisterAutoStubHandler(comctl32, "InitMUILanguage", func(ctx *ntapi.TrapContext) uint32 {
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "ImageList_SetFilter", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(comctl32, "_TrackMouseEvent", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(comctl32, "FlatSB_EnableScrollBar", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE - FlatSB not supported
			return 0
		})
		d.RegisterAutoStubHandler(comctl32, "FlatSB_ShowScrollBar", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
	}
	})
	delayHandlerRegistrars[len(delayHandlerRegistrars)-1]()

	// --- ole32.dll ---
	delayHandlerRegistrars = append(delayHandlerRegistrars, func() {
	if ole32, ok := synthByName["ole32.dll"]; ok {
		d.RegisterAutoStubHandler(ole32, "CoInitialize", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // S_OK
			return 0
		})
		d.RegisterAutoStubHandler(ole32, "CoInitializeEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // S_OK
			return 0
		})
		d.RegisterAutoStubHandler(ole32, "CoInitializeSecurity", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // S_OK
			return 0
		})
		d.RegisterAutoStubHandler(ole32, "CoCreateInstance", func(ctx *ntapi.TrapContext) uint32 {
			// rclsid *CLSID, pUnkOuter, dwClsContext, riid *IID, ppv **void
			ppv := ctx.Arg(4)
			if ppv == 0 {
				ctx.SetReturn(0x80004003) // E_POINTER
				return 0
			}
			// Build a minimal IUnknown vtable in guest memory.
			// vtable[0] = QueryInterface stub, [1] = AddRef stub, [2] = Release stub
			// Each stub is a trap that returns S_OK / 1.
			// We reuse a single shared IUnknown object for all CoCreateInstance calls.
			// The guest object layout: [8-byte vtable ptr] → vtable[3 pointers]
			const comObjSize = 8  // just the vtable pointer
			const vtableSize = 24 // 3 × 8-byte pointers
			// Allocate per-call so each object is independent.
			objAddr := mem.Mmap(0, comObjSize+vtableSize+3*64, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
			vtableAddr := objAddr + comObjSize
			// Write 3 stub functions right after vtable entries.
			stubBase := vtableAddr + vtableSize
			// Stub: mov eax, 0; ret (returns 0 / S_OK or 1 for AddRef/Release)
			for i := uint64(0); i < 3; i++ {
				sAddr := stubBase + i*64
				// xor eax, eax; ret
				ctx.Mem.Write8(sAddr+0, 0x31)
				ctx.Mem.Write8(sAddr+1, 0xC0)
				ctx.Mem.Write8(sAddr+2, 0xC3)
				ctx.Mem.Write64(vtableAddr+i*8, sAddr)
			}
			// AddRef/Release return 1 not 0 - patch the ret value
			// mov eax, 1; ret
			for _, i := range []uint64{1, 2} {
				sAddr := stubBase + i*64
				ctx.Mem.Write8(sAddr+0, 0xB8)
				ctx.Mem.Write32(sAddr+1, 1)
				ctx.Mem.Write8(sAddr+5, 0xC3)
			}
			// Object: vtable pointer at offset 0
			ctx.Mem.Write64(objAddr, vtableAddr)
			// *ppv = objAddr
			ctx.Mem.Write64(ppv, objAddr)
			ctx.SetReturn(0) // S_OK
			return 0
		})
		d.RegisterAutoStubHandler(ole32, "CoCreateInstanceEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x80004005) // E_FAIL
			return 0
		})
		d.RegisterAutoStubHandler(ole32, "StringFromGUID2", func(ctx *ntapi.TrapContext) uint32 {
			// rguid *GUID, lpsz *OLECHAR, cchMax int → returns chars written
			guidPtr := ctx.Arg(0)
			outPtr := ctx.Arg(1)
			cchMax := int(ctx.Arg(2))
			if guidPtr == 0 || outPtr == 0 || cchMax < 39 {
				ctx.SetReturn(0)
				return 0
			}
			// Read 16 bytes of GUID
			b := make([]byte, 16)
			for i := range b {
				v, _ := ctx.Mem.Read8(guidPtr + uint64(i))
				b[i] = v
			}
			d1 := uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
			d2 := uint16(b[4]) | uint16(b[5])<<8
			d3 := uint16(b[6]) | uint16(b[7])<<8
			s := fmt.Sprintf("{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
				d1, d2, d3, b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
			// Write as UTF-16LE
			runes := []rune(s)
			for i, r := range runes {
				ctx.Mem.Write16(outPtr+uint64(i)*2, uint16(r))
			}
			ctx.Mem.Write16(outPtr+uint64(len(runes))*2, 0) // NUL
			ctx.SetReturn(uint64(len(runes) + 1))
			return 0
		})
		d.RegisterAutoStubHandler(ole32, "CLSIDFromString", func(ctx *ntapi.TrapContext) uint32 {
			// Parse "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}" → GUID struct
			strPtr := ctx.Arg(0)
			clsidPtr := ctx.Arg(1)
			if strPtr == 0 || clsidPtr == 0 {
				ctx.SetReturn(0x80004003) // E_POINTER
				return 0
			}
			s := readGuestUTF16(strPtr)
			var d1 uint32; var d2, d3 uint16; var rest [8]byte
			n, _ := fmt.Sscanf(s, "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
				&d1, &d2, &d3,
				&rest[0], &rest[1], &rest[2], &rest[3], &rest[4], &rest[5], &rest[6], &rest[7])
			if n < 11 {
				ctx.SetReturn(0x80070057) // E_INVALIDARG
				return 0
			}
			ctx.Mem.Write8(clsidPtr+0, byte(d1))
			ctx.Mem.Write8(clsidPtr+1, byte(d1>>8))
			ctx.Mem.Write8(clsidPtr+2, byte(d1>>16))
			ctx.Mem.Write8(clsidPtr+3, byte(d1>>24))
			ctx.Mem.Write8(clsidPtr+4, byte(d2))
			ctx.Mem.Write8(clsidPtr+5, byte(d2>>8))
			ctx.Mem.Write8(clsidPtr+6, byte(d3))
			ctx.Mem.Write8(clsidPtr+7, byte(d3>>8))
			for i := 0; i < 8; i++ {
				ctx.Mem.Write8(clsidPtr+8+uint64(i), rest[i])
			}
			ctx.SetReturn(0) // S_OK
			return 0
		})
		d.RegisterAutoStubHandler(ole32, "CLSIDFromProgID", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x800401F3) // CO_E_CLASSSTRING
			return 0
		})
		d.RegisterAutoStubHandler(ole32, "StringFromCLSID", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x80004005) // E_FAIL
			return 0
		})
		d.RegisterAutoStubHandler(ole32, "IIDFromString", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x80004005)
			return 0
		})
		d.RegisterAutoStubHandler(ole32, "IsEqualGUID", func(ctx *ntapi.TrapContext) uint32 {
			// rguid1 *GUID, rguid2 *GUID → BOOL
			g1 := ctx.Arg(0); g2 := ctx.Arg(1)
			for i := uint64(0); i < 16; i++ {
				b1, _ := ctx.Mem.Read8(g1 + i)
				b2, _ := ctx.Mem.Read8(g2 + i)
				if b1 != b2 { ctx.SetReturn(0); return 0 }
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(ole32, "CreateStreamOnHGlobal", func(ctx *ntapi.TrapContext) uint32 {
			// hGlobal, fDeleteOnRelease, ppstm
			ppstm := ctx.Arg(2)
			if ppstm == 0 { ctx.SetReturn(0x80004003); return 0 }
			// Minimal IStream stub (same IUnknown pattern)
			objAddr := mem.Mmap(0, 8+64+10*64, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
			vtAddr := objAddr + 8
			stubBase := vtAddr + 80 // 10 vtable entries × 8
			// Write xor eax,eax; ret for all 10 IStream methods
			for i := uint64(0); i < 10; i++ {
				s := stubBase + i*64
				ctx.Mem.Write8(s+0, 0x31); ctx.Mem.Write8(s+1, 0xC0); ctx.Mem.Write8(s+2, 0xC3)
				ctx.Mem.Write64(vtAddr+i*8, s)
			}
			// AddRef/Release (idx 1,2) → return 1
			for _, i := range []uint64{1, 2} {
				s := stubBase + i*64
				ctx.Mem.Write8(s+0, 0xB8); ctx.Mem.Write32(s+1, 1); ctx.Mem.Write8(s+5, 0xC3)
			}
			ctx.Mem.Write64(objAddr, vtAddr)
			ctx.Mem.Write64(ppstm, objAddr)
			ctx.SetReturn(0) // S_OK
			return 0
		})
		d.RegisterAutoStubHandler(ole32, "CoUninitialize", func(ctx *ntapi.TrapContext) uint32 {
			return 0
		})
		d.RegisterAutoStubHandler(ole32, "CoTaskMemAlloc", func(ctx *ntapi.TrapContext) uint32 {
			size := ctx.Arg(0)
			if size == 0 { size = 1 }
			addr := mem.Mmap(0, size, mmu.PermRead|mmu.PermWrite)
			ctx.SetReturn(addr)
			return 0
		})
		d.RegisterAutoStubHandler(ole32, "CoTaskMemFree", func(ctx *ntapi.TrapContext) uint32 {
			return 0 // No-op (guest GC handles cleanup)
		})
		d.RegisterAutoStubHandler(ole32, "CoTaskMemRealloc", func(ctx *ntapi.TrapContext) uint32 {
			size := ctx.Arg(1)
			if size == 0 { size = 1 }
			addr := mem.Mmap(0, size, mmu.PermRead|mmu.PermWrite)
			ctx.SetReturn(addr)
			return 0
		})
		d.RegisterAutoStubHandler(ole32, "OleInitialize", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // S_OK
			return 0
		})
		d.RegisterAutoStubHandler(ole32, "OleUninitialize", func(ctx *ntapi.TrapContext) uint32 {
			return 0
		})
		d.RegisterAutoStubHandler(ole32, "RegisterDragDrop", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // S_OK (drag-drop not actually supported)
			return 0
		})
		d.RegisterAutoStubHandler(ole32, "RevokeDragDrop", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // S_OK
			return 0
		})
		d.RegisterAutoStubHandler(ole32, "DoDragDrop", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x80004004) // DRAGDROP_S_DROP cancel
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

	// win32Timer tracks active SetTimer timers.
	type win32Timer struct {
		id         uint64
		hwnd       uint64
		intervalMs uint64
		proc       uint64 // TimerProc (0 = post WM_TIMER to queue)
		deadline   time.Time
	}
	timerMap := map[uint64]*win32Timer{}
	nextTimerID := uint64(1000)
	// frameReady: set to trigger the next Commit().
	// hasBaseFrame: set once DefWindowProcW has drawn the base frame (menu+background).
	// repaintBuiltin: when true, commitIfDone calls paintTree (for initial frame compositing).
	var frameReady, hasBaseFrame, repaintBuiltin bool

	// drawMenuOverlay draws the open dropdown menu on top of everything else.
	// Must be called AFTER paintTree so the toolbar/rebar don't overwrite it.
	var drawMenuOverlay func()
	drawMenuOverlay = func() {
		if wlWindow == nil || openMenuIdx < 0 {
			return
		}
		menuH, ok := hwndMenuBar[mainHWND]
		if !ok {
			return
		}
		md, ok2 := menus[menuH]
		if !ok2 || openMenuHwnd != mainHWND {
			return
		}
		clientTop := wlWindow.TitleBarH + menuBarHeight
		x := int32(4)
		for i, item := range md.items {
			if item.flags&0x0800 != 0 || item.flags&0x0010 == 0 {
				continue
			}
			label := menuStripAmpersand(item.text)
			if idx := strings.IndexByte(label, '\t'); idx >= 0 {
				label = label[:idx]
			}
			if label == "" || label == "-" {
				continue
			}
			hasRenderable := false
			for _, r := range label {
				if r >= 32 && r <= 126 {
					hasRenderable = true
					break
				}
			}
			if !hasRenderable {
				continue
			}
			tw := int32(len([]rune(label)))*8 + 12
			if i == openMenuIdx && len(item.submenu) > 0 {
				dropX := x
				dropY := clientTop
				dropW := int32(200)
				dropH := int32(len(item.submenu)) * 20
				// Shadow
				wlWindow.DrawRectAbs(dropX+2, dropY+dropH, dropX+dropW+2, dropY+dropH+2, 0x808080)
				wlWindow.DrawRectAbs(dropX+dropW, dropY+2, dropX+dropW+2, dropY+dropH+2, 0x808080)
				// Background
				wlWindow.DrawRectAbs(dropX, dropY, dropX+dropW, dropY+dropH, sysColors[15])
				// Border
				wlWindow.DrawRectAbs(dropX, dropY, dropX+dropW, dropY+1, sysColors[16])
				wlWindow.DrawRectAbs(dropX, dropY, dropX+1, dropY+dropH, sysColors[16])
				wlWindow.DrawRectAbs(dropX, dropY+dropH-1, dropX+dropW, dropY+dropH, sysColors[16])
				wlWindow.DrawRectAbs(dropX+dropW-1, dropY, dropX+dropW, dropY+dropH, sysColors[16])
				for j, si := range item.submenu {
					iy := dropY + int32(j)*20
					if si.flags&0x0800 != 0 {
						wlWindow.DrawRectAbs(dropX+2, iy+9, dropX+dropW-2, iy+10, sysColors[16])
						wlWindow.DrawRectAbs(dropX+2, iy+10, dropX+dropW-2, iy+11, sysColors[20])
					} else {
						sl := menuStripAmpersand(si.text)
						if k := strings.IndexByte(sl, '\t'); k >= 0 {
							sl = sl[:k]
						}
						wlWindow.DrawTextAbs(dropX+20, iy+3, sl, 0x000000, sysColors[15], true)
					}
				}
				break
			}
			x += tw
		}
	}

	// commitIfDone commits the Wayland buffer whenever a paint pass has finished.
	// Called after DefWindowProcW WM_PAINT and after each child EndPaint.
	// Multiple commits are fine; each one produces a progressively more complete frame.
	commitIfDone := func() {
		if !frameReady || wlWindow == nil {
			return
		}
		frameReady = false
		if repaintBuiltin {
			// Re-composite builtin controls (toolbar, tabs, status bar) on top of
			// guest-drawn content (Scintilla may have overwritten them with its fill).
			repaintBuiltin = false
			paintTree(mainHWND)
		}
		// Always draw dropdown menu overlay on top of everything (including toolbar).
		drawMenuOverlay()
		ravelog.Logf("[commit] Commit w=%d h=%d pixLen=%d\n", wlWindow.Width, wlWindow.Height, len(wlWindow.Pix))
		wlWindow.Commit()
		frameCount++
		// Save a debug screenshot only for the first 10 frames to avoid filling /tmp.
		if frameCount <= 10 {
			path := fmt.Sprintf("/tmp/npp_frame%d.png", frameCount)
			saveScreenshot(wlWindow.Pix, int(wlWindow.Width), int(wlWindow.Height+wlWindow.TitleBarH), path)
		}
	}

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
				wlWindow.DrawRectAbs(cs.x, cs.y, cs.x+cs.w, cs.y+1, sysColors[16])   // top shadow
				wlWindow.DrawRectAbs(cs.x, cs.y, cs.x+1, cs.y+cs.h, sysColors[16])   // left shadow
				wlWindow.DrawRectAbs(cs.x+1, cs.y+1, cs.x+cs.w-1, cs.y+2, 0x404040)  // inner top
				wlWindow.DrawRectAbs(cs.x+1, cs.y+1, cs.x+2, cs.y+cs.h-1, 0x404040)  // inner left
				wlWindow.DrawRectAbs(cs.x+cs.w-1, cs.y, cs.x+cs.w, cs.y+cs.h, sysColors[20]) // right highlight
				wlWindow.DrawRectAbs(cs.x, cs.y+cs.h-1, cs.x+cs.w, cs.y+cs.h, sysColors[20]) // bottom highlight
				wlWindow.DrawRectAbs(cs.x+cs.w-2, cs.y+1, cs.x+cs.w-1, cs.y+cs.h-1, 0xDFDFDF) // inner right
				wlWindow.DrawRectAbs(cs.x+1, cs.y+cs.h-2, cs.x+cs.w-1, cs.y+cs.h-1, 0xDFDFDF) // inner bottom
				// White client area
				wlWindow.DrawRectAbs(cs.x+2, cs.y+2, cs.x+cs.w-2, cs.y+cs.h-2, sysColors[5])
				// Draw text content
				if cs.text != "" {
					wlWindow.DrawTextAbs(cs.x+4, cs.y+4, cs.text, 0x000000, sysColors[5], true)
				}
				// Text cursor (blinking caret) - tracks last line for multiline edits
				cursorX := cs.x + 4
				cursorY := cs.y + 4
				if cs.text != "" {
					lines := strings.Split(cs.text, "\n")
					cursorY += int32((len(lines)-1) * 16)
					cursorX += int32(len([]rune(lines[len(lines)-1]))) * 8
				}
				wlWindow.DrawRectAbs(cursorX, cursorY, cursorX+1, cursorY+16, 0x000000)
			case "msctls_statusbar32":
				// Snap statusbar to bottom of Wayland window (common control behavior: WM_SIZE repositions it)
				if wlWindow != nil {
					sbY := wlWindow.Height - cs.h
					if sbY > cs.y { cs.y = sbY } // only snap down, not up
					cs.x = 0
					cs.w = wlWindow.Width
				}
				// Top edge: etched line (shadow + highlight)
				wlWindow.DrawRectAbs(cs.x, cs.y, cs.x+cs.w, cs.y+1, sysColors[16])   // shadow
				wlWindow.DrawRectAbs(cs.x, cs.y+1, cs.x+cs.w, cs.y+2, sysColors[20]) // highlight
				// Face
				wlWindow.DrawRectAbs(cs.x, cs.y+2, cs.x+cs.w, cs.y+cs.h, sysColors[15])
				// Draw parts text
				if len(cs.sbParts) > 0 {
					left := cs.x + 2
					for i, rightEdge := range cs.sbParts {
						right := cs.x + rightEdge
						if rightEdge < 0 { right = cs.x + cs.w }
						// Sunken part area
						wlWindow.DrawRectAbs(left, cs.y+3, right-1, cs.y+4, sysColors[16])     // top shadow
						wlWindow.DrawRectAbs(left, cs.y+3, left+1, cs.y+cs.h-2, sysColors[16]) // left shadow
						wlWindow.DrawRectAbs(left, cs.y+cs.h-2, right-1, cs.y+cs.h-1, sysColors[20]) // bottom highlight
						wlWindow.DrawRectAbs(right-2, cs.y+3, right-1, cs.y+cs.h-1, sysColors[20])   // right highlight
						if i < len(cs.sbTexts) && cs.sbTexts[i] != "" {
							wlWindow.DrawTextAbs(left+4, cs.y+4, cs.sbTexts[i], 0x000000, sysColors[15], true)
						}
						left = right
					}
				} else if cs.text != "" {
					wlWindow.DrawTextAbs(cs.x+4, cs.y+4, cs.text, 0x000000, sysColors[15], true)
				}
				// Sizing grip (small triangular area in bottom-right)
				gripX := cs.x + cs.w - 14
				gripY := cs.y + cs.h - 14
				for i := int32(0); i < 3; i++ {
					ox := gripX + i*4 + 2
					oy := gripY + (2-i)*4 + 2
					wlWindow.DrawRectAbs(ox, oy, ox+2, oy+2, sysColors[20])
					wlWindow.DrawRectAbs(ox+1, oy+1, ox+3, oy+3, sysColors[16])
				}
			case "static":
				wlWindow.DrawRectAbs(cs.x, cs.y, cs.x+cs.w, cs.y+cs.h, sysColors[15])
				if cs.text != "" {
					wlWindow.DrawTextAbs(cs.x+2, cs.y+2, cs.text, 0x000000, sysColors[15], true)
				}
			case "button":
				wlWindow.DrawRectAbs(cs.x, cs.y, cs.x+cs.w, cs.y+cs.h, sysColors[15])
				wlWindow.DrawRectAbs(cs.x, cs.y, cs.x+cs.w, cs.y+1, sysColors[20])
				wlWindow.DrawRectAbs(cs.x, cs.y, cs.x+1, cs.y+cs.h, sysColors[20])
				wlWindow.DrawRectAbs(cs.x, cs.y+cs.h-1, cs.x+cs.w, cs.y+cs.h, sysColors[16])
				wlWindow.DrawRectAbs(cs.x+cs.w-1, cs.y, cs.x+cs.w, cs.y+cs.h, sysColors[16])
				if cs.text != "" {
					tx := cs.x + (cs.w-int32(len(cs.text)*8))/2
					ty := cs.y + (cs.h-16)/2
					wlWindow.DrawTextAbs(tx, ty, cs.text, 0x000000, sysColors[15], true)
				}
			case "systreeview32":
				// 3D sunken border + white area
				wlWindow.DrawRectAbs(cs.x, cs.y, cs.x+cs.w, cs.y+1, sysColors[16])
				wlWindow.DrawRectAbs(cs.x, cs.y, cs.x+1, cs.y+cs.h, sysColors[16])
				wlWindow.DrawRectAbs(cs.x+cs.w-1, cs.y, cs.x+cs.w, cs.y+cs.h, sysColors[20])
				wlWindow.DrawRectAbs(cs.x, cs.y+cs.h-1, cs.x+cs.w, cs.y+cs.h, sysColors[20])
				wlWindow.DrawRectAbs(cs.x+1, cs.y+1, cs.x+cs.w-1, cs.y+cs.h-1, sysColors[5])
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
								wlWindow.DrawRectAbs(mx-4, my-4, mx+5, my+5, sysColors[5])
								wlWindow.DrawRectAbs(mx-4, my-4, mx+5, my-5+1, sysColors[16])
								wlWindow.DrawRectAbs(mx-4, my-4, mx-4+1, my+5, sysColors[16])
								wlWindow.DrawRectAbs(mx+4, my-4, mx+5, my+5, sysColors[16])
								wlWindow.DrawRectAbs(mx-4, my+4, mx+5, my+5, sysColors[16])
								// Horizontal line (always)
								wlWindow.DrawRectAbs(mx-2, my, mx+3, my+1, 0x000000)
								if !ti.expanded {
									// Vertical line (plus sign)
									wlWindow.DrawRectAbs(mx, my-2, mx+1, my+3, 0x000000)
								}
							}
							// Draw item text
							if ti.text != "" {
								wlWindow.DrawTextAbs(tx, ty+1, ti.text, 0x000000, sysColors[5], true)
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
				wlWindow.DrawRectAbs(cs.x, cs.y, cs.x+cs.w, cs.y+1, sysColors[16])
				wlWindow.DrawRectAbs(cs.x, cs.y, cs.x+1, cs.y+cs.h, sysColors[16])
				wlWindow.DrawRectAbs(cs.x+cs.w-1, cs.y, cs.x+cs.w, cs.y+cs.h, sysColors[20])
				wlWindow.DrawRectAbs(cs.x, cs.y+cs.h-1, cs.x+cs.w, cs.y+cs.h, sysColors[20])
				wlWindow.DrawRectAbs(cs.x+1, cs.y+1, cs.x+cs.w-1, cs.y+cs.h-1, sysColors[5])
				// Header area with column names
				wlWindow.DrawRectAbs(cs.x+1, cs.y+1, cs.x+cs.w-1, cs.y+21, sysColors[15])
				wlWindow.DrawRectAbs(cs.x+1, cs.y+21, cs.x+cs.w-1, cs.y+22, sysColors[16])
				if len(cs.lvColumns) > 0 {
					colX := cs.x + 2
					for _, col := range cs.lvColumns {
						if col.text != "" {
							wlWindow.DrawTextAbs(colX+4, cs.y+3, col.text, 0x000000, sysColors[15], true)
						}
						colX += col.width
						// Column separator
						wlWindow.DrawRectAbs(colX-1, cs.y+1, colX, cs.y+21, sysColors[16])
					}
				}
			case "systabcontrol32":
				const tabH = int32(22)
				wlWindow.DrawRectAbs(cs.x, cs.y, cs.x+cs.w, cs.y+cs.h, sysColors[15])
				wlWindow.DrawRectAbs(cs.x, cs.y+tabH-1, cs.x+cs.w, cs.y+tabH, sysColors[16])
				// Draw each tab
				tx := cs.x
				for i := 0; i < cs.tabCount; i++ {
					sel := i == cs.tabCurSel
					bgCol := sysColors[15]
					if sel {
						bgCol = sysColors[5]
					}
					tabW := int32(80)
					wlWindow.DrawRectAbs(tx, cs.y, tx+tabW, cs.y+tabH, bgCol)
					wlWindow.DrawRectAbs(tx, cs.y, tx+1, cs.y+tabH, sysColors[16])
					wlWindow.DrawRectAbs(tx+tabW-1, cs.y, tx+tabW, cs.y+tabH, sysColors[16])
					wlWindow.DrawRectAbs(tx, cs.y, tx+tabW, cs.y+1, sysColors[16])
					if i < len(cs.tabTitles) && cs.tabTitles[i] != "" {
						wlWindow.DrawTextAbs(tx+4, cs.y+4, cs.tabTitles[i], 0x000000, bgCol, false)
					}
					tx += tabW
				}
			default:
				if _, hasGuest := hwndWndProc[hwnd]; hasGuest {
					// Do NOT pre-fill here: BeginPaint will fill the background when the
					// guest processes WM_PAINT. Pre-filling from paintTree would erase
					// content already drawn by the guest (e.g. Scintilla text).
					return 0, false // let DispatchMessageW call the guest WndProc
				}
				// Generic builtin control with no guest WndProc: fill with face color
				if cs.w > 0 && cs.h > 0 {
					wlWindow.DrawRectAbs(cs.x, cs.y, cs.x+cs.w, cs.y+cs.h, sysColors[15])
				}
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
				cs.y = wlWindow.Height + wlWindow.TitleBarH - sbHeight
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
				} else if ch == '\r' {
					cs.text += "\n" // normalize CR to LF for storage
				} else if ch >= 0x20 || ch == '\n' || ch == '\t' {
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

	// rebarBandCounts tracks how many bands have been inserted into each ReBar
	rebarBandCounts := make(map[uint64]int)

	// Wrap builtinWndProc to add ReBar/Toolbar/SysTab handling
	innerBuiltin := builtinWndProc
	builtinWndProc = func(hwnd uint64, msg uint32, wParam, lParam uint64) (uint64, bool) {
		cs, ok := hwndChildren[hwnd]
		if !ok {
			return innerBuiltin(hwnd, msg, wParam, lParam)
		}
		switch cs.className {
		case "rebarwindow32":
			const rbFirst = 0x0400
			switch msg {
			case 0x000F: // WM_PAINT
				// Rebar is a container for toolbars - do NOT fill background here.
				// Child toolbars draw inside the same rect and we must not overwrite them.
				// Only draw the 3D-edge lines.
				if wlWindow != nil {
					wlWindow.DrawRectAbs(cs.x, cs.y, cs.x+cs.w, cs.y+1, sysColors[20])       // top highlight
					wlWindow.DrawRectAbs(cs.x, cs.y+cs.h-1, cs.x+cs.w, cs.y+cs.h, sysColors[16]) // bottom shadow
				}
				return 0, true
			case 0x0005: // WM_SIZE
				cs.w = int32(lParam & 0xFFFF)
				cs.h = int32(lParam >> 16)
				return 0, true
			case rbFirst + 1: // RB_INSERTBANDA
				rebarBandCounts[hwnd]++
				// Update rebar height: each band is 26px
				cs.h = int32(rebarBandCounts[hwnd]) * 26
				return 1, true
			case rbFirst + 10: // RB_INSERTBANDW
				// Parse REBARBANDINFOW to extract and size the child window.
				// 64-bit layout: cbSize(4), fMask(4), fStyle(4), clrFore(4), clrBack(4),
				//   pad(4), lpText(8), cch(4), iImage(4), hwndChild(8), cxMinChild(4), cyMinChild(4), cx(4)
				if lParam != 0 {
					fMaskRB, _ := mem.Read32(lParam + 4)
					const RBBIM_CHILD = 0x10
					const RBBIM_CHILDSIZE = 0x20
					if fMaskRB&RBBIM_CHILD != 0 {
						childHWND, _ := mem.Read64(lParam + 40)
						cyMinChild := int32(0)
						if fMaskRB&RBBIM_CHILDSIZE != 0 {
							cyV, _ := mem.Read32(lParam + 52)
							cyMinChild = int32(cyV)
						}
						if cyMinChild <= 0 { cyMinChild = 26 }
						if csc, ok2 := hwndChildren[childHWND]; ok2 {
							csc.w = cs.w
							if csc.w <= 0 && wlWindow != nil { csc.w = wlWindow.Width }
							csc.h = cyMinChild
							csc.x = cs.x
							csc.y = cs.y
						}
					}
				}
				rebarBandCounts[hwnd]++
				cs.h = int32(rebarBandCounts[hwnd]) * 26
				// Queue repaint so the toolbar gets drawn after sizing
				msgQueue = append(msgQueue, queuedMsg{mainHWND, 0x000F, 0, 0})
				return 1, true
			case rbFirst + 12: // RB_GETBANDCOUNT
				return uint64(rebarBandCounts[hwnd]), true
			case rbFirst + 14: // RB_GETBANDINFO / RB_GETBANDINFOA
				return 1, true
			case rbFirst + 4: // RB_DELETEBAND
				if rebarBandCounts[hwnd] > 0 {
					rebarBandCounts[hwnd]--
					cs.h = int32(rebarBandCounts[hwnd]) * 26
				}
				return 1, true
			case rbFirst + 6: // RB_GETBARHEIGHT
				return uint64(cs.h), true
			case rbFirst + 9: // RB_GETBARINFO
				return 1, true
			case rbFirst + 19: // RB_SETBARINFO
				return 1, true
			case rbFirst + 25: // RB_GETBANDINFOW
				return 1, true
			case rbFirst + 31: // RB_SETBANDINFOW
				return 1, true
			case rbFirst + 22: // RB_SIZETORECT
				return 1, true
			case rbFirst + 17: // RB_HITTEST
				return uint64(0xFFFFFFFF), true // RBHT_NOWHERE
			default:
				return 0, true
			}

		case "toolbarwindow32":
			const tbFirst = 0x0400
			const wmUser = 0x0400
			switch msg {
			case 0x000F: // WM_PAINT
				if wlWindow != nil {
					// Draw toolbar background - slightly darker than button face for contrast
					wlWindow.DrawRectAbs(cs.x, cs.y, cs.x+cs.w, cs.y+cs.h, 0xD4D0C8)
					btnW := cs.tbBtnW
					if btnW <= 0 { btnW = 23 }
					btnH := cs.tbBtnH
					if btnH <= 0 { btnH = 22 }
					if btnH > cs.h-2 { btnH = cs.h - 2 }
					const padY = int32(2)
					x := cs.x + 2
					drawBtn := func(bx, by, bw, bh int32) {
						// Windows classic raised button: face + 3D border
						wlWindow.DrawRectAbs(bx, by, bx+bw, by+bh, 0xECE9D8)     // button face
						wlWindow.DrawRectAbs(bx, by, bx+bw, by+1, 0xFFFFFF)      // top highlight
						wlWindow.DrawRectAbs(bx, by, bx+1, by+bh, 0xFFFFFF)      // left highlight
						wlWindow.DrawRectAbs(bx+bw-2, by+1, bx+bw-1, by+bh-1, 0xACA899) // inner right shadow
						wlWindow.DrawRectAbs(bx+1, by+bh-2, bx+bw-1, by+bh-1, 0xACA899) // inner bottom shadow
						wlWindow.DrawRectAbs(bx+bw-1, by, bx+bw, by+bh, 0x716F64) // outer right shadow
						wlWindow.DrawRectAbs(bx, by+bh-1, bx+bw, by+bh, 0x716F64) // outer bottom shadow
					}
					for _, btn := range cs.tbButtons {
						if x >= cs.x+cs.w { break }
						if btn.fsStyle&0x01 != 0 { // TBSTYLE_SEP
							mid := x + 3
							wlWindow.DrawRectAbs(mid, cs.y+padY+2, mid+1, cs.y+padY+btnH-2, 0x716F64)
							wlWindow.DrawRectAbs(mid+1, cs.y+padY+2, mid+2, cs.y+padY+btnH-2, 0xFFFFFF)
							x += 8
							continue
						}
						drawBtn(x, cs.y+padY, btnW, btnH)
						// Draw icon if available
						iconIdx := int(btn.iBitmap)
						iconW := int(cs.tbBitmapIconW)
						iconH := int(cs.tbBitmapIconH)
						if iconW <= 0 { iconW = 16 }
						if iconH <= 0 { iconH = 16 }
						if iconIdx >= 0 && iconIdx < len(cs.tbBitmapStore) && len(cs.tbBitmapStore[iconIdx]) > 0 {
							pix := cs.tbBitmapStore[iconIdx]
							offX := x + (btnW-int32(iconW))/2
							offY := cs.y + padY + (btnH-int32(iconH))/2
							winW := int(wlWindow.Width)
							winH := int(wlWindow.Height + wlWindow.TitleBarH)
							maskColor := uint32(0x00FF00FF) // magenta = transparent
							for py := 0; py < iconH; py++ {
								for px := 0; px < iconW; px++ {
									c := pix[py*iconW+px]
									if c == maskColor { continue }
									sx := int(offX) + px
									sy := int(offY) + py
									if sx >= 0 && sy >= 0 && sx < winW && sy < winH {
										base := (sy*winW + sx) * 4
										wlWindow.Pix[base+0] = byte(c & 0xFF)        // B
										wlWindow.Pix[base+1] = byte((c >> 8) & 0xFF) // G
										wlWindow.Pix[base+2] = byte((c >> 16) & 0xFF) // R
										wlWindow.Pix[base+3] = 0xFF
									}
								}
							}
						}
						x += btnW + 1
					}
				}
				return 0, true
			case 0x0005: // WM_SIZE
				cs.w = int32(lParam & 0xFFFF)
				cs.h = 26 // standard toolbar height
				return 0, true
			case 0x0201: // WM_LBUTTONDOWN - toolbar button click
				clickX := int32(lParam & 0xFFFF)
				btnW := cs.tbBtnW
				if btnW <= 0 { btnW = 23 }
				x := int32(2)
				for _, btn := range cs.tbButtons {
					if btn.fsStyle&0x01 != 0 { // TBSTYLE_SEP
						x += 8
						continue
					}
					if clickX >= x && clickX < x+btnW {
						if btn.fsState&0x04 == 0 { // not disabled (TBSTATE_ENABLED=0x04 means enabled)
							// WM_COMMAND: LOWORD=cmdID, HIWORD=1 (BN_CLICKED), lParam=toolbar HWND
							msgQueue = append(msgQueue, queuedMsg{cs.parentHWND, 0x0111,
								uint64(uint16(btn.idCommand)) | (1 << 16), hwnd})
						}
						break
					}
					x += btnW + 1
				}
				return 0, true
			case wmUser + 3: // TB_ENABLEBUTTON
				return 1, true
			case wmUser + 4: // TB_CHECKBUTTON
				return 1, true
			case wmUser + 8: // TB_PRESSBUTTON
				return 1, true
			case wmUser + 9: // TB_HIDEBUTTON
				return 1, true
			case wmUser + 6: // TB_GETSTATE
				return 0, true
			case wmUser + 11: // TB_ISBUTTONCHECKED
				return 0, true
			case wmUser + 10: // TB_ISBUTTONENABLED
				return 1, true
			case wmUser + 19: // TB_ADDBITMAP - load bitmap from PE resource, return start index
				startIdx := len(cs.tbBitmapStore)
				nBitmaps := int(wParam)
				if lParam != 0 && mainModule != nil {
					hInst, _ := mem.Read64(lParam)
					nID, _ := mem.Read64(lParam + 8)
					iconW := int(cs.tbBitmapIconW)
					iconH := int(cs.tbBitmapIconH)
					if iconW <= 0 { iconW = 16 }
					if iconH <= 0 { iconH = 16 }
					ravelog.Logf("[toolbar] TB_ADDBITMAP nBitmaps=%d hInst=0x%x nID=0x%x mainBase=0x%x iconW=%d iconH=%d\n",
						nBitmaps, hInst, nID, mainModule.BaseAddr, iconW, iconH)

					if hInst == 0 {
						// nID is an HBITMAP handle from LoadImage/LoadBitmap
						if bd, ok2 := bitmapHandles[nID]; ok2 && len(bd.slots) > 0 {
							// re-slice icons using requested icon size
							// bd.slots may have been decoded with wrong size, re-decode from scratch if needed
							// For now use slots as-is if count matches or just use them
							ravelog.Logf("[toolbar] TB_ADDBITMAP HBITMAP handle found, %d slots\n", len(bd.slots))
							cs.tbBitmapStore = append(cs.tbBitmapStore, bd.slots...)
						} else {
							ravelog.Logf("[toolbar] TB_ADDBITMAP HBITMAP handle 0x%x not found or empty\n", nID)
							for i := 0; i < nBitmaps; i++ {
								cs.tbBitmapStore = append(cs.tbBitmapStore, nil)
							}
						}
					} else if hInst == mainModule.BaseAddr {
						// nID is a resource ID in the main PE
						addr, sz, ok2 := peLoadRawResource(mainModule.BaseAddr, mainModule.ResourceDirRVA, 2 /*RT_BITMAP*/, uint32(nID))
						ravelog.Logf("[toolbar] TB_ADDBITMAP peLoadRawResource ok=%v addr=0x%x sz=%d\n", ok2, addr, sz)
						if ok2 {
							slots := decodeDIBSlots(addr, sz, iconW, iconH)
							ravelog.Logf("[toolbar] TB_ADDBITMAP decoded %d icon slots\n", len(slots))
							cs.tbBitmapStore = append(cs.tbBitmapStore, slots...)
						} else {
							for i := 0; i < nBitmaps; i++ {
								cs.tbBitmapStore = append(cs.tbBitmapStore, nil)
							}
						}
					} else {
						ravelog.Logf("[toolbar] TB_ADDBITMAP hInst mismatch 0x%x, skipping\n", hInst)
						for i := 0; i < nBitmaps; i++ {
							cs.tbBitmapStore = append(cs.tbBitmapStore, nil)
						}
					}
				}
				return uint64(startIdx), true
			case wmUser + 20: // TB_ADDBUTTONSA
				return 1, true
			case wmUser + 68: // TB_ADDBUTTONSW
				// TBBUTTON (64-bit layout): iBitmap(4), idCommand(4), fsState(1), fsStyle(1), bReserved(6), dwData(8), iString(8) = 32 bytes
				nButtons := int(wParam)
				btnStruct := lParam
				const tbBtnSize = uint64(32)
				for i := 0; i < nButtons; i++ {
					base := btnStruct + uint64(i)*tbBtnSize
					iBitmapV, _ := mem.Read32(base)
					idCommandV, _ := mem.Read32(base + 4)
					stateBytes, _ := mem.ReadBytes(base+8, 2)
					fsState, fsStyle := byte(0), byte(0)
					if len(stateBytes) >= 2 {
						fsState = stateBytes[0]
						fsStyle = stateBytes[1]
					}
					cs.tbButtons = append(cs.tbButtons, tbButtonData{int32(iBitmapV), int32(idCommandV), fsState, fsStyle})
					if i < 5 { // log first few to avoid spam
						ravelog.Logf("[toolbar] TB_ADDBUTTONSW[%d] iBitmap=%d idCmd=0x%x state=0x%x style=0x%x\n", i, iBitmapV, idCommandV, fsState, fsStyle)
					}
				}
				return 1, true
			case wmUser + 44: // TB_BUTTONSTRUCTSIZE
				return 0, true
			case wmUser + 45: // TB_SETBITMAPSIZE
				cs.tbBitmapIconW = int32(lParam & 0xFFFF)
				cs.tbBitmapIconH = int32((lParam >> 16) & 0xFFFF)
				ravelog.Logf("[toolbar] TB_SETBITMAPSIZE iconW=%d iconH=%d\n", cs.tbBitmapIconW, cs.tbBitmapIconH)
				return 1, true
			case wmUser + 48: // TB_AUTOSIZE
				cs.h = 26
				// Set width to parent's client width
				if parent, ok := hwndChildren[cs.parentHWND]; ok {
					cs.w = parent.w
				} else if cs.parentHWND == mainHWND && wlWindow != nil {
					cs.w = wlWindow.Width
				}
				return 0, true
			case wmUser + 46: // TB_SETBUTTONSIZE
				cs.tbBtnW = int32(lParam & 0xFFFF)
				cs.tbBtnH = int32((lParam >> 16) & 0xFFFF)
				return 1, true
			case wmUser + 55: // TB_GETROWS
				return 1, true
			case wmUser + 77: // TB_GETROWCOUNT
				return 1, true
			case wmUser + 56: // TB_GETBUTTONSIZE
				return (uint64(26)<<16) | 24, true // height=26, width=24
			case wmUser + 22: // TB_BUTTONCOUNT
				return uint64(len(cs.tbButtons)), true
			case wmUser + 21: // TB_DELETEBUTTON
				return 1, true
			case wmUser + 71: // TB_SETTOOLTIPS
				return 0, true
			case wmUser + 36: // TB_SETMAXTEXTROWS
				return 1, true
			case wmUser + 70: // TB_SETIMAGELIST
				return 0, true
			case wmUser + 69: // TB_GETIMAGELIST
				return 0, true
			case wmUser + 41: // TB_GETITEMRECT
				if lParam != 0 {
					btnIdx := int32(wParam)
					x := btnIdx * 24
					mem.Write32(lParam, uint32(x))
					mem.Write32(lParam+4, 0)
					mem.Write32(lParam+8, uint32(x+24))
					mem.Write32(lParam+12, 26)
				}
				return 1, true
			case wmUser + 27: // TB_GETBUTTONA
				return 0, true
			case wmUser + 111: // TB_GETBUTTONW
				return 0, true
			case wmUser + 39: // TB_SETPARENT
				return 0, true
			case wmUser + 93: // TB_SETBUTTONINFOW
				return 1, true
			case wmUser + 63: // TB_GETEXTENDEDSTYLE
				return 0, true
			case wmUser + 64: // TB_SETEXTENDEDSTYLE
				return 0, true
			case wmUser + 28: // TB_LOADIMAGES
				return 0, true
			case wmUser + 5: // TB_GETBUTTON
				return 0, true
			default:
				return 0, true
			}

		case "systabcontrol32":
			const tcmFirst = 0x1300
			switch msg {
			case tcmFirst + 7: // TCM_INSERTITEMA
				// TCITEMA: mask(4), dwState(4), dwStateMask(4), [pad4], pszText(8 ptr)
				if lParam != 0 {
					mask, _ := mem.Read32(lParam)
					if mask&0x1 != 0 { // TCIF_TEXT
						pText, _ := mem.Read64(lParam + 16)
						if pText != 0 {
							text := readGuestString(pText)
							cs.tabTitles = append(cs.tabTitles, text)
						}
					} else {
						cs.tabTitles = append(cs.tabTitles, "")
					}
				}
				cs.tabCount++
				return uint64(cs.tabCount - 1), true
			case tcmFirst + 62: // TCM_INSERTITEMW
				// TCITEMW: mask(4), dwState(4), dwStateMask(4), [pad4], pszText(8 ptr)
				if lParam != 0 {
					mask, _ := mem.Read32(lParam)
					if mask&0x1 != 0 { // TCIF_TEXT
						pText, _ := mem.Read64(lParam + 16)
						if pText != 0 {
							text := readGuestUTF16(pText)
							cs.tabTitles = append(cs.tabTitles, text)
						}
					} else {
						cs.tabTitles = append(cs.tabTitles, "")
					}
				} else {
					cs.tabTitles = append(cs.tabTitles, "")
				}
				cs.tabCount++
				return uint64(cs.tabCount - 1), true
			case tcmFirst + 8: // TCM_DELETEITEM
				if cs.tabCount > 0 { cs.tabCount-- }
				return 1, true
			case tcmFirst + 5: // TCM_GETITEMCOUNT
				return uint64(cs.tabCount), true
			case tcmFirst + 11: // TCM_GETCURSEL
				return uint64(cs.tabCurSel), true
			case tcmFirst + 12: // TCM_SETCURSEL
				cs.tabCurSel = int(wParam)
				return 0, true
			case tcmFirst + 13: // TCM_HITTEST
				return uint64(0xFFFFFFFF), true // no tab hit
			case tcmFirst + 10: // TCM_GETITEMRECT
				if lParam != 0 {
					mem.Write32(lParam, uint32(int32(wParam)*80))
					mem.Write32(lParam+4, 0)
					mem.Write32(lParam+8, uint32(int32(wParam)*80+80))
					mem.Write32(lParam+12, 22)
				}
				return 1, true
			case tcmFirst + 61: // TCM_GETITEMA
				return 1, true
			case tcmFirst + 60: // TCM_GETITEMW
				return 1, true
			case tcmFirst + 48: // TCM_ADJUSTRECT
				// Shrinks or expands rect by tab bar height
				if lParam != 0 {
					l, _ := mem.Read32(lParam)
					t, _ := mem.Read32(lParam + 4)
					r, _ := mem.Read32(lParam + 8)
					b, _ := mem.Read32(lParam + 12)
					if wParam != 0 { // expand from display area
						mem.Write32(lParam, l)
						mem.Write32(lParam+4, t)
						mem.Write32(lParam+8, r)
						mem.Write32(lParam+12, b+22)
					} else { // shrink to display area
						mem.Write32(lParam, l)
						mem.Write32(lParam+4, t+22)
						mem.Write32(lParam+8, r)
						mem.Write32(lParam+12, b)
					}
				}
				return 0, true
			case tcmFirst + 26: // TCM_SETITEMSIZE
				return 1, true
			case 0x0030: // WM_SETFONT
				return 0, true
			case 0x0005: // WM_SIZE
				cs.w = int32(lParam & 0xFFFF)
				cs.h = int32(lParam >> 16)
				return 0, true
			case 0x000F: // WM_PAINT - draw tab bar strip (not the full client area)
				if wlWindow != nil {
					const tabH = int32(22) // height of tab header strip
					// Only fill the tab strip area, not the entire control height
					wlWindow.DrawRectAbs(cs.x, cs.y, cs.x+cs.w, cs.y+tabH, sysColors[15])
					// Bottom border of tab strip
					wlWindow.DrawRectAbs(cs.x, cs.y+tabH-1, cs.x+cs.w, cs.y+tabH, sysColors[16])
					// Draw tabs
					x := cs.x
					for i := 0; i < cs.tabCount; i++ {
						sel := i == cs.tabCurSel
						bgCol := sysColors[15]
						if sel { bgCol = sysColors[5] }
						tabW := int32(80)
						wlWindow.DrawRectAbs(x, cs.y, x+tabW, cs.y+tabH, bgCol)
						// tab border
						wlWindow.DrawRectAbs(x, cs.y, x+1, cs.y+tabH, sysColors[16])
						wlWindow.DrawRectAbs(x+tabW-1, cs.y, x+tabW, cs.y+tabH, sysColors[16])
						wlWindow.DrawRectAbs(x, cs.y, x+tabW, cs.y+1, sysColors[16])
						// tab title
						if i < len(cs.tabTitles) && cs.tabTitles[i] != "" {
							textColor := uint32(0x000000)
							wlWindow.DrawTextAbs(x+4, cs.y+4, cs.tabTitles[i], textColor, bgCol, false)
						}
						x += tabW
					}
				}
				return 0, true
			default:
				return 0, true
			}

		case "tooltips_class32":
			// Tooltips: just return success for all messages
			return 0, true
		}
		return innerBuiltin(hwnd, msg, wParam, lParam)
	}
	paintTree = func(parentHwnd uint64) {
		var children []uint64
		for h, cs := range hwndChildren {
			if cs.parentHWND == parentHwnd && cs.visible {
				children = append(children, h)
			}
		}
		sort.Slice(children, func(i, j int) bool { return children[i] < children[j] })
		for _, h := range children {
			cs := hwndChildren[h]
			ravelog.Logf("[paint] paintTree child=0x%x class=%q pos=(%d,%d %dx%d)\n", h, cs.className, cs.x, cs.y, cs.w, cs.h)
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
		queue              []syncDispatch
		retAddr            uint64
		hwnd               uint64
		returnWndProcResult bool // if true, return WndProc's RAX instead of hwnd
	}
	var syncStack []syncDispatchFrame

	const syncTrampolineID = 0x3FFE
	// Allocate a trampoline page.
	// Layout:
	//   +0  48 89 05 09 00 00 00  MOV [RIP+9], RAX  ; save WndProc result at +16
	//   +7  B8 FE 3F 00 00        MOV EAX, 0x3FFE   ; trampoline vmcall ID
	//   +12 0F 01 C1              VMCALL
	//   +15 C3                    RET
	//   +16 (8 bytes)             WndProc RAX save slot
	syncTrampoline := mem.Mmap(0, 4096, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	// MOV [RIP+9], RAX - after this 7-byte instruction RIP=+7, so [+7+9]=[+16]
	mem.Write8(syncTrampoline+0, 0x48)
	mem.Write8(syncTrampoline+1, 0x89)
	mem.Write8(syncTrampoline+2, 0x05)
	mem.Write32(syncTrampoline+3, 9) // RIP-relative offset
	mem.Write8(syncTrampoline+7, 0xB8)               // MOV EAX, imm32
	mem.Write32(syncTrampoline+8, syncTrampolineID)
	mem.Write8(syncTrampoline+12, 0x0F)               // vmcall
	mem.Write8(syncTrampoline+13, 0x01)
	mem.Write8(syncTrampoline+14, 0xC1)
	mem.Write8(syncTrampoline+15, 0xC3)               // ret

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

		// Queue empty: all sync dispatches done. Pop frame and return.
		retAddr := frame.retAddr
		hwnd := frame.hwnd
		returnWndProcResult := frame.returnWndProcResult
		syncStack = syncStack[:len(syncStack)-1]

		rsp := rr.ReadReg(4) // RSP
		rsp -= 8
		mem.Write64(rsp, retAddr)
		rw.WriteReg(4, rsp)
		if returnWndProcResult {
			// RAX was saved to syncTrampoline+16 by the first trampoline instruction
			// before MOV EAX,ID overwrote it.
			saved, _ := mem.Read64(syncTrampoline + 16)
			ctx.SetReturn(saved)
		} else {
			ctx.SetReturn(hwnd)
		}
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
			// hInstance := ctx.Arg(0)
			lpTableName := ctx.Arg(1)
			var resID uint16
			if lpTableName < 0x10000 {
				resID = uint16(lpTableName)
			} else {
				name := readGuestUTF16(lpTableName)
				if n, err := strconv.Atoi(name); err == nil {
					resID = uint16(n)
				}
			}
			_ = resID
			// Return a real handle - accelerator tables are only used
			// by TranslateAccelerator which we stub
			h := handles.Alloc(&ntapi.GenericHandle{Kind: "accel"})
			ctx.SetReturn(uint64(h))
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
		d.RegisterAutoStubHandler(user32, "wsprintfA", func(ctx *ntapi.TrapContext) uint32 {
			lpOut := ctx.Arg(0)
			lpFmt := ctx.Arg(1)
			fmtStr := readGuestString(lpFmt)
			var args []uint64
			for i := 2; i < 10; i++ {
				args = append(args, ctx.Arg(i))
			}
			result := wideprintf(fmtStr, args)
			for i := range result { mem.Write8(lpOut+uint64(i), result[i]) }
			mem.Write8(lpOut+uint64(len(result)), 0)
			ctx.SetReturn(uint64(len(result)))
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
						} else {
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
			parentHwndLog := ctx.Arg(8)
			ravelog.Logf("[wndclass] CreateWindowExW class=%q hwnd=0x%x parent=0x%x wndProc=0x%x style=0x%x\n", className, hwnd, parentHwndLog, wp, style)

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
				// Child windows with invalid/zero dimensions start at 0×0.
				// They will be sized by the parent's WM_SIZE/MoveWindow calls.
				if cw < 0 || cw > 0x7FFF { cw = 0 }
				if ch < 0 || ch > 0x7FFF { ch = 0 }
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
				dwExStyle := uint32(ctx.Arg(0))
				hMenu := ctx.Arg(9) // for child windows, this is the control ID
				hwndChildren[hwnd] = &controlState{
					className:  lClassName,
					parentHWND: parentHwnd,
					ctrlID:    hMenu,
					x: cx, y: cy, w: cw, h: ch,
					style:   style,
					exStyle: dwExStyle,
					text:    windowName,
					visible: style&0x10000000 != 0, // WS_VISIBLE
				}
				// Initialise GWL_STYLE / GWL_EXSTYLE so GetWindowLong returns correct values.
				windowLongPtr[hwnd] = map[int32]uint64{-16: uint64(style), -20: uint64(dwExStyle)}
				win32.Global.Create(hwnd, lClassName, cx, cy, cw, ch, style, dwExStyle, parentHwnd)
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
					const wsCaption = 0x00C00000
					// Compute NC top height from window style (ported from ReactOS NCCALCSIZE).
					// This replaces the hardcoded titleBarH=30 that was the old fake CSD.
					ncTop := int32(0)
					if wlDisplay.HasNoSSD() {
						// Use AdjustWindowRectEx to compute borders: start with
						// a zero client rect and see how much the top grows.
						var r win32.Rect
						exStyle := uint32(ctx.Arg(0))
						hasMenu := false
						if hm := ctx.Arg(9); hm != 0 {
							if _, ok := menus[hm]; ok {
								hasMenu = true
							}
						}
						win32.AdjustWindowRectEx(&r, style, hasMenu, exStyle)
						ncTop = -r.Top // r.Top is negative after AdjustWindowRectEx
						if ncTop < 0 {
							ncTop = 0
						}
					}
					if win, err := wlDisplay.CreateWindow(title, w, h, ncTop); err == nil {
						wlWindow = win
						mainHWND = hwnd
						mainTitle = title
						// Initialise GWL_STYLE / GWL_EXSTYLE for the main window.
						exStyle := uint32(ctx.Arg(0))
						windowLongPtr[hwnd] = map[int32]uint64{-16: uint64(style), -20: uint64(exStyle)}
						// Register the main window in win32.Global so NC paint and other lookups work.
						win32.Global.Create(hwnd, strings.ToLower(readGuestUTF16(lpClassName)), 0, 0, w, h, style, exStyle, 0)
						ravelog.Logf("[wl] window created: %q %dx%d hwnd=0x%x ncTop=%d\n", title, w, h, hwnd, ncTop)
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
								ravelog.Logf("[menu] attached class menu hmenu=0x%x to hwnd=0x%x\n", mh, hwnd)
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
				// Win32: ShowWindow on a parent sends WM_SHOWWINDOW (0x0018) to all children.
				// DefWindowProc sets WS_VISIBLE on children. Simulate: mark all children visible.
				if nCmdShow != 0 {
					for h, cs := range hwndChildren {
						if !cs.visible {
							cs.visible = true
							if wp, ok2 := hwndWndProc[h]; ok2 && wp != 0 {
								msgQueue = append(msgQueue, queuedMsg{h, 0x000F, 0, 0})
							}
						}
					}
				}
			}
			if cs, ok := hwndChildren[hwnd]; ok {
				wasVisible := cs.visible
				cs.visible = nCmdShow != 0 // SW_HIDE = 0
				// Queue WM_PAINT when a window with a guest WndProc becomes visible
				if cs.visible && !wasVisible {
					if wp, ok2 := hwndWndProc[hwnd]; ok2 && wp != 0 {
						msgQueue = append(msgQueue, queuedMsg{hwnd, 0x000F, 0, 0})
					}
				}
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
		d.RegisterAutoStubHandler(user32, "FindWindowExA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "GetDC", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			ox, oy := clientAreaOrigin(hwnd)
			h, dc := allocScreenDC(ox, oy)
			if cs, ok := hwndChildren[hwnd]; ok {
				dc.SetClipRect(cs.x, cs.y, cs.x+cs.w, cs.y+cs.h)
			}
			ctx.SetReturn(h)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "ReleaseDC", func(ctx *ntapi.TrapContext) uint32 {
			gdiMgr.DeleteDC(ctx.Arg(1))
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "GetSystemMetrics", func(ctx *ntapi.TrapContext) uint32 {
			idx := int(ctx.Arg(0))
			// Keep SM_CXSCREEN / SM_CYSCREEN in sync with actual Wayland window size.
			if wlWindow != nil {
				win32.ScreenWidth = int32(wlWindow.Width)
				win32.ScreenHeight = int32(wlWindow.Height)
			}
			ctx.SetReturn(uint64(win32.GetSystemMetrics(idx)))
			return 0
		})
		d.RegisterAutoStubHandler(user32, "GetSysColor", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(uint64(getSysColor(uint32(ctx.Arg(0)))))
			return 0
		})
		d.RegisterAutoStubHandler(user32, "LoadCursorW", func(ctx *ntapi.TrapContext) uint32 {
			// Return IDC_ value as handle so SetCursor can map it back.
			// IDC_ARROW=32512, IDC_IBEAM=32513, etc.
			lpCursorName := ctx.Arg(1)
			if lpCursorName < 0x10000 && lpCursorName != 0 {
				ctx.SetReturn(lpCursorName) // atom → return as-is
			} else {
				ctx.SetReturn(0x00010001) // default dummy
			}
			return 0
		})
		d.RegisterAutoStubHandler(user32, "LoadIconW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x00020001) // dummy icon handle
			return 0
		})
		d.RegisterAutoStubHandler(user32, "LoadImageW", func(ctx *ntapi.TrapContext) uint32 {
			hInst := ctx.Arg(0)
			nameArg := ctx.Arg(1)
			imgType := ctx.Arg(2)
			// IMAGE_BITMAP=0: try to load from PE resource
			if imgType == 0 && nameArg < 0x10000 && mainModule != nil &&
				(hInst == mainModule.BaseAddr || hInst == 0) {
				resID := uint32(nameArg)
				addr, sz, ok2 := peLoadRawResource(mainModule.BaseAddr, mainModule.ResourceDirRVA, 2 /*RT_BITMAP*/, resID)
				if ok2 {
					slots := decodeDIBSlots(addr, sz, 0, 0)
					h := nextBitmapHandle
					nextBitmapHandle += 2
					bd := &bitmapHandleData{slots: slots}
					if len(slots) > 0 {
						bd.w = len(slots[0])
					}
					bitmapHandles[h] = bd
					ravelog.Logf("[loadimage] LoadImageW IMAGE_BITMAP resID=0x%x → handle=0x%x slots=%d\n", resID, h, len(slots))
					ctx.SetReturn(h)
					return 0
				}
			}
			ctx.SetReturn(0x00030001) // fallback dummy handle
			return 0
		})
		d.RegisterAutoStubHandler(user32, "SetWindowPos", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			// Handle main (top-level) window resize - updates the Wayland window
			if hwnd == mainHWND && wlWindow != nil {
				flags := uint32(ctx.Arg(6))
				const swpNoSize = 0x0001
				const swpNoMove = 0x0002
				prevW, prevH := wlWindow.Width, wlWindow.Height
				mainX, mainY := int32(0), int32(0)
				if flags&swpNoSize == 0 {
					w := int32(ctx.Arg(4))
					h := int32(ctx.Arg(5))
					if w > 0 && w < 0x7FFF && h > 0 && h < 0x7FFF {
						if wlWindow.Resize(w, h) {
							syncScreenSurface()
							ravelog.Logf("[setpos] mainHWND resize → %dx%d\n", w, h)
						}
						lParam := uint64(uint16(w)) | (uint64(uint16(h)) << 16)
						msgQueue = append(msgQueue, queuedMsg{hwnd, 0x0005, 0, lParam})
						msgQueue = append(msgQueue, queuedMsg{hwnd, 0x000F, 0, 0})
					}
				}
				if flags&swpNoMove == 0 {
					// Wayland top-level position is compositor-managed; track for GetWindowRect
					mainX = int32(ctx.Arg(2))
					mainY = int32(ctx.Arg(3))
					if mainX < 0 || mainX >= 0x7FFF { mainX = 0 }
					if mainY < 0 || mainY >= 0x7FFF { mainY = 0 }
				}
				// Keep win32.Global in sync for GetWindowRect/GetClientRect
				if wnd := win32.Global.Get(hwnd); wnd != nil {
					win32.Global.UpdatePos(wnd, mainX, mainY, wlWindow.Width, wlWindow.Height)
				}
				if wlWindow.Width != prevW || wlWindow.Height != prevH {
					msgQueue = append(msgQueue, queuedMsg{hwnd, 0x0003, uint64(uint16(mainX)) | (uint64(uint16(mainY)) << 16), 0})
				}
				ctx.SetReturn(1)
				return 0
			}
			if ci, ok := hwndChildren[hwnd]; ok {
				flags := uint32(ctx.Arg(6))
				const swpNoMove       = 0x0002
				const swpNoSize       = 0x0001
				const swpShowWindow   = 0x0040
				const swpHideWindow   = 0x0080
				ox, oy := clientAreaOrigin(ci.parentHWND)
				prevX, prevY := ci.x, ci.y
				prevW, prevH := ci.w, ci.h
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
				if flags&swpShowWindow != 0 {
					ci.visible = true
				}
				if flags&swpHideWindow != 0 {
					ci.visible = false
				}
				// Auto-show: if window is sized non-zero, treat as implicitly visible.
				// (Win32 WM_SHOWWINDOW from parent's ShowWindow may not fire in our HLE)
				if ci.w > 0 && ci.h > 0 {
					ci.visible = true
				}
				ravelog.Logf("[setpos] hwnd=0x%x class=%q flags=0x%x → %d,%d %dx%d visible=%v\n", hwnd, ci.className, flags, ci.x, ci.y, ci.w, ci.h, ci.visible)
				if wnd := win32.Global.Get(hwnd); wnd != nil {
					win32.Global.UpdatePos(wnd, ci.x, ci.y, ci.w, ci.h)
				}
				// Queue WM_SIZE / WM_MOVE for windows with a guest WndProc
				if wp, ok := hwndWndProc[hwnd]; ok && wp != 0 {
					if ci.w != prevW || ci.h != prevH {
						lParam := uint64(uint16(ci.w)) | (uint64(uint16(ci.h)) << 16)
						msgQueue = append(msgQueue, queuedMsg{hwnd, 0x0005, 0, lParam})
					}
					if ci.x != prevX || ci.y != prevY {
						// WM_MOVE lParam = MAKELPARAM(x, y) in client-relative coords
						relX := ci.x - ox
						relY := ci.y - oy
						msgQueue = append(msgQueue, queuedMsg{hwnd, 0x0003, 0, uint64(uint16(relX)) | (uint64(uint16(relY)) << 16)})
					}
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
			ravelog.Logf("[defer] DeferWindowPos hwnd=0x%x x=%d y=%d w=%d h=%d flags=0x%x\n", hwnd, x, y, cx, cy, flags)
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
				prevX, prevY := ci.x, ci.y
				prevW, prevH := ci.w, ci.h
				if dp.flags&swpNoMove == 0 {
					ci.x = dp.x + ox
					ci.y = dp.y + oy
				}
				if dp.flags&swpNoSize == 0 {
					if dp.w > 0 {
						ci.w = dp.w
					}
					if dp.h > 0 {
						ci.h = dp.h
					}
				}
				ravelog.Logf("[setpos] hwnd=0x%x class=%q flags=0x%x → %d,%d %dx%d\n", dp.hwnd, ci.className, dp.flags, ci.x, ci.y, ci.w, ci.h)
				// Auto-show: sized non-zero → implicitly visible
				if ci.w > 0 && ci.h > 0 {
					ci.visible = true
				}
				if wnd := win32.Global.Get(dp.hwnd); wnd != nil {
					win32.Global.UpdatePos(wnd, ci.x, ci.y, ci.w, ci.h)
				}
				// Dispatch WM_SIZE / WM_MOVE to children with guest WndProcs
				if wp, ok2 := hwndWndProc[dp.hwnd]; ok2 && wp != 0 {
					if ci.w != prevW || ci.h != prevH {
						lParam := uint64(uint16(ci.w)) | (uint64(uint16(ci.h)) << 16)
						msgQueue = append(msgQueue, queuedMsg{dp.hwnd, 0x0005, 0, lParam})
					}
					if ci.x != prevX || ci.y != prevY {
						relX := ci.x - ox
						relY := ci.y - oy
						msgQueue = append(msgQueue, queuedMsg{dp.hwnd, 0x0003, 0, uint64(uint16(relX)) | (uint64(uint16(relY)) << 16)})
					}
				}
			}
			deferredPositions = deferredPositions[:0]
			ctx.SetReturn(1)
			return 0
		})

		d.RegisterAutoStubHandler(user32, "MoveWindow", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			newX, newY := int32(ctx.Arg(1)), int32(ctx.Arg(2))
			newW, newH := int32(ctx.Arg(3)), int32(ctx.Arg(4))
			bRepaint := ctx.Arg(5)
			ravelog.Logf("[move] MoveWindow hwnd=0x%x x=%d y=%d w=%d h=%d repaint=%d\n", hwnd, newX, newY, newW, newH, bRepaint)
			// Handle main window resize
			if hwnd == mainHWND && wlWindow != nil {
				prevW, prevH := wlWindow.Width, wlWindow.Height
				if newW > 0 && newW < 0x7FFF && newH > 0 && newH < 0x7FFF {
					if wlWindow.Resize(newW, newH) {
						syncScreenSurface()
					}
					lParam := uint64(uint16(newW)) | (uint64(uint16(newH)) << 16)
					msgQueue = append(msgQueue, queuedMsg{hwnd, 0x0005, 0, lParam})
					if bRepaint != 0 {
						msgQueue = append(msgQueue, queuedMsg{hwnd, 0x000F, 0, 0})
					}
				}
				// Keep win32.Global in sync
				if wnd := win32.Global.Get(hwnd); wnd != nil {
					win32.Global.UpdatePos(wnd, 0, 0, wlWindow.Width, wlWindow.Height)
				}
				if wlWindow.Width != prevW || wlWindow.Height != prevH {
					msgQueue = append(msgQueue, queuedMsg{hwnd, 0x0003, 0, 0})
				}
				ctx.SetReturn(1)
				return 0
			}
			if ci, ok := hwndChildren[hwnd]; ok {
				ox, oy := clientAreaOrigin(ci.parentHWND)
				prevX, prevY := ci.x, ci.y
				prevW, prevH := ci.w, ci.h
				ci.x = newX + ox
				ci.y = newY + oy
				if newW > 0 { ci.w = newW }
				if newH > 0 { ci.h = newH }
				// Auto-show: sized non-zero → implicitly visible
				if ci.w > 0 && ci.h > 0 {
					ci.visible = true
				}
				if wnd := win32.Global.Get(hwnd); wnd != nil {
					win32.Global.UpdatePos(wnd, ci.x, ci.y, ci.w, ci.h)
				}
				// Queue WM_SIZE / WM_MOVE for windows with a guest WndProc
				if wp, ok := hwndWndProc[hwnd]; ok && wp != 0 {
					if ci.w != prevW || ci.h != prevH {
						lParam := uint64(uint16(ci.w)) | (uint64(uint16(ci.h)) << 16)
						msgQueue = append(msgQueue, queuedMsg{hwnd, 0x0005, 0, lParam})
					}
					if ci.x != prevX || ci.y != prevY {
						relX := ci.x - ox
						relY := ci.y - oy
						msgQueue = append(msgQueue, queuedMsg{hwnd, 0x0003, 0, uint64(uint16(relX)) | (uint64(uint16(relY)) << 16)})
					}
				}
				if bRepaint != 0 {
					msgQueue = append(msgQueue, queuedMsg{hwnd, 0x000F, 0, 0})
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
				if wlWindow != nil {
					wlWindow.Title = text
					// Update the compositor title (xdg_toplevel.set_title opcode 2)
					wlDisplay.SetWindowTitle(wlWindow, text)
				}
			}
			if cs, ok := hwndChildren[hwnd]; ok {
				cs.text = text
			}
			hwndTitle[hwnd] = text
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
			win32.Global.SetLong(hwnd, index, newVal)
			ravelog.Logf("[wndlong] SetWindowLongPtrW hwnd=0x%x index=%d val=0x%x\n", hwnd, index, newVal)
			ctx.SetReturn(old)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "GetWindowLongPtrW", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			index := int32(ctx.Arg(1))
			var val uint64
			if m, ok := windowLongPtr[hwnd]; ok {
				val = m[index]
			}
			ravelog.Logf("[wndlong] GetWindowLongPtrW hwnd=0x%x index=%d → 0x%x\n", hwnd, index, val)
			ctx.SetReturn(val)
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
				var left, top, right, bottom int32
				if ci, ok := hwndChildren[hwnd]; ok {
					// Child window: client area is the full window rect (origin at 0,0)
					right, bottom = ci.w, ci.h
				} else if hwnd == mainHWND {
					// Top-level window: use Wayland dimensions, subtract menu bar height
					right, bottom = 800, 600
					if wlWindow != nil {
						right, bottom = wlWindow.Width, wlWindow.Height
						
					}
					if _, hasMenu := hwndMenuBar[hwnd]; hasMenu {
						bottom -= menuBarHeight
					}
				} else if wnd := win32.Global.Get(hwnd); wnd != nil {
					// Window registered in global table but not yet in hwndChildren
					right = wnd.RcClient.Width()
					bottom = wnd.RcClient.Height()
				} else {
					right, bottom = 800, 600
					if wlWindow != nil {
						right, bottom = wlWindow.Width, wlWindow.Height
					}
				}
				ravelog.Logf("[getrect] GetClientRect hwnd=0x%x → %d,%d,%d,%d\n", hwnd, left, top, right, bottom)
				ctx.Mem.Write32(pRect, uint32(left))
				ctx.Mem.Write32(pRect+4, uint32(top))
				ctx.Mem.Write32(pRect+8, uint32(right))
				ctx.Mem.Write32(pRect+12, uint32(bottom))
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "GetWindowRect", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			pRect := ctx.Arg(1)
			if pRect != 0 {
				if wnd := win32.Global.Get(hwnd); wnd != nil {
					// Use the pre-computed screen-absolute window rect from win32.Global
					ctx.Mem.Write32(pRect, uint32(wnd.RcWindow.Left))
					ctx.Mem.Write32(pRect+4, uint32(wnd.RcWindow.Top))
					ctx.Mem.Write32(pRect+8, uint32(wnd.RcWindow.Right))
					ctx.Mem.Write32(pRect+12, uint32(wnd.RcWindow.Bottom))
				} else if ci, ok := hwndChildren[hwnd]; ok {
					// Fallback: child window stored absolute coords
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
					var fw, fh int32 = 800, 600
					if wlWindow != nil { fw, fh = wlWindow.Width, wlWindow.Height }
					ctx.Mem.Write32(pRect, 0)
					ctx.Mem.Write32(pRect+4, 0)
					ctx.Mem.Write32(pRect+8, uint32(fw))
					ctx.Mem.Write32(pRect+12, uint32(fh))
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
			// Log SCI messages (>= 0x400 = WM_USER) sent to Scintilla
			if msg >= 0x0400 {
				ravelog.Logf("[sci] SendMessageW hwnd=0x%x msg=0x%x(%d) wParam=0x%x\n", hwnd, msg, msg, wParam)
			}
			// Built-in controls first
			if result, handled := builtinWndProc(hwnd, msg, wParam, lParam); handled {
				ctx.SetReturn(result)
				return 0
			}
			// For guest WndProcs: dispatch synchronously via syncStack
			wp, hasWP := hwndWndProc[hwnd]
			if !hasWP || wp == 0 {
				ctx.SetReturn(0)
				return 0
			}
			rw, okW := ctx.CPU.(ntapi.RegisterWriter)
			rr, okR := ctx.CPU.(ntapi.RegisterReader)
			if okW && okR {
				rsp := rr.ReadReg(4)
				retAddr, _ := mem.Read64(rsp)
				syncStack = append(syncStack, syncDispatchFrame{
					queue:               []syncDispatch{},
					retAddr:             retAddr,
					hwnd:                hwnd,
					returnWndProcResult: true,
				})
				mem.Write64(rsp, syncTrampoline)
				rw.WriteReg(1, hwnd)
				rw.WriteReg(2, uint64(msg))
				rw.WriteReg(8, wParam)
				rw.WriteReg(9, lParam)
				ctx.CPU.SetPC(wp)
				ctx.ReturnOverridden = true
				return 0
			}
			// Fallback: queue for async dispatch (won't return result synchronously)
			msgQueue = append(msgQueue, queuedMsg{hwnd, msg, wParam, lParam})
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "PostMessageW", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			msg := uint32(ctx.Arg(1))
			wParam := ctx.Arg(2)
			lParam := ctx.Arg(3)
			// Route into our message queue so guest WndProcs see it
			if hwnd == mainHWND || hwnd == 0xFFFF || hwnd == 0xFFFFFFFFFFFFFFFF {
				msgQueue = append(msgQueue, queuedMsg{mainHWND, msg, wParam, lParam})
			} else if _, ok := hwndChildren[hwnd]; ok {
				msgQueue = append(msgQueue, queuedMsg{hwnd, msg, wParam, lParam})
			}
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(user32, "DefWindowProcW", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			msg := uint32(ctx.Arg(1))
			wParam := ctx.Arg(2)
			lParam := ctx.Arg(3)

			// WM_PAINT: draw non-client area (NC paint + menu bar), erase background, paint children
			if msg == 0x000F && wlWindow != nil {
				if hwnd == mainHWND {
					if wlWindow.ResizeIfNeeded() {
						syncScreenSurface()
					}
					w := wlWindow.Width

					// Trigger NC paint first (draws frame + caption + client edge)
					if wlWindow.TitleBarH > 0 {
						ncPaintCtx := *ctx // shallow copy for re-entrant dispatch
						_ = ncPaintCtx
						// Directly invoke our WM_NCPAINT handler logic
						wnd := win32.Global.Get(hwnd)
						if wnd != nil {
							ncStyle := wnd.Style
							ncExStyle := wnd.ExStyle
							winW := wlWindow.Width
							winH := wlWindow.Height + wlWindow.TitleBarH
							syncScreenSurface()
							_, ncDC := gdiMgr.AllocScreenDC()
							ncDC.OriginX = 0
							ncDC.OriginY = 0
							curL, curT, curR, curB := int32(0), int32(0), winW, winH

							if win32.UserHasWindowEdge(ncStyle, ncExStyle) {
								ncDC.DrawEdge(curL, curT, curR, curB, 0x0005, 0x000F, sysColors)
								curL += 2; curT += 2; curR -= 2; curB -= 2
							}
							if ncStyle&0x00040000 != 0 && ncStyle&0x20000000 == 0 {
								fW := (win32.GetSystemMetrics(win32.SM_CXFRAME) - win32.GetSystemMetrics(win32.SM_CXDLGFRAME)) *
									win32.GetSystemMetrics(win32.SM_CXBORDER)
								fH := (win32.GetSystemMetrics(win32.SM_CYFRAME) - win32.GetSystemMetrics(win32.SM_CYDLGFRAME)) *
									win32.GetSystemMetrics(win32.SM_CYBORDER)
								borderColor := sysColors[10]
								if !mainActive { borderColor = sysColors[11] }
								ncDC.FillRect(curL, curT, curR, curT+fH, borderColor)
								ncDC.FillRect(curL, curT, curL+fW, curB, borderColor)
								ncDC.FillRect(curL, curB-fH, curR, curB, borderColor)
								ncDC.FillRect(curR-fW, curT, curR, curB, borderColor)
								curL += fW; curT += fH; curR -= fW; curB -= fH
							}
							if ncStyle&(0x00400000|0x00800000) != 0 || ncExStyle&0x00000001 != 0 {
								bW := win32.GetSystemMetrics(win32.SM_CXBORDER)
								bH := win32.GetSystemMetrics(win32.SM_CYBORDER)
								var brushColor uint32
								if ncExStyle&(0x00000001|0x00000200) != 0 {
									brushColor = sysColors[15]
								} else if ncExStyle&0x00020000 != 0 {
									brushColor = sysColors[6]
								} else if ncStyle&(0x00400000|0x00040000) != 0 {
									brushColor = sysColors[15]
								} else {
									brushColor = sysColors[6]
								}
								ncDC.FillRect(curL, curT, curR, curT+bH, brushColor)
								ncDC.FillRect(curL, curT, curL+bW, curB, brushColor)
								ncDC.FillRect(curL, curB-bH, curR, curB, brushColor)
								ncDC.FillRect(curR-bW, curT, curR, curB, brushColor)
								curL += bW; curT += bH; curR -= bW; curB -= bH
							}
							if ncStyle&0x00C00000 == 0x00C00000 {
								captionH := win32.GetSystemMetrics(win32.SM_CYCAPTION)
								if ncExStyle&0x00000080 != 0 {
									captionH = win32.GetSystemMetrics(win32.SM_CYSMCAPTION)
								}
								captionBottom := curT + captionH
								flags := uint32(0x0020 | 0x0008)
								if mainActive { flags |= 0x0001 }
								ncDC.DrawCaption(curL, curT, curR, captionBottom-1, mainTitle, flags, sysColors)
								btnW := win32.GetSystemMetrics(win32.SM_CXSIZE)
								btnH := captionH - 2
								if ncStyle&0x00080000 != 0 {
									ncDC.DrawFrameControl(curR-btnW, curT, curR, curT+btnH, 1, 0, sysColors)
									if ncExStyle&0x00000080 == 0 && ncStyle&(0x00020000|0x00010000) != 0 {
										ncDC.DrawFrameControl(curR-2*btnW, curT, curR-btnW, curT+btnH, 1, 2, sysColors)
										ncDC.DrawFrameControl(curR-3*btnW, curT, curR-2*btnW, curT+btnH, 1, 1, sysColors)
									}
								}
								lineColor := sysColors[15]
								ncDC.FillRect(curL, captionBottom-1, curR, captionBottom, lineColor)
								curT = captionBottom
							}
							if ncExStyle&0x00000200 != 0 {
								ncDC.DrawEdge(curL, curT, curR, curB, 0x000A, 0x000F, sysColors)
							}
						}
					}

					clientTop := wlWindow.TitleBarH
					ravelog.Logf("[paint] DefWndProc WM_PAINT mainHWND w=%d h=%d\n", wlWindow.Width, wlWindow.Height)

					// Non-client area: draw menu bar
					menuH, menuOk := hwndMenuBar[hwnd]
					if menuOk {
						md, ok2 := menus[menuH]
						if ok2 && len(md.items) > 0 {
							clientTop = wlWindow.TitleBarH + menuBarHeight
							wlWindow.DrawRectAbs(0, wlWindow.TitleBarH, w, clientTop, sysColors[15])
							wlWindow.DrawRectAbs(0, clientTop-1, w, clientTop, sysColors[16])
							x := int32(4)
							for i, item := range md.items {
								if item.flags&0x0800 != 0 {
									continue
								}
								// Only show popup items in menu bar (items with submenus)
								if item.flags&0x0010 == 0 {
									continue
								}
								label := menuStripAmpersand(item.text)
								// Strip accelerator text after tab
								if idx := strings.IndexByte(label, '\t'); idx >= 0 {
									label = label[:idx]
								}
								if label == "" || label == "-" {
									continue
								}
								// Skip items with no ASCII-renderable characters
								hasRenderable := false
								for _, r := range label {
									if r >= 32 && r <= 126 {
										hasRenderable = true
										break
									}
								}
								if !hasRenderable {
									continue
								}
								tw := int32(len([]rune(label)))*8 + 12
								if openMenuIdx == i && openMenuHwnd == hwnd {
									wlWindow.DrawRectAbs(x, wlWindow.TitleBarH, x+tw, clientTop-1, sysColors[20])
									wlWindow.DrawTextAbs(x+4, wlWindow.TitleBarH+3, label, 0x000000, sysColors[20], true)
								} else {
									wlWindow.DrawTextAbs(x+4, wlWindow.TitleBarH+3, label, 0x000000, sysColors[15], true)
								}
								x += tw
							}

							// Dropdown overlay drawn later in commitIfDone (after paintTree).
						}
					}

					// Fill entire client area with background color.
					// Builtin children will paint on top via paintTree.
					// Guest-drawn children (Scintilla) repaint in their own
					// WM_PAINT pass and trigger a re-commit.
					totalH := wlWindow.Height + wlWindow.TitleBarH
					wlWindow.DrawRectAbs(0, clientTop, w, totalH, sysColors[5])

					// Recursively paint built-in descendant windows (builtinWndProc skips app-defined children)
					paintTree(hwnd)
					// Signal that the base frame is ready; all subsequent EndPaints can trigger re-commits.
					hasBaseFrame = true
					repaintBuiltin = true
					frameReady = true
					commitIfDone()
				}
				// For non-mainHWND: ReactOS DefWindowProc just calls BeginPaint+EndPaint
				// In our model, the child is painted by paintTree from the parent
				ctx.SetReturn(0)
				return 0
			}
			// WM_NCCALCSIZE (0x0083): compute client rect from window rect.
			// Ported from ReactOS nonclient.c NC_HandleNCCalcSize.
			if msg == 0x0083 && wlWindow != nil {
				wnd := win32.Global.Get(hwnd)
				if wnd != nil {
					style := wnd.Style
					exStyle := wnd.ExStyle
					if style&0x20000000 == 0 { // !WS_MINIMIZE
						// Read the proposed RECT from guest memory (lParam).
						// For wParam==0 lParam → single RECT.
						// For wParam==1 lParam → NCCALCSIZE_PARAMS (first RECT is the new window rect).
						rAddr := lParam
						rL, _ := mem.Read32(rAddr)
						rT, _ := mem.Read32(rAddr + 4)
						rR, _ := mem.Read32(rAddr + 8)
						rBot, _ := mem.Read32(rAddr + 12)
						left := int32(rL)
						top := int32(rT)
						right := int32(rR)
						bottom := int32(rBot)

						// Deflate by border
						if win32.UserHasWindowEdge(style, exStyle) {
							bx, by := win32.BorderSize(style, exStyle)
							left += bx; top += by; right -= bx; bottom -= by
						} else if exStyle&0x00020000 != 0 { // WS_EX_STATICEDGE
							left++; top++; right--; bottom--
						} else if style&0x00800000 != 0 { // WS_BORDER
							left++; top++; right--; bottom--
						}

						// Subtract caption
						if style&0x00C00000 == 0x00C00000 { // WS_CAPTION
							if exStyle&0x00000080 != 0 { // WS_EX_TOOLWINDOW
								top += win32.GetSystemMetrics(win32.SM_CYSMCAPTION)
							} else {
								top += win32.GetSystemMetrics(win32.SM_CYCAPTION)
							}
						}

						// Subtract menu bar
						if _, hasMenu := hwndMenuBar[hwnd]; hasMenu {
							top += menuBarHeight
						}

						// Subtract client edge
						if exStyle&0x00000200 != 0 { // WS_EX_CLIENTEDGE
							bw := win32.GetSystemMetrics(win32.SM_CXBORDER)
							bh := win32.GetSystemMetrics(win32.SM_CYBORDER)
							left += 2 * bw; top += 2 * bh
							right -= 2 * bw; bottom -= 2 * bh
						}

						if top > bottom { bottom = top }
						if left > right { right = left }

						// Write back
						mem.Write32(rAddr, uint32(left))
						mem.Write32(rAddr+4, uint32(top))
						mem.Write32(rAddr+8, uint32(right))
						mem.Write32(rAddr+12, uint32(bottom))
					}
				}
				ctx.SetReturn(0)
				return 0
			}
			// WM_NCPAINT (0x0085): draw the non-client area.
			// Ported from ReactOS nonclient.c NC_DoNCPaint.
			if msg == 0x0085 && wlWindow != nil && hwnd == mainHWND {
				wnd := win32.Global.Get(hwnd)
				if wnd != nil {
					style := wnd.Style
					exStyle := wnd.ExStyle
					winW := wlWindow.Width
					winH := wlWindow.Height + wlWindow.TitleBarH
					// Create a window DC (origin 0,0 covering full surface including NC)
					syncScreenSurface()
					hDC, dc := gdiMgr.AllocScreenDC()
					dc.OriginX = 0
					dc.OriginY = 0
					// Current rect tracks the shrinking paint area
					curL, curT, curR, curB := int32(0), int32(0), winW, winH

					// 1. Draw outer edge (EDGE_RAISED)
					if win32.UserHasWindowEdge(style, exStyle) {
						dc.DrawEdge(curL, curT, curR, curB, 0x0005, 0x000F, sysColors) // EDGE_RAISED|BF_RECT
						curL += 2; curT += 2; curR -= 2; curB -= 2 // BF_ADJUST
					} else if exStyle&0x00020000 != 0 { // WS_EX_STATICEDGE
						dc.FillRect(curL, curT, curR, curT+1, sysColors[16]) // top
						dc.FillRect(curL, curT, curL+1, curB, sysColors[16]) // left
						dc.FillRect(curL, curB-1, curR, curB, sysColors[20]) // bottom
						dc.FillRect(curR-1, curT, curR, curB, sysColors[20]) // right
						curL++; curT++; curR--; curB--
					}

					// 2. Draw frame (NC_DrawFrame from ReactOS)
					if style&0x00040000 != 0 && style&0x20000000 == 0 { // WS_THICKFRAME && !WS_MINIMIZE
						fW := (win32.GetSystemMetrics(win32.SM_CXFRAME) - win32.GetSystemMetrics(win32.SM_CXDLGFRAME)) *
							win32.GetSystemMetrics(win32.SM_CXBORDER)
						fH := (win32.GetSystemMetrics(win32.SM_CYFRAME) - win32.GetSystemMetrics(win32.SM_CYDLGFRAME)) *
							win32.GetSystemMetrics(win32.SM_CYBORDER)
						borderColor := sysColors[10] // COLOR_ACTIVEBORDER
						if !mainActive {
							borderColor = sysColors[11] // COLOR_INACTIVEBORDER
						}
						dc.FillRect(curL, curT, curR, curT+fH, borderColor)
						dc.FillRect(curL, curT, curL+fW, curB, borderColor)
						dc.FillRect(curL, curB-fH, curR, curB, borderColor)
						dc.FillRect(curR-fW, curT, curR, curB, borderColor)
						curL += fW; curT += fH; curR -= fW; curB -= fH
					}
					// Inner border
					if style&(0x00400000|0x00800000) != 0 || exStyle&0x00000001 != 0 { // WS_DLGFRAME|WS_BORDER|WS_EX_DLGMODALFRAME
						bW := win32.GetSystemMetrics(win32.SM_CXBORDER)
						bH := win32.GetSystemMetrics(win32.SM_CYBORDER)
						var brushColor uint32
						if exStyle&(0x00000001|0x00000200) != 0 { // WS_EX_DLGMODALFRAME|WS_EX_CLIENTEDGE
							brushColor = sysColors[15] // COLOR_3DFACE
						} else if exStyle&0x00020000 != 0 { // WS_EX_STATICEDGE
							brushColor = sysColors[6] // COLOR_WINDOWFRAME
						} else if style&(0x00400000|0x00040000) != 0 { // WS_DLGFRAME|WS_THICKFRAME
							brushColor = sysColors[15] // COLOR_3DFACE
						} else {
							brushColor = sysColors[6] // COLOR_WINDOWFRAME
						}
						dc.FillRect(curL, curT, curR, curT+bH, brushColor)
						dc.FillRect(curL, curT, curL+bW, curB, brushColor)
						dc.FillRect(curL, curB-bH, curR, curB, brushColor)
						dc.FillRect(curR-bW, curT, curR, curB, brushColor)
						curL += bW; curT += bH; curR -= bW; curB -= bH
					}

					// 3. Draw caption
					if style&0x00C00000 == 0x00C00000 { // WS_CAPTION
						captionH := win32.GetSystemMetrics(win32.SM_CYCAPTION)
						if exStyle&0x00000080 != 0 { // WS_EX_TOOLWINDOW
							captionH = win32.GetSystemMetrics(win32.SM_CYSMCAPTION)
						}
						captionBottom := curT + captionH
						// Draw caption bar with gradient
						flags := uint32(0x0020 | 0x0008) // DC_GRADIENT | DC_TEXT
						if mainActive {
							flags |= 0x0001 // DC_ACTIVE
						}
						dc.DrawCaption(curL, curT, curR, captionBottom-1, mainTitle, flags, sysColors)

						// Draw caption buttons (ReactOS UserDrawCaptionButton)
						btnW := win32.GetSystemMetrics(win32.SM_CXSIZE)
						btnH := captionH - 2
						if style&0x00080000 != 0 { // WS_SYSMENU
							// Close button (rightmost)
							dc.DrawFrameControl(curR-btnW, curT, curR, curT+btnH, 1, 0, sysColors) // DFC_CAPTION, DFCS_CAPTIONCLOSE
							// Min/Max if not tool window
							if exStyle&0x00000080 == 0 {
								if style&(0x00020000|0x00010000) != 0 { // WS_MINIMIZEBOX|WS_MAXIMIZEBOX
									dc.DrawFrameControl(curR-2*btnW, curT, curR-btnW, curT+btnH, 1, 2, sysColors) // DFCS_CAPTIONMAX
									dc.DrawFrameControl(curR-3*btnW, curT, curR-2*btnW, curT+btnH, 1, 1, sysColors) // DFCS_CAPTIONMIN
								}
							}
						}

						// Line under caption (ReactOS: IntSetDCPenColor + LineTo)
						lineColor := sysColors[15] // COLOR_3DFACE
						if exStyle&(0x00020000|0x00000200|0x00000001) == 0x00020000 { // only WS_EX_STATICEDGE
							lineColor = sysColors[6] // COLOR_WINDOWFRAME
						}
						dc.FillRect(curL, captionBottom-1, curR, captionBottom, lineColor)

						curT = captionBottom
					}

					// 4. Menu bar (drawn in our existing menu paint, skip NC for now)
					// The menu bar is drawn by WM_PAINT / menu paint handlers.

					// 5. Client edge
					if exStyle&0x00000200 != 0 { // WS_EX_CLIENTEDGE
						dc.DrawEdge(curL, curT, curR, curB, 0x000A, 0x000F, sysColors) // EDGE_SUNKEN|BF_RECT
					}

					gdiMgr.DeleteDC(hDC)
				}
				ctx.SetReturn(0)
				return 0
			}
			// WM_NCACTIVATE (0x0086): redraw caption with active/inactive state.
			if msg == 0x0086 && wlWindow != nil && hwnd == mainHWND {
				mainActive = wParam != 0
				// Trigger NC repaint
				// (We directly call the NC paint logic by re-dispatching WM_NCPAINT)
				ctx.SetReturn(1) // return TRUE = allow activation change
				return 0
			}
			// WM_NCHITTEST (0x0084): hit-test the non-client area.
			// Ported from ReactOS nonclient.c DefWndNCHitTest.
			if msg == 0x0084 && wlWindow != nil && hwnd == mainHWND {
				// lParam contains POINT: x = LOWORD, y = HIWORD (signed)
				px := int32(int16(lParam & 0xFFFF))
				py := int32(int16((lParam >> 16) & 0xFFFF))
				wnd := win32.Global.Get(hwnd)
				if wnd == nil {
					ctx.SetReturn(1) // HTCLIENT
					return 0
				}
				style := wnd.Style
				exStyle := wnd.ExStyle
				winW := wlWindow.Width
				winH := wlWindow.Height + wlWindow.TitleBarH
				// Window rect in screen coords (we use 0,0 origin for top-level)
				wr := win32.Rect{Left: 0, Top: 0, Right: winW, Bottom: winH}
				if !win32.PtInRect(&wr, px, py) {
					ctx.SetReturn(0) // HTNOWHERE
					return 0
				}

				// Deflate by border
				if win32.UserHasWindowEdge(style, exStyle) {
					bx, by := win32.BorderSize(style, exStyle)
					win32.InflateRect(&wr, -bx, -by)
					if !win32.PtInRect(&wr, px, py) {
						// In the border area - determine which border
						xSize := win32.GetSystemMetrics(win32.SM_CXSIZE) * win32.GetSystemMetrics(win32.SM_CXBORDER)
						ySize := win32.GetSystemMetrics(win32.SM_CYSIZE) * win32.GetSystemMetrics(win32.SM_CYBORDER)
						thickFrame := style&0x00040000 != 0 // WS_THICKFRAME
						if py < wr.Top {
							if !thickFrame { ctx.SetReturn(18); return 0 } // HTBORDER
							if px < wr.Left+xSize { ctx.SetReturn(13); return 0 } // HTTOPLEFT
							if px >= wr.Right-xSize { ctx.SetReturn(14); return 0 } // HTTOPRIGHT
							ctx.SetReturn(12); return 0 // HTTOP
						}
						if py >= wr.Bottom {
							if !thickFrame { ctx.SetReturn(18); return 0 }
							if px < wr.Left+xSize { ctx.SetReturn(16); return 0 } // HTBOTTOMLEFT
							if px >= wr.Right-xSize { ctx.SetReturn(17); return 0 } // HTBOTTOMRIGHT
							ctx.SetReturn(15); return 0 // HTBOTTOM
						}
						if px < wr.Left {
							if !thickFrame { ctx.SetReturn(18); return 0 }
							if py < wr.Top+ySize { ctx.SetReturn(13); return 0 } // HTTOPLEFT
							if py >= wr.Bottom-ySize { ctx.SetReturn(16); return 0 } // HTBOTTOMLEFT
							ctx.SetReturn(10); return 0 // HTLEFT
						}
						if px >= wr.Right {
							if !thickFrame { ctx.SetReturn(18); return 0 }
							if py < wr.Top+ySize { ctx.SetReturn(14); return 0 } // HTTOPRIGHT
							if py >= wr.Bottom-ySize { ctx.SetReturn(17); return 0 } // HTBOTTOMRIGHT
							ctx.SetReturn(11); return 0 // HTRIGHT
						}
					}
				} else {
					if exStyle&0x00020000 != 0 { // WS_EX_STATICEDGE
						win32.InflateRect(&wr, -1, -1)
					}
					if !win32.PtInRect(&wr, px, py) {
						ctx.SetReturn(18) // HTBORDER
						return 0
					}
				}
				// Check caption area
				if style&0x00C00000 == 0x00C00000 { // WS_CAPTION
					captionH := win32.GetSystemMetrics(win32.SM_CYCAPTION)
					if exStyle&0x00000080 != 0 { // WS_EX_TOOLWINDOW
						captionH = win32.GetSystemMetrics(win32.SM_CYSMCAPTION)
					}
					wr.Top += captionH
					if !win32.PtInRect(&wr, px, py) {
						// In caption - check for sysmenu, close, min, max
						if style&0x00080000 != 0 { // WS_SYSMENU
							btnW := win32.GetSystemMetrics(win32.SM_CXSIZE)
							if exStyle&0x00000080 == 0 { // not tool window
								// System menu icon area
								wr.Left += btnW
							}
							wr.Right -= btnW // close button
						}
						if px < wr.Left { ctx.SetReturn(3); return 0 } // HTSYSMENU
						if px >= wr.Right+win32.GetSystemMetrics(win32.SM_CXSIZE)-win32.GetSystemMetrics(win32.SM_CXSIZE) {
							// We already subtracted close button space
						}
						if px >= wr.Right { ctx.SetReturn(20); return 0 } // HTCLOSE
						if style&(0x00020000|0x00010000) != 0 { // WS_MINIMIZEBOX|WS_MAXIMIZEBOX
							btnW := win32.GetSystemMetrics(win32.SM_CXSIZE)
							wr.Right -= btnW // max button
							if px >= wr.Right { ctx.SetReturn(9); return 0 } // HTMAXBUTTON
							if style&0x00020000 != 0 { // WS_MINIMIZEBOX
								wr.Right -= btnW // min button
								if px >= wr.Right { ctx.SetReturn(8); return 0 } // HTMINBUTTON
							}
						}
						ctx.SetReturn(2) // HTCAPTION
						return 0
					}
				}
				// Check menu area
				if _, hasMenu := hwndMenuBar[hwnd]; hasMenu {
					wr.Top += menuBarHeight
					if !win32.PtInRect(&wr, px, py) {
						ctx.SetReturn(5) // HTMENU
						return 0
					}
				}
				ctx.SetReturn(1) // HTCLIENT
				return 0
			}
			// WM_NCCREATE: must return TRUE for window creation to proceed
			if msg == 0x0081 {
				ctx.SetReturn(1)
				return 0
			}
			// WM_NCLBUTTONDOWN (0x00A1): handle clicks in non-client area.
			// Ported from ReactOS nonclient.c NC_HandleNCLButtonDown.
			if msg == 0x00A1 && wlWindow != nil && hwnd == mainHWND {
				hitTest := wParam
				switch hitTest {
				case 2: // HTCAPTION - initiate window move via WM_SYSCOMMAND SC_MOVE
					// Post WM_SYSCOMMAND SC_MOVE+HTCAPTION (0xF012)
					msgQueue = append(msgQueue, queuedMsg{hwnd: mainHWND, message: 0x0112, wParam: 0xF012, lParam: lParam})
				case 3: // HTSYSMENU - double-click closes, single opens system menu
					msgQueue = append(msgQueue, queuedMsg{hwnd: mainHWND, message: 0x0112, wParam: 0xF060, lParam: lParam}) // SC_CLOSE
				case 8: // HTMINBUTTON - SC_MINIMIZE (0xF020)
					msgQueue = append(msgQueue, queuedMsg{hwnd: mainHWND, message: 0x0112, wParam: 0xF020, lParam: lParam})
				case 9: // HTMAXBUTTON - SC_MAXIMIZE (0xF030)
					msgQueue = append(msgQueue, queuedMsg{hwnd: mainHWND, message: 0x0112, wParam: 0xF030, lParam: lParam})
				case 20: // HTCLOSE - SC_CLOSE (0xF060)
					msgQueue = append(msgQueue, queuedMsg{hwnd: mainHWND, message: 0x0112, wParam: 0xF060, lParam: lParam})
				}
				ctx.SetReturn(0)
				return 0
			}
			// WM_SYSCOMMAND (0x0112): handle system commands (close, minimize, maximize, move).
			// Ported from ReactOS defwnd.c DefWndHandleSysCommand.
			if msg == 0x0112 && wlWindow != nil {
				cmd := wParam & 0xFFF0
				switch cmd {
				case 0xF060: // SC_CLOSE
					ravelog.Logf("[syscmd] SC_CLOSE hwnd=0x%x\n", hwnd)
					// Send WM_CLOSE to the window
					msgQueue = append(msgQueue, queuedMsg{hwnd: hwnd, message: 0x0010, wParam: 0, lParam: 0})
				case 0xF020: // SC_MINIMIZE
					ravelog.Logf("[syscmd] SC_MINIMIZE hwnd=0x%x\n", hwnd)
					// Minimize via xdg_toplevel.set_minimized
					if wlWindow != nil {
						wlWindow.Minimize()
					}
				case 0xF030: // SC_MAXIMIZE
					ravelog.Logf("[syscmd] SC_MAXIMIZE hwnd=0x%x\n", hwnd)
					if wlWindow != nil {
						wlWindow.Maximize()
					}
				case 0xF120: // SC_RESTORE
					ravelog.Logf("[syscmd] SC_RESTORE hwnd=0x%x\n", hwnd)
					if wlWindow != nil {
						wlWindow.Restore()
					}
				case 0xF012: // SC_MOVE + HTCAPTION
					ravelog.Logf("[syscmd] SC_MOVE hwnd=0x%x\n", hwnd)
					if wlWindow != nil {
						wlWindow.StartMove()
					}
				case 0xF000: // SC_SIZE
					ravelog.Logf("[syscmd] SC_SIZE hwnd=0x%x\n", hwnd)
				}
				ctx.SetReturn(0)
				return 0
			}
			// WM_CLOSE (0x0010): destroy the window.
			if msg == 0x0010 && wlWindow != nil {
				ravelog.Logf("[wm] WM_CLOSE hwnd=0x%x\n", hwnd)
				// Post WM_DESTROY + WM_QUIT
				msgQueue = append(msgQueue, queuedMsg{hwnd: hwnd, message: 0x0002, wParam: 0, lParam: 0}) // WM_DESTROY
				ctx.SetReturn(0)
				return 0
			}
			// WM_DESTROY (0x0002): post quit message.
			if msg == 0x0002 {
				ravelog.Logf("[wm] WM_DESTROY hwnd=0x%x\n", hwnd)
				// PostQuitMessage(0)
				msgQueue = append(msgQueue, queuedMsg{hwnd: 0, message: 0x0012, wParam: 0, lParam: 0}) // WM_QUIT
				ctx.SetReturn(0)
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
					wlWindow.DrawRectAbs(cs.x, cs.y, cs.x+cs.w, cs.y+cs.h, bgColor)
				} else if hwnd == mainHWND {
					clientTop := wlWindow.TitleBarH
					if _, hasMenu := hwndMenuBar[hwnd]; hasMenu {
						clientTop = wlWindow.TitleBarH + menuBarHeight
					}
					w := wlWindow.Width
					h := wlWindow.Height + wlWindow.TitleBarH
					wlWindow.DrawRectAbs(0, clientTop, w, h, bgColor)
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
		// dispatchWl is shared with PeekMessageW - defined as a package-level var so both can access it.
		var dispatchWl func(evt wl.EventType)
		d.RegisterAutoStubHandler(user32, "GetMessageW", func(ctx *ntapi.TrapContext) uint32 {
			pMsg := ctx.Arg(0)

			// Helper: check expired timers, post WM_TIMER for each.
			checkTimers := func() {
				now := time.Now()
				for id, t := range timerMap {
					if now.Before(t.deadline) {
						continue
					}
					// Re-arm before posting to avoid duplicate posts.
					t.deadline = now.Add(time.Duration(t.intervalMs) * time.Millisecond)
					timerMap[id] = t
					target := t.hwnd
					if target == 0 {
						target = mainHWND
					}
					msgQueue = append(msgQueue, queuedMsg{target, 0x0113, id, 0}) // WM_TIMER
				}
			}

			// Helper: convert a Wayland event into Win32 messages.
			dispatchWl = func(evt wl.EventType) {
				if evt == wl.EventClose {
					msgQueue = append(msgQueue, queuedMsg{mainHWND, 0x12, 0, 0})
					return
				}
				if evt == wl.EventConfigure {
					// Compositor resized the window - resize buffer and post WM_SIZE to guest
					if wlWindow.ResizeIfNeeded() {
						syncScreenSurface()
					}
					w := wlWindow.Width
					h := wlWindow.Height
					lParam := uint64(uint16(w)) | (uint64(uint16(h)) << 16)
					msgQueue = append(msgQueue, queuedMsg{mainHWND, 0x0005, 0, lParam}) // WM_SIZE
					return
				}
				if evt == wl.EventKey {
					for {
						ke, ok := wlDisplay.PollKey()
						if !ok {
							break
						}
						// ESC closes open menu dropdown
						if ke.Pressed && ke.VK == 0x1B && openMenuIdx >= 0 {
							openMenuIdx = -1
							if wlWindow != nil && hasBaseFrame {
								frameReady = true
								commitIfDone()
							} else {
								msgQueue = append(msgQueue, queuedMsg{mainHWND, 0x000F, 0, 0})
							}
							continue
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
				if evt == wl.EventMouse {
					for {
						me, ok := wlDisplay.PollMouse()
						if !ok {
							break
						}
						ravelog.Logf("[mouse] kind=%d x=%d y=%d button=%d pressed=%v\n", me.Kind, me.X, me.Y, me.Button, me.Pressed)
						// Our custom title bar occupies y=[0, TitleBarH).
						// Menu bar occupies y=[TitleBarH, TitleBarH+menuBarHeight).
						// Client area starts at y=TitleBarH+menuBarHeight.
						var (
							ncTitleTop  = int32(0)
							ncMenuTop   int32
							clientTop   = int32(0)
						)
						if wlWindow != nil {
							ncMenuTop  = wlWindow.TitleBarH
							clientTop  = wlWindow.TitleBarH + menuBarHeight
						}
						// Client-relative coordinates for WM_LBUTTON* messages
						clientX := me.X
						clientY := me.Y - clientTop

						// childAt returns the child window of mainHWND at surface position (sx, sy),
						// or 0 if none. Returns child-relative coordinates via relParam.
						childAt := func(sx, sy int32) (child uint64, relParam uint64) {
							for chWnd, cs := range hwndChildren {
								if cs.parentHWND != mainHWND || !cs.visible {
									continue
								}
								if sx >= cs.x && sx < cs.x+cs.w && sy >= cs.y && sy < cs.y+cs.h {
									rx := uint64(uint16(sx - cs.x))
									ry := uint64(uint16(sy - cs.y))
									return chWnd, rx | (ry << 16)
								}
							}
							return 0, 0
						}
						// routeMouseToChild routes a mouse message to child or mainHWND.
						// Returns true if routed to a child builtin (no need to queue).
						routeMouseMsg := func(msg uint32, wp uint64, sx, sy int32) {
							targetHWND := mouseCapture
							var relParam uint64
							if targetHWND == 0 {
								targetHWND, relParam = childAt(sx, sy)
							} else {
								if cs, ok := hwndChildren[targetHWND]; ok {
									rx := uint64(uint16(sx - cs.x))
									ry := uint64(uint16(sy - cs.y))
									relParam = rx | (ry << 16)
								} else {
									relParam = uint64(uint16(sx)) | (uint64(uint16(sy-clientTop)) << 16)
								}
							}
							if targetHWND != 0 {
								_, handled := builtinWndProc(targetHWND, msg, wp, relParam)
								if !handled {
									msgQueue = append(msgQueue, queuedMsg{targetHWND, msg, wp, relParam})
								}
							} else {
								// Fall back to mainHWND with client-relative coords
								mcp := uint64(uint16(sx)) | (uint64(uint16(sy-clientTop)) << 16)
								msgQueue = append(msgQueue, queuedMsg{mainHWND, msg, wp, mcp})
							}
						}

						switch me.Kind {
						case 0: // WM_MOUSEMOVE
							if wlWindow != nil && me.Y >= ncMenuTop && me.Y < clientTop && openMenuIdx >= 0 {
								// Hovering menu bar while a menu is open - switch item
								if menuH, ok2 := hwndMenuBar[mainHWND]; ok2 {
									if md, ok3 := menus[menuH]; ok3 {
										x := int32(4)
										for i, item := range md.items {
											if item.flags&0x0800 != 0 || item.flags&0x0010 == 0 {
												continue
											}
											label := menuStripAmpersand(item.text)
											if idx := strings.IndexByte(label, '\t'); idx >= 0 {
												label = label[:idx]
											}
											if label == "" {
												continue
											}
											hasRenderable := false
											for _, r := range label {
												if r >= 32 && r <= 126 {
													hasRenderable = true
													break
												}
											}
											if !hasRenderable {
												continue
											}
											tw := int32(len([]rune(label)))*8 + 12
											if me.X >= x && me.X < x+tw && i != openMenuIdx {
												openMenuIdx = i
												openMenuHwnd = mainHWND
												if wlWindow != nil && hasBaseFrame {
													repaintBuiltin = true
													frameReady = true
													commitIfDone()
												} else {
													msgQueue = append(msgQueue, queuedMsg{mainHWND, 0x000F, 0, 0})
												}
											}
											x += tw
										}
									}
								}
							} else if me.Y >= clientTop {
								// Client area mouse move - route to captured/child/mainHWND
								routeMouseMsg(0x0200, 0, me.X, me.Y)
							}
						case 1: // button press/release
							const btnLeft, btnRight, btnMiddle = 272, 273, 274
							switch me.Button {
							case btnLeft:
								if me.Pressed {
									ravelog.Logf("[click] left press x=%d y=%d ncMenuTop=%d clientTop=%d\n", me.X, me.Y, ncMenuTop, clientTop)
									if wlWindow != nil && me.Y >= ncMenuTop && me.Y < clientTop {
										// ── Menu bar click (non-client) ──
										// Intercept here instead of routing via DefWindowProcW.
										ravelog.Logf("[click] menu bar hit, looking for item\n")
										if menuH, ok2 := hwndMenuBar[mainHWND]; ok2 {
											if md, ok3 := menus[menuH]; ok3 {
												x := int32(4)
												handled := false
												for i, item := range md.items {
													if item.flags&0x0800 != 0 || item.flags&0x0010 == 0 {
														continue
													}
													label := menuStripAmpersand(item.text)
													if idx := strings.IndexByte(label, '\t'); idx >= 0 {
														label = label[:idx]
													}
													if label == "" {
														continue
													}
													hasRenderable := false
													for _, r := range label {
														if r >= 32 && r <= 126 {
															hasRenderable = true
															break
														}
													}
													if !hasRenderable {
														continue
													}
													tw := int32(len([]rune(label)))*8 + 12
													ravelog.Logf("[click] item i=%d label=%q x=%d..%d\n", i, label, x, x+tw)
													if me.X >= x && me.X < x+tw {
														if openMenuIdx == i && openMenuHwnd == mainHWND {
															openMenuIdx = -1
														} else {
															openMenuIdx = i
															openMenuHwnd = mainHWND
														}
															// Force-render dropdown immediately without waiting for WM_PAINT.
														if wlWindow != nil && hasBaseFrame {
															// Force re-draw the menu bar to show highlight, then overlay dropdown.
															repaintBuiltin = true
															frameReady = true
															commitIfDone()
														} else {
															msgQueue = append(msgQueue, queuedMsg{mainHWND, 0x000F, 0, 0})
														}
														handled = true
														break
													}
													x += tw
												}
												_ = md
												if !handled {
													openMenuIdx = -1
													msgQueue = append(msgQueue, queuedMsg{mainHWND, 0x000F, 0, 0})
												}
											}
										}
									} else if wlWindow != nil && me.Y >= ncTitleTop && me.Y < ncMenuTop {
										// ── Title bar click (non-client) ── ignore or handle drag
									} else {
										// ── Client area click ──
										clParam := uint64(uint16(clientX)) | (uint64(uint16(clientY)) << 16)
										dropHit := false
										if openMenuIdx >= 0 {
											// Check if click is inside the open dropdown
											if menuH, ok2 := hwndMenuBar[mainHWND]; ok2 {
												if md, ok3 := menus[menuH]; ok3 {
													x := int32(4)
													for i, item := range md.items {
														if item.flags&0x0800 != 0 || item.flags&0x0010 == 0 {
															continue
														}
														label := menuStripAmpersand(item.text)
														if idx := strings.IndexByte(label, '\t'); idx >= 0 {
															label = label[:idx]
														}
														if label == "" {
															continue
														}
														hasRenderable := false
														for _, r := range label {
															if r >= 32 && r <= 126 {
																hasRenderable = true
																break
															}
														}
														if !hasRenderable {
															continue
														}
														tw := int32(len([]rune(label)))*8 + 12
														if i == openMenuIdx && len(item.submenu) > 0 {
															dropX := x
															dropY := clientTop
															dropW := int32(200)
															dropH := int32(len(item.submenu)) * 20
															if me.X >= dropX && me.X < dropX+dropW && me.Y >= dropY && me.Y < dropY+dropH {
																itemIdx := int(me.Y-dropY) / 20
																if itemIdx >= 0 && itemIdx < len(item.submenu) {
																	si := item.submenu[itemIdx]
																	if si.flags&0x0800 == 0 {
																		msgQueue = append(msgQueue, queuedMsg{mainHWND, 0x0111, si.id, 0})
																	}
																}
																openMenuIdx = -1
																msgQueue = append(msgQueue, queuedMsg{mainHWND, 0x000F, 0, 0})
																dropHit = true
																break
															}
														}
														x += tw
													}
												}
											}
											if !dropHit {
												openMenuIdx = -1
												msgQueue = append(msgQueue, queuedMsg{mainHWND, 0x000F, 0, 0})
											}
										}
										if !dropHit {
											// Route click to child under cursor or mainHWND
											hitChild, hitRelParam := childAt(me.X, me.Y)
											if hitChild != 0 {
												// Update focus to clicked child
												if focusHwnd != hitChild {
													if focusHwnd != 0 {
														msgQueue = append(msgQueue, queuedMsg{focusHwnd, 0x0008, uint64(hitChild), 0})
													}
													focusHwnd = hitChild
													msgQueue = append(msgQueue, queuedMsg{hitChild, 0x0007, 0, 0})
												}
												_, handled := builtinWndProc(hitChild, 0x0201, 0x0001, hitRelParam)
												if !handled {
													msgQueue = append(msgQueue, queuedMsg{hitChild, 0x0201, 0x0001, hitRelParam})
												}
											} else {
												msgQueue = append(msgQueue, queuedMsg{mainHWND, 0x0201, 0x0001, clParam})
											}
										}
									}
								} else {
									// Left button release - route to captured window or hit-test
									if me.Y >= clientTop || (wlWindow == nil) {
										routeMouseMsg(0x0202, 0, me.X, me.Y)
									}
								}
							case btnRight:
								if me.Y >= clientTop || wlWindow == nil {
									if me.Pressed {
										routeMouseMsg(0x0204, 0x0002, me.X, me.Y)
									} else {
										routeMouseMsg(0x0205, 0, me.X, me.Y)
									}
								}
							case btnMiddle:
								if me.Y >= clientTop || wlWindow == nil {
									if me.Pressed {
										routeMouseMsg(0x0207, 0x0010, me.X, me.Y)
									} else {
										routeMouseMsg(0x0208, 0, me.X, me.Y)
									}
								}
							}
						case 2: // scroll wheel
							routeMouseMsg(0x020A, uint64(int16(me.AxisVal*-120))<<16, me.X, me.Y)
						}
					}
				}
			}

			dequeueMsg := func() bool {
				if len(msgQueue) == 0 {
					return false
				}
				m := msgQueue[0]
				msgQueue = msgQueue[1:]
				if pMsg != 0 {
					writeMsg(pMsg, m.hwnd, m.message, m.wParam, m.lParam)
				}
				ctx.SetReturn(1)
				return true
			}

			if wlDisplay == nil {
				if pMsg != 0 {
					writeMsg(pMsg, mainHWND, 0x12, 0, 0)
				}
				ctx.SetReturn(0)
				return 0
			}

			for {
				// 1. Drain already-queued messages.
				checkTimers()
				if dequeueMsg() {
					return 0
				}

				// 2. Non-blocking poll of Wayland socket.
				evt, _ := wlDisplay.Poll()
				if evt != wl.EventNone {
					dispatchWl(evt)
					checkTimers()
					if dequeueMsg() {
						return 0
					}
				}

				// 3. Nothing ready - compute timeout until next timer (or 16ms frame).
				timeoutUs := int64(16000) // 16ms default (60fps synthetic WM_PAINT)
				now := time.Now()
				for _, t := range timerMap {
					d := t.deadline.Sub(now).Microseconds()
					if d < timeoutUs {
						if d < 0 {
							d = 0
						}
						timeoutUs = d
					}
				}

				// 4. Block on Wayland fd until timeout.
				wlFd := wlDisplay.Fd()
				var rfds unix.FdSet
				rfds.Set(wlFd)
				tv := unix.Timeval{Sec: timeoutUs / 1_000_000, Usec: timeoutUs % 1_000_000}
				n, _ := unix.Select(wlFd+1, &rfds, nil, nil, &tv)
				if n > 0 {
					evt2, _ := wlDisplay.Dispatch()
					dispatchWl(evt2)
				}

				// 5. Check timers again after sleep, then post WM_PAINT if queue still empty.
				checkTimers()
				if dequeueMsg() {
					return 0
				}

				// 6. Synthetic WM_PAINT frame.
				// mainHWND paints first (fills background), children paint on top.
				// This matches Win32 WS_CLIPCHILDREN ordering: parent → children.
				var childPaints []queuedMsg
				for h, cs := range hwndChildren {
					if hwndWndProc[h] != 0 && (cs.visible || (cs.w > 0 && cs.h > 0)) {
						childPaints = append(childPaints, queuedMsg{h, 0x000F, 0, 0})
					}
				}
				sort.Slice(childPaints, func(i, j int) bool { return childPaints[i].hwnd < childPaints[j].hwnd })
				msgQueue = append(msgQueue, queuedMsg{mainHWND, 0x000F, 0, 0})
				msgQueue = append(msgQueue, childPaints...)
				if dequeueMsg() {
					return 0
				}
			}
		})
		d.RegisterAutoStubHandler(user32, "PeekMessageW", func(ctx *ntapi.TrapContext) uint32 {
			pMsg := ctx.Arg(0)
			// wMsgFilterMin := ctx.Arg(2) // ignored for now
			// wMsgFilterMax := ctx.Arg(3)
			remove := ctx.Arg(4)&0x1 != 0 // PM_REMOVE = 0x0001

			if wlDisplay != nil {
				evt, _ := wlDisplay.Poll()
				if evt != wl.EventNone && evt != wl.EventClose {
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
					if evt == wl.EventMouse {
						if dispatchWl != nil { dispatchWl(evt) }
					}
				}
			}

			if len(msgQueue) == 0 {
				ctx.SetReturn(0)
				return 0
			}
			m := msgQueue[0]
			if remove {
				msgQueue = msgQueue[1:]
			}
			if pMsg != 0 {
				writeMsg(pMsg, m.hwnd, m.message, m.wParam, m.lParam)
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "TranslateMessage", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1) // message processed
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
					// After a WM_PAINT is fully handled (no guest WndProc will call
					// EndPaint), check if we now have a complete frame to commit.
					if message == 0x000F {
						commitIfDone()
					}
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
		// CreateAcceleratorTableW - create accelerator table (stub handle)
		var nextAccelTable uint64 = 0xac000
		d.RegisterAutoStubHandler(user32, "CreateAcceleratorTableW", func(ctx *ntapi.TrapContext) uint32 {
			nextAccelTable++
			ctx.SetReturn(nextAccelTable)
			return 0
		})
		// DestroyAcceleratorTable
		d.RegisterAutoStubHandler(user32, "DestroyAcceleratorTable", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		// IsClipboardFormatAvailable
		d.RegisterAutoStubHandler(user32, "IsClipboardFormatAvailable", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE - clipboard not implemented
			return 0
		})
		// LoadBitmapW - load bitmap from PE resource, return HBITMAP
		d.RegisterAutoStubHandler(user32, "LoadBitmapW", func(ctx *ntapi.TrapContext) uint32 {
			hInst := ctx.Arg(0)
			nameArg := ctx.Arg(1)
			if nameArg < 0x10000 && mainModule != nil &&
				(hInst == mainModule.BaseAddr || hInst == 0) {
				resID := uint32(nameArg)
				addr, sz, ok2 := peLoadRawResource(mainModule.BaseAddr, mainModule.ResourceDirRVA, 2 /*RT_BITMAP*/, resID)
				if ok2 {
					slots := decodeDIBSlots(addr, sz, 0, 0)
					h := nextBitmapHandle
					nextBitmapHandle += 2
					bitmapHandles[h] = &bitmapHandleData{slots: slots}
					ravelog.Logf("[loadbitmap] LoadBitmapW resID=0x%x → handle=0x%x slots=%d\n", resID, h, len(slots))
					ctx.SetReturn(h)
					return 0
				}
			}
			ctx.SetReturn(0) // NULL
			return 0
		})
		d.RegisterAutoStubHandler(user32, "GetForegroundWindow", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(mainHWND)
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
			prev := mouseCapture
			mouseCapture = ctx.Arg(0)
			ctx.SetReturn(prev)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "ReleaseCapture", func(ctx *ntapi.TrapContext) uint32 {
			mouseCapture = 0
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "EnableWindow", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // was enabled
			return 0
		})
		d.RegisterAutoStubHandler(user32, "SetTimer", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			id := ctx.Arg(1)
			elapse := ctx.Arg(2)
			proc := ctx.Arg(3)
			if elapse < 10 {
				elapse = 10
			}
			if id == 0 {
				nextTimerID++
				id = nextTimerID
			}
			timerMap[id] = &win32Timer{
				id:         id,
				hwnd:       hwnd,
				intervalMs: elapse,
				proc:       proc,
				deadline:   time.Now().Add(time.Duration(elapse) * time.Millisecond),
			}
			ctx.SetReturn(id)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "KillTimer", func(ctx *ntapi.TrapContext) uint32 {
			id := ctx.Arg(1)
			delete(timerMap, id)
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "InvalidateRect", func(ctx *ntapi.TrapContext) uint32 {
			// Any InvalidateRect triggers a full repaint of mainHWND (which repaints all children)
			msgQueue = append(msgQueue, queuedMsg{mainHWND, 0x000F, 0, 0})
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "InvalidateRgn", func(ctx *ntapi.TrapContext) uint32 {
			msgQueue = append(msgQueue, queuedMsg{mainHWND, 0x000F, 0, 0})
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "ValidateRect", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "ValidateRgn", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "GetUpdateRgn", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			hrgn := ctx.Arg(1)
			// Fill the region with the window's client rect and return SIMPLEREGION
			if hrgn != 0 {
				if cs, ok := hwndChildren[hwnd]; ok {
					gdiMgr.SetRectRgn(hrgn, 0, 0, cs.w, cs.h)
				} else if hwnd == mainHWND && wlWindow != nil {
					gdiMgr.SetRectRgn(hrgn, 0, 0, wlWindow.Width, wlWindow.Height)
				} else {
					gdiMgr.SetRectRgn(hrgn, 0, 0, 800, 600)
				}
			}
			ctx.SetReturn(2) // SIMPLEREGION
			return 0
		})
		d.RegisterAutoStubHandler(user32, "GetUpdateRect", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			pRect := ctx.Arg(1)
			if pRect != 0 {
				var w, h int32 = 800, 600
				if cs, ok := hwndChildren[hwnd]; ok {
					w, h = cs.w, cs.h
				} else if wlWindow != nil {
					w, h = wlWindow.Width, wlWindow.Height
				}
				ctx.Mem.Write32(pRect,    0)
				ctx.Mem.Write32(pRect+4,  0)
				ctx.Mem.Write32(pRect+8,  uint32(w))
				ctx.Mem.Write32(pRect+12, uint32(h))
			}
			ctx.SetReturn(1) // update region is non-empty
			return 0
		})
		d.RegisterAutoStubHandler(user32, "RedrawWindow", func(ctx *ntapi.TrapContext) uint32 {
			msgQueue = append(msgQueue, queuedMsg{mainHWND, 0x000F, 0, 0})
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "PrintWindow", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		// DrawEdge/DrawFrameControl/DrawFocusRect in user32
		d.RegisterAutoStubHandler(user32, "DrawEdge", func(ctx *ntapi.TrapContext) uint32 {
			if wlWindow == nil { ctx.SetReturn(1); return 0 }
			dc := getDC(ctx.Arg(0))
			pRect := ctx.Arg(1)
			edge := uint32(ctx.Arg(2))
			flags := uint32(ctx.Arg(3))
			if pRect != 0 {
				l, _ := mem.Read32(pRect);  t, _ := mem.Read32(pRect+4)
				r, _ := mem.Read32(pRect+8); b, _ := mem.Read32(pRect+12)
				dc.DrawEdge(int32(l), int32(t), int32(r), int32(b), edge, flags, sysColors)
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "DrawFrameControl", func(ctx *ntapi.TrapContext) uint32 {
			if wlWindow == nil { ctx.SetReturn(1); return 0 }
			dc := getDC(ctx.Arg(0))
			pRect := ctx.Arg(1)
			uType := uint32(ctx.Arg(2))
			uState := uint32(ctx.Arg(3))
			if pRect != 0 {
				l, _ := mem.Read32(pRect);  t, _ := mem.Read32(pRect+4)
				r, _ := mem.Read32(pRect+8); b, _ := mem.Read32(pRect+12)
				dc.DrawFrameControl(int32(l), int32(t), int32(r), int32(b), uType, uState, sysColors)
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "DrawFocusRect", func(ctx *ntapi.TrapContext) uint32 {
			if wlWindow == nil { ctx.SetReturn(1); return 0 }
			dc := getDC(ctx.Arg(0))
			pRect := ctx.Arg(1)
			if pRect != 0 {
				l, _ := mem.Read32(pRect);  t, _ := mem.Read32(pRect+4)
				r, _ := mem.Read32(pRect+8); b, _ := mem.Read32(pRect+12)
				dc.DrawFocusRect(int32(l), int32(t), int32(r), int32(b))
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "InvertRect", func(ctx *ntapi.TrapContext) uint32 {
			if wlWindow == nil { ctx.SetReturn(1); return 0 }
			dc := getDC(ctx.Arg(0))
			pRect := ctx.Arg(1)
			if pRect != 0 {
				l, _ := mem.Read32(pRect);  t, _ := mem.Read32(pRect+4)
				r, _ := mem.Read32(pRect+8); b, _ := mem.Read32(pRect+12)
				dc.InvertRect(int32(l), int32(t), int32(r), int32(b))
			}
			ctx.SetReturn(1)
			return 0
		})
		// DrawText/DrawTextEx
		d.RegisterAutoStubHandler(user32, "DrawTextW", func(ctx *ntapi.TrapContext) uint32 {
			if wlWindow == nil { ctx.SetReturn(1); return 0 }
			hdc := ctx.Arg(0)
			lpStr := ctx.Arg(1)
			nCount := int(int32(ctx.Arg(2)))
			lpRect := ctx.Arg(3)
			uFormat := uint32(ctx.Arg(4))
			dc := getDC(hdc)
			text := readGuestUTF16(lpStr)
			if nCount >= 0 && nCount < len(text) { text = text[:nCount] }
			if lpRect != 0 {
				l, _ := mem.Read32(lpRect);  t, _ := mem.Read32(lpRect+4)
				r, _ := mem.Read32(lpRect+8); b, _ := mem.Read32(lpRect+12)
				// DT_CALCRECT=0x400 - just return text height
				if uFormat & 0x400 != 0 {
					f := dc.Font; if f == nil { f = gdi.DefaultFont() }
					ctx.Mem.Write32(lpRect+12, uint32(int32(t)+f.CellHeight))
					ctx.SetReturn(uint64(f.CellHeight))
					return 0
				}
				// Center horizontally (DT_CENTER=1) or right (DT_RIGHT=2)
				x := int32(l) + 2
				y := int32(t)
				f := dc.Font; if f == nil { f = gdi.DefaultFont() }
				w := int32(r) - int32(l)
				tw := int32(len([]rune(text))) * f.AveCharWidth
				if uFormat & 0x1 != 0 { x = int32(l) + (w - tw) / 2 }
				if uFormat & 0x2 != 0 { x = int32(r) - tw - 2 }
				// DT_VCENTER=4: vertically center
				if uFormat & 0x4 != 0 {
					h := int32(b) - int32(t)
					y = int32(t) + (h - f.CellHeight) / 2
				}
				// ETO_CLIPPED on the rect
				oldClip := [4]int32{dc.ClipX0, dc.ClipY0, dc.ClipX1, dc.ClipY1}
				dc.ClipX0 = int32(l) + dc.OriginX
				dc.ClipY0 = int32(t) + dc.OriginY
				dc.ClipX1 = int32(r) + dc.OriginX
				dc.ClipY1 = int32(b) + dc.OriginY
				dc.TextOut(x, y, text, false)
				dc.ClipX0, dc.ClipY0, dc.ClipX1, dc.ClipY1 = oldClip[0], oldClip[1], oldClip[2], oldClip[3]
				ctx.SetReturn(uint64(f.CellHeight))
			}
			return 0
		})
		d.RegisterAutoStubHandler(user32, "DrawTextExW", func(ctx *ntapi.TrapContext) uint32 {
			if wlWindow == nil { ctx.SetReturn(1); return 0 }
			// Delegate to DrawTextW implementation (same first 4 args + format)
			hdc := ctx.Arg(0)
			lpStr := ctx.Arg(1)
			nCount := int(int32(ctx.Arg(2)))
			lpRect := ctx.Arg(3)
			uFormat := uint32(ctx.Arg(4))
			dc := getDC(hdc)
			text := readGuestUTF16(lpStr)
			if nCount >= 0 && nCount < len(text) { text = text[:nCount] }
			f := dc.Font; if f == nil { f = gdi.DefaultFont() }
			if lpRect != 0 {
				l, _ := mem.Read32(lpRect); t, _ := mem.Read32(lpRect+4)
				r, _ := mem.Read32(lpRect+8)
				x := int32(l) + 2
				y := int32(t)
				tw := int32(len([]rune(text))) * f.AveCharWidth
				w := int32(r) - int32(l)
				if uFormat & 0x1 != 0 { x = int32(l) + (w - tw) / 2 }
				if uFormat & 0x2 != 0 { x = int32(r) - tw - 2 }
				dc.TextOut(x, y, text, false)
				ctx.SetReturn(uint64(f.CellHeight))
			}
			return 0
		})
		d.RegisterAutoStubHandler(user32, "TabbedTextOutW", func(ctx *ntapi.TrapContext) uint32 {
			if wlWindow == nil { ctx.SetReturn(0); return 0 }
			dc := getDC(ctx.Arg(0))
			x := int32(ctx.Arg(1))
			y := int32(ctx.Arg(2))
			lpStr := ctx.Arg(3)
			nCount := int(ctx.Arg(4))
			text := readGuestUTF16(lpStr)
			if nCount > 0 && nCount < len(text) { text = text[:nCount] }
			dc.TextOut(x, y, text, false)
			f := dc.Font; if f == nil { f = gdi.DefaultFont() }
			w := int32(len([]rune(text))) * f.AveCharWidth
			ctx.SetReturn(uint64(uint32(f.CellHeight)<<16 | uint32(w)))
			return 0
		})
		d.RegisterAutoStubHandler(user32, "GrayStringW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		// Scroll bars
		d.RegisterAutoStubHandler(user32, "GetScrollInfo", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			nBar := int(ctx.Arg(1))
			psi := ctx.Arg(2)
			if psi == 0 { ctx.SetReturn(0); return 0 }
			cbSize, _ := mem.Read32(psi)
			if cbSize < 28 { ctx.SetReturn(0); return 0 }
			fMask, _ := mem.Read32(psi + 4)
			si := win32.ScrollInfo{}
			win32.GetScrollInfo(hwnd, nBar, &si, uint32(fMask))
			if uint32(fMask) & win32.SIF_RANGE != 0 {
				ctx.Mem.Write32(psi+8, uint32(si.Min))
				ctx.Mem.Write32(psi+12, uint32(si.Max))
			}
			if uint32(fMask) & win32.SIF_PAGE != 0 {
				ctx.Mem.Write32(psi+16, si.Page)
			}
			if uint32(fMask) & win32.SIF_POS != 0 {
				ctx.Mem.Write32(psi+20, uint32(si.Pos))
			}
			if uint32(fMask) & win32.SIF_TRACKPOS != 0 {
				ctx.Mem.Write32(psi+24, uint32(si.TrackPos))
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "SetScrollInfo", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			nBar := int(ctx.Arg(1))
			psi := ctx.Arg(2)
			if psi == 0 { ctx.SetReturn(0); return 0 }
			cbSize, _ := mem.Read32(psi)
			if cbSize < 28 { ctx.SetReturn(0); return 0 }
			fMask, _ := mem.Read32(psi + 4)
			si := win32.ScrollInfo{}
			min32, _ := mem.Read32(psi + 8); si.Min = int32(min32)
			max32, _ := mem.Read32(psi + 12); si.Max = int32(max32)
			page32, _ := mem.Read32(psi + 16); si.Page = page32
			pos32, _ := mem.Read32(psi + 20); si.Pos = int32(pos32)
			pos := win32.SetScrollInfo(hwnd, nBar, &si, uint32(fMask))
			ctx.SetReturn(uint64(pos))
			return 0
		})
		d.RegisterAutoStubHandler(user32, "GetScrollPos", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			nBar := int(ctx.Arg(1))
			ctx.SetReturn(uint64(win32.GetScrollPos(hwnd, nBar)))
			return 0
		})
		d.RegisterAutoStubHandler(user32, "SetScrollPos", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			nBar := int(ctx.Arg(1))
			pos := int32(ctx.Arg(2))
			prev := win32.SetScrollPos(hwnd, nBar, pos)
			ctx.SetReturn(uint64(prev))
			return 0
		})
		d.RegisterAutoStubHandler(user32, "GetScrollRange", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			nBar := int(ctx.Arg(1))
			pMin := ctx.Arg(2); pMax := ctx.Arg(3)
			mn, mx := win32.GetScrollRange(hwnd, nBar)
			if pMin != 0 { ctx.Mem.Write32(pMin, uint32(mn)) }
			if pMax != 0 { ctx.Mem.Write32(pMax, uint32(mx)) }
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "SetScrollRange", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			nBar := int(ctx.Arg(1))
			mn := int32(ctx.Arg(2)); mx := int32(ctx.Arg(3))
			win32.SetScrollRange(hwnd, nBar, mn, mx)
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "ShowScrollBar", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "EnableScrollBar", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "ScrollWindow", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "ScrollWindowEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(user32, "ScrollDC", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		// Window region
		d.RegisterAutoStubHandler(user32, "SetWindowRgn", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "GetWindowRgn", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0 // ERROR - no window region set
		})
		d.RegisterAutoStubHandler(user32, "GetWindowRgnBox", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		// Caret
		d.RegisterAutoStubHandler(user32, "CreateCaret", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "DestroyCaret", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "ShowCaret", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "HideCaret", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "GetCaretPos", func(ctx *ntapi.TrapContext) uint32 {
			p := ctx.Arg(0)
			if p != 0 { ctx.Mem.Write32(p, 0); ctx.Mem.Write32(p+4, 0) }
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "SetCaretPos", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "GetCaretBlinkTime", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(530); return 0
		})
		d.RegisterAutoStubHandler(user32, "SetCaretBlinkTime", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		// Window geometry helpers
		d.RegisterAutoStubHandler(user32, "AdjustWindowRect", func(ctx *ntapi.TrapContext) uint32 {
			pRect := ctx.Arg(0)
			style := uint32(ctx.Arg(1))
			hasMenu := ctx.Arg(2) != 0
			if pRect != 0 {
				l, _ := mem.Read32(pRect); t, _ := mem.Read32(pRect + 4)
				r, _ := mem.Read32(pRect + 8); b, _ := mem.Read32(pRect + 12)
				rc := win32.Rect{Left: int32(l), Top: int32(t), Right: int32(r), Bottom: int32(b)}
				win32.AdjustWindowRectEx(&rc, style, hasMenu, 0)
				ctx.Mem.Write32(pRect, uint32(rc.Left)); ctx.Mem.Write32(pRect+4, uint32(rc.Top))
				ctx.Mem.Write32(pRect+8, uint32(rc.Right)); ctx.Mem.Write32(pRect+12, uint32(rc.Bottom))
			}
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "AdjustWindowRectEx", func(ctx *ntapi.TrapContext) uint32 {
			pRect := ctx.Arg(0)
			style := uint32(ctx.Arg(1))
			hasMenu := ctx.Arg(2) != 0
			exStyle := uint32(ctx.Arg(3))
			if pRect != 0 {
				l, _ := mem.Read32(pRect); t, _ := mem.Read32(pRect + 4)
				r, _ := mem.Read32(pRect + 8); b, _ := mem.Read32(pRect + 12)
				rc := win32.Rect{Left: int32(l), Top: int32(t), Right: int32(r), Bottom: int32(b)}
				win32.AdjustWindowRectEx(&rc, style, hasMenu, exStyle)
				ctx.Mem.Write32(pRect, uint32(rc.Left)); ctx.Mem.Write32(pRect+4, uint32(rc.Top))
				ctx.Mem.Write32(pRect+8, uint32(rc.Right)); ctx.Mem.Write32(pRect+12, uint32(rc.Bottom))
			}
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "WindowFromPoint", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(mainHWND); return 0
		})
		d.RegisterAutoStubHandler(user32, "ChildWindowFromPoint", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(ctx.Arg(0)); return 0
		})
		d.RegisterAutoStubHandler(user32, "ChildWindowFromPointEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(ctx.Arg(0)); return 0
		})
		d.RegisterAutoStubHandler(user32, "RealChildWindowFromPoint", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(ctx.Arg(0)); return 0
		})
		d.RegisterAutoStubHandler(user32, "GetNextWindow", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(user32, "GetTopWindow", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(mainHWND); return 0
		})
		d.RegisterAutoStubHandler(user32, "GetWindow", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(user32, "EnumChildWindows", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "EnumWindows", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "LockWindowUpdate", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		// Dialog functions
		d.RegisterAutoStubHandler(user32, "DialogBoxParamW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0 // IDCANCEL
		})
		d.RegisterAutoStubHandler(user32, "DialogBoxIndirectParamW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(user32, "CreateDialogParamW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(user32, "CreateDialogIndirectParamW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(user32, "EndDialog", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "GetDlgItem", func(ctx *ntapi.TrapContext) uint32 {
			hDlg := ctx.Arg(0)
			nIDDlgItem := ctx.Arg(1)
			// Search child windows of hDlg for matching control ID
			for h, cs := range hwndChildren {
				if cs.parentHWND == hDlg && cs.ctrlID == nIDDlgItem {
					ctx.SetReturn(h)
					return 0
				}
			}
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "GetDlgCtrlID", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			if cs, ok := hwndChildren[hwnd]; ok {
				ctx.SetReturn(cs.ctrlID)
				return 0
			}
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "SendDlgItemMessageW", func(ctx *ntapi.TrapContext) uint32 {
			hDlg := ctx.Arg(0)
			nIDDlgItem := ctx.Arg(1)
			msg := uint32(ctx.Arg(2))
			wParam := ctx.Arg(3)
			lParam := ctx.Arg(4)
			// Find child HWND by control ID, then SendMessage to it
			for h, cs := range hwndChildren {
				if cs.parentHWND == hDlg && cs.ctrlID == nIDDlgItem {
					if result, handled := builtinWndProc(h, msg, wParam, lParam); handled {
						ctx.SetReturn(result)
						return 0
					}
					break
				}
			}
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "MapDialogRect", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "GetDlgItemTextW", func(ctx *ntapi.TrapContext) uint32 {
			hDlg := ctx.Arg(0)
			nIDDlgItem := ctx.Arg(1)
			lpString := ctx.Arg(2)
			nMaxCount := ctx.Arg(3)
			for h, cs := range hwndChildren {
				if cs.parentHWND == hDlg && cs.ctrlID == nIDDlgItem {
					text := cs.text
					runes := []rune(text)
					maxChars := int(nMaxCount) - 1
					if maxChars < 0 { maxChars = 0 }
					if len(runes) > maxChars { runes = runes[:maxChars] }
					for i, r := range runes {
						mem.Write16(lpString+uint64(i)*2, uint16(r))
					}
					mem.Write16(lpString+uint64(len(runes))*2, 0)
					ctx.SetReturn(uint64(len(runes)))
					_ = h
					return 0
				}
			}
			if lpString != 0 && nMaxCount > 0 { mem.Write16(lpString, 0) }
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "SetDlgItemTextW", func(ctx *ntapi.TrapContext) uint32 {
			hDlg := ctx.Arg(0)
			nIDDlgItem := ctx.Arg(1)
			lpString := ctx.Arg(2)
			text := readGuestUTF16(lpString)
			for _, cs := range hwndChildren {
				if cs.parentHWND == hDlg && cs.ctrlID == nIDDlgItem {
					cs.text = text
					ctx.SetReturn(1)
					return 0
				}
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "GetDlgItemInt", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(user32, "SetDlgItemInt", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "IsDlgButtonChecked", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(user32, "CheckDlgButton", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "CheckRadioButton", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		// Icons/cursors
		d.RegisterAutoStubHandler(user32, "DrawIconEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "DrawIcon", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "DestroyIcon", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "DestroyCursor", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "CopyIcon", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(ctx.Arg(0)); return 0
		})
		d.RegisterAutoStubHandler(user32, "GetIconInfo", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(user32, "CreateIconIndirect", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x8001); return 0
		})
		// Misc UI
		d.RegisterAutoStubHandler(user32, "DrawStateW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "GetSysColorBrush", func(ctx *ntapi.TrapContext) uint32 {
			idx := int(ctx.Arg(0))
			color := uint32(0xD4D0C8)
			if idx >= 0 && idx < len(sysColors) { color = sysColors[idx] }
			ctx.SetReturn(gdiMgr.CreateSolidBrush(color))
			return 0
		})
		d.RegisterAutoStubHandler(user32, "FrameRect", func(ctx *ntapi.TrapContext) uint32 {
			if wlWindow == nil { ctx.SetReturn(1); return 0 }
			dc := getDC(ctx.Arg(0))
			pRect := ctx.Arg(1)
			hbr := ctx.Arg(2)
			color := gdiMgr.BrushColor(hbr, sysColors)
			if pRect != 0 {
				l, _ := mem.Read32(pRect);  t, _ := mem.Read32(pRect+4)
				r, _ := mem.Read32(pRect+8); b, _ := mem.Read32(pRect+12)
				dc.DrawBorder(int32(l), int32(t), int32(r), int32(b), color)
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "PaintDesktop", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "GetSystemColorBrush", func(ctx *ntapi.TrapContext) uint32 {
			idx := int(ctx.Arg(0))
			color := uint32(0xD4D0C8)
			if idx >= 0 && idx < len(sysColors) { color = sysColors[idx] }
			ctx.SetReturn(gdiMgr.CreateSolidBrush(color))
			return 0
		})
		d.RegisterAutoStubHandler(user32, "GetWindowTextW", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			pBuf := ctx.Arg(1)
			nMax := int(ctx.Arg(2))
			title := ""
			if t, ok := hwndTitle[hwnd]; ok { title = t }
			if pBuf != 0 && nMax > 0 {
				runes := []rune(title)
				n := len(runes)
				if n >= nMax { n = nMax - 1 }
				for i := 0; i < n; i++ { ctx.Mem.Write16(pBuf+uint64(i)*2, uint16(runes[i])) }
				ctx.Mem.Write16(pBuf+uint64(n)*2, 0)
				ctx.SetReturn(uint64(n))
			} else {
				ctx.SetReturn(uint64(len([]rune(title))))
			}
			return 0
		})
		d.RegisterAutoStubHandler(user32, "BeginPaint", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			pPaint := ctx.Arg(1)
			ox, oy := clientAreaOrigin(hwnd)
			if cs, ok := hwndChildren[hwnd]; ok {
				ravelog.Logf("[paint] BeginPaint hwnd=0x%x class=%q x=%d y=%d w=%d h=%d\n", hwnd, cs.className, cs.x, cs.y, cs.w, cs.h)
			} else {
				ravelog.Logf("[paint] BeginPaint hwnd=0x%x (mainHWND)\n", hwnd)
			}
			hdc, dc := allocScreenDC(ox, oy)
			ravelog.Logf("[paint] BeginPaint hwnd=0x%x → hdc=0x%x ox=%d oy=%d\n", hwnd, hdc, ox, oy)

			var rcLeft, rcTop, rcRight, rcBottom int32

			if wlWindow != nil && hwnd == mainHWND {
				wlWindow.ResizeIfNeeded()
				syncScreenSurface()
				w, h := wlWindow.Width, wlWindow.Height
				_ = h
				clientTop := wlWindow.TitleBarH

				// Non-client area: draw menu bar (same filter/width as click-handler and drawMenuOverlay).
				if menuH, ok := hwndMenuBar[hwnd]; ok {
					if md, ok2 := menus[menuH]; ok2 && len(md.items) > 0 {
						clientTop = wlWindow.TitleBarH + menuBarHeight
						wlWindow.DrawRectAbs(0, wlWindow.TitleBarH, w, clientTop, sysColors[15])
						wlWindow.DrawRectAbs(0, clientTop-1, w, clientTop, sysColors[16])
						x := int32(4)
						for i, item := range md.items {
							if item.flags&0x0800 != 0 || item.flags&0x0010 == 0 {
								continue // separator or non-popup
							}
							label := menuStripAmpersand(item.text)
							if idx := strings.IndexByte(label, '\t'); idx >= 0 {
								label = label[:idx]
							}
							if label == "" || label == "-" {
								continue
							}
							hasRenderable := false
							for _, r := range label {
								if r >= 32 && r <= 126 {
									hasRenderable = true
									break
								}
							}
							if !hasRenderable {
								continue
							}
							tw := int32(len([]rune(label)))*8 + 12
							if openMenuIdx == i && openMenuHwnd == hwnd {
								wlWindow.DrawRectAbs(x, wlWindow.TitleBarH, x+tw, clientTop-1, sysColors[20])
								wlWindow.DrawTextAbs(x+4, wlWindow.TitleBarH+3, label, 0x000000, sysColors[20], true)
							} else {
								wlWindow.DrawTextAbs(x+4, wlWindow.TitleBarH+3, label, 0x000000, sysColors[15], true)
							}
							x += tw
						}
					}
				}

				// Do NOT fill the full client area - child windows cover it entirely.
				// Filling here wipes Scintilla/children that painted first in the message queue.
				// ReactOS WM_ERASEBKGND only fills uncovered (non-child) regions.
				rcLeft, rcTop = 0, 0
				rcRight, rcBottom = w, h
				dc.SetClipRect(0, clientTop, w, h+wlWindow.TitleBarH)
			} else if cs, ok := hwndChildren[hwnd]; ok && wlWindow != nil {
				// Child window BeginPaint: fill with class brush
				bgColor := sysColors[5]
				if a, ok := hwndClassAtom[hwnd]; ok {
					if brushIdx, ok2 := classBrush[a]; ok2 && brushIdx > 0 && int(brushIdx-1) < len(sysColors) {
						bgColor = sysColors[brushIdx-1]
					}
				}
				wlWindow.DrawRectAbs(cs.x, cs.y, cs.x+cs.w, cs.y+cs.h, bgColor)
				rcLeft, rcTop = 0, 0
				rcRight, rcBottom = cs.w, cs.h
				// Clip all GDI drawing to this child's screen rect
				dc.SetClipRect(cs.x, cs.y, cs.x+cs.w, cs.y+cs.h)
				// For Scintilla windows: record sciThis for diagnostics only.
				// Do NOT patch Scintilla internal state - offsets are version-specific
				// and writing wrong fields corrupts state (e.g. sets paintState=painting,
				// making SetPaintState return abandoned and skip all rendering).
				if strings.EqualFold(cs.className, "scintilla") {
					if m, mok := windowLongPtr[hwnd]; mok {
						sciThis0 := m[-21]
						if sciThis0 == 0 {
							sciThis0 = m[0]
						}
						if sciThis := sciThis0; sciThis != 0 {
							ravelog.Logf("[sci] BeginPaint hwnd=0x%x sciThis=0x%x size=(%d,%d)\n", hwnd, sciThis, cs.w, cs.h)
						}
					}
				}
			} else {
				rcRight, rcBottom = 800, 600
				if wlWindow != nil {
					rcRight, rcBottom = wlWindow.Width, wlWindow.Height
				}
			}

			if pPaint != 0 {
				ctx.Mem.Write64(pPaint, hdc)                   // hdc
				ctx.Mem.Write32(pPaint+8, 0)                   // fErase = FALSE → paintingAllText = true in Scintilla
				ctx.Mem.Write32(pPaint+12, uint32(rcLeft))     // rcPaint.left
				ctx.Mem.Write32(pPaint+16, uint32(rcTop))      // rcPaint.top
				ctx.Mem.Write32(pPaint+20, uint32(rcRight))    // rcPaint.right
				ctx.Mem.Write32(pPaint+24, uint32(rcBottom))   // rcPaint.bottom
				// Verify reads back correctly
				rv, _ := ctx.Mem.Read32(pPaint+20)
				rb, _ := ctx.Mem.Read32(pPaint+24)
				ravelog.Logf("[paint] PAINTSTRUCT pPaint=0x%x right=%d bottom=%d (wrote %d,%d)\n", pPaint, rv, rb, rcRight, rcBottom)
			}
			ctx.SetReturn(hdc)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "EndPaint", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			ravelog.Logf("[paint] EndPaint hwnd=0x%x\n", hwnd)
			if wlWindow != nil {
				paintTree(hwnd)
				// Re-commit after any EndPaint once the base frame is established.
				// Set repaintBuiltin so commitIfDone repaints builtin controls
				// (tab strip, status bar) on top of guest-drawn content (Scintilla).
				if hasBaseFrame {
					frameReady = true
					repaintBuiltin = true
				}
				commitIfDone()
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
			ctx.SetReturn(ctx.Arg(0))
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
			_ = menus[hMenu]
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
			textPtr := ctx.Arg(1)
			captionPtr := ctx.Arg(2)
			uType := ctx.Arg(3)
			text := readGuestString(textPtr)
			caption := readGuestString(captionPtr)
			ravelog.Logf("[user32] MessageBoxA: [%s] %s\n", caption, text)
			const (
				MB_OKCANCEL     = 1
				MB_YESNO        = 4
				MB_YESNOCANCEL  = 3
				IDOK     = 1
				IDYES    = 6
				IDCANCEL = 2
			)
			switch uType & 0xF {
			case MB_YESNO, MB_YESNOCANCEL: ctx.SetReturn(IDYES)
			case MB_OKCANCEL: ctx.SetReturn(IDOK)
			default: ctx.SetReturn(IDOK)
			}
			return 0
		})
		d.RegisterAutoStubHandler(user32, "MessageBoxW", func(ctx *ntapi.TrapContext) uint32 {
			textPtr := ctx.Arg(1)
			captionPtr := ctx.Arg(2)
			uType := ctx.Arg(3)
			text := readGuestUTF16(textPtr)
			caption := readGuestUTF16(captionPtr)
			ravelog.Logf("[user32] MessageBoxW: [%s] %s\n", caption, text)
			const (
				MB_OKCANCEL     = 1
				MB_YESNO        = 4
				MB_YESNOCANCEL  = 3
				IDOK     = 1
				IDYES    = 6
				IDCANCEL = 2
			)
			switch uType & 0xF {
			case MB_YESNO, MB_YESNOCANCEL: ctx.SetReturn(IDYES)
			case MB_OKCANCEL: ctx.SetReturn(IDOK)
			default: ctx.SetReturn(IDOK)
			}
			return 0
		})
		d.RegisterAutoStubHandler(user32, "SetCursor", func(ctx *ntapi.TrapContext) uint32 {
			hCursor := ctx.Arg(0)
			// Map Windows IDC_ cursor IDs to wp_cursor_shape_v1 shapes.
			if wlDisplay != nil {
				var shape uint32
				switch hCursor {
				case 32512: shape = wl.CursorDefault    // IDC_ARROW
				case 32513: shape = wl.CursorText       // IDC_IBEAM
				case 32514: shape = wl.CursorProgress   // IDC_WAIT (spinner)
				case 32515: shape = wl.CursorCrosshair  // IDC_CROSS
				case 32642: shape = wl.CursorResizeNWSE // IDC_SIZENWSE
				case 32643: shape = wl.CursorResizeNESW // IDC_SIZENESW
				case 32644: shape = wl.CursorResizeEW   // IDC_SIZEWE
				case 32645: shape = wl.CursorResizeNS   // IDC_SIZENS
				case 32646: shape = wl.CursorMove       // IDC_SIZEALL
				case 32648: shape = wl.CursorNotAllowed // IDC_NO
				case 32649: shape = wl.CursorPointer    // IDC_HAND
				case 32650: shape = wl.CursorProgress   // IDC_APPSTARTING
				case 32651: shape = wl.CursorHelp       // IDC_HELP
				default:    shape = wl.CursorDefault
				}
				wlDisplay.SetCursorShape(shape)
			}
			ctx.SetReturn(hCursor)
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
			hwnd := ctx.Arg(0)
			pPt := ctx.Arg(1)
			if pPt == 0 { ctx.SetReturn(0); return 0 }
			rx, _ := mem.Read32(pPt); ry, _ := mem.Read32(pPt + 4)
			x, y := int32(rx), int32(ry)
			if cs, ok := hwndChildren[hwnd]; ok {
				x -= cs.x
				y -= cs.y
			}
			ctx.Mem.Write32(pPt, uint32(x))
			ctx.Mem.Write32(pPt+4, uint32(y))
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "ClientToScreen", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			pPt := ctx.Arg(1)
			if pPt == 0 { ctx.SetReturn(0); return 0 }
			rx, _ := mem.Read32(pPt); ry, _ := mem.Read32(pPt + 4)
			x, y := int32(rx), int32(ry)
			if cs, ok := hwndChildren[hwnd]; ok {
				x += cs.x
				y += cs.y
			}
			ctx.Mem.Write32(pPt, uint32(x))
			ctx.Mem.Write32(pPt+4, uint32(y))
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "MapWindowPoints", func(ctx *ntapi.TrapContext) uint32 {
			// ReactOS: winpos.c MapWindowPoints
			// Maps nCount points from fromHwnd's client coords to toHwnd's client coords.
			// fromHwnd==0 → screen coords as source; toHwnd==0 → screen coords as dest.
			fromHwnd := ctx.Arg(0)
			toHwnd := ctx.Arg(1)
			pPts := ctx.Arg(2)
			nPts := int(ctx.Arg(3))
			if pPts == 0 || nPts == 0 { ctx.SetReturn(0); return 0 }
			var fromX, fromY int32
			if fromHwnd != 0 {
				if cs, ok := hwndChildren[fromHwnd]; ok {
					fromX, fromY = cs.x, cs.y
				}
			}
			var toX, toY int32
			if toHwnd != 0 {
				if cs, ok := hwndChildren[toHwnd]; ok {
					toX, toY = cs.x, cs.y
				}
			}
			dx := fromX - toX
			dy := fromY - toY
			for i := 0; i < nPts; i++ {
				off := pPts + uint64(i)*8
				px, _ := mem.Read32(off); py, _ := mem.Read32(off + 4)
				ctx.Mem.Write32(off, uint32(int32(px)+dx))
				ctx.Mem.Write32(off+4, uint32(int32(py)+dy))
			}
			// Return value: low word = dx, high word = dy (signed)
			ret := (uint64(uint16(dx)) & 0xFFFF) | ((uint64(uint16(dy)) & 0xFFFF) << 16)
			ctx.SetReturn(ret)
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
		d.RegisterAutoStubHandler(user32, "GetMonitorInfoA", func(ctx *ntapi.TrapContext) uint32 {
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
			uiAction := ctx.Arg(0)
			pvParam := ctx.Arg(2)
			w := int32(1920)
			h := int32(1080)
			if wlWindow != nil { w = int32(wlWindow.Width); h = int32(wlWindow.Height) }
			switch uiAction {
			case 0x0030: // SPI_GETWORKAREA
				if pvParam != 0 {
					ctx.Mem.Write32(pvParam+0, 0)
					ctx.Mem.Write32(pvParam+4, 0)
					ctx.Mem.Write32(pvParam+8, uint32(w))
					ctx.Mem.Write32(pvParam+12, uint32(h))
				}
			case 0x0048: // SPI_GETFONTSMOOTHINGTYPE
				if pvParam != 0 { ctx.Mem.Write32(pvParam, 2) } // FE_FONTSMOOTHINGCLEARTYPE
			case 0x004A: // SPI_GETFONTSMOOTHING
				if pvParam != 0 { ctx.Mem.Write32(pvParam, 1) }
			case 0x0067: // SPI_GETMOUSETRAILS
				if pvParam != 0 { ctx.Mem.Write32(pvParam, 0) }
			case 0x0024: // SPI_GETNONCLIENTMETRICS - fill NONCLIENTMETRICSW
				if pvParam != 0 {
					// NONCLIENTMETRICSW (504 bytes on Vista+):
					// +0   cbSize        = 504
					// +4   iBorderWidth  = 1
					// +8   iScrollWidth  = 17
					// +12  iScrollHeight = 17
					// +16  iCaptionWidth  = 23
					// +20  iCaptionHeight = 23
					// +24  lfCaptionFont  (LOGFONTW = 92 bytes, all zero except lfHeight=−11, lfCharSet=1, name="Segoe UI")
					// +116 iSmCaptionWidth  = 12
					// +120 iSmCaptionHeight = 15
					// +124 lfSmCaptionFont  (92 bytes)
					// +216 iMenuWidth  = 18
					// +220 iMenuHeight = 19
					// +224 lfMenuFont  (92 bytes)
					// +316 lfStatusFont (92 bytes)
					// +408 lfMessageFont (92 bytes)
					// +500 iPaddedBorderWidth = 4
					ctx.Mem.Write32(pvParam+0, 504)   // cbSize
					ctx.Mem.Write32(pvParam+4, 1)     // iBorderWidth
					ctx.Mem.Write32(pvParam+8, 17)    // iScrollWidth
					ctx.Mem.Write32(pvParam+12, 17)   // iScrollHeight
					ctx.Mem.Write32(pvParam+16, 23)   // iCaptionWidth
					ctx.Mem.Write32(pvParam+20, 23)   // iCaptionHeight
					ctx.Mem.Write32(pvParam+116, 12)  // iSmCaptionWidth
					ctx.Mem.Write32(pvParam+120, 15)  // iSmCaptionHeight
					ctx.Mem.Write32(pvParam+216, 18)  // iMenuWidth
					ctx.Mem.Write32(pvParam+220, 19)  // iMenuHeight
					ctx.Mem.Write32(pvParam+500, 4)   // iPaddedBorderWidth
					// Write "Segoe UI" into lfCaptionFont.lfFaceName (offset 24+28=52 from pvParam)
					writeLogFontName := func(off uint64, name string, height int32) {
						ctx.Mem.Write32(pvParam+off, uint32(height)) // lfHeight
						ctx.Mem.Write32(pvParam+off+16, 400)         // lfWeight = FW_NORMAL
						ctx.Mem.Write8(pvParam+off+17, 0)            // lfItalic
						ws := utf16Encode(name)
						for i, w := range ws { ctx.Mem.Write16(pvParam+off+28+uint64(i)*2, w) }
					}
					writeLogFontName(24, "Segoe UI", -11)
					writeLogFontName(124, "Segoe UI", -11)
					writeLogFontName(224, "Segoe UI", -11)
					writeLogFontName(316, "Segoe UI", -11)
					writeLogFontName(408, "Segoe UI", -11)
				}
			case 0x001A: // SPI_GETDESKWALLPAPER
				if pvParam != 0 { ctx.Mem.Write16(pvParam, 0) }
			case 0x0059: // SPI_GETANIMATION - ANIMATIONINFO cbSize+iMinAnimate
				if pvParam != 0 { ctx.Mem.Write32(pvParam, 8); ctx.Mem.Write32(pvParam+4, 0) }
			case 0x0068: // SPI_GETFONTSMOOTHINGGAMMA
				if pvParam != 0 { ctx.Mem.Write32(pvParam, 2200) }
			case 0x006A: // SPI_GETFONTSMOOTHINGORIENTATIONTYPE
				if pvParam != 0 { ctx.Mem.Write32(pvParam, 0) } // FE_FONTSMOOTHINGORIENTATIONRGB
			}
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
		d.RegisterAutoStubHandler(user32, "AdjustWindowRectExForDpi", func(ctx *ntapi.TrapContext) uint32 {
			pRect := ctx.Arg(0)
			style := uint32(ctx.Arg(1))
			hasMenu := ctx.Arg(2) != 0
			exStyle := uint32(ctx.Arg(3))
			if pRect != 0 {
				l, _ := mem.Read32(pRect); t, _ := mem.Read32(pRect + 4)
				r, _ := mem.Read32(pRect + 8); b, _ := mem.Read32(pRect + 12)
				rc := win32.Rect{Left: int32(l), Top: int32(t), Right: int32(r), Bottom: int32(b)}
				win32.AdjustWindowRectEx(&rc, style, hasMenu, exStyle)
				ctx.Mem.Write32(pRect, uint32(rc.Left)); ctx.Mem.Write32(pRect+4, uint32(rc.Top))
				ctx.Mem.Write32(pRect+8, uint32(rc.Right)); ctx.Mem.Write32(pRect+12, uint32(rc.Bottom))
			}
			ctx.SetReturn(1); return 0
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
			hwnd := ctx.Arg(0)
			lpwndpl := ctx.Arg(1)
			if lpwndpl != 0 && wlWindow != nil {
				// WINDOWPLACEMENT layout (all int32):
				// offset 0: length (uint32)
				// offset 4: flags (uint32)
				// offset 8: showCmd (uint32)
				// offset 12: ptMinPosition.x, offset 16: ptMinPosition.y
				// offset 20: ptMaxPosition.x, offset 24: ptMaxPosition.y
				// offset 28: rcNormalPosition.left, offset 32: top, offset 36: right, offset 40: bottom
				readI32 := func(off uint64) int32 {
					v, _ := mem.Read32(lpwndpl + off)
					return int32(v)
				}
				left   := readI32(28)
				top    := readI32(32)
				right  := readI32(36)
				bottom := readI32(40)
				w := right - left
				h := bottom - top
				if w > 0 && w < 0x7FFF && h > 0 && h < 0x7FFF {
					ravelog.Logf("[placement] SetWindowPlacement hwnd=0x%x → %d,%d %dx%d\n", hwnd, left, top, w, h)
					if hwnd == mainHWND {
						if wlWindow.Resize(w, h) {
							syncScreenSurface()
						}
						lParam := uint64(uint16(w)) | (uint64(uint16(h)) << 16)
						msgQueue = append(msgQueue, queuedMsg{hwnd, 0x0005, 0, lParam})
						msgQueue = append(msgQueue, queuedMsg{hwnd, 0x000F, 0, 0})
					} else if ci, ok := hwndChildren[hwnd]; ok {
						ci.w = w
						ci.h = h
					}
				}
			}
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

		// ModifyMenuW: actually modify an existing menu item
		d.RegisterAutoStubHandler(user32, "ModifyMenuW", func(ctx *ntapi.TrapContext) uint32 {
			hMenu := ctx.Arg(0)
			idPos := ctx.Arg(1)
			flags := uint32(ctx.Arg(2))
			idNewItem := ctx.Arg(3)
			lpNewItem := ctx.Arg(4)
			m, ok := menus[hMenu]
			if !ok { ctx.SetReturn(0); return 0 }
			const MF_BYPOSITION = 0x0400
			const mfSeparator = 0x0800
			if flags&MF_BYPOSITION != 0 {
				idx := int(idPos)
				if idx >= 0 && idx < len(m.items) {
					m.items[idx].flags = flags
					m.items[idx].id = idNewItem
					if flags&mfSeparator == 0 && lpNewItem != 0 {
						m.items[idx].text = readGuestUTF16(lpNewItem)
					}
				}
			} else {
				for i := range m.items {
					if m.items[i].id == idPos {
						m.items[i].flags = flags
						m.items[i].id = idNewItem
						if flags&mfSeparator == 0 && lpNewItem != 0 {
							m.items[i].text = readGuestUTF16(lpNewItem)
						}
						break
					}
				}
			}
			ctx.SetReturn(1)
			return 0
		})
		// DeleteMenu: remove a menu item by position or ID
		d.RegisterAutoStubHandler(user32, "DeleteMenu", func(ctx *ntapi.TrapContext) uint32 {
			hMenu := ctx.Arg(0)
			idPos := ctx.Arg(1)
			flags := uint32(ctx.Arg(2))
			m, ok := menus[hMenu]
			if !ok { ctx.SetReturn(0); return 0 }
			const MF_BYPOSITION = 0x0400
			if flags&MF_BYPOSITION != 0 {
				idx := int(idPos)
				if idx >= 0 && idx < len(m.items) {
					m.items = append(m.items[:idx], m.items[idx+1:]...)
				}
			} else {
				for i := range m.items {
					if m.items[i].id == idPos {
						m.items = append(m.items[:i], m.items[i+1:]...)
						break
					}
				}
			}
			ctx.SetReturn(1)
			return 0
		})

		// GetMenuItemInfoW: fill MENUITEMINFOW for a valid item
		d.RegisterAutoStubHandler(user32, "GetMenuItemInfoW", func(ctx *ntapi.TrapContext) uint32 {
			hMenu := ctx.Arg(0)
			item := ctx.Arg(1)
			byPos := ctx.Arg(2) != 0
			lpmii := ctx.Arg(3)
			if lpmii == 0 { ctx.SetReturn(0); return 0 }
			m, ok := menus[hMenu]
			if !ok { ctx.SetReturn(0); return 0 }
			var found *menuItem
			if byPos {
				idx := int(item)
				if idx >= 0 && idx < len(m.items) { found = &m.items[idx] }
			} else {
				for i := range m.items {
					if m.items[i].id == item { found = &m.items[i]; break }
				}
			}
			if found == nil { ctx.SetReturn(0); return 0 }
			fMask, _ := ctx.Mem.Read32(lpmii + 4)
			const MIIM_TYPE   = 0x00000010
			const MIIM_ID     = 0x00000002
			const MIIM_STRING = 0x00000040
			if fMask&MIIM_ID != 0 { ctx.Mem.Write32(lpmii+16, uint32(found.id)) }
			if fMask&(MIIM_TYPE|MIIM_STRING) != 0 {
				// 32-bit MENUITEMINFOW: dwTypeData ptr at +36, cch at +40
				dtPtr, _ := ctx.Mem.Read64(lpmii + 36)
				cch, _ := ctx.Mem.Read32(lpmii + 40)
				if dtPtr != 0 && cch > 0 {
					ws := utf16Encode(found.text)
					limit := int(cch) - 1
					if limit > len(ws) { limit = len(ws) }
					for i := 0; i < limit; i++ { ctx.Mem.Write16(dtPtr+uint64(i)*2, ws[i]) }
					ctx.Mem.Write16(dtPtr+uint64(limit)*2, 0)
				}
				ctx.Mem.Write32(lpmii+40, uint32(len(utf16Encode(found.text))))
			}
			ctx.SetReturn(1)
			return 0
		})

		// GetMenuState returns flags for menu item (by position or ID)
		d.RegisterAutoStubHandler(user32, "GetMenuState", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // no flags
			return 0
		})

		// GetMenuItemCount returns number of items in a menu
		d.RegisterAutoStubHandler(user32, "GetMenuItemCount", func(ctx *ntapi.TrapContext) uint32 {
			hmenu := ctx.Arg(0)
			if m, ok := menus[hmenu]; ok {
				ctx.SetReturn(uint64(len(m.items)))
			} else {
				ctx.SetReturn(0xffffffffffffffff) // -1 on error
			}
			return 0
		})

		// SetMenuItemInfoW
		d.RegisterAutoStubHandler(user32, "SetMenuItemInfoW", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "SetMenuItemInfoA", func(ctx *ntapi.TrapContext) uint32 {
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
		// GetSysColorBrush: return a solid brush for the given system colour index
		d.RegisterAutoStubHandler(user32, "GetSysColorBrush", func(ctx *ntapi.TrapContext) uint32 {
			idx := ctx.Arg(0)
			h := gdiMgr.CreateSolidBrush(getSysColor(uint32(idx)))
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
			dc := getDC(hDC)
			left, _ := mem.Read32(lpRect)
			top, _ := mem.Read32(lpRect + 4)
			right, _ := mem.Read32(lpRect + 8)
			bottom, _ := mem.Read32(lpRect + 12)
			color := gdiMgr.BrushColor(hBrush, sysColors)
			dc.FillRect(int32(left), int32(top), int32(right), int32(bottom), color)
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
		// RemoveMenu: remove a menu item by position or ID
		d.RegisterAutoStubHandler(user32, "RemoveMenu", func(ctx *ntapi.TrapContext) uint32 {
			hMenu := ctx.Arg(0)
			idPos := ctx.Arg(1)
			flags := uint32(ctx.Arg(2))
			m, ok := menus[hMenu]
			if !ok { ctx.SetReturn(0); return 0 }
			const MF_BYPOSITION = 0x0400
			if flags&MF_BYPOSITION != 0 {
				idx := int(idPos)
				if idx >= 0 && idx < len(m.items) {
					m.items = append(m.items[:idx], m.items[idx+1:]...)
				}
			} else {
				for i := range m.items {
					if m.items[i].id == idPos {
						m.items = append(m.items[:i], m.items[i+1:]...)
						break
					}
				}
			}
			ctx.SetReturn(1)
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

		// FindWindowA: ANSI wrapper - convert strings, return NULL (not found)
		d.RegisterAutoStubHandler(user32, "FindWindowA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // not found
			return 0
		})

		// GetDoubleClickTime: standard Windows default of 500ms
		d.RegisterAutoStubHandler(user32, "GetDoubleClickTime", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(500)
			return 0
		})

		// GetMessageA: ANSI wrapper for GetMessageW - delegate to same queue
		d.RegisterAutoStubHandler(user32, "GetMessageA", func(ctx *ntapi.TrapContext) uint32 {
			pMsg := ctx.Arg(0)
			if len(msgQueue) > 0 {
				m := msgQueue[0]
				msgQueue = msgQueue[1:]
				if pMsg != 0 {
					writeMsg(pMsg, m.hwnd, m.message, m.wParam, m.lParam)
				}
				ctx.SetReturn(1)
				return 0
			}
			// No messages; return WM_QUIT to avoid infinite spin
			if pMsg != 0 {
				writeMsg(pMsg, mainHWND, 0x12, 0, 0) // WM_QUIT
			}
			ctx.SetReturn(0)
			return 0
		})

		// LoadCursorA: ANSI wrapper - same as LoadCursorW
		d.RegisterAutoStubHandler(user32, "LoadCursorA", func(ctx *ntapi.TrapContext) uint32 {
			lpCursorName := ctx.Arg(1)
			if lpCursorName < 0x10000 && lpCursorName != 0 {
				ctx.SetReturn(lpCursorName)
			} else {
				ctx.SetReturn(0x00010001)
			}
			return 0
		})

		// SetWindowsHookExA: ANSI wrapper - return dummy hook handle
		d.RegisterAutoStubHandler(user32, "SetWindowsHookExA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x00060001) // dummy hook handle
			return 0
		})

		// -------------------------------------------------------
		// RECT operations - delegate to pkg/win32/rect.go
		// -------------------------------------------------------
		readRect := func(p uint64) win32.Rect {
			l, _ := mem.Read32(p); t, _ := mem.Read32(p+4)
			r, _ := mem.Read32(p+8); b, _ := mem.Read32(p+12)
			return win32.Rect{Left: int32(l), Top: int32(t), Right: int32(r), Bottom: int32(b)}
		}
		writeRect := func(p uint64, rc win32.Rect) {
			ctx2 := rc // local copy to avoid capture issues
			_ = ctx2
			mem.Write32(p, uint32(rc.Left)); mem.Write32(p+4, uint32(rc.Top))
			mem.Write32(p+8, uint32(rc.Right)); mem.Write32(p+12, uint32(rc.Bottom))
		}
		_ = writeRect
		_ = readRect
		d.RegisterAutoStubHandler(user32, "CopyRect", func(ctx *ntapi.TrapContext) uint32 {
			pDst, pSrc := ctx.Arg(0), ctx.Arg(1)
			if pDst == 0 || pSrc == 0 { ctx.SetReturn(0); return 0 }
			rc := readRect(pSrc)
			mem.Write32(pDst, uint32(rc.Left)); mem.Write32(pDst+4, uint32(rc.Top))
			mem.Write32(pDst+8, uint32(rc.Right)); mem.Write32(pDst+12, uint32(rc.Bottom))
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "EqualRect", func(ctx *ntapi.TrapContext) uint32 {
			r1, r2 := readRect(ctx.Arg(0)), readRect(ctx.Arg(1))
			if win32.EqualRect(&r1, &r2) { ctx.SetReturn(1) } else { ctx.SetReturn(0) }
			return 0
		})
		d.RegisterAutoStubHandler(user32, "InflateRect", func(ctx *ntapi.TrapContext) uint32 {
			p := ctx.Arg(0); dx, dy := int32(ctx.Arg(1)), int32(ctx.Arg(2))
			rc := readRect(p); win32.InflateRect(&rc, dx, dy)
			mem.Write32(p, uint32(rc.Left)); mem.Write32(p+4, uint32(rc.Top))
			mem.Write32(p+8, uint32(rc.Right)); mem.Write32(p+12, uint32(rc.Bottom))
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "IntersectRect", func(ctx *ntapi.TrapContext) uint32 {
			pDst, pSrc1, pSrc2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
			r1, r2 := readRect(pSrc1), readRect(pSrc2)
			dst := win32.Rect{}
			ok := win32.IntersectRect(&dst, &r1, &r2)
			mem.Write32(pDst, uint32(dst.Left)); mem.Write32(pDst+4, uint32(dst.Top))
			mem.Write32(pDst+8, uint32(dst.Right)); mem.Write32(pDst+12, uint32(dst.Bottom))
			if ok { ctx.SetReturn(1) } else { ctx.SetReturn(0) }
			return 0
		})
		d.RegisterAutoStubHandler(user32, "IsRectEmpty", func(ctx *ntapi.TrapContext) uint32 {
			rc := readRect(ctx.Arg(0))
			if win32.IsRectEmpty(&rc) { ctx.SetReturn(1) } else { ctx.SetReturn(0) }
			return 0
		})
		d.RegisterAutoStubHandler(user32, "OffsetRect", func(ctx *ntapi.TrapContext) uint32 {
			p := ctx.Arg(0); dx, dy := int32(ctx.Arg(1)), int32(ctx.Arg(2))
			rc := readRect(p); win32.OffsetRect(&rc, dx, dy)
			mem.Write32(p, uint32(rc.Left)); mem.Write32(p+4, uint32(rc.Top))
			mem.Write32(p+8, uint32(rc.Right)); mem.Write32(p+12, uint32(rc.Bottom))
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "PtInRect", func(ctx *ntapi.TrapContext) uint32 {
			rc := readRect(ctx.Arg(0))
			x, y := int32(ctx.Arg(1)), int32(ctx.Arg(2))
			if win32.PtInRect(&rc, x, y) { ctx.SetReturn(1) } else { ctx.SetReturn(0) }
			return 0
		})
		d.RegisterAutoStubHandler(user32, "SetRect", func(ctx *ntapi.TrapContext) uint32 {
			p := ctx.Arg(0)
			l, t, r, b := int32(ctx.Arg(1)), int32(ctx.Arg(2)), int32(ctx.Arg(3)), int32(ctx.Arg(4))
			rc := win32.Rect{Left: l, Top: t, Right: r, Bottom: b}
			win32.SetRect(&rc, l, t, r, b)
			mem.Write32(p, uint32(rc.Left)); mem.Write32(p+4, uint32(rc.Top))
			mem.Write32(p+8, uint32(rc.Right)); mem.Write32(p+12, uint32(rc.Bottom))
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "SetRectEmpty", func(ctx *ntapi.TrapContext) uint32 {
			p := ctx.Arg(0)
			mem.Write32(p, 0); mem.Write32(p+4, 0); mem.Write32(p+8, 0); mem.Write32(p+12, 0)
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "SubtractRect", func(ctx *ntapi.TrapContext) uint32 {
			pDst, pSrc1, pSrc2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
			r1, r2 := readRect(pSrc1), readRect(pSrc2)
			dst := win32.Rect{}; ok := win32.SubtractRect(&dst, &r1, &r2)
			mem.Write32(pDst, uint32(dst.Left)); mem.Write32(pDst+4, uint32(dst.Top))
			mem.Write32(pDst+8, uint32(dst.Right)); mem.Write32(pDst+12, uint32(dst.Bottom))
			if ok { ctx.SetReturn(1) } else { ctx.SetReturn(0) }
			return 0
		})
		d.RegisterAutoStubHandler(user32, "UnionRect", func(ctx *ntapi.TrapContext) uint32 {
			pDst, pSrc1, pSrc2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
			r1, r2 := readRect(pSrc1), readRect(pSrc2)
			dst := win32.Rect{}; win32.UnionRect(&dst, &r1, &r2)
			mem.Write32(pDst, uint32(dst.Left)); mem.Write32(pDst+4, uint32(dst.Top))
			mem.Write32(pDst+8, uint32(dst.Right)); mem.Write32(pDst+12, uint32(dst.Bottom))
			ctx.SetReturn(1); return 0
		})

		// -------------------------------------------------------
		// Char / string operations
		// -------------------------------------------------------
		// Helper: read ANSI string from guest
		readAnsi := func(p uint64) string {
			var b []byte
			for i := uint64(0); i < 1024; i++ {
				ch, _ := mem.Read8(p + i)
				if ch == 0 { break }
				b = append(b, ch)
			}
			return string(b)
		}
		_ = readAnsi
		d.RegisterAutoStubHandler(user32, "CharUpperW", func(ctx *ntapi.TrapContext) uint32 {
			p := ctx.Arg(0)
			if p < 0x10000 {
				ctx.SetReturn(uint64(unicode.ToUpper(rune(p))))
			} else {
				for off := uint64(0); ; off += 2 {
					lo, _ := mem.Read16(p + off)
					if lo == 0 { break }
					up := uint16(unicode.ToUpper(rune(lo)))
					ctx.Mem.Write16(p+off, up)
				}
				ctx.SetReturn(p)
			}
			return 0
		})
		d.RegisterAutoStubHandler(user32, "CharUpperA", func(ctx *ntapi.TrapContext) uint32 {
			p := ctx.Arg(0)
			if p < 0x100 {
				ctx.SetReturn(uint64(unicode.ToUpper(rune(p & 0xFF))))
			} else {
				for off := uint64(0); ; off++ {
					b, _ := mem.Read8(p + off)
					if b == 0 { break }
					ctx.Mem.Write8(p+off, byte(unicode.ToUpper(rune(b))))
				}
				ctx.SetReturn(p)
			}
			return 0
		})
		d.RegisterAutoStubHandler(user32, "CharLowerW", func(ctx *ntapi.TrapContext) uint32 {
			p := ctx.Arg(0)
			if p < 0x10000 {
				ctx.SetReturn(uint64(unicode.ToLower(rune(p))))
			} else {
				for off := uint64(0); ; off += 2 {
					lo, _ := mem.Read16(p + off)
					if lo == 0 { break }
					ctx.Mem.Write16(p+off, uint16(unicode.ToLower(rune(lo))))
				}
				ctx.SetReturn(p)
			}
			return 0
		})
		d.RegisterAutoStubHandler(user32, "CharLowerA", func(ctx *ntapi.TrapContext) uint32 {
			p := ctx.Arg(0)
			if p < 0x100 {
				ctx.SetReturn(uint64(unicode.ToLower(rune(p & 0xFF))))
			} else {
				for off := uint64(0); ; off++ {
					b, _ := mem.Read8(p + off)
					if b == 0 { break }
					ctx.Mem.Write8(p+off, byte(unicode.ToLower(rune(b))))
				}
				ctx.SetReturn(p)
			}
			return 0
		})
		d.RegisterAutoStubHandler(user32, "CharUpperBuffW", func(ctx *ntapi.TrapContext) uint32 {
			p, n := ctx.Arg(0), ctx.Arg(1)
			for i := uint64(0); i < n; i++ {
				lo, _ := mem.Read16(p + i*2)
				ctx.Mem.Write16(p+i*2, uint16(unicode.ToUpper(rune(lo))))
			}
			ctx.SetReturn(n); return 0
		})
		d.RegisterAutoStubHandler(user32, "CharUpperBuffA", func(ctx *ntapi.TrapContext) uint32 {
			p, n := ctx.Arg(0), ctx.Arg(1)
			for i := uint64(0); i < n; i++ {
				b, _ := mem.Read8(p + i)
				ctx.Mem.Write8(p+i, byte(unicode.ToUpper(rune(b))))
			}
			ctx.SetReturn(n); return 0
		})
		d.RegisterAutoStubHandler(user32, "CharLowerBuffW", func(ctx *ntapi.TrapContext) uint32 {
			p, n := ctx.Arg(0), ctx.Arg(1)
			for i := uint64(0); i < n; i++ {
				lo, _ := mem.Read16(p + i*2)
				ctx.Mem.Write16(p+i*2, uint16(unicode.ToLower(rune(lo))))
			}
			ctx.SetReturn(n); return 0
		})
		d.RegisterAutoStubHandler(user32, "CharLowerBuffA", func(ctx *ntapi.TrapContext) uint32 {
			p, n := ctx.Arg(0), ctx.Arg(1)
			for i := uint64(0); i < n; i++ {
				b, _ := mem.Read8(p + i)
				ctx.Mem.Write8(p+i, byte(unicode.ToLower(rune(b))))
			}
			ctx.SetReturn(n); return 0
		})
		d.RegisterAutoStubHandler(user32, "CharNextW", func(ctx *ntapi.TrapContext) uint32 {
			p := ctx.Arg(0)
			lo, _ := mem.Read16(p)
			if lo != 0 { ctx.SetReturn(p + 2) } else { ctx.SetReturn(p) }
			return 0
		})
		d.RegisterAutoStubHandler(user32, "CharNextA", func(ctx *ntapi.TrapContext) uint32 {
			p := ctx.Arg(0)
			b, _ := mem.Read8(p)
			if b != 0 { ctx.SetReturn(p + 1) } else { ctx.SetReturn(p) }
			return 0
		})
		d.RegisterAutoStubHandler(user32, "CharNextExA", func(ctx *ntapi.TrapContext) uint32 {
			p := ctx.Arg(1) // (codePage, pCurrentChar, flags)
			b, _ := mem.Read8(p)
			if b != 0 { ctx.SetReturn(p + 1) } else { ctx.SetReturn(p) }
			return 0
		})
		d.RegisterAutoStubHandler(user32, "CharPrevW", func(ctx *ntapi.TrapContext) uint32 {
			start, cur := ctx.Arg(0), ctx.Arg(1)
			if cur > start+2 { ctx.SetReturn(cur - 2) } else { ctx.SetReturn(start) }
			return 0
		})
		d.RegisterAutoStubHandler(user32, "CharPrevA", func(ctx *ntapi.TrapContext) uint32 {
			start, cur := ctx.Arg(0), ctx.Arg(1)
			if cur > start { ctx.SetReturn(cur - 1) } else { ctx.SetReturn(start) }
			return 0
		})
		d.RegisterAutoStubHandler(user32, "CharPrevExA", func(ctx *ntapi.TrapContext) uint32 {
			start, cur := ctx.Arg(1), ctx.Arg(2)
			if cur > start { ctx.SetReturn(cur - 1) } else { ctx.SetReturn(start) }
			return 0
		})
		d.RegisterAutoStubHandler(user32, "IsCharAlphaW", func(ctx *ntapi.TrapContext) uint32 {
			if unicode.IsLetter(rune(ctx.Arg(0))) { ctx.SetReturn(1) } else { ctx.SetReturn(0) }
			return 0
		})
		d.RegisterAutoStubHandler(user32, "IsCharAlphaA", func(ctx *ntapi.TrapContext) uint32 {
			c := rune(ctx.Arg(0) & 0xFF)
			if unicode.IsLetter(c) { ctx.SetReturn(1) } else { ctx.SetReturn(0) }
			return 0
		})
		d.RegisterAutoStubHandler(user32, "IsCharAlphaNumericW", func(ctx *ntapi.TrapContext) uint32 {
			c := rune(ctx.Arg(0))
			if unicode.IsLetter(c) || unicode.IsDigit(c) { ctx.SetReturn(1) } else { ctx.SetReturn(0) }
			return 0
		})
		d.RegisterAutoStubHandler(user32, "IsCharAlphaNumericA", func(ctx *ntapi.TrapContext) uint32 {
			c := rune(ctx.Arg(0) & 0xFF)
			if unicode.IsLetter(c) || unicode.IsDigit(c) { ctx.SetReturn(1) } else { ctx.SetReturn(0) }
			return 0
		})
		d.RegisterAutoStubHandler(user32, "IsCharLowerW", func(ctx *ntapi.TrapContext) uint32 {
			if unicode.IsLower(rune(ctx.Arg(0))) { ctx.SetReturn(1) } else { ctx.SetReturn(0) }
			return 0
		})
		d.RegisterAutoStubHandler(user32, "IsCharLowerA", func(ctx *ntapi.TrapContext) uint32 {
			if unicode.IsLower(rune(ctx.Arg(0) & 0xFF)) { ctx.SetReturn(1) } else { ctx.SetReturn(0) }
			return 0
		})
		d.RegisterAutoStubHandler(user32, "IsCharUpperW", func(ctx *ntapi.TrapContext) uint32 {
			if unicode.IsUpper(rune(ctx.Arg(0))) { ctx.SetReturn(1) } else { ctx.SetReturn(0) }
			return 0
		})
		d.RegisterAutoStubHandler(user32, "IsCharUpperA", func(ctx *ntapi.TrapContext) uint32 {
			if unicode.IsUpper(rune(ctx.Arg(0) & 0xFF)) { ctx.SetReturn(1) } else { ctx.SetReturn(0) }
			return 0
		})
		// OEM ↔ char: identity in Unicode mode
		for _, fn := range []string{"OemToCharA", "OemToCharW", "CharToOemA", "CharToOemW"} {
			fn := fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				src, dst := ctx.Arg(0), ctx.Arg(1)
				if src != 0 && dst != 0 {
					for off := uint64(0); off < 1024; off++ {
						b, _ := mem.Read8(src + off)
						ctx.Mem.Write8(dst+off, b)
						if b == 0 { break }
					}
				}
				ctx.SetReturn(1); return 0
			})
		}
		for _, fn := range []string{"OemToCharBuffA", "OemToCharBuffW", "CharToOemBuffA", "CharToOemBuffW"} {
			fn := fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				src, dst, n := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
				for i := uint64(0); i < n; i++ {
					b, _ := mem.Read8(src + i)
					ctx.Mem.Write8(dst+i, b)
				}
				ctx.SetReturn(1); return 0
			})
		}

		// -------------------------------------------------------
		// Clipboard
		// -------------------------------------------------------
		d.RegisterAutoStubHandler(user32, "OpenClipboard", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			if win32.OpenClipboard(hwnd) { ctx.SetReturn(1) } else { ctx.SetReturn(0) }
			return 0
		})
		d.RegisterAutoStubHandler(user32, "CloseClipboard", func(ctx *ntapi.TrapContext) uint32 {
			if win32.CloseClipboard() { ctx.SetReturn(1) } else { ctx.SetReturn(0) }
			return 0
		})
		d.RegisterAutoStubHandler(user32, "EmptyClipboard", func(ctx *ntapi.TrapContext) uint32 {
			if win32.EmptyClipboard() { ctx.SetReturn(1) } else { ctx.SetReturn(0) }
			return 0
		})
		d.RegisterAutoStubHandler(user32, "SetClipboardData", func(ctx *ntapi.TrapContext) uint32 {
			// hData is a global memory handle; we can't dereference it here - just track it
			ctx.SetReturn(ctx.Arg(1)); return 0
		})
		d.RegisterAutoStubHandler(user32, "GetClipboardData", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(user32, "CountClipboardFormats", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(uint64(win32.CountClipboardFormats())); return 0
		})
		d.RegisterAutoStubHandler(user32, "IsClipboardFormatAvailable", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(user32, "GetClipboardOwner", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(win32.GetClipboardOwner()); return 0
		})
		d.RegisterAutoStubHandler(user32, "GetOpenClipboardWindow", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(win32.GetOpenClipboardWindow()); return 0
		})
		d.RegisterAutoStubHandler(user32, "GetClipboardViewer", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(user32, "SetClipboardViewer", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(user32, "ChangeClipboardChain", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "EnumClipboardFormats", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(user32, "GetClipboardFormatNameA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(user32, "GetClipboardFormatNameW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(user32, "GetClipboardSequenceNumber", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "GetPriorityClipboardFormat", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(uint64(0xFFFFFFFF)); return 0 // -1 = no format
		})
		d.RegisterAutoStubHandler(user32, "RegisterClipboardFormatA", func(ctx *ntapi.TrapContext) uint32 {
			// Return a fixed handle in the private format range 0xC000-0xFFFF
			p := ctx.Arg(0)
			hash := uint64(0xC000)
			for i := uint64(0); i < 32; i++ {
				b, _ := mem.Read8(p + i)
				if b == 0 { break }
				hash = hash*31 + uint64(b)
			}
			ctx.SetReturn((hash & 0x3FFF) + 0xC000); return 0
		})

		// -------------------------------------------------------
		// Keyboard / input
		// -------------------------------------------------------
		d.RegisterAutoStubHandler(user32, "GetKeyboardState", func(ctx *ntapi.TrapContext) uint32 {
			p := ctx.Arg(0)
			for i := uint64(0); i < 256; i++ { ctx.Mem.Write8(p+i, 0) }
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "SetKeyboardState", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "GetKeyboardType", func(ctx *ntapi.TrapContext) uint32 {
			switch ctx.Arg(0) {
			case 0: ctx.SetReturn(4)   // enhanced keyboard
			case 1: ctx.SetReturn(0)   // subtype
			case 2: ctx.SetReturn(101) // function keys
			default: ctx.SetReturn(0)
			}
			return 0
		})
		d.RegisterAutoStubHandler(user32, "GetKeyboardLayoutList", func(ctx *ntapi.TrapContext) uint32 {
			n := ctx.Arg(0); p := ctx.Arg(1)
			if p != 0 && n >= 1 { ctx.Mem.Write64(p, 0x04090409) }
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "GetKeyboardLayoutNameA", func(ctx *ntapi.TrapContext) uint32 {
			p := ctx.Arg(0)
			if p != 0 {
				layout := "00000409"
				for i, ch := range layout { ctx.Mem.Write8(p+uint64(i), byte(ch)) }
				ctx.Mem.Write8(p+8, 0)
			}
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "GetKeyboardLayoutNameW", func(ctx *ntapi.TrapContext) uint32 {
			p := ctx.Arg(0)
			if p != 0 {
				layout := "00000409"
				for i, ch := range layout { ctx.Mem.Write16(p+uint64(i)*2, uint16(ch)) }
				ctx.Mem.Write16(p+16, 0)
			}
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "ActivateKeyboardLayout", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x04090409); return 0
		})
		d.RegisterAutoStubHandler(user32, "UnloadKeyboardLayout", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		for _, fn := range []string{"LoadKeyboardLayoutA", "LoadKeyboardLayoutW", "LoadKeyboardLayoutEx"} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(0x04090409); return 0
			})
		}
		d.RegisterAutoStubHandler(user32, "GetKBCodePage", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1252); return 0
		})
		// VkKeyScan: map ASCII char to VK | (shiftState << 8)
		vkKeyScanChar := func(c rune) uint64 {
			if c >= '0' && c <= '9' { return uint64(c) }
			if c >= 'a' && c <= 'z' { return uint64(c - 32) } // VK_A..VK_Z = 0x41..0x5A
			if c >= 'A' && c <= 'Z' { return uint64(c) | (1 << 8) } // shifted
			return uint64(0xFFFF) // not found
		}
		d.RegisterAutoStubHandler(user32, "VkKeyScanA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(vkKeyScanChar(rune(ctx.Arg(0) & 0xFF))); return 0
		})
		d.RegisterAutoStubHandler(user32, "VkKeyScanW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(vkKeyScanChar(rune(ctx.Arg(0) & 0xFFFF))); return 0
		})
		d.RegisterAutoStubHandler(user32, "VkKeyScanExA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(vkKeyScanChar(rune(ctx.Arg(0) & 0xFF))); return 0
		})
		d.RegisterAutoStubHandler(user32, "VkKeyScanExW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(vkKeyScanChar(rune(ctx.Arg(0) & 0xFFFF))); return 0
		})
		for _, fn := range []string{"MapVirtualKeyA", "MapVirtualKeyExA", "MapVirtualKeyExW"} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(0); return 0
			})
		}
		d.RegisterAutoStubHandler(user32, "GetKeyNameTextA", func(ctx *ntapi.TrapContext) uint32 {
			p := ctx.Arg(1)
			if p != 0 { ctx.Mem.Write8(p, 'K'); ctx.Mem.Write8(p+1, 'e'); ctx.Mem.Write8(p+2, 'y'); ctx.Mem.Write8(p+3, 0) }
			ctx.SetReturn(3); return 0
		})
		d.RegisterAutoStubHandler(user32, "GetKeyNameTextW", func(ctx *ntapi.TrapContext) uint32 {
			p := ctx.Arg(1)
			if p != 0 { ctx.Mem.Write16(p, 'K'); ctx.Mem.Write16(p+2, 'e'); ctx.Mem.Write16(p+4, 'y'); ctx.Mem.Write16(p+6, 0) }
			ctx.SetReturn(3); return 0
		})
		d.RegisterAutoStubHandler(user32, "OemKeyScan", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(ctx.Arg(0) & 0xFF); return 0
		})
		for _, fn := range []string{"ToAscii", "ToAsciiEx", "ToUnicode", "ToUnicodeEx"} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(0); return 0
			})
		}
		d.RegisterAutoStubHandler(user32, "keybd_event", func(ctx *ntapi.TrapContext) uint32 {
			return 0
		})
		d.RegisterAutoStubHandler(user32, "mouse_event", func(ctx *ntapi.TrapContext) uint32 {
			return 0
		})
		d.RegisterAutoStubHandler(user32, "SendInput", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(ctx.Arg(0)); return 0
		})

		// -------------------------------------------------------
		// Message / queue
		// -------------------------------------------------------
		d.RegisterAutoStubHandler(user32, "PostQuitMessage", func(ctx *ntapi.TrapContext) uint32 {
			return 0
		})
		for _, fn := range []string{"GetInputState", "GetQueueStatus", "InSendMessage"} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(0); return 0
			})
		}
		d.RegisterAutoStubHandler(user32, "InSendMessageEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(user32, "ReplyMessage", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(user32, "QuerySendMessage", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(user32, "MsgWaitForMultipleObjects", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0 // WAIT_OBJECT_0
		})
		d.RegisterAutoStubHandler(user32, "MsgWaitForMultipleObjectsEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(user32, "WaitMessage", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "WaitForInputIdle", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		for _, fn := range []string{"GetMessagePos", "GetMessageTime", "GetMessageExtraInfo"} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(0); return 0
			})
		}
		d.RegisterAutoStubHandler(user32, "SetMessageExtraInfo", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		for _, fn := range []string{"PostMessageA", "PostThreadMessageA", "PostThreadMessageW"} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(1); return 0
			})
		}
		d.RegisterAutoStubHandler(user32, "PeekMessageA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(user32, "DispatchMessageA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(user32, "SendMessageA", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			msg := uint32(ctx.Arg(1))
			wParam := ctx.Arg(2)
			lParam := ctx.Arg(3)
			if result, handled := builtinWndProc(hwnd, msg, wParam, lParam); handled {
				ctx.SetReturn(result); return 0
			}
			wp, hasWP := hwndWndProc[hwnd]
			if !hasWP || wp == 0 { ctx.SetReturn(0); return 0 }
			rw, okW := ctx.CPU.(ntapi.RegisterWriter)
			rr, okR := ctx.CPU.(ntapi.RegisterReader)
			if okW && okR {
				rsp := rr.ReadReg(4)
				retAddr, _ := mem.Read64(rsp)
				syncStack = append(syncStack, syncDispatchFrame{
					queue: []syncDispatch{}, retAddr: retAddr,
					hwnd: hwnd, returnWndProcResult: true,
				})
				mem.Write64(rsp, syncTrampoline)
				rw.WriteReg(1, hwnd); rw.WriteReg(2, uint64(msg))
				rw.WriteReg(8, wParam); rw.WriteReg(9, lParam)
				ctx.CPU.SetPC(wp); ctx.ReturnOverridden = true
				return 0
			}
			msgQueue = append(msgQueue, queuedMsg{hwnd, msg, wParam, lParam})
			ctx.SetReturn(0); return 0
		})
		for _, fn := range []string{"SendMessageTimeoutA", "SendMessageTimeoutW",
			"SendMessageCallbackA", "SendMessageCallbackW",
			"SendNotifyMessageA", "SendNotifyMessageW", "SendDlgItemMessageA"} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(0); return 0
			})
		}
		d.RegisterAutoStubHandler(user32, "TranslateMessageEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		for _, fn := range []string{"BroadcastSystemMessage", "BroadcastSystemMessageA",
			"BroadcastSystemMessageW", "BroadcastSystemMessageExA", "BroadcastSystemMessageExW",
			"CsrBroadcastSystemMessageExW"} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(1); return 0
			})
		}

		// -------------------------------------------------------
		// Window state / info
		// -------------------------------------------------------
		d.RegisterAutoStubHandler(user32, "IsIconic", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(user32, "IsZoomed", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(user32, "IsWindowEnabled", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "IsWindowUnicode", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "IsMenu", func(ctx *ntapi.TrapContext) uint32 {
			if ctx.Arg(0) != 0 { ctx.SetReturn(1) } else { ctx.SetReturn(0) }
			return 0
		})
		d.RegisterAutoStubHandler(user32, "IsGUIThread", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "IsHungAppWindow", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(user32, "IsWindowInDestroy", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(user32, "IsServerSideWindow", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(user32, "IsSETEnabled", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(user32, "AnyPopup", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(user32, "GetActiveWindow", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(mainHWND); return 0
		})
		d.RegisterAutoStubHandler(user32, "SetActiveWindow", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(mainHWND); return 0
		})
		d.RegisterAutoStubHandler(user32, "GetCapture", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(user32, "GetLastActivePopup", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(ctx.Arg(0)); return 0
		})
		d.RegisterAutoStubHandler(user32, "GetAncestor", func(ctx *ntapi.TrapContext) uint32 {
			hwnd, gaFlags := ctx.Arg(0), ctx.Arg(1)
			switch gaFlags {
			case 2, 3: ctx.SetReturn(mainHWND) // GA_ROOT / GA_ROOTOWNER
			default:
				if cs, ok := hwndChildren[hwnd]; ok { ctx.SetReturn(cs.parentHWND) } else { ctx.SetReturn(0) }
			}
			return 0
		})
		d.RegisterAutoStubHandler(user32, "CloseWindow", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "OpenIcon", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "BringWindowToTop", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "ShowWindowAsync", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "ShowOwnedPopups", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "GetWindowThreadProcessId", func(ctx *ntapi.TrapContext) uint32 {
			pPid := ctx.Arg(1)
			if pPid != 0 { ctx.Mem.Write32(pPid, 1) }
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "GetWindowTextA", func(ctx *ntapi.TrapContext) uint32 {
			hwnd, pBuf, nMax := ctx.Arg(0), ctx.Arg(1), int(ctx.Arg(2))
			var text string
			if cs, ok := hwndChildren[hwnd]; ok { text = cs.text } else if hwnd == mainHWND { text = mainTitle }
			if pBuf != 0 && nMax > 0 {
				bs := []byte(text)
				if len(bs) >= nMax { bs = bs[:nMax-1] }
				for i, b := range bs { ctx.Mem.Write8(pBuf+uint64(i), b) }
				ctx.Mem.Write8(pBuf+uint64(len(bs)), 0)
			}
			ctx.SetReturn(uint64(len(text))); return 0
		})
		d.RegisterAutoStubHandler(user32, "GetWindowTextLengthA", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			if cs, ok := hwndChildren[hwnd]; ok { ctx.SetReturn(uint64(len(cs.text))); return 0 }
			if hwnd == mainHWND { ctx.SetReturn(uint64(len(mainTitle))); return 0 }
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(user32, "SetWindowTextA", func(ctx *ntapi.TrapContext) uint32 {
			hwnd, p := ctx.Arg(0), ctx.Arg(1)
			text := readAnsi(p)
			if hwnd == mainHWND { mainTitle = text }
			if cs, ok := hwndChildren[hwnd]; ok { cs.text = text }
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "GetWindowLongA", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0); index := int32(ctx.Arg(1))
			var val uint64
			if m, ok := windowLongPtr[hwnd]; ok { val = m[index] }
			ctx.SetReturn(val); return 0
		})
		d.RegisterAutoStubHandler(user32, "SetWindowLongA", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0); index := int32(ctx.Arg(1)); newVal := ctx.Arg(2)
			m := windowLongPtr[hwnd]
			if m == nil { m = make(map[int32]uint64); windowLongPtr[hwnd] = m }
			old := m[index]; m[index] = newVal
			ctx.SetReturn(old); return 0
		})
		d.RegisterAutoStubHandler(user32, "GetWindowWord", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0); index := int32(ctx.Arg(1))
			var val uint64
			if m, ok := windowLongPtr[hwnd]; ok { val = m[index] }
			ctx.SetReturn(val & 0xFFFF); return 0
		})
		d.RegisterAutoStubHandler(user32, "SetWindowWord", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0); index := int32(ctx.Arg(1)); newVal := ctx.Arg(2) & 0xFFFF
			m := windowLongPtr[hwnd]
			if m == nil { m = make(map[int32]uint64); windowLongPtr[hwnd] = m }
			old := m[index] & 0xFFFF; m[index] = (m[index] & 0xFFFF0000) | newVal
			ctx.SetReturn(old); return 0
		})
		d.RegisterAutoStubHandler(user32, "GetClassNameA", func(ctx *ntapi.TrapContext) uint32 {
			hwnd, pBuf, nMax := ctx.Arg(0), ctx.Arg(1), int(ctx.Arg(2))
			var name string
			if cs, ok := hwndChildren[hwnd]; ok { name = cs.className }
			if pBuf != 0 && nMax > 0 {
				bs := []byte(name)
				if len(bs) >= nMax { bs = bs[:nMax-1] }
				for i, b := range bs { ctx.Mem.Write8(pBuf+uint64(i), b) }
				ctx.Mem.Write8(pBuf+uint64(len(bs)), 0)
			}
			ctx.SetReturn(uint64(len(name))); return 0
		})
		d.RegisterAutoStubHandler(user32, "GetClassNameW", func(ctx *ntapi.TrapContext) uint32 {
			hwnd, pBuf, nMax := ctx.Arg(0), ctx.Arg(1), int(ctx.Arg(2))
			var name string
			if cs, ok := hwndChildren[hwnd]; ok { name = cs.className }
			if pBuf != 0 && nMax > 0 {
				rs := []rune(name)
				if len(rs) >= nMax { rs = rs[:nMax-1] }
				for i, r := range rs { ctx.Mem.Write16(pBuf+uint64(i)*2, uint16(r)) }
				ctx.Mem.Write16(pBuf+uint64(len(rs))*2, 0)
			}
			ctx.SetReturn(uint64(len(name))); return 0
		})
		for _, fn := range []string{"RealGetWindowClass", "RealGetWindowClassA", "RealGetWindowClassW"} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				hwnd, pBuf, nMax := ctx.Arg(0), ctx.Arg(1), int(ctx.Arg(2))
				var name string
				if cs, ok := hwndChildren[hwnd]; ok { name = cs.className }
				if pBuf != 0 && nMax > 0 {
					bs := []byte(name); if len(bs) >= nMax { bs = bs[:nMax-1] }
					for i, b := range bs { ctx.Mem.Write8(pBuf+uint64(i), b) }
					ctx.Mem.Write8(pBuf+uint64(len(bs)), 0)
				}
				ctx.SetReturn(uint64(len(name))); return 0
			})
		}
		d.RegisterAutoStubHandler(user32, "InternalGetWindowText", func(ctx *ntapi.TrapContext) uint32 {
			hwnd, pBuf, nMax := ctx.Arg(0), ctx.Arg(1), int(ctx.Arg(2))
			var text string
			if cs, ok := hwndChildren[hwnd]; ok { text = cs.text } else if hwnd == mainHWND { text = mainTitle }
			if pBuf != 0 && nMax > 0 {
				rs := []rune(text); if len(rs) >= nMax { rs = rs[:nMax-1] }
				for i, r := range rs { ctx.Mem.Write16(pBuf+uint64(i)*2, uint16(r)) }
				ctx.Mem.Write16(pBuf+uint64(len(rs))*2, 0)
			}
			ctx.SetReturn(uint64(len(text))); return 0
		})
		d.RegisterAutoStubHandler(user32, "GetWindowInfo", func(ctx *ntapi.TrapContext) uint32 {
			hwnd, pWI := ctx.Arg(0), ctx.Arg(1)
			if pWI == 0 { ctx.SetReturn(0); return 0 }
			// WINDOWINFO: cbSize(4)+rcWindow(16)+rcClient(16)+dwStyle(4)+dwExStyle(4)+dwWindowStatus(4)+cxWindowBorders(4)+cyWindowBorders(4)+atomWindowType(2)+wCreatorVersion(2)
			cbSize, _ := mem.Read32(pWI)
			if cbSize < 60 { ctx.SetReturn(0); return 0 }
			var x, y, w, h int32
			if cs, ok := hwndChildren[hwnd]; ok { x, y, w, h = cs.x, cs.y, cs.w, cs.h } else if wlWindow != nil { w, h = wlWindow.Width, wlWindow.Height }
			ctx.Mem.Write32(pWI+4,  uint32(x)); ctx.Mem.Write32(pWI+8,  uint32(y))
			ctx.Mem.Write32(pWI+12, uint32(x+w)); ctx.Mem.Write32(pWI+16, uint32(y+h))
			ctx.Mem.Write32(pWI+20, uint32(x)); ctx.Mem.Write32(pWI+24, uint32(y))
			ctx.Mem.Write32(pWI+28, uint32(x+w)); ctx.Mem.Write32(pWI+32, uint32(y+h))
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "GetWindowDC", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			ox, oy := clientAreaOrigin(hwnd)
			h, dc := allocScreenDC(ox, oy)
			if cs, ok := hwndChildren[hwnd]; ok {
				dc.SetClipRect(cs.x, cs.y, cs.x+cs.w, cs.y+cs.h)
			}
			ctx.SetReturn(h); return 0
		})
		d.RegisterAutoStubHandler(user32, "GetDCEx", func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			ox, oy := clientAreaOrigin(hwnd)
			h, dc := allocScreenDC(ox, oy)
			if cs, ok := hwndChildren[hwnd]; ok {
				dc.SetClipRect(cs.x, cs.y, cs.x+cs.w, cs.y+cs.h)
			}
			ctx.SetReturn(h); return 0
		})
		d.RegisterAutoStubHandler(user32, "GetWindowContextHelpId", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(user32, "SetWindowContextHelpId", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		for _, fn := range []string{"GetWindowModuleFileName", "GetWindowModuleFileNameA", "GetWindowModuleFileNameW"} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(0); return 0
			})
		}
		d.RegisterAutoStubHandler(user32, "GetWindowPlacement", func(ctx *ntapi.TrapContext) uint32 {
			hwnd, pWP := ctx.Arg(0), ctx.Arg(1)
			if pWP == 0 { ctx.SetReturn(0); return 0 }
			// WINDOWPLACEMENT: length(4)+flags(4)+showCmd(4)+ptMinPos(8)+ptMaxPos(8)+rcNormalPos(16)
			ctx.Mem.Write32(pWP, 44) // length
			ctx.Mem.Write32(pWP+4, 0); ctx.Mem.Write32(pWP+8, 1) // SW_SHOWNORMAL
			var x, y, w, h int32
			if cs, ok := hwndChildren[hwnd]; ok { x, y, w, h = cs.x, cs.y, cs.w, cs.h } else if wlWindow != nil { w, h = wlWindow.Width, wlWindow.Height }
			ctx.Mem.Write32(pWP+28, uint32(x)); ctx.Mem.Write32(pWP+32, uint32(y))
			ctx.Mem.Write32(pWP+36, uint32(x+w)); ctx.Mem.Write32(pWP+40, uint32(y+h))
			ctx.SetReturn(1); return 0
		})
		for _, fn := range []string{"GetClassInfoA", "GetClassInfoW", "GetClassInfoExA", "GetClassInfoExW"} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(0); return 0
			})
		}
		for _, fn := range []string{"GetClassLongA", "GetClassLongW", "SetClassLongA", "SetClassLongW", "GetClassWord", "SetClassWord"} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(0); return 0
			})
		}
		d.RegisterAutoStubHandler(user32, "WindowFromDC", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(mainHWND); return 0
		})

		// -------------------------------------------------------
		// Cursor / display
		// -------------------------------------------------------
		d.RegisterAutoStubHandler(user32, "ShowCursor", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0 // fake refcount 1
		})
		d.RegisterAutoStubHandler(user32, "SetCursorPos", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "GetCursorInfo", func(ctx *ntapi.TrapContext) uint32 {
			p := ctx.Arg(0)
			if p != 0 {
				ctx.Mem.Write32(p, 20) // cbSize
				ctx.Mem.Write32(p+4, 1) // flags = CURSOR_SHOWING
				ctx.Mem.Write64(p+8, 0x00010001) // hCursor
				ctx.Mem.Write32(p+16, 0); ctx.Mem.Write32(p+20, 0) // pt
			}
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "ClipCursor", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "GetClipCursor", func(ctx *ntapi.TrapContext) uint32 {
			p := ctx.Arg(0)
			if p != 0 {
				var w, h int32 = 1920, 1080
				if wlWindow != nil { w, h = wlWindow.Width, wlWindow.Height }
				ctx.Mem.Write32(p, 0); ctx.Mem.Write32(p+4, 0)
				ctx.Mem.Write32(p+8, uint32(w)); ctx.Mem.Write32(p+12, uint32(h))
			}
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "GetCursor", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x00010001); return 0
		})
		d.RegisterAutoStubHandler(user32, "GetCursorFrameInfo", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(user32, "SetCursorContents", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "SwapMouseButton", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(user32, "TrackMouseEvent", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "GetMouseMovePointsEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(uint64(0xFFFFFFFF)); return 0 // -1
		})
		d.RegisterAutoStubHandler(user32, "GetLastInputInfo", func(ctx *ntapi.TrapContext) uint32 {
			p := ctx.Arg(0)
			if p != 0 { ctx.Mem.Write32(p, 8); ctx.Mem.Write32(p+4, 0) }
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "MonitorFromPoint", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x00040001); return 0
		})

		// -------------------------------------------------------
		// Display / monitor
		// -------------------------------------------------------
		d.RegisterAutoStubHandler(user32, "EnumDisplayMonitors", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		for _, fn := range []string{"EnumDisplayDevicesA", "EnumDisplayDevicesW",
			"EnumDisplaySettingsA", "EnumDisplaySettingsW", "EnumDisplaySettingsExA", "EnumDisplaySettingsExW"} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(0); return 0
			})
		}
		for _, fn := range []string{"ChangeDisplaySettingsA", "ChangeDisplaySettingsW",
			"ChangeDisplaySettingsExA", "ChangeDisplaySettingsExW"} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(0); return 0 // DISP_CHANGE_SUCCESSFUL
			})
		}

		// -------------------------------------------------------
		// Hooks / WinEvents
		// -------------------------------------------------------
		d.RegisterAutoStubHandler(user32, "SetWindowsHookA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x00070001); return 0
		})
		d.RegisterAutoStubHandler(user32, "SetWindowsHookW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x00070001); return 0
		})
		d.RegisterAutoStubHandler(user32, "SetWinEventHook", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x00080001); return 0
		})
		d.RegisterAutoStubHandler(user32, "NotifyWinEvent", func(ctx *ntapi.TrapContext) uint32 {
			return 0
		})
		d.RegisterAutoStubHandler(user32, "UnhookWinEvent", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "UnhookWindowsHook", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "CallNextHookEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(user32, "IsWinEventHookInstalled", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(user32, "RegisterShellHookWindow", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "DeregisterShellHookWindow", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})

		// -------------------------------------------------------
		// Properties
		// -------------------------------------------------------
		d.RegisterAutoStubHandler(user32, "SetPropA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "GetPropA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(user32, "RemovePropA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		for _, fn := range []string{"EnumPropsA", "EnumPropsW", "EnumPropsExA", "EnumPropsExW"} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(0); return 0
			})
		}

		// -------------------------------------------------------
		// Dialog
		// -------------------------------------------------------
		for _, fn := range []string{"DefDlgProcA", "DefDlgProcW"} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(0); return 0
			})
		}
		d.RegisterAutoStubHandler(user32, "IsDialogMessage", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(user32, "IsDialogMessageA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(user32, "GetDialogBaseUnits", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x00080004); return 0 // MAKELONG(4,8)
		})
		d.RegisterAutoStubHandler(user32, "GetDlgItemTextA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(user32, "SetDlgItemTextA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		for _, fn := range []string{"GetNextDlgGroupItem", "GetNextDlgTabItem"} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(ctx.Arg(1)); return 0 // return hCtl
			})
		}
		for _, fn := range []string{"CreateDialogParamA", "CreateDialogIndirectParamA",
			"CreateDialogIndirectParamAorW"} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(0); return 0
			})
		}
		for _, fn := range []string{"DialogBoxParamA", "DialogBoxIndirectParamA",
			"DialogBoxIndirectParamAorW"} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(uint64(0xFFFFFFFF)); return 0 // -1 = error
			})
		}
		for _, fn := range []string{"DlgDirListA", "DlgDirListW", "DlgDirListComboBoxA",
			"DlgDirListComboBoxW", "DlgDirSelectExA", "DlgDirSelectExW",
			"DlgDirSelectComboBoxExA", "DlgDirSelectComboBoxExW"} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(0); return 0
			})
		}

		// -------------------------------------------------------
		// Menu (A variants + extensions)
		// -------------------------------------------------------
		for _, fn := range []string{"AppendMenuA", "InsertMenuA", "InsertMenuItemA",
			"ModifyMenuA", "ChangeMenuA", "ChangeMenuW"} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(1); return 0
			})
		}
		d.RegisterAutoStubHandler(user32, "GetMenuStringA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(user32, "GetMenuItemID", func(ctx *ntapi.TrapContext) uint32 {
			hMenu := ctx.Arg(0)
			nPos := int(ctx.Arg(1))
			m, ok := menus[hMenu]
			if !ok || nPos < 0 || nPos >= len(m.items) { ctx.SetReturn(0xFFFFFFFF); return 0 }
			ctx.SetReturn(m.items[nPos].id)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "GetMenuCheckMarkDimensions", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x000D000D); return 0 // MAKELONG(13,13)
		})
		for _, fn := range []string{"GetMenuContextHelpId", "GetMenuDefaultItem"} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(uint64(0xFFFFFFFF)); return 0 // -1
			})
		}
		for _, fn := range []string{"SetMenuContextHelpId", "SetMenuDefaultItem"} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(1); return 0
			})
		}
		for _, fn := range []string{"GetMenuBarInfo", "GetMenuInfo", "GetMenuItemInfoA", "GetMenuItemRect"} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(0); return 0
			})
		}
		d.RegisterAutoStubHandler(user32, "SetMenuInfo", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "HiliteMenuItem", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(user32, "CheckMenuRadioItem", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "MenuItemFromPoint", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(uint64(0xFFFFFFFF)); return 0 // -1
		})
		for _, fn := range []string{"TrackPopupMenu", "TrackPopupMenuEx"} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				// hMenu := ntapi.Handle(ctx.Arg(0))
				uFlags := ctx.Arg(1)
				// x := int32(ctx.Arg(2))
				// y := int32(ctx.Arg(3))
				// reserved := ctx.Arg(4)  // only for TrackPopupMenu
				// hwndOwner := ntapi.Handle(ctx.Arg(5))
				const TPM_RETURNCMD = 0x0100
				if uFlags&TPM_RETURNCMD != 0 {
					ctx.SetReturn(0) // no selection
				} else {
					ctx.SetReturn(1) // TRUE = menu was tracked
				}
				return 0
			})
		}
		for _, fn := range []string{"PaintMenuBar", "DrawMenuBarTemp", "CalcMenuBar",
			"MenuWindowProcA", "MenuWindowProcW"} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(0); return 0
			})
		}
		d.RegisterAutoStubHandler(user32, "EndMenu", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "SetSystemMenu", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		for _, fn := range []string{"LoadMenuA", "LoadMenuIndirectA", "LoadMenuIndirectW"} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(0); return 0
			})
		}

		// -------------------------------------------------------
		// SystemParametersInfoA
		// -------------------------------------------------------
		d.RegisterAutoStubHandler(user32, "SystemParametersInfoA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0 // most queries succeed with default values
		})

		// -------------------------------------------------------
		// Drawing (A variants)
		// -------------------------------------------------------
		d.RegisterAutoStubHandler(user32, "DrawTextA", func(ctx *ntapi.TrapContext) uint32 {
			if wlWindow == nil { ctx.SetReturn(1); return 0 }
			// Convert ANSI to UTF-16 and draw via existing DC
			pStr, nCount := ctx.Arg(1), int(int32(ctx.Arg(2)))
			var bs []byte
			for i := 0; i < 4096; i++ {
				b, _ := mem.Read8(ctx.Arg(1) + uint64(i))
				if b == 0 && (nCount < 0 || i >= nCount) { break }
				if nCount >= 0 && i >= nCount { break }
				bs = append(bs, b); _ = pStr
			}
			_ = bs
			// Fallback: just return a valid height
			ctx.SetReturn(16); return 0
		})
		d.RegisterAutoStubHandler(user32, "DrawTextExA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(16); return 0
		})
		d.RegisterAutoStubHandler(user32, "DrawStateA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		for _, fn := range []string{"DrawCaption", "DrawCaptionTempA", "DrawCaptionTempW",
			"DrawFrame", "DrawAnimatedRects"} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(1); return 0
			})
		}
		d.RegisterAutoStubHandler(user32, "GrayStringA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		for _, fn := range []string{"TabbedTextOutA", "GetTabbedTextExtentA", "GetTabbedTextExtentW"} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(0); return 0
			})
		}
		d.RegisterAutoStubHandler(user32, "ExcludeUpdateRgn", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})

		// -------------------------------------------------------
		// Misc utility
		// -------------------------------------------------------
		d.RegisterAutoStubHandler(user32, "MessageBeep", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		for _, fn := range []string{"MessageBoxExA", "MessageBoxExW",
			"MessageBoxIndirectA", "MessageBoxIndirectW",
			"MessageBoxTimeoutA", "MessageBoxTimeoutW", "SoftModalMessageBox"} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(1); return 0 // IDOK
			})
		}
		d.RegisterAutoStubHandler(user32, "LoadStringA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(user32, "RegisterWindowMessageA", func(ctx *ntapi.TrapContext) uint32 {
			p := ctx.Arg(0)
			hash := uint64(0xC000)
			for i := uint64(0); i < 64; i++ {
				b, _ := mem.Read8(p + i); if b == 0 { break }
				hash = hash*31 + uint64(b)
			}
			ctx.SetReturn((hash & 0x3FFF) + 0xC000); return 0
		})
		d.RegisterAutoStubHandler(user32, "ExitWindowsEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		for _, fn := range []string{"FlashWindow", "FlashWindowEx"} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(0); return 0
			})
		}
		d.RegisterAutoStubHandler(user32, "AnimateWindow", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "LockWorkStation", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		for _, fn := range []string{"SetLayeredWindowAttributes", "UpdateLayeredWindow",
			"UpdateLayeredWindowIndirect"} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(1); return 0
			})
		}
		d.RegisterAutoStubHandler(user32, "GetLayeredWindowAttributes", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(user32, "DisableProcessWindowsGhosting", func(ctx *ntapi.TrapContext) uint32 {
			return 0
		})
		d.RegisterAutoStubHandler(user32, "GetGuiResources", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(100); return 0
		})
		d.RegisterAutoStubHandler(user32, "GetGUIThreadInfo", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		for _, fn := range []string{"GetComboBoxInfo", "GetListBoxInfo", "GetScrollBarInfo", "GetTitleBarInfo"} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(0); return 0
			})
		}
		for _, fn := range []string{"AllowSetForegroundWindow", "LockSetForegroundWindow"} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(1); return 0
			})
		}
		d.RegisterAutoStubHandler(user32, "ShowStartGlass", func(ctx *ntapi.TrapContext) uint32 {
			return 0
		})
		for _, fn := range []string{"ArrangeIconicWindows", "CascadeChildWindows",
			"CascadeWindows", "TileChildWindows", "TileWindows"} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(0); return 0
			})
		}
		d.RegisterAutoStubHandler(user32, "RegisterHotKey", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "UnregisterHotKey", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		for _, fn := range []string{"RegisterDeviceNotificationA", "RegisterDeviceNotificationW"} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(0x00090001); return 0
			})
		}
		d.RegisterAutoStubHandler(user32, "UnregisterDeviceNotification", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		for _, fn := range []string{"TranslateAccelerator", "TranslateAcceleratorA", "TranslateMDISysAccel"} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(0); return 0
			})
		}
		d.RegisterAutoStubHandler(user32, "AttachThreadInput", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "BlockInput", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "DragDetect", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(user32, "DragObject", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})

		// -------------------------------------------------------
		// Window class (ANSI registration)
		// -------------------------------------------------------
		d.RegisterAutoStubHandler(user32, "RegisterClassA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0xA001); return 0 // dummy atom
		})
		d.RegisterAutoStubHandler(user32, "RegisterClassExA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0xA001); return 0
		})
		for _, fn := range []string{"UnregisterClassA", "UnregisterClassW"} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(1); return 0
			})
		}
		d.RegisterAutoStubHandler(user32, "CreateWindowExA", func(ctx *ntapi.TrapContext) uint32 {
			// Return a dummy non-zero HWND for ANSI CreateWindow
			ctx.SetReturn(0x0000BEEF); return 0
		})

		// -------------------------------------------------------
		// DDE (all stub → 0)
		// -------------------------------------------------------
		for _, fn := range []string{"DdeAbandonTransaction", "DdeAccessData", "DdeAddData",
			"DdeClientTransaction", "DdeCmpStringHandles", "DdeConnect", "DdeConnectList",
			"DdeCreateDataHandle", "DdeCreateStringHandleA", "DdeCreateStringHandleW",
			"DdeDisconnect", "DdeDisconnectList", "DdeEnableCallback", "DdeFreeDataHandle",
			"DdeFreeStringHandle", "DdeGetData", "DdeGetLastError", "DdeGetQualityOfService",
			"DdeImpersonateClient", "DdeInitializeA", "DdeInitializeW", "DdeKeepStringHandle",
			"DdeNameService", "DdePostAdvise", "DdeQueryConvInfo", "DdeQueryNextServer",
			"DdeQueryStringA", "DdeQueryStringW", "DdeReconnect", "DdeSetQualityOfService",
			"DdeSetUserHandle", "DdeUnaccessData", "DdeUninitialize",
			"FreeDDElParam", "PackDDElParam", "ReuseDDElParam", "UnpackDDElParam",
			"ImpersonateDdeClientWindow"} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(0); return 0
			})
		}

		// -------------------------------------------------------
		// Desktop / WindowStation (all stub)
		// -------------------------------------------------------
		for _, fn := range []string{"CloseDesktop", "CloseWindowStation", "CreateDesktopA",
			"CreateDesktopW", "CreateWindowStationA", "CreateWindowStationW",
			"GetInputDesktop", "GetProcessWindowStation", "GetThreadDesktop",
			"GetUserObjectInformationA", "GetUserObjectInformationW", "GetUserObjectSecurity",
			"LockWindowStation", "OpenDesktopA", "OpenDesktopW", "OpenInputDesktop",
			"OpenWindowStationA", "OpenWindowStationW", "SetProcessWindowStation",
			"SetThreadDesktop", "SetUserObjectInformationA", "SetUserObjectInformationW",
			"SetUserObjectSecurity", "SwitchDesktop", "UnlockWindowStation",
			"EnumDesktopsA", "EnumDesktopsW", "EnumDesktopWindows",
			"EnumWindowStationsA", "EnumWindowStationsW", "GetWinStationInfo"} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(0); return 0
			})
		}

		// -------------------------------------------------------
		// Raw input (all stub)
		// -------------------------------------------------------
		for _, fn := range []string{"GetRawInputBuffer", "GetRawInputData",
			"GetRawInputDeviceInfoA", "GetRawInputDeviceInfoW", "GetRawInputDeviceList",
			"GetRegisteredRawInputDevices", "RegisterRawInputDevices", "DefRawInputProc"} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(0); return 0
			})
		}

		// -------------------------------------------------------
		// IME / WINNLS / misc internal
		// -------------------------------------------------------
		for _, fn := range []string{"IMPGetIMEA", "IMPGetIMEW", "IMPQueryIMEA", "IMPQueryIMEW",
			"IMPSetIMEA", "IMPSetIMEW", "CliImmSetHotKey",
			"WINNLSEnableIME", "WINNLSGetEnableStatus", "WINNLSGetIMEHotkey"} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(0); return 0
			})
		}
		for _, fn := range []string{"SendIMEMessageExA", "SendIMEMessageExW"} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(0); return 0
			})
		}

		// -------------------------------------------------------
		// Accelerators / icons (stubs)
		// -------------------------------------------------------
		for _, fn := range []string{"CopyAcceleratorTableA", "CopyAcceleratorTableW",
			"CreateAcceleratorTableA", "LoadAcceleratorsA"} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(0); return 0
			})
		}
		for _, fn := range []string{"CreateCursor", "CreateIcon", "CreateIconFromResource",
			"CreateIconFromResourceEx", "LoadBitmapA", "LoadIconA", "LoadImageA",
			"CopyImage", "LookupIconIdFromDirectory", "LookupIconIdFromDirectoryEx",
			"PrivateExtractIconExA", "PrivateExtractIconExW",
			"PrivateExtractIconsA", "PrivateExtractIconsW"} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(0); return 0
			})
		}
		d.RegisterAutoStubHandler(user32, "LoadCursorFromFileA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x00010001); return 0
		})
		d.RegisterAutoStubHandler(user32, "LoadCursorFromFileW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x00010001); return 0
		})

		// -------------------------------------------------------
		// MDI / misc window management
		// -------------------------------------------------------
		for _, fn := range []string{"CreateMDIWindowA", "CreateMDIWindowW",
			"DefFrameProcA", "DefFrameProcW", "DefMDIChildProcA", "DefMDIChildProcW",
			"TranslateMDISysAccel"} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(0); return 0
			})
		}
		d.RegisterAutoStubHandler(user32, "DefWindowProcA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(user32, "CallWindowProcA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(user32, "CallWindowProcW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		for _, fn := range []string{"CallMsgFilter", "CallMsgFilterA", "CallMsgFilterW"} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(0); return 0
			})
		}
		d.RegisterAutoStubHandler(user32, "EnumThreadWindows", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(user32, "SwitchToThisWindow", func(ctx *ntapi.TrapContext) uint32 {
			return 0
		})
		d.RegisterAutoStubHandler(user32, "SetDoubleClickTime", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})

		// -------------------------------------------------------
		// WinHelp / string conversion helpers
		// -------------------------------------------------------
		for _, fn := range []string{"WinHelpA", "WinHelpW"} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(0); return 0
			})
		}
		for _, fn := range []string{"wvsprintfA", "wvsprintfW", "MB_GetString",
			"MBToWCSEx", "WCSToMBEx"} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(0); return 0
			})
		}
		for _, fn := range []string{"AlignRects", "BuildReasonArray", "DestroyReasons",
			"ReasonCodeNeedsBugID", "ReasonCodeNeedsComment", "RecordShutdownReason",
			"GetReasonTitleFromReasonCode", "DisplayExitWindowsWarnings"} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(0); return 0
			})
		}

		// -------------------------------------------------------
		// Internal / undocumented
		// -------------------------------------------------------
		for _, fn := range []string{"UserClientDllInitialize", "User32InitializeImmEntryTable",
			"ClientThreadSetup", "CtxInitUser32", "CreateSystemThreads",
			"InitializeLpkHooks", "InitializeWin32EntryTable",
			"UserHandleGrantAccess", "UserLpkPSMTextOut", "UserLpkTabbedTextOut",
			"UserRealizePalette", "UserRegisterWowHandlers",
			"UpdatePerUserSystemParameters", "Win32PoolAllocationStats",
			"AllowForegroundActivation", "DeviceEventWorker",
			"EnterReaderModeHelper", "GetAppCompatFlags", "GetAppCompatFlags2",
			"GetAltTabInfo", "GetAltTabInfoA", "GetAltTabInfoW",
			"GetInputDesktop", "GetInternalWindowPos", "SetInternalWindowPos",
			"GetProgmanWindow", "SetProgmanWindow", "GetShellWindow",
			"SetShellWindow", "SetShellWindowEx", "GetTaskmanWindow", "SetTaskmanWindow",
			"SetLogonNotifyWindow", "RegisterLogonProcess", "RegisterServicesProcess",
			"RegisterSystemThread", "RegisterTasklist", "RegisterMessagePumpHook",
			"UnregisterMessagePumpHook", "RegisterUserApiHook", "UnregisterUserApiHook",
			"SetConsoleReserveKeys", "SetDebugErrorLevel", "SetLastErrorEx",
			"SetDeskWallpaper", "SetKeyboardState", "SetMessageQueue",
			"SetProcessDefaultLayout", "GetProcessDefaultLayout",
			"SetWindowStationUser", "LoadLocalFonts", "LoadRemoteFonts",
			"KillSystemTimer", "SetSystemTimer",
			"ScrollChildren", "EndTask", "IsWinEventHookInstalled",
			"GetAltTabInfo", "EditWndProc",
			"ClientThreadSetup", "CsrBroadcastSystemMessageExW"} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(0); return 0
			})
		}
		for _, fn := range []string{"SetSysColors", "SetSysColorsTemp", "SetSystemCursor"} {
			fn := fn; _ = fn
			d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(1); return 0
			})
		}

		// DPI-aware functions (Win10+) - apps resolve at runtime via GetProcAddress.
		// Using RegisterDynamicHandler to make them discoverable.
		nextDynID := uint32(ntapi.DynExportIDBase)
		dpiStub96 := func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(96) // standard DPI
			return 0
		}
		d.RegisterDynamicHandler(mem, user32, "GetDpiForSystem", nextDynID, dpiStub96); nextDynID++
		d.RegisterDynamicHandler(mem, user32, "GetDpiForWindow", nextDynID, dpiStub96); nextDynID++
		d.RegisterDynamicHandler(mem, user32, "GetSystemMetricsForDpi", nextDynID, func(ctx *ntapi.TrapContext) uint32 {
			// Fall through to GetSystemMetrics behavior with standard DPI
			ctx.SetReturn(0)
			return 0
		}); nextDynID++
		d.RegisterDynamicHandler(mem, user32, "AdjustWindowRectExForDpi", nextDynID, func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		}); nextDynID++
		d.RegisterDynamicHandler(mem, user32, "SetThreadDpiAwarenessContext", nextDynID, func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(ctx.Arg(0)) // return previous context = same as requested
			return 0
		}); nextDynID++
		d.RegisterDynamicHandler(mem, user32, "GetWindowDpiAwarenessContext", nextDynID, func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0xFFFFFFFFFFFFFFFD) // DPI_AWARENESS_CONTEXT_SYSTEM_AWARE (-3)
			return 0
		}); nextDynID++
		d.RegisterDynamicHandler(mem, user32, "AreDpiAwarenessContextsEqual", nextDynID, func(ctx *ntapi.TrapContext) uint32 {
			if ctx.Arg(0) == ctx.Arg(1) { ctx.SetReturn(1) } else { ctx.SetReturn(0) }
			return 0
		}); nextDynID++
		d.RegisterDynamicHandler(mem, user32, "ChangeWindowMessageFilterEx", nextDynID, func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		}); nextDynID++
		d.RegisterDynamicHandler(mem, user32, "SetCoalescableTimer", nextDynID, func(ctx *ntapi.TrapContext) uint32 {
			// Delegate to SetTimer behavior - return a timer ID
			ctx.SetReturn(ctx.Arg(1)) // nIDEvent
			return 0
		}); nextDynID++
		_ = nextDynID
	}
	})
	delayHandlerRegistrars[len(delayHandlerRegistrars)-1]()

	// --- gdi32.dll ---
	delayHandlerRegistrars = append(delayHandlerRegistrars, func() {
	if gdi32, ok := synthByName["gdi32.dll"]; ok {
		ravelog.Logf("[gdi] registrar running: %d exports\n", len(gdi32.Exports))
		d.RegisterAutoStubHandler(gdi32, "CreateSolidBrush", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(gdiMgr.CreateSolidBrush(uint32(ctx.Arg(0))))
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "CreateHatchBrush", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(gdiMgr.CreateHatchBrush(int32(ctx.Arg(0)), uint32(ctx.Arg(1))))
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "CreatePen", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(gdiMgr.CreatePen(int32(ctx.Arg(0)), int32(ctx.Arg(1)), uint32(ctx.Arg(2))))
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "CreateFontIndirectW", func(ctx *ntapi.TrapContext) uint32 {
			lf := ctx.Arg(0)
			f := &gdi.Font{}
			if lf != 0 {
				v32, _ := mem.Read32(lf); f.Height = int32(v32)
				v32, _ = mem.Read32(lf + 4); f.Width = int32(v32)
				v32, _ = mem.Read32(lf + 16); f.Weight = int32(v32)
				v8, _ := mem.Read8(lf + 20); f.Italic = v8 != 0
				v8, _ = mem.Read8(lf + 21); f.Underline = v8 != 0
				v8, _ = mem.Read8(lf + 23); f.CharSet = v8
				// FaceName at offset 28 (LF_FACESIZE=32 UTF-16LE chars)
				f.FaceName = readGuestUTF16(lf + 28)
			}
			h := gdiMgr.CreateFont(f)
			ctx.SetReturn(h)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "CreateFontW", func(ctx *ntapi.TrapContext) uint32 {
			f := &gdi.Font{
				Height: int32(ctx.Arg(0)),
				Width:  int32(ctx.Arg(1)),
				Weight: int32(ctx.Arg(5)),
				Italic: ctx.Arg(6) != 0,
			}
			ctx.SetReturn(gdiMgr.CreateFont(f))
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "CreateCompatibleDC", func(ctx *ntapi.TrapContext) uint32 {
			hdcParent := ctx.Arg(0)
			h, memDC := gdiMgr.AllocMemDC()
			if parent := gdiMgr.GetDC(hdcParent); parent != nil {
				// Inherit parent DC properties (origin, clip, colours, surface).
				memDC.InheritFrom(parent)
			} else if gdiMgr.Screen != nil {
				// No parent → attach to screen surface directly (transparent mode).
				memDC.Target = gdiMgr.Screen
				memDC.IsScreen = true
			}
			callerRIP := uint64(0)
			if rr, ok := ctx.CPU.(ntapi.RegisterReader); ok {
				rsp := rr.ReadReg(4) // RSP
				callerRIP, _ = mem.Read64(rsp)
			}
			ravelog.Logf("[gdi] CreateCompatibleDC parent=0x%x → hdc=0x%x caller=0x%x\n", hdcParent, h, callerRIP)
			ctx.SetReturn(h)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "CreateCompatibleBitmap", func(ctx *ntapi.TrapContext) uint32 {
			h := gdiMgr.CreateCompatibleBitmap(int32(ctx.Arg(1)), int32(ctx.Arg(2)))
			callerRIP := uint64(0)
			var callers [8]uint64
			if rr, ok := ctx.CPU.(ntapi.RegisterReader); ok {
				rsp := rr.ReadReg(4)
				callerRIP, _ = mem.Read64(rsp)
				for i := range callers {
					callers[i], _ = mem.Read64(rsp + uint64(i*8))
				}
			}
			ravelog.Logf("[gdi] CreateCompatibleBitmap hdc=0x%x w=%d h=%d → 0x%x caller=0x%x stack=%x\n", ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), h, callerRIP, callers)
			ctx.SetReturn(h)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "CreateDIBSection", func(ctx *ntapi.TrapContext) uint32 {
			// BITMAPINFO at arg1; width/height at offset 4 and 8 (BITMAPINFOHEADER)
			pbi := ctx.Arg(1)
			w, h := int32(0), int32(0)
			if pbi != 0 {
				v32, _ := mem.Read32(pbi + 4); w = int32(v32)
				v32, _ = mem.Read32(pbi + 8); h = int32(v32)
				if h < 0 {
					h = -h
				}
			}
			ctx.SetReturn(gdiMgr.CreateDIBSection(w, h))
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "CreateDIBitmap", func(ctx *ntapi.TrapContext) uint32 {
			// hdc := ctx.Arg(0)
			lpbmih := ctx.Arg(1)
			// fdwInit := ctx.Arg(2)
			// lpbInit := ctx.Arg(3)
			// lpbmi := ctx.Arg(4)
			// fuUsage := ctx.Arg(5)
			var w, h int32
			if lpbmih != 0 {
				ww, _ := mem.Read32(lpbmih + 4)
				hh, _ := mem.Read32(lpbmih + 8)
				w = int32(ww)
				h = int32(hh)
				if h < 0 { h = -h }
			}
			if w <= 0 { w = 1 }
			if h <= 0 { h = 1 }
			ctx.SetReturn(gdiMgr.CreateDIBSection(w, h))
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "DeleteDC", func(ctx *ntapi.TrapContext) uint32 {
			gdiMgr.DeleteDC(ctx.Arg(0))
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "DeleteObject", func(ctx *ntapi.TrapContext) uint32 {
			gdiMgr.DeleteObject(ctx.Arg(0))
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "SelectObject", func(ctx *ntapi.TrapContext) uint32 {
			dc := ctx.Arg(0)
			obj := ctx.Arg(1)
			old := gdiMgr.SelectObject(dc, obj)
			ravelog.Logf("[gdi] SelectObject dc=0x%x obj=0x%x → old=0x%x\n", dc, obj, old)
			ctx.SetReturn(old)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GetStockObject", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(gdiMgr.GetStockObject(int(ctx.Arg(0))))
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GetObjectW", func(ctx *ntapi.TrapContext) uint32 {
			// Return LOGBRUSH or LOGFONT size for the object type
			h := ctx.Arg(0)
			obj := gdiMgr.GetObject(h)
			if obj == nil {
				ctx.SetReturn(0)
				return 0
			}
			pv := ctx.Arg(2)
			switch obj.Type {
			case gdi.ObjBrush:
				ctx.SetReturn(12) // sizeof(LOGBRUSH)
				if pv != 0 && obj.Brush != nil {
					ctx.Mem.Write32(pv, uint32(obj.Brush.Style))
					ctx.Mem.Write32(pv+4, obj.Brush.Color)
					ctx.Mem.Write32(pv+8, uint32(obj.Brush.Hatch))
				}
			case gdi.ObjBitmap:
				ctx.SetReturn(24) // sizeof(BITMAP)
				if pv != 0 && obj.Bitmap != nil {
					ctx.Mem.Write32(pv, 0)                    // bmType
					ctx.Mem.Write32(pv+4, uint32(obj.Bitmap.Width))
					ctx.Mem.Write32(pv+8, uint32(obj.Bitmap.Height))
					ctx.Mem.Write32(pv+12, uint32(obj.Bitmap.Width*4)) // bmWidthBytes
					ctx.Mem.Write16(pv+16, 1)                  // bmPlanes
					ctx.Mem.Write16(pv+18, 32)                 // bmBitsPixel
					ctx.Mem.Write32(pv+20, 0)                  // bmBits
				}
			default:
				ctx.SetReturn(0)
			}
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GetDeviceCaps", func(ctx *ntapi.TrapContext) uint32 {
			idx := ctx.Arg(1)
			val := uint64(0)
			switch idx {
			case 2:   val = 4    // TECHNOLOGY: DT_RASDISPLAY
			case 8:   val = 1920 // HORZRES
			case 10:  val = 1080 // VERTRES
			case 12:  val = 32   // BITSPIXEL
			case 14:  val = 1    // PLANES
			case 88:  val = 96   // LOGPIXELSX
			case 90:  val = 96   // LOGPIXELSY
			case 118: val = 1920 // DESKTOPHORZRES
			case 117: val = 1080 // DESKTOPVERTRES
			}
			ctx.SetReturn(val)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GetTextMetricsW", func(ctx *ntapi.TrapContext) uint32 {
			hdc := ctx.Arg(0)
			pTM := ctx.Arg(1)
			dc := getDC(hdc)
			f := dc.Font
			if f == nil {
				f = gdi.DefaultFont()
			}
			ravelog.Logf("[gdi] GetTextMetricsW dc=0x%x → h=%d asc=%d desc=%d avew=%d maxw=%d\n", hdc, f.CellHeight, f.Ascent, f.Descent, f.AveCharWidth, f.MaxCharWidth)
			if pTM != 0 {
				// TEXTMETRICW layout (Win32 x64, all int32 unless noted):
				// +0  tmHeight           = CellHeight
				// +4  tmAscent           = Ascent
				// +8  tmDescent          = Descent
				// +12 tmInternalLeading  = 0
				// +16 tmExternalLeading  = 0
				// +20 tmAveCharWidth     = AveCharWidth
				// +24 tmMaxCharWidth     = MaxCharWidth
				// +28 tmWeight           = FW_NORMAL=400
				// +32 tmOverhang         = 0
				// +36 tmDigitizedAspectX = 96 (DPI)
				// +40 tmDigitizedAspectY = 96 (DPI)
				// +44 tmFirstChar        WCHAR = 0x0020
				// +46 tmLastChar         WCHAR = 0x00FF
				// +48 tmDefaultChar      WCHAR = 0x003F ('?')
				// +50 tmBreakChar        WCHAR = 0x0020 (' ')
				// +52 tmItalic           BYTE
				// +53 tmUnderlined       BYTE
				// +54 tmStruckOut        BYTE
				// +55 tmPitchAndFamily   BYTE  = TMPF_FIXED_PITCH|FF_MODERN = 0x21
				// +56 tmCharSet          BYTE  = ANSI_CHARSET = 0
				weight := f.Weight; if weight == 0 { weight = 400 }
				italic := byte(0); if f.Italic { italic = 1 }
				underline := byte(0); if f.Underline { underline = 1 }
				ctx.Mem.Write32(pTM,    uint32(f.CellHeight))
				ctx.Mem.Write32(pTM+4,  uint32(f.Ascent))
				ctx.Mem.Write32(pTM+8,  uint32(f.Descent))
				ctx.Mem.Write32(pTM+12, 0)
				ctx.Mem.Write32(pTM+16, 0)
				ctx.Mem.Write32(pTM+20, uint32(f.AveCharWidth))
				ctx.Mem.Write32(pTM+24, uint32(f.MaxCharWidth))
				ctx.Mem.Write32(pTM+28, uint32(weight))
				ctx.Mem.Write32(pTM+32, 0)
				ctx.Mem.Write32(pTM+36, 96)
				ctx.Mem.Write32(pTM+40, 96)
				ctx.Mem.Write16(pTM+44, 0x0020) // tmFirstChar
				ctx.Mem.Write16(pTM+46, 0x00FF) // tmLastChar
				ctx.Mem.Write16(pTM+48, 0x003F) // tmDefaultChar '?'
				ctx.Mem.Write16(pTM+50, 0x0020) // tmBreakChar ' '
				ctx.Mem.Write8(pTM+52,  italic)
				ctx.Mem.Write8(pTM+53,  underline)
				ctx.Mem.Write8(pTM+54,  0)
				ctx.Mem.Write8(pTM+55,  0x01) // TMPF_FIXED_PITCH
				ctx.Mem.Write8(pTM+56,  0)    // ANSI_CHARSET
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GetTextExtentPoint32W", func(ctx *ntapi.TrapContext) uint32 {
			hdc := ctx.Arg(0)
			nLen := int32(ctx.Arg(2))
			pSize := ctx.Arg(3)
			dc := getDC(hdc)
			f := dc.Font
			if f == nil {
				f = gdi.DefaultFont()
			}
			if pSize != 0 {
				ctx.Mem.Write32(pSize,   uint32(nLen*f.AveCharWidth))
				ctx.Mem.Write32(pSize+4, uint32(f.CellHeight))
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GetTextExtentExPointW", func(ctx *ntapi.TrapContext) uint32 {
			hdc := ctx.Arg(0)
			nLen := int32(ctx.Arg(2))
			pSize := ctx.Arg(5)
			dc := getDC(hdc)
			f := dc.Font
			if f == nil {
				f = gdi.DefaultFont()
			}
			if pSize != 0 {
				ctx.Mem.Write32(pSize,   uint32(nLen*f.AveCharWidth))
				ctx.Mem.Write32(pSize+4, uint32(f.CellHeight))
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "SetBkMode", func(ctx *ntapi.TrapContext) uint32 {
			dc := getDC(ctx.Arg(0))
			prev := dc.BkMode
			dc.BkMode = int32(ctx.Arg(1))
			ctx.SetReturn(uint64(prev))
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "SetBkColor", func(ctx *ntapi.TrapContext) uint32 {
			dc := getDC(ctx.Arg(0))
			prev := dc.BkColor
			dc.BkColor = uint32(ctx.Arg(1))
			ravelog.Logf("[gdi] SetBkColor dc=0x%x color=0x%06x\n", ctx.Arg(0), ctx.Arg(1))
			ctx.SetReturn(uint64(prev))
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GetBkColor", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(uint64(getDC(ctx.Arg(0)).BkColor))
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "SetTextColor", func(ctx *ntapi.TrapContext) uint32 {
			dc := getDC(ctx.Arg(0))
			prev := dc.TextColor
			dc.TextColor = uint32(ctx.Arg(1))
			ctx.SetReturn(uint64(prev))
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GetTextColor", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(uint64(getDC(ctx.Arg(0)).TextColor))
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "SaveDC", func(ctx *ntapi.TrapContext) uint32 {
			dc := getDC(ctx.Arg(0))
			ctx.SetReturn(uint64(dc.Save()))
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "RestoreDC", func(ctx *ntapi.TrapContext) uint32 {
			dc := getDC(ctx.Arg(0))
			level := int(int32(ctx.Arg(1)))
			ok := dc.Restore(level)
			if ok { ctx.SetReturn(1) } else { ctx.SetReturn(0) }
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "SetViewportOrgEx", func(ctx *ntapi.TrapContext) uint32 {
			dc := getDC(ctx.Arg(0))
			dc.SetViewportOrg(int32(ctx.Arg(1)), int32(ctx.Arg(2)))
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "OffsetViewportOrgEx", func(ctx *ntapi.TrapContext) uint32 {
			dc := getDC(ctx.Arg(0))
			dc.OffsetViewportOrg(int32(ctx.Arg(1)), int32(ctx.Arg(2)))
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GetViewportOrgEx", func(ctx *ntapi.TrapContext) uint32 {
			dc := getDC(ctx.Arg(0))
			p := ctx.Arg(1)
			if p != 0 {
				ctx.Mem.Write32(p,   uint32(dc.OriginX))
				ctx.Mem.Write32(p+4, uint32(dc.OriginY))
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "TextOutW", func(ctx *ntapi.TrapContext) uint32 {
			if wlWindow == nil { ctx.SetReturn(1); return 0 }
			dc := getDC(ctx.Arg(0))
			x := int32(ctx.Arg(1))
			y := int32(ctx.Arg(2))
			lpStr := ctx.Arg(3)
			nLen := int(ctx.Arg(4))
			text := readGuestUTF16(lpStr)
			if nLen > 0 && nLen < len(text) { text = text[:nLen] }
			dc.TextOut(x, y, text, false)
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "ExtTextOutW", func(ctx *ntapi.TrapContext) uint32 {
			if wlWindow == nil { ctx.SetReturn(1); return 0 }
			dc := getDC(ctx.Arg(0))
			x := int32(ctx.Arg(1))
			y := int32(ctx.Arg(2))
			opts := uint32(ctx.Arg(3))
			lprc := ctx.Arg(4)
			lpStr := ctx.Arg(5)
			nLen := int(ctx.Arg(6))
			text := readGuestUTF16(lpStr)
			if nLen > 0 && nLen < len(text) { text = text[:nLen] }
			if lprc != 0 {
				rL, _ := mem.Read32(lprc); rT, _ := mem.Read32(lprc+4); rR, _ := mem.Read32(lprc+8); rB, _ := mem.Read32(lprc+12)
				if len(text) > 0 || opts&0x2 != 0 {
					ravelog.Logf("[gdi] ExtTextOut dc=0x%x ox=%d oy=%d x=%d y=%d opts=0x%x rc=(%d,%d,%d,%d) bk=0x%x text=%q\n",
						ctx.Arg(0), dc.OriginX, dc.OriginY, x, y, opts, rL, rT, rR, rB, dc.BkColor, text)
				}
				// ETO_OPAQUE (0x2): fill background rect
				if opts & 0x2 != 0 {
					dc.FillRect(int32(rL), int32(rT), int32(rR), int32(rB), dc.BkColor)
				}
				// ETO_CLIPPED (0x4): clip to rect
				if opts & 0x4 != 0 {
					// Temporarily tighten clip to rect (absolute coords)
					x0 := int32(rL) + dc.OriginX
					y0 := int32(rT) + dc.OriginY
					x1 := int32(rR) + dc.OriginX
					y1 := int32(rB) + dc.OriginY
					oldX0, oldY0, oldX1, oldY1 := dc.ClipX0, dc.ClipY0, dc.ClipX1, dc.ClipY1
					// Intersect with existing clip
					if oldX1 > oldX0 {
						if x0 < oldX0 { x0 = oldX0 }
						if y0 < oldY0 { y0 = oldY0 }
						if x1 > oldX1 { x1 = oldX1 }
						if y1 > oldY1 { y1 = oldY1 }
					}
					dc.ClipX0, dc.ClipY0, dc.ClipX1, dc.ClipY1 = x0, y0, x1, y1
					if len(text) > 0 { dc.TextOut(x, y, text, false) }
					dc.ClipX0, dc.ClipY0, dc.ClipX1, dc.ClipY1 = oldX0, oldY0, oldX1, oldY1
					ctx.SetReturn(1)
					return 0
				}
			}
			if len(text) > 0 {
				dc.TextOut(x, y, text, false)
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "BitBlt", func(ctx *ntapi.TrapContext) uint32 {
			if wlWindow == nil { ctx.SetReturn(1); return 0 }
			hdcDst := ctx.Arg(0)
			dx := int32(ctx.Arg(1))
			dy := int32(ctx.Arg(2))
			w  := int32(ctx.Arg(3))
			h  := int32(ctx.Arg(4))
			hdcSrc := ctx.Arg(5)
			sx := int32(ctx.Arg(6))
			sy := int32(ctx.Arg(7))
			rop3 := uint32(ctx.Arg(8))
			dst := getDC(hdcDst)
			src := gdiMgr.GetDC(hdcSrc)
			if dst != nil {
				dstO := fmt.Sprintf("ox=%d,oy=%d", dst.OriginX, dst.OriginY)
				srcO := "nil"
				if src != nil { srcO = fmt.Sprintf("ox=%d,oy=%d", src.OriginX, src.OriginY) }
				ravelog.Logf("[gdi] BitBlt dst=0x%x(%s) dx=%d dy=%d w=%d h=%d src=0x%x(%s) sx=%d sy=%d rop=0x%x\n",
					hdcDst, dstO, dx, dy, w, h, hdcSrc, srcO, sx, sy, rop3)
			}
			dst.BitBlt(dx, dy, w, h, src, sx, sy, rop3)
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "StretchBlt", func(ctx *ntapi.TrapContext) uint32 {
			if wlWindow == nil { ctx.SetReturn(1); return 0 }
			hdcDst := ctx.Arg(0)
			dx := int32(ctx.Arg(1)); dy := int32(ctx.Arg(2))
			dw := int32(ctx.Arg(3)); dh := int32(ctx.Arg(4))
			hdcSrc := ctx.Arg(5)
			sx := int32(ctx.Arg(6)); sy := int32(ctx.Arg(7))
			sw := int32(ctx.Arg(8)); sh := int32(ctx.Arg(9))
			rop3 := uint32(ctx.Arg(10))
			dst := getDC(hdcDst)
			src := gdiMgr.GetDC(hdcSrc)
			dst.StretchBlt(dx, dy, dw, dh, src, sx, sy, sw, sh, rop3)
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "PatBlt", func(ctx *ntapi.TrapContext) uint32 {
			if wlWindow == nil { ctx.SetReturn(1); return 0 }
			dc := getDC(ctx.Arg(0))
			x := int32(ctx.Arg(1))
			y := int32(ctx.Arg(2))
			w := int32(ctx.Arg(3))
			h := int32(ctx.Arg(4))
			rop := ctx.Arg(5)
			ravelog.Logf("[gdi] PatBlt dc=0x%x x=%d y=%d w=%d h=%d rop=0x%x\n", ctx.Arg(0), x, y, w, h, rop)
			switch rop & 0xFF0000 {
			case 0x000000: // BLACKNESS
				dc.FillRect(x, y, x+w, y+h, 0x000000)
			case 0xFF0000: // WHITENESS
				dc.FillRect(x, y, x+w, y+h, 0xFFFFFF)
			case 0x5A0000: // PATINVERT - XOR; approximate as solid fill
				brushColor := uint32(0xF0F0F0)
				if dc.Brush != nil && dc.Brush.Style == 0 {
					brushColor = dc.Brush.Color
				}
				dc.FillRect(x, y, x+w, y+h, brushColor^0xFFFFFF)
			default: // PATCOPY and others - fill with brush
				brushColor := uint32(0xF0F0F0)
				if dc.Brush != nil && dc.Brush.Style == 0 {
					brushColor = dc.Brush.Color
				}
				dc.FillRect(x, y, x+w, y+h, brushColor)
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "FillRect", func(ctx *ntapi.TrapContext) uint32 {
			if wlWindow == nil { ctx.SetReturn(1); return 0 }
			lpRect := ctx.Arg(1)
			if lpRect == 0 { ctx.SetReturn(1); return 0 }
			dc := getDC(ctx.Arg(0))
			left, _ := mem.Read32(lpRect)
			top, _ := mem.Read32(lpRect + 4)
			right, _ := mem.Read32(lpRect + 8)
			bottom, _ := mem.Read32(lpRect + 12)
			color := gdiMgr.BrushColor(ctx.Arg(2), sysColors)
			ravelog.Logf("[gdi] FillRect dc=0x%x (%d,%d,%d,%d) color=0x%06x\n", ctx.Arg(0), left, top, right, bottom, color)
			dc.FillRect(int32(left), int32(top), int32(right), int32(bottom), color)
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "Rectangle", func(ctx *ntapi.TrapContext) uint32 {
			if wlWindow == nil { ctx.SetReturn(1); return 0 }
			dc := getDC(ctx.Arg(0))
			dc.Rectangle(int32(ctx.Arg(1)), int32(ctx.Arg(2)), int32(ctx.Arg(3)), int32(ctx.Arg(4)))
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "MoveToEx", func(ctx *ntapi.TrapContext) uint32 {
			dc := getDC(ctx.Arg(0))
			dc.MoveTo(int32(ctx.Arg(1)), int32(ctx.Arg(2)))
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "LineTo", func(ctx *ntapi.TrapContext) uint32 {
			if wlWindow == nil { ctx.SetReturn(1); return 0 }
			dc := getDC(ctx.Arg(0))
			dc.LineTo(int32(ctx.Arg(1)), int32(ctx.Arg(2)))
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "Ellipse", func(ctx *ntapi.TrapContext) uint32 {
			if wlWindow == nil { ctx.SetReturn(1); return 0 }
			dc := getDC(ctx.Arg(0))
			dc.Ellipse(int32(ctx.Arg(1)), int32(ctx.Arg(2)), int32(ctx.Arg(3)), int32(ctx.Arg(4)))
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "StretchDIBits", func(ctx *ntapi.TrapContext) uint32 {
			if wlWindow == nil { ctx.SetReturn(uint64(0xFFFFFFFF)); return 0 }
			dc  := getDC(ctx.Arg(0))
			dx  := int32(ctx.Arg(1));  dy  := int32(ctx.Arg(2))
			dw  := int32(ctx.Arg(3));  dh  := int32(ctx.Arg(4))
			sx  := int32(ctx.Arg(5));  sy  := int32(ctx.Arg(6))
			sw  := int32(ctx.Arg(7));  sh  := int32(ctx.Arg(8))
			pBits := ctx.Arg(9)
			pBMI  := ctx.Arg(10)
			// arg11 = iUsage (ignored - we treat as DIB_RGB_COLORS)
			// arg12 = rop (ignored - SRCCOPY assumed)
			srcW, srcH, bitCount, _, ct, _ := readDIBInfo(pBMI)
			pixData := readDIBPixels(pBits, srcW, srcH, bitCount)
			if pixData == nil || dc.Target == nil {
				ctx.SetReturn(uint64(dh)); return 0
			}
			adx := dx + dc.OriginX
			ady := dy + dc.OriginY
			dc.Target.BlitDIB(adx, ady, dw, dh, pixData, srcW, srcH, bitCount, ct, sx, sy, sw, sh)
			ctx.SetReturn(uint64(dh))
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "SetDIBitsToDevice", func(ctx *ntapi.TrapContext) uint32 {
			if wlWindow == nil { ctx.SetReturn(0); return 0 }
			dc    := getDC(ctx.Arg(0))
			dx    := int32(ctx.Arg(1));  dy    := int32(ctx.Arg(2))
			sw    := int32(ctx.Arg(3));  sh    := int32(ctx.Arg(4))
			sx    := int32(ctx.Arg(5));  sy    := int32(ctx.Arg(6))
			// arg7 = StartScan (first scan line to copy)
			// arg8 = NumScans (number of scan lines)
			pBits := ctx.Arg(9)
			pBMI  := ctx.Arg(10)
			srcW, srcH, bitCount, _, ct, _ := readDIBInfo(pBMI)
			pixData := readDIBPixels(pBits, srcW, srcH, bitCount)
			if pixData == nil || dc.Target == nil {
				ctx.SetReturn(uint64(sh)); return 0
			}
			adx := dx + dc.OriginX
			ady := dy + dc.OriginY
			// No scaling: dw=sw, dh=sh
			dc.Target.BlitDIB(adx, ady, sw, sh, pixData, srcW, srcH, bitCount, ct, sx, sy, sw, sh)
			ctx.SetReturn(uint64(sh))
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "SetMapMode", func(ctx *ntapi.TrapContext) uint32 {
			dc := getDC(ctx.Arg(0))
			prev := dc.MapMode
			if prev == 0 { prev = 1 }
			dc.MapMode = int32(ctx.Arg(1))
			if dc.MapMode == 0 { dc.MapMode = 1 }
			ctx.SetReturn(uint64(prev))
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GetMapMode", func(ctx *ntapi.TrapContext) uint32 {
			dc := getDC(ctx.Arg(0))
			mm := dc.MapMode
			if mm == 0 { mm = 1 }
			ctx.SetReturn(uint64(mm))
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "SetTextAlign", func(ctx *ntapi.TrapContext) uint32 {
			dc := getDC(ctx.Arg(0))
			prev := dc.TextAlign
			dc.TextAlign = int32(ctx.Arg(1))
			ctx.SetReturn(uint64(uint32(prev)))
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GetTextAlign", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(uint64(uint32(getDC(ctx.Arg(0)).TextAlign)))
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "SetTextCharacterExtra", func(ctx *ntapi.TrapContext) uint32 {
			dc := getDC(ctx.Arg(0))
			prev := dc.CharExtra
			dc.CharExtra = int32(ctx.Arg(1))
			ctx.SetReturn(uint64(uint32(prev)))
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GetTextCharacterExtra", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(uint64(uint32(getDC(ctx.Arg(0)).CharExtra)))
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "SetStretchBltMode", func(ctx *ntapi.TrapContext) uint32 {
			dc := getDC(ctx.Arg(0))
			prev := dc.StretchBltMode
			if prev == 0 { prev = 1 }
			dc.StretchBltMode = int32(ctx.Arg(1))
			ctx.SetReturn(uint64(uint32(prev)))
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GetStretchBltMode", func(ctx *ntapi.TrapContext) uint32 {
			dc := getDC(ctx.Arg(0))
			m := dc.StretchBltMode
			if m == 0 { m = 1 }
			ctx.SetReturn(uint64(uint32(m)))
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "SetROP2", func(ctx *ntapi.TrapContext) uint32 {
			dc := getDC(ctx.Arg(0))
			prev := dc.ROP2
			if prev == 0 { prev = 13 }
			dc.ROP2 = int32(ctx.Arg(1))
			ctx.SetReturn(uint64(uint32(prev)))
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GetROP2", func(ctx *ntapi.TrapContext) uint32 {
			dc := getDC(ctx.Arg(0))
			r := dc.ROP2
			if r == 0 { r = 13 }
			ctx.SetReturn(uint64(uint32(r)))
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "SetArcDirection", func(ctx *ntapi.TrapContext) uint32 {
			dc := getDC(ctx.Arg(0))
			prev := dc.ArcDir
			if prev == 0 { prev = 1 }
			dc.ArcDir = int32(ctx.Arg(1))
			ctx.SetReturn(uint64(uint32(prev)))
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GetArcDirection", func(ctx *ntapi.TrapContext) uint32 {
			dc := getDC(ctx.Arg(0))
			d2 := dc.ArcDir
			if d2 == 0 { d2 = 1 }
			ctx.SetReturn(uint64(uint32(d2)))
			return 0
		})
		// --- Region functions ---
		d.RegisterAutoStubHandler(gdi32, "CreateRectRgn", func(ctx *ntapi.TrapContext) uint32 {
			h := gdiMgr.CreateRectRgn(int32(ctx.Arg(0)), int32(ctx.Arg(1)), int32(ctx.Arg(2)), int32(ctx.Arg(3)))
			ctx.SetReturn(h)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "CreateRectRgnIndirect", func(ctx *ntapi.TrapContext) uint32 {
			p := ctx.Arg(0)
			var l, t, r, b int32
			if p != 0 {
				v, _ := mem.Read32(p);   l = int32(v)
				v, _ = mem.Read32(p+4);  t = int32(v)
				v, _ = mem.Read32(p+8);  r = int32(v)
				v, _ = mem.Read32(p+12); b = int32(v)
			}
			ctx.SetReturn(gdiMgr.CreateRectRgn(l, t, r, b))
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "CreateEllipticRgn", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(gdiMgr.CreateEllipticRgn(int32(ctx.Arg(0)), int32(ctx.Arg(1)), int32(ctx.Arg(2)), int32(ctx.Arg(3))))
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "CreateEllipticRgnIndirect", func(ctx *ntapi.TrapContext) uint32 {
			p := ctx.Arg(0)
			var l, t, r, b int32
			if p != 0 {
				v, _ := mem.Read32(p);   l = int32(v)
				v, _ = mem.Read32(p+4);  t = int32(v)
				v, _ = mem.Read32(p+8);  r = int32(v)
				v, _ = mem.Read32(p+12); b = int32(v)
			}
			ctx.SetReturn(gdiMgr.CreateEllipticRgn(l, t, r, b))
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "CreateRoundRectRgn", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(gdiMgr.CreateRoundRectRgn(int32(ctx.Arg(0)), int32(ctx.Arg(1)), int32(ctx.Arg(2)), int32(ctx.Arg(3)), int32(ctx.Arg(4)), int32(ctx.Arg(5))))
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "SetRectRgn", func(ctx *ntapi.TrapContext) uint32 {
			ok := gdiMgr.SetRectRgn(ctx.Arg(0), int32(ctx.Arg(1)), int32(ctx.Arg(2)), int32(ctx.Arg(3)), int32(ctx.Arg(4)))
			if ok { ctx.SetReturn(1) } else { ctx.SetReturn(0) }
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "CombineRgn", func(ctx *ntapi.TrapContext) uint32 {
			result := gdiMgr.CombineRgn(ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), int(ctx.Arg(3)))
			ctx.SetReturn(uint64(result))
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GetRgnBox", func(ctx *ntapi.TrapContext) uint32 {
			p := ctx.Arg(1)
			var bounds [4]int32
			result := gdiMgr.GetRgnBox(ctx.Arg(0), &bounds)
			if p != 0 {
				ctx.Mem.Write32(p,    uint32(bounds[0]))
				ctx.Mem.Write32(p+4,  uint32(bounds[1]))
				ctx.Mem.Write32(p+8,  uint32(bounds[2]))
				ctx.Mem.Write32(p+12, uint32(bounds[3]))
			}
			ctx.SetReturn(uint64(result))
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "SelectClipRgn", func(ctx *ntapi.TrapContext) uint32 {
			result := gdiMgr.SelectClipRgn(ctx.Arg(0), ctx.Arg(1))
			ctx.SetReturn(uint64(result))
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "ExtSelectClipRgn", func(ctx *ntapi.TrapContext) uint32 {
			// mode arg(2): RGN_AND=1, RGN_OR=2, RGN_XOR=3, RGN_DIFF=4, RGN_COPY=5
			result := gdiMgr.SelectClipRgn(ctx.Arg(0), ctx.Arg(1))
			ctx.SetReturn(uint64(result))
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "OffsetRgn", func(ctx *ntapi.TrapContext) uint32 {
			hRgn := ctx.Arg(0)
			xOffset := int32(ctx.Arg(1))
			yOffset := int32(ctx.Arg(2))
			rgn := gdiMgr.GetRegion(hRgn)
			if rgn != nil {
				rgn.X0 += xOffset; rgn.Y0 += yOffset
				rgn.X1 += xOffset; rgn.Y1 += yOffset
				ctx.SetReturn(1) // SIMPLEREGION
			} else {
				ctx.SetReturn(0) // ERROR
			}
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GetClipRgn", func(ctx *ntapi.TrapContext) uint32 {
			dc := getDC(ctx.Arg(0))
			hrgn := ctx.Arg(1)
			if dc.ClipRgnHandle != 0 && hrgn != 0 {
				// Copy clip region bounds to the destination hrgn
				if src := gdiMgr.GetRegion(dc.ClipRgnHandle); src != nil {
					gdiMgr.SetRectRgn(hrgn, src.X0, src.Y0, src.X1, src.Y1)
				}
				ctx.SetReturn(1)
			} else {
				ctx.SetReturn(0)
			}
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GetClipBox", func(ctx *ntapi.TrapContext) uint32 {
			dc := getDC(ctx.Arg(0))
			p := ctx.Arg(1)
			if p != 0 {
				// Return clip rect in client (non-origin-offset) coords
				l := dc.ClipX0 - dc.OriginX
				t := dc.ClipY0 - dc.OriginY
				r := dc.ClipX1 - dc.OriginX
				b := dc.ClipY1 - dc.OriginY
				if dc.ClipX1 == 0 && dc.ClipY1 == 0 {
					// No clip set - return DC extents
					if dc.Target != nil {
						r, b = dc.Target.Width, dc.Target.Height
					}
				}
				ctx.Mem.Write32(p,    uint32(l))
				ctx.Mem.Write32(p+4,  uint32(t))
				ctx.Mem.Write32(p+8,  uint32(r))
				ctx.Mem.Write32(p+12, uint32(b))
			}
			ctx.SetReturn(2) // SIMPLEREGION
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "IntersectClipRect", func(ctx *ntapi.TrapContext) uint32 {
			dc := getDC(ctx.Arg(0))
			l := int32(ctx.Arg(1)) + dc.OriginX
			t := int32(ctx.Arg(2)) + dc.OriginY
			r := int32(ctx.Arg(3)) + dc.OriginX
			b := int32(ctx.Arg(4)) + dc.OriginY
			if dc.ClipX1 > dc.ClipX0 {
				if l < dc.ClipX0 { l = dc.ClipX0 }
				if t < dc.ClipY0 { t = dc.ClipY0 }
				if r > dc.ClipX1 { r = dc.ClipX1 }
				if b > dc.ClipY1 { b = dc.ClipY1 }
			}
			dc.ClipX0, dc.ClipY0, dc.ClipX1, dc.ClipY1 = l, t, r, b
			if l >= r || t >= b {
				ctx.SetReturn(1) // NULLREGION
			} else {
				ctx.SetReturn(2) // SIMPLEREGION
			}
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "ExcludeClipRect", func(ctx *ntapi.TrapContext) uint32 {
			// ExcludeClipRect: subtract (left,top,right,bottom) from current clip.
			// Since our clip is always rectangular, we can only handle the case where
			// the exclusion covers a full edge of the current clip (shrink from one side).
			// Other cases fall back to SIMPLEREGION (clip unchanged).
			dc := getDC(ctx.Arg(0))
			el := int32(ctx.Arg(1)) + dc.OriginX
			et := int32(ctx.Arg(2)) + dc.OriginY
			er := int32(ctx.Arg(3)) + dc.OriginX
			eb := int32(ctx.Arg(4)) + dc.OriginY
			// Use full-surface clip if no clip set yet
			cl, ct, cr, cb := dc.ClipX0, dc.ClipY0, dc.ClipX1, dc.ClipY1
			if cl == 0 && cr == 0 && ct == 0 && cb == 0 {
				if dc.Target != nil {
					cr = dc.Target.Width
					cb = dc.Target.Height
				}
			}
			// Check if exclude rect covers a full edge → shrink clip
			if el <= cl && er >= cr { // full width
				if et <= ct { ct = eb }      // top edge excluded
				if eb >= cb { cb = et }      // bottom edge excluded
			} else if et <= ct && eb >= cb { // full height
				if el <= cl { cl = er }      // left edge excluded
				if er >= cr { cr = el }      // right edge excluded
			}
			if cl >= cr || ct >= cb {
				dc.ClipX0, dc.ClipY0, dc.ClipX1, dc.ClipY1 = 0, 0, 0, 0
				ctx.SetReturn(1) // NULLREGION
				return 0
			}
			dc.ClipX0, dc.ClipY0, dc.ClipX1, dc.ClipY1 = cl, ct, cr, cb
			ctx.SetReturn(2) // SIMPLEREGION
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "OffsetClipRgn", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(2) // SIMPLEREGION
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "PtInRegion", func(ctx *ntapi.TrapContext) uint32 {
			rgn := gdiMgr.GetRegion(ctx.Arg(0))
			x, y := int32(ctx.Arg(1)), int32(ctx.Arg(2))
			if rgn != nil && x >= rgn.X0 && x < rgn.X1 && y >= rgn.Y0 && y < rgn.Y1 {
				ctx.SetReturn(1)
			} else {
				ctx.SetReturn(0)
			}
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "RectInRegion", func(ctx *ntapi.TrapContext) uint32 {
			rgn := gdiMgr.GetRegion(ctx.Arg(0))
			p := ctx.Arg(1)
			if rgn != nil && p != 0 {
				l, _ := mem.Read32(p); t, _ := mem.Read32(p+4); r, _ := mem.Read32(p+8); b, _ := mem.Read32(p+12)
				if int32(r) > rgn.X0 && int32(l) < rgn.X1 && int32(b) > rgn.Y0 && int32(t) < rgn.Y1 {
					ctx.SetReturn(1); return 0
				}
			}
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "FillRgn", func(ctx *ntapi.TrapContext) uint32 {
			if wlWindow == nil { ctx.SetReturn(1); return 0 }
			dc := getDC(ctx.Arg(0))
			rgn := gdiMgr.GetRegion(ctx.Arg(1))
			hbr := ctx.Arg(2)
			color := gdiMgr.BrushColor(hbr, sysColors)
			if rgn != nil {
				dc.FillRect(rgn.X0, rgn.Y0, rgn.X1, rgn.Y1, color)
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "FrameRgn", func(ctx *ntapi.TrapContext) uint32 {
			if wlWindow == nil { ctx.SetReturn(1); return 0 }
			dc := getDC(ctx.Arg(0))
			rgn := gdiMgr.GetRegion(ctx.Arg(1))
			hbr := ctx.Arg(2)
			color := gdiMgr.BrushColor(hbr, sysColors)
			if rgn != nil {
				dc.DrawBorder(rgn.X0, rgn.Y0, rgn.X1, rgn.Y1, color)
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "InvertRgn", func(ctx *ntapi.TrapContext) uint32 {
			if wlWindow == nil { ctx.SetReturn(1); return 0 }
			dc := getDC(ctx.Arg(0))
			rgn := gdiMgr.GetRegion(ctx.Arg(1))
			if rgn != nil {
				dc.InvertRect(rgn.X0, rgn.Y0, rgn.X1, rgn.Y1)
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "PaintRgn", func(ctx *ntapi.TrapContext) uint32 {
			if wlWindow == nil { ctx.SetReturn(1); return 0 }
			dc := getDC(ctx.Arg(0))
			rgn := gdiMgr.GetRegion(ctx.Arg(1))
			if rgn != nil {
				dc.FillRectBrush(rgn.X0, rgn.Y0, rgn.X1, rgn.Y1)
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "PathToRegion", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(gdiMgr.CreateRectRgn(0, 0, 0, 0))
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "EqualRgn", func(ctx *ntapi.TrapContext) uint32 {
			r1 := gdiMgr.GetRegion(ctx.Arg(0))
			r2 := gdiMgr.GetRegion(ctx.Arg(1))
			if r1 != nil && r2 != nil && r1.X0 == r2.X0 && r1.Y0 == r2.Y0 && r1.X1 == r2.X1 && r1.Y1 == r2.Y1 {
				ctx.SetReturn(1)
			} else {
				ctx.SetReturn(0)
			}
			return 0
		})
		// --- Window coord mapping ---
		d.RegisterAutoStubHandler(gdi32, "SetWindowOrgEx", func(ctx *ntapi.TrapContext) uint32 {
			dc := getDC(ctx.Arg(0))
			p := ctx.Arg(3)
			if p != 0 {
				ctx.Mem.Write32(p,   uint32(dc.WindowOrgX))
				ctx.Mem.Write32(p+4, uint32(dc.WindowOrgY))
			}
			dc.WindowOrgX = int32(ctx.Arg(1))
			dc.WindowOrgY = int32(ctx.Arg(2))
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GetWindowOrgEx", func(ctx *ntapi.TrapContext) uint32 {
			dc := getDC(ctx.Arg(0))
			p := ctx.Arg(1)
			if p != 0 {
				ctx.Mem.Write32(p,   uint32(dc.WindowOrgX))
				ctx.Mem.Write32(p+4, uint32(dc.WindowOrgY))
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "SetWindowExtEx", func(ctx *ntapi.TrapContext) uint32 {
			dc := getDC(ctx.Arg(0))
			p := ctx.Arg(3)
			if p != 0 {
				ctx.Mem.Write32(p,   uint32(dc.WindowExtX))
				ctx.Mem.Write32(p+4, uint32(dc.WindowExtY))
			}
			dc.WindowExtX = int32(ctx.Arg(1))
			dc.WindowExtY = int32(ctx.Arg(2))
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GetWindowExtEx", func(ctx *ntapi.TrapContext) uint32 {
			dc := getDC(ctx.Arg(0))
			p := ctx.Arg(1)
			if p != 0 {
				ex := dc.WindowExtX; if ex == 0 { ex = 1 }
				ey := dc.WindowExtY; if ey == 0 { ey = 1 }
				ctx.Mem.Write32(p,   uint32(ex))
				ctx.Mem.Write32(p+4, uint32(ey))
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "SetViewportExtEx", func(ctx *ntapi.TrapContext) uint32 {
			dc := getDC(ctx.Arg(0))
			p := ctx.Arg(3)
			if p != 0 {
				ctx.Mem.Write32(p,   uint32(dc.ViewportExtX))
				ctx.Mem.Write32(p+4, uint32(dc.ViewportExtY))
			}
			dc.ViewportExtX = int32(ctx.Arg(1))
			dc.ViewportExtY = int32(ctx.Arg(2))
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GetViewportExtEx", func(ctx *ntapi.TrapContext) uint32 {
			dc := getDC(ctx.Arg(0))
			p := ctx.Arg(1)
			if p != 0 {
				ex := dc.ViewportExtX; if ex == 0 { ex = 1 }
				ey := dc.ViewportExtY; if ey == 0 { ey = 1 }
				ctx.Mem.Write32(p,   uint32(ex))
				ctx.Mem.Write32(p+4, uint32(ey))
			}
			ctx.SetReturn(1)
			return 0
		})
		// RectVisible: returns TRUE if any part of rect lies within the DC's clip region.
		// ReactOS: NtGdiRectVisible → GreRectVisible in win32ss/gdi/ntgdi/cliprgn.c
		d.RegisterAutoStubHandler(gdi32, "RectVisible", func(ctx *ntapi.TrapContext) uint32 {
			dc := getDC(ctx.Arg(0))
			p := ctx.Arg(1)
			if p == 0 { ctx.SetReturn(1); return 0 }
			rL, _ := mem.Read32(p);   rT, _ := mem.Read32(p+4)
			rR, _ := mem.Read32(p+8); rB, _ := mem.Read32(p+12)
			if int32(rR) <= int32(rL) || int32(rB) <= int32(rT) { ctx.SetReturn(0); return 0 }
			// Convert logical (client) rect to screen (device) coords
			sl := int32(rL) + dc.OriginX; st := int32(rT) + dc.OriginY
			sr := int32(rR) + dc.OriginX; sb := int32(rB) + dc.OriginY
			// If clip not set, the whole surface is visible
			if dc.ClipX1 <= dc.ClipX0 && dc.ClipY1 <= dc.ClipY0 {
				ctx.SetReturn(1); return 0
			}
			// Check overlap
			if sr <= dc.ClipX0 || sl >= dc.ClipX1 || sb <= dc.ClipY0 || st >= dc.ClipY1 {
				ctx.SetReturn(0); return 0
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "OffsetWindowOrgEx", func(ctx *ntapi.TrapContext) uint32 {
			dc := getDC(ctx.Arg(0))
			p := ctx.Arg(3)
			if p != 0 {
				ctx.Mem.Write32(p,   uint32(dc.WindowOrgX))
				ctx.Mem.Write32(p+4, uint32(dc.WindowOrgY))
			}
			dc.WindowOrgX += int32(ctx.Arg(1))
			dc.WindowOrgY += int32(ctx.Arg(2))
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "SetBrushOrgEx", func(ctx *ntapi.TrapContext) uint32 {
			// Brush origin affects pattern fill alignment - no-op for solid brushes.
			p := ctx.Arg(3)
			if p != 0 {
				ctx.Mem.Write32(p,   0)
				ctx.Mem.Write32(p+4, 0)
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "LPtoDP", func(ctx *ntapi.TrapContext) uint32 {
			// In MM_TEXT mode, logical == device, so no-op
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "DPtoLP", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "ScaleWindowExtEx", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "ScaleViewportExtEx", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "SetGraphicsMode", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // GM_COMPATIBLE
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GetGraphicsMode", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // GM_COMPATIBLE
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "SetWorldTransform", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GetWorldTransform", func(ctx *ntapi.TrapContext) uint32 {
			// Return identity XFORM
			p := ctx.Arg(1)
			if p != 0 {
				// XFORM: eM11=1.0, eM12=0, eM21=0, eM22=1.0, eDx=0, eDy=0 (6 floats)
				one := uint32(0x3F800000) // 1.0f
				ctx.Mem.Write32(p,    one)
				ctx.Mem.Write32(p+4,  0)
				ctx.Mem.Write32(p+8,  0)
				ctx.Mem.Write32(p+12, one)
				ctx.Mem.Write32(p+16, 0)
				ctx.Mem.Write32(p+20, 0)
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "ModifyWorldTransform", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "CombineTransform", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		// --- Text/font queries ---
		d.RegisterAutoStubHandler(gdi32, "GetTextFaceW", func(ctx *ntapi.TrapContext) uint32 {
			dc := getDC(ctx.Arg(0))
			nCount := int(ctx.Arg(1))
			pFace := ctx.Arg(2)
			faceName := "Courier New"
			if dc.Font != nil && dc.Font.FaceName != "" {
				faceName = dc.Font.FaceName
			}
			if pFace != 0 && nCount > 0 {
				runes := []rune(faceName)
				n := len(runes)
				if n >= nCount { n = nCount - 1 }
				for i := 0; i < n; i++ {
					ctx.Mem.Write16(pFace+uint64(i)*2, uint16(runes[i]))
				}
				ctx.Mem.Write16(pFace+uint64(n)*2, 0)
				ctx.SetReturn(uint64(n))
			} else {
				ctx.SetReturn(uint64(len([]rune(faceName)) + 1))
			}
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GetCharWidth32W", func(ctx *ntapi.TrapContext) uint32 {
			hdc := ctx.Arg(0)
			first := int(ctx.Arg(1))
			last := int(ctx.Arg(2))
			pBuf := ctx.Arg(3)
			dc := getDC(hdc)
			f := dc.Font
			if f == nil { f = gdi.DefaultFont() }
			charW := f.AveCharWidth
			if pBuf != 0 {
				for i := first; i <= last; i++ {
					ctx.Mem.Write32(pBuf+uint64(i-first)*4, uint32(charW))
				}
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GetCharWidthW", func(ctx *ntapi.TrapContext) uint32 {
			hdc := ctx.Arg(0)
			first := int(ctx.Arg(1))
			last := int(ctx.Arg(2))
			pBuf := ctx.Arg(3)
			dc := getDC(hdc)
			f := dc.Font
			if f == nil { f = gdi.DefaultFont() }
			charW := f.AveCharWidth
			if pBuf != 0 {
				for i := first; i <= last; i++ {
					ctx.Mem.Write32(pBuf+uint64(i-first)*4, uint32(charW))
				}
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GetCharABCWidthsW", func(ctx *ntapi.TrapContext) uint32 {
			hdc := ctx.Arg(0)
			first := int(ctx.Arg(1))
			last := int(ctx.Arg(2))
			pBuf := ctx.Arg(3)
			dc := getDC(hdc)
			f := dc.Font
			if f == nil { f = gdi.DefaultFont() }
			charW := f.AveCharWidth
			if pBuf != 0 {
				for i := first; i <= last; i++ {
					off := pBuf + uint64(i-first)*12
					ctx.Mem.Write32(off,   0)                // abcA
					ctx.Mem.Write32(off+4, uint32(charW))    // abcB
					ctx.Mem.Write32(off+8, 0)                // abcC
				}
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GetCharABCWidthsFloatW", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GetCharWidthFloatW", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GetGlyphIndicesW", func(ctx *ntapi.TrapContext) uint32 {
			// Copy input wchar indices as-is (identity mapping)
			pStr := ctx.Arg(1)
			n := int(ctx.Arg(2))
			pGI := ctx.Arg(3)
			flags := ctx.Arg(4)
			if pStr != 0 && pGI != 0 {
				for i := 0; i < n; i++ {
					ch, _ := mem.Read16(pStr + uint64(i)*2)
					gi := ch
					if flags == 1 && (ch < 0x20 || ch > 0x7E) { gi = 0xFFFF }
					ctx.Mem.Write16(pGI+uint64(i)*2, gi)
				}
			}
			ctx.SetReturn(uint64(n))
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GetKerningPairsW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // no kerning pairs
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GetOutlineTextMetricsW", func(ctx *ntapi.TrapContext) uint32 {
			// OUTLINETEXTMETRICW is ~276 bytes. Return size=276, fill TEXTMETRICW at offset 4.
			cb   := ctx.Arg(1)
			pOTM := ctx.Arg(2)
			const otmSize = 276
			if cb == 0 || pOTM == 0 {
				ctx.SetReturn(otmSize)
				return 0
			}
			if cb < otmSize { ctx.SetReturn(0); return 0 }
			dc := getDC(ctx.Arg(0))
			f := dc.Font; if f == nil { f = gdi.DefaultFont() }
			// Zero the struct
			for i := uint64(0); i < otmSize; i++ { ctx.Mem.Write8(pOTM+i, 0) }
			ctx.Mem.Write32(pOTM, otmSize) // otmSize
			// TEXTMETRICW at pOTM+4 (60 bytes)
			tm := pOTM + 4
			ch := int32(f.CellHeight)
			ctx.Mem.Write32(tm,    uint32(ch))                    // tmHeight
			ctx.Mem.Write32(tm+4,  uint32(f.Ascent))             // tmAscent
			ctx.Mem.Write32(tm+8,  uint32(ch-f.Ascent))          // tmDescent
			ctx.Mem.Write32(tm+12, 0)                             // tmInternalLeading
			ctx.Mem.Write32(tm+16, 2)                             // tmExternalLeading
			ctx.Mem.Write32(tm+20, uint32(f.AveCharWidth))       // tmAveCharWidth
			ctx.Mem.Write32(tm+24, uint32(f.AveCharWidth)*2)     // tmMaxCharWidth
			ctx.Mem.Write32(tm+28, uint32(f.Weight))             // tmWeight
			ctx.Mem.Write32(tm+32, 0)                             // tmOverhang
			ctx.Mem.Write32(tm+36, 96)                            // tmDigitizedAspectX
			ctx.Mem.Write32(tm+40, 96)                            // tmDigitizedAspectY
			ctx.Mem.Write32(tm+48, 0xFF)                          // tmLastChar
			ctx.Mem.Write32(tm+52, uint32(' '))                   // tmDefaultChar
			ctx.Mem.Write32(tm+56, uint32(' '))                   // tmBreakChar
			ctx.Mem.Write8(tm+60, 0)                              // tmItalic
			ctx.Mem.Write8(tm+61, 0)                              // tmUnderlined
			ctx.Mem.Write8(tm+62, 0)                              // tmStruckOut
			ctx.Mem.Write8(tm+63, 4|32)                           // tmPitchAndFamily=variable|TrueType
			ctx.Mem.Write8(tm+64, 0)                              // tmCharSet=ANSI
			// OUTLINETEXTMETRICW fields after TEXTMETRICW (offset 64)
			otm := pOTM + 68
			ctx.Mem.Write32(otm,   uint32(f.Ascent))  // otmAscent
			ctx.Mem.Write32(otm+4, uint32(ch-f.Ascent)) // otmDescent
			ctx.Mem.Write32(otm+8, 0)                  // otmLineGap
			ctx.Mem.Write32(otm+12, uint32(f.Ascent)) // otmCapEmHeight (approx cap height)
			ctx.Mem.Write32(otm+16, uint32(f.Ascent)) // otmXHeight
			// RECT otmrcFontBox
			ctx.Mem.Write32(otm+20, 0)
			ctx.Mem.Write32(otm+24, uint32(-int32(ch-f.Ascent)))
			ctx.Mem.Write32(otm+28, uint32(f.AveCharWidth))
			ctx.Mem.Write32(otm+32, uint32(f.Ascent))
			ctx.SetReturn(otmSize)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GetFontData", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0xFFFFFFFF) // GDI_ERROR - no font data
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GetGlyphOutlineW", func(ctx *ntapi.TrapContext) uint32 {
			// Return 1 for GGO_METRICS, fill GLYPHMETRICS if provided
			pGM := ctx.Arg(5)
			if pGM != 0 {
				dc := getDC(ctx.Arg(0))
				f := dc.Font
				if f == nil { f = gdi.DefaultFont() }
				ctx.Mem.Write32(pGM,    uint32(f.AveCharWidth))  // gmBlackBoxX
				ctx.Mem.Write32(pGM+4,  uint32(f.CellHeight))    // gmBlackBoxY
				ctx.Mem.Write32(pGM+8,  0)                       // gmptGlyphOrigin.x
				ctx.Mem.Write32(pGM+12, uint32(f.Ascent))        // gmptGlyphOrigin.y
				ctx.Mem.Write16(pGM+16, uint16(f.AveCharWidth))  // gmCellIncX
				ctx.Mem.Write16(pGM+18, 0)                       // gmCellIncY
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "EnumFontFamiliesExW", func(ctx *ntapi.TrapContext) uint32 {
			// We don't attempt to call the callback synchronously - the app will use defaults.
			// Returning 1 indicates enumeration completed without the callback stopping it.
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "EnumFontsW", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "AddFontMemResourceEx", func(ctx *ntapi.TrapContext) uint32 {
			pNumFonts := ctx.Arg(3)
			if pNumFonts != 0 { ctx.Mem.Write32(pNumFonts, 1) }
			ctx.SetReturn(0x12340001) // fake handle
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "RemoveFontMemResourceEx", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "AddFontResourceW", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "AddFontResourceExW", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "RemoveFontResourceW", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "RemoveFontResourceExW", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "CreateFontIndirectExW", func(ctx *ntapi.TrapContext) uint32 {
			// ENUMLOGFONTEXDVW - first field is ENUMLOGFONTEXW, which starts with LOGFONTW
			lf := ctx.Arg(0)
			f := &gdi.Font{}
			if lf != 0 {
				v32, _ := mem.Read32(lf);     f.Height = int32(v32)
				v32, _ = mem.Read32(lf+4);    f.Width = int32(v32)
				v32, _ = mem.Read32(lf+16);   f.Weight = int32(v32)
				v8, _ := mem.Read8(lf+20);    f.Italic = v8 != 0
				v8, _ = mem.Read8(lf+21);     f.Underline = v8 != 0
				v8, _ = mem.Read8(lf+23);     f.CharSet = v8
				f.FaceName = readGuestUTF16(lf+28)
			}
			ctx.SetReturn(gdiMgr.CreateFont(f))
			return 0
		})
		// --- Pen/Brush extras ---
		d.RegisterAutoStubHandler(gdi32, "CreatePenIndirect", func(ctx *ntapi.TrapContext) uint32 {
			p := ctx.Arg(0)
			style, width, color := int32(0), int32(1), uint32(0)
			if p != 0 {
				v, _ := mem.Read32(p);   style = int32(v)
				v, _ = mem.Read32(p+4);  width = int32(v)
				v, _ = mem.Read32(p+8);  color = v
			}
			ctx.SetReturn(gdiMgr.CreatePen(style, width, color))
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "ExtCreatePen", func(ctx *ntapi.TrapContext) uint32 {
			style := uint32(ctx.Arg(0))
			width := int32(ctx.Arg(1))
			pLB := ctx.Arg(2)
			color := uint32(0)
			if pLB != 0 {
				v, _ := mem.Read32(pLB+4); color = v
			}
			penStyle := int32(style & 0x0F)
			ctx.SetReturn(gdiMgr.CreatePen(penStyle, width, color))
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "CreateBrushIndirect", func(ctx *ntapi.TrapContext) uint32 {
			p := ctx.Arg(0)
			style, color := int32(0), uint32(0)
			if p != 0 {
				v, _ := mem.Read32(p);   style = int32(v)
				v, _ = mem.Read32(p+4);  color = v
			}
			if style == 1 { // BS_HOLLOW/BS_NULL
				ctx.SetReturn(gdiMgr.GetStockObject(gdi.StockNullBrush))
			} else {
				ctx.SetReturn(gdiMgr.CreateSolidBrush(color))
			}
			return 0
		})
		// --- Bitmap extras ---
		d.RegisterAutoStubHandler(gdi32, "CreateBitmap", func(ctx *ntapi.TrapContext) uint32 {
			w := int32(ctx.Arg(0))
			h := int32(ctx.Arg(1))
			ctx.SetReturn(gdiMgr.CreateCompatibleBitmap(w, h))
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "CreateBitmapIndirect", func(ctx *ntapi.TrapContext) uint32 {
			p := ctx.Arg(0)
			w, h := int32(0), int32(0)
			if p != 0 {
				v, _ := mem.Read32(p+4); w = int32(v)
				v, _ = mem.Read32(p+8); h = int32(v)
			}
			ctx.SetReturn(gdiMgr.CreateCompatibleBitmap(w, h))
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GetBitmapBits", func(ctx *ntapi.TrapContext) uint32 {
			// GetBitmapBits(hbm, cb, lpvBits) - 24bpp BGR rows, 4-byte aligned
			hbm    := ctx.Arg(0)
			cb     := int(ctx.Arg(1))
			pBits  := ctx.Arg(2)
			obj := gdiMgr.GetObject(hbm)
			if obj == nil || obj.Bitmap == nil || obj.Bitmap.Surf == nil || pBits == 0 {
				ctx.SetReturn(0); return 0
			}
			bm := obj.Bitmap
			stride := gdi.DIBStride(bm.Width, 24)
			rows   := cb / int(stride)
			if rows <= 0 { ctx.SetReturn(0); return 0 }
			buf := make([]byte, rows*int(stride))
			gdi.WriteDIBFromSurface(buf, bm.Surf, 0, 0, bm.Width, int32(rows), 24)
			n := rows * int(stride)
			for i := 0; i < n; i++ {
				ctx.Mem.Write8(pBits+uint64(i), buf[i])
			}
			ctx.SetReturn(uint64(n))
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "SetBitmapBits", func(ctx *ntapi.TrapContext) uint32 {
			// SetBitmapBits(hbm, cb, lpvBits) - 24bpp BGR rows, 4-byte aligned
			hbm    := ctx.Arg(0)
			cb     := int(ctx.Arg(1))
			pBits  := ctx.Arg(2)
			obj := gdiMgr.GetObject(hbm)
			if obj == nil || obj.Bitmap == nil || obj.Bitmap.Surf == nil || pBits == 0 {
				ctx.SetReturn(0); return 0
			}
			bm := obj.Bitmap
			stride := gdi.DIBStride(bm.Width, 24)
			if stride == 0 { ctx.SetReturn(0); return 0 }
			rows := cb / int(stride)
			if rows <= 0 { ctx.SetReturn(0); return 0 }
			buf := make([]byte, cb)
			for i := 0; i < cb; i++ {
				buf[i], _ = ctx.Mem.Read8(pBits + uint64(i))
			}
			// Write 24bpp bottom-up into surface (flip)
			for row := 0; row < rows; row++ {
				srcRow := (rows - 1 - row) // bottom-up
				sy := srcRow
				for col := int32(0); col < bm.Width && col < int32(int(stride/3)); col++ {
					off := row*int(stride) + int(col)*3
					b := buf[off]; g := buf[off+1]; r := buf[off+2]
					bm.Surf.SetPixel(col, int32(sy), uint32(r)<<16|uint32(g)<<8|uint32(b))
				}
			}
			ctx.SetReturn(uint64(rows * int(stride)))
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GetBitmapDimensionEx", func(ctx *ntapi.TrapContext) uint32 {
			p := ctx.Arg(2)
			if p != 0 {
				ctx.Mem.Write32(p, 0)
				ctx.Mem.Write32(p+4, 0)
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "SetBitmapDimensionEx", func(ctx *ntapi.TrapContext) uint32 {
						ctx.SetReturn(1)
			return 0
		})
		// --- Drawing extras ---
		d.RegisterAutoStubHandler(gdi32, "RoundRect", func(ctx *ntapi.TrapContext) uint32 {
			if wlWindow == nil { ctx.SetReturn(1); return 0 }
			dc := getDC(ctx.Arg(0))
			dc.RoundRect(int32(ctx.Arg(1)), int32(ctx.Arg(2)), int32(ctx.Arg(3)), int32(ctx.Arg(4)), int32(ctx.Arg(5)), int32(ctx.Arg(6)))
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "SetPixel", func(ctx *ntapi.TrapContext) uint32 {
			if wlWindow == nil { ctx.SetReturn(0); return 0 }
			dc := getDC(ctx.Arg(0))
			dc.SetPixel(int32(ctx.Arg(1)), int32(ctx.Arg(2)), uint32(ctx.Arg(3)))
			ctx.SetReturn(ctx.Arg(3))
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GetPixel", func(ctx *ntapi.TrapContext) uint32 {
			if wlWindow == nil { ctx.SetReturn(0xFFFFFFFF); return 0 }
			dc := getDC(ctx.Arg(0))
			c := dc.GetPixel(int32(ctx.Arg(1)), int32(ctx.Arg(2)))
			ctx.SetReturn(uint64(c))
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "DrawEdge", func(ctx *ntapi.TrapContext) uint32 {
			if wlWindow == nil { ctx.SetReturn(1); return 0 }
			dc := getDC(ctx.Arg(0))
			pRect := ctx.Arg(1)
			edge := uint32(ctx.Arg(2))
			flags := uint32(ctx.Arg(3))
			if pRect != 0 {
				l, _ := mem.Read32(pRect);  t, _ := mem.Read32(pRect+4)
				r, _ := mem.Read32(pRect+8); b, _ := mem.Read32(pRect+12)
				dc.DrawEdge(int32(l), int32(t), int32(r), int32(b), edge, flags, sysColors)
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "DrawFrameControl", func(ctx *ntapi.TrapContext) uint32 {
			if wlWindow == nil { ctx.SetReturn(1); return 0 }
			dc := getDC(ctx.Arg(0))
			pRect := ctx.Arg(1)
			uType := uint32(ctx.Arg(2))
			uState := uint32(ctx.Arg(3))
			if pRect != 0 {
				l, _ := mem.Read32(pRect);  t, _ := mem.Read32(pRect+4)
				r, _ := mem.Read32(pRect+8); b, _ := mem.Read32(pRect+12)
				dc.DrawFrameControl(int32(l), int32(t), int32(r), int32(b), uType, uState, sysColors)
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "DrawFocusRect", func(ctx *ntapi.TrapContext) uint32 {
			if wlWindow == nil { ctx.SetReturn(1); return 0 }
			dc := getDC(ctx.Arg(0))
			pRect := ctx.Arg(1)
			if pRect != 0 {
				l, _ := mem.Read32(pRect);  t, _ := mem.Read32(pRect+4)
				r, _ := mem.Read32(pRect+8); b, _ := mem.Read32(pRect+12)
				dc.DrawFocusRect(int32(l), int32(t), int32(r), int32(b))
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "InvertRect", func(ctx *ntapi.TrapContext) uint32 {
			if wlWindow == nil { ctx.SetReturn(1); return 0 }
			dc := getDC(ctx.Arg(0))
			pRect := ctx.Arg(1)
			if pRect != 0 {
				l, _ := mem.Read32(pRect);  t, _ := mem.Read32(pRect+4)
				r, _ := mem.Read32(pRect+8); b, _ := mem.Read32(pRect+12)
				dc.InvertRect(int32(l), int32(t), int32(r), int32(b))
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "Polygon", func(ctx *ntapi.TrapContext) uint32 {
			if wlWindow == nil { ctx.SetReturn(1); return 0 }
			dc := getDC(ctx.Arg(0))
			pPts := ctx.Arg(1)
			n := int(ctx.Arg(2))
			pts := make([][2]int32, n)
			for i := 0; i < n; i++ {
				x, _ := mem.Read32(pPts + uint64(i)*8)
				y, _ := mem.Read32(pPts + uint64(i)*8 + 4)
				pts[i] = [2]int32{int32(x), int32(y)}
			}
			dc.Polygon(pts)
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "Polyline", func(ctx *ntapi.TrapContext) uint32 {
			if wlWindow == nil { ctx.SetReturn(1); return 0 }
			dc := getDC(ctx.Arg(0))
			pPts := ctx.Arg(1)
			n := int(ctx.Arg(2))
			pts := make([][2]int32, n)
			for i := 0; i < n; i++ {
				x, _ := mem.Read32(pPts + uint64(i)*8)
				y, _ := mem.Read32(pPts + uint64(i)*8 + 4)
				pts[i] = [2]int32{int32(x), int32(y)}
			}
			dc.PolylinePoints(pts)
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "PolylineTo", func(ctx *ntapi.TrapContext) uint32 {
			if wlWindow == nil { ctx.SetReturn(1); return 0 }
			dc := getDC(ctx.Arg(0))
			pPts := ctx.Arg(1)
			n := int(ctx.Arg(2))
			for i := 0; i < n; i++ {
				x, _ := mem.Read32(pPts + uint64(i)*8)
				y, _ := mem.Read32(pPts + uint64(i)*8 + 4)
				dc.LineTo(int32(x), int32(y))
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "PolyBezier", func(ctx *ntapi.TrapContext) uint32 {
			if wlWindow == nil { ctx.SetReturn(1); return 0 }
			// Approximate bezier as polyline
			dc := getDC(ctx.Arg(0))
			pPts := ctx.Arg(1)
			n := int(ctx.Arg(2))
			pts := make([][2]int32, n)
			for i := 0; i < n; i++ {
				x, _ := mem.Read32(pPts + uint64(i)*8)
				y, _ := mem.Read32(pPts + uint64(i)*8 + 4)
				pts[i] = [2]int32{int32(x), int32(y)}
			}
			dc.PolylinePoints(pts)
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "PolyBezierto", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(gdi32, "PolyPolyline", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(gdi32, "PolyPolygon", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(gdi32, "Arc", func(ctx *ntapi.TrapContext) uint32 {
			// Arc: draw ellipse approximation
			if wlWindow == nil { ctx.SetReturn(1); return 0 }
			dc := getDC(ctx.Arg(0))
			dc.Ellipse(int32(ctx.Arg(1)), int32(ctx.Arg(2)), int32(ctx.Arg(3)), int32(ctx.Arg(4)))
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "ArcTo", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(gdi32, "AngleArc", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(gdi32, "Chord", func(ctx *ntapi.TrapContext) uint32 {
			if wlWindow == nil { ctx.SetReturn(1); return 0 }
			dc := getDC(ctx.Arg(0))
			dc.Ellipse(int32(ctx.Arg(1)), int32(ctx.Arg(2)), int32(ctx.Arg(3)), int32(ctx.Arg(4)))
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "Pie", func(ctx *ntapi.TrapContext) uint32 {
			if wlWindow == nil { ctx.SetReturn(1); return 0 }
			dc := getDC(ctx.Arg(0))
			dc.Ellipse(int32(ctx.Arg(1)), int32(ctx.Arg(2)), int32(ctx.Arg(3)), int32(ctx.Arg(4)))
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "FloodFill", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(gdi32, "ExtFloodFill", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GradientFill", func(ctx *ntapi.TrapContext) uint32 {
			// GradientFill(hdc, pVertex, nVertex, pMesh, nMesh, ulMode)
			// TRIVERTEX: {x, y, Red, Green, Blue, Alpha} (each color is 16-bit, upper 8 used)
			if wlWindow == nil { ctx.SetReturn(1); return 0 }
			dc       := getDC(ctx.Arg(0))
			pVertex  := ctx.Arg(1)
			pMesh    := ctx.Arg(3)
			nMesh    := int(ctx.Arg(4))
			ulMode   := ctx.Arg(5) // 0=RECT_H, 1=RECT_V, 2=TRIANGLE
			if dc.Target == nil || pVertex == 0 || pMesh == 0 { ctx.SetReturn(1); return 0 }
			// TRIVERTEX size = 8+2+2+2+2 = 16 bytes (x,y=int32,R,G,B,A=WORD)
			readVertex := func(idx uint64) (x, y int32, r, g, b uint8) {
				base := pVertex + idx*16
				vx, _ := mem.Read32(base);   x = int32(vx) + dc.OriginX
				vy, _ := mem.Read32(base+4); y = int32(vy) + dc.OriginY
				rv, _ := mem.Read16(base+8);  r = uint8(rv >> 8)
				gv, _ := mem.Read16(base+10); g = uint8(gv >> 8)
				bv, _ := mem.Read16(base+12); b = uint8(bv >> 8)
				return
			}
			if ulMode <= 1 { // GRADIENT_FILL_RECT_H or _V
				for i := 0; i < nMesh; i++ {
					ul, _ := mem.Read32(pMesh + uint64(i)*8)    // upper-left vertex index
					lr, _ := mem.Read32(pMesh + uint64(i)*8 + 4) // lower-right vertex index
					x0, y0, r0, g0, b0 := readVertex(uint64(ul))
					x1, y1, r1, g1, b1 := readVertex(uint64(lr))
					c0 := uint32(r0)<<16 | uint32(g0)<<8 | uint32(b0)
					c1 := uint32(r1)<<16 | uint32(g1)<<8 | uint32(b1)
					if ulMode == 0 { // horizontal
						dc.Target.GradientFillH(x0, y0, x1, y1, c0, c1)
					} else { // vertical
						dc.Target.GradientFillV(x0, y0, x1, y1, c0, c1)
					}
				}
			} else { // GRADIENT_FILL_TRIANGLE: just fill bounding box with first colour
				for i := 0; i < nMesh; i++ {
					v0, _ := mem.Read32(pMesh + uint64(i)*12)
					v1, _ := mem.Read32(pMesh + uint64(i)*12 + 4)
					v2, _ := mem.Read32(pMesh + uint64(i)*12 + 8)
					x0, y0, r0, g0, b0 := readVertex(uint64(v0))
					x1, y1, _, _, _ := readVertex(uint64(v1))
					x2, y2, _, _, _ := readVertex(uint64(v2))
					minX := x0; if x1 < minX { minX = x1 }; if x2 < minX { minX = x2 }
					minY := y0; if y1 < minY { minY = y1 }; if y2 < minY { minY = y2 }
					maxX := x0; if x1 > maxX { maxX = x1 }; if x2 > maxX { maxX = x2 }
					maxY := y0; if y1 > maxY { maxY = y1 }; if y2 > maxY { maxY = y2 }
					c := uint32(r0)<<16 | uint32(g0)<<8 | uint32(b0)
					dc.Target.FillRect(minX, minY, maxX, maxY, c)
				}
			}
			ctx.SetReturn(1)
			return 0
		})
		// --- Palettes (stubbed) ---
		d.RegisterAutoStubHandler(gdi32, "CreatePalette", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x9000 + 1) // fake palette handle
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "SelectPalette", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(gdiMgr.GetStockObject(gdi.StockDefaultPalette))
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "RealizePalette", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GetSystemPaletteEntries", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GetPaletteEntries", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "SetPaletteEntries", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "AnimatePalette", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(gdi32, "UpdateColors", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GetNearestColor", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(ctx.Arg(1)); return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GetNearestPaletteIndex", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		// --- Paths ---
		d.RegisterAutoStubHandler(gdi32, "BeginPath", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(gdi32, "EndPath", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(gdi32, "StrokePath", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(gdi32, "FillPath", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(gdi32, "StrokeAndFillPath", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(gdi32, "CloseFigure", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(gdi32, "AbortPath", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(gdi32, "SelectClipPath", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(gdi32, "FlattenPath", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(gdi32, "WidenPath", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GetPath", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		// --- Metafiles (stubbed as no-op) ---
		d.RegisterAutoStubHandler(gdi32, "CreateMetaFileW", func(ctx *ntapi.TrapContext) uint32 {
			h, _ := gdiMgr.AllocMemDC()
			ctx.SetReturn(h); return 0
		})
		d.RegisterAutoStubHandler(gdi32, "CloseMetaFile", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(gdi32, "DeleteMetaFile", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(gdi32, "CreateEnhMetaFileW", func(ctx *ntapi.TrapContext) uint32 {
			h, _ := gdiMgr.AllocMemDC()
			ctx.SetReturn(h); return 0
		})
		d.RegisterAutoStubHandler(gdi32, "CloseEnhMetaFile", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0); return 0
		})
		d.RegisterAutoStubHandler(gdi32, "DeleteEnhMetaFile", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(gdi32, "PlayMetaFile", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(gdi32, "PlayEnhMetaFile", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		// --- GDI flush/batch ---
		d.RegisterAutoStubHandler(gdi32, "GdiFlush", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GdiGetBatchLimit", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GdiSetBatchLimit", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GdiAlphaBlend", func(ctx *ntapi.TrapContext) uint32 {
			if wlWindow == nil { ctx.SetReturn(1); return 0 }
			hdcDst := ctx.Arg(0)
			dx := int32(ctx.Arg(1)); dy := int32(ctx.Arg(2))
			dw := int32(ctx.Arg(3)); dh := int32(ctx.Arg(4))
			hdcSrc := ctx.Arg(5)
			sx := int32(ctx.Arg(6)); sy := int32(ctx.Arg(7))
			sw := int32(ctx.Arg(8)); sh := int32(ctx.Arg(9))
			// arg10 = BLENDFUNCTION packed as uint32: [BlendOp, BlendFlags, Alpha, AlphaFormat]
			bf := uint32(ctx.Arg(10))
			globalAlpha := uint8((bf >> 16) & 0xFF)
			perPixel    := (bf >> 24) == 1 // AC_SRC_ALPHA
			if globalAlpha == 0 { globalAlpha = 255 }
			dst := getDC(hdcDst)
			src := gdiMgr.GetDC(hdcSrc)
			if dst.Target != nil && src != nil && src.Target != nil {
				adx := dx + dst.OriginX; ady := dy + dst.OriginY
				asx := sx + src.OriginX; asy := sy + src.OriginY
				dst.Target.AlphaBlendSurface(adx, ady, dw, dh, src.Target, asx, asy, sw, sh, globalAlpha, perPixel)
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "AlphaBlend", func(ctx *ntapi.TrapContext) uint32 {
			if wlWindow == nil { ctx.SetReturn(1); return 0 }
			hdcDst := ctx.Arg(0)
			dx := int32(ctx.Arg(1)); dy := int32(ctx.Arg(2))
			dw := int32(ctx.Arg(3)); dh := int32(ctx.Arg(4))
			hdcSrc := ctx.Arg(5)
			sx := int32(ctx.Arg(6)); sy := int32(ctx.Arg(7))
			sw := int32(ctx.Arg(8)); sh := int32(ctx.Arg(9))
			bf := uint32(ctx.Arg(10))
			globalAlpha := uint8((bf >> 16) & 0xFF)
			perPixel    := (bf >> 24) == 1
			if globalAlpha == 0 { globalAlpha = 255 }
			dst := getDC(hdcDst)
			src := gdiMgr.GetDC(hdcSrc)
			if dst.Target != nil && src != nil && src.Target != nil {
				adx := dx + dst.OriginX; ady := dy + dst.OriginY
				asx := sx + src.OriginX; asy := sy + src.OriginY
				dst.Target.AlphaBlendSurface(adx, ady, dw, dh, src.Target, asx, asy, sw, sh, globalAlpha, perPixel)
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "TransparentBlt", func(ctx *ntapi.TrapContext) uint32 {
			if wlWindow == nil { ctx.SetReturn(1); return 0 }
			hdcDst := ctx.Arg(0)
			dx := int32(ctx.Arg(1)); dy := int32(ctx.Arg(2))
			dw := int32(ctx.Arg(3)); dh := int32(ctx.Arg(4))
			hdcSrc := ctx.Arg(5)
			sx := int32(ctx.Arg(6)); sy := int32(ctx.Arg(7))
			sw := int32(ctx.Arg(8)); sh := int32(ctx.Arg(9))
			transColor := uint32(ctx.Arg(10)) // transparent colour key (COLORREF)
			dst := getDC(hdcDst)
			src := gdiMgr.GetDC(hdcSrc)
			if dst.Target != nil && src != nil && src.Target != nil {
				adx := dx + dst.OriginX; ady := dy + dst.OriginY
				asx := sx + src.OriginX; asy := sy + src.OriginY
				// Scale first if needed via StretchBlt, then apply transparent blt
				if sw == dw && sh == dh {
					dst.Target.TransparentBlt(adx, ady, dw, dh, src.Target, asx, asy, sw, sh, transColor)
				} else {
					// Stretch into a temp surface then transparent-blt
					tmp := gdi.NewSurface(dw, dh)
					tmp.StretchBlt(0, 0, dw, dh, src.Target, asx, asy, sw, sh)
					dst.Target.TransparentBlt(adx, ady, dw, dh, tmp, 0, 0, dw, dh, transColor)
				}
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GetCurrentObject", func(ctx *ntapi.TrapContext) uint32 {
			dc := getDC(ctx.Arg(0))
			objType := ctx.Arg(1)
			switch objType {
			case 2: // OBJ_BRUSH
				if dc.Brush != nil { ctx.SetReturn(gdiMgr.FindBrushHandle(dc.Brush)) } else { ctx.SetReturn(gdiMgr.GetStockObject(gdi.StockWhiteBrush)) }
			case 1: // OBJ_PEN
				if dc.Pen != nil { ctx.SetReturn(gdiMgr.FindPenHandle(dc.Pen)) } else { ctx.SetReturn(gdiMgr.GetStockObject(gdi.StockBlackPen)) }
			case 6: // OBJ_FONT
				if dc.Font != nil { ctx.SetReturn(gdiMgr.FindFontHandle(dc.Font)) } else { ctx.SetReturn(gdiMgr.GetStockObject(gdi.StockSystemFont)) }
			case 7: // OBJ_BITMAP
				ctx.SetReturn(gdiMgr.FindBitmapHandle(dc.Bitmap))
			default:
				ctx.SetReturn(0)
			}
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GetObjectType", func(ctx *ntapi.TrapContext) uint32 {
			obj := gdiMgr.GetObject(ctx.Arg(0))
			if obj == nil { ctx.SetReturn(0); return 0 }
			switch obj.Type {
			case gdi.ObjBrush:  ctx.SetReturn(2)
			case gdi.ObjPen:    ctx.SetReturn(1)
			case gdi.ObjFont:   ctx.SetReturn(6)
			case gdi.ObjBitmap: ctx.SetReturn(7)
			case gdi.ObjRegion: ctx.SetReturn(8)
			default:            ctx.SetReturn(0)
			}
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "CancelDC", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1); return 0
		})
		d.RegisterAutoStubHandler(gdi32, "ResetDCW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(ctx.Arg(0)); return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GetCurrentPositionEx", func(ctx *ntapi.TrapContext) uint32 {
			dc := getDC(ctx.Arg(0))
			p := ctx.Arg(1)
			if p != 0 {
				ctx.Mem.Write32(p,   uint32(dc.CurX))
				ctx.Mem.Write32(p+4, uint32(dc.CurY))
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "GetDIBits", func(ctx *ntapi.TrapContext) uint32 {
			// GetDIBits(hdc, hbm, startScan, numScans, lpvBits, lpbmi, usage)
			hbm      := ctx.Arg(1)
			startScan := int32(ctx.Arg(2))
			numScans  := int32(ctx.Arg(3))
			lpvBits  := ctx.Arg(4)
			pBMI     := ctx.Arg(5)
			obj := gdiMgr.GetObject(hbm)
			if obj == nil || obj.Bitmap == nil || obj.Bitmap.Surf == nil {
				ctx.SetReturn(0); return 0
			}
			bm := obj.Bitmap
			// Fill BITMAPINFOHEADER if provided (bitCount=32 BI_RGB)
			if pBMI != 0 {
				ctx.Mem.Write32(pBMI,      40)               // biSize
				ctx.Mem.Write32(pBMI+4,    uint32(bm.Width)) // biWidth
				ctx.Mem.Write32(pBMI+8,    uint32(bm.Height)) // biHeight (bottom-up)
				ctx.Mem.Write16(pBMI+12,   1)                // biPlanes
				ctx.Mem.Write16(pBMI+14,   32)               // biBitCount
				ctx.Mem.Write32(pBMI+16,   0)                // biCompression BI_RGB
				ctx.Mem.Write32(pBMI+20,   0)                // biSizeImage
				ctx.Mem.Write32(pBMI+24,   0)
				ctx.Mem.Write32(pBMI+28,   0)
				ctx.Mem.Write32(pBMI+32,   0)
				ctx.Mem.Write32(pBMI+36,   0)
			}
			if lpvBits == 0 {
				ctx.SetReturn(uint64(numScans)); return 0
			}
			// Write pixel data (32bpp bottom-up)
			stride := gdi.DIBStride(bm.Width, 32)
			buf := make([]byte, int(stride)*int(numScans))
			gdi.WriteDIBFromSurface(buf, bm.Surf, 0, startScan, bm.Width, numScans, 32)
			for i, b := range buf {
				ctx.Mem.Write8(lpvBits+uint64(i), b)
			}
			ctx.SetReturn(uint64(numScans))
			return 0
		})
	}
	})
	ravelog.Logf("[gdi] calling gdi32 registrar\n")
	delayHandlerRegistrars[len(delayHandlerRegistrars)-1]()

	// --- crypt32.dll ---
	delayHandlerRegistrars = append(delayHandlerRegistrars, func() {
	if crypt32, ok := synthByName["crypt32.dll"]; ok {
		d.RegisterAutoStubHandler(crypt32, "CryptQueryObject", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE - no crypto
			return 0
		})
		d.RegisterAutoStubHandler(crypt32, "CryptMsgClose", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(crypt32, "CryptMsgGetParam", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(crypt32, "CertCloseStore", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(crypt32, "CertFindCertificateInStore", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // NULL - not found
			return 0
		})
		d.RegisterAutoStubHandler(crypt32, "CertGetCertificateContextProperty", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(crypt32, "CertGetNameStringW", func(ctx *ntapi.TrapContext) uint32 {
			pszNameString := ctx.Arg(4)
			cchNameString := ctx.Arg(3)
			if pszNameString != 0 && cchNameString > 0 {
				ctx.Mem.Write16(pszNameString, 0)
			}
			ctx.SetReturn(1) // 1 char (empty string with NUL)
			return 0
		})
		d.RegisterAutoStubHandler(crypt32, "CertNameToStrW", func(ctx *ntapi.TrapContext) uint32 {
			psz := ctx.Arg(3)
			csz := ctx.Arg(4)
			if psz != 0 && csz > 0 {
				ctx.Mem.Write16(psz, 0)
			}
			ctx.SetReturn(1)
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
		// IsTextUnicode: heuristic check for Unicode text - return TRUE (assume Unicode)
		d.RegisterAutoStubHandler(advapi32, "IsTextUnicode", func(ctx *ntapi.TrapContext) uint32 {
			pResult := ctx.Arg(2)
			if pResult != 0 {
				ctx.Mem.Write32(pResult, 0x0001) // IS_TEXT_UNICODE_ASCII16
			}
			ctx.SetReturn(1) // TRUE
			return 0
		})
	}
	})
	delayHandlerRegistrars[len(delayHandlerRegistrars)-1]()

	// --- uxtheme.dll ---
	delayHandlerRegistrars = append(delayHandlerRegistrars, func() {
	if uxtheme, ok := synthByName["uxtheme.dll"]; ok {
		d.RegisterAutoStubHandler(uxtheme, "SetWindowTheme", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // S_OK - we don't support visual themes
			return 0
		})
		d.RegisterAutoStubHandler(uxtheme, "OpenThemeData", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // NULL - no theme data
			return 0
		})
		d.RegisterAutoStubHandler(uxtheme, "CloseThemeData", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(uxtheme, "DrawThemeBackground", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x80004001) // E_NOTIMPL
			return 0
		})
		d.RegisterAutoStubHandler(uxtheme, "DrawThemeText", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x80004001) // E_NOTIMPL
			return 0
		})
		d.RegisterAutoStubHandler(uxtheme, "GetThemeColor", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x80004001) // E_NOTIMPL
			return 0
		})
		d.RegisterAutoStubHandler(uxtheme, "GetThemeInt", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x80004001) // E_NOTIMPL
			return 0
		})
		d.RegisterAutoStubHandler(uxtheme, "GetThemeFont", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x80004001) // E_NOTIMPL
			return 0
		})
		d.RegisterAutoStubHandler(uxtheme, "GetThemeRect", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x80004001) // E_NOTIMPL
			return 0
		})
		d.RegisterAutoStubHandler(uxtheme, "GetThemePartSize", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x80004001) // E_NOTIMPL
			return 0
		})
		d.RegisterAutoStubHandler(uxtheme, "GetThemeTextExtent", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x80004001) // E_NOTIMPL
			return 0
		})
		d.RegisterAutoStubHandler(uxtheme, "IsThemeActive", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE - themes disabled
			return 0
		})
		d.RegisterAutoStubHandler(uxtheme, "IsAppThemed", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(uxtheme, "IsThemeBackgroundPartiallyTransparent", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
		d.RegisterAutoStubHandler(uxtheme, "DrawThemeParentBackground", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(uxtheme, "BufferedPaintInit", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // S_OK
			return 0
		})
		d.RegisterAutoStubHandler(uxtheme, "BufferedPaintUnInit", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(uxtheme, "EndBufferedAnimation", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // S_OK
			return 0
		})
		d.RegisterAutoStubHandler(uxtheme, "GetThemeTransitionDuration", func(ctx *ntapi.TrapContext) uint32 {
			pdwDuration := ctx.Arg(4)
			if pdwDuration != 0 {
				ctx.Mem.Write32(pdwDuration, 0)
			}
			ctx.SetReturn(0x80004001) // E_NOTIMPL
			return 0
		})
		d.RegisterAutoStubHandler(uxtheme, "GetThemeBackgroundContentRect", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x80004001) // E_NOTIMPL
			return 0
		})
		d.RegisterAutoStubHandler(uxtheme, "EnableThemeDialogTexture", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // S_OK
			return 0
		})
		d.RegisterAutoStubHandler(uxtheme, "DrawThemeTextEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x80004001) // E_NOTIMPL
			return 0
		})
		d.RegisterAutoStubHandler(uxtheme, "BufferedPaintStopAllAnimations", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // S_OK
			return 0
		})
		d.RegisterAutoStubHandler(uxtheme, "BeginBufferedAnimation", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // NULL - no animation handle
			return 0
		})
		d.RegisterAutoStubHandler(uxtheme, "BufferedPaintRenderAnimation", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE - no animation to render
			return 0
		})
	}
	})
	delayHandlerRegistrars[len(delayHandlerRegistrars)-1]()

	// --- mpr.dll ---
	delayHandlerRegistrars = append(delayHandlerRegistrars, func() {
	if mpr, ok := synthByName["mpr.dll"]; ok {
		d.RegisterAutoStubHandler(mpr, "WNetGetProviderNameA", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1203) // ERROR_NO_NET_OR_BAD_PATH
			return 0
		})
		d.RegisterAutoStubHandler(mpr, "WNetGetProviderNameW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1203) // ERROR_NO_NET_OR_BAD_PATH
			return 0
		})
	}
	})
	delayHandlerRegistrars[len(delayHandlerRegistrars)-1]()

	// --- ws2_32.dll ---
	delayHandlerRegistrars = append(delayHandlerRegistrars, func() {
	if ws2, ok := synthByName["ws2_32.dll"]; ok {
		// getaddrinfo: return EAI_NONAME (no DNS resolution in emulator)
		d.RegisterAutoStubHandler(ws2, "getaddrinfo", func(ctx *ntapi.TrapContext) uint32 {
			ppResult := ctx.Arg(3)
			if ppResult != 0 {
				ctx.Mem.Write64(ppResult, 0)
			}
			ctx.SetReturn(11) // EAI_NONAME (WSAHOST_NOT_FOUND)
			return 0
		})
		// freeaddrinfo: no-op (we never allocate addrinfo structs)
		d.RegisterAutoStubHandler(ws2, "freeaddrinfo", func(ctx *ntapi.TrapContext) uint32 {
			return 0
		})
		// WSAStartup: pretend Winsock 2.2 is available
		d.RegisterAutoStubHandler(ws2, "WSAStartup", func(ctx *ntapi.TrapContext) uint32 {
			lpWSAData := ctx.Arg(1)
			if lpWSAData != 0 {
				// WSADATA: first two WORDs are wVersion and wHighVersion
				ctx.Mem.Write16(lpWSAData+0, 0x0202) // version 2.2
				ctx.Mem.Write16(lpWSAData+2, 0x0202) // high version 2.2
			}
			ctx.SetReturn(0) // success
			return 0
		})
		d.RegisterAutoStubHandler(ws2, "WSACleanup", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
	}
	})
	delayHandlerRegistrars[len(delayHandlerRegistrars)-1]()

	// --- iphlpapi.dll ---
	delayHandlerRegistrars = append(delayHandlerRegistrars, func() {
	if iphlpapi, ok := synthByName["iphlpapi.dll"]; ok {
		// GetAdaptersAddresses: return ERROR_NO_DATA (no adapters to enumerate)
		d.RegisterAutoStubHandler(iphlpapi, "GetAdaptersAddresses", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(232) // ERROR_NO_DATA
			return 0
		})
	}
	})
	delayHandlerRegistrars[len(delayHandlerRegistrars)-1]()

	// --- version.dll ---
	versionBuf := mem.Mmap(0, 128, mmu.PermRead|mmu.PermWrite)
	// VS_FIXEDFILEINFO at versionBuf
	mem.Write32(versionBuf+0, 0xFEEF04BD)  // dwSignature
	mem.Write32(versionBuf+4, 0x00010000)  // dwStrucVersion
	mem.Write32(versionBuf+8, 0x00080007)  // dwFileVersionMS (8.7)
	mem.Write32(versionBuf+12, 0x00060000) // dwFileVersionLS
	mem.Write32(versionBuf+16, 0x00080007) // dwProductVersionMS
	mem.Write32(versionBuf+20, 0x00060000) // dwProductVersionLS
	mem.Write32(versionBuf+24, 0x0000003F) // dwFileFlagsMask
	mem.Write32(versionBuf+28, 0)          // dwFileFlags
	mem.Write32(versionBuf+32, 0x00040004) // dwFileOS (VOS_NT_WINDOWS32)
	mem.Write32(versionBuf+36, 1)          // dwFileType (VFT_APP)
	delayHandlerRegistrars = append(delayHandlerRegistrars, func() {
	if version, ok := synthByName["version.dll"]; ok {
		d.RegisterAutoStubHandler(version, "GetFileVersionInfoSizeW", func(ctx *ntapi.TrapContext) uint32 {
			pHandle := ctx.Arg(1)
			if pHandle != 0 {
				ctx.Mem.Write32(pHandle, 0)
			}
			ctx.SetReturn(128) // fake non-zero size
			return 0
		})
		d.RegisterAutoStubHandler(version, "GetFileVersionInfoW", func(ctx *ntapi.TrapContext) uint32 {
			lpData := ctx.Arg(3)
			if lpData != 0 {
				for i := uint64(0); i < 52; i += 4 {
					v, _ := ctx.Mem.Read32(versionBuf + i)
					ctx.Mem.Write32(lpData+i, v)
				}
			}
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(version, "VerQueryValueW", func(ctx *ntapi.TrapContext) uint32 {
			pBlock := ctx.Arg(0)
			lpSubBlock := ctx.Arg(1)
			lplpBuffer := ctx.Arg(2)
			puLen := ctx.Arg(3)
			sub := readGuestUTF16(lpSubBlock)
			if sub == "\\" {
				if lplpBuffer != 0 {
					ctx.Mem.Write64(lplpBuffer, pBlock)
				}
				if puLen != 0 {
					ctx.Mem.Write32(puLen, 52)
				}
				ctx.SetReturn(1) // TRUE
			} else {
				ctx.SetReturn(0) // not found
			}
			return 0
		})
	}
	})
	delayHandlerRegistrars[len(delayHandlerRegistrars)-1]()

	// --- imm32.dll ---
	delayHandlerRegistrars = append(delayHandlerRegistrars, func() {
	if imm32dll, ok := synthByName["imm32.dll"]; ok {
		d.RegisterAutoStubHandler(imm32dll, "ImmGetContext", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // NULL HIMC - no IME
			return 0
		})
		d.RegisterAutoStubHandler(imm32dll, "ImmReleaseContext", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(imm32dll, "ImmGetCompositionStringW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // 0 = no composition string / GCS_RESULTSTR not available
			return 0
		})
		d.RegisterAutoStubHandler(imm32dll, "ImmGetDefaultIMEWnd", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // NULL - no IME window
			return 0
		})
		d.RegisterAutoStubHandler(imm32dll, "ImmAssociateContext", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // NULL - no previous context
			return 0
		})
		d.RegisterAutoStubHandler(imm32dll, "ImmAssociateContextEx", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(imm32dll, "ImmDisableIME", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(imm32dll, "ImmIsIME", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE - no IME
			return 0
		})
		for _, fname := range []string{
			"ImmSetCandidateWindow", "ImmSetCompositionWindow",
			"ImmSetCompositionFontW", "ImmSetCompositionStringW",
			"ImmNotifyIME", "ImmEscapeW",
		} {
			n := fname
			d.RegisterAutoStubHandler(imm32dll, n, func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(0) // FALSE / no-op
				return 0
			})
		}
	}
	})
	delayHandlerRegistrars[len(delayHandlerRegistrars)-1]()

	// --- sensapi.dll ---
	delayHandlerRegistrars = append(delayHandlerRegistrars, func() {
	if sensapi, ok := synthByName["sensapi.dll"]; ok {
		d.RegisterAutoStubHandler(sensapi, "IsNetworkAlive", func(ctx *ntapi.TrapContext) uint32 {
			lpdwFlags := ctx.Arg(0)
			if lpdwFlags != 0 {
				ctx.Mem.Write32(lpdwFlags, 1) // NETWORK_ALIVE_LAN
			}
			ctx.SetReturn(1) // TRUE - pretend connected
			return 0
		})
		d.RegisterAutoStubHandler(sensapi, "IsDestinationReachableW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE
			return 0
		})
	}
	})
	delayHandlerRegistrars[len(delayHandlerRegistrars)-1]()

	// --- dwmapi.dll ---
	delayHandlerRegistrars = append(delayHandlerRegistrars, func() {
	if dwmapi, ok := synthByName["dwmapi.dll"]; ok {
		d.RegisterAutoStubHandler(dwmapi, "DwmSetWindowAttribute", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // S_OK
			return 0
		})
	}
	})
	delayHandlerRegistrars[len(delayHandlerRegistrars)-1]()

	// --- dbghelp.dll ---
	delayHandlerRegistrars = append(delayHandlerRegistrars, func() {
	if dbghelp, ok := synthByName["dbghelp.dll"]; ok {
		d.RegisterAutoStubHandler(dbghelp, "ImageNtHeader", func(ctx *ntapi.TrapContext) uint32 {
			base := ctx.Arg(0)
			if base == 0 {
				ctx.SetReturn(0)
				return 0
			}
			// NT headers start at base + e_lfanew (DOS header offset 0x3C)
			lfanew, _ := ctx.Mem.Read32(base + 0x3C)
			ctx.SetReturn(base + uint64(lfanew))
			return 0
		})
	}
	})
	delayHandlerRegistrars[len(delayHandlerRegistrars)-1]()

	// --- wintrust.dll ---
	delayHandlerRegistrars = append(delayHandlerRegistrars, func() {
	if wintrust, ok := synthByName["wintrust.dll"]; ok {
		d.RegisterAutoStubHandler(wintrust, "WinVerifyTrust", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // S_OK - trusted (skip signature check)
			return 0
		})
	}
	})
	delayHandlerRegistrars[len(delayHandlerRegistrars)-1]()

	// --- wininet.dll ---
	delayHandlerRegistrars = append(delayHandlerRegistrars, func() {
	if wininet, ok := synthByName["wininet.dll"]; ok {
		d.RegisterAutoStubHandler(wininet, "InternetCrackUrlW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE - no URL parsing in emulator
			return 0
		})
		d.RegisterAutoStubHandler(wininet, "InternetGetConnectedState", func(ctx *ntapi.TrapContext) uint32 {
			lpdwFlags := ctx.Arg(0)
			if lpdwFlags != 0 { ctx.Mem.Write32(lpdwFlags, 0x40) } // INTERNET_CONNECTION_LAN
			ctx.SetReturn(1) // TRUE
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
		} else {
			// Ordinal-only import: use a generated placeholder so the DLL gets a synth
			placeholder := fmt.Sprintf("ord_%d", imp.Ordinal)
			needed[dllKey] = append(needed[dllKey], placeholder)
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

		// HeapAlloc/HeapFree/HeapReAlloc: NOT patched inline -
		// use Go vmcall handlers with free-list support.

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

// writeFindData fills a WIN32_FIND_DATAW structure in guest memory.
func writeFindData(m *mmu.MMU, ptr uint64, dir string, e os.DirEntry) {
	// WIN32_FIND_DATAW layout:
	// +0:  DWORD  dwFileAttributes
	// +4:  FILETIME ftCreationTime (8)
	// +12: FILETIME ftLastAccessTime (8)
	// +20: FILETIME ftLastWriteTime (8)
	// +28: DWORD  nFileSizeHigh
	// +32: DWORD  nFileSizeLow
	// +36: DWORD  dwReserved0
	// +40: DWORD  dwReserved1
	// +44: WCHAR  cFileName[260]
	// +564: WCHAR cAlternateFileName[14]
	var attrs uint32 = 0x20 // FILE_ATTRIBUTE_NORMAL
	if e.IsDir() {
		attrs = 0x10 // FILE_ATTRIBUTE_DIRECTORY
	}
	m.Write32(ptr+0, attrs)
	info, err := e.Info()
	if err == nil {
		const epochDiff = int64(11644473600) // seconds between 1601 and 1970
		ft := uint64(info.ModTime().Unix()+epochDiff) * 10000000
		m.Write64Raw(ptr+4, ft)  // ftCreationTime
		m.Write64Raw(ptr+12, ft) // ftLastAccessTime
		m.Write64Raw(ptr+20, ft) // ftLastWriteTime
		if !e.IsDir() {
			sz := info.Size()
			m.Write32(ptr+28, uint32(sz>>32))
			m.Write32(ptr+32, uint32(sz))
		}
	}
	// Write cFileName as UTF-16LE
	name := e.Name()
	for i, r := range []rune(name) {
		if i >= 259 {
			break
		}
		m.Write16(ptr+44+uint64(i)*2, uint16(r))
	}
	m.Write16(ptr+44+uint64(len([]rune(name)))*2, 0) // null terminator
}

// saveScreenshot saves the XRGB8888 wl.Window pixel buffer as a PNG.
// Encodes to a buffer first then writes atomically to avoid truncation on SIGTERM.
func saveScreenshot(pix []byte, w, h int, path string) {
ravelog.Logf("[ss] saveScreenshot w=%d h=%d pixLen=%d path=%s\n", w, h, len(pix), path)
img := image.NewRGBA(image.Rect(0, 0, w, h))
for y := 0; y < h; y++ {
for x := 0; x < w; x++ {
off := (y*w + x) * 4
if off+3 >= len(pix) { break }
b := pix[off+0]
g := pix[off+1]
r := pix[off+2]
img.SetRGBA(x, y, color.RGBA{R: r, G: g, B: b, A: 0xFF})
}
}
var buf bytes.Buffer
err2 := png.Encode(&buf, img)
ravelog.Logf("[ss] png.Encode err=%v size=%d\n", err2, buf.Len())
if err2 != nil { return }
os.WriteFile(path, buf.Bytes(), 0644)
}

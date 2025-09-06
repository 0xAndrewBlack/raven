package main

import (
"flag"
"fmt"
"os"
"path/filepath"
"runtime/pprof"
"strings"
"time"

"github.com/mirkobrombin/go-vm/pkg/arch"
"github.com/mirkobrombin/go-vm/pkg/cpu"
"github.com/mirkobrombin/go-vm/pkg/loader"
"github.com/mirkobrombin/go-vm/pkg/mmu"
"github.com/mirkobrombin/go-vm/pkg/ntapi"
gosyscall "github.com/mirkobrombin/go-vm/pkg/syscall"
"github.com/mirkobrombin/go-vm/pkg/thread"
"github.com/mirkobrombin/go-vm/pkg/vfs"
"github.com/mirkobrombin/go-vm/pkg/win32k"
"github.com/mirkobrombin/go-vm/pkg/x64"
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

func main() {
trace := flag.Bool("trace", false, "enable instruction trace to stderr")
memMB := flag.Int("mem", 256, "guest memory limit in MiB (advisory)")
sysroot := flag.String("sysroot", "", "path to Windows system DLL directory (for PE mode)")
regFile := flag.String("registry", "", "path to registry hive JSON file (for PE mode)")
cpuprof := flag.String("cpuprofile", "", "write CPU profile to file")

flag.Usage = func() {
fmt.Fprintf(os.Stderr, "Usage: govm [flags] <binary> [args...]\n\n")
fmt.Fprintf(os.Stderr, "go-vm - in-process RISC-V / x86_64 / Windows PE Library OS\n\n")
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
runPE(absPath, guestArgv, *sysroot, *regFile, *trace)
} else {
runELF(absPath, guestArgv, *trace)
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
func runELF(absPath string, guestArgv []string, trace bool) {
guestEnvp := []string{
"PATH=/usr/bin:/bin",
"HOME=/",
"TERM=dumb",
}

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
func runPE(absPath string, guestArgv []string, sysroot, regFile string, trace bool) {
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
synthWin32u := ntapi.GenerateWin32u(mem)

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

// Stack layout
stackTop := uint64(0x7FFE0000)
stackSize := uint64(8 * 1024 * 1024)

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

// Create the trap dispatcher
dispatcher := ntapi.NewDispatcher(mem, fs, handles, registry, procState, synthNtdll, synthWin32u)
dispatcher.SetTrace(trace)

// Register auto-synth stub names with the dispatcher for trace output
for _, synth := range autoSynthDLLs {
	dispatcher.RegisterAutoStubNames(synth)
}

// Register handlers for critical CRT/Win32 functions
peBasename := filepath.Base(filepath.Dir(absPath))
winImagePath := `C:\` + peBasename + `\` + filepath.Base(absPath)
registerAutoSynthHandlers(mem, dispatcher, autoSynthDLLs, guestArgv, cmdLine, winImagePath, handles, procState, exceptionTable)

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
// offsets (like [rcx+0x28] with rcx=0) read zero instead of segfaulting.
// Many C++ vtable dispatch patterns null-check the loaded value after reading.
mem.Mmap(1, 0x10000, mmu.PermRead) // addr≠0 so Mmap uses it as-is; page 0 gets mapped

// Patch hot Win32 API stubs with inline x64 code to avoid vmcall overhead.
patchHotStubs(mem, autoSynthDLLs, flsDataArray)

if trace && exceptionTable != nil {
	fmt.Fprintf(os.Stderr, "[seh] parsed %d RUNTIME_FUNCTION entries from .pdata\n", len(exceptionTable.Entries))
}

// Set up handlers
c.SetVmcallHandler(dispatcher.Handle) // NT trap handler
c.SetSyscallHandler(func(cpu arch.CPU) {
if trace {
fmt.Fprintf(os.Stderr, "[pe] unexpected Linux syscall %d at RIP=0x%x\n",
cpu.SyscallNum(), cpu.GetPC())
}
cpu.SetSyscallReturn(0xC0000002) // STATUS_NOT_IMPLEMENTED
})

// Thread manager
tm := thread.NewManager(mem, dispatcher.Handle)
mainThread := tm.MainThread(c)

if trace {
fmt.Fprintf(os.Stderr, "[pe] entry=0x%x sp=0x%x teb=0x%x peb=0x%x\n",
result.EntryPoint, result.StackPtr, procState.TEBAddr, procState.PEBAddr)
fmt.Fprintf(os.Stderr, "[pe] ntdll=0x%x win32u=0x%x\n",
synthNtdll.BaseAddr, synthWin32u.BaseAddr)
}

// Call DllMain(DLL_PROCESS_ATTACH) for each loaded BYODLL in dependency order
if len(dllLoadOrder) > 0 {
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
func registerAutoSynthHandlers(mem *mmu.MMU, d *ntapi.Dispatcher, dlls []*ntapi.SynthPE, argv []string, cmdLine, imagePath string, handles *ntapi.HandleTable, procState *ntapi.ProcessState, exceptionTable *ntapi.ExceptionTable) {
	synthByName := make(map[string]*ntapi.SynthPE)
	for _, s := range dlls {
		synthByName[strings.ToLower(s.Name)] = s
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
				ctx.SetReturn(0)
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
				fmt.Fprintf(os.Stderr, "[win32] CreateFileW: %q access=0x%x disp=%d\n", name, desiredAccess, creationDisp)
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
					fmt.Fprintf(os.Stderr, "[win32] CreateFileW: %q → INVALID_HANDLE_VALUE (%v)\n", name, err)
				}
				ctx.SetReturn(0xFFFFFFFFFFFFFFFF) // INVALID_HANDLE_VALUE
				procState.LastError = 2 // ERROR_FILE_NOT_FOUND
				return 0
			}
			h := handles.Alloc(&ntapi.FileHandle{FD: fd, Path: vfsPath})
			if ctx.Trace {
				fmt.Fprintf(os.Stderr, "[win32] CreateFileW: %q → handle=0x%x (fd=%d)\n", name, uint64(h), fd)
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
			for i := 0; i < n; i++ {
				ctx.Mem.Write8(bufAddr+uint64(i), buf[i])
			}
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
			fmt.Fprintf(os.Stderr, "[win32] RaiseException: code=0x%x flags=0x%x\n", code, flags)
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
						fmt.Fprintf(os.Stderr, "[seh] C++ exception → FH4 fallback unwind to RIP=0x%x RSP=0x%x\n",
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
						fmt.Fprintf(os.Stderr, "[seh] C++ exception → catch funclet at 0x%x, RBP=0x%x\n",
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
				fmt.Fprintf(os.Stderr, "[win32] RaiseException: C++ exception (0xe06d7363) - no SEH handler, continuing\n")
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
	}

	// --- shlwapi.dll ---
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
	}

	// --- shell32.dll ---
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
	}

	// --- advapi32.dll ---
	if advapi32, ok := synthByName["advapi32.dll"]; ok {
		d.RegisterAutoStubHandler(advapi32, "RegOpenKeyExW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(2) // ERROR_FILE_NOT_FOUND
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
			hkResult := ctx.Arg(6)
			if hkResult != 0 {
				ctx.Mem.Write64(hkResult, 0xBEEF0100) // fake key handle
			}
			ctx.SetReturn(0) // ERROR_SUCCESS
			return 0
		})
		d.RegisterAutoStubHandler(advapi32, "RegEnumKeyExW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(259) // ERROR_NO_MORE_ITEMS
			return 0
		})
		d.RegisterAutoStubHandler(advapi32, "RegEnumValueW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(259) // ERROR_NO_MORE_ITEMS
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

	// --- ole32.dll ---
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
	}

	// --- oleaut32.dll ---
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

	// Simple handle generator for GDI objects, windows, etc.
	nextGDIHandle := uint64(0xD0010001) // GDI handle space
	gdiAlloc := func() uint64 {
		h := nextGDIHandle
		nextGDIHandle++
		return h
	}
	nextHWND := uint64(0x00050001) // window handle space
	hwndAlloc := func() uint64 {
		h := nextHWND
		nextHWND++
		return h
	}
	nextMsgID := uint32(0xC000) // RegisterWindowMessage range
	nextAtom := uint16(0xC001)  // RegisterClass atom range

	// --- user32.dll ---
	if user32, ok := synthByName["user32.dll"]; ok {
		d.RegisterAutoStubHandler(user32, "RegisterClassW", func(ctx *ntapi.TrapContext) uint32 {
			// WNDCLASSW* in RCX - return a unique atom
			a := nextAtom
			nextAtom++
			ctx.SetReturn(uint64(a))
			return 0
		})
		d.RegisterAutoStubHandler(user32, "RegisterClassExW", func(ctx *ntapi.TrapContext) uint32 {
			a := nextAtom
			nextAtom++
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
			ctx.SetReturn(hwnd)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "DestroyWindow", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(user32, "ShowWindow", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // was previously visible
			return 0
		})
		d.RegisterAutoStubHandler(user32, "UpdateWindow", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
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
			ctx.SetReturn(gdiAlloc()) // return a valid-looking DC handle
			return 0
		})
		d.RegisterAutoStubHandler(user32, "ReleaseDC", func(ctx *ntapi.TrapContext) uint32 {
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
			idx := ctx.Arg(0)
			// Return standard Windows 10 system colors (COLORREF = 0x00BBGGRR)
			colors := map[uint64]uint64{
				0:  0x00D4D0C8, // COLOR_SCROLLBAR
				1:  0x00A56E3A, // COLOR_BACKGROUND/DESKTOP
				2:  0x00B99D7F, // COLOR_ACTIVECAPTION
				3:  0x00D4D0C8, // COLOR_INACTIVECAPTION
				4:  0x00F0F0F0, // COLOR_MENU
				5:  0x00FFFFFF, // COLOR_WINDOW
				6:  0x00000000, // COLOR_WINDOWFRAME
				7:  0x00000000, // COLOR_MENUTEXT
				8:  0x00000000, // COLOR_WINDOWTEXT
				9:  0x00FFFFFF, // COLOR_CAPTIONTEXT
				10: 0x00D4D0C8, // COLOR_ACTIVEBORDER
				11: 0x00D4D0C8, // COLOR_INACTIVEBORDER
				12: 0x00808080, // COLOR_APPWORKSPACE
				13: 0x00B99D7F, // COLOR_HIGHLIGHT
				14: 0x00FFFFFF, // COLOR_HIGHLIGHTTEXT
				15: 0x00F0F0F0, // COLOR_BTNFACE / 3DFACE
				16: 0x00A0A0A0, // COLOR_BTNSHADOW / 3DSHADOW
				17: 0x006D6D6D, // COLOR_GRAYTEXT
				18: 0x00000000, // COLOR_BTNTEXT
				19: 0x00D4D0C8, // COLOR_INACTIVECAPTIONTEXT
				20: 0x00FFFFFF, // COLOR_BTNHIGHLIGHT
				21: 0x00696969, // COLOR_3DDKSHADOW
				22: 0x00E3E3E3, // COLOR_3DLIGHT
				23: 0x00000000, // COLOR_INFOTEXT
				24: 0x00E1FFFF, // COLOR_INFOBK
				26: 0x00CC6600, // COLOR_HOTLIGHT
			}
			c, ok := colors[idx]
			if !ok {
				c = 0x00C0C0C0 // fallback gray
			}
			ctx.SetReturn(c)
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
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(user32, "MoveWindow", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "SetWindowTextW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "SetWindowLongPtrW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "GetWindowLongPtrW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "SetWindowLongW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "GetWindowLongW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "GetClientRect", func(ctx *ntapi.TrapContext) uint32 {
			pRect := ctx.Arg(1)
			if pRect != 0 {
				ctx.Mem.Write32(pRect, 0)      // left
				ctx.Mem.Write32(pRect+4, 0)    // top
				ctx.Mem.Write32(pRect+8, 800)  // right
				ctx.Mem.Write32(pRect+12, 600) // bottom
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "GetWindowRect", func(ctx *ntapi.TrapContext) uint32 {
			pRect := ctx.Arg(1)
			if pRect != 0 {
				ctx.Mem.Write32(pRect, 100)    // left
				ctx.Mem.Write32(pRect+4, 100)  // top
				ctx.Mem.Write32(pRect+8, 900)  // right
				ctx.Mem.Write32(pRect+12, 700) // bottom
			}
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "SendMessageW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "PostMessageW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(user32, "DefWindowProcW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		// GetMessageW: return 0 = WM_QUIT for now (single iteration)
		// TODO: implement proper message loop with Wayland events
		d.RegisterAutoStubHandler(user32, "GetMessageW", func(ctx *ntapi.TrapContext) uint32 {
			pMsg := ctx.Arg(0)
			if pMsg != 0 {
				// MSG struct: hwnd(8) message(4) wParam(8) lParam(8) time(4) pt.x(4) pt.y(4)
				// Write WM_QUIT (0x0012) message
				ctx.Mem.Write64(pMsg, 0)       // hwnd = NULL
				ctx.Mem.Write32(pMsg+8, 0x12)  // message = WM_QUIT
				ctx.Mem.Write64(pMsg+12, 0)    // wParam
				ctx.Mem.Write64(pMsg+20, 0)    // lParam
				ctx.Mem.Write32(pMsg+28, 0)    // time
				ctx.Mem.Write32(pMsg+32, 0)    // pt.x
				ctx.Mem.Write32(pMsg+36, 0)    // pt.y
			}
			ctx.SetReturn(0) // 0 = WM_QUIT received
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
			ctx.SetReturn(0)
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
			ctx.SetReturn(ctx.Arg(0)) // return previous focus (same hwnd)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "GetFocus", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
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
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "BeginPaint", func(ctx *ntapi.TrapContext) uint32 {
			pPaint := ctx.Arg(1)
			hdc := gdiAlloc()
			if pPaint != 0 {
				ctx.Mem.Write64(pPaint, hdc)      // hdc
				ctx.Mem.Write32(pPaint+8, 1)      // fErase
				ctx.Mem.Write32(pPaint+12, 0)     // rcPaint.left
				ctx.Mem.Write32(pPaint+16, 0)     // rcPaint.top
				ctx.Mem.Write32(pPaint+20, 800)   // rcPaint.right
				ctx.Mem.Write32(pPaint+24, 600)   // rcPaint.bottom
			}
			ctx.SetReturn(hdc)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "EndPaint", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "GetDesktopWindow", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x00050000) // desktop window handle
			return 0
		})
		d.RegisterAutoStubHandler(user32, "GetParent", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "SetParent", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "GetMenu", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // no menu
			return 0
		})
		d.RegisterAutoStubHandler(user32, "SetMenu", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "CreateMenu", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(gdiAlloc())
			return 0
		})
		d.RegisterAutoStubHandler(user32, "CreatePopupMenu", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(gdiAlloc())
			return 0
		})
		d.RegisterAutoStubHandler(user32, "AppendMenuW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "InsertMenuW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "InsertMenuItemW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(user32, "DrawMenuBar", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
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
			ctx.SetReturn(1) // TRUE
			return 0
		})
	}

	// --- gdi32.dll ---
	if gdi32, ok := synthByName["gdi32.dll"]; ok {
		d.RegisterAutoStubHandler(gdi32, "CreateSolidBrush", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(gdiAlloc())
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
			ctx.SetReturn(gdiAlloc())
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
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "DeleteObject", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "SelectObject", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(gdiAlloc()) // return "previous" object
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
			ctx.SetReturn(1) // previous mode
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "SetBkColor", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x00FFFFFF) // previous color
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "SetTextColor", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x00000000) // previous color
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "TextOutW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "ExtTextOutW", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "BitBlt", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "PatBlt", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "StretchBlt", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
		d.RegisterAutoStubHandler(gdi32, "FillRect", func(ctx *ntapi.TrapContext) uint32 {
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

	// --- crypt32.dll ---
	if crypt32, ok := synthByName["crypt32.dll"]; ok {
		d.RegisterAutoStubHandler(crypt32, "CryptQueryObject", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE - no crypto
			return 0
		})
	}

	// --- advapi32.dll ---
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
		fmt.Fprintf(os.Stderr, "[pe] auto-synth %s: %d stubs (id base 0x%X)\n",
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

// loadBYODLLs loads real Windows DLLs from the sysroot directory.
// Returns updated module info, loaded modules map, and DLL load order (for DllMain).
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

loaded[strings.ToLower(mod.Name)] = mod
loadOrder = append(loadOrder, mod)
modules = append(modules, ntapi.ModuleInfo{
Name:      mod.Name,
FullPath:  `C:\Windows\System32\` + mod.Name,
BaseAddr:  mod.BaseAddr,
ImageSize: mod.ImageSize,
Entry:     mod.EntryPoint,
})

loader.ResolveImports(mem, mod, loaded)

for _, imp := range mod.Imports {
depName := strings.ToLower(imp.DLLName)
if !seen[depName] {
seen[depName] = true
queue = append(queue, depName)
}
}
}

return modules, loaded, loadOrder
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

package main

import (
"flag"
"fmt"
"os"
"path/filepath"
"strings"

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

func main() {
trace := flag.Bool("trace", false, "enable instruction trace to stderr")
memMB := flag.Int("mem", 256, "guest memory limit in MiB (advisory)")
sysroot := flag.String("sysroot", "", "path to Windows system DLL directory (for PE mode)")
regFile := flag.String("registry", "", "path to registry hive JSON file (for PE mode)")

flag.Usage = func() {
fmt.Fprintf(os.Stderr, "Usage: govm [flags] <binary> [args...]\n\n")
fmt.Fprintf(os.Stderr, "go-vm - in-process RISC-V / x86_64 / Windows PE Library OS\n\n")
fmt.Fprintf(os.Stderr, "Supports ELF (Linux) and PE (Windows) executables.\n")
fmt.Fprintf(os.Stderr, "PE mode is auto-detected from the file header (.exe/.dll or MZ magic).\n\n")
flag.PrintDefaults()
}
flag.Parse()

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
registerAutoSynthHandlers(mem, dispatcher, autoSynthDLLs, guestArgv)

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
os.Exit(exitErr.Code)
}
fmt.Fprintf(os.Stderr, "govm: PE runtime error: %v\n", err)
if regFile != "" {
registry.Save(regFile)
}
os.Exit(1)
}

if regFile != "" {
registry.Save(regFile)
}

tm.Wait()
}

// registerAutoSynthHandlers registers vmcall handlers for critical
// CRT and Win32 functions in auto-generated synthetic DLLs.
func registerAutoSynthHandlers(mem *mmu.MMU, d *ntapi.Dispatcher, dlls []*ntapi.SynthPE, argv []string) {
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
			ctx.SetReturn(0)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "SetLastError", func(ctx *ntapi.TrapContext) uint32 {
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
			// NULL → return base of main exe
			name := ctx.Arg(0)
			if name == 0 {
				ctx.SetReturn(0x400000) // typical image base
			} else {
				ctx.SetReturn(0)
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

		d.RegisterAutoStubHandler(kernel32, "SetUnhandledExceptionFilter", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // return NULL (no previous filter)
			return 0
		})

		d.RegisterAutoStubHandler(kernel32, "TlsGetValue", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})

		d.RegisterAutoStubHandler(kernel32, "Sleep", func(ctx *ntapi.TrapContext) uint32 {
			return 0 // no-op
		})

		d.RegisterAutoStubHandler(kernel32, "GetSystemInfo", func(ctx *ntapi.TrapContext) uint32 {
			si := ctx.Arg(0)
			// SYSTEM_INFO: zero-fill then set key fields
			for i := uint64(0); i < 48; i++ {
				ctx.Mem.Write8(si+i, 0)
			}
			ctx.Mem.Write16(si+0, 9)    // wProcessorArchitecture = AMD64
			ctx.Mem.Write32(si+4, 4096) // dwPageSize
			ctx.Mem.Write32(si+20, 1)   // dwNumberOfProcessors
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
			srcLen := int64(ctx.Arg(3))
			dstBuf := ctx.Arg(4)
			dstLen := int64(ctx.Arg(5))

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
			srcLen := int64(ctx.Arg(3))
			dstBuf := ctx.Arg(4)
			dstLen := int64(ctx.Arg(5))

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
			buf := ctx.Arg(1)
			size := ctx.Arg(2)
			name := []byte("C:\\pafish64.exe")
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
			mem.Write64(imp.IATSlot, addr)
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

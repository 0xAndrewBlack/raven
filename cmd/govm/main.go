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
registerAutoSynthHandlers(mem, dispatcher, autoSynthDLLs, guestArgv, cmdLine, `C:\`+filepath.Base(absPath))

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
func registerAutoSynthHandlers(mem *mmu.MMU, d *ntapi.Dispatcher, dlls []*ntapi.SynthPE, argv []string, cmdLine, imagePath string) {
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

		// FLS (Fiber Local Storage) - same implementation as TLS for single-threaded
		var flsNextSlot uint32 = 1
		flsValues := make(map[uint32]uint64)
		d.RegisterAutoStubHandler(kernel32, "FlsAlloc", func(ctx *ntapi.TrapContext) uint32 {
			slot := flsNextSlot
			flsNextSlot++
			ctx.SetReturn(uint64(slot))
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FlsGetValue", func(ctx *ntapi.TrapContext) uint32 {
			slot := uint32(ctx.Arg(0))
			val := flsValues[slot]
			ctx.SetReturn(val)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FlsSetValue", func(ctx *ntapi.TrapContext) uint32 {
			slot := uint32(ctx.Arg(0))
			val := ctx.Arg(1)
			flsValues[slot] = val
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "FlsFree", func(ctx *ntapi.TrapContext) uint32 {
			slot := uint32(ctx.Arg(0))
			delete(flsValues, slot)
			ctx.SetReturn(1) // TRUE
			return 0
		})

		d.RegisterAutoStubHandler(kernel32, "Sleep", func(ctx *ntapi.TrapContext) uint32 {
			return 0 // no-op
		})

		// Heap emulation via bump allocator
		const heapHandle = 0xBEEF0001
		var heapBase uint64
		var heapOffset uint64
		const heapMaxSize = 64 * 1024 * 1024 // 64MB
		heapAllocs := make(map[uint64]uint64) // addr → size

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
			flags := ctx.Arg(1)
			size := ctx.Arg(2)
			if size == 0 {
				size = 1
			}
			// Align to 16 bytes
			size = (size + 15) &^ 15
			if heapBase == 0 {
				heapBase = ctx.Mem.Mmap(0, heapMaxSize, mmu.PermRead|mmu.PermWrite)
			}
			if heapOffset+size > heapMaxSize {
				ctx.SetReturn(0) // out of memory
				return 0
			}
			addr := heapBase + heapOffset
			heapOffset += size
			heapAllocs[addr] = size
			if flags&0x08 != 0 { // HEAP_ZERO_MEMORY
				// Already zero (Mmap returns zeroed pages)
			}
			ctx.SetReturn(addr)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "HeapFree", func(ctx *ntapi.TrapContext) uint32 {
			// No-op for bump allocator
			ctx.SetReturn(1) // TRUE
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "HeapReAlloc", func(ctx *ntapi.TrapContext) uint32 {
			flags := ctx.Arg(1)
			oldPtr := ctx.Arg(2)
			newSize := ctx.Arg(3)
			if newSize == 0 {
				newSize = 1
			}
			newSize = (newSize + 15) &^ 15
			if heapBase == 0 {
				heapBase = ctx.Mem.Mmap(0, heapMaxSize, mmu.PermRead|mmu.PermWrite)
			}
			if heapOffset+newSize > heapMaxSize {
				ctx.SetReturn(0)
				return 0
			}
			newAddr := heapBase + heapOffset
			heapOffset += newSize
			// Copy old data
			oldSize := heapAllocs[oldPtr]
			if oldSize > 0 && oldPtr != 0 {
				copyLen := oldSize
				if newSize < copyLen {
					copyLen = newSize
				}
				for i := uint64(0); i < copyLen; i++ {
					b, _ := ctx.Mem.Read8(oldPtr + i)
					ctx.Mem.Write8(newAddr+i, b)
				}
			}
			heapAllocs[newAddr] = newSize
			if flags&0x08 != 0 { // HEAP_ZERO_MEMORY (for extra bytes)
				// Already zero from Mmap
			}
			ctx.SetReturn(newAddr)
			return 0
		})
		d.RegisterAutoStubHandler(kernel32, "HeapSize", func(ctx *ntapi.TrapContext) uint32 {
			ptr := ctx.Arg(2)
			if sz, ok := heapAllocs[ptr]; ok {
				ctx.SetReturn(sz)
			} else {
				ctx.SetReturn(0xFFFFFFFFFFFFFFFF) // -1 = error
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

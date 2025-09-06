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

if sysroot != "" {
modules, loadedModules = loadBYODLLs(mem, sysroot, result.MainModule, modules, loadedModules)
}

// Resolve imports for the main module
loader.ResolveImports(mem, result.MainModule, loadedModules)

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

// loadBYODLLs loads real Windows DLLs from the sysroot directory.
func loadBYODLLs(mem *mmu.MMU, sysroot string, mainMod *loader.PEModule,
modules []ntapi.ModuleInfo, loaded map[string]*loader.PEModule) ([]ntapi.ModuleInfo, map[string]*loader.PEModule) {

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

return modules, loaded
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

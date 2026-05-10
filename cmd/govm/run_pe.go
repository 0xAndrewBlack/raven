//go:build guest_windows

package main

import (
	"bufio"
	"bytes"
	"compress/flate"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mirkobrombin/Raven/pkg/arch"
	comctl32 "github.com/mirkobrombin/Raven/pkg/comctl32"
	gdi "github.com/mirkobrombin/Raven/pkg/gdi"
	"github.com/mirkobrombin/Raven/pkg/jit"
	"github.com/mirkobrombin/Raven/pkg/loader"
	ravelog "github.com/mirkobrombin/Raven/pkg/log"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
	"github.com/mirkobrombin/Raven/pkg/ntobj"
	"github.com/mirkobrombin/Raven/pkg/thread"
	"github.com/mirkobrombin/Raven/pkg/vfs"
	"github.com/mirkobrombin/Raven/pkg/win32"
	"github.com/mirkobrombin/Raven/pkg/win32k"
	"github.com/mirkobrombin/Raven/pkg/wl"
	"github.com/mirkobrombin/Raven/pkg/x64"
)

// runPE runs a Windows PE binary with the NT subsystem.
func runPE(absPath string, guestArgv []string, sysroot, regFile string, trace, traceSyscall bool, enableWayland bool, autoScript, callExport, renderPNG string) {
	mem := mmu.New()
	if os.Getenv("RAVEN_FLAT_MEM") != "" {
		if err := mem.EnableFlatBacking(); err != nil {
			ravelog.Logf("[mmu] flat backing unavailable: %v\n", err)
		} else {
			ravelog.Logf("[mmu] flat 4GiB backing enabled\n")
		}
	}
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
	fs.MkdirAll("/Windows/System32/Fonts")
	fs.MkdirAll("/Windows/Temp")
	fs.MkdirAll("/Windows/TEMP")
	fs.MkdirAll("/Users/user/AppData/Local/Temp")
	fs.MkdirAll("/Program Files")
	userName := shellUserName()
	fs.MkdirAll("/Users/" + userName + "/.config")
	fs.MkdirAll("/Users/" + userName + "/AppData/Local")
	fs.MkdirAll("/Users/" + userName + "/AppData/Roaming")
	populateVFSFromHost(fs, filepath.Join("testdata", "npp"), "/Users/"+userName+"/.config/Notepad++")
	populateVFSFromHost(fs, filepath.Join("testdata", "npp"), "/Users/"+userName+"/AppData/Roaming/Notepad++")
	for _, name := range []string{"config.xml", "contextMenu.xml", "doLocalConf.xml", "langs.xml", "shortcuts.xml", "stylers.xml", "toolbarIcons.xml"} {
		if data, err := os.ReadFile(filepath.Join("testdata", "npp", name)); err == nil {
			fs.CreateFile("/Users/"+name, data, 0644)
		}
	}

	// Populate VFS with the PE's directory contents
	peDir := filepath.Dir(absPath)
	peDirBase := filepath.Base(peDir)
	populateVFSFromHost(fs, peDir, "/"+peDirBase)
	fs.Cwd = "/" + peDirBase
	guestArgv, hostArgPaths := preparePEGuestArgs(fs, absPath, guestArgv)

	// Detect Wise 5.x self-extracting installer and extract game files proactively.
	// This bypasses the native bytecode conditional that gates file extraction in the
	// Wise script interpreter (which we can't intercept).
	if raw, err := os.ReadFile(absPath); err == nil && len(raw) > 0x100 {
		if raw[0] == 'M' && raw[1] == 'Z' {
			// Check for Wise installer signature: overlay containing deflatable script
			// with %MAINDIR% file entries.
			peOff := int(binary.LittleEndian.Uint32(raw[0x3c:]))
			if peOff+0x100 < len(raw) && string(raw[peOff:peOff+4]) == "PE\x00\x00" {
				numSec := int(binary.LittleEndian.Uint16(raw[peOff+6:]))
				secStart := peOff + 0x18 + int(binary.LittleEndian.Uint16(raw[peOff+0x14:]))
				ovOff := 0
				for i := 0; i < numSec; i++ {
					off := secStart + i*0x28
					end := int(binary.LittleEndian.Uint32(raw[off+0x14:])) + int(binary.LittleEndian.Uint32(raw[off+0x10:]))
					if end > ovOff {
						ovOff = end
					}
				}
				if ovOff > 0 && ovOff < len(raw)-0x100 {
					// Try to decompress script at overlay+0x51
					scriptOff := ovOff + 0x51
					if scriptOff < len(raw) {
						r := flate.NewReader(bytes.NewReader(raw[scriptOff:]))
						script, serr := io.ReadAll(r)
						r.Close()
						if serr == nil && bytes.Contains(script, []byte("%MAINDIR%\\")) {
							ravelog.Logf("[wise-detect] Wise 5.x installer detected, extracting files...\n")
							if err := wiseExtractArchive(absPath, fs, "/DXBall"); err != nil {
								ravelog.Logf("[wise-detect] extraction error: %v\n", err)
							} else {
								wiseExtractDone = true
							}
						}
					}
				}
			}
		}
	}

	// After Wise extraction, redirect PE loading to the extracted game EXE
	// instead of continuing with the installer.
	if wiseExtractDone && wiseGameHostPath != "" {
		ravelog.Logf("[wise-detect] redirecting PE load to extracted game: %s\n", wiseGameHostPath)
		absPath = wiseGameHostPath
		peDir = filepath.Dir(absPath)
		peDirBase = filepath.Base(peDir)
		fs.Cwd = "/" + peDirBase
		guestArgv = []string{absPath}
		guestArgv, hostArgPaths = preparePEGuestArgs(fs, absPath, guestArgv)
		// Also ensure the game directory is populated in VFS from host (if present)
		// The game files are already in /DXBall from Wise extraction.
	}

	// Load the main PE
	result, err := loader.LoadPE(absPath, mem, guestArgv, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "govm: PE load error: %v\n", err)
		os.Exit(1)
	}
	// PE32 and PE32+ are both supported; set MMU/CPU mode accordingly.
	if !result.MainModule.Is64 {
		mem.Mode32 = true
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
	// PatchCRTFunctions writes x64-only inline code; in a PE32 process it would
	// decode as garbage (0x4C = dec esp) and corrupt the stack. For 32-bit,
	// keep the ntdll CRT stubs as vmcall traps (handlers registered below).
	if !mem.Mode32 {
		ntapi.PatchCRTFunctions(synthNtdll, mem)
	}
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
		mem.Write32(kuserAddr+0x014, uint32(ft))     // LowPart
		mem.Write32(kuserAddr+0x018, uint32(ft>>32)) // High1Time
		mem.Write32(kuserAddr+0x01C, uint32(ft>>32)) // High2Time (duplicate)
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

	// SystemCall pointer at +0x0300: on 32-bit ReactOS/Windows, ntdll and win32
	// (gdi32/user32) syscall stubs dispatch via
	//   mov eax, <service#>; mov edx, 0x7FFE0300; call dword ptr [edx]
	// i.e. they call SharedUserData->SystemCall. Point it at a tiny guest
	// trampoline that executes our trap instruction (vmcall, 0F 01 C1) and
	// returns; the trap enters the NT/win32k dispatcher with EAX = service
	// number. Without this the call targets uninitialized memory and faults.
	win32kTramp := mem.Mmap(0, 16, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	mem.Write8(win32kTramp+0, 0x0F) // vmcall
	mem.Write8(win32kTramp+1, 0x01)
	mem.Write8(win32kTramp+2, 0xC1)
	mem.Write8(win32kTramp+3, 0xC3) // ret
	mem.Write32(kuserAddr+0x0300, uint32(win32kTramp))
	ravelog.Logf("[kuser] SystemCall stub at 0x7FFE0300 → trampoline 0x%x\n", win32kTramp)

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

	// Register the main module so loadBYODLLs does not load a second copy when
	// the main image is itself a DLL that dependents import (e.g. -call-export
	// gdi32.dll, which user32 imports). Without this the main copy runs at its
	// preferred ImageBase while a relocated duplicate is loaded for dependents.
	if result.MainModule != nil && result.MainModule.Name != "" {
		mainKey := strings.ToLower(result.MainModule.Name)
		if _, exists := loadedModules[mainKey]; !exists {
			loadedModules[mainKey] = result.MainModule
		}
	}

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
				mem.Write32(entryAddr, 0x80)          // flags = 0x80 (initialized, no debug output)
				mem.Write64(entryAddr+8, 0)           // CS.DebugInfo = NULL
				mem.Write32(entryAddr+16, 0xFFFFFFFF) // CS.LockCount = -1 (unlocked)
				mem.Write32(entryAddr+20, 0)          // CS.RecursionCount = 0
			}
			if trace {
				ravelog.Logf("[pe] initialized ucrtbase debug channel table (%d entries)\n", numChannels)
			}
		}
	}

	// Auto-generate synthetic stub DLLs for any unresolved import DLLs
	autoSynthDLLs, synthAliases := autoSynthUnresolved(mem, result.MainModule, loadedModules)
	// Pre-create shcore.dll so DPI functions are available via GetProcAddress
	synthShcore := ntapi.GenerateSynthDLL(mem, "shcore.dll", []string{}, 0)
	// Programs may load either CRT dynamically without importing it. Keep empty
	// synthetic modules available so registered handlers can be materialized by
	// GetProcAddress on demand.
	synthMsvcrt := ntapi.GenerateSynthDLL(mem, "msvcrt.dll", []string{}, 0)
	synthUcrtbase := ntapi.GenerateSynthDLL(mem, "ucrtbase.dll", []string{}, 0)
	// Games commonly resolve the multimedia timer API dynamically.
	synthWinmm := ntapi.GenerateSynthDLL(mem, "winmm.dll", []string{
		"timeBeginPeriod",
		"timeEndPeriod",
		"timeGetDevCaps",
		"timeGetSystemTime",
		"timeGetTime",
		"timeKillEvent",
		"timeSetEvent",
	}, 0)
	synthUser32 := ntapi.GenerateSynthDLL(mem, "user32.dll", []string{}, 0)
	// Include pre-generated full DLLs so their handlers are wired in registerAutoSynthHandlers.
	autoSynthDLLs = append(autoSynthDLLs, synthKernel32, synthComctl32, synthOleaut32, synthShcore)
	for _, coreSynth := range []*ntapi.SynthPE{synthMsvcrt, synthUcrtbase, synthWinmm, synthUser32} {
		if _, loaded := loadedModules[strings.ToLower(coreSynth.Name)]; loaded {
			continue
		}
		found := false
		for _, existing := range autoSynthDLLs {
			if strings.EqualFold(existing.Name, coreSynth.Name) {
				found = true
				break
			}
		}
		if !found {
			autoSynthDLLs = append(autoSynthDLLs, coreSynth)
		}
	}
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
	// Register forwarding DLL aliases (api-ms-win-crt-* → ucrtbase.dll, etc.) so
	// that ResolveImports can find and patch their IAT entries correctly.
	for alias, canonical := range synthAliases {
		if mod, ok := loadedModules[canonical]; ok {
			loadedModules[alias] = mod
		}
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
		case "comctl32.dll":
			// Map undocumented ordinals used by many Win32 apps
			ordMap := map[uint16]string{
				17:  "InitCommonControls",
				345: "PropertySheetW",
				381: "SetWindowSubclass",
				410: "SetWindowSubclass",
				411: "GetWindowSubclass",
				412: "RemoveWindowSubclass",
				413: "DefSubclassProc",
			}
			for ord, name := range ordMap {
				if addr, ok := synth.Exports[name]; ok {
					synth.ExportOrds[ord] = addr
				}
			}
		case "dsound.dll":
			// Windows DSOUND ordinal 1 = DirectSoundCreate.
			// Auto-synth creates "ord_1" placeholder; rename to real name so
			// registerDsoundHandlers can wire up the handler.
			dsOrdNames := map[uint16]string{
				1: "DirectSoundCreate",
				2: "DirectSoundEnumerateA",
				3: "DirectSoundEnumerateW",
				6: "DirectSoundCaptureCreate",
				7: "DirectSoundCaptureEnumerateA",
				8: "DirectSoundCaptureEnumerateW",
			}
			for ord, name := range dsOrdNames {
				placeholder := fmt.Sprintf("ord_%d", ord)
				if addr, ok := synth.Exports[placeholder]; ok {
					synth.Exports[name] = addr
					synth.ExportOrds[ord] = addr
				} else if addr, ok := synth.Exports[name]; ok {
					synth.ExportOrds[ord] = addr
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
		ntapi.RegisterExceptionTable(result.MainModule.BaseAddr, result.MainModule.ImageSize, exceptionTable)
	}
	for _, mod := range loadedModules {
		if mod == nil || mod.BaseAddr == 0 || mod.ExceptionDirRVA == 0 || mod.BaseAddr == result.MainModule.BaseAddr {
			continue
		}
		ntapi.RegisterExceptionTable(
			mod.BaseAddr,
			mod.ImageSize,
			ntapi.ParseExceptionDirectory(mem, mod.BaseAddr, mod.ExceptionDirRVA, mod.ExceptionDirSize),
		)
	}

	// Patch CRT data exports (variables like _acmdln, _commode, etc.)
	patchCRTDataExports(mem, result.MainModule, guestArgv)

	// Build command line
	cmdLine := windowsCommandLine(guestArgv)

	// Stack layout - below KUSER_SHARED_DATA (0x7FFE0000)
	stackTop := uint64(0x7FFD0000)
	stackSize := uint64(64 * 1024 * 1024)
	if !result.MainModule.Is64 {
		// PE32: keep stack in lower 2GB
		stackTop = 0x00FF0000
		stackSize = 8 * 1024 * 1024
	}

	procArch := "AMD64"
	if !result.MainModule.Is64 {
		procArch = "x86"
	}
	guestEnvironment := []string{
		"PATH=C:\\Windows\\System32;C:\\Windows",
		"SYSTEMROOT=C:\\Windows",
		"WINDIR=C:\\Windows",
		"TEMP=C:\\Windows\\TEMP",
		"TMP=C:\\Windows\\TEMP",
		"OS=Windows_NT",
		"PROCESSOR_ARCHITECTURE=" + procArch,
		"NUMBER_OF_PROCESSORS=4",
	}

	// Initialize PEB/TEB
	guestImagePath := `C:\` + peDirBase + `\` + filepath.Base(absPath)
	guestCurrentDir := `C:\` + peDirBase
	procState, err := ntapi.InitProcess(mem, &ntapi.ProcessInit{
		ImageBase:   result.MainModule.BaseAddr,
		ImageSize:   result.MainModule.ImageSize,
		EntryPoint:  result.MainModule.EntryPoint,
		CommandLine: cmdLine,
		ImagePath:   guestImagePath,
		CurrentDir:  guestCurrentDir,
		Environment: guestEnvironment,
		ProcessId:   1000,
		ThreadId:    1004,
		StackBase:   stackTop,
		StackLimit:  stackTop - stackSize,
		Is32:        !result.MainModule.Is64,
	}, modules)
	if err != nil {
		fmt.Fprintf(os.Stderr, "govm: PEB/TEB init error: %v\n", err)
		os.Exit(1)
	}
	// Tell the dispatcher where the PE32 win32k SystemCall trampoline lives, so
	// it can recognize syscalls arriving via `call [0x7FFE0300]` and read their
	// stack args at the right offset (one extra return address).
	procState.Win32kTrampoline = win32kTramp

	// Initialize NLS code page data in PEB before DllMain
	ntapi.InitNlsData(mem, procState.PEBAddr, sysroot)

	// Load TrueType fonts from sysroot for real font rendering
	if sysroot != "" {
		fontsDir := sysroot + "/Windows/Fonts"
		gdi.AddFontSearchDir(fontsDir)
	}

	// Create the trap dispatcher
	dispatcher := ntapi.NewDispatcher(mem, fs, handles, registry, procState, synthNtdll, synthWin32u)
	if os.Getenv("RAVEN_PROFILE_HANDLERS") != "" {
		dispatcher.EnableHandlerProfile()
	}
	if os.Getenv("RAVEN_TRACE_STDCALL") != "" {
		dispatcher.EnableStdcallTrace()
	}
	if os.Getenv("RAVEN_WATCH_STACKVAL") != "" {
		// Catch whatever writes the sentinel 0x20000010 onto the guest stack
		// (it clobbers a saved EBX and breaks kkrieger's pump). Cover the whole
		// 32-bit stack region; the callback filters by value and dumps a Go
		// stack trace once so the culprit (handler vs guest interpreter) is clear.
		mem.WatchAddr = 0x7ff00000
		mem.WatchSize = 0x00100000
		var stackValHit bool
		mem.WatchCB = func(addr, val uint64, size int) {
			if stackValHit || size != 4 || uint32(val) != 0x20000010 {
				return
			}
			stackValHit = true
			buf := make([]byte, 4096)
			n := runtime.Stack(buf, false)
			ravelog.Logf("[stackval] 0x20000010 written to stack @0x%x\n%s\n", addr, buf[:n])
		}
	}
	// PE32: ntdll CRT stubs (memcpy/memmove/memset/strlen/strcmp) are served by
	// Go handlers since the x64 inline patch is skipped for 32-bit.
	if mem.Mode32 {
		ntapi.RegisterCRT32Handlers(dispatcher, synthNtdll)
	}
	dispatcher.SetTrace(trace)
	dispatcher.SetTraceSyscall(traceSyscall)
	dispatcher.SetSysRoot(sysroot)

	// Register no-op stubs for any remaining unresolved ordinal imports so
	// cpu-recover never needs to handle them (they just return 0 quietly).
	patchUnresolvedOrdinals(mem, dispatcher, result.MainModule)

	is32 := !result.MainModule.Is64

	handlerSynthDLLs := make([]*ntapi.SynthPE, 0, len(autoSynthDLLs)+2)
	handlerSynthDLLs = append(handlerSynthDLLs, autoSynthDLLs...)
	handlerSynthDLLs = append(handlerSynthDLLs, synthNtdll, synthWin32u)

	// Register auto-synth stub names with the dispatcher for trace output
	for _, synth := range handlerSynthDLLs {
		dispatcher.RegisterAutoStubNames(synth)
		// Apply Win32 API arg counts for PE32 stdcall cleanup
		if is32 {
			dispatcher.ApplyWin32ArgCounts(synth)
		}
		// Mark C runtime DLLs as cdecl (caller cleans up args, not callee)
		dllLower := strings.ToLower(synth.Name)
		if dllLower == "msvcrt.dll" || dllLower == "ucrtbase.dll" ||
			strings.HasPrefix(dllLower, "msvcp") || strings.HasPrefix(dllLower, "vcruntime") {
			dispatcher.MarkCdeclModule(synth)
		}
	}

	// Register handlers for critical CRT/Win32 functions
	peBasename := filepath.Base(filepath.Dir(absPath))
	winImagePath := `C:\` + peBasename + `\` + filepath.Base(absPath)
	var tmPtr *thread.Manager

	// Pre-allocate the heap region and wire to TEB for inline HeapAlloc.
	// Must happen before registerAutoSynthHandlers so sharedHeapAlloc can read it.
	const heapInlineSize = 256 * 1024 * 1024 // 256MB
	heapRegion := mem.Mmap(0, heapInlineSize, mmu.PermRead|mmu.PermWrite)
	if is32 {
		mem.Write32(procState.TEBAddr+ntapi.Teb32HeapBase, uint32(heapRegion))
		mem.Write32(procState.TEBAddr+ntapi.Teb32HeapOffset, 0)
	} else {
		mem.Write64(procState.TEBAddr+ntapi.TebHeapBase, heapRegion)
		mem.Write64(procState.TEBAddr+ntapi.TebHeapOffset, 0)
	}

	var renderSnapshot func()
	renderSnapshotProxy := func() {
		if renderSnapshot != nil {
			renderSnapshot()
		}
	}
	hctx := registerAutoSynthHandlers(mem, dispatcher, handlerSynthDLLs, guestArgv, cmdLine, winImagePath, absPath, handles, procState, exceptionTable, result.MainModule, loadedModules, &tmPtr, bootTime, registry, autoScript, enableWayland, renderSnapshotProxy, renderPNG, hostArgPaths)

	// Real-DLL win32k handlers, registered LAST so they win the dispatcher map
	// over the HLE win32u handlers (gdiMgr) for a real ReactOS gdi32/user32.

	// Set up Win32k subsystem
	w32k := win32k.New(mem, handles)
	gdi := win32k.NewGDI(mem, w32k)
	w32kTrap := win32k.NewTrapDispatcher(w32k, gdi)
	w32kTrap.RegisterAll(dispatcher)

	// Create x64 CPU
	c := x64.New(mem)
	if os.Getenv("RAVEN_PROFILE_OPCODES") != "" {
		c.EnableOpcodeProfile()
	}
	if os.Getenv("RAVEN_WATCH_EBX") != "" {
		c.EnableEBXWatch()
	}
	if slot := os.Getenv("RAVEN_WATCH_SLOT"); slot != "" {
		// Watch a single guest stack address (deterministic across runs) for
		// every write, logging value + guest RIP, to find what overwrites the
		// saved-EBX slot that the texture-setup function's epilogue pops.
		var addr uint64
		fmt.Sscanf(slot, "0x%x", &addr)
		mem.WatchAddr = addr
		mem.WatchSize = 4
		mem.WatchCB = func(a, val uint64, size int) {
			if size == 4 {
				ravelog.Logf("[slot] write @0x%x val=0x%08x guestRIP=0x%x\n", a, uint32(val), c.GetPC())
			}
		}
	}
	if os.Getenv("RAVEN_LOG_INSTRET") != "" {
		go func() {
			var last uint64
			for {
				time.Sleep(10 * time.Second)
				now := c.GetInstret()
				ravelog.Logf("[instret] main-thread %d insns in 10s (%.1f M/s)\n", now-last, float64(now-last)/10e6)
				last = now
			}
		}()
	}
	if !result.MainModule.Is64 {
		c.Mode32 = true
	}
	c.SetPC(result.EntryPoint)
	c.SetSP(result.StackPtr)
	ravelog.Logf("[pe] starting entry at 0x%x SP=0x%x mode32=%v\n", result.EntryPoint, result.StackPtr, !result.MainModule.Is64)
	// Watch for writes to the return address area around 0x7ffcff40
	if !result.MainModule.Is64 {
		// Dump function prologue at 0x40cc60 and code at 0x40d03f (the good path)
		for _, base := range []uint64{0x40cc60, 0x40d03f} {
			var codeBuf [32]byte
			for i := range codeBuf {
				codeBuf[i], _ = mem.Read8(base + uint64(i))
			}
			ravelog.Logf("[CODE-DUMP] 0x%x: % x\n", base, codeBuf[:])
		}
		// DXBall: force DirectX availability flag - the game's packer
		// normally sets [0x434998] during import resolution, but our
		// synthetic DLL system resolves imports differently.
		mem.Write32(0x434998, 1)
	}

	// PE32 NULL-guard page: make page 0 executable with a vtable that
	// returns S_OK for any method call on a NULL object pointer.
	// Prevents crashes from null COM object dereferences.
	if c.Mode32 {
		// Map page 0 as RWX (MapPage handles both new and existing pages)
		mem.MapPage(0, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
		// Fill first 0x200 bytes with pointers to a "ret 8" stub at 0xF00
		stubAddr := uint32(0xF00)
		for off := uint32(0); off < 0x200; off += 4 {
			mem.Write32(uint64(off), stubAddr)
		}
		// Write "xor eax,eax; ret 8" stub at 0xF00
		mem.Write8(0xF00, 0x31) // xor eax, eax
		mem.Write8(0xF01, 0xC0)
		mem.Write8(0xF02, 0xC2) // ret 8
		mem.Write8(0xF03, 0x08)
		mem.Write8(0xF04, 0x00)
	}
	if c.Mode32 {
		c.SetTLS(procState.TEBAddr) // FS points to TEB (x86 Win32 convention)
	} else {
		c.SetGSBase(procState.TEBAddr) // GS points to TEB (x64 Windows convention)
	}

	// Wire JIT compiler
	jitCache := jit.NewCache(mem)
	jitPE32 := c.Mode32 && os.Getenv("RAVEN_JIT_PE32_EXPERIMENTAL") != ""
	if os.Getenv("RAVEN_JIT") != "" && (!c.Mode32 || jitPE32) {
		x64.NewJITCompiler(c, mem).Enable()
		ravelog.Logf("[jit] enabled mode32=%v\n", c.Mode32)
	} else if os.Getenv("RAVEN_JIT") != "" {
		ravelog.Logf("[jit] disabled for PE32 guests\n")
	}
	_ = jitCache // JIT disabled - needs debugging for NPP

	// Wire up implicit TLS (__declspec(thread)) if the PE has a TLS directory.
	if result.MainModule.TLSDataAddr != 0 {
		if is32 {
			tlsSlotsArray := mem.Mmap(0, 64*4, mmu.PermRead|mmu.PermWrite)
			mem.Write32(tlsSlotsArray+0, uint32(result.MainModule.TLSDataAddr))
			mem.Write32(procState.TEBAddr+ntapi.Teb32ThreadLocalStorage, uint32(tlsSlotsArray))
		} else {
			tlsSlotsArray := mem.Mmap(0, 64*8, mmu.PermRead|mmu.PermWrite)
			mem.Write64(tlsSlotsArray+0, result.MainModule.TLSDataAddr)
			mem.Write64(procState.TEBAddr+0x58, tlsSlotsArray)
		}
	}

	// Allocate FLS data array in guest memory for inline FlsGetValue/FlsSetValue.
	const flsMaxSlots = 128
	var flsDataArray uint64
	if is32 {
		flsDataArray = mem.Mmap(0, flsMaxSlots*4, mmu.PermRead|mmu.PermWrite)
		mem.Write32(procState.TEBAddr+ntapi.Teb32FlsData, uint32(flsDataArray))
	} else {
		flsDataArray = mem.Mmap(0, flsMaxSlots*8, mmu.PermRead|mmu.PermWrite)
		mem.Write64(procState.TEBAddr+ntapi.TebFlsData, flsDataArray)
	}

	// Map a zero-filled null page so that null-pointer dereferences with small
	// offsets (like [rcx+0x28] with rcx=0) read/write zero instead of segfaulting.
	// Many C++ vtable dispatch patterns null-check the loaded value after reading,
	// and some code writes to null-derived pointers after a failed allocation.
	mem.MapRange(0, 0x10000, mmu.PermRead|mmu.PermWrite) // force-map pages 0-0xFFFF

	// Patch hot Win32 API stubs with inline x64 code to avoid vmcall overhead.
	// Skip for PE32 - the inline stubs use GS-segment and 64-bit instructions.
	if !is32 {
		patchHotStubs(mem, autoSynthDLLs, flsDataArray)
	}

	if trace && exceptionTable != nil {
		ravelog.Logf("[seh] parsed %d RUNTIME_FUNCTION entries from .pdata\n", len(exceptionTable.Entries))
	}

	// Set up handlers
	c.SetVmcallHandler(dispatcher.Handle) // NT trap handler (vmcall import thunks)

	// win32k bridge: real DLLs reach the GUI engines through numbered syscalls.
	// x64 syscall convention: service index in EAX; args in R10, RDX, R8, R9,
	// then the stack (rcx is clobbered by the syscall instruction, so the stub
	// copies it into r10). Anything that isn't a win32k service falls through to
	// the NT trap dispatcher (preserving the prior syscall behavior).
	w32kBridge := newWin32kBridge(mem, 1280, 1024)
	if renderPNG != "" {
		renderSnapshot = func() {
			if err := w32kBridge.RenderPNG(renderPNG); err != nil {
				ravelog.Logf("[render-png] %v\n", err)
				return
			}
			ravelog.Logf("[render-png] wrote %s\n", renderPNG)
		}
	}
	// Real-DLL win32k handlers (NtUser*/NtGdi*) over winmgr/gfx, registered LAST
	// so they win the dispatcher map over the HLE win32u stubs. PE32 + sysroot.
	if procState.Is32 && sysroot != "" {
		registerRealWin32kHandlers(dispatcher, w32kBridge)
	}
	syscallHandler := func(cpu arch.CPU) {
		idx := uint32(cpu.SyscallNum())
		if rr, ok := cpu.(ntapi.RegisterReader); ok {
			args := []uint64{rr.ReadReg(10), rr.ReadReg(2), rr.ReadReg(8), rr.ReadReg(9)}
			sp := rr.ReadReg(4)
			for i := 0; i < 4; i++ {
				v, _ := mem.Read64(sp + 0x28 + uint64(i)*8)
				args = append(args, v)
			}
			if ret, name, ok := w32kBridge.dispatch(idx, args); ok {
				if traceSyscall {
					ravelog.Logf("[win32k] %s (idx=0x%x) -> 0x%x\n", name, idx, ret)
				}
				cpu.SetSyscallReturn(ret)
				return
			}
		}
		// Not a win32k service: hand off to the NT trap dispatcher.
		dispatcher.Handle(cpu)
	}
	c.SetSyscallHandler(syscallHandler)

	// Thread manager
	tm := thread.NewManager(mem, syscallHandler)
	tmPtr = tm
	tm.SetExitHook(hctx.cleanupMessageCPU)
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

		// Call TLS callbacks for each DLL that has them (DLL_PROCESS_ATTACH)
		for _, dll := range dllLoadOrder {
			for _, cb := range dll.TLSCallbacks {
				if cb == 0 {
					continue
				}
				ravelog.Logf("[pe] calling TLS callback for %s at 0x%x\n", dll.Name, cb)
				if err := ntapi.CallDllMain(c, mem, trampoline, dll.BaseAddr, cb, trace); err != nil {
					if _, isExit := err.(*arch.ExitError); isExit {
						os.Exit(1)
					}
					ravelog.Logf("[pe] warning: TLS callback 0x%x for %s failed: %v\n", cb, dll.Name, err)
				}
			}
		}

		// Call TLS callbacks for the main EXE
		for _, cb := range result.MainModule.TLSCallbacks {
			if cb == 0 {
				continue
			}
			ravelog.Logf("[pe] calling EXE TLS callback at 0x%x\n", cb)
			if err := ntapi.CallDllMain(c, mem, trampoline, result.MainModule.BaseAddr, cb, trace); err != nil {
				if _, isExit := err.(*arch.ExitError); isExit {
					os.Exit(1)
				}
				ravelog.Logf("[pe] warning: EXE TLS callback 0x%x failed: %v\n", cb, err)
			}
		}

		// Restore CPU state for main entry
		c.SetPC(result.EntryPoint)
		c.SetSP(result.StackPtr)
		ravelog.Logf("[pe] DllMain phase complete, starting main entry at 0x%x SP=0x%x\n", result.EntryPoint, result.StackPtr)
		// Debug: dump stack top to verify exit sentinel
		for i := uint64(0); i < 32; i += 4 {
			v, _ := mem.Read32(result.StackPtr + i)
			ravelog.Logf("[pe] stack[SP+0x%x] = 0x%08x\n", i, v)
		}
	}

	// DLL export check: load a real DLL, run its DllMain, call an export.
	if callExport != "" {
		doCallExport(c, mem, result.MainModule, callExport, trace)
		if renderPNG != "" {
			if err := w32kBridge.RenderPNG(renderPNG); err != nil {
				fmt.Fprintf(os.Stderr, "[render-png] %v\n", err)
			} else {
				fmt.Printf("[render-png] wrote %s\n", renderPNG)
			}
		}
		return
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

	// Automation goroutine is now started inside registerAutoSynthHandlers.

	// Run the PE
rerun:
	if err := mainThread.CPU.Run(); err != nil {
		if exitErr, ok := err.(*arch.ExitError); ok {
			if regFile != "" {
				registry.Save(regFile)
			}
			pprof.StopCPUProfile()
			os.Exit(exitErr.Code)
		}
		errMsg := err.Error()
		// Handle __fastfail (INT 0x29) - typically GS cookie failure.
		// Instead of terminating, rewind to the message loop entry.
		if strings.Contains(errMsg, "__fastfail") {
			fmt.Fprintf(os.Stderr, "govm: %s - attempting to survive\n", errMsg)
			if msgLoopSP != 0 && msgLoopPC != 0 {
				c.SetSP(msgLoopSP)
				c.SetPC(msgLoopPC)
				goto rerun
			}
		}
		fmt.Fprintf(os.Stderr, "govm: PE runtime error: %v\n", err)
		// Dump registers and stack for debugging
		sp := c.GetSP()
		fmt.Fprintf(os.Stderr, "  RIP=0x%x RSP=0x%x\n", c.GetPC(), sp)
		regNames := []string{"RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI",
			"R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"}
		for i, name := range regNames {
			fmt.Fprintf(os.Stderr, "  %s=0x%x", name, c.ReadReg(i))
			if i%4 == 3 {
				fmt.Fprintln(os.Stderr)
			}
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

func drawMenuBitmapPixels(window *wl.Window, pixels []uint32, sourceWidth, width, height int, x, y int32, monochrome bool, monoColor uint32) bool {
	if window == nil || sourceWidth <= 0 || width <= 0 || height <= 0 || len(pixels) < sourceWidth*height {
		return false
	}
	for py := 0; py < height; py++ {
		for px := 0; px < width; px++ {
			color := pixels[py*sourceWidth+px]
			if monochrome {
				if color&0x00ffffff == 0x00ffffff {
					continue
				}
				color = 0xff000000 | monoColor&0x00ffffff
			}
			if color>>24 == 0 {
				continue
			}
			dx, dy := x+int32(px), y+int32(py)
			if dx < 0 || dy < 0 || dx >= window.Width || dy >= window.Height+window.TitleBarH {
				continue
			}
			offset := int(dy*window.Stride + dx*4)
			if offset+3 >= len(window.Pix) {
				continue
			}
			window.Pix[offset] = byte(color)
			window.Pix[offset+1] = byte(color >> 8)
			window.Pix[offset+2] = byte(color >> 16)
			window.Pix[offset+3] = 0xff
		}
	}
	return true
}

// runAutoScript parses and executes a semicolon-separated automation script.
// Format: "<delay_sec>:<action>:<args>;..."
// Actions: screenshot:<path>, click:<x>,<y>, key:<keycode>, chord:<modifier>,<keycode>
func runAutoScript(script string, disp *wl.Display) {
	type autoCmd struct {
		delay  time.Duration
		action string
		args   string
	}
	var cmds []autoCmd
	for _, part := range strings.Split(script, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		tokens := strings.SplitN(part, ":", 3)
		if len(tokens) < 2 {
			ravelog.Logf("[auto] bad command: %q\n", part)
			continue
		}
		delaySec, err := strconv.ParseFloat(tokens[0], 64)
		if err != nil {
			ravelog.Logf("[auto] bad delay %q: %v\n", tokens[0], err)
			continue
		}
		action := tokens[1]
		args := ""
		if len(tokens) == 3 {
			args = tokens[2]
		}
		cmds = append(cmds, autoCmd{
			delay:  time.Duration(delaySec * float64(time.Second)),
			action: action,
			args:   args,
		})
	}
	if disp != nil {
		for len(disp.Windows()) == 0 {
			time.Sleep(25 * time.Millisecond)
		}
		ravelog.Logf("[auto] first window ready\n")
	}
	start := time.Now()

	for _, cmd := range cmds {
		// Wait until the scheduled time
		elapsed := time.Since(start)
		if cmd.delay > elapsed {
			time.Sleep(cmd.delay - elapsed)
		}
		switch cmd.action {
		case "screenshot":
			var w *wl.Window
			if disp != nil {
				windows := disp.Windows()
				if len(windows) > 0 {
					w = windows[0]
				}
			}
			if w == nil {
				ravelog.Logf("[auto] screenshot: no window yet\n")
				continue
			}
			if err := w.Screenshot(cmd.args); err != nil {
				ravelog.Logf("[auto] screenshot %q failed: %v\n", cmd.args, err)
			} else {
				ravelog.Logf("[auto] screenshot saved: %s\n", cmd.args)
			}
		case "screenshot-all":
			if disp == nil {
				ravelog.Logf("[auto] screenshot-all: no display\n")
				continue
			}
			for i, win := range disp.Windows() {
				path := fmt.Sprintf("%s-%d.png", cmd.args, i)
				if err := win.Screenshot(path); err != nil {
					ravelog.Logf("[auto] screenshot-all %q failed: %v\n", path, err)
				} else {
					ravelog.Logf("[auto] screenshot-all saved: %s title=%q\n", path, win.Title)
				}
			}
		case "click":
			if disp == nil {
				ravelog.Logf("[auto] click: no display\n")
				continue
			}
			parts := strings.SplitN(cmd.args, ",", 2)
			if len(parts) != 2 {
				ravelog.Logf("[auto] click: bad args %q\n", cmd.args)
				continue
			}
			x, _ := strconv.Atoi(strings.TrimSpace(parts[0]))
			y, _ := strconv.Atoi(strings.TrimSpace(parts[1]))
			disp.InjectClick(int32(x), int32(y))
			ravelog.Logf("[auto] click at (%d,%d)\n", x, y)
		case "double-click":
			if disp == nil {
				ravelog.Logf("[auto] double-click: no display\n")
				continue
			}
			parts := strings.SplitN(cmd.args, ",", 2)
			if len(parts) != 2 {
				ravelog.Logf("[auto] double-click: bad args %q\n", cmd.args)
				continue
			}
			x, _ := strconv.Atoi(strings.TrimSpace(parts[0]))
			y, _ := strconv.Atoi(strings.TrimSpace(parts[1]))
			disp.InjectDoubleClick(int32(x), int32(y))
			ravelog.Logf("[auto] double-click at (%d,%d)\n", x, y)
		case "click-title":
			if disp == nil {
				ravelog.Logf("[auto] click-title: no display\n")
				continue
			}
			parts := strings.SplitN(cmd.args, ",", 3)
			if len(parts) != 3 {
				ravelog.Logf("[auto] click-title: bad args %q\n", cmd.args)
				continue
			}
			x, _ := strconv.Atoi(strings.TrimSpace(parts[1]))
			y, _ := strconv.Atoi(strings.TrimSpace(parts[2]))
			var target *wl.Window
			for _, win := range disp.Windows() {
				if strings.EqualFold(win.Title, strings.TrimSpace(parts[0])) {
					target = win
					break
				}
			}
			if target == nil {
				ravelog.Logf("[auto] click-title: window %q not found\n", parts[0])
				continue
			}
			disp.InjectClickWindow(target, int32(x), int32(y))
			ravelog.Logf("[auto] click-title %q at (%d,%d)\n", target.Title, x, y)
		case "key":
			if disp == nil {
				ravelog.Logf("[auto] key: no display\n")
				continue
			}
			code, _ := strconv.Atoi(cmd.args)
			disp.InjectKey(uint32(code))
			ravelog.Logf("[auto] key %d\n", code)
		case "key-title":
			if disp == nil {
				continue
			}
			parts := strings.SplitN(cmd.args, ",", 2)
			if len(parts) != 2 {
				ravelog.Logf("[auto] key-title: bad args %q\n", cmd.args)
				continue
			}
			code, _ := strconv.Atoi(strings.TrimSpace(parts[1]))
			var target *wl.Window
			for _, win := range disp.Windows() {
				if strings.EqualFold(win.Title, strings.TrimSpace(parts[0])) {
					target = win
					break
				}
			}
			if target == nil {
				ravelog.Logf("[auto] key-title: window %q not found\n", parts[0])
				continue
			}
			disp.InjectKeyWindow(target, uint32(code))
			ravelog.Logf("[auto] key-title %q key %d\n", target.Title, code)
		case "type-title":
			if disp == nil {
				continue
			}
			parts := strings.SplitN(cmd.args, ",", 2)
			if len(parts) != 2 {
				ravelog.Logf("[auto] type-title: bad args %q\n", cmd.args)
				continue
			}
			var target *wl.Window
			for _, win := range disp.Windows() {
				if strings.EqualFold(win.Title, strings.TrimSpace(parts[0])) {
					target = win
					break
				}
			}
			if target == nil {
				ravelog.Logf("[auto] type-title: window %q not found\n", parts[0])
				continue
			}
			disp.InjectTextWindow(target, parts[1])
			ravelog.Logf("[auto] type-title %q text=%q\n", target.Title, parts[1])
		case "close-title":
			if disp == nil {
				continue
			}
			var target *wl.Window
			for _, win := range disp.Windows() {
				if strings.EqualFold(win.Title, strings.TrimSpace(cmd.args)) {
					target = win
					break
				}
			}
			if target == nil {
				ravelog.Logf("[auto] close-title: window %q not found\n", cmd.args)
				continue
			}
			disp.InjectCloseWindow(target)
			ravelog.Logf("[auto] close-title %q\n", target.Title)
		case "chord":
			if disp == nil {
				ravelog.Logf("[auto] chord: no display\n")
				continue
			}
			parts := strings.SplitN(cmd.args, ",", 2)
			if len(parts) != 2 {
				ravelog.Logf("[auto] chord: bad args %q\n", cmd.args)
				continue
			}
			modifier, _ := strconv.Atoi(strings.TrimSpace(parts[0]))
			code, _ := strconv.Atoi(strings.TrimSpace(parts[1]))
			disp.InjectKeyChord(uint32(modifier), uint32(code))
			ravelog.Logf("[auto] chord %d,%d\n", modifier, code)
		default:
			ravelog.Logf("[auto] unknown action: %q\n", cmd.action)
		}
	}
	ravelog.Logf("[auto] script complete\n")
}

// registerAutoSynthHandlers registers vmcall handlers for critical
// CRT and Win32 functions in auto-generated synthetic DLLs.
func registerAutoSynthHandlers(mem *mmu.MMU, d *ntapi.Dispatcher, dlls []*ntapi.SynthPE, argv []string, cmdLine, imagePath, hostImagePath string, handles *ntapi.HandleTable, procState *ntapi.ProcessState, exceptionTable *ntapi.ExceptionTable, mainModule *loader.PEModule, loadedModules map[string]*loader.PEModule, tmPtr **thread.Manager, bootTime time.Time, regHive *ntapi.RegistryHive, autoScript string, enableWayland bool, renderSnapshot func(), renderPNG string, hostArgPaths map[string]string) *HandlerCtx {
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
	var heapFreeList []freeBlock
	heapMmapBlocks := make(map[uint64]uint64) // user ptr → block size
	var heapMu sync.Mutex                     // protects heapFreeList, heapMmapBlocks, and TEB bump counter
	mode32 := !mainModule.Is64

	// Resolve TEB heap fields (different offsets for x86 vs x64)
	var tebHeapBaseOff, tebHeapOffOff uint64
	if mode32 {
		tebHeapBaseOff = ntapi.Teb32HeapBase
		tebHeapOffOff = ntapi.Teb32HeapOffset
	} else {
		tebHeapBaseOff = ntapi.TebHeapBase
		tebHeapOffOff = ntapi.TebHeapOffset
	}
	var heapRegion uint64
	if mode32 {
		v, _ := mem.Read32(procState.TEBAddr + tebHeapBaseOff)
		heapRegion = uint64(v)
	} else {
		heapRegion, _ = mem.Read64(procState.TEBAddr + tebHeapBaseOff)
	}

	sharedHeapAlloc := func(size uint64, zeroInit bool) uint64 {
		heapMu.Lock()
		defer heapMu.Unlock()
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
		var heapOff uint64
		if mode32 {
			v, _ := mem.Read32(procState.TEBAddr + tebHeapOffOff)
			heapOff = uint64(v)
		} else {
			heapOff, _ = mem.Read64(procState.TEBAddr + tebHeapOffOff)
		}
		if heapOff+totalBlock <= 256*1024*1024 {
			addr := heapRegion + heapOff
			mem.Write64(addr, totalBlock)
			heapOff += totalBlock
			if mode32 {
				mem.Write32(procState.TEBAddr+tebHeapOffOff, uint32(heapOff))
			} else {
				mem.Write64(procState.TEBAddr+tebHeapOffOff, heapOff)
			}
			return addr + 16
		}

		// Mmap overflow
		addr := mem.Mmap(0, totalBlock, mmu.PermRead|mmu.PermWrite)
		if addr == 0 {
			var heapOff uint64
			if mode32 {
				v, _ := mem.Read32(procState.TEBAddr + tebHeapOffOff)
				heapOff = uint64(v)
			} else {
				heapOff, _ = mem.Read64(procState.TEBAddr + tebHeapOffOff)
			}
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
		heapMu.Lock()
		defer heapMu.Unlock()
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

	// Wire shared heap into ProcessState so ntdll RtlAllocateHeap/Free/Size
	// use the same bump-allocator as kernel32 HeapAlloc/HeapFree.
	procState.HeapAlloc = sharedHeapAlloc
	procState.HeapFree = sharedHeapFree
	procState.HeapSize = func(ptr uint64) uint64 {
		if ptr == 0 {
			return 0
		}
		blockSize, _ := mem.Read64(ptr - 16)
		if blockSize >= 16 {
			return blockSize - 16
		}
		return 0
	}

	// delayHandlerRegistrars stored in hctx.DelayHandlerRegistrars:
	// re-runnable closures that register handlers for each DLL.
	// After delay-load synthesizes a new DLL, we re-run all registrars so the
	// new DLL's handlers get registered.

	// Shared delay-load state used by both ResolveDelayLoadedAPI and __delayLoadHelper2
	var delayLoadFallback uint64
	nextDelayID := uint32(ntapi.AutoSynthIDBase)
	for _, s := range dlls {
		for _, id := range s.StubIDs {
			if id+1 > nextDelayID {
				nextDelayID = id + 1
			}
		}
	}

	// Wayland connection for window display (used by user32 handlers below)
	var wlDisplay *wl.Display
	var wlWindow *wl.Window
	// mainHWND/mainTitle/mainActive: will be set via hctx after it is created
	// (hctx.MainHWND, hctx.MainTitle, hctx.MainActive)
	if !enableWayland {
		ravelog.Logf("[wl] headless (-wayland=false): window display disabled\n")
	} else if wld, err := wl.Connect(); err == nil {
		wlDisplay = wld
		ravelog.Logf("[wl] connected to Wayland compositor\n")
	} else {
		ravelog.Logf("[wl] no Wayland: %v (window display disabled)\n", err)
	}

	// Automation goroutine: parse -auto script and execute timed actions.
	if autoScript != "" {
		go runAutoScript(autoScript, wlDisplay)
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
	readGuestUTF16N := func(addr uint64, n int) string {
		if addr == 0 {
			return ""
		}
		if n < 0 {
			return readGuestUTF16(addr)
		}
		chars := make([]uint16, n)
		for i := 0; i < n; i++ {
			w, _ := mem.Read16(addr + uint64(i)*2)
			chars[i] = w
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

	// Atom tables
	localAtomTable := map[string]uint16{}
	localAtomNames := map[uint16]string{}
	nextLocalAtom := uint16(0xC100)
	globalAtomTable := map[string]uint16{}
	globalAtomNames := map[uint16]string{}
	nextGlobalAtom := uint16(0xC200)

	addAtomLocal := func(name string) uint16 {
		key := strings.ToLower(name)
		if a, ok := localAtomTable[key]; ok {
			return a
		}
		a := nextLocalAtom
		nextLocalAtom++
		localAtomTable[key] = a
		localAtomNames[a] = name
		return a
	}
	addAtomGlobal := func(name string) uint16 {
		key := strings.ToLower(name)
		if a, ok := globalAtomTable[key]; ok {
			return a
		}
		a := nextGlobalAtom
		nextGlobalAtom++
		globalAtomTable[key] = a
		globalAtomNames[a] = name
		return a
	}

	// INI file cache: hostPath → section(lower) → key(lower) → value
	iniCache := map[string]map[string]map[string]string{}
	iniRead := func(hostPath string) map[string]map[string]string {
		if c, ok := iniCache[hostPath]; ok {
			return c
		}
		sections := map[string]map[string]string{}
		if data, err := os.ReadFile(hostPath); err == nil {
			var curSec string
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
					curSec = strings.ToLower(line[1 : len(line)-1])
					if sections[curSec] == nil {
						sections[curSec] = map[string]string{}
					}
				} else if idx := strings.IndexByte(line, '='); idx > 0 && curSec != "" {
					k := strings.ToLower(strings.TrimSpace(line[:idx]))
					v := strings.TrimSpace(line[idx+1:])
					sections[curSec][k] = v
				}
			}
		}
		iniCache[hostPath] = sections
		return sections
	}
	iniWrite := func(hostPath, section, key, value string) {
		sections := iniRead(hostPath)
		sec := strings.ToLower(section)
		if sections[sec] == nil {
			sections[sec] = map[string]string{}
		}
		sections[sec][strings.ToLower(key)] = value
		var sb strings.Builder
		for s, kvs := range sections {
			sb.WriteString("[")
			sb.WriteString(s)
			sb.WriteString("]\n")
			for k, v := range kvs {
				sb.WriteString(k)
				sb.WriteString("=")
				sb.WriteString(v)
				sb.WriteString("\n")
			}
		}
		_ = os.WriteFile(hostPath, []byte(sb.String()), 0644)
	}

	// viewMapping tracks an active MapViewOfFile view for sync-back.
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
		case 1:
			stride = ((biWidth + 31) / 32) * 4
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
					a := (v >> 24) & 0xFF
					if a == 0 {
						a = 0xFF // BI_RGB 32-bit: reserved byte is 0, treat as opaque
					}
					pixel = (a << 24) | (r << 16) | (g << 8) | b
				case 24:
					b0, _ := mem.ReadBytes(rowBase+uint64(col)*3, 3)
					if len(b0) == 3 {
						pixel = 0xFF000000 | (uint32(b0[2]) << 16) | (uint32(b0[1]) << 8) | uint32(b0[0])
					}
				case 8:
					idx, _ := mem.ReadBytes(rowBase+uint64(col), 1)
					if len(idx) > 0 && int(idx[0]) < len(palette) {
						pixel = 0xFF000000 | palette[idx[0]]
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
							pixel = 0xFF000000 | palette[nibble]
						}
					}
				case 1:
					value, _ := mem.ReadBytes(rowBase+uint64(col/8), 1)
					if len(value) > 0 {
						index := (value[0] >> uint(7-(col&7))) & 1
						if int(index) < len(palette) {
							pixel = 0xff000000 | palette[index]
						} else if index != 0 {
							pixel = 0xffffffff
						} else {
							pixel = 0xff000000
						}
					}
				}
				allPix[row*biWidth+col] = pixel
			}
		}
		// Split into icon slots: each slot is iconW wide, full height=iconH
		if iconW <= 0 {
			iconW = biWidth
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
					sourceColumn := s*iconW + col
					src := row*biWidth + sourceColumn
					if sourceColumn < biWidth && src < len(allPix) {
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

	// ansiprintf is like wideprintf but reads %s as ANSI (for wsprintfA, sprintfA, etc.)
	// In ANSI variants: %s = ANSI string, %S = wide string.
	ansiprintf := func(format string, args []uint64) string {
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
			case 's': // ANSI string
				p := nextPtr()
				for _, r := range readGuestString(p) {
					result = append(result, r)
				}
			case 'S': // Wide string in ANSI printf
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
		v, _ := mem.Read32(pBMI + 4)
		w = int32(v)
		v, _ = mem.Read32(pBMI + 8)
		h = int32(v)
		v16, _ := mem.Read16(pBMI + 14)
		bitCount = int32(v16)
		v, _ = mem.Read32(pBMI + 16)
		compr = v
		v, _ = mem.Read32(pBMI + 32)
		clrUsed := v // biClrUsed

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
			case 1:
				numColors = 2
			case 4:
				numColors = 16
			case 8:
				numColors = 256
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

	// ── Create HandlerCtx (shared state for all extracted DLL handlers) ──
	guestCallTrampoline := ntapi.AllocTrampoline(mem)
	envVars := map[string]string{
		"PATH":                   "C:\\Windows\\System32;C:\\Windows",
		"SYSTEMROOT":             "C:\\Windows",
		"WINDIR":                 "C:\\Windows",
		"TEMP":                   "C:\\Windows\\TEMP",
		"TMP":                    "C:\\Windows\\TEMP",
		"OS":                     "Windows_NT",
		"NUMBER_OF_PROCESSORS":   "4",
		"PROCESSOR_ARCHITECTURE": "AMD64",
	}
	if mode32 {
		envVars["PROCESSOR_ARCHITECTURE"] = "x86"
	}
	renderSnapshotForCtx := renderSnapshot
	if renderPNG != "" {
		renderSnapshotForCtx = func() {
			if wlWindow != nil && len(wlWindow.Pix) > 0 {
				if err := wlWindow.Screenshot(renderPNG); err != nil {
					ravelog.Logf("[render-png] %v\n", err)
					return
				}
				ravelog.Logf("[render-png] wrote %s\n", renderPNG)
				return
			}
			if renderSnapshot != nil {
				renderSnapshot()
			}
		}
	}
	moduleResourceRVAs := make(map[uint64]uint32)
	for _, module := range loadedModules {
		if module != nil && module.BaseAddr != 0 && module.ResourceDirRVA != 0 {
			moduleResourceRVAs[module.BaseAddr] = module.ResourceDirRVA
		}
	}
	hctx := &HandlerCtx{
		// Core references
		Mem: mem, Disp: d, Handles: handles, ProcState: procState,
		ExTable: exceptionTable, MainModule: mainModule, TMPtr: tmPtr,
		RegHive: regHive, SynthByName: synthByName,
		// Config
		Argv: argv, CmdLine: cmdLine, ImagePath: imagePath, HostImagePath: hostImagePath,
		StartTime: startTime, BootTime: bootTime, StdinReader: stdinReader,
		Dlls: dlls, KeepHeadlessAlive: renderPNG != "" || autoScript != "",
		// Wayland / GUI
		WlDisplay: wlDisplay, WlWindow: wlWindow,
		WlWindows: make(map[uint64]*wl.Window), WlWindowHWND: make(map[*wl.Window]uint64),
		WindowCPU:      make(map[uint64]arch.CPU),
		RenderSnapshot: renderSnapshotForCtx, GdiMgr: gdiMgr,
		// Maps
		EnvVars:        envVars,
		LocalAtomTable: localAtomTable, LocalAtomNames: localAtomNames,
		GlobalAtomTable: globalAtomTable, GlobalAtomNames: globalAtomNames,
		NamedMappings: namedMappings, LocalAllocSizes: make(map[uint64]uint64), IniCache: iniCache,
		ViewMappings: viewMappings, HostSavePaths: hostArgPaths, VfsModuleResRVA: moduleResourceRVAs,
		// Func fields from setup
		ReadGuestUTF16: readGuestUTF16, ReadGuestUTF16N: readGuestUTF16N,
		ReadGuestString: readGuestString,
		HeapAlloc:       sharedHeapAlloc, HeapFree: sharedHeapFree,
		Wideprintf: wideprintf, Ansiprintf: ansiprintf, CrtStreamWriter: crtStreamWriter,
		AddAtomLocal: addAtomLocal, AddAtomGlobal: addAtomGlobal,
		IniRead: iniRead, IniWrite: iniWrite,
		DoCreateFileMapping: doCreateFileMapping, DoMapView: doMapView, DoUnmapView: doUnmapView,
		PickBestLangEntry: pickBestLangEntry, PeLoadStringW: peLoadStringW,
		PeLoadMenuResource: peLoadMenuResource, PeLoadRawResource: peLoadRawResource,
		DecodeDIBSlots: decodeDIBSlots,
		GetSysColor:    getSysColor, SyncScreenSurface: syncScreenSurface,
		AllocScreenDC: allocScreenDC, GetDCFn: getDC,
		ReadDIBInfo: readDIBInfo, ReadDIBPixels: readDIBPixels,
		SysColors: sysColors,
		// CRT file I/O
		CrtFiles:  make(map[uint64]*os.File),
		CrtNextFP: mem.Mmap(0, 0x10000, mmu.PermRead|mmu.PermWrite),
		// Mutable scalars (initial values)
		MainActive:          true,
		DelayLoadFallback:   delayLoadFallback,
		NextDelayID:         nextDelayID,
		NextLocalAtom:       nextLocalAtom,
		NextGlobalAtom:      nextGlobalAtom,
		FrameCount:          frameCount,
		GuestCallTrampoline: guestCallTrampoline,
	}
	// Sync callback: when user32 creates the Wayland window, update local wlWindow
	// so that all closures in this function (builtinWndProc, paintTree, etc.) see it.
	hctx.OnWlWindowSet = func(w *wl.Window) { wlWindow = w }

	delayReg := func(fn func()) {
		hctx.DelayHandlerRegistrars = append(hctx.DelayHandlerRegistrars, fn)
		fn()
	}

	// --- msvcrt.dll ---
	registerMsvcrtHandlers(hctx)
	registerUcrtHandlers(hctx)

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
	hctx.RegKeyPath = regKeyPath
	hctx.RegQueryValue = regQueryValue
	hctx.RegIsProbeKey = regIsProbeKey

	// --- kernel32.dll ---
	registerKernel32Handlers(hctx)

	// --- shcore.dll ---
	delayReg(func() { registerShcoreHandlers1(hctx) })

	// --- shlwapi.dll ---
	delayReg(func() { registerAppcompatHandlers(hctx) })
	delayReg(func() { registerShlwapiHandlers(hctx) })
	delayReg(func() { registerShell32Handlers(hctx) })

	// --- shcore.dll ---
	delayReg(func() { registerShcoreHandlers2(hctx) })

	// --- rpcrt4.dll ---
	delayReg(func() { registerRpcrt4Handlers(hctx) })

	// --- comdlg32.dll ---
	delayReg(func() { registerComdlg32Handlers(hctx) })

	// --- advapi32.dll ---

	delayReg(func() { registerAdvapi32Handlers1(hctx) })

	// --- kernelbase.dll (extra handlers not covered by kernel32 alias) ---
	delayReg(func() { registerKernelbaseHandlers(hctx) })

	// --- vcruntime140.dll ---
	delayReg(func() { registerVcruntime140Handlers(hctx) })

	// --- msvcp140.dll ---
	delayReg(func() { registerMsvcp140Handlers(hctx) })

	// Simple handle generator for GDI objects, windows, etc.
	hctx.NextGDIHandle = 0xD0010001 // GDI handle space
	gdiAlloc := func() uint64 {
		h := hctx.NextGDIHandle
		hctx.NextGDIHandle++
		return h
	}
	hctx.GdiAlloc = gdiAlloc

	// Menu data structures (types defined earlier near peLoadMenuResource)
	hctx.Menus = make(map[uint64]*menuData)    // menu handle → menu data
	hctx.HwndMenuBar = make(map[uint64]uint64) // HWND → menu bar handle
	// Menu bar interaction state
	hctx.OpenMenuIdx = -1 // which top-level menu is open (-1 = none)
	// hctx.OpenMenuHwnd: hctx.OpenMenuHwnd already zero-valued

	// hctx.BitmapHandles maps an HBITMAP handle to its decoded pixel data.
	// Used by LoadImageW/LoadBitmapW (store) and TB_ADDBITMAP (lookup).
	hctx.BitmapHandles = make(map[uint64]*bitmapHandleData)
	hctx.NextBitmapHandle = 0x00030001 // start from known value
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
	hctx.MenuStripAmpersand = menuStripAmpersand

	hctx.NextHWND = 0x00050001 // window handle space
	hwndAlloc := func() uint64 {
		h := hctx.NextHWND
		hctx.NextHWND++
		hctx.HwndOrder = append(hctx.HwndOrder, h)
		hctx.HwndZOrder = append([]uint64{h}, hctx.HwndZOrder...)
		return h
	}
	hctx.HwndAlloc = hwndAlloc
	hctx.NextMsgID = 0xC000 // RegisterWindowMessage range
	hctx.RegisteredMsgNames = make(map[string]uint32)
	hctx.NextAtom = 0xC001 // RegisterClass atom range
	// hctx.FocusHwnd: hctx.FocusHwnd already zero-valued
	// hctx.MouseCapture: hctx.MouseCapture already zero-valued

	// WndProc dispatch tables
	hctx.AtomWndProc = make(map[uint16]uint64)             // class atom → WndProc address
	hctx.HwndWndProc = make(map[uint64]uint64)             // HWND → WndProc address
	hctx.ClassNameAtom = make(map[string]uint16)           // class name → atom (for lpClassName string lookups)
	hctx.ClassMenuHandle = make(map[uint16]uint64)         // class atom → loaded menu handle
	hctx.ClassBrush = make(map[uint16]uint32)              // class atom → hbrBackground (COLOR_xxx+1 index)
	hctx.ClassInfo = make(map[uint16]*registeredClassInfo) // class atom → full class info
	hctx.HwndClassAtom = make(map[uint64]uint16)           // HWND → class atom (for brush lookup)
	hctx.TrackMouseHwnds = make(map[uint64]uint32)         // HWND → TME flags

	// Built-in window class tracking for Edit, Static, Button, etc.
	hctx.HwndChildren = make(map[uint64]*controlState)
	hctx.HwndTitle = make(map[uint64]string)
	// hctx.HwndExplicitlyHidden tracks HWNDs that the guest explicitly hid via
	// ShowWindow(SW_HIDE). These must NOT be auto-shown when the parent is
	// shown or when they receive a SetWindowPos/MoveWindow with non-zero size.
	hctx.HwndExplicitlyHidden = make(map[uint64]bool)
	hctx.WinErasePending = make(map[uint64]bool)

	// clientAreaOrigin returns the absolute (surface) coordinates of a
	// window's client-area top-left. For hctx.MainHWND with a menu bar the
	// client area starts below the menu; for child windows it's their
	// stored (absolute) position. The title-bar height is added to all
	// y values so that GDI drawing at app-y=0 lands below the title bar.
	hctx.ClientAreaOrigin = func(hwnd uint64) (int32, int32) {
		tbH := int32(0)
		if wlWindow != nil {
			tbH = wlWindow.TitleBarH
		}
		if cs, ok := hctx.HwndChildren[hwnd]; ok {
			// cs.x/cs.y are already in surface (absolute) coordinates and include
			// TitleBarH. Do NOT add tbH again - that would shift DC origins and
			// grandchild positions by TitleBarH a second time.
			return cs.x, cs.y
		}
		if hwnd == hctx.MainHWND {
			if _, hasMenu := hctx.HwndMenuBar[hctx.MainHWND]; hasMenu {
				return 0, menuBarHeight + tbH
			}
		}
		return 0, tbH
	}

	// paintTree recursively paints a window's child tree in creation
	// order (sorted by HWND) so that containers are filled before their
	// contents are drawn on top. Assigned after builtinWndProc.

	// --- comctl32.dll ---
	delayReg(func() { registerComctl32Handlers(hctx) })

	// --- ole32.dll ---
	delayReg(func() { registerOle32Handlers(hctx) })

	// --- oleaut32.dll ---
	delayReg(func() { registerOleaut32Handlers(hctx) })

	// --- oleacc.dll / uiautomationcore.dll ---
	delayReg(func() { registerOleaccHandlers(hctx) })

	// --- windowscodecs.dll ---
	delayReg(func() { registerWindowsCodecsHandlers(hctx) })

	// --- dwrite.dll ---
	delayReg(func() { registerDWriteHandlers(hctx) })

	// --- d2d1.dll ---
	delayReg(func() { registerD2D1Handlers(hctx) })

	// Message queue for synthetic messages (WM_CREATE, WM_SIZE, etc.)
	// hctx.MsgQueue: hctx.MsgQueue already nil
	// Tracks non-empty update regions per HWND.
	hctx.WinInvalid = map[uint64]bool{}
	// hctx.LastPostedMainW/H: hctx fields already zero-valued
	hctx.QueuePaint = func(hwnd uint64) {
		if hwnd == 0 {
			hwnd = hctx.MainHWND
		}
		hctx.WinInvalid[hwnd] = true
		win32.Global.Invalidate(hwnd, nil)
		if hctx.MsgQueue.contains(func(qm queuedMsg) bool {
			return qm.hwnd == hwnd && qm.message == 0x000F
		}) {
			return
		}
		hctx.enqueueMessage(nil, newQueuedMsg(hctx, hwnd, 0x000F, 0, 0))
	}

	// win32Timer tracks active SetTimer timers.
	hctx.NextTimerID = 1000
	// hctx.FrameReady: set to trigger the next Commit().
	// hctx.HasBaseFrame: set once DefWindowProcW has drawn the base frame (menu+background).
	// hctx.RepaintBuiltin: when true, commitIfDone calls paintTree (for initial frame compositing).
	// hctx.FrameReady/hctx.HasBaseFrame/hctx.RepaintBuiltin: hctx fields already false

	// drawMenuOverlay draws the open dropdown menu on top of everything else.
	// Must be called AFTER paintTree so the toolbar/rebar don't overwrite it.

	// ncTextFont is a lazily-created Font for NC area text rendering (menu bar, tabs, status bar).
	// Uses TrueType if any faces are loaded; otherwise returns nil (bitmap fallback).
	hctx.NcTextFont = func(size int32) *gdi.Font {
		if !gdi.HasTTFFonts() {
			return nil
		}
		faceID := gdi.ResolveFontFace("segoe ui")
		if faceID < 0 {
			faceID = gdi.ResolveFontFace("dejavu sans")
		}
		if faceID < 0 {
			faceID = gdi.ResolveFontFace("liberation sans")
		}
		if faceID < 0 {
			faces := gdi.ListFaces()
			if len(faces) > 0 {
				faceID = faces[0].ID
			}
		}
		if faceID < 0 {
			return nil
		}
		cellH, asc, desc, aveW := gdi.FaceMetrics(faceID, size)
		return &gdi.Font{
			FaceID:       faceID,
			Height:       size,
			CellHeight:   cellH,
			Ascent:       asc,
			Descent:      desc,
			AveCharWidth: aveW,
			MaxCharWidth: aveW * 2,
			Weight:       400,
		}
	}

	// ncDrawText draws text at absolute surface coordinates using GDI TrueType if available,
	// otherwise falls back to the bitmap DrawTextAbs.
	hctx.NcDrawText = func(x, y int32, text string, fg, bg uint32, opaque bool, size int32) {
		if wlWindow == nil {
			return
		}
		f := hctx.NcTextFont(size)
		if f == nil {
			wlWindow.DrawTextAbs(x, y, text, fg, bg, opaque)
			return
		}
		syncScreenSurface()
		h, dc := gdiMgr.AllocScreenDC()
		dc.OriginX = 0
		dc.OriginY = 0
		dc.Font = f
		dc.TextColor = fg
		dc.BkColor = bg
		// Fill background if opaque - use real glyph widths
		if opaque {
			tw := int32(0)
			pixSize := size
			if pixSize < 0 {
				pixSize = -pixSize
			}
			if pixSize == 0 {
				pixSize = 12
			}
			for _, r := range text {
				if g := gdi.GlyphFor(f.FaceID, pixSize, r); g != nil {
					tw += g.Advance
				} else {
					tw += f.AveCharWidth
				}
			}
			dc.FillRect(x, y, x+tw, y+f.CellHeight, bg)
		}
		dc.TextOut(x, y, text, opaque)
		gdiMgr.DeleteDC(h)
	}

	// NcDrawTextClipped: like NcDrawText but clips to (cx0,cy0,cx1,cy1) in absolute surface coords.
	hctx.NcDrawTextClipped = func(x, y, cx0, cy0, cx1, cy1 int32, text string, fg, bg uint32, opaque bool, size int32) {
		if wlWindow == nil {
			return
		}
		f := hctx.NcTextFont(size)
		if f == nil {
			if x < cx0 {
				x = cx0
			}
			wlWindow.DrawTextAbs(x, y, text, fg, bg, opaque)
			return
		}
		syncScreenSurface()
		h, dc := gdiMgr.AllocScreenDC()
		dc.OriginX = 0
		dc.OriginY = 0
		dc.Font = f
		dc.TextColor = fg
		dc.BkColor = bg
		dc.SetClipRect(cx0, cy0, cx1, cy1)
		if opaque {
			tw := int32(0)
			pixSize := size
			if pixSize < 0 {
				pixSize = -pixSize
			}
			if pixSize == 0 {
				pixSize = 12
			}
			for _, r := range text {
				if g := gdi.GlyphFor(f.FaceID, pixSize, r); g != nil {
					tw += g.Advance
				} else {
					tw += f.AveCharWidth
				}
			}
			dc.FillRect(x, y, x+tw, y+f.CellHeight, bg)
		}
		dc.TextOut(x, y, text, opaque)
		gdiMgr.DeleteDC(h)
	}

	// Wire real glyph-based text measurement for menu layout.
	hctx.MeasureNcText = func(text string, size int32) int32 {
		f := hctx.NcTextFont(size)
		if f == nil || f.FaceID < 0 {
			return int32(len([]rune(text))) * 7
		}
		pixSize := size
		if pixSize < 0 {
			pixSize = -pixSize
		}
		if pixSize == 0 {
			pixSize = 12
		}
		w := int32(0)
		for _, r := range text {
			if g := gdi.GlyphFor(f.FaceID, pixSize, r); g != nil {
				w += g.Advance
			} else {
				w += f.AveCharWidth
			}
		}
		return w
	}
	menuTextMeasure = hctx.MeasureNcText
	drawMenuBitmap := func(handle uint64, x, y, maxWidth, maxHeight int32, color uint32) bool {
		if handle == 0 || wlWindow == nil {
			return false
		}
		var pixels []uint32
		width, height := 0, 0
		monochrome := false
		if bitmap := hctx.BitmapHandles[handle]; bitmap != nil && len(bitmap.slots) > 0 {
			pixels = bitmap.slots[0]
			width, height = bitmap.w, bitmap.h
			monochrome = bitmap.monochrome
			if width <= 0 || height <= 0 || width*height > len(pixels) {
				width = 16
				if len(pixels)%width != 0 {
					width = len(pixels)
				}
				height = len(pixels) / width
			}
		} else if object := gdiMgr.GetObject(handle); object != nil && object.Bitmap != nil && object.Bitmap.Surf != nil {
			surface := object.Bitmap.Surf
			width, height = int(surface.Width), int(surface.Height)
			monochrome = object.Bitmap.BitCount == 1
			pixels = make([]uint32, width*height)
			for index := range pixels {
				offset := index * 4
				if offset+3 >= len(surface.Pix) {
					break
				}
				pixels[index] = uint32(surface.Pix[offset]) | uint32(surface.Pix[offset+1])<<8 |
					uint32(surface.Pix[offset+2])<<16 | uint32(surface.Pix[offset+3])<<24
			}
		}
		if width <= 0 || height <= 0 || len(pixels) < width*height {
			return false
		}
		sourceWidth := width
		if width > int(maxWidth) {
			width = int(maxWidth)
		}
		if height > int(maxHeight) {
			height = int(maxHeight)
		}
		return drawMenuBitmapPixels(wlWindow, pixels, sourceWidth, width, height, x, y, monochrome, color)
	}

	hctx.DrawMenuOverlay = func() {
		if wlWindow == nil {
			return
		}
		pm := hctx.ActivePopupMenu
		if pm == nil || len(pm.Items) == 0 {
			return
		}
		// Restore the clean content captured when the menu opened before drawing
		// the current popup, so navigating between menu-bar items (or opening a
		// submenu) does not stack one dropdown's pixels over another.
		if hctx.MenuBehind != nil {
			wlWindow.RestorePixels(hctx.MenuBehind)
		}
		dropX, dropY, dropW, dropH := pm.X, pm.Y, pm.Width, pm.Height
		wlWindow.DrawRectAbs(dropX+2, dropY+dropH, dropX+dropW+2, dropY+dropH+2, 0x808080)
		wlWindow.DrawRectAbs(dropX+dropW, dropY+2, dropX+dropW+2, dropY+dropH+2, 0x808080)
		wlWindow.DrawRectAbs(dropX, dropY, dropX+dropW, dropY+dropH, sysColors[15])
		wlWindow.DrawRectAbs(dropX, dropY, dropX+dropW, dropY+1, 0xA0A0A0)
		wlWindow.DrawRectAbs(dropX, dropY, dropX+1, dropY+dropH, 0xA0A0A0)
		wlWindow.DrawRectAbs(dropX, dropY+dropH-1, dropX+dropW, dropY+dropH, 0xA0A0A0)
		wlWindow.DrawRectAbs(dropX+dropW-1, dropY, dropX+dropW, dropY+dropH, 0xA0A0A0)
		for j, si := range pm.Items {
			iy := dropY + int32(j)*pm.ItemHeight
			if si.flags&0x0800 != 0 {
				wlWindow.DrawRectAbs(dropX+6, iy+pm.ItemHeight/2, dropX+dropW-6, iy+pm.ItemHeight/2+1, sysColors[16])
				continue
			}
			selected := j == pm.Selected
			if selected {
				wlWindow.DrawRectAbs(dropX+2, iy+1, dropX+dropW-2, iy+pm.ItemHeight-1, sysColors[13])
			} else if si.flags&0x0003 != 0 {
				wlWindow.DrawRectAbs(dropX+2, iy+1, dropX+dropW-2, iy+pm.ItemHeight-1, 0xF0F0F0)
			}
			label, accel := menuTextParts(hctx.MenuStripAmpersand(si.text))
			textColor := uint32(0x000000)
			textBackground := sysColors[15]
			if selected {
				textColor = 0xFFFFFF
				textBackground = sysColors[13]
			}
			hctx.NcDrawText(dropX+24, iy+4, label, textColor, textBackground, true, 12)
			if accel != "" {
				accelX := dropX + dropW - 12 - int32(len([]rune(accel))*8)
				accelColor := uint32(0x404040)
				if selected {
					accelColor = textColor
				}
				hctx.NcDrawText(accelX, iy+4, accel, accelColor, textBackground, true, 12)
			}
			checkBitmap := si.uncheckedBitmap
			if si.flags&0x0008 != 0 {
				checkBitmap = si.checkedBitmap
			}
			bitmapDrawn := drawMenuBitmap(checkBitmap, dropX+5, iy+(pm.ItemHeight-16)/2, 16, 16, textColor)
			if si.flags&0x0008 != 0 && !bitmapDrawn {
				wlWindow.DrawRectAbs(dropX+8, iy+7, dropX+10, iy+13, 0x000000)
				wlWindow.DrawRectAbs(dropX+10, iy+9, dropX+14, iy+11, 0x000000)
			}
			if len(si.submenu) > 0 || si.flags&0x0010 != 0 {
				// Submenu indicator points RIGHT (submenu opens to the right):
				// wide base on the left, narrow tip on the right.
				ax := dropX + dropW - 8
				wlWindow.DrawRectAbs(ax, iy+7, ax+1, iy+12, 0x000000)
				wlWindow.DrawRectAbs(ax+1, iy+8, ax+2, iy+11, 0x000000)
				wlWindow.DrawRectAbs(ax+2, iy+9, ax+3, iy+10, 0x000000)
			}
		}
	}

	// DrawDialogOverlay renders the modal dialog box on top of everything.
	hctx.DrawDialogOverlay = func() {
		// Draw Find/Replace modeless dialog if open.
		if !hctx.DialogActive || wlWindow == nil {
			return
		}
		ravelog.Logf("[dialog] DrawDialogOverlay title=%q\n", hctx.DialogTitle)
		w := int32(wlWindow.Width)
		h := wlWindow.Height + wlWindow.TitleBarH

		// Dialog dimensions: centered, reasonable size
		const dlgW, dlgH = int32(340), int32(180)
		dx := (w - dlgW) / 2
		dy := (h - dlgH) / 2
		if dx < 0 {
			dx = 0
		}
		if dy < 0 {
			dy = 0
		}

		// Semi-transparent scrim (darken background by filling with gray overlay pattern)
		// We can't do alpha blending easily, so just draw the dialog solid.

		// Dialog background
		wlWindow.DrawRectAbs(dx, dy, dx+dlgW, dy+dlgH, 0xF0F0F0)
		// Outer border
		wlWindow.DrawRectAbs(dx, dy, dx+dlgW, dy+1, 0x606060)
		wlWindow.DrawRectAbs(dx, dy, dx+1, dy+dlgH, 0x606060)
		wlWindow.DrawRectAbs(dx, dy+dlgH-1, dx+dlgW, dy+dlgH, 0x606060)
		wlWindow.DrawRectAbs(dx+dlgW-1, dy, dx+dlgW, dy+dlgH, 0x606060)
		// Title bar (blue)
		wlWindow.DrawRectAbs(dx+1, dy+1, dx+dlgW-1, dy+24, 0x0078D7)
		hctx.NcDrawText(dx+8, dy+5, hctx.DialogTitle, 0xFFFFFF, 0x0078D7, true, 12)

		// Text body
		if hctx.DialogText != "" {
			hctx.NcDrawText(dx+20, dy+40, hctx.DialogText, 0x000000, 0xF0F0F0, true, 12)
		}
		if hctx.DialogText2 != "" {
			hctx.NcDrawText(dx+20, dy+60, hctx.DialogText2, 0x444444, 0xF0F0F0, true, 12)
		}
		// "Raven VM" branding
		hctx.NcDrawText(dx+20, dy+90, "Running on Raven VM", 0x888888, 0xF0F0F0, true, 12)

		// OK button: centered at bottom
		btnW, btnH := int32(80), int32(26)
		btnX := dx + (dlgW-btnW)/2
		btnY := dy + dlgH - 40
		// Button background
		wlWindow.DrawRectAbs(btnX, btnY, btnX+btnW, btnY+btnH, 0xE1E1E1)
		// Button border
		wlWindow.DrawRectAbs(btnX, btnY, btnX+btnW, btnY+1, 0xADADAD)
		wlWindow.DrawRectAbs(btnX, btnY, btnX+1, btnY+btnH, 0xADADAD)
		wlWindow.DrawRectAbs(btnX, btnY+btnH-1, btnX+btnW, btnY+btnH, 0xADADAD)
		wlWindow.DrawRectAbs(btnX+btnW-1, btnY, btnX+btnW, btnY+btnH, 0xADADAD)
		// Button text "OK"
		hctx.NcDrawText(btnX+32, btnY+6, "OK", 0x000000, 0xE1E1E1, true, 12)

		// Store button bounds for click detection
		hctx.DialogBtnX = btnX
		hctx.DialogBtnY = btnY
		hctx.DialogBtnW = btnW
		hctx.DialogBtnH = btnH
		ravelog.Logf("[dialog] drawn at (%d,%d) size %dx%d btn at (%d,%d)\n", dx, dy, dlgW, dlgH, btnX, btnY)
	}

	// commitIfDone commits the Wayland buffer whenever a paint pass has finished.
	// Called after DefWindowProcW WM_PAINT and after each child EndPaint.
	// Multiple commits are fine; each one produces a progressively more complete frame.
	hctx.CommitIfDone = func() {
		w := hctx.WlWindow
		if !hctx.FrameReady || w == nil {
			return
		}
		hctx.FrameReady = false
		if hctx.RepaintBuiltin {
			// Re-composite builtin controls (toolbar, tabs, status bar) on top of
			// guest-drawn content (Scintilla may have overwritten them with its fill).
			hctx.RepaintBuiltin = false
			hctx.PaintTree(hctx.MainHWND)
		}
		if hctx.MainHWND != 0 {
			if wnd := win32.Global.Get(hctx.MainHWND); wnd != nil {
				win32.Global.UpdatePos(wnd, 0, 0, w.Width, w.Height+w.TitleBarH)
			}
		}
		// Always draw dropdown menu overlay on top of everything (including toolbar).
		hctx.DrawMenuOverlay()
		// Draw modal dialog overlay on top of everything else.
		hctx.DrawDialogOverlay()
		ravelog.Logf("[commit] Commit w=%d h=%d pixLen=%d\n", w.Width, w.Height, len(w.Pix))
		w.Commit()
		frameCount++
		if hctx.RenderSnapshot != nil {
			hctx.RenderSnapshot()
		}
	}
	sendNotifySync := func(parentHWND uint64, msg uint32, wParam, lParam uint64) uint64 {
		if parentHWND == 0 {
			return 0
		}
		if result, handled := hctx.BuiltinWndProc(parentHWND, msg, wParam, lParam); handled {
			return result
		}
		wp := hctx.HwndWndProc[parentHWND]
		if wp == 0 {
			// Fallback: recover WndProc via class atom.
			if atom, ok := hctx.HwndClassAtom[parentHWND]; ok {
				if recovered, ok2 := hctx.AtomWndProc[atom]; ok2 && recovered != 0 {
					wp = recovered
					hctx.HwndWndProc[parentHWND] = wp
				}
			}
		}
		cpu := hctx.windowCPU(parentHWND)
		if cpu == nil {
			cpu = hctx.GetCurrentCPU()
		}
		if wp == 0 || cpu == nil || hctx.GuestCallTrampoline == nil {
			hctx.enqueueMessage(nil, newQueuedMsg(hctx, parentHWND, msg, wParam, lParam))
			return 0
		}
		ret, err := ntapi.CallGuestFunction(cpu, mem, hctx.GuestCallTrampoline, wp,
			[]uint64{parentHWND, uint64(msg), wParam, lParam}, false)
		if err != nil {
			hctx.enqueueMessage(nil, newQueuedMsg(hctx, parentHWND, msg, wParam, lParam))
			return 0
		}
		return ret
	}
	measureOwnerListItem := func(state *controlState, index int, itemData uint64) (int32, int32) {
		if state == nil {
			return 0, 0
		}
		mis := hctx.ScratchAlloc(32)
		mem.Write32(mis, 2)
		mem.Write32(mis+4, uint32(state.ctrlID))
		mem.Write32(mis+8, uint32(index))
		mem.Write32(mis+12, uint32(state.w))
		mem.Write32(mis+16, 18)
		if hctx.ProcState != nil && hctx.ProcState.Is32 {
			mem.Write32(mis+20, uint32(itemData))
		} else {
			mem.Write64(mis+24, itemData)
		}
		sendNotifySync(state.parentHWND, 0x002C, state.ctrlID, mis)
		measuredWidth, _ := mem.Read32(mis + 12)
		measuredHeight, _ := mem.Read32(mis + 16)
		return int32(measuredWidth), int32(measuredHeight)
	}
	drawOwnerButton := func(root, hwnd uint64, target *wl.Window) bool {
		state := hctx.HwndChildren[hwnd]
		rootState := hctx.HwndChildren[root]
		if state == nil || rootState == nil || target == nil || state.className != "button" || state.style&0x0F != 11 {
			return false
		}
		oldScreen := gdiMgr.Screen
		gdiMgr.Screen = gdi.WrapPix(target.Pix, target.Width, target.Height+target.TitleBarH, target.Stride)
		hdc, dc := gdiMgr.AllocScreenDC()
		dc.OriginX = state.x - rootState.x
		dc.OriginY = state.y - rootState.y

		is32 := hctx.ProcState != nil && hctx.ProcState.Is32
		dis := hctx.ScratchAlloc(64)
		mem.Write32(dis, 4) // ODT_BUTTON
		mem.Write32(dis+4, uint32(state.ctrlID))
		mem.Write32(dis+8, uint32(^uint32(0)))
		mem.Write32(dis+12, 1) // ODA_DRAWENTIRE
		mem.Write32(dis+16, 0)
		if is32 {
			mem.Write32(dis+20, uint32(hwnd))
			mem.Write32(dis+24, uint32(hdc))
			mem.Write32(dis+28, 0)
			mem.Write32(dis+32, 0)
			mem.Write32(dis+36, uint32(state.w))
			mem.Write32(dis+40, uint32(state.h))
			mem.Write32(dis+44, 0)
		} else {
			mem.Write64(dis+24, hwnd)
			mem.Write64(dis+32, hdc)
			mem.Write32(dis+40, 0)
			mem.Write32(dis+44, 0)
			mem.Write32(dis+48, uint32(state.w))
			mem.Write32(dis+52, uint32(state.h))
			mem.Write64(dis+56, 0)
		}
		sendNotifySync(state.parentHWND, 0x002B, state.ctrlID, dis)
		ravelog.Logf("[ownerdraw] WM_DRAWITEM hwnd=0x%x parent=0x%x id=%d hdc=0x%x\n", hwnd, state.parentHWND, state.ctrlID, hdc)
		gdiMgr.DeleteDC(hdc)
		gdiMgr.Screen = oldScreen
		target.Commit()
		return true
	}
	drawOwnerListBox := func(root, hwnd uint64, target *wl.Window) bool {
		state := hctx.HwndChildren[hwnd]
		rootState := hctx.HwndChildren[root]
		if state == nil || rootState == nil || target == nil || state.className != "listbox" || state.style&0x0030 == 0 {
			return false
		}
		is32 := hctx.ProcState != nil && hctx.ProcState.Is32
		if state.style&0x0020 != 0 {
			if len(state.listItemHeights) != len(state.listItems) {
				state.listItemHeights = make([]int32, len(state.listItems))
			}
			for index := range state.listItems {
				if state.listItemHeights[index] > 0 {
					continue
				}
				itemData := uint64(0)
				if index < len(state.listItemData) {
					itemData = state.listItemData[index]
				}
				measuredWidth, measuredHeight := measureOwnerListItem(state, index, itemData)
				if measuredWidth > 0 && state.listColumnWidth <= 0 {
					state.listColumnWidth = measuredWidth
				}
				if measuredHeight > 0 {
					state.listItemHeights[index] = measuredHeight
				}
			}
		} else if state.listItemHeight <= 0 || state.listColumnWidth <= 0 {
			measuredWidth, measuredHeight := measureOwnerListItem(state, -1, 0)
			if measuredWidth > 0 {
				state.listColumnWidth = measuredWidth
			}
			if measuredHeight > 0 {
				state.listItemHeight = measuredHeight
			}
		}

		oldScreen := gdiMgr.Screen
		gdiMgr.Screen = gdi.WrapPix(target.Pix, target.Width, target.Height+target.TitleBarH, target.Stride)
		hdc, dc := gdiMgr.AllocScreenDC()
		dc.OriginX = state.x - rootState.x
		dc.OriginY = state.y - rootState.y
		for index := range state.listItems {
			left, top, right, bottom, valid := listBoxItemRect(state, index)
			if !valid || left >= state.w || top >= state.h || right <= 0 || bottom <= 0 {
				continue
			}
			itemState := uint32(0)
			if index == state.listCurSel {
				itemState = 0x0001
			}
			itemData := uint64(0)
			if index < len(state.listItemData) {
				itemData = state.listItemData[index]
			}
			dis := hctx.ScratchAlloc(64)
			mem.Write32(dis, 2)
			mem.Write32(dis+4, uint32(state.ctrlID))
			mem.Write32(dis+8, uint32(index))
			mem.Write32(dis+12, 1)
			mem.Write32(dis+16, itemState)
			if is32 {
				mem.Write32(dis+20, uint32(hwnd))
				mem.Write32(dis+24, uint32(hdc))
				mem.Write32(dis+28, uint32(left))
				mem.Write32(dis+32, uint32(top))
				mem.Write32(dis+36, uint32(right))
				mem.Write32(dis+40, uint32(bottom))
				mem.Write32(dis+44, uint32(itemData))
			} else {
				mem.Write64(dis+24, hwnd)
				mem.Write64(dis+32, hdc)
				mem.Write32(dis+40, uint32(left))
				mem.Write32(dis+44, uint32(top))
				mem.Write32(dis+48, uint32(right))
				mem.Write32(dis+52, uint32(bottom))
				mem.Write64(dis+56, itemData)
			}
			sendNotifySync(state.parentHWND, 0x002B, state.ctrlID, dis)
		}
		gdiMgr.DeleteDC(hdc)
		gdiMgr.Screen = oldScreen
		return true
	}
	type dialogEraseDC struct {
		handle uint64
		target *gdi.Surface
	}
	dialogEraseDCs := make(map[uint64]dialogEraseDC)
	hctx.ReleaseDialogPaintDC = func(hwnd uint64) {
		if eraseDC := dialogEraseDCs[hwnd]; eraseDC.handle != 0 {
			gdiMgr.DeleteDC(eraseDC.handle)
			delete(dialogEraseDCs, hwnd)
		}
	}
	hctx.RenderDialogCustom = func(root uint64, target *wl.Window) {
		explicitPage := false
		for _, state := range hctx.HwndChildren {
			if state.parentHWND == root && (strings.EqualFold(state.className, "dialog") || strings.EqualFold(state.className, "#32770")) && state.style&0x40000000 != 0 && state.showCalled {
				explicitPage = true
				break
			}
		}
		var controls []uint64
		for hwnd, state := range hctx.HwndChildren {
			if hwnd == root || state == nil || !state.visible || hctx.HwndWndProc[hwnd] == 0 || !isDialogDescendant(hctx, hwnd, root) {
				continue
			}
			if explicitPage {
				if page := dialogPageFor(hctx, hwnd, root); page != 0 {
					pageState := hctx.HwndChildren[page]
					if pageState == nil || !pageState.showCalled || !pageState.visible {
						continue
					}
				}
			}
			if strings.EqualFold(state.className, "dialog") || strings.EqualFold(state.className, "#32770") {
				continue
			}
			controls = append(controls, hwnd)
		}
		sort.Slice(controls, func(i, j int) bool { return controls[i] < controls[j] })
		for _, hwnd := range controls {
			if !hctx.WinInvalid[hwnd] {
				state := hctx.HwndChildren[hwnd]
				rootState := hctx.HwndChildren[root]
				if state == nil || rootState == nil {
					continue
				}
				surface := gdi.WrapPix(target.Pix, target.Width, target.Height+target.TitleBarH, target.Stride)
				eraseDC := dialogEraseDCs[hwnd]
				targetChanged := eraseDC.target == nil || len(eraseDC.target.Pix) == 0 || len(surface.Pix) == 0
				if !targetChanged {
					targetChanged = &eraseDC.target.Pix[0] != &surface.Pix[0] || eraseDC.target.Width != surface.Width || eraseDC.target.Height != surface.Height || eraseDC.target.Stride != surface.Stride
				}
				if targetChanged {
					if eraseDC.handle != 0 {
						gdiMgr.DeleteDC(eraseDC.handle)
					}
					eraseDC.handle, _ = gdiMgr.AllocTargetDC(surface)
					eraseDC.target = surface
					dialogEraseDCs[hwnd] = eraseDC
				}
				if dc := gdiMgr.GetDC(eraseDC.handle); dc != nil {
					dc.OriginX = state.x - rootState.x
					dc.OriginY = state.y - rootState.y
					dc.SetClipRect(dc.OriginX, dc.OriginY, dc.OriginX+state.w, dc.OriginY+state.h)
				}
				hctx.enqueueMessage(nil, newQueuedMsg(hctx, hwnd, 0x0014, eraseDC.handle, 0))
				hctx.QueuePaint(hwnd)
			}
		}
		var ownerLists []uint64
		for hwnd, state := range hctx.HwndChildren {
			if state != nil && state.visible && state.className == "listbox" && state.style&0x0030 != 0 && isDialogDescendant(hctx, hwnd, root) {
				ownerLists = append(ownerLists, hwnd)
			}
		}
		sort.Slice(ownerLists, func(i, j int) bool { return ownerLists[i] < ownerLists[j] })
		for _, hwnd := range ownerLists {
			drawOwnerListBox(root, hwnd, target)
		}
	}
	writeGuestUTF16Limited := func(ptr uint64, text string, maxChars int) {
		if ptr == 0 || maxChars <= 0 {
			return
		}
		ws := utf16Encode(text)
		limit := maxChars - 1
		if limit < 0 {
			limit = 0
		}
		if len(ws) > limit {
			ws = ws[:limit]
		}
		for i, ch := range ws {
			mem.Write16(ptr+uint64(i*2), ch)
		}
		mem.Write16(ptr+uint64(len(ws))*2, 0)
	}
	writeGuestStringLimited := func(ptr uint64, text string, maxChars int) {
		if ptr == 0 || maxChars <= 0 {
			return
		}
		buf := []byte(text)
		limit := maxChars - 1
		if limit < 0 {
			limit = 0
		}
		if len(buf) > limit {
			buf = buf[:limit]
		}
		for i, b := range buf {
			mem.Write8(ptr+uint64(i), b)
		}
		mem.Write8(ptr+uint64(len(buf)), 0)
	}
	readTooltipText := func(ptr uint64, isWide bool) string {
		if ptr == 0 || ptr == 0xFFFFFFFFFFFFFFFF {
			return ""
		}
		if isWide {
			return readGuestUTF16(ptr)
		}
		return readGuestString(ptr)
	}
	findTooltipIndex := func(tt *tooltipState, hwndTool, uid uint64) int {
		if tt == nil {
			return -1
		}
		for i, tool := range tt.tools {
			if tool.hwnd == hwndTool && tool.id == uid {
				return i
			}
		}
		return -1
	}
	writeToolInfo := func(ptr uint64, tool tooltipTool, isWide bool) {
		if ptr == 0 {
			return
		}
		mem.Write32(ptr+4, tool.flags)
		mem.Write64(ptr+8, tool.hwnd)
		mem.Write64(ptr+16, tool.id)
		mem.Write32(ptr+24, uint32(tool.rect[0]))
		mem.Write32(ptr+28, uint32(tool.rect[1]))
		mem.Write32(ptr+32, uint32(tool.rect[2]))
		mem.Write32(ptr+36, uint32(tool.rect[3]))
		pszText, _ := mem.Read64(ptr + 48)
		cchTextMax := 260
		if pszText != 0 {
			if isWide {
				writeGuestUTF16Limited(pszText, tool.text, cchTextMax)
			} else {
				writeGuestStringLimited(pszText, tool.text, cchTextMax)
			}
		}
	}
	parseToolInfo := func(ptr uint64, isWide bool) (tooltipTool, bool) {
		if ptr == 0 {
			return tooltipTool{}, false
		}
		flags, _ := mem.Read32(ptr + 4)
		hwndTool, _ := mem.Read64(ptr + 8)
		uid, _ := mem.Read64(ptr + 16)
		left, _ := mem.Read32(ptr + 24)
		top, _ := mem.Read32(ptr + 28)
		right, _ := mem.Read32(ptr + 32)
		bottom, _ := mem.Read32(ptr + 36)
		pszText, _ := mem.Read64(ptr + 48)
		return tooltipTool{
			id:    uid,
			hwnd:  hwndTool,
			text:  readTooltipText(pszText, isWide),
			rect:  [4]int32{int32(left), int32(top), int32(right), int32(bottom)},
			flags: flags,
		}, true
	}
	readHeaderItem := func(ptr uint64, isWide bool) headerItem {
		item := headerItem{width: 80, order: -1, image: -1}
		if ptr == 0 {
			return item
		}
		mask, _ := mem.Read32(ptr)
		if mask&0x0001 != 0 {
			cxy, _ := mem.Read32(ptr + 4)
			item.width = int32(cxy)
		}
		if mask&0x0002 != 0 {
			pszText, _ := mem.Read64(ptr + 8)
			item.text = readTooltipText(pszText, isWide)
		}
		if mask&0x0004 != 0 {
			hbm, _ := mem.Read64(ptr + 16)
			item.bitmap = hbm
		}
		if mask&0x0008 != 0 {
			fmtV, _ := mem.Read32(ptr + 28)
			item.fmt = int32(fmtV)
		}
		if mask&0x0010 != 0 {
			param, _ := mem.Read64(ptr + 32)
			item.param = param
		}
		if mask&0x0020 != 0 {
			iImage, _ := mem.Read32(ptr + 40)
			item.image = int32(iImage)
		}
		if mask&0x0080 != 0 {
			iOrder, _ := mem.Read32(ptr + 44)
			item.order = int32(iOrder)
		}
		if mask&0x0200 != 0 {
			state, _ := mem.Read32(ptr + 60)
			item.state = state
		}
		return item
	}
	writeHeaderItem := func(ptr uint64, src headerItem, isWide bool) {
		if ptr == 0 {
			return
		}
		mask, _ := mem.Read32(ptr)
		if mask&0x0001 != 0 {
			mem.Write32(ptr+4, uint32(src.width))
		}
		if mask&0x0002 != 0 {
			pszText, _ := mem.Read64(ptr + 8)
			cchTextMax, _ := mem.Read32(ptr + 24)
			if isWide {
				writeGuestUTF16Limited(pszText, src.text, int(cchTextMax))
			} else {
				writeGuestStringLimited(pszText, src.text, int(cchTextMax))
			}
		}
		if mask&0x0004 != 0 {
			mem.Write64(ptr+16, src.bitmap)
		}
		if mask&0x0008 != 0 {
			mem.Write32(ptr+28, uint32(src.fmt))
		}
		if mask&0x0010 != 0 {
			mem.Write64(ptr+32, src.param)
		}
		if mask&0x0020 != 0 {
			mem.Write32(ptr+40, uint32(src.image))
		}
		if mask&0x0080 != 0 {
			mem.Write32(ptr+44, uint32(src.order))
		}
		if mask&0x0200 != 0 {
			mem.Write32(ptr+60, src.state)
		}
	}
	listViewGetItemCount := func(lv *listViewState) int {
		if lv == nil {
			return 0
		}
		if lv.style&0x1000 != 0 {
			return lv.virtualCount
		}
		return len(lv.items)
	}
	listViewFetchVirtualItem := func(hwnd uint64, cs *controlState, idx, subIdx int, wide bool) lvItem {
		lv := cs.listView
		if lv == nil {
			return lvItem{}
		}
		is32 := hctx.ProcState != nil && hctx.ProcState.Is32
		notifyLayout := listViewNotifyOffsets(is32)
		itemLayout := listViewItemOffsets(is32)
		var item lvItem
		if idx >= 0 && idx < len(lv.items) {
			item = lv.items[idx]
		}
		bufChars := 260
		textBuf := hctx.ScratchAlloc(uint64(bufChars * 2))
		nm := hctx.ScratchAlloc(notifyLayout.size)
		for offset := uint64(0); offset < notifyLayout.size; offset += 4 {
			mem.Write32(nm+offset, 0)
		}
		if is32 {
			mem.Write32(nm, uint32(hwnd))
			mem.Write32(nm+4, uint32(cs.ctrlID))
			if wide {
				mem.Write32(nm+8, 0xFFFFFF4F)
			} else {
				mem.Write32(nm+8, 0xFFFFFF6A)
			}
		} else {
			mem.Write64(nm, hwnd)
			mem.Write64(nm+8, cs.ctrlID)
			if wide {
				mem.Write32(nm+16, 0xFFFFFF4F)
			} else {
				mem.Write32(nm+16, 0xFFFFFF6A)
			}
		}
		base := nm + notifyLayout.header
		mem.Write32(base, 0x000F)
		mem.Write32(base+4, uint32(idx))
		mem.Write32(base+8, uint32(subIdx))
		mem.Write32(base+12, item.state)
		mem.Write32(base+16, 0xFFFFFFFF)
		_ = writeGuestPointer(mem, base+itemLayout.text, textBuf, is32)
		mem.Write32(base+itemLayout.textMax, uint32(bufChars))
		mem.Write32(base+itemLayout.image, uint32(item.image))
		_ = writeGuestPointer(mem, base+itemLayout.param, item.param, is32)
		sendNotifySync(cs.parentHWND, 0x004E, uint64(cs.ctrlID), nm)
		pszText, _ := readGuestPointer(mem, base+itemLayout.text, is32)
		if pszText == 0 {
			pszText = textBuf
		}
		if wide {
			item.text = readGuestUTF16(pszText)
		} else {
			item.text = readGuestString(pszText)
		}
		item.state, _ = mem.Read32(base + 12)
		iImage, _ := mem.Read32(base + itemLayout.image)
		item.image = int(int32(iImage))
		item.param, _ = readGuestPointer(mem, base+itemLayout.param, is32)
		return item
	}

	// builtinWndProc handles messages for built-in window classes (Edit, StatusBar, etc.)
	// Returns (result, handled).
	hctx.BuiltinWndProc = func(hwnd uint64, msg uint32, wParam, lParam uint64) (uint64, bool) {
		cs, ok := hctx.HwndChildren[hwnd]
		if !ok {
			return 0, false
		}
		initBuiltinControlState(cs)

		switch msg {
		case 0x00F0: // BM_GETCHECK
			if cs.className == "button" {
				ravelog.Logf("[button] BM_GETCHECK hwnd=0x%x id=%d state=%d\n", hwnd, cs.ctrlID, cs.checkState)
				return uint64(cs.checkState), true
			}
		case 0x00F1: // BM_SETCHECK
			if cs.className == "button" {
				cs.checkState = uint32(wParam)
				ravelog.Logf("[button] BM_SETCHECK hwnd=0x%x id=%d state=%d\n", hwnd, cs.ctrlID, cs.checkState)
				if cs.parentHWND != 0 {
					hctx.QueuePaint(cs.parentHWND)
				}
				return 0, true
			}
		case 0x000F: // WM_PAINT
			if root, target, isOwnedDialog := topLevelDialogTarget(hctx, hwnd); isOwnedDialog {
				if target != nil {
					if hwnd != root && hctx.HwndWndProc[hwnd] != 0 {
						return 0, false
					}
					hctx.WinInvalid[hwnd] = false
					delete(hctx.WinErasePending, hwnd)
					win32.Global.Validate(hwnd)
					renderOwnedDialog(hctx, root, target)
					drawOwnerButton(root, hwnd, target)
				}
				return 0, true
			}
			hctx.WinInvalid[hwnd] = false
			delete(hctx.WinErasePending, hwnd)
			win32.Global.Validate(hwnd)
			if wlWindow == nil {
				return 0, true
			}
			switch cs.className {
			case "dialog", "dialogbox":
				wlWindow.DrawRectAbs(cs.x, cs.y, cs.x+cs.w, cs.y+cs.h, sysColors[15])
				wlWindow.DrawRectAbs(cs.x, cs.y, cs.x+cs.w, cs.y+1, sysColors[16])
				wlWindow.DrawRectAbs(cs.x, cs.y, cs.x+1, cs.y+cs.h, sysColors[16])
				wlWindow.DrawRectAbs(cs.x, cs.y+cs.h-1, cs.x+cs.w, cs.y+cs.h, sysColors[20])
				wlWindow.DrawRectAbs(cs.x+cs.w-1, cs.y, cs.x+cs.w, cs.y+cs.h, sysColors[20])
			case "edit":
				// 3D sunken border
				wlWindow.DrawRectAbs(cs.x, cs.y, cs.x+cs.w, cs.y+1, sysColors[16])            // top shadow
				wlWindow.DrawRectAbs(cs.x, cs.y, cs.x+1, cs.y+cs.h, sysColors[16])            // left shadow
				wlWindow.DrawRectAbs(cs.x+1, cs.y+1, cs.x+cs.w-1, cs.y+2, 0x404040)           // inner top
				wlWindow.DrawRectAbs(cs.x+1, cs.y+1, cs.x+2, cs.y+cs.h-1, 0x404040)           // inner left
				wlWindow.DrawRectAbs(cs.x+cs.w-1, cs.y, cs.x+cs.w, cs.y+cs.h, sysColors[20])  // right highlight
				wlWindow.DrawRectAbs(cs.x, cs.y+cs.h-1, cs.x+cs.w, cs.y+cs.h, sysColors[20])  // bottom highlight
				wlWindow.DrawRectAbs(cs.x+cs.w-2, cs.y+1, cs.x+cs.w-1, cs.y+cs.h-1, 0xDFDFDF) // inner right
				wlWindow.DrawRectAbs(cs.x+1, cs.y+cs.h-2, cs.x+cs.w-1, cs.y+cs.h-1, 0xDFDFDF) // inner bottom
				// White client area
				wlWindow.DrawRectAbs(cs.x+2, cs.y+2, cs.x+cs.w-2, cs.y+cs.h-2, sysColors[5])
				// Draw text content
				if cs.text != "" {
					hctx.NcDrawText(cs.x+4, cs.y+4, cs.text, 0x000000, sysColors[5], true, 12)
				}
				// Text cursor (blinking caret) - tracks last line for multiline edits
				cursorX := cs.x + 4
				cursorY := cs.y + 4
				if cs.text != "" {
					lines := strings.Split(cs.text, "\n")
					cursorY += int32((len(lines) - 1) * 16)
					cursorX += int32(len([]rune(lines[len(lines)-1]))) * 8
				}
				wlWindow.DrawRectAbs(cursorX, cursorY, cursorX+1, cursorY+16, 0x000000)
			case "msctls_statusbar32":
				syncStatusBarCompat(cs)
				// Snap statusbar to bottom of Wayland window (common control behavior: WM_SIZE repositions it)
				if wlWindow != nil {
					sbY := wlWindow.Height + wlWindow.TitleBarH - cs.h
					if sbY > cs.y {
						cs.y = sbY
					} // only snap down, not up
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
						if rightEdge < 0 {
							right = cs.x + cs.w
						}
						// Sunken part area
						wlWindow.DrawRectAbs(left, cs.y+3, right-1, cs.y+4, sysColors[16])           // top shadow
						wlWindow.DrawRectAbs(left, cs.y+3, left+1, cs.y+cs.h-2, sysColors[16])       // left shadow
						wlWindow.DrawRectAbs(left, cs.y+cs.h-2, right-1, cs.y+cs.h-1, sysColors[20]) // bottom highlight
						wlWindow.DrawRectAbs(right-2, cs.y+3, right-1, cs.y+cs.h-1, sysColors[20])   // right highlight
						if right > left+4 {
							wlWindow.DrawRectAbs(left+2, cs.y+4, right-3, cs.y+cs.h-2, sysColors[15])
						}
						if i < len(cs.sbTexts) && cs.sbTexts[i] != "" {
							// Clip text to pane bounds so adjacent panes don't bleed into each other.
							hctx.NcDrawTextClipped(left+4, cs.y+4, left+4, cs.y+3, right-3, cs.y+cs.h-2, cs.sbTexts[i], 0x000000, sysColors[15], true, 12)
						}
						left = right
					}
				} else if cs.text != "" {
					hctx.NcDrawText(cs.x+4, cs.y+4, cs.text, 0x000000, sysColors[15], true, 12)
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
			case "msctls_progress32":
				syncProgressBarCompat(cs)
				bg := uint32(0xE6E6E6)
				fill := uint32(0x0078D7)
				if cs.progress != nil {
					if cs.progress.bkColor != 0 {
						bg = cs.progress.bkColor
					}
					if cs.progress.barColor != 0 {
						fill = cs.progress.barColor
					}
					switch cs.progress.state {
					case 2:
						fill = 0xD9534F
					case 3:
						fill = 0xF0AD4E
					}
				}
				wlWindow.DrawRectAbs(cs.x, cs.y, cs.x+cs.w, cs.y+cs.h, bg)
				wlWindow.DrawRectAbs(cs.x, cs.y, cs.x+cs.w, cs.y+1, 0xC8C8C8)
				wlWindow.DrawRectAbs(cs.x, cs.y, cs.x+1, cs.y+cs.h, 0xC8C8C8)
				wlWindow.DrawRectAbs(cs.x, cs.y+cs.h-1, cs.x+cs.w, cs.y+cs.h, 0xFFFFFF)
				wlWindow.DrawRectAbs(cs.x+cs.w-1, cs.y, cs.x+cs.w, cs.y+cs.h, 0xFFFFFF)
				if cs.progressBarCompat != nil {
					minV := cs.progressBarCompat.min
					maxV := cs.progressBarCompat.max
					posV := clampInt32(cs.progressBarCompat.pos, minV, maxV)
					rangeV := maxV - minV
					if rangeV <= 0 {
						rangeV = 1
					}
					fillW := (cs.w - 2) * (posV - minV) / rangeV
					if fillW < 0 {
						fillW = 0
					}
					if fillW > cs.w-2 {
						fillW = cs.w - 2
					}
					if fillW > 0 {
						wlWindow.DrawRectAbs(cs.x+1, cs.y+1, cs.x+1+fillW, cs.y+cs.h-1, fill)
					}
				}
			case "static":
				wlWindow.DrawRectAbs(cs.x, cs.y, cs.x+cs.w, cs.y+cs.h, sysColors[15])
				if cs.text != "" {
					hctx.NcDrawText(cs.x+2, cs.y+2, hctx.MenuStripAmpersand(cs.text), 0x000000, sysColors[15], true, 12)
				}
			case "combobox", "comboboxex32":
				h := cs.h
				if h > 24 {
					h = 24
				}
				if h < 18 {
					h = 18
				}
				arrowW := int32(20)
				wlWindow.DrawRectAbs(cs.x, cs.y, cs.x+cs.w, cs.y+h, sysColors[5])
				wlWindow.DrawRectAbs(cs.x, cs.y, cs.x+cs.w, cs.y+1, sysColors[16])
				wlWindow.DrawRectAbs(cs.x, cs.y, cs.x+1, cs.y+h, sysColors[16])
				wlWindow.DrawRectAbs(cs.x+cs.w-1, cs.y, cs.x+cs.w, cs.y+h, sysColors[20])
				wlWindow.DrawRectAbs(cs.x, cs.y+h-1, cs.x+cs.w, cs.y+h, sysColors[20])
				wlWindow.DrawRectAbs(cs.x+cs.w-arrowW, cs.y+1, cs.x+cs.w-1, cs.y+h-1, sysColors[15])
				ax := cs.x + cs.w - arrowW/2
				ay := cs.y + h/2
				wlWindow.DrawRectAbs(ax-4, ay-2, ax+4, ay-1, 0x000000)
				wlWindow.DrawRectAbs(ax-3, ay-1, ax+3, ay, 0x000000)
				wlWindow.DrawRectAbs(ax-2, ay, ax+2, ay+1, 0x000000)
				if cs.text != "" {
					hctx.NcDrawTextClipped(cs.x+4, cs.y+4, cs.x+2, cs.y+2, cs.x+cs.w-arrowW-2, cs.y+h-2, cs.text, 0x000000, sysColors[5], true, 12)
				}
			case "button":
				label := hctx.MenuStripAmpersand(cs.text)
				switch cs.style & 0x0F {
				case 2, 3, 5, 6, 4, 9:
					wlWindow.DrawRectAbs(cs.x, cs.y, cs.x+cs.w, cs.y+cs.h, sysColors[15])
					boxY := cs.y + (cs.h-13)/2
					wlWindow.DrawRectAbs(cs.x, boxY, cs.x+13, boxY+13, sysColors[5])
					wlWindow.DrawRectAbs(cs.x, boxY, cs.x+13, boxY+1, sysColors[16])
					wlWindow.DrawRectAbs(cs.x, boxY, cs.x+1, boxY+13, sysColors[16])
					wlWindow.DrawRectAbs(cs.x+12, boxY, cs.x+13, boxY+13, sysColors[20])
					wlWindow.DrawRectAbs(cs.x, boxY+12, cs.x+13, boxY+13, sysColors[20])
					if cs.checkState != 0 {
						wlWindow.DrawRectAbs(cs.x+3, boxY+5, cs.x+6, boxY+8, 0x000000)
						wlWindow.DrawRectAbs(cs.x+6, boxY+3, cs.x+10, boxY+6, 0x000000)
					}
					hctx.NcDrawText(cs.x+18, cs.y+(cs.h-16)/2, label, 0x000000, sysColors[15], true, 12)
				case 7:
					wlWindow.DrawRectAbs(cs.x, cs.y+8, cs.x+cs.w, cs.y+9, sysColors[16])
					wlWindow.DrawRectAbs(cs.x, cs.y+8, cs.x+1, cs.y+cs.h, sysColors[16])
					wlWindow.DrawRectAbs(cs.x, cs.y+cs.h-1, cs.x+cs.w, cs.y+cs.h, sysColors[20])
					wlWindow.DrawRectAbs(cs.x+cs.w-1, cs.y+8, cs.x+cs.w, cs.y+cs.h, sysColors[20])
					if label != "" {
						hctx.NcDrawText(cs.x+8, cs.y, label, 0x000000, sysColors[15], true, 12)
					}
				default:
					wlWindow.DrawRectAbs(cs.x, cs.y, cs.x+cs.w, cs.y+cs.h, sysColors[15])
					wlWindow.DrawRectAbs(cs.x, cs.y, cs.x+cs.w, cs.y+1, sysColors[20])
					wlWindow.DrawRectAbs(cs.x, cs.y, cs.x+1, cs.y+cs.h, sysColors[20])
					wlWindow.DrawRectAbs(cs.x, cs.y+cs.h-1, cs.x+cs.w, cs.y+cs.h, sysColors[16])
					wlWindow.DrawRectAbs(cs.x+cs.w-1, cs.y, cs.x+cs.w, cs.y+cs.h, sysColors[16])
					if label != "" {
						tx := cs.x + (cs.w-int32(len([]rune(label)))*8)/2
						ty := cs.y + (cs.h-16)/2
						hctx.NcDrawText(tx, ty, label, 0x000000, sysColors[15], true, 12)
					}
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
								textColor := uint32(0x000000)
								background := sysColors[5]
								if cs.treeView != nil && cs.treeView.selected != nil && cs.treeView.selected.handle == h {
									background = sysColors[13]
									textColor = sysColors[14]
									wlWindow.DrawRectAbs(tx-2, ty, cs.x+cs.w-2, ty+itemHeight, background)
								}
								hctx.NcDrawText(tx, ty+1, ti.text, textColor, background, true, 12)
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
				syncListViewCompat(cs)
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
							hctx.NcDrawText(colX+4, cs.y+3, col.text, 0x000000, sysColors[15], true, 12)
						}
						colX += col.width
						// Column separator
						wlWindow.DrawRectAbs(colX-1, cs.y+1, colX, cs.y+21, sysColors[16])
					}
				}
				if cs.listView != nil {
					rowY := cs.y + 24
					rowH := int32(18)
					itemCount := listViewGetItemCount(cs.listView)
					for i := 0; i < itemCount; i++ {
						if rowY+rowH > cs.y+cs.h-1 {
							break
						}
						item := lvItem{}
						if cs.listView.style&0x1000 != 0 {
							item = listViewFetchVirtualItem(hwnd, cs, i, 0, true)
						} else if i < len(cs.listView.items) {
							item = cs.listView.items[i]
						}
						bg := sysColors[5]
						if item.state&0x0002 != 0 {
							bg = 0xD9E8FB
						}
						wlWindow.DrawRectAbs(cs.x+2, rowY, cs.x+cs.w-2, rowY+rowH, bg)
						colX := cs.x + 6
						if item.text != "" {
							hctx.NcDrawText(colX, rowY+1, item.text, 0x000000, bg, true, 12)
						}
						colCount := len(cs.listView.columns)
						for subIdx := 1; subIdx < colCount; subIdx++ {
							width := int32(cs.listView.columns[subIdx-1].width)
							if width <= 0 {
								width = 100
							}
							colX += width
							sub := ""
							if cs.listView.style&0x1000 != 0 {
								sub = listViewFetchVirtualItem(hwnd, cs, i, subIdx, true).text
							} else if subIdx-1 < len(item.subItems) {
								sub = item.subItems[subIdx-1]
							}
							if sub != "" {
								hctx.NcDrawText(colX+4, rowY+1, sub, 0x000000, bg, true, 12)
							}
						}
						rowY += rowH
					}
				}
			case "sysheader32":
				if cs.header != nil {
					wlWindow.DrawRectAbs(cs.x, cs.y, cs.x+cs.w, cs.y+cs.h, sysColors[15])
					wlWindow.DrawRectAbs(cs.x, cs.y, cs.x+cs.w, cs.y+1, sysColors[20])
					wlWindow.DrawRectAbs(cs.x, cs.y, cs.x+1, cs.y+cs.h, sysColors[20])
					wlWindow.DrawRectAbs(cs.x, cs.y+cs.h-1, cs.x+cs.w, cs.y+cs.h, sysColors[16])
					wlWindow.DrawRectAbs(cs.x+cs.w-1, cs.y, cs.x+cs.w, cs.y+cs.h, sysColors[16])
					x := cs.x
					for i, item := range cs.header.items {
						w := item.width
						if w <= 0 {
							w = 80
						}
						wlWindow.DrawRectAbs(x, cs.y, x+w, cs.y+cs.h, sysColors[15])
						wlWindow.DrawRectAbs(x+w-1, cs.y+1, x+w, cs.y+cs.h-1, sysColors[16])
						if item.text != "" {
							hctx.NcDrawText(x+6, cs.y+4, item.text, 0x000000, sysColors[15], true, 12)
						}
						if int32(i) == cs.header.focusedIdx {
							wlWindow.DrawRectAbs(x+2, cs.y+2, x+w-2, cs.y+cs.h-2, 0xBBD7F2)
						}
						x += w
						if x >= cs.x+cs.w {
							break
						}
					}
				}
			case "systabcontrol32":
				syncTabCompat(cs)
				const tabH = int32(22)
				const tabPad = int32(16) // padding on each side of text
				wlWindow.DrawRectAbs(cs.x, cs.y, cs.x+cs.w, cs.y+cs.h, sysColors[15])
				wlWindow.DrawRectAbs(cs.x, cs.y+tabH-1, cs.x+cs.w, cs.y+tabH, sysColors[16])
				tx := cs.x
				for i := 0; i < cs.tabCount; i++ {
					sel := i == cs.tabCurSel
					bgCol := sysColors[15]
					if sel {
						bgCol = sysColors[5]
					}
					label := ""
					if i < len(cs.tabTitles) {
						label = cs.tabTitles[i]
					}
					tabW := menuTextWidth(label) + tabPad*2
					if tabW < 40 {
						tabW = 40
					}
					wlWindow.DrawRectAbs(tx, cs.y, tx+tabW, cs.y+tabH, bgCol)
					wlWindow.DrawRectAbs(tx, cs.y, tx+1, cs.y+tabH, sysColors[16])
					wlWindow.DrawRectAbs(tx+tabW-1, cs.y, tx+tabW, cs.y+tabH, sysColors[16])
					wlWindow.DrawRectAbs(tx, cs.y, tx+tabW, cs.y+1, sysColors[16])
					if label != "" {
						hctx.NcDrawText(tx+tabPad/2, cs.y+4, label, 0x000000, bgCol, false, 12)
					}
					tx += tabW
				}
			default:
				if _, hasGuest := hctx.HwndWndProc[hwnd]; hasGuest {
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

		case 0x0201: // WM_LBUTTONDOWN
			if hctx.HwndWndProc[hwnd] != 0 && !hctx.CallBuiltinControl {
				return 0, false
			}
			if cs.className == "button" || cs.className == "listbox" {
				return 0, true
			}

		case 0x0202: // WM_LBUTTONUP
			if hctx.HwndWndProc[hwnd] != 0 && !hctx.CallBuiltinControl {
				return 0, false
			}
			if cs.className == "button" {
				switch cs.style & 0x0F {
				case 3, 6: // BS_AUTOCHECKBOX, BS_AUTO3STATE
					cs.checkState = (cs.checkState + 1) % 2
				case 9: // BS_AUTORADIOBUTTON
					for _, sibling := range hctx.HwndChildren {
						if sibling.parentHWND == cs.parentHWND && sibling.className == "button" && sibling.style&0x0F == 9 {
							sibling.checkState = 0
						}
					}
					cs.checkState = 1
				}
				if cs.parentHWND != 0 {
					ravelog.Logf("[button] BN_CLICKED hwnd=0x%x parent=0x%x id=%d checked=%d\n", hwnd, cs.parentHWND, cs.ctrlID, cs.checkState)
					hctx.enqueueMessage(nil, newQueuedMsg(hctx, cs.parentHWND, 0x0111, cs.ctrlID&0xFFFF, hwnd))
				}
				hctx.QueuePaint(hwnd)
				return 0, true
			}
			if cs.className == "listbox" {
				x := int32(int16(lParam & 0xFFFF))
				y := int32(int16((lParam >> 16) & 0xFFFF))
				index, outside := listBoxItemFromPoint(cs, x, y)
				if !outside && index >= 0 {
					cs.listCurSel = index
					if cs.parentHWND != 0 {
						hctx.enqueueMessage(nil, newQueuedMsg(hctx, cs.parentHWND, 0x0111, (uint64(1)<<16)|(cs.ctrlID&0xFFFF), hwnd))
					}
					hctx.QueuePaint(hwnd)
				}
				return 0, true
			}

		case 0x000C: // WM_SETTEXT
			if lParam != 0 {
				cs.text = readGuestUTF16(lParam)
			}
			return 1, true

		case 0x000D: // WM_GETTEXT
			maxChars := wParam
			buf := lParam
			if buf == 0 || maxChars == 0 {
				return 0, true
			}
			ws := utf16Encode(cs.text)
			limit := uint64(len(ws))
			if limit+1 > maxChars {
				limit = maxChars - 1
			}
			for i := uint64(0); i < limit; i++ {
				mem.Write16(buf+i*2, ws[i])
			}
			mem.Write16(buf+limit*2, 0) // null terminator
			return limit, true

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
			if wp, ok := hctx.HwndWndProc[hwnd]; ok && wp != 0 {
				return 0, false
			}
			return 0, true

		case 0x0001: // WM_CREATE
			// Visibility is set in CreateWindowExW from WS_VISIBLE; do NOT override here.
			// If there's a guest WndProc, let it handle WM_CREATE too
			if wp, ok := hctx.HwndWndProc[hwnd]; ok && wp != 0 {
				return 0, false
			}
			return 0, true

		case 0x0007: // WM_SETFOCUS
			hctx.FocusHwnd = hwnd
			// If the window has a guest WndProc (e.g. Scintilla), let it receive
			// WM_SETFOCUS too so it can set up its caret / input state.
			if _, hasGuest := hctx.HwndWndProc[hwnd]; hasGuest {
				return 0, false
			}
			return 0, true
		case 0x0008: // WM_KILLFOCUS
			// Forward to guest WndProc if present (e.g. Scintilla needs to hide its caret).
			if _, hasGuest := hctx.HwndWndProc[hwnd]; hasGuest {
				return 0, false
			}
			return 0, true
		case 0x0030: // WM_SETFONT
			return 0, true
		}

		if cs.className == "combobox" || cs.className == "comboboxex32" {
			const (
				cbsSimple       = uint32(1)
				cbsDropdownList = uint32(3)
				cbsHasStrings   = uint32(0x0200)
			)
			comboType := cs.style & 3
			comboStoresStrings := cs.style&0x0030 == 0 || cs.style&cbsHasStrings != 0
			if comboType == cbsSimple {
				cs.comboDropped = true
			}
			cbErr := ^uint64(0)
			switch msg {
			case 0x0201: // WM_LBUTTONDOWN
				y := int32(int16((lParam >> 16) & 0xFFFF))
				if comboType == cbsSimple && y < 24 {
					return 0, true
				}
				if !cs.comboDropped || y < 24 {
					cs.comboDropped = !cs.comboDropped
					cs.comboPressedIndex = 0
					if cs.comboDropped && cs.comboCurSel >= 0 {
						cs.comboTopIndex = cs.comboCurSel
						if cs.comboTopIndex > len(cs.comboItems)-8 {
							cs.comboTopIndex = len(cs.comboItems) - 8
						}
						if cs.comboTopIndex < 0 {
							cs.comboTopIndex = 0
						}
					}
					ravelog.Logf("[combobox] dropdown hwnd=0x%x parent=0x%x id=%d open=%t items=%d\n", hwnd, cs.parentHWND, cs.ctrlID, cs.comboDropped, len(cs.comboItems))
					if cs.parentHWND != 0 {
						if cs.comboDropped {
							hctx.enqueueMessage(nil, newQueuedMsg(hctx, cs.parentHWND, 0x0111, (uint64(7)<<16)|(cs.ctrlID&0xFFFF), hwnd))
						} else {
							hctx.enqueueMessage(nil,
								newQueuedMsg(hctx, cs.parentHWND, 0x0111, (uint64(10)<<16)|(cs.ctrlID&0xFFFF), hwnd),
								newQueuedMsg(hctx, cs.parentHWND, 0x0111, (uint64(8)<<16)|(cs.ctrlID&0xFFFF), hwnd),
							)
						}
					}
				} else {
					index := cs.comboTopIndex + int((y-26)/18)
					if index >= 0 && index < len(cs.comboItems) {
						cs.comboPressedIndex = index + 1
						hctx.MouseCapture = hwnd
						ravelog.Logf("[combobox] press hwnd=0x%x index=%d capture=0x%x\n", hwnd, index, hctx.MouseCapture)
					}
				}
				if hctx.RequestWindowRepaint != nil {
					hctx.RequestWindowRepaint(hwnd)
				} else {
					hctx.QueuePaint(hwnd)
				}
				return 0, true
			case 0x020A: // WM_MOUSEWHEEL
				if cs.comboDropped && len(cs.comboItems) > 8 {
					delta := int16((wParam >> 16) & 0xFFFF)
					if delta > 0 && cs.comboTopIndex > 0 {
						cs.comboTopIndex--
					} else if delta < 0 && cs.comboTopIndex < len(cs.comboItems)-8 {
						cs.comboTopIndex++
					}
					if hctx.RequestWindowRepaint != nil {
						hctx.RequestWindowRepaint(hwnd)
					}
				}
				return 0, true
			case 0x0202: // WM_LBUTTONUP
				if cs.comboDropped && cs.comboPressedIndex > 0 {
					index := cs.comboPressedIndex - 1
					cs.comboPressedIndex = 0
					if hctx.MouseCapture == hwnd {
						hctx.MouseCapture = 0
					}
					y := int32(int16((lParam >> 16) & 0xFFFF))
					releaseIndex := cs.comboTopIndex + int((y-26)/18)
					if cs.comboPopupAbove {
						rows := len(cs.comboItems) - cs.comboTopIndex
						if rows > 8 {
							rows = 8
						}
						releaseIndex = cs.comboTopIndex + int((y+int32(rows*18+4)-2)/18)
					}
					accepted := releaseIndex == index && index >= 0 && index < len(cs.comboItems)
					ravelog.Logf("[combobox] release hwnd=0x%x pressed=%d release=%d accepted=%t\n", hwnd, index, releaseIndex, accepted)
					if accepted {
						cs.comboCurSel = index
						cs.text = cs.comboItems[index]
						ravelog.Logf("[combobox] select hwnd=0x%x parent=0x%x id=%d index=%d text=%q\n", hwnd, cs.parentHWND, cs.ctrlID, index, cs.text)
						if cs.parentHWND != 0 {
							hctx.enqueueMessage(nil,
								newQueuedMsg(hctx, cs.parentHWND, 0x0111, (uint64(1)<<16)|(cs.ctrlID&0xFFFF), hwnd),
								newQueuedMsg(hctx, cs.parentHWND, 0x0111, (uint64(9)<<16)|(cs.ctrlID&0xFFFF), hwnd),
								newQueuedMsg(hctx, cs.parentHWND, 0x0111, (uint64(8)<<16)|(cs.ctrlID&0xFFFF), hwnd),
							)
						}
					}
					if !accepted && cs.parentHWND != 0 {
						hctx.enqueueMessage(nil, newQueuedMsg(hctx, cs.parentHWND, 0x0111, (uint64(10)<<16)|(cs.ctrlID&0xFFFF), hwnd))
					}
					cs.comboDropped = comboType == cbsSimple
					if cs.parentHWND != 0 && !accepted {
						hctx.enqueueMessage(nil, newQueuedMsg(hctx, cs.parentHWND, 0x0111, (uint64(8)<<16)|(cs.ctrlID&0xFFFF), hwnd))
					}
					if hctx.RequestWindowRepaint != nil {
						hctx.RequestWindowRepaint(hwnd)
					}
				}
				return 0, true
			case 0x0102: // WM_CHAR
				if comboType == cbsDropdownList {
					return 0, true
				}
				ch := rune(wParam)
				if ch == '\b' {
					runes := []rune(cs.text)
					if len(runes) > 0 {
						cs.text = string(runes[:len(runes)-1])
					}
				} else if ch >= 0x20 {
					cs.text += string(ch)
				}
				if cs.parentHWND != 0 {
					hctx.enqueueMessage(nil, newQueuedMsg(hctx, cs.parentHWND, 0x0111, (uint64(5)<<16)|(cs.ctrlID&0xFFFF), hwnd))
				}
				if hctx.RequestWindowRepaint != nil {
					hctx.RequestWindowRepaint(hwnd)
				} else {
					hctx.QueuePaint(hwnd)
				}
				return 0, true
			case 0x0100, 0x0101: // WM_KEYDOWN, WM_KEYUP
				return 0, true
			case 0x0143: // CB_ADDSTRING
				item := ""
				itemData := uint64(0)
				if comboStoresStrings {
					item = readGuestUTF16(lParam)
				} else {
					itemData = lParam
				}
				cs.comboItems = append(cs.comboItems, item)
				cs.comboItemData = append(cs.comboItemData, itemData)
				return uint64(len(cs.comboItems) - 1), true
			case 0x0144: // CB_DELETESTRING
				index := int(int32(wParam))
				if index < 0 || index >= len(cs.comboItems) {
					return cbErr, true
				}
				oldSelection := cs.comboCurSel
				cs.comboItems = append(cs.comboItems[:index], cs.comboItems[index+1:]...)
				cs.comboItemData = append(cs.comboItemData[:index], cs.comboItemData[index+1:]...)
				if oldSelection == index {
					cs.comboCurSel = -1
					cs.text = ""
				} else if oldSelection > index {
					cs.comboCurSel--
				}
				return uint64(len(cs.comboItems)), true
			case 0x0146: // CB_GETCOUNT
				return uint64(len(cs.comboItems)), true
			case 0x0147: // CB_GETCURSEL
				if cs.comboCurSel < 0 {
					return cbErr, true
				}
				return uint64(cs.comboCurSel), true
			case 0x0148: // CB_GETLBTEXT
				index := int(int32(wParam))
				if index < 0 || index >= len(cs.comboItems) || lParam == 0 {
					return cbErr, true
				}
				text := utf16Encode(cs.comboItems[index])
				for i, ch := range text {
					mem.Write16(lParam+uint64(i*2), ch)
				}
				mem.Write16(lParam+uint64(len(text)*2), 0)
				return uint64(len(text)), true
			case 0x0149: // CB_GETLBTEXTLEN
				index := int(int32(wParam))
				if index < 0 || index >= len(cs.comboItems) {
					return cbErr, true
				}
				return uint64(len(utf16Encode(cs.comboItems[index]))), true
			case 0x014A: // CB_INSERTSTRING
				index := int(int32(wParam))
				if index < 0 || index > len(cs.comboItems) {
					index = len(cs.comboItems)
				}
				cs.comboItems = append(cs.comboItems, "")
				copy(cs.comboItems[index+1:], cs.comboItems[index:])
				if comboStoresStrings {
					cs.comboItems[index] = readGuestUTF16(lParam)
				}
				cs.comboItemData = append(cs.comboItemData, 0)
				copy(cs.comboItemData[index+1:], cs.comboItemData[index:])
				if !comboStoresStrings {
					cs.comboItemData[index] = lParam
				}
				return uint64(index), true
			case 0x014B: // CB_RESETCONTENT
				cs.comboItems = nil
				cs.comboItemData = nil
				cs.comboCurSel = -1
				cs.comboTopIndex = 0
				cs.text = ""
				return 0, true
			case 0x014C, 0x014D: // CB_FINDSTRING, CB_SELECTSTRING
				needle := strings.ToLower(readGuestUTF16(lParam))
				start := int(int32(wParam)) + 1
				if start < 0 || start >= len(cs.comboItems) {
					start = 0
				}
				for offset := 0; offset < len(cs.comboItems); offset++ {
					index := (start + offset) % len(cs.comboItems)
					if strings.HasPrefix(strings.ToLower(cs.comboItems[index]), needle) {
						if msg == 0x014D {
							cs.comboCurSel = index
							cs.text = cs.comboItems[index]
							hctx.QueuePaint(hwnd)
						}
						return uint64(index), true
					}
				}
				return cbErr, true
			case 0x014E: // CB_SETCURSEL
				index := int(int32(wParam))
				if index < 0 || index >= len(cs.comboItems) {
					cs.comboCurSel = -1
					cs.text = ""
					return cbErr, true
				}
				cs.comboCurSel = index
				cs.text = cs.comboItems[index]
				hctx.QueuePaint(hwnd)
				return uint64(index), true
			case 0x014F: // CB_SHOWDROPDOWN
				wasDropped := cs.comboDropped
				cs.comboDropped = wParam != 0 || comboType == cbsSimple
				if wasDropped != cs.comboDropped && cs.parentHWND != 0 {
					notify := uint64(8)
					if cs.comboDropped {
						notify = 7
					}
					hctx.enqueueMessage(nil, newQueuedMsg(hctx, cs.parentHWND, 0x0111, (notify<<16)|(cs.ctrlID&0xFFFF), hwnd))
				}
				if hctx.RequestWindowRepaint != nil {
					hctx.RequestWindowRepaint(hwnd)
				} else {
					hctx.QueuePaint(hwnd)
				}
				return 1, true
			case 0x0150: // CB_GETITEMDATA
				index := int(int32(wParam))
				if index < 0 || index >= len(cs.comboItemData) {
					return cbErr, true
				}
				return cs.comboItemData[index], true
			case 0x0151: // CB_SETITEMDATA
				index := int(int32(wParam))
				if index < 0 || index >= len(cs.comboItemData) {
					return cbErr, true
				}
				cs.comboItemData[index] = lParam
				return 0, true
			case 0x0157: // CB_GETDROPPEDSTATE
				if cs.comboDropped || comboType == cbsSimple {
					return 1, true
				}
				return 0, true
			}
		}

		// Edit-specific messages
		if cs.className == "listbox" {
			const lbsHasStrings = uint32(0x0040)
			const listErr = ^uint64(0)
			listStoresStrings := cs.style&0x0030 == 0 || cs.style&lbsHasStrings != 0
			switch msg {
			case 0x0180: // LB_ADDSTRING
				text := ""
				data := lParam
				if listStoresStrings {
					text = readGuestUTF16(lParam)
					data = 0
				}
				cs.listItems = append(cs.listItems, text)
				cs.listItemData = append(cs.listItemData, data)
				cs.listItemHeights = append(cs.listItemHeights, 0)
				index := len(cs.listItems) - 1
				if cs.style&0x0020 != 0 {
					measuredWidth, measuredHeight := measureOwnerListItem(cs, index, data)
					if measuredWidth > 0 && cs.listColumnWidth <= 0 {
						cs.listColumnWidth = measuredWidth
					}
					if measuredHeight > 0 {
						cs.listItemHeights[index] = measuredHeight
					}
				}
				return uint64(index), true
			case 0x0181: // LB_INSERTSTRING
				index := int(int32(wParam))
				if index < 0 || index > len(cs.listItems) {
					index = len(cs.listItems)
				}
				cs.listItems = append(cs.listItems, "")
				cs.listItemData = append(cs.listItemData, 0)
				cs.listItemHeights = append(cs.listItemHeights, 0)
				copy(cs.listItems[index+1:], cs.listItems[index:])
				copy(cs.listItemData[index+1:], cs.listItemData[index:])
				copy(cs.listItemHeights[index+1:], cs.listItemHeights[index:])
				cs.listItems[index] = ""
				cs.listItemData[index] = 0
				cs.listItemHeights[index] = 0
				if listStoresStrings {
					cs.listItems[index] = readGuestUTF16(lParam)
				} else {
					cs.listItemData[index] = lParam
				}
				if cs.listCurSel >= index {
					cs.listCurSel++
				}
				if cs.style&0x0020 != 0 {
					measuredWidth, measuredHeight := measureOwnerListItem(cs, index, cs.listItemData[index])
					if measuredWidth > 0 && cs.listColumnWidth <= 0 {
						cs.listColumnWidth = measuredWidth
					}
					if measuredHeight > 0 {
						cs.listItemHeights[index] = measuredHeight
					}
				}
				return uint64(index), true
			case 0x0182: // LB_DELETESTRING
				index := int(int32(wParam))
				if index < 0 || index >= len(cs.listItems) {
					return listErr, true
				}
				if cs.listCurSel == index {
					cs.listCurSel = -1
				} else if cs.listCurSel > index {
					cs.listCurSel--
				}
				cs.listItems = append(cs.listItems[:index], cs.listItems[index+1:]...)
				cs.listItemData = append(cs.listItemData[:index], cs.listItemData[index+1:]...)
				if index < len(cs.listItemHeights) {
					cs.listItemHeights = append(cs.listItemHeights[:index], cs.listItemHeights[index+1:]...)
				}
				return uint64(len(cs.listItems)), true
			case 0x0184: // LB_RESETCONTENT
				cs.listItems = nil
				cs.listItemData = nil
				cs.listItemHeights = nil
				cs.listCurSel = -1
				return 0, true
			case 0x0186: // LB_SETCURSEL
				index := int(int32(wParam))
				if index < 0 || index >= len(cs.listItems) {
					cs.listCurSel = -1
					return listErr, true
				}
				cs.listCurSel = index
				hctx.QueuePaint(hwnd)
				return uint64(index), true
			case 0x0188: // LB_GETCURSEL
				if cs.listCurSel < 0 {
					return listErr, true
				}
				return uint64(cs.listCurSel), true
			case 0x0189: // LB_GETTEXT
				index := int(int32(wParam))
				if index < 0 || index >= len(cs.listItems) || lParam == 0 {
					return listErr, true
				}
				text := utf16Encode(cs.listItems[index])
				for i, ch := range text {
					mem.Write16(lParam+uint64(i*2), ch)
				}
				mem.Write16(lParam+uint64(len(text)*2), 0)
				return uint64(len(text)), true
			case 0x018A: // LB_GETTEXTLEN
				index := int(int32(wParam))
				if index < 0 || index >= len(cs.listItems) {
					return listErr, true
				}
				return uint64(len(utf16Encode(cs.listItems[index]))), true
			case 0x018B: // LB_GETCOUNT
				return uint64(len(cs.listItems)), true
			case 0x0195: // LB_SETCOLUMNWIDTH
				cs.listColumnWidth = int32(wParam)
				ravelog.Logf("[listbox] LB_SETCOLUMNWIDTH hwnd=0x%x width=%d\n", hwnd, cs.listColumnWidth)
				return 0, true
			case 0x0198: // LB_GETITEMRECT
				index := int(int32(wParam))
				left, top, right, bottom, ok := listBoxItemRect(cs, index)
				if !ok || lParam == 0 {
					return listErr, true
				}
				mem.Write32(lParam, uint32(left))
				mem.Write32(lParam+4, uint32(top))
				mem.Write32(lParam+8, uint32(right))
				mem.Write32(lParam+12, uint32(bottom))
				return 0, true
			case 0x0199: // LB_GETITEMDATA
				index := int(int32(wParam))
				if index < 0 || index >= len(cs.listItemData) {
					return listErr, true
				}
				return cs.listItemData[index], true
			case 0x019A: // LB_SETITEMDATA
				index := int(int32(wParam))
				if index < 0 || index >= len(cs.listItemData) {
					return listErr, true
				}
				cs.listItemData[index] = lParam
				return 0, true
			case 0x01A0: // LB_SETITEMHEIGHT
				height := int32(lParam & 0xFFFF)
				index := int(int32(wParam))
				if cs.style&0x0020 != 0 && index >= 0 && index < len(cs.listItems) {
					if len(cs.listItemHeights) != len(cs.listItems) {
						cs.listItemHeights = make([]int32, len(cs.listItems))
					}
					cs.listItemHeights[index] = height
				} else {
					cs.listItemHeight = height
				}
				ravelog.Logf("[listbox] LB_SETITEMHEIGHT hwnd=0x%x index=%d height=%d\n", hwnd, index, height)
				return 0, true
			case 0x01A7: // LB_SETCOUNT
				count := int(int32(wParam))
				if count < 0 {
					return listErr, true
				}
				cs.listItems = make([]string, count)
				cs.listItemData = make([]uint64, count)
				cs.listItemHeights = make([]int32, count)
				cs.listCurSel = -1
				if cs.style&0x0020 != 0 {
					for index := range cs.listItems {
						measuredWidth, measuredHeight := measureOwnerListItem(cs, index, 0)
						if measuredWidth > 0 && cs.listColumnWidth <= 0 {
							cs.listColumnWidth = measuredWidth
						}
						if measuredHeight > 0 {
							cs.listItemHeights[index] = measuredHeight
						}
					}
				}
				ravelog.Logf("[listbox] LB_SETCOUNT hwnd=0x%x count=%d\n", hwnd, count)
				return 0, true
			case 0x01A9: // LB_ITEMFROMPOINT
				x := int32(int16(lParam & 0xFFFF))
				y := int32(int16((lParam >> 16) & 0xFFFF))
				index, outside := listBoxItemFromPoint(cs, x, y)
				if index < 0 {
					index = 0
					outside = true
				}
				result := uint64(uint16(index))
				if outside {
					result |= uint64(1) << 16
				}
				return result, true
			}
		}

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
				if hctx.RequestWindowRepaint != nil {
					hctx.RequestWindowRepaint(hwnd)
				} else {
					hctx.QueuePaint(hwnd)
				}
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
				maxChars := wParam
				buf := lParam
				if buf == 0 || maxChars == 0 {
					return 0, true
				}
				ws := utf16Encode(cs.text)
				limit := uint64(len(ws))
				if limit+1 > maxChars {
					limit = maxChars - 1
				}
				for i := uint64(0); i < limit; i++ {
					mem.Write16(buf+i*2, ws[i])
				}
				mem.Write16(buf+limit*2, 0)
				return limit, true
			case 0x000E: // WM_GETTEXTLENGTH
				return uint64(len(utf16Encode(cs.text))), true
			case 0x00B7: // EM_SETMODIFY
				cs.editModified = wParam != 0
				return 0, true
			case 0x00B8: // EM_GETMODIFY
				if cs.editModified {
					return 1, true
				}
				return 0, true
			case 0x00B1: // EM_SETSEL
				return 0, true
			case 0x00B0: // EM_GETSEL
				// wParam = *DWORD start, lParam = *DWORD end
				if wParam != 0 {
					mem.Write32(wParam, 0)
				}
				if lParam != 0 {
					mem.Write32(lParam, 0)
				}
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
				lines := strings.Count(cs.text, "\n") + 1
				if cs.text == "" {
					lines = 1
				}
				return uint64(lines), true
			case 0x00C1: // EM_GETLINE
				lineIdx := int(wParam)
				buf := lParam
				textLines := strings.Split(cs.text, "\n")
				if lineIdx < 0 || lineIdx >= len(textLines) || buf == 0 {
					return 0, true
				}
				line := textLines[lineIdx]
				ws := utf16Encode(line)
				// First word at buf is max chars (pre-filled by caller)
				maxChars, _ := mem.Read16(buf)
				if maxChars == 0 {
					maxChars = uint16(len(ws))
				}
				limit := len(ws)
				if limit > int(maxChars) {
					limit = int(maxChars)
				}
				for i := 0; i < limit; i++ {
					mem.Write16(buf+uint64(i)*2, ws[i])
				}
				return uint64(limit), true
			case 0x00B6: // EM_LINEFROMCHAR
				return 0, true
			case 0x00B9: // EM_LINEINDEX
				return 0, true
			case 0x00C4: // EM_LINELENGTH
				charIdx := int(wParam)
				textLines := strings.Split(cs.text, "\n")
				// Find which line charIdx belongs to
				pos := 0
				for _, line := range textLines {
					lineLen := len(utf16Encode(line))
					if charIdx < 0 || pos+lineLen >= charIdx {
						return uint64(lineLen), true
					}
					pos += lineLen + 1 // +1 for \n
				}
				// Default: last line length
				if len(textLines) > 0 {
					return uint64(len(utf16Encode(textLines[len(textLines)-1]))), true
				}
				return 0, true
			}
		}

		// StatusBar-specific messages (SB_xxx: WM_USER+x)
		if cs.className == "msctls_statusbar32" {
			const wmUser = 0x0400
			switch msg {
			case wmUser + 4: // SB_SETPARTS
				nParts := int(wParam)
				if nParts > 0 && nParts < 256 {
					cs.statusBar.parts = make([]int, nParts)
					if len(cs.statusBar.texts) < nParts {
						texts := make([]string, nParts)
						copy(texts, cs.statusBar.texts)
						cs.statusBar.texts = texts
					} else {
						cs.statusBar.texts = cs.statusBar.texts[:nParts]
					}
				}
				if nParts > 0 && nParts < 256 && lParam != 0 {
					for i := 0; i < nParts; i++ {
						v, _ := mem.Read32(lParam + uint64(i*4))
						cs.statusBar.parts[i] = int(v)
					}
				}
				syncStatusBarCompat(cs)
				hctx.QueuePaint(hwnd)
				return 1, true
			case wmUser + 11: // SB_SETTEXTW (unicode)
				part := int(wParam & 0xFF)
				// Auto-grow parts array if needed
				for len(cs.statusBar.texts) <= part {
					cs.statusBar.texts = append(cs.statusBar.texts, "")
				}
				for len(cs.statusBar.parts) <= part {
					cs.statusBar.parts = append(cs.statusBar.parts, -1)
				}
				if lParam != 0 {
					cs.statusBar.texts[part] = readGuestUTF16(lParam)
				}
				syncStatusBarCompat(cs)
				hctx.QueuePaint(hwnd)
				return 1, true
			case wmUser + 1: // SB_SETTEXTA
				part := int(wParam & 0xFF)
				for len(cs.statusBar.texts) <= part {
					cs.statusBar.texts = append(cs.statusBar.texts, "")
				}
				for len(cs.statusBar.parts) <= part {
					cs.statusBar.parts = append(cs.statusBar.parts, -1)
				}
				if lParam != 0 {
					// Read ASCII string
					var buf []byte
					for i := uint64(0); i < 256; i++ {
						b, err := mem.Read8(lParam + i)
						if err != nil || b == 0 {
							break
						}
						buf = append(buf, b)
					}
					cs.statusBar.texts[part] = string(buf)
				}
				syncStatusBarCompat(cs)
				hctx.QueuePaint(hwnd)
				return 1, true
			case wmUser + 5: // SB_GETPARTS
				if lParam != 0 {
					limit := len(cs.statusBar.parts)
					if int(wParam) < limit {
						limit = int(wParam)
					}
					for i := 0; i < limit; i++ {
						mem.Write32(lParam+uint64(i*4), uint32(cs.statusBar.parts[i]))
					}
				}
				return uint64(len(cs.statusBar.parts)), true
			case wmUser + 3: // SB_GETTEXTLENGTHW
				part := int(wParam)
				if part >= 0 && part < len(cs.statusBar.texts) {
					return uint64(len(utf16Encode(cs.statusBar.texts[part]))), true
				}
				return 0, true
			case wmUser + 13: // SB_GETTEXTW
				part := int(wParam & 0xFF)
				if part >= 0 && part < len(cs.statusBar.texts) && lParam != 0 {
					ws := utf16Encode(cs.statusBar.texts[part])
					for i, ch := range ws {
						mem.Write16(lParam+uint64(i*2), ch)
					}
					mem.Write16(lParam+uint64(len(ws))*2, 0)
					return uint64(len(ws)), true
				}
				return 0, true
			case wmUser + 8: // SB_SETMINHEIGHT
				cs.statusMinH = int32(wParam)
				if cs.statusMinH > 0 {
					cs.h = cs.statusMinH + 4
				}
				hctx.QueuePaint(hwnd)
				return 1, true
			case wmUser + 9: // SB_SIMPLE
				cs.statusSimple = wParam != 0
				hctx.QueuePaint(hwnd)
				return 1, true
			case wmUser + 14: // SB_ISSIMPLE
				if cs.statusSimple {
					return 1, true
				}
				return 0, true
			case wmUser + 6: // SB_GETBORDERS
				return 0, true
			}
		}

		if cs.className == "msctls_progress32" {
			const wmUser = 0x0400
			pb := cs.progress
			switch msg {
			case wmUser + 1: // PBM_SETRANGE
				old := (uint64(uint16(pb.min)) << 16) | uint64(uint16(pb.max))
				pb.min = int(int16(lParam & 0xFFFF))
				pb.max = int(int16((lParam >> 16) & 0xFFFF))
				if pb.max <= pb.min {
					pb.max = pb.min + 1
				}
				pb.pos = int(clampInt32(int32(pb.pos), int32(pb.min), int32(pb.max)))
				syncProgressBarCompat(cs)
				hctx.QueuePaint(hwnd)
				return old, true
			case wmUser + 2: // PBM_SETPOS
				old := pb.pos
				pb.pos = int(clampInt32(int32(wParam), int32(pb.min), int32(pb.max)))
				syncProgressBarCompat(cs)
				hctx.QueuePaint(hwnd)
				return uint64(old), true
			case wmUser + 3: // PBM_DELTAPOS
				old := pb.pos
				pb.pos = int(clampInt32(int32(pb.pos)+int32(wParam), int32(pb.min), int32(pb.max)))
				syncProgressBarCompat(cs)
				hctx.QueuePaint(hwnd)
				return uint64(old), true
			case wmUser + 4: // PBM_SETSTEP
				old := pb.step
				pb.step = int(int32(wParam))
				syncProgressBarCompat(cs)
				return uint64(old), true
			case wmUser + 5: // PBM_STEPIT
				pb.pos = int(clampInt32(int32(pb.pos)+int32(pb.step), int32(pb.min), int32(pb.max)))
				syncProgressBarCompat(cs)
				hctx.QueuePaint(hwnd)
				return uint64(pb.pos), true
			case wmUser + 6: // PBM_SETRANGE32
				pb.min = int(int32(wParam))
				pb.max = int(int32(lParam))
				if pb.max <= pb.min {
					pb.max = pb.min + 1
				}
				pb.pos = int(clampInt32(int32(pb.pos), int32(pb.min), int32(pb.max)))
				syncProgressBarCompat(cs)
				hctx.QueuePaint(hwnd)
				return 1, true
			case wmUser + 7: // PBM_GETRANGE
				if lParam != 0 {
					mem.Write32(lParam, uint32(int32(pb.min)))
					mem.Write32(lParam+4, uint32(int32(pb.max)))
				}
				if wParam != 0 {
					return uint64(pb.max), true
				}
				return uint64(pb.min), true
			case wmUser + 8: // PBM_GETPOS
				return uint64(pb.pos), true
			case wmUser + 9: // PBM_SETBARCOLOR
				old := pb.barColor
				pb.barColor = uint32(lParam)
				hctx.QueuePaint(hwnd)
				return uint64(old), true
			case wmUser + 10: // PBM_SETMARQUEE
				pb.marquee = wParam != 0
				cs.progressMq = pb.marquee
				syncProgressBarCompat(cs)
				hctx.QueuePaint(hwnd)
				return 1, true
			case wmUser + 13: // PBM_GETSTEP
				return uint64(pb.step), true
			case wmUser + 14: // PBM_GETBKCOLOR
				return uint64(pb.bkColor), true
			case wmUser + 15: // PBM_GETBARCOLOR
				return uint64(pb.barColor), true
			case wmUser + 16: // PBM_SETSTATE
				old := pb.state
				pb.state = int32(wParam)
				hctx.QueuePaint(hwnd)
				return uint64(old), true
			case wmUser + 17: // PBM_GETSTATE
				return uint64(pb.state), true
			case 0x2001: // PBM_SETBKCOLOR / CCM_SETBKCOLOR
				old := pb.bkColor
				pb.bkColor = uint32(lParam)
				hctx.QueuePaint(hwnd)
				return uint64(old), true
			}
		}

		// TreeView messages (TVM_xxx = TV_FIRST + x, TV_FIRST = 0x1100)
		if cs.className == "systreeview32" {
			tv := cs.treeView
			is32 := hctx.ProcState != nil && hctx.ProcState.Is32
			layout := treeViewItemOffsets(is32)
			switch msg {
			case 0x0201: // WM_LBUTTONDOWN
				y := int32(int16((lParam >> 16) & 0xFFFF))
				items := treeViewVisibleItems(tv)
				index := int((y - 2) / 18)
				if y < 2 || index < 0 || index >= len(items) {
					return 0, true
				}
				oldItem := tv.selected
				newItem := items[index]
				if oldItem == newItem {
					return 0, true
				}
				notifyLayout := treeViewNotifyOffsets(is32)
				writeNotify := func(code uint32) uint64 {
					notify := hctx.ScratchAlloc(notifyLayout.size)
					for offset := uint64(0); offset < notifyLayout.size; offset += 4 {
						mem.Write32(notify+offset, 0)
					}
					if is32 {
						mem.Write32(notify, uint32(hwnd))
						mem.Write32(notify+4, uint32(cs.ctrlID))
						mem.Write32(notify+8, code)
					} else {
						mem.Write64(notify, hwnd)
						mem.Write64(notify+8, cs.ctrlID)
						mem.Write32(notify+16, code)
					}
					mem.Write32(notify+notifyLayout.action, 1)
					writeItem := func(base uint64, item *tvItem) {
						if item == nil {
							return
						}
						mem.Write32(base, 0x001C)
						_ = writeGuestPointer(mem, base+layout.item, item.handle, is32)
						mem.Write32(base+layout.state, item.state)
						mem.Write32(base+layout.state+4, 0xFFFFFFFF)
						_ = writeGuestPointer(mem, base+layout.param, item.param, is32)
					}
					writeItem(notify+notifyLayout.itemOld, oldItem)
					writeItem(notify+notifyLayout.itemNew, newItem)
					mem.Write32(notify+notifyLayout.point, uint32(int32(int16(lParam&0xFFFF))))
					mem.Write32(notify+notifyLayout.point+4, uint32(y))
					return sendNotifySync(cs.parentHWND, 0x004E, cs.ctrlID, notify)
				}
				const (
					tvnSelChangingW = uint32(0xFFFFFE3E)
					tvnSelChangedW  = uint32(0xFFFFFE3D)
				)
				if writeNotify(tvnSelChangingW) != 0 {
					return 0, true
				}
				if oldItem != nil {
					oldItem.state &^= 0x0002
				}
				newItem.state |= 0x0002
				tv.selected = newItem
				syncTreeViewCompat(cs)
				hctx.QueuePaint(hwnd)
				writeNotify(tvnSelChangedW)
				return 0, true
			case tvmInsertItemA, tvmInsertItemW:
				if lParam == 0 {
					return 0, true
				}
				hParent, _ := readGuestPointer(mem, lParam, is32)
				itemBase := lParam + layout.insertItem
				mask, _ := mem.Read32(itemBase)
				state, _ := mem.Read32(itemBase + layout.state)
				stateMask, _ := mem.Read32(itemBase + layout.state + 4)
				pszText, _ := readGuestPointer(mem, itemBase+layout.text, is32)
				itemLParam, _ := readGuestPointer(mem, itemBase+layout.param, is32)
				text := ""
				const tvifText = 0x0001
				const tvifState = 0x0008
				if mask&tvifText != 0 && pszText != 0 && !isTextCallbackPointer(pszText, is32) {
					if msg == tvmInsertItemW {
						text = readGuestUTF16(pszText)
					} else {
						text = readGuestString(pszText)
					}
				}
				newItem := &tvItem{
					handle:   tv.nextH,
					text:     text,
					param:    itemLParam,
					expanded: true,
				}
				if mask&tvifState != 0 {
					newItem.state = state & stateMask
				}
				tv.nextH++
				parent := tv.root
				const tviRoot uint64 = 0xFFFFFFFFFFFF0000
				if hParent != 0 && hParent != tviRoot && hParent != 0xFFFF0000 {
					if existing, ok := cs.treeViewIndex[hParent]; ok && existing != nil {
						parent = existing
					}
				}
				newItem.parent = parent
				parent.children = append(parent.children, newItem)
				cs.treeViewIndex[newItem.handle] = newItem
				syncTreeViewCompat(cs)
				hctx.QueuePaint(hwnd)
				return newItem.handle, true
			case tvmDeleteItem:
				const tviRoot uint64 = 0xFFFFFFFFFFFF0000
				if lParam == 0 || lParam == tviRoot || lParam == 0xFFFF0000 {
					tv.root.children = nil
					tv.selected = nil
					cs.treeViewIndex = map[uint64]*tvItem{}
					syncTreeViewCompat(cs)
					hctx.QueuePaint(hwnd)
					return 1, true
				}
				if item, ok := cs.treeViewIndex[lParam]; ok {
					treeViewRemoveItem(cs, item)
					syncTreeViewCompat(cs)
					hctx.QueuePaint(hwnd)
					return 1, true
				}
				return 1, true
			case tvmExpand:
				if item, ok := cs.treeViewIndex[lParam]; ok && item != nil {
					const (
						tveCollapse      = 0x0001
						tveExpand        = 0x0002
						tveToggle        = 0x0003
						tveCollapseReset = 0x8000
					)
					action := uint32(wParam)
					switch action &^ tveCollapseReset {
					case tveCollapse:
						item.expanded = false
					case tveExpand:
						item.expanded = true
					case tveToggle:
						item.expanded = !item.expanded
					}
					syncTreeViewCompat(cs)
					hctx.QueuePaint(hwnd)
				}
				return 1, true
			case tvmSetImageList:
				return 0, true
			case tvmGetImageList:
				return 0, true
			case tvmSelectItem:
				const tvgnCaret = 0x0009
				if uint32(wParam) != tvgnCaret {
					return 0, true
				}
				if item, ok := cs.treeViewIndex[lParam]; ok {
					if tv.selected != nil {
						tv.selected.state &^= 0x0002
					}
					tv.selected = item
					item.state |= 0x0002
					syncTreeViewCompat(cs)
					hctx.QueuePaint(hwnd)
					return 1, true
				}
				if lParam == 0 {
					if tv.selected != nil {
						tv.selected.state &^= 0x0002
					}
					tv.selected = nil
					syncTreeViewCompat(cs)
					hctx.QueuePaint(hwnd)
					return 1, true
				}
				return 1, true
			case tvmGetItemA, tvmGetItemW:
				if lParam != 0 {
					mask, _ := mem.Read32(lParam)
					hItem, _ := readGuestPointer(mem, lParam+layout.item, is32)
					if ti, ok := cs.treeViewIndex[hItem]; ok {
						const tvifText = 0x0001
						const tvifParam = 0x0004
						const tvifState = 0x0008
						if mask&tvifText != 0 {
							pszText, _ := readGuestPointer(mem, lParam+layout.text, is32)
							cchMax, _ := mem.Read32(lParam + layout.textMax)
							if pszText != 0 && cchMax > 0 {
								if msg == tvmGetItemW {
									writeUTF16(mem, pszText, ti.text, int(cchMax))
								} else {
									writeCString(mem, pszText, ti.text, int(cchMax))
								}
							}
						}
						if mask&tvifParam != 0 {
							_ = writeGuestPointer(mem, lParam+layout.param, ti.param, is32)
						}
						if mask&tvifState != 0 {
							stateMask, _ := mem.Read32(lParam + layout.state + 4)
							mem.Write32(lParam+layout.state, ti.state&stateMask)
						}
						return 1, true
					}
				}
				return 0, true
			case tvmSetItemA, tvmSetItemW:
				if lParam != 0 {
					mask, _ := mem.Read32(lParam)
					hItem, _ := readGuestPointer(mem, lParam+layout.item, is32)
					if ti, ok := cs.treeViewIndex[hItem]; ok {
						const tvifText = 0x0001
						const tvifParam = 0x0004
						const tvifState = 0x0008
						if mask&tvifText != 0 {
							pszText, _ := readGuestPointer(mem, lParam+layout.text, is32)
							if pszText != 0 {
								if msg == tvmSetItemW {
									ti.text = readGuestUTF16(pszText)
								} else {
									ti.text = readGuestString(pszText)
								}
							}
						}
						if mask&tvifParam != 0 {
							ti.param, _ = readGuestPointer(mem, lParam+layout.param, is32)
						}
						if mask&tvifState != 0 {
							state, _ := mem.Read32(lParam + layout.state)
							stateMask, _ := mem.Read32(lParam + layout.state + 4)
							ti.state = (ti.state &^ stateMask) | (state & stateMask)
						}
						syncTreeViewCompat(cs)
						hctx.QueuePaint(hwnd)
						return 1, true
					}
				}
				return 1, true
			case tvmEditLabelA, tvmEditLabelW:
				return 0, true
			case tvmGetCount:
				return uint64(len(cs.treeViewIndex)), true
			case tvmGetNextItem:
				switch uint32(wParam) {
				case 0x0001: // TVGN_ROOT
					if len(tv.root.children) > 0 {
						return tv.root.children[0].handle, true
					}
				case 0x0002: // TVGN_NEXT
					if item, ok := cs.treeViewIndex[lParam]; ok {
						if next := treeViewNextSibling(item); next != nil {
							return next.handle, true
						}
					}
				case 0x0003: // TVGN_PREVIOUS
					if item, ok := cs.treeViewIndex[lParam]; ok && item.parent != nil {
						siblings := item.parent.children
						for i, sibling := range siblings {
							if sibling == item && i > 0 {
								return siblings[i-1].handle, true
							}
						}
					}
				case 0x0004: // TVGN_PARENT
					if item, ok := cs.treeViewIndex[lParam]; ok && item.parent != nil && item.parent != tv.root {
						return item.parent.handle, true
					}
				case 0x0005: // TVGN_CHILD
					if item, ok := cs.treeViewIndex[lParam]; ok && len(item.children) > 0 {
						return item.children[0].handle, true
					}
				case 0x0009: // TVGN_CARET
					if tv.selected != nil {
						return tv.selected.handle, true
					}
				}
				return 0, true
			case tvmGetItemRect:
				if lParam != 0 {
					hItem, _ := readGuestPointer(mem, lParam, is32)
					if _, ok := cs.treeViewIndex[hItem]; ok {
						items := treeViewVisibleItems(tv)
						for idx, item := range items {
							if item.handle == hItem {
								top := int32(idx)*18 + 2
								mem.Write32(lParam, 2)
								mem.Write32(lParam+4, uint32(top))
								mem.Write32(lParam+8, uint32(cs.w-2))
								mem.Write32(lParam+12, uint32(top+18))
								return 1, true
							}
						}
					}
				}
				return 0, true
			case tvmSortChildren:
				parent := tv.root
				if lParam != 0 {
					var ok bool
					parent, ok = cs.treeViewIndex[lParam]
					if !ok {
						return 0, true
					}
				}
				if parent != nil {
					sort.SliceStable(parent.children, func(i, j int) bool {
						return strings.ToLower(parent.children[i].text) < strings.ToLower(parent.children[j].text)
					})
					syncTreeViewCompat(cs)
					hctx.QueuePaint(hwnd)
				}
				return 1, true
			default:
				if msg >= tvmInsertItemA && msg < tvmInsertItemA+100 {
					return 0, true
				}
			}
		}

		// ListView messages (LVM_xxx = LV_FIRST + x, LV_FIRST = 0x1000)
		if cs.className == "syslistview32" {
			const lvFirst = 0x1000
			lv := cs.listView
			is32 := hctx.ProcState != nil && hctx.ProcState.Is32
			layout := listViewItemOffsets(is32)
			switch msg {
			case lvFirst + 0: // LVM_GETBKCOLOR
				return 0xFFFFFF, true
			case lvFirst + 1: // LVM_SETBKCOLOR
				return 1, true
			case lvFirst + 2: // LVM_GETIMAGELIST
				return 0, true
			case lvFirst + 3: // LVM_SETIMAGELIST
				return 0, true
			case lvFirst + 4: // LVM_GETITEMCOUNT
				return uint64(listViewGetItemCount(lv)), true
			case lvFirst + 7, lvFirst + 77: // LVM_INSERTITEMA/W
				if lv.style&0x1000 != 0 {
					return uint64(^uint32(0)), true
				}
				if lParam == 0 {
					return uint64(^uint32(0)), true
				}
				mask, _ := mem.Read32(lParam)
				iItemV, _ := mem.Read32(lParam + 4)
				iSubItemV, _ := mem.Read32(lParam + 8)
				state, _ := mem.Read32(lParam + 12)
				stateMask, _ := mem.Read32(lParam + 16)
				pszText, _ := readGuestPointer(mem, lParam+layout.text, is32)
				iImageV, _ := mem.Read32(lParam + layout.image)
				param, _ := readGuestPointer(mem, lParam+layout.param, is32)
				item := lvItem{image: int(int32(iImageV)), param: param}
				if mask&0x0008 != 0 {
					item.state = state & stateMask
				}
				if mask&0x0001 != 0 && pszText != 0 && !isTextCallbackPointer(pszText, is32) {
					if msg == lvFirst+77 {
						item.text = readGuestUTF16(pszText)
					} else {
						item.text = readGuestString(pszText)
					}
				}
				idx := int(int32(iItemV))
				if idx < 0 || idx > len(lv.items) {
					idx = len(lv.items)
				}
				if int32(iSubItemV) > 0 {
					if idx < len(lv.items) {
						subIdx := int(int32(iSubItemV) - 1)
						for len(lv.items[idx].subItems) <= subIdx {
							lv.items[idx].subItems = append(lv.items[idx].subItems, "")
						}
						lv.items[idx].subItems[subIdx] = item.text
						if item.param != 0 {
							lv.items[idx].param = item.param
						}
						if item.image != 0 {
							lv.items[idx].image = item.image
						}
						if mask&0x0008 != 0 {
							lv.items[idx].state = (lv.items[idx].state &^ stateMask) | (state & stateMask)
							if stateMask&0x0002 != 0 {
								if state&0x0002 != 0 {
									lv.selectedIdx = idx
								} else if lv.selectedIdx == idx {
									lv.selectedIdx = -1
								}
							}
						}
						hctx.QueuePaint(hwnd)
						return uint64(idx), true
					}
					return uint64(^uint32(0)), true
				}
				lv.items = append(lv.items, lvItem{})
				copy(lv.items[idx+1:], lv.items[idx:])
				lv.items[idx] = item
				if item.state&0x0002 != 0 || lv.selectedIdx < 0 {
					lv.selectedIdx = idx
				}
				hctx.QueuePaint(hwnd)
				return uint64(idx), true
			case lvFirst + 8: // LVM_DELETEITEM
				if lv.style&0x1000 != 0 {
					if lv.virtualCount > 0 {
						lv.virtualCount--
					}
					hctx.QueuePaint(hwnd)
					return 1, true
				}
				idx := int(int32(wParam))
				if idx >= 0 && idx < len(lv.items) {
					lv.items = append(lv.items[:idx], lv.items[idx+1:]...)
					if lv.selectedIdx == idx {
						lv.selectedIdx = -1
					} else if lv.selectedIdx > idx {
						lv.selectedIdx--
					}
					hctx.QueuePaint(hwnd)
					return 1, true
				}
				return 1, true
			case lvFirst + 9: // LVM_DELETEALLITEMS
				if lv.style&0x1000 != 0 {
					lv.virtualCount = 0
				}
				lv.items = nil
				lv.selectedIdx = -1
				hctx.QueuePaint(hwnd)
				return 1, true
			case lvFirst + 47: // LVM_SETITEMCOUNT
				if lv.style&0x1000 != 0 {
					lv.virtualCount = int(int32(wParam))
					if lv.virtualCount < 0 {
						lv.virtualCount = 0
					}
					hctx.QueuePaint(hwnd)
					return 1, true
				}
				return 0, true
			case lvFirst + 27: // LVM_INSERTCOLUMNA
				if lParam != 0 {
					mask, _ := mem.Read32(lParam)
					fmtV, _ := mem.Read32(lParam + 4)
					cx, _ := mem.Read32(lParam + 8)
					pszText, _ := readGuestPointer(mem, lParam+listViewColumnTextOffset(is32), is32)
					text := ""
					if mask&0x0004 != 0 && pszText != 0 { // LVCF_TEXT
						text = readGuestString(pszText)
					}
					width := int32(cx)
					if width == 0 {
						width = 100
					}
					col := lvColumn{text: text, width: int(width), fmt: int(int32(fmtV))}
					idx := int(int32(wParam))
					if idx < 0 || idx > len(lv.columns) {
						idx = len(lv.columns)
					}
					lv.columns = append(lv.columns, lvColumn{})
					copy(lv.columns[idx+1:], lv.columns[idx:])
					lv.columns[idx] = col
					syncListViewCompat(cs)
					hctx.QueuePaint(hwnd)
					return uint64(idx), true
				}
				return uint64(len(lv.columns)), true
			case lvFirst + 97: // LVM_INSERTCOLUMNW
				if lParam != 0 {
					mask, _ := mem.Read32(lParam)
					fmtV, _ := mem.Read32(lParam + 4)
					cx, _ := mem.Read32(lParam + 8)
					pszText, _ := readGuestPointer(mem, lParam+listViewColumnTextOffset(is32), is32)
					text := ""
					if mask&0x0004 != 0 && pszText != 0 { // LVCF_TEXT
						text = readGuestUTF16(pszText)
					}
					width := int32(cx)
					if width == 0 {
						width = 100
					}
					col := lvColumn{text: text, width: int(width), fmt: int(int32(fmtV))}
					idx := int(int32(wParam))
					if idx < 0 || idx > len(lv.columns) {
						idx = len(lv.columns)
					}
					lv.columns = append(lv.columns, lvColumn{})
					copy(lv.columns[idx+1:], lv.columns[idx:])
					lv.columns[idx] = col
					syncListViewCompat(cs)
					hctx.QueuePaint(hwnd)
					return uint64(idx), true
				}
				return uint64(len(lv.columns)), true
			case lvFirst + 96: // LVM_SETCOLUMNW
				idx := int(int32(wParam))
				if idx >= 0 && idx < len(lv.columns) && lParam != 0 {
					mask, _ := mem.Read32(lParam)
					if mask&0x0001 != 0 {
						fmtV, _ := mem.Read32(lParam + 4)
						lv.columns[idx].fmt = int(int32(fmtV))
					}
					if mask&0x0002 != 0 {
						cx, _ := mem.Read32(lParam + 8)
						lv.columns[idx].width = int(int32(cx))
					}
					if mask&0x0004 != 0 {
						pszText, _ := readGuestPointer(mem, lParam+listViewColumnTextOffset(is32), is32)
						if pszText != 0 {
							lv.columns[idx].text = readGuestUTF16(pszText)
						}
					}
					syncListViewCompat(cs)
					hctx.QueuePaint(hwnd)
				}
				return 1, true
			case lvFirst + 28: // LVM_DELETECOLUMN
				idx := int(int32(wParam))
				if idx >= 0 && idx < len(lv.columns) {
					lv.columns = append(lv.columns[:idx], lv.columns[idx+1:]...)
					syncListViewCompat(cs)
					hctx.QueuePaint(hwnd)
					return 1, true
				}
				return 0, true
			case lvFirst + 30: // LVM_SETCOLUMNWIDTH
				idx := int(int32(wParam))
				if idx >= 0 && idx < len(lv.columns) {
					lv.columns[idx].width = int(int32(lParam))
					syncListViewCompat(cs)
					hctx.QueuePaint(hwnd)
					return 1, true
				}
				return 1, true
			case lvFirst + 29: // LVM_GETCOLUMNWIDTH
				idx := int(int32(wParam))
				if idx >= 0 && idx < len(lv.columns) {
					return uint64(lv.columns[idx].width), true
				}
				return 0, true
			case lvFirst + 31: // LVM_GETHEADER
				return 0, true
			case lvFirst + 33: // LVM_CREATEDRAGIMAGE
				return 0, true
			case lvFirst + 54: // LVM_SETEXTENDEDLISTVIEWSTYLE
				return uint64(setListViewExtendedStyle(lv, uint32(wParam), uint32(lParam))), true
			case lvFirst + 55: // LVM_GETEXTENDEDLISTVIEWSTYLE
				return uint64(lv.extStyle), true
			case lvFirst + 75: // LVM_GETITEMW
				if lParam == 0 {
					return 0, true
				}
				iItemV, _ := mem.Read32(lParam + 4)
				iSubItemV, _ := mem.Read32(lParam + 8)
				idx := int(int32(iItemV))
				subIdx := int(int32(iSubItemV))
				if idx < 0 || idx >= listViewGetItemCount(lv) {
					return 0, true
				}
				item := lvItem{}
				if lv.style&0x1000 != 0 {
					item = listViewFetchVirtualItem(hwnd, cs, idx, subIdx, true)
				} else {
					item = lv.items[idx]
				}
				mask, _ := mem.Read32(lParam)
				if mask&0x0001 != 0 {
					pszText, _ := readGuestPointer(mem, lParam+layout.text, is32)
					cchTextMax, _ := mem.Read32(lParam + layout.textMax)
					text := item.text
					if lv.style&0x1000 == 0 && subIdx > 0 && subIdx-1 < len(item.subItems) {
						text = item.subItems[subIdx-1]
					}
					if pszText != 0 && cchTextMax > 0 {
						writeGuestUTF16Limited(pszText, text, int(cchTextMax))
					}
				}
				if mask&0x0002 != 0 {
					mem.Write32(lParam+layout.image, uint32(item.image))
				}
				if mask&0x0004 != 0 {
					_ = writeGuestPointer(mem, lParam+layout.param, item.param, is32)
				}
				if mask&0x0008 != 0 {
					stateMask, _ := mem.Read32(lParam + 16)
					mem.Write32(lParam+12, item.state&stateMask)
				}
				return 1, true
			case lvFirst + 76: // LVM_SETITEMW
				if lv.style&0x1000 != 0 {
					return 0, true
				}
				if lParam == 0 {
					return 0, true
				}
				iItemV, _ := mem.Read32(lParam + 4)
				iSubItemV, _ := mem.Read32(lParam + 8)
				idx := int(int32(iItemV))
				subIdx := int(int32(iSubItemV))
				if idx < 0 || idx >= len(lv.items) {
					return 0, true
				}
				mask, _ := mem.Read32(lParam)
				item := &lv.items[idx]
				if mask&0x0001 != 0 {
					pszText, _ := readGuestPointer(mem, lParam+layout.text, is32)
					if pszText != 0 && !isTextCallbackPointer(pszText, is32) {
						text := readGuestUTF16(pszText)
						if subIdx > 0 {
							for len(item.subItems) < subIdx {
								item.subItems = append(item.subItems, "")
							}
							item.subItems[subIdx-1] = text
						} else {
							item.text = text
						}
					}
				}
				if mask&0x0002 != 0 {
					iImageV, _ := mem.Read32(lParam + layout.image)
					item.image = int(int32(iImageV))
				}
				if mask&0x0004 != 0 {
					item.param, _ = readGuestPointer(mem, lParam+layout.param, is32)
				}
				if mask&0x0008 != 0 {
					state, _ := mem.Read32(lParam + 12)
					stateMask, _ := mem.Read32(lParam + 16)
					item.state = (item.state &^ stateMask) | (state & stateMask)
					if stateMask&0x0002 != 0 {
						if state&0x0002 != 0 {
							lv.selectedIdx = idx
						} else if lv.selectedIdx == idx {
							lv.selectedIdx = -1
						}
					}
				}
				hctx.QueuePaint(hwnd)
				return 1, true
			case lvFirst + 50: // LVM_GETSELECTEDCOUNT
				if lv.style&0x1000 != 0 {
					if lv.selectedIdx >= 0 && lv.selectedIdx < lv.virtualCount {
						return 1, true
					}
					return 0, true
				}
				count := 0
				for _, item := range lv.items {
					if item.state&0x0002 != 0 {
						count++
					}
				}
				return uint64(count), true
			case lvFirst + 12: // LVM_GETNEXTITEM
				start := int(int32(wParam))
				flags := uint32(lParam)
				if start < -1 {
					start = -1
				}
				limit := listViewGetItemCount(lv)
				for i := start + 1; i < limit; i++ {
					if lv.style&0x1000 != 0 {
						if flags == 0 || (flags&0x0002 != 0 && lv.selectedIdx == i) {
							return uint64(i), true
						}
						continue
					}
					if flags == 0 || (flags&0x0002 != 0 && lv.items[i].state&0x0002 != 0) {
						return uint64(i), true
					}
				}
				return uint64(^uint32(0)), true
			case lvFirst + 48: // LVM_SORTITEMS
				sort.SliceStable(lv.items, func(i, j int) bool {
					return strings.ToLower(lv.items[i].text) < strings.ToLower(lv.items[j].text)
				})
				hctx.QueuePaint(hwnd)
				return 1, true
			case lvFirst + 19: // LVM_ENSUREVISIBLE
				return 1, true
			case lvFirst + 43: // LVM_SETITEMSTATE
				idx := int(int32(wParam))
				if lv.style&0x1000 != 0 {
					if idx >= 0 && idx < lv.virtualCount && lParam != 0 {
						state, _ := mem.Read32(lParam + 12)
						stateMask, _ := mem.Read32(lParam + 16)
						if stateMask&0x0002 != 0 {
							if state&0x0002 != 0 {
								lv.selectedIdx = idx
							} else if lv.selectedIdx == idx {
								lv.selectedIdx = -1
							}
						}
						hctx.QueuePaint(hwnd)
					}
					return 1, true
				}
				if idx >= 0 && idx < len(lv.items) && lParam != 0 {
					state, _ := mem.Read32(lParam + 12)
					stateMask, _ := mem.Read32(lParam + 16)
					lv.items[idx].state = (lv.items[idx].state &^ stateMask) | (state & stateMask)
					if lv.items[idx].state&0x0002 != 0 {
						lv.selectedIdx = idx
					} else if lv.selectedIdx == idx {
						lv.selectedIdx = -1
					}
					hctx.QueuePaint(hwnd)
				}
				return 1, true
			case lvFirst + 44: // LVM_GETITEMSTATE
				idx := int(int32(wParam))
				if lv.style&0x1000 != 0 {
					if idx >= 0 && idx < lv.virtualCount && lv.selectedIdx == idx {
						return uint64(0x0002 & uint32(lParam)), true
					}
					return 0, true
				}
				if idx >= 0 && idx < len(lv.items) {
					return uint64(lv.items[idx].state & uint32(lParam)), true
				}
				return 0, true
			default:
				if msg >= lvFirst && msg < lvFirst+200 {
					return 0, true
				}
			}
		}

		if cs.className == "sysheader32" {
			const hdmFirst = 0x1200
			hd := cs.header
			switch msg {
			case hdmFirst + 0: // HDM_GETITEMCOUNT
				return uint64(len(hd.items)), true
			case hdmFirst + 1, hdmFirst + 10: // HDM_INSERTITEMA/W
				idx := int(int32(wParam))
				if idx < 0 || idx > len(hd.items) {
					idx = len(hd.items)
				}
				item := readHeaderItem(lParam, msg == hdmFirst+10)
				if item.width <= 0 {
					item.width = 80
				}
				if item.order < 0 {
					item.order = int32(idx)
				}
				hd.items = append(hd.items, headerItem{})
				copy(hd.items[idx+1:], hd.items[idx:])
				hd.items[idx] = item
				hctx.QueuePaint(hwnd)
				return uint64(idx), true
			case hdmFirst + 2: // HDM_DELETEITEM
				idx := int(int32(wParam))
				if idx >= 0 && idx < len(hd.items) {
					hd.items = append(hd.items[:idx], hd.items[idx+1:]...)
					if hd.focusedIdx >= int32(len(hd.items)) {
						hd.focusedIdx = int32(len(hd.items)) - 1
					}
					hctx.QueuePaint(hwnd)
					return 1, true
				}
				return 0, true
			case hdmFirst + 3, hdmFirst + 11: // HDM_GETITEMA/W
				idx := int(int32(wParam))
				if idx >= 0 && idx < len(hd.items) && lParam != 0 {
					writeHeaderItem(lParam, hd.items[idx], msg == hdmFirst+11)
					return 1, true
				}
				return 0, true
			case hdmFirst + 4, hdmFirst + 12: // HDM_SETITEMA/W
				idx := int(int32(wParam))
				if idx >= 0 && idx < len(hd.items) && lParam != 0 {
					mask, _ := mem.Read32(lParam)
					item := hd.items[idx]
					patch := readHeaderItem(lParam, msg == hdmFirst+12)
					if mask&0x0001 != 0 {
						item.width = patch.width
					}
					if mask&0x0002 != 0 {
						item.text = patch.text
					}
					if mask&0x0004 != 0 {
						item.bitmap = patch.bitmap
					}
					if mask&0x0008 != 0 {
						item.fmt = patch.fmt
					}
					if mask&0x0010 != 0 {
						item.param = patch.param
					}
					if mask&0x0020 != 0 {
						item.image = patch.image
					}
					if mask&0x0080 != 0 {
						item.order = patch.order
					}
					if mask&0x0200 != 0 {
						item.state = patch.state
					}
					hd.items[idx] = item
					hctx.QueuePaint(hwnd)
					return 1, true
				}
				return 0, true
			case hdmFirst + 5: // HDM_LAYOUT
				if lParam != 0 {
					prc, _ := mem.Read64(lParam)
					pwpos, _ := mem.Read64(lParam + 8)
					if pwpos != 0 {
						mem.Write64(pwpos+0, hwnd)
						mem.Write32(pwpos+8, uint32(cs.x))
						mem.Write32(pwpos+12, uint32(cs.y))
						mem.Write32(pwpos+16, uint32(cs.w))
						mem.Write32(pwpos+20, uint32(cs.h))
						mem.Write32(pwpos+24, 0x0040) // SWP_NOZORDER
					}
					if prc != 0 {
						left, _ := mem.Read32(prc)
						top, _ := mem.Read32(prc + 4)
						right, _ := mem.Read32(prc + 8)
						mem.Write32(prc, left)
						mem.Write32(prc+4, top+uint32(cs.h))
						mem.Write32(prc+8, right)
					}
				}
				return 1, true
			case hdmFirst + 6: // HDM_HITTEST
				if lParam == 0 {
					return ^uint64(0), true
				}
				xp, _ := mem.Read32(lParam)
				x := int32(xp)
				cur := int32(0)
				for i, item := range hd.items {
					w := item.width
					if w <= 0 {
						w = 80
					}
					if x >= cur && x < cur+w {
						mem.Write32(lParam+8, uint32(i))
						return uint64(i), true
					}
					cur += w
				}
				mem.Write32(lParam+8, 0xFFFFFFFF)
				return ^uint64(0), true
			case hdmFirst + 7: // HDM_GETITEMRECT
				idx := int(int32(wParam))
				if idx >= 0 && idx < len(hd.items) && lParam != 0 {
					left := int32(0)
					for i := 0; i < idx; i++ {
						w := hd.items[i].width
						if w <= 0 {
							w = 80
						}
						left += w
					}
					width := hd.items[idx].width
					if width <= 0 {
						width = 80
					}
					mem.Write32(lParam, uint32(left))
					mem.Write32(lParam+4, 0)
					mem.Write32(lParam+8, uint32(left+width))
					mem.Write32(lParam+12, uint32(cs.h))
					return 1, true
				}
				return 0, true
			case hdmFirst + 8: // HDM_SETIMAGELIST
				old := hd.imageList
				hd.imageList = lParam
				return old, true
			case hdmFirst + 9: // HDM_GETIMAGELIST
				return hd.imageList, true
			case hdmFirst + 16: // HDM_GETORDERARRAY
				count := int(int32(wParam))
				if lParam == 0 {
					return 0, true
				}
				if count > len(hd.items) {
					count = len(hd.items)
				}
				for i := 0; i < count; i++ {
					order := hd.items[i].order
					if order < 0 {
						order = int32(i)
					}
					mem.Write32(lParam+uint64(i*4), uint32(order))
				}
				return 1, true
			case hdmFirst + 17: // HDM_SETORDERARRAY
				count := int(int32(wParam))
				if lParam != 0 && count > 0 {
					if count > len(hd.items) {
						count = len(hd.items)
					}
					for i := 0; i < count; i++ {
						order, _ := mem.Read32(lParam + uint64(i*4))
						hd.items[i].order = int32(order)
					}
					hctx.QueuePaint(hwnd)
				}
				return 1, true
			case hdmFirst + 18: // HDM_GETITEMDROPDOWNRECT
				idx := int(int32(wParam))
				if idx >= 0 && idx < len(hd.items) && lParam != 0 {
					left := int32(0)
					for i := 0; i < idx; i++ {
						w := hd.items[i].width
						if w <= 0 {
							w = 80
						}
						left += w
					}
					width := hd.items[idx].width
					if width <= 0 {
						width = 80
					}
					mem.Write32(lParam, uint32(left+width-16))
					mem.Write32(lParam+4, 0)
					mem.Write32(lParam+8, uint32(left+width))
					mem.Write32(lParam+12, uint32(cs.h))
					return 1, true
				}
				return 0, true
			case hdmFirst + 19: // HDM_GETFOCUSEDITEM
				return uint64(hd.focusedIdx), true
			case hdmFirst + 20: // HDM_SETFOCUSEDITEM
				hd.focusedIdx = int32(wParam)
				hctx.QueuePaint(hwnd)
				return 1, true
			}
		}

		return 0, false
	}

	// hctx.RebarBandCounts tracks how many bands have been inserted into each ReBar
	hctx.RebarBandCounts = make(map[uint64]int)

	// Pre-declare scratchAlloc so the builtinWndProc closure below can reference it.
	// The actual allocator is initialised later (after scratchPage is mapped).

	// Wrap builtinWndProc to add ReBar/Toolbar/SysTab handling
	innerBuiltin := hctx.BuiltinWndProc
	hctx.BuiltinWndProc = func(hwnd uint64, msg uint32, wParam, lParam uint64) (uint64, bool) {
		cs, ok := hctx.HwndChildren[hwnd]
		if !ok {
			return innerBuiltin(hwnd, msg, wParam, lParam)
		}
		initBuiltinControlState(cs)
		validatePaint := func() {
			hctx.WinInvalid[hwnd] = false
			delete(hctx.WinErasePending, hwnd)
			win32.Global.Validate(hwnd)
		}
		switch cs.className {
		case "msctls_trackbar32":
			const tbmFirst = 0x0400
			switch msg {
			case tbmFirst: // TBM_GETPOS
				return uint64(uint32(cs.trackPos)), true
			case tbmFirst + 1: // TBM_GETRANGEMIN
				return uint64(uint32(cs.trackMin)), true
			case tbmFirst + 2: // TBM_GETRANGEMAX
				return uint64(uint32(cs.trackMax)), true
			case tbmFirst + 5: // TBM_SETPOS
				cs.trackPos = int32(lParam)
				return 0, true
			case tbmFirst + 6: // TBM_SETRANGE
				cs.trackMin = int32(int16(lParam & 0xFFFF))
				cs.trackMax = int32(int16((lParam >> 16) & 0xFFFF))
				return 0, true
			case tbmFirst + 7: // TBM_SETRANGEMIN
				cs.trackMin = int32(lParam)
				return 0, true
			case tbmFirst + 8: // TBM_SETRANGEMAX
				cs.trackMax = int32(lParam)
				return 0, true
			}
		case "rebarwindow32":
			const rbFirst = 0x0400
			switch msg {
			case 0x000F: // WM_PAINT
				validatePaint()
				// Rebar is a container for toolbars - do NOT fill background here.
				// Child toolbars draw inside the same rect and we must not overwrite them.
				// Only draw the 3D-edge lines.
				if wlWindow != nil {
					wlWindow.DrawRectAbs(cs.x, cs.y, cs.x+cs.w, cs.y+1, sysColors[20])           // top highlight
					wlWindow.DrawRectAbs(cs.x, cs.y+cs.h-1, cs.x+cs.w, cs.y+cs.h, sysColors[16]) // bottom shadow
				}
				return 0, true
			case 0x0005: // WM_SIZE
				cs.w = int32(lParam & 0xFFFF)
				cs.h = int32(lParam >> 16)
				return 0, true
			case rbFirst + 1: // RB_INSERTBANDA
				hctx.RebarBandCounts[hwnd]++
				// Update rebar height: each band is 26px
				cs.h = int32(hctx.RebarBandCounts[hwnd]) * 26
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
						if cyMinChild <= 0 {
							cyMinChild = 26
						}
						if csc, ok2 := hctx.HwndChildren[childHWND]; ok2 {
							csc.w = cs.w
							if csc.w <= 0 && wlWindow != nil {
								csc.w = wlWindow.Width
							}
							csc.h = cyMinChild
							csc.x = cs.x
							csc.y = cs.y
						}
					}
				}
				hctx.RebarBandCounts[hwnd]++
				cs.h = int32(hctx.RebarBandCounts[hwnd]) * 26
				// Queue repaint so the toolbar gets drawn after sizing
				hctx.QueuePaint(hctx.MainHWND)
				return 1, true
			case rbFirst + 12: // RB_GETBANDCOUNT
				return uint64(hctx.RebarBandCounts[hwnd]), true
			case rbFirst + 14: // RB_GETBANDINFO / RB_GETBANDINFOA
				return 1, true
			case rbFirst + 4: // RB_DELETEBAND
				if hctx.RebarBandCounts[hwnd] > 0 {
					hctx.RebarBandCounts[hwnd]--
					cs.h = int32(hctx.RebarBandCounts[hwnd]) * 26
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
			tb := cs.toolbar
			is32 := hctx.ProcState != nil && hctx.ProcState.Is32
			buttonLayout := toolbarButtonOffsets(is32)
			buttonInfoLayout := toolbarButtonInfoOffsets(is32)
			if os.Getenv("RAVEN_TRACE_TOOLBAR") != "" && msg != 0x000F {
				ravelog.Logf("[toolbar-msg] hwnd=0x%x msg=0x%x wParam=0x%x lParam=0x%x\n", hwnd, msg, wParam, lParam)
			}
			readToolbarButton := func(base uint64, wide bool) tbButton {
				iBitmap, _ := mem.Read32(base)
				idCommand, _ := mem.Read32(base + 4)
				stateBytes, _ := mem.ReadBytes(base+8, 2)
				state, style := byte(0), byte(0)
				if len(stateBytes) == 2 {
					state = stateBytes[0]
					style = stateBytes[1]
				}
				data, _ := readGuestPointer(mem, base+buttonLayout.data, is32)
				stringValue, _ := readGuestPointer(mem, base+buttonLayout.string, is32)
				button := tbButton{
					id:          int(int32(idCommand)),
					iBitmap:     int(int32(iBitmap)),
					state:       int(state),
					style:       int(style),
					param:       data,
					stringValue: stringValue,
				}
				if stringValue > 0xFFFF {
					if wide {
						button.text = readGuestUTF16(stringValue)
					} else {
						button.text = readGuestString(stringValue)
					}
				}
				return button
			}
			switch msg {
			case 0x000F: // WM_PAINT
				validatePaint()
				if wlWindow != nil {
					// Draw toolbar background - slightly darker than button face for contrast
					wlWindow.DrawRectAbs(cs.x, cs.y, cs.x+cs.w, cs.y+cs.h, 0xD4D0C8)
					btnW := cs.tbBtnW
					if btnW <= 0 {
						btnW = 23
					}
					btnH := cs.tbBtnH
					if btnH <= 0 {
						btnH = 22
					}
					if btnH > cs.h-2 {
						btnH = cs.h - 2
					}
					const padY = int32(2)
					x := cs.x + 2
					drawBtn := func(bx, by, bw, bh int32) {
						// Windows classic raised button: face + 3D border
						wlWindow.DrawRectAbs(bx, by, bx+bw, by+bh, 0xECE9D8)            // button face
						wlWindow.DrawRectAbs(bx, by, bx+bw, by+1, 0xFFFFFF)             // top highlight
						wlWindow.DrawRectAbs(bx, by, bx+1, by+bh, 0xFFFFFF)             // left highlight
						wlWindow.DrawRectAbs(bx+bw-2, by+1, bx+bw-1, by+bh-1, 0xACA899) // inner right shadow
						wlWindow.DrawRectAbs(bx+1, by+bh-2, bx+bw-1, by+bh-1, 0xACA899) // inner bottom shadow
						wlWindow.DrawRectAbs(bx+bw-1, by, bx+bw, by+bh, 0x716F64)       // outer right shadow
						wlWindow.DrawRectAbs(bx, by+bh-1, bx+bw, by+bh, 0x716F64)       // outer bottom shadow
					}
					fallbackKey := toolbarFallbackKey{
						parent: cs.parentHWND,
						layout: toolbarLayoutSignature(tb),
					}
					for _, btn := range tb.buttons {
						if btn.state&0x08 != 0 {
							continue
						}
						if x >= cs.x+cs.w {
							break
						}
						if btn.style&0x01 != 0 { // TBSTYLE_SEP
							mid := x + 3
							wlWindow.DrawRectAbs(mid, cs.y+padY+2, mid+1, cs.y+padY+btnH-2, 0x716F64)
							wlWindow.DrawRectAbs(mid+1, cs.y+padY+2, mid+2, cs.y+padY+btnH-2, 0xFFFFFF)
							x += 8
							continue
						}
						drawBtn(x, cs.y+padY, btnW, btnH)
						// Draw icon if available; resolve lazy handle if pixel data not yet loaded.
						iconIdx := btn.iBitmap
						iconW := int(cs.tbBitmapIconW)
						iconH := int(cs.tbBitmapIconH)
						if cs.tbImageList != 0 {
							if width, height, ok := comctl32.ImageListGetIconSize(cs.tbImageList); ok {
								iconW = int(width)
								iconH = int(height)
								cs.tbBitmapIconW = width
								cs.tbBitmapIconH = height
							}
						}
						if iconW <= 0 {
							iconW = 16
						}
						if iconH <= 0 {
							iconH = 16
						}
						var pix []uint32
						imagePresent := false
						iconStore := cs.tbBitmapStore
						if cs.tbImageList != 0 {
							imagePixels, mask, hasAlpha, ok := comctl32.ImageListGetImage(cs.tbImageList, int32(iconIdx))
							if ok {
								imagePresent = true
								pix = toolbarImagePixels(imagePixels, mask, hasAlpha, iconW, iconH)
							}
						}
						if cs.tbImageList == 0 && len(pix) == 0 && iconIdx >= 0 && iconIdx < len(iconStore) {
							pix = iconStore[iconIdx]
							if len(pix) == 0 && cs.tbHandleMap != nil {
								if ref, ok2 := cs.tbHandleMap[iconIdx]; ok2 {
									if bd, ok3 := hctx.BitmapHandles[ref.handle]; ok3 && ref.slotIndex < len(bd.slots) {
										cs.tbBitmapStore[iconIdx] = bd.slots[ref.slotIndex]
										pix = cs.tbBitmapStore[iconIdx]
									} else if obj := gdiMgr.GetObject(ref.handle); obj != nil && obj.Bitmap != nil && obj.Bitmap.Surf != nil {
										surf := obj.Bitmap.Surf
										bw := int(surf.Width)
										bh := int(surf.Height)
										iw, ih := iconW, iconH
										s := ref.slotIndex
										slot := make([]uint32, iw*ih)
										for py := 0; py < ih && py < bh; py++ {
											for px := 0; px < iw; px++ {
												off := (py*bw + s*iw + px) * 4
												if off+3 >= len(surf.Pix) {
													break
												}
												b, g, r, a := surf.Pix[off], surf.Pix[off+1], surf.Pix[off+2], surf.Pix[off+3]
												if a == 0 {
													a = 0xFF
												}
												slot[py*iw+px] = uint32(b) | uint32(g)<<8 | uint32(r)<<16 | uint32(a)<<24
											}
										}
										cs.tbBitmapStore[iconIdx] = slot
										pix = slot
									}
								}
							}
						}
						if cs.tbImageList == 0 && toolbarIconHasVisiblePixel(pix) {
							cacheToolbarFallbackIcon(hctx, fallbackKey, iconIdx, iconW, iconH, pix)
						} else if imagePresent && !toolbarIconHasVisiblePixel(pix) {
							pix = toolbarFallbackIcon(hctx, fallbackKey, iconIdx, iconW, iconH)
						}
						if len(pix) > 0 {
							offX := x + (btnW-int32(iconW))/2
							offY := cs.y + padY + (btnH-int32(iconH))/2
							winW := int(wlWindow.Width)
							winH := int(wlWindow.Height + wlWindow.TitleBarH)
							for py := 0; py < iconH; py++ {
								for px := 0; px < iconW; px++ {
									idx := py*iconW + px
									if idx >= len(pix) {
										break
									}
									c := pix[idx]
									a := byte(c >> 24)
									if a == 0 {
										continue // fully transparent
									}
									sx := int(offX) + px
									sy := int(offY) + py
									if sx >= 0 && sy >= 0 && sx < winW && sy < winH {
										base := (sy*winW + sx) * 4
										if a == 0xFF {
											wlWindow.Pix[base+0] = byte(c & 0xFF)
											wlWindow.Pix[base+1] = byte((c >> 8) & 0xFF)
											wlWindow.Pix[base+2] = byte((c >> 16) & 0xFF)
											wlWindow.Pix[base+3] = 0xFF
										} else {
											// Alpha blend: dst = src*a + dst*(1-a)
											sa := uint32(a)
											da := 255 - sa
											wlWindow.Pix[base+0] = byte((uint32(byte(c&0xFF))*sa + uint32(wlWindow.Pix[base+0])*da) / 255)
											wlWindow.Pix[base+1] = byte((uint32(byte((c>>8)&0xFF))*sa + uint32(wlWindow.Pix[base+1])*da) / 255)
											wlWindow.Pix[base+2] = byte((uint32(byte((c>>16)&0xFF))*sa + uint32(wlWindow.Pix[base+2])*da) / 255)
											wlWindow.Pix[base+3] = 0xFF
										}
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
				if btnW <= 0 {
					btnW = 23
				}
				x := int32(2)
				for _, btn := range tb.buttons {
					if btn.state&0x08 != 0 {
						continue
					}
					if btn.style&0x01 != 0 { // TBSTYLE_SEP
						x += 8
						continue
					}
					if clickX >= x && clickX < x+btnW {
						if btn.state&0x0C == 0x04 {
							// WM_COMMAND: LOWORD=cmdID, HIWORD=1 (BN_CLICKED), lParam=toolbar HWND
							hctx.enqueueMessage(nil, newQueuedMsg(hctx, cs.parentHWND, 0x0111,
								uint64(uint16(btn.id))|(1<<16), hwnd))
						}
						break
					}
					x += btnW + 1
				}
				return 0, true
			case wmUser + 1: // TB_ENABLEBUTTON
				id := int(int32(wParam))
				if setToolbarButtonFlag(tb, id, 0x04, lParam != 0) {
					syncToolbarCompat(cs)
					hctx.QueuePaint(hwnd)
				}
				return 1, true
			case wmUser + 2: // TB_CHECKBUTTON
				setToolbarButtonFlag(tb, int(int32(wParam)), 0x01, lParam != 0)
				syncToolbarCompat(cs)
				hctx.QueuePaint(hwnd)
				return 1, true
			case wmUser + 3: // TB_PRESSBUTTON
				setToolbarButtonFlag(tb, int(int32(wParam)), 0x02, lParam != 0)
				syncToolbarCompat(cs)
				hctx.QueuePaint(hwnd)
				return 1, true
			case wmUser + 4: // TB_HIDEBUTTON
				setToolbarButtonFlag(tb, int(int32(wParam)), 0x08, lParam != 0)
				syncToolbarCompat(cs)
				hctx.QueuePaint(hwnd)
				return 1, true
			case wmUser + 18: // TB_GETSTATE
				id := int(int32(wParam))
				for _, btn := range tb.buttons {
					if btn.id == id {
						return uint64(btn.state), true
					}
				}
				return 0, true
			case wmUser + 10: // TB_ISBUTTONCHECKED
				id := int(int32(wParam))
				for _, btn := range tb.buttons {
					if btn.id == id {
						if btn.state&0x01 != 0 {
							return 1, true
						}
						return 0, true
					}
				}
				return 0, true
			case wmUser + 9: // TB_ISBUTTONENABLED
				id := int(int32(wParam))
				for _, btn := range tb.buttons {
					if btn.id == id {
						if btn.state&0x04 != 0 {
							return 1, true
						}
						return 0, true
					}
				}
				return 0, true
			case wmUser + 19: // TB_ADDBITMAP - load bitmap from PE resource, return start index
				startIdx := len(cs.tbBitmapStore)
				nBitmaps := int(wParam)
				if lParam != 0 && mainModule != nil {
					hInst, _ := readGuestPointer(mem, lParam, is32)
					nID, _ := readGuestPointer(mem, lParam+toolbarAddBitmapResourceOffset(is32), is32)
					iconW := int(cs.tbBitmapIconW)
					iconH := int(cs.tbBitmapIconH)
					if iconW <= 0 {
						iconW = 16
					}
					if iconH <= 0 {
						iconH = 16
					}
					ravelog.Logf("[toolbar] TB_ADDBITMAP nBitmaps=%d hInst=0x%x nID=0x%x mainBase=0x%x iconW=%d iconH=%d\n",
						nBitmaps, hInst, nID, mainModule.BaseAddr, iconW, iconH)

					hinstCommctrl := ^uint64(0)
					if is32 {
						hinstCommctrl = uint64(^uint32(0))
					}
					if hInst == hinstCommctrl {
						if nBitmaps <= 0 {
							nBitmaps = 1
						}
						for i := 0; i < nBitmaps; i++ {
							cs.tbBitmapStore = append(cs.tbBitmapStore, makeToolbarPlaceholderIcon(iconW, iconH, nID+uint64(i)))
						}
						return uint64(startIdx), true
					} else if hInst == 0 {
						if _, ok2 := hctx.BitmapHandles[nID]; !ok2 {
							obj := gdiMgr.GetObject(nID)
							if obj == nil || obj.Bitmap == nil || obj.Bitmap.Surf == nil {
								if lParam != 0 && mainModule != nil {
									if nID != 0 {
										if addr, sz, ok3 := peLoadRawResource(mainModule.BaseAddr, mainModule.ResourceDirRVA, 2, uint32(nID)); ok3 {
											slots := decodeDIBSlots(addr, sz, iconW, iconH)
											ravelog.Logf("[toolbar] TB_ADDBITMAP fallback resource id=0x%x decoded %d icon slots\n", uint32(nID), len(slots))
											cs.tbBitmapStore = append(cs.tbBitmapStore, slots...)
											return uint64(startIdx), true
										}
									}
								}
								ravelog.Logf("[toolbar] TB_ADDBITMAP HBITMAP 0x%x not found, returning failure\n", nID)
								return uint64(uint32(0xFFFFFFFF)), true
							}
						}
						// nID is an HBITMAP handle (LoadBitmap/LoadImage or CreateDIBSection).
						// Check bitmapHandles, then gdiMgr (DIBSection), then defer lazy.
						if bd, ok2 := hctx.BitmapHandles[nID]; ok2 && len(bd.slots) > 0 {
							ravelog.Logf("[toolbar] TB_ADDBITMAP HBITMAP handle found, %d slots\n", len(bd.slots))
							cs.tbBitmapStore = append(cs.tbBitmapStore, bd.slots...)
						} else if obj := gdiMgr.GetObject(nID); obj != nil && obj.Bitmap != nil && obj.Bitmap.Surf != nil {
							surf := obj.Bitmap.Surf
							bw := int(surf.Width)
							bh := int(surf.Height)
							iw, ih := iconW, iconH
							if iw <= 0 {
								iw = bw
							}
							if ih <= 0 {
								ih = bh
							}
							ns := bw / iw
							if ns == 0 {
								ns = 1
							}
							slots := make([][]uint32, ns)
							for s := 0; s < ns; s++ {
								pix := make([]uint32, iw*ih)
								for py := 0; py < ih && py < bh; py++ {
									for px := 0; px < iw; px++ {
										off := (py*bw + s*iw + px) * 4
										if off+3 >= len(surf.Pix) {
											break
										}
										b, g, r, a := surf.Pix[off], surf.Pix[off+1], surf.Pix[off+2], surf.Pix[off+3]
										if a == 0 {
											a = 0xFF
										}
										pix[py*iw+px] = uint32(b) | uint32(g)<<8 | uint32(r)<<16 | uint32(a)<<24
									}
								}
								slots[s] = pix
							}
							ravelog.Logf("[toolbar] TB_ADDBITMAP GDI surf %dx%d → %d slots (iconW=%d iconH=%d)\n", bw, bh, ns, iw, ih)
							cs.tbBitmapStore = append(cs.tbBitmapStore, slots...)
						} else {
							ravelog.Logf("[toolbar] TB_ADDBITMAP HBITMAP 0x%x not found - lazy\n", nID)
							if cs.tbHandleMap == nil {
								cs.tbHandleMap = make(map[int]tbLazyRef)
							}
							for i := 0; i < nBitmaps; i++ {
								cs.tbHandleMap[startIdx+i] = tbLazyRef{handle: nID, slotIndex: i}
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
							return uint64(uint32(0xFFFFFFFF)), true
						}
					} else {
						ravelog.Logf("[toolbar] TB_ADDBITMAP hInst mismatch 0x%x, skipping\n", hInst)
						return uint64(uint32(0xFFFFFFFF)), true
					}
				}
				return uint64(startIdx), true
			case wmUser + 20, wmUser + 68: // TB_ADDBUTTONSA, TB_ADDBUTTONSW
				nButtons := int(wParam)
				btnStruct := lParam
				for i := 0; i < nButtons; i++ {
					base := btnStruct + uint64(i)*buttonLayout.size
					tb.buttons = append(tb.buttons, readToolbarButton(base, msg == wmUser+68))
				}
				syncToolbarCompat(cs)
				hctx.QueuePaint(hwnd)
				return 1, true
			case wmUser + 21, wmUser + 67: // TB_INSERTBUTTONA, TB_INSERTBUTTONW
				idx := int(int32(wParam))
				if lParam == 0 {
					return 0, true
				}
				btn := readToolbarButton(lParam, msg == wmUser+67)
				if idx < 0 || idx > len(tb.buttons) {
					idx = len(tb.buttons)
				}
				tb.buttons = append(tb.buttons, tbButton{})
				copy(tb.buttons[idx+1:], tb.buttons[idx:])
				tb.buttons[idx] = btn
				syncToolbarCompat(cs)
				hctx.QueuePaint(hwnd)
				return 1, true
			case wmUser + 30: // TB_BUTTONSTRUCTSIZE
				return 0, true
			case wmUser + 32: // TB_SETBITMAPSIZE
				cs.tbBitmapIconW = int32(lParam & 0xFFFF)
				cs.tbBitmapIconH = int32((lParam >> 16) & 0xFFFF)
				ravelog.Logf("[toolbar] TB_SETBITMAPSIZE iconW=%d iconH=%d\n", cs.tbBitmapIconW, cs.tbBitmapIconH)
				return 1, true
			case wmUser + 33: // TB_AUTOSIZE
				cs.h = 26
				// Set width to parent's client width
				if parent, ok := hctx.HwndChildren[cs.parentHWND]; ok {
					cs.w = parent.w
				} else if cs.parentHWND == hctx.MainHWND && wlWindow != nil {
					cs.w = wlWindow.Width
				}
				return 0, true
			case wmUser + 31: // TB_SETBUTTONSIZE
				cs.tbBtnW = int32(lParam & 0xFFFF)
				cs.tbBtnH = int32((lParam >> 16) & 0xFFFF)
				return 1, true
			case wmUser + 40: // TB_GETROWS
				return 1, true
			case wmUser + 58: // TB_GETBUTTONSIZE
				return (uint64(26) << 16) | 24, true // height=26, width=24
			case wmUser + 24: // TB_BUTTONCOUNT
				return uint64(len(tb.buttons)), true
			case wmUser + 22: // TB_DELETEBUTTON
				idx := int(int32(wParam))
				if idx >= 0 && idx < len(tb.buttons) {
					tb.buttons = append(tb.buttons[:idx], tb.buttons[idx+1:]...)
					syncToolbarCompat(cs)
					hctx.QueuePaint(hwnd)
					return 1, true
				}
				return 0, true
			case wmUser + 36: // TB_SETTOOLTIPS
				return 0, true
			case wmUser + 60: // TB_SETMAXTEXTROWS
				return 1, true
			case wmUser + 48: // TB_SETIMAGELIST
				old := cs.tbImageList
				cs.tbImageList = lParam
				if lParam != 0 {
					count := int(comctl32.ImageListGetImageCount(lParam))
					cx, cy, ok := comctl32.ImageListGetIconSize(lParam)
					if ok && cx > 0 && cy > 0 {
						cs.tbBitmapIconW = cx
						cs.tbBitmapIconH = cy
					}
					ravelog.Logf("[toolbar] TB_SETIMAGELIST h=0x%x count=%d iconW=%d iconH=%d\n",
						lParam, count, cs.tbBitmapIconW, cs.tbBitmapIconH)
				}
				return old, true
			case wmUser + 49: // TB_GETIMAGELIST
				return cs.tbImageList, true
			case wmUser + 29: // TB_GETITEMRECT
				if lParam != 0 {
					btnIdx := int32(wParam)
					x := btnIdx * 24
					mem.Write32(lParam, uint32(x))
					mem.Write32(lParam+4, 0)
					mem.Write32(lParam+8, uint32(x+24))
					mem.Write32(lParam+12, 26)
				}
				return 1, true
			case wmUser + 23: // TB_GETBUTTON
				index := int(int32(wParam))
				if lParam == 0 || index < 0 || index >= len(tb.buttons) {
					return 0, true
				}
				button := tb.buttons[index]
				mem.Write32(lParam, uint32(int32(button.iBitmap)))
				mem.Write32(lParam+4, uint32(int32(button.id)))
				mem.Write8(lParam+8, uint8(button.state))
				mem.Write8(lParam+9, uint8(button.style))
				_ = writeGuestPointer(mem, lParam+buttonLayout.data, button.param, is32)
				_ = writeGuestPointer(mem, lParam+buttonLayout.string, button.stringValue, is32)
				return 1, true
			case wmUser + 37: // TB_SETPARENT
				return 0, true
			case wmUser + 64, wmUser + 66: // TB_SETBUTTONINFOW, TB_SETBUTTONINFOA
				id := int(int32(wParam))
				if lParam != 0 {
					mask, _ := mem.Read32(lParam + 4)
					for i := range tb.buttons {
						if tb.buttons[i].id != id {
							continue
						}
						if mask&0x0001 != 0 { // TBIF_IMAGE
							iImage, _ := mem.Read32(lParam + 12)
							tb.buttons[i].iBitmap = int(int32(iImage))
						}
						if mask&0x0004 != 0 { // TBIF_STATE
							state, _ := mem.Read8(lParam + 16)
							tb.buttons[i].state = int(state)
						}
						if mask&0x0008 != 0 { // TBIF_STYLE
							style, _ := mem.Read8(lParam + 17)
							tb.buttons[i].style = int(style)
						}
						if mask&0x0010 != 0 { // TBIF_LPARAM
							tb.buttons[i].param, _ = readGuestPointer(mem, lParam+buttonInfoLayout.param, is32)
						}
						if mask&0x0002 != 0 { // TBIF_TEXT
							pszText, _ := readGuestPointer(mem, lParam+buttonInfoLayout.text, is32)
							if pszText != 0 {
								if msg == wmUser+64 {
									tb.buttons[i].text = readGuestUTF16(pszText)
								} else {
									tb.buttons[i].text = readGuestString(pszText)
								}
							}
						}
						syncToolbarCompat(cs)
						hctx.QueuePaint(hwnd)
						break
					}
				}
				return 1, true
			case wmUser + 63, wmUser + 65: // TB_GETBUTTONINFOW, TB_GETBUTTONINFOA
				if lParam == 0 {
					return uint64(^uint32(0)), true
				}
				id := int(int32(wParam))
				for i, btn := range tb.buttons {
					if btn.id != id {
						continue
					}
					mask, _ := mem.Read32(lParam + 4)
					if mask&0x0001 != 0 { // TBIF_IMAGE
						mem.Write32(lParam+12, uint32(int32(btn.iBitmap)))
					}
					if mask&0x0004 != 0 { // TBIF_STATE
						mem.Write8(lParam+16, uint8(btn.state))
					}
					if mask&0x0008 != 0 { // TBIF_STYLE
						mem.Write8(lParam+17, uint8(btn.style))
					}
					if mask&0x0010 != 0 { // TBIF_LPARAM
						_ = writeGuestPointer(mem, lParam+buttonInfoLayout.param, btn.param, is32)
					}
					if mask&0x0002 != 0 { // TBIF_TEXT
						pszText, _ := readGuestPointer(mem, lParam+buttonInfoLayout.text, is32)
						cchText, _ := mem.Read32(lParam + buttonInfoLayout.textMax)
						if pszText != 0 && cchText > 0 {
							if msg == wmUser+63 {
								ws := utf16Encode(btn.text)
								limit := int(cchText) - 1
								if limit < 0 {
									limit = 0
								}
								if len(ws) > limit {
									ws = ws[:limit]
								}
								for j, ch := range ws {
									mem.Write16(pszText+uint64(j*2), ch)
								}
								mem.Write16(pszText+uint64(len(ws))*2, 0)
							} else {
								writeGuestStringLimited(pszText, btn.text, int(cchText))
							}
						}
					}
					return uint64(i), true
				}
				return uint64(^uint32(0)), true
			case wmUser + 17: // TB_SETSTATE
				id := int(int32(wParam))
				for i := range tb.buttons {
					if tb.buttons[i].id == id {
						tb.buttons[i].state = int(uint32(lParam))
						syncToolbarCompat(cs)
						hctx.QueuePaint(hwnd)
						break
					}
				}
				return 0, true
			case wmUser + 85: // TB_GETEXTENDEDSTYLE
				return uint64(tb.extStyle), true
			case wmUser + 84: // TB_SETEXTENDEDSTYLE
				old := tb.extStyle
				tb.extStyle = uint32(lParam)
				return uint64(old), true
			case wmUser + 50: // TB_LOADIMAGES
				return 0, true
			default:
				return 0, true
			}

		case "systabcontrol32":
			const tcmFirst = 0x1300
			const (
				tcifText  = 0x0001
				tcifParam = 0x0008
			)
			if tabInputNeedsSubclassFirst(hctx.HwndWndProc[hwnd] != 0, hctx.CallBuiltinControl, msg) {
				return 0, false
			}
			tab := cs.tab
			if os.Getenv("RAVEN_TRACE_CLICK") != "" && msg != 0x000F {
				ravelog.Logf("[tab-msg] hwnd=0x%x msg=0x%x wParam=0x%x curSel=%d\n", hwnd, msg, wParam, tab.curSel)
			}
			is32 := hctx.ProcState != nil && hctx.ProcState.Is32
			textOffset, paramOffset := tabItemOffsets(is32)
			readItemPtr := func(addr uint64) uint64 {
				if is32 {
					v, _ := mem.Read32(addr)
					return uint64(v)
				}
				v, _ := mem.Read64(addr)
				return v
			}
			readItemParam := readItemPtr
			writeItemParam := func(addr, value uint64) {
				if is32 {
					mem.Write32(addr, uint32(value))
				} else {
					mem.Write64(addr, value)
				}
			}
			switch msg {
			case tcmFirst + 7: // TCM_INSERTITEMA
				item := tabItem{}
				if lParam != 0 {
					mask, _ := mem.Read32(lParam)
					if mask&tcifText != 0 {
						pText := readItemPtr(lParam + textOffset)
						if pText != 0 {
							item.text = readGuestString(pText)
						}
					}
					if mask&tcifParam != 0 {
						item.param = readItemParam(lParam + paramOffset)
					}
				}
				idx := int(int32(wParam))
				if idx < 0 || idx > len(tab.items) {
					idx = len(tab.items)
				}
				tab.items = append(tab.items, tabItem{})
				copy(tab.items[idx+1:], tab.items[idx:])
				tab.items[idx] = item
				if tab.curSel < 0 {
					tab.curSel = 0
				}
				syncTabCompat(cs)
				hctx.QueuePaint(hwnd)
				return uint64(idx), true
			case tcmFirst + 62: // TCM_INSERTITEMW
				item := tabItem{}
				if lParam != 0 {
					mask, _ := mem.Read32(lParam)
					if mask&tcifText != 0 {
						pText := readItemPtr(lParam + textOffset)
						if pText != 0 {
							item.text = readGuestUTF16(pText)
						}
					}
					if mask&tcifParam != 0 {
						item.param = readItemParam(lParam + paramOffset)
					}
				}
				idx := int(int32(wParam))
				if idx < 0 || idx > len(tab.items) {
					idx = len(tab.items)
				}
				tab.items = append(tab.items, tabItem{})
				copy(tab.items[idx+1:], tab.items[idx:])
				tab.items[idx] = item
				if tab.curSel < 0 {
					tab.curSel = 0
				}
				syncTabCompat(cs)
				hctx.QueuePaint(hwnd)
				return uint64(idx), true
			case tcmFirst + 8: // TCM_DELETEITEM
				idx := int(int32(wParam))
				if idx >= 0 && idx < len(tab.items) {
					tab.items = append(tab.items[:idx], tab.items[idx+1:]...)
					if tab.curSel >= len(tab.items) {
						tab.curSel = len(tab.items) - 1
					}
					syncTabCompat(cs)
					hctx.QueuePaint(hwnd)
					return 1, true
				}
				return 0, true
			case tcmFirst + 4: // TCM_GETITEMCOUNT
				return uint64(len(tab.items)), true
			case tcmFirst + 44: // TCM_GETROWCOUNT
				return tabRowCount(tab), true
			case tcmFirst + 11: // TCM_GETCURSEL
				return uint64(tab.curSel), true
			case tcmFirst + 12: // TCM_SETCURSEL
				prev := tab.curSel
				newSel := int(int32(wParam))
				if newSel >= 0 && newSel < len(tab.items) {
					tab.curSel = newSel
					syncTabCompat(cs)
					hctx.QueuePaint(hwnd)
				}
				return uint64(prev), true
			case tcmFirst + 13: // TCM_HITTEST
				if lParam != 0 {
					v, _ := mem.Read32(lParam)
					ptX := int32(v)
					const tabPadHT = int32(16)
					tx := int32(0)
					for i := 0; i < len(tab.items); i++ {
						tw := menuTextWidth(tab.items[i].text) + tabPadHT*2
						if tw < 40 {
							tw = 40
						}
						if ptX >= tx && ptX < tx+tw {
							mem.Write32(lParam+8, 0x0001) // TCHT_ONITEM
							return uint64(i), true
						}
						tx += tw
					}
				}
				return uint64(0xFFFFFFFF), true // no tab hit
			case tcmFirst + 10: // TCM_GETITEMRECT
				if lParam != 0 {
					idx := int(int32(wParam))
					const tabPadR = int32(16)
					left := int32(0)
					for i := 0; i < idx && i < len(tab.items); i++ {
						tw := menuTextWidth(tab.items[i].text) + tabPadR*2
						if tw < 40 {
							tw = 40
						}
						left += tw
					}
					tw := int32(80) // default
					if idx >= 0 && idx < len(tab.items) {
						tw = menuTextWidth(tab.items[idx].text) + tabPadR*2
						if tw < 40 {
							tw = 40
						}
					}
					mem.Write32(lParam, uint32(left))
					mem.Write32(lParam+4, 0)
					mem.Write32(lParam+8, uint32(left+tw))
					mem.Write32(lParam+12, 22)
				}
				return 1, true
			case tcmFirst + 60: // TCM_GETITEMW
				idx := int(int32(wParam))
				if idx >= 0 && idx < len(tab.items) && lParam != 0 {
					mask, _ := mem.Read32(lParam)
					if mask&tcifText != 0 {
						pText := readItemPtr(lParam + textOffset)
						if pText != 0 {
							ws := utf16Encode(tab.items[idx].text)
							for i, ch := range ws {
								mem.Write16(pText+uint64(i*2), ch)
							}
							mem.Write16(pText+uint64(len(ws))*2, 0)
						}
					}
					if mask&tcifParam != 0 {
						writeItemParam(lParam+paramOffset, tab.items[idx].param)
					}
					return 1, true
				}
				return 0, true
			case tcmFirst + 5: // TCM_GETITEMA
				idx := int(int32(wParam))
				if idx >= 0 && idx < len(tab.items) && lParam != 0 {
					mask, _ := mem.Read32(lParam)
					if mask&tcifText != 0 {
						pText := readItemPtr(lParam + textOffset)
						if pText != 0 {
							for i, b := range []byte(tab.items[idx].text) {
								mem.Write8(pText+uint64(i), b)
							}
							mem.Write8(pText+uint64(len(tab.items[idx].text)), 0)
						}
					}
					if mask&tcifParam != 0 {
						writeItemParam(lParam+paramOffset, tab.items[idx].param)
					}
					return 1, true
				}
				return 0, true
			case tcmFirst + 61: // TCM_SETITEMW
				idx := int(int32(wParam))
				if idx >= 0 && idx < len(tab.items) && lParam != 0 {
					mask, _ := mem.Read32(lParam)
					if mask&tcifText != 0 {
						pText := readItemPtr(lParam + textOffset)
						if pText != 0 {
							tab.items[idx].text = readGuestUTF16(pText)
						}
					}
					if mask&tcifParam != 0 {
						tab.items[idx].param = readItemParam(lParam + paramOffset)
					}
					syncTabCompat(cs)
					hctx.QueuePaint(hwnd)
					return 1, true
				}
				return 0, true
			case tcmAdjustRect: // TCM_ADJUSTRECT
				if lParam != 0 {
					l, _ := mem.Read32(lParam)
					t, _ := mem.Read32(lParam + 4)
					r, _ := mem.Read32(lParam + 8)
					b, _ := mem.Read32(lParam + 12)
					rect := adjustTabRect([4]int32{int32(l), int32(t), int32(r), int32(b)}, cs.style, wParam != 0, 22, 1)
					mem.Write32(lParam, uint32(rect[0]))
					mem.Write32(lParam+4, uint32(rect[1]))
					mem.Write32(lParam+8, uint32(rect[2]))
					mem.Write32(lParam+12, uint32(rect[3]))
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
			case 0x000F: // WM_PAINT: draw tab bar strip (not the full client area)
				validatePaint()
				// A tab control inside an owned dialog (e.g. NPP's Find/Replace)
				// must be painted by the dialog renderer into the dialog's own
				// window, not hardcoded onto the main window. Otherwise the tab
				// strip leaks onto the main window and the panel never switches.
				if root, target, isOwnedDialog := topLevelDialogTarget(hctx, hwnd); isOwnedDialog && target != nil {
					renderOwnedDialog(hctx, root, target)
					return 0, true
				}
				if wlWindow != nil {
					const tabH = int32(22) // height of tab header strip
					// Only fill the tab strip area, not the entire control height
					wlWindow.DrawRectAbs(cs.x, cs.y, cs.x+cs.w, cs.y+tabH, sysColors[15])
					// Bottom border of tab strip
					wlWindow.DrawRectAbs(cs.x, cs.y+tabH-1, cs.x+cs.w, cs.y+tabH, sysColors[16])
					// Draw tabs
					x := cs.x
					for i := 0; i < len(tab.items); i++ {
						sel := i == cs.tabCurSel
						bgCol := sysColors[15]
						if sel {
							bgCol = sysColors[5]
						}
						tabW := int32(80)
						wlWindow.DrawRectAbs(x, cs.y, x+tabW, cs.y+tabH, bgCol)
						// tab border
						wlWindow.DrawRectAbs(x, cs.y, x+1, cs.y+tabH, sysColors[16])
						wlWindow.DrawRectAbs(x+tabW-1, cs.y, x+tabW, cs.y+tabH, sysColors[16])
						wlWindow.DrawRectAbs(x, cs.y, x+tabW, cs.y+1, sysColors[16])
						// tab title
						if i < len(tab.items) && tab.items[i].text != "" {
							textColor := uint32(0x000000)
							hctx.NcDrawText(x+4, cs.y+4, tab.items[i].text, textColor, bgCol, false, 12)
						}
						x += tabW
					}
				}
				return 0, true
			case 0x0201: // WM_LBUTTONDOWN - find which tab was hit and notify parent
				clickX := int32(lParam & 0xFFFF)
				const tabPad2 = int32(16)
				tx := int32(0)
				hitTab := -1
				for i := 0; i < len(tab.items); i++ {
					label := tab.items[i].text
					tw := menuTextWidth(label) + tabPad2*2
					if tw < 40 {
						tw = 40
					}
					if clickX >= tx && clickX < tx+tw {
						hitTab = i
						break
					}
					tx += tw
				}
				if os.Getenv("RAVEN_TRACE_CLICK") != "" {
					ravelog.Logf("[tab-click] hwnd=0x%x clickX=%d hitTab=%d curSel=%d parent=0x%x is32=%v\n",
						hwnd, clickX, hitTab, tab.curSel, cs.parentHWND, mem.Mode32)
				}
				notifyParent := func(code uint32) uint64 {
					if hctx.NotifyBuf == 0 {
						hctx.NotifyBuf = mem.Mmap(0, 128, mmu.PermRead|mmu.PermWrite)
					}
					nmhdr := hctx.NotifyBuf
					if code == tcnSelChanging {
						nmhdr += 64
					}
					if mem.Mode32 {
						mem.Write32(nmhdr, uint32(hwnd))
						mem.Write32(nmhdr+4, uint32(cs.ctrlID))
						mem.Write32(nmhdr+8, code)
					} else {
						mem.Write64(nmhdr, hwnd)
						mem.Write64(nmhdr+8, uint64(cs.ctrlID))
						mem.Write32(nmhdr+16, code)
					}
					return sendNotifySync(cs.parentHWND, 0x004E, uint64(cs.ctrlID), nmhdr)
				}
				if selectTabFromInput(tab, hitTab, notifyParent) {
					syncTabCompat(cs)
					// Repaint tab strip to show new selection.
					hctx.QueuePaint(hwnd)
				}
				return 0, true
			default:
				return 0, false // let guest WndProc handle unrecognised messages
			}

		case "tooltips_class32":
			const wmUser = 0x0400
			tt := cs.tooltip
			switch msg {
			case wmUser + 1: // TTM_ACTIVATE
				tt.active = wParam != 0
				return 0, true
			case wmUser + 3: // TTM_SETDELAYTIME
				return 0, true
			case wmUser + 4, wmUser + 50: // TTM_ADDTOOLA/W
				tool, ok := parseToolInfo(lParam, msg == wmUser+50)
				if !ok {
					return 0, true
				}
				if idx := findTooltipIndex(tt, tool.hwnd, tool.id); idx >= 0 {
					tt.tools[idx] = tool
				} else {
					tt.tools = append(tt.tools, tool)
				}
				return 1, true
			case wmUser + 51: // TTM_DELTOOLW
				tool, ok := parseToolInfo(lParam, true)
				if !ok {
					return 0, true
				}
				if idx := findTooltipIndex(tt, tool.hwnd, tool.id); idx >= 0 {
					tt.tools = append(tt.tools[:idx], tt.tools[idx+1:]...)
					return 1, true
				}
				return 0, true
			case wmUser + 6, wmUser + 52: // TTM_NEWTOOLRECTA/W
				tool, ok := parseToolInfo(lParam, msg == wmUser+52)
				if !ok {
					return 0, true
				}
				if idx := findTooltipIndex(tt, tool.hwnd, tool.id); idx >= 0 {
					tt.tools[idx].rect = tool.rect
					return 1, true
				}
				return 0, true
			case wmUser + 13: // TTM_GETTOOLCOUNT
				return uint64(len(tt.tools)), true
			case wmUser + 8, wmUser + 53: // TTM_GETTOOLINFOA/W
				tool, ok := parseToolInfo(lParam, msg == wmUser+53)
				if !ok {
					return 0, true
				}
				if idx := findTooltipIndex(tt, tool.hwnd, tool.id); idx >= 0 {
					writeToolInfo(lParam, tt.tools[idx], msg == wmUser+53)
					return 1, true
				}
				return 0, true
			case wmUser + 54: // TTM_SETTOOLINFOW
				tool, ok := parseToolInfo(lParam, true)
				if !ok {
					return 0, true
				}
				if idx := findTooltipIndex(tt, tool.hwnd, tool.id); idx >= 0 {
					tt.tools[idx] = tool
					return 1, true
				}
				tt.tools = append(tt.tools, tool)
				return 1, true
			case wmUser + 55: // TTM_HITTESTW
				if lParam == 0 {
					return 0, true
				}
				hwndTool, _ := mem.Read64(lParam)
				x, _ := mem.Read32(lParam + 8)
				y, _ := mem.Read32(lParam + 12)
				for _, tool := range tt.tools {
					if hwndTool != 0 && tool.hwnd != hwndTool {
						continue
					}
					if int32(x) >= tool.rect[0] && int32(x) < tool.rect[2] && int32(y) >= tool.rect[1] && int32(y) < tool.rect[3] {
						toolInfo := lParam + 24
						writeToolInfo(toolInfo, tool, true)
						return 1, true
					}
				}
				return 0, true
			case wmUser + 56: // TTM_GETTEXTW
				tool, ok := parseToolInfo(lParam, true)
				if !ok {
					return 0, true
				}
				if idx := findTooltipIndex(tt, tool.hwnd, tool.id); idx >= 0 {
					pszText, _ := mem.Read64(lParam + 48)
					writeGuestUTF16Limited(pszText, tt.tools[idx].text, 260)
					return 1, true
				}
				return 0, true
			case wmUser + 57: // TTM_UPDATETIPTEXTW
				tool, ok := parseToolInfo(lParam, true)
				if !ok {
					return 0, true
				}
				if idx := findTooltipIndex(tt, tool.hwnd, tool.id); idx >= 0 {
					tt.tools[idx].text = tool.text
					return 1, true
				}
				tt.tools = append(tt.tools, tool)
				return 1, true
			case wmUser + 24: // TTM_SETMAXTIPWIDTH
				old := tt.maxWidth
				tt.maxWidth = int32(lParam)
				return uint64(old), true
			case wmUser + 19: // TTM_SETTIPBKCOLOR
				old := tt.bgColor
				tt.bgColor = uint32(wParam)
				return uint64(old), true
			case wmUser + 20: // TTM_SETTIPTEXTCOLOR
				old := tt.textColor
				tt.textColor = uint32(wParam)
				return uint64(old), true
			case wmUser + 34: // TTM_POPUP
				return 0, true
			case wmUser + 7: // TTM_RELAYEVENT
				return 0, true
			case wmUser + 16: // TTM_WINDOWFROMPOINT
				if lParam == 0 {
					return 0, true
				}
				x, _ := mem.Read32(lParam)
				y, _ := mem.Read32(lParam + 4)
				for _, tool := range tt.tools {
					if int32(x) >= tool.rect[0] && int32(x) < tool.rect[2] && int32(y) >= tool.rect[1] && int32(y) < tool.rect[3] {
						return tool.hwnd, true
					}
				}
				return 0, true
			case wmUser + 17: // TTM_TRACKACTIVATE
				tt.active = wParam != 0
				return 0, true
			case wmUser + 18: // TTM_TRACKPOSITION
				return 0, true
			case wmUser + 29: // TTM_UPDATE
				return 0, true
			case wmUser + 58: // TTM_ENUMTOOLSW
				idx := int(int32(wParam))
				if idx >= 0 && idx < len(tt.tools) && lParam != 0 {
					writeToolInfo(lParam, tt.tools[idx], true)
					return 1, true
				}
				return 0, true
			case wmUser + 59: // TTM_GETCURRENTTOOLW
				if len(tt.tools) > 0 && lParam != 0 {
					writeToolInfo(lParam, tt.tools[0], true)
					return 1, true
				}
				return 0, true
			default:
				return 0, true
			}
		}
		return innerBuiltin(hwnd, msg, wParam, lParam)
	}
	hctx.PaintTree = func(parentHwnd uint64) {
		var children []uint64
		for h, cs := range hctx.HwndChildren {
			if cs.parentHWND == parentHwnd && cs.visible {
				children = append(children, h)
			}
		}
		sort.Slice(children, func(i, j int) bool { return children[i] < children[j] })
		for _, h := range children {
			cs := hctx.HwndChildren[h]
			if hctx.WlWindows[h] != nil || (strings.EqualFold(cs.className, "dialog") && cs.parentHWND == hctx.MainHWND) {
				continue
			}
			ravelog.Logf("[paint] paintTree child=0x%x class=%q pos=(%d,%d %dx%d)\n", h, cs.className, cs.x, cs.y, cs.w, cs.h)
			hctx.BuiltinWndProc(h, 0x000F, 0, 0)
			hctx.PaintTree(h)
		}
	}
	hctx.WindowLongPtr = make(map[uint64]map[int32]uint64) // HWND → index → value
	// Per-window properties: SetPropW / GetPropW
	hctx.WindowProps = make(map[uint64]map[string]uint64) // HWND → prop name → value

	// Scratch page for CREATESTRUCT and similar temporary guest-side structs
	hctx.ScratchPage = mem.Mmap(0, 4096, mmu.PermRead|mmu.PermWrite)
	// hctx.ScratchOff: hctx.ScratchOff already zero
	hctx.ScratchAlloc = func(n uint64) uint64 {
		n = (n + 7) &^ 7 // 8-byte align
		if hctx.ScratchOff+n > 4096 {
			hctx.ScratchOff = 0 // wrap
		}
		addr := hctx.ScratchPage + hctx.ScratchOff
		hctx.ScratchOff += n
		return addr
	}

	// Synchronous WndProc dispatch for CreateWindowExW.
	// In real Win32, CreateWindowExW sends WM_NCCREATE/WM_CREATE synchronously
	// before returning the HWND. We implement this with a trampoline vmcall.
	// hctx.SyncStack: hctx.SyncStack already nil

	const syncTrampolineID = 0x3FFE
	// Allocate a trampoline page.
	// Layout:
	//   PE32:
	//     +0  A3 [addr32]          MOV [scratch], EAX
	//     +5  B8 [imm32]           MOV EAX, syncTrampolineID
	//     +10 0F 01 C1             VMCALL
	//     +13 C3                   RET
	//     +14 (4 bytes)            scratch slot
	//   PE64:
	//     +0  48 89 05 0D 00 00 00 MOV [RIP+13], RAX ; save WndProc result at +20
	//     +7  48 83 C4 28          ADD RSP, 0x28     ; release Win64 shadow/alignment space
	//     +11 B8 FE 3F 00 00       MOV EAX, 0x3FFE
	//     +16 0F 01 C1             VMCALL
	//     +19 C3                   RET
	//     +20 (8 bytes)            scratch slot
	hctx.SyncTrampoline = mem.Mmap(0, 4096, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	is32 := procState.Is32
	if is32 {
		// PE32 trampoline layout:
		//   +0  A3 [addr32]          MOV [scratch], EAX  ; save WndProc result
		//   +5  B8 [imm32]           MOV EAX, syncTrampolineID
		//   +10 0F 01 C1             VMCALL
		//   +13 C3                   RET
		//   +14 (4 bytes)            scratch slot for EAX
		scratchAddr := uint32(hctx.SyncTrampoline + 14)
		mem.Write8(hctx.SyncTrampoline+0, 0xA3)
		mem.Write32(hctx.SyncTrampoline+1, scratchAddr)
		mem.Write8(hctx.SyncTrampoline+5, 0xB8) // MOV EAX, imm32
		mem.Write32(hctx.SyncTrampoline+6, syncTrampolineID)
		mem.Write8(hctx.SyncTrampoline+10, 0x0F) // vmcall
		mem.Write8(hctx.SyncTrampoline+11, 0x01)
		mem.Write8(hctx.SyncTrampoline+12, 0xC1)
		mem.Write8(hctx.SyncTrampoline+13, 0xC3) // ret
	} else {
		// x64 trampoline layout:
		//   +0  48 89 05 0D 00 00 00  MOV [RIP+13], RAX ; save WndProc result at +20
		//   +7  48 83 C4 28           ADD RSP, 0x28     ; release Win64 shadow/alignment space
		//   +11 B8 FE 3F 00 00        MOV EAX, 0x3FFE
		//   +16 0F 01 C1              VMCALL
		//   +19 C3                    RET
		//   +20 (8 bytes)             WndProc RAX save slot
		mem.Write8(hctx.SyncTrampoline+0, 0x48)
		mem.Write8(hctx.SyncTrampoline+1, 0x89)
		mem.Write8(hctx.SyncTrampoline+2, 0x05)
		mem.Write32(hctx.SyncTrampoline+3, 13) // RIP-relative offset
		mem.Write8(hctx.SyncTrampoline+7, 0x48)
		mem.Write8(hctx.SyncTrampoline+8, 0x83)
		mem.Write8(hctx.SyncTrampoline+9, 0xC4)
		mem.Write8(hctx.SyncTrampoline+10, 0x28)
		mem.Write8(hctx.SyncTrampoline+11, 0xB8)
		mem.Write32(hctx.SyncTrampoline+12, syncTrampolineID)
		mem.Write8(hctx.SyncTrampoline+16, 0x0F)
		mem.Write8(hctx.SyncTrampoline+17, 0x01)
		mem.Write8(hctx.SyncTrampoline+18, 0xC1)
		mem.Write8(hctx.SyncTrampoline+19, 0xC3)
	}

	// ModalPumpTrampoline stub: same layout as SyncTrampoline but uses
	// modalPumpTrampolineID.  Placed at SyncTrampoline+64 in the same page.
	hctx.ModalPumpTrampoline = hctx.SyncTrampoline + 64
	if is32 {
		scratchAddr2 := uint32(hctx.ModalPumpTrampoline + 14)
		mem.Write8(hctx.ModalPumpTrampoline+0, 0xA3)
		mem.Write32(hctx.ModalPumpTrampoline+1, scratchAddr2)
		mem.Write8(hctx.ModalPumpTrampoline+5, 0xB8)
		mem.Write32(hctx.ModalPumpTrampoline+6, modalPumpTrampolineID)
		mem.Write8(hctx.ModalPumpTrampoline+10, 0x0F)
		mem.Write8(hctx.ModalPumpTrampoline+11, 0x01)
		mem.Write8(hctx.ModalPumpTrampoline+12, 0xC1)
		mem.Write8(hctx.ModalPumpTrampoline+13, 0xC3)
	} else {
		mem.Write8(hctx.ModalPumpTrampoline+0, 0x48)
		mem.Write8(hctx.ModalPumpTrampoline+1, 0x89)
		mem.Write8(hctx.ModalPumpTrampoline+2, 0x05)
		mem.Write32(hctx.ModalPumpTrampoline+3, 13)
		mem.Write8(hctx.ModalPumpTrampoline+7, 0x48)
		mem.Write8(hctx.ModalPumpTrampoline+8, 0x83)
		mem.Write8(hctx.ModalPumpTrampoline+9, 0xC4)
		mem.Write8(hctx.ModalPumpTrampoline+10, 0x28)
		mem.Write8(hctx.ModalPumpTrampoline+11, 0xB8)
		mem.Write32(hctx.ModalPumpTrampoline+12, modalPumpTrampolineID)
		mem.Write8(hctx.ModalPumpTrampoline+16, 0x0F)
		mem.Write8(hctx.ModalPumpTrampoline+17, 0x01)
		mem.Write8(hctx.ModalPumpTrampoline+18, 0xC1)
		mem.Write8(hctx.ModalPumpTrampoline+19, 0xC3)
	}

	// on stack) and PE32+ (x64 fastcall in registers). It pushes a return
	// address (retAddr) so the WndProc RET returns there.
	syncSetupWndProcCall := func(ctx *ntapi.TrapContext, wndProc, hwnd uint64, msg uint32, wParam, lParam, retAddr uint64) {
		rw := ctx.CPU.(ntapi.RegisterWriter)
		rr := ctx.CPU.(ntapi.RegisterReader)
		if is32 {
			// PE32 stdcall: push args right-to-left, then retAddr
			rsp := rr.ReadReg(4)
			rsp -= 4
			mem.Write32(rsp, uint32(lParam))
			rsp -= 4
			mem.Write32(rsp, uint32(wParam))
			rsp -= 4
			mem.Write32(rsp, msg)
			rsp -= 4
			mem.Write32(rsp, uint32(hwnd))
			rsp -= 4
			mem.Write32(rsp, uint32(retAddr))
			rw.WriteReg(4, rsp)
		} else {
			rsp := rr.ReadReg(4)
			// Win64 requires 32 bytes of shadow space plus 8 bytes to keep the
			// callee entry stack aligned like a normal CALL would.
			rsp -= 48
			mem.Write64(rsp, retAddr)
			rw.WriteReg(4, rsp)
			rw.WriteReg(1, hwnd)
			rw.WriteReg(2, uint64(msg))
			rw.WriteReg(8, wParam)
			rw.WriteReg(9, lParam)
		}
		// Injected WndProc dispatches set PCRedirected, so ntapi.Handle skips its
		// own callee-saved-register restore and delegates it to the trampoline's
		// per-frame restore. A non-ABI-compliant guest WndProc (e.g. kkrieger's,
		// which leaves EBX != 0 after DirectSound setup in WM_CREATE) would then
		// leak a clobbered EBX/EBP/ESI/EDI back into the interrupted caller (the
		// message pump), breaking it. Capture the caller's pristine callee-saved
		// registers into the top sync frame on the FIRST dispatch (before any
		// WndProc runs) so the trampoline can restore them on frame pop. Only the
		// first setup saves; re-dispatch of queued messages sees hasSavedCalleeRegs
		// already set and leaves the pristine snapshot intact. Handlers that set
		// hasSavedCalleeRegs explicitly (CreateWindowExA) are likewise preserved.
		if is32 {
			syncStack := hctx.syncStack(ctx)
			if n := len(*syncStack); n > 0 {
				if f := &(*syncStack)[n-1]; !f.hasSavedCalleeRegs {
					f.savedCalleeRegs = [4]uint64{rr.ReadReg(3), rr.ReadReg(5), rr.ReadReg(6), rr.ReadReg(7)} // EBX,EBP,ESI,EDI
					f.hasSavedCalleeRegs = true
				}
			}
		}
		ctx.CPU.SetPC(wndProc)
		ctx.ReturnOverridden = true
		ctx.PCRedirected = true
	}
	hctx.SyncCallWndProc = syncSetupWndProcCall

	d.RegisterHandler(syncTrampolineID, "syncDispatchTrampoline", func(ctx *ntapi.TrapContext) uint32 {
		rw, ok := ctx.CPU.(ntapi.RegisterWriter)
		if !ok {
			return 0
		}
		rr, ok2 := ctx.CPU.(ntapi.RegisterReader)
		if !ok2 {
			return 0
		}
		syncStack := hctx.syncStack(ctx)
		if len(*syncStack) == 0 {
			return 0
		}
		frame := &(*syncStack)[len(*syncStack)-1]

		if len(frame.queue) > 0 {
			sd := frame.queue[0]
			frame.queue = frame.queue[1:]
			syncSetupWndProcCall(ctx, sd.wndProc, sd.hwnd, uint32(sd.msg), sd.wParam, sd.lParam, hctx.SyncTrampoline)
			return 0
		}

		// Queue empty: all sync dispatches done. Pop frame and return.
		retAddr := frame.retAddr
		hwnd := frame.hwnd
		returnWndProcResult := frame.returnWndProcResult
		isModal := frame.IsModalDialog
		modalDlgHwnd := frame.ModalDlgHwnd
		modalLoopSP := frame.ModalLoopSP
		modalLoopPC := frame.ModalLoopPC
		// Restore the caller's callee-saved registers around an injected
		// WndProc dispatch so it is transparent to the guest (see the
		// syncDispatchFrame comment). Only for frames that captured them.
		if frame.hasSavedCalleeRegs {
			rw.WriteReg(3, frame.savedCalleeRegs[0]) // EBX
			rw.WriteReg(5, frame.savedCalleeRegs[1]) // EBP
			rw.WriteReg(6, frame.savedCalleeRegs[2]) // ESI
			rw.WriteReg(7, frame.savedCalleeRegs[3]) // EDI
		}
		*syncStack = (*syncStack)[:len(*syncStack)-1]

		if isModal {
			if hctx.FinishModalDialog != nil && hctx.FinishModalDialog(ctx, modalDlgHwnd) {
				return 0
			}
			if modalLoopSP == 0 || modalLoopPC == 0 {
				modalLoopSP = msgLoopSP
				modalLoopPC = msgLoopPC
			}
			if modalLoopSP != 0 && modalLoopPC != 0 {
				if is32 {
					rsp := modalLoopSP - 4
					mem.Write32(rsp, uint32(modalLoopPC))
					rw.WriteReg(4, rsp)
				} else {
					rsp := modalLoopSP - 8
					mem.Write64(rsp, modalLoopPC)
					rw.WriteReg(4, rsp)
				}
				ctx.SetReturn(0)
				return 0
			}
		}

		rsp := rr.ReadReg(4)
		if is32 {
			rsp -= 4
			mem.Write32(rsp, uint32(retAddr))
		} else {
			mem.Write64(rsp, retAddr)
		}
		rw.WriteReg(4, rsp)
		if returnWndProcResult {
			if is32 {
				saved, _ := mem.Read32(hctx.SyncTrampoline + 14)
				ctx.SetReturn(uint64(saved))
			} else {
				saved, _ := mem.Read64(hctx.SyncTrampoline + 20)
				ctx.SetReturn(saved)
			}
		} else {
			ctx.SetReturn(hwnd)
		}
		return 0
	})

	// --- user32.dll ---
	delayReg(func() { registerUser32Handlers(hctx) })

	// --- gdi32.dll ---
	delayReg(func() { registerGdi32Handlers(hctx) })

	// --- win32u.dll ---
	delayReg(func() { registerWin32UHandlers(hctx) })

	// --- gdiplus.dll ---
	delayReg(func() { registerGdiplusHandlers(hctx) })

	// --- crypt32.dll ---
	delayReg(func() { registerCrypt32Handlers(hctx) })

	// --- advapi32.dll ---
	delayReg(func() { registerAdvapi32Handlers2(hctx) })

	// --- uxtheme.dll ---
	delayReg(func() { registerUxthemeHandlers(hctx) })

	// --- mpr.dll ---
	delayReg(func() { registerMprHandlers(hctx) })

	// --- ws2_32.dll ---
	delayReg(func() { registerWs2Handlers(hctx) })

	// --- iphlpapi.dll ---
	delayReg(func() { registerIphlpapiHandlers(hctx) })

	// --- imm32.dll ---
	delayReg(func() { registerImm32Handlers(hctx) })

	// --- sensapi.dll ---
	delayReg(func() { registerSensapiHandlers(hctx) })

	// --- dwmapi.dll ---
	delayReg(func() { registerDwmapiHandlers(hctx) })

	// --- dbghelp.dll / version.dll / imagehlp.dll ---
	delayReg(func() { registerDbghelpHandlers(hctx) })

	// --- wintrust.dll ---
	delayReg(func() { registerWintrustHandlers(hctx) })

	// --- wininet.dll ---
	delayReg(func() { registerWininetHandlers(hctx) })

	// --- winhttp.dll ---
	delayReg(func() { registerWinhttpHandlers(hctx) })

	// --- winmm.dll ---
	delayReg(func() { registerWinmmHandlers(hctx) })

	// --- dsound.dll ---
	delayReg(func() { registerDsoundHandlers(hctx) })

	// --- Media Foundation ---
	delayReg(func() { registerMediaFoundationHandlers(hctx) })

	// --- dinput8.dll ---
	delayReg(func() { registerDinputHandlers(hctx) })

	// --- msimg32.dll ---
	delayReg(func() { registerMsimg32Handlers(hctx) })

	// --- msi.dll ---
	delayReg(func() { registerMsiHandlers(hctx) })

	// --- psapi.dll ---
	delayReg(func() { registerPsapiHandlers(hctx) })

	// --- userenv.dll ---
	delayReg(func() { registerUserenvHandlers(hctx) })

	// --- secur32.dll ---
	delayReg(func() { registerSecur32Handlers(hctx) })

	// --- setupapi.dll ---
	delayReg(func() { registerSetupapiHandlers(hctx) })

	// --- netapi32.dll ---
	delayReg(func() { registerNetapi32Handlers(hctx) })

	// --- powrprof.dll ---
	delayReg(func() { registerPowrprofHandlers(hctx) })

	// --- wtsapi32.dll ---
	delayReg(func() { registerWtsapi32Handlers(hctx) })

	// --- normaliz.dll ---
	delayReg(func() { registerNormalizHandlers(hctx) })

	// --- bcrypt.dll ---
	delayReg(func() { registerBcryptHandlers(hctx) })

	// --- cabinet.dll ---
	delayReg(func() { registerCabinetHandlers(hctx) })

	// --- d3d9.dll / d3d11.dll / d3d12.dll / dxgi.dll ---
	delayReg(func() { registerD3dHandlers(hctx) })
	// --- opengl32.dll ---
	delayReg(func() { registerOpengl32Handlers(hctx) })
	return hctx
}

// autoSynthUnresolved generates synthetic stub DLLs for any DLLs referenced
// in the main module's imports that aren't already in loadedModules.
// Returns the synths and a map of alias→canonical DLL names (for IAT patching).
func autoSynthUnresolved(mem *mmu.MMU, mainMod *loader.PEModule, loaded map[string]*loader.PEModule) ([]*ntapi.SynthPE, map[string]string) {
	// Canonicalize api-ms-win-crt-* and api-ms-win-core-* to their real DLLs so
	// all their functions share a single SynthPE and a single set of handler IDs.
	// Without this, each forwarding DLL gets its own unique stub IDs, making it
	// impossible to register handlers in one place for both ucrtbase.dll and
	// api-ms-win-crt-runtime-l1-1-0.dll (etc.).
	canonicalize := func(name string) string {
		switch {
		case strings.HasPrefix(name, "api-ms-win-crt-"):
			return "ucrtbase.dll"
		case strings.HasPrefix(name, "api-ms-win-core-"):
			return "kernel32.dll"
		case strings.HasPrefix(name, "api-ms-win-security-"):
			return "advapi32.dll"
		case strings.HasPrefix(name, "api-ms-win-shcore-"):
			return "shcore.dll"
		case name == "kernelbase.dll":
			return "kernel32.dll"
		default:
			return name
		}
	}

	aliases := make(map[string]string)  // original name → canonical name
	needed := make(map[string][]string) // canonical dll name → function names
	for _, imp := range mainMod.Imports {
		dllKey := strings.ToLower(imp.DLLName)
		if _, ok := loaded[dllKey]; ok {
			continue
		}
		if _, ok := loaded[strings.TrimSuffix(dllKey, ".dll")]; ok {
			continue
		}
		canonical := canonicalize(dllKey)
		if canonical != dllKey {
			aliases[dllKey] = canonical
			// If the canonical DLL is already loaded, we only need the alias.
			if _, ok := loaded[canonical]; ok {
				continue
			}
		}
		if imp.FuncName != "" {
			needed[canonical] = append(needed[canonical], imp.FuncName)
		} else {
			// Ordinal-only import: use a generated placeholder so the DLL gets a synth
			placeholder := fmt.Sprintf("ord_%d", imp.Ordinal)
			needed[canonical] = append(needed[canonical], placeholder)
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
	return result, aliases
}

// patchCRTDataExports fixes IAT slots for known msvcrt data exports.
// These are variables (not functions) whose IAT slots must point to
// actual guest memory containing the proper values.
func patchCRTDataExports(mem *mmu.MMU, mainMod *loader.PEModule, argv []string) {
	cmdLine := windowsCommandLine(argv)

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

	// _acmdln: pointer to the command line string (4-byte for PE32, 8-byte for PE64)
	if mainMod.Is64 {
		mem.Write64(dataPage+0x200, dataPage+0x000)
	} else {
		mem.Write32(dataPage+0x200, uint32(dataPage+0x000))
	}

	// _commode: 0
	mem.Write32(dataPage+0x208, 0)

	// _fmode: 0
	mem.Write32(dataPage+0x210, 0)

	// __initenv: null pointer (4-byte for PE32, 8-byte for PE64)
	if mainMod.Is64 {
		mem.Write64(dataPage+0x218, 0)
	}

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
			if mainMod.Is64 {
				mem.Write64Raw(imp.IATSlot, addr)
			} else {
				mem.Write32Raw(imp.IATSlot, uint32(addr))
			}
		}
	}
}

// patchUnresolvedOrdinals finds imports that are still pointing at the
// unresolved-sentinel address and replaces each IAT slot with a tiny vmcall
// trampoline that logs the call and returns 0.  This covers ordinal-only
// imports (e.g. COMCTL32 FlatSB ordinals) that no synthetic DLL exposes.
func patchUnresolvedOrdinals(mem *mmu.MMU, d *ntapi.Dispatcher, mainMod *loader.PEModule) {
	// ID range reserved for ordinal stubs - well above auto-synth (0x2000+)
	const ordinalIDBase = uint32(0xF000)
	const stubBytes = 9 // B8 xx xx xx xx | 0F 01 C1 | C3

	// Collect unresolved entries
	var unresolved []loader.PEImportEntry
	unresolvedSentinel64 := uint64(0xDEAD_DEAD_0001_0000)
	unresolvedSentinel32 := uint32(0xDEAD0000)
	for _, imp := range mainMod.Imports {
		if mainMod.Is64 {
			v, _ := mem.Read64(imp.IATSlot)
			if v == unresolvedSentinel64 {
				unresolved = append(unresolved, imp)
			}
		} else {
			v, _ := mem.Read32(imp.IATSlot)
			if v == unresolvedSentinel32 {
				unresolved = append(unresolved, imp)
			}
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

		if mainMod.Is64 {
			mem.Write64Raw(imp.IATSlot, stubAddr)
		} else {
			mem.Write32Raw(imp.IATSlot, uint32(stubAddr))
		}
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
		// User-provided system layout: <sysroot>/Windows/System32 (matches
		// the Fonts loader, which reads <sysroot>/Windows/Fonts).
		filepath.Join(sysroot, "Windows", "System32", name),
		filepath.Join(sysroot, "Windows", "system32", name),
		filepath.Join(sysroot, "Windows", "SysWOW64", name),
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
			0x48, 0x31, 0xC0, // xor rax, rax
			0x66, 0x83, 0x3C, 0x41, 0x00, // cmp word [rcx+rax*2], 0
			0x74, 0x04, // je +4 (.done)
			0x48, 0xFF, 0xC0, // inc rax
			0xEB, 0xF5, // jmp -11 (.loop)
			0xC3, // ret
		})

		// strlen(RCX): scan for 0 byte, return count in RAX
		synth.PatchStub(mem, "strlen", []byte{
			0x48, 0x31, 0xC0, // xor rax, rax
			0x80, 0x3C, 0x01, 0x00, // cmp byte [rcx+rax], 0
			0x74, 0x04, // je +4 (.done)
			0x48, 0xFF, 0xC0, // inc rax
			0xEB, 0xF6, // jmp -10 (.loop)
			0xC3, // ret
		})

		// memset(RCX=dst, EDX=val, R8=count): fill and return dst in RAX
		synth.PatchStub(mem, "memset", []byte{
			0x48, 0x89, 0xC8, // mov rax, rcx  (save dst for return)
			0x4D, 0x85, 0xC0, // test r8, r8
			0x74, 0x07, // je .done
			0x88, 0x11, // mov [rcx], dl
			0x48, 0xFF, 0xC1, // inc rcx
			0x49, 0xFF, 0xC8, // dec r8
			0xEB, 0xF5, // jmp .loop
			0xC3, // ret
		})

		// memcpy(RCX=dst, RDX=src, R8=count): copy and return dst in RAX
		synth.PatchStub(mem, "memcpy", []byte{
			0x48, 0x89, 0xC8, // mov rax, rcx
			0x4D, 0x85, 0xC0, // test r8, r8
			0x74, 0x09, // je .done
			0x44, 0x8A, 0x0A, // mov r9b, [rdx]
			0x44, 0x88, 0x09, // mov [rcx], r9b
			0x48, 0xFF, 0xC1, // inc rcx
			0x48, 0xFF, 0xC2, // inc rdx
			0x49, 0xFF, 0xC8, // dec r8
			0xEB, 0xF1, // jmp .loop
			0xC3, // ret
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

func preparePEGuestArgs(fs *vfs.VFS, imagePath string, argv []string) ([]string, map[string]string) {
	imageDir := filepath.Base(filepath.Dir(imagePath))
	guestArgs := make([]string, len(argv))
	hostPaths := make(map[string]string)
	if len(argv) == 0 {
		return guestArgs, hostPaths
	}
	guestArgs[0] = `C:\` + imageDir + `\` + filepath.Base(imagePath)
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		if strings.Contains(arg, `\`) || len(arg) >= 2 && arg[1] == ':' {
			guestArgs[i] = arg
			continue
		}
		hostPath, err := filepath.Abs(arg)
		if err != nil {
			guestArgs[i] = arg
			continue
		}
		info, err := os.Stat(hostPath)
		if err != nil || info.IsDir() {
			guestArgs[i] = arg
			continue
		}
		data, err := os.ReadFile(hostPath)
		if err != nil {
			guestArgs[i] = arg
			continue
		}
		guestPath := linuxToWinPath(hostPath)
		vfsPath := winPathToVFS(guestPath)
		fs.MkdirAll(filepath.Dir(vfsPath))
		if err := fs.CreateFile(vfsPath, data, 0644); err != nil {
			guestArgs[i] = arg
			continue
		}
		guestArgs[i] = guestPath
		hostPaths[vfsPath] = hostPath
	}
	return guestArgs, hostPaths
}

func windowsCommandLine(argv []string) string {
	quoted := make([]string, len(argv))
	for i, arg := range argv {
		if arg != "" && !strings.ContainsAny(arg, " \t\"") {
			quoted[i] = arg
			continue
		}
		var value strings.Builder
		value.WriteByte('"')
		backslashes := 0
		for _, ch := range arg {
			if ch == '\\' {
				backslashes++
				continue
			}
			if ch == '"' {
				value.WriteString(strings.Repeat(`\`, backslashes*2+1))
				value.WriteRune(ch)
				backslashes = 0
				continue
			}
			value.WriteString(strings.Repeat(`\`, backslashes))
			backslashes = 0
			value.WriteRune(ch)
		}
		value.WriteString(strings.Repeat(`\`, backslashes*2))
		value.WriteByte('"')
		quoted[i] = value.String()
	}
	return strings.Join(quoted, " ")
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
	// Collapse consecutive slashes (e.g. from "C:\Temp\" + "\file.exe")
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	return p
}

func windowsFileMatch(pattern, name string) bool {
	pattern = strings.ToLower(pattern)
	name = strings.ToLower(name)
	if pattern == "*" || pattern == "*.*" {
		return true
	}
	matched, err := filepath.Match(pattern, name)
	return err == nil && matched
}

// normalizePipeName strips the \\.\pipe\ prefix (case-insensitive) from a pipe path.
func normalizePipeName(name string) string {
	norm := strings.ReplaceAll(name, `\`, "/")
	for _, prefix := range []string{"//./pipe/", "//./Pipe/", "//./PIPE/"} {
		if strings.HasPrefix(norm, prefix) {
			return norm[len(prefix):]
		}
	}
	// Also handle original backslash variants
	for _, prefix := range []string{`\\.\pipe\`, `\\.\Pipe\`, `\\.\PIPE\`} {
		if strings.HasPrefix(name, prefix) {
			return name[len(prefix):]
		}
	}
	return name
}

// isPipePath returns true if name is a Windows named pipe path.
func isPipePath(name string) bool {
	norm := strings.ToLower(strings.ReplaceAll(name, `\`, "/"))
	return strings.HasPrefix(norm, "//./pipe/")
}

// msToTimeout converts a Win32 millisecond timeout to a Go duration.
// 0xFFFFFFFF = INFINITE (-1), 0 = poll (0).
func msToTimeout(ms uint64) time.Duration {
	if ms == 0xFFFFFFFF {
		return -1
	}
	return time.Duration(ms) * time.Millisecond
}

// waitOneWin32 waits on a single handle; returns Win32 WAIT_* value.
func waitOneWin32(handles *ntapi.HandleTable, h ntapi.Handle, tid uint32, timeout time.Duration) uint64 {
	const waitObject0 = uint64(0)
	const waitTimeout = uint64(0x102)
	const waitAbandoned = uint64(0x80)
	obj := handles.Get(h)
	switch v := obj.(type) {
	case *ntapi.EventHandle:
		if v.WaitTimeout(timeout) {
			return waitObject0
		}
		return waitTimeout
	case *ntapi.MutantHandle:
		res := v.WaitTimeout(tid, timeout)
		if res == 0x80 {
			return waitAbandoned
		}
		if res == 0 {
			return waitObject0
		}
		return waitTimeout
	case *ntapi.SemaphoreHandle:
		if v.WaitTimeout(timeout) == 0 {
			return waitObject0
		}
		return waitTimeout
	case *ntapi.WaitableTimerHandle:
		if v.WaitTimeout(timeout) == 0 {
			return waitObject0
		}
		return waitTimeout
	case *ntapi.ThreadHandle:
		if v.Done == nil {
			return waitObject0
		}
		if timeout < 0 {
			<-v.Done
			return waitObject0
		}
		if timeout == 0 {
			select {
			case <-v.Done:
				return waitObject0
			default:
				return waitTimeout
			}
		}
		select {
		case <-v.Done:
			return waitObject0
		case <-time.After(timeout):
			return waitTimeout
		}
	case nil:
		// Unknown or process handle - signal immediately
		return waitObject0
	default:
		return waitObject0
	}
}

func readWin32HandleArray(mem *mmu.MMU, address, count uint64, is32 bool) []ntapi.Handle {
	if count > 64 {
		count = 64
	}
	result := make([]ntapi.Handle, 0, count)
	stride := uint64(8)
	if is32 {
		stride = 4
	}
	for index := uint64(0); index < count; index++ {
		if is32 {
			value, err := mem.Read32(address + index*stride)
			if err != nil {
				return nil
			}
			result = append(result, ntapi.Handle(value))
			continue
		}
		value, err := mem.Read64(address + index*stride)
		if err != nil {
			return nil
		}
		result = append(result, ntapi.Handle(value))
	}
	return result
}

func waitMultipleFallbackWin32(handles *ntapi.HandleTable, values []ntapi.Handle, tid uint32, waitAll bool, timeout time.Duration) uint64 {
	const (
		waitObject0    = uint64(0)
		waitAbandoned0 = uint64(0x80)
		waitTimeout    = uint64(0x102)
		waitFailed     = uint64(0xFFFFFFFF)
	)
	if len(values) == 0 {
		return waitFailed
	}
	waitables := make([]ntobj.Waitable, 0, len(values))
	nonUnified := make([]ntapi.Handle, 0, len(values))
	for _, handle := range values {
		waitable := handles.WaitableFor(handle)
		if waitable == nil {
			nonUnified = append(nonUnified, handle)
			continue
		}
		waitables = append(waitables, waitable)
	}
	if len(nonUnified) == 0 {
		return uint64(ntapi.ObjMgr.Wait(waitables, waitAll, uint64(tid), timeout))
	}
	deadline := time.Time{}
	if timeout >= 0 {
		deadline = time.Now().Add(timeout)
	}
	remaining := func() time.Duration {
		if timeout < 0 {
			return -1
		}
		value := time.Until(deadline)
		if value < 0 {
			return 0
		}
		return value
	}
	if waitAll {
		for _, handle := range nonUnified {
			result := waitOneWin32(handles, handle, tid, remaining())
			if result != waitObject0 {
				return result
			}
		}
		if len(waitables) > 0 {
			return uint64(ntapi.ObjMgr.Wait(waitables, true, uint64(tid), remaining()))
		}
		return waitObject0
	}
	for {
		for index, handle := range values {
			switch result := waitOneWin32(handles, handle, tid, 0); result {
			case waitObject0:
				return waitObject0 + uint64(index)
			case waitAbandoned0:
				return waitAbandoned0 + uint64(index)
			}
		}
		if timeout >= 0 && !time.Now().Before(deadline) {
			return waitTimeout
		}
		sleep := time.Millisecond
		if timeout >= 0 && remaining() < sleep {
			sleep = remaining()
		}
		if sleep > 0 {
			time.Sleep(sleep)
		}
	}
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

// writeFindDataA writes a WIN32_FIND_DATAA struct (ANSI filenames).
func writeFindDataA(m *mmu.MMU, ptr uint64, dir string, e os.DirEntry) {
	var attrs uint32 = 0x20 // FILE_ATTRIBUTE_NORMAL
	if e.IsDir() {
		attrs = 0x10
	}
	m.Write32(ptr+0, attrs)
	info, err := e.Info()
	if err == nil {
		const epochDiff = int64(11644473600)
		ft := uint64(info.ModTime().Unix()+epochDiff) * 10000000
		m.Write64Raw(ptr+4, ft)
		m.Write64Raw(ptr+12, ft)
		m.Write64Raw(ptr+20, ft)
		if !e.IsDir() {
			sz := info.Size()
			m.Write32(ptr+28, uint32(sz>>32))
			m.Write32(ptr+32, uint32(sz))
		}
	}
	// WIN32_FIND_DATAA: cFileName at +44 is char[260], cAlternateFileName at +304 is char[14]
	name := e.Name()
	for i := 0; i < len(name) && i < 259; i++ {
		m.Write8(ptr+44+uint64(i), name[i])
	}
	if len(name) < 260 {
		m.Write8(ptr+44+uint64(len(name)), 0)
	}
}

// saveScreenshot saves the XRGB8888 wl.Window pixel buffer as a PNG.
// Encodes to a buffer first then writes atomically to avoid truncation on SIGTERM.
func saveScreenshot(pix []byte, w, h int, path string) {
	ravelog.Logf("[ss] saveScreenshot w=%d h=%d pixLen=%d path=%s\n", w, h, len(pix), path)
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			off := (y*w + x) * 4
			if off+3 >= len(pix) {
				break
			}
			b := pix[off+0]
			g := pix[off+1]
			r := pix[off+2]
			img.SetRGBA(x, y, color.RGBA{R: r, G: g, B: b, A: 0xFF})
		}
	}
	var buf bytes.Buffer
	err2 := png.Encode(&buf, img)
	ravelog.Logf("[ss] png.Encode err=%v size=%d\n", err2, buf.Len())
	if err2 != nil {
		return
	}
	os.WriteFile(path, buf.Bytes(), 0644)
}

// drawFindDialogWindow renders the modeless Find/Replace dialog.
func drawFindDialogWindow(hctx *HandlerCtx, w *wl.Window) {
	fd := hctx.FindDialog
	if fd == nil || w == nil {
		return
	}
	const (
		dlgW        = int32(380)
		dlgHFind    = int32(130)
		dlgHReplace = int32(160)
		pad         = int32(8)
	)
	dlgH := dlgHFind
	if fd.IsReplace {
		dlgH = dlgHReplace
	}
	x := int32(0)
	y := int32(0)
	fd.X, fd.Y, fd.W, fd.H = x, y, dlgW, dlgH

	// Dialog background & border
	w.DrawRectAbs(x, y, x+dlgW, y+dlgH, 0xF0F0F0)
	w.DrawRectAbs(x, y, x+dlgW, y+1, 0x808080)
	w.DrawRectAbs(x, y, x+1, y+dlgH, 0x808080)
	w.DrawRectAbs(x, y+dlgH-1, x+dlgW, y+dlgH, 0x808080)
	w.DrawRectAbs(x+dlgW-1, y, x+dlgW, y+dlgH, 0x808080)

	row := y + pad

	// "Find what:" label + edit field
	w.DrawTextAbs(x+pad, row+3, "Find what:", 0x000000, 0xF0F0F0, true)
	editX := x + pad + 76
	editW := dlgW - pad - 76 - 90 - pad
	editH := int32(20)
	w.DrawRectAbs(editX, row, editX+editW, row+editH, 0xFFFFFF)
	w.DrawRectAbs(editX, row, editX+editW, row+1, 0x808080)
	w.DrawRectAbs(editX, row, editX+1, row+editH, 0x808080)
	w.DrawRectAbs(editX, row+editH-1, editX+editW, row+editH, 0x808080)
	w.DrawRectAbs(editX+editW-1, row, editX+editW, row+editH, 0x808080)
	findDisplay := fd.FindText
	if !fd.FocusOnReplace {
		findDisplay += "_" // cursor indicator
	}
	w.DrawTextAbs(editX+3, row+3, findDisplay, 0x000000, 0xFFFFFF, true)
	fd.FindEditX, fd.FindEditY, fd.FindEditW, fd.FindEditH = editX, row, editW, editH

	row += editH + pad

	// "Replace with:" label + edit field (Replace dialog only)
	if fd.IsReplace {
		w.DrawTextAbs(x+pad, row+3, "Replace with:", 0x000000, 0xF0F0F0, true)
		replEditX := x + pad + 90
		replEditW := dlgW - pad - 90 - 90 - pad
		w.DrawRectAbs(replEditX, row, replEditX+replEditW, row+editH, 0xFFFFFF)
		w.DrawRectAbs(replEditX, row, replEditX+replEditW, row+1, 0x808080)
		w.DrawRectAbs(replEditX, row, replEditX+1, row+editH, 0x808080)
		w.DrawRectAbs(replEditX, row+editH-1, replEditX+replEditW, row+editH, 0x808080)
		w.DrawRectAbs(replEditX+replEditW-1, row, replEditX+replEditW, row+editH, 0x808080)
		replDisplay := fd.ReplaceText
		if fd.FocusOnReplace {
			replDisplay += "_"
		}
		w.DrawTextAbs(replEditX+3, row+3, replDisplay, 0x000000, 0xFFFFFF, true)
		fd.ReplEditX, fd.ReplEditY, fd.ReplEditW, fd.ReplEditH = replEditX, row, replEditW, editH
		row += editH + pad
	}

	// Buttons (right-aligned column)
	const btnW, btnH = int32(82), int32(24)
	btnX := x + dlgW - btnW - pad

	drawBtn := func(bx, by int32, label string) {
		w.DrawRectAbs(bx, by, bx+btnW, by+btnH, 0xE1E1E1)
		w.DrawRectAbs(bx, by, bx+btnW, by+1, 0xADADAD)
		w.DrawRectAbs(bx, by, bx+1, by+btnH, 0xADADAD)
		w.DrawRectAbs(bx, by+btnH-1, bx+btnW, by+btnH, 0xADADAD)
		w.DrawRectAbs(bx+btnW-1, by, bx+btnW, by+btnH, 0xADADAD)
		// Center label
		labelX := bx + (btnW-int32(len(label))*6)/2
		if labelX < bx+4 {
			labelX = bx + 4
		}
		w.DrawTextAbs(labelX, by+5, label, 0x000000, 0xE1E1E1, true)
	}

	btnRow := y + pad
	drawBtn(btnX, btnRow, "Find Next")
	fd.FindNextBtnX, fd.FindNextBtnY, fd.FindNextBtnW, fd.FindNextBtnH = btnX, btnRow, btnW, btnH
	btnRow += btnH + 4

	if fd.IsReplace {
		drawBtn(btnX, btnRow, "Replace")
		fd.ReplaceBtnX, fd.ReplaceBtnY, fd.ReplaceBtnW, fd.ReplaceBtnH = btnX, btnRow, btnW, btnH
		btnRow += btnH + 4
		drawBtn(btnX, btnRow, "Replace All")
		fd.ReplAllBtnX, fd.ReplAllBtnY, fd.ReplAllBtnW, fd.ReplAllBtnH = btnX, btnRow, btnW, btnH
		btnRow += btnH + 4
	}

	drawBtn(btnX, btnRow, "Cancel")
	fd.CancelBtnX, fd.CancelBtnY, fd.CancelBtnW, fd.CancelBtnH = btnX, btnRow, btnW, btnH
}

// doCallExport implements the DLL export check (-call-export): it runs
// the main module's DllMain (if it is a DLL) and then synchronously invokes a
// named export with the given arguments, printing its return value. It proves
// the loader + emulator + ntdll can execute real, non-synthetic DLL code
// end-to-end. Spec form: "exportName" or "exportName:arg0,arg1,..." (args parse
// as Go integer literals, e.g. 2, 0x2A, -5). Exit code 0 on a successful call.
func doCallExport(c arch.CPU, mem *mmu.MMU, mod *loader.PEModule, spec string, trace bool) {
	tramp := ntapi.AllocTrampoline(mem)

	// Initialize the DLL (DLL_PROCESS_ATTACH) before calling into it.
	if mod.IsDLL && mod.EntryPoint != 0 && mod.EntryPoint != mod.BaseAddr {
		ravelog.Logf("[call-export] running DllMain at 0x%x\n", mod.EntryPoint)
		if err := ntapi.CallDllMain(c, mem, tramp, mod.BaseAddr, mod.EntryPoint, trace); err != nil {
			fmt.Fprintf(os.Stderr, "[call-export] DllMain failed: %v\n", err)
			os.Exit(3)
		}
	}

	name := spec
	var args []uint64
	if i := strings.IndexByte(spec, ':'); i >= 0 {
		name = spec[:i]
		for _, a := range strings.Split(spec[i+1:], ",") {
			a = strings.TrimSpace(a)
			if a == "" {
				continue
			}
			v, err := strconv.ParseInt(a, 0, 64)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[call-export] bad argument %q: %v\n", a, err)
				os.Exit(2)
			}
			args = append(args, uint64(v))
		}
	}

	addr, ok := mod.Exports[name]
	if !ok || addr == 0 {
		fmt.Fprintf(os.Stderr, "[call-export] export %q not found in %s (%d exports available)\n",
			name, mod.Name, len(mod.Exports))
		os.Exit(4)
	}

	ravelog.Logf("[call-export] calling %s @0x%x with %v\n", name, addr, args)
	ret, err := ntapi.CallGuestFunction(c, mem, tramp, addr, args, trace)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[call-export] call to %s failed: %v\n", name, err)
		os.Exit(5)
	}
	// Exports here return a 32-bit int in EAX; show signed-decimal and hex.
	fmt.Printf("[call-export] %s => %d (0x%x)\n", name, int64(int32(uint32(ret))), ret)
}

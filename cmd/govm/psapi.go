package main

import (
	ravelog "github.com/mirkobrombin/Raven/pkg/log"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

func registerPsapiHandlers(hctx *HandlerCtx) {
	d := hctx.Disp
	dll, ok := hctx.SynthByName["psapi.dll"]
	if !ok {
		return
	}
	_ = dll

	d.RegisterAutoStubHandler(dll, "EmptyWorkingSet", func(ctx *ntapi.TrapContext) uint32 {
		hProcess := ctx.Arg(0)
		ravelog.Logf("[psapi] EmptyWorkingSet proc=0x%x\n", hProcess)
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "EnumDeviceDrivers", func(ctx *ntapi.TrapContext) uint32 {
		lpImageBase := ctx.Arg(0)
		cb := ctx.Arg(1)
		lpcbNeeded := ctx.Arg(2)
		ravelog.Logf("[psapi] EnumDeviceDrivers buf=0x%x size=%d\n", lpImageBase, cb)
		if lpcbNeeded != 0 { ctx.Mem.Write32(lpcbNeeded, 0) } // no drivers
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "EnumPageFilesA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[psapi] EnumPageFilesA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "EnumPageFilesW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[psapi] EnumPageFilesW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "EnumProcessModules", func(ctx *ntapi.TrapContext) uint32 {
		hProcess := ctx.Arg(0)
		lphModule := ctx.Arg(1)
		cb := ctx.Arg(2)
		lpcbNeeded := ctx.Arg(3)
		ravelog.Logf("[psapi] EnumProcessModules proc=0x%x buf=0x%x size=%d\n", hProcess, lphModule, cb)
		// Return one fake module handle
		if lphModule != 0 && cb >= 8 { ctx.Mem.Write64(lphModule, 0x00400000) } // base addr
		if lpcbNeeded != 0 { ctx.Mem.Write32(lpcbNeeded, 8) } // 1 module * 8 bytes
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "EnumProcesses", func(ctx *ntapi.TrapContext) uint32 {
		lpidProcess := ctx.Arg(0)
		cb := ctx.Arg(1)
		lpcbNeeded := ctx.Arg(2)
		ravelog.Logf("[psapi] EnumProcesses buf=0x%x size=%d\n", lpidProcess, cb)
		// Return our fake PID (4 = System) + current process (1000)
		if lpidProcess != 0 && cb >= 8 {
			ctx.Mem.Write32(lpidProcess, 4)     // System
			ctx.Mem.Write32(lpidProcess+4, 1000) // current
		}
		if lpcbNeeded != 0 { ctx.Mem.Write32(lpcbNeeded, 8) } // 2 PIDs * 4 bytes
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetDeviceDriverBaseNameA", func(ctx *ntapi.TrapContext) uint32 {
		ImageBase := ctx.Arg(0)
		lpFilename := ctx.Arg(1)
		nSize := ctx.Arg(2)
		ravelog.Logf("[psapi] GetDeviceDriverBaseNameA base=0x%x\n", ImageBase)
		name := "ntoskrnl.exe"
		if lpFilename != 0 && nSize > 0 {
			for i, ch := range name {
				if uint64(i) >= nSize-1 { break }
				ctx.Mem.Write8(lpFilename+uint64(i)*1, byte(ch))
			}
			ctx.Mem.Write8(lpFilename+uint64(len(name))*1, 0)
		}
		ctx.SetReturn(uint64(len(name)))
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetDeviceDriverBaseNameW", func(ctx *ntapi.TrapContext) uint32 {
		ImageBase := ctx.Arg(0)
		lpFilename := ctx.Arg(1)
		nSize := ctx.Arg(2)
		ravelog.Logf("[psapi] GetDeviceDriverBaseNameW base=0x%x\n", ImageBase)
		name := "ntoskrnl.exe"
		if lpFilename != 0 && nSize > 0 {
			for i, ch := range name {
				if uint64(i) >= nSize-1 { break }
				ctx.Mem.Write16(lpFilename+uint64(i)*2, uint16(ch))
			}
			ctx.Mem.Write16(lpFilename+uint64(len(name))*2, 0)
		}
		ctx.SetReturn(uint64(len(name)))
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetDeviceDriverFileNameA", func(ctx *ntapi.TrapContext) uint32 {
		ImageBase := ctx.Arg(0)
		lpFilename := ctx.Arg(1)
		nSize := ctx.Arg(2)
		ravelog.Logf("[psapi] GetDeviceDriverFileNameA base=0x%x\n", ImageBase)
		path := "\\SystemRoot\\System32\\ntoskrnl.exe"
		if lpFilename != 0 && nSize > 0 {
			for i, ch := range path {
				if uint64(i) >= nSize-1 { break }
				ctx.Mem.Write8(lpFilename+uint64(i)*1, byte(ch))
			}
			ctx.Mem.Write8(lpFilename+uint64(len(path))*1, 0)
		}
		ctx.SetReturn(uint64(len(path)))
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetDeviceDriverFileNameW", func(ctx *ntapi.TrapContext) uint32 {
		ImageBase := ctx.Arg(0)
		lpFilename := ctx.Arg(1)
		nSize := ctx.Arg(2)
		ravelog.Logf("[psapi] GetDeviceDriverFileNameW base=0x%x\n", ImageBase)
		path := "\\SystemRoot\\System32\\ntoskrnl.exe"
		if lpFilename != 0 && nSize > 0 {
			for i, ch := range path {
				if uint64(i) >= nSize-1 { break }
				ctx.Mem.Write16(lpFilename+uint64(i)*2, uint16(ch))
			}
			ctx.Mem.Write16(lpFilename+uint64(len(path))*2, 0)
		}
		ctx.SetReturn(uint64(len(path)))
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetMappedFileNameA", func(ctx *ntapi.TrapContext) uint32 {
		hProcess := ctx.Arg(0)
		lpv := ctx.Arg(1)
		lpFilename := ctx.Arg(2)
		nSize := ctx.Arg(3)
		ravelog.Logf("[psapi] GetMappedFileNameA proc=0x%x addr=0x%x\n", hProcess, lpv)
		if lpFilename != 0 && nSize > 0 { ctx.Mem.Write8(lpFilename, 0) }
		ctx.SetReturn(0) // 0 = not mapped
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetMappedFileNameW", func(ctx *ntapi.TrapContext) uint32 {
		hProcess := ctx.Arg(0)
		lpv := ctx.Arg(1)
		lpFilename := ctx.Arg(2)
		nSize := ctx.Arg(3)
		ravelog.Logf("[psapi] GetMappedFileNameW proc=0x%x addr=0x%x\n", hProcess, lpv)
		if lpFilename != 0 && nSize > 0 { ctx.Mem.Write16(lpFilename, 0) }
		ctx.SetReturn(0) // 0 = not mapped
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetModuleBaseNameA", func(ctx *ntapi.TrapContext) uint32 {
		hProcess := ctx.Arg(0)
		hModule := ctx.Arg(1)
		lpBaseName := ctx.Arg(2)
		nSize := ctx.Arg(3)
		ravelog.Logf("[psapi] GetModuleBaseNameA proc=0x%x mod=0x%x\n", hProcess, hModule)
		name := "program.exe"
		if lpBaseName != 0 && nSize > 0 {
			for i, ch := range name {
				if uint64(i) >= nSize-1 { break }
				ctx.Mem.Write8(lpBaseName+uint64(i)*1, byte(ch))
			}
			ctx.Mem.Write8(lpBaseName+uint64(len(name))*1, 0)
		}
		ctx.SetReturn(uint64(len(name)))
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetModuleBaseNameW", func(ctx *ntapi.TrapContext) uint32 {
		hProcess := ctx.Arg(0)
		hModule := ctx.Arg(1)
		lpBaseName := ctx.Arg(2)
		nSize := ctx.Arg(3)
		ravelog.Logf("[psapi] GetModuleBaseNameW proc=0x%x mod=0x%x\n", hProcess, hModule)
		name := "program.exe"
		if lpBaseName != 0 && nSize > 0 {
			for i, ch := range name {
				if uint64(i) >= nSize-1 { break }
				ctx.Mem.Write16(lpBaseName+uint64(i)*2, uint16(ch))
			}
			ctx.Mem.Write16(lpBaseName+uint64(len(name))*2, 0)
		}
		ctx.SetReturn(uint64(len(name)))
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetModuleFileNameExA", func(ctx *ntapi.TrapContext) uint32 {
		hProcess := ctx.Arg(0)
		hModule := ctx.Arg(1)
		lpFilename := ctx.Arg(2)
		nSize := ctx.Arg(3)
		ravelog.Logf("[psapi] GetModuleFileNameExA proc=0x%x mod=0x%x\n", hProcess, hModule)
		path := "C:\\program.exe"
		if lpFilename != 0 && nSize > 0 {
			for i, ch := range path {
				if uint64(i) >= nSize-1 { break }
				ctx.Mem.Write8(lpFilename+uint64(i)*1, byte(ch))
			}
			ctx.Mem.Write8(lpFilename+uint64(len(path))*1, 0)
		}
		ctx.SetReturn(uint64(len(path)))
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetModuleFileNameExW", func(ctx *ntapi.TrapContext) uint32 {
		hProcess := ctx.Arg(0)
		hModule := ctx.Arg(1)
		lpFilename := ctx.Arg(2)
		nSize := ctx.Arg(3)
		ravelog.Logf("[psapi] GetModuleFileNameExW proc=0x%x mod=0x%x\n", hProcess, hModule)
		path := "C:\\program.exe"
		if lpFilename != 0 && nSize > 0 {
			for i, ch := range path {
				if uint64(i) >= nSize-1 { break }
				ctx.Mem.Write16(lpFilename+uint64(i)*2, uint16(ch))
			}
			ctx.Mem.Write16(lpFilename+uint64(len(path))*2, 0)
		}
		ctx.SetReturn(uint64(len(path)))
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetModuleInformation", func(ctx *ntapi.TrapContext) uint32 {
		hProcess := ctx.Arg(0)
		hModule := ctx.Arg(1)
		lpmodinfo := ctx.Arg(2)
		cb := ctx.Arg(3)
		ravelog.Logf("[psapi] GetModuleInformation proc=0x%x mod=0x%x\n", hProcess, hModule)
		// MODULEINFO: lpBaseOfDll(8), SizeOfImage(4), EntryPoint(8)
		if lpmodinfo != 0 && cb >= 24 {
			ctx.Mem.Write64(lpmodinfo, 0x00400000)     // lpBaseOfDll
			ctx.Mem.Write32(lpmodinfo+8, 0x00100000)   // SizeOfImage (1MB)
			ctx.Mem.Write64(lpmodinfo+16, 0x00401000)  // EntryPoint
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetPerformanceInfo", func(ctx *ntapi.TrapContext) uint32 {
		pPerformanceInformation := ctx.Arg(0)
		cb := ctx.Arg(1)
		ravelog.Logf("[psapi] GetPerformanceInfo size=%d\n", cb)
		if pPerformanceInformation != 0 && cb >= 104 {
			ctx.Mem.Write32(pPerformanceInformation, uint32(cb)) // cb
			ctx.Mem.Write64(pPerformanceInformation+8, 1024*1024)  // CommitTotal (pages)
			ctx.Mem.Write64(pPerformanceInformation+16, 4*1024*1024) // CommitLimit
			ctx.Mem.Write64(pPerformanceInformation+24, 2*1024*1024) // CommitPeak
			ctx.Mem.Write64(pPerformanceInformation+32, 2*1024*1024) // PhysicalTotal
			ctx.Mem.Write64(pPerformanceInformation+40, 1*1024*1024) // PhysicalAvailable
			ctx.Mem.Write64(pPerformanceInformation+48, 512*1024)    // SystemCache
			ctx.Mem.Write64(pPerformanceInformation+56, 256*1024)    // KernelTotal
			ctx.Mem.Write64(pPerformanceInformation+64, 128*1024)    // KernelPaged
			ctx.Mem.Write64(pPerformanceInformation+72, 128*1024)    // KernelNonpaged
			ctx.Mem.Write64(pPerformanceInformation+80, 4096)        // PageSize
			ctx.Mem.Write32(pPerformanceInformation+88, 100)         // HandleCount
			ctx.Mem.Write32(pPerformanceInformation+92, 50)          // ProcessCount
			ctx.Mem.Write32(pPerformanceInformation+96, 200)         // ThreadCount
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetProcessImageFileNameA", func(ctx *ntapi.TrapContext) uint32 {
		hProcess := ctx.Arg(0)
		lpImageFileName := ctx.Arg(1)
		nSize := ctx.Arg(2)
		ravelog.Logf("[psapi] GetProcessImageFileNameA proc=0x%x\n", hProcess)
		path := "\\Device\\HarddiskVolume1\\program.exe"
		if lpImageFileName != 0 && nSize > 0 {
			for i, ch := range path {
				if uint64(i) >= nSize-1 { break }
				ctx.Mem.Write8(lpImageFileName+uint64(i)*1, byte(ch))
			}
			ctx.Mem.Write8(lpImageFileName+uint64(len(path))*1, 0)
		}
		ctx.SetReturn(uint64(len(path)))
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetProcessImageFileNameW", func(ctx *ntapi.TrapContext) uint32 {
		hProcess := ctx.Arg(0)
		lpImageFileName := ctx.Arg(1)
		nSize := ctx.Arg(2)
		ravelog.Logf("[psapi] GetProcessImageFileNameW proc=0x%x\n", hProcess)
		path := "\\Device\\HarddiskVolume1\\program.exe"
		if lpImageFileName != 0 && nSize > 0 {
			for i, ch := range path {
				if uint64(i) >= nSize-1 { break }
				ctx.Mem.Write16(lpImageFileName+uint64(i)*2, uint16(ch))
			}
			ctx.Mem.Write16(lpImageFileName+uint64(len(path))*2, 0)
		}
		ctx.SetReturn(uint64(len(path)))
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetProcessMemoryInfo", func(ctx *ntapi.TrapContext) uint32 {
		Process := ctx.Arg(0)
		ppsmemCounters := ctx.Arg(1)
		cb := ctx.Arg(2)
		ravelog.Logf("[psapi] GetProcessMemoryInfo proc=0x%x\n", Process)
		// PROCESS_MEMORY_COUNTERS: cb(4), PageFaultCount(4), PeakWorkingSetSize(8), WorkingSetSize(8), ...
		if ppsmemCounters != 0 && cb >= 72 {
			ctx.Mem.Write32(ppsmemCounters, uint32(cb)) // cb
			ctx.Mem.Write32(ppsmemCounters+4, 100)      // PageFaultCount
			ctx.Mem.Write64(ppsmemCounters+8, 64*1024*1024)  // PeakWorkingSetSize (64MB)
			ctx.Mem.Write64(ppsmemCounters+16, 32*1024*1024) // WorkingSetSize (32MB)
			ctx.Mem.Write64(ppsmemCounters+24, 16*1024*1024) // QuotaPeakPagedPoolUsage
			ctx.Mem.Write64(ppsmemCounters+32, 8*1024*1024)  // QuotaPagedPoolUsage
			ctx.Mem.Write64(ppsmemCounters+40, 4*1024*1024)  // QuotaPeakNonPagedPoolUsage
			ctx.Mem.Write64(ppsmemCounters+48, 2*1024*1024)  // QuotaNonPagedPoolUsage
			ctx.Mem.Write64(ppsmemCounters+56, 64*1024*1024) // PagefileUsage
			ctx.Mem.Write64(ppsmemCounters+64, 64*1024*1024) // PeakPagefileUsage
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetWsChanges", func(ctx *ntapi.TrapContext) uint32 {
		hProcess := ctx.Arg(0)
		lpWatchInfo := ctx.Arg(1)
		cb := ctx.Arg(2)
		ravelog.Logf("[psapi] GetWsChanges proc=0x%x size=%d\n", hProcess, cb)
		if lpWatchInfo != 0 && cb >= 16 { ctx.Mem.Write64(lpWatchInfo, 0) } // no changes
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "InitializeProcessForWsWatch", func(ctx *ntapi.TrapContext) uint32 {
		hProcess := ctx.Arg(0)
		ravelog.Logf("[psapi] InitializeProcessForWsWatch proc=0x%x\n", hProcess)
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "QueryWorkingSet", func(ctx *ntapi.TrapContext) uint32 {
		hProcess := ctx.Arg(0)
		pv := ctx.Arg(1)
		cb := ctx.Arg(2)
		ravelog.Logf("[psapi] QueryWorkingSet proc=0x%x size=%d\n", hProcess, cb)
		if pv != 0 && cb >= 8 { ctx.Mem.Write64(pv, 0) } // NumberOfEntries = 0
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "QueryWorkingSetEx", func(ctx *ntapi.TrapContext) uint32 {
		hProcess := ctx.Arg(0)
		_ = ctx.Arg(1)
		cb := ctx.Arg(2)
		ravelog.Logf("[psapi] QueryWorkingSetEx proc=0x%x size=%d\n", hProcess, cb)
		ctx.SetReturn(1) // TRUE
		return 0
	})
}

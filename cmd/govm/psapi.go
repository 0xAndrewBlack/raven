package main

import (
	ravelog "github.com/mirkobrombin/Raven/pkg/log"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
	"runtime"
	"strings"
)

func registerPsapiHandlers(hctx *HandlerCtx) {
	d := hctx.Disp
	mainModule := hctx.MainModule
	dll, ok := hctx.SynthByName["psapi.dll"]
	if !ok {
		return
	}
	_ = dll

	type moduleSnapshot struct {
		BaseAddr   uint64
		EntryPoint uint64
		ImageSize  uint64
		Name       string
		FullPath   string
	}
	readUnicodeString := func(addr uint64) string {
		if addr == 0 {
			return ""
		}
		length, _ := hctx.Mem.Read16(addr + ntapi.UnicodeStringLength)
		buf, _ := hctx.Mem.Read64(addr + ntapi.UnicodeStringBuffer)
		if buf == 0 || length == 0 {
			return ""
		}
		return hctx.ReadGuestUTF16N(buf, int(length/2))
	}
	listLoadedModules := func() []moduleSnapshot {
		if hctx.ProcState == nil || hctx.ProcState.LdrDataAddr == 0 {
			return nil
		}
		head := hctx.ProcState.LdrDataAddr + ntapi.LdrInLoadOrderModuleList
		cur, _ := hctx.Mem.Read64(head)
		seen := map[uint64]struct{}{}
		var mods []moduleSnapshot
		for cur != 0 && cur != head {
			if _, ok := seen[cur]; ok {
				break
			}
			seen[cur] = struct{}{}
			entry := cur - ntapi.LdrEntryInLoadOrderLinks
			base, _ := hctx.Mem.Read64(entry + ntapi.LdrEntryDllBase)
			ep, _ := hctx.Mem.Read64(entry + ntapi.LdrEntryEntryPoint)
			size, _ := hctx.Mem.Read32(entry + ntapi.LdrEntrySizeOfImage)
			mods = append(mods, moduleSnapshot{
				BaseAddr:   base,
				EntryPoint: ep,
				ImageSize:  uint64(size),
				Name:       strings.ToLower(readUnicodeString(entry + ntapi.LdrEntryBaseDllName)),
				FullPath:   readUnicodeString(entry + ntapi.LdrEntryFullDllName),
			})
			cur, _ = hctx.Mem.Read64(cur)
		}
		if len(mods) == 0 && mainModule != nil {
			mods = append(mods, moduleSnapshot{
				BaseAddr:   mainModule.BaseAddr,
				EntryPoint: mainModule.EntryPoint,
				ImageSize:  mainModule.ImageSize,
				Name:       strings.ToLower(mainModule.Name),
				FullPath:   hctx.ImagePath,
			})
		}
		return mods
	}
	findModule := func(handle uint64) (moduleSnapshot, bool) {
		if handle == 0 && mainModule != nil {
			return moduleSnapshot{
				BaseAddr:   mainModule.BaseAddr,
				EntryPoint: mainModule.EntryPoint,
				ImageSize:  mainModule.ImageSize,
				Name:       strings.ToLower(mainModule.Name),
				FullPath:   hctx.ImagePath,
			}, true
		}
		for _, mod := range listLoadedModules() {
			if mod.BaseAddr == handle {
				return mod, true
			}
		}
		return moduleSnapshot{}, false
	}

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
		if lpcbNeeded != 0 {
			ctx.Mem.Write32(lpcbNeeded, 0)
		} // no drivers
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
		mods := listLoadedModules()
		if lpcbNeeded != 0 {
			ctx.Mem.Write32(lpcbNeeded, uint32(len(mods))*8)
		}
		maxCount := int(cb / 8)
		if maxCount > len(mods) {
			maxCount = len(mods)
		}
		for i := 0; i < maxCount; i++ {
			ctx.Mem.Write64(lphModule+uint64(i)*8, mods[i].BaseAddr)
		}
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
			ctx.Mem.Write32(lpidProcess, 4)      // System
			ctx.Mem.Write32(lpidProcess+4, 1000) // current
		}
		if lpcbNeeded != 0 {
			ctx.Mem.Write32(lpcbNeeded, 8)
		} // 2 PIDs * 4 bytes
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
				if uint64(i) >= nSize-1 {
					break
				}
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
				if uint64(i) >= nSize-1 {
					break
				}
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
				if uint64(i) >= nSize-1 {
					break
				}
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
				if uint64(i) >= nSize-1 {
					break
				}
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
		if lpFilename != 0 && nSize > 0 {
			ctx.Mem.Write8(lpFilename, 0)
		}
		ctx.SetReturn(0) // 0 = not mapped
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetMappedFileNameW", func(ctx *ntapi.TrapContext) uint32 {
		hProcess := ctx.Arg(0)
		lpv := ctx.Arg(1)
		lpFilename := ctx.Arg(2)
		nSize := ctx.Arg(3)
		ravelog.Logf("[psapi] GetMappedFileNameW proc=0x%x addr=0x%x\n", hProcess, lpv)
		if lpFilename != 0 && nSize > 0 {
			ctx.Mem.Write16(lpFilename, 0)
		}
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
				if uint64(i) >= nSize-1 {
					break
				}
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
				if uint64(i) >= nSize-1 {
					break
				}
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
				if uint64(i) >= nSize-1 {
					break
				}
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
				if uint64(i) >= nSize-1 {
					break
				}
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
		if mod, ok := findModule(hModule); ok && lpmodinfo != 0 && cb >= 24 {
			ctx.Mem.Write64(lpmodinfo, mod.BaseAddr)
			ctx.Mem.Write32(lpmodinfo+8, uint32(mod.ImageSize))
			ctx.Mem.Write64(lpmodinfo+16, mod.EntryPoint)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetPerformanceInfo", func(ctx *ntapi.TrapContext) uint32 {
		pPerformanceInformation := ctx.Arg(0)
		cb := ctx.Arg(1)
		ravelog.Logf("[psapi] GetPerformanceInfo size=%d\n", cb)
		if pPerformanceInformation != 0 && cb >= 104 {
			ctx.Mem.Write32(pPerformanceInformation, uint32(cb))     // cb
			ctx.Mem.Write64(pPerformanceInformation+8, 1024*1024)    // CommitTotal (pages)
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
				if uint64(i) >= nSize-1 {
					break
				}
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
				if uint64(i) >= nSize-1 {
					break
				}
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
		var memStats runtime.MemStats
		runtime.ReadMemStats(&memStats)
		if ppsmemCounters != 0 && cb >= 72 {
			ctx.Mem.Write32(ppsmemCounters, uint32(cb))
			ctx.Mem.Write32(ppsmemCounters+4, uint32(memStats.Mallocs-memStats.Frees))
			ctx.Mem.Write64(ppsmemCounters+8, memStats.Sys)
			ctx.Mem.Write64(ppsmemCounters+16, memStats.Alloc)
			ctx.Mem.Write64(ppsmemCounters+24, memStats.HeapSys)
			ctx.Mem.Write64(ppsmemCounters+32, memStats.HeapAlloc)
			ctx.Mem.Write64(ppsmemCounters+40, memStats.StackSys)
			ctx.Mem.Write64(ppsmemCounters+48, memStats.StackInuse)
			ctx.Mem.Write64(ppsmemCounters+56, memStats.HeapInuse)
			ctx.Mem.Write64(ppsmemCounters+64, memStats.HeapSys)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetWsChanges", func(ctx *ntapi.TrapContext) uint32 {
		hProcess := ctx.Arg(0)
		lpWatchInfo := ctx.Arg(1)
		cb := ctx.Arg(2)
		ravelog.Logf("[psapi] GetWsChanges proc=0x%x size=%d\n", hProcess, cb)
		if lpWatchInfo != 0 && cb >= 16 {
			ctx.Mem.Write64(lpWatchInfo, 0)
		} // no changes
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
		if pv != 0 && cb >= 8 {
			ctx.Mem.Write64(pv, 0)
		} // NumberOfEntries = 0
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

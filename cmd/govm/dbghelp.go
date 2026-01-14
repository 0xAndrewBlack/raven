package main

import (
	"encoding/binary"
	"strings"
	"sync"

	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

type dbgState struct {
	mu        sync.Mutex
	processes map[uint64]*dbgProcess
	options   uint32
}

type dbgProcess struct {
	handle      uint64
	searchPath  string
	options     uint32
	initialized bool
}

type versionInfo struct {
	data []byte
}

var dbgGlobal = dbgState{processes: make(map[uint64]*dbgProcess)}

var versionGlobal = versionInfo{
	data: func() []byte {
		const (
			versionBlockSize      = 256
			versionTranslationOff = 64
		)
		data := make([]byte, versionBlockSize)
		binary.LittleEndian.PutUint32(data[0:], 0xFEEF04BD)
		binary.LittleEndian.PutUint32(data[4:], 0x00010000)
		binary.LittleEndian.PutUint32(data[8:], 0x000A0000)
		binary.LittleEndian.PutUint32(data[12:], 0x4A610000)
		binary.LittleEndian.PutUint32(data[16:], 0x000A0000)
		binary.LittleEndian.PutUint32(data[20:], 0x4A610000)
		binary.LittleEndian.PutUint32(data[24:], 0x0000003F)
		binary.LittleEndian.PutUint32(data[28:], 0)
		binary.LittleEndian.PutUint32(data[32:], 0x00040004)
		binary.LittleEndian.PutUint32(data[36:], 1)
		binary.LittleEndian.PutUint16(data[versionTranslationOff:], 0x0409)
		binary.LittleEndian.PutUint16(data[versionTranslationOff+2:], 0x04B0)
		return data
	}(),
}

func registerDbghelpHandlers(hctx *HandlerCtx) {
	registerVersionDLLHandlers(hctx)
	registerDbghelpDLLHandlers(hctx)
	registerImagehlpDLLHandlers(hctx)
}

func registerVersionDLLHandlers(hctx *HandlerCtx) {
	d := hctx.Disp
	readGuestString := hctx.ReadGuestString
	readGuestUTF16 := hctx.ReadGuestUTF16

	version, ok := hctx.SynthByName["version.dll"]
	if !ok {
		return
	}

	const (
		versionBlockSize      = 256
		versionRootLen        = 52
		versionTranslationOff = 64
		versionANSIStringOff  = 72
		versionWideStringOff  = 80
	)

	writeVersionBlock := func(ctx *ntapi.TrapContext, ptr, maxLen uint64) {
		if ptr == 0 || maxLen == 0 {
			return
		}
		n := len(versionGlobal.data)
		if uint64(n) > maxLen {
			n = int(maxLen)
		}
		_ = ctx.Mem.WriteBytes(ptr, versionGlobal.data[:n])
	}
	writeVerQueryResult := func(ctx *ntapi.TrapContext, resultPtr uint64, valueLen uint32) {
		if ctx.Arg(2) != 0 {
			ctx.Mem.Write64(ctx.Arg(2), resultPtr)
		}
		if ctx.Arg(3) != 0 {
			ctx.Mem.Write32(ctx.Arg(3), valueLen)
		}
		ctx.SetReturn(1)
	}

	d.RegisterAutoStubHandler(version, "GetFileVersionInfoSizeW", func(ctx *ntapi.TrapContext) uint32 {
		if handlePtr := ctx.Arg(1); handlePtr != 0 {
			ctx.Mem.Write32(handlePtr, 0)
		}
		ctx.SetReturn(versionBlockSize)
		return 0
	})
	d.RegisterAutoStubHandler(version, "GetFileVersionInfoSizeA", func(ctx *ntapi.TrapContext) uint32 {
		if handlePtr := ctx.Arg(1); handlePtr != 0 {
			ctx.Mem.Write32(handlePtr, 0)
		}
		ctx.SetReturn(versionBlockSize)
		return 0
	})
	d.RegisterAutoStubHandler(version, "GetFileVersionInfoSizeExW", func(ctx *ntapi.TrapContext) uint32 {
		if handlePtr := ctx.Arg(2); handlePtr != 0 {
			ctx.Mem.Write32(handlePtr, 0)
		}
		ctx.SetReturn(versionBlockSize)
		return 0
	})
	d.RegisterAutoStubHandler(version, "GetFileVersionInfoSizeExA", func(ctx *ntapi.TrapContext) uint32 {
		if handlePtr := ctx.Arg(2); handlePtr != 0 {
			ctx.Mem.Write32(handlePtr, 0)
		}
		ctx.SetReturn(versionBlockSize)
		return 0
	})
	d.RegisterAutoStubHandler(version, "GetFileVersionInfoW", func(ctx *ntapi.TrapContext) uint32 {
		writeVersionBlock(ctx, ctx.Arg(3), ctx.Arg(2))
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(version, "GetFileVersionInfoA", func(ctx *ntapi.TrapContext) uint32 {
		writeVersionBlock(ctx, ctx.Arg(3), ctx.Arg(2))
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(version, "GetFileVersionInfoExW", func(ctx *ntapi.TrapContext) uint32 {
		writeVersionBlock(ctx, ctx.Arg(4), ctx.Arg(3))
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(version, "GetFileVersionInfoExA", func(ctx *ntapi.TrapContext) uint32 {
		writeVersionBlock(ctx, ctx.Arg(4), ctx.Arg(3))
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(version, "VerQueryValueW", func(ctx *ntapi.TrapContext) uint32 {
		pBlock := ctx.Arg(0)
		sub := strings.ToLower(readGuestUTF16(ctx.Arg(1)))
		switch {
		case sub == `\`:
			writeVerQueryResult(ctx, pBlock, versionRootLen)
		case strings.HasPrefix(sub, `\stringfileinfo\`):
			writeVerQueryResult(ctx, pBlock+versionWideStringOff, 1)
		case sub == `\varfileinfo\translation`:
			writeVerQueryResult(ctx, pBlock+versionTranslationOff, 4)
		default:
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(version, "VerQueryValueA", func(ctx *ntapi.TrapContext) uint32 {
		pBlock := ctx.Arg(0)
		sub := strings.ToLower(readGuestString(ctx.Arg(1)))
		switch {
		case sub == `\`:
			writeVerQueryResult(ctx, pBlock, versionRootLen)
		case strings.HasPrefix(sub, `\stringfileinfo\`):
			writeVerQueryResult(ctx, pBlock+versionANSIStringOff, 1)
		case sub == `\varfileinfo\translation`:
			writeVerQueryResult(ctx, pBlock+versionTranslationOff, 4)
		default:
			ctx.SetReturn(0)
		}
		return 0
	})
}

func registerDbghelpDLLHandlers(hctx *HandlerCtx) {
	d := hctx.Disp
	mem := hctx.Mem
	readGuestString := hctx.ReadGuestString
	readGuestUTF16 := hctx.ReadGuestUTF16

	dbghelp, ok := hctx.SynthByName["dbghelp.dll"]
	if !ok {
		return
	}

	const (
		imagehlpModule64Size  = 1680
		imagehlpModuleW64Size = 3260
	)

	getProcess := func(handle uint64, create bool) *dbgProcess {
		dbgGlobal.mu.Lock()
		defer dbgGlobal.mu.Unlock()
		proc := dbgGlobal.processes[handle]
		if proc == nil && create {
			proc = &dbgProcess{handle: handle, options: dbgGlobal.options}
			dbgGlobal.processes[handle] = proc
		}
		return proc
	}
	setSearchPath := func(handle uint64, path string) {
		dbgGlobal.mu.Lock()
		defer dbgGlobal.mu.Unlock()
		proc := dbgGlobal.processes[handle]
		if proc == nil {
			proc = &dbgProcess{handle: handle, options: dbgGlobal.options}
			dbgGlobal.processes[handle] = proc
		}
		proc.searchPath = path
	}
	getSearchPath := func(handle uint64) string {
		dbgGlobal.mu.Lock()
		defer dbgGlobal.mu.Unlock()
		if proc := dbgGlobal.processes[handle]; proc != nil {
			return proc.searchPath
		}
		return ""
	}
	writeANSIResult := func(ptr uint64, value string, maxChars uint64) {
		if ptr == 0 || maxChars == 0 {
			return
		}
		writeGuestANSIStringN(mem, ptr, value, int(maxChars))
	}
	writeWideResult := func(ptr uint64, value string, maxChars uint64) {
		if ptr == 0 || maxChars == 0 {
			return
		}
		writeGuestUTF16StringN(mem, ptr, value, int(maxChars))
	}
	writeModuleInfo := func(ptr uint64, base uint64, wide bool) {
		if ptr == 0 {
			return
		}
		size, _ := mem.Read32(ptr)
		structSize := uint32(imagehlpModule64Size)
		if wide {
			structSize = imagehlpModuleW64Size
		}
		clearLen := size
		if clearLen == 0 || clearLen > structSize {
			clearLen = structSize
		}
		if clearLen > 0 {
			_ = mem.WriteBytes(ptr, make([]byte, clearLen))
		}
		mem.Write32(ptr, size)
		mem.Write64(ptr+8, base)
		moduleName := ""
		imageName := ""
		if hctx.MainModule != nil {
			moduleName = hctx.MainModule.Name
			imageName = hctx.ImagePath
			if base == 0 {
				mem.Write64(ptr+8, hctx.MainModule.BaseAddr)
			}
			mem.Write32(ptr+16, uint32(hctx.MainModule.ImageSize))
		}
		if wide {
			writeGuestUTF16StringN(mem, ptr+36, moduleName, 32)
			writeGuestUTF16StringN(mem, ptr+100, imageName, 256)
			writeGuestUTF16StringN(mem, ptr+612, imageName, 256)
			return
		}
		writeGuestANSIStringN(mem, ptr+36, moduleName, 32)
		writeGuestANSIStringN(mem, ptr+68, imageName, 256)
		writeGuestANSIStringN(mem, ptr+324, imageName, 256)
	}

	d.RegisterAutoStubHandler(dbghelp, "SymInitialize", func(ctx *ntapi.TrapContext) uint32 {
		hProcess := ctx.Arg(0)
		path := readGuestString(ctx.Arg(1))
		proc := getProcess(hProcess, true)
		dbgGlobal.mu.Lock()
		proc.searchPath = path
		proc.initialized = true
		proc.options = dbgGlobal.options
		dbgGlobal.mu.Unlock()
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dbghelp, "SymInitializeW", func(ctx *ntapi.TrapContext) uint32 {
		hProcess := ctx.Arg(0)
		path := readGuestUTF16(ctx.Arg(1))
		proc := getProcess(hProcess, true)
		dbgGlobal.mu.Lock()
		proc.searchPath = path
		proc.initialized = true
		proc.options = dbgGlobal.options
		dbgGlobal.mu.Unlock()
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dbghelp, "SymCleanup", func(ctx *ntapi.TrapContext) uint32 {
		dbgGlobal.mu.Lock()
		delete(dbgGlobal.processes, ctx.Arg(0))
		dbgGlobal.mu.Unlock()
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dbghelp, "SymSetOptions", func(ctx *ntapi.TrapContext) uint32 {
		dbgGlobal.mu.Lock()
		old := dbgGlobal.options
		dbgGlobal.options = uint32(ctx.Arg(0))
		dbgGlobal.mu.Unlock()
		ctx.SetReturn(uint64(old))
		return 0
	})
	d.RegisterAutoStubHandler(dbghelp, "SymGetOptions", func(ctx *ntapi.TrapContext) uint32 {
		dbgGlobal.mu.Lock()
		opts := dbgGlobal.options
		dbgGlobal.mu.Unlock()
		ctx.SetReturn(uint64(opts))
		return 0
	})
	d.RegisterAutoStubHandler(dbghelp, "SymSetSearchPath", func(ctx *ntapi.TrapContext) uint32 {
		setSearchPath(ctx.Arg(0), readGuestString(ctx.Arg(1)))
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dbghelp, "SymSetSearchPathW", func(ctx *ntapi.TrapContext) uint32 {
		setSearchPath(ctx.Arg(0), readGuestUTF16(ctx.Arg(1)))
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dbghelp, "SymGetSearchPath", func(ctx *ntapi.TrapContext) uint32 {
		writeANSIResult(ctx.Arg(1), getSearchPath(ctx.Arg(0)), ctx.Arg(2))
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dbghelp, "SymGetSearchPathW", func(ctx *ntapi.TrapContext) uint32 {
		writeWideResult(ctx.Arg(1), getSearchPath(ctx.Arg(0)), ctx.Arg(2))
		ctx.SetReturn(1)
		return 0
	})
	for _, name := range []string{"SymLoadModule64", "SymLoadModuleEx", "SymLoadModuleExW"} {
		funcName := name
		d.RegisterAutoStubHandler(dbghelp, funcName, func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(ctx.Arg(4))
			return 0
		})
	}
	d.RegisterAutoStubHandler(dbghelp, "SymUnloadModule64", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dbghelp, "SymGetModuleInfo64", func(ctx *ntapi.TrapContext) uint32 {
		writeModuleInfo(ctx.Arg(2), ctx.Arg(1), false)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dbghelp, "SymGetModuleInfoW64", func(ctx *ntapi.TrapContext) uint32 {
		writeModuleInfo(ctx.Arg(2), ctx.Arg(1), true)
		ctx.SetReturn(1)
		return 0
	})
	for _, name := range []string{
		"SymFromAddr", "SymFromAddrW", "SymFromName", "SymFromNameW",
		"SymGetLineFromAddr64", "SymGetLineFromAddrW64",
		"MiniDumpReadDumpStream", "StackWalk64", "StackWalkEx",
	} {
		funcName := name
		d.RegisterAutoStubHandler(dbghelp, funcName, func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
	}
	for _, name := range []string{
		"SymEnumSymbols", "SymEnumSymbolsW", "SymEnumLines", "SymEnumSourceFiles",
		"SymRegisterCallback64", "SymRegisterCallbackW64", "SymRefreshModuleList",
		"SymSetContext", "MiniDumpWriteDump",
	} {
		funcName := name
		d.RegisterAutoStubHandler(dbghelp, funcName, func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
	}
	d.RegisterAutoStubHandler(dbghelp, "SymFunctionTableAccess64", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dbghelp, "SymGetModuleBase64", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dbghelp, "UnDecorateSymbolName", func(ctx *ntapi.TrapContext) uint32 {
		name := readGuestString(ctx.Arg(0))
		writeANSIResult(ctx.Arg(1), name, ctx.Arg(2))
		ctx.SetReturn(uint64(len(name)))
		return 0
	})
	d.RegisterAutoStubHandler(dbghelp, "UnDecorateSymbolNameW", func(ctx *ntapi.TrapContext) uint32 {
		name := readGuestUTF16(ctx.Arg(0))
		writeWideResult(ctx.Arg(1), name, ctx.Arg(2))
		ctx.SetReturn(uint64(len(utf16Encode(name))))
		return 0
	})
	d.RegisterAutoStubHandler(dbghelp, "ImageNtHeader", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
}

func registerImagehlpDLLHandlers(hctx *HandlerCtx) {
	d := hctx.Disp

	imagehlp, ok := hctx.SynthByName["imagehlp.dll"]
	if !ok {
		return
	}

	d.RegisterAutoStubHandler(imagehlp, "CheckSumMappedFile", func(ctx *ntapi.TrapContext) uint32 {
		if headerSum := ctx.Arg(2); headerSum != 0 {
			ctx.Mem.Write32(headerSum, 0)
		}
		if checkSum := ctx.Arg(3); checkSum != 0 {
			ctx.Mem.Write32(checkSum, 0)
		}
		ctx.SetReturn(ctx.Arg(0))
		return 0
	})
	for _, name := range []string{"MapFileAndCheckSumW", "MapFileAndCheckSumA"} {
		funcName := name
		d.RegisterAutoStubHandler(imagehlp, funcName, func(ctx *ntapi.TrapContext) uint32 {
			if headerSum := ctx.Arg(1); headerSum != 0 {
				ctx.Mem.Write32(headerSum, 0)
			}
			if checkSum := ctx.Arg(2); checkSum != 0 {
				ctx.Mem.Write32(checkSum, 0)
			}
			ctx.SetReturn(0)
			return 0
		})
	}
	for _, name := range []string{"ImageNtHeader", "ImageDirectoryEntryToData", "ImageRvaToVa"} {
		funcName := name
		d.RegisterAutoStubHandler(imagehlp, funcName, func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
	}
}

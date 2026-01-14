package main

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"io"
	"sync"

	ravelog "github.com/mirkobrombin/Raven/pkg/log"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

const (
	COMPRESS_ALGORITHM_INVALID      = 0
	COMPRESS_ALGORITHM_NULL         = 1
	COMPRESS_ALGORITHM_MSZIP        = 2
	COMPRESS_ALGORITHM_XPRESS       = 3
	COMPRESS_ALGORITHM_XPRESS_HUFF  = 4
	COMPRESS_ALGORITHM_LZMS         = 5
	ERROR_INSUFFICIENT_BUFFER       = 122
	ERROR_INVALID_HANDLE            = 6
	ERROR_INVALID_PARAMETER         = 87
	ERROR_UNSUPPORTED_TYPE          = 0x1065
	cabinetDefaultMSZipBlockSize    = 32768
	cabinetDefaultIdentityBlockSize = 65536
)

type fdiState struct {
	mu         sync.Mutex
	nextHandle uint32
	contexts   map[uint32]*fdiContext
}

type fdiContext struct {
	allocFn uint64
	freeFn  uint64
	openFn  uint64
	readFn  uint64
	writeFn uint64
	closeFn uint64
	seekFn  uint64
	cpuType int32
}

var fdiGlobal = fdiState{nextHandle: 0x7000, contexts: make(map[uint32]*fdiContext)}

type fciState struct {
	mu         sync.Mutex
	nextHandle uint32
	contexts   map[uint32]*fciContext
}

type fciContext struct {
	tempFiles     []string
	filePlacedFn  uint64
	allocFn       uint64
	freeFn        uint64
	openFn        uint64
	readFn        uint64
	writeFn       uint64
	closeFn       uint64
	seekFn        uint64
	deleteFn      uint64
	getTempFileFn uint64
	ccabPtr       uint64
	userData      uint64
}

var fciGlobal = fciState{nextHandle: 0x7100, contexts: make(map[uint32]*fciContext)}

type compressorState struct {
	mu          sync.Mutex
	nextHandle  uint32
	compressors map[uint32]*compressor
}

type compressor struct {
	algorithm uint32
	isDecomp  bool
	settings  map[uint32][]byte
}

var compGlobal = compressorState{nextHandle: 0x7200, compressors: make(map[uint32]*compressor)}

func msZipCompress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(data); err != nil {
		_ = w.Close()
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func msZipDecompress(data []byte) ([]byte, error) {
	r := flate.NewReader(bytes.NewReader(data))
	defer r.Close()
	return io.ReadAll(r)
}

func cabinetSupportedAlgorithm(algorithm uint32) bool {
	switch algorithm {
	case COMPRESS_ALGORITHM_NULL,
		COMPRESS_ALGORITHM_MSZIP,
		COMPRESS_ALGORITHM_XPRESS,
		COMPRESS_ALGORITHM_XPRESS_HUFF,
		COMPRESS_ALGORITHM_LZMS:
		return true
	default:
		return false
	}
}

func registerCabinetHandlers(hctx *HandlerCtx) {
	d := hctx.Disp
	mem := hctx.Mem
	procState := hctx.ProcState
	readGuestString := hctx.ReadGuestString

	dll, ok := hctx.SynthByName["cabinet.dll"]
	if !ok {
		return
	}

	setLastErrorValue := func(code uint32) {
		if procState == nil || procState.TEBAddr == 0 {
			return
		}
		_ = mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, code)
	}
	readBuffer := func(ptr, size uint64) ([]byte, bool) {
		if size == 0 {
			return []byte{}, true
		}
		if ptr == 0 {
			return nil, false
		}
		if size > uint64(^uint(0)>>1) {
			return nil, false
		}
		data, err := mem.ReadBytes(ptr, int(size))
		if err != nil {
			return nil, false
		}
		return data, true
	}
	writeSizedBuffer := func(dst, dstSize, sizePtr uint64, data []byte) bool {
		if sizePtr != 0 {
			_ = mem.Write64(sizePtr, uint64(len(data)))
		}
		if len(data) == 0 {
			return true
		}
		if dst == 0 || uint64(len(data)) > dstSize {
			setLastErrorValue(ERROR_INSUFFICIENT_BUFFER)
			return false
		}
		if err := mem.WriteBytes(dst, data); err != nil {
			setLastErrorValue(ERROR_INVALID_PARAMETER)
			return false
		}
		return true
	}
	allocFDIHandle := func(ctx *fdiContext) uint32 {
		fdiGlobal.mu.Lock()
		defer fdiGlobal.mu.Unlock()
		handle := fdiGlobal.nextHandle
		fdiGlobal.nextHandle++
		fdiGlobal.contexts[handle] = ctx
		return handle
	}
	getFDIContext := func(handle uint32) (*fdiContext, bool) {
		fdiGlobal.mu.Lock()
		defer fdiGlobal.mu.Unlock()
		ctx, ok := fdiGlobal.contexts[handle]
		return ctx, ok
	}
	deleteFDIContext := func(handle uint32) {
		fdiGlobal.mu.Lock()
		delete(fdiGlobal.contexts, handle)
		fdiGlobal.mu.Unlock()
	}
	allocFCIHandle := func(ctx *fciContext) uint32 {
		fciGlobal.mu.Lock()
		defer fciGlobal.mu.Unlock()
		handle := fciGlobal.nextHandle
		fciGlobal.nextHandle++
		fciGlobal.contexts[handle] = ctx
		return handle
	}
	getFCIContext := func(handle uint32) (*fciContext, bool) {
		fciGlobal.mu.Lock()
		defer fciGlobal.mu.Unlock()
		ctx, ok := fciGlobal.contexts[handle]
		return ctx, ok
	}
	deleteFCIContext := func(handle uint32) {
		fciGlobal.mu.Lock()
		delete(fciGlobal.contexts, handle)
		fciGlobal.mu.Unlock()
	}
	allocCompressorHandle := func(algorithm uint32, isDecomp bool) uint32 {
		compGlobal.mu.Lock()
		defer compGlobal.mu.Unlock()
		handle := compGlobal.nextHandle
		compGlobal.nextHandle++
		compGlobal.compressors[handle] = &compressor{
			algorithm: algorithm,
			isDecomp:  isDecomp,
			settings:  make(map[uint32][]byte),
		}
		return handle
	}
	getCompressor := func(handle uint32, isDecomp bool) (*compressor, bool) {
		compGlobal.mu.Lock()
		defer compGlobal.mu.Unlock()
		entry, ok := compGlobal.compressors[handle]
		if !ok || entry == nil || entry.isDecomp != isDecomp {
			return nil, false
		}
		return entry, true
	}
	deleteCompressor := func(handle uint32, isDecomp bool) bool {
		compGlobal.mu.Lock()
		defer compGlobal.mu.Unlock()
		entry, ok := compGlobal.compressors[handle]
		if !ok || entry == nil || entry.isDecomp != isDecomp {
			return false
		}
		delete(compGlobal.compressors, handle)
		return true
	}
	setCompressorInfo := func(handle uint32, isDecomp bool, class uint32, value []byte) bool {
		compGlobal.mu.Lock()
		defer compGlobal.mu.Unlock()
		entry, ok := compGlobal.compressors[handle]
		if !ok || entry == nil || entry.isDecomp != isDecomp {
			return false
		}
		if len(value) == 0 {
			delete(entry.settings, class)
			return true
		}
		entry.settings[class] = append([]byte(nil), value...)
		return true
	}
	queryCompressorInfo := func(handle uint32, isDecomp bool, class uint32) ([]byte, bool) {
		compGlobal.mu.Lock()
		defer compGlobal.mu.Unlock()
		entry, ok := compGlobal.compressors[handle]
		if !ok || entry == nil || entry.isDecomp != isDecomp {
			return nil, false
		}
		if data, ok := entry.settings[class]; ok {
			return append([]byte(nil), data...), true
		}
		var value uint32
		switch class {
		case 1:
			if entry.algorithm == COMPRESS_ALGORITHM_MSZIP {
				value = cabinetDefaultMSZipBlockSize
			} else {
				value = cabinetDefaultIdentityBlockSize
			}
		case 2:
			value = 0
		default:
			return []byte{}, true
		}
		out := make([]byte, 4)
		binary.LittleEndian.PutUint32(out, value)
		return out, true
	}

	d.RegisterAutoStubHandler(dll, "FDICreate", func(ctx *ntapi.TrapContext) uint32 {
		handle := allocFDIHandle(&fdiContext{
			allocFn: ctx.Arg(0),
			freeFn:  ctx.Arg(1),
			openFn:  ctx.Arg(2),
			readFn:  ctx.Arg(3),
			writeFn: ctx.Arg(4),
			closeFn: ctx.Arg(5),
			seekFn:  ctx.Arg(6),
			cpuType: int32(ctx.Arg(7)),
		})
		ravelog.Logf("[cabinet] FDICreate alloc=0x%x free=0x%x open=0x%x read=0x%x write=0x%x close=0x%x seek=0x%x cpu=%d -> 0x%x\n",
			ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5), ctx.Arg(6), int32(ctx.Arg(7)), handle)
		setLastErrorValue(0)
		ctx.SetReturn(uint64(handle))
		return 0
	})

	d.RegisterAutoStubHandler(dll, "FDIDestroy", func(ctx *ntapi.TrapContext) uint32 {
		handle := uint32(ctx.Arg(0))
		deleteFDIContext(handle)
		ravelog.Logf("[cabinet] FDIDestroy hfdi=0x%x\n", handle)
		setLastErrorValue(0)
		ctx.SetReturn(1)
		return 0
	})

	d.RegisterAutoStubHandler(dll, "FDICopy", func(ctx *ntapi.TrapContext) uint32 {
		handle := uint32(ctx.Arg(0))
		cabinetName := readGuestString(ctx.Arg(1))
		cabPath := readGuestString(ctx.Arg(2))
		flags := uint32(ctx.Arg(3))
		if _, ok := getFDIContext(handle); !ok {
			setLastErrorValue(ERROR_INVALID_HANDLE)
			ctx.SetReturn(0)
			return 0
		}
		ravelog.Logf("[cabinet] FDICopy hfdi=0x%x cabinet=%q cabPath=%q flags=0x%x fdin=0x%x fdid=0x%x user=0x%x\n",
			handle, cabinetName, cabPath, flags, ctx.Arg(4), ctx.Arg(5), ctx.Arg(6))
		setLastErrorValue(0)
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(dll, "FDIIsCabinet", func(ctx *ntapi.TrapContext) uint32 {
		handle := uint32(ctx.Arg(0))
		hf := ctx.Arg(1)
		fdici := ctx.Arg(2)
		if _, ok := getFDIContext(handle); !ok {
			setLastErrorValue(ERROR_INVALID_HANDLE)
			ctx.SetReturn(0)
			return 0
		}
		ravelog.Logf("[cabinet] FDIIsCabinet hfdi=0x%x hf=0x%x fdici=0x%x\n", handle, hf, fdici)
		setLastErrorValue(0)
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(dll, "FDITruncateCabinet", func(ctx *ntapi.TrapContext) uint32 {
		handle := uint32(ctx.Arg(0))
		cabinetName := readGuestString(ctx.Arg(1))
		folderToDelete := int32(ctx.Arg(2))
		if _, ok := getFDIContext(handle); !ok {
			setLastErrorValue(ERROR_INVALID_HANDLE)
			ctx.SetReturn(0)
			return 0
		}
		ravelog.Logf("[cabinet] FDITruncateCabinet hfdi=0x%x cabinet=%q folder=%d\n", handle, cabinetName, folderToDelete)
		setLastErrorValue(0)
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(dll, "FCICreate", func(ctx *ntapi.TrapContext) uint32 {
		handle := allocFCIHandle(&fciContext{
			filePlacedFn:  ctx.Arg(1),
			allocFn:       ctx.Arg(2),
			freeFn:        ctx.Arg(3),
			openFn:        ctx.Arg(4),
			readFn:        ctx.Arg(5),
			writeFn:       ctx.Arg(6),
			closeFn:       ctx.Arg(7),
			seekFn:        ctx.Arg(8),
			deleteFn:      ctx.Arg(9),
			getTempFileFn: ctx.Arg(10),
			ccabPtr:       ctx.Arg(11),
			userData:      ctx.Arg(12),
		})
		ravelog.Logf("[cabinet] FCICreate perf=0x%x filePlaced=0x%x alloc=0x%x free=0x%x open=0x%x read=0x%x write=0x%x close=0x%x seek=0x%x delete=0x%x getTemp=0x%x ccab=0x%x user=0x%x -> 0x%x\n",
			ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5), ctx.Arg(6), ctx.Arg(7), ctx.Arg(8), ctx.Arg(9), ctx.Arg(10), ctx.Arg(11), ctx.Arg(12), handle)
		setLastErrorValue(0)
		ctx.SetReturn(uint64(handle))
		return 0
	})

	d.RegisterAutoStubHandler(dll, "FCIDestroy", func(ctx *ntapi.TrapContext) uint32 {
		handle := uint32(ctx.Arg(0))
		deleteFCIContext(handle)
		ravelog.Logf("[cabinet] FCIDestroy hfci=0x%x\n", handle)
		setLastErrorValue(0)
		ctx.SetReturn(1)
		return 0
	})

	d.RegisterAutoStubHandler(dll, "FCIAddFile", func(ctx *ntapi.TrapContext) uint32 {
		handle := uint32(ctx.Arg(0))
		sourceFile := readGuestString(ctx.Arg(1))
		fileName := readGuestString(ctx.Arg(2))
		execute := ctx.Arg(3) != 0
		if _, ok := getFCIContext(handle); !ok {
			setLastErrorValue(ERROR_INVALID_HANDLE)
			ctx.SetReturn(0)
			return 0
		}
		ravelog.Logf("[cabinet] FCIAddFile hfci=0x%x source=%q name=%q execute=%t getNextCab=0x%x status=0x%x getOpenInfo=0x%x type=0x%x\n",
			handle, sourceFile, fileName, execute, ctx.Arg(4), ctx.Arg(5), ctx.Arg(6), uint16(ctx.Arg(7)))
		setLastErrorValue(0)
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(dll, "FCIFlushFolder", func(ctx *ntapi.TrapContext) uint32 {
		handle := uint32(ctx.Arg(0))
		if _, ok := getFCIContext(handle); !ok {
			setLastErrorValue(ERROR_INVALID_HANDLE)
			ctx.SetReturn(0)
			return 0
		}
		ravelog.Logf("[cabinet] FCIFlushFolder hfci=0x%x getNextCab=0x%x status=0x%x\n", handle, ctx.Arg(1), ctx.Arg(2))
		setLastErrorValue(0)
		ctx.SetReturn(1)
		return 0
	})

	d.RegisterAutoStubHandler(dll, "FCIFlushCabinet", func(ctx *ntapi.TrapContext) uint32 {
		handle := uint32(ctx.Arg(0))
		if _, ok := getFCIContext(handle); !ok {
			setLastErrorValue(ERROR_INVALID_HANDLE)
			ctx.SetReturn(0)
			return 0
		}
		ravelog.Logf("[cabinet] FCIFlushCabinet hfci=0x%x getNextCab=%t getNextCb=0x%x status=0x%x\n", handle, ctx.Arg(1) != 0, ctx.Arg(2), ctx.Arg(3))
		setLastErrorValue(0)
		ctx.SetReturn(1)
		return 0
	})

	d.RegisterAutoStubHandler(dll, "Extract", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[cabinet] Extract arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x arg4=0x%x arg5=0x%x\n",
			ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5))
		setLastErrorValue(0)
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(dll, "DeleteExtractedFiles", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[cabinet] DeleteExtractedFiles arg0=0x%x arg1=0x%x arg2=0x%x\n", ctx.Arg(0), ctx.Arg(1), ctx.Arg(2))
		setLastErrorValue(0)
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(dll, "CreateCompressor", func(ctx *ntapi.TrapContext) uint32 {
		algorithm := uint32(ctx.Arg(0))
		handlePtr := ctx.Arg(2)
		if handlePtr == 0 {
			setLastErrorValue(ERROR_INVALID_PARAMETER)
			ctx.SetReturn(0)
			return 0
		}
		if !cabinetSupportedAlgorithm(algorithm) {
			setLastErrorValue(ERROR_UNSUPPORTED_TYPE)
			ctx.SetReturn(0)
			return 0
		}
		handle := allocCompressorHandle(algorithm, false)
		_ = mem.Write64(handlePtr, uint64(handle))
		ravelog.Logf("[cabinet] CreateCompressor algorithm=%d allocRoutines=0x%x out=0x%x -> 0x%x\n", algorithm, ctx.Arg(1), handlePtr, handle)
		setLastErrorValue(0)
		ctx.SetReturn(1)
		return 0
	})

	d.RegisterAutoStubHandler(dll, "CloseCompressor", func(ctx *ntapi.TrapContext) uint32 {
		handle := uint32(ctx.Arg(0))
		if !deleteCompressor(handle, false) {
			setLastErrorValue(ERROR_INVALID_HANDLE)
			ctx.SetReturn(0)
			return 0
		}
		ravelog.Logf("[cabinet] CloseCompressor handle=0x%x\n", handle)
		setLastErrorValue(0)
		ctx.SetReturn(1)
		return 0
	})

	d.RegisterAutoStubHandler(dll, "Compress", func(ctx *ntapi.TrapContext) uint32 {
		handle := uint32(ctx.Arg(0))
		inputPtr := ctx.Arg(1)
		inputSize := ctx.Arg(2)
		outputPtr := ctx.Arg(3)
		outputSize := ctx.Arg(4)
		resultSizePtr := ctx.Arg(5)
		entry, ok := getCompressor(handle, false)
		if !ok {
			setLastErrorValue(ERROR_INVALID_HANDLE)
			ctx.SetReturn(0)
			return 0
		}
		input, ok := readBuffer(inputPtr, inputSize)
		if !ok {
			setLastErrorValue(ERROR_INVALID_PARAMETER)
			ctx.SetReturn(0)
			return 0
		}
		var output []byte
		var err error
		switch entry.algorithm {
		case COMPRESS_ALGORITHM_MSZIP:
			output, err = msZipCompress(input)
		case COMPRESS_ALGORITHM_NULL, COMPRESS_ALGORITHM_XPRESS, COMPRESS_ALGORITHM_XPRESS_HUFF, COMPRESS_ALGORITHM_LZMS:
			output = append([]byte(nil), input...)
		default:
			setLastErrorValue(ERROR_UNSUPPORTED_TYPE)
			ctx.SetReturn(0)
			return 0
		}
		if err != nil {
			setLastErrorValue(ERROR_UNSUPPORTED_TYPE)
			ctx.SetReturn(0)
			return 0
		}
		if !writeSizedBuffer(outputPtr, outputSize, resultSizePtr, output) {
			ctx.SetReturn(0)
			return 0
		}
		ravelog.Logf("[cabinet] Compress handle=0x%x algorithm=%d in=%d out=%d\n", handle, entry.algorithm, len(input), len(output))
		setLastErrorValue(0)
		ctx.SetReturn(1)
		return 0
	})

	d.RegisterAutoStubHandler(dll, "CreateDecompressor", func(ctx *ntapi.TrapContext) uint32 {
		algorithm := uint32(ctx.Arg(0))
		handlePtr := ctx.Arg(2)
		if handlePtr == 0 {
			setLastErrorValue(ERROR_INVALID_PARAMETER)
			ctx.SetReturn(0)
			return 0
		}
		if !cabinetSupportedAlgorithm(algorithm) {
			setLastErrorValue(ERROR_UNSUPPORTED_TYPE)
			ctx.SetReturn(0)
			return 0
		}
		handle := allocCompressorHandle(algorithm, true)
		_ = mem.Write64(handlePtr, uint64(handle))
		ravelog.Logf("[cabinet] CreateDecompressor algorithm=%d allocRoutines=0x%x out=0x%x -> 0x%x\n", algorithm, ctx.Arg(1), handlePtr, handle)
		setLastErrorValue(0)
		ctx.SetReturn(1)
		return 0
	})

	d.RegisterAutoStubHandler(dll, "CloseDecompressor", func(ctx *ntapi.TrapContext) uint32 {
		handle := uint32(ctx.Arg(0))
		if !deleteCompressor(handle, true) {
			setLastErrorValue(ERROR_INVALID_HANDLE)
			ctx.SetReturn(0)
			return 0
		}
		ravelog.Logf("[cabinet] CloseDecompressor handle=0x%x\n", handle)
		setLastErrorValue(0)
		ctx.SetReturn(1)
		return 0
	})

	d.RegisterAutoStubHandler(dll, "Decompress", func(ctx *ntapi.TrapContext) uint32 {
		handle := uint32(ctx.Arg(0))
		inputPtr := ctx.Arg(1)
		inputSize := ctx.Arg(2)
		outputPtr := ctx.Arg(3)
		outputSize := ctx.Arg(4)
		resultSizePtr := ctx.Arg(5)
		entry, ok := getCompressor(handle, true)
		if !ok {
			setLastErrorValue(ERROR_INVALID_HANDLE)
			ctx.SetReturn(0)
			return 0
		}
		input, ok := readBuffer(inputPtr, inputSize)
		if !ok {
			setLastErrorValue(ERROR_INVALID_PARAMETER)
			ctx.SetReturn(0)
			return 0
		}
		var output []byte
		var err error
		switch entry.algorithm {
		case COMPRESS_ALGORITHM_MSZIP:
			output, err = msZipDecompress(input)
		case COMPRESS_ALGORITHM_NULL, COMPRESS_ALGORITHM_XPRESS, COMPRESS_ALGORITHM_XPRESS_HUFF, COMPRESS_ALGORITHM_LZMS:
			output = append([]byte(nil), input...)
		default:
			setLastErrorValue(ERROR_UNSUPPORTED_TYPE)
			ctx.SetReturn(0)
			return 0
		}
		if err != nil {
			setLastErrorValue(ERROR_UNSUPPORTED_TYPE)
			ctx.SetReturn(0)
			return 0
		}
		if !writeSizedBuffer(outputPtr, outputSize, resultSizePtr, output) {
			ctx.SetReturn(0)
			return 0
		}
		ravelog.Logf("[cabinet] Decompress handle=0x%x algorithm=%d in=%d out=%d\n", handle, entry.algorithm, len(input), len(output))
		setLastErrorValue(0)
		ctx.SetReturn(1)
		return 0
	})

	d.RegisterAutoStubHandler(dll, "QueryCompressorInformation", func(ctx *ntapi.TrapContext) uint32 {
		handle := uint32(ctx.Arg(0))
		infoClass := uint32(ctx.Arg(1))
		infoPtr := ctx.Arg(2)
		infoSize := ctx.Arg(3)
		infoSizeNeeded := ctx.Arg(4)
		data, ok := queryCompressorInfo(handle, false, infoClass)
		if !ok {
			setLastErrorValue(ERROR_INVALID_HANDLE)
			ctx.SetReturn(0)
			return 0
		}
		if !writeSizedBuffer(infoPtr, infoSize, infoSizeNeeded, data) {
			ctx.SetReturn(0)
			return 0
		}
		ravelog.Logf("[cabinet] QueryCompressorInformation handle=0x%x class=%d size=%d -> %d\n", handle, infoClass, infoSize, len(data))
		setLastErrorValue(0)
		ctx.SetReturn(1)
		return 0
	})

	d.RegisterAutoStubHandler(dll, "QueryDecompressorInformation", func(ctx *ntapi.TrapContext) uint32 {
		handle := uint32(ctx.Arg(0))
		infoClass := uint32(ctx.Arg(1))
		infoPtr := ctx.Arg(2)
		infoSize := ctx.Arg(3)
		infoSizeNeeded := ctx.Arg(4)
		data, ok := queryCompressorInfo(handle, true, infoClass)
		if !ok {
			setLastErrorValue(ERROR_INVALID_HANDLE)
			ctx.SetReturn(0)
			return 0
		}
		if !writeSizedBuffer(infoPtr, infoSize, infoSizeNeeded, data) {
			ctx.SetReturn(0)
			return 0
		}
		ravelog.Logf("[cabinet] QueryDecompressorInformation handle=0x%x class=%d size=%d -> %d\n", handle, infoClass, infoSize, len(data))
		setLastErrorValue(0)
		ctx.SetReturn(1)
		return 0
	})

	d.RegisterAutoStubHandler(dll, "SetCompressorInformation", func(ctx *ntapi.TrapContext) uint32 {
		handle := uint32(ctx.Arg(0))
		infoClass := uint32(ctx.Arg(1))
		infoPtr := ctx.Arg(2)
		infoSize := ctx.Arg(3)
		data, ok := readBuffer(infoPtr, infoSize)
		if !ok {
			setLastErrorValue(ERROR_INVALID_PARAMETER)
			ctx.SetReturn(0)
			return 0
		}
		if !setCompressorInfo(handle, false, infoClass, data) {
			setLastErrorValue(ERROR_INVALID_HANDLE)
			ctx.SetReturn(0)
			return 0
		}
		ravelog.Logf("[cabinet] SetCompressorInformation handle=0x%x class=%d size=%d\n", handle, infoClass, len(data))
		setLastErrorValue(0)
		ctx.SetReturn(1)
		return 0
	})

	d.RegisterAutoStubHandler(dll, "SetDecompressorInformation", func(ctx *ntapi.TrapContext) uint32 {
		handle := uint32(ctx.Arg(0))
		infoClass := uint32(ctx.Arg(1))
		infoPtr := ctx.Arg(2)
		infoSize := ctx.Arg(3)
		data, ok := readBuffer(infoPtr, infoSize)
		if !ok {
			setLastErrorValue(ERROR_INVALID_PARAMETER)
			ctx.SetReturn(0)
			return 0
		}
		if !setCompressorInfo(handle, true, infoClass, data) {
			setLastErrorValue(ERROR_INVALID_HANDLE)
			ctx.SetReturn(0)
			return 0
		}
		ravelog.Logf("[cabinet] SetDecompressorInformation handle=0x%x class=%d size=%d\n", handle, infoClass, len(data))
		setLastErrorValue(0)
		ctx.SetReturn(1)
		return 0
	})

	d.RegisterAutoStubHandler(dll, "ResetCompressor", func(ctx *ntapi.TrapContext) uint32 {
		handle := uint32(ctx.Arg(0))
		if _, ok := getCompressor(handle, false); !ok {
			setLastErrorValue(ERROR_INVALID_HANDLE)
			ctx.SetReturn(0)
			return 0
		}
		ravelog.Logf("[cabinet] ResetCompressor handle=0x%x\n", handle)
		setLastErrorValue(0)
		ctx.SetReturn(1)
		return 0
	})

	d.RegisterAutoStubHandler(dll, "ResetDecompressor", func(ctx *ntapi.TrapContext) uint32 {
		handle := uint32(ctx.Arg(0))
		if _, ok := getCompressor(handle, true); !ok {
			setLastErrorValue(ERROR_INVALID_HANDLE)
			ctx.SetReturn(0)
			return 0
		}
		ravelog.Logf("[cabinet] ResetDecompressor handle=0x%x\n", handle)
		setLastErrorValue(0)
		ctx.SetReturn(1)
		return 0
	})
}

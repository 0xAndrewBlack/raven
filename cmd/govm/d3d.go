package main

import (
	"encoding/binary"
	"fmt"
	"math"
	"sync"

	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

const (
	d3dTrapIDBase = 0x15000000

	DXGI_ERROR_NOT_FOUND      = 0x887A0002
	DXGI_ERROR_DEVICE_REMOVED = 0x887A0005
	DXGI_ERROR_DEVICE_RESET   = 0x887A0007
	D3D_OK                    = 0
	D3DERR_NOTAVAILABLE       = 0x8876086A
	D3D_FEATURE_LEVEL_9_1     = 0x9100
	D3D_FEATURE_LEVEL_11_0    = 0xB000
	D3D_FEATURE_LEVEL_12_0    = 0xC000

	d3dFormatX8R8G8B8       = 22
	dxgiFormatR8G8B8A8Unorm = 28
	fakeMonitorHandle       = 0x0000000000010001
)

type dxgiState struct {
	mu          sync.Mutex
	nextFactory uint32
	nextAdapter uint32
	nextOutput  uint32
	factories   map[uint32]*dxgiFactory
	adapters    map[uint32]*dxgiAdapter
	outputs     map[uint32]*dxgiOutput
}

type dxgiFactory struct {
	adapters []uint32
}

type dxgiAdapter struct {
	desc          string
	vendorId      uint32
	deviceId      uint32
	dedicatedVRAM uint64
	outputs       []uint32
}

type dxgiOutput struct {
	desc   string
	left   int32
	top    int32
	right  int32
	bottom int32
}

var dxgiGlobal = dxgiState{
	nextFactory: 0xB000,
	nextAdapter: 0xB100,
	nextOutput:  0xB200,
	factories:   make(map[uint32]*dxgiFactory),
	adapters:    make(map[uint32]*dxgiAdapter),
	outputs:     make(map[uint32]*dxgiOutput),
}

type d3dCOMObject struct {
	objectAddr uint64
	kind       string
	id         uint32
	refCount   uint32
	dispatch   func(ctx *ntapi.TrapContext, method int, obj *d3dCOMObject) uint32
}

var (
	d3dCOMMu         sync.Mutex
	d3dCOMNextTrapID uint32 = d3dTrapIDBase
	d3dCOMObjects           = map[uint64]*d3dCOMObject{}
)

func registerD3dHandlers(hctx *HandlerCtx) {
	d := hctx.Disp

	if dll, ok := hctx.SynthByName["dxgi.dll"]; ok {
		registerDxgiHandlers(hctx, dll)
	}
	if dll, ok := hctx.SynthByName["d3d9.dll"]; ok {
		registerD3d9Handlers(hctx, dll)
	}
	if dll, ok := hctx.SynthByName["d3d11.dll"]; ok {
		registerD3d11HandlersBridge(hctx, dll)
	}
	if dll, ok := hctx.SynthByName["d3d12.dll"]; ok {
		registerD3d12Handlers(hctx, dll)
	}

	_ = d
}

func registerDxgiHandlers(hctx *HandlerCtx, dll *ntapi.SynthPE) {
	d := hctx.Disp
	registerFactory := func() uint64 {
		return dxgiCreateFactory(hctx)
	}
	d.RegisterAutoStubHandler(dll, "CreateDXGIFactory", func(ctx *ntapi.TrapContext) uint32 {
		ppFactory := ctx.Arg(1)
		if ppFactory == 0 {
			ctx.SetReturn(E_POINTER)
			return 0
		}
		ctx.Mem.Write64(ppFactory, 0)
		obj := registerFactory()
		if obj == 0 {
			ctx.SetReturn(E_OUTOFMEMORY)
			return 0
		}
		ctx.Mem.Write64(ppFactory, obj)
		ctx.SetReturn(S_OK)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CreateDXGIFactory1", func(ctx *ntapi.TrapContext) uint32 {
		ppFactory := ctx.Arg(1)
		if ppFactory == 0 {
			ctx.SetReturn(E_POINTER)
			return 0
		}
		ctx.Mem.Write64(ppFactory, 0)
		obj := registerFactory()
		if obj == 0 {
			ctx.SetReturn(E_OUTOFMEMORY)
			return 0
		}
		ctx.Mem.Write64(ppFactory, obj)
		ctx.SetReturn(S_OK)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "CreateDXGIFactory2", func(ctx *ntapi.TrapContext) uint32 {
		ppFactory := ctx.Arg(2)
		if ppFactory == 0 {
			ctx.SetReturn(E_POINTER)
			return 0
		}
		ctx.Mem.Write64(ppFactory, 0)
		obj := registerFactory()
		if obj == 0 {
			ctx.SetReturn(E_OUTOFMEMORY)
			return 0
		}
		ctx.Mem.Write64(ppFactory, obj)
		ctx.SetReturn(S_OK)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "DXGIGetDebugInterface1", func(ctx *ntapi.TrapContext) uint32 {
		if ppv := ctx.Arg(2); ppv != 0 {
			ctx.Mem.Write64(ppv, 0)
		}
		ctx.SetReturn(E_NOINTERFACE)
		return 0
	})
}

func registerD3d9Handlers(hctx *HandlerCtx, dll *ntapi.SynthPE) {
	d := hctx.Disp
	d.RegisterAutoStubHandler(dll, "Direct3DCreate9", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(d3d9CreateObject(hctx))
		return 0
	})
	d.RegisterAutoStubHandler(dll, "Direct3DCreate9Ex", func(ctx *ntapi.TrapContext) uint32 {
		ppD3D := ctx.Arg(1)
		if ppD3D == 0 {
			ctx.SetReturn(E_POINTER)
			return 0
		}
		ctx.Mem.Write64(ppD3D, 0)
		obj := d3d9CreateObject(hctx)
		if obj == 0 {
			ctx.SetReturn(E_OUTOFMEMORY)
			return 0
		}
		ctx.Mem.Write64(ppD3D, obj)
		ctx.SetReturn(S_OK)
		return 0
	})

	for _, name := range []string{
		"D3DPERF_BeginEvent",
		"D3DPERF_EndEvent",
		"D3DPERF_SetMarker",
		"D3DPERF_SetOptions",
		"D3DPERF_GetStatus",
		"D3DPERF_QueryRepeatFrame",
		"D3DPERF_SetRegion",
	} {
		d.RegisterAutoStubHandler(dll, name, func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0
		})
	}
}

func registerD3d11HandlersBridge(hctx *HandlerCtx, dll *ntapi.SynthPE) {
	d := hctx.Disp
	d.RegisterAutoStubHandler(dll, "D3D11CreateDevice", func(ctx *ntapi.TrapContext) uint32 {
		ppDevice := ctx.Arg(7)
		pFeatureLevel := ctx.Arg(8)
		ppImmediateContext := ctx.Arg(9)
		// pFeatureLevel output: always report D3D_FEATURE_LEVEL_11_0
		if pFeatureLevel != 0 {
			ctx.Mem.Write32(pFeatureLevel, D3D_FEATURE_LEVEL_11_0)
		}
		if ppDevice == 0 {
			// Capability-check only (ppDevice == NULL): report success.
			if ppImmediateContext != 0 {
				ctx.Mem.Write64(ppImmediateContext, 0)
			}
			ctx.SetReturn(S_OK)
			return 0
		}
		devObj := d3d11CreateDevice(hctx)
		if devObj == 0 {
			ctx.Mem.Write64(ppDevice, 0)
			if ppImmediateContext != 0 {
				ctx.Mem.Write64(ppImmediateContext, 0)
			}
			ctx.SetReturn(E_OUTOFMEMORY)
			return 0
		}
		ctx.Mem.Write64(ppDevice, devObj)
		if ppImmediateContext != 0 {
			icObj := d3d11CreateContext(ctx.Mem, ctx.Disp)
			ctx.Mem.Write64(ppImmediateContext, icObj)
		}
		ctx.SetReturn(S_OK)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "D3D11CreateDeviceAndSwapChain", func(ctx *ntapi.TrapContext) uint32 {
		// Arg layout: pAdapter(0) DriverType(1) Software(2) Flags(3)
		// pFeatureLevels(4) FeatureLevels(5) SDKVersion(6) pSwapChainDesc(7)
		// ppSwapChain(8) ppDevice(9) pFeatureLevel(10) ppImmediateContext(11)
		ppSwapChain := ctx.Arg(8)
		ppDevice := ctx.Arg(9)
		pFeatureLevel := ctx.Arg(10)
		ppImmediateContext := ctx.Arg(11)
		if ppSwapChain != 0 {
			ctx.Mem.Write64(ppSwapChain, 0)
		}
		if pFeatureLevel != 0 {
			ctx.Mem.Write32(pFeatureLevel, D3D_FEATURE_LEVEL_11_0)
		}
		if ppDevice == 0 {
			if ppImmediateContext != 0 {
				ctx.Mem.Write64(ppImmediateContext, 0)
			}
			ctx.SetReturn(S_OK)
			return 0
		}
		devObj := d3d11CreateDevice(hctx)
		if devObj == 0 {
			ctx.Mem.Write64(ppDevice, 0)
			if ppImmediateContext != 0 {
				ctx.Mem.Write64(ppImmediateContext, 0)
			}
			ctx.SetReturn(E_OUTOFMEMORY)
			return 0
		}
		ctx.Mem.Write64(ppDevice, devObj)
		if ppImmediateContext != 0 {
			icObj := d3d11CreateContext(ctx.Mem, ctx.Disp)
			ctx.Mem.Write64(ppImmediateContext, icObj)
		}
		// SwapChain creation is unsupported in software emulation.
		ctx.SetReturn(E_NOTIMPL)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "D3D11On12CreateDevice", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(E_NOTIMPL)
		return 0
	})
}

func registerD3d12Handlers(hctx *HandlerCtx, dll *ntapi.SynthPE) {
	d := hctx.Disp
	d.RegisterAutoStubHandler(dll, "D3D12CreateDevice", func(ctx *ntapi.TrapContext) uint32 {
		if ppDevice := ctx.Arg(3); ppDevice != 0 {
			ctx.Mem.Write64(ppDevice, 0)
		}
		ctx.SetReturn(E_NOTIMPL)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "D3D12GetDebugInterface", func(ctx *ntapi.TrapContext) uint32 {
		if ppvDebug := ctx.Arg(1); ppvDebug != 0 {
			ctx.Mem.Write64(ppvDebug, 0)
		}
		ctx.SetReturn(E_NOINTERFACE)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "D3D12SerializeRootSignature", func(ctx *ntapi.TrapContext) uint32 {
		if ppBlob := ctx.Arg(2); ppBlob != 0 {
			ctx.Mem.Write64(ppBlob, 0)
		}
		if ppErrorBlob := ctx.Arg(3); ppErrorBlob != 0 {
			ctx.Mem.Write64(ppErrorBlob, 0)
		}
		ctx.SetReturn(E_NOTIMPL)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "D3D12CreateRootSignatureDeserializer", func(ctx *ntapi.TrapContext) uint32 {
		if ppDeserializer := ctx.Arg(3); ppDeserializer != 0 {
			ctx.Mem.Write64(ppDeserializer, 0)
		}
		ctx.SetReturn(E_NOTIMPL)
		return 0
	})
}

func dxgiCreateFactory(hctx *HandlerCtx) uint64 {
	dxgiGlobal.mu.Lock()
	factoryID := dxgiGlobal.nextFactory
	dxgiGlobal.nextFactory++
	adapterID := dxgiGlobal.nextAdapter
	dxgiGlobal.nextAdapter++
	outputID := dxgiGlobal.nextOutput
	dxgiGlobal.nextOutput++
	dxgiGlobal.factories[factoryID] = &dxgiFactory{adapters: []uint32{adapterID}}
	dxgiGlobal.adapters[adapterID] = &dxgiAdapter{
		desc:          "Raven Virtual GPU",
		vendorId:      0x1AF4,
		deviceId:      0x1000,
		dedicatedVRAM: 2 << 30,
		outputs:       []uint32{outputID},
	}
	dxgiGlobal.outputs[outputID] = &dxgiOutput{
		desc:   "Raven Display",
		left:   0,
		top:    0,
		right:  1920,
		bottom: 1080,
	}
	dxgiGlobal.mu.Unlock()
	return d3dCreateCOMObject(hctx, "dxgi-factory", 8, factoryID, dxgiDispatchFactory)
}

func dxgiDispatchFactory(ctx *ntapi.TrapContext, method int, obj *d3dCOMObject) uint32 {
	switch method {
	case 3:
		index := uint32(ctx.Arg(1))
		ppAdapter := ctx.Arg(2)
		if ppAdapter == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppAdapter, 0)
		dxgiGlobal.mu.Lock()
		factory := dxgiGlobal.factories[obj.id]
		var adapterID uint32
		if factory != nil && int(index) < len(factory.adapters) {
			adapterID = factory.adapters[index]
		}
		dxgiGlobal.mu.Unlock()
		if adapterID == 0 {
			return DXGI_ERROR_NOT_FOUND
		}
		adapterObj := d3dCreateCOMObjectFromID(ctx.Mem, ctx.Disp, "dxgi-adapter", 6, adapterID, dxgiDispatchAdapter)
		if adapterObj == 0 {
			return E_OUTOFMEMORY
		}
		ctx.Mem.Write64(ppAdapter, adapterObj)
		return S_OK
	case 4:
		return S_OK
	case 5:
		if pWindowHandle := ctx.Arg(1); pWindowHandle != 0 {
			ctx.Mem.Write64(pWindowHandle, 0)
		}
		return S_OK
	case 6:
		if ppSwapChain := ctx.Arg(3); ppSwapChain != 0 {
			ctx.Mem.Write64(ppSwapChain, 0)
		}
		return E_NOTIMPL
	case 7:
		if ppAdapter := ctx.Arg(2); ppAdapter != 0 {
			ctx.Mem.Write64(ppAdapter, 0)
		}
		return E_NOTIMPL
	default:
		return E_NOTIMPL
	}
}

func dxgiDispatchAdapter(ctx *ntapi.TrapContext, method int, obj *d3dCOMObject) uint32 {
	switch method {
	case 3:
		index := uint32(ctx.Arg(1))
		ppOutput := ctx.Arg(2)
		if ppOutput == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppOutput, 0)
		dxgiGlobal.mu.Lock()
		adapter := dxgiGlobal.adapters[obj.id]
		var outputID uint32
		if adapter != nil && int(index) < len(adapter.outputs) {
			outputID = adapter.outputs[index]
		}
		dxgiGlobal.mu.Unlock()
		if outputID == 0 {
			return DXGI_ERROR_NOT_FOUND
		}
		outputObj := d3dCreateCOMObjectFromID(ctx.Mem, ctx.Disp, "dxgi-output", 7, outputID, dxgiDispatchOutput)
		if outputObj == 0 {
			return E_OUTOFMEMORY
		}
		ctx.Mem.Write64(ppOutput, outputObj)
		return S_OK
	case 4:
		pDesc := ctx.Arg(1)
		if pDesc == 0 {
			return E_POINTER
		}
		dxgiGlobal.mu.Lock()
		adapter := dxgiGlobal.adapters[obj.id]
		dxgiGlobal.mu.Unlock()
		if adapter == nil {
			return E_POINTER
		}
		writeDXGIAdapterDesc(ctx.Mem, pDesc, adapter)
		return S_OK
	case 5:
		if pUMDVersion := ctx.Arg(2); pUMDVersion != 0 {
			ctx.Mem.Write64(pUMDVersion, 0)
		}
		return S_OK
	default:
		return E_NOTIMPL
	}
}

func dxgiDispatchOutput(ctx *ntapi.TrapContext, method int, obj *d3dCOMObject) uint32 {
	switch method {
	case 3:
		pDesc := ctx.Arg(1)
		if pDesc == 0 {
			return E_POINTER
		}
		dxgiGlobal.mu.Lock()
		output := dxgiGlobal.outputs[obj.id]
		dxgiGlobal.mu.Unlock()
		if output == nil {
			return E_POINTER
		}
		writeDXGIOutputDesc(ctx.Mem, pDesc, output)
		return S_OK
	case 4:
		enumFormat := uint32(ctx.Arg(1))
		pNumModes := ctx.Arg(3)
		pDesc := ctx.Arg(4)
		if pNumModes == 0 {
			return E_POINTER
		}
		modeCount := uint32(3)
		if pDesc == 0 {
			ctx.Mem.Write32(pNumModes, modeCount)
			return S_OK
		}
		requested, _ := ctx.Mem.Read32(pNumModes)
		if requested == 0 || requested > modeCount {
			requested = modeCount
		}
		for i := uint32(0); i < requested; i++ {
			width, height := d3dModeDimensions(i)
			writeDXGIModeDesc(ctx.Mem, pDesc+uint64(i)*28, width, height, enumFormat)
		}
		ctx.Mem.Write32(pNumModes, modeCount)
		return S_OK
	case 5:
		pClosestMatch := ctx.Arg(2)
		if pClosestMatch == 0 {
			return E_POINTER
		}
		format := uint32(dxgiFormatR8G8B8A8Unorm)
		if pModeToMatch := ctx.Arg(1); pModeToMatch != 0 {
			if v, err := ctx.Mem.Read32(pModeToMatch + 16); err == nil && v != 0 {
				format = v
			}
		}
		writeDXGIModeDesc(ctx.Mem, pClosestMatch, 1920, 1080, format)
		return S_OK
	case 6:
		return S_OK
	default:
		return E_NOTIMPL
	}
}

func d3d9CreateObject(hctx *HandlerCtx) uint64 {
	return d3dCreateCOMObject(hctx, "d3d9", 17, 0, d3d9Dispatch)
}

func d3d9Dispatch(ctx *ntapi.TrapContext, method int, obj *d3dCOMObject) uint32 {
	_ = obj
	switch method {
	case 3:
		return D3D_OK
	case 4:
		ctx.SetReturn(1)
		return 0
	case 5:
		pIdentifier := ctx.Arg(3)
		if pIdentifier == 0 {
			return E_POINTER
		}
		writeD3DAdapterIdentifier(ctx.Mem, pIdentifier)
		return D3D_OK
	case 6:
		ctx.SetReturn(3)
		return 0
	case 7:
		mode := uint32(ctx.Arg(3))
		pMode := ctx.Arg(4)
		if pMode == 0 {
			return E_POINTER
		}
		if mode >= 3 {
			return D3DERR_NOTAVAILABLE
		}
		width, height := d3dModeDimensions(mode)
		writeD3DDisplayMode(ctx.Mem, pMode, width, height)
		return D3D_OK
	case 8:
		pMode := ctx.Arg(2)
		if pMode == 0 {
			return E_POINTER
		}
		writeD3DDisplayMode(ctx.Mem, pMode, 1920, 1080)
		return D3D_OK
	case 9, 10, 11, 12, 13:
		return D3D_OK
	case 14:
		pCaps := ctx.Arg(3)
		if pCaps == 0 {
			return E_POINTER
		}
		writeD3DCaps9(ctx.Mem, pCaps)
		return D3D_OK
	case 15:
		ctx.SetReturn(fakeMonitorHandle)
		return 0
	case 16:
		if ppDevice := ctx.Arg(6); ppDevice != 0 {
			ctx.Mem.Write64(ppDevice, 0)
		}
		return D3DERR_NOTAVAILABLE
	default:
		return E_NOTIMPL
	}
}

func d3dCreateCOMObject(hctx *HandlerCtx, kind string, methods int, id uint32, dispatch func(ctx *ntapi.TrapContext, method int, obj *d3dCOMObject) uint32) uint64 {
	return d3dCreateCOMObjectFromID(hctx.Mem, hctx.Disp, kind, methods, id, dispatch)
}

func d3dCreateCOMObjectFromID(mem *mmu.MMU, disp *ntapi.Dispatcher, kind string, methods int, id uint32, dispatch func(ctx *ntapi.TrapContext, method int, obj *d3dCOMObject) uint32) uint64 {
	if methods < 3 {
		methods = 3
	}
	totalSize := uint64(8 + methods*8 + methods*16)
	objAddr := mem.Mmap(0, totalSize, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	if objAddr == 0 {
		return 0
	}
	vtableAddr := objAddr + 8
	stubBase := vtableAddr + uint64(methods*8)
	obj := &d3dCOMObject{
		objectAddr: objAddr,
		kind:       kind,
		id:         id,
		refCount:   1,
		dispatch:   dispatch,
	}

	d3dCOMMu.Lock()
	d3dCOMObjects[objAddr] = obj
	for i := 0; i < methods; i++ {
		trapID := d3dCOMNextTrapID
		d3dCOMNextTrapID++
		methodIndex := i
		disp.RegisterHandler(trapID, fmt.Sprintf("d3d!%s[%d]", kind, methodIndex), func(ctx *ntapi.TrapContext) uint32 {
			return d3dDispatchCOMMethod(ctx, methodIndex)
		})
		stubAddr := stubBase + uint64(i*16)
		code := make([]byte, 16)
		code[0] = 0xB8
		binary.LittleEndian.PutUint32(code[1:5], trapID)
		code[5] = 0x0F
		code[6] = 0x01
		code[7] = 0xC1
		code[8] = 0xC3
		for j := 9; j < len(code); j++ {
			code[j] = 0xCC
		}
		mem.WriteBytes(stubAddr, code)
		mem.Write64(vtableAddr+uint64(i*8), stubAddr)
	}
	d3dCOMMu.Unlock()

	mem.Write64(objAddr, vtableAddr)
	return objAddr
}

func d3dDispatchCOMMethod(ctx *ntapi.TrapContext, method int) uint32 {
	thisPtr := ctx.Arg(0)
	d3dCOMMu.Lock()
	obj := d3dCOMObjects[thisPtr]
	if obj == nil {
		d3dCOMMu.Unlock()
		return E_POINTER
	}
	switch method {
	case 0:
		ppv := ctx.Arg(2)
		if ppv == 0 {
			d3dCOMMu.Unlock()
			return E_POINTER
		}
		ctx.Mem.Write64(ppv, thisPtr)
		obj.refCount++
		d3dCOMMu.Unlock()
		return S_OK
	case 1:
		obj.refCount++
		count := obj.refCount
		d3dCOMMu.Unlock()
		ctx.SetReturn(uint64(count))
		return 0
	case 2:
		if obj.refCount > 0 {
			obj.refCount--
		}
		count := obj.refCount
		if count == 0 {
			delete(d3dCOMObjects, thisPtr)
		}
		d3dCOMMu.Unlock()
		ctx.SetReturn(uint64(count))
		return 0
	default:
		dispatch := obj.dispatch
		d3dCOMMu.Unlock()
		if dispatch == nil {
			return E_NOTIMPL
		}
		return dispatch(ctx, method, obj)
	}
}

func writeFixedCString(mem *mmu.MMU, addr uint64, size int, value string) {
	buf := make([]byte, size)
	copy(buf, []byte(value))
	mem.WriteBytes(addr, buf)
}

func writeUTF16Fixed(mem *mmu.MMU, addr uint64, chars int, value string) {
	enc := utf16Encode(value)
	if len(enc) >= chars {
		enc = enc[:chars-1]
	}
	for i := 0; i < chars; i++ {
		var v uint16
		if i < len(enc) {
			v = enc[i]
		}
		mem.Write16(addr+uint64(i*2), v)
	}
}

func writeFloat32(mem *mmu.MMU, addr uint64, value float32) {
	mem.Write32(addr, math.Float32bits(value))
}

func writeDXGIAdapterDesc(mem *mmu.MMU, addr uint64, adapter *dxgiAdapter) {
	mem.WriteBytes(addr, make([]byte, 304))
	writeUTF16Fixed(mem, addr, 128, adapter.desc)
	mem.Write32(addr+256, adapter.vendorId)
	mem.Write32(addr+260, adapter.deviceId)
	mem.Write32(addr+264, 0x00001000)
	mem.Write32(addr+268, 1)
	mem.Write64(addr+272, adapter.dedicatedVRAM)
	mem.Write64(addr+280, 0)
	mem.Write64(addr+288, 2<<30)
	mem.Write64(addr+296, 0x524156454E000001)
}

func writeDXGIOutputDesc(mem *mmu.MMU, addr uint64, output *dxgiOutput) {
	mem.WriteBytes(addr, make([]byte, 96))
	writeUTF16Fixed(mem, addr, 32, output.desc)
	mem.Write32(addr+64, uint32(output.left))
	mem.Write32(addr+68, uint32(output.top))
	mem.Write32(addr+72, uint32(output.right))
	mem.Write32(addr+76, uint32(output.bottom))
	mem.Write32(addr+80, 1)
	mem.Write32(addr+84, 1)
	mem.Write64(addr+88, fakeMonitorHandle)
}

func writeDXGIModeDesc(mem *mmu.MMU, addr uint64, width, height uint32, format uint32) {
	if format == 0 {
		format = dxgiFormatR8G8B8A8Unorm
	}
	mem.Write32(addr+0, width)
	mem.Write32(addr+4, height)
	mem.Write32(addr+8, 60)
	mem.Write32(addr+12, 1)
	mem.Write32(addr+16, format)
	mem.Write32(addr+20, 0)
	mem.Write32(addr+24, 0)
}

func writeD3DDisplayMode(mem *mmu.MMU, addr uint64, width, height uint32) {
	mem.Write32(addr+0, width)
	mem.Write32(addr+4, height)
	mem.Write32(addr+8, 60)
	mem.Write32(addr+12, d3dFormatX8R8G8B8)
}

func writeD3DAdapterIdentifier(mem *mmu.MMU, addr uint64) {
	mem.WriteBytes(addr, make([]byte, 1100))
	writeFixedCString(mem, addr+0, 512, "ravend3d9.dll")
	writeFixedCString(mem, addr+512, 512, "Raven Virtual GPU")
	writeFixedCString(mem, addr+1024, 32, "\\\\.\\DISPLAY1")
	mem.Write64(addr+1056, 0x0001000000000000)
	mem.Write32(addr+1064, 0x1AF4)
	mem.Write32(addr+1068, 0x1000)
	mem.Write32(addr+1072, 0x00001000)
	mem.Write32(addr+1076, 1)
	writeGUID(mem, addr+1080, GUID{0x5256414E, 0x4453, 0x4439, [8]byte{0x56, 0x47, 0x50, 0x55, 0x00, 0x00, 0x00, 0x01}})
	mem.Write32(addr+1096, 1)
}

func writeD3DCaps9(mem *mmu.MMU, addr uint64) {
	mem.WriteBytes(addr, make([]byte, 304))
	mem.Write32(addr+0, 1)
	mem.Write32(addr+4, 0)
	mem.Write32(addr+8, 0x00020000)
	mem.Write32(addr+28, 0x00100000)
	mem.Write32(addr+32, 0x0000FFFF)
	mem.Write32(addr+36, 0x001F7FFF)
	mem.Write32(addr+56, 0x00084208)
	mem.Write32(addr+60, 0x0001EC03)
	mem.Write32(addr+64, 0x03FFFFFF)
	mem.Write32(addr+76, 0x0000001F)
	mem.Write32(addr+88, 16384)
	mem.Write32(addr+92, 16384)
	mem.Write32(addr+96, 2048)
	mem.Write32(addr+100, 8192)
	mem.Write32(addr+104, 16384)
	mem.Write32(addr+108, 16)
	writeFloat32(mem, addr+112, 1.0)
	writeFloat32(mem, addr+116, -8192.0)
	writeFloat32(mem, addr+120, 8192.0)
	writeFloat32(mem, addr+124, 8192.0)
	writeFloat32(mem, addr+128, -8192.0)
	writeFloat32(mem, addr+132, 0.0)
	mem.Write32(addr+140, 0x0008FFFF)
	mem.Write32(addr+144, 0x03FFFFFF)
	mem.Write32(addr+148, 8)
	mem.Write32(addr+152, 8)
	mem.Write32(addr+156, 0x0000011B)
	mem.Write32(addr+160, 8)
	mem.Write32(addr+164, 6)
	mem.Write32(addr+168, 4)
	mem.Write32(addr+172, 255)
	writeFloat32(mem, addr+176, 8192.0)
	mem.Write32(addr+180, 1048575)
	mem.Write32(addr+184, 16777215)
	mem.Write32(addr+188, 16)
	mem.Write32(addr+192, 255)
	mem.Write32(addr+196, 0xFFFE0300)
	mem.Write32(addr+200, 256)
	mem.Write32(addr+204, 0xFFFF0300)
	writeFloat32(mem, addr+208, 65504.0)
	mem.Write32(addr+212, 1)
	writeFloat32(mem, addr+216, 1.0)
	mem.Write32(addr+224, 0)
	mem.Write32(addr+228, 0)
	mem.Write32(addr+232, 1)
	mem.Write32(addr+236, 0xFFFFFFFF)
	mem.Write32(addr+240, 4)
	mem.Write32(addr+244, 0x00003000)
	mem.Write32(addr+248, 0x0000FFFF)
	mem.Write32(addr+252, 24)
	mem.Write32(addr+256, 32)
	mem.Write32(addr+260, 4)
	mem.Write32(addr+264, 0x0000FFFF)
	mem.Write32(addr+268, 24)
	mem.Write32(addr+272, 32)
	mem.Write32(addr+276, 4)
	mem.Write32(addr+280, 512)
	mem.Write32(addr+284, 0x03FFFFFF)
	mem.Write32(addr+288, 65535)
	mem.Write32(addr+292, 65535)
	mem.Write32(addr+296, 32768)
	mem.Write32(addr+300, 32768)
}

func d3dModeDimensions(index uint32) (uint32, uint32) {
	switch index {
	case 0:
		return 1920, 1080
	case 1:
		return 1280, 720
	default:
		return 3840, 2160
	}
}

// ---- D3D11 device and device-context COM stubs ----
//
// ID3D11Device vtable has 43 entries (methods 0-42).
// ID3D11DeviceContext vtable has 121 entries (methods 0-120).
// We implement the IUnknown trio via d3dDispatchCOMMethod and handle the
// small set of methods that matter for feature-detection and context retrieval.

const (
	d3d11DeviceMethods  = 43
	d3d11ContextMethods = 121
)

func d3d11CreateDevice(hctx *HandlerCtx) uint64 {
	return d3dCreateCOMObject(hctx, "d3d11-device", d3d11DeviceMethods, 0, d3d11DeviceDispatch)
}

func d3d11CreateContext(mem *mmu.MMU, disp *ntapi.Dispatcher) uint64 {
	return d3dCreateCOMObjectFromID(mem, disp, "d3d11-context", d3d11ContextMethods, 0, d3d11ContextDispatch)
}

func d3d11DeviceDispatch(ctx *ntapi.TrapContext, method int, obj *d3dCOMObject) uint32 {
	switch method {
	case 37: // GetFeatureLevel → D3D_FEATURE_LEVEL_11_0 returned in EAX
		ctx.SetReturn(D3D_FEATURE_LEVEL_11_0)
		return 0
	case 38: // GetCreationFlags → 0
		ctx.SetReturn(0)
		return 0
	case 39: // GetDeviceRemovedReason → S_OK (device not removed)
		return S_OK
	case 40: // GetImmediateContext(ppImmediateContext)
		ppIC := ctx.Arg(1)
		if ppIC == 0 {
			return E_POINTER
		}
		icObj := d3d11CreateContext(ctx.Mem, ctx.Disp)
		ctx.Mem.Write64(ppIC, icObj)
		return S_OK
	case 41: // SetExceptionMode → S_OK
		return S_OK
	case 42: // GetExceptionMode → 0 (no exception mode flags)
		ctx.SetReturn(0)
		return 0
	default:
		return E_NOTIMPL
	}
}

// d3d11ContextDispatch handles ID3D11DeviceContext methods beyond IUnknown.
// Most are fire-and-forget "set" commands; we acknowledge them silently.
func d3d11ContextDispatch(ctx *ntapi.TrapContext, method int, obj *d3dCOMObject) uint32 {
	// GetDevice (method 3 on ID3D11DeviceChild, inherited)
	if method == 3 {
		if ppDevice := ctx.Arg(1); ppDevice != 0 {
			ctx.Mem.Write64(ppDevice, 0) // no back-reference to device
		}
		return S_OK
	}
	// Flush (method 114) and similar state-sync ops succeed silently.
	return S_OK
}

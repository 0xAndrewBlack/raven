package main

import (
	"encoding/binary"
	"fmt"
	"math"
	"sync"

	"github.com/mirkobrombin/Raven/pkg/d3d9"
	"github.com/mirkobrombin/Raven/pkg/dxgi"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

const (
	d3dTrapIDBase = 0x15000000

	DXGI_ERROR_DEVICE_REMOVED = 0x887A0005
	DXGI_ERROR_DEVICE_RESET   = 0x887A0007
	D3D_OK                    = 0
	D3DERR_NOTAVAILABLE       = 0x8876086A
	D3D_FEATURE_LEVEL_9_1     = 0x9100
	D3D_FEATURE_LEVEL_11_0    = 0xB000
	D3D_FEATURE_LEVEL_12_0    = 0xC000

	d3dFormatX8R8G8B8 = 22
	fakeMonitorHandle = 0x0000000000010001
)

type dxgiState struct {
	mu            sync.Mutex
	nextFactory   uint32
	nextAdapter   uint32
	nextOutput    uint32
	nextSwapChain uint32
	nextTexture   uint32
	factories     map[uint32]*dxgi.Factory
	adapters      map[uint32]*dxgi.Adapter
	outputs       map[uint32]*dxgi.Output
	swapChains    map[uint32]*dxgiSwapChainRecord
	textures      map[uint32]*dxgiTextureRecord
}

type dxgiSwapChainRecord struct {
	chain     *dxgi.SwapChain
	deviceObj uint64
}

type dxgiTextureRecord struct {
	texture     *dxgi.Texture2D
	deviceObj   uint64
	swapChainID uint32
}

var dxgiGlobal = dxgiState{
	nextFactory:   0xB000,
	nextAdapter:   0xB100,
	nextOutput:    0xB200,
	nextSwapChain: 0xB300,
	nextTexture:   0xB400,
	factories:     make(map[uint32]*dxgi.Factory),
	adapters:      make(map[uint32]*dxgi.Adapter),
	outputs:       make(map[uint32]*dxgi.Output),
	swapChains:    make(map[uint32]*dxgiSwapChainRecord),
	textures:      make(map[uint32]*dxgiTextureRecord),
}

type d3dCOMObject struct {
	objectAddr uint64
	kind       string
	id         uint32
	refCount   uint32
	payload    any
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
	defer dxgiGlobal.mu.Unlock()

	factoryID := dxgiGlobal.nextFactory
	dxgiGlobal.nextFactory++
	factory := dxgi.NewFactory()
	dxgiGlobal.factories[factoryID] = factory
	for i := uint32(0); ; i++ {
		adapter, hr := factory.EnumAdapters(i)
		if hr != dxgi.S_OK || adapter == nil {
			break
		}
		adapterID := dxgiGlobal.nextAdapter
		dxgiGlobal.nextAdapter++
		dxgiGlobal.adapters[adapterID] = adapter
		for j := uint32(0); ; j++ {
			output, outHR := adapter.EnumOutputs(j)
			if outHR != dxgi.S_OK || output == nil {
				break
			}
			outputID := dxgiGlobal.nextOutput
			dxgiGlobal.nextOutput++
			dxgiGlobal.outputs[outputID] = output
		}
	}
	return d3dCreatePayloadCOMObjectFromID(hctx.Mem, hctx.Disp, "dxgi-factory", 12, factoryID, hctx, dxgiDispatchFactory)
}

func dxgiDispatchFactory(ctx *ntapi.TrapContext, method int, obj *d3dCOMObject) uint32 {
	hctx, _ := obj.payload.(*HandlerCtx)
	if handled, hr := dxgiDispatchObjectCommon(ctx, method); handled {
		return hr
	}
	switch method {
	case 7:
		index := uint32(ctx.Arg(1))
		ppAdapter := ctx.Arg(2)
		if ppAdapter == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppAdapter, 0)
		dxgiGlobal.mu.Lock()
		factory := dxgiGlobal.factories[obj.id]
		var adapterID uint32
		if factory != nil {
			if adapter, hr := factory.EnumAdapters(index); hr == dxgi.S_OK {
				adapterID = dxgiFindAdapterIDLocked(adapter)
			}
		}
		dxgiGlobal.mu.Unlock()
		if adapterID == 0 {
			return dxgi.DXGI_ERROR_NOT_FOUND
		}
		adapterObj := d3dCreateCOMObjectFromID(ctx.Mem, ctx.Disp, "dxgi-adapter", 10, adapterID, dxgiDispatchAdapter)
		if adapterObj == 0 {
			return E_OUTOFMEMORY
		}
		ctx.Mem.Write64(ppAdapter, adapterObj)
		return S_OK
	case 8:
		return S_OK
	case 9:
		if pWindowHandle := ctx.Arg(1); pWindowHandle != 0 {
			ctx.Mem.Write64(pWindowHandle, 0)
		}
		return S_OK
	case 10:
		ppSwapChain := ctx.Arg(3)
		if ppSwapChain == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppSwapChain, 0)
		swapChainObj := dxgiCreateSwapChainObject(hctx, ctx.Arg(1), ctx.Arg(2))
		if swapChainObj == 0 {
			return E_OUTOFMEMORY
		}
		ctx.Mem.Write64(ppSwapChain, swapChainObj)
		return S_OK
	case 11:
		if ppAdapter := ctx.Arg(2); ppAdapter != 0 {
			ctx.Mem.Write64(ppAdapter, 0)
		}
		return E_NOTIMPL
	default:
		return E_NOTIMPL
	}
}

func dxgiDispatchAdapter(ctx *ntapi.TrapContext, method int, obj *d3dCOMObject) uint32 {
	if handled, hr := dxgiDispatchObjectCommon(ctx, method); handled {
		return hr
	}
	switch method {
	case 7:
		index := uint32(ctx.Arg(1))
		ppOutput := ctx.Arg(2)
		if ppOutput == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppOutput, 0)
		dxgiGlobal.mu.Lock()
		adapter := dxgiGlobal.adapters[obj.id]
		var outputID uint32
		if adapter != nil {
			if output, hr := adapter.EnumOutputs(index); hr == dxgi.S_OK {
				outputID = dxgiFindOutputIDLocked(output)
			}
		}
		dxgiGlobal.mu.Unlock()
		if outputID == 0 {
			return dxgi.DXGI_ERROR_NOT_FOUND
		}
		outputObj := d3dCreateCOMObjectFromID(ctx.Mem, ctx.Disp, "dxgi-output", 19, outputID, dxgiDispatchOutput)
		if outputObj == 0 {
			return E_OUTOFMEMORY
		}
		ctx.Mem.Write64(ppOutput, outputObj)
		return S_OK
	case 8:
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
		writeDXGIAdapterDesc(ctx.Mem, pDesc, adapter.GetDesc())
		return S_OK
	case 9:
		if pUMDVersion := ctx.Arg(2); pUMDVersion != 0 {
			ctx.Mem.Write64(pUMDVersion, 0)
		}
		return S_OK
	default:
		return E_NOTIMPL
	}
}

func dxgiDispatchOutput(ctx *ntapi.TrapContext, method int, obj *d3dCOMObject) uint32 {
	if handled, hr := dxgiDispatchObjectCommon(ctx, method); handled {
		return hr
	}
	switch method {
	case 7:
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
		writeDXGIOutputDesc(ctx.Mem, pDesc, output.GetDesc())
		return S_OK
	case 8:
		enumFormat := uint32(ctx.Arg(1))
		pNumModes := ctx.Arg(3)
		pDesc := ctx.Arg(4)
		if pNumModes == 0 {
			return E_POINTER
		}
		dxgiGlobal.mu.Lock()
		output := dxgiGlobal.outputs[obj.id]
		var modes []dxgi.DXGI_MODE_DESC
		if output != nil {
			modes = output.GetDisplayModeList(enumFormat)
		}
		dxgiGlobal.mu.Unlock()
		modeCount := uint32(len(modes))
		if pDesc == 0 {
			ctx.Mem.Write32(pNumModes, modeCount)
			return S_OK
		}
		requested, _ := ctx.Mem.Read32(pNumModes)
		if requested == 0 || requested > modeCount {
			requested = modeCount
		}
		for i := uint32(0); i < requested; i++ {
			writeDXGIModeDesc(ctx.Mem, pDesc+uint64(i)*28, modes[i])
		}
		ctx.Mem.Write32(pNumModes, modeCount)
		return S_OK
	case 9:
		pClosestMatch := ctx.Arg(2)
		if pClosestMatch == 0 {
			return E_POINTER
		}
		format := uint32(dxgi.DXGI_FORMAT_R8G8B8A8_UNORM)
		if pModeToMatch := ctx.Arg(1); pModeToMatch != 0 {
			if v, err := ctx.Mem.Read32(pModeToMatch + 16); err == nil && v != 0 {
				format = v
			}
		}
		writeDXGIModeDesc(ctx.Mem, pClosestMatch, dxgi.DXGI_MODE_DESC{
			Width:       1920,
			Height:      1080,
			RefreshRate: dxgi.DXGI_RATIONAL{Numerator: 60, Denominator: 1},
			Format:      format,
		})
		return S_OK
	case 10:
		return S_OK
	default:
		return E_NOTIMPL
	}
}

func dxgiDispatchObjectCommon(ctx *ntapi.TrapContext, method int) (bool, uint32) {
	switch method {
	case 3, 4:
		return true, S_OK
	case 5:
		if pDataSize := ctx.Arg(2); pDataSize != 0 {
			ctx.Mem.Write32(pDataSize, 0)
		}
		return true, E_NOTIMPL
	case 6:
		if ppParent := ctx.Arg(2); ppParent != 0 {
			ctx.Mem.Write64(ppParent, 0)
		}
		return true, E_NOINTERFACE
	default:
		return false, 0
	}
}

func dxgiCreateSwapChainObject(hctx *HandlerCtx, deviceObj, descAddr uint64) uint64 {
	if hctx == nil || descAddr == 0 {
		return 0
	}
	desc, ok := readGuestStruct[dxgi.DXGI_SWAP_CHAIN_DESC](hctx.Mem, descAddr)
	if !ok {
		return 0
	}
	window := hctx.WlWindow
	if desc.OutputWindow != 0 && desc.OutputWindow != hctx.MainHWND {
		window = nil
	}
	factory := dxgi.NewFactory()
	swapChain, hr := factory.CreateSwapChain(deviceObj, desc, window)
	if hr != dxgi.S_OK || swapChain == nil {
		return 0
	}

	dxgiGlobal.mu.Lock()
	swapChainID := dxgiGlobal.nextSwapChain
	dxgiGlobal.nextSwapChain++
	dxgiGlobal.swapChains[swapChainID] = &dxgiSwapChainRecord{chain: swapChain, deviceObj: deviceObj}
	dxgiGlobal.mu.Unlock()

	return d3dCreateCOMObjectFromID(hctx.Mem, hctx.Disp, "dxgi-swap-chain", 18, swapChainID, dxgiDispatchSwapChain)
}

func dxgiDispatchSwapChain(ctx *ntapi.TrapContext, method int, obj *d3dCOMObject) uint32 {
	if handled, hr := dxgiDispatchObjectCommon(ctx, method); handled {
		return hr
	}

	dxgiGlobal.mu.Lock()
	record := dxgiGlobal.swapChains[obj.id]
	dxgiGlobal.mu.Unlock()
	if record == nil || record.chain == nil {
		return E_POINTER
	}

	switch method {
	case 7:
		ppDevice := ctx.Arg(2)
		if ppDevice == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppDevice, 0)
		if record.deviceObj != 0 {
			d3dAddRefObject(record.deviceObj)
			ctx.Mem.Write64(ppDevice, record.deviceObj)
			return S_OK
		}
		return E_NOINTERFACE
	case 8:
		return record.chain.Present(uint32(ctx.Arg(1)), uint32(ctx.Arg(2)))
	case 9:
		ppSurface := ctx.Arg(3)
		if ppSurface == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppSurface, 0)
		texture, hr := record.chain.GetBuffer(uint32(ctx.Arg(1)))
		if hr != dxgi.S_OK || texture == nil {
			return hr
		}
		dxgiGlobal.mu.Lock()
		textureID := dxgiFindOrCreateTextureIDLocked(texture, record.deviceObj, obj.id)
		dxgiGlobal.mu.Unlock()
		textureObj := d3dCreateCOMObjectFromID(ctx.Mem, ctx.Disp, "d3d11-texture2d", d3d11Texture2DMethods, textureID, d3d11Texture2DDispatch)
		if textureObj == 0 {
			return E_OUTOFMEMORY
		}
		ctx.Mem.Write64(ppSurface, textureObj)
		return S_OK
	case 10, 11:
		return S_OK
	case 12:
		pDesc := ctx.Arg(1)
		if pDesc == 0 {
			return E_POINTER
		}
		writeGuestStruct(ctx.Mem, pDesc, record.chain.GetDesc())
		return S_OK
	case 13:
		hr := record.chain.ResizeBuffers(uint32(ctx.Arg(1)), uint32(ctx.Arg(2)), uint32(ctx.Arg(3)), uint32(ctx.Arg(4)), uint32(ctx.Arg(5)))
		if hr == S_OK {
			dxgiGlobal.mu.Lock()
			for id, rec := range dxgiGlobal.textures {
				if rec.swapChainID == obj.id {
					delete(dxgiGlobal.textures, id)
				}
			}
			dxgiGlobal.mu.Unlock()
		}
		return hr
	default:
		return E_NOTIMPL
	}
}

func dxgiFindAdapterIDLocked(target *dxgi.Adapter) uint32 {
	for id, adapter := range dxgiGlobal.adapters {
		if adapter == target {
			return id
		}
	}
	return 0
}

func dxgiFindOutputIDLocked(target *dxgi.Output) uint32 {
	for id, output := range dxgiGlobal.outputs {
		if output == target {
			return id
		}
	}
	return 0
}

func dxgiFindOrCreateTextureIDLocked(texture *dxgi.Texture2D, deviceObj uint64, swapChainID uint32) uint32 {
	for id, record := range dxgiGlobal.textures {
		if record.texture == texture {
			return id
		}
	}
	textureID := dxgiGlobal.nextTexture
	dxgiGlobal.nextTexture++
	dxgiGlobal.textures[textureID] = &dxgiTextureRecord{texture: texture, deviceObj: deviceObj, swapChainID: swapChainID}
	return textureID
}

func d3d9CreateObject(hctx *HandlerCtx) uint64 {
	return d3dCreatePayloadCOMObject(hctx.Mem, hctx.Disp, "d3d9", 17, hctx, d3d9Dispatch)
}

func d3d9Dispatch(ctx *ntapi.TrapContext, method int, obj *d3dCOMObject) uint32 {
	hctx, _ := obj.payload.(*HandlerCtx)
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
		ppDevice := ctx.Arg(6)
		if ppDevice == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppDevice, 0)
		var deviceObj uint64
		if hctx != nil {
			deviceObj = d3d9CreateDeviceObject(hctx, ctx.Arg(5))
		} else {
			device := d3d9.NewDevice()
			deviceObj = d3dCreatePayloadCOMObject(ctx.Mem, ctx.Disp, "d3d9-device", d3d9DeviceMethods, device, d3d9DeviceDispatch)
		}
		if deviceObj == 0 {
			return E_OUTOFMEMORY
		}
		ctx.Mem.Write64(ppDevice, deviceObj)
		return D3D_OK
	default:
		return E_NOTIMPL
	}
}

func d3dCreateCOMObject(hctx *HandlerCtx, kind string, methods int, id uint32, dispatch func(ctx *ntapi.TrapContext, method int, obj *d3dCOMObject) uint32) uint64 {
	return d3dCreateCOMObjectFromID(hctx.Mem, hctx.Disp, kind, methods, id, dispatch)
}

func d3dCreatePayloadCOMObjectFromID(mem *mmu.MMU, disp *ntapi.Dispatcher, kind string, methods int, id uint32, payload any, dispatch func(ctx *ntapi.TrapContext, method int, obj *d3dCOMObject) uint32) uint64 {
	addr := d3dCreateCOMObjectFromID(mem, disp, kind, methods, id, dispatch)
	if addr == 0 {
		return 0
	}
	d3dCOMMu.Lock()
	if obj := d3dCOMObjects[addr]; obj != nil {
		obj.payload = payload
	}
	d3dCOMMu.Unlock()
	return addr
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

func writeDXGIAdapterDesc(mem *mmu.MMU, addr uint64, desc dxgi.DXGI_ADAPTER_DESC) {
	writeGuestStruct(mem, addr, desc)
}

func writeDXGIOutputDesc(mem *mmu.MMU, addr uint64, desc dxgi.DXGI_OUTPUT_DESC) {
	writeGuestStruct(mem, addr, desc)
}

func writeDXGIModeDesc(mem *mmu.MMU, addr uint64, desc dxgi.DXGI_MODE_DESC) {
	if desc.Format == 0 {
		desc.Format = dxgi.DXGI_FORMAT_R8G8B8A8_UNORM
	}
	if desc.RefreshRate.Denominator == 0 {
		desc.RefreshRate = dxgi.DXGI_RATIONAL{Numerator: 60, Denominator: 1}
	}
	writeGuestStruct(mem, addr, desc)
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
	writeGuestStruct(mem, addr, d3d9.DefaultCaps())
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

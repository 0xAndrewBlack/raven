package main

import (
	"math"
	"unsafe"

	"github.com/mirkobrombin/Raven/pkg/d3d11"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

const (
	d3d11DeviceMethods      = 43
	d3d11ContextMethods     = 121
	d3d11Texture2DMethods   = 11
	d3d11BufferMethods      = 11
	d3d11ViewMethods        = 9
	d3d11DeviceChildMethods = 7
)

type d3d11Bridge struct {
	hctx       *HandlerCtx
	device     *d3d11.Device
	context    *d3d11.DeviceContext
	deviceObj  uint64
	contextObj uint64
}

type d3d11COMHandle struct {
	bridge      *d3d11Bridge
	handle      uint64
	resourceObj uint64
}

func registerD3d11HandlersBridge(hctx *HandlerCtx, dll *ntapi.SynthPE) {
	d := hctx.Disp
	d.RegisterAutoStubHandler(dll, "D3D11CreateDevice", func(ctx *ntapi.TrapContext) uint32 {
		ppDevice := ctx.Arg(7)
		pFeatureLevel := ctx.Arg(8)
		ppImmediateContext := ctx.Arg(9)
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
		bridge, hr := d3d11CreateBridge(hctx)
		if hr != S_OK || bridge == nil {
			ctx.Mem.Write64(ppDevice, 0)
			if ppImmediateContext != 0 {
				ctx.Mem.Write64(ppImmediateContext, 0)
			}
			ctx.SetReturn(uint64(hr))
			return 0
		}
		ctx.Mem.Write64(ppDevice, bridge.deviceObj)
		if ppImmediateContext != 0 {
			d3dAddRefObject(bridge.contextObj)
			ctx.Mem.Write64(ppImmediateContext, bridge.contextObj)
		}
		ctx.SetReturn(S_OK)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "D3D11CreateDeviceAndSwapChain", func(ctx *ntapi.TrapContext) uint32 {
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
		bridge, hr := d3d11CreateBridge(hctx)
		if hr != S_OK || bridge == nil {
			ctx.Mem.Write64(ppDevice, 0)
			if ppImmediateContext != 0 {
				ctx.Mem.Write64(ppImmediateContext, 0)
			}
			ctx.SetReturn(uint64(hr))
			return 0
		}
		ctx.Mem.Write64(ppDevice, bridge.deviceObj)
		if ppImmediateContext != 0 {
			d3dAddRefObject(bridge.contextObj)
			ctx.Mem.Write64(ppImmediateContext, bridge.contextObj)
		}
		if ppSwapChain != 0 {
			swapChainObj := dxgiCreateSwapChainObject(hctx, bridge.deviceObj, ctx.Arg(7))
			if swapChainObj == 0 {
				ctx.SetReturn(E_OUTOFMEMORY)
				return 0
			}
			ctx.Mem.Write64(ppSwapChain, swapChainObj)
		}
		ctx.SetReturn(S_OK)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "D3D11On12CreateDevice", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(E_NOTIMPL)
		return 0
	})
}

func d3d11CreateBridge(hctx *HandlerCtx) (*d3d11Bridge, uint32) {
	if hctx == nil {
		return nil, E_POINTER
	}
	device := d3d11.NewDevice(0)
	context := d3d11.NewDeviceContext(device)
	bridge := &d3d11Bridge{hctx: hctx, device: device, context: context}
	deviceObj := d3dCreatePayloadCOMObject(hctx.Mem, hctx.Disp, "d3d11-device", d3d11DeviceMethods, bridge, d3d11DeviceDispatch)
	if deviceObj == 0 {
		return nil, E_OUTOFMEMORY
	}
	bridge.deviceObj = deviceObj
	contextObj := d3dCreatePayloadCOMObject(hctx.Mem, hctx.Disp, "d3d11-context", d3d11ContextMethods, &d3d11COMHandle{bridge: bridge}, d3d11ContextDispatch)
	if contextObj == 0 {
		return nil, E_OUTOFMEMORY
	}
	bridge.contextObj = contextObj
	hctx.D3D11Device = device
	hctx.D3D11ImmediateContext = context
	return bridge, S_OK
}

func d3d11DeviceDispatch(ctx *ntapi.TrapContext, method int, obj *d3dCOMObject) uint32 {
	bridge, _ := obj.payload.(*d3d11Bridge)
	if bridge == nil {
		return E_POINTER
	}
	switch method {
	case 3:
		return d3d11HandleCreateBuffer(ctx, bridge)
	case 5:
		return d3d11HandleCreateTexture2D(ctx, bridge)
	case 7:
		return d3d11HandleCreateSRV(ctx, bridge)
	case 9:
		return d3d11HandleCreateRTV(ctx, bridge)
	case 10:
		return d3d11HandleCreateDSV(ctx, bridge)
	case 11:
		return d3d11HandleCreateInputLayout(ctx, bridge)
	case 12:
		return d3d11HandleCreateVertexShader(ctx, bridge)
	case 15:
		return d3d11HandleCreatePixelShader(ctx, bridge)
	case 20:
		return d3d11HandleCreateBlendState(ctx, bridge)
	case 21:
		return d3d11HandleCreateDepthStencilState(ctx, bridge)
	case 22:
		return d3d11HandleCreateRasterizerState(ctx, bridge)
	case 23:
		return d3d11HandleCreateSamplerState(ctx, bridge)
	case 37:
		ctx.SetReturn(D3D_FEATURE_LEVEL_11_0)
		return 0
	case 38:
		ctx.SetReturn(0)
		return 0
	case 39:
		return S_OK
	case 40:
		ppIC := ctx.Arg(1)
		if ppIC == 0 {
			return E_POINTER
		}
		d3dAddRefObject(bridge.contextObj)
		ctx.Mem.Write64(ppIC, bridge.contextObj)
		return S_OK
	case 41:
		return S_OK
	case 42:
		ctx.SetReturn(0)
		return 0
	default:
		return E_NOTIMPL
	}
}

func d3d11ContextDispatch(ctx *ntapi.TrapContext, method int, obj *d3dCOMObject) uint32 {
	payload, _ := obj.payload.(*d3d11COMHandle)
	if payload == nil || payload.bridge == nil {
		return E_POINTER
	}
	bridge := payload.bridge
	switch method {
	case 3:
		return writeDeviceRef(ctx, bridge.deviceObj)
	case 7:
		bridge.context.VSSetConstantBuffers(uint32(ctx.Arg(1)), uint32(ctx.Arg(2)), readCOMHandleArray(ctx.Mem, ctx.Arg(3), uint32(ctx.Arg(2))))
	case 8:
		bridge.context.PSSetShaderResources(uint32(ctx.Arg(1)), uint32(ctx.Arg(2)), readCOMHandleArray(ctx.Mem, ctx.Arg(3), uint32(ctx.Arg(2))))
	case 9:
		bridge.context.PSSetShader(resolveHandle(ctx.Arg(1)), nil, uint32(ctx.Arg(3)))
	case 10:
		bridge.context.PSSetSamplers(uint32(ctx.Arg(1)), uint32(ctx.Arg(2)), readCOMHandleArray(ctx.Mem, ctx.Arg(3), uint32(ctx.Arg(2))))
	case 11:
		bridge.context.VSSetShader(resolveHandle(ctx.Arg(1)), nil, uint32(ctx.Arg(3)))
	case 12:
		bridge.context.DrawIndexed(uint32(ctx.Arg(1)), uint32(ctx.Arg(2)), int32(ctx.Arg(3)))
	case 13:
		bridge.context.Draw(uint32(ctx.Arg(1)), uint32(ctx.Arg(2)))
	case 14:
		return d3d11HandleMap(ctx, bridge)
	case 15:
		bridge.context.Unmap(uint32(resolveHandle(ctx.Arg(1))), uint32(ctx.Arg(2)))
	case 16:
		bridge.context.PSSetConstantBuffers(uint32(ctx.Arg(1)), uint32(ctx.Arg(2)), readCOMHandleArray(ctx.Mem, ctx.Arg(3), uint32(ctx.Arg(2))))
	case 17:
		bridge.context.IASetInputLayout(resolveHandle(ctx.Arg(1)))
	case 18:
		bridge.context.IASetVertexBuffers(uint32(ctx.Arg(1)), uint32(ctx.Arg(2)), readCOMHandleArray(ctx.Mem, ctx.Arg(3), uint32(ctx.Arg(2))), readU32ArrayAs64(ctx.Mem, ctx.Arg(4), uint32(ctx.Arg(2))), readU32ArrayAs64(ctx.Mem, ctx.Arg(5), uint32(ctx.Arg(2))))
	case 19:
		bridge.context.IASetIndexBuffer(resolveHandle(ctx.Arg(1)), ctx.Arg(2), ctx.Arg(3))
	case 24:
		bridge.context.IASetPrimitiveTopology(uint32(ctx.Arg(1)))
	case 33:
		bridge.context.OMSetRenderTargets(uint32(ctx.Arg(1)), readCOMHandleArray(ctx.Mem, ctx.Arg(2), uint32(ctx.Arg(1))), resolveHandle(ctx.Arg(3)))
	case 35:
		bridge.context.OMSetBlendState(resolveHandle(ctx.Arg(1)), readFloat4(ctx.Mem, ctx.Arg(2)), uint32(ctx.Arg(3)))
	case 36:
		bridge.context.OMSetDepthStencilState(resolveHandle(ctx.Arg(1)), uint32(ctx.Arg(2)))
	case 43:
		bridge.context.RSSetState(resolveHandle(ctx.Arg(1)))
	case 44:
		bridge.context.RSSetViewports(uint32(ctx.Arg(1)), readViewports(ctx.Mem, ctx.Arg(2), uint32(ctx.Arg(1))))
	case 45:
		bridge.context.RSSetScissorRects(uint32(ctx.Arg(1)), readRects(ctx.Mem, ctx.Arg(2), uint32(ctx.Arg(1))))
	case 48:
		return d3d11HandleUpdateSubresource(ctx, bridge)
	case 50:
		return d3d11HandleClearRTV(ctx, bridge)
	case 53:
		return d3d11HandleClearDSV(ctx, bridge)
	case 111, 114:
		return S_OK
	}
	return S_OK
}

func d3d11BufferDispatch(ctx *ntapi.TrapContext, method int, obj *d3dCOMObject) uint32 {
	payload, _ := obj.payload.(*d3d11COMHandle)
	if payload == nil || payload.bridge == nil {
		return E_POINTER
	}
	buf, _ := payload.bridge.device.Lookup(payload.handle).(*d3d11.Buffer)
	if buf == nil {
		return E_POINTER
	}
	switch method {
	case 3:
		return writeDeviceRef(ctx, payload.bridge.deviceObj)
	case 7:
		if pDim := ctx.Arg(1); pDim != 0 {
			ctx.Mem.Write32(pDim, 1)
		}
		return S_OK
	case 8:
		return S_OK
	case 9:
		ctx.SetReturn(0)
		return 0
	case 10:
		pDesc := ctx.Arg(1)
		if pDesc == 0 {
			return E_POINTER
		}
		writeGuestStruct(ctx.Mem, pDesc, buf.Desc)
		return S_OK
	default:
		return d3d11ChildDispatch(ctx, method, payload)
	}
}

func d3d11Texture2DDispatch(ctx *ntapi.TrapContext, method int, obj *d3dCOMObject) uint32 {
	payload, tex, deviceObj := resolveTextureObject(obj)
	if tex == nil {
		return E_POINTER
	}
	switch method {
	case 3:
		return writeDeviceRef(ctx, deviceObj)
	case 4:
		if pDataSize := ctx.Arg(2); pDataSize != 0 {
			ctx.Mem.Write32(pDataSize, 0)
		}
		return E_NOTIMPL
	case 5, 6, 8:
		return S_OK
	case 7:
		if pDimension := ctx.Arg(1); pDimension != 0 {
			ctx.Mem.Write32(pDimension, 3)
		}
		return S_OK
	case 9:
		ctx.SetReturn(0)
		return 0
	case 10:
		pDesc := ctx.Arg(1)
		if pDesc == 0 {
			return E_POINTER
		}
		writeGuestStruct(ctx.Mem, pDesc, tex.Desc)
		return S_OK
	default:
		if payload != nil {
			return d3d11ChildDispatch(ctx, method, payload)
		}
		return E_NOTIMPL
	}
}

func d3d11SRVDispatch(ctx *ntapi.TrapContext, method int, obj *d3dCOMObject) uint32 {
	payload, _ := obj.payload.(*d3d11COMHandle)
	if payload == nil || payload.bridge == nil {
		return E_POINTER
	}
	view, _ := payload.bridge.device.Lookup(payload.handle).(*d3d11.ShaderResourceView)
	if view == nil {
		return E_POINTER
	}
	switch method {
	case 3:
		return writeDeviceRef(ctx, payload.bridge.deviceObj)
	case 7:
		return writeResourceRef(ctx, payload.resourceObj)
	case 8:
		pDesc := ctx.Arg(1)
		if pDesc == 0 {
			return E_POINTER
		}
		writeGuestStruct(ctx.Mem, pDesc, view.Desc)
		return S_OK
	default:
		return d3d11ChildDispatch(ctx, method, payload)
	}
}

func d3d11RTVDispatch(ctx *ntapi.TrapContext, method int, obj *d3dCOMObject) uint32 {
	payload, _ := obj.payload.(*d3d11COMHandle)
	if payload == nil || payload.bridge == nil {
		return E_POINTER
	}
	view, _ := payload.bridge.device.Lookup(payload.handle).(*d3d11.RenderTargetView)
	if view == nil {
		return E_POINTER
	}
	switch method {
	case 3:
		return writeDeviceRef(ctx, payload.bridge.deviceObj)
	case 7:
		return writeResourceRef(ctx, payload.resourceObj)
	case 8:
		pDesc := ctx.Arg(1)
		if pDesc == 0 {
			return E_POINTER
		}
		writeGuestStruct(ctx.Mem, pDesc, view.Desc)
		return S_OK
	default:
		return d3d11ChildDispatch(ctx, method, payload)
	}
}

func d3d11DSVDispatch(ctx *ntapi.TrapContext, method int, obj *d3dCOMObject) uint32 {
	payload, _ := obj.payload.(*d3d11COMHandle)
	if payload == nil || payload.bridge == nil {
		return E_POINTER
	}
	view, _ := payload.bridge.device.Lookup(payload.handle).(*d3d11.DepthStencilView)
	if view == nil {
		return E_POINTER
	}
	switch method {
	case 3:
		return writeDeviceRef(ctx, payload.bridge.deviceObj)
	case 7:
		return writeResourceRef(ctx, payload.resourceObj)
	case 8:
		pDesc := ctx.Arg(1)
		if pDesc == 0 {
			return E_POINTER
		}
		writeGuestStruct(ctx.Mem, pDesc, view.Desc)
		return S_OK
	default:
		return d3d11ChildDispatch(ctx, method, payload)
	}
}

func d3d11ChildObjectDispatch(ctx *ntapi.TrapContext, method int, obj *d3dCOMObject) uint32 {
	payload, _ := obj.payload.(*d3d11COMHandle)
	return d3d11ChildDispatch(ctx, method, payload)
}

func d3d11ChildDispatch(ctx *ntapi.TrapContext, method int, payload *d3d11COMHandle) uint32 {
	if payload == nil || payload.bridge == nil {
		return E_POINTER
	}
	switch method {
	case 3:
		return writeDeviceRef(ctx, payload.bridge.deviceObj)
	case 4:
		if pDataSize := ctx.Arg(2); pDataSize != 0 {
			ctx.Mem.Write32(pDataSize, 0)
		}
		return E_NOTIMPL
	case 5, 6:
		return S_OK
	default:
		return E_NOTIMPL
	}
}

func d3d11HandleCreateBuffer(ctx *ntapi.TrapContext, bridge *d3d11Bridge) uint32 {
	desc, ok := readGuestStruct[d3d11.D3D11_BUFFER_DESC](ctx.Mem, ctx.Arg(1))
	if !ok {
		return E_POINTER
	}
	handle, err := bridge.device.CreateBuffer(desc, readSubresourceData(ctx.Mem, ctx.Arg(2), int(desc.ByteWidth)))
	if err != nil {
		return E_OUTOFMEMORY
	}
	objAddr := d3dCreatePayloadCOMObject(ctx.Mem, ctx.Disp, "d3d11-buffer", d3d11BufferMethods, &d3d11COMHandle{bridge: bridge, handle: handle}, d3d11BufferDispatch)
	return writeCreatedObject(ctx, ctx.Arg(3), objAddr)
}

func d3d11HandleCreateTexture2D(ctx *ntapi.TrapContext, bridge *d3d11Bridge) uint32 {
	desc, ok := readGuestStruct[d3d11.D3D11_TEXTURE2D_DESC](ctx.Mem, ctx.Arg(1))
	if !ok {
		return E_POINTER
	}
	size := int(desc.Width * desc.Height * 4)
	handle, err := bridge.device.CreateTexture2D(desc, readSubresourceData(ctx.Mem, ctx.Arg(2), size))
	if err != nil {
		return E_OUTOFMEMORY
	}
	objAddr := d3dCreatePayloadCOMObject(ctx.Mem, ctx.Disp, "d3d11-texture2d", d3d11Texture2DMethods, &d3d11COMHandle{bridge: bridge, handle: handle}, d3d11Texture2DDispatch)
	return writeCreatedObject(ctx, ctx.Arg(3), objAddr)
}

func d3d11HandleCreateSRV(ctx *ntapi.TrapContext, bridge *d3d11Bridge) uint32 {
	resourceHandle, resourceObj := resolveResourceHandle(ctx.Arg(1), bridge)
	if resourceHandle == 0 {
		return E_POINTER
	}
	var desc *d3d11.D3D11_SHADER_RESOURCE_VIEW_DESC
	if ctx.Arg(2) != 0 {
		v, ok := readGuestStruct[d3d11.D3D11_SHADER_RESOURCE_VIEW_DESC](ctx.Mem, ctx.Arg(2))
		if !ok {
			return E_POINTER
		}
		desc = &v
	}
	handle, err := bridge.device.CreateShaderResourceView(resourceHandle, desc)
	if err != nil {
		return E_OUTOFMEMORY
	}
	objAddr := d3dCreatePayloadCOMObject(ctx.Mem, ctx.Disp, "d3d11-srv", d3d11ViewMethods, &d3d11COMHandle{bridge: bridge, handle: handle, resourceObj: resourceObj}, d3d11SRVDispatch)
	return writeCreatedObject(ctx, ctx.Arg(3), objAddr)
}

func d3d11HandleCreateRTV(ctx *ntapi.TrapContext, bridge *d3d11Bridge) uint32 {
	resourceHandle, resourceObj := resolveResourceHandle(ctx.Arg(1), bridge)
	if resourceHandle == 0 {
		return E_POINTER
	}
	var desc *d3d11.D3D11_RENDER_TARGET_VIEW_DESC
	if ctx.Arg(2) != 0 {
		v, ok := readGuestStruct[d3d11.D3D11_RENDER_TARGET_VIEW_DESC](ctx.Mem, ctx.Arg(2))
		if !ok {
			return E_POINTER
		}
		desc = &v
	}
	handle, err := bridge.device.CreateRenderTargetView(resourceHandle, desc)
	if err != nil {
		return E_OUTOFMEMORY
	}
	objAddr := d3dCreatePayloadCOMObject(ctx.Mem, ctx.Disp, "d3d11-rtv", d3d11ViewMethods, &d3d11COMHandle{bridge: bridge, handle: handle, resourceObj: resourceObj}, d3d11RTVDispatch)
	return writeCreatedObject(ctx, ctx.Arg(3), objAddr)
}

func d3d11HandleCreateDSV(ctx *ntapi.TrapContext, bridge *d3d11Bridge) uint32 {
	resourceHandle, resourceObj := resolveResourceHandle(ctx.Arg(1), bridge)
	if resourceHandle == 0 {
		return E_POINTER
	}
	var desc *d3d11.D3D11_DEPTH_STENCIL_VIEW_DESC
	if ctx.Arg(2) != 0 {
		v, ok := readGuestStruct[d3d11.D3D11_DEPTH_STENCIL_VIEW_DESC](ctx.Mem, ctx.Arg(2))
		if !ok {
			return E_POINTER
		}
		desc = &v
	}
	handle, err := bridge.device.CreateDepthStencilView(resourceHandle, desc)
	if err != nil {
		return E_OUTOFMEMORY
	}
	objAddr := d3dCreatePayloadCOMObject(ctx.Mem, ctx.Disp, "d3d11-dsv", d3d11ViewMethods, &d3d11COMHandle{bridge: bridge, handle: handle, resourceObj: resourceObj}, d3d11DSVDispatch)
	return writeCreatedObject(ctx, ctx.Arg(3), objAddr)
}

func d3d11HandleCreateVertexShader(ctx *ntapi.TrapContext, bridge *d3d11Bridge) uint32 {
	handle, err := bridge.device.CreateVertexShader(readBytes(ctx.Mem, ctx.Arg(1), int(ctx.Arg(2))))
	if err != nil {
		return E_OUTOFMEMORY
	}
	objAddr := d3dCreatePayloadCOMObject(ctx.Mem, ctx.Disp, "d3d11-vs", d3d11DeviceChildMethods, &d3d11COMHandle{bridge: bridge, handle: handle}, d3d11ChildObjectDispatch)
	return writeCreatedObject(ctx, ctx.Arg(4), objAddr)
}

func d3d11HandleCreatePixelShader(ctx *ntapi.TrapContext, bridge *d3d11Bridge) uint32 {
	handle, err := bridge.device.CreatePixelShader(readBytes(ctx.Mem, ctx.Arg(1), int(ctx.Arg(2))))
	if err != nil {
		return E_OUTOFMEMORY
	}
	objAddr := d3dCreatePayloadCOMObject(ctx.Mem, ctx.Disp, "d3d11-ps", d3d11DeviceChildMethods, &d3d11COMHandle{bridge: bridge, handle: handle}, d3d11ChildObjectDispatch)
	return writeCreatedObject(ctx, ctx.Arg(4), objAddr)
}

func d3d11HandleCreateInputLayout(ctx *ntapi.TrapContext, bridge *d3d11Bridge) uint32 {
	num := uint32(ctx.Arg(2))
	elems := make([]d3d11.D3D11_INPUT_ELEMENT_DESC, 0, num)
	size := uint64(unsafe.Sizeof(d3d11.D3D11_INPUT_ELEMENT_DESC{}))
	for i := uint32(0); i < num; i++ {
		elem, ok := readGuestStruct[d3d11.D3D11_INPUT_ELEMENT_DESC](ctx.Mem, ctx.Arg(1)+uint64(i)*size)
		if !ok {
			return E_POINTER
		}
		elems = append(elems, elem)
	}
	handle, err := bridge.device.CreateInputLayout(elems, readBytes(ctx.Mem, ctx.Arg(3), int(ctx.Arg(4))))
	if err != nil {
		return E_OUTOFMEMORY
	}
	objAddr := d3dCreatePayloadCOMObject(ctx.Mem, ctx.Disp, "d3d11-input-layout", d3d11DeviceChildMethods, &d3d11COMHandle{bridge: bridge, handle: handle}, d3d11ChildObjectDispatch)
	return writeCreatedObject(ctx, ctx.Arg(5), objAddr)
}

func d3d11HandleCreateBlendState(ctx *ntapi.TrapContext, bridge *d3d11Bridge) uint32 {
	desc, ok := readGuestStruct[d3d11.D3D11_BLEND_DESC](ctx.Mem, ctx.Arg(1))
	if !ok {
		return E_POINTER
	}
	handle, err := bridge.device.CreateBlendState(desc)
	if err != nil {
		return E_OUTOFMEMORY
	}
	objAddr := d3dCreatePayloadCOMObject(ctx.Mem, ctx.Disp, "d3d11-blend-state", d3d11DeviceChildMethods, &d3d11COMHandle{bridge: bridge, handle: handle}, d3d11ChildObjectDispatch)
	return writeCreatedObject(ctx, ctx.Arg(2), objAddr)
}

func d3d11HandleCreateRasterizerState(ctx *ntapi.TrapContext, bridge *d3d11Bridge) uint32 {
	desc, ok := readGuestStruct[d3d11.D3D11_RASTERIZER_DESC](ctx.Mem, ctx.Arg(1))
	if !ok {
		return E_POINTER
	}
	handle, err := bridge.device.CreateRasterizerState(desc)
	if err != nil {
		return E_OUTOFMEMORY
	}
	objAddr := d3dCreatePayloadCOMObject(ctx.Mem, ctx.Disp, "d3d11-rasterizer-state", d3d11DeviceChildMethods, &d3d11COMHandle{bridge: bridge, handle: handle}, d3d11ChildObjectDispatch)
	return writeCreatedObject(ctx, ctx.Arg(2), objAddr)
}

func d3d11HandleCreateDepthStencilState(ctx *ntapi.TrapContext, bridge *d3d11Bridge) uint32 {
	desc, ok := readGuestStruct[d3d11.D3D11_DEPTH_STENCIL_DESC](ctx.Mem, ctx.Arg(1))
	if !ok {
		return E_POINTER
	}
	handle, err := bridge.device.CreateDepthStencilState(desc)
	if err != nil {
		return E_OUTOFMEMORY
	}
	objAddr := d3dCreatePayloadCOMObject(ctx.Mem, ctx.Disp, "d3d11-depth-stencil-state", d3d11DeviceChildMethods, &d3d11COMHandle{bridge: bridge, handle: handle}, d3d11ChildObjectDispatch)
	return writeCreatedObject(ctx, ctx.Arg(2), objAddr)
}

func d3d11HandleCreateSamplerState(ctx *ntapi.TrapContext, bridge *d3d11Bridge) uint32 {
	desc, ok := readGuestStruct[d3d11.D3D11_SAMPLER_DESC](ctx.Mem, ctx.Arg(1))
	if !ok {
		return E_POINTER
	}
	handle, err := bridge.device.CreateSamplerState(desc)
	if err != nil {
		return E_OUTOFMEMORY
	}
	objAddr := d3dCreatePayloadCOMObject(ctx.Mem, ctx.Disp, "d3d11-sampler-state", d3d11DeviceChildMethods, &d3d11COMHandle{bridge: bridge, handle: handle}, d3d11ChildObjectDispatch)
	return writeCreatedObject(ctx, ctx.Arg(2), objAddr)
}

func d3d11HandleMap(ctx *ntapi.TrapContext, bridge *d3d11Bridge) uint32 {
	pMapped := ctx.Arg(5)
	if pMapped == 0 {
		return E_POINTER
	}
	mapped, err := bridge.context.Map(uint32(resolveHandle(ctx.Arg(1))), uint32(ctx.Arg(2)), uint32(ctx.Arg(3)))
	if err != nil {
		return E_POINTER
	}
	writeGuestStruct(ctx.Mem, pMapped, mapped)
	return S_OK
}

func d3d11HandleUpdateSubresource(ctx *ntapi.TrapContext, bridge *d3d11Bridge) uint32 {
	var box *d3d11.D3D11_BOX
	if ctx.Arg(3) != 0 {
		v, ok := readGuestStruct[d3d11.D3D11_BOX](ctx.Mem, ctx.Arg(3))
		if !ok {
			return E_POINTER
		}
		box = &v
	}
	handle := resolveHandle(ctx.Arg(1))
	data := readBytes(ctx.Mem, ctx.Arg(4), d3d11UpdateSize(bridge, handle, uint32(ctx.Arg(5)), uint32(ctx.Arg(6))))
	if err := bridge.context.UpdateSubresource(uint32(handle), uint32(ctx.Arg(2)), box, data, uint32(ctx.Arg(5)), uint32(ctx.Arg(6))); err != nil {
		return E_POINTER
	}
	return S_OK
}

func d3d11HandleClearRTV(ctx *ntapi.TrapContext, bridge *d3d11Bridge) uint32 {
	if err := bridge.context.ClearRenderTargetView(resolveHandle(ctx.Arg(1)), readFloat4(ctx.Mem, ctx.Arg(2))); err != nil {
		return E_POINTER
	}
	return S_OK
}

func d3d11HandleClearDSV(ctx *ntapi.TrapContext, bridge *d3d11Bridge) uint32 {
	if err := bridge.context.ClearDepthStencilView(resolveHandle(ctx.Arg(1)), uint32(ctx.Arg(2)), readFloat32At(ctx.Mem, ctx.Arg(3)), uint8(ctx.Arg(4))); err != nil {
		return E_POINTER
	}
	return S_OK
}

func writeCreatedObject(ctx *ntapi.TrapContext, outPtr, objAddr uint64) uint32 {
	if outPtr == 0 {
		return E_POINTER
	}
	if objAddr == 0 {
		return E_OUTOFMEMORY
	}
	ctx.Mem.Write64(outPtr, objAddr)
	return S_OK
}

func writeDeviceRef(ctx *ntapi.TrapContext, deviceObj uint64) uint32 {
	ppDevice := ctx.Arg(1)
	if ppDevice == 0 {
		return E_POINTER
	}
	ctx.Mem.Write64(ppDevice, 0)
	if deviceObj != 0 {
		d3dAddRefObject(deviceObj)
		ctx.Mem.Write64(ppDevice, deviceObj)
	}
	return S_OK
}

func writeResourceRef(ctx *ntapi.TrapContext, resourceObj uint64) uint32 {
	ppResource := ctx.Arg(1)
	if ppResource == 0 {
		return E_POINTER
	}
	ctx.Mem.Write64(ppResource, 0)
	if resourceObj != 0 {
		d3dAddRefObject(resourceObj)
		ctx.Mem.Write64(ppResource, resourceObj)
	}
	return S_OK
}

func resolveTextureObject(obj *d3dCOMObject) (*d3d11COMHandle, *d3d11.Texture2D, uint64) {
	if obj == nil {
		return nil, nil, 0
	}
	if payload, ok := obj.payload.(*d3d11COMHandle); ok && payload != nil && payload.bridge != nil {
		if tex, _ := payload.bridge.device.Lookup(payload.handle).(*d3d11.Texture2D); tex != nil {
			return payload, tex, payload.bridge.deviceObj
		}
	}
	dxgiGlobal.mu.Lock()
	record := dxgiGlobal.textures[obj.id]
	dxgiGlobal.mu.Unlock()
	if record == nil || record.texture == nil {
		return nil, nil, 0
	}
	return nil, &d3d11.Texture2D{Desc: d3d11.D3D11_TEXTURE2D_DESC{Width: record.texture.Width, Height: record.texture.Height, MipLevels: 1, ArraySize: 1, Format: record.texture.Format, SampleCount: record.texture.SampleDesc.Count, SampleQuality: record.texture.SampleDesc.Quality, Usage: record.texture.Usage, BindFlags: record.texture.BindFlags}, Data: record.texture.Pixels, VkImage: record.texture.Image, VkImageView: record.texture.View}, record.deviceObj
}

func resolveHandle(comObj uint64) uint64 {
	if comObj == 0 {
		return 0
	}
	d3dCOMMu.Lock()
	defer d3dCOMMu.Unlock()
	if obj := d3dCOMObjects[comObj]; obj != nil {
		if payload, ok := obj.payload.(*d3d11COMHandle); ok && payload != nil {
			return payload.handle
		}
	}
	return 0
}

func resolveResourceHandle(comObj uint64, bridge *d3d11Bridge) (uint64, uint64) {
	if comObj == 0 || bridge == nil {
		return 0, 0
	}
	d3dCOMMu.Lock()
	obj := d3dCOMObjects[comObj]
	d3dCOMMu.Unlock()
	if obj == nil {
		return 0, 0
	}
	if payload, ok := obj.payload.(*d3d11COMHandle); ok && payload != nil {
		return payload.handle, comObj
	}
	if obj.kind != "d3d11-texture2d" {
		return 0, 0
	}
	dxgiGlobal.mu.Lock()
	record := dxgiGlobal.textures[obj.id]
	dxgiGlobal.mu.Unlock()
	if record == nil || record.texture == nil {
		return 0, 0
	}
	desc := d3d11.D3D11_TEXTURE2D_DESC{Width: record.texture.Width, Height: record.texture.Height, MipLevels: 1, ArraySize: 1, Format: record.texture.Format, SampleCount: record.texture.SampleDesc.Count, SampleQuality: record.texture.SampleDesc.Quality, Usage: record.texture.Usage, BindFlags: record.texture.BindFlags}
	handle := bridge.device.ImportTexture2D(desc, record.texture.Pixels, record.texture.Image, record.texture.View)
	payload := &d3d11COMHandle{bridge: bridge, handle: handle}
	d3dCOMMu.Lock()
	if cur := d3dCOMObjects[comObj]; cur != nil {
		cur.payload = payload
	}
	d3dCOMMu.Unlock()
	return handle, comObj
}

func readCOMHandleArray(mem *mmu.MMU, addr uint64, count uint32) []uint64 {
	vals := make([]uint64, 0, count)
	for i := uint32(0); i < count; i++ {
		v, err := mem.Read64(addr + uint64(i)*8)
		if err != nil {
			break
		}
		vals = append(vals, resolveHandle(v))
	}
	return vals
}

func readU32ArrayAs64(mem *mmu.MMU, addr uint64, count uint32) []uint64 {
	vals := make([]uint64, 0, count)
	for i := uint32(0); i < count; i++ {
		v, err := mem.Read32(addr + uint64(i)*4)
		if err != nil {
			break
		}
		vals = append(vals, uint64(v))
	}
	return vals
}

func readViewports(mem *mmu.MMU, addr uint64, count uint32) []d3d11.D3D11_VIEWPORT {
	vals := make([]d3d11.D3D11_VIEWPORT, 0, count)
	size := uint64(unsafe.Sizeof(d3d11.D3D11_VIEWPORT{}))
	for i := uint32(0); i < count; i++ {
		v, ok := readGuestStruct[d3d11.D3D11_VIEWPORT](mem, addr+uint64(i)*size)
		if !ok {
			break
		}
		vals = append(vals, v)
	}
	return vals
}

func readRects(mem *mmu.MMU, addr uint64, count uint32) []d3d11.D3D11_RECT {
	vals := make([]d3d11.D3D11_RECT, 0, count)
	size := uint64(unsafe.Sizeof(d3d11.D3D11_RECT{}))
	for i := uint32(0); i < count; i++ {
		v, ok := readGuestStruct[d3d11.D3D11_RECT](mem, addr+uint64(i)*size)
		if !ok {
			break
		}
		vals = append(vals, v)
	}
	return vals
}

func readBytes(mem *mmu.MMU, addr uint64, size int) []byte {
	if addr == 0 || size <= 0 {
		return nil
	}
	buf, err := mem.ReadBytes(addr, size)
	if err != nil {
		return nil
	}
	out := make([]byte, len(buf))
	copy(out, buf)
	return out
}

func readSubresourceData(mem *mmu.MMU, addr uint64, fallback int) []byte {
	if addr == 0 {
		return nil
	}
	sub, ok := readGuestStruct[d3d11.D3D11_SUBRESOURCE_DATA](mem, addr)
	if !ok || sub.PSysMem == 0 {
		return nil
	}
	size := fallback
	if sub.SysMemSlicePitch != 0 {
		size = int(sub.SysMemSlicePitch)
	} else if sub.SysMemPitch != 0 {
		size = int(sub.SysMemPitch)
	}
	return readBytes(mem, sub.PSysMem, size)
}

func readFloat4(mem *mmu.MMU, addr uint64) [4]float32 {
	var out [4]float32
	for i := range out {
		out[i] = readFloat32At(mem, addr+uint64(i*4))
	}
	return out
}

func readFloat32At(mem *mmu.MMU, addr uint64) float32 {
	bits, err := mem.Read32(addr)
	if err != nil {
		return 0
	}
	return math.Float32frombits(bits)
}

func d3d11UpdateSize(bridge *d3d11Bridge, handle uint64, rowPitch, depthPitch uint32) int {
	if bridge == nil {
		return 0
	}
	switch v := bridge.device.Lookup(handle).(type) {
	case *d3d11.Buffer:
		return len(v.Data)
	case *d3d11.Texture2D:
		if depthPitch != 0 {
			return int(depthPitch)
		}
		if rowPitch != 0 {
			return int(rowPitch * v.Desc.Height)
		}
		return int(v.Desc.Width * v.Desc.Height * 4)
	default:
		return 0
	}
}

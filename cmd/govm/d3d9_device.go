package main

import (
	"bytes"
	"encoding/binary"
	"math"

	"github.com/mirkobrombin/Raven/pkg/d3d9"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

const (
	d3d9DeviceMethods            = 119
	d3d9TextureMethods           = 22
	d3d9VertexBufferMethods      = 14
	d3d9IndexBufferMethods       = 14
	d3d9VertexDeclarationMethods = 8
)

func d3d9CreateDeviceObject(hctx *HandlerCtx, presentParams uint64) uint64 {
	device := d3d9.NewDevice()
	if params, ok := readGuestStruct[d3d9.D3DPRESENT_PARAMETERS](hctx.Mem, presentParams); ok {
		if params.BackBufferWidth != 0 && params.BackBufferHeight != 0 {
			device.SetViewport(d3d9.Viewport{Width: params.BackBufferWidth, Height: params.BackBufferHeight, MinZ: 0, MaxZ: 1})
		}
	}
	hctx.D3D9Device = device
	return d3dCreatePayloadCOMObject(hctx.Mem, hctx.Disp, "d3d9-device", d3d9DeviceMethods, device, d3d9DeviceDispatch)
}

func d3dCreatePayloadCOMObject(mem *mmu.MMU, disp *ntapi.Dispatcher, kind string, methods int, payload any, dispatch func(ctx *ntapi.TrapContext, method int, obj *d3dCOMObject) uint32) uint64 {
	addr := d3dCreateCOMObjectFromID(mem, disp, kind, methods, 0, dispatch)
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

func d3dAddRefObject(addr uint64) {
	d3dCOMMu.Lock()
	if obj := d3dCOMObjects[addr]; obj != nil {
		obj.refCount++
	}
	d3dCOMMu.Unlock()
}

func d3dFindTextureObject(tex *d3d9.Texture) uint64 {
	d3dCOMMu.Lock()
	defer d3dCOMMu.Unlock()
	for addr, obj := range d3dCOMObjects {
		if payload, ok := obj.payload.(*d3d9.Texture); ok && payload == tex {
			return addr
		}
	}
	return 0
}

func d3dFindVertexBufferObject(vb *d3d9.VertexBuffer) uint64 {
	d3dCOMMu.Lock()
	defer d3dCOMMu.Unlock()
	for addr, obj := range d3dCOMObjects {
		if payload, ok := obj.payload.(*d3d9.VertexBuffer); ok && payload == vb {
			return addr
		}
	}
	return 0
}

func d3dFindIndexBufferObject(ib *d3d9.IndexBuffer) uint64 {
	d3dCOMMu.Lock()
	defer d3dCOMMu.Unlock()
	for addr, obj := range d3dCOMObjects {
		if payload, ok := obj.payload.(*d3d9.IndexBuffer); ok && payload == ib {
			return addr
		}
	}
	return 0
}

func d3dFindVertexDeclarationObject(decl *d3d9.VertexDeclaration) uint64 {
	d3dCOMMu.Lock()
	defer d3dCOMMu.Unlock()
	for addr, obj := range d3dCOMObjects {
		if payload, ok := obj.payload.(*d3d9.VertexDeclaration); ok && payload == decl {
			return addr
		}
	}
	return 0
}

func d3dLookupPayload[T any](addr uint64) (T, bool) {
	var zero T
	d3dCOMMu.Lock()
	defer d3dCOMMu.Unlock()
	obj := d3dCOMObjects[addr]
	if obj == nil {
		return zero, false
	}
	payload, ok := obj.payload.(T)
	return payload, ok
}

func d3d9DeviceDispatch(ctx *ntapi.TrapContext, method int, obj *d3dCOMObject) uint32 {
	device, ok := obj.payload.(*d3d9.Device)
	if !ok || device == nil {
		return E_POINTER
	}

	switch method {
	case 3, 5, 16, 17, 18, 20, 21, 22, 30, 31, 32, 33, 34, 35, 37, 39, 61, 70, 71, 72, 73, 74, 77, 79, 80, 81, 82, 83, 84, 91, 92, 93, 94, 95, 96, 97, 98, 99, 102, 103, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118:
		return D3D_OK
	case 4:
		ctx.SetReturn(256 << 20)
		return 0
	case 6:
		ppD3D := ctx.Arg(1)
		if ppD3D == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppD3D, 0)
		addr := d3dCreatePayloadCOMObject(ctx.Mem, ctx.Disp, "d3d9", 17, nil, d3d9Dispatch)
		if addr == 0 {
			return E_OUTOFMEMORY
		}
		d3dAddRefObject(addr)
		ctx.Mem.Write64(ppD3D, addr)
		return D3D_OK
	case 7:
		if pCaps := ctx.Arg(1); pCaps != 0 {
			writeD3DCaps9(ctx.Mem, pCaps)
			return D3D_OK
		}
		return E_POINTER
	case 8:
		pMode := ctx.Arg(2)
		if pMode == 0 {
			return E_POINTER
		}
		writeD3DDisplayMode(ctx.Mem, pMode, maxU32(device.Viewport.Width, 1920), maxU32(device.Viewport.Height, 1080))
		return D3D_OK
	case 9:
		if pParams := ctx.Arg(1); pParams != 0 {
			ctx.Mem.WriteBytes(pParams, make([]byte, 24))
			return D3D_OK
		}
		return E_POINTER
	case 23:
		return d3d9DeviceCreateTexture(ctx)
	case 26:
		return d3d9DeviceCreateVertexBuffer(ctx)
	case 27:
		return d3d9DeviceCreateIndexBuffer(ctx)
	case 41:
		device.SceneActive = true
		return D3D_OK
	case 42:
		device.SceneActive = false
		return D3D_OK
	case 43:
		device.ClearFlags = uint32(ctx.Arg(3))
		device.ClearColor = uint32(ctx.Arg(4))
		device.ClearDepth = math.Float32frombits(uint32(ctx.Arg(5)))
		device.ClearStencil = uint32(ctx.Arg(6))
		return D3D_OK
	case 44:
		matrix, ok := readGuestStruct[[16]float32](ctx.Mem, ctx.Arg(2))
		if !ok {
			return E_POINTER
		}
		device.SetTransform(uint32(ctx.Arg(1)), matrix)
		return D3D_OK
	case 45:
		pMatrix := ctx.Arg(2)
		if pMatrix == 0 {
			return E_POINTER
		}
		matrix, found := device.Transforms[uint32(ctx.Arg(1))]
		if !found {
			matrix = identityMatrix()
		}
		writeGuestStruct(ctx.Mem, pMatrix, matrix)
		return D3D_OK
	case 47:
		vp, ok := readGuestStruct[d3d9.Viewport](ctx.Mem, ctx.Arg(1))
		if !ok {
			return E_POINTER
		}
		device.SetViewport(vp)
		return D3D_OK
	case 48:
		if pViewport := ctx.Arg(1); pViewport != 0 {
			writeGuestStruct(ctx.Mem, pViewport, device.Viewport)
			return D3D_OK
		}
		return E_POINTER
	case 49:
		material, ok := readGuestStruct[d3d9.D3DMATERIAL9](ctx.Mem, ctx.Arg(1))
		if !ok {
			return E_POINTER
		}
		device.Material = material
		return D3D_OK
	case 50:
		if pMaterial := ctx.Arg(1); pMaterial != 0 {
			writeGuestStruct(ctx.Mem, pMaterial, device.Material)
			return D3D_OK
		}
		return E_POINTER
	case 51:
		light, ok := readGuestStruct[d3d9.D3DLIGHT9](ctx.Mem, ctx.Arg(2))
		if !ok {
			return E_POINTER
		}
		device.Lights[uint32(ctx.Arg(1))] = light
		return D3D_OK
	case 52:
		pLight := ctx.Arg(2)
		if pLight == 0 {
			return E_POINTER
		}
		light, ok := device.Lights[uint32(ctx.Arg(1))]
		if !ok {
			return D3DERR_NOTAVAILABLE
		}
		writeGuestStruct(ctx.Mem, pLight, light)
		return D3D_OK
	case 53:
		device.LightEnabled[uint32(ctx.Arg(1))] = ctx.Arg(2) != 0
		return D3D_OK
	case 54:
		pEnable := ctx.Arg(2)
		if pEnable == 0 {
			return E_POINTER
		}
		var enabled uint32
		if device.LightEnabled[uint32(ctx.Arg(1))] {
			enabled = 1
		}
		ctx.Mem.Write32(pEnable, enabled)
		return D3D_OK
	case 55:
		plane, ok := readGuestStruct[[4]float32](ctx.Mem, ctx.Arg(2))
		if !ok {
			return E_POINTER
		}
		index := uint32(ctx.Arg(1))
		if index >= uint32(len(device.ClipPlanes)) {
			return D3DERR_NOTAVAILABLE
		}
		device.ClipPlanes[index] = plane
		return D3D_OK
	case 56:
		pPlane := ctx.Arg(2)
		index := uint32(ctx.Arg(1))
		if pPlane == 0 {
			return E_POINTER
		}
		if index >= uint32(len(device.ClipPlanes)) {
			return D3DERR_NOTAVAILABLE
		}
		writeGuestStruct(ctx.Mem, pPlane, device.ClipPlanes[index])
		return D3D_OK
	case 57:
		device.SetRenderState(uint32(ctx.Arg(1)), uint32(ctx.Arg(2)))
		return D3D_OK
	case 58:
		pValue := ctx.Arg(2)
		if pValue == 0 {
			return E_POINTER
		}
		ctx.Mem.Write32(pValue, device.GetRenderState(uint32(ctx.Arg(1))))
		return D3D_OK
	case 64:
		ppTexture := ctx.Arg(2)
		if ppTexture == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppTexture, 0)
		stage := uint32(ctx.Arg(1))
		if stage >= uint32(len(device.CurrentTextures)) || device.CurrentTextures[stage] == nil {
			return D3D_OK
		}
		addr := d3dFindTextureObject(device.CurrentTextures[stage])
		if addr != 0 {
			d3dAddRefObject(addr)
			ctx.Mem.Write64(ppTexture, addr)
		}
		return D3D_OK
	case 65:
		stage := uint32(ctx.Arg(1))
		if stage >= uint32(len(device.CurrentTextures)) {
			return D3DERR_NOTAVAILABLE
		}
		if ctx.Arg(2) == 0 {
			device.CurrentTextures[stage] = nil
			return D3D_OK
		}
		tex, ok := d3dLookupPayload[*d3d9.Texture](ctx.Arg(2))
		if !ok {
			return E_POINTER
		}
		device.CurrentTextures[stage] = tex
		return D3D_OK
	case 66:
		pValue := ctx.Arg(3)
		if pValue == 0 {
			return E_POINTER
		}
		stage := uint32(ctx.Arg(1))
		if stage >= uint32(len(device.TextureStageStates)) {
			return D3DERR_NOTAVAILABLE
		}
		ctx.Mem.Write32(pValue, device.TextureStageStates[stage][uint32(ctx.Arg(2))])
		return D3D_OK
	case 67:
		device.SetTextureStageState(uint32(ctx.Arg(1)), uint32(ctx.Arg(2)), uint32(ctx.Arg(3)))
		return D3D_OK
	case 68:
		pValue := ctx.Arg(3)
		if pValue == 0 {
			return E_POINTER
		}
		sampler := uint32(ctx.Arg(1))
		if sampler >= uint32(len(device.SamplerStates)) {
			return D3DERR_NOTAVAILABLE
		}
		ctx.Mem.Write32(pValue, device.SamplerStates[sampler][uint32(ctx.Arg(2))])
		return D3D_OK
	case 69:
		device.SetSamplerState(uint32(ctx.Arg(1)), uint32(ctx.Arg(2)), uint32(ctx.Arg(3)))
		return D3D_OK
	case 75:
		rect, ok := readGuestStruct[d3d9.Rect](ctx.Mem, ctx.Arg(1))
		if !ok {
			return E_POINTER
		}
		device.ScissorRect = rect
		return D3D_OK
	case 76:
		if pRect := ctx.Arg(1); pRect != 0 {
			writeGuestStruct(ctx.Mem, pRect, device.ScissorRect)
			return D3D_OK
		}
		return E_POINTER
	case 86:
		return d3d9DeviceCreateVertexDeclaration(ctx, device)
	case 87:
		if ctx.Arg(1) == 0 {
			device.CurrentVertexDecl = nil
			device.VertexDeclaration = nil
			return D3D_OK
		}
		decl, ok := d3dLookupPayload[*d3d9.VertexDeclaration](ctx.Arg(1))
		if !ok {
			return E_POINTER
		}
		device.CurrentVertexDecl = decl
		device.VertexDeclaration = append([]d3d9.VertexElement(nil), decl.Elements...)
		return D3D_OK
	case 88:
		ppDecl := ctx.Arg(1)
		if ppDecl == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppDecl, 0)
		if device.CurrentVertexDecl != nil {
			addr := d3dFindVertexDeclarationObject(device.CurrentVertexDecl)
			if addr != 0 {
				d3dAddRefObject(addr)
				ctx.Mem.Write64(ppDecl, addr)
			}
		}
		return D3D_OK
	case 89:
		device.FVF = uint32(ctx.Arg(1))
		return D3D_OK
	case 90:
		ctx.SetReturn(uint64(device.FVF))
		return 0
	case 100:
		stream := uint32(ctx.Arg(1))
		if stream >= uint32(len(device.StreamSources)) {
			return D3DERR_NOTAVAILABLE
		}
		if ctx.Arg(2) == 0 {
			device.StreamSources[stream] = d3d9.StreamSource{Offset: uint32(ctx.Arg(3)), Stride: uint32(ctx.Arg(4))}
			return D3D_OK
		}
		vb, ok := d3dLookupPayload[*d3d9.VertexBuffer](ctx.Arg(2))
		if !ok {
			return E_POINTER
		}
		device.StreamSources[stream] = d3d9.StreamSource{Buffer: vb, Offset: uint32(ctx.Arg(3)), Stride: uint32(ctx.Arg(4))}
		return D3D_OK
	case 101:
		ppVB := ctx.Arg(2)
		pOffset := ctx.Arg(3)
		pStride := ctx.Arg(4)
		if ppVB == 0 || pOffset == 0 || pStride == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppVB, 0)
		stream := uint32(ctx.Arg(1))
		if stream >= uint32(len(device.StreamSources)) {
			return D3DERR_NOTAVAILABLE
		}
		source := device.StreamSources[stream]
		ctx.Mem.Write32(pOffset, source.Offset)
		ctx.Mem.Write32(pStride, source.Stride)
		if source.Buffer != nil {
			addr := d3dFindVertexBufferObject(source.Buffer)
			if addr != 0 {
				d3dAddRefObject(addr)
				ctx.Mem.Write64(ppVB, addr)
			}
		}
		return D3D_OK
	case 104:
		if ctx.Arg(1) == 0 {
			device.IndexBuffer = nil
			return D3D_OK
		}
		ib, ok := d3dLookupPayload[*d3d9.IndexBuffer](ctx.Arg(1))
		if !ok {
			return E_POINTER
		}
		device.IndexBuffer = ib
		return D3D_OK
	case 105:
		ppIB := ctx.Arg(1)
		if ppIB == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppIB, 0)
		if device.IndexBuffer != nil {
			addr := d3dFindIndexBufferObject(device.IndexBuffer)
			if addr != 0 {
				d3dAddRefObject(addr)
				ctx.Mem.Write64(ppIB, addr)
			}
		}
		return D3D_OK
	default:
		return D3D_OK
	}
}

func d3d9ResourceDispatch(ctx *ntapi.TrapContext, method int, obj *d3dCOMObject) uint32 {
	switch payload := obj.payload.(type) {
	case *d3d9.Texture:
		switch method {
		case 10:
			ctx.SetReturn(uint64(d3d9.D3DRTYPE_TEXTURE))
			return 0
		case 13:
			ctx.SetReturn(uint64(len(payload.Levels)))
			return 0
		case 19, 20:
			return D3D_OK
		}
	case *d3d9.VertexBuffer:
		switch method {
		case 10:
			ctx.SetReturn(uint64(d3d9.D3DRTYPE_VERTEXBUFFER))
			return 0
		case 11, 12:
			return D3D_OK
		}
	case *d3d9.IndexBuffer:
		switch method {
		case 10:
			ctx.SetReturn(uint64(d3d9.D3DRTYPE_INDEXBUFFER))
			return 0
		case 11, 12:
			return D3D_OK
		}
	case *d3d9.VertexDeclaration:
		if method == 7 {
			pNumElements := ctx.Arg(2)
			if pNumElements != 0 {
				ctx.Mem.Write32(pNumElements, uint32(len(payload.Elements)))
			}
			return D3D_OK
		}
	}
	return D3D_OK
}

func d3d9DeviceCreateTexture(ctx *ntapi.TrapContext) uint32 {
	ppTexture := ctx.Arg(7)
	if ppTexture == 0 {
		return E_POINTER
	}
	ctx.Mem.Write64(ppTexture, 0)
	tex := d3d9.NewTexture(uint32(ctx.Arg(1)), uint32(ctx.Arg(2)), uint32(ctx.Arg(3)), uint32(ctx.Arg(5)), uint32(ctx.Arg(6)))
	tex.Usage = uint32(ctx.Arg(4))
	addr := d3dCreatePayloadCOMObject(ctx.Mem, ctx.Disp, "d3d9-texture", d3d9TextureMethods, tex, d3d9ResourceDispatch)
	if addr == 0 {
		return E_OUTOFMEMORY
	}
	ctx.Mem.Write64(ppTexture, addr)
	return D3D_OK
}

func d3d9DeviceCreateVertexBuffer(ctx *ntapi.TrapContext) uint32 {
	ppVB := ctx.Arg(5)
	if ppVB == 0 {
		return E_POINTER
	}
	ctx.Mem.Write64(ppVB, 0)
	vb := &d3d9.VertexBuffer{
		Size:  uint32(ctx.Arg(1)),
		Usage: uint32(ctx.Arg(2)),
		FVF:   uint32(ctx.Arg(3)),
		Pool:  uint32(ctx.Arg(4)),
		Data:  make([]byte, uint32(ctx.Arg(1))),
	}
	addr := d3dCreatePayloadCOMObject(ctx.Mem, ctx.Disp, "d3d9-vertex-buffer", d3d9VertexBufferMethods, vb, d3d9ResourceDispatch)
	if addr == 0 {
		return E_OUTOFMEMORY
	}
	ctx.Mem.Write64(ppVB, addr)
	return D3D_OK
}

func d3d9DeviceCreateIndexBuffer(ctx *ntapi.TrapContext) uint32 {
	ppIB := ctx.Arg(5)
	if ppIB == 0 {
		return E_POINTER
	}
	ctx.Mem.Write64(ppIB, 0)
	ib := &d3d9.IndexBuffer{
		Size:   uint32(ctx.Arg(1)),
		Format: uint32(ctx.Arg(3)),
		Pool:   uint32(ctx.Arg(4)),
		Data:   make([]byte, uint32(ctx.Arg(1))),
	}
	addr := d3dCreatePayloadCOMObject(ctx.Mem, ctx.Disp, "d3d9-index-buffer", d3d9IndexBufferMethods, ib, d3d9ResourceDispatch)
	if addr == 0 {
		return E_OUTOFMEMORY
	}
	ctx.Mem.Write64(ppIB, addr)
	return D3D_OK
}

func d3d9DeviceCreateVertexDeclaration(ctx *ntapi.TrapContext, device *d3d9.Device) uint32 {
	ppDecl := ctx.Arg(2)
	if ppDecl == 0 {
		return E_POINTER
	}
	ctx.Mem.Write64(ppDecl, 0)
	elements, ok := readVertexElements(ctx.Mem, ctx.Arg(1))
	if !ok {
		return E_POINTER
	}
	decl := &d3d9.VertexDeclaration{Elements: elements}
	device.CurrentVertexDecl = decl
	device.VertexDeclaration = append([]d3d9.VertexElement(nil), elements...)
	addr := d3dCreatePayloadCOMObject(ctx.Mem, ctx.Disp, "d3d9-vertex-declaration", d3d9VertexDeclarationMethods, decl, d3d9ResourceDispatch)
	if addr == 0 {
		return E_OUTOFMEMORY
	}
	ctx.Mem.Write64(ppDecl, addr)
	return D3D_OK
}

func readVertexElements(mem *mmu.MMU, addr uint64) ([]d3d9.VertexElement, bool) {
	if addr == 0 {
		return nil, false
	}
	var elements []d3d9.VertexElement
	for i := 0; i < 64; i++ {
		elem, ok := readGuestStruct[d3d9.VertexElement](mem, addr+uint64(i*8))
		if !ok {
			return nil, false
		}
		if elem.Stream == 0xFF && elem.Type == d3d9.D3DDECLTYPE_UNUSED {
			break
		}
		elements = append(elements, elem)
	}
	return elements, true
}

func readGuestStruct[T any](mem *mmu.MMU, addr uint64) (T, bool) {
	var out T
	if addr == 0 {
		return out, false
	}
	size := binary.Size(out)
	if size <= 0 {
		return out, false
	}
	buf, err := mem.ReadBytes(addr, size)
	if err != nil {
		return out, false
	}
	if err := binary.Read(bytes.NewReader(buf), binary.LittleEndian, &out); err != nil {
		return out, false
	}
	return out, true
}

func writeGuestStruct(mem *mmu.MMU, addr uint64, value any) bool {
	if addr == 0 {
		return false
	}
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, value); err != nil {
		return false
	}
	return mem.WriteBytes(addr, buf.Bytes()) == nil
}

func identityMatrix() [16]float32 {
	return [16]float32{1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1}
}

func maxU32(a, b uint32) uint32 {
	if a > b {
		return a
	}
	return b
}

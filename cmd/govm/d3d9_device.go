//go:build guest_windows

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"sync"

	"github.com/mirkobrombin/Raven/pkg/d3d9"
	ravelog "github.com/mirkobrombin/Raven/pkg/log"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
	"github.com/mirkobrombin/Raven/pkg/wl"
)

const (
	d3d9DeviceMethods            = 119
	d3d9TextureMethods           = 22
	d3d9VertexBufferMethods      = 14
	d3d9IndexBufferMethods       = 14
	d3d9VertexDeclarationMethods = 5
	d3d9SurfaceMethods           = 17
)

// d3d9Bridge bundles device + renderer + host context so the COM dispatch
// function can reach all three without a separate lookup.
type d3d9Bridge struct {
	hctx            *HandlerCtx
	device          *d3d9.Device
	renderer        *d3d9.Renderer
	shmDirty        bool
	deviceCOM       uint64
	swapChainCOM    uint64
	backBufferCOM   uint64
	depthSurfaceCOM uint64
	present         d3d9.D3DPRESENT_PARAMETERS
	trace           bool
	cacheMu         sync.Mutex
	shaderCache     map[string]*d3d9.ShaderProgram
	lifetimeMu      sync.Mutex
	liveObjects     int
}

type d3d9CubeTexture struct {
	faces [6]*d3d9.Texture
}

type d3d9SurfacePayload struct {
	bridge *d3d9Bridge
	desc   d3d9SurfaceDesc
}

type d3d9SurfaceDesc struct {
	Format             uint32
	Type               uint32
	Usage              uint32
	Pool               uint32
	MultiSampleType    uint32
	MultiSampleQuality uint32
	Width              uint32
	Height             uint32
}

type d3d9SwapChainPayload struct {
	bridge          *d3d9Bridge
	present         d3d9.D3DPRESENT_PARAMETERS
	backBufferCache *uint64
}

func d3d9DeviceArgCounts() []int {
	return []int{
		3, 1, 1, 1, 1, 1, 2, 2, 3, 2,
		4, 4, 2, 3, 3, 1, 2, 5, 5, 3,
		2, 4, 3, 9, 10, 8, 7, 7, 9, 9,
		5, 3, 3, 3, 6, 4, 7, 3, 3, 2,
		2, 1, 1, 7, 3, 3, 3, 2, 2, 2,
		2, 3, 3, 3, 3, 3, 3, 3, 3, 3,
		1, 2, 2, 2, 3, 3, 4, 4, 4, 4,
		2, 3, 3, 2, 2, 2, 2, 2, 1, 2,
		1, 4, 7, 5, 9, 7, 3, 2, 2, 2,
		2, 3, 2, 2, 4, 4, 4, 4, 4, 4,
		5, 5, 3, 3, 2, 2, 3, 2, 2, 4,
		4, 4, 4, 4, 4, 4, 4, 2, 3,
	}
}

func d3d9TextureArgCounts(cube bool) []int {
	counts := []int{3, 1, 1, 2, 5, 4, 2, 2, 1, 1, 1, 2, 1, 1, 2, 1, 1, 3, 3, 5, 2, 2}
	if cube {
		counts[18], counts[19], counts[20], counts[21] = 4, 6, 3, 3
	}
	return counts
}

func d3d9BufferArgCounts() []int {
	return []int{3, 1, 1, 2, 5, 4, 2, 2, 1, 1, 1, 5, 1, 2}
}

func d3d9VertexDeclarationArgCounts() []int {
	return []int{3, 1, 1, 2, 3}
}

func d3d9SurfaceArgCounts() []int {
	return []int{3, 1, 1, 2, 5, 4, 2, 2, 1, 1, 1, 3, 2, 4, 1, 2, 2}
}

func d3d9SwapChainArgCounts() []int {
	return []int{3, 1, 1, 6, 2, 4, 2, 2, 2, 2}
}

func d3d9ShaderArgCounts() []int {
	return []int{3, 1, 1, 2, 3}
}

func d3d9CreateDeviceObject(hctx *HandlerCtx, presentParams uint64) uint64 {
	device := d3d9.NewDevice()
	// Default to window size; fall back to 800x600 if no window exists.
	width, height := uint32(800), uint32(600)
	if win := hctx.WlWindow; win != nil && win.Width > 0 && win.Height > 0 {
		width, height = uint32(win.Width), uint32(win.Height)
	}
	var present d3d9.D3DPRESENT_PARAMETERS
	is32 := hctx.ProcState != nil && hctx.ProcState.Is32
	if params, ok := readD3DPresentParameters(hctx.Mem, presentParams, is32); ok {
		present = params
		if params.BackBufferWidth != 0 && params.BackBufferHeight != 0 {
			width, height = params.BackBufferWidth, params.BackBufferHeight
		}
	}
	device.SetViewport(d3d9.Viewport{Width: width, Height: height, MinZ: 0, MaxZ: 1})
	hctx.D3D9Device = device

	renderer, err := d3d9.NewRenderer(width, height)
	if err != nil {
		ravelog.Logf("[d3d9] renderer initialization failed: %v\n", err)
		renderer = nil
	}
	hctx.D3D9Renderer = renderer

	present.BackBufferWidth = width
	present.BackBufferHeight = height
	if present.BackBufferFormat == 0 {
		present.BackBufferFormat = d3d9.D3DFMT_X8R8G8B8
	}
	bridge := &d3d9Bridge{
		hctx:        hctx,
		device:      device,
		renderer:    renderer,
		present:     present,
		trace:       os.Getenv("RAVEN_TRACE_D3D9") != "",
		shaderCache: make(map[string]*d3d9.ShaderProgram),
		liveObjects: 1,
	}
	bridge.deviceCOM = d3dCreatePayloadCOMObject(hctx.Mem, hctx.Disp, "d3d9-device", d3d9DeviceMethods, bridge, d3d9DeviceDispatch, d3d9DeviceArgCounts())
	if bridge.deviceCOM != 0 {
		d3dCOMMu.Lock()
		if obj := d3dCOMObjects[bridge.deviceCOM]; obj != nil {
			obj.externalZero = bridge.releaseCaches
			obj.finalize = bridge.release
		}
		d3dCOMMu.Unlock()
	} else {
		hctx.D3D9Device = nil
		hctx.D3D9Renderer = nil
		if renderer != nil {
			renderer.Close()
		}
	}
	return bridge.deviceCOM
}

func (bridge *d3d9Bridge) releaseCaches() {
	bridge.cacheMu.Lock()
	objects := []uint64{bridge.backBufferCOM, bridge.depthSurfaceCOM, bridge.swapChainCOM}
	bridge.backBufferCOM = 0
	bridge.depthSurfaceCOM = 0
	bridge.swapChainCOM = 0
	bridge.cacheMu.Unlock()
	for _, addr := range objects {
		if addr != 0 {
			d3dReleaseObject(addr)
		}
	}
}

func (bridge *d3d9Bridge) rendererSnapshot() *d3d9.Renderer {
	bridge.lifetimeMu.Lock()
	renderer := bridge.renderer
	bridge.lifetimeMu.Unlock()
	return renderer
}

func (bridge *d3d9Bridge) retain() {
	bridge.lifetimeMu.Lock()
	bridge.liveObjects++
	bridge.lifetimeMu.Unlock()
}

func (bridge *d3d9Bridge) release() {
	bridge.lifetimeMu.Lock()
	if bridge.liveObjects > 0 {
		bridge.liveObjects--
	}
	if bridge.liveObjects != 0 {
		bridge.lifetimeMu.Unlock()
		return
	}
	renderer := bridge.renderer
	bridge.renderer = nil
	if bridge.hctx != nil && bridge.hctx.D3D9Renderer == renderer {
		bridge.hctx.D3D9Renderer = nil
	}
	bridge.lifetimeMu.Unlock()
	if renderer != nil {
		renderer.Close()
	}
}

func d3d9AttachBridgeLifetime(addr uint64, bridge *d3d9Bridge) {
	if addr == 0 || bridge == nil {
		return
	}
	bridge.retain()
	d3dCOMMu.Lock()
	if obj := d3dCOMObjects[addr]; obj != nil {
		device := d3dCOMObjects[bridge.deviceCOM]
		if device == nil {
			d3dCOMMu.Unlock()
			bridge.release()
			return
		}
		device.refCount++
		device.internalRefs++
		previous := obj.finalize
		obj.finalize = func() {
			if previous != nil {
				previous()
			}
			d3dReleaseInternalObject(bridge.deviceCOM)
			bridge.release()
		}
		d3dCOMMu.Unlock()
		return
	}
	d3dCOMMu.Unlock()
	bridge.release()
}

func readD3DPresentParameters(mem *mmu.MMU, addr uint64, is32 bool) (d3d9.D3DPRESENT_PARAMETERS, bool) {
	var p d3d9.D3DPRESENT_PARAMETERS
	if addr == 0 {
		return p, false
	}
	fields := []*uint32{
		&p.BackBufferWidth, &p.BackBufferHeight, &p.BackBufferFormat, &p.BackBufferCount,
		&p.MultiSampleType, &p.MultiSampleQuality, &p.SwapEffect,
	}
	for i, field := range fields {
		value, err := mem.Read32(addr + uint64(i*4))
		if err != nil {
			return p, false
		}
		*field = value
	}
	windowOffset := uint64(28)
	pointerSize := uint64(4)
	if is32 {
		value, err := mem.Read32(addr + windowOffset)
		if err != nil {
			return p, false
		}
		p.HDeviceWindow = uint64(value)
	} else {
		windowOffset = 32
		pointerSize = 8
		value, err := mem.Read64(addr + windowOffset)
		if err != nil {
			return p, false
		}
		p.HDeviceWindow = value
	}
	tail := []*uint32{
		&p.Windowed, &p.EnableAutoDepthStencil, &p.AutoDepthStencilFormat, &p.Flags,
		&p.FullScreenRefreshRateInHz, &p.PresentationInterval,
	}
	tailOffset := windowOffset + pointerSize
	for i, field := range tail {
		value, err := mem.Read32(addr + tailOffset + uint64(i*4))
		if err != nil {
			return p, false
		}
		*field = value
	}
	return p, true
}

func d3dCreatePayloadCOMObject(mem *mmu.MMU, disp *ntapi.Dispatcher, kind string, methods int, payload any, dispatch func(ctx *ntapi.TrapContext, method int, obj *d3dCOMObject) uint32, stdcallArgs ...[]int) uint64 {
	addr := d3dCreateCOMObjectFromID(mem, disp, kind, methods, 0, dispatch, stdcallArgs...)
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

func d3dAddRefObject(addr uint64) bool {
	d3dCOMMu.Lock()
	found := false
	if obj := d3dCOMObjects[addr]; obj != nil {
		obj.refCount++
		found = true
	}
	d3dCOMMu.Unlock()
	return found
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

// dumpD3D9ShaderBytecode logs the D3D9 shader token stream at pFunc (guest
// pointer) when RAVEN_DUMP_SHADERS is set, so we can see the exact SM2 opcode
// set kkrieger uses before building the SM2->SPIR-V translator. The stream is
// DWORD tokens: version (0xFFFE02xx vs / 0xFFFF02xx ps), instructions, then
// the END token 0x0000FFFF.
func dumpD3D9ShaderBytecode(ctx *ntapi.TrapContext, pFunc uint64, kind string) {
	if os.Getenv("RAVEN_DUMP_SHADERS") == "" || pFunc == 0 {
		return
	}
	var toks []uint32
	for i := 0; i < 4096; i++ {
		w, err := ctx.Mem.Read32(pFunc + uint64(i)*4)
		if err != nil {
			break
		}
		toks = append(toks, w)
		if w == 0x0000FFFF { // END token
			break
		}
	}
	if len(toks) == 0 {
		return
	}
	ver := toks[0]
	ravelog.Logf("[shader-dump] %s bytecode ptr=0x%x version=0x%08x ntokens=%d\n", kind, pFunc, ver, len(toks))
	line := "[shader-dump]  "
	for i, w := range toks {
		line += fmt.Sprintf("%08x ", w)
		if (i+1)%8 == 0 {
			ravelog.Logf("%s\n", line)
			line = "[shader-dump]  "
		}
	}
	if line != "[shader-dump]  " {
		ravelog.Logf("%s\n", line)
	}
}

// readD3D9ShaderTokens reads a D3D9 shader token stream (until the END token)
// from guest memory at pFunc.
func readD3D9ShaderTokens(ctx *ntapi.TrapContext, pFunc uint64) []uint32 {
	var toks []uint32
	for i := 0; i < 8192; i++ {
		w, err := ctx.Mem.Read32(pFunc + uint64(i)*4)
		if err != nil {
			break
		}
		toks = append(toks, w)
		if w == 0x0000FFFF {
			break
		}
	}
	return toks
}

func (bridge *d3d9Bridge) shaderProgram(toks []uint32, isVertex bool) *d3d9.ShaderProgram {
	keyBytes := make([]byte, 1+len(toks)*4)
	if isVertex {
		keyBytes[0] = 1
	}
	for i, tok := range toks {
		binary.LittleEndian.PutUint32(keyBytes[1+i*4:], tok)
	}
	key := string(keyBytes)

	bridge.cacheMu.Lock()
	defer bridge.cacheMu.Unlock()
	if bridge.shaderCache == nil {
		bridge.shaderCache = make(map[string]*d3d9.ShaderProgram)
	}
	if prog := bridge.shaderCache[key]; prog != nil {
		return prog
	}

	prog := &d3d9.ShaderProgram{}
	if sh, ok := d3d9.ParseSM(toks); ok {
		prog.Parsed = sh
		if isVertex {
			if spirv, err := d3d9.EmitVertexSPIRV(sh); err == nil {
				prog.SPIRV = spirv
				ravelog.Logf("[d3d9] translated vertex shader vs_%d_%d -> %d bytes SPIR-V\n", sh.MajorVer, sh.MinorVer, len(spirv))
			} else {
				ravelog.Logf("[d3d9] vertex shader vs_%d_%d translation failed: %v\n", sh.MajorVer, sh.MinorVer, err)
			}
		}
	}
	bridge.shaderCache[key] = prog
	return prog
}

// d3d9CreateShaderObject parses and (for vertex shaders) translates a D3D9
// programmable shader to SPIR-V, storing a *d3d9.ShaderProgram as the COM
// object payload so SetVertexShader/SetPixelShader can bind it. A translation
// failure still returns a valid (untranslated) object so the guest keeps
// running; the renderer falls back to the fixed-function path for it.
func d3d9CreateShaderObject(ctx *ntapi.TrapContext, outArg int, kind string, bridge *d3d9Bridge, pFunc uint64, isVertex bool) uint32 {
	ppObject := ctx.Arg(outArg)
	if ppObject == 0 {
		return E_POINTER
	}
	toks := readD3D9ShaderTokens(ctx, pFunc)
	prog := &d3d9.ShaderProgram{}
	if len(toks) >= 2 {
		prog = bridge.shaderProgram(toks, isVertex)
	}
	writeGuestPtr(ctx, ppObject, 0)
	addr := d3dCreatePayloadCOMObject(ctx.Mem, ctx.Disp, kind, 5, prog, func(_ *ntapi.TrapContext, _ int, _ *d3dCOMObject) uint32 {
		return D3D_OK
	}, d3d9ShaderArgCounts())
	if addr == 0 {
		return E_OUTOFMEMORY
	}
	d3d9AttachBridgeLifetime(addr, bridge)
	writeGuestPtr(ctx, ppObject, addr)
	return D3D_OK
}

// setD3D9ShaderConstantsF reads Vector4fCount vec4 float constants from the
// guest at pConstantData and stores them into dst starting at StartRegister.
// Args: (1)=StartRegister, (2)=pConstantData, (3)=Vector4fCount.
func setD3D9ShaderConstantsF(ctx *ntapi.TrapContext, dst [][4]float32) {
	start := uint32(ctx.Arg(1))
	ptr := ctx.Arg(2)
	count := uint32(ctx.Arg(3))
	if ptr == 0 {
		return
	}
	for i := uint32(0); i < count; i++ {
		reg := start + i
		if int(reg) >= len(dst) {
			break
		}
		for c := 0; c < 4; c++ {
			bits, err := ctx.Mem.Read32(ptr + uint64(i)*16 + uint64(c)*4)
			if err != nil {
				return
			}
			dst[reg][c] = math.Float32frombits(bits)
		}
	}
}

func d3d9DeviceDispatch(ctx *ntapi.TrapContext, method int, obj *d3dCOMObject) uint32 {
	bridge, ok := obj.payload.(*d3d9Bridge)
	if !ok || bridge == nil || bridge.device == nil {
		return E_POINTER
	}
	device := bridge.device
	if bridge.trace {
		ravelog.Logf("[d3d9-trace] device method=%d\n", method)
	}
	if os.Getenv("RAVEN_TRACE_D3D9_ESP") != "" {
		esp := uint64(0)
		if rr, ok := ctx.CPU.(ntapi.RegisterReader); ok {
			esp = rr.ReadReg(4)
		}
		ravelog.Logf("[d3d9-esp] device method=%d esp=0x%x\n", method, esp)
	}

	switch method {
	case 3, 5, 16, 20, 21, 22, 30, 31, 32, 33, 34, 37, 39, 61, 70, 71, 72, 73, 74, 77, 79, 80, 84, 93, 95, 96, 97, 98, 99, 102, 103, 108, 110, 111, 112, 113, 114, 115, 116, 117, 118:
		return D3D_OK
	case 94: // SetVertexShaderConstantF(StartRegister, pConstantData, Vector4fCount)
		setD3D9ShaderConstantsF(ctx, device.VSConstants[:])
		return D3D_OK
	case 109: // SetPixelShaderConstantF(StartRegister, pConstantData, Vector4fCount)
		setD3D9ShaderConstantsF(ctx, device.PSConstants[:])
		return D3D_OK
	case 4:
		ctx.SetReturn(256 << 20)
		return 0
	case 6:
		ppD3D := ctx.Arg(1)
		if ppD3D == 0 {
			return E_POINTER
		}
		writeGuestPtr(ctx, ppD3D, 0)
		addr := d3dCreatePayloadCOMObject(ctx.Mem, ctx.Disp, "d3d9", 17, nil, d3d9Dispatch)
		if addr == 0 {
			return E_OUTOFMEMORY
		}
		d3dAddRefObject(addr)
		writeGuestPtr(ctx, ppD3D, addr)
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
	case 13:
		return d3d9DeviceCreateAdditionalSwapChain(ctx, bridge)
	case 14:
		return d3d9DeviceGetSwapChain(ctx, bridge)
	case 15:
		ctx.SetReturn(1)
		return 0
	case 18:
		return d3d9WriteCachedSurface(ctx, bridge, &bridge.backBufferCOM, ctx.Arg(4), "d3d9-back-buffer")
	case 19:
		status := ctx.Arg(2)
		if status == 0 {
			return E_POINTER
		}
		ctx.Mem.Write32(status, 0)
		ctx.Mem.Write32(status+4, 0)
		return D3D_OK
	case 23:
		return d3d9DeviceCreateTexture(ctx, bridge)
	case 25:
		return d3d9DeviceCreateCubeTexture(ctx, bridge)
	case 26:
		return d3d9DeviceCreateVertexBuffer(ctx, bridge)
	case 27:
		return d3d9DeviceCreateIndexBuffer(ctx, bridge)
	case 28:
		return d3d9DeviceCreateSurfaceObject(ctx, 7, bridge, "d3d9-render-target", d3d9SurfaceDesc{
			Format: uint32(ctx.Arg(3)), Type: d3d9.D3DRTYPE_SURFACE, Usage: d3d9.D3DUSAGE_RENDERTARGET,
			Pool: d3d9.D3DPOOL_DEFAULT, MultiSampleType: uint32(ctx.Arg(4)), MultiSampleQuality: uint32(ctx.Arg(5)),
			Width: uint32(ctx.Arg(1)), Height: uint32(ctx.Arg(2)),
		})
	case 29:
		return d3d9DeviceCreateSurfaceObject(ctx, 7, bridge, "d3d9-depth-surface", d3d9SurfaceDesc{
			Format: uint32(ctx.Arg(3)), Type: d3d9.D3DRTYPE_SURFACE, Usage: d3d9.D3DUSAGE_DEPTHSTENCIL,
			Pool: d3d9.D3DPOOL_DEFAULT, MultiSampleType: uint32(ctx.Arg(4)), MultiSampleQuality: uint32(ctx.Arg(5)),
			Width: uint32(ctx.Arg(1)), Height: uint32(ctx.Arg(2)),
		})
	case 36:
		return d3d9DeviceCreateSurfaceObject(ctx, 5, bridge, "d3d9-offscreen-surface", d3d9SurfaceDesc{
			Format: uint32(ctx.Arg(3)), Type: d3d9.D3DRTYPE_SURFACE, Pool: uint32(ctx.Arg(4)),
			Width: uint32(ctx.Arg(1)), Height: uint32(ctx.Arg(2)),
		})
	case 38:
		return d3d9WriteCachedSurface(ctx, bridge, &bridge.backBufferCOM, ctx.Arg(2), "d3d9-back-buffer")
	case 40:
		return d3d9WriteCachedSurface(ctx, bridge, &bridge.depthSurfaceCOM, ctx.Arg(1), "d3d9-depth-surface")
	case 35: // ColorFill(pSurface, pRect, color)
		if win := bridge.hctx.WlWindow; win != nil && d3dObjectHasKind(ctx.Arg(1), "d3d9-back-buffer") {
			var rect *[4]int32
			if rectPtr := ctx.Arg(2); rectPtr != 0 {
				var value [4]int32
				for i := range value {
					v, err := ctx.Mem.Read32(rectPtr + uint64(i*4))
					if err != nil {
						return D3DERR_INVALIDCALL
					}
					value[i] = int32(v)
				}
				rect = &value
			}
			if bridge.trace {
				ravelog.Logf("[d3d9-trace] ColorFill surface=0x%x rect=%v color=0x%08x\n", ctx.Arg(1), rect, uint32(ctx.Arg(3)))
			}
			fillD3DColorRect(win, rect, uint32(ctx.Arg(3)))
			bridge.shmDirty = true
		}
		return D3D_OK
	case 17: // Present(pSrcRect, pDstRect, hWnd, pDirtyRegion)
		if bridge.trace {
			ravelog.Logf("[d3d9-trace] Present src=0x%x dst=0x%x hwnd=0x%x dirty=0x%x\n", ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4))
		}
		win := bridge.hctx.WlWindow
		if bridge.shmDirty && win != nil {
			win.Commit()
			bridge.shmDirty = false
		} else if r := bridge.rendererSnapshot(); r != nil {
			r.Present(win)
		} else if win != nil && win.Pix != nil {
			// Software fallback: fill the entire back-buffer with the last clear color.
			c := device.ClearColor // D3DCOLOR = 0xAARRGGBB
			rr := byte(c >> 16)
			gg := byte(c >> 8)
			bb := byte(c)
			pix := win.Pix
			for i := 0; i+3 < len(pix); i += 4 {
				pix[i+0] = bb // B
				pix[i+1] = gg // G
				pix[i+2] = rr // R
				pix[i+3] = 0xFF
			}
			win.Commit()
		} else if win != nil {
			win.Commit()
		}
		return D3D_OK
	case 41: // BeginScene
		device.SceneActive = true
		if r := bridge.rendererSnapshot(); r != nil {
			r.BeginScene()
		}
		return D3D_OK
	case 42: // EndScene
		device.SceneActive = false
		if r := bridge.rendererSnapshot(); r != nil {
			r.EndScene()
		}
		return D3D_OK
	case 43: // Clear
		flags := uint32(ctx.Arg(3))
		color := uint32(ctx.Arg(4))
		z := math.Float32frombits(uint32(ctx.Arg(5)))
		stencil := uint32(ctx.Arg(6))
		device.ClearFlags = flags
		device.ClearColor = color
		device.ClearDepth = z
		device.ClearStencil = stencil
		if r := bridge.rendererSnapshot(); r != nil {
			r.Clear(flags, color, z, stencil)
		}
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
		writeGuestPtr(ctx, ppTexture, 0)
		stage := uint32(ctx.Arg(1))
		if stage >= uint32(len(device.CurrentTextures)) || device.CurrentTextures[stage] == nil {
			return D3D_OK
		}
		addr := d3dFindTextureObject(device.CurrentTextures[stage])
		if addr != 0 {
			d3dAddRefObject(addr)
			writeGuestPtr(ctx, ppTexture, addr)
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
		if ok {
			device.CurrentTextures[stage] = tex
			return D3D_OK
		}
		cube, ok := d3dLookupPayload[*d3d9CubeTexture](ctx.Arg(2))
		if !ok || cube.faces[0] == nil {
			return E_POINTER
		}
		device.CurrentTextures[stage] = cube.faces[0]
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
		return d3d9DeviceCreateVertexDeclaration(ctx, device, bridge)
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
		writeGuestPtr(ctx, ppDecl, 0)
		if device.CurrentVertexDecl != nil {
			addr := d3dFindVertexDeclarationObject(device.CurrentVertexDecl)
			if addr != 0 {
				d3dAddRefObject(addr)
				writeGuestPtr(ctx, ppDecl, addr)
			}
		}
		return D3D_OK
	case 89:
		device.FVF = uint32(ctx.Arg(1))
		return D3D_OK
	case 90:
		ctx.SetReturn(uint64(device.FVF))
		return 0
	case 91:
		dumpD3D9ShaderBytecode(ctx, ctx.Arg(1), "vertex")
		return d3d9CreateShaderObject(ctx, 2, "d3d9-vertex-shader", bridge, ctx.Arg(1), true)
	case 92: // SetVertexShader(pShader)
		if ctx.Arg(1) == 0 {
			device.CurrentVertexShader = nil
			return D3D_OK
		}
		if prog, ok := d3dLookupPayload[*d3d9.ShaderProgram](ctx.Arg(1)); ok {
			device.CurrentVertexShader = prog
		}
		return D3D_OK
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
		writeGuestPtr(ctx, ppVB, 0)
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
				writeGuestPtr(ctx, ppVB, addr)
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
		writeGuestPtr(ctx, ppIB, 0)
		if device.IndexBuffer != nil {
			addr := d3dFindIndexBufferObject(device.IndexBuffer)
			if addr != 0 {
				d3dAddRefObject(addr)
				writeGuestPtr(ctx, ppIB, addr)
			}
		}
		return D3D_OK
	case 106:
		dumpD3D9ShaderBytecode(ctx, ctx.Arg(1), "pixel")
		return d3d9CreateShaderObject(ctx, 2, "d3d9-pixel-shader", bridge, ctx.Arg(1), false)
	case 107: // SetPixelShader(pShader)
		if ctx.Arg(1) == 0 {
			device.CurrentPixelShader = nil
			return D3D_OK
		}
		if prog, ok := d3dLookupPayload[*d3d9.ShaderProgram](ctx.Arg(1)); ok {
			device.CurrentPixelShader = prog
		}
		return D3D_OK
	case 81: // DrawPrimitive(PrimType, StartVertex, PrimCount)
		if r := bridge.rendererSnapshot(); r != nil && device.SceneActive {
			r.DrawPrimitive(device, uint32(ctx.Arg(1)), uint32(ctx.Arg(2)), uint32(ctx.Arg(3)))
		}
		return D3D_OK
	case 82: // DrawIndexedPrimitive(PrimType, BaseVertexIndex, MinVertexIndex, NumVertices, StartIndex, PrimCount)
		if r := bridge.rendererSnapshot(); r != nil && device.SceneActive {
			r.DrawIndexedPrimitive(device, uint32(ctx.Arg(1)), int32(ctx.Arg(2)), uint32(ctx.Arg(3)), uint32(ctx.Arg(4)), uint32(ctx.Arg(5)), uint32(ctx.Arg(6)))
		}
		return D3D_OK
	case 83: // DrawPrimitiveUP(PrimType, PrimCount, pVertexData, Stride)
		pData := ctx.Arg(3)
		stride := uint32(ctx.Arg(4))
		if r := bridge.rendererSnapshot(); r != nil && device.SceneActive && pData != 0 && stride != 0 {
			primType := uint32(ctx.Arg(1))
			primCount := uint32(ctx.Arg(2))
			byteCount := d3d9VertexCountForPrim(primType, primCount) * stride
			if data, err := ctx.Mem.ReadBytes(pData, int(byteCount)); err == nil {
				r.DrawPrimitiveUP(device, primType, primCount, data, stride)
			}
		}
		return D3D_OK
	default:
		return D3D_OK
	}
}

func d3dObjectHasKind(addr uint64, kind string) bool {
	d3dCOMMu.Lock()
	defer d3dCOMMu.Unlock()
	obj := d3dCOMObjects[addr]
	return obj != nil && obj.kind == kind
}

func fillD3DColorRect(win *wl.Window, rect *[4]int32, color uint32) {
	if win == nil || len(win.Pix) == 0 {
		return
	}
	left, top, right, bottom := int32(0), int32(0), win.Width, win.Height
	if rect != nil {
		left, top, right, bottom = rect[0], rect[1], rect[2], rect[3]
	}
	left = max(left, 0)
	top = max(top, 0)
	right = min(right, win.Width)
	bottom = min(bottom, win.Height)
	if left >= right || top >= bottom {
		return
	}
	blue, green, red := byte(color), byte(color>>8), byte(color>>16)
	stride := int(win.Stride)
	for y := top; y < bottom; y++ {
		for x := left; x < right; x++ {
			off := int(y)*stride + int(x)*4
			win.Pix[off] = blue
			win.Pix[off+1] = green
			win.Pix[off+2] = red
			win.Pix[off+3] = 0xff
		}
	}
}

func d3d9DeviceCreateOpaqueObject(ctx *ntapi.TrapContext, outArg int, kind string, bridge *d3d9Bridge) uint32 {
	ppObject := ctx.Arg(outArg)
	if ppObject == 0 {
		return E_POINTER
	}
	writeGuestPtr(ctx, ppObject, 0)
	addr := d3dCreatePayloadCOMObject(ctx.Mem, ctx.Disp, kind, 5, struct{}{}, func(_ *ntapi.TrapContext, _ int, _ *d3dCOMObject) uint32 {
		return D3D_OK
	}, d3d9ShaderArgCounts())
	if addr == 0 {
		return E_OUTOFMEMORY
	}
	d3d9AttachBridgeLifetime(addr, bridge)
	writeGuestPtr(ctx, ppObject, addr)
	return D3D_OK
}

func d3d9DeviceCreateSurfaceObject(ctx *ntapi.TrapContext, outArg int, bridge *d3d9Bridge, kind string, desc d3d9SurfaceDesc) uint32 {
	ppSurface := ctx.Arg(outArg)
	if ppSurface == 0 {
		return E_POINTER
	}
	writeGuestPtr(ctx, ppSurface, 0)
	payload := &d3d9SurfacePayload{bridge: bridge, desc: desc}
	addr := d3dCreatePayloadCOMObject(ctx.Mem, ctx.Disp, kind, d3d9SurfaceMethods, payload, d3d9SurfaceDispatch, d3d9SurfaceArgCounts())
	if addr == 0 {
		return E_OUTOFMEMORY
	}
	d3d9AttachBridgeLifetime(addr, bridge)
	if os.Getenv("RAVEN_TRACE_STDCALL") != "" {
		esp := uint64(0)
		if rr, ok := ctx.CPU.(ntapi.RegisterReader); ok {
			esp = rr.ReadReg(4)
		}
		ravelog.Logf("[surf] CreateSurface kind=%s ppSurface(Arg%d)=0x%x addr=0x%x esp=0x%x args=[%x %x %x %x %x %x]\n",
			kind, outArg, ppSurface, addr, esp,
			ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5), ctx.Arg(6))
	}
	writeGuestPtr(ctx, ppSurface, addr)
	return D3D_OK
}

func d3d9DeviceGetSwapChain(ctx *ntapi.TrapContext, bridge *d3d9Bridge) uint32 {
	ppSwapChain := ctx.Arg(2)
	if ppSwapChain == 0 {
		return E_POINTER
	}
	writeGuestPtr(ctx, ppSwapChain, 0)
	if ctx.Arg(1) != 0 {
		return D3DERR_INVALIDCALL
	}
	bridge.cacheMu.Lock()
	defer bridge.cacheMu.Unlock()
	if bridge.swapChainCOM == 0 {
		payload := &d3d9SwapChainPayload{bridge: bridge, present: bridge.present, backBufferCache: &bridge.backBufferCOM}
		bridge.swapChainCOM = d3dCreatePayloadCOMObject(ctx.Mem, ctx.Disp, "d3d9-swap-chain", 10, payload, d3d9SwapChainDispatch, d3d9SwapChainArgCounts())
		if bridge.swapChainCOM == 0 {
			return E_OUTOFMEMORY
		}
		d3d9AttachBridgeLifetime(bridge.swapChainCOM, bridge)
	}
	d3dAddRefObject(bridge.swapChainCOM)
	writeGuestPtr(ctx, ppSwapChain, bridge.swapChainCOM)
	return D3D_OK
}

func d3d9DeviceCreateAdditionalSwapChain(ctx *ntapi.TrapContext, bridge *d3d9Bridge) uint32 {
	paramsAddr, out := ctx.Arg(1), ctx.Arg(2)
	if paramsAddr == 0 || out == 0 || bridge == nil {
		return E_POINTER
	}
	writeGuestPtr(ctx, out, 0)
	is32 := ctx.State != nil && ctx.State.Is32
	present, ok := readD3DPresentParameters(ctx.Mem, paramsAddr, is32)
	if !ok {
		return D3DERR_INVALIDCALL
	}
	if present.BackBufferWidth == 0 {
		present.BackBufferWidth = bridge.present.BackBufferWidth
	}
	if present.BackBufferHeight == 0 {
		present.BackBufferHeight = bridge.present.BackBufferHeight
	}
	if present.BackBufferFormat == 0 {
		present.BackBufferFormat = bridge.present.BackBufferFormat
	}
	payload := &d3d9SwapChainPayload{bridge: bridge, present: present, backBufferCache: new(uint64)}
	addr := d3dCreatePayloadCOMObject(ctx.Mem, ctx.Disp, "d3d9-swap-chain", 10, payload, d3d9SwapChainDispatch, d3d9SwapChainArgCounts())
	if addr == 0 {
		return E_OUTOFMEMORY
	}
	d3d9AttachBridgeLifetime(addr, bridge)
	d3dCOMMu.Lock()
	if obj := d3dCOMObjects[addr]; obj != nil {
		previous := obj.finalize
		obj.finalize = func() {
			bridge.cacheMu.Lock()
			cacheAddr := *payload.backBufferCache
			*payload.backBufferCache = 0
			bridge.cacheMu.Unlock()
			if cacheAddr != 0 {
				d3dReleaseObject(cacheAddr)
			}
			if previous != nil {
				previous()
			}
		}
	}
	d3dCOMMu.Unlock()
	writeGuestPtr(ctx, out, addr)
	return D3D_OK
}

func d3d9SwapChainDispatch(ctx *ntapi.TrapContext, method int, obj *d3dCOMObject) uint32 {
	payload, _ := obj.payload.(*d3d9SwapChainPayload)
	if payload == nil || payload.bridge == nil {
		return E_POINTER
	}
	bridge := payload.bridge
	switch method {
	case 3:
		_ = ctx.Arg(5)
		if renderer := bridge.rendererSnapshot(); renderer != nil {
			renderer.Present(bridge.hctx.WlWindow)
		}
		return D3D_OK
	case 5:
		if ctx.Arg(1) != 0 || ctx.Arg(2) != 0 {
			return D3DERR_INVALIDCALL
		}
		return d3d9WriteCachedSurfaceWithPresent(ctx, bridge, payload.backBufferCache, ctx.Arg(3), "d3d9-back-buffer", payload.present)
	case 6:
		status := ctx.Arg(1)
		if status == 0 {
			return E_POINTER
		}
		ctx.Mem.Write32(status, 0)
		ctx.Mem.Write32(status+4, 0)
		return D3D_OK
	case 7:
		mode := ctx.Arg(1)
		if mode == 0 || bridge == nil {
			return E_POINTER
		}
		ctx.Mem.Write32(mode, payload.present.BackBufferWidth)
		ctx.Mem.Write32(mode+4, payload.present.BackBufferHeight)
		ctx.Mem.Write32(mode+8, payload.present.FullScreenRefreshRateInHz)
		ctx.Mem.Write32(mode+12, payload.present.BackBufferFormat)
		return D3D_OK
	case 8:
		return d3d9WriteDevice(ctx, bridge, ctx.Arg(1))
	case 9:
		if bridge == nil || ctx.Arg(1) == 0 {
			return E_POINTER
		}
		writeD3DPresentParameters(ctx, ctx.Arg(1), payload.present)
		return D3D_OK
	default:
		return D3D_OK
	}
}

func d3d9WriteCachedSurface(ctx *ntapi.TrapContext, bridge *d3d9Bridge, cache *uint64, out uint64, kind string) uint32 {
	if bridge == nil {
		return E_POINTER
	}
	return d3d9WriteCachedSurfaceWithPresent(ctx, bridge, cache, out, kind, bridge.present)
}

func d3d9WriteCachedSurfaceWithPresent(ctx *ntapi.TrapContext, bridge *d3d9Bridge, cache *uint64, out uint64, kind string, present d3d9.D3DPRESENT_PARAMETERS) uint32 {
	if out == 0 || bridge == nil || cache == nil {
		return E_POINTER
	}
	writeGuestPtr(ctx, out, 0)
	bridge.cacheMu.Lock()
	defer bridge.cacheMu.Unlock()
	if *cache == 0 {
		desc := d3d9SurfaceDesc{
			Format: present.BackBufferFormat, Type: d3d9.D3DRTYPE_SURFACE, Pool: d3d9.D3DPOOL_DEFAULT,
			MultiSampleType: present.MultiSampleType, MultiSampleQuality: present.MultiSampleQuality,
			Width: present.BackBufferWidth, Height: present.BackBufferHeight,
		}
		if kind == "d3d9-depth-surface" {
			desc.Format = present.AutoDepthStencilFormat
			desc.Usage = d3d9.D3DUSAGE_DEPTHSTENCIL
		} else {
			desc.Usage = d3d9.D3DUSAGE_RENDERTARGET
		}
		payload := &d3d9SurfacePayload{bridge: bridge, desc: desc}
		*cache = d3dCreatePayloadCOMObject(ctx.Mem, ctx.Disp, kind, d3d9SurfaceMethods, payload, d3d9SurfaceDispatch, d3d9SurfaceArgCounts())
		if *cache == 0 {
			return E_OUTOFMEMORY
		}
		d3d9AttachBridgeLifetime(*cache, bridge)
	}
	d3dAddRefObject(*cache)
	writeGuestPtr(ctx, out, *cache)
	return D3D_OK
}

func d3d9SurfaceDispatch(ctx *ntapi.TrapContext, method int, obj *d3dCOMObject) uint32 {
	payload, _ := obj.payload.(*d3d9SurfacePayload)
	var bridge *d3d9Bridge
	if payload != nil {
		bridge = payload.bridge
	}
	switch method {
	case 3:
		return d3d9WriteDevice(ctx, bridge, ctx.Arg(1))
	case 10:
		ctx.SetReturn(uint64(d3d9.D3DRTYPE_SURFACE))
		return 0
	case 12:
		pDesc := ctx.Arg(1)
		if pDesc == 0 || payload == nil {
			return E_POINTER
		}
		writeGuestStruct(ctx.Mem, pDesc, payload.desc)
		return D3D_OK
	case 11:
		if ctx.Arg(2) != 0 {
			writeGuestPtr(ctx, ctx.Arg(2), 0)
		}
		return E_NOINTERFACE
	case 13, 15:
		return E_NOTIMPL
	default:
		return D3D_OK
	}
}

func d3d9WriteDevice(ctx *ntapi.TrapContext, bridge *d3d9Bridge, out uint64) uint32 {
	if out == 0 || bridge == nil || bridge.deviceCOM == 0 {
		return E_POINTER
	}
	if !d3dAddRefObject(bridge.deviceCOM) {
		writeGuestPtr(ctx, out, 0)
		return E_POINTER
	}
	writeGuestPtr(ctx, out, bridge.deviceCOM)
	return D3D_OK
}

func writeD3DPresentParameters(ctx *ntapi.TrapContext, addr uint64, p d3d9.D3DPRESENT_PARAMETERS) {
	values := []uint32{
		p.BackBufferWidth, p.BackBufferHeight, p.BackBufferFormat, p.BackBufferCount,
		p.MultiSampleType, p.MultiSampleQuality, p.SwapEffect,
	}
	for i, value := range values {
		ctx.Mem.Write32(addr+uint64(i*4), value)
	}
	windowOffset := uint64(28)
	pointerSize := uint64(4)
	if ctx.State == nil || !ctx.State.Is32 {
		windowOffset = 32
		pointerSize = 8
		ctx.Mem.Write64(addr+windowOffset, p.HDeviceWindow)
	} else {
		ctx.Mem.Write32(addr+windowOffset, uint32(p.HDeviceWindow))
	}
	tail := []uint32{
		p.Windowed, p.EnableAutoDepthStencil, p.AutoDepthStencilFormat, p.Flags,
		p.FullScreenRefreshRateInHz, p.PresentationInterval,
	}
	tailOffset := windowOffset + pointerSize
	for i, value := range tail {
		ctx.Mem.Write32(addr+tailOffset+uint64(i*4), value)
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
		case 19:
			level := uint32(ctx.Arg(1))
			lockedRect := ctx.Arg(2)
			_ = ctx.Arg(4)
			if level >= uint32(len(payload.Levels)) {
				return D3DERR_NOTAVAILABLE
			}
			return d3d9LockSurface(ctx, payload.Levels[level], lockedRect)
		case 20:
			level := uint32(ctx.Arg(1))
			if level < uint32(len(payload.Levels)) {
				payload.Levels[level].Unlock()
			}
			return D3D_OK
		}
	case *d3d9CubeTexture:
		switch method {
		case 10:
			ctx.SetReturn(uint64(d3d9.D3DRTYPE_CUBETEXTURE))
			return 0
		case 13:
			ctx.SetReturn(uint64(len(payload.faces[0].Levels)))
			return 0
		case 19:
			face := uint32(ctx.Arg(1))
			level := uint32(ctx.Arg(2))
			lockedRect := ctx.Arg(3)
			_ = ctx.Arg(5)
			if face >= 6 || level >= uint32(len(payload.faces[face].Levels)) {
				return D3DERR_NOTAVAILABLE
			}
			return d3d9LockSurface(ctx, payload.faces[face].Levels[level], lockedRect)
		case 20:
			face := uint32(ctx.Arg(1))
			level := uint32(ctx.Arg(2))
			if face < 6 && level < uint32(len(payload.faces[face].Levels)) {
				payload.faces[face].Levels[level].Unlock()
			}
			return D3D_OK
		}
	case *d3d9.VertexBuffer:
		switch method {
		case 10:
			ctx.SetReturn(uint64(d3d9.D3DRTYPE_VERTEXBUFFER))
			return 0
		case 11: // Lock(OffsetToLock, SizeToLock, ppbData, Flags)
			return d3d9LockBuffer(ctx, payload.Staging, uint64(payload.Size), &payload.GuestAddr, "vertex", payload.BeginGuestWrite, payload.EndGuestWrite)
		case 12: // Unlock
			if payload.EndGuestWrite() {
				return D3D_OK
			}
			return D3DERR_INVALIDCALL
		}
	case *d3d9.IndexBuffer:
		switch method {
		case 10:
			ctx.SetReturn(uint64(d3d9.D3DRTYPE_INDEXBUFFER))
			return 0
		case 11: // Lock(OffsetToLock, SizeToLock, ppbData, Flags)
			return d3d9LockBuffer(ctx, payload.Staging, uint64(payload.Size), &payload.GuestAddr, "index", payload.BeginGuestWrite, payload.EndGuestWrite)
		case 12: // Unlock
			if payload.EndGuestWrite() {
				return D3D_OK
			}
			return D3DERR_INVALIDCALL
		}
	case *d3d9.VertexDeclaration:
		if method == 4 {
			pNumElements := ctx.Arg(2)
			if pNumElements != 0 {
				ctx.Mem.Write32(pNumElements, uint32(len(payload.Elements)))
			}
			return D3D_OK
		}
	}
	return D3D_OK
}

func d3d9LockBuffer(ctx *ntapi.TrapContext, data []byte, length uint64, guestAddr *uint64, kind string, beginWrite func() bool, endWrite func() bool) uint32 {
	ppbData := ctx.Arg(3)
	if ppbData == 0 {
		return E_POINTER
	}
	if err := writeD3D9LockPtr(ctx, ppbData, 0); err != nil {
		return E_POINTER
	}
	offset := ctx.Arg(1)
	size := ctx.Arg(2)
	if length == 0 || offset >= length || (size != 0 && size > length-offset) {
		return D3DERR_INVALIDCALL
	}
	if !beginWrite() {
		return D3DERR_INVALIDCALL
	}
	if *guestAddr == 0 {
		*guestAddr = ctx.Mem.MapHostSlice(0, data, mmu.PermRead|mmu.PermWrite)
		if os.Getenv("RAVEN_TRACE_D3D9") != "" {
			ravelog.Logf("[d3d9-trace] %s buffer mapped addr=0x%x size=%d\n", kind, *guestAddr, length)
		}
	}
	if err := writeD3D9LockPtr(ctx, ppbData, *guestAddr+offset); err != nil {
		endWrite()
		return E_POINTER
	}
	return D3D_OK
}

func writeD3D9LockPtr(ctx *ntapi.TrapContext, addr, value uint64) error {
	if ctx.State != nil && ctx.State.Is32 {
		return ctx.Mem.Write32(addr, uint32(value))
	}
	return ctx.Mem.Write64(addr, value)
}

func d3d9LockSurface(ctx *ntapi.TrapContext, surface *d3d9.Surface, lockedRect uint64) uint32 {
	if surface == nil || lockedRect == 0 {
		return E_POINTER
	}
	pitch, data := surface.Lock(nil)
	if surface.GuestAddr == 0 {
		surface.GuestAddr = ctx.Mem.MapHostSlice(0, data, mmu.PermRead|mmu.PermWrite)
	}
	ctx.Mem.Write32(lockedRect, uint32(pitch))
	pointerOffset := uint64(4)
	if ctx.State == nil || !ctx.State.Is32 {
		pointerOffset = 8
	}
	writeGuestPtr(ctx, lockedRect+pointerOffset, surface.GuestAddr)
	return D3D_OK
}

func d3d9DeviceCreateTexture(ctx *ntapi.TrapContext, bridge *d3d9Bridge) uint32 {
	ppTexture := ctx.Arg(7)
	_ = ctx.Arg(8)
	if ppTexture == 0 {
		return E_POINTER
	}
	writeGuestPtr(ctx, ppTexture, 0)
	tex := d3d9.NewTexture(uint32(ctx.Arg(1)), uint32(ctx.Arg(2)), uint32(ctx.Arg(3)), uint32(ctx.Arg(5)), uint32(ctx.Arg(6)))
	tex.Usage = uint32(ctx.Arg(4))
	addr := d3dCreatePayloadCOMObject(ctx.Mem, ctx.Disp, "d3d9-texture", d3d9TextureMethods, tex, d3d9ResourceDispatch, d3d9TextureArgCounts(false))
	if addr == 0 {
		return E_OUTOFMEMORY
	}
	d3d9AttachBridgeLifetime(addr, bridge)
	writeGuestPtr(ctx, ppTexture, addr)
	return D3D_OK
}

func d3d9DeviceCreateCubeTexture(ctx *ntapi.TrapContext, bridge *d3d9Bridge) uint32 {
	ppTexture := ctx.Arg(6)
	_ = ctx.Arg(7)
	if ppTexture == 0 {
		return E_POINTER
	}
	writeGuestPtr(ctx, ppTexture, 0)
	edge := uint32(ctx.Arg(1))
	levels := uint32(ctx.Arg(2))
	format := uint32(ctx.Arg(4))
	pool := uint32(ctx.Arg(5))
	cube := &d3d9CubeTexture{}
	for i := range cube.faces {
		cube.faces[i] = d3d9.NewTexture(edge, edge, levels, format, pool)
		cube.faces[i].Usage = uint32(ctx.Arg(3))
	}
	addr := d3dCreatePayloadCOMObject(ctx.Mem, ctx.Disp, "d3d9-cube-texture", d3d9TextureMethods, cube, d3d9ResourceDispatch, d3d9TextureArgCounts(true))
	if addr == 0 {
		return E_OUTOFMEMORY
	}
	d3d9AttachBridgeLifetime(addr, bridge)
	writeGuestPtr(ctx, ppTexture, addr)
	return D3D_OK
}

func d3d9DeviceCreateVertexBuffer(ctx *ntapi.TrapContext, bridge *d3d9Bridge) uint32 {
	ppVB := ctx.Arg(5)
	if ppVB == 0 {
		return E_POINTER
	}
	length := uint32(ctx.Arg(1))
	if length == 0 {
		writeGuestPtr(ctx, ppVB, 0)
		return D3DERR_INVALIDCALL
	}
	writeGuestPtr(ctx, ppVB, 0)
	vb := &d3d9.VertexBuffer{
		Size:    length,
		Usage:   uint32(ctx.Arg(2)),
		FVF:     uint32(ctx.Arg(3)),
		Pool:    uint32(ctx.Arg(4)),
		Data:    makeD3D9BufferBacking(length),
		Staging: makeD3D9BufferBacking(length),
	}
	addr := d3dCreatePayloadCOMObject(ctx.Mem, ctx.Disp, "d3d9-vertex-buffer", d3d9VertexBufferMethods, vb, d3d9ResourceDispatch, d3d9BufferArgCounts())
	if addr == 0 {
		return E_OUTOFMEMORY
	}
	d3d9AttachBridgeLifetime(addr, bridge)
	writeGuestPtr(ctx, ppVB, addr)
	return D3D_OK
}

func d3d9DeviceCreateIndexBuffer(ctx *ntapi.TrapContext, bridge *d3d9Bridge) uint32 {
	ppIB := ctx.Arg(5)
	if ppIB == 0 {
		return E_POINTER
	}
	length := uint32(ctx.Arg(1))
	if length == 0 {
		writeGuestPtr(ctx, ppIB, 0)
		return D3DERR_INVALIDCALL
	}
	writeGuestPtr(ctx, ppIB, 0)
	ib := &d3d9.IndexBuffer{
		Size:    length,
		Format:  uint32(ctx.Arg(3)),
		Pool:    uint32(ctx.Arg(4)),
		Data:    makeD3D9BufferBacking(length),
		Staging: makeD3D9BufferBacking(length),
	}
	addr := d3dCreatePayloadCOMObject(ctx.Mem, ctx.Disp, "d3d9-index-buffer", d3d9IndexBufferMethods, ib, d3d9ResourceDispatch, d3d9BufferArgCounts())
	if addr == 0 {
		return E_OUTOFMEMORY
	}
	d3d9AttachBridgeLifetime(addr, bridge)
	writeGuestPtr(ctx, ppIB, addr)
	return D3D_OK
}

func makeD3D9BufferBacking(length uint32) []byte {
	size := (uint64(length) + mmu.PageSize - 1) &^ uint64(mmu.PageSize-1)
	return make([]byte, size)
}

func d3d9DeviceCreateVertexDeclaration(ctx *ntapi.TrapContext, device *d3d9.Device, bridge *d3d9Bridge) uint32 {
	ppDecl := ctx.Arg(2)
	if ppDecl == 0 {
		return E_POINTER
	}
	writeGuestPtr(ctx, ppDecl, 0)
	elements, ok := readVertexElements(ctx.Mem, ctx.Arg(1))
	if !ok {
		return E_POINTER
	}
	decl := &d3d9.VertexDeclaration{Elements: elements}
	device.CurrentVertexDecl = decl
	device.VertexDeclaration = append([]d3d9.VertexElement(nil), elements...)
	addr := d3dCreatePayloadCOMObject(ctx.Mem, ctx.Disp, "d3d9-vertex-declaration", d3d9VertexDeclarationMethods, decl, d3d9ResourceDispatch, d3d9VertexDeclarationArgCounts())
	if addr == 0 {
		return E_OUTOFMEMORY
	}
	d3d9AttachBridgeLifetime(addr, bridge)
	writeGuestPtr(ctx, ppDecl, addr)
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

func d3d9VertexCountForPrim(primType, primCount uint32) uint32 {
	switch primType {
	case 1: // D3DPT_POINTLIST
		return primCount
	case 2: // D3DPT_LINELIST
		return primCount * 2
	case 3: // D3DPT_LINESTRIP
		return primCount + 1
	case 4: // D3DPT_TRIANGLELIST
		return primCount * 3
	case 5, 6: // D3DPT_TRIANGLESTRIP, D3DPT_TRIANGLEFAN
		return primCount + 2
	default:
		return 0
	}
}

func maxU32(a, b uint32) uint32 {
	if a > b {
		return a
	}
	return b
}

//go:build guest_windows

package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"time"

	"github.com/mirkobrombin/Raven/pkg/ddraw"
	ravelog "github.com/mirkobrombin/Raven/pkg/log"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

const (
	ddraw7Methods        = 30
	ddrawSurface7Methods = 49
	ddrawPaletteMethods  = 7
)

// PE32 stdcall arg counts for COM methods (including 'this' pointer).
// IDirectDraw7 vtable (30 methods):
//
//	0:QueryInterface(3) 1:AddRef(1) 2:Release(1) 3:Compact(1) 4:CreateClipper(3)
//	5:CreatePalette(5) 6:CreateSurface(4) 7:DuplicateSurface(3) 8:EnumDisplayModes(5)
//	9:EnumSurfaces(5) 10:FlipToGDISurface(1) 11:GetCaps(3) 12:GetDisplayMode(2)
//
// 13:GetFourCCCodes(3) 14:GetGDISurface(2) 15:GetMonitorFrequency(2) 16:GetScanLine(2)
// 17:GetVerticalBlankStatus(2) 18:Initialize(2) 19:RestoreAllSurfaces(1)
// 20:SetCooperativeLevel(3) 21:SetDisplayMode(6) 22:WaitForVerticalBlank(3)
// 23:GetAvailableVidMem(4) 24:GetSurfaceFromDC(3) 25:RestoreAllSurfaces2(1)
// 26:TestCooperativeLevel(1) 27:GetDeviceIdentifier(3) 28:StartModeTest(3) 29:EvaluateMode(3)
var ddraw7StdcallArgs = []int{
	3, 1, 1, 1, 3, 5, 4, 3, 5, 5, 1, 3, 2, 3, 2, 2, 2, 2, 2, 1,
	3, 6, 3, 4, 3, 1, 1, 3, 3, 3,
}

// IDirectDrawSurface7 vtable (49 methods):
//
//	0:QueryInterface(3) 1:AddRef(1) 2:Release(1) 3:AddAttachedSurface(2)
//	4:AddOverlayDirtyRect(2) 5:Blt(6) 6:BltBatch(3) 7:BltFast(6)
//	8:DeleteAttachedSurface(3) 9:EnumAttachedSurfaces(3) 10:EnumOverlayZOrders(4)
//
// 11:Flip(3) 12:GetAttachedSurface(3) 13:GetBltStatus(2) 14:GetCaps(2)
// 15:GetClipper(2) 16:GetColorKey(3) 17:GetDC(2) 18:GetFlipStatus(2)
// 19:GetOverlayPosition(3) 20:GetPalette(2) 21:GetPixelFormat(2)
// 22:GetSurfaceDesc(2) 23:Initialize(3) 24:IsLost(1) 25:Lock(5)
// 26:ReleaseDC(2) 27:Restore(1) 28:SetClipper(2) 29:SetColorKey(3)
// 30:SetOverlayPosition(3) 31:SetPalette(2) 32:Unlock(2)
// 33:UpdateOverlay(6) 34:UpdateOverlayDisplay(2) 35:UpdateOverlayZOrder(3)
// 36:GetDDInterface(2) 37:PageLock(2) 38:PageUnlock(2)
// 39:SetSurfaceDesc(3) 40:SetPrivateData(5) 41:GetPrivateData(4)
// 42:FreePrivateData(2) 43:GetUniquenessValue(2) 44:ChangeUniquenessValue(1)
// 45:SetPriority(2) 46:GetPriority(2) 47:SetLOD(2) 48:GetLOD(2)
var ddrawSurface7StdcallArgs = []int{
	3, 1, 1, 2, 2, 6, 3, 6, 3, 3, 4,
	3, 3, 2, 2, 2, 3, 2, 2, 3, 2, 2,
	2, 3, 1, 5, 2, 1, 2, 3, 3, 2, 2,
	6, 2, 3, 2, 2, 2, 3, 5, 4, 2, 2, 1,
	2, 2, 2, 2,
}

// IDirectDrawPalette vtable (7 methods):
//
//	0:QueryInterface(3) 1:AddRef(1) 2:Release(1) 3:GetCaps(2) 4:GetEntries(5)
//	5:Initialize(3) 6:SetEntries(5)
var ddrawPaletteStdcallArgs = []int{3, 1, 1, 2, 5, 3, 5}

var (
	IID_IDirectDraw7        = GUID{0x15E65EC0, 0x3B9C, 0x11D2, [8]byte{0xB9, 0x2F, 0x00, 0x60, 0x97, 0x97, 0xEA, 0x5B}}
	IID_IDirectDrawSurface7 = GUID{0x06675A80, 0x3B9B, 0x11D2, [8]byte{0xB9, 0x2F, 0x00, 0x60, 0x97, 0x97, 0xEA, 0x5B}}
	IID_IDirectDrawPalette  = GUID{0x6C14DB84, 0xA733, 0x11CE, [8]byte{0xA5, 0x21, 0x00, 0x20, 0xAF, 0x0B, 0xE5, 0x60}}
)

// ddrawPrimaryDirty is set when any BltFast/Blt writes to the primary surface.
// Cleared when WaitForVerticalBlank presents the frame.
var ddrawPrimaryDirty bool

// ddrawLastRenderTarget tracks the last surface written to by BltFast/Blt.
// Used to present the correct surface when the game composites to offscreen.
var ddrawLastRenderTarget *ddraw.Surface
var ddrawFrameDumped int

// ddrawActivePalette is the most recently created DDraw palette object.
// Games that use GDI CreatePalette+RealizePalette to set colors update this
// indirectly via ddrawApplyGDIPalette.
var ddrawActivePalette *ddraw.Palette

// ddrawApplyGDIPalette copies GDI palette entries into the active DDraw palette.
// Called by RealizePalette when a game uses the GDI path for color management.
// entries is a slice of {R, G, B, Flags} 4-byte records.
func ddrawApplyGDIPalette(entries [][4]byte) {
	if ddrawActivePalette == nil || len(entries) == 0 {
		return
	}
	ddEntries := make([]ddraw.PaletteEntry, len(entries))
	for i, e := range entries {
		ddEntries[i] = ddraw.PaletteEntry{Red: e[0], Green: e[1], Blue: e[2]}
	}
	ddrawActivePalette.SetEntries(0, 0, uint32(len(ddEntries)), ddEntries)
}

// nullCOMPageSetup tracks whether page 0 has been set up as a NULL COM safety
// net. Must be called AFTER the packer has finished decompressing (i.e., from
// the first DDraw/DSound API call, not at PE load time).
var nullCOMPageSetup bool

// setupNullCOMPage0 rebuilds page 0 with VMCALL traps so NULL COM object
// dereferences route through the dispatcher (with proper stdcall cleanup)
// instead of crashing. Layout:
//
//	[0x000] = 0x00000004  (vtable ptr → self + 4)
//	[0x004..0x103] = 64 method pointers → stubs at 0x200+
//	[0x200..0x5FF] = 64 VMCALL stubs (16 bytes each)
func setupNullCOMPage0(mem *mmu.MMU, disp *ntapi.Dispatcher) {
	if nullCOMPageSetup {
		return
	}
	nullCOMPageSetup = true
	mem.MapPage(0, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)

	const (
		vtableBase  = uint32(4)
		stubBase    = uint32(0x200)
		numMethods  = 64
		defaultArgs = 6 // covers most COM methods (this + up to 5 params)
		trapIDBase  = uint32(0x16000000)
	)

	// [0] = vtable pointer → address 4
	mem.Write32(0, vtableBase)

	for i := uint32(0); i < numMethods; i++ {
		stubAddr := stubBase + i*16
		trapID := trapIDBase + i

		methodIdx := int(i)
		disp.RegisterHandler(trapID, fmt.Sprintf("null-com[%d]", methodIdx), func(ctx *ntapi.TrapContext) uint32 {
			return S_OK
		})
		disp.SetStdcallArgCount(trapID, defaultArgs)

		// Write VMCALL stub: mov eax, trapID; vmcall; ret
		code := [16]byte{}
		code[0] = 0xB8
		code[1] = byte(trapID)
		code[2] = byte(trapID >> 8)
		code[3] = byte(trapID >> 16)
		code[4] = byte(trapID >> 24)
		code[5] = 0x0F
		code[6] = 0x01
		code[7] = 0xC1
		code[8] = 0xC3
		for j := 9; j < 16; j++ {
			code[j] = 0xCC
		}
		mem.WriteBytes(uint64(stubAddr), code[:]) //nolint:errcheck
		mem.Write32(uint64(vtableBase+i*4), stubAddr)
	}
	ravelog.Logf("[null-com] page 0 rebuilt with %d VMCALL stubs (post-packer)\n", numMethods)
}

type ddrawDeviceObject struct {
	hctx *HandlerCtx
	dd   *ddraw.DirectDraw
}

type ddrawSurfaceObject struct {
	hctx        *HandlerCtx
	dd          *ddraw.DirectDraw
	surface     *ddraw.Surface
	surfaceAddr uint64 // permanent guest-mapped pixel buffer (same as Lock gives)
	lockAddr    uint64
	lockSize    uint64
	lockRect    *ddraw.Rect
	lockBPP     uint32 // BPP at Lock time (may differ from surface.BPP if SwitchBPP ran)
	lockPitch   int    // Pitch at Lock time
}

type ddrawPaletteObject struct {
	palette *ddraw.Palette
}

func registerDdrawHandlers(hctx *HandlerCtx, dll *ntapi.SynthPE) {
	d := hctx.Disp
	d.RegisterAutoStubHandler(dll, "DirectDrawCreateEx", func(ctx *ntapi.TrapContext) uint32 {
		ppDD := ctx.Arg(1)
		riid := ctx.Arg(2)
		pUnkOuter := ctx.Arg(3)
		is32 := ctx.State != nil && ctx.State.Is32
		writePtr := func(addr, val uint64) {
			if is32 {
				ctx.Mem.Write32(addr, uint32(val))
			} else {
				ctx.Mem.Write64(addr, val)
			}
		}
		if pUnkOuter != 0 {
			ctx.SetReturn(CLASS_E_NOAGGREGATION)
			return 0
		}
		if ppDD == 0 {
			ctx.SetReturn(E_POINTER)
			return 0
		}
		if riid != 0 {
			iid := readGUID(ctx.Mem, riid)
			if !guidEqual(iid, IID_IDirectDraw7) && !guidEqual(iid, IID_IUnknown) {
				writePtr(ppDD, 0)
				ctx.SetReturn(E_NOINTERFACE)
				return 0
			}
		}
		writePtr(ppDD, 0)
		obj := createDirectDrawObject(hctx)
		if obj == 0 {
			ctx.SetReturn(E_OUTOFMEMORY)
			return 0
		}
		writePtr(ppDD, obj)
		ctx.SetReturn(S_OK)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "DirectDrawCreate", func(ctx *ntapi.TrapContext) uint32 {
		ppDD := ctx.Arg(1)
		pUnkOuter := ctx.Arg(2)
		is32 := ctx.State != nil && ctx.State.Is32
		writePtr := func(addr, val uint64) {
			if is32 {
				ctx.Mem.Write32(addr, uint32(val))
			} else {
				ctx.Mem.Write64(addr, val)
			}
		}
		if pUnkOuter != 0 {
			ctx.SetReturn(CLASS_E_NOAGGREGATION)
			return 0
		}
		if ppDD == 0 {
			ctx.SetReturn(E_POINTER)
			return 0
		}
		writePtr(ppDD, 0)
		obj := createDirectDrawObject(hctx)
		if obj == 0 {
			ctx.SetReturn(E_OUTOFMEMORY)
			return 0
		}
		writePtr(ppDD, obj)
		ctx.SetReturn(S_OK)
		return 0
	})
}

func createDirectDrawObject(hctx *HandlerCtx) uint64 {
	dd := ddraw.NewDirectDraw()
	return d3dCreatePayloadCOMObject(hctx.Mem, hctx.Disp, "ddraw7", ddraw7Methods, &ddrawDeviceObject{hctx: hctx, dd: dd}, ddrawDispatch, ddraw7StdcallArgs)
}

func createSurfaceObject(hctx *HandlerCtx, dd *ddraw.DirectDraw, surface *ddraw.Surface) uint64 {
	surface.SetGDIManager(hctx.GdiMgr)
	return d3dCreatePayloadCOMObject(hctx.Mem, hctx.Disp, "ddraw-surface7", ddrawSurface7Methods, &ddrawSurfaceObject{hctx: hctx, dd: dd, surface: surface}, ddrawSurfaceDispatch, ddrawSurface7StdcallArgs)
}

func createPaletteObject(hctx *HandlerCtx, palette *ddraw.Palette) uint64 {
	return d3dCreatePayloadCOMObject(hctx.Mem, hctx.Disp, "ddraw-palette", ddrawPaletteMethods, &ddrawPaletteObject{palette: palette}, ddrawPaletteDispatch, ddrawPaletteStdcallArgs)
}

// getSurfaceGuestAddr ensures the surface has a permanent guest-mapped pixel
// buffer and returns its address. Both Lock and GetSurfaceDesc return this.
func getSurfaceGuestAddr(surfObj *ddrawSurfaceObject) uint64 {
	if surfObj.surfaceAddr != 0 {
		return surfObj.surfaceAddr
	}
	s := surfObj.surface
	size := uint64(s.Pitch) * uint64(s.Height)
	if size == 0 {
		return 0
	}
	addr := surfObj.hctx.Mem.Mmap(0, size, mmu.PermRead|mmu.PermWrite)
	if addr == 0 {
		return 0
	}
	// Copy current pixels into the guest buffer.
	_ = surfObj.hctx.Mem.WriteBytes(addr, s.Pixels)
	surfObj.surfaceAddr = addr
	return addr
}

// syncSurfaceFromGuest reads the permanent guest buffer back into surface.Pixels.
// Call this before any operation that reads from surface.Pixels (BltFast, Blt, present).
func syncSurfaceFromGuest(surfObj *ddrawSurfaceObject) {
	if surfObj.surfaceAddr == 0 {
		ravelog.Logf("[ddraw] syncSurface: SKIP surfaceAddr=0 surface=%dx%d\n", surfObj.surface.Width, surfObj.surface.Height)
		return
	}
	s := surfObj.surface
	size := s.Pitch * int(s.Height)
	data, err := surfObj.hctx.Mem.ReadBytes(surfObj.surfaceAddr, size)
	if err != nil || len(data) == 0 {
		return
	}
	nonZ := 0
	for _, b := range data {
		if b != 0 {
			nonZ++
		}
	}
	ravelog.Logf("[ddraw] syncSurface: %dx%d bpp=%d nonZero=%d/%d\n",
		s.Width, s.Height, s.BPP, nonZ, size)
	copy(s.Pixels, data)
}

func ddrawDispatch(ctx *ntapi.TrapContext, method int, obj *d3dCOMObject) uint32 {
	device, _ := obj.payload.(*ddrawDeviceObject)
	if device == nil || device.dd == nil {
		return E_POINTER
	}
	is32 := ctx.State != nil && ctx.State.Is32
	writeSurfDesc := func(addr uint64, desc ddraw.DDSURFACEDESC2) {
		if is32 {
			writeDDSurfaceDesc2_32(ctx.Mem, addr, desc)
		} else {
			writeGuestStruct(ctx.Mem, addr, desc)
		}
	}
	ravelog.Logf("[ddraw] dispatch method=%d\n", method)
	switch method {
	case 5:
		return ddrawCreatePaletteMethod(ctx, device.hctx, device.dd)
	case 6:
		pDesc := ctx.Arg(1)
		ppSurface := ctx.Arg(2)
		if pDesc == 0 || ppSurface == 0 {
			return E_POINTER
		}
		is32 := ctx.State != nil && ctx.State.Is32
		if is32 {
			ctx.Mem.Write32(ppSurface, 0)
		} else {
			ctx.Mem.Write64(ppSurface, 0)
		}
		var desc ddraw.DDSURFACEDESC2
		if is32 {
			desc = readDDSurfaceDesc2_32(ctx.Mem, pDesc)
		} else {
			var ok bool
			desc, ok = readGuestStruct[ddraw.DDSURFACEDESC2](ctx.Mem, pDesc)
			if !ok {
				return E_POINTER
			}
		}
		ravelog.Logf("[ddraw] CreateSurface: flags=0x%x w=%d h=%d caps=0x%x bbc=%d\n",
			desc.DwFlags, desc.DwWidth, desc.DwHeight, desc.DdsCaps.DwCaps, desc.DwBackBufferCount)
		surface, err := device.dd.CreateSurface(&desc)
		if err != nil {
			ravelog.Logf("[ddraw] CreateSurface failed: %v\n", err)
			return E_FAIL
		}
		addr := createSurfaceObject(device.hctx, device.dd, surface)
		if addr == 0 {
			return E_OUTOFMEMORY
		}
		ravelog.Logf("[ddraw] CreateSurface → obj=0x%x ppSurface=0x%x\n", addr, ppSurface)
		if is32 {
			ctx.Mem.Write32(ppSurface, uint32(addr))
		} else {
			ctx.Mem.Write64(ppSurface, addr)
		}
		return S_OK
	case 8:
		flags := uint32(ctx.Arg(1))
		var filter *ddraw.DDSURFACEDESC2
		if ctx.Arg(2) != 0 {
			value, ok := readGuestStruct[ddraw.DDSURFACEDESC2](ctx.Mem, ctx.Arg(2))
			if ok {
				filter = &value
			}
		}
		context := ctx.Arg(3)
		callback := ctx.Arg(4)
		trampoline := ntapi.AllocTrampoline(ctx.Mem)
		descSize := uint64(binary.Size(ddraw.DDSURFACEDESC2{}))
		if is32 {
			descSize = 124
		}
		device.dd.EnumDisplayModes(flags, filter, func(mode *ddraw.DDSURFACEDESC2) bool {
			if callback == 0 {
				return false
			}
			tmp := ctx.Mem.Mmap(0, descSize, mmu.PermRead|mmu.PermWrite)
			if tmp == 0 {
				return false
			}
			writeSurfDesc(tmp, *mode)
			defer ctx.Mem.Munmap(tmp, descSize)
			ret, err := ntapi.CallGuestFunction(ctx.CPU, ctx.Mem, trampoline, callback, []uint64{tmp, context}, ctx.Trace)
			return err == nil && ret != 0
		})
		return S_OK
	case 11:
		caps := device.dd.GetCaps()
		if pDriverCaps := ctx.Arg(1); pDriverCaps != 0 {
			writeGuestStruct(ctx.Mem, pDriverCaps, caps)
		}
		if pHELCaps := ctx.Arg(2); pHELCaps != 0 {
			writeGuestStruct(ctx.Mem, pHELCaps, caps)
		}
		return S_OK
	case 12:
		pDesc := ctx.Arg(1)
		if pDesc == 0 {
			return E_POINTER
		}
		desc := ddraw.DDSURFACEDESC2{
			DwSize:  124, // PE32 size
			DwFlags: ddraw.DDSD_HEIGHT | ddraw.DDSD_WIDTH | ddraw.DDSD_PIXELFORMAT | ddraw.DDSD_PITCH,
			DwWidth: device.dd.DisplayWidth, DwHeight: device.dd.DisplayHeight,
			LPitch: int32(device.dd.DisplayWidth * maxU32(device.dd.DisplayBPP, 8) / 8),
			DdpfPixelFormat: ddraw.DDPIXELFORMAT{
				DwSize:        uint32(binary.Size(ddraw.DDPIXELFORMAT{})),
				DwFlags:       ddraw.DDPF_RGB,
				DwRGBBitCount: device.dd.DisplayBPP,
				DwRBitMask:    0x00FF0000,
				DwGBitMask:    0x0000FF00,
				DwBBitMask:    0x000000FF,
			},
		}
		if !is32 {
			desc.DwSize = uint32(binary.Size(ddraw.DDSURFACEDESC2{}))
		}
		writeSurfDesc(pDesc, desc)
		return S_OK
	case 20:
		return ddrawHRESULT(device.dd.SetCooperativeLevel(uint32(ctx.Arg(1)), uint32(ctx.Arg(2))))
	case 21:
		return ddrawHRESULT(device.dd.SetDisplayMode(uint32(ctx.Arg(1)), uint32(ctx.Arg(2)), uint32(ctx.Arg(3)), uint32(ctx.Arg(4)), uint32(ctx.Arg(5))))
	case 22:
		// WaitForVerticalBlank - present the active render surface and sleep ~16ms
		setupNullCOMPage0(ctx.Mem, device.hctx.Disp)
		presentSurface := device.dd.PrimarySurface
		if !ddrawPrimaryDirty && ddrawLastRenderTarget != nil && !ddrawLastRenderTarget.IsPrimary {
			// Game composites to offscreen - present that instead
			presentSurface = ddrawLastRenderTarget
		}
		if presentSurface != nil {
			presentPrimarySurface(device.hctx, presentSurface)
		}
		ddrawPrimaryDirty = false
		ddrawLastRenderTarget = nil
		time.Sleep(16 * time.Millisecond)
		return S_OK
	default:
		return S_OK
	}
}

func ddrawSurfaceDispatch(ctx *ntapi.TrapContext, method int, obj *d3dCOMObject) uint32 {
	surfObj, _ := obj.payload.(*ddrawSurfaceObject)
	if surfObj == nil || surfObj.surface == nil {
		return E_POINTER
	}
	surface := surfObj.surface
	is32 := ctx.State != nil && ctx.State.Is32
	writePtr := func(addr, val uint64) {
		if is32 {
			ctx.Mem.Write32(addr, uint32(val))
		} else {
			ctx.Mem.Write64(addr, val)
		}
	}
	writeSurfDesc := func(addr uint64, desc ddraw.DDSURFACEDESC2) {
		if is32 {
			writeDDSurfaceDesc2_32(ctx.Mem, addr, desc)
		} else {
			writeGuestStruct(ctx.Mem, addr, desc)
		}
	}
	if method != 32 { // skip Unlock spam (Lock is logged below in case 25)
		ravelog.Logf("[ddraw] surface dispatch method=%d surfObj=%p %dx%d\n", method, surfObj, surface.Width, surface.Height)
	}
	switch method {
	case 5:
		dstRect := readDDRect(ctx.Mem, ctx.Arg(1))
		var srcSurface *ddraw.Surface
		if ctx.Arg(2) != 0 {
			payload, ok := d3dLookupPayload[*ddrawSurfaceObject](ctx.Arg(2))
			if !ok || payload == nil {
				return E_POINTER
			}
			ravelog.Logf("[ddraw] Blt: dst=%dx%d src=%dx%d src_surfObj=%p surfaceAddr=0x%x\n",
				surface.Width, surface.Height, payload.surface.Width, payload.surface.Height, payload, payload.surfaceAddr)
			syncSurfaceFromGuest(payload)
			srcSurface = payload.surface
		}
		srcRect := readDDRect(ctx.Mem, ctx.Arg(3))
		var fx *ddraw.DDBLTFX
		if ctx.Arg(5) != 0 {
			value, ok := readGuestStruct[ddraw.DDBLTFX](ctx.Mem, ctx.Arg(5))
			if ok {
				fx = &value
			}
		}
		if err := surface.Blt(dstRect, srcSurface, srcRect, uint32(ctx.Arg(4)), fx); err != nil {
			return E_FAIL
		}
		// Debug: check if destination pixels are non-zero after Blt
		nzDst := 0
		for _, b := range surface.Pixels {
			if b != 0 {
				nzDst++
			}
		}
		ravelog.Logf("[ddraw] Blt done: dst nonZero=%d/%d\n", nzDst, len(surface.Pixels))
		ddrawLastRenderTarget = surface
		if surface.IsPrimary {
			ddrawPrimaryDirty = true
		}
		return S_OK
	case 7:
		var srcSurface *ddraw.Surface
		payload, ok := d3dLookupPayload[*ddrawSurfaceObject](ctx.Arg(3))
		if !ok || payload == nil {
			return E_POINTER
		}
		ravelog.Logf("[ddraw] BltFast: dst surfObj=%p %dx%d PRIMARY=%v | src payload=%p surfaceAddr=0x%x %dx%d\n",
			surfObj, surface.Width, surface.Height, surface.IsPrimary,
			payload, payload.surfaceAddr, payload.surface.Width, payload.surface.Height)
		syncSurfaceFromGuest(payload)
		srcSurface = payload.surface
		srcRect := readDDRect(ctx.Mem, ctx.Arg(4))
		if err := surface.BltFast(int32(ctx.Arg(1)), int32(ctx.Arg(2)), srcSurface, srcRect, uint32(ctx.Arg(5))); err != nil {
			return E_FAIL
		}
		ddrawLastRenderTarget = surface
		if surface.IsPrimary {
			ddrawPrimaryDirty = true
		}
		return S_OK
	case 11:
		var target *ddraw.Surface
		if ctx.Arg(1) != 0 {
			payload, ok := d3dLookupPayload[*ddrawSurfaceObject](ctx.Arg(1))
			if ok && payload != nil {
				target = payload.surface
			}
		}
		if err := surface.Flip(target, uint32(ctx.Arg(2))); err != nil {
			return E_FAIL
		}
		if surface.IsPrimary {
			presentPrimarySurface(surfObj.hctx, surface)
		} else if target != nil && target.IsPrimary {
			presentPrimarySurface(surfObj.hctx, target)
		}
		return S_OK
	case 12:
		ppAttached := ctx.Arg(2)
		if ppAttached == 0 {
			return E_POINTER
		}
		writePtr(ppAttached, 0)
		var caps *ddraw.DDSCAPS2
		if ctx.Arg(1) != 0 {
			value, ok := readGuestStruct[ddraw.DDSCAPS2](ctx.Mem, ctx.Arg(1))
			if ok {
				caps = &value
			}
		}
		attached := surface.GetAttachedSurface(caps)
		if attached == nil {
			return E_FAIL
		}
		addr := createSurfaceObject(surfObj.hctx, surfObj.dd, attached)
		if addr == 0 {
			return E_OUTOFMEMORY
		}
		writePtr(ppAttached, addr)
		return S_OK
	case 14:
		if pCaps := ctx.Arg(1); pCaps != 0 {
			writeGuestStruct(ctx.Mem, pCaps, surface.Caps)
			return S_OK
		}
		return E_POINTER
	case 17:
		pHDC := ctx.Arg(1)
		if pHDC == 0 {
			return E_POINTER
		}
		hdc, _ := surface.GetDC()
		writePtr(pHDC, hdc)
		return S_OK
	case 20:
		pPalette := ctx.Arg(1)
		if pPalette == 0 {
			return E_POINTER
		}
		writePtr(pPalette, 0)
		if surface.Palette == nil {
			return S_OK
		}
		addr := createPaletteObject(surfObj.hctx, surface.Palette)
		if addr == 0 {
			return E_OUTOFMEMORY
		}
		writePtr(pPalette, addr)
		return S_OK
	case 21:
		pFormat := ctx.Arg(1)
		if pFormat == 0 {
			return E_POINTER
		}
		writeGuestStruct(ctx.Mem, pFormat, surface.Format)
		return S_OK
	case 22:
		pDesc := ctx.Arg(1)
		if pDesc == 0 {
			return E_POINTER
		}
		var desc ddraw.DDSURFACEDESC2
		if err := surface.GetSurfaceDesc(&desc); err != nil {
			return E_FAIL
		}
		// Return the permanent guest buffer so the game can write directly.
		guestAddr := getSurfaceGuestAddr(surfObj)
		ravelog.Logf("[ddraw] GetSurfaceDesc: %dx%d surfObj=%p surfaceAddr=0x%x\n", surface.Width, surface.Height, surfObj, guestAddr)
		desc.LpSurface = guestAddr
		if is32 {
			desc.DwSize = 124 // 32-bit DDSURFACEDESC2 is exactly 124 bytes
		}
		writeSurfDesc(pDesc, desc)
		// Verify what we wrote to the guest struct
		if is32 && surface.Width == 640 {
			readback, _ := ctx.Mem.ReadBytes(pDesc, 44)
			if len(readback) >= 40 {
				ravelog.Logf("[ddraw] GetSurfaceDesc: wrote to 0x%x: dwSize=%d dwFlags=0x%x lpSurface=0x%x (at offset36=0x%x)\n",
					pDesc,
					uint32(readback[0])|uint32(readback[1])<<8|uint32(readback[2])<<16|uint32(readback[3])<<24,
					uint32(readback[4])|uint32(readback[5])<<8|uint32(readback[6])<<16|uint32(readback[7])<<24,
					guestAddr,
					uint32(readback[36])|uint32(readback[37])<<8|uint32(readback[38])<<16|uint32(readback[39])<<24,
				)
			}
		}
		return S_OK
	case 25:
		pDesc := ctx.Arg(2)
		if pDesc == 0 {
			return E_POINTER
		}
		lockRect := readDDRect(ctx.Mem, ctx.Arg(1))
		var desc ddraw.DDSURFACEDESC2
		if err := surface.Lock(lockRect, &desc, uint32(ctx.Arg(3))); err != nil {
			return E_FAIL
		}
		// Use the persistent guest buffer - same address as GetSurfaceDesc gives.
		// This ensures the game can obtain the pointer via either method.
		surfAddr := getSurfaceGuestAddr(surfObj)
		ravelog.Logf("[ddraw] Lock: surfObj=%p %dx%d surfaceAddr=0x%x\n", surfObj, surface.Width, surface.Height, surfAddr)
		if surfAddr == 0 {
			_ = surface.Unlock(lockRect)
			return E_OUTOFMEMORY
		}
		lockSize := uint64(surface.Pitch) * uint64(surface.Height)
		if lockRect != nil {
			lockSize = uint64(surface.Pitch) * uint64(lockRect.Bottom-lockRect.Top)
		}
		desc.LpSurface = surfAddr
		if is32 {
			desc.DwSize = 124 // 32-bit DDSURFACEDESC2 is exactly 124 bytes
		}
		writeSurfDesc(pDesc, desc)
		surfObj.lockAddr = surfAddr
		surfObj.lockSize = lockSize
		surfObj.lockRect = lockRect
		surfObj.lockSize = lockSize
		surfObj.lockRect = lockRect
		surfObj.lockBPP = surface.BPP
		surfObj.lockPitch = surface.Pitch
		return S_OK
	case 26:
		if err := surface.ReleaseDC(ctx.Arg(1)); err != nil {
			return E_FAIL
		}
		if surface.IsPrimary {
			presentPrimarySurface(surfObj.hctx, surface)
		}
		return S_OK
	case 29:
		if ctx.Arg(2) == 0 {
			surface.SetColorKey(uint32(ctx.Arg(1)), nil)
			return S_OK
		}
		value, ok := readGuestStruct[ddraw.DDCOLORKEY](ctx.Mem, ctx.Arg(2))
		if !ok {
			return E_POINTER
		}
		surface.SetColorKey(uint32(ctx.Arg(1)), &value)
		return S_OK
	case 31:
		if ctx.Arg(1) == 0 {
			surface.SetPalette(nil)
			return S_OK
		}
		payload, ok := d3dLookupPayload[*ddrawPaletteObject](ctx.Arg(1))
		if !ok || payload == nil {
			return E_POINTER
		}
		surface.SetPalette(payload.palette)
		// Propagate palette to all surfaces - games often only call
		// SetPalette on the primary but expect all surfaces to share it.
		if surface.IsPrimary && surfObj.dd != nil {
			for _, s := range surfObj.dd.Surfaces {
				if s != surface && s.Palette == nil {
					s.SetPalette(payload.palette)
				}
			}
		}
		return S_OK
	case 32:
		if surfObj.lockAddr != 0 {
			// Sync guest buffer → surface.Pixels using the BPP/pitch at lock time.
			data, err := ctx.Mem.ReadBytes(surfObj.lockAddr, int(surfObj.lockSize))
			if err == nil {
				// Check for non-zero data after unlock
				nz := 0
				for _, b := range data {
					if b != 0 {
						nz++
					}
				}
				ravelog.Logf("[ddraw] Unlock: surfObj=%p %dx%d lockSize=%d nonZero=%d\n",
					surfObj, surface.Width, surface.Height, surfObj.lockSize, nz)
				writeSurfaceBytes(surface, surfObj.lockRect, data, surfObj.lockBPP, surfObj.lockPitch)
			}
			// Don't Munmap - the persistent buffer stays valid for future GetSurfaceDesc / Lock.
			surfObj.lockAddr = 0
			surfObj.lockSize = 0
			surfObj.lockRect = nil
			surfObj.lockBPP = 0
			surfObj.lockPitch = 0
		}
		if err := surface.Unlock(readDDRect(ctx.Mem, ctx.Arg(1))); err != nil {
			return E_FAIL
		}
		if surface.IsPrimary {
			ddrawPrimaryDirty = true
		}
		return S_OK
	default:
		return S_OK
	}
}

func ddrawPaletteDispatch(ctx *ntapi.TrapContext, method int, obj *d3dCOMObject) uint32 {
	palObj, _ := obj.payload.(*ddrawPaletteObject)
	if palObj == nil || palObj.palette == nil {
		return E_POINTER
	}
	ravelog.Logf("[ddraw] palette dispatch method=%d\n", method)
	switch method {
	case 3:
		if pCaps := ctx.Arg(1); pCaps != 0 {
			ctx.Mem.Write32(pCaps, 0)
			return S_OK
		}
		return E_POINTER
	case 4:
		pEntries := ctx.Arg(4)
		if pEntries == 0 {
			return E_POINTER
		}
		entries := palObj.palette.GetEntries(uint32(ctx.Arg(1)), uint32(ctx.Arg(2)), uint32(ctx.Arg(3)))
		writePaletteEntries(ctx.Mem, pEntries, entries)
		return S_OK
	case 6:
		count := uint32(ctx.Arg(3))
		pEntries := ctx.Arg(4)
		if pEntries == 0 {
			return E_POINTER
		}
		entries, ok := readPaletteEntries(ctx.Mem, pEntries, count)
		if !ok {
			return E_POINTER
		}
		palObj.palette.SetEntries(uint32(ctx.Arg(1)), uint32(ctx.Arg(2)), count, entries)
		return S_OK
	default:
		return S_OK
	}
}

func ddrawCreatePaletteMethod(ctx *ntapi.TrapContext, hctx *HandlerCtx, dd *ddraw.DirectDraw) uint32 {
	ppPalette := ctx.Arg(3)
	if ppPalette == 0 {
		return E_POINTER
	}
	is32 := ctx.State != nil && ctx.State.Is32
	if is32 {
		ctx.Mem.Write32(ppPalette, 0)
	} else {
		ctx.Mem.Write64(ppPalette, 0)
	}
	palette := &ddraw.Palette{}
	if pEntries := ctx.Arg(2); pEntries != 0 {
		if entries, ok := readPaletteEntries(ctx.Mem, pEntries, 256); ok {
			palette.SetEntries(uint32(ctx.Arg(1)), 0, uint32(len(entries)), entries)
			// Log first 8 palette entries to check
			ravelog.Logf("[ddraw] CreatePalette: pEntries=0x%x first8=", pEntries)
			for i := 0; i < 8 && i < len(entries); i++ {
				ravelog.Logf("{%d,%d,%d} ", entries[i].Red, entries[i].Green, entries[i].Blue)
			}
			ravelog.Logf("\n")
		}
	} else {
		ravelog.Logf("[ddraw] CreatePalette: pEntries=0 (no palette data!)\n")
	}
	// A game that creates a palette expects 8bpp mode.
	dd.SwitchBPP(8, palette)
	ddrawActivePalette = palette
	ravelog.Logf("[ddraw] CreatePalette → switched to 8bpp\n")
	addr := createPaletteObject(hctx, palette)
	ravelog.Logf("[ddraw] CreatePalette → palette obj at 0x%x, ppPalette=0x%x\n", addr, ppPalette)
	if addr == 0 {
		return E_OUTOFMEMORY
	}
	if is32 {
		ctx.Mem.Write32(ppPalette, uint32(addr))
	} else {
		ctx.Mem.Write64(ppPalette, addr)
	}
	return S_OK
}

func readDDRect(mem *mmu.MMU, addr uint64) *ddraw.Rect {
	if addr == 0 {
		return nil
	}
	rect, ok := readGuestStruct[ddraw.Rect](mem, addr)
	if !ok {
		return nil
	}
	return &rect
}

// readDDSurfaceDesc2_32 reads a 32-bit DDSURFACEDESC2 from guest memory.
// In 32-bit Windows, lpSurface is a 4-byte pointer (not 8), shifting all
// subsequent fields by 4 bytes compared to the Go struct which uses uint64.
// 32-bit total struct size: 124 bytes.
func readDDSurfaceDesc2_32(mem *mmu.MMU, addr uint64) ddraw.DDSURFACEDESC2 {
	var desc ddraw.DDSURFACEDESC2
	buf, err := mem.ReadBytes(addr, 124)
	if err != nil {
		return desc
	}
	desc.DwSize = binary.LittleEndian.Uint32(buf[0:4])
	desc.DwFlags = binary.LittleEndian.Uint32(buf[4:8])
	desc.DwHeight = binary.LittleEndian.Uint32(buf[8:12])
	desc.DwWidth = binary.LittleEndian.Uint32(buf[12:16])
	desc.LPitch = int32(binary.LittleEndian.Uint32(buf[16:20]))
	desc.DwBackBufferCount = binary.LittleEndian.Uint32(buf[20:24])
	desc.DwMipMapCount = binary.LittleEndian.Uint32(buf[24:28])
	desc.DwAlphaBitDepth = binary.LittleEndian.Uint32(buf[28:32])
	desc.DwReserved = binary.LittleEndian.Uint32(buf[32:36])
	desc.LpSurface = uint64(binary.LittleEndian.Uint32(buf[36:40])) // 4-byte ptr in PE32
	// DDCOLORKEY pairs (8 bytes each)
	desc.DdckCKDestOverlay.DwColorSpaceLowValue = binary.LittleEndian.Uint32(buf[40:44])
	desc.DdckCKDestOverlay.DwColorSpaceHighValue = binary.LittleEndian.Uint32(buf[44:48])
	desc.DdckCKDestBlt.DwColorSpaceLowValue = binary.LittleEndian.Uint32(buf[48:52])
	desc.DdckCKDestBlt.DwColorSpaceHighValue = binary.LittleEndian.Uint32(buf[52:56])
	desc.DdckCKSrcOverlay.DwColorSpaceLowValue = binary.LittleEndian.Uint32(buf[56:60])
	desc.DdckCKSrcOverlay.DwColorSpaceHighValue = binary.LittleEndian.Uint32(buf[60:64])
	desc.DdckCKSrcBlt.DwColorSpaceLowValue = binary.LittleEndian.Uint32(buf[64:68])
	desc.DdckCKSrcBlt.DwColorSpaceHighValue = binary.LittleEndian.Uint32(buf[68:72])
	// DDPIXELFORMAT (32 bytes)
	desc.DdpfPixelFormat.DwSize = binary.LittleEndian.Uint32(buf[72:76])
	desc.DdpfPixelFormat.DwFlags = binary.LittleEndian.Uint32(buf[76:80])
	desc.DdpfPixelFormat.DwFourCC = binary.LittleEndian.Uint32(buf[80:84])
	desc.DdpfPixelFormat.DwRGBBitCount = binary.LittleEndian.Uint32(buf[84:88])
	desc.DdpfPixelFormat.DwRBitMask = binary.LittleEndian.Uint32(buf[88:92])
	desc.DdpfPixelFormat.DwGBitMask = binary.LittleEndian.Uint32(buf[92:96])
	desc.DdpfPixelFormat.DwBBitMask = binary.LittleEndian.Uint32(buf[96:100])
	desc.DdpfPixelFormat.DwAlphaBitMask = binary.LittleEndian.Uint32(buf[100:104])
	// DDSCAPS2 (16 bytes)
	desc.DdsCaps.DwCaps = binary.LittleEndian.Uint32(buf[104:108])
	desc.DdsCaps.DwCaps2 = binary.LittleEndian.Uint32(buf[108:112])
	desc.DdsCaps.DwCaps3 = binary.LittleEndian.Uint32(buf[112:116])
	desc.DdsCaps.DwCaps4 = binary.LittleEndian.Uint32(buf[116:120])
	desc.DwTextureStage = binary.LittleEndian.Uint32(buf[120:124])
	return desc
}

// writeDDSurfaceDesc2_32 writes a 32-bit DDSURFACEDESC2 to guest memory.
// PE32 layout: LpSurface is 4 bytes (not 8), total 124 bytes.
func writeDDSurfaceDesc2_32(mem *mmu.MMU, addr uint64, desc ddraw.DDSURFACEDESC2) {
	var buf [124]byte
	binary.LittleEndian.PutUint32(buf[0:4], desc.DwSize)
	binary.LittleEndian.PutUint32(buf[4:8], desc.DwFlags)
	binary.LittleEndian.PutUint32(buf[8:12], desc.DwHeight)
	binary.LittleEndian.PutUint32(buf[12:16], desc.DwWidth)
	binary.LittleEndian.PutUint32(buf[16:20], uint32(desc.LPitch))
	binary.LittleEndian.PutUint32(buf[20:24], desc.DwBackBufferCount)
	binary.LittleEndian.PutUint32(buf[24:28], desc.DwMipMapCount)
	binary.LittleEndian.PutUint32(buf[28:32], desc.DwAlphaBitDepth)
	binary.LittleEndian.PutUint32(buf[32:36], desc.DwReserved)
	binary.LittleEndian.PutUint32(buf[36:40], uint32(desc.LpSurface))
	binary.LittleEndian.PutUint32(buf[40:44], desc.DdckCKDestOverlay.DwColorSpaceLowValue)
	binary.LittleEndian.PutUint32(buf[44:48], desc.DdckCKDestOverlay.DwColorSpaceHighValue)
	binary.LittleEndian.PutUint32(buf[48:52], desc.DdckCKDestBlt.DwColorSpaceLowValue)
	binary.LittleEndian.PutUint32(buf[52:56], desc.DdckCKDestBlt.DwColorSpaceHighValue)
	binary.LittleEndian.PutUint32(buf[56:60], desc.DdckCKSrcOverlay.DwColorSpaceLowValue)
	binary.LittleEndian.PutUint32(buf[60:64], desc.DdckCKSrcOverlay.DwColorSpaceHighValue)
	binary.LittleEndian.PutUint32(buf[64:68], desc.DdckCKSrcBlt.DwColorSpaceLowValue)
	binary.LittleEndian.PutUint32(buf[68:72], desc.DdckCKSrcBlt.DwColorSpaceHighValue)
	binary.LittleEndian.PutUint32(buf[72:76], desc.DdpfPixelFormat.DwSize)
	binary.LittleEndian.PutUint32(buf[76:80], desc.DdpfPixelFormat.DwFlags)
	binary.LittleEndian.PutUint32(buf[80:84], desc.DdpfPixelFormat.DwFourCC)
	binary.LittleEndian.PutUint32(buf[84:88], desc.DdpfPixelFormat.DwRGBBitCount)
	binary.LittleEndian.PutUint32(buf[88:92], desc.DdpfPixelFormat.DwRBitMask)
	binary.LittleEndian.PutUint32(buf[92:96], desc.DdpfPixelFormat.DwGBitMask)
	binary.LittleEndian.PutUint32(buf[96:100], desc.DdpfPixelFormat.DwBBitMask)
	binary.LittleEndian.PutUint32(buf[100:104], desc.DdpfPixelFormat.DwAlphaBitMask)
	binary.LittleEndian.PutUint32(buf[104:108], desc.DdsCaps.DwCaps)
	binary.LittleEndian.PutUint32(buf[108:112], desc.DdsCaps.DwCaps2)
	binary.LittleEndian.PutUint32(buf[112:116], desc.DdsCaps.DwCaps3)
	binary.LittleEndian.PutUint32(buf[116:120], desc.DdsCaps.DwCaps4)
	binary.LittleEndian.PutUint32(buf[120:124], desc.DwTextureStage)
	_ = mem.WriteBytes(addr, buf[:])
}

func readPaletteEntries(mem *mmu.MMU, addr uint64, count uint32) ([]ddraw.PaletteEntry, bool) {
	if addr == 0 {
		return nil, false
	}
	entries := make([]ddraw.PaletteEntry, count)
	data, err := mem.ReadBytes(addr, int(count)*4)
	if err != nil {
		return nil, false
	}
	for i := uint32(0); i < count; i++ {
		off := i * 4
		entries[i] = ddraw.PaletteEntry{Red: data[off], Green: data[off+1], Blue: data[off+2], Flags: data[off+3]}
	}
	return entries, true
}

func writePaletteEntries(mem *mmu.MMU, addr uint64, entries []ddraw.PaletteEntry) {
	data := make([]byte, len(entries)*4)
	for i, entry := range entries {
		off := i * 4
		data[off] = entry.Red
		data[off+1] = entry.Green
		data[off+2] = entry.Blue
		data[off+3] = entry.Flags
	}
	_ = mem.WriteBytes(addr, data)
}

func ddrawGetSurfaceAddr(s *ddraw.Surface) uint64 {
	for _, obj := range d3dCOMObjects {
		if p, ok := obj.payload.(*ddrawSurfaceObject); ok && p.surface == s {
			return p.surfaceAddr
		}
	}
	return 0
}

func presentPrimarySurface(hctx *HandlerCtx, surface *ddraw.Surface) {
	if hctx == nil || hctx.WlWindow == nil || surface == nil {
		ravelog.Logf("[present] bail: hctx=%v wl=%v surface=%v\n", hctx != nil, hctx != nil && hctx.WlWindow != nil, surface != nil)
		return
	}
	w := hctx.WlWindow
	if int32(surface.Width) != w.Width || int32(surface.Height) != w.Height {
		if w.Resize(int32(surface.Width), int32(surface.Height)) && hctx.SyncScreenSurface != nil {
			hctx.SyncScreenSurface()
		}
	}
	frame := surface.ReadbackXRGB8888(int(w.Width), int(w.Height))
	// Debug: check primary surface pixels and all related surfaces
	if ddrawFrameDumped == 0 {
		nzPrimary := 0
		for _, b := range surface.Pixels {
			if b != 0 {
				nzPrimary++
			}
		}
		ravelog.Logf("[present] primary nonZero=%d/%d bpp=%d\n", nzPrimary, len(surface.Pixels), surface.BPP)
		// Check palette
		if surface.Palette != nil {
			nzPal := 0
			for _, e := range surface.Palette.Entries {
				if e.Red != 0 || e.Green != 0 || e.Blue != 0 {
					nzPal++
				}
			}
			ravelog.Logf("[present] palette nonZero=%d/256\n", nzPal)
		}
		// Check if game wrote directly to palette COM object memory (Wine layout: palent at offset 8)
		paletteObjAddr := uint64(0)
		for _, obj := range d3dCOMObjects {
			if _, ok := obj.payload.(*ddrawPaletteObject); ok {
				paletteObjAddr = obj.objectAddr
				break
			}
		}
		if paletteObjAddr != 0 {
			raw, err := hctx.Mem.ReadBytes(paletteObjAddr, 12)
			if err == nil {
				ravelog.Logf("[present] paletteObj at 0x%x first12=% x\n", paletteObjAddr, raw)
			}
			// Check Wine-style offset 8 for palent[0]
			entry, err2 := hctx.Mem.ReadBytes(paletteObjAddr+8, 8)
			if err2 == nil {
				ravelog.Logf("[present] paletteObj+8 (palent[0..1])=% x\n", entry)
			}
		}
	}
	if dumpPath := os.Getenv("RAVEN_DDRAW_FRAME_DUMP"); dumpPath != "" && ddrawFrameDumped == 0 {
		ddrawFrameDumped++
		if f, err := os.Create(dumpPath); err == nil {
			fmt.Fprintf(f, "P6\n%d %d\n255\n", w.Width, w.Height)
			for i := 0; i < len(frame); i += 4 {
				f.Write([]byte{frame[i+2], frame[i+1], frame[i+0]}) // XRGB → RGB
			}
			f.Close()
			ravelog.Logf("[ddraw-dump] saved %s\n", dumpPath)
		}
	}
	if w.TitleBarH == 0 {
		copy(w.Pix, frame)
		w.Commit()
		return
	}
	rowBytes := int(w.Width) * 4
	for y := 0; y < int(w.Height); y++ {
		srcOff := y * rowBytes
		dstOff := (y + int(w.TitleBarH)) * int(w.Stride)
		copy(w.Pix[dstOff:dstOff+rowBytes], frame[srcOff:srcOff+rowBytes])
	}
	w.Commit()
}

func extractSurfaceBytes(surface *ddraw.Surface, rect *ddraw.Rect) []byte {
	bytesPerPixel := int(maxU32(surface.BPP/8, 1))
	top, left := 0, 0
	height := int(surface.Height)
	width := int(surface.Width)
	if rect != nil {
		left = int(rect.Left)
		top = int(rect.Top)
		width = int(rect.Right - rect.Left)
		height = int(rect.Bottom - rect.Top)
	}
	buf := make([]byte, surface.Pitch*height)
	for y := 0; y < height; y++ {
		srcOff := (top+y)*surface.Pitch + left*bytesPerPixel
		dstOff := y * surface.Pitch
		copy(buf[dstOff:dstOff+width*bytesPerPixel], surface.Pixels[srcOff:srcOff+width*bytesPerPixel])
	}
	return buf
}

func writeSurfaceBytes(surface *ddraw.Surface, rect *ddraw.Rect, data []byte, srcBPP uint32, srcPitch int) {
	if srcBPP == 0 {
		srcBPP = surface.BPP
	}
	if srcPitch == 0 {
		srcPitch = surface.Pitch
	}
	srcBytesPerPixel := int(maxU32(srcBPP/8, 1))
	top, left := 0, 0
	height := int(surface.Height)
	width := int(surface.Width)
	if rect != nil {
		left = int(rect.Left)
		top = int(rect.Top)
		width = int(rect.Right - rect.Left)
		height = int(rect.Bottom - rect.Top)
	}
	if srcBPP == surface.BPP {
		// Fast path: same BPP, use pitch-aware row copy.
		dstBytesPerPixel := srcBytesPerPixel
		for y := 0; y < height; y++ {
			srcOff := y * srcPitch
			dstOff := (top+y)*surface.Pitch + left*dstBytesPerPixel
			n := width * dstBytesPerPixel
			if srcOff+n > len(data) || dstOff+n > len(surface.Pixels) {
				break
			}
			copy(surface.Pixels[dstOff:dstOff+n], data[srcOff:srcOff+n])
		}
	} else {
		// Slow path: BPP changed between Lock and Unlock (e.g. SwitchBPP ran).
		// Decode each pixel from srcBPP, re-encode to surface.BPP via palette.
		for y := 0; y < height; y++ {
			for x := 0; x < width; x++ {
				srcOff := y*srcPitch + x*srcBytesPerPixel
				if srcOff+srcBytesPerPixel > len(data) {
					break
				}
				var raw uint32
				switch srcBPP {
				case 8:
					raw = uint32(data[srcOff])
				case 16:
					raw = uint32(data[srcOff]) | uint32(data[srcOff+1])<<8
				case 24:
					raw = uint32(data[srcOff]) | uint32(data[srcOff+1])<<8 | uint32(data[srcOff+2])<<16
				default: // 32
					raw = uint32(data[srcOff]) | uint32(data[srcOff+1])<<8 | uint32(data[srcOff+2])<<16 | uint32(data[srcOff+3])<<24
				}
				surface.SetPixelRaw(left+x, top+y, raw, srcBPP)
			}
		}
	}
}

func ddrawHRESULT(err error) uint32 {
	if err != nil {
		return E_FAIL
	}
	return S_OK
}

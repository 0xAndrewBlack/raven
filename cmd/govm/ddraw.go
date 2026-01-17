package main

import (
	"encoding/binary"

	"github.com/mirkobrombin/Raven/pkg/ddraw"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

const (
	ddraw7Methods        = 30
	ddrawSurface7Methods = 49
	ddrawPaletteMethods  = 7
)

var (
	IID_IDirectDraw7        = GUID{0x15E65EC0, 0x3B9C, 0x11D2, [8]byte{0xB9, 0x2F, 0x00, 0x60, 0x97, 0x97, 0xEA, 0x5B}}
	IID_IDirectDrawSurface7 = GUID{0x06675A80, 0x3B9B, 0x11D2, [8]byte{0xB9, 0x2F, 0x00, 0x60, 0x97, 0x97, 0xEA, 0x5B}}
	IID_IDirectDrawPalette  = GUID{0x6C14DB84, 0xA733, 0x11CE, [8]byte{0xA5, 0x21, 0x00, 0x20, 0xAF, 0x0B, 0xE5, 0x60}}
)

type ddrawDeviceObject struct {
	hctx *HandlerCtx
	dd   *ddraw.DirectDraw
}

type ddrawSurfaceObject struct {
	hctx     *HandlerCtx
	dd       *ddraw.DirectDraw
	surface  *ddraw.Surface
	lockAddr uint64
	lockSize uint64
	lockRect *ddraw.Rect
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
				ctx.Mem.Write64(ppDD, 0)
				ctx.SetReturn(E_NOINTERFACE)
				return 0
			}
		}
		ctx.Mem.Write64(ppDD, 0)
		obj := createDirectDrawObject(hctx)
		if obj == 0 {
			ctx.SetReturn(E_OUTOFMEMORY)
			return 0
		}
		ctx.Mem.Write64(ppDD, obj)
		ctx.SetReturn(S_OK)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "DirectDrawCreate", func(ctx *ntapi.TrapContext) uint32 {
		ppDD := ctx.Arg(1)
		pUnkOuter := ctx.Arg(2)
		if pUnkOuter != 0 {
			ctx.SetReturn(CLASS_E_NOAGGREGATION)
			return 0
		}
		if ppDD == 0 {
			ctx.SetReturn(E_POINTER)
			return 0
		}
		ctx.Mem.Write64(ppDD, 0)
		obj := createDirectDrawObject(hctx)
		if obj == 0 {
			ctx.SetReturn(E_OUTOFMEMORY)
			return 0
		}
		ctx.Mem.Write64(ppDD, obj)
		ctx.SetReturn(S_OK)
		return 0
	})
}

func createDirectDrawObject(hctx *HandlerCtx) uint64 {
	dd := ddraw.NewDirectDraw()
	return d3dCreatePayloadCOMObject(hctx.Mem, hctx.Disp, "ddraw7", ddraw7Methods, &ddrawDeviceObject{hctx: hctx, dd: dd}, ddrawDispatch)
}

func createSurfaceObject(hctx *HandlerCtx, dd *ddraw.DirectDraw, surface *ddraw.Surface) uint64 {
	surface.SetGDIManager(hctx.GdiMgr)
	return d3dCreatePayloadCOMObject(hctx.Mem, hctx.Disp, "ddraw-surface7", ddrawSurface7Methods, &ddrawSurfaceObject{hctx: hctx, dd: dd, surface: surface}, ddrawSurfaceDispatch)
}

func createPaletteObject(hctx *HandlerCtx, palette *ddraw.Palette) uint64 {
	return d3dCreatePayloadCOMObject(hctx.Mem, hctx.Disp, "ddraw-palette", ddrawPaletteMethods, &ddrawPaletteObject{palette: palette}, ddrawPaletteDispatch)
}

func ddrawDispatch(ctx *ntapi.TrapContext, method int, obj *d3dCOMObject) uint32 {
	device, _ := obj.payload.(*ddrawDeviceObject)
	if device == nil || device.dd == nil {
		return E_POINTER
	}
	switch method {
	case 5:
		return ddrawCreatePaletteMethod(ctx, device.hctx)
	case 6:
		pDesc := ctx.Arg(1)
		ppSurface := ctx.Arg(2)
		if pDesc == 0 || ppSurface == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppSurface, 0)
		desc, ok := readGuestStruct[ddraw.DDSURFACEDESC2](ctx.Mem, pDesc)
		if !ok {
			return E_POINTER
		}
		surface, err := device.dd.CreateSurface(&desc)
		if err != nil {
			return E_FAIL
		}
		addr := createSurfaceObject(device.hctx, device.dd, surface)
		if addr == 0 {
			return E_OUTOFMEMORY
		}
		ctx.Mem.Write64(ppSurface, addr)
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
		device.dd.EnumDisplayModes(flags, filter, func(mode *ddraw.DDSURFACEDESC2) bool {
			if callback == 0 {
				return false
			}
			tmp := ctx.Mem.Mmap(0, uint64(binary.Size(*mode)), mmu.PermRead|mmu.PermWrite)
			if tmp == 0 {
				return false
			}
			writeGuestStruct(ctx.Mem, tmp, *mode)
			defer ctx.Mem.Munmap(tmp, uint64(binary.Size(*mode)))
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
			DwSize:  uint32(binary.Size(ddraw.DDSURFACEDESC2{})),
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
		writeGuestStruct(ctx.Mem, pDesc, desc)
		return S_OK
	case 20:
		return ddrawHRESULT(device.dd.SetCooperativeLevel(uint32(ctx.Arg(1)), uint32(ctx.Arg(2))))
	case 21:
		return ddrawHRESULT(device.dd.SetDisplayMode(uint32(ctx.Arg(1)), uint32(ctx.Arg(2)), uint32(ctx.Arg(3)), uint32(ctx.Arg(4)), uint32(ctx.Arg(5))))
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
	switch method {
	case 5:
		dstRect := readDDRect(ctx.Mem, ctx.Arg(1))
		var srcSurface *ddraw.Surface
		if ctx.Arg(2) != 0 {
			payload, ok := d3dLookupPayload[*ddrawSurfaceObject](ctx.Arg(2))
			if !ok || payload == nil {
				return E_POINTER
			}
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
		if surface.IsPrimary {
			presentPrimarySurface(surfObj.hctx, surface)
		}
		return S_OK
	case 7:
		var srcSurface *ddraw.Surface
		payload, ok := d3dLookupPayload[*ddrawSurfaceObject](ctx.Arg(3))
		if !ok || payload == nil {
			return E_POINTER
		}
		srcSurface = payload.surface
		srcRect := readDDRect(ctx.Mem, ctx.Arg(4))
		if err := surface.BltFast(int32(ctx.Arg(1)), int32(ctx.Arg(2)), srcSurface, srcRect, uint32(ctx.Arg(5))); err != nil {
			return E_FAIL
		}
		if surface.IsPrimary {
			presentPrimarySurface(surfObj.hctx, surface)
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
		ctx.Mem.Write64(ppAttached, 0)
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
		ctx.Mem.Write64(ppAttached, addr)
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
		ctx.Mem.Write64(pHDC, hdc)
		return S_OK
	case 20:
		pPalette := ctx.Arg(1)
		if pPalette == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(pPalette, 0)
		if surface.Palette == nil {
			return S_OK
		}
		addr := createPaletteObject(surfObj.hctx, surface.Palette)
		if addr == 0 {
			return E_OUTOFMEMORY
		}
		ctx.Mem.Write64(pPalette, addr)
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
		writeGuestStruct(ctx.Mem, pDesc, desc)
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
		lockHeight := uint64(surface.Height)
		if lockRect != nil {
			lockHeight = uint64(lockRect.Bottom - lockRect.Top)
		}
		lockSize := uint64(surface.Pitch) * lockHeight
		lockAddr := ctx.Mem.Mmap(0, lockSize, mmu.PermRead|mmu.PermWrite)
		if lockAddr == 0 {
			_ = surface.Unlock(lockRect)
			return E_OUTOFMEMORY
		}
		copyBuf := extractSurfaceBytes(surface, lockRect)
		_ = ctx.Mem.WriteBytes(lockAddr, copyBuf)
		desc.LpSurface = lockAddr
		writeGuestStruct(ctx.Mem, pDesc, desc)
		surfObj.lockAddr = lockAddr
		surfObj.lockSize = lockSize
		surfObj.lockRect = lockRect
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
		return S_OK
	case 32:
		if surfObj.lockAddr != 0 {
			data, err := ctx.Mem.ReadBytes(surfObj.lockAddr, int(surfObj.lockSize))
			if err == nil {
				writeSurfaceBytes(surface, surfObj.lockRect, data)
			}
			ctx.Mem.Munmap(surfObj.lockAddr, surfObj.lockSize)
			surfObj.lockAddr = 0
			surfObj.lockSize = 0
			surfObj.lockRect = nil
		}
		if err := surface.Unlock(readDDRect(ctx.Mem, ctx.Arg(1))); err != nil {
			return E_FAIL
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

func ddrawCreatePaletteMethod(ctx *ntapi.TrapContext, hctx *HandlerCtx) uint32 {
	ppPalette := ctx.Arg(3)
	if ppPalette == 0 {
		return E_POINTER
	}
	ctx.Mem.Write64(ppPalette, 0)
	palette := &ddraw.Palette{}
	if pEntries := ctx.Arg(2); pEntries != 0 {
		if entries, ok := readPaletteEntries(ctx.Mem, pEntries, 256); ok {
			palette.SetEntries(uint32(ctx.Arg(1)), 0, uint32(len(entries)), entries)
		}
	}
	addr := createPaletteObject(hctx, palette)
	if addr == 0 {
		return E_OUTOFMEMORY
	}
	ctx.Mem.Write64(ppPalette, addr)
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

func presentPrimarySurface(hctx *HandlerCtx, surface *ddraw.Surface) {
	if hctx == nil || hctx.WlWindow == nil || surface == nil {
		return
	}
	w := hctx.WlWindow
	if int32(surface.Width) != w.Width || int32(surface.Height) != w.Height {
		if w.Resize(int32(surface.Width), int32(surface.Height)) && hctx.SyncScreenSurface != nil {
			hctx.SyncScreenSurface()
		}
	}
	frame := surface.ReadbackXRGB8888(int(w.Width), int(w.Height))
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

func writeSurfaceBytes(surface *ddraw.Surface, rect *ddraw.Rect, data []byte) {
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
	for y := 0; y < height; y++ {
		srcOff := y * surface.Pitch
		dstOff := (top+y)*surface.Pitch + left*bytesPerPixel
		copy(surface.Pixels[dstOff:dstOff+width*bytesPerPixel], data[srcOff:srcOff+width*bytesPerPixel])
	}
}

func ddrawHRESULT(err error) uint32 {
	if err != nil {
		return E_FAIL
	}
	return S_OK
}

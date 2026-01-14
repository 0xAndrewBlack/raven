package main

import (
	"fmt"
	"math"
	"strings"

	gdi "github.com/mirkobrombin/Raven/pkg/gdi"
	ravelog "github.com/mirkobrombin/Raven/pkg/log"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
	"github.com/mirkobrombin/Raven/pkg/win32"
)

type gdiDrawTextAdapter struct {
	dc *gdi.DC
}

func (a gdiDrawTextAdapter) TextExtent(s string) (w, h int32) {
	return a.dc.TextExtentStr(s)
}

func (a gdiDrawTextAdapter) TextOut(x, y int32, s string) {
	a.dc.TextOut(x, y, s, false)
}

func (a gdiDrawTextAdapter) FontHeight() int32 {
	if a.dc == nil || a.dc.Font == nil {
		return gdi.DefaultFont().CellHeight
	}
	return a.dc.Font.CellHeight
}

func registerGdi32Handlers(hctx *HandlerCtx) {
	d := hctx.Disp
	gdiMgr := hctx.GdiMgr
	getDC := hctx.GetDCFn
	mem := hctx.Mem
	readDIBInfo := hctx.ReadDIBInfo
	readDIBPixels := hctx.ReadDIBPixels
	readGuestUTF16 := hctx.ReadGuestUTF16
	sharedHeapAlloc := hctx.HeapAlloc

	gdi32, ok := hctx.SynthByName["gdi32.dll"]
	if !ok {
		return
	}
	_ = gdi32

	ravelog.Logf("[gdi] registrar running: %d exports\n", len(gdi32.Exports))

	identityXform := [6]uint32{0x3F800000, 0, 0, 0x3F800000, 0, 0}

	// readXformMem reads an XFORM struct (6 float32s) from guest memory.
	readXformMem := func(ctx *ntapi.TrapContext, addr uint64) [6]uint32 {
		var xf [6]uint32
		for i := 0; i < 6; i++ {
			xf[i], _ = ctx.Mem.Read32(addr + uint64(i)*4)
		}
		return xf
	}
	// writeXformMem writes an XFORM struct (6 float32s) to guest memory.
	writeXformMem := func(ctx *ntapi.TrapContext, addr uint64, xf [6]uint32) {
		for i := 0; i < 6; i++ {
			ctx.Mem.Write32(addr+uint64(i)*4, xf[i])
		}
	}
	rawToXForm := func(xf [6]uint32) gdi.XForm {
		return gdi.XForm{
			EM11: math.Float32frombits(xf[0]),
			EM12: math.Float32frombits(xf[1]),
			EM21: math.Float32frombits(xf[2]),
			EM22: math.Float32frombits(xf[3]),
			EDx:  math.Float32frombits(xf[4]),
			EDy:  math.Float32frombits(xf[5]),
		}
	}
	xformToRaw := func(xf gdi.XForm) [6]uint32 {
		return [6]uint32{
			math.Float32bits(xf.EM11),
			math.Float32bits(xf.EM12),
			math.Float32bits(xf.EM21),
			math.Float32bits(xf.EM22),
			math.Float32bits(xf.EDx),
			math.Float32bits(xf.EDy),
		}
	}
	// xformMul multiplies two XFORM matrices: result = a * b.
	// ReactOS: CombineTransform in win32ss/gdi/ntgdi/coord.c
	xformMul := func(a, b [6]uint32) [6]uint32 {
		af := [6]float32{}
		bf := [6]float32{}
		for i := 0; i < 6; i++ {
			af[i] = math.Float32frombits(a[i])
			bf[i] = math.Float32frombits(b[i])
		}
		var r [6]float32
		r[0] = af[0]*bf[0] + af[1]*bf[2]         // eM11
		r[1] = af[0]*bf[1] + af[1]*bf[3]         // eM12
		r[2] = af[2]*bf[0] + af[3]*bf[2]         // eM21
		r[3] = af[2]*bf[1] + af[3]*bf[3]         // eM22
		r[4] = af[4]*bf[0] + af[5]*bf[2] + bf[4] // eDx
		r[5] = af[4]*bf[1] + af[5]*bf[3] + bf[5] // eDy
		var out [6]uint32
		for i := 0; i < 6; i++ {
			out[i] = math.Float32bits(r[i])
		}
		return out
	}

	d.RegisterAutoStubHandler(gdi32, "CreateSolidBrush", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(gdiMgr.CreateSolidBrush(uint32(ctx.Arg(0))))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "CreateHatchBrush", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(gdiMgr.CreateHatchBrush(int32(ctx.Arg(0)), uint32(ctx.Arg(1))))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "CreatePen", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(gdiMgr.CreatePen(int32(ctx.Arg(0)), int32(ctx.Arg(1)), uint32(ctx.Arg(2))))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "CreateFontIndirectW", func(ctx *ntapi.TrapContext) uint32 {
		lf := ctx.Arg(0)
		f := &gdi.Font{}
		if lf != 0 {
			v32, _ := mem.Read32(lf)
			f.Height = int32(v32)
			v32, _ = mem.Read32(lf + 4)
			f.Width = int32(v32)
			v32, _ = mem.Read32(lf + 16)
			f.Weight = int32(v32)
			v8, _ := mem.Read8(lf + 20)
			f.Italic = v8 != 0
			v8, _ = mem.Read8(lf + 21)
			f.Underline = v8 != 0
			v8, _ = mem.Read8(lf + 22)
			f.StrikeOut = v8 != 0
			v8, _ = mem.Read8(lf + 23)
			f.CharSet = v8
			v8, _ = mem.Read8(lf + 24)
			f.OutPrecision = v8
			v8, _ = mem.Read8(lf + 25)
			f.ClipPrecision = v8
			v8, _ = mem.Read8(lf + 26)
			f.Quality = v8
			v8, _ = mem.Read8(lf + 27)
			f.PitchFamily = v8
			// FaceName at offset 28 (LF_FACESIZE=32 UTF-16LE chars)
			f.FaceName = readGuestUTF16(lf + 28)
		}
		h := gdiMgr.CreateFont(f)
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "CreateFontW", func(ctx *ntapi.TrapContext) uint32 {
		f := &gdi.Font{
			Height:        int32(ctx.Arg(0)),
			Width:         int32(ctx.Arg(1)),
			Escapement:    int32(ctx.Arg(2)),
			Orientation:   int32(ctx.Arg(3)),
			Weight:        int32(ctx.Arg(4)),
			Italic:        ctx.Arg(5) != 0,
			Underline:     ctx.Arg(6) != 0,
			StrikeOut:     ctx.Arg(7) != 0,
			CharSet:       uint8(ctx.Arg(8)),
			OutPrecision:  uint8(ctx.Arg(9)),
			ClipPrecision: uint8(ctx.Arg(10)),
			Quality:       uint8(ctx.Arg(11)),
			PitchFamily:   uint8(ctx.Arg(12)),
		}
		if pFace := ctx.Arg(13); pFace != 0 {
			name := readGuestUTF16(pFace)
			if len(name) > 31 {
				name = name[:31]
			}
			f.FaceName = name
		}
		ctx.SetReturn(gdiMgr.CreateFont(f))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "CreateCompatibleDC", func(ctx *ntapi.TrapContext) uint32 {
		hdcParent := ctx.Arg(0)
		h, memDC := gdiMgr.AllocMemDC()
		if parent := gdiMgr.GetDC(hdcParent); parent != nil {
			// Inherit parent DC properties (origin, clip, colours, surface).
			memDC.InheritFrom(parent)
		} else if gdiMgr.Screen != nil {
			// No parent → attach to screen surface directly (transparent mode).
			memDC.Target = gdiMgr.Screen
			memDC.IsScreen = true
		}
		memDC.WorldTransform = gdi.IdentityXForm()
		memDC.PolyFillMode = 1
		callerRIP := uint64(0)
		if rr, ok := ctx.CPU.(ntapi.RegisterReader); ok {
			rsp := rr.ReadReg(4) // RSP
			callerRIP, _ = mem.Read64(rsp)
		}
		ravelog.Logf("[gdi] CreateCompatibleDC parent=0x%x → hdc=0x%x caller=0x%x\n", hdcParent, h, callerRIP)
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "CreateCompatibleBitmap", func(ctx *ntapi.TrapContext) uint32 {
		h := gdiMgr.CreateCompatibleBitmap(int32(ctx.Arg(1)), int32(ctx.Arg(2)))
		callerRIP := uint64(0)
		var callers [8]uint64
		if rr, ok := ctx.CPU.(ntapi.RegisterReader); ok {
			rsp := rr.ReadReg(4)
			callerRIP, _ = mem.Read64(rsp)
			for i := range callers {
				callers[i], _ = mem.Read64(rsp + uint64(i*8))
			}
		}
		ravelog.Logf("[gdi] CreateCompatibleBitmap hdc=0x%x w=%d h=%d → 0x%x caller=0x%x stack=%x\n", ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), h, callerRIP, callers)
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "CreateDIBSection", func(ctx *ntapi.TrapContext) uint32 {
		// CreateDIBSection(hdc, pbmi, usage, ppvBits, hSection, offset)
		pbi := ctx.Arg(1)
		ppvBits := ctx.Arg(4)
		w, h := int32(0), int32(0)
		if pbi != 0 {
			v32, _ := mem.Read32(pbi + 4)
			w = int32(v32)
			v32, _ = mem.Read32(pbi + 8)
			h = int32(v32)
			if h < 0 {
				h = -h
			}
		}
		if w <= 0 {
			w = 1
		}
		if h <= 0 {
			h = 1
		}
		// Allocate guest memory for the pixel data and write ppvBits
		stride := int(w) * 4 // 32bpp BGRA
		sz := uint64(stride * int(h))
		bits := mem.Mmap(0, sz, mmu.PermRead|mmu.PermWrite)
		if ppvBits != 0 {
			mem.Write64(ppvBits, bits)
		}
		hBmp := gdiMgr.CreateDIBSection(w, h)
		ravelog.Logf("[gdi] CreateDIBSection %dx%d → hbm=0x%x bits=0x%x (%d bytes)\n", w, h, hBmp, bits, sz)
		ctx.SetReturn(hBmp)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "CreateDIBitmap", func(ctx *ntapi.TrapContext) uint32 {
		// hdc := ctx.Arg(0)
		lpbmih := ctx.Arg(1)
		// fdwInit := ctx.Arg(2)
		// lpbInit := ctx.Arg(3)
		// lpbmi := ctx.Arg(4)
		// fuUsage := ctx.Arg(5)
		var w, h int32
		if lpbmih != 0 {
			ww, _ := mem.Read32(lpbmih + 4)
			hh, _ := mem.Read32(lpbmih + 8)
			w = int32(ww)
			h = int32(hh)
			if h < 0 {
				h = -h
			}
		}
		if w <= 0 {
			w = 1
		}
		if h <= 0 {
			h = 1
		}
		ctx.SetReturn(gdiMgr.CreateDIBSection(w, h))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DeleteDC", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		if gdiMgr.GetDC(hdc) == nil {
			ctx.SetReturn(0)
			return 0
		}
		gdiMgr.DeleteDC(hdc)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DeleteObject", func(ctx *ntapi.TrapContext) uint32 {
		if gdiMgr.DeleteObject(ctx.Arg(0)) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SelectObject", func(ctx *ntapi.TrapContext) uint32 {
		dc := ctx.Arg(0)
		obj := ctx.Arg(1)
		old := gdiMgr.SelectObject(dc, obj)
		ravelog.Logf("[gdi] SelectObject dc=0x%x obj=0x%x → old=0x%x\n", dc, obj, old)
		ctx.SetReturn(old)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetStockObject", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(gdiMgr.GetStockObject(int(ctx.Arg(0))))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetObjectW", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: NtGdiExtGetObjectW - return object info based on type
		h := ctx.Arg(0)
		obj := gdiMgr.GetObject(h)
		if obj == nil {
			ctx.SetReturn(0)
			return 0
		}
		pv := ctx.Arg(2)
		switch obj.Type {
		case gdi.ObjPen:
			// LOGPEN: {lopnStyle:UINT(+0), lopnWidth:POINT(+4,+8), lopnColor:COLORREF(+12)} = 16 bytes
			ctx.SetReturn(16)
			if pv != 0 && obj.Pen != nil {
				ctx.Mem.Write32(pv, uint32(obj.Pen.Style))
				ctx.Mem.Write32(pv+4, uint32(obj.Pen.Width)) // POINT.x
				ctx.Mem.Write32(pv+8, 0)                     // POINT.y
				ctx.Mem.Write32(pv+12, obj.Pen.Color)
			}
		case gdi.ObjBrush:
			// LOGBRUSH on x64: {lbStyle:UINT(+0,4), lbColor:COLORREF(+4,4), lbHatch:ULONG_PTR(+8,8)} = 16
			ctx.SetReturn(16)
			if pv != 0 && obj.Brush != nil {
				ctx.Mem.Write32(pv, uint32(obj.Brush.Style))
				ctx.Mem.Write32(pv+4, obj.Brush.Color)
				ctx.Mem.Write64(pv+8, uint64(obj.Brush.Hatch))
			}
		case gdi.ObjFont:
			ctx.SetReturn(92) // sizeof(LOGFONTW)
			if pv != 0 && obj.Font != nil {
				f := obj.Font
				ctx.Mem.Write32(pv, uint32(f.Height))
				ctx.Mem.Write32(pv+4, uint32(f.Width))
				ctx.Mem.Write32(pv+8, uint32(f.Escapement))
				ctx.Mem.Write32(pv+12, uint32(f.Orientation))
				w := f.Weight
				if w == 0 {
					w = 400
				}
				ctx.Mem.Write32(pv+16, uint32(w))
				italic := byte(0)
				if f.Italic {
					italic = 1
				}
				ctx.Mem.Write8(pv+20, italic)
				underline := byte(0)
				if f.Underline {
					underline = 1
				}
				ctx.Mem.Write8(pv+21, underline)
				strike := byte(0)
				if f.StrikeOut {
					strike = 1
				}
				ctx.Mem.Write8(pv+22, strike)
				ctx.Mem.Write8(pv+23, f.CharSet)
				ctx.Mem.Write8(pv+24, f.OutPrecision)
				ctx.Mem.Write8(pv+25, f.ClipPrecision)
				ctx.Mem.Write8(pv+26, f.Quality)
				ctx.Mem.Write8(pv+27, f.PitchFamily)
				// lfFaceName: WCHAR[32] at offset 28
				face := []rune(f.FaceName)
				if len(face) > 31 {
					face = face[:31]
				}
				for i, ch := range face {
					ctx.Mem.Write16(pv+28+uint64(i)*2, uint16(ch))
				}
				ctx.Mem.Write16(pv+28+uint64(len(face))*2, 0) // NUL terminator
			}
		case gdi.ObjBitmap:
			ctx.SetReturn(32) // sizeof(BITMAP) on x64
			if pv != 0 && obj.Bitmap != nil {
				ctx.Mem.Write32(pv, 0)
				ctx.Mem.Write32(pv+4, uint32(obj.Bitmap.Width))
				ctx.Mem.Write32(pv+8, uint32(obj.Bitmap.Height))
				ctx.Mem.Write32(pv+12, uint32(obj.Bitmap.Width*4))
				ctx.Mem.Write16(pv+16, 1)
				ctx.Mem.Write16(pv+18, 32)
				ctx.Mem.Write32(pv+20, 0)
				ctx.Mem.Write64(pv+24, 0)
			}
		default:
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetDeviceCaps", func(ctx *ntapi.TrapContext) uint32 {
		idx := ctx.Arg(1)
		val := uint64(0)
		w, h := uint64(1920), uint64(1080)
		if hctx.WlWindow != nil {
			w = uint64(hctx.WlWindow.Width)
			h = uint64(hctx.WlWindow.Height)
		}
		switch idx {
		case 0:
			val = 0 // DRIVERVERSION
		case 2:
			val = 1 // TECHNOLOGY: DT_RASDISPLAY
		case 4:
			val = 508 // HORZSIZE (mm)
		case 6:
			val = 285 // VERTSIZE (mm)
		case 8:
			val = w // HORZRES
		case 10:
			val = h // VERTRES
		case 12:
			val = 32 // BITSPIXEL
		case 14:
			val = 1 // PLANES
		case 16:
			val = 0 // NUMBRUSHES
		case 18:
			val = 0 // NUMPENS
		case 20:
			val = 0 // NUMMARKERS
		case 22:
			val = 0 // NUMFONTS
		case 24:
			val = 0xFFFFFF // NUMCOLORS
		case 26:
			val = 0x0001 // CLIPCAPS
		case 28:
			val = 0x7F // SIZEPALETTE
		case 30:
			val = 0x0001FF // POLYGONALCAPS
		case 32:
			val = 0x0000FF // LINECAPS
		case 34:
			val = 0x6A04 // TEXTCAPS
		case 36:
			val = 0x0001FF // CURVECAPS
		case 38:
			val = 0x7E99 // RASTERCAPS (RC_BITBLT|RC_SCALING|RC_BITMAP64|RC_DI_BITMAP|RC_PALETTE|RC_DIBTODEV|RC_STRETCHBLT|RC_STRETCHDIB)
		case 40:
			val = w // ASPECTX
		case 42:
			val = h // ASPECTY
		case 44:
			val = w // ASPECTXY (diagonal)
		case 86:
			val = 8 // COLORRES (bits per primary)
		case 88:
			val = 96 // LOGPIXELSX
		case 90:
			val = 96 // LOGPIXELSY
		case 104:
			val = 256 // SIZEPALETTE
		case 106:
			val = 20 // NUMRESERVED
		case 108:
			val = 24 // COLORRES (bits of color resolution)
		case 110:
			val = w // PHYSICALWIDTH
		case 111:
			val = h // PHYSICALHEIGHT
		case 112:
			val = 0 // PHYSICALOFFSETX
		case 113:
			val = 0 // PHYSICALOFFSETY
		case 114:
			val = 0 // SCALINGFACTORX
		case 115:
			val = 0 // SCALINGFACTORY
		case 116:
			val = 60 // VREFRESH
		case 117:
			val = h // DESKTOPVERTRES
		case 118:
			val = w // DESKTOPHORZRES
		case 119:
			val = 0 // BLTALIGNMENT
		case 120:
			val = 0x0002 // SHADEBLENDCAPS (SB_CONST_ALPHA | SB_PIXEL_ALPHA)
		case 121:
			val = 0x0003 // COLORMGMTCAPS (CM_GAMMA_RAMP | CM_CMYK_COLOR)
		}
		ctx.SetReturn(val)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetTextMetricsW", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		pTM := ctx.Arg(1)
		dc := getDC(hdc)
		f := dc.Font
		if f == nil {
			f = gdi.DefaultFont()
		}
		ravelog.Logf("[gdi] GetTextMetricsW dc=0x%x → h=%d asc=%d desc=%d avew=%d maxw=%d\n", hdc, f.CellHeight, f.Ascent, f.Descent, f.AveCharWidth, f.MaxCharWidth)
		if pTM != 0 {
			// TEXTMETRICW layout (Win32 x64, all int32 unless noted):
			// +0  tmHeight           = CellHeight
			// +4  tmAscent           = Ascent
			// +8  tmDescent          = Descent
			// +12 tmInternalLeading  = 0
			// +16 tmExternalLeading  = 0
			// +20 tmAveCharWidth     = AveCharWidth
			// +24 tmMaxCharWidth     = MaxCharWidth
			// +28 tmWeight           = FW_NORMAL=400
			// +32 tmOverhang         = 0
			// +36 tmDigitizedAspectX = 96 (DPI)
			// +40 tmDigitizedAspectY = 96 (DPI)
			// +44 tmFirstChar        WCHAR = 0x0020
			// +46 tmLastChar         WCHAR = 0x00FF
			// +48 tmDefaultChar      WCHAR = 0x003F ('?')
			// +50 tmBreakChar        WCHAR = 0x0020 (' ')
			// +52 tmItalic           BYTE
			// +53 tmUnderlined       BYTE
			// +54 tmStruckOut        BYTE
			// +55 tmPitchAndFamily   BYTE  = TMPF_FIXED_PITCH|FF_MODERN = 0x21
			// +56 tmCharSet          BYTE  = ANSI_CHARSET = 0
			weight := f.Weight
			if weight == 0 {
				weight = 400
			}
			italic := byte(0)
			if f.Italic {
				italic = 1
			}
			underline := byte(0)
			if f.Underline {
				underline = 1
			}
			ctx.Mem.Write32(pTM, uint32(f.CellHeight))
			ctx.Mem.Write32(pTM+4, uint32(f.Ascent))
			ctx.Mem.Write32(pTM+8, uint32(f.Descent))
			ctx.Mem.Write32(pTM+12, 0)
			ctx.Mem.Write32(pTM+16, 0)
			ctx.Mem.Write32(pTM+20, uint32(f.AveCharWidth))
			ctx.Mem.Write32(pTM+24, uint32(f.MaxCharWidth))
			ctx.Mem.Write32(pTM+28, uint32(weight))
			ctx.Mem.Write32(pTM+32, 0)
			ctx.Mem.Write32(pTM+36, 96)
			ctx.Mem.Write32(pTM+40, 96)
			ctx.Mem.Write16(pTM+44, 0x0020) // tmFirstChar
			ctx.Mem.Write16(pTM+46, 0x00FF) // tmLastChar
			ctx.Mem.Write16(pTM+48, 0x003F) // tmDefaultChar '?'
			ctx.Mem.Write16(pTM+50, 0x0020) // tmBreakChar ' '
			ctx.Mem.Write8(pTM+52, italic)
			ctx.Mem.Write8(pTM+53, underline)
			ctx.Mem.Write8(pTM+54, 0)
			ctx.Mem.Write8(pTM+55, 0x01) // TMPF_FIXED_PITCH
			ctx.Mem.Write8(pTM+56, 0)    // ANSI_CHARSET
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetTextMetricsA", func(ctx *ntapi.TrapContext) uint32 {
		// TEXTMETRICA is byte-char version; same layout as TEXTMETRICW but tmFirstChar/LastChar/DefaultChar/BreakChar are BYTE, not WCHAR.
		// Offset differences: tmFirstChar(+44,1), tmLastChar(+45,1), tmDefaultChar(+46,1), tmBreakChar(+47,1) = total 48 bytes (vs 52 for W).
		hdc := ctx.Arg(0)
		pTM := ctx.Arg(1)
		dc := getDC(hdc)
		f := dc.Font
		if f == nil {
			f = gdi.DefaultFont()
		}
		weight := f.Weight
		if weight == 0 {
			weight = 400
		}
		italic := byte(0)
		if f.Italic {
			italic = 1
		}
		underline := byte(0)
		if f.Underline {
			underline = 1
		}
		if pTM != 0 {
			ctx.Mem.Write32(pTM+0, uint32(f.CellHeight))
			ctx.Mem.Write32(pTM+4, uint32(f.Ascent))
			ctx.Mem.Write32(pTM+8, uint32(f.Descent))
			ctx.Mem.Write32(pTM+12, 0)
			ctx.Mem.Write32(pTM+16, 0)
			ctx.Mem.Write32(pTM+20, uint32(f.AveCharWidth))
			ctx.Mem.Write32(pTM+24, uint32(f.MaxCharWidth))
			ctx.Mem.Write32(pTM+28, uint32(weight))
			ctx.Mem.Write32(pTM+32, 0)
			ctx.Mem.Write32(pTM+36, 96)
			ctx.Mem.Write32(pTM+40, 96)
			ctx.Mem.Write8(pTM+44, 0x20) // tmFirstChar
			ctx.Mem.Write8(pTM+45, 0xFF) // tmLastChar
			ctx.Mem.Write8(pTM+46, 0x3F) // tmDefaultChar '?'
			ctx.Mem.Write8(pTM+47, 0x20) // tmBreakChar ' '
			ctx.Mem.Write8(pTM+48, italic)
			ctx.Mem.Write8(pTM+49, underline)
			ctx.Mem.Write8(pTM+50, 0)
			ctx.Mem.Write8(pTM+51, 0x01) // TMPF_FIXED_PITCH
			ctx.Mem.Write8(pTM+52, 0)    // ANSI_CHARSET
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetTextExtentPoint32W", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		lpString := ctx.Arg(1)
		nLen := int32(ctx.Arg(2))
		pSize := ctx.Arg(3)
		dc := getDC(hdc)
		f := dc.Font
		if f == nil {
			f = gdi.DefaultFont()
		}
		if pSize != 0 {
			w := int32(0)
			if f.FaceID >= 0 && lpString != 0 && nLen > 0 {
				// Measure real TrueType glyph widths
				pixSize := f.Height
				if pixSize < 0 {
					pixSize = -pixSize
				}
				if pixSize == 0 {
					pixSize = 12
				}
				chars := make([]uint16, nLen)
				for i := int32(0); i < nLen; i++ {
					ch, _ := ctx.Mem.Read16(lpString + uint64(i)*2)
					chars[i] = ch
				}
				for _, r := range gdi.UTF16ToRunes(chars) {
					if g := gdi.GlyphFor(f.FaceID, pixSize, r); g != nil {
						w += g.Advance
					} else {
						w += f.AveCharWidth
					}
					w += dc.CharExtra
				}
				if w > 0 {
					w -= dc.CharExtra
				}
			} else {
				if nLen > 0 {
					w = nLen*f.AveCharWidth + (nLen-1)*dc.CharExtra
				}
			}
			ctx.Mem.Write32(pSize, uint32(w))
			ctx.Mem.Write32(pSize+4, uint32(f.CellHeight))
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetTextExtentPoint32A", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		lpString := ctx.Arg(1)
		nLen := int32(ctx.Arg(2))
		pSize := ctx.Arg(3)
		dc := getDC(hdc)
		f := dc.Font
		if f == nil {
			f = gdi.DefaultFont()
		}
		if pSize != 0 {
			w := int32(0)
			if f.FaceID >= 0 && lpString != 0 && nLen > 0 {
				pixSize := f.Height
				if pixSize < 0 {
					pixSize = -pixSize
				}
				if pixSize == 0 {
					pixSize = 12
				}
				for i := int32(0); i < nLen; i++ {
					b, _ := ctx.Mem.Read8(lpString + uint64(i))
					if g := gdi.GlyphFor(f.FaceID, pixSize, rune(b)); g != nil {
						w += g.Advance
					} else {
						w += f.AveCharWidth
					}
					w += dc.CharExtra
				}
				if w > 0 {
					w -= dc.CharExtra
				}
			} else {
				if nLen > 0 {
					w = nLen*f.AveCharWidth + (nLen-1)*dc.CharExtra
				}
			}
			ctx.Mem.Write32(pSize, uint32(w))
			ctx.Mem.Write32(pSize+4, uint32(f.CellHeight))
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetTextExtentExPointW", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		nLen := int32(ctx.Arg(2))
		pSize := ctx.Arg(5)
		dc := getDC(hdc)
		f := dc.Font
		if f == nil {
			f = gdi.DefaultFont()
		}
		if pSize != 0 {
			ctx.Mem.Write32(pSize, uint32(nLen*f.AveCharWidth))
			ctx.Mem.Write32(pSize+4, uint32(f.CellHeight))
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SetBkMode", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		prev := dc.BkMode
		dc.BkMode = int32(ctx.Arg(1))
		ctx.SetReturn(uint64(prev))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SetBkColor", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		prev := dc.BkColor
		dc.BkColor = uint32(ctx.Arg(1))
		ravelog.Logf("[gdi] SetBkColor dc=0x%x color=0x%06x\n", ctx.Arg(0), ctx.Arg(1))
		ctx.SetReturn(uint64(prev))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetBkColor", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(getDC(ctx.Arg(0)).BkColor))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SetTextColor", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		prev := dc.TextColor
		dc.TextColor = uint32(ctx.Arg(1))
		ctx.SetReturn(uint64(prev))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetTextColor", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(getDC(ctx.Arg(0)).TextColor))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SaveDC", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		ctx.SetReturn(uint64(dc.Save()))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "RestoreDC", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		level := int(int32(ctx.Arg(1)))
		ok := dc.Restore(level)
		if ok {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SetViewportOrgEx", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		// ReactOS: NtGdiSetViewportOrgEx - write old origin to lpPoint (arg 3)
		p := ctx.Arg(3)
		if p != 0 {
			ctx.Mem.Write32(p, uint32(dc.OriginX))
			ctx.Mem.Write32(p+4, uint32(dc.OriginY))
		}
		dc.SetViewportOrg(int32(ctx.Arg(1)), int32(ctx.Arg(2)))
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "OffsetViewportOrgEx", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		// ReactOS: NtGdiOffsetViewportOrgEx - write old origin to lpPoint (arg 3)
		p := ctx.Arg(3)
		if p != 0 {
			ctx.Mem.Write32(p, uint32(dc.OriginX))
			ctx.Mem.Write32(p+4, uint32(dc.OriginY))
		}
		dc.OffsetViewportOrg(int32(ctx.Arg(1)), int32(ctx.Arg(2)))
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetViewportOrgEx", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		p := ctx.Arg(1)
		if p != 0 {
			ctx.Mem.Write32(p, uint32(dc.OriginX))
			ctx.Mem.Write32(p+4, uint32(dc.OriginY))
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "TextOutW", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		x := int32(ctx.Arg(1))
		y := int32(ctx.Arg(2))
		lpStr := ctx.Arg(3)
		nLen := int(ctx.Arg(4))
		text := readGuestUTF16(lpStr)
		if nLen > 0 && nLen < len(text) {
			text = text[:nLen]
		}
		dc.TextOut(x, y, text, false)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "ExtTextOutW", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		x := int32(ctx.Arg(1))
		y := int32(ctx.Arg(2))
		opts := uint32(ctx.Arg(3))
		lprc := ctx.Arg(4)
		lpStr := ctx.Arg(5)
		nLen := int(ctx.Arg(6))
		text := readGuestUTF16(lpStr)
		if nLen > 0 && nLen < len(text) {
			text = text[:nLen]
		}
		if lprc != 0 {
			rL, _ := mem.Read32(lprc)
			rT, _ := mem.Read32(lprc + 4)
			rR, _ := mem.Read32(lprc + 8)
			rB, _ := mem.Read32(lprc + 12)
			if len(text) > 0 || opts&0x2 != 0 {
				ravelog.Logf("[gdi] ExtTextOut dc=0x%x ox=%d oy=%d x=%d y=%d opts=0x%x rc=(%d,%d,%d,%d) bk=0x%x text=%q\n",
					ctx.Arg(0), dc.OriginX, dc.OriginY, x, y, opts, rL, rT, rR, rB, dc.BkColor, text)
			}
			// ETO_OPAQUE (0x2): fill background rect
			if opts&0x2 != 0 {
				dc.FillRect(int32(rL), int32(rT), int32(rR), int32(rB), dc.BkColor)
			}
			// ETO_CLIPPED (0x4): clip to rect
			if opts&0x4 != 0 {
				// Temporarily tighten clip to rect (absolute coords)
				x0 := int32(rL) + dc.OriginX
				y0 := int32(rT) + dc.OriginY
				x1 := int32(rR) + dc.OriginX
				y1 := int32(rB) + dc.OriginY
				oldX0, oldY0, oldX1, oldY1 := dc.ClipX0, dc.ClipY0, dc.ClipX1, dc.ClipY1
				// Intersect with existing clip
				if oldX1 > oldX0 {
					if x0 < oldX0 {
						x0 = oldX0
					}
					if y0 < oldY0 {
						y0 = oldY0
					}
					if x1 > oldX1 {
						x1 = oldX1
					}
					if y1 > oldY1 {
						y1 = oldY1
					}
				}
				dc.ClipX0, dc.ClipY0, dc.ClipX1, dc.ClipY1 = x0, y0, x1, y1
				if len(text) > 0 {
					dc.TextOut(x, y, text, false)
				}
				dc.ClipX0, dc.ClipY0, dc.ClipX1, dc.ClipY1 = oldX0, oldY0, oldX1, oldY1
				ctx.SetReturn(1)
				return 0
			}
		}
		if len(text) > 0 {
			dc.TextOut(x, y, text, false)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "BitBlt", func(ctx *ntapi.TrapContext) uint32 {
		if hctx.WlWindow == nil {
			ctx.SetReturn(1)
			return 0
		}
		hdcDst := ctx.Arg(0)
		dx := int32(ctx.Arg(1))
		dy := int32(ctx.Arg(2))
		w := int32(ctx.Arg(3))
		h := int32(ctx.Arg(4))
		hdcSrc := ctx.Arg(5)
		sx := int32(ctx.Arg(6))
		sy := int32(ctx.Arg(7))
		rop3 := uint32(ctx.Arg(8))
		dst := getDC(hdcDst)
		src := gdiMgr.GetDC(hdcSrc)
		if dst != nil {
			dstO := fmt.Sprintf("ox=%d,oy=%d", dst.OriginX, dst.OriginY)
			srcO := "nil"
			if src != nil {
				srcO = fmt.Sprintf("ox=%d,oy=%d", src.OriginX, src.OriginY)
			}
			ravelog.Logf("[gdi] BitBlt dst=0x%x(%s) dx=%d dy=%d w=%d h=%d src=0x%x(%s) sx=%d sy=%d rop=0x%x\n",
				hdcDst, dstO, dx, dy, w, h, hdcSrc, srcO, sx, sy, rop3)
		}
		dst.BitBlt(dx, dy, w, h, src, sx, sy, rop3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "StretchBlt", func(ctx *ntapi.TrapContext) uint32 {
		if hctx.WlWindow == nil {
			ctx.SetReturn(1)
			return 0
		}
		hdcDst := ctx.Arg(0)
		dx := int32(ctx.Arg(1))
		dy := int32(ctx.Arg(2))
		dw := int32(ctx.Arg(3))
		dh := int32(ctx.Arg(4))
		hdcSrc := ctx.Arg(5)
		sx := int32(ctx.Arg(6))
		sy := int32(ctx.Arg(7))
		sw := int32(ctx.Arg(8))
		sh := int32(ctx.Arg(9))
		rop3 := uint32(ctx.Arg(10))
		dst := getDC(hdcDst)
		src := gdiMgr.GetDC(hdcSrc)
		dst.StretchBlt(dx, dy, dw, dh, src, sx, sy, sw, sh, rop3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "PatBlt", func(ctx *ntapi.TrapContext) uint32 {
		if hctx.WlWindow == nil {
			ctx.SetReturn(1)
			return 0
		}
		dc := getDC(ctx.Arg(0))
		x := int32(ctx.Arg(1))
		y := int32(ctx.Arg(2))
		w := int32(ctx.Arg(3))
		h := int32(ctx.Arg(4))
		rop := ctx.Arg(5)
		ravelog.Logf("[gdi] PatBlt dc=0x%x x=%d y=%d w=%d h=%d rop=0x%x\n", ctx.Arg(0), x, y, w, h, rop)
		switch rop & 0xFF0000 {
		case 0x000000: // BLACKNESS
			dc.FillRect(x, y, x+w, y+h, 0x000000)
		case 0xFF0000: // WHITENESS
			dc.FillRect(x, y, x+w, y+h, 0xFFFFFF)
		case 0x5A0000: // PATINVERT - XOR; approximate as solid fill
			brushColor := uint32(0xF0F0F0)
			if dc.Brush != nil && dc.Brush.Style == 0 {
				brushColor = dc.Brush.Color
			}
			dc.FillRect(x, y, x+w, y+h, brushColor^0xFFFFFF)
		default: // PATCOPY and others - fill with brush
			brushColor := uint32(0xF0F0F0)
			if dc.Brush != nil && dc.Brush.Style == 0 {
				brushColor = dc.Brush.Color
			}
			dc.FillRect(x, y, x+w, y+h, brushColor)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "FillRect", func(ctx *ntapi.TrapContext) uint32 {
		lpRect := ctx.Arg(1)
		if lpRect == 0 {
			ctx.SetReturn(1)
			return 0
		}
		dc := getDC(ctx.Arg(0))
		left, _ := mem.Read32(lpRect)
		top, _ := mem.Read32(lpRect + 4)
		right, _ := mem.Read32(lpRect + 8)
		bottom, _ := mem.Read32(lpRect + 12)
		color := gdiMgr.BrushColor(ctx.Arg(2), hctx.SysColors)
		ravelog.Logf("[gdi] FillRect dc=0x%x (%d,%d,%d,%d) color=0x%06x\n", ctx.Arg(0), left, top, right, bottom, color)
		dc.FillRect(int32(left), int32(top), int32(right), int32(bottom), color)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "FrameRect", func(ctx *ntapi.TrapContext) uint32 {
		lpRect := ctx.Arg(1)
		if lpRect == 0 {
			ctx.SetReturn(0)
			return 0
		}
		dc := getDC(ctx.Arg(0))
		left, _ := mem.Read32(lpRect)
		top, _ := mem.Read32(lpRect + 4)
		right, _ := mem.Read32(lpRect + 8)
		bottom, _ := mem.Read32(lpRect + 12)
		color := gdiMgr.BrushColor(ctx.Arg(2), hctx.SysColors)
		dc.FrameRect(int32(left), int32(top), int32(right), int32(bottom), color)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "Rectangle", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		dc.Rectangle(int32(ctx.Arg(1)), int32(ctx.Arg(2)), int32(ctx.Arg(3)), int32(ctx.Arg(4)))
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "MoveToEx", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		// ReactOS: NtGdiMoveToEx - write old position to lpPoint (arg 3)
		p := ctx.Arg(3)
		if p != 0 {
			ctx.Mem.Write32(p, uint32(dc.CurX))
			ctx.Mem.Write32(p+4, uint32(dc.CurY))
		}
		dc.MoveTo(int32(ctx.Arg(1)), int32(ctx.Arg(2)))
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "LineTo", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		dc.LineTo(int32(ctx.Arg(1)), int32(ctx.Arg(2)))
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "Ellipse", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		dc.Ellipse(int32(ctx.Arg(1)), int32(ctx.Arg(2)), int32(ctx.Arg(3)), int32(ctx.Arg(4)))
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "StretchDIBits", func(ctx *ntapi.TrapContext) uint32 {
		if hctx.WlWindow == nil {
			ctx.SetReturn(uint64(0xFFFFFFFF))
			return 0
		}
		dc := getDC(ctx.Arg(0))
		dx := int32(ctx.Arg(1))
		dy := int32(ctx.Arg(2))
		dw := int32(ctx.Arg(3))
		dh := int32(ctx.Arg(4))
		sx := int32(ctx.Arg(5))
		sy := int32(ctx.Arg(6))
		sw := int32(ctx.Arg(7))
		sh := int32(ctx.Arg(8))
		pBits := ctx.Arg(9)
		pBMI := ctx.Arg(10)
		// arg11 = iUsage (ignored - we treat as DIB_RGB_COLORS)
		// arg12 = rop (ignored - SRCCOPY assumed)
		srcW, srcH, bitCount, _, ct, _ := readDIBInfo(pBMI)
		pixData := readDIBPixels(pBits, srcW, srcH, bitCount)
		if pixData == nil || dc.Target == nil {
			ctx.SetReturn(uint64(dh))
			return 0
		}
		adx := dx + dc.OriginX
		ady := dy + dc.OriginY
		dc.Target.BlitDIB(adx, ady, dw, dh, pixData, srcW, srcH, bitCount, ct, sx, sy, sw, sh)
		ctx.SetReturn(uint64(dh))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SetDIBitsToDevice", func(ctx *ntapi.TrapContext) uint32 {
		if hctx.WlWindow == nil {
			ctx.SetReturn(0)
			return 0
		}
		dc := getDC(ctx.Arg(0))
		dx := int32(ctx.Arg(1))
		dy := int32(ctx.Arg(2))
		sw := int32(ctx.Arg(3))
		sh := int32(ctx.Arg(4))
		sx := int32(ctx.Arg(5))
		sy := int32(ctx.Arg(6))
		// arg7 = StartScan (first scan line to copy)
		// arg8 = NumScans (number of scan lines)
		pBits := ctx.Arg(9)
		pBMI := ctx.Arg(10)
		srcW, srcH, bitCount, _, ct, _ := readDIBInfo(pBMI)
		pixData := readDIBPixels(pBits, srcW, srcH, bitCount)
		if pixData == nil || dc.Target == nil {
			ctx.SetReturn(uint64(sh))
			return 0
		}
		adx := dx + dc.OriginX
		ady := dy + dc.OriginY
		// No scaling: dw=sw, dh=sh
		dc.Target.BlitDIB(adx, ady, sw, sh, pixData, srcW, srcH, bitCount, ct, sx, sy, sw, sh)
		ctx.SetReturn(uint64(sh))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SetMapMode", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		prev := dc.MapMode
		if prev == 0 {
			prev = 1
		}
		dc.MapMode = int32(ctx.Arg(1))
		if dc.MapMode == 0 {
			dc.MapMode = 1
		}
		ctx.SetReturn(uint64(prev))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetMapMode", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		mm := dc.MapMode
		if mm == 0 {
			mm = 1
		}
		ctx.SetReturn(uint64(mm))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SetTextAlign", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		prev := dc.TextAlign
		dc.TextAlign = int32(ctx.Arg(1))
		ctx.SetReturn(uint64(uint32(prev)))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetTextAlign", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(uint32(getDC(ctx.Arg(0)).TextAlign)))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SetTextCharacterExtra", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		prev := dc.CharExtra
		dc.CharExtra = int32(ctx.Arg(1))
		ctx.SetReturn(uint64(uint32(prev)))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetTextCharacterExtra", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(uint32(getDC(ctx.Arg(0)).CharExtra)))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SetStretchBltMode", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		prev := dc.StretchBltMode
		if prev == 0 {
			prev = 1
		}
		dc.StretchBltMode = int32(ctx.Arg(1))
		ctx.SetReturn(uint64(uint32(prev)))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetStretchBltMode", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		m := dc.StretchBltMode
		if m == 0 {
			m = 1
		}
		ctx.SetReturn(uint64(uint32(m)))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SetROP2", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		prev := dc.ROP2
		if prev == 0 {
			prev = 13
		}
		dc.ROP2 = int32(ctx.Arg(1))
		ctx.SetReturn(uint64(uint32(prev)))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetROP2", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		r := dc.ROP2
		if r == 0 {
			r = 13
		}
		ctx.SetReturn(uint64(uint32(r)))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SetArcDirection", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		prev := dc.ArcDir
		if prev == 0 {
			prev = 1
		}
		dc.ArcDir = int32(ctx.Arg(1))
		ctx.SetReturn(uint64(uint32(prev)))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetArcDirection", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		d2 := dc.ArcDir
		if d2 == 0 {
			d2 = 1
		}
		ctx.SetReturn(uint64(uint32(d2)))
		return 0
	})
	// --- Region functions ---
	d.RegisterAutoStubHandler(gdi32, "CreateRectRgn", func(ctx *ntapi.TrapContext) uint32 {
		h := gdiMgr.CreateRectRgn(int32(ctx.Arg(0)), int32(ctx.Arg(1)), int32(ctx.Arg(2)), int32(ctx.Arg(3)))
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "CreateRectRgnIndirect", func(ctx *ntapi.TrapContext) uint32 {
		p := ctx.Arg(0)
		var l, t, r, b int32
		if p != 0 {
			v, _ := mem.Read32(p)
			l = int32(v)
			v, _ = mem.Read32(p + 4)
			t = int32(v)
			v, _ = mem.Read32(p + 8)
			r = int32(v)
			v, _ = mem.Read32(p + 12)
			b = int32(v)
		}
		ctx.SetReturn(gdiMgr.CreateRectRgn(l, t, r, b))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "CreateEllipticRgn", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(gdiMgr.CreateEllipticRgn(int32(ctx.Arg(0)), int32(ctx.Arg(1)), int32(ctx.Arg(2)), int32(ctx.Arg(3))))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "CreateEllipticRgnIndirect", func(ctx *ntapi.TrapContext) uint32 {
		p := ctx.Arg(0)
		var l, t, r, b int32
		if p != 0 {
			v, _ := mem.Read32(p)
			l = int32(v)
			v, _ = mem.Read32(p + 4)
			t = int32(v)
			v, _ = mem.Read32(p + 8)
			r = int32(v)
			v, _ = mem.Read32(p + 12)
			b = int32(v)
		}
		ctx.SetReturn(gdiMgr.CreateEllipticRgn(l, t, r, b))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "CreateRoundRectRgn", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(gdiMgr.CreateRoundRectRgn(int32(ctx.Arg(0)), int32(ctx.Arg(1)), int32(ctx.Arg(2)), int32(ctx.Arg(3)), int32(ctx.Arg(4)), int32(ctx.Arg(5))))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SetRectRgn", func(ctx *ntapi.TrapContext) uint32 {
		ok := gdiMgr.SetRectRgn(ctx.Arg(0), int32(ctx.Arg(1)), int32(ctx.Arg(2)), int32(ctx.Arg(3)), int32(ctx.Arg(4)))
		if ok {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "CombineRgn", func(ctx *ntapi.TrapContext) uint32 {
		result := gdiMgr.CombineRgn(ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), int(ctx.Arg(3)))
		ctx.SetReturn(uint64(result))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetRgnBox", func(ctx *ntapi.TrapContext) uint32 {
		p := ctx.Arg(1)
		var bounds [4]int32
		result := gdiMgr.GetRgnBox(ctx.Arg(0), &bounds)
		if p != 0 {
			ctx.Mem.Write32(p, uint32(bounds[0]))
			ctx.Mem.Write32(p+4, uint32(bounds[1]))
			ctx.Mem.Write32(p+8, uint32(bounds[2]))
			ctx.Mem.Write32(p+12, uint32(bounds[3]))
		}
		ctx.SetReturn(uint64(result))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SelectClipRgn", func(ctx *ntapi.TrapContext) uint32 {
		result := gdiMgr.SelectClipRgn(ctx.Arg(0), ctx.Arg(1))
		ctx.SetReturn(uint64(result))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "ExtSelectClipRgn", func(ctx *ntapi.TrapContext) uint32 {
		// mode arg(2): RGN_AND=1, RGN_OR=2, RGN_XOR=3, RGN_DIFF=4, RGN_COPY=5
		result := gdiMgr.SelectClipRgn(ctx.Arg(0), ctx.Arg(1))
		ctx.SetReturn(uint64(result))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "OffsetRgn", func(ctx *ntapi.TrapContext) uint32 {
		hRgn := ctx.Arg(0)
		xOffset := int32(ctx.Arg(1))
		yOffset := int32(ctx.Arg(2))
		rgn := gdiMgr.GetRegion(hRgn)
		if rgn != nil {
			rgn.X0 += xOffset
			rgn.Y0 += yOffset
			rgn.X1 += xOffset
			rgn.Y1 += yOffset
			ctx.SetReturn(1) // SIMPLEREGION
		} else {
			ctx.SetReturn(0) // ERROR
		}
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetClipRgn", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		hrgn := ctx.Arg(1)
		if dc.ClipRgnHandle != 0 && hrgn != 0 {
			// Copy clip region bounds to the destination hrgn
			if src := gdiMgr.GetRegion(dc.ClipRgnHandle); src != nil {
				gdiMgr.SetRectRgn(hrgn, src.X0, src.Y0, src.X1, src.Y1)
			}
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetClipBox", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		p := ctx.Arg(1)
		if p != 0 {
			// Return clip rect in client (non-origin-offset) coords
			l := dc.ClipX0 - dc.OriginX
			t := dc.ClipY0 - dc.OriginY
			r := dc.ClipX1 - dc.OriginX
			b := dc.ClipY1 - dc.OriginY
			if dc.ClipX1 == 0 && dc.ClipY1 == 0 {
				// No clip set - return DC extents
				if dc.Target != nil {
					r, b = dc.Target.Width, dc.Target.Height
				}
			}
			ctx.Mem.Write32(p, uint32(l))
			ctx.Mem.Write32(p+4, uint32(t))
			ctx.Mem.Write32(p+8, uint32(r))
			ctx.Mem.Write32(p+12, uint32(b))
		}
		ctx.SetReturn(2) // SIMPLEREGION
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "IntersectClipRect", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		l := int32(ctx.Arg(1)) + dc.OriginX
		t := int32(ctx.Arg(2)) + dc.OriginY
		r := int32(ctx.Arg(3)) + dc.OriginX
		b := int32(ctx.Arg(4)) + dc.OriginY
		if dc.ClipX1 > dc.ClipX0 {
			if l < dc.ClipX0 {
				l = dc.ClipX0
			}
			if t < dc.ClipY0 {
				t = dc.ClipY0
			}
			if r > dc.ClipX1 {
				r = dc.ClipX1
			}
			if b > dc.ClipY1 {
				b = dc.ClipY1
			}
		}
		dc.ClipX0, dc.ClipY0, dc.ClipX1, dc.ClipY1 = l, t, r, b
		if l >= r || t >= b {
			ctx.SetReturn(1) // NULLREGION
		} else {
			ctx.SetReturn(2) // SIMPLEREGION
		}
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "ExcludeClipRect", func(ctx *ntapi.TrapContext) uint32 {
		// ExcludeClipRect: subtract (left,top,right,bottom) from current clip.
		// Since our clip is always rectangular, we can only handle the case where
		// the exclusion covers a full edge of the current clip (shrink from one side).
		// Other cases fall back to SIMPLEREGION (clip unchanged).
		dc := getDC(ctx.Arg(0))
		el := int32(ctx.Arg(1)) + dc.OriginX
		et := int32(ctx.Arg(2)) + dc.OriginY
		er := int32(ctx.Arg(3)) + dc.OriginX
		eb := int32(ctx.Arg(4)) + dc.OriginY
		// Use full-surface clip if no clip set yet
		cl, ct, cr, cb := dc.ClipX0, dc.ClipY0, dc.ClipX1, dc.ClipY1
		if cl == 0 && cr == 0 && ct == 0 && cb == 0 {
			if dc.Target != nil {
				cr = dc.Target.Width
				cb = dc.Target.Height
			}
		}
		// Check if exclude rect covers a full edge → shrink clip
		if el <= cl && er >= cr { // full width
			if et <= ct {
				ct = eb
			} // top edge excluded
			if eb >= cb {
				cb = et
			} // bottom edge excluded
		} else if et <= ct && eb >= cb { // full height
			if el <= cl {
				cl = er
			} // left edge excluded
			if er >= cr {
				cr = el
			} // right edge excluded
		}
		if cl >= cr || ct >= cb {
			dc.ClipX0, dc.ClipY0, dc.ClipX1, dc.ClipY1 = 0, 0, 0, 0
			ctx.SetReturn(1) // NULLREGION
			return 0
		}
		dc.ClipX0, dc.ClipY0, dc.ClipX1, dc.ClipY1 = cl, ct, cr, cb
		ctx.SetReturn(2) // SIMPLEREGION
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "OffsetClipRgn", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(2) // SIMPLEREGION
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "PtInRegion", func(ctx *ntapi.TrapContext) uint32 {
		rgn := gdiMgr.GetRegion(ctx.Arg(0))
		x, y := int32(ctx.Arg(1)), int32(ctx.Arg(2))
		if rgn != nil && x >= rgn.X0 && x < rgn.X1 && y >= rgn.Y0 && y < rgn.Y1 {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "RectInRegion", func(ctx *ntapi.TrapContext) uint32 {
		rgn := gdiMgr.GetRegion(ctx.Arg(0))
		p := ctx.Arg(1)
		if rgn != nil && p != 0 {
			l, _ := mem.Read32(p)
			t, _ := mem.Read32(p + 4)
			r, _ := mem.Read32(p + 8)
			b, _ := mem.Read32(p + 12)
			if int32(r) > rgn.X0 && int32(l) < rgn.X1 && int32(b) > rgn.Y0 && int32(t) < rgn.Y1 {
				ctx.SetReturn(1)
				return 0
			}
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "FillRgn", func(ctx *ntapi.TrapContext) uint32 {
		if hctx.WlWindow == nil {
			ctx.SetReturn(1)
			return 0
		}
		dc := getDC(ctx.Arg(0))
		rgn := gdiMgr.GetRegion(ctx.Arg(1))
		hbr := ctx.Arg(2)
		color := gdiMgr.BrushColor(hbr, hctx.SysColors)
		if rgn != nil {
			dc.FillRect(rgn.X0, rgn.Y0, rgn.X1, rgn.Y1, color)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "FrameRgn", func(ctx *ntapi.TrapContext) uint32 {
		if hctx.WlWindow == nil {
			ctx.SetReturn(1)
			return 0
		}
		dc := getDC(ctx.Arg(0))
		rgn := gdiMgr.GetRegion(ctx.Arg(1))
		hbr := ctx.Arg(2)
		color := gdiMgr.BrushColor(hbr, hctx.SysColors)
		if rgn != nil {
			dc.DrawBorder(rgn.X0, rgn.Y0, rgn.X1, rgn.Y1, color)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "InvertRgn", func(ctx *ntapi.TrapContext) uint32 {
		if hctx.WlWindow == nil {
			ctx.SetReturn(1)
			return 0
		}
		dc := getDC(ctx.Arg(0))
		rgn := gdiMgr.GetRegion(ctx.Arg(1))
		if rgn != nil {
			dc.InvertRect(rgn.X0, rgn.Y0, rgn.X1, rgn.Y1)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "PaintRgn", func(ctx *ntapi.TrapContext) uint32 {
		if hctx.WlWindow == nil {
			ctx.SetReturn(1)
			return 0
		}
		dc := getDC(ctx.Arg(0))
		rgn := gdiMgr.GetRegion(ctx.Arg(1))
		if rgn != nil {
			dc.FillRectBrush(rgn.X0, rgn.Y0, rgn.X1, rgn.Y1)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "PathToRegion", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(gdiMgr.CreateRectRgn(0, 0, 0, 0))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EqualRgn", func(ctx *ntapi.TrapContext) uint32 {
		r1 := gdiMgr.GetRegion(ctx.Arg(0))
		r2 := gdiMgr.GetRegion(ctx.Arg(1))
		if r1 != nil && r2 != nil && r1.X0 == r2.X0 && r1.Y0 == r2.Y0 && r1.X1 == r2.X1 && r1.Y1 == r2.Y1 {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	// --- Window coord mapping ---
	d.RegisterAutoStubHandler(gdi32, "SetWindowOrgEx", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		p := ctx.Arg(3)
		if p != 0 {
			ctx.Mem.Write32(p, uint32(dc.WindowOrgX))
			ctx.Mem.Write32(p+4, uint32(dc.WindowOrgY))
		}
		dc.WindowOrgX = int32(ctx.Arg(1))
		dc.WindowOrgY = int32(ctx.Arg(2))
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetWindowOrgEx", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		p := ctx.Arg(1)
		if p != 0 {
			ctx.Mem.Write32(p, uint32(dc.WindowOrgX))
			ctx.Mem.Write32(p+4, uint32(dc.WindowOrgY))
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SetWindowExtEx", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		p := ctx.Arg(3)
		if p != 0 {
			ctx.Mem.Write32(p, uint32(dc.WindowExtX))
			ctx.Mem.Write32(p+4, uint32(dc.WindowExtY))
		}
		dc.WindowExtX = int32(ctx.Arg(1))
		dc.WindowExtY = int32(ctx.Arg(2))
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetWindowExtEx", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		p := ctx.Arg(1)
		if p != 0 {
			ex := dc.WindowExtX
			if ex == 0 {
				ex = 1
			}
			ey := dc.WindowExtY
			if ey == 0 {
				ey = 1
			}
			ctx.Mem.Write32(p, uint32(ex))
			ctx.Mem.Write32(p+4, uint32(ey))
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SetViewportExtEx", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		p := ctx.Arg(3)
		if p != 0 {
			ctx.Mem.Write32(p, uint32(dc.ViewportExtX))
			ctx.Mem.Write32(p+4, uint32(dc.ViewportExtY))
		}
		dc.ViewportExtX = int32(ctx.Arg(1))
		dc.ViewportExtY = int32(ctx.Arg(2))
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetViewportExtEx", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		p := ctx.Arg(1)
		if p != 0 {
			ex := dc.ViewportExtX
			if ex == 0 {
				ex = 1
			}
			ey := dc.ViewportExtY
			if ey == 0 {
				ey = 1
			}
			ctx.Mem.Write32(p, uint32(ex))
			ctx.Mem.Write32(p+4, uint32(ey))
		}
		ctx.SetReturn(1)
		return 0
	})
	// RectVisible: returns TRUE if any part of rect lies within the DC's clip region.
	// ReactOS: NtGdiRectVisible → GreRectVisible in win32ss/gdi/ntgdi/cliprgn.c
	d.RegisterAutoStubHandler(gdi32, "RectVisible", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		p := ctx.Arg(1)
		if p == 0 {
			ctx.SetReturn(1)
			return 0
		}
		rL, _ := mem.Read32(p)
		rT, _ := mem.Read32(p + 4)
		rR, _ := mem.Read32(p + 8)
		rB, _ := mem.Read32(p + 12)
		if int32(rR) <= int32(rL) || int32(rB) <= int32(rT) {
			ctx.SetReturn(0)
			return 0
		}
		// Convert logical (client) rect to screen (device) coords
		sl := int32(rL) + dc.OriginX
		st := int32(rT) + dc.OriginY
		sr := int32(rR) + dc.OriginX
		sb := int32(rB) + dc.OriginY
		// If clip not set, the whole surface is visible
		if dc.ClipX1 <= dc.ClipX0 && dc.ClipY1 <= dc.ClipY0 {
			ctx.SetReturn(1)
			return 0
		}
		// Check overlap
		if sr <= dc.ClipX0 || sl >= dc.ClipX1 || sb <= dc.ClipY0 || st >= dc.ClipY1 {
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "OffsetWindowOrgEx", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		p := ctx.Arg(3)
		if p != 0 {
			ctx.Mem.Write32(p, uint32(dc.WindowOrgX))
			ctx.Mem.Write32(p+4, uint32(dc.WindowOrgY))
		}
		dc.WindowOrgX += int32(ctx.Arg(1))
		dc.WindowOrgY += int32(ctx.Arg(2))
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SetBrushOrgEx", func(ctx *ntapi.TrapContext) uint32 {
		// Brush origin affects pattern fill alignment - no-op for solid brushes.
		p := ctx.Arg(3)
		if p != 0 {
			ctx.Mem.Write32(p, 0)
			ctx.Mem.Write32(p+4, 0)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "LPtoDP", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		pPts := ctx.Arg(1) // LPPOINT
		n := int(ctx.Arg(2))
		if pPts == 0 || n <= 0 {
			ctx.SetReturn(0)
			return 0
		}
		for i := 0; i < n; i++ {
			addr := pPts + uint64(i)*8
			px, _ := mem.Read32(addr)
			py, _ := mem.Read32(addr + 4)
			x, y := float64(int32(px)), float64(int32(py))
			// Apply world transform if GM_ADVANCED
			if dc.GraphicsMode == 2 {
				xf := xformToRaw(dc.WorldTransform)
				af := [6]float32{}
				for j := 0; j < 6; j++ {
					af[j] = math.Float32frombits(xf[j])
				}
				nx := x*float64(af[0]) + y*float64(af[2]) + float64(af[4])
				ny := x*float64(af[1]) + y*float64(af[3]) + float64(af[5])
				x, y = nx, ny
			}
			// Window → viewport scaling
			x -= float64(dc.WindowOrgX)
			y -= float64(dc.WindowOrgY)
			if dc.WindowExtX != 0 && dc.WindowExtY != 0 {
				x = x * float64(dc.ViewportExtX) / float64(dc.WindowExtX)
				y = y * float64(dc.ViewportExtY) / float64(dc.WindowExtY)
			}
			x += float64(dc.OriginX)
			y += float64(dc.OriginY)
			mem.Write32(addr, uint32(int32(math.Round(x))))
			mem.Write32(addr+4, uint32(int32(math.Round(y))))
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DPtoLP", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		pPts := ctx.Arg(1) // LPPOINT
		n := int(ctx.Arg(2))
		if pPts == 0 || n <= 0 {
			ctx.SetReturn(0)
			return 0
		}
		for i := 0; i < n; i++ {
			addr := pPts + uint64(i)*8
			px, _ := mem.Read32(addr)
			py, _ := mem.Read32(addr + 4)
			x, y := float64(int32(px)), float64(int32(py))
			// Reverse viewport origin
			x -= float64(dc.OriginX)
			y -= float64(dc.OriginY)
			// Reverse viewport → window scaling
			if dc.ViewportExtX != 0 && dc.ViewportExtY != 0 {
				x = x * float64(dc.WindowExtX) / float64(dc.ViewportExtX)
				y = y * float64(dc.WindowExtY) / float64(dc.ViewportExtY)
			}
			x += float64(dc.WindowOrgX)
			y += float64(dc.WindowOrgY)
			// Reverse world transform if GM_ADVANCED
			if dc.GraphicsMode == 2 {
				xf := xformToRaw(dc.WorldTransform)
				af := [6]float32{}
				for j := 0; j < 6; j++ {
					af[j] = math.Float32frombits(xf[j])
				}
				det := float64(af[0])*float64(af[3]) - float64(af[1])*float64(af[2])
				if det != 0 {
					px := x - float64(af[4])
					py := y - float64(af[5])
					x = (px*float64(af[3]) - py*float64(af[2])) / det
					y = (-px*float64(af[1]) + py*float64(af[0])) / det
				}
			}
			mem.Write32(addr, uint32(int32(math.Round(x))))
			mem.Write32(addr+4, uint32(int32(math.Round(y))))
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "ScaleWindowExtEx", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		xNum := int32(ctx.Arg(1))
		xDen := int32(ctx.Arg(2))
		yNum := int32(ctx.Arg(3))
		yDen := int32(ctx.Arg(4))
		pSize := ctx.Arg(5) // optional LPSIZE for previous extents
		if pSize != 0 {
			mem.Write32(pSize, uint32(dc.WindowExtX))
			mem.Write32(pSize+4, uint32(dc.WindowExtY))
		}
		if xDen != 0 && yDen != 0 {
			dc.WindowExtX = dc.WindowExtX * xNum / xDen
			dc.WindowExtY = dc.WindowExtY * yNum / yDen
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "ScaleViewportExtEx", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		xNum := int32(ctx.Arg(1))
		xDen := int32(ctx.Arg(2))
		yNum := int32(ctx.Arg(3))
		yDen := int32(ctx.Arg(4))
		pSize := ctx.Arg(5)
		if pSize != 0 {
			mem.Write32(pSize, uint32(dc.ViewportExtX))
			mem.Write32(pSize+4, uint32(dc.ViewportExtY))
		}
		if xDen != 0 && yDen != 0 {
			dc.ViewportExtX = dc.ViewportExtX * xNum / xDen
			dc.ViewportExtY = dc.ViewportExtY * yNum / yDen
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SetGraphicsMode", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		prev := dc.GraphicsMode
		if prev == 0 {
			prev = 1 // GM_COMPATIBLE
		}
		mode := int32(ctx.Arg(1))
		if mode == 1 || mode == 2 { // GM_COMPATIBLE or GM_ADVANCED
			dc.GraphicsMode = mode
		}
		ctx.SetReturn(uint64(prev))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetGraphicsMode", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		mode := dc.GraphicsMode
		if mode == 0 {
			mode = 1 // GM_COMPATIBLE
		}
		ctx.SetReturn(uint64(mode))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SetWorldTransform", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		if dc == nil || dc.GraphicsMode != 2 {
			ctx.SetReturn(0)
			return 0
		}
		p := ctx.Arg(1)
		if p != 0 {
			dc.WorldTransform = rawToXForm(readXformMem(ctx, p))
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetWorldTransform", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		xf := identityXform
		if dc != nil {
			xf = xformToRaw(dc.WorldTransform)
		}
		p := ctx.Arg(1)
		if p != 0 {
			writeXformMem(ctx, p, xf)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "ModifyWorldTransform", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: NtGdiModifyWorldTransform in win32ss/gdi/ntgdi/coord.c
		// iMode: MWT_IDENTITY=1, MWT_LEFTMULTIPLY=2, MWT_RIGHTMULTIPLY=3
		hdc := ctx.Arg(0)
		p := ctx.Arg(1)
		mode := ctx.Arg(2)
		dc := getDC(hdc)
		if dc == nil || dc.GraphicsMode != 2 {
			ctx.SetReturn(0)
			return 0
		}
		switch mode {
		case 1: // MWT_IDENTITY
			dc.WorldTransform = gdi.IdentityXForm()
		case 2: // MWT_LEFTMULTIPLY: result = pXform * current
			if p != 0 {
				newXf := readXformMem(ctx, p)
				dc.WorldTransform = rawToXForm(xformMul(newXf, xformToRaw(dc.WorldTransform)))
			}
		case 3: // MWT_RIGHTMULTIPLY: result = current * pXform
			if p != 0 {
				newXf := readXformMem(ctx, p)
				dc.WorldTransform = rawToXForm(xformMul(xformToRaw(dc.WorldTransform), newXf))
			}
		default:
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "CombineTransform", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: CombineTransform in win32ss/gdi/ntgdi/coord.c
		// CombineTransform(lpxformResult, lpxform1, lpxform2) - result = xform1 * xform2
		pOut := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		if pOut != 0 && p1 != 0 && p2 != 0 {
			xf1 := readXformMem(ctx, p1)
			xf2 := readXformMem(ctx, p2)
			writeXformMem(ctx, pOut, xformMul(xf1, xf2))
		}
		ctx.SetReturn(1)
		return 0
	})
	// --- CreatePolygonRgn ---
	// ReactOS: NtGdiCreatePolygonRgn in win32ss/gdi/ntgdi/region.c
	// Approximate as bounding-rect region (complex polygon clipping not needed).
	d.RegisterAutoStubHandler(gdi32, "CreatePolygonRgn", func(ctx *ntapi.TrapContext) uint32 {
		pPts := ctx.Arg(0)
		n := int(ctx.Arg(1))
		// arg2 = fill mode (ALTERNATE/WINDING) - ignored for bounding rect
		if pPts == 0 || n < 1 {
			ctx.SetReturn(0)
			return 0
		}
		var minX, minY, maxX, maxY int32
		for i := 0; i < n; i++ {
			px, _ := mem.Read32(pPts + uint64(i)*8)
			py, _ := mem.Read32(pPts + uint64(i)*8 + 4)
			x, y := int32(px), int32(py)
			if i == 0 {
				minX, minY, maxX, maxY = x, y, x, y
			} else {
				if x < minX {
					minX = x
				}
				if y < minY {
					minY = y
				}
				if x > maxX {
					maxX = x
				}
				if y > maxY {
					maxY = y
				}
			}
		}
		ctx.SetReturn(gdiMgr.CreateRectRgn(minX, minY, maxX, maxY))
		return 0
	})
	// --- SetPolyFillMode / GetPolyFillMode ---
	// ReactOS: NtGdiSetPolyFillMode / NtGdiGetPolyFillMode
	// ALTERNATE=1 (default), WINDING=2.
	d.RegisterAutoStubHandler(gdi32, "SetPolyFillMode", func(ctx *ntapi.TrapContext) uint32 {
		mode := int32(ctx.Arg(1))
		dc := getDC(ctx.Arg(0))
		prev := int32(1)
		if dc != nil && dc.PolyFillMode != 0 {
			prev = dc.PolyFillMode
		}
		if dc != nil && (mode == 1 || mode == 2) {
			dc.PolyFillMode = mode
		}
		ctx.SetReturn(uint64(uint32(prev)))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetPolyFillMode", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		mode := int32(1)
		if dc != nil && dc.PolyFillMode != 0 {
			mode = dc.PolyFillMode
		}
		ctx.SetReturn(uint64(uint32(mode)))
		return 0
	})
	// --- Text/font queries ---
	d.RegisterAutoStubHandler(gdi32, "GetTextFaceW", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		nCount := int(ctx.Arg(1))
		pFace := ctx.Arg(2)
		faceName := "Courier New"
		if dc.Font != nil && dc.Font.FaceName != "" {
			faceName = dc.Font.FaceName
		}
		if pFace != 0 && nCount > 0 {
			runes := []rune(faceName)
			n := len(runes)
			if n >= nCount {
				n = nCount - 1
			}
			for i := 0; i < n; i++ {
				ctx.Mem.Write16(pFace+uint64(i)*2, uint16(runes[i]))
			}
			ctx.Mem.Write16(pFace+uint64(n)*2, 0)
			ctx.SetReturn(uint64(n))
		} else {
			ctx.SetReturn(uint64(len([]rune(faceName)) + 1))
		}
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetCharWidth32W", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		first := int(ctx.Arg(1))
		last := int(ctx.Arg(2))
		pBuf := ctx.Arg(3)
		if last < first || last-first > 0xFFFF {
			ctx.SetReturn(0)
			return 0
		}
		dc := getDC(hdc)
		f := dc.Font
		if f == nil {
			f = gdi.DefaultFont()
		}
		pixSize := f.Height
		if pixSize < 0 {
			pixSize = -pixSize
		}
		if pixSize == 0 {
			pixSize = 12
		}
		if pBuf != 0 {
			for i := first; i <= last; i++ {
				charW := f.AveCharWidth
				if f.FaceID >= 0 {
					if g := gdi.GlyphFor(f.FaceID, pixSize, rune(i)); g != nil {
						charW = g.Advance
					}
				}
				ctx.Mem.Write32(pBuf+uint64(i-first)*4, uint32(charW))
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetCharWidthW", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		first := int(ctx.Arg(1))
		last := int(ctx.Arg(2))
		pBuf := ctx.Arg(3)
		if last < first || last-first > 0xFFFF {
			ctx.SetReturn(0)
			return 0
		}
		dc := getDC(hdc)
		f := dc.Font
		if f == nil {
			f = gdi.DefaultFont()
		}
		pixSize := f.Height
		if pixSize < 0 {
			pixSize = -pixSize
		}
		if pixSize == 0 {
			pixSize = 12
		}
		if pBuf != 0 {
			for i := first; i <= last; i++ {
				charW := f.AveCharWidth
				if f.FaceID >= 0 {
					if g := gdi.GlyphFor(f.FaceID, pixSize, rune(i)); g != nil {
						charW = g.Advance
					}
				}
				ctx.Mem.Write32(pBuf+uint64(i-first)*4, uint32(charW))
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetCharABCWidthsW", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		first := int(ctx.Arg(1))
		last := int(ctx.Arg(2))
		pBuf := ctx.Arg(3)
		if last < first || last-first > 0xFFFF {
			ctx.SetReturn(0)
			return 0
		}
		dc := getDC(hdc)
		f := dc.Font
		if f == nil {
			f = gdi.DefaultFont()
		}
		pixSize := f.Height
		if pixSize < 0 {
			pixSize = -pixSize
		}
		if pixSize == 0 {
			pixSize = 12
		}
		if pBuf != 0 {
			for i := first; i <= last; i++ {
				off := pBuf + uint64(i-first)*12
				charW := f.AveCharWidth
				if f.FaceID >= 0 {
					if g := gdi.GlyphFor(f.FaceID, pixSize, rune(i)); g != nil {
						charW = g.Advance
					}
				}
				ctx.Mem.Write32(off, 0)               // abcA (left bearing)
				ctx.Mem.Write32(off+4, uint32(charW)) // abcB (character width)
				ctx.Mem.Write32(off+8, 0)             // abcC (right bearing)
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetCharABCWidthsFloatW", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		first := int(ctx.Arg(1))
		last := int(ctx.Arg(2))
		pBuf := ctx.Arg(3) // LPABCFLOAT array
		if last < first || pBuf == 0 {
			ctx.SetReturn(0)
			return 0
		}
		dc := getDC(hdc)
		f := dc.Font
		if f == nil {
			f = gdi.DefaultFont()
		}
		pixSize := f.Height
		if pixSize < 0 {
			pixSize = -pixSize
		}
		if pixSize == 0 {
			pixSize = 12
		}
		for i := first; i <= last; i++ {
			base := pBuf + uint64(i-first)*12
			w := float32(f.AveCharWidth)
			if f.FaceID >= 0 {
				if g := gdi.GlyphFor(f.FaceID, pixSize, rune(i)); g != nil {
					w = float32(g.Advance)
				}
			}
			ctx.Mem.Write32(base, math.Float32bits(0))   // abcfA (left bearing)
			ctx.Mem.Write32(base+4, math.Float32bits(w)) // abcfB (char width)
			ctx.Mem.Write32(base+8, math.Float32bits(0)) // abcfC (right bearing)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetCharWidthFloatW", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		first := int(ctx.Arg(1))
		last := int(ctx.Arg(2))
		pBuf := ctx.Arg(3) // float array
		if last < first || pBuf == 0 {
			ctx.SetReturn(0)
			return 0
		}
		dc := getDC(hdc)
		f := dc.Font
		if f == nil {
			f = gdi.DefaultFont()
		}
		pixSize := f.Height
		if pixSize < 0 {
			pixSize = -pixSize
		}
		if pixSize == 0 {
			pixSize = 12
		}
		for i := first; i <= last; i++ {
			w := float32(f.AveCharWidth)
			if f.FaceID >= 0 {
				if g := gdi.GlyphFor(f.FaceID, pixSize, rune(i)); g != nil {
					w = float32(g.Advance)
				}
			}
			ctx.Mem.Write32(pBuf+uint64(i-first)*4, math.Float32bits(w))
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetGlyphIndicesW", func(ctx *ntapi.TrapContext) uint32 {
		// Copy input wchar indices as-is (identity mapping)
		pStr := ctx.Arg(1)
		n := int(ctx.Arg(2))
		pGI := ctx.Arg(3)
		flags := ctx.Arg(4)
		if pStr != 0 && pGI != 0 {
			for i := 0; i < n; i++ {
				ch, _ := mem.Read16(pStr + uint64(i)*2)
				gi := ch
				if flags == 1 && (ch < 0x20 || ch > 0x7E) {
					gi = 0xFFFF
				}
				ctx.Mem.Write16(pGI+uint64(i)*2, gi)
			}
		}
		ctx.SetReturn(uint64(n))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetKerningPairsW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // no kerning pairs
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetOutlineTextMetricsW", func(ctx *ntapi.TrapContext) uint32 {
		// OUTLINETEXTMETRICW is ~276 bytes. Return size=276, fill TEXTMETRICW at offset 4.
		cb := ctx.Arg(1)
		pOTM := ctx.Arg(2)
		const otmSize = 276
		if cb == 0 || pOTM == 0 {
			ctx.SetReturn(otmSize)
			return 0
		}
		if cb < otmSize {
			ctx.SetReturn(0)
			return 0
		}
		dc := getDC(ctx.Arg(0))
		f := dc.Font
		if f == nil {
			f = gdi.DefaultFont()
		}
		// Zero the struct
		for i := uint64(0); i < otmSize; i++ {
			ctx.Mem.Write8(pOTM+i, 0)
		}
		ctx.Mem.Write32(pOTM, otmSize) // otmSize
		// TEXTMETRICW at pOTM+4 (60 bytes)
		tm := pOTM + 4
		ch := int32(f.CellHeight)
		ctx.Mem.Write32(tm, uint32(ch))                  // tmHeight
		ctx.Mem.Write32(tm+4, uint32(f.Ascent))          // tmAscent
		ctx.Mem.Write32(tm+8, uint32(ch-f.Ascent))       // tmDescent
		ctx.Mem.Write32(tm+12, 0)                        // tmInternalLeading
		ctx.Mem.Write32(tm+16, 2)                        // tmExternalLeading
		ctx.Mem.Write32(tm+20, uint32(f.AveCharWidth))   // tmAveCharWidth
		ctx.Mem.Write32(tm+24, uint32(f.AveCharWidth)*2) // tmMaxCharWidth
		ctx.Mem.Write32(tm+28, uint32(f.Weight))         // tmWeight
		ctx.Mem.Write32(tm+32, 0)                        // tmOverhang
		ctx.Mem.Write32(tm+36, 96)                       // tmDigitizedAspectX
		ctx.Mem.Write32(tm+40, 96)                       // tmDigitizedAspectY
		// TEXTMETRICW char fields (WCHAR, 2 bytes each) and BYTE fields
		italic := byte(0)
		if f.Italic {
			italic = 1
		}
		ctx.Mem.Write16(tm+44, 0x0020) // tmFirstChar
		ctx.Mem.Write16(tm+46, 0x00FF) // tmLastChar
		ctx.Mem.Write16(tm+48, 0x003F) // tmDefaultChar '?'
		ctx.Mem.Write16(tm+50, 0x0020) // tmBreakChar ' '
		ctx.Mem.Write8(tm+52, italic)  // tmItalic
		ctx.Mem.Write8(tm+53, 0)       // tmUnderlined
		ctx.Mem.Write8(tm+54, 0)       // tmStruckOut
		ctx.Mem.Write8(tm+55, 1|32)    // tmPitchAndFamily = TMPF_FIXED_PITCH|TMPF_TRUETYPE
		ctx.Mem.Write8(tm+56, 0)       // tmCharSet = ANSI_CHARSET
		// OUTLINETEXTMETRICW fields: pOTM+4(TEXTMETRICW,60)+otmFiller(1)+PANOSE(10)+pad(1)=pOTM+76
		ctx.Mem.Write32(pOTM+96, 2048)                       // otmEMSquare
		ctx.Mem.Write32(pOTM+100, uint32(f.Ascent))          // otmAscent
		ctx.Mem.Write32(pOTM+104, uint32(-int32(f.Descent))) // otmDescent (negative)
		ctx.Mem.Write32(pOTM+108, 0)                         // otmLineGap
		ctx.Mem.Write32(pOTM+112, uint32(f.Ascent))          // otmsCapEmHeight
		ctx.Mem.Write32(pOTM+116, uint32(f.Ascent*2/3))      // otmsXHeight
		// RECT otmrcFontBox at pOTM+120
		ctx.Mem.Write32(pOTM+120, 0)
		ctx.Mem.Write32(pOTM+124, uint32(-int32(f.Descent)))
		ctx.Mem.Write32(pOTM+128, uint32(f.AveCharWidth))
		ctx.Mem.Write32(pOTM+132, uint32(f.Ascent))
		ctx.SetReturn(otmSize)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetFontData", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0xFFFFFFFF) // GDI_ERROR - no font data
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetGlyphOutlineW", func(ctx *ntapi.TrapContext) uint32 {
		// Return 1 for GGO_METRICS, fill GLYPHMETRICS if provided
		pGM := ctx.Arg(5)
		if pGM != 0 {
			dc := getDC(ctx.Arg(0))
			f := dc.Font
			if f == nil {
				f = gdi.DefaultFont()
			}
			ctx.Mem.Write32(pGM, uint32(f.AveCharWidth))    // gmBlackBoxX
			ctx.Mem.Write32(pGM+4, uint32(f.CellHeight))    // gmBlackBoxY
			ctx.Mem.Write32(pGM+8, 0)                       // gmptGlyphOrigin.x
			ctx.Mem.Write32(pGM+12, uint32(f.Ascent))       // gmptGlyphOrigin.y
			ctx.Mem.Write16(pGM+16, uint16(f.AveCharWidth)) // gmCellIncX
			ctx.Mem.Write16(pGM+18, 0)                      // gmCellIncY
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EnumFontFamiliesExW", func(ctx *ntapi.TrapContext) uint32 {
		lpLogfont := ctx.Arg(1) // LOGFONTW* (0 = enumerate all)
		lpProc := ctx.Arg(2)    // FONTENUMPROCW callback
		enumLParam := ctx.Arg(3)

		if lpProc == 0 {
			ctx.SetReturn(1)
			return 0
		}

		// Optionally filter by requested face name (lfFaceName at LOGFONTW+28).
		filterName := ""
		if lpLogfont != 0 {
			filterName = strings.ToLower(strings.TrimSpace(readGuestUTF16(lpLogfont + 28)))
		}

		faces := gdi.ListFaces()
		if len(faces) == 0 {
			ctx.SetReturn(1)
			return 0
		}

		if filterName != "" && filterName != "@" {
			var filtered []gdi.FaceInfo
			for _, f := range faces {
				if strings.ToLower(f.FamilyName) == filterName {
					filtered = append(filtered, f)
				}
			}
			if len(filtered) > 0 {
				faces = filtered
			}
		}

		rw, okW := ctx.CPU.(ntapi.RegisterWriter)
		rr, okR := ctx.CPU.(ntapi.RegisterReader)
		if !okW || !okR {
			ctx.SetReturn(1)
			return 0
		}

		// ENUMLOGFONTEXW = 348 bytes (padded to 352), NEWTEXTMETRICEXW = 100 bytes (padded to 104).
		const elfSize = uint64(352)
		const ntmSize = uint64(104)
		const perFace = elfSize + ntmSize

		numFaces := uint64(len(faces))
		buf := sharedHeapAlloc(numFaces*perFace, true)
		if buf == 0 {
			ctx.SetReturn(1)
			return 0
		}

		// writeUTF16 writes a null-padded UTF-16LE string to guest memory.
		writeUTF16 := func(addr uint64, s string, maxWchars int) {
			ws := utf16Encode(s)
			for i := 0; i < maxWchars; i++ {
				if i < len(ws) {
					ctx.Mem.Write16(addr+uint64(i)*2, ws[i])
				} else {
					ctx.Mem.Write16(addr+uint64(i)*2, 0)
				}
			}
		}

		queue := make([]syncDispatch, 0, numFaces)
		for i, fi := range faces {
			elfePtr := buf + uint64(i)*perFace
			ntmPtr := elfePtr + elfSize

			cellH, asc, desc, aveW := gdi.FaceMetrics(fi.ID, 12)

			// LOGFONTW (92 bytes) at elfePtr+0
			ctx.Mem.Write32(elfePtr+0, uint32(cellH))
			ctx.Mem.Write32(elfePtr+4, 0)
			ctx.Mem.Write32(elfePtr+8, 0)
			ctx.Mem.Write32(elfePtr+12, 0)
			ctx.Mem.Write32(elfePtr+16, 400) // lfWeight = FW_NORMAL
			ctx.Mem.Write8(elfePtr+20, 0)
			ctx.Mem.Write8(elfePtr+21, 0)
			ctx.Mem.Write8(elfePtr+22, 0)
			ctx.Mem.Write8(elfePtr+23, 0) // lfCharSet = ANSI_CHARSET
			ctx.Mem.Write8(elfePtr+24, 4) // lfOutPrecision = OUT_TT_PRECIS
			ctx.Mem.Write8(elfePtr+25, 0)
			ctx.Mem.Write8(elfePtr+26, 0)
			ctx.Mem.Write8(elfePtr+27, 0x31)          // lfPitchAndFamily = FIXED_PITCH|FF_MODERN
			writeUTF16(elfePtr+28, fi.FamilyName, 32) // lfFaceName
			// elfFullName at +92, elfStyle at +220, elfScript at +284
			writeUTF16(elfePtr+92, fi.FamilyName, 64)
			writeUTF16(elfePtr+220, "Regular", 32)
			writeUTF16(elfePtr+284, "Western", 32)

			// NEWTEXTMETRICW (76 bytes) at ntmPtr
			ctx.Mem.Write32(ntmPtr+0, uint32(cellH))
			ctx.Mem.Write32(ntmPtr+4, uint32(asc))
			ctx.Mem.Write32(ntmPtr+8, uint32(desc))
			ctx.Mem.Write32(ntmPtr+12, 0)
			ctx.Mem.Write32(ntmPtr+16, 0)
			ctx.Mem.Write32(ntmPtr+20, uint32(aveW))
			ctx.Mem.Write32(ntmPtr+24, uint32(aveW*2))
			ctx.Mem.Write32(ntmPtr+28, 400) // tmWeight
			ctx.Mem.Write32(ntmPtr+32, 0)
			ctx.Mem.Write32(ntmPtr+36, 96)     // tmDigitizedAspectX
			ctx.Mem.Write32(ntmPtr+40, 96)     // tmDigitizedAspectY
			ctx.Mem.Write16(ntmPtr+44, 0x0020) // tmFirstChar
			ctx.Mem.Write16(ntmPtr+46, 0x00FF) // tmLastChar
			ctx.Mem.Write16(ntmPtr+48, 0x003F) // tmDefaultChar '?'
			ctx.Mem.Write16(ntmPtr+50, 0x0020) // tmBreakChar ' '
			ctx.Mem.Write8(ntmPtr+52, 0)
			ctx.Mem.Write8(ntmPtr+53, 0)
			ctx.Mem.Write8(ntmPtr+54, 0)
			ctx.Mem.Write8(ntmPtr+55, 0x31) // tmPitchAndFamily
			ctx.Mem.Write8(ntmPtr+56, 0)    // tmCharSet = ANSI_CHARSET
			// ntmFlags/ntmSizeEM/ntmCellHeight/ntmAvgWidth at +60
			ctx.Mem.Write32(ntmPtr+60, 0)
			ctx.Mem.Write32(ntmPtr+64, 2048)          // ntmSizeEM
			ctx.Mem.Write32(ntmPtr+68, uint32(cellH)) // ntmCellHeight
			ctx.Mem.Write32(ntmPtr+72, uint32(aveW))  // ntmAvgWidth
			// FONTSIGNATURE at +76 (24 bytes)
			ctx.Mem.Write32(ntmPtr+76, 0x00000001) // fsUsb[0] Basic Latin
			ctx.Mem.Write32(ntmPtr+80, 0)
			ctx.Mem.Write32(ntmPtr+84, 0)
			ctx.Mem.Write32(ntmPtr+88, 0)
			ctx.Mem.Write32(ntmPtr+92, 0x00000001) // fsCsb[0] Latin1/ANSI
			ctx.Mem.Write32(ntmPtr+96, 0)

			queue = append(queue, syncDispatch{
				wndProc: lpProc,
				hwnd:    elfePtr,    // RCX = ENUMLOGFONTEXW*
				msg:     ntmPtr,     // RDX = NEWTEXTMETRICEXW*
				wParam:  4,          // R8 = TRUETYPE_FONTTYPE
				lParam:  enumLParam, // R9 = caller's lParam
			})
			_ = asc
			_ = desc
		}

		first := queue[0]
		rest := queue[1:]

		rsp := rr.ReadReg(4)
		retAddr, _ := mem.Read64(rsp)
		hctx.SyncStack = append(hctx.SyncStack, syncDispatchFrame{
			queue:               rest,
			retAddr:             retAddr,
			hwnd:                1, // fallback return value
			returnWndProcResult: true,
		})
		mem.Write64(rsp, hctx.SyncTrampoline)

		rw.WriteReg(1, first.hwnd)
		rw.WriteReg(2, first.msg)
		rw.WriteReg(8, first.wParam)
		rw.WriteReg(9, first.lParam)
		ctx.CPU.SetPC(first.wndProc)
		ctx.ReturnOverridden = true
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EnumFontsW", func(ctx *ntapi.TrapContext) uint32 {
		// EnumFontsW(hdc, lpFaceName, lpProc, lParam)
		// Callback: int CALLBACK(LOGFONTW*, TEXTMETRICW*, DWORD fontType, LPARAM)
		lpProc := ctx.Arg(2)
		enumLParam := ctx.Arg(3)
		if lpProc == 0 {
			ctx.SetReturn(1)
			return 0
		}
		faces := gdi.ListFaces()
		if len(faces) == 0 {
			ctx.SetReturn(1)
			return 0
		}

		rw, okW := ctx.CPU.(ntapi.RegisterWriter)
		rr, okR := ctx.CPU.(ntapi.RegisterReader)
		if !okW || !okR {
			ctx.SetReturn(1)
			return 0
		}

		const lfSz = uint64(92) // LOGFONTW
		const tmSz = uint64(60) // TEXTMETRICW
		const perFace = lfSz + tmSz
		numFaces := uint64(len(faces))
		buf := sharedHeapAlloc(numFaces*perFace, true)
		if buf == 0 {
			ctx.SetReturn(1)
			return 0
		}

		writeUTF16 := func(addr uint64, s string, maxWchars int) {
			ws := utf16Encode(s)
			for i := 0; i < maxWchars; i++ {
				if i < len(ws) {
					ctx.Mem.Write16(addr+uint64(i)*2, ws[i])
				} else {
					ctx.Mem.Write16(addr+uint64(i)*2, 0)
				}
			}
		}

		queue := make([]syncDispatch, 0, numFaces)
		for i, fi := range faces {
			lfPtr := buf + uint64(i)*perFace
			tmPtr := lfPtr + lfSz

			cellH, asc, desc, aveW := gdi.FaceMetrics(fi.ID, 12)
			if cellH == 0 {
				cellH = 16
				asc = 13
				desc = 3
				aveW = 8
			}

			// LOGFONTW (92 bytes)
			ctx.Mem.Write32(lfPtr+0, uint32(cellH))
			ctx.Mem.Write32(lfPtr+4, 0)
			ctx.Mem.Write32(lfPtr+8, 0)
			ctx.Mem.Write32(lfPtr+12, 0)
			ctx.Mem.Write32(lfPtr+16, 400) // lfWeight = FW_NORMAL
			ctx.Mem.Write8(lfPtr+20, 0)
			ctx.Mem.Write8(lfPtr+21, 0)
			ctx.Mem.Write8(lfPtr+22, 0)
			ctx.Mem.Write8(lfPtr+23, 0) // ANSI_CHARSET
			ctx.Mem.Write8(lfPtr+24, 4) // OUT_TT_PRECIS
			ctx.Mem.Write8(lfPtr+25, 0)
			ctx.Mem.Write8(lfPtr+26, 0)
			ctx.Mem.Write8(lfPtr+27, 0x31) // FIXED_PITCH|FF_MODERN
			writeUTF16(lfPtr+28, fi.FamilyName, 32)

			// TEXTMETRICW (60 bytes)
			ctx.Mem.Write32(tmPtr+0, uint32(cellH))
			ctx.Mem.Write32(tmPtr+4, uint32(asc))
			ctx.Mem.Write32(tmPtr+8, uint32(desc))
			ctx.Mem.Write32(tmPtr+12, 0)
			ctx.Mem.Write32(tmPtr+16, 0)
			ctx.Mem.Write32(tmPtr+20, uint32(aveW))
			ctx.Mem.Write32(tmPtr+24, uint32(aveW*2))
			ctx.Mem.Write32(tmPtr+28, 400) // tmWeight
			ctx.Mem.Write32(tmPtr+32, 0)
			ctx.Mem.Write32(tmPtr+36, 96)
			ctx.Mem.Write32(tmPtr+40, 96)
			ctx.Mem.Write16(tmPtr+44, 0x0020)
			ctx.Mem.Write16(tmPtr+46, 0x00FF)
			ctx.Mem.Write16(tmPtr+48, 0x003F)
			ctx.Mem.Write16(tmPtr+50, 0x0020)
			ctx.Mem.Write8(tmPtr+52, 0)
			ctx.Mem.Write8(tmPtr+53, 0)
			ctx.Mem.Write8(tmPtr+54, 0)
			ctx.Mem.Write8(tmPtr+55, 0x31) // tmPitchAndFamily
			ctx.Mem.Write8(tmPtr+56, 0)    // ANSI_CHARSET

			queue = append(queue, syncDispatch{
				wndProc: lpProc,
				hwnd:    lfPtr, // RCX = LOGFONTW*
				msg:     tmPtr, // RDX = TEXTMETRICW*
				wParam:  4,     // R8 = TRUETYPE_FONTTYPE
				lParam:  enumLParam,
			})
			_ = asc
			_ = desc
		}

		first := queue[0]
		rest := queue[1:]

		rsp := rr.ReadReg(4)
		retAddr, _ := mem.Read64(rsp)
		hctx.SyncStack = append(hctx.SyncStack, syncDispatchFrame{
			queue:               rest,
			retAddr:             retAddr,
			hwnd:                1,
			returnWndProcResult: true,
		})
		mem.Write64(rsp, hctx.SyncTrampoline)

		rw.WriteReg(1, first.hwnd)
		rw.WriteReg(2, first.msg)
		rw.WriteReg(8, first.wParam)
		rw.WriteReg(9, first.lParam)
		ctx.CPU.SetPC(first.wndProc)
		ctx.ReturnOverridden = true
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "AddFontMemResourceEx", func(ctx *ntapi.TrapContext) uint32 {
		pbFont := ctx.Arg(0)
		cbFont := ctx.Arg(1)
		pNumFonts := ctx.Arg(3)

		if pbFont == 0 || cbFont == 0 || cbFont > 64*1024*1024 {
			if pNumFonts != 0 {
				ctx.Mem.Write32(pNumFonts, 0)
			}
			ctx.SetReturn(0)
			return 0
		}
		data, err := ctx.Mem.ReadBytes(pbFont, int(cbFont))
		if err != nil {
			if pNumFonts != 0 {
				ctx.Mem.Write32(pNumFonts, 0)
			}
			ctx.SetReturn(0)
			return 0
		}
		id := gdi.AddFontFromBytes("embedded-font", data)
		if id < 0 {
			if pNumFonts != 0 {
				ctx.Mem.Write32(pNumFonts, 0)
			}
			ctx.SetReturn(0)
			return 0
		}
		ravelog.Logf("[gdi] AddFontMemResourceEx loaded faceID=%d size=%d\n", id, cbFont)
		if pNumFonts != 0 {
			ctx.Mem.Write32(pNumFonts, 1)
		}
		ctx.SetReturn(uint64(0x12340000 + uint32(id+1)))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "RemoveFontMemResourceEx", func(ctx *ntapi.TrapContext) uint32 {
		h := ctx.Arg(0)
		if gdiMgr.RemoveFontMemResource(h) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "AddFontResourceW", func(ctx *ntapi.TrapContext) uint32 {
		path := readGuestUTF16(ctx.Arg(0))
		n := gdiMgr.AddFontResource(path)
		ctx.SetReturn(uint64(n))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "AddFontResourceExW", func(ctx *ntapi.TrapContext) uint32 {
		path := readGuestUTF16(ctx.Arg(0))
		// arg1 = flags (FR_PRIVATE, FR_NOT_ENUM), arg2 = reserved
		n := gdiMgr.AddFontResource(path)
		ctx.SetReturn(uint64(n))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "RemoveFontResourceW", func(ctx *ntapi.TrapContext) uint32 {
		path := readGuestUTF16(ctx.Arg(0))
		if gdiMgr.RemoveFontResource(path) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "RemoveFontResourceExW", func(ctx *ntapi.TrapContext) uint32 {
		path := readGuestUTF16(ctx.Arg(0))
		// arg1 = flags, arg2 = reserved
		if gdiMgr.RemoveFontResource(path) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "CreateFontIndirectExW", func(ctx *ntapi.TrapContext) uint32 {
		// ENUMLOGFONTEXDVW - first field is ENUMLOGFONTEXW, which starts with LOGFONTW
		lf := ctx.Arg(0)
		f := &gdi.Font{}
		if lf != 0 {
			v32, _ := mem.Read32(lf)
			f.Height = int32(v32)
			v32, _ = mem.Read32(lf + 4)
			f.Width = int32(v32)
			v32, _ = mem.Read32(lf + 16)
			f.Weight = int32(v32)
			v8, _ := mem.Read8(lf + 20)
			f.Italic = v8 != 0
			v8, _ = mem.Read8(lf + 21)
			f.Underline = v8 != 0
			v8, _ = mem.Read8(lf + 23)
			f.CharSet = v8
			f.FaceName = readGuestUTF16(lf + 28)
		}
		ctx.SetReturn(gdiMgr.CreateFont(f))
		return 0
	})
	// --- Pen/Brush extras ---
	d.RegisterAutoStubHandler(gdi32, "CreatePenIndirect", func(ctx *ntapi.TrapContext) uint32 {
		// LOGPEN: {lopnStyle:UINT(+0), lopnWidth:POINT(+4,+8), lopnColor:COLORREF(+12)}
		p := ctx.Arg(0)
		style, width, color := int32(0), int32(1), uint32(0)
		if p != 0 {
			v, _ := mem.Read32(p)
			style = int32(v)
			v, _ = mem.Read32(p + 4)
			width = int32(v)
			v, _ = mem.Read32(p + 12)
			color = v
		}
		ctx.SetReturn(gdiMgr.CreatePen(style, width, color))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "ExtCreatePen", func(ctx *ntapi.TrapContext) uint32 {
		style := uint32(ctx.Arg(0))
		width := int32(ctx.Arg(1))
		pLB := ctx.Arg(2)
		color := uint32(0)
		if pLB != 0 {
			v, _ := mem.Read32(pLB + 4)
			color = v
		}
		penStyle := int32(style & 0x0F)
		ctx.SetReturn(gdiMgr.CreatePen(penStyle, width, color))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "CreateBrushIndirect", func(ctx *ntapi.TrapContext) uint32 {
		p := ctx.Arg(0)
		style, color := int32(0), uint32(0)
		if p != 0 {
			v, _ := mem.Read32(p)
			style = int32(v)
			v, _ = mem.Read32(p + 4)
			color = v
		}
		if style == 1 { // BS_HOLLOW/BS_NULL
			ctx.SetReturn(gdiMgr.GetStockObject(gdi.StockNullBrush))
		} else {
			ctx.SetReturn(gdiMgr.CreateSolidBrush(color))
		}
		return 0
	})
	// --- Bitmap extras ---
	d.RegisterAutoStubHandler(gdi32, "CreateBitmap", func(ctx *ntapi.TrapContext) uint32 {
		w := int32(ctx.Arg(0))
		h := int32(ctx.Arg(1))
		ctx.SetReturn(gdiMgr.CreateCompatibleBitmap(w, h))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "CreateBitmapIndirect", func(ctx *ntapi.TrapContext) uint32 {
		p := ctx.Arg(0)
		w, h := int32(0), int32(0)
		if p != 0 {
			v, _ := mem.Read32(p + 4)
			w = int32(v)
			v, _ = mem.Read32(p + 8)
			h = int32(v)
		}
		ctx.SetReturn(gdiMgr.CreateCompatibleBitmap(w, h))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetBitmapBits", func(ctx *ntapi.TrapContext) uint32 {
		// GetBitmapBits(hbm, cb, lpvBits) - 24bpp BGR rows, 4-byte aligned
		hbm := ctx.Arg(0)
		cb := int(ctx.Arg(1))
		pBits := ctx.Arg(2)
		obj := gdiMgr.GetObject(hbm)
		if obj == nil || obj.Bitmap == nil || obj.Bitmap.Surf == nil || pBits == 0 {
			ctx.SetReturn(0)
			return 0
		}
		bm := obj.Bitmap
		stride := gdi.DIBStride(bm.Width, 24)
		rows := cb / int(stride)
		if rows <= 0 {
			ctx.SetReturn(0)
			return 0
		}
		buf := make([]byte, rows*int(stride))
		gdi.WriteDIBFromSurface(buf, bm.Surf, 0, 0, bm.Width, int32(rows), 24)
		n := rows * int(stride)
		for i := 0; i < n; i++ {
			ctx.Mem.Write8(pBits+uint64(i), buf[i])
		}
		ctx.SetReturn(uint64(n))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SetBitmapBits", func(ctx *ntapi.TrapContext) uint32 {
		// SetBitmapBits(hbm, cb, lpvBits) - 24bpp BGR rows, 4-byte aligned
		hbm := ctx.Arg(0)
		cb := int(ctx.Arg(1))
		pBits := ctx.Arg(2)
		obj := gdiMgr.GetObject(hbm)
		if obj == nil || obj.Bitmap == nil || obj.Bitmap.Surf == nil || pBits == 0 {
			ctx.SetReturn(0)
			return 0
		}
		bm := obj.Bitmap
		stride := gdi.DIBStride(bm.Width, 24)
		if stride == 0 {
			ctx.SetReturn(0)
			return 0
		}
		rows := cb / int(stride)
		if rows <= 0 {
			ctx.SetReturn(0)
			return 0
		}
		buf := make([]byte, cb)
		for i := 0; i < cb; i++ {
			buf[i], _ = ctx.Mem.Read8(pBits + uint64(i))
		}
		// Write 24bpp bottom-up into surface (flip)
		for row := 0; row < rows; row++ {
			srcRow := (rows - 1 - row) // bottom-up
			sy := srcRow
			for col := int32(0); col < bm.Width && col < int32(int(stride/3)); col++ {
				off := row*int(stride) + int(col)*3
				b := buf[off]
				g := buf[off+1]
				r := buf[off+2]
				bm.Surf.SetPixel(col, int32(sy), uint32(r)<<16|uint32(g)<<8|uint32(b))
			}
		}
		ctx.SetReturn(uint64(rows * int(stride)))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetBitmapDimensionEx", func(ctx *ntapi.TrapContext) uint32 {
		p := ctx.Arg(2)
		if p != 0 {
			ctx.Mem.Write32(p, 0)
			ctx.Mem.Write32(p+4, 0)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SetBitmapDimensionEx", func(ctx *ntapi.TrapContext) uint32 {
		// SetBitmapDimensionEx(hbm, w, h, lpSize) - stores preferred dimensions (rarely used).
		// ReactOS: NtGdiSetBitmapDimension - sets szlBitmap on the bitmap object.
		hbm := ctx.Arg(0)
		_ = hbm // dimensions are cosmetic; we track nothing extra
		pSize := ctx.Arg(3)
		if pSize != 0 {
			// Return previous dimensions (0,0 since we don't track them)
			ctx.Mem.Write32(pSize, 0)
			ctx.Mem.Write32(pSize+4, 0)
		}
		ctx.SetReturn(1)
		return 0
	})
	// --- Drawing extras ---
	d.RegisterAutoStubHandler(gdi32, "RoundRect", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		dc.RoundRect(int32(ctx.Arg(1)), int32(ctx.Arg(2)), int32(ctx.Arg(3)), int32(ctx.Arg(4)), int32(ctx.Arg(5)), int32(ctx.Arg(6)))
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SetPixel", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		dc.SetPixel(int32(ctx.Arg(1)), int32(ctx.Arg(2)), uint32(ctx.Arg(3)))
		ctx.SetReturn(ctx.Arg(3))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetPixel", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		c := dc.GetPixel(int32(ctx.Arg(1)), int32(ctx.Arg(2)))
		ctx.SetReturn(uint64(c))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DrawEdge", func(ctx *ntapi.TrapContext) uint32 {
		if hctx.WlWindow == nil {
			ctx.SetReturn(1)
			return 0
		}
		dc := getDC(ctx.Arg(0))
		pRect := ctx.Arg(1)
		edge := uint32(ctx.Arg(2))
		flags := uint32(ctx.Arg(3))
		if pRect != 0 {
			l, _ := mem.Read32(pRect)
			t, _ := mem.Read32(pRect + 4)
			r, _ := mem.Read32(pRect + 8)
			b, _ := mem.Read32(pRect + 12)
			dc.DrawEdge(int32(l), int32(t), int32(r), int32(b), edge, flags, hctx.SysColors)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DrawFrameControl", func(ctx *ntapi.TrapContext) uint32 {
		if hctx.WlWindow == nil {
			ctx.SetReturn(1)
			return 0
		}
		dc := getDC(ctx.Arg(0))
		pRect := ctx.Arg(1)
		uType := uint32(ctx.Arg(2))
		uState := uint32(ctx.Arg(3))
		if pRect != 0 {
			l, _ := mem.Read32(pRect)
			t, _ := mem.Read32(pRect + 4)
			r, _ := mem.Read32(pRect + 8)
			b, _ := mem.Read32(pRect + 12)
			dc.DrawFrameControl(int32(l), int32(t), int32(r), int32(b), uType, uState, hctx.SysColors)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DrawFocusRect", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		pRect := ctx.Arg(1)
		if pRect != 0 {
			l, _ := mem.Read32(pRect)
			t, _ := mem.Read32(pRect + 4)
			r, _ := mem.Read32(pRect + 8)
			b, _ := mem.Read32(pRect + 12)
			dc.DrawFocusRect(int32(l), int32(t), int32(r), int32(b))
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "InvertRect", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		pRect := ctx.Arg(1)
		if pRect != 0 {
			l, _ := mem.Read32(pRect)
			t, _ := mem.Read32(pRect + 4)
			r, _ := mem.Read32(pRect + 8)
			b, _ := mem.Read32(pRect + 12)
			dc.InvertRect(int32(l), int32(t), int32(r), int32(b))
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "Polygon", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		pPts := ctx.Arg(1)
		n := int(ctx.Arg(2))
		pts := make([][2]int32, n)
		for i := 0; i < n; i++ {
			x, _ := mem.Read32(pPts + uint64(i)*8)
			y, _ := mem.Read32(pPts + uint64(i)*8 + 4)
			pts[i] = [2]int32{int32(x), int32(y)}
		}
		dc.Polygon(pts)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "Polyline", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		pPts := ctx.Arg(1)
		n := int(ctx.Arg(2))
		pts := make([][2]int32, n)
		for i := 0; i < n; i++ {
			x, _ := mem.Read32(pPts + uint64(i)*8)
			y, _ := mem.Read32(pPts + uint64(i)*8 + 4)
			pts[i] = [2]int32{int32(x), int32(y)}
		}
		dc.PolylinePoints(pts)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "PolylineTo", func(ctx *ntapi.TrapContext) uint32 {
		if hctx.WlWindow == nil {
			ctx.SetReturn(1)
			return 0
		}
		dc := getDC(ctx.Arg(0))
		pPts := ctx.Arg(1)
		n := int(ctx.Arg(2))
		for i := 0; i < n; i++ {
			x, _ := mem.Read32(pPts + uint64(i)*8)
			y, _ := mem.Read32(pPts + uint64(i)*8 + 4)
			dc.LineTo(int32(x), int32(y))
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "PolyBezier", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		pPts := ctx.Arg(1)
		n := int(ctx.Arg(2))
		pts := make([][2]int32, n)
		for i := 0; i < n; i++ {
			x, _ := mem.Read32(pPts + uint64(i)*8)
			y, _ := mem.Read32(pPts + uint64(i)*8 + 4)
			pts[i] = [2]int32{int32(x), int32(y)}
		}
		dc.PolyBezier(pts)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "PolyBezierTo", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		pPts := ctx.Arg(1)
		n := int(ctx.Arg(2))
		pts := make([][2]int32, n)
		for i := 0; i < n; i++ {
			x, _ := mem.Read32(pPts + uint64(i)*8)
			y, _ := mem.Read32(pPts + uint64(i)*8 + 4)
			pts[i] = [2]int32{int32(x), int32(y)}
		}
		dc.PolyBezierTo(pts)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "PolyPolyline", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: NtGdiPolyPolyDraw
		if hctx.WlWindow == nil {
			ctx.SetReturn(1)
			return 0
		}
		dc := getDC(ctx.Arg(0))
		pPts := ctx.Arg(1)
		pCounts := ctx.Arg(2)
		nPolys := int(ctx.Arg(3))
		off := uint64(0)
		for p := 0; p < nPolys; p++ {
			cnt, _ := mem.Read32(pCounts + uint64(p)*4)
			n := int(cnt)
			if n < 2 {
				off += uint64(n) * 8
				continue
			}
			pts := make([][2]int32, n)
			for i := 0; i < n; i++ {
				x, _ := mem.Read32(pPts + (off + uint64(i)*8))
				y, _ := mem.Read32(pPts + (off + uint64(i)*8 + 4))
				pts[i] = [2]int32{int32(x), int32(y)}
			}
			dc.PolylinePoints(pts)
			off += uint64(n) * 8
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "PolyPolygon", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: NtGdiPolyPolyDraw
		if hctx.WlWindow == nil {
			ctx.SetReturn(1)
			return 0
		}
		dc := getDC(ctx.Arg(0))
		pPts := ctx.Arg(1)
		pCounts := ctx.Arg(2)
		nPolys := int(ctx.Arg(3))
		off := uint64(0)
		for p := 0; p < nPolys; p++ {
			cnt, _ := mem.Read32(pCounts + uint64(p)*4)
			n := int(cnt)
			if n < 3 {
				off += uint64(n) * 8
				continue
			}
			pts := make([][2]int32, n)
			for i := 0; i < n; i++ {
				x, _ := mem.Read32(pPts + (off + uint64(i)*8))
				y, _ := mem.Read32(pPts + (off + uint64(i)*8 + 4))
				pts[i] = [2]int32{int32(x), int32(y)}
			}
			dc.Polygon(pts)
			off += uint64(n) * 8
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "Arc", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		dc.Arc(
			int32(ctx.Arg(1)), int32(ctx.Arg(2)), int32(ctx.Arg(3)), int32(ctx.Arg(4)),
			int32(ctx.Arg(5)), int32(ctx.Arg(6)), int32(ctx.Arg(7)), int32(ctx.Arg(8)),
		)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "ArcTo", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		dc.ArcTo(
			int32(ctx.Arg(1)), int32(ctx.Arg(2)), int32(ctx.Arg(3)), int32(ctx.Arg(4)),
			int32(ctx.Arg(5)), int32(ctx.Arg(6)), int32(ctx.Arg(7)), int32(ctx.Arg(8)),
		)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "AngleArc", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		start := math.Float32frombits(uint32(ctx.Arg(4)))
		sweep := math.Float32frombits(uint32(ctx.Arg(5)))
		dc.AngleArc(int32(ctx.Arg(1)), int32(ctx.Arg(2)), int32(ctx.Arg(3)), float64(start), float64(sweep))
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "Chord", func(ctx *ntapi.TrapContext) uint32 {
		if hctx.WlWindow == nil {
			ctx.SetReturn(1)
			return 0
		}
		dc := getDC(ctx.Arg(0))
		dc.Ellipse(int32(ctx.Arg(1)), int32(ctx.Arg(2)), int32(ctx.Arg(3)), int32(ctx.Arg(4)))
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "Pie", func(ctx *ntapi.TrapContext) uint32 {
		if hctx.WlWindow == nil {
			ctx.SetReturn(1)
			return 0
		}
		dc := getDC(ctx.Arg(0))
		dc.Ellipse(int32(ctx.Arg(1)), int32(ctx.Arg(2)), int32(ctx.Arg(3)), int32(ctx.Arg(4)))
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "FloodFill", func(ctx *ntapi.TrapContext) uint32 {
		// FloodFill(hdc, x, y, color) - fills area of specified color.
		// ReactOS: NtGdiExtFloodFill with FLOODFILLBORDER
		if hctx.WlWindow == nil {
			ctx.SetReturn(1)
			return 0
		}
		dc := getDC(ctx.Arg(0))
		x := int32(ctx.Arg(1)) + dc.OriginX
		y := int32(ctx.Arg(2)) + dc.OriginY
		// Simple scanline flood fill from seed point using brush color
		surf := dc.Target
		if surf == nil || surf.Pix == nil {
			ctx.SetReturn(1)
			return 0
		}
		borderColor := uint32(ctx.Arg(3))
		brushColor := uint32(0xFFFFFF)
		if dc.Brush != nil && dc.Brush.Style == 0 {
			brushColor = dc.Brush.Color
		}
		surf.FloodFill(x, y, borderColor, brushColor, true)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "ExtFloodFill", func(ctx *ntapi.TrapContext) uint32 {
		// ExtFloodFill(hdc, x, y, color, type)
		// type: FLOODFILLBORDER=0 or FLOODFILLSURFACE=1
		// ReactOS: NtGdiExtFloodFill
		if hctx.WlWindow == nil {
			ctx.SetReturn(1)
			return 0
		}
		dc := getDC(ctx.Arg(0))
		x := int32(ctx.Arg(1)) + dc.OriginX
		y := int32(ctx.Arg(2)) + dc.OriginY
		color := uint32(ctx.Arg(3))
		fillType := ctx.Arg(4)
		surf := dc.Target
		if surf == nil || surf.Pix == nil {
			ctx.SetReturn(1)
			return 0
		}
		brushColor := uint32(0xFFFFFF)
		if dc.Brush != nil && dc.Brush.Style == 0 {
			brushColor = dc.Brush.Color
		}
		isBorder := fillType == 0
		surf.FloodFill(x, y, color, brushColor, isBorder)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GradientFill", func(ctx *ntapi.TrapContext) uint32 {
		// GradientFill(hdc, pVertex, nVertex, pMesh, nMesh, ulMode)
		// TRIVERTEX: {x, y, Red, Green, Blue, Alpha} (each color is 16-bit, upper 8 used)
		if hctx.WlWindow == nil {
			ctx.SetReturn(1)
			return 0
		}
		dc := getDC(ctx.Arg(0))
		pVertex := ctx.Arg(1)
		pMesh := ctx.Arg(3)
		nMesh := int(ctx.Arg(4))
		ulMode := ctx.Arg(5) // 0=RECT_H, 1=RECT_V, 2=TRIANGLE
		if dc.Target == nil || pVertex == 0 || pMesh == 0 {
			ctx.SetReturn(1)
			return 0
		}
		// TRIVERTEX size = 8+2+2+2+2 = 16 bytes (x,y=int32,R,G,B,A=WORD)
		readVertex := func(idx uint64) (x, y int32, r, g, b uint8) {
			base := pVertex + idx*16
			vx, _ := mem.Read32(base)
			x = int32(vx) + dc.OriginX
			vy, _ := mem.Read32(base + 4)
			y = int32(vy) + dc.OriginY
			rv, _ := mem.Read16(base + 8)
			r = uint8(rv >> 8)
			gv, _ := mem.Read16(base + 10)
			g = uint8(gv >> 8)
			bv, _ := mem.Read16(base + 12)
			b = uint8(bv >> 8)
			return
		}
		if ulMode <= 1 { // GRADIENT_FILL_RECT_H or _V
			for i := 0; i < nMesh; i++ {
				ul, _ := mem.Read32(pMesh + uint64(i)*8)     // upper-left vertex index
				lr, _ := mem.Read32(pMesh + uint64(i)*8 + 4) // lower-right vertex index
				x0, y0, r0, g0, b0 := readVertex(uint64(ul))
				x1, y1, r1, g1, b1 := readVertex(uint64(lr))
				c0 := uint32(r0)<<16 | uint32(g0)<<8 | uint32(b0)
				c1 := uint32(r1)<<16 | uint32(g1)<<8 | uint32(b1)
				if ulMode == 0 { // horizontal
					dc.Target.GradientFillH(x0, y0, x1, y1, c0, c1)
				} else { // vertical
					dc.Target.GradientFillV(x0, y0, x1, y1, c0, c1)
				}
			}
		} else { // GRADIENT_FILL_TRIANGLE: just fill bounding box with first colour
			for i := 0; i < nMesh; i++ {
				v0, _ := mem.Read32(pMesh + uint64(i)*12)
				v1, _ := mem.Read32(pMesh + uint64(i)*12 + 4)
				v2, _ := mem.Read32(pMesh + uint64(i)*12 + 8)
				x0, y0, r0, g0, b0 := readVertex(uint64(v0))
				x1, y1, _, _, _ := readVertex(uint64(v1))
				x2, y2, _, _, _ := readVertex(uint64(v2))
				minX := x0
				if x1 < minX {
					minX = x1
				}
				if x2 < minX {
					minX = x2
				}
				minY := y0
				if y1 < minY {
					minY = y1
				}
				if y2 < minY {
					minY = y2
				}
				maxX := x0
				if x1 > maxX {
					maxX = x1
				}
				if x2 > maxX {
					maxX = x2
				}
				maxY := y0
				if y1 > maxY {
					maxY = y1
				}
				if y2 > maxY {
					maxY = y2
				}
				c := uint32(r0)<<16 | uint32(g0)<<8 | uint32(b0)
				dc.Target.FillRect(minX, minY, maxX, maxY, c)
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	// --- Palettes ---
	// ReactOS: win32ss/gdi/ntgdi/palette.c
	// Selected palette per DC: track which palette handle is selected for each DC.
	dcSelectedPalette := map[uint64]uint64{} // DC handle → palette handle

	d.RegisterAutoStubHandler(gdi32, "CreatePalette", func(ctx *ntapi.TrapContext) uint32 {
		// LOGPALETTE: WORD palVersion, WORD palNumEntries, PALETTEENTRY[n]
		pLogPal := ctx.Arg(0)
		if pLogPal == 0 {
			ctx.SetReturn(0)
			return 0
		}
		numEntries, _ := mem.Read16(pLogPal + 2)
		entries := make([]gdi.PaletteEntry, numEntries)
		for i := uint32(0); i < uint32(numEntries); i++ {
			base := pLogPal + 4 + uint64(i)*4
			r, _ := mem.Read8(base)
			g, _ := mem.Read8(base + 1)
			b, _ := mem.Read8(base + 2)
			fl, _ := mem.Read8(base + 3)
			entries[i] = gdi.PaletteEntry{R: r, G: g, B: b, Flags: fl}
		}
		h := gdiMgr.CreatePalette(entries)
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SelectPalette", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		hPal := ctx.Arg(1)
		// Return previously selected palette
		prev := dcSelectedPalette[hdc]
		if prev == 0 {
			prev = gdiMgr.GetStockObject(gdi.StockDefaultPalette)
		}
		dcSelectedPalette[hdc] = hPal
		ctx.SetReturn(prev)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "RealizePalette", func(ctx *ntapi.TrapContext) uint32 {
		// On true-color displays, RealizePalette is effectively a no-op.
		// Returns the number of entries in the logical palette that were
		// mapped to different entries in the system palette (0 on truecolor).
		// ReactOS: NtGdiRealizePalette
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetSystemPaletteEntries", func(ctx *ntapi.TrapContext) uint32 {
		// UINT GetSystemPaletteEntries(HDC, UINT iStart, UINT nEntries, LPPALETTEENTRY)
		iStart := uint32(ctx.Arg(1))
		nEntries := uint32(ctx.Arg(2))
		pEntries := ctx.Arg(3)
		sysPal := gdiMgr.SystemPalette
		if pEntries == 0 {
			// Query count
			ctx.SetReturn(uint64(len(sysPal.Entries)))
			return 0
		}
		dst := make([]gdi.PaletteEntry, nEntries)
		n := sysPal.GetEntries(int(iStart), dst)
		for i := 0; i < n; i++ {
			base := pEntries + uint64(i)*4
			mem.Write8(base, dst[i].R)
			mem.Write8(base+1, dst[i].G)
			mem.Write8(base+2, dst[i].B)
			mem.Write8(base+3, dst[i].Flags)
		}
		ctx.SetReturn(uint64(n))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetPaletteEntries", func(ctx *ntapi.TrapContext) uint32 {
		// UINT GetPaletteEntries(HPALETTE, UINT iStart, UINT nEntries, LPPALETTEENTRY)
		hPal := ctx.Arg(0)
		iStart := uint32(ctx.Arg(1))
		nEntries := uint32(ctx.Arg(2))
		pEntries := ctx.Arg(3)
		pal := gdiMgr.GetPalette(hPal)
		if pal == nil {
			ctx.SetReturn(0)
			return 0
		}
		if pEntries == 0 {
			ctx.SetReturn(uint64(len(pal.Entries)))
			return 0
		}
		dst := make([]gdi.PaletteEntry, nEntries)
		n := pal.GetEntries(int(iStart), dst)
		for i := 0; i < n; i++ {
			base := pEntries + uint64(i)*4
			mem.Write8(base, dst[i].R)
			mem.Write8(base+1, dst[i].G)
			mem.Write8(base+2, dst[i].B)
			mem.Write8(base+3, dst[i].Flags)
		}
		ctx.SetReturn(uint64(n))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SetPaletteEntries", func(ctx *ntapi.TrapContext) uint32 {
		// UINT SetPaletteEntries(HPALETTE, UINT iStart, UINT nEntries, const PALETTEENTRY*)
		hPal := ctx.Arg(0)
		iStart := uint32(ctx.Arg(1))
		nEntries := uint32(ctx.Arg(2))
		pEntries := ctx.Arg(3)
		pal := gdiMgr.GetPalette(hPal)
		if pal == nil {
			ctx.SetReturn(0)
			return 0
		}
		src := make([]gdi.PaletteEntry, nEntries)
		for i := uint32(0); i < nEntries; i++ {
			base := pEntries + uint64(i)*4
			r, _ := mem.Read8(base)
			g, _ := mem.Read8(base + 1)
			b, _ := mem.Read8(base + 2)
			fl, _ := mem.Read8(base + 3)
			src[i] = gdi.PaletteEntry{R: r, G: g, B: b, Flags: fl}
		}
		n := pal.SetEntries(int(iStart), src)
		ctx.SetReturn(uint64(n))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "AnimatePalette", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL AnimatePalette(HPALETTE, UINT iStart, UINT nEntries, const PALETTEENTRY*)
		hPal := ctx.Arg(0)
		iStart := uint32(ctx.Arg(1))
		nEntries := uint32(ctx.Arg(2))
		pEntries := ctx.Arg(3)
		pal := gdiMgr.GetPalette(hPal)
		if pal == nil {
			ctx.SetReturn(0)
			return 0
		}
		src := make([]gdi.PaletteEntry, nEntries)
		for i := uint32(0); i < nEntries; i++ {
			base := pEntries + uint64(i)*4
			r, _ := mem.Read8(base)
			g, _ := mem.Read8(base + 1)
			b, _ := mem.Read8(base + 2)
			fl, _ := mem.Read8(base + 3)
			src[i] = gdi.PaletteEntry{R: r, G: g, B: b, Flags: fl}
		}
		if pal.AnimateEntries(int(iStart), src) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "UpdateColors", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL UpdateColors(HDC) - refreshes the DC's surface colors from the
		// currently realized palette. On true-color this is a no-op success.
		// ReactOS: NtGdiUpdateColors
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetNearestColor", func(ctx *ntapi.TrapContext) uint32 {
		// COLORREF GetNearestColor(HDC, COLORREF)
		// On true-color displays, the nearest color IS the requested color.
		hdc := ctx.Arg(0)
		colorRef := uint32(ctx.Arg(1))
		palH := dcSelectedPalette[hdc]
		if palH != 0 {
			if pal := gdiMgr.GetPalette(palH); pal != nil {
				ctx.SetReturn(uint64(pal.NearestColor(colorRef)))
				return 0
			}
		}
		ctx.SetReturn(uint64(colorRef))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetNearestPaletteIndex", func(ctx *ntapi.TrapContext) uint32 {
		// UINT GetNearestPaletteIndex(HPALETTE, COLORREF)
		hPal := ctx.Arg(0)
		colorRef := uint32(ctx.Arg(1))
		pal := gdiMgr.GetPalette(hPal)
		if pal == nil {
			pal = gdiMgr.SystemPalette
		}
		idx := pal.NearestIndex(colorRef)
		ctx.SetReturn(uint64(idx))
		return 0
	})
	// --- Paths ---
	d.RegisterAutoStubHandler(gdi32, "BeginPath", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		ok := dc.BeginPath()
		if ok {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EndPath", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		ok := dc.EndPath()
		if ok {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "StrokePath", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		ok := dc.StrokePath()
		if ok {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "FillPath", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		ok := dc.FillPath()
		if ok {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "StrokeAndFillPath", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		ok := dc.StrokeAndFillPath()
		if ok {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "CloseFigure", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		ok := dc.CloseFigure()
		if ok {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "AbortPath", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		ok := dc.AbortPath()
		if ok {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SelectClipPath", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		mode := int(ctx.Arg(1))
		ok := dc.SelectClipPath(mode)
		if ok {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "FlattenPath", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		ok := dc.FlattenPath()
		if ok {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "WidenPath", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		ok := dc.WidenPath()
		if ok {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetPath", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		pPoints := ctx.Arg(1) // LPPOINT
		pTypes := ctx.Arg(2)  // LPBYTE
		nSize := int(ctx.Arg(3))
		pts := dc.GetPath()
		if pts == nil {
			ctx.SetReturn(uint64(0xFFFFFFFF)) // -1 = error
			return 0
		}
		if nSize == 0 || pPoints == 0 {
			// Query mode: return number of points
			ctx.SetReturn(uint64(len(pts)))
			return 0
		}
		count := len(pts)
		if count > nSize {
			count = nSize
		}
		for i := 0; i < count; i++ {
			mem.Write32(pPoints+uint64(i*8), uint32(pts[i].X))
			mem.Write32(pPoints+uint64(i*8+4), uint32(pts[i].Y))
			mem.Write8(pTypes+uint64(i), pts[i].Flags)
		}
		ctx.SetReturn(uint64(count))
		return 0
	})
	// --- Metafiles ---
	// ReactOS: win32ss/gdi/ntgdi/metafile.c
	mfMgr := gdiMgr.Metafiles

	d.RegisterAutoStubHandler(gdi32, "CreateMetaFileW", func(ctx *ntapi.TrapContext) uint32 {
		file := ""
		if ctx.Arg(0) != 0 {
			file = readGuestUTF16(ctx.Arg(0))
		}
		dcH, _ := gdiMgr.AllocMemDC()
		mfMgr.Create(gdi.MetafileWMF, dcH, file)
		ctx.SetReturn(dcH)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "CloseMetaFile", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		h := mfMgr.Close(hdc)
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DeleteMetaFile", func(ctx *ntapi.TrapContext) uint32 {
		h := ctx.Arg(0)
		if mfMgr.Delete(h) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "CreateEnhMetaFileW", func(ctx *ntapi.TrapContext) uint32 {
		// HDC CreateEnhMetaFileW(HDC hdcRef, LPCWSTR lpFilename, const RECT*, LPCWSTR lpDesc)
		file := ""
		if ctx.Arg(1) != 0 {
			file = readGuestUTF16(ctx.Arg(1))
		}
		dcH, _ := gdiMgr.AllocMemDC()
		mfMgr.Create(gdi.MetafileEMF, dcH, file)
		ctx.SetReturn(dcH)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "CloseEnhMetaFile", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		h := mfMgr.Close(hdc)
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DeleteEnhMetaFile", func(ctx *ntapi.TrapContext) uint32 {
		h := ctx.Arg(0)
		if mfMgr.Delete(h) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "PlayMetaFile", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL PlayMetaFile(HDC, HMETAFILE)
		h := ctx.Arg(1)
		if mfMgr.Play(h) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "PlayEnhMetaFile", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL PlayEnhMetaFile(HDC, HENHMETAFILE, const RECT*)
		h := ctx.Arg(1)
		if mfMgr.Play(h) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	// --- GDI flush/batch ---
	// ReactOS: NtGdiFlush, GdiGetBatchLimit, GdiSetBatchLimit
	gdiBatchLimit := uint32(20) // default Windows batch limit
	d.RegisterAutoStubHandler(gdi32, "GdiFlush", func(ctx *ntapi.TrapContext) uint32 {
		// Flush pending GDI operations. We execute synchronously, so always success.
		if hctx.SyncScreenSurface != nil {
			hctx.SyncScreenSurface()
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiGetBatchLimit", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(gdiBatchLimit))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiSetBatchLimit", func(ctx *ntapi.TrapContext) uint32 {
		newLimit := uint32(ctx.Arg(0))
		if newLimit == 0 {
			ctx.SetReturn(0)
			return 0
		}
		old := gdiBatchLimit
		gdiBatchLimit = newLimit
		ctx.SetReturn(uint64(old))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiAlphaBlend", func(ctx *ntapi.TrapContext) uint32 {
		if hctx.WlWindow == nil {
			ctx.SetReturn(1)
			return 0
		}
		hdcDst := ctx.Arg(0)
		dx := int32(ctx.Arg(1))
		dy := int32(ctx.Arg(2))
		dw := int32(ctx.Arg(3))
		dh := int32(ctx.Arg(4))
		hdcSrc := ctx.Arg(5)
		sx := int32(ctx.Arg(6))
		sy := int32(ctx.Arg(7))
		sw := int32(ctx.Arg(8))
		sh := int32(ctx.Arg(9))
		// arg10 = BLENDFUNCTION packed as uint32: [BlendOp, BlendFlags, Alpha, AlphaFormat]
		bf := uint32(ctx.Arg(10))
		globalAlpha := uint8((bf >> 16) & 0xFF)
		perPixel := (bf >> 24) == 1 // AC_SRC_ALPHA
		if globalAlpha == 0 {
			globalAlpha = 255
		}
		dst := getDC(hdcDst)
		src := gdiMgr.GetDC(hdcSrc)
		if dst.Target != nil && src != nil && src.Target != nil {
			adx := dx + dst.OriginX
			ady := dy + dst.OriginY
			asx := sx + src.OriginX
			asy := sy + src.OriginY
			dst.Target.AlphaBlendSurface(adx, ady, dw, dh, src.Target, asx, asy, sw, sh, globalAlpha, perPixel)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "AlphaBlend", func(ctx *ntapi.TrapContext) uint32 {
		if hctx.WlWindow == nil {
			ctx.SetReturn(1)
			return 0
		}
		hdcDst := ctx.Arg(0)
		dx := int32(ctx.Arg(1))
		dy := int32(ctx.Arg(2))
		dw := int32(ctx.Arg(3))
		dh := int32(ctx.Arg(4))
		hdcSrc := ctx.Arg(5)
		sx := int32(ctx.Arg(6))
		sy := int32(ctx.Arg(7))
		sw := int32(ctx.Arg(8))
		sh := int32(ctx.Arg(9))
		bf := uint32(ctx.Arg(10))
		globalAlpha := uint8((bf >> 16) & 0xFF)
		perPixel := (bf >> 24) == 1
		if globalAlpha == 0 {
			globalAlpha = 255
		}
		dst := getDC(hdcDst)
		src := gdiMgr.GetDC(hdcSrc)
		if dst.Target != nil && src != nil && src.Target != nil {
			adx := dx + dst.OriginX
			ady := dy + dst.OriginY
			asx := sx + src.OriginX
			asy := sy + src.OriginY
			dst.Target.AlphaBlendSurface(adx, ady, dw, dh, src.Target, asx, asy, sw, sh, globalAlpha, perPixel)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "TransparentBlt", func(ctx *ntapi.TrapContext) uint32 {
		if hctx.WlWindow == nil {
			ctx.SetReturn(1)
			return 0
		}
		hdcDst := ctx.Arg(0)
		dx := int32(ctx.Arg(1))
		dy := int32(ctx.Arg(2))
		dw := int32(ctx.Arg(3))
		dh := int32(ctx.Arg(4))
		hdcSrc := ctx.Arg(5)
		sx := int32(ctx.Arg(6))
		sy := int32(ctx.Arg(7))
		sw := int32(ctx.Arg(8))
		sh := int32(ctx.Arg(9))
		transColor := uint32(ctx.Arg(10)) // transparent colour key (COLORREF)
		dst := getDC(hdcDst)
		src := gdiMgr.GetDC(hdcSrc)
		if dst.Target != nil && src != nil && src.Target != nil {
			adx := dx + dst.OriginX
			ady := dy + dst.OriginY
			asx := sx + src.OriginX
			asy := sy + src.OriginY
			// Scale first if needed via StretchBlt, then apply transparent blt
			if sw == dw && sh == dh {
				dst.Target.TransparentBlt(adx, ady, dw, dh, src.Target, asx, asy, sw, sh, transColor)
			} else {
				// Stretch into a temp surface then transparent-blt
				tmp := gdi.NewSurface(dw, dh)
				tmp.StretchBlt(0, 0, dw, dh, src.Target, asx, asy, sw, sh)
				dst.Target.TransparentBlt(adx, ady, dw, dh, tmp, 0, 0, dw, dh, transColor)
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetCurrentObject", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		objType := ctx.Arg(1)
		switch objType {
		case 2: // OBJ_BRUSH
			if dc.Brush != nil {
				ctx.SetReturn(gdiMgr.FindBrushHandle(dc.Brush))
			} else {
				ctx.SetReturn(gdiMgr.GetStockObject(gdi.StockWhiteBrush))
			}
		case 1: // OBJ_PEN
			if dc.Pen != nil {
				ctx.SetReturn(gdiMgr.FindPenHandle(dc.Pen))
			} else {
				ctx.SetReturn(gdiMgr.GetStockObject(gdi.StockBlackPen))
			}
		case 6: // OBJ_FONT
			if dc.Font != nil {
				ctx.SetReturn(gdiMgr.FindFontHandle(dc.Font))
			} else {
				ctx.SetReturn(gdiMgr.GetStockObject(gdi.StockSystemFont))
			}
		case 7: // OBJ_BITMAP
			ctx.SetReturn(gdiMgr.FindBitmapHandle(dc.Bitmap))
		default:
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetObjectType", func(ctx *ntapi.TrapContext) uint32 {
		obj := gdiMgr.GetObject(ctx.Arg(0))
		if obj == nil {
			ctx.SetReturn(0)
			return 0
		}
		switch obj.Type {
		case gdi.ObjBrush:
			ctx.SetReturn(2)
		case gdi.ObjPen:
			ctx.SetReturn(1)
		case gdi.ObjFont:
			ctx.SetReturn(6)
		case gdi.ObjBitmap:
			ctx.SetReturn(7)
		case gdi.ObjRegion:
			ctx.SetReturn(8)
		default:
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "CancelDC", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: NtGdiCancelDC - sets DC_ABORT flag on the DC.
		// We mark the DC as cancelled so any pending path/metafile recording stops.
		dc := getDC(ctx.Arg(0))
		if dc != nil {
			dc.AbortPath() // cancel any in-progress path
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "ResetDCW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(ctx.Arg(0))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetCurrentPositionEx", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		p := ctx.Arg(1)
		if p != 0 {
			ctx.Mem.Write32(p, uint32(dc.CurX))
			ctx.Mem.Write32(p+4, uint32(dc.CurY))
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetDIBits", func(ctx *ntapi.TrapContext) uint32 {
		// GetDIBits(hdc, hbm, startScan, numScans, lpvBits, lpbmi, usage)
		hbm := ctx.Arg(1)
		startScan := int32(ctx.Arg(2))
		numScans := int32(ctx.Arg(3))
		lpvBits := ctx.Arg(4)
		pBMI := ctx.Arg(5)
		obj := gdiMgr.GetObject(hbm)
		if obj == nil || obj.Bitmap == nil || obj.Bitmap.Surf == nil {
			ctx.SetReturn(0)
			return 0
		}
		bm := obj.Bitmap
		// Fill BITMAPINFOHEADER if provided (bitCount=32 BI_RGB)
		if pBMI != 0 {
			ctx.Mem.Write32(pBMI, 40)                  // biSize
			ctx.Mem.Write32(pBMI+4, uint32(bm.Width))  // biWidth
			ctx.Mem.Write32(pBMI+8, uint32(bm.Height)) // biHeight (bottom-up)
			ctx.Mem.Write16(pBMI+12, 1)                // biPlanes
			ctx.Mem.Write16(pBMI+14, 32)               // biBitCount
			ctx.Mem.Write32(pBMI+16, 0)                // biCompression BI_RGB
			ctx.Mem.Write32(pBMI+20, 0)                // biSizeImage
			ctx.Mem.Write32(pBMI+24, 0)
			ctx.Mem.Write32(pBMI+28, 0)
			ctx.Mem.Write32(pBMI+32, 0)
			ctx.Mem.Write32(pBMI+36, 0)
		}
		if lpvBits == 0 {
			ctx.SetReturn(uint64(numScans))
			return 0
		}
		// Write pixel data (32bpp bottom-up)
		stride := gdi.DIBStride(bm.Width, 32)
		buf := make([]byte, int(stride)*int(numScans))
		gdi.WriteDIBFromSurface(buf, bm.Surf, 0, startScan, bm.Width, numScans, 32)
		for i, b := range buf {
			ctx.Mem.Write8(lpvBits+uint64(i), b)
		}
		ctx.SetReturn(uint64(numScans))
		return 0
	})
	// --- SetDIBits ---
	// ReactOS: NtGdiSetDIBitsToDeviceInternal / GreSetDIBits
	d.RegisterAutoStubHandler(gdi32, "SetDIBits", func(ctx *ntapi.TrapContext) uint32 {
		// SetDIBits(hdc, hbm, startScan, numScans, lpBits, lpbmi, usage)
		hbm := ctx.Arg(1)
		startScan := int32(ctx.Arg(2))
		numScans := int32(ctx.Arg(3))
		lpBits := ctx.Arg(4)
		pBMI := ctx.Arg(5)
		obj := gdiMgr.GetObject(hbm)
		if obj == nil || obj.Bitmap == nil || obj.Bitmap.Surf == nil || lpBits == 0 || pBMI == 0 {
			ctx.SetReturn(0)
			return 0
		}
		bm := obj.Bitmap
		srcW, _, bitCount, _, ct, _ := readDIBInfo(pBMI)
		// lpBits contains numScans scan lines starting from startScan
		pixData := readDIBPixels(lpBits, srcW, numScans, bitCount)
		if pixData == nil {
			ctx.SetReturn(0)
			return 0
		}
		// Blit DIB rows into bitmap surface at startScan offset
		bm.Surf.BlitDIB(0, startScan, bm.Width, numScans, pixData, srcW, numScans, bitCount, ct, 0, 0, bm.Width, numScans)
		ctx.SetReturn(uint64(numScans))
		return 0
	})
	// --- CreatePatternBrush ---
	// ReactOS: NtGdiCreatePatternBrushInternal in win32ss/gdi/ntgdi/brush.c
	d.RegisterAutoStubHandler(gdi32, "CreatePatternBrush", func(ctx *ntapi.TrapContext) uint32 {
		hbm := ctx.Arg(0)
		ctx.SetReturn(gdiMgr.CreatePatternBrush(hbm))
		return 0
	})
	// --- GetObjectA ---
	// ReactOS: NtGdiExtGetObjectW (ANSI wrapper in gdi32)
	// Same as GetObjectW but LOGFONTA uses char[32] (not WCHAR[32]) for lfFaceName.
	d.RegisterAutoStubHandler(gdi32, "GetObjectA", func(ctx *ntapi.TrapContext) uint32 {
		h := ctx.Arg(0)
		obj := gdiMgr.GetObject(h)
		if obj == nil {
			ctx.SetReturn(0)
			return 0
		}
		pv := ctx.Arg(2)
		switch obj.Type {
		case gdi.ObjPen:
			ctx.SetReturn(16) // sizeof(LOGPEN)
			if pv != 0 && obj.Pen != nil {
				ctx.Mem.Write32(pv, uint32(obj.Pen.Style))
				ctx.Mem.Write32(pv+4, uint32(obj.Pen.Width))
				ctx.Mem.Write32(pv+8, 0)
				ctx.Mem.Write32(pv+12, obj.Pen.Color)
			}
		case gdi.ObjBrush:
			ctx.SetReturn(16) // sizeof(LOGBRUSH) on x64
			if pv != 0 && obj.Brush != nil {
				ctx.Mem.Write32(pv, uint32(obj.Brush.Style))
				ctx.Mem.Write32(pv+4, obj.Brush.Color)
				ctx.Mem.Write64(pv+8, uint64(obj.Brush.Hatch))
			}
		case gdi.ObjBitmap:
			ctx.SetReturn(32) // sizeof(BITMAP) on x64
			if pv != 0 && obj.Bitmap != nil {
				ctx.Mem.Write32(pv, 0)
				ctx.Mem.Write32(pv+4, uint32(obj.Bitmap.Width))
				ctx.Mem.Write32(pv+8, uint32(obj.Bitmap.Height))
				ctx.Mem.Write32(pv+12, uint32(obj.Bitmap.Width*4))
				ctx.Mem.Write16(pv+16, 1)
				ctx.Mem.Write16(pv+18, 32)
				ctx.Mem.Write32(pv+20, 0) // padding
				ctx.Mem.Write64(pv+24, 0) // bmBits (8 bytes on x64)
			}
		case gdi.ObjFont:
			// LOGFONTA = 60 bytes (lfFaceName is char[32] at offset 28)
			ctx.SetReturn(60)
			if pv != 0 && obj.Font != nil {
				f := obj.Font
				ctx.Mem.Write32(pv, uint32(f.Height))
				ctx.Mem.Write32(pv+4, uint32(f.Width))
				ctx.Mem.Write32(pv+8, uint32(f.Escapement))
				ctx.Mem.Write32(pv+12, uint32(f.Orientation))
				w := f.Weight
				if w == 0 {
					w = 400
				}
				ctx.Mem.Write32(pv+16, uint32(w))
				italic := byte(0)
				if f.Italic {
					italic = 1
				}
				underline := byte(0)
				if f.Underline {
					underline = 1
				}
				strike := byte(0)
				if f.StrikeOut {
					strike = 1
				}
				ctx.Mem.Write8(pv+20, italic)
				ctx.Mem.Write8(pv+21, underline)
				ctx.Mem.Write8(pv+22, strike)
				ctx.Mem.Write8(pv+23, f.CharSet)
				ctx.Mem.Write8(pv+24, f.OutPrecision)
				ctx.Mem.Write8(pv+25, f.ClipPrecision)
				ctx.Mem.Write8(pv+26, f.Quality)
				ctx.Mem.Write8(pv+27, f.PitchFamily)
				// lfFaceName: char[32] at offset 28
				face := f.FaceName
				if len(face) > 31 {
					face = face[:31]
				}
				for i := 0; i < len(face); i++ {
					ctx.Mem.Write8(pv+28+uint64(i), face[i])
				}
				ctx.Mem.Write8(pv+28+uint64(len(face)), 0)
			}
		default:
			ctx.SetReturn(0)
		}
		return 0
	})
	// --- GetBkMode ---
	// ReactOS: NtGdiGetDCDword(hdc, GdiGetSetBkMode)
	d.RegisterAutoStubHandler(gdi32, "GetBkMode", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		m := dc.BkMode
		if m == 0 {
			m = 2 // OPAQUE default
		}
		ctx.SetReturn(uint64(m))
		return 0
	})
	// --- DC_PEN / DC_BRUSH colour functions ---
	// ReactOS: NtGdiGetDCDword / NtGdiSetDCDword for DC_PEN_COLOR / DC_BRUSH_COLOR
	d.RegisterAutoStubHandler(gdi32, "SetDCPenColor", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		prev := dc.DCPenColor
		dc.DCPenColor = uint32(ctx.Arg(1))
		ctx.SetReturn(uint64(prev))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetDCPenColor", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(getDC(ctx.Arg(0)).DCPenColor))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SetDCBrushColor", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		prev := dc.DCBrushColor
		dc.DCBrushColor = uint32(ctx.Arg(1))
		ctx.SetReturn(uint64(prev))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetDCBrushColor", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(getDC(ctx.Arg(0)).DCBrushColor))
		return 0
	})
	// --- SetPixelV ---
	// ReactOS: NtGdiSetPixel (SetPixelV is SetPixel that returns BOOL not color)
	d.RegisterAutoStubHandler(gdi32, "SetPixelV", func(ctx *ntapi.TrapContext) uint32 {
		if hctx.WlWindow == nil {
			ctx.SetReturn(0)
			return 0
		}
		dc := getDC(ctx.Arg(0))
		dc.SetPixel(int32(ctx.Arg(1)), int32(ctx.Arg(2)), uint32(ctx.Arg(3)))
		ctx.SetReturn(1) // TRUE
		return 0
	})
	// --- TextOutA ---
	// ReactOS: NtGdiExtTextOutW (ANSI → wide conversion in gdi32 client)
	d.RegisterAutoStubHandler(gdi32, "TextOutA", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		x := int32(ctx.Arg(1))
		y := int32(ctx.Arg(2))
		lpStr := ctx.Arg(3)
		nLen := int(ctx.Arg(4))
		if lpStr != 0 && nLen > 0 {
			buf := make([]byte, nLen)
			for i := 0; i < nLen; i++ {
				b, _ := mem.Read8(lpStr + uint64(i))
				buf[i] = b
			}
			dc.TextOut(x, y, string(buf), false)
		}
		ctx.SetReturn(1)
		return 0
	})
	// --- ExtTextOutA ---
	// ReactOS: NtGdiExtTextOutW (ANSI → wide in gdi32 client)
	d.RegisterAutoStubHandler(gdi32, "ExtTextOutA", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		x := int32(ctx.Arg(1))
		y := int32(ctx.Arg(2))
		opts := uint32(ctx.Arg(3))
		lprc := ctx.Arg(4)
		lpStr := ctx.Arg(5)
		nLen := int(ctx.Arg(6))
		text := ""
		if lpStr != 0 && nLen > 0 {
			buf := make([]byte, nLen)
			for i := 0; i < nLen; i++ {
				b, _ := mem.Read8(lpStr + uint64(i))
				buf[i] = b
			}
			text = string(buf)
		}
		if lprc != 0 {
			rL, _ := mem.Read32(lprc)
			rT, _ := mem.Read32(lprc + 4)
			rR, _ := mem.Read32(lprc + 8)
			rB, _ := mem.Read32(lprc + 12)
			if opts&0x2 != 0 { // ETO_OPAQUE
				dc.FillRect(int32(rL), int32(rT), int32(rR), int32(rB), dc.BkColor)
			}
			if opts&0x4 != 0 { // ETO_CLIPPED
				x0 := int32(rL) + dc.OriginX
				y0 := int32(rT) + dc.OriginY
				x1 := int32(rR) + dc.OriginX
				y1 := int32(rB) + dc.OriginY
				oldX0, oldY0, oldX1, oldY1 := dc.ClipX0, dc.ClipY0, dc.ClipX1, dc.ClipY1
				if oldX1 > oldX0 {
					if x0 < oldX0 {
						x0 = oldX0
					}
					if y0 < oldY0 {
						y0 = oldY0
					}
					if x1 > oldX1 {
						x1 = oldX1
					}
					if y1 > oldY1 {
						y1 = oldY1
					}
				}
				dc.ClipX0, dc.ClipY0, dc.ClipX1, dc.ClipY1 = x0, y0, x1, y1
				if len(text) > 0 {
					dc.TextOut(x, y, text, false)
				}
				dc.ClipX0, dc.ClipY0, dc.ClipX1, dc.ClipY1 = oldX0, oldY0, oldX1, oldY1
				ctx.SetReturn(1)
				return 0
			}
		}
		if len(text) > 0 {
			dc.TextOut(x, y, text, false)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DrawTextW", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		lpStr := ctx.Arg(1)
		nLen := int(ctx.Arg(2))
		pRect := ctx.Arg(3)
		format := uint32(ctx.Arg(4))
		if dc == nil || pRect == 0 {
			ctx.SetReturn(0)
			return 0
		}
		left, _ := mem.Read32(pRect)
		top, _ := mem.Read32(pRect + 4)
		right, _ := mem.Read32(pRect + 8)
		bottom, _ := mem.Read32(pRect + 12)
		var text []rune
		if lpStr != 0 {
			if nLen < 0 {
				text = []rune(readGuestUTF16(lpStr))
			} else {
				chars := make([]uint16, 0, nLen)
				for i := 0; i < nLen; i++ {
					ch, _ := mem.Read16(lpStr + uint64(i)*2)
					if ch == 0 {
						break
					}
					chars = append(chars, ch)
				}
				text = gdi.UTF16ToRunes(chars)
			}
		}
		rect := win32.Rect{Left: int32(left), Top: int32(top), Right: int32(right), Bottom: int32(bottom)}
		height := win32.DrawTextW(gdiDrawTextAdapter{dc: dc}, text, &rect, format)
		mem.Write32(pRect, uint32(rect.Left))
		mem.Write32(pRect+4, uint32(rect.Top))
		mem.Write32(pRect+8, uint32(rect.Right))
		mem.Write32(pRect+12, uint32(rect.Bottom))
		ctx.SetReturn(uint64(height))
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DrawTextA", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		lpStr := ctx.Arg(1)
		nLen := int(ctx.Arg(2))
		pRect := ctx.Arg(3)
		format := uint32(ctx.Arg(4))
		if dc == nil || pRect == 0 {
			ctx.SetReturn(0)
			return 0
		}
		left, _ := mem.Read32(pRect)
		top, _ := mem.Read32(pRect + 4)
		right, _ := mem.Read32(pRect + 8)
		bottom, _ := mem.Read32(pRect + 12)
		text := ""
		if lpStr != 0 {
			if nLen < 0 {
				var buf []byte
				for i := uint64(0); ; i++ {
					b, _ := mem.Read8(lpStr + i)
					if b == 0 {
						break
					}
					buf = append(buf, b)
				}
				text = string(buf)
			} else {
				buf := make([]byte, 0, nLen)
				for i := 0; i < nLen; i++ {
					b, _ := mem.Read8(lpStr + uint64(i))
					if b == 0 {
						break
					}
					buf = append(buf, b)
				}
				text = string(buf)
			}
		}
		rect := win32.Rect{Left: int32(left), Top: int32(top), Right: int32(right), Bottom: int32(bottom)}
		height := win32.DrawTextW(gdiDrawTextAdapter{dc: dc}, []rune(text), &rect, format)
		mem.Write32(pRect, uint32(rect.Left))
		mem.Write32(pRect+4, uint32(rect.Top))
		mem.Write32(pRect+8, uint32(rect.Right))
		mem.Write32(pRect+12, uint32(rect.Bottom))
		ctx.SetReturn(uint64(height))
		return 0
	})
	// --- GetDCOrgEx ---
	// ReactOS: NtGdiGetDCPoint(hdc, GdiGetDCOrg)
	d.RegisterAutoStubHandler(gdi32, "GetDCOrgEx", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		p := ctx.Arg(1)
		if p != 0 {
			ctx.Mem.Write32(p, uint32(dc.OriginX))
			ctx.Mem.Write32(p+4, uint32(dc.OriginY))
		}
		ctx.SetReturn(1)
		return 0
	})
	// --- GetTextExtentExPointA ---
	// ReactOS: NtGdiGetTextExtentExW (ANSI wrapper in gdi32)
	d.RegisterAutoStubHandler(gdi32, "GetTextExtentExPointA", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		nLen := int32(ctx.Arg(2))
		pSize := ctx.Arg(5)
		dc := getDC(hdc)
		f := dc.Font
		if f == nil {
			f = gdi.DefaultFont()
		}
		if pSize != 0 {
			ctx.Mem.Write32(pSize, uint32(nLen*f.AveCharWidth))
			ctx.Mem.Write32(pSize+4, uint32(f.CellHeight))
		}
		ctx.SetReturn(1)
		return 0
	})
	// --- GetCharWidth32A ---
	// ReactOS: NtGdiGetCharWidthW (ANSI wrapper)
	d.RegisterAutoStubHandler(gdi32, "GetCharWidth32A", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		first := int(ctx.Arg(1))
		last := int(ctx.Arg(2))
		pBuf := ctx.Arg(3)
		if last < first || last-first > 0xFFFF {
			ctx.SetReturn(0)
			return 0
		}
		dc := getDC(hdc)
		f := dc.Font
		if f == nil {
			f = gdi.DefaultFont()
		}
		charW := f.AveCharWidth
		if pBuf != 0 {
			for i := first; i <= last; i++ {
				ctx.Mem.Write32(pBuf+uint64(i-first)*4, uint32(charW))
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	// --- GetCharWidthA ---
	// ReactOS: NtGdiGetCharWidthW (ANSI wrapper, same as GetCharWidth32A)
	d.RegisterAutoStubHandler(gdi32, "GetCharWidthA", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		first := int(ctx.Arg(1))
		last := int(ctx.Arg(2))
		pBuf := ctx.Arg(3)
		if last < first || last-first > 0xFFFF {
			ctx.SetReturn(0)
			return 0
		}
		dc := getDC(hdc)
		f := dc.Font
		if f == nil {
			f = gdi.DefaultFont()
		}
		charW := f.AveCharWidth
		if pBuf != 0 {
			for i := first; i <= last; i++ {
				ctx.Mem.Write32(pBuf+uint64(i-first)*4, uint32(charW))
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	// --- GetLayout / SetLayout ---
	// ReactOS: NtGdiGetLayout / NtGdiSetLayout
	d.RegisterAutoStubHandler(gdi32, "GetLayout", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // LAYOUT_LTR (default left-to-right)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SetLayout", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // previous layout = LAYOUT_LTR
		return 0
	})
	// --- CreateDCA / CreateDCW ---
	// ReactOS: NtGdiOpenDCW - create DC for a display device
	d.RegisterAutoStubHandler(gdi32, "CreateDCW", func(ctx *ntapi.TrapContext) uint32 {
		// lpszDriver typically "DISPLAY"; allocate a screen DC
		h, _ := gdiMgr.AllocScreenDC()
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "CreateDCA", func(ctx *ntapi.TrapContext) uint32 {
		h, _ := gdiMgr.AllocScreenDC()
		ctx.SetReturn(h)
		return 0
	})
	// --- CreateICA / CreateICW ---
	// ReactOS: NtGdiOpenDCW - information context (same as DC but no drawing)
	d.RegisterAutoStubHandler(gdi32, "CreateICW", func(ctx *ntapi.TrapContext) uint32 {
		h, _ := gdiMgr.AllocMemDC()
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "CreateICA", func(ctx *ntapi.TrapContext) uint32 {
		h, _ := gdiMgr.AllocMemDC()
		ctx.SetReturn(h)
		return 0
	})
	// --- GetTextFaceA ---
	// ReactOS: NtGdiGetTextFaceW (ANSI wrapper)
	d.RegisterAutoStubHandler(gdi32, "GetTextFaceA", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		nCount := int(ctx.Arg(1))
		pFace := ctx.Arg(2)
		faceName := "Courier New"
		if dc.Font != nil && dc.Font.FaceName != "" {
			faceName = dc.Font.FaceName
		}
		if pFace != 0 && nCount > 0 {
			n := len(faceName)
			if n >= nCount {
				n = nCount - 1
			}
			for i := 0; i < n; i++ {
				ctx.Mem.Write8(pFace+uint64(i), faceName[i])
			}
			ctx.Mem.Write8(pFace+uint64(n), 0)
			ctx.SetReturn(uint64(n))
		} else {
			ctx.SetReturn(uint64(len(faceName) + 1))
		}
		return 0
	})

	// ═══════════════════════════════════════════════════════════════
	// AUTO-GENERATED: Missing gdi32 handlers from ReactOS spec
	// ═══════════════════════════════════════════════════════════════

	d.RegisterAutoStubHandler(gdi32, "AbortDoc", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] AbortDoc(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "AddFontResourceA", func(ctx *ntapi.TrapContext) uint32 {
		pName := ctx.Arg(0)
		var name string
		if pName != 0 {
			var buf []byte
			for i := uint64(0); ; i++ {
				b, _ := mem.Read8(pName + i)
				if b == 0 {
					break
				}
				buf = append(buf, b)
			}
			name = string(buf)
		}
		ravelog.Logf("[gdi32] AddFontResourceA(%q)\n", name)
		ctx.SetReturn(1) // success: 1 font added
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "AddFontResourceExA", func(ctx *ntapi.TrapContext) uint32 {
		pName := ctx.Arg(0)
		fl := ctx.Arg(1)
		_ = ctx.Arg(2) // reserved
		var name string
		if pName != 0 {
			var buf []byte
			for i := uint64(0); ; i++ {
				b, _ := mem.Read8(pName + i)
				if b == 0 {
					break
				}
				buf = append(buf, b)
			}
			name = string(buf)
		}
		ravelog.Logf("[gdi32] AddFontResourceExA(%q, flags=0x%x)\n", name, fl)
		ctx.SetReturn(1) // success: 1 font added
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "AddFontResourceTracking", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] AddFontResourceTracking(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "AnyLinkedFonts", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[gdi32] AnyLinkedFonts()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "BRUSHOBJ_hGetColorTransform", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] BRUSHOBJ_hGetColorTransform(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "BRUSHOBJ_pvAllocRbrush", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] BRUSHOBJ_pvAllocRbrush(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "BRUSHOBJ_pvGetRbrush", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] BRUSHOBJ_pvGetRbrush(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "BRUSHOBJ_ulGetBrushColor", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] BRUSHOBJ_ulGetBrushColor(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "CLIPOBJ_bEnum", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] CLIPOBJ_bEnum(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "CLIPOBJ_cEnumStart", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[gdi32] CLIPOBJ_cEnumStart(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "CLIPOBJ_ppoGetPath", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] CLIPOBJ_ppoGetPath(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "CheckColorsInGamut", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[gdi32] CheckColorsInGamut(0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "ChoosePixelFormat", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] ChoosePixelFormat(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "ClearBitmapAttributes", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] ClearBitmapAttributes(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "ClearBrushAttributes", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] ClearBrushAttributes(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "ColorCorrectPalette", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[gdi32] ColorCorrectPalette(0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "ColorMatchToTarget", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] ColorMatchToTarget(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "CopyEnhMetaFileA", func(ctx *ntapi.TrapContext) uint32 {
		hEmf := ctx.Arg(0)
		pFile := ctx.Arg(1)
		ravelog.Logf("[gdi32] CopyEnhMetaFileA(0x%x, 0x%x)\n", hEmf, pFile)
		h := gdiMgr.Metafiles.Create(gdi.MetafileEMF, 0, "")
		gdiMgr.Metafiles.Close(0)
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "CopyEnhMetaFileW", func(ctx *ntapi.TrapContext) uint32 {
		hEmf := ctx.Arg(0)
		pFile := ctx.Arg(1)
		ravelog.Logf("[gdi32] CopyEnhMetaFileW(0x%x, 0x%x)\n", hEmf, pFile)
		h := gdiMgr.Metafiles.Create(gdi.MetafileEMF, 0, "")
		gdiMgr.Metafiles.Close(0)
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "CopyMetaFileA", func(ctx *ntapi.TrapContext) uint32 {
		hMf := ctx.Arg(0)
		pFile := ctx.Arg(1)
		ravelog.Logf("[gdi32] CopyMetaFileA(0x%x, 0x%x)\n", hMf, pFile)
		h := gdiMgr.Metafiles.Create(gdi.MetafileWMF, 0, "")
		gdiMgr.Metafiles.Close(0)
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "CopyMetaFileW", func(ctx *ntapi.TrapContext) uint32 {
		hMf := ctx.Arg(0)
		pFile := ctx.Arg(1)
		ravelog.Logf("[gdi32] CopyMetaFileW(0x%x, 0x%x)\n", hMf, pFile)
		h := gdiMgr.Metafiles.Create(gdi.MetafileWMF, 0, "")
		gdiMgr.Metafiles.Close(0)
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "CreateColorSpaceA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] CreateColorSpaceA(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "CreateColorSpaceW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] CreateColorSpaceW(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "CreateDIBPatternBrush", func(ctx *ntapi.TrapContext) uint32 {
		hGlobal := ctx.Arg(0)
		usage := ctx.Arg(1)
		ravelog.Logf("[gdi32] CreateDIBPatternBrush(hGlobal=0x%x, usage=%d)\n", hGlobal, usage)
		h := gdiMgr.CreatePatternBrush(0)
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "CreateDIBPatternBrushPt", func(ctx *ntapi.TrapContext) uint32 {
		pData := ctx.Arg(0)
		usage := ctx.Arg(1)
		ravelog.Logf("[gdi32] CreateDIBPatternBrushPt(pData=0x%x, usage=%d)\n", pData, usage)
		h := gdiMgr.CreatePatternBrush(0)
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "CreateDiscardableBitmap", func(ctx *ntapi.TrapContext) uint32 {
		_ = ctx.Arg(0) // hdc
		w := int32(ctx.Arg(1))
		h := int32(ctx.Arg(2))
		hBmp := gdiMgr.CreateCompatibleBitmap(w, h)
		ravelog.Logf("[gdi32] CreateDiscardableBitmap(w=%d, h=%d) → 0x%x\n", w, h, hBmp)
		ctx.SetReturn(hBmp)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "CreateEnhMetaFileA", func(ctx *ntapi.TrapContext) uint32 {
		hdcRef := ctx.Arg(0)
		pFile := ctx.Arg(1)
		_ = ctx.Arg(2) // lpRect
		_ = ctx.Arg(3) // lpDescription
		var fileName string
		if pFile != 0 {
			var buf []byte
			for i := uint64(0); ; i++ {
				b, _ := mem.Read8(pFile + i)
				if b == 0 {
					break
				}
				buf = append(buf, b)
			}
			fileName = string(buf)
		}
		h := gdiMgr.Metafiles.Create(gdi.MetafileEMF, hdcRef, fileName)
		ravelog.Logf("[gdi32] CreateEnhMetaFileA(hdcRef=0x%x, file=%q) → 0x%x\n", hdcRef, fileName, h)
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "CreateFontA", func(ctx *ntapi.TrapContext) uint32 {
		f := &gdi.Font{
			Height:        int32(ctx.Arg(0)),
			Width:         int32(ctx.Arg(1)),
			Escapement:    int32(ctx.Arg(2)),
			Orientation:   int32(ctx.Arg(3)),
			Weight:        int32(ctx.Arg(4)),
			Italic:        ctx.Arg(5) != 0,
			Underline:     ctx.Arg(6) != 0,
			StrikeOut:     ctx.Arg(7) != 0,
			CharSet:       uint8(ctx.Arg(8)),
			OutPrecision:  uint8(ctx.Arg(9)),
			ClipPrecision: uint8(ctx.Arg(10)),
			Quality:       uint8(ctx.Arg(11)),
			PitchFamily:   uint8(ctx.Arg(12)),
		}
		pFace := ctx.Arg(13)
		if pFace != 0 {
			var buf []byte
			for i := uint64(0); i < 32; i++ {
				b, _ := mem.Read8(pFace + i)
				if b == 0 {
					break
				}
				buf = append(buf, b)
			}
			f.FaceName = string(buf)
		}
		h := gdiMgr.CreateFont(f)
		ravelog.Logf("[gdi32] CreateFontA(%q, h=%d, w=%d, wt=%d) → 0x%x\n", f.FaceName, f.Height, f.Width, f.Weight, h)
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "CreateFontIndirectA", func(ctx *ntapi.TrapContext) uint32 {
		lf := ctx.Arg(0)
		f := &gdi.Font{}
		if lf != 0 {
			v32, _ := mem.Read32(lf)
			f.Height = int32(v32)
			v32, _ = mem.Read32(lf + 4)
			f.Width = int32(v32)
			v32, _ = mem.Read32(lf + 8)
			f.Escapement = int32(v32)
			v32, _ = mem.Read32(lf + 12)
			f.Orientation = int32(v32)
			v32, _ = mem.Read32(lf + 16)
			f.Weight = int32(v32)
			v8, _ := mem.Read8(lf + 20)
			f.Italic = v8 != 0
			v8, _ = mem.Read8(lf + 21)
			f.Underline = v8 != 0
			v8, _ = mem.Read8(lf + 22)
			f.StrikeOut = v8 != 0
			v8, _ = mem.Read8(lf + 23)
			f.CharSet = v8
			v8, _ = mem.Read8(lf + 24)
			f.OutPrecision = v8
			v8, _ = mem.Read8(lf + 25)
			f.ClipPrecision = v8
			v8, _ = mem.Read8(lf + 26)
			f.Quality = v8
			v8, _ = mem.Read8(lf + 27)
			f.PitchFamily = v8
			var buf []byte
			for i := uint64(0); i < 32; i++ {
				b, _ := mem.Read8(lf + 28 + i)
				if b == 0 {
					break
				}
				buf = append(buf, b)
			}
			f.FaceName = string(buf)
		}
		h := gdiMgr.CreateFont(f)
		ravelog.Logf("[gdi32] CreateFontIndirectA(%q, h=%d) → 0x%x\n", f.FaceName, f.Height, h)
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "CreateFontIndirectExA", func(ctx *ntapi.TrapContext) uint32 {
		lf := ctx.Arg(0)
		f := &gdi.Font{}
		if lf != 0 {
			v32, _ := mem.Read32(lf)
			f.Height = int32(v32)
			v32, _ = mem.Read32(lf + 4)
			f.Width = int32(v32)
			v32, _ = mem.Read32(lf + 8)
			f.Escapement = int32(v32)
			v32, _ = mem.Read32(lf + 12)
			f.Orientation = int32(v32)
			v32, _ = mem.Read32(lf + 16)
			f.Weight = int32(v32)
			v8, _ := mem.Read8(lf + 20)
			f.Italic = v8 != 0
			v8, _ = mem.Read8(lf + 21)
			f.Underline = v8 != 0
			v8, _ = mem.Read8(lf + 22)
			f.StrikeOut = v8 != 0
			v8, _ = mem.Read8(lf + 23)
			f.CharSet = v8
			v8, _ = mem.Read8(lf + 24)
			f.OutPrecision = v8
			v8, _ = mem.Read8(lf + 25)
			f.ClipPrecision = v8
			v8, _ = mem.Read8(lf + 26)
			f.Quality = v8
			v8, _ = mem.Read8(lf + 27)
			f.PitchFamily = v8
			var buf []byte
			for i := uint64(0); i < 32; i++ {
				b, _ := mem.Read8(lf + 28 + i)
				if b == 0 {
					break
				}
				buf = append(buf, b)
			}
			f.FaceName = string(buf)
		}
		h := gdiMgr.CreateFont(f)
		ravelog.Logf("[gdi32] CreateFontIndirectExA(%q, h=%d) → 0x%x\n", f.FaceName, f.Height, h)
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "CreateHalftonePalette", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] CreateHalftonePalette(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "CreateMetaFileA", func(ctx *ntapi.TrapContext) uint32 {
		pFile := ctx.Arg(0)
		var fileName string
		if pFile != 0 {
			var buf []byte
			for i := uint64(0); ; i++ {
				b, _ := mem.Read8(pFile + i)
				if b == 0 {
					break
				}
				buf = append(buf, b)
			}
			fileName = string(buf)
		}
		h := gdiMgr.Metafiles.Create(gdi.MetafileWMF, 0, fileName)
		ravelog.Logf("[gdi32] CreateMetaFileA(%q) → 0x%x\n", fileName, h)
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "CreatePolyPolygonRgn", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[gdi32] CreatePolyPolygonRgn(0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "CreateScalableFontResourceA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[gdi32] CreateScalableFontResourceA(0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "CreateScalableFontResourceW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[gdi32] CreateScalableFontResourceW(0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry0", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[gdi32] DdEntry0(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4, arg5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry1", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[gdi32] DdEntry1(0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry10", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] DdEntry10(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry11", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] DdEntry11(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry12", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] DdEntry12(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry13", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] DdEntry13(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry14", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] DdEntry14(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry15", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] DdEntry15(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry16", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		arg6 := ctx.Arg(6)
		arg7 := ctx.Arg(7)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		_ = arg6
		_ = arg7
		ravelog.Logf("[gdi32] DdEntry16(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry17", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		arg6 := ctx.Arg(6)
		arg7 := ctx.Arg(7)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		_ = arg6
		_ = arg7
		ravelog.Logf("[gdi32] DdEntry17(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry18", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] DdEntry18(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry19", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[gdi32] DdEntry19(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4, arg5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry2", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] DdEntry2(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry20", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] DdEntry20(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry21", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] DdEntry21(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry22", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] DdEntry22(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry23", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] DdEntry23(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry24", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] DdEntry24(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry25", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] DdEntry25(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry26", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[gdi32] DdEntry26(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry27", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] DdEntry27(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry28", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] DdEntry28(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry29", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] DdEntry29(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry3", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] DdEntry3(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry30", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] DdEntry30(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry31", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] DdEntry31(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry32", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] DdEntry32(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry33", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] DdEntry33(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry34", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] DdEntry34(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry35", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] DdEntry35(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry36", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] DdEntry36(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry37", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] DdEntry37(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry38", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] DdEntry38(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry39", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] DdEntry39(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry4", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] DdEntry4(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry40", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] DdEntry40(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry41", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		arg6 := ctx.Arg(6)
		arg7 := ctx.Arg(7)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		_ = arg6
		_ = arg7
		ravelog.Logf("[gdi32] DdEntry41(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry42", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] DdEntry42(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry43", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] DdEntry43(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry44", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] DdEntry44(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry45", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] DdEntry45(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry46", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] DdEntry46(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry47", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] DdEntry47(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry48", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] DdEntry48(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry49", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] DdEntry49(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry5", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		arg6 := ctx.Arg(6)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		_ = arg6
		ravelog.Logf("[gdi32] DdEntry5(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4, arg5, arg6)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry50", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] DdEntry50(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry51", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] DdEntry51(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry52", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] DdEntry52(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry53", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] DdEntry53(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry54", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] DdEntry54(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry55", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] DdEntry55(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry56", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] DdEntry56(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry6", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] DdEntry6(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry7", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] DdEntry7(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry8", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] DdEntry8(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DdEntry9", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] DdEntry9(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DeleteColorSpace", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] DeleteColorSpace(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DescribePixelFormat", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[gdi32] DescribePixelFormat(0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DeviceCapabilitiesExA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[gdi32] DeviceCapabilitiesExA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DeviceCapabilitiesExW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[gdi32] DeviceCapabilitiesExW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "DrawEscape", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[gdi32] DrawEscape(0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EnableEUDC", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] EnableEUDC(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EndDoc", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] EndDoc(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EndFormPage", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] EndFormPage(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EndPage", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] EndPage(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EngAcquireSemaphore", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] EngAcquireSemaphore(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EngAlphaBlend", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		arg6 := ctx.Arg(6)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		_ = arg6
		ravelog.Logf("[gdi32] EngAlphaBlend(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4, arg5, arg6)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EngAssociateSurface", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] EngAssociateSurface(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EngBitBlt", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		arg6 := ctx.Arg(6)
		arg7 := ctx.Arg(7)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		_ = arg6
		_ = arg7
		ravelog.Logf("[gdi32] EngBitBlt(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EngCheckAbort", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] EngCheckAbort(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EngComputeGlyphSet", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] EngComputeGlyphSet(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EngCopyBits", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[gdi32] EngCopyBits(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4, arg5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EngCreateBitmap", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[gdi32] EngCreateBitmap(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EngCreateClip", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[gdi32] EngCreateClip()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EngCreateDeviceBitmap", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] EngCreateDeviceBitmap(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EngCreateDeviceSurface", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] EngCreateDeviceSurface(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EngCreatePalette", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[gdi32] EngCreatePalette(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4, arg5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EngCreateSemaphore", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[gdi32] EngCreateSemaphore()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EngDeleteClip", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] EngDeleteClip(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EngDeletePalette", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] EngDeletePalette(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EngDeletePath", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] EngDeletePath(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EngDeleteSemaphore", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] EngDeleteSemaphore(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EngDeleteSurface", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] EngDeleteSurface(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EngEraseSurface", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] EngEraseSurface(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EngFillPath", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		arg6 := ctx.Arg(6)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		_ = arg6
		ravelog.Logf("[gdi32] EngFillPath(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4, arg5, arg6)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EngFindResource", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[gdi32] EngFindResource(0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EngFreeModule", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] EngFreeModule(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EngGetCurrentCodePage", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] EngGetCurrentCodePage(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EngGetDriverName", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] EngGetDriverName(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EngGetPrinterDataFileName", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] EngGetPrinterDataFileName(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EngGradientFill", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		arg6 := ctx.Arg(6)
		arg7 := ctx.Arg(7)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		_ = arg6
		_ = arg7
		ravelog.Logf("[gdi32] EngGradientFill(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EngLineTo", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		arg6 := ctx.Arg(6)
		arg7 := ctx.Arg(7)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		_ = arg6
		_ = arg7
		ravelog.Logf("[gdi32] EngLineTo(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EngLoadModule", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] EngLoadModule(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EngLockSurface", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] EngLockSurface(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EngMarkBandingSurface", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] EngMarkBandingSurface(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EngMultiByteToUnicodeN", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[gdi32] EngMultiByteToUnicodeN(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EngMultiByteToWideChar", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[gdi32] EngMultiByteToWideChar(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EngPaint", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[gdi32] EngPaint(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EngPlgBlt", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		arg6 := ctx.Arg(6)
		arg7 := ctx.Arg(7)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		_ = arg6
		_ = arg7
		ravelog.Logf("[gdi32] EngPlgBlt(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EngQueryEMFInfo", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] EngQueryEMFInfo(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EngQueryLocalTime", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] EngQueryLocalTime(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EngReleaseSemaphore", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] EngReleaseSemaphore(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EngStretchBlt", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		arg6 := ctx.Arg(6)
		arg7 := ctx.Arg(7)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		_ = arg6
		_ = arg7
		ravelog.Logf("[gdi32] EngStretchBlt(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EngStretchBltROP", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		arg6 := ctx.Arg(6)
		arg7 := ctx.Arg(7)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		_ = arg6
		_ = arg7
		ravelog.Logf("[gdi32] EngStretchBltROP(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EngStrokeAndFillPath", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		arg6 := ctx.Arg(6)
		arg7 := ctx.Arg(7)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		_ = arg6
		_ = arg7
		ravelog.Logf("[gdi32] EngStrokeAndFillPath(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EngStrokePath", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		arg6 := ctx.Arg(6)
		arg7 := ctx.Arg(7)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		_ = arg6
		_ = arg7
		ravelog.Logf("[gdi32] EngStrokePath(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EngTextOut", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		arg6 := ctx.Arg(6)
		arg7 := ctx.Arg(7)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		_ = arg6
		_ = arg7
		ravelog.Logf("[gdi32] EngTextOut(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EngTransparentBlt", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		arg6 := ctx.Arg(6)
		arg7 := ctx.Arg(7)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		_ = arg6
		_ = arg7
		ravelog.Logf("[gdi32] EngTransparentBlt(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EngUnicodeToMultiByteN", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[gdi32] EngUnicodeToMultiByteN(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EngUnlockSurface", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] EngUnlockSurface(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EngWideCharToMultiByte", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[gdi32] EngWideCharToMultiByte(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EnumEnhMetaFile", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		hEmf := ctx.Arg(1)
		lpProc := ctx.Arg(2)
		_ = ctx.Arg(3) // lpData
		_ = ctx.Arg(4) // lpRect
		ravelog.Logf("[gdi32] EnumEnhMetaFile(hdc=0x%x, hEmf=0x%x, proc=0x%x)\n", hdc, hEmf, lpProc)
		ctx.SetReturn(1) // success, no records enumerated
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EnumFontFamiliesA", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		lpFamily := ctx.Arg(1)
		lpProc := ctx.Arg(2)
		lParam := ctx.Arg(3)
		var family string
		if lpFamily != 0 {
			var buf []byte
			for i := uint64(0); i < 32; i++ {
				b, _ := mem.Read8(lpFamily + i)
				if b == 0 {
					break
				}
				buf = append(buf, b)
			}
			family = string(buf)
		}
		ravelog.Logf("[gdi32] EnumFontFamiliesA(hdc=0x%x, family=%q, proc=0x%x, lParam=0x%x)\n", hdc, family, lpProc, lParam)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EnumFontFamiliesExA", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		lpLogfont := ctx.Arg(1)
		lpProc := ctx.Arg(2)
		lParam := ctx.Arg(3)
		_ = ctx.Arg(4) // dwFlags
		ravelog.Logf("[gdi32] EnumFontFamiliesExA(hdc=0x%x, logfont=0x%x, proc=0x%x, lParam=0x%x)\n", hdc, lpLogfont, lpProc, lParam)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EnumFontFamiliesW", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		lpFamily := ctx.Arg(1)
		lpProc := ctx.Arg(2)
		lParam := ctx.Arg(3)
		var family string
		if lpFamily != 0 {
			family = readGuestUTF16(lpFamily)
		}
		ravelog.Logf("[gdi32] EnumFontFamiliesW(hdc=0x%x, family=%q, proc=0x%x, lParam=0x%x)\n", hdc, family, lpProc, lParam)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EnumFontsA", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		lpFamily := ctx.Arg(1)
		lpProc := ctx.Arg(2)
		lParam := ctx.Arg(3)
		var family string
		if lpFamily != 0 {
			var buf []byte
			for i := uint64(0); i < 32; i++ {
				b, _ := mem.Read8(lpFamily + i)
				if b == 0 {
					break
				}
				buf = append(buf, b)
			}
			family = string(buf)
		}
		ravelog.Logf("[gdi32] EnumFontsA(hdc=0x%x, family=%q, proc=0x%x, lParam=0x%x)\n", hdc, family, lpProc, lParam)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EnumICMProfilesA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] EnumICMProfilesA(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EnumICMProfilesW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] EnumICMProfilesW(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EnumMetaFile", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		hMf := ctx.Arg(1)
		lpProc := ctx.Arg(2)
		_ = ctx.Arg(3) // lParam
		ravelog.Logf("[gdi32] EnumMetaFile(hdc=0x%x, hMf=0x%x, proc=0x%x)\n", hdc, hMf, lpProc)
		ctx.SetReturn(1) // success, no records
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EnumObjects", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[gdi32] EnumObjects(0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "Escape", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[gdi32] Escape(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EudcLoadLinkW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[gdi32] EudcLoadLinkW(0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "EudcUnloadLinkW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] EudcUnloadLinkW(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "ExtCreateRegion", func(ctx *ntapi.TrapContext) uint32 {
		lpXform := ctx.Arg(0)
		nCount := ctx.Arg(1)
		lpRgnData := ctx.Arg(2)
		ravelog.Logf("[gdi32] ExtCreateRegion(xform=0x%x, count=%d, data=0x%x)\n", lpXform, nCount, lpRgnData)
		ctx.SetReturn(0) // return NULL (empty region)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "ExtEscape", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[gdi32] ExtEscape(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4, arg5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "FONTOBJ_cGetAllGlyphHandles", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] FONTOBJ_cGetAllGlyphHandles(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "FONTOBJ_cGetGlyphs", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[gdi32] FONTOBJ_cGetGlyphs(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "FONTOBJ_pQueryGlyphAttrs", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] FONTOBJ_pQueryGlyphAttrs(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "FONTOBJ_pfdg", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] FONTOBJ_pfdg(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "FONTOBJ_pifi", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] FONTOBJ_pifi(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "FONTOBJ_pvTrueTypeFontFile", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] FONTOBJ_pvTrueTypeFontFile(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "FONTOBJ_pxoGetXform", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] FONTOBJ_pxoGetXform(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "FONTOBJ_vGetInfo", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] FONTOBJ_vGetInfo(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "FixBrushOrgEx", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[gdi32] FixBrushOrgEx(0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "FontIsLinked", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] FontIsLinked(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiAddFontResourceW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiAddFontResourceW(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiAddGlsBounds", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiAddGlsBounds(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiAddGlsRecord", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[gdi32] GdiAddGlsRecord(0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiArtificialDecrementDriver", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiArtificialDecrementDriver(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiCleanCacheDC", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiCleanCacheDC(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiComment", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiComment(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiConsoleTextOut", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[gdi32] GdiConsoleTextOut(0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiConvertAndCheckDC", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiConvertAndCheckDC(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiConvertBitmap", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiConvertBitmap(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiConvertBitmapV5", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[gdi32] GdiConvertBitmapV5(0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiConvertBrush", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiConvertBrush(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiConvertDC", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiConvertDC(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiConvertEnhMetaFile", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiConvertEnhMetaFile(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiConvertFont", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiConvertFont(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiConvertMetaFilePict", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiConvertMetaFilePict(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiConvertPalette", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiConvertPalette(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiConvertRegion", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiConvertRegion(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiConvertToDevmodeW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiConvertToDevmodeW(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiCreateLocalEnhMetaFile", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiCreateLocalEnhMetaFile(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiCreateLocalMetaFilePict", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiCreateLocalMetaFilePict(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiDeleteLocalDC", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiDeleteLocalDC(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiDeleteSpoolFileHandle", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiDeleteSpoolFileHandle(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiDescribePixelFormat", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[gdi32] GdiDescribePixelFormat(0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiDllInitialize", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiDllInitialize(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiDrawStream", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiDrawStream(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiEndDocEMF", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiEndDocEMF(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiEndPageEMF", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiEndPageEMF(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiEntry1", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiEntry1(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiEntry10", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiEntry10(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiEntry11", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiEntry11(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiEntry12", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiEntry12(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiEntry13", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[gdi32] GdiEntry13()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiEntry14", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiEntry14(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiEntry15", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiEntry15(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiEntry16", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiEntry16(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiEntry2", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		arg6 := ctx.Arg(6)
		arg7 := ctx.Arg(7)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		_ = arg6
		_ = arg7
		ravelog.Logf("[gdi32] GdiEntry2(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiEntry3", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiEntry3(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiEntry4", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiEntry4(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiEntry5", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiEntry5(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiEntry6", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiEntry6(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiEntry7", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiEntry7(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiEntry8", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiEntry8(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiEntry9", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[gdi32] GdiEntry9(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4, arg5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiFixUpHandle", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiFixUpHandle(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiFullscreenControl", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[gdi32] GdiFullscreenControl(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiGetBitmapBitsSize", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiGetBitmapBitsSize(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiGetCharDimensions", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiGetCharDimensions(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiGetCodePage", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiGetCodePage(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiGetDC", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiGetDC(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiGetDevmodeForPage", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[gdi32] GdiGetDevmodeForPage(0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiGetLocalBrush", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiGetLocalBrush(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiGetLocalDC", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiGetLocalDC(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiGetLocalFont", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiGetLocalFont(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiGetPageCount", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiGetPageCount(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiGetPageHandle", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiGetPageHandle(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiGetSpoolFileHandle", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiGetSpoolFileHandle(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiGetSpoolMessage", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[gdi32] GdiGetSpoolMessage(0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiGradientFill", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[gdi32] GdiGradientFill(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4, arg5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiInitSpool", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[gdi32] GdiInitSpool()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiInitializeLanguagePack", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiInitializeLanguagePack(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiIsMetaFileDC", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiIsMetaFileDC(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiIsMetaPrintDC", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiIsMetaPrintDC(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiIsPlayMetafileDC", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiIsPlayMetafileDC(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiPlayDCScript", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[gdi32] GdiPlayDCScript(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4, arg5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiPlayEMF", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[gdi32] GdiPlayEMF(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiPlayJournal", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[gdi32] GdiPlayJournal(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiPlayPageEMF", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[gdi32] GdiPlayPageEMF(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiPlayPrivatePageEMF", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiPlayPrivatePageEMF(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiPlayScript", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		arg6 := ctx.Arg(6)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		_ = arg6
		ravelog.Logf("[gdi32] GdiPlayScript(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4, arg5, arg6)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiPrinterThunk", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiPrinterThunk(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiProcessSetup", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[gdi32] GdiProcessSetup()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiQueryFonts", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiQueryFonts(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiQueryTable", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[gdi32] GdiQueryTable()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiRealizationInfo", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiRealizationInfo(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiReleaseDC", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiReleaseDC(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiReleaseLocalDC", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiReleaseLocalDC(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiResetDCEMF", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiResetDCEMF(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiSetAttrs", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiSetAttrs(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiSetLastError", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiSetLastError(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiSetPixelFormat", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiSetPixelFormat(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiSetServerAttr", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiSetServerAttr(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiStartDocEMF", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiStartDocEMF(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiStartPageEMF", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiStartPageEMF(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiSwapBuffers", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiSwapBuffers(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiTransparentBlt", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		arg6 := ctx.Arg(6)
		arg7 := ctx.Arg(7)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		_ = arg6
		_ = arg7
		ravelog.Logf("[gdi32] GdiTransparentBlt(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GdiValidateHandle", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GdiValidateHandle(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetAspectRatioFilterEx", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GetAspectRatioFilterEx(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetBitmapAttributes", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GetBitmapAttributes(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetBoundsRect", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		lprcBounds := ctx.Arg(1)
		flags := ctx.Arg(2)
		ravelog.Logf("[gdi32] GetBoundsRect(hdc=0x%x, lprc=0x%x, flags=0x%x)\n", hdc, lprcBounds, flags)
		if lprcBounds != 0 {
			ctx.Mem.Write32(lprcBounds, 0)
			ctx.Mem.Write32(lprcBounds+4, 0)
			ctx.Mem.Write32(lprcBounds+8, 0)
			ctx.Mem.Write32(lprcBounds+12, 0)
		}
		ctx.SetReturn(0) // DCB_RESET - bounds rectangle is empty
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetBrushAttributes", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GetBrushAttributes(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetBrushOrgEx", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GetBrushOrgEx(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetCharABCWidthsA", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		first := ctx.Arg(1)
		last := ctx.Arg(2)
		_ = ctx.Arg(3) // lpABC
		ravelog.Logf("[gdi32] GetCharABCWidthsA(hdc=0x%x, first=%d, last=%d)\n", hdc, first, last)
		ctx.SetReturn(0) // failure
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetCharABCWidthsFloatA", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		first := ctx.Arg(1)
		last := ctx.Arg(2)
		_ = ctx.Arg(3) // lpABCF
		ravelog.Logf("[gdi32] GetCharABCWidthsFloatA(hdc=0x%x, first=%d, last=%d)\n", hdc, first, last)
		ctx.SetReturn(0) // failure
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetCharABCWidthsI", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		giFirst := ctx.Arg(1)
		cgi := ctx.Arg(2)
		_ = ctx.Arg(3) // pgi
		_ = ctx.Arg(4) // lpABC
		ravelog.Logf("[gdi32] GetCharABCWidthsI(hdc=0x%x, first=%d, count=%d)\n", hdc, giFirst, cgi)
		ctx.SetReturn(0) // failure
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetCharWidthFloatA", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		first := ctx.Arg(1)
		last := ctx.Arg(2)
		_ = ctx.Arg(3) // lpBuffer
		ravelog.Logf("[gdi32] GetCharWidthFloatA(hdc=0x%x, first=%d, last=%d)\n", hdc, first, last)
		ctx.SetReturn(0) // failure
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetCharWidthI", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		giFirst := ctx.Arg(1)
		cgi := ctx.Arg(2)
		_ = ctx.Arg(3) // pgi
		_ = ctx.Arg(4) // lpBuffer
		ravelog.Logf("[gdi32] GetCharWidthI(hdc=0x%x, first=%d, count=%d)\n", hdc, giFirst, cgi)
		ctx.SetReturn(0) // failure
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetCharWidthInfo", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GetCharWidthInfo(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetCharacterPlacementA", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		lpString := ctx.Arg(1)
		nCount := ctx.Arg(2)
		nMaxExtent := ctx.Arg(3)
		lpResults := ctx.Arg(4)
		dwFlags := ctx.Arg(5)
		ravelog.Logf("[gdi32] GetCharacterPlacementA(hdc=0x%x, str=0x%x, n=%d, max=%d, res=0x%x, flags=0x%x)\n", hdc, lpString, nCount, nMaxExtent, lpResults, dwFlags)
		ctx.SetReturn(0) // failure
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetCharacterPlacementW", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		lpString := ctx.Arg(1)
		nCount := ctx.Arg(2)
		nMaxExtent := ctx.Arg(3)
		lpResults := ctx.Arg(4)
		dwFlags := ctx.Arg(5)
		ravelog.Logf("[gdi32] GetCharacterPlacementW(hdc=0x%x, str=0x%x, n=%d, max=%d, res=0x%x, flags=0x%x)\n", hdc, lpString, nCount, nMaxExtent, lpResults, dwFlags)
		ctx.SetReturn(0) // failure
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetColorAdjustment", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GetColorAdjustment(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetColorSpace", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GetColorSpace(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetDIBColorTable", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		iStart := ctx.Arg(1)
		cEntries := ctx.Arg(2)
		pColors := ctx.Arg(3)
		ravelog.Logf("[gdi32] GetDIBColorTable(hdc=0x%x, start=%d, count=%d, buf=0x%x)\n", hdc, iStart, cEntries, pColors)
		// Return 0 entries (no color table available for 32bpp DIBs)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetDeviceGammaRamp", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GetDeviceGammaRamp(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetETM", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GetETM(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetEUDCTimeStamp", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[gdi32] GetEUDCTimeStamp()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetEUDCTimeStampExW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GetEUDCTimeStampExW(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetEnhMetaFileA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GetEnhMetaFileA(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetEnhMetaFileBits", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GetEnhMetaFileBits(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetEnhMetaFileDescriptionA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GetEnhMetaFileDescriptionA(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetEnhMetaFileDescriptionW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GetEnhMetaFileDescriptionW(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetEnhMetaFileHeader", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GetEnhMetaFileHeader(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetEnhMetaFilePixelFormat", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GetEnhMetaFilePixelFormat(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetEnhMetaFileW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GetEnhMetaFileW(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetFontAssocStatus", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GetFontAssocStatus(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetFontLanguageInfo", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		ravelog.Logf("[gdi32] GetFontLanguageInfo(hdc=0x%x)\n", hdc)
		ctx.SetReturn(0) // no complex script support
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetFontResourceInfoW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[gdi32] GetFontResourceInfoW(0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetFontUnicodeRanges", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		lpgs := ctx.Arg(1)
		ravelog.Logf("[gdi32] GetFontUnicodeRanges(hdc=0x%x, lpgs=0x%x)\n", hdc, lpgs)
		ctx.SetReturn(0) // failure / no data
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetGlyphIndicesA", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		lpstr := ctx.Arg(1)
		c := ctx.Arg(2)
		_ = ctx.Arg(3) // pgi
		_ = ctx.Arg(4) // fl
		ravelog.Logf("[gdi32] GetGlyphIndicesA(hdc=0x%x, str=0x%x, count=%d)\n", hdc, lpstr, c)
		ctx.SetReturn(0xFFFFFFFF) // GDI_ERROR
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetGlyphOutline", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		uChar := ctx.Arg(1)
		fuFormat := ctx.Arg(2)
		_ = ctx.Arg(3) // lpgm
		_ = ctx.Arg(4) // cjBuffer
		_ = ctx.Arg(5) // pvBuffer
		_ = ctx.Arg(6) // lpmat2
		ravelog.Logf("[gdi32] GetGlyphOutline(hdc=0x%x, char=0x%x, fmt=0x%x)\n", hdc, uChar, fuFormat)
		ctx.SetReturn(0xFFFFFFFF) // GDI_ERROR
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetGlyphOutlineA", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		uChar := ctx.Arg(1)
		fuFormat := ctx.Arg(2)
		_ = ctx.Arg(3) // lpgm
		_ = ctx.Arg(4) // cjBuffer
		_ = ctx.Arg(5) // pvBuffer
		_ = ctx.Arg(6) // lpmat2
		ravelog.Logf("[gdi32] GetGlyphOutlineA(hdc=0x%x, char=0x%x, fmt=0x%x)\n", hdc, uChar, fuFormat)
		ctx.SetReturn(0xFFFFFFFF) // GDI_ERROR
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetGlyphOutlineWow", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		uChar := ctx.Arg(1)
		fuFormat := ctx.Arg(2)
		ravelog.Logf("[gdi32] GetGlyphOutlineWow(hdc=0x%x, char=0x%x, fmt=0x%x)\n", hdc, uChar, fuFormat)
		ctx.SetReturn(0xFFFFFFFF) // GDI_ERROR
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetHFONT", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GetHFONT(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetICMProfileA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GetICMProfileA(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetICMProfileW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GetICMProfileW(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetKerningPairs", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		nPairs := ctx.Arg(1)
		_ = ctx.Arg(2) // lpKernPair
		ravelog.Logf("[gdi32] GetKerningPairs(hdc=0x%x, nPairs=%d)\n", hdc, nPairs)
		ctx.SetReturn(0) // no kerning pairs
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetKerningPairsA", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		nPairs := ctx.Arg(1)
		_ = ctx.Arg(2) // lpKernPair
		ravelog.Logf("[gdi32] GetKerningPairsA(hdc=0x%x, nPairs=%d)\n", hdc, nPairs)
		ctx.SetReturn(0) // no kerning pairs
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetLogColorSpaceA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GetLogColorSpaceA(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetLogColorSpaceW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GetLogColorSpaceW(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetMetaFileA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GetMetaFileA(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetMetaFileBitsEx", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GetMetaFileBitsEx(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetMetaFileW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GetMetaFileW(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetMetaRgn", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		hrgn := ctx.Arg(1)
		ravelog.Logf("[gdi32] GetMetaRgn(hdc=0x%x, hrgn=0x%x)\n", hdc, hrgn)
		ctx.SetReturn(0) // 0 = no meta region set
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetMiterLimit", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GetMiterLimit(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetOutlineTextMetricsA", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		cbData := ctx.Arg(1)
		_ = ctx.Arg(2) // lpOTM
		ravelog.Logf("[gdi32] GetOutlineTextMetricsA(hdc=0x%x, cb=%d)\n", hdc, cbData)
		ctx.SetReturn(0) // failure - no outline text metrics available
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetPixelFormat", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GetPixelFormat(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetRandomRgn", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		hrgn := ctx.Arg(1)
		iNum := int32(ctx.Arg(2))
		ravelog.Logf("[gdi32] GetRandomRgn(hdc=0x%x, hrgn=0x%x, iNum=%d)\n", hdc, hrgn, iNum)
		// -1 = no clipping region, 0 = error, 1 = region returned
		ctx.SetReturn(uint64(uint32(0xFFFFFFFF))) // -1: no region
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetRasterizerCaps", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GetRasterizerCaps(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetRegionData", func(ctx *ntapi.TrapContext) uint32 {
		hrgn := ctx.Arg(0)
		nCount := ctx.Arg(1)
		_ = ctx.Arg(2) // lpRgnData
		ravelog.Logf("[gdi32] GetRegionData(hrgn=0x%x, nCount=%d)\n", hrgn, nCount)
		ctx.SetReturn(0) // failure
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetRelAbs", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GetRelAbs(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetStringBitmapA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[gdi32] GetStringBitmapA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetStringBitmapW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[gdi32] GetStringBitmapW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetSystemPaletteUse", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GetSystemPaletteUse(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetTextCharset", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		ravelog.Logf("[gdi32] GetTextCharset(hdc=0x%x)\n", hdc)
		ctx.SetReturn(1) // DEFAULT_CHARSET
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetTextCharsetInfo", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		lpSig := ctx.Arg(1)
		_ = ctx.Arg(2) // dwFlags
		ravelog.Logf("[gdi32] GetTextCharsetInfo(hdc=0x%x, lpSig=0x%x)\n", hdc, lpSig)
		// Zero out FONTSIGNATURE if provided (24 bytes: 4 USB DWORDs + 2 CSB DWORDs)
		if lpSig != 0 {
			for i := uint64(0); i < 24; i += 4 {
				ctx.Mem.Write32(lpSig+i, 0)
			}
		}
		ctx.SetReturn(1) // DEFAULT_CHARSET
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetTextExtentExPointI", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		_ = ctx.Arg(1) // pgiIn
		cgi := int32(ctx.Arg(2))
		nMaxExtent := ctx.Arg(3)
		lpnFit := ctx.Arg(4)
		_ = ctx.Arg(5) // lpnDx
		lpSize := ctx.Arg(6)
		ravelog.Logf("[gdi32] GetTextExtentExPointI(hdc=0x%x, count=%d, maxExt=%d)\n", hdc, cgi, nMaxExtent)
		dc := getDC(hdc)
		charW := int32(8)
		charH := int32(16)
		if dc.Font != nil {
			if dc.Font.AveCharWidth > 0 {
				charW = dc.Font.AveCharWidth
			}
			if dc.Font.CellHeight > 0 {
				charH = dc.Font.CellHeight
			}
		}
		if lpSize != 0 {
			ctx.Mem.Write32(lpSize, uint32(charW*cgi))
			ctx.Mem.Write32(lpSize+4, uint32(charH))
		}
		if lpnFit != 0 {
			ctx.Mem.Write32(lpnFit, uint32(cgi))
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetTextExtentExPointWPri", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		_ = ctx.Arg(1) // lpszStr
		cchString := int32(ctx.Arg(2))
		nMaxExtent := ctx.Arg(3)
		lpnFit := ctx.Arg(4)
		_ = ctx.Arg(5) // lpnDx
		lpSize := ctx.Arg(6)
		ravelog.Logf("[gdi32] GetTextExtentExPointWPri(hdc=0x%x, count=%d, maxExt=%d)\n", hdc, cchString, nMaxExtent)
		dc := getDC(hdc)
		charW := int32(8)
		charH := int32(16)
		if dc.Font != nil {
			if dc.Font.AveCharWidth > 0 {
				charW = dc.Font.AveCharWidth
			}
			if dc.Font.CellHeight > 0 {
				charH = dc.Font.CellHeight
			}
		}
		if lpSize != 0 {
			ctx.Mem.Write32(lpSize, uint32(charW*cchString))
			ctx.Mem.Write32(lpSize+4, uint32(charH))
		}
		if lpnFit != 0 {
			ctx.Mem.Write32(lpnFit, uint32(cchString))
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetTextExtentPointA", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		_ = ctx.Arg(1) // lpString
		c := int32(ctx.Arg(2))
		lpSize := ctx.Arg(3)
		ravelog.Logf("[gdi32] GetTextExtentPointA(hdc=0x%x, count=%d)\n", hdc, c)
		dc := getDC(hdc)
		charW := int32(8)
		charH := int32(16)
		if dc.Font != nil {
			if dc.Font.AveCharWidth > 0 {
				charW = dc.Font.AveCharWidth
			}
			if dc.Font.CellHeight > 0 {
				charH = dc.Font.CellHeight
			}
		}
		if lpSize != 0 {
			ctx.Mem.Write32(lpSize, uint32(charW*c))
			ctx.Mem.Write32(lpSize+4, uint32(charH))
		}
		ctx.SetReturn(1) // success
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetTextExtentPointI", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		_ = ctx.Arg(1) // pgiIn
		cgi := int32(ctx.Arg(2))
		lpSize := ctx.Arg(3)
		ravelog.Logf("[gdi32] GetTextExtentPointI(hdc=0x%x, count=%d)\n", hdc, cgi)
		dc := getDC(hdc)
		charW := int32(8)
		charH := int32(16)
		if dc.Font != nil {
			if dc.Font.AveCharWidth > 0 {
				charW = dc.Font.AveCharWidth
			}
			if dc.Font.CellHeight > 0 {
				charH = dc.Font.CellHeight
			}
		}
		if lpSize != 0 {
			ctx.Mem.Write32(lpSize, uint32(charW*cgi))
			ctx.Mem.Write32(lpSize+4, uint32(charH))
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetTextExtentPointW", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		_ = ctx.Arg(1) // lpString
		c := int32(ctx.Arg(2))
		lpSize := ctx.Arg(3)
		ravelog.Logf("[gdi32] GetTextExtentPointW(hdc=0x%x, count=%d)\n", hdc, c)
		dc := getDC(hdc)
		charW := int32(8)
		charH := int32(16)
		if dc.Font != nil {
			if dc.Font.AveCharWidth > 0 {
				charW = dc.Font.AveCharWidth
			}
			if dc.Font.CellHeight > 0 {
				charH = dc.Font.CellHeight
			}
		}
		if lpSize != 0 {
			ctx.Mem.Write32(lpSize, uint32(charW*c))
			ctx.Mem.Write32(lpSize+4, uint32(charH))
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetTextFaceAliasW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GetTextFaceAliasW(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetTransform", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] GetTransform(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "GetWinMetaFileBits", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[gdi32] GetWinMetaFileBits(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "HT_Get8BPPFormatPalette", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[gdi32] HT_Get8BPPFormatPalette(0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "HT_Get8BPPMaskPalette", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[gdi32] HT_Get8BPPMaskPalette(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4, arg5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "IsValidEnhMetaRecord", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] IsValidEnhMetaRecord(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "IsValidEnhMetaRecordOffExt", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[gdi32] IsValidEnhMetaRecordOffExt(0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "LineDDA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[gdi32] LineDDA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4, arg5)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "MaskBlt", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		arg6 := ctx.Arg(6)
		arg7 := ctx.Arg(7)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		_ = arg6
		_ = arg7
		ravelog.Logf("[gdi32] MaskBlt(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "MirrorRgn", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] MirrorRgn(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "NamedEscape", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		arg6 := ctx.Arg(6)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		_ = arg6
		ravelog.Logf("[gdi32] NamedEscape(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4, arg5, arg6)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "PATHOBJ_bEnum", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] PATHOBJ_bEnum(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "PATHOBJ_bEnumClipLines", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] PATHOBJ_bEnumClipLines(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "PATHOBJ_vEnumStart", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] PATHOBJ_vEnumStart(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "PATHOBJ_vEnumStartClipLines", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[gdi32] PATHOBJ_vEnumStartClipLines(0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "PATHOBJ_vGetBounds", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] PATHOBJ_vGetBounds(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "PlayEnhMetaFileRecord", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		_ = ctx.Arg(1) // lpHandleTable
		_ = ctx.Arg(2) // lpEnhMetaRecord
		_ = ctx.Arg(3) // nHandles
		ravelog.Logf("[gdi32] PlayEnhMetaFileRecord(hdc=0x%x)\n", hdc)
		ctx.SetReturn(1) // success
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "PlayMetaFileRecord", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		_ = ctx.Arg(1) // lpHandleTable
		_ = ctx.Arg(2) // lpMetaRecord
		_ = ctx.Arg(3) // nHandles
		ravelog.Logf("[gdi32] PlayMetaFileRecord(hdc=0x%x)\n", hdc)
		ctx.SetReturn(1) // success
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "PlgBlt", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		arg6 := ctx.Arg(6)
		arg7 := ctx.Arg(7)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		_ = arg6
		_ = arg7
		ravelog.Logf("[gdi32] PlgBlt(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "PolyDraw", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[gdi32] PolyDraw(0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "PolyPatBlt", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[gdi32] PolyPatBlt(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "PolyTextOutA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] PolyTextOutA(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "PolyTextOutW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] PolyTextOutW(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "PtVisible", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] PtVisible(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "QueryFontAssocStatus", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[gdi32] QueryFontAssocStatus()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "RemoveFontResourceA", func(ctx *ntapi.TrapContext) uint32 {
		pName := ctx.Arg(0)
		var name string
		if pName != 0 {
			var buf []byte
			for i := uint64(0); ; i++ {
				b, _ := mem.Read8(pName + i)
				if b == 0 {
					break
				}
				buf = append(buf, b)
			}
			name = string(buf)
		}
		ravelog.Logf("[gdi32] RemoveFontResourceA(%q)\n", name)
		ctx.SetReturn(1) // success
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "RemoveFontResourceExA", func(ctx *ntapi.TrapContext) uint32 {
		pName := ctx.Arg(0)
		fl := ctx.Arg(1)
		_ = ctx.Arg(2) // reserved
		var name string
		if pName != 0 {
			var buf []byte
			for i := uint64(0); ; i++ {
				b, _ := mem.Read8(pName + i)
				if b == 0 {
					break
				}
				buf = append(buf, b)
			}
			name = string(buf)
		}
		ravelog.Logf("[gdi32] RemoveFontResourceExA(%q, flags=0x%x)\n", name, fl)
		ctx.SetReturn(1) // success
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "RemoveFontResourceTracking", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] RemoveFontResourceTracking(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "ResetDCA", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		_ = ctx.Arg(1) // lpDevMode
		ravelog.Logf("[gdi32] ResetDCA(hdc=0x%x)\n", hdc)
		ctx.SetReturn(hdc) // return the DC handle on success
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "ResizePalette", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] ResizePalette(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "STROBJ_bEnum", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] STROBJ_bEnum(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "STROBJ_bEnumPositionsOnly", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] STROBJ_bEnumPositionsOnly(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "STROBJ_bGetAdvanceWidths", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[gdi32] STROBJ_bGetAdvanceWidths(0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "STROBJ_dwGetCodePage", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] STROBJ_dwGetCodePage(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "STROBJ_vEnumStart", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] STROBJ_vEnumStart(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SelectBrushLocal", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] SelectBrushLocal(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SelectFontLocal", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] SelectFontLocal(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SetAbortProc", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] SetAbortProc(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SetBitmapAttributes", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] SetBitmapAttributes(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SetBoundsRect", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		_ = ctx.Arg(1) // lprcBounds
		flags := ctx.Arg(2)
		ravelog.Logf("[gdi32] SetBoundsRect(hdc=0x%x, flags=0x%x)\n", hdc, flags)
		// Return previous state: DCB_DISABLE (0x0008) - bounds accumulation was disabled
		ctx.SetReturn(0x0008)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SetBrushAttributes", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] SetBrushAttributes(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SetColorAdjustment", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] SetColorAdjustment(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SetColorSpace", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] SetColorSpace(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SetDIBColorTable", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		iStart := ctx.Arg(1)
		cEntries := ctx.Arg(2)
		_ = ctx.Arg(3) // prgbq
		ravelog.Logf("[gdi32] SetDIBColorTable(hdc=0x%x, start=%d, count=%d)\n", hdc, iStart, cEntries)
		ctx.SetReturn(cEntries) // return number of entries set
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SetDeviceGammaRamp", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] SetDeviceGammaRamp(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SetEnhMetaFileBits", func(ctx *ntapi.TrapContext) uint32 {
		nSize := ctx.Arg(0)
		_ = ctx.Arg(1) // pb
		ravelog.Logf("[gdi32] SetEnhMetaFileBits(size=%d)\n", nSize)
		// Create a dummy closed EMF from the raw bits
		h := gdiMgr.Metafiles.Create(gdi.MetafileEMF, 0, "")
		gdiMgr.Metafiles.Close(0)
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SetFontEnumeration", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] SetFontEnumeration(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SetICMMode", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] SetICMMode(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SetICMProfileA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] SetICMProfileA(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SetICMProfileW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] SetICMProfileW(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SetLayoutWidth", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] SetLayoutWidth(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SetMagicColors", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] SetMagicColors(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SetMapperFlags", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] SetMapperFlags(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SetMetaFileBitsEx", func(ctx *ntapi.TrapContext) uint32 {
		nSize := ctx.Arg(0)
		_ = ctx.Arg(1) // pb
		ravelog.Logf("[gdi32] SetMetaFileBitsEx(size=%d)\n", nSize)
		h := gdiMgr.Metafiles.Create(gdi.MetafileWMF, 0, "")
		gdiMgr.Metafiles.Close(0)
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SetMetaRgn", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		ravelog.Logf("[gdi32] SetMetaRgn(hdc=0x%x)\n", hdc)
		ctx.SetReturn(0) // ERROR (NULLREGION=1 would be success)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SetMiterLimit", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] SetMiterLimit(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SetPixelFormat", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] SetPixelFormat(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SetRelAbs", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] SetRelAbs(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SetSystemPaletteUse", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] SetSystemPaletteUse(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SetTextJustification", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] SetTextJustification(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SetVirtualResolution", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[gdi32] SetVirtualResolution(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SetWinMetaFileBits", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[gdi32] SetWinMetaFileBits(0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "StartDocA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] StartDocA(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "StartDocW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] StartDocW(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "StartFormPage", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] StartFormPage(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "StartPage", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] StartPage(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "SwapBuffers", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] SwapBuffers(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "TranslateCharsetInfo", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] TranslateCharsetInfo(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "UnloadNetworkFonts", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] UnloadNetworkFonts(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "UnrealizeObject", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] UnrealizeObject(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "UpdateICMRegKeyA", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[gdi32] UpdateICMRegKeyA(0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "UpdateICMRegKeyW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[gdi32] UpdateICMRegKeyW(0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "XFORMOBJ_bApplyXform", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		ravelog.Logf("[gdi32] XFORMOBJ_bApplyXform(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "XFORMOBJ_iGetXform", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] XFORMOBJ_iGetXform(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "XLATEOBJ_cGetPalette", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[gdi32] XLATEOBJ_cGetPalette(0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "XLATEOBJ_hGetColorTransform", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] XLATEOBJ_hGetColorTransform(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "XLATEOBJ_iXlate", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] XLATEOBJ_iXlate(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "XLATEOBJ_piVector", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] XLATEOBJ_piVector(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "bInitSystemAndFontsDirectoriesW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		_ = arg0
		ravelog.Logf("[gdi32] bInitSystemAndFontsDirectoriesW(0x%x)\n", arg0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "bMakePathNameW", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[gdi32] bMakePathNameW(0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "cGetTTFFromFOT", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		arg6 := ctx.Arg(6)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		_ = arg6
		ravelog.Logf("[gdi32] cGetTTFFromFOT(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4, arg5, arg6)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(gdi32, "gdiPlaySpoolStream", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		arg4 := ctx.Arg(4)
		arg5 := ctx.Arg(5)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		_ = arg4
		_ = arg5
		ravelog.Logf("[gdi32] gdiPlaySpoolStream(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", arg0, arg1, arg2, arg3, arg4, arg5)
		ctx.SetReturn(1)
		return 0
	})
}

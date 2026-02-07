//go:build guest_windows

package main

import (
	"fmt"
	"math"
	"strings"

	gdi "github.com/mirkobrombin/Raven/pkg/gdi"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
	"github.com/mirkobrombin/Raven/pkg/win32"
)

type win32uLayeredAttrs struct {
	colorKey uint32
	alpha    uint8
	flags    uint32
}

var (
	win32uCursorHandle   uint64 = 32512
	win32uCursorPosX     int32
	win32uCursorPosY     int32
	win32uWindowRgns     = map[uint64]uint64{}
	win32uLayeredWindows = map[uint64]win32uLayeredAttrs{}
)

func registerWin32UHandlers(hctx *HandlerCtx) {
	dll, ok := hctx.SynthByName["win32u.dll"]
	if !ok {
		return
	}

	d := hctx.Disp
	mem := hctx.Mem
	gdiMgr := hctx.GdiMgr
	getDC := hctx.GetDCFn
	allocScreenDC := hctx.AllocScreenDC
	readGuestUTF16 := hctx.ReadGuestUTF16
	readGuestUTF16N := hctx.ReadGuestUTF16N
	clientAreaOrigin := hctx.ClientAreaOrigin
	queuePaint := hctx.QueuePaint

	nextDynID := uint32(ntapi.DynExportIDBase + 0x600)
	reg := func(name string, handler ntapi.TrapHandler) {
		if _, ok := dll.Exports[name]; ok {
			d.RegisterAutoStubHandler(dll, name, handler)
			return
		}
		d.RegisterDynamicHandler(mem, dll, name, nextDynID, handler)
		nextDynID++
	}

	identityXform := [6]uint32{0x3F800000, 0, 0, 0x3F800000, 0, 0}
	readXformMem := func(ctx *ntapi.TrapContext, addr uint64) [6]uint32 {
		var xf [6]uint32
		for i := 0; i < 6; i++ {
			xf[i], _ = ctx.Mem.Read32(addr + uint64(i)*4)
		}
		return xf
	}
	writeXformMem := func(ctx *ntapi.TrapContext, addr uint64, xf [6]uint32) {
		for i := 0; i < 6; i++ {
			ctx.Mem.Write32(addr+uint64(i)*4, xf[i])
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
	rawToXform := func(xf [6]uint32) gdi.XForm {
		return gdi.XForm{
			EM11: math.Float32frombits(xf[0]),
			EM12: math.Float32frombits(xf[1]),
			EM21: math.Float32frombits(xf[2]),
			EM22: math.Float32frombits(xf[3]),
			EDx:  math.Float32frombits(xf[4]),
			EDy:  math.Float32frombits(xf[5]),
		}
	}
	xformMul := func(a, b [6]uint32) [6]uint32 {
		af := [6]float32{}
		bf := [6]float32{}
		for i := 0; i < 6; i++ {
			af[i] = math.Float32frombits(a[i])
			bf[i] = math.Float32frombits(b[i])
		}
		var r [6]float32
		r[0] = af[0]*bf[0] + af[1]*bf[2]
		r[1] = af[0]*bf[1] + af[1]*bf[3]
		r[2] = af[2]*bf[0] + af[3]*bf[2]
		r[3] = af[2]*bf[1] + af[3]*bf[3]
		r[4] = af[4]*bf[0] + af[5]*bf[2] + bf[4]
		r[5] = af[4]*bf[1] + af[5]*bf[3] + bf[5]
		var out [6]uint32
		for i := 0; i < 6; i++ {
			out[i] = math.Float32bits(r[i])
		}
		return out
	}
	writeBitmapObject := func(ctx *ntapi.TrapContext, pv uint64, bm *gdi.Bitmap) {
		if pv == 0 || bm == nil {
			return
		}
		widthBytes := bm.Width * 4
		if widthBytes < 0 {
			widthBytes = -widthBytes
		}
		bitsPixel := bm.BitCount
		if bitsPixel == 0 {
			bitsPixel = 32
		}
		ctx.Mem.Write32(pv, 0)
		ctx.Mem.Write32(pv+4, uint32(bm.Width))
		ctx.Mem.Write32(pv+8, uint32(bm.Height))
		ctx.Mem.Write32(pv+12, uint32(widthBytes))
		ctx.Mem.Write16(pv+16, 1)
		ctx.Mem.Write16(pv+18, uint16(bitsPixel))
		ctx.Mem.Write32(pv+20, 0)
		ctx.Mem.Write64(pv+24, bm.Bits)
	}
	writeObjectInfo := func(ctx *ntapi.TrapContext, h, pv uint64) {
		obj := gdiMgr.GetObject(h)
		if obj == nil {
			ctx.SetReturn(0)
			return
		}
		switch obj.Type {
		case gdi.ObjPen:
			ctx.SetReturn(16)
			if pv != 0 && obj.Pen != nil {
				ctx.Mem.Write32(pv, uint32(obj.Pen.Style))
				ctx.Mem.Write32(pv+4, uint32(obj.Pen.Width))
				ctx.Mem.Write32(pv+8, 0)
				ctx.Mem.Write32(pv+12, obj.Pen.Color)
			}
		case gdi.ObjBrush:
			ctx.SetReturn(16)
			if pv != 0 && obj.Brush != nil {
				ctx.Mem.Write32(pv, uint32(obj.Brush.Style))
				ctx.Mem.Write32(pv+4, obj.Brush.Color)
				ctx.Mem.Write64(pv+8, uint64(obj.Brush.Hatch))
			}
		case gdi.ObjFont:
			ctx.SetReturn(92)
			if pv != 0 && obj.Font != nil {
				f := obj.Font
				ctx.Mem.Write32(pv, uint32(f.Height))
				ctx.Mem.Write32(pv+4, uint32(f.Width))
				ctx.Mem.Write32(pv+8, uint32(f.Escapement))
				ctx.Mem.Write32(pv+12, uint32(f.Orientation))
				weight := f.Weight
				if weight == 0 {
					weight = 400
				}
				ctx.Mem.Write32(pv+16, uint32(weight))
				if f.Italic {
					ctx.Mem.Write8(pv+20, 1)
				}
				if f.Underline {
					ctx.Mem.Write8(pv+21, 1)
				}
				if f.StrikeOut {
					ctx.Mem.Write8(pv+22, 1)
				}
				ctx.Mem.Write8(pv+23, f.CharSet)
				ctx.Mem.Write8(pv+24, f.OutPrecision)
				ctx.Mem.Write8(pv+25, f.ClipPrecision)
				ctx.Mem.Write8(pv+26, f.Quality)
				ctx.Mem.Write8(pv+27, f.PitchFamily)
				face := []rune(f.FaceName)
				if len(face) > 31 {
					face = face[:31]
				}
				for i, ch := range face {
					ctx.Mem.Write16(pv+28+uint64(i)*2, uint16(ch))
				}
				ctx.Mem.Write16(pv+28+uint64(len(face))*2, 0)
			}
		case gdi.ObjBitmap:
			ctx.SetReturn(32)
			writeBitmapObject(ctx, pv, obj.Bitmap)
		default:
			ctx.SetReturn(0)
		}
	}
	deviceCaps := func(idx uint64) uint64 {
		val := uint64(0)
		w, h := uint64(1920), uint64(1080)
		if hctx.WlWindow != nil {
			w = uint64(hctx.WlWindow.Width)
			h = uint64(hctx.WlWindow.Height)
		}
		switch idx {
		case 2:
			val = 1
		case 4:
			val = 508
		case 6:
			val = 285
		case 8:
			val = w
		case 10:
			val = h
		case 12:
			val = 32
		case 14:
			val = 1
		case 24:
			val = 0xFFFFFF
		case 26:
			val = 0x0001
		case 38:
			val = 0x7E99
		case 88, 90:
			val = 96
		case 104:
			val = 256
		case 108:
			val = 24
		case 110, 118:
			val = w
		case 111, 117:
			val = h
		case 116:
			val = 60
		case 120:
			val = 0x0002
		case 121:
			val = 0x0003
		}
		return val
	}
	writeMsg := func(pMsg, hwnd uint64, message uint32, wParam, lParam uint64) {
		if pMsg == 0 {
			return
		}
		mem.Write64(pMsg, hwnd)
		mem.Write32(pMsg+8, message)
		mem.Write32(pMsg+12, 0)
		mem.Write64(pMsg+16, wParam)
		mem.Write64(pMsg+24, lParam)
		mem.Write32(pMsg+32, 0)
		mem.Write32(pMsg+36, uint32(win32uCursorPosX))
		mem.Write32(pMsg+40, uint32(win32uCursorPosY))
		mem.Write32(pMsg+44, 0)
	}
	absoluteClientRect := func(hwnd uint64) (int32, int32, int32, int32) {
		ox, oy := clientAreaOrigin(hwnd)
		if cs, ok := hctx.HwndChildren[hwnd]; ok {
			return cs.x, cs.y, cs.x + cs.w, cs.y + cs.h
		}
		if hwnd == hctx.MainHWND && hctx.WlWindow != nil {
			w := hctx.WlWindow.Width
			h := hctx.WlWindow.Height
			if _, hasMenu := hctx.HwndMenuBar[hwnd]; hasMenu && h > win32.GetSystemMetrics(win32.SM_CYMENU) {
				h -= win32.GetSystemMetrics(win32.SM_CYMENU)
			}
			return ox, oy, ox + w, oy + h
		}
		if wnd := win32.Global.Get(hwnd); wnd != nil {
			return wnd.RcClient.Left, wnd.RcClient.Top, wnd.RcClient.Right, wnd.RcClient.Bottom
		}
		return ox, oy, ox, oy
	}
	getTopLevelClientSize := func(hwnd uint64) (int32, int32) {
		if hwnd == hctx.MainHWND && hctx.WlWindow != nil {
			w := hctx.WlWindow.Width
			h := hctx.WlWindow.Height
			if _, hasMenu := hctx.HwndMenuBar[hwnd]; hasMenu && h > win32.GetSystemMetrics(win32.SM_CYMENU) {
				h -= win32.GetSystemMetrics(win32.SM_CYMENU)
			}
			return w, h
		}
		if wnd := win32.Global.Get(hwnd); wnd != nil {
			return wnd.RcClient.Width(), wnd.RcClient.Height()
		}
		return 800, 600
	}
	systemParametersInfo := func(ctx *ntapi.TrapContext, action, data uint64) {
		w := int32(1920)
		h := int32(1080)
		if hctx.WlWindow != nil {
			w = hctx.WlWindow.Width
			h = hctx.WlWindow.Height
		}
		writeLogFont := func(base uint64, name string, height int32) {
			ctx.Mem.Write32(base+0, uint32(height))
			ctx.Mem.Write32(base+16, 400)
			ctx.Mem.Write8(base+23, 1)
			ctx.Mem.Write8(base+26, 5)
			ctx.Mem.Write8(base+27, 0x22)
			ws := utf16Encode(name)
			for i, r := range ws {
				ctx.Mem.Write16(base+28+uint64(i)*2, r)
			}
			ctx.Mem.Write16(base+28+uint64(len(ws))*2, 0)
		}
		switch action {
		case 0x0026:
			if data != 0 {
				ctx.Mem.Write32(data, 1)
			}
		case 0x0029:
			if data != 0 {
				ctx.Mem.Write32(data+0, 504)
				ctx.Mem.Write32(data+4, 1)
				ctx.Mem.Write32(data+8, 17)
				ctx.Mem.Write32(data+12, 17)
				ctx.Mem.Write32(data+16, 36)
				ctx.Mem.Write32(data+20, 36)
				writeLogFont(data+24, "Segoe UI", -12)
				ctx.Mem.Write32(data+116, 36)
				ctx.Mem.Write32(data+120, 36)
				writeLogFont(data+124, "Segoe UI", -12)
				ctx.Mem.Write32(data+216, 36)
				ctx.Mem.Write32(data+220, 36)
				writeLogFont(data+224, "Segoe UI", -12)
				writeLogFont(data+316, "Segoe UI", -12)
				writeLogFont(data+408, "Segoe UI", -12)
				ctx.Mem.Write32(data+500, 4)
			}
		case 0x001F:
			if data != 0 {
				writeLogFont(data, "Segoe UI", -12)
			}
		case 0x0030:
			if data != 0 {
				ctx.Mem.Write32(data+8, uint32(w))
				ctx.Mem.Write32(data+12, uint32(h))
			}
		case 0x0048:
			if data != 0 {
				ctx.Mem.Write32(data, 8)
				ctx.Mem.Write32(data+4, 0)
			}
		case 0x004A:
			if data != 0 {
				ctx.Mem.Write32(data, 1)
			}
		case 0x0068:
			if data != 0 {
				ctx.Mem.Write32(data, 3)
			}
		case 0x006A:
			if data != 0 {
				ctx.Mem.Write32(data, 400)
			}
		case 0x200A:
			if data != 0 {
				ctx.Mem.Write32(data, 2)
			}
		}
	}
	findWindowEx := func(parent, childAfter uint64, wantClass, wantTitle string) uint64 {
		found := childAfter == 0
		for h, cs := range hctx.HwndChildren {
			if parent != 0 && cs.parentHWND != parent {
				continue
			}
			if !found {
				if h == childAfter {
					found = true
				}
				continue
			}
			if wantClass != "" && strings.ToLower(cs.className) != wantClass {
				continue
			}
			if wantTitle != "" {
				title := cs.text
				if t, ok := hctx.HwndTitle[h]; ok {
					title = t
				}
				if title != wantTitle {
					continue
				}
			}
			return h
		}
		return 0
	}

	reg("NtGdiCreateCompatibleDC", func(ctx *ntapi.TrapContext) uint32 {
		h, memDC := gdiMgr.AllocMemDC()
		if parent := gdiMgr.GetDC(ctx.Arg(0)); parent != nil {
			memDC.InheritFrom(parent)
		}
		memDC.WorldTransform = gdi.IdentityXForm()
		memDC.PolyFillMode = 1
		ctx.SetReturn(h)
		return 0
	})
	reg("NtGdiDeleteObjectApp", func(ctx *ntapi.TrapContext) uint32 {
		if gdiMgr.DeleteObject(ctx.Arg(0)) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	reg("NtGdiGetDCforBitmap", func(ctx *ntapi.TrapContext) uint32 {
		hbm := ctx.Arg(0)
		obj := gdiMgr.GetObject(hbm)
		if obj == nil || obj.Bitmap == nil {
			ctx.SetReturn(0)
			return 0
		}
		hdc, dc := gdiMgr.AllocMemDC()
		dc.WorldTransform = gdi.IdentityXForm()
		gdiMgr.SelectObject(hdc, hbm)
		ctx.SetReturn(hdc)
		return 0
	})
	reg("NtGdiSaveDC", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(getDC(ctx.Arg(0)).Save()))
		return 0
	})
	reg("NtGdiRestoreDC", func(ctx *ntapi.TrapContext) uint32 {
		if getDC(ctx.Arg(0)).Restore(int(int32(ctx.Arg(1)))) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	reg("NtGdiGetDeviceCaps", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(deviceCaps(ctx.Arg(1)))
		return 0
	})
	for _, name := range []string{"NtGdiSelectBitmap", "NtGdiSelectPen", "NtGdiSelectBrush"} {
		name := name
		reg(name, func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(gdiMgr.SelectObject(ctx.Arg(0), ctx.Arg(1)))
			return 0
		})
	}
	reg("NtGdiBitBlt", func(ctx *ntapi.TrapContext) uint32 {
		dst := getDC(ctx.Arg(0))
		src := gdiMgr.GetDC(ctx.Arg(5))
		dst.BitBlt(int32(ctx.Arg(1)), int32(ctx.Arg(2)), int32(ctx.Arg(3)), int32(ctx.Arg(4)), src, int32(ctx.Arg(6)), int32(ctx.Arg(7)), uint32(ctx.Arg(8)))
		ctx.SetReturn(1)
		return 0
	})
	reg("NtGdiStretchBlt", func(ctx *ntapi.TrapContext) uint32 {
		dst := getDC(ctx.Arg(0))
		src := gdiMgr.GetDC(ctx.Arg(5))
		dst.StretchBlt(int32(ctx.Arg(1)), int32(ctx.Arg(2)), int32(ctx.Arg(3)), int32(ctx.Arg(4)), src, int32(ctx.Arg(6)), int32(ctx.Arg(7)), int32(ctx.Arg(8)), int32(ctx.Arg(9)), uint32(ctx.Arg(10)))
		ctx.SetReturn(1)
		return 0
	})
	reg("NtGdiAlphaBlend", func(ctx *ntapi.TrapContext) uint32 {
		dst := getDC(ctx.Arg(0))
		src := gdiMgr.GetDC(ctx.Arg(5))
		if dst == nil || src == nil || dst.Target == nil || src.Target == nil {
			ctx.SetReturn(1)
			return 0
		}
		bf := uint32(ctx.Arg(10))
		globalAlpha := uint8((bf >> 16) & 0xFF)
		if globalAlpha == 0 {
			globalAlpha = 255
		}
		perPixel := (bf >> 24) == 1
		dst.Target.AlphaBlendSurface(
			int32(ctx.Arg(1))+dst.OriginX, int32(ctx.Arg(2))+dst.OriginY,
			int32(ctx.Arg(3)), int32(ctx.Arg(4)),
			src.Target,
			int32(ctx.Arg(6))+src.OriginX, int32(ctx.Arg(7))+src.OriginY,
			int32(ctx.Arg(8)), int32(ctx.Arg(9)),
			globalAlpha, perPixel,
		)
		ctx.SetReturn(1)
		return 0
	})
	reg("NtGdiTransparentBlt", func(ctx *ntapi.TrapContext) uint32 {
		dst := getDC(ctx.Arg(0))
		src := gdiMgr.GetDC(ctx.Arg(5))
		if dst == nil || src == nil || dst.Target == nil || src.Target == nil {
			ctx.SetReturn(1)
			return 0
		}
		dx, dy := int32(ctx.Arg(1))+dst.OriginX, int32(ctx.Arg(2))+dst.OriginY
		dw, dh := int32(ctx.Arg(3)), int32(ctx.Arg(4))
		sx, sy := int32(ctx.Arg(6))+src.OriginX, int32(ctx.Arg(7))+src.OriginY
		sw, sh := int32(ctx.Arg(8)), int32(ctx.Arg(9))
		trans := uint32(ctx.Arg(10))
		if dw == sw && dh == sh {
			dst.Target.TransparentBlt(dx, dy, dw, dh, src.Target, sx, sy, sw, sh, trans)
		} else {
			tmp := gdi.NewSurface(dw, dh)
			tmp.StretchBlt(0, 0, dw, dh, src.Target, sx, sy, sw, sh)
			dst.Target.TransparentBlt(dx, dy, dw, dh, tmp, 0, 0, dw, dh, trans)
		}
		ctx.SetReturn(1)
		return 0
	})
	reg("NtGdiFillRgn", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		rgn := gdiMgr.GetRegion(ctx.Arg(1))
		if dc != nil && rgn != nil {
			dc.FillRect(rgn.X0, rgn.Y0, rgn.X1, rgn.Y1, gdiMgr.BrushColor(ctx.Arg(2), hctx.SysColors))
		}
		ctx.SetReturn(1)
		return 0
	})
	reg("NtGdiRectangle", func(ctx *ntapi.TrapContext) uint32 {
		getDC(ctx.Arg(0)).Rectangle(int32(ctx.Arg(1)), int32(ctx.Arg(2)), int32(ctx.Arg(3)), int32(ctx.Arg(4)))
		ctx.SetReturn(1)
		return 0
	})
	reg("NtGdiEllipse", func(ctx *ntapi.TrapContext) uint32 {
		getDC(ctx.Arg(0)).Ellipse(int32(ctx.Arg(1)), int32(ctx.Arg(2)), int32(ctx.Arg(3)), int32(ctx.Arg(4)))
		ctx.SetReturn(1)
		return 0
	})
	reg("NtGdiLineTo", func(ctx *ntapi.TrapContext) uint32 {
		getDC(ctx.Arg(0)).LineTo(int32(ctx.Arg(1)), int32(ctx.Arg(2)))
		ctx.SetReturn(1)
		return 0
	})
	reg("NtGdiPolyPolyDraw", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		pPts := ctx.Arg(1)
		pCounts := ctx.Arg(2)
		nPolys := int(ctx.Arg(3))
		fn := ctx.Arg(4)
		if dc == nil || pPts == 0 || pCounts == 0 || nPolys <= 0 {
			ctx.SetReturn(0)
			return 0
		}
		off := uint64(0)
		for p := 0; p < nPolys; p++ {
			cnt, _ := mem.Read32(pCounts + uint64(p)*4)
			n := int(cnt)
			if n <= 0 {
				continue
			}
			pts := make([][2]int32, n)
			for i := 0; i < n; i++ {
				x, _ := mem.Read32(pPts + off + uint64(i)*8)
				y, _ := mem.Read32(pPts + off + uint64(i)*8 + 4)
				pts[i] = [2]int32{int32(x), int32(y)}
			}
			switch fn {
			case 1:
				if n >= 3 {
					dc.Polygon(pts)
				}
			case 2:
				if n >= 2 {
					dc.PolylinePoints(pts)
				}
			case 3:
				dc.PolyBezier(pts)
			case 4:
				for _, pt := range pts {
					dc.LineTo(pt[0], pt[1])
				}
			case 5:
				dc.PolyBezierTo(pts)
			default:
				if n >= 2 {
					dc.PolylinePoints(pts)
				}
			}
			off += uint64(n) * 8
		}
		ctx.SetReturn(1)
		return 0
	})
	reg("NtGdiPatBlt", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		x := int32(ctx.Arg(1))
		y := int32(ctx.Arg(2))
		w := int32(ctx.Arg(3))
		h := int32(ctx.Arg(4))
		switch ctx.Arg(5) {
		case 0x00000042:
			dc.FillRect(x, y, x+w, y+h, 0x000000)
		case 0x00FF0062:
			dc.FillRect(x, y, x+w, y+h, 0xFFFFFF)
		default:
			dc.BitBlt(x, y, w, h, nil, 0, 0, uint32(ctx.Arg(5)))
		}
		ctx.SetReturn(1)
		return 0
	})
	reg("NtGdiExtTextOutW", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		if dc == nil {
			ctx.SetReturn(0)
			return 0
		}
		x := int32(ctx.Arg(1))
		y := int32(ctx.Arg(2))
		opts := uint32(ctx.Arg(3))
		lprc := ctx.Arg(4)
		text := readGuestUTF16N(ctx.Arg(5), int(ctx.Arg(6)))
		if lprc != 0 {
			rL, _ := mem.Read32(lprc)
			rT, _ := mem.Read32(lprc + 4)
			rR, _ := mem.Read32(lprc + 8)
			rB, _ := mem.Read32(lprc + 12)
			if opts&0x2 != 0 {
				dc.FillRect(int32(rL), int32(rT), int32(rR), int32(rB), dc.BkColor)
			}
		}
		if len(text) > 0 {
			dc.TextOut(x, y, text, false)
		}
		ctx.SetReturn(1)
		return 0
	})
	reg("NtGdiCreateCompatibleBitmap", func(ctx *ntapi.TrapContext) uint32 {
		w := int32(ctx.Arg(1))
		h := int32(ctx.Arg(2))
		if w <= 0 {
			w = 1
		}
		if h <= 0 {
			h = 1
		}
		ctx.SetReturn(gdiMgr.CreateCompatibleBitmap(w, h))
		return 0
	})
	reg("NtGdiCreateBitmap", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(gdiMgr.CreateCompatibleBitmap(int32(ctx.Arg(0)), int32(ctx.Arg(1))))
		return 0
	})
	reg("NtGdiCreateDIBSection", func(ctx *ntapi.TrapContext) uint32 {
		pbi := ctx.Arg(1)
		ppvBits := ctx.Arg(3)
		if ppvBits == 0 {
			ppvBits = ctx.Arg(4)
		}
		w, h, bitCount := int32(1), int32(1), int32(32)
		topDown := false
		if pbi != 0 {
			v32, _ := mem.Read32(pbi + 4)
			w = int32(v32)
			v32, _ = mem.Read32(pbi + 8)
			h = int32(v32)
			if h < 0 {
				topDown = true
				h = -h
			}
			v16, _ := mem.Read16(pbi + 14)
			if v16 != 0 {
				bitCount = int32(v16)
			}
		}
		if w <= 0 {
			w = 1
		}
		if h <= 0 {
			h = 1
		}
		stride := int(w) * 4
		sz := uint64(stride * int(h))
		bits := mem.Mmap(0, sz, mmu.PermRead|mmu.PermWrite)
		pix, _ := mem.ReadBytes(bits, int(sz))
		if ppvBits != 0 {
			mem.Write64(ppvBits, bits)
		}
		ctx.SetReturn(gdiMgr.CreateDIBSectionWithData(w, h, bitCount, bits, pix, topDown))
		return 0
	})
	reg("NtGdiGetBitmapBits", func(ctx *ntapi.TrapContext) uint32 {
		hbm := ctx.Arg(0)
		cb := int(ctx.Arg(1))
		pBits := ctx.Arg(2)
		obj := gdiMgr.GetObject(hbm)
		if obj == nil || obj.Bitmap == nil || obj.Bitmap.Surf == nil || pBits == 0 {
			ctx.SetReturn(0)
			return 0
		}
		buf := obj.Bitmap.Surf.Pix
		size := len(buf)
		if cb < size {
			size = cb
		}
		ctx.Mem.WriteBytes(pBits, buf[:size])
		ctx.SetReturn(uint64(size))
		return 0
	})
	reg("NtGdiSetBitmapBits", func(ctx *ntapi.TrapContext) uint32 {
		hbm := ctx.Arg(0)
		cb := int(ctx.Arg(1))
		pBits := ctx.Arg(2)
		obj := gdiMgr.GetObject(hbm)
		if obj == nil || obj.Bitmap == nil || obj.Bitmap.Surf == nil || pBits == 0 {
			ctx.SetReturn(0)
			return 0
		}
		size := len(obj.Bitmap.Surf.Pix)
		if cb < size {
			size = cb
		}
		buf, _ := ctx.Mem.ReadBytes(pBits, size)
		copy(obj.Bitmap.Surf.Pix[:size], buf)
		if obj.Bitmap.Bits != 0 {
			mem.WriteBytes(obj.Bitmap.Bits, buf)
		}
		ctx.SetReturn(uint64(size))
		return 0
	})
	reg("NtGdiGetBitmapDimension", func(ctx *ntapi.TrapContext) uint32 {
		if p := ctx.Arg(1); p != 0 {
			ctx.Mem.Write32(p, 0)
			ctx.Mem.Write32(p+4, 0)
		}
		ctx.SetReturn(1)
		return 0
	})
	reg("NtGdiGetDIBitsInternal", func(ctx *ntapi.TrapContext) uint32 {
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
		if pBMI != 0 {
			ctx.Mem.Write32(pBMI, 40)
			ctx.Mem.Write32(pBMI+4, uint32(bm.Width))
			height := bm.Height
			if bm.TopDown {
				height = -height
			}
			ctx.Mem.Write32(pBMI+8, uint32(height))
			ctx.Mem.Write16(pBMI+12, 1)
			bitCount := bm.BitCount
			if bitCount == 0 {
				bitCount = 32
			}
			ctx.Mem.Write16(pBMI+14, uint16(bitCount))
			ctx.Mem.Write32(pBMI+16, 0)
			ctx.Mem.Write32(pBMI+20, uint32(gdi.DIBStride(bm.Width, bitCount)*bm.Height))
		}
		if lpvBits == 0 {
			ctx.SetReturn(uint64(numScans))
			return 0
		}
		bitCount := bm.BitCount
		if bitCount == 0 {
			bitCount = 32
		}
		stride := gdi.DIBStride(bm.Width, bitCount)
		if startScan < 0 {
			startScan = 0
		}
		if startScan > bm.Height {
			startScan = bm.Height
		}
		if numScans < 0 || startScan+numScans > bm.Height {
			numScans = bm.Height - startScan
		}
		for row := int32(0); row < numScans; row++ {
			srcOff := int((startScan + row) * bm.Width * 4)
			need := int(stride)
			if srcOff+need > len(bm.Surf.Pix) {
				need = len(bm.Surf.Pix) - srcOff
			}
			if need <= 0 {
				break
			}
			ctx.Mem.WriteBytes(lpvBits+uint64(row)*uint64(stride), bm.Surf.Pix[srcOff:srcOff+need])
		}
		ctx.SetReturn(uint64(numScans))
		return 0
	})
	reg("NtGdiAddFontResourceW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(gdiMgr.AddFontResource(readGuestUTF16(ctx.Arg(0)))))
		return 0
	})
	reg("NtGdiGetTextExtentExW", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		f := dc.Font
		if f == nil {
			f = gdi.DefaultFont()
		}
		text := readGuestUTF16N(ctx.Arg(1), int(ctx.Arg(2)))
		maxExt := int32(ctx.Arg(3))
		pFit := ctx.Arg(4)
		pDx := ctx.Arg(5)
		pSize := ctx.Arg(6)
		width := int32(0)
		fit := 0
		for _, r := range text {
			cw := f.AveCharWidth
			width += cw
			if pDx != 0 {
				ctx.Mem.Write32(pDx+uint64(fit)*4, uint32(width))
			}
			if maxExt <= 0 || width <= maxExt {
				fit++
			}
			_ = r
		}
		if pFit != 0 {
			ctx.Mem.Write32(pFit, uint32(fit))
		}
		if pSize != 0 {
			ctx.Mem.Write32(pSize, uint32(width))
			ctx.Mem.Write32(pSize+4, uint32(f.CellHeight))
		}
		ctx.SetReturn(1)
		return 0
	})
	reg("NtGdiGetCharABCWidthsW", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		f := dc.Font
		if f == nil {
			f = gdi.DefaultFont()
		}
		first := int(ctx.Arg(1))
		last := int(ctx.Arg(2))
		pBuf := ctx.Arg(3)
		if last < first {
			ctx.SetReturn(0)
			return 0
		}
		pixSize := f.Height
		if pixSize < 0 {
			pixSize = -pixSize
		}
		if pixSize == 0 {
			pixSize = 12
		}
		for i := first; i <= last && pBuf != 0; i++ {
			off := pBuf + uint64(i-first)*12
			w := f.AveCharWidth
			if f.FaceID >= 0 {
				if g := gdi.GlyphFor(f.FaceID, pixSize, rune(i)); g != nil && g.Advance > 0 {
					w = g.Advance
				}
			}
			ctx.Mem.Write32(off, 0)
			ctx.Mem.Write32(off+4, uint32(w))
			ctx.Mem.Write32(off+8, 0)
		}
		ctx.SetReturn(1)
		return 0
	})
	reg("NtGdiGetCharWidthW", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		f := dc.Font
		if f == nil {
			f = gdi.DefaultFont()
		}
		first := int(ctx.Arg(1))
		last := int(ctx.Arg(2))
		pBuf := ctx.Arg(3)
		if last < first {
			ctx.SetReturn(0)
			return 0
		}
		pixSize := f.Height
		if pixSize < 0 {
			pixSize = -pixSize
		}
		if pixSize == 0 {
			pixSize = 12
		}
		for i := first; i <= last && pBuf != 0; i++ {
			w := f.AveCharWidth
			if f.FaceID >= 0 {
				if g := gdi.GlyphFor(f.FaceID, pixSize, rune(i)); g != nil && g.Advance > 0 {
					w = g.Advance
				}
			}
			ctx.Mem.Write32(pBuf+uint64(i-first)*4, uint32(w))
		}
		ctx.SetReturn(1)
		return 0
	})
	reg("NtGdiGetTextMetricsW", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		f := dc.Font
		if f == nil {
			f = gdi.DefaultFont()
		}
		if pTM := ctx.Arg(1); pTM != 0 {
			weight := f.Weight
			if weight == 0 {
				weight = 400
			}
			ctx.Mem.Write32(pTM, uint32(f.CellHeight))
			ctx.Mem.Write32(pTM+4, uint32(f.Ascent))
			ctx.Mem.Write32(pTM+8, uint32(f.Descent))
			ctx.Mem.Write32(pTM+20, uint32(f.AveCharWidth))
			ctx.Mem.Write32(pTM+24, uint32(f.MaxCharWidth))
			ctx.Mem.Write32(pTM+28, uint32(weight))
			ctx.Mem.Write32(pTM+36, 96)
			ctx.Mem.Write32(pTM+40, 96)
			ctx.Mem.Write16(pTM+44, 0x0020)
			ctx.Mem.Write16(pTM+46, 0x00FF)
			ctx.Mem.Write16(pTM+48, 0x003F)
			ctx.Mem.Write16(pTM+50, 0x0020)
		}
		ctx.SetReturn(1)
		return 0
	})
	reg("NtGdiSetTextColor", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		prev := dc.TextColor
		dc.TextColor = uint32(ctx.Arg(1))
		ctx.SetReturn(uint64(prev))
		return 0
	})
	reg("NtGdiSetBkColor", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		prev := dc.BkColor
		dc.BkColor = uint32(ctx.Arg(1))
		ctx.SetReturn(uint64(prev))
		return 0
	})
	reg("NtGdiSetBkMode", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		prev := dc.BkMode
		dc.BkMode = int32(ctx.Arg(1))
		ctx.SetReturn(uint64(prev))
		return 0
	})
	reg("NtGdiCreatePen", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(gdiMgr.CreatePen(int32(ctx.Arg(0)), int32(ctx.Arg(1)), uint32(ctx.Arg(2))))
		return 0
	})
	reg("NtGdiCreateSolidBrush", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(gdiMgr.CreateSolidBrush(uint32(ctx.Arg(0))))
		return 0
	})
	reg("NtGdiCreateHatchBrushInternal", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(gdiMgr.CreateHatchBrush(int32(ctx.Arg(0)), uint32(ctx.Arg(1))))
		return 0
	})
	reg("NtGdiGetStockObject", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(gdiMgr.GetStockObject(int(ctx.Arg(0))))
		return 0
	})
	reg("NtGdiExtGetObjectW", func(ctx *ntapi.TrapContext) uint32 {
		writeObjectInfo(ctx, ctx.Arg(0), ctx.Arg(2))
		return 0
	})
	reg("NtGdiGetObjectW", func(ctx *ntapi.TrapContext) uint32 {
		writeObjectInfo(ctx, ctx.Arg(0), ctx.Arg(2))
		return 0
	})
	reg("NtGdiCreateClientObj", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(hctx.GdiAlloc())
		return 0
	})
	reg("NtGdiCreateRectRgn", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(gdiMgr.CreateRectRgn(int32(ctx.Arg(0)), int32(ctx.Arg(1)), int32(ctx.Arg(2)), int32(ctx.Arg(3))))
		return 0
	})
	reg("NtGdiCombineRgn", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(gdiMgr.CombineRgn(ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), int(ctx.Arg(3)))))
		return 0
	})
	reg("NtGdiGetRgnBox", func(ctx *ntapi.TrapContext) uint32 {
		var bounds [4]int32
		result := gdiMgr.GetRgnBox(ctx.Arg(0), &bounds)
		if p := ctx.Arg(1); p != 0 {
			ctx.Mem.Write32(p, uint32(bounds[0]))
			ctx.Mem.Write32(p+4, uint32(bounds[1]))
			ctx.Mem.Write32(p+8, uint32(bounds[2]))
			ctx.Mem.Write32(p+12, uint32(bounds[3]))
		}
		ctx.SetReturn(uint64(result))
		return 0
	})
	reg("NtGdiOffsetRgn", func(ctx *ntapi.TrapContext) uint32 {
		rgn := gdiMgr.GetRegion(ctx.Arg(0))
		if rgn == nil {
			ctx.SetReturn(0)
			return 0
		}
		dx := int32(ctx.Arg(1))
		dy := int32(ctx.Arg(2))
		rgn.X0 += dx
		rgn.Y0 += dy
		rgn.X1 += dx
		rgn.Y1 += dy
		ctx.SetReturn(1)
		return 0
	})
	reg("NtGdiExtSelectClipRgn", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(gdiMgr.SelectClipRgn(ctx.Arg(0), ctx.Arg(1))))
		return 0
	})
	reg("NtGdiExcludeClipRect", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		el := int32(ctx.Arg(1)) + dc.OriginX
		et := int32(ctx.Arg(2)) + dc.OriginY
		er := int32(ctx.Arg(3)) + dc.OriginX
		eb := int32(ctx.Arg(4)) + dc.OriginY
		cl, ct, cr, cb := dc.ClipX0, dc.ClipY0, dc.ClipX1, dc.ClipY1
		if cl == 0 && ct == 0 && cr == 0 && cb == 0 && dc.Target != nil {
			cr, cb = dc.Target.Width, dc.Target.Height
		}
		if el <= cl && er >= cr {
			if et <= ct {
				ct = eb
			}
			if eb >= cb {
				cb = et
			}
		} else if et <= ct && eb >= cb {
			if el <= cl {
				cl = er
			}
			if er >= cr {
				cr = el
			}
		}
		if cl >= cr || ct >= cb {
			dc.ClipX0, dc.ClipY0, dc.ClipX1, dc.ClipY1 = 0, 0, 0, 0
			ctx.SetReturn(1)
			return 0
		}
		dc.ClipX0, dc.ClipY0, dc.ClipX1, dc.ClipY1 = cl, ct, cr, cb
		ctx.SetReturn(2)
		return 0
	})
	reg("NtGdiIntersectClipRect", func(ctx *ntapi.TrapContext) uint32 {
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
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(2)
		}
		return 0
	})
	reg("NtGdiSetViewportOrgEx", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		if p := ctx.Arg(3); p != 0 {
			ctx.Mem.Write32(p, uint32(dc.OriginX))
			ctx.Mem.Write32(p+4, uint32(dc.OriginY))
		}
		dc.SetViewportOrg(int32(ctx.Arg(1)), int32(ctx.Arg(2)))
		ctx.SetReturn(1)
		return 0
	})
	reg("NtGdiSetWindowOrgEx", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		if p := ctx.Arg(3); p != 0 {
			ctx.Mem.Write32(p, uint32(dc.WindowOrgX))
			ctx.Mem.Write32(p+4, uint32(dc.WindowOrgY))
		}
		dc.WindowOrgX = int32(ctx.Arg(1))
		dc.WindowOrgY = int32(ctx.Arg(2))
		ctx.SetReturn(1)
		return 0
	})
	reg("NtGdiGetViewportOrgEx", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		if p := ctx.Arg(1); p != 0 {
			ctx.Mem.Write32(p, uint32(dc.OriginX))
			ctx.Mem.Write32(p+4, uint32(dc.OriginY))
		}
		ctx.SetReturn(1)
		return 0
	})
	reg("NtGdiSetMapMode", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		prev := dc.MapMode
		dc.MapMode = int32(ctx.Arg(1))
		ctx.SetReturn(uint64(prev))
		return 0
	})
	reg("NtGdiGetTransform", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		xf := identityXform
		if dc != nil {
			xf = xformToRaw(dc.WorldTransform)
		}
		if p := ctx.Arg(2); p != 0 {
			writeXformMem(ctx, p, xf)
		}
		ctx.SetReturn(1)
		return 0
	})
	reg("NtGdiModifyWorldTransform", func(ctx *ntapi.TrapContext) uint32 {
		dc := getDC(ctx.Arg(0))
		if dc == nil || dc.GraphicsMode != 2 {
			ctx.SetReturn(0)
			return 0
		}
		switch ctx.Arg(2) {
		case 1:
			dc.WorldTransform = gdi.IdentityXForm()
		case 2:
			if p := ctx.Arg(1); p != 0 {
				dc.WorldTransform = rawToXform(xformMul(readXformMem(ctx, p), xformToRaw(dc.WorldTransform)))
			}
		case 3:
			if p := ctx.Arg(1); p != 0 {
				dc.WorldTransform = rawToXform(xformMul(xformToRaw(dc.WorldTransform), readXformMem(ctx, p)))
			}
		default:
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(1)
		return 0
	})

	reg("NtUserCreateWindowEx", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := hctx.HwndAlloc()
		lpClassName := ctx.Arg(1)
		style := uint32(ctx.Arg(3))
		exStyle := uint32(ctx.Arg(0))
		windowName := readGuestUTF16(ctx.Arg(2))
		parent := ctx.Arg(8)
		var className string
		var classAtom uint16
		if lpClassName != 0 && lpClassName < 0x10000 {
			classAtom = uint16(lpClassName)
			className = fmt.Sprintf("atom:0x%x", lpClassName)
		} else {
			className = readGuestUTF16(lpClassName)
			classAtom = hctx.ClassNameAtom[strings.ToLower(className)]
		}
		if classAtom != 0 {
			hctx.HwndClassAtom[hwnd] = classAtom
			if wp := hctx.AtomWndProc[classAtom]; wp != 0 {
				hctx.HwndWndProc[hwnd] = wp
			}
		}
		const wsChild = 0x40000000
		if style&wsChild != 0 {
			ox, oy := clientAreaOrigin(parent)
			cs := &controlState{
				className:  strings.ToLower(className),
				parentHWND: parent,
				ctrlID:     ctx.Arg(9),
				x:          int32(ctx.Arg(4)) + ox,
				y:          int32(ctx.Arg(5)) + oy,
				w:          int32(ctx.Arg(6)),
				h:          int32(ctx.Arg(7)),
				style:      style,
				exStyle:    exStyle,
				text:       windowName,
				visible:    style&0x10000000 != 0,
			}
			initBuiltinControlState(cs)
			hctx.HwndChildren[hwnd] = cs
			hctx.WindowLongPtr[hwnd] = map[int32]uint64{-16: uint64(style), -20: uint64(exStyle)}
			win32.Global.Create(hwnd, strings.ToLower(className), cs.x, cs.y, cs.w, cs.h, style, exStyle, parent)
		} else {
			if hctx.WlDisplay != nil && hctx.WlWindow == nil {
				title := windowName
				if title == "" {
					title = "govm"
				}
				w := int32(800)
				h := int32(600)
				if nw := int32(ctx.Arg(6)); nw > 0 && nw < 0x7FFF {
					w = nw
				}
				if nh := int32(ctx.Arg(7)); nh > 0 && nh < 0x7FFF {
					h = nh
				}
				if win, err := hctx.WlDisplay.CreateWindow(title, w, h, 0); err == nil {
					hctx.WlWindow = win
					if hctx.OnWlWindowSet != nil {
						hctx.OnWlWindowSet(win)
					}
				}
			}
			if hctx.MainHWND == 0 {
				hctx.MainHWND = hwnd
			}
			hctx.WindowLongPtr[hwnd] = map[int32]uint64{-16: uint64(style), -20: uint64(exStyle)}
			w := int32(800)
			h := int32(600)
			if hctx.WlWindow != nil {
				w = hctx.WlWindow.Width
				h = hctx.WlWindow.Height + hctx.WlWindow.TitleBarH
			}
			win32.Global.Create(hwnd, strings.ToLower(className), 0, 0, w, h, style, exStyle, 0)
		}
		hctx.HwndTitle[hwnd] = windowName
		ctx.SetReturn(hwnd)
		return 0
	})
	reg("NtUserDestroyWindow", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		delete(hctx.HwndChildren, hwnd)
		delete(hctx.HwndWndProc, hwnd)
		delete(hctx.HwndTitle, hwnd)
		delete(win32uWindowRgns, hwnd)
		ctx.SetReturn(1)
		return 0
	})
	reg("NtUserSetWindowPos", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		flags := uint32(ctx.Arg(6))
		const swpNoSize = 0x0001
		const swpNoMove = 0x0002
		const swpShowWindow = 0x0040
		const swpHideWindow = 0x0080
		if hwnd == hctx.MainHWND && hctx.WlWindow != nil {
			mainX, mainY := int32(0), int32(0)
			if flags&swpNoSize == 0 {
				if w := int32(ctx.Arg(4)); w > 0 {
					if h := int32(ctx.Arg(5)); h > 0 {
						if hctx.WlWindow.Resize(w, h) {
							hctx.SyncScreenSurface()
						}
					}
				}
			}
			if flags&swpNoMove == 0 {
				mainX = int32(ctx.Arg(2))
				mainY = int32(ctx.Arg(3))
			}
			if wnd := win32.Global.Get(hwnd); wnd != nil {
				win32.Global.UpdatePos(wnd, mainX, mainY, hctx.WlWindow.Width, hctx.WlWindow.Height+hctx.WlWindow.TitleBarH)
			}
			queuePaint(hwnd)
			ctx.SetReturn(1)
			return 0
		}
		if cs, ok := hctx.HwndChildren[hwnd]; ok {
			ox, oy := clientAreaOrigin(cs.parentHWND)
			if flags&swpNoMove == 0 {
				cs.x = int32(ctx.Arg(2)) + ox
				cs.y = int32(ctx.Arg(3)) + oy
			}
			if flags&swpNoSize == 0 {
				if w := int32(ctx.Arg(4)); w > 0 {
					cs.w = w
				}
				if h := int32(ctx.Arg(5)); h > 0 {
					cs.h = h
				}
			}
			if flags&swpShowWindow != 0 {
				cs.visible = true
			}
			if flags&swpHideWindow != 0 {
				cs.visible = false
			}
			if wnd := win32.Global.Get(hwnd); wnd != nil {
				win32.Global.UpdatePos(wnd, cs.x, cs.y, cs.w, cs.h)
			}
			queuePaint(hwnd)
		}
		ctx.SetReturn(1)
		return 0
	})
	reg("NtUserMoveWindow", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		if hwnd == hctx.MainHWND && hctx.WlWindow != nil {
			if w := int32(ctx.Arg(3)); w > 0 {
				if h := int32(ctx.Arg(4)); h > 0 {
					if hctx.WlWindow.Resize(w, h) {
						hctx.SyncScreenSurface()
					}
				}
			}
			if wnd := win32.Global.Get(hwnd); wnd != nil {
				win32.Global.UpdatePos(wnd, int32(ctx.Arg(1)), int32(ctx.Arg(2)), int32(ctx.Arg(3)), int32(ctx.Arg(4))+hctx.WlWindow.TitleBarH)
			}
			if ctx.Arg(5) != 0 {
				queuePaint(hwnd)
			}
			ctx.SetReturn(1)
			return 0
		}
		if cs, ok := hctx.HwndChildren[hwnd]; ok {
			ox, oy := clientAreaOrigin(cs.parentHWND)
			cs.x = int32(ctx.Arg(1)) + ox
			cs.y = int32(ctx.Arg(2)) + oy
			cs.w = int32(ctx.Arg(3))
			cs.h = int32(ctx.Arg(4))
			cs.visible = true
			if wnd := win32.Global.Get(hwnd); wnd != nil {
				win32.Global.UpdatePos(wnd, cs.x, cs.y, cs.w, cs.h)
			}
			if ctx.Arg(5) != 0 {
				queuePaint(hwnd)
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	reg("NtUserShowWindow", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		show := ctx.Arg(1) != 0
		if cs, ok := hctx.HwndChildren[hwnd]; ok {
			cs.visible = show
		}
		if show {
			queuePaint(hwnd)
		}
		ctx.SetReturn(1)
		return 0
	})
	reg("NtUserGetWindowRect", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		pRect := ctx.Arg(1)
		if pRect != 0 {
			if wnd := win32.Global.Get(hwnd); wnd != nil {
				ctx.Mem.Write32(pRect, uint32(wnd.RcWindow.Left))
				ctx.Mem.Write32(pRect+4, uint32(wnd.RcWindow.Top))
				ctx.Mem.Write32(pRect+8, uint32(wnd.RcWindow.Right))
				ctx.Mem.Write32(pRect+12, uint32(wnd.RcWindow.Bottom))
			} else if cs, ok := hctx.HwndChildren[hwnd]; ok {
				ctx.Mem.Write32(pRect, uint32(cs.x))
				ctx.Mem.Write32(pRect+4, uint32(cs.y))
				ctx.Mem.Write32(pRect+8, uint32(cs.x+cs.w))
				ctx.Mem.Write32(pRect+12, uint32(cs.y+cs.h))
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	reg("NtUserGetClientRect", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		pRect := ctx.Arg(1)
		if pRect != 0 {
			left, top, right, bottom := int32(0), int32(0), int32(0), int32(0)
			if cs, ok := hctx.HwndChildren[hwnd]; ok {
				right, bottom = cs.w, cs.h
			} else if hwnd == hctx.MainHWND {
				right, bottom = getTopLevelClientSize(hwnd)
			} else if wnd := win32.Global.Get(hwnd); wnd != nil {
				right, bottom = wnd.RcClient.Width(), wnd.RcClient.Height()
			}
			ctx.Mem.Write32(pRect, uint32(left))
			ctx.Mem.Write32(pRect+4, uint32(top))
			ctx.Mem.Write32(pRect+8, uint32(right))
			ctx.Mem.Write32(pRect+12, uint32(bottom))
		}
		ctx.SetReturn(1)
		return 0
	})
	for _, name := range []string{"NtUserSetWindowLong", "NtUserSetWindowLongPtr"} {
		name := name
		reg(name, func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			index := int32(ctx.Arg(1))
			newVal := ctx.Arg(2)
			m := hctx.WindowLongPtr[hwnd]
			if m == nil {
				m = make(map[int32]uint64)
				hctx.WindowLongPtr[hwnd] = m
			}
			old := m[index]
			if old == 0 {
				old = win32.Global.GetLong(hwnd, index)
			}
			m[index] = newVal
			win32.Global.SetLong(hwnd, index, newVal)
			if index == -4 {
				hctx.HwndWndProc[hwnd] = newVal
			}
			if index == -16 {
				if cs, ok := hctx.HwndChildren[hwnd]; ok {
					cs.style = uint32(newVal)
					cs.visible = cs.style&0x10000000 != 0
				}
			}
			ctx.SetReturn(old)
			return 0
		})
	}
	for _, name := range []string{"NtUserGetWindowLong", "NtUserGetWindowLongPtr"} {
		name := name
		reg(name, func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			index := int32(ctx.Arg(1))
			if m, ok := hctx.WindowLongPtr[hwnd]; ok {
				if val := m[index]; val != 0 {
					ctx.SetReturn(val)
					return 0
				}
			}
			if index == -4 {
				ctx.SetReturn(hctx.HwndWndProc[hwnd])
				return 0
			}
			ctx.SetReturn(win32.Global.GetLong(hwnd, index))
			return 0
		})
	}
	reg("NtUserGetWindowInfo", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		pWI := ctx.Arg(1)
		if pWI == 0 {
			ctx.SetReturn(0)
			return 0
		}
		cbSize, _ := mem.Read32(pWI)
		if cbSize < 60 {
			ctx.SetReturn(0)
			return 0
		}
		var x, y, w, h int32
		var style, exStyle uint32
		if cs, ok := hctx.HwndChildren[hwnd]; ok {
			x, y, w, h = cs.x, cs.y, cs.w, cs.h
			style, exStyle = cs.style, cs.exStyle
		} else if wnd := win32.Global.Get(hwnd); wnd != nil {
			x = wnd.RcWindow.Left
			y = wnd.RcWindow.Top
			w = wnd.RcWindow.Width()
			h = wnd.RcWindow.Height()
			style = uint32(win32.Global.GetLong(hwnd, -16))
			exStyle = uint32(win32.Global.GetLong(hwnd, -20))
		}
		ctx.Mem.Write32(pWI+4, uint32(x))
		ctx.Mem.Write32(pWI+8, uint32(y))
		ctx.Mem.Write32(pWI+12, uint32(x+w))
		ctx.Mem.Write32(pWI+16, uint32(y+h))
		ctx.Mem.Write32(pWI+20, uint32(x))
		ctx.Mem.Write32(pWI+24, uint32(y))
		ctx.Mem.Write32(pWI+28, uint32(x+w))
		ctx.Mem.Write32(pWI+32, uint32(y+h))
		ctx.Mem.Write32(pWI+36, style)
		ctx.Mem.Write32(pWI+40, exStyle)
		if hwnd == hctx.MainHWND || hwnd == hctx.FocusHwnd {
			ctx.Mem.Write32(pWI+44, 1)
		}
		ctx.Mem.Write32(pWI+48, 1)
		ctx.Mem.Write32(pWI+52, 1)
		ctx.Mem.Write16(pWI+56, hctx.HwndClassAtom[hwnd])
		ctx.Mem.Write16(pWI+58, 0x0600)
		ctx.SetReturn(1)
		return 0
	})
	reg("NtUserIsWindowVisible", func(ctx *ntapi.TrapContext) uint32 {
		if cs, ok := hctx.HwndChildren[ctx.Arg(0)]; ok {
			if cs.visible {
				ctx.SetReturn(1)
			} else {
				ctx.SetReturn(0)
			}
			return 0
		}
		ctx.SetReturn(1)
		return 0
	})
	reg("NtUserGetAncestor", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		switch ctx.Arg(1) {
		case 2, 3:
			ctx.SetReturn(hctx.MainHWND)
		default:
			if cs, ok := hctx.HwndChildren[hwnd]; ok {
				ctx.SetReturn(cs.parentHWND)
			} else {
				ctx.SetReturn(0)
			}
		}
		return 0
	})
	reg("NtUserGetParent", func(ctx *ntapi.TrapContext) uint32 {
		if cs, ok := hctx.HwndChildren[ctx.Arg(0)]; ok {
			ctx.SetReturn(cs.parentHWND)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	reg("NtUserSetParent", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		parent := ctx.Arg(1)
		old := uint64(0)
		if cs, ok := hctx.HwndChildren[hwnd]; ok {
			old = cs.parentHWND
			cs.parentHWND = parent
		}
		ctx.SetReturn(old)
		return 0
	})
	reg("NtUserGetDC", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		ox, oy := clientAreaOrigin(hwnd)
		h, dc := allocScreenDC(ox, oy)
		x0, y0, x1, y1 := absoluteClientRect(hwnd)
		dc.SetClipRect(x0, y0, x1, y1)
		ctx.SetReturn(h)
		return 0
	})
	reg("NtUserGetDCEx", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		ox, oy := clientAreaOrigin(hwnd)
		h, dc := allocScreenDC(ox, oy)
		x0, y0, x1, y1 := absoluteClientRect(hwnd)
		dc.SetClipRect(x0, y0, x1, y1)
		ctx.SetReturn(h)
		return 0
	})
	reg("NtUserReleaseDC", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(1)
		dc := gdiMgr.GetDC(hdc)
		dirtyScreen := dc != nil && dc.IsScreen && dc.Dirty
		gdiMgr.DeleteDC(hdc)
		if dirtyScreen {
			hctx.CommitIfDone()
		}
		ctx.SetReturn(1)
		return 0
	})
	reg("NtUserBeginPaint", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		pPaint := ctx.Arg(1)
		hctx.WinInvalid[hwnd] = false
		win32.Global.Validate(hwnd)
		ox, oy := clientAreaOrigin(hwnd)
		hdc, dc := allocScreenDC(ox, oy)
		x0, y0, x1, y1 := absoluteClientRect(hwnd)
		dc.SetClipRect(x0, y0, x1, y1)
		if pPaint != 0 {
			ctx.Mem.Write64(pPaint, hdc)
			ctx.Mem.Write32(pPaint+8, 0)
			ctx.Mem.Write32(pPaint+12, 0)
			ctx.Mem.Write32(pPaint+16, 0)
			ctx.Mem.Write32(pPaint+20, uint32(x1-x0))
			ctx.Mem.Write32(pPaint+24, uint32(y1-y0))
		}
		ctx.SetReturn(hdc)
		return 0
	})
	reg("NtUserEndPaint", func(ctx *ntapi.TrapContext) uint32 {
		if hctx.WlWindow != nil {
			hctx.PaintTree(ctx.Arg(0))
			hctx.FrameReady = true
			hctx.RepaintBuiltin = true
			hctx.CommitIfDone()
		}
		ctx.SetReturn(1)
		return 0
	})
	reg("NtUserRedrawWindow", func(ctx *ntapi.TrapContext) uint32 {
		queuePaint(ctx.Arg(0))
		ctx.SetReturn(1)
		return 0
	})
	reg("NtUserInvalidateRect", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		win32.Global.Invalidate(hwnd, nil)
		hctx.WinInvalid[hwnd] = true
		if ctx.Arg(2) != 0 {
			hctx.WinErasePending[hwnd] = true
		}
		queuePaint(hwnd)
		ctx.SetReturn(1)
		return 0
	})
	reg("NtUserUpdateWindow", func(ctx *ntapi.TrapContext) uint32 {
		queuePaint(ctx.Arg(0))
		ctx.SetReturn(1)
		return 0
	})
	reg("NtUserGetMessage", func(ctx *ntapi.TrapContext) uint32 {
		pMsg := ctx.Arg(0)
		if len(hctx.MsgQueue) == 0 {
			for hwnd, invalid := range hctx.WinInvalid {
				if invalid {
					queuePaint(hwnd)
					break
				}
			}
		}
		if len(hctx.MsgQueue) == 0 {
			if hctx.WlDisplay == nil {
				writeMsg(pMsg, hctx.MainHWND, 0x12, 0, 0)
				ctx.SetReturn(0)
				return 0
			}
			ctx.SetReturn(0)
			return 0
		}
		m := hctx.MsgQueue[0]
		hctx.MsgQueue = hctx.MsgQueue[1:]
		writeMsg(pMsg, m.hwnd, m.message, m.wParam, m.lParam)
		ctx.SetReturn(1)
		return 0
	})
	reg("NtUserPeekMessage", func(ctx *ntapi.TrapContext) uint32 {
		pMsg := ctx.Arg(0)
		remove := ctx.Arg(4)&0x1 != 0
		if len(hctx.MsgQueue) == 0 {
			ctx.SetReturn(0)
			return 0
		}
		m := hctx.MsgQueue[0]
		if remove {
			hctx.MsgQueue = hctx.MsgQueue[1:]
		}
		writeMsg(pMsg, m.hwnd, m.message, m.wParam, m.lParam)
		ctx.SetReturn(1)
		return 0
	})
	reg("NtUserDispatchMessage", func(ctx *ntapi.TrapContext) uint32 {
		pMsg := ctx.Arg(0)
		if pMsg == 0 {
			ctx.SetReturn(0)
			return 0
		}
		hwnd, _ := mem.Read64(pMsg)
		message, _ := mem.Read32(pMsg + 8)
		wParam, _ := mem.Read64(pMsg + 16)
		lParam, _ := mem.Read64(pMsg + 24)
		if result, handled := hctx.BuiltinWndProc(hwnd, message, wParam, lParam); handled {
			ctx.SetReturn(result)
			return 0
		}
		wndProc := hctx.HwndWndProc[hwnd]
		if wndProc == 0 {
			ctx.SetReturn(0)
			return 0
		}
		rw, ok := ctx.CPU.(ntapi.RegisterWriter)
		if !ok {
			ctx.SetReturn(0)
			return 0
		}
		rw.WriteReg(1, hwnd)
		rw.WriteReg(2, uint64(message))
		rw.WriteReg(8, wParam)
		rw.WriteReg(9, lParam)
		ctx.CPU.SetPC(wndProc)
		ctx.ReturnOverridden = true
		ctx.PCRedirected = true
		return 0
	})
	reg("NtUserPostMessage", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		if hwnd == 0 || hwnd == 0xFFFF || hwnd == 0xFFFFFFFFFFFFFFFF {
			hwnd = hctx.MainHWND
		}
		hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{hwnd: hwnd, message: uint32(ctx.Arg(1)), wParam: ctx.Arg(2), lParam: ctx.Arg(3)})
		ctx.SetReturn(1)
		return 0
	})
	sendMessage := func(ctx *ntapi.TrapContext, hwnd uint64, msg uint32, wParam, lParam uint64) uint32 {
		if result, handled := hctx.BuiltinWndProc(hwnd, msg, wParam, lParam); handled {
			ctx.SetReturn(result)
			return 0
		}
		wp := hctx.HwndWndProc[hwnd]
		if wp == 0 {
			ctx.SetReturn(0)
			return 0
		}
		rw, okW := ctx.CPU.(ntapi.RegisterWriter)
		rr, okR := ctx.CPU.(ntapi.RegisterReader)
		if okW && okR {
			rsp := rr.ReadReg(4)
			retAddr, _ := mem.Read64(rsp)
			if retAddr < 0x1000000 {
				ctx.SetReturn(0)
				return 0
			}
			hctx.SyncStack = append(hctx.SyncStack, syncDispatchFrame{
				queue:               nil,
				retAddr:             retAddr,
				hwnd:                hwnd,
				returnWndProcResult: true,
			})
			rsp -= 48
			mem.Write64(rsp, hctx.SyncTrampoline)
			rw.WriteReg(4, rsp)
			rw.WriteReg(1, hwnd)
			rw.WriteReg(2, uint64(msg))
			rw.WriteReg(8, wParam)
			rw.WriteReg(9, lParam)
			ctx.CPU.SetPC(wp)
			ctx.ReturnOverridden = true
			ctx.PCRedirected = true
			return 0
		}
		hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{hwnd: hwnd, message: msg, wParam: wParam, lParam: lParam})
		ctx.SetReturn(0)
		return 0
	}
	reg("NtUserSendMessage", func(ctx *ntapi.TrapContext) uint32 {
		return sendMessage(ctx, ctx.Arg(0), uint32(ctx.Arg(1)), ctx.Arg(2), ctx.Arg(3))
	})
	reg("NtUserMessageCall", func(ctx *ntapi.TrapContext) uint32 {
		return sendMessage(ctx, ctx.Arg(0), uint32(ctx.Arg(1)), ctx.Arg(2), ctx.Arg(3))
	})
	reg("NtUserTranslateMessage", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1)
		return 0
	})
	reg("NtUserWaitForInputIdle", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	reg("NtUserMsgWaitForMultipleObjectsEx", func(ctx *ntapi.TrapContext) uint32 {
		nCount := uint32(ctx.Arg(0))
		if len(hctx.MsgQueue) > 0 {
			ctx.SetReturn(uint64(nCount))
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	reg("NtUserGetKeyState", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	reg("NtUserGetAsyncKeyState", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	reg("NtUserGetCursorPos", func(ctx *ntapi.TrapContext) uint32 {
		if p := ctx.Arg(0); p != 0 {
			ctx.Mem.Write32(p, uint32(win32uCursorPosX))
			ctx.Mem.Write32(p+4, uint32(win32uCursorPosY))
		}
		ctx.SetReturn(1)
		return 0
	})
	reg("NtUserSetCursorPos", func(ctx *ntapi.TrapContext) uint32 {
		win32uCursorPosX = int32(ctx.Arg(0))
		win32uCursorPosY = int32(ctx.Arg(1))
		ctx.SetReturn(1)
		return 0
	})
	reg("NtUserSetCursor", func(ctx *ntapi.TrapContext) uint32 {
		prev := win32uCursorHandle
		win32uCursorHandle = ctx.Arg(0)
		ctx.SetReturn(prev)
		return 0
	})
	reg("NtUserGetFocus", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(hctx.FocusHwnd)
		return 0
	})
	reg("NtUserSetFocus", func(ctx *ntapi.TrapContext) uint32 {
		prev := hctx.FocusHwnd
		hctx.FocusHwnd = ctx.Arg(0)
		ctx.SetReturn(prev)
		return 0
	})
	reg("NtUserGetForegroundWindow", func(ctx *ntapi.TrapContext) uint32 {
		if hctx.FocusHwnd != 0 {
			ctx.SetReturn(hctx.FocusHwnd)
		} else {
			ctx.SetReturn(hctx.MainHWND)
		}
		return 0
	})
	reg("NtUserSetForegroundWindow", func(ctx *ntapi.TrapContext) uint32 {
		hctx.FocusHwnd = ctx.Arg(0)
		hctx.ActiveHwnd = ctx.Arg(0)
		ctx.SetReturn(1)
		return 0
	})
	reg("NtUserGetCapture", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(hctx.MouseCapture)
		return 0
	})
	reg("NtUserSetCapture", func(ctx *ntapi.TrapContext) uint32 {
		prev := hctx.MouseCapture
		hctx.MouseCapture = ctx.Arg(0)
		ctx.SetReturn(prev)
		return 0
	})
	reg("NtUserReleaseCapture", func(ctx *ntapi.TrapContext) uint32 {
		hctx.MouseCapture = 0
		ctx.SetReturn(1)
		return 0
	})
	reg("NtUserRegisterClassExWOW", func(ctx *ntapi.TrapContext) uint32 {
		pClass := ctx.Arg(0)
		a := hctx.NextAtom
		hctx.NextAtom++
		if pClass != 0 {
			style, _ := mem.Read32(pClass + 4)
			wndProc, _ := mem.Read64(pClass + 8)
			cbClsExtra, _ := mem.Read32(pClass + 16)
			cbWndExtra, _ := mem.Read32(pClass + 20)
			hInst, _ := mem.Read64(pClass + 24)
			hIcon, _ := mem.Read64(pClass + 32)
			hCursor, _ := mem.Read64(pClass + 40)
			hBrush, _ := mem.Read64(pClass + 48)
			lpszMenuName, _ := mem.Read64(pClass + 56)
			lpName, _ := mem.Read64(pClass + 64)
			hIconSm, _ := mem.Read64(pClass + 72)
			hctx.AtomWndProc[a] = wndProc
			var name string
			if lpName != 0 && lpName < 0x10000 {
				name = fmt.Sprintf("atom:0x%x", lpName)
			} else {
				name = readGuestUTF16(lpName)
			}
			if name != "" {
				hctx.ClassNameAtom[strings.ToLower(name)] = a
			}
			hctx.ClassInfo[a] = &registeredClassInfo{
				Style: style, WndProc: wndProc,
				ClsExtra: int32(cbClsExtra), WndExtra: int32(cbWndExtra),
				HInstance: hInst, HIcon: hIcon, HCursor: hCursor,
				HbrBG: hBrush, MenuName: lpszMenuName, ClassName: name,
				HIconSm: hIconSm, Atom: a,
			}
		}
		ctx.SetReturn(uint64(a))
		return 0
	})
	reg("NtUserUnregisterClass", func(ctx *ntapi.TrapContext) uint32 {
		namePtr := ctx.Arg(0)
		name := readGuestUTF16(namePtr)
		if namePtr != 0 && namePtr < 0x10000 {
			name = fmt.Sprintf("atom:0x%x", namePtr)
		}
		if atom, ok := hctx.ClassNameAtom[strings.ToLower(name)]; ok {
			delete(hctx.ClassNameAtom, strings.ToLower(name))
			delete(hctx.AtomWndProc, atom)
			delete(hctx.ClassInfo, atom)
		}
		ctx.SetReturn(1)
		return 0
	})
	getClassInfo := func(ctx *ntapi.TrapContext) *registeredClassInfo {
		nameArg := ctx.Arg(1)
		if nameArg != 0 && nameArg < 0x10000 {
			return hctx.ClassInfo[uint16(nameArg)]
		}
		name := readGuestUTF16(nameArg)
		return hctx.ClassInfo[hctx.ClassNameAtom[strings.ToLower(name)]]
	}
	reg("NtUserGetClassInfo", func(ctx *ntapi.TrapContext) uint32 {
		ci := getClassInfo(ctx)
		if ci == nil {
			ctx.SetReturn(0)
			return 0
		}
		out := ctx.Arg(2)
		if out != 0 {
			cbSize, _ := mem.Read32(out)
			if cbSize == 0 {
				mem.Write32(out, 80)
			}
			mem.Write32(out+4, ci.Style)
			mem.Write64(out+8, ci.WndProc)
			mem.Write32(out+16, uint32(ci.ClsExtra))
			mem.Write32(out+20, uint32(ci.WndExtra))
			mem.Write64(out+24, ci.HInstance)
			mem.Write64(out+32, ci.HIcon)
			mem.Write64(out+40, ci.HCursor)
			mem.Write64(out+48, ci.HbrBG)
			mem.Write64(out+56, ci.MenuName)
			mem.Write64(out+72, ci.HIconSm)
		}
		ctx.SetReturn(1)
		return 0
	})
	reg("NtUserGetClassInfoEx", func(ctx *ntapi.TrapContext) uint32 {
		ci := getClassInfo(ctx)
		if ci == nil {
			ctx.SetReturn(0)
			return 0
		}
		out := ctx.Arg(2)
		if out != 0 {
			cbSize, _ := mem.Read32(out)
			if cbSize == 0 {
				mem.Write32(out, 80)
			}
			mem.Write32(out+4, ci.Style)
			mem.Write64(out+8, ci.WndProc)
			mem.Write32(out+16, uint32(ci.ClsExtra))
			mem.Write32(out+20, uint32(ci.WndExtra))
			mem.Write64(out+24, ci.HInstance)
			mem.Write64(out+32, ci.HIcon)
			mem.Write64(out+40, ci.HCursor)
			mem.Write64(out+48, ci.HbrBG)
			mem.Write64(out+56, ci.MenuName)
			mem.Write64(out+72, ci.HIconSm)
		}
		ctx.SetReturn(1)
		return 0
	})
	reg("NtUserFindWindowEx", func(ctx *ntapi.TrapContext) uint32 {
		wantClass := strings.ToLower(readGuestUTF16(ctx.Arg(2)))
		wantTitle := readGuestUTF16(ctx.Arg(3))
		ctx.SetReturn(findWindowEx(ctx.Arg(0), ctx.Arg(1), wantClass, wantTitle))
		return 0
	})
	reg("NtUserSystemParametersInfo", func(ctx *ntapi.TrapContext) uint32 {
		systemParametersInfo(ctx, ctx.Arg(0), ctx.Arg(2))
		ctx.SetReturn(1)
		return 0
	})
	reg("NtUserSystemParametersInfoForDpi", func(ctx *ntapi.TrapContext) uint32 {
		systemParametersInfo(ctx, ctx.Arg(0), ctx.Arg(2))
		ctx.SetReturn(1)
		return 0
	})
	reg("NtUserGetSystemMetrics", func(ctx *ntapi.TrapContext) uint32 {
		if hctx.WlWindow != nil {
			win32.ScreenWidth = hctx.WlWindow.Width
			win32.ScreenHeight = hctx.WlWindow.Height
		}
		ctx.SetReturn(uint64(win32.GetSystemMetrics(int(ctx.Arg(0)))))
		return 0
	})
	reg("NtUserGetSystemMetricsForDpi", func(ctx *ntapi.TrapContext) uint32 {
		if hctx.WlWindow != nil {
			win32.ScreenWidth = hctx.WlWindow.Width
			win32.ScreenHeight = hctx.WlWindow.Height
		}
		ctx.SetReturn(uint64(win32.GetSystemMetrics(int(ctx.Arg(0)))))
		return 0
	})
	reg("NtUserLoadImage", func(ctx *ntapi.TrapContext) uint32 {
		hInst := ctx.Arg(0)
		nameArg := ctx.Arg(1)
		imgType := ctx.Arg(2)
		if imgType == 0 && nameArg < 0x10000 && hctx.MainModule != nil && (hInst == hctx.MainModule.BaseAddr || hInst == 0) {
			addr, sz, ok := hctx.PeLoadRawResource(hctx.MainModule.BaseAddr, hctx.MainModule.ResourceDirRVA, 2, uint32(nameArg))
			if ok {
				slots := hctx.DecodeDIBSlots(addr, sz, 0, 0)
				h := hctx.NextBitmapHandle
				hctx.NextBitmapHandle += 2
				hctx.BitmapHandles[h] = &bitmapHandleData{slots: slots}
				ctx.SetReturn(h)
				return 0
			}
		}
		ctx.SetReturn(0x00030001)
		return 0
	})
	reg("NtUserLoadCursor", func(ctx *ntapi.TrapContext) uint32 {
		if name := ctx.Arg(1); name < 0x10000 && name != 0 {
			ctx.SetReturn(name)
		} else {
			ctx.SetReturn(32512)
		}
		return 0
	})
	reg("NtUserDrawIconEx", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1)
		return 0
	})
	reg("NtUserTrackPopupMenuEx", func(ctx *ntapi.TrapContext) uint32 {
		hMenu := ctx.Arg(0)
		uFlags := uint32(ctx.Arg(1))
		hwndOwner := ctx.Arg(4)
		if hwndOwner == 0 {
			hwndOwner = hctx.MainHWND
		}
		selected := uint64(0)
		if m, ok := hctx.Menus[hMenu]; ok {
			for _, item := range m.items {
				if item.flags&(0x0800|0x0001|0x0002) != 0 {
					continue
				}
				if item.flags&0x0010 != 0 && len(item.submenu) > 0 {
					for _, sub := range item.submenu {
						if sub.flags&(0x0800|0x0001|0x0002) == 0 && sub.id != 0 {
							selected = sub.id
							break
						}
					}
				} else if item.id != 0 {
					selected = item.id
				}
				if selected != 0 {
					break
				}
			}
		}
		if uFlags&0x0100 != 0 {
			ctx.SetReturn(selected)
			return 0
		}
		if selected != 0 {
			hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{hwnd: hwndOwner, message: 0x0111, wParam: selected})
		}
		ctx.SetReturn(1)
		return 0
	})
	reg("NtUserGetWindowDC", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		if cs, ok := hctx.HwndChildren[hwnd]; ok {
			h, dc := allocScreenDC(cs.x, cs.y)
			dc.SetClipRect(cs.x, cs.y, cs.x+cs.w, cs.y+cs.h)
			ctx.SetReturn(h)
			return 0
		}
		h, _ := allocScreenDC(0, 0)
		ctx.SetReturn(h)
		return 0
	})
	reg("NtUserScrollWindowEx", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		win32.Global.Invalidate(hwnd, nil)
		queuePaint(hwnd)
		if prcUpdate := ctx.Arg(6); prcUpdate != 0 {
			if cs, ok := hctx.HwndChildren[hwnd]; ok {
				mem.Write32(prcUpdate, 0)
				mem.Write32(prcUpdate+4, 0)
				mem.Write32(prcUpdate+8, uint32(cs.w))
				mem.Write32(prcUpdate+12, uint32(cs.h))
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	reg("NtUserSetWindowRgn", func(ctx *ntapi.TrapContext) uint32 {
		if ctx.Arg(1) != 0 {
			win32uWindowRgns[ctx.Arg(0)] = ctx.Arg(1)
		} else {
			delete(win32uWindowRgns, ctx.Arg(0))
		}
		ctx.SetReturn(1)
		return 0
	})
	reg("NtUserSetLayeredWindowAttributes", func(ctx *ntapi.TrapContext) uint32 {
		win32uLayeredWindows[ctx.Arg(0)] = win32uLayeredAttrs{
			colorKey: uint32(ctx.Arg(1)),
			alpha:    uint8(ctx.Arg(2)),
			flags:    uint32(ctx.Arg(3)),
		}
		ctx.SetReturn(1)
		return 0
	})
	reg("NtUserGetLayeredWindowAttributes", func(ctx *ntapi.TrapContext) uint32 {
		la, ok := win32uLayeredWindows[ctx.Arg(0)]
		if !ok {
			ctx.SetReturn(0)
			return 0
		}
		if p := ctx.Arg(1); p != 0 {
			mem.Write32(p, la.colorKey)
		}
		if p := ctx.Arg(2); p != 0 {
			mem.Write8(p, la.alpha)
		}
		if p := ctx.Arg(3); p != 0 {
			mem.Write32(p, la.flags)
		}
		ctx.SetReturn(1)
		return 0
	})
	reg("NtUserDwmStartRedirection", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1)
		return 0
	})
}

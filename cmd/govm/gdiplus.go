package main

import (
	"encoding/binary"
	"math"
	"os"
	"strings"
	"sync"

	gdi "github.com/mirkobrombin/Raven/pkg/gdi"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

var (
	gdipGraphicsMap          = map[uint64]*gdipGraphics{}
	gdipPenMap               = map[uint64]*gdipPen{}
	gdipBrushMap             = map[uint64]*gdipBrush{}
	gdipFontMap              = map[uint64]*gdipFont{}
	gdipImageMap             = map[uint64]*gdipImage{}
	gdipStringFmtMap         = map[uint64]*gdipStringFormat{}
	gdipFontFamilyMap        = map[uint64]string{}
	gdipMatrixMap            = map[uint64]*gdipMatrix{}
	gdipPathMap              = map[uint64]*gdipPath{}
	gdipNextHandle    uint64 = 0x6D000001
	gdipMu            sync.Mutex
)

type gdipGraphics struct {
	hdc        uint64
	smoothing  int
	textHint   int
	ownsDC     bool
	clipActive bool
	clipX      float64
	clipY      float64
	clipW      float64
	clipH      float64
	world      [6]float64
	nextState  uint32
	saved      map[uint32]gdipGraphicsState
}

type gdipGraphicsState struct {
	dcLevel    int
	smoothing  int
	textHint   int
	clipActive bool
	clipX      float64
	clipY      float64
	clipW      float64
	clipH      float64
	world      [6]float64
}

type gdipPen struct {
	color uint32
	width float32
	style int
}

type gdipBrush struct {
	kind  int
	color uint32
}

type gdipFont struct {
	family string
	size   float32
	style  int
	unit   int
}

type gdipImage struct {
	width     int
	height    int
	format    int
	data      []byte
	stride    int
	lockAddr  uint64
	lockFlags uint32
	locked    bool
}

type gdipStringFormat struct {
	align     int
	lineAlign int
	flags     int
}

type gdipMatrix struct {
	m [6]float64 // m11,m12,m21,m22,dx,dy
}

type gdipPath struct {
	fillMode int
	figures  [][][2]float64
	closed   []bool
}

const (
	GdipOk               = 0
	GdipGenericError     = 1
	GdipInvalidParameter = 2
	GdipOutOfMemory      = 3
	GdipNotImplemented   = 6
)

const (
	gdipCombineReplace   = 0
	gdipCombineIntersect = 1

	gdipMatrixOrderPrepend = 0
	gdipMatrixOrderAppend  = 1

	gdipPixelFormat32bppARGB = 0x26200A
)

func registerGdiplusHandlers(hctx *HandlerCtx) {
	dll, ok := hctx.SynthByName["gdiplus.dll"]
	if !ok {
		return
	}

	d := hctx.Disp
	mem := hctx.Mem
	gdiMgr := hctx.GdiMgr
	readGuestUTF16 := hctx.ReadGuestUTF16
	readGuestUTF16N := hctx.ReadGuestUTF16N
	allocScreenDC := hctx.AllocScreenDC
	clientAreaOrigin := hctx.ClientAreaOrigin
	hwndChildren := hctx.HwndChildren

	d.RegisterAutoStubHandler(dll, "GdiplusStartup", func(ctx *ntapi.TrapContext) uint32 {
		tokenPtr := ctx.Arg(0)
		if tokenPtr == 0 {
			return GdipInvalidParameter
		}
		_ = mem.Write64(tokenPtr, 1)
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdiplusShutdown", func(ctx *ntapi.TrapContext) uint32 {
		return GdipOk
	})

	d.RegisterAutoStubHandler(dll, "GdipCreateFromHDC", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		out := ctx.Arg(1)
		if hdc == 0 || out == 0 || gdiMgr.GetDC(hdc) == nil {
			return GdipInvalidParameter
		}
		h := gdipStoreGraphics(&gdipGraphics{
			hdc:       hdc,
			smoothing: 0,
			textHint:  0,
			world:     gdipIdentityMatrix(),
			saved:     map[uint32]gdipGraphicsState{},
		})
		_ = ctx.Mem.Write64(out, h)
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipCreateFromHWND", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		out := ctx.Arg(1)
		if out == 0 {
			return GdipInvalidParameter
		}
		ox, oy := clientAreaOrigin(hwnd)
		hdc, dc := allocScreenDC(ox, oy)
		if cs, ok := hwndChildren[hwnd]; ok {
			dc.SetClipRect(cs.x, cs.y, cs.x+cs.w, cs.y+cs.h)
		}
		h := gdipStoreGraphics(&gdipGraphics{
			hdc:       hdc,
			smoothing: 0,
			textHint:  0,
			ownsDC:    true,
			world:     gdipIdentityMatrix(),
			saved:     map[uint32]gdipGraphicsState{},
		})
		_ = ctx.Mem.Write64(out, h)
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipDeleteGraphics", func(ctx *ntapi.TrapContext) uint32 {
		g, ok := gdipGetGraphics(ctx.Arg(0))
		if !ok {
			return GdipInvalidParameter
		}
		if g.ownsDC {
			gdiMgr.DeleteDC(g.hdc)
		}
		gdipMu.Lock()
		delete(gdipGraphicsMap, ctx.Arg(0))
		gdipMu.Unlock()
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipGetDC", func(ctx *ntapi.TrapContext) uint32 {
		g, ok := gdipGetGraphics(ctx.Arg(0))
		out := ctx.Arg(1)
		if !ok || out == 0 {
			return GdipInvalidParameter
		}
		_ = ctx.Mem.Write64(out, g.hdc)
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipReleaseDC", func(ctx *ntapi.TrapContext) uint32 {
		g, ok := gdipGetGraphics(ctx.Arg(0))
		if !ok || g.hdc != ctx.Arg(1) {
			return GdipInvalidParameter
		}
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipSetSmoothingMode", func(ctx *ntapi.TrapContext) uint32 {
		g, ok := gdipGetGraphics(ctx.Arg(0))
		if !ok {
			return GdipInvalidParameter
		}
		g.smoothing = int(int32(ctx.Arg(1)))
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipGetSmoothingMode", func(ctx *ntapi.TrapContext) uint32 {
		g, ok := gdipGetGraphics(ctx.Arg(0))
		out := ctx.Arg(1)
		if !ok || out == 0 {
			return GdipInvalidParameter
		}
		_ = ctx.Mem.Write32(out, uint32(g.smoothing))
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipSetTextRenderingHint", func(ctx *ntapi.TrapContext) uint32 {
		g, ok := gdipGetGraphics(ctx.Arg(0))
		if !ok {
			return GdipInvalidParameter
		}
		g.textHint = int(int32(ctx.Arg(1)))
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipGetTextRenderingHint", func(ctx *ntapi.TrapContext) uint32 {
		g, ok := gdipGetGraphics(ctx.Arg(0))
		out := ctx.Arg(1)
		if !ok || out == 0 {
			return GdipInvalidParameter
		}
		_ = ctx.Mem.Write32(out, uint32(g.textHint))
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipGraphicsClear", func(ctx *ntapi.TrapContext) uint32 {
		g, dc, ok := gdipGetGraphicsDC(gdiMgr, ctx.Arg(0))
		if !ok || dc.Target == nil {
			return gdipStatusForGraphics(ok)
		}
		dc.Target.FillRect(0, 0, dc.Target.Width, dc.Target.Height, gdipARGBToColorRef(uint32(ctx.Arg(1))))
		gdipApplyClip(g, dc)
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipSetClipRect", func(ctx *ntapi.TrapContext) uint32 {
		g, dc, ok := gdipGetGraphicsDC(gdiMgr, ctx.Arg(0))
		if !ok {
			return GdipInvalidParameter
		}
		x := float64(gdipRealArg32(ctx, 1))
		y := float64(gdipRealArg32(ctx, 2))
		w := float64(gdipRealArg32(ctx, 3))
		h := float64(gdipRealArg32(ctx, 4))
		combineMode := int(int32(ctx.Arg(5)))
		if combineMode != gdipCombineReplace && g.clipActive {
			nx, ny, nw, nh := gdipCombineClip(g.clipX, g.clipY, g.clipW, g.clipH, x, y, w, h, combineMode)
			x, y, w, h = nx, ny, nw, nh
		}
		g.clipActive, g.clipX, g.clipY, g.clipW, g.clipH = true, x, y, w, h
		gdipApplyClip(g, dc)
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipResetClip", func(ctx *ntapi.TrapContext) uint32 {
		g, dc, ok := gdipGetGraphicsDC(gdiMgr, ctx.Arg(0))
		if !ok {
			return GdipInvalidParameter
		}
		g.clipActive = false
		dc.SetClipRect(0, 0, 0, 0)
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipSaveGraphics", func(ctx *ntapi.TrapContext) uint32 {
		g, dc, ok := gdipGetGraphicsDC(gdiMgr, ctx.Arg(0))
		out := ctx.Arg(1)
		if !ok || out == 0 {
			return GdipInvalidParameter
		}
		g.nextState++
		if g.nextState == 0 {
			g.nextState = 1
		}
		g.saved[g.nextState] = gdipGraphicsState{
			dcLevel:    dc.Save(),
			smoothing:  g.smoothing,
			textHint:   g.textHint,
			clipActive: g.clipActive,
			clipX:      g.clipX,
			clipY:      g.clipY,
			clipW:      g.clipW,
			clipH:      g.clipH,
			world:      g.world,
		}
		_ = ctx.Mem.Write32(out, g.nextState)
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipRestoreGraphics", func(ctx *ntapi.TrapContext) uint32 {
		g, dc, ok := gdipGetGraphicsDC(gdiMgr, ctx.Arg(0))
		if !ok {
			return GdipInvalidParameter
		}
		stateID := uint32(ctx.Arg(1))
		state, ok := g.saved[stateID]
		if !ok {
			return GdipInvalidParameter
		}
		_ = dc.Restore(state.dcLevel)
		g.smoothing = state.smoothing
		g.textHint = state.textHint
		g.clipActive = state.clipActive
		g.clipX = state.clipX
		g.clipY = state.clipY
		g.clipW = state.clipW
		g.clipH = state.clipH
		g.world = state.world
		if g.clipActive {
			gdipApplyClip(g, dc)
		} else {
			dc.SetClipRect(0, 0, 0, 0)
		}
		delete(g.saved, stateID)
		return GdipOk
	})

	d.RegisterAutoStubHandler(dll, "GdipDrawLineI", func(ctx *ntapi.TrapContext) uint32 {
		return gdipDrawLine(gdiMgr, ctx, true)
	})
	d.RegisterAutoStubHandler(dll, "GdipDrawLine", func(ctx *ntapi.TrapContext) uint32 {
		return gdipDrawLine(gdiMgr, ctx, false)
	})
	d.RegisterAutoStubHandler(dll, "GdipDrawRectangleI", func(ctx *ntapi.TrapContext) uint32 {
		return gdipDrawRect(gdiMgr, ctx, true, false)
	})
	d.RegisterAutoStubHandler(dll, "GdipDrawRectangle", func(ctx *ntapi.TrapContext) uint32 {
		return gdipDrawRect(gdiMgr, ctx, false, false)
	})
	d.RegisterAutoStubHandler(dll, "GdipFillRectangleI", func(ctx *ntapi.TrapContext) uint32 {
		return gdipDrawRect(gdiMgr, ctx, true, true)
	})
	d.RegisterAutoStubHandler(dll, "GdipFillRectangle", func(ctx *ntapi.TrapContext) uint32 {
		return gdipDrawRect(gdiMgr, ctx, false, true)
	})
	d.RegisterAutoStubHandler(dll, "GdipDrawEllipseI", func(ctx *ntapi.TrapContext) uint32 {
		return gdipDrawEllipse(gdiMgr, ctx, true, false)
	})
	d.RegisterAutoStubHandler(dll, "GdipDrawEllipse", func(ctx *ntapi.TrapContext) uint32 {
		return gdipDrawEllipse(gdiMgr, ctx, false, false)
	})
	d.RegisterAutoStubHandler(dll, "GdipFillEllipseI", func(ctx *ntapi.TrapContext) uint32 {
		return gdipDrawEllipse(gdiMgr, ctx, true, true)
	})
	d.RegisterAutoStubHandler(dll, "GdipFillEllipse", func(ctx *ntapi.TrapContext) uint32 {
		return gdipDrawEllipse(gdiMgr, ctx, false, true)
	})
	d.RegisterAutoStubHandler(dll, "GdipDrawString", func(ctx *ntapi.TrapContext) uint32 {
		g, dc, ok := gdipGetGraphicsDC(gdiMgr, ctx.Arg(0))
		if !ok {
			return GdipInvalidParameter
		}
		text := gdipReadUTF16Text(ctx, readGuestUTF16, readGuestUTF16N, ctx.Arg(1), ctx.Arg(2))
		font, ok := gdipGetFont(ctx.Arg(3))
		if !ok {
			return GdipInvalidParameter
		}
		layoutX, layoutY, layoutW, layoutH := gdipReadRectF(ctx.Mem, ctx.Arg(4))
		format, _ := gdipGetStringFormat(ctx.Arg(5))
		brush, ok := gdipGetBrush(ctx.Arg(6))
		if !ok {
			return GdipInvalidParameter
		}
		gf := gdipMakeGDIFont(font)
		oldFont, oldTextColor, oldAlign := dc.Font, dc.TextColor, dc.TextAlign
		dc.Font = gf
		dc.TextColor = gdipARGBToColorRef(brush.color)
		if format != nil {
			dc.TextAlign = gdipTextAlign(format.align, format.lineAlign)
		}
		tw, th := dc.TextExtentStr(text)
		x, y := gdipLayoutText(float64(layoutX), float64(layoutY), float64(layoutW), float64(layoutH), float64(tw), float64(th), format)
		tx, ty := gdipTransformPoint(g, x, y)
		dc.TextOut(int32(math.Round(tx)), int32(math.Round(ty)), text, false)
		dc.Font, dc.TextColor, dc.TextAlign = oldFont, oldTextColor, oldAlign
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipMeasureString", func(ctx *ntapi.TrapContext) uint32 {
		g, dc, ok := gdipGetGraphicsDC(gdiMgr, ctx.Arg(0))
		if !ok {
			return GdipInvalidParameter
		}
		text := gdipReadUTF16Text(ctx, readGuestUTF16, readGuestUTF16N, ctx.Arg(1), ctx.Arg(2))
		font, ok := gdipGetFont(ctx.Arg(3))
		if !ok {
			return GdipInvalidParameter
		}
		layoutX, layoutY, layoutW, layoutH := gdipReadRectF(ctx.Mem, ctx.Arg(4))
		format, _ := gdipGetStringFormat(ctx.Arg(5))
		gf := gdipMakeGDIFont(font)
		oldFont := dc.Font
		dc.Font = gf
		tw, th := dc.TextExtentStr(text)
		dc.Font = oldFont
		bw := float32(tw)
		bh := float32(th)
		if layoutW > 0 && bw > layoutW {
			bw = layoutW
		}
		if layoutH > 0 && bh > layoutH {
			bh = layoutH
		}
		bx, by := gdipLayoutText(float64(layoutX), float64(layoutY), float64(layoutW), float64(layoutH), float64(bw), float64(bh), format)
		if ctx.Arg(6) != 0 {
			_ = gdipWriteRectF(ctx.Mem, ctx.Arg(6), float32(bx), float32(by), bw, bh)
		}
		if ctx.Arg(7) != 0 {
			_ = ctx.Mem.Write32(ctx.Arg(7), uint32(len([]rune(text))))
		}
		if ctx.Arg(8) != 0 {
			_ = ctx.Mem.Write32(ctx.Arg(8), uint32(strings.Count(text, "\n")+1))
		}
		_ = g
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipDrawImageI", func(ctx *ntapi.TrapContext) uint32 {
		img, ok := gdipGetImage(ctx.Arg(1))
		if !ok {
			return GdipInvalidParameter
		}
		return gdipDrawImage(gdiMgr, ctx, img, int32(ctx.Arg(2)), int32(ctx.Arg(3)), int32(img.width), int32(img.height))
	})
	d.RegisterAutoStubHandler(dll, "GdipDrawImageRectI", func(ctx *ntapi.TrapContext) uint32 {
		img, ok := gdipGetImage(ctx.Arg(1))
		if !ok {
			return GdipInvalidParameter
		}
		return gdipDrawImage(gdiMgr, ctx, img, int32(ctx.Arg(2)), int32(ctx.Arg(3)), int32(ctx.Arg(4)), int32(ctx.Arg(5)))
	})
	d.RegisterAutoStubHandler(dll, "GdipDrawPolygonI", func(ctx *ntapi.TrapContext) uint32 {
		return gdipDrawPolygon(gdiMgr, ctx, true, false)
	})
	d.RegisterAutoStubHandler(dll, "GdipFillPolygonI", func(ctx *ntapi.TrapContext) uint32 {
		return gdipDrawPolygon(gdiMgr, ctx, true, true)
	})
	d.RegisterAutoStubHandler(dll, "GdipDrawPath", func(ctx *ntapi.TrapContext) uint32 {
		return gdipRenderPath(gdiMgr, ctx, false)
	})
	d.RegisterAutoStubHandler(dll, "GdipFillPath", func(ctx *ntapi.TrapContext) uint32 {
		return gdipRenderPath(gdiMgr, ctx, true)
	})

	d.RegisterAutoStubHandler(dll, "GdipCreatePen1", func(ctx *ntapi.TrapContext) uint32 {
		out := ctx.Arg(3)
		if out == 0 {
			return GdipInvalidParameter
		}
		h := gdipStorePen(&gdipPen{
			color: uint32(ctx.Arg(0)),
			width: gdipRealArg32(ctx, 1),
			style: 0,
		})
		_ = ctx.Mem.Write64(out, h)
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipDeletePen", func(ctx *ntapi.TrapContext) uint32 {
		gdipMu.Lock()
		defer gdipMu.Unlock()
		if _, ok := gdipPenMap[ctx.Arg(0)]; !ok {
			return GdipInvalidParameter
		}
		delete(gdipPenMap, ctx.Arg(0))
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipSetPenColor", func(ctx *ntapi.TrapContext) uint32 {
		pen, ok := gdipGetPen(ctx.Arg(0))
		if !ok {
			return GdipInvalidParameter
		}
		pen.color = uint32(ctx.Arg(1))
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipSetPenWidth", func(ctx *ntapi.TrapContext) uint32 {
		pen, ok := gdipGetPen(ctx.Arg(0))
		if !ok {
			return GdipInvalidParameter
		}
		pen.width = gdipRealArg32(ctx, 1)
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipGetPenColor", func(ctx *ntapi.TrapContext) uint32 {
		pen, ok := gdipGetPen(ctx.Arg(0))
		out := ctx.Arg(1)
		if !ok || out == 0 {
			return GdipInvalidParameter
		}
		_ = ctx.Mem.Write32(out, pen.color)
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipGetPenWidth", func(ctx *ntapi.TrapContext) uint32 {
		pen, ok := gdipGetPen(ctx.Arg(0))
		out := ctx.Arg(1)
		if !ok || out == 0 {
			return GdipInvalidParameter
		}
		_ = ctx.Mem.Write32(out, math.Float32bits(pen.width))
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipSetPenDashStyle", func(ctx *ntapi.TrapContext) uint32 {
		pen, ok := gdipGetPen(ctx.Arg(0))
		if !ok {
			return GdipInvalidParameter
		}
		pen.style = int(int32(ctx.Arg(1)))
		return GdipOk
	})

	d.RegisterAutoStubHandler(dll, "GdipCreateSolidFill", func(ctx *ntapi.TrapContext) uint32 {
		out := ctx.Arg(1)
		if out == 0 {
			return GdipInvalidParameter
		}
		h := gdipStoreBrush(&gdipBrush{kind: 0, color: uint32(ctx.Arg(0))})
		_ = ctx.Mem.Write64(out, h)
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipDeleteBrush", func(ctx *ntapi.TrapContext) uint32 {
		gdipMu.Lock()
		defer gdipMu.Unlock()
		if _, ok := gdipBrushMap[ctx.Arg(0)]; !ok {
			return GdipInvalidParameter
		}
		delete(gdipBrushMap, ctx.Arg(0))
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipSetSolidFillColor", func(ctx *ntapi.TrapContext) uint32 {
		brush, ok := gdipGetBrush(ctx.Arg(0))
		if !ok {
			return GdipInvalidParameter
		}
		brush.color = uint32(ctx.Arg(1))
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipGetSolidFillColor", func(ctx *ntapi.TrapContext) uint32 {
		brush, ok := gdipGetBrush(ctx.Arg(0))
		out := ctx.Arg(1)
		if !ok || out == 0 {
			return GdipInvalidParameter
		}
		_ = ctx.Mem.Write32(out, brush.color)
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipCreateLineBrush", func(ctx *ntapi.TrapContext) uint32 {
		out := ctx.Arg(5)
		if out == 0 {
			return GdipInvalidParameter
		}
		h := gdipStoreBrush(&gdipBrush{kind: 1, color: uint32(ctx.Arg(2))})
		_ = ctx.Mem.Write64(out, h)
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipCreateHatchBrush", func(ctx *ntapi.TrapContext) uint32 {
		out := ctx.Arg(3)
		if out == 0 {
			return GdipInvalidParameter
		}
		h := gdipStoreBrush(&gdipBrush{kind: int(int32(ctx.Arg(0))), color: uint32(ctx.Arg(1))})
		_ = ctx.Mem.Write64(out, h)
		return GdipOk
	})

	d.RegisterAutoStubHandler(dll, "GdipCreateFontFamilyFromName", func(ctx *ntapi.TrapContext) uint32 {
		namePtr := ctx.Arg(0)
		out := ctx.Arg(2)
		if namePtr == 0 || out == 0 {
			return GdipInvalidParameter
		}
		name := readGuestUTF16(namePtr)
		if name == "" {
			name = "System"
		}
		h := gdipStoreFontFamily(name)
		_ = ctx.Mem.Write64(out, h)
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipDeleteFontFamily", func(ctx *ntapi.TrapContext) uint32 {
		gdipMu.Lock()
		defer gdipMu.Unlock()
		if _, ok := gdipFontFamilyMap[ctx.Arg(0)]; !ok {
			return GdipInvalidParameter
		}
		delete(gdipFontFamilyMap, ctx.Arg(0))
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipCreateFont", func(ctx *ntapi.TrapContext) uint32 {
		family, ok := gdipGetFontFamily(ctx.Arg(0))
		out := ctx.Arg(4)
		if !ok || out == 0 {
			return GdipInvalidParameter
		}
		h := gdipStoreFont(&gdipFont{
			family: family,
			size:   gdipRealArg32(ctx, 1),
			style:  int(int32(ctx.Arg(2))),
			unit:   int(int32(ctx.Arg(3))),
		})
		_ = ctx.Mem.Write64(out, h)
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipDeleteFont", func(ctx *ntapi.TrapContext) uint32 {
		gdipMu.Lock()
		defer gdipMu.Unlock()
		if _, ok := gdipFontMap[ctx.Arg(0)]; !ok {
			return GdipInvalidParameter
		}
		delete(gdipFontMap, ctx.Arg(0))
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipGetFontSize", func(ctx *ntapi.TrapContext) uint32 {
		font, ok := gdipGetFont(ctx.Arg(0))
		out := ctx.Arg(1)
		if !ok || out == 0 {
			return GdipInvalidParameter
		}
		_ = ctx.Mem.Write32(out, math.Float32bits(font.size))
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipGetFontHeight", func(ctx *ntapi.TrapContext) uint32 {
		font, ok := gdipGetFont(ctx.Arg(0))
		out := ctx.Arg(2)
		if !ok || out == 0 {
			return GdipInvalidParameter
		}
		height := font.size * 1.2
		_ = ctx.Mem.Write32(out, math.Float32bits(height))
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipCreateFontFromDC", func(ctx *ntapi.TrapContext) uint32 {
		out := ctx.Arg(1)
		if out == 0 {
			return GdipInvalidParameter
		}
		family := "System"
		size := float32(12)
		if dc := gdiMgr.GetDC(ctx.Arg(0)); dc != nil && dc.Font != nil {
			if dc.Font.FaceName != "" {
				family = dc.Font.FaceName
			}
			if dc.Font.Height != 0 {
				if dc.Font.Height < 0 {
					size = float32(-dc.Font.Height)
				} else {
					size = float32(dc.Font.Height)
				}
			}
		}
		h := gdipStoreFont(&gdipFont{family: family, size: size})
		_ = ctx.Mem.Write64(out, h)
		return GdipOk
	})

	d.RegisterAutoStubHandler(dll, "GdipCreateStringFormat", func(ctx *ntapi.TrapContext) uint32 {
		out := ctx.Arg(2)
		if out == 0 {
			return GdipInvalidParameter
		}
		h := gdipStoreStringFormat(&gdipStringFormat{flags: int(int32(ctx.Arg(0)))})
		_ = ctx.Mem.Write64(out, h)
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipDeleteStringFormat", func(ctx *ntapi.TrapContext) uint32 {
		gdipMu.Lock()
		defer gdipMu.Unlock()
		if _, ok := gdipStringFmtMap[ctx.Arg(0)]; !ok {
			return GdipInvalidParameter
		}
		delete(gdipStringFmtMap, ctx.Arg(0))
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipSetStringFormatAlign", func(ctx *ntapi.TrapContext) uint32 {
		f, ok := gdipGetStringFormat(ctx.Arg(0))
		if !ok {
			return GdipInvalidParameter
		}
		f.align = int(int32(ctx.Arg(1)))
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipSetStringFormatLineAlign", func(ctx *ntapi.TrapContext) uint32 {
		f, ok := gdipGetStringFormat(ctx.Arg(0))
		if !ok {
			return GdipInvalidParameter
		}
		f.lineAlign = int(int32(ctx.Arg(1)))
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipStringFormatGetGenericDefault", func(ctx *ntapi.TrapContext) uint32 {
		out := ctx.Arg(0)
		if out == 0 {
			return GdipInvalidParameter
		}
		h := gdipStoreStringFormat(&gdipStringFormat{})
		_ = ctx.Mem.Write64(out, h)
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipStringFormatGetGenericTypographic", func(ctx *ntapi.TrapContext) uint32 {
		out := ctx.Arg(0)
		if out == 0 {
			return GdipInvalidParameter
		}
		h := gdipStoreStringFormat(&gdipStringFormat{flags: 0x4000})
		_ = ctx.Mem.Write64(out, h)
		return GdipOk
	})

	d.RegisterAutoStubHandler(dll, "GdipCreateBitmapFromScan0", func(ctx *ntapi.TrapContext) uint32 {
		w := int(int32(ctx.Arg(0)))
		h := int(int32(ctx.Arg(1)))
		stride := int(int32(ctx.Arg(2)))
		format := int(uint32(ctx.Arg(3)))
		scan0 := ctx.Arg(4)
		out := ctx.Arg(5)
		if w <= 0 || h <= 0 || out == 0 {
			return GdipInvalidParameter
		}
		if stride == 0 {
			stride = w * 4
		}
		if stride < 0 {
			stride = -stride
		}
		data := make([]byte, stride*h)
		if scan0 != 0 {
			for i := range data {
				b, err := ctx.Mem.Read8(scan0 + uint64(i))
				if err != nil {
					break
				}
				data[i] = b
			}
		}
		hImg := gdipStoreImage(&gdipImage{
			width:  w,
			height: h,
			format: format,
			data:   data,
			stride: stride,
		})
		_ = ctx.Mem.Write64(out, hImg)
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipCreateBitmapFromHBITMAP", func(ctx *ntapi.TrapContext) uint32 {
		hbm := ctx.Arg(0)
		out := ctx.Arg(2)
		if out == 0 {
			return GdipInvalidParameter
		}
		obj := gdiMgr.GetObject(hbm)
		if obj == nil || obj.Bitmap == nil {
			return GdipInvalidParameter
		}
		bm := obj.Bitmap
		stride := int(bm.Width) * 4
		data := make([]byte, stride*int(bm.Height))
		if bm.Surf != nil {
			copy(data, bm.Surf.Pix)
		}
		hImg := gdipStoreImage(&gdipImage{
			width:  int(bm.Width),
			height: int(bm.Height),
			format: gdipPixelFormat32bppARGB,
			data:   data,
			stride: stride,
		})
		_ = ctx.Mem.Write64(out, hImg)
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipDisposeImage", func(ctx *ntapi.TrapContext) uint32 {
		gdipMu.Lock()
		defer gdipMu.Unlock()
		if _, ok := gdipImageMap[ctx.Arg(0)]; !ok {
			return GdipInvalidParameter
		}
		delete(gdipImageMap, ctx.Arg(0))
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipGetImageWidth", func(ctx *ntapi.TrapContext) uint32 {
		img, ok := gdipGetImage(ctx.Arg(0))
		out := ctx.Arg(1)
		if !ok || out == 0 {
			return GdipInvalidParameter
		}
		_ = ctx.Mem.Write32(out, uint32(img.width))
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipGetImageHeight", func(ctx *ntapi.TrapContext) uint32 {
		img, ok := gdipGetImage(ctx.Arg(0))
		out := ctx.Arg(1)
		if !ok || out == 0 {
			return GdipInvalidParameter
		}
		_ = ctx.Mem.Write32(out, uint32(img.height))
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipGetImagePixelFormat", func(ctx *ntapi.TrapContext) uint32 {
		img, ok := gdipGetImage(ctx.Arg(0))
		out := ctx.Arg(1)
		if !ok || out == 0 {
			return GdipInvalidParameter
		}
		_ = ctx.Mem.Write32(out, uint32(img.format))
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipBitmapLockBits", func(ctx *ntapi.TrapContext) uint32 {
		img, ok := gdipGetImage(ctx.Arg(0))
		out := ctx.Arg(4)
		if !ok || out == 0 {
			return GdipInvalidParameter
		}
		lockSize := uint64(len(img.data))
		addr := ctx.Mem.Mmap(0, lockSize, mmu.PermRead|mmu.PermWrite)
		for i, b := range img.data {
			_ = ctx.Mem.Write8(addr+uint64(i), b)
		}
		img.lockAddr = addr
		img.lockFlags = uint32(ctx.Arg(2))
		img.locked = true
		_ = ctx.Mem.Write32(out+0, uint32(img.width))
		_ = ctx.Mem.Write32(out+4, uint32(img.height))
		_ = ctx.Mem.Write32(out+8, uint32(int32(img.stride)))
		_ = ctx.Mem.Write32(out+12, uint32(img.format))
		_ = ctx.Mem.Write64(out+16, addr)
		_ = ctx.Mem.Write64(out+24, 0)
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipBitmapUnlockBits", func(ctx *ntapi.TrapContext) uint32 {
		img, ok := gdipGetImage(ctx.Arg(0))
		if !ok || !img.locked {
			return GdipInvalidParameter
		}
		if img.lockFlags&2 != 0 {
			for i := range img.data {
				b, err := ctx.Mem.Read8(img.lockAddr + uint64(i))
				if err != nil {
					break
				}
				img.data[i] = b
			}
		}
		img.locked = false
		img.lockAddr = 0
		img.lockFlags = 0
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipLoadImageFromFile", func(ctx *ntapi.TrapContext) uint32 {
		namePtr := ctx.Arg(0)
		out := ctx.Arg(1)
		if namePtr == 0 || out == 0 {
			return GdipInvalidParameter
		}
		path := winPathToVFS(readGuestUTF16(namePtr))
		data, err := gdipReadVFSFile(ctx, path)
		if err != nil {
			return GdipGenericError
		}
		img, ok := gdipDecodeBMP(data)
		if !ok {
			return GdipNotImplemented
		}
		h := gdipStoreImage(img)
		_ = ctx.Mem.Write64(out, h)
		return GdipOk
	})

	d.RegisterAutoStubHandler(dll, "GdipCreateMatrix", func(ctx *ntapi.TrapContext) uint32 {
		out := ctx.Arg(0)
		if out == 0 {
			return GdipInvalidParameter
		}
		h := gdipStoreMatrix(&gdipMatrix{m: gdipIdentityMatrix()})
		_ = ctx.Mem.Write64(out, h)
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipDeleteMatrix", func(ctx *ntapi.TrapContext) uint32 {
		gdipMu.Lock()
		defer gdipMu.Unlock()
		if _, ok := gdipMatrixMap[ctx.Arg(0)]; !ok {
			return GdipInvalidParameter
		}
		delete(gdipMatrixMap, ctx.Arg(0))
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipSetWorldTransform", func(ctx *ntapi.TrapContext) uint32 {
		g, ok := gdipGetGraphics(ctx.Arg(0))
		if !ok {
			return GdipInvalidParameter
		}
		m, ok := gdipGetMatrix(ctx.Arg(1))
		if !ok {
			return GdipInvalidParameter
		}
		g.world = m.m
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipResetWorldTransform", func(ctx *ntapi.TrapContext) uint32 {
		g, ok := gdipGetGraphics(ctx.Arg(0))
		if !ok {
			return GdipInvalidParameter
		}
		g.world = gdipIdentityMatrix()
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipTranslateWorldTransform", func(ctx *ntapi.TrapContext) uint32 {
		g, ok := gdipGetGraphics(ctx.Arg(0))
		if !ok {
			return GdipInvalidParameter
		}
		t := gdipTranslateMatrix(float64(gdipRealArg32(ctx, 1)), float64(gdipRealArg32(ctx, 2)))
		g.world = gdipCombineMatrix(g.world, t, int(int32(ctx.Arg(3))))
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipRotateWorldTransform", func(ctx *ntapi.TrapContext) uint32 {
		g, ok := gdipGetGraphics(ctx.Arg(0))
		if !ok {
			return GdipInvalidParameter
		}
		t := gdipRotateMatrix(float64(gdipRealArg32(ctx, 1)))
		g.world = gdipCombineMatrix(g.world, t, int(int32(ctx.Arg(2))))
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipScaleWorldTransform", func(ctx *ntapi.TrapContext) uint32 {
		g, ok := gdipGetGraphics(ctx.Arg(0))
		if !ok {
			return GdipInvalidParameter
		}
		t := gdipScaleMatrix(float64(gdipRealArg32(ctx, 1)), float64(gdipRealArg32(ctx, 2)))
		g.world = gdipCombineMatrix(g.world, t, int(int32(ctx.Arg(3))))
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipMultiplyMatrix", func(ctx *ntapi.TrapContext) uint32 {
		m1, ok1 := gdipGetMatrix(ctx.Arg(0))
		m2, ok2 := gdipGetMatrix(ctx.Arg(1))
		if !ok1 || !ok2 {
			return GdipInvalidParameter
		}
		m1.m = gdipCombineMatrix(m1.m, m2.m, int(int32(ctx.Arg(2))))
		return GdipOk
	})

	d.RegisterAutoStubHandler(dll, "GdipCreatePath", func(ctx *ntapi.TrapContext) uint32 {
		out := ctx.Arg(1)
		if out == 0 {
			return GdipInvalidParameter
		}
		h := gdipStorePath(&gdipPath{fillMode: int(int32(ctx.Arg(0)))})
		_ = ctx.Mem.Write64(out, h)
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipDeletePath", func(ctx *ntapi.TrapContext) uint32 {
		gdipMu.Lock()
		defer gdipMu.Unlock()
		if _, ok := gdipPathMap[ctx.Arg(0)]; !ok {
			return GdipInvalidParameter
		}
		delete(gdipPathMap, ctx.Arg(0))
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipAddPathLine", func(ctx *ntapi.TrapContext) uint32 {
		p, ok := gdipGetPath(ctx.Arg(0))
		if !ok {
			return GdipInvalidParameter
		}
		gdipPathAddLine(p,
			float64(gdipRealArg32(ctx, 1)),
			float64(gdipRealArg32(ctx, 2)),
			float64(gdipRealArg32(ctx, 3)),
			float64(gdipRealArg32(ctx, 4)))
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipAddPathArc", func(ctx *ntapi.TrapContext) uint32 {
		p, ok := gdipGetPath(ctx.Arg(0))
		if !ok {
			return GdipInvalidParameter
		}
		gdipPathAddArc(p,
			float64(gdipRealArg32(ctx, 1)),
			float64(gdipRealArg32(ctx, 2)),
			float64(gdipRealArg32(ctx, 3)),
			float64(gdipRealArg32(ctx, 4)),
			float64(gdipRealArg32(ctx, 5)),
			float64(gdipRealArg32(ctx, 6)))
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipAddPathRectangle", func(ctx *ntapi.TrapContext) uint32 {
		p, ok := gdipGetPath(ctx.Arg(0))
		if !ok {
			return GdipInvalidParameter
		}
		gdipPathAddRectangle(p,
			float64(gdipRealArg32(ctx, 1)),
			float64(gdipRealArg32(ctx, 2)),
			float64(gdipRealArg32(ctx, 3)),
			float64(gdipRealArg32(ctx, 4)))
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipAddPathEllipse", func(ctx *ntapi.TrapContext) uint32 {
		p, ok := gdipGetPath(ctx.Arg(0))
		if !ok {
			return GdipInvalidParameter
		}
		gdipPathAddEllipse(p,
			float64(gdipRealArg32(ctx, 1)),
			float64(gdipRealArg32(ctx, 2)),
			float64(gdipRealArg32(ctx, 3)),
			float64(gdipRealArg32(ctx, 4)))
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipClosePathFigure", func(ctx *ntapi.TrapContext) uint32 {
		p, ok := gdipGetPath(ctx.Arg(0))
		if !ok {
			return GdipInvalidParameter
		}
		gdipPathCloseFigure(p)
		return GdipOk
	})
	d.RegisterAutoStubHandler(dll, "GdipStartPathFigure", func(ctx *ntapi.TrapContext) uint32 {
		p, ok := gdipGetPath(ctx.Arg(0))
		if !ok {
			return GdipInvalidParameter
		}
		gdipPathStartFigure(p)
		return GdipOk
	})
}

func gdipStoreGraphics(g *gdipGraphics) uint64 {
	gdipMu.Lock()
	defer gdipMu.Unlock()
	h := gdipNextHandle
	gdipNextHandle++
	gdipGraphicsMap[h] = g
	return h
}

func gdipStorePen(p *gdipPen) uint64 {
	gdipMu.Lock()
	defer gdipMu.Unlock()
	h := gdipNextHandle
	gdipNextHandle++
	gdipPenMap[h] = p
	return h
}

func gdipStoreBrush(b *gdipBrush) uint64 {
	gdipMu.Lock()
	defer gdipMu.Unlock()
	h := gdipNextHandle
	gdipNextHandle++
	gdipBrushMap[h] = b
	return h
}

func gdipStoreFont(f *gdipFont) uint64 {
	gdipMu.Lock()
	defer gdipMu.Unlock()
	h := gdipNextHandle
	gdipNextHandle++
	gdipFontMap[h] = f
	return h
}

func gdipStoreImage(i *gdipImage) uint64 {
	gdipMu.Lock()
	defer gdipMu.Unlock()
	h := gdipNextHandle
	gdipNextHandle++
	gdipImageMap[h] = i
	return h
}

func gdipStoreStringFormat(f *gdipStringFormat) uint64 {
	gdipMu.Lock()
	defer gdipMu.Unlock()
	h := gdipNextHandle
	gdipNextHandle++
	gdipStringFmtMap[h] = f
	return h
}

func gdipStoreFontFamily(name string) uint64 {
	gdipMu.Lock()
	defer gdipMu.Unlock()
	h := gdipNextHandle
	gdipNextHandle++
	gdipFontFamilyMap[h] = name
	return h
}

func gdipStoreMatrix(m *gdipMatrix) uint64 {
	gdipMu.Lock()
	defer gdipMu.Unlock()
	h := gdipNextHandle
	gdipNextHandle++
	gdipMatrixMap[h] = m
	return h
}

func gdipStorePath(p *gdipPath) uint64 {
	gdipMu.Lock()
	defer gdipMu.Unlock()
	h := gdipNextHandle
	gdipNextHandle++
	gdipPathMap[h] = p
	return h
}

func gdipGetGraphics(h uint64) (*gdipGraphics, bool) {
	gdipMu.Lock()
	defer gdipMu.Unlock()
	g, ok := gdipGraphicsMap[h]
	return g, ok
}

func gdipGetPen(h uint64) (*gdipPen, bool) {
	gdipMu.Lock()
	defer gdipMu.Unlock()
	p, ok := gdipPenMap[h]
	return p, ok
}

func gdipGetBrush(h uint64) (*gdipBrush, bool) {
	gdipMu.Lock()
	defer gdipMu.Unlock()
	b, ok := gdipBrushMap[h]
	return b, ok
}

func gdipGetFont(h uint64) (*gdipFont, bool) {
	gdipMu.Lock()
	defer gdipMu.Unlock()
	f, ok := gdipFontMap[h]
	return f, ok
}

func gdipGetImage(h uint64) (*gdipImage, bool) {
	gdipMu.Lock()
	defer gdipMu.Unlock()
	img, ok := gdipImageMap[h]
	return img, ok
}

func gdipGetStringFormat(h uint64) (*gdipStringFormat, bool) {
	if h == 0 {
		return nil, false
	}
	gdipMu.Lock()
	defer gdipMu.Unlock()
	f, ok := gdipStringFmtMap[h]
	return f, ok
}

func gdipGetFontFamily(h uint64) (string, bool) {
	gdipMu.Lock()
	defer gdipMu.Unlock()
	name, ok := gdipFontFamilyMap[h]
	return name, ok
}

func gdipGetMatrix(h uint64) (*gdipMatrix, bool) {
	gdipMu.Lock()
	defer gdipMu.Unlock()
	m, ok := gdipMatrixMap[h]
	return m, ok
}

func gdipGetPath(h uint64) (*gdipPath, bool) {
	gdipMu.Lock()
	defer gdipMu.Unlock()
	p, ok := gdipPathMap[h]
	return p, ok
}

func gdipGetGraphicsDC(gdiMgr *gdi.Manager, h uint64) (*gdipGraphics, *gdi.DC, bool) {
	g, ok := gdipGetGraphics(h)
	if !ok {
		return nil, nil, false
	}
	dc := gdiMgr.GetDC(g.hdc)
	if dc == nil {
		return g, nil, false
	}
	return g, dc, true
}

func gdipStatusForGraphics(ok bool) uint32 {
	if ok {
		return GdipGenericError
	}
	return GdipInvalidParameter
}

func gdipIdentityMatrix() [6]float64 {
	return [6]float64{1, 0, 0, 1, 0, 0}
}

func gdipARGBToColorRef(c uint32) uint32 {
	return c & 0x00FFFFFF
}

func gdipReadUTF16Text(ctx *ntapi.TrapContext, readGuestUTF16 func(uint64) string, readGuestUTF16N func(uint64, int) string, ptr, n uint64) string {
	if ptr == 0 {
		return ""
	}
	if int32(n) < 0 {
		return readGuestUTF16(ptr)
	}
	return readGuestUTF16N(ptr, int(n))
}

func gdipRealArg32(ctx *ntapi.TrapContext, pos int) float32 {
	if pos < 4 {
		if xa, ok := ctx.CPU.(ntapi.XMMAccess); ok {
			return math.Float32frombits(uint32(xa.ReadXMM(pos)))
		}
	}
	return math.Float32frombits(uint32(ctx.Arg(pos)))
}

func gdipReadRectF(mem *mmu.MMU, addr uint64) (float32, float32, float32, float32) {
	if addr == 0 {
		return 0, 0, 0, 0
	}
	return gdipReadFloat32(mem, addr), gdipReadFloat32(mem, addr+4), gdipReadFloat32(mem, addr+8), gdipReadFloat32(mem, addr+12)
}

func gdipWriteRectF(mem *mmu.MMU, addr uint64, x, y, w, h float32) error {
	if addr == 0 {
		return nil
	}
	if err := mem.Write32(addr, math.Float32bits(x)); err != nil {
		return err
	}
	if err := mem.Write32(addr+4, math.Float32bits(y)); err != nil {
		return err
	}
	if err := mem.Write32(addr+8, math.Float32bits(w)); err != nil {
		return err
	}
	return mem.Write32(addr+12, math.Float32bits(h))
}

func gdipReadFloat32(mem *mmu.MMU, addr uint64) float32 {
	v, _ := mem.Read32(addr)
	return math.Float32frombits(v)
}

func gdipTransformPoint(g *gdipGraphics, x, y float64) (float64, float64) {
	m := g.world
	return x*m[0] + y*m[2] + m[4], x*m[1] + y*m[3] + m[5]
}

func gdipTransformRect(g *gdipGraphics, x, y, w, h float64) (float64, float64, float64, float64) {
	p1x, p1y := gdipTransformPoint(g, x, y)
	p2x, p2y := gdipTransformPoint(g, x+w, y)
	p3x, p3y := gdipTransformPoint(g, x+w, y+h)
	p4x, p4y := gdipTransformPoint(g, x, y+h)
	minX := math.Min(math.Min(p1x, p2x), math.Min(p3x, p4x))
	maxX := math.Max(math.Max(p1x, p2x), math.Max(p3x, p4x))
	minY := math.Min(math.Min(p1y, p2y), math.Min(p3y, p4y))
	maxY := math.Max(math.Max(p1y, p2y), math.Max(p3y, p4y))
	return minX, minY, maxX - minX, maxY - minY
}

func gdipCombineClip(x1, y1, w1, h1, x2, y2, w2, h2 float64, mode int) (float64, float64, float64, float64) {
	switch mode {
	case gdipCombineIntersect:
		l := math.Max(x1, x2)
		t := math.Max(y1, y2)
		r := math.Min(x1+w1, x2+w2)
		b := math.Min(y1+h1, y2+h2)
		if r < l || b < t {
			return l, t, 0, 0
		}
		return l, t, r - l, b - t
	default:
		l := math.Min(x1, x2)
		t := math.Min(y1, y2)
		r := math.Max(x1+w1, x2+w2)
		b := math.Max(y1+h1, y2+h2)
		return l, t, r - l, b - t
	}
}

func gdipApplyClip(g *gdipGraphics, dc *gdi.DC) {
	if !g.clipActive {
		dc.SetClipRect(0, 0, 0, 0)
		return
	}
	x, y, w, h := gdipTransformRect(g, g.clipX, g.clipY, g.clipW, g.clipH)
	ax := int32(math.Round(x)) + dc.OriginX
	ay := int32(math.Round(y)) + dc.OriginY
	aw := int32(math.Round(w))
	ah := int32(math.Round(h))
	dc.SetClipRect(ax, ay, ax+aw, ay+ah)
}

func gdipDrawLine(gdiMgr *gdi.Manager, ctx *ntapi.TrapContext, integer bool) uint32 {
	g, dc, ok := gdipGetGraphicsDC(gdiMgr, ctx.Arg(0))
	if !ok {
		return gdipStatusForGraphics(ok)
	}
	pen, ok := gdipGetPen(ctx.Arg(1))
	if !ok {
		return GdipInvalidParameter
	}
	var x1, y1, x2, y2 float64
	if integer {
		x1 = float64(int32(ctx.Arg(2)))
		y1 = float64(int32(ctx.Arg(3)))
		x2 = float64(int32(ctx.Arg(4)))
		y2 = float64(int32(ctx.Arg(5)))
	} else {
		x1 = float64(gdipRealArg32(ctx, 2))
		y1 = float64(gdipRealArg32(ctx, 3))
		x2 = float64(gdipRealArg32(ctx, 4))
		y2 = float64(gdipRealArg32(ctx, 5))
	}
	tx1, ty1 := gdipTransformPoint(g, x1, y1)
	tx2, ty2 := gdipTransformPoint(g, x2, y2)
	oldPen, oldBrush := dc.Pen, dc.Brush
	dc.Pen = &gdi.Pen{Style: int32(pen.style), Width: int32(math.Round(float64(pen.width))), Color: gdipARGBToColorRef(pen.color)}
	dc.Brush = &gdi.Brush{Style: 1}
	dc.MoveTo(int32(math.Round(tx1)), int32(math.Round(ty1)))
	dc.LineTo(int32(math.Round(tx2)), int32(math.Round(ty2)))
	dc.Pen, dc.Brush = oldPen, oldBrush
	return GdipOk
}

func gdipDrawRect(gdiMgr *gdi.Manager, ctx *ntapi.TrapContext, integer, fill bool) uint32 {
	g, dc, ok := gdipGetGraphicsDC(gdiMgr, ctx.Arg(0))
	if !ok {
		return gdipStatusForGraphics(ok)
	}
	var x, y, w, h float64
	if integer {
		x = float64(int32(ctx.Arg(2)))
		y = float64(int32(ctx.Arg(3)))
		w = float64(int32(ctx.Arg(4)))
		h = float64(int32(ctx.Arg(5)))
	} else {
		x = float64(gdipRealArg32(ctx, 2))
		y = float64(gdipRealArg32(ctx, 3))
		w = float64(gdipRealArg32(ctx, 4))
		h = float64(gdipRealArg32(ctx, 5))
	}
	tx, ty, tw, th := gdipTransformRect(g, x, y, w, h)
	x0 := int32(math.Round(tx))
	y0 := int32(math.Round(ty))
	x1 := x0 + int32(math.Round(tw))
	y1 := y0 + int32(math.Round(th))
	oldPen, oldBrush := dc.Pen, dc.Brush
	if fill {
		brush, ok := gdipGetBrush(ctx.Arg(1))
		if !ok {
			return GdipInvalidParameter
		}
		dc.Brush = &gdi.Brush{Style: 0, Color: gdipARGBToColorRef(brush.color)}
		dc.Pen = &gdi.Pen{Style: 5}
		dc.Rectangle(x0, y0, x1, y1)
	} else {
		pen, ok := gdipGetPen(ctx.Arg(1))
		if !ok {
			return GdipInvalidParameter
		}
		dc.Pen = &gdi.Pen{Style: int32(pen.style), Width: int32(math.Round(float64(pen.width))), Color: gdipARGBToColorRef(pen.color)}
		dc.Brush = &gdi.Brush{Style: 1}
		dc.Rectangle(x0, y0, x1, y1)
	}
	dc.Pen, dc.Brush = oldPen, oldBrush
	return GdipOk
}

func gdipDrawEllipse(gdiMgr *gdi.Manager, ctx *ntapi.TrapContext, integer, fill bool) uint32 {
	g, dc, ok := gdipGetGraphicsDC(gdiMgr, ctx.Arg(0))
	if !ok {
		return gdipStatusForGraphics(ok)
	}
	var x, y, w, h float64
	if integer {
		x = float64(int32(ctx.Arg(2)))
		y = float64(int32(ctx.Arg(3)))
		w = float64(int32(ctx.Arg(4)))
		h = float64(int32(ctx.Arg(5)))
	} else {
		x = float64(gdipRealArg32(ctx, 2))
		y = float64(gdipRealArg32(ctx, 3))
		w = float64(gdipRealArg32(ctx, 4))
		h = float64(gdipRealArg32(ctx, 5))
	}
	tx, ty, tw, th := gdipTransformRect(g, x, y, w, h)
	x0 := int32(math.Round(tx))
	y0 := int32(math.Round(ty))
	x1 := x0 + int32(math.Round(tw))
	y1 := y0 + int32(math.Round(th))
	oldPen, oldBrush := dc.Pen, dc.Brush
	if fill {
		brush, ok := gdipGetBrush(ctx.Arg(1))
		if !ok {
			return GdipInvalidParameter
		}
		dc.Brush = &gdi.Brush{Style: 0, Color: gdipARGBToColorRef(brush.color)}
		dc.Pen = &gdi.Pen{Style: 5}
	} else {
		pen, ok := gdipGetPen(ctx.Arg(1))
		if !ok {
			return GdipInvalidParameter
		}
		dc.Pen = &gdi.Pen{Style: int32(pen.style), Width: int32(math.Round(float64(pen.width))), Color: gdipARGBToColorRef(pen.color)}
		dc.Brush = &gdi.Brush{Style: 1}
	}
	dc.Ellipse(x0, y0, x1, y1)
	dc.Pen, dc.Brush = oldPen, oldBrush
	return GdipOk
}

func gdipMakeGDIFont(font *gdipFont) *gdi.Font {
	size := int32(math.Round(float64(font.size)))
	if size == 0 {
		size = 12
	}
	f := &gdi.Font{
		Height:   size,
		Width:    0,
		Weight:   400,
		FaceName: font.family,
		FaceID:   gdi.ResolveFontFace(font.family),
	}
	if f.FaceID >= 0 {
		cellH, asc, desc, aveW := gdi.FaceMetrics(f.FaceID, size)
		f.CellHeight = cellH
		f.Ascent = asc
		f.Descent = desc
		f.AveCharWidth = aveW
		f.MaxCharWidth = aveW * 2
	} else {
		df := gdi.DefaultFont()
		f.AveCharWidth = df.AveCharWidth
		f.MaxCharWidth = df.MaxCharWidth
		f.CellHeight = df.CellHeight
		f.Ascent = df.Ascent
		f.Descent = df.Descent
	}
	return f
}

func gdipTextAlign(hAlign, vAlign int) int32 {
	var align int32
	switch hAlign {
	case 1:
		align |= 6
	case 2:
		align |= 2
	}
	switch vAlign {
	case 1:
		align |= 8
	case 2:
		align |= 24
	}
	return align
}

func gdipLayoutText(x, y, w, h, textW, textH float64, format *gdipStringFormat) (float64, float64) {
	if format == nil {
		return x, y
	}
	switch format.align {
	case 1:
		x += (w - textW) / 2
	case 2:
		x += w - textW
	}
	switch format.lineAlign {
	case 1:
		y += (h - textH) / 2
	case 2:
		y += h - textH
	}
	return x, y
}

func gdipDrawImage(gdiMgr *gdi.Manager, ctx *ntapi.TrapContext, img *gdipImage, x, y, w, h int32) uint32 {
	g, dc, ok := gdipGetGraphicsDC(gdiMgr, ctx.Arg(0))
	if !ok {
		return gdipStatusForGraphics(ok)
	}
	if img.width <= 0 || img.height <= 0 || dc.Target == nil {
		return GdipInvalidParameter
	}
	src := gdi.WrapPix(img.data, int32(img.width), int32(img.height), int32(img.stride))
	tx, ty, tw, th := gdipTransformRect(g, float64(x), float64(y), float64(w), float64(h))
	dx := int32(math.Round(tx)) + dc.OriginX
	dy := int32(math.Round(ty)) + dc.OriginY
	dw := int32(math.Round(tw))
	dh := int32(math.Round(th))
	if dw <= 0 || dh <= 0 {
		return GdipOk
	}
	if dw == int32(img.width) && dh == int32(img.height) {
		dc.Target.BitBlt(dx, dy, src, 0, 0, dw, dh)
	} else {
		dc.Target.StretchBlt(dx, dy, dw, dh, src, 0, 0, int32(img.width), int32(img.height))
	}
	return GdipOk
}

func gdipReadPointI(mem *mmu.MMU, addr uint64) (int32, int32) {
	x, _ := mem.Read32(addr)
	y, _ := mem.Read32(addr + 4)
	return int32(x), int32(y)
}

func gdipDrawPolygon(gdiMgr *gdi.Manager, ctx *ntapi.TrapContext, integer, fill bool) uint32 {
	g, dc, ok := gdipGetGraphicsDC(gdiMgr, ctx.Arg(0))
	if !ok {
		return gdipStatusForGraphics(ok)
	}
	pointsPtr := ctx.Arg(2)
	count := int(int32(ctx.Arg(3)))
	if fill {
		pointsPtr = ctx.Arg(2)
		count = int(int32(ctx.Arg(3)))
	}
	if count <= 0 || pointsPtr == 0 {
		return GdipInvalidParameter
	}
	pts := make([][2]int32, 0, count)
	for i := 0; i < count; i++ {
		x, y := gdipReadPointI(ctx.Mem, pointsPtr+uint64(i*8))
		tx, ty := gdipTransformPoint(g, float64(x), float64(y))
		pts = append(pts, [2]int32{int32(math.Round(tx)), int32(math.Round(ty))})
	}
	oldPen, oldBrush := dc.Pen, dc.Brush
	if fill {
		brush, ok := gdipGetBrush(ctx.Arg(1))
		if !ok {
			return GdipInvalidParameter
		}
		dc.Brush = &gdi.Brush{Style: 0, Color: gdipARGBToColorRef(brush.color)}
		dc.Pen = &gdi.Pen{Style: 5}
	} else {
		pen, ok := gdipGetPen(ctx.Arg(1))
		if !ok {
			return GdipInvalidParameter
		}
		dc.Pen = &gdi.Pen{Style: int32(pen.style), Width: int32(math.Round(float64(pen.width))), Color: gdipARGBToColorRef(pen.color)}
		dc.Brush = &gdi.Brush{Style: 1}
	}
	dc.Polygon(pts)
	dc.Pen, dc.Brush = oldPen, oldBrush
	return GdipOk
}

func gdipRenderPath(gdiMgr *gdi.Manager, ctx *ntapi.TrapContext, fill bool) uint32 {
	g, dc, ok := gdipGetGraphicsDC(gdiMgr, ctx.Arg(0))
	if !ok {
		return gdipStatusForGraphics(ok)
	}
	path, ok := gdipGetPath(ctx.Arg(2))
	if fill {
		path, ok = gdipGetPath(ctx.Arg(2))
	} else {
		path, ok = gdipGetPath(ctx.Arg(2))
	}
	if !ok {
		return GdipInvalidParameter
	}
	oldPen, oldBrush := dc.Pen, dc.Brush
	if fill {
		brush, ok := gdipGetBrush(ctx.Arg(1))
		if !ok {
			return GdipInvalidParameter
		}
		dc.Brush = &gdi.Brush{Style: 0, Color: gdipARGBToColorRef(brush.color)}
		dc.Pen = &gdi.Pen{Style: 5}
	} else {
		pen, ok := gdipGetPen(ctx.Arg(1))
		if !ok {
			return GdipInvalidParameter
		}
		dc.Pen = &gdi.Pen{Style: int32(pen.style), Width: int32(math.Round(float64(pen.width))), Color: gdipARGBToColorRef(pen.color)}
		dc.Brush = &gdi.Brush{Style: 1}
	}
	for i, fig := range path.figures {
		if len(fig) == 0 {
			continue
		}
		pts := make([][2]int32, 0, len(fig))
		for _, p := range fig {
			tx, ty := gdipTransformPoint(g, p[0], p[1])
			pts = append(pts, [2]int32{int32(math.Round(tx)), int32(math.Round(ty))})
		}
		if fill || (i < len(path.closed) && path.closed[i]) {
			dc.Polygon(pts)
		} else {
			dc.PolylinePoints(pts)
		}
	}
	dc.Pen, dc.Brush = oldPen, oldBrush
	return GdipOk
}

func gdipReadVFSFile(ctx *ntapi.TrapContext, path string) ([]byte, error) {
	fd, err := ctx.FS.Open(path, os.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer ctx.FS.Close(fd)
	var out []byte
	buf := make([]byte, 4096)
	for {
		n, readErr := ctx.FS.Read(fd, buf)
		if n > 0 {
			out = append(out, buf[:n]...)
		}
		if readErr != nil || n == 0 {
			break
		}
	}
	return out, nil
}

func gdipDecodeBMP(data []byte) (*gdipImage, bool) {
	if len(data) < 54 || data[0] != 'B' || data[1] != 'M' {
		return nil, false
	}
	off := int(binary.LittleEndian.Uint32(data[10:14]))
	infoSize := int(binary.LittleEndian.Uint32(data[14:18]))
	if infoSize < 40 || len(data) < off {
		return nil, false
	}
	w := int(int32(binary.LittleEndian.Uint32(data[18:22])))
	hSigned := int32(binary.LittleEndian.Uint32(data[22:26]))
	planes := binary.LittleEndian.Uint16(data[26:28])
	bpp := int(binary.LittleEndian.Uint16(data[28:30]))
	compression := binary.LittleEndian.Uint32(data[30:34])
	if w <= 0 || hSigned == 0 || planes != 1 || compression != 0 {
		return nil, false
	}
	topDown := hSigned < 0
	h := int(hSigned)
	if h < 0 {
		h = -h
	}
	if bpp != 24 && bpp != 32 {
		return nil, false
	}
	srcStride := ((w*bpp + 31) / 32) * 4
	if len(data) < off+srcStride*h {
		return nil, false
	}
	dstStride := w * 4
	dst := make([]byte, dstStride*h)
	for y := 0; y < h; y++ {
		srcY := y
		if !topDown {
			srcY = h - 1 - y
		}
		srcOff := off + srcY*srcStride
		dstOff := y * dstStride
		for x := 0; x < w; x++ {
			if bpp == 24 {
				dst[dstOff+x*4+0] = data[srcOff+x*3+0]
				dst[dstOff+x*4+1] = data[srcOff+x*3+1]
				dst[dstOff+x*4+2] = data[srcOff+x*3+2]
				dst[dstOff+x*4+3] = 0xFF
			} else {
				copy(dst[dstOff+x*4:dstOff+x*4+4], data[srcOff+x*4:srcOff+x*4+4])
				if dst[dstOff+x*4+3] == 0 {
					dst[dstOff+x*4+3] = 0xFF
				}
			}
		}
	}
	return &gdipImage{
		width:  w,
		height: h,
		format: gdipPixelFormat32bppARGB,
		data:   dst,
		stride: dstStride,
	}, true
}

func gdipTranslateMatrix(dx, dy float64) [6]float64 {
	return [6]float64{1, 0, 0, 1, dx, dy}
}

func gdipScaleMatrix(sx, sy float64) [6]float64 {
	return [6]float64{sx, 0, 0, sy, 0, 0}
}

func gdipRotateMatrix(angleDeg float64) [6]float64 {
	rad := angleDeg * math.Pi / 180
	c := math.Cos(rad)
	s := math.Sin(rad)
	return [6]float64{c, s, -s, c, 0, 0}
}

func gdipMultiply(a, b [6]float64) [6]float64 {
	return [6]float64{
		a[0]*b[0] + a[1]*b[2],
		a[0]*b[1] + a[1]*b[3],
		a[2]*b[0] + a[3]*b[2],
		a[2]*b[1] + a[3]*b[3],
		a[4]*b[0] + a[5]*b[2] + b[4],
		a[4]*b[1] + a[5]*b[3] + b[5],
	}
}

func gdipCombineMatrix(cur, other [6]float64, order int) [6]float64 {
	if order == gdipMatrixOrderAppend {
		return gdipMultiply(cur, other)
	}
	return gdipMultiply(other, cur)
}

func gdipPathEnsureFigure(p *gdipPath) int {
	if len(p.figures) == 0 {
		p.figures = append(p.figures, nil)
		p.closed = append(p.closed, false)
	}
	return len(p.figures) - 1
}

func gdipPathStartFigure(p *gdipPath) {
	if len(p.figures) == 0 || len(p.figures[len(p.figures)-1]) > 0 {
		p.figures = append(p.figures, nil)
		p.closed = append(p.closed, false)
	}
}

func gdipPathCloseFigure(p *gdipPath) {
	if len(p.closed) == 0 {
		gdipPathStartFigure(p)
	}
	p.closed[len(p.closed)-1] = true
}

func gdipPathAddLine(p *gdipPath, x1, y1, x2, y2 float64) {
	idx := gdipPathEnsureFigure(p)
	if len(p.figures[idx]) == 0 {
		p.figures[idx] = append(p.figures[idx], [2]float64{x1, y1})
	}
	last := p.figures[idx][len(p.figures[idx])-1]
	if last[0] != x1 || last[1] != y1 {
		p.figures[idx] = append(p.figures[idx], [2]float64{x1, y1})
	}
	p.figures[idx] = append(p.figures[idx], [2]float64{x2, y2})
}

func gdipPathAddArc(p *gdipPath, x, y, w, h, startDeg, sweepDeg float64) {
	idx := gdipPathEnsureFigure(p)
	cx := x + w/2
	cy := y + h/2
	rx := w / 2
	ry := h / 2
	steps := 16
	for i := 0; i <= steps; i++ {
		t := (startDeg + sweepDeg*float64(i)/float64(steps)) * math.Pi / 180
		px := cx + rx*math.Cos(t)
		py := cy + ry*math.Sin(t)
		p.figures[idx] = append(p.figures[idx], [2]float64{px, py})
	}
}

func gdipPathAddRectangle(p *gdipPath, x, y, w, h float64) {
	gdipPathStartFigure(p)
	idx := gdipPathEnsureFigure(p)
	p.figures[idx] = append(p.figures[idx],
		[2]float64{x, y},
		[2]float64{x + w, y},
		[2]float64{x + w, y + h},
		[2]float64{x, y + h},
	)
	p.closed[idx] = true
}

func gdipPathAddEllipse(p *gdipPath, x, y, w, h float64) {
	gdipPathStartFigure(p)
	idx := gdipPathEnsureFigure(p)
	cx := x + w/2
	cy := y + h/2
	rx := w / 2
	ry := h / 2
	steps := 24
	for i := 0; i < steps; i++ {
		t := 2 * math.Pi * float64(i) / float64(steps)
		p.figures[idx] = append(p.figures[idx], [2]float64{cx + rx*math.Cos(t), cy + ry*math.Sin(t)})
	}
	p.closed[idx] = true
}

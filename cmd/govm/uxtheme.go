package main

import (
	"sync"

	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

type themeState struct {
	mu         sync.Mutex
	nextHandle uint32
	themes     map[uint32]*themeData
}

type themeData struct {
	className string
	hwnd      uint64
}

var themeGlobal = themeState{nextHandle: 0x5000, themes: make(map[uint32]*themeData)}

type bufferedPaintState struct {
	mu         sync.Mutex
	nextHandle uint32
	paints     map[uint32]uint64
}

var bufferedPaintGlobal = bufferedPaintState{nextHandle: 0x6000, paints: make(map[uint32]uint64)}

type dwmThumbnailState struct {
	mu         sync.Mutex
	nextHandle uint32
	thumbs     map[uint32]struct{}
}

var dwmThumbnailGlobal = dwmThumbnailState{nextHandle: 0x7000, thumbs: make(map[uint32]struct{})}

const (
	sOK                     uint64 = 0
	eInvalidArg             uint64 = 0x80070057
	dwmECompositionDisabled uint64 = 0x80263001
)

func writeRect(mem *mmu.MMU, addr uint64, left, top, right, bottom int32) {
	if addr == 0 {
		return
	}
	mem.Write32(addr+0, uint32(left))
	mem.Write32(addr+4, uint32(top))
	mem.Write32(addr+8, uint32(right))
	mem.Write32(addr+12, uint32(bottom))
}

func readRect(mem *mmu.MMU, addr uint64) (int32, int32, int32, int32, bool) {
	if addr == 0 {
		return 0, 0, 0, 0, false
	}
	left, _ := mem.Read32(addr + 0)
	top, _ := mem.Read32(addr + 4)
	right, _ := mem.Read32(addr + 8)
	bottom, _ := mem.Read32(addr + 12)
	return int32(left), int32(top), int32(right), int32(bottom), true
}

func copyRect(mem *mmu.MMU, dst, src uint64) bool {
	left, top, right, bottom, ok := readRect(mem, src)
	if !ok || dst == 0 {
		return false
	}
	writeRect(mem, dst, left, top, right, bottom)
	return true
}

func writeSize(mem *mmu.MMU, addr uint64, cx, cy int32) {
	if addr == 0 {
		return
	}
	mem.Write32(addr+0, uint32(cx))
	mem.Write32(addr+4, uint32(cy))
}

func writePoint(mem *mmu.MMU, addr uint64, x, y int32) {
	if addr == 0 {
		return
	}
	mem.Write32(addr+0, uint32(x))
	mem.Write32(addr+4, uint32(y))
}

func writeMargins(mem *mmu.MMU, addr uint64, leftWidth, rightWidth, topHeight, bottomHeight int32) {
	if addr == 0 {
		return
	}
	mem.Write32(addr+0, uint32(leftWidth))
	mem.Write32(addr+4, uint32(rightWidth))
	mem.Write32(addr+8, uint32(topHeight))
	mem.Write32(addr+12, uint32(bottomHeight))
}

func writeBool32(mem *mmu.MMU, addr uint64, value bool) {
	if addr == 0 {
		return
	}
	if value {
		mem.Write32(addr, 1)
	} else {
		mem.Write32(addr, 0)
	}
}

func writeThemeString(mem *mmu.MMU, addr uint64, cch uint32, value string) uint32 {
	if addr == 0 || cch == 0 {
		return 0
	}
	ws := utf16Encode(value)
	limit := int(cch) - 1
	if limit < 0 {
		limit = 0
	}
	if len(ws) > limit {
		ws = ws[:limit]
	}
	for i, wc := range ws {
		mem.Write16(addr+uint64(i)*2, wc)
	}
	mem.Write16(addr+uint64(len(ws))*2, 0)
	return uint32(len(ws))
}

func writeLogFontW(mem *mmu.MMU, addr uint64, face string, height int32) {
	if addr == 0 {
		return
	}
	mem.Write32(addr+0, uint32(height))
	mem.Write32(addr+4, 0)
	mem.Write32(addr+8, 0)
	mem.Write32(addr+12, 0)
	mem.Write32(addr+16, 400)
	mem.Write8(addr+20, 0)
	mem.Write8(addr+21, 0)
	mem.Write8(addr+22, 0)
	mem.Write8(addr+23, 1)
	mem.Write8(addr+24, 0)
	mem.Write8(addr+25, 0)
	mem.Write8(addr+26, 5)
	mem.Write8(addr+27, 0x22)
	ws := utf16Encode(face)
	if len(ws) > 31 {
		ws = ws[:31]
	}
	for i, wc := range ws {
		mem.Write16(addr+28+uint64(i)*2, wc)
	}
	mem.Write16(addr+28+uint64(len(ws))*2, 0)
}

func registerUxthemeHandlers(hctx *HandlerCtx) {
	d := hctx.Disp
	mem := hctx.Mem
	readGuestUTF16 := hctx.ReadGuestUTF16
	gdiMgr := hctx.GdiMgr
	getSysColor := hctx.GetSysColor

	uxtheme, ok := hctx.SynthByName["uxtheme.dll"]
	if !ok {
		return
	}

	defaultThemeColor := func() uint32 {
		if getSysColor != nil {
			return getSysColor(15)
		}
		return 0x00F0F0F0
	}
	defaultThemeInt := func() uint32 { return 0 }
	defaultThemeMetric := func() uint32 { return 20 }
	defaultThemeSize := func() (int32, int32) { return 20, 20 }
	defaultTextRect := func(text string) (int32, int32, int32, int32) {
		width := int32(len([]rune(text)) * 8)
		if width <= 0 {
			width = 20
		}
		return 0, 0, width, 20
	}
	allocThemeHandle := func(hwnd uint64, className string) uint64 {
		themeGlobal.mu.Lock()
		defer themeGlobal.mu.Unlock()
		h := themeGlobal.nextHandle
		themeGlobal.nextHandle++
		themeGlobal.themes[h] = &themeData{className: className, hwnd: hwnd}
		return uint64(h)
	}
	closeThemeHandle := func(handle uint64) {
		themeGlobal.mu.Lock()
		delete(themeGlobal.themes, uint32(handle))
		themeGlobal.mu.Unlock()
	}
	allocBufferedHandle := func(hdcTarget uint64) uint64 {
		bufferedPaintGlobal.mu.Lock()
		defer bufferedPaintGlobal.mu.Unlock()
		h := bufferedPaintGlobal.nextHandle
		bufferedPaintGlobal.nextHandle++
		bufferedPaintGlobal.paints[h] = hdcTarget
		return uint64(h)
	}
	closeBufferedHandle := func(handle uint64) {
		bufferedPaintGlobal.mu.Lock()
		delete(bufferedPaintGlobal.paints, uint32(handle))
		bufferedPaintGlobal.mu.Unlock()
	}

	d.RegisterAutoStubHandler(uxtheme, "OpenThemeData", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		className := readGuestUTF16(ctx.Arg(1))
		if className == "" {
			className = "window"
		}
		ctx.SetReturn(allocThemeHandle(hwnd, className))
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "OpenThemeDataEx", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		className := readGuestUTF16(ctx.Arg(1))
		if className == "" {
			className = "window"
		}
		_ = ctx.Arg(2)
		ctx.SetReturn(allocThemeHandle(hwnd, className))
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "CloseThemeData", func(ctx *ntapi.TrapContext) uint32 {
		closeThemeHandle(ctx.Arg(0))
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "IsThemeActive", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "IsAppThemed", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "SetWindowTheme", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "GetCurrentThemeName", func(ctx *ntapi.TrapContext) uint32 {
		writeThemeString(mem, ctx.Arg(0), uint32(ctx.Arg(1)), "Raven")
		writeThemeString(mem, ctx.Arg(2), uint32(ctx.Arg(3)), "NormalColor")
		writeThemeString(mem, ctx.Arg(4), uint32(ctx.Arg(5)), "NormalSize")
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "GetWindowTheme", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(uxtheme, "DrawThemeBackground", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "DrawThemeBackgroundEx", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "DrawThemeText", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "DrawThemeTextEx", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "DrawThemeIcon", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "DrawThemeEdge", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "DrawThemeParentBackground", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "DrawThemeParentBackgroundEx", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(sOK)
		return 0
	})

	d.RegisterAutoStubHandler(uxtheme, "GetThemePartSize", func(ctx *ntapi.TrapContext) uint32 {
		w, h := defaultThemeSize()
		writeSize(mem, ctx.Arg(6), w, h)
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "GetThemeColor", func(ctx *ntapi.TrapContext) uint32 {
		if pColor := ctx.Arg(4); pColor != 0 {
			mem.Write32(pColor, defaultThemeColor())
		}
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "GetThemeFont", func(ctx *ntapi.TrapContext) uint32 {
		writeLogFontW(mem, ctx.Arg(5), "Segoe UI", -12)
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "GetThemeInt", func(ctx *ntapi.TrapContext) uint32 {
		if pValue := ctx.Arg(4); pValue != 0 {
			mem.Write32(pValue, defaultThemeInt())
		}
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "GetThemeBool", func(ctx *ntapi.TrapContext) uint32 {
		writeBool32(mem, ctx.Arg(4), true)
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "GetThemeMetric", func(ctx *ntapi.TrapContext) uint32 {
		if pValue := ctx.Arg(5); pValue != 0 {
			mem.Write32(pValue, defaultThemeMetric())
		}
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "GetThemeMargins", func(ctx *ntapi.TrapContext) uint32 {
		writeMargins(mem, ctx.Arg(6), 0, 0, 0, 0)
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "GetThemeRect", func(ctx *ntapi.TrapContext) uint32 {
		writeRect(mem, ctx.Arg(4), 0, 0, 20, 20)
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "GetThemePosition", func(ctx *ntapi.TrapContext) uint32 {
		writePoint(mem, ctx.Arg(4), 0, 0)
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "GetThemeBackgroundContentRect", func(ctx *ntapi.TrapContext) uint32 {
		if !copyRect(mem, ctx.Arg(5), ctx.Arg(4)) {
			writeRect(mem, ctx.Arg(5), 0, 0, 20, 20)
		}
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "GetThemeBackgroundExtent", func(ctx *ntapi.TrapContext) uint32 {
		if !copyRect(mem, ctx.Arg(5), ctx.Arg(4)) {
			writeRect(mem, ctx.Arg(5), 0, 0, 20, 20)
		}
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "GetThemeTextExtent", func(ctx *ntapi.TrapContext) uint32 {
		pBoundingRect := ctx.Arg(6)
		pExtentRect := ctx.Arg(7)
		if pBoundingRect != 0 && pExtentRect != 0 {
			copyRect(mem, pExtentRect, pBoundingRect)
		} else {
			text := readGuestUTF16(ctx.Arg(4))
			left, top, right, bottom := defaultTextRect(text)
			writeRect(mem, pExtentRect, left, top, right, bottom)
		}
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "GetThemeSysColor", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(defaultThemeColor()))
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "GetThemeSysColorBrush", func(ctx *ntapi.TrapContext) uint32 {
		if gdiMgr == nil {
			ctx.SetReturn(0)
		} else {
			ctx.SetReturn(gdiMgr.CreateSolidBrush(defaultThemeColor()))
		}
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "GetThemeSysFont", func(ctx *ntapi.TrapContext) uint32 {
		writeLogFontW(mem, ctx.Arg(2), "Segoe UI", -12)
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "GetThemeSysSize", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(16)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "IsThemePartDefined", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "IsThemeBackgroundPartiallyTransparent", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "IsThemeDialogTextureEnabled", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "HitTestThemeBackground", func(ctx *ntapi.TrapContext) uint32 {
		if pHitTest := ctx.Arg(8); pHitTest != 0 {
			mem.Write16(pHitTest, 0)
		}
		ctx.SetReturn(sOK)
		return 0
	})

	d.RegisterAutoStubHandler(uxtheme, "BufferedPaintInit", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "BufferedPaintUnInit", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "BeginBufferedPaint", func(ctx *ntapi.TrapContext) uint32 {
		hdcTarget := ctx.Arg(0)
		if phdc := ctx.Arg(4); phdc != 0 {
			mem.Write64(phdc, hdcTarget)
		}
		ctx.SetReturn(allocBufferedHandle(hdcTarget))
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "EndBufferedPaint", func(ctx *ntapi.TrapContext) uint32 {
		closeBufferedHandle(ctx.Arg(0))
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "BufferedPaintSetAlpha", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "BeginBufferedAnimation", func(ctx *ntapi.TrapContext) uint32 {
		hdcTarget := ctx.Arg(1)
		if phdcFrom := ctx.Arg(6); phdcFrom != 0 {
			mem.Write64(phdcFrom, hdcTarget)
		}
		if phdcTo := ctx.Arg(7); phdcTo != 0 {
			mem.Write64(phdcTo, hdcTarget)
		}
		ctx.SetReturn(allocBufferedHandle(hdcTarget))
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "EndBufferedAnimation", func(ctx *ntapi.TrapContext) uint32 {
		closeBufferedHandle(ctx.Arg(0))
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "BufferedPaintRenderAnimation", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "GetThemeTransitionDuration", func(ctx *ntapi.TrapContext) uint32 {
		if pDuration := ctx.Arg(4); pDuration != 0 {
			mem.Write32(pDuration, 0)
		}
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "EnableThemeDialogTexture", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "BufferedPaintStopAllAnimations", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(sOK)
		return 0
	})
}

func registerDwmapiHandlers(hctx *HandlerCtx) {
	d := hctx.Disp
	mem := hctx.Mem

	dwmapi, ok := hctx.SynthByName["dwmapi.dll"]
	if !ok {
		return
	}

	defaultWindowRect := func() (int32, int32, int32, int32) {
		if hctx.WlWindow != nil {
			return 0, 0, hctx.WlWindow.Width, hctx.WlWindow.Height
		}
		return 0, 0, 800, 600
	}
	allocThumbnail := func() uint64 {
		dwmThumbnailGlobal.mu.Lock()
		defer dwmThumbnailGlobal.mu.Unlock()
		h := dwmThumbnailGlobal.nextHandle
		dwmThumbnailGlobal.nextHandle++
		dwmThumbnailGlobal.thumbs[h] = struct{}{}
		return uint64(h)
	}
	freeThumbnail := func(handle uint64) bool {
		dwmThumbnailGlobal.mu.Lock()
		defer dwmThumbnailGlobal.mu.Unlock()
		h := uint32(handle)
		if _, ok := dwmThumbnailGlobal.thumbs[h]; !ok {
			return false
		}
		delete(dwmThumbnailGlobal.thumbs, h)
		return true
	}
	hasThumbnail := func(handle uint64) bool {
		dwmThumbnailGlobal.mu.Lock()
		_, ok := dwmThumbnailGlobal.thumbs[uint32(handle)]
		dwmThumbnailGlobal.mu.Unlock()
		return ok
	}

	d.RegisterAutoStubHandler(dwmapi, "DwmIsCompositionEnabled", func(ctx *ntapi.TrapContext) uint32 {
		writeBool32(mem, ctx.Arg(0), true)
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(dwmapi, "DwmEnableComposition", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(dwmapi, "DwmExtendFrameIntoClientArea", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(dwmapi, "DwmSetWindowAttribute", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(dwmapi, "DwmGetWindowAttribute", func(ctx *ntapi.TrapContext) uint32 {
		attr := uint32(ctx.Arg(1))
		pvAttr := ctx.Arg(2)
		cbAttr := uint32(ctx.Arg(3))
		if pvAttr != 0 {
			switch attr {
			case 1:
				if cbAttr >= 4 {
					mem.Write32(pvAttr, 1)
				}
			case 5, 9:
				left, top, right, bottom := defaultWindowRect()
				if cbAttr >= 16 {
					writeRect(mem, pvAttr, left, top, right, bottom)
				}
			case 14:
				if cbAttr >= 4 {
					mem.Write32(pvAttr, 0)
				}
			default:
				switch {
				case cbAttr >= 16:
					left, top, right, bottom := defaultWindowRect()
					writeRect(mem, pvAttr, left, top, right, bottom)
				case cbAttr >= 8:
					mem.Write64(pvAttr, 0)
				case cbAttr >= 4:
					mem.Write32(pvAttr, 0)
				case cbAttr >= 1:
					mem.Write8(pvAttr, 0)
				}
			}
		}
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(dwmapi, "DwmEnableBlurBehindWindow", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(dwmapi, "DwmDefWindowProc", func(ctx *ntapi.TrapContext) uint32 {
		if plResult := ctx.Arg(4); plResult != 0 {
			mem.Write64(plResult, 0)
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dwmapi, "DwmGetColorizationColor", func(ctx *ntapi.TrapContext) uint32 {
		if pcrColor := ctx.Arg(0); pcrColor != 0 {
			mem.Write32(pcrColor, 0xFF1E90FF)
		}
		writeBool32(mem, ctx.Arg(1), true)
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(dwmapi, "DwmFlush", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(dwmapi, "DwmInvalidateIconicBitmaps", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(dwmapi, "DwmSetIconicThumbnail", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(dwmapi, "DwmSetIconicLivePreviewBitmap", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(dwmapi, "DwmRegisterThumbnail", func(ctx *ntapi.TrapContext) uint32 {
		if ctx.Arg(0) == 0 || ctx.Arg(1) == 0 || ctx.Arg(2) == 0 {
			ctx.SetReturn(eInvalidArg)
			return 0
		}
		mem.Write64(ctx.Arg(2), allocThumbnail())
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(dwmapi, "DwmUnregisterThumbnail", func(ctx *ntapi.TrapContext) uint32 {
		if freeThumbnail(ctx.Arg(0)) {
			ctx.SetReturn(sOK)
		} else {
			ctx.SetReturn(eInvalidArg)
		}
		return 0
	})
	d.RegisterAutoStubHandler(dwmapi, "DwmUpdateThumbnailProperties", func(ctx *ntapi.TrapContext) uint32 {
		if !hasThumbnail(ctx.Arg(0)) {
			ctx.SetReturn(eInvalidArg)
		} else {
			ctx.SetReturn(sOK)
		}
		return 0
	})
	d.RegisterAutoStubHandler(dwmapi, "DwmGetTransportAttributes", func(ctx *ntapi.TrapContext) uint32 {
		writeBool32(mem, ctx.Arg(0), false)
		writeBool32(mem, ctx.Arg(1), false)
		if pGeneration := ctx.Arg(2); pGeneration != 0 {
			mem.Write32(pGeneration, 0)
		}
		ctx.SetReturn(dwmECompositionDisabled)
		return 0
	})
}

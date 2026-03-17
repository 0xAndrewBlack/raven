//go:build guest_windows

package main

import "github.com/mirkobrombin/Raven/pkg/ntapi"

// registerRealNtGdiHandlers installs win32k handlers that return ReactOS-format
// HGDIOBJs, registered AFTER registerAutoSynthHandlers (which registers the HLE
// win32u handlers via gdiMgr, whose 0x80000100+ handles are not valid ReactOS
// handles). Being registered last, these win the dispatcher's id→handler map,
// so a real ReactOS gdi32/user32 sees correctly-typed handles.
//
// Gated on Is32 + a BYO sysroot (real DLLs); the HLE path is unaffected.
func registerRealNtGdiHandlers(d *ntapi.Dispatcher) {
	// NtGdiGetStockObject(index) → stock HGDIOBJ. Encodes the object type in
	// bits 16-22 (GDILoObjType_LO_*) + stock mask 0x00800000; gdi32 caches it.
	d.RegisterWin32kHandler("NtGdiGetStockObject", func(ctx *ntapi.TrapContext) uint32 {
		idx := ctx.Arg(0)
		var loType uint32
		switch {
		case idx <= 5 || idx == 18: // brushes + DC_BRUSH
			loType = 0x00100000 // LO_BRUSH_TYPE
		case (idx >= 6 && idx <= 8) || idx == 19: // pens + DC_PEN
			loType = 0x00300000 // LO_PEN_TYPE
		case idx >= 10 && idx <= 17: // stock fonts
			loType = 0x000a0000 // LO_FONT_TYPE
		case idx == 9 || idx == 14: // palettes
			loType = 0x00080000 // LO_PALETTE_TYPE
		default:
			loType = 0x00100000
		}
		ctx.SetReturn(uint64(0x00800000 | loType | (0x20 + uint32(idx&0x1F))))
		return 0
	})
}

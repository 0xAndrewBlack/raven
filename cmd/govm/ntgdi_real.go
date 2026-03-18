//go:build guest_windows

package main

import (
	"github.com/mirkobrombin/Raven/pkg/ntapi"
	"github.com/mirkobrombin/Raven/pkg/winmgr"
)

// registerRealWin32kHandlers installs win32k handlers (NtUser*/NtGdi*) that back
// a REAL ReactOS user32/gdi32, over the pkg/winmgr + pkg/gfx engines owned by the
// win32k bridge. Registered AFTER registerAutoSynthHandlers so these (correct,
// ReactOS-format) handlers win the dispatcher map over the HLE win32u stubs.
// Gated on Is32 + sysroot. ZERO per-app hacks - the real DLLs drive everything.
func registerRealWin32kHandlers(d *ntapi.Dispatcher, b *win32kBridge) {
	reg := func(name string, h ntapi.TrapHandler) { d.RegisterWin32kHandler(name, h) }

	// --- GDI stock objects (real gdi32 caches these at init) ---
	reg("NtGdiGetStockObject", func(ctx *ntapi.TrapContext) uint32 {
		idx := ctx.Arg(0)
		var loType uint32
		switch {
		case idx <= 5 || idx == 18:
			loType = 0x00100000 // LO_BRUSH
		case (idx >= 6 && idx <= 8) || idx == 19:
			loType = 0x00300000 // LO_PEN
		case idx >= 10 && idx <= 17:
			loType = 0x000a0000 // LO_FONT
		case idx == 9 || idx == 14:
			loType = 0x00080000 // LO_PALETTE
		default:
			loType = 0x00100000
		}
		ctx.SetReturn(uint64(0x00800000 | loType | (0x20 + uint32(idx&0x1F))))
		return 0
	})

	// NtUserProcessConnect(hProcess, PUSERCONNECT, size): user32 init calls this
	// to obtain gSharedInfo (SERVERINFO + the HANDLEENTRY table aheList) used by
	// ValidateHwnd. Without it ShowWindow/BeginPaint no-op on a created window.
	reg("NtUserProcessConnect", func(ctx *ntapi.TrapContext) uint32 {
		b.setupSharedInfo(uint32(ctx.Arg(1)))
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})

	// --- user32 class registration. Real user32 keeps the WNDCLASS on its side;
	// the kernel needs a non-zero atom AND the WndProc (for the WND it creates).
	// NtUserRegisterClassExWOW(WNDCLASSEXW* lpwcx, ...): WNDCLASSEXW.lpfnWndProc@8.
	var nextAtom uint32 = 0xC001
	reg("NtUserRegisterClassExWOW", func(ctx *ntapi.TrapContext) uint32 {
		b.ensureClass()
		a := nextAtom
		nextAtom++
		if wcx := uint32(ctx.Arg(0)); wcx != 0 {
			wndproc, _ := b.mem.Read32(uint64(wcx) + 8) // lpfnWndProc
			b.wndProcOf[a] = uint32(wndproc)
			b.lastWndProc = uint32(wndproc)
		}
		ctx.SetReturn(uint64(a))
		return 0
	})
	// NtUserGetClassInfo(hinst, classname, pWndClassEx, pAtom?, ansi) -> BOOL.
	// Return 0 (class not yet known) so user32 proceeds to register it.
	reg("NtUserGetClassInfo", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})

	// --- window creation. ReactOS NtUserCreateWindowEx arg layout (0-indexed):
	// 0 dwExStyle, 1 plstrClassName, 2 plstrClsVersion, 3 plstrWindowName,
	// 4 dwStyle, 5 x, 6 y, 7 nWidth, 8 nHeight, ... ---
	reg("NtUserCreateWindowEx", func(ctx *ntapi.TrapContext) uint32 {
		b.ensureClass()
		x := int32(uint32(ctx.Arg(5)))
		y := int32(uint32(ctx.Arg(6)))
		w := int32(uint32(ctx.Arg(7)))
		h := int32(uint32(ctx.Arg(8)))
		if w <= 0 || w > 4096 {
			w = 400
		}
		if h <= 0 || h > 4096 {
			h = 300
		}
		win := b.wm.CreateWindow(winmgr.CreateWindowParams{
			ClassName: "RavenWindow",
			Style:     uint32(ctx.Arg(4)),
			X:         x, Y: y, W: w, H: h,
		})
		if win == nil {
			ctx.SetReturn(0)
			return 0
		}
		// Build the shared WND object so real user32 ValidateHwnd resolves it.
		b.createWND(uint32(win.Handle), uint32(ctx.Arg(4)), uint32(ctx.Arg(0)),
			b.lastWndProc, 0, x, y, w, h)
		ctx.SetReturn(uint64(uint32(win.Handle)))
		return 0
	})

	reg("NtUserShowWindow", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := winmgr.HWND(uint32(ctx.Arg(0)))
		b.wm.ShowWindow(hwnd, ctx.Arg(1) != 0)
		b.paintQueue = append(b.paintQueue, hwnd) // needs first WM_PAINT
		ctx.SetReturn(0)
		return 0
	})

	// --- message loop. Deliver one WM_PAINT per window
	// that needs painting, then WM_QUIT so the guest's GetMessage loop exits.
	// NtUserGetMessage(LPMSG pMsg, HWND, UINT min, UINT max) -> BOOL (0 on WM_QUIT)
	reg("NtUserGetMessage", func(ctx *ntapi.TrapContext) uint32 {
		pMsg := ctx.Arg(0)
		writeMsg := func(hwnd uint32, msg uint32) {
			b.mem.Write32(pMsg+0, hwnd) // hwnd
			b.mem.Write32(pMsg+4, msg)  // message
			b.mem.Write32(pMsg+8, 0)    // wParam
			b.mem.Write32(pMsg+12, 0)   // lParam
			b.mem.Write32(pMsg+16, 0)   // time
			b.mem.Write32(pMsg+20, 0)   // pt.x
			b.mem.Write32(pMsg+24, 0)   // pt.y
		}
		if len(b.paintQueue) > 0 {
			hwnd := b.paintQueue[0]
			b.paintQueue = b.paintQueue[1:]
			writeMsg(uint32(hwnd), 0x000F) // WM_PAINT
			ctx.SetReturn(1)
			return 0
		}
		writeMsg(0, 0x0012) // WM_QUIT
		ctx.SetReturn(0)
		return 0
	})

	// NtUserBeginPaint(HWND, PAINTSTRUCT*) -> HDC. Hand back a DC bound to the
	// window's client area on the screen surface; NtGdi* draws through it.
	reg("NtUserBeginPaint", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := winmgr.HWND(uint32(ctx.Arg(0)))
		pPS := ctx.Arg(1)
		hdc := b.beginPaintDC(hwnd)
		// PAINTSTRUCT (PE32): hdc@0, fErase@4, rcPaint@8 (l,t,r,b)
		if pPS != 0 {
			b.mem.Write32(pPS+0, hdc)
			b.mem.Write32(pPS+4, 0)
			if r, ok := b.wm.WindowRect(hwnd); ok {
				b.mem.Write32(pPS+8, 0)
				b.mem.Write32(pPS+12, 0)
				b.mem.Write32(pPS+16, uint32(r.Right-r.Left))
				b.mem.Write32(pPS+20, uint32(r.Bottom-r.Top))
			}
		}
		ctx.SetReturn(uint64(hdc))
		return 0
	})
	reg("NtUserEndPaint", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1)
		return 0
	})
}

package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	gdi "github.com/mirkobrombin/Raven/pkg/gdi"
	ravelog "github.com/mirkobrombin/Raven/pkg/log"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
	"github.com/mirkobrombin/Raven/pkg/win32"
	"github.com/mirkobrombin/Raven/pkg/wl"
	"golang.org/x/sys/unix"
)

func registerUser32Handlers(hctx *HandlerCtx) {
	allocScreenDC := hctx.AllocScreenDC
	bitmapHandles := hctx.BitmapHandles
	builtinWndProc := hctx.BuiltinWndProc
	clientAreaOrigin := hctx.ClientAreaOrigin
	commitIfDone := hctx.CommitIfDone
	d := hctx.Disp
	decodeDIBSlots := hctx.DecodeDIBSlots
	gdiAlloc := hctx.GdiAlloc
	gdiMgr := hctx.GdiMgr
	getDC := hctx.GetDCFn
	getSysColor := hctx.GetSysColor
	handles := hctx.Handles
	hwndAlloc := hctx.HwndAlloc
	hwndChildren := hctx.HwndChildren
	hwndExplicitlyHidden := hctx.HwndExplicitlyHidden
	hwndMenuBar := hctx.HwndMenuBar
	hwndTitle := hctx.HwndTitle
	hwndWndProc := hctx.HwndWndProc
	mainModule := hctx.MainModule
	mem := hctx.Mem
	menuStripAmpersand := hctx.MenuStripAmpersand
	menus := hctx.Menus
	ncDrawText := hctx.NcDrawText
	paintTree := hctx.PaintTree
	peLoadMenuResource := hctx.PeLoadMenuResource
	peLoadRawResource := hctx.PeLoadRawResource
	peLoadStringW := hctx.PeLoadStringW
	queuePaint := hctx.QueuePaint
	readGuestString := hctx.ReadGuestString
	readGuestUTF16 := hctx.ReadGuestUTF16
	readGuestUTF16N := hctx.ReadGuestUTF16N
	scratchAlloc := hctx.ScratchAlloc
	syncScreenSurface := hctx.SyncScreenSurface
	timerMap := hctx.TimerMap
	wideprintf := hctx.Wideprintf
	windowLongPtr := hctx.WindowLongPtr
	windowProps := hctx.WindowProps
	wlDisplay := hctx.WlDisplay
	wlWindow := hctx.WlWindow

	hwndDisabled := make(map[uint64]bool)
	hwndWindowRgn := make(map[uint64]uint64)

	// findMenuItem locates a menu item by position or command ID.
	findMenuItem := func(hMenu uint64, uID uint64, uFlags uint32) *menuItem {
		const mfByPosition = 0x0400
		m, ok := menus[hMenu]
		if !ok {
			return nil
		}
		if uFlags&mfByPosition != 0 {
			pos := int(uID)
			if pos >= 0 && pos < len(m.items) {
				return &m.items[pos]
			}
			return nil
		}
		for i := range m.items {
			if m.items[i].id == uID {
				return &m.items[i]
			}
		}
		return nil
	}

	getClientScrollbarSizes := func(hwnd uint64) (int32, int32) {
		wnd := win32.Global.Get(hwnd)
		if wnd == nil {
			return 0, 0
		}
		var vW, hH int32
		if wnd.Style&win32.WS_VSCROLL != 0 {
			vW = win32.GetSystemMetrics(win32.SM_CXVSCROLL)
		}
		if wnd.Style&win32.WS_HSCROLL != 0 {
			hH = win32.GetSystemMetrics(win32.SM_CYHSCROLL)
		}
		return vW, hH
	}
	getMenuClientTop := func(hwnd uint64) int32 {
		top := int32(0)
		if wlWindow != nil {
			top = wlWindow.TitleBarH
		}
		if _, hasMenu := hwndMenuBar[hwnd]; hasMenu {
			top += win32.GetSystemMetrics(win32.SM_CYMENU)
		}
		return top
	}
	getTopLevelClientSize := func(hwnd uint64) (int32, int32) {
		if wlWindow == nil {
			return 0, 0
		}
		w := wlWindow.Width
		h := wlWindow.Height
		if _, hasMenu := hwndMenuBar[hwnd]; hasMenu && h > win32.GetSystemMetrics(win32.SM_CYMENU) {
			h -= win32.GetSystemMetrics(win32.SM_CYMENU)
		}
		vW, hH := getClientScrollbarSizes(hwnd)
		if w > vW {
			w -= vW
		}
		if h > hH {
			h -= hH
		}
		if w < 0 {
			w = 0
		}
		if h < 0 {
			h = 0
		}
		return w, h
	}
	resolveMenuItems := func(item menuItem) []menuItem {
		subItems := item.submenu
		if len(subItems) == 0 && item.flags&0x0010 != 0 {
			if sub, ok := menus[item.id]; ok {
				subItems = sub.items
			}
		}
		return subItems
	}
	menuBarItemBounds := func(hwnd uint64, idx int) (menuItem, int32, int32, bool) {
		menuH, ok := hwndMenuBar[hwnd]
		if !ok {
			return menuItem{}, 0, 0, false
		}
		md, ok := menus[menuH]
		if !ok {
			return menuItem{}, 0, 0, false
		}
		x := int32(4)
		for i, item := range md.items {
			if item.flags&0x0800 != 0 || item.flags&0x0010 == 0 {
				continue
			}
			label, _ := menuTextParts(menuStripAmpersand(item.text))
			if label == "" || label == "-" || !menuHasRenderableText(label) {
				continue
			}
			tw := menuTextWidth(label) + 12
			if i == idx {
				return item, x, tw, true
			}
			x += tw
		}
		return menuItem{}, 0, 0, false
	}
	showPopupMenu := func(hMenu, owner uint64, x, y int32) {
		m, ok := menus[hMenu]
		if !ok || len(m.items) == 0 {
			hctx.ActivePopupMenu = nil
			return
		}
		boundW, boundH := int32(0), int32(0)
		if wlWindow != nil {
			boundW = wlWindow.Width
			boundH = wlWindow.Height + wlWindow.TitleBarH
		}
		layout := menuPopupLayout(m.items, x, y, boundW, boundH, menuStripAmpersand)
		layout.Menu = hMenu
		layout.OwnerHWND = owner
		hctx.ActivePopupMenu = &layout
	}
	showMenuBarPopup := func(hwnd uint64, idx int) {
		item, x, _, ok := menuBarItemBounds(hwnd, idx)
		if !ok || wlWindow == nil {
			hctx.ActivePopupMenu = nil
			return
		}
		subItems := resolveMenuItems(item)
		if len(subItems) == 0 {
			hctx.ActivePopupMenu = nil
			return
		}
		layout := menuPopupLayout(subItems, x, wlWindow.TitleBarH+win32.GetSystemMetrics(win32.SM_CYMENU), wlWindow.Width, wlWindow.Height+wlWindow.TitleBarH, menuStripAmpersand)
		layout.Menu = item.id
		layout.OwnerHWND = hwnd
		hctx.ActivePopupMenu = &layout
	}
	closePopupMenus := func() {
		hctx.ActivePopupMenu = nil
		hctx.OpenMenuIdx = -1
		hctx.OpenMenuHwnd = 0
	}
	requestWindowRepaint := func(hwnd uint64) {
		if hwnd == 0 {
			hwnd = hctx.MainHWND
		}
		if hwnd == hctx.MainHWND && wlWindow != nil && hctx.HasBaseFrame {
			hctx.RepaintBuiltin = true
			hctx.FrameReady = true
			commitIfDone()
			return
		}
		queuePaint(hwnd)
	}
	drawAbsHLine := func(x0, x1, y int32, color uint32) {
		if wlWindow == nil || x1 <= x0 {
			return
		}
		wlWindow.DrawRectAbs(x0, y, x1, y+1, color)
	}
	drawAbsVLine := func(x, y0, y1 int32, color uint32) {
		if wlWindow == nil || y1 <= y0 {
			return
		}
		wlWindow.DrawRectAbs(x, y0, x+1, y1, color)
	}
	drawPopupArrow := func(x, y int32, vertical bool, dir int32, color uint32) {
		if wlWindow == nil {
			return
		}
		if vertical {
			for row := int32(0); row < 5; row++ {
				width := row*2 + 1
				if dir > 0 {
					drawAbsHLine(x-width/2, x-width/2+width, y+row, color)
				} else {
					drawAbsHLine(x-width/2, x-width/2+width, y+4-row, color)
				}
			}
			return
		}
		for col := int32(0); col < 5; col++ {
			height := col*2 + 1
			if dir > 0 {
				drawAbsVLine(x+col, y-height/2, y-height/2+height, color)
			} else {
				drawAbsVLine(x+4-col, y-height/2, y-height/2+height, color)
			}
		}
	}
	drawScrollBar := func(rect win32.Rect, vertical bool, si win32.ScrollInfo) {
		if wlWindow == nil {
			return
		}
		btnSize := win32.GetSystemMetrics(win32.SM_CXVSCROLL)
		if !vertical {
			btnSize = win32.GetSystemMetrics(win32.SM_CYHSCROLL)
		}
		bg := uint32(0xF0F0F0)
		border := uint32(0xA0A0A0)
		thumb := uint32(0xCDCDCD)
		wlWindow.DrawRectAbs(rect.Left, rect.Top, rect.Right, rect.Bottom, bg)
		drawAbsHLine(rect.Left, rect.Right, rect.Top, border)
		drawAbsHLine(rect.Left, rect.Right, rect.Bottom-1, border)
		drawAbsVLine(rect.Left, rect.Top, rect.Bottom, border)
		drawAbsVLine(rect.Right-1, rect.Top, rect.Bottom, border)
		if vertical {
			wlWindow.DrawRectAbs(rect.Left+1, rect.Top+1, rect.Right-1, rect.Top+btnSize, bg)
			wlWindow.DrawRectAbs(rect.Left+1, rect.Bottom-btnSize, rect.Right-1, rect.Bottom-1, bg)
			drawPopupArrow(rect.Left+(rect.Right-rect.Left)/2, rect.Top+6, true, -1, 0x404040)
			drawPopupArrow(rect.Left+(rect.Right-rect.Left)/2, rect.Bottom-btnSize+6, true, 1, 0x404040)
			trackTop := rect.Top + btnSize
			trackBottom := rect.Bottom - btnSize
			if trackBottom > trackTop {
				wlWindow.DrawRectAbs(rect.Left+1, trackTop, rect.Right-1, trackBottom, bg)
				trackH := trackBottom - trackTop
				thumbH := int32(24)
				rangeSpan := si.Max - si.Min + 1
				if rangeSpan < 1 {
					rangeSpan = 1
				}
				if si.Page > 0 {
					thumbH = int32(si.Page) * trackH / rangeSpan
					if thumbH < 20 {
						thumbH = 20
					}
					if thumbH > trackH {
						thumbH = trackH
					}
				}
				thumbTop := trackTop
				movable := trackH - thumbH
				denom := si.Max - si.Min - int32(si.Page) + 1
				if denom < 1 {
					denom = si.Max - si.Min
				}
				if denom > 0 && movable > 0 {
					thumbTop += (si.Pos - si.Min) * movable / denom
				}
				wlWindow.DrawRectAbs(rect.Left+2, thumbTop, rect.Right-2, thumbTop+thumbH, thumb)
				drawAbsHLine(rect.Left+2, rect.Right-2, thumbTop, border)
				drawAbsHLine(rect.Left+2, rect.Right-2, thumbTop+thumbH-1, border)
				drawAbsVLine(rect.Left+2, thumbTop, thumbTop+thumbH, border)
				drawAbsVLine(rect.Right-3, thumbTop, thumbTop+thumbH, border)
			}
		} else {
			wlWindow.DrawRectAbs(rect.Left+1, rect.Top+1, rect.Left+btnSize, rect.Bottom-1, bg)
			wlWindow.DrawRectAbs(rect.Right-btnSize, rect.Top+1, rect.Right-1, rect.Bottom-1, bg)
			drawPopupArrow(rect.Left+6, rect.Top+(rect.Bottom-rect.Top)/2, false, -1, 0x404040)
			drawPopupArrow(rect.Right-btnSize+6, rect.Top+(rect.Bottom-rect.Top)/2, false, 1, 0x404040)
			trackLeft := rect.Left + btnSize
			trackRight := rect.Right - btnSize
			if trackRight > trackLeft {
				wlWindow.DrawRectAbs(trackLeft, rect.Top+1, trackRight, rect.Bottom-1, bg)
				trackW := trackRight - trackLeft
				thumbW := int32(24)
				rangeSpan := si.Max - si.Min + 1
				if rangeSpan < 1 {
					rangeSpan = 1
				}
				if si.Page > 0 {
					thumbW = int32(si.Page) * trackW / rangeSpan
					if thumbW < 20 {
						thumbW = 20
					}
					if thumbW > trackW {
						thumbW = trackW
					}
				}
				thumbLeft := trackLeft
				movable := trackW - thumbW
				denom := si.Max - si.Min - int32(si.Page) + 1
				if denom < 1 {
					denom = si.Max - si.Min
				}
				if denom > 0 && movable > 0 {
					thumbLeft += (si.Pos - si.Min) * movable / denom
				}
				wlWindow.DrawRectAbs(thumbLeft, rect.Top+2, thumbLeft+thumbW, rect.Bottom-2, thumb)
				drawAbsHLine(thumbLeft, thumbLeft+thumbW, rect.Top+2, border)
				drawAbsHLine(thumbLeft, thumbLeft+thumbW, rect.Bottom-3, border)
				drawAbsVLine(thumbLeft, rect.Top+2, rect.Bottom-2, border)
				drawAbsVLine(thumbLeft+thumbW-1, rect.Top+2, rect.Bottom-2, border)
			}
		}
	}

	user32, ok := hctx.SynthByName["user32.dll"]
	if !ok {
		return
	}
	_ = user32

	// LoadStringW: load string resource from PE
	d.RegisterAutoStubHandler(user32, "LoadStringW", func(ctx *ntapi.TrapContext) uint32 {
		uID := uint32(ctx.Arg(1))
		lpBuffer := ctx.Arg(2)
		cchBufferMax := int(int32(ctx.Arg(3)))
		s, guestAddr, slen := peLoadStringW(uID)
		if s != "" {
			ravelog.Logf("[loadstr] id=%d → %q\n", uID, s)
		}
		if s == "" || lpBuffer == 0 {
			ctx.SetReturn(0)
			return 0
		}
		// When cchBufferMax == 0, return a read-only pointer to the resource string
		if cchBufferMax == 0 {
			mem.Write64(lpBuffer, guestAddr)
			ctx.SetReturn(uint64(slen))
			return 0
		}
		runes := []rune(s)
		n := len(runes)
		if n >= cchBufferMax {
			n = cchBufferMax - 1
		}
		for i := 0; i < n; i++ {
			mem.Write16(lpBuffer+uint64(i)*2, uint16(runes[i]))
		}
		mem.Write16(lpBuffer+uint64(n)*2, 0)
		ctx.SetReturn(uint64(n))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "IsDialogMessageW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // FALSE - not a dialog message
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetWindowTextLengthW", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		if cs, ok := hwndChildren[hwnd]; ok && cs.text != "" {
			ctx.SetReturn(uint64(len([]rune(cs.text))))
		} else if hwnd == hctx.MainHWND && hctx.MainTitle != "" {
			ctx.SetReturn(uint64(len([]rune(hctx.MainTitle))))
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "MonitorFromRect", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0xD0000001) // fake monitor handle
		return 0
	})
	d.RegisterAutoStubHandler(user32, "LoadAcceleratorsW", func(ctx *ntapi.TrapContext) uint32 {
		// hInstance := ctx.Arg(0)
		lpTableName := ctx.Arg(1)
		var resID uint16
		if lpTableName < 0x10000 {
			resID = uint16(lpTableName)
		} else {
			name := readGuestUTF16(lpTableName)
			if n, err := strconv.Atoi(name); err == nil {
				resID = uint16(n)
			}
		}
		_ = resID
		// Return a real handle - accelerator tables are only used
		// by TranslateAccelerator which we stub
		h := handles.Alloc(&ntapi.GenericHandle{Kind: "accel"})
		ctx.SetReturn(uint64(h))
		return 0
	})
	// wsprintfW(lpOut, lpFmt, ...) - varargs format, returns char count
	d.RegisterAutoStubHandler(user32, "wsprintfW", func(ctx *ntapi.TrapContext) uint32 {
		lpOut := ctx.Arg(0)
		lpFmt := ctx.Arg(1)
		fmtStr := readGuestUTF16(lpFmt)
		var args []uint64
		for i := 2; i < 10; i++ {
			args = append(args, ctx.Arg(i))
		}
		result := wideprintf(fmtStr, args)
		for i, r := range result {
			mem.Write16(lpOut+uint64(i)*2, uint16(r))
		}
		mem.Write16(lpOut+uint64(len([]rune(result)))*2, 0)
		ctx.SetReturn(uint64(len([]rune(result))))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "wsprintfA", func(ctx *ntapi.TrapContext) uint32 {
		lpOut := ctx.Arg(0)
		lpFmt := ctx.Arg(1)
		fmtStr := readGuestString(lpFmt)
		var args []uint64
		for i := 2; i < 10; i++ {
			args = append(args, ctx.Arg(i))
		}
		result := wideprintf(fmtStr, args)
		for i := range result {
			mem.Write8(lpOut+uint64(i), result[i])
		}
		mem.Write8(lpOut+uint64(len(result)), 0)
		ctx.SetReturn(uint64(len(result)))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "RegisterClassW", func(ctx *ntapi.TrapContext) uint32 {
		// WNDCLASSW layout (x64): style(4)+pad(4), lpfnWndProc(8), cbClsExtra(4)+cbWndExtra(4),
		//   hInstance(8), hIcon(8), hCursor(8), hbrBackground(8), lpszMenuName(8), lpszClassName(8)
		pClass := ctx.Arg(0)
		a := hctx.NextAtom
		hctx.NextAtom++
		if pClass != 0 {
			style, _ := mem.Read32(pClass)
			wndProc, _ := mem.Read64(pClass + 8)
			cbClsExtra, _ := mem.Read32(pClass + 16)
			cbWndExtra, _ := mem.Read32(pClass + 20)
			hInst, _ := mem.Read64(pClass + 24)
			hIcon, _ := mem.Read64(pClass + 32)
			hCursor, _ := mem.Read64(pClass + 40)
			hBrush, _ := mem.Read64(pClass + 48)
			lpMenuName, _ := mem.Read64(pClass + 56)
			lpName, _ := mem.Read64(pClass + 64)
			hctx.AtomWndProc[a] = wndProc
			if hBrush > 0 && hBrush <= 30 {
				hctx.ClassBrush[a] = uint32(hBrush)
			}
			name := readGuestUTF16(lpName)
			if name != "" {
				hctx.ClassNameAtom[name] = a
			}
			hctx.ClassInfo[a] = &registeredClassInfo{
				Style: style, WndProc: wndProc,
				ClsExtra: int32(cbClsExtra), WndExtra: int32(cbWndExtra),
				HInstance: hInst, HIcon: hIcon, HCursor: hCursor,
				HbrBG: hBrush, MenuName: lpMenuName, ClassName: name,
				Atom: a,
			}
			if lpMenuName != 0 && mainModule != nil {
				var menuID uint32
				if lpMenuName < 0x10000 {
					menuID = uint32(lpMenuName)
				} else {
					menuName := readGuestUTF16(lpMenuName)
					if id, err := strconv.ParseUint(menuName, 10, 32); err == nil {
						menuID = uint32(id)
					}
				}
				if menuID != 0 {
					if md := peLoadMenuResource(menuID); md != nil {
						h := gdiAlloc()
						menus[h] = md
						hctx.ClassMenuHandle[a] = h
					}
				}
			}
			ravelog.Logf("[wndclass] RegisterClassW %q atom=0x%x wndProc=0x%x brush=%d\n", name, a, wndProc, hBrush)
		}
		ctx.SetReturn(uint64(a))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "RegisterClassExW", func(ctx *ntapi.TrapContext) uint32 {
		// WNDCLASSEXW layout (x64): cbSize(4)+style(4), lpfnWndProc(8), cbClsExtra(4)+cbWndExtra(4),
		//   hInstance(8), hIcon(8), hCursor(8), hbrBackground(8), lpszMenuName(8), lpszClassName(8), hIconSm(8)
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
			if hBrush > 0 && hBrush <= 30 {
				hctx.ClassBrush[a] = uint32(hBrush)
			}
			var name string
			if lpName != 0 && lpName < 0x10000 {
				name = fmt.Sprintf("atom:0x%x", lpName)
			} else {
				name = readGuestUTF16(lpName)
			}
			if name != "" {
				hctx.ClassNameAtom[name] = a
			}
			hctx.ClassInfo[a] = &registeredClassInfo{
				Style: style, WndProc: wndProc,
				ClsExtra: int32(cbClsExtra), WndExtra: int32(cbWndExtra),
				HInstance: hInst, HIcon: hIcon, HCursor: hCursor,
				HbrBG: hBrush, MenuName: lpszMenuName, ClassName: name,
				HIconSm: hIconSm, Atom: a,
			}
			if lpszMenuName != 0 && mainModule != nil {
				var menuID uint32
				if lpszMenuName < 0x10000 {
					menuID = uint32(lpszMenuName)
				} else {
					menuName := readGuestUTF16(lpszMenuName)
					if id, err := strconv.ParseUint(menuName, 10, 32); err == nil {
						menuID = uint32(id)
					}
				}
				if menuID != 0 {
					if md := peLoadMenuResource(menuID); md != nil {
						h := gdiAlloc()
						menus[h] = md
						hctx.ClassMenuHandle[a] = h
					}
				}
			}
			ravelog.Logf("[wndclass] RegisterClassExW name=%q lpName=0x%x atom=0x%x wndProc=0x%x brush=%d\n", name, lpName, a, wndProc, hBrush)
		}
		ctx.SetReturn(uint64(a))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "RegisterWindowMessageW", func(ctx *ntapi.TrapContext) uint32 {
		id := hctx.NextMsgID
		hctx.NextMsgID++
		ctx.SetReturn(uint64(id))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CreateWindowExW", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := hwndAlloc()
		lpClassName := ctx.Arg(1)
		style := uint32(ctx.Arg(3))

		// Associate HWND with WndProc via class name or atom
		var className string
		var classAtomForHwnd uint16
		if lpClassName != 0 && lpClassName < 0x10000 {
			// Integer atom
			classAtomForHwnd = uint16(lpClassName)
			if wp, ok := hctx.AtomWndProc[classAtomForHwnd]; ok {
				hwndWndProc[hwnd] = wp
			}
			className = fmt.Sprintf("atom:0x%x", lpClassName)
		} else if lpClassName != 0 {
			className = readGuestUTF16(lpClassName)
			if a, ok := hctx.ClassNameAtom[className]; ok {
				classAtomForHwnd = a
				if wp, ok2 := hctx.AtomWndProc[a]; ok2 {
					hwndWndProc[hwnd] = wp
				}
			}
		}
		if classAtomForHwnd != 0 {
			hctx.HwndClassAtom[hwnd] = classAtomForHwnd
		}
		wp := hwndWndProc[hwnd]
		parentHwndLog := ctx.Arg(8)
		ravelog.Logf("[wndclass] CreateWindowExW class=%q hwnd=0x%x parent=0x%x wndProc=0x%x style=0x%x\n", className, hwnd, parentHwndLog, wp, style)

		const wsChild = 0x40000000
		// Track child windows (built-in classes like Edit, Static, Button)
		if style&wsChild != 0 {
			cx := int32(ctx.Arg(4))
			cy := int32(ctx.Arg(5))
			cw := int32(ctx.Arg(6))
			ch := int32(ctx.Arg(7))
			parentHwnd := ctx.Arg(8) // hWndParent
			if cx < 0 || cx > 0x7FFF {
				cx = 0
			}
			if cy < 0 || cy > 0x7FFF {
				cy = 0
			}
			var defW, defH int32 = 800, 600
			if wlWindow != nil {
				defW, defH = wlWindow.Width, wlWindow.Height
			}
			// Child windows with invalid/zero dimensions start at 0×0.
			// They will be sized by the parent's WM_SIZE/MoveWindow calls.
			if cw < 0 || cw > 0x7FFF {
				cw = 0
			}
			if ch < 0 || ch > 0x7FFF {
				ch = 0
			}
			lClassName := strings.ToLower(className)
			// Statusbar: auto-position at bottom of parent (absolute)
			if lClassName == "msctls_statusbar32" {
				const sbHeight int32 = 20
				cx, cy = 0, defH-sbHeight
				cw, ch = defW, sbHeight
			} else {
				// Convert from parent-relative to absolute coordinates
				ox, oy := clientAreaOrigin(parentHwnd)
				cx += ox
				cy += oy
			}
			windowName := readGuestUTF16(ctx.Arg(2))
			dwExStyle := uint32(ctx.Arg(0))
			hMenu := ctx.Arg(9) // for child windows, this is the control ID
			hwndChildren[hwnd] = &controlState{
				className:  lClassName,
				parentHWND: parentHwnd,
				ctrlID:     hMenu,
				x:          cx, y: cy, w: cw, h: ch,
				style:   style,
				exStyle: dwExStyle,
				text:    windowName,
				visible: style&0x10000000 != 0, // WS_VISIBLE
			}
			initBuiltinControlState(hwndChildren[hwnd])
			// Initialise GWL_STYLE / GWL_EXSTYLE so GetWindowLong returns correct values.
			windowLongPtr[hwnd] = map[int32]uint64{-16: uint64(style), -20: uint64(dwExStyle)}
			win32.Global.Create(hwnd, lClassName, cx, cy, cw, ch, style, dwExStyle, parentHwnd)
			// Auto-focus first edit control
			if lClassName == "edit" && hctx.FocusHwnd == 0 {
				hctx.FocusHwnd = hwnd
			}
		}

		// Create a real Wayland window for the first top-level window
		if wlDisplay != nil && wlWindow == nil {
			if style&wsChild == 0 {
				title := readGuestUTF16(ctx.Arg(2))
				if title == "" {
					title = "govm"
				}
				var w, h int32 = 800, 600
				if nw := int32(ctx.Arg(6)); nw > 0 && nw < 0x7FFF {
					w = nw
				}
				if nh := int32(ctx.Arg(7)); nh > 0 && nh < 0x7FFF {
					h = nh
				}
				const wsCaption = 0x00C00000
				// Compute NC top height from window style (ported from ReactOS NCCALCSIZE).
				// This replaces the hardcoded titleBarH=30 that was the old fake CSD.
				ncTop := int32(0)
				if wlDisplay.HasNoSSD() {
					// Compute NC top (borders + caption only, NO menu bar).
					// Menu bar sits between TitleBarH and the client area via menuBarHeight.
					var r win32.Rect
					exStyle := uint32(ctx.Arg(0))
					win32.AdjustWindowRectEx(&r, style, false, exStyle)
					ncTop = -r.Top
					if ncTop < 0 {
						ncTop = 0
					}
				}
				if win, err := wlDisplay.CreateWindow(title, w, h, ncTop); err == nil {
					wlWindow = win
					hctx.WlWindow = win
					if hctx.OnWlWindowSet != nil {
						hctx.OnWlWindowSet(win)
					}
					hctx.MainHWND = hwnd
					hctx.MainTitle = title
					// Initialise GWL_STYLE / GWL_EXSTYLE for the main window.
					exStyle := uint32(ctx.Arg(0))
					windowLongPtr[hwnd] = map[int32]uint64{-16: uint64(style), -20: uint64(exStyle)}
					// Register the main window in win32.Global so NC paint and other lookups work.
					win32.Global.Create(hwnd, strings.ToLower(readGuestUTF16(lpClassName)), 0, 0, w, h+ncTop, style, exStyle, 0)
					ravelog.Logf("[wl] window created: %q %dx%d hwnd=0x%x ncTop=%d\n", title, w, h, hwnd, ncTop)
					// Attach menu bar: first check hMenu parameter, then class menu
					hMenu := ctx.Arg(9)
					ravelog.Logf("[menu] CreateWindowExW hMenu=0x%x menus_has=%v\n", hMenu, menus[hMenu] != nil)
					if hMenu != 0 {
						if _, ok := menus[hMenu]; ok {
							hwndMenuBar[hwnd] = hMenu
						}
					}
					if _, hasMenu := hwndMenuBar[hwnd]; !hasMenu && lpClassName != 0 {
						var classAtom uint16
						if lpClassName < 0x10000 {
							classAtom = uint16(lpClassName)
						} else {
							cn := readGuestUTF16(lpClassName)
							classAtom = hctx.ClassNameAtom[cn]
						}
						if mh, ok := hctx.ClassMenuHandle[classAtom]; ok {
							hwndMenuBar[hwnd] = mh
							ravelog.Logf("[menu] attached class menu hmenu=0x%x to hwnd=0x%x\n", mh, hwnd)
						}
					}
				} else {
					ravelog.Logf("[wl] CreateWindow failed: %v\n", err)
				}
			}
		}
		// Dispatch WM_NCCREATE + WM_CREATE synchronously for windows with a WndProc
		if wp, hasWP := hwndWndProc[hwnd]; hasWP && wp != 0 {
			// Build CREATESTRUCT in guest memory (80 bytes, x64 layout):
			//   0: lpCreateParams(8) 8: hInstance(8) 16: hMenu(8) 24: hwndParent(8)
			//  32: cy(4) 36: cx(4) 40: y(4) 44: x(4)
			//  48: style(4) 52: pad(4) 56: lpszName(8) 64: lpszClass(8) 72: dwExStyle(4)
			cs := scratchAlloc(80)
			mem.Write64(cs+0, ctx.Arg(11))         // lpCreateParams
			mem.Write64(cs+8, ctx.Arg(10))         // hInstance
			mem.Write64(cs+16, ctx.Arg(9))         // hMenu
			mem.Write64(cs+24, ctx.Arg(8))         // hwndParent
			mem.Write32(cs+32, uint32(ctx.Arg(7))) // cy (nHeight)
			mem.Write32(cs+36, uint32(ctx.Arg(6))) // cx (nWidth)
			mem.Write32(cs+40, uint32(ctx.Arg(5))) // y
			mem.Write32(cs+44, uint32(ctx.Arg(4))) // x
			mem.Write32(cs+48, style)              // style
			mem.Write32(cs+52, 0)                  // padding
			mem.Write64(cs+56, ctx.Arg(2))         // lpszName
			mem.Write64(cs+64, ctx.Arg(1))         // lpszClass
			mem.Write32(cs+72, uint32(ctx.Arg(0))) // dwExStyle

			// Synchronous dispatch via trampoline:
			// Queue WM_CREATE (dispatched second), then set up WM_NCCREATE (dispatched first).
			rw, ok := ctx.CPU.(ntapi.RegisterWriter)
			rr, ok2 := ctx.CPU.(ntapi.RegisterReader)
			if ok && ok2 {
				// Save original return address and push a new sync frame
				rsp := rr.ReadReg(4) // RSP
				retAddr, _ := mem.Read64(rsp)
				hctx.SyncStack = append(hctx.SyncStack, syncDispatchFrame{
					queue:   []syncDispatch{{wndProc: wp, hwnd: hwnd, msg: 0x0001, wParam: 0, lParam: cs}},
					retAddr: retAddr,
					hwnd:    hwnd,
				})
				mem.Write64(rsp, hctx.SyncTrampoline) // WndProc RET → trampoline

				// Set up WM_NCCREATE call
				rw.WriteReg(1, hwnd)   // RCX = hwnd
				rw.WriteReg(2, 0x0081) // RDX = WM_NCCREATE
				rw.WriteReg(8, 0)      // R8 = wParam
				rw.WriteReg(9, cs)     // R9 = lParam (CREATESTRUCT)

				ctx.CPU.SetPC(wp)
				ctx.ReturnOverridden = true
				return 0
			}
			// Fallback: queue messages if register access unavailable
			hctx.MsgQueue = append(hctx.MsgQueue,
				queuedMsg{hwnd, 0x0081, 0, cs}, // WM_NCCREATE
				queuedMsg{hwnd, 0x0001, 0, cs}, // WM_CREATE
			)
		}

		ctx.SetReturn(hwnd)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "DestroyWindow", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		ravelog.Logf("[destroy] hwnd=0x%x\n", hwnd)
		delete(hwndChildren, hwnd)
		delete(hwndWndProc, hwnd)
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(user32, "ShowWindow", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		nCmdShow := ctx.Arg(1)
		ravelog.Logf("[show] ShowWindow hwnd=0x%x nCmdShow=%d\n", hwnd, nCmdShow)
		if hwnd == hctx.MainHWND && wlWindow != nil {
			// ReactOS co_WinPosSendSizeMove: WM_SIZE lParam = MAKELONG(clientW, clientH).
			cw, ch := getTopLevelClientSize(hwnd)
			sw := uint64(cw)
			sh := uint64(ch)
			hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{hwnd, 0x0005, 0, (sh << 16) | sw}) // WM_SIZE
			// WM_ACTIVATE(WA_ACTIVE=1): NPP's WndProc calls SetFocus(scintilla) here.
			hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{hwnd, 0x0006, 1, 0}) // WM_ACTIVATE
			queuePaint(hwnd)                                                     // WM_PAINT
			// Win32: ShowWindow on a parent cascades visibility only to children that
			// were created with WS_VISIBLE (0x10000000). Windows created without
			// WS_VISIBLE are intentionally hidden and must be shown explicitly.
			const wsVisible = uint32(0x10000000)
			if nCmdShow != 0 {
				for h, cs := range hwndChildren {
					if !cs.visible && !hwndExplicitlyHidden[h] && cs.style&wsVisible != 0 {
						cs.visible = true
						if wp, ok2 := hwndWndProc[h]; ok2 && wp != 0 {
							queuePaint(h)
						}
					}
					requestWindowRepaint(hwnd)
				}
			}
		}
		if cs, ok := hwndChildren[hwnd]; ok {
			wasVisible := cs.visible
			cs.visible = nCmdShow != 0 // SW_HIDE = 0
			if nCmdShow == 0 {
				// Only mark explicitly hidden if the window was actually visible.
				// SW_HIDE on a never-shown window is a no-op for cascade/auto-show
				// purposes: a subsequent MoveWindow should still be able to auto-show it.
				if wasVisible {
					hwndExplicitlyHidden[hwnd] = true
				}
			} else {
				delete(hwndExplicitlyHidden, hwnd)
			}
			// Queue WM_PAINT when a window with a guest WndProc becomes visible
			if cs.visible && !wasVisible {
				if wp, ok2 := hwndWndProc[hwnd]; ok2 && wp != 0 {
					queuePaint(hwnd)
				}
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "UpdateWindow", func(ctx *ntapi.TrapContext) uint32 {
		// Trigger immediate paint for main window
		hwnd := ctx.Arg(0)
		if hwnd == hctx.MainHWND && wlWindow != nil {
			queuePaint(hwnd)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "IsChild", func(ctx *ntapi.TrapContext) uint32 {
		parent := ctx.Arg(0)
		child := ctx.Arg(1)
		if cs, ok := hwndChildren[child]; ok && cs.parentHWND == parent {
			ctx.SetReturn(1) // TRUE
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "FindWindowW", func(ctx *ntapi.TrapContext) uint32 {
		// FindWindowW(lpClassName, lpWindowName) - search all known HWNDs
		wantClass := strings.ToLower(readGuestUTF16(ctx.Arg(0)))
		wantTitle := readGuestUTF16(ctx.Arg(1))
		for h, cs := range hwndChildren {
			if wantClass != "" && strings.ToLower(cs.className) != wantClass {
				continue
			}
			if wantTitle != "" {
				title := cs.text
				if t, ok := hwndTitle[h]; ok {
					title = t
				}
				if title != wantTitle {
					continue
				}
			}
			ctx.SetReturn(h)
			return 0
		}
		// Check main window
		if wantClass == "" || wantClass == "notepad++" {
			if wantTitle == "" || hwndTitle[hctx.MainHWND] == wantTitle {
				ctx.SetReturn(hctx.MainHWND)
				return 0
			}
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "FindWindowExW", func(ctx *ntapi.TrapContext) uint32 {
		// FindWindowExW(hwndParent, hwndChildAfter, lpClassName, lpWindowName)
		parent := ctx.Arg(0)
		childAfter := ctx.Arg(1)
		wantClass := strings.ToLower(readGuestUTF16(ctx.Arg(2)))
		wantTitle := readGuestUTF16(ctx.Arg(3))
		found := childAfter == 0 // if childAfter==0, match first; else skip until we see childAfter
		for h, cs := range hwndChildren {
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
				if t, ok := hwndTitle[h]; ok {
					title = t
				}
				if title != wantTitle {
					continue
				}
			}
			ctx.SetReturn(h)
			return 0
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "FindWindowExA", func(ctx *ntapi.TrapContext) uint32 {
		parent := ctx.Arg(0)
		childAfter := ctx.Arg(1)
		wantClass := strings.ToLower(readGuestString(ctx.Arg(2)))
		wantTitle := readGuestString(ctx.Arg(3))
		found := childAfter == 0
		for h, cs := range hwndChildren {
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
				if t, ok := hwndTitle[h]; ok {
					title = t
				}
				if title != wantTitle {
					continue
				}
			}
			ctx.SetReturn(h)
			return 0
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetDC", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		ox, oy := clientAreaOrigin(hwnd)
		h, dc := allocScreenDC(ox, oy)
		if cs, ok := hwndChildren[hwnd]; ok {
			dc.SetClipRect(cs.x, cs.y, cs.x+cs.w, cs.y+cs.h)
		}
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "ReleaseDC", func(ctx *ntapi.TrapContext) uint32 {
		gdiMgr.DeleteDC(ctx.Arg(1))
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetSystemMetrics", func(ctx *ntapi.TrapContext) uint32 {
		idx := int(ctx.Arg(0))
		// Keep SM_CXSCREEN / SM_CYSCREEN in sync with actual Wayland window size.
		if wlWindow != nil {
			win32.ScreenWidth = int32(wlWindow.Width)
			win32.ScreenHeight = int32(wlWindow.Height)
		}
		ctx.SetReturn(uint64(win32.GetSystemMetrics(idx)))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetSysColor", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(getSysColor(uint32(ctx.Arg(0)))))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "LoadCursorW", func(ctx *ntapi.TrapContext) uint32 {
		// Return IDC_ value as handle so SetCursor can map it back.
		// IDC_ARROW=32512, IDC_IBEAM=32513, etc.
		lpCursorName := ctx.Arg(1)
		if lpCursorName < 0x10000 && lpCursorName != 0 {
			ctx.SetReturn(lpCursorName) // atom → return as-is
		} else {
			ctx.SetReturn(0x00010001) // default dummy
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "LoadIconW", func(ctx *ntapi.TrapContext) uint32 {
		hInst := ctx.Arg(0)
		nameArg := ctx.Arg(1)
		if hInst == 0 && nameArg >= 32512 && nameArg <= 32522 {
			ctx.SetReturn(0x00020000 + nameArg) // system icon
			return 0
		}
		if nameArg < 0x10000 && mainModule != nil && (hInst == mainModule.BaseAddr || hInst == 0) {
			_, _, ok := peLoadRawResource(mainModule.BaseAddr, mainModule.ResourceDirRVA, 14, uint32(nameArg))
			if ok {
				ctx.SetReturn(0x00020000 + nameArg)
				return 0
			}
		}
		ctx.SetReturn(0x00020001) // dummy icon handle
		return 0
	})
	d.RegisterAutoStubHandler(user32, "LoadImageW", func(ctx *ntapi.TrapContext) uint32 {
		hInst := ctx.Arg(0)
		nameArg := ctx.Arg(1)
		imgType := ctx.Arg(2)
		// IMAGE_BITMAP=0: try to load from PE resource
		if imgType == 0 && nameArg < 0x10000 && mainModule != nil &&
			(hInst == mainModule.BaseAddr || hInst == 0) {
			resID := uint32(nameArg)
			addr, sz, ok2 := peLoadRawResource(mainModule.BaseAddr, mainModule.ResourceDirRVA, 2 /*RT_BITMAP*/, resID)
			if ok2 {
				slots := decodeDIBSlots(addr, sz, 0, 0)
				h := hctx.NextBitmapHandle
				hctx.NextBitmapHandle += 2
				bd := &bitmapHandleData{slots: slots}
				if len(slots) > 0 {
					bd.w = len(slots[0])
				}
				bitmapHandles[h] = bd
				ravelog.Logf("[loadimage] LoadImageW IMAGE_BITMAP resID=0x%x → handle=0x%x slots=%d\n", resID, h, len(slots))
				ctx.SetReturn(h)
				return 0
			}
		}
		ctx.SetReturn(0x00030001) // fallback dummy handle
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetWindowPos", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		// Handle main (top-level) window resize - updates the Wayland window
		if hwnd == hctx.MainHWND && wlWindow != nil {
			flags := uint32(ctx.Arg(6))
			const swpNoSize = 0x0001
			const swpNoMove = 0x0002
			prevW, prevH := wlWindow.Width, wlWindow.Height
			mainX, mainY := int32(0), int32(0)
			if flags&swpNoSize == 0 {
				w := int32(ctx.Arg(4))
				h := int32(ctx.Arg(5))
				if w > 0 && w < 0x7FFF && h > 0 && h < 0x7FFF {
					if wlWindow.Resize(w, h) {
						syncScreenSurface()
						ravelog.Logf("[setpos] hctx.MainHWND resize → %dx%d\n", w, h)
					}
					// ReactOS: WM_SIZE lParam = MAKELONG(clientW, clientH).
					clientW, clientH := getTopLevelClientSize(hwnd)
					lParam := uint64(uint16(clientW)) | (uint64(uint16(clientH)) << 16)
					hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{hwnd, 0x0005, 0, lParam})
					queuePaint(hwnd)
				}
			}
			if flags&swpNoMove == 0 {
				// Wayland top-level position is compositor-managed; track for GetWindowRect
				mainX = int32(ctx.Arg(2))
				mainY = int32(ctx.Arg(3))
				if mainX < 0 || mainX >= 0x7FFF {
					mainX = 0
				}
				if mainY < 0 || mainY >= 0x7FFF {
					mainY = 0
				}
			}
			// Keep win32.Global in sync for GetWindowRect/GetClientRect
			if wnd := win32.Global.Get(hwnd); wnd != nil {
				win32.Global.UpdatePos(wnd, mainX, mainY, wlWindow.Width, wlWindow.Height+wlWindow.TitleBarH)
			}
			if wlWindow.Width != prevW || wlWindow.Height != prevH {
				hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{hwnd, 0x0003, uint64(uint16(mainX)) | (uint64(uint16(mainY)) << 16), 0})
			}
			ctx.SetReturn(1)
			return 0
		}
		if ci, ok := hwndChildren[hwnd]; ok {
			flags := uint32(ctx.Arg(6))
			const swpNoMove = 0x0002
			const swpNoSize = 0x0001
			const swpShowWindow = 0x0040
			const swpHideWindow = 0x0080
			ox, oy := clientAreaOrigin(ci.parentHWND)
			prevX, prevY := ci.x, ci.y
			prevW, prevH := ci.w, ci.h
			if flags&swpNoMove == 0 {
				x := int32(ctx.Arg(2))
				y := int32(ctx.Arg(3))
				if x >= 0 && x < 0x7FFF {
					ci.x = x + ox
				}
				if y >= 0 && y < 0x7FFF {
					ci.y = y + oy
				}
			}
			if flags&swpNoSize == 0 {
				w := int32(ctx.Arg(4))
				h := int32(ctx.Arg(5))
				if w > 0 && w < 0x7FFF {
					ci.w = w
				}
				if h > 0 && h < 0x7FFF {
					ci.h = h
				}
			}
			if flags&swpShowWindow != 0 {
				ci.visible = true
				delete(hwndExplicitlyHidden, hwnd)
			}
			if flags&swpHideWindow != 0 {
				ci.visible = false
				hwndExplicitlyHidden[hwnd] = true
			}
			// Auto-show only when the size was explicitly set in this call (SWP_NOSIZE not
			// set) and the resulting size is non-zero, and the guest never hid the window.
			if flags&swpNoSize == 0 && ci.w > 0 && ci.h > 0 && !hwndExplicitlyHidden[hwnd] {
				ci.visible = true
			}
			ravelog.Logf("[setpos] hwnd=0x%x class=%q flags=0x%x → %d,%d %dx%d visible=%v\n", hwnd, ci.className, flags, ci.x, ci.y, ci.w, ci.h, ci.visible)
			if wnd := win32.Global.Get(hwnd); wnd != nil {
				win32.Global.UpdatePos(wnd, ci.x, ci.y, ci.w, ci.h)
			}
			// Queue WM_SIZE / WM_MOVE for windows with a guest WndProc
			if wp, ok := hwndWndProc[hwnd]; ok && wp != 0 {
				if ci.w != prevW || ci.h != prevH {
					lParam := uint64(uint16(ci.w)) | (uint64(uint16(ci.h)) << 16)
					hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{hwnd, 0x0005, 0, lParam})
				}
				if ci.x != prevX || ci.y != prevY {
					// WM_MOVE lParam = MAKELPARAM(x, y) in client-relative coords
					relX := ci.x - ox
					relY := ci.y - oy
					hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{hwnd, 0x0003, 0, uint64(uint16(relX)) | (uint64(uint16(relY)) << 16)})
				}
			}
		}
		ctx.SetReturn(1)
		return 0
	})

	// DeferWindowPos batch positioning
	type deferredPos struct {
		hwnd  uint64
		x, y  int32
		w, h  int32
		flags uint32
	}
	var deferredPositions []deferredPos
	var nextDWPHandle uint64 = 0xDEF00000

	d.RegisterAutoStubHandler(user32, "BeginDeferWindowPos", func(ctx *ntapi.TrapContext) uint32 {
		deferredPositions = deferredPositions[:0]
		nextDWPHandle++
		ctx.SetReturn(nextDWPHandle)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "DeferWindowPos", func(ctx *ntapi.TrapContext) uint32 {
		hdwp := ctx.Arg(0)
		hwnd := ctx.Arg(1)
		// arg2 = hWndInsertAfter (ignored)
		x := int32(ctx.Arg(3))
		y := int32(ctx.Arg(4))
		cx := int32(ctx.Arg(5))
		cy := int32(ctx.Arg(6))
		flags := uint32(ctx.Arg(7))
		ravelog.Logf("[defer] DeferWindowPos hwnd=0x%x x=%d y=%d w=%d h=%d flags=0x%x\n", hwnd, x, y, cx, cy, flags)
		deferredPositions = append(deferredPositions, deferredPos{hwnd: hwnd, x: x, y: y, w: cx, h: cy, flags: flags})
		ctx.SetReturn(hdwp)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "EndDeferWindowPos", func(ctx *ntapi.TrapContext) uint32 {
		const swpNoMove = 0x0002
		const swpNoSize = 0x0001
		for _, dp := range deferredPositions {
			ci, ok := hwndChildren[dp.hwnd]
			if !ok {
				continue
			}
			ox, oy := clientAreaOrigin(ci.parentHWND)
			prevX, prevY := ci.x, ci.y
			prevW, prevH := ci.w, ci.h
			if dp.flags&swpNoMove == 0 {
				ci.x = dp.x + ox
				ci.y = dp.y + oy
			}
			if dp.flags&swpNoSize == 0 {
				if dp.w > 0 {
					ci.w = dp.w
				}
				if dp.h > 0 {
					ci.h = dp.h
				}
			}
			ravelog.Logf("[setpos] hwnd=0x%x class=%q flags=0x%x → %d,%d %dx%d\n", dp.hwnd, ci.className, dp.flags, ci.x, ci.y, ci.w, ci.h)
			// Auto-show: sized non-zero → implicitly visible
			if ci.w > 0 && ci.h > 0 {
				ci.visible = true
			}
			if wnd := win32.Global.Get(dp.hwnd); wnd != nil {
				win32.Global.UpdatePos(wnd, ci.x, ci.y, ci.w, ci.h)
			}
			// Dispatch WM_SIZE / WM_MOVE to children with guest WndProcs
			if wp, ok2 := hwndWndProc[dp.hwnd]; ok2 && wp != 0 {
				if ci.w != prevW || ci.h != prevH {
					lParam := uint64(uint16(ci.w)) | (uint64(uint16(ci.h)) << 16)
					hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{dp.hwnd, 0x0005, 0, lParam})
				}
				if ci.x != prevX || ci.y != prevY {
					relX := ci.x - ox
					relY := ci.y - oy
					hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{dp.hwnd, 0x0003, 0, uint64(uint16(relX)) | (uint64(uint16(relY)) << 16)})
				}
			}
		}
		deferredPositions = deferredPositions[:0]
		ctx.SetReturn(1)
		return 0
	})

	d.RegisterAutoStubHandler(user32, "MoveWindow", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		newX, newY := int32(ctx.Arg(1)), int32(ctx.Arg(2))
		newW, newH := int32(ctx.Arg(3)), int32(ctx.Arg(4))
		bRepaint := ctx.Arg(5)
		ravelog.Logf("[move] MoveWindow hwnd=0x%x x=%d y=%d w=%d h=%d repaint=%d\n", hwnd, newX, newY, newW, newH, bRepaint)
		// Handle main window resize
		if hwnd == hctx.MainHWND && wlWindow != nil {
			prevW, prevH := wlWindow.Width, wlWindow.Height
			if newW > 0 && newW < 0x7FFF && newH > 0 && newH < 0x7FFF {
				if wlWindow.Resize(newW, newH) {
					syncScreenSurface()
				}
				clientW, clientH := getTopLevelClientSize(hwnd)
				lParam := uint64(uint16(clientW)) | (uint64(uint16(clientH)) << 16)
				hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{hwnd, 0x0005, 0, lParam})
				if bRepaint != 0 {
					queuePaint(hwnd)
				}
			}
			// Keep win32.Global in sync
			if wnd := win32.Global.Get(hwnd); wnd != nil {
				win32.Global.UpdatePos(wnd, 0, 0, wlWindow.Width, wlWindow.Height+wlWindow.TitleBarH)
			}
			if wlWindow.Width != prevW || wlWindow.Height != prevH {
				hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{hwnd, 0x0003, 0, 0})
			}
			ctx.SetReturn(1)
			return 0
		}
		if ci, ok := hwndChildren[hwnd]; ok {
			ox, oy := clientAreaOrigin(ci.parentHWND)
			prevX, prevY := ci.x, ci.y
			prevW, prevH := ci.w, ci.h
			ci.x = newX + ox
			ci.y = newY + oy
			if newW > 0 {
				ci.w = newW
			}
			if newH > 0 {
				ci.h = newH
			}
			sizeChanged := ci.w != prevW || ci.h != prevH
			// Auto-show only if size actually changed to non-zero, and guest never hid it.
			if sizeChanged && ci.w > 0 && ci.h > 0 && !hwndExplicitlyHidden[hwnd] {
				ci.visible = true
			}
			if wnd := win32.Global.Get(hwnd); wnd != nil {
				win32.Global.UpdatePos(wnd, ci.x, ci.y, ci.w, ci.h)
			}
			// Queue WM_SIZE / WM_MOVE for windows with a guest WndProc
			if wp, ok := hwndWndProc[hwnd]; ok && wp != 0 {
				if sizeChanged {
					lParam := uint64(uint16(ci.w)) | (uint64(uint16(ci.h)) << 16)
					hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{hwnd, 0x0005, 0, lParam})
				}
				if ci.x != prevX || ci.y != prevY {
					relX := ci.x - ox
					relY := ci.y - oy
					hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{hwnd, 0x0003, 0, uint64(uint16(relX)) | (uint64(uint16(relY)) << 16)})
				}
			}
			// Only repaint if size changed to a valid value (not just a position update).
			if bRepaint != 0 && sizeChanged && ci.w > 0 && ci.h > 0 {
				queuePaint(hwnd)
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetWindowTextW", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		text := readGuestUTF16(ctx.Arg(1))
		if hwnd == hctx.MainHWND && text != "" {
			hctx.MainTitle = text
			if wlWindow != nil {
				wlWindow.Title = text
				// Update the compositor title (xdg_toplevel.set_title opcode 2)
				wlDisplay.SetWindowTitle(wlWindow, text)
			}
		}
		if cs, ok := hwndChildren[hwnd]; ok {
			cs.text = text
		}
		hwndTitle[hwnd] = text
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetWindowLongPtrW", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		index := int32(ctx.Arg(1))
		newVal := ctx.Arg(2)
		m := windowLongPtr[hwnd]
		if m == nil {
			m = make(map[int32]uint64)
			windowLongPtr[hwnd] = m
		}
		old := m[index]
		m[index] = newVal
		// GWLP_WNDPROC (-4): sync with hwndWndProc dispatch map
		if index == -4 {
			if old == 0 {
				old = hwndWndProc[hwnd]
			}
			hwndWndProc[hwnd] = newVal
		}
		win32.Global.SetLong(hwnd, index, newVal)
		ravelog.Logf("[wndlong] SetWindowLongPtrW hwnd=0x%x index=%d val=0x%x\n", hwnd, index, newVal)
		// GWL_STYLE (-16): sync cs.style and cs.visible from WS_VISIBLE bit.
		if index == -16 {
			if cs, ok := hwndChildren[hwnd]; ok {
				const wsVisible = uint32(0x10000000)
				cs.style = uint32(newVal)
				nowVisible := cs.style&wsVisible != 0
				if nowVisible && !cs.visible {
					cs.visible = true
					delete(hwndExplicitlyHidden, hwnd)
				} else if !nowVisible && cs.visible {
					cs.visible = false
				}
			}
		}
		ctx.SetReturn(old)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetWindowLongPtrW", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		index := int32(ctx.Arg(1))
		var val uint64
		if m, ok := windowLongPtr[hwnd]; ok {
			val = m[index]
		}
		// GWLP_WNDPROC (-4): fall back to hwndWndProc dispatch map
		if index == -4 && val == 0 {
			val = hwndWndProc[hwnd]
		}
		ravelog.Logf("[wndlong] GetWindowLongPtrW hwnd=0x%x index=%d → 0x%x\n", hwnd, index, val)
		ctx.SetReturn(val)
		return 0
	})
	// SetWindowLongPtrA: ANSI version mirrors SetWindowLongPtrW
	d.RegisterAutoStubHandler(user32, "SetWindowLongPtrA", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		index := int32(ctx.Arg(1))
		newVal := ctx.Arg(2)
		m := windowLongPtr[hwnd]
		if m == nil {
			m = make(map[int32]uint64)
			windowLongPtr[hwnd] = m
		}
		old := m[index]
		m[index] = newVal
		if index == -4 {
			if old == 0 {
				old = hwndWndProc[hwnd]
			}
			hwndWndProc[hwnd] = newVal
		}
		if index == -16 {
			if cs, ok := hwndChildren[hwnd]; ok {
				const wsVisible = uint32(0x10000000)
				cs.style = uint32(newVal)
				nowVisible := cs.style&wsVisible != 0
				if nowVisible && !cs.visible {
					cs.visible = true
					delete(hwndExplicitlyHidden, hwnd)
				} else if !nowVisible && cs.visible {
					cs.visible = false
				}
			}
		}
		ravelog.Logf("[wndlong] SetWindowLongPtrA hwnd=0x%x index=%d val=0x%x\n", hwnd, index, newVal)
		ctx.SetReturn(old)
		return 0
	})
	// GetWindowLongPtrA: ANSI version mirrors GetWindowLongPtrW
	d.RegisterAutoStubHandler(user32, "GetWindowLongPtrA", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		index := int32(ctx.Arg(1))
		var val uint64
		if m, ok := windowLongPtr[hwnd]; ok {
			val = m[index]
		}
		if index == -4 && val == 0 {
			val = hwndWndProc[hwnd]
		}
		ravelog.Logf("[wndlong] GetWindowLongPtrA hwnd=0x%x index=%d → 0x%x\n", hwnd, index, val)
		ctx.SetReturn(val)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetWindowLongW", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		index := int32(ctx.Arg(1))
		newVal := ctx.Arg(2)
		m := windowLongPtr[hwnd]
		if m == nil {
			m = make(map[int32]uint64)
			windowLongPtr[hwnd] = m
		}
		old := m[index]
		m[index] = newVal
		if index == -16 {
			if cs, ok := hwndChildren[hwnd]; ok {
				const wsVisible = uint32(0x10000000)
				cs.style = uint32(newVal)
				nowVisible := cs.style&wsVisible != 0
				if nowVisible && !cs.visible {
					cs.visible = true
					delete(hwndExplicitlyHidden, hwnd)
				} else if !nowVisible && cs.visible {
					cs.visible = false
				}
			}
		}
		ctx.SetReturn(old)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetWindowLongW", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		index := int32(ctx.Arg(1))
		if m, ok := windowLongPtr[hwnd]; ok {
			ctx.SetReturn(m[index])
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetPropW", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		lpString := ctx.Arg(1)
		hData := ctx.Arg(2)
		var name string
		if lpString < 0x10000 {
			name = fmt.Sprintf("atom:%d", lpString)
		} else {
			name = readGuestUTF16(lpString)
		}
		m := windowProps[hwnd]
		if m == nil {
			m = make(map[string]uint64)
			windowProps[hwnd] = m
		}
		m[name] = hData
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetPropW", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		lpString := ctx.Arg(1)
		var name string
		if lpString < 0x10000 {
			name = fmt.Sprintf("atom:%d", lpString)
		} else {
			name = readGuestUTF16(lpString)
		}
		if m, ok := windowProps[hwnd]; ok {
			ctx.SetReturn(m[name])
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "RemovePropW", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		lpString := ctx.Arg(1)
		var name string
		if lpString < 0x10000 {
			name = fmt.Sprintf("atom:%d", lpString)
		} else {
			name = readGuestUTF16(lpString)
		}
		if m, ok := windowProps[hwnd]; ok {
			old := m[name]
			delete(m, name)
			ctx.SetReturn(old)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetClientRect", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		pRect := ctx.Arg(1)
		if pRect != 0 {
			var left, top, right, bottom int32
			if ci, ok := hwndChildren[hwnd]; ok {
				right, bottom = ci.w, ci.h
				if ci.style&win32.WS_VSCROLL != 0 {
					right -= win32.GetSystemMetrics(win32.SM_CXVSCROLL)
				}
				if ci.style&win32.WS_HSCROLL != 0 {
					bottom -= win32.GetSystemMetrics(win32.SM_CYHSCROLL)
				}
			} else if hwnd == hctx.MainHWND {
				right, bottom = getTopLevelClientSize(hwnd)
			} else if wnd := win32.Global.Get(hwnd); wnd != nil {
				// Window registered in global table but not yet in hwndChildren
				right = wnd.RcClient.Width()
				bottom = wnd.RcClient.Height()
			} else {
				right, bottom = 800, 600
				if wlWindow != nil {
					right, bottom = wlWindow.Width, wlWindow.Height
				}
			}
			ravelog.Logf("[getrect] GetClientRect hwnd=0x%x → %d,%d,%d,%d\n", hwnd, left, top, right, bottom)
			ctx.Mem.Write32(pRect, uint32(left))
			ctx.Mem.Write32(pRect+4, uint32(top))
			ctx.Mem.Write32(pRect+8, uint32(right))
			ctx.Mem.Write32(pRect+12, uint32(bottom))
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetWindowRect", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		pRect := ctx.Arg(1)
		if pRect != 0 {
			if wnd := win32.Global.Get(hwnd); wnd != nil {
				// Use the pre-computed screen-absolute window rect from win32.Global
				ctx.Mem.Write32(pRect, uint32(wnd.RcWindow.Left))
				ctx.Mem.Write32(pRect+4, uint32(wnd.RcWindow.Top))
				ctx.Mem.Write32(pRect+8, uint32(wnd.RcWindow.Right))
				ctx.Mem.Write32(pRect+12, uint32(wnd.RcWindow.Bottom))
			} else if ci, ok := hwndChildren[hwnd]; ok {
				// Fallback: child window stored absolute coords
				ctx.Mem.Write32(pRect, uint32(ci.x))
				ctx.Mem.Write32(pRect+4, uint32(ci.y))
				ctx.Mem.Write32(pRect+8, uint32(ci.x+ci.w))
				ctx.Mem.Write32(pRect+12, uint32(ci.y+ci.h))
			} else if hwnd == hctx.MainHWND && wlWindow != nil {
				ctx.Mem.Write32(pRect, 0)
				ctx.Mem.Write32(pRect+4, 0)
				ctx.Mem.Write32(pRect+8, uint32(wlWindow.Width))
				ctx.Mem.Write32(pRect+12, uint32(wlWindow.Height+wlWindow.TitleBarH))
			} else {
				var fw, fh int32 = 800, 600
				if wlWindow != nil {
					fw, fh = wlWindow.Width, wlWindow.Height+wlWindow.TitleBarH
				}
				ctx.Mem.Write32(pRect, 0)
				ctx.Mem.Write32(pRect+4, 0)
				ctx.Mem.Write32(pRect+8, uint32(fw))
				ctx.Mem.Write32(pRect+12, uint32(fh))
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SendMessageW", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		msg := uint32(ctx.Arg(1))
		wParam := ctx.Arg(2)
		lParam := ctx.Arg(3)
		// Log SCI messages (>= 0x400 = WM_USER) sent to Scintilla
		if msg >= 0x0400 {
			ravelog.Logf("[sci] SendMessageW hwnd=0x%x msg=0x%x(%d) wParam=0x%x\n", hwnd, msg, msg, wParam)
		}
		// Built-in controls first
		if result, handled := builtinWndProc(hwnd, msg, wParam, lParam); handled {
			ctx.SetReturn(result)
			return 0
		}
		// For guest WndProcs: dispatch synchronously via hctx.SyncStack
		wp, hasWP := hwndWndProc[hwnd]
		if !hasWP || wp == 0 {
			ctx.SetReturn(0)
			return 0
		}
		rw, okW := ctx.CPU.(ntapi.RegisterWriter)
		rr, okR := ctx.CPU.(ntapi.RegisterReader)
		if okW && okR {
			rsp := rr.ReadReg(4)
			retAddr, _ := mem.Read64(rsp)
			// Validate retAddr: must be a plausible code address (>= 16MB).
			// Values below 0x1000000 are HWNDs or other small handles stored on the
			// stack (e.g., as shadow space), not valid return addresses. Using such a
			// value as a return target after WndProc would crash the CPU.
			if retAddr < 0x1000000 {
				ravelog.Logf("[sendmsg] skipping sync dispatch: bad retAddr=0x%x hwnd=0x%x msg=0x%x\n",
					retAddr, hwnd, msg)
				ctx.SetReturn(0)
				return 0
			}
			hctx.SyncStack = append(hctx.SyncStack, syncDispatchFrame{
				queue:               []syncDispatch{},
				retAddr:             retAddr,
				hwnd:                hwnd,
				returnWndProcResult: true,
			})
			mem.Write64(rsp, hctx.SyncTrampoline)
			rw.WriteReg(1, hwnd)
			rw.WriteReg(2, uint64(msg))
			rw.WriteReg(8, wParam)
			rw.WriteReg(9, lParam)
			ctx.CPU.SetPC(wp)
			ctx.ReturnOverridden = true
			return 0
		}
		// Fallback: queue for async dispatch (won't return result synchronously)
		hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{hwnd, msg, wParam, lParam})
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "PostMessageW", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		msg := uint32(ctx.Arg(1))
		wParam := ctx.Arg(2)
		lParam := ctx.Arg(3)
		// Route into our message queue so guest WndProcs see it
		if hwnd == hctx.MainHWND || hwnd == 0xFFFF || hwnd == 0xFFFFFFFFFFFFFFFF {
			hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{hctx.MainHWND, msg, wParam, lParam})
		} else if _, ok := hwndChildren[hwnd]; ok {
			hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{hwnd, msg, wParam, lParam})
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	defWindowProcFn := func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		msg := uint32(ctx.Arg(1))
		wParam := ctx.Arg(2)
		lParam := ctx.Arg(3)

		// WM_PAINT: draw non-client area (NC paint + menu bar), erase background, paint children
		if msg == 0x000F && wlWindow != nil {
			if hwnd == hctx.MainHWND {
				if wlWindow.ResizeIfNeeded() {
					syncScreenSurface()
				}
				w := wlWindow.Width

				// Trigger NC paint first (draws frame + caption + client edge)
				if wlWindow.TitleBarH > 0 {
					ncPaintCtx := *ctx // shallow copy for re-entrant dispatch
					_ = ncPaintCtx
					// Directly invoke our WM_NCPAINT handler logic
					wnd := win32.Global.Get(hwnd)
					if wnd != nil {
						ncStyle := wnd.Style
						ncExStyle := wnd.ExStyle
						winW := wlWindow.Width
						winH := wlWindow.Height + wlWindow.TitleBarH
						syncScreenSurface()
						_, ncDC := gdiMgr.AllocScreenDC()
						ncDC.OriginX = 0
						ncDC.OriginY = 0
						curL, curT, curR, curB := int32(0), int32(0), winW, winH

						if win32.UserHasWindowEdge(ncStyle, ncExStyle) {
							ncDC.DrawEdge(curL, curT, curR, curB, 0x0005, 0x000F, hctx.SysColors)
							curL += 2
							curT += 2
							curR -= 2
							curB -= 2
						}
						if ncStyle&0x00040000 != 0 && ncStyle&0x20000000 == 0 {
							fW := (win32.GetSystemMetrics(win32.SM_CXFRAME) - win32.GetSystemMetrics(win32.SM_CXDLGFRAME)) *
								win32.GetSystemMetrics(win32.SM_CXBORDER)
							fH := (win32.GetSystemMetrics(win32.SM_CYFRAME) - win32.GetSystemMetrics(win32.SM_CYDLGFRAME)) *
								win32.GetSystemMetrics(win32.SM_CYBORDER)
							borderColor := hctx.SysColors[10]
							if !hctx.MainActive {
								borderColor = hctx.SysColors[11]
							}
							ncDC.FillRect(curL, curT, curR, curT+fH, borderColor)
							ncDC.FillRect(curL, curT, curL+fW, curB, borderColor)
							ncDC.FillRect(curL, curB-fH, curR, curB, borderColor)
							ncDC.FillRect(curR-fW, curT, curR, curB, borderColor)
							curL += fW
							curT += fH
							curR -= fW
							curB -= fH
						}
						if ncStyle&(0x00400000|0x00800000) != 0 || ncExStyle&0x00000001 != 0 {
							bW := win32.GetSystemMetrics(win32.SM_CXBORDER)
							bH := win32.GetSystemMetrics(win32.SM_CYBORDER)
							var brushColor uint32
							if ncExStyle&(0x00000001|0x00000200) != 0 {
								brushColor = hctx.SysColors[15]
							} else if ncExStyle&0x00020000 != 0 {
								brushColor = hctx.SysColors[6]
							} else if ncStyle&(0x00400000|0x00040000) != 0 {
								brushColor = hctx.SysColors[15]
							} else {
								brushColor = hctx.SysColors[6]
							}
							ncDC.FillRect(curL, curT, curR, curT+bH, brushColor)
							ncDC.FillRect(curL, curT, curL+bW, curB, brushColor)
							ncDC.FillRect(curL, curB-bH, curR, curB, brushColor)
							ncDC.FillRect(curR-bW, curT, curR, curB, brushColor)
							curL += bW
							curT += bH
							curR -= bW
							curB -= bH
						}
						if ncStyle&0x00C00000 == 0x00C00000 {
							captionH := win32.GetSystemMetrics(win32.SM_CYCAPTION)
							if ncExStyle&0x00000080 != 0 {
								captionH = win32.GetSystemMetrics(win32.SM_CYSMCAPTION)
							}
							captionBottom := curT + captionH
							flags := uint32(0x0020 | 0x0008)
							if hctx.MainActive {
								flags |= 0x0001
							}
							ncDC.DrawCaption(curL, curT, curR, captionBottom-1, hctx.MainTitle, flags, hctx.SysColors)
							btnW := win32.GetSystemMetrics(win32.SM_CXSIZE)
							btnH := captionH - 2
							if ncStyle&0x00080000 != 0 {
								ncDC.DrawFrameControl(curR-btnW, curT, curR, curT+btnH, 1, 0, hctx.SysColors)
								if ncExStyle&0x00000080 == 0 && ncStyle&(0x00020000|0x00010000) != 0 {
									ncDC.DrawFrameControl(curR-2*btnW, curT, curR-btnW, curT+btnH, 1, 2, hctx.SysColors)
									ncDC.DrawFrameControl(curR-3*btnW, curT, curR-2*btnW, curT+btnH, 1, 1, hctx.SysColors)
								}
							}
							lineColor := hctx.SysColors[15]
							ncDC.FillRect(curL, captionBottom-1, curR, captionBottom, lineColor)
							curT = captionBottom
						}
						if ncExStyle&0x00000200 != 0 {
							ncDC.DrawEdge(curL, curT, curR, curB, 0x000A, 0x000F, hctx.SysColors)
						}
					}
				}

				clientTop := wlWindow.TitleBarH
				ravelog.Logf("[paint] DefWndProc WM_PAINT hctx.MainHWND w=%d h=%d\n", wlWindow.Width, wlWindow.Height)

				// Non-client area: draw menu bar
				menuH, menuOk := hwndMenuBar[hwnd]
				if menuOk {
					md, ok2 := menus[menuH]
					if ok2 && len(md.items) > 0 {
						menuBarH := win32.GetSystemMetrics(win32.SM_CYMENU)
						clientTop = wlWindow.TitleBarH + menuBarH
						wlWindow.DrawRectAbs(0, wlWindow.TitleBarH, w, clientTop, hctx.SysColors[15])
						wlWindow.DrawRectAbs(0, clientTop-1, w, clientTop, hctx.SysColors[16])
						x := int32(4)
						for i, item := range md.items {
							if item.flags&0x0800 != 0 {
								continue
							}
							// Only show popup items in menu bar (items with submenus)
							if item.flags&0x0010 == 0 {
								continue
							}
							label, _ := menuTextParts(menuStripAmpersand(item.text))
							if label == "" || label == "-" {
								continue
							}
							if !menuHasRenderableText(label) {
								continue
							}
							tw := menuTextWidth(label) + 12
							if hctx.OpenMenuIdx == i && hctx.OpenMenuHwnd == hwnd {
								wlWindow.DrawRectAbs(x, wlWindow.TitleBarH, x+tw, clientTop-1, hctx.SysColors[20])
								ncDrawText(x+4, wlWindow.TitleBarH+3, label, 0x000000, hctx.SysColors[20], true, 12)
							} else {
								ncDrawText(x+4, wlWindow.TitleBarH+3, label, 0x000000, hctx.SysColors[15], true, 12)
							}
							x += tw
						}

						// Dropdown overlay drawn later in commitIfDone (after paintTree).
					}
				}

				// Fill entire client area with background color.
				// Builtin children will paint on top via paintTree.
				// Guest-drawn children (Scintilla) repaint in their own
				// WM_PAINT pass and trigger a re-commit.
				totalH := wlWindow.Height + wlWindow.TitleBarH
				vScrollW, hScrollH := getClientScrollbarSizes(hwnd)
				clientRight := w - vScrollW
				clientBottom := totalH - hScrollH
				if clientRight < 0 {
					clientRight = 0
				}
				if clientBottom < clientTop {
					clientBottom = clientTop
				}
				wlWindow.DrawRectAbs(0, clientTop, clientRight, clientBottom, hctx.SysColors[5])
				if vScrollW > 0 {
					si := win32.ScrollInfo{}
					win32.GetScrollInfo(hwnd, win32.SB_VERT, &si, win32.SIF_ALL)
					drawScrollBar(win32.Rect{
						Left:   clientRight,
						Top:    clientTop,
						Right:  w,
						Bottom: clientBottom,
					}, true, si)
				}
				if hScrollH > 0 {
					si := win32.ScrollInfo{}
					win32.GetScrollInfo(hwnd, win32.SB_HORZ, &si, win32.SIF_ALL)
					drawScrollBar(win32.Rect{
						Left:   0,
						Top:    clientBottom,
						Right:  clientRight,
						Bottom: totalH,
					}, false, si)
				}
				if vScrollW > 0 && hScrollH > 0 {
					wlWindow.DrawRectAbs(clientRight, clientBottom, w, totalH, hctx.SysColors[15])
				}

				// Recursively paint built-in descendant windows (builtinWndProc skips app-defined children)
				paintTree(hwnd)
				// Signal that the base frame is ready; all subsequent EndPaints can trigger re-commits.
				hctx.HasBaseFrame = true
				hctx.RepaintBuiltin = true
				// Always commit the base frame immediately. Guest-wndproc children
				// (e.g. Scintilla) will re-commit when their EndPaint fires.
				// Previously we deferred waiting for their EndPaint, but child
				// WM_PAINT sits behind WM_SIZE/WM_MOVE in the FIFO queue and
				// under emulation the delay is unbounded → permanently gray window.
				hctx.FrameReady = true
				commitIfDone()
				// Queue WM_PAINT for guest children so they repaint on top.
				for h, cs := range hwndChildren {
					if cs.parentHWND == hctx.MainHWND && cs.visible && cs.w > 0 && cs.h > 0 {
						if _, hasGuest := hwndWndProc[h]; hasGuest {
							queuePaint(h)
						}
					}
				}
			}
			// For non-hctx.MainHWND: ReactOS DefWindowProc just calls BeginPaint+EndPaint
			// In our model, the child is painted by paintTree from the parent
			ctx.SetReturn(0)
			return 0
		}
		// WM_NCCALCSIZE (0x0083): compute client rect from window rect.
		// Ported from ReactOS nonclient.c NC_HandleNCCalcSize.
		if msg == 0x0083 && wlWindow != nil {
			wnd := win32.Global.Get(hwnd)
			if wnd != nil {
				style := wnd.Style
				exStyle := wnd.ExStyle
				if style&0x20000000 == 0 { // !WS_MINIMIZE
					// Read the proposed RECT from guest memory (lParam).
					// For wParam==0 lParam → single RECT.
					// For wParam==1 lParam → NCCALCSIZE_PARAMS (first RECT is the new window rect).
					rAddr := lParam
					rL, _ := mem.Read32(rAddr)
					rT, _ := mem.Read32(rAddr + 4)
					rR, _ := mem.Read32(rAddr + 8)
					rBot, _ := mem.Read32(rAddr + 12)
					left := int32(rL)
					top := int32(rT)
					right := int32(rR)
					bottom := int32(rBot)

					// Deflate by border
					if win32.UserHasWindowEdge(style, exStyle) {
						bx, by := win32.BorderSize(style, exStyle)
						left += bx
						top += by
						right -= bx
						bottom -= by
					} else if exStyle&0x00020000 != 0 { // WS_EX_STATICEDGE
						left++
						top++
						right--
						bottom--
					} else if style&0x00800000 != 0 { // WS_BORDER
						left++
						top++
						right--
						bottom--
					}

					// Subtract caption
					if style&0x00C00000 == 0x00C00000 { // WS_CAPTION
						if exStyle&0x00000080 != 0 { // WS_EX_TOOLWINDOW
							top += win32.GetSystemMetrics(win32.SM_CYSMCAPTION)
						} else {
							top += win32.GetSystemMetrics(win32.SM_CYCAPTION)
						}
					}

					// Subtract menu bar
					if _, hasMenu := hwndMenuBar[hwnd]; hasMenu {
						top += win32.GetSystemMetrics(win32.SM_CYMENU)
					}

					if style&win32.WS_VSCROLL != 0 {
						right -= win32.GetSystemMetrics(win32.SM_CXVSCROLL)
					}
					if style&win32.WS_HSCROLL != 0 {
						bottom -= win32.GetSystemMetrics(win32.SM_CYHSCROLL)
					}

					// Subtract client edge
					if exStyle&0x00000200 != 0 { // WS_EX_CLIENTEDGE
						bw := win32.GetSystemMetrics(win32.SM_CXBORDER)
						bh := win32.GetSystemMetrics(win32.SM_CYBORDER)
						left += 2 * bw
						top += 2 * bh
						right -= 2 * bw
						bottom -= 2 * bh
					}

					if top > bottom {
						bottom = top
					}
					if left > right {
						right = left
					}

					// Write back
					mem.Write32(rAddr, uint32(left))
					mem.Write32(rAddr+4, uint32(top))
					mem.Write32(rAddr+8, uint32(right))
					mem.Write32(rAddr+12, uint32(bottom))
				}
			}
			ctx.SetReturn(0)
			return 0
		}
		// WM_NCPAINT (0x0085): draw the non-client area.
		// Ported from ReactOS nonclient.c NC_DoNCPaint.
		if msg == 0x0085 && wlWindow != nil && hwnd == hctx.MainHWND {
			wnd := win32.Global.Get(hwnd)
			if wnd != nil {
				style := wnd.Style
				exStyle := wnd.ExStyle
				winW := wlWindow.Width
				winH := wlWindow.Height + wlWindow.TitleBarH
				// Create a window DC (origin 0,0 covering full surface including NC)
				syncScreenSurface()
				hDC, dc := gdiMgr.AllocScreenDC()
				dc.OriginX = 0
				dc.OriginY = 0
				// Current rect tracks the shrinking paint area
				curL, curT, curR, curB := int32(0), int32(0), winW, winH

				// 1. Draw outer edge (EDGE_RAISED)
				if win32.UserHasWindowEdge(style, exStyle) {
					dc.DrawEdge(curL, curT, curR, curB, 0x0005, 0x000F, hctx.SysColors) // EDGE_RAISED|BF_RECT
					curL += 2
					curT += 2
					curR -= 2
					curB -= 2 // BF_ADJUST
				} else if exStyle&0x00020000 != 0 { // WS_EX_STATICEDGE
					dc.FillRect(curL, curT, curR, curT+1, hctx.SysColors[16]) // top
					dc.FillRect(curL, curT, curL+1, curB, hctx.SysColors[16]) // left
					dc.FillRect(curL, curB-1, curR, curB, hctx.SysColors[20]) // bottom
					dc.FillRect(curR-1, curT, curR, curB, hctx.SysColors[20]) // right
					curL++
					curT++
					curR--
					curB--
				}

				// 2. Draw frame (NC_DrawFrame from ReactOS)
				if style&0x00040000 != 0 && style&0x20000000 == 0 { // WS_THICKFRAME && !WS_MINIMIZE
					fW := (win32.GetSystemMetrics(win32.SM_CXFRAME) - win32.GetSystemMetrics(win32.SM_CXDLGFRAME)) *
						win32.GetSystemMetrics(win32.SM_CXBORDER)
					fH := (win32.GetSystemMetrics(win32.SM_CYFRAME) - win32.GetSystemMetrics(win32.SM_CYDLGFRAME)) *
						win32.GetSystemMetrics(win32.SM_CYBORDER)
					borderColor := hctx.SysColors[10] // COLOR_ACTIVEBORDER
					if !hctx.MainActive {
						borderColor = hctx.SysColors[11] // COLOR_INACTIVEBORDER
					}
					dc.FillRect(curL, curT, curR, curT+fH, borderColor)
					dc.FillRect(curL, curT, curL+fW, curB, borderColor)
					dc.FillRect(curL, curB-fH, curR, curB, borderColor)
					dc.FillRect(curR-fW, curT, curR, curB, borderColor)
					curL += fW
					curT += fH
					curR -= fW
					curB -= fH
				}
				// Inner border
				if style&(0x00400000|0x00800000) != 0 || exStyle&0x00000001 != 0 { // WS_DLGFRAME|WS_BORDER|WS_EX_DLGMODALFRAME
					bW := win32.GetSystemMetrics(win32.SM_CXBORDER)
					bH := win32.GetSystemMetrics(win32.SM_CYBORDER)
					var brushColor uint32
					if exStyle&(0x00000001|0x00000200) != 0 { // WS_EX_DLGMODALFRAME|WS_EX_CLIENTEDGE
						brushColor = hctx.SysColors[15] // COLOR_3DFACE
					} else if exStyle&0x00020000 != 0 { // WS_EX_STATICEDGE
						brushColor = hctx.SysColors[6] // COLOR_WINDOWFRAME
					} else if style&(0x00400000|0x00040000) != 0 { // WS_DLGFRAME|WS_THICKFRAME
						brushColor = hctx.SysColors[15] // COLOR_3DFACE
					} else {
						brushColor = hctx.SysColors[6] // COLOR_WINDOWFRAME
					}
					dc.FillRect(curL, curT, curR, curT+bH, brushColor)
					dc.FillRect(curL, curT, curL+bW, curB, brushColor)
					dc.FillRect(curL, curB-bH, curR, curB, brushColor)
					dc.FillRect(curR-bW, curT, curR, curB, brushColor)
					curL += bW
					curT += bH
					curR -= bW
					curB -= bH
				}

				// 3. Draw caption
				if style&0x00C00000 == 0x00C00000 { // WS_CAPTION
					captionH := win32.GetSystemMetrics(win32.SM_CYCAPTION)
					if exStyle&0x00000080 != 0 { // WS_EX_TOOLWINDOW
						captionH = win32.GetSystemMetrics(win32.SM_CYSMCAPTION)
					}
					captionBottom := curT + captionH
					// Draw caption bar with gradient
					flags := uint32(0x0020 | 0x0008) // DC_GRADIENT | DC_TEXT
					if hctx.MainActive {
						flags |= 0x0001 // DC_ACTIVE
					}
					dc.DrawCaption(curL, curT, curR, captionBottom-1, hctx.MainTitle, flags, hctx.SysColors)

					// Draw caption buttons (ReactOS UserDrawCaptionButton)
					btnW := win32.GetSystemMetrics(win32.SM_CXSIZE)
					btnH := captionH - 2
					if style&0x00080000 != 0 { // WS_SYSMENU
						// Close button (rightmost)
						dc.DrawFrameControl(curR-btnW, curT, curR, curT+btnH, 1, 0, hctx.SysColors) // DFC_CAPTION, DFCS_CAPTIONCLOSE
						// Min/Max if not tool window
						if exStyle&0x00000080 == 0 {
							if style&(0x00020000|0x00010000) != 0 { // WS_MINIMIZEBOX|WS_MAXIMIZEBOX
								dc.DrawFrameControl(curR-2*btnW, curT, curR-btnW, curT+btnH, 1, 2, hctx.SysColors)   // DFCS_CAPTIONMAX
								dc.DrawFrameControl(curR-3*btnW, curT, curR-2*btnW, curT+btnH, 1, 1, hctx.SysColors) // DFCS_CAPTIONMIN
							}
						}
					}

					// Line under caption (ReactOS: IntSetDCPenColor + LineTo)
					lineColor := hctx.SysColors[15]                               // COLOR_3DFACE
					if exStyle&(0x00020000|0x00000200|0x00000001) == 0x00020000 { // only WS_EX_STATICEDGE
						lineColor = hctx.SysColors[6] // COLOR_WINDOWFRAME
					}
					dc.FillRect(curL, captionBottom-1, curR, captionBottom, lineColor)

					curT = captionBottom
				}

				if _, hasMenu := hwndMenuBar[hwnd]; hasMenu {
					menuBarH := win32.GetSystemMetrics(win32.SM_CYMENU)
					dc.FillRect(curL, curT, curR, curT+menuBarH, hctx.SysColors[30])
					dc.FillRect(curL, curT+menuBarH-1, curR, curT+menuBarH, hctx.SysColors[16])
					curT += menuBarH
				}

				if style&win32.WS_VSCROLL != 0 {
					sbW := win32.GetSystemMetrics(win32.SM_CXVSCROLL)
					si := win32.ScrollInfo{}
					win32.GetScrollInfo(hwnd, win32.SB_VERT, &si, win32.SIF_ALL)
					drawScrollBar(win32.Rect{
						Left:   curR - sbW,
						Top:    curT,
						Right:  curR,
						Bottom: curB,
					}, true, si)
					curR -= sbW
				}
				if style&win32.WS_HSCROLL != 0 {
					sbH := win32.GetSystemMetrics(win32.SM_CYHSCROLL)
					si := win32.ScrollInfo{}
					win32.GetScrollInfo(hwnd, win32.SB_HORZ, &si, win32.SIF_ALL)
					drawScrollBar(win32.Rect{
						Left:   curL,
						Top:    curB - sbH,
						Right:  curR,
						Bottom: curB,
					}, false, si)
					curB -= sbH
				}
				if style&win32.WS_VSCROLL != 0 && style&win32.WS_HSCROLL != 0 {
					wlWindow.DrawRectAbs(curR, curB, winW, winH, hctx.SysColors[15])
				}

				// 5. Client edge
				if exStyle&0x00000200 != 0 { // WS_EX_CLIENTEDGE
					dc.DrawEdge(curL, curT, curR, curB, 0x000A, 0x000F, hctx.SysColors) // EDGE_SUNKEN|BF_RECT
				}

				gdiMgr.DeleteDC(hDC)
			}
			ctx.SetReturn(0)
			return 0
		}
		// WM_NCACTIVATE (0x0086): redraw caption with active/inactive state.
		if msg == 0x0086 && wlWindow != nil && hwnd == hctx.MainHWND {
			hctx.MainActive = wParam != 0
			// Queue WM_NCPAINT so the caption redraws with correct active/inactive colours.
			hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{hwnd: hctx.MainHWND, message: 0x0085, wParam: 1, lParam: 0})
			ctx.SetReturn(1) // return TRUE = allow activation change
			return 0
		}
		// WM_NCHITTEST (0x0084): hit-test the non-client area.
		// Ported from ReactOS nonclient.c DefWndNCHitTest.
		if msg == 0x0084 && wlWindow != nil && hwnd == hctx.MainHWND {
			// lParam contains POINT: x = LOWORD, y = HIWORD (signed)
			px := int32(int16(lParam & 0xFFFF))
			py := int32(int16((lParam >> 16) & 0xFFFF))
			wnd := win32.Global.Get(hwnd)
			if wnd == nil {
				ctx.SetReturn(1) // HTCLIENT
				return 0
			}
			style := wnd.Style
			exStyle := wnd.ExStyle
			winW := wlWindow.Width
			winH := wlWindow.Height + wlWindow.TitleBarH
			// Window rect in screen coords (we use 0,0 origin for top-level)
			wr := win32.Rect{Left: 0, Top: 0, Right: winW, Bottom: winH}
			if !win32.PtInRect(&wr, px, py) {
				ctx.SetReturn(0) // HTNOWHERE
				return 0
			}

			// Deflate by border
			if win32.UserHasWindowEdge(style, exStyle) {
				bx, by := win32.BorderSize(style, exStyle)
				win32.InflateRect(&wr, -bx, -by)
				if !win32.PtInRect(&wr, px, py) {
					// In the border area - determine which border
					xSize := win32.GetSystemMetrics(win32.SM_CXSIZE) * win32.GetSystemMetrics(win32.SM_CXBORDER)
					ySize := win32.GetSystemMetrics(win32.SM_CYSIZE) * win32.GetSystemMetrics(win32.SM_CYBORDER)
					thickFrame := style&0x00040000 != 0 // WS_THICKFRAME
					if py < wr.Top {
						if !thickFrame {
							ctx.SetReturn(18)
							return 0
						} // HTBORDER
						if px < wr.Left+xSize {
							ctx.SetReturn(13)
							return 0
						} // HTTOPLEFT
						if px >= wr.Right-xSize {
							ctx.SetReturn(14)
							return 0
						} // HTTOPRIGHT
						ctx.SetReturn(12)
						return 0 // HTTOP
					}
					if py >= wr.Bottom {
						if !thickFrame {
							ctx.SetReturn(18)
							return 0
						}
						if px < wr.Left+xSize {
							ctx.SetReturn(16)
							return 0
						} // HTBOTTOMLEFT
						if px >= wr.Right-xSize {
							ctx.SetReturn(17)
							return 0
						} // HTBOTTOMRIGHT
						ctx.SetReturn(15)
						return 0 // HTBOTTOM
					}
					if px < wr.Left {
						if !thickFrame {
							ctx.SetReturn(18)
							return 0
						}
						if py < wr.Top+ySize {
							ctx.SetReturn(13)
							return 0
						} // HTTOPLEFT
						if py >= wr.Bottom-ySize {
							ctx.SetReturn(16)
							return 0
						} // HTBOTTOMLEFT
						ctx.SetReturn(10)
						return 0 // HTLEFT
					}
					if px >= wr.Right {
						if !thickFrame {
							ctx.SetReturn(18)
							return 0
						}
						if py < wr.Top+ySize {
							ctx.SetReturn(14)
							return 0
						} // HTTOPRIGHT
						if py >= wr.Bottom-ySize {
							ctx.SetReturn(17)
							return 0
						} // HTBOTTOMRIGHT
						ctx.SetReturn(11)
						return 0 // HTRIGHT
					}
				}
			} else {
				if exStyle&0x00020000 != 0 { // WS_EX_STATICEDGE
					win32.InflateRect(&wr, -1, -1)
				}
				if !win32.PtInRect(&wr, px, py) {
					ctx.SetReturn(18) // HTBORDER
					return 0
				}
			}
			// Check caption area
			if style&0x00C00000 == 0x00C00000 { // WS_CAPTION
				captionH := win32.GetSystemMetrics(win32.SM_CYCAPTION)
				if exStyle&0x00000080 != 0 { // WS_EX_TOOLWINDOW
					captionH = win32.GetSystemMetrics(win32.SM_CYSMCAPTION)
				}
				wr.Top += captionH
				if !win32.PtInRect(&wr, px, py) {
					// In caption - check for sysmenu, close, min, max
					if style&0x00080000 != 0 { // WS_SYSMENU
						btnW := win32.GetSystemMetrics(win32.SM_CXSIZE)
						if exStyle&0x00000080 == 0 { // not tool window
							// System menu icon area
							wr.Left += btnW
						}
						wr.Right -= btnW // close button
					}
					if px < wr.Left {
						ctx.SetReturn(3)
						return 0
					} // HTSYSMENU
					if px >= wr.Right+win32.GetSystemMetrics(win32.SM_CXSIZE)-win32.GetSystemMetrics(win32.SM_CXSIZE) {
						// We already subtracted close button space
					}
					if px >= wr.Right {
						ctx.SetReturn(20)
						return 0
					} // HTCLOSE
					if style&(0x00020000|0x00010000) != 0 { // WS_MINIMIZEBOX|WS_MAXIMIZEBOX
						btnW := win32.GetSystemMetrics(win32.SM_CXSIZE)
						wr.Right -= btnW // max button
						if px >= wr.Right {
							ctx.SetReturn(9)
							return 0
						} // HTMAXBUTTON
						if style&0x00020000 != 0 { // WS_MINIMIZEBOX
							wr.Right -= btnW // min button
							if px >= wr.Right {
								ctx.SetReturn(8)
								return 0
							} // HTMINBUTTON
						}
					}
					ctx.SetReturn(2) // HTCAPTION
					return 0
				}
			}
			// Check menu area
			if _, hasMenu := hwndMenuBar[hwnd]; hasMenu {
				wr.Top += win32.GetSystemMetrics(win32.SM_CYMENU)
				if !win32.PtInRect(&wr, px, py) {
					ctx.SetReturn(5) // HTMENU
					return 0
				}
			}
			ctx.SetReturn(1) // HTCLIENT
			return 0
		}
		// WM_NCCREATE: must return TRUE for window creation to proceed
		if msg == 0x0081 {
			ctx.SetReturn(1)
			return 0
		}
		// WM_NCLBUTTONDOWN (0x00A1): handle clicks in non-client area.
		// Ported from ReactOS nonclient.c NC_HandleNCLButtonDown.
		if msg == 0x00A1 && wlWindow != nil && hwnd == hctx.MainHWND {
			hitTest := wParam
			switch hitTest {
			case 2: // HTCAPTION - initiate window move via WM_SYSCOMMAND SC_MOVE
				// Post WM_SYSCOMMAND SC_MOVE+HTCAPTION (0xF012)
				hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{hwnd: hctx.MainHWND, message: 0x0112, wParam: 0xF012, lParam: lParam})
			case 3: // HTSYSMENU - double-click closes, single opens system menu
				hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{hwnd: hctx.MainHWND, message: 0x0112, wParam: 0xF060, lParam: lParam}) // SC_CLOSE
			case 8: // HTMINBUTTON - SC_MINIMIZE (0xF020)
				hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{hwnd: hctx.MainHWND, message: 0x0112, wParam: 0xF020, lParam: lParam})
			case 9: // HTMAXBUTTON - SC_MAXIMIZE (0xF030)
				hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{hwnd: hctx.MainHWND, message: 0x0112, wParam: 0xF030, lParam: lParam})
			case 20: // HTCLOSE - SC_CLOSE (0xF060)
				hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{hwnd: hctx.MainHWND, message: 0x0112, wParam: 0xF060, lParam: lParam})
			}
			ctx.SetReturn(0)
			return 0
		}
		// WM_SYSCOMMAND (0x0112): handle system commands (close, minimize, maximize, move).
		// Ported from ReactOS defwnd.c DefWndHandleSysCommand.
		if msg == 0x0112 && wlWindow != nil {
			cmd := wParam & 0xFFF0
			switch cmd {
			case 0xF060: // SC_CLOSE
				ravelog.Logf("[syscmd] SC_CLOSE hwnd=0x%x\n", hwnd)
				// Send WM_CLOSE to the window
				hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{hwnd: hwnd, message: 0x0010, wParam: 0, lParam: 0})
			case 0xF020: // SC_MINIMIZE
				ravelog.Logf("[syscmd] SC_MINIMIZE hwnd=0x%x\n", hwnd)
				// Minimize via xdg_toplevel.set_minimized
				if wlWindow != nil {
					wlWindow.Minimize()
				}
			case 0xF030: // SC_MAXIMIZE
				ravelog.Logf("[syscmd] SC_MAXIMIZE hwnd=0x%x\n", hwnd)
				if wlWindow != nil {
					wlWindow.Maximize()
				}
			case 0xF120: // SC_RESTORE
				ravelog.Logf("[syscmd] SC_RESTORE hwnd=0x%x\n", hwnd)
				if wlWindow != nil {
					wlWindow.Restore()
				}
			case 0xF012: // SC_MOVE + HTCAPTION
				ravelog.Logf("[syscmd] SC_MOVE hwnd=0x%x\n", hwnd)
				if wlWindow != nil {
					wlWindow.StartMove()
				}
			case 0xF000: // SC_SIZE
				ravelog.Logf("[syscmd] SC_SIZE hwnd=0x%x\n", hwnd)
			}
			ctx.SetReturn(0)
			return 0
		}
		// WM_CLOSE (0x0010): destroy the window.
		if msg == 0x0010 && wlWindow != nil {
			ravelog.Logf("[wm] WM_CLOSE hwnd=0x%x\n", hwnd)
			// Post WM_DESTROY + WM_QUIT
			hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{hwnd: hwnd, message: 0x0002, wParam: 0, lParam: 0}) // WM_DESTROY
			ctx.SetReturn(0)
			return 0
		}
		// WM_DESTROY (0x0002): post quit message.
		if msg == 0x0002 {
			ravelog.Logf("[wm] WM_DESTROY hwnd=0x%x\n", hwnd)
			// PostQuitMessage(0)
			hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{hwnd: 0, message: 0x0012, wParam: 0, lParam: 0}) // WM_QUIT
			ctx.SetReturn(0)
			return 0
		}
		// WM_ERASEBKGND: fill with class background brush (ReactOS: defwnd.c)
		if msg == 0x0014 && wlWindow != nil {
			bgColor := hctx.SysColors[5] // default COLOR_WINDOW
			if a, ok := hctx.HwndClassAtom[hwnd]; ok {
				if brushIdx, ok2 := hctx.ClassBrush[a]; ok2 && brushIdx > 0 && int(brushIdx-1) < len(hctx.SysColors) {
					bgColor = hctx.SysColors[brushIdx-1]
				}
			}
			if cs, ok := hwndChildren[hwnd]; ok {
				wlWindow.DrawRectAbs(cs.x, cs.y, cs.x+cs.w, cs.y+cs.h, bgColor)
			} else if hwnd == hctx.MainHWND {
				clientTop := getMenuClientTop(hwnd)
				w := wlWindow.Width
				h := wlWindow.Height + wlWindow.TitleBarH
				vScrollW, hScrollH := getClientScrollbarSizes(hwnd)
				wlWindow.DrawRectAbs(0, clientTop, w-vScrollW, h-hScrollH, bgColor)
			}
			ctx.SetReturn(1)
			return 0
		}
		_ = wParam
		ctx.SetReturn(0)
		return 0
	}
	d.RegisterAutoStubHandler(user32, "DefWindowProcW", defWindowProcFn)
	// writeMsg writes a Win32 MSG struct to guest memory (correct x64 layout).
	// MSG: HWND(8) message(4) pad(4) WPARAM(8) LPARAM(8) time(4) POINT(8)
	writeMsg := func(pMsg, hwnd uint64, message uint32, wParam, lParam uint64) {
		mem.Write64(pMsg, hwnd)
		mem.Write32(pMsg+8, message)
		mem.Write32(pMsg+12, 0) // padding
		mem.Write64(pMsg+16, wParam)
		mem.Write64(pMsg+24, lParam)
		mem.Write32(pMsg+32, 0) // time
		mem.Write32(pMsg+36, 0) // pt.x
		mem.Write32(pMsg+40, 0) // pt.y
	}
	// GetMessageW: drain message queue first, then block on Wayland events
	// dispatchWl is shared with PeekMessageW - defined as a package-level var so both can access it.
	var dispatchWl func(evt wl.EventType)
	d.RegisterAutoStubHandler(user32, "GetMessageW", func(ctx *ntapi.TrapContext) uint32 {
		pMsg := ctx.Arg(0)

		// Save message loop entry point for crash recovery
		if msgLoopSP == 0 {
			retAddr, _ := mem.Read64(ctx.CPU.GetSP())
			msgLoopPC = retAddr
			msgLoopSP = ctx.CPU.GetSP() + 8
		}

		// Helper: check expired timers, post WM_TIMER for each.
		checkTimers := func() {
			now := time.Now()
			for id, t := range timerMap {
				if now.Before(t.deadline) {
					continue
				}
				// Re-arm before posting to avoid duplicate posts.
				t.deadline = now.Add(time.Duration(t.intervalMs) * time.Millisecond)
				timerMap[id] = t
				target := t.hwnd
				if target == 0 {
					target = hctx.MainHWND
				}
				hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{target, 0x0113, id, 0}) // WM_TIMER
			}
		}

		// Helper: convert a Wayland event into Win32 messages.
		dispatchWl = func(evt wl.EventType) {
			if evt == wl.EventClose {
				hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{hctx.MainHWND, 0x12, 0, 0})
				return
			}
			if evt == wl.EventConfigure {
				// Compositor resized the window - resize buffer and post WM_SIZE to guest
				if wlWindow.ResizeIfNeeded() {
					syncScreenSurface()
				}
				w := wlWindow.Width
				h := wlWindow.Height
				if hctx.LastPostedMainW == w && hctx.LastPostedMainH == h {
					return
				}
				hctx.LastPostedMainW, hctx.LastPostedMainH = w, h
				// Keep RcWindow/RcClient in sync so GetWindowRect returns correct values.
				if wnd := win32.Global.Get(hctx.MainHWND); wnd != nil {
					win32.Global.UpdatePos(wnd, 0, 0, w, h+wlWindow.TitleBarH)
				}
				// ReactOS co_WinPosSendSizeMove: WM_SIZE lParam = MAKELONG(clientW, clientH).
				// Client height excludes the menu bar (NC area in Win32).
				clientW, clientH := getTopLevelClientSize(hctx.MainHWND)
				lParam := uint64(uint16(clientW)) | (uint64(uint16(clientH)) << 16)
				hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{hctx.MainHWND, 0x0005, 0, lParam}) // WM_SIZE
				return
			}
			if evt == wl.EventKey {
				for {
					ke, ok := wlDisplay.PollKey()
					if !ok {
						break
					}
					// ESC closes open menu dropdown
					if ke.Pressed && (ke.VK == 0x1B) && (hctx.OpenMenuIdx >= 0 || hctx.ActivePopupMenu != nil) {
						closePopupMenus()
						requestWindowRepaint(hctx.MainHWND)
						continue
					}
					target := hctx.FocusHwnd
					if target == 0 {
						target = hctx.MainHWND
					}
					if ke.Pressed {
						hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{target, 0x0100, uint64(ke.VK), 0})
						if ke.Char >= 0x20 || ke.Char == '\r' || ke.Char == '\b' || ke.Char == '\t' {
							hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{target, 0x0102, uint64(ke.Char), 0})
						}
					} else {
						hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{target, 0x0101, uint64(ke.VK), 0})
					}
				}
			}
			if evt == wl.EventMouse {
				for {
					me, ok := wlDisplay.PollMouse()
					if !ok {
						break
					}
					ravelog.Logf("[mouse] kind=%d x=%d y=%d button=%d pressed=%v\n", me.Kind, me.X, me.Y, me.Button, me.Pressed)
					// Our custom title bar occupies y=[0, TitleBarH).
					// Menu bar occupies y=[TitleBarH, TitleBarH+menuBarHeight).
					// Client area starts at y=TitleBarH+menuBarHeight.
					var (
						ncTitleTop = int32(0)
						ncMenuTop  int32
						clientTop  = int32(0)
					)
					if wlWindow != nil {
						ncMenuTop = wlWindow.TitleBarH
						clientTop = getMenuClientTop(hctx.MainHWND)
					}
					// Client-relative coordinates for WM_LBUTTON* messages
					clientX := me.X
					clientY := me.Y - clientTop

					// childAt returns the deepest visible window at surface position (sx, sy),
					// or 0 if none. Returns window-relative coordinates via relParam.
					//
					// Priority rules (mimicking Win32 z-order / WM_NCHITTEST):
					//   1. SysTabControl32 only claims clicks inside its tab-strip header
					//      (top 22 px). Clicks in the content area fall through to siblings.
					//   2. Among equal-priority candidates, prefer the window with the
					//      smaller area (most specific / on top visually).
					//   3. Grandchildren of containers (e.g. ReBarWindow32) beat their parent.
					childAt := func(sx, sy int32) (child uint64, relParam uint64) {
						const tabStripH = int32(22) // height of SysTabControl32 header strip
						isContainerClass := func(cn string) bool {
							return cn == "rebarwindow32"
						}
						area := func(c *controlState) int64 { return int64(c.w) * int64(c.h) }
						for chWnd, cs := range hwndChildren {
							if cs.parentHWND != hctx.MainHWND || !cs.visible {
								continue
							}
							if sx < cs.x || sx >= cs.x+cs.w || sy < cs.y || sy >= cs.y+cs.h {
								continue
							}
							// SysTabControl32: only claim the tab-strip header area.
							// Content area is transparent - let siblings underneath handle it.
							if cs.className == "systabcontrol32" && sy >= cs.y+tabStripH {
								continue
							}
							// Grandchildren of container classes beat the container itself.
							if isContainerClass(cs.className) {
								for gcWnd, gcs := range hwndChildren {
									if gcs.parentHWND != chWnd || !gcs.visible {
										continue
									}
									if sx >= gcs.x && sx < gcs.x+gcs.w && sy >= gcs.y && sy < gcs.y+gcs.h {
										if child == 0 || area(gcs) < area(hwndChildren[child]) {
											child = gcWnd
											relParam = uint64(uint16(sx-gcs.x)) | (uint64(uint16(sy-gcs.y)) << 16)
										}
									}
								}
								continue
							}
							// Accept this child if it is more specific than the current winner.
							if child == 0 || area(cs) < area(hwndChildren[child]) {
								child = chWnd
								relParam = uint64(uint16(sx-cs.x)) | (uint64(uint16(sy-cs.y)) << 16)
							}
						}
						return child, relParam
					}
					// routeMouseToChild routes a mouse message to child or hctx.MainHWND.
					// Returns true if routed to a child builtin (no need to queue).
					routeMouseMsg := func(msg uint32, wp uint64, sx, sy int32) {
						targetHWND := hctx.MouseCapture
						var relParam uint64
						if targetHWND == 0 {
							targetHWND, relParam = childAt(sx, sy)
						} else {
							if cs, ok := hwndChildren[targetHWND]; ok {
								rx := uint64(uint16(sx - cs.x))
								ry := uint64(uint16(sy - cs.y))
								relParam = rx | (ry << 16)
							} else {
								relParam = uint64(uint16(sx)) | (uint64(uint16(sy-clientTop)) << 16)
							}
						}
						if targetHWND != 0 {
							_, handled := builtinWndProc(targetHWND, msg, wp, relParam)
							if !handled {
								hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{targetHWND, msg, wp, relParam})
							}
						} else {
							// Fall back to hctx.MainHWND with client-relative coords
							mcp := uint64(uint16(sx)) | (uint64(uint16(sy-clientTop)) << 16)
							hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{hctx.MainHWND, msg, wp, mcp})
						}
					}

					switch me.Kind {
					case 0: // WM_MOUSEMOVE
						if wlWindow != nil && me.Y >= ncMenuTop && me.Y < clientTop && hctx.OpenMenuIdx >= 0 {
							// Hovering menu bar while a menu is open - switch item
							if menuH, ok2 := hwndMenuBar[hctx.MainHWND]; ok2 {
								if md, ok3 := menus[menuH]; ok3 {
									x := int32(4)
									for i, item := range md.items {
										if item.flags&0x0800 != 0 || item.flags&0x0010 == 0 {
											continue
										}
										label, _ := menuTextParts(menuStripAmpersand(item.text))
										if label == "" {
											continue
										}
										if !menuHasRenderableText(label) {
											continue
										}
										tw := menuTextWidth(label) + 12
										if me.X >= x && me.X < x+tw && i != hctx.OpenMenuIdx {
											hctx.OpenMenuIdx = i
											hctx.OpenMenuHwnd = hctx.MainHWND
											showMenuBarPopup(hctx.MainHWND, i)
											requestWindowRepaint(hctx.MainHWND)
										}
										x += tw
									}
								}
							}
						} else if hctx.ActivePopupMenu != nil {
							if me.X < hctx.ActivePopupMenu.X || me.X >= hctx.ActivePopupMenu.X+hctx.ActivePopupMenu.Width ||
								me.Y < hctx.ActivePopupMenu.Y || me.Y >= hctx.ActivePopupMenu.Y+hctx.ActivePopupMenu.Height {
								// outside popup; leave state unchanged until click
							}
						} else if me.Y >= clientTop {
							// Client area mouse move - route to captured/child/hctx.MainHWND
							routeMouseMsg(0x0200, 0, me.X, me.Y)
						}
					case 1: // button press/release
						const btnLeft, btnRight, btnMiddle = 272, 273, 274
						switch me.Button {
						case btnLeft:
							if me.Pressed {
								ravelog.Logf("[click] left press x=%d y=%d ncMenuTop=%d clientTop=%d\n", me.X, me.Y, ncMenuTop, clientTop)

								// Modal dialog intercept: all clicks go to dialog when active
								if hctx.DialogActive {
									bx, by := hctx.DialogBtnX, hctx.DialogBtnY
									bw, bh := hctx.DialogBtnW, hctx.DialogBtnH
									if me.X >= bx && me.X < bx+bw && me.Y >= by && me.Y < by+bh {
										ravelog.Logf("[dialog] OK button clicked, dismissing dialog\n")
										hctx.DialogActive = false
										if wlWindow != nil && hctx.HasBaseFrame {
											hctx.RepaintBuiltin = true
											hctx.FrameReady = true
											commitIfDone()
										} else {
											queuePaint(hctx.MainHWND)
										}
									}
									// Swallow all clicks while dialog is active (modal)
									break
								}

								if wlWindow != nil && me.Y >= ncMenuTop && me.Y < clientTop {
									// ── Menu bar click (non-client) ──
									// Intercept here instead of routing via DefWindowProcW.
									ravelog.Logf("[click] menu bar hit, looking for item\n")
									if menuH, ok2 := hwndMenuBar[hctx.MainHWND]; ok2 {
										if md, ok3 := menus[menuH]; ok3 {
											x := int32(4)
											handled := false
											for i, item := range md.items {
												if item.flags&0x0800 != 0 || item.flags&0x0010 == 0 {
													continue
												}
												label, _ := menuTextParts(menuStripAmpersand(item.text))
												if label == "" {
													continue
												}
												if !menuHasRenderableText(label) {
													continue
												}
												tw := menuTextWidth(label) + 12
												ravelog.Logf("[click] item i=%d label=%q x=%d..%d\n", i, label, x, x+tw)
												if me.X >= x && me.X < x+tw {
													if hctx.OpenMenuIdx == i && hctx.OpenMenuHwnd == hctx.MainHWND {
														closePopupMenus()
													} else {
														hctx.OpenMenuIdx = i
														hctx.OpenMenuHwnd = hctx.MainHWND
														showMenuBarPopup(hctx.MainHWND, i)
													}
													requestWindowRepaint(hctx.MainHWND)
													handled = true
													break
												}
												x += tw
											}
											_ = md
											if !handled {
												closePopupMenus()
												requestWindowRepaint(hctx.MainHWND)
											}
										}
									}
								} else if wlWindow != nil && me.Y >= ncTitleTop && me.Y < ncMenuTop {
									// ── Title bar click (non-client) ── ignore or handle drag
								} else {
									// ── Client area click ──
									clParam := uint64(uint16(clientX)) | (uint64(uint16(clientY)) << 16)
									dropHit := false
									if pm := hctx.ActivePopupMenu; pm != nil {
										if me.X >= pm.X && me.X < pm.X+pm.Width && me.Y >= pm.Y && me.Y < pm.Y+pm.Height {
											itemIdx := int((me.Y - pm.Y) / pm.ItemHeight)
											if itemIdx >= 0 && itemIdx < len(pm.Items) {
												si := pm.Items[itemIdx]
												if si.flags&0x0800 != 0 || si.flags&0x0003 != 0 {
													dropHit = true
												} else {
													cmd := si.id
													if len(resolveMenuItems(si)) == 0 && cmd != 0 {
														target := pm.OwnerHWND
														if target == 0 {
															target = hctx.MainHWND
														}
														hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{target, 0x0111, cmd, 0})
													}
													dropHit = true
													closePopupMenus()
													requestWindowRepaint(hctx.MainHWND)
												}
											}
										}
										if !dropHit {
											closePopupMenus()
											requestWindowRepaint(hctx.MainHWND)
										}
									}
									if !dropHit {
										// Route click to child under cursor or hctx.MainHWND
										hitChild, hitRelParam := childAt(me.X, me.Y)
										if hitChild != 0 {
											// Update focus to clicked child
											if hctx.FocusHwnd != hitChild {
												if hctx.FocusHwnd != 0 {
													hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{hctx.FocusHwnd, 0x0008, uint64(hitChild), 0})
												}
												hctx.FocusHwnd = hitChild
												hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{hitChild, 0x0007, 0, 0})
											}
											_, handled := builtinWndProc(hitChild, 0x0201, 0x0001, hitRelParam)
											if !handled {
												hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{hitChild, 0x0201, 0x0001, hitRelParam})
											}
										} else {
											hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{hctx.MainHWND, 0x0201, 0x0001, clParam})
										}
									}
								}
							} else {
								// Left button release - route to captured window or hit-test
								if me.Y >= clientTop || (wlWindow == nil) {
									routeMouseMsg(0x0202, 0, me.X, me.Y)
								}
							}
						case btnRight:
							if me.Y >= clientTop || wlWindow == nil {
								if me.Pressed {
									routeMouseMsg(0x0204, 0x0002, me.X, me.Y)
								} else {
									routeMouseMsg(0x0205, 0, me.X, me.Y)
								}
							}
						case btnMiddle:
							if me.Y >= clientTop || wlWindow == nil {
								if me.Pressed {
									routeMouseMsg(0x0207, 0x0010, me.X, me.Y)
								} else {
									routeMouseMsg(0x0208, 0, me.X, me.Y)
								}
							}
						}
					case 2: // scroll wheel
						routeMouseMsg(0x020A, uint64(int16(me.AxisVal*-120))<<16, me.X, me.Y)
					}
				}
			}
		}

		dequeueMsg := func() bool {
			if len(hctx.MsgQueue) == 0 {
				return false
			}
			m := hctx.MsgQueue[0]
			hctx.MsgQueue = hctx.MsgQueue[1:]
			if m.message == 0x000F && m.hwnd == hctx.MainHWND {
				// Main update region is consumed once WM_PAINT is dequeued.
				// This prevents synthetic repaint frames from re-posting forever.
				hctx.WinInvalid[hctx.MainHWND] = false
			}
			if pMsg != 0 {
				writeMsg(pMsg, m.hwnd, m.message, m.wParam, m.lParam)
			}
			ctx.SetReturn(1)
			return true
		}

		if wlDisplay == nil {
			if pMsg != 0 {
				writeMsg(pMsg, hctx.MainHWND, 0x12, 0, 0)
			}
			ctx.SetReturn(0)
			return 0
		}

		var lastSyntheticFrameNs int64
		for {
			// 1. Drain already-queued messages.
			checkTimers()
			if dequeueMsg() {
				return 0
			}

			// 2. Non-blocking poll of Wayland socket.
			evt, _ := wlDisplay.Poll()
			if evt != wl.EventNone {
				dispatchWl(evt)
				checkTimers()
				if dequeueMsg() {
					return 0
				}
			}

			// 3. Nothing ready - compute timeout until next timer (or 16ms frame).
			timeoutUs := int64(16000) // 16ms default (60fps synthetic WM_PAINT)
			now := time.Now()
			for _, t := range timerMap {
				d := t.deadline.Sub(now).Microseconds()
				if d < timeoutUs {
					if d < 0 {
						d = 0
					}
					timeoutUs = d
				}
			}

			// 4. Block on Wayland fd until timeout.
			wlFd := wlDisplay.Fd()
			var rfds unix.FdSet
			rfds.Set(wlFd)
			tv := unix.Timeval{Sec: timeoutUs / 1_000_000, Usec: timeoutUs % 1_000_000}
			n, _ := unix.Select(wlFd+1, &rfds, nil, nil, &tv)
			if n > 0 {
				evt2, _ := wlDisplay.Dispatch()
				dispatchWl(evt2)
			}

			// 5. Check timers again after sleep, then post WM_PAINT if queue still empty.
			checkTimers()

			// 5b. Drain any injected input events (from -auto script).
			if wlDisplay.HasPendingInput() {
				dispatchWl(wl.EventKey)
				dispatchWl(wl.EventMouse)
			}

			if dequeueMsg() {
				return 0
			}

			// 6. Synthetic WM_PAINT frame - rate-limited to ~60fps.
			// hctx.MainHWND paints first (fills background), children paint on top.
			// This matches Win32 WS_CLIPCHILDREN ordering: parent → children.
			nowNs := time.Now().UnixNano()
			if nowNs-lastSyntheticFrameNs < 16_000_000 {
				continue
			}
			lastSyntheticFrameNs = nowNs
			var childPaints []uint64
			for h, cs := range hwndChildren {
				if hwndWndProc[h] != 0 && cs.visible && hctx.WinInvalid[h] {
					childPaints = append(childPaints, h)
				}
			}
			if !hctx.WinInvalid[hctx.MainHWND] && len(childPaints) == 0 {
				continue
			}
			sort.Slice(childPaints, func(i, j int) bool { return childPaints[i] < childPaints[j] })
			if hctx.WinInvalid[hctx.MainHWND] {
				queuePaint(hctx.MainHWND)
			}
			for _, h := range childPaints {
				queuePaint(h)
			}
			if dequeueMsg() {
				return 0
			}
		}
	})
	d.RegisterAutoStubHandler(user32, "PeekMessageW", func(ctx *ntapi.TrapContext) uint32 {
		pMsg := ctx.Arg(0)
		// wMsgFilterMin := ctx.Arg(2) // ignored for now
		// wMsgFilterMax := ctx.Arg(3)
		remove := ctx.Arg(4)&0x1 != 0 // PM_REMOVE = 0x0001

		if wlDisplay != nil {
			evt, _ := wlDisplay.Poll()
			if evt != wl.EventNone && evt != wl.EventClose {
				if evt == wl.EventKey {
					for {
						ke, ok := wlDisplay.PollKey()
						if !ok {
							break
						}
						target := hctx.FocusHwnd
						if target == 0 {
							target = hctx.MainHWND
						}
						if ke.Pressed {
							hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{target, 0x0100, uint64(ke.VK), 0})
							if ke.Char >= 0x20 || ke.Char == '\r' || ke.Char == '\b' || ke.Char == '\t' {
								hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{target, 0x0102, uint64(ke.Char), 0})
							}
						} else {
							hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{target, 0x0101, uint64(ke.VK), 0})
						}
					}
				}
				if evt == wl.EventMouse {
					if dispatchWl != nil {
						dispatchWl(evt)
					}
				}
			}
		}

		if len(hctx.MsgQueue) == 0 {
			ctx.SetReturn(0)
			return 0
		}
		m := hctx.MsgQueue[0]
		if remove {
			hctx.MsgQueue = hctx.MsgQueue[1:]
		}
		if pMsg != 0 {
			writeMsg(pMsg, m.hwnd, m.message, m.wParam, m.lParam)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "TranslateMessage", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1) // message processed
		return 0
	})
	d.RegisterAutoStubHandler(user32, "DispatchMessageW", func(ctx *ntapi.TrapContext) uint32 {
		pMsg := ctx.Arg(0)
		if pMsg == 0 {
			ctx.SetReturn(0)
			return 0
		}
		// MSG layout (x64): HWND(8) message(4) pad(4) WPARAM(8) LPARAM(8) ...
		hwnd, _ := mem.Read64(pMsg)
		message, _ := mem.Read32(pMsg + 8)
		wParam, _ := mem.Read64(pMsg + 16)
		lParam, _ := mem.Read64(pMsg + 24)

		// Try built-in control first
		if _, isChild := hwndChildren[hwnd]; isChild {
			result, handled := builtinWndProc(hwnd, message, wParam, lParam)
			if handled {
				// After a WM_PAINT is fully handled (no guest WndProc will call
				// EndPaint), check if we now have a complete frame to commit.
				if message == 0x000F {
					commitIfDone()
				}
				ctx.SetReturn(result)
				return 0
			}
		}

		wndProc, ok := hwndWndProc[hwnd]
		if !ok || wndProc == 0 {
			ravelog.Logf("[dispatch] no WndProc for hwnd=0x%x msg=0x%x\n", hwnd, message)
			ctx.SetReturn(0)
			return 0
		}

		rw, ok := ctx.CPU.(ntapi.RegisterWriter)
		if !ok {
			ctx.SetReturn(0)
			return 0
		}

		ravelog.Logf("[dispatch] hwnd=0x%x msg=0x%x → WndProc=0x%x\n", hwnd, message, wndProc)

		// Stack is already correct: [RSP] = caller's return address,
		// [RSP+8..RSP+0x28] = shadow space. WndProc will RET to caller.
		rw.WriteReg(1, hwnd)            // RCX
		rw.WriteReg(2, uint64(message)) // RDX
		rw.WriteReg(8, wParam)          // R8
		rw.WriteReg(9, lParam)          // R9

		ctx.CPU.SetPC(wndProc)
		ctx.ReturnOverridden = true
		return 0
	})
	// Accelerator table tracking
	// ReactOS: NtUserCreateAcceleratorTable
	type accelEntry struct {
		fVirt byte
		key   uint16
		cmd   uint16
	}
	accelTables := map[uint64][]accelEntry{}
	var nextAccelTable uint64 = 0xac000

	d.RegisterAutoStubHandler(user32, "TranslateAcceleratorW", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL TranslateAcceleratorW(HWND, HACCEL, LPMSG)
		// ReactOS: win32ss/user/ntuser/accelerator.c NtUserTranslateAccelerator
		// Read MSG: {hwnd(8), message(4), wParam(8), lParam(8), time(4), pt.x(4), pt.y(4)}
		hAccel := ctx.Arg(1)
		pMsg := ctx.Arg(2)
		if pMsg == 0 || hAccel == 0 {
			ctx.SetReturn(0)
			return 0
		}
		entries := accelTables[hAccel]
		if len(entries) == 0 {
			ctx.SetReturn(0)
			return 0
		}
		msgID, _ := mem.Read32(pMsg + 8)
		wParam, _ := mem.Read64(pMsg + 12)
		key := uint16(wParam & 0xFFFF)
		const (
			WM_KEYDOWN    = 0x0100
			WM_SYSKEYDOWN = 0x0104
			FVIRTKEY      = 0x01
			FCONTROL      = 0x08
			FALT          = 0x10
			FSHIFT        = 0x04
		)
		if msgID != WM_KEYDOWN && msgID != WM_SYSKEYDOWN {
			ctx.SetReturn(0)
			return 0
		}
		for _, ae := range entries {
			if ae.fVirt&FVIRTKEY != 0 {
				if ae.key == key {
					// match (simplified: we don't check modifier state)
					ctx.SetReturn(1)
					return 0
				}
			} else if uint16(ae.key) == key {
				ctx.SetReturn(1)
				return 0
			}
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CreateAcceleratorTableW", func(ctx *ntapi.TrapContext) uint32 {
		pAccel := ctx.Arg(0)
		nEntries := int(ctx.Arg(1))
		nextAccelTable++
		h := nextAccelTable
		entries := make([]accelEntry, 0, nEntries)
		for i := 0; i < nEntries; i++ {
			base := pAccel + uint64(i)*6
			fv, _ := mem.Read8(base)
			k, _ := mem.Read16(base + 2)
			c, _ := mem.Read16(base + 4)
			entries = append(entries, accelEntry{fVirt: fv, key: k, cmd: c})
		}
		accelTables[h] = entries
		ctx.SetReturn(h)
		return 0
	})
	// DestroyAcceleratorTable
	d.RegisterAutoStubHandler(user32, "DestroyAcceleratorTable", func(ctx *ntapi.TrapContext) uint32 {
		hAccel := ctx.Arg(0)
		delete(accelTables, hAccel)
		ravelog.Logf("[user32] DestroyAcceleratorTable hAccel=0x%x", hAccel)
		ctx.SetReturn(1)
		return 0
	})
	// IsClipboardFormatAvailable - duplicate registration handled later in the clipboard section
	// LoadBitmapW - load bitmap from PE resource, return HBITMAP
	d.RegisterAutoStubHandler(user32, "LoadBitmapW", func(ctx *ntapi.TrapContext) uint32 {
		hInst := ctx.Arg(0)
		nameArg := ctx.Arg(1)
		if nameArg < 0x10000 && mainModule != nil &&
			(hInst == mainModule.BaseAddr || hInst == 0) {
			resID := uint32(nameArg)
			addr, sz, ok2 := peLoadRawResource(mainModule.BaseAddr, mainModule.ResourceDirRVA, 2 /*RT_BITMAP*/, resID)
			if ok2 {
				slots := decodeDIBSlots(addr, sz, 0, 0)
				h := hctx.NextBitmapHandle
				hctx.NextBitmapHandle += 2
				bitmapHandles[h] = &bitmapHandleData{slots: slots}
				ravelog.Logf("[loadbitmap] LoadBitmapW resID=0x%x → handle=0x%x slots=%d\n", resID, h, len(slots))
				ctx.SetReturn(h)
				return 0
			}
		}
		ctx.SetReturn(0) // NULL
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetForegroundWindow", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: win32ss/user/ntuser/focus.c IntGetForegroundWindow
		if hctx.FocusHwnd != 0 {
			ctx.SetReturn(hctx.FocusHwnd)
		} else {
			ctx.SetReturn(hctx.MainHWND)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetForegroundWindow", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: win32ss/user/ntuser/focus.c co_IntSetForegroundWindow
		hctx.FocusHwnd = ctx.Arg(0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "IsWindowVisible", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		if cs, ok := hwndChildren[hwnd]; ok {
			if cs.visible {
				ctx.SetReturn(1)
			} else {
				ctx.SetReturn(0)
			}
			return 0
		}
		// Main window or unknown: assume visible
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "IsWindow", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: win32ss/user/ntuser/window.c NtUserIsWindow
		hwnd := ctx.Arg(0)
		if hwnd == hctx.MainHWND || hwnd == 0x00050000 {
			ctx.SetReturn(1)
			return 0
		}
		if _, ok := hwndChildren[hwnd]; ok {
			ctx.SetReturn(1)
			return 0
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetFocus", func(ctx *ntapi.TrapContext) uint32 {
		prev := hctx.FocusHwnd
		newFocus := ctx.Arg(0)
		if newFocus == prev {
			ctx.SetReturn(prev)
			return 0
		}
		// ReactOS co_UserSetFocus: send WM_KILLFOCUS to old window, WM_SETFOCUS to new.
		if prev != 0 {
			if _, hasGuest := hwndWndProc[prev]; hasGuest {
				hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{prev, 0x0008, newFocus, 0}) // WM_KILLFOCUS
			}
		}
		hctx.FocusHwnd = newFocus
		if newFocus != 0 {
			if _, hasGuest := hwndWndProc[newFocus]; hasGuest {
				hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{newFocus, 0x0007, prev, 0}) // WM_SETFOCUS
			}
		}
		ctx.SetReturn(prev)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetFocus", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(hctx.FocusHwnd)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetCapture", func(ctx *ntapi.TrapContext) uint32 {
		prev := hctx.MouseCapture
		hctx.MouseCapture = ctx.Arg(0)
		ctx.SetReturn(prev)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "ReleaseCapture", func(ctx *ntapi.TrapContext) uint32 {
		hctx.MouseCapture = 0
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "EnableWindow", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		bEnable := ctx.Arg(1)
		wasDisabled := hwndDisabled[hwnd]
		if bEnable == 0 {
			hwndDisabled[hwnd] = true
		} else {
			delete(hwndDisabled, hwnd)
		}
		// Return TRUE if the window was previously disabled
		if wasDisabled {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetTimer", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		id := ctx.Arg(1)
		elapse := ctx.Arg(2)
		proc := ctx.Arg(3)
		if elapse < 10 {
			elapse = 10
		}
		if id == 0 {
			hctx.NextTimerID++
			id = hctx.NextTimerID
		}
		timerMap[id] = &win32Timer{
			id:         id,
			hwnd:       hwnd,
			intervalMs: elapse,
			proc:       proc,
			deadline:   time.Now().Add(time.Duration(elapse) * time.Millisecond),
		}
		ctx.SetReturn(id)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "KillTimer", func(ctx *ntapi.TrapContext) uint32 {
		id := ctx.Arg(1)
		delete(timerMap, id)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "InvalidateRect", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		// Route WM_PAINT to the actual window, not always hctx.MainHWND.
		// Routing Scintilla's own InvalidateRect to hctx.MainHWND causes an infinite
		// repaint loop: hctx.MainHWND erases Scintilla → Scintilla redraws →
		// Scintilla calls InvalidateRect → hctx.MainHWND erases again → loop.
		target := hctx.MainHWND
		if hwnd != 0 && hwnd != hctx.MainHWND {
			if cs, ok := hwndChildren[hwnd]; ok && cs.visible {
				target = hwnd
			} else if _, ok := hwndChildren[hwnd]; ok {
				// Child exists but is invisible: no paint needed.
				ctx.SetReturn(1)
				return 0
			}
		}
		queuePaint(target)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "InvalidateRgn", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		target := hctx.MainHWND
		if hwnd != 0 && hwnd != hctx.MainHWND {
			if cs, ok := hwndChildren[hwnd]; ok && cs.visible {
				target = hwnd
			} else if _, ok := hwndChildren[hwnd]; ok {
				ctx.SetReturn(1)
				return 0
			}
		}
		queuePaint(target)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "ValidateRect", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		if hwnd == 0 {
			hwnd = hctx.MainHWND
		}
		hctx.WinInvalid[hwnd] = false
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "ValidateRgn", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		if hwnd == 0 {
			hwnd = hctx.MainHWND
		}
		hctx.WinInvalid[hwnd] = false
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetUpdateRgn", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		hrgn := ctx.Arg(1)
		if hwnd == 0 {
			hwnd = hctx.MainHWND
		}
		if !hctx.WinInvalid[hwnd] {
			ctx.SetReturn(0) // NULLREGION
			return 0
		}
		// Fill the region with the window's client rect and return SIMPLEREGION
		if hrgn != 0 {
			if cs, ok := hwndChildren[hwnd]; ok {
				gdiMgr.SetRectRgn(hrgn, 0, 0, cs.w, cs.h)
			} else if hwnd == hctx.MainHWND && wlWindow != nil {
				gdiMgr.SetRectRgn(hrgn, 0, 0, wlWindow.Width, wlWindow.Height)
			} else {
				gdiMgr.SetRectRgn(hrgn, 0, 0, 800, 600)
			}
		}
		ctx.SetReturn(2) // SIMPLEREGION
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetUpdateRect", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		pRect := ctx.Arg(1)
		if hwnd == 0 {
			hwnd = hctx.MainHWND
		}
		if !hctx.WinInvalid[hwnd] {
			if pRect != 0 {
				ctx.Mem.Write32(pRect, 0)
				ctx.Mem.Write32(pRect+4, 0)
				ctx.Mem.Write32(pRect+8, 0)
				ctx.Mem.Write32(pRect+12, 0)
			}
			ctx.SetReturn(0)
			return 0
		}
		if pRect != 0 {
			var w, h int32 = 800, 600
			if cs, ok := hwndChildren[hwnd]; ok {
				w, h = cs.w, cs.h
			} else if wlWindow != nil {
				w, h = wlWindow.Width, wlWindow.Height
			}
			ctx.Mem.Write32(pRect, 0)
			ctx.Mem.Write32(pRect+4, 0)
			ctx.Mem.Write32(pRect+8, uint32(w))
			ctx.Mem.Write32(pRect+12, uint32(h))
		}
		ctx.SetReturn(1) // update region is non-empty
		return 0
	})
	d.RegisterAutoStubHandler(user32, "PrintWindow", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL PrintWindow(HWND hwnd, HDC hdcBlt, UINT nFlags)
		hwnd := ctx.Arg(0)
		hdcBlt := ctx.Arg(1)
		nFlags := uint32(ctx.Arg(2))
		ravelog.Logf("[user32] PrintWindow hwnd=0x%x hdc=0x%x flags=0x%x", hwnd, hdcBlt, nFlags)
		ctx.SetReturn(1)
		return 0
	})
	// DrawEdge/DrawFrameControl/DrawFocusRect in user32
	d.RegisterAutoStubHandler(user32, "DrawEdge", func(ctx *ntapi.TrapContext) uint32 {
		if wlWindow == nil {
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
	d.RegisterAutoStubHandler(user32, "DrawFrameControl", func(ctx *ntapi.TrapContext) uint32 {
		if wlWindow == nil {
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
	d.RegisterAutoStubHandler(user32, "DrawFocusRect", func(ctx *ntapi.TrapContext) uint32 {
		if wlWindow == nil {
			ctx.SetReturn(1)
			return 0
		}
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
	d.RegisterAutoStubHandler(user32, "InvertRect", func(ctx *ntapi.TrapContext) uint32 {
		if wlWindow == nil {
			ctx.SetReturn(1)
			return 0
		}
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
	// DrawText/DrawTextEx
	d.RegisterAutoStubHandler(user32, "DrawTextW", func(ctx *ntapi.TrapContext) uint32 {
		if wlWindow == nil {
			ctx.SetReturn(1)
			return 0
		}
		hdc := ctx.Arg(0)
		lpStr := ctx.Arg(1)
		nCount := int(int32(ctx.Arg(2)))
		lpRect := ctx.Arg(3)
		uFormat := uint32(ctx.Arg(4))
		dc := getDC(hdc)
		text := readGuestUTF16(lpStr)
		if nCount >= 0 && nCount < len(text) {
			text = text[:nCount]
		}
		if lpRect != 0 {
			l, _ := mem.Read32(lpRect)
			t, _ := mem.Read32(lpRect + 4)
			r, _ := mem.Read32(lpRect + 8)
			b, _ := mem.Read32(lpRect + 12)
			// DT_CALCRECT=0x400 - just return text height
			if uFormat&0x400 != 0 {
				f := dc.Font
				if f == nil {
					f = gdi.DefaultFont()
				}
				ctx.Mem.Write32(lpRect+12, uint32(int32(t)+f.CellHeight))
				ctx.SetReturn(uint64(f.CellHeight))
				return 0
			}
			// Center horizontally (DT_CENTER=1) or right (DT_RIGHT=2)
			x := int32(l) + 2
			y := int32(t)
			f := dc.Font
			if f == nil {
				f = gdi.DefaultFont()
			}
			w := int32(r) - int32(l)
			tw := int32(len([]rune(text))) * f.AveCharWidth
			if uFormat&0x1 != 0 {
				x = int32(l) + (w-tw)/2
			}
			if uFormat&0x2 != 0 {
				x = int32(r) - tw - 2
			}
			// DT_VCENTER=4: vertically center
			if uFormat&0x4 != 0 {
				h := int32(b) - int32(t)
				y = int32(t) + (h-f.CellHeight)/2
			}
			// ETO_CLIPPED on the rect
			oldClip := [4]int32{dc.ClipX0, dc.ClipY0, dc.ClipX1, dc.ClipY1}
			dc.ClipX0 = int32(l) + dc.OriginX
			dc.ClipY0 = int32(t) + dc.OriginY
			dc.ClipX1 = int32(r) + dc.OriginX
			dc.ClipY1 = int32(b) + dc.OriginY
			dc.TextOut(x, y, text, false)
			dc.ClipX0, dc.ClipY0, dc.ClipX1, dc.ClipY1 = oldClip[0], oldClip[1], oldClip[2], oldClip[3]
			ctx.SetReturn(uint64(f.CellHeight))
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "DrawTextExW", func(ctx *ntapi.TrapContext) uint32 {
		if wlWindow == nil {
			ctx.SetReturn(1)
			return 0
		}
		// Delegate to DrawTextW implementation (same first 4 args + format)
		hdc := ctx.Arg(0)
		lpStr := ctx.Arg(1)
		nCount := int(int32(ctx.Arg(2)))
		lpRect := ctx.Arg(3)
		uFormat := uint32(ctx.Arg(4))
		dc := getDC(hdc)
		text := readGuestUTF16(lpStr)
		if nCount >= 0 && nCount < len(text) {
			text = text[:nCount]
		}
		f := dc.Font
		if f == nil {
			f = gdi.DefaultFont()
		}
		if lpRect != 0 {
			l, _ := mem.Read32(lpRect)
			t, _ := mem.Read32(lpRect + 4)
			r, _ := mem.Read32(lpRect + 8)
			x := int32(l) + 2
			y := int32(t)
			tw := int32(len([]rune(text))) * f.AveCharWidth
			w := int32(r) - int32(l)
			if uFormat&0x1 != 0 {
				x = int32(l) + (w-tw)/2
			}
			if uFormat&0x2 != 0 {
				x = int32(r) - tw - 2
			}
			dc.TextOut(x, y, text, false)
			ctx.SetReturn(uint64(f.CellHeight))
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "TabbedTextOutW", func(ctx *ntapi.TrapContext) uint32 {
		if wlWindow == nil {
			ctx.SetReturn(0)
			return 0
		}
		dc := getDC(ctx.Arg(0))
		x := int32(ctx.Arg(1))
		y := int32(ctx.Arg(2))
		lpStr := ctx.Arg(3)
		nCount := int(ctx.Arg(4))
		text := readGuestUTF16(lpStr)
		if nCount > 0 && nCount < len(text) {
			text = text[:nCount]
		}
		dc.TextOut(x, y, text, false)
		f := dc.Font
		if f == nil {
			f = gdi.DefaultFont()
		}
		w := int32(len([]rune(text))) * f.AveCharWidth
		ctx.SetReturn(uint64(uint32(f.CellHeight)<<16 | uint32(w)))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GrayStringW", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL GrayStringW(HDC hDC, HBRUSH hBrush, GRAYSTRINGPROC lpOutputFunc, LPARAM lpData, int nCount, int X, int Y, int nWidth, int nHeight)
		hdc := ctx.Arg(0)
		lpData := ctx.Arg(3)
		nCount := int32(ctx.Arg(4))
		x := int32(ctx.Arg(5))
		y := int32(ctx.Arg(6))
		dc := getDC(hdc)
		if dc != nil && dc.Target != nil && lpData != 0 && nCount > 0 {
			txt := readGuestUTF16N(lpData, int(nCount))
			oldColor := dc.TextColor
			dc.TextColor = 0x808080
			dc.TextOut(x, y, txt, false)
			dc.TextColor = oldColor
		}
		ctx.SetReturn(1)
		return 0
	})
	// Scroll bars
	d.RegisterAutoStubHandler(user32, "GetScrollInfo", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		nBar := int(ctx.Arg(1))
		psi := ctx.Arg(2)
		if psi == 0 {
			ctx.SetReturn(0)
			return 0
		}
		cbSize, _ := mem.Read32(psi)
		if cbSize < 28 {
			ctx.SetReturn(0)
			return 0
		}
		fMask, _ := mem.Read32(psi + 4)
		si := win32.ScrollInfo{}
		win32.GetScrollInfo(hwnd, nBar, &si, uint32(fMask))
		if uint32(fMask)&win32.SIF_RANGE != 0 {
			ctx.Mem.Write32(psi+8, uint32(si.Min))
			ctx.Mem.Write32(psi+12, uint32(si.Max))
		}
		if uint32(fMask)&win32.SIF_PAGE != 0 {
			ctx.Mem.Write32(psi+16, si.Page)
		}
		if uint32(fMask)&win32.SIF_POS != 0 {
			ctx.Mem.Write32(psi+20, uint32(si.Pos))
		}
		if uint32(fMask)&win32.SIF_TRACKPOS != 0 {
			ctx.Mem.Write32(psi+24, uint32(si.TrackPos))
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetScrollInfo", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		nBar := int(ctx.Arg(1))
		psi := ctx.Arg(2)
		if psi == 0 {
			ctx.SetReturn(0)
			return 0
		}
		cbSize, _ := mem.Read32(psi)
		if cbSize < 28 {
			ctx.SetReturn(0)
			return 0
		}
		fMask, _ := mem.Read32(psi + 4)
		si := win32.ScrollInfo{}
		min32, _ := mem.Read32(psi + 8)
		si.Min = int32(min32)
		max32, _ := mem.Read32(psi + 12)
		si.Max = int32(max32)
		page32, _ := mem.Read32(psi + 16)
		si.Page = page32
		pos32, _ := mem.Read32(psi + 20)
		si.Pos = int32(pos32)
		pos := win32.SetScrollInfo(hwnd, nBar, &si, uint32(fMask))
		requestWindowRepaint(hwnd)
		ctx.SetReturn(uint64(pos))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetScrollPos", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		nBar := int(ctx.Arg(1))
		ctx.SetReturn(uint64(win32.GetScrollPos(hwnd, nBar)))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetScrollPos", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		nBar := int(ctx.Arg(1))
		pos := int32(ctx.Arg(2))
		prev := win32.SetScrollPos(hwnd, nBar, pos)
		requestWindowRepaint(hwnd)
		ctx.SetReturn(uint64(prev))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetScrollRange", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		nBar := int(ctx.Arg(1))
		pMin := ctx.Arg(2)
		pMax := ctx.Arg(3)
		mn, mx := win32.GetScrollRange(hwnd, nBar)
		if pMin != 0 {
			ctx.Mem.Write32(pMin, uint32(mn))
		}
		if pMax != 0 {
			ctx.Mem.Write32(pMax, uint32(mx))
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetScrollRange", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		nBar := int(ctx.Arg(1))
		mn := int32(ctx.Arg(2))
		mx := int32(ctx.Arg(3))
		win32.SetScrollRange(hwnd, nBar, mn, mx)
		requestWindowRepaint(hwnd)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "ShowScrollBar", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		wBar := int32(ctx.Arg(1))
		bShow := ctx.Arg(2) != 0
		ravelog.Logf("[user32] ShowScrollBar hwnd=0x%x bar=%d show=%v\n", hwnd, wBar, bShow)
		requestWindowRepaint(hwnd)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "EnableScrollBar", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		wSBflags := uint32(ctx.Arg(1))
		wArrows := uint32(ctx.Arg(2))
		ravelog.Logf("[user32] EnableScrollBar hwnd=0x%x flags=0x%x arrows=0x%x\n", hwnd, wSBflags, wArrows)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "ScrollWindow", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		queuePaint(hwnd)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "ScrollWindowEx", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: win32ss/user/ntuser/scrollex.c NtUserScrollWindowEx
		hwnd := ctx.Arg(0)
		// dx := int32(ctx.Arg(1))
		// dy := int32(ctx.Arg(2))
		// prcScroll := ctx.Arg(3) // nullable RECT
		// prcClip := ctx.Arg(4)   // nullable RECT
		// hrgnUpdate := ctx.Arg(5)
		prcUpdate := ctx.Arg(6)
		// flags := ctx.Arg(7) // SW_SCROLLCHILDREN | SW_INVALIDATE | SW_ERASE
		// Write update rect if requested (full client area)
		if prcUpdate != 0 {
			if cs, ok := hwndChildren[hwnd]; ok {
				mem.Write32(prcUpdate, 0)
				mem.Write32(prcUpdate+4, 0)
				mem.Write32(prcUpdate+8, uint32(cs.w))
				mem.Write32(prcUpdate+12, uint32(cs.h))
			}
		}
		queuePaint(hwnd)
		ctx.SetReturn(1) // SIMPLEREGION
		return 0
	})
	d.RegisterAutoStubHandler(user32, "ScrollDC", func(ctx *ntapi.TrapContext) uint32 {
		hDC := ctx.Arg(0)
		dx := int32(ctx.Arg(1))
		dy := int32(ctx.Arg(2))
		lprcUpdate := ctx.Arg(6)
		if lprcUpdate != 0 {
			mem.Write32(lprcUpdate, 0)
			mem.Write32(lprcUpdate+4, 0)
			mem.Write32(lprcUpdate+8, 0)
			mem.Write32(lprcUpdate+12, 0)
		}
		ravelog.Logf("[user32] ScrollDC hdc=0x%x dx=%d dy=%d\n", hDC, dx, dy)
		ctx.SetReturn(1)
		return 0
	})
	// Window region
	d.RegisterAutoStubHandler(user32, "SetWindowRgn", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: win32ss/user/ntuser/winpos.c co_WinPosSetWindowRgn
		hwnd := ctx.Arg(0)
		hRgn := ctx.Arg(1)
		if hRgn != 0 {
			hwndWindowRgn[hwnd] = hRgn
		} else {
			delete(hwndWindowRgn, hwnd)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetWindowRgn", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0 // ERROR - no window region set
	})
	d.RegisterAutoStubHandler(user32, "GetWindowRgnBox", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		lprc := ctx.Arg(1)
		if _, ok := hwndWindowRgn[hwnd]; ok && lprc != 0 {
			if cs, ok2 := hwndChildren[hwnd]; ok2 {
				mem.Write32(lprc, 0)
				mem.Write32(lprc+4, 0)
				mem.Write32(lprc+8, uint32(cs.w))
				mem.Write32(lprc+12, uint32(cs.h))
				ctx.SetReturn(1)
				return 0
			}
		}
		ctx.SetReturn(0)
		return 0
	})
	// Caret - ReactOS: win32ss/user/ntuser/caret.c
	d.RegisterAutoStubHandler(user32, "CreateCaret", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		hBitmap := ctx.Arg(1)
		w := int32(ctx.Arg(2))
		h := int32(ctx.Arg(3))
		if w == 0 {
			w = 1 // SM_CXBORDER
		}
		if h == 0 {
			h = 20
		}
		_ = hBitmap
		hctx.CaretHwnd = hwnd
		hctx.CaretWidth = w
		hctx.CaretHeight = h
		hctx.CaretX = 0
		hctx.CaretY = 0
		hctx.CaretVisible = false
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "DestroyCaret", func(ctx *ntapi.TrapContext) uint32 {
		hctx.CaretHwnd = 0
		hctx.CaretVisible = false
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "ShowCaret", func(ctx *ntapi.TrapContext) uint32 {
		hctx.CaretVisible = true
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "HideCaret", func(ctx *ntapi.TrapContext) uint32 {
		hctx.CaretVisible = false
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetCaretPos", func(ctx *ntapi.TrapContext) uint32 {
		p := ctx.Arg(0)
		if p != 0 {
			ctx.Mem.Write32(p, uint32(hctx.CaretX))
			ctx.Mem.Write32(p+4, uint32(hctx.CaretY))
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetCaretPos", func(ctx *ntapi.TrapContext) uint32 {
		hctx.CaretX = int32(ctx.Arg(0))
		hctx.CaretY = int32(ctx.Arg(1))
		ctx.SetReturn(1)
		return 0
	})
	caretBlinkTime := uint32(530)
	d.RegisterAutoStubHandler(user32, "GetCaretBlinkTime", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(caretBlinkTime))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetCaretBlinkTime", func(ctx *ntapi.TrapContext) uint32 {
		newTime := uint32(ctx.Arg(0))
		if newTime > 0 {
			caretBlinkTime = newTime
		}
		ctx.SetReturn(1)
		return 0
	})
	// Window geometry helpers
	d.RegisterAutoStubHandler(user32, "AdjustWindowRect", func(ctx *ntapi.TrapContext) uint32 {
		pRect := ctx.Arg(0)
		style := uint32(ctx.Arg(1))
		hasMenu := ctx.Arg(2) != 0
		if pRect != 0 {
			l, _ := mem.Read32(pRect)
			t, _ := mem.Read32(pRect + 4)
			r, _ := mem.Read32(pRect + 8)
			b, _ := mem.Read32(pRect + 12)
			rc := win32.Rect{Left: int32(l), Top: int32(t), Right: int32(r), Bottom: int32(b)}
			win32.AdjustWindowRectEx(&rc, style, hasMenu, 0)
			ctx.Mem.Write32(pRect, uint32(rc.Left))
			ctx.Mem.Write32(pRect+4, uint32(rc.Top))
			ctx.Mem.Write32(pRect+8, uint32(rc.Right))
			ctx.Mem.Write32(pRect+12, uint32(rc.Bottom))
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "AdjustWindowRectEx", func(ctx *ntapi.TrapContext) uint32 {
		pRect := ctx.Arg(0)
		style := uint32(ctx.Arg(1))
		hasMenu := ctx.Arg(2) != 0
		exStyle := uint32(ctx.Arg(3))
		if pRect != 0 {
			l, _ := mem.Read32(pRect)
			t, _ := mem.Read32(pRect + 4)
			r, _ := mem.Read32(pRect + 8)
			b, _ := mem.Read32(pRect + 12)
			rc := win32.Rect{Left: int32(l), Top: int32(t), Right: int32(r), Bottom: int32(b)}
			win32.AdjustWindowRectEx(&rc, style, hasMenu, exStyle)
			ctx.Mem.Write32(pRect, uint32(rc.Left))
			ctx.Mem.Write32(pRect+4, uint32(rc.Top))
			ctx.Mem.Write32(pRect+8, uint32(rc.Right))
			ctx.Mem.Write32(pRect+12, uint32(rc.Bottom))
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "WindowFromPoint", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(hctx.MainHWND)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "ChildWindowFromPoint", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(ctx.Arg(0))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "ChildWindowFromPointEx", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(ctx.Arg(0))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "RealChildWindowFromPoint", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(ctx.Arg(0))
		return 0
	})
	// childrenOf returns HWND slice of children whose parent matches p, sorted ascending.
	childrenOf := func(p uint64) []uint64 {
		var out []uint64
		for h, cs := range hwndChildren {
			if cs.parentHWND == p {
				out = append(out, h)
			}
		}
		sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
		return out
	}

	d.RegisterAutoStubHandler(user32, "GetNextWindow", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: GetNextWindow is GetWindow(hwnd, cmd)
		// GW_HWNDNEXT=2, GW_HWNDPREV=3
		hwnd := ctx.Arg(0)
		cmd := ctx.Arg(1)
		cs, ok := hwndChildren[hwnd]
		if !ok {
			ctx.SetReturn(0)
			return 0
		}
		siblings := childrenOf(cs.parentHWND)
		idx := -1
		for i, h := range siblings {
			if h == hwnd {
				idx = i
				break
			}
		}
		if idx < 0 {
			ctx.SetReturn(0)
			return 0
		}
		switch cmd {
		case 2: // GW_HWNDNEXT
			if idx+1 < len(siblings) {
				ctx.SetReturn(siblings[idx+1])
			} else {
				ctx.SetReturn(0)
			}
		case 3: // GW_HWNDPREV
			if idx > 0 {
				ctx.SetReturn(siblings[idx-1])
			} else {
				ctx.SetReturn(0)
			}
		default:
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetTopWindow", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: win32ss/user/ntuser/window.c NtUserGetTopWindow
		// Returns the first child window (top of Z-order) of the given parent.
		// If hwnd==0, use the desktop window.
		hwnd := ctx.Arg(0)
		if hwnd == 0 {
			hwnd = 0x00050000 // desktop
		}
		kids := childrenOf(hwnd)
		// Also treat MainHWND's children as top-level for desktop queries.
		if len(kids) == 0 && (hwnd == 0x00050000 || hwnd == hctx.MainHWND) {
			kids = childrenOf(hctx.MainHWND)
		}
		if len(kids) > 0 {
			ctx.SetReturn(kids[0])
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetWindow", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: win32ss/user/ntuser/window.c NtUserGetWindow
		hwnd := ctx.Arg(0)
		cmd := ctx.Arg(1)
		const (
			gwHWNDFIRST = 0
			gwHWNDLAST  = 1
			gwHWNDNEXT  = 2
			gwHWNDPREV  = 3
			gwOWNER     = 4
			gwCHILD     = 5
		)
		switch cmd {
		case gwCHILD:
			kids := childrenOf(hwnd)
			if len(kids) > 0 {
				ctx.SetReturn(kids[0])
			} else {
				ctx.SetReturn(0)
			}
		case gwOWNER:
			// For child windows, the owner is the parent. For top-level, 0.
			if cs, ok := hwndChildren[hwnd]; ok {
				ctx.SetReturn(cs.parentHWND)
			} else {
				ctx.SetReturn(0)
			}
		case gwHWNDNEXT, gwHWNDPREV, gwHWNDFIRST, gwHWNDLAST:
			cs, ok := hwndChildren[hwnd]
			if !ok {
				ctx.SetReturn(0)
				return 0
			}
			siblings := childrenOf(cs.parentHWND)
			idx := -1
			for i, h := range siblings {
				if h == hwnd {
					idx = i
					break
				}
			}
			if idx < 0 {
				ctx.SetReturn(0)
				return 0
			}
			switch cmd {
			case gwHWNDNEXT:
				if idx+1 < len(siblings) {
					ctx.SetReturn(siblings[idx+1])
				} else {
					ctx.SetReturn(0)
				}
			case gwHWNDPREV:
				if idx > 0 {
					ctx.SetReturn(siblings[idx-1])
				} else {
					ctx.SetReturn(0)
				}
			case gwHWNDFIRST:
				ctx.SetReturn(siblings[0])
			case gwHWNDLAST:
				ctx.SetReturn(siblings[len(siblings)-1])
			}
		default:
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "EnumChildWindows", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL EnumChildWindows(HWND hWndParent, WNDENUMPROC lpEnumFunc, LPARAM lParam)
		// ReactOS: win32ss/user/ntuser/window.c NtUserBuildHwndList
		// Callback: BOOL CALLBACK EnumChildProc(HWND, LPARAM) → RCX=hwnd, RDX=lParam
		hWndParent := ctx.Arg(0)
		lpEnumFunc := ctx.Arg(1)
		lParam := ctx.Arg(2)
		if lpEnumFunc == 0 {
			ctx.SetReturn(0)
			return 0
		}
		parent := hWndParent
		if parent == 0 {
			parent = hctx.MainHWND
		}
		kids := win32.Global.ChildrenOf(parent)
		if len(kids) == 0 {
			ctx.SetReturn(1) // no children = success
			return 0
		}
		rw, ok := ctx.CPU.(ntapi.RegisterWriter)
		rr, ok2 := ctx.CPU.(ntapi.RegisterReader)
		if !ok || !ok2 {
			ctx.SetReturn(1)
			return 0
		}
		rsp := rr.ReadReg(4)
		retAddr, _ := mem.Read64(rsp)
		// Build dispatch queue: each entry calls lpEnumFunc(child_hwnd, lParam)
		queue := make([]syncDispatch, len(kids))
		for i, kid := range kids {
			queue[i] = syncDispatch{
				wndProc: lpEnumFunc,
				hwnd:    kid,
				msg:     lParam,
			}
		}
		hctx.SyncStack = append(hctx.SyncStack, syncDispatchFrame{
			queue:   queue,
			retAddr: retAddr,
			hwnd:    1, // return TRUE
		})
		mem.Write64(rsp, hctx.SyncTrampoline)
		// Start first dispatch
		sd := queue[0]
		hctx.SyncStack[len(hctx.SyncStack)-1].queue = queue[1:]
		rsp -= 8
		mem.Write64(rsp, hctx.SyncTrampoline)
		rw.WriteReg(4, rsp)
		rw.WriteReg(1, sd.hwnd)
		rw.WriteReg(2, uint64(sd.msg))
		rw.WriteReg(8, 0)
		rw.WriteReg(9, 0)
		ctx.CPU.SetPC(sd.wndProc)
		ctx.ReturnOverridden = true
		return 0
	})
	d.RegisterAutoStubHandler(user32, "EnumWindows", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL EnumWindows(WNDENUMPROC lpEnumFunc, LPARAM lParam)
		// ReactOS: NtUserBuildHwndList (all top-level windows)
		lpEnumFunc := ctx.Arg(0)
		lParam := ctx.Arg(1)
		if lpEnumFunc == 0 {
			ctx.SetReturn(0)
			return 0
		}
		all := win32.Global.AllWindows()
		// Filter to top-level only (Parent == 0 or MainHWND)
		var topLevel []uint64
		for _, h := range all {
			wnd := win32.Global.Get(h)
			if wnd != nil && (wnd.Parent == 0 || h == hctx.MainHWND) {
				topLevel = append(topLevel, h)
			}
		}
		if len(topLevel) == 0 {
			ctx.SetReturn(1)
			return 0
		}
		rw, ok := ctx.CPU.(ntapi.RegisterWriter)
		rr, ok2 := ctx.CPU.(ntapi.RegisterReader)
		if !ok || !ok2 {
			ctx.SetReturn(1)
			return 0
		}
		rsp := rr.ReadReg(4)
		retAddr, _ := mem.Read64(rsp)
		queue := make([]syncDispatch, len(topLevel))
		for i, h := range topLevel {
			queue[i] = syncDispatch{wndProc: lpEnumFunc, hwnd: h, msg: lParam}
		}
		hctx.SyncStack = append(hctx.SyncStack, syncDispatchFrame{
			queue:   queue[1:],
			retAddr: retAddr,
			hwnd:    1,
		})
		rsp -= 8
		mem.Write64(rsp, hctx.SyncTrampoline)
		rw.WriteReg(4, rsp)
		rw.WriteReg(1, queue[0].hwnd)
		rw.WriteReg(2, uint64(queue[0].msg))
		rw.WriteReg(8, 0)
		rw.WriteReg(9, 0)
		ctx.CPU.SetPC(queue[0].wndProc)
		ctx.ReturnOverridden = true
		return 0
	})
	lockedUpdateHwnd := uint64(0)
	d.RegisterAutoStubHandler(user32, "LockWindowUpdate", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		if hwnd == 0 {
			lockedUpdateHwnd = 0
		} else {
			if lockedUpdateHwnd != 0 && lockedUpdateHwnd != hwnd {
				ctx.SetReturn(0)
				return 0
			}
			lockedUpdateHwnd = hwnd
		}
		ctx.SetReturn(1)
		return 0
	})
	// Dialog functions

	// DialogBoxParamW: modal dialog.
	// Full implementation would load the template, create controls, run a modal loop.
	// For now: allocate an HWND, call dlgProc(WM_INITDIALOG) via syncDispatch,
	// then return IDCANCEL (2). This lets dialog init code run.
	d.RegisterAutoStubHandler(user32, "DialogBoxParamW", func(ctx *ntapi.TrapContext) uint32 {
		// hInstance := ctx.Arg(0)
		lpTemplate := ctx.Arg(1)
		hWndParent := ctx.Arg(2)
		lpDialogFunc := ctx.Arg(3)
		dwInitParam := ctx.Arg(4)

		templateName := ""
		if lpTemplate < 0x10000 {
			templateName = fmt.Sprintf("#%d", lpTemplate)
		} else {
			templateName = readGuestUTF16(lpTemplate)
		}
		ravelog.Logf("[dialog] DialogBoxParamW template=%s parent=0x%x dlgProc=0x%x initParam=0x%x\n",
			templateName, hWndParent, lpDialogFunc, dwInitParam)

		if lpDialogFunc == 0 {
			ctx.SetReturn(0)
			return 0
		}

		// Allocate an HWND for the dialog
		dlgHwnd := hwndAlloc()
		hwndChildren[dlgHwnd] = &controlState{
			className:  "DialogBox",
			parentHWND: hWndParent,
			visible:    true,
		}

		// Send WM_INITDIALOG synchronously via trampoline
		rw, ok := ctx.CPU.(ntapi.RegisterWriter)
		rr, ok2 := ctx.CPU.(ntapi.RegisterReader)
		if ok && ok2 && lpDialogFunc != 0 {
			rsp := rr.ReadReg(4) // RSP
			retAddr, _ := mem.Read64(rsp)
			hctx.SyncStack = append(hctx.SyncStack, syncDispatchFrame{
				queue:               nil,
				retAddr:             retAddr,
				hwnd:                2, // IDCANCEL
				returnWndProcResult: false,
			})
			mem.Write64(rsp, hctx.SyncTrampoline)

			// Set up WM_INITDIALOG call: dlgProc(hwnd, WM_INITDIALOG, wParam=focus, lParam=initParam)
			rw.WriteReg(1, dlgHwnd)     // RCX = hDlg
			rw.WriteReg(2, 0x0110)      // RDX = WM_INITDIALOG
			rw.WriteReg(8, 0)           // R8 = wParam (focus control, 0 for now)
			rw.WriteReg(9, dwInitParam) // R9 = lParam (init param)
			ctx.CPU.SetPC(lpDialogFunc)
			ctx.ReturnOverridden = true
			return 0
		}

		// Fallback: just return IDCANCEL
		ctx.SetReturn(2) // IDCANCEL
		return 0
	})
	d.RegisterAutoStubHandler(user32, "DialogBoxIndirectParamW", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := hwndAlloc()
		hwndChildren[hwnd] = &controlState{
			className: "DialogBox",
			visible:   true,
		}
		ravelog.Logf("[dialog] DialogBoxIndirectParamW → hwnd=0x%x\n", hwnd)
		ctx.SetReturn(hwnd)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CreateDialogParamW", func(ctx *ntapi.TrapContext) uint32 {
		// HWND CreateDialogParamW(HINSTANCE hInstance, LPCWSTR lpTemplate,
		//   HWND hWndParent, DLGPROC lpDialogFunc, LPARAM dwInitParam)
		// ReactOS: win32ss/user/user32/windows/dialog.c
		lpTemplate := ctx.Arg(1)
		hWndParent := ctx.Arg(2)
		lpDialogFunc := ctx.Arg(3)
		templateName := ""
		if lpTemplate < 0x10000 {
			templateName = fmt.Sprintf("#%d", lpTemplate)
		} else {
			templateName = readGuestUTF16(lpTemplate)
		}
		hwnd := hwndAlloc()
		hwndChildren[hwnd] = &controlState{
			className:  "DialogBox",
			parentHWND: hWndParent,
			visible:    true,
		}
		ravelog.Logf("[dialog] CreateDialogParamW template=%s parent=0x%x dlgProc=0x%x → hwnd=0x%x\n",
			templateName, hWndParent, lpDialogFunc, hwnd)
		ctx.SetReturn(hwnd)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CreateDialogIndirectParamW", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := hwndAlloc()
		hwndChildren[hwnd] = &controlState{
			className: "DialogBox",
			visible:   true,
		}
		ravelog.Logf("[dialog] CreateDialogIndirectParamW → hwnd=0x%x\n", hwnd)
		ctx.SetReturn(hwnd)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "EndDialog", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL EndDialog(HWND hDlg, INT_PTR nResult)
		// ReactOS: win32ss/user/user32/windows/dialog.c
		hDlg := ctx.Arg(0)
		nResult := ctx.Arg(1)
		ravelog.Logf("[dialog] EndDialog hwnd=0x%x result=%d\n", hDlg, nResult)
		// Mark dialog as not visible, clean up
		if cs, ok := hwndChildren[hDlg]; ok {
			cs.visible = false
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetDlgItem", func(ctx *ntapi.TrapContext) uint32 {
		hDlg := ctx.Arg(0)
		nIDDlgItem := ctx.Arg(1)
		// Search child windows of hDlg for matching control ID
		for h, cs := range hwndChildren {
			if cs.parentHWND == hDlg && cs.ctrlID == nIDDlgItem {
				ctx.SetReturn(h)
				return 0
			}
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetDlgCtrlID", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		if cs, ok := hwndChildren[hwnd]; ok {
			ctx.SetReturn(cs.ctrlID)
			return 0
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SendDlgItemMessageW", func(ctx *ntapi.TrapContext) uint32 {
		hDlg := ctx.Arg(0)
		nIDDlgItem := ctx.Arg(1)
		msg := uint32(ctx.Arg(2))
		wParam := ctx.Arg(3)
		lParam := ctx.Arg(4)
		// Find child HWND by control ID, then SendMessage to it
		for h, cs := range hwndChildren {
			if cs.parentHWND == hDlg && cs.ctrlID == nIDDlgItem {
				if result, handled := builtinWndProc(h, msg, wParam, lParam); handled {
					ctx.SetReturn(result)
					return 0
				}
				break
			}
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "MapDialogRect", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL MapDialogRect(HWND hDlg, LPRECT lpRect)
		// ReactOS: win32ss/user/user32/windows/dialog.c
		// Converts dialog units to pixels using font metrics
		// Default: 1 DLU horizontal = avg char width / 4
		//          1 DLU vertical = char height / 8
		// Using 8x16 as default system font metrics
		lpRect := ctx.Arg(1)
		if lpRect != 0 {
			l, _ := mem.Read32(lpRect)
			t, _ := mem.Read32(lpRect + 4)
			r, _ := mem.Read32(lpRect + 8)
			b, _ := mem.Read32(lpRect + 12)
			baseX := uint32(8)  // avg char width
			baseY := uint32(16) // char height
			mem.Write32(lpRect, l*baseX/4)
			mem.Write32(lpRect+4, t*baseY/8)
			mem.Write32(lpRect+8, r*baseX/4)
			mem.Write32(lpRect+12, b*baseY/8)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetDlgItemTextW", func(ctx *ntapi.TrapContext) uint32 {
		hDlg := ctx.Arg(0)
		nIDDlgItem := ctx.Arg(1)
		lpString := ctx.Arg(2)
		nMaxCount := ctx.Arg(3)
		for h, cs := range hwndChildren {
			if cs.parentHWND == hDlg && cs.ctrlID == nIDDlgItem {
				text := cs.text
				runes := []rune(text)
				maxChars := int(nMaxCount) - 1
				if maxChars < 0 {
					maxChars = 0
				}
				if len(runes) > maxChars {
					runes = runes[:maxChars]
				}
				for i, r := range runes {
					mem.Write16(lpString+uint64(i)*2, uint16(r))
				}
				mem.Write16(lpString+uint64(len(runes))*2, 0)
				ctx.SetReturn(uint64(len(runes)))
				_ = h
				return 0
			}
		}
		if lpString != 0 && nMaxCount > 0 {
			mem.Write16(lpString, 0)
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetDlgItemTextW", func(ctx *ntapi.TrapContext) uint32 {
		hDlg := ctx.Arg(0)
		nIDDlgItem := ctx.Arg(1)
		lpString := ctx.Arg(2)
		text := readGuestUTF16(lpString)
		for _, cs := range hwndChildren {
			if cs.parentHWND == hDlg && cs.ctrlID == nIDDlgItem {
				cs.text = text
				ctx.SetReturn(1)
				return 0
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetDlgItemInt", func(ctx *ntapi.TrapContext) uint32 {
		hDlg := ctx.Arg(0)
		nID := ctx.Arg(1)
		lpTranslated := ctx.Arg(2)
		bSigned := ctx.Arg(3) != 0
		for _, cs := range hwndChildren {
			if cs.parentHWND == hDlg && cs.ctrlID == nID {
				var n int64
				_, err := fmt.Sscan(cs.text, &n)
				if lpTranslated != 0 {
					if err == nil {
						mem.Write32(lpTranslated, 1)
					} else {
						mem.Write32(lpTranslated, 0)
					}
				}
				if bSigned {
					ctx.SetReturn(uint64(int32(n)))
				} else {
					ctx.SetReturn(uint64(uint32(n)))
				}
				return 0
			}
		}
		if lpTranslated != 0 {
			mem.Write32(lpTranslated, 0)
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetDlgItemInt", func(ctx *ntapi.TrapContext) uint32 {
		hDlg := ctx.Arg(0)
		nID := ctx.Arg(1)
		val := ctx.Arg(2)
		bSigned := ctx.Arg(3) != 0
		var s string
		if bSigned {
			s = fmt.Sprintf("%d", int32(val))
		} else {
			s = fmt.Sprintf("%d", uint32(val))
		}
		for _, cs := range hwndChildren {
			if cs.parentHWND == hDlg && cs.ctrlID == nID {
				cs.text = s
				ctx.SetReturn(1)
				return 0
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "IsDlgButtonChecked", func(ctx *ntapi.TrapContext) uint32 {
		hDlg := ctx.Arg(0)
		nID := ctx.Arg(1)
		for h, cs := range hwndChildren {
			if cs.parentHWND == hDlg && cs.ctrlID == nID {
				_ = h
				ctx.SetReturn(uint64(cs.checkState))
				return 0
			}
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CheckDlgButton", func(ctx *ntapi.TrapContext) uint32 {
		hDlg := ctx.Arg(0)
		nID := ctx.Arg(1)
		uCheck := uint32(ctx.Arg(2))
		for h, cs := range hwndChildren {
			if cs.parentHWND == hDlg && cs.ctrlID == nID {
				_ = h
				cs.checkState = uCheck
				ctx.SetReturn(1)
				return 0
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CheckRadioButton", func(ctx *ntapi.TrapContext) uint32 {
		hDlg := ctx.Arg(0)
		nIDFirst := ctx.Arg(1)
		nIDLast := ctx.Arg(2)
		nIDCheck := ctx.Arg(3)
		for h, cs := range hwndChildren {
			if cs.parentHWND == hDlg && cs.ctrlID >= nIDFirst && cs.ctrlID <= nIDLast {
				_ = h
				if cs.ctrlID == nIDCheck {
					cs.checkState = 1
				} else {
					cs.checkState = 0
				}
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	// Icons/cursors
	d.RegisterAutoStubHandler(user32, "DrawIconEx", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL DrawIconEx(HDC, int x, int y, HICON, int cxWidth, int cyWidth, UINT istepAnim, HBRUSH flicker, UINT flags)
		// ReactOS: win32ss/user/ntuser/cursoricon.c NtUserDrawIconEx
		// We don't have full icon pixel data, but draw a small filled rect as placeholder.
		hdc := ctx.Arg(0)
		x := int32(ctx.Arg(1))
		y := int32(ctx.Arg(2))
		cxWidth := int32(ctx.Arg(4))
		cyWidth := int32(ctx.Arg(5))
		if cxWidth == 0 {
			cxWidth = 32 // SM_CXICON default
		}
		if cyWidth == 0 {
			cyWidth = 32 // SM_CYICON default
		}
		dc := getDC(hdc)
		if dc != nil && dc.Target != nil {
			dc.Target.FillRect(x, y, x+cxWidth, y+cyWidth, 0x808080) // gray placeholder
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "DrawIcon", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL DrawIcon(HDC hDC, int X, int Y, HICON hIcon)
		// ReactOS: win32ss/user/ntuser/cursoricon.c - calls DrawIconEx internally
		hdc := ctx.Arg(0)
		x := int32(ctx.Arg(1))
		y := int32(ctx.Arg(2))
		// hIcon := ctx.Arg(3)
		dc := getDC(hdc)
		if dc != nil && dc.Target != nil {
			dc.Target.FillRect(x, y, x+32, y+32, 0x808080) // gray placeholder
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "DestroyIcon", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL DestroyIcon(HICON hIcon)
		// ReactOS: win32ss/user/ntuser/cursoricon.c
		hIcon := ctx.Arg(0)
		ravelog.Logf("[user32] DestroyIcon hIcon=0x%x\n", hIcon)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "DestroyCursor", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL DestroyCursor(HCURSOR hCursor)
		// ReactOS: win32ss/user/ntuser/cursoricon.c
		hCursor := ctx.Arg(0)
		ravelog.Logf("[user32] DestroyCursor hCursor=0x%x\n", hCursor)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CopyIcon", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(ctx.Arg(0))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetIconInfo", func(ctx *ntapi.TrapContext) uint32 {
		// ICONINFO: fIcon(BOOL 4), xHotspot(DWORD 4), yHotspot(DWORD 4), hbmMask(HBITMAP 8), hbmColor(HBITMAP 8)
		pInfo := ctx.Arg(1)
		if pInfo != 0 {
			mem.Write32(pInfo, 1)    // fIcon = TRUE
			mem.Write32(pInfo+4, 0)  // xHotspot
			mem.Write32(pInfo+8, 0)  // yHotspot
			mem.Write64(pInfo+16, 0) // hbmMask (NULL)
			mem.Write64(pInfo+24, 0) // hbmColor (NULL)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CreateIconIndirect", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0x8001)
		return 0
	})
	// Misc UI
	d.RegisterAutoStubHandler(user32, "DrawStateW", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL DrawStateW(HDC hdc, HBRUSH hbrFore, DRAWSTATEPROC qfnCallBack,
		//   LPARAM lData, WPARAM wData, int x, int y, int cx, int cy, UINT uFlags)
		// ReactOS: win32ss/user/user32/windows/draw.c
		hdc := ctx.Arg(0)
		_ = hdc
		x := int32(ctx.Arg(5))
		y := int32(ctx.Arg(6))
		ravelog.Logf("[user32] DrawStateW hdc=0x%x x=%d y=%d\n", hdc, x, y)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetSysColorBrush", func(ctx *ntapi.TrapContext) uint32 {
		idx := int(ctx.Arg(0))
		color := uint32(0xD4D0C8)
		if idx >= 0 && idx < len(hctx.SysColors) {
			color = hctx.SysColors[idx]
		}
		ctx.SetReturn(gdiMgr.CreateSolidBrush(color))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "FrameRect", func(ctx *ntapi.TrapContext) uint32 {
		if wlWindow == nil {
			ctx.SetReturn(1)
			return 0
		}
		dc := getDC(ctx.Arg(0))
		pRect := ctx.Arg(1)
		hbr := ctx.Arg(2)
		color := gdiMgr.BrushColor(hbr, hctx.SysColors)
		if pRect != 0 {
			l, _ := mem.Read32(pRect)
			t, _ := mem.Read32(pRect + 4)
			r, _ := mem.Read32(pRect + 8)
			b, _ := mem.Read32(pRect + 12)
			dc.DrawBorder(int32(l), int32(t), int32(r), int32(b), color)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "PaintDesktop", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL PaintDesktop(HDC hdc) - fills with desktop color (COLOR_DESKTOP)
		// ReactOS: win32ss/user/ntuser/painting.c
		hdc := ctx.Arg(0)
		dc := getDC(hdc)
		if dc != nil && dc.Target != nil {
			desktopColor := uint32(0x004E6A) // default teal
			if len(hctx.SysColors) > 1 {
				desktopColor = hctx.SysColors[1] // COLOR_DESKTOP=1
			}
			dc.Target.FillRect(0, 0, dc.Target.Width, dc.Target.Height, desktopColor)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetSystemColorBrush", func(ctx *ntapi.TrapContext) uint32 {
		idx := int(ctx.Arg(0))
		color := uint32(0xD4D0C8)
		if idx >= 0 && idx < len(hctx.SysColors) {
			color = hctx.SysColors[idx]
		}
		ctx.SetReturn(gdiMgr.CreateSolidBrush(color))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetWindowTextW", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		pBuf := ctx.Arg(1)
		nMax := int(ctx.Arg(2))
		title := ""
		if t, ok := hwndTitle[hwnd]; ok {
			title = t
		}
		if pBuf != 0 && nMax > 0 {
			runes := []rune(title)
			n := len(runes)
			if n >= nMax {
				n = nMax - 1
			}
			for i := 0; i < n; i++ {
				ctx.Mem.Write16(pBuf+uint64(i)*2, uint16(runes[i]))
			}
			ctx.Mem.Write16(pBuf+uint64(n)*2, 0)
			ctx.SetReturn(uint64(n))
		} else {
			ctx.SetReturn(uint64(len([]rune(title))))
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "BeginPaint", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		pPaint := ctx.Arg(1)
		if hwnd != 0 {
			hctx.WinInvalid[hwnd] = false
		}
		ox, oy := clientAreaOrigin(hwnd)
		if cs, ok := hwndChildren[hwnd]; ok {
			ravelog.Logf("[paint] BeginPaint hwnd=0x%x class=%q x=%d y=%d w=%d h=%d\n", hwnd, cs.className, cs.x, cs.y, cs.w, cs.h)
		} else {
			ravelog.Logf("[paint] BeginPaint hwnd=0x%x (hctx.MainHWND)\n", hwnd)
		}
		hdc, dc := allocScreenDC(ox, oy)
		ravelog.Logf("[paint] BeginPaint hwnd=0x%x → hdc=0x%x ox=%d oy=%d\n", hwnd, hdc, ox, oy)

		var rcLeft, rcTop, rcRight, rcBottom int32

		if wlWindow != nil && hwnd == hctx.MainHWND {
			wlWindow.ResizeIfNeeded()
			syncScreenSurface()
			w, h := wlWindow.Width, wlWindow.Height
			_ = h
			clientTop := wlWindow.TitleBarH

			// Non-client area: draw menu bar (same filter/width as click-handler and drawMenuOverlay).
			if menuH, ok := hwndMenuBar[hwnd]; ok {
				if md, ok2 := menus[menuH]; ok2 && len(md.items) > 0 {
					clientTop = getMenuClientTop(hwnd)
					wlWindow.DrawRectAbs(0, wlWindow.TitleBarH, w, clientTop, hctx.SysColors[15])
					wlWindow.DrawRectAbs(0, clientTop-1, w, clientTop, hctx.SysColors[16])
					x := int32(4)
					for i, item := range md.items {
						if item.flags&0x0800 != 0 || item.flags&0x0010 == 0 {
							continue // separator or non-popup
						}
						label, _ := menuTextParts(menuStripAmpersand(item.text))
						if label == "" || label == "-" {
							continue
						}
						if !menuHasRenderableText(label) {
							continue
						}
						tw := menuTextWidth(label) + 12
						if hctx.OpenMenuIdx == i && hctx.OpenMenuHwnd == hwnd {
							wlWindow.DrawRectAbs(x, wlWindow.TitleBarH, x+tw, clientTop-1, hctx.SysColors[20])
							ncDrawText(x+4, wlWindow.TitleBarH+3, label, 0x000000, hctx.SysColors[20], true, 12)
						} else {
							ncDrawText(x+4, wlWindow.TitleBarH+3, label, 0x000000, hctx.SysColors[15], true, 12)
						}
						x += tw
					}
				}
			}

			// Do NOT fill the full client area - child windows cover it entirely.
			// Filling here wipes Scintilla/children that painted first in the message queue.
			// ReactOS WM_ERASEBKGND only fills uncovered (non-child) regions.
			rcLeft, rcTop = 0, 0
			rcRight, rcBottom = w, h
			dc.SetClipRect(0, clientTop, w, h+wlWindow.TitleBarH)
		} else if cs, ok := hwndChildren[hwnd]; ok && wlWindow != nil {
			// Child window BeginPaint: fill with class brush
			bgColor := hctx.SysColors[5]
			if a, ok := hctx.HwndClassAtom[hwnd]; ok {
				if brushIdx, ok2 := hctx.ClassBrush[a]; ok2 && brushIdx > 0 && int(brushIdx-1) < len(hctx.SysColors) {
					bgColor = hctx.SysColors[brushIdx-1]
				}
			}
			wlWindow.DrawRectAbs(cs.x, cs.y, cs.x+cs.w, cs.y+cs.h, bgColor)
			rcLeft, rcTop = 0, 0
			rcRight, rcBottom = cs.w, cs.h
			// Clip all GDI drawing to this child's screen rect
			dc.SetClipRect(cs.x, cs.y, cs.x+cs.w, cs.y+cs.h)
			// For Scintilla windows: record sciThis for diagnostics only.
			// Do NOT patch Scintilla internal state - offsets are version-specific
			// and writing wrong fields corrupts state (e.g. sets paintState=painting,
			// making SetPaintState return abandoned and skip all rendering).
		} else {
			rcRight, rcBottom = 800, 600
			if wlWindow != nil {
				rcRight, rcBottom = wlWindow.Width, wlWindow.Height
			}
		}

		if pPaint != 0 {
			ctx.Mem.Write64(pPaint, hdc)                 // hdc
			ctx.Mem.Write32(pPaint+8, 0)                 // fErase = FALSE → paintingAllText = true in Scintilla
			ctx.Mem.Write32(pPaint+12, uint32(rcLeft))   // rcPaint.left
			ctx.Mem.Write32(pPaint+16, uint32(rcTop))    // rcPaint.top
			ctx.Mem.Write32(pPaint+20, uint32(rcRight))  // rcPaint.right
			ctx.Mem.Write32(pPaint+24, uint32(rcBottom)) // rcPaint.bottom
			// Verify reads back correctly
			rv, _ := ctx.Mem.Read32(pPaint + 20)
			rb, _ := ctx.Mem.Read32(pPaint + 24)
			ravelog.Logf("[paint] PAINTSTRUCT pPaint=0x%x right=%d bottom=%d (wrote %d,%d)\n", pPaint, rv, rb, rcRight, rcBottom)
		}
		ctx.SetReturn(hdc)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "EndPaint", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		ravelog.Logf("[paint] EndPaint hwnd=0x%x\n", hwnd)
		if wlWindow != nil {
			paintTree(hwnd)
			// Re-commit after any EndPaint once the base frame is established.
			// Set hctx.RepaintBuiltin so commitIfDone repaints builtin controls
			// (tab strip, status bar) on top of guest-drawn content (Scintilla).
			if hctx.HasBaseFrame {
				hctx.FrameReady = true
				hctx.RepaintBuiltin = true
			}
			commitIfDone()
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetDesktopWindow", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0x00050000) // desktop window handle
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetParent", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		if cs, ok := hwndChildren[hwnd]; ok {
			ctx.SetReturn(cs.parentHWND)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetParent", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(ctx.Arg(0))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetMenu", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		if h, ok := hwndMenuBar[hwnd]; ok {
			ctx.SetReturn(h)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetMenu", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		hMenu := ctx.Arg(1)
		if hMenu == 0 {
			delete(hwndMenuBar, hwnd)
		} else {
			hwndMenuBar[hwnd] = hMenu
		}
		if hwnd == hctx.MainHWND {
			requestWindowRepaint(hwnd)
		}
		_ = menus[hMenu]
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CreateMenu", func(ctx *ntapi.TrapContext) uint32 {
		h := gdiAlloc()
		menus[h] = &menuData{}
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CreatePopupMenu", func(ctx *ntapi.TrapContext) uint32 {
		h := gdiAlloc()
		menus[h] = &menuData{}
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "AppendMenuW", func(ctx *ntapi.TrapContext) uint32 {
		hMenu := ctx.Arg(0)
		flags := uint32(ctx.Arg(1))
		idOrSubmenu := ctx.Arg(2)
		lpNewItem := ctx.Arg(3)
		m, ok := menus[hMenu]
		if !ok {
			ctx.SetReturn(0)
			return 0
		}
		item := menuItem{flags: flags, id: idOrSubmenu}
		const mfSeparator = 0x0800
		const mfPopup = 0x0010
		if flags&mfSeparator == 0 && lpNewItem != 0 {
			item.text = readGuestUTF16(lpNewItem)
		}
		if flags&mfPopup != 0 {
			if sub, ok2 := menus[idOrSubmenu]; ok2 {
				item.submenu = sub.items
			}
		}
		m.items = append(m.items, item)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "InsertMenuW", func(ctx *ntapi.TrapContext) uint32 {
		hMenu := ctx.Arg(0)
		flags := uint32(ctx.Arg(2))
		idOrSubmenu := ctx.Arg(3)
		lpNewItem := ctx.Arg(4)
		m, ok := menus[hMenu]
		if !ok {
			ctx.SetReturn(0)
			return 0
		}
		item := menuItem{flags: flags, id: idOrSubmenu}
		const mfSeparator = 0x0800
		const mfPopup = 0x0010
		if flags&mfSeparator == 0 && lpNewItem != 0 {
			item.text = readGuestUTF16(lpNewItem)
		}
		if flags&mfPopup != 0 {
			if sub, ok2 := menus[idOrSubmenu]; ok2 {
				item.submenu = sub.items
			}
		}
		m.items = append(m.items, item)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "InsertMenuItemW", func(ctx *ntapi.TrapContext) uint32 {
		hMenu := ctx.Arg(0)
		lpmii := ctx.Arg(3) // MENUITEMINFOW*
		m, ok := menus[hMenu]
		if !ok {
			ctx.SetReturn(0)
			return 0
		}
		item := menuItem{}
		if lpmii != 0 {
			// MENUITEMINFOW x64 layout:
			// +0:cbSize(4) +4:fMask(4) +8:fType(4) +12:fState(4) +16:wID(4) +20:pad(4)
			// +24:hSubMenu(8) +32:hbmpChecked(8) +40:hbmpUnchecked(8) +48:dwItemData(8)
			// +56:dwTypeData(8) +64:cch(4) +68:pad(4) +72:hbmpItem(8) = 80 bytes
			fMask, _ := mem.Read32(lpmii + 4)
			fType, _ := mem.Read32(lpmii + 8)
			item.flags = fType
			if fMask&0x40 != 0 { // MIIM_STRING
				dwTypeData, _ := mem.Read64(lpmii + 56)
				if dwTypeData != 0 {
					item.text = readGuestUTF16(dwTypeData)
				}
			}
			if fMask&0x02 != 0 { // MIIM_ID
				wID, _ := mem.Read32(lpmii + 16)
				item.id = uint64(wID)
			}
			if fMask&0x04 != 0 { // MIIM_SUBMENU
				hSub, _ := mem.Read64(lpmii + 24)
				item.id = hSub
				item.flags |= 0x10 // MF_POPUP
				if sub, ok2 := menus[hSub]; ok2 {
					item.submenu = sub.items
				}
			}
		}
		m.items = append(m.items, item)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "DrawMenuBar", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: win32ss/user/ntuser/menu.c NtUserDrawMenuBar
		// Invalidate the menu bar area to trigger a repaint on next WM_PAINT.
		hwnd := ctx.Arg(0)
		if hwnd == hctx.MainHWND || hwnd == 0 {
			requestWindowRepaint(hctx.MainHWND)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "MessageBoxA", func(ctx *ntapi.TrapContext) uint32 {
		textPtr := ctx.Arg(1)
		captionPtr := ctx.Arg(2)
		uType := ctx.Arg(3)
		text := readGuestString(textPtr)
		caption := readGuestString(captionPtr)
		ravelog.Logf("[user32] MessageBoxA: [%s] %s type=0x%x\n", caption, text, uType)
		fmt.Printf("[MessageBoxA] %s: %s\n", caption, text)

		const (
			MB_OK          = 0
			MB_OKCANCEL    = 1
			MB_YESNO       = 4
			MB_YESNOCANCEL = 3
			IDOK           = 1
			IDYES          = 6
			IDCANCEL       = 2
		)

		if ret, ok := hostMessageBox(caption, text, uint32(uType)); ok {
			ctx.SetReturn(uint64(ret))
			return 0
		}

		// Show visual overlay dialog
		hctx.DialogActive = true
		hctx.DialogTitle = caption
		hctx.DialogText = text
		hctx.DialogText2 = ""
		hctx.DialogHwnd = ctx.Arg(0)
		hctx.OpenMenuIdx = -1

		if hctx.WlWindow != nil && hctx.HasBaseFrame {
			hctx.RepaintBuiltin = true
			hctx.FrameReady = true
			hctx.CommitIfDone()
		}

		switch uType & 0xF {
		case MB_YESNO, MB_YESNOCANCEL:
			ctx.SetReturn(IDYES)
		case MB_OKCANCEL:
			ctx.SetReturn(IDOK)
		default:
			ctx.SetReturn(IDOK)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "MessageBoxW", func(ctx *ntapi.TrapContext) uint32 {
		textPtr := ctx.Arg(1)
		captionPtr := ctx.Arg(2)
		uType := ctx.Arg(3)
		text := readGuestUTF16(textPtr)
		caption := readGuestUTF16(captionPtr)
		ravelog.Logf("[user32] MessageBoxW: [%s] %s type=0x%x\n", caption, text, uType)
		fmt.Printf("[MessageBoxW] %s: %s\n", caption, text)

		const (
			MB_OK          = 0
			MB_OKCANCEL    = 1
			MB_YESNO       = 4
			MB_YESNOCANCEL = 3
			IDOK           = 1
			IDYES          = 6
			IDCANCEL       = 2
		)

		if ret, ok := hostMessageBox(caption, text, uint32(uType)); ok {
			ctx.SetReturn(uint64(ret))
			return 0
		}

		// Show visual overlay dialog
		hctx.DialogActive = true
		hctx.DialogTitle = caption
		hctx.DialogText = text
		hctx.DialogText2 = ""
		hctx.DialogHwnd = ctx.Arg(0)
		hctx.OpenMenuIdx = -1

		if hctx.WlWindow != nil && hctx.HasBaseFrame {
			hctx.RepaintBuiltin = true
			hctx.FrameReady = true
			hctx.CommitIfDone()
		}

		// Return appropriate button ID based on type
		switch uType & 0xF {
		case MB_YESNO, MB_YESNOCANCEL:
			ctx.SetReturn(IDYES)
		case MB_OKCANCEL:
			ctx.SetReturn(IDOK)
		default:
			ctx.SetReturn(IDOK)
		}
		return 0
	})
	var currentCursorHandle uint64 = 32512 // IDC_ARROW default
	cursorPosX, cursorPosY := int32(0), int32(0)
	d.RegisterAutoStubHandler(user32, "SetCursor", func(ctx *ntapi.TrapContext) uint32 {
		hCursor := ctx.Arg(0)
		prevCursor := currentCursorHandle
		currentCursorHandle = hCursor
		// Map Windows IDC_ cursor IDs to wp_cursor_shape_v1 shapes.
		if wlDisplay != nil {
			var shape uint32
			switch hCursor {
			case 32512:
				shape = wl.CursorDefault // IDC_ARROW
			case 32513:
				shape = wl.CursorText // IDC_IBEAM
			case 32514:
				shape = wl.CursorProgress // IDC_WAIT (spinner)
			case 32515:
				shape = wl.CursorCrosshair // IDC_CROSS
			case 32642:
				shape = wl.CursorResizeNWSE // IDC_SIZENWSE
			case 32643:
				shape = wl.CursorResizeNESW // IDC_SIZENESW
			case 32644:
				shape = wl.CursorResizeEW // IDC_SIZEWE
			case 32645:
				shape = wl.CursorResizeNS // IDC_SIZENS
			case 32646:
				shape = wl.CursorMove // IDC_SIZEALL
			case 32648:
				shape = wl.CursorNotAllowed // IDC_NO
			case 32649:
				shape = wl.CursorPointer // IDC_HAND
			case 32650:
				shape = wl.CursorProgress // IDC_APPSTARTING
			case 32651:
				shape = wl.CursorHelp // IDC_HELP
			default:
				shape = wl.CursorDefault
			}
			wlDisplay.SetCursorShape(shape)
		}
		ctx.SetReturn(prevCursor)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetCursorPos", func(ctx *ntapi.TrapContext) uint32 {
		p := ctx.Arg(0)
		if p != 0 {
			mx, my := cursorPosX, cursorPosY
			if hctx.WlDisplay != nil {
				mx, my = hctx.WlDisplay.MousePos()
			}
			ctx.Mem.Write32(p, uint32(mx))
			ctx.Mem.Write32(p+4, uint32(my))
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "ScreenToClient", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		pPt := ctx.Arg(1)
		if pPt == 0 {
			ctx.SetReturn(0)
			return 0
		}
		rx, _ := mem.Read32(pPt)
		ry, _ := mem.Read32(pPt + 4)
		x, y := int32(rx), int32(ry)
		if cs, ok := hwndChildren[hwnd]; ok {
			// cs.x/cs.y are surface (absolute) coordinates of the child's top-left.
			x -= cs.x
			y -= cs.y
		} else if hwnd == hctx.MainHWND && wlWindow != nil {
			// hctx.MainHWND client area starts below the NC area (TitleBarH + menuBar).
			y -= getMenuClientTop(hwnd)
		}
		ctx.Mem.Write32(pPt, uint32(x))
		ctx.Mem.Write32(pPt+4, uint32(y))
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "ClientToScreen", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		pPt := ctx.Arg(1)
		if pPt == 0 {
			ctx.SetReturn(0)
			return 0
		}
		rx, _ := mem.Read32(pPt)
		ry, _ := mem.Read32(pPt + 4)
		x, y := int32(rx), int32(ry)
		if cs, ok := hwndChildren[hwnd]; ok {
			x += cs.x
			y += cs.y
		} else if hwnd == hctx.MainHWND && wlWindow != nil {
			y += getMenuClientTop(hwnd)
		}
		ctx.Mem.Write32(pPt, uint32(x))
		ctx.Mem.Write32(pPt+4, uint32(y))
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "MapWindowPoints", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: winpos.c MapWindowPoints
		// Maps nCount points from fromHwnd's client coords to toHwnd's client coords.
		// fromHwnd==0 → screen coords as source; toHwnd==0 → screen coords as dest.
		// clientOrigin returns the surface (absolute) coordinate of a window's client top-left.
		clientOrigin := func(h uint64) (int32, int32) {
			if h == 0 {
				return 0, 0
			}
			if cs, ok := hwndChildren[h]; ok {
				return cs.x, cs.y
			}
			if h == hctx.MainHWND && wlWindow != nil {
				return 0, getMenuClientTop(h)
			}
			return 0, 0
		}
		fromHwnd := ctx.Arg(0)
		toHwnd := ctx.Arg(1)
		pPts := ctx.Arg(2)
		nPts := int(ctx.Arg(3))
		if pPts == 0 || nPts == 0 {
			ctx.SetReturn(0)
			return 0
		}
		fromX, fromY := clientOrigin(fromHwnd)
		toX, toY := clientOrigin(toHwnd)
		dx := fromX - toX
		dy := fromY - toY
		for i := 0; i < nPts; i++ {
			off := pPts + uint64(i)*8
			px, _ := mem.Read32(off)
			py, _ := mem.Read32(off + 4)
			ctx.Mem.Write32(off, uint32(int32(px)+dx))
			ctx.Mem.Write32(off+4, uint32(int32(py)+dy))
		}
		// Return value: low word = dx, high word = dy (signed)
		ret := (uint64(uint16(dx)) & 0xFFFF) | ((uint64(uint16(dy)) & 0xFFFF) << 16)
		ctx.SetReturn(ret)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "MonitorFromWindow", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0x00040001) // dummy monitor handle
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetMonitorInfoW", func(ctx *ntapi.TrapContext) uint32 {
		pInfo := ctx.Arg(1)
		if pInfo != 0 {
			cbSize, _ := ctx.Mem.Read32(pInfo)
			if cbSize >= 40 {
				ctx.Mem.Write32(pInfo+4, 0)     // rcMonitor.left
				ctx.Mem.Write32(pInfo+8, 0)     // rcMonitor.top
				ctx.Mem.Write32(pInfo+12, 1920) // rcMonitor.right
				ctx.Mem.Write32(pInfo+16, 1080) // rcMonitor.bottom
				ctx.Mem.Write32(pInfo+20, 0)    // rcWork.left
				ctx.Mem.Write32(pInfo+24, 0)    // rcWork.top
				ctx.Mem.Write32(pInfo+28, 1920) // rcWork.right
				ctx.Mem.Write32(pInfo+32, 1040) // rcWork.bottom
				ctx.Mem.Write32(pInfo+36, 1)    // dwFlags = MONITORINFOF_PRIMARY
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetMonitorInfoA", func(ctx *ntapi.TrapContext) uint32 {
		pInfo := ctx.Arg(1)
		if pInfo != 0 {
			cbSize, _ := ctx.Mem.Read32(pInfo)
			if cbSize >= 40 {
				ctx.Mem.Write32(pInfo+4, 0)     // rcMonitor.left
				ctx.Mem.Write32(pInfo+8, 0)     // rcMonitor.top
				ctx.Mem.Write32(pInfo+12, 1920) // rcMonitor.right
				ctx.Mem.Write32(pInfo+16, 1080) // rcMonitor.bottom
				ctx.Mem.Write32(pInfo+20, 0)    // rcWork.left
				ctx.Mem.Write32(pInfo+24, 0)    // rcWork.top
				ctx.Mem.Write32(pInfo+28, 1920) // rcWork.right
				ctx.Mem.Write32(pInfo+32, 1040) // rcWork.bottom
				ctx.Mem.Write32(pInfo+36, 1)    // dwFlags = MONITORINFOF_PRIMARY
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SystemParametersInfoW", func(ctx *ntapi.TrapContext) uint32 {
		uiAction := ctx.Arg(0)
		pvParam := ctx.Arg(2)
		w := int32(1920)
		h := int32(1080)
		if wlWindow != nil {
			w = int32(wlWindow.Width)
			h = int32(wlWindow.Height)
		}
		// writeLogFont writes a complete LOGFONTW (92 bytes) at pvParam+off.
		writeLogFont := func(off uint64, name string, height int32) {
			ctx.Mem.Write32(pvParam+off+0, uint32(height)) // lfHeight
			ctx.Mem.Write32(pvParam+off+4, 0)              // lfWidth
			ctx.Mem.Write32(pvParam+off+8, 0)              // lfEscapement
			ctx.Mem.Write32(pvParam+off+12, 0)             // lfOrientation
			ctx.Mem.Write32(pvParam+off+16, 400)           // lfWeight = FW_NORMAL
			ctx.Mem.Write8(pvParam+off+20, 0)              // lfItalic
			ctx.Mem.Write8(pvParam+off+21, 0)              // lfUnderline
			ctx.Mem.Write8(pvParam+off+22, 0)              // lfStrikeOut
			ctx.Mem.Write8(pvParam+off+23, 1)              // lfCharSet = DEFAULT_CHARSET
			ctx.Mem.Write8(pvParam+off+24, 0)              // lfOutPrecision
			ctx.Mem.Write8(pvParam+off+25, 0)              // lfClipPrecision
			ctx.Mem.Write8(pvParam+off+26, 5)              // lfQuality = CLEARTYPE_QUALITY
			ctx.Mem.Write8(pvParam+off+27, 0x22)           // lfPitchAndFamily
			ws := utf16Encode(name)
			for i, wc := range ws {
				ctx.Mem.Write16(pvParam+off+28+uint64(i)*2, wc)
			}
			ctx.Mem.Write16(pvParam+off+28+uint64(len(ws))*2, 0) // null terminator
		}
		switch uiAction {
		case 0x0026: // SPI_GETDRAGFULLWINDOWS
			if pvParam != 0 {
				ctx.Mem.Write32(pvParam, 1) // TRUE
			}
		case 0x0029: // SPI_GETNONCLIENTMETRICS - fill NONCLIENTMETRICSW (504 bytes)
			if pvParam != 0 {
				// NONCLIENTMETRICSW layout (Vista+, 504 bytes):
				// +0x00 cbSize=504, +0x04 iBorderWidth=1, +0x08 iScrollWidth=17, +0x0C iScrollHeight=17
				// +0x10 iCaptionWidth=36, +0x14 iCaptionHeight=36
				// +0x18 lfCaptionFont (92 bytes)
				// +0x74 iSmCaptionWidth=36, +0x78 iSmCaptionHeight=36
				// +0x7C lfSmCaptionFont (92 bytes)
				// +0xD8 iMenuWidth=36, +0xDC iMenuHeight=36
				// +0xE0 lfMenuFont (92 bytes)
				// +0x13C lfStatusFont (92 bytes)
				// +0x198 lfMessageFont (92 bytes)
				// +0x1F4 iPaddedBorderWidth=4
				ctx.Mem.Write32(pvParam+0, 504)    // cbSize
				ctx.Mem.Write32(pvParam+4, 1)      // iBorderWidth
				ctx.Mem.Write32(pvParam+8, 17)     // iScrollWidth
				ctx.Mem.Write32(pvParam+12, 17)    // iScrollHeight
				ctx.Mem.Write32(pvParam+16, 36)    // iCaptionWidth
				ctx.Mem.Write32(pvParam+20, 36)    // iCaptionHeight
				writeLogFont(24, "Segoe UI", -12)  // lfCaptionFont
				ctx.Mem.Write32(pvParam+116, 36)   // iSmCaptionWidth
				ctx.Mem.Write32(pvParam+120, 36)   // iSmCaptionHeight
				writeLogFont(124, "Segoe UI", -12) // lfSmCaptionFont
				ctx.Mem.Write32(pvParam+216, 36)   // iMenuWidth
				ctx.Mem.Write32(pvParam+220, 36)   // iMenuHeight
				writeLogFont(224, "Segoe UI", -12) // lfMenuFont
				writeLogFont(316, "Segoe UI", -12) // lfStatusFont
				writeLogFont(408, "Segoe UI", -12) // lfMessageFont
				ctx.Mem.Write32(pvParam+500, 4)    // iPaddedBorderWidth
			}
		case 0x002B: // SPI_GETMINIMIZEDMETRICS - MINIMIZEDMETRICS (20 bytes)
			if pvParam != 0 {
				ctx.Mem.Write32(pvParam+0, 20)  // cbSize
				ctx.Mem.Write32(pvParam+4, 160) // iWidth
				ctx.Mem.Write32(pvParam+8, 0)   // iHorzGap
				ctx.Mem.Write32(pvParam+12, 0)  // iVertGap
				ctx.Mem.Write32(pvParam+16, 0)  // iArrange
			}
		case 0x001F: // SPI_GETICONTITLELOGFONT - LOGFONTW (92 bytes)
			if pvParam != 0 {
				writeLogFont(0, "Segoe UI", -12)
			}
		case 0x0030: // SPI_GETWORKAREA
			if pvParam != 0 {
				ctx.Mem.Write32(pvParam+0, 0)
				ctx.Mem.Write32(pvParam+4, 0)
				ctx.Mem.Write32(pvParam+8, uint32(w))
				ctx.Mem.Write32(pvParam+12, uint32(h))
			}
		case 0x0048: // SPI_GETANIMATION - ANIMATIONINFO{cbSize=8, iMinAnimate=0}
			if pvParam != 0 {
				ctx.Mem.Write32(pvParam, 8)
				ctx.Mem.Write32(pvParam+4, 0)
			}
		case 0x004A: // SPI_GETFONTSMOOTHING
			if pvParam != 0 {
				ctx.Mem.Write32(pvParam, 1)
			}
		case 0x0067: // SPI_GETMOUSETRAILS
			if pvParam != 0 {
				ctx.Mem.Write32(pvParam, 0)
			}
		case 0x001A: // SPI_GETDESKWALLPAPER
			if pvParam != 0 {
				ctx.Mem.Write16(pvParam, 0)
			}
		case 0x0068: // SPI_GETWHEELSCROLLLINES
			if pvParam != 0 {
				ctx.Mem.Write32(pvParam, 3)
			}
		case 0x006A: // SPI_GETMENUSHOWDELAY
			if pvParam != 0 {
				ctx.Mem.Write32(pvParam, 400)
			}
		case 0x200A: // SPI_GETFONTSMOOTHINGTYPE
			if pvParam != 0 {
				ctx.Mem.Write32(pvParam, 2) // FE_FONTSMOOTHINGCLEARTYPE
			}
		default:
			ravelog.Logf("[spi] SystemParametersInfoW unknown uiAction=0x%x pvParam=0x%x\n", uiAction, pvParam)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetKeyboardLayout", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0x04090409) // en-US
		return 0
	})
	d.RegisterAutoStubHandler(user32, "MapVirtualKeyW", func(ctx *ntapi.TrapContext) uint32 {
		code := uint32(ctx.Arg(0))
		mapType := uint32(ctx.Arg(1))
		var result uint32
		switch mapType {
		case 0: // MAPVK_VK_TO_VSC
			// Common VK → scan code mappings
			vkToScan := map[uint32]uint32{
				0x08: 0x0E, 0x09: 0x0F, 0x0D: 0x1C, 0x10: 0x2A, 0x11: 0x1D, 0x12: 0x38,
				0x14: 0x3A, 0x1B: 0x01, 0x20: 0x39,
				0x25: 0x4B, 0x26: 0x48, 0x27: 0x4D, 0x28: 0x50, // arrows
				0x2D: 0x52, 0x2E: 0x53, 0x24: 0x47, 0x23: 0x4F, 0x21: 0x49, 0x22: 0x51,
			}
			// A-Z
			for vk := uint32(0x41); vk <= 0x5A; vk++ {
				aToZ := []uint32{0x1E, 0x30, 0x2E, 0x20, 0x12, 0x21, 0x22, 0x23, 0x17, 0x24, 0x25, 0x26, 0x32, 0x31, 0x18, 0x19, 0x10, 0x13, 0x1F, 0x14, 0x16, 0x2F, 0x11, 0x2D, 0x15, 0x2C}
				vkToScan[vk] = aToZ[vk-0x41]
			}
			// 0-9
			for vk := uint32(0x30); vk <= 0x39; vk++ {
				vkToScan[vk] = vk - 0x30 + 0x0B
				if vk == 0x30 {
					vkToScan[vk] = 0x0B
				}
			}
			result = vkToScan[code]
		case 1: // MAPVK_VSC_TO_VK
			result = code // simplified
		case 2: // MAPVK_VK_TO_CHAR
			if code >= 0x41 && code <= 0x5A {
				result = code // A-Z → 'A'-'Z'
			} else if code >= 0x30 && code <= 0x39 {
				result = code // 0-9
			} else if code == 0x20 {
				result = 0x20 // space
			}
		}
		ctx.SetReturn(uint64(result))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetKeyState", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: win32ss/user/ntuser/input.c NtUserGetKeyState
		vk := ctx.Arg(0) & 0xFF
		var state int16
		switch vk {
		case 0x10: // VK_SHIFT
			if hctx.WlDisplay != nil && hctx.WlDisplay.ShiftDown() {
				state = -128 // 0xFF80 - high bit = pressed
			}
		case 0x11: // VK_CONTROL
			if hctx.WlDisplay != nil && hctx.WlDisplay.CtrlDown() {
				state = -128
			}
		case 0x12: // VK_MENU (Alt)
			if hctx.WlDisplay != nil && hctx.WlDisplay.AltDown() {
				state = -128
			}
		case 0xA0: // VK_LSHIFT
			if hctx.WlDisplay != nil && hctx.WlDisplay.ShiftDown() {
				state = -128
			}
		case 0xA2: // VK_LCONTROL
			if hctx.WlDisplay != nil && hctx.WlDisplay.CtrlDown() {
				state = -128
			}
		case 0xA4: // VK_LMENU
			if hctx.WlDisplay != nil && hctx.WlDisplay.AltDown() {
				state = -128
			}
		case 0x14: // VK_CAPITAL - toggled state in low bit
			// We don't track CapsLock yet
		}
		ctx.SetReturn(uint64(uint16(state)))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetAsyncKeyState", func(ctx *ntapi.TrapContext) uint32 {
		vk := ctx.Arg(0) & 0xFF
		var state int16
		switch vk {
		case 0x10, 0xA0, 0xA1: // VK_SHIFT, VK_LSHIFT, VK_RSHIFT
			if hctx.WlDisplay != nil && hctx.WlDisplay.ShiftDown() {
				state = -32768 // 0x8000 - currently held
			}
		case 0x11, 0xA2, 0xA3: // VK_CONTROL, VK_LCONTROL, VK_RCONTROL
			if hctx.WlDisplay != nil && hctx.WlDisplay.CtrlDown() {
				state = -32768
			}
		case 0x12, 0xA4, 0xA5: // VK_MENU, VK_LMENU, VK_RMENU
			if hctx.WlDisplay != nil && hctx.WlDisplay.AltDown() {
				state = -32768
			}
		case 0x01: // VK_LBUTTON
			// TODO: track mouse button state
		}
		ctx.SetReturn(uint64(uint16(state)))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetWindowsHookExW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0x00060001) // dummy hook handle
		return 0
	})
	d.RegisterAutoStubHandler(user32, "UnhookWindowsHookEx", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL UnhookWindowsHookEx(HHOOK hhk)
		// ReactOS: win32ss/user/ntuser/hook.c NtUserUnhookWindowsHookEx
		hhk := ctx.Arg(0)
		ravelog.Logf("[user32] UnhookWindowsHookEx hhk=0x%x\n", hhk)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetDpiForWindow", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(96) // standard DPI
		return 0
	})
	d.RegisterAutoStubHandler(user32, "AdjustWindowRectExForDpi", func(ctx *ntapi.TrapContext) uint32 {
		pRect := ctx.Arg(0)
		style := uint32(ctx.Arg(1))
		hasMenu := ctx.Arg(2) != 0
		exStyle := uint32(ctx.Arg(3))
		if pRect != 0 {
			l, _ := mem.Read32(pRect)
			t, _ := mem.Read32(pRect + 4)
			r, _ := mem.Read32(pRect + 8)
			b, _ := mem.Read32(pRect + 12)
			rc := win32.Rect{Left: int32(l), Top: int32(t), Right: int32(r), Bottom: int32(b)}
			win32.AdjustWindowRectEx(&rc, style, hasMenu, exStyle)
			ctx.Mem.Write32(pRect, uint32(rc.Left))
			ctx.Mem.Write32(pRect+4, uint32(rc.Top))
			ctx.Mem.Write32(pRect+8, uint32(rc.Right))
			ctx.Mem.Write32(pRect+12, uint32(rc.Bottom))
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CheckMenuItem", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: win32ss/user/ntuser/menu.c IntCheckMenuItem
		const mfChecked = 0x0008
		item := findMenuItem(ctx.Arg(0), ctx.Arg(1), uint32(ctx.Arg(2)))
		if item == nil {
			ctx.SetReturn(0xFFFFFFFF)
			return 0
		}
		prev := item.flags & mfChecked
		if uint32(ctx.Arg(2))&mfChecked != 0 {
			item.flags |= mfChecked
		} else {
			item.flags &^= mfChecked
		}
		ctx.SetReturn(uint64(prev))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetWindowPlacement", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		lpwndpl := ctx.Arg(1)
		if lpwndpl != 0 && wlWindow != nil {
			// WINDOWPLACEMENT layout (all int32):
			// offset 0: length (uint32)
			// offset 4: flags (uint32)
			// offset 8: showCmd (uint32)
			// offset 12: ptMinPosition.x, offset 16: ptMinPosition.y
			// offset 20: ptMaxPosition.x, offset 24: ptMaxPosition.y
			// offset 28: rcNormalPosition.left, offset 32: top, offset 36: right, offset 40: bottom
			readI32 := func(off uint64) int32 {
				v, _ := mem.Read32(lpwndpl + off)
				return int32(v)
			}
			left := readI32(28)
			top := readI32(32)
			right := readI32(36)
			bottom := readI32(40)
			w := right - left
			h := bottom - top
			if w > 0 && w < 0x7FFF && h > 0 && h < 0x7FFF {
				ravelog.Logf("[placement] SetWindowPlacement hwnd=0x%x → %d,%d %dx%d\n", hwnd, left, top, w, h)
				if hwnd == hctx.MainHWND {
					if wlWindow.Resize(w, h) {
						syncScreenSurface()
					}
					lParam := uint64(uint16(w)) | (uint64(uint16(h)) << 16)
					hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{hwnd, 0x0005, 0, lParam})
					queuePaint(hwnd)
				} else if ci, ok := hwndChildren[hwnd]; ok {
					ci.w = w
					ci.h = h
				}
			}
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(user32, "RedrawWindow", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		// Route WM_PAINT to the actual window, not always hctx.MainHWND.
		// Same reasoning as InvalidateRect: routing child RedrawWindow to hctx.MainHWND
		// creates a paint loop when Scintilla redraws itself.
		if hwnd == 0 || hwnd == hctx.MainHWND {
			queuePaint(hctx.MainHWND)
		} else if cs, ok := hwndChildren[hwnd]; ok && cs.visible {
			queuePaint(hwnd)
		}
		ctx.SetReturn(1)
		return 0
	})

	// LoadMenuW: load menu from PE resources (same as LoadMenuIndirectW essentially)
	d.RegisterAutoStubHandler(user32, "LoadMenuW", func(ctx *ntapi.TrapContext) uint32 {
		menuName := ctx.Arg(1)
		if menuName == 0 {
			ctx.SetReturn(0)
			return 0
		}
		// menuName can be an integer resource ID (MAKEINTRESOURCE) or string pointer
		var resID uint32
		if menuName < 0x10000 {
			resID = uint32(menuName)
		} else {
			// It's a string - try reading it as an integer name
			ctx.SetReturn(0)
			return 0
		}
		menu := peLoadMenuResource(resID)
		if menu == nil {
			ravelog.Logf("[menu] LoadMenuW resID=%d → nil\n", resID)
			ctx.SetReturn(0)
			return 0
		}
		hmenu := uint64(0x60000 + resID)
		menus[hmenu] = menu
		ravelog.Logf("[menu] LoadMenuW resID=%d → hmenu=0x%x items=%d\n", resID, hmenu, len(menu.items))
		for i, item := range menu.items {
			ravelog.Logf("[menu]   [%d] %q flags=0x%x submenu=%d\n", i, item.text, item.flags, len(item.submenu))
		}
		ctx.SetReturn(hmenu)
		return 0
	})

	// RegisterClipboardFormatW/A: maintain name→id map for consistent IDs
	clipFmtByName := make(map[string]uint64)
	var nextClipFmtID uint64 = 0xC000
	registerClipFmt := func(name string) uint64 {
		name = strings.ToLower(name)
		if id, ok := clipFmtByName[name]; ok {
			return id
		}
		nextClipFmtID++
		clipFmtByName[name] = nextClipFmtID
		return nextClipFmtID
	}
	d.RegisterAutoStubHandler(user32, "RegisterClipboardFormatW", func(ctx *ntapi.TrapContext) uint32 {
		name := readGuestUTF16(ctx.Arg(0))
		ctx.SetReturn(registerClipFmt(name))
		return 0
	})

	// DestroyMenu
	d.RegisterAutoStubHandler(user32, "DestroyMenu", func(ctx *ntapi.TrapContext) uint32 {
		hmenu := ctx.Arg(0)
		delete(menus, hmenu)
		ctx.SetReturn(1)
		return 0
	})

	// EnableMenuItem
	d.RegisterAutoStubHandler(user32, "EnableMenuItem", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: win32ss/user/ntuser/menu.c IntEnableMenuItem
		const (
			mfGrayed   = 0x0001
			mfDisabled = 0x0002
		)
		item := findMenuItem(ctx.Arg(0), ctx.Arg(1), uint32(ctx.Arg(2)))
		if item == nil {
			ctx.SetReturn(0xFFFFFFFF)
			return 0
		}
		prev := item.flags & (mfGrayed | mfDisabled)
		item.flags &^= (mfGrayed | mfDisabled)
		item.flags |= uint32(ctx.Arg(2)) & (mfGrayed | mfDisabled)
		ctx.SetReturn(uint64(prev))
		return 0
	})

	// GetMenu / SetMenu
	d.RegisterAutoStubHandler(user32, "GetMenu", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		if hm, ok := hwndMenuBar[hwnd]; ok {
			ctx.SetReturn(hm)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetMenu", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		hmenu := ctx.Arg(1)
		if hmenu != 0 {
			hwndMenuBar[hwnd] = hmenu
		} else {
			delete(hwndMenuBar, hwnd)
		}
		ctx.SetReturn(1)
		return 0
	})

	// GetSubMenu
	d.RegisterAutoStubHandler(user32, "GetSubMenu", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: win32ss/user/ntuser/menu.c IntGetSubMenu
		hmenu := ctx.Arg(0)
		pos := int(ctx.Arg(1))
		m, ok := menus[hmenu]
		if !ok || pos < 0 || pos >= len(m.items) {
			ctx.SetReturn(0)
			return 0
		}
		item := &m.items[pos]
		if len(item.submenu) == 0 {
			ctx.SetReturn(0)
			return 0
		}
		subH := uint64(0x70000 + uint64(pos)<<8 + hmenu&0xFF)
		if _, exists := menus[subH]; !exists {
			menus[subH] = &menuData{items: item.submenu}
		}
		ctx.SetReturn(subH)
		return 0
	})

	// ModifyMenuW: actually modify an existing menu item
	d.RegisterAutoStubHandler(user32, "ModifyMenuW", func(ctx *ntapi.TrapContext) uint32 {
		hMenu := ctx.Arg(0)
		idPos := ctx.Arg(1)
		flags := uint32(ctx.Arg(2))
		idNewItem := ctx.Arg(3)
		lpNewItem := ctx.Arg(4)
		m, ok := menus[hMenu]
		if !ok {
			ctx.SetReturn(0)
			return 0
		}
		const MF_BYPOSITION = 0x0400
		const mfSeparator = 0x0800
		if flags&MF_BYPOSITION != 0 {
			idx := int(idPos)
			if idx >= 0 && idx < len(m.items) {
				m.items[idx].flags = flags
				m.items[idx].id = idNewItem
				if flags&mfSeparator == 0 && lpNewItem != 0 {
					m.items[idx].text = readGuestUTF16(lpNewItem)
				}
			}
		} else {
			for i := range m.items {
				if m.items[i].id == idPos {
					m.items[i].flags = flags
					m.items[i].id = idNewItem
					if flags&mfSeparator == 0 && lpNewItem != 0 {
						m.items[i].text = readGuestUTF16(lpNewItem)
					}
					break
				}
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	// DeleteMenu: remove a menu item by position or ID
	d.RegisterAutoStubHandler(user32, "DeleteMenu", func(ctx *ntapi.TrapContext) uint32 {
		hMenu := ctx.Arg(0)
		idPos := ctx.Arg(1)
		flags := uint32(ctx.Arg(2))
		m, ok := menus[hMenu]
		if !ok {
			ctx.SetReturn(0)
			return 0
		}
		const MF_BYPOSITION = 0x0400
		if flags&MF_BYPOSITION != 0 {
			idx := int(idPos)
			if idx >= 0 && idx < len(m.items) {
				m.items = append(m.items[:idx], m.items[idx+1:]...)
			}
		} else {
			for i := range m.items {
				if m.items[i].id == idPos {
					m.items = append(m.items[:i], m.items[i+1:]...)
					break
				}
			}
		}
		ctx.SetReturn(1)
		return 0
	})

	// GetMenuItemInfoW: fill MENUITEMINFOW for a valid item
	d.RegisterAutoStubHandler(user32, "GetMenuItemInfoW", func(ctx *ntapi.TrapContext) uint32 {
		hMenu := ctx.Arg(0)
		item := ctx.Arg(1)
		byPos := ctx.Arg(2) != 0
		lpmii := ctx.Arg(3)
		if lpmii == 0 {
			ctx.SetReturn(0)
			return 0
		}
		m, ok := menus[hMenu]
		if !ok {
			ctx.SetReturn(0)
			return 0
		}
		var found *menuItem
		if byPos {
			idx := int(item)
			if idx >= 0 && idx < len(m.items) {
				found = &m.items[idx]
			}
		} else {
			for i := range m.items {
				if m.items[i].id == item {
					found = &m.items[i]
					break
				}
			}
		}
		if found == nil {
			ctx.SetReturn(0)
			return 0
		}
		fMask, _ := ctx.Mem.Read32(lpmii + 4)
		const MIIM_TYPE = 0x00000010
		const MIIM_ID = 0x00000002
		const MIIM_STRING = 0x00000040
		if fMask&MIIM_ID != 0 {
			ctx.Mem.Write32(lpmii+16, uint32(found.id))
		}
		if fMask&(MIIM_TYPE|MIIM_STRING) != 0 {
			// x64 MENUITEMINFOW: dwTypeData at +56, cch at +64
			dtPtr, _ := ctx.Mem.Read64(lpmii + 56)
			cch, _ := ctx.Mem.Read32(lpmii + 64)
			if dtPtr != 0 && cch > 0 {
				ws := utf16Encode(found.text)
				limit := int(cch) - 1
				if limit > len(ws) {
					limit = len(ws)
				}
				for i := 0; i < limit; i++ {
					ctx.Mem.Write16(dtPtr+uint64(i)*2, ws[i])
				}
				ctx.Mem.Write16(dtPtr+uint64(limit)*2, 0)
			}
			ctx.Mem.Write32(lpmii+64, uint32(len(utf16Encode(found.text))))
		}
		ctx.SetReturn(1)
		return 0
	})

	// GetMenuState returns flags for menu item (by position or ID)
	d.RegisterAutoStubHandler(user32, "GetMenuState", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: win32ss/user/ntuser/menu.c IntGetMenuState
		item := findMenuItem(ctx.Arg(0), ctx.Arg(1), uint32(ctx.Arg(2)))
		if item == nil {
			ctx.SetReturn(0xFFFFFFFF)
			return 0
		}
		flags := item.flags
		if len(item.submenu) > 0 {
			flags |= uint32(len(item.submenu)) << 8
		}
		ctx.SetReturn(uint64(flags))
		return 0
	})

	// GetMenuItemCount returns number of items in a menu
	d.RegisterAutoStubHandler(user32, "GetMenuItemCount", func(ctx *ntapi.TrapContext) uint32 {
		hmenu := ctx.Arg(0)
		if m, ok := menus[hmenu]; ok {
			ctx.SetReturn(uint64(len(m.items)))
		} else {
			ctx.SetReturn(0xffffffffffffffff) // -1 on error
		}
		return 0
	})

	// SetMenuItemInfoW - reads MENUITEMINFOW and updates menu item data
	d.RegisterAutoStubHandler(user32, "SetMenuItemInfoW", func(ctx *ntapi.TrapContext) uint32 {
		hMenu := ctx.Arg(0)
		item := ctx.Arg(1)
		byPos := ctx.Arg(2) != 0
		lpmii := ctx.Arg(3)
		if lpmii == 0 {
			ctx.SetReturn(0)
			return 0
		}
		m, ok := menus[hMenu]
		if !ok {
			ctx.SetReturn(0)
			return 0
		}
		var found *menuItem
		if byPos {
			idx := int(item)
			if idx >= 0 && idx < len(m.items) {
				found = &m.items[idx]
			}
		} else {
			for i := range m.items {
				if m.items[i].id == item {
					found = &m.items[i]
					break
				}
			}
		}
		if found == nil {
			ctx.SetReturn(0)
			return 0
		}
		fMask, _ := mem.Read32(lpmii + 4)
		const (
			MIIM_STATE  = 0x00000001
			MIIM_ID     = 0x00000002
			MIIM_TYPE   = 0x00000010
			MIIM_STRING = 0x00000040
		)
		if fMask&MIIM_STATE != 0 {
			fState, _ := mem.Read32(lpmii + 12)
			// Update flags: clear state bits and apply new state
			found.flags = (found.flags &^ 0x0F) | (fState & 0x0F)
		}
		if fMask&MIIM_ID != 0 {
			wID, _ := mem.Read32(lpmii + 16)
			found.id = uint64(wID)
		}
		if fMask&(MIIM_TYPE|MIIM_STRING) != 0 {
			dwTypeData, _ := mem.Read64(lpmii + 56)
			if dwTypeData != 0 {
				found.text = readGuestUTF16(dwTypeData)
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetMenuItemInfoA", func(ctx *ntapi.TrapContext) uint32 {
		hMenu := ctx.Arg(0)
		item := ctx.Arg(1)
		byPos := ctx.Arg(2) != 0
		lpmii := ctx.Arg(3)
		if lpmii == 0 {
			ctx.SetReturn(0)
			return 0
		}
		m, ok := menus[hMenu]
		if !ok {
			ctx.SetReturn(0)
			return 0
		}
		var found *menuItem
		if byPos {
			idx := int(item)
			if idx >= 0 && idx < len(m.items) {
				found = &m.items[idx]
			}
		} else {
			for i := range m.items {
				if m.items[i].id == item {
					found = &m.items[i]
					break
				}
			}
		}
		if found == nil {
			ctx.SetReturn(0)
			return 0
		}
		fMask, _ := mem.Read32(lpmii + 4)
		const (
			MIIM_STATE  = 0x00000001
			MIIM_ID     = 0x00000002
			MIIM_TYPE   = 0x00000010
			MIIM_STRING = 0x00000040
		)
		if fMask&MIIM_STATE != 0 {
			fState, _ := mem.Read32(lpmii + 12)
			found.flags = (found.flags &^ 0x0F) | (fState & 0x0F)
		}
		if fMask&MIIM_ID != 0 {
			wID, _ := mem.Read32(lpmii + 16)
			found.id = uint64(wID)
		}
		if fMask&(MIIM_TYPE|MIIM_STRING) != 0 {
			dwTypeData, _ := mem.Read64(lpmii + 56)
			if dwTypeData != 0 {
				found.text = readGuestString(dwTypeData)
			}
		}
		ctx.SetReturn(1)
		return 0
	})

	// GetSystemMenu
	d.RegisterAutoStubHandler(user32, "GetSystemMenu", func(ctx *ntapi.TrapContext) uint32 {
		sysMenu := uint64(0x80000)
		if _, ok := menus[sysMenu]; !ok {
			menus[sysMenu] = &menuData{}
		}
		ctx.SetReturn(sysMenu)
		return 0
	})
	// GetSysColorBrush: return a solid brush for the given system colour index
	d.RegisterAutoStubHandler(user32, "GetSysColorBrush", func(ctx *ntapi.TrapContext) uint32 {
		idx := ctx.Arg(0)
		h := gdiMgr.CreateSolidBrush(getSysColor(uint32(idx)))
		ctx.SetReturn(h)
		return 0
	})
	// FillRect (user32 export, same semantics as gdi32.FillRect)
	d.RegisterAutoStubHandler(user32, "FillRect", func(ctx *ntapi.TrapContext) uint32 {
		if wlWindow == nil {
			ctx.SetReturn(1)
			return 0
		}
		hDC := ctx.Arg(0)
		lpRect := ctx.Arg(1)
		hBrush := ctx.Arg(2)
		if lpRect == 0 {
			ctx.SetReturn(1)
			return 0
		}
		dc := getDC(hDC)
		left, _ := mem.Read32(lpRect)
		top, _ := mem.Read32(lpRect + 4)
		right, _ := mem.Read32(lpRect + 8)
		bottom, _ := mem.Read32(lpRect + 12)
		color := gdiMgr.BrushColor(hBrush, hctx.SysColors)
		dc.FillRect(int32(left), int32(top), int32(right), int32(bottom), color)
		ctx.SetReturn(1)
		return 0
	})
	// SetMenuItemBitmaps: associate bitmaps with menu items
	d.RegisterAutoStubHandler(user32, "SetMenuItemBitmaps", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL SetMenuItemBitmaps(HMENU hMenu, UINT uPosition, UINT uFlags, HBITMAP hBitmapUnchecked, HBITMAP hBitmapChecked)
		// ReactOS: win32ss/user/ntuser/menu.c
		hMenu := ctx.Arg(0)
		uPosition := ctx.Arg(1)
		uFlags := uint32(ctx.Arg(2))
		ravelog.Logf("[user32] SetMenuItemBitmaps menu=0x%x pos=%d flags=0x%x\n", hMenu, uPosition, uFlags)
		ctx.SetReturn(1)
		return 0
	})
	// RemoveMenu: remove a menu item by position or ID
	d.RegisterAutoStubHandler(user32, "RemoveMenu", func(ctx *ntapi.TrapContext) uint32 {
		hMenu := ctx.Arg(0)
		idPos := ctx.Arg(1)
		flags := uint32(ctx.Arg(2))
		m, ok := menus[hMenu]
		if !ok {
			ctx.SetReturn(0)
			return 0
		}
		const MF_BYPOSITION = 0x0400
		if flags&MF_BYPOSITION != 0 {
			idx := int(idPos)
			if idx >= 0 && idx < len(m.items) {
				m.items = append(m.items[:idx], m.items[idx+1:]...)
			}
		} else {
			for i := range m.items {
				if m.items[i].id == idPos {
					m.items = append(m.items[:i], m.items[i+1:]...)
					break
				}
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	// GetMenuStringW: copy menu item text into caller's buffer
	d.RegisterAutoStubHandler(user32, "GetMenuStringW", func(ctx *ntapi.TrapContext) uint32 {
		hMenu := ctx.Arg(0)
		idItem := ctx.Arg(1)
		lpStr := ctx.Arg(2)
		nMaxCount := int(ctx.Arg(3))
		// flags := ctx.Arg(4)  // MF_BYPOSITION or MF_BYCOMMAND
		md, ok := menus[hMenu]
		if !ok || nMaxCount == 0 || lpStr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		for _, item := range md.items {
			if item.id == idItem {
				runes := []rune(item.text)
				n := len(runes)
				if n >= nMaxCount {
					n = nMaxCount - 1
				}
				for i := 0; i < n; i++ {
					mem.Write16(lpStr+uint64(i)*2, uint16(runes[i]))
				}
				mem.Write16(lpStr+uint64(n)*2, 0)
				ctx.SetReturn(uint64(n))
				return 0
			}
		}
		ctx.SetReturn(0)
		return 0
	})

	// FindWindowA: ANSI wrapper - convert strings, return NULL (not found)
	d.RegisterAutoStubHandler(user32, "FindWindowA", func(ctx *ntapi.TrapContext) uint32 {
		wantClass := strings.ToLower(readGuestString(ctx.Arg(0)))
		wantTitle := readGuestString(ctx.Arg(1))
		for h, cs := range hwndChildren {
			if wantClass != "" && strings.ToLower(cs.className) != wantClass {
				continue
			}
			if wantTitle != "" {
				title := cs.text
				if t, ok := hwndTitle[h]; ok {
					title = t
				}
				if title != wantTitle {
					continue
				}
			}
			ctx.SetReturn(h)
			return 0
		}
		ctx.SetReturn(0)
		return 0
	})

	// GetDoubleClickTime/SetDoubleClickTime with mutable state
	doubleClickTime := uint32(500)
	d.RegisterAutoStubHandler(user32, "GetDoubleClickTime", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(doubleClickTime))
		return 0
	})

	// GetMessageA: ANSI wrapper for GetMessageW - delegate to same queue
	d.RegisterAutoStubHandler(user32, "GetMessageA", func(ctx *ntapi.TrapContext) uint32 {
		pMsg := ctx.Arg(0)
		if len(hctx.MsgQueue) > 0 {
			m := hctx.MsgQueue[0]
			hctx.MsgQueue = hctx.MsgQueue[1:]
			if pMsg != 0 {
				writeMsg(pMsg, m.hwnd, m.message, m.wParam, m.lParam)
			}
			ctx.SetReturn(1)
			return 0
		}
		// No messages; return WM_QUIT to avoid infinite spin
		if pMsg != 0 {
			writeMsg(pMsg, hctx.MainHWND, 0x12, 0, 0) // WM_QUIT
		}
		ctx.SetReturn(0)
		return 0
	})

	// LoadCursorA: ANSI wrapper - same as LoadCursorW
	d.RegisterAutoStubHandler(user32, "LoadCursorA", func(ctx *ntapi.TrapContext) uint32 {
		lpCursorName := ctx.Arg(1)
		if lpCursorName < 0x10000 && lpCursorName != 0 {
			ctx.SetReturn(lpCursorName)
		} else {
			ctx.SetReturn(0x00010001)
		}
		return 0
	})

	// SetWindowsHookExA: ANSI wrapper - return dummy hook handle
	d.RegisterAutoStubHandler(user32, "SetWindowsHookExA", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0x00060001) // dummy hook handle
		return 0
	})

	// -------------------------------------------------------
	// RECT operations - delegate to pkg/win32/rect.go
	// -------------------------------------------------------
	readRect := func(p uint64) win32.Rect {
		l, _ := mem.Read32(p)
		t, _ := mem.Read32(p + 4)
		r, _ := mem.Read32(p + 8)
		b, _ := mem.Read32(p + 12)
		return win32.Rect{Left: int32(l), Top: int32(t), Right: int32(r), Bottom: int32(b)}
	}
	writeRect := func(p uint64, rc win32.Rect) {
		ctx2 := rc // local copy to avoid capture issues
		_ = ctx2
		mem.Write32(p, uint32(rc.Left))
		mem.Write32(p+4, uint32(rc.Top))
		mem.Write32(p+8, uint32(rc.Right))
		mem.Write32(p+12, uint32(rc.Bottom))
	}
	_ = writeRect
	_ = readRect
	d.RegisterAutoStubHandler(user32, "CopyRect", func(ctx *ntapi.TrapContext) uint32 {
		pDst, pSrc := ctx.Arg(0), ctx.Arg(1)
		if pDst == 0 || pSrc == 0 {
			ctx.SetReturn(0)
			return 0
		}
		rc := readRect(pSrc)
		mem.Write32(pDst, uint32(rc.Left))
		mem.Write32(pDst+4, uint32(rc.Top))
		mem.Write32(pDst+8, uint32(rc.Right))
		mem.Write32(pDst+12, uint32(rc.Bottom))
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "EqualRect", func(ctx *ntapi.TrapContext) uint32 {
		r1, r2 := readRect(ctx.Arg(0)), readRect(ctx.Arg(1))
		if win32.EqualRect(&r1, &r2) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "InflateRect", func(ctx *ntapi.TrapContext) uint32 {
		p := ctx.Arg(0)
		dx, dy := int32(ctx.Arg(1)), int32(ctx.Arg(2))
		rc := readRect(p)
		win32.InflateRect(&rc, dx, dy)
		mem.Write32(p, uint32(rc.Left))
		mem.Write32(p+4, uint32(rc.Top))
		mem.Write32(p+8, uint32(rc.Right))
		mem.Write32(p+12, uint32(rc.Bottom))
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "IntersectRect", func(ctx *ntapi.TrapContext) uint32 {
		pDst, pSrc1, pSrc2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		r1, r2 := readRect(pSrc1), readRect(pSrc2)
		dst := win32.Rect{}
		ok := win32.IntersectRect(&dst, &r1, &r2)
		mem.Write32(pDst, uint32(dst.Left))
		mem.Write32(pDst+4, uint32(dst.Top))
		mem.Write32(pDst+8, uint32(dst.Right))
		mem.Write32(pDst+12, uint32(dst.Bottom))
		if ok {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "IsRectEmpty", func(ctx *ntapi.TrapContext) uint32 {
		rc := readRect(ctx.Arg(0))
		if win32.IsRectEmpty(&rc) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "OffsetRect", func(ctx *ntapi.TrapContext) uint32 {
		p := ctx.Arg(0)
		dx, dy := int32(ctx.Arg(1)), int32(ctx.Arg(2))
		rc := readRect(p)
		win32.OffsetRect(&rc, dx, dy)
		mem.Write32(p, uint32(rc.Left))
		mem.Write32(p+4, uint32(rc.Top))
		mem.Write32(p+8, uint32(rc.Right))
		mem.Write32(p+12, uint32(rc.Bottom))
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "PtInRect", func(ctx *ntapi.TrapContext) uint32 {
		rc := readRect(ctx.Arg(0))
		x, y := int32(ctx.Arg(1)), int32(ctx.Arg(2))
		if win32.PtInRect(&rc, x, y) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetRect", func(ctx *ntapi.TrapContext) uint32 {
		p := ctx.Arg(0)
		l, t, r, b := int32(ctx.Arg(1)), int32(ctx.Arg(2)), int32(ctx.Arg(3)), int32(ctx.Arg(4))
		rc := win32.Rect{Left: l, Top: t, Right: r, Bottom: b}
		win32.SetRect(&rc, l, t, r, b)
		mem.Write32(p, uint32(rc.Left))
		mem.Write32(p+4, uint32(rc.Top))
		mem.Write32(p+8, uint32(rc.Right))
		mem.Write32(p+12, uint32(rc.Bottom))
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetRectEmpty", func(ctx *ntapi.TrapContext) uint32 {
		p := ctx.Arg(0)
		mem.Write32(p, 0)
		mem.Write32(p+4, 0)
		mem.Write32(p+8, 0)
		mem.Write32(p+12, 0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SubtractRect", func(ctx *ntapi.TrapContext) uint32 {
		pDst, pSrc1, pSrc2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		r1, r2 := readRect(pSrc1), readRect(pSrc2)
		dst := win32.Rect{}
		ok := win32.SubtractRect(&dst, &r1, &r2)
		mem.Write32(pDst, uint32(dst.Left))
		mem.Write32(pDst+4, uint32(dst.Top))
		mem.Write32(pDst+8, uint32(dst.Right))
		mem.Write32(pDst+12, uint32(dst.Bottom))
		if ok {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "UnionRect", func(ctx *ntapi.TrapContext) uint32 {
		pDst, pSrc1, pSrc2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		r1, r2 := readRect(pSrc1), readRect(pSrc2)
		dst := win32.Rect{}
		win32.UnionRect(&dst, &r1, &r2)
		mem.Write32(pDst, uint32(dst.Left))
		mem.Write32(pDst+4, uint32(dst.Top))
		mem.Write32(pDst+8, uint32(dst.Right))
		mem.Write32(pDst+12, uint32(dst.Bottom))
		ctx.SetReturn(1)
		return 0
	})

	// -------------------------------------------------------
	// Char / string operations
	// -------------------------------------------------------
	// Helper: read ANSI string from guest
	readAnsi := func(p uint64) string {
		var b []byte
		for i := uint64(0); i < 1024; i++ {
			ch, _ := mem.Read8(p + i)
			if ch == 0 {
				break
			}
			b = append(b, ch)
		}
		return string(b)
	}
	_ = readAnsi
	d.RegisterAutoStubHandler(user32, "CharUpperW", func(ctx *ntapi.TrapContext) uint32 {
		p := ctx.Arg(0)
		if p < 0x10000 {
			ctx.SetReturn(uint64(unicode.ToUpper(rune(p))))
		} else {
			for off := uint64(0); ; off += 2 {
				lo, _ := mem.Read16(p + off)
				if lo == 0 {
					break
				}
				up := uint16(unicode.ToUpper(rune(lo)))
				ctx.Mem.Write16(p+off, up)
			}
			ctx.SetReturn(p)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CharUpperA", func(ctx *ntapi.TrapContext) uint32 {
		p := ctx.Arg(0)
		if p < 0x100 {
			ctx.SetReturn(uint64(unicode.ToUpper(rune(p & 0xFF))))
		} else {
			for off := uint64(0); ; off++ {
				b, _ := mem.Read8(p + off)
				if b == 0 {
					break
				}
				ctx.Mem.Write8(p+off, byte(unicode.ToUpper(rune(b))))
			}
			ctx.SetReturn(p)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CharLowerW", func(ctx *ntapi.TrapContext) uint32 {
		p := ctx.Arg(0)
		if p < 0x10000 {
			ctx.SetReturn(uint64(unicode.ToLower(rune(p))))
		} else {
			for off := uint64(0); ; off += 2 {
				lo, _ := mem.Read16(p + off)
				if lo == 0 {
					break
				}
				ctx.Mem.Write16(p+off, uint16(unicode.ToLower(rune(lo))))
			}
			ctx.SetReturn(p)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CharLowerA", func(ctx *ntapi.TrapContext) uint32 {
		p := ctx.Arg(0)
		if p < 0x100 {
			ctx.SetReturn(uint64(unicode.ToLower(rune(p & 0xFF))))
		} else {
			for off := uint64(0); ; off++ {
				b, _ := mem.Read8(p + off)
				if b == 0 {
					break
				}
				ctx.Mem.Write8(p+off, byte(unicode.ToLower(rune(b))))
			}
			ctx.SetReturn(p)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CharUpperBuffW", func(ctx *ntapi.TrapContext) uint32 {
		p, n := ctx.Arg(0), ctx.Arg(1)
		for i := uint64(0); i < n; i++ {
			lo, _ := mem.Read16(p + i*2)
			ctx.Mem.Write16(p+i*2, uint16(unicode.ToUpper(rune(lo))))
		}
		ctx.SetReturn(n)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CharUpperBuffA", func(ctx *ntapi.TrapContext) uint32 {
		p, n := ctx.Arg(0), ctx.Arg(1)
		for i := uint64(0); i < n; i++ {
			b, _ := mem.Read8(p + i)
			ctx.Mem.Write8(p+i, byte(unicode.ToUpper(rune(b))))
		}
		ctx.SetReturn(n)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CharLowerBuffW", func(ctx *ntapi.TrapContext) uint32 {
		p, n := ctx.Arg(0), ctx.Arg(1)
		for i := uint64(0); i < n; i++ {
			lo, _ := mem.Read16(p + i*2)
			ctx.Mem.Write16(p+i*2, uint16(unicode.ToLower(rune(lo))))
		}
		ctx.SetReturn(n)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CharLowerBuffA", func(ctx *ntapi.TrapContext) uint32 {
		p, n := ctx.Arg(0), ctx.Arg(1)
		for i := uint64(0); i < n; i++ {
			b, _ := mem.Read8(p + i)
			ctx.Mem.Write8(p+i, byte(unicode.ToLower(rune(b))))
		}
		ctx.SetReturn(n)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CharNextW", func(ctx *ntapi.TrapContext) uint32 {
		p := ctx.Arg(0)
		lo, _ := mem.Read16(p)
		if lo != 0 {
			ctx.SetReturn(p + 2)
		} else {
			ctx.SetReturn(p)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CharNextA", func(ctx *ntapi.TrapContext) uint32 {
		p := ctx.Arg(0)
		b, _ := mem.Read8(p)
		if b != 0 {
			ctx.SetReturn(p + 1)
		} else {
			ctx.SetReturn(p)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CharNextExA", func(ctx *ntapi.TrapContext) uint32 {
		p := ctx.Arg(1) // (codePage, pCurrentChar, flags)
		b, _ := mem.Read8(p)
		if b != 0 {
			ctx.SetReturn(p + 1)
		} else {
			ctx.SetReturn(p)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CharPrevW", func(ctx *ntapi.TrapContext) uint32 {
		start, cur := ctx.Arg(0), ctx.Arg(1)
		if cur > start+2 {
			ctx.SetReturn(cur - 2)
		} else {
			ctx.SetReturn(start)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CharPrevA", func(ctx *ntapi.TrapContext) uint32 {
		start, cur := ctx.Arg(0), ctx.Arg(1)
		if cur > start {
			ctx.SetReturn(cur - 1)
		} else {
			ctx.SetReturn(start)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CharPrevExA", func(ctx *ntapi.TrapContext) uint32 {
		start, cur := ctx.Arg(1), ctx.Arg(2)
		if cur > start {
			ctx.SetReturn(cur - 1)
		} else {
			ctx.SetReturn(start)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "IsCharAlphaW", func(ctx *ntapi.TrapContext) uint32 {
		if unicode.IsLetter(rune(ctx.Arg(0))) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "IsCharAlphaA", func(ctx *ntapi.TrapContext) uint32 {
		c := rune(ctx.Arg(0) & 0xFF)
		if unicode.IsLetter(c) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "IsCharAlphaNumericW", func(ctx *ntapi.TrapContext) uint32 {
		c := rune(ctx.Arg(0))
		if unicode.IsLetter(c) || unicode.IsDigit(c) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "IsCharAlphaNumericA", func(ctx *ntapi.TrapContext) uint32 {
		c := rune(ctx.Arg(0) & 0xFF)
		if unicode.IsLetter(c) || unicode.IsDigit(c) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "IsCharLowerW", func(ctx *ntapi.TrapContext) uint32 {
		if unicode.IsLower(rune(ctx.Arg(0))) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "IsCharLowerA", func(ctx *ntapi.TrapContext) uint32 {
		if unicode.IsLower(rune(ctx.Arg(0) & 0xFF)) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "IsCharUpperW", func(ctx *ntapi.TrapContext) uint32 {
		if unicode.IsUpper(rune(ctx.Arg(0))) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "IsCharUpperA", func(ctx *ntapi.TrapContext) uint32 {
		if unicode.IsUpper(rune(ctx.Arg(0) & 0xFF)) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	// OEM ↔ char: identity in Unicode mode
	for _, fn := range []string{"OemToCharA", "OemToCharW", "CharToOemA", "CharToOemW"} {
		fn := fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			src, dst := ctx.Arg(0), ctx.Arg(1)
			if src != 0 && dst != 0 {
				for off := uint64(0); off < 1024; off++ {
					b, _ := mem.Read8(src + off)
					ctx.Mem.Write8(dst+off, b)
					if b == 0 {
						break
					}
				}
			}
			ctx.SetReturn(1)
			return 0
		})
	}
	for _, fn := range []string{"OemToCharBuffA", "OemToCharBuffW", "CharToOemBuffA", "CharToOemBuffW"} {
		fn := fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			src, dst, n := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
			for i := uint64(0); i < n; i++ {
				b, _ := mem.Read8(src + i)
				ctx.Mem.Write8(dst+i, b)
			}
			ctx.SetReturn(1)
			return 0
		})
	}

	// -------------------------------------------------------
	// Clipboard - guest-side store
	// clipStore[format] = HGLOBAL (guest mmap address)
	// clipFormats tracks insertion order for EnumClipboardFormats
	// -------------------------------------------------------
	clipStore := make(map[uint32]uint64) // format → HGLOBAL
	var clipFormats []uint32             // ordered list of stored formats
	clipSeq := uint32(1)
	clipboardViewerHwnd := uint64(0)

	d.RegisterAutoStubHandler(user32, "OpenClipboard", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		if win32.OpenClipboard(hwnd) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CloseClipboard", func(ctx *ntapi.TrapContext) uint32 {
		if win32.CloseClipboard() {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "EmptyClipboard", func(ctx *ntapi.TrapContext) uint32 {
		clipStore = make(map[uint32]uint64)
		clipFormats = nil
		clipSeq++
		win32.EmptyClipboard()
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetClipboardData", func(ctx *ntapi.TrapContext) uint32 {
		format := uint32(ctx.Arg(0))
		hMem := ctx.Arg(1)
		if hMem != 0 {
			if _, exists := clipStore[format]; !exists {
				clipFormats = append(clipFormats, format)
			}
			clipStore[format] = hMem
			clipSeq++
		}
		ctx.SetReturn(hMem)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetClipboardData", func(ctx *ntapi.TrapContext) uint32 {
		format := uint32(ctx.Arg(0))
		if h, ok := clipStore[format]; ok {
			ctx.SetReturn(h)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CountClipboardFormats", func(ctx *ntapi.TrapContext) uint32 {
		n := len(clipStore)
		if n == 0 {
			n = int(win32.CountClipboardFormats())
		}
		ctx.SetReturn(uint64(n))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "IsClipboardFormatAvailable", func(ctx *ntapi.TrapContext) uint32 {
		format := uint32(ctx.Arg(0))
		if _, ok := clipStore[format]; ok {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetClipboardOwner", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(win32.GetClipboardOwner())
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetOpenClipboardWindow", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(win32.GetOpenClipboardWindow())
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetClipboardViewer", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(clipboardViewerHwnd)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetClipboardViewer", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		prev := clipboardViewerHwnd
		clipboardViewerHwnd = hwnd
		ctx.SetReturn(prev)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "ChangeClipboardChain", func(ctx *ntapi.TrapContext) uint32 {
		hWndRemove := ctx.Arg(0)
		hWndNewNext := ctx.Arg(1)
		if clipboardViewerHwnd == hWndRemove {
			clipboardViewerHwnd = hWndNewNext
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "EnumClipboardFormats", func(ctx *ntapi.TrapContext) uint32 {
		prev := uint32(ctx.Arg(0))
		if len(clipFormats) == 0 {
			ctx.SetReturn(0)
			return 0
		}
		if prev == 0 {
			ctx.SetReturn(uint64(clipFormats[0]))
			return 0
		}
		for i, f := range clipFormats {
			if f == prev && i+1 < len(clipFormats) {
				ctx.SetReturn(uint64(clipFormats[i+1]))
				return 0
			}
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetClipboardFormatNameA", func(ctx *ntapi.TrapContext) uint32 {
		format := uint32(ctx.Arg(0))
		buf := ctx.Arg(1)
		cchMax := int(ctx.Arg(2))
		name := clipFormatName(format)
		if buf == 0 || cchMax <= 0 || name == "" {
			ctx.SetReturn(0)
			return 0
		}
		b := []byte(name)
		if len(b) >= cchMax {
			b = b[:cchMax-1]
		}
		for i, c := range b {
			ctx.Mem.Write8(buf+uint64(i), c)
		}
		ctx.Mem.Write8(buf+uint64(len(b)), 0)
		ctx.SetReturn(uint64(len(b)))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetClipboardFormatNameW", func(ctx *ntapi.TrapContext) uint32 {
		format := uint32(ctx.Arg(0))
		buf := ctx.Arg(1)
		cchMax := int(ctx.Arg(2))
		name := clipFormatName(format)
		if buf == 0 || cchMax <= 0 || name == "" {
			ctx.SetReturn(0)
			return 0
		}
		ws := utf16Encode(name)
		n := len(ws)
		if n >= cchMax {
			n = cchMax - 1
		}
		for i := 0; i < n; i++ {
			ctx.Mem.Write16(buf+uint64(i)*2, ws[i])
		}
		ctx.Mem.Write16(buf+uint64(n)*2, 0)
		ctx.SetReturn(uint64(n))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetClipboardSequenceNumber", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(clipSeq))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetPriorityClipboardFormat", func(ctx *ntapi.TrapContext) uint32 {
		// pPriorityList = arg0 array of UINT formats, cFormats = arg1
		pList := ctx.Arg(0)
		cFormats := int(ctx.Arg(1))
		for i := 0; i < cFormats; i++ {
			f, _ := ctx.Mem.Read32(pList + uint64(i)*4)
			if _, ok := clipStore[uint32(f)]; ok {
				ctx.SetReturn(uint64(f))
				return 0
			}
		}
		ctx.SetReturn(uint64(0xFFFFFFFF))
		return 0 // -1 = no matching format
	})
	d.RegisterAutoStubHandler(user32, "RegisterClipboardFormatA", func(ctx *ntapi.TrapContext) uint32 {
		name := readGuestString(ctx.Arg(0))
		ctx.SetReturn(registerClipFmt(name))
		return 0
	})

	// -------------------------------------------------------
	// Keyboard / input
	// -------------------------------------------------------
	keyboardState := make([]byte, 256)
	d.RegisterAutoStubHandler(user32, "GetKeyboardState", func(ctx *ntapi.TrapContext) uint32 {
		p := ctx.Arg(0)
		for i := uint64(0); i < 256; i++ {
			ctx.Mem.Write8(p+i, keyboardState[i])
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetKeyboardState", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL SetKeyboardState(LPBYTE lpKeyState)
		// ReactOS: win32ss/user/ntuser/input.c
		p := ctx.Arg(0)
		if p != 0 {
			for i := uint64(0); i < 256; i++ {
				b, _ := ctx.Mem.Read8(p + i)
				keyboardState[i] = b
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetKeyboardType", func(ctx *ntapi.TrapContext) uint32 {
		switch ctx.Arg(0) {
		case 0:
			ctx.SetReturn(4) // enhanced keyboard
		case 1:
			ctx.SetReturn(0) // subtype
		case 2:
			ctx.SetReturn(101) // function keys
		default:
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetKeyboardLayoutList", func(ctx *ntapi.TrapContext) uint32 {
		n := ctx.Arg(0)
		p := ctx.Arg(1)
		if p != 0 && n >= 1 {
			ctx.Mem.Write64(p, 0x04090409)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetKeyboardLayoutNameA", func(ctx *ntapi.TrapContext) uint32 {
		p := ctx.Arg(0)
		if p != 0 {
			layout := "00000409"
			for i, ch := range layout {
				ctx.Mem.Write8(p+uint64(i), byte(ch))
			}
			ctx.Mem.Write8(p+8, 0)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetKeyboardLayoutNameW", func(ctx *ntapi.TrapContext) uint32 {
		p := ctx.Arg(0)
		if p != 0 {
			layout := "00000409"
			for i, ch := range layout {
				ctx.Mem.Write16(p+uint64(i)*2, uint16(ch))
			}
			ctx.Mem.Write16(p+16, 0)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "ActivateKeyboardLayout", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0x04090409)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "UnloadKeyboardLayout", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL UnloadKeyboardLayout(HKL hkl)
		// ReactOS: win32ss/user/ntuser/kbdlayout.c
		hkl := ctx.Arg(0)
		ravelog.Logf("[user32] UnloadKeyboardLayout hkl=0x%x\n", hkl)
		ctx.SetReturn(1)
		return 0
	})
	for _, fn := range []string{"LoadKeyboardLayoutA", "LoadKeyboardLayoutW", "LoadKeyboardLayoutEx"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x04090409)
			return 0
		})
	}
	d.RegisterAutoStubHandler(user32, "GetKBCodePage", func(ctx *ntapi.TrapContext) uint32 {
		// UINT GetKBCodePage(void)
		// ReactOS: win32ss/user/user32/misc/misc.c
		// Returns the OEM code page for the system
		ctx.SetReturn(1252) // Windows-1252 Western European
		return 0
	})
	// VkKeyScan: map ASCII char to VK | (shiftState << 8)
	vkKeyScanChar := func(c rune) uint64 {
		if c >= '0' && c <= '9' {
			return uint64(c)
		}
		if c >= 'a' && c <= 'z' {
			return uint64(c - 32)
		} // VK_A..VK_Z = 0x41..0x5A
		if c >= 'A' && c <= 'Z' {
			return uint64(c) | (1 << 8)
		} // shifted
		return uint64(0xFFFF) // not found
	}
	d.RegisterAutoStubHandler(user32, "VkKeyScanA", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(vkKeyScanChar(rune(ctx.Arg(0) & 0xFF)))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "VkKeyScanW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(vkKeyScanChar(rune(ctx.Arg(0) & 0xFFFF)))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "VkKeyScanExA", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(vkKeyScanChar(rune(ctx.Arg(0) & 0xFF)))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "VkKeyScanExW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(vkKeyScanChar(rune(ctx.Arg(0) & 0xFFFF)))
		return 0
	})
	for _, fn := range []string{"MapVirtualKeyA", "MapVirtualKeyExA", "MapVirtualKeyExW"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}
	d.RegisterAutoStubHandler(user32, "GetKeyNameTextA", func(ctx *ntapi.TrapContext) uint32 {
		p := ctx.Arg(1)
		if p != 0 {
			ctx.Mem.Write8(p, 'K')
			ctx.Mem.Write8(p+1, 'e')
			ctx.Mem.Write8(p+2, 'y')
			ctx.Mem.Write8(p+3, 0)
		}
		ctx.SetReturn(3)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetKeyNameTextW", func(ctx *ntapi.TrapContext) uint32 {
		p := ctx.Arg(1)
		if p != 0 {
			ctx.Mem.Write16(p, 'K')
			ctx.Mem.Write16(p+2, 'e')
			ctx.Mem.Write16(p+4, 'y')
			ctx.Mem.Write16(p+6, 0)
		}
		ctx.SetReturn(3)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "OemKeyScan", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(ctx.Arg(0) & 0xFF)
		return 0
	})
	for _, fn := range []string{"ToAscii", "ToAsciiEx", "ToUnicode", "ToUnicodeEx"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}
	d.RegisterAutoStubHandler(user32, "keybd_event", func(ctx *ntapi.TrapContext) uint32 {
		return 0
	})
	d.RegisterAutoStubHandler(user32, "mouse_event", func(ctx *ntapi.TrapContext) uint32 {
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SendInput", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(ctx.Arg(0))
		return 0
	})

	// -------------------------------------------------------
	// Message / queue
	// -------------------------------------------------------
	d.RegisterAutoStubHandler(user32, "PostQuitMessage", func(ctx *ntapi.TrapContext) uint32 {
		exitCode := ctx.Arg(0)
		hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{hwnd: 0, message: 0x0012, wParam: exitCode, lParam: 0}) // WM_QUIT
		return 0
	})
	for _, fn := range []string{"GetInputState", "GetQueueStatus", "InSendMessage"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}
	d.RegisterAutoStubHandler(user32, "InSendMessageEx", func(ctx *ntapi.TrapContext) uint32 {
		// DWORD InSendMessageEx(LPVOID lpReserved)
		// ReactOS: NtUserGetSendMessageReceiver
		// Returns ISMEX_NOSEND(0) when the calling thread is not processing a
		// sent message. We execute everything synchronously in one thread, so
		// cross-thread SendMessage never happens.
		ctx.SetReturn(0) // ISMEX_NOSEND
		return 0
	})
	d.RegisterAutoStubHandler(user32, "ReplyMessage", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL ReplyMessage(LRESULT lResult)
		// ReactOS: win32ss/user/ntuser/message.c
		// Replies to a SendMessage before the handler returns
		lResult := ctx.Arg(0)
		ravelog.Logf("[user32] ReplyMessage result=0x%x\n", lResult)
		ctx.SetReturn(1) // TRUE if called within SendMessage handler
		return 0
	})
	d.RegisterAutoStubHandler(user32, "QuerySendMessage", func(ctx *ntapi.TrapContext) uint32 {
		// Undocumented - returns 0 if not in a SendMessage
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "MsgWaitForMultipleObjects", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: win32ss/user/ntuser/msgqueue.c NtUserMsgWaitForMultipleObjectsEx
		// Args: nCount, pHandles, fWaitAll, dwMilliseconds, dwWakeMask
		nCount := uint32(ctx.Arg(0))
		// dwMilliseconds := ctx.Arg(3) // ignored - we return immediately
		// dwWakeMask := ctx.Arg(4)

		// Check if there are queued messages
		if len(hctx.MsgQueue) > 0 {
			ctx.SetReturn(uint64(nCount)) // WAIT_OBJECT_0 + nCount = "input available"
			return 0
		}
		// No messages - poll Wayland once
		if wlDisplay != nil {
			evt, _ := wlDisplay.Poll()
			if evt != wl.EventNone {
				ctx.SetReturn(uint64(nCount))
				return 0
			}
		}
		// Return WAIT_OBJECT_0 (first object signaled) as best-effort
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "MsgWaitForMultipleObjectsEx", func(ctx *ntapi.TrapContext) uint32 {
		nCount := uint32(ctx.Arg(0))
		if len(hctx.MsgQueue) > 0 {
			ctx.SetReturn(uint64(nCount))
			return 0
		}
		if wlDisplay != nil {
			evt, _ := wlDisplay.Poll()
			if evt != wl.EventNone {
				ctx.SetReturn(uint64(nCount))
				return 0
			}
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "WaitMessage", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL WaitMessage(void) - blocks until message available
		// ReactOS: win32ss/user/ntuser/message.c
		// In our emulator, poll Wayland once then return
		if wlDisplay != nil {
			wlDisplay.Poll()
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "WaitForInputIdle", func(ctx *ntapi.TrapContext) uint32 {
		// DWORD WaitForInputIdle(HANDLE hProcess, DWORD dwMilliseconds)
		// ReactOS: win32ss/user/ntuser/input.c
		// 0 = wait satisfied, WAIT_TIMEOUT=258
		// Since we're single-process, the app is always "idle"
		ctx.SetReturn(0)
		return 0
	})
	for _, fn := range []string{"GetMessagePos", "GetMessageTime", "GetMessageExtraInfo"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}
	messageExtraInfo := uint64(0)
	d.RegisterAutoStubHandler(user32, "SetMessageExtraInfo", func(ctx *ntapi.TrapContext) uint32 {
		// LPARAM SetMessageExtraInfo(LPARAM lParam) - returns previous value
		prev := messageExtraInfo
		messageExtraInfo = ctx.Arg(0)
		ctx.SetReturn(prev)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "PostMessageA", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: win32ss/user/ntuser/message.c NtUserPostMessage
		hwnd := ctx.Arg(0)
		msg := uint32(ctx.Arg(1))
		wParam := ctx.Arg(2)
		lParam := ctx.Arg(3)
		if hwnd == hctx.MainHWND || hwnd == 0xFFFF || hwnd == 0xFFFFFFFFFFFFFFFF {
			hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{hctx.MainHWND, msg, wParam, lParam})
		} else if _, ok := hwndChildren[hwnd]; ok {
			hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{hwnd, msg, wParam, lParam})
		}
		ctx.SetReturn(1)
		return 0
	})
	for _, fn := range []string{"PostThreadMessageA", "PostThreadMessageW"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(1)
			return 0
		})
	}
	d.RegisterAutoStubHandler(user32, "PeekMessageA", func(ctx *ntapi.TrapContext) uint32 {
		// PeekMessageA: identical to PeekMessageW - our messages are internal, no A/W distinction
		pMsg := ctx.Arg(0)
		remove := ctx.Arg(4)&0x1 != 0

		if wlDisplay != nil {
			evt, _ := wlDisplay.Poll()
			if evt != wl.EventNone && evt != wl.EventClose {
				if evt == wl.EventKey {
					for {
						ke, ok := wlDisplay.PollKey()
						if !ok {
							break
						}
						target := hctx.FocusHwnd
						if target == 0 {
							target = hctx.MainHWND
						}
						if ke.Pressed {
							hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{target, 0x0100, uint64(ke.VK), 0})
							if ke.Char >= 0x20 || ke.Char == '\r' || ke.Char == '\b' || ke.Char == '\t' {
								hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{target, 0x0102, uint64(ke.Char), 0})
							}
						} else {
							hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{target, 0x0101, uint64(ke.VK), 0})
						}
					}
				}
				if evt == wl.EventMouse {
					if dispatchWl != nil {
						dispatchWl(evt)
					}
				}
			}
		}

		if len(hctx.MsgQueue) == 0 {
			ctx.SetReturn(0)
			return 0
		}
		m := hctx.MsgQueue[0]
		if remove {
			hctx.MsgQueue = hctx.MsgQueue[1:]
		}
		if pMsg != 0 {
			writeMsg(pMsg, m.hwnd, m.message, m.wParam, m.lParam)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "DispatchMessageA", func(ctx *ntapi.TrapContext) uint32 {
		pMsg := ctx.Arg(0)
		if pMsg == 0 {
			ctx.SetReturn(0)
			return 0
		}
		// MSG layout (x64): HWND(8) message(4) pad(4) WPARAM(8) LPARAM(8) ...
		hwnd, _ := mem.Read64(pMsg)
		message, _ := mem.Read32(pMsg + 8)
		wParam, _ := mem.Read64(pMsg + 16)
		lParam, _ := mem.Read64(pMsg + 24)

		// Try built-in control first
		if _, isChild := hwndChildren[hwnd]; isChild {
			result, handled := builtinWndProc(hwnd, message, wParam, lParam)
			if handled {
				if message == 0x000F {
					commitIfDone()
				}
				ctx.SetReturn(result)
				return 0
			}
		}

		wndProc, ok := hwndWndProc[hwnd]
		if !ok || wndProc == 0 {
			ravelog.Logf("[dispatch] DispatchMessageA: no WndProc for hwnd=0x%x msg=0x%x\n", hwnd, message)
			ctx.SetReturn(0)
			return 0
		}

		rw, ok := ctx.CPU.(ntapi.RegisterWriter)
		if !ok {
			ctx.SetReturn(0)
			return 0
		}

		ravelog.Logf("[dispatch] DispatchMessageA: hwnd=0x%x msg=0x%x → WndProc=0x%x\n", hwnd, message, wndProc)

		rw.WriteReg(1, hwnd)            // RCX
		rw.WriteReg(2, uint64(message)) // RDX
		rw.WriteReg(8, wParam)          // R8
		rw.WriteReg(9, lParam)          // R9

		ctx.CPU.SetPC(wndProc)
		ctx.ReturnOverridden = true
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SendMessageA", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		msg := uint32(ctx.Arg(1))
		wParam := ctx.Arg(2)
		lParam := ctx.Arg(3)
		if result, handled := builtinWndProc(hwnd, msg, wParam, lParam); handled {
			ctx.SetReturn(result)
			return 0
		}
		wp, hasWP := hwndWndProc[hwnd]
		if !hasWP || wp == 0 {
			ctx.SetReturn(0)
			return 0
		}
		rw, okW := ctx.CPU.(ntapi.RegisterWriter)
		rr, okR := ctx.CPU.(ntapi.RegisterReader)
		if okW && okR {
			rsp := rr.ReadReg(4)
			retAddr, _ := mem.Read64(rsp)
			hctx.SyncStack = append(hctx.SyncStack, syncDispatchFrame{
				queue: []syncDispatch{}, retAddr: retAddr,
				hwnd: hwnd, returnWndProcResult: true,
			})
			mem.Write64(rsp, hctx.SyncTrampoline)
			rw.WriteReg(1, hwnd)
			rw.WriteReg(2, uint64(msg))
			rw.WriteReg(8, wParam)
			rw.WriteReg(9, lParam)
			ctx.CPU.SetPC(wp)
			ctx.ReturnOverridden = true
			return 0
		}
		hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{hwnd, msg, wParam, lParam})
		ctx.SetReturn(0)
		return 0
	})
	// SendMessageTimeoutA/W - ReactOS: win32ss/user/ntuser/message.c co_IntSendMessageTimeout
	// Signature: LRESULT SendMessageTimeoutW(HWND,UINT,WPARAM,LPARAM,UINT fuFlags,UINT uTimeout,PDWORD_PTR lpdwResult)
	sendMsgTimeoutImpl := func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		msg := uint32(ctx.Arg(1))
		wParam := ctx.Arg(2)
		lParam := ctx.Arg(3)
		// Arg(4) = fuFlags, Arg(5) = uTimeout (ignored - we dispatch synchronously)
		lpdwResult := ctx.Arg(6)

		var result uint64
		if res, handled := builtinWndProc(hwnd, msg, wParam, lParam); handled {
			result = res
		} else if hwnd == hctx.MainHWND || hwnd == 0xFFFF || hwnd == 0xFFFFFFFFFFFFFFFF {
			hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{hctx.MainHWND, msg, wParam, lParam})
		} else if _, ok := hwndChildren[hwnd]; ok {
			hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{hwnd, msg, wParam, lParam})
		}
		if lpdwResult != 0 {
			mem.Write64(lpdwResult, result)
		}
		ctx.SetReturn(1) // nonzero = success
		return 0
	}
	d.RegisterAutoStubHandler(user32, "SendMessageTimeoutA", sendMsgTimeoutImpl)
	d.RegisterAutoStubHandler(user32, "SendMessageTimeoutW", sendMsgTimeoutImpl)
	for _, fn := range []string{
		"SendMessageCallbackA", "SendMessageCallbackW"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}
	for _, fn := range []string{"SendNotifyMessageA", "SendNotifyMessageW"} {
		fn := fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			msg := uint32(ctx.Arg(1))
			wParam := ctx.Arg(2)
			lParam := ctx.Arg(3)
			target := hwnd
			if target == 0 || target == 0xFFFF || target == 0xFFFFFFFFFFFFFFFF {
				target = hctx.MainHWND
			}
			if target == hctx.MainHWND || hwndChildren[target] != nil {
				hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{target, msg, wParam, lParam})
				ctx.SetReturn(1)
			} else {
				ctx.SetReturn(0)
			}
			return 0
		})
	}
	d.RegisterAutoStubHandler(user32, "SendDlgItemMessageA", func(ctx *ntapi.TrapContext) uint32 {
		hDlg := ctx.Arg(0)
		nIDDlgItem := ctx.Arg(1)
		msg := uint32(ctx.Arg(2))
		wParam := ctx.Arg(3)
		lParam := ctx.Arg(4)
		for h, cs := range hwndChildren {
			if cs.parentHWND == hDlg && cs.ctrlID == nIDDlgItem {
				if result, handled := builtinWndProc(h, msg, wParam, lParam); handled {
					ctx.SetReturn(result)
					return 0
				}
				if wp, ok := hwndWndProc[h]; ok && wp != 0 {
					hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{h, msg, wParam, lParam})
				}
				break
			}
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "TranslateMessageEx", func(ctx *ntapi.TrapContext) uint32 {
		// Undocumented extended TranslateMessage. Same behavior.
		pMsg := ctx.Arg(0)
		if pMsg != 0 {
			msg, _ := mem.Read32(pMsg + 8)      // MSG.message
			if msg == 0x0100 || msg == 0x0104 { // WM_KEYDOWN, WM_SYSKEYDOWN
				ctx.SetReturn(1)
				return 0
			}
		}
		ctx.SetReturn(0)
		return 0
	})
	for _, fn := range []string{"BroadcastSystemMessage", "BroadcastSystemMessageA",
		"BroadcastSystemMessageW", "BroadcastSystemMessageExA", "BroadcastSystemMessageExW",
		"CsrBroadcastSystemMessageExW"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(1)
			return 0
		})
	}

	// -------------------------------------------------------
	// Window state / info
	// -------------------------------------------------------
	d.RegisterAutoStubHandler(user32, "IsIconic", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		var style uint64
		if m, ok := windowLongPtr[hwnd]; ok {
			style = m[-16]
		}
		if style&0x20000000 != 0 { // WS_MINIMIZE
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "IsZoomed", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		var style uint64
		if m, ok := windowLongPtr[hwnd]; ok {
			style = m[-16]
		}
		if style&0x01000000 != 0 { // WS_MAXIMIZE
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "IsWindowEnabled", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		if hwndDisabled[hwnd] {
			ctx.SetReturn(0)
		} else {
			ctx.SetReturn(1)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "IsWindowUnicode", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: win32ss/user/ntuser/window.c NtUserIsWindowUnicode
		// We register all classes as Unicode, so return TRUE for any valid HWND.
		hwnd := ctx.Arg(0)
		if hwnd == hctx.MainHWND || hwnd == 0x00050000 {
			ctx.SetReturn(1)
			return 0
		}
		if _, ok := hwndChildren[hwnd]; ok {
			ctx.SetReturn(1)
			return 0
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "IsMenu", func(ctx *ntapi.TrapContext) uint32 {
		if ctx.Arg(0) != 0 {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "IsGUIThread", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL IsGUIThread(BOOL bConvert)
		// ReactOS: NtUserGetThreadState(12)
		// We always run in a GUI context.
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "IsHungAppWindow", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL IsHungAppWindow(HWND)
		// ReactOS: NtUserQueryWindow → IsHungAppWindow
		// Our app is never hung (single-threaded, synchronous execution).
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "IsWindowInDestroy", func(ctx *ntapi.TrapContext) uint32 {
		// Undocumented. Returns TRUE if the window is being destroyed.
		// Check if the HWND still exists in the window manager.
		hwnd := ctx.Arg(0)
		if win32.Global.Get(hwnd) == nil && hwnd != 0 {
			ctx.SetReturn(1) // window not in table → likely being destroyed
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "IsServerSideWindow", func(ctx *ntapi.TrapContext) uint32 {
		// Undocumented. We never use server-side windows.
		_ = ctx.Arg(0) // hWnd
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "IsSETEnabled", func(ctx *ntapi.TrapContext) uint32 {
		// Undocumented. Software Enhancement Technology - always disabled.
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "AnyPopup", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL AnyPopup() - returns TRUE if any visible popup/owned window exists
		// ReactOS: win32ss/user/ntuser/window.c
		found := false
		for _, h := range win32.Global.AllWindows() {
			wnd := win32.Global.Get(h)
			if wnd != nil && wnd.Parent != 0 && wnd.Style&0x10000000 != 0 { // WS_VISIBLE
				found = true
				break
			}
		}
		if found {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetActiveWindow", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: win32ss/user/ntuser/focus.c IntGetActiveWindow
		if hctx.ActiveHwnd != 0 {
			ctx.SetReturn(hctx.ActiveHwnd)
		} else {
			ctx.SetReturn(hctx.MainHWND)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetActiveWindow", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: win32ss/user/ntuser/focus.c co_IntSetActiveWindow
		prev := hctx.ActiveHwnd
		if prev == 0 {
			prev = hctx.MainHWND
		}
		hctx.ActiveHwnd = ctx.Arg(0)
		ctx.SetReturn(prev)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetCapture", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: win32ss/user/ntuser/msgqueue.c IntGetCapture
		ctx.SetReturn(hctx.MouseCapture)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetLastActivePopup", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(ctx.Arg(0))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetAncestor", func(ctx *ntapi.TrapContext) uint32 {
		hwnd, gaFlags := ctx.Arg(0), ctx.Arg(1)
		switch gaFlags {
		case 2, 3:
			ctx.SetReturn(hctx.MainHWND) // GA_ROOT / GA_ROOTOWNER
		default:
			if cs, ok := hwndChildren[hwnd]; ok {
				ctx.SetReturn(cs.parentHWND)
			} else {
				ctx.SetReturn(0)
			}
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CloseWindow", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL CloseWindow(HWND) - minimizes the specified window.
		// ReactOS: NtUserShowWindow(hwnd, SW_MINIMIZE)
		// We don't implement minimization, but we can mark it as valid.
		hwnd := ctx.Arg(0)
		if win32.Global.Get(hwnd) != nil {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "OpenIcon", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL OpenIcon(HWND) - restores a minimized window.
		// ReactOS: NtUserShowWindow(hwnd, SW_RESTORE)
		hwnd := ctx.Arg(0)
		if win32.Global.Get(hwnd) != nil {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "BringWindowToTop", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL BringWindowToTop(HWND hWnd) - equivalent to SetWindowPos(SWP_NOMOVE|SWP_NOSIZE)
		// ReactOS: win32ss/user/ntuser/winpos.c
		hwnd := ctx.Arg(0)
		if hwnd == hctx.MainHWND || hwndChildren[hwnd] != nil {
			hctx.ActiveHwnd = hwnd
			queuePaint(hwnd)
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "ShowWindowAsync", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL ShowWindowAsync(HWND hWnd, int nCmdShow)
		// ReactOS: posts message instead of synchronous ShowWindow
		hwnd := ctx.Arg(0)
		nCmd := uint32(ctx.Arg(1))
		ravelog.Logf("[user32] ShowWindowAsync hwnd=0x%x cmd=%d\n", hwnd, nCmd)
		if cs, ok := hwndChildren[hwnd]; ok {
			cs.visible = (nCmd != 0) // SW_HIDE=0
		}
		queuePaint(hwnd)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "ShowOwnedPopups", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL ShowOwnedPopups(HWND hWndOwner, BOOL fShow)
		// ReactOS: win32ss/user/ntuser/window.c
		owner := ctx.Arg(0)
		fShow := ctx.Arg(1) != 0
		for _, h := range win32.Global.AllWindows() {
			wnd := win32.Global.Get(h)
			if wnd != nil && wnd.Parent == owner {
				if fShow {
					wnd.Style |= 0x10000000 // WS_VISIBLE
				} else {
					wnd.Style &^= 0x10000000
				}
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetWindowThreadProcessId", func(ctx *ntapi.TrapContext) uint32 {
		pPid := ctx.Arg(1)
		if pPid != 0 {
			ctx.Mem.Write32(pPid, 1)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetWindowTextA", func(ctx *ntapi.TrapContext) uint32 {
		hwnd, pBuf, nMax := ctx.Arg(0), ctx.Arg(1), int(ctx.Arg(2))
		var text string
		if cs, ok := hwndChildren[hwnd]; ok {
			text = cs.text
		} else if hwnd == hctx.MainHWND {
			text = hctx.MainTitle
		}
		if pBuf != 0 && nMax > 0 {
			bs := []byte(text)
			if len(bs) >= nMax {
				bs = bs[:nMax-1]
			}
			for i, b := range bs {
				ctx.Mem.Write8(pBuf+uint64(i), b)
			}
			ctx.Mem.Write8(pBuf+uint64(len(bs)), 0)
		}
		ctx.SetReturn(uint64(len(text)))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetWindowTextLengthA", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		if cs, ok := hwndChildren[hwnd]; ok {
			ctx.SetReturn(uint64(len(cs.text)))
			return 0
		}
		if hwnd == hctx.MainHWND {
			ctx.SetReturn(uint64(len(hctx.MainTitle)))
			return 0
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetWindowTextA", func(ctx *ntapi.TrapContext) uint32 {
		hwnd, p := ctx.Arg(0), ctx.Arg(1)
		text := readAnsi(p)
		if hwnd == hctx.MainHWND {
			hctx.MainTitle = text
		}
		if cs, ok := hwndChildren[hwnd]; ok {
			cs.text = text
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetWindowLongA", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		index := int32(ctx.Arg(1))
		var val uint64
		if m, ok := windowLongPtr[hwnd]; ok {
			val = m[index]
		}
		ctx.SetReturn(val)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetWindowLongA", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		index := int32(ctx.Arg(1))
		newVal := ctx.Arg(2)
		m := windowLongPtr[hwnd]
		if m == nil {
			m = make(map[int32]uint64)
			windowLongPtr[hwnd] = m
		}
		old := m[index]
		m[index] = newVal
		ctx.SetReturn(old)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetWindowWord", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		index := int32(ctx.Arg(1))
		var val uint64
		if m, ok := windowLongPtr[hwnd]; ok {
			val = m[index]
		}
		ctx.SetReturn(val & 0xFFFF)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetWindowWord", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		index := int32(ctx.Arg(1))
		newVal := ctx.Arg(2) & 0xFFFF
		m := windowLongPtr[hwnd]
		if m == nil {
			m = make(map[int32]uint64)
			windowLongPtr[hwnd] = m
		}
		old := m[index] & 0xFFFF
		m[index] = (m[index] & 0xFFFF0000) | newVal
		ctx.SetReturn(old)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetClassNameA", func(ctx *ntapi.TrapContext) uint32 {
		hwnd, pBuf, nMax := ctx.Arg(0), ctx.Arg(1), int(ctx.Arg(2))
		var name string
		if cs, ok := hwndChildren[hwnd]; ok {
			name = cs.className
		}
		if pBuf != 0 && nMax > 0 {
			bs := []byte(name)
			if len(bs) >= nMax {
				bs = bs[:nMax-1]
			}
			for i, b := range bs {
				ctx.Mem.Write8(pBuf+uint64(i), b)
			}
			ctx.Mem.Write8(pBuf+uint64(len(bs)), 0)
		}
		ctx.SetReturn(uint64(len(name)))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetClassNameW", func(ctx *ntapi.TrapContext) uint32 {
		hwnd, pBuf, nMax := ctx.Arg(0), ctx.Arg(1), int(ctx.Arg(2))
		var name string
		if cs, ok := hwndChildren[hwnd]; ok {
			name = cs.className
		}
		if pBuf != 0 && nMax > 0 {
			rs := []rune(name)
			if len(rs) >= nMax {
				rs = rs[:nMax-1]
			}
			for i, r := range rs {
				ctx.Mem.Write16(pBuf+uint64(i)*2, uint16(r))
			}
			ctx.Mem.Write16(pBuf+uint64(len(rs))*2, 0)
		}
		ctx.SetReturn(uint64(len(name)))
		return 0
	})
	for _, fn := range []string{"RealGetWindowClass", "RealGetWindowClassA", "RealGetWindowClassW"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			hwnd, pBuf, nMax := ctx.Arg(0), ctx.Arg(1), int(ctx.Arg(2))
			var name string
			if cs, ok := hwndChildren[hwnd]; ok {
				name = cs.className
			}
			if pBuf != 0 && nMax > 0 {
				bs := []byte(name)
				if len(bs) >= nMax {
					bs = bs[:nMax-1]
				}
				for i, b := range bs {
					ctx.Mem.Write8(pBuf+uint64(i), b)
				}
				ctx.Mem.Write8(pBuf+uint64(len(bs)), 0)
			}
			ctx.SetReturn(uint64(len(name)))
			return 0
		})
	}
	d.RegisterAutoStubHandler(user32, "InternalGetWindowText", func(ctx *ntapi.TrapContext) uint32 {
		hwnd, pBuf, nMax := ctx.Arg(0), ctx.Arg(1), int(ctx.Arg(2))
		var text string
		if cs, ok := hwndChildren[hwnd]; ok {
			text = cs.text
		} else if hwnd == hctx.MainHWND {
			text = hctx.MainTitle
		}
		if pBuf != 0 && nMax > 0 {
			rs := []rune(text)
			if len(rs) >= nMax {
				rs = rs[:nMax-1]
			}
			for i, r := range rs {
				ctx.Mem.Write16(pBuf+uint64(i)*2, uint16(r))
			}
			ctx.Mem.Write16(pBuf+uint64(len(rs))*2, 0)
		}
		ctx.SetReturn(uint64(len(text)))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetWindowInfo", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: win32ss/user/ntuser/window.c NtUserGetWindowInfo
		hwnd, pWI := ctx.Arg(0), ctx.Arg(1)
		if pWI == 0 {
			ctx.SetReturn(0)
			return 0
		}
		// WINDOWINFO: cbSize(4)+rcWindow(16)+rcClient(16)+dwStyle(4)+dwExStyle(4)+
		//   dwWindowStatus(4)+cxWindowBorders(4)+cyWindowBorders(4)+atomWindowType(2)+wCreatorVersion(2)
		cbSize, _ := mem.Read32(pWI)
		if cbSize < 60 {
			ctx.SetReturn(0)
			return 0
		}
		var x, y, w, h int32
		var style, exStyle uint32
		if cs, ok := hwndChildren[hwnd]; ok {
			x, y, w, h = cs.x, cs.y, cs.w, cs.h
			style, exStyle = cs.style, cs.exStyle
		} else if wlWindow != nil {
			w, h = wlWindow.Width, wlWindow.Height
			style = 0x00CF0000 // WS_OVERLAPPEDWINDOW
		}
		// rcWindow
		ctx.Mem.Write32(pWI+4, uint32(x))
		ctx.Mem.Write32(pWI+8, uint32(y))
		ctx.Mem.Write32(pWI+12, uint32(x+w))
		ctx.Mem.Write32(pWI+16, uint32(y+h))
		// rcClient
		ctx.Mem.Write32(pWI+20, uint32(x))
		ctx.Mem.Write32(pWI+24, uint32(y))
		ctx.Mem.Write32(pWI+28, uint32(x+w))
		ctx.Mem.Write32(pWI+32, uint32(y+h))
		// dwStyle
		ctx.Mem.Write32(pWI+36, style)
		// dwExStyle
		ctx.Mem.Write32(pWI+40, exStyle)
		// dwWindowStatus: WS_ACTIVECAPTION (1) if foreground
		var winStatus uint32
		if hwnd == hctx.MainHWND || hwnd == hctx.FocusHwnd {
			winStatus = 1
		}
		ctx.Mem.Write32(pWI+44, winStatus)
		// cxWindowBorders, cyWindowBorders
		ctx.Mem.Write32(pWI+48, 1)
		ctx.Mem.Write32(pWI+52, 1)
		// atomWindowType
		var atom uint16
		if a, ok := hctx.HwndClassAtom[hwnd]; ok {
			atom = a
		}
		ctx.Mem.Write16(pWI+56, atom)
		// wCreatorVersion (Windows Vista = 0x0600)
		ctx.Mem.Write16(pWI+58, 0x0600)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetWindowDC", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		// Window DC covers the full surface (NC + client), so origin is (0,0) for the main window.
		var ox, oy int32
		if cs, ok := hwndChildren[hwnd]; ok {
			// Child window: origin at the child top-left (no extra NC offset)
			ox, oy = cs.x, cs.y
			h, dc := allocScreenDC(ox, oy)
			dc.SetClipRect(cs.x, cs.y, cs.x+cs.w, cs.y+cs.h)
			ctx.SetReturn(h)
			return 0
		}
		// Main window: origin (0,0) covers full surface including NC area
		h, _ := allocScreenDC(ox, oy)
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetDCEx", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		ox, oy := clientAreaOrigin(hwnd)
		h, dc := allocScreenDC(ox, oy)
		if cs, ok := hwndChildren[hwnd]; ok {
			dc.SetClipRect(cs.x, cs.y, cs.x+cs.w, cs.y+cs.h)
		}
		ctx.SetReturn(h)
		return 0
	})
	helpIdMap := map[uint64]uint32{}
	d.RegisterAutoStubHandler(user32, "GetWindowContextHelpId", func(ctx *ntapi.TrapContext) uint32 {
		// DWORD GetWindowContextHelpId(HWND hWnd)
		// ReactOS: win32ss/user/ntuser/window.c
		hwnd := ctx.Arg(0)
		ctx.SetReturn(uint64(helpIdMap[hwnd]))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetWindowContextHelpId", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL SetWindowContextHelpId(HWND hWnd, DWORD dwContextHelpId)
		hwnd := ctx.Arg(0)
		helpID := uint32(ctx.Arg(1))
		helpIdMap[hwnd] = helpID
		ctx.SetReturn(1)
		return 0
	})
	for _, fn := range []string{"GetWindowModuleFileName", "GetWindowModuleFileNameA", "GetWindowModuleFileNameW"} {
		fn := fn
		isW := fn == "GetWindowModuleFileNameW"
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			pBuf := ctx.Arg(1)
			nMax := int(ctx.Arg(2))
			path := hctx.ImagePath
			if pBuf != 0 && nMax > 0 {
				if isW {
					rs := []rune(path)
					if len(rs) >= nMax {
						rs = rs[:nMax-1]
					}
					for i, r := range rs {
						mem.Write16(pBuf+uint64(i)*2, uint16(r))
					}
					mem.Write16(pBuf+uint64(len(rs))*2, 0)
					ctx.SetReturn(uint64(len(rs)))
				} else {
					bs := []byte(path)
					if len(bs) >= nMax {
						bs = bs[:nMax-1]
					}
					for i, b := range bs {
						mem.Write8(pBuf+uint64(i), b)
					}
					mem.Write8(pBuf+uint64(len(bs)), 0)
					ctx.SetReturn(uint64(len(bs)))
				}
			} else {
				ctx.SetReturn(0)
			}
			return 0
		})
	}
	d.RegisterAutoStubHandler(user32, "GetWindowPlacement", func(ctx *ntapi.TrapContext) uint32 {
		hwnd, pWP := ctx.Arg(0), ctx.Arg(1)
		if pWP == 0 {
			ctx.SetReturn(0)
			return 0
		}
		// WINDOWPLACEMENT: length(4)+flags(4)+showCmd(4)+ptMinPos(8)+ptMaxPos(8)+rcNormalPos(16)
		ctx.Mem.Write32(pWP, 44) // length
		ctx.Mem.Write32(pWP+4, 0)
		ctx.Mem.Write32(pWP+8, 1) // SW_SHOWNORMAL
		var x, y, w, h int32
		if cs, ok := hwndChildren[hwnd]; ok {
			x, y, w, h = cs.x, cs.y, cs.w, cs.h
		} else if wlWindow != nil {
			w, h = wlWindow.Width, wlWindow.Height
		}
		ctx.Mem.Write32(pWP+28, uint32(x))
		ctx.Mem.Write32(pWP+32, uint32(y))
		ctx.Mem.Write32(pWP+36, uint32(x+w))
		ctx.Mem.Write32(pWP+40, uint32(y+h))
		ctx.SetReturn(1)
		return 0
	})
	// ─── GetClassInfo/GetClassLong ─────────────────────────────────────
	d.RegisterAutoStubHandler(user32, "GetClassInfoExW", func(ctx *ntapi.TrapContext) uint32 {
		lpClassName := ctx.Arg(1)
		pOut := ctx.Arg(2) // WNDCLASSEXW
		var atom uint16
		if lpClassName < 0x10000 {
			atom = uint16(lpClassName)
		} else {
			name := readGuestUTF16(lpClassName)
			atom = hctx.ClassNameAtom[name]
		}
		ci := hctx.ClassInfo[atom]
		if ci == nil {
			ctx.SetReturn(0) // class not found
			return 0
		}
		if pOut != 0 {
			mem.Write32(pOut, 80)                     // cbSize
			mem.Write32(pOut+4, ci.Style)             // style
			mem.Write64(pOut+8, ci.WndProc)           // lpfnWndProc
			mem.Write32(pOut+16, uint32(ci.ClsExtra)) // cbClsExtra
			mem.Write32(pOut+20, uint32(ci.WndExtra)) // cbWndExtra
			mem.Write64(pOut+24, ci.HInstance)        // hInstance
			mem.Write64(pOut+32, ci.HIcon)            // hIcon
			mem.Write64(pOut+40, ci.HCursor)          // hCursor
			mem.Write64(pOut+48, ci.HbrBG)            // hbrBackground
			mem.Write64(pOut+56, ci.MenuName)         // lpszMenuName
			mem.Write64(pOut+64, 0)                   // lpszClassName (pointer; set to 0)
			mem.Write64(pOut+72, ci.HIconSm)          // hIconSm
		}
		ctx.SetReturn(uint64(atom))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetClassInfoExA", func(ctx *ntapi.TrapContext) uint32 {
		lpClassName := ctx.Arg(1)
		pOut := ctx.Arg(2)
		var atom uint16
		if lpClassName < 0x10000 {
			atom = uint16(lpClassName)
		} else {
			name := readGuestString(lpClassName)
			atom = hctx.ClassNameAtom[name]
		}
		ci := hctx.ClassInfo[atom]
		if ci == nil {
			ctx.SetReturn(0)
			return 0
		}
		if pOut != 0 {
			mem.Write32(pOut, 80)
			mem.Write32(pOut+4, ci.Style)
			mem.Write64(pOut+8, ci.WndProc)
			mem.Write32(pOut+16, uint32(ci.ClsExtra))
			mem.Write32(pOut+20, uint32(ci.WndExtra))
			mem.Write64(pOut+24, ci.HInstance)
			mem.Write64(pOut+32, ci.HIcon)
			mem.Write64(pOut+40, ci.HCursor)
			mem.Write64(pOut+48, ci.HbrBG)
			mem.Write64(pOut+56, ci.MenuName)
			mem.Write64(pOut+64, 0)
			mem.Write64(pOut+72, ci.HIconSm)
		}
		ctx.SetReturn(uint64(atom))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetClassInfoW", func(ctx *ntapi.TrapContext) uint32 {
		lpClassName := ctx.Arg(1)
		pOut := ctx.Arg(2) // WNDCLASSW (no cbSize/hIconSm)
		var atom uint16
		if lpClassName < 0x10000 {
			atom = uint16(lpClassName)
		} else {
			name := readGuestUTF16(lpClassName)
			atom = hctx.ClassNameAtom[name]
		}
		ci := hctx.ClassInfo[atom]
		if ci == nil {
			ctx.SetReturn(0)
			return 0
		}
		if pOut != 0 {
			mem.Write32(pOut, ci.Style)               // style
			mem.Write64(pOut+8, ci.WndProc)           // lpfnWndProc
			mem.Write32(pOut+16, uint32(ci.ClsExtra)) // cbClsExtra
			mem.Write32(pOut+20, uint32(ci.WndExtra)) // cbWndExtra
			mem.Write64(pOut+24, ci.HInstance)
			mem.Write64(pOut+32, ci.HIcon)
			mem.Write64(pOut+40, ci.HCursor)
			mem.Write64(pOut+48, ci.HbrBG)
			mem.Write64(pOut+56, ci.MenuName)
			mem.Write64(pOut+64, 0)
		}
		ctx.SetReturn(uint64(atom))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetClassInfoA", func(ctx *ntapi.TrapContext) uint32 {
		lpClassName := ctx.Arg(1)
		pOut := ctx.Arg(2)
		var atom uint16
		if lpClassName < 0x10000 {
			atom = uint16(lpClassName)
		} else {
			name := readGuestString(lpClassName)
			atom = hctx.ClassNameAtom[name]
		}
		ci := hctx.ClassInfo[atom]
		if ci == nil {
			ctx.SetReturn(0)
			return 0
		}
		if pOut != 0 {
			mem.Write32(pOut, ci.Style)
			mem.Write64(pOut+8, ci.WndProc)
			mem.Write32(pOut+16, uint32(ci.ClsExtra))
			mem.Write32(pOut+20, uint32(ci.WndExtra))
			mem.Write64(pOut+24, ci.HInstance)
			mem.Write64(pOut+32, ci.HIcon)
			mem.Write64(pOut+40, ci.HCursor)
			mem.Write64(pOut+48, ci.HbrBG)
			mem.Write64(pOut+56, ci.MenuName)
			mem.Write64(pOut+64, 0)
		}
		ctx.SetReturn(uint64(atom))
		return 0
	})
	// GetClassLongPtrW/A - ReactOS: NtUserGetClassLongPtr
	d.RegisterAutoStubHandler(user32, "GetClassLongPtrW", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		idx := int32(ctx.Arg(1))
		atom := hctx.HwndClassAtom[hwnd]
		ci := hctx.ClassInfo[atom]
		if ci == nil {
			ctx.SetReturn(0)
			return 0
		}
		var val uint64
		switch idx {
		case -26: // GCL_STYLE
			val = uint64(ci.Style)
		case -24: // GCL_WNDPROC / GCLP_WNDPROC
			val = ci.WndProc
		case -20: // GCL_CBCLSEXTRA
			val = uint64(uint32(ci.ClsExtra))
		case -18: // GCL_CBWNDEXTRA
			val = uint64(uint32(ci.WndExtra))
		case -16: // GCL_HMODULE / GCLP_HMODULE
			val = ci.HInstance
		case -14: // GCL_HICON / GCLP_HICON
			val = ci.HIcon
		case -12: // GCL_HCURSOR / GCLP_HCURSOR
			val = ci.HCursor
		case -10: // GCL_HBRBACKGROUND / GCLP_HBRBACKGROUND
			val = ci.HbrBG
		case -8: // GCL_MENUNAME / GCLP_MENUNAME
			val = ci.MenuName
		case -34: // GCL_HICONSM / GCLP_HICONSM
			val = ci.HIconSm
		}
		ctx.SetReturn(val)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetClassLongPtrA", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		idx := int32(ctx.Arg(1))
		atom := hctx.HwndClassAtom[hwnd]
		ci := hctx.ClassInfo[atom]
		if ci == nil {
			ctx.SetReturn(0)
			return 0
		}
		var val uint64
		switch idx {
		case -26:
			val = uint64(ci.Style)
		case -24:
			val = ci.WndProc
		case -20:
			val = uint64(uint32(ci.ClsExtra))
		case -18:
			val = uint64(uint32(ci.WndExtra))
		case -16:
			val = ci.HInstance
		case -14:
			val = ci.HIcon
		case -12:
			val = ci.HCursor
		case -10:
			val = ci.HbrBG
		case -8:
			val = ci.MenuName
		case -34:
			val = ci.HIconSm
		}
		ctx.SetReturn(val)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetClassLongPtrW", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		idx := int32(ctx.Arg(1))
		newVal := ctx.Arg(2)
		atom := hctx.HwndClassAtom[hwnd]
		ci := hctx.ClassInfo[atom]
		if ci == nil {
			ctx.SetReturn(0)
			return 0
		}
		var old uint64
		switch idx {
		case -26:
			old = uint64(ci.Style)
			ci.Style = uint32(newVal)
		case -24:
			old = ci.WndProc
			ci.WndProc = newVal
			hctx.AtomWndProc[atom] = newVal
		case -14:
			old = ci.HIcon
			ci.HIcon = newVal
		case -12:
			old = ci.HCursor
			ci.HCursor = newVal
		case -10:
			old = ci.HbrBG
			ci.HbrBG = newVal
		case -34:
			old = ci.HIconSm
			ci.HIconSm = newVal
		}
		ctx.SetReturn(old)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetClassLongPtrA", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		idx := int32(ctx.Arg(1))
		newVal := ctx.Arg(2)
		atom := hctx.HwndClassAtom[hwnd]
		ci := hctx.ClassInfo[atom]
		if ci == nil {
			ctx.SetReturn(0)
			return 0
		}
		var old uint64
		switch idx {
		case -26:
			old = uint64(ci.Style)
			ci.Style = uint32(newVal)
		case -24:
			old = ci.WndProc
			ci.WndProc = newVal
			hctx.AtomWndProc[atom] = newVal
		case -14:
			old = ci.HIcon
			ci.HIcon = newVal
		case -12:
			old = ci.HCursor
			ci.HCursor = newVal
		case -10:
			old = ci.HbrBG
			ci.HbrBG = newVal
		case -34:
			old = ci.HIconSm
			ci.HIconSm = newVal
		}
		ctx.SetReturn(old)
		return 0
	})
	for _, fn := range []string{"GetClassLongA", "GetClassLongW"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			idx := int32(ctx.Arg(1))
			atom := hctx.HwndClassAtom[hwnd]
			ci := hctx.ClassInfo[atom]
			if ci == nil {
				ctx.SetReturn(0)
				return 0
			}
			var val uint64
			switch idx {
			case -26:
				val = uint64(ci.Style)
			case -24:
				val = ci.WndProc
			case -20:
				val = uint64(uint32(ci.ClsExtra))
			case -18:
				val = uint64(uint32(ci.WndExtra))
			}
			ctx.SetReturn(val)
			return 0
		})
	}
	for _, fn := range []string{"SetClassLongA", "SetClassLongW"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			idx := int32(ctx.Arg(1))
			newVal := ctx.Arg(2)
			atom := hctx.HwndClassAtom[hwnd]
			ci := hctx.ClassInfo[atom]
			if ci == nil {
				ctx.SetReturn(0)
				return 0
			}
			var old uint64
			switch idx {
			case -26:
				old = uint64(ci.Style)
				ci.Style = uint32(newVal)
			case -24:
				old = ci.WndProc
				ci.WndProc = newVal
				hctx.AtomWndProc[atom] = newVal
			}
			ctx.SetReturn(old)
			return 0
		})
	}
	for _, fn := range []string{"GetClassWord", "SetClassWord"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}
	d.RegisterAutoStubHandler(user32, "WindowFromDC", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(hctx.MainHWND)
		return 0
	})

	// -------------------------------------------------------
	// Cursor / display
	// -------------------------------------------------------
	showCursorCount := int32(0)
	d.RegisterAutoStubHandler(user32, "ShowCursor", func(ctx *ntapi.TrapContext) uint32 {
		if ctx.Arg(0) == 0 {
			showCursorCount--
		} else {
			showCursorCount++
		}
		ctx.SetReturn(uint64(int64(showCursorCount)))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetCursorPos", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL SetCursorPos(int X, int Y)
		// ReactOS: win32ss/user/ntuser/cursoricon.c
		cursorPosX = int32(ctx.Arg(0))
		cursorPosY = int32(ctx.Arg(1))
		ravelog.Logf("[user32] SetCursorPos x=%d y=%d\n", cursorPosX, cursorPosY)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetCursorInfo", func(ctx *ntapi.TrapContext) uint32 {
		p := ctx.Arg(0)
		if p != 0 {
			ctx.Mem.Write32(p, 20)           // cbSize
			ctx.Mem.Write32(p+4, 1)          // flags = CURSOR_SHOWING
			ctx.Mem.Write64(p+8, 0x00010001) // hCursor
			ctx.Mem.Write32(p+16, 0)
			ctx.Mem.Write32(p+20, 0) // pt
		}
		ctx.SetReturn(1)
		return 0
	})
	var clipCursorRect *[4]int32
	d.RegisterAutoStubHandler(user32, "ClipCursor", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL ClipCursor(const RECT *lpRect)
		// ReactOS: win32ss/user/ntuser/cursoricon.c
		pRect := ctx.Arg(0)
		if pRect == 0 {
			clipCursorRect = nil // release clip
		} else {
			l, _ := mem.Read32(pRect)
			t, _ := mem.Read32(pRect + 4)
			r, _ := mem.Read32(pRect + 8)
			b, _ := mem.Read32(pRect + 12)
			clipCursorRect = &[4]int32{int32(l), int32(t), int32(r), int32(b)}
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetClipCursor", func(ctx *ntapi.TrapContext) uint32 {
		p := ctx.Arg(0)
		if p != 0 {
			if clipCursorRect != nil {
				ctx.Mem.Write32(p, uint32(clipCursorRect[0]))
				ctx.Mem.Write32(p+4, uint32(clipCursorRect[1]))
				ctx.Mem.Write32(p+8, uint32(clipCursorRect[2]))
				ctx.Mem.Write32(p+12, uint32(clipCursorRect[3]))
			} else {
				var w, h int32 = 1920, 1080
				if wlWindow != nil {
					w, h = wlWindow.Width, wlWindow.Height
				}
				ctx.Mem.Write32(p, 0)
				ctx.Mem.Write32(p+4, 0)
				ctx.Mem.Write32(p+8, uint32(w))
				ctx.Mem.Write32(p+12, uint32(h))
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetCursor", func(ctx *ntapi.TrapContext) uint32 {
		// HCURSOR GetCursor(void)
		// ReactOS: NtUserGetCursor
		ctx.SetReturn(currentCursorHandle)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetCursorFrameInfo", func(ctx *ntapi.TrapContext) uint32 {
		// Undocumented. Returns HCURSOR of animation frame.
		// hCursor := ctx.Arg(0)
		// istep := ctx.Arg(1)  // animation step pointer
		// We don't support animated cursors - return NULL
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetCursorContents", func(ctx *ntapi.TrapContext) uint32 {
		// Undocumented NtUserSetCursorContents
		// hCursor := ctx.Arg(0)
		// pInfo := ctx.Arg(1)
		ravelog.Logf("[user32] SetCursorContents (stub)\n")
		ctx.SetReturn(1)
		return 0
	})
	mouseSwapped := false
	d.RegisterAutoStubHandler(user32, "SwapMouseButton", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL SwapMouseButton(BOOL fSwap) - returns previous state
		// ReactOS: win32ss/user/ntuser/misc.c
		prev := mouseSwapped
		mouseSwapped = ctx.Arg(0) != 0
		if prev {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "TrackMouseEvent", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: win32ss/user/ntuser/mouse.c NtUserTrackMouseEvent
		pTME := ctx.Arg(0)
		if pTME == 0 {
			ctx.SetReturn(0)
			return 0
		}
		flags, _ := mem.Read32(pTME + 4)
		hwnd, _ := mem.Read64(pTME + 8)
		// TME_QUERY (0x40000000) - return current tracking info
		if flags&0x40000000 != 0 {
			ctx.SetReturn(1)
			return 0
		}
		// TME_CANCEL (0x80000000) - cancel tracking
		if flags&0x80000000 != 0 {
			delete(hctx.TrackMouseHwnds, hwnd)
			ctx.SetReturn(1)
			return 0
		}
		// TME_LEAVE (0x02) or TME_HOVER (0x01) - record for future delivery
		hctx.TrackMouseHwnds[hwnd] = flags
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetMouseMovePointsEx", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(0xFFFFFFFF))
		return 0 // -1
	})
	d.RegisterAutoStubHandler(user32, "GetLastInputInfo", func(ctx *ntapi.TrapContext) uint32 {
		p := ctx.Arg(0)
		if p != 0 {
			ctx.Mem.Write32(p, 8)
			ctx.Mem.Write32(p+4, 0)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "MonitorFromPoint", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0x00040001)
		return 0
	})

	// -------------------------------------------------------
	// Display / monitor
	// -------------------------------------------------------
	d.RegisterAutoStubHandler(user32, "EnumDisplayMonitors", func(ctx *ntapi.TrapContext) uint32 {
		// hdc := ctx.Arg(0), lprcClip := ctx.Arg(1), lpfnEnum := ctx.Arg(2), dwData := ctx.Arg(3)
		// Would need callback trampoline to call lpfnEnum - return TRUE (no monitors enumerated)
		ctx.SetReturn(1)
		return 0
	})
	for _, fn := range []string{"EnumDisplayDevicesA", "EnumDisplayDevicesW",
		"EnumDisplaySettingsA", "EnumDisplaySettingsW", "EnumDisplaySettingsExA", "EnumDisplaySettingsExW"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}
	for _, fn := range []string{"ChangeDisplaySettingsA", "ChangeDisplaySettingsW",
		"ChangeDisplaySettingsExA", "ChangeDisplaySettingsExW"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0 // DISP_CHANGE_SUCCESSFUL
		})
	}

	// -------------------------------------------------------
	// Hooks / WinEvents
	// -------------------------------------------------------
	// ReactOS: win32ss/user/ntuser/hook.c
	// Hook chain: map from HHOOK → {hookType, proc, hMod, threadId}
	type hookEntry struct {
		hookType int32
		proc     uint64
		hMod     uint64
		threadID uint64
	}
	hookTable := map[uint64]*hookEntry{}
	var nextHookHandle uint64 = 0x00070000

	type winEventEntry struct {
		eventMin uint32
		eventMax uint32
		proc     uint64
		hMod     uint64
		threadID uint32
		flags    uint32
	}
	winEventTable := map[uint64]*winEventEntry{}
	var nextWinEventHandle uint64 = 0x00080000

	d.RegisterAutoStubHandler(user32, "SetWindowsHookA", func(ctx *ntapi.TrapContext) uint32 {
		// HHOOK SetWindowsHookA(int idHook, HOOKPROC lpfn)
		// Old-style: no hMod/threadId params (thread-local only)
		idHook := int32(ctx.Arg(0))
		lpfn := ctx.Arg(1)
		nextHookHandle++
		h := nextHookHandle
		hookTable[h] = &hookEntry{hookType: idHook, proc: lpfn}
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetWindowsHookW", func(ctx *ntapi.TrapContext) uint32 {
		idHook := int32(ctx.Arg(0))
		lpfn := ctx.Arg(1)
		nextHookHandle++
		h := nextHookHandle
		hookTable[h] = &hookEntry{hookType: idHook, proc: lpfn}
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetWinEventHook", func(ctx *ntapi.TrapContext) uint32 {
		// HWINEVENTHOOK SetWinEventHook(DWORD eventMin, DWORD eventMax,
		//   HMODULE hmod, WINEVENTPROC pfn, DWORD pid, DWORD tid, DWORD flags)
		eventMin := uint32(ctx.Arg(0))
		eventMax := uint32(ctx.Arg(1))
		hmod := ctx.Arg(2)
		pfn := ctx.Arg(3)
		tid := uint32(ctx.Arg(5))
		flags := uint32(ctx.Arg(6))
		nextWinEventHandle++
		h := nextWinEventHandle
		winEventTable[h] = &winEventEntry{
			eventMin: eventMin, eventMax: eventMax,
			proc: pfn, hMod: hmod, threadID: tid, flags: flags,
		}
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "NotifyWinEvent", func(ctx *ntapi.TrapContext) uint32 {
		// void NotifyWinEvent(DWORD event, HWND, LONG idObject, LONG idChild)
		// We don't invoke callbacks yet, but the API is void - nothing to return.
		return 0
	})
	d.RegisterAutoStubHandler(user32, "UnhookWinEvent", func(ctx *ntapi.TrapContext) uint32 {
		h := ctx.Arg(0)
		if _, ok := winEventTable[h]; ok {
			delete(winEventTable, h)
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "UnhookWindowsHook", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL UnhookWindowsHook(int nCode, HOOKPROC pfnFilterProc)
		// Old-style unhook by type+proc. Find and remove.
		nCode := int32(ctx.Arg(0))
		pfn := ctx.Arg(1)
		removed := false
		for h, entry := range hookTable {
			if entry.hookType == nCode && entry.proc == pfn {
				delete(hookTable, h)
				removed = true
				break
			}
		}
		if removed {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CallNextHookEx", func(ctx *ntapi.TrapContext) uint32 {
		// LRESULT CallNextHookEx(HHOOK hhk, int nCode, WPARAM, LPARAM)
		// We have only one hook per type, so "next" is the system default → return 0.
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "IsWinEventHookInstalled", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL IsWinEventHookInstalled(DWORD event)
		event := uint32(ctx.Arg(0))
		for _, we := range winEventTable {
			if event >= we.eventMin && event <= we.eventMax {
				ctx.SetReturn(1)
				return 0
			}
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "RegisterShellHookWindow", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		ravelog.Logf("[user32] RegisterShellHookWindow hwnd=0x%x", hwnd)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "DeregisterShellHookWindow", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		ravelog.Logf("[user32] DeregisterShellHookWindow hwnd=0x%x", hwnd)
		ctx.SetReturn(1)
		return 0
	})

	// -------------------------------------------------------
	// Properties
	// -------------------------------------------------------
	d.RegisterAutoStubHandler(user32, "SetPropA", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		lpString := ctx.Arg(1)
		hData := ctx.Arg(2)
		var name string
		if lpString < 0x10000 {
			name = fmt.Sprintf("atom:%d", lpString)
		} else {
			name = readGuestString(lpString)
		}
		m := windowProps[hwnd]
		if m == nil {
			m = make(map[string]uint64)
			windowProps[hwnd] = m
		}
		m[name] = hData
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetPropA", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		lpString := ctx.Arg(1)
		var name string
		if lpString < 0x10000 {
			name = fmt.Sprintf("atom:%d", lpString)
		} else {
			name = readGuestString(lpString)
		}
		if m, ok := windowProps[hwnd]; ok {
			ctx.SetReturn(m[name])
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "RemovePropA", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		lpString := ctx.Arg(1)
		var name string
		if lpString < 0x10000 {
			name = fmt.Sprintf("atom:%d", lpString)
		} else {
			name = readGuestString(lpString)
		}
		if m, ok := windowProps[hwnd]; ok {
			old := m[name]
			delete(m, name)
			ctx.SetReturn(old)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	for _, fn := range []string{"EnumPropsA", "EnumPropsW", "EnumPropsExA", "EnumPropsExW"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}

	// -------------------------------------------------------
	// Dialog
	// -------------------------------------------------------
	for _, fn := range []string{"DefDlgProcA", "DefDlgProcW"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}
	d.RegisterAutoStubHandler(user32, "IsDialogMessage", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL IsDialogMessageW(HWND hDlg, LPMSG lpMsg)
		// ReactOS: win32ss/user/user32/windows/dialog.c IsDialogMessageW
		// Checks if a message is for the dialog (Tab, Enter, Esc, arrow keys).
		// We check for Tab (VK_TAB=0x09) and Esc (VK_ESCAPE=0x1B) in WM_KEYDOWN.
		pMsg := ctx.Arg(1)
		if pMsg == 0 {
			ctx.SetReturn(0)
			return 0
		}
		msgID, _ := mem.Read32(pMsg + 8) // message field at offset 8
		if msgID == 0x0100 {             // WM_KEYDOWN
			wParam, _ := mem.Read64(pMsg + 12)
			vk := uint32(wParam & 0xFF)
			if vk == 0x09 || vk == 0x1B { // VK_TAB or VK_ESCAPE
				ctx.SetReturn(1) // consumed by dialog
				return 0
			}
		}
		ctx.SetReturn(0) // not a dialog message
		return 0
	})
	d.RegisterAutoStubHandler(user32, "IsDialogMessageA", func(ctx *ntapi.TrapContext) uint32 {
		// Same logic as IsDialogMessageW (ANSI version)
		pMsg := ctx.Arg(1)
		if pMsg == 0 {
			ctx.SetReturn(0)
			return 0
		}
		msgID, _ := mem.Read32(pMsg + 8)
		if msgID == 0x0100 {
			wParam, _ := mem.Read64(pMsg + 12)
			vk := uint32(wParam & 0xFF)
			if vk == 0x09 || vk == 0x1B {
				ctx.SetReturn(1)
				return 0
			}
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetDialogBaseUnits", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0x00080004)
		return 0 // MAKELONG(4,8)
	})
	d.RegisterAutoStubHandler(user32, "GetDlgItemTextA", func(ctx *ntapi.TrapContext) uint32 {
		hDlg := ctx.Arg(0)
		nIDDlgItem := ctx.Arg(1)
		lpStr := ctx.Arg(2)
		nMaxCount := int(ctx.Arg(3))
		var text string
		for h, cs := range hwndChildren {
			if cs.parentHWND == hDlg && cs.ctrlID == nIDDlgItem {
				text = hwndChildren[h].text
				break
			}
		}
		written := 0
		if lpStr != 0 && nMaxCount > 0 {
			bs := []byte(text)
			if len(bs) >= nMaxCount {
				bs = bs[:nMaxCount-1]
			}
			for i, b := range bs {
				ctx.Mem.Write8(lpStr+uint64(i), b)
				written++
			}
			ctx.Mem.Write8(lpStr+uint64(written), 0)
		}
		ctx.SetReturn(uint64(written))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetDlgItemTextA", func(ctx *ntapi.TrapContext) uint32 {
		hDlg := ctx.Arg(0)
		nIDDlgItem := ctx.Arg(1)
		lpStr := ctx.Arg(2)
		text := readGuestString(lpStr)
		for h, cs := range hwndChildren {
			if cs.parentHWND == hDlg && cs.ctrlID == nIDDlgItem {
				hwndChildren[h].text = text
				break
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	for _, fn := range []string{"GetNextDlgGroupItem", "GetNextDlgTabItem"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(ctx.Arg(1))
			return 0 // return hCtl
		})
	}
	d.RegisterAutoStubHandler(user32, "CreateDialogParamA", func(ctx *ntapi.TrapContext) uint32 {
		lpTemplate := ctx.Arg(1)
		hWndParent := ctx.Arg(2)
		lpDialogFunc := ctx.Arg(3)
		templateName := ""
		if lpTemplate < 0x10000 {
			templateName = fmt.Sprintf("#%d", lpTemplate)
		} else {
			templateName = readGuestString(lpTemplate)
		}
		hwnd := hwndAlloc()
		hwndChildren[hwnd] = &controlState{
			className:  "dialogbox",
			parentHWND: hWndParent,
			visible:    true,
		}
		ravelog.Logf("[dialog] CreateDialogParamA template=%s parent=0x%x dlgProc=0x%x → hwnd=0x%x\n",
			templateName, hWndParent, lpDialogFunc, hwnd)
		ctx.SetReturn(hwnd)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CreateDialogIndirectParamA", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := hwndAlloc()
		hwndChildren[hwnd] = &controlState{
			className: "dialogbox",
			visible:   true,
		}
		ravelog.Logf("[dialog] CreateDialogIndirectParamA → hwnd=0x%x\n", hwnd)
		ctx.SetReturn(hwnd)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CreateDialogIndirectParamAorW", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := hwndAlloc()
		hwndChildren[hwnd] = &controlState{
			className: "dialogbox",
			visible:   true,
		}
		ravelog.Logf("[dialog] CreateDialogIndirectParamAorW → hwnd=0x%x\n", hwnd)
		ctx.SetReturn(hwnd)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "DialogBoxParamA", func(ctx *ntapi.TrapContext) uint32 {
		lpTemplate := ctx.Arg(1)
		hWndParent := ctx.Arg(2)
		lpDialogFunc := ctx.Arg(3)
		dwInitParam := ctx.Arg(4)

		templateName := ""
		if lpTemplate < 0x10000 {
			templateName = fmt.Sprintf("#%d", lpTemplate)
		} else {
			templateName = readGuestString(lpTemplate)
		}
		ravelog.Logf("[dialog] DialogBoxParamA template=%s parent=0x%x dlgProc=0x%x initParam=0x%x\n",
			templateName, hWndParent, lpDialogFunc, dwInitParam)

		if lpDialogFunc == 0 {
			ctx.SetReturn(0)
			return 0
		}

		dlgHwnd := hwndAlloc()
		hwndChildren[dlgHwnd] = &controlState{
			className:  "dialogbox",
			parentHWND: hWndParent,
			visible:    true,
		}

		rw, ok := ctx.CPU.(ntapi.RegisterWriter)
		rr, ok2 := ctx.CPU.(ntapi.RegisterReader)
		if ok && ok2 {
			rsp := rr.ReadReg(4)
			retAddr, _ := mem.Read64(rsp)
			hctx.SyncStack = append(hctx.SyncStack, syncDispatchFrame{
				queue:               nil,
				retAddr:             retAddr,
				hwnd:                2,
				returnWndProcResult: false,
			})
			mem.Write64(rsp, hctx.SyncTrampoline)
			rw.WriteReg(1, dlgHwnd)
			rw.WriteReg(2, 0x0110)
			rw.WriteReg(8, 0)
			rw.WriteReg(9, dwInitParam)
			ctx.CPU.SetPC(lpDialogFunc)
			ctx.ReturnOverridden = true
			return 0
		}

		ctx.SetReturn(2)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "DialogBoxIndirectParamA", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := hwndAlloc()
		hwndChildren[hwnd] = &controlState{
			className: "dialogbox",
			visible:   true,
		}
		ravelog.Logf("[dialog] DialogBoxIndirectParamA → hwnd=0x%x\n", hwnd)
		ctx.SetReturn(hwnd)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "DialogBoxIndirectParamAorW", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := hwndAlloc()
		hwndChildren[hwnd] = &controlState{
			className: "dialogbox",
			visible:   true,
		}
		ravelog.Logf("[dialog] DialogBoxIndirectParamAorW → hwnd=0x%x\n", hwnd)
		ctx.SetReturn(hwnd)
		return 0
	})
	for _, fn := range []string{"DlgDirListA", "DlgDirListW", "DlgDirListComboBoxA",
		"DlgDirListComboBoxW", "DlgDirSelectExA", "DlgDirSelectExW",
		"DlgDirSelectComboBoxExA", "DlgDirSelectComboBoxExW"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}

	// -------------------------------------------------------
	// Menu (A variants + extensions)
	// -------------------------------------------------------
	d.RegisterAutoStubHandler(user32, "InsertMenuItemA", func(ctx *ntapi.TrapContext) uint32 {
		hMenu := ctx.Arg(0)
		lpmii := ctx.Arg(3)
		m, ok := menus[hMenu]
		if !ok {
			ctx.SetReturn(0)
			return 0
		}
		item := menuItem{}
		if lpmii != 0 {
			fMask, _ := mem.Read32(lpmii + 4)
			fType, _ := mem.Read32(lpmii + 8)
			item.flags = fType
			if fMask&0x40 != 0 { // MIIM_STRING
				dwTypeData, _ := mem.Read64(lpmii + 56)
				if dwTypeData != 0 {
					item.text = readGuestString(dwTypeData)
				}
			}
			if fMask&0x02 != 0 { // MIIM_ID
				wID, _ := mem.Read32(lpmii + 16)
				item.id = uint64(wID)
			}
			if fMask&0x04 != 0 { // MIIM_SUBMENU
				hSub, _ := mem.Read64(lpmii + 24)
				item.id = hSub
				item.flags |= 0x10
				if sub, ok2 := menus[hSub]; ok2 {
					item.submenu = sub.items
				}
			}
		}
		m.items = append(m.items, item)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "AppendMenuA", func(ctx *ntapi.TrapContext) uint32 {
		hMenu := ctx.Arg(0)
		flags := uint32(ctx.Arg(1))
		idOrSubmenu := ctx.Arg(2)
		textPtr := ctx.Arg(3)
		m, ok := menus[hMenu]
		if !ok {
			menus[hMenu] = &menuData{}
			m = menus[hMenu]
		}
		item := menuItem{flags: flags, id: idOrSubmenu}
		if textPtr != 0 && flags&0x800 == 0 { // not MF_SEPARATOR
			item.text = readGuestString(textPtr)
		}
		if flags&0x10 != 0 { // MF_POPUP
			if sub, ok2 := menus[idOrSubmenu]; ok2 {
				item.submenu = sub.items
			}
		}
		m.items = append(m.items, item)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "InsertMenuA", func(ctx *ntapi.TrapContext) uint32 {
		hMenu := ctx.Arg(0)
		flags := uint32(ctx.Arg(2))
		idOrSubmenu := ctx.Arg(3)
		textPtr := ctx.Arg(4)
		m, ok := menus[hMenu]
		if !ok {
			ctx.SetReturn(0)
			return 0
		}
		item := menuItem{flags: flags, id: idOrSubmenu}
		if textPtr != 0 && flags&0x800 == 0 {
			item.text = readGuestString(textPtr)
		}
		if flags&0x10 != 0 { // MF_POPUP
			if sub, ok2 := menus[idOrSubmenu]; ok2 {
				item.submenu = sub.items
			}
		}
		m.items = append(m.items, item)
		ctx.SetReturn(1)
		return 0
	})
	for _, fn := range []string{"ModifyMenuA", "ChangeMenuA", "ChangeMenuW"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(1)
			return 0
		})
	}
	d.RegisterAutoStubHandler(user32, "GetMenuStringA", func(ctx *ntapi.TrapContext) uint32 {
		hMenu := ctx.Arg(0)
		uIDItem := ctx.Arg(1)
		lpStr := ctx.Arg(2)
		cchMax := int(ctx.Arg(3))
		uFlags := uint32(ctx.Arg(4))
		item := findMenuItem(hMenu, uIDItem, uFlags)
		text := ""
		if item != nil {
			text = item.text
		}
		written := 0
		if lpStr != 0 && cchMax > 0 {
			bs := []byte(text)
			if len(bs) >= cchMax {
				bs = bs[:cchMax-1]
			}
			for i, b := range bs {
				ctx.Mem.Write8(lpStr+uint64(i), b)
				written++
			}
			ctx.Mem.Write8(lpStr+uint64(written), 0)
		}
		ctx.SetReturn(uint64(written))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetMenuItemID", func(ctx *ntapi.TrapContext) uint32 {
		hMenu := ctx.Arg(0)
		nPos := int(ctx.Arg(1))
		m, ok := menus[hMenu]
		if !ok || nPos < 0 || nPos >= len(m.items) {
			ctx.SetReturn(0xFFFFFFFF)
			return 0
		}
		ctx.SetReturn(m.items[nPos].id)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetMenuCheckMarkDimensions", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0x000D000D)
		return 0 // MAKELONG(13,13)
	})
	for _, fn := range []string{"GetMenuContextHelpId", "GetMenuDefaultItem"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(uint64(0xFFFFFFFF))
			return 0 // -1
		})
	}
	for _, fn := range []string{"SetMenuContextHelpId", "SetMenuDefaultItem"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(1)
			return 0
		})
	}
	d.RegisterAutoStubHandler(user32, "GetMenuBarInfo", func(ctx *ntapi.TrapContext) uint32 {
		pInfo := ctx.Arg(3) // MENUBARINFO
		if pInfo != 0 {
			// MENUBARINFO: cbSize(4)+rcBar(16)+hMenu(8)+hwndMenu(8)+fBarFocused:1+fFocused:1
			mem.Write32(pInfo, 48)   // cbSize
			mem.Write32(pInfo+4, 0)  // rcBar.left
			mem.Write32(pInfo+8, 0)  // rcBar.top
			mem.Write32(pInfo+12, 0) // rcBar.right
			mem.Write32(pInfo+16, 0) // rcBar.bottom
			mem.Write64(pInfo+24, 0) // hMenu
			mem.Write64(pInfo+32, 0) // hwndMenu
			mem.Write32(pInfo+40, 0) // flags
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetMenuItemInfoA", func(ctx *ntapi.TrapContext) uint32 {
		hMenu := ctx.Arg(0)
		item := ctx.Arg(1)
		byPos := ctx.Arg(2) != 0
		lpmii := ctx.Arg(3)
		if lpmii == 0 {
			ctx.SetReturn(0)
			return 0
		}
		m, ok := menus[hMenu]
		if !ok {
			ctx.SetReturn(0)
			return 0
		}
		var found *menuItem
		if byPos {
			idx := int(item)
			if idx >= 0 && idx < len(m.items) {
				found = &m.items[idx]
			}
		} else {
			for i := range m.items {
				if m.items[i].id == item {
					found = &m.items[i]
					break
				}
			}
		}
		if found == nil {
			ctx.SetReturn(0)
			return 0
		}
		fMask, _ := mem.Read32(lpmii + 4)
		const (
			MIIM_ID     = 0x00000002
			MIIM_TYPE   = 0x00000010
			MIIM_STRING = 0x00000040
		)
		if fMask&MIIM_ID != 0 {
			mem.Write32(lpmii+16, uint32(found.id))
		}
		if fMask&(MIIM_TYPE|MIIM_STRING) != 0 {
			dtPtr, _ := mem.Read64(lpmii + 56)
			cch, _ := mem.Read32(lpmii + 64)
			if dtPtr != 0 && cch > 0 {
				ansi := []byte(found.text)
				limit := int(cch) - 1
				if limit > len(ansi) {
					limit = len(ansi)
				}
				mem.WriteBytes(dtPtr, ansi[:limit])
				mem.Write8(dtPtr+uint64(limit), 0)
			}
			mem.Write32(lpmii+64, uint32(len(found.text)))
		}
		ctx.SetReturn(1)
		return 0
	})
	for _, fn := range []string{"GetMenuInfo", "GetMenuItemRect"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}
	d.RegisterAutoStubHandler(user32, "SetMenuInfo", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL SetMenuInfo(HMENU, LPCMENUINFO)
		// ReactOS: NtUserThunkedMenuInfo
		// MENUINFO: cbSize, fMask, dwStyle, cyMax, hbrBack, dwContextHelpID, dwMenuData
		hMenu := ctx.Arg(0)
		pInfo := ctx.Arg(1)
		if hMenu == 0 || pInfo == 0 {
			ctx.SetReturn(0)
			return 0
		}
		// Read fMask to know which fields to apply
		fMask, _ := mem.Read32(pInfo + 4)
		_ = fMask // We accept the call but don't change internal state yet
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "HiliteMenuItem", func(ctx *ntapi.TrapContext) uint32 {
		hMenu := ctx.Arg(1)
		uIDItem := ctx.Arg(2)
		uHilite := uint32(ctx.Arg(3))
		item := findMenuItem(hMenu, uIDItem, uHilite)
		if item != nil {
			if uHilite&0x0080 != 0 { // MF_HILITE
				item.flags |= 0x0080
			} else {
				item.flags &^= 0x0080
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CheckMenuRadioItem", func(ctx *ntapi.TrapContext) uint32 {
		hMenu := ctx.Arg(0)
		first := uint32(ctx.Arg(1))
		last := uint32(ctx.Arg(2))
		check := uint32(ctx.Arg(3))
		flags := uint32(ctx.Arg(4))
		m, ok := menus[hMenu]
		if !ok {
			ctx.SetReturn(0)
			return 0
		}
		const mfChecked = 0x0008
		for _, item := range m.items {
			id := uint32(item.id)
			if flags&0x0400 != 0 { // MF_BYPOSITION - skip for now
				continue
			}
			if id >= first && id <= last {
				if id == check {
					item.flags |= mfChecked | 0x0200
				} else {
					item.flags &^= mfChecked | 0x0200
				}
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "MenuItemFromPoint", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(0xFFFFFFFF))
		return 0 // -1
	})
	for _, fn := range []string{"TrackPopupMenu", "TrackPopupMenuEx"} {
		fn := fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			hMenu := ctx.Arg(0)
			uFlags := uint32(ctx.Arg(1))
			x := int32(ctx.Arg(2))
			y := int32(ctx.Arg(3))
			hwndOwner := ctx.Arg(5)
			if fn == "TrackPopupMenuEx" {
				hwndOwner = ctx.Arg(4)
			}
			const (
				TPM_RETURNCMD = 0x0100
				MF_SEPARATOR  = 0x0800
				MF_GRAYED     = 0x0001
				MF_DISABLED   = 0x0002
				MF_POPUP      = 0x0010
				WM_COMMAND    = 0x0111
			)
			if hwndOwner == 0 {
				hwndOwner = hctx.MainHWND
			}
			if wlWindow != nil {
				showPopupMenu(hMenu, hwndOwner, x, y)
				requestWindowRepaint(hwndOwner)
			}
			selected := uint64(0)
			if m, ok := menus[hMenu]; ok {
				for _, item := range m.items {
					if item.flags&(MF_SEPARATOR|MF_GRAYED|MF_DISABLED) != 0 {
						continue
					}
					if item.flags&MF_POPUP != 0 && len(item.submenu) > 0 {
						for _, sub := range item.submenu {
							if sub.flags&(MF_SEPARATOR|MF_GRAYED|MF_DISABLED) == 0 && sub.id != 0 {
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
			if uFlags&TPM_RETURNCMD != 0 {
				closePopupMenus()
				ctx.SetReturn(selected)
				return 0
			}
			if selected != 0 {
				target := hwndOwner
				hctx.MsgQueue = append(hctx.MsgQueue, queuedMsg{target, WM_COMMAND, selected, 0})
			}
			closePopupMenus()
			ctx.SetReturn(1)
			return 0
		})
	}
	for _, fn := range []string{"PaintMenuBar", "DrawMenuBarTemp", "CalcMenuBar",
		"MenuWindowProcA", "MenuWindowProcW"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}
	d.RegisterAutoStubHandler(user32, "EndMenu", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[user32] EndMenu\n")
		closePopupMenus()
		requestWindowRepaint(hctx.MainHWND)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetSystemMenu", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		hMenu := ctx.Arg(1)
		ravelog.Logf("[user32] SetSystemMenu hwnd=0x%x menu=0x%x", hwnd, hMenu)
		ctx.SetReturn(1)
		return 0
	})
	for _, fn := range []string{"LoadMenuA", "LoadMenuIndirectA", "LoadMenuIndirectW"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}

	// -------------------------------------------------------
	// SystemParametersInfoA
	// -------------------------------------------------------
	d.RegisterAutoStubHandler(user32, "SystemParametersInfoA", func(ctx *ntapi.TrapContext) uint32 {
		uiAction := ctx.Arg(0)
		pvParam := ctx.Arg(2)
		w := int32(1920)
		h := int32(1080)
		if wlWindow != nil {
			w = int32(wlWindow.Width)
			h = int32(wlWindow.Height)
		}
		writeLogFontA := func(off uint64, name string, height int32) {
			mem.Write32(pvParam+off+0, uint32(height))
			mem.Write32(pvParam+off+4, 0)
			mem.Write32(pvParam+off+8, 0)
			mem.Write32(pvParam+off+12, 0)
			mem.Write32(pvParam+off+16, 400) // lfWeight = FW_NORMAL
			mem.Write8(pvParam+off+20, 0)    // lfItalic
			mem.Write8(pvParam+off+21, 0)    // lfUnderline
			mem.Write8(pvParam+off+22, 0)    // lfStrikeOut
			mem.Write8(pvParam+off+23, 1)    // lfCharSet = DEFAULT_CHARSET
			mem.Write8(pvParam+off+24, 0)    // lfOutPrecision
			mem.Write8(pvParam+off+25, 0)    // lfClipPrecision
			mem.Write8(pvParam+off+26, 5)    // lfQuality = CLEARTYPE_QUALITY
			mem.Write8(pvParam+off+27, 0x22) // lfPitchAndFamily
			// LOGFONTA: lfFaceName is 32 bytes of ANSI chars at +28
			for i, ch := range name {
				mem.Write8(pvParam+off+28+uint64(i), uint8(ch))
			}
			mem.Write8(pvParam+off+28+uint64(len(name)), 0)
		}
		switch uiAction {
		case 0x0026: // SPI_GETDRAGFULLWINDOWS
			if pvParam != 0 {
				mem.Write32(pvParam, 1)
			}
		case 0x0029: // SPI_GETNONCLIENTMETRICS - NONCLIENTMETRICSA (500 bytes: no iPaddedBorderWidth pre-Vista)
			if pvParam != 0 {
				mem.Write32(pvParam+0, 500) // cbSize
				mem.Write32(pvParam+4, 1)   // iBorderWidth
				mem.Write32(pvParam+8, 17)  // iScrollWidth
				mem.Write32(pvParam+12, 17) // iScrollHeight
				mem.Write32(pvParam+16, 36) // iCaptionWidth
				mem.Write32(pvParam+20, 36) // iCaptionHeight
				writeLogFontA(24, "Segoe UI", -12)
				mem.Write32(pvParam+84, 36) // iSmCaptionWidth (+0x54)
				mem.Write32(pvParam+88, 36) // iSmCaptionHeight (+0x58)
				writeLogFontA(92, "Segoe UI", -12)
				mem.Write32(pvParam+152, 36) // iMenuWidth (+0x98)
				mem.Write32(pvParam+156, 36) // iMenuHeight (+0x9C)
				writeLogFontA(160, "Segoe UI", -12)
				writeLogFontA(220, "Segoe UI", -12) // lfStatusFont
				writeLogFontA(280, "Segoe UI", -12) // lfMessageFont
			}
		case 0x002B: // SPI_GETMINIMIZEDMETRICS
			if pvParam != 0 {
				mem.Write32(pvParam+0, 20)
				mem.Write32(pvParam+4, 160)
				mem.Write32(pvParam+8, 0)
				mem.Write32(pvParam+12, 0)
				mem.Write32(pvParam+16, 0)
			}
		case 0x001F: // SPI_GETICONTITLELOGFONT - LOGFONTA (60 bytes)
			if pvParam != 0 {
				writeLogFontA(0, "Segoe UI", -12)
			}
		case 0x0030: // SPI_GETWORKAREA
			if pvParam != 0 {
				mem.Write32(pvParam+0, 0)
				mem.Write32(pvParam+4, 0)
				mem.Write32(pvParam+8, uint32(w))
				mem.Write32(pvParam+12, uint32(h))
			}
		case 0x0048: // SPI_GETANIMATION
			if pvParam != 0 {
				mem.Write32(pvParam, 8)
				mem.Write32(pvParam+4, 0)
			}
		case 0x004A: // SPI_GETFONTSMOOTHING
			if pvParam != 0 {
				mem.Write32(pvParam, 1)
			}
		case 0x006A: // SPI_GETMENUSHOWDELAY
			if pvParam != 0 {
				mem.Write32(pvParam, 400)
			}
		case 0x200A: // SPI_GETFONTSMOOTHINGTYPE
			if pvParam != 0 {
				mem.Write32(pvParam, 2) // FE_FONTSMOOTHINGCLEARTYPE
			}
		default:
			ravelog.Logf("[spi] SystemParametersInfoA unknown uiAction=0x%x pvParam=0x%x\n", uiAction, pvParam)
		}
		ctx.SetReturn(1)
		return 0
	})

	// -------------------------------------------------------
	// Drawing (A variants)
	// -------------------------------------------------------
	d.RegisterAutoStubHandler(user32, "DrawTextA", func(ctx *ntapi.TrapContext) uint32 {
		if wlWindow == nil {
			ctx.SetReturn(1)
			return 0
		}
		// Convert ANSI to UTF-16 and draw via existing DC
		pStr, nCount := ctx.Arg(1), int(int32(ctx.Arg(2)))
		var bs []byte
		for i := 0; i < 4096; i++ {
			b, _ := mem.Read8(ctx.Arg(1) + uint64(i))
			if b == 0 && (nCount < 0 || i >= nCount) {
				break
			}
			if nCount >= 0 && i >= nCount {
				break
			}
			bs = append(bs, b)
			_ = pStr
		}
		_ = bs
		// Fallback: just return a valid height
		ctx.SetReturn(16)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "DrawTextExA", func(ctx *ntapi.TrapContext) uint32 {
		if wlWindow == nil {
			ctx.SetReturn(1)
			return 0
		}
		hdc := ctx.Arg(0)
		lpStr := ctx.Arg(1)
		nCount := int(int32(ctx.Arg(2)))
		lpRect := ctx.Arg(3)
		uFormat := uint32(ctx.Arg(4))
		dc := getDC(hdc)
		text := readGuestString(lpStr)
		if nCount >= 0 && nCount < len(text) {
			text = text[:nCount]
		}
		f := dc.Font
		if f == nil {
			f = gdi.DefaultFont()
		}
		lineH := f.Height
		if lineH == 0 {
			lineH = 16
		}
		if lpRect != 0 {
			l, _ := mem.Read32(lpRect)
			t, _ := mem.Read32(lpRect + 4)
			r, _ := mem.Read32(lpRect + 8)
			x := int32(l) + 2
			y := int32(t)
			tw := int32(len([]rune(text))) * f.AveCharWidth
			w := int32(r) - int32(l)
			if uFormat&0x1 != 0 { // DT_CENTER
				x = int32(l) + (w-tw)/2
			}
			if uFormat&0x4 != 0 { // DT_VCENTER
				if b, err := mem.Read32(lpRect + 12); err == nil {
					y = int32(t) + (int32(b)-int32(t)-lineH)/2
				}
			}
			dc.TextOut(x, y, text, false)
		}
		ctx.SetReturn(uint64(lineH))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "DrawStateA", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		x := int32(ctx.Arg(5))
		y := int32(ctx.Arg(6))
		ravelog.Logf("[user32] DrawStateA hdc=0x%x x=%d y=%d", hdc, x, y)
		ctx.SetReturn(1)
		return 0
	})
	for _, fn := range []string{"DrawCaption", "DrawCaptionTempA", "DrawCaptionTempW",
		"DrawFrame", "DrawAnimatedRects"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(1)
			return 0
		})
	}
	d.RegisterAutoStubHandler(user32, "GrayStringA", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		lpData := ctx.Arg(3)
		nCount := int32(ctx.Arg(4))
		x := int32(ctx.Arg(5))
		y := int32(ctx.Arg(6))
		dc := getDC(hdc)
		if dc != nil && dc.Target != nil && lpData != 0 {
			var txt string
			if nCount > 0 {
				// Read nCount bytes from guest as ANSI string
				bs := make([]byte, nCount)
				for i := int32(0); i < nCount; i++ {
					b, _ := ctx.Mem.Read8(lpData + uint64(i))
					bs[i] = b
				}
				txt = string(bs)
			} else {
				txt = readGuestString(lpData)
			}
			oldColor := dc.TextColor
			dc.TextColor = 0x808080
			dc.TextOut(x, y, txt, false)
			dc.TextColor = oldColor
		}
		ctx.SetReturn(1)
		return 0
	})
	for _, fn := range []string{"TabbedTextOutA", "GetTabbedTextExtentA", "GetTabbedTextExtentW"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}
	d.RegisterAutoStubHandler(user32, "ExcludeUpdateRgn", func(ctx *ntapi.TrapContext) uint32 {
		// int ExcludeUpdateRgn(HDC hDC, HWND hWnd) - returns SIMPLEREGION
		_ = ctx.Arg(0)   // hDC
		_ = ctx.Arg(1)   // hWnd
		ctx.SetReturn(1) // SIMPLEREGION
		return 0
	})

	// -------------------------------------------------------
	// Misc utility
	// -------------------------------------------------------
	d.RegisterAutoStubHandler(user32, "MessageBeep", func(ctx *ntapi.TrapContext) uint32 {
		uType := uint32(ctx.Arg(0))
		ravelog.Logf("[user32] MessageBeep type=0x%x", uType)
		ctx.SetReturn(1)
		return 0
	})
	for _, fn := range []string{"MessageBoxExA", "MessageBoxExW",
		"MessageBoxIndirectA", "MessageBoxIndirectW",
		"MessageBoxTimeoutA", "MessageBoxTimeoutW", "SoftModalMessageBox"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0 // IDOK
		})
	}
	d.RegisterAutoStubHandler(user32, "LoadStringA", func(ctx *ntapi.TrapContext) uint32 {
		uID := uint32(ctx.Arg(1))
		lpBuffer := ctx.Arg(2)
		cchBufferMax := int(int32(ctx.Arg(3)))
		s, _, _ := peLoadStringW(uID)
		if s == "" || lpBuffer == 0 {
			ctx.SetReturn(0)
			return 0
		}
		if cchBufferMax == 0 {
			ctx.SetReturn(0)
			return 0
		}
		ansi := []byte(s)
		n := len(ansi)
		if n >= cchBufferMax {
			n = cchBufferMax - 1
		}
		mem.WriteBytes(lpBuffer, ansi[:n])
		mem.Write8(lpBuffer+uint64(n), 0)
		ctx.SetReturn(uint64(n))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "RegisterWindowMessageA", func(ctx *ntapi.TrapContext) uint32 {
		p := ctx.Arg(0)
		hash := uint64(0xC000)
		for i := uint64(0); i < 64; i++ {
			b, _ := mem.Read8(p + i)
			if b == 0 {
				break
			}
			hash = hash*31 + uint64(b)
		}
		ctx.SetReturn((hash & 0x3FFF) + 0xC000)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "ExitWindowsEx", func(ctx *ntapi.TrapContext) uint32 {
		uFlags := uint32(ctx.Arg(0))
		dwReason := uint32(ctx.Arg(1))
		ravelog.Logf("[user32] ExitWindowsEx flags=0x%x reason=0x%x (ignored)", uFlags, dwReason)
		ctx.SetReturn(1)
		return 0
	})
	for _, fn := range []string{"FlashWindow", "FlashWindowEx"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}
	d.RegisterAutoStubHandler(user32, "AnimateWindow", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		dwTime := uint32(ctx.Arg(1))
		dwFlags := uint32(ctx.Arg(2))
		ravelog.Logf("[user32] AnimateWindow hwnd=0x%x time=%d flags=0x%x", hwnd, dwTime, dwFlags)
		queuePaint(hwnd)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "LockWorkStation", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[user32] LockWorkStation (ignored)\n")
		ctx.SetReturn(1)
		return 0
	})
	// Layered window attributes tracking.
	// ReactOS: win32ss/user/ntuser/layered.c
	type layeredAttrs struct {
		colorKey uint32
		alpha    uint8
		flags    uint32
	}
	layeredWindows := map[uint64]*layeredAttrs{}

	d.RegisterAutoStubHandler(user32, "SetLayeredWindowAttributes", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		colorKey := uint32(ctx.Arg(1))
		alpha := uint8(ctx.Arg(2))
		flags := uint32(ctx.Arg(3))
		layeredWindows[hwnd] = &layeredAttrs{colorKey: colorKey, alpha: alpha, flags: flags}
		ctx.SetReturn(1)
		return 0
	})
	for _, fn := range []string{"UpdateLayeredWindow", "UpdateLayeredWindowIndirect"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(1)
			return 0
		})
	}
	d.RegisterAutoStubHandler(user32, "GetLayeredWindowAttributes", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL GetLayeredWindowAttributes(HWND, COLORREF*, BYTE*, DWORD*)
		hwnd := ctx.Arg(0)
		pColorKey := ctx.Arg(1)
		pAlpha := ctx.Arg(2)
		pFlags := ctx.Arg(3)
		la, ok := layeredWindows[hwnd]
		if !ok {
			ctx.SetReturn(0) // not a layered window
			return 0
		}
		if pColorKey != 0 {
			mem.Write32(pColorKey, la.colorKey)
		}
		if pAlpha != 0 {
			mem.Write8(pAlpha, la.alpha)
		}
		if pFlags != 0 {
			mem.Write32(pFlags, la.flags)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "DisableProcessWindowsGhosting", func(ctx *ntapi.TrapContext) uint32 {
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetGuiResources", func(ctx *ntapi.TrapContext) uint32 {
		// DWORD GetGuiResources(HANDLE hProcess, DWORD uiFlags)
		uiFlags := uint32(ctx.Arg(1))
		count := uint32(len(hwndChildren))
		if uiFlags == 1 { // GR_GDIOBJECTS
			count = 50
		}
		ctx.SetReturn(uint64(count))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetGUIThreadInfo", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL GetGUIThreadInfo(DWORD idThread, PGUITHREADINFO pgui)
		pgui := ctx.Arg(1)
		if pgui != 0 {
			mem.Write32(pgui, 48)                // cbSize
			mem.Write32(pgui+4, 0)               // flags
			mem.Write64(pgui+8, hctx.ActiveHwnd) // hwndActive
			mem.Write64(pgui+16, hctx.FocusHwnd) // hwndFocus
			mem.Write64(pgui+24, 0)              // hwndCapture
			mem.Write64(pgui+32, 0)              // hwndMenuOwner
			mem.Write64(pgui+40, 0)              // hwndMoveSize
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetComboBoxInfo", func(ctx *ntapi.TrapContext) uint32 {
		pInfo := ctx.Arg(1) // COMBOBOXINFO
		if pInfo != 0 {
			// COMBOBOXINFO: cbSize(4)+rcItem(16)+rcButton(16)+stateButton(4)+hwndCombo(8)+hwndItem(8)+hwndList(8)
			hwnd := ctx.Arg(0)
			mem.Write32(pInfo, 64)      // cbSize
			mem.Write64(pInfo+44, hwnd) // hwndCombo
			mem.Write64(pInfo+52, 0)    // hwndItem
			mem.Write64(pInfo+60, 0)    // hwndList
		}
		ctx.SetReturn(1)
		return 0
	})
	for _, fn := range []string{"GetListBoxInfo", "GetScrollBarInfo", "GetTitleBarInfo"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}
	for _, fn := range []string{"AllowSetForegroundWindow", "LockSetForegroundWindow"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(1)
			return 0
		})
	}
	d.RegisterAutoStubHandler(user32, "ShowStartGlass", func(ctx *ntapi.TrapContext) uint32 {
		return 0
	})
	for _, fn := range []string{"ArrangeIconicWindows", "CascadeChildWindows",
		"CascadeWindows", "TileChildWindows", "TileWindows"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}
	d.RegisterAutoStubHandler(user32, "RegisterHotKey", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		id := int32(ctx.Arg(1))
		fsModifiers := uint32(ctx.Arg(2))
		vk := uint32(ctx.Arg(3))
		ravelog.Logf("[user32] RegisterHotKey hwnd=0x%x id=%d mod=0x%x vk=0x%x", hwnd, id, fsModifiers, vk)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "UnregisterHotKey", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		id := int32(ctx.Arg(1))
		ravelog.Logf("[user32] UnregisterHotKey hwnd=0x%x id=%d", hwnd, id)
		ctx.SetReturn(1)
		return 0
	})
	for _, fn := range []string{"RegisterDeviceNotificationA", "RegisterDeviceNotificationW"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x00090001)
			return 0
		})
	}
	d.RegisterAutoStubHandler(user32, "UnregisterDeviceNotification", func(ctx *ntapi.TrapContext) uint32 {
		handle := ctx.Arg(0)
		ravelog.Logf("[user32] UnregisterDeviceNotification handle=0x%x", handle)
		ctx.SetReturn(1)
		return 0
	})
	for _, fn := range []string{"TranslateAccelerator", "TranslateAcceleratorA", "TranslateMDISysAccel"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}
	d.RegisterAutoStubHandler(user32, "AttachThreadInput", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL AttachThreadInput(DWORD idAttach, DWORD idAttachTo, BOOL fAttach)
		// ReactOS: NtUserAttachThreadInput
		// We run single-threaded, so all threads share one input queue already.
		ctx.SetReturn(1) // success
		return 0
	})
	var inputBlocked bool
	d.RegisterAutoStubHandler(user32, "BlockInput", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL BlockInput(BOOL fBlockIt)
		// ReactOS: NtUserBlockInput
		fBlock := ctx.Arg(0) != 0
		if fBlock == inputBlocked {
			ctx.SetReturn(0) // already in requested state
		} else {
			inputBlocked = fBlock
			ctx.SetReturn(1)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "DragDetect", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL DragDetect(HWND hwnd, POINT pt)
		_ = ctx.Arg(0)   // hwnd
		_ = ctx.Arg(1)   // pt packed as POINT
		ctx.SetReturn(0) // no drag detected
		return 0
	})
	d.RegisterAutoStubHandler(user32, "DragObject", func(ctx *ntapi.TrapContext) uint32 {
		// DWORD DragObject(HWND hwndParent, HWND hwndFrom, UINT fmt, ULONG_PTR data, HCURSOR hcur)
		_ = ctx.Arg(0)
		_ = ctx.Arg(1)
		ravelog.Logf("[user32] DragObject (stub)\n")
		ctx.SetReturn(0)
		return 0
	})

	// -------------------------------------------------------
	// Window class (ANSI registration)
	// -------------------------------------------------------
	d.RegisterAutoStubHandler(user32, "RegisterClassA", func(ctx *ntapi.TrapContext) uint32 {
		// WNDCLASSA layout is identical to WNDCLASSW but lpszMenuName/lpszClassName are ANSI
		pClass := ctx.Arg(0)
		a := hctx.NextAtom
		hctx.NextAtom++
		if pClass != 0 {
			style, _ := mem.Read32(pClass)
			wndProc, _ := mem.Read64(pClass + 8)
			cbClsExtra, _ := mem.Read32(pClass + 16)
			cbWndExtra, _ := mem.Read32(pClass + 20)
			hInst, _ := mem.Read64(pClass + 24)
			hIcon, _ := mem.Read64(pClass + 32)
			hCursor, _ := mem.Read64(pClass + 40)
			hBrush, _ := mem.Read64(pClass + 48)
			lpMenuName, _ := mem.Read64(pClass + 56)
			lpName, _ := mem.Read64(pClass + 64)
			hctx.AtomWndProc[a] = wndProc
			if hBrush > 0 && hBrush <= 30 {
				hctx.ClassBrush[a] = uint32(hBrush)
			}
			name := readGuestString(lpName)
			if name != "" {
				hctx.ClassNameAtom[name] = a
			}
			hctx.ClassInfo[a] = &registeredClassInfo{
				Style: style, WndProc: wndProc,
				ClsExtra: int32(cbClsExtra), WndExtra: int32(cbWndExtra),
				HInstance: hInst, HIcon: hIcon, HCursor: hCursor,
				HbrBG: hBrush, MenuName: lpMenuName, ClassName: name,
				Atom: a,
			}
			if lpMenuName != 0 && mainModule != nil {
				var menuID uint32
				if lpMenuName < 0x10000 {
					menuID = uint32(lpMenuName)
				} else {
					menuName := readGuestString(lpMenuName)
					if id, err := strconv.ParseUint(menuName, 10, 32); err == nil {
						menuID = uint32(id)
					}
				}
				if menuID != 0 {
					if md := peLoadMenuResource(menuID); md != nil {
						h := gdiAlloc()
						menus[h] = md
						hctx.ClassMenuHandle[a] = h
					}
				}
			}
			ravelog.Logf("[wndclass] RegisterClassA %q atom=0x%x wndProc=0x%x\n", name, a, wndProc)
		}
		ctx.SetReturn(uint64(a))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "RegisterClassExA", func(ctx *ntapi.TrapContext) uint32 {
		// WNDCLASSEXA has cbSize(4)+style(4) prefix and hIconSm(8) suffix
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
			lpMenuName, _ := mem.Read64(pClass + 56)
			lpName, _ := mem.Read64(pClass + 64)
			hIconSm, _ := mem.Read64(pClass + 72)
			hctx.AtomWndProc[a] = wndProc
			if hBrush > 0 && hBrush <= 30 {
				hctx.ClassBrush[a] = uint32(hBrush)
			}
			name := readGuestString(lpName)
			if name != "" {
				hctx.ClassNameAtom[name] = a
			}
			hctx.ClassInfo[a] = &registeredClassInfo{
				Style: style, WndProc: wndProc,
				ClsExtra: int32(cbClsExtra), WndExtra: int32(cbWndExtra),
				HInstance: hInst, HIcon: hIcon, HCursor: hCursor,
				HbrBG: hBrush, MenuName: lpMenuName, ClassName: name,
				HIconSm: hIconSm, Atom: a,
			}
			ravelog.Logf("[wndclass] RegisterClassExA %q atom=0x%x wndProc=0x%x\n", name, a, wndProc)
		}
		ctx.SetReturn(uint64(a))
		return 0
	})
	for _, fn := range []string{"UnregisterClassA", "UnregisterClassW"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(1)
			return 0
		})
	}
	d.RegisterAutoStubHandler(user32, "CreateWindowExA", func(ctx *ntapi.TrapContext) uint32 {
		// CreateWindowExA: convert ANSI class/window name to UTF-16, then delegate to CreateWindowExW logic.
		// ReactOS: win32ss/user/user32/windows/window.c CreateWindowExA → CreateWindowExW
		hwnd := hwndAlloc()
		lpClassName := ctx.Arg(1)
		style := uint32(ctx.Arg(3))

		var className string
		var classAtomForHwnd uint16
		if lpClassName != 0 && lpClassName < 0x10000 {
			classAtomForHwnd = uint16(lpClassName)
			if wp, ok := hctx.AtomWndProc[classAtomForHwnd]; ok {
				hwndWndProc[hwnd] = wp
			}
			className = fmt.Sprintf("atom:0x%x", lpClassName)
		} else if lpClassName != 0 {
			className = readGuestString(lpClassName)
			if a, ok := hctx.ClassNameAtom[className]; ok {
				classAtomForHwnd = a
				if wp, ok2 := hctx.AtomWndProc[a]; ok2 {
					hwndWndProc[hwnd] = wp
				}
			}
		}
		if classAtomForHwnd != 0 {
			hctx.HwndClassAtom[hwnd] = classAtomForHwnd
		}
		wp := hwndWndProc[hwnd]
		parentHwndLog := ctx.Arg(8)
		ravelog.Logf("[wndclass] CreateWindowExA class=%q hwnd=0x%x parent=0x%x wndProc=0x%x style=0x%x\n", className, hwnd, parentHwndLog, wp, style)

		const wsChild = 0x40000000
		if style&wsChild != 0 {
			cx := int32(ctx.Arg(4))
			cy := int32(ctx.Arg(5))
			cw := int32(ctx.Arg(6))
			ch := int32(ctx.Arg(7))
			parentHwnd := ctx.Arg(8)
			if cx < 0 || cx > 0x7FFF {
				cx = 0
			}
			if cy < 0 || cy > 0x7FFF {
				cy = 0
			}
			var defW, defH int32 = 800, 600
			if wlWindow != nil {
				defW, defH = wlWindow.Width, wlWindow.Height
			}
			if cw < 0 || cw > 0x7FFF {
				cw = 0
			}
			if ch < 0 || ch > 0x7FFF {
				ch = 0
			}
			lClassName := strings.ToLower(className)
			if lClassName == "msctls_statusbar32" {
				const sbHeight int32 = 20
				cx, cy = 0, defH-sbHeight
				cw, ch = defW, sbHeight
			} else {
				ox, oy := clientAreaOrigin(parentHwnd)
				cx += ox
				cy += oy
			}
			windowName := readGuestString(ctx.Arg(2))
			dwExStyle := uint32(ctx.Arg(0))
			hMenu := ctx.Arg(9)
			hwndChildren[hwnd] = &controlState{
				className:  lClassName,
				parentHWND: parentHwnd,
				ctrlID:     hMenu,
				x:          cx, y: cy, w: cw, h: ch,
				style:   style,
				exStyle: dwExStyle,
				text:    windowName,
				visible: style&0x10000000 != 0,
			}
			initBuiltinControlState(hwndChildren[hwnd])
			windowLongPtr[hwnd] = map[int32]uint64{-16: uint64(style), -20: uint64(dwExStyle)}
			win32.Global.Create(hwnd, lClassName, cx, cy, cw, ch, style, dwExStyle, parentHwnd)
			if lClassName == "edit" && hctx.FocusHwnd == 0 {
				hctx.FocusHwnd = hwnd
			}
		}

		// Create Wayland window for first top-level (same as W variant)
		if wlDisplay != nil && wlWindow == nil {
			if style&wsChild == 0 {
				title := readGuestString(ctx.Arg(2))
				if title == "" {
					title = "govm"
				}
				var w, h int32 = 800, 600
				if nw := int32(ctx.Arg(6)); nw > 0 && nw < 0x7FFF {
					w = nw
				}
				if nh := int32(ctx.Arg(7)); nh > 0 && nh < 0x7FFF {
					h = nh
				}
				ncTop := int32(0)
				if wlDisplay.HasNoSSD() {
					var r win32.Rect
					exStyle := uint32(ctx.Arg(0))
					win32.AdjustWindowRectEx(&r, style, false, exStyle)
					ncTop = -r.Top
					if ncTop < 0 {
						ncTop = 0
					}
				}
				if win, err := wlDisplay.CreateWindow(title, w, h, ncTop); err == nil {
					wlWindow = win
					hctx.WlWindow = win
					if hctx.OnWlWindowSet != nil {
						hctx.OnWlWindowSet(win)
					}
					hctx.MainHWND = hwnd
					hctx.MainTitle = title
					exStyle := uint32(ctx.Arg(0))
					windowLongPtr[hwnd] = map[int32]uint64{-16: uint64(style), -20: uint64(exStyle)}
					win32.Global.Create(hwnd, strings.ToLower(className), 0, 0, w, h+ncTop, style, exStyle, 0)
					ravelog.Logf("[wl] window created (A): %q %dx%d hwnd=0x%x ncTop=%d\n", title, w, h, hwnd, ncTop)
					hMenu := ctx.Arg(9)
					if hMenu != 0 {
						if _, ok := menus[hMenu]; ok {
							hwndMenuBar[hwnd] = hMenu
						}
					}
					if _, hasMenu := hwndMenuBar[hwnd]; !hasMenu && lpClassName != 0 {
						var classAtom uint16
						if lpClassName < 0x10000 {
							classAtom = uint16(lpClassName)
						} else {
							classAtom = hctx.ClassNameAtom[readGuestString(lpClassName)]
						}
						if mh, ok := hctx.ClassMenuHandle[classAtom]; ok {
							hwndMenuBar[hwnd] = mh
						}
					}
				}
			}
		}
		// Sync dispatch WM_NCCREATE + WM_CREATE
		if wp, hasWP := hwndWndProc[hwnd]; hasWP && wp != 0 {
			cs := scratchAlloc(80)
			mem.Write64(cs+0, ctx.Arg(11))
			mem.Write64(cs+8, ctx.Arg(10))
			mem.Write64(cs+16, ctx.Arg(9))
			mem.Write64(cs+24, ctx.Arg(8))
			mem.Write32(cs+32, uint32(ctx.Arg(7)))
			mem.Write32(cs+36, uint32(ctx.Arg(6)))
			mem.Write32(cs+40, uint32(ctx.Arg(5)))
			mem.Write32(cs+44, uint32(ctx.Arg(4)))
			mem.Write32(cs+48, style)
			mem.Write32(cs+52, 0)
			mem.Write64(cs+56, ctx.Arg(2))
			mem.Write64(cs+64, ctx.Arg(1))
			mem.Write32(cs+72, uint32(ctx.Arg(0)))

			rw, ok := ctx.CPU.(ntapi.RegisterWriter)
			rr, ok2 := ctx.CPU.(ntapi.RegisterReader)
			if ok && ok2 {
				rsp := rr.ReadReg(4)
				retAddr, _ := mem.Read64(rsp)
				hctx.SyncStack = append(hctx.SyncStack, syncDispatchFrame{
					queue:   []syncDispatch{{wndProc: wp, hwnd: hwnd, msg: 0x0001, wParam: 0, lParam: cs}},
					retAddr: retAddr,
				})
				rw.WriteReg(1, hwnd)
				rw.WriteReg(2, 0x0081)
				rw.WriteReg(8, 0)
				rw.WriteReg(9, cs)
				mem.Write64(rsp, hctx.SyncTrampoline)
				rw.WriteReg(16, wp)
			}
		}
		ctx.SetReturn(hwnd)
		return 0
	})

	// -------------------------------------------------------
	// DDE (all stub → 0)
	// -------------------------------------------------------
	for _, fn := range []string{"DdeAbandonTransaction", "DdeAccessData", "DdeAddData",
		"DdeClientTransaction", "DdeCmpStringHandles", "DdeConnect", "DdeConnectList",
		"DdeCreateDataHandle", "DdeCreateStringHandleA", "DdeCreateStringHandleW",
		"DdeDisconnect", "DdeDisconnectList", "DdeEnableCallback", "DdeFreeDataHandle",
		"DdeFreeStringHandle", "DdeGetData", "DdeGetLastError", "DdeGetQualityOfService",
		"DdeImpersonateClient", "DdeInitializeA", "DdeInitializeW", "DdeKeepStringHandle",
		"DdeNameService", "DdePostAdvise", "DdeQueryConvInfo", "DdeQueryNextServer",
		"DdeQueryStringA", "DdeQueryStringW", "DdeReconnect", "DdeSetQualityOfService",
		"DdeSetUserHandle", "DdeUnaccessData", "DdeUninitialize",
		"FreeDDElParam", "PackDDElParam", "ReuseDDElParam", "UnpackDDElParam",
		"ImpersonateDdeClientWindow"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}

	// -------------------------------------------------------
	// Desktop / WindowStation (all stub)
	// -------------------------------------------------------
	for _, fn := range []string{"CloseDesktop", "CloseWindowStation", "CreateDesktopA",
		"CreateDesktopW", "CreateWindowStationA", "CreateWindowStationW",
		"GetInputDesktop", "GetProcessWindowStation", "GetThreadDesktop",
		"GetUserObjectInformationA", "GetUserObjectInformationW", "GetUserObjectSecurity",
		"LockWindowStation", "OpenDesktopA", "OpenDesktopW", "OpenInputDesktop",
		"OpenWindowStationA", "OpenWindowStationW", "SetProcessWindowStation",
		"SetThreadDesktop", "SetUserObjectInformationA", "SetUserObjectInformationW",
		"SetUserObjectSecurity", "SwitchDesktop", "UnlockWindowStation",
		"EnumDesktopsA", "EnumDesktopsW", "EnumDesktopWindows",
		"EnumWindowStationsA", "EnumWindowStationsW", "GetWinStationInfo"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}

	// -------------------------------------------------------
	// Raw input (all stub)
	// -------------------------------------------------------
	for _, fn := range []string{"GetRawInputBuffer", "GetRawInputData",
		"GetRawInputDeviceInfoA", "GetRawInputDeviceInfoW", "GetRawInputDeviceList",
		"GetRegisteredRawInputDevices", "RegisterRawInputDevices", "DefRawInputProc"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}

	// -------------------------------------------------------
	// IME / WINNLS / misc internal
	// -------------------------------------------------------
	for _, fn := range []string{"IMPGetIMEA", "IMPGetIMEW", "IMPQueryIMEA", "IMPQueryIMEW",
		"IMPSetIMEA", "IMPSetIMEW", "CliImmSetHotKey",
		"WINNLSEnableIME", "WINNLSGetEnableStatus", "WINNLSGetIMEHotkey"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}
	for _, fn := range []string{"SendIMEMessageExA", "SendIMEMessageExW"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}

	// -------------------------------------------------------
	// Accelerators / icons (stubs)
	// -------------------------------------------------------
	for _, fn := range []string{"CopyAcceleratorTableA", "CopyAcceleratorTableW",
		"CreateAcceleratorTableA", "LoadAcceleratorsA"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}
	// ─── Icon/Image/Cursor loading ───────────────────────────────────────
	d.RegisterAutoStubHandler(user32, "LoadIconA", func(ctx *ntapi.TrapContext) uint32 {
		// Same logic as LoadIconW - return dummy icon handle
		hInst := ctx.Arg(0)
		nameArg := ctx.Arg(1)
		if hInst == 0 && nameArg >= 32512 && nameArg <= 32522 {
			// System icon (IDI_APPLICATION etc.)
			ctx.SetReturn(0x00020000 + nameArg)
			return 0
		}
		// App icon from PE resource
		if nameArg < 0x10000 && mainModule != nil && (hInst == mainModule.BaseAddr || hInst == 0) {
			_, _, ok := peLoadRawResource(mainModule.BaseAddr, mainModule.ResourceDirRVA, 14 /*RT_GROUP_ICON*/, uint32(nameArg))
			if ok {
				ctx.SetReturn(0x00020000 + nameArg)
				return 0
			}
		}
		ctx.SetReturn(0x00020001) // dummy icon
		return 0
	})
	d.RegisterAutoStubHandler(user32, "LoadImageA", func(ctx *ntapi.TrapContext) uint32 {
		hInst := ctx.Arg(0)
		nameArg := ctx.Arg(1)
		imgType := ctx.Arg(2)
		// IMAGE_BITMAP=0: try to load from PE resource (same as LoadImageW)
		if imgType == 0 && nameArg < 0x10000 && mainModule != nil &&
			(hInst == mainModule.BaseAddr || hInst == 0) {
			resID := uint32(nameArg)
			addr, sz, ok2 := peLoadRawResource(mainModule.BaseAddr, mainModule.ResourceDirRVA, 2 /*RT_BITMAP*/, resID)
			if ok2 {
				slots := decodeDIBSlots(addr, sz, 0, 0)
				h := hctx.NextBitmapHandle
				hctx.NextBitmapHandle += 2
				bd := &bitmapHandleData{slots: slots}
				if len(slots) > 0 {
					bd.w = len(slots[0])
				}
				bitmapHandles[h] = bd
				ravelog.Logf("[loadimage] LoadImageA IMAGE_BITMAP resID=0x%x → handle=0x%x\n", resID, h)
				ctx.SetReturn(h)
				return 0
			}
		}
		// IMAGE_ICON=1: return dummy icon handle
		if imgType == 1 {
			if nameArg < 0x10000 {
				ctx.SetReturn(0x00020000 + nameArg)
			} else {
				ctx.SetReturn(0x00020001)
			}
			return 0
		}
		// IMAGE_CURSOR=2: return dummy cursor handle
		if imgType == 2 {
			ctx.SetReturn(0x00010001)
			return 0
		}
		ctx.SetReturn(0x00030001) // fallback dummy
		return 0
	})
	d.RegisterAutoStubHandler(user32, "LoadBitmapA", func(ctx *ntapi.TrapContext) uint32 {
		hInst := ctx.Arg(0)
		nameArg := ctx.Arg(1)
		if nameArg < 0x10000 && mainModule != nil && (hInst == mainModule.BaseAddr || hInst == 0) {
			resID := uint32(nameArg)
			addr, sz, ok2 := peLoadRawResource(mainModule.BaseAddr, mainModule.ResourceDirRVA, 2, resID)
			if ok2 {
				slots := decodeDIBSlots(addr, sz, 0, 0)
				h := hctx.NextBitmapHandle
				hctx.NextBitmapHandle += 2
				bitmapHandles[h] = &bitmapHandleData{slots: slots, w: len(slots[0])}
				ctx.SetReturn(h)
				return 0
			}
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CopyImage", func(ctx *ntapi.TrapContext) uint32 {
		h := ctx.Arg(0)
		ctx.SetReturn(h) // return same handle (shallow copy)
		return 0
	})
	// Icon/Cursor handle table - track created icons with unique handles.
	// ReactOS: win32ss/user/ntuser/cursoricon.c
	type iconEntry struct {
		isIcon bool
		cx, cy int32
	}
	iconTable := map[uint64]*iconEntry{}
	var nextIconHandle uint64 = 0x00020010

	d.RegisterAutoStubHandler(user32, "CreateIconFromResourceEx", func(ctx *ntapi.TrapContext) uint32 {
		// HICON CreateIconFromResourceEx(PBYTE presbits, DWORD dwResSize, BOOL fIcon,
		//   DWORD dwVer, int cxDesired, int cyDesired, UINT Flags)
		fIcon := ctx.Arg(2) != 0
		cxDesired := int32(ctx.Arg(4))
		cyDesired := int32(ctx.Arg(5))
		if cxDesired == 0 {
			cxDesired = 32
		}
		if cyDesired == 0 {
			cyDesired = 32
		}
		nextIconHandle++
		h := nextIconHandle
		iconTable[h] = &iconEntry{isIcon: fIcon, cx: cxDesired, cy: cyDesired}
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CreateIconFromResource", func(ctx *ntapi.TrapContext) uint32 {
		// HICON CreateIconFromResource(PBYTE presbits, DWORD dwResSize, BOOL fIcon, DWORD dwVer)
		fIcon := ctx.Arg(2) != 0
		nextIconHandle++
		h := nextIconHandle
		iconTable[h] = &iconEntry{isIcon: fIcon, cx: 32, cy: 32}
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CreateCursor", func(ctx *ntapi.TrapContext) uint32 {
		// HCURSOR CreateCursor(HINSTANCE, int xHot, int yHot, int nWidth, int nHeight,
		//   const VOID *pvANDPlane, const VOID *pvXORPlane)
		nw := int32(ctx.Arg(3))
		nh := int32(ctx.Arg(4))
		nextIconHandle++
		h := nextIconHandle
		iconTable[h] = &iconEntry{isIcon: false, cx: nw, cy: nh}
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CreateIcon", func(ctx *ntapi.TrapContext) uint32 {
		// HICON CreateIcon(HINSTANCE, int nWidth, int nHeight, BYTE cPlanes, BYTE cBitsPixel,
		//   const BYTE *lpbANDbits, const BYTE *lpbXORbits)
		nw := int32(ctx.Arg(1))
		nh := int32(ctx.Arg(2))
		nextIconHandle++
		h := nextIconHandle
		iconTable[h] = &iconEntry{isIcon: true, cx: nw, cy: nh}
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "LookupIconIdFromDirectory", func(ctx *ntapi.TrapContext) uint32 {
		// int LookupIconIdFromDirectory(PBYTE presbits, BOOL fIcon)
		// ReactOS: LookupIconIdFromDirectoryEx with default sizes
		// Parse GRPICONDIR: idReserved(2), idType(2), idCount(2), then GRPICONDIRENTRY[idCount]
		presbits := ctx.Arg(0)
		if presbits == 0 {
			ctx.SetReturn(0)
			return 0
		}
		idCount, _ := mem.Read16(presbits + 4)
		if idCount == 0 {
			ctx.SetReturn(0)
			return 0
		}
		// Return the nID of the first entry (offset 12 in GRPICONDIRENTRY, at presbits+6+0*14+12)
		nID, _ := mem.Read16(presbits + 6 + 12)
		ctx.SetReturn(uint64(nID))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "LookupIconIdFromDirectoryEx", func(ctx *ntapi.TrapContext) uint32 {
		// int LookupIconIdFromDirectoryEx(PBYTE presBits, BOOL fIcon, int cxDesired, int cyDesired, UINT Flags)
		// ReactOS: win32ss/user/user32/windows/cursoricon.c
		presBits := ctx.Arg(0)
		fIcon := ctx.Arg(1) != 0
		cxDesired := int32(ctx.Arg(2))
		cyDesired := int32(ctx.Arg(3))
		ravelog.Logf("[user32] LookupIconIdFromDirectoryEx bits=0x%x icon=%v cx=%d cy=%d\n",
			presBits, fIcon, cxDesired, cyDesired)
		ctx.SetReturn(1) // first resource ID
		return 0
	})
	for _, fn := range []string{"PrivateExtractIconExA", "PrivateExtractIconExW",
		"PrivateExtractIconsA", "PrivateExtractIconsW"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // no icons extracted
			return 0
		})
	}
	d.RegisterAutoStubHandler(user32, "LoadCursorFromFileA", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0x00010001)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "LoadCursorFromFileW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0x00010001)
		return 0
	})

	// -------------------------------------------------------
	// MDI / misc window management
	// -------------------------------------------------------
	for _, fn := range []string{"CreateMDIWindowA", "CreateMDIWindowW",
		"DefFrameProcA", "DefFrameProcW", "DefMDIChildProcA", "DefMDIChildProcW",
		"TranslateMDISysAccel"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}
	d.RegisterAutoStubHandler(user32, "DefWindowProcA", defWindowProcFn)
	d.RegisterAutoStubHandler(user32, "CallWindowProcA", func(ctx *ntapi.TrapContext) uint32 {
		lpPrevWndFunc := ctx.Arg(0)
		hwnd := ctx.Arg(1)
		msg := uint32(ctx.Arg(2))
		wParam := ctx.Arg(3)
		lParam := ctx.Arg(4)

		ravelog.Logf("[callwndproc] CallWindowProcA prev=0x%x hwnd=0x%x msg=0x%x\n", lpPrevWndFunc, hwnd, msg)

		// Try built-in control handler first
		if result, handled := builtinWndProc(hwnd, msg, wParam, lParam); handled {
			ctx.SetReturn(result)
			return 0
		}

		// Dispatch synchronously to the specified WndProc (same as SendMessageW pattern)
		if lpPrevWndFunc != 0 {
			rw, okW := ctx.CPU.(ntapi.RegisterWriter)
			rr, okR := ctx.CPU.(ntapi.RegisterReader)
			if okW && okR {
				rsp := rr.ReadReg(4) // RSP
				retAddr, _ := mem.Read64(rsp)
				if retAddr >= 0x1000000 {
					hctx.SyncStack = append(hctx.SyncStack, syncDispatchFrame{
						queue:               []syncDispatch{},
						retAddr:             retAddr,
						hwnd:                hwnd,
						returnWndProcResult: true,
					})
					mem.Write64(rsp, hctx.SyncTrampoline)
					rw.WriteReg(1, hwnd)
					rw.WriteReg(2, uint64(msg))
					rw.WriteReg(8, wParam)
					rw.WriteReg(9, lParam)
					ctx.CPU.SetPC(lpPrevWndFunc)
					ctx.ReturnOverridden = true
					return 0
				}
			}
		}

		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CallWindowProcW", func(ctx *ntapi.TrapContext) uint32 {
		lpPrevWndFunc := ctx.Arg(0)
		hwnd := ctx.Arg(1)
		msg := uint32(ctx.Arg(2))
		wParam := ctx.Arg(3)
		lParam := ctx.Arg(4)

		ravelog.Logf("[callwndproc] CallWindowProcW prev=0x%x hwnd=0x%x msg=0x%x\n", lpPrevWndFunc, hwnd, msg)

		// Try built-in control handler first
		if result, handled := builtinWndProc(hwnd, msg, wParam, lParam); handled {
			ctx.SetReturn(result)
			return 0
		}

		// Dispatch synchronously to the specified WndProc (same as SendMessageW pattern)
		if lpPrevWndFunc != 0 {
			rw, okW := ctx.CPU.(ntapi.RegisterWriter)
			rr, okR := ctx.CPU.(ntapi.RegisterReader)
			if okW && okR {
				rsp := rr.ReadReg(4) // RSP
				retAddr, _ := mem.Read64(rsp)
				if retAddr >= 0x1000000 {
					hctx.SyncStack = append(hctx.SyncStack, syncDispatchFrame{
						queue:               []syncDispatch{},
						retAddr:             retAddr,
						hwnd:                hwnd,
						returnWndProcResult: true,
					})
					mem.Write64(rsp, hctx.SyncTrampoline)
					rw.WriteReg(1, hwnd)
					rw.WriteReg(2, uint64(msg))
					rw.WriteReg(8, wParam)
					rw.WriteReg(9, lParam)
					ctx.CPU.SetPC(lpPrevWndFunc)
					ctx.ReturnOverridden = true
					return 0
				}
			}
		}

		ctx.SetReturn(0)
		return 0
	})
	for _, fn := range []string{"CallMsgFilter", "CallMsgFilterA", "CallMsgFilterW"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}
	d.RegisterAutoStubHandler(user32, "EnumThreadWindows", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL EnumThreadWindows(DWORD dwThreadId, WNDENUMPROC lpfn, LPARAM lParam)
		// ReactOS: NtUserBuildHwndList
		// Since we're single-threaded, enumerate all top-level windows.
		lpEnumFunc := ctx.Arg(1)
		lParam := ctx.Arg(2)
		if lpEnumFunc == 0 {
			ctx.SetReturn(0)
			return 0
		}
		all := win32.Global.AllWindows()
		if len(all) == 0 {
			ctx.SetReturn(1)
			return 0
		}
		rw, ok := ctx.CPU.(ntapi.RegisterWriter)
		rr, ok2 := ctx.CPU.(ntapi.RegisterReader)
		if !ok || !ok2 {
			ctx.SetReturn(1)
			return 0
		}
		rsp := rr.ReadReg(4)
		retAddr, _ := mem.Read64(rsp)
		queue := make([]syncDispatch, len(all))
		for i, h := range all {
			queue[i] = syncDispatch{wndProc: lpEnumFunc, hwnd: h, msg: lParam}
		}
		hctx.SyncStack = append(hctx.SyncStack, syncDispatchFrame{
			queue:   queue[1:],
			retAddr: retAddr,
			hwnd:    1,
		})
		rsp -= 8
		mem.Write64(rsp, hctx.SyncTrampoline)
		rw.WriteReg(4, rsp)
		rw.WriteReg(1, queue[0].hwnd)
		rw.WriteReg(2, uint64(queue[0].msg))
		rw.WriteReg(8, 0)
		rw.WriteReg(9, 0)
		ctx.CPU.SetPC(queue[0].wndProc)
		ctx.ReturnOverridden = true
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SwitchToThisWindow", func(ctx *ntapi.TrapContext) uint32 {
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetDoubleClickTime", func(ctx *ntapi.TrapContext) uint32 {
		newTime := uint32(ctx.Arg(0))
		if newTime > 0 {
			doubleClickTime = newTime
		}
		ctx.SetReturn(1)
		return 0
	})

	// -------------------------------------------------------
	// WinHelp / string conversion helpers
	// -------------------------------------------------------
	for _, fn := range []string{"WinHelpA", "WinHelpW"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}
	for _, fn := range []string{"wvsprintfA", "wvsprintfW", "MB_GetString",
		"MBToWCSEx", "WCSToMBEx"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}
	for _, fn := range []string{"AlignRects", "BuildReasonArray", "DestroyReasons",
		"ReasonCodeNeedsBugID", "ReasonCodeNeedsComment", "RecordShutdownReason",
		"GetReasonTitleFromReasonCode", "DisplayExitWindowsWarnings"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}

	// -------------------------------------------------------
	// Internal / undocumented
	// -------------------------------------------------------
	for _, fn := range []string{"UserClientDllInitialize", "User32InitializeImmEntryTable",
		"ClientThreadSetup", "CtxInitUser32", "CreateSystemThreads",
		"InitializeLpkHooks", "InitializeWin32EntryTable",
		"UserHandleGrantAccess", "UserLpkPSMTextOut", "UserLpkTabbedTextOut",
		"UserRealizePalette", "UserRegisterWowHandlers",
		"UpdatePerUserSystemParameters", "Win32PoolAllocationStats",
		"AllowForegroundActivation", "DeviceEventWorker",
		"EnterReaderModeHelper", "GetAppCompatFlags", "GetAppCompatFlags2",
		"GetAltTabInfo", "GetAltTabInfoA", "GetAltTabInfoW",
		"GetInputDesktop", "GetInternalWindowPos", "SetInternalWindowPos",
		"GetProgmanWindow", "SetProgmanWindow", "GetShellWindow",
		"SetShellWindow", "SetShellWindowEx", "GetTaskmanWindow", "SetTaskmanWindow",
		"SetLogonNotifyWindow", "RegisterLogonProcess", "RegisterServicesProcess",
		"RegisterSystemThread", "RegisterTasklist", "RegisterMessagePumpHook",
		"UnregisterMessagePumpHook", "RegisterUserApiHook", "UnregisterUserApiHook",
		"SetConsoleReserveKeys", "SetDebugErrorLevel", "SetLastErrorEx",
		"SetDeskWallpaper", "SetKeyboardState", "SetMessageQueue",
		"SetProcessDefaultLayout", "GetProcessDefaultLayout",
		"SetWindowStationUser", "LoadLocalFonts", "LoadRemoteFonts",
		"KillSystemTimer", "SetSystemTimer",
		"ScrollChildren", "EndTask", "IsWinEventHookInstalled",
		"GetAltTabInfo", "EditWndProc",
		"ClientThreadSetup", "CsrBroadcastSystemMessageExW"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}
	for _, fn := range []string{"SetSysColors", "SetSysColorsTemp", "SetSystemCursor"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(1)
			return 0
		})
	}

	// DPI-aware functions (Win10+) - apps resolve at runtime via GetProcAddress.
	// Using RegisterDynamicHandler to make them discoverable.
	nextDynID := uint32(ntapi.DynExportIDBase)
	dpiStub96 := func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(96) // standard DPI
		return 0
	}
	d.RegisterDynamicHandler(mem, user32, "GetDpiForSystem", nextDynID, dpiStub96)
	nextDynID++
	d.RegisterDynamicHandler(mem, user32, "GetDpiForWindow", nextDynID, dpiStub96)
	nextDynID++
	d.RegisterDynamicHandler(mem, user32, "GetSystemMetricsForDpi", nextDynID, func(ctx *ntapi.TrapContext) uint32 {
		// Fall through to GetSystemMetrics behavior with standard DPI
		ctx.SetReturn(0)
		return 0
	})
	nextDynID++
	d.RegisterDynamicHandler(mem, user32, "AdjustWindowRectExForDpi", nextDynID, func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1) // TRUE
		return 0
	})
	nextDynID++
	d.RegisterDynamicHandler(mem, user32, "SetThreadDpiAwarenessContext", nextDynID, func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(ctx.Arg(0)) // return previous context = same as requested
		return 0
	})
	nextDynID++
	d.RegisterDynamicHandler(mem, user32, "GetWindowDpiAwarenessContext", nextDynID, func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0xFFFFFFFFFFFFFFFD) // DPI_AWARENESS_CONTEXT_SYSTEM_AWARE (-3)
		return 0
	})
	nextDynID++
	d.RegisterDynamicHandler(mem, user32, "AreDpiAwarenessContextsEqual", nextDynID, func(ctx *ntapi.TrapContext) uint32 {
		if ctx.Arg(0) == ctx.Arg(1) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	nextDynID++
	d.RegisterDynamicHandler(mem, user32, "ChangeWindowMessageFilterEx", nextDynID, func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1) // TRUE
		return 0
	})
	nextDynID++
	d.RegisterDynamicHandler(mem, user32, "SetCoalescableTimer", nextDynID, func(ctx *ntapi.TrapContext) uint32 {
		// Delegate to SetTimer behavior - return a timer ID
		ctx.SetReturn(ctx.Arg(1)) // nIDEvent
		return 0
	})
	nextDynID++
	_ = nextDynID
}

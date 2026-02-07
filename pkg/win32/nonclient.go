//go:build guest_windows

package win32

// Non-client area helpers - ported from ReactOS
// win32ss/user/user32/windows/nonclient.c

// UserHasWindowEdge returns true when the window style combination produces
// a raised 3-D window edge.  Mirrors ReactOS UserHasWindowEdge.
func UserHasWindowEdge(style, exStyle uint32) bool {
	if style&WS_MINIMIZE != 0 {
		return true
	}
	if exStyle&WS_EX_DLGMODALFRAME != 0 {
		return true
	}
	if exStyle&WS_EX_STATICEDGE != 0 {
		return false
	}
	if style&WS_THICKFRAME != 0 {
		return true
	}
	caption := style & WS_CAPTION
	return caption == WS_DLGFRAME || caption == WS_CAPTION
}

// BorderSize returns the horizontal and vertical border sizes (cx, cy) in
// pixels for the given style/exStyle combination.
// Mirrors ReactOS UserGetWindowBorders (SIZE variant).
func BorderSize(style, exStyle uint32) (cx, cy int32) {
	border := int32(0)
	if UserHasWindowEdge(style, exStyle) {
		border += 2
	} else if exStyle&WS_EX_STATICEDGE != 0 {
		border += 1
	}
	if exStyle&WS_EX_CLIENTEDGE != 0 {
		border += 2
	}
	if style&WS_CAPTION != 0 || exStyle&WS_EX_DLGMODALFRAME != 0 {
		border++
	}
	cx = border
	cy = border
	if style&WS_THICKFRAME != 0 && style&WS_MINIMIZE == 0 {
		cx += int32(GetSystemMetrics(SM_CXFRAME)) - int32(GetSystemMetrics(SM_CXDLGFRAME))
		cy += int32(GetSystemMetrics(SM_CYFRAME)) - int32(GetSystemMetrics(SM_CYDLGFRAME))
	}
	cx *= int32(GetSystemMetrics(SM_CXBORDER))
	cy *= int32(GetSystemMetrics(SM_CYBORDER))
	return
}

// AdjustWindowRectEx adjusts a client rect to include the non-client area.
// Mirrors ReactOS RealAdjustWindowRectEx in nonclient.c.
//
//	lpRect:   on input = desired client rect, on output = required window rect.
//	style:    window style (WS_* flags).
//	hasMenu:  true if window has a menu bar.
//	exStyle:  extended window style (WS_EX_* flags).
func AdjustWindowRectEx(r *Rect, style uint32, hasMenu bool, exStyle uint32) bool {
	if r == nil {
		return false
	}
	if hasMenu {
		r.Top -= int32(GetSystemMetrics(SM_CYMENU))
	}
	if (style & WS_CAPTION) == WS_CAPTION {
		if exStyle&WS_EX_TOOLWINDOW != 0 {
			r.Top -= int32(GetSystemMetrics(SM_CYSMCAPTION))
		} else {
			r.Top -= int32(GetSystemMetrics(SM_CYCAPTION))
		}
	}
	bx, by := BorderSize(style, exStyle)
	InflateRect(r, bx, by)
	return true
}

// AdjustWindowRect is AdjustWindowRectEx with exStyle=0.
func AdjustWindowRect(r *Rect, style uint32, hasMenu bool) bool {
	return AdjustWindowRectEx(r, style, hasMenu, 0)
}

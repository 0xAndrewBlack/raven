//go:build guest_windows

// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright: see COPYING in the ReactOS source root.
// Upstream programmer: Casper S. Hornstrup (2001).
// Derived from ReactOS win32ss/user/user32/windows/winpos.c.
// Upstream: https://github.com/reactos/reactos/tree/dacf2a6c47fa562799f9c8a41ab6d5c558556558

package win32

// Coordinate transform utilities - ported from ReactOS
// win32ss/user/user32/windows/winpos.c

// ClientToScreen converts a point from client coordinates of hwnd to
// screen coordinates, exactly as ReactOS BOOL ClientToScreen(HWND,LPPOINT):
//
//	lpPoint->x += Wnd->rcClient.left
//	lpPoint->y += Wnd->rcClient.top
func ClientToScreen(hwnd uint64, x, y int32) (int32, int32) {
	wnd := Global.Get(hwnd)
	if wnd == nil {
		return x, y
	}
	if wnd.ExStyle&WS_EX_LAYOUTRTL != 0 {
		x = wnd.RcClient.Right - x
	} else {
		x += wnd.RcClient.Left
	}
	y += wnd.RcClient.Top
	return x, y
}

// ScreenToClient converts a point from screen coordinates to client
// coordinates of hwnd:
//
//	lpPoint->x -= Wnd->rcClient.left
//	lpPoint->y -= Wnd->rcClient.top
func ScreenToClient(hwnd uint64, x, y int32) (int32, int32) {
	wnd := Global.Get(hwnd)
	if wnd == nil {
		return x, y
	}
	if wnd.ExStyle&WS_EX_LAYOUTRTL != 0 {
		x = wnd.RcClient.Right - x
	} else {
		x -= wnd.RcClient.Left
	}
	y -= wnd.RcClient.Top
	return x, y
}

// MapWindowPoints converts nPoints points from the coordinate space of
// fromHWND to the coordinate space of toHWND.
// Pass fromHWND=0 or toHWND=0 to use screen coordinates for that end.
// Returns MAKELONG(delta.x, delta.y) as a packed int32.
//
// Ported from ReactOS MapWindowPoints in winpos.c.
func MapWindowPoints(fromHWND, toHWND uint64, pts [][2]int32) int32 {
	var deltaX, deltaY int32
	change := int32(1)
	mirrorFrom, mirrorTo := false, false

	if fromHWND != 0 {
		from := Global.Get(fromHWND)
		if from != nil {
			if from.ExStyle&WS_EX_LAYOUTRTL != 0 {
				mirrorFrom = true
				change = -change
				deltaX = -from.RcClient.Right
			} else {
				deltaX = from.RcClient.Left
			}
			deltaY = from.RcClient.Top
		}
	}

	if toHWND != 0 {
		to := Global.Get(toHWND)
		if to != nil {
			if to.ExStyle&WS_EX_LAYOUTRTL != 0 {
				mirrorTo = true
				change = -change
				deltaX += change * to.RcClient.Right
			} else {
				deltaX -= change * to.RcClient.Left
			}
			deltaY -= to.RcClient.Top
		}
	}

	for i := range pts {
		pts[i][0] = (pts[i][0] + deltaX) * change
		pts[i][1] += deltaY
	}

	// Special case: if both ends mirrored and exactly 2 points (a RECT),
	// ensure left ≤ right.
	if (mirrorFrom || mirrorTo) && len(pts) == 2 {
		if pts[0][0] > pts[1][0] {
			pts[0][0], pts[1][0] = pts[1][0], pts[0][0]
		}
	}

	// Return MAKELONG(loword(deltaX), loword(deltaY))
	return int32(uint16(deltaX)) | (int32(uint16(deltaY)) << 16)
}

// GetClientRect fills r with the client-area dimensions (origin always 0,0).
// Mirrors ReactOS: *lpRect = Wnd->rcClient; OffsetRect(lpRect, -left, -top).
func GetClientRect(hwnd uint64) Rect {
	wnd := Global.Get(hwnd)
	if wnd == nil {
		return Rect{}
	}
	w := wnd.RcClient.Width()
	h := wnd.RcClient.Height()
	if w < 0 {
		w = 0
	}
	if h < 0 {
		h = 0
	}
	return Rect{0, 0, w, h}
}

// GetWindowRect returns the window's bounding rect in screen coordinates.
func GetWindowRect(hwnd uint64) Rect {
	wnd := Global.Get(hwnd)
	if wnd == nil {
		return Rect{}
	}
	return wnd.RcWindow
}

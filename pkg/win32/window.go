//go:build guest_windows

// Package win32 provides a user32-compatible Win32 window management layer.
// Ported from ReactOS win32ss/user/user32/windows/.
package win32

import "sync"

// Window styles (WS_*)
const (
	WS_OVERLAPPED       = 0x00000000
	WS_POPUP            = 0x80000000
	WS_CHILD            = 0x40000000
	WS_MINIMIZE         = 0x20000000
	WS_VISIBLE          = 0x10000000
	WS_DISABLED         = 0x08000000
	WS_CLIPSIBLINGS     = 0x04000000
	WS_CLIPCHILDREN     = 0x02000000
	WS_MAXIMIZE         = 0x01000000
	WS_CAPTION          = 0x00C00000
	WS_BORDER           = 0x00800000
	WS_DLGFRAME         = 0x00400000
	WS_VSCROLL          = 0x00200000
	WS_HSCROLL          = 0x00100000
	WS_SYSMENU          = 0x00080000
	WS_THICKFRAME       = 0x00040000
	WS_MINIMIZEBOX      = 0x00020000
	WS_MAXIMIZEBOX      = 0x00010000
	WS_OVERLAPPEDWINDOW = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU |
		WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX

	// Extended styles (WS_EX_*)
	WS_EX_DLGMODALFRAME    = 0x00000001
	WS_EX_STATICEDGE       = 0x00020000
	WS_EX_CLIENTEDGE       = 0x00000200
	WS_EX_TOOLWINDOW       = 0x00000080
	WS_EX_LAYERED          = 0x00080000
	WS_EX_LAYOUTRTL        = 0x00400000
	WS_EX_CONTROLPARENT    = 0x00010000
	WS_EX_APPWINDOW        = 0x00040000
	WS_EX_WINDOWEDGE       = 0x00000100
	WS_EX_OVERLAPPEDWINDOW = WS_EX_WINDOWEDGE | WS_EX_CLIENTEDGE

	// GetWindowLong indices
	GWL_STYLE      = -16
	GWL_EXSTYLE    = -20
	GWL_ID         = -12
	GWL_HWNDPARENT = -8
	GWL_USERDATA   = -21
	GWLP_WNDPROC   = -4
	GWLP_HINSTANCE = -6
	// GWLP_ID == GWL_ID == -12
	GWLP_HWNDPARENT = -8
	GWLP_USERDATA   = -21
)

// Rect mirrors Windows RECT: left, top, right, bottom.
type Rect struct {
	Left, Top, Right, Bottom int32
}

func (r *Rect) Width() int32  { return r.Right - r.Left }
func (r *Rect) Height() int32 { return r.Bottom - r.Top }
func (r *Rect) Empty() bool   { return r.Left >= r.Right || r.Top >= r.Bottom }

// Window holds the per-HWND state tracked by our emulated user32.
// Mirrors ReactOS WNDOBJ / WND structure fields that are relevant
// for userspace coordinate math and paint cycle management.
type Window struct {
	// rcWindow: bounding rectangle of the entire window in screen coords.
	RcWindow Rect
	// rcClient: bounding rectangle of the client area in screen coords.
	// For coordinate transforms: ClientToScreen adds rcClient.{Left,Top}.
	RcClient Rect

	Style   uint32
	ExStyle uint32
	ID      uint32
	Parent  uint64 // HWND of parent window

	ClassName string

	// WindowLong slots (GWL_* / GWLP_* indices).
	// Keyed by the index value (negative for predefined slots).
	LongPtr map[int32]uint64

	// Dirty update region (for InvalidateRect / GetUpdateRect / BeginPaint).
	Dirty     bool
	DirtyRect Rect
}

// Manager is the global window table.
// All methods are goroutine-safe via mu.
type Manager struct {
	mu      sync.RWMutex
	windows map[uint64]*Window // key = HWND value
}

var Global = &Manager{
	windows: make(map[uint64]*Window),
}

// Create registers a new window.
func (m *Manager) Create(hwnd uint64, className string, x, y, w, h int32, style, exStyle uint32, parent uint64) *Window {
	wnd := &Window{
		ClassName: className,
		Style:     style,
		ExStyle:   exStyle,
		Parent:    parent,
		LongPtr:   make(map[int32]uint64),
	}
	m.UpdatePos(wnd, x, y, w, h)
	m.mu.Lock()
	m.windows[hwnd] = wnd
	m.mu.Unlock()
	return wnd
}

// UpdatePos recomputes rcWindow and rcClient from screen position + size + style.
// ReactOS: NC client rect = window rect minus borders and caption.
func (m *Manager) UpdatePos(wnd *Window, x, y, w, h int32) {
	wnd.RcWindow = Rect{x, y, x + w, y + h}
	bx, by := BorderSize(wnd.Style, wnd.ExStyle)
	captionH := int32(0)
	if (wnd.Style & WS_CAPTION) == WS_CAPTION {
		if wnd.ExStyle&WS_EX_TOOLWINDOW != 0 {
			captionH = int32(GetSystemMetrics(SM_CYSMCAPTION))
		} else {
			captionH = int32(GetSystemMetrics(SM_CYCAPTION))
		}
	}
	wnd.RcClient = Rect{
		Left:   x + bx,
		Top:    y + by + captionH,
		Right:  x + w - bx,
		Bottom: y + h - by,
	}
}

// Get returns the Window for hwnd, or nil.
func (m *Manager) Get(hwnd uint64) *Window {
	m.mu.RLock()
	wnd := m.windows[hwnd]
	m.mu.RUnlock()
	return wnd
}

// Destroy removes the window.
func (m *Manager) Destroy(hwnd uint64) {
	m.mu.Lock()
	delete(m.windows, hwnd)
	m.mu.Unlock()
}

func (m *Manager) SetParent(hwnd, parent uint64) (uint64, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	wnd := m.windows[hwnd]
	if wnd == nil {
		return 0, false
	}
	oldParent := wnd.Parent
	wnd.Parent = parent
	return oldParent, true
}

func (m *Manager) Parent(hwnd uint64) (uint64, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	wnd := m.windows[hwnd]
	if wnd == nil {
		return 0, false
	}
	return wnd.Parent, true
}

func (m *Manager) SetDisabled(hwnd uint64, disabled bool) (bool, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	wnd := m.windows[hwnd]
	if wnd == nil {
		return false, false
	}
	wasDisabled := wnd.Style&WS_DISABLED != 0
	if disabled {
		wnd.Style |= WS_DISABLED
	} else {
		wnd.Style &^= WS_DISABLED
	}
	wnd.LongPtr[GWL_STYLE] = uint64(wnd.Style)
	return wasDisabled, true
}

// SetLong stores a window long value (GWL_* index).
func (m *Manager) SetLong(hwnd uint64, index int32, value uint64) {
	m.mu.Lock()
	if wnd, ok := m.windows[hwnd]; ok {
		wnd.LongPtr[index] = value
		switch index {
		case GWL_STYLE:
			wnd.Style = uint32(value)
		case GWL_EXSTYLE:
			wnd.ExStyle = uint32(value)
		case GWL_ID:
			wnd.ID = uint32(value)
		}
	}
	m.mu.Unlock()
}

// GetLong retrieves a window long value.
func (m *Manager) GetLong(hwnd uint64, index int32) uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if wnd, ok := m.windows[hwnd]; ok {
		switch index {
		case GWL_STYLE:
			return uint64(wnd.Style)
		case GWL_EXSTYLE:
			return uint64(wnd.ExStyle)
		case GWL_ID: // == GWLP_ID == -12
			return uint64(wnd.ID)
		}
		return wnd.LongPtr[index]
	}
	return 0
}

// Invalidate marks a rect dirty (InvalidateRect).
// If rect is nil the entire client area is invalidated.
func (m *Manager) Invalidate(hwnd uint64, rect *Rect) {
	m.mu.Lock()
	if wnd, ok := m.windows[hwnd]; ok {
		if rect == nil {
			wnd.DirtyRect = Rect{0, 0, wnd.RcClient.Width(), wnd.RcClient.Height()}
		} else {
			if !wnd.Dirty {
				wnd.DirtyRect = *rect
			} else {
				// Union with existing dirty rect.
				if rect.Left < wnd.DirtyRect.Left {
					wnd.DirtyRect.Left = rect.Left
				}
				if rect.Top < wnd.DirtyRect.Top {
					wnd.DirtyRect.Top = rect.Top
				}
				if rect.Right > wnd.DirtyRect.Right {
					wnd.DirtyRect.Right = rect.Right
				}
				if rect.Bottom > wnd.DirtyRect.Bottom {
					wnd.DirtyRect.Bottom = rect.Bottom
				}
			}
		}
		wnd.Dirty = true
	}
	m.mu.Unlock()
}

// Validate clears the dirty flag (ValidateRect).
func (m *Manager) Validate(hwnd uint64) {
	m.mu.Lock()
	if wnd, ok := m.windows[hwnd]; ok {
		wnd.Dirty = false
		wnd.DirtyRect = Rect{}
	}
	m.mu.Unlock()
}

// GetUpdateRect returns the current dirty rect (in client coords) and whether dirty.
func (m *Manager) GetUpdateRect(hwnd uint64) (Rect, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if wnd, ok := m.windows[hwnd]; ok {
		return wnd.DirtyRect, wnd.Dirty
	}
	return Rect{}, false
}

// AllWindows returns a snapshot of all registered HWNDs.
func (m *Manager) AllWindows() []uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]uint64, 0, len(m.windows))
	for h := range m.windows {
		out = append(out, h)
	}
	return out
}

// ChildrenOf returns all HWNDs whose parent matches the given handle.
func (m *Manager) ChildrenOf(parent uint64) []uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []uint64
	for h, wnd := range m.windows {
		if wnd.Parent == parent {
			out = append(out, h)
		}
	}
	return out
}

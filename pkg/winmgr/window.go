package winmgr

// Window-management operations: geometry, z-order, visibility, GetWindowLong,
// GetWindow navigation, and hit-testing. All take the manager lock.

// Non-client metrics used to derive the client rect from the window rect. These
// match the engine's simple frame model; real user32 NC painting runs on top.
const (
	borderW  = 1
	captionH = 19
)

// WindowRect returns the window's screen rectangle and true, or false if unknown.
func (m *Manager) WindowRect(h HWND) (Rect, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	w := m.windows[h]
	if w == nil {
		return Rect{}, false
	}
	return w.rect, true
}

// ClientRect returns the client rectangle (origin at 0,0, like GetClientRect).
func (m *Manager) ClientRect(h HWND) (Rect, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	w := m.windows[h]
	if w == nil {
		return Rect{}, false
	}
	return clientRectOf(w), true
}

func clientRectOf(w *Window) Rect {
	cw, ch := w.rect.Width(), w.rect.Height()
	if w.Style&WS_CHILD == 0 { // top-level: subtract frame + caption
		if w.Style&(WS_BORDER|WS_THICKFRAME|WS_DLGFRAME) != 0 {
			cw -= 2 * borderW
			ch -= 2 * borderW
		}
		if w.Style&WS_CAPTION == WS_CAPTION {
			ch -= captionH
		}
	}
	if cw < 0 {
		cw = 0
	}
	if ch < 0 {
		ch = 0
	}
	return Rect{0, 0, cw, ch}
}

// MoveWindow sets the window rectangle (screen coords). Returns false if unknown.
func (m *Manager) MoveWindow(h HWND, x, y, w_, h_ int32) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	w := m.windows[h]
	if w == nil {
		return false
	}
	w.rect = Rect{x, y, x + w_, y + h_}
	return true
}

// SetWindowPos moves/sizes/reorders a window per the Win32 contract. Returns
// false if the handle is unknown.
func (m *Manager) SetWindowPos(h, insertAfter HWND, x, y, w_, h_ int32, flags uint32) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	w := m.windows[h]
	if w == nil {
		return false
	}
	if flags&SWP_NOMOVE == 0 {
		dw, dh := w.rect.Width(), w.rect.Height()
		w.rect.Left, w.rect.Top = x, y
		w.rect.Right, w.rect.Bottom = x+dw, y+dh
	}
	if flags&SWP_NOSIZE == 0 {
		w.rect.Right = w.rect.Left + w_
		w.rect.Bottom = w.rect.Top + h_
	}
	if flags&SWP_SHOWWINDOW != 0 {
		w.visible = true
		w.Style |= WS_VISIBLE
	}
	if flags&SWP_HIDEWINDOW != 0 {
		w.visible = false
		w.Style &^= WS_VISIBLE
	}
	if flags&SWP_NOZORDER == 0 {
		m.reorderLocked(w, insertAfter)
	}
	return true
}

// reorderLocked places w in its sibling list per insertAfter (HWND_TOP/BOTTOM or
// "after this sibling"). Topmost is index 0.
func (m *Manager) reorderLocked(w *Window, insertAfter HWND) {
	list := m.siblings(w)
	*list = removeWindow(*list, w)
	switch insertAfter {
	case HWND_TOP, HWND_TOPMOST:
		*list = append([]*Window{w}, *list...)
	case HWND_BOTTOM, HWND_NOTOPMOST:
		*list = append(*list, w)
	default:
		after := m.windows[insertAfter]
		placed := false
		for i, x := range *list {
			if x == after {
				ns := append([]*Window{}, (*list)[:i+1]...)
				ns = append(ns, w)
				ns = append(ns, (*list)[i+1:]...)
				*list = ns
				placed = true
				break
			}
		}
		if !placed {
			*list = append([]*Window{w}, *list...)
		}
	}
}

// BringToTop raises a window to the top of its sibling z-order.
func (m *Manager) BringToTop(h HWND) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	w := m.windows[h]
	if w == nil {
		return false
	}
	m.reorderLocked(w, HWND_TOP)
	return true
}

// ShowWindow sets visibility; returns the previous visible state.
func (m *Manager) ShowWindow(h HWND, show bool) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	w := m.windows[h]
	if w == nil {
		return false
	}
	prev := w.visible
	w.visible = show
	if show {
		w.Style |= WS_VISIBLE
	} else {
		w.Style &^= WS_VISIBLE
	}
	return prev
}

// IsVisible reports whether the window and all ancestors are visible.
func (m *Manager) IsVisible(h HWND) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for w := m.windows[h]; w != nil; w = w.parent {
		if !w.visible {
			return false
		}
	}
	return true
}

// EnableWindow sets the enabled state; returns the previous state.
func (m *Manager) EnableWindow(h HWND, enable bool) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	w := m.windows[h]
	if w == nil {
		return false
	}
	prev := w.enabled
	w.enabled = enable
	if enable {
		w.Style &^= WS_DISABLED
	} else {
		w.Style |= WS_DISABLED
	}
	return prev
}

// GetParent returns the parent (for children) or owner (for top-level) handle.
func (m *Manager) GetParent(h HWND) HWND {
	m.mu.Lock()
	defer m.mu.Unlock()
	w := m.windows[h]
	if w == nil {
		return 0
	}
	if w.parent != nil {
		return w.parent.Handle
	}
	if w.owner != nil {
		return w.owner.Handle
	}
	return 0
}

// GetWindow navigates the window tree per a GW_* relationship code.
func (m *Manager) GetWindow(h HWND, rel int) HWND {
	m.mu.Lock()
	defer m.mu.Unlock()
	w := m.windows[h]
	if w == nil {
		return 0
	}
	list := *m.siblings(w)
	idx := -1
	for i, x := range list {
		if x == w {
			idx = i
			break
		}
	}
	switch rel {
	case GW_HWNDFIRST:
		if len(list) > 0 {
			return list[0].Handle
		}
	case GW_HWNDLAST:
		if len(list) > 0 {
			return list[len(list)-1].Handle
		}
	case GW_HWNDNEXT:
		if idx >= 0 && idx+1 < len(list) {
			return list[idx+1].Handle
		}
	case GW_HWNDPREV:
		if idx > 0 {
			return list[idx-1].Handle
		}
	case GW_OWNER:
		if w.owner != nil {
			return w.owner.Handle
		}
	case GW_CHILD:
		if len(w.children) > 0 {
			return w.children[0].Handle
		}
	}
	return 0
}

// Window-long indices with dedicated storage (others use the userData map).
const (
	GWL_STYLE     = -16
	GWL_EXSTYLE   = -20
	GWL_ID        = -12
	GWL_WNDPROC   = -4
	GWL_HINSTANCE = -6
	GWLP_USERDATA = -21
)

// GetWindowLong reads a window-long value. Returns 0 for unknown windows.
func (m *Manager) GetWindowLong(h HWND, index int32) uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	w := m.windows[h]
	if w == nil {
		return 0
	}
	switch index {
	case GWL_STYLE:
		return uint64(w.Style)
	case GWL_EXSTYLE:
		return uint64(w.ExStyle)
	case GWL_ID:
		return w.ID
	case GWL_WNDPROC:
		return w.WndProc
	case GWL_HINSTANCE:
		return w.Instance
	default:
		return w.userData[index]
	}
}

// SetWindowLong writes a window-long value and returns the previous value.
func (m *Manager) SetWindowLong(h HWND, index int32, val uint64) uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	w := m.windows[h]
	if w == nil {
		return 0
	}
	var prev uint64
	switch index {
	case GWL_STYLE:
		prev = uint64(w.Style)
		w.Style = uint32(val)
		w.visible = w.Style&WS_VISIBLE != 0
	case GWL_EXSTYLE:
		prev = uint64(w.ExStyle)
		w.ExStyle = uint32(val)
	case GWL_ID:
		prev, w.ID = w.ID, val
	case GWL_WNDPROC:
		prev, w.WndProc = w.WndProc, val
	case GWL_HINSTANCE:
		prev, w.Instance = w.Instance, val
	default:
		prev = w.userData[index]
		w.userData[index] = val
	}
	return prev
}

// SetWindowText sets the window title.
func (m *Manager) SetWindowText(h HWND, text string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	w := m.windows[h]
	if w == nil {
		return false
	}
	w.Text = text
	return true
}

// FindWindow finds a top-level window by class and/or title ("" = any). Returns 0
// if none match.
func (m *Manager) FindWindow(className, title string) HWND {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, w := range m.desktop.topLevel {
		if className != "" && (w.Class == nil || w.Class.Name != className) {
			continue
		}
		if title != "" && w.Text != title {
			continue
		}
		return w.Handle
	}
	return 0
}

// WindowFromPoint returns the deepest visible, enabled window containing the
// screen point (top-most in z-order first), or 0.
func (m *Manager) WindowFromPoint(x, y int32) HWND {
	m.mu.Lock()
	defer m.mu.Unlock()
	if w := hitTest(m.desktop.topLevel, x, y); w != nil {
		return w.Handle
	}
	return 0
}

func hitTest(list []*Window, x, y int32) *Window {
	for _, w := range list { // z-order: front (top-most) first
		if !w.visible || w.Style&WS_DISABLED != 0 || !w.rect.Contains(x, y) {
			continue
		}
		if child := hitTest(w.children, x, y); child != nil {
			return child
		}
		return w
	}
	return nil
}

// TopLevelZOrder returns top-level handles from top-most to bottom-most (for the
// compositor / paint order). Visible-only when visibleOnly is set.
func (m *Manager) TopLevelZOrder(visibleOnly bool) []HWND {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]HWND, 0, len(m.desktop.topLevel))
	for _, w := range m.desktop.topLevel {
		if visibleOnly && !w.visible {
			continue
		}
		out = append(out, w.Handle)
	}
	return out
}

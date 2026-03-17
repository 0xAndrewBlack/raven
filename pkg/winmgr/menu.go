package winmgr

import "sync"

// Menu model . Menus are kernel objects too; TrackPopupMenu opens a
// popup surface  whose items are hit-tested here. The engine owns menu
// state and hit-testing; real user32/uxtheme draw the items.

// Menu item flags (subset).
const (
	MF_STRING    uint32 = 0x0000
	MF_SEPARATOR uint32 = 0x0800
	MF_POPUP     uint32 = 0x0010
	MF_GRAYED    uint32 = 0x0001
	MF_DISABLED  uint32 = 0x0002
	MF_CHECKED   uint32 = 0x0008
)

// HMENU is a menu handle.
type HMENU uint32

// MenuItem is one entry in a menu.
type MenuItem struct {
	ID      uint32
	Text    string
	Flags   uint32
	Submenu HMENU // when MF_POPUP
	// Layout (filled by the drawer / TrackPopupMenu); used for hit-testing.
	Top, Height int32
}

// Menu is a menu (bar or popup).
type Menu struct {
	Handle HMENU
	Items  []*MenuItem
}

// Enabled reports whether an item is selectable.
func (it *MenuItem) Enabled() bool { return it.Flags&(MF_GRAYED|MF_DISABLED|MF_SEPARATOR) == 0 }

// MenuTable owns menus by handle.
type MenuTable struct {
	mu    sync.Mutex
	next  uint32
	menus map[HMENU]*Menu
}

// NewMenuTable creates an empty menu table.
func NewMenuTable() *MenuTable {
	return &MenuTable{next: 0x20010, menus: make(map[HMENU]*Menu)}
}

// Create makes an empty menu and returns its handle.
func (t *MenuTable) Create() HMENU {
	t.mu.Lock()
	defer t.mu.Unlock()
	h := HMENU(t.next)
	t.next += 4
	t.menus[h] = &Menu{Handle: h}
	return h
}

// Get returns a menu by handle (nil if unknown).
func (t *MenuTable) Get(h HMENU) *Menu {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.menus[h]
}

// Destroy removes a menu; returns false if unknown.
func (t *MenuTable) Destroy(h HMENU) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.menus[h]; !ok {
		return false
	}
	delete(t.menus, h)
	return true
}

// Append adds an item to a menu; returns false if the menu is unknown.
func (t *MenuTable) Append(h HMENU, item *MenuItem) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	m := t.menus[h]
	if m == nil {
		return false
	}
	m.Items = append(m.Items, item)
	return true
}

// Layout assigns vertical extents to items (separators thin, others itemH) so
// HitTest can map a popup-relative y to an item. Returns the total height.
func (m *Menu) Layout(itemH, sepH int32) int32 {
	y := int32(0)
	for _, it := range m.Items {
		h := itemH
		if it.Flags&MF_SEPARATOR != 0 {
			h = sepH
		}
		it.Top = y
		it.Height = h
		y += h
	}
	return y
}

// HitTest returns the index of the item at popup-relative y, or -1. Disabled
// items and separators return their index but callers should check Enabled().
func (m *Menu) HitTest(y int32) int {
	for i, it := range m.Items {
		if y >= it.Top && y < it.Top+it.Height {
			return i
		}
	}
	return -1
}

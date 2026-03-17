// Package winmgr is the pure-Go window-manager engine for the win32k GUI
// subsystem . It implements the kernel-side object
// model and algorithms - window stations/desktops, window classes + atoms, the
// window tree with z-order and rectangles, SetWindowPos, hit-testing, per-thread
// message queues, menus and timers - with no dependency on guest memory or the
// CPU, so it is fully unit-testable on its own (like pkg/ntobj for the object
// manager). The win32k syscall handlers become thin marshallers over this
// engine, and real user32.dll runs on top: the engine never draws widgets, it
// only manages window state and routes messages, which is what makes the runtime
// generic.
package winmgr

import "sync"

// HWND is a window handle (kernel-assigned, never a guest pointer).
type HWND uint32

// Common window styles (subset used by the engine's NC/visibility logic).
const (
	WS_OVERLAPPED uint32 = 0x00000000
	WS_VISIBLE    uint32 = 0x10000000
	WS_DISABLED   uint32 = 0x08000000
	WS_CHILD      uint32 = 0x40000000
	WS_POPUP      uint32 = 0x80000000
	WS_BORDER     uint32 = 0x00800000
	WS_DLGFRAME   uint32 = 0x00400000
	WS_CAPTION    uint32 = WS_BORDER | WS_DLGFRAME
	WS_THICKFRAME uint32 = 0x00040000
	WS_MINIMIZE   uint32 = 0x20000000
	WS_MAXIMIZE   uint32 = 0x01000000
)

// GetWindow relationship codes (NtUserGetWindow / GetWindow).
const (
	GW_HWNDFIRST = 0
	GW_HWNDLAST  = 1
	GW_HWNDNEXT  = 2
	GW_HWNDPREV  = 3
	GW_OWNER     = 4
	GW_CHILD     = 5
)

// SetWindowPos zorder placement and flags.
const (
	HWND_TOP       = HWND(0)
	HWND_BOTTOM    = HWND(1)
	HWND_TOPMOST   = ^HWND(0)     // (HWND)-1
	HWND_NOTOPMOST = ^HWND(0) - 1 // (HWND)-2

	SWP_NOSIZE     uint32 = 0x0001
	SWP_NOMOVE     uint32 = 0x0002
	SWP_NOZORDER   uint32 = 0x0004
	SWP_NOACTIVATE uint32 = 0x0010
	SWP_SHOWWINDOW uint32 = 0x0040
	SWP_HIDEWINDOW uint32 = 0x0080
)

// Rect is a window rectangle in screen coordinates (right/bottom exclusive).
type Rect struct{ Left, Top, Right, Bottom int32 }

func (r Rect) Width() int32  { return r.Right - r.Left }
func (r Rect) Height() int32 { return r.Bottom - r.Top }
func (r Rect) Contains(x, y int32) bool {
	return x >= r.Left && x < r.Right && y >= r.Top && y < r.Bottom
}

// Class is a registered window class.
type Class struct {
	Atom       uint16
	Name       string
	Style      uint32
	WndProc    uint64 // guest address of the class WndProc
	Instance   uint64
	CbClsExtra int32
	CbWndExtra int32
	Background uint32
	MenuName   string
}

// Window is a window object in the tree.
type Window struct {
	Handle   HWND
	Class    *Class
	Style    uint32
	ExStyle  uint32
	Text     string
	WndProc  uint64 // per-window WndProc (defaults to class WndProc)
	Instance uint64
	ID       uint64 // child-window id / HMENU for top-level

	parent   *Window
	owner    *Window
	children []*Window // front (index 0) is top-most child in z-order

	rect     Rect // window rect (screen coords)
	visible  bool
	enabled  bool
	userData map[int32]uint64 // Get/SetWindowLongPtr index -> value
}

// WindowStation/Desktop model the win32k containers. A session has one window
// station with one (interactive) desktop in this engine.
type Desktop struct {
	name     string
	topLevel []*Window // front (index 0) is top-most in z-order
}

// Manager is the window-manager engine.
type Manager struct {
	mu       sync.Mutex
	nextH    uint32
	nextAtom uint16
	windows  map[HWND]*Window
	classes  map[string]*Class // by name
	atoms    map[uint16]*Class // by atom
	desktop  *Desktop
}

// New creates a window manager with one desktop.
func New() *Manager {
	return &Manager{
		nextH:    0x10010, // handles start above low magic values
		nextAtom: 0xC000,  // class atoms live in the 0xC000+ range
		windows:  make(map[HWND]*Window),
		classes:  make(map[string]*Class),
		atoms:    make(map[uint16]*Class),
		desktop:  &Desktop{name: "Default"},
	}
}

func (m *Manager) allocHandle() HWND {
	h := HWND(m.nextH)
	m.nextH += 4 // HWNDs are 4-aligned like real Windows
	return h
}

// RegisterClass registers (or replaces) a window class and returns its atom.
func (m *Manager) RegisterClass(c *Class) uint16 {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c.Atom == 0 {
		c.Atom = m.nextAtom
		m.nextAtom++
	}
	m.classes[c.Name] = c
	m.atoms[c.Atom] = c
	return c.Atom
}

// UnregisterClass removes a class by name; returns false if unknown.
func (m *Manager) UnregisterClass(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.classes[name]
	if !ok {
		return false
	}
	delete(m.classes, name)
	delete(m.atoms, c.Atom)
	return true
}

// FindClass looks up a class by name (nil if unknown).
func (m *Manager) FindClass(name string) *Class {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.classes[name]
}

// CreateWindowParams carries the inputs to CreateWindow.
type CreateWindowParams struct {
	ClassName  string
	Title      string
	Style      uint32
	ExStyle    uint32
	X, Y, W, H int32
	Parent     HWND
	Menu       uint64 // HMENU or child id
	Instance   uint64
}

// CreateWindow creates a window, links it into the tree and z-order, and returns
// it (nil if the class is unknown). Children go to the front of the parent's
// child z-order; top-level windows go to the front of the desktop z-order.
func (m *Manager) CreateWindow(p CreateWindowParams) *Window {
	m.mu.Lock()
	defer m.mu.Unlock()
	cls := m.classes[p.ClassName]
	if cls == nil {
		return nil
	}
	w := &Window{
		Handle:   m.allocHandle(),
		Class:    cls,
		Style:    p.Style,
		ExStyle:  p.ExStyle,
		Text:     p.Title,
		WndProc:  cls.WndProc,
		Instance: p.Instance,
		ID:       p.Menu,
		rect:     Rect{p.X, p.Y, p.X + p.W, p.Y + p.H},
		visible:  p.Style&WS_VISIBLE != 0,
		enabled:  p.Style&WS_DISABLED == 0,
		userData: make(map[int32]uint64),
	}
	if p.Style&WS_CHILD != 0 && p.Parent != 0 {
		if parent := m.windows[p.Parent]; parent != nil {
			w.parent = parent
			parent.children = append([]*Window{w}, parent.children...)
		}
	} else {
		if p.Parent != 0 {
			w.owner = m.windows[p.Parent] // owner (not parent) for popups/dialogs
		}
		m.desktop.topLevel = append([]*Window{w}, m.desktop.topLevel...)
	}
	m.windows[w.Handle] = w
	return w
}

// Get returns a window by handle (nil if unknown).
func (m *Manager) Get(h HWND) *Window {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.windows[h]
}

// DestroyWindow destroys a window and all of its children, unlinking from the
// tree and z-order. Returns false if the handle is unknown.
func (m *Manager) DestroyWindow(h HWND) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	w := m.windows[h]
	if w == nil {
		return false
	}
	m.destroyLocked(w)
	return true
}

func (m *Manager) destroyLocked(w *Window) {
	for _, c := range append([]*Window(nil), w.children...) {
		m.destroyLocked(c)
	}
	if w.parent != nil {
		w.parent.children = removeWindow(w.parent.children, w)
	} else {
		m.desktop.topLevel = removeWindow(m.desktop.topLevel, w)
	}
	delete(m.windows, w.Handle)
}

func removeWindow(list []*Window, w *Window) []*Window {
	for i, x := range list {
		if x == w {
			return append(list[:i:i], list[i+1:]...)
		}
	}
	return list
}

// siblings returns the z-order list that contains w (parent's children or the
// desktop top-level list).
func (m *Manager) siblings(w *Window) *[]*Window {
	if w.parent != nil {
		return &w.parent.children
	}
	return &m.desktop.topLevel
}

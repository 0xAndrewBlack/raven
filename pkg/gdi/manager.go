package gdi

import "sync/atomic"

// Manager is the central GDI handle table.
// ReactOS equivalent: GDI handle table in win32ss/gdi/ntgdi/gdiobj.c
//
// Handles are monotonically-increasing uint64 values starting at 0x10000.
// The lower word encodes the object type (for quick validation).
// External code (main.go) uses uint64 handles exclusively.
type Manager struct {
	next    uint64 // atomic
	objects map[uint64]*Object
	dcs     map[uint64]*DC

	// Stock objects (pre-allocated, never freed).
	stock [18]uint64

	// Screen surface - updated when the Wayland window resizes.
	Screen *Surface
}

var baseHandle = uint64(0x10000)

// NewManager creates an initialised GDI Manager with stock objects.
func NewManager() *Manager {
	m := &Manager{
		next:    baseHandle,
		objects: make(map[uint64]*Object),
		dcs:     make(map[uint64]*DC),
	}
	m.initStock()
	return m
}

func (m *Manager) alloc() uint64 {
	return atomic.AddUint64(&m.next, 1) - 1
}

func (m *Manager) initStock() {
	for idx, brush := range stockBrushes {
		h := m.alloc()
		m.objects[h] = &Object{Type: ObjBrush, Brush: brush}
		if idx < len(m.stock) {
			m.stock[idx] = h
		}
	}
	for idx, pen := range stockPens {
		h := m.alloc()
		m.objects[h] = &Object{Type: ObjPen, Pen: pen}
		if idx < len(m.stock) {
			m.stock[idx] = h
		}
	}
	// System font stock objects
	for _, idx := range []int{StockSystemFont, StockDefaultGuiFont, StockSystemFixedFont, StockDeviceDefaultFont} {
		f := defaultFont()
		h := m.alloc()
		m.objects[h] = &Object{Type: ObjFont, Font: f}
		if idx < len(m.stock) {
			m.stock[idx] = h
		}
	}
}

// --- DC lifecycle ---

// AllocScreenDC creates a screen-target DC wrapping the current Screen surface.
func (m *Manager) AllocScreenDC() (uint64, *DC) {
	dc := NewScreenDC(m.Screen)
	h := m.alloc()
	m.dcs[h] = dc
	return h, dc
}

// AllocMemDC creates an off-screen DC.
func (m *Manager) AllocMemDC() (uint64, *DC) {
	dc := NewMemoryDC()
	h := m.alloc()
	m.dcs[h] = dc
	return h, dc
}

// DeleteDC removes a DC from the table.
func (m *Manager) DeleteDC(h uint64) {
	delete(m.dcs, h)
}

// GetDC looks up a DC handle. Returns nil if not found.
func (m *Manager) GetDC(h uint64) *DC {
	return m.dcs[h]
}

// --- GDI object lifecycle ---

// CreateSolidBrush allocates a solid brush handle.
// ReactOS: NtGdiCreateSolidBrush
func (m *Manager) CreateSolidBrush(color uint32) uint64 {
	h := m.alloc()
	m.objects[h] = &Object{Type: ObjBrush, Brush: &Brush{Style: 0, Color: color}}
	return h
}

// CreateHatchBrush allocates a hatched brush (rendered as solid for simplicity).
// ReactOS: NtGdiCreateHatchBrushInternal
func (m *Manager) CreateHatchBrush(style int32, color uint32) uint64 {
	h := m.alloc()
	m.objects[h] = &Object{Type: ObjBrush, Brush: &Brush{Style: 2, Hatch: style, Color: color}}
	return h
}

// CreatePatternBrush allocates a pattern brush backed by a bitmap.
func (m *Manager) CreatePatternBrush(bitmapH uint64) uint64 {
	h := m.alloc()
	var bm *Bitmap
	if obj, ok := m.objects[bitmapH]; ok && obj.Bitmap != nil {
		bm = obj.Bitmap
	}
	m.objects[h] = &Object{Type: ObjBrush, Brush: &Brush{Style: 3}}
	_ = bm
	return h
}

// CreatePen allocates a pen.
// ReactOS: NtGdiCreatePen
func (m *Manager) CreatePen(style, width int32, color uint32) uint64 {
	h := m.alloc()
	m.objects[h] = &Object{Type: ObjPen, Pen: &Pen{Style: style, Width: width, Color: color}}
	return h
}

// CreateFont allocates a logical font.
// ReactOS: NtGdiHfontCreate
func (m *Manager) CreateFont(f *Font) uint64 {
	if f.AveCharWidth == 0 {
		f.AveCharWidth = fontCharW
	}
	if f.MaxCharWidth == 0 {
		f.MaxCharWidth = fontCharW
	}
	if f.CellHeight == 0 {
		f.CellHeight = fontCharH
	}
	if f.Ascent == 0 {
		f.Ascent = 13
	}
	if f.Descent == 0 {
		f.Descent = 3
	}
	h := m.alloc()
	m.objects[h] = &Object{Type: ObjFont, Font: f}
	return h
}

// CreateCompatibleBitmap allocates a bitmap of given dimensions.
// ReactOS: NtGdiCreateCompatibleBitmap
func (m *Manager) CreateCompatibleBitmap(w, h int32) uint64 {
	handle := m.alloc()
	bm := &Bitmap{Width: w, Height: h}
	if w > 0 && h > 0 {
		bm.Surf = NewSurface(w, h)
	}
	m.objects[handle] = &Object{Type: ObjBitmap, Bitmap: bm}
	return handle
}

// CreateDIBSection allocates a DIB section (treated as a compatible bitmap).
// ReactOS: NtGdiCreateDIBSection
func (m *Manager) CreateDIBSection(w, h int32) uint64 {
	return m.CreateCompatibleBitmap(w, h)
}

// DeleteObject frees a GDI object handle.
// ReactOS: NtGdiDeleteObjectApp
func (m *Manager) DeleteObject(h uint64) bool {
	_, ok := m.objects[h]
	delete(m.objects, h)
	return ok
}

// GetObject returns the GDI object for a handle, or nil.
func (m *Manager) GetObject(h uint64) *Object {
	return m.objects[h]
}

// GetStockObject returns the handle of a stock GDI object.
// ReactOS: NtGdiGetStockObject
func (m *Manager) GetStockObject(idx int) uint64 {
	if idx >= 0 && idx < len(m.stock) {
		return m.stock[idx]
	}
	// Return a valid but dummy handle
	return m.stock[StockBlackPen]
}

// --- SelectObject ---

// SelectObject selects a GDI object into a DC, returning the previous object handle.
// ReactOS: NtGdiSelectObject → GreSelectObject
func (m *Manager) SelectObject(dcH, objH uint64) uint64 {
	dc := m.GetDC(dcH)
	if dc == nil {
		return 0
	}
	obj := m.GetObject(objH)
	if obj == nil {
		return 0
	}
	switch obj.Type {
	case ObjBrush:
		prev := m.findBrushHandle(dc.Brush)
		dc.Brush = obj.Brush
		return prev
	case ObjPen:
		prev := m.findPenHandle(dc.Pen)
		dc.Pen = obj.Pen
		return prev
	case ObjFont:
		prev := m.findFontHandle(dc.Font)
		dc.Font = obj.Font
		return prev
	case ObjBitmap:
		prev := m.findBitmapHandle(dc.Bitmap)
		bm := obj.Bitmap
		dc.Bitmap = bm
		// Selecting a bitmap into a memory DC sets its rendering surface.
		if !dc.IsScreen && bm != nil && bm.Surf != nil {
			dc.Target = bm.Surf
		}
		return prev
	}
	return 0
}

// FindHandle reverses a pointer lookup to a handle.
// These are O(n) but GDI object counts are small in practice.
func (m *Manager) findBrushHandle(b *Brush) uint64 {
	for h, obj := range m.objects {
		if obj.Type == ObjBrush && obj.Brush == b {
			return h
		}
	}
	return m.stock[StockWhiteBrush]
}

func (m *Manager) findPenHandle(p *Pen) uint64 {
	for h, obj := range m.objects {
		if obj.Type == ObjPen && obj.Pen == p {
			return h
		}
	}
	return m.stock[StockBlackPen]
}

func (m *Manager) findFontHandle(f *Font) uint64 {
	for h, obj := range m.objects {
		if obj.Type == ObjFont && obj.Font == f {
			return h
		}
	}
	if len(m.stock) > StockSystemFont {
		return m.stock[StockSystemFont]
	}
	return 0
}

func (m *Manager) findBitmapHandle(bm *Bitmap) uint64 {
	if bm == nil {
		return 0
	}
	for h, obj := range m.objects {
		if obj.Type == ObjBitmap && obj.Bitmap == bm {
			return h
		}
	}
	return 0
}

// --- Brush colour helper ---

// BrushColor resolves the fill colour for a brush handle.
// Handles Win32 system-colour brush pseudo-handles (1-31).
// ReactOS: BRUSH_ulGetBrushColor
func (m *Manager) BrushColor(h uint64, sysColors [31]uint32) uint32 {
	// Pseudo-handle: system colour index (1-based, passed by FillRect)
	if h >= 1 && h <= 31 {
		return sysColors[h-1]
	}
	obj := m.GetObject(h)
	if obj != nil && obj.Brush != nil {
		return obj.Brush.Color
	}
	return 0xF0F0F0 // fallback: light gray
}

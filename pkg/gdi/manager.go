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

// DeleteDC removes a DC from the table and releases its bitmap surface.
func (m *Manager) DeleteDC(h uint64) {
	if dc, ok := m.dcs[h]; ok {
		if dc.Bitmap != nil {
			dc.Bitmap.Surf = nil
		}
	}
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
	// Try to resolve a real TrueType face if one is available
	f.FaceID = -1
	if f.FaceName != "" {
		f.FaceID = ResolveFontFace(f.FaceName)
	}

	// Compute actual pixel size: LOGFONT.lfHeight < 0 means "cell height in pixels"
	pixSize := f.Height
	if pixSize < 0 {
		pixSize = -pixSize
	}
	if pixSize == 0 {
		pixSize = 12
	}

	if f.FaceID >= 0 {
		// Use real TrueType metrics
		cellH, asc, desc, aveW := FaceMetrics(f.FaceID, pixSize)
		f.CellHeight = cellH
		f.Ascent = asc
		f.Descent = desc
		f.AveCharWidth = aveW
		f.MaxCharWidth = aveW * 2
	} else {
		// Fall back to bitmap font metrics
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

// DeleteObject frees a GDI object handle and releases its bitmap surface.
// ReactOS: NtGdiDeleteObjectApp
func (m *Manager) DeleteObject(h uint64) bool {
	obj, ok := m.objects[h]
	if ok && obj.Type == ObjBitmap && obj.Bitmap != nil {
		obj.Bitmap.Surf = nil
	}
	delete(m.objects, h)
	return ok
}

// GetObject returns the GDI object for a handle, or nil.
func (m *Manager) GetObject(h uint64) *Object {
	return m.objects[h]
}

// --- Region management ---
// ReactOS: win32ss/gdi/ntgdi/region.c

// Region result codes (Win32 standard).
const (
	RgnError       = 0
	RgnNull        = 1
	RgnSimple      = 2
	RgnComplex     = 3
)

// Region combine modes (CombineRgn).
const (
	RgnAnd  = 1
	RgnOr   = 2
	RgnXor  = 3
	RgnDiff = 4
	RgnCopy = 5
)

// CreateRectRgn creates a rectangular region.
// ReactOS: NtGdiCreateRectRgn
func (m *Manager) CreateRectRgn(x0, y0, x1, y1 int32) uint64 {
	h := m.alloc()
	m.objects[h] = &Object{Type: ObjRegion, Region: &Region{X0: x0, Y0: y0, X1: x1, Y1: y1}}
	return h
}

// CreateEllipticRgn creates an elliptic region (approximated as bounding rect).
// ReactOS: NtGdiCreateEllipticRgn
func (m *Manager) CreateEllipticRgn(x0, y0, x1, y1 int32) uint64 {
	return m.CreateRectRgn(x0, y0, x1, y1)
}

// CreateRoundRectRgn creates a rounded-rectangle region (approximated as rect).
func (m *Manager) CreateRoundRectRgn(x0, y0, x1, y1, xr, yr int32) uint64 {
	return m.CreateRectRgn(x0, y0, x1, y1)
}

// GetRegion returns the Region object for a handle, or nil.
func (m *Manager) GetRegion(h uint64) *Region {
	obj := m.objects[h]
	if obj != nil && obj.Type == ObjRegion {
		return obj.Region
	}
	return nil
}

// SetRectRgn changes the bounds of an existing region.
// ReactOS: NtGdiSetRectRgn
func (m *Manager) SetRectRgn(h uint64, x0, y0, x1, y1 int32) bool {
	rgn := m.GetRegion(h)
	if rgn == nil {
		return false
	}
	rgn.X0, rgn.Y0, rgn.X1, rgn.Y1 = x0, y0, x1, y1
	rgn.IsEmpty = false
	rgn.IsInfinite = false
	return true
}

// GetRgnBox fills the bounding rect of a region and returns the region type.
// ReactOS: NtGdiGetRgnBox
func (m *Manager) GetRgnBox(h uint64, pRect *[4]int32) int {
	rgn := m.GetRegion(h)
	if rgn == nil {
		return RgnError
	}
	if rgn.IsEmpty || (rgn.X0 == rgn.X1 && rgn.Y0 == rgn.Y1) {
		if pRect != nil {
			*pRect = [4]int32{}
		}
		return RgnNull
	}
	if pRect != nil {
		pRect[0] = rgn.X0
		pRect[1] = rgn.Y0
		pRect[2] = rgn.X1
		pRect[3] = rgn.Y1
	}
	return RgnSimple
}

// CombineRgn combines two regions into a destination region.
// ReactOS: NtGdiCombineRgn
func (m *Manager) CombineRgn(dst, src1, src2 uint64, mode int) int {
	dstRgn := m.GetRegion(dst)
	if dstRgn == nil {
		return RgnError
	}
	r1 := m.GetRegion(src1)
	r2 := m.GetRegion(src2)
	if r1 == nil {
		return RgnError
	}

	var x0, y0, x1, y1 int32
	switch mode {
	case RgnCopy:
		x0, y0, x1, y1 = r1.X0, r1.Y0, r1.X1, r1.Y1
	case RgnAnd:
		if r2 == nil { return RgnError }
		x0 = max32(r1.X0, r2.X0)
		y0 = max32(r1.Y0, r2.Y0)
		x1 = min32(r1.X1, r2.X1)
		y1 = min32(r1.Y1, r2.Y1)
		if x0 > x1 || y0 > y1 {
			dstRgn.IsEmpty = true
			return RgnNull
		}
	case RgnOr:
		if r2 == nil { return RgnError }
		x0 = min32(r1.X0, r2.X0)
		y0 = min32(r1.Y0, r2.Y0)
		x1 = max32(r1.X1, r2.X1)
		y1 = max32(r1.Y1, r2.Y1)
	case RgnXor:
		// Simplified: use union for XOR (approximation)
		if r2 == nil { return RgnError }
		x0 = min32(r1.X0, r2.X0)
		y0 = min32(r1.Y0, r2.Y0)
		x1 = max32(r1.X1, r2.X1)
		y1 = max32(r1.Y1, r2.Y1)
	case RgnDiff:
		// src1 minus src2 - simplified: keep src1 unchanged
		x0, y0, x1, y1 = r1.X0, r1.Y0, r1.X1, r1.Y1
	default:
		return RgnError
	}
	dstRgn.X0, dstRgn.Y0, dstRgn.X1, dstRgn.Y1 = x0, y0, x1, y1
	dstRgn.IsEmpty = false
	if x0 == 0 && y0 == 0 && x1 == 0 && y1 == 0 {
		return RgnNull
	}
	return RgnSimple
}

// SelectClipRgn sets the clipping region for a DC.
// ReactOS: NtGdiExtSelectClipRgn
func (m *Manager) SelectClipRgn(dcH, rgnH uint64) int {
	dc := m.GetDC(dcH)
	if dc == nil {
		return RgnError
	}
	if rgnH == 0 {
		// Remove clip region
		dc.ClipX0, dc.ClipY0, dc.ClipX1, dc.ClipY1 = 0, 0, 0, 0
		dc.ClipRgnHandle = 0
		return RgnSimple
	}
	rgn := m.GetRegion(rgnH)
	if rgn == nil {
		return RgnError
	}
	dc.ClipRgnHandle = rgnH
	// Translate region bounds to absolute screen coords using DC origin
	dc.ClipX0 = rgn.X0 + dc.OriginX
	dc.ClipY0 = rgn.Y0 + dc.OriginY
	dc.ClipX1 = rgn.X1 + dc.OriginX
	dc.ClipY1 = rgn.Y1 + dc.OriginY
	if rgn.IsEmpty {
		return RgnNull
	}
	return RgnSimple
}

func min32(a, b int32) int32 { if a < b { return a }; return b }
func max32(a, b int32) int32 { if a > b { return a }; return b }

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
		// Selecting a bitmap into a DC makes it a memory DC targeting that bitmap.
		// ReactOS: NtGdiSelectBitmap → GreSelectBitmap resets origin to (0,0).
		if bm != nil && bm.Surf != nil {
			dc.Target = bm.Surf
			dc.IsScreen = false
			dc.OriginX = 0
			dc.OriginY = 0
			dc.ClipX0 = 0
			dc.ClipY0 = 0
			dc.ClipX1 = bm.Width
			dc.ClipY1 = bm.Height
		}
		return prev
	}
	return 0
}

// FindHandle reverses a pointer lookup to a handle.
// These are O(n) but GDI object counts are small in practice.
func (m *Manager) FindBrushHandle(b *Brush) uint64 {
	return m.findBrushHandle(b)
}

func (m *Manager) FindPenHandle(p *Pen) uint64 {
	return m.findPenHandle(p)
}

func (m *Manager) FindFontHandle(f *Font) uint64 {
	return m.findFontHandle(f)
}

func (m *Manager) FindBitmapHandle(bm *Bitmap) uint64 {
	return m.findBitmapHandle(bm)
}

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

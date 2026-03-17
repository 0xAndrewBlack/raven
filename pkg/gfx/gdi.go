package gfx

import "sync"

// GDI object model: a device context (DC) holds the currently selected pen,
// brush and font plus an origin and clip, and draws onto a Surface. Screen DCs
// target the compositor surface; memory DCs (CreateCompatibleDC) target an
// offscreen Surface so they don't pollute the framebuffer. An ObjectTable hands
// out GDI handles for pens/brushes/fonts/bitmaps.

// HGDIOBJ is a GDI object handle.
type HGDIOBJ uint32

// Pen / Brush / Bitmap / Font GDI objects (font carries a face id resolved by
// the text path).
type Pen struct {
	Style uint32
	Width int
	Color uint32 // ARGB
}
type Brush struct {
	Color uint32 // ARGB (solid)
	Null  bool   // NULL_BRUSH: no fill
}
type Bitmap struct {
	Surface *Surface
}
type Font struct {
	FaceID int
	Height int
	Weight int
	Italic bool
}

// ObjectTable allocates and stores GDI objects by handle.
type ObjectTable struct {
	mu   sync.Mutex
	next uint32
	objs map[HGDIOBJ]interface{}
}

// NewObjectTable creates an empty GDI object table.
func NewObjectTable() *ObjectTable {
	return &ObjectTable{next: 0x30010, objs: make(map[HGDIOBJ]interface{})}
}

func (t *ObjectTable) add(o interface{}) HGDIOBJ {
	t.mu.Lock()
	defer t.mu.Unlock()
	h := HGDIOBJ(t.next)
	t.next += 4
	t.objs[h] = o
	return h
}

// CreatePen / CreateSolidBrush / CreateFont return new GDI handles.
func (t *ObjectTable) CreatePen(style uint32, width int, colorref uint32) HGDIOBJ {
	return t.add(&Pen{Style: style, Width: width, Color: FromCOLORREF(colorref)})
}
func (t *ObjectTable) CreateSolidBrush(colorref uint32) HGDIOBJ {
	return t.add(&Brush{Color: FromCOLORREF(colorref)})
}
func (t *ObjectTable) CreateNullBrush() HGDIOBJ { return t.add(&Brush{Null: true}) }
func (t *ObjectTable) CreateFont(faceID, height, weight int, italic bool) HGDIOBJ {
	return t.add(&Font{FaceID: faceID, Height: height, Weight: weight, Italic: italic})
}
func (t *ObjectTable) CreateBitmap(w, h int) HGDIOBJ {
	return t.add(&Bitmap{Surface: NewSurface(w, h)})
}

// Get returns the object for a handle (nil if unknown).
func (t *ObjectTable) Get(h HGDIOBJ) interface{} {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.objs[h]
}

// Delete removes a GDI object; returns false if unknown.
func (t *ObjectTable) Delete(h HGDIOBJ) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.objs[h]; !ok {
		return false
	}
	delete(t.objs, h)
	return true
}

// DC is a device context drawing onto Target.
type DC struct {
	Target        *Surface
	Memory        bool // true for CreateCompatibleDC offscreen DCs
	OrgX          int  // logical->device origin (SetViewportOrgEx)
	OrgY          int
	Pen           *Pen
	Brush         *Brush
	Font          *Font
	TextCol       uint32 // ARGB
	BkCol         uint32 // ARGB
	BkTransparent bool
	penX, penY    int // current position (MoveToEx/LineTo)
}

// NewScreenDC creates a screen DC drawing onto the compositor surface.
func NewScreenDC(target *Surface) *DC {
	return &DC{Target: target, Pen: &Pen{Color: 0xFF000000}, Brush: &Brush{Color: 0xFFFFFFFF},
		TextCol: 0xFF000000, BkCol: 0xFFFFFFFF}
}

// NewMemoryDC creates an offscreen DC of the given size (CreateCompatibleDC +
// a default 1×1 bitmap until one is selected).
func NewMemoryDC(w, h int) *DC {
	dc := NewScreenDC(NewSurface(w, h))
	dc.Memory = true
	return dc
}

// device maps a logical point to device coords via the viewport origin.
func (dc *DC) device(x, y int) (int, int) { return x + dc.OrgX, y + dc.OrgY }

// FillRect fills a logical rectangle with brush (NULL brush = no-op).
func (dc *DC) FillRect(r Rect, brush *Brush) {
	if brush == nil || brush.Null {
		return
	}
	dr := Rect{r.Left + dc.OrgX, r.Top + dc.OrgY, r.Right + dc.OrgX, r.Bottom + dc.OrgY}
	dc.Target.FillRect(dr, brush.Color)
}

// Rectangle draws the current-brush fill + current-pen outline (GDI Rectangle).
func (dc *DC) Rectangle(r Rect) {
	dr := Rect{r.Left + dc.OrgX, r.Top + dc.OrgY, r.Right + dc.OrgX, r.Bottom + dc.OrgY}
	if dc.Brush != nil && !dc.Brush.Null {
		dc.Target.FillRect(dr, dc.Brush.Color)
	}
	if dc.Pen != nil {
		dc.Target.FrameRect(dr, dc.Pen.Color)
	}
}

// MoveTo sets the current position; LineTo draws from it with the current pen.
func (dc *DC) MoveTo(x, y int) { dc.penX, dc.penY = x, y }
func (dc *DC) LineTo(x, y int) {
	x0, y0 := dc.device(dc.penX, dc.penY)
	x1, y1 := dc.device(x, y)
	col := uint32(0xFF000000)
	if dc.Pen != nil {
		col = dc.Pen.Color
	}
	dc.Target.Line(x0, y0, x1, y1, col)
	dc.penX, dc.penY = x, y
}

// SetPixel sets a single device pixel via the DC origin; returns the color.
func (dc *DC) SetPixel(x, y int, colorref uint32) {
	dx, dy := dc.device(x, y)
	dc.Target.SetPixel(dx, dy, FromCOLORREF(colorref))
}

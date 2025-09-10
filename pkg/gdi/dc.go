package gdi

// DC is a GDI Device Context.
// ReactOS: DC / PDC in win32ss/gdi/ntgdi/dc.c
//
// A DC carries the full rendering state: selected objects, colours, clip rect,
// viewport/window origin, and a pointer to the target Surface.
//
// Screen DCs (IsScreen=true) target the Wayland framebuffer Surface.
// Memory DCs (IsScreen=false) target their own Surface (backed by a Bitmap).
type DC struct {
	// Rendering target surface.
	Target   *Surface
	IsScreen bool

	// DC origin offset (GreSetDCOrg / SetViewportOrgEx).
	// All logical coordinates are translated by this offset before rendering.
	OriginX, OriginY int32

	// Clip rectangle in absolute surface coordinates.
	// When ClipX1 > ClipX0 && ClipY1 > ClipY0 the clip is active.
	ClipX0, ClipY0, ClipX1, ClipY1 int32

	// Selected GDI objects.
	// ReactOS keeps these in DC_ATTR.
	Brush  *Brush
	Pen    *Pen
	Font   *Font
	Bitmap *Bitmap // selected into memory DC via SelectObject(HBITMAP)

	// Text / background colours.
	TextColor uint32 // COLORREF 0x00RRGGBB
	BkColor   uint32
	// BkMode: TRANSPARENT=1, OPAQUE=2
	BkMode int32

	// TextAlign: combination of TA_LEFT=0, TA_RIGHT=2, TA_CENTER=6,
	// TA_TOP=0, TA_BOTTOM=8, TA_BASELINE=24, TA_NOUPDATECP=0, TA_UPDATECP=1.
	// ReactOS: DC_ATTR.lTextAlign
	TextAlign int32

	// MapMode: MM_TEXT=1 (default), MM_LOMETRIC=2, MM_HIMETRIC=3, MM_LOENGLISH=4,
	// MM_HIENGLISH=5, MM_TWIPS=6, MM_ISOTROPIC=7, MM_ANISOTROPIC=8.
	MapMode int32

	// Window and viewport origins / extents (SetWindowOrgEx, SetViewportExtEx etc.)
	// ReactOS: DC_ATTR.ptlWindowOrg / szlWindowExt / ptlViewportOrg / szlViewportExt
	WindowOrgX, WindowOrgY     int32
	WindowExtX, WindowExtY     int32
	ViewportExtX, ViewportExtY int32

	// CharExtra: extra spacing between characters (SetTextCharacterExtra).
	CharExtra int32

	// StretchBltMode: BLACKONWHITE=1, WHITEONBLACK=2, COLORONCOLOR=3, HALFTONE=4.
	StretchBltMode int32

	// ClipRgnHandle: HRGN selected via SelectClipRgn.
	ClipRgnHandle uint64

	// ArcDir: 1=COUNTERCLOCKWISE (default), 2=CLOCKWISE.
	ArcDir int32

	// Current drawing position (MoveToEx / LineTo).
	CurX, CurY int32

	// ROP2 (binary raster operation). Default: R2_COPYPEN=13.
	ROP2 int32

	// Saved DC stack (SaveDC / RestoreDC).
	saved []*dcSave
}

// dcSave is a snapshot of mutable DC state stored by SaveDC.
// ReactOS: DCSAVE in win32ss/gdi/ntgdi/dc.c
type dcSave struct {
	OriginX, OriginY       int32
	ClipX0, ClipY0         int32
	ClipX1, ClipY1         int32
	Brush                  *Brush
	Pen                    *Pen
	Font                   *Font
	Bitmap                 *Bitmap
	TextColor, BkColor     uint32
	BkMode                 int32
	TextAlign              int32
	MapMode                int32
	WindowOrgX, WindowOrgY int32
	WindowExtX, WindowExtY int32
	ViewportExtX, ViewportExtY int32
	CharExtra              int32
	StretchBltMode         int32
	ClipRgnHandle          uint64
	ArcDir                 int32
	CurX, CurY             int32
	ROP2                   int32
}

// NewScreenDC creates a DC that targets the given Surface (the Wayland framebuffer).
func NewScreenDC(s *Surface) *DC {
	return &DC{
		Target:       s,
		IsScreen:     true,
		TextColor:    0x000000,
		BkColor:      0xFFFFFF,
		BkMode:       2, // OPAQUE
		ROP2:         13,
		MapMode:      1, // MM_TEXT
		WindowExtX:   1, WindowExtY: 1,
		ViewportExtX: 1, ViewportExtY: 1,
		StretchBltMode: 1, // BLACKONWHITE
		ArcDir:       1,  // COUNTERCLOCKWISE
		Brush:        stockBrushes[StockWhiteBrush],
		Pen:          stockPens[StockBlackPen],
		Font:         defaultFont(),
	}
}

// NewMemoryDC creates an off-screen DC with no backing surface yet.
// A bitmap must be selected via SelectBitmap before drawing.
func NewMemoryDC() *DC {
	return &DC{
		IsScreen:       false,
		TextColor:      0x000000,
		BkColor:        0xFFFFFF,
		BkMode:         2,
		ROP2:           13,
		MapMode:        1,
		WindowExtX:     1, WindowExtY: 1,
		ViewportExtX:   1, ViewportExtY: 1,
		StretchBltMode: 1,
		ArcDir:         1,
		Brush:          stockBrushes[StockWhiteBrush],
		Pen:            stockPens[StockBlackPen],
		Font:           defaultFont(),
	}
}

// InheritFrom copies screen-DC properties to a newly created memory DC
// so that CreateCompatibleDC inherits origin, clip and colours.
func (dc *DC) InheritFrom(src *DC) {
	dc.OriginX = src.OriginX
	dc.OriginY = src.OriginY
	dc.ClipX0 = src.ClipX0
	dc.ClipY0 = src.ClipY0
	dc.ClipX1 = src.ClipX1
	dc.ClipY1 = src.ClipY1
	dc.TextColor = src.TextColor
	dc.BkColor = src.BkColor
	dc.BkMode = src.BkMode
	dc.TextAlign = src.TextAlign
	dc.MapMode = src.MapMode
	dc.WindowOrgX = src.WindowOrgX
	dc.WindowOrgY = src.WindowOrgY
	dc.WindowExtX = src.WindowExtX
	dc.WindowExtY = src.WindowExtY
	dc.ViewportExtX = src.ViewportExtX
	dc.ViewportExtY = src.ViewportExtY
	dc.CharExtra = src.CharExtra
	dc.StretchBltMode = src.StretchBltMode
	dc.ArcDir = src.ArcDir
	dc.ROP2 = src.ROP2
	dc.Brush = src.Brush
	dc.Pen = src.Pen
	dc.Font = src.Font
	// Memory DCs created via CreateCompatibleDC share the screen target
	// until a bitmap is selected. This lets FillRect/TextOut draw through
	// even without an explicit BitBlt (transparent double-buffer mode).
	dc.Target = src.Target
	dc.IsScreen = src.IsScreen
}

// SaveDC pushes the current DC state onto the stack, returning the save count.
// ReactOS: NtGdiSaveDC in win32ss/gdi/ntgdi/dc.c
func (dc *DC) Save() int {
	snap := &dcSave{
		OriginX: dc.OriginX, OriginY: dc.OriginY,
		ClipX0: dc.ClipX0, ClipY0: dc.ClipY0,
		ClipX1: dc.ClipX1, ClipY1: dc.ClipY1,
		Brush: dc.Brush, Pen: dc.Pen, Font: dc.Font, Bitmap: dc.Bitmap,
		TextColor: dc.TextColor, BkColor: dc.BkColor, BkMode: dc.BkMode,
		TextAlign: dc.TextAlign, MapMode: dc.MapMode,
		WindowOrgX: dc.WindowOrgX, WindowOrgY: dc.WindowOrgY,
		WindowExtX: dc.WindowExtX, WindowExtY: dc.WindowExtY,
		ViewportExtX: dc.ViewportExtX, ViewportExtY: dc.ViewportExtY,
		CharExtra: dc.CharExtra, StretchBltMode: dc.StretchBltMode,
		ClipRgnHandle: dc.ClipRgnHandle, ArcDir: dc.ArcDir,
		CurX: dc.CurX, CurY: dc.CurY, ROP2: dc.ROP2,
	}
	dc.saved = append(dc.saved, snap)
	return len(dc.saved)
}

// RestoreDC pops the DC state from the stack.
// level=-1 restores the most recently saved state (Win32 convention).
// ReactOS: NtGdiRestoreDC in win32ss/gdi/ntgdi/dc.c
func (dc *DC) Restore(level int) bool {
	if len(dc.saved) == 0 {
		return false
	}
	idx := len(dc.saved) - 1
	if level > 0 && level <= len(dc.saved) {
		idx = level - 1
	}
	s := dc.saved[idx]
	dc.saved = dc.saved[:idx]
	dc.OriginX, dc.OriginY = s.OriginX, s.OriginY
	dc.ClipX0, dc.ClipY0 = s.ClipX0, s.ClipY0
	dc.ClipX1, dc.ClipY1 = s.ClipX1, s.ClipY1
	dc.Brush, dc.Pen, dc.Font, dc.Bitmap = s.Brush, s.Pen, s.Font, s.Bitmap
	dc.TextColor, dc.BkColor, dc.BkMode = s.TextColor, s.BkColor, s.BkMode
	dc.TextAlign = s.TextAlign
	dc.MapMode = s.MapMode
	dc.WindowOrgX, dc.WindowOrgY = s.WindowOrgX, s.WindowOrgY
	dc.WindowExtX, dc.WindowExtY = s.WindowExtX, s.WindowExtY
	dc.ViewportExtX, dc.ViewportExtY = s.ViewportExtX, s.ViewportExtY
	dc.CharExtra = s.CharExtra
	dc.StretchBltMode = s.StretchBltMode
	dc.ClipRgnHandle = s.ClipRgnHandle
	dc.ArcDir = s.ArcDir
	dc.CurX, dc.CurY = s.CurX, s.CurY
	dc.ROP2 = s.ROP2
	return true
}

// SetViewportOrg sets the DC origin (viewport origin in device coords).
// ReactOS: NtGdiSetViewportOrgEx → GreSetViewportOrgEx
func (dc *DC) SetViewportOrg(x, y int32) {
	dc.OriginX = x
	dc.OriginY = y
}

// OffsetViewportOrg adds a delta to the current DC origin.
func (dc *DC) OffsetViewportOrg(dx, dy int32) {
	dc.OriginX += dx
	dc.OriginY += dy
}

// SetClipRect sets the clipping rectangle in absolute surface coordinates.
// All drawing outside this rect will be silently discarded.
func (dc *DC) SetClipRect(x0, y0, x1, y1 int32) {
	dc.ClipX0 = x0
	dc.ClipY0 = y0
	dc.ClipX1 = x1
	dc.ClipY1 = y1
}

// clipRect applies the DC clip (if active) to an absolute rect.
// Returns (x0,y0,x1,y1, ok). ok=false means the rect is fully clipped.
func (dc *DC) clipRect(x0, y0, x1, y1 int32) (int32, int32, int32, int32, bool) {
	if dc.ClipX1 > dc.ClipX0 && dc.ClipY1 > dc.ClipY0 {
		if x0 < dc.ClipX0 {
			x0 = dc.ClipX0
		}
		if y0 < dc.ClipY0 {
			y0 = dc.ClipY0
		}
		if x1 > dc.ClipX1 {
			x1 = dc.ClipX1
		}
		if y1 > dc.ClipY1 {
			y1 = dc.ClipY1
		}
		if x0 >= x1 || y0 >= y1 {
			return 0, 0, 0, 0, false
		}
	}
	return x0, y0, x1, y1, true
}

// target returns the Surface to draw on (nil-safe; returns a dummy if unset).
func (dc *DC) target() *Surface {
	if dc.Target != nil {
		return dc.Target
	}
	return &Surface{} // safe no-op surface
}

// --- stock objects ---

var stockBrushes = map[int]*Brush{
	StockWhiteBrush:  {Style: 0, Color: 0xFFFFFF},
	StockLtGrayBrush: {Style: 0, Color: 0xC0C0C0},
	StockGrayBrush:   {Style: 0, Color: 0x808080},
	StockDkGrayBrush: {Style: 0, Color: 0x404040},
	StockBlackBrush:  {Style: 0, Color: 0x000000},
	StockNullBrush:   {Style: 1},
}

var stockPens = map[int]*Pen{
	StockWhitePen: {Style: 0, Width: 1, Color: 0xFFFFFF},
	StockBlackPen: {Style: 0, Width: 1, Color: 0x000000},
	StockNullPen:  {Style: 5, Width: 0},
}

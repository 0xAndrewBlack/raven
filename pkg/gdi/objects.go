package gdi

// GDI object types - ReactOS win32ss/gdi/ntgdi/
// Each Win32 HGDIOBJ maps to one of these via Manager.

// ObjType identifies the kind of GDI object.
type ObjType int

const (
	ObjBrush ObjType = iota + 1
	ObjPen
	ObjFont
	ObjBitmap
	ObjRegion
	ObjPalette
)

// Brush represents a GDI brush.
// ReactOS: BRUSH / EBRUSHOBJ in win32ss/gdi/ntgdi/brush.c
type Brush struct {
	// Style: BS_SOLID=0, BS_NULL/BS_HOLLOW=1, BS_HATCHED=2, BS_PATTERN=3, BS_DIBPATTERN=5
	Style int32
	Color uint32 // COLORREF for solid brushes
	Hatch int32  // hatch style for hatched brushes
}

// Pen represents a GDI pen.
// ReactOS: PEN / PPEN in win32ss/gdi/ntgdi/pen.c
type Pen struct {
	// Style: PS_SOLID=0, PS_DASH=1, PS_DOT=2, PS_DASHDOT=3, PS_DASHDOTDOT=4, PS_NULL=5, PS_INSIDEFRAME=6
	Style int32
	Width int32
	Color uint32 // COLORREF
}

// Font represents a logical font (HFONT).
// ReactOS: FONTOBJ / LFONT in win32ss/gdi/ntgdi/freetype.c
type Font struct {
	Height        int32
	Width         int32
	Escapement    int32
	Orientation   int32
	Weight        int32
	Italic        bool
	Underline     bool
	StrikeOut     bool
	CharSet       uint8
	OutPrecision  uint8
	ClipPrecision uint8
	Quality       uint8
	PitchFamily   uint8
	FaceName      string
	// Computed metrics (filled by CreateFont / selectFont)
	AveCharWidth int32
	MaxCharWidth int32
	CellHeight   int32 // tmHeight
	Ascent       int32 // tmAscent
	Descent      int32 // tmDescent
	// TrueType face, -1 means use bitmap fallback
	FaceID int
}

// Bitmap represents a GDI bitmap (HBITMAP).
// ReactOS: SURFACE in win32ss/gdi/ntgdi/surface.c
type Bitmap struct {
	Width  int32
	Height int32
	Surf   *Surface // nil = uninitialized (compatible bitmap not yet used)
}

// Region represents a GDI clip region (HRGN).
// ReactOS: REGION in win32ss/gdi/ntgdi/region.c
// We implement rectangular regions only for now.
type Region struct {
	X0, Y0, X1, Y1 int32 // bounding rect
	IsEmpty        bool
	IsInfinite     bool
}

// Object wraps any GDI object with its type tag.
type Object struct {
	Type ObjType
	// Only one of these is non-nil:
	Brush  *Brush
	Pen    *Pen
	Font   *Font
	Bitmap *Bitmap
	Region *Region
}

// Stock object indices - GetStockObject constants.
const (
	StockWhiteBrush        = 0
	StockLtGrayBrush       = 1
	StockGrayBrush         = 2
	StockDkGrayBrush       = 3
	StockBlackBrush        = 4
	StockNullBrush         = 5
	StockWhitePen          = 6
	StockBlackPen          = 7
	StockNullPen           = 8
	StockOEMFixedFont      = 10
	StockAnsiFixedFont     = 11
	StockAnsiVarFont       = 12
	StockSystemFont        = 13
	StockDeviceDefaultFont = 14
	StockDefaultPalette    = 15
	StockSystemFixedFont   = 16
	StockDefaultGuiFont    = 17
)

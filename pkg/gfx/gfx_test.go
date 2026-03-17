package gfx

import (
	"os"
	"testing"
)

const (
	red   = 0xFFFF0000
	green = 0xFF00FF00
	blue  = 0xFF0000FF
	white = 0xFFFFFFFF
	black = 0xFF000000
)

func TestFillRectAndClip(t *testing.T) {
	s := NewSurface(10, 10)
	s.FillRect(Rect{2, 2, 6, 6}, red)
	if s.GetPixel(2, 2) != red || s.GetPixel(5, 5) != red {
		t.Fatal("fill did not cover the rect")
	}
	if s.GetPixel(1, 1) != 0 || s.GetPixel(6, 6) != 0 {
		t.Fatal("fill leaked outside the rect")
	}
	// Clip restricts subsequent draws.
	s2 := NewSurface(10, 10)
	s2.SetClip(Rect{0, 0, 5, 5})
	s2.FillRect(Rect{0, 0, 10, 10}, green)
	if s2.GetPixel(4, 4) != green || s2.GetPixel(5, 5) != 0 {
		t.Fatal("clip not honored")
	}
}

func TestColorrefRoundTrip(t *testing.T) {
	// COLORREF 0x00BBGGRR red = 0x000000FF -> ARGB 0xFFFF0000
	if got := FromCOLORREF(0x000000FF); got != red {
		t.Fatalf("FromCOLORREF red = %#x", got)
	}
	if got := ToCOLORREF(red); got != 0x000000FF {
		t.Fatalf("ToCOLORREF red = %#x", got)
	}
}

func TestBitBltROPs(t *testing.T) {
	src := NewSurface(4, 4)
	src.FillRect(src.Bounds(), red)
	dst := NewSurface(4, 4)
	dst.FillRect(dst.Bounds(), blue)

	dst.BitBlt(0, 0, 4, 4, src, 0, 0, SRCCOPY)
	if dst.GetPixel(1, 1) != red {
		t.Fatal("SRCCOPY failed")
	}
	dst.BitBlt(0, 0, 4, 4, nil, 0, 0, BLACKNESS)
	if dst.GetPixel(1, 1) != black {
		t.Fatal("BLACKNESS failed")
	}
	dst.BitBlt(0, 0, 4, 4, nil, 0, 0, WHITENESS)
	if dst.GetPixel(1, 1) != white {
		t.Fatal("WHITENESS failed")
	}
}

func TestStretchBlt(t *testing.T) {
	src := NewSurface(2, 2)
	src.SetPixel(0, 0, red)
	src.SetPixel(1, 0, green)
	src.SetPixel(0, 1, blue)
	src.SetPixel(1, 1, white)
	dst := NewSurface(4, 4)
	dst.StretchBlt(0, 0, 4, 4, src, 0, 0, 2, 2, SRCCOPY)
	// Top-left quadrant maps to src(0,0)=red, top-right to green.
	if dst.GetPixel(0, 0) != red || dst.GetPixel(3, 0) != green || dst.GetPixel(0, 3) != blue {
		t.Fatalf("stretch mapping wrong: %x %x %x", dst.GetPixel(0, 0), dst.GetPixel(3, 0), dst.GetPixel(0, 3))
	}
}

func TestAlphaBlend(t *testing.T) {
	dst := NewSurface(2, 2)
	dst.FillRect(dst.Bounds(), black)
	src := NewSurface(2, 2)
	src.FillRect(src.Bounds(), 0x80FFFFFF) // 50% white
	dst.AlphaBlend(0, 0, 2, 2, src, 0, 0, 2, 2, 255)
	// black + 50% white ~= mid grey on each channel.
	p := dst.GetPixel(0, 0)
	r := (p >> 16) & 0xFF
	if r < 0x70 || r > 0x90 {
		t.Fatalf("alpha blend mid-grey expected, got R=%#x", r)
	}
}

func TestLineAndFrame(t *testing.T) {
	s := NewSurface(10, 10)
	s.Line(0, 0, 9, 9, red)
	if s.GetPixel(0, 0) != red || s.GetPixel(9, 9) != red || s.GetPixel(5, 5) != red {
		t.Fatal("diagonal line missing endpoints/middle")
	}
	s.FrameRect(Rect{1, 1, 5, 5}, green)
	if s.GetPixel(1, 1) != green || s.GetPixel(4, 4) != green {
		t.Fatal("frame corners missing")
	}
	if s.GetPixel(2, 2) == green {
		t.Fatal("frame should not fill interior")
	}
}

func TestFillEllipse(t *testing.T) {
	s := NewSurface(20, 20)
	s.FillEllipse(Rect{0, 0, 20, 20}, red)
	if s.GetPixel(10, 10) != red { // center filled
		t.Fatal("ellipse center not filled")
	}
	if s.GetPixel(0, 0) == red { // corner outside the ellipse
		t.Fatal("ellipse should not fill the corner")
	}
}

func TestGDIDCRectangleAndMemoryDC(t *testing.T) {
	dc := NewMemoryDC(20, 20)
	if !dc.Memory {
		t.Fatal("memory DC flag")
	}
	dc.Brush = &Brush{Color: green}
	dc.Pen = &Pen{Color: red}
	dc.Rectangle(Rect{2, 2, 10, 10})
	if dc.Target.GetPixel(5, 5) != green {
		t.Fatal("rectangle interior not brush-filled")
	}
	if dc.Target.GetPixel(2, 2) != red {
		t.Fatal("rectangle outline not pen-drawn")
	}
	// Viewport origin offsets device coords.
	dc.OrgX, dc.OrgY = 1, 1
	dc.MoveTo(0, 0)
	dc.LineTo(0, 5)
	if dc.Target.GetPixel(1, 3) != red {
		t.Fatal("LineTo did not honor viewport origin")
	}
}

func TestObjectTable(t *testing.T) {
	tbl := NewObjectTable()
	hp := tbl.CreatePen(0, 1, 0x000000FF) // red colorref
	pen, ok := tbl.Get(hp).(*Pen)
	if !ok || pen.Color != red {
		t.Fatal("pen object wrong")
	}
	hb := tbl.CreateSolidBrush(0x0000FF00) // green colorref
	if br, ok := tbl.Get(hb).(*Brush); !ok || br.Color != green {
		t.Fatal("brush object wrong")
	}
	if !tbl.Delete(hp) || tbl.Get(hp) != nil {
		t.Fatal("delete failed")
	}
}

func TestCompositorZOrder(t *testing.T) {
	be := NewMemoryBackend(10, 10)
	comp := NewCompositor(be)
	bottom := NewSurface(10, 10)
	bottom.FillRect(bottom.Bounds(), red)
	top := NewSurface(4, 4)
	top.FillRect(top.Bounds(), green)
	comp.Composite([]Layer{{Surface: bottom, X: 0, Y: 0}, {Surface: top, X: 0, Y: 0}})
	f := be.Frame()
	if f.GetPixel(1, 1) != green { // top window wins
		t.Fatal("z-order compositing wrong at overlap")
	}
	if f.GetPixel(8, 8) != red { // bottom shows where top isn't
		t.Fatal("bottom window not visible outside top")
	}
	if be.Presents() != 1 {
		t.Fatalf("present count = %d", be.Presents())
	}
}

// findFont returns a TTF path on the host or "" if none is available.
func findFont() string {
	for _, p := range []string{
		"/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
		"/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func TestTrueTypeText(t *testing.T) {
	path := findFont()
	if path == "" {
		t.Skip("no TrueType font available on host")
	}
	fc := NewFontCache()
	id, err := fc.LoadFile(path)
	if err != nil || id != 0 {
		t.Fatalf("LoadFile: id=%d err=%v", id, err)
	}
	w, asc, desc, err := fc.MeasureText("Raven", id, 16)
	if err != nil || w <= 0 || asc <= 0 || desc < 0 {
		t.Fatalf("measure: w=%d asc=%d desc=%d err=%v", w, asc, desc, err)
	}
	s := NewSurface(120, 30)
	s.FillRect(s.Bounds(), white)
	adv, err := fc.DrawText(s, "Raven", 2, 20, id, 16, black)
	if err != nil || adv <= 0 {
		t.Fatalf("DrawText: adv=%d err=%v", adv, err)
	}
	// Some pixels must have been darkened by anti-aliased glyphs.
	dark := 0
	for _, p := range s.Pix {
		if (p>>16)&0xFF < 0x80 {
			dark++
		}
	}
	if dark == 0 {
		t.Fatal("no glyph pixels rendered (text path produced nothing)")
	}
}

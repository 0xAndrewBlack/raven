//go:build guest_windows

package gdi

import (
	"bytes"
	"testing"
)

func TestTextMetricPitchAndFamilyUsesInvertedPitchBit(t *testing.T) {
	fixed := &Font{FaceID: -1, PitchFamily: 0x31}
	if got := TextMetricPitchAndFamily(fixed); got != 0x30 {
		t.Fatalf("fixed pitch flags = 0x%x", got)
	}

	variable := &Font{FaceID: -1, PitchFamily: 0x22}
	if got := TextMetricPitchAndFamily(variable); got != 0x21 {
		t.Fatalf("variable pitch flags = 0x%x", got)
	}

	defaultVariable := &Font{FaceID: -1, AveCharWidth: 7, MaxCharWidth: 14}
	if got := TextMetricPitchAndFamily(defaultVariable); got != 0x01 {
		t.Fatalf("default variable pitch flags = 0x%x", got)
	}
}

func TestTextMetricPitchAndFamilyMarksTrueTypeVector(t *testing.T) {
	f := &Font{FaceID: 0, PitchFamily: 0x30, Height: 12}
	if got := TextMetricPitchAndFamily(f); got&0x06 != 0x06 {
		t.Fatalf("TrueType flags = 0x%x", got)
	}
}

func TestDefaultGUIFontUsesVariableWidthMetrics(t *testing.T) {
	font := DefaultGUIFont()
	if font.FaceName != "Segoe UI" || font.Height != -12 {
		t.Fatalf("GUI font = %q height %d", font.FaceName, font.Height)
	}
	if font.FaceID < 0 {
		t.Fatal("GUI font did not resolve a TrueType face")
	}
	narrow := GlyphFor(font.FaceID, 12, 'i')
	wide := GlyphFor(font.FaceID, 12, 'W')
	if narrow == nil || wide == nil || narrow.Advance >= wide.Advance {
		t.Fatalf("GUI glyph advances = i:%v W:%v", narrow, wide)
	}
	dc := NewScreenDC(NewSurface(100, 30))
	dc.Font = font
	narrowWidth, _ := dc.TextExtentStr("iiii")
	wideWidth, _ := dc.TextExtentStr("WWWW")
	if narrowWidth >= wideWidth {
		t.Fatalf("GUI text widths = i:%d W:%d", narrowWidth, wideWidth)
	}
}

func TestGlyphForUsesSystemFallback(t *testing.T) {
	faceID := ResolveFontFace("Consolas")
	if faceID < 0 {
		t.Fatal("primary font did not resolve")
	}
	matches := findSystemFallbackFonts("Consolas", '\u65e5')
	if len(matches) == 0 {
		t.Skip("no CJK fallback font installed")
	}
	cjk := GlyphFor(faceID, 14, '\u65e5')
	if !glyphHasInk(cjk, '\u65e5') {
		t.Fatal("CJK glyph did not resolve through font fallback")
	}
	emoji := GlyphFor(faceID, 14, '\U0001f600')
	if !glyphHasInk(emoji, '\U0001f600') {
		t.Fatal("supplementary-plane glyph did not resolve through font fallback")
	}
	missingBox := GlyphFor(faceID, 14, '\u25a1')
	if missingBox != nil && bytes.Equal(cjk.Pix, missingBox.Pix) {
		t.Fatal("CJK fallback rendered the missing-glyph box")
	}

	surface := NewSurface(120, 30)
	dc := NewScreenDC(surface)
	dc.Font = &Font{
		FaceID:       faceID,
		Height:       -14,
		CellHeight:   17,
		Ascent:       13,
		Descent:      4,
		AveCharWidth: 8,
	}
	dc.BkMode = 1
	dc.TextColor = 0xFFFFFF
	dc.TextOut(2, 2, "\u65e5\U0001f600", false)
	ink := 0
	for i := 0; i+3 < len(surface.Pix); i += 4 {
		if surface.Pix[i] != 0 || surface.Pix[i+1] != 0 || surface.Pix[i+2] != 0 {
			ink++
		}
	}
	if ink < 10 {
		t.Fatalf("fallback compositing produced %d painted pixels", ink)
	}
}

func TestTextOutAdvancesPositionsGlyphs(t *testing.T) {
	for _, test := range []struct {
		name string
		font *Font
	}{
		{name: "bitmap", font: bitmapTestFont()},
		{name: "TrueType", font: DefaultGUIFont()},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.name == "TrueType" && test.font.FaceID < 0 {
				t.Skip("TrueType font is unavailable")
			}
			surface := NewSurface(40, 40)
			dc := NewScreenDC(surface)
			dc.Font = test.font
			dc.TextColor = 0xFFFFFF
			dc.BkMode = 1

			dc.TextOutAdvances(0, 0, "||", false, []int32{14, 8}, nil)

			first := paintedBounds(surface, 0, 0, 8, 20)
			second := paintedBounds(surface, 8, 0, 30, 20)
			if first[0] < 0 || second[0] != first[0]+14 {
				t.Fatalf("glyph origins = %d and %d", first[0], second[0])
			}
		})
	}
}

func TestTextOutAdvancesAlignsWithPartialAdvanceArray(t *testing.T) {
	actual := NewSurface(40, 20)
	actualDC := NewScreenDC(actual)
	actualDC.Font = bitmapTestFont()
	actualDC.TextColor = 0xFFFFFF
	actualDC.BkMode = 1
	actualDC.TextAlign = 2
	actualDC.TextOutAdvances(30, 0, "||", false, []int32{12}, nil)

	expected := NewSurface(40, 20)
	expectedDC := NewScreenDC(expected)
	expectedDC.Font = bitmapTestFont()
	expectedDC.TextColor = 0xFFFFFF
	expectedDC.BkMode = 1
	expectedDC.TextOutAdvances(10, 0, "||", false, []int32{12}, nil)

	if !bytes.Equal(actual.Pix, expected.Pix) {
		t.Fatal("partial advance array produced inconsistent right alignment")
	}
}

func TestTextOutAdvancesAppliesVerticalOffsets(t *testing.T) {
	surface := NewSurface(40, 40)
	dc := NewScreenDC(surface)
	dc.Font = bitmapTestFont()
	dc.TextColor = 0xFFFFFF
	dc.BkMode = 1

	dc.TextOutAdvances(0, 0, "||", false, []int32{12, 8}, []int32{5, 0})

	first := paintedBounds(surface, 0, 0, 8, 16)
	second := paintedBounds(surface, 8, 0, 30, 30)
	if first[1] < 0 || second[1] != first[1]+5 {
		t.Fatalf("glyph origins = %d and %d", first[1], second[1])
	}
}

func TestTextOutAdvancesKeepsBitmapFallbackOneToOne(t *testing.T) {
	for _, advances := range [][]int32{nil, {14, 8}} {
		surface := NewSurface(50, 20)
		dc := NewScreenDC(surface)
		dc.Font = bitmapTestFont()
		dc.TextColor = 0xFFFFFF
		dc.BkMode = 1

		dc.TextOutAdvances(0, 0, "\u00C3\u00A9", false, advances, nil)

		start := int32(16)
		if advances != nil {
			start = 22
		}
		if bounds := paintedBounds(surface, start, 0, 50, 20); bounds[0] >= 0 {
			t.Fatalf("advances %v produced an extra glyph at x=%d", advances, bounds[0])
		}
	}
}

func TestTextOutANSIPreservesBitmapCodeUnits(t *testing.T) {
	surface := NewSurface(40, 20)
	dc := NewScreenDC(surface)
	dc.Font = bitmapTestFont()
	dc.TextColor = 0xFFFFFF
	dc.BkMode = 1

	dc.TextOutANSI(0, 0, []byte{0xC3, 0xA9}, false)

	if second := paintedBounds(surface, 8, 0, 16, 20); second[0] < 0 {
		t.Fatal("second ANSI byte did not produce a bitmap cell")
	}
	if extra := paintedBounds(surface, 16, 0, 40, 20); extra[0] >= 0 {
		t.Fatalf("ANSI bytes produced an extra glyph at x=%d", extra[0])
	}
}

func TestTextOutANSIDecodesWindows1252ForTrueType(t *testing.T) {
	font := DefaultGUIFont()
	if font.FaceID < 0 {
		t.Skip("TrueType font is unavailable")
	}
	actual := NewSurface(40, 30)
	actualDC := NewScreenDC(actual)
	actualDC.Font = font
	actualDC.TextColor = 0xFFFFFF
	actualDC.BkMode = 1
	actualDC.TextOutANSI(0, 0, []byte{0x80}, false)

	expected := NewSurface(40, 30)
	expectedDC := NewScreenDC(expected)
	expectedDC.Font = font
	expectedDC.TextColor = 0xFFFFFF
	expectedDC.BkMode = 1
	expectedDC.TextOut(0, 0, "\u20ac", false)

	if !bytes.Equal(actual.Pix, expected.Pix) {
		t.Fatal("ANSI 0x80 did not render as the Windows-1252 euro glyph")
	}
}

func bitmapTestFont() *Font {
	return &Font{
		FaceID:       -1,
		CellHeight:   fontCharH,
		Ascent:       13,
		Descent:      3,
		AveCharWidth: fontCharW,
		MaxCharWidth: fontCharW,
	}
}

func paintedBounds(surface *Surface, x0, y0, x1, y1 int32) [4]int32 {
	bounds := [4]int32{-1, -1, -1, -1}
	for y := y0; y < y1; y++ {
		for x := x0; x < x1; x++ {
			if surface.GetPixel(x, y) == 0 {
				continue
			}
			if bounds[0] < 0 || x < bounds[0] {
				bounds[0] = x
			}
			if bounds[1] < 0 || y < bounds[1] {
				bounds[1] = y
			}
			if x > bounds[2] {
				bounds[2] = x
			}
			if y > bounds[3] {
				bounds[3] = y
			}
		}
	}
	return bounds
}

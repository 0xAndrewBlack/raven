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

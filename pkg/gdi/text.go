package gdi

// text.go - GDI text rendering
// ReactOS reference: win32ss/gdi/ntgdi/freetype.c, text.c
//
// We use the embedded 8×16 bitmap font for all text rendering.
// This covers ASCII 32-126.  Non-ASCII characters fall back to '?'.
// The font metrics match those returned by GetTextMetricsW.

const (
	fontCharW = 8  // pixels per glyph column
	fontCharH = 16 // pixels per glyph row
)

// defaultFont returns the built-in 8×16 system font.
func defaultFont() *Font {
	return &Font{
		Height:       fontCharH,
		Width:        fontCharW,
		AveCharWidth: fontCharW,
		MaxCharWidth: fontCharW,
		CellHeight:   fontCharH,
		Ascent:       13,
		Descent:      3,
		FaceName:     "System",
		Weight:       400,
		CharSet:      0,
	}
}

// DefaultFont is the exported alias for defaultFont.
func DefaultFont() *Font { return defaultFont() }

// TextExtent returns the pixel width of a UTF-16LE string using the DC's current font.
// ReactOS: GreGetTextExtentW → ftGdiGetTextExtentW
func (dc *DC) TextExtent(chars []uint16) (w, h int32) {
	f := dc.Font
	if f == nil {
		f = defaultFont()
	}
	return int32(len(chars)) * f.AveCharWidth, f.CellHeight
}

// TextExtentStr is the same for a Go string (ASCII).
func (dc *DC) TextExtentStr(s string) (w, h int32) {
	f := dc.Font
	if f == nil {
		f = defaultFont()
	}
	runes := []rune(s)
	return int32(len(runes)) * f.AveCharWidth, f.CellHeight
}

// TextOut renders a Go string at (x, y) in client coordinates.
// opaque=true fills the background rectangle first.
// ReactOS: NtGdiExtTextOutW → ftGdiExtTextOutW
func (dc *DC) TextOut(x, y int32, text string, opaque bool) {
	if dc.Target == nil {
		return
	}
	f := dc.Font
	if f == nil {
		f = defaultFont()
	}
	fgColor := dc.TextColor
	bgColor := dc.BkColor
	bkOpaque := opaque || dc.BkMode == 2 // OPAQUE

	fgB := byte(fgColor)
	fgG := byte(fgColor >> 8)
	fgR := byte(fgColor >> 16)
	bgB := byte(bgColor)
	bgG := byte(bgColor >> 8)
	bgR := byte(bgColor >> 16)

	s := dc.Target
	cx := x + dc.OriginX
	cy := y + dc.OriginY

	for _, ch := range []byte(text) {
		if cx+fontCharW > s.Width {
			break
		}
		glyphIdx := int(ch) - 32
		if glyphIdx < 0 || glyphIdx >= 95 {
			glyphIdx = int('?') - 32
		}
		glyphData := font8x16[glyphIdx*16 : (glyphIdx+1)*16]

		for row := 0; row < fontCharH; row++ {
			py := cy + int32(row)
			// Clip check
			if dc.ClipY1 > dc.ClipY0 {
				if py < dc.ClipY0 || py >= dc.ClipY1 {
					continue
				}
			}
			if py < 0 || py >= s.Height {
				continue
			}
			bits := glyphData[row]
			off := int(py)*int(s.Stride) + int(cx)*4
			for col := 0; col < fontCharW; col++ {
				px := cx + int32(col)
				if dc.ClipX1 > dc.ClipX0 {
					if px < dc.ClipX0 || px >= dc.ClipX1 {
						off += 4
						continue
					}
				}
				if px < 0 || px >= s.Width {
					off += 4
					continue
				}
				if bits&(0x80>>uint(col)) != 0 {
					s.Pix[off+0] = fgB
					s.Pix[off+1] = fgG
					s.Pix[off+2] = fgR
					s.Pix[off+3] = 0xFF
				} else if bkOpaque {
					s.Pix[off+0] = bgB
					s.Pix[off+1] = bgG
					s.Pix[off+2] = bgR
					s.Pix[off+3] = 0xFF
				}
				off += 4
			}
		}
		cx += fontCharW
	}
}

// TextOutW renders a UTF-16LE string at (x, y).
func (dc *DC) TextOutW(x, y int32, chars []uint16, opaque bool) {
	// Decode UTF-16LE to bytes for the bitmap font (ASCII range).
	ascii := make([]byte, 0, len(chars))
	for _, c := range chars {
		if c < 128 {
			ascii = append(ascii, byte(c))
		} else {
			ascii = append(ascii, '?')
		}
	}
	dc.TextOut(x, y, string(ascii), opaque)
}

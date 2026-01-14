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
	f := &Font{
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
		FaceID:       -1,
	}
	if faceID := ResolveFontFaceStyle(f.FaceName, false, false); faceID >= 0 {
		f.FaceID = faceID
		cellH, asc, desc, aveW := FaceMetrics(faceID, fontCharH)
		f.CellHeight = cellH
		f.Ascent = asc
		f.Descent = desc
		f.AveCharWidth = aveW
		f.MaxCharWidth = aveW * 2
	}
	return f
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
	charCount := int32(len(UTF16ToRunes(chars)))
	if charCount == 0 {
		return 0, f.CellHeight
	}
	return charCount*f.AveCharWidth + (charCount-1)*dc.CharExtra, f.CellHeight
}

// TextExtentStr is the same for a Go string (ASCII).
func (dc *DC) TextExtentStr(s string) (w, h int32) {
	f := dc.Font
	if f == nil {
		f = defaultFont()
	}
	runes := []rune(s)
	if len(runes) == 0 {
		return 0, f.CellHeight
	}
	return int32(len(runes))*f.AveCharWidth + int32(len(runes)-1)*dc.CharExtra, f.CellHeight
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

	runes := []rune(text)
	textW, _ := dc.TextExtentStr(text)
	hAlign := dc.TextAlign & 0x06
	vAlign := dc.TextAlign & 0x18
	switch hAlign {
	case 2: // TA_RIGHT
		x -= textW
	case 6: // TA_CENTER
		x -= textW / 2
	}
	switch vAlign {
	case 24: // TA_BASELINE
		y -= f.Ascent
	case 8: // TA_BOTTOM
		y -= f.CellHeight
	}

	if f.FaceID >= 0 {
		dc.textOutTTF(x, y, runes, f, opaque)
	} else {
		dc.textOutBitmap(x, y, text, opaque)
	}
}

// textOutTTF renders using TrueType rasterized glyphs.
func (dc *DC) textOutTTF(x, y int32, runes []rune, f *Font, opaque bool) {
	s := dc.Target
	cx := x + dc.OriginX
	cy := y + dc.OriginY

	fgColor := dc.TextColor
	bgColor := dc.BkColor
	bkOpaque := opaque || dc.BkMode == 2

	fgB := byte(fgColor)
	fgG := byte(fgColor >> 8)
	fgR := byte(fgColor >> 16)
	bgB := byte(bgColor)
	bgG := byte(bgColor >> 8)
	bgR := byte(bgColor >> 16)

	pixSize := f.Height
	if pixSize < 0 {
		pixSize = -pixSize
	}
	if pixSize == 0 {
		pixSize = 12
	}

	for _, r := range runes {
		g := GlyphFor(f.FaceID, pixSize, r)
		if g == nil {
			cx += f.AveCharWidth
			continue
		}
		if bkOpaque && g.W > 0 {
			// Fill background rect for this character cell
			for row := int32(0); row < f.CellHeight; row++ {
				py := cy + row
				if py < 0 || py >= s.Height {
					continue
				}
				for col := int32(0); col < g.Advance; col++ {
					px := cx + col
					if px < 0 || px >= s.Width {
						continue
					}
					off := int(py)*int(s.Stride) + int(px)*4
					s.Pix[off+0] = bgB
					s.Pix[off+1] = bgG
					s.Pix[off+2] = bgR
					s.Pix[off+3] = 0xFF
				}
			}
		}
		// Composite glyph pixels (alpha-blend fg color over background)
		penX := cx + g.BearingX
		penY := cy + f.Ascent - g.BearingY
		for row := int32(0); row < g.H; row++ {
			py := penY + row
			if dc.ClipY1 > dc.ClipY0 && (py < dc.ClipY0 || py >= dc.ClipY1) {
				continue
			}
			if py < 0 || py >= s.Height {
				continue
			}
			for col := int32(0); col < g.W; col++ {
				px := penX + col
				if dc.ClipX1 > dc.ClipX0 && (px < dc.ClipX0 || px >= dc.ClipX1) {
					continue
				}
				if px < 0 || px >= s.Width {
					continue
				}
				a := g.Pix[(int(row)*int(g.W)+int(col))*4+3]
				if a == 0 {
					continue
				}
				off := int(py)*int(s.Stride) + int(px)*4
				if a == 255 {
					s.Pix[off+0] = fgB
					s.Pix[off+1] = fgG
					s.Pix[off+2] = fgR
					s.Pix[off+3] = 0xFF
				} else {
					// Linear alpha blend
					inv := uint32(255 - a)
					s.Pix[off+0] = byte((uint32(fgB)*uint32(a) + uint32(s.Pix[off+0])*inv) / 255)
					s.Pix[off+1] = byte((uint32(fgG)*uint32(a) + uint32(s.Pix[off+1])*inv) / 255)
					s.Pix[off+2] = byte((uint32(fgR)*uint32(a) + uint32(s.Pix[off+2])*inv) / 255)
					s.Pix[off+3] = 0xFF
				}
			}
		}
		cx += g.Advance + dc.CharExtra
	}
}

// textOutBitmap renders using the legacy 8×16 bitmap font (ASCII only).
func (dc *DC) textOutBitmap(x, y int32, text string, opaque bool) {
	fgColor := dc.TextColor
	bgColor := dc.BkColor
	bkOpaque := opaque || dc.BkMode == 2

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
		cx += fontCharW + dc.CharExtra
	}
}

// TextOutW renders a UTF-16LE string at (x, y).
func (dc *DC) TextOutW(x, y int32, chars []uint16, opaque bool) {
	f := dc.Font
	if f == nil {
		f = defaultFont()
	}
	if f.FaceID >= 0 {
		// Decode UTF-16 surrogates to runes
		runes := utf16ToRunes(chars)
		textW := int32(0)
		for i, r := range runes {
			if g := GlyphFor(f.FaceID, pixSizeForFont(f), r); g != nil {
				textW += g.Advance
			} else {
				textW += f.AveCharWidth
			}
			if i+1 < len(runes) {
				textW += dc.CharExtra
			}
		}
		hAlign := dc.TextAlign & 0x06
		vAlign := dc.TextAlign & 0x18
		ax := x
		ay := y
		switch hAlign {
		case 2:
			ax -= textW
		case 6:
			ax -= textW / 2
		}
		switch vAlign {
		case 24:
			ay -= f.Ascent
		case 8:
			ay -= f.CellHeight
		}
		dc.textOutTTF(ax, ay, runes, f, opaque)
		return
	}
	// Bitmap fallback: decode to ASCII best-effort
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

// UTF16ToRunes converts a UTF-16 slice to []rune, handling surrogate pairs.
func UTF16ToRunes(s []uint16) []rune {
	out := make([]rune, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0xD800 && c <= 0xDBFF && i+1 < len(s) {
			lo := s[i+1]
			if lo >= 0xDC00 && lo <= 0xDFFF {
				out = append(out, rune(0x10000+(rune(c-0xD800)<<10)|rune(lo-0xDC00)))
				i++
				continue
			}
		}
		out = append(out, rune(c))
	}
	return out
}

// utf16ToRunes is the internal alias.
func utf16ToRunes(s []uint16) []rune { return UTF16ToRunes(s) }

func pixSizeForFont(f *Font) int32 {
	pixSize := f.Height
	if pixSize < 0 {
		pixSize = -pixSize
	}
	if pixSize == 0 {
		pixSize = 12
	}
	return pixSize
}

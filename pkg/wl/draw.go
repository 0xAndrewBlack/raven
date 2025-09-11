package wl

// DrawRect fills a rectangle in the pixel buffer with a COLORREF color.
// Coordinates are clipped to the buffer bounds.
func (w *Window) DrawRect(left, top, right, bottom int32, colorref uint32) {
	if left < 0 {
		left = 0
	}
	if top < 0 {
		top = 0
	}
	if right > w.Width {
		right = w.Width
	}
	if bottom > w.Height {
		bottom = w.Height
	}
	if left >= right || top >= bottom {
		return
	}

	// COLORREF: 0x00RRGGBB → Wayland XRGB8888 memory layout: [B][G][R][X]
	B := byte(colorref)
	G := byte(colorref >> 8)
	R := byte(colorref >> 16)

	stride := int(w.Stride)
	for y := int(top); y < int(bottom); y++ {
		off := y*stride + int(left)*4
		for x := int(left); x < int(right); x++ {
			w.Pix[off] = B
			w.Pix[off+1] = G
			w.Pix[off+2] = R
			w.Pix[off+3] = 0xFF
			off += 4
		}
	}
}

// DrawText renders a UTF-8 string at (x,y) using the embedded 8x16 bitmap font.
// Only ASCII 32-126 are rendered; others are shown as '?'.
// '\n' starts a new line; '\r' is ignored.
func (w *Window) DrawText(x, y int32, text string, fgColor, bgColor uint32, opaque bool) {
	// COLORREF: 0x00RRGGBB → Wayland XRGB8888: [B][G][R][X]
	fgB := byte(fgColor)
	fgG := byte(fgColor >> 8)
	fgR := byte(fgColor >> 16)
	bgB := byte(bgColor)
	bgG := byte(bgColor >> 8)
	bgR := byte(bgColor >> 16)

	stride := int(w.Stride)
	cx := int(x)
	cy := int(y)

	for _, ch := range []byte(text) {
		if ch == '\n' {
			cy += 16
			cx = int(x)
			continue
		}
		if ch == '\r' {
			continue
		}
		if cy+16 > int(w.Height) {
			break
		}
		if cx+8 > int(w.Width) {
			continue
		}

		glyphIdx := int(ch) - 32
		if glyphIdx < 0 || glyphIdx >= 95 {
			glyphIdx = int('?') - 32
		}

		glyphData := font8x16[glyphIdx*16 : (glyphIdx+1)*16]

		for row := 0; row < 16; row++ {
			py := cy + row
			if py < 0 || py >= int(w.Height) {
				continue
			}
			bits := glyphData[row]
			off := py*stride + cx*4
			for col := 0; col < 8; col++ {
				px := cx + col
				if px < 0 || px >= int(w.Width) {
					off += 4
					continue
				}
				if bits&(0x80>>uint(col)) != 0 {
					w.Pix[off] = fgB
					w.Pix[off+1] = fgG
					w.Pix[off+2] = fgR
					w.Pix[off+3] = 0xFF
				} else if opaque {
					w.Pix[off] = bgB
					w.Pix[off+1] = bgG
					w.Pix[off+2] = bgR
					w.Pix[off+3] = 0xFF
				}
				off += 4
			}
		}
		cx += 8
	}
}

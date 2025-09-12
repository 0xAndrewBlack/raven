package wl

// DrawRect fills a rectangle in the pixel buffer with a COLORREF color.
// Coordinates are in client-area space (y=0 is the top of the client area,
// below any title bar). The title-bar offset is added automatically.
func (w *Window) DrawRect(left, top, right, bottom int32, colorref uint32) {
	top += w.TitleBarH
	bottom += w.TitleBarH
	w.drawRectRaw(left, top, right, bottom, colorref)
}

// drawRectRaw fills a rectangle using raw surface coordinates (no TitleBarH offset).
func (w *Window) drawRectRaw(left, top, right, bottom int32, colorref uint32) {
	totalH := int(w.Height + w.TitleBarH)
	if left < 0 {
		left = 0
	}
	if top < 0 {
		top = 0
	}
	if right > w.Width {
		right = w.Width
	}
	if int(bottom) > totalH {
		bottom = int32(totalH)
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
// Coordinates are in client-area space; the title-bar offset is added automatically.
// Only ASCII 32-126 are rendered; others are shown as '?'.
// '\n' starts a new line; '\r' is ignored.
func (w *Window) DrawText(x, y int32, text string, fgColor, bgColor uint32, opaque bool) {
	w.drawTextRaw(x, y+w.TitleBarH, text, fgColor, bgColor, opaque)
}

// drawTextRaw renders text at raw surface coordinates (no TitleBarH offset).
func (w *Window) drawTextRaw(x, y int32, text string, fgColor, bgColor uint32, opaque bool) {
	// COLORREF: 0x00RRGGBB → Wayland XRGB8888: [B][G][R][X]
	fgB := byte(fgColor)
	fgG := byte(fgColor >> 8)
	fgR := byte(fgColor >> 16)
	bgB := byte(bgColor)
	bgG := byte(bgColor >> 8)
	bgR := byte(bgColor >> 16)

	totalH := int(w.Height + w.TitleBarH)
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
		if cy+16 > totalH {
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
			if py < 0 || py >= totalH {
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

// DrawTitleBar renders a Windows-style title bar at the top of the surface
// (surface y=0..TitleBarH). It is called automatically by Commit() when
// TitleBarH > 0. The title bar mimics the Windows 10 / ReactOS NC paint style.
//
// Layout (button widths follow standard SM_CXSIZE = 46 px):
//
//	[─ minimize][□ maximize][✕ close]   ← rightmost buttons, 46 px each
func (w *Window) DrawTitleBar(title string, focused bool) {
	if w.TitleBarH == 0 || w.Pix == nil {
		return
	}
	h := w.TitleBarH
	width := w.Width

	// Title bar background.
	// Active: Windows 10 Fluent blue #0078D7 - inactive: mid-gray #999999
	var tbBg uint32
	if focused {
		tbBg = 0x0078D7
	} else {
		tbBg = 0x999999
	}
	w.drawRectRaw(0, 0, width, h, tbBg)

	// Button dimensions - SM_CXSIZE = 46, full title-bar height.
	const btnW int32 = 46

	// Close button: highlighted red when active.
	closeX := width - btnW
	var closeBg uint32
	if focused {
		closeBg = 0xCC2929
	} else {
		closeBg = 0x808080
	}
	w.drawRectRaw(closeX, 0, width, h, closeBg)

	// Maximize button (same bg as title bar).
	maxX := width - btnW*2
	w.drawRectRaw(maxX, 0, closeX, h, tbBg)

	// Minimize button (same bg as title bar).
	minX := width - btnW*3
	w.drawRectRaw(minX, 0, maxX, h, tbBg)

	// Thin separator lines between buttons (1 px, slightly darker).
	sepColor := darken(tbBg, 30)
	w.drawRectRaw(maxX, 0, maxX+1, h, sepColor)
	w.drawRectRaw(minX, 0, minX+1, h, sepColor)

	// Button symbols - centered in each button.
	symY := (h - 16) / 2
	if symY < 0 {
		symY = 0
	}
	white := uint32(0xFFFFFF)
	// Close: "X"
	w.drawTextRaw(closeX+(btnW-8)/2, symY, "X", white, closeBg, true)
	// Maximize: draw a small box outline (4×4 px) instead of text.
	w.drawMaxIcon(maxX+(btnW-9)/2, symY+4, tbBg)
	// Minimize: horizontal bar at lower third.
	w.drawMinIcon(minX+(btnW-8)/2, symY+10, tbBg)

	// Title text - left-padded 10 px, vertically centered, white, transparent bg.
	titleMaxW := minX - 10
	if titleMaxW > 10 {
		truncated := truncateTitle(title, int(titleMaxW))
		w.drawTextRaw(10, symY, truncated, white, tbBg, false)
	}
}

// darken reduces each RGB channel of a COLORREF by delta (clamped to 0).
func darken(c uint32, delta uint8) uint32 {
	r := byte(c >> 16)
	g := byte(c >> 8)
	b := byte(c)
	if r > delta {
		r -= delta
	} else {
		r = 0
	}
	if g > delta {
		g -= delta
	} else {
		g = 0
	}
	if b > delta {
		b -= delta
	} else {
		b = 0
	}
	return uint32(r)<<16 | uint32(g)<<8 | uint32(b)
}

// drawMaxIcon draws a small rectangle outline (maximize icon) at raw coords.
func (w *Window) drawMaxIcon(x, y int32, bg uint32) {
	white := uint32(0xFFFFFF)
	// 9×8 px box outline
	w.drawRectRaw(x, y, x+9, y+1, white)    // top
	w.drawRectRaw(x, y+7, x+9, y+8, white)  // bottom
	w.drawRectRaw(x, y+1, x+1, y+7, white)  // left
	w.drawRectRaw(x+8, y+1, x+9, y+7, white) // right
	// title-bar stripe inside (double top border = Windows style)
	w.drawRectRaw(x+1, y+1, x+8, y+3, white)
}

// drawMinIcon draws a horizontal bar (minimize icon) at raw coords.
func (w *Window) drawMinIcon(x, y int32, _ uint32) {
	w.drawRectRaw(x, y, x+9, y+2, 0xFFFFFF)
}

// truncateTitle clips title to at most maxW pixels (each ASCII char = 8 px).
func truncateTitle(title string, maxW int) string {
	maxChars := maxW / 8
	runes := []rune(title)
	if len(runes) <= maxChars {
		return title
	}
	if maxChars < 3 {
		return ""
	}
	return string(runes[:maxChars-3]) + "..."
}


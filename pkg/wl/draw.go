package wl

import (
	"fmt"
	"image"
	"image/png"
	"os"
)

// DrawRect fills a rectangle in the pixel buffer with a COLORREF color.
// Coordinates are in client-area space (y=0 is the top of the client area,
// below any title bar). The title-bar offset is added automatically.
func (w *Window) DrawRect(left, top, right, bottom int32, colorref uint32) {
	top += w.TitleBarH
	bottom += w.TitleBarH
	w.DrawRectAbs(left, top, right, bottom, colorref)
}

// DrawRectAbs fills a rectangle using absolute surface coordinates (no TitleBarH offset).
func (w *Window) DrawRectAbs(left, top, right, bottom int32, colorref uint32) {
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
	pixLen := len(w.Pix)
	for y := int(top); y < int(bottom); y++ {
		off := y*stride + int(left)*4
		endOff := off + (int(right)-int(left))*4
		if endOff > pixLen {
			break
		}
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
	w.DrawTextAbs(x, y+w.TitleBarH, text, fgColor, bgColor, opaque)
}

// DrawTextAbs renders text at absolute surface coordinates (no TitleBarH offset).
func (w *Window) DrawTextAbs(x, y int32, text string, fgColor, bgColor uint32, opaque bool) {
	w.drawTextAbsClipped(x, y, w.Width, w.Height+w.TitleBarH, text, fgColor, bgColor, opaque)
}

// DrawTextAbsClipped renders text without writing beyond the supplied bounds.
func (w *Window) DrawTextAbsClipped(x, y, maxX, maxY int32, text string, fgColor, bgColor uint32, opaque bool) {
	if maxX > w.Width {
		maxX = w.Width
	}
	if totalH := w.Height + w.TitleBarH; maxY > totalH {
		maxY = totalH
	}
	w.drawTextAbsClipped(x, y, maxX, maxY, text, fgColor, bgColor, opaque)
}

func (w *Window) drawTextAbsClipped(x, y, maxX, maxY int32, text string, fgColor, bgColor uint32, opaque bool) {
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
		if cy+16 > int(maxY) {
			break
		}
		if cx+8 > int(maxX) {
			continue
		}

		glyphIdx := int(ch) - 32
		if glyphIdx < 0 || glyphIdx >= 95 {
			glyphIdx = int('?') - 32
		}

		glyphData := font8x16[glyphIdx*16 : (glyphIdx+1)*16]

		for row := 0; row < 16; row++ {
			py := cy + row
			if py < 0 || py >= int(maxY) {
				continue
			}
			bits := glyphData[row]
			off := py*stride + cx*4
			if off+8*4 > len(w.Pix) {
				continue
			}
			for col := 0; col < 8; col++ {
				px := cx + col
				if px < 0 || px >= int(maxX) {
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

// Screenshot saves the current framebuffer as a PNG file.
// The entire surface (title bar + client area) is captured.
func (w *Window) Screenshot(path string) error {
	if w.Pix == nil {
		return fmt.Errorf("no pixel buffer")
	}
	totalH := int(w.Height + w.TitleBarH)
	width := int(w.Width)
	stride := int(w.Stride)
	if totalH <= 0 || width <= 0 {
		return fmt.Errorf("zero-size surface")
	}
	img := image.NewRGBA(image.Rect(0, 0, width, totalH))
	for y := 0; y < totalH; y++ {
		rowOff := y * stride
		for x := 0; x < width; x++ {
			off := rowOff + x*4
			if off+2 >= len(w.Pix) {
				break
			}
			// XRGB8888 memory: [B][G][R][X]
			img.Pix[(y*width+x)*4+0] = w.Pix[off+2] // R
			img.Pix[(y*width+x)*4+1] = w.Pix[off+1] // G
			img.Pix[(y*width+x)*4+2] = w.Pix[off+0] // B
			img.Pix[(y*width+x)*4+3] = 255          // A
		}
	}
	tmpPath := path + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		return err
	}
	if err := png.Encode(f, img); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, path)
}

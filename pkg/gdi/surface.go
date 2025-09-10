// Package gdi implements a software GDI layer modelled after ReactOS win32ss/gdi/.
// The rendering target is a 32-bit XRGB8888 pixel buffer (B, G, R, X byte order),
// compatible with the Wayland wl_shm shared-memory surface used by pkg/wl.
package gdi

// Surface is a software pixel buffer (XRGB8888, same layout as wl.Window.Pix).
// ReactOS equivalent: SURFACE / SURFOBJ in win32ss/gdi/ntgdi/surface.c
type Surface struct {
	Pix    []byte
	Width  int32
	Height int32
	Stride int32 // bytes per row = Width * 4
}

// NewSurface allocates an off-screen surface (memory DC backing bitmap).
func NewSurface(w, h int32) *Surface {
	stride := w * 4
	return &Surface{
		Pix:    make([]byte, stride*h),
		Width:  w,
		Height: h,
		Stride: stride,
	}
}

// WrapPix wraps an existing pixel buffer (e.g. wl.Window.Pix) as a Surface.
func WrapPix(pix []byte, w, h, stride int32) *Surface {
	return &Surface{Pix: pix, Width: w, Height: h, Stride: stride}
}

// SetPixel writes a COLORREF (0x00RRGGBB) to (x, y). No bounds check.
func (s *Surface) SetPixel(x, y int32, c uint32) {
	off := int(y)*int(s.Stride) + int(x)*4
	s.Pix[off+0] = byte(c >> 16) // R → stored as R in offset+2? No - XRGB8888 is B G R X
	// XRGB8888 in memory: byte0=B, byte1=G, byte2=R, byte3=X
	// COLORREF: 0x00RRGGBB → R=bits[23:16], G=bits[15:8], B=bits[7:0]
	s.Pix[off+0] = byte(c)        // B
	s.Pix[off+1] = byte(c >> 8)   // G
	s.Pix[off+2] = byte(c >> 16)  // R
	s.Pix[off+3] = 0xFF
}

// GetPixel reads a COLORREF (0x00RRGGBB) from (x, y). No bounds check.
// ReactOS: NtGdiGetPixel
func (s *Surface) GetPixel(x, y int32) uint32 {
	off := int(y)*int(s.Stride) + int(x)*4
	b := uint32(s.Pix[off+0])
	g := uint32(s.Pix[off+1])
	r := uint32(s.Pix[off+2])
	return r<<16 | g<<8 | b
}


func (s *Surface) FillRect(x0, y0, x1, y1 int32, color uint32) {
	if x0 < 0 {
		x0 = 0
	}
	if y0 < 0 {
		y0 = 0
	}
	if x1 > s.Width {
		x1 = s.Width
	}
	if y1 > s.Height {
		y1 = s.Height
	}
	if x0 >= x1 || y0 >= y1 {
		return
	}
	B := byte(color)
	G := byte(color >> 8)
	R := byte(color >> 16)
	stride := int(s.Stride)
	for y := int(y0); y < int(y1); y++ {
		off := y*stride + int(x0)*4
		for x := int(x0); x < int(x1); x++ {
			s.Pix[off+0] = B
			s.Pix[off+1] = G
			s.Pix[off+2] = R
			s.Pix[off+3] = 0xFF
			off += 4
		}
	}
}

// HLine draws a horizontal line from (x0,y) to (x1-1,y).
func (s *Surface) HLine(x0, x1, y int32, color uint32) {
	s.FillRect(x0, y, x1, y+1, color)
}

// VLine draws a vertical line from (x,y0) to (x,y1-1).
func (s *Surface) VLine(x, y0, y1 int32, color uint32) {
	s.FillRect(x, y0, x+1, y1, color)
}

// DrawLine draws a line from (x0,y0) to (x1,y1) using Bresenham's algorithm.
// ReactOS: IntEngLineTo in win32ss/gdi/eng/lineto.c
func (s *Surface) DrawLine(x0, y0, x1, y1 int32, color uint32) {
	dx := x1 - x0
	dy := y1 - y0
	if dx < 0 {
		dx = -dx
	}
	if dy < 0 {
		dy = -dy
	}
	sx := int32(1)
	if x0 > x1 {
		sx = -1
	}
	sy := int32(1)
	if y0 > y1 {
		sy = -1
	}
	err := dx - dy
	for {
		if x0 >= 0 && x0 < s.Width && y0 >= 0 && y0 < s.Height {
			s.SetPixel(x0, y0, color)
		}
		if x0 == x1 && y0 == y1 {
			break
		}
		e2 := err * 2
		if e2 > -dy {
			err -= dy
			x0 += sx
		}
		if e2 < dx {
			err += dx
			y0 += sy
		}
	}
}

// DrawRect draws a hollow rectangle outline.
func (s *Surface) DrawRect(x0, y0, x1, y1 int32, color uint32) {
	s.HLine(x0, x1, y0, color)
	s.HLine(x0, x1, y1-1, color)
	s.VLine(x0, y0, y1, color)
	s.VLine(x1-1, y0, y1, color)
}

// BitBlt copies a rectangle from src surface to this surface.
// ReactOS: EngBitBlt / DrvBitBlt in win32ss/gdi/eng/bitblt.c
func (s *Surface) BitBlt(dx, dy int32, src *Surface, sx, sy, w, h int32) {
	// Clip destination
	if dx < 0 {
		sx -= dx
		w += dx
		dx = 0
	}
	if dy < 0 {
		sy -= dy
		h += dy
		dy = 0
	}
	if dx+w > s.Width {
		w = s.Width - dx
	}
	if dy+h > s.Height {
		h = s.Height - dy
	}
	// Clip source
	if sx < 0 {
		dx -= sx
		w += sx
		sx = 0
	}
	if sy < 0 {
		dy -= sy
		h += sy
		sy = 0
	}
	if sx+w > src.Width {
		w = src.Width - sx
	}
	if sy+h > src.Height {
		h = src.Height - sy
	}
	if w <= 0 || h <= 0 {
		return
	}
	dstStride := int(s.Stride)
	srcStride := int(src.Stride)
	for row := int32(0); row < h; row++ {
		dOff := int(dy+row)*dstStride + int(dx)*4
		sOff := int(sy+row)*srcStride + int(sx)*4
		copy(s.Pix[dOff:dOff+int(w)*4], src.Pix[sOff:sOff+int(w)*4])
	}
}

// StretchBlt copies and scales src rect to dst rect using nearest-neighbour.
// ReactOS: EngStretchBlt in win32ss/gdi/eng/stretchblt.c
func (s *Surface) StretchBlt(dx, dy, dw, dh int32, src *Surface, sx, sy, sw, sh int32) {
	if dw <= 0 || dh <= 0 || sw <= 0 || sh <= 0 {
		return
	}
	for row := int32(0); row < dh; row++ {
		srcRow := sy + row*sh/dh
		if srcRow < 0 || srcRow >= src.Height {
			continue
		}
		dstY := dy + row
		if dstY < 0 || dstY >= s.Height {
			continue
		}
		for col := int32(0); col < dw; col++ {
			srcCol := sx + col*sw/dw
			if srcCol < 0 || srcCol >= src.Width {
				continue
			}
			dstX := dx + col
			if dstX < 0 || dstX >= s.Width {
				continue
			}
			sOff := int(srcRow)*int(src.Stride) + int(srcCol)*4
			dOff := int(dstY)*int(s.Stride) + int(dstX)*4
			copy(s.Pix[dOff:dOff+4], src.Pix[sOff:sOff+4])
		}
	}
}

// PatBlt fills a rectangle with a brush pattern.
// Currently supports solid brushes only; ROP3 is ignored (PATCOPY assumed).
// ReactOS: NtGdiPatBlt → EngBitBlt in win32ss/gdi/ntgdi/bitblt.c
func (s *Surface) PatBlt(x, y, w, h int32, color uint32) {
	s.FillRect(x, y, x+w, y+h, color)
}

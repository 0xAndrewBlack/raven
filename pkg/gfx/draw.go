package gfx

// GDI drawing primitives over a Surface: blits with ternary raster ops,
// stretch, alpha-blend, lines (Bresenham), rectangle/ellipse outline+fill. All
// honor the destination clip.

// Ternary raster operation codes (the common subset).
const (
	SRCCOPY    uint32 = 0x00CC0020 // dst = src
	SRCPAINT   uint32 = 0x00EE0086 // dst = src | dst
	SRCAND     uint32 = 0x008800C6 // dst = src & dst
	SRCINVERT  uint32 = 0x00660046 // dst = src ^ dst
	NOTSRCCOPY uint32 = 0x00330008 // dst = ~src
	DSTINVERT  uint32 = 0x00550009 // dst = ~dst
	BLACKNESS  uint32 = 0x00000042 // dst = 0
	WHITENESS  uint32 = 0x00FF0062 // dst = white
	PATCOPY    uint32 = 0x00F00021 // dst = pattern (here: src treated as pattern)
)

func applyROP(rop, dst, src uint32) uint32 {
	switch rop {
	case SRCCOPY, PATCOPY:
		return src
	case SRCPAINT:
		return 0xFF000000 | (src | dst)
	case SRCAND:
		return 0xFF000000 | (src & dst)
	case SRCINVERT:
		return 0xFF000000 | ((src ^ dst) & 0xFFFFFF)
	case NOTSRCCOPY:
		return 0xFF000000 | (^src & 0xFFFFFF)
	case DSTINVERT:
		return 0xFF000000 | (^dst & 0xFFFFFF)
	case BLACKNESS:
		return 0xFF000000
	case WHITENESS:
		return 0xFFFFFFFF
	default:
		return src
	}
}

// BitBlt copies a w×h block from src at (sx,sy) to dst at (dx,dy) applying rop.
func (dst *Surface) BitBlt(dx, dy, w, h int, src *Surface, sx, sy int, rop uint32) {
	for j := 0; j < h; j++ {
		for i := 0; i < w; i++ {
			ddx, ddy := dx+i, dy+j
			if !dst.inClip(ddx, ddy) {
				continue
			}
			var s uint32
			if src != nil {
				s = src.GetPixel(sx+i, sy+j)
			}
			di := ddy*dst.W + ddx
			dst.Pix[di] = applyROP(rop, dst.Pix[di], s)
		}
	}
}

// StretchBlt copies src[sx,sy,sw,sh] into dst[dx,dy,dw,dh] with nearest-neighbor
// scaling, applying rop.
func (dst *Surface) StretchBlt(dx, dy, dw, dh int, src *Surface, sx, sy, sw, sh int, rop uint32) {
	if dw == 0 || dh == 0 || sw == 0 || sh == 0 {
		return
	}
	for j := 0; j < dh; j++ {
		syj := sy + j*sh/dh
		for i := 0; i < dw; i++ {
			ddx, ddy := dx+i, dy+j
			if !dst.inClip(ddx, ddy) {
				continue
			}
			sxi := sx + i*sw/dw
			var s uint32
			if src != nil {
				s = src.GetPixel(sxi, syj)
			}
			di := ddy*dst.W + ddx
			dst.Pix[di] = applyROP(rop, dst.Pix[di], s)
		}
	}
}

// AlphaBlend blends src[sx,sy,sw,sh] into dst[dx,dy,dw,dh] (nearest-neighbor
// scaled) using each source pixel's alpha scaled by constAlpha (0..255).
func (dst *Surface) AlphaBlend(dx, dy, dw, dh int, src *Surface, sx, sy, sw, sh int, constAlpha uint32) {
	if dw == 0 || dh == 0 || sw == 0 || sh == 0 {
		return
	}
	for j := 0; j < dh; j++ {
		syj := sy + j*sh/dh
		for i := 0; i < dw; i++ {
			ddx, ddy := dx+i, dy+j
			if !dst.inClip(ddx, ddy) {
				continue
			}
			s := src.GetPixel(sx+i*sw/dw, syj)
			a := ((s >> 24) * constAlpha) / 255
			s = (a << 24) | (s & 0xFFFFFF)
			di := ddy*dst.W + ddx
			dst.Pix[di] = blendOver(dst.Pix[di], s)
		}
	}
}

// Line draws a solid line from (x0,y0) to (x1,y1) with Bresenham's algorithm.
func (s *Surface) Line(x0, y0, x1, y1 int, argb uint32) {
	dx := abs(x1 - x0)
	dy := -abs(y1 - y0)
	sx := sign(x1 - x0)
	sy := sign(y1 - y0)
	err := dx + dy
	for {
		s.SetPixel(x0, y0, argb)
		if x0 == x1 && y0 == y1 {
			break
		}
		e2 := 2 * err
		if e2 >= dy {
			err += dy
			x0 += sx
		}
		if e2 <= dx {
			err += dx
			y0 += sy
		}
	}
}

// FrameRect draws a 1px rectangle outline.
func (s *Surface) FrameRect(r Rect, argb uint32) {
	if r.Empty() {
		return
	}
	s.Line(r.Left, r.Top, r.Right-1, r.Top, argb)
	s.Line(r.Left, r.Bottom-1, r.Right-1, r.Bottom-1, argb)
	s.Line(r.Left, r.Top, r.Left, r.Bottom-1, argb)
	s.Line(r.Right-1, r.Top, r.Right-1, r.Bottom-1, argb)
}

// FillEllipse fills the ellipse inscribed in r (midpoint scanline fill).
func (s *Surface) FillEllipse(r Rect, argb uint32) {
	a := r.Width() / 2
	b := r.Height() / 2
	if a <= 0 || b <= 0 {
		return
	}
	cx := r.Left + a
	cy := r.Top + b
	a2, b2 := a*a, b*b
	for y := -b; y <= b; y++ {
		// x extent where (x/a)^2 + (y/b)^2 <= 1
		xspan := isqrt(a2 * (b2 - y*y) / b2)
		for x := -xspan; x <= xspan; x++ {
			s.SetPixel(cx+x, cy+y, argb)
		}
	}
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
func sign(x int) int {
	switch {
	case x > 0:
		return 1
	case x < 0:
		return -1
	}
	return 0
}
func isqrt(n int) int {
	if n <= 0 {
		return 0
	}
	x := n
	y := (x + 1) / 2
	for y < x {
		x = y
		y = (x + n/x) / 2
	}
	return x
}

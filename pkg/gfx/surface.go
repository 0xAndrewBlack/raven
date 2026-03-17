// Package gfx is the pure-Go GDI / software-raster engine for the win32k display
// side . It provides a pixel Surface with the GDI
// drawing primitives (fills, blits with ROPs, stretch, alpha-blend, lines,
// rectangles, ellipses, clipping), the GDI object model (DC, pen, brush, font,
// region), a TrueType text path (the ONLY text path - no bitmap fallback), and a
// DisplayBackend abstraction (screen surface vs offscreen memory DC; the Wayland
// fd backend in pkg/wl implements it). Like pkg/winmgr and pkg/ntobj it has no
// guest/CPU dependency and is fully unit-testable on its own.
package gfx

// Rect is a half-open rectangle (right/bottom exclusive), screen/device coords.
type Rect struct{ Left, Top, Right, Bottom int }

func (r Rect) Width() int  { return r.Right - r.Left }
func (r Rect) Height() int { return r.Bottom - r.Top }
func (r Rect) Empty() bool { return r.Right <= r.Left || r.Bottom <= r.Top }

// Intersect returns the overlap of two rectangles (possibly empty).
func (r Rect) Intersect(o Rect) Rect {
	out := Rect{max(r.Left, o.Left), max(r.Top, o.Top), min(r.Right, o.Right), min(r.Bottom, o.Bottom)}
	if out.Empty() {
		return Rect{}
	}
	return out
}

// Surface is a 32-bit ARGB pixel buffer (0xAARRGGBB). It implements draw.Image so
// the TrueType text path can render anti-aliased glyphs directly into it.
type Surface struct {
	W, H int
	Pix  []uint32
	clip Rect
}

// NewSurface allocates a w×h surface with the clip set to the full bounds.
func NewSurface(w, h int) *Surface {
	if w < 0 {
		w = 0
	}
	if h < 0 {
		h = 0
	}
	return &Surface{W: w, H: h, Pix: make([]uint32, w*h), clip: Rect{0, 0, w, h}}
}

// Bounds is the full surface rectangle.
func (s *Surface) Bounds() Rect { return Rect{0, 0, s.W, s.H} }

// SetClip intersects the clip rectangle with the surface bounds.
func (s *Surface) SetClip(r Rect) { s.clip = r.Intersect(s.Bounds()) }

// Clip returns the current clip rectangle.
func (s *Surface) Clip() Rect { return s.clip }

// ResetClip restores the clip to the full bounds.
func (s *Surface) ResetClip() { s.clip = s.Bounds() }

func (s *Surface) inClip(x, y int) bool {
	return x >= s.clip.Left && x < s.clip.Right && y >= s.clip.Top && y < s.clip.Bottom
}

// SetPixel writes an ARGB pixel if it lies within the clip.
func (s *Surface) SetPixel(x, y int, argb uint32) {
	if s.inClip(x, y) {
		s.Pix[y*s.W+x] = argb
	}
}

// GetPixel reads an ARGB pixel (0 if out of bounds).
func (s *Surface) GetPixel(x, y int) uint32 {
	if x < 0 || y < 0 || x >= s.W || y >= s.H {
		return 0
	}
	return s.Pix[y*s.W+x]
}

// FillRect fills r (clipped) with a solid ARGB color.
func (s *Surface) FillRect(r Rect, argb uint32) {
	r = r.Intersect(s.clip)
	for y := r.Top; y < r.Bottom; y++ {
		row := y * s.W
		for x := r.Left; x < r.Right; x++ {
			s.Pix[row+x] = argb
		}
	}
}

// blend composites src (premultiplied-by-alpha conceptually, straight here) over
// dst using src's alpha (source-over).
func blendOver(dst, src uint32) uint32 {
	sa := src >> 24
	if sa == 0xFF {
		return src
	}
	if sa == 0 {
		return dst
	}
	da := 255 - sa
	sr, sg, sb := (src>>16)&0xFF, (src>>8)&0xFF, src&0xFF
	dr, dg, db := (dst>>16)&0xFF, (dst>>8)&0xFF, dst&0xFF
	r := (sr*sa + dr*da) / 255
	g := (sg*sa + dg*da) / 255
	b := (sb*sa + db*da) / 255
	oa := sa + (da*((dst>>24)&0xFF))/255
	return oa<<24 | r<<16 | g<<8 | b
}

// BlendPixel composites an ARGB color over the destination pixel (source-over).
func (s *Surface) BlendPixel(x, y int, argb uint32) {
	if s.inClip(x, y) {
		i := y*s.W + x
		s.Pix[i] = blendOver(s.Pix[i], argb)
	}
}

// COLORREF (0x00BBGGRR) conversions.
func FromCOLORREF(cr uint32) uint32 {
	r := cr & 0xFF
	g := (cr >> 8) & 0xFF
	b := (cr >> 16) & 0xFF
	return 0xFF000000 | r<<16 | g<<8 | b
}

// ToCOLORREF converts an opaque ARGB color to a Win32 COLORREF.
func ToCOLORREF(argb uint32) uint32 {
	r := (argb >> 16) & 0xFF
	g := (argb >> 8) & 0xFF
	b := argb & 0xFF
	return b<<16 | g<<8 | r
}

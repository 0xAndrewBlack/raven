//go:build guest_windows

package gdi

// dib.go - Device Independent Bitmap (DIB) support
// ReactOS reference: win32ss/gdi/ntgdi/dibobj.c

// DIBCompression constants - biCompression field in BITMAPINFOHEADER.
const (
	BIrgb       = 0 // uncompressed RGB
	BIrle8      = 1 // 8-bit RLE
	BIrle4      = 2 // 4-bit RLE
	BIbitfields = 3 // bit-field masks follow header
	BIjpeg      = 4
	BIpng       = 5
)

// DIBRow calculates the byte offset of a scanline in a bottom-up or top-down DIB.
// width is in pixels, bitCount is bits per pixel, row is the scanline index
// (0 = topmost visible row for top-down, bottommost row for bottom-up).
// Returns the byte offset from the start of the pixel data.
func DIBRowOffset(width, bitCount, row int32) int32 {
	stride := DIBStride(width, bitCount)
	return row * stride
}

// DIBStride returns the padded byte width of one scanline.
// ReactOS: DIB_GetDIBWidthBytes
func DIBStride(width, bitCount int32) int32 {
	return ((width*bitCount + 31) / 32) * 4
}

// ReadDIBPixel reads a single pixel from a DIB scanline buffer and returns COLORREF.
// colorTable is the 8bpp/4bpp/1bpp colour lookup (nil for 16/24/32bpp).
// ReactOS: DIB_GetSource
func ReadDIBPixel(row []byte, col, bitCount int32, colorTable []uint32) uint32 {
	switch bitCount {
	case 32:
		off := col * 4
		if int(off+3) >= len(row) {
			return 0
		}
		b := uint32(row[off+0])
		g := uint32(row[off+1])
		r := uint32(row[off+2])
		return r<<16 | g<<8 | b
	case 24:
		off := col * 3
		if int(off+2) >= len(row) {
			return 0
		}
		b := uint32(row[off+0])
		g := uint32(row[off+1])
		r := uint32(row[off+2])
		return r<<16 | g<<8 | b
	case 16:
		off := col * 2
		if int(off+1) >= len(row) {
			return 0
		}
		w := uint32(row[off+0]) | uint32(row[off+1])<<8
		// Default 5-5-5: XRRRRRGGGGGBBBBB
		r := (w >> 10) & 0x1F
		g := (w >> 5) & 0x1F
		b := w & 0x1F
		return (r<<3)<<16 | (g<<3)<<8 | (b << 3)
	case 8:
		if int(col) >= len(row) || colorTable == nil {
			return 0
		}
		idx := uint32(row[col])
		if int(idx) >= len(colorTable) {
			return 0
		}
		return colorTable[idx]
	case 4:
		byteOff := col / 2
		if int(byteOff) >= len(row) || colorTable == nil {
			return 0
		}
		var idx uint32
		if col%2 == 0 {
			idx = uint32(row[byteOff] >> 4)
		} else {
			idx = uint32(row[byteOff] & 0x0F)
		}
		if int(idx) >= len(colorTable) {
			return 0
		}
		return colorTable[idx]
	case 1:
		byteOff := col / 8
		bitOff := 7 - (col % 8)
		if int(byteOff) >= len(row) || colorTable == nil {
			return 0
		}
		idx := (uint32(row[byteOff]) >> uint(bitOff)) & 1
		if int(idx) >= len(colorTable) {
			return 0
		}
		return colorTable[idx]
	}
	return 0
}

// ReadDIBPixel32WithAlpha is like ReadDIBPixel but also extracts the alpha byte
// for 32bpp bitmaps. Returns (colorref, alpha).
func ReadDIBPixel32WithAlpha(row []byte, col int32) (uint32, uint8) {
	off := col * 4
	if int(off+3) >= len(row) {
		return 0, 0xFF
	}
	b := uint32(row[off+0])
	g := uint32(row[off+1])
	r := uint32(row[off+2])
	a := row[off+3]
	return r<<16 | g<<8 | b, a
}

// BlitDIB blits a DIB (Device Independent Bitmap) rectangle to a Surface.
// pixData is the raw DIB pixel bytes (no BITMAPFILEHEADER, starting at pixel data).
// width, height are the full DIB dimensions (height > 0 means bottom-up).
// bitCount: bits per pixel (1,4,8,16,24,32).
// colorTable: RGBQUAD entries for indexed bitmaps (as COLORREFs 0x00RRGGBB).
// Src rect: (sx,sy)→(sx+sw, sy+sh) in DIB coords (0,0 = top-left visible).
// Dst rect on surface: (dx,dy)→(dx+dw, dy+dh).
// ReactOS: NtGdiStretchDIBitsInternal
func (s *Surface) BlitDIB(
	dx, dy, dw, dh int32,
	pixData []byte, srcW, srcH, bitCount int32, colorTable []uint32,
	sx, sy, sw, sh int32,
) {
	if dw <= 0 || dh <= 0 || sw <= 0 || sh <= 0 {
		return
	}
	stride := DIBStride(srcW, bitCount)
	bottomUp := srcH > 0
	absH := srcH
	if absH < 0 {
		absH = -absH
	}

	for row := int32(0); row < dh; row++ {
		// Map destination row → source row in DIB
		srcRowIdx := sy + row*sh/dh
		if srcRowIdx < 0 || srcRowIdx >= absH {
			continue
		}
		// For bottom-up DIB: row 0 of visible image = last byte row
		var dibRow []byte
		if bottomUp {
			byteRow := absH - 1 - srcRowIdx
			off := int(byteRow) * int(stride)
			end := off + int(stride)
			if off < 0 || end > len(pixData) {
				continue
			}
			dibRow = pixData[off:end]
		} else {
			off := int(srcRowIdx) * int(stride)
			end := off + int(stride)
			if off < 0 || end > len(pixData) {
				continue
			}
			dibRow = pixData[off:end]
		}

		dstY := dy + row
		if dstY < 0 || dstY >= s.Height {
			continue
		}

		for col := int32(0); col < dw; col++ {
			srcColIdx := sx + col*sw/dw
			if srcColIdx < 0 || srcColIdx >= srcW {
				continue
			}
			dstX := dx + col
			if dstX < 0 || dstX >= s.Width {
				continue
			}
			color := ReadDIBPixel(dibRow, srcColIdx, bitCount, colorTable)
			s.SetPixel(dstX, dstY, color)
		}
	}
}

// BlitDIBAlpha blits a 32bpp DIB with per-pixel alpha onto a Surface.
// ReactOS: NtGdiAlphaBlend with AC_SRC_ALPHA
func (s *Surface) BlitDIBAlpha(
	dx, dy, dw, dh int32,
	pixData []byte, srcW, srcH int32,
	sx, sy, sw, sh int32,
	globalAlpha uint8,
) {
	if dw <= 0 || dh <= 0 || sw <= 0 || sh <= 0 {
		return
	}
	stride := DIBStride(srcW, 32)
	bottomUp := srcH > 0
	absH := srcH
	if absH < 0 {
		absH = -absH
	}

	for row := int32(0); row < dh; row++ {
		srcRowIdx := sy + row*sh/dh
		if srcRowIdx < 0 || srcRowIdx >= absH {
			continue
		}
		var dibRow []byte
		if bottomUp {
			byteRow := absH - 1 - srcRowIdx
			off := int(byteRow) * int(stride)
			end := off + int(stride)
			if off < 0 || end > len(pixData) {
				continue
			}
			dibRow = pixData[off:end]
		} else {
			off := int(srcRowIdx) * int(stride)
			end := off + int(stride)
			if off < 0 || end > len(pixData) {
				continue
			}
			dibRow = pixData[off:end]
		}
		dstY := dy + row
		if dstY < 0 || dstY >= s.Height {
			continue
		}
		for col := int32(0); col < dw; col++ {
			srcColIdx := sx + col*sw/dw
			if srcColIdx < 0 || srcColIdx >= srcW {
				continue
			}
			dstX := dx + col
			if dstX < 0 || dstX >= s.Width {
				continue
			}
			srcColor, srcA := ReadDIBPixel32WithAlpha(dibRow, srcColIdx)
			alpha := uint32(srcA) * uint32(globalAlpha) / 255
			if alpha == 0 {
				continue
			}
			if alpha == 255 {
				s.SetPixel(dstX, dstY, srcColor)
				continue
			}
			dstColor := s.GetPixel(dstX, dstY)
			blended := alphaBlendColor(srcColor, dstColor, uint8(alpha))
			s.SetPixel(dstX, dstY, blended)
		}
	}
}

// AlphaBlendSurface blends src surface onto dst surface with optional per-pixel alpha.
// ReactOS: NtGdiAlphaBlend → EngAlphaBlend
func (s *Surface) AlphaBlendSurface(
	dx, dy, dw, dh int32,
	src *Surface, sx, sy, sw, sh int32,
	globalAlpha uint8, perPixel bool,
) {
	if src == nil || dw <= 0 || dh <= 0 || sw <= 0 || sh <= 0 {
		return
	}
	for row := int32(0); row < dh; row++ {
		srcY := sy + row*sh/dh
		dstY := dy + row
		if srcY < 0 || srcY >= src.Height || dstY < 0 || dstY >= s.Height {
			continue
		}
		for col := int32(0); col < dw; col++ {
			srcX := sx + col*sw/dw
			dstX := dx + col
			if srcX < 0 || srcX >= src.Width || dstX < 0 || dstX >= s.Width {
				continue
			}
			srcColor := src.GetPixel(srcX, srcY)
			var alpha uint8
			if perPixel {
				// 32bpp surface: alpha is in byte 3
				off := int(srcY)*int(src.Stride) + int(srcX)*4
				if off+3 < len(src.Pix) {
					a := uint32(src.Pix[off+3]) * uint32(globalAlpha) / 255
					alpha = uint8(a)
				} else {
					alpha = globalAlpha
				}
			} else {
				alpha = globalAlpha
			}
			if alpha == 0 {
				continue
			}
			if alpha == 255 {
				s.SetPixel(dstX, dstY, srcColor)
				continue
			}
			dstColor := s.GetPixel(dstX, dstY)
			s.SetPixel(dstX, dstY, alphaBlendColor(srcColor, dstColor, alpha))
		}
	}
}

// alphaBlendColor computes: dst = src*alpha/255 + dst*(255-alpha)/255
func alphaBlendColor(src, dst uint32, alpha uint8) uint32 {
	a := uint32(alpha)
	ia := uint32(255 - alpha)
	sr := (src >> 16) & 0xFF
	sg := (src >> 8) & 0xFF
	sb := src & 0xFF
	dr := (dst >> 16) & 0xFF
	dg := (dst >> 8) & 0xFF
	db := dst & 0xFF
	r := (sr*a + dr*ia) / 255
	g := (sg*a + dg*ia) / 255
	b := (sb*a + db*ia) / 255
	return r<<16 | g<<8 | b
}

// TransparentBlt blits src to dst skipping pixels that match the transparent color.
// ReactOS: NtGdiTransparentBlt
func (s *Surface) TransparentBlt(
	dx, dy, dw, dh int32,
	src *Surface, sx, sy, sw, sh int32,
	transColor uint32,
) {
	if src == nil || dw <= 0 || dh <= 0 || sw <= 0 || sh <= 0 {
		return
	}
	for row := int32(0); row < dh; row++ {
		srcY := sy + row*sh/dh
		dstY := dy + row
		if srcY < 0 || srcY >= src.Height || dstY < 0 || dstY >= s.Height {
			continue
		}
		for col := int32(0); col < dw; col++ {
			srcX := sx + col*sw/dw
			dstX := dx + col
			if srcX < 0 || srcX >= src.Width || dstX < 0 || dstX >= s.Width {
				continue
			}
			c := src.GetPixel(srcX, srcY)
			if c == transColor {
				continue
			}
			s.SetPixel(dstX, dstY, c)
		}
	}
}

// GradientFillH fills a horizontal gradient from colorLeft to colorRight.
// ReactOS: NtGdiGradientFill GRADIENT_FILL_RECT_H
func (s *Surface) GradientFillH(x0, y0, x1, y1 int32, colorLeft, colorRight uint32) {
	if x0 >= x1 || y0 >= y1 {
		return
	}
	w := x1 - x0
	for col := int32(0); col < w; col++ {
		t := uint32(col * 256 / w)
		c := lerpColor(colorLeft, colorRight, t)
		for row := y0; row < y1; row++ {
			if x0+col >= 0 && x0+col < s.Width && row >= 0 && row < s.Height {
				s.SetPixel(x0+col, row, c)
			}
		}
	}
}

// GradientFillV fills a vertical gradient from colorTop to colorBottom.
// ReactOS: NtGdiGradientFill GRADIENT_FILL_RECT_V
func (s *Surface) GradientFillV(x0, y0, x1, y1 int32, colorTop, colorBottom uint32) {
	if x0 >= x1 || y0 >= y1 {
		return
	}
	h := y1 - y0
	for row := int32(0); row < h; row++ {
		t := uint32(row * 256 / h)
		c := lerpColor(colorTop, colorBottom, t)
		for col := x0; col < x1; col++ {
			if col >= 0 && col < s.Width && y0+row >= 0 && y0+row < s.Height {
				s.SetPixel(col, y0+row, c)
			}
		}
	}
}

func lerpColor(c0, c1, t uint32) uint32 {
	r0, g0, b0 := (c0>>16)&0xFF, (c0>>8)&0xFF, c0&0xFF
	r1, g1, b1 := (c1>>16)&0xFF, (c1>>8)&0xFF, c1&0xFF
	r := r0 + (r1-r0)*t/256
	g := g0 + (g1-g0)*t/256
	b := b0 + (b1-b0)*t/256
	return r<<16 | g<<8 | b
}

// WriteDIBFromSurface writes the pixels of a Surface into a DIB byte buffer.
// Used by GetDIBits. bitCount must be 24 or 32. Buffer must be pre-allocated.
// ReactOS: NtGdiGetDIBitsInternal
func WriteDIBFromSurface(buf []byte, s *Surface, sx, sy, sw, sh, bitCount int32) {
	stride := DIBStride(sw, bitCount)
	// Win32 GetDIBits default: bottom-up
	for row := int32(0); row < sh; row++ {
		srcY := sy + row
		dstRow := sh - 1 - row // bottom-up
		if srcY < 0 || srcY >= s.Height {
			continue
		}
		off := int(dstRow) * int(stride)
		for col := int32(0); col < sw; col++ {
			srcX := sx + col
			if srcX < 0 || srcX >= s.Width {
				continue
			}
			c := s.GetPixel(srcX, srcY)
			pixOff := off + int(col)*int(bitCount/8)
			if bitCount == 32 {
				if pixOff+3 >= len(buf) {
					continue
				}
				buf[pixOff+0] = byte(c)       // B
				buf[pixOff+1] = byte(c >> 8)  // G
				buf[pixOff+2] = byte(c >> 16) // R
				buf[pixOff+3] = 0xFF          // A
			} else if bitCount == 24 {
				if pixOff+2 >= len(buf) {
					continue
				}
				buf[pixOff+0] = byte(c)       // B
				buf[pixOff+1] = byte(c >> 8)  // G
				buf[pixOff+2] = byte(c >> 16) // R
			}
		}
	}
}

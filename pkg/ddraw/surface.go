package ddraw

import (
	"encoding/binary"
	"errors"
	"math/bits"
	"unsafe"

	"github.com/mirkobrombin/Raven/pkg/gdi"
)

type Surface struct {
	Width      uint32
	Height     uint32
	BPP        uint32
	Pitch      int
	Pixels     []byte
	Format     DDPIXELFORMAT
	Caps       DDSCAPS2
	Locked     bool
	BackBuffer *Surface
	ColorKey   *DDCOLORKEY
	Palette    *Palette
	IsPrimary  bool

	gdiMgr   *gdi.Manager
	dcHandle uint64
	dcBitmap uint64
	dcShadow []byte
}

func newSurface(width, height, bpp uint32, format DDPIXELFORMAT, caps DDSCAPS2) *Surface {
	pitch := alignedPitch(width, bpp)
	return &Surface{
		Width:  width,
		Height: height,
		BPP:    bpp,
		Pitch:  pitch,
		Pixels: make([]byte, pitch*int(height)),
		Format: format,
		Caps:   caps,
	}
}

func (s *Surface) SetGDIManager(m *gdi.Manager) {
	s.gdiMgr = m
}

func (s *Surface) Lock(rect *Rect, desc *DDSURFACEDESC2, flags uint32) error {
	_ = flags
	if s.Locked {
		return errors.New("ddraw: surface already locked")
	}
	s.Locked = true
	if desc != nil {
		lockRect := s.clipRect(rect)
		desc.DwSize = uint32(sizeofDDSurfaceDesc2())
		desc.DwFlags = DDSD_CAPS | DDSD_HEIGHT | DDSD_WIDTH | DDSD_PITCH | DDSD_PIXELFORMAT
		desc.DwWidth = uint32(lockRect.Right - lockRect.Left)
		desc.DwHeight = uint32(lockRect.Bottom - lockRect.Top)
		desc.LPitch = int32(s.Pitch)
		desc.DdpfPixelFormat = s.Format
		desc.DdsCaps = s.Caps
		desc.LpSurface = s.lockPointer(lockRect.Left, lockRect.Top)
	}
	return nil
}

func (s *Surface) Unlock(rect *Rect) error {
	_ = rect
	if !s.Locked {
		return nil
	}
	s.Locked = false
	return nil
}

func (s *Surface) Blt(destRect *Rect, srcSurface *Surface, srcRect *Rect, flags uint32, bltFx *DDBLTFX) error {
	dst := s.clipRect(destRect)
	if flags&DDBLT_COLORFILL != 0 {
		fill := uint32(0)
		if bltFx != nil {
			fill = bltFx.DwFillColor
		}
		for y := int(dst.Top); y < int(dst.Bottom); y++ {
			for x := int(dst.Left); x < int(dst.Right); x++ {
				s.setPixelColor(x, y, fill)
			}
		}
		return nil
	}
	if srcSurface == nil {
		return errors.New("ddraw: missing source surface")
	}
	src := srcSurface.clipRect(srcRect)
	dstW := int(dst.Right - dst.Left)
	dstH := int(dst.Bottom - dst.Top)
	srcW := int(src.Right - src.Left)
	srcH := int(src.Bottom - src.Top)
	if dstW <= 0 || dstH <= 0 || srcW <= 0 || srcH <= 0 {
		return nil
	}
	useColorKey := flags&DDBLT_KEYSRC != 0 && srcSurface.ColorKey != nil
	for y := 0; y < dstH; y++ {
		sy := int(src.Top) + y
		if dstH != srcH {
			sy = int(src.Top) + y*srcH/dstH
		}
		for x := 0; x < dstW; x++ {
			sx := int(src.Left) + x
			if dstW != srcW {
				sx = int(src.Left) + x*srcW/dstW
			}
			color := srcSurface.getPixelColor(sx, sy)
			if useColorKey {
				low := srcSurface.ColorKey.DwColorSpaceLowValue
				high := srcSurface.ColorKey.DwColorSpaceHighValue
				if color >= low && color <= high {
					continue
				}
			}
			s.setPixelColor(int(dst.Left)+x, int(dst.Top)+y, color)
		}
	}
	return nil
}

func (s *Surface) BltFast(x, y int32, srcSurface *Surface, srcRect *Rect, flags uint32) error {
	if srcSurface == nil {
		return errors.New("ddraw: missing source surface")
	}
	src := srcSurface.clipRect(srcRect)
	dst := Rect{Left: x, Top: y, Right: x + (src.Right - src.Left), Bottom: y + (src.Bottom - src.Top)}
	useColorKey := flags&DDBLTFAST_SRCCOLORKEY != 0 && srcSurface.ColorKey != nil
	dst = s.clipRect(&dst)
	for dy := int(dst.Top); dy < int(dst.Bottom); dy++ {
		sy := int(src.Top) + (dy - int(y))
		for dx := int(dst.Left); dx < int(dst.Right); dx++ {
			sx := int(src.Left) + (dx - int(x))
			color := srcSurface.getPixelColor(sx, sy)
			if useColorKey {
				low := srcSurface.ColorKey.DwColorSpaceLowValue
				high := srcSurface.ColorKey.DwColorSpaceHighValue
				if color >= low && color <= high {
					continue
				}
			}
			s.setPixelColor(dx, dy, color)
		}
	}
	return nil
}

func (s *Surface) Flip(targetOverride *Surface, flags uint32) error {
	_ = flags
	target := targetOverride
	if target == nil {
		target = s.BackBuffer
	}
	if target == nil {
		return errors.New("ddraw: no back buffer")
	}
	s.Pixels, target.Pixels = target.Pixels, s.Pixels
	return nil
}

func (s *Surface) GetSurfaceDesc(desc *DDSURFACEDESC2) error {
	if desc == nil {
		return errors.New("ddraw: nil surface desc")
	}
	desc.DwSize = uint32(sizeofDDSurfaceDesc2())
	desc.DwFlags = DDSD_CAPS | DDSD_HEIGHT | DDSD_WIDTH | DDSD_PITCH | DDSD_PIXELFORMAT
	desc.DwWidth = s.Width
	desc.DwHeight = s.Height
	desc.LPitch = int32(s.Pitch)
	desc.DdpfPixelFormat = s.Format
	desc.DdsCaps = s.Caps
	desc.LpSurface = s.lockPointer(0, 0)
	return nil
}

func (s *Surface) GetDC() (uint64, *gdi.DC) {
	if s.dcHandle != 0 && s.gdiMgr != nil {
		return s.dcHandle, s.gdiMgr.GetDC(s.dcHandle)
	}
	mgr := s.gdiMgr
	if mgr == nil {
		mgr = gdi.NewManager()
		s.gdiMgr = mgr
	}
	hdc, dc := mgr.AllocMemDC()
	pix := s.Pixels
	if s.BPP != 32 || s.Pitch != int(s.Width)*4 {
		pix = s.ReadbackXRGB8888(int(s.Width), int(s.Height))
		s.dcShadow = pix
	} else {
		s.dcShadow = nil
	}
	s.dcBitmap = mgr.CreateDIBSectionWithData(int32(s.Width), int32(s.Height), 32, 0, pix, true)
	mgr.SelectObject(hdc, s.dcBitmap)
	s.dcHandle = hdc
	return hdc, dc
}

func (s *Surface) ReleaseDC(hdc uint64) error {
	if s.gdiMgr == nil || s.dcHandle == 0 || (hdc != 0 && hdc != s.dcHandle) {
		return nil
	}
	if len(s.dcShadow) != 0 {
		for y := 0; y < int(s.Height); y++ {
			for x := 0; x < int(s.Width); x++ {
				off := (y*int(s.Width) + x) * 4
				color := uint32(s.dcShadow[off+2])<<16 | uint32(s.dcShadow[off+1])<<8 | uint32(s.dcShadow[off])
				s.setPixelColor(x, y, color)
			}
		}
	}
	if s.dcBitmap != 0 {
		s.gdiMgr.DeleteObject(s.dcBitmap)
	}
	s.gdiMgr.DeleteDC(s.dcHandle)
	s.dcHandle = 0
	s.dcBitmap = 0
	s.dcShadow = nil
	return nil
}

func (s *Surface) SetColorKey(flags uint32, colorKey *DDCOLORKEY) {
	_ = flags
	if colorKey == nil {
		s.ColorKey = nil
		return
	}
	dup := *colorKey
	s.ColorKey = &dup
}

func (s *Surface) SetPalette(p *Palette) {
	s.Palette = p
}

func (s *Surface) GetAttachedSurface(caps *DDSCAPS2) *Surface {
	if s.BackBuffer == nil {
		return nil
	}
	if caps == nil || caps.DwCaps == 0 || caps.DwCaps&DDSCAPS_BACKBUFFER != 0 {
		return s.BackBuffer
	}
	return nil
}

func (s *Surface) clipRect(rect *Rect) Rect {
	r := Rect{Left: 0, Top: 0, Right: int32(s.Width), Bottom: int32(s.Height)}
	if rect == nil {
		return r
	}
	r = *rect
	if r.Left < 0 {
		r.Left = 0
	}
	if r.Top < 0 {
		r.Top = 0
	}
	if r.Right > int32(s.Width) {
		r.Right = int32(s.Width)
	}
	if r.Bottom > int32(s.Height) {
		r.Bottom = int32(s.Height)
	}
	if r.Right < r.Left {
		r.Right = r.Left
	}
	if r.Bottom < r.Top {
		r.Bottom = r.Top
	}
	return r
}

func (s *Surface) lockPointer(x, y int32) uint64 {
	if len(s.Pixels) == 0 {
		return 0
	}
	offset := int(y)*s.Pitch + int(x)*bytesPerPixel(s.BPP)
	if offset < 0 || offset >= len(s.Pixels) {
		return 0
	}
	return uint64(uintptr(unsafe.Pointer(&s.Pixels[offset])))
}

func (s *Surface) getPixelColor(x, y int) uint32 {
	if x < 0 || y < 0 || x >= int(s.Width) || y >= int(s.Height) {
		return 0
	}
	off := y*s.Pitch + x*bytesPerPixel(s.BPP)
	switch s.BPP {
	case 8:
		idx := int(s.Pixels[off])
		if s.Palette == nil {
			v := uint32(idx)
			return v<<16 | v<<8 | v
		}
		entry := s.Palette.Entries[idx]
		return uint32(entry.Red)<<16 | uint32(entry.Green)<<8 | uint32(entry.Blue)
	case 16:
		raw := binary.LittleEndian.Uint16(s.Pixels[off : off+2])
		return decode16Bit(raw, s.Format)
	default:
		raw := binary.LittleEndian.Uint32(s.Pixels[off : off+4])
		return decode32Bit(raw, s.Format)
	}
}

func (s *Surface) setPixelColor(x, y int, color uint32) {
	if x < 0 || y < 0 || x >= int(s.Width) || y >= int(s.Height) {
		return
	}
	off := y*s.Pitch + x*bytesPerPixel(s.BPP)
	switch s.BPP {
	case 8:
		if s.Palette == nil {
			r := (color >> 16) & 0xFF
			g := (color >> 8) & 0xFF
			b := color & 0xFF
			s.Pixels[off] = byte((r + g + b) / 3)
			return
		}
		best := 0
		bestScore := uint32(^uint32(0))
		r := int32((color >> 16) & 0xFF)
		g := int32((color >> 8) & 0xFF)
		b := int32(color & 0xFF)
		for i, entry := range s.Palette.Entries {
			dr := r - int32(entry.Red)
			dg := g - int32(entry.Green)
			db := b - int32(entry.Blue)
			score := uint32(dr*dr + dg*dg + db*db)
			if score < bestScore {
				bestScore = score
				best = i
				if score == 0 {
					break
				}
			}
		}
		s.Pixels[off] = byte(best)
	case 16:
		binary.LittleEndian.PutUint16(s.Pixels[off:off+2], encode16Bit(color, s.Format))
	default:
		binary.LittleEndian.PutUint32(s.Pixels[off:off+4], encode32Bit(color, s.Format))
	}
}

func alignedPitch(width, bpp uint32) int {
	row := int(width) * bytesPerPixel(bpp)
	return (row + 3) &^ 3
}

func bytesPerPixel(bpp uint32) int {
	switch bpp {
	case 8:
		return 1
	case 16:
		return 2
	default:
		return 4
	}
}

func defaultPixelFormat(bpp uint32) DDPIXELFORMAT {
	pf := DDPIXELFORMAT{
		DwSize:        uint32(sizeofDDPixelFormat()),
		DwRGBBitCount: bpp,
	}
	switch bpp {
	case 8:
		pf.DwFlags = DDPF_PALETTEINDEXED8 | DDPF_RGB
	case 16:
		pf.DwFlags = DDPF_RGB
		pf.DwRBitMask = 0xF800
		pf.DwGBitMask = 0x07E0
		pf.DwBBitMask = 0x001F
	default:
		pf.DwFlags = DDPF_RGB
		pf.DwRGBBitCount = 32
		pf.DwRBitMask = 0x00FF0000
		pf.DwGBitMask = 0x0000FF00
		pf.DwBBitMask = 0x000000FF
	}
	return pf
}

func decode16Bit(raw uint16, format DDPIXELFORMAT) uint32 {
	rMask, gMask, bMask := format.DwRBitMask, format.DwGBitMask, format.DwBBitMask
	if rMask == 0 || gMask == 0 || bMask == 0 {
		rMask, gMask, bMask = 0xF800, 0x07E0, 0x001F
	}
	return decodeMaskedColor(uint32(raw), rMask, gMask, bMask)
}

func decode32Bit(raw uint32, format DDPIXELFORMAT) uint32 {
	rMask, gMask, bMask := format.DwRBitMask, format.DwGBitMask, format.DwBBitMask
	if rMask == 0 || gMask == 0 || bMask == 0 {
		rMask, gMask, bMask = 0x00FF0000, 0x0000FF00, 0x000000FF
	}
	return decodeMaskedColor(raw, rMask, gMask, bMask)
}

func decodeMaskedColor(raw, rMask, gMask, bMask uint32) uint32 {
	r := extractMasked(raw, rMask)
	g := extractMasked(raw, gMask)
	b := extractMasked(raw, bMask)
	return r<<16 | g<<8 | b
}

func encode16Bit(color uint32, format DDPIXELFORMAT) uint16 {
	rMask, gMask, bMask := format.DwRBitMask, format.DwGBitMask, format.DwBBitMask
	if rMask == 0 || gMask == 0 || bMask == 0 {
		rMask, gMask, bMask = 0xF800, 0x07E0, 0x001F
	}
	return uint16(encodeMaskedColor(color, rMask, gMask, bMask))
}

func encode32Bit(color uint32, format DDPIXELFORMAT) uint32 {
	rMask, gMask, bMask := format.DwRBitMask, format.DwGBitMask, format.DwBBitMask
	if rMask == 0 || gMask == 0 || bMask == 0 {
		rMask, gMask, bMask = 0x00FF0000, 0x0000FF00, 0x000000FF
	}
	raw := encodeMaskedColor(color, rMask, gMask, bMask)
	if format.DwAlphaBitMask != 0 {
		raw |= format.DwAlphaBitMask
	}
	return raw
}

func encodeMaskedColor(color, rMask, gMask, bMask uint32) uint32 {
	raw := uint32(0)
	raw |= placeMasked((color>>16)&0xFF, rMask)
	raw |= placeMasked((color>>8)&0xFF, gMask)
	raw |= placeMasked(color&0xFF, bMask)
	return raw
}

func extractMasked(raw, mask uint32) uint32 {
	if mask == 0 {
		return 0
	}
	shift := bits.TrailingZeros32(mask)
	value := (raw & mask) >> shift
	max := mask >> shift
	if max == 0 {
		return 0
	}
	return value * 255 / max
}

func placeMasked(value, mask uint32) uint32 {
	if mask == 0 {
		return 0
	}
	shift := bits.TrailingZeros32(mask)
	max := mask >> shift
	return ((value * max / 255) << shift) & mask
}

func sizeofDDSurfaceDesc2() int {
	var v DDSURFACEDESC2
	return int(unsafe.Sizeof(v))
}

func sizeofDDPixelFormat() int {
	var v DDPIXELFORMAT
	return int(unsafe.Sizeof(v))
}

func sizeofDDCaps() int {
	var v DDCAPS
	return int(unsafe.Sizeof(v))
}

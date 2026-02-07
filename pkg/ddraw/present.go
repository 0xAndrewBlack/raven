//go:build guest_windows

package ddraw

func (s *Surface) ReadbackXRGB8888(dstWidth, dstHeight int) []byte {
	if dstWidth <= 0 {
		dstWidth = int(s.Width)
	}
	if dstHeight <= 0 {
		dstHeight = int(s.Height)
	}
	out := make([]byte, dstWidth*dstHeight*4)
	if s == nil || s.Width == 0 || s.Height == 0 {
		return out
	}
	for y := 0; y < dstHeight; y++ {
		srcY := int(uint64(y) * uint64(s.Height) / uint64(dstHeight))
		if srcY >= int(s.Height) {
			srcY = int(s.Height) - 1
		}
		for x := 0; x < dstWidth; x++ {
			srcX := int(uint64(x) * uint64(s.Width) / uint64(dstWidth))
			if srcX >= int(s.Width) {
				srcX = int(s.Width) - 1
			}
			color := s.getPixelColor(srcX, srcY)
			off := (y*dstWidth + x) * 4
			out[off+0] = byte(color)
			out[off+1] = byte(color >> 8)
			out[off+2] = byte(color >> 16)
			out[off+3] = 0xFF
		}
	}
	return out
}

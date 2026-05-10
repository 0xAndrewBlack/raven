package wl

import "testing"

func TestDrawTextAbsClippedDoesNotTouchPixelsOutsideBounds(t *testing.T) {
	win := NewHeadlessWindow("clip", 32, 20, 0)
	before := append([]byte(nil), win.Pix...)

	win.DrawTextAbsClipped(0, 0, 8, 16, "AB", 0x000000, 0xFFFFFF, true)

	for y := 0; y < 16; y++ {
		for x := 8; x < 16; x++ {
			off := y*int(win.Stride) + x*4
			for channel := 0; channel < 4; channel++ {
				if win.Pix[off+channel] != before[off+channel] {
					t.Fatalf("pixel (%d,%d) changed outside clip", x, y)
				}
			}
		}
	}
}

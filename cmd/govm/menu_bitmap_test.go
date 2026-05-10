//go:build guest_windows

package main

import (
	"testing"

	"github.com/mirkobrombin/Raven/pkg/wl"
)

func TestDrawMenuBitmapPixelsClipsAndPreservesTransparentPixels(t *testing.T) {
	window := wl.NewHeadlessWindow("menu", 4, 4, 0)
	window.DrawRectAbs(0, 0, 4, 4, 0x112233)
	pixels := []uint32{
		0xffff0000, 0x00000000, 0xff00ff00,
		0xff0000ff, 0xffffffff, 0xff000000,
	}
	if !drawMenuBitmapPixels(window, pixels, 3, 3, 2, 1, 1, false, 0) {
		t.Fatal("bitmap was not drawn")
	}
	if got := dialogPixel(window, 1, 1); got != 0xff0000 {
		t.Fatalf("red pixel = %#x", got)
	}
	if got := dialogPixel(window, 2, 1); got != 0x112233 {
		t.Fatalf("transparent pixel changed to %#x", got)
	}
	if got := dialogPixel(window, 3, 1); got != 0x00ff00 {
		t.Fatalf("green pixel = %#x", got)
	}
	if got := dialogPixel(window, 1, 2); got != 0x0000ff {
		t.Fatalf("blue pixel = %#x", got)
	}
	if drawMenuBitmapPixels(window, pixels, 0, 3, 2, 0, 0, false, 0) {
		t.Fatal("accepted invalid source dimensions")
	}
	window.DrawRectAbs(0, 0, 4, 4, 0x112233)
	mono := []uint32{0xffffffff, 0xff000000}
	if !drawMenuBitmapPixels(window, mono, 2, 2, 1, 1, 1, true, 0x445566) {
		t.Fatal("monochrome bitmap was not drawn")
	}
	if got := dialogPixel(window, 1, 1); got != 0x112233 {
		t.Fatalf("monochrome white pixel changed to %#x", got)
	}
	if got := dialogPixel(window, 2, 1); got != 0x445566 {
		t.Fatalf("monochrome black pixel = %#x", got)
	}
}

//go:build guest_windows

package main

import (
	"testing"

	"github.com/mirkobrombin/Raven/pkg/gdi"
)

func TestFillRectUsingBrushHandlePreservesPatternAndSystemColors(t *testing.T) {
	manager := gdi.NewManager()
	target := gdi.NewSurface(4, 2)
	dc := gdi.NewScreenDC(target)
	pattern := gdi.NewSurface(2, 1)
	pattern.SetPixel(0, 0, 0x112233)
	pattern.SetPixel(1, 0, 0x445566)
	bitmap := manager.CreateCompatibleBitmap(2, 1)
	object := manager.GetObject(bitmap)
	object.Bitmap.Surf = pattern
	brush := manager.CreatePatternBrush(bitmap)

	fillRectUsingBrushHandle(dc, manager, brush, [31]uint32{}, 0, 0, 4, 1)
	for x, want := range []uint32{0x112233, 0x445566, 0x112233, 0x445566} {
		if got := target.GetPixel(int32(x), 0); got != want {
			t.Fatalf("pattern pixel %d = %#06x, want %#06x", x, got, want)
		}
	}

	var colors [31]uint32
	colors[4] = 0xAABBCC
	fillRectUsingBrushHandle(dc, manager, 5, colors, 0, 1, 4, 2)
	if got := target.GetPixel(3, 1); got != 0xAABBCC {
		t.Fatalf("system brush pixel = %#06x, want %#06x", got, uint32(0xAABBCC))
	}
}

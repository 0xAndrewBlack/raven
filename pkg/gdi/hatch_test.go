//go:build guest_windows

package gdi

import "testing"

func TestFillRectBrushHatchPreservesTransparentBackground(t *testing.T) {
	surface := NewSurface(16, 16)
	surface.FillRect(0, 0, 16, 16, 0x000000)
	dc := NewScreenDC(surface)
	dc.Mgr = nil
	dc.Brush = &Brush{Style: 2, Hatch: 2, Color: 0xFFFFFF}
	dc.BkMode = 1

	dc.FillRectBrush(0, 0, 16, 16)

	if got := surface.GetPixel(0, 0); got != 0xFFFFFF {
		t.Fatalf("hatch pixel = 0x%06x, want 0xffffff", got)
	}
	if got := surface.GetPixel(1, 1); got != 0x000000 {
		t.Fatalf("transparent background pixel = 0x%06x, want 0x000000", got)
	}
}

func TestFillRectBrushHatchPaintsOpaqueBackground(t *testing.T) {
	surface := NewSurface(16, 16)
	surface.FillRect(0, 0, 16, 16, 0xFF0000)
	dc := NewScreenDC(surface)
	dc.Mgr = nil
	dc.Brush = &Brush{Style: 2, Hatch: 1, Color: 0xFFFFFF}
	dc.BkColor = 0x00FF00
	dc.BkMode = 2

	dc.FillRectBrush(0, 0, 16, 16)

	if got := surface.GetPixel(0, 1); got != 0xFFFFFF {
		t.Fatalf("hatch pixel = 0x%06x, want 0xffffff", got)
	}
	if got := surface.GetPixel(1, 1); got != 0x00FF00 {
		t.Fatalf("opaque background pixel = 0x%06x, want 0x00ff00", got)
	}
}

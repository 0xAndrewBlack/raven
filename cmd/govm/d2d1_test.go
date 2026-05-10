//go:build guest_windows

package main

import (
	"testing"

	"github.com/mirkobrombin/Raven/pkg/gdi"
)

func TestD2D1NewDCOffsetsClipToTargetOrigin(t *testing.T) {
	surface := gdi.NewSurface(200, 120)
	target := &d2d1RenderTarget{
		originX:   17,
		originY:   23,
		clipStack: []d2d1Rect{{left: 4, top: 5, right: 80, bottom: 60}},
	}

	dc := d2d1NewDC(target, surface, 0, 1)
	if dc == nil {
		t.Fatal("d2d1NewDC returned nil")
	}
	if got, want := [4]int32{dc.ClipX0, dc.ClipY0, dc.ClipX1, dc.ClipY1}, [4]int32{21, 28, 97, 83}; got != want {
		t.Fatalf("clip = %v, want %v", got, want)
	}
}

func TestD2D1DerivedBrushMethodCounts(t *testing.T) {
	if d2d1SolidColorBrushMethods != 10 || d2d1BitmapBrushMethods != 16 || d2d1LinearGradientMethods != 13 || d2d1RadialGradientMethods != 17 {
		t.Fatalf("unexpected derived brush vtable sizes: solid=%d bitmap=%d linear=%d radial=%d",
			d2d1SolidColorBrushMethods, d2d1BitmapBrushMethods, d2d1LinearGradientMethods, d2d1RadialGradientMethods)
	}
}

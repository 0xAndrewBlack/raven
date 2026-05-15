//go:build guest_windows

package gdi

import "testing"

func TestFillRectWithBrushTilesPatternWithoutColorFallback(t *testing.T) {
	surface := NewSurface(6, 4)
	dc := NewScreenDC(surface)
	dc.Mgr = nil
	pattern := NewSurface(2, 2)
	pattern.SetPixel(0, 0, 0x112233)
	pattern.SetPixel(1, 0, 0x445566)
	pattern.SetPixel(0, 1, 0x778899)
	pattern.SetPixel(1, 1, 0xAABBCC)
	brush := &Brush{
		Style:   3,
		Color:   0x000000,
		Pattern: &Bitmap{Width: 2, Height: 2, Surf: pattern},
	}

	dc.FillRectWithBrush(0, 0, 6, 4, brush)

	for y := int32(0); y < 4; y++ {
		for x := int32(0); x < 6; x++ {
			want := pattern.GetPixel(x%2, y%2)
			if got := surface.GetPixel(x, y); got != want {
				t.Fatalf("pixel (%d,%d) = 0x%06x, want 0x%06x", x, y, got, want)
			}
		}
	}
}

func TestFillRectWithBrushPatternRespectsClipAndOrigin(t *testing.T) {
	const untouched = 0xDDEEFF

	surface := NewSurface(8, 7)
	surface.FillRect(0, 0, 8, 7, untouched)
	dc := NewScreenDC(surface)
	dc.Mgr = nil
	dc.SetViewportOrg(2, 1)
	dc.SetClipRect(3, 2, 7, 5)
	pattern := NewSurface(3, 2)
	pattern.SetPixel(0, 0, 0x100001)
	pattern.SetPixel(1, 0, 0x100002)
	pattern.SetPixel(2, 0, 0x100003)
	pattern.SetPixel(0, 1, 0x200001)
	pattern.SetPixel(1, 1, 0x200002)
	pattern.SetPixel(2, 1, 0x200003)
	brush := &Brush{Style: 3, Pattern: &Bitmap{Width: 3, Height: 2, Surf: pattern}}

	dc.FillRectWithBrush(0, 0, 6, 5, brush)

	for y := int32(0); y < 7; y++ {
		for x := int32(0); x < 8; x++ {
			want := uint32(untouched)
			if x >= 3 && x < 7 && y >= 2 && y < 5 {
				want = pattern.GetPixel((x-dc.OriginX)%3, (y-dc.OriginY)%2)
			}
			if got := surface.GetPixel(x, y); got != want {
				t.Fatalf("pixel (%d,%d) = 0x%06x, want 0x%06x", x, y, got, want)
			}
		}
	}
}

func TestFillRectBrushUsesSelectedPattern(t *testing.T) {
	surface := NewSurface(3, 1)
	dc := NewScreenDC(surface)
	dc.Mgr = nil
	pattern := NewSurface(2, 1)
	pattern.SetPixel(0, 0, 0x123456)
	pattern.SetPixel(1, 0, 0xABCDEF)
	dc.Brush = &Brush{Style: 3, Pattern: &Bitmap{Width: 2, Height: 1, Surf: pattern}}

	dc.FillRectBrush(0, 0, 3, 1)

	want := []uint32{0x123456, 0xABCDEF, 0x123456}
	for x, color := range want {
		if got := surface.GetPixel(int32(x), 0); got != color {
			t.Fatalf("pixel (%d,0) = 0x%06x, want 0x%06x", x, got, color)
		}
	}
}

func TestFillRectWithBrushSupportsBasicStyles(t *testing.T) {
	t.Run("solid", func(t *testing.T) {
		surface := NewSurface(2, 2)
		dc := NewScreenDC(surface)
		dc.Mgr = nil

		dc.FillRectWithBrush(0, 0, 2, 2, &Brush{Style: 0, Color: 0x123456})

		if got := surface.GetPixel(1, 1); got != 0x123456 {
			t.Fatalf("solid pixel = 0x%06x, want 0x123456", got)
		}
	})

	t.Run("null", func(t *testing.T) {
		surface := NewSurface(2, 2)
		surface.FillRect(0, 0, 2, 2, 0x654321)
		dc := NewScreenDC(surface)
		dc.Mgr = nil

		dc.FillRectWithBrush(0, 0, 2, 2, &Brush{Style: 1, Color: 0x000000})

		if got := surface.GetPixel(1, 1); got != 0x654321 {
			t.Fatalf("null-brush pixel = 0x%06x, want untouched", got)
		}
	})

	t.Run("hatched", func(t *testing.T) {
		surface := NewSurface(2, 2)
		surface.FillRect(0, 0, 2, 2, 0x654321)
		dc := NewScreenDC(surface)
		dc.Mgr = nil
		dc.BkMode = 1

		dc.FillRectWithBrush(0, 0, 2, 2, &Brush{Style: 2, Hatch: 0, Color: 0x123456})

		if got := surface.GetPixel(0, 0); got != 0x123456 {
			t.Fatalf("hatch pixel = 0x%06x, want 0x123456", got)
		}
		if got := surface.GetPixel(0, 1); got != 0x654321 {
			t.Fatalf("hatch background = 0x%06x, want untouched", got)
		}
	})
}

func TestFillRectWithBrushIgnoresInvalidPatterns(t *testing.T) {
	tests := []struct {
		name    string
		pattern *Bitmap
	}{
		{name: "nil bitmap"},
		{name: "nil surface", pattern: &Bitmap{Width: 2, Height: 2}},
		{name: "zero width", pattern: &Bitmap{Surf: NewSurface(0, 2)}},
		{name: "zero height", pattern: &Bitmap{Surf: NewSurface(2, 0)}},
		{name: "zero bitmap width", pattern: &Bitmap{Height: 2, Surf: NewSurface(2, 2)}},
		{name: "zero bitmap height", pattern: &Bitmap{Width: 2, Surf: NewSurface(2, 2)}},
		{
			name: "short stride",
			pattern: &Bitmap{
				Width: 2, Height: 2,
				Surf: &Surface{Width: 2, Height: 2, Stride: 4, Pix: make([]byte, 8)},
			},
		},
		{
			name: "short buffer",
			pattern: &Bitmap{
				Width: 2, Height: 2,
				Surf: &Surface{Width: 2, Height: 2, Stride: 8, Pix: make([]byte, 15)},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			surface := NewSurface(2, 2)
			surface.FillRect(0, 0, 2, 2, 0x654321)
			dc := NewScreenDC(surface)
			dc.Mgr = nil

			dc.FillRectWithBrush(0, 0, 2, 2, &Brush{
				Style:   3,
				Color:   0x000000,
				Pattern: tt.pattern,
			})

			for y := int32(0); y < 2; y++ {
				for x := int32(0); x < 2; x++ {
					if got := surface.GetPixel(x, y); got != 0x654321 {
						t.Fatalf("pixel (%d,%d) = 0x%06x, want untouched", x, y, got)
					}
				}
			}
			if dc.Dirty {
				t.Fatal("invalid pattern marked DC dirty")
			}
		})
	}
}

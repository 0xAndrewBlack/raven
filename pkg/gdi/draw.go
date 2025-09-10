package gdi

// draw.go - GDI drawing primitives
// ReactOS reference: win32ss/gdi/ntgdi/

// FillRect fills a client-space rectangle with the DC's current brush.
// RECT coordinates are exclusive on the right/bottom edge (Win32 convention).
// ReactOS: NtGdiFillRect → BRUSH_EngFillSpans
func (dc *DC) FillRect(left, top, right, bottom int32, color uint32) {
	x0 := left + dc.OriginX
	y0 := top + dc.OriginY
	x1 := right + dc.OriginX
	y1 := bottom + dc.OriginY
	x0, y0, x1, y1, ok := dc.clipRect(x0, y0, x1, y1)
	if !ok {
		return
	}
	dc.target().FillRect(x0, y0, x1, y1, color)
}

// FillRectBrush fills using the DC's current brush color.
func (dc *DC) FillRectBrush(left, top, right, bottom int32) {
	color := uint32(0xF0F0F0)
	if dc.Brush != nil && dc.Brush.Style == 0 {
		color = dc.Brush.Color
	}
	dc.FillRect(left, top, right, bottom, color)
}

// Rectangle draws a filled rectangle with the current brush and a border with the current pen.
// ReactOS: NtGdiRectangle → RECT_lCalcBoundingBox
func (dc *DC) Rectangle(x0, y0, x1, y1 int32) {
	// Fill interior (inside the pen border)
	if dc.Brush != nil && dc.Brush.Style != 1 { // not NULL brush
		dc.FillRectBrush(x0+1, y0+1, x1-1, y1-1)
	}
	// Draw border with pen
	if dc.Pen != nil && dc.Pen.Style != 5 { // not NULL pen
		dc.DrawBorder(x0, y0, x1, y1, dc.Pen.Color)
	}
}

// DrawBorder draws a 1-pixel border around the given rect.
func (dc *DC) DrawBorder(x0, y0, x1, y1 int32, color uint32) {
	s := dc.target()
	ox, oy := dc.OriginX, dc.OriginY
	clip := func(ax0, ay0, ax1, ay1 int32) {
		ax0, ay0, ax1, ay1, ok := dc.clipRect(ax0, ay0, ax1, ay1)
		if ok {
			s.FillRect(ax0, ay0, ax1, ay1, color)
		}
	}
	clip(x0+ox, y0+oy, x1+ox, y0+oy+1)   // top
	clip(x0+ox, y1+oy-1, x1+ox, y1+oy)   // bottom
	clip(x0+ox, y0+oy, x0+ox+1, y1+oy)   // left
	clip(x1+ox-1, y0+oy, x1+ox, y1+oy)   // right
}

// MoveTo sets the current drawing position.
// ReactOS: NtGdiMoveToEx
func (dc *DC) MoveTo(x, y int32) (oldX, oldY int32) {
	oldX, oldY = dc.CurX, dc.CurY
	dc.CurX, dc.CurY = x, y
	return
}

// LineTo draws a line from the current position to (x,y), updating CurX/Y.
// ReactOS: NtGdiLineTo → EngLineTo → IntEngLineTo
func (dc *DC) LineTo(x, y int32) {
	if dc.Pen == nil || dc.Pen.Style == 5 { // NULL pen
		dc.CurX, dc.CurY = x, y
		return
	}
	color := dc.Pen.Color
	x0 := dc.CurX + dc.OriginX
	y0 := dc.CurY + dc.OriginY
	x1 := x + dc.OriginX
	y1 := y + dc.OriginY
	// Note: LineTo does not draw the endpoint (Win32 convention)
	dc.target().DrawLine(x0, y0, x1-1, y1, color)
	dc.CurX, dc.CurY = x, y
}

// Polyline draws a series of connected line segments.
// ReactOS: NtGdiPolyPolyline
func (dc *DC) Polyline(pts [][2]int32) {
	if len(pts) < 2 {
		return
	}
	for i := 1; i < len(pts); i++ {
		dc.MoveTo(pts[i-1][0], pts[i-1][1])
		dc.LineTo(pts[i][0], pts[i][1])
	}
}

// Ellipse draws a filled ellipse with the current brush and pen.
// ReactOS: NtGdiEllipse → EngPlgBlt
// Simple midpoint-circle algorithm.
func (dc *DC) Ellipse(x0, y0, x1, y1 int32) {
	cx := (x0 + x1) / 2
	cy := (y0 + y1) / 2
	a := (x1 - x0) / 2
	b := (y1 - y0) / 2
	if a <= 0 || b <= 0 {
		return
	}
	s := dc.target()
	brushColor := uint32(0)
	hasBrush := dc.Brush != nil && dc.Brush.Style == 0
	if hasBrush {
		brushColor = dc.Brush.Color
	}
	penColor := uint32(0)
	hasPen := dc.Pen != nil && dc.Pen.Style != 5
	if hasPen {
		penColor = dc.Pen.Color
	}
	ox, oy := dc.OriginX, dc.OriginY
	for dy := int32(0); dy <= b; dy++ {
		dx := a * dy / b // approximate - proper: a*sqrt(1-(dy/b)^2)
		// Midpoint horizontal span
		for x := cx - dx; x <= cx+dx; x++ {
			for _, yy := range []int32{cy - dy, cy + dy} {
				ax := x + ox
				ay := yy + oy
				if ax < 0 || ax >= s.Width || ay < 0 || ay >= s.Height {
					continue
				}
				if hasBrush && dy < b {
					ax2, ay2, ax3, ay3, ok := dc.clipRect(ax, ay, ax+1, ay+1)
					if ok {
						s.FillRect(ax2, ay2, ax3, ay3, brushColor)
					}
				}
			}
		}
		// Draw border at edge
		if hasPen {
			for _, sign := range []int32{-1, 1} {
				ax := cx + sign*(a*dy/b) + ox
				ay := cy + dy + oy
				if ax >= 0 && ax < s.Width && ay >= 0 && ay < s.Height {
					s.SetPixel(ax, ay, penColor)
				}
				ay = cy - dy + oy
				if ax >= 0 && ax < s.Width && ay >= 0 && ay < s.Height {
					s.SetPixel(ax, ay, penColor)
				}
			}
		}
	}
}

// BitBlt copies pixels from srcDC to this DC.
// ReactOS: NtGdiBitBlt → EngBitBlt
//
// rop3 values: SRCCOPY=0xCC0020, PATCOPY=0xF00021, BLACKNESS=0x420000, WHITENESS=0xFF0062
func (dc *DC) BitBlt(dx, dy, w, h int32, src *DC, sx, sy int32, rop3 uint32) {
	if src == nil || src.Target == nil {
		return
	}
	if dc.Target == nil {
		return
	}
	// Map destination to absolute coords
	adx := dx + dc.OriginX
	ady := dy + dc.OriginY
	// Map source to absolute coords then back to surface-local
	asx := sx + src.OriginX
	asy := sy + src.OriginY
	switch rop3 & 0xFF0000 {
	case 0xCC0000: // SRCCOPY
		dc.Target.BitBlt(adx, ady, src.Target, asx, asy, w, h)
	case 0x000000: // BLACKNESS
		dc.Target.FillRect(adx, ady, adx+w, ady+h, 0x000000)
	case 0xFF0000: // WHITENESS
		dc.Target.FillRect(adx, ady, adx+w, ady+h, 0xFFFFFF)
	case 0xF00000: // PATCOPY
		color := uint32(0xF0F0F0)
		if dc.Brush != nil && dc.Brush.Style == 0 {
			color = dc.Brush.Color
		}
		dc.Target.FillRect(adx, ady, adx+w, ady+h, color)
	default:
		// Unrecognised ROP - fall back to SRCCOPY
		dc.Target.BitBlt(adx, ady, src.Target, asx, asy, w, h)
	}
}

// StretchBlt copies and scales src to dst with nearest-neighbour interpolation.
// ReactOS: NtGdiStretchBlt → EngStretchBlt
func (dc *DC) StretchBlt(dx, dy, dw, dh int32, src *DC, sx, sy, sw, sh int32, rop3 uint32) {
	if src == nil || src.Target == nil || dc.Target == nil {
		return
	}
	adx := dx + dc.OriginX
	ady := dy + dc.OriginY
	asx := sx + src.OriginX
	asy := sy + src.OriginY
	dc.Target.StretchBlt(adx, ady, dw, dh, src.Target, asx, asy, sw, sh)
}

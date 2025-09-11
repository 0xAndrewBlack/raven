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
	// Map destination to absolute surface coords using DC origin.
	adx := dx + dc.OriginX
	ady := dy + dc.OriginY
	// Map source to source-surface-local coords.
	asx := sx + src.OriginX
	asy := sy + src.OriginY
	// Apply DC clip rect to destination region.
	if dc.ClipX1 > dc.ClipX0 {
		if adx < dc.ClipX0 {
			asx += dc.ClipX0 - adx
			w -= dc.ClipX0 - adx
			adx = dc.ClipX0
		}
		if ady < dc.ClipY0 {
			asy += dc.ClipY0 - ady
			h -= dc.ClipY0 - ady
			ady = dc.ClipY0
		}
		if adx+w > dc.ClipX1 {
			w = dc.ClipX1 - adx
		}
		if ady+h > dc.ClipY1 {
			h = dc.ClipY1 - ady
		}
	}
	if w <= 0 || h <= 0 {
		return
	}
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

// SetPixel sets a single pixel. ReactOS: NtGdiSetPixel
func (dc *DC) SetPixel(x, y int32, color uint32) {
	px := x + dc.OriginX
	py := y + dc.OriginY
	if px < 0 || py < 0 || px >= dc.target().Width || py >= dc.target().Height {
		return
	}
	dc.target().SetPixel(px, py, color)
}

// GetPixel returns the color of a single pixel. ReactOS: NtGdiGetPixel
func (dc *DC) GetPixel(x, y int32) uint32 {
	px := x + dc.OriginX
	py := y + dc.OriginY
	s := dc.target()
	if px < 0 || py < 0 || px >= s.Width || py >= s.Height {
		return 0xFFFFFFFF // CLR_INVALID
	}
	return s.GetPixel(px, py)
}

// RoundRect draws a rounded rectangle. ReactOS: NtGdiRoundRect
func (dc *DC) RoundRect(x0, y0, x1, y1, xr, yr int32) {
	// Simplified: draw as regular rectangle
	dc.Rectangle(x0, y0, x1, y1)
}

// Polygon draws a filled polygon. ReactOS: NtGdiPolygon
func (dc *DC) Polygon(pts [][2]int32) {
	if len(pts) < 2 {
		return
	}
	// Fill with brush using scanline algorithm (simplified bounding box fill)
	if dc.Brush != nil && dc.Brush.Style != 1 {
		minX, maxX := pts[0][0], pts[0][0]
		minY, maxY := pts[0][1], pts[0][1]
		for _, p := range pts[1:] {
			if p[0] < minX { minX = p[0] }
			if p[0] > maxX { maxX = p[0] }
			if p[1] < minY { minY = p[1] }
			if p[1] > maxY { maxY = p[1] }
		}
		dc.FillRectBrush(minX, minY, maxX+1, maxY+1)
	}
	// Draw border
	for i := range pts {
		next := (i + 1) % len(pts)
		dc.MoveTo(pts[i][0], pts[i][1])
		dc.LineTo(pts[next][0], pts[next][1])
	}
}

// Polyline draws connected lines (no fill). ReactOS: NtGdiPolyPolyline
func (dc *DC) PolylinePoints(pts [][2]int32) {
	for i := 1; i < len(pts); i++ {
		dc.MoveTo(pts[i-1][0], pts[i-1][1])
		dc.LineTo(pts[i][0], pts[i][1])
	}
}

// InvertRect inverts the colors in a rectangle. ReactOS: NtGdiInvertRgn
func (dc *DC) InvertRect(left, top, right, bottom int32) {
	x0 := left + dc.OriginX
	y0 := top + dc.OriginY
	x1 := right + dc.OriginX
	y1 := bottom + dc.OriginY
	x0, y0, x1, y1, ok := dc.clipRect(x0, y0, x1, y1)
	if !ok { return }
	s := dc.target()
	for py := y0; py < y1; py++ {
		for px := x0; px < x1; px++ {
			if px < 0 || py < 0 || px >= s.Width || py >= s.Height { continue }
			off := int(py)*int(s.Stride) + int(px)*4
			s.Pix[off+0] ^= 0xFF
			s.Pix[off+1] ^= 0xFF
			s.Pix[off+2] ^= 0xFF
		}
	}
}

// DrawFocusRect draws a dotted focus rectangle (XOR mode). ReactOS: NtGdiDrawFocusRect
func (dc *DC) DrawFocusRect(left, top, right, bottom int32) {
	x0 := left + dc.OriginX
	y0 := top + dc.OriginY
	x1 := right + dc.OriginX
	y1 := bottom + dc.OriginY
	s := dc.target()
	dotColor := uint32(0x000000)
	drawDot := func(px, py int32) {
		if px < 0 || py < 0 || px >= s.Width || py >= s.Height { return }
		off := int(py)*int(s.Stride) + int(px)*4
		// XOR with existing pixel
		existing := uint32(s.Pix[off+2])<<16 | uint32(s.Pix[off+1])<<8 | uint32(s.Pix[off+0])
		c := existing ^ dotColor ^ 0xFFFFFF
		s.Pix[off+0] = byte(c)
		s.Pix[off+1] = byte(c >> 8)
		s.Pix[off+2] = byte(c >> 16)
		s.Pix[off+3] = 0xFF
	}
	for px := x0; px < x1; px++ {
		if (px - x0) % 2 == 0 {
			drawDot(px, y0)
			drawDot(px, y1-1)
		}
	}
	for py := y0; py < y1; py++ {
		if (py - y0) % 2 == 0 {
			drawDot(x0, py)
			drawDot(x1-1, py)
		}
	}
}

// DrawEdge draws a 3D edge rectangle.
// ReactOS: UserDrawEdge in win32ss/user/user32/windows/draw.c
// edge: combination of BDR_RAISEDOUTER=1, BDR_SUNKENOUTER=2, BDR_RAISEDINNER=4, BDR_SUNKENINNER=8
//       shortcuts: EDGE_RAISED=5, EDGE_SUNKEN=10, EDGE_ETCHED=6, EDGE_BUMP=9
// grfFlags: BF_LEFT=1, BF_TOP=2, BF_RIGHT=4, BF_BOTTOM=8, BF_RECT=15, BF_MIDDLE=0x800, BF_SOFT=0x1000
//
// System colors used (Win32 COLOR_* indices):
//   COLOR_3DDKSHADOW=21, COLOR_3DSHADOW=16, COLOR_3DFACE=15, COLOR_3DHILIGHT=20, COLOR_3DLIGHT=22
func (dc *DC) DrawEdge(left, top, right, bottom int32, edge, grfFlags uint32, sysColors [31]uint32) {
	// Color mappings from Win32 system palette
	hiLight := uint32(0xFFFFFF)
	shadow := uint32(0x808080)
	dkShadow := uint32(0x404040)
	face := uint32(0xD4D0C8)
	if len(sysColors) > 22 {
		hiLight = sysColors[20]  // COLOR_3DHILIGHT
		shadow = sysColors[16]   // COLOR_3DSHADOW
		dkShadow = sysColors[21] // COLOR_3DDKSHADOW
		face = sysColors[15]     // COLOR_3DFACE
	}
	_ = dkShadow

	// Determine outer/inner edge colors based on edge type
	var outerTopLeft, outerBotRight uint32
	var innerTopLeft, innerBotRight uint32

	const (
		BDR_RAISEDOUTER = 0x0001
		BDR_SUNKENOUTER = 0x0002
		BDR_RAISEDINNER = 0x0004
		BDR_SUNKENINNER = 0x0008
	)
	const (
		BF_LEFT   = 0x0001
		BF_TOP    = 0x0002
		BF_RIGHT  = 0x0004
		BF_BOTTOM = 0x0008
		BF_MIDDLE = 0x0800
		BF_SOFT   = 0x1000
		BF_FLAT   = 0x4000
	)

	if edge & BDR_RAISEDOUTER != 0 {
		outerTopLeft = hiLight
		outerBotRight = dkShadow
	} else if edge & BDR_SUNKENOUTER != 0 {
		outerTopLeft = dkShadow
		outerBotRight = hiLight
	}

	if edge & BDR_RAISEDINNER != 0 {
		innerTopLeft = hiLight
		innerBotRight = shadow
	} else if edge & BDR_SUNKENINNER != 0 {
		innerTopLeft = shadow
		innerBotRight = hiLight
	}

	hasOuter := (edge & (BDR_RAISEDOUTER | BDR_SUNKENOUTER)) != 0
	hasInner := (edge & (BDR_RAISEDINNER | BDR_SUNKENINNER)) != 0

	drawLine := func(x0, y0, x1, y1 int32, color uint32) {
		if grfFlags & BF_FLAT != 0 { color = shadow }
		ax0 := x0 + dc.OriginX
		ay0 := y0 + dc.OriginY
		ax1 := x1 + dc.OriginX
		ay1 := y1 + dc.OriginY
		ax0, ay0, ax1, ay1, ok := dc.clipRect(ax0, ay0, ax1, ay1)
		if ok { dc.target().FillRect(ax0, ay0, ax1, ay1, color) }
	}

	if hasOuter {
		// Outer edge (1px)
		if grfFlags & BF_TOP    != 0 { drawLine(left, top, right, top+1, outerTopLeft) }
		if grfFlags & BF_LEFT   != 0 { drawLine(left, top, left+1, bottom, outerTopLeft) }
		if grfFlags & BF_RIGHT  != 0 { drawLine(right-1, top, right, bottom, outerBotRight) }
		if grfFlags & BF_BOTTOM != 0 { drawLine(left, bottom-1, right, bottom, outerBotRight) }
		left++; top++; right--; bottom--
	}

	if hasInner {
		// Inner edge (1px)
		if grfFlags & BF_TOP    != 0 { drawLine(left, top, right, top+1, innerTopLeft) }
		if grfFlags & BF_LEFT   != 0 { drawLine(left, top, left+1, bottom, innerTopLeft) }
		if grfFlags & BF_RIGHT  != 0 { drawLine(right-1, top, right, bottom, innerBotRight) }
		if grfFlags & BF_BOTTOM != 0 { drawLine(left, bottom-1, right, bottom, innerBotRight) }
		left++; top++; right--; bottom--
	}

	if grfFlags & BF_MIDDLE != 0 && left < right && top < bottom {
		dc.FillRect(left, top, right, bottom, face)
	}
}

// DrawFrameControl draws a frame control (checkbox, radio, button, arrow, etc.)
// ReactOS: UserDrawFrameControl in win32ss/user/user32/windows/draw.c
// uType: DFC_CAPTION=1, DFC_MENU=2, DFC_SCROLL=3, DFC_BUTTON=4
// uState: DFCS_CAPTIONCLOSE=0, DFCS_CAPTIONMIN=1, DFCS_CAPTIONMAX=2, DFCS_CAPTIONRESTORE=3
//         DFCS_BUTTONCHECK=0, DFCS_BUTTONRADIOIMAGE=1, DFCS_BUTTONRADIOMASK=2, DFCS_BUTTONRADIO=4
//         DFCS_BUTTON3STATE=8, DFCS_BUTTONPUSH=16
//         DFCS_INACTIVE=0x100, DFCS_PUSHED=0x200, DFCS_CHECKED=0x400, DFCS_FLAT=0x4000
func (dc *DC) DrawFrameControl(left, top, right, bottom int32, uType, uState uint32, sysColors [31]uint32) {
	face := uint32(0xD4D0C8)
	hiLight := uint32(0xFFFFFF)
	shadow := uint32(0x808080)
	dkShadow := uint32(0x404040)
	if len(sysColors) > 21 {
		face = sysColors[15]
		hiLight = sysColors[20]
		shadow = sysColors[16]
		dkShadow = sysColors[21]
	}
	_ = dkShadow

	const (
		DFC_CAPTION = 1
		DFC_MENU    = 2
		DFC_SCROLL  = 3
		DFC_BUTTON  = 4
	)
	const (
		DFCS_BUTTONPUSH = 0x0010
		DFCS_BUTTONCHECK = 0x0000
		DFCS_BUTTONRADIO = 0x0004
		DFCS_PUSHED     = 0x0200
		DFCS_CHECKED    = 0x0400
		DFCS_FLAT       = 0x4000
	)

	w := right - left
	h := bottom - top
	cx := left + w/2
	cy := top + h/2

	switch uType {
	case DFC_BUTTON:
		if uState & DFCS_BUTTONPUSH != 0 {
			// Push button
			if uState & DFCS_PUSHED != 0 {
				dc.DrawEdge(left, top, right, bottom, 0x000A, 0x000F, sysColors) // EDGE_SUNKEN|BF_RECT
			} else {
				dc.DrawEdge(left, top, right, bottom, 0x0005, 0x000F, sysColors) // EDGE_RAISED|BF_RECT
			}
		} else if uState & DFCS_BUTTONRADIO != 0 {
			// Radio button: draw circle approximation
			dc.FillRect(left+1, top+1, right-1, bottom-1, face)
			dc.DrawBorder(left, top, right, bottom, shadow)
			if uState & DFCS_CHECKED != 0 {
				dc.FillRect(cx-2, cy-2, cx+2, cy+2, 0x000000)
			}
		} else {
			// Checkbox
			dc.FillRect(left, top, right, bottom, 0xFFFFFF)
			dc.DrawBorder(left, top, right, bottom, shadow)
			if uState & DFCS_CHECKED != 0 {
				// Draw checkmark
				for i := int32(0); i < h-4; i++ {
					dc.FillRect(left+2+i/2, top+2+i, left+3+i/2, top+3+i, 0x000000)
					dc.FillRect(right-3-i/2, top+2+i, right-2-i/2, top+3+i, 0x000000)
				}
			}
		}

	case DFC_CAPTION:
		// Caption buttons (close/min/max) - draw simple button appearance
		if uState & DFCS_PUSHED != 0 {
			dc.DrawEdge(left, top, right, bottom, 0x000A, 0x000F, sysColors)
		} else {
			dc.DrawEdge(left, top, right, bottom, 0x0005, 0x000F, sysColors)
		}
		dc.FillRect(left+2, top+2, right-2, bottom-2, face)
		// Draw X for close, - for min, box for max based on state
		switch uState & 0x0F {
		case 0: // DFCS_CAPTIONCLOSE - X
			for i := int32(2); i < w-2; i++ {
				dc.FillRect(left+i, top+i, left+i+1, top+i+1, 0x000000)
				dc.FillRect(right-i-1, top+i, right-i, top+i+1, 0x000000)
			}
		case 1: // DFCS_CAPTIONMIN - underscore
			dc.FillRect(cx-w/4, bottom-3, cx+w/4, bottom-2, 0x000000)
		case 2: // DFCS_CAPTIONMAX - box
			dc.DrawBorder(left+2, top+2, right-2, bottom-2, 0x000000)
		case 3: // DFCS_CAPTIONRESTORE - two overlapping boxes
			dc.DrawBorder(left+3, top+2, right-2, bottom-3, 0x000000)
			dc.DrawBorder(left+2, top+3, right-3, bottom-2, 0x000000)
		}

	case DFC_SCROLL:
		// Scrollbar arrows
		dc.FillRect(left, top, right, bottom, face)
		if uState & DFCS_PUSHED != 0 {
			dc.DrawBorder(left, top, right, bottom, dkShadow)
		} else {
			dc.DrawEdge(left, top, right, bottom, 0x0005, 0x000F, sysColors)
		}
		// Draw arrow
		_ = cx; _ = cy
		_ = hiLight

	case DFC_MENU:
		dc.FillRect(left, top, right, bottom, face)
	}
}

// GradientFill fills a rect with a gradient (simplified: use top color for whole rect).
// ReactOS: NtGdiGradientFill
func (dc *DC) GradientFill(left, top, right, bottom int32, colorTop, colorBottom uint32, horiz bool) {
	if !horiz {
		// Vertical gradient (top to bottom)
		h := int(bottom - top)
		if h <= 0 { return }
		for y := top; y < bottom; y++ {
			t := int(y - top)
			rr := (int(colorTop>>16)*(h-t) + int(colorBottom>>16)*t) / h
			gg := (int((colorTop>>8)&0xFF)*(h-t) + int((colorBottom>>8)&0xFF)*t) / h
			bb := (int(colorTop&0xFF)*(h-t) + int(colorBottom&0xFF)*t) / h
			c := uint32(rr<<16 | gg<<8 | bb)
			dc.FillRect(left, y, right, y+1, c)
		}
	} else {
		// Horizontal gradient (left to right)
		w := int(right - left)
		if w <= 0 { return }
		for x := left; x < right; x++ {
			t := int(x - left)
			rr := (int(colorTop>>16)*(w-t) + int(colorBottom>>16)*t) / w
			gg := (int((colorTop>>8)&0xFF)*(w-t) + int((colorBottom>>8)&0xFF)*t) / w
			bb := (int(colorTop&0xFF)*(w-t) + int(colorBottom&0xFF)*t) / w
			c := uint32(rr<<16 | gg<<8 | bb)
			dc.FillRect(x, top, x+1, bottom, c)
		}
	}
}

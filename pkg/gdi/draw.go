package gdi

import "math"

const (
	ropBlackness  = 0x00000042
	ropNotSrcCopy = 0x00330008
	ropSrcErase   = 0x00440328
	ropSrcInvert  = 0x00660046
	ropSrcAnd     = 0x008800C6
	ropPatInvert  = 0x005A0049
	ropSrcPaint   = 0x00EE0086
	ropPatCopy    = 0x00F00021
	ropSrcCopy    = 0x00CC0020
	ropWhiteness  = 0x00FF0062
)

// draw.go - GDI drawing primitives
// ReactOS reference: win32ss/gdi/ntgdi/

// FillRect fills a client-space rectangle with the DC's current brush.
// RECT coordinates are exclusive on the right/bottom edge (Win32 convention).
// ReactOS: NtGdiFillRect → BRUSH_EngFillSpans
func (dc *DC) FillRect(left, top, right, bottom int32, color uint32) {
	dc.Dirty = true
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
	if color, ok := dc.brushColor(); ok {
		dc.FillRect(left, top, right, bottom, color)
	}
}

// Rectangle draws a filled rectangle with the current brush and a border with the current pen.
// ReactOS: NtGdiRectangle → RECT_lCalcBoundingBox
func (dc *DC) Rectangle(x0, y0, x1, y1 int32) {
	if dc.IsRecording() {
		dc.PathAddRect(x0, y0, x1, y1)
		dc.CurX, dc.CurY = x0, y0
		return
	}
	// Fill interior (inside the pen border)
	penInset := dc.penWidth()
	if penInset < 1 {
		penInset = 1
	}
	if _, ok := dc.brushColor(); ok {
		dc.FillRectBrush(x0+penInset, y0+penInset, x1-penInset, y1-penInset)
	}
	// Draw border with pen
	if color, ok := dc.penColor(); ok {
		dc.DrawBorder(x0, y0, x1, y1, color)
	}
}

// DrawBorder draws a 1-pixel border around the given rect.
func (dc *DC) DrawBorder(x0, y0, x1, y1 int32, color uint32) {
	dc.Dirty = true
	s := dc.target()
	ox, oy := dc.OriginX, dc.OriginY
	width := dc.penWidth()
	if width < 1 {
		width = 1
	}
	clip := func(ax0, ay0, ax1, ay1 int32) {
		ax0, ay0, ax1, ay1, ok := dc.clipRect(ax0, ay0, ax1, ay1)
		if ok {
			s.FillRect(ax0, ay0, ax1, ay1, color)
		}
	}
	clip(x0+ox, y0+oy, x1+ox, y0+oy+width) // top
	clip(x0+ox, y1+oy-width, x1+ox, y1+oy) // bottom
	clip(x0+ox, y0+oy, x0+ox+width, y1+oy) // left
	clip(x1+ox-width, y0+oy, x1+ox, y1+oy) // right
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
	if dc.IsRecording() {
		dc.PathLineTo(x, y)
		dc.CurX, dc.CurY = x, y
		return
	}
	color, ok := dc.penColor()
	if !ok {
		dc.CurX, dc.CurY = x, y
		return
	}
	dc.Dirty = true
	x0 := dc.CurX + dc.OriginX
	y0 := dc.CurY + dc.OriginY
	x1 := x + dc.OriginX
	y1 := y + dc.OriginY
	// Note: LineTo does not draw the endpoint (Win32 convention)
	dc.drawLineWidth(x0, y0, x1-1, y1, color, dc.penWidth())
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
	if dc.IsRecording() {
		dc.PathAddEllipse(x0, y0, x1, y1)
		return
	}
	cx := (x0 + x1) / 2
	cy := (y0 + y1) / 2
	dc.Dirty = true
	a := (x1 - x0) / 2
	b := (y1 - y0) / 2
	if a <= 0 || b <= 0 {
		return
	}
	if brushColor, ok := dc.brushColor(); ok {
		for y := cy - b; y <= cy+b; y++ {
			dy := float64(y-cy) / float64(b)
			if dy < -1 || dy > 1 {
				continue
			}
			dx := int32(math.Round(float64(a) * math.Sqrt(1-dy*dy)))
			dc.FillRect(x0+((cx-dx)-x0), y, x0+((cx+dx)-x0)+1, y+1, brushColor)
		}
	}
	if penColor, ok := dc.penColor(); ok {
		pts := dc.ellipseOutlinePoints(x0, y0, x1, y1, 72)
		dc.strokePolylineAbs(pts, true, penColor, dc.penWidth())
	}
}

// BitBlt copies pixels from srcDC to this DC.
// ReactOS: NtGdiBitBlt → EngBitBlt
//
// rop3 values: SRCCOPY=0xCC0020, PATCOPY=0xF00021, BLACKNESS=0x420000, WHITENESS=0xFF0062
func (dc *DC) BitBlt(dx, dy, w, h int32, src *DC, sx, sy int32, rop3 uint32) {
	dstSurf := dc.target()
	if dstSurf.Pix == nil {
		return
	}
	dc.Dirty = true
	// Map destination to absolute surface coords using DC origin.
	adx := dx + dc.OriginX
	ady := dy + dc.OriginY
	asx := sx
	asy := sy
	if src != nil {
		asx += src.OriginX
		asy += src.OriginY
	}
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
	if !ropNeedsSource(rop3) {
		dc.applySolidROP(adx, ady, w, h, rop3)
		return
	}
	if src == nil {
		return
	}
	srcSurf := src.target()
	if srcSurf.Pix == nil {
		return
	}
	if rop3 == ropSrcCopy {
		dstSurf.BitBlt(adx, ady, srcSurf, asx, asy, w, h)
		return
	}
	dc.blitROP(adx, ady, w, h, srcSurf, asx, asy, w, h, rop3)
}

// StretchBlt copies and scales src to dst with nearest-neighbour interpolation.
// ReactOS: NtGdiStretchBlt → EngStretchBlt
func (dc *DC) StretchBlt(dx, dy, dw, dh int32, src *DC, sx, sy, sw, sh int32, rop3 uint32) {
	dstSurf := dc.target()
	if dstSurf.Pix == nil {
		return
	}
	dc.Dirty = true
	adx := dx + dc.OriginX
	ady := dy + dc.OriginY
	asx := sx
	asy := sy
	if src != nil {
		asx += src.OriginX
		asy += src.OriginY
	}
	if !ropNeedsSource(rop3) {
		dc.applySolidROP(adx, ady, dw, dh, rop3)
		return
	}
	if src == nil {
		return
	}
	srcSurf := src.target()
	if srcSurf.Pix == nil {
		return
	}
	if rop3 == ropSrcCopy {
		dstSurf.StretchBlt(adx, ady, dw, dh, srcSurf, asx, asy, sw, sh)
		return
	}
	dc.blitROP(adx, ady, dw, dh, srcSurf, asx, asy, sw, sh, rop3)
}

func ropNeedsSource(rop3 uint32) bool {
	switch rop3 {
	case ropBlackness, ropWhiteness, ropPatCopy, ropPatInvert:
		return false
	default:
		return true
	}
}

func (dc *DC) applySolidROP(dx, dy, w, h int32, rop3 uint32) {
	s := dc.target()
	switch rop3 {
	case ropBlackness:
		s.FillRect(dx, dy, dx+w, dy+h, 0x000000)
	case ropWhiteness:
		s.FillRect(dx, dy, dx+w, dy+h, 0xFFFFFF)
	case ropPatInvert:
		dc.fillPatternROP(dx, dy, w, h, true)
	default:
		dc.fillPatternROP(dx, dy, w, h, false)
	}
}

func (dc *DC) fillPatternROP(dx, dy, w, h int32, invert bool) {
	s := dc.target()
	if s.Pix == nil || w <= 0 || h <= 0 {
		return
	}
	if dc.Brush != nil && dc.Brush.Style == 3 && dc.Brush.Pattern != nil && dc.Brush.Pattern.Surf != nil {
		ps := dc.Brush.Pattern.Surf
		for row := int32(0); row < h; row++ {
			dstY := dy + row
			if dstY < 0 || dstY >= s.Height {
				continue
			}
			for col := int32(0); col < w; col++ {
				dstX := dx + col
				if dstX < 0 || dstX >= s.Width {
					continue
				}
				c := ps.GetPixel(col%ps.Width, row%ps.Height)
				if invert {
					c = c ^ s.GetPixel(dstX, dstY)
				}
				s.SetPixel(dstX, dstY, c)
			}
		}
		return
	}
	color := uint32(0xF0F0F0)
	if dc.Brush != nil && dc.Brush.Style == 0 {
		color = dc.Brush.Color
	}
	if invert {
		for row := int32(0); row < h; row++ {
			dstY := dy + row
			if dstY < 0 || dstY >= s.Height {
				continue
			}
			for col := int32(0); col < w; col++ {
				dstX := dx + col
				if dstX < 0 || dstX >= s.Width {
					continue
				}
				s.SetPixel(dstX, dstY, s.GetPixel(dstX, dstY)^color)
			}
		}
		return
	}
	s.FillRect(dx, dy, dx+w, dy+h, color)
}

func (dc *DC) blitROP(dx, dy, dw, dh int32, src *Surface, sx, sy, sw, sh int32, rop3 uint32) {
	s := dc.target()
	if s.Pix == nil || src == nil || dw <= 0 || dh <= 0 || sw <= 0 || sh <= 0 {
		return
	}
	for row := int32(0); row < dh; row++ {
		srcY := sy + row*sh/dh
		dstY := dy + row
		if srcY < 0 || srcY >= src.Height || dstY < 0 || dstY >= s.Height {
			continue
		}
		for col := int32(0); col < dw; col++ {
			srcX := sx + col*sw/dw
			dstX := dx + col
			if srcX < 0 || srcX >= src.Width || dstX < 0 || dstX >= s.Width {
				continue
			}
			srcColor := src.GetPixel(srcX, srcY)
			dstColor := s.GetPixel(dstX, dstY)
			out := applyROPColor(rop3, srcColor, dstColor)
			s.SetPixel(dstX, dstY, out)
		}
	}
}

func applyROPColor(rop3, srcColor, dstColor uint32) uint32 {
	switch rop3 {
	case ropSrcCopy:
		return srcColor
	case ropSrcPaint:
		return srcColor | dstColor
	case ropSrcAnd:
		return srcColor & dstColor
	case ropSrcInvert:
		return srcColor ^ dstColor
	case ropNotSrcCopy:
		return (^srcColor) & 0x00FFFFFF
	case ropSrcErase:
		return srcColor & (^dstColor & 0x00FFFFFF)
	default:
		return srcColor
	}
}

// SetPixel sets a single pixel. ReactOS: NtGdiSetPixel
func (dc *DC) SetPixel(x, y int32, color uint32) {
	px := x + dc.OriginX
	py := y + dc.OriginY
	if _, _, _, _, ok := dc.clipRect(px, py, px+1, py+1); !ok {
		return
	}
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
	if xr <= 0 || yr <= 0 {
		dc.Rectangle(x0, y0, x1, y1)
		return
	}
	rx := xr / 2
	ry := yr / 2
	if rx <= 0 || ry <= 0 {
		dc.Rectangle(x0, y0, x1, y1)
		return
	}
	if dc.IsRecording() {
		dc.PathAddRect(x0, y0, x1, y1)
		return
	}
	if color, ok := dc.brushColor(); ok {
		dc.FillRect(x0+rx, y0, x1-rx, y1, color)
		dc.FillRect(x0, y0+ry, x1, y1-ry, color)
		for y := int32(0); y < ry; y++ {
			dy := float64(y-ry) / float64(ry)
			dx := int32(math.Round(float64(rx) * math.Sqrt(math.Max(0, 1-dy*dy))))
			dc.FillRect(x0+rx-dx, y0+y, x1-rx+dx, y0+y+1, color)
			dc.FillRect(x0+rx-dx, y1-1-y, x1-rx+dx, y1-y, color)
		}
	}
	if penColor, ok := dc.penColor(); ok {
		pts := dc.roundRectOutlinePoints(x0, y0, x1, y1, rx, ry, 8)
		dc.strokePolylineAbs(pts, true, penColor, dc.penWidth())
	}
}

// Polygon draws a filled polygon. ReactOS: NtGdiPolygon
func (dc *DC) Polygon(pts [][2]int32) {
	if len(pts) < 2 {
		return
	}
	if dc.IsRecording() {
		dc.PathMoveTo(pts[0][0], pts[0][1])
		for i := 1; i < len(pts); i++ {
			dc.PathLineTo(pts[i][0], pts[i][1])
		}
		dc.CloseFigure()
		return
	}
	if color, ok := dc.brushColor(); ok {
		dc.fillPolygon(pts, color)
	}
	if color, ok := dc.penColor(); ok {
		dc.strokePolylineLogical(pts, true, color, dc.penWidth())
	}
}

// Polyline draws connected lines (no fill). ReactOS: NtGdiPolyPolyline
func (dc *DC) PolylinePoints(pts [][2]int32) {
	if dc.IsRecording() {
		if len(pts) == 0 {
			return
		}
		dc.PathMoveTo(pts[0][0], pts[0][1])
		for i := 1; i < len(pts); i++ {
			dc.PathLineTo(pts[i][0], pts[i][1])
		}
		if last := pts[len(pts)-1]; true {
			dc.CurX, dc.CurY = last[0], last[1]
		}
		return
	}
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
	if !ok {
		return
	}
	s := dc.target()
	for py := y0; py < y1; py++ {
		for px := x0; px < x1; px++ {
			if px < 0 || py < 0 || px >= s.Width || py >= s.Height {
				continue
			}
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
		if px < 0 || py < 0 || px >= s.Width || py >= s.Height {
			return
		}
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
		if (px-x0)%2 == 0 {
			if _, _, _, _, ok := dc.clipRect(px, y0, px+1, y0+1); ok {
				drawDot(px, y0)
			}
			if _, _, _, _, ok := dc.clipRect(px, y1-1, px+1, y1); ok {
				drawDot(px, y1-1)
			}
		}
	}
	for py := y0; py < y1; py++ {
		if (py-y0)%2 == 0 {
			if _, _, _, _, ok := dc.clipRect(x0, py, x0+1, py+1); ok {
				drawDot(x0, py)
			}
			if _, _, _, _, ok := dc.clipRect(x1-1, py, x1, py+1); ok {
				drawDot(x1-1, py)
			}
		}
	}
}

// FrameRect draws a one-pen-width border using the supplied brush color.
func (dc *DC) FrameRect(left, top, right, bottom int32, color uint32) {
	dc.DrawBorder(left, top, right, bottom, color)
}

// PolyBezier draws one or more cubic Bézier segments.
func (dc *DC) PolyBezier(pts [][2]int32) {
	if len(pts) < 4 {
		return
	}
	if dc.IsRecording() {
		dc.PathMoveTo(pts[0][0], pts[0][1])
	}
	for i := 0; i+3 < len(pts); i += 3 {
		if dc.IsRecording() {
			dc.PathBezierTo(
				pts[i+1][0], pts[i+1][1],
				pts[i+2][0], pts[i+2][1],
				pts[i+3][0], pts[i+3][1],
			)
			dc.CurX, dc.CurY = pts[i+3][0], pts[i+3][1]
			continue
		}
		dc.drawBezierSegment(pts[i][0], pts[i][1], pts[i+1][0], pts[i+1][1], pts[i+2][0], pts[i+2][1], pts[i+3][0], pts[i+3][1])
	}
	if !dc.IsRecording() {
		last := pts[len(pts)-1]
		dc.CurX, dc.CurY = last[0], last[1]
	}
}

// PolyBezierTo draws cubic Bézier segments from the current point.
func (dc *DC) PolyBezierTo(pts [][2]int32) {
	if len(pts) < 3 {
		return
	}
	cur := [2]int32{dc.CurX, dc.CurY}
	if dc.IsRecording() && len(dc.path.Points) == 0 {
		dc.PathMoveTo(cur[0], cur[1])
	}
	for i := 0; i+2 < len(pts); i += 3 {
		if dc.IsRecording() {
			dc.PathBezierTo(
				pts[i][0], pts[i][1],
				pts[i+1][0], pts[i+1][1],
				pts[i+2][0], pts[i+2][1],
			)
			dc.CurX, dc.CurY = pts[i+2][0], pts[i+2][1]
			continue
		}
		dc.drawBezierSegment(cur[0], cur[1], pts[i][0], pts[i][1], pts[i+1][0], pts[i+1][1], pts[i+2][0], pts[i+2][1])
		cur = pts[i+2]
		dc.CurX, dc.CurY = cur[0], cur[1]
	}
}

// Arc draws an elliptical arc.
func (dc *DC) Arc(left, top, right, bottom, xr1, yr1, xr2, yr2 int32) {
	pts, _, _ := dc.arcPoints(left, top, right, bottom, xr1, yr1, xr2, yr2, false)
	if len(pts) == 0 {
		return
	}
	if dc.IsRecording() {
		dc.PathMoveTo(pts[0][0], pts[0][1])
		for i := 1; i < len(pts); i++ {
			dc.PathLineTo(pts[i][0], pts[i][1])
		}
		return
	}
	if color, ok := dc.penColor(); ok {
		dc.strokePolylineLogical(pts, false, color, dc.penWidth())
	}
}

// ArcTo draws an arc and updates the current position to the arc end.
func (dc *DC) ArcTo(left, top, right, bottom, xr1, yr1, xr2, yr2 int32) {
	pts, start, end := dc.arcPoints(left, top, right, bottom, xr1, yr1, xr2, yr2, true)
	if len(pts) == 0 {
		return
	}
	if dc.IsRecording() {
		dc.PathMoveTo(dc.CurX, dc.CurY)
		dc.PathLineTo(start[0], start[1])
		for _, p := range pts[1:] {
			dc.PathLineTo(p[0], p[1])
		}
		dc.CurX, dc.CurY = end[0], end[1]
		return
	}
	dc.MoveTo(dc.CurX, dc.CurY)
	dc.LineTo(start[0], start[1])
	if color, ok := dc.penColor(); ok {
		dc.strokePolylineLogical(pts, false, color, dc.penWidth())
	}
	dc.CurX, dc.CurY = end[0], end[1]
}

// AngleArc draws a circular arc from the current point to the arc start.
func (dc *DC) AngleArc(cx, cy, radius int32, startAngle, sweepAngle float64) {
	if radius <= 0 {
		return
	}
	steps := int(math.Abs(sweepAngle)/7.5) + 4
	if steps < 4 {
		steps = 4
	}
	pts := make([][2]int32, 0, steps+1)
	for i := 0; i <= steps; i++ {
		a := (startAngle + sweepAngle*float64(i)/float64(steps)) * math.Pi / 180
		x := cx + int32(math.Round(float64(radius)*math.Cos(a)))
		y := cy - int32(math.Round(float64(radius)*math.Sin(a)))
		pts = append(pts, [2]int32{x, y})
	}
	if len(pts) == 0 {
		return
	}
	if dc.IsRecording() {
		dc.PathMoveTo(dc.CurX, dc.CurY)
		dc.PathLineTo(pts[0][0], pts[0][1])
		for _, p := range pts[1:] {
			dc.PathLineTo(p[0], p[1])
		}
		dc.CurX, dc.CurY = pts[len(pts)-1][0], pts[len(pts)-1][1]
		return
	}
	dc.LineTo(pts[0][0], pts[0][1])
	if color, ok := dc.penColor(); ok {
		dc.strokePolylineLogical(pts, false, color, dc.penWidth())
	}
	dc.CurX, dc.CurY = pts[len(pts)-1][0], pts[len(pts)-1][1]
}

func (dc *DC) penWidth() int32 {
	if dc.Pen == nil || dc.Pen.Style == 5 {
		return 0
	}
	if dc.Pen.Width <= 0 {
		return 1
	}
	return dc.Pen.Width
}

func (dc *DC) brushColor() (uint32, bool) {
	if dc.Brush == nil || dc.Brush.Style == 1 {
		return 0, false
	}
	return dc.Brush.Color, true
}

func (dc *DC) penColor() (uint32, bool) {
	if dc.Pen == nil || dc.Pen.Style == 5 {
		return 0, false
	}
	return dc.Pen.Color, true
}

func (dc *DC) drawLineWidth(x0, y0, x1, y1 int32, color uint32, width int32) {
	if width <= 1 {
		s := dc.target()
		if dc.ClipX1 <= dc.ClipX0 || dc.ClipY1 <= dc.ClipY0 {
			s.DrawLine(x0, y0, x1, y1, color)
			return
		}
		dx := abs32(x1 - x0)
		dy := abs32(y1 - y0)
		steps := dx
		if dy > steps {
			steps = dy
		}
		if steps == 0 {
			if _, _, _, _, ok := dc.clipRect(x0, y0, x0+1, y0+1); ok {
				s.SetPixel(x0, y0, color)
			}
			return
		}
		for i := int32(0); i <= steps; i++ {
			px := x0 + (x1-x0)*i/steps
			py := y0 + (y1-y0)*i/steps
			if _, _, _, _, ok := dc.clipRect(px, py, px+1, py+1); ok {
				s.SetPixel(px, py, color)
			}
		}
		return
	}
	half := width / 2
	dx := x1 - x0
	dy := y1 - y0
	if dx == 0 && dy == 0 {
		for oy := -half; oy <= half; oy++ {
			for ox := -half; ox <= half; ox++ {
				dc.SetPixel(x0-dc.OriginX+ox, y0-dc.OriginY+oy, color)
			}
		}
		return
	}
	if abs32(dx) >= abs32(dy) {
		for oy := -half; oy <= half; oy++ {
			dc.drawLineWidth(x0, y0+oy, x1, y1+oy, color, 1)
		}
	} else {
		for ox := -half; ox <= half; ox++ {
			dc.drawLineWidth(x0+ox, y0, x1+ox, y1, color, 1)
		}
	}
}

func (dc *DC) strokePolylineLogical(pts [][2]int32, closed bool, color uint32, width int32) {
	if len(pts) < 2 {
		return
	}
	abs := make([][2]int32, len(pts))
	for i, p := range pts {
		abs[i] = [2]int32{p[0] + dc.OriginX, p[1] + dc.OriginY}
	}
	dc.strokePolylineAbs(abs, closed, color, width)
}

func (dc *DC) strokePolylineAbs(pts [][2]int32, closed bool, color uint32, width int32) {
	if len(pts) < 2 {
		return
	}
	limit := len(pts) - 1
	for i := 0; i < limit; i++ {
		dc.drawLineWidth(pts[i][0], pts[i][1], pts[i+1][0], pts[i+1][1], color, width)
	}
	if closed {
		dc.drawLineWidth(pts[len(pts)-1][0], pts[len(pts)-1][1], pts[0][0], pts[0][1], color, width)
	}
}

func (dc *DC) fillPolygon(pts [][2]int32, color uint32) {
	if len(pts) < 3 {
		return
	}
	minY, maxY := pts[0][1], pts[0][1]
	for _, p := range pts[1:] {
		if p[1] < minY {
			minY = p[1]
		}
		if p[1] > maxY {
			maxY = p[1]
		}
	}
	for y := minY; y <= maxY; y++ {
		var nodes []int32
		for i, j := 0, len(pts)-1; i < len(pts); j, i = i, i+1 {
			yi, yj := pts[i][1], pts[j][1]
			if (yi < y && yj >= y) || (yj < y && yi >= y) {
				xi, xj := pts[i][0], pts[j][0]
				x := xi + (y-yi)*(xj-xi)/(yj-yi)
				nodes = append(nodes, x)
			}
		}
		for i := 0; i+1 < len(nodes); i += 2 {
			for j := i + 1; j < len(nodes); j++ {
				if nodes[j] < nodes[i] {
					nodes[i], nodes[j] = nodes[j], nodes[i]
				}
			}
		}
		for i := 0; i+1 < len(nodes); i += 2 {
			dc.FillRect(nodes[i], y, nodes[i+1]+1, y+1, color)
		}
	}
}

func (dc *DC) drawBezierSegment(x0, y0, x1, y1, x2, y2, x3, y3 int32) {
	if color, ok := dc.penColor(); ok {
		segs := flattenBezierPts(x0, y0, x1, y1, x2, y2, x3, y3)
		pts := make([][2]int32, 0, len(segs)+1)
		pts = append(pts, [2]int32{x0, y0})
		pts = append(pts, segs...)
		dc.strokePolylineLogical(pts, false, color, dc.penWidth())
	}
}

func (dc *DC) ellipseOutlinePoints(x0, y0, x1, y1 int32, steps int) [][2]int32 {
	if steps < 8 {
		steps = 8
	}
	cx := float64(x0+x1) / 2
	cy := float64(y0+y1) / 2
	rx := float64(x1-x0) / 2
	ry := float64(y1-y0) / 2
	pts := make([][2]int32, 0, steps)
	for i := 0; i < steps; i++ {
		a := 2 * math.Pi * float64(i) / float64(steps)
		x := int32(math.Round(cx + rx*math.Cos(a)))
		y := int32(math.Round(cy - ry*math.Sin(a)))
		pts = append(pts, [2]int32{x + dc.OriginX, y + dc.OriginY})
	}
	return pts
}

func (dc *DC) roundRectOutlinePoints(x0, y0, x1, y1, rx, ry int32, cornerSteps int) [][2]int32 {
	if cornerSteps < 2 {
		cornerSteps = 2
	}
	var pts [][2]int32
	addArc := func(cx, cy float64, start, end float64) {
		for i := 0; i <= cornerSteps; i++ {
			a := start + (end-start)*float64(i)/float64(cornerSteps)
			x := int32(math.Round(cx + float64(rx)*math.Cos(a)))
			y := int32(math.Round(cy + float64(ry)*math.Sin(a)))
			pts = append(pts, [2]int32{x + dc.OriginX, y + dc.OriginY})
		}
	}
	addArc(float64(x1-rx-1), float64(y0+ry), -math.Pi/2, 0)
	addArc(float64(x1-rx-1), float64(y1-ry-1), 0, math.Pi/2)
	addArc(float64(x0+rx), float64(y1-ry-1), math.Pi/2, math.Pi)
	addArc(float64(x0+rx), float64(y0+ry), math.Pi, 3*math.Pi/2)
	return pts
}

func (dc *DC) arcPoints(left, top, right, bottom, xr1, yr1, xr2, yr2 int32, withEnds bool) ([][2]int32, [2]int32, [2]int32) {
	var zero [2]int32
	w := right - left
	h := bottom - top
	if w == 0 || h == 0 {
		return nil, zero, zero
	}
	cx := float64(left+right) / 2
	cy := float64(top+bottom) / 2
	rx := float64(w) / 2
	ry := float64(h) / 2
	startAngle := math.Atan2((cy-float64(yr1))/ry, (float64(xr1)-cx)/rx)
	endAngle := math.Atan2((cy-float64(yr2))/ry, (float64(xr2)-cx)/rx)
	if dc.ArcDir == 2 {
		for endAngle > startAngle {
			endAngle -= 2 * math.Pi
		}
	} else {
		for endAngle < startAngle {
			endAngle += 2 * math.Pi
		}
	}
	steps := int(math.Abs(endAngle-startAngle)/(math.Pi/24)) + 1
	if steps < 4 {
		steps = 4
	}
	pts := make([][2]int32, 0, steps+1)
	for i := 0; i <= steps; i++ {
		a := startAngle + (endAngle-startAngle)*float64(i)/float64(steps)
		x := int32(math.Round(cx + rx*math.Cos(a)))
		y := int32(math.Round(cy - ry*math.Sin(a)))
		pts = append(pts, [2]int32{x, y})
	}
	if len(pts) == 0 {
		return nil, zero, zero
	}
	return pts, pts[0], pts[len(pts)-1]
}

func abs32(v int32) int32 {
	if v < 0 {
		return -v
	}
	return v
}

// DrawEdge draws a 3D edge rectangle.
// ReactOS: UserDrawEdge in win32ss/user/user32/windows/draw.c
// edge: combination of BDR_RAISEDOUTER=1, BDR_SUNKENOUTER=2, BDR_RAISEDINNER=4, BDR_SUNKENINNER=8
//
//	shortcuts: EDGE_RAISED=5, EDGE_SUNKEN=10, EDGE_ETCHED=6, EDGE_BUMP=9
//
// grfFlags: BF_LEFT=1, BF_TOP=2, BF_RIGHT=4, BF_BOTTOM=8, BF_RECT=15, BF_MIDDLE=0x800, BF_SOFT=0x1000
//
// System colors used (Win32 COLOR_* indices):
//
//	COLOR_3DDKSHADOW=21, COLOR_3DSHADOW=16, COLOR_3DFACE=15, COLOR_3DHILIGHT=20, COLOR_3DLIGHT=22
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

	if edge&BDR_RAISEDOUTER != 0 {
		outerTopLeft = hiLight
		outerBotRight = dkShadow
	} else if edge&BDR_SUNKENOUTER != 0 {
		outerTopLeft = dkShadow
		outerBotRight = hiLight
	}

	if edge&BDR_RAISEDINNER != 0 {
		innerTopLeft = hiLight
		innerBotRight = shadow
	} else if edge&BDR_SUNKENINNER != 0 {
		innerTopLeft = shadow
		innerBotRight = hiLight
	}

	hasOuter := (edge & (BDR_RAISEDOUTER | BDR_SUNKENOUTER)) != 0
	hasInner := (edge & (BDR_RAISEDINNER | BDR_SUNKENINNER)) != 0

	drawLine := func(x0, y0, x1, y1 int32, color uint32) {
		if grfFlags&BF_FLAT != 0 {
			color = shadow
		}
		ax0 := x0 + dc.OriginX
		ay0 := y0 + dc.OriginY
		ax1 := x1 + dc.OriginX
		ay1 := y1 + dc.OriginY
		ax0, ay0, ax1, ay1, ok := dc.clipRect(ax0, ay0, ax1, ay1)
		if ok {
			dc.target().FillRect(ax0, ay0, ax1, ay1, color)
		}
	}

	if hasOuter {
		// Outer edge (1px)
		if grfFlags&BF_TOP != 0 {
			drawLine(left, top, right, top+1, outerTopLeft)
		}
		if grfFlags&BF_LEFT != 0 {
			drawLine(left, top, left+1, bottom, outerTopLeft)
		}
		if grfFlags&BF_RIGHT != 0 {
			drawLine(right-1, top, right, bottom, outerBotRight)
		}
		if grfFlags&BF_BOTTOM != 0 {
			drawLine(left, bottom-1, right, bottom, outerBotRight)
		}
		left++
		top++
		right--
		bottom--
	}

	if hasInner {
		// Inner edge (1px)
		if grfFlags&BF_TOP != 0 {
			drawLine(left, top, right, top+1, innerTopLeft)
		}
		if grfFlags&BF_LEFT != 0 {
			drawLine(left, top, left+1, bottom, innerTopLeft)
		}
		if grfFlags&BF_RIGHT != 0 {
			drawLine(right-1, top, right, bottom, innerBotRight)
		}
		if grfFlags&BF_BOTTOM != 0 {
			drawLine(left, bottom-1, right, bottom, innerBotRight)
		}
		left++
		top++
		right--
		bottom--
	}

	if grfFlags&BF_MIDDLE != 0 && left < right && top < bottom {
		dc.FillRect(left, top, right, bottom, face)
	}
}

// DrawFrameControl draws a frame control (checkbox, radio, button, arrow, etc.)
// ReactOS: UserDrawFrameControl in win32ss/user/user32/windows/draw.c
// uType: DFC_CAPTION=1, DFC_MENU=2, DFC_SCROLL=3, DFC_BUTTON=4
// uState: DFCS_CAPTIONCLOSE=0, DFCS_CAPTIONMIN=1, DFCS_CAPTIONMAX=2, DFCS_CAPTIONRESTORE=3
//
//	DFCS_BUTTONCHECK=0, DFCS_BUTTONRADIOIMAGE=1, DFCS_BUTTONRADIOMASK=2, DFCS_BUTTONRADIO=4
//	DFCS_BUTTON3STATE=8, DFCS_BUTTONPUSH=16
//	DFCS_INACTIVE=0x100, DFCS_PUSHED=0x200, DFCS_CHECKED=0x400, DFCS_FLAT=0x4000
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
		DFCS_BUTTONPUSH  = 0x0010
		DFCS_BUTTONCHECK = 0x0000
		DFCS_BUTTONRADIO = 0x0004
		DFCS_PUSHED      = 0x0200
		DFCS_CHECKED     = 0x0400
		DFCS_FLAT        = 0x4000
	)

	w := right - left
	h := bottom - top
	cx := left + w/2
	cy := top + h/2

	switch uType {
	case DFC_BUTTON:
		if uState&DFCS_BUTTONPUSH != 0 {
			// Push button
			if uState&DFCS_PUSHED != 0 {
				dc.DrawEdge(left, top, right, bottom, 0x000A, 0x000F, sysColors) // EDGE_SUNKEN|BF_RECT
			} else {
				dc.DrawEdge(left, top, right, bottom, 0x0005, 0x000F, sysColors) // EDGE_RAISED|BF_RECT
			}
		} else if uState&DFCS_BUTTONRADIO != 0 {
			// Radio button: draw circle approximation
			dc.FillRect(left+1, top+1, right-1, bottom-1, face)
			dc.DrawBorder(left, top, right, bottom, shadow)
			if uState&DFCS_CHECKED != 0 {
				dc.FillRect(cx-2, cy-2, cx+2, cy+2, 0x000000)
			}
		} else {
			// Checkbox
			dc.FillRect(left, top, right, bottom, 0xFFFFFF)
			dc.DrawBorder(left, top, right, bottom, shadow)
			if uState&DFCS_CHECKED != 0 {
				// Draw checkmark
				for i := int32(0); i < h-4; i++ {
					dc.FillRect(left+2+i/2, top+2+i, left+3+i/2, top+3+i, 0x000000)
					dc.FillRect(right-3-i/2, top+2+i, right-2-i/2, top+3+i, 0x000000)
				}
			}
		}

	case DFC_CAPTION:
		// Caption buttons (close/min/max) - draw simple button appearance
		if uState&DFCS_PUSHED != 0 {
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
		if uState&DFCS_PUSHED != 0 {
			dc.DrawBorder(left, top, right, bottom, dkShadow)
		} else {
			dc.DrawEdge(left, top, right, bottom, 0x0005, 0x000F, sysColors)
		}
		// Draw arrow
		_ = cx
		_ = cy
		_ = hiLight

	case DFC_MENU:
		dc.FillRect(left, top, right, bottom, face)
	}
}

// DrawCaption draws a window caption bar.
// ReactOS: win32ss/user/ntuser/painting.c UserDrawCaption
// Flags: DC_ACTIVE=0x0001, DC_SMALLCAP=0x0002, DC_ICON=0x0004,
//
//	DC_TEXT=0x0008, DC_GRADIENT=0x0020, DC_NC=0x001F.
func (dc *DC) DrawCaption(left, top, right, bottom int32, title string, flags uint32, sysColors [31]uint32) {
	const (
		DC_ACTIVE   = 0x0001
		DC_SMALLCAP = 0x0002
		DC_TEXT     = 0x0008
		DC_GRADIENT = 0x0020
	)

	active := flags&DC_ACTIVE != 0
	gradient := flags&DC_GRADIENT != 0

	// Caption colours (ReactOS: IntGetSysColor)
	var bgLeft, bgRight, textColor uint32
	if active {
		bgLeft = sysColors[2]    // COLOR_ACTIVECAPTION
		bgRight = sysColors[27]  // COLOR_GRADIENTACTIVECAPTION
		textColor = sysColors[9] // COLOR_CAPTIONTEXT
	} else {
		bgLeft = sysColors[3]     // COLOR_INACTIVECAPTION
		bgRight = sysColors[28]   // COLOR_GRADIENTINACTIVECAPTION
		textColor = sysColors[19] // COLOR_INACTIVECAPTIONTEXT
	}

	if gradient && bgLeft != bgRight {
		dc.GradientFill(left, top, right, bottom, bgLeft, bgRight, true)
	} else {
		dc.FillRect(left, top, right, bottom, bgLeft)
	}

	if title != "" {
		textLeft := left + 2
		textTop := top + (bottom-top-16)/2
		if textTop < top {
			textTop = top
		}
		dc.drawTextSimple(textLeft, textTop, right-2, bottom, title, textColor)
	}
}

// drawTextSimple renders ASCII text with the embedded 8x16 font.
// Used internally by DrawCaption. Clips to (right, bottom).
func (dc *DC) drawTextSimple(x, y, right, bottom int32, text string, color uint32) {
	s := dc.target()
	if s.Pix == nil {
		return
	}

	ox, oy := dc.OriginX, dc.OriginY
	cx := x + ox
	cy := y + oy

	for _, ch := range []byte(text) {
		if cx+8 > right+ox || cy+16 > bottom+oy {
			break
		}
		if ch < 32 || ch > 126 {
			ch = '?'
		}
		glyphIdx := int(ch) - 32
		glyphData := font8x16[glyphIdx*16 : (glyphIdx+1)*16]
		for row := 0; row < 16; row++ {
			py := cy + int32(row)
			if py < 0 || py >= s.Height {
				continue
			}
			bits := glyphData[row]
			off := int(py)*int(s.Stride) + int(cx)*4
			for col := 0; col < 8; col++ {
				px := cx + int32(col)
				if px < 0 || px >= s.Width {
					off += 4
					continue
				}
				if bits&(0x80>>uint(col)) != 0 {
					s.Pix[off] = byte(color)
					s.Pix[off+1] = byte(color >> 8)
					s.Pix[off+2] = byte(color >> 16)
					s.Pix[off+3] = 0xFF
				}
				off += 4
			}
		}
		cx += 8
	}
}

// GradientFill fills a rect with a gradient (simplified: use top color for whole rect).
// ReactOS: NtGdiGradientFill
func (dc *DC) GradientFill(left, top, right, bottom int32, colorTop, colorBottom uint32, horiz bool) {
	if !horiz {
		// Vertical gradient (top to bottom)
		h := int(bottom - top)
		if h <= 0 {
			return
		}
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
		if w <= 0 {
			return
		}
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

package gdi

import "math"

// Path records GDI path operations between BeginPath/EndPath.
// ReactOS: win32ss/gdi/ntgdi/path.c - GdiPath / PATH
//
// A path is a sequence of subpaths. Each subpath is a series of
// line/curve segments. BeginPath opens recording mode; all GDI
// drawing functions (LineTo, Rectangle, Ellipse, etc.) add their
// outlines to the path instead of drawing. EndPath closes recording
// and the path can be stroked, filled, or used as a clip region.
type Path struct {
	Points []PathPoint
	Open   bool // true while recording (between BeginPath/EndPath)
}

// PathPoint is a single point in a GDI path.
type PathPoint struct {
	X, Y  int32
	Flags byte // PT_MOVETO=0x06, PT_LINETO=0x02, PT_BEZIERTO=0x04, PT_CLOSEFIGURE=0x01
}

// Path point type constants - ReactOS: win32ss/include/ntgdityp.h
const (
	PT_CLOSEFIGURE = 0x01
	PT_LINETO      = 0x02
	PT_BEZIERTO    = 0x04
	PT_MOVETO      = 0x06
)

// BeginPath opens path recording mode on this DC.
// Clears any existing path and starts fresh.
// ReactOS: NtGdiBeginPath → PATH_ResetGdiPath
func (dc *DC) BeginPath() bool {
	dc.path = &Path{Open: true}
	return true
}

// EndPath closes path recording mode.
// ReactOS: NtGdiEndPath
func (dc *DC) EndPath() bool {
	if dc.path == nil || !dc.path.Open {
		return false
	}
	dc.path.Open = false
	return true
}

// AbortPath discards the current path.
// ReactOS: NtGdiAbortPath
func (dc *DC) AbortPath() bool {
	dc.path = nil
	return true
}

// CloseFigure closes the current subpath by adding a line from the
// current position back to the subpath start.
// ReactOS: NtGdiCloseFigure
func (dc *DC) CloseFigure() bool {
	if dc.path == nil || !dc.path.Open {
		return false
	}
	n := len(dc.path.Points)
	if n > 0 {
		dc.path.Points[n-1].Flags |= PT_CLOSEFIGURE
	}
	return true
}

// PathMoveTo adds a MOVETO point (starts a new subpath).
func (dc *DC) PathMoveTo(x, y int32) {
	if dc.path == nil || !dc.path.Open {
		return
	}
	dc.path.Points = append(dc.path.Points, PathPoint{X: x, Y: y, Flags: PT_MOVETO})
}

// PathLineTo adds a LINETO point.
func (dc *DC) PathLineTo(x, y int32) {
	if dc.path == nil || !dc.path.Open {
		return
	}
	if len(dc.path.Points) == 0 {
		dc.path.Points = append(dc.path.Points, PathPoint{X: dc.CurX, Y: dc.CurY, Flags: PT_MOVETO})
	}
	dc.path.Points = append(dc.path.Points, PathPoint{X: x, Y: y, Flags: PT_LINETO})
}

// PathBezierTo adds 3 BEZIERTO points (cubic Bézier control points).
func (dc *DC) PathBezierTo(x1, y1, x2, y2, x3, y3 int32) {
	if dc.path == nil || !dc.path.Open {
		return
	}
	dc.path.Points = append(dc.path.Points,
		PathPoint{X: x1, Y: y1, Flags: PT_BEZIERTO},
		PathPoint{X: x2, Y: y2, Flags: PT_BEZIERTO},
		PathPoint{X: x3, Y: y3, Flags: PT_BEZIERTO},
	)
}

// PathAddRect adds a rectangle subpath (MoveTo + 3 LineTo + CloseFigure).
func (dc *DC) PathAddRect(x0, y0, x1, y1 int32) {
	if dc.path == nil || !dc.path.Open {
		return
	}
	dc.path.Points = append(dc.path.Points,
		PathPoint{X: x0, Y: y0, Flags: PT_MOVETO},
		PathPoint{X: x1, Y: y0, Flags: PT_LINETO},
		PathPoint{X: x1, Y: y1, Flags: PT_LINETO},
		PathPoint{X: x0, Y: y1, Flags: PT_LINETO | PT_CLOSEFIGURE},
	)
}

// PathAddEllipse adds an ellipse subpath approximated with Bézier curves.
// ReactOS: PATH_AddEllipse - approximation with 4 cubic Béziers.
func (dc *DC) PathAddEllipse(x0, y0, x1, y1 int32) {
	if dc.path == nil || !dc.path.Open {
		return
	}
	// Standard 4-segment Bézier approximation of an ellipse.
	// k = 4*(sqrt(2)-1)/3 ≈ 0.5522847498
	cx := float64(x0+x1) / 2
	cy := float64(y0+y1) / 2
	rx := float64(x1-x0) / 2
	ry := float64(y1-y0) / 2
	const k = 0.5522847498

	i := func(f float64) int32 { return int32(math.Round(f)) }

	dc.path.Points = append(dc.path.Points,
		PathPoint{X: i(cx + rx), Y: i(cy), Flags: PT_MOVETO},
		// top-right quadrant
		PathPoint{X: i(cx + rx), Y: i(cy - ry*k), Flags: PT_BEZIERTO},
		PathPoint{X: i(cx + rx*k), Y: i(cy - ry), Flags: PT_BEZIERTO},
		PathPoint{X: i(cx), Y: i(cy - ry), Flags: PT_BEZIERTO},
		// top-left quadrant
		PathPoint{X: i(cx - rx*k), Y: i(cy - ry), Flags: PT_BEZIERTO},
		PathPoint{X: i(cx - rx), Y: i(cy - ry*k), Flags: PT_BEZIERTO},
		PathPoint{X: i(cx - rx), Y: i(cy), Flags: PT_BEZIERTO},
		// bottom-left quadrant
		PathPoint{X: i(cx - rx), Y: i(cy + ry*k), Flags: PT_BEZIERTO},
		PathPoint{X: i(cx - rx*k), Y: i(cy + ry), Flags: PT_BEZIERTO},
		PathPoint{X: i(cx), Y: i(cy + ry), Flags: PT_BEZIERTO},
		// bottom-right quadrant
		PathPoint{X: i(cx + rx*k), Y: i(cy + ry), Flags: PT_BEZIERTO},
		PathPoint{X: i(cx + rx), Y: i(cy + ry*k), Flags: PT_BEZIERTO},
		PathPoint{X: i(cx + rx), Y: i(cy), Flags: PT_BEZIERTO | PT_CLOSEFIGURE},
	)
}

// IsRecording returns true if the DC is in path recording mode.
func (dc *DC) IsRecording() bool {
	return dc.path != nil && dc.path.Open
}

// GetPath returns the current path points (for GetPath Win32 API).
// Returns nil if no path or still recording.
func (dc *DC) GetPath() []PathPoint {
	if dc.path == nil || dc.path.Open {
		return nil
	}
	return dc.path.Points
}

// StrokePath draws the path outline using the current pen,
// then discards the path.
// ReactOS: NtGdiStrokePath → PATH_StrokePath
func (dc *DC) StrokePath() bool {
	if dc.path == nil || dc.path.Open {
		return false
	}
	pts := dc.path.Points
	dc.path = nil
	if len(pts) == 0 {
		return true
	}
	// Walk segments and draw lines/curves
	for i := 0; i < len(pts); i++ {
		p := pts[i]
		switch p.Flags & 0x06 {
		case PT_MOVETO:
			dc.CurX = p.X
			dc.CurY = p.Y
		case PT_LINETO:
			dc.LineTo(p.X + dc.OriginX, p.Y + dc.OriginY)
			dc.CurX = p.X
			dc.CurY = p.Y
		case PT_BEZIERTO:
			// Flatten Bézier to line segments
			if i+2 < len(pts) {
				flattenBezier(dc, dc.CurX, dc.CurY, pts[i].X, pts[i].Y, pts[i+1].X, pts[i+1].Y, pts[i+2].X, pts[i+2].Y)
				dc.CurX = pts[i+2].X
				dc.CurY = pts[i+2].Y
				i += 2
			}
		}
		if p.Flags&PT_CLOSEFIGURE != 0 {
			// Find the subpath start and draw line back to it
			for j := i; j >= 0; j-- {
				if pts[j].Flags&0x06 == PT_MOVETO {
					dc.LineTo(pts[j].X+dc.OriginX, pts[j].Y+dc.OriginY)
					break
				}
			}
		}
	}
	return true
}

// FillPath fills the closed path using the current brush,
// then discards the path.
// ReactOS: NtGdiFillPath → PATH_FillPath
func (dc *DC) FillPath() bool {
	if dc.path == nil || dc.path.Open {
		return false
	}
	pts := dc.path.Points
	dc.path = nil
	if len(pts) == 0 {
		return true
	}
	// Simple fill: compute bounding box and fill with brush
	minX, minY := pts[0].X, pts[0].Y
	maxX, maxY := pts[0].X, pts[0].Y
	for _, p := range pts {
		if p.X < minX {
			minX = p.X
		}
		if p.Y < minY {
			minY = p.Y
		}
		if p.X > maxX {
			maxX = p.X
		}
		if p.Y > maxY {
			maxY = p.Y
		}
	}
	dc.FillRectBrush(minX+dc.OriginX, minY+dc.OriginY, maxX+dc.OriginX, maxY+dc.OriginY)
	return true
}

// StrokeAndFillPath strokes then fills the path, then discards it.
// ReactOS: NtGdiStrokeAndFillPath
func (dc *DC) StrokeAndFillPath() bool {
	if dc.path == nil || dc.path.Open {
		return false
	}
	// Save points before stroke consumes them
	saved := make([]PathPoint, len(dc.path.Points))
	copy(saved, dc.path.Points)

	dc.StrokePath()
	// Restore for fill
	dc.path = &Path{Points: saved}
	dc.FillPath()
	return true
}

// FlattenPath converts all Bézier curves in the path to line segments.
// ReactOS: NtGdiFlattenPath → PATH_FlattenPath
func (dc *DC) FlattenPath() bool {
	if dc.path == nil || dc.path.Open {
		return false
	}
	var flat []PathPoint
	var cx, cy int32
	for i := 0; i < len(dc.path.Points); i++ {
		p := dc.path.Points[i]
		switch p.Flags & 0x06 {
		case PT_MOVETO:
			flat = append(flat, p)
			cx, cy = p.X, p.Y
		case PT_LINETO:
			flat = append(flat, p)
			cx, cy = p.X, p.Y
		case PT_BEZIERTO:
			if i+2 < len(dc.path.Points) {
				segs := flattenBezierPts(cx, cy, dc.path.Points[i].X, dc.path.Points[i].Y,
					dc.path.Points[i+1].X, dc.path.Points[i+1].Y,
					dc.path.Points[i+2].X, dc.path.Points[i+2].Y)
				for _, s := range segs {
					flags := byte(PT_LINETO)
					flat = append(flat, PathPoint{X: s[0], Y: s[1], Flags: flags})
				}
				cx = dc.path.Points[i+2].X
				cy = dc.path.Points[i+2].Y
				// Carry CLOSEFIGURE from the last Bézier point
				if dc.path.Points[i+2].Flags&PT_CLOSEFIGURE != 0 && len(flat) > 0 {
					flat[len(flat)-1].Flags |= PT_CLOSEFIGURE
				}
				i += 2
			}
		}
	}
	dc.path.Points = flat
	return true
}

// WidenPath converts the path to the outline of the stroked path.
// This is a simplified version that just keeps the path as-is.
// ReactOS: NtGdiWidenPath - full impl needs pen width/style outset.
func (dc *DC) WidenPath() bool {
	if dc.path == nil || dc.path.Open {
		return false
	}
	// For our purposes, widening is a no-op (path already represents outlines).
	// A full implementation would offset the path by half the pen width.
	return true
}

// SelectClipPath selects the current path as a clip region.
// ReactOS: NtGdiSelectClipPath
func (dc *DC) SelectClipPath(mode int) bool {
	if dc.path == nil || dc.path.Open {
		return false
	}
	pts := dc.path.Points
	dc.path = nil
	if len(pts) == 0 {
		return false
	}
	// Compute bounding box of path and set as clip
	minX, minY := pts[0].X, pts[0].Y
	maxX, maxY := pts[0].X, pts[0].Y
	for _, p := range pts {
		if p.X < minX {
			minX = p.X
		}
		if p.Y < minY {
			minY = p.Y
		}
		if p.X > maxX {
			maxX = p.X
		}
		if p.Y > maxY {
			maxY = p.Y
		}
	}
	dc.SetClipRect(minX+dc.OriginX, minY+dc.OriginY, maxX+dc.OriginX, maxY+dc.OriginY)
	return true
}

// flattenBezier draws a flattened cubic Bézier directly on the DC.
func flattenBezier(dc *DC, x0, y0, x1, y1, x2, y2, x3, y3 int32) {
	segs := flattenBezierPts(x0, y0, x1, y1, x2, y2, x3, y3)
	for _, s := range segs {
		dc.LineTo(s[0]+dc.OriginX, s[1]+dc.OriginY)
	}
}

// flattenBezierPts returns line segments approximating a cubic Bézier.
func flattenBezierPts(x0, y0, x1, y1, x2, y2, x3, y3 int32) [][2]int32 {
	const maxDepth = 6
	var result [][2]int32
	subdivide(&result, float64(x0), float64(y0), float64(x1), float64(y1),
		float64(x2), float64(y2), float64(x3), float64(y3), 0, maxDepth)
	result = append(result, [2]int32{x3, y3})
	return result
}

func subdivide(out *[][2]int32, x0, y0, x1, y1, x2, y2, x3, y3 float64, depth, maxDepth int) {
	if depth >= maxDepth {
		*out = append(*out, [2]int32{int32(math.Round(x3)), int32(math.Round(y3))})
		return
	}
	// Check flatness: if control points are close to the line p0→p3, no need to subdivide
	dx := x3 - x0
	dy := y3 - y0
	d := math.Sqrt(dx*dx + dy*dy)
	if d < 1 {
		*out = append(*out, [2]int32{int32(math.Round(x3)), int32(math.Round(y3))})
		return
	}
	d1 := math.Abs((x1-x0)*dy-(y1-y0)*dx) / d
	d2 := math.Abs((x2-x0)*dy-(y2-y0)*dx) / d
	if d1+d2 < 1.0 {
		*out = append(*out, [2]int32{int32(math.Round(x3)), int32(math.Round(y3))})
		return
	}
	// De Casteljau subdivision at t=0.5
	mx01 := (x0 + x1) / 2
	my01 := (y0 + y1) / 2
	mx12 := (x1 + x2) / 2
	my12 := (y1 + y2) / 2
	mx23 := (x2 + x3) / 2
	my23 := (y2 + y3) / 2
	mx012 := (mx01 + mx12) / 2
	my012 := (my01 + my12) / 2
	mx123 := (mx12 + mx23) / 2
	my123 := (my12 + my23) / 2
	mx0123 := (mx012 + mx123) / 2
	my0123 := (my012 + my123) / 2
	subdivide(out, x0, y0, mx01, my01, mx012, my012, mx0123, my0123, depth+1, maxDepth)
	subdivide(out, mx0123, my0123, mx123, my123, mx23, my23, x3, y3, depth+1, maxDepth)
}

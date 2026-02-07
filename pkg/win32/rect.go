//go:build guest_windows

package win32

// Rect operations - ported from ReactOS win32ss/user/user32/windows/rect.c
// All functions mirror the Windows API exactly.

// CopyRect copies src into dst.
func CopyRect(dst, src *Rect) bool {
	if dst == nil || src == nil {
		return false
	}
	*dst = *src
	return true
}

// EqualRect returns true if both rects are identical.
func EqualRect(r1, r2 *Rect) bool {
	if r1 == nil || r2 == nil {
		return false
	}
	return r1.Left == r2.Left && r1.Top == r2.Top &&
		r1.Right == r2.Right && r1.Bottom == r2.Bottom
}

// InflateRect expands (dx>0) or shrinks (dx<0) a rectangle.
func InflateRect(r *Rect, dx, dy int32) bool {
	if r == nil {
		return false
	}
	r.Left -= dx
	r.Top -= dy
	r.Right += dx
	r.Bottom += dy
	return true
}

// IntersectRect stores the intersection of r1 and r2 in dst.
// Returns false (and empties dst) if there is no intersection.
func IntersectRect(dst, r1, r2 *Rect) bool {
	if dst == nil || r1 == nil || r2 == nil {
		return false
	}
	if r1.Empty() || r2.Empty() ||
		r1.Left >= r2.Right || r2.Left >= r1.Right ||
		r1.Top >= r2.Bottom || r2.Top >= r1.Bottom {
		SetRectEmpty(dst)
		return false
	}
	dst.Left = max32(r1.Left, r2.Left)
	dst.Right = min32(r1.Right, r2.Right)
	dst.Top = max32(r1.Top, r2.Top)
	dst.Bottom = min32(r1.Bottom, r2.Bottom)
	return true
}

// OffsetRect translates a rectangle by (dx, dy).
func OffsetRect(r *Rect, dx, dy int32) bool {
	if r == nil {
		return false
	}
	r.Left += dx
	r.Top += dy
	r.Right += dx
	r.Bottom += dy
	return true
}

// PtInRect returns true if the point (x,y) is inside the rectangle.
// Matches Windows convention: point on left/top edge IN, right/bottom edge OUT.
func PtInRect(r *Rect, x, y int32) bool {
	if r == nil {
		return false
	}
	return x >= r.Left && x < r.Right && y >= r.Top && y < r.Bottom
}

// SetRect initialises a rectangle with the given coordinates.
func SetRect(r *Rect, left, top, right, bottom int32) bool {
	if r == nil {
		return false
	}
	r.Left = left
	r.Top = top
	r.Right = right
	r.Bottom = bottom
	return true
}

// SetRectEmpty zeroes all fields of a rectangle.
func SetRectEmpty(r *Rect) bool {
	if r == nil {
		return false
	}
	r.Left = 0
	r.Top = 0
	r.Right = 0
	r.Bottom = 0
	return true
}

// SubtractRect subtracts r2 from r1 and stores the result in dst.
// When r2 covers r1 entirely, dst is emptied and false is returned.
func SubtractRect(dst, r1, r2 *Rect) bool {
	if dst == nil || r1 == nil || r2 == nil {
		return false
	}
	var tmp Rect
	if !IntersectRect(&tmp, r1, r2) {
		*dst = *r1
		return true
	}
	if EqualRect(&tmp, r1) {
		SetRectEmpty(dst)
		return false
	}
	*dst = *r1
	if dst.Top == tmp.Top && dst.Bottom == tmp.Bottom {
		if dst.Left == tmp.Left {
			dst.Left = tmp.Right
		} else if dst.Right == tmp.Right {
			dst.Right = tmp.Left
		}
	} else if dst.Left == tmp.Left && dst.Right == tmp.Right {
		if dst.Top == tmp.Top {
			dst.Top = tmp.Bottom
		} else if dst.Bottom == tmp.Bottom {
			dst.Bottom = tmp.Top
		}
	}
	return true
}

// UnionRect stores the smallest rectangle that encloses both r1 and r2.
func UnionRect(dst, r1, r2 *Rect) bool {
	if dst == nil || r1 == nil || r2 == nil {
		return false
	}
	if r1.Empty() {
		if r2.Empty() {
			SetRectEmpty(dst)
			return false
		}
		*dst = *r2
	} else {
		if r2.Empty() {
			*dst = *r1
		} else {
			dst.Left = min32(r1.Left, r2.Left)
			dst.Top = min32(r1.Top, r2.Top)
			dst.Right = max32(r1.Right, r2.Right)
			dst.Bottom = max32(r1.Bottom, r2.Bottom)
		}
	}
	return true
}

// IsRectEmpty returns true for a null or degenerate rectangle.
func IsRectEmpty(r *Rect) bool {
	if r == nil {
		return true
	}
	return r.Empty()
}

// NormalizeRect ensures Left ≤ Right and Top ≤ Bottom (swaps if needed).
func NormalizeRect(r *Rect) {
	if r.Left > r.Right {
		r.Left, r.Right = r.Right, r.Left
	}
	if r.Top > r.Bottom {
		r.Top, r.Bottom = r.Bottom, r.Top
	}
}

func min32(a, b int32) int32 {
	if a < b {
		return a
	}
	return b
}

func max32(a, b int32) int32 {
	if a > b {
		return a
	}
	return b
}

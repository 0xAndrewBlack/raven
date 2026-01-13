package gdi

import "math"

// IdentityXForm returns the identity transformation matrix.
func IdentityXForm() XForm {
	return XForm{EM11: 1, EM22: 1}
}

// SetWorldTransform sets the world-to-page transformation.
// Only effective when GraphicsMode == GM_ADVANCED (2).
// ReactOS: NtGdiSetWorldTransform
func (dc *DC) SetWorldTransform(xf XForm) bool {
	if dc.GraphicsMode != 2 {
		return false
	}
	dc.WorldTransform = xf
	return true
}

// GetWorldTransform returns the current world transform.
// ReactOS: NtGdiGetTransform(DC_WORLD_TO_PAGE)
func (dc *DC) GetWorldTransform() XForm {
	return dc.WorldTransform
}

// ModifyWorldTransform modifies the world transform.
// mode: MWT_IDENTITY=1, MWT_LEFTMULTIPLY=2, MWT_RIGHTMULTIPLY=3
// ReactOS: NtGdiModifyWorldTransform
func (dc *DC) ModifyWorldTransform(xf XForm, mode int) bool {
	if dc.GraphicsMode != 2 {
		return false
	}
	switch mode {
	case 1: // MWT_IDENTITY
		dc.WorldTransform = IdentityXForm()
	case 2: // MWT_LEFTMULTIPLY
		dc.WorldTransform = multiplyXForm(xf, dc.WorldTransform)
	case 3: // MWT_RIGHTMULTIPLY
		dc.WorldTransform = multiplyXForm(dc.WorldTransform, xf)
	default:
		return false
	}
	return true
}

// multiplyXForm computes a * b (matrix multiplication for XFORM).
func multiplyXForm(a, b XForm) XForm {
	return XForm{
		EM11: a.EM11*b.EM11 + a.EM12*b.EM21,
		EM12: a.EM11*b.EM12 + a.EM12*b.EM22,
		EM21: a.EM21*b.EM11 + a.EM22*b.EM21,
		EM22: a.EM21*b.EM12 + a.EM22*b.EM22,
		EDx:  a.EDx*b.EM11 + a.EDy*b.EM21 + b.EDx,
		EDy:  a.EDx*b.EM12 + a.EDy*b.EM22 + b.EDy,
	}
}

// DPtoLP converts device (pixel) coordinates to logical coordinates.
// ReactOS: NtGdiTransformPoints(GdiDpToLp)
//
// The transform chain is: logical → world → page → device
// DPtoLP reverses: device → page → world → logical
func (dc *DC) DPtoLP(pts [][2]int32) {
	for i := range pts {
		x := float64(pts[i][0])
		y := float64(pts[i][1])

		// Device → page: subtract viewport origin, apply inverse viewport/window scaling
		x -= float64(dc.OriginX)
		y -= float64(dc.OriginY)

		if dc.ViewportExtX != 0 && dc.ViewportExtY != 0 {
			x = x * float64(dc.WindowExtX) / float64(dc.ViewportExtX)
			y = y * float64(dc.WindowExtY) / float64(dc.ViewportExtY)
		}

		x += float64(dc.WindowOrgX)
		y += float64(dc.WindowOrgY)

		// Page → world: apply inverse world transform
		if dc.GraphicsMode == 2 {
			wt := dc.WorldTransform
			det := float64(wt.EM11)*float64(wt.EM22) - float64(wt.EM12)*float64(wt.EM21)
			if det != 0 {
				px := x - float64(wt.EDx)
				py := y - float64(wt.EDy)
				x = (px*float64(wt.EM22) - py*float64(wt.EM21)) / det
				y = (-px*float64(wt.EM12) + py*float64(wt.EM11)) / det
			}
		}

		pts[i][0] = int32(math.Round(x))
		pts[i][1] = int32(math.Round(y))
	}
}

// LPtoDP converts logical coordinates to device (pixel) coordinates.
// ReactOS: NtGdiTransformPoints(GdiLpToDp)
//
// The transform chain is: logical → world → page → device
func (dc *DC) LPtoDP(pts [][2]int32) {
	for i := range pts {
		x := float64(pts[i][0])
		y := float64(pts[i][1])

		// Logical → world: apply world transform
		if dc.GraphicsMode == 2 {
			wt := dc.WorldTransform
			nx := x*float64(wt.EM11) + y*float64(wt.EM21) + float64(wt.EDx)
			ny := x*float64(wt.EM12) + y*float64(wt.EM22) + float64(wt.EDy)
			x = nx
			y = ny
		}

		// World → page: subtract window origin, apply window/viewport scaling
		x -= float64(dc.WindowOrgX)
		y -= float64(dc.WindowOrgY)

		if dc.WindowExtX != 0 && dc.WindowExtY != 0 {
			x = x * float64(dc.ViewportExtX) / float64(dc.WindowExtX)
			y = y * float64(dc.ViewportExtY) / float64(dc.WindowExtY)
		}

		// Page → device: add viewport origin
		x += float64(dc.OriginX)
		y += float64(dc.OriginY)

		pts[i][0] = int32(math.Round(x))
		pts[i][1] = int32(math.Round(y))
	}
}

// ScaleViewportExt multiplies the viewport extents by (xNum/xDen, yNum/yDen).
// ReactOS: NtGdiScaleViewportExtEx
func (dc *DC) ScaleViewportExt(xNum, xDen, yNum, yDen int32) bool {
	if xDen == 0 || yDen == 0 {
		return false
	}
	dc.ViewportExtX = dc.ViewportExtX * xNum / xDen
	dc.ViewportExtY = dc.ViewportExtY * yNum / yDen
	return true
}

// ScaleWindowExt multiplies the window extents by (xNum/xDen, yNum/yDen).
// ReactOS: NtGdiScaleWindowExtEx
func (dc *DC) ScaleWindowExt(xNum, xDen, yNum, yDen int32) bool {
	if xDen == 0 || yDen == 0 {
		return false
	}
	dc.WindowExtX = dc.WindowExtX * xNum / xDen
	dc.WindowExtY = dc.WindowExtY * yNum / yDen
	return true
}

// OffsetWindowOrg adds a delta to the window origin.
// ReactOS: NtGdiOffsetWindowOrgEx
func (dc *DC) OffsetWindowOrg(dx, dy int32) {
	dc.WindowOrgX += dx
	dc.WindowOrgY += dy
}

// SetGraphicsMode sets the graphics mode (GM_COMPATIBLE=1, GM_ADVANCED=2).
// GM_ADVANCED enables world transforms. Switching to GM_COMPATIBLE resets
// the world transform to identity.
// ReactOS: NtGdiSetGraphicsMode
func (dc *DC) SetGraphicsMode(mode int32) int32 {
	old := dc.GraphicsMode
	if mode < 1 || mode > 2 {
		return 0 // error
	}
	dc.GraphicsMode = mode
	if mode == 1 {
		dc.WorldTransform = IdentityXForm()
	}
	return old
}

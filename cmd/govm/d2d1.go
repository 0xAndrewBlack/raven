//go:build guest_windows

package main

import (
	"math"
	"strings"

	gdi "github.com/mirkobrombin/Raven/pkg/gdi"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

const (
	d2d1FactoryMethods            = 17
	d2d1RenderTargetMethods       = 57
	d2d1BitmapRenderTargetMethods = 58
	d2d1HwndRenderTargetMethods   = 61
	d2d1DCRenderTargetMethods     = 58
	d2d1BrushMethods              = 8
	d2d1SolidColorBrushMethods    = 10
	d2d1BitmapBrushMethods        = 16
	d2d1LinearGradientMethods     = 13
	d2d1RadialGradientMethods     = 17
	d2d1GradientStopsMethods      = 8
	d2d1BitmapMethods             = 10
	d2d1GeometryMethods           = 18
	d2d1RectangleGeometryMethods  = 19
	d2d1RoundedGeometryMethods    = 19
	d2d1EllipseGeometryMethods    = 19
	d2d1GeometryGroupMethods      = 21
	d2d1TransformedGeomMethods    = 20
	d2d1PathGeometryMethods       = 22
	d2d1GeometrySinkMethods       = 15
	d2d1StrokeStyleMethods        = 12
	d2d1DrawingStateMethods       = 8
	d2d1LayerMethods              = 5
	d2d1MeshMethods               = 5

	d2d1FactoryTypeSingleThreaded = 0
	d2d1FactoryTypeMultiThreaded  = 1

	d2d1FillModeAlternate = 0
	d2d1FillModeWinding   = 1

	d2d1GeomTypePath        = 0
	d2d1GeomTypeRectangle   = 1
	d2d1GeomTypeRoundedRect = 2
	d2d1GeomTypeEllipse     = 3
	d2d1GeomTypeGroup       = 4
	d2d1GeomTypeTransform   = 5

	d2d1SegmentLine   = 0
	d2d1SegmentBezier = 1
	d2d1SegmentArc    = 2
)

var (
	IID_ID2D1Resource           = GUID{0x2cd90691, 0x12e2, 0x11dc, [8]byte{0x9f, 0xed, 0x00, 0x11, 0x43, 0xa0, 0x55, 0xf9}}
	IID_ID2D1Geometry           = GUID{0x2cd906a1, 0x12e2, 0x11dc, [8]byte{0x9f, 0xed, 0x00, 0x11, 0x43, 0xa0, 0x55, 0xf9}}
	IID_ID2D1GeometrySink       = GUID{0x2cd9069f, 0x12e2, 0x11dc, [8]byte{0x9f, 0xed, 0x00, 0x11, 0x43, 0xa0, 0x55, 0xf9}}
	IID_ID2D1PathGeometry       = GUID{0x2cd906a5, 0x12e2, 0x11dc, [8]byte{0x9f, 0xed, 0x00, 0x11, 0x43, 0xa0, 0x55, 0xf9}}
	IID_ID2D1Brush              = GUID{0x2cd906a8, 0x12e2, 0x11dc, [8]byte{0x9f, 0xed, 0x00, 0x11, 0x43, 0xa0, 0x55, 0xf9}}
	IID_ID2D1SolidColorBrush    = GUID{0x2cd906a9, 0x12e2, 0x11dc, [8]byte{0x9f, 0xed, 0x00, 0x11, 0x43, 0xa0, 0x55, 0xf9}}
	IID_ID2D1RenderTarget       = GUID{0x2cd90694, 0x12e2, 0x11dc, [8]byte{0x9f, 0xed, 0x00, 0x11, 0x43, 0xa0, 0x55, 0xf9}}
	IID_ID2D1BitmapRenderTarget = GUID{0x2cd90695, 0x12e2, 0x11dc, [8]byte{0x9f, 0xed, 0x00, 0x11, 0x43, 0xa0, 0x55, 0xf9}}
	IID_ID2D1HwndRenderTarget   = GUID{0x2cd90698, 0x12e2, 0x11dc, [8]byte{0x9f, 0xed, 0x00, 0x11, 0x43, 0xa0, 0x55, 0xf9}}
	IID_ID2D1DCRenderTarget     = GUID{0x1c51bc64, 0xde61, 0x46fd, [8]byte{0x98, 0x99, 0x63, 0xa5, 0xd8, 0xf0, 0x39, 0x50}}
	IID_ID2D1Factory            = GUID{0x06152247, 0x6f50, 0x465a, [8]byte{0x92, 0x45, 0x11, 0x8b, 0xfd, 0x3b, 0x60, 0x07}}
	IID_ID2D1Bitmap             = GUID{0xa2296057, 0xea42, 0x4099, [8]byte{0x98, 0x3b, 0x53, 0x9f, 0xb6, 0x50, 0x54, 0x26}}
	IID_ID2D1DrawingStateBlock  = GUID{0x28506e39, 0xebf6, 0x46a1, [8]byte{0xbb, 0x47, 0xfd, 0x85, 0x56, 0x5a, 0xb9, 0x57}}

	CLSID_D2D1Factory = GUID{0x06152247, 0x6f50, 0x465a, [8]byte{0x92, 0x45, 0x11, 0x8b, 0xfd, 0x3b, 0x60, 0x07}}
)

type d2d1Factory struct {
	factoryType int
	dpiX, dpiY  float32
}

type d2d1RenderTarget struct {
	factoryPtr          uint64
	hwnd                uint64
	hdc                 uint64
	dc                  *gdi.DC
	width               uint32
	height              uint32
	originX             int32
	originY             int32
	dpiX, dpiY          float32
	transform           [6]float32
	clipStack           []d2d1Rect
	isDrawing           bool
	tags                [2]uint64
	antialiasMode       uint32
	textAntialiasMode   uint32
	textRenderingParams uint64
	offscreen           *gdi.Surface
	wicBitmap           *wicBitmap
}

type d2d1SolidColorBrush struct {
	factoryPtr uint64
	r, g, b, a float32
	opacity    float32
	transform  [6]float32
}

type d2d1BitmapBrush struct {
	factoryPtr    uint64
	bitmapPtr     uint64
	opacity       float32
	transform     [6]float32
	extendModeX   uint32
	extendModeY   uint32
	interpolation uint32
}

type d2d1GradientStop struct {
	position float32
	color    [4]float32
}

type d2d1GradientStopCollection struct {
	factoryPtr uint64
	stops      []d2d1GradientStop
	gamma      uint32
	extendMode uint32
}

type d2d1LinearGradientBrush struct {
	factoryPtr uint64
	opacity    float32
	transform  [6]float32
	start      [2]float32
	end        [2]float32
	gradient   uint64
	avg        [4]float32
}

type d2d1RadialGradientBrush struct {
	factoryPtr uint64
	opacity    float32
	transform  [6]float32
	center     [2]float32
	offset     [2]float32
	radiusX    float32
	radiusY    float32
	gradient   uint64
	avg        [4]float32
}

type d2d1PathGeometry struct {
	factoryPtr       uint64
	geometryType     int
	fillMode         int
	rect             d2d1Rect
	radiusX, radiusY float32
	ellipse          d2d1Ellipse
	sourcePtr        uint64
	sourceGeometries []uint64
	transform        [6]float32
	figures          []d2d1Figure
}

type d2d1Figure struct {
	startX, startY float32
	segments       []d2d1Segment
	closed         bool
}

type d2d1Segment struct {
	kind int
	pts  [3][2]float32
}

type d2d1GeometrySink struct {
	geom         *d2d1PathGeometry
	current      *d2d1Figure
	closed       bool
	segmentFlags int
}

type d2d1Bitmap struct {
	factoryPtr    uint64
	width, height uint32
	pixels        []byte
	stride        uint32
}

type d2d1StrokeStyle struct {
	factoryPtr                uint64
	startCap, endCap, dashCap uint32
	lineJoin                  uint32
	miterLimit                float32
	dashOffset                float32
	dashStyle                 uint32
	dashes                    []float32
}

type d2d1DrawingStateBlock struct {
	factoryPtr          uint64
	transform           [6]float32
	antialiasMode       uint32
	textAntialiasMode   uint32
	tags                [2]uint64
	textRenderingParams uint64
}

type d2d1Layer struct {
	factoryPtr uint64
	width      float32
	height     float32
}

type d2d1Mesh struct {
	factoryPtr uint64
}

type d2d1Rect struct {
	left, top, right, bottom float32
}

type d2d1RoundedRect struct {
	rect             d2d1Rect
	radiusX, radiusY float32
}

type d2d1Ellipse struct {
	x, y    float32
	radiusX float32
	radiusY float32
}

func registerD2D1ClassFactories(cs *comState) {
	cs.classFactories[CLSID_D2D1Factory] = &classFactory{
		clsid: CLSID_D2D1Factory,
		create: func(iid GUID) (*comObject, error) {
			if !guidEqual(iid, IID_IUnknown) && !guidEqual(iid, IID_ID2D1Factory) {
				return nil, hresultError(E_NOINTERFACE)
			}
			return cs.createD2D1FactoryObject(d2d1FactoryTypeSingleThreaded)
		},
	}
}

func registerD2D1Handlers(hctx *HandlerCtx) {
	dll, ok := hctx.SynthByName["d2d1.dll"]
	if !ok {
		return
	}
	if hctx.Com == nil {
		hctx.Com = newCOMState(hctx)
	}
	cs := hctx.Com
	d := hctx.Disp
	registerAutoOrDynamicHandler(hctx, dll, "D2D1CreateFactory", func(ctx *ntapi.TrapContext) uint32 {
		factoryType := int(ctx.Arg(0))
		riidPtr := ctx.Arg(1)
		ppFactory := ctx.Arg(3)
		if ppFactory == 0 {
			ctx.SetReturn(E_POINTER)
			return 0
		}
		ctx.Mem.Write64(ppFactory, 0)
		if riidPtr == 0 {
			ctx.SetReturn(E_POINTER)
			return 0
		}
		if factoryType != d2d1FactoryTypeSingleThreaded && factoryType != d2d1FactoryTypeMultiThreaded {
			ctx.SetReturn(E_INVALIDARG)
			return 0
		}
		riid := readGUID(ctx.Mem, riidPtr)
		if !guidEqual(riid, IID_IUnknown) && !guidEqual(riid, IID_ID2D1Factory) {
			ctx.SetReturn(E_NOINTERFACE)
			return 0
		}
		obj, err := cs.createD2D1FactoryObject(factoryType)
		if err != nil {
			ctx.SetReturn(uint64(hresultFromError(err)))
			return 0
		}
		ctx.Mem.Write64(ppFactory, obj.objectAddr)
		ctx.SetReturn(S_OK)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "D2D1CreateDevice", func(ctx *ntapi.TrapContext) uint32 {
		if pp := ctx.Arg(2); pp != 0 {
			ctx.Mem.Write64(pp, 0)
		}
		ctx.SetReturn(E_NOTIMPL)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "D2D1CreateDeviceContext", func(ctx *ntapi.TrapContext) uint32 {
		if pp := ctx.Arg(2); pp != 0 {
			ctx.Mem.Write64(pp, 0)
		}
		ctx.SetReturn(E_NOTIMPL)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "DllCanUnloadNow", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(S_FALSE)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "DllGetClassObject", func(ctx *ntapi.TrapContext) uint32 {
		rclsid := ctx.Arg(0)
		riid := ctx.Arg(1)
		ppv := ctx.Arg(2)
		if ppv == 0 {
			ctx.SetReturn(E_POINTER)
			return 0
		}
		ctx.Mem.Write64(ppv, 0)
		if rclsid == 0 || riid == 0 {
			ctx.SetReturn(E_POINTER)
			return 0
		}
		iid := readGUID(ctx.Mem, riid)
		if !guidEqual(iid, IID_IClassFactory) && !guidEqual(iid, IID_IUnknown) {
			ctx.SetReturn(E_NOINTERFACE)
			return 0
		}
		clsid := readGUID(ctx.Mem, rclsid)
		cf, ok := cs.classFactories[clsid]
		if !ok {
			ctx.SetReturn(CLASS_E_CLASSNOTAVAILABLE)
			return 0
		}
		obj, err := cs.createClassFactoryObject(cf)
		if err != nil {
			ctx.SetReturn(uint64(hresultFromError(err)))
			return 0
		}
		ctx.Mem.Write64(ppv, obj.objectAddr)
		ctx.SetReturn(S_OK)
		return 0
	})
}

func (cs *comState) createD2D1FactoryObject(factoryType int) (*comObject, error) {
	obj, err := cs.createGuestObject(cs.mem, IID_ID2D1Factory, d2d1FactoryMethods)
	if err != nil {
		return nil, err
	}
	obj.clsid = CLSID_D2D1Factory
	obj.kind = "d2d1-factory"
	obj.supportedIIDs[IID_ID2D1Factory] = true
	obj.data = &d2d1Factory{factoryType: factoryType, dpiX: 96, dpiY: 96}
	return obj, nil
}

func (cs *comState) createD2D1PathGeometryObject(kind string, methods int, geom *d2d1PathGeometry) (*comObject, error) {
	obj, err := cs.createGuestObject(cs.mem, IID_ID2D1Geometry, methods)
	if err != nil {
		return nil, err
	}
	obj.kind = kind
	obj.supportedIIDs[IID_ID2D1Resource] = true
	obj.supportedIIDs[IID_ID2D1Geometry] = true
	if kind == "d2d1-path-geometry" {
		obj.primaryIID = IID_ID2D1PathGeometry
		obj.supportedIIDs[IID_ID2D1PathGeometry] = true
	}
	obj.data = geom
	return obj, nil
}

func (cs *comState) createD2D1GeometrySinkObject(geom *d2d1PathGeometry) (*comObject, error) {
	obj, err := cs.createGuestObject(cs.mem, IID_ID2D1GeometrySink, d2d1GeometrySinkMethods)
	if err != nil {
		return nil, err
	}
	obj.kind = "d2d1-geometry-sink"
	obj.supportedIIDs[IID_ID2D1GeometrySink] = true
	obj.data = &d2d1GeometrySink{geom: geom}
	return obj, nil
}

func (cs *comState) createD2D1SolidColorBrushObject(rtFactory uint64, r, g, b, a, opacity float32) (*comObject, error) {
	obj, err := cs.createGuestObject(cs.mem, IID_ID2D1SolidColorBrush, d2d1SolidColorBrushMethods)
	if err != nil {
		return nil, err
	}
	obj.kind = "d2d1-solid-color-brush"
	obj.supportedIIDs[IID_ID2D1Resource] = true
	obj.supportedIIDs[IID_ID2D1Brush] = true
	obj.supportedIIDs[IID_ID2D1SolidColorBrush] = true
	obj.data = &d2d1SolidColorBrush{
		factoryPtr: rtFactory,
		r:          r,
		g:          g,
		b:          b,
		a:          a,
		opacity:    opacity,
		transform:  d2d1IdentityMatrix(),
	}
	return obj, nil
}

func (cs *comState) createD2D1BitmapObject(factoryPtr uint64, bmp *d2d1Bitmap) (*comObject, error) {
	obj, err := cs.createGuestObject(cs.mem, IID_ID2D1Bitmap, d2d1BitmapMethods)
	if err != nil {
		return nil, err
	}
	obj.kind = "d2d1-bitmap"
	obj.supportedIIDs[IID_ID2D1Resource] = true
	obj.supportedIIDs[IID_ID2D1Bitmap] = true
	bmp.factoryPtr = factoryPtr
	obj.data = bmp
	return obj, nil
}

func (cs *comState) createD2D1RenderTargetObject(kind string, methods int, rt *d2d1RenderTarget) (*comObject, error) {
	obj, err := cs.createGuestObject(cs.mem, IID_ID2D1RenderTarget, methods)
	if err != nil {
		return nil, err
	}
	obj.kind = kind
	obj.supportedIIDs[IID_ID2D1Resource] = true
	obj.supportedIIDs[IID_ID2D1RenderTarget] = true
	switch kind {
	case "d2d1-hwnd-render-target":
		obj.primaryIID = IID_ID2D1HwndRenderTarget
		obj.supportedIIDs[IID_ID2D1HwndRenderTarget] = true
	case "d2d1-dc-render-target":
		obj.primaryIID = IID_ID2D1DCRenderTarget
		obj.supportedIIDs[IID_ID2D1DCRenderTarget] = true
	case "d2d1-bitmap-render-target":
		obj.primaryIID = IID_ID2D1BitmapRenderTarget
		obj.supportedIIDs[IID_ID2D1BitmapRenderTarget] = true
	}
	if rt.transform == [6]float32{} {
		rt.transform = d2d1IdentityMatrix()
	}
	if rt.dpiX == 0 {
		rt.dpiX = 96
	}
	if rt.dpiY == 0 {
		rt.dpiY = 96
	}
	rt.antialiasMode = 0
	rt.textAntialiasMode = 0
	obj.data = rt
	return obj, nil
}

func (cs *comState) createD2D1GradientStops(factoryPtr uint64, stops []d2d1GradientStop, gamma, extendMode uint32) (*comObject, error) {
	obj, err := cs.createGuestObject(cs.mem, IID_IUnknown, d2d1GradientStopsMethods)
	if err != nil {
		return nil, err
	}
	obj.kind = "d2d1-gradient-stops"
	obj.supportedIIDs[IID_ID2D1Resource] = true
	obj.data = &d2d1GradientStopCollection{
		factoryPtr: factoryPtr,
		stops:      stops,
		gamma:      gamma,
		extendMode: extendMode,
	}
	return obj, nil
}

func (cs *comState) createD2D1BitmapBrush(factoryPtr, bitmapPtr uint64) (*comObject, error) {
	obj, err := cs.createGuestObject(cs.mem, IID_IUnknown, d2d1BitmapBrushMethods)
	if err != nil {
		return nil, err
	}
	obj.kind = "d2d1-bitmap-brush"
	obj.supportedIIDs[IID_ID2D1Resource] = true
	obj.supportedIIDs[IID_ID2D1Brush] = true
	obj.data = &d2d1BitmapBrush{
		factoryPtr:    factoryPtr,
		bitmapPtr:     bitmapPtr,
		opacity:       1,
		transform:     d2d1IdentityMatrix(),
		extendModeX:   0,
		extendModeY:   0,
		interpolation: 0,
	}
	return obj, nil
}

func (cs *comState) createD2D1LinearGradientBrush(factoryPtr, gradientPtr uint64, start, end [2]float32, avg [4]float32) (*comObject, error) {
	obj, err := cs.createGuestObject(cs.mem, IID_IUnknown, d2d1LinearGradientMethods)
	if err != nil {
		return nil, err
	}
	obj.kind = "d2d1-linear-gradient-brush"
	obj.supportedIIDs[IID_ID2D1Resource] = true
	obj.supportedIIDs[IID_ID2D1Brush] = true
	obj.data = &d2d1LinearGradientBrush{
		factoryPtr: factoryPtr,
		opacity:    1,
		transform:  d2d1IdentityMatrix(),
		start:      start,
		end:        end,
		gradient:   gradientPtr,
		avg:        avg,
	}
	return obj, nil
}

func (cs *comState) createD2D1RadialGradientBrush(factoryPtr, gradientPtr uint64, center, offset [2]float32, radiusX, radiusY float32, avg [4]float32) (*comObject, error) {
	obj, err := cs.createGuestObject(cs.mem, IID_IUnknown, d2d1RadialGradientMethods)
	if err != nil {
		return nil, err
	}
	obj.kind = "d2d1-radial-gradient-brush"
	obj.supportedIIDs[IID_ID2D1Resource] = true
	obj.supportedIIDs[IID_ID2D1Brush] = true
	obj.data = &d2d1RadialGradientBrush{
		factoryPtr: factoryPtr,
		opacity:    1,
		transform:  d2d1IdentityMatrix(),
		center:     center,
		offset:     offset,
		radiusX:    radiusX,
		radiusY:    radiusY,
		gradient:   gradientPtr,
		avg:        avg,
	}
	return obj, nil
}

func (cs *comState) createD2D1StrokeStyleObject(factoryPtr uint64, style *d2d1StrokeStyle) (*comObject, error) {
	obj, err := cs.createGuestObject(cs.mem, IID_IUnknown, d2d1StrokeStyleMethods)
	if err != nil {
		return nil, err
	}
	obj.kind = "d2d1-stroke-style"
	obj.supportedIIDs[IID_ID2D1Resource] = true
	style.factoryPtr = factoryPtr
	obj.data = style
	return obj, nil
}

func (cs *comState) createD2D1DrawingStateObject(factoryPtr uint64) (*comObject, error) {
	obj, err := cs.createGuestObject(cs.mem, IID_ID2D1DrawingStateBlock, d2d1DrawingStateMethods)
	if err != nil {
		return nil, err
	}
	obj.kind = "d2d1-drawing-state-block"
	obj.supportedIIDs[IID_ID2D1Resource] = true
	obj.supportedIIDs[IID_ID2D1DrawingStateBlock] = true
	obj.data = &d2d1DrawingStateBlock{factoryPtr: factoryPtr, transform: d2d1IdentityMatrix()}
	return obj, nil
}

func (cs *comState) createD2D1LayerObject(factoryPtr uint64, w, h float32) (*comObject, error) {
	obj, err := cs.createGuestObject(cs.mem, IID_IUnknown, d2d1LayerMethods)
	if err != nil {
		return nil, err
	}
	obj.kind = "d2d1-layer"
	obj.supportedIIDs[IID_ID2D1Resource] = true
	obj.data = &d2d1Layer{factoryPtr: factoryPtr, width: w, height: h}
	return obj, nil
}

func (cs *comState) createD2D1MeshObject(factoryPtr uint64) (*comObject, error) {
	obj, err := cs.createGuestObject(cs.mem, IID_IUnknown, d2d1MeshMethods)
	if err != nil {
		return nil, err
	}
	obj.kind = "d2d1-mesh"
	obj.supportedIIDs[IID_ID2D1Resource] = true
	obj.data = &d2d1Mesh{factoryPtr: factoryPtr}
	return obj, nil
}

func d2d1IdentityMatrix() [6]float32 {
	return [6]float32{1, 0, 0, 1, 0, 0}
}

func d2d1ColorToRGB(r, g, b float32) uint32 {
	ri := uint32(r * 255)
	gi := uint32(g * 255)
	bi := uint32(b * 255)
	if ri > 255 {
		ri = 255
	}
	if gi > 255 {
		gi = 255
	}
	if bi > 255 {
		bi = 255
	}
	return ri<<16 | gi<<8 | bi
}

func readD2D1Color(hctx *HandlerCtx, ptr uint64) (r, g, b, a float32) {
	rv, _ := hctx.Mem.Read32(ptr)
	gv, _ := hctx.Mem.Read32(ptr + 4)
	bv, _ := hctx.Mem.Read32(ptr + 8)
	av, _ := hctx.Mem.Read32(ptr + 12)
	r = math.Float32frombits(rv)
	g = math.Float32frombits(gv)
	b = math.Float32frombits(bv)
	a = math.Float32frombits(av)
	return
}

func writeD2D1Color(mem *mmu.MMU, ptr uint64, r, g, b, a float32) {
	if ptr == 0 {
		return
	}
	mem.Write32(ptr+0, math.Float32bits(r))
	mem.Write32(ptr+4, math.Float32bits(g))
	mem.Write32(ptr+8, math.Float32bits(b))
	mem.Write32(ptr+12, math.Float32bits(a))
}

func readD2D1Rect(hctx *HandlerCtx, ptr uint64) d2d1Rect {
	lv, _ := hctx.Mem.Read32(ptr)
	tv, _ := hctx.Mem.Read32(ptr + 4)
	rv, _ := hctx.Mem.Read32(ptr + 8)
	bv, _ := hctx.Mem.Read32(ptr + 12)
	return d2d1Rect{
		left:   math.Float32frombits(lv),
		top:    math.Float32frombits(tv),
		right:  math.Float32frombits(rv),
		bottom: math.Float32frombits(bv),
	}
}

func writeD2D1Rect(mem *mmu.MMU, ptr uint64, rect d2d1Rect) {
	if ptr == 0 {
		return
	}
	mem.Write32(ptr+0, math.Float32bits(rect.left))
	mem.Write32(ptr+4, math.Float32bits(rect.top))
	mem.Write32(ptr+8, math.Float32bits(rect.right))
	mem.Write32(ptr+12, math.Float32bits(rect.bottom))
}

func readD2D1Point(hctx *HandlerCtx, ptr uint64) (x, y float32) {
	xv, _ := hctx.Mem.Read32(ptr)
	yv, _ := hctx.Mem.Read32(ptr + 4)
	return math.Float32frombits(xv), math.Float32frombits(yv)
}

func writeD2D1Point(mem *mmu.MMU, ptr uint64, x, y float32) {
	if ptr == 0 {
		return
	}
	mem.Write32(ptr+0, math.Float32bits(x))
	mem.Write32(ptr+4, math.Float32bits(y))
}

func readPackedD2D1Point(v uint64) (float32, float32) {
	return math.Float32frombits(uint32(v)), math.Float32frombits(uint32(v >> 32))
}

func readD2D1RoundedRect(hctx *HandlerCtx, ptr uint64) d2d1RoundedRect {
	rect := readD2D1Rect(hctx, ptr)
	rx, _ := hctx.Mem.Read32(ptr + 16)
	ry, _ := hctx.Mem.Read32(ptr + 20)
	return d2d1RoundedRect{
		rect:    rect,
		radiusX: math.Float32frombits(rx),
		radiusY: math.Float32frombits(ry),
	}
}

func writeD2D1RoundedRect(mem *mmu.MMU, ptr uint64, rr d2d1RoundedRect) {
	if ptr == 0 {
		return
	}
	writeD2D1Rect(mem, ptr, rr.rect)
	mem.Write32(ptr+16, math.Float32bits(rr.radiusX))
	mem.Write32(ptr+20, math.Float32bits(rr.radiusY))
}

func readD2D1Ellipse(hctx *HandlerCtx, ptr uint64) d2d1Ellipse {
	x, y := readD2D1Point(hctx, ptr)
	rx, _ := hctx.Mem.Read32(ptr + 8)
	ry, _ := hctx.Mem.Read32(ptr + 12)
	return d2d1Ellipse{x: x, y: y, radiusX: math.Float32frombits(rx), radiusY: math.Float32frombits(ry)}
}

func writeD2D1Ellipse(mem *mmu.MMU, ptr uint64, e d2d1Ellipse) {
	if ptr == 0 {
		return
	}
	writeD2D1Point(mem, ptr, e.x, e.y)
	mem.Write32(ptr+8, math.Float32bits(e.radiusX))
	mem.Write32(ptr+12, math.Float32bits(e.radiusY))
}

func readD2D1Matrix(mem *mmu.MMU, ptr uint64) [6]float32 {
	if ptr == 0 {
		return d2d1IdentityMatrix()
	}
	var out [6]float32
	for i := 0; i < 6; i++ {
		v, _ := mem.Read32(ptr + uint64(i*4))
		out[i] = math.Float32frombits(v)
	}
	return out
}

func writeD2D1Matrix(mem *mmu.MMU, ptr uint64, m [6]float32) {
	if ptr == 0 {
		return
	}
	for i := 0; i < 6; i++ {
		mem.Write32(ptr+uint64(i*4), math.Float32bits(m[i]))
	}
}

func readGuestUTF16Len(mem *mmu.MMU, ptr uint64, n int) string {
	if ptr == 0 || n <= 0 {
		return ""
	}
	runes := make([]rune, 0, n)
	for i := 0; i < n; i++ {
		w, err := mem.Read16(ptr + uint64(i*2))
		if err != nil || w == 0 {
			break
		}
		runes = append(runes, rune(w))
	}
	return string(runes)
}

func d2d1Object(hctx *HandlerCtx, ptr uint64) *comObject {
	if hctx == nil || hctx.Com == nil || ptr == 0 {
		return nil
	}
	return hctx.Com.objects[ptr]
}

func d2d1FactoryFromObject(obj *comObject) uint64 {
	if obj == nil {
		return 0
	}
	switch v := obj.data.(type) {
	case *d2d1RenderTarget:
		return v.factoryPtr
	case *d2d1SolidColorBrush:
		return v.factoryPtr
	case *d2d1BitmapBrush:
		return v.factoryPtr
	case *d2d1LinearGradientBrush:
		return v.factoryPtr
	case *d2d1RadialGradientBrush:
		return v.factoryPtr
	case *d2d1GradientStopCollection:
		return v.factoryPtr
	case *d2d1PathGeometry:
		return v.factoryPtr
	case *d2d1Bitmap:
		return v.factoryPtr
	case *d2d1StrokeStyle:
		return v.factoryPtr
	case *d2d1DrawingStateBlock:
		return v.factoryPtr
	case *d2d1Layer:
		return v.factoryPtr
	case *d2d1Mesh:
		return v.factoryPtr
	default:
		return 0
	}
}

func d2d1GetRenderTargetSurface(hctx *HandlerCtx, rt *d2d1RenderTarget) *gdi.Surface {
	if rt == nil {
		return nil
	}
	if rt.offscreen != nil {
		return rt.offscreen
	}
	if rt.hdc != 0 && hctx.GdiMgr != nil {
		dc := hctx.GdiMgr.GetDC(rt.hdc)
		if dc != nil && dc.Target != nil {
			rt.dc = dc
			return dc.Target
		}
	}
	if rt.hwnd != 0 && hctx.GdiMgr != nil && hctx.GdiMgr.Screen != nil {
		return hctx.GdiMgr.Screen
	}
	if hctx.GdiMgr != nil {
		return hctx.GdiMgr.Screen
	}
	return nil
}

func d2d1BrushRGBA(hctx *HandlerCtx, ptr uint64) (float32, float32, float32, float32, float32, bool) {
	obj := d2d1Object(hctx, ptr)
	if obj == nil {
		return 0, 0, 0, 0, 0, false
	}
	switch v := obj.data.(type) {
	case *d2d1SolidColorBrush:
		return v.r, v.g, v.b, v.a, v.opacity, true
	case *d2d1LinearGradientBrush:
		return v.avg[0], v.avg[1], v.avg[2], v.avg[3], v.opacity, true
	case *d2d1RadialGradientBrush:
		return v.avg[0], v.avg[1], v.avg[2], v.avg[3], v.opacity, true
	case *d2d1BitmapBrush:
		return 1, 1, 1, 1, v.opacity, true
	default:
		return 0, 0, 0, 0, 0, false
	}
}

func d2d1BrushColorRef(hctx *HandlerCtx, ptr uint64) (uint32, bool) {
	r, g, b, _, _, ok := d2d1BrushRGBA(hctx, ptr)
	if !ok {
		return 0, false
	}
	return d2d1ColorToRGB(r, g, b), true
}

func d2d1ApplyPoint(m [6]float32, x, y float32) (float32, float32) {
	return m[0]*x + m[2]*y + m[4], m[1]*x + m[3]*y + m[5]
}

func d2d1TransformRect(m [6]float32, r d2d1Rect) d2d1Rect {
	x0, y0 := d2d1ApplyPoint(m, r.left, r.top)
	x1, y1 := d2d1ApplyPoint(m, r.right, r.top)
	x2, y2 := d2d1ApplyPoint(m, r.right, r.bottom)
	x3, y3 := d2d1ApplyPoint(m, r.left, r.bottom)
	minX, maxX := minMax4(x0, x1, x2, x3)
	minY, maxY := minMax4(y0, y1, y2, y3)
	return d2d1Rect{left: minX, top: minY, right: maxX, bottom: maxY}
}

func minMax4(a, b, c, d float32) (float32, float32) {
	minV, maxV := a, a
	for _, v := range []float32{b, c, d} {
		if v < minV {
			minV = v
		}
		if v > maxV {
			maxV = v
		}
	}
	return minV, maxV
}

func d2d1CurrentClip(rt *d2d1RenderTarget, surf *gdi.Surface) (d2d1Rect, bool) {
	if surf == nil {
		return d2d1Rect{}, false
	}
	clip := d2d1Rect{left: 0, top: 0, right: float32(surf.Width), bottom: float32(surf.Height)}
	for _, c := range rt.clipStack {
		if c.left > clip.left {
			clip.left = c.left
		}
		if c.top > clip.top {
			clip.top = c.top
		}
		if c.right < clip.right {
			clip.right = c.right
		}
		if c.bottom < clip.bottom {
			clip.bottom = c.bottom
		}
	}
	return clip, clip.left < clip.right && clip.top < clip.bottom
}

func d2d1NewDC(rt *d2d1RenderTarget, surf *gdi.Surface, color uint32, strokeWidth int32) *gdi.DC {
	if surf == nil {
		return nil
	}
	dc := gdi.NewScreenDC(surf)
	dc.Target = surf
	dc.OriginX = rt.originX
	dc.OriginY = rt.originY
	dc.TextColor = color
	dc.Brush = &gdi.Brush{Style: 0, Color: color}
	dc.Pen = &gdi.Pen{Style: 0, Width: strokeWidth, Color: color}
	if clip, ok := d2d1CurrentClip(rt, surf); ok {
		dc.SetClipRect(
			rt.originX+int32(math.Floor(float64(clip.left))),
			rt.originY+int32(math.Floor(float64(clip.top))),
			rt.originX+int32(math.Ceil(float64(clip.right))),
			rt.originY+int32(math.Ceil(float64(clip.bottom))),
		)
	}
	return dc
}

func d2d1FigurePoints(fig d2d1Figure) [][2]float32 {
	points := [][2]float32{{fig.startX, fig.startY}}
	cur := [2]float32{fig.startX, fig.startY}
	for _, seg := range fig.segments {
		switch seg.kind {
		case d2d1SegmentLine:
			cur = seg.pts[0]
			points = append(points, cur)
		case d2d1SegmentBezier:
			for i := 1; i <= 16; i++ {
				t := float32(i) / 16
				it := 1 - t
				x := it*it*it*cur[0] + 3*it*it*t*seg.pts[0][0] + 3*it*t*t*seg.pts[1][0] + t*t*t*seg.pts[2][0]
				y := it*it*it*cur[1] + 3*it*it*t*seg.pts[0][1] + 3*it*t*t*seg.pts[1][1] + t*t*t*seg.pts[2][1]
				points = append(points, [2]float32{x, y})
			}
			cur = seg.pts[2]
		case d2d1SegmentArc:
			cur = seg.pts[0]
			points = append(points, cur)
		}
	}
	return points
}

func d2d1GeometryPoints(geom *d2d1PathGeometry, transform [6]float32) [][][2]int32 {
	if geom == nil {
		return nil
	}
	var out [][][2]int32
	for _, fig := range geom.figures {
		src := d2d1FigurePoints(fig)
		if len(src) == 0 {
			continue
		}
		dst := make([][2]int32, 0, len(src))
		for _, p := range src {
			x, y := d2d1ApplyPoint(transform, p[0], p[1])
			dst = append(dst, [2]int32{int32(math.Round(float64(x))), int32(math.Round(float64(y)))})
		}
		out = append(out, dst)
	}
	return out
}

func d2d1GeometryBounds(geom *d2d1PathGeometry, transform [6]float32) d2d1Rect {
	points := d2d1GeometryPoints(geom, transform)
	if len(points) == 0 {
		return d2d1Rect{}
	}
	minX, minY := float32(points[0][0][0]), float32(points[0][0][1])
	maxX, maxY := minX, minY
	for _, fig := range points {
		for _, p := range fig {
			x, y := float32(p[0]), float32(p[1])
			if x < minX {
				minX = x
			}
			if y < minY {
				minY = y
			}
			if x > maxX {
				maxX = x
			}
			if y > maxY {
				maxY = y
			}
		}
	}
	return d2d1Rect{left: minX, top: minY, right: maxX, bottom: maxY}
}

func d2d1FillContainsPoint(geom *d2d1PathGeometry, x, y float32, transform [6]float32) bool {
	for _, fig := range d2d1GeometryPoints(geom, transform) {
		if len(fig) < 3 {
			continue
		}
		inside := false
		for i, j := 0, len(fig)-1; i < len(fig); j, i = i, i+1 {
			xi, yi := float32(fig[i][0]), float32(fig[i][1])
			xj, yj := float32(fig[j][0]), float32(fig[j][1])
			intersects := ((yi > y) != (yj > y)) && (x < (xj-xi)*(y-yi)/(yj-yi+0.00001)+xi)
			if intersects {
				inside = !inside
			}
		}
		if inside {
			return true
		}
	}
	return false
}

func d2d1GeometryArea(geom *d2d1PathGeometry, transform [6]float32) float32 {
	var area float32
	for _, fig := range d2d1GeometryPoints(geom, transform) {
		if len(fig) < 3 {
			continue
		}
		var sum float32
		for i := 0; i < len(fig); i++ {
			j := (i + 1) % len(fig)
			sum += float32(fig[i][0])*float32(fig[j][1]) - float32(fig[j][0])*float32(fig[i][1])
		}
		area += float32(math.Abs(float64(sum))) * 0.5
	}
	return area
}

func d2d1GeometryLength(geom *d2d1PathGeometry, transform [6]float32) float32 {
	var length float32
	for _, fig := range d2d1GeometryPoints(geom, transform) {
		for i := 1; i < len(fig); i++ {
			dx := float64(fig[i][0] - fig[i-1][0])
			dy := float64(fig[i][1] - fig[i-1][1])
			length += float32(math.Hypot(dx, dy))
		}
		if len(fig) > 1 {
			dx := float64(fig[0][0] - fig[len(fig)-1][0])
			dy := float64(fig[0][1] - fig[len(fig)-1][1])
			length += float32(math.Hypot(dx, dy))
		}
	}
	return length
}

func d2d1PointAtLength(geom *d2d1PathGeometry, distance float32, transform [6]float32) (float32, float32, float32, float32) {
	for _, fig := range d2d1GeometryPoints(geom, transform) {
		for i := 1; i < len(fig); i++ {
			x0, y0 := float32(fig[i-1][0]), float32(fig[i-1][1])
			x1, y1 := float32(fig[i][0]), float32(fig[i][1])
			segLen := float32(math.Hypot(float64(x1-x0), float64(y1-y0)))
			if distance <= segLen || segLen == 0 {
				t := float32(0)
				if segLen > 0 {
					t = distance / segLen
				}
				px := x0 + (x1-x0)*t
				py := y0 + (y1-y0)*t
				tx, ty := x1-x0, y1-y0
				if segLen > 0 {
					tx /= segLen
					ty /= segLen
				}
				return px, py, tx, ty
			}
			distance -= segLen
		}
	}
	bounds := d2d1GeometryBounds(geom, transform)
	return bounds.right, bounds.bottom, 1, 0
}

func d2d1RasterizeGeometry(hctx *HandlerCtx, rt *d2d1RenderTarget, surf *gdi.Surface, geom *d2d1PathGeometry, brushPtr uint64, fill bool, strokeWidth float32) {
	if surf == nil || geom == nil {
		return
	}
	color, ok := d2d1BrushColorRef(hctx, brushPtr)
	if !ok {
		return
	}
	width := int32(math.Round(float64(strokeWidth)))
	if width <= 0 {
		width = 1
	}
	dc := d2d1NewDC(rt, surf, color, width)
	if dc == nil {
		return
	}
	for idx, fig := range d2d1GeometryPoints(geom, rt.transform) {
		if len(fig) == 0 {
			continue
		}
		if fill {
			if len(fig) >= 3 {
				dc.Polygon(fig)
			}
		} else {
			closed := geom.figures[idx].closed
			dc.PolylinePoints(fig)
			if closed && len(fig) > 1 {
				dc.MoveTo(fig[len(fig)-1][0], fig[len(fig)-1][1])
				dc.LineTo(fig[0][0], fig[0][1])
			}
		}
	}
}

func d2d1AverageGradientColor(obj *comObject) [4]float32 {
	if obj == nil {
		return [4]float32{0, 0, 0, 1}
	}
	gs, _ := obj.data.(*d2d1GradientStopCollection)
	if gs == nil || len(gs.stops) == 0 {
		return [4]float32{0, 0, 0, 1}
	}
	var out [4]float32
	for _, stop := range gs.stops {
		out[0] += stop.color[0]
		out[1] += stop.color[1]
		out[2] += stop.color[2]
		out[3] += stop.color[3]
	}
	scale := float32(1) / float32(len(gs.stops))
	out[0] *= scale
	out[1] *= scale
	out[2] *= scale
	out[3] *= scale
	return out
}

func d2d1ReadWICBitmap(cs *comState, ptr uint64) *wicBitmap {
	if cs == nil {
		return nil
	}
	obj := cs.objects[ptr]
	if obj == nil {
		return nil
	}
	switch v := obj.data.(type) {
	case *wicBitmap:
		return v
	case *wicFormatConverter:
		return d2d1ReadWICBitmap(cs, v.sourcePtr)
	default:
		return nil
	}
}

func d2d1CopyBitmapPixels(src *wicBitmap) (*d2d1Bitmap, bool) {
	if src == nil || src.width <= 0 || src.height <= 0 {
		return nil, false
	}
	stride := uint32(src.width * 4)
	pixels := make([]byte, int(stride)*src.height)
	copy(pixels, src.pixels)
	return &d2d1Bitmap{width: uint32(src.width), height: uint32(src.height), stride: stride, pixels: pixels}, true
}

func d2d1RenderTargetSize(rt *d2d1RenderTarget, surf *gdi.Surface) (uint32, uint32) {
	if rt.width != 0 && rt.height != 0 {
		return rt.width, rt.height
	}
	if surf != nil {
		return uint32(surf.Width), uint32(surf.Height)
	}
	return 0, 0
}

func d2d1BuildRectGeometry(factoryPtr uint64, rect d2d1Rect) *d2d1PathGeometry {
	return &d2d1PathGeometry{
		factoryPtr:   factoryPtr,
		geometryType: d2d1GeomTypeRectangle,
		fillMode:     d2d1FillModeWinding,
		rect:         rect,
		figures: []d2d1Figure{{
			startX: rect.left,
			startY: rect.top,
			closed: true,
			segments: []d2d1Segment{
				{kind: d2d1SegmentLine, pts: [3][2]float32{{rect.right, rect.top}}},
				{kind: d2d1SegmentLine, pts: [3][2]float32{{rect.right, rect.bottom}}},
				{kind: d2d1SegmentLine, pts: [3][2]float32{{rect.left, rect.bottom}}},
			},
		}},
	}
}

func d2d1BuildRoundedGeometry(factoryPtr uint64, rr d2d1RoundedRect) *d2d1PathGeometry {
	const steps = 8
	rect := rr.rect
	rx := rr.radiusX
	ry := rr.radiusY
	if rx <= 0 || ry <= 0 {
		return d2d1BuildRectGeometry(factoryPtr, rect)
	}
	points := make([][2]float32, 0, steps*4+4)
	arc := func(cx, cy, ax, ay, start, end float64) {
		for i := 0; i <= steps; i++ {
			t := start + (end-start)*float64(i)/steps
			points = append(points, [2]float32{
				float32(cx + float64(ax)*math.Cos(t)),
				float32(cy + float64(ay)*math.Sin(t)),
			})
		}
	}
	arc(float64(rect.right-rx), float64(rect.top+ry), float64(rx), float64(ry), -math.Pi/2, 0)
	arc(float64(rect.right-rx), float64(rect.bottom-ry), float64(rx), float64(ry), 0, math.Pi/2)
	arc(float64(rect.left+rx), float64(rect.bottom-ry), float64(rx), float64(ry), math.Pi/2, math.Pi)
	arc(float64(rect.left+rx), float64(rect.top+ry), float64(rx), float64(ry), math.Pi, 3*math.Pi/2)
	fig := d2d1Figure{startX: points[0][0], startY: points[0][1], closed: true}
	for _, p := range points[1:] {
		fig.segments = append(fig.segments, d2d1Segment{kind: d2d1SegmentLine, pts: [3][2]float32{{p[0], p[1]}}})
	}
	return &d2d1PathGeometry{
		factoryPtr:   factoryPtr,
		geometryType: d2d1GeomTypeRoundedRect,
		fillMode:     d2d1FillModeWinding,
		rect:         rect,
		radiusX:      rr.radiusX,
		radiusY:      rr.radiusY,
		figures:      []d2d1Figure{fig},
	}
}

func d2d1BuildEllipseGeometry(factoryPtr uint64, e d2d1Ellipse) *d2d1PathGeometry {
	const steps = 32
	points := make([][2]float32, 0, steps)
	for i := 0; i < steps; i++ {
		a := 2 * math.Pi * float64(i) / steps
		points = append(points, [2]float32{
			e.x + e.radiusX*float32(math.Cos(a)),
			e.y + e.radiusY*float32(math.Sin(a)),
		})
	}
	fig := d2d1Figure{startX: points[0][0], startY: points[0][1], closed: true}
	for _, p := range points[1:] {
		fig.segments = append(fig.segments, d2d1Segment{kind: d2d1SegmentLine, pts: [3][2]float32{{p[0], p[1]}}})
	}
	return &d2d1PathGeometry{
		factoryPtr:   factoryPtr,
		geometryType: d2d1GeomTypeEllipse,
		fillMode:     d2d1FillModeWinding,
		ellipse:      e,
		figures:      []d2d1Figure{fig},
	}
}

func d2d1CloneGeometry(src *d2d1PathGeometry) *d2d1PathGeometry {
	if src == nil {
		return nil
	}
	out := *src
	out.figures = make([]d2d1Figure, len(src.figures))
	for i, fig := range src.figures {
		out.figures[i] = fig
		out.figures[i].segments = append([]d2d1Segment(nil), fig.segments...)
	}
	out.sourceGeometries = append([]uint64(nil), src.sourceGeometries...)
	return &out
}

func d2d1ApplyGeometryTransform(src *d2d1PathGeometry, transform [6]float32) *d2d1PathGeometry {
	out := d2d1CloneGeometry(src)
	if out == nil {
		return nil
	}
	for i := range out.figures {
		x, y := d2d1ApplyPoint(transform, out.figures[i].startX, out.figures[i].startY)
		out.figures[i].startX, out.figures[i].startY = x, y
		for j := range out.figures[i].segments {
			for k := 0; k < 3; k++ {
				x, y := d2d1ApplyPoint(transform, out.figures[i].segments[j].pts[k][0], out.figures[i].segments[j].pts[k][1])
				out.figures[i].segments[j].pts[k][0], out.figures[i].segments[j].pts[k][1] = x, y
			}
		}
	}
	out.rect = d2d1TransformRect(transform, out.rect)
	out.transform = transform
	return out
}

func (cs *comState) dispatchD2D1Factory(ctx *ntapi.TrapContext, obj *comObject, method int) uint32 {
	factory, _ := obj.data.(*d2d1Factory)
	if factory == nil {
		return E_FAIL
	}
	switch method {
	case 3:
		return S_OK
	case 4:
		if p := ctx.Arg(1); p != 0 {
			ctx.Mem.Write32(p, math.Float32bits(factory.dpiX))
		}
		if p := ctx.Arg(2); p != 0 {
			ctx.Mem.Write32(p, math.Float32bits(factory.dpiY))
		}
		return 0
	case 5:
		rectPtr := ctx.Arg(1)
		ppGeom := ctx.Arg(2)
		if rectPtr == 0 || ppGeom == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppGeom, 0)
		geom, err := cs.createD2D1PathGeometryObject("d2d1-rectangle-geometry", d2d1RectangleGeometryMethods, d2d1BuildRectGeometry(obj.objectAddr, readD2D1Rect(cs.hctx, rectPtr)))
		if err != nil {
			return hresultFromError(err)
		}
		ctx.Mem.Write64(ppGeom, geom.objectAddr)
		return S_OK
	case 6:
		rrPtr := ctx.Arg(1)
		ppGeom := ctx.Arg(2)
		if rrPtr == 0 || ppGeom == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppGeom, 0)
		geom, err := cs.createD2D1PathGeometryObject("d2d1-rounded-geometry", d2d1RoundedGeometryMethods, d2d1BuildRoundedGeometry(obj.objectAddr, readD2D1RoundedRect(cs.hctx, rrPtr)))
		if err != nil {
			return hresultFromError(err)
		}
		ctx.Mem.Write64(ppGeom, geom.objectAddr)
		return S_OK
	case 7:
		ellipsePtr := ctx.Arg(1)
		ppGeom := ctx.Arg(2)
		if ellipsePtr == 0 || ppGeom == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppGeom, 0)
		geom, err := cs.createD2D1PathGeometryObject("d2d1-ellipse-geometry", d2d1EllipseGeometryMethods, d2d1BuildEllipseGeometry(obj.objectAddr, readD2D1Ellipse(cs.hctx, ellipsePtr)))
		if err != nil {
			return hresultFromError(err)
		}
		ctx.Mem.Write64(ppGeom, geom.objectAddr)
		return S_OK
	case 8:
		fillMode := int(ctx.Arg(1))
		geomsPtr := ctx.Arg(2)
		count := uint32(ctx.Arg(3))
		ppGeom := ctx.Arg(4)
		if ppGeom == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppGeom, 0)
		group := &d2d1PathGeometry{factoryPtr: obj.objectAddr, geometryType: d2d1GeomTypeGroup, fillMode: fillMode}
		for i := uint32(0); i < count; i++ {
			ptr, _ := ctx.Mem.Read64(geomsPtr + uint64(i)*8)
			group.sourceGeometries = append(group.sourceGeometries, ptr)
			if srcObj := cs.objects[ptr]; srcObj != nil {
				if srcGeom, _ := srcObj.data.(*d2d1PathGeometry); srcGeom != nil {
					group.figures = append(group.figures, d2d1CloneGeometry(srcGeom).figures...)
				}
			}
		}
		geom, err := cs.createD2D1PathGeometryObject("d2d1-geometry-group", d2d1GeometryGroupMethods, group)
		if err != nil {
			return hresultFromError(err)
		}
		ctx.Mem.Write64(ppGeom, geom.objectAddr)
		return S_OK
	case 9:
		srcPtr := ctx.Arg(1)
		matrixPtr := ctx.Arg(2)
		ppGeom := ctx.Arg(3)
		if srcPtr == 0 || ppGeom == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppGeom, 0)
		srcGeom, _ := cs.objectData(srcPtr).(*d2d1PathGeometry)
		if srcGeom == nil {
			return E_INVALIDARG
		}
		matrix := readD2D1Matrix(ctx.Mem, matrixPtr)
		geom := d2d1ApplyGeometryTransform(srcGeom, matrix)
		geom.factoryPtr = obj.objectAddr
		geom.geometryType = d2d1GeomTypeTransform
		geom.sourcePtr = srcPtr
		out, err := cs.createD2D1PathGeometryObject("d2d1-transformed-geometry", d2d1TransformedGeomMethods, geom)
		if err != nil {
			return hresultFromError(err)
		}
		ctx.Mem.Write64(ppGeom, out.objectAddr)
		return S_OK
	case 10:
		ppGeom := ctx.Arg(1)
		if ppGeom == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppGeom, 0)
		geom, err := cs.createD2D1PathGeometryObject("d2d1-path-geometry", d2d1PathGeometryMethods, &d2d1PathGeometry{factoryPtr: obj.objectAddr, geometryType: d2d1GeomTypePath, fillMode: d2d1FillModeWinding})
		if err != nil {
			return hresultFromError(err)
		}
		ctx.Mem.Write64(ppGeom, geom.objectAddr)
		return S_OK
	case 11:
		descPtr := ctx.Arg(1)
		dashesPtr := ctx.Arg(2)
		dashCount := uint32(ctx.Arg(3))
		ppStyle := ctx.Arg(4)
		if ppStyle == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppStyle, 0)
		style := &d2d1StrokeStyle{}
		if descPtr != 0 {
			style.startCap, _ = ctx.Mem.Read32(descPtr + 0)
			style.endCap, _ = ctx.Mem.Read32(descPtr + 4)
			style.dashCap, _ = ctx.Mem.Read32(descPtr + 8)
			style.lineJoin, _ = ctx.Mem.Read32(descPtr + 12)
			if v, _ := ctx.Mem.Read32(descPtr + 16); true {
				style.miterLimit = math.Float32frombits(v)
			}
			if v, _ := ctx.Mem.Read32(descPtr + 20); true {
				style.dashOffset = math.Float32frombits(v)
			}
			style.dashStyle, _ = ctx.Mem.Read32(descPtr + 24)
		}
		for i := uint32(0); i < dashCount; i++ {
			v, _ := ctx.Mem.Read32(dashesPtr + uint64(i*4))
			style.dashes = append(style.dashes, math.Float32frombits(v))
		}
		out, err := cs.createD2D1StrokeStyleObject(obj.objectAddr, style)
		if err != nil {
			return hresultFromError(err)
		}
		ctx.Mem.Write64(ppStyle, out.objectAddr)
		return S_OK
	case 12:
		ppState := ctx.Arg(3)
		if ppState == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppState, 0)
		out, err := cs.createD2D1DrawingStateObject(obj.objectAddr)
		if err != nil {
			return hresultFromError(err)
		}
		if st, _ := out.data.(*d2d1DrawingStateBlock); st != nil {
			st.textRenderingParams = ctx.Arg(2)
		}
		ctx.Mem.Write64(ppState, out.objectAddr)
		return S_OK
	case 13:
		targetPtr := ctx.Arg(1)
		ppRT := ctx.Arg(3)
		if targetPtr == 0 || ppRT == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppRT, 0)
		wic := d2d1ReadWICBitmap(cs, targetPtr)
		if wic == nil {
			return E_INVALIDARG
		}
		rt := &d2d1RenderTarget{
			factoryPtr: obj.objectAddr,
			width:      uint32(wic.width),
			height:     uint32(wic.height),
			dpiX:       96,
			dpiY:       96,
			transform:  d2d1IdentityMatrix(),
			offscreen:  gdi.WrapPix(wic.pixels, int32(wic.width), int32(wic.height), int32(wic.width*4)),
			wicBitmap:  wic,
		}
		out, err := cs.createD2D1RenderTargetObject("d2d1-bitmap-render-target", d2d1BitmapRenderTargetMethods, rt)
		if err != nil {
			return hresultFromError(err)
		}
		ctx.Mem.Write64(ppRT, out.objectAddr)
		return S_OK
	case 14:
		hwndPropsPtr := ctx.Arg(2)
		ppRT := ctx.Arg(3)
		if hwndPropsPtr == 0 || ppRT == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppRT, 0)
		hwnd, _ := ctx.Mem.Read64(hwndPropsPtr + 0)
		w, _ := ctx.Mem.Read32(hwndPropsPtr + 8)
		h, _ := ctx.Mem.Read32(hwndPropsPtr + 12)
		rt := &d2d1RenderTarget{
			factoryPtr: obj.objectAddr,
			hwnd:       hwnd,
			width:      w,
			height:     h,
			dpiX:       96,
			dpiY:       96,
			transform:  d2d1IdentityMatrix(),
		}
		if state := cs.hctx.HwndChildren[hwnd]; state != nil {
			rt.originX = state.x
			rt.originY = state.y
		}
		out, err := cs.createD2D1RenderTargetObject("d2d1-hwnd-render-target", d2d1HwndRenderTargetMethods, rt)
		if err != nil {
			return hresultFromError(err)
		}
		ctx.Mem.Write64(ppRT, out.objectAddr)
		return S_OK
	case 15:
		ppRT := ctx.Arg(3)
		if ppRT != 0 {
			ctx.Mem.Write64(ppRT, 0)
		}
		return E_NOTIMPL
	case 16:
		ppRT := ctx.Arg(2)
		if ppRT == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppRT, 0)
		rt := &d2d1RenderTarget{factoryPtr: obj.objectAddr, dpiX: 96, dpiY: 96, transform: d2d1IdentityMatrix()}
		out, err := cs.createD2D1RenderTargetObject("d2d1-dc-render-target", d2d1DCRenderTargetMethods, rt)
		if err != nil {
			return hresultFromError(err)
		}
		ctx.Mem.Write64(ppRT, out.objectAddr)
		return S_OK
	default:
		return E_NOTIMPL
	}
}

func (cs *comState) dispatchD2D1Resource(ctx *ntapi.TrapContext, obj *comObject, method int) uint32 {
	if method != 3 {
		return E_NOTIMPL
	}
	if pp := ctx.Arg(1); pp != 0 {
		ctx.Mem.Write64(pp, d2d1FactoryFromObject(obj))
	}
	return 0
}

func (cs *comState) dispatchD2D1BrushCommon(ctx *ntapi.TrapContext, obj *comObject, method int) uint32 {
	switch v := obj.data.(type) {
	case *d2d1SolidColorBrush:
		switch method {
		case 3:
			return cs.dispatchD2D1Resource(ctx, obj, method)
		case 4:
			v.opacity = math.Float32frombits(uint32(ctx.Arg(1)))
			return 0
		case 5:
			v.transform = readD2D1Matrix(ctx.Mem, ctx.Arg(1))
			return 0
		case 6:
			ctx.SetReturn(uint64(math.Float32bits(v.opacity)))
			return 0
		case 7:
			writeD2D1Matrix(ctx.Mem, ctx.Arg(1), v.transform)
			return 0
		}
	case *d2d1BitmapBrush:
		switch method {
		case 3:
			return cs.dispatchD2D1Resource(ctx, obj, method)
		case 4:
			v.opacity = math.Float32frombits(uint32(ctx.Arg(1)))
			return 0
		case 5:
			v.transform = readD2D1Matrix(ctx.Mem, ctx.Arg(1))
			return 0
		case 6:
			ctx.SetReturn(uint64(math.Float32bits(v.opacity)))
			return 0
		case 7:
			writeD2D1Matrix(ctx.Mem, ctx.Arg(1), v.transform)
			return 0
		}
	case *d2d1LinearGradientBrush:
		switch method {
		case 3:
			return cs.dispatchD2D1Resource(ctx, obj, method)
		case 4:
			v.opacity = math.Float32frombits(uint32(ctx.Arg(1)))
			return 0
		case 5:
			v.transform = readD2D1Matrix(ctx.Mem, ctx.Arg(1))
			return 0
		case 6:
			ctx.SetReturn(uint64(math.Float32bits(v.opacity)))
			return 0
		case 7:
			writeD2D1Matrix(ctx.Mem, ctx.Arg(1), v.transform)
			return 0
		}
	case *d2d1RadialGradientBrush:
		switch method {
		case 3:
			return cs.dispatchD2D1Resource(ctx, obj, method)
		case 4:
			v.opacity = math.Float32frombits(uint32(ctx.Arg(1)))
			return 0
		case 5:
			v.transform = readD2D1Matrix(ctx.Mem, ctx.Arg(1))
			return 0
		case 6:
			ctx.SetReturn(uint64(math.Float32bits(v.opacity)))
			return 0
		case 7:
			writeD2D1Matrix(ctx.Mem, ctx.Arg(1), v.transform)
			return 0
		}
	}
	return E_NOTIMPL
}

func (cs *comState) dispatchD2D1SolidColorBrush(ctx *ntapi.TrapContext, obj *comObject, method int) uint32 {
	if hr := cs.dispatchD2D1BrushCommon(ctx, obj, method); hr != E_NOTIMPL {
		return hr
	}
	brush, _ := obj.data.(*d2d1SolidColorBrush)
	if brush == nil {
		return E_FAIL
	}
	switch method {
	case 8:
		brush.r, brush.g, brush.b, brush.a = readD2D1Color(cs.hctx, ctx.Arg(1))
		return 0
	case 9:
		writeD2D1Color(ctx.Mem, ctx.Arg(1), brush.r, brush.g, brush.b, brush.a)
		return 0
	default:
		return E_NOTIMPL
	}
}

func (cs *comState) dispatchD2D1BitmapBrush(ctx *ntapi.TrapContext, obj *comObject, method int) uint32 {
	if hr := cs.dispatchD2D1BrushCommon(ctx, obj, method); hr != E_NOTIMPL {
		return hr
	}
	brush, _ := obj.data.(*d2d1BitmapBrush)
	if brush == nil {
		return E_FAIL
	}
	switch method {
	case 8:
		brush.extendModeX = uint32(ctx.Arg(1))
	case 9:
		brush.extendModeY = uint32(ctx.Arg(1))
	case 10:
		brush.interpolation = uint32(ctx.Arg(1))
	case 11:
		brush.bitmapPtr = ctx.Arg(1)
	case 12:
		ctx.SetReturn(uint64(brush.extendModeX))
	case 13:
		ctx.SetReturn(uint64(brush.extendModeY))
	case 14:
		ctx.SetReturn(uint64(brush.interpolation))
	case 15:
		if pp := ctx.Arg(1); pp != 0 {
			ctx.Mem.Write64(pp, brush.bitmapPtr)
		}
	default:
		return E_NOTIMPL
	}
	return 0
}

func (cs *comState) dispatchD2D1GradientStops(ctx *ntapi.TrapContext, obj *comObject, method int) uint32 {
	stops, _ := obj.data.(*d2d1GradientStopCollection)
	if stops == nil {
		return E_FAIL
	}
	switch method {
	case 3:
		return cs.dispatchD2D1Resource(ctx, obj, method)
	case 4:
		ctx.SetReturn(uint64(len(stops.stops)))
		return 0
	case 5:
		base := ctx.Arg(1)
		count := uint32(ctx.Arg(2))
		limit := count
		if limit > uint32(len(stops.stops)) {
			limit = uint32(len(stops.stops))
		}
		for i := uint32(0); i < limit; i++ {
			off := base + uint64(i)*20
			ctx.Mem.Write32(off+0, math.Float32bits(stops.stops[i].position))
			writeD2D1Color(ctx.Mem, off+4, stops.stops[i].color[0], stops.stops[i].color[1], stops.stops[i].color[2], stops.stops[i].color[3])
		}
		return 0
	case 6:
		ctx.SetReturn(uint64(stops.gamma))
		return 0
	case 7:
		ctx.SetReturn(uint64(stops.extendMode))
		return 0
	default:
		return E_NOTIMPL
	}
}

func (cs *comState) dispatchD2D1LinearGradientBrush(ctx *ntapi.TrapContext, obj *comObject, method int) uint32 {
	if hr := cs.dispatchD2D1BrushCommon(ctx, obj, method); hr != E_NOTIMPL {
		return hr
	}
	brush, _ := obj.data.(*d2d1LinearGradientBrush)
	if brush == nil {
		return E_FAIL
	}
	switch method {
	case 8:
		brush.start[0], brush.start[1] = readPackedD2D1Point(ctx.Arg(1))
	case 9:
		brush.end[0], brush.end[1] = readPackedD2D1Point(ctx.Arg(1))
	case 10:
		ctx.SetFloatReturn(float64(brush.start[0]))
		return 0
	case 11:
		ctx.SetFloatReturn(float64(brush.end[0]))
		return 0
	case 12:
		if pp := ctx.Arg(1); pp != 0 {
			ctx.Mem.Write64(pp, brush.gradient)
		}
	default:
		return E_NOTIMPL
	}
	return 0
}

func (cs *comState) dispatchD2D1RadialGradientBrush(ctx *ntapi.TrapContext, obj *comObject, method int) uint32 {
	if hr := cs.dispatchD2D1BrushCommon(ctx, obj, method); hr != E_NOTIMPL {
		return hr
	}
	brush, _ := obj.data.(*d2d1RadialGradientBrush)
	if brush == nil {
		return E_FAIL
	}
	switch method {
	case 8:
		brush.center[0], brush.center[1] = readPackedD2D1Point(ctx.Arg(1))
	case 9:
		brush.offset[0], brush.offset[1] = readPackedD2D1Point(ctx.Arg(1))
	case 10:
		brush.radiusX = math.Float32frombits(uint32(ctx.Arg(1)))
	case 11:
		brush.radiusY = math.Float32frombits(uint32(ctx.Arg(1)))
	case 12:
		ctx.SetFloatReturn(float64(brush.center[0]))
		return 0
	case 13:
		ctx.SetFloatReturn(float64(brush.offset[0]))
		return 0
	case 14:
		ctx.SetFloatReturn(float64(brush.radiusX))
		return 0
	case 15:
		ctx.SetFloatReturn(float64(brush.radiusY))
		return 0
	case 16:
		if pp := ctx.Arg(1); pp != 0 {
			ctx.Mem.Write64(pp, brush.gradient)
		}
	default:
		return E_NOTIMPL
	}
	return 0
}

func (cs *comState) dispatchD2D1Bitmap(ctx *ntapi.TrapContext, obj *comObject, method int) uint32 {
	bmp, _ := obj.data.(*d2d1Bitmap)
	if bmp == nil {
		return E_FAIL
	}
	switch method {
	case 3:
		return cs.dispatchD2D1Resource(ctx, obj, method)
	case 4:
		writeD2D1Point(ctx.Mem, ctx.Arg(1), float32(bmp.width), float32(bmp.height))
		return 0
	case 5:
		if p := ctx.Arg(1); p != 0 {
			ctx.Mem.Write32(p+0, bmp.width)
			ctx.Mem.Write32(p+4, bmp.height)
		}
		return 0
	case 6:
		if p := ctx.Arg(1); p != 0 {
			ctx.Mem.Write32(p+0, 87)
			ctx.Mem.Write32(p+4, 0)
		}
		return 0
	case 7:
		if p := ctx.Arg(1); p != 0 {
			ctx.Mem.Write32(p+0, math.Float32bits(96))
		}
		if p := ctx.Arg(2); p != 0 {
			ctx.Mem.Write32(p+0, math.Float32bits(96))
		}
		return 0
	case 8:
		return S_OK
	case 9:
		dstRect := d2d1Rect{left: 0, top: 0, right: float32(bmp.width), bottom: float32(bmp.height)}
		if rectPtr := ctx.Arg(1); rectPtr != 0 {
			left, _ := ctx.Mem.Read32(rectPtr + 0)
			top, _ := ctx.Mem.Read32(rectPtr + 4)
			right, _ := ctx.Mem.Read32(rectPtr + 8)
			bottom, _ := ctx.Mem.Read32(rectPtr + 12)
			dstRect = d2d1Rect{
				left:   float32(left),
				top:    float32(top),
				right:  float32(right),
				bottom: float32(bottom),
			}
		}
		srcData := ctx.Arg(2)
		pitch := uint32(ctx.Arg(3))
		if pitch == 0 {
			pitch = bmp.stride
		}
		x0 := int(dstRect.left)
		y0 := int(dstRect.top)
		x1 := int(dstRect.right)
		y1 := int(dstRect.bottom)
		if x0 < 0 {
			x0 = 0
		}
		if y0 < 0 {
			y0 = 0
		}
		if x1 > int(bmp.width) {
			x1 = int(bmp.width)
		}
		if y1 > int(bmp.height) {
			y1 = int(bmp.height)
		}
		for y := y0; y < y1; y++ {
			for x := x0; x < x1; x++ {
				for c := 0; c < 4; c++ {
					b, _ := ctx.Mem.Read8(srcData + uint64(y-y0)*uint64(pitch) + uint64(x-x0)*4 + uint64(c))
					bmp.pixels[y*int(bmp.stride)+x*4+c] = b
				}
			}
		}
		return S_OK
	default:
		return E_NOTIMPL
	}
}

func (cs *comState) dispatchD2D1GeometryBase(ctx *ntapi.TrapContext, obj *comObject, method int, geom *d2d1PathGeometry) uint32 {
	if geom == nil {
		return E_FAIL
	}
	switch method {
	case 3:
		return cs.dispatchD2D1Resource(ctx, obj, method)
	case 4:
		writeD2D1Rect(ctx.Mem, ctx.Arg(2), d2d1GeometryBounds(geom, d2d1IdentityMatrix()))
		return S_OK
	case 5:
		bounds := d2d1GeometryBounds(geom, d2d1IdentityMatrix())
		strokeWidth := math.Float32frombits(uint32(ctx.Arg(1))) / 2
		bounds.left -= strokeWidth
		bounds.top -= strokeWidth
		bounds.right += strokeWidth
		bounds.bottom += strokeWidth
		writeD2D1Rect(ctx.Mem, ctx.Arg(5), bounds)
		return S_OK
	case 6:
		x, y := readPackedD2D1Point(ctx.Arg(1))
		strokeWidth := math.Float32frombits(uint32(ctx.Arg(2)))
		bounds := d2d1GeometryBounds(geom, d2d1IdentityMatrix())
		contains := x >= bounds.left-strokeWidth && x <= bounds.right+strokeWidth && y >= bounds.top-strokeWidth && y <= bounds.bottom+strokeWidth
		if p := ctx.Arg(5); p != 0 {
			if contains {
				ctx.Mem.Write32(p, 1)
			} else {
				ctx.Mem.Write32(p, 0)
			}
		}
		return S_OK
	case 7:
		x, y := readPackedD2D1Point(ctx.Arg(1))
		if p := ctx.Arg(4); p != 0 {
			if d2d1FillContainsPoint(geom, x, y, d2d1IdentityMatrix()) {
				ctx.Mem.Write32(p, 1)
			} else {
				ctx.Mem.Write32(p, 0)
			}
		}
		return S_OK
	case 8:
		otherGeom, _ := cs.objectData(ctx.Arg(1)).(*d2d1PathGeometry)
		relation := uint32(1)
		if otherGeom != nil {
			a := d2d1GeometryBounds(geom, d2d1IdentityMatrix())
			b := d2d1GeometryBounds(otherGeom, d2d1IdentityMatrix())
			if a.left <= b.left && a.top <= b.top && a.right >= b.right && a.bottom >= b.bottom {
				relation = 3
			} else if b.left <= a.left && b.top <= a.top && b.right >= a.right && b.bottom >= a.bottom {
				relation = 2
			} else if a.right > b.left && a.left < b.right && a.bottom > b.top && a.top < b.bottom {
				relation = 4
			}
		}
		if p := ctx.Arg(4); p != 0 {
			ctx.Mem.Write32(p, relation)
		}
		return S_OK
	case 9, 12, 17:
		sinkArg := ctx.Arg(4)
		if method == 9 || method == 12 {
			sinkArg = ctx.Arg(3)
		}
		if method == 17 {
			sinkArg = ctx.Arg(5)
		}
		sink, _ := cs.objectData(sinkArg).(*d2d1GeometrySink)
		if sink == nil || sink.geom == nil {
			return E_INVALIDARG
		}
		for _, fig := range geom.figures {
			cloned := fig
			cloned.segments = append([]d2d1Segment(nil), fig.segments...)
			sink.geom.figures = append(sink.geom.figures, cloned)
		}
		return S_OK
	case 10:
		return S_OK
	case 11:
		otherGeom, _ := cs.objectData(ctx.Arg(1)).(*d2d1PathGeometry)
		sink, _ := cs.objectData(ctx.Arg(5)).(*d2d1GeometrySink)
		if sink == nil || sink.geom == nil {
			return E_INVALIDARG
		}
		for _, fig := range geom.figures {
			cloned := fig
			cloned.segments = append([]d2d1Segment(nil), fig.segments...)
			sink.geom.figures = append(sink.geom.figures, cloned)
		}
		if otherGeom != nil {
			for _, fig := range otherGeom.figures {
				cloned := fig
				cloned.segments = append([]d2d1Segment(nil), fig.segments...)
				sink.geom.figures = append(sink.geom.figures, cloned)
			}
		}
		return S_OK
	case 13:
		if p := ctx.Arg(3); p != 0 {
			ctx.Mem.Write32(p, math.Float32bits(d2d1GeometryArea(geom, d2d1IdentityMatrix())))
		}
		return S_OK
	case 14:
		if p := ctx.Arg(3); p != 0 {
			ctx.Mem.Write32(p, math.Float32bits(d2d1GeometryLength(geom, d2d1IdentityMatrix())))
		}
		return S_OK
	case 15:
		length := math.Float32frombits(uint32(ctx.Arg(1)))
		px, py, tx, ty := d2d1PointAtLength(geom, length, d2d1IdentityMatrix())
		writeD2D1Point(ctx.Mem, ctx.Arg(4), px, py)
		writeD2D1Point(ctx.Mem, ctx.Arg(5), tx, ty)
		return S_OK
	case 16:
		return S_OK
	default:
		return E_NOTIMPL
	}
}

func (cs *comState) dispatchD2D1Geometry(ctx *ntapi.TrapContext, obj *comObject, method int) uint32 {
	geom, _ := obj.data.(*d2d1PathGeometry)
	if method <= 17 {
		return cs.dispatchD2D1GeometryBase(ctx, obj, method, geom)
	}
	switch obj.kind {
	case "d2d1-rectangle-geometry":
		if method == 18 {
			writeD2D1Rect(ctx.Mem, ctx.Arg(1), geom.rect)
			return 0
		}
	case "d2d1-rounded-geometry":
		if method == 18 {
			writeD2D1RoundedRect(ctx.Mem, ctx.Arg(1), d2d1RoundedRect{rect: geom.rect, radiusX: geom.radiusX, radiusY: geom.radiusY})
			return 0
		}
	case "d2d1-ellipse-geometry":
		if method == 18 {
			writeD2D1Ellipse(ctx.Mem, ctx.Arg(1), geom.ellipse)
			return 0
		}
	case "d2d1-geometry-group":
		switch method {
		case 18:
			ctx.SetReturn(uint64(geom.fillMode))
			return 0
		case 19:
			ctx.SetReturn(uint64(len(geom.sourceGeometries)))
			return 0
		case 20:
			base := ctx.Arg(1)
			count := uint32(ctx.Arg(2))
			for i := uint32(0); i < count && i < uint32(len(geom.sourceGeometries)); i++ {
				ctx.Mem.Write64(base+uint64(i)*8, geom.sourceGeometries[i])
			}
			return 0
		}
	case "d2d1-transformed-geometry":
		switch method {
		case 18:
			if pp := ctx.Arg(1); pp != 0 {
				ctx.Mem.Write64(pp, geom.sourcePtr)
			}
			return 0
		case 19:
			writeD2D1Matrix(ctx.Mem, ctx.Arg(1), geom.transform)
			return 0
		}
	case "d2d1-path-geometry":
		switch method {
		case 18:
			ppSink := ctx.Arg(1)
			if ppSink == 0 {
				return E_POINTER
			}
			ctx.Mem.Write64(ppSink, 0)
			sink, err := cs.createD2D1GeometrySinkObject(geom)
			if err != nil {
				return hresultFromError(err)
			}
			ctx.Mem.Write64(ppSink, sink.objectAddr)
			return S_OK
		case 19:
			sink, _ := cs.objectData(ctx.Arg(1)).(*d2d1GeometrySink)
			if sink == nil || sink.geom == nil {
				return E_INVALIDARG
			}
			for _, fig := range geom.figures {
				cloned := fig
				cloned.segments = append([]d2d1Segment(nil), fig.segments...)
				sink.geom.figures = append(sink.geom.figures, cloned)
			}
			return S_OK
		case 20:
			var count uint32
			for _, fig := range geom.figures {
				count += uint32(len(fig.segments))
			}
			if p := ctx.Arg(1); p != 0 {
				ctx.Mem.Write32(p, count)
			}
			return S_OK
		case 21:
			if p := ctx.Arg(1); p != 0 {
				ctx.Mem.Write32(p, uint32(len(geom.figures)))
			}
			return S_OK
		}
	}
	return E_NOTIMPL
}

func (cs *comState) dispatchD2D1GeometrySink(ctx *ntapi.TrapContext, obj *comObject, method int) uint32 {
	sink, _ := obj.data.(*d2d1GeometrySink)
	if sink == nil || sink.geom == nil {
		return E_FAIL
	}
	switch method {
	case 3:
		sink.geom.fillMode = int(ctx.Arg(1))
		return 0
	case 4:
		sink.segmentFlags = int(ctx.Arg(1))
		return 0
	case 5:
		x, y := readPackedD2D1Point(ctx.Arg(1))
		fig := d2d1Figure{startX: x, startY: y}
		sink.geom.figures = append(sink.geom.figures, fig)
		sink.current = &sink.geom.figures[len(sink.geom.figures)-1]
		return 0
	case 6:
		if sink.current == nil {
			return E_FAIL
		}
		base := ctx.Arg(1)
		count := uint32(ctx.Arg(2))
		for i := uint32(0); i < count; i++ {
			x, y := readD2D1Point(cs.hctx, base+uint64(i)*8)
			sink.current.segments = append(sink.current.segments, d2d1Segment{kind: d2d1SegmentLine, pts: [3][2]float32{{x, y}}})
		}
		return 0
	case 7:
		if sink.current == nil {
			return E_FAIL
		}
		base := ctx.Arg(1)
		count := uint32(ctx.Arg(2))
		for i := uint32(0); i < count; i++ {
			off := base + uint64(i)*24
			p1x, p1y := readD2D1Point(cs.hctx, off)
			p2x, p2y := readD2D1Point(cs.hctx, off+8)
			p3x, p3y := readD2D1Point(cs.hctx, off+16)
			sink.current.segments = append(sink.current.segments, d2d1Segment{kind: d2d1SegmentBezier, pts: [3][2]float32{{p1x, p1y}, {p2x, p2y}, {p3x, p3y}}})
		}
		return 0
	case 8:
		if sink.current != nil {
			sink.current.closed = ctx.Arg(1) != 0
		}
		sink.current = nil
		return 0
	case 9:
		sink.closed = true
		return S_OK
	case 10:
		if sink.current == nil {
			return E_FAIL
		}
		x, y := readPackedD2D1Point(ctx.Arg(1))
		sink.current.segments = append(sink.current.segments, d2d1Segment{kind: d2d1SegmentLine, pts: [3][2]float32{{x, y}}})
		return 0
	case 11:
		if sink.current == nil {
			return E_FAIL
		}
		p1x, p1y := readD2D1Point(cs.hctx, ctx.Arg(1)+0)
		p2x, p2y := readD2D1Point(cs.hctx, ctx.Arg(1)+8)
		p3x, p3y := readD2D1Point(cs.hctx, ctx.Arg(1)+16)
		sink.current.segments = append(sink.current.segments, d2d1Segment{kind: d2d1SegmentBezier, pts: [3][2]float32{{p1x, p1y}, {p2x, p2y}, {p3x, p3y}}})
		return 0
	case 12:
		if sink.current == nil {
			return E_FAIL
		}
		ex, ey := readD2D1Point(cs.hctx, ctx.Arg(1)+8)
		sink.current.segments = append(sink.current.segments, d2d1Segment{kind: d2d1SegmentLine, pts: [3][2]float32{{ex, ey}}})
		return 0
	case 13:
		if sink.current == nil {
			return E_FAIL
		}
		base := ctx.Arg(1)
		count := uint32(ctx.Arg(2))
		for i := uint32(0); i < count; i++ {
			ex, ey := readD2D1Point(cs.hctx, base+uint64(i)*16+8)
			sink.current.segments = append(sink.current.segments, d2d1Segment{kind: d2d1SegmentLine, pts: [3][2]float32{{ex, ey}}})
		}
		return 0
	case 14:
		if sink.current == nil {
			return E_FAIL
		}
		endX, endY := readD2D1Point(cs.hctx, ctx.Arg(1))
		sizeX, sizeY := readD2D1Point(cs.hctx, ctx.Arg(1)+8)
		sweep, _ := ctx.Mem.Read32(ctx.Arg(1) + 20)
		arcSize, _ := ctx.Mem.Read32(ctx.Arg(1) + 24)
		sink.current.segments = append(sink.current.segments, d2d1Segment{kind: d2d1SegmentArc, pts: [3][2]float32{{endX, endY}, {sizeX, sizeY}, {float32(sweep), float32(arcSize)}}})
		return 0
	default:
		return E_NOTIMPL
	}
}

func d2d1TextFont(format *dwriteTextFormat) *gdi.Font {
	font := &gdi.Font{
		Height:   -12,
		Weight:   400,
		FaceName: "System",
		FaceID:   -1,
	}
	if format != nil {
		if format.fontFamily != "" {
			font.FaceName = format.fontFamily
		}
		if format.fontSize > 0 {
			font.Height = -int32(math.Round(format.fontSize))
		}
		font.Weight = int32(format.fontWeight)
		font.Italic = format.fontStyle != dwriteFontStyleNormal
		font.FaceID = gdi.ResolveFontFaceStyle(font.FaceName, font.Weight >= 700, font.Italic)
	}
	if font.FaceID >= 0 {
		pix := font.Height
		if pix < 0 {
			pix = -pix
		}
		if pix == 0 {
			pix = 12
		}
		cellH, asc, desc, aveW := gdi.FaceMetrics(font.FaceID, pix)
		font.CellHeight = cellH
		font.Ascent = asc
		font.Descent = desc
		font.AveCharWidth = aveW
		font.MaxCharWidth = aveW * 2
	} else {
		font.CellHeight = 16
		font.Ascent = 12
		font.Descent = 4
		font.AveCharWidth = 8
		font.MaxCharWidth = 16
	}
	return font
}

func (cs *comState) dispatchD2D1RenderTarget(ctx *ntapi.TrapContext, obj *comObject, method int) uint32 {
	rt, _ := obj.data.(*d2d1RenderTarget)
	if rt == nil {
		return E_FAIL
	}
	if method == 3 {
		return cs.dispatchD2D1Resource(ctx, obj, method)
	}
	surf := d2d1GetRenderTargetSurface(cs.hctx, rt)
	if rt.hwnd != 0 {
		if state := cs.hctx.HwndChildren[rt.hwnd]; state != nil {
			rt.originX = state.x
			rt.originY = state.y
		}
	}
	switch method {
	case 4:
		size := ctx.Arg(1)
		srcData := ctx.Arg(2)
		pitch := uint32(ctx.Arg(3))
		ppBitmap := ctx.Arg(5)
		if ppBitmap == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppBitmap, 0)
		w := uint32(size)
		h := uint32(size >> 32)
		if pitch == 0 {
			pitch = w * 4
		}
		pixels := make([]byte, int(pitch)*int(h))
		if srcData != 0 {
			for i := range pixels {
				b, _ := ctx.Mem.Read8(srcData + uint64(i))
				pixels[i] = b
			}
		}
		out, err := cs.createD2D1BitmapObject(rt.factoryPtr, &d2d1Bitmap{width: w, height: h, stride: pitch, pixels: pixels})
		if err != nil {
			return hresultFromError(err)
		}
		ctx.Mem.Write64(ppBitmap, out.objectAddr)
		return S_OK
	case 5:
		ppBitmap := ctx.Arg(3)
		if ppBitmap == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppBitmap, 0)
		wic := d2d1ReadWICBitmap(cs, ctx.Arg(1))
		bmp, ok := d2d1CopyBitmapPixels(wic)
		if !ok {
			return E_INVALIDARG
		}
		out, err := cs.createD2D1BitmapObject(rt.factoryPtr, bmp)
		if err != nil {
			return hresultFromError(err)
		}
		ctx.Mem.Write64(ppBitmap, out.objectAddr)
		return S_OK
	case 6:
		ppBitmap := ctx.Arg(4)
		if ppBitmap == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppBitmap, 0)
		if bmpObj := cs.objects[ctx.Arg(2)]; bmpObj != nil && bmpObj.kind == "d2d1-bitmap" {
			cs.addRef(bmpObj)
			ctx.Mem.Write64(ppBitmap, bmpObj.objectAddr)
			return S_OK
		}
		return E_INVALIDARG
	case 7:
		ppBrush := ctx.Arg(4)
		if ppBrush == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppBrush, 0)
		out, err := cs.createD2D1BitmapBrush(rt.factoryPtr, ctx.Arg(1))
		if err != nil {
			return hresultFromError(err)
		}
		if brushProps := ctx.Arg(3); brushProps != 0 {
			if brush, _ := out.data.(*d2d1BitmapBrush); brush != nil {
				brush.opacity = math.Float32frombits(func() uint32 { v, _ := ctx.Mem.Read32(brushProps + 0); return v }())
				brush.transform = readD2D1Matrix(ctx.Mem, brushProps+4)
			}
		}
		ctx.Mem.Write64(ppBrush, out.objectAddr)
		return S_OK
	case 8:
		colorPtr := ctx.Arg(1)
		ppBrush := ctx.Arg(3)
		if ppBrush == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppBrush, 0)
		r, g, b, a := float32(0), float32(0), float32(0), float32(1)
		if colorPtr != 0 {
			r, g, b, a = readD2D1Color(cs.hctx, colorPtr)
		}
		opacity := float32(1)
		if brushProps := ctx.Arg(2); brushProps != 0 {
			v, _ := ctx.Mem.Read32(brushProps + 0)
			opacity = math.Float32frombits(v)
		}
		out, err := cs.createD2D1SolidColorBrushObject(rt.factoryPtr, r, g, b, a, opacity)
		if err != nil {
			return hresultFromError(err)
		}
		if brushProps := ctx.Arg(2); brushProps != 0 {
			if brush, _ := out.data.(*d2d1SolidColorBrush); brush != nil {
				brush.transform = readD2D1Matrix(ctx.Mem, brushProps+4)
			}
		}
		ctx.Mem.Write64(ppBrush, out.objectAddr)
		return S_OK
	case 9:
		ppStops := ctx.Arg(5)
		if ppStops == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppStops, 0)
		base := ctx.Arg(1)
		count := uint32(ctx.Arg(2))
		stops := make([]d2d1GradientStop, 0, count)
		for i := uint32(0); i < count; i++ {
			off := base + uint64(i)*20
			p, _ := ctx.Mem.Read32(off + 0)
			r, g, b, a := readD2D1Color(cs.hctx, off+4)
			stops = append(stops, d2d1GradientStop{position: math.Float32frombits(p), color: [4]float32{r, g, b, a}})
		}
		out, err := cs.createD2D1GradientStops(rt.factoryPtr, stops, uint32(ctx.Arg(3)), uint32(ctx.Arg(4)))
		if err != nil {
			return hresultFromError(err)
		}
		ctx.Mem.Write64(ppStops, out.objectAddr)
		return S_OK
	case 10:
		ppBrush := ctx.Arg(4)
		if ppBrush == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppBrush, 0)
		var start, end [2]float32
		if p := ctx.Arg(1); p != 0 {
			start[0], start[1] = readD2D1Point(cs.hctx, p)
			end[0], end[1] = readD2D1Point(cs.hctx, p+8)
		}
		avg := d2d1AverageGradientColor(cs.objects[ctx.Arg(3)])
		out, err := cs.createD2D1LinearGradientBrush(rt.factoryPtr, ctx.Arg(3), start, end, avg)
		if err != nil {
			return hresultFromError(err)
		}
		if brushProps := ctx.Arg(2); brushProps != 0 {
			if brush, _ := out.data.(*d2d1LinearGradientBrush); brush != nil {
				v, _ := ctx.Mem.Read32(brushProps)
				brush.opacity = math.Float32frombits(v)
				brush.transform = readD2D1Matrix(ctx.Mem, brushProps+4)
			}
		}
		ctx.Mem.Write64(ppBrush, out.objectAddr)
		return S_OK
	case 11:
		ppBrush := ctx.Arg(4)
		if ppBrush == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppBrush, 0)
		var center, offset [2]float32
		rx, ry := float32(0), float32(0)
		if p := ctx.Arg(1); p != 0 {
			center[0], center[1] = readD2D1Point(cs.hctx, p)
			offset[0], offset[1] = readD2D1Point(cs.hctx, p+8)
			vx, _ := ctx.Mem.Read32(p + 16)
			vy, _ := ctx.Mem.Read32(p + 20)
			rx, ry = math.Float32frombits(vx), math.Float32frombits(vy)
		}
		avg := d2d1AverageGradientColor(cs.objects[ctx.Arg(3)])
		out, err := cs.createD2D1RadialGradientBrush(rt.factoryPtr, ctx.Arg(3), center, offset, rx, ry, avg)
		if err != nil {
			return hresultFromError(err)
		}
		if brushProps := ctx.Arg(2); brushProps != 0 {
			if brush, _ := out.data.(*d2d1RadialGradientBrush); brush != nil {
				v, _ := ctx.Mem.Read32(brushProps)
				brush.opacity = math.Float32frombits(v)
				brush.transform = readD2D1Matrix(ctx.Mem, brushProps+4)
			}
		}
		ctx.Mem.Write64(ppBrush, out.objectAddr)
		return S_OK
	case 12:
		ppRT := ctx.Arg(5)
		if ppRT == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppRT, 0)
		var w, h uint32
		if p := ctx.Arg(2); p != 0 {
			w, _ = ctx.Mem.Read32(p)
			h, _ = ctx.Mem.Read32(p + 4)
		}
		if w == 0 || h == 0 {
			w, h = d2d1RenderTargetSize(rt, surf)
		}
		compat := &d2d1RenderTarget{
			factoryPtr: rt.factoryPtr,
			width:      w,
			height:     h,
			dpiX:       rt.dpiX,
			dpiY:       rt.dpiY,
			transform:  d2d1IdentityMatrix(),
			offscreen:  gdi.NewSurface(int32(w), int32(h)),
		}
		out, err := cs.createD2D1RenderTargetObject("d2d1-bitmap-render-target", d2d1BitmapRenderTargetMethods, compat)
		if err != nil {
			return hresultFromError(err)
		}
		ctx.Mem.Write64(ppRT, out.objectAddr)
		return S_OK
	case 13:
		ppLayer := ctx.Arg(2)
		if ppLayer == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppLayer, 0)
		w, h := float32(0), float32(0)
		if p := ctx.Arg(1); p != 0 {
			w, h = readD2D1Point(cs.hctx, p)
		}
		out, err := cs.createD2D1LayerObject(rt.factoryPtr, w, h)
		if err != nil {
			return hresultFromError(err)
		}
		ctx.Mem.Write64(ppLayer, out.objectAddr)
		return S_OK
	case 14:
		ppMesh := ctx.Arg(1)
		if ppMesh == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppMesh, 0)
		out, err := cs.createD2D1MeshObject(rt.factoryPtr)
		if err != nil {
			return hresultFromError(err)
		}
		ctx.Mem.Write64(ppMesh, out.objectAddr)
		return S_OK
	case 15:
		color, ok := d2d1BrushColorRef(cs.hctx, ctx.Arg(3))
		if !ok || surf == nil {
			return 0
		}
		x0, y0 := readPackedD2D1Point(ctx.Arg(1))
		x1, y1 := readPackedD2D1Point(ctx.Arg(2))
		x0, y0 = d2d1ApplyPoint(rt.transform, x0, y0)
		x1, y1 = d2d1ApplyPoint(rt.transform, x1, y1)
		dc := d2d1NewDC(rt, surf, color, int32(math.Round(float64(math.Float32frombits(uint32(ctx.Arg(4)))))))
		if dc != nil {
			dc.MoveTo(int32(math.Round(float64(x0))), int32(math.Round(float64(y0))))
			dc.LineTo(int32(math.Round(float64(x1))), int32(math.Round(float64(y1))))
		}
		return 0
	case 16:
		rect := d2d1TransformRect(rt.transform, readD2D1Rect(cs.hctx, ctx.Arg(1)))
		color, ok := d2d1BrushColorRef(cs.hctx, ctx.Arg(2))
		if !ok || surf == nil {
			return 0
		}
		dc := d2d1NewDC(rt, surf, color, int32(math.Round(float64(math.Float32frombits(uint32(ctx.Arg(3)))))))
		if dc != nil {
			dc.Rectangle(int32(rect.left), int32(rect.top), int32(rect.right), int32(rect.bottom))
		}
		return 0
	case 17:
		rect := d2d1TransformRect(rt.transform, readD2D1Rect(cs.hctx, ctx.Arg(1)))
		color, ok := d2d1BrushColorRef(cs.hctx, ctx.Arg(2))
		if !ok || surf == nil {
			return 0
		}
		dc := d2d1NewDC(rt, surf, color, 1)
		if dc != nil {
			dc.FillRect(int32(rect.left), int32(rect.top), int32(rect.right), int32(rect.bottom), color)
		}
		return 0
	case 18:
		rr := readD2D1RoundedRect(cs.hctx, ctx.Arg(1))
		rect := d2d1TransformRect(rt.transform, rr.rect)
		color, ok := d2d1BrushColorRef(cs.hctx, ctx.Arg(2))
		if !ok || surf == nil {
			return 0
		}
		dc := d2d1NewDC(rt, surf, color, int32(math.Round(float64(math.Float32frombits(uint32(ctx.Arg(3)))))))
		if dc != nil {
			dc.RoundRect(int32(rect.left), int32(rect.top), int32(rect.right), int32(rect.bottom), int32(rr.radiusX*2), int32(rr.radiusY*2))
		}
		return 0
	case 19:
		rr := readD2D1RoundedRect(cs.hctx, ctx.Arg(1))
		rect := d2d1TransformRect(rt.transform, rr.rect)
		color, ok := d2d1BrushColorRef(cs.hctx, ctx.Arg(2))
		if !ok || surf == nil {
			return 0
		}
		dc := d2d1NewDC(rt, surf, color, 1)
		if dc != nil {
			dc.RoundRect(int32(rect.left), int32(rect.top), int32(rect.right), int32(rect.bottom), int32(rr.radiusX*2), int32(rr.radiusY*2))
		}
		return 0
	case 20:
		e := readD2D1Ellipse(cs.hctx, ctx.Arg(1))
		cx, cy := d2d1ApplyPoint(rt.transform, e.x, e.y)
		color, ok := d2d1BrushColorRef(cs.hctx, ctx.Arg(2))
		if !ok || surf == nil {
			return 0
		}
		dc := d2d1NewDC(rt, surf, color, int32(math.Round(float64(math.Float32frombits(uint32(ctx.Arg(3)))))))
		if dc != nil {
			dc.Ellipse(int32(cx-e.radiusX), int32(cy-e.radiusY), int32(cx+e.radiusX), int32(cy+e.radiusY))
		}
		return 0
	case 21:
		e := readD2D1Ellipse(cs.hctx, ctx.Arg(1))
		cx, cy := d2d1ApplyPoint(rt.transform, e.x, e.y)
		color, ok := d2d1BrushColorRef(cs.hctx, ctx.Arg(2))
		if !ok || surf == nil {
			return 0
		}
		dc := d2d1NewDC(rt, surf, color, 1)
		if dc != nil {
			dc.Ellipse(int32(cx-e.radiusX), int32(cy-e.radiusY), int32(cx+e.radiusX), int32(cy+e.radiusY))
		}
		return 0
	case 22:
		geom, _ := cs.objectData(ctx.Arg(1)).(*d2d1PathGeometry)
		if geom != nil {
			d2d1RasterizeGeometry(cs.hctx, rt, surf, geom, ctx.Arg(2), false, math.Float32frombits(uint32(ctx.Arg(3))))
		}
		return 0
	case 23:
		geom, _ := cs.objectData(ctx.Arg(1)).(*d2d1PathGeometry)
		if geom != nil {
			d2d1RasterizeGeometry(cs.hctx, rt, surf, geom, ctx.Arg(2), true, 1)
		}
		return 0
	case 24, 25:
		return 0
	case 26:
		bmp, _ := cs.objectData(ctx.Arg(1)).(*d2d1Bitmap)
		if bmp == nil || surf == nil {
			return 0
		}
		dst := d2d1Rect{left: 0, top: 0, right: float32(bmp.width), bottom: float32(bmp.height)}
		if p := ctx.Arg(2); p != 0 {
			dst = readD2D1Rect(cs.hctx, p)
		}
		src := d2d1Rect{left: 0, top: 0, right: float32(bmp.width), bottom: float32(bmp.height)}
		if p := ctx.Arg(5); p != 0 {
			src = readD2D1Rect(cs.hctx, p)
		}
		dst = d2d1TransformRect(rt.transform, dst)
		srcSurf := gdi.WrapPix(bmp.pixels, int32(bmp.width), int32(bmp.height), int32(bmp.stride))
		dx0, dy0 := int32(dst.left), int32(dst.top)
		dw := int32(dst.right - dst.left)
		dh := int32(dst.bottom - dst.top)
		sx0, sy0 := int32(src.left), int32(src.top)
		sw := int32(src.right - src.left)
		sh := int32(src.bottom - src.top)
		if dw <= 0 || dh <= 0 || sw <= 0 || sh <= 0 {
			return 0
		}
		if clip, ok := d2d1CurrentClip(rt, surf); ok {
			if float32(dx0) < clip.left {
				sx0 += int32(clip.left) - dx0
				sw -= int32(clip.left) - dx0
				dw -= int32(clip.left) - dx0
				dx0 = int32(clip.left)
			}
			if float32(dy0) < clip.top {
				sy0 += int32(clip.top) - dy0
				sh -= int32(clip.top) - dy0
				dh -= int32(clip.top) - dy0
				dy0 = int32(clip.top)
			}
		}
		if dw == sw && dh == sh {
			surf.BitBlt(dx0, dy0, srcSurf, sx0, sy0, dw, dh)
		} else {
			surf.StretchBlt(dx0, dy0, dw, dh, srcSurf, sx0, sy0, sw, sh)
		}
		return 0
	case 27:
		formatObj := dwriteLookupObject(ctx.Arg(3))
		format, _ := formatObj.data.(*dwriteTextFormat)
		text := readGuestUTF16Len(ctx.Mem, ctx.Arg(1), int(ctx.Arg(2)))
		rect := readD2D1Rect(cs.hctx, ctx.Arg(4))
		rect = d2d1TransformRect(rt.transform, rect)
		color, ok := d2d1BrushColorRef(cs.hctx, ctx.Arg(5))
		if !ok || surf == nil {
			return 0
		}
		dc := d2d1NewDC(rt, surf, color, 1)
		if dc != nil {
			dc.Font = d2d1TextFont(format)
			lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
			lineH := dc.Font.CellHeight
			if lineH <= 0 {
				lineH = 16
			}
			y := int32(rect.top)
			for _, line := range lines {
				dc.TextOut(int32(rect.left), y, line, false)
				y += lineH
			}
		}
		return 0
	case 28:
		layoutObj := dwriteLookupObject(ctx.Arg(2))
		layout, _ := layoutObj.data.(*dwriteTextLayout)
		color, ok := d2d1BrushColorRef(cs.hctx, ctx.Arg(3))
		if !ok || surf == nil || layout == nil {
			return 0
		}
		ox, oy := readPackedD2D1Point(ctx.Arg(1))
		ox, oy = d2d1ApplyPoint(rt.transform, ox, oy)
		dc := d2d1NewDC(rt, surf, color, 1)
		if dc != nil {
			dc.Font = d2d1TextFont(&layout.dwriteTextFormat)
			lines := strings.Split(strings.ReplaceAll(string(layout.text), "\r\n", "\n"), "\n")
			lineH := dc.Font.CellHeight
			if lineH <= 0 {
				lineH = 16
			}
			y := int32(oy)
			for _, line := range lines {
				dc.TextOut(int32(ox), y, line, false)
				y += lineH
			}
		}
		return 0
	case 29:
		glyphRunPtr := ctx.Arg(2)
		color, ok := d2d1BrushColorRef(cs.hctx, ctx.Arg(3))
		if glyphRunPtr == 0 || !ok || surf == nil {
			return 0
		}
		fontFacePtr, _ := ctx.Mem.Read64(glyphRunPtr)
		fontSizeBits, _ := ctx.Mem.Read32(glyphRunPtr + 8)
		glyphCount, _ := ctx.Mem.Read32(glyphRunPtr + 12)
		glyphIndicesPtr, _ := ctx.Mem.Read64(glyphRunPtr + 16)
		glyphAdvancesPtr, _ := ctx.Mem.Read64(glyphRunPtr + 24)
		glyphOffsetsPtr, _ := ctx.Mem.Read64(glyphRunPtr + 32)
		if glyphIndicesPtr == 0 || glyphCount == 0 {
			return 0
		}
		fontSize := float64(math.Float32frombits(fontSizeBits))
		if fontSize <= 0 {
			fontSize = 12
		}
		format := &dwriteTextFormat{fontFamily: "Segoe UI", fontSize: fontSize, fontWeight: dwriteFontWeightNormal}
		if faceObj := dwriteLookupObject(fontFacePtr); faceObj != nil {
			if face, faceOK := faceObj.data.(*dwriteFontFace); faceOK && face != nil {
				format.fontFamily = dwriteFamilyOrDefault(face.familyName)
				format.fontWeight = face.weight
				format.fontStyle = face.style
			}
		}
		dc := d2d1NewDC(rt, surf, color, 1)
		if dc == nil {
			return 0
		}
		dc.Font = d2d1TextFont(format)
		baselineX, baselineY := readPackedD2D1Point(ctx.Arg(1))
		baselineX, baselineY = d2d1ApplyPoint(rt.transform, baselineX, baselineY)
		penX := baselineX
		for i := uint32(0); i < glyphCount; i++ {
			glyph, _ := ctx.Mem.Read16(glyphIndicesPtr + uint64(i)*2)
			r := rune(glyph)
			if r == 0 {
				r = '?'
			}
			advanceOffset, ascenderOffset := float32(0), float32(0)
			if glyphOffsetsPtr != 0 {
				advanceBits, _ := ctx.Mem.Read32(glyphOffsetsPtr + uint64(i)*8)
				ascenderBits, _ := ctx.Mem.Read32(glyphOffsetsPtr + uint64(i)*8 + 4)
				advanceOffset = math.Float32frombits(advanceBits)
				ascenderOffset = math.Float32frombits(ascenderBits)
			}
			dc.TextOut(int32(math.Round(float64(penX+advanceOffset))), int32(math.Round(float64(baselineY-float32(dc.Font.Ascent)-ascenderOffset))), string(r), false)
			advance := float32(dc.Font.AveCharWidth)
			if glyphAdvancesPtr != 0 {
				advanceBits, _ := ctx.Mem.Read32(glyphAdvancesPtr + uint64(i)*4)
				advance = math.Float32frombits(advanceBits)
			}
			penX += advance
		}
		return 0
	case 30:
		rt.transform = readD2D1Matrix(ctx.Mem, ctx.Arg(1))
		return 0
	case 31:
		writeD2D1Matrix(ctx.Mem, ctx.Arg(1), rt.transform)
		return 0
	case 32:
		rt.antialiasMode = uint32(ctx.Arg(1))
		return 0
	case 33:
		ctx.SetReturn(uint64(rt.antialiasMode))
		return 0
	case 34:
		rt.textAntialiasMode = uint32(ctx.Arg(1))
		return 0
	case 35:
		ctx.SetReturn(uint64(rt.textAntialiasMode))
		return 0
	case 36:
		rt.textRenderingParams = ctx.Arg(1)
		return 0
	case 37:
		if pp := ctx.Arg(1); pp != 0 {
			ctx.Mem.Write64(pp, rt.textRenderingParams)
		}
		return 0
	case 38:
		rt.tags[0], rt.tags[1] = ctx.Arg(1), ctx.Arg(2)
		return 0
	case 39:
		if p := ctx.Arg(1); p != 0 {
			ctx.Mem.Write64(p, rt.tags[0])
		}
		if p := ctx.Arg(2); p != 0 {
			ctx.Mem.Write64(p, rt.tags[1])
		}
		return 0
	case 40:
		if p := ctx.Arg(1); p != 0 {
			rt.clipStack = append(rt.clipStack, readD2D1Rect(cs.hctx, p))
		}
		return 0
	case 41:
		if n := len(rt.clipStack); n > 0 {
			rt.clipStack = rt.clipStack[:n-1]
		}
		return 0
	case 42:
		if p := ctx.Arg(1); p != 0 {
			ctx.Mem.Write64(p, rt.tags[0])
		}
		if p := ctx.Arg(2); p != 0 {
			ctx.Mem.Write64(p, rt.tags[1])
		}
		return S_OK
	case 43:
		state, _ := cs.objectData(ctx.Arg(1)).(*d2d1DrawingStateBlock)
		if state == nil {
			return E_INVALIDARG
		}
		state.transform = rt.transform
		state.antialiasMode = rt.antialiasMode
		state.textAntialiasMode = rt.textAntialiasMode
		state.tags = rt.tags
		state.textRenderingParams = rt.textRenderingParams
		return 0
	case 44:
		state, _ := cs.objectData(ctx.Arg(1)).(*d2d1DrawingStateBlock)
		if state == nil {
			return E_INVALIDARG
		}
		rt.transform = state.transform
		rt.antialiasMode = state.antialiasMode
		rt.textAntialiasMode = state.textAntialiasMode
		rt.tags = state.tags
		rt.textRenderingParams = state.textRenderingParams
		return 0
	case 45:
		if p := ctx.Arg(1); p != 0 {
			rt.clipStack = append(rt.clipStack, readD2D1Rect(cs.hctx, p))
		}
		return 0
	case 46:
		if n := len(rt.clipStack); n > 0 {
			rt.clipStack = rt.clipStack[:n-1]
		}
		return 0
	case 47:
		color := uint32(0)
		if p := ctx.Arg(1); p != 0 {
			r, g, b, _ := readD2D1Color(cs.hctx, p)
			color = d2d1ColorToRGB(r, g, b)
		}
		if surf != nil {
			w, h := d2d1RenderTargetSize(rt, surf)
			surf.FillRect(rt.originX, rt.originY, rt.originX+int32(w), rt.originY+int32(h), color)
		}
		return 0
	case 48:
		rt.isDrawing = true
		return 0
	case 49:
		rt.isDrawing = false
		if p := ctx.Arg(1); p != 0 {
			ctx.Mem.Write64(p, rt.tags[0])
		}
		if p := ctx.Arg(2); p != 0 {
			ctx.Mem.Write64(p, rt.tags[1])
		}
		if rt.hwnd != 0 && cs.hctx.WlWindow != nil {
			cs.hctx.WlWindow.Commit()
		}
		return S_OK
	case 50:
		if p := ctx.Arg(1); p != 0 {
			ctx.Mem.Write32(p+0, 87)
			ctx.Mem.Write32(p+4, 0)
		}
		return 0
	case 51:
		rt.dpiX = math.Float32frombits(uint32(ctx.Arg(1)))
		rt.dpiY = math.Float32frombits(uint32(ctx.Arg(2)))
		return 0
	case 52:
		if p := ctx.Arg(1); p != 0 {
			ctx.Mem.Write32(p, math.Float32bits(rt.dpiX))
		}
		if p := ctx.Arg(2); p != 0 {
			ctx.Mem.Write32(p, math.Float32bits(rt.dpiY))
		}
		return 0
	case 53:
		w, h := d2d1RenderTargetSize(rt, surf)
		if p := ctx.Arg(1); p != 0 {
			ctx.Mem.Write32(p+0, math.Float32bits(float32(w)))
			ctx.Mem.Write32(p+4, math.Float32bits(float32(h)))
		}
		return 0
	case 54:
		w, h := d2d1RenderTargetSize(rt, surf)
		if p := ctx.Arg(1); p != 0 {
			ctx.Mem.Write32(p+0, w)
			ctx.Mem.Write32(p+4, h)
		}
		return 0
	case 55:
		ctx.SetReturn(16384)
		return 0
	case 56:
		ctx.SetReturn(1)
		return 0
	case 57:
		switch obj.kind {
		case "d2d1-bitmap-render-target":
			ppBitmap := ctx.Arg(1)
			if ppBitmap == 0 {
				return E_POINTER
			}
			ctx.Mem.Write64(ppBitmap, 0)
			if surf == nil {
				return E_FAIL
			}
			pixels := append([]byte(nil), surf.Pix...)
			out, err := cs.createD2D1BitmapObject(rt.factoryPtr, &d2d1Bitmap{width: uint32(surf.Width), height: uint32(surf.Height), stride: uint32(surf.Stride), pixels: pixels})
			if err != nil {
				return hresultFromError(err)
			}
			ctx.Mem.Write64(ppBitmap, out.objectAddr)
			return S_OK
		case "d2d1-hwnd-render-target":
			ctx.SetReturn(0)
			return 0
		case "d2d1-dc-render-target":
			rt.hdc = ctx.Arg(1)
			rt.dc = cs.hctx.GdiMgr.GetDC(rt.hdc)
			if rectPtr := ctx.Arg(2); rectPtr != 0 {
				left, _ := ctx.Mem.Read32(rectPtr + 0)
				top, _ := ctx.Mem.Read32(rectPtr + 4)
				right, _ := ctx.Mem.Read32(rectPtr + 8)
				bottom, _ := ctx.Mem.Read32(rectPtr + 12)
				if right > left {
					rt.width = right - left
				}
				if bottom > top {
					rt.height = bottom - top
				}
			} else if rt.dc != nil && rt.dc.Target != nil {
				rt.width = uint32(rt.dc.Target.Width)
				rt.height = uint32(rt.dc.Target.Height)
			}
			return S_OK
		}
	case 58:
		if obj.kind == "d2d1-hwnd-render-target" {
			sizePtr := ctx.Arg(1)
			if sizePtr == 0 {
				return E_POINTER
			}
			rt.width, _ = ctx.Mem.Read32(sizePtr)
			rt.height, _ = ctx.Mem.Read32(sizePtr + 4)
			return S_OK
		}
	case 59:
		if obj.kind == "d2d1-hwnd-render-target" {
			ctx.SetReturn(rt.hwnd)
			return 0
		}
	case 60:
		if obj.kind == "d2d1-hwnd-render-target" {
			if pp := ctx.Arg(1); pp != 0 {
				ctx.Mem.Write64(pp, obj.objectAddr)
			}
			return S_OK
		}
	}
	return E_NOTIMPL
}

func (cs *comState) dispatchD2D1StrokeStyle(ctx *ntapi.TrapContext, obj *comObject, method int) uint32 {
	style, _ := obj.data.(*d2d1StrokeStyle)
	if style == nil {
		return E_FAIL
	}
	switch method {
	case 3:
		return cs.dispatchD2D1Resource(ctx, obj, method)
	case 4:
		ctx.SetReturn(uint64(style.startCap))
	case 5:
		ctx.SetReturn(uint64(style.endCap))
	case 6:
		ctx.SetReturn(uint64(style.dashCap))
	case 7:
		ctx.SetReturn(uint64(math.Float32bits(style.miterLimit)))
	case 8:
		ctx.SetReturn(uint64(style.lineJoin))
	case 9:
		ctx.SetReturn(uint64(math.Float32bits(style.dashOffset)))
	case 10:
		ctx.SetReturn(uint64(style.dashStyle))
	case 11:
		ctx.SetReturn(uint64(len(style.dashes)))
	default:
		return E_NOTIMPL
	}
	return 0
}

func (cs *comState) dispatchD2D1DrawingState(ctx *ntapi.TrapContext, obj *comObject, method int) uint32 {
	state, _ := obj.data.(*d2d1DrawingStateBlock)
	if state == nil {
		return E_FAIL
	}
	switch method {
	case 3:
		return cs.dispatchD2D1Resource(ctx, obj, method)
	case 4:
		if desc := ctx.Arg(1); desc != 0 {
			ctx.Mem.Write32(desc+0, state.antialiasMode)
			ctx.Mem.Write32(desc+4, state.textAntialiasMode)
			writeD2D1Matrix(ctx.Mem, desc+8, state.transform)
			ctx.Mem.Write64(desc+32, state.tags[0])
			ctx.Mem.Write64(desc+40, state.tags[1])
		}
		return 0
	case 5:
		if desc := ctx.Arg(1); desc != 0 {
			state.antialiasMode, _ = ctx.Mem.Read32(desc + 0)
			state.textAntialiasMode, _ = ctx.Mem.Read32(desc + 4)
			state.transform = readD2D1Matrix(ctx.Mem, desc+8)
			state.tags[0], _ = ctx.Mem.Read64(desc + 32)
			state.tags[1], _ = ctx.Mem.Read64(desc + 40)
		}
		return 0
	case 6:
		state.textRenderingParams = ctx.Arg(1)
		return 0
	case 7:
		if pp := ctx.Arg(1); pp != 0 {
			ctx.Mem.Write64(pp, state.textRenderingParams)
		}
		return 0
	default:
		return E_NOTIMPL
	}
}

func (cs *comState) dispatchD2D1Layer(ctx *ntapi.TrapContext, obj *comObject, method int) uint32 {
	layer, _ := obj.data.(*d2d1Layer)
	if layer == nil {
		return E_FAIL
	}
	switch method {
	case 3:
		return cs.dispatchD2D1Resource(ctx, obj, method)
	case 4:
		if p := ctx.Arg(1); p != 0 {
			ctx.Mem.Write32(p+0, math.Float32bits(layer.width))
			ctx.Mem.Write32(p+4, math.Float32bits(layer.height))
		}
		return 0
	default:
		return E_NOTIMPL
	}
}

func (cs *comState) dispatchD2D1Mesh(ctx *ntapi.TrapContext, obj *comObject, method int) uint32 {
	switch method {
	case 3:
		return cs.dispatchD2D1Resource(ctx, obj, method)
	case 4:
		if pp := ctx.Arg(1); pp != 0 {
			ctx.Mem.Write64(pp, 0)
		}
		return E_NOTIMPL
	default:
		return E_NOTIMPL
	}
}

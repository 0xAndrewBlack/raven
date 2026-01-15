package main

import (
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"sync"

	gdi "github.com/mirkobrombin/Raven/pkg/gdi"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

const (
	dwriteTrapIDBase = 0x16000000

	dwriteFactoryMethods            = 64
	dwriteTextFormatMethods         = 28
	dwriteTextLayoutMethods         = 66
	dwriteFontCollectionMethods     = 7
	dwriteFontFamilyMethods         = 9
	dwriteLocalizedStringsMethods   = 9
	dwriteGdiInteropMethods         = 8
	dwriteBitmapRenderTargetMethods = 12
	dwriteRenderingParamsMethods    = 8
	dwriteTextAnalyzerMethods       = 12
	dwriteFontMethods               = 14
	dwriteFontFaceMethods           = 3

	dwriteFactoryTypeShared   = 0
	dwriteFactoryTypeIsolated = 1

	dwriteFontWeightNormal  = 400
	dwriteFontWeightBold    = 700
	dwriteFontStyleNormal   = 0
	dwriteFontStyleOblique  = 1
	dwriteFontStyleItalic   = 2
	dwriteFontStretchNormal = 5

	dwriteTextAlignmentLeading = 0
	dwriteWordWrappingWrap     = 0
	dwriteWordWrappingNoWrap   = 1

	dwritePixelGeometryRGB = 1
	dwriteRenderingDefault = 0
)

var (
	IID_IDWriteFactory            = GUID{0xb859ee5a, 0xd838, 0x4b5b, [8]byte{0xa2, 0xe8, 0x1a, 0xdc, 0x7d, 0x93, 0xdb, 0x48}}
	IID_IDWriteFactory1           = GUID{0x30572f99, 0xdac6, 0x41db, [8]byte{0xa1, 0x6e, 0x04, 0x86, 0x30, 0x7e, 0x60, 0x6a}}
	IID_IDWriteFactory2           = GUID{0x0439fc60, 0xca44, 0x4994, [8]byte{0x8d, 0xee, 0x3a, 0x9a, 0xf7, 0xb7, 0x32, 0xec}}
	IID_IDWriteFactory3           = GUID{0x9a1b41c3, 0xd3bb, 0x466a, [8]byte{0x87, 0xfc, 0xfe, 0x67, 0x55, 0x6a, 0x3b, 0x65}}
	IID_IDWriteFactory4           = GUID{0x4b0b5bd3, 0x0797, 0x4549, [8]byte{0x8a, 0xc5, 0xfe, 0x91, 0x5c, 0xc5, 0x38, 0x56}}
	IID_IDWriteFactory5           = GUID{0x958db99a, 0xbe2a, 0x4f09, [8]byte{0xaf, 0x7d, 0x65, 0x18, 0x98, 0x03, 0xd1, 0xd3}}
	IID_IDWriteFactory6           = GUID{0xf3744d80, 0x21f7, 0x42eb, [8]byte{0xb3, 0x5d, 0x99, 0x5b, 0xc7, 0x2f, 0xc2, 0x23}}
	IID_IDWriteFactory7           = GUID{0x35d0e0b3, 0x9076, 0x4d2e, [8]byte{0xa0, 0x16, 0xa9, 0x1b, 0x56, 0x8a, 0x06, 0xb4}}
	IID_IDWriteLocalizedStrings   = GUID{0x08256209, 0x099a, 0x4b34, [8]byte{0xb8, 0x6d, 0xc2, 0x2b, 0x11, 0x0e, 0x77, 0x71}}
	IID_IDWriteRenderingParams    = GUID{0x2f0da53a, 0x2add, 0x47cd, [8]byte{0x82, 0xee, 0xd9, 0xec, 0x34, 0x68, 0x8e, 0x75}}
	IID_IDWriteFontFace           = GUID{0x5f49804d, 0x7024, 0x4d43, [8]byte{0xbf, 0xa9, 0xd2, 0x59, 0x84, 0xf5, 0x38, 0x49}}
	IID_IDWriteFont               = GUID{0xacd16696, 0x8c14, 0x4f5d, [8]byte{0x87, 0x7e, 0xfe, 0x3f, 0xc1, 0xd3, 0x27, 0x37}}
	IID_IDWriteFontList           = GUID{0x1a0d8438, 0x1d97, 0x4ec1, [8]byte{0xae, 0xf9, 0xa2, 0xfb, 0x86, 0xed, 0x6a, 0xcb}}
	IID_IDWriteFontFamily         = GUID{0xda20d8ef, 0x812a, 0x4c43, [8]byte{0x98, 0x02, 0x62, 0xec, 0x4a, 0xbd, 0x7a, 0xdd}}
	IID_IDWriteFontCollection     = GUID{0xa84cee02, 0x3eea, 0x4eee, [8]byte{0xa8, 0x27, 0x87, 0xc1, 0xa0, 0x2a, 0x0f, 0xcc}}
	IID_IDWriteTextFormat         = GUID{0x9c906818, 0x31d7, 0x4fd3, [8]byte{0xa1, 0x51, 0x7c, 0x5e, 0x22, 0x5d, 0xb5, 0x5a}}
	IID_IDWriteBitmapRenderTarget = GUID{0x5e5a32a3, 0x8dff, 0x4773, [8]byte{0x9f, 0xf6, 0x06, 0x96, 0xea, 0xb7, 0x72, 0x67}}
	IID_IDWriteGdiInterop         = GUID{0x1edd9491, 0x9853, 0x4299, [8]byte{0x89, 0x8f, 0x64, 0x32, 0x98, 0x3b, 0x6f, 0x3a}}
	IID_IDWriteTextLayout         = GUID{0x53737037, 0x6d14, 0x410b, [8]byte{0x9b, 0xfe, 0x0b, 0x18, 0x2b, 0xb7, 0x09, 0x61}}
	IID_IDWriteTextAnalyzer       = GUID{0xb7e6163e, 0x7f46, 0x43b4, [8]byte{0x84, 0xb3, 0xe4, 0xe6, 0x24, 0x9c, 0x36, 0x5d}}
)

type dwriteCOMObject struct {
	objectAddr    uint64
	refCount      uint32
	hctx          *HandlerCtx
	supportedIIDs map[GUID]bool
	data          interface{}
	dispatch      func(ctx *ntapi.TrapContext, method int, obj *dwriteCOMObject) uint32
}

type dwriteFactory struct {
	factoryType   int
	sysCollection *dwriteFontCollection
	gdiInterop    *dwriteGdiInterop
}

type dwriteTextFormat struct {
	factory            *dwriteFactory
	fontCollection     *dwriteFontCollection
	fontFamily         string
	fontSize           float64
	fontWeight         uint32
	fontStyle          uint32
	fontStretch        uint32
	locale             string
	textAlignment      uint32
	paragraphAlignment uint32
	wordWrapping       uint32
	readingDirection   uint32
	flowDirection      uint32
	incrementalTabStop float64
	lineSpacingMethod  uint32
	lineSpacing        float64
	baseline           float64
	maxWidth           float64
	maxHeight          float64
}

type dwriteTextLayout struct {
	dwriteTextFormat
	text          []rune
	textLength    uint32
	underline     bool
	strikethrough bool
	lines         []dwriteLineInfo
}

type dwriteLineInfo struct {
	length   uint32
	width    float64
	baseline float64
	height   float64
}

type dwriteFontCollection struct {
	factory  *dwriteFactory
	families []dwriteFontFamilyEntry
}

type dwriteFontFamilyEntry struct {
	name   string
	faceID int
}

type dwriteFont struct {
	factory      *dwriteFactory
	collection   *dwriteFontCollection
	family       dwriteFontFamilyEntry
	weight       uint32
	style        uint32
	stretch      uint32
	systemFont   bool
	familyLocale string
}

type dwriteFontFace struct {
	factory    *dwriteFactory
	familyName string
	faceID     int
	weight     uint32
	style      uint32
	stretch    uint32
}

type dwriteLocalizedString struct {
	locale string
	value  string
}

type dwriteLocalizedStrings struct {
	entries []dwriteLocalizedString
}

type dwriteGdiInterop struct {
	factory *dwriteFactory
}

type dwriteBitmapRenderTarget struct {
	hctx          *HandlerCtx
	hdc           uint64
	hbitmap       uint64
	width         uint32
	height        uint32
	pixelsPerDip  float64
	transform     gdi.XForm
	naturalEmSize float64
}

type dwriteRenderingParams struct {
	gamma, enhContrast, clearTypeLevel float64
	pixelGeometry, renderingMode       int
}

type dwriteTextAnalyzer struct{}

type dwriteTextMetrics struct {
	left, top, width, widthWithTrailing float64
	height, layoutWidth, layoutHeight   float64
	lineCount                           uint32
}

var (
	dwriteCOMMu         sync.Mutex
	dwriteCOMNextTrapID uint32 = dwriteTrapIDBase
	dwriteCOMObjects           = map[uint64]*dwriteCOMObject{}
)

func registerDWriteHandlers(hctx *HandlerCtx) {
	dll, ok := hctx.SynthByName["dwrite.dll"]
	if !ok {
		return
	}

	hctx.Disp.RegisterAutoStubHandler(dll, "DWriteCreateFactory", func(ctx *ntapi.TrapContext) uint32 {
		factoryType := int(ctx.Arg(0))
		riidPtr := ctx.Arg(1)
		ppFactory := ctx.Arg(2)
		if ppFactory == 0 {
			ctx.SetReturn(E_POINTER)
			return 0
		}
		ctx.Mem.Write64(ppFactory, 0)
		if riidPtr == 0 {
			ctx.SetReturn(E_POINTER)
			return 0
		}
		if factoryType != dwriteFactoryTypeShared && factoryType != dwriteFactoryTypeIsolated {
			ctx.SetReturn(E_INVALIDARG)
			return 0
		}

		riid := readGUID(ctx.Mem, riidPtr)
		if !dwriteIsFactoryIID(riid) && !guidEqual(riid, IID_IUnknown) {
			ctx.SetReturn(E_NOINTERFACE)
			return 0
		}

		factory := &dwriteFactory{factoryType: factoryType}
		factory.sysCollection = dwriteBuildSystemFontCollection(factory)
		factory.gdiInterop = &dwriteGdiInterop{factory: factory}
		obj := dwriteCreateObject(hctx, dwriteFactoryMethods, dwriteDispatchFactory, factory,
			IID_IUnknown, IID_IDWriteFactory, IID_IDWriteFactory1, IID_IDWriteFactory2,
			IID_IDWriteFactory3, IID_IDWriteFactory4, IID_IDWriteFactory5,
			IID_IDWriteFactory6, IID_IDWriteFactory7)
		if obj == 0 {
			ctx.SetReturn(E_OUTOFMEMORY)
			return 0
		}

		ctx.Mem.Write64(ppFactory, obj)
		ctx.SetReturn(S_OK)
		return 0
	})
}

func dwriteCreateObject(hctx *HandlerCtx, methods int, dispatch func(ctx *ntapi.TrapContext, method int, obj *dwriteCOMObject) uint32, data interface{}, iids ...GUID) uint64 {
	if methods < 3 {
		methods = 3
	}

	totalSize := uint64(8 + methods*8 + methods*16)
	objAddr := hctx.Mem.Mmap(0, totalSize, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	if objAddr == 0 {
		return 0
	}

	vtableAddr := objAddr + 8
	stubBase := vtableAddr + uint64(methods*8)
	obj := &dwriteCOMObject{
		objectAddr:    objAddr,
		refCount:      1,
		hctx:          hctx,
		supportedIIDs: map[GUID]bool{IID_IUnknown: true},
		data:          data,
		dispatch:      dispatch,
	}
	for _, iid := range iids {
		obj.supportedIIDs[iid] = true
	}

	dwriteCOMMu.Lock()
	dwriteCOMObjects[objAddr] = obj
	for i := 0; i < methods; i++ {
		trapID := dwriteCOMNextTrapID
		dwriteCOMNextTrapID++
		methodIndex := i
		hctx.Disp.RegisterHandler(trapID, fmt.Sprintf("dwrite[%d]", methodIndex), func(ctx *ntapi.TrapContext) uint32 {
			return dwriteDispatchCOMMethod(ctx, methodIndex)
		})
		stubAddr := stubBase + uint64(i*16)
		code := make([]byte, 16)
		code[0] = 0xB8
		binary.LittleEndian.PutUint32(code[1:5], trapID)
		code[5] = 0x0F
		code[6] = 0x01
		code[7] = 0xC1
		code[8] = 0xC3
		for j := 9; j < len(code); j++ {
			code[j] = 0xCC
		}
		hctx.Mem.WriteBytes(stubAddr, code)
		hctx.Mem.Write64(vtableAddr+uint64(i*8), stubAddr)
	}
	dwriteCOMMu.Unlock()

	hctx.Mem.Write64(objAddr, vtableAddr)
	return objAddr
}

func dwriteDispatchCOMMethod(ctx *ntapi.TrapContext, method int) uint32 {
	thisPtr := ctx.Arg(0)
	obj := dwriteLookupObject(thisPtr)
	if obj == nil {
		return E_POINTER
	}

	dwriteCOMMu.Lock()
	switch method {
	case 0:
		riidPtr := ctx.Arg(1)
		ppv := ctx.Arg(2)
		if ppv == 0 {
			dwriteCOMMu.Unlock()
			return E_POINTER
		}
		ctx.Mem.Write64(ppv, 0)
		if riidPtr == 0 {
			dwriteCOMMu.Unlock()
			return E_POINTER
		}
		riid := readGUID(ctx.Mem, riidPtr)
		if obj.supportedIIDs[riid] || guidEqual(riid, IID_IUnknown) {
			obj.refCount++
			ctx.Mem.Write64(ppv, thisPtr)
			dwriteCOMMu.Unlock()
			return S_OK
		}
		dwriteCOMMu.Unlock()
		return E_NOINTERFACE
	case 1:
		obj.refCount++
		count := obj.refCount
		dwriteCOMMu.Unlock()
		ctx.SetReturn(uint64(count))
		return 0
	case 2:
		if obj.refCount > 0 {
			obj.refCount--
		}
		count := obj.refCount
		if count == 0 {
			delete(dwriteCOMObjects, thisPtr)
		}
		dwriteCOMMu.Unlock()
		ctx.SetReturn(uint64(count))
		return 0
	default:
		dispatch := obj.dispatch
		dwriteCOMMu.Unlock()
		if dispatch == nil {
			return E_NOTIMPL
		}
		return dispatch(ctx, method, obj)
	}
}

func dwriteLookupObject(ptr uint64) *dwriteCOMObject {
	dwriteCOMMu.Lock()
	defer dwriteCOMMu.Unlock()
	return dwriteCOMObjects[ptr]
}

func dwriteIsFactoryIID(iid GUID) bool {
	return guidEqual(iid, IID_IDWriteFactory) ||
		guidEqual(iid, IID_IDWriteFactory1) ||
		guidEqual(iid, IID_IDWriteFactory2) ||
		guidEqual(iid, IID_IDWriteFactory3) ||
		guidEqual(iid, IID_IDWriteFactory4) ||
		guidEqual(iid, IID_IDWriteFactory5) ||
		guidEqual(iid, IID_IDWriteFactory6) ||
		guidEqual(iid, IID_IDWriteFactory7)
}

func dwriteBuildSystemFontCollection(factory *dwriteFactory) *dwriteFontCollection {
	coll := &dwriteFontCollection{factory: factory}
	seen := map[string]bool{}
	addFamily := func(name string) {
		trimmed := strings.TrimSpace(name)
		if trimmed == "" {
			return
		}
		key := strings.ToLower(trimmed)
		if seen[key] {
			return
		}
		seen[key] = true
		coll.families = append(coll.families, dwriteFontFamilyEntry{
			name:   trimmed,
			faceID: gdi.ResolveFontFaceStyle(trimmed, false, false),
		})
	}

	for _, face := range gdi.ListFaces() {
		addFamily(face.FamilyName)
	}
	for _, name := range []string{
		"Arial", "Times New Roman", "Courier New", "Tahoma", "Verdana", "Segoe UI",
		"Calibri", "Georgia", "Consolas", "Microsoft Sans Serif", "System",
	} {
		addFamily(name)
	}
	return coll
}

func dwriteFindFamilyIndex(coll *dwriteFontCollection, name string) int {
	for i, family := range coll.families {
		if strings.EqualFold(family.name, name) {
			return i
		}
	}
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return -1
	}
	faceID := gdi.ResolveFontFaceStyle(trimmed, false, false)
	if faceID < 0 {
		return -1
	}
	coll.families = append(coll.families, dwriteFontFamilyEntry{name: trimmed, faceID: faceID})
	return len(coll.families) - 1
}

func dwriteDefaultFormat(factory *dwriteFactory) dwriteTextFormat {
	return dwriteTextFormat{
		factory:            factory,
		fontCollection:     factory.sysCollection,
		fontFamily:         "Segoe UI",
		fontSize:           12,
		fontWeight:         dwriteFontWeightNormal,
		fontStyle:          dwriteFontStyleNormal,
		fontStretch:        dwriteFontStretchNormal,
		locale:             "en-us",
		textAlignment:      dwriteTextAlignmentLeading,
		wordWrapping:       dwriteWordWrappingWrap,
		incrementalTabStop: 48,
	}
}

func dwriteDispatchFactory(ctx *ntapi.TrapContext, method int, obj *dwriteCOMObject) uint32 {
	factory, _ := obj.data.(*dwriteFactory)
	if factory == nil {
		return E_FAIL
	}

	switch method {
	case 3:
		ppCollection := ctx.Arg(1)
		if ppCollection == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppCollection, 0)
		ptr := dwriteCreateFontCollectionObject(obj.hctx, factory.sysCollection)
		if ptr == 0 {
			return E_OUTOFMEMORY
		}
		ctx.Mem.Write64(ppCollection, ptr)
		return S_OK
	case 10:
		ppParams := ctx.Arg(1)
		if ppParams == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppParams, 0)
		ptr := dwriteCreateRenderingParamsObject(obj.hctx, &dwriteRenderingParams{
			gamma:          2.2,
			enhContrast:    1.0,
			clearTypeLevel: 1.0,
			pixelGeometry:  dwritePixelGeometryRGB,
			renderingMode:  dwriteRenderingDefault,
		})
		if ptr == 0 {
			return E_OUTOFMEMORY
		}
		ctx.Mem.Write64(ppParams, ptr)
		return S_OK
	case 11:
		ppParams := ctx.Arg(2)
		if ppParams == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppParams, 0)
		ptr := dwriteCreateRenderingParamsObject(obj.hctx, &dwriteRenderingParams{
			gamma:          2.2,
			enhContrast:    1.0,
			clearTypeLevel: 1.0,
			pixelGeometry:  dwritePixelGeometryRGB,
			renderingMode:  dwriteRenderingDefault,
		})
		if ptr == 0 {
			return E_OUTOFMEMORY
		}
		ctx.Mem.Write64(ppParams, ptr)
		return S_OK
	case 12:
		ppParams := ctx.Arg(6)
		if ppParams == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppParams, 0)
		ptr := dwriteCreateRenderingParamsObject(obj.hctx, &dwriteRenderingParams{
			gamma:          float64(math.Float32frombits(uint32(ctx.Arg(1)))),
			enhContrast:    float64(math.Float32frombits(uint32(ctx.Arg(2)))),
			clearTypeLevel: float64(math.Float32frombits(uint32(ctx.Arg(3)))),
			pixelGeometry:  int(ctx.Arg(4)),
			renderingMode:  int(ctx.Arg(5)),
		})
		if ptr == 0 {
			return E_OUTOFMEMORY
		}
		ctx.Mem.Write64(ppParams, ptr)
		return S_OK
	case 15:
		fontFamily := obj.hctx.ReadGuestUTF16(ctx.Arg(1))
		weight := uint32(ctx.Arg(3))
		style := uint32(ctx.Arg(4))
		stretch := uint32(ctx.Arg(5))
		fontSize := float64(math.Float32frombits(uint32(ctx.Arg(6))))
		locale := obj.hctx.ReadGuestUTF16(ctx.Arg(7))
		ppFormat := ctx.Arg(8)
		if ppFormat == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppFormat, 0)
		format := dwriteDefaultFormat(factory)
		if fontFamily != "" {
			format.fontFamily = fontFamily
		}
		if collPtr := ctx.Arg(2); collPtr != 0 {
			if collObj := dwriteLookupObject(collPtr); collObj != nil {
				if coll, ok := collObj.data.(*dwriteFontCollection); ok {
					format.fontCollection = coll
				}
			}
		}
		if weight != 0 {
			format.fontWeight = weight
		}
		if stretch != 0 {
			format.fontStretch = stretch
		}
		format.fontStyle = style
		if fontSize > 0 {
			format.fontSize = fontSize
		}
		if locale != "" {
			format.locale = locale
		}
		ptr := dwriteCreateTextFormatObject(obj.hctx, &format)
		if ptr == 0 {
			return E_OUTOFMEMORY
		}
		ctx.Mem.Write64(ppFormat, ptr)
		return S_OK
	case 17:
		ppInterop := ctx.Arg(1)
		if ppInterop == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppInterop, 0)
		ptr := dwriteCreateGdiInteropObject(obj.hctx, factory.gdiInterop)
		if ptr == 0 {
			return E_OUTOFMEMORY
		}
		ctx.Mem.Write64(ppInterop, ptr)
		return S_OK
	case 18:
		text := obj.hctx.ReadGuestUTF16N(ctx.Arg(1), int(uint32(ctx.Arg(2))))
		formatObj := dwriteLookupObject(ctx.Arg(3))
		ppLayout := ctx.Arg(6)
		if ppLayout == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppLayout, 0)
		base := dwriteDefaultFormat(factory)
		if formatObj != nil {
			switch data := formatObj.data.(type) {
			case *dwriteTextFormat:
				base = *data
			case *dwriteTextLayout:
				base = data.dwriteTextFormat
			}
		}
		base.maxWidth = float64(math.Float32frombits(uint32(ctx.Arg(4))))
		base.maxHeight = float64(math.Float32frombits(uint32(ctx.Arg(5))))
		layout := &dwriteTextLayout{dwriteTextFormat: base, text: []rune(text), textLength: uint32(len([]rune(text)))}
		dwriteEnsureLayout(layout)
		ptr := dwriteCreateTextLayoutObject(obj.hctx, layout)
		if ptr == 0 {
			return E_OUTOFMEMORY
		}
		ctx.Mem.Write64(ppLayout, ptr)
		return S_OK
	case 19:
		text := obj.hctx.ReadGuestUTF16N(ctx.Arg(1), int(uint32(ctx.Arg(2))))
		formatObj := dwriteLookupObject(ctx.Arg(3))
		ppLayout := ctx.Arg(9)
		if ppLayout == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppLayout, 0)
		base := dwriteDefaultFormat(factory)
		if formatObj != nil {
			switch data := formatObj.data.(type) {
			case *dwriteTextFormat:
				base = *data
			case *dwriteTextLayout:
				base = data.dwriteTextFormat
			}
		}
		base.maxWidth = float64(math.Float32frombits(uint32(ctx.Arg(4))))
		base.maxHeight = float64(math.Float32frombits(uint32(ctx.Arg(5))))
		layout := &dwriteTextLayout{dwriteTextFormat: base, text: []rune(text), textLength: uint32(len([]rune(text)))}
		dwriteEnsureLayout(layout)
		ptr := dwriteCreateTextLayoutObject(obj.hctx, layout)
		if ptr == 0 {
			return E_OUTOFMEMORY
		}
		ctx.Mem.Write64(ppLayout, ptr)
		return S_OK
	case 21:
		ppAnalyzer := ctx.Arg(1)
		if ppAnalyzer == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppAnalyzer, 0)
		ptr := dwriteCreateTextAnalyzerObject(obj.hctx, &dwriteTextAnalyzer{})
		if ptr == 0 {
			return E_OUTOFMEMORY
		}
		ctx.Mem.Write64(ppAnalyzer, ptr)
		return S_OK
	default:
		return E_NOTIMPL
	}
}

func dwriteCreateTextFormatObject(hctx *HandlerCtx, format *dwriteTextFormat) uint64 {
	return dwriteCreateObject(hctx, dwriteTextFormatMethods, dwriteDispatchTextFormat, format, IID_IUnknown, IID_IDWriteTextFormat)
}

func dwriteDispatchTextFormat(ctx *ntapi.TrapContext, method int, obj *dwriteCOMObject) uint32 {
	format, _ := obj.data.(*dwriteTextFormat)
	if format == nil {
		return E_FAIL
	}
	return dwriteDispatchTextFormatCommon(ctx, method, format, obj.hctx)
}

func dwriteCreateTextLayoutObject(hctx *HandlerCtx, layout *dwriteTextLayout) uint64 {
	return dwriteCreateObject(hctx, dwriteTextLayoutMethods, dwriteDispatchTextLayout, layout, IID_IUnknown, IID_IDWriteTextFormat, IID_IDWriteTextLayout)
}

func dwriteDispatchTextLayout(ctx *ntapi.TrapContext, method int, obj *dwriteCOMObject) uint32 {
	layout, _ := obj.data.(*dwriteTextLayout)
	if layout == nil {
		return E_FAIL
	}
	if method <= 27 {
		return dwriteDispatchTextFormatCommon(ctx, method, &layout.dwriteTextFormat, obj.hctx)
	}

	switch method {
	case 28:
		layout.maxWidth = float64(math.Float32frombits(uint32(ctx.Arg(1))))
		dwriteEnsureLayout(layout)
		return S_OK
	case 29:
		layout.maxHeight = float64(math.Float32frombits(uint32(ctx.Arg(1))))
		dwriteEnsureLayout(layout)
		return S_OK
	case 30:
		if collObj := dwriteLookupObject(ctx.Arg(1)); collObj != nil {
			if coll, ok := collObj.data.(*dwriteFontCollection); ok {
				layout.fontCollection = coll
			}
		}
		return S_OK
	case 31:
		layout.fontFamily = obj.hctx.ReadGuestUTF16(ctx.Arg(1))
		dwriteEnsureLayout(layout)
		return S_OK
	case 32:
		layout.fontWeight = uint32(ctx.Arg(1))
		dwriteEnsureLayout(layout)
		return S_OK
	case 33:
		layout.fontStyle = uint32(ctx.Arg(1))
		dwriteEnsureLayout(layout)
		return S_OK
	case 34:
		layout.fontStretch = uint32(ctx.Arg(1))
		return S_OK
	case 35:
		layout.fontSize = float64(math.Float32frombits(uint32(ctx.Arg(1))))
		dwriteEnsureLayout(layout)
		return S_OK
	case 36:
		layout.underline = ctx.Arg(1) != 0
		return S_OK
	case 37:
		layout.strikethrough = ctx.Arg(1) != 0
		return S_OK
	case 41:
		layout.locale = obj.hctx.ReadGuestUTF16(ctx.Arg(1))
		return S_OK
	case 42:
		ctx.SetReturn(uint64(math.Float32bits(float32(layout.maxWidth))))
		return 0
	case 43:
		ctx.SetReturn(uint64(math.Float32bits(float32(layout.maxHeight))))
		return 0
	case 44:
		ppCollection := ctx.Arg(2)
		if ppCollection == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppCollection, 0)
		if layout.fontCollection != nil {
			ptr := dwriteCreateFontCollectionObject(obj.hctx, layout.fontCollection)
			if ptr == 0 {
				return E_OUTOFMEMORY
			}
			ctx.Mem.Write64(ppCollection, ptr)
		}
		if tr := ctx.Arg(3); tr != 0 {
			dwriteWriteTextRange(ctx.Mem, tr, 0, layout.textLength)
		}
		return S_OK
	case 45:
		if out := ctx.Arg(2); out != 0 {
			ctx.Mem.Write32(out, uint32(len(utf16Encode(layout.fontFamily))))
		}
		if tr := ctx.Arg(3); tr != 0 {
			dwriteWriteTextRange(ctx.Mem, tr, 0, layout.textLength)
		}
		return S_OK
	case 46:
		buf := ctx.Arg(2)
		size := uint32(ctx.Arg(3))
		if buf == 0 || size == 0 {
			return E_INVALIDARG
		}
		writeGuestUTF16StringN(ctx.Mem, buf, layout.fontFamily, int(size))
		if tr := ctx.Arg(4); tr != 0 {
			dwriteWriteTextRange(ctx.Mem, tr, 0, layout.textLength)
		}
		return S_OK
	case 47:
		if out := ctx.Arg(2); out != 0 {
			ctx.Mem.Write32(out, layout.fontWeight)
		}
		if tr := ctx.Arg(3); tr != 0 {
			dwriteWriteTextRange(ctx.Mem, tr, 0, layout.textLength)
		}
		return S_OK
	case 48:
		if out := ctx.Arg(2); out != 0 {
			ctx.Mem.Write32(out, layout.fontStyle)
		}
		if tr := ctx.Arg(3); tr != 0 {
			dwriteWriteTextRange(ctx.Mem, tr, 0, layout.textLength)
		}
		return S_OK
	case 49:
		if out := ctx.Arg(2); out != 0 {
			ctx.Mem.Write32(out, layout.fontStretch)
		}
		if tr := ctx.Arg(3); tr != 0 {
			dwriteWriteTextRange(ctx.Mem, tr, 0, layout.textLength)
		}
		return S_OK
	case 50:
		if out := ctx.Arg(2); out != 0 {
			ctx.Mem.Write32(out, math.Float32bits(float32(layout.fontSize)))
		}
		if tr := ctx.Arg(3); tr != 0 {
			dwriteWriteTextRange(ctx.Mem, tr, 0, layout.textLength)
		}
		return S_OK
	case 51:
		if out := ctx.Arg(2); out != 0 {
			ctx.Mem.Write32(out, boolToUint32(layout.underline))
		}
		if tr := ctx.Arg(3); tr != 0 {
			dwriteWriteTextRange(ctx.Mem, tr, 0, layout.textLength)
		}
		return S_OK
	case 52:
		if out := ctx.Arg(2); out != 0 {
			ctx.Mem.Write32(out, boolToUint32(layout.strikethrough))
		}
		if tr := ctx.Arg(3); tr != 0 {
			dwriteWriteTextRange(ctx.Mem, tr, 0, layout.textLength)
		}
		return S_OK
	case 56:
		buf := ctx.Arg(2)
		size := uint32(ctx.Arg(3))
		if buf != 0 && size > 0 {
			writeGuestUTF16StringN(ctx.Mem, buf, layout.locale, int(size))
		}
		if tr := ctx.Arg(4); tr != 0 {
			dwriteWriteTextRange(ctx.Mem, tr, 0, layout.textLength)
		}
		return S_OK
	case 58:
		dwriteEnsureLayout(layout)
		metricsPtr := ctx.Arg(1)
		maxCount := uint32(ctx.Arg(2))
		actualPtr := ctx.Arg(3)
		if actualPtr != 0 {
			ctx.Mem.Write32(actualPtr, uint32(len(layout.lines)))
		}
		if metricsPtr == 0 {
			return E_POINTER
		}
		count := uint32(len(layout.lines))
		if maxCount < count {
			count = maxCount
		}
		for i := uint32(0); i < count; i++ {
			base := metricsPtr + uint64(i)*24
			line := layout.lines[i]
			ctx.Mem.Write32(base+0, line.length)
			ctx.Mem.Write32(base+4, 0)
			ctx.Mem.Write32(base+8, 0)
			ctx.Mem.Write32(base+12, math.Float32bits(float32(line.height)))
			ctx.Mem.Write32(base+16, math.Float32bits(float32(line.baseline)))
			ctx.Mem.Write32(base+20, 0)
		}
		return S_OK
	case 59:
		metricsPtr := ctx.Arg(1)
		if metricsPtr == 0 {
			return E_POINTER
		}
		dwriteWriteTextMetrics(ctx.Mem, metricsPtr, dwriteTextMetricsForLayout(layout))
		return S_OK
	case 60:
		if out := ctx.Arg(1); out != 0 {
			for i := 0; i < 4; i++ {
				ctx.Mem.Write32(out+uint64(i*4), 0)
			}
		}
		return S_OK
	case 61:
		metricsPtr := ctx.Arg(1)
		maxCount := uint32(ctx.Arg(2))
		actualPtr := ctx.Arg(3)
		if actualPtr != 0 {
			ctx.Mem.Write32(actualPtr, uint32(len(layout.text)))
		}
		if metricsPtr == 0 {
			return E_POINTER
		}
		count := uint32(len(layout.text))
		if maxCount < count {
			count = maxCount
		}
		advance := dwriteAverageAdvance(&layout.dwriteTextFormat)
		for i := uint32(0); i < count; i++ {
			base := metricsPtr + uint64(i)*8
			ctx.Mem.Write32(base+0, math.Float32bits(float32(advance)))
			ctx.Mem.Write16(base+4, 1)
			flags := uint16(0)
			if layout.text[i] == ' ' || layout.text[i] == '\t' {
				flags |= 1 << 1
			}
			if layout.text[i] == '\n' || layout.text[i] == '\r' {
				flags |= 1 << 2
			}
			ctx.Mem.Write16(base+6, flags)
		}
		return S_OK
	case 62:
		if out := ctx.Arg(1); out == 0 {
			return E_POINTER
		} else {
			ctx.Mem.Write32(out, math.Float32bits(float32(dwriteDetermineMinWidth(layout))))
		}
		return S_OK
	case 63:
		return dwriteHitTestPoint(ctx, layout)
	case 64:
		return dwriteHitTestTextPosition(ctx, layout)
	case 65:
		return dwriteHitTestTextRange(ctx, layout)
	default:
		return E_NOTIMPL
	}
}

func dwriteDispatchTextFormatCommon(ctx *ntapi.TrapContext, method int, format *dwriteTextFormat, hctx *HandlerCtx) uint32 {
	switch method {
	case 3:
		format.textAlignment = uint32(ctx.Arg(1))
		return S_OK
	case 4:
		format.paragraphAlignment = uint32(ctx.Arg(1))
		return S_OK
	case 5:
		format.wordWrapping = uint32(ctx.Arg(1))
		return S_OK
	case 6:
		format.readingDirection = uint32(ctx.Arg(1))
		return S_OK
	case 7:
		format.flowDirection = uint32(ctx.Arg(1))
		return S_OK
	case 8:
		format.incrementalTabStop = float64(math.Float32frombits(uint32(ctx.Arg(1))))
		return S_OK
	case 9:
		return S_OK
	case 10:
		format.lineSpacingMethod = uint32(ctx.Arg(1))
		format.lineSpacing = float64(math.Float32frombits(uint32(ctx.Arg(2))))
		format.baseline = float64(math.Float32frombits(uint32(ctx.Arg(3))))
		return S_OK
	case 11:
		ctx.SetReturn(uint64(format.textAlignment))
		return 0
	case 12:
		ctx.SetReturn(uint64(format.paragraphAlignment))
		return 0
	case 13:
		ctx.SetReturn(uint64(format.wordWrapping))
		return 0
	case 14:
		ctx.SetReturn(uint64(format.readingDirection))
		return 0
	case 15:
		ctx.SetReturn(uint64(format.flowDirection))
		return 0
	case 16:
		ctx.SetReturn(uint64(math.Float32bits(float32(format.incrementalTabStop))))
		return 0
	case 17:
		if options := ctx.Arg(1); options != 0 {
			ctx.Mem.Write32(options+0, 0)
			ctx.Mem.Write32(options+4, 0)
			ctx.Mem.Write32(options+8, 0)
		}
		if sign := ctx.Arg(2); sign != 0 {
			ctx.Mem.Write64(sign, 0)
		}
		return S_OK
	case 18:
		if methodPtr := ctx.Arg(1); methodPtr != 0 {
			ctx.Mem.Write32(methodPtr, format.lineSpacingMethod)
		}
		if spacingPtr := ctx.Arg(2); spacingPtr != 0 {
			ctx.Mem.Write32(spacingPtr, math.Float32bits(float32(format.lineSpacing)))
		}
		if baselinePtr := ctx.Arg(3); baselinePtr != 0 {
			ctx.Mem.Write32(baselinePtr, math.Float32bits(float32(format.baseline)))
		}
		return S_OK
	case 19:
		ppCollection := ctx.Arg(1)
		if ppCollection == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppCollection, 0)
		if format.fontCollection != nil {
			ptr := dwriteCreateFontCollectionObject(hctx, format.fontCollection)
			if ptr == 0 {
				return E_OUTOFMEMORY
			}
			ctx.Mem.Write64(ppCollection, ptr)
		}
		return S_OK
	case 20:
		ctx.SetReturn(uint64(len(utf16Encode(format.fontFamily))))
		return 0
	case 21:
		buf := ctx.Arg(1)
		size := uint32(ctx.Arg(2))
		if buf == 0 || size == 0 {
			return E_INVALIDARG
		}
		writeGuestUTF16StringN(ctx.Mem, buf, format.fontFamily, int(size))
		return S_OK
	case 22:
		ctx.SetReturn(uint64(format.fontWeight))
		return 0
	case 23:
		ctx.SetReturn(uint64(format.fontStyle))
		return 0
	case 24:
		ctx.SetReturn(uint64(format.fontStretch))
		return 0
	case 25:
		ctx.SetReturn(uint64(math.Float32bits(float32(format.fontSize))))
		return 0
	case 26:
		ctx.SetReturn(uint64(len(utf16Encode(format.locale))))
		return 0
	case 27:
		buf := ctx.Arg(1)
		size := uint32(ctx.Arg(2))
		if buf == 0 || size == 0 {
			return E_INVALIDARG
		}
		writeGuestUTF16StringN(ctx.Mem, buf, format.locale, int(size))
		return S_OK
	default:
		return E_NOTIMPL
	}
}

func dwriteCreateFontCollectionObject(hctx *HandlerCtx, coll *dwriteFontCollection) uint64 {
	return dwriteCreateObject(hctx, dwriteFontCollectionMethods, dwriteDispatchFontCollection, coll, IID_IUnknown, IID_IDWriteFontCollection)
}

func dwriteDispatchFontCollection(ctx *ntapi.TrapContext, method int, obj *dwriteCOMObject) uint32 {
	coll, _ := obj.data.(*dwriteFontCollection)
	if coll == nil {
		return E_FAIL
	}

	switch method {
	case 3:
		ctx.SetReturn(uint64(len(coll.families)))
		return 0
	case 4:
		index := int(ctx.Arg(1))
		ppFamily := ctx.Arg(2)
		if ppFamily == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppFamily, 0)
		if index < 0 || index >= len(coll.families) {
			return E_INVALIDARG
		}
		ptr := dwriteCreateFontFamilyObject(obj.hctx, coll, coll.families[index])
		if ptr == 0 {
			return E_OUTOFMEMORY
		}
		ctx.Mem.Write64(ppFamily, ptr)
		return S_OK
	case 5:
		name := obj.hctx.ReadGuestUTF16(ctx.Arg(1))
		idx := dwriteFindFamilyIndex(coll, name)
		if indexPtr := ctx.Arg(2); indexPtr != 0 {
			if idx >= 0 {
				ctx.Mem.Write32(indexPtr, uint32(idx))
			} else {
				ctx.Mem.Write32(indexPtr, 0xffffffff)
			}
		}
		if existsPtr := ctx.Arg(3); existsPtr != 0 {
			ctx.Mem.Write32(existsPtr, boolToUint32(idx >= 0))
		}
		return S_OK
	case 6:
		fontFaceObj := dwriteLookupObject(ctx.Arg(1))
		ppFont := ctx.Arg(2)
		if ppFont == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppFont, 0)
		if fontFaceObj == nil {
			return E_INVALIDARG
		}
		face, _ := fontFaceObj.data.(*dwriteFontFace)
		if face == nil {
			return E_INVALIDARG
		}
		ptr := dwriteCreateFontObject(obj.hctx, &dwriteFont{
			factory:      coll.factory,
			collection:   coll,
			family:       dwriteFontFamilyEntry{name: face.familyName, faceID: face.faceID},
			weight:       face.weight,
			style:        face.style,
			stretch:      face.stretch,
			systemFont:   true,
			familyLocale: "en-us",
		})
		if ptr == 0 {
			return E_OUTOFMEMORY
		}
		ctx.Mem.Write64(ppFont, ptr)
		return S_OK
	default:
		return E_NOTIMPL
	}
}

func dwriteCreateFontFamilyObject(hctx *HandlerCtx, coll *dwriteFontCollection, family dwriteFontFamilyEntry) uint64 {
	data := &dwriteFont{factory: coll.factory, collection: coll, family: family, weight: dwriteFontWeightNormal, style: dwriteFontStyleNormal, stretch: dwriteFontStretchNormal, systemFont: true, familyLocale: "en-us"}
	return dwriteCreateObject(hctx, dwriteFontFamilyMethods, dwriteDispatchFontFamily, data, IID_IUnknown, IID_IDWriteFontList, IID_IDWriteFontFamily)
}

func dwriteDispatchFontFamily(ctx *ntapi.TrapContext, method int, obj *dwriteCOMObject) uint32 {
	fontData, _ := obj.data.(*dwriteFont)
	if fontData == nil {
		return E_FAIL
	}

	switch method {
	case 3:
		ppCollection := ctx.Arg(1)
		if ppCollection == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppCollection, 0)
		if fontData.collection != nil {
			ptr := dwriteCreateFontCollectionObject(obj.hctx, fontData.collection)
			if ptr == 0 {
				return E_OUTOFMEMORY
			}
			ctx.Mem.Write64(ppCollection, ptr)
		}
		return S_OK
	case 4:
		ctx.SetReturn(1)
		return 0
	case 5:
		if ctx.Arg(1) != 0 {
			return E_INVALIDARG
		}
		ppFont := ctx.Arg(2)
		if ppFont == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppFont, 0)
		clone := *fontData
		ptr := dwriteCreateFontObject(obj.hctx, &clone)
		if ptr == 0 {
			return E_OUTOFMEMORY
		}
		ctx.Mem.Write64(ppFont, ptr)
		return S_OK
	case 6:
		ppNames := ctx.Arg(1)
		if ppNames == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppNames, 0)
		ptr := dwriteCreateLocalizedStringsObject(obj.hctx, &dwriteLocalizedStrings{entries: []dwriteLocalizedString{{locale: "en-us", value: fontData.family.name}}})
		if ptr == 0 {
			return E_OUTOFMEMORY
		}
		ctx.Mem.Write64(ppNames, ptr)
		return S_OK
	case 7:
		ppFont := ctx.Arg(4)
		if ppFont == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppFont, 0)
		clone := *fontData
		clone.weight = uint32(ctx.Arg(1))
		clone.stretch = uint32(ctx.Arg(2))
		clone.style = uint32(ctx.Arg(3))
		ptr := dwriteCreateFontObject(obj.hctx, &clone)
		if ptr == 0 {
			return E_OUTOFMEMORY
		}
		ctx.Mem.Write64(ppFont, ptr)
		return S_OK
	default:
		return E_NOTIMPL
	}
}

func dwriteCreateLocalizedStringsObject(hctx *HandlerCtx, values *dwriteLocalizedStrings) uint64 {
	return dwriteCreateObject(hctx, dwriteLocalizedStringsMethods, dwriteDispatchLocalizedStrings, values, IID_IUnknown, IID_IDWriteLocalizedStrings)
}

func dwriteDispatchLocalizedStrings(ctx *ntapi.TrapContext, method int, obj *dwriteCOMObject) uint32 {
	stringsObj, _ := obj.data.(*dwriteLocalizedStrings)
	if stringsObj == nil {
		return E_FAIL
	}

	switch method {
	case 3:
		ctx.SetReturn(uint64(len(stringsObj.entries)))
		return 0
	case 4:
		locale := obj.hctx.ReadGuestUTF16(ctx.Arg(1))
		found := -1
		for i, entry := range stringsObj.entries {
			if strings.EqualFold(entry.locale, locale) {
				found = i
				break
			}
		}
		if found < 0 && len(stringsObj.entries) > 0 {
			found = 0
		}
		if indexPtr := ctx.Arg(2); indexPtr != 0 {
			ctx.Mem.Write32(indexPtr, uint32(found))
		}
		if existsPtr := ctx.Arg(3); existsPtr != 0 {
			ctx.Mem.Write32(existsPtr, boolToUint32(found >= 0))
		}
		return S_OK
	case 5:
		entry, hr := dwriteLocalizedEntry(stringsObj, uint32(ctx.Arg(1)))
		if hr != S_OK {
			return hr
		}
		if out := ctx.Arg(2); out != 0 {
			ctx.Mem.Write32(out, uint32(len(utf16Encode(entry.locale))))
		}
		return S_OK
	case 6:
		entry, hr := dwriteLocalizedEntry(stringsObj, uint32(ctx.Arg(1)))
		if hr != S_OK {
			return hr
		}
		writeGuestUTF16StringN(ctx.Mem, ctx.Arg(2), entry.locale, int(uint32(ctx.Arg(3))))
		return S_OK
	case 7:
		entry, hr := dwriteLocalizedEntry(stringsObj, uint32(ctx.Arg(1)))
		if hr != S_OK {
			return hr
		}
		if out := ctx.Arg(2); out != 0 {
			ctx.Mem.Write32(out, uint32(len(utf16Encode(entry.value))))
		}
		return S_OK
	case 8:
		entry, hr := dwriteLocalizedEntry(stringsObj, uint32(ctx.Arg(1)))
		if hr != S_OK {
			return hr
		}
		writeGuestUTF16StringN(ctx.Mem, ctx.Arg(2), entry.value, int(uint32(ctx.Arg(3))))
		return S_OK
	default:
		return E_NOTIMPL
	}
}

func dwriteLocalizedEntry(stringsObj *dwriteLocalizedStrings, index uint32) (dwriteLocalizedString, uint32) {
	if int(index) < 0 || int(index) >= len(stringsObj.entries) {
		return dwriteLocalizedString{}, E_INVALIDARG
	}
	return stringsObj.entries[index], S_OK
}

func dwriteCreateGdiInteropObject(hctx *HandlerCtx, interop *dwriteGdiInterop) uint64 {
	return dwriteCreateObject(hctx, dwriteGdiInteropMethods, dwriteDispatchGdiInterop, interop, IID_IUnknown, IID_IDWriteGdiInterop)
}

func dwriteDispatchGdiInterop(ctx *ntapi.TrapContext, method int, obj *dwriteCOMObject) uint32 {
	interop, _ := obj.data.(*dwriteGdiInterop)
	if interop == nil {
		return E_FAIL
	}

	switch method {
	case 3:
		ppFont := ctx.Arg(2)
		if ppFont == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppFont, 0)
		font := dwriteFontFromLOGFONT(ctx.Mem, ctx.Arg(1), interop.factory)
		ptr := dwriteCreateFontObject(obj.hctx, font)
		if ptr == 0 {
			return E_OUTOFMEMORY
		}
		ctx.Mem.Write64(ppFont, ptr)
		return S_OK
	case 4:
		fontObj := dwriteLookupObject(ctx.Arg(1))
		if fontObj == nil {
			return E_INVALIDARG
		}
		font, _ := fontObj.data.(*dwriteFont)
		if font == nil {
			return E_INVALIDARG
		}
		dwriteWriteLOGFONT(ctx.Mem, ctx.Arg(2), font.family.name, -12, int32(defaultUint32(font.weight, dwriteFontWeightNormal)), font.style != dwriteFontStyleNormal)
		if out := ctx.Arg(3); out != 0 {
			ctx.Mem.Write32(out, boolToUint32(font.systemFont))
		}
		return S_OK
	case 5:
		faceObj := dwriteLookupObject(ctx.Arg(1))
		if faceObj == nil {
			return E_INVALIDARG
		}
		face, _ := faceObj.data.(*dwriteFontFace)
		if face == nil {
			return E_INVALIDARG
		}
		dwriteWriteLOGFONT(ctx.Mem, ctx.Arg(2), face.familyName, -12, int32(defaultUint32(face.weight, dwriteFontWeightNormal)), face.style != dwriteFontStyleNormal)
		return S_OK
	case 6:
		ppFace := ctx.Arg(2)
		if ppFace == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppFace, 0)
		dc := obj.hctx.GdiMgr.GetDC(ctx.Arg(1))
		if dc == nil {
			return E_INVALIDARG
		}
		f := dc.Font
		if f == nil {
			f = gdi.DefaultFont()
		}
		ptr := dwriteCreateFontFaceObject(obj.hctx, &dwriteFontFace{
			factory:    interop.factory,
			familyName: dwriteFamilyOrDefault(f.FaceName),
			faceID:     f.FaceID,
			weight:     uint32(defaultInt32(f.Weight, dwriteFontWeightNormal)),
			style:      dwriteBoolToStyle(f.Italic),
			stretch:    dwriteFontStretchNormal,
		})
		if ptr == 0 {
			return E_OUTOFMEMORY
		}
		ctx.Mem.Write64(ppFace, ptr)
		return S_OK
	case 7:
		width := int32(ctx.Arg(2))
		height := int32(ctx.Arg(3))
		ppTarget := ctx.Arg(4)
		if ppTarget == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppTarget, 0)
		hdc, memDC := obj.hctx.GdiMgr.AllocMemDC()
		if parent := obj.hctx.GdiMgr.GetDC(ctx.Arg(1)); parent != nil {
			memDC.InheritFrom(parent)
		}
		memDC.WorldTransform = gdi.IdentityXForm()
		memDC.PolyFillMode = 1
		if width <= 0 {
			width = 1
		}
		if height <= 0 {
			height = 1
		}
		hbmp := obj.hctx.GdiMgr.CreateCompatibleBitmap(width, height)
		obj.hctx.GdiMgr.SelectObject(hdc, hbmp)
		ptr := dwriteCreateBitmapRenderTargetObject(obj.hctx, &dwriteBitmapRenderTarget{
			hctx:         obj.hctx,
			hdc:          hdc,
			hbitmap:      hbmp,
			width:        uint32(width),
			height:       uint32(height),
			pixelsPerDip: 1.0,
			transform:    gdi.IdentityXForm(),
		})
		if ptr == 0 {
			return E_OUTOFMEMORY
		}
		ctx.Mem.Write64(ppTarget, ptr)
		return S_OK
	default:
		return E_NOTIMPL
	}
}

func dwriteFontFromLOGFONT(mem *mmu.MMU, ptr uint64, factory *dwriteFactory) *dwriteFont {
	family := strings.TrimSpace(readGuestUTF16String(mem, ptr+28))
	if family == "" {
		family = "Segoe UI"
	}
	weight, _ := mem.Read32(ptr + 16)
	italic, _ := mem.Read8(ptr + 20)
	collection := (*dwriteFontCollection)(nil)
	if factory != nil {
		collection = factory.sysCollection
	}
	return &dwriteFont{
		factory:      factory,
		collection:   collection,
		family:       dwriteFontFamilyEntry{name: family, faceID: gdi.ResolveFontFaceStyle(family, weight >= dwriteFontWeightBold, italic != 0)},
		weight:       defaultUint32(weight, dwriteFontWeightNormal),
		style:        dwriteBoolToStyle(italic != 0),
		stretch:      dwriteFontStretchNormal,
		systemFont:   true,
		familyLocale: "en-us",
	}
}

func dwriteCreateBitmapRenderTargetObject(hctx *HandlerCtx, target *dwriteBitmapRenderTarget) uint64 {
	return dwriteCreateObject(hctx, dwriteBitmapRenderTargetMethods, dwriteDispatchBitmapRenderTarget, target, IID_IUnknown, IID_IDWriteBitmapRenderTarget)
}

func dwriteDispatchBitmapRenderTarget(ctx *ntapi.TrapContext, method int, obj *dwriteCOMObject) uint32 {
	target, _ := obj.data.(*dwriteBitmapRenderTarget)
	if target == nil {
		return E_FAIL
	}

	switch method {
	case 3:
		return dwriteDrawGlyphRunToBitmap(ctx, target)
	case 4:
		ctx.SetReturn(target.hdc)
		return 0
	case 5:
		ctx.SetReturn(uint64(math.Float32bits(float32(target.pixelsPerDip))))
		return 0
	case 6:
		target.pixelsPerDip = float64(math.Float32frombits(uint32(ctx.Arg(1))))
		return S_OK
	case 7:
		if out := ctx.Arg(1); out == 0 {
			return E_POINTER
		} else {
			dwriteWriteMatrix(ctx.Mem, out, target.transform)
		}
		return S_OK
	case 8:
		if mat := ctx.Arg(1); mat != 0 {
			target.transform = dwriteReadMatrix(ctx.Mem, mat)
		}
		return S_OK
	case 9:
		if out := ctx.Arg(1); out == 0 {
			return E_POINTER
		} else {
			ctx.Mem.Write32(out+0, target.width)
			ctx.Mem.Write32(out+4, target.height)
		}
		return S_OK
	case 10:
		width := int32(ctx.Arg(1))
		height := int32(ctx.Arg(2))
		if width <= 0 || height <= 0 {
			return E_INVALIDARG
		}
		hbmp := target.hctx.GdiMgr.CreateCompatibleBitmap(width, height)
		target.hctx.GdiMgr.SelectObject(target.hdc, hbmp)
		target.hbitmap = hbmp
		target.width = uint32(width)
		target.height = uint32(height)
		return S_OK
	case 11:
		target.naturalEmSize = float64(math.Float32frombits(uint32(ctx.Arg(1))))
		return S_OK
	default:
		return E_NOTIMPL
	}
}

func dwriteDrawGlyphRunToBitmap(ctx *ntapi.TrapContext, target *dwriteBitmapRenderTarget) uint32 {
	dc := target.hctx.GdiMgr.GetDC(target.hdc)
	if dc == nil {
		return E_INVALIDARG
	}
	glyphRunPtr := ctx.Arg(4)
	if glyphRunPtr == 0 {
		return E_POINTER
	}

	fontFacePtr, _ := ctx.Mem.Read64(glyphRunPtr + 0)
	fontEmSizeBits, _ := ctx.Mem.Read32(glyphRunPtr + 8)
	glyphCount, _ := ctx.Mem.Read32(glyphRunPtr + 12)
	glyphIndicesPtr, _ := ctx.Mem.Read64(glyphRunPtr + 16)
	glyphAdvancesPtr, _ := ctx.Mem.Read64(glyphRunPtr + 24)
	baselineX := int32(math.Round(float64(math.Float32frombits(uint32(ctx.Arg(1))))))
	baselineY := int32(math.Round(float64(math.Float32frombits(uint32(ctx.Arg(2))))))
	fontSize := float64(math.Float32frombits(fontEmSizeBits))
	if fontSize <= 0 {
		fontSize = 12
	}

	familyName := "Segoe UI"
	weight := uint32(dwriteFontWeightNormal)
	style := uint32(dwriteFontStyleNormal)
	if faceObj := dwriteLookupObject(fontFacePtr); faceObj != nil {
		if face, ok := faceObj.data.(*dwriteFontFace); ok && face != nil {
			familyName = dwriteFamilyOrDefault(face.familyName)
			if face.weight != 0 {
				weight = face.weight
			}
			style = face.style
		}
	}

	oldFont := dc.Font
	oldColor := dc.TextColor
	tmpFont := &gdi.Font{
		Height:   -int32(math.Round(fontSize)),
		Weight:   int32(weight),
		Italic:   style != dwriteFontStyleNormal,
		FaceName: familyName,
	}
	tmpFont.FaceID = gdi.ResolveFontFaceStyle(tmpFont.FaceName, tmpFont.Weight >= dwriteFontWeightBold, tmpFont.Italic)
	if tmpFont.FaceID >= 0 {
		cellH, asc, desc, aveW := gdi.FaceMetrics(tmpFont.FaceID, int32(math.Round(fontSize)))
		tmpFont.CellHeight = cellH
		tmpFont.Ascent = asc
		tmpFont.Descent = desc
		tmpFont.AveCharWidth = aveW
		tmpFont.MaxCharWidth = aveW * 2
	}
	dc.Font = tmpFont
	dc.TextColor = uint32(ctx.Arg(6))

	runes := make([]rune, 0, glyphCount)
	for i := uint32(0); i < glyphCount; i++ {
		glyph, _ := ctx.Mem.Read16(glyphIndicesPtr + uint64(i)*2)
		r := rune(glyph)
		if r == 0 {
			r = '?'
		}
		runes = append(runes, r)
	}
	text := string(runes)
	topY := baselineY - tmpFont.Ascent
	dc.TextOut(baselineX, topY, text, false)

	width := int32(0)
	if glyphAdvancesPtr != 0 {
		for i := uint32(0); i < glyphCount; i++ {
			advBits, _ := ctx.Mem.Read32(glyphAdvancesPtr + uint64(i)*4)
			width += int32(math.Round(float64(math.Float32frombits(advBits))))
		}
	}
	if width == 0 {
		width, _ = dc.TextExtentStr(text)
	}
	if rectPtr := ctx.Arg(7); rectPtr != 0 {
		ctx.Mem.Write32(rectPtr+0, uint32(baselineX))
		ctx.Mem.Write32(rectPtr+4, uint32(topY))
		ctx.Mem.Write32(rectPtr+8, uint32(baselineX+width))
		ctx.Mem.Write32(rectPtr+12, uint32(topY+tmpFont.CellHeight))
	}

	dc.Font = oldFont
	dc.TextColor = oldColor
	return S_OK
}

func dwriteCreateRenderingParamsObject(hctx *HandlerCtx, params *dwriteRenderingParams) uint64 {
	return dwriteCreateObject(hctx, dwriteRenderingParamsMethods, dwriteDispatchRenderingParams, params, IID_IUnknown, IID_IDWriteRenderingParams)
}

func dwriteDispatchRenderingParams(ctx *ntapi.TrapContext, method int, obj *dwriteCOMObject) uint32 {
	params, _ := obj.data.(*dwriteRenderingParams)
	if params == nil {
		return E_FAIL
	}

	switch method {
	case 3:
		ctx.SetReturn(uint64(math.Float32bits(float32(params.gamma))))
		return 0
	case 4:
		ctx.SetReturn(uint64(math.Float32bits(float32(params.enhContrast))))
		return 0
	case 5:
		ctx.SetReturn(uint64(math.Float32bits(float32(params.clearTypeLevel))))
		return 0
	case 6:
		ctx.SetReturn(uint64(params.pixelGeometry))
		return 0
	case 7:
		ctx.SetReturn(uint64(params.renderingMode))
		return 0
	default:
		return E_NOTIMPL
	}
}

func dwriteCreateTextAnalyzerObject(hctx *HandlerCtx, analyzer *dwriteTextAnalyzer) uint64 {
	return dwriteCreateObject(hctx, dwriteTextAnalyzerMethods, dwriteDispatchTextAnalyzer, analyzer, IID_IUnknown, IID_IDWriteTextAnalyzer)
}

func dwriteDispatchTextAnalyzer(ctx *ntapi.TrapContext, method int, obj *dwriteCOMObject) uint32 {
	switch method {
	case 3, 4, 5, 6:
		return S_OK
	case 7:
		textPtr := ctx.Arg(1)
		textLength := uint32(ctx.Arg(2))
		maxGlyphCount := uint32(ctx.Arg(12))
		clusterMapPtr := ctx.Arg(13)
		textPropsPtr := ctx.Arg(14)
		glyphIndicesPtr := ctx.Arg(15)
		glyphPropsPtr := ctx.Arg(16)
		actualGlyphCountPtr := ctx.Arg(17)
		if glyphIndicesPtr == 0 || actualGlyphCountPtr == 0 {
			return E_POINTER
		}
		count := textLength
		if maxGlyphCount > 0 && count > maxGlyphCount {
			count = maxGlyphCount
		}
		for i := uint32(0); i < textLength; i++ {
			w, _ := ctx.Mem.Read16(textPtr + uint64(i)*2)
			mapped := uint16(0)
			if count > 0 {
				mapped = uint16(minUint32(i, count-1))
			}
			if clusterMapPtr != 0 {
				ctx.Mem.Write16(clusterMapPtr+uint64(i)*2, mapped)
			}
			if i < count {
				if w == 0 {
					w = '?'
				}
				ctx.Mem.Write16(glyphIndicesPtr+uint64(i)*2, w)
				if glyphPropsPtr != 0 {
					ctx.Mem.Write16(glyphPropsPtr+uint64(i)*2, 0)
				}
			}
			if textPropsPtr != 0 {
				ctx.Mem.Write16(textPropsPtr+uint64(i)*2, 0)
			}
		}
		ctx.Mem.Write32(actualGlyphCountPtr, count)
		return S_OK
	case 8:
		glyphIndicesPtr := ctx.Arg(5)
		glyphCount := uint32(ctx.Arg(7))
		fontFaceObj := dwriteLookupObject(ctx.Arg(8))
		fontSize := float64(math.Float32frombits(uint32(ctx.Arg(9))))
		glyphAdvancesPtr := ctx.Arg(16)
		glyphOffsetsPtr := ctx.Arg(17)
		if glyphAdvancesPtr == 0 {
			return E_POINTER
		}
		faceID := -1
		family := "Segoe UI"
		weight := uint32(dwriteFontWeightNormal)
		style := uint32(dwriteFontStyleNormal)
		if fontFaceObj != nil {
			if face, ok := fontFaceObj.data.(*dwriteFontFace); ok && face != nil {
				family = dwriteFamilyOrDefault(face.familyName)
				faceID = face.faceID
				weight = face.weight
				style = face.style
			}
		}
		if faceID < 0 {
			faceID = gdi.ResolveFontFaceStyle(family, weight >= dwriteFontWeightBold, style != dwriteFontStyleNormal)
		}
		for i := uint32(0); i < glyphCount; i++ {
			glyph, _ := ctx.Mem.Read16(glyphIndicesPtr + uint64(i)*2)
			adv := dwriteAverageAdvanceForFace(faceID, fontSize, rune(glyph))
			ctx.Mem.Write32(glyphAdvancesPtr+uint64(i)*4, math.Float32bits(float32(adv)))
			if glyphOffsetsPtr != 0 {
				ctx.Mem.Write32(glyphOffsetsPtr+uint64(i)*8+0, 0)
				ctx.Mem.Write32(glyphOffsetsPtr+uint64(i)*8+4, 0)
			}
		}
		return S_OK
	default:
		return E_NOTIMPL
	}
}

func dwriteCreateFontObject(hctx *HandlerCtx, font *dwriteFont) uint64 {
	return dwriteCreateObject(hctx, dwriteFontMethods, dwriteDispatchFont, font, IID_IUnknown, IID_IDWriteFont)
}

func dwriteDispatchFont(ctx *ntapi.TrapContext, method int, obj *dwriteCOMObject) uint32 {
	font, _ := obj.data.(*dwriteFont)
	if font == nil {
		return E_FAIL
	}

	switch method {
	case 3:
		ppFamily := ctx.Arg(1)
		if ppFamily == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppFamily, 0)
		if font.collection != nil {
			ptr := dwriteCreateFontFamilyObject(obj.hctx, font.collection, font.family)
			if ptr == 0 {
				return E_OUTOFMEMORY
			}
			ctx.Mem.Write64(ppFamily, ptr)
		}
		return S_OK
	case 4:
		ctx.SetReturn(uint64(font.weight))
		return 0
	case 5:
		ctx.SetReturn(uint64(font.stretch))
		return 0
	case 6:
		ctx.SetReturn(uint64(font.style))
		return 0
	case 7:
		ctx.SetReturn(0)
		return 0
	case 8:
		ppNames := ctx.Arg(1)
		if ppNames == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppNames, 0)
		ptr := dwriteCreateLocalizedStringsObject(obj.hctx, &dwriteLocalizedStrings{entries: []dwriteLocalizedString{{locale: font.familyLocale, value: font.family.name}}})
		if ptr == 0 {
			return E_OUTOFMEMORY
		}
		ctx.Mem.Write64(ppNames, ptr)
		return S_OK
	case 10:
		ctx.SetReturn(0)
		return 0
	case 11:
		if out := ctx.Arg(1); out != 0 {
			for i := 0; i < 24; i += 4 {
				ctx.Mem.Write32(out+uint64(i), 0)
			}
		}
		return S_OK
	case 12:
		if exists := ctx.Arg(2); exists != 0 {
			ctx.Mem.Write32(exists, 1)
		}
		return S_OK
	case 13:
		ppFace := ctx.Arg(1)
		if ppFace == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppFace, 0)
		ptr := dwriteCreateFontFaceObject(obj.hctx, &dwriteFontFace{
			factory:    font.factory,
			familyName: font.family.name,
			faceID:     font.family.faceID,
			weight:     font.weight,
			style:      font.style,
			stretch:    font.stretch,
		})
		if ptr == 0 {
			return E_OUTOFMEMORY
		}
		ctx.Mem.Write64(ppFace, ptr)
		return S_OK
	default:
		return E_NOTIMPL
	}
}

func dwriteCreateFontFaceObject(hctx *HandlerCtx, face *dwriteFontFace) uint64 {
	return dwriteCreateObject(hctx, dwriteFontFaceMethods, nil, face, IID_IUnknown, IID_IDWriteFontFace)
}

func dwriteEnsureLayout(layout *dwriteTextLayout) {
	lineHeight, baseline := dwriteLineGeometry(&layout.dwriteTextFormat)
	maxWidth := layout.maxWidth
	wrap := maxWidth > 0 && layout.wordWrapping != dwriteWordWrappingNoWrap
	lines := make([]dwriteLineInfo, 0, 4)
	currentLen := uint32(0)
	currentWidth := 0.0
	flush := func() {
		lines = append(lines, dwriteLineInfo{length: currentLen, width: currentWidth, baseline: baseline, height: lineHeight})
		currentLen = 0
		currentWidth = 0
	}
	if len(layout.text) == 0 {
		flush()
		layout.lines = lines
		return
	}
	for _, r := range layout.text {
		if r == '\r' {
			continue
		}
		if r == '\n' {
			flush()
			continue
		}
		adv := dwriteAverageAdvanceForFormat(&layout.dwriteTextFormat, r)
		if wrap && currentLen > 0 && currentWidth+adv > maxWidth {
			flush()
		}
		currentLen++
		currentWidth += adv
	}
	flush()
	layout.lines = lines
}

func dwriteAverageAdvance(format *dwriteTextFormat) float64 {
	return dwriteAverageAdvanceForFormat(format, 'x')
}

func dwriteAverageAdvanceForFormat(format *dwriteTextFormat, r rune) float64 {
	if format == nil {
		return 7.2
	}
	faceID := gdi.ResolveFontFaceStyle(format.fontFamily, format.fontWeight >= dwriteFontWeightBold, format.fontStyle != dwriteFontStyleNormal)
	return dwriteAverageAdvanceForFace(faceID, format.fontSize, r)
}

func dwriteAverageAdvanceForFace(faceID int, fontSize float64, r rune) float64 {
	pix := int32(math.Round(fontSize))
	if pix <= 0 {
		pix = 12
	}
	if faceID >= 0 {
		if glyph := gdi.GlyphFor(faceID, pix, r); glyph != nil && glyph.Advance > 0 {
			return float64(glyph.Advance)
		}
		_, _, _, aveW := gdi.FaceMetrics(faceID, pix)
		if aveW > 0 {
			return float64(aveW)
		}
	}
	if fontSize <= 0 {
		fontSize = 12
	}
	if r == ' ' {
		return fontSize * 0.35
	}
	return fontSize * 0.6
}

func dwriteLineGeometry(format *dwriteTextFormat) (float64, float64) {
	if format == nil {
		return 14.4, 11.0
	}
	faceID := gdi.ResolveFontFaceStyle(format.fontFamily, format.fontWeight >= dwriteFontWeightBold, format.fontStyle != dwriteFontStyleNormal)
	pix := int32(math.Round(format.fontSize))
	if pix <= 0 {
		pix = 12
	}
	lineHeight := format.lineSpacing
	baseline := format.baseline
	if faceID >= 0 {
		cellH, asc, _, _ := gdi.FaceMetrics(faceID, pix)
		if lineHeight <= 0 {
			lineHeight = float64(cellH)
		}
		if baseline <= 0 {
			baseline = float64(asc)
		}
	}
	if lineHeight <= 0 {
		lineHeight = format.fontSize * 1.2
	}
	if baseline <= 0 {
		baseline = lineHeight * 0.8
	}
	return lineHeight, baseline
}

func dwriteTextMetricsForLayout(layout *dwriteTextLayout) dwriteTextMetrics {
	dwriteEnsureLayout(layout)
	metrics := dwriteTextMetrics{}
	for _, line := range layout.lines {
		if line.width > metrics.width {
			metrics.width = line.width
			metrics.widthWithTrailing = line.width
		}
		metrics.height += line.height
	}
	metrics.layoutWidth = layout.maxWidth
	if metrics.layoutWidth <= 0 {
		metrics.layoutWidth = metrics.width
	}
	metrics.layoutHeight = layout.maxHeight
	if metrics.layoutHeight <= 0 {
		metrics.layoutHeight = metrics.height
	}
	metrics.lineCount = uint32(len(layout.lines))
	return metrics
}

func dwriteWriteTextMetrics(mem *mmu.MMU, addr uint64, metrics dwriteTextMetrics) {
	mem.Write32(addr+0, math.Float32bits(float32(metrics.left)))
	mem.Write32(addr+4, math.Float32bits(float32(metrics.top)))
	mem.Write32(addr+8, math.Float32bits(float32(metrics.width)))
	mem.Write32(addr+12, math.Float32bits(float32(metrics.widthWithTrailing)))
	mem.Write32(addr+16, math.Float32bits(float32(metrics.height)))
	mem.Write32(addr+20, math.Float32bits(float32(metrics.layoutWidth)))
	mem.Write32(addr+24, math.Float32bits(float32(metrics.layoutHeight)))
	mem.Write32(addr+28, 1)
	mem.Write32(addr+32, metrics.lineCount)
}

func dwriteWriteTextRange(mem *mmu.MMU, addr uint64, start, length uint32) {
	mem.Write32(addr+0, start)
	mem.Write32(addr+4, length)
}

func dwriteDetermineMinWidth(layout *dwriteTextLayout) float64 {
	longest := 0.0
	current := 0.0
	for _, r := range layout.text {
		switch r {
		case ' ', '\t', '\r', '\n':
			if current > longest {
				longest = current
			}
			current = 0
		default:
			current += dwriteAverageAdvanceForFormat(&layout.dwriteTextFormat, r)
		}
	}
	if current > longest {
		longest = current
	}
	return longest
}

func dwriteHitTestPoint(ctx *ntapi.TrapContext, layout *dwriteTextLayout) uint32 {
	pointX := float64(math.Float32frombits(uint32(ctx.Arg(1))))
	pointY := float64(math.Float32frombits(uint32(ctx.Arg(2))))
	metrics := dwriteTextMetricsForLayout(layout)
	lineHeight, _ := dwriteLineGeometry(&layout.dwriteTextFormat)
	inside := pointX >= 0 && pointY >= 0 && pointX <= metrics.layoutWidth && pointY <= metrics.height
	if ptr := ctx.Arg(3); ptr != 0 {
		ctx.Mem.Write32(ptr, 0)
	}
	if ptr := ctx.Arg(4); ptr != 0 {
		ctx.Mem.Write32(ptr, boolToUint32(inside))
	}
	if ptr := ctx.Arg(5); ptr != 0 {
		line := uint32(0)
		if lineHeight > 0 {
			line = uint32(pointY / lineHeight)
		}
		pos := uint32(pointX / maxFloat64(dwriteAverageAdvance(&layout.dwriteTextFormat), 1))
		dwriteWriteHitTestMetrics(ctx.Mem, ptr, pos, 1, pointX, float64(line)*lineHeight, dwriteAverageAdvance(&layout.dwriteTextFormat), lineHeight)
	}
	return S_OK
}

func dwriteHitTestTextPosition(ctx *ntapi.TrapContext, layout *dwriteTextLayout) uint32 {
	textPosition := uint32(ctx.Arg(1))
	lineHeight, _ := dwriteLineGeometry(&layout.dwriteTextFormat)
	advance := dwriteAverageAdvance(&layout.dwriteTextFormat)
	x := float64(textPosition) * advance
	y := 0.0
	if ptr := ctx.Arg(3); ptr != 0 {
		ctx.Mem.Write32(ptr, math.Float32bits(float32(x)))
	}
	if ptr := ctx.Arg(4); ptr != 0 {
		ctx.Mem.Write32(ptr, math.Float32bits(float32(y)))
	}
	if ptr := ctx.Arg(5); ptr != 0 {
		dwriteWriteHitTestMetrics(ctx.Mem, ptr, textPosition, 1, x, y, advance, lineHeight)
	}
	return S_OK
}

func dwriteHitTestTextRange(ctx *ntapi.TrapContext, layout *dwriteTextLayout) uint32 {
	textPosition := uint32(ctx.Arg(1))
	textLength := uint32(ctx.Arg(2))
	originX := float64(math.Float32frombits(uint32(ctx.Arg(3))))
	originY := float64(math.Float32frombits(uint32(ctx.Arg(4))))
	metricsPtr := ctx.Arg(5)
	maxCount := uint32(ctx.Arg(6))
	if actualPtr := ctx.Arg(7); actualPtr != 0 {
		ctx.Mem.Write32(actualPtr, 1)
	}
	if metricsPtr == 0 || maxCount == 0 {
		return E_POINTER
	}
	lineHeight, _ := dwriteLineGeometry(&layout.dwriteTextFormat)
	advance := dwriteAverageAdvance(&layout.dwriteTextFormat)
	dwriteWriteHitTestMetrics(ctx.Mem, metricsPtr, textPosition, textLength, originX, originY, float64(textLength)*advance, lineHeight)
	return S_OK
}

func dwriteWriteHitTestMetrics(mem *mmu.MMU, addr uint64, textPosition, length uint32, left, top, width, height float64) {
	mem.Write32(addr+0, textPosition)
	mem.Write32(addr+4, length)
	mem.Write32(addr+8, math.Float32bits(float32(left)))
	mem.Write32(addr+12, math.Float32bits(float32(top)))
	mem.Write32(addr+16, math.Float32bits(float32(width)))
	mem.Write32(addr+20, math.Float32bits(float32(height)))
	mem.Write32(addr+24, 0)
	mem.Write32(addr+28, 1)
	mem.Write32(addr+32, 0)
}

func dwriteWriteMatrix(mem *mmu.MMU, addr uint64, xf gdi.XForm) {
	mem.Write32(addr+0, math.Float32bits(xf.EM11))
	mem.Write32(addr+4, math.Float32bits(xf.EM12))
	mem.Write32(addr+8, math.Float32bits(xf.EM21))
	mem.Write32(addr+12, math.Float32bits(xf.EM22))
	mem.Write32(addr+16, math.Float32bits(xf.EDx))
	mem.Write32(addr+20, math.Float32bits(xf.EDy))
}

func dwriteReadMatrix(mem *mmu.MMU, addr uint64) gdi.XForm {
	m11, _ := mem.Read32(addr + 0)
	m12, _ := mem.Read32(addr + 4)
	m21, _ := mem.Read32(addr + 8)
	m22, _ := mem.Read32(addr + 12)
	dx, _ := mem.Read32(addr + 16)
	dy, _ := mem.Read32(addr + 20)
	return gdi.XForm{
		EM11: math.Float32frombits(m11),
		EM12: math.Float32frombits(m12),
		EM21: math.Float32frombits(m21),
		EM22: math.Float32frombits(m22),
		EDx:  math.Float32frombits(dx),
		EDy:  math.Float32frombits(dy),
	}
}

func dwriteWriteLOGFONT(mem *mmu.MMU, addr uint64, family string, height, weight int32, italic bool) {
	if addr == 0 {
		return
	}
	mem.Write32(addr+0, uint32(height))
	mem.Write32(addr+4, 0)
	mem.Write32(addr+8, 0)
	mem.Write32(addr+12, 0)
	mem.Write32(addr+16, uint32(weight))
	if italic {
		mem.Write8(addr+20, 1)
	} else {
		mem.Write8(addr+20, 0)
	}
	mem.Write8(addr+21, 0)
	mem.Write8(addr+22, 0)
	mem.Write8(addr+23, 0)
	mem.Write8(addr+24, 0)
	mem.Write8(addr+25, 0)
	mem.Write8(addr+26, 0)
	mem.Write8(addr+27, 0)
	writeGuestUTF16StringN(mem, addr+28, family, 32)
}

func dwriteFamilyOrDefault(name string) string {
	if strings.TrimSpace(name) == "" {
		return "Segoe UI"
	}
	return name
}

func dwriteBoolToStyle(v bool) uint32 {
	if v {
		return dwriteFontStyleItalic
	}
	return dwriteFontStyleNormal
}

func boolToUint32(v bool) uint32 {
	if v {
		return 1
	}
	return 0
}

func defaultUint32(v, def uint32) uint32 {
	if v == 0 {
		return def
	}
	return v
}

func defaultInt32(v int32, def uint32) int32 {
	if v == 0 {
		return int32(def)
	}
	return v
}

func minUint32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

func maxFloat64(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

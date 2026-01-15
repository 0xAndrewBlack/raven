package main

import (
	"bytes"
	"encoding/binary"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
	_ "golang.org/x/image/bmp"
)

var (
	IID_IWICBitmapSource        = GUID{0x00000120, 0xA8F2, 0x4877, [8]byte{0xBA, 0x0A, 0xFD, 0x2B, 0x66, 0x45, 0xFB, 0x94}}
	IID_IWICBitmap              = GUID{0x00000121, 0xA8F2, 0x4877, [8]byte{0xBA, 0x0A, 0xFD, 0x2B, 0x66, 0x45, 0xFB, 0x94}}
	IID_IWICComponentInfo       = GUID{0x23BC3F0A, 0x698B, 0x4357, [8]byte{0x88, 0x6B, 0xF2, 0x4D, 0x50, 0x67, 0x13, 0x34}}
	IID_IWICBitmapFrameDecode   = GUID{0x3B16811B, 0x6A43, 0x4EC9, [8]byte{0xA8, 0x13, 0x3D, 0x93, 0x0C, 0x13, 0xB9, 0x40}}
	IID_IWICBitmapDecoderInfo   = GUID{0xD8CD007F, 0xD08F, 0x4191, [8]byte{0x9B, 0xFC, 0x23, 0x6E, 0xA7, 0xF0, 0xE4, 0xB5}}
	IID_IWICBitmapDecoder       = GUID{0x9EDDE9E7, 0x8DEE, 0x47EA, [8]byte{0x99, 0xDF, 0xE6, 0xFA, 0xF2, 0xED, 0x44, 0xBF}}
	IID_IWICFormatConverter     = GUID{0x00000301, 0xA8F2, 0x4877, [8]byte{0xBA, 0x0A, 0xFD, 0x2B, 0x66, 0x45, 0xFB, 0x94}}
	IID_IWICFormatConverterInfo = GUID{0x9F34FB65, 0x13F4, 0x4F15, [8]byte{0xBC, 0x57, 0x37, 0x26, 0xB5, 0xE5, 0x3D, 0x9F}}
	IID_IWICStream              = GUID{0x135FF860, 0x22B7, 0x4DDF, [8]byte{0xB0, 0xF6, 0x21, 0x8F, 0x4F, 0x29, 0x9A, 0x43}}
	IID_IWICImagingFactory      = GUID{0xEC5EC8A9, 0xC395, 0x4314, [8]byte{0x9C, 0x77, 0x54, 0xD7, 0xA9, 0x35, 0xFF, 0x70}}
	IID_IWICImagingFactory2     = GUID{0x7B816B45, 0x1996, 0x4476, [8]byte{0xB1, 0x32, 0xDE, 0x9E, 0x24, 0x7C, 0x8A, 0xF0}}

	CLSID_WICImagingFactory         = GUID{0xCACAF262, 0x9370, 0x4615, [8]byte{0xA1, 0x3B, 0x9F, 0x55, 0x39, 0xDA, 0x4C, 0x0A}}
	CLSID_WICImagingFactory2        = GUID{0x317D06E8, 0x5F24, 0x433D, [8]byte{0xBD, 0xF7, 0x79, 0xCE, 0x68, 0xD8, 0xAB, 0xC2}}
	CLSID_WICPngDecoder             = GUID{0x389EA17B, 0x5078, 0x4CDE, [8]byte{0xB6, 0xEF, 0x25, 0xC1, 0x51, 0x75, 0xC7, 0x51}}
	CLSID_WICBmpDecoder             = GUID{0x6B462062, 0x7CBF, 0x400D, [8]byte{0x9F, 0xDB, 0x81, 0x3D, 0xD1, 0x0F, 0x27, 0x78}}
	CLSID_WICIcoDecoder             = GUID{0xC61BFCDF, 0x2E0F, 0x4AAD, [8]byte{0xA8, 0xD7, 0xE0, 0x6B, 0xAF, 0xEB, 0xCD, 0xFE}}
	CLSID_WICJpegDecoder            = GUID{0x9456A480, 0xE88B, 0x43EA, [8]byte{0x9E, 0x73, 0x0B, 0x2D, 0x9B, 0x71, 0xB1, 0xCA}}
	CLSID_WICGifDecoder             = GUID{0x381DDA3C, 0x9CE9, 0x4834, [8]byte{0xA2, 0x3E, 0x1F, 0x98, 0xF8, 0xFC, 0x52, 0xBE}}
	CLSID_WICBitmapEncoder          = GUID{0x69BE8BB4, 0xD66D, 0x47C8, [8]byte{0x86, 0x5A, 0xED, 0x15, 0x89, 0x43, 0x37, 0x82}}
	CLSID_WICDefaultFormatConverter = GUID{0x1A3F11DC, 0xB514, 0x4B17, [8]byte{0x8C, 0x5F, 0x21, 0x54, 0x51, 0x38, 0x52, 0xF1}}

	GUID_WICPixelFormat32bppBGRA   = GUID{0x6FDDC324, 0x4E03, 0x4BFE, [8]byte{0xB1, 0x85, 0x3D, 0x77, 0x76, 0x8D, 0xC9, 0x0F}}
	GUID_WICPixelFormat32bppBGR    = GUID{0x6FDDC324, 0x4E03, 0x4BFE, [8]byte{0xB1, 0x85, 0x3D, 0x77, 0x76, 0x8D, 0xC9, 0x08}}
	GUID_WICPixelFormat24bppBGR    = GUID{0x6FDDC324, 0x4E03, 0x4BFE, [8]byte{0xB1, 0x85, 0x3D, 0x77, 0x76, 0x8D, 0xC9, 0x0C}}
	GUID_WICPixelFormat8bppIndexed = GUID{0x6FDDC324, 0x4E03, 0x4BFE, [8]byte{0xB1, 0x85, 0x3D, 0x77, 0x76, 0x8D, 0xC9, 0x04}}

	GUID_ContainerFormatBmp  = GUID{0x0AF1D87E, 0xFCFE, 0x4188, [8]byte{0xBD, 0xEB, 0xA7, 0x90, 0x64, 0x71, 0xCB, 0xE3}}
	GUID_ContainerFormatPng  = GUID{0x1B7CFAF4, 0x713F, 0x473C, [8]byte{0xBB, 0xCD, 0x61, 0x37, 0x42, 0x5F, 0xAE, 0xAF}}
	GUID_ContainerFormatIco  = GUID{0xA3A860C4, 0x338F, 0x4C17, [8]byte{0x91, 0x9A, 0xFB, 0xA4, 0xB5, 0x62, 0x8F, 0x21}}
	GUID_ContainerFormatJpeg = GUID{0x19E4A5AA, 0x5662, 0x4FC5, [8]byte{0xA0, 0xC0, 0x17, 0x58, 0x02, 0x8E, 0x10, 0x57}}
	GUID_ContainerFormatGif  = GUID{0x1F8A5601, 0x7D4D, 0x4CBD, [8]byte{0x9C, 0x82, 0x1B, 0xC8, 0xD4, 0xEE, 0xB9, 0xA5}}
)

const (
	WINCODEC_ERR_WRONGSTATE             = 0x88982F04
	WINCODEC_ERR_NOTINITIALIZED         = 0x88982F0C
	WINCODEC_ERR_CODECNOTHUMBNAIL       = 0x88982F44
	WINCODEC_ERR_PALETTEUNAVAILABLE     = 0x88982F45
	WINCODEC_ERR_COMPONENTNOTFOUND      = 0x88982F50
	WINCODEC_ERR_BADIMAGE               = 0x88982F60
	WINCODEC_ERR_FRAMEMISSING           = 0x88982F62
	WINCODEC_ERR_STREAMREAD             = 0x88982F72
	WINCODEC_ERR_UNSUPPORTEDPIXELFORMAT = 0x88982F80
	WINCODEC_ERR_UNSUPPORTEDOPERATION   = 0x88982F81

	wicComponentDecoder              = 0x00000001
	wicComponentPixelFormatConverter = 0x00000004
	wicComponentUnsignedSafe         = 0x00000006

	wicBitmapDecoderCapabilityAllImages = 0x00000002
)

type wicBitmap struct {
	width       int
	height      int
	pixels      []byte
	dpiX        float64
	dpiY        float64
	pixelFormat GUID
}

type wicDecoder struct {
	clsid       GUID
	format      GUID
	frames      []*wicBitmap
	initialized bool
}

type wicFormatConverter struct {
	sourcePtr   uint64
	dstFormat   GUID
	initialized bool
}

type wicStream struct {
	data interface{}
	name string
}

type wicComponentInfoData struct {
	clsid              GUID
	componentType      uint32
	friendlyName       string
	author             string
	version            string
	specVersion        string
	containerFormat    GUID
	fileExtensions     string
	mimeTypes          string
	pixelFormats       []GUID
	supportsMultiframe bool
	create             func() (*comObject, error)
}

type wicRect struct {
	X      int32
	Y      int32
	Width  int32
	Height int32
}

func registerWICClassFactories(cs *comState) {
	cs.classFactories[CLSID_WICImagingFactory] = &classFactory{
		clsid: CLSID_WICImagingFactory,
		create: func(iid GUID) (*comObject, error) {
			return cs.createWICFactoryObject(CLSID_WICImagingFactory, iid)
		},
	}
	cs.classFactories[CLSID_WICImagingFactory2] = &classFactory{
		clsid: CLSID_WICImagingFactory2,
		create: func(iid GUID) (*comObject, error) {
			return cs.createWICFactoryObject(CLSID_WICImagingFactory2, iid)
		},
	}
	for _, clsid := range []GUID{CLSID_WICPngDecoder, CLSID_WICBmpDecoder, CLSID_WICIcoDecoder, CLSID_WICJpegDecoder, CLSID_WICGifDecoder} {
		current := clsid
		cs.classFactories[current] = &classFactory{
			clsid: current,
			create: func(iid GUID) (*comObject, error) {
				if !guidEqual(iid, IID_IUnknown) && !guidEqual(iid, IID_IWICBitmapDecoder) {
					return nil, hresultError(E_NOINTERFACE)
				}
				return cs.createWICDecoderObject(current)
			},
		}
	}
	cs.classFactories[CLSID_WICDefaultFormatConverter] = &classFactory{
		clsid: CLSID_WICDefaultFormatConverter,
		create: func(iid GUID) (*comObject, error) {
			if !guidEqual(iid, IID_IUnknown) && !guidEqual(iid, IID_IWICFormatConverter) && !guidEqual(iid, IID_IWICBitmapSource) {
				return nil, hresultError(E_NOINTERFACE)
			}
			return cs.createWICFormatConverterObject()
		},
	}
}

func (cs *comState) createWICFactoryObject(clsid, iid GUID) (*comObject, error) {
	if !guidEqual(iid, IID_IUnknown) && !guidEqual(iid, IID_IWICImagingFactory) && !guidEqual(iid, IID_IWICImagingFactory2) {
		return nil, hresultError(E_NOINTERFACE)
	}
	obj, err := cs.createGuestObject(cs.mem, IID_IWICImagingFactory2, 29)
	if err != nil {
		return nil, err
	}
	obj.clsid = clsid
	obj.kind = "wic-factory"
	obj.supportedIIDs[IID_IWICImagingFactory] = true
	obj.supportedIIDs[IID_IWICImagingFactory2] = true
	return obj, nil
}

func (cs *comState) createWICDecoderObject(clsid GUID) (*comObject, error) {
	obj, err := cs.createGuestObject(cs.mem, IID_IWICBitmapDecoder, 14)
	if err != nil {
		return nil, err
	}
	obj.clsid = clsid
	obj.kind = "wic-decoder"
	obj.supportedIIDs[IID_IWICBitmapDecoder] = true
	obj.data = &wicDecoder{clsid: clsid, format: wicContainerFormatFromCLSID(clsid)}
	return obj, nil
}

func (cs *comState) createWICFrameObject(bitmap *wicBitmap) (*comObject, error) {
	obj, err := cs.createGuestObject(cs.mem, IID_IWICBitmapFrameDecode, 11)
	if err != nil {
		return nil, err
	}
	obj.kind = "wic-frame"
	obj.supportedIIDs[IID_IWICBitmapSource] = true
	obj.supportedIIDs[IID_IWICBitmapFrameDecode] = true
	obj.data = bitmap
	return obj, nil
}

func (cs *comState) createWICFormatConverterObject() (*comObject, error) {
	obj, err := cs.createGuestObject(cs.mem, IID_IWICFormatConverter, 10)
	if err != nil {
		return nil, err
	}
	obj.kind = "wic-format-converter"
	obj.supportedIIDs[IID_IWICBitmapSource] = true
	obj.supportedIIDs[IID_IWICFormatConverter] = true
	obj.data = &wicFormatConverter{}
	return obj, nil
}

func (cs *comState) createWICBitmapObject(bitmap *wicBitmap) (*comObject, error) {
	obj, err := cs.createGuestObject(cs.mem, IID_IWICBitmap, 11)
	if err != nil {
		return nil, err
	}
	obj.kind = "wic-bitmap"
	obj.supportedIIDs[IID_IWICBitmapSource] = true
	obj.supportedIIDs[IID_IWICBitmap] = true
	obj.data = bitmap
	return obj, nil
}

func (cs *comState) createWICStreamObject() (*comObject, error) {
	obj, err := cs.createGuestObject(cs.mem, IID_IWICStream, 18)
	if err != nil {
		return nil, err
	}
	obj.kind = "wic-stream"
	obj.supportedIIDs[IID_IWICStream] = true
	obj.supportedIIDs[IID_IStream] = true
	obj.data = &wicStream{}
	return obj, nil
}

func (cs *comState) createWICComponentInfoObject(clsid GUID) (*comObject, error) {
	info, iid, methods, err := cs.wicComponentInfoForCLSID(clsid)
	if err != nil {
		return nil, err
	}
	obj, err := cs.createGuestObject(cs.mem, iid, methods)
	if err != nil {
		return nil, err
	}
	obj.clsid = clsid
	obj.kind = "wic-component-info"
	obj.supportedIIDs[IID_IWICComponentInfo] = true
	if guidEqual(iid, IID_IWICBitmapDecoderInfo) {
		obj.supportedIIDs[IID_IWICBitmapDecoderInfo] = true
	}
	if guidEqual(iid, IID_IWICFormatConverterInfo) {
		obj.supportedIIDs[IID_IWICFormatConverterInfo] = true
	}
	obj.data = info
	return obj, nil
}

func (cs *comState) wicComponentInfoForCLSID(clsid GUID) (*wicComponentInfoData, GUID, int, error) {
	makeDecoder := func(factoryCLSID GUID) func() (*comObject, error) {
		return func() (*comObject, error) { return cs.createWICDecoderObject(factoryCLSID) }
	}
	switch {
	case guidEqual(clsid, CLSID_WICPngDecoder):
		return &wicComponentInfoData{
			clsid:              clsid,
			componentType:      wicComponentDecoder,
			friendlyName:       "Go VM PNG Decoder",
			author:             "Raven",
			version:            "1.0",
			specVersion:        "1.0",
			containerFormat:    GUID_ContainerFormatPng,
			fileExtensions:     ".png",
			mimeTypes:          "image/png",
			pixelFormats:       []GUID{GUID_WICPixelFormat32bppBGRA},
			supportsMultiframe: false,
			create:             makeDecoder(clsid),
		}, IID_IWICBitmapDecoderInfo, 23, nil
	case guidEqual(clsid, CLSID_WICBmpDecoder):
		return &wicComponentInfoData{
			clsid:              clsid,
			componentType:      wicComponentDecoder,
			friendlyName:       "Go VM BMP Decoder",
			author:             "Raven",
			version:            "1.0",
			specVersion:        "1.0",
			containerFormat:    GUID_ContainerFormatBmp,
			fileExtensions:     ".bmp;.dib",
			mimeTypes:          "image/bmp",
			pixelFormats:       []GUID{GUID_WICPixelFormat32bppBGRA},
			supportsMultiframe: false,
			create:             makeDecoder(clsid),
		}, IID_IWICBitmapDecoderInfo, 23, nil
	case guidEqual(clsid, CLSID_WICIcoDecoder):
		return &wicComponentInfoData{
			clsid:              clsid,
			componentType:      wicComponentDecoder,
			friendlyName:       "Go VM ICO Decoder",
			author:             "Raven",
			version:            "1.0",
			specVersion:        "1.0",
			containerFormat:    GUID_ContainerFormatIco,
			fileExtensions:     ".ico",
			mimeTypes:          "image/x-icon;image/vnd.microsoft.icon",
			pixelFormats:       []GUID{GUID_WICPixelFormat32bppBGRA},
			supportsMultiframe: true,
			create:             makeDecoder(clsid),
		}, IID_IWICBitmapDecoderInfo, 23, nil
	case guidEqual(clsid, CLSID_WICJpegDecoder):
		return &wicComponentInfoData{
			clsid:              clsid,
			componentType:      wicComponentDecoder,
			friendlyName:       "Go VM JPEG Decoder",
			author:             "Raven",
			version:            "1.0",
			specVersion:        "1.0",
			containerFormat:    GUID_ContainerFormatJpeg,
			fileExtensions:     ".jpg;.jpeg;.jpe;.jfif",
			mimeTypes:          "image/jpeg",
			pixelFormats:       []GUID{GUID_WICPixelFormat32bppBGRA},
			supportsMultiframe: false,
			create:             makeDecoder(clsid),
		}, IID_IWICBitmapDecoderInfo, 23, nil
	case guidEqual(clsid, CLSID_WICGifDecoder):
		return &wicComponentInfoData{
			clsid:              clsid,
			componentType:      wicComponentDecoder,
			friendlyName:       "Go VM GIF Decoder",
			author:             "Raven",
			version:            "1.0",
			specVersion:        "1.0",
			containerFormat:    GUID_ContainerFormatGif,
			fileExtensions:     ".gif",
			mimeTypes:          "image/gif",
			pixelFormats:       []GUID{GUID_WICPixelFormat32bppBGRA},
			supportsMultiframe: false,
			create:             makeDecoder(clsid),
		}, IID_IWICBitmapDecoderInfo, 23, nil
	case guidEqual(clsid, CLSID_WICDefaultFormatConverter):
		return &wicComponentInfoData{
			clsid:         clsid,
			componentType: wicComponentPixelFormatConverter,
			friendlyName:  "Go VM Format Converter",
			author:        "Raven",
			version:       "1.0",
			specVersion:   "1.0",
			pixelFormats:  []GUID{GUID_WICPixelFormat32bppBGRA, GUID_WICPixelFormat32bppBGR, GUID_WICPixelFormat24bppBGR, GUID_WICPixelFormat8bppIndexed},
			create:        func() (*comObject, error) { return cs.createWICFormatConverterObject() },
		}, IID_IWICFormatConverterInfo, 13, nil
	default:
		return nil, GUID{}, 0, hresultError(WINCODEC_ERR_COMPONENTNOTFOUND)
	}
}

func registerWindowsCodecsHandlers(hctx *HandlerCtx) {
	dll, ok := hctx.SynthByName["windowscodecs.dll"]
	if !ok {
		return
	}
	cs := hctx.Com
	if cs == nil {
		cs = newCOMState(hctx)
		hctx.Com = cs
	}
	d := hctx.Disp
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

func resolveWICHostPath(imagePath, filePath string) string {
	filePath = strings.TrimSpace(filePath)
	if filePath == "" {
		return ""
	}
	if strings.Contains(filePath, `\`) || (len(filePath) >= 2 && filePath[1] == ':') {
		return winToLinuxPath(filePath)
	}
	if filepath.IsAbs(filePath) {
		return filepath.Clean(filePath)
	}
	base := "/"
	if imagePath != "" {
		base = filepath.Dir(winToLinuxPath(imagePath))
	}
	return filepath.Clean(filepath.Join(base, filePath))
}

func wicContainerFormatFromCLSID(clsid GUID) GUID {
	switch {
	case guidEqual(clsid, CLSID_WICPngDecoder):
		return GUID_ContainerFormatPng
	case guidEqual(clsid, CLSID_WICBmpDecoder):
		return GUID_ContainerFormatBmp
	case guidEqual(clsid, CLSID_WICIcoDecoder):
		return GUID_ContainerFormatIco
	case guidEqual(clsid, CLSID_WICJpegDecoder):
		return GUID_ContainerFormatJpeg
	case guidEqual(clsid, CLSID_WICGifDecoder):
		return GUID_ContainerFormatGif
	default:
		return GUID{}
	}
}

func wicCLSIDFromContainerFormat(format GUID) GUID {
	switch {
	case guidEqual(format, GUID_ContainerFormatPng):
		return CLSID_WICPngDecoder
	case guidEqual(format, GUID_ContainerFormatBmp):
		return CLSID_WICBmpDecoder
	case guidEqual(format, GUID_ContainerFormatIco):
		return CLSID_WICIcoDecoder
	case guidEqual(format, GUID_ContainerFormatJpeg):
		return CLSID_WICJpegDecoder
	case guidEqual(format, GUID_ContainerFormatGif):
		return CLSID_WICGifDecoder
	default:
		return GUID{}
	}
}

func wicBytesPerPixel(format GUID) int {
	switch {
	case guidEqual(format, GUID_WICPixelFormat32bppBGRA), guidEqual(format, GUID_WICPixelFormat32bppBGR):
		return 4
	case guidEqual(format, GUID_WICPixelFormat24bppBGR):
		return 3
	case guidEqual(format, GUID_WICPixelFormat8bppIndexed):
		return 1
	default:
		return 0
	}
}

func wicStringOut(mem *mmu.MMU, ptr uint64, cch uint32, value string, actualPtr uint64) {
	encoded := append([]uint16{}, utf16Encode(value)...)
	required := uint32(len(encoded) + 1)
	if actualPtr != 0 {
		mem.Write32(actualPtr, required)
	}
	if ptr == 0 || cch == 0 {
		return
	}
	limit := int(cch)
	if limit > len(encoded) {
		limit = len(encoded)
	}
	for i := 0; i < limit; i++ {
		mem.Write16(ptr+uint64(i*2), encoded[i])
	}
	mem.Write16(ptr+uint64(limit*2), 0)
}

func wicReadRect(mem *mmu.MMU, addr uint64, fullW, fullH int) (wicRect, uint32) {
	if addr == 0 {
		return wicRect{Width: int32(fullW), Height: int32(fullH)}, S_OK
	}
	x, _ := mem.Read32(addr)
	y, _ := mem.Read32(addr + 4)
	w, _ := mem.Read32(addr + 8)
	h, _ := mem.Read32(addr + 12)
	rect := wicRect{X: int32(x), Y: int32(y), Width: int32(w), Height: int32(h)}
	if rect.Width < 0 || rect.Height < 0 || rect.X < 0 || rect.Y < 0 {
		return wicRect{}, E_INVALIDARG
	}
	if int(rect.X)+int(rect.Width) > fullW || int(rect.Y)+int(rect.Height) > fullH {
		return wicRect{}, E_INVALIDARG
	}
	return rect, S_OK
}

func wicBitmapToPixels(bitmap *wicBitmap, format GUID, rect wicRect, stride uint32, bufSize uint32) ([]byte, uint32) {
	if bitmap == nil {
		return nil, WINCODEC_ERR_NOTINITIALIZED
	}
	width := int(rect.Width)
	height := int(rect.Height)
	if width == 0 {
		width = bitmap.width
	}
	if height == 0 {
		height = bitmap.height
	}
	bpp := wicBytesPerPixel(format)
	if bpp == 0 {
		return nil, WINCODEC_ERR_UNSUPPORTEDPIXELFORMAT
	}
	minStride := width * bpp
	if int(stride) < minStride {
		return nil, E_INVALIDARG
	}
	required := int(stride) * height
	if int(bufSize) < required {
		return nil, E_INVALIDARG
	}
	out := make([]byte, required)
	for y := 0; y < height; y++ {
		srcOff := ((int(rect.Y)+y)*bitmap.width + int(rect.X)) * 4
		dstOff := y * int(stride)
		for x := 0; x < width; x++ {
			s := srcOff + x*4
			d := dstOff + x*bpp
			b := bitmap.pixels[s+0]
			g := bitmap.pixels[s+1]
			r := bitmap.pixels[s+2]
			a := bitmap.pixels[s+3]
			switch {
			case guidEqual(format, GUID_WICPixelFormat32bppBGRA):
				out[d+0] = b
				out[d+1] = g
				out[d+2] = r
				out[d+3] = a
			case guidEqual(format, GUID_WICPixelFormat32bppBGR):
				out[d+0] = b
				out[d+1] = g
				out[d+2] = r
				out[d+3] = 0
			case guidEqual(format, GUID_WICPixelFormat24bppBGR):
				out[d+0] = b
				out[d+1] = g
				out[d+2] = r
			case guidEqual(format, GUID_WICPixelFormat8bppIndexed):
				out[d] = byte((uint16(r)*77 + uint16(g)*150 + uint16(b)*29) >> 8)
			}
		}
	}
	return out, S_OK
}

func imageToWICBitmap(img image.Image) *wicBitmap {
	b := img.Bounds()
	w := b.Dx()
	h := b.Dy()
	pixels := make([]byte, w*h*4)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			r16, g16, b16, a16 := img.At(b.Min.X+x, b.Min.Y+y).RGBA()
			off := (y*w + x) * 4
			pixels[off+0] = byte(b16 >> 8)
			pixels[off+1] = byte(g16 >> 8)
			pixels[off+2] = byte(r16 >> 8)
			pixels[off+3] = byte(a16 >> 8)
		}
	}
	return &wicBitmap{
		width:       w,
		height:      h,
		pixels:      pixels,
		dpiX:        96.0,
		dpiY:        96.0,
		pixelFormat: GUID_WICPixelFormat32bppBGRA,
	}
}

func detectWICContainer(data []byte, hint string) GUID {
	if len(data) >= 8 && bytes.Equal(data[:8], []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'}) {
		return GUID_ContainerFormatPng
	}
	if len(data) >= 4 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF {
		return GUID_ContainerFormatJpeg
	}
	if len(data) >= 6 && (string(data[:6]) == "GIF87a" || string(data[:6]) == "GIF89a") {
		return GUID_ContainerFormatGif
	}
	if len(data) >= 4 && data[0] == 'B' && data[1] == 'M' {
		return GUID_ContainerFormatBmp
	}
	if len(data) >= 4 && data[0] == 0 && data[1] == 0 && (data[2] == 1 || data[2] == 2) && data[3] == 0 {
		return GUID_ContainerFormatIco
	}
	switch strings.ToLower(filepath.Ext(hint)) {
	case ".png":
		return GUID_ContainerFormatPng
	case ".jpg", ".jpeg", ".jpe", ".jfif":
		return GUID_ContainerFormatJpeg
	case ".gif":
		return GUID_ContainerFormatGif
	case ".bmp", ".dib":
		return GUID_ContainerFormatBmp
	case ".ico":
		return GUID_ContainerFormatIco
	}
	return GUID{}
}

func decodeWICImageData(data []byte, expected GUID, hint string) ([]*wicBitmap, GUID, error) {
	container := detectWICContainer(data, hint)
	if expected != (GUID{}) && !guidEqual(expected, container) {
		if container == (GUID{}) {
			container = expected
		} else {
			return nil, GUID{}, hresultError(WINCODEC_ERR_BADIMAGE)
		}
	}
	switch {
	case guidEqual(container, GUID_ContainerFormatIco):
		frames, err := decodeICOFrames(data)
		return frames, GUID_ContainerFormatIco, err
	case guidEqual(container, GUID_ContainerFormatBmp), guidEqual(container, GUID_ContainerFormatPng), guidEqual(container, GUID_ContainerFormatJpeg), guidEqual(container, GUID_ContainerFormatGif):
		img, _, err := image.Decode(bytes.NewReader(data))
		if err != nil {
			return nil, container, hresultError(WINCODEC_ERR_BADIMAGE)
		}
		return []*wicBitmap{imageToWICBitmap(img)}, container, nil
	default:
		img, _, err := image.Decode(bytes.NewReader(data))
		if err != nil {
			return nil, GUID{}, hresultError(WINCODEC_ERR_BADIMAGE)
		}
		return []*wicBitmap{imageToWICBitmap(img)}, detectWICContainer(data, hint), nil
	}
}

func decodeICOFrames(data []byte) ([]*wicBitmap, error) {
	if len(data) < 6 {
		return nil, hresultError(WINCODEC_ERR_BADIMAGE)
	}
	if binary.LittleEndian.Uint16(data[0:2]) != 0 || binary.LittleEndian.Uint16(data[2:4]) != 1 {
		return nil, hresultError(WINCODEC_ERR_BADIMAGE)
	}
	count := int(binary.LittleEndian.Uint16(data[4:6]))
	frames := make([]*wicBitmap, 0, count)
	for i := 0; i < count; i++ {
		entry := 6 + i*16
		if entry+16 > len(data) {
			break
		}
		size := int(binary.LittleEndian.Uint32(data[entry+8 : entry+12]))
		offset := int(binary.LittleEndian.Uint32(data[entry+12 : entry+16]))
		if size <= 0 || offset < 0 || offset+size > len(data) {
			continue
		}
		frameData := data[offset : offset+size]
		var bitmap *wicBitmap
		var err error
		if len(frameData) >= 8 && bytes.Equal(frameData[:8], []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'}) {
			var img image.Image
			img, _, err = image.Decode(bytes.NewReader(frameData))
			if err == nil {
				bitmap = imageToWICBitmap(img)
			}
		} else {
			bitmap, err = decodeICODIB(frameData)
		}
		if err == nil && bitmap != nil {
			frames = append(frames, bitmap)
		}
	}
	if len(frames) == 0 {
		return nil, hresultError(WINCODEC_ERR_BADIMAGE)
	}
	return frames, nil
}

func decodeICODIB(data []byte) (*wicBitmap, error) {
	if len(data) < 40 {
		return nil, hresultError(WINCODEC_ERR_BADIMAGE)
	}
	headerSize := int(binary.LittleEndian.Uint32(data[0:4]))
	if headerSize < 40 || len(data) < headerSize {
		return nil, hresultError(WINCODEC_ERR_BADIMAGE)
	}
	width := int(int32(binary.LittleEndian.Uint32(data[4:8])))
	totalHeight := int(int32(binary.LittleEndian.Uint32(data[8:12])))
	if width <= 0 || totalHeight == 0 {
		return nil, hresultError(WINCODEC_ERR_BADIMAGE)
	}
	height := totalHeight
	if height < 0 {
		height = -height
	}
	height /= 2
	if height <= 0 {
		return nil, hresultError(WINCODEC_ERR_BADIMAGE)
	}
	bitCount := int(binary.LittleEndian.Uint16(data[14:16]))
	compression := binary.LittleEndian.Uint32(data[16:20])
	if compression != 0 && compression != 3 {
		return nil, hresultError(WINCODEC_ERR_BADIMAGE)
	}
	paletteColors := int(binary.LittleEndian.Uint32(data[32:36]))
	if paletteColors == 0 && bitCount <= 8 {
		paletteColors = 1 << bitCount
	}
	pixelOffset := headerSize + paletteColors*4
	if compression == 3 {
		pixelOffset += 12
	}
	if pixelOffset > len(data) {
		return nil, hresultError(WINCODEC_ERR_BADIMAGE)
	}
	var palette []uint32
	if paletteColors > 0 {
		palette = make([]uint32, paletteColors)
		palBase := headerSize
		for i := 0; i < paletteColors; i++ {
			if palBase+i*4+4 > len(data) {
				return nil, hresultError(WINCODEC_ERR_BADIMAGE)
			}
			b := data[palBase+i*4+0]
			g := data[palBase+i*4+1]
			r := data[palBase+i*4+2]
			palette[i] = uint32(r)<<16 | uint32(g)<<8 | uint32(b)
		}
	}
	xorStride := ((width*bitCount + 31) / 32) * 4
	andStride := ((width + 31) / 32) * 4
	andOffset := pixelOffset + xorStride*height
	if andOffset > len(data) {
		return nil, hresultError(WINCODEC_ERR_BADIMAGE)
	}
	out := &wicBitmap{
		width:       width,
		height:      height,
		pixels:      make([]byte, width*height*4),
		dpiX:        96.0,
		dpiY:        96.0,
		pixelFormat: GUID_WICPixelFormat32bppBGRA,
	}
	hasAlpha := false
	for y := 0; y < height; y++ {
		srcY := height - 1 - y
		rowBase := pixelOffset + srcY*xorStride
		for x := 0; x < width; x++ {
			off := (y*width + x) * 4
			var r, g, b, a byte
			a = 0xFF
			switch bitCount {
			case 32:
				p := rowBase + x*4
				if p+4 > len(data) {
					return nil, hresultError(WINCODEC_ERR_BADIMAGE)
				}
				b = data[p+0]
				g = data[p+1]
				r = data[p+2]
				a = data[p+3]
				if a != 0 {
					hasAlpha = true
				}
			case 24:
				p := rowBase + x*3
				if p+3 > len(data) {
					return nil, hresultError(WINCODEC_ERR_BADIMAGE)
				}
				b = data[p+0]
				g = data[p+1]
				r = data[p+2]
			case 8:
				p := rowBase + x
				if p >= len(data) {
					return nil, hresultError(WINCODEC_ERR_BADIMAGE)
				}
				idx := int(data[p])
				if idx < len(palette) {
					c := palette[idx]
					r = byte(c >> 16)
					g = byte(c >> 8)
					b = byte(c)
				}
			case 4:
				p := rowBase + x/2
				if p >= len(data) {
					return nil, hresultError(WINCODEC_ERR_BADIMAGE)
				}
				idx := data[p] >> 4
				if x&1 == 1 {
					idx = data[p] & 0x0F
				}
				if int(idx) < len(palette) {
					c := palette[idx]
					r = byte(c >> 16)
					g = byte(c >> 8)
					b = byte(c)
				}
			case 1:
				p := rowBase + x/8
				if p >= len(data) {
					return nil, hresultError(WINCODEC_ERR_BADIMAGE)
				}
				bit := 7 - uint(x&7)
				idx := (data[p] >> bit) & 1
				if int(idx) < len(palette) {
					c := palette[idx]
					r = byte(c >> 16)
					g = byte(c >> 8)
					b = byte(c)
				}
			default:
				return nil, hresultError(WINCODEC_ERR_BADIMAGE)
			}
			out.pixels[off+0] = b
			out.pixels[off+1] = g
			out.pixels[off+2] = r
			out.pixels[off+3] = a
		}
	}
	if !hasAlpha {
		for y := 0; y < height; y++ {
			srcY := height - 1 - y
			rowBase := andOffset + srcY*andStride
			for x := 0; x < width; x++ {
				p := rowBase + x/8
				if p >= len(data) {
					return nil, hresultError(WINCODEC_ERR_BADIMAGE)
				}
				maskBit := (data[p] >> (7 - uint(x&7))) & 1
				alpha := byte(0xFF)
				if maskBit != 0 {
					alpha = 0
				}
				out.pixels[(y*width+x)*4+3] = alpha
			}
		}
	}
	return out, nil
}

func (cs *comState) wicBitmapFromObjectPtr(ptr uint64) (*wicBitmap, GUID, uint32) {
	obj := cs.objects[ptr]
	if obj == nil {
		return nil, GUID{}, E_POINTER
	}
	switch obj.kind {
	case "wic-frame", "wic-bitmap":
		bmp, _ := obj.data.(*wicBitmap)
		if bmp == nil {
			return nil, GUID{}, WINCODEC_ERR_NOTINITIALIZED
		}
		return bmp, bmp.pixelFormat, S_OK
	case "wic-format-converter":
		conv, _ := obj.data.(*wicFormatConverter)
		if conv == nil || !conv.initialized {
			return nil, GUID{}, WINCODEC_ERR_NOTINITIALIZED
		}
		bmp, _, hr := cs.wicBitmapFromObjectPtr(conv.sourcePtr)
		return bmp, conv.dstFormat, hr
	default:
		return nil, GUID{}, E_NOINTERFACE
	}
}

func (cs *comState) wicLoadDecoderFromBytes(dec *wicDecoder, data []byte, hint string, expected GUID) uint32 {
	if dec == nil {
		return E_POINTER
	}
	frames, container, err := decodeWICImageData(data, expected, hint)
	if err != nil {
		return hresultFromError(err)
	}
	dec.frames = frames
	dec.format = container
	dec.initialized = true
	return S_OK
}

func wicHandleToHostPath(hctx *HandlerCtx, fileHandle uint64) string {
	if hctx == nil || hctx.Handles == nil {
		return ""
	}
	obj := hctx.Handles.Get(ntapi.Handle(fileHandle))
	fh, _ := obj.(*ntapi.FileHandle)
	if fh == nil {
		return ""
	}
	if fh.Path == "" {
		return ""
	}
	return filepath.Clean(fh.Path)
}

func (cs *comState) dispatchWICFactory(ctx *ntapi.TrapContext, obj *comObject, method int) uint32 {
	switch method {
	case 3:
		fileName := ctx.Arg(1)
		ppDecoder := ctx.Arg(5)
		if ppDecoder == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppDecoder, 0)
		path := resolveWICHostPath("", hctxReadUTF16(ctx.Mem, fileName))
		if path == "" {
			return E_INVALIDARG
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return 0x80070002
		}
		container := detectWICContainer(data, path)
		clsid := wicCLSIDFromContainerFormat(container)
		if clsid == (GUID{}) {
			return WINCODEC_ERR_COMPONENTNOTFOUND
		}
		decoder, err := cs.createWICDecoderObject(clsid)
		if err != nil {
			return hresultFromError(err)
		}
		if hr := cs.wicLoadDecoderFromBytes(decoder.data.(*wicDecoder), data, path, container); hr != S_OK {
			return hr
		}
		ctx.Mem.Write64(ppDecoder, decoder.objectAddr)
		return S_OK
	case 4:
		streamPtr := ctx.Arg(1)
		ppDecoder := ctx.Arg(4)
		if ppDecoder == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppDecoder, 0)
		data, _, hr := cs.wicReadAllStreamData(streamPtr)
		if hr != S_OK {
			return hr
		}
		container := detectWICContainer(data, "")
		clsid := wicCLSIDFromContainerFormat(container)
		if clsid == (GUID{}) {
			return WINCODEC_ERR_COMPONENTNOTFOUND
		}
		decoder, err := cs.createWICDecoderObject(clsid)
		if err != nil {
			return hresultFromError(err)
		}
		if hr := cs.wicLoadDecoderFromBytes(decoder.data.(*wicDecoder), data, "", container); hr != S_OK {
			return hr
		}
		ctx.Mem.Write64(ppDecoder, decoder.objectAddr)
		return S_OK
	case 5:
		fileHandle := ctx.Arg(1)
		ppDecoder := ctx.Arg(4)
		if ppDecoder == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppDecoder, 0)
		path := wicHandleToHostPath(cs.hctx, fileHandle)
		if path == "" {
			return E_INVALIDARG
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return 0x80070002
		}
		container := detectWICContainer(data, path)
		clsid := wicCLSIDFromContainerFormat(container)
		if clsid == (GUID{}) {
			return WINCODEC_ERR_COMPONENTNOTFOUND
		}
		decoder, err := cs.createWICDecoderObject(clsid)
		if err != nil {
			return hresultFromError(err)
		}
		if hr := cs.wicLoadDecoderFromBytes(decoder.data.(*wicDecoder), data, path, container); hr != S_OK {
			return hr
		}
		ctx.Mem.Write64(ppDecoder, decoder.objectAddr)
		return S_OK
	case 6:
		clsidPtr := ctx.Arg(1)
		ppInfo := ctx.Arg(2)
		if clsidPtr == 0 || ppInfo == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppInfo, 0)
		infoObj, err := cs.createWICComponentInfoObject(readGUID(ctx.Mem, clsidPtr))
		if err != nil {
			return hresultFromError(err)
		}
		ctx.Mem.Write64(ppInfo, infoObj.objectAddr)
		return S_OK
	case 7:
		formatPtr := ctx.Arg(1)
		ppDecoder := ctx.Arg(3)
		if formatPtr == 0 || ppDecoder == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppDecoder, 0)
		clsid := wicCLSIDFromContainerFormat(readGUID(ctx.Mem, formatPtr))
		if clsid == (GUID{}) {
			return WINCODEC_ERR_COMPONENTNOTFOUND
		}
		decoder, err := cs.createWICDecoderObject(clsid)
		if err != nil {
			return hresultFromError(err)
		}
		ctx.Mem.Write64(ppDecoder, decoder.objectAddr)
		return S_OK
	case 8:
		return WINCODEC_ERR_UNSUPPORTEDOPERATION
	case 9:
		return WINCODEC_ERR_UNSUPPORTEDOPERATION
	case 10:
		ppConverter := ctx.Arg(1)
		if ppConverter == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppConverter, 0)
		converter, err := cs.createWICFormatConverterObject()
		if err != nil {
			return hresultFromError(err)
		}
		ctx.Mem.Write64(ppConverter, converter.objectAddr)
		return S_OK
	case 11, 12, 13, 15, 16, 23, 24, 25, 26, 27, 28:
		return WINCODEC_ERR_UNSUPPORTEDOPERATION
	case 14:
		ppStream := ctx.Arg(1)
		if ppStream == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppStream, 0)
		stream, err := cs.createWICStreamObject()
		if err != nil {
			return hresultFromError(err)
		}
		ctx.Mem.Write64(ppStream, stream.objectAddr)
		return S_OK
	case 17:
		width := int(ctx.Arg(1))
		height := int(ctx.Arg(2))
		pfPtr := ctx.Arg(3)
		ppBitmap := ctx.Arg(5)
		if pfPtr == 0 || ppBitmap == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppBitmap, 0)
		if width <= 0 || height <= 0 {
			return E_INVALIDARG
		}
		pf := readGUID(ctx.Mem, pfPtr)
		if wicBytesPerPixel(pf) == 0 {
			return WINCODEC_ERR_UNSUPPORTEDPIXELFORMAT
		}
		bmp := &wicBitmap{
			width:       width,
			height:      height,
			pixels:      make([]byte, width*height*4),
			dpiX:        96.0,
			dpiY:        96.0,
			pixelFormat: pf,
		}
		for i := 0; i < len(bmp.pixels); i += 4 {
			bmp.pixels[i+3] = 0xFF
		}
		bmpObj, err := cs.createWICBitmapObject(bmp)
		if err != nil {
			return hresultFromError(err)
		}
		ctx.Mem.Write64(ppBitmap, bmpObj.objectAddr)
		return S_OK
	case 18:
		sourcePtr := ctx.Arg(1)
		ppBitmap := ctx.Arg(3)
		if ppBitmap == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppBitmap, 0)
		src, _, hr := cs.wicBitmapFromObjectPtr(sourcePtr)
		if hr != S_OK {
			return hr
		}
		clone := &wicBitmap{
			width:       src.width,
			height:      src.height,
			pixels:      append([]byte(nil), src.pixels...),
			dpiX:        src.dpiX,
			dpiY:        src.dpiY,
			pixelFormat: src.pixelFormat,
		}
		bmpObj, err := cs.createWICBitmapObject(clone)
		if err != nil {
			return hresultFromError(err)
		}
		ctx.Mem.Write64(ppBitmap, bmpObj.objectAddr)
		return S_OK
	case 19:
		sourcePtr := ctx.Arg(1)
		x := int(ctx.Arg(2))
		y := int(ctx.Arg(3))
		w := int(ctx.Arg(4))
		h := int(ctx.Arg(5))
		ppBitmap := ctx.Arg(6)
		if ppBitmap == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppBitmap, 0)
		src, _, hr := cs.wicBitmapFromObjectPtr(sourcePtr)
		if hr != S_OK {
			return hr
		}
		if x < 0 || y < 0 || w <= 0 || h <= 0 || x+w > src.width || y+h > src.height {
			return E_INVALIDARG
		}
		cropped := &wicBitmap{
			width:       w,
			height:      h,
			pixels:      make([]byte, w*h*4),
			dpiX:        src.dpiX,
			dpiY:        src.dpiY,
			pixelFormat: src.pixelFormat,
		}
		for row := 0; row < h; row++ {
			copy(cropped.pixels[row*w*4:(row+1)*w*4], src.pixels[((y+row)*src.width+x)*4:((y+row)*src.width+x+w)*4])
		}
		bmpObj, err := cs.createWICBitmapObject(cropped)
		if err != nil {
			return hresultFromError(err)
		}
		ctx.Mem.Write64(ppBitmap, bmpObj.objectAddr)
		return S_OK
	case 20:
		width := int(ctx.Arg(1))
		height := int(ctx.Arg(2))
		pfPtr := ctx.Arg(3)
		stride := uint32(ctx.Arg(4))
		bufSize := uint32(ctx.Arg(5))
		buffer := ctx.Arg(6)
		ppBitmap := ctx.Arg(7)
		if pfPtr == 0 || ppBitmap == 0 || (buffer == 0 && bufSize != 0) {
			return E_POINTER
		}
		ctx.Mem.Write64(ppBitmap, 0)
		pf := readGUID(ctx.Mem, pfPtr)
		if width <= 0 || height <= 0 {
			return E_INVALIDARG
		}
		bmp, hr := wicBitmapFromMemory(ctx.Mem, width, height, pf, stride, bufSize, buffer)
		if hr != S_OK {
			return hr
		}
		bmpObj, err := cs.createWICBitmapObject(bmp)
		if err != nil {
			return hresultFromError(err)
		}
		ctx.Mem.Write64(ppBitmap, bmpObj.objectAddr)
		return S_OK
	case 21:
		hbitmap := ctx.Arg(1)
		ppBitmap := ctx.Arg(4)
		if ppBitmap == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppBitmap, 0)
		bmp, hr := wicBitmapFromHBITMAP(cs.hctx, hbitmap)
		if hr != S_OK {
			return hr
		}
		bmpObj, err := cs.createWICBitmapObject(bmp)
		if err != nil {
			return hresultFromError(err)
		}
		ctx.Mem.Write64(ppBitmap, bmpObj.objectAddr)
		return S_OK
	case 22:
		ppBitmap := ctx.Arg(2)
		if ppBitmap == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppBitmap, 0)
		bmp := &wicBitmap{
			width:       32,
			height:      32,
			pixels:      make([]byte, 32*32*4),
			dpiX:        96.0,
			dpiY:        96.0,
			pixelFormat: GUID_WICPixelFormat32bppBGRA,
		}
		bmpObj, err := cs.createWICBitmapObject(bmp)
		if err != nil {
			return hresultFromError(err)
		}
		ctx.Mem.Write64(ppBitmap, bmpObj.objectAddr)
		return S_OK
	default:
		return E_NOTIMPL
	}
}

func wicBitmapFromMemory(mem *mmu.MMU, width, height int, format GUID, stride, bufSize uint32, buffer uint64) (*wicBitmap, uint32) {
	bpp := wicBytesPerPixel(format)
	if bpp == 0 {
		return nil, WINCODEC_ERR_UNSUPPORTEDPIXELFORMAT
	}
	if int(stride) < width*bpp {
		return nil, E_INVALIDARG
	}
	required := int(stride) * height
	if int(bufSize) < required {
		return nil, E_INVALIDARG
	}
	src, err := mem.ReadBytes(buffer, required)
	if err != nil && required != 0 {
		return nil, E_POINTER
	}
	out := &wicBitmap{
		width:       width,
		height:      height,
		pixels:      make([]byte, width*height*4),
		dpiX:        96.0,
		dpiY:        96.0,
		pixelFormat: format,
	}
	for y := 0; y < height; y++ {
		row := src[y*int(stride):]
		for x := 0; x < width; x++ {
			dst := (y*width + x) * 4
			switch {
			case guidEqual(format, GUID_WICPixelFormat32bppBGRA):
				copy(out.pixels[dst:dst+4], row[x*4:x*4+4])
			case guidEqual(format, GUID_WICPixelFormat32bppBGR):
				copy(out.pixels[dst:dst+3], row[x*4:x*4+3])
				out.pixels[dst+3] = 0xFF
			case guidEqual(format, GUID_WICPixelFormat24bppBGR):
				copy(out.pixels[dst:dst+3], row[x*3:x*3+3])
				out.pixels[dst+3] = 0xFF
			case guidEqual(format, GUID_WICPixelFormat8bppIndexed):
				v := row[x]
				out.pixels[dst+0] = v
				out.pixels[dst+1] = v
				out.pixels[dst+2] = v
				out.pixels[dst+3] = 0xFF
			}
		}
	}
	return out, S_OK
}

func wicBitmapFromHBITMAP(hctx *HandlerCtx, hbitmap uint64) (*wicBitmap, uint32) {
	if hctx == nil {
		return nil, E_POINTER
	}
	if bd := hctx.BitmapHandles[hbitmap]; bd != nil && len(bd.slots) > 0 {
		slot := bd.slots[0]
		width := bd.w
		if width <= 0 && len(slot) > 0 {
			width = len(slot)
		}
		if width <= 0 {
			return nil, E_FAIL
		}
		height := len(slot) / width
		out := &wicBitmap{
			width:       width,
			height:      height,
			pixels:      make([]byte, width*height*4),
			dpiX:        96.0,
			dpiY:        96.0,
			pixelFormat: GUID_WICPixelFormat32bppBGRA,
		}
		for i, c := range slot {
			out.pixels[i*4+0] = byte(c)
			out.pixels[i*4+1] = byte(c >> 8)
			out.pixels[i*4+2] = byte(c >> 16)
			out.pixels[i*4+3] = 0xFF
		}
		return out, S_OK
	}
	if hctx.GdiMgr == nil {
		return nil, E_FAIL
	}
	gdiObj := hctx.GdiMgr.GetObject(hbitmap)
	if gdiObj == nil || gdiObj.Bitmap == nil || gdiObj.Bitmap.Surf == nil {
		return nil, E_FAIL
	}
	surf := gdiObj.Bitmap.Surf
	out := &wicBitmap{
		width:       int(surf.Width),
		height:      int(surf.Height),
		pixels:      append([]byte(nil), surf.Pix...),
		dpiX:        96.0,
		dpiY:        96.0,
		pixelFormat: GUID_WICPixelFormat32bppBGRA,
	}
	for i := 0; i < len(out.pixels); i += 4 {
		out.pixels[i+3] = 0xFF
	}
	return out, S_OK
}

func (cs *comState) wicReadAllStreamData(streamPtr uint64) ([]byte, string, uint32) {
	obj := cs.objects[streamPtr]
	if obj == nil {
		return nil, "", E_POINTER
	}
	switch obj.kind {
	case "istream":
		switch s := obj.data.(type) {
		case *memStream:
			return append([]byte(nil), s.buffer.data...), s.name, S_OK
		case *fileStream:
			data, err := os.ReadFile(s.path)
			if err != nil {
				return nil, "", WINCODEC_ERR_STREAMREAD
			}
			return data, s.path, S_OK
		}
	case "wic-stream":
		ws, _ := obj.data.(*wicStream)
		if ws == nil || ws.data == nil {
			return nil, "", WINCODEC_ERR_NOTINITIALIZED
		}
		switch s := ws.data.(type) {
		case *memStream:
			return append([]byte(nil), s.buffer.data...), ws.name, S_OK
		case *fileStream:
			data, err := os.ReadFile(s.path)
			if err != nil {
				return nil, "", WINCODEC_ERR_STREAMREAD
			}
			return data, s.path, S_OK
		}
	}
	return nil, "", E_NOINTERFACE
}

func (cs *comState) dispatchWICDecoder(ctx *ntapi.TrapContext, obj *comObject, method int) uint32 {
	dec, _ := obj.data.(*wicDecoder)
	if dec == nil {
		return E_FAIL
	}
	switch method {
	case 3:
		streamPtr := ctx.Arg(1)
		pCapability := ctx.Arg(2)
		if pCapability == 0 {
			return E_POINTER
		}
		ctx.Mem.Write32(pCapability, 0)
		data, hint, hr := cs.wicReadAllStreamData(streamPtr)
		if hr != S_OK {
			return hr
		}
		container := detectWICContainer(data, hint)
		if guidEqual(container, dec.format) {
			ctx.Mem.Write32(pCapability, wicBitmapDecoderCapabilityAllImages)
		}
		return S_OK
	case 4:
		if dec.initialized {
			return WINCODEC_ERR_WRONGSTATE
		}
		data, hint, hr := cs.wicReadAllStreamData(ctx.Arg(1))
		if hr != S_OK {
			return hr
		}
		return cs.wicLoadDecoderFromBytes(dec, data, hint, dec.format)
	case 5:
		pFormat := ctx.Arg(1)
		if pFormat == 0 {
			return E_POINTER
		}
		writeGUID(ctx.Mem, pFormat, dec.format)
		return S_OK
	case 6:
		return WINCODEC_ERR_UNSUPPORTEDOPERATION
	case 7:
		return WINCODEC_ERR_PALETTEUNAVAILABLE
	case 8, 9:
		return WINCODEC_ERR_UNSUPPORTEDOPERATION
	case 10:
		actualCount := ctx.Arg(3)
		if actualCount != 0 {
			ctx.Mem.Write32(actualCount, 0)
		}
		return S_OK
	case 11:
		return WINCODEC_ERR_CODECNOTHUMBNAIL
	case 12:
		pCount := ctx.Arg(1)
		if pCount == 0 {
			return E_POINTER
		}
		if !dec.initialized {
			return WINCODEC_ERR_NOTINITIALIZED
		}
		ctx.Mem.Write32(pCount, uint32(len(dec.frames)))
		return S_OK
	case 13:
		index := int(ctx.Arg(1))
		ppFrame := ctx.Arg(2)
		if ppFrame == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppFrame, 0)
		if !dec.initialized {
			return WINCODEC_ERR_NOTINITIALIZED
		}
		if index < 0 || index >= len(dec.frames) {
			return WINCODEC_ERR_FRAMEMISSING
		}
		frame, err := cs.createWICFrameObject(dec.frames[index])
		if err != nil {
			return hresultFromError(err)
		}
		ctx.Mem.Write64(ppFrame, frame.objectAddr)
		return S_OK
	default:
		return E_NOTIMPL
	}
}

func (cs *comState) dispatchWICBitmapSource(ctx *ntapi.TrapContext, obj *comObject, method int) uint32 {
	bmp, format, hr := cs.wicBitmapFromObjectPtr(obj.objectAddr)
	if hr != S_OK {
		return hr
	}
	switch method {
	case 3:
		pWidth := ctx.Arg(1)
		pHeight := ctx.Arg(2)
		if pWidth == 0 || pHeight == 0 {
			return E_POINTER
		}
		ctx.Mem.Write32(pWidth, uint32(bmp.width))
		ctx.Mem.Write32(pHeight, uint32(bmp.height))
		return S_OK
	case 4:
		pFormat := ctx.Arg(1)
		if pFormat == 0 {
			return E_POINTER
		}
		writeGUID(ctx.Mem, pFormat, format)
		return S_OK
	case 5:
		pDpiX := ctx.Arg(1)
		pDpiY := ctx.Arg(2)
		if pDpiX == 0 || pDpiY == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64Raw(pDpiX, math.Float64bits(bmp.dpiX))
		ctx.Mem.Write64Raw(pDpiY, math.Float64bits(bmp.dpiY))
		return S_OK
	case 6:
		return WINCODEC_ERR_PALETTEUNAVAILABLE
	case 7:
		pRect := ctx.Arg(1)
		stride := uint32(ctx.Arg(2))
		bufSize := uint32(ctx.Arg(3))
		buffer := ctx.Arg(4)
		if buffer == 0 && bufSize != 0 {
			return E_POINTER
		}
		rect, hr := wicReadRect(ctx.Mem, pRect, bmp.width, bmp.height)
		if hr != S_OK {
			return hr
		}
		pixels, hr := wicBitmapToPixels(bmp, format, rect, stride, bufSize)
		if hr != S_OK {
			return hr
		}
		ctx.Mem.WriteBytes(buffer, pixels)
		return S_OK
	default:
		return E_NOTIMPL
	}
}

func (cs *comState) dispatchWICFrame(ctx *ntapi.TrapContext, obj *comObject, method int) uint32 {
	if method >= 3 && method <= 7 {
		return cs.dispatchWICBitmapSource(ctx, obj, method)
	}
	switch method {
	case 8:
		return WINCODEC_ERR_UNSUPPORTEDOPERATION
	case 9:
		actualCount := ctx.Arg(3)
		if actualCount != 0 {
			ctx.Mem.Write32(actualCount, 0)
		}
		return S_OK
	case 10:
		return WINCODEC_ERR_CODECNOTHUMBNAIL
	default:
		return E_NOTIMPL
	}
}

func (cs *comState) dispatchWICFormatConverter(ctx *ntapi.TrapContext, obj *comObject, method int) uint32 {
	if method >= 3 && method <= 7 {
		return cs.dispatchWICBitmapSource(ctx, obj, method)
	}
	conv, _ := obj.data.(*wicFormatConverter)
	if conv == nil {
		return E_FAIL
	}
	switch method {
	case 8:
		if conv.initialized {
			return WINCODEC_ERR_WRONGSTATE
		}
		source := ctx.Arg(1)
		dstFormatPtr := ctx.Arg(2)
		if source == 0 || dstFormatPtr == 0 {
			return E_POINTER
		}
		dstFormat := readGUID(ctx.Mem, dstFormatPtr)
		if !wicCanConvertFormat(dstFormat) {
			return WINCODEC_ERR_UNSUPPORTEDPIXELFORMAT
		}
		if _, _, hr := cs.wicBitmapFromObjectPtr(source); hr != S_OK {
			return hr
		}
		conv.sourcePtr = source
		conv.dstFormat = dstFormat
		conv.initialized = true
		return S_OK
	case 9:
		srcFormatPtr := ctx.Arg(1)
		dstFormatPtr := ctx.Arg(2)
		pCanConvert := ctx.Arg(3)
		if srcFormatPtr == 0 || dstFormatPtr == 0 || pCanConvert == 0 {
			return E_POINTER
		}
		srcFormat := readGUID(ctx.Mem, srcFormatPtr)
		dstFormat := readGUID(ctx.Mem, dstFormatPtr)
		can := uint32(0)
		if wicCanConvertFormat(srcFormat) && wicCanConvertFormat(dstFormat) {
			can = 1
		}
		ctx.Mem.Write32(pCanConvert, can)
		return S_OK
	default:
		return E_NOTIMPL
	}
}

func wicCanConvertFormat(format GUID) bool {
	return guidEqual(format, GUID_WICPixelFormat32bppBGRA) ||
		guidEqual(format, GUID_WICPixelFormat32bppBGR) ||
		guidEqual(format, GUID_WICPixelFormat24bppBGR) ||
		guidEqual(format, GUID_WICPixelFormat8bppIndexed)
}

func (cs *comState) dispatchWICBitmap(ctx *ntapi.TrapContext, obj *comObject, method int) uint32 {
	if method >= 3 && method <= 7 {
		return cs.dispatchWICBitmapSource(ctx, obj, method)
	}
	bmp, _ := obj.data.(*wicBitmap)
	if bmp == nil {
		return E_FAIL
	}
	switch method {
	case 8:
		return WINCODEC_ERR_UNSUPPORTEDOPERATION
	case 9:
		return WINCODEC_ERR_PALETTEUNAVAILABLE
	case 10:
		bmp.dpiX = ctx.FloatArg(1)
		bmp.dpiY = ctx.FloatArg(2)
		return S_OK
	default:
		return E_NOTIMPL
	}
}

func wicStreamBacking(ws *wicStream) (interface{}, *int64) {
	if ws == nil || ws.data == nil {
		return nil, nil
	}
	switch s := ws.data.(type) {
	case *memStream:
		return s, &s.pos
	case *fileStream:
		return s, &s.pos
	default:
		return nil, nil
	}
}

func (cs *comState) dispatchWICStream(ctx *ntapi.TrapContext, obj *comObject, method int) uint32 {
	ws, _ := obj.data.(*wicStream)
	if ws == nil {
		return E_FAIL
	}
	if method >= 3 && method <= 13 {
		data, pos := wicStreamBacking(ws)
		if data == nil || pos == nil {
			if method == 6 {
				return WINCODEC_ERR_NOTINITIALIZED
			}
			return WINCODEC_ERR_NOTINITIALIZED
		}
		switch method {
		case 3:
			pv := ctx.Arg(1)
			cb := ctx.Arg(2)
			pcbRead := ctx.Arg(3)
			if pv == 0 && cb != 0 {
				return STG_E_INVALIDPOINTER
			}
			if pcbRead != 0 {
				ctx.Mem.Write32(pcbRead, 0)
			}
			tmp := make([]byte, int(cb))
			n, err := streamReadAt(data, *pos, tmp)
			if n > 0 {
				ctx.Mem.WriteBytes(pv, tmp[:n])
				*pos += int64(n)
			}
			if pcbRead != 0 {
				ctx.Mem.Write32(pcbRead, uint32(n))
			}
			if err != nil && n == 0 {
				return WINCODEC_ERR_STREAMREAD
			}
			if uint64(n) == cb {
				return S_OK
			}
			return S_FALSE
		case 4:
			pv := ctx.Arg(1)
			cb := ctx.Arg(2)
			pcbWritten := ctx.Arg(3)
			if pv == 0 && cb != 0 {
				return STG_E_INVALIDPOINTER
			}
			if pcbWritten != 0 {
				ctx.Mem.Write32(pcbWritten, 0)
			}
			src, err := ctx.Mem.ReadBytes(pv, int(cb))
			if err != nil && cb != 0 {
				return E_POINTER
			}
			n, err := streamWriteAt(data, *pos, src)
			if err != nil {
				return hresultFromError(err)
			}
			*pos += int64(n)
			if pcbWritten != 0 {
				ctx.Mem.Write32(pcbWritten, uint32(n))
			}
			return S_OK
		case 5:
			move := int64(ctx.Arg(1))
			origin := uint32(ctx.Arg(2))
			pNewPos := ctx.Arg(3)
			size, err := streamSize(data)
			if err != nil {
				return hresultFromError(err)
			}
			base := int64(0)
			switch origin {
			case 0:
			case 1:
				base = *pos
			case 2:
				base = size
			default:
				return E_INVALIDARG
			}
			next := base + move
			if next < 0 {
				return E_INVALIDARG
			}
			*pos = next
			if pNewPos != 0 {
				ctx.Mem.Write64Raw(pNewPos, uint64(next))
			}
			return S_OK
		case 6:
			if err := streamSetSize(data, int64(ctx.Arg(1))); err != nil {
				return hresultFromError(err)
			}
			return S_OK
		case 7:
			pstm := ctx.Arg(1)
			cb := ctx.Arg(2)
			pcbRead := ctx.Arg(3)
			pcbWritten := ctx.Arg(4)
			if pcbRead != 0 {
				ctx.Mem.Write64Raw(pcbRead, 0)
			}
			if pcbWritten != 0 {
				ctx.Mem.Write64Raw(pcbWritten, 0)
			}
			dest := cs.objects[pstm]
			if dest == nil {
				return E_POINTER
			}
			if dest.kind != "istream" && dest.kind != "wic-stream" {
				return E_NOINTERFACE
			}
			data2, pos2, hr := cs.wicStreamObjectBacking(dest)
			if hr != S_OK {
				return hr
			}
			remaining := cb
			buf := make([]byte, 64*1024)
			var total uint64
			for remaining > 0 {
				chunk := remaining
				if chunk > uint64(len(buf)) {
					chunk = uint64(len(buf))
				}
				n, err := streamReadAt(data, *pos, buf[:chunk])
				if n > 0 {
					written, writeErr := streamWriteAt(data2, *pos2, buf[:n])
					if writeErr != nil {
						return hresultFromError(writeErr)
					}
					*pos += int64(written)
					*pos2 += int64(written)
					total += uint64(written)
					remaining -= uint64(written)
				}
				if err != nil || n == 0 {
					break
				}
			}
			if pcbRead != 0 {
				ctx.Mem.Write64Raw(pcbRead, total)
			}
			if pcbWritten != 0 {
				ctx.Mem.Write64Raw(pcbWritten, total)
			}
			if total == cb {
				return S_OK
			}
			return S_FALSE
		case 8:
			if err := streamCommit(data); err != nil {
				return hresultFromError(err)
			}
			return S_OK
		case 9:
			return STG_E_REVERTED
		case 10, 11:
			return S_OK
		case 12:
			pstat := ctx.Arg(1)
			flags := uint32(ctx.Arg(2))
			if pstat == 0 {
				return E_POINTER
			}
			size, err := streamSize(data)
			if err != nil {
				return hresultFromError(err)
			}
			writeSTATSTG(ctx.Mem, cs, pstat, statStgEntry{
				name:    ws.name,
				stgType: STGTY_STREAM,
				size:    uint64(size),
				modTime: streamModTime(data),
			}, flags, 0)
			return S_OK
		case 13:
			ppstm := ctx.Arg(1)
			if ppstm == 0 {
				return E_POINTER
			}
			ctx.Mem.Write64(ppstm, 0)
			clone, err := cs.createWICStreamObject()
			if err != nil {
				return hresultFromError(err)
			}
			dst := clone.data.(*wicStream)
			switch s := data.(type) {
			case *memStream:
				s.buffer.addRef()
				dst.data = &memStream{buffer: s.buffer, pos: s.pos, name: s.name}
				dst.name = ws.name
			case *fileStream:
				fileClone, err := cs.createFileStreamObject(s.path, s.name, s.grfMode, false)
				if err != nil {
					return hresultFromError(err)
				}
				dst.data = fileClone.data
				dst.name = ws.name
				delete(cs.objects, fileClone.objectAddr)
			}
			ctx.Mem.Write64(ppstm, clone.objectAddr)
			return S_OK
		}
	}
	switch method {
	case 14:
		streamPtr := ctx.Arg(1)
		data, name, hr := cs.wicReadAllStreamData(streamPtr)
		if hr != S_OK {
			return hr
		}
		ws.data = &memStream{buffer: &memoryBuffer{data: append([]byte(nil), data...), refs: 1}, name: name}
		ws.name = name
		return S_OK
	case 15:
		path := resolveWICHostPath(cs.hctx.ImagePath, hctxReadUTF16(ctx.Mem, ctx.Arg(1)))
		if path == "" {
			return E_INVALIDARG
		}
		streamObj, err := cs.createFileStreamObject(path, filepath.Base(path), 0, false)
		if err != nil {
			return hresultFromError(err)
		}
		ws.data = streamObj.data
		ws.name = filepath.Base(path)
		delete(cs.objects, streamObj.objectAddr)
		return S_OK
	case 16:
		buffer := ctx.Arg(1)
		size := int(ctx.Arg(2))
		if buffer == 0 && size != 0 {
			return E_POINTER
		}
		data, err := ctx.Mem.ReadBytes(buffer, size)
		if err != nil && size != 0 {
			return E_POINTER
		}
		ws.data = &memStream{buffer: &memoryBuffer{data: append([]byte(nil), data...), refs: 1}}
		ws.name = ""
		return S_OK
	case 17:
		streamPtr := ctx.Arg(1)
		data, name, hr := cs.wicReadAllStreamData(streamPtr)
		if hr != S_OK {
			return hr
		}
		offset := int(ctx.Arg(2))
		size := int(ctx.Arg(3))
		if offset < 0 || size < 0 || offset > len(data) || offset+size > len(data) {
			return E_INVALIDARG
		}
		ws.data = &memStream{buffer: &memoryBuffer{data: append([]byte(nil), data[offset:offset+size]...), refs: 1}}
		ws.name = name
		return S_OK
	default:
		return E_NOTIMPL
	}
}

func (cs *comState) wicStreamObjectBacking(obj *comObject) (interface{}, *int64, uint32) {
	if obj == nil {
		return nil, nil, E_POINTER
	}
	switch obj.kind {
	case "istream":
		switch s := obj.data.(type) {
		case *memStream:
			return s, &s.pos, S_OK
		case *fileStream:
			return s, &s.pos, S_OK
		}
	case "wic-stream":
		ws, _ := obj.data.(*wicStream)
		data, pos := wicStreamBacking(ws)
		if data == nil || pos == nil {
			return nil, nil, WINCODEC_ERR_NOTINITIALIZED
		}
		return data, pos, S_OK
	}
	return nil, nil, E_NOINTERFACE
}

func (cs *comState) dispatchWICComponentInfo(ctx *ntapi.TrapContext, obj *comObject, method int) uint32 {
	info, _ := obj.data.(*wicComponentInfoData)
	if info == nil {
		return E_FAIL
	}
	switch method {
	case 3:
		pType := ctx.Arg(1)
		if pType == 0 {
			return E_POINTER
		}
		ctx.Mem.Write32(pType, info.componentType)
		return S_OK
	case 4:
		pCLSID := ctx.Arg(1)
		if pCLSID == 0 {
			return E_POINTER
		}
		writeGUID(ctx.Mem, pCLSID, info.clsid)
		return S_OK
	case 5:
		pStatus := ctx.Arg(1)
		if pStatus == 0 {
			return E_POINTER
		}
		ctx.Mem.Write32(pStatus, wicComponentUnsignedSafe)
		return S_OK
	case 6:
		wicStringOut(ctx.Mem, ctx.Arg(2), uint32(ctx.Arg(1)), info.author, ctx.Arg(3))
		return S_OK
	case 7:
		pVendor := ctx.Arg(1)
		if pVendor == 0 {
			return E_POINTER
		}
		writeGUID(ctx.Mem, pVendor, GUID{})
		return S_OK
	case 8:
		wicStringOut(ctx.Mem, ctx.Arg(2), uint32(ctx.Arg(1)), info.version, ctx.Arg(3))
		return S_OK
	case 9:
		wicStringOut(ctx.Mem, ctx.Arg(2), uint32(ctx.Arg(1)), info.specVersion, ctx.Arg(3))
		return S_OK
	case 10:
		wicStringOut(ctx.Mem, ctx.Arg(2), uint32(ctx.Arg(1)), info.friendlyName, ctx.Arg(3))
		return S_OK
	case 11:
		pFormat := ctx.Arg(1)
		if pFormat == 0 {
			return E_POINTER
		}
		writeGUID(ctx.Mem, pFormat, info.containerFormat)
		return S_OK
	case 12:
		count := uint32(ctx.Arg(1))
		formatsPtr := ctx.Arg(2)
		actualPtr := ctx.Arg(3)
		if actualPtr != 0 {
			ctx.Mem.Write32(actualPtr, uint32(len(info.pixelFormats)))
		}
		if formatsPtr != 0 {
			limit := int(count)
			if limit > len(info.pixelFormats) {
				limit = len(info.pixelFormats)
			}
			for i := 0; i < limit; i++ {
				writeGUID(ctx.Mem, formatsPtr+uint64(i*16), info.pixelFormats[i])
			}
		}
		return S_OK
	case 13, 14:
		wicStringOut(ctx.Mem, ctx.Arg(2), uint32(ctx.Arg(1)), "", ctx.Arg(3))
		return S_OK
	case 15:
		wicStringOut(ctx.Mem, ctx.Arg(2), uint32(ctx.Arg(1)), info.mimeTypes, ctx.Arg(3))
		return S_OK
	case 16:
		wicStringOut(ctx.Mem, ctx.Arg(2), uint32(ctx.Arg(1)), info.fileExtensions, ctx.Arg(3))
		return S_OK
	case 17, 18, 19:
		ptr := ctx.Arg(1)
		if ptr == 0 {
			return E_POINTER
		}
		ctx.Mem.Write32(ptr, 0)
		return S_OK
	case 20:
		ptr := ctx.Arg(1)
		if ptr == 0 {
			return E_POINTER
		}
		if info.supportsMultiframe {
			ctx.Mem.Write32(ptr, 1)
		} else {
			ctx.Mem.Write32(ptr, 0)
		}
		return S_OK
	case 21:
		mime := strings.ToLower(hctxReadUTF16(ctx.Mem, ctx.Arg(1)))
		ptr := ctx.Arg(2)
		if ptr == 0 {
			return E_POINTER
		}
		match := uint32(0)
		for _, item := range strings.Split(strings.ToLower(info.mimeTypes), ";") {
			if strings.TrimSpace(item) == mime {
				match = 1
				break
			}
		}
		ctx.Mem.Write32(ptr, match)
		return S_OK
	case 22:
		return WINCODEC_ERR_UNSUPPORTEDOPERATION
	case 23:
		streamPtr := ctx.Arg(1)
		pMatch := ctx.Arg(2)
		if pMatch == 0 {
			return E_POINTER
		}
		ctx.Mem.Write32(pMatch, 0)
		if guidEqual(obj.primaryIID, IID_IWICBitmapDecoderInfo) {
			data, hint, hr := cs.wicReadAllStreamData(streamPtr)
			if hr != S_OK {
				return hr
			}
			if guidEqual(detectWICContainer(data, hint), info.containerFormat) {
				ctx.Mem.Write32(pMatch, 1)
			}
			return S_OK
		}
		return E_NOTIMPL
	case 24:
		if info.create == nil {
			return WINCODEC_ERR_COMPONENTNOTFOUND
		}
		ppObj := ctx.Arg(1)
		if ppObj == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppObj, 0)
		created, err := info.create()
		if err != nil {
			return hresultFromError(err)
		}
		ctx.Mem.Write64(ppObj, created.objectAddr)
		return S_OK
	default:
		return E_NOTIMPL
	}
}

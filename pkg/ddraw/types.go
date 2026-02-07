//go:build guest_windows

package ddraw

type DDSCAPS2 struct {
	DwCaps  uint32
	DwCaps2 uint32
	DwCaps3 uint32
	DwCaps4 uint32
}

type DDCOLORKEY struct {
	DwColorSpaceLowValue  uint32
	DwColorSpaceHighValue uint32
}

type DDPIXELFORMAT struct {
	DwSize         uint32
	DwFlags        uint32
	DwFourCC       uint32
	DwRGBBitCount  uint32
	DwRBitMask     uint32
	DwGBitMask     uint32
	DwBBitMask     uint32
	DwAlphaBitMask uint32
}

type DDSURFACEDESC2 struct {
	DwSize            uint32
	DwFlags           uint32
	DwHeight          uint32
	DwWidth           uint32
	LPitch            int32
	DwBackBufferCount uint32
	DwMipMapCount     uint32
	DwAlphaBitDepth   uint32
	DwReserved        uint32
	LpSurface         uint64
	DdckCKDestOverlay DDCOLORKEY
	DdckCKDestBlt     DDCOLORKEY
	DdckCKSrcOverlay  DDCOLORKEY
	DdckCKSrcBlt      DDCOLORKEY
	DdpfPixelFormat   DDPIXELFORMAT
	DdsCaps           DDSCAPS2
	DwTextureStage    uint32
}

type DDBLTFX struct {
	DwSize      uint32
	DwFillColor uint32
}

type DDCAPS struct {
	DwSize        uint32
	DwCaps        uint32
	DwCaps2       uint32
	DwCKeyCaps    uint32
	DwFXCaps      uint32
	DwVidMemTotal uint32
	DwVidMemFree  uint32
	DdsCaps       DDSCAPS2
}

type Rect struct {
	Left   int32
	Top    int32
	Right  int32
	Bottom int32
}

const (
	DDSD_CAPS            = 0x00000001
	DDSD_HEIGHT          = 0x00000002
	DDSD_WIDTH           = 0x00000004
	DDSD_PITCH           = 0x00000008
	DDSD_BACKBUFFERCOUNT = 0x00000020
	DDSD_LPSURFACE       = 0x00000800
	DDSD_PIXELFORMAT     = 0x00001000
)

const (
	DDSCAPS_BACKBUFFER     = 0x00000004
	DDSCAPS_COMPLEX        = 0x00000008
	DDSCAPS_FLIP           = 0x00000010
	DDSCAPS_OFFSCREENPLAIN = 0x00000040
	DDSCAPS_PRIMARYSURFACE = 0x00000200
	DDSCAPS_SYSTEMMEMORY   = 0x00000800
	DDSCAPS_VIDEOMEMORY    = 0x00004000
)

const (
	DDSCL_FULLSCREEN = 0x00000001
	DDSCL_NORMAL     = 0x00000008
	DDSCL_EXCLUSIVE  = 0x00000010
)

const (
	DDPF_ALPHAPIXELS     = 0x00000001
	DDPF_ALPHA           = 0x00000002
	DDPF_FOURCC          = 0x00000004
	DDPF_PALETTEINDEXED8 = 0x00000020
	DDPF_RGB             = 0x00000040
)

const (
	DDBLT_COLORFILL = 0x00000400
	DDBLT_KEYDEST   = 0x00002000
	DDBLT_KEYSRC    = 0x00008000

	DDBLTFAST_SRCCOLORKEY  = 0x00000001
	DDBLTFAST_DESTCOLORKEY = 0x00000002

	DDCKEY_DESTBLT = 0x00000002
	DDCKEY_SRCBLT  = 0x00000004

	DDENUMRET_CANCEL = 0
	DDENUMRET_OK     = 1
)

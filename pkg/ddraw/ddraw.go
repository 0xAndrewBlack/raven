package ddraw

import (
	"encoding/binary"
	"errors"
)

type DirectDraw struct {
	CoopLevel      uint32
	DisplayWidth   uint32
	DisplayHeight  uint32
	DisplayBPP     uint32
	Surfaces       []*Surface
	PrimarySurface *Surface
}

func NewDirectDraw() *DirectDraw {
	return &DirectDraw{
		DisplayWidth:  640,
		DisplayHeight: 480,
		DisplayBPP:    32,
	}
}

func (dd *DirectDraw) SetCooperativeLevel(hwnd, flags uint32) error {
	if flags == 0 {
		return errors.New("ddraw: cooperative level flags required")
	}
	dd.CoopLevel = flags
	return nil
}

func (dd *DirectDraw) SetDisplayMode(width, height, bpp, refreshRate, flags uint32) error {
	if width == 0 || height == 0 || bpp == 0 {
		return errors.New("ddraw: invalid display mode")
	}
	dd.DisplayWidth = width
	dd.DisplayHeight = height
	dd.DisplayBPP = bpp
	_ = refreshRate
	_ = flags
	return nil
}

// SwitchBPP changes the display BPP and converts all existing surfaces.
// Called when CreatePalette indicates the game expects 8bpp mode.
func (dd *DirectDraw) SwitchBPP(bpp uint32, palette *Palette) {
	if dd.DisplayBPP == bpp {
		return
	}
	oldBPP := dd.DisplayBPP
	dd.DisplayBPP = bpp
	for _, s := range dd.Surfaces {
		if s.BPP == bpp {
			continue
		}
		oldPixels := s.Pixels
		oldPitch := s.Pitch
		oldFormat := s.Format
		s.BPP = bpp
		s.Format = defaultPixelFormat(bpp)
		s.Pitch = alignedPitch(s.Width, bpp)
		s.Pixels = make([]byte, s.Pitch*int(s.Height))
		// Convert existing pixel data from old BPP to new BPP
		if len(oldPixels) > 0 && palette != nil && oldBPP > bpp {
			for y := 0; y < int(s.Height); y++ {
				for x := 0; x < int(s.Width); x++ {
					off := y*oldPitch + x*bytesPerPixel(oldBPP)
					var color uint32
					switch oldBPP {
					case 32:
						if off+4 <= len(oldPixels) {
							color = binary.LittleEndian.Uint32(oldPixels[off : off+4])
							color = decode32Bit(color, oldFormat)
						}
					case 16:
						if off+2 <= len(oldPixels) {
							raw := binary.LittleEndian.Uint16(oldPixels[off : off+2])
							color = decode16Bit(raw, oldFormat)
						}
					}
					s.setPixelColor(x, y, color)
				}
			}
		}
		if palette != nil && s.Palette == nil {
			s.Palette = palette
		}
	}
}

func (dd *DirectDraw) CreateSurface(desc *DDSURFACEDESC2) (*Surface, error) {
	if desc == nil {
		return nil, errors.New("ddraw: nil surface description")
	}
	// Only use width/height from the descriptor if the corresponding flag is set;
	// otherwise these fields may contain uninitialized garbage.
	var width, height uint32
	if desc.DwFlags&DDSD_WIDTH != 0 {
		width = desc.DwWidth
	}
	if desc.DwFlags&DDSD_HEIGHT != 0 {
		height = desc.DwHeight
	}
	caps := desc.DdsCaps
	if caps.DwCaps&DDSCAPS_PRIMARYSURFACE != 0 {
		if width == 0 {
			width = dd.DisplayWidth
		}
		if height == 0 {
			height = dd.DisplayHeight
		}
	}
	if width == 0 {
		width = dd.DisplayWidth
	}
	if height == 0 {
		height = dd.DisplayHeight
	}
	bpp := dd.DisplayBPP
	if desc.DwFlags&DDSD_PIXELFORMAT != 0 && desc.DdpfPixelFormat.DwRGBBitCount != 0 {
		bpp = desc.DdpfPixelFormat.DwRGBBitCount
	}
	format := desc.DdpfPixelFormat
	if desc.DwFlags&DDSD_PIXELFORMAT == 0 || format.DwSize == 0 {
		format = defaultPixelFormat(bpp)
	}
	surface := newSurface(width, height, bpp, format, caps)
	if caps.DwCaps&DDSCAPS_PRIMARYSURFACE != 0 {
		surface.IsPrimary = true
		dd.PrimarySurface = surface
	}
	dd.Surfaces = append(dd.Surfaces, surface)
	if caps.DwCaps&DDSCAPS_PRIMARYSURFACE != 0 && desc.DwFlags&DDSD_BACKBUFFERCOUNT != 0 && desc.DwBackBufferCount > 0 {
		prev := surface
		for i := uint32(0); i < desc.DwBackBufferCount; i++ {
			backCaps := caps
			backCaps.DwCaps &^= DDSCAPS_PRIMARYSURFACE
			backCaps.DwCaps |= DDSCAPS_BACKBUFFER
			back := newSurface(width, height, bpp, format, backCaps)
			prev.BackBuffer = back
			prev = back
			dd.Surfaces = append(dd.Surfaces, back)
		}
	}
	return surface, nil
}

func (dd *DirectDraw) EnumDisplayModes(flags uint32, desc *DDSURFACEDESC2, callback func(*DDSURFACEDESC2) bool) {
	modes := [][3]uint32{
		{640, 480, 32},
		{800, 600, 32},
		{1024, 768, 32},
	}
	for _, mode := range modes {
		modeDesc := DDSURFACEDESC2{
			DwSize:  uint32(sizeofDDSurfaceDesc2()),
			DwFlags: DDSD_CAPS | DDSD_HEIGHT | DDSD_WIDTH | DDSD_PITCH | DDSD_PIXELFORMAT,
			DwWidth: mode[0], DwHeight: mode[1],
			LPitch:          int32(mode[0] * 4),
			DdpfPixelFormat: defaultPixelFormat(mode[2]),
			DdsCaps:         DDSCAPS2{DwCaps: DDSCAPS_PRIMARYSURFACE | DDSCAPS_VIDEOMEMORY},
		}
		if !matchesDisplayMode(desc, &modeDesc, flags) {
			continue
		}
		if callback != nil && !callback(&modeDesc) {
			return
		}
	}
}

func (dd *DirectDraw) GetCaps() DDCAPS {
	caps := DDCAPS{
		DwSize:        uint32(sizeofDDCaps()),
		DwCaps:        DDSCAPS_PRIMARYSURFACE | DDSCAPS_OFFSCREENPLAIN | DDSCAPS_BACKBUFFER | DDSCAPS_FLIP | DDSCAPS_COMPLEX,
		DwCaps2:       DDSCAPS_VIDEOMEMORY | DDSCAPS_SYSTEMMEMORY,
		DwCKeyCaps:    1,
		DwFXCaps:      DDBLT_COLORFILL | DDBLT_KEYSRC,
		DwVidMemTotal: 64 << 20,
		DwVidMemFree:  64 << 20,
		DdsCaps: DDSCAPS2{
			DwCaps:  DDSCAPS_PRIMARYSURFACE | DDSCAPS_OFFSCREENPLAIN | DDSCAPS_BACKBUFFER | DDSCAPS_FLIP | DDSCAPS_COMPLEX,
			DwCaps2: DDSCAPS_VIDEOMEMORY | DDSCAPS_SYSTEMMEMORY,
		},
	}
	return caps
}

func matchesDisplayMode(filter, mode *DDSURFACEDESC2, flags uint32) bool {
	if filter == nil {
		return true
	}
	if (flags&DDSD_WIDTH != 0 || filter.DwWidth != 0) && filter.DwWidth != mode.DwWidth {
		return false
	}
	if (flags&DDSD_HEIGHT != 0 || filter.DwHeight != 0) && filter.DwHeight != mode.DwHeight {
		return false
	}
	if (flags&DDSD_PIXELFORMAT != 0 || filter.DdpfPixelFormat.DwRGBBitCount != 0) &&
		filter.DdpfPixelFormat.DwRGBBitCount != 0 &&
		filter.DdpfPixelFormat.DwRGBBitCount != mode.DdpfPixelFormat.DwRGBBitCount {
		return false
	}
	return true
}

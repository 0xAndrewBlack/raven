package dxgi

import "unicode/utf16"

type Output struct {
desc  DXGI_OUTPUT_DESC
modes []DXGI_MODE_DESC
}

func newOutput() *Output {
desc := DXGI_OUTPUT_DESC{
DesktopCoordinates: Rect{Left: 0, Top: 0, Right: 1920, Bottom: 1080},
AttachedToDesktop: 1,
Rotation:          1,
Monitor:           0x0000000000010001,
}
copy(desc.DeviceName[:], utf16.Encode([]rune("Raven Display")))
return &Output{
desc: desc,
modes: []DXGI_MODE_DESC{
newModeDesc(1920, 1080, DXGI_FORMAT_R8G8B8A8_UNORM),
newModeDesc(1280, 720, DXGI_FORMAT_R8G8B8A8_UNORM),
newModeDesc(800, 600, DXGI_FORMAT_R8G8B8A8_UNORM),
},
}
}

func newModeDesc(width, height, format uint32) DXGI_MODE_DESC {
if format == DXGI_FORMAT_UNKNOWN {
format = DXGI_FORMAT_R8G8B8A8_UNORM
}
return DXGI_MODE_DESC{
Width:       width,
Height:      height,
RefreshRate: DXGI_RATIONAL{Numerator: 60, Denominator: 1},
Format:      format,
}
}

func (o *Output) GetDesc() DXGI_OUTPUT_DESC {
if o == nil {
return DXGI_OUTPUT_DESC{}
}
return o.desc
}

func (o *Output) GetDisplayModeList(format uint32) []DXGI_MODE_DESC {
if o == nil {
return nil
}
modes := make([]DXGI_MODE_DESC, len(o.modes))
copy(modes, o.modes)
if format != DXGI_FORMAT_UNKNOWN {
for i := range modes {
modes[i].Format = format
}
}
return modes
}

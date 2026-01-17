package dxgi

import "unicode/utf16"

type Adapter struct {
Desc    DXGI_ADAPTER_DESC
outputs []*Output
}

func newAdapter() *Adapter {
desc := DXGI_ADAPTER_DESC{
VendorId:             0x1AF4,
DeviceId:             0x1000,
SubSysId:             0x00001000,
Revision:             1,
DedicatedVideoMemory: 2 << 30,
SharedSystemMemory:   2 << 30,
AdapterLuid:          0x524156454E000001,
}
copy(desc.Description[:], utf16.Encode([]rune("Raven Virtual GPU")))
return &Adapter{
Desc: desc,
outputs: []*Output{newOutput()},
}
}

func (a *Adapter) GetDesc() DXGI_ADAPTER_DESC {
if a == nil {
return DXGI_ADAPTER_DESC{}
}
return a.Desc
}

func (a *Adapter) EnumOutputs(index uint32) (*Output, uint32) {
if a == nil || int(index) >= len(a.outputs) {
return nil, DXGI_ERROR_NOT_FOUND
}
return a.outputs[index], S_OK
}

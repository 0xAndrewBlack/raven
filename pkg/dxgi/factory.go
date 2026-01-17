package dxgi

import "github.com/mirkobrombin/Raven/pkg/wl"

type Factory struct {
adapters []*Adapter
}

func NewFactory() *Factory {
return &Factory{adapters: []*Adapter{newAdapter()}}
}

func (f *Factory) EnumAdapters(index uint32) (*Adapter, uint32) {
if f == nil || int(index) >= len(f.adapters) {
return nil, DXGI_ERROR_NOT_FOUND
}
return f.adapters[index], S_OK
}

func (f *Factory) CreateSwapChain(device any, desc DXGI_SWAP_CHAIN_DESC, window *wl.Window) (*SwapChain, uint32) {
_ = device
return NewSwapChain(desc, window), S_OK
}

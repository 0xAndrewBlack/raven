package dxgi

import (
"math"
"sync"

"github.com/mirkobrombin/Raven/pkg/vk"
"github.com/mirkobrombin/Raven/pkg/wl"
)

type Texture2D struct {
mu           sync.Mutex
Width        uint32
Height       uint32
Format       uint32
SampleDesc   DXGI_SAMPLE_DESC
Usage        uint32
BindFlags    uint32
Pixels       []byte
VulkanFormat vk.VkFormat
Image        vk.VkImage
Memory       vk.VkDeviceMemory
View         vk.VkImageView
}

func NewTexture2D(width, height, format uint32, sample DXGI_SAMPLE_DESC, usage uint32) *Texture2D {
if width == 0 {
width = 1
}
if height == 0 {
height = 1
}
if format == DXGI_FORMAT_UNKNOWN {
format = DXGI_FORMAT_R8G8B8A8_UNORM
}
if sample.Count == 0 {
sample.Count = 1
}
return &Texture2D{
Width:        width,
Height:       height,
Format:       format,
SampleDesc:   sample,
Usage:        usage,
BindFlags:    DXGI_USAGE_RENDER_TARGET_OUTPUT,
Pixels:       make([]byte, int(width*height)*4),
VulkanFormat: FormatToVulkan(format),
}
}

func (t *Texture2D) Resize(width, height, format uint32) {
t.mu.Lock()
defer t.mu.Unlock()
if width == 0 {
width = t.Width
}
if height == 0 {
height = t.Height
}
if format == DXGI_FORMAT_UNKNOWN {
format = t.Format
}
t.Width = width
t.Height = height
t.Format = format
t.VulkanFormat = FormatToVulkan(format)
t.Pixels = make([]byte, int(width*height)*4)
}

func (t *Texture2D) ReadbackPixels() []byte {
t.mu.Lock()
defer t.mu.Unlock()
buf := make([]byte, len(t.Pixels))
copy(buf, t.Pixels)
return buf
}

type SwapChain struct {
mu          sync.Mutex
Desc        DXGI_SWAP_CHAIN_DESC
backBuffers []*Texture2D
currentBack int
window      *wl.Window
}

func NewSwapChain(desc DXGI_SWAP_CHAIN_DESC, window *wl.Window) *SwapChain {
if desc.BufferCount == 0 {
desc.BufferCount = 1
}
if desc.BufferDesc.Width == 0 && window != nil {
desc.BufferDesc.Width = uint32(window.Width)
}
if desc.BufferDesc.Height == 0 && window != nil {
desc.BufferDesc.Height = uint32(window.Height)
}
if desc.BufferDesc.Width == 0 {
desc.BufferDesc.Width = 1280
}
if desc.BufferDesc.Height == 0 {
desc.BufferDesc.Height = 720
}
if desc.BufferDesc.Format == DXGI_FORMAT_UNKNOWN {
desc.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM
}
if desc.BufferUsage == 0 {
desc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT | DXGI_USAGE_BACK_BUFFER
}
if desc.SampleDesc.Count == 0 {
desc.SampleDesc.Count = 1
}
sc := &SwapChain{Desc: desc, window: window}
sc.resetBackBuffers(desc.BufferCount, desc.BufferDesc.Width, desc.BufferDesc.Height, desc.BufferDesc.Format)
return sc
}

func (s *SwapChain) Present(syncInterval, flags uint32) uint32 {
_ = syncInterval
_ = flags
if s == nil {
return S_OK
}
s.mu.Lock()
defer s.mu.Unlock()
if len(s.backBuffers) == 0 {
return S_OK
}
buf := s.backBuffers[s.currentBack]
if s.window != nil {
if s.window.Width != int32(s.Desc.BufferDesc.Width) || s.window.Height != int32(s.Desc.BufferDesc.Height) {
s.window.Resize(int32(s.Desc.BufferDesc.Width), int32(s.Desc.BufferDesc.Height))
}
s.window.ResizeIfNeeded()
copyTextureToWindow(buf, s.window)
s.window.Commit()
}
if len(s.backBuffers) > 1 {
s.currentBack = (s.currentBack + 1) % len(s.backBuffers)
}
return S_OK
}

func copyTextureToWindow(tex *Texture2D, window *wl.Window) {
if tex == nil || window == nil || len(window.Pix) == 0 {
return
}
src := tex.ReadbackPixels()
width := minU32(tex.Width, uint32(window.Width))
height := minU32(tex.Height, uint32(window.Height))
stride := int(window.Stride)
if stride <= 0 {
stride = int(width) * 4
}
for y := uint32(0); y < height; y++ {
dstRow := int(y) * stride
srcRow := int(y*tex.Width) * 4
for x := uint32(0); x < width; x++ {
si := srcRow + int(x)*4
di := dstRow + int(x)*4
switch tex.Format {
case DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_FORMAT_B8G8R8X8_UNORM:
window.Pix[di+0] = src[si+0]
window.Pix[di+1] = src[si+1]
window.Pix[di+2] = src[si+2]
window.Pix[di+3] = 0
case DXGI_FORMAT_R32_FLOAT:
v := clampByte(math.Float32frombits(uint32(src[si]) | uint32(src[si+1])<<8 | uint32(src[si+2])<<16 | uint32(src[si+3])<<24))
window.Pix[di+0], window.Pix[di+1], window.Pix[di+2], window.Pix[di+3] = v, v, v, 0
default:
window.Pix[di+0] = src[si+2]
window.Pix[di+1] = src[si+1]
window.Pix[di+2] = src[si+0]
window.Pix[di+3] = 0
}
}
}
}

func clampByte(v float32) byte {
if v <= 0 {
return 0
}
if v >= 1 {
return 255
}
return byte(v * 255)
}

func (s *SwapChain) GetBuffer(index uint32) (*Texture2D, uint32) {
s.mu.Lock()
defer s.mu.Unlock()
if s == nil || len(s.backBuffers) == 0 || int(index) >= len(s.backBuffers) {
return nil, DXGI_ERROR_NOT_FOUND
}
physical := (s.currentBack + int(index)) % len(s.backBuffers)
return s.backBuffers[physical], S_OK
}

func (s *SwapChain) ResizeBuffers(count, width, height, format, flags uint32) uint32 {
_ = flags
if s == nil {
return S_OK
}
s.mu.Lock()
defer s.mu.Unlock()
if count == 0 {
count = uint32(len(s.backBuffers))
if count == 0 {
count = 1
}
}
if width == 0 {
width = s.Desc.BufferDesc.Width
}
if height == 0 {
height = s.Desc.BufferDesc.Height
}
if format == DXGI_FORMAT_UNKNOWN {
format = s.Desc.BufferDesc.Format
}
s.Desc.BufferCount = count
s.Desc.BufferDesc.Width = width
s.Desc.BufferDesc.Height = height
s.Desc.BufferDesc.Format = format
if s.window != nil {
s.window.Resize(int32(width), int32(height))
s.window.ResizeIfNeeded()
}
s.resetBackBuffers(count, width, height, format)
return S_OK
}

func (s *SwapChain) GetDesc() DXGI_SWAP_CHAIN_DESC {
s.mu.Lock()
defer s.mu.Unlock()
if s == nil {
return DXGI_SWAP_CHAIN_DESC{}
}
return s.Desc
}

func (s *SwapChain) resetBackBuffers(count, width, height, format uint32) {
s.backBuffers = make([]*Texture2D, 0, count)
for i := uint32(0); i < count; i++ {
s.backBuffers = append(s.backBuffers, NewTexture2D(width, height, format, s.Desc.SampleDesc, s.Desc.BufferUsage))
}
s.currentBack = 0
}

func minU32(a, b uint32) uint32 {
if a < b {
return a
}
return b
}

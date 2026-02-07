//go:build guest_windows

package dxgi

import "github.com/mirkobrombin/Raven/pkg/vk"

const (
S_OK uint32 = 0

DXGI_ERROR_NOT_FOUND = 0x887A0002
)

const (
DXGI_FORMAT_UNKNOWN              uint32 = 0
DXGI_FORMAT_R32_FLOAT           uint32 = 41
DXGI_FORMAT_D24_UNORM_S8_UINT   uint32 = 45
DXGI_FORMAT_R8G8B8A8_UNORM      uint32 = 28
DXGI_FORMAT_B8G8R8A8_UNORM      uint32 = 87
DXGI_FORMAT_B8G8R8X8_UNORM      uint32 = 88
DXGI_FORMAT_R16G16B16A16_FLOAT  uint32 = 10
DXGI_FORMAT_R10G10B10A2_UNORM   uint32 = 24
)

const (
DXGI_SWAP_EFFECT_DISCARD         uint32 = 0
DXGI_SWAP_EFFECT_SEQUENTIAL      uint32 = 1
DXGI_SWAP_EFFECT_FLIP_SEQUENTIAL uint32 = 3
DXGI_SWAP_EFFECT_FLIP_DISCARD    uint32 = 4
)

const (
DXGI_USAGE_SHADER_INPUT         uint32 = 0x00000010
DXGI_USAGE_RENDER_TARGET_OUTPUT uint32 = 0x00000020
DXGI_USAGE_BACK_BUFFER          uint32 = 0x00000040
DXGI_USAGE_SHARED               uint32 = 0x00000080
DXGI_USAGE_READ_ONLY            uint32 = 0x00000100
DXGI_USAGE_DISCARD_ON_PRESENT   uint32 = 0x00000200
DXGI_USAGE_UNORDERED_ACCESS     uint32 = 0x00000400
)

type Rect struct {
Left   int32
Top    int32
Right  int32
Bottom int32
}

type DXGI_RATIONAL struct {
Numerator   uint32
Denominator uint32
}

type DXGI_SAMPLE_DESC struct {
Count   uint32
Quality uint32
}

type DXGI_MODE_DESC struct {
Width             uint32
Height            uint32
RefreshRate       DXGI_RATIONAL
Format            uint32
ScanlineOrdering  uint32
Scaling           uint32
}

type DXGI_SWAP_CHAIN_DESC struct {
BufferDesc   DXGI_MODE_DESC
SampleDesc   DXGI_SAMPLE_DESC
BufferUsage  uint32
BufferCount  uint32
OutputWindow uint64
Windowed     uint32
SwapEffect   uint32
Flags        uint32
}

type DXGI_ADAPTER_DESC struct {
Description             [128]uint16
VendorId                uint32
DeviceId                uint32
SubSysId                uint32
Revision                uint32
DedicatedVideoMemory    uint64
DedicatedSystemMemory   uint64
SharedSystemMemory      uint64
AdapterLuid             uint64
}

type DXGI_OUTPUT_DESC struct {
DeviceName        [32]uint16
DesktopCoordinates Rect
AttachedToDesktop uint32
Rotation          uint32
Monitor           uint64
}

func FormatToVulkan(format uint32) vk.VkFormat {
switch format {
case DXGI_FORMAT_R8G8B8A8_UNORM:
return vk.VK_FORMAT_R8G8B8A8_UNORM
case DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_FORMAT_B8G8R8X8_UNORM:
return vk.VK_FORMAT_B8G8R8A8_UNORM
case DXGI_FORMAT_D24_UNORM_S8_UINT:
return vk.VK_FORMAT_D24_UNORM_S8_UINT
default:
return vk.VK_FORMAT_UNDEFINED
}
}

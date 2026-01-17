package d3d9

import "github.com/mirkobrombin/Raven/pkg/vk"

const (
	D3DFVF_POSITION_MASK  uint32 = 0x00E
	D3DFVF_XYZ            uint32 = 0x002
	D3DFVF_XYZRHW         uint32 = 0x004
	D3DFVF_NORMAL         uint32 = 0x010
	D3DFVF_DIFFUSE        uint32 = 0x040
	D3DFVF_SPECULAR       uint32 = 0x080
	D3DFVF_TEXCOUNT_MASK  uint32 = 0xF00
	D3DFVF_TEXCOUNT_SHIFT uint32 = 8
	D3DFVF_TEX0           uint32 = 0x000
	D3DFVF_TEX1           uint32 = 0x100
	D3DFVF_TEX2           uint32 = 0x200
	D3DFVF_TEX3           uint32 = 0x300
	D3DFVF_TEX4           uint32 = 0x400
	D3DFVF_TEX5           uint32 = 0x500
	D3DFVF_TEX6           uint32 = 0x600
	D3DFVF_TEX7           uint32 = 0x700
	D3DFVF_TEX8           uint32 = 0x800
)

func FVFVertexSize(fvf uint32) uint32 {
	var size uint32
	switch fvf & D3DFVF_POSITION_MASK {
	case D3DFVF_XYZ:
		size += 12
	case D3DFVF_XYZRHW:
		size += 16
	}
	if fvf&D3DFVF_NORMAL != 0 {
		size += 12
	}
	if fvf&D3DFVF_DIFFUSE != 0 {
		size += 4
	}
	if fvf&D3DFVF_SPECULAR != 0 {
		size += 4
	}
	size += fvfTexCoordCount(fvf) * 8
	return size
}

func FVFToVertexBindings(fvf uint32) ([]vk.VkVertexInputBindingDescription, []vk.VkVertexInputAttributeDescription) {
	stride := FVFVertexSize(fvf)
	if stride == 0 {
		return nil, nil
	}
	bindings := []vk.VkVertexInputBindingDescription{{Binding: 0, Stride: stride, InputRate: vk.VK_VERTEX_INPUT_RATE_VERTEX}}
	attrs := make([]vk.VkVertexInputAttributeDescription, 0, 7)
	var offset uint32
	switch fvf & D3DFVF_POSITION_MASK {
	case D3DFVF_XYZ:
		attrs = append(attrs, vk.VkVertexInputAttributeDescription{Location: 0, Binding: 0, Format: vk.VK_FORMAT_R32G32B32_SFLOAT, Offset: offset})
		offset += 12
	case D3DFVF_XYZRHW:
		attrs = append(attrs, vk.VkVertexInputAttributeDescription{Location: 0, Binding: 0, Format: vk.VK_FORMAT_R32G32B32A32_SFLOAT, Offset: offset})
		offset += 16
	}
	if fvf&D3DFVF_NORMAL != 0 {
		attrs = append(attrs, vk.VkVertexInputAttributeDescription{Location: 1, Binding: 0, Format: vk.VK_FORMAT_R32G32B32_SFLOAT, Offset: offset})
		offset += 12
	}
	if fvf&D3DFVF_DIFFUSE != 0 {
		attrs = append(attrs, vk.VkVertexInputAttributeDescription{Location: 2, Binding: 0, Format: vk.VK_FORMAT_R8G8B8A8_UNORM, Offset: offset})
		offset += 4
	}
	if fvf&D3DFVF_SPECULAR != 0 {
		offset += 4
	}
	for i := uint32(0); i < fvfTexCoordCount(fvf) && i < 4; i++ {
		attrs = append(attrs, vk.VkVertexInputAttributeDescription{Location: 3 + i, Binding: 0, Format: vk.VK_FORMAT_R32G32_SFLOAT, Offset: offset})
		offset += 8
	}
	return bindings, attrs
}

func fvfTexCoordCount(fvf uint32) uint32 {
	return (fvf & D3DFVF_TEXCOUNT_MASK) >> D3DFVF_TEXCOUNT_SHIFT
}

func declTypeToVkFormat(typ uint8) vk.VkFormat {
	switch typ {
	case D3DDECLTYPE_FLOAT1:
		return vk.VK_FORMAT_R32_SFLOAT
	case D3DDECLTYPE_FLOAT2, D3DDECLTYPE_FLOAT16_2:
		return vk.VK_FORMAT_R32G32_SFLOAT
	case D3DDECLTYPE_FLOAT3:
		return vk.VK_FORMAT_R32G32B32_SFLOAT
	case D3DDECLTYPE_FLOAT4, D3DDECLTYPE_FLOAT16_4:
		return vk.VK_FORMAT_R32G32B32A32_SFLOAT
	case D3DDECLTYPE_D3DCOLOR, D3DDECLTYPE_UBYTE4, D3DDECLTYPE_UBYTE4N:
		return vk.VK_FORMAT_R8G8B8A8_UNORM
	case D3DDECLTYPE_SHORT2, D3DDECLTYPE_SHORT2N, D3DDECLTYPE_USHORT2N:
		return vk.VK_FORMAT_R32G32_SFLOAT
	case D3DDECLTYPE_SHORT4, D3DDECLTYPE_SHORT4N, D3DDECLTYPE_USHORT4N:
		return vk.VK_FORMAT_R32G32B32A32_SFLOAT
	default:
		return vk.VK_FORMAT_UNDEFINED
	}
}

func declTypeSize(typ uint8) uint32 {
	switch typ {
	case D3DDECLTYPE_FLOAT1:
		return 4
	case D3DDECLTYPE_FLOAT2, D3DDECLTYPE_SHORT2, D3DDECLTYPE_SHORT2N, D3DDECLTYPE_USHORT2N, D3DDECLTYPE_FLOAT16_2:
		return 8
	case D3DDECLTYPE_FLOAT3:
		return 12
	case D3DDECLTYPE_FLOAT4, D3DDECLTYPE_SHORT4, D3DDECLTYPE_SHORT4N, D3DDECLTYPE_USHORT4N, D3DDECLTYPE_FLOAT16_4:
		return 16
	case D3DDECLTYPE_D3DCOLOR, D3DDECLTYPE_UBYTE4, D3DDECLTYPE_UBYTE4N, D3DDECLTYPE_UDEC3, D3DDECLTYPE_DEC3N:
		return 4
	default:
		return 0
	}
}

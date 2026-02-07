//go:build guest_windows

package d3d11

import "github.com/mirkobrombin/Raven/pkg/vk"

type Buffer struct {
	Desc     D3D11_BUFFER_DESC
	Data     []byte
	VkBuffer vk.VkBuffer
	VkMemory vk.VkDeviceMemory
}

type Texture2D struct {
	Desc        D3D11_TEXTURE2D_DESC
	Data        []byte
	VkImage     vk.VkImage
	VkImageView vk.VkImageView
	VkMemory    vk.VkDeviceMemory
}

type ShaderResourceView struct {
	Resource uint64
	Desc     D3D11_SHADER_RESOURCE_VIEW_DESC
}

type RenderTargetView struct {
	Resource uint64
	Desc     D3D11_RENDER_TARGET_VIEW_DESC
}

type DepthStencilView struct {
	Resource uint64
	Desc     D3D11_DEPTH_STENCIL_VIEW_DESC
}

type VertexShader struct {
	Bytecode       []byte
	SPIRV          []byte
	VkShaderModule vk.VkShaderModule
}

type PixelShader struct {
	Bytecode       []byte
	SPIRV          []byte
	VkShaderModule vk.VkShaderModule
}

type InputLayout struct {
	Elements       []D3D11_INPUT_ELEMENT_DESC
	ShaderBytecode []byte
}

type BlendState struct{ Desc D3D11_BLEND_DESC }

type RasterizerState struct{ Desc D3D11_RASTERIZER_DESC }

type DepthStencilState struct{ Desc D3D11_DEPTH_STENCIL_DESC }

type SamplerState struct{ Desc D3D11_SAMPLER_DESC }

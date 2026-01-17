package d3d11

import (
	"errors"
	"fmt"
	"sync"

	"github.com/mirkobrombin/Raven/pkg/dxbc"
	"github.com/mirkobrombin/Raven/pkg/dxgi"
	"github.com/mirkobrombin/Raven/pkg/vk"
)

type Device struct {
	VkDevice  vk.VkDevice
	Features  []uint32
	Resources map[uint64]any

	mu         sync.Mutex
	nextHandle uint64
}

func NewDevice(vkDevice vk.VkDevice) *Device {
	return &Device{
		VkDevice:   vkDevice,
		Features:   []uint32{0x9100, 0xB000, 0xC000},
		Resources:  map[uint64]any{},
		nextHandle: 1,
	}
}

func (d *Device) nextID() uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	id := d.nextHandle
	d.nextHandle++
	return id
}

func (d *Device) store(v any) uint64 {
	id := d.nextID()
	d.mu.Lock()
	d.Resources[id] = v
	d.mu.Unlock()
	return id
}

func (d *Device) Lookup(handle uint64) any {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.Resources[handle]
}

func (d *Device) CreateBuffer(desc D3D11_BUFFER_DESC, initialData []byte) (uint64, error) {
	if desc.ByteWidth == 0 {
		return 0, errors.New("buffer byte width is zero")
	}
	buf := &Buffer{Desc: desc, Data: make([]byte, desc.ByteWidth)}
	copy(buf.Data, initialData)
	if d.VkDevice != 0 {
		usage := vk.VK_BUFFER_USAGE_TRANSFER_DST_BIT
		if desc.BindFlags&D3D11_BIND_VERTEX_BUFFER != 0 {
			usage |= vk.VK_BUFFER_USAGE_VERTEX_BUFFER_BIT
		}
		if desc.BindFlags&D3D11_BIND_INDEX_BUFFER != 0 {
			usage |= vk.VK_BUFFER_USAGE_INDEX_BUFFER_BIT
		}
		if desc.BindFlags&D3D11_BIND_CONSTANT_BUFFER != 0 {
			usage |= vk.VK_BUFFER_USAGE_UNIFORM_BUFFER_BIT
		}
		buf.VkBuffer, buf.VkMemory, _ = vk.CreateBuffer(d.VkDevice, vk.VkDeviceSize(desc.ByteWidth), usage, vk.VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT|vk.VK_MEMORY_PROPERTY_HOST_COHERENT_BIT)
	}
	if buf.VkBuffer == 0 {
		buf.VkBuffer = vk.VkBuffer(d.nextID())
	}
	return d.store(buf), nil
}

func (d *Device) CreateTexture2D(desc D3D11_TEXTURE2D_DESC, initialData []byte) (uint64, error) {
	if desc.Width == 0 {
		desc.Width = 1
	}
	if desc.Height == 0 {
		desc.Height = 1
	}
	if desc.MipLevels == 0 {
		desc.MipLevels = 1
	}
	if desc.ArraySize == 0 {
		desc.ArraySize = 1
	}
	if desc.SampleCount == 0 {
		desc.SampleCount = 1
	}
	tex := &Texture2D{Desc: desc, Data: make([]byte, textureDataSize(desc, 0, 0))}
	copy(tex.Data, initialData)
	if d.VkDevice != 0 {
		usage := vk.VK_IMAGE_USAGE_TRANSFER_DST_BIT
		if desc.BindFlags&D3D11_BIND_SHADER_RESOURCE != 0 {
			usage |= vk.VK_IMAGE_USAGE_SAMPLED_BIT
		}
		if desc.BindFlags&D3D11_BIND_RENDER_TARGET != 0 {
			usage |= vk.VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT
		}
		if desc.BindFlags&D3D11_BIND_DEPTH_STENCIL != 0 {
			usage |= vk.VK_IMAGE_USAGE_DEPTH_STENCIL_ATTACHMENT_BIT
		}
		format := dxgi.FormatToVulkan(desc.Format)
		tex.VkImage, tex.VkMemory, _ = vk.CreateImage(d.VkDevice, desc.Width, desc.Height, format, usage, vk.VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT)
		if tex.VkImage != 0 {
			aspect := vk.VK_IMAGE_ASPECT_COLOR_BIT
			if desc.BindFlags&D3D11_BIND_DEPTH_STENCIL != 0 {
				aspect = vk.VK_IMAGE_ASPECT_DEPTH_BIT | vk.VK_IMAGE_ASPECT_STENCIL_BIT
			}
			tex.VkImageView, _ = vk.CreateImageView(d.VkDevice, tex.VkImage, format, aspect)
		}
	}
	if tex.VkImage == 0 {
		tex.VkImage = vk.VkImage(d.nextID())
	}
	if tex.VkImageView == 0 {
		tex.VkImageView = vk.VkImageView(d.nextID())
	}
	return d.store(tex), nil
}

func (d *Device) ImportTexture2D(desc D3D11_TEXTURE2D_DESC, data []byte, image vk.VkImage, view vk.VkImageView) uint64 {
	tex := &Texture2D{Desc: desc, Data: data, VkImage: image, VkImageView: view}
	if tex.VkImage == 0 {
		tex.VkImage = vk.VkImage(d.nextID())
	}
	if tex.VkImageView == 0 {
		tex.VkImageView = vk.VkImageView(d.nextID())
	}
	return d.store(tex)
}

func (d *Device) CreateShaderResourceView(resource uint64, desc *D3D11_SHADER_RESOURCE_VIEW_DESC) (uint64, error) {
	if d.Lookup(resource) == nil {
		return 0, errors.New("resource not found")
	}
	view := &ShaderResourceView{Resource: resource}
	if desc != nil {
		view.Desc = *desc
	}
	if view.Desc.ViewDimension == 0 {
		view.Desc.ViewDimension = D3D11_SRV_DIMENSION_TEXTURE2D
	}
	return d.store(view), nil
}

func (d *Device) CreateRenderTargetView(resource uint64, desc *D3D11_RENDER_TARGET_VIEW_DESC) (uint64, error) {
	if d.Lookup(resource) == nil {
		return 0, errors.New("resource not found")
	}
	view := &RenderTargetView{Resource: resource}
	if desc != nil {
		view.Desc = *desc
	}
	if view.Desc.ViewDimension == 0 {
		view.Desc.ViewDimension = D3D11_RTV_DIMENSION_TEXTURE2D
	}
	return d.store(view), nil
}

func (d *Device) CreateDepthStencilView(resource uint64, desc *D3D11_DEPTH_STENCIL_VIEW_DESC) (uint64, error) {
	if d.Lookup(resource) == nil {
		return 0, errors.New("resource not found")
	}
	view := &DepthStencilView{Resource: resource}
	if desc != nil {
		view.Desc = *desc
	}
	if view.Desc.ViewDimension == 0 {
		view.Desc.ViewDimension = D3D11_DSV_DIMENSION_TEXTURE2D
	}
	return d.store(view), nil
}

func (d *Device) CreateVertexShader(bytecode []byte) (uint64, error) {
	shader, err := d.compileShader(bytecode)
	if err != nil {
		return 0, err
	}
	return d.store(&VertexShader{Bytecode: append([]byte(nil), bytecode...), SPIRV: shader.SPIRV, VkShaderModule: shader.VkShaderModule}), nil
}

func (d *Device) CreatePixelShader(bytecode []byte) (uint64, error) {
	shader, err := d.compileShader(bytecode)
	if err != nil {
		return 0, err
	}
	return d.store(&PixelShader{Bytecode: append([]byte(nil), bytecode...), SPIRV: shader.SPIRV, VkShaderModule: shader.VkShaderModule}), nil
}

func (d *Device) CreateInputLayout(elementDescs []D3D11_INPUT_ELEMENT_DESC, shaderBytecode []byte) (uint64, error) {
	layout := &InputLayout{Elements: append([]D3D11_INPUT_ELEMENT_DESC(nil), elementDescs...), ShaderBytecode: append([]byte(nil), shaderBytecode...)}
	return d.store(layout), nil
}

func (d *Device) CreateBlendState(desc D3D11_BLEND_DESC) (uint64, error) {
	return d.store(&BlendState{Desc: desc}), nil
}

func (d *Device) CreateRasterizerState(desc D3D11_RASTERIZER_DESC) (uint64, error) {
	return d.store(&RasterizerState{Desc: desc}), nil
}

func (d *Device) CreateDepthStencilState(desc D3D11_DEPTH_STENCIL_DESC) (uint64, error) {
	return d.store(&DepthStencilState{Desc: desc}), nil
}

func (d *Device) CreateSamplerState(desc D3D11_SAMPLER_DESC) (uint64, error) {
	return d.store(&SamplerState{Desc: desc}), nil
}

func textureDataSize(desc D3D11_TEXTURE2D_DESC, rowPitch, depthPitch uint32) int {
	if depthPitch != 0 {
		return int(depthPitch)
	}
	if rowPitch != 0 {
		return int(rowPitch * desc.Height)
	}
	return int(desc.Width) * int(desc.Height) * bytesPerPixel(desc.Format)
}

func bytesPerPixel(format uint32) int {
	switch format {
	case D3D11_FORMAT_R16G16B16A16_FLOAT:
		return 8
	default:
		return 4
	}
}

type compiledShader struct {
	SPIRV          []byte
	VkShaderModule vk.VkShaderModule
}

func (d *Device) compileShader(bytecode []byte) (*compiledShader, error) {
	dxbcShader, err := dxbc.Parse(bytecode)
	if err != nil {
		return nil, fmt.Errorf("parse dxbc shader: %w", err)
	}
	spirvCode, err := dxbc.Compile(dxbcShader)
	if err != nil {
		return nil, fmt.Errorf("compile dxbc shader: %w", err)
	}
	out := &compiledShader{SPIRV: spirvCode}
	if d.VkDevice != 0 {
		module, res := vk.CreateShaderModule(d.VkDevice, spirvCode)
		if res != vk.VK_SUCCESS {
			return nil, fmt.Errorf("create shader module: %v", res)
		}
		out.VkShaderModule = module
	}
	return out, nil
}

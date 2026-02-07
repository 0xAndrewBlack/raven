//go:build guest_windows

package d3d11

import (
	"errors"
	"math"
	"unsafe"

	"github.com/mirkobrombin/Raven/pkg/vk"
)

type BoundVertexBuffer struct {
	Buffer uint64
	Stride uint32
	Offset uint32
}

type DrawCommand struct {
	Indexed          bool
	VertexCount      uint32
	StartVertex      uint32
	IndexCount       uint32
	StartIndex       uint32
	BaseVertex       int32
	Topology         uint32
	InputLayout      uint64
	VertexShader     uint64
	PixelShader      uint64
	VertexBuffers    []BoundVertexBuffer
	IndexBuffer      uint64
	IndexFormat      uint32
	IndexOffset      uint32
	RenderTargets    []uint64
	DepthStencilView uint64
	Viewports        []D3D11_VIEWPORT
	Scissors         []D3D11_RECT
}

type DeviceContext struct {
	device *Device

	VertexBuffers     []BoundVertexBuffer
	IndexBuffer       uint64
	IndexFormat       uint32
	IndexOffset       uint32
	InputLayout       uint64
	PrimitiveTopology uint32
	VertexShader      uint64
	PixelShader       uint64
	VSConstantBuffers []uint64
	PSConstantBuffers []uint64
	PSShaderResources []uint64
	PSSamplers        []uint64
	Viewports         []D3D11_VIEWPORT
	Scissors          []D3D11_RECT
	RasterizerState   uint64
	RenderTargets     []uint64
	DepthStencilView  uint64
	BlendState        uint64
	BlendFactor       [4]float32
	SampleMask        uint32
	DepthStencilState uint64
	StencilRef        uint32
	VkCommandBuffer   vk.VkCommandBuffer
	Commands          []DrawCommand
}

func NewDeviceContext(device *Device) *DeviceContext {
	return &DeviceContext{device: device, SampleMask: ^uint32(0)}
}

func (c *DeviceContext) Device() *Device { return c.device }

func (c *DeviceContext) IASetVertexBuffers(startSlot, numBuffers uint32, buffers, strides, offsets []uint64) {
	if numBuffers == 0 {
		return
	}
	ensureVB(&c.VertexBuffers, int(startSlot+numBuffers))
	for i := uint32(0); i < numBuffers; i++ {
		if int(i) >= len(buffers) {
			break
		}
		var stride, offset uint32
		if int(i) < len(strides) {
			stride = uint32(strides[i])
		}
		if int(i) < len(offsets) {
			offset = uint32(offsets[i])
		}
		c.VertexBuffers[int(startSlot+i)] = BoundVertexBuffer{Buffer: buffers[i], Stride: stride, Offset: offset}
	}
}

func (c *DeviceContext) IASetIndexBuffer(buffer, format, offset uint64) {
	c.IndexBuffer = buffer
	c.IndexFormat = uint32(format)
	c.IndexOffset = uint32(offset)
}

func (c *DeviceContext) IASetInputLayout(layout uint64)                  { c.InputLayout = layout }
func (c *DeviceContext) IASetPrimitiveTopology(topology uint32)          { c.PrimitiveTopology = topology }
func (c *DeviceContext) VSSetShader(shader uint64, _ []uint64, _ uint32) { c.VertexShader = shader }
func (c *DeviceContext) PSSetShader(shader uint64, _ []uint64, _ uint32) { c.PixelShader = shader }
func (c *DeviceContext) RSSetState(state uint64)                         { c.RasterizerState = state }
func (c *DeviceContext) OMSetDepthStencilState(state uint64, ref uint32) {
	c.DepthStencilState, c.StencilRef = state, ref
}

func (c *DeviceContext) VSSetConstantBuffers(startSlot, numBuffers uint32, buffers []uint64) {
	ensureHandles(&c.VSConstantBuffers, int(startSlot+numBuffers))
	copy(c.VSConstantBuffers[startSlot:], buffers[:minInt(int(numBuffers), len(buffers))])
}

func (c *DeviceContext) PSSetShaderResources(startSlot, numViews uint32, views []uint64) {
	ensureHandles(&c.PSShaderResources, int(startSlot+numViews))
	copy(c.PSShaderResources[startSlot:], views[:minInt(int(numViews), len(views))])
}

func (c *DeviceContext) PSSetSamplers(startSlot, numSamplers uint32, samplers []uint64) {
	ensureHandles(&c.PSSamplers, int(startSlot+numSamplers))
	copy(c.PSSamplers[startSlot:], samplers[:minInt(int(numSamplers), len(samplers))])
}

func (c *DeviceContext) PSSetConstantBuffers(startSlot, numBuffers uint32, buffers []uint64) {
	ensureHandles(&c.PSConstantBuffers, int(startSlot+numBuffers))
	copy(c.PSConstantBuffers[startSlot:], buffers[:minInt(int(numBuffers), len(buffers))])
}

func (c *DeviceContext) RSSetViewports(numViewports uint32, viewports []D3D11_VIEWPORT) {
	c.Viewports = append([]D3D11_VIEWPORT(nil), viewports[:minInt(int(numViewports), len(viewports))]...)
}

func (c *DeviceContext) RSSetScissorRects(numRects uint32, rects []D3D11_RECT) {
	c.Scissors = append([]D3D11_RECT(nil), rects[:minInt(int(numRects), len(rects))]...)
}

func (c *DeviceContext) OMSetRenderTargets(numViews uint32, renderTargetViews []uint64, depthStencilView uint64) {
	c.RenderTargets = append([]uint64(nil), renderTargetViews[:minInt(int(numViews), len(renderTargetViews))]...)
	c.DepthStencilView = depthStencilView
}

func (c *DeviceContext) OMSetBlendState(blendState uint64, blendFactor [4]float32, sampleMask uint32) {
	c.BlendState = blendState
	c.BlendFactor = blendFactor
	c.SampleMask = sampleMask
}

func (c *DeviceContext) Draw(vertexCount, startVertexLocation uint32) {
	cmd := c.snapshot(false)
	cmd.VertexCount = vertexCount
	cmd.StartVertex = startVertexLocation
	c.Commands = append(c.Commands, cmd)
	c.emit(cmd)
}

func (c *DeviceContext) DrawIndexed(indexCount, startIndexLocation uint32, baseVertexLocation int32) {
	cmd := c.snapshot(true)
	cmd.IndexCount = indexCount
	cmd.StartIndex = startIndexLocation
	cmd.BaseVertex = baseVertexLocation
	c.Commands = append(c.Commands, cmd)
	c.emit(cmd)
}

func (c *DeviceContext) ClearRenderTargetView(view uint64, color [4]float32) error {
	rtv, ok := c.device.Lookup(view).(*RenderTargetView)
	if !ok || rtv == nil {
		return errors.New("render target view not found")
	}
	tex, ok := c.device.Lookup(rtv.Resource).(*Texture2D)
	if !ok || tex == nil {
		return errors.New("render target resource not found")
	}
	fillColor(tex.Data, tex.Desc.Format, color)
	return nil
}

func (c *DeviceContext) ClearDepthStencilView(view uint64, clearFlags uint32, depth float32, stencil uint8) error {
	dsv, ok := c.device.Lookup(view).(*DepthStencilView)
	if !ok || dsv == nil {
		return errors.New("depth stencil view not found")
	}
	tex, ok := c.device.Lookup(dsv.Resource).(*Texture2D)
	if !ok || tex == nil {
		return errors.New("depth stencil resource not found")
	}
	if len(tex.Data) == 0 {
		tex.Data = make([]byte, textureDataSize(tex.Desc, 0, 0))
	}
	for i := 0; i+3 < len(tex.Data); i += 4 {
		if clearFlags&D3D11_CLEAR_DEPTH != 0 {
			bits := math.Float32bits(depth)
			tex.Data[i+0] = byte(bits)
			tex.Data[i+1] = byte(bits >> 8)
			tex.Data[i+2] = byte(bits >> 16)
			tex.Data[i+3] = byte(bits >> 24)
		}
		if clearFlags&D3D11_CLEAR_STENCIL != 0 {
			tex.Data[i+3] = stencil
		}
	}
	return nil
}

func (c *DeviceContext) Map(resource, subresource, mapType uint32) (D3D11_MAPPED_SUBRESOURCE, error) {
	_, _ = subresource, mapType
	switch v := c.device.Lookup(uint64(resource)).(type) {
	case *Buffer:
		if len(v.Data) == 0 {
			v.Data = make([]byte, v.Desc.ByteWidth)
		}
		return mapped(v.Data, uint32(len(v.Data)), uint32(len(v.Data))), nil
	case *Texture2D:
		if len(v.Data) == 0 {
			v.Data = make([]byte, textureDataSize(v.Desc, 0, 0))
		}
		rowPitch := uint32(v.Desc.Width * uint32(bytesPerPixel(v.Desc.Format)))
		return mapped(v.Data, rowPitch, rowPitch*v.Desc.Height), nil
	default:
		return D3D11_MAPPED_SUBRESOURCE{}, errors.New("resource not mappable")
	}
}

func (c *DeviceContext) Unmap(resource, subresource uint32) { _, _ = resource, subresource }

func (c *DeviceContext) UpdateSubresource(resource, subresource uint32, box *D3D11_BOX, data []byte, rowPitch, depthPitch uint32) error {
	_, _ = subresource, box
	switch v := c.device.Lookup(uint64(resource)).(type) {
	case *Buffer:
		if len(v.Data) < len(data) {
			v.Data = make([]byte, len(data))
		}
		copy(v.Data, data)
		return nil
	case *Texture2D:
		size := textureDataSize(v.Desc, rowPitch, depthPitch)
		if size < len(data) {
			size = len(data)
		}
		if len(v.Data) < size {
			v.Data = make([]byte, size)
		}
		copy(v.Data, data)
		return nil
	default:
		return errors.New("resource not found")
	}
}

func (c *DeviceContext) snapshot(indexed bool) DrawCommand {
	return DrawCommand{
		Indexed:          indexed,
		Topology:         c.PrimitiveTopology,
		InputLayout:      c.InputLayout,
		VertexShader:     c.VertexShader,
		PixelShader:      c.PixelShader,
		VertexBuffers:    append([]BoundVertexBuffer(nil), c.VertexBuffers...),
		IndexBuffer:      c.IndexBuffer,
		IndexFormat:      c.IndexFormat,
		IndexOffset:      c.IndexOffset,
		RenderTargets:    append([]uint64(nil), c.RenderTargets...),
		DepthStencilView: c.DepthStencilView,
		Viewports:        append([]D3D11_VIEWPORT(nil), c.Viewports...),
		Scissors:         append([]D3D11_RECT(nil), c.Scissors...),
	}
}

func (c *DeviceContext) emit(cmd DrawCommand) {
	if c.VkCommandBuffer == 0 {
		return
	}
	if len(cmd.Viewports) != 0 {
		vps := make([]vk.VkViewport, 0, len(cmd.Viewports))
		for _, vp := range cmd.Viewports {
			vps = append(vps, vk.VkViewport{X: vp.TopLeftX, Y: vp.TopLeftY, Width: vp.Width, Height: vp.Height, MinDepth: vp.MinDepth, MaxDepth: vp.MaxDepth})
		}
		vk.CmdSetViewport(c.VkCommandBuffer, 0, vps)
	}
	if len(cmd.Scissors) != 0 {
		scs := make([]vk.VkRect2D, 0, len(cmd.Scissors))
		for _, rect := range cmd.Scissors {
			width := rect.Right - rect.Left
			height := rect.Bottom - rect.Top
			if width < 0 {
				width = 0
			}
			if height < 0 {
				height = 0
			}
			scs = append(scs, vk.VkRect2D{Offset: vk.VkOffset2D{X: rect.Left, Y: rect.Top}, Extent: vk.VkExtent2D{Width: uint32(width), Height: uint32(height)}})
		}
		vk.CmdSetScissor(c.VkCommandBuffer, 0, scs)
	}
	if len(cmd.VertexBuffers) != 0 {
		var bufs []vk.VkBuffer
		var offs []vk.VkDeviceSize
		for _, bound := range cmd.VertexBuffers {
			buf, ok := c.device.Lookup(bound.Buffer).(*Buffer)
			if !ok || buf == nil || buf.VkBuffer == 0 {
				continue
			}
			bufs = append(bufs, buf.VkBuffer)
			offs = append(offs, vk.VkDeviceSize(bound.Offset))
		}
		if len(bufs) != 0 {
			vk.CmdBindVertexBuffers(c.VkCommandBuffer, 0, bufs, offs)
		}
	}
	if cmd.Indexed {
		if buf, ok := c.device.Lookup(cmd.IndexBuffer).(*Buffer); ok && buf != nil && buf.VkBuffer != 0 {
			vk.CmdBindIndexBuffer(c.VkCommandBuffer, buf.VkBuffer, vk.VkDeviceSize(cmd.IndexOffset), indexType(cmd.IndexFormat))
		}
		vk.CmdDrawIndexed(c.VkCommandBuffer, cmd.IndexCount, 1, cmd.StartIndex, cmd.BaseVertex, 0)
		return
	}
	vk.CmdDraw(c.VkCommandBuffer, cmd.VertexCount, 1, cmd.StartVertex, 0)
}

func mapped(data []byte, rowPitch, depthPitch uint32) D3D11_MAPPED_SUBRESOURCE {
	var ptr uint64
	if len(data) != 0 {
		ptr = uint64(uintptr(unsafe.Pointer(&data[0])))
	}
	return D3D11_MAPPED_SUBRESOURCE{PData: ptr, RowPitch: rowPitch, DepthPitch: depthPitch}
}

func fillColor(dst []byte, format uint32, color [4]float32) {
	if len(dst) == 0 {
		return
	}
	r, g, b, a := clampColor(color[0]), clampColor(color[1]), clampColor(color[2]), clampColor(color[3])
	for i := 0; i+3 < len(dst); i += 4 {
		switch format {
		case D3D11_FORMAT_B8G8R8A8_UNORM, D3D11_FORMAT_B8G8R8X8_UNORM:
			dst[i+0], dst[i+1], dst[i+2], dst[i+3] = b, g, r, a
		default:
			dst[i+0], dst[i+1], dst[i+2], dst[i+3] = r, g, b, a
		}
	}
}

func clampColor(v float32) byte {
	if v <= 0 {
		return 0
	}
	if v >= 1 {
		return 255
	}
	return byte(v * 255)
}

func indexType(format uint32) vk.VkIndexType {
	switch format {
	case 42:
		return vk.VK_INDEX_TYPE_UINT32
	default:
		return vk.VK_INDEX_TYPE_UINT16
	}
}

func ensureVB(dst *[]BoundVertexBuffer, size int) {
	if len(*dst) >= size {
		return
	}
	next := make([]BoundVertexBuffer, size)
	copy(next, *dst)
	*dst = next
}

func ensureHandles(dst *[]uint64, size int) {
	if len(*dst) >= size {
		return
	}
	next := make([]uint64, size)
	copy(next, *dst)
	*dst = next
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

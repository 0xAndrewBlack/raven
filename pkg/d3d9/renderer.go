//go:build guest_windows

package d3d9

import (
	"hash/fnv"
	"math"
	"strconv"
	"sync"
	"unsafe"

	"github.com/mirkobrombin/Raven/pkg/vk"
	"github.com/mirkobrombin/Raven/pkg/wl"
)

type RenderTarget struct {
	Width, Height  uint32
	Image          vk.VkImage
	View           vk.VkImageView
	Memory         vk.VkDeviceMemory
	Format         vk.VkFormat
	DmabufStride   uint32
	DmabufFormat   uint32
	DmabufModifier uint64
}

type depthAttachment struct {
	Image  vk.VkImage
	View   vk.VkImageView
	Memory vk.VkDeviceMemory
}

type transientBuffer struct {
	buffer vk.VkBuffer
	memory vk.VkDeviceMemory
}

type Renderer struct {
	lifecycle            sync.Mutex
	closed               bool
	vkInstance           vk.VkInstance
	vkPhysicalDevice     vk.VkPhysicalDevice
	vkDevice             vk.VkDevice
	vkQueue              vk.VkQueue
	vkCommandPool        vk.VkCommandPool
	vkCommandBuffer      vk.VkCommandBuffer
	vkRenderPass         vk.VkRenderPass
	currentFramebuffer   vk.VkFramebuffer
	pipelineCache        map[uint64]vk.VkPipeline
	vertexShaderModule   vk.VkShaderModule
	fragmentShaderModule vk.VkShaderModule
	pipelineLayout       vk.VkPipelineLayout
	renderTarget         *RenderTarget
	depthBuffer          depthAttachment
	frameFence           vk.VkFence
	clearValues          [2]vk.VkClearValue
	inScene              bool
	commandReady         bool
	// linearExport is a VK_IMAGE_TILING_LINEAR image used as the DMA-buf export
	// source. The render target uses optimal tiling (GPU-vendor specific layout)
	// which cannot be imported by the compositor with modifier=0. After each
	// frame we vkCmdCopyImage from the render target into this linear image and
	// then export its fd. The actual row pitch is queried once at creation time.
	linearExport       vk.VkImage
	linearExportMemory vk.VkDeviceMemory
	linearExportStride uint32
	pendingBuffers     []transientBuffer

	// Programmable vertex-shader path resources, created lazily on the first
	// draw that has a translated vertex shader bound. The translated SPIR-V
	// reads its c# constants from a uniform block at set 0, binding 0, so the
	// shader path needs a descriptor set + uniform buffer and a pipeline layout
	// that references the descriptor set layout (instead of the FFP push
	// constants). shaderModules tracks vk modules created for cached
	// ShaderProgram.VkModule handles so they can be destroyed on Close.
	shaderResourcesReady bool
	shaderDescLayout     vk.VkDescriptorSetLayout
	shaderDescPool       vk.VkDescriptorPool
	shaderDescSet        vk.VkDescriptorSet
	shaderUniformBuffer  vk.VkBuffer
	shaderUniformMemory  vk.VkDeviceMemory
	shaderPipelineLayout vk.VkPipelineLayout
	shaderModules        []vk.VkShaderModule
}

// vsConstantBufferSize is the byte size of the vertex-shader constant uniform
// buffer: 256 c# registers of vec4 (16 bytes each).
const vsConstantBufferSize = 256 * 16

func (r *Renderer) Close() {
	if r == nil {
		return
	}
	r.lifecycle.Lock()
	defer r.lifecycle.Unlock()
	if r.closed {
		return
	}
	r.closed = true
	device := r.vkDevice
	if device != 0 {
		vk.DeviceWaitIdle(device)
		r.releasePendingBuffers()
		for _, pipeline := range r.pipelineCache {
			vk.DestroyPipeline(device, pipeline)
		}
		for _, module := range r.shaderModules {
			vk.DestroyShaderModule(device, module)
		}
		if r.shaderResourcesReady {
			vk.DestroyPipelineLayout(device, r.shaderPipelineLayout)
			vk.DestroyBuffer(device, r.shaderUniformBuffer)
			vk.FreeMemory(device, r.shaderUniformMemory)
			vk.DestroyDescriptorPool(device, r.shaderDescPool)
			vk.DestroyDescriptorSetLayout(device, r.shaderDescLayout)
		}
		vk.DestroyFramebuffer(device, r.currentFramebuffer)
		vk.DestroyPipelineLayout(device, r.pipelineLayout)
		vk.DestroyShaderModule(device, r.fragmentShaderModule)
		vk.DestroyShaderModule(device, r.vertexShaderModule)
		vk.DestroyRenderPass(device, r.vkRenderPass)
		if r.linearExport != 0 {
			vk.DestroyImage(device, r.linearExport)
			vk.FreeMemory(device, r.linearExportMemory)
		}
		if r.depthBuffer.View != 0 {
			vk.DestroyImageView(device, r.depthBuffer.View)
		}
		if r.depthBuffer.Image != 0 {
			vk.DestroyImage(device, r.depthBuffer.Image)
			vk.FreeMemory(device, r.depthBuffer.Memory)
		}
		if r.renderTarget != nil {
			vk.DestroyImageView(device, r.renderTarget.View)
			vk.DestroyImage(device, r.renderTarget.Image)
			vk.FreeMemory(device, r.renderTarget.Memory)
		}
		vk.DestroyFence(device, r.frameFence)
		if r.vkCommandBuffer != 0 {
			vk.FreeCommandBuffer(device, r.vkCommandPool, r.vkCommandBuffer)
		}
		vk.DestroyCommandPool(device, r.vkCommandPool)
		vk.DestroyDevice(device)
	}
	vk.DestroyInstance(r.vkInstance)
}

type ffpPushConstants struct {
	WVP        [16]float32
	World      [16]float32
	LightDir   [4][4]float32
	LightColor [4][4]float32
	Ambient    [4]float32
}

func NewRenderer(width, height uint32) (*Renderer, error) {
	if err := vk.Init(); err != nil {
		return nil, err
	}
	instance, res := vk.CreateInstance("Raven D3D9", false)
	if res != vk.VK_SUCCESS {
		return nil, vkResultError("create instance", res)
	}
	r := &Renderer{vkInstance: instance, pipelineCache: map[uint64]vk.VkPipeline{}}
	initialized := false
	defer func() {
		if !initialized {
			r.Close()
		}
	}()
	physicalDevice, res := vk.PickPhysicalDevice(instance)
	if res != vk.VK_SUCCESS {
		return nil, vkResultError("pick physical device", res)
	}
	r.vkPhysicalDevice = physicalDevice
	queueFamily := vk.FindGraphicsQueueFamily(physicalDevice)
	device, queue, res := vk.CreateDevice(physicalDevice, queueFamily)
	if res != vk.VK_SUCCESS {
		return nil, vkResultError("create device", res)
	}
	r.vkDevice = device
	r.vkQueue = queue
	commandPool, res := vk.CreateCommandPool(device, queueFamily)
	if res != vk.VK_SUCCESS {
		return nil, vkResultError("create command pool", res)
	}
	r.vkCommandPool = commandPool
	commandBuffer, res := vk.AllocateCommandBuffer(device, commandPool)
	if res != vk.VK_SUCCESS {
		return nil, vkResultError("allocate command buffer", res)
	}
	r.vkCommandBuffer = commandBuffer
	var colorImage vk.VkImage
	var colorMemory vk.VkDeviceMemory
	if vk.SupportsDmabufExport(device) {
		colorImage, colorMemory, res = vk.CreateExportableImage(device, width, height, vk.VK_FORMAT_B8G8R8A8_UNORM, vk.VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT|vk.VK_IMAGE_USAGE_TRANSFER_SRC_BIT, vk.VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT, vk.VkExternalMemoryHandleTypeFlags(vk.VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF_BIT_EXT))
		if res != vk.VK_SUCCESS {
			colorImage, colorMemory, res = vk.CreateImage(device, width, height, vk.VK_FORMAT_B8G8R8A8_UNORM, vk.VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT|vk.VK_IMAGE_USAGE_TRANSFER_SRC_BIT, vk.VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT)
		}
	} else {
		colorImage, colorMemory, res = vk.CreateImage(device, width, height, vk.VK_FORMAT_B8G8R8A8_UNORM, vk.VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT|vk.VK_IMAGE_USAGE_TRANSFER_SRC_BIT, vk.VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT)
	}
	if res != vk.VK_SUCCESS {
		return nil, vkResultError("create render target", res)
	}
	r.renderTarget = &RenderTarget{Width: width, Height: height, Image: colorImage, Memory: colorMemory, Format: vk.VK_FORMAT_B8G8R8A8_UNORM, DmabufStride: width * 4, DmabufFormat: wl.DrmFormatARGB8888}
	colorView, res := vk.CreateImageView(device, colorImage, vk.VK_FORMAT_B8G8R8A8_UNORM, vk.VK_IMAGE_ASPECT_COLOR_BIT)
	if res != vk.VK_SUCCESS {
		return nil, vkResultError("create render target view", res)
	}
	r.renderTarget.View = colorView
	depthImage, depthMemory, res := vk.CreateImage(device, width, height, vk.VK_FORMAT_D24_UNORM_S8_UINT, vk.VK_IMAGE_USAGE_DEPTH_STENCIL_ATTACHMENT_BIT, vk.VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT)
	if res != vk.VK_SUCCESS {
		return nil, vkResultError("create depth buffer", res)
	}
	r.depthBuffer = depthAttachment{Image: depthImage, Memory: depthMemory}
	depthView, res := vk.CreateImageView(device, depthImage, vk.VK_FORMAT_D24_UNORM_S8_UINT, vk.VK_IMAGE_ASPECT_DEPTH_BIT|vk.VK_IMAGE_ASPECT_STENCIL_BIT)
	if res != vk.VK_SUCCESS {
		return nil, vkResultError("create depth buffer view", res)
	}
	r.depthBuffer.View = depthView
	renderPass, res := vk.CreateRenderPass(device, vk.VK_FORMAT_B8G8R8A8_UNORM, vk.VK_FORMAT_D24_UNORM_S8_UINT)
	if res != vk.VK_SUCCESS {
		return nil, vkResultError("create render pass", res)
	}
	r.vkRenderPass = renderPass
	framebuffer, res := vk.CreateFramebuffer(device, renderPass, colorView, depthView, width, height)
	if res != vk.VK_SUCCESS {
		return nil, vkResultError("create framebuffer", res)
	}
	r.currentFramebuffer = framebuffer
	vertSPV := GenerateFFPVertexShader(4, false, 0)
	fragSPV := GenerateFFPFragmentShader(0, nil)
	vertModule, res := vk.CreateShaderModule(device, vertSPV)
	if res != vk.VK_SUCCESS {
		return nil, vkResultError("create vertex shader", res)
	}
	r.vertexShaderModule = vertModule
	fragModule, res := vk.CreateShaderModule(device, fragSPV)
	if res != vk.VK_SUCCESS {
		return nil, vkResultError("create fragment shader", res)
	}
	r.fragmentShaderModule = fragModule
	pushRange := vk.VkPushConstantRange{StageFlags: vk.VkShaderStageFlags(vk.VK_SHADER_STAGE_VERTEX_BIT), Size: uint32(unsafe.Sizeof(ffpPushConstants{}))}
	pipelineLayout, res := vk.CreatePipelineLayout(device, nil, []vk.VkPushConstantRange{pushRange})
	if res != vk.VK_SUCCESS {
		return nil, vkResultError("create pipeline layout", res)
	}
	r.pipelineLayout = pipelineLayout
	frameFence, res := vk.CreateFence(device, true)
	if res != vk.VK_SUCCESS {
		return nil, vkResultError("create fence", res)
	}
	r.frameFence = frameFence
	// Create a linear-tiled exportable image so DMA-buf imports use the correct
	// memory layout. If creation fails, the dmabuf path falls back to readback.
	if vk.SupportsDmabufExport(device) {
		linImg, linMem, linRes := vk.CreateLinearExportableImage(device, width, height, vk.VK_FORMAT_B8G8R8A8_UNORM)
		if linRes == vk.VK_SUCCESS {
			r.linearExport = linImg
			r.linearExportMemory = linMem
			r.linearExportStride = vk.GetLinearImageRowPitch(device, linImg)
			if r.linearExportStride == 0 {
				r.linearExportStride = width * 4
			}
		}
	}
	r.Clear(D3DCLEAR_TARGET|D3DCLEAR_ZBUFFER|D3DCLEAR_STENCIL, 0, 1, 0)
	initialized = true
	return r, nil
}

func (r *Renderer) BeginScene() {
	if r == nil {
		return
	}
	r.lifecycle.Lock()
	defer r.lifecycle.Unlock()
	if r.closed || r.inScene {
		return
	}
	if vk.ResetCommandBuffer(r.vkCommandBuffer, 0) != vk.VK_SUCCESS {
		return
	}
	if vk.BeginCommandBuffer(r.vkCommandBuffer) != vk.VK_SUCCESS {
		return
	}
	v := vk.VkRect2D{Extent: vk.VkExtent2D{Width: r.renderTarget.Width, Height: r.renderTarget.Height}}
	vk.CmdBeginRenderPass(r.vkCommandBuffer, r.vkRenderPass, r.currentFramebuffer, v, r.clearValues[:])
	r.inScene = true
}

func (r *Renderer) EndScene() {
	if r == nil {
		return
	}
	r.lifecycle.Lock()
	defer r.lifecycle.Unlock()
	r.endScene()
}

func (r *Renderer) endScene() {
	if r.closed || !r.inScene {
		return
	}
	vk.CmdEndRenderPass(r.vkCommandBuffer)
	if vk.EndCommandBuffer(r.vkCommandBuffer) == vk.VK_SUCCESS {
		r.inScene = false
		r.commandReady = true
	}
}

func (r *Renderer) Clear(flags uint32, color uint32, z float32, stencil uint32) {
	if r == nil {
		return
	}
	r.lifecycle.Lock()
	defer r.lifecycle.Unlock()
	if r.closed {
		return
	}
	if flags&D3DCLEAR_TARGET != 0 {
		r.clearValues[0] = colorToClearValue(color)
	}
	if flags&(D3DCLEAR_ZBUFFER|D3DCLEAR_STENCIL) != 0 {
		r.clearValues[1] = depthStencilClearValue(z, stencil)
	}
}

func (r *Renderer) DrawPrimitive(dev *Device, primType uint32, startVertex, primCount uint32) {
	if r == nil {
		return
	}
	r.lifecycle.Lock()
	defer r.lifecycle.Unlock()
	if r.closed || dev == nil || !r.inScene {
		return
	}
	source := dev.StreamSources[0]
	if source.Buffer == nil {
		return
	}
	vertexCount := primitiveVertexCount(primType, primCount)
	if vertexCount == 0 {
		return
	}
	vertModule, layout, useShader := r.resolveVertexStage(dev)
	pipeline := r.getOrCreatePipeline(dev, d3dPrimToVkTopology(primType), vertModule, layout)
	if pipeline == 0 {
		return
	}
	vb, _, ok := r.uploadVertexStream(source)
	if !ok {
		return
	}
	vk.CmdBindPipeline(r.vkCommandBuffer, vk.VK_PIPELINE_BIND_POINT_GRAPHICS, pipeline)
	vk.CmdBindVertexBuffers(r.vkCommandBuffer, 0, []vk.VkBuffer{vb}, []vk.VkDeviceSize{0})
	r.bindViewportAndScissor(dev)
	r.bindVertexStageConstants(dev, layout, useShader)
	vk.CmdDraw(r.vkCommandBuffer, vertexCount, 1, startVertex, 0)
}

func (r *Renderer) DrawIndexedPrimitive(dev *Device, primType uint32, baseVertex int32, minIdx, numVertices, startIndex, primCount uint32) {
	_ = minIdx
	_ = numVertices
	if r == nil {
		return
	}
	r.lifecycle.Lock()
	defer r.lifecycle.Unlock()
	if r.closed || dev == nil || !r.inScene || dev.IndexBuffer == nil {
		return
	}
	source := dev.StreamSources[0]
	if source.Buffer == nil {
		return
	}
	indexCount := primitiveIndexCount(primType, primCount)
	if indexCount == 0 {
		return
	}
	vertModule, layout, useShader := r.resolveVertexStage(dev)
	pipeline := r.getOrCreatePipeline(dev, d3dPrimToVkTopology(primType), vertModule, layout)
	if pipeline == 0 {
		return
	}
	vb, _, ok := r.uploadVertexStream(source)
	if !ok {
		return
	}
	ib, indexType, ok := r.uploadIndexBuffer(dev.IndexBuffer)
	if !ok {
		return
	}
	vk.CmdBindPipeline(r.vkCommandBuffer, vk.VK_PIPELINE_BIND_POINT_GRAPHICS, pipeline)
	vk.CmdBindVertexBuffers(r.vkCommandBuffer, 0, []vk.VkBuffer{vb}, []vk.VkDeviceSize{0})
	vk.CmdBindIndexBuffer(r.vkCommandBuffer, ib, 0, indexType)
	r.bindViewportAndScissor(dev)
	r.bindVertexStageConstants(dev, layout, useShader)
	vk.CmdDrawIndexed(r.vkCommandBuffer, indexCount, 1, startIndex, baseVertex, 0)
}

// DrawPrimitiveUP draws using vertex data from a Go byte slice (guest memory
// already copied), bypassing the stream source / vertex buffer mechanism.
func (r *Renderer) DrawPrimitiveUP(dev *Device, primType uint32, primCount uint32, vertexData []byte, stride uint32) {
	if r == nil {
		return
	}
	r.lifecycle.Lock()
	defer r.lifecycle.Unlock()
	if r.closed || dev == nil || !r.inScene || len(vertexData) == 0 || primCount == 0 {
		return
	}
	vertexCount := primitiveVertexCount(primType, primCount)
	if vertexCount == 0 {
		return
	}
	vb, _, ok := r.uploadBytes(vertexData, vk.VK_BUFFER_USAGE_VERTEX_BUFFER_BIT)
	if !ok {
		return
	}
	topology := d3dPrimToVkTopology(primType)
	vertModule, layout, useShader := r.resolveVertexStage(dev)
	pipeline := r.getOrCreatePipeline(dev, topology, vertModule, layout)
	if pipeline == 0 {
		return
	}
	vk.CmdBindPipeline(r.vkCommandBuffer, vk.VK_PIPELINE_BIND_POINT_GRAPHICS, pipeline)
	vk.CmdBindVertexBuffers(r.vkCommandBuffer, 0, []vk.VkBuffer{vb}, []vk.VkDeviceSize{0})
	r.bindViewportAndScissor(dev)
	r.bindVertexStageConstants(dev, layout, useShader)
	vk.CmdDraw(r.vkCommandBuffer, vertexCount, 1, 0, 0)
}

func (r *Renderer) Present(windows ...*wl.Window) []byte {
	if r == nil {
		return nil
	}
	r.lifecycle.Lock()
	defer r.lifecycle.Unlock()
	if r.closed {
		return nil
	}
	if r.inScene {
		r.endScene()
	}
	if !r.commandReady && !r.recordClearFrame() {
		return nil
	}
	if vk.ResetFence(r.vkDevice, r.frameFence) != vk.VK_SUCCESS {
		return nil
	}
	if vk.QueueSubmit(r.vkQueue, r.vkCommandBuffer, r.frameFence) != vk.VK_SUCCESS {
		return nil
	}
	if vk.WaitForFence(r.vkDevice, r.frameFence, ^uint64(0)) != vk.VK_SUCCESS {
		return nil
	}
	r.releasePendingBuffers()
	r.commandReady = false
	var window *wl.Window
	for _, candidate := range windows {
		if candidate != nil {
			window = candidate
			break
		}
	}
	if window != nil && r.tryDmabufPresent(window) {
		_ = vk.ResetCommandBuffer(r.vkCommandBuffer, 0)
		return nil
	}
	pixels := r.readbackPresent()
	if window != nil && len(pixels) != 0 {
		copyReadbackToWindow(pixels, r.renderTarget.Width, r.renderTarget.Height, window)
		window.Commit()
	}
	return pixels
}

func (r *Renderer) recordClearFrame() bool {
	if vk.ResetCommandBuffer(r.vkCommandBuffer, 0) != vk.VK_SUCCESS || vk.BeginCommandBuffer(r.vkCommandBuffer) != vk.VK_SUCCESS {
		return false
	}
	area := vk.VkRect2D{Extent: vk.VkExtent2D{Width: r.renderTarget.Width, Height: r.renderTarget.Height}}
	vk.CmdBeginRenderPass(r.vkCommandBuffer, r.vkRenderPass, r.currentFramebuffer, area, r.clearValues[:])
	vk.CmdEndRenderPass(r.vkCommandBuffer)
	if vk.EndCommandBuffer(r.vkCommandBuffer) != vk.VK_SUCCESS {
		return false
	}
	r.commandReady = true
	return true
}

func (r *Renderer) tryDmabufPresent(window *wl.Window) bool {
	if r == nil || r.renderTarget == nil || window == nil {
		return false
	}
	if !vk.SupportsDmabufExport(r.vkDevice) || !window.HasDmabufSupport() {
		return false
	}
	// Require the linear export image - without it we would export optimal-tiled
	// GPU memory as linear (modifier=0), producing corrupted stripes.
	if r.linearExport == 0 {
		return false
	}
	if !window.SupportsDmabufFormat(wl.DrmFormatARGB8888, 0) {
		return false
	}

	// Copy the rendered frame from the optimal-tiled render target into the
	// linear export image so the compositor can read it correctly.
	if !r.blitToLinear() {
		return false
	}

	stride := r.linearExportStride
	w := r.renderTarget.Width
	h := r.renderTarget.Height
	if !window.DmabufReady(w, h, stride, wl.DrmFormatARGB8888, 0) {
		fd, err := vk.ExportImageDmabufFd(r.vkDevice, r.linearExportMemory)
		if err != nil {
			return false
		}
		if err := window.CreateDmabufBuffer(fd, w, h, stride, wl.DrmFormatARGB8888, 0); err != nil {
			return false
		}
	}
	window.CommitDmabuf()
	return true
}

// blitToLinear copies the current render target into the linear export image
// using a one-shot command buffer submission.
func (r *Renderer) blitToLinear() bool {
	cb, res := vk.AllocateCommandBuffer(r.vkDevice, r.vkCommandPool)
	if res != vk.VK_SUCCESS {
		return false
	}
	commandBufferSafe := true
	defer func() {
		if commandBufferSafe {
			vk.FreeCommandBuffer(r.vkDevice, r.vkCommandPool, cb)
		}
	}()
	if vk.BeginCommandBuffer(cb) != vk.VK_SUCCESS {
		return false
	}

	w, h := r.renderTarget.Width, r.renderTarget.Height
	colorSub := vk.VkImageSubresourceLayers{
		AspectMask: vk.VK_IMAGE_ASPECT_COLOR_BIT, MipLevel: 0,
		BaseArrayLayer: 0, LayerCount: 1,
	}

	// Transition render target: COLOR_ATTACHMENT_OPTIMAL → TRANSFER_SRC_OPTIMAL
	vk.CmdPipelineBarrier(cb,
		vk.VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT,
		vk.VK_PIPELINE_STAGE_TRANSFER_BIT,
		[]vk.VkImageMemoryBarrier{{
			SType:               vk.VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER,
			SrcAccessMask:       vk.VkAccessFlags(vk.VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT),
			DstAccessMask:       vk.VkAccessFlags(vk.VK_ACCESS_TRANSFER_READ_BIT),
			OldLayout:           vk.VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL,
			NewLayout:           vk.VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL,
			SrcQueueFamilyIndex: vk.VK_QUEUE_FAMILY_IGNORED,
			DstQueueFamilyIndex: vk.VK_QUEUE_FAMILY_IGNORED,
			Image:               r.renderTarget.Image,
			SubresourceRange: vk.VkImageSubresourceRange{
				AspectMask: vk.VK_IMAGE_ASPECT_COLOR_BIT,
				LevelCount: 1, LayerCount: 1,
			},
		}})

	// Transition linear export image: UNDEFINED / GENERAL → TRANSFER_DST_OPTIMAL
	vk.CmdPipelineBarrier(cb,
		vk.VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT,
		vk.VK_PIPELINE_STAGE_TRANSFER_BIT,
		[]vk.VkImageMemoryBarrier{{
			SType:               vk.VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER,
			SrcAccessMask:       0,
			DstAccessMask:       vk.VkAccessFlags(vk.VK_ACCESS_TRANSFER_WRITE_BIT),
			OldLayout:           vk.VK_IMAGE_LAYOUT_UNDEFINED,
			NewLayout:           vk.VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,
			SrcQueueFamilyIndex: vk.VK_QUEUE_FAMILY_IGNORED,
			DstQueueFamilyIndex: vk.VK_QUEUE_FAMILY_IGNORED,
			Image:               r.linearExport,
			SubresourceRange: vk.VkImageSubresourceRange{
				AspectMask: vk.VK_IMAGE_ASPECT_COLOR_BIT,
				LevelCount: 1, LayerCount: 1,
			},
		}})

	vk.CmdCopyImage(cb,
		r.renderTarget.Image, vk.VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL,
		r.linearExport, vk.VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,
		vk.VkImageCopy{
			SrcSubresource: colorSub,
			DstSubresource: colorSub,
			Extent:         vk.VkExtent3D{Width: w, Height: h, Depth: 1},
		})

	// Transition linear image to GENERAL so the compositor can read it.
	vk.CmdPipelineBarrier(cb,
		vk.VK_PIPELINE_STAGE_TRANSFER_BIT,
		vk.VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT,
		[]vk.VkImageMemoryBarrier{{
			SType:               vk.VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER,
			SrcAccessMask:       vk.VkAccessFlags(vk.VK_ACCESS_TRANSFER_WRITE_BIT),
			DstAccessMask:       0,
			OldLayout:           vk.VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,
			NewLayout:           vk.VK_IMAGE_LAYOUT_GENERAL,
			SrcQueueFamilyIndex: vk.VK_QUEUE_FAMILY_IGNORED,
			DstQueueFamilyIndex: vk.VK_QUEUE_FAMILY_IGNORED,
			Image:               r.linearExport,
			SubresourceRange: vk.VkImageSubresourceRange{
				AspectMask: vk.VK_IMAGE_ASPECT_COLOR_BIT,
				LevelCount: 1, LayerCount: 1,
			},
		}})

	// Restore render target to COLOR_ATTACHMENT_OPTIMAL for next frame.
	vk.CmdPipelineBarrier(cb,
		vk.VK_PIPELINE_STAGE_TRANSFER_BIT,
		vk.VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT,
		[]vk.VkImageMemoryBarrier{{
			SType:               vk.VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER,
			SrcAccessMask:       vk.VkAccessFlags(vk.VK_ACCESS_TRANSFER_READ_BIT),
			DstAccessMask:       vk.VkAccessFlags(vk.VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT),
			OldLayout:           vk.VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL,
			NewLayout:           vk.VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL,
			SrcQueueFamilyIndex: vk.VK_QUEUE_FAMILY_IGNORED,
			DstQueueFamilyIndex: vk.VK_QUEUE_FAMILY_IGNORED,
			Image:               r.renderTarget.Image,
			SubresourceRange: vk.VkImageSubresourceRange{
				AspectMask: vk.VK_IMAGE_ASPECT_COLOR_BIT,
				LevelCount: 1, LayerCount: 1,
			},
		}})

	if vk.EndCommandBuffer(cb) != vk.VK_SUCCESS {
		return false
	}
	fence, res := vk.CreateFence(r.vkDevice, false)
	if res != vk.VK_SUCCESS {
		return false
	}
	fenceSafe := true
	defer func() {
		if fenceSafe {
			vk.DestroyFence(r.vkDevice, fence)
		}
	}()
	if vk.QueueSubmit(r.vkQueue, cb, fence) != vk.VK_SUCCESS {
		return false
	}
	if vk.WaitForFence(r.vkDevice, fence, ^uint64(0)) != vk.VK_SUCCESS {
		// Do not release submitted resources unless the queue is known idle.
		// A device failure may leave them live until process teardown.
		commandBufferSafe = vk.DeviceWaitIdle(r.vkDevice) == vk.VK_SUCCESS
		fenceSafe = commandBufferSafe
		return false
	}
	return true
}

func (r *Renderer) readbackPresent() []byte {
	if r == nil || r.renderTarget == nil {
		return nil
	}
	size := vk.VkDeviceSize(r.renderTarget.Width) * vk.VkDeviceSize(r.renderTarget.Height) * 4
	readbackBuffer, readbackMemory, res := vk.CreateBuffer(r.vkDevice, size, vk.VK_BUFFER_USAGE_TRANSFER_DST_BIT, vk.VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT|vk.VK_MEMORY_PROPERTY_HOST_COHERENT_BIT)
	if res != vk.VK_SUCCESS {
		return nil
	}
	defer func() {
		vk.DestroyBuffer(r.vkDevice, readbackBuffer)
		vk.FreeMemory(r.vkDevice, readbackMemory)
	}()
	if vk.ResetCommandBuffer(r.vkCommandBuffer, 0) != vk.VK_SUCCESS || vk.BeginCommandBuffer(r.vkCommandBuffer) != vk.VK_SUCCESS {
		return nil
	}
	barrier := vk.VkImageMemoryBarrier{SType: vk.VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER, SrcAccessMask: vk.VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT, DstAccessMask: vk.VK_ACCESS_TRANSFER_READ_BIT, OldLayout: vk.VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL, NewLayout: vk.VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL, SrcQueueFamilyIndex: vk.VK_QUEUE_FAMILY_IGNORED, DstQueueFamilyIndex: vk.VK_QUEUE_FAMILY_IGNORED, Image: r.renderTarget.Image, SubresourceRange: vk.VkImageSubresourceRange{AspectMask: vk.VK_IMAGE_ASPECT_COLOR_BIT, LevelCount: 1, LayerCount: 1}}
	vk.CmdPipelineBarrier(r.vkCommandBuffer, vk.VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT, vk.VK_PIPELINE_STAGE_TRANSFER_BIT, []vk.VkImageMemoryBarrier{barrier})
	vk.CmdCopyImageToBuffer(r.vkCommandBuffer, r.renderTarget.Image, vk.VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL, readbackBuffer, []vk.VkBufferImageCopy{{ImageSubresource: vk.VkImageSubresourceLayers{AspectMask: vk.VK_IMAGE_ASPECT_COLOR_BIT, LayerCount: 1}, ImageExtent: vk.VkExtent3D{Width: r.renderTarget.Width, Height: r.renderTarget.Height, Depth: 1}}})
	barrier.SrcAccessMask = vk.VK_ACCESS_TRANSFER_READ_BIT
	barrier.DstAccessMask = vk.VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT
	barrier.OldLayout = vk.VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL
	barrier.NewLayout = vk.VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL
	vk.CmdPipelineBarrier(r.vkCommandBuffer, vk.VK_PIPELINE_STAGE_TRANSFER_BIT, vk.VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT, []vk.VkImageMemoryBarrier{barrier})
	if vk.EndCommandBuffer(r.vkCommandBuffer) != vk.VK_SUCCESS {
		return nil
	}
	if vk.ResetFence(r.vkDevice, r.frameFence) != vk.VK_SUCCESS || vk.QueueSubmit(r.vkQueue, r.vkCommandBuffer, r.frameFence) != vk.VK_SUCCESS || vk.WaitForFence(r.vkDevice, r.frameFence, ^uint64(0)) != vk.VK_SUCCESS {
		return nil
	}
	ptr, res := vk.MapMemory(r.vkDevice, readbackMemory, 0, size)
	if res != vk.VK_SUCCESS || ptr == nil {
		return nil
	}
	defer vk.UnmapMemory(r.vkDevice, readbackMemory)
	pixels := make([]byte, int(size))
	copy(pixels, unsafe.Slice((*byte)(ptr), int(size)))
	_ = vk.ResetCommandBuffer(r.vkCommandBuffer, 0)
	return pixels
}

func copyReadbackToWindow(pixels []byte, width, height uint32, window *wl.Window) {
	if window == nil || len(window.Pix) == 0 || len(pixels) == 0 {
		return
	}
	copyWidth := minU32(width, uint32(window.Width))
	copyHeight := minU32(height, uint32(window.Height))
	srcStride := int(width) * 4
	dstStride := int(window.Stride)
	if dstStride <= 0 {
		dstStride = int(copyWidth) * 4
	}
	rowBytes := int(copyWidth) * 4
	// SHM format is XRGB8888: the 4th byte (X) is ignored by the compositor,
	// so a bulk copy per row is safe and avoids the per-pixel alpha-force loop.
	for y := uint32(0); y < copyHeight; y++ {
		copy(window.Pix[int(y)*dstStride:], pixels[int(y)*srcStride:int(y)*srcStride+rowBytes])
	}
}

func minU32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

func (r *Renderer) getOrCreatePipeline(dev *Device, topology vk.VkPrimitiveTopology, vertModule vk.VkShaderModule, layout vk.VkPipelineLayout) vk.VkPipeline {
	hash := hashPipelineState(dev, topology, vertModule)
	if pipeline, ok := r.pipelineCache[hash]; ok {
		return pipeline
	}
	bindings, attrs := r.vertexInputDescriptions(dev)
	pipeline, res := vk.CreateGraphicsPipelineWithOptions(r.vkDevice, r.vkRenderPass, layout, vertModule, r.fragmentShaderModule, vk.GraphicsPipelineOptions{
		Topology:            topology,
		VertexBindings:      bindings,
		VertexAttributes:    attrs,
		PolygonMode:         d3dFillToVkPolygonMode(dev.GetRenderState(D3DRS_FILLMODE)),
		CullMode:            d3dCullToVkCullMode(dev.GetRenderState(D3DRS_CULLMODE)),
		FrontFace:           vk.VK_FRONT_FACE_COUNTER_CLOCKWISE,
		BlendEnable:         dev.GetRenderState(D3DRS_ALPHABLENDENABLE) != 0,
		SrcColorBlendFactor: d3dBlendToVkFactor(dev.GetRenderState(D3DRS_SRCBLEND)),
		DstColorBlendFactor: d3dBlendToVkFactor(dev.GetRenderState(D3DRS_DESTBLEND)),
		ColorBlendOp:        d3dBlendOpToVk(dev.GetRenderState(D3DRS_BLENDOP)),
		SrcAlphaBlendFactor: d3dBlendToVkFactor(dev.GetRenderState(D3DRS_SRCBLENDALPHA)),
		DstAlphaBlendFactor: d3dBlendToVkFactor(dev.GetRenderState(D3DRS_DESTBLENDALPHA)),
		AlphaBlendOp:        d3dBlendOpToVk(dev.GetRenderState(D3DRS_BLENDOPALPHA)),
		DepthTestEnable:     dev.GetRenderState(D3DRS_ZENABLE) != D3DZB_FALSE,
		DepthWriteEnable:    dev.GetRenderState(D3DRS_ZWRITEENABLE) != 0,
		DepthCompareOp:      d3dCmpToVkCompare(dev.GetRenderState(D3DRS_ZFUNC)),
	})
	if res != vk.VK_SUCCESS {
		return 0
	}
	r.pipelineCache[hash] = pipeline
	return pipeline
}

func d3dPrimToVkTopology(d3dPrim uint32) vk.VkPrimitiveTopology {
	switch d3dPrim {
	case D3DPT_POINTLIST:
		return vk.VK_PRIMITIVE_TOPOLOGY_POINT_LIST
	case D3DPT_LINELIST:
		return vk.VK_PRIMITIVE_TOPOLOGY_LINE_LIST
	case D3DPT_LINESTRIP:
		return vk.VK_PRIMITIVE_TOPOLOGY_LINE_STRIP
	case D3DPT_TRIANGLESTRIP:
		return vk.VK_PRIMITIVE_TOPOLOGY_TRIANGLE_STRIP
	case D3DPT_TRIANGLEFAN:
		return vk.VK_PRIMITIVE_TOPOLOGY_TRIANGLE_FAN
	default:
		return vk.VK_PRIMITIVE_TOPOLOGY_TRIANGLE_LIST
	}
}

func (r *Renderer) uploadVertexStream(source StreamSource) (vk.VkBuffer, vk.VkDeviceMemory, bool) {
	source.Buffer.BeginRead()
	defer source.Buffer.EndRead()
	data := source.Buffer.Data[:min(uint32(len(source.Buffer.Data)), source.Buffer.Size)]
	if source.Offset < uint32(len(data)) {
		data = data[source.Offset:]
	}
	return r.uploadBytes(data, vk.VK_BUFFER_USAGE_VERTEX_BUFFER_BIT)
}

func (r *Renderer) uploadIndexBuffer(ib *IndexBuffer) (vk.VkBuffer, vk.VkIndexType, bool) {
	ib.BeginRead()
	defer ib.EndRead()
	data := ib.Data[:min(uint32(len(ib.Data)), ib.Size)]
	buffer, _, ok := r.uploadBytes(data, vk.VK_BUFFER_USAGE_INDEX_BUFFER_BIT)
	if !ok {
		return 0, vk.VK_INDEX_TYPE_UINT16, false
	}
	if ib.Format == D3DFMT_INDEX32 {
		return buffer, vk.VK_INDEX_TYPE_UINT32, true
	}
	return buffer, vk.VK_INDEX_TYPE_UINT16, true
}

func (r *Renderer) uploadBytes(data []byte, usage vk.VkBufferUsageFlags) (vk.VkBuffer, vk.VkDeviceMemory, bool) {
	if len(data) == 0 {
		return 0, 0, false
	}
	buffer, memory, res := vk.CreateBuffer(r.vkDevice, vk.VkDeviceSize(len(data)), usage, vk.VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT|vk.VK_MEMORY_PROPERTY_HOST_COHERENT_BIT)
	if res != vk.VK_SUCCESS {
		return 0, 0, false
	}
	ptr, res := vk.MapMemory(r.vkDevice, memory, 0, vk.VkDeviceSize(len(data)))
	if res != vk.VK_SUCCESS || ptr == nil {
		vk.DestroyBuffer(r.vkDevice, buffer)
		vk.FreeMemory(r.vkDevice, memory)
		return 0, 0, false
	}
	copy(unsafe.Slice((*byte)(ptr), len(data)), data)
	vk.UnmapMemory(r.vkDevice, memory)
	r.pendingBuffers = append(r.pendingBuffers, transientBuffer{buffer: buffer, memory: memory})
	return buffer, memory, true
}

func (r *Renderer) releasePendingBuffers() {
	for _, resource := range r.pendingBuffers {
		vk.DestroyBuffer(r.vkDevice, resource.buffer)
		vk.FreeMemory(r.vkDevice, resource.memory)
	}
	r.pendingBuffers = r.pendingBuffers[:0]
}

func (r *Renderer) bindViewportAndScissor(dev *Device) {
	vp := dev.Viewport
	if vp.Width == 0 || vp.Height == 0 {
		vp.Width, vp.Height, vp.MinZ, vp.MaxZ = r.renderTarget.Width, r.renderTarget.Height, 0, 1
	}
	viewport := vk.VkViewport{X: float32(vp.X), Y: float32(vp.Y), Width: float32(vp.Width), Height: float32(vp.Height), MinDepth: vp.MinZ, MaxDepth: vp.MaxZ}
	scissor := vk.VkRect2D{Offset: vk.VkOffset2D{X: int32(vp.X), Y: int32(vp.Y)}, Extent: vk.VkExtent2D{Width: vp.Width, Height: vp.Height}}
	if dev.GetRenderState(D3DRS_SCISSORTESTENABLE) != 0 {
		rect := dev.ScissorRect
		if rect.Right > rect.Left && rect.Bottom > rect.Top {
			scissor = vk.VkRect2D{Offset: vk.VkOffset2D{X: rect.Left, Y: rect.Top}, Extent: vk.VkExtent2D{Width: uint32(rect.Right - rect.Left), Height: uint32(rect.Bottom - rect.Top)}}
		}
	}
	vk.CmdSetViewport(r.vkCommandBuffer, 0, []vk.VkViewport{viewport})
	vk.CmdSetScissor(r.vkCommandBuffer, 0, []vk.VkRect2D{scissor})
}

func (r *Renderer) pushConstants(dev *Device) {
	world := matrixFromDevice(dev, D3DTS_WORLD)
	view := matrixFromDevice(dev, D3DTS_VIEW)
	proj := matrixFromDevice(dev, D3DTS_PROJECTION)
	push := ffpPushConstants{WVP: mulMat4(mulMat4(world, view), proj), World: world, Ambient: colorUint32ToVec4(dev.GetRenderState(D3DRS_AMBIENT))}
	if dev.FVF&D3DFVF_XYZRHW != 0 {
		push.WVP = pretransformedWVP(dev, r.renderTarget.Width, r.renderTarget.Height)
	}
	lightIndex := 0
	for idx, enabled := range dev.LightEnabled {
		if !enabled {
			continue
		}
		light, ok := dev.Lights[idx]
		if !ok {
			continue
		}
		push.LightDir[lightIndex] = [4]float32{light.Direction.X, light.Direction.Y, light.Direction.Z, 0}
		push.LightColor[lightIndex] = [4]float32{light.Diffuse.R, light.Diffuse.G, light.Diffuse.B, light.Diffuse.A}
		lightIndex++
		if lightIndex == len(push.LightDir) {
			break
		}
	}
	vk.CmdPushConstants(r.vkCommandBuffer, r.pipelineLayout, vk.VkShaderStageFlags(vk.VK_SHADER_STAGE_VERTEX_BIT), 0, uint32(unsafe.Sizeof(push)), unsafe.Pointer(&push))
}

// resolveVertexStage decides whether the current draw uses a translated
// programmable vertex shader or the fixed-function vertex module. When a shader
// is bound (dev.CurrentVertexShader has translated SPIR-V) it lazily creates the
// shader-path descriptor resources and the vk shader module, returning the
// shader module + descriptor-backed pipeline layout and useShader=true. If any
// of that setup fails, or no shader is bound, it falls back to the FFP module +
// push-constant layout with useShader=false so drawing still proceeds.
func (r *Renderer) resolveVertexStage(dev *Device) (vk.VkShaderModule, vk.VkPipelineLayout, bool) {
	prog := dev.CurrentVertexShader
	if prog == nil || len(prog.SPIRV) == 0 {
		return r.vertexShaderModule, r.pipelineLayout, false
	}
	if !r.ensureShaderResources() {
		return r.vertexShaderModule, r.pipelineLayout, false
	}
	module := r.ensureVertexShaderModule(prog)
	if module == 0 {
		return r.vertexShaderModule, r.pipelineLayout, false
	}
	return module, r.shaderPipelineLayout, true
}

// bindVertexStageConstants feeds the vertex stage its constants. For the shader
// path it copies dev.VSConstants into the shared uniform buffer and binds the
// descriptor set; for the FFP path it pushes the fixed-function constants.
func (r *Renderer) bindVertexStageConstants(dev *Device, layout vk.VkPipelineLayout, useShader bool) {
	if !useShader {
		r.pushConstants(dev)
		return
	}
	ptr, res := vk.MapMemory(r.vkDevice, r.shaderUniformMemory, 0, vsConstantBufferSize)
	if res == vk.VK_SUCCESS && ptr != nil {
		copy(unsafe.Slice((*byte)(ptr), vsConstantBufferSize), unsafe.Slice((*byte)(unsafe.Pointer(&dev.VSConstants[0][0])), vsConstantBufferSize))
		vk.UnmapMemory(r.vkDevice, r.shaderUniformMemory)
	}
	vk.CmdBindDescriptorSets(r.vkCommandBuffer, vk.VK_PIPELINE_BIND_POINT_GRAPHICS, layout, 0, r.shaderDescSet)
}

// ensureShaderResources lazily creates the descriptor set layout, descriptor
// pool, descriptor set, host-visible uniform buffer and the descriptor-backed
// pipeline layout used by the programmable vertex-shader path. Created once and
// reused for every subsequent shader draw.
func (r *Renderer) ensureShaderResources() bool {
	if r.shaderResourcesReady {
		return true
	}
	device := r.vkDevice
	layout, res := vk.CreateDescriptorSetLayout(device)
	if res != vk.VK_SUCCESS {
		return false
	}
	pool, res := vk.CreateDescriptorPool(device, 1)
	if res != vk.VK_SUCCESS {
		vk.DestroyDescriptorSetLayout(device, layout)
		return false
	}
	set, res := vk.AllocateDescriptorSet(device, pool, layout)
	if res != vk.VK_SUCCESS {
		vk.DestroyDescriptorPool(device, pool)
		vk.DestroyDescriptorSetLayout(device, layout)
		return false
	}
	buffer, memory, res := vk.CreateBuffer(device, vsConstantBufferSize, vk.VK_BUFFER_USAGE_UNIFORM_BUFFER_BIT, vk.VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT|vk.VK_MEMORY_PROPERTY_HOST_COHERENT_BIT)
	if res != vk.VK_SUCCESS {
		vk.DestroyDescriptorPool(device, pool)
		vk.DestroyDescriptorSetLayout(device, layout)
		return false
	}
	pipelineLayout, res := vk.CreatePipelineLayout(device, []vk.VkDescriptorSetLayout{layout}, nil)
	if res != vk.VK_SUCCESS {
		vk.DestroyBuffer(device, buffer)
		vk.FreeMemory(device, memory)
		vk.DestroyDescriptorPool(device, pool)
		vk.DestroyDescriptorSetLayout(device, layout)
		return false
	}
	vk.UpdateDescriptorSetUniformBuffer(device, set, buffer, 0, vsConstantBufferSize)
	r.shaderDescLayout = layout
	r.shaderDescPool = pool
	r.shaderDescSet = set
	r.shaderUniformBuffer = buffer
	r.shaderUniformMemory = memory
	r.shaderPipelineLayout = pipelineLayout
	r.shaderResourcesReady = true
	return true
}

// ensureVertexShaderModule lazily creates and caches the vk shader module for a
// translated vertex ShaderProgram, storing the handle in prog.VkModule.
func (r *Renderer) ensureVertexShaderModule(prog *ShaderProgram) vk.VkShaderModule {
	if prog.VkModule != 0 {
		return vk.VkShaderModule(prog.VkModule)
	}
	if len(prog.SPIRV) == 0 {
		return 0
	}
	module, res := vk.CreateShaderModule(r.vkDevice, prog.SPIRV)
	if res != vk.VK_SUCCESS || module == 0 {
		return 0
	}
	prog.VkModule = uint64(module)
	r.shaderModules = append(r.shaderModules, module)
	return module
}

func (r *Renderer) vertexInputDescriptions(dev *Device) ([]vk.VkVertexInputBindingDescription, []vk.VkVertexInputAttributeDescription) {
	if dev.CurrentVertexDecl != nil && len(dev.CurrentVertexDecl.Elements) != 0 {
		bindings, attrs := vertexDeclToDescriptions(dev.CurrentVertexDecl.Elements)
		if len(bindings) != 0 {
			if dev.StreamSources[0].Stride != 0 {
				bindings[0].Stride = dev.StreamSources[0].Stride
			}
			return bindings, attrs
		}
	}
	bindings, attrs := FVFToVertexBindings(dev.FVF)
	if len(bindings) != 0 && dev.StreamSources[0].Stride != 0 {
		bindings[0].Stride = dev.StreamSources[0].Stride
	}
	return bindings, attrs
}

func vertexDeclToDescriptions(elements []VertexElement) ([]vk.VkVertexInputBindingDescription, []vk.VkVertexInputAttributeDescription) {
	var stride uint32
	attrs := make([]vk.VkVertexInputAttributeDescription, 0, len(elements))
	for _, elem := range elements {
		format := declTypeToVkFormat(elem.Type)
		location := declUsageToLocation(elem.Usage, elem.UsageIndex)
		if format == vk.VK_FORMAT_UNDEFINED || location < 0 || elem.Stream != 0 {
			continue
		}
		attrs = append(attrs, vk.VkVertexInputAttributeDescription{Location: uint32(location), Binding: 0, Format: format, Offset: uint32(elem.Offset)})
		if s := uint32(elem.Offset) + declTypeSize(elem.Type); s > stride {
			stride = s
		}
	}
	if len(attrs) == 0 {
		return nil, nil
	}
	return []vk.VkVertexInputBindingDescription{{Binding: 0, Stride: stride, InputRate: vk.VK_VERTEX_INPUT_RATE_VERTEX}}, attrs
}

func declUsageToLocation(usage, usageIndex uint8) int {
	switch usage {
	case D3DDECLUSAGE_POSITION, D3DDECLUSAGE_POSITIONT:
		return 0
	case D3DDECLUSAGE_NORMAL:
		return 1
	case D3DDECLUSAGE_COLOR:
		if usageIndex == 0 {
			return 2
		}
	case D3DDECLUSAGE_TEXCOORD:
		if usageIndex < 4 {
			return 3 + int(usageIndex)
		}
	}
	return -1
}

func hashPipelineState(dev *Device, topology vk.VkPrimitiveTopology, vertModule vk.VkShaderModule) uint64 {
	h := fnv.New64a()
	write := func(v uint64) {
		var b [8]byte
		for i := 0; i < 8; i++ {
			b[i] = byte(v >> (8 * i))
		}
		_, _ = h.Write(b[:])
	}
	write(uint64(topology))
	write(uint64(vertModule))
	write(uint64(dev.GetRenderState(D3DRS_ALPHABLENDENABLE)))
	write(uint64(dev.GetRenderState(D3DRS_CULLMODE)))
	write(uint64(dev.GetRenderState(D3DRS_ZENABLE)))
	write(uint64(dev.GetRenderState(D3DRS_FILLMODE)))
	write(uint64(dev.FVF))
	for _, elem := range dev.VertexDeclaration {
		write(uint64(elem.Stream) | uint64(elem.Offset)<<16 | uint64(elem.Type)<<32 | uint64(elem.Usage)<<40 | uint64(elem.UsageIndex)<<48)
	}
	return h.Sum64()
}

func primitiveVertexCount(primType, primCount uint32) uint32 {
	switch primType {
	case D3DPT_POINTLIST:
		return primCount
	case D3DPT_LINELIST:
		return primCount * 2
	case D3DPT_LINESTRIP:
		return primCount + 1
	case D3DPT_TRIANGLELIST:
		return primCount * 3
	case D3DPT_TRIANGLESTRIP, D3DPT_TRIANGLEFAN:
		return primCount + 2
	default:
		return 0
	}
}

func primitiveIndexCount(primType, primCount uint32) uint32 {
	return primitiveVertexCount(primType, primCount)
}

func d3dBlendToVkFactor(blend uint32) vk.VkBlendFactor {
	switch blend {
	case D3DBLEND_ZERO:
		return vk.VK_BLEND_FACTOR_ZERO
	case D3DBLEND_SRCCOLOR:
		return vk.VK_BLEND_FACTOR_SRC_COLOR
	case D3DBLEND_INVSRCCOLOR:
		return vk.VK_BLEND_FACTOR_ONE_MINUS_SRC_COLOR
	case D3DBLEND_SRCALPHA, D3DBLEND_BOTHSRCALPHA:
		return vk.VK_BLEND_FACTOR_SRC_ALPHA
	case D3DBLEND_INVSRCALPHA, D3DBLEND_BOTHINVSRCALPHA:
		return vk.VK_BLEND_FACTOR_ONE_MINUS_SRC_ALPHA
	case D3DBLEND_DESTALPHA:
		return vk.VK_BLEND_FACTOR_DST_ALPHA
	case D3DBLEND_INVDESTALPHA:
		return vk.VK_BLEND_FACTOR_ONE_MINUS_DST_ALPHA
	case D3DBLEND_DESTCOLOR:
		return vk.VK_BLEND_FACTOR_DST_COLOR
	case D3DBLEND_INVDESTCOLOR:
		return vk.VK_BLEND_FACTOR_ONE_MINUS_DST_COLOR
	case D3DBLEND_SRCALPHASAT:
		return vk.VK_BLEND_FACTOR_SRC_ALPHA_SATURATE
	default:
		return vk.VK_BLEND_FACTOR_ONE
	}
}

func d3dBlendOpToVk(op uint32) vk.VkBlendOp {
	switch op {
	case D3DBLENDOP_SUBTRACT:
		return vk.VK_BLEND_OP_SUBTRACT
	case D3DBLENDOP_REVSUBTRACT:
		return vk.VK_BLEND_OP_REVERSE_SUBTRACT
	case D3DBLENDOP_MIN:
		return vk.VK_BLEND_OP_MIN
	case D3DBLENDOP_MAX:
		return vk.VK_BLEND_OP_MAX
	default:
		return vk.VK_BLEND_OP_ADD
	}
}

func d3dCmpToVkCompare(cmp uint32) vk.VkCompareOp {
	switch cmp {
	case D3DCMP_NEVER:
		return vk.VK_COMPARE_OP_NEVER
	case D3DCMP_LESS:
		return vk.VK_COMPARE_OP_LESS
	case D3DCMP_EQUAL:
		return vk.VK_COMPARE_OP_EQUAL
	case D3DCMP_GREATER:
		return vk.VK_COMPARE_OP_GREATER
	case D3DCMP_NOTEQUAL:
		return vk.VK_COMPARE_OP_NOT_EQUAL
	case D3DCMP_GREATEREQUAL:
		return vk.VK_COMPARE_OP_GREATER_OR_EQUAL
	case D3DCMP_ALWAYS:
		return vk.VK_COMPARE_OP_ALWAYS
	default:
		return vk.VK_COMPARE_OP_LESS_OR_EQUAL
	}
}

func d3dCullToVkCullMode(cull uint32) vk.VkCullModeFlags {
	switch cull {
	case D3DCULL_CW:
		return vk.VK_CULL_MODE_FRONT_BIT
	case D3DCULL_CCW:
		return vk.VK_CULL_MODE_BACK_BIT
	default:
		return vk.VK_CULL_MODE_NONE
	}
}

func d3dFillToVkPolygonMode(fill uint32) vk.VkPolygonMode {
	switch fill {
	case D3DFILL_POINT:
		return vk.VK_POLYGON_MODE_POINT
	case D3DFILL_WIREFRAME:
		return vk.VK_POLYGON_MODE_LINE
	default:
		return vk.VK_POLYGON_MODE_FILL
	}
}

func matrixFromDevice(dev *Device, typ uint32) [16]float32 {
	if m, ok := dev.Transforms[typ]; ok {
		return m
	}
	return [16]float32{1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1}
}

func mulMat4(a, b [16]float32) [16]float32 {
	var out [16]float32
	for row := 0; row < 4; row++ {
		for col := 0; col < 4; col++ {
			for k := 0; k < 4; k++ {
				out[row*4+col] += a[row*4+k] * b[k*4+col]
			}
		}
	}
	return out
}

func colorToClearValue(color uint32) vk.VkClearValue {
	return vk.VkClearValue{Uint32: [4]uint32{math.Float32bits(float32((color>>16)&0xff) / 255), math.Float32bits(float32((color>>8)&0xff) / 255), math.Float32bits(float32(color&0xff) / 255), math.Float32bits(float32((color>>24)&0xff) / 255)}}
}

func depthStencilClearValue(depth float32, stencil uint32) vk.VkClearValue {
	return vk.VkClearValue{Uint32: [4]uint32{math.Float32bits(depth), stencil, 0, 0}}
}

func colorUint32ToVec4(color uint32) [4]float32 {
	return [4]float32{float32((color>>16)&0xff) / 255, float32((color>>8)&0xff) / 255, float32(color&0xff) / 255, float32((color>>24)&0xff) / 255}
}

func pretransformedWVP(dev *Device, width, height uint32) [16]float32 {
	vp := dev.Viewport
	if vp.Width == 0 {
		vp.Width = width
	}
	if vp.Height == 0 {
		vp.Height = height
	}
	if vp.Width == 0 {
		vp.Width = 1
	}
	if vp.Height == 0 {
		vp.Height = 1
	}
	sx := 2.0 / float32(vp.Width)
	sy := 2.0 / float32(vp.Height)
	tx := -1.0 - float32(vp.X)*sx
	ty := -1.0 - float32(vp.Y)*sy
	return [16]float32{
		sx, 0, 0, 0,
		0, sy, 0, 0,
		0, 0, 1, 0,
		tx, ty, 0, 1,
	}
}

func vkResultError(op string, res vk.VkResult) error { return &vkError{op: op, res: res} }

type vkError struct {
	op  string
	res vk.VkResult
}

func (e *vkError) Error() string {
	return e.op + ": Vulkan error " + strconv.FormatInt(int64(e.res), 10)
}

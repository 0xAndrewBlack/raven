package vk

import "unsafe"

func CreateCommandPool(device VkDevice, queueFamily uint32) (VkCommandPool, VkResult) {
	ci := VkCommandPoolCreateInfo{
		SType:            VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO,
		Flags:            VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT,
		QueueFamilyIndex: queueFamily,
	}
	var pool VkCommandPool
	res := callResult(procs.vkCreateCommandPool, uintptr(device), uintptr(unsafe.Pointer(&ci)), 0, uintptr(unsafe.Pointer(&pool)))
	return pool, res
}

func AllocateCommandBuffer(device VkDevice, pool VkCommandPool) (VkCommandBuffer, VkResult) {
	ci := VkCommandBufferAllocateInfo{
		SType:              VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO,
		CommandPool:        pool,
		Level:              VK_COMMAND_BUFFER_LEVEL_PRIMARY,
		CommandBufferCount: 1,
	}
	var cb VkCommandBuffer
	res := callResult(procs.vkAllocateCommandBuffers, uintptr(device), uintptr(unsafe.Pointer(&ci)), uintptr(unsafe.Pointer(&cb)))
	return cb, res
}

func BeginCommandBuffer(cb VkCommandBuffer) VkResult {
	ci := VkCommandBufferBeginInfo{
		SType: VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO,
		Flags: VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT,
	}
	return callResult(procs.vkBeginCommandBuffer, uintptr(cb), uintptr(unsafe.Pointer(&ci)))
}

func EndCommandBuffer(cb VkCommandBuffer) VkResult {
	return callResult(procs.vkEndCommandBuffer, uintptr(cb))
}

func ResetCommandBuffer(cb VkCommandBuffer, flags VkCommandBufferResetFlags) VkResult {
	return callResult(procs.vkResetCommandBuffer, uintptr(cb), uintptr(flags))
}

func CmdBeginRenderPass(cb VkCommandBuffer, renderPass VkRenderPass, framebuffer VkFramebuffer, renderArea VkRect2D, clearValues []VkClearValue) {
	ci := VkRenderPassBeginInfo{
		SType:       VK_STRUCTURE_TYPE_RENDER_PASS_BEGIN_INFO,
		RenderPass:  renderPass,
		Framebuffer: framebuffer,
		RenderArea:  renderArea,
	}
	if len(clearValues) != 0 {
		ci.ClearValueCount = uint32(len(clearValues))
		ci.PClearValues = &clearValues[0]
	}
	callVoid(procs.vkCmdBeginRenderPass, uintptr(cb), uintptr(unsafe.Pointer(&ci)), uintptr(VK_SUBPASS_CONTENTS_INLINE))
}

func CmdEndRenderPass(cb VkCommandBuffer) {
	callVoid(procs.vkCmdEndRenderPass, uintptr(cb))
}

func CmdBindPipeline(cb VkCommandBuffer, bindPoint VkPipelineBindPoint, pipeline VkPipeline) {
	callVoid(procs.vkCmdBindPipeline, uintptr(cb), uintptr(bindPoint), uintptr(pipeline))
}

func CmdBindVertexBuffers(cb VkCommandBuffer, firstBinding uint32, buffers []VkBuffer, offsets []VkDeviceSize) {
	if len(buffers) == 0 || len(buffers) != len(offsets) {
		return
	}
	callVoid(procs.vkCmdBindVertexBuffers, uintptr(cb), uintptr(firstBinding), uintptr(len(buffers)), uintptr(unsafe.Pointer(&buffers[0])), uintptr(unsafe.Pointer(&offsets[0])))
}

func CmdBindIndexBuffer(cb VkCommandBuffer, buffer VkBuffer, offset VkDeviceSize, indexType VkIndexType) {
	callVoid(procs.vkCmdBindIndexBuffer, uintptr(cb), uintptr(buffer), uintptr(offset), uintptr(indexType))
}

func CmdDraw(cb VkCommandBuffer, vertexCount, instanceCount, firstVertex, firstInstance uint32) {
	callVoid(procs.vkCmdDraw, uintptr(cb), uintptr(vertexCount), uintptr(instanceCount), uintptr(firstVertex), uintptr(firstInstance))
}

func CmdDrawIndexed(cb VkCommandBuffer, indexCount, instanceCount, firstIndex uint32, vertexOffset int32, firstInstance uint32) {
	callVoid(procs.vkCmdDrawIndexed, uintptr(cb), uintptr(indexCount), uintptr(instanceCount), uintptr(firstIndex), uintptr(vertexOffset), uintptr(firstInstance))
}

func CmdSetViewport(cb VkCommandBuffer, firstViewport uint32, viewports []VkViewport) {
	if len(viewports) == 0 {
		return
	}
	callVoid(procs.vkCmdSetViewport, uintptr(cb), uintptr(firstViewport), uintptr(len(viewports)), uintptr(unsafe.Pointer(&viewports[0])))
}

func CmdSetScissor(cb VkCommandBuffer, firstScissor uint32, scissors []VkRect2D) {
	if len(scissors) == 0 {
		return
	}
	callVoid(procs.vkCmdSetScissor, uintptr(cb), uintptr(firstScissor), uintptr(len(scissors)), uintptr(unsafe.Pointer(&scissors[0])))
}

func CmdPushConstants(cb VkCommandBuffer, layout VkPipelineLayout, stageFlags VkShaderStageFlags, offset, size uint32, data unsafe.Pointer) {
	if size == 0 || data == nil {
		return
	}
	callVoid(procs.vkCmdPushConstants, uintptr(cb), uintptr(layout), uintptr(stageFlags), uintptr(offset), uintptr(size), uintptr(data))
}

func CmdPipelineBarrier(cb VkCommandBuffer, srcStageMask, dstStageMask VkPipelineStageFlags, imageBarriers []VkImageMemoryBarrier) {
	var imageBarrierPtr uintptr
	if len(imageBarriers) != 0 {
		imageBarrierPtr = uintptr(unsafe.Pointer(&imageBarriers[0]))
	}
	callVoid(procs.vkCmdPipelineBarrier, uintptr(cb), uintptr(srcStageMask), uintptr(dstStageMask), 0, 0, 0, 0, 0, uintptr(len(imageBarriers)), imageBarrierPtr)
}

func CmdCopyImageToBuffer(cb VkCommandBuffer, image VkImage, imageLayout VkImageLayout, buffer VkBuffer, regions []VkBufferImageCopy) {
	if len(regions) == 0 {
		return
	}
	callVoid(procs.vkCmdCopyImageToBuffer, uintptr(cb), uintptr(image), uintptr(imageLayout), uintptr(buffer), uintptr(len(regions)), uintptr(unsafe.Pointer(&regions[0])))
}

func QueueSubmit(queue VkQueue, cb VkCommandBuffer, fence VkFence) VkResult {
	ci := VkSubmitInfo{
		SType:              VK_STRUCTURE_TYPE_SUBMIT_INFO,
		CommandBufferCount: 1,
		PCommandBuffers:    &cb,
	}
	return callResult(procs.vkQueueSubmit, uintptr(queue), 1, uintptr(unsafe.Pointer(&ci)), uintptr(fence))
}

func QueueWaitIdle(queue VkQueue) VkResult {
	return callResult(procs.vkQueueWaitIdle, uintptr(queue))
}

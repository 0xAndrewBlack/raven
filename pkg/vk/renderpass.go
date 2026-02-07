//go:build guest_windows

package vk

import "unsafe"

func CreateRenderPass(device VkDevice, colorFormat, depthFormat VkFormat) (VkRenderPass, VkResult) {
	attachments := []VkAttachmentDescription{{
		Format:         colorFormat,
		Samples:        VK_SAMPLE_COUNT_1_BIT,
		LoadOp:         VK_ATTACHMENT_LOAD_OP_CLEAR,
		StoreOp:        VK_ATTACHMENT_STORE_OP_STORE,
		StencilLoadOp:  VK_ATTACHMENT_LOAD_OP_DONT_CARE,
		StencilStoreOp: VK_ATTACHMENT_STORE_OP_DONT_CARE,
		InitialLayout:  VK_IMAGE_LAYOUT_UNDEFINED,
		FinalLayout:    VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL,
	}}
	colorRef := VkAttachmentReference{Attachment: 0, Layout: VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL}
	var depthRef *VkAttachmentReference
	if depthFormat != VK_FORMAT_UNDEFINED {
		attachments = append(attachments, VkAttachmentDescription{
			Format:         depthFormat,
			Samples:        VK_SAMPLE_COUNT_1_BIT,
			LoadOp:         VK_ATTACHMENT_LOAD_OP_CLEAR,
			StoreOp:        VK_ATTACHMENT_STORE_OP_DONT_CARE,
			StencilLoadOp:  VK_ATTACHMENT_LOAD_OP_DONT_CARE,
			StencilStoreOp: VK_ATTACHMENT_STORE_OP_DONT_CARE,
			InitialLayout:  VK_IMAGE_LAYOUT_UNDEFINED,
			FinalLayout:    VK_IMAGE_LAYOUT_DEPTH_STENCIL_ATTACHMENT_OPTIMAL,
		})
		ref := VkAttachmentReference{Attachment: 1, Layout: VK_IMAGE_LAYOUT_DEPTH_STENCIL_ATTACHMENT_OPTIMAL}
		depthRef = &ref
	}

	subpass := VkSubpassDescription{
		PipelineBindPoint:       VK_PIPELINE_BIND_POINT_GRAPHICS,
		ColorAttachmentCount:    1,
		PColorAttachments:       &colorRef,
		PDepthStencilAttachment: depthRef,
	}
	dep := VkSubpassDependency{
		SrcSubpass:    VK_SUBPASS_EXTERNAL,
		DstSubpass:    0,
		SrcStageMask:  VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT,
		DstStageMask:  VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT,
		DstAccessMask: VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT,
	}
	if depthFormat != VK_FORMAT_UNDEFINED {
		dep.SrcStageMask |= VK_PIPELINE_STAGE_EARLY_FRAGMENT_TESTS_BIT | VK_PIPELINE_STAGE_LATE_FRAGMENT_TESTS_BIT
		dep.DstStageMask |= VK_PIPELINE_STAGE_EARLY_FRAGMENT_TESTS_BIT | VK_PIPELINE_STAGE_LATE_FRAGMENT_TESTS_BIT
		dep.DstAccessMask |= VK_ACCESS_DEPTH_STENCIL_ATTACHMENT_WRITE_BIT
	}

	ci := VkRenderPassCreateInfo{
		SType:           VK_STRUCTURE_TYPE_RENDER_PASS_CREATE_INFO,
		AttachmentCount: uint32(len(attachments)),
		PAttachments:    &attachments[0],
		SubpassCount:    1,
		PSubpasses:      &subpass,
		DependencyCount: 1,
		PDependencies:   &dep,
	}
	var renderPass VkRenderPass
	res := callResult(procs.vkCreateRenderPass, uintptr(device), uintptr(unsafe.Pointer(&ci)), 0, uintptr(unsafe.Pointer(&renderPass)))
	return renderPass, res
}

func CreateFramebuffer(device VkDevice, renderPass VkRenderPass, imageView, depthView VkImageView, width, height uint32) (VkFramebuffer, VkResult) {
	attachments := []VkImageView{imageView}
	if depthView != 0 {
		attachments = append(attachments, depthView)
	}
	ci := VkFramebufferCreateInfo{
		SType:           VK_STRUCTURE_TYPE_FRAMEBUFFER_CREATE_INFO,
		RenderPass:      renderPass,
		AttachmentCount: uint32(len(attachments)),
		PAttachments:    &attachments[0],
		Width:           width,
		Height:          height,
		Layers:          1,
	}
	var framebuffer VkFramebuffer
	res := callResult(procs.vkCreateFramebuffer, uintptr(device), uintptr(unsafe.Pointer(&ci)), 0, uintptr(unsafe.Pointer(&framebuffer)))
	return framebuffer, res
}

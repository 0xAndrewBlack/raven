//go:build guest_windows

package vk

import "unsafe"

func CreateBuffer(device VkDevice, size VkDeviceSize, usage VkBufferUsageFlags, memProps VkMemoryPropertyFlags) (VkBuffer, VkDeviceMemory, VkResult) {
	ci := VkBufferCreateInfo{
		SType:       VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO,
		Size:        size,
		Usage:       usage,
		SharingMode: VK_SHARING_MODE_EXCLUSIVE,
	}
	var buffer VkBuffer
	res := callResult(procs.vkCreateBuffer, uintptr(device), uintptr(unsafe.Pointer(&ci)), 0, uintptr(unsafe.Pointer(&buffer)))
	if res != VK_SUCCESS {
		return 0, 0, res
	}

	var req VkMemoryRequirements
	callVoid(procs.vkGetBufferMemoryRequirements, uintptr(device), uintptr(buffer), uintptr(unsafe.Pointer(&req)))
	phys := currentPhysicalDevice(device)
	if phys == 0 {
		DestroyBuffer(device, buffer)
		return 0, 0, VK_ERROR_INITIALIZATION_FAILED
	}
	memType := FindMemoryType(phys, req.MemoryTypeBits, memProps)
	if memType == VK_QUEUE_FAMILY_IGNORED {
		DestroyBuffer(device, buffer)
		return 0, 0, VK_ERROR_OUT_OF_DEVICE_MEMORY
	}

	alloc := VkMemoryAllocateInfo{
		SType:           VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO,
		AllocationSize:  req.Size,
		MemoryTypeIndex: memType,
	}
	var memory VkDeviceMemory
	res = callResult(procs.vkAllocateMemory, uintptr(device), uintptr(unsafe.Pointer(&alloc)), 0, uintptr(unsafe.Pointer(&memory)))
	if res != VK_SUCCESS {
		DestroyBuffer(device, buffer)
		return 0, 0, res
	}
	res = callResult(procs.vkBindBufferMemory, uintptr(device), uintptr(buffer), uintptr(memory), 0)
	if res != VK_SUCCESS {
		DestroyBuffer(device, buffer)
		FreeMemory(device, memory)
		return 0, 0, res
	}
	return buffer, memory, res
}

func DestroyBuffer(device VkDevice, buffer VkBuffer) {
	if buffer != 0 {
		callVoid(procs.vkDestroyBuffer, uintptr(device), uintptr(buffer), 0)
	}
}

func FreeMemory(device VkDevice, memory VkDeviceMemory) {
	if memory != 0 {
		callVoid(procs.vkFreeMemory, uintptr(device), uintptr(memory), 0)
	}
}

func CreateImage(device VkDevice, width, height uint32, format VkFormat, usage VkImageUsageFlags, memProps VkMemoryPropertyFlags) (VkImage, VkDeviceMemory, VkResult) {
	ci := VkImageCreateInfo{
		SType:         VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO,
		ImageType:     VK_IMAGE_TYPE_2D,
		Format:        format,
		Extent:        VkExtent3D{Width: width, Height: height, Depth: 1},
		MipLevels:     1,
		ArrayLayers:   1,
		Samples:       VK_SAMPLE_COUNT_1_BIT,
		Tiling:        VK_IMAGE_TILING_OPTIMAL,
		Usage:         usage,
		SharingMode:   VK_SHARING_MODE_EXCLUSIVE,
		InitialLayout: VK_IMAGE_LAYOUT_UNDEFINED,
	}
	var image VkImage
	res := callResult(procs.vkCreateImage, uintptr(device), uintptr(unsafe.Pointer(&ci)), 0, uintptr(unsafe.Pointer(&image)))
	if res != VK_SUCCESS {
		return 0, 0, res
	}

	var req VkMemoryRequirements
	callVoid(procs.vkGetImageMemoryRequirements, uintptr(device), uintptr(image), uintptr(unsafe.Pointer(&req)))
	phys := currentPhysicalDevice(device)
	if phys == 0 {
		DestroyImage(device, image)
		return 0, 0, VK_ERROR_INITIALIZATION_FAILED
	}
	memType := FindMemoryType(phys, req.MemoryTypeBits, memProps)
	if memType == VK_QUEUE_FAMILY_IGNORED {
		DestroyImage(device, image)
		return 0, 0, VK_ERROR_OUT_OF_DEVICE_MEMORY
	}

	alloc := VkMemoryAllocateInfo{
		SType:           VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO,
		AllocationSize:  req.Size,
		MemoryTypeIndex: memType,
	}
	var memory VkDeviceMemory
	res = callResult(procs.vkAllocateMemory, uintptr(device), uintptr(unsafe.Pointer(&alloc)), 0, uintptr(unsafe.Pointer(&memory)))
	if res != VK_SUCCESS {
		DestroyImage(device, image)
		return 0, 0, res
	}
	res = callResult(procs.vkBindImageMemory, uintptr(device), uintptr(image), uintptr(memory), 0)
	if res != VK_SUCCESS {
		DestroyImage(device, image)
		FreeMemory(device, memory)
		return 0, 0, res
	}
	return image, memory, res
}

func DestroyImage(device VkDevice, image VkImage) {
	if image != 0 {
		callVoid(procs.vkDestroyImage, uintptr(device), uintptr(image), 0)
	}
}

func CreateImageView(device VkDevice, image VkImage, format VkFormat, aspect VkImageAspectFlags) (VkImageView, VkResult) {
	ci := VkImageViewCreateInfo{
		SType:    VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO,
		Image:    image,
		ViewType: VK_IMAGE_VIEW_TYPE_2D,
		Format:   format,
		Components: VkComponentMapping{
			R: VK_COMPONENT_SWIZZLE_IDENTITY,
			G: VK_COMPONENT_SWIZZLE_IDENTITY,
			B: VK_COMPONENT_SWIZZLE_IDENTITY,
			A: VK_COMPONENT_SWIZZLE_IDENTITY,
		},
		SubresourceRange: VkImageSubresourceRange{
			AspectMask:     aspect,
			BaseMipLevel:   0,
			LevelCount:     1,
			BaseArrayLayer: 0,
			LayerCount:     1,
		},
	}
	var view VkImageView
	res := callResult(procs.vkCreateImageView, uintptr(device), uintptr(unsafe.Pointer(&ci)), 0, uintptr(unsafe.Pointer(&view)))
	return view, res
}

func DestroyImageView(device VkDevice, view VkImageView) {
	if view != 0 {
		callVoid(procs.vkDestroyImageView, uintptr(device), uintptr(view), 0)
	}
}

func MapMemory(device VkDevice, memory VkDeviceMemory, offset, size VkDeviceSize) (unsafe.Pointer, VkResult) {
	var ptr unsafe.Pointer
	res := callResult(procs.vkMapMemory, uintptr(device), uintptr(memory), uintptr(offset), uintptr(size), 0, uintptr(unsafe.Pointer(&ptr)))
	return ptr, res
}

func UnmapMemory(device VkDevice, memory VkDeviceMemory) {
	callVoid(procs.vkUnmapMemory, uintptr(device), uintptr(memory))
}

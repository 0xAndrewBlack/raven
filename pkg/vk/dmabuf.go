package vk

import (
	"fmt"
	"unsafe"
)

func hasDeviceExtension(device VkDevice, name string) bool {
	if device == 0 {
		return false
	}
	exts, ok := deviceExtensionMap.Load(device)
	if !ok {
		return false
	}
	_, ok = exts.(map[string]struct{})[name]
	return ok
}

func SupportsDmabufExport(device VkDevice) bool {
	return device != 0 &&
		procs.vkGetMemoryFdKHR != 0 &&
		hasDeviceExtension(device, VK_KHR_EXTERNAL_MEMORY_EXTENSION_NAME) &&
		hasDeviceExtension(device, VK_KHR_EXTERNAL_MEMORY_FD_EXTENSION_NAME) &&
		hasDeviceExtension(device, VK_EXT_EXTERNAL_MEMORY_DMA_BUF_EXTENSION_NAME)
}

func CreateExportableImage(device VkDevice, width, height uint32, format VkFormat, usage VkImageUsageFlags, memProps VkMemoryPropertyFlags, handleTypes VkExternalMemoryHandleTypeFlags) (VkImage, VkDeviceMemory, VkResult) {
	if handleTypes == 0 {
		return CreateImage(device, width, height, format, usage, memProps)
	}

	externalImage := VkExternalMemoryImageCreateInfo{
		SType:       VK_STRUCTURE_TYPE_EXTERNAL_MEMORY_IMAGE_CREATE_INFO,
		HandleTypes: handleTypes,
	}
	ci := VkImageCreateInfo{
		SType:         VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO,
		PNext:         unsafe.Pointer(&externalImage),
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
		return 0, 0, VK_ERROR_INITIALIZATION_FAILED
	}
	memType := FindMemoryType(phys, req.MemoryTypeBits, memProps)
	if memType == VK_QUEUE_FAMILY_IGNORED {
		return 0, 0, VK_ERROR_OUT_OF_DEVICE_MEMORY
	}

	exportAlloc := VkExportMemoryAllocateInfo{
		SType:       VK_STRUCTURE_TYPE_EXPORT_MEMORY_ALLOCATE_INFO,
		HandleTypes: handleTypes,
	}
	alloc := VkMemoryAllocateInfo{
		SType:           VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO,
		PNext:           unsafe.Pointer(&exportAlloc),
		AllocationSize:  req.Size,
		MemoryTypeIndex: memType,
	}
	var memory VkDeviceMemory
	res = callResult(procs.vkAllocateMemory, uintptr(device), uintptr(unsafe.Pointer(&alloc)), 0, uintptr(unsafe.Pointer(&memory)))
	if res != VK_SUCCESS {
		return 0, 0, res
	}
	res = callResult(procs.vkBindImageMemory, uintptr(device), uintptr(image), uintptr(memory), 0)
	return image, memory, res
}

func ExportImageDmabufFd(device VkDevice, memory VkDeviceMemory) (int, error) {
	if !SupportsDmabufExport(device) {
		return -1, fmt.Errorf("vulkan: dma-buf export unavailable")
	}
	info := VkMemoryGetFdInfoKHR{
		SType:      VK_STRUCTURE_TYPE_MEMORY_GET_FD_INFO_KHR,
		Memory:     memory,
		HandleType: VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF_BIT_EXT,
	}
	var fd int32 = -1
	res := callResult(procs.vkGetMemoryFdKHR, uintptr(device), uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&fd)))
	if res != VK_SUCCESS {
		return -1, fmt.Errorf("vulkan: vkGetMemoryFdKHR failed: %d", res)
	}
	return int(fd), nil
}

//go:build guest_windows

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
		memoryFdProc(device) != 0 &&
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
		DestroyImage(device, image)
		return 0, 0, VK_ERROR_INITIALIZATION_FAILED
	}
	memType := FindMemoryType(phys, req.MemoryTypeBits, memProps)
	if memType == VK_QUEUE_FAMILY_IGNORED {
		DestroyImage(device, image)
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
	res := callResult(memoryFdProc(device), uintptr(device), uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&fd)))
	if res != VK_SUCCESS {
		return -1, fmt.Errorf("vulkan: vkGetMemoryFdKHR failed: %d", res)
	}
	return int(fd), nil
}

// CreateLinearExportableImage creates a VK_IMAGE_TILING_LINEAR image with
// exportable memory (dma-buf). Linear tiling guarantees that the row pitch
// queried via vkGetImageSubresourceLayout is the actual stride in memory, so
// the compositor can import the buffer without any tiling mismatch.
func CreateLinearExportableImage(device VkDevice, width, height uint32, format VkFormat) (VkImage, VkDeviceMemory, VkResult) {
	externalImage := VkExternalMemoryImageCreateInfo{
		SType:       VK_STRUCTURE_TYPE_EXTERNAL_MEMORY_IMAGE_CREATE_INFO,
		HandleTypes: VkExternalMemoryHandleTypeFlags(VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF_BIT_EXT),
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
		Tiling:        VK_IMAGE_TILING_LINEAR,
		Usage:         VK_IMAGE_USAGE_TRANSFER_DST_BIT,
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
	// Prefer host-visible so the compositor can map it; fall back to device-local.
	memType := FindMemoryType(phys, req.MemoryTypeBits,
		VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT|VK_MEMORY_PROPERTY_HOST_COHERENT_BIT)
	if memType == VK_QUEUE_FAMILY_IGNORED {
		memType = FindMemoryType(phys, req.MemoryTypeBits, VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT)
	}
	if memType == VK_QUEUE_FAMILY_IGNORED {
		DestroyImage(device, image)
		return 0, 0, VK_ERROR_OUT_OF_DEVICE_MEMORY
	}

	exportAlloc := VkExportMemoryAllocateInfo{
		SType:       VK_STRUCTURE_TYPE_EXPORT_MEMORY_ALLOCATE_INFO,
		HandleTypes: VkExternalMemoryHandleTypeFlags(VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF_BIT_EXT),
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

// GetLinearImageRowPitch queries the actual row pitch (stride in bytes) of a
// linear-tiled image via vkGetImageSubresourceLayout. Only valid for images
// created with VK_IMAGE_TILING_LINEAR.
func GetLinearImageRowPitch(device VkDevice, image VkImage) uint32 {
	sub := VkImageSubresource{
		AspectMask: VK_IMAGE_ASPECT_COLOR_BIT,
		MipLevel:   0,
		ArrayLayer: 0,
	}
	var layout VkSubresourceLayout
	callVoid(procs.vkGetImageSubresourceLayout,
		uintptr(device), uintptr(image),
		uintptr(unsafe.Pointer(&sub)),
		uintptr(unsafe.Pointer(&layout)))
	return uint32(layout.RowPitch)
}

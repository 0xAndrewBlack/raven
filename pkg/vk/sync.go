package vk

import "unsafe"

func CreateFence(device VkDevice, signaled bool) (VkFence, VkResult) {
	ci := VkFenceCreateInfo{SType: VK_STRUCTURE_TYPE_FENCE_CREATE_INFO}
	if signaled {
		ci.Flags = VK_FENCE_CREATE_SIGNALED_BIT
	}
	var fence VkFence
	res := callResult(procs.vkCreateFence, uintptr(device), uintptr(unsafe.Pointer(&ci)), 0, uintptr(unsafe.Pointer(&fence)))
	return fence, res
}

func CreateSemaphore(device VkDevice) (VkSemaphore, VkResult) {
	ci := VkSemaphoreCreateInfo{SType: VK_STRUCTURE_TYPE_SEMAPHORE_CREATE_INFO}
	var sem VkSemaphore
	res := callResult(procs.vkCreateSemaphore, uintptr(device), uintptr(unsafe.Pointer(&ci)), 0, uintptr(unsafe.Pointer(&sem)))
	return sem, res
}

func WaitForFence(device VkDevice, fence VkFence, timeout uint64) VkResult {
	return callResult(procs.vkWaitForFences, uintptr(device), 1, uintptr(unsafe.Pointer(&fence)), uintptr(VK_TRUE), uintptr(timeout))
}

func ResetFence(device VkDevice, fence VkFence) VkResult {
	return callResult(procs.vkResetFences, uintptr(device), 1, uintptr(unsafe.Pointer(&fence)))
}

func DestroyFence(device VkDevice, fence VkFence) {
	callVoid(procs.vkDestroyFence, uintptr(device), uintptr(fence), 0)
}

func FreeCommandBuffer(device VkDevice, pool VkCommandPool, cb VkCommandBuffer) {
	callVoid(procs.vkFreeCommandBuffers, uintptr(device), uintptr(pool), 1, uintptr(unsafe.Pointer(&cb)))
}

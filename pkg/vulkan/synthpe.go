package vulkan

import (
	"github.com/mirkobrombin/Raven/pkg/ntapi"
	"github.com/mirkobrombin/Raven/pkg/mmu"
)

// vulkanExports lists the Vulkan API entry points for the synthetic vulkan-1.dll.
// This is a minimal subset for basic Vulkan initialization.
var vulkanExports = []string{
	"vkCreateInstance",
	"vkDestroyInstance",
	"vkEnumeratePhysicalDevices",
	"vkGetPhysicalDeviceProperties",
	"vkGetPhysicalDeviceFeatures",
	"vkGetPhysicalDeviceQueueFamilyProperties",
	"vkCreateDevice",
	"vkDestroyDevice",
	"vkGetDeviceQueue",
	"vkDeviceWaitIdle",
	"vkCreateCommandPool",
	"vkDestroyCommandPool",
	"vkAllocateCommandBuffers",
	"vkFreeCommandBuffers",
	"vkBeginCommandBuffer",
	"vkEndCommandBuffer",
	"vkQueueSubmit",
	"vkQueueWaitIdle",
	"vkCreateFence",
	"vkDestroyFence",
	"vkWaitForFences",
	"vkResetFences",
	"vkCreateSemaphore",
	"vkDestroySemaphore",
	"vkCreateSwapchainKHR",
	"vkDestroySwapchainKHR",
	"vkGetSwapchainImagesKHR",
	"vkAcquireNextImageKHR",
	"vkQueuePresentKHR",
	"vkCreateRenderPass",
	"vkDestroyRenderPass",
	"vkCreateFramebuffer",
	"vkDestroyFramebuffer",
	"vkCreateImageView",
	"vkDestroyImageView",
	"vkCreateShaderModule",
	"vkDestroyShaderModule",
	"vkCreatePipelineLayout",
	"vkDestroyPipelineLayout",
	"vkCreateGraphicsPipelines",
	"vkDestroyPipeline",
	"vkCmdBeginRenderPass",
	"vkCmdEndRenderPass",
	"vkCmdBindPipeline",
	"vkCmdDraw",
	"vkCmdDrawIndexed",
	"vkGetInstanceProcAddr",
	"vkGetDeviceProcAddr",
}

const vulkanIDBase = uint32(0x2000) // Vulkan syscalls: 0x2000-0x2FFF

// GenerateVulkanDLL creates a synthetic vulkan-1.dll in guest memory.
func GenerateVulkanDLL(mem *mmu.MMU) *ntapi.SynthPE {
	return ntapi.GenerateSynthDLL(mem, "vulkan-1.dll", vulkanExports, vulkanIDBase)
}

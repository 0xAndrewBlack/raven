//go:build guest_windows

package vk

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

type vulkanProcs struct {
	lib uintptr

	vkGetInstanceProcAddr uintptr
	vkGetDeviceProcAddr   uintptr
	vkCreateInstance      uintptr

	vkEnumerateInstanceLayerProperties       uintptr
	vkEnumerateInstanceExtensionProperties   uintptr
	vkEnumeratePhysicalDevices               uintptr
	vkGetPhysicalDeviceProperties            uintptr
	vkGetPhysicalDeviceQueueFamilyProperties uintptr
	vkGetPhysicalDeviceMemoryProperties      uintptr
	vkEnumerateDeviceExtensionProperties     uintptr
	vkCreateDevice                           uintptr
	vkGetDeviceQueue                         uintptr
	vkDestroyInstance                        uintptr

	vkDestroyDevice               uintptr
	vkDeviceWaitIdle              uintptr
	vkCreateCommandPool           uintptr
	vkAllocateCommandBuffers      uintptr
	vkBeginCommandBuffer          uintptr
	vkEndCommandBuffer            uintptr
	vkResetCommandBuffer          uintptr
	vkCmdBeginRenderPass          uintptr
	vkCmdEndRenderPass            uintptr
	vkCmdBindPipeline             uintptr
	vkCmdBindVertexBuffers        uintptr
	vkCmdBindIndexBuffer          uintptr
	vkCmdDraw                     uintptr
	vkCmdDrawIndexed              uintptr
	vkCmdSetViewport              uintptr
	vkCmdSetScissor               uintptr
	vkCmdPushConstants            uintptr
	vkCmdPipelineBarrier          uintptr
	vkCmdCopyImageToBuffer        uintptr
	vkCmdCopyImage                uintptr
	vkGetImageSubresourceLayout   uintptr
	vkQueueSubmit                 uintptr
	vkQueueWaitIdle               uintptr
	vkCreateRenderPass            uintptr
	vkCreateFramebuffer           uintptr
	vkCreateShaderModule          uintptr
	vkCreatePipelineLayout        uintptr
	vkCreateGraphicsPipelines     uintptr
	vkCreateBuffer                uintptr
	vkGetBufferMemoryRequirements uintptr
	vkBindBufferMemory            uintptr
	vkCreateImage                 uintptr
	vkGetImageMemoryRequirements  uintptr
	vkBindImageMemory             uintptr
	vkCreateImageView             uintptr
	vkAllocateMemory              uintptr
	vkMapMemory                   uintptr
	vkUnmapMemory                 uintptr
	vkCreateFence                 uintptr
	vkDestroyFence                uintptr
	vkCreateSemaphore             uintptr
	vkWaitForFences               uintptr
	vkResetFences                 uintptr
	vkFreeCommandBuffers          uintptr
	vkGetMemoryFdKHR              uintptr
	vkCreateSwapchainKHR          uintptr
	vkDestroySwapchainKHR         uintptr
	vkGetSwapchainImagesKHR       uintptr
	vkAcquireNextImageKHR         uintptr
	vkQueuePresentKHR             uintptr
}

var (
	procs vulkanProcs

	initOnce sync.Once
	initErr  error

	activePhysicalDevice VkPhysicalDevice
	devicePhysicalMap    sync.Map
	deviceExtensionMap   sync.Map
)

func Init() error {
	initOnce.Do(func() {
		lib, err := purego.Dlopen("libvulkan.so.1", purego.RTLD_LAZY)
		if err != nil {
			initErr = fmt.Errorf("dlopen libvulkan.so.1: %w", err)
			return
		}
		procs.lib = lib

		procs.vkGetInstanceProcAddr, err = purego.Dlsym(lib, "vkGetInstanceProcAddr")
		if err != nil {
			initErr = fmt.Errorf("resolve vkGetInstanceProcAddr: %w", err)
			return
		}

		// vkGetDeviceProcAddr is not always available via vkGetInstanceProcAddr(NULL, ...),
		// so load it directly from the shared library.
		procs.vkGetDeviceProcAddr, err = purego.Dlsym(lib, "vkGetDeviceProcAddr")
		if err != nil {
			initErr = fmt.Errorf("resolve vkGetDeviceProcAddr: %w", err)
			return
		}

		if err := loadGlobalFuncs(); err != nil {
			initErr = err
		}
	})
	return initErr
}

func LoadInstanceFuncs(instance VkInstance) error {
	if err := Init(); err != nil {
		return err
	}

	var err error
	if procs.vkEnumeratePhysicalDevices, err = loadRequiredInstanceProc(instance, "vkEnumeratePhysicalDevices"); err != nil {
		return err
	}
	if procs.vkGetPhysicalDeviceProperties, err = loadRequiredInstanceProc(instance, "vkGetPhysicalDeviceProperties"); err != nil {
		return err
	}
	if procs.vkGetPhysicalDeviceQueueFamilyProperties, err = loadRequiredInstanceProc(instance, "vkGetPhysicalDeviceQueueFamilyProperties"); err != nil {
		return err
	}
	if procs.vkGetPhysicalDeviceMemoryProperties, err = loadRequiredInstanceProc(instance, "vkGetPhysicalDeviceMemoryProperties"); err != nil {
		return err
	}
	if procs.vkEnumerateDeviceExtensionProperties, err = loadRequiredInstanceProc(instance, "vkEnumerateDeviceExtensionProperties"); err != nil {
		return err
	}
	if procs.vkCreateDevice, err = loadRequiredInstanceProc(instance, "vkCreateDevice"); err != nil {
		return err
	}
	if procs.vkDestroyInstance, err = loadRequiredInstanceProc(instance, "vkDestroyInstance"); err != nil {
		return err
	}
	return nil
}

func LoadDeviceFuncs(device VkDevice) error {
	if err := Init(); err != nil {
		return err
	}

	var err error
	if procs.vkGetDeviceQueue, err = loadRequiredDeviceProc(device, "vkGetDeviceQueue"); err != nil {
		return err
	}
	if procs.vkDestroyDevice, err = loadRequiredDeviceProc(device, "vkDestroyDevice"); err != nil {
		return err
	}
	if procs.vkDeviceWaitIdle, err = loadRequiredDeviceProc(device, "vkDeviceWaitIdle"); err != nil {
		return err
	}
	if procs.vkCreateCommandPool, err = loadRequiredDeviceProc(device, "vkCreateCommandPool"); err != nil {
		return err
	}
	if procs.vkAllocateCommandBuffers, err = loadRequiredDeviceProc(device, "vkAllocateCommandBuffers"); err != nil {
		return err
	}
	if procs.vkBeginCommandBuffer, err = loadRequiredDeviceProc(device, "vkBeginCommandBuffer"); err != nil {
		return err
	}
	if procs.vkEndCommandBuffer, err = loadRequiredDeviceProc(device, "vkEndCommandBuffer"); err != nil {
		return err
	}
	if procs.vkResetCommandBuffer, err = loadRequiredDeviceProc(device, "vkResetCommandBuffer"); err != nil {
		return err
	}
	if procs.vkCmdBeginRenderPass, err = loadRequiredDeviceProc(device, "vkCmdBeginRenderPass"); err != nil {
		return err
	}
	if procs.vkCmdEndRenderPass, err = loadRequiredDeviceProc(device, "vkCmdEndRenderPass"); err != nil {
		return err
	}
	if procs.vkCmdBindPipeline, err = loadRequiredDeviceProc(device, "vkCmdBindPipeline"); err != nil {
		return err
	}
	if procs.vkCmdBindVertexBuffers, err = loadRequiredDeviceProc(device, "vkCmdBindVertexBuffers"); err != nil {
		return err
	}
	if procs.vkCmdBindIndexBuffer, err = loadRequiredDeviceProc(device, "vkCmdBindIndexBuffer"); err != nil {
		return err
	}
	if procs.vkCmdDraw, err = loadRequiredDeviceProc(device, "vkCmdDraw"); err != nil {
		return err
	}
	if procs.vkCmdDrawIndexed, err = loadRequiredDeviceProc(device, "vkCmdDrawIndexed"); err != nil {
		return err
	}
	if procs.vkCmdSetViewport, err = loadRequiredDeviceProc(device, "vkCmdSetViewport"); err != nil {
		return err
	}
	if procs.vkCmdSetScissor, err = loadRequiredDeviceProc(device, "vkCmdSetScissor"); err != nil {
		return err
	}
	if procs.vkCmdPushConstants, err = loadRequiredDeviceProc(device, "vkCmdPushConstants"); err != nil {
		return err
	}
	if procs.vkCmdPipelineBarrier, err = loadRequiredDeviceProc(device, "vkCmdPipelineBarrier"); err != nil {
		return err
	}
	if procs.vkCmdCopyImageToBuffer, err = loadRequiredDeviceProc(device, "vkCmdCopyImageToBuffer"); err != nil {
		return err
	}
	if procs.vkCmdCopyImage, err = loadRequiredDeviceProc(device, "vkCmdCopyImage"); err != nil {
		return err
	}
	if procs.vkGetImageSubresourceLayout, err = loadRequiredDeviceProc(device, "vkGetImageSubresourceLayout"); err != nil {
		return err
	}
	if procs.vkQueueSubmit, err = loadRequiredDeviceProc(device, "vkQueueSubmit"); err != nil {
		return err
	}
	if procs.vkQueueWaitIdle, err = loadRequiredDeviceProc(device, "vkQueueWaitIdle"); err != nil {
		return err
	}
	if procs.vkCreateRenderPass, err = loadRequiredDeviceProc(device, "vkCreateRenderPass"); err != nil {
		return err
	}
	if procs.vkCreateFramebuffer, err = loadRequiredDeviceProc(device, "vkCreateFramebuffer"); err != nil {
		return err
	}
	if procs.vkCreateShaderModule, err = loadRequiredDeviceProc(device, "vkCreateShaderModule"); err != nil {
		return err
	}
	if procs.vkCreatePipelineLayout, err = loadRequiredDeviceProc(device, "vkCreatePipelineLayout"); err != nil {
		return err
	}
	if procs.vkCreateGraphicsPipelines, err = loadRequiredDeviceProc(device, "vkCreateGraphicsPipelines"); err != nil {
		return err
	}
	if procs.vkCreateBuffer, err = loadRequiredDeviceProc(device, "vkCreateBuffer"); err != nil {
		return err
	}
	if procs.vkGetBufferMemoryRequirements, err = loadRequiredDeviceProc(device, "vkGetBufferMemoryRequirements"); err != nil {
		return err
	}
	if procs.vkBindBufferMemory, err = loadRequiredDeviceProc(device, "vkBindBufferMemory"); err != nil {
		return err
	}
	if procs.vkCreateImage, err = loadRequiredDeviceProc(device, "vkCreateImage"); err != nil {
		return err
	}
	if procs.vkGetImageMemoryRequirements, err = loadRequiredDeviceProc(device, "vkGetImageMemoryRequirements"); err != nil {
		return err
	}
	if procs.vkBindImageMemory, err = loadRequiredDeviceProc(device, "vkBindImageMemory"); err != nil {
		return err
	}
	if procs.vkCreateImageView, err = loadRequiredDeviceProc(device, "vkCreateImageView"); err != nil {
		return err
	}
	if procs.vkAllocateMemory, err = loadRequiredDeviceProc(device, "vkAllocateMemory"); err != nil {
		return err
	}
	if procs.vkMapMemory, err = loadRequiredDeviceProc(device, "vkMapMemory"); err != nil {
		return err
	}
	if procs.vkUnmapMemory, err = loadRequiredDeviceProc(device, "vkUnmapMemory"); err != nil {
		return err
	}
	if procs.vkCreateFence, err = loadRequiredDeviceProc(device, "vkCreateFence"); err != nil {
		return err
	}
	if procs.vkDestroyFence, err = loadRequiredDeviceProc(device, "vkDestroyFence"); err != nil {
		return err
	}
	if procs.vkCreateSemaphore, err = loadRequiredDeviceProc(device, "vkCreateSemaphore"); err != nil {
		return err
	}
	if procs.vkWaitForFences, err = loadRequiredDeviceProc(device, "vkWaitForFences"); err != nil {
		return err
	}
	if procs.vkResetFences, err = loadRequiredDeviceProc(device, "vkResetFences"); err != nil {
		return err
	}
	if procs.vkFreeCommandBuffers, err = loadRequiredDeviceProc(device, "vkFreeCommandBuffers"); err != nil {
		return err
	}
	procs.vkGetMemoryFdKHR, _ = loadOptionalDeviceProc(device, "vkGetMemoryFdKHR")

	procs.vkCreateSwapchainKHR, _ = loadOptionalDeviceProc(device, "vkCreateSwapchainKHR")
	procs.vkDestroySwapchainKHR, _ = loadOptionalDeviceProc(device, "vkDestroySwapchainKHR")
	procs.vkGetSwapchainImagesKHR, _ = loadOptionalDeviceProc(device, "vkGetSwapchainImagesKHR")
	procs.vkAcquireNextImageKHR, _ = loadOptionalDeviceProc(device, "vkAcquireNextImageKHR")
	procs.vkQueuePresentKHR, _ = loadOptionalDeviceProc(device, "vkQueuePresentKHR")
	return nil
}

func loadGlobalFuncs() error {
	var err error
	if procs.vkCreateInstance, err = loadRequiredGlobalProc("vkCreateInstance"); err != nil {
		return err
	}
	if procs.vkEnumerateInstanceLayerProperties, err = loadRequiredGlobalProc("vkEnumerateInstanceLayerProperties"); err != nil {
		return err
	}
	if procs.vkEnumerateInstanceExtensionProperties, err = loadRequiredGlobalProc("vkEnumerateInstanceExtensionProperties"); err != nil {
		return err
	}
	return nil
}

func loadRequiredGlobalProc(name string) (uintptr, error) {
	ptr, err := loadGlobalProc(name)
	if err != nil {
		return 0, err
	}
	if ptr == 0 {
		return 0, fmt.Errorf("resolve %s: %w", name, errors.New("symbol returned null"))
	}
	return ptr, nil
}

func loadRequiredInstanceProc(instance VkInstance, name string) (uintptr, error) {
	ptr, err := loadInstanceProc(instance, name)
	if err != nil {
		return 0, err
	}
	if ptr == 0 {
		return 0, fmt.Errorf("resolve %s: %w", name, errors.New("symbol returned null"))
	}
	return ptr, nil
}

func loadRequiredDeviceProc(device VkDevice, name string) (uintptr, error) {
	ptr, err := loadDeviceProc(device, name)
	if err != nil {
		return 0, err
	}
	if ptr == 0 {
		return 0, fmt.Errorf("resolve %s: %w", name, errors.New("symbol returned null"))
	}
	return ptr, nil
}

func loadOptionalDeviceProc(device VkDevice, name string) (uintptr, error) {
	return loadDeviceProc(device, name)
}

func loadGlobalProc(name string) (uintptr, error) {
	return loadInstanceProc(0, name)
}

func loadInstanceProc(instance VkInstance, name string) (uintptr, error) {
	cname := cString(name)
	r1, _, _ := purego.SyscallN(procs.vkGetInstanceProcAddr, uintptr(instance), uintptr(unsafe.Pointer(&cname[0])))
	runtime.KeepAlive(cname)
	return r1, nil
}

func loadDeviceProc(device VkDevice, name string) (uintptr, error) {
	if procs.vkGetDeviceProcAddr == 0 {
		return 0, errors.New("vkGetDeviceProcAddr not loaded")
	}
	cname := cString(name)
	r1, _, _ := purego.SyscallN(procs.vkGetDeviceProcAddr, uintptr(device), uintptr(unsafe.Pointer(&cname[0])))
	runtime.KeepAlive(cname)
	return r1, nil
}

func callResult(proc uintptr, args ...uintptr) VkResult {
	r1, _, _ := purego.SyscallN(proc, args...)
	return VkResult(int32(r1))
}

func callVoid(proc uintptr, args ...uintptr) uintptr {
	r1, _, _ := purego.SyscallN(proc, args...)
	return r1
}

func cString(s string) []byte {
	b := make([]byte, len(s)+1)
	copy(b, s)
	return b
}

func boolToVkBool(v bool) VkBool32 {
	if v {
		return VK_TRUE
	}
	return VK_FALSE
}

func stringArray(strs []string) ([][]byte, []*byte) {
	if len(strs) == 0 {
		return nil, nil
	}
	storage := make([][]byte, len(strs))
	ptrs := make([]*byte, len(strs))
	for i, s := range strs {
		storage[i] = cString(s)
		ptrs[i] = &storage[i][0]
	}
	return storage, ptrs
}

func currentPhysicalDevice(device VkDevice) VkPhysicalDevice {
	if device != 0 {
		if phys, ok := devicePhysicalMap.Load(device); ok {
			return phys.(VkPhysicalDevice)
		}
	}
	return activePhysicalDevice
}

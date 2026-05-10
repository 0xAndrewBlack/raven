//go:build guest_windows

package vk

import (
	"errors"
	"fmt"
	"reflect"
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
	vkDestroyCommandPool          uintptr
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
	vkDestroyRenderPass           uintptr
	vkCreateFramebuffer           uintptr
	vkDestroyFramebuffer          uintptr
	vkCreateShaderModule          uintptr
	vkDestroyShaderModule         uintptr
	vkCreatePipelineLayout        uintptr
	vkDestroyPipelineLayout       uintptr
	vkCreateGraphicsPipelines     uintptr
	vkDestroyPipeline             uintptr
	vkCreateDescriptorSetLayout   uintptr
	vkDestroyDescriptorSetLayout  uintptr
	vkCreateDescriptorPool        uintptr
	vkDestroyDescriptorPool       uintptr
	vkAllocateDescriptorSets      uintptr
	vkUpdateDescriptorSets        uintptr
	vkCmdBindDescriptorSets       uintptr
	vkCreateBuffer                uintptr
	vkDestroyBuffer               uintptr
	vkGetBufferMemoryRequirements uintptr
	vkBindBufferMemory            uintptr
	vkCreateImage                 uintptr
	vkDestroyImage                uintptr
	vkGetImageMemoryRequirements  uintptr
	vkBindImageMemory             uintptr
	vkCreateImageView             uintptr
	vkDestroyImageView            uintptr
	vkAllocateMemory              uintptr
	vkFreeMemory                  uintptr
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

	devicePhysicalMap  sync.Map
	deviceExtensionMap sync.Map
	deviceMemoryFdProc sync.Map
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

		if err := loadExportedFuncs(); err != nil {
			initErr = err
		}
	})
	return initErr
}

func LoadInstanceFuncs(instance VkInstance) error {
	_ = instance
	return Init()
}

func LoadDeviceFuncs(device VkDevice) error {
	if err := Init(); err != nil {
		return err
	}
	ptr, err := loadOptionalDeviceProc(device, "vkGetMemoryFdKHR")
	if err != nil {
		return err
	}
	if ptr != 0 {
		deviceMemoryFdProc.Store(device, ptr)
	}
	return nil
}

func loadExportedFuncs() error {
	optional := map[string]bool{
		"vkCreateSwapchainKHR":    true,
		"vkDestroySwapchainKHR":   true,
		"vkGetSwapchainImagesKHR": true,
		"vkAcquireNextImageKHR":   true,
		"vkQueuePresentKHR":       true,
	}
	typ := reflect.TypeOf(procs)
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		name := field.Name
		if name == "lib" || name == "vkGetInstanceProcAddr" || name == "vkGetDeviceProcAddr" || name == "vkGetMemoryFdKHR" {
			continue
		}
		ptr, err := purego.Dlsym(procs.lib, name)
		if err != nil {
			if optional[name] {
				continue
			}
			return fmt.Errorf("resolve %s: %w", name, err)
		}
		slot := (*uintptr)(unsafe.Add(unsafe.Pointer(&procs), field.Offset))
		*slot = ptr
	}
	return nil
}

func memoryFdProc(device VkDevice) uintptr {
	ptr, ok := deviceMemoryFdProc.Load(device)
	if !ok {
		return 0
	}
	return ptr.(uintptr)
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
	if phys, ok := devicePhysicalMap.Load(device); ok {
		return phys.(VkPhysicalDevice)
	}
	return 0
}

//go:build guest_windows

package vk

import (
	"bytes"
	"runtime"
	"unsafe"
)

type physicalDevicePropertiesPrefix struct {
	APIVersion    uint32
	DriverVersion uint32
	VendorID      uint32
	DeviceID      uint32
	DeviceType    VkPhysicalDeviceType
}

func CreateInstance(appName string, enableValidation bool) (VkInstance, VkResult) {
	if err := Init(); err != nil {
		return 0, VK_ERROR_INITIALIZATION_FAILED
	}

	appNameBuf := cString(appName)
	engineNameBuf := cString("Raven")
	appInfo := VkApplicationInfo{
		SType:              VK_STRUCTURE_TYPE_APPLICATION_INFO,
		PApplicationName:   &appNameBuf[0],
		ApplicationVersion: 1,
		PEngineName:        &engineNameBuf[0],
		EngineVersion:      1,
		APIVersion:         MakeAPIVersion(0, 1, 0, 0),
	}

	var layers []string
	if enableValidation && hasInstanceLayer("VK_LAYER_KHRONOS_validation") {
		layers = append(layers, "VK_LAYER_KHRONOS_validation")
	}
	layerStorage, layerPtrs := stringArray(layers)
	extensions := supportedInstanceExtensions([]string{VK_KHR_EXTERNAL_MEMORY_CAPABILITIES_EXTENSION_NAME})
	extStorage, extPtrs := stringArray(extensions)

	ci := VkInstanceCreateInfo{
		SType:                 VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO,
		PApplicationInfo:      &appInfo,
		EnabledLayerCount:     uint32(len(layerPtrs)),
		EnabledExtensionCount: uint32(len(extPtrs)),
	}
	if len(layerPtrs) != 0 {
		ci.PPEnabledLayerNames = &layerPtrs[0]
	}
	if len(extPtrs) != 0 {
		ci.PPEnabledExtensionNames = &extPtrs[0]
	}

	var instance VkInstance
	res := callResult(procs.vkCreateInstance, uintptr(unsafe.Pointer(&ci)), 0, uintptr(unsafe.Pointer(&instance)))
	runtime.KeepAlive(appNameBuf)
	runtime.KeepAlive(engineNameBuf)
	runtime.KeepAlive(layerPtrs)
	runtime.KeepAlive(layerStorage)
	runtime.KeepAlive(extPtrs)
	runtime.KeepAlive(extStorage)
	if res != VK_SUCCESS {
		return 0, res
	}
	if err := LoadInstanceFuncs(instance); err != nil {
		if procs.vkDestroyInstance != 0 {
			callVoid(procs.vkDestroyInstance, uintptr(instance), 0)
		}
		return 0, VK_ERROR_INITIALIZATION_FAILED
	}
	return instance, VK_SUCCESS
}

func PickPhysicalDevice(instance VkInstance) (VkPhysicalDevice, VkResult) {
	if err := LoadInstanceFuncs(instance); err != nil {
		return 0, VK_ERROR_INITIALIZATION_FAILED
	}

	var count uint32
	res := callResult(procs.vkEnumeratePhysicalDevices, uintptr(instance), uintptr(unsafe.Pointer(&count)), 0)
	if res != VK_SUCCESS || count == 0 {
		return 0, res
	}

	devices := make([]VkPhysicalDevice, count)
	res = callResult(procs.vkEnumeratePhysicalDevices, uintptr(instance), uintptr(unsafe.Pointer(&count)), uintptr(unsafe.Pointer(&devices[0])))
	if res != VK_SUCCESS {
		return 0, res
	}

	var integrated VkPhysicalDevice
	for _, dev := range devices {
		switch physicalDeviceType(dev) {
		case VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU:
			return dev, VK_SUCCESS
		case VK_PHYSICAL_DEVICE_TYPE_INTEGRATED_GPU:
			if integrated == 0 {
				integrated = dev
			}
		}
	}

	if integrated != 0 {
		return integrated, VK_SUCCESS
	}
	return devices[0], VK_SUCCESS
}

func CreateDevice(physDev VkPhysicalDevice, queueFamilyIdx uint32) (VkDevice, VkQueue, VkResult) {
	if queueFamilyIdx == VK_QUEUE_FAMILY_IGNORED {
		queueFamilyIdx = FindGraphicsQueueFamily(physDev)
	}
	if queueFamilyIdx == VK_QUEUE_FAMILY_IGNORED {
		return 0, 0, VK_ERROR_INITIALIZATION_FAILED
	}

	priority := float32(1.0)
	queueInfo := VkDeviceQueueCreateInfo{
		SType:            VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO,
		QueueFamilyIndex: queueFamilyIdx,
		QueueCount:       1,
		PQueuePriorities: &priority,
	}

	extensions := supportedDeviceExtensions(physDev, []string{
		VK_KHR_SWAPCHAIN_EXTENSION_NAME,
		VK_KHR_EXTERNAL_MEMORY_EXTENSION_NAME,
		VK_KHR_EXTERNAL_MEMORY_FD_EXTENSION_NAME,
		VK_EXT_EXTERNAL_MEMORY_DMA_BUF_EXTENSION_NAME,
	})
	extStorage, extPtrs := stringArray(extensions)
	ci := VkDeviceCreateInfo{
		SType:                 VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO,
		QueueCreateInfoCount:  1,
		PQueueCreateInfos:     &queueInfo,
		EnabledExtensionCount: uint32(len(extPtrs)),
	}
	if len(extPtrs) != 0 {
		ci.PPEnabledExtensionNames = &extPtrs[0]
	}

	var device VkDevice
	res := callResult(procs.vkCreateDevice, uintptr(physDev), uintptr(unsafe.Pointer(&ci)), 0, uintptr(unsafe.Pointer(&device)))
	runtime.KeepAlive(extPtrs)
	runtime.KeepAlive(extStorage)
	if res != VK_SUCCESS {
		return 0, 0, res
	}
	if err := LoadDeviceFuncs(device); err != nil {
		if procs.vkDestroyDevice != 0 {
			callVoid(procs.vkDestroyDevice, uintptr(device), 0)
		}
		return 0, 0, VK_ERROR_INITIALIZATION_FAILED
	}
	enabledExts := make(map[string]struct{}, len(extensions))
	for _, name := range extensions {
		enabledExts[name] = struct{}{}
	}
	deviceExtensionMap.Store(device, enabledExts)

	var queue VkQueue
	callVoid(procs.vkGetDeviceQueue, uintptr(device), uintptr(queueFamilyIdx), 0, uintptr(unsafe.Pointer(&queue)))
	devicePhysicalMap.Store(device, physDev)
	return device, queue, VK_SUCCESS
}

func DeviceWaitIdle(device VkDevice) VkResult {
	if device == 0 {
		return VK_SUCCESS
	}
	return callResult(procs.vkDeviceWaitIdle, uintptr(device))
}

func DestroyDevice(device VkDevice) {
	if device == 0 {
		return
	}
	devicePhysicalMap.Delete(device)
	deviceExtensionMap.Delete(device)
	deviceMemoryFdProc.Delete(device)
	callVoid(procs.vkDestroyDevice, uintptr(device), 0)
}

func DestroyInstance(instance VkInstance) {
	if instance != 0 {
		callVoid(procs.vkDestroyInstance, uintptr(instance), 0)
	}
}

func FindGraphicsQueueFamily(physDev VkPhysicalDevice) uint32 {
	var count uint32
	callVoid(procs.vkGetPhysicalDeviceQueueFamilyProperties, uintptr(physDev), uintptr(unsafe.Pointer(&count)), 0)
	if count == 0 {
		return VK_QUEUE_FAMILY_IGNORED
	}
	props := make([]VkQueueFamilyProperties, count)
	callVoid(procs.vkGetPhysicalDeviceQueueFamilyProperties, uintptr(physDev), uintptr(unsafe.Pointer(&count)), uintptr(unsafe.Pointer(&props[0])))
	for i, prop := range props {
		if prop.QueueCount > 0 && prop.QueueFlags&VK_QUEUE_GRAPHICS_BIT != 0 {
			return uint32(i)
		}
	}
	return VK_QUEUE_FAMILY_IGNORED
}

func FindMemoryType(physDev VkPhysicalDevice, typeFilter uint32, properties VkMemoryPropertyFlags) uint32 {
	if physDev == 0 {
		return VK_QUEUE_FAMILY_IGNORED
	}
	var memProps VkPhysicalDeviceMemoryProperties
	callVoid(procs.vkGetPhysicalDeviceMemoryProperties, uintptr(physDev), uintptr(unsafe.Pointer(&memProps)))
	for i := uint32(0); i < memProps.MemoryTypeCount; i++ {
		if typeFilter&(1<<i) == 0 {
			continue
		}
		if memProps.MemoryTypes[i].PropertyFlags&properties == properties {
			return i
		}
	}
	return VK_QUEUE_FAMILY_IGNORED
}

func hasInstanceLayer(name string) bool {
	if procs.vkEnumerateInstanceLayerProperties == 0 {
		return false
	}
	var count uint32
	res := callResult(procs.vkEnumerateInstanceLayerProperties, uintptr(unsafe.Pointer(&count)), 0)
	if res != VK_SUCCESS || count == 0 {
		return false
	}
	layers := make([]VkLayerProperties, count)
	res = callResult(procs.vkEnumerateInstanceLayerProperties, uintptr(unsafe.Pointer(&count)), uintptr(unsafe.Pointer(&layers[0])))
	if res != VK_SUCCESS {
		return false
	}
	needle := []byte(name)
	for i := range layers {
		end := bytes.IndexByte(layers[i].LayerName[:], 0)
		if end < 0 {
			end = len(layers[i].LayerName)
		}
		if bytes.Equal(layers[i].LayerName[:end], needle) {
			return true
		}
	}
	return false
}

func supportedInstanceExtensions(wanted []string) []string {
	if len(wanted) == 0 || procs.vkEnumerateInstanceExtensionProperties == 0 {
		return nil
	}
	var count uint32
	res := callResult(procs.vkEnumerateInstanceExtensionProperties, 0, uintptr(unsafe.Pointer(&count)), 0)
	if res != VK_SUCCESS || count == 0 {
		return nil
	}
	props := make([]VkExtensionProperties, count)
	res = callResult(procs.vkEnumerateInstanceExtensionProperties, 0, uintptr(unsafe.Pointer(&count)), uintptr(unsafe.Pointer(&props[0])))
	if res != VK_SUCCESS {
		return nil
	}

	available := make(map[string]struct{}, count)
	for i := range props {
		end := bytes.IndexByte(props[i].ExtensionName[:], 0)
		if end < 0 {
			end = len(props[i].ExtensionName)
		}
		available[string(props[i].ExtensionName[:end])] = struct{}{}
	}

	out := make([]string, 0, len(wanted))
	for _, name := range wanted {
		if _, ok := available[name]; ok {
			out = append(out, name)
		}
	}
	return out
}

func supportedDeviceExtensions(physDev VkPhysicalDevice, wanted []string) []string {
	if len(wanted) == 0 || procs.vkEnumerateDeviceExtensionProperties == 0 {
		return nil
	}
	var count uint32
	res := callResult(procs.vkEnumerateDeviceExtensionProperties, uintptr(physDev), 0, uintptr(unsafe.Pointer(&count)), 0)
	if res != VK_SUCCESS || count == 0 {
		return nil
	}
	props := make([]VkExtensionProperties, count)
	res = callResult(procs.vkEnumerateDeviceExtensionProperties, uintptr(physDev), 0, uintptr(unsafe.Pointer(&count)), uintptr(unsafe.Pointer(&props[0])))
	if res != VK_SUCCESS {
		return nil
	}

	available := make(map[string]struct{}, count)
	for i := range props {
		end := bytes.IndexByte(props[i].ExtensionName[:], 0)
		if end < 0 {
			end = len(props[i].ExtensionName)
		}
		available[string(props[i].ExtensionName[:end])] = struct{}{}
	}

	out := make([]string, 0, len(wanted))
	for _, name := range wanted {
		if _, ok := available[name]; ok {
			out = append(out, name)
		}
	}
	return out
}

func physicalDeviceType(physDev VkPhysicalDevice) VkPhysicalDeviceType {
	buf := make([]byte, 4096)
	callVoid(procs.vkGetPhysicalDeviceProperties, uintptr(physDev), uintptr(unsafe.Pointer(&buf[0])))
	props := (*physicalDevicePropertiesPrefix)(unsafe.Pointer(&buf[0]))
	return props.DeviceType
}

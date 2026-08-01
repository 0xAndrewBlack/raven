#include <vulkan/vulkan.h>

_Static_assert(sizeof(VkInstanceCreateInfo) == 64, "PE64 instance info ABI");
_Static_assert(sizeof(VkApplicationInfo) == 48, "PE64 application info ABI");
_Static_assert(sizeof(VkPhysicalDeviceProperties) == 824, "PE64 properties ABI");

__declspec(dllexport) VkPhysicalDeviceProperties observed;
__declspec(dllexport) uint32_t device_count;
__declspec(dllexport) uint32_t loader_version;
__declspec(dllexport) uint32_t family_count;
__declspec(dllexport) VkQueueFamilyProperties families[16];
__declspec(dllexport) VkPhysicalDeviceMemoryProperties memory_properties;
__declspec(dllexport) VkPhysicalDeviceFeatures features;
__declspec(dllexport) uint32_t device_workflow;

unsigned int raven_entry(void)
{
	if (vkEnumerateInstanceVersion(&loader_version) != VK_SUCCESS || loader_version < VK_API_VERSION_1_0)
		return 1;
	if (vkGetInstanceProcAddr(VK_NULL_HANDLE, "vkEnumeratePhysicalDevices") ||
		vkGetInstanceProcAddr(VK_NULL_HANDLE, "vkNotImplemented"))
		return 2;
	PFN_vkCreateInstance create = (PFN_vkCreateInstance)vkGetInstanceProcAddr(VK_NULL_HANDLE, "vkCreateInstance");
	if (!create)
		return 3;
	VkApplicationInfo application = {VK_STRUCTURE_TYPE_APPLICATION_INFO, 0, "Raven ABI fixture", 1, "Raven", 1, VK_API_VERSION_1_0};
	VkInstanceCreateInfo info = {VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO, 0, 0, &application, 0, 0, 0, 0};
	VkInstance instance = VK_NULL_HANDLE;
	if (create(&info, 0, &instance) != VK_SUCCESS || !instance)
		return 4;
	if (vkEnumeratePhysicalDevices(instance, &device_count, 0) != VK_SUCCESS || !device_count || device_count > 16)
		return 5;
	VkPhysicalDevice devices[16];
	uint32_t count = 0;
	devices[0] = (VkPhysicalDevice)(uintptr_t)0x1234;
	if (vkEnumeratePhysicalDevices(instance, &count, devices) != VK_INCOMPLETE || count ||
		devices[0] != (VkPhysicalDevice)(uintptr_t)0x1234)
		return 6;
	count = 16;
	if (vkEnumeratePhysicalDevices(instance, &count, devices) != VK_SUCCESS || count != device_count)
		return 7;
	PFN_vkGetPhysicalDeviceProperties properties = (PFN_vkGetPhysicalDeviceProperties)vkGetInstanceProcAddr(instance, "vkGetPhysicalDeviceProperties");
	if (!properties)
		return 8;
	properties(devices[0], &observed);
	if (!observed.deviceName[0] || !observed.apiVersion)
		return 9;
	VkPhysicalDevice repeated[16];
	count = 16;
	if (vkEnumeratePhysicalDevices(instance, &count, repeated) != VK_SUCCESS || repeated[0] != devices[0])
		return 10;
	vkGetPhysicalDeviceMemoryProperties(devices[0], &memory_properties);
	vkGetPhysicalDeviceFeatures(devices[0], &features);
	if (!memory_properties.memoryTypeCount || !memory_properties.memoryHeapCount)
		return 11;
	vkGetPhysicalDeviceQueueFamilyProperties(devices[0], &family_count, 0);
	if (!family_count || family_count > 16)
		return 12;
	{
		uint32_t capacity = 1;
		VkQueueFamilyProperties single[2];
		single[1].queueCount = 0x7777;
		vkGetPhysicalDeviceQueueFamilyProperties(devices[0], &capacity, single);
		if (capacity != 1 || single[1].queueCount != 0x7777)
			return 13;
	}
	count = family_count;
	vkGetPhysicalDeviceQueueFamilyProperties(devices[0], &count, families);
	if (count != family_count || !families[0].queueCount)
		return 14;
	{
		float priority = 1.0f;
		VkDeviceQueueCreateInfo queue = {VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO, 0, 0, 0, 1, &priority};
		VkDeviceCreateInfo device_info = {VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO, 0, 0, 1, &queue, 0, 0, 0, 0, 0};
		VkDevice device = VK_NULL_HANDLE;
		VkQueue first = VK_NULL_HANDLE, second = VK_NULL_HANDLE;
		PFN_vkGetDeviceProcAddr get_device_proc = (PFN_vkGetDeviceProcAddr)vkGetInstanceProcAddr(instance, "vkGetDeviceProcAddr");
		if (!get_device_proc)
			return 15;
		if (vkCreateDevice(devices[0], &device_info, 0, &device) != VK_SUCCESS || !device)
			return 16;
		if (!get_device_proc(device, "vkGetDeviceQueue") || get_device_proc(device, "vkCreateInstance"))
			return 17;
		vkGetDeviceQueue(device, 0, 0, &first);
		vkGetDeviceQueue(device, 0, 0, &second);
		if (!first || first != second)
			return 18;
		if (vkDeviceWaitIdle(device) != VK_SUCCESS)
			return 19;
		vkDestroyDevice(device, 0);
		vkDestroyDevice(VK_NULL_HANDLE, 0);
		device_workflow = 1;
	}
	vkDestroyInstance(instance, 0);
	vkDestroyInstance(VK_NULL_HANDLE, 0);
	return 0;
}

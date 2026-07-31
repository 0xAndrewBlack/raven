#include <vulkan/vulkan.h>

_Static_assert(sizeof(VkInstanceCreateInfo) == 64, "PE64 instance info ABI");
_Static_assert(sizeof(VkApplicationInfo) == 48, "PE64 application info ABI");
_Static_assert(sizeof(VkPhysicalDeviceProperties) == 824, "PE64 properties ABI");

__declspec(dllexport) VkPhysicalDeviceProperties observed;
__declspec(dllexport) uint32_t device_count;
__declspec(dllexport) uint32_t loader_version;

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
	vkDestroyInstance(instance, 0);
	vkDestroyInstance(VK_NULL_HANDLE, 0);
	return 0;
}

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stddef.h>
#include <stdint.h>

/* Vulkan as a 32-bit program sees it: dispatchable handles are 32 bits wide, the rest of the types follow from that. */
#define VKAPI __stdcall
typedef uint32_t VkFlags;
typedef uint32_t VkBool32;
typedef uint64_t VkDeviceSize;
typedef int32_t VkResult;
typedef struct VkInstance_T *VkInstance;
typedef struct VkPhysicalDevice_T *VkPhysicalDevice;
typedef struct VkDevice_T *VkDevice;
typedef struct VkQueue_T *VkQueue;
typedef struct VkCommandBuffer_T *VkCommandBuffer;
typedef uint64_t VkBuffer, VkDeviceMemory, VkCommandPool, VkFence;

typedef struct { int32_t sType; const void *pNext; const char *pApplicationName; uint32_t applicationVersion; const char *pEngineName;
	uint32_t engineVersion; uint32_t apiVersion; } VkApplicationInfo;
typedef struct { int32_t sType; const void *pNext; VkFlags flags; const VkApplicationInfo *pApplicationInfo; uint32_t enabledLayerCount;
	const char *const *ppEnabledLayerNames; uint32_t enabledExtensionCount; const char *const *ppEnabledExtensionNames; } VkInstanceCreateInfo;
typedef struct { uint32_t queueFlags; uint32_t queueCount; uint32_t timestampValidBits; uint32_t minImageTransferGranularity[3]; } VkQueueFamilyProperties;
typedef struct { int32_t sType; const void *pNext; VkFlags flags; uint32_t queueFamilyIndex; uint32_t queueCount; const float *pQueuePriorities; } VkDeviceQueueCreateInfo;
typedef struct { int32_t sType; const void *pNext; VkFlags flags; uint32_t queueCreateInfoCount; const VkDeviceQueueCreateInfo *pQueueCreateInfos;
	uint32_t enabledLayerCount; const char *const *ppEnabledLayerNames; uint32_t enabledExtensionCount; const char *const *ppEnabledExtensionNames;
	const void *pEnabledFeatures; } VkDeviceCreateInfo;
typedef struct { uint32_t propertyFlags; uint32_t heapIndex; } VkMemoryType;
typedef struct { VkDeviceSize size; uint32_t flags; } VkMemoryHeap;
typedef struct { uint32_t memoryTypeCount; VkMemoryType memoryTypes[32]; uint32_t memoryHeapCount; VkMemoryHeap memoryHeaps[16]; } VkPhysicalDeviceMemoryProperties;
typedef struct { int32_t sType; const void *pNext; VkFlags flags; VkDeviceSize size; VkFlags usage; int32_t sharingMode; uint32_t queueFamilyIndexCount;
	const uint32_t *pQueueFamilyIndices; } VkBufferCreateInfo;
typedef struct { VkDeviceSize size; VkDeviceSize alignment; uint32_t memoryTypeBits; } VkMemoryRequirements;
typedef struct { int32_t sType; const void *pNext; VkDeviceSize allocationSize; uint32_t memoryTypeIndex; } VkMemoryAllocateInfo;
typedef struct { int32_t sType; const void *pNext; VkFlags flags; uint32_t queueFamilyIndex; } VkCommandPoolCreateInfo;
typedef struct { int32_t sType; const void *pNext; VkCommandPool commandPool; int32_t level; uint32_t commandBufferCount; } VkCommandBufferAllocateInfo;
typedef struct { int32_t sType; const void *pNext; VkFlags flags; const void *pInheritanceInfo; } VkCommandBufferBeginInfo;
typedef struct { int32_t sType; const void *pNext; uint32_t waitSemaphoreCount; const uint64_t *pWaitSemaphores; const uint32_t *pWaitDstStageMask;
	uint32_t commandBufferCount; const VkCommandBuffer *pCommandBuffers; uint32_t signalSemaphoreCount; const uint64_t *pSignalSemaphores; } VkSubmitInfo;
typedef struct { int32_t sType; const void *pNext; VkFlags flags; } VkFenceCreateInfo;
typedef struct { uint32_t apiVersion; uint32_t driverVersion; uint32_t vendorID; uint32_t deviceID; int32_t deviceType; char deviceName[256]; } VkPropertiesHead;

typedef void *(VKAPI *get_proc)(void *, const char *);
typedef VkResult (VKAPI *create_instance_function)(const VkInstanceCreateInfo *, const void *, VkInstance *);
typedef VkResult (VKAPI *enumerate_function)(VkInstance, uint32_t *, VkPhysicalDevice *);
typedef void (VKAPI *properties_function)(VkPhysicalDevice, void *);
typedef void (VKAPI *families_function)(VkPhysicalDevice, uint32_t *, VkQueueFamilyProperties *);
typedef void (VKAPI *memory_properties_function)(VkPhysicalDevice, VkPhysicalDeviceMemoryProperties *);
typedef VkResult (VKAPI *create_device_function)(VkPhysicalDevice, const VkDeviceCreateInfo *, const void *, VkDevice *);
typedef void (VKAPI *get_queue_function)(VkDevice, uint32_t, uint32_t, VkQueue *);
typedef VkResult (VKAPI *create_buffer_function)(VkDevice, const VkBufferCreateInfo *, const void *, VkBuffer *);
typedef void (VKAPI *buffer_requirements_function)(VkDevice, VkBuffer, VkMemoryRequirements *);
typedef VkResult (VKAPI *allocate_function)(VkDevice, const VkMemoryAllocateInfo *, const void *, VkDeviceMemory *);
typedef VkResult (VKAPI *bind_function)(VkDevice, VkBuffer, VkDeviceMemory, VkDeviceSize);
typedef VkResult (VKAPI *map_function)(VkDevice, VkDeviceMemory, VkDeviceSize, VkDeviceSize, VkFlags, void **);
typedef void (VKAPI *unmap_function)(VkDevice, VkDeviceMemory);
typedef VkResult (VKAPI *pool_function)(VkDevice, const VkCommandPoolCreateInfo *, const void *, VkCommandPool *);
typedef VkResult (VKAPI *allocate_buffers_function)(VkDevice, const VkCommandBufferAllocateInfo *, VkCommandBuffer *);
typedef VkResult (VKAPI *begin_function)(VkCommandBuffer, const VkCommandBufferBeginInfo *);
typedef void (VKAPI *fill_function)(VkCommandBuffer, VkBuffer, VkDeviceSize, VkDeviceSize, uint32_t);
typedef VkResult (VKAPI *end_function)(VkCommandBuffer);
typedef VkResult (VKAPI *fence_function)(VkDevice, const VkFenceCreateInfo *, const void *, VkFence *);
typedef VkResult (VKAPI *submit_function)(VkQueue, uint32_t, const VkSubmitInfo *, VkFence);
typedef VkResult (VKAPI *wait_function)(VkDevice, uint32_t, const VkFence *, VkBool32, uint64_t);
typedef VkResult (VKAPI *idle_function)(VkDevice);

static int equal(const char *a, const char *b)
{
	while (*a && *a == *b) { ++a; ++b; }
	return *a == *b;
}

int raven_entry(void)
{
	HMODULE loader = LoadLibraryA("vulkan-1.dll");
	if (!loader)
		return 1;
	get_proc instance_proc = (get_proc)GetProcAddress(loader, "vkGetInstanceProcAddr");
	create_instance_function create_instance = (create_instance_function)GetProcAddress(loader, "vkCreateInstance");
	if (!instance_proc || !create_instance)
		return 2;
	VkApplicationInfo application = {0};
	application.sType = 0;
	application.pApplicationName = "raven";
	application.apiVersion = (1u << 22) | (1u << 12);
	VkInstanceCreateInfo instance_info = {0};
	instance_info.sType = 1;
	instance_info.pApplicationInfo = &application;
	VkInstance instance = 0;
	if (create_instance(&instance_info, 0, &instance) != 0 || !instance)
		return 3;
	enumerate_function enumerate = (enumerate_function)instance_proc(instance, "vkEnumeratePhysicalDevices");
	properties_function properties = (properties_function)instance_proc(instance, "vkGetPhysicalDeviceProperties");
	families_function families = (families_function)instance_proc(instance, "vkGetPhysicalDeviceQueueFamilyProperties");
	memory_properties_function memory_properties = (memory_properties_function)instance_proc(instance, "vkGetPhysicalDeviceMemoryProperties");
	create_device_function create_device = (create_device_function)instance_proc(instance, "vkCreateDevice");
	get_proc device_proc = (get_proc)instance_proc(instance, "vkGetDeviceProcAddr");
	if (!enumerate || !properties || !families || !memory_properties || !create_device || !device_proc)
		return 4;
	uint32_t count = 0;
	if (enumerate(instance, &count, 0) != 0 || count == 0)
		return 5;
	VkPhysicalDevice devices[8];
	if (count > 8)
		count = 8;
	if (enumerate(instance, &count, devices) != 0 || !devices[0])
		return 6;
	static VkPropertiesHead head;
	static char properties_storage[1024];
	properties(devices[0], properties_storage);
	{
		VkPropertiesHead *source = (VkPropertiesHead *)properties_storage;
		head = *source;
	}
	if (head.apiVersion < (1u << 22) || !head.deviceName[0])
		return 7;
	uint32_t family_count = 0;
	families(devices[0], &family_count, 0);
	if (!family_count || family_count > 16)
		return 8;
	VkQueueFamilyProperties family_properties[16];
	families(devices[0], &family_count, family_properties);
	uint32_t family = 0xffffffffu;
	for (uint32_t index = 0; index < family_count; ++index)
		if (family_properties[index].queueFlags & 1) { family = index; break; }
	if (family == 0xffffffffu)
		return 9;
	VkPhysicalDeviceMemoryProperties memory;
	memory_properties(devices[0], &memory);
	if (!memory.memoryTypeCount)
		return 10;
	float priority = 1.0f;
	VkDeviceQueueCreateInfo queue_info = {0};
	queue_info.sType = 2;
	queue_info.queueFamilyIndex = family;
	queue_info.queueCount = 1;
	queue_info.pQueuePriorities = &priority;
	VkDeviceCreateInfo device_info = {0};
	device_info.sType = 3;
	device_info.queueCreateInfoCount = 1;
	device_info.pQueueCreateInfos = &queue_info;
	VkDevice device = 0;
	if (create_device(devices[0], &device_info, 0, &device) != 0 || !device)
		return 11;
	get_queue_function get_queue = (get_queue_function)device_proc(device, "vkGetDeviceQueue");
	create_buffer_function create_buffer = (create_buffer_function)device_proc(device, "vkCreateBuffer");
	buffer_requirements_function requirements = (buffer_requirements_function)device_proc(device, "vkGetBufferMemoryRequirements");
	allocate_function allocate = (allocate_function)device_proc(device, "vkAllocateMemory");
	bind_function bind = (bind_function)device_proc(device, "vkBindBufferMemory");
	map_function map = (map_function)device_proc(device, "vkMapMemory");
	unmap_function unmap = (unmap_function)device_proc(device, "vkUnmapMemory");
	pool_function create_pool = (pool_function)device_proc(device, "vkCreateCommandPool");
	allocate_buffers_function allocate_buffers = (allocate_buffers_function)device_proc(device, "vkAllocateCommandBuffers");
	begin_function begin = (begin_function)device_proc(device, "vkBeginCommandBuffer");
	fill_function fill = (fill_function)device_proc(device, "vkCmdFillBuffer");
	end_function end = (end_function)device_proc(device, "vkEndCommandBuffer");
	fence_function create_fence = (fence_function)device_proc(device, "vkCreateFence");
	submit_function submit = (submit_function)device_proc(device, "vkQueueSubmit");
	wait_function wait = (wait_function)device_proc(device, "vkWaitForFences");
	idle_function idle = (idle_function)device_proc(device, "vkDeviceWaitIdle");
	if (!get_queue || !create_buffer || !requirements || !allocate || !bind || !map || !unmap || !create_pool || !allocate_buffers || !begin || !fill ||
			!end || !create_fence || !submit || !wait || !idle)
		return 12;
	VkQueue queue = 0;
	get_queue(device, family, 0, &queue);
	if (!queue)
		return 13;
	VkBufferCreateInfo buffer_info = {0};
	buffer_info.sType = 12;
	buffer_info.size = 4096;
	buffer_info.usage = 0x2 | 0x4;
	VkBuffer buffer = 0;
	if (create_buffer(device, &buffer_info, 0, &buffer) != 0 || !buffer)
		return 14;
	VkMemoryRequirements need;
	requirements(device, buffer, &need);
	uint32_t type = 0xffffffffu;
	for (uint32_t index = 0; index < memory.memoryTypeCount; ++index)
		if ((need.memoryTypeBits & (1u << index)) && (memory.memoryTypes[index].propertyFlags & 6) == 6) { type = index; break; }
	if (type == 0xffffffffu)
		return 15;
	VkMemoryAllocateInfo allocation = {0};
	allocation.sType = 5;
	allocation.allocationSize = need.size;
	allocation.memoryTypeIndex = type;
	VkDeviceMemory block = 0;
	if (allocate(device, &allocation, 0, &block) != 0 || !block || bind(device, buffer, block, 0) != 0)
		return 16;
	VkCommandPoolCreateInfo pool_info = {0};
	pool_info.sType = 39;
	pool_info.queueFamilyIndex = family;
	VkCommandPool pool = 0;
	if (create_pool(device, &pool_info, 0, &pool) != 0)
		return 17;
	VkCommandBufferAllocateInfo buffers_info = {0};
	buffers_info.sType = 40;
	buffers_info.commandPool = pool;
	buffers_info.commandBufferCount = 1;
	VkCommandBuffer commands[1] = {0};
	if (allocate_buffers(device, &buffers_info, commands) != 0 || !commands[0])
		return 18;
	VkCommandBufferBeginInfo begin_info = {0};
	begin_info.sType = 42;
	if (begin(commands[0], &begin_info) != 0)
		return 19;
	fill(commands[0], buffer, 0, 4096, 0x5a5a1234u);
	if (end(commands[0]) != 0)
		return 20;
	VkFenceCreateInfo fence_info = {0};
	fence_info.sType = 8;
	VkFence fence = 0;
	if (create_fence(device, &fence_info, 0, &fence) != 0)
		return 21;
	VkSubmitInfo submission = {0};
	submission.sType = 4;
	submission.commandBufferCount = 1;
	submission.pCommandBuffers = commands;
	if (submit(queue, 1, &submission, fence) != 0)
		return 22;
	if (wait(device, 1, &fence, 1, 5000000000ull) != 0)
		return 23;
	void *mapped = 0;
	if (map(device, block, 0, 4096, 0, &mapped) != 0 || !mapped)
		return 24;
	if ((uintptr_t)mapped >= 0x80000000u)
		return 25;
	const uint32_t *words = (const uint32_t *)mapped;
	for (int index = 0; index < 1024; ++index)
		if (words[index] != 0x5a5a1234u)
			return 26;
	unmap(device, block);
	if (idle(device) != 0)
		return 27;
	return 0;
}

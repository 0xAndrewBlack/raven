#include <vulkan/vulkan.h>
#include "vulkan_compute_spirv.h"

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
__declspec(dllexport) uint32_t copy_workflow;
__declspec(dllexport) uint8_t copied[256];
__declspec(dllexport) uint32_t copy_fence_waits;
__declspec(dllexport) uint32_t compute_workflow;
__declspec(dllexport) uint32_t computed[64];

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
		{
			VkBufferCreateInfo buffer_info = {VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO, 0, 0, 256,
				VK_BUFFER_USAGE_TRANSFER_SRC_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT, VK_SHARING_MODE_EXCLUSIVE, 0, 0};
			VkBuffer source = VK_NULL_HANDLE, target = VK_NULL_HANDLE;
			VkDeviceMemory source_memory = VK_NULL_HANDLE, target_memory = VK_NULL_HANDLE;
			VkMemoryRequirements requirements;
			uint32_t type = 0xffffffffu, index;
			uint8_t *source_data = 0, *target_data = 0;
			VkCommandPoolCreateInfo pool_info = {VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO, 0, 0, 0};
			VkCommandPool pool = VK_NULL_HANDLE;
			VkCommandBuffer command = VK_NULL_HANDLE;
			VkFenceCreateInfo fence_info = {VK_STRUCTURE_TYPE_FENCE_CREATE_INFO, 0, 0};
			VkFence fence = VK_NULL_HANDLE;
			VkBufferCopy region = {0, 0, 256};
			VkQueue queue = first;
			if (vkCreateBuffer(device, &buffer_info, 0, &source) != VK_SUCCESS || vkCreateBuffer(device, &buffer_info, 0, &target) != VK_SUCCESS)
				return 20;
			vkGetBufferMemoryRequirements(device, source, &requirements);
			if (requirements.size < 256)
				return 21;
			for (index = 0; index < memory_properties.memoryTypeCount; ++index)
				if ((requirements.memoryTypeBits & (1u << index)) && (memory_properties.memoryTypes[index].propertyFlags &
					(VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT)) == (VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT)) {
					type = index;
					break;
				}
			if (type == 0xffffffffu)
				return 22;
			{
				VkMemoryAllocateInfo allocation = {VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO, 0, requirements.size, type};
				if (vkAllocateMemory(device, &allocation, 0, &source_memory) != VK_SUCCESS || vkAllocateMemory(device, &allocation, 0, &target_memory) != VK_SUCCESS)
					return 23;
			}
			if (vkBindBufferMemory(device, source, source_memory, 0) != VK_SUCCESS || vkBindBufferMemory(device, target, target_memory, 0) != VK_SUCCESS)
				return 24;
			if (vkMapMemory(device, source_memory, 0, VK_WHOLE_SIZE, 0, (void **)&source_data) != VK_SUCCESS || !source_data ||
				vkMapMemory(device, target_memory, 0, VK_WHOLE_SIZE, 0, (void **)&target_data) != VK_SUCCESS || !target_data)
				return 25;
			for (index = 0; index < 256; ++index) {
				source_data[index] = (uint8_t)(index * 7 + 3);
				target_data[index] = 0xee;
			}
			if (vkCreateCommandPool(device, &pool_info, 0, &pool) != VK_SUCCESS)
				return 26;
			{
				VkCommandBufferAllocateInfo allocation = {VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO, 0, pool, VK_COMMAND_BUFFER_LEVEL_PRIMARY, 1};
				VkCommandBufferBeginInfo begin = {VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO, 0, VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT, 0};
				if (vkAllocateCommandBuffers(device, &allocation, &command) != VK_SUCCESS || !command)
					return 27;
				if (vkBeginCommandBuffer(command, &begin) != VK_SUCCESS)
					return 28;
			}
			vkCmdCopyBuffer(command, source, target, 1, &region);
			if (vkEndCommandBuffer(command) != VK_SUCCESS)
				return 29;
			if (vkCreateFence(device, &fence_info, 0, &fence) != VK_SUCCESS)
				return 30;
			{
				VkSubmitInfo submit = {VK_STRUCTURE_TYPE_SUBMIT_INFO, 0, 0, 0, 0, 1, &command, 0, 0};
				if (vkQueueSubmit(queue, 1, &submit, fence) != VK_SUCCESS)
					return 31;
			}
			if (vkWaitForFences(device, 1, &fence, VK_TRUE, 10000000000ull) != VK_SUCCESS)
				return 32;
			++copy_fence_waits;
			for (index = 0; index < 256; ++index)
				if (target_data[index] != (uint8_t)(index * 7 + 3))
					return 33;
			for (index = 0; index < 256; ++index)
				copied[index] = target_data[index];
			if (vkResetFences(device, 1, &fence) != VK_SUCCESS)
				return 34;
			/* A second round trip through the same mappings: the guest changes the source, the device copies it again. */
			source_data[0] = 0x5a;
			{
				VkCommandBufferBeginInfo begin = {VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO, 0, VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT, 0};
				VkSubmitInfo submit = {VK_STRUCTURE_TYPE_SUBMIT_INFO, 0, 0, 0, 0, 1, &command, 0, 0};
				if (vkResetCommandPool(device, pool, 0) != VK_SUCCESS || vkBeginCommandBuffer(command, &begin) != VK_SUCCESS)
					return 35;
				vkCmdCopyBuffer(command, source, target, 1, &region);
				if (vkEndCommandBuffer(command) != VK_SUCCESS || vkQueueSubmit(queue, 1, &submit, VK_NULL_HANDLE) != VK_SUCCESS || vkQueueWaitIdle(queue) != VK_SUCCESS)
					return 36;
			}
			if (target_data[0] != 0x5a || target_data[1] != (uint8_t)(1 * 7 + 3))
				return 37;
			vkUnmapMemory(device, source_memory);
			vkUnmapMemory(device, target_memory);
			vkFreeCommandBuffers(device, pool, 1, &command);
			vkDestroyFence(device, fence, 0);
			vkDestroyCommandPool(device, pool, 0);
			vkDestroyBuffer(device, source, 0);
			vkDestroyBuffer(device, target, 0);
			vkFreeMemory(device, source_memory, 0);
			vkFreeMemory(device, target_memory, 0);
			copy_workflow = 1;
		}
		{
			/* A compute shader reads one storage buffer, scales it by a push constant and writes another. */
			VkBufferCreateInfo buffer_info = {VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO, 0, 0, 256, VK_BUFFER_USAGE_STORAGE_BUFFER_BIT, VK_SHARING_MODE_EXCLUSIVE, 0, 0};
			VkBuffer input = VK_NULL_HANDLE, output = VK_NULL_HANDLE;
			VkDeviceMemory input_memory = VK_NULL_HANDLE, output_memory = VK_NULL_HANDLE;
			VkMemoryRequirements requirements;
			uint32_t type = 0xffffffffu, index, scale = 3;
			uint32_t *input_data = 0, *output_data = 0;
			VkShaderModuleCreateInfo shader_info = {VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO, 0, 0, sizeof compute_words, compute_words};
			VkShaderModule shader = VK_NULL_HANDLE;
			VkDescriptorSetLayoutBinding bindings[2] = {
				{0, VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, 1, VK_SHADER_STAGE_COMPUTE_BIT, 0},
				{1, VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, 1, VK_SHADER_STAGE_COMPUTE_BIT, 0}};
			VkDescriptorSetLayoutCreateInfo set_layout_info = {VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO, 0, 0, 2, bindings};
			VkDescriptorSetLayout set_layout = VK_NULL_HANDLE;
			VkPushConstantRange range = {VK_SHADER_STAGE_COMPUTE_BIT, 0, 4};
			VkPipelineLayoutCreateInfo layout_info = {VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO, 0, 0, 1, &set_layout, 1, &range};
			VkPipelineLayout layout = VK_NULL_HANDLE;
			VkPipeline pipeline = VK_NULL_HANDLE;
			VkDescriptorPoolSize pool_size = {VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, 2};
			VkDescriptorPoolCreateInfo descriptor_pool_info = {VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO, 0, 0, 1, 1, &pool_size};
			VkDescriptorPool descriptor_pool = VK_NULL_HANDLE;
			VkDescriptorSet set = VK_NULL_HANDLE;
			VkDescriptorBufferInfo input_info, output_info;
			VkCommandPoolCreateInfo pool_info = {VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO, 0, 0, 0};
			VkCommandPool pool = VK_NULL_HANDLE;
			VkCommandBuffer command = VK_NULL_HANDLE;
			if (vkCreateBuffer(device, &buffer_info, 0, &input) != VK_SUCCESS || vkCreateBuffer(device, &buffer_info, 0, &output) != VK_SUCCESS)
				return 40;
			vkGetBufferMemoryRequirements(device, input, &requirements);
			for (index = 0; index < memory_properties.memoryTypeCount; ++index)
				if ((requirements.memoryTypeBits & (1u << index)) && (memory_properties.memoryTypes[index].propertyFlags &
					(VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT)) == (VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT)) {
					type = index;
					break;
				}
			if (type == 0xffffffffu)
				return 41;
			{
				VkMemoryAllocateInfo allocation = {VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO, 0, requirements.size, type};
				if (vkAllocateMemory(device, &allocation, 0, &input_memory) != VK_SUCCESS || vkAllocateMemory(device, &allocation, 0, &output_memory) != VK_SUCCESS)
					return 42;
			}
			if (vkBindBufferMemory(device, input, input_memory, 0) != VK_SUCCESS || vkBindBufferMemory(device, output, output_memory, 0) != VK_SUCCESS)
				return 43;
			if (vkMapMemory(device, input_memory, 0, VK_WHOLE_SIZE, 0, (void **)&input_data) != VK_SUCCESS ||
				vkMapMemory(device, output_memory, 0, VK_WHOLE_SIZE, 0, (void **)&output_data) != VK_SUCCESS || !input_data || !output_data)
				return 44;
			for (index = 0; index < 64; ++index) {
				input_data[index] = index + 10;
				output_data[index] = 0xdeadbeefu;
			}
			if (vkCreateShaderModule(device, &shader_info, 0, &shader) != VK_SUCCESS || !shader)
				return 45;
			if (vkCreateDescriptorSetLayout(device, &set_layout_info, 0, &set_layout) != VK_SUCCESS || vkCreatePipelineLayout(device, &layout_info, 0, &layout) != VK_SUCCESS)
				return 46;
			{
				VkComputePipelineCreateInfo pipeline_info = {VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO, 0, 0,
					{VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO, 0, 0, VK_SHADER_STAGE_COMPUTE_BIT, shader, "main", 0}, layout, VK_NULL_HANDLE, -1};
				if (vkCreateComputePipelines(device, VK_NULL_HANDLE, 1, &pipeline_info, 0, &pipeline) != VK_SUCCESS || !pipeline)
					return 47;
			}
			if (vkCreateDescriptorPool(device, &descriptor_pool_info, 0, &descriptor_pool) != VK_SUCCESS)
				return 48;
			{
				VkDescriptorSetAllocateInfo allocation = {VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO, 0, descriptor_pool, 1, &set_layout};
				if (vkAllocateDescriptorSets(device, &allocation, &set) != VK_SUCCESS || !set)
					return 49;
			}
			input_info.buffer = input; input_info.offset = 0; input_info.range = VK_WHOLE_SIZE;
			output_info.buffer = output; output_info.offset = 0; output_info.range = VK_WHOLE_SIZE;
			{
				VkWriteDescriptorSet writes[2] = {
					{VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET, 0, set, 0, 0, 1, VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, 0, &input_info, 0},
					{VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET, 0, set, 1, 0, 1, VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, 0, &output_info, 0}};
				vkUpdateDescriptorSets(device, 2, writes, 0, 0);
			}
			if (vkCreateCommandPool(device, &pool_info, 0, &pool) != VK_SUCCESS)
				return 50;
			{
				VkCommandBufferAllocateInfo allocation = {VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO, 0, pool, VK_COMMAND_BUFFER_LEVEL_PRIMARY, 1};
				VkCommandBufferBeginInfo begin = {VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO, 0, VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT, 0};
				VkSubmitInfo submit = {VK_STRUCTURE_TYPE_SUBMIT_INFO, 0, 0, 0, 0, 1, &command, 0, 0};
				if (vkAllocateCommandBuffers(device, &allocation, &command) != VK_SUCCESS || vkBeginCommandBuffer(command, &begin) != VK_SUCCESS)
					return 51;
				vkCmdBindPipeline(command, VK_PIPELINE_BIND_POINT_COMPUTE, pipeline);
				vkCmdBindDescriptorSets(command, VK_PIPELINE_BIND_POINT_COMPUTE, layout, 0, 1, &set, 0, 0);
				vkCmdPushConstants(command, layout, VK_SHADER_STAGE_COMPUTE_BIT, 0, 4, &scale);
				vkCmdDispatch(command, 1, 1, 1);
				if (vkEndCommandBuffer(command) != VK_SUCCESS || vkQueueSubmit(first, 1, &submit, VK_NULL_HANDLE) != VK_SUCCESS || vkQueueWaitIdle(first) != VK_SUCCESS)
					return 52;
			}
			for (index = 0; index < 64; ++index) {
				computed[index] = output_data[index];
				if (output_data[index] != (index + 10) * scale + index)
					return 53;
			}
			vkUnmapMemory(device, input_memory);
			vkUnmapMemory(device, output_memory);
			vkDestroyCommandPool(device, pool, 0);
			vkDestroyDescriptorPool(device, descriptor_pool, 0);
			vkDestroyPipeline(device, pipeline, 0);
			vkDestroyPipelineLayout(device, layout, 0);
			vkDestroyDescriptorSetLayout(device, set_layout, 0);
			vkDestroyShaderModule(device, shader, 0);
			vkDestroyBuffer(device, input, 0);
			vkDestroyBuffer(device, output, 0);
			vkFreeMemory(device, input_memory, 0);
			vkFreeMemory(device, output_memory, 0);
			compute_workflow = 1;
		}
		vkDestroyDevice(device, 0);
		vkDestroyDevice(VK_NULL_HANDLE, 0);
		device_workflow = 1;
	}
	vkDestroyInstance(instance, 0);
	vkDestroyInstance(VK_NULL_HANDLE, 0);
	return 0;
}

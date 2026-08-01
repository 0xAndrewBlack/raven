#include <vulkan/vulkan.h>
#include "vulkan_compute_spirv.h"
#include "vulkan_triangle_spirv.h"
#include "vulkan_quad_spirv.h"

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
__declspec(dllexport) uint32_t image_workflow;
__declspec(dllexport) uint32_t image_readback[64];
__declspec(dllexport) uint32_t graphics_workflow;
__declspec(dllexport) uint32_t rendered[256];
__declspec(dllexport) uint32_t textured_workflow;
__declspec(dllexport) uint32_t textured[256];

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
		{
			/* A 8x8 image on the device: upload from one buffer, barrier, read back into another, ordered by a semaphore. */
			VkImageCreateInfo image_info = {VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO, 0, 0, VK_IMAGE_TYPE_2D, VK_FORMAT_R8G8B8A8_UNORM, {8, 8, 1}, 1, 1,
				VK_SAMPLE_COUNT_1_BIT, VK_IMAGE_TILING_OPTIMAL, VK_IMAGE_USAGE_TRANSFER_DST_BIT | VK_IMAGE_USAGE_TRANSFER_SRC_BIT | VK_IMAGE_USAGE_SAMPLED_BIT,
				VK_SHARING_MODE_EXCLUSIVE, 0, 0, VK_IMAGE_LAYOUT_UNDEFINED};
			VkBufferCreateInfo buffer_info = {VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO, 0, 0, 256,
				VK_BUFFER_USAGE_TRANSFER_SRC_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT, VK_SHARING_MODE_EXCLUSIVE, 0, 0};
			VkImage image = VK_NULL_HANDLE;
			VkImageView view = VK_NULL_HANDLE;
			VkBuffer upload = VK_NULL_HANDLE, download = VK_NULL_HANDLE;
			VkDeviceMemory image_memory = VK_NULL_HANDLE, upload_memory = VK_NULL_HANDLE, download_memory = VK_NULL_HANDLE;
			VkMemoryRequirements requirements, buffer_requirements;
			uint32_t type = 0xffffffffu, host_type = 0xffffffffu, index, *upload_data = 0, *download_data = 0;
			VkCommandPoolCreateInfo pool_info = {VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO, 0, 0, 0};
			VkCommandPool pool = VK_NULL_HANDLE;
			VkCommandBuffer commands[2] = {VK_NULL_HANDLE, VK_NULL_HANDLE};
			VkSemaphoreCreateInfo semaphore_info = {VK_STRUCTURE_TYPE_SEMAPHORE_CREATE_INFO, 0, 0};
			VkSemaphore semaphore = VK_NULL_HANDLE;
			VkFenceCreateInfo fence_info = {VK_STRUCTURE_TYPE_FENCE_CREATE_INFO, 0, 0};
			VkFence fence = VK_NULL_HANDLE;
			VkImageSubresourceRange range = {VK_IMAGE_ASPECT_COLOR_BIT, 0, 1, 0, 1};
			VkBufferImageCopy copy = {0, 0, 0, {VK_IMAGE_ASPECT_COLOR_BIT, 0, 0, 1}, {0, 0, 0}, {8, 8, 1}};
			VkPipelineStageFlags wait_stage = VK_PIPELINE_STAGE_TRANSFER_BIT;
			if (vkCreateImage(device, &image_info, 0, &image) != VK_SUCCESS || !image)
				return 60;
			vkGetImageMemoryRequirements(device, image, &requirements);
			for (index = 0; index < 32 && type == 0xffffffffu; ++index)
				if (requirements.memoryTypeBits & (1u << index))
					type = index;
			if (type == 0xffffffffu)
				return 61;
			if (vkCreateBuffer(device, &buffer_info, 0, &upload) != VK_SUCCESS || vkCreateBuffer(device, &buffer_info, 0, &download) != VK_SUCCESS)
				return 62;
			vkGetBufferMemoryRequirements(device, upload, &buffer_requirements);
			for (index = 0; index < memory_properties.memoryTypeCount; ++index)
				if ((buffer_requirements.memoryTypeBits & (1u << index)) && (memory_properties.memoryTypes[index].propertyFlags &
					(VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT)) == (VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT)) {
					host_type = index;
					break;
				}
			if (host_type == 0xffffffffu)
				return 63;
			{
				VkMemoryAllocateInfo image_allocation = {VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO, 0, requirements.size, type};
				VkMemoryAllocateInfo host_allocation = {VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO, 0, buffer_requirements.size, host_type};
				if (vkAllocateMemory(device, &image_allocation, 0, &image_memory) != VK_SUCCESS || vkAllocateMemory(device, &host_allocation, 0, &upload_memory) != VK_SUCCESS ||
					vkAllocateMemory(device, &host_allocation, 0, &download_memory) != VK_SUCCESS)
					return 64;
			}
			if (vkBindImageMemory(device, image, image_memory, 0) != VK_SUCCESS || vkBindBufferMemory(device, upload, upload_memory, 0) != VK_SUCCESS ||
				vkBindBufferMemory(device, download, download_memory, 0) != VK_SUCCESS)
				return 65;
			{
				VkImageViewCreateInfo view_info = {VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO, 0, 0, image, VK_IMAGE_VIEW_TYPE_2D, VK_FORMAT_R8G8B8A8_UNORM,
					{VK_COMPONENT_SWIZZLE_IDENTITY, VK_COMPONENT_SWIZZLE_IDENTITY, VK_COMPONENT_SWIZZLE_IDENTITY, VK_COMPONENT_SWIZZLE_IDENTITY}, range};
				if (vkCreateImageView(device, &view_info, 0, &view) != VK_SUCCESS || !view)
					return 66;
			}
			if (vkMapMemory(device, upload_memory, 0, VK_WHOLE_SIZE, 0, (void **)&upload_data) != VK_SUCCESS ||
				vkMapMemory(device, download_memory, 0, VK_WHOLE_SIZE, 0, (void **)&download_data) != VK_SUCCESS || !upload_data || !download_data)
				return 67;
			for (index = 0; index < 64; ++index) {
				upload_data[index] = 0xff000000u | (index * 3u << 16) | (index * 2u << 8) | index;
				download_data[index] = 0;
			}
			if (vkCreateCommandPool(device, &pool_info, 0, &pool) != VK_SUCCESS || vkCreateSemaphore(device, &semaphore_info, 0, &semaphore) != VK_SUCCESS ||
				vkCreateFence(device, &fence_info, 0, &fence) != VK_SUCCESS)
				return 68;
			{
				VkCommandBufferAllocateInfo allocation = {VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO, 0, pool, VK_COMMAND_BUFFER_LEVEL_PRIMARY, 2};
				VkCommandBufferBeginInfo begin = {VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO, 0, VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT, 0};
				VkImageMemoryBarrier to_destination = {VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER, 0, 0, VK_ACCESS_TRANSFER_WRITE_BIT, VK_IMAGE_LAYOUT_UNDEFINED,
					VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL, VK_QUEUE_FAMILY_IGNORED, VK_QUEUE_FAMILY_IGNORED, image, range};
				VkImageMemoryBarrier to_source = {VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER, 0, VK_ACCESS_TRANSFER_WRITE_BIT, VK_ACCESS_TRANSFER_READ_BIT,
					VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL, VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL, VK_QUEUE_FAMILY_IGNORED, VK_QUEUE_FAMILY_IGNORED, image, range};
				VkSubmitInfo first_submit = {VK_STRUCTURE_TYPE_SUBMIT_INFO, 0, 0, 0, 0, 1, &commands[0], 1, &semaphore};
				VkSubmitInfo second_submit = {VK_STRUCTURE_TYPE_SUBMIT_INFO, 0, 1, &semaphore, &wait_stage, 1, &commands[1], 0, 0};
				if (vkAllocateCommandBuffers(device, &allocation, commands) != VK_SUCCESS || !commands[0] || !commands[1] || commands[0] == commands[1])
					return 69;
				vkBeginCommandBuffer(commands[0], &begin);
				vkCmdPipelineBarrier(commands[0], VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT, VK_PIPELINE_STAGE_TRANSFER_BIT, 0, 0, 0, 0, 0, 1, &to_destination);
				vkCmdCopyBufferToImage(commands[0], upload, image, VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL, 1, &copy);
				vkCmdPipelineBarrier(commands[0], VK_PIPELINE_STAGE_TRANSFER_BIT, VK_PIPELINE_STAGE_TRANSFER_BIT, 0, 0, 0, 0, 0, 1, &to_source);
				if (vkEndCommandBuffer(commands[0]) != VK_SUCCESS)
					return 70;
				vkBeginCommandBuffer(commands[1], &begin);
				vkCmdCopyImageToBuffer(commands[1], image, VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL, download, 1, &copy);
				if (vkEndCommandBuffer(commands[1]) != VK_SUCCESS)
					return 71;
				if (vkQueueSubmit(first, 1, &first_submit, VK_NULL_HANDLE) != VK_SUCCESS || vkQueueSubmit(first, 1, &second_submit, fence) != VK_SUCCESS)
					return 72;
			}
			if (vkWaitForFences(device, 1, &fence, VK_TRUE, 10000000000ull) != VK_SUCCESS || vkGetFenceStatus(device, fence) != VK_SUCCESS)
				return 73;
			for (index = 0; index < 64; ++index) {
				image_readback[index] = download_data[index];
				if (download_data[index] != upload_data[index])
					return 74;
			}
			vkUnmapMemory(device, upload_memory);
			vkUnmapMemory(device, download_memory);
			vkDestroyFence(device, fence, 0);
			vkDestroySemaphore(device, semaphore, 0);
			vkDestroyCommandPool(device, pool, 0);
			vkDestroyImageView(device, view, 0);
			vkDestroyImage(device, image, 0);
			vkDestroyBuffer(device, upload, 0);
			vkDestroyBuffer(device, download, 0);
			vkFreeMemory(device, image_memory, 0);
			vkFreeMemory(device, upload_memory, 0);
			vkFreeMemory(device, download_memory, 0);
			image_workflow = 1;
		}
		{
			/* A 16x16 target cleared to blue with a red triangle over its upper left half, read back through a buffer. */
			VkImageCreateInfo image_info = {VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO, 0, 0, VK_IMAGE_TYPE_2D, VK_FORMAT_R8G8B8A8_UNORM, {16, 16, 1}, 1, 1,
				VK_SAMPLE_COUNT_1_BIT, VK_IMAGE_TILING_OPTIMAL, VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT | VK_IMAGE_USAGE_TRANSFER_SRC_BIT,
				VK_SHARING_MODE_EXCLUSIVE, 0, 0, VK_IMAGE_LAYOUT_UNDEFINED};
			VkBufferCreateInfo buffer_info = {VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO, 0, 0, 1024, VK_BUFFER_USAGE_TRANSFER_DST_BIT, VK_SHARING_MODE_EXCLUSIVE, 0, 0};
			VkImage image = VK_NULL_HANDLE;
			VkImageView view = VK_NULL_HANDLE;
			VkBuffer readback = VK_NULL_HANDLE;
			VkDeviceMemory image_memory = VK_NULL_HANDLE, readback_memory = VK_NULL_HANDLE;
			VkMemoryRequirements requirements, buffer_requirements;
			uint32_t type = 0xffffffffu, host_type = 0xffffffffu, index, *pixels = 0;
			VkShaderModuleCreateInfo vertex_info = {VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO, 0, 0, sizeof triangle_vertex_words, triangle_vertex_words};
			VkShaderModuleCreateInfo fragment_info = {VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO, 0, 0, sizeof triangle_fragment_words, triangle_fragment_words};
			VkShaderModule vertex = VK_NULL_HANDLE, fragment = VK_NULL_HANDLE;
			VkAttachmentDescription attachment = {0, VK_FORMAT_R8G8B8A8_UNORM, VK_SAMPLE_COUNT_1_BIT, VK_ATTACHMENT_LOAD_OP_CLEAR, VK_ATTACHMENT_STORE_OP_STORE,
				VK_ATTACHMENT_LOAD_OP_DONT_CARE, VK_ATTACHMENT_STORE_OP_DONT_CARE, VK_IMAGE_LAYOUT_UNDEFINED, VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL};
			VkAttachmentReference reference = {0, VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL};
			VkSubpassDescription subpass = {0, VK_PIPELINE_BIND_POINT_GRAPHICS, 0, 0, 1, &reference, 0, 0, 0, 0};
			VkRenderPassCreateInfo pass_info = {VK_STRUCTURE_TYPE_RENDER_PASS_CREATE_INFO, 0, 0, 1, &attachment, 1, &subpass, 0, 0};
			VkRenderPass pass = VK_NULL_HANDLE;
			VkFramebufferCreateInfo framebuffer_info;
			VkFramebuffer framebuffer = VK_NULL_HANDLE;
			VkPipelineLayoutCreateInfo layout_info = {VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO, 0, 0, 0, 0, 0, 0};
			VkPipelineLayout layout = VK_NULL_HANDLE;
			VkPipeline pipeline = VK_NULL_HANDLE;
			VkCommandPoolCreateInfo pool_info = {VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO, 0, 0, 0};
			VkCommandPool pool = VK_NULL_HANDLE;
			VkCommandBuffer command = VK_NULL_HANDLE;
			VkImageSubresourceRange range = {VK_IMAGE_ASPECT_COLOR_BIT, 0, 1, 0, 1};
			VkBufferImageCopy copy = {0, 0, 0, {VK_IMAGE_ASPECT_COLOR_BIT, 0, 0, 1}, {0, 0, 0}, {16, 16, 1}};
			if (vkCreateImage(device, &image_info, 0, &image) != VK_SUCCESS)
				return 80;
			vkGetImageMemoryRequirements(device, image, &requirements);
			for (index = 0; index < 32 && type == 0xffffffffu; ++index)
				if (requirements.memoryTypeBits & (1u << index))
					type = index;
			if (vkCreateBuffer(device, &buffer_info, 0, &readback) != VK_SUCCESS)
				return 81;
			vkGetBufferMemoryRequirements(device, readback, &buffer_requirements);
			for (index = 0; index < memory_properties.memoryTypeCount; ++index)
				if ((buffer_requirements.memoryTypeBits & (1u << index)) && (memory_properties.memoryTypes[index].propertyFlags &
					(VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT)) == (VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT)) {
					host_type = index;
					break;
				}
			if (type == 0xffffffffu || host_type == 0xffffffffu)
				return 82;
			{
				VkMemoryAllocateInfo image_allocation = {VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO, 0, requirements.size, type};
				VkMemoryAllocateInfo host_allocation = {VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO, 0, buffer_requirements.size, host_type};
				if (vkAllocateMemory(device, &image_allocation, 0, &image_memory) != VK_SUCCESS || vkAllocateMemory(device, &host_allocation, 0, &readback_memory) != VK_SUCCESS)
					return 83;
			}
			if (vkBindImageMemory(device, image, image_memory, 0) != VK_SUCCESS || vkBindBufferMemory(device, readback, readback_memory, 0) != VK_SUCCESS ||
				vkMapMemory(device, readback_memory, 0, VK_WHOLE_SIZE, 0, (void **)&pixels) != VK_SUCCESS || !pixels)
				return 84;
			for (index = 0; index < 256; ++index)
				pixels[index] = 0x11223344u;
			{
				VkImageViewCreateInfo view_info = {VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO, 0, 0, image, VK_IMAGE_VIEW_TYPE_2D, VK_FORMAT_R8G8B8A8_UNORM,
					{VK_COMPONENT_SWIZZLE_IDENTITY, VK_COMPONENT_SWIZZLE_IDENTITY, VK_COMPONENT_SWIZZLE_IDENTITY, VK_COMPONENT_SWIZZLE_IDENTITY}, range};
				if (vkCreateImageView(device, &view_info, 0, &view) != VK_SUCCESS)
					return 85;
			}
			if (vkCreateShaderModule(device, &vertex_info, 0, &vertex) != VK_SUCCESS || vkCreateShaderModule(device, &fragment_info, 0, &fragment) != VK_SUCCESS)
				return 86;
			if (vkCreateRenderPass(device, &pass_info, 0, &pass) != VK_SUCCESS || !pass)
				return 87;
			framebuffer_info.sType = VK_STRUCTURE_TYPE_FRAMEBUFFER_CREATE_INFO; framebuffer_info.pNext = 0; framebuffer_info.flags = 0;
			framebuffer_info.renderPass = pass; framebuffer_info.attachmentCount = 1; framebuffer_info.pAttachments = &view;
			framebuffer_info.width = 16; framebuffer_info.height = 16; framebuffer_info.layers = 1;
			if (vkCreateFramebuffer(device, &framebuffer_info, 0, &framebuffer) != VK_SUCCESS || vkCreatePipelineLayout(device, &layout_info, 0, &layout) != VK_SUCCESS)
				return 88;
			{
				VkPipelineShaderStageCreateInfo stages[2] = {
					{VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO, 0, 0, VK_SHADER_STAGE_VERTEX_BIT, vertex, "main", 0},
					{VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO, 0, 0, VK_SHADER_STAGE_FRAGMENT_BIT, fragment, "main", 0}};
				VkPipelineVertexInputStateCreateInfo vertex_state = {VK_STRUCTURE_TYPE_PIPELINE_VERTEX_INPUT_STATE_CREATE_INFO, 0, 0, 0, 0, 0, 0};
				VkPipelineInputAssemblyStateCreateInfo assembly = {VK_STRUCTURE_TYPE_PIPELINE_INPUT_ASSEMBLY_STATE_CREATE_INFO, 0, 0, VK_PRIMITIVE_TOPOLOGY_TRIANGLE_LIST, VK_FALSE};
				VkViewport viewport = {0, 0, 16, 16, 0, 1};
				VkRect2D scissor = {{0, 0}, {16, 16}};
				VkPipelineViewportStateCreateInfo viewport_state = {VK_STRUCTURE_TYPE_PIPELINE_VIEWPORT_STATE_CREATE_INFO, 0, 0, 1, &viewport, 1, &scissor};
				VkPipelineRasterizationStateCreateInfo raster = {VK_STRUCTURE_TYPE_PIPELINE_RASTERIZATION_STATE_CREATE_INFO, 0, 0, VK_FALSE, VK_FALSE,
					VK_POLYGON_MODE_FILL, VK_CULL_MODE_NONE, VK_FRONT_FACE_COUNTER_CLOCKWISE, VK_FALSE, 0, 0, 0, 1.0f};
				VkPipelineMultisampleStateCreateInfo multisample = {VK_STRUCTURE_TYPE_PIPELINE_MULTISAMPLE_STATE_CREATE_INFO, 0, 0, VK_SAMPLE_COUNT_1_BIT, VK_FALSE, 0, 0, VK_FALSE, VK_FALSE};
				VkPipelineColorBlendAttachmentState blend_attachment = {VK_FALSE, VK_BLEND_FACTOR_ONE, VK_BLEND_FACTOR_ZERO, VK_BLEND_OP_ADD, VK_BLEND_FACTOR_ONE, VK_BLEND_FACTOR_ZERO, VK_BLEND_OP_ADD,
					VK_COLOR_COMPONENT_R_BIT | VK_COLOR_COMPONENT_G_BIT | VK_COLOR_COMPONENT_B_BIT | VK_COLOR_COMPONENT_A_BIT};
				VkPipelineColorBlendStateCreateInfo blend = {VK_STRUCTURE_TYPE_PIPELINE_COLOR_BLEND_STATE_CREATE_INFO, 0, 0, VK_FALSE, VK_LOGIC_OP_COPY, 1, &blend_attachment, {0, 0, 0, 0}};
				VkGraphicsPipelineCreateInfo pipeline_info = {VK_STRUCTURE_TYPE_GRAPHICS_PIPELINE_CREATE_INFO, 0, 0, 2, stages, &vertex_state, &assembly, 0, &viewport_state,
					&raster, &multisample, 0, &blend, 0, layout, pass, 0, VK_NULL_HANDLE, -1};
				if (vkCreateGraphicsPipelines(device, VK_NULL_HANDLE, 1, &pipeline_info, 0, &pipeline) != VK_SUCCESS || !pipeline)
					return 89;
			}
			if (vkCreateCommandPool(device, &pool_info, 0, &pool) != VK_SUCCESS)
				return 90;
			{
				VkCommandBufferAllocateInfo allocation = {VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO, 0, pool, VK_COMMAND_BUFFER_LEVEL_PRIMARY, 1};
				VkCommandBufferBeginInfo begin = {VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO, 0, VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT, 0};
				VkClearValue clear;
				VkRenderPassBeginInfo pass_begin;
				VkImageMemoryBarrier barrier = {VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER, 0, VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT, VK_ACCESS_TRANSFER_READ_BIT,
					VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL, VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL, VK_QUEUE_FAMILY_IGNORED, VK_QUEUE_FAMILY_IGNORED, image, range};
				VkSubmitInfo submit = {VK_STRUCTURE_TYPE_SUBMIT_INFO, 0, 0, 0, 0, 1, &command, 0, 0};
				clear.color.float32[0] = 0.0f; clear.color.float32[1] = 0.0f; clear.color.float32[2] = 1.0f; clear.color.float32[3] = 1.0f;
				pass_begin.sType = VK_STRUCTURE_TYPE_RENDER_PASS_BEGIN_INFO; pass_begin.pNext = 0; pass_begin.renderPass = pass; pass_begin.framebuffer = framebuffer;
				pass_begin.renderArea.offset.x = 0; pass_begin.renderArea.offset.y = 0; pass_begin.renderArea.extent.width = 16; pass_begin.renderArea.extent.height = 16;
				pass_begin.clearValueCount = 1; pass_begin.pClearValues = &clear;
				if (vkAllocateCommandBuffers(device, &allocation, &command) != VK_SUCCESS || vkBeginCommandBuffer(command, &begin) != VK_SUCCESS)
					return 91;
				vkCmdBeginRenderPass(command, &pass_begin, VK_SUBPASS_CONTENTS_INLINE);
				vkCmdBindPipeline(command, VK_PIPELINE_BIND_POINT_GRAPHICS, pipeline);
				vkCmdDraw(command, 3, 1, 0, 0);
				vkCmdEndRenderPass(command);
				vkCmdPipelineBarrier(command, VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT, VK_PIPELINE_STAGE_TRANSFER_BIT, 0, 0, 0, 0, 0, 1, &barrier);
				vkCmdCopyImageToBuffer(command, image, VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL, readback, 1, &copy);
				if (vkEndCommandBuffer(command) != VK_SUCCESS || vkQueueSubmit(first, 1, &submit, VK_NULL_HANDLE) != VK_SUCCESS || vkQueueWaitIdle(first) != VK_SUCCESS)
					return 92;
			}
			for (index = 0; index < 256; ++index)
				rendered[index] = pixels[index];
			/* Pixel (2,2) lies inside the triangle, pixel (14,14) outside it. */
			if (pixels[2 * 16 + 2] != 0xff0000ffu || pixels[14 * 16 + 14] != 0xffff0000u)
				return 93;
			vkUnmapMemory(device, readback_memory);
			vkDestroyCommandPool(device, pool, 0);
			vkDestroyPipeline(device, pipeline, 0);
			vkDestroyPipelineLayout(device, layout, 0);
			vkDestroyFramebuffer(device, framebuffer, 0);
			vkDestroyRenderPass(device, pass, 0);
			vkDestroyShaderModule(device, vertex, 0);
			vkDestroyShaderModule(device, fragment, 0);
			vkDestroyImageView(device, view, 0);
			vkDestroyImage(device, image, 0);
			vkDestroyBuffer(device, readback, 0);
			vkFreeMemory(device, image_memory, 0);
			vkFreeMemory(device, readback_memory, 0);
			graphics_workflow = 1;
		}
		{
			/* A quad from vertex and index buffers, sampling a 2x2 texture through a combined image sampler, with dynamic viewport and scissor. */
			static const float vertices[16] = {-1, -1, 0, 0,  1, -1, 1, 0,  1, 1, 1, 1,  -1, 1, 0, 1};
			static const uint16_t indices[6] = {0, 1, 2, 2, 3, 0};
			static const uint32_t texels[4] = {0xff0000ffu, 0xff00ff00u, 0xffff0000u, 0xffffffffu};
			VkImageCreateInfo target_info = {VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO, 0, 0, VK_IMAGE_TYPE_2D, VK_FORMAT_R8G8B8A8_UNORM, {16, 16, 1}, 1, 1,
				VK_SAMPLE_COUNT_1_BIT, VK_IMAGE_TILING_OPTIMAL, VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT | VK_IMAGE_USAGE_TRANSFER_SRC_BIT, VK_SHARING_MODE_EXCLUSIVE, 0, 0, VK_IMAGE_LAYOUT_UNDEFINED};
			VkImageCreateInfo texture_info = {VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO, 0, 0, VK_IMAGE_TYPE_2D, VK_FORMAT_R8G8B8A8_UNORM, {2, 2, 1}, 1, 1,
				VK_SAMPLE_COUNT_1_BIT, VK_IMAGE_TILING_OPTIMAL, VK_IMAGE_USAGE_SAMPLED_BIT | VK_IMAGE_USAGE_TRANSFER_DST_BIT, VK_SHARING_MODE_EXCLUSIVE, 0, 0, VK_IMAGE_LAYOUT_UNDEFINED};
			VkBufferCreateInfo vertex_buffer_info = {VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO, 0, 0, sizeof vertices, VK_BUFFER_USAGE_VERTEX_BUFFER_BIT, VK_SHARING_MODE_EXCLUSIVE, 0, 0};
			VkBufferCreateInfo index_buffer_info = {VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO, 0, 0, sizeof indices, VK_BUFFER_USAGE_INDEX_BUFFER_BIT, VK_SHARING_MODE_EXCLUSIVE, 0, 0};
			VkBufferCreateInfo staging_info = {VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO, 0, 0, sizeof texels, VK_BUFFER_USAGE_TRANSFER_SRC_BIT, VK_SHARING_MODE_EXCLUSIVE, 0, 0};
			VkBufferCreateInfo readback_info = {VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO, 0, 0, 1024, VK_BUFFER_USAGE_TRANSFER_DST_BIT, VK_SHARING_MODE_EXCLUSIVE, 0, 0};
			VkImage target = VK_NULL_HANDLE, texture = VK_NULL_HANDLE;
			VkImageView target_view = VK_NULL_HANDLE, texture_view = VK_NULL_HANDLE;
			VkBuffer vertex_buffer = VK_NULL_HANDLE, index_buffer = VK_NULL_HANDLE, staging = VK_NULL_HANDLE, readback = VK_NULL_HANDLE;
			VkDeviceMemory target_memory = VK_NULL_HANDLE, texture_memory = VK_NULL_HANDLE, vertex_memory = VK_NULL_HANDLE, index_memory = VK_NULL_HANDLE,
				staging_memory = VK_NULL_HANDLE, readback_memory = VK_NULL_HANDLE;
			VkMemoryRequirements requirements;
			uint32_t host_type = 0xffffffffu, index, type, *pixels = 0;
			void *mapped = 0;
			VkSamplerCreateInfo sampler_info = {VK_STRUCTURE_TYPE_SAMPLER_CREATE_INFO, 0, 0, VK_FILTER_NEAREST, VK_FILTER_NEAREST, VK_SAMPLER_MIPMAP_MODE_NEAREST,
				VK_SAMPLER_ADDRESS_MODE_CLAMP_TO_EDGE, VK_SAMPLER_ADDRESS_MODE_CLAMP_TO_EDGE, VK_SAMPLER_ADDRESS_MODE_CLAMP_TO_EDGE, 0, VK_FALSE, 1, VK_FALSE,
				VK_COMPARE_OP_ALWAYS, 0, 0, VK_BORDER_COLOR_FLOAT_TRANSPARENT_BLACK, VK_FALSE};
			VkSampler sampler = VK_NULL_HANDLE;
			VkImageSubresourceRange range = {VK_IMAGE_ASPECT_COLOR_BIT, 0, 1, 0, 1};
			VkDescriptorSetLayoutBinding binding = {0, VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER, 1, VK_SHADER_STAGE_FRAGMENT_BIT, 0};
			VkDescriptorSetLayoutCreateInfo set_layout_info = {VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO, 0, 0, 1, &binding};
			VkDescriptorSetLayout set_layout = VK_NULL_HANDLE;
			VkPipelineLayoutCreateInfo layout_info = {VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO, 0, 0, 1, &set_layout, 0, 0};
			VkPipelineLayout layout = VK_NULL_HANDLE;
			VkDescriptorPoolSize pool_size = {VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER, 1};
			VkDescriptorPoolCreateInfo descriptor_pool_info = {VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO, 0, 0, 1, 1, &pool_size};
			VkDescriptorPool descriptor_pool = VK_NULL_HANDLE;
			VkDescriptorSet set = VK_NULL_HANDLE;
			VkShaderModuleCreateInfo vertex_info = {VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO, 0, 0, sizeof quad_vertex_words, quad_vertex_words};
			VkShaderModuleCreateInfo fragment_info = {VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO, 0, 0, sizeof quad_fragment_words, quad_fragment_words};
			VkShaderModule vertex = VK_NULL_HANDLE, fragment = VK_NULL_HANDLE;
			VkAttachmentDescription attachment = {0, VK_FORMAT_R8G8B8A8_UNORM, VK_SAMPLE_COUNT_1_BIT, VK_ATTACHMENT_LOAD_OP_CLEAR, VK_ATTACHMENT_STORE_OP_STORE,
				VK_ATTACHMENT_LOAD_OP_DONT_CARE, VK_ATTACHMENT_STORE_OP_DONT_CARE, VK_IMAGE_LAYOUT_UNDEFINED, VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL};
			VkAttachmentReference reference = {0, VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL};
			VkSubpassDescription subpass = {0, VK_PIPELINE_BIND_POINT_GRAPHICS, 0, 0, 1, &reference, 0, 0, 0, 0};
			VkRenderPassCreateInfo pass_info = {VK_STRUCTURE_TYPE_RENDER_PASS_CREATE_INFO, 0, 0, 1, &attachment, 1, &subpass, 0, 0};
			VkRenderPass pass = VK_NULL_HANDLE;
			VkFramebufferCreateInfo framebuffer_info;
			VkFramebuffer framebuffer = VK_NULL_HANDLE;
			VkPipeline pipeline = VK_NULL_HANDLE;
			VkCommandPoolCreateInfo pool_info = {VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO, 0, 0, 0};
			VkCommandPool pool = VK_NULL_HANDLE;
			VkCommandBuffer command = VK_NULL_HANDLE;
			VkBufferImageCopy upload = {0, 0, 0, {VK_IMAGE_ASPECT_COLOR_BIT, 0, 0, 1}, {0, 0, 0}, {2, 2, 1}};
			VkBufferImageCopy download = {0, 0, 0, {VK_IMAGE_ASPECT_COLOR_BIT, 0, 0, 1}, {0, 0, 0}, {16, 16, 1}};
			VkDescriptorImageInfo image_info;
			/* One helper pattern for every buffer and image: find a memory type, allocate, bind. */
#define RAVEN_BUFFER(buffer, memory, info, flags) \
			do { VkMemoryRequirements need; uint32_t pick = 0xffffffffu, at; \
				if (vkCreateBuffer(device, &(info), 0, &(buffer)) != VK_SUCCESS) return 100; \
				vkGetBufferMemoryRequirements(device, buffer, &need); \
				for (at = 0; at < memory_properties.memoryTypeCount && pick == 0xffffffffu; ++at) \
					if ((need.memoryTypeBits & (1u << at)) && (memory_properties.memoryTypes[at].propertyFlags & (flags)) == (flags)) pick = at; \
				if (pick == 0xffffffffu) return 101; \
				{ VkMemoryAllocateInfo allocation = {VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO, 0, need.size, pick}; \
				  if (vkAllocateMemory(device, &allocation, 0, &(memory)) != VK_SUCCESS || vkBindBufferMemory(device, buffer, memory, 0) != VK_SUCCESS) return 102; } } while (0)
			{
				const uint32_t host_flags = VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT;
				RAVEN_BUFFER(vertex_buffer, vertex_memory, vertex_buffer_info, host_flags);
				RAVEN_BUFFER(index_buffer, index_memory, index_buffer_info, host_flags);
				RAVEN_BUFFER(staging, staging_memory, staging_info, host_flags);
				RAVEN_BUFFER(readback, readback_memory, readback_info, host_flags);
			}
			(void)host_type;
			if (vkMapMemory(device, vertex_memory, 0, VK_WHOLE_SIZE, 0, &mapped) != VK_SUCCESS)
				return 103;
			for (index = 0; index < 16; ++index)
				((float *)mapped)[index] = vertices[index];
			vkUnmapMemory(device, vertex_memory);
			if (vkMapMemory(device, index_memory, 0, VK_WHOLE_SIZE, 0, &mapped) != VK_SUCCESS)
				return 104;
			for (index = 0; index < 6; ++index)
				((uint16_t *)mapped)[index] = indices[index];
			vkUnmapMemory(device, index_memory);
			if (vkMapMemory(device, staging_memory, 0, VK_WHOLE_SIZE, 0, &mapped) != VK_SUCCESS)
				return 105;
			for (index = 0; index < 4; ++index)
				((uint32_t *)mapped)[index] = texels[index];
			vkUnmapMemory(device, staging_memory);
			if (vkMapMemory(device, readback_memory, 0, VK_WHOLE_SIZE, 0, (void **)&pixels) != VK_SUCCESS)
				return 106;
			for (index = 0; index < 256; ++index)
				pixels[index] = 0x11223344u;
			if (vkCreateImage(device, &target_info, 0, &target) != VK_SUCCESS || vkCreateImage(device, &texture_info, 0, &texture) != VK_SUCCESS)
				return 107;
#define RAVEN_IMAGE(image, memory) \
			do { uint32_t pick = 0xffffffffu, at; vkGetImageMemoryRequirements(device, image, &requirements); \
				for (at = 0; at < 32 && pick == 0xffffffffu; ++at) if (requirements.memoryTypeBits & (1u << at)) pick = at; \
				{ VkMemoryAllocateInfo allocation = {VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO, 0, requirements.size, pick}; \
				  if (pick == 0xffffffffu || vkAllocateMemory(device, &allocation, 0, &(memory)) != VK_SUCCESS || vkBindImageMemory(device, image, memory, 0) != VK_SUCCESS) return 108; } } while (0)
			RAVEN_IMAGE(target, target_memory);
			RAVEN_IMAGE(texture, texture_memory);
			(void)type;
			{
				VkImageViewCreateInfo view_info = {VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO, 0, 0, target, VK_IMAGE_VIEW_TYPE_2D, VK_FORMAT_R8G8B8A8_UNORM,
					{VK_COMPONENT_SWIZZLE_IDENTITY, VK_COMPONENT_SWIZZLE_IDENTITY, VK_COMPONENT_SWIZZLE_IDENTITY, VK_COMPONENT_SWIZZLE_IDENTITY}, range};
				if (vkCreateImageView(device, &view_info, 0, &target_view) != VK_SUCCESS)
					return 109;
				view_info.image = texture;
				if (vkCreateImageView(device, &view_info, 0, &texture_view) != VK_SUCCESS)
					return 110;
			}
			if (vkCreateSampler(device, &sampler_info, 0, &sampler) != VK_SUCCESS || !sampler)
				return 111;
			if (vkCreateDescriptorSetLayout(device, &set_layout_info, 0, &set_layout) != VK_SUCCESS || vkCreatePipelineLayout(device, &layout_info, 0, &layout) != VK_SUCCESS ||
				vkCreateDescriptorPool(device, &descriptor_pool_info, 0, &descriptor_pool) != VK_SUCCESS)
				return 112;
			{
				VkDescriptorSetAllocateInfo allocation = {VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO, 0, descriptor_pool, 1, &set_layout};
				VkWriteDescriptorSet write = {VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET, 0, 0, 0, 0, 1, VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER, &image_info, 0, 0};
				if (vkAllocateDescriptorSets(device, &allocation, &set) != VK_SUCCESS)
					return 113;
				image_info.sampler = sampler; image_info.imageView = texture_view; image_info.imageLayout = VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL;
				write.dstSet = set;
				vkUpdateDescriptorSets(device, 1, &write, 0, 0);
			}
			if (vkCreateShaderModule(device, &vertex_info, 0, &vertex) != VK_SUCCESS || vkCreateShaderModule(device, &fragment_info, 0, &fragment) != VK_SUCCESS ||
				vkCreateRenderPass(device, &pass_info, 0, &pass) != VK_SUCCESS)
				return 114;
			framebuffer_info.sType = VK_STRUCTURE_TYPE_FRAMEBUFFER_CREATE_INFO; framebuffer_info.pNext = 0; framebuffer_info.flags = 0;
			framebuffer_info.renderPass = pass; framebuffer_info.attachmentCount = 1; framebuffer_info.pAttachments = &target_view;
			framebuffer_info.width = 16; framebuffer_info.height = 16; framebuffer_info.layers = 1;
			if (vkCreateFramebuffer(device, &framebuffer_info, 0, &framebuffer) != VK_SUCCESS)
				return 115;
			{
				VkPipelineShaderStageCreateInfo stages[2] = {
					{VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO, 0, 0, VK_SHADER_STAGE_VERTEX_BIT, vertex, "main", 0},
					{VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO, 0, 0, VK_SHADER_STAGE_FRAGMENT_BIT, fragment, "main", 0}};
				VkVertexInputBindingDescription vertex_binding = {0, 16, VK_VERTEX_INPUT_RATE_VERTEX};
				VkVertexInputAttributeDescription attributes[2] = {{0, 0, VK_FORMAT_R32G32_SFLOAT, 0}, {1, 0, VK_FORMAT_R32G32_SFLOAT, 8}};
				VkPipelineVertexInputStateCreateInfo vertex_state = {VK_STRUCTURE_TYPE_PIPELINE_VERTEX_INPUT_STATE_CREATE_INFO, 0, 0, 1, &vertex_binding, 2, attributes};
				VkPipelineInputAssemblyStateCreateInfo assembly = {VK_STRUCTURE_TYPE_PIPELINE_INPUT_ASSEMBLY_STATE_CREATE_INFO, 0, 0, VK_PRIMITIVE_TOPOLOGY_TRIANGLE_LIST, VK_FALSE};
				VkPipelineViewportStateCreateInfo viewport_state = {VK_STRUCTURE_TYPE_PIPELINE_VIEWPORT_STATE_CREATE_INFO, 0, 0, 1, 0, 1, 0};
				VkPipelineRasterizationStateCreateInfo raster = {VK_STRUCTURE_TYPE_PIPELINE_RASTERIZATION_STATE_CREATE_INFO, 0, 0, VK_FALSE, VK_FALSE,
					VK_POLYGON_MODE_FILL, VK_CULL_MODE_NONE, VK_FRONT_FACE_COUNTER_CLOCKWISE, VK_FALSE, 0, 0, 0, 1.0f};
				VkPipelineMultisampleStateCreateInfo multisample = {VK_STRUCTURE_TYPE_PIPELINE_MULTISAMPLE_STATE_CREATE_INFO, 0, 0, VK_SAMPLE_COUNT_1_BIT, VK_FALSE, 0, 0, VK_FALSE, VK_FALSE};
				VkPipelineColorBlendAttachmentState blend_attachment = {VK_FALSE, VK_BLEND_FACTOR_ONE, VK_BLEND_FACTOR_ZERO, VK_BLEND_OP_ADD, VK_BLEND_FACTOR_ONE, VK_BLEND_FACTOR_ZERO, VK_BLEND_OP_ADD,
					VK_COLOR_COMPONENT_R_BIT | VK_COLOR_COMPONENT_G_BIT | VK_COLOR_COMPONENT_B_BIT | VK_COLOR_COMPONENT_A_BIT};
				VkPipelineColorBlendStateCreateInfo blend = {VK_STRUCTURE_TYPE_PIPELINE_COLOR_BLEND_STATE_CREATE_INFO, 0, 0, VK_FALSE, VK_LOGIC_OP_COPY, 1, &blend_attachment, {0, 0, 0, 0}};
				VkDynamicState dynamic_states[2] = {VK_DYNAMIC_STATE_VIEWPORT, VK_DYNAMIC_STATE_SCISSOR};
				VkPipelineDynamicStateCreateInfo dynamic = {VK_STRUCTURE_TYPE_PIPELINE_DYNAMIC_STATE_CREATE_INFO, 0, 0, 2, dynamic_states};
				VkGraphicsPipelineCreateInfo pipeline_info = {VK_STRUCTURE_TYPE_GRAPHICS_PIPELINE_CREATE_INFO, 0, 0, 2, stages, &vertex_state, &assembly, 0, &viewport_state,
					&raster, &multisample, 0, &blend, &dynamic, layout, pass, 0, VK_NULL_HANDLE, -1};
				if (vkCreateGraphicsPipelines(device, VK_NULL_HANDLE, 1, &pipeline_info, 0, &pipeline) != VK_SUCCESS || !pipeline)
					return 116;
			}
			if (vkCreateCommandPool(device, &pool_info, 0, &pool) != VK_SUCCESS)
				return 117;
			{
				VkCommandBufferAllocateInfo allocation = {VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO, 0, pool, VK_COMMAND_BUFFER_LEVEL_PRIMARY, 1};
				VkCommandBufferBeginInfo begin = {VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO, 0, VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT, 0};
				VkImageMemoryBarrier to_destination = {VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER, 0, 0, VK_ACCESS_TRANSFER_WRITE_BIT, VK_IMAGE_LAYOUT_UNDEFINED,
					VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL, VK_QUEUE_FAMILY_IGNORED, VK_QUEUE_FAMILY_IGNORED, texture, range};
				VkImageMemoryBarrier to_shader = {VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER, 0, VK_ACCESS_TRANSFER_WRITE_BIT, VK_ACCESS_SHADER_READ_BIT,
					VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL, VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL, VK_QUEUE_FAMILY_IGNORED, VK_QUEUE_FAMILY_IGNORED, texture, range};
				VkImageMemoryBarrier to_copy = {VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER, 0, VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT, VK_ACCESS_TRANSFER_READ_BIT,
					VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL, VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL, VK_QUEUE_FAMILY_IGNORED, VK_QUEUE_FAMILY_IGNORED, target, range};
				VkClearValue clear;
				VkRenderPassBeginInfo pass_begin;
				VkBuffer vertex_buffers[1];
				VkDeviceSize offsets[1] = {0};
				VkViewport viewport = {0, 0, 16, 16, 0, 1};
				VkRect2D scissor = {{0, 0}, {16, 16}};
				VkSubmitInfo submit = {VK_STRUCTURE_TYPE_SUBMIT_INFO, 0, 0, 0, 0, 1, &command, 0, 0};
				vertex_buffers[0] = vertex_buffer;
				clear.color.float32[0] = 0.0f; clear.color.float32[1] = 0.0f; clear.color.float32[2] = 0.0f; clear.color.float32[3] = 1.0f;
				pass_begin.sType = VK_STRUCTURE_TYPE_RENDER_PASS_BEGIN_INFO; pass_begin.pNext = 0; pass_begin.renderPass = pass; pass_begin.framebuffer = framebuffer;
				pass_begin.renderArea.offset.x = 0; pass_begin.renderArea.offset.y = 0; pass_begin.renderArea.extent.width = 16; pass_begin.renderArea.extent.height = 16;
				pass_begin.clearValueCount = 1; pass_begin.pClearValues = &clear;
				if (vkAllocateCommandBuffers(device, &allocation, &command) != VK_SUCCESS || vkBeginCommandBuffer(command, &begin) != VK_SUCCESS)
					return 118;
				vkCmdPipelineBarrier(command, VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT, VK_PIPELINE_STAGE_TRANSFER_BIT, 0, 0, 0, 0, 0, 1, &to_destination);
				vkCmdCopyBufferToImage(command, staging, texture, VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL, 1, &upload);
				vkCmdPipelineBarrier(command, VK_PIPELINE_STAGE_TRANSFER_BIT, VK_PIPELINE_STAGE_FRAGMENT_SHADER_BIT, 0, 0, 0, 0, 0, 1, &to_shader);
				vkCmdBeginRenderPass(command, &pass_begin, VK_SUBPASS_CONTENTS_INLINE);
				vkCmdBindPipeline(command, VK_PIPELINE_BIND_POINT_GRAPHICS, pipeline);
				vkCmdSetViewport(command, 0, 1, &viewport);
				vkCmdSetScissor(command, 0, 1, &scissor);
				vkCmdBindDescriptorSets(command, VK_PIPELINE_BIND_POINT_GRAPHICS, layout, 0, 1, &set, 0, 0);
				vkCmdBindVertexBuffers(command, 0, 1, vertex_buffers, offsets);
				vkCmdBindIndexBuffer(command, index_buffer, 0, VK_INDEX_TYPE_UINT16);
				vkCmdDrawIndexed(command, 6, 1, 0, 0, 0);
				vkCmdEndRenderPass(command);
				vkCmdPipelineBarrier(command, VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT, VK_PIPELINE_STAGE_TRANSFER_BIT, 0, 0, 0, 0, 0, 1, &to_copy);
				vkCmdCopyImageToBuffer(command, target, VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL, readback, 1, &download);
				if (vkEndCommandBuffer(command) != VK_SUCCESS || vkQueueSubmit(first, 1, &submit, VK_NULL_HANDLE) != VK_SUCCESS || vkQueueWaitIdle(first) != VK_SUCCESS)
					return 119;
			}
			for (index = 0; index < 256; ++index)
				textured[index] = pixels[index];
			if (pixels[4 * 16 + 4] != 0xff0000ffu || pixels[4 * 16 + 12] != 0xff00ff00u || pixels[12 * 16 + 4] != 0xffff0000u || pixels[12 * 16 + 12] != 0xffffffffu)
				return 120;
			vkUnmapMemory(device, readback_memory);
			vkDestroyCommandPool(device, pool, 0);
			vkDestroyPipeline(device, pipeline, 0);
			vkDestroyFramebuffer(device, framebuffer, 0);
			vkDestroyRenderPass(device, pass, 0);
			vkDestroyShaderModule(device, vertex, 0);
			vkDestroyShaderModule(device, fragment, 0);
			vkDestroyDescriptorPool(device, descriptor_pool, 0);
			vkDestroyPipelineLayout(device, layout, 0);
			vkDestroyDescriptorSetLayout(device, set_layout, 0);
			vkDestroySampler(device, sampler, 0);
			vkDestroyImageView(device, texture_view, 0);
			vkDestroyImageView(device, target_view, 0);
			vkDestroyImage(device, texture, 0);
			vkDestroyImage(device, target, 0);
			vkDestroyBuffer(device, vertex_buffer, 0);
			vkDestroyBuffer(device, index_buffer, 0);
			vkDestroyBuffer(device, staging, 0);
			vkDestroyBuffer(device, readback, 0);
			vkFreeMemory(device, target_memory, 0);
			vkFreeMemory(device, texture_memory, 0);
			vkFreeMemory(device, vertex_memory, 0);
			vkFreeMemory(device, index_memory, 0);
			vkFreeMemory(device, staging_memory, 0);
			vkFreeMemory(device, readback_memory, 0);
			textured_workflow = 1;
		}
		vkDestroyDevice(device, 0);
		vkDestroyDevice(VK_NULL_HANDLE, 0);
		device_workflow = 1;
	}
	vkDestroyInstance(instance, 0);
	vkDestroyInstance(VK_NULL_HANDLE, 0);
	return 0;
}

#include <vulkan/vulkan.h>
#include "vulkan_compute_spirv.h"

static VkPhysicalDevice physical[16];
static VkExtensionProperties offered[256];

unsigned int raven_entry(void)
{
	const char *extensions[] = {"VK_KHR_maintenance1", "VK_KHR_create_renderpass2",
		"VK_KHR_imageless_framebuffer", "VK_KHR_descriptor_update_template"};
	VkApplicationInfo application = {VK_STRUCTURE_TYPE_APPLICATION_INFO, 0, "Vulkan extension fixture", 1, 0, 0, VK_API_VERSION_1_2};
	VkInstanceCreateInfo instance_info = {VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO, 0, 0, &application};
	VkInstance instance = VK_NULL_HANDLE;
	uint32_t count = 16;
	if (vkCreateInstance(&instance_info, 0, &instance) != VK_SUCCESS ||
		vkEnumeratePhysicalDevices(instance, &count, physical) != VK_SUCCESS || !count) return 1;
	count = 256;
	if (vkEnumerateDeviceExtensionProperties(physical[0], 0, &count, offered) != VK_SUCCESS) return 2;
	for (uint32_t e = 0; e < 4; ++e) {
		uint32_t found = 0;
		for (uint32_t i = 0; i < count; ++i) {
			uint32_t j = 0;
			while (extensions[e][j] && extensions[e][j] == offered[i].extensionName[j]) ++j;
			if (!extensions[e][j] && !offered[i].extensionName[j]) found = offered[i].specVersion;
		}
		if (!found) return 3 + e;
	}
	VkPhysicalDeviceImagelessFramebufferFeatures imageless = {VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_IMAGELESS_FRAMEBUFFER_FEATURES};
	VkPhysicalDeviceFeatures2 features = {VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FEATURES_2, &imageless};
	vkGetPhysicalDeviceFeatures2(physical[0], &features);
	if (!imageless.imagelessFramebuffer) return 7;
	float priority = 1;
	VkDeviceQueueCreateInfo queue_info = {VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO, 0, 0, 0, 1, &priority};
	VkDeviceCreateInfo device_info = {VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO, &imageless, 0, 1, &queue_info, 0, 0, 4, extensions, 0};
	VkDevice device = VK_NULL_HANDLE;
	if (vkCreateDevice(physical[0], &device_info, 0, &device) != VK_SUCCESS) return 8;
	PFN_vkTrimCommandPoolKHR trim = (PFN_vkTrimCommandPoolKHR)vkGetDeviceProcAddr(device, "vkTrimCommandPoolKHR");
	PFN_vkCreateRenderPass2KHR create_pass = (PFN_vkCreateRenderPass2KHR)vkGetDeviceProcAddr(device, "vkCreateRenderPass2KHR");
	PFN_vkCmdBeginRenderPass2KHR begin_pass = (PFN_vkCmdBeginRenderPass2KHR)vkGetDeviceProcAddr(device, "vkCmdBeginRenderPass2KHR");
	PFN_vkCmdNextSubpass2KHR next_pass = (PFN_vkCmdNextSubpass2KHR)vkGetDeviceProcAddr(device, "vkCmdNextSubpass2KHR");
	PFN_vkCmdEndRenderPass2KHR end_pass = (PFN_vkCmdEndRenderPass2KHR)vkGetDeviceProcAddr(device, "vkCmdEndRenderPass2KHR");
	PFN_vkCreateDescriptorUpdateTemplateKHR create_template = (PFN_vkCreateDescriptorUpdateTemplateKHR)vkGetDeviceProcAddr(device, "vkCreateDescriptorUpdateTemplateKHR");
	PFN_vkUpdateDescriptorSetWithTemplateKHR update_template = (PFN_vkUpdateDescriptorSetWithTemplateKHR)vkGetDeviceProcAddr(device, "vkUpdateDescriptorSetWithTemplateKHR");
	PFN_vkDestroyDescriptorUpdateTemplateKHR destroy_template = (PFN_vkDestroyDescriptorUpdateTemplateKHR)vkGetDeviceProcAddr(device, "vkDestroyDescriptorUpdateTemplateKHR");
	if (!trim || !create_pass || !begin_pass || !next_pass || !end_pass || !create_template || !update_template || !destroy_template) return 9;
	VkBufferCreateInfo buffer_info = {VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO, 0, 0, 8192,
		VK_BUFFER_USAGE_STORAGE_BUFFER_BIT, VK_SHARING_MODE_EXCLUSIVE};
	VkBuffer buffer = VK_NULL_HANDLE;
	if (vkCreateBuffer(device, &buffer_info, 0, &buffer) != VK_SUCCESS) return 10;
	VkMemoryRequirements requirements;
	VkPhysicalDeviceMemoryProperties memory_properties;
	vkGetBufferMemoryRequirements(device, buffer, &requirements);
	vkGetPhysicalDeviceMemoryProperties(physical[0], &memory_properties);
	uint32_t memory_type = UINT32_MAX;
	for (uint32_t i = 0; i < memory_properties.memoryTypeCount; ++i)
		if ((requirements.memoryTypeBits & (1u << i)) && (memory_properties.memoryTypes[i].propertyFlags &
			(VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT)) ==
			(VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT)) { memory_type = i; break; }
	if (memory_type == UINT32_MAX) return 11;
	VkMemoryAllocateInfo allocation = {VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO, 0, requirements.size, memory_type};
	VkDeviceMemory memory = VK_NULL_HANDLE;
	uint32_t *data = 0;
	if (vkAllocateMemory(device, &allocation, 0, &memory) != VK_SUCCESS || vkBindBufferMemory(device, buffer, memory, 0) != VK_SUCCESS ||
		vkMapMemory(device, memory, 0, VK_WHOLE_SIZE, 0, (void **)&data) != VK_SUCCESS) return 12;
	for (uint32_t i = 0; i < 64; ++i) { data[i] = i + 10; data[1024 + i] = 0xdeadbeef; }
	VkDescriptorSetLayoutBinding bindings[2] = {{0, VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, 1, VK_SHADER_STAGE_COMPUTE_BIT, 0},
		{1, VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, 1, VK_SHADER_STAGE_COMPUTE_BIT, 0}};
	VkDescriptorSetLayoutCreateInfo set_info = {VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO, 0, 0, 2, bindings};
	VkDescriptorSetLayout set_layout = VK_NULL_HANDLE;
	if (vkCreateDescriptorSetLayout(device, &set_info, 0, &set_layout) != VK_SUCCESS) return 13;
	VkDescriptorPoolSize pool_size = {VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, 2};
	VkDescriptorPoolCreateInfo descriptor_pool_info = {VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO, 0, 0, 1, 1, &pool_size};
	VkDescriptorPool descriptor_pool = VK_NULL_HANDLE;
	VkDescriptorSet set = VK_NULL_HANDLE;
	if (vkCreateDescriptorPool(device, &descriptor_pool_info, 0, &descriptor_pool) != VK_SUCCESS) return 14;
	VkDescriptorSetAllocateInfo set_allocate = {VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO, 0, descriptor_pool, 1, &set_layout};
	if (vkAllocateDescriptorSets(device, &set_allocate, &set) != VK_SUCCESS) return 15;
	VkDescriptorBufferInfo buffers[2] = {{buffer, 0, 256}, {buffer, 4096, 256}};
	VkDescriptorUpdateTemplateEntry entries[2] = {{0, 0, 1, VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, 0, sizeof buffers[0]},
		{1, 0, 1, VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, sizeof buffers[0], sizeof buffers[0]}};
	VkDescriptorUpdateTemplateCreateInfo template_info = {VK_STRUCTURE_TYPE_DESCRIPTOR_UPDATE_TEMPLATE_CREATE_INFO, 0, 0, 2, entries,
		VK_DESCRIPTOR_UPDATE_TEMPLATE_TYPE_DESCRIPTOR_SET, set_layout};
	VkDescriptorUpdateTemplate descriptor_template = VK_NULL_HANDLE;
	if (create_template(device, &template_info, 0, &descriptor_template) != VK_SUCCESS) return 16;
	update_template(device, set, descriptor_template, buffers);
	VkPushConstantRange push_range = {VK_SHADER_STAGE_COMPUTE_BIT, 0, 4};
	VkPipelineLayoutCreateInfo layout_info = {VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO, 0, 0, 1, &set_layout, 1, &push_range};
	VkPipelineLayout layout = VK_NULL_HANDLE;
	VkShaderModuleCreateInfo shader_info = {VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO, 0, 0, sizeof compute_words, compute_words};
	VkShaderModule shader = VK_NULL_HANDLE;
	if (vkCreatePipelineLayout(device, &layout_info, 0, &layout) != VK_SUCCESS || vkCreateShaderModule(device, &shader_info, 0, &shader) != VK_SUCCESS) return 17;
	VkComputePipelineCreateInfo pipeline_info = {VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO, 0, 0,
		{VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO, 0, 0, VK_SHADER_STAGE_COMPUTE_BIT, shader, "main", 0}, layout, VK_NULL_HANDLE, -1};
	VkPipeline pipeline = VK_NULL_HANDLE;
	if (vkCreateComputePipelines(device, VK_NULL_HANDLE, 1, &pipeline_info, 0, &pipeline) != VK_SUCCESS) return 18;
	VkSubpassDescription2 subpasses[2] = {{VK_STRUCTURE_TYPE_SUBPASS_DESCRIPTION_2, 0, 0, VK_PIPELINE_BIND_POINT_GRAPHICS},
		{VK_STRUCTURE_TYPE_SUBPASS_DESCRIPTION_2, 0, 0, VK_PIPELINE_BIND_POINT_GRAPHICS}};
	VkRenderPassCreateInfo2 pass_info = {VK_STRUCTURE_TYPE_RENDER_PASS_CREATE_INFO_2, 0, 0, 0, 0, 2, subpasses};
	VkRenderPass pass = VK_NULL_HANDLE;
	if (create_pass(device, &pass_info, 0, &pass) != VK_SUCCESS) return 19;
	VkFramebufferCreateInfo framebuffer_info = {VK_STRUCTURE_TYPE_FRAMEBUFFER_CREATE_INFO, 0, VK_FRAMEBUFFER_CREATE_IMAGELESS_BIT,
		pass, 0, 0, 16, 16, 1};
	VkFramebuffer framebuffer = VK_NULL_HANDLE;
	if (vkCreateFramebuffer(device, &framebuffer_info, 0, &framebuffer) != VK_SUCCESS) return 20;
	VkCommandPoolCreateInfo pool_info = {VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO, 0, 0, 0};
	VkCommandPool pool = VK_NULL_HANDLE;
	if (vkCreateCommandPool(device, &pool_info, 0, &pool) != VK_SUCCESS) return 21;
	VkCommandBufferAllocateInfo command_info = {VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO, 0, pool, VK_COMMAND_BUFFER_LEVEL_PRIMARY, 1};
	VkCommandBuffer command = VK_NULL_HANDLE;
	VkCommandBufferBeginInfo begin = {VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO, 0, VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT, 0};
	if (vkAllocateCommandBuffers(device, &command_info, &command) != VK_SUCCESS || vkBeginCommandBuffer(command, &begin) != VK_SUCCESS) return 22;
	VkRenderPassBeginInfo pass_begin = {VK_STRUCTURE_TYPE_RENDER_PASS_BEGIN_INFO, 0, pass, framebuffer, {{0, 0}, {16, 16}}};
	VkSubpassBeginInfo subpass_begin = {VK_STRUCTURE_TYPE_SUBPASS_BEGIN_INFO, 0, VK_SUBPASS_CONTENTS_INLINE};
	VkSubpassEndInfo subpass_end = {VK_STRUCTURE_TYPE_SUBPASS_END_INFO};
	begin_pass(command, &pass_begin, &subpass_begin);
	next_pass(command, &subpass_begin, &subpass_end);
	end_pass(command, &subpass_end);
	vkCmdBindPipeline(command, VK_PIPELINE_BIND_POINT_COMPUTE, pipeline);
	vkCmdBindDescriptorSets(command, VK_PIPELINE_BIND_POINT_COMPUTE, layout, 0, 1, &set, 0, 0);
	uint32_t scale = 3;
	vkCmdPushConstants(command, layout, VK_SHADER_STAGE_COMPUTE_BIT, 0, 4, &scale);
	vkCmdDispatch(command, 1, 1, 1);
	VkMemoryBarrier barrier = {VK_STRUCTURE_TYPE_MEMORY_BARRIER, 0, VK_ACCESS_SHADER_WRITE_BIT, VK_ACCESS_HOST_READ_BIT};
	vkCmdPipelineBarrier(command, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, VK_PIPELINE_STAGE_HOST_BIT, 0, 1, &barrier, 0, 0, 0, 0);
	VkQueue queue = VK_NULL_HANDLE;
	vkGetDeviceQueue(device, 0, 0, &queue);
	VkSubmitInfo submit = {VK_STRUCTURE_TYPE_SUBMIT_INFO, 0, 0, 0, 0, 1, &command, 0, 0};
	if (vkEndCommandBuffer(command) != VK_SUCCESS || vkQueueSubmit(queue, 1, &submit, VK_NULL_HANDLE) != VK_SUCCESS || vkQueueWaitIdle(queue) != VK_SUCCESS) return 23;
	for (uint32_t i = 0; i < 64; ++i)
		if (data[1024 + i] != (i + 10) * scale + i) return 24;
	vkFreeCommandBuffers(device, pool, 1, &command);
	trim(device, pool, 0);
	vkDestroyCommandPool(device, pool, 0);
	vkDestroyFramebuffer(device, framebuffer, 0);
	vkDestroyRenderPass(device, pass, 0);
	vkDestroyPipeline(device, pipeline, 0);
	vkDestroyShaderModule(device, shader, 0);
	vkDestroyPipelineLayout(device, layout, 0);
	destroy_template(device, descriptor_template, 0);
	vkDestroyDescriptorPool(device, descriptor_pool, 0);
	vkDestroyDescriptorSetLayout(device, set_layout, 0);
	vkUnmapMemory(device, memory);
	vkDestroyBuffer(device, buffer, 0);
	vkFreeMemory(device, memory, 0);
	vkDestroyDevice(device, 0);
	vkDestroyInstance(instance, 0);
	return 0;
}

#include <vulkan/vulkan.h>
#include "vulkan_compute_spirv.h"

static VkExtensionProperties extensions[256];
static VkPhysicalDevice physical[16];

unsigned int raven_entry(void)
{
	VkApplicationInfo application = {VK_STRUCTURE_TYPE_APPLICATION_INFO, 0, "Descriptor buffer fixture", 1, 0, 0, VK_API_VERSION_1_3};
	VkInstanceCreateInfo instance_info = {VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO, 0, 0, &application, 0, 0, 0, 0};
	VkInstance instance = VK_NULL_HANDLE;
	uint32_t count = 16;
	if (vkCreateInstance(&instance_info, 0, &instance) != VK_SUCCESS ||
		vkEnumeratePhysicalDevices(instance, &count, physical) != VK_SUCCESS || !count)
		return 1;
	count = 256;
	if (vkEnumerateDeviceExtensionProperties(physical[0], 0, &count, extensions) != VK_SUCCESS)
		return 2;
	uint32_t offered = 0;
	const char *extension = "VK_EXT_descriptor_buffer";
	for (uint32_t i = 0; i < count; ++i) {
		uint32_t j = 0;
		while (extension[j] && extension[j] == extensions[i].extensionName[j]) ++j;
		if (!extension[j] && !extensions[i].extensionName[j]) offered = 1;
	}
	if (!offered) return 3;
	VkPhysicalDeviceDescriptorBufferFeaturesEXT descriptor_features = {VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DESCRIPTOR_BUFFER_FEATURES_EXT};
	VkPhysicalDeviceVulkan12Features features12 = {VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VULKAN_1_2_FEATURES, &descriptor_features};
	VkPhysicalDeviceFeatures2 features = {VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FEATURES_2, &features12};
	vkGetPhysicalDeviceFeatures2(physical[0], &features);
	if (!descriptor_features.descriptorBuffer || !features12.bufferDeviceAddress) return 4;
	VkPhysicalDeviceDescriptorBufferPropertiesEXT descriptor_properties = {VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DESCRIPTOR_BUFFER_PROPERTIES_EXT};
	VkPhysicalDeviceProperties2 properties = {VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PROPERTIES_2, &descriptor_properties};
	vkGetPhysicalDeviceProperties2(physical[0], &properties);
	float priority = 1.0f;
	VkDeviceQueueCreateInfo queue_info = {VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO, 0, 0, 0, 1, &priority};
	VkPhysicalDeviceBufferDeviceAddressFeatures address_features = {VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_BUFFER_DEVICE_ADDRESS_FEATURES, 0, VK_TRUE};
	VkPhysicalDeviceDescriptorBufferFeaturesEXT enabled = {VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DESCRIPTOR_BUFFER_FEATURES_EXT, &address_features, VK_TRUE};
	VkDeviceCreateInfo device_info = {VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO, &enabled, 0, 1, &queue_info, 0, 0, 1, &extension, 0};
	VkDevice device = VK_NULL_HANDLE;
	if (vkCreateDevice(physical[0], &device_info, 0, &device) != VK_SUCCESS) return 5;
	const char *commands[] = {"vkGetDescriptorEXT", "vkGetDescriptorSetLayoutSizeEXT", "vkGetDescriptorSetLayoutBindingOffsetEXT",
		"vkCmdBindDescriptorBuffersEXT", "vkCmdSetDescriptorBufferOffsetsEXT", "vkCmdBindDescriptorBufferEmbeddedSamplersEXT",
		"vkGetBufferOpaqueCaptureDescriptorDataEXT", "vkGetImageOpaqueCaptureDescriptorDataEXT",
		"vkGetImageViewOpaqueCaptureDescriptorDataEXT", "vkGetSamplerOpaqueCaptureDescriptorDataEXT"};
	for (uint32_t i = 0; i < sizeof commands / sizeof commands[0]; ++i)
		if (!vkGetDeviceProcAddr(device, commands[i])) return 6;
	VkBufferCreateInfo buffer_info = {VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO, 0, 0, 8192,
		VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_SHADER_DEVICE_ADDRESS_BIT | VK_BUFFER_USAGE_RESOURCE_DESCRIPTOR_BUFFER_BIT_EXT,
		VK_SHARING_MODE_EXCLUSIVE, 0, 0};
	VkBuffer buffer = VK_NULL_HANDLE;
	VkMemoryRequirements requirements;
	VkPhysicalDeviceMemoryProperties memory_properties;
	if (vkCreateBuffer(device, &buffer_info, 0, &buffer) != VK_SUCCESS) return 7;
	vkGetBufferMemoryRequirements(device, buffer, &requirements);
	vkGetPhysicalDeviceMemoryProperties(physical[0], &memory_properties);
	uint32_t memory_type = UINT32_MAX;
	for (uint32_t i = 0; i < memory_properties.memoryTypeCount; ++i)
		if ((requirements.memoryTypeBits & (1u << i)) && (memory_properties.memoryTypes[i].propertyFlags &
			(VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT)) ==
			(VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT)) { memory_type = i; break; }
	if (memory_type == UINT32_MAX) return 8;
	VkMemoryAllocateFlagsInfo flags = {VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_FLAGS_INFO, 0, VK_MEMORY_ALLOCATE_DEVICE_ADDRESS_BIT, 0};
	VkMemoryAllocateInfo allocation = {VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO, &flags, requirements.size, memory_type};
	VkDeviceMemory memory = VK_NULL_HANDLE;
	uint8_t *data = 0;
	if (vkAllocateMemory(device, &allocation, 0, &memory) != VK_SUCCESS || vkBindBufferMemory(device, buffer, memory, 0) != VK_SUCCESS ||
		vkMapMemory(device, memory, 0, VK_WHOLE_SIZE, 0, (void **)&data) != VK_SUCCESS) return 9;
	VkBufferDeviceAddressInfo address_info = {VK_STRUCTURE_TYPE_BUFFER_DEVICE_ADDRESS_INFO, 0, buffer};
	VkDeviceAddress address = vkGetBufferDeviceAddress(device, &address_info);
	if (!address) return 10;
	uint32_t *input = (uint32_t *)(data + 4096), *output = (uint32_t *)(data + 4352);
	for (uint32_t i = 0; i < 64; ++i) { input[i] = i + 10; output[i] = 0xdeadbeef; }
	VkDescriptorSetLayoutBinding bindings[2] = {{0, VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, 1, VK_SHADER_STAGE_COMPUTE_BIT, 0},
		{1, VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, 1, VK_SHADER_STAGE_COMPUTE_BIT, 0}};
	VkDescriptorSetLayoutCreateInfo set_info = {VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO, 0,
		VK_DESCRIPTOR_SET_LAYOUT_CREATE_DESCRIPTOR_BUFFER_BIT_EXT, 2, bindings};
	VkDescriptorSetLayout set = VK_NULL_HANDLE;
	if (vkCreateDescriptorSetLayout(device, &set_info, 0, &set) != VK_SUCCESS) return 11;
	VkDeviceSize size = 0, offsets[2] = {0, 0};
	vkGetDescriptorSetLayoutSizeEXT(device, set, &size);
	vkGetDescriptorSetLayoutBindingOffsetEXT(device, set, 0, &offsets[0]);
	vkGetDescriptorSetLayoutBindingOffsetEXT(device, set, 1, &offsets[1]);
	if (!size || size > 4096 || !descriptor_properties.storageBufferDescriptorSize) return 12;
	for (uint32_t i = 0; i < 2; ++i) {
		VkDescriptorAddressInfoEXT source = {VK_STRUCTURE_TYPE_DESCRIPTOR_ADDRESS_INFO_EXT, 0, address + 4096 + i * 256, 256, VK_FORMAT_UNDEFINED};
		VkDescriptorGetInfoEXT get = {VK_STRUCTURE_TYPE_DESCRIPTOR_GET_INFO_EXT, 0, VK_DESCRIPTOR_TYPE_STORAGE_BUFFER};
		get.data.accelerationStructure = UINT64_MAX;
		get.data.pStorageBuffer = &source;
		if (offsets[i] + descriptor_properties.storageBufferDescriptorSize > size) return 13;
		vkGetDescriptorEXT(device, &get, descriptor_properties.storageBufferDescriptorSize, data + offsets[i]);
	}
	VkPushConstantRange push_range = {VK_SHADER_STAGE_COMPUTE_BIT, 0, 4};
	VkPipelineLayoutCreateInfo layout_info = {VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO, 0, 0, 1, &set, 1, &push_range};
	VkPipelineLayout layout = VK_NULL_HANDLE;
	VkShaderModuleCreateInfo shader_info = {VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO, 0, 0, sizeof compute_words, compute_words};
	VkShaderModule shader = VK_NULL_HANDLE;
	if (vkCreatePipelineLayout(device, &layout_info, 0, &layout) != VK_SUCCESS || vkCreateShaderModule(device, &shader_info, 0, &shader) != VK_SUCCESS) return 14;
	VkComputePipelineCreateInfo pipeline_info = {VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO, 0, VK_PIPELINE_CREATE_DESCRIPTOR_BUFFER_BIT_EXT,
		{VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO, 0, 0, VK_SHADER_STAGE_COMPUTE_BIT, shader, "main", 0}, layout, VK_NULL_HANDLE, -1};
	VkPipeline pipeline = VK_NULL_HANDLE;
	if (vkCreateComputePipelines(device, VK_NULL_HANDLE, 1, &pipeline_info, 0, &pipeline) != VK_SUCCESS) return 15;
	VkCommandPoolCreateInfo pool_info = {VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO, 0, 0, 0};
	VkCommandPool pool = VK_NULL_HANDLE;
	if (vkCreateCommandPool(device, &pool_info, 0, &pool) != VK_SUCCESS) return 16;
	VkCommandBufferAllocateInfo command_info = {VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO, 0, pool, VK_COMMAND_BUFFER_LEVEL_PRIMARY, 1};
	VkCommandBuffer command = VK_NULL_HANDLE;
	VkCommandBufferBeginInfo begin = {VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO, 0, VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT, 0};
	if (vkAllocateCommandBuffers(device, &command_info, &command) != VK_SUCCESS || vkBeginCommandBuffer(command, &begin) != VK_SUCCESS) return 17;
	vkCmdBindPipeline(command, VK_PIPELINE_BIND_POINT_COMPUTE, pipeline);
	VkDescriptorBufferBindingInfoEXT binding = {VK_STRUCTURE_TYPE_DESCRIPTOR_BUFFER_BINDING_INFO_EXT, 0, address, VK_BUFFER_USAGE_RESOURCE_DESCRIPTOR_BUFFER_BIT_EXT};
	vkCmdBindDescriptorBuffersEXT(command, 1, &binding);
	uint32_t buffer_index = 0, scale = 3;
	VkDeviceSize offset = 0;
	vkCmdSetDescriptorBufferOffsetsEXT(command, VK_PIPELINE_BIND_POINT_COMPUTE, layout, 0, 1, &buffer_index, &offset);
	vkCmdPushConstants(command, layout, VK_SHADER_STAGE_COMPUTE_BIT, 0, 4, &scale);
	vkCmdDispatch(command, 1, 1, 1);
	VkQueue queue = VK_NULL_HANDLE;
	vkGetDeviceQueue(device, 0, 0, &queue);
	VkSubmitInfo submit = {VK_STRUCTURE_TYPE_SUBMIT_INFO, 0, 0, 0, 0, 1, &command, 0, 0};
	if (vkEndCommandBuffer(command) != VK_SUCCESS || vkQueueSubmit(queue, 1, &submit, VK_NULL_HANDLE) != VK_SUCCESS || vkQueueWaitIdle(queue) != VK_SUCCESS) return 18;
	for (uint32_t i = 0; i < 64; ++i)
		if (output[i] != (i + 10) * scale + i) return 19;
	vkDestroyCommandPool(device, pool, 0);
	vkDestroyPipeline(device, pipeline, 0);
	vkDestroyShaderModule(device, shader, 0);
	vkDestroyPipelineLayout(device, layout, 0);
	vkDestroyDescriptorSetLayout(device, set, 0);
	vkUnmapMemory(device, memory);
	vkDestroyBuffer(device, buffer, 0);
	vkFreeMemory(device, memory, 0);
	vkDestroyDevice(device, 0);
	vkDestroyInstance(instance, 0);
	return 0;
}

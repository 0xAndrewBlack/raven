#include "vulkan_bridge.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <stdexcept>

namespace raven {

// Names are kept in byte order because the guest provider binary searches its export table.
static constexpr std::array<std::string_view, 16> names{
	"vkAllocateDescriptorSets", "vkCmdBindDescriptorSets", "vkCmdBindPipeline", "vkCmdDispatch", "vkCmdPushConstants",
	"vkCreateComputePipelines", "vkCreateDescriptorPool", "vkCreateDescriptorSetLayout", "vkCreatePipelineLayout",
	"vkCreateShaderModule", "vkDestroyDescriptorPool", "vkDestroyDescriptorSetLayout", "vkDestroyPipeline",
	"vkDestroyPipelineLayout", "vkDestroyShaderModule", "vkUpdateDescriptorSets"
};

std::span<const std::string_view> vulkan_compute_names() { return names; }

template<typename H> static H as_handle(uint64_t value) { return reinterpret_cast<H>(value); }

void VulkanBridge::destroy_object(const VkDevice &device, const Object &object)
{
	switch (object.kind) {
	case Kind::shader: vkDestroyShaderModule(device, as_handle<VkShaderModule>(object.handle), nullptr); break;
	case Kind::set_layout: vkDestroyDescriptorSetLayout(device, as_handle<VkDescriptorSetLayout>(object.handle), nullptr); break;
	case Kind::pipeline_layout: vkDestroyPipelineLayout(device, as_handle<VkPipelineLayout>(object.handle), nullptr); break;
	case Kind::pipeline: vkDestroyPipeline(device, as_handle<VkPipeline>(object.handle), nullptr); break;
	case Kind::pool: vkDestroyDescriptorPool(device, as_handle<VkDescriptorPool>(object.handle), nullptr); break;
	case Kind::set: break;
	}
}

bool VulkanBridge::dispatch_compute(std::string_view name)
{
	if (std::find(names.begin(), names.end(), name) == names.end())
		return false;
	static const std::map<std::string_view, size_t, std::less<>> words{
		{"vkAllocateDescriptorSets", 3}, {"vkCmdBindDescriptorSets", 8}, {"vkCmdBindPipeline", 3}, {"vkCmdDispatch", 4},
		{"vkCmdPushConstants", 6}, {"vkCreateComputePipelines", 6}, {"vkCreateDescriptorPool", 4}, {"vkCreateDescriptorSetLayout", 4},
		{"vkCreatePipelineLayout", 4}, {"vkCreateShaderModule", 4}, {"vkDestroyDescriptorPool", 3}, {"vkDestroyDescriptorSetLayout", 3},
		{"vkDestroyPipeline", 3}, {"vkDestroyPipelineLayout", 3}, {"vkDestroyShaderModule", 3}, {"vkUpdateDescriptorSets", 5}};
	auto a = process.api_arguments(words.at(name));
	// A 32-bit argument leaves the upper half of its register or stack slot undefined, so those are narrowed before use.
	static const std::map<std::string_view, std::vector<size_t>, std::less<>> narrow{
		{"vkCmdBindPipeline", {1}}, {"vkCmdBindDescriptorSets", {1, 3, 4, 6}}, {"vkCmdDispatch", {1, 2, 3}}, {"vkCmdPushConstants", {2, 3, 4}},
		{"vkCreateComputePipelines", {2}}, {"vkUpdateDescriptorSets", {1, 3}}};
	if (const auto found = narrow.find(name); found != narrow.end())
		for (const auto index : found->second)
			a[index] = uint32_t(a[index]);
	const auto device_of = [&](uint64_t token) -> Device & {
		const auto found = devices.find(token);
		if (found == devices.end())
			throw std::runtime_error("invalid Vulkan device handle");
		return found->second;
	};
	const auto no_allocator = [&](uint64_t pointer) {
		if (pointer)
			throw std::runtime_error("Vulkan guest allocation callbacks are not implemented");
	};
	const auto object_of = [&](uint64_t token, uint64_t device, Kind kind) -> Object & {
		const auto found = objects.find(token);
		if (found == objects.end() || found->second.device != device || found->second.kind != kind)
			throw std::runtime_error("invalid Vulkan object handle");
		return found->second;
	};
	const auto command_of = [&](uint64_t token) -> CommandBuffer & {
		const auto found = command_buffers.find(token);
		if (found == command_buffers.end())
			throw std::runtime_error("invalid Vulkan command buffer handle");
		return found->second;
	};
	const auto buffer_of = [&](uint64_t token, uint64_t device) -> Buffer & {
		const auto found = buffers.find(token);
		if (found == buffers.end() || found->second.device != device)
			throw std::runtime_error("invalid Vulkan buffer handle");
		return found->second;
	};
	// Copies a counted array of guest records into host storage.
	const auto records = [&]<typename T>(uint64_t address, uint64_t count, uint64_t limit) {
		if (count > limit || (count && !address))
			throw std::runtime_error("unsupported Vulkan record count");
		std::vector<T> result(count);
		for (uint64_t index = 0; index < count; ++index)
			result[index] = load<T>(address + index * sizeof(T));
		return result;
	};
	const auto create = [&](Kind kind, uint64_t device, uint64_t out, uint64_t host, VkResult status) -> uint32_t {
		if (status == VK_SUCCESS) {
			const auto token = next_handle++;
			objects.emplace(token, Object{host, device, kind});
			store(out, token);
		}
		return static_cast<uint32_t>(status);
	};
	uint64_t result = 0;
	if (name == "vkCreateShaderModule") {
		auto &device = device_of(a[0]);
		no_allocator(a[2]);
		auto info = load<VkShaderModuleCreateInfo>(a[1]);
		if (info.sType != VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO || info.pNext || info.flags || !info.codeSize || info.codeSize % 4 ||
			info.codeSize > (1U << 20) || !info.pCode)
			throw std::runtime_error("unsupported Vulkan shader module create info");
		const auto bytes = process.read_memory(reinterpret_cast<uint64_t>(info.pCode), info.codeSize);
		std::vector<uint32_t> code(info.codeSize / 4);
		std::memcpy(code.data(), bytes.data(), bytes.size());
		if (code[0] != 0x07230203U)
			throw std::runtime_error("Vulkan shader code is not SPIR-V");
		info.pCode = code.data();
		check_writable(a[3], 8);
		VkShaderModule module = VK_NULL_HANDLE;
		const auto status = vkCreateShaderModule(device.handle, &info, nullptr, &module);
		result = create(Kind::shader, a[0], a[3], reinterpret_cast<uint64_t>(module), status);
	} else if (name == "vkCreateDescriptorSetLayout") {
		auto &device = device_of(a[0]);
		no_allocator(a[2]);
		auto info = load<VkDescriptorSetLayoutCreateInfo>(a[1]);
		if (info.sType != VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO || info.pNext || info.flags)
			throw std::runtime_error("unsupported Vulkan descriptor set layout create info");
		auto bindings = records.template operator()<VkDescriptorSetLayoutBinding>(reinterpret_cast<uint64_t>(info.pBindings), info.bindingCount, 64);
		for (const auto &binding : bindings)
			if (binding.pImmutableSamplers)
				throw std::runtime_error("Vulkan immutable samplers are not implemented");
		info.pBindings = bindings.data();
		check_writable(a[3], 8);
		VkDescriptorSetLayout layout = VK_NULL_HANDLE;
		const auto status = vkCreateDescriptorSetLayout(device.handle, &info, nullptr, &layout);
		result = create(Kind::set_layout, a[0], a[3], reinterpret_cast<uint64_t>(layout), status);
	} else if (name == "vkCreatePipelineLayout") {
		auto &device = device_of(a[0]);
		no_allocator(a[2]);
		auto info = load<VkPipelineLayoutCreateInfo>(a[1]);
		if (info.sType != VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO || info.pNext || info.flags)
			throw std::runtime_error("unsupported Vulkan pipeline layout create info");
		std::vector<VkDescriptorSetLayout> layouts;
		const auto tokens = records.template operator()<uint64_t>(reinterpret_cast<uint64_t>(info.pSetLayouts), info.setLayoutCount, 16);
		for (const auto token : tokens)
			layouts.push_back(as_handle<VkDescriptorSetLayout>(object_of(token, a[0], Kind::set_layout).handle));
		auto ranges = records.template operator()<VkPushConstantRange>(reinterpret_cast<uint64_t>(info.pPushConstantRanges), info.pushConstantRangeCount, 16);
		info.pSetLayouts = layouts.data();
		info.pPushConstantRanges = ranges.data();
		check_writable(a[3], 8);
		VkPipelineLayout layout = VK_NULL_HANDLE;
		const auto status = vkCreatePipelineLayout(device.handle, &info, nullptr, &layout);
		result = create(Kind::pipeline_layout, a[0], a[3], reinterpret_cast<uint64_t>(layout), status);
	} else if (name == "vkCreateComputePipelines") {
		auto &device = device_of(a[0]);
		no_allocator(a[4]);
		if (a[1] || a[2] != 1)
			throw std::runtime_error("Vulkan pipeline caches and batched pipeline creation are not implemented");
		auto info = load<VkComputePipelineCreateInfo>(a[3]);
		if (info.sType != VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO || info.pNext || info.flags || info.basePipelineHandle ||
			info.stage.sType != VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO || info.stage.pNext || info.stage.flags ||
			info.stage.stage != VK_SHADER_STAGE_COMPUTE_BIT || info.stage.pSpecializationInfo || !info.stage.pName)
			throw std::runtime_error("unsupported Vulkan compute pipeline create info");
		std::string entry;
		for (size_t index = 0; index < 256; ++index) {
			const auto byte = process.read_memory(reinterpret_cast<uint64_t>(info.stage.pName) + index, 1)[0];
			if (!byte)
				break;
			entry.push_back(static_cast<char>(byte));
			if (index == 255)
				throw std::runtime_error("Vulkan shader entry point name is too long");
		}
		info.stage.module = as_handle<VkShaderModule>(object_of(reinterpret_cast<uint64_t>(info.stage.module), a[0], Kind::shader).handle);
		info.stage.pName = entry.c_str();
		info.layout = as_handle<VkPipelineLayout>(object_of(reinterpret_cast<uint64_t>(info.layout), a[0], Kind::pipeline_layout).handle);
		check_writable(a[5], 8);
		VkPipeline pipeline = VK_NULL_HANDLE;
		const auto status = vkCreateComputePipelines(device.handle, VK_NULL_HANDLE, 1, &info, nullptr, &pipeline);
		result = create(Kind::pipeline, a[0], a[5], reinterpret_cast<uint64_t>(pipeline), status);
	} else if (name == "vkCreateDescriptorPool") {
		auto &device = device_of(a[0]);
		no_allocator(a[2]);
		auto info = load<VkDescriptorPoolCreateInfo>(a[1]);
		if (info.sType != VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO || info.pNext || info.flags || !info.maxSets || info.maxSets > 256)
			throw std::runtime_error("unsupported Vulkan descriptor pool create info");
		auto sizes = records.template operator()<VkDescriptorPoolSize>(reinterpret_cast<uint64_t>(info.pPoolSizes), info.poolSizeCount, 16);
		info.pPoolSizes = sizes.data();
		check_writable(a[3], 8);
		VkDescriptorPool pool = VK_NULL_HANDLE;
		const auto status = vkCreateDescriptorPool(device.handle, &info, nullptr, &pool);
		result = create(Kind::pool, a[0], a[3], reinterpret_cast<uint64_t>(pool), status);
	} else if (name == "vkAllocateDescriptorSets") {
		auto &device = device_of(a[0]);
		auto info = load<VkDescriptorSetAllocateInfo>(a[1]);
		if (info.sType != VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO || info.pNext || !info.descriptorSetCount || info.descriptorSetCount > 16)
			throw std::runtime_error("unsupported Vulkan descriptor set allocate info");
		const auto pool_token = reinterpret_cast<uint64_t>(info.descriptorPool);
		info.descriptorPool = as_handle<VkDescriptorPool>(object_of(pool_token, a[0], Kind::pool).handle);
		std::vector<VkDescriptorSetLayout> layouts;
		const auto tokens = records.template operator()<uint64_t>(reinterpret_cast<uint64_t>(info.pSetLayouts), info.descriptorSetCount, 16);
		for (const auto token : tokens)
			layouts.push_back(as_handle<VkDescriptorSetLayout>(object_of(token, a[0], Kind::set_layout).handle));
		info.pSetLayouts = layouts.data();
		check_writable(a[2], size_t(info.descriptorSetCount) * 8);
		std::vector<VkDescriptorSet> sets(info.descriptorSetCount);
		const auto status = vkAllocateDescriptorSets(device.handle, &info, sets.data());
		result = static_cast<uint32_t>(status);
		if (status == VK_SUCCESS)
			for (size_t index = 0; index < sets.size(); ++index) {
				const auto token = next_handle++;
				objects.emplace(token, Object{reinterpret_cast<uint64_t>(sets[index]), a[0], Kind::set, pool_token});
				store(a[2] + index * 8, token);
			}
	} else if (name == "vkUpdateDescriptorSets") {
		auto &device = device_of(a[0]);
		if (a[3])
			throw std::runtime_error("Vulkan descriptor copies are not implemented");
		auto writes = records.template operator()<VkWriteDescriptorSet>(a[2], a[1], 16);
		std::vector<std::vector<VkDescriptorBufferInfo>> buffer_infos(writes.size());
		for (size_t index = 0; index < writes.size(); ++index) {
			auto &write = writes[index];
			if (write.sType != VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET || write.pNext || write.pImageInfo || write.pTexelBufferView ||
				!write.pBufferInfo || !write.descriptorCount || write.descriptorCount > 16 ||
				(write.descriptorType != VK_DESCRIPTOR_TYPE_STORAGE_BUFFER && write.descriptorType != VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER))
				throw std::runtime_error("unsupported Vulkan descriptor write");
			write.dstSet = as_handle<VkDescriptorSet>(object_of(reinterpret_cast<uint64_t>(write.dstSet), a[0], Kind::set).handle);
			buffer_infos[index] = records.template operator()<VkDescriptorBufferInfo>(reinterpret_cast<uint64_t>(write.pBufferInfo), write.descriptorCount, 16);
			for (auto &info : buffer_infos[index])
				info.buffer = buffer_of(reinterpret_cast<uint64_t>(info.buffer), a[0]).handle;
			write.pBufferInfo = buffer_infos[index].data();
		}
		vkUpdateDescriptorSets(device.handle, uint32_t(writes.size()), writes.data(), 0, nullptr);
	} else if (name == "vkDestroyShaderModule" || name == "vkDestroyDescriptorSetLayout" || name == "vkDestroyPipelineLayout" ||
		name == "vkDestroyPipeline" || name == "vkDestroyDescriptorPool") {
		auto &device = device_of(a[0]);
		no_allocator(a[2]);
		if (a[1]) {
			const auto kind = name == "vkDestroyShaderModule" ? Kind::shader : name == "vkDestroyDescriptorSetLayout" ? Kind::set_layout :
				name == "vkDestroyPipelineLayout" ? Kind::pipeline_layout : name == "vkDestroyPipeline" ? Kind::pipeline : Kind::pool;
			const auto object = object_of(a[1], a[0], kind);
			destroy_object(device.handle, object);
			objects.erase(a[1]);
			if (kind == Kind::pool)
				std::erase_if(objects, [&](const auto &item) { return item.second.kind == Kind::set && item.second.parent == a[1]; });
		}
	} else if (name == "vkCmdBindPipeline") {
		const auto &command = command_of(a[0]);
		if (a[1] != VK_PIPELINE_BIND_POINT_COMPUTE)
			throw std::runtime_error("only compute pipelines are implemented");
		vkCmdBindPipeline(command.handle, VK_PIPELINE_BIND_POINT_COMPUTE, as_handle<VkPipeline>(object_of(a[2], command.device, Kind::pipeline).handle));
	} else if (name == "vkCmdBindDescriptorSets") {
		const auto &command = command_of(a[0]);
		if (a[1] != VK_PIPELINE_BIND_POINT_COMPUTE || a[6])
			throw std::runtime_error("only compute descriptor sets without dynamic offsets are implemented");
		const auto layout = as_handle<VkPipelineLayout>(object_of(a[2], command.device, Kind::pipeline_layout).handle);
		std::vector<VkDescriptorSet> sets;
		for (const auto token : records.template operator()<uint64_t>(a[5], a[4], 16))
			sets.push_back(as_handle<VkDescriptorSet>(object_of(token, command.device, Kind::set).handle));
		vkCmdBindDescriptorSets(command.handle, VK_PIPELINE_BIND_POINT_COMPUTE, layout, uint32_t(a[3]), uint32_t(sets.size()), sets.data(), 0, nullptr);
	} else if (name == "vkCmdDispatch") {
		const auto &command = command_of(a[0]);
		vkCmdDispatch(command.handle, uint32_t(a[1]), uint32_t(a[2]), uint32_t(a[3]));
	} else if (name == "vkCmdPushConstants") {
		const auto &command = command_of(a[0]);
		const auto layout = as_handle<VkPipelineLayout>(object_of(a[1], command.device, Kind::pipeline_layout).handle);
		if (!a[4] || a[4] > 128 || !a[5])
			throw std::runtime_error("unsupported Vulkan push constant range");
		const auto bytes = process.read_memory(a[5], size_t(a[4]));
		vkCmdPushConstants(command.handle, layout, uint32_t(a[2]), uint32_t(a[3]), uint32_t(a[4]), bytes.data());
	}
	process.return_api(result);
	return true;
}

}

#include "vulkan_bridge.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <stdexcept>

namespace raven {

// Names are kept in byte order because the guest provider binary searches its export table.
static constexpr std::array<std::string_view, 15> names{
	"vkCmdBeginRenderPass", "vkCmdBindIndexBuffer", "vkCmdBindVertexBuffers", "vkCmdDraw", "vkCmdDrawIndexed", "vkCmdEndRenderPass",
	"vkCmdSetScissor", "vkCmdSetViewport", "vkCreateFramebuffer", "vkCreateGraphicsPipelines", "vkCreateRenderPass", "vkCreateSampler",
	"vkDestroyFramebuffer", "vkDestroyRenderPass", "vkDestroySampler"
};

std::span<const std::string_view> vulkan_graphics_names() { return names; }

template<typename H> static H as_handle(uint64_t value) { return reinterpret_cast<H>(value); }

bool VulkanBridge::dispatch_graphics(std::string_view name)
{
	if (std::find(names.begin(), names.end(), name) == names.end())
		return false;
	static const std::map<std::string_view, size_t, std::less<>> words{
		{"vkCmdBeginRenderPass", 3}, {"vkCmdBindIndexBuffer", 4}, {"vkCmdBindVertexBuffers", 5}, {"vkCmdDraw", 5}, {"vkCmdDrawIndexed", 6},
		{"vkCmdEndRenderPass", 1}, {"vkCmdSetScissor", 4}, {"vkCmdSetViewport", 4}, {"vkCreateFramebuffer", 4}, {"vkCreateGraphicsPipelines", 6},
		{"vkCreateRenderPass", 4}, {"vkCreateSampler", 4}, {"vkDestroyFramebuffer", 3}, {"vkDestroyRenderPass", 3}, {"vkDestroySampler", 3}};
	auto a = process.api_arguments(words.at(name));
	// A 32-bit argument leaves the upper half of its register or stack slot undefined, so those are narrowed before use.
	static const std::map<std::string_view, std::vector<size_t>, std::less<>> narrow{
		{"vkCmdBeginRenderPass", {2}}, {"vkCmdBindIndexBuffer", {3}}, {"vkCmdBindVertexBuffers", {1, 2}}, {"vkCmdDraw", {1, 2, 3, 4}},
		{"vkCmdDrawIndexed", {1, 2, 3, 4, 5}}, {"vkCmdSetScissor", {1, 2}}, {"vkCmdSetViewport", {1, 2}}, {"vkCreateGraphicsPipelines", {2}}};
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
	const auto buffer_of = [&](uint64_t token, uint64_t device) -> Buffer & {
		const auto found = buffers.find(token);
		if (found == buffers.end() || found->second.device != device)
			throw std::runtime_error("invalid Vulkan buffer handle");
		return found->second;
	};
	const auto pointer = [](const void *value) { return reinterpret_cast<uint64_t>(value); };
	uint64_t result = 0;
	if (name == "vkCreateRenderPass") {
		auto &device = device_of(a[0]);
		no_allocator(a[2]);
		auto info = load<VkRenderPassCreateInfo>(a[1]);
		if (info.sType != VK_STRUCTURE_TYPE_RENDER_PASS_CREATE_INFO || info.pNext || info.flags || !info.subpassCount)
			throw std::runtime_error("unsupported Vulkan render pass create info");
		auto attachments = records.template operator()<VkAttachmentDescription>(pointer(info.pAttachments), info.attachmentCount, 16);
		auto subpasses = records.template operator()<VkSubpassDescription>(pointer(info.pSubpasses), info.subpassCount, 8);
		auto dependencies = records.template operator()<VkSubpassDependency>(pointer(info.pDependencies), info.dependencyCount, 16);
		// Every subpass carries pointers to its attachment references; each array is copied into host storage.
		std::vector<std::vector<VkAttachmentReference>> inputs(subpasses.size()), colors(subpasses.size()), resolves(subpasses.size());
		std::vector<VkAttachmentReference> depths(subpasses.size());
		std::vector<std::vector<uint32_t>> preserves(subpasses.size());
		for (size_t index = 0; index < subpasses.size(); ++index) {
			auto &subpass = subpasses[index];
			if (subpass.flags)
				throw std::runtime_error("unsupported Vulkan subpass flags");
			inputs[index] = records.template operator()<VkAttachmentReference>(pointer(subpass.pInputAttachments), subpass.inputAttachmentCount, 8);
			colors[index] = records.template operator()<VkAttachmentReference>(pointer(subpass.pColorAttachments), subpass.colorAttachmentCount, 8);
			if (subpass.pResolveAttachments)
				resolves[index] = records.template operator()<VkAttachmentReference>(pointer(subpass.pResolveAttachments), subpass.colorAttachmentCount, 8);
			if (subpass.pDepthStencilAttachment)
				depths[index] = load<VkAttachmentReference>(pointer(subpass.pDepthStencilAttachment));
			preserves[index] = records.template operator()<uint32_t>(pointer(subpass.pPreserveAttachments), subpass.preserveAttachmentCount, 16);
			subpass.pInputAttachments = inputs[index].data();
			subpass.pColorAttachments = colors[index].data();
			subpass.pResolveAttachments = resolves[index].empty() ? nullptr : resolves[index].data();
			subpass.pDepthStencilAttachment = subpass.pDepthStencilAttachment ? &depths[index] : nullptr;
			subpass.pPreserveAttachments = preserves[index].data();
		}
		info.pAttachments = attachments.data();
		info.pSubpasses = subpasses.data();
		info.pDependencies = dependencies.data();
		check_writable(a[3], 8);
		VkRenderPass pass = VK_NULL_HANDLE;
		const auto status = vkCreateRenderPass(device.handle, &info, nullptr, &pass);
		result = create(Kind::render_pass, a[0], a[3], reinterpret_cast<uint64_t>(pass), status);
	} else if (name == "vkCreateFramebuffer") {
		auto &device = device_of(a[0]);
		no_allocator(a[2]);
		auto info = load<VkFramebufferCreateInfo>(a[1]);
		if (info.sType != VK_STRUCTURE_TYPE_FRAMEBUFFER_CREATE_INFO || info.pNext || info.flags || info.width > 16384 || info.height > 16384)
			throw std::runtime_error("unsupported Vulkan framebuffer create info");
		info.renderPass = as_handle<VkRenderPass>(object_of(pointer(info.renderPass), a[0], Kind::render_pass).handle);
		std::vector<VkImageView> views;
		for (const auto token : records.template operator()<uint64_t>(pointer(info.pAttachments), info.attachmentCount, 8))
			views.push_back(as_handle<VkImageView>(object_of(token, a[0], Kind::image_view).handle));
		info.pAttachments = views.data();
		check_writable(a[3], 8);
		VkFramebuffer framebuffer = VK_NULL_HANDLE;
		const auto status = vkCreateFramebuffer(device.handle, &info, nullptr, &framebuffer);
		result = create(Kind::framebuffer, a[0], a[3], reinterpret_cast<uint64_t>(framebuffer), status);
	} else if (name == "vkCreateGraphicsPipelines") {
		auto &device = device_of(a[0]);
		no_allocator(a[4]);
		if (a[1] || a[2] != 1)
			throw std::runtime_error("Vulkan pipeline caches and batched pipeline creation are not implemented");
		auto info = load<VkGraphicsPipelineCreateInfo>(a[3]);
		if (info.sType != VK_STRUCTURE_TYPE_GRAPHICS_PIPELINE_CREATE_INFO || info.pNext || info.flags || info.basePipelineHandle ||
			info.pTessellationState || !info.stageCount || !info.pVertexInputState || !info.pInputAssemblyState || !info.pRasterizationState)
			throw std::runtime_error("unsupported Vulkan graphics pipeline create info");
		auto stages = records.template operator()<VkPipelineShaderStageCreateInfo>(pointer(info.pStages), info.stageCount, 5);
		std::vector<std::string> entries(stages.size());
		for (size_t index = 0; index < stages.size(); ++index) {
			auto &stage = stages[index];
			if (stage.sType != VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO || stage.pNext || stage.flags || stage.pSpecializationInfo || !stage.pName)
				throw std::runtime_error("unsupported Vulkan shader stage");
			for (size_t at = 0; at < 256; ++at) {
				const auto byte = process.read_memory(pointer(stage.pName) + at, 1)[0];
				if (!byte)
					break;
				entries[index].push_back(static_cast<char>(byte));
				if (at == 255)
					throw std::runtime_error("Vulkan shader entry point name is too long");
			}
			stage.module = as_handle<VkShaderModule>(object_of(pointer(stage.module), a[0], Kind::shader).handle);
			stage.pName = entries[index].c_str();
		}
		auto vertex = load<VkPipelineVertexInputStateCreateInfo>(pointer(info.pVertexInputState));
		auto bindings = records.template operator()<VkVertexInputBindingDescription>(pointer(vertex.pVertexBindingDescriptions), vertex.vertexBindingDescriptionCount, 16);
		auto attributes = records.template operator()<VkVertexInputAttributeDescription>(pointer(vertex.pVertexAttributeDescriptions), vertex.vertexAttributeDescriptionCount, 32);
		vertex.pVertexBindingDescriptions = bindings.data();
		vertex.pVertexAttributeDescriptions = attributes.data();
		auto assembly = load<VkPipelineInputAssemblyStateCreateInfo>(pointer(info.pInputAssemblyState));
		auto rasterization = load<VkPipelineRasterizationStateCreateInfo>(pointer(info.pRasterizationState));
		VkPipelineViewportStateCreateInfo viewport{};
		std::vector<VkViewport> viewports;
		std::vector<VkRect2D> scissors;
		if (info.pViewportState) {
			viewport = load<VkPipelineViewportStateCreateInfo>(pointer(info.pViewportState));
			viewports = records.template operator()<VkViewport>(pointer(viewport.pViewports), viewport.pViewports ? viewport.viewportCount : 0, 16);
			scissors = records.template operator()<VkRect2D>(pointer(viewport.pScissors), viewport.pScissors ? viewport.scissorCount : 0, 16);
			viewport.pViewports = viewports.empty() ? nullptr : viewports.data();
			viewport.pScissors = scissors.empty() ? nullptr : scissors.data();
			info.pViewportState = &viewport;
		}
		VkPipelineMultisampleStateCreateInfo multisample{};
		std::vector<VkSampleMask> masks;
		if (info.pMultisampleState) {
			multisample = load<VkPipelineMultisampleStateCreateInfo>(pointer(info.pMultisampleState));
			if (multisample.pSampleMask) {
				masks = records.template operator()<VkSampleMask>(pointer(multisample.pSampleMask), (multisample.rasterizationSamples + 31) / 32, 2);
				multisample.pSampleMask = masks.data();
			}
			info.pMultisampleState = &multisample;
		}
		VkPipelineDepthStencilStateCreateInfo depth{};
		if (info.pDepthStencilState) {
			depth = load<VkPipelineDepthStencilStateCreateInfo>(pointer(info.pDepthStencilState));
			info.pDepthStencilState = &depth;
		}
		VkPipelineColorBlendStateCreateInfo blend{};
		std::vector<VkPipelineColorBlendAttachmentState> blend_attachments;
		if (info.pColorBlendState) {
			blend = load<VkPipelineColorBlendStateCreateInfo>(pointer(info.pColorBlendState));
			blend_attachments = records.template operator()<VkPipelineColorBlendAttachmentState>(pointer(blend.pAttachments), blend.attachmentCount, 8);
			blend.pAttachments = blend_attachments.data();
			info.pColorBlendState = &blend;
		}
		VkPipelineDynamicStateCreateInfo dynamic{};
		std::vector<VkDynamicState> dynamic_states;
		if (info.pDynamicState) {
			dynamic = load<VkPipelineDynamicStateCreateInfo>(pointer(info.pDynamicState));
			dynamic_states = records.template operator()<VkDynamicState>(pointer(dynamic.pDynamicStates), dynamic.dynamicStateCount, 16);
			dynamic.pDynamicStates = dynamic_states.data();
			info.pDynamicState = &dynamic;
		}
		info.pStages = stages.data();
		info.pVertexInputState = &vertex;
		info.pInputAssemblyState = &assembly;
		info.pRasterizationState = &rasterization;
		info.layout = as_handle<VkPipelineLayout>(object_of(pointer(info.layout), a[0], Kind::pipeline_layout).handle);
		info.renderPass = as_handle<VkRenderPass>(object_of(pointer(info.renderPass), a[0], Kind::render_pass).handle);
		check_writable(a[5], 8);
		VkPipeline pipeline = VK_NULL_HANDLE;
		const auto status = vkCreateGraphicsPipelines(device.handle, VK_NULL_HANDLE, 1, &info, nullptr, &pipeline);
		result = create(Kind::pipeline, a[0], a[5], reinterpret_cast<uint64_t>(pipeline), status);
	} else if (name == "vkCreateSampler") {
		auto &device = device_of(a[0]);
		no_allocator(a[2]);
		auto info = load<VkSamplerCreateInfo>(a[1]);
		if (info.sType != VK_STRUCTURE_TYPE_SAMPLER_CREATE_INFO || info.pNext || info.flags)
			throw std::runtime_error("unsupported Vulkan sampler create info");
		check_writable(a[3], 8);
		VkSampler sampler = VK_NULL_HANDLE;
		const auto status = vkCreateSampler(device.handle, &info, nullptr, &sampler);
		result = create(Kind::sampler, a[0], a[3], reinterpret_cast<uint64_t>(sampler), status);
	} else if (name == "vkCmdBindVertexBuffers") {
		const auto &command = command_of(a[0]);
		if (!a[2] || a[2] > 16)
			throw std::runtime_error("unsupported Vulkan vertex buffer count");
		std::vector<VkBuffer> handles;
		for (const auto token : records.template operator()<uint64_t>(a[3], a[2], 16))
			handles.push_back(buffer_of(token, command.device).handle);
		const auto offsets = records.template operator()<VkDeviceSize>(a[4], a[2], 16);
		vkCmdBindVertexBuffers(command.handle, uint32_t(a[1]), uint32_t(handles.size()), handles.data(), offsets.data());
	} else if (name == "vkCmdBindIndexBuffer") {
		const auto &command = command_of(a[0]);
		vkCmdBindIndexBuffer(command.handle, buffer_of(a[1], command.device).handle, a[2], VkIndexType(a[3]));
	} else if (name == "vkCmdDrawIndexed") {
		vkCmdDrawIndexed(command_of(a[0]).handle, uint32_t(a[1]), uint32_t(a[2]), uint32_t(a[3]), int32_t(a[4]), uint32_t(a[5]));
	} else if (name == "vkCmdSetViewport") {
		const auto &command = command_of(a[0]);
		const auto viewports = records.template operator()<VkViewport>(a[3], a[2], 16);
		if (viewports.empty())
			throw std::runtime_error("unsupported Vulkan viewport count");
		vkCmdSetViewport(command.handle, uint32_t(a[1]), uint32_t(viewports.size()), viewports.data());
	} else if (name == "vkCmdSetScissor") {
		const auto &command = command_of(a[0]);
		const auto scissors = records.template operator()<VkRect2D>(a[3], a[2], 16);
		if (scissors.empty())
			throw std::runtime_error("unsupported Vulkan scissor count");
		vkCmdSetScissor(command.handle, uint32_t(a[1]), uint32_t(scissors.size()), scissors.data());
	} else if (name == "vkDestroyRenderPass" || name == "vkDestroyFramebuffer" || name == "vkDestroySampler") {
		auto &device = device_of(a[0]);
		no_allocator(a[2]);
		if (a[1]) {
			const auto kind = name == "vkDestroyRenderPass" ? Kind::render_pass : name == "vkDestroySampler" ? Kind::sampler : Kind::framebuffer;
			const auto object = object_of(a[1], a[0], kind);
			destroy_object(device.handle, object);
			objects.erase(a[1]);
		}
	} else if (name == "vkCmdBeginRenderPass") {
		const auto &command = command_of(a[0]);
		if (a[2] != VK_SUBPASS_CONTENTS_INLINE)
			throw std::runtime_error("only inline render pass contents are implemented");
		auto info = load<VkRenderPassBeginInfo>(a[1]);
		if (info.sType != VK_STRUCTURE_TYPE_RENDER_PASS_BEGIN_INFO || info.pNext)
			throw std::runtime_error("unsupported Vulkan render pass begin info");
		info.renderPass = as_handle<VkRenderPass>(object_of(pointer(info.renderPass), command.device, Kind::render_pass).handle);
		info.framebuffer = as_handle<VkFramebuffer>(object_of(pointer(info.framebuffer), command.device, Kind::framebuffer).handle);
		auto clears = records.template operator()<VkClearValue>(pointer(info.pClearValues), info.clearValueCount, 8);
		info.pClearValues = clears.data();
		vkCmdBeginRenderPass(command.handle, &info, VK_SUBPASS_CONTENTS_INLINE);
	} else if (name == "vkCmdEndRenderPass") {
		vkCmdEndRenderPass(command_of(a[0]).handle);
	} else if (name == "vkCmdDraw") {
		vkCmdDraw(command_of(a[0]).handle, uint32_t(a[1]), uint32_t(a[2]), uint32_t(a[3]), uint32_t(a[4]));
	}
	process.return_api(result);
	return true;
}

}

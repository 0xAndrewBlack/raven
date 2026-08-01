#include "vulkan_bridge.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <stdexcept>

namespace raven {

// Names are kept in byte order because the guest provider binary searches its export table.
static constexpr std::array<std::string_view, 13> names{
	"vkBindImageMemory", "vkCmdCopyBufferToImage", "vkCmdCopyImageToBuffer", "vkCmdPipelineBarrier", "vkCreateImage",
	"vkCreateImageView", "vkCreateSemaphore", "vkDestroyImage", "vkDestroyImageView", "vkDestroySemaphore", "vkGetFenceStatus",
	"vkGetImageMemoryRequirements", "vkGetImageSubresourceLayout"
};

std::span<const std::string_view> vulkan_image_names() { return names; }

template<typename H> static H as_handle(uint64_t value) { return reinterpret_cast<H>(value); }

bool VulkanBridge::dispatch_images(std::string_view name)
{
	const auto exported = vulkan_image_names();
	if (std::find(exported.begin(), exported.end(), name) == exported.end())
		return false;
	static const std::map<std::string_view, size_t, std::less<>> words{
		{"vkBindImageMemory", 4}, {"vkCmdCopyBufferToImage", 6}, {"vkCmdCopyImageToBuffer", 6}, {"vkCmdPipelineBarrier", 10},
		{"vkCreateImage", 4}, {"vkCreateImageView", 4}, {"vkCreateSemaphore", 4}, {"vkDestroyImage", 3}, {"vkDestroyImageView", 3},
		{"vkDestroySemaphore", 3}, {"vkGetFenceStatus", 2}, {"vkGetImageMemoryRequirements", 3}, {"vkGetImageSubresourceLayout", 4}};
	auto a = process.api_arguments(words.at(name));
	// A 32-bit argument leaves the upper half of its register or stack slot undefined, so those are narrowed before use.
	static const std::map<std::string_view, std::vector<size_t>, std::less<>> narrow{
		{"vkCmdCopyBufferToImage", {3, 4}}, {"vkCmdCopyImageToBuffer", {2, 4}},
		{"vkCmdPipelineBarrier", {1, 2, 3, 4, 6, 8}}};
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
	if (name == "vkCreateImage") {
		auto &device = device_of(a[0]);
		no_allocator(a[2]);
		auto info = load<VkImageCreateInfo>(a[1]);
		if (info.sType != VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO || info.pNext || info.flags || info.sharingMode != VK_SHARING_MODE_EXCLUSIVE ||
			info.queueFamilyIndexCount || info.pQueueFamilyIndices || info.extent.width > 8192 || info.extent.height > 8192 || info.extent.depth > 256)
			throw std::runtime_error("unsupported Vulkan image create info");
		check_writable(a[3], 8);
		VkImage image = VK_NULL_HANDLE;
		const auto status = vkCreateImage(device.handle, &info, nullptr, &image);
		result = create(Kind::image, a[0], a[3], reinterpret_cast<uint64_t>(image), status);
	} else if (name == "vkGetImageMemoryRequirements") {
		auto &device = device_of(a[0]);
		const auto &image = object_of(a[1], a[0], Kind::image);
		check_writable(a[2], sizeof(VkMemoryRequirements));
		VkMemoryRequirements requirements{};
		vkGetImageMemoryRequirements(device.handle, as_handle<VkImage>(image.handle), &requirements);
		store(a[2], requirements);
	} else if (name == "vkGetImageSubresourceLayout") {
		auto &device = device_of(a[0]);
		const auto &image = object_of(a[1], a[0], Kind::image);
		check_writable(a[3], sizeof(VkSubresourceLayout));
		const auto subresource = load<VkImageSubresource>(a[2]);
		VkSubresourceLayout layout{};
		vkGetImageSubresourceLayout(device.handle, as_handle<VkImage>(image.handle), &subresource, &layout);
		store(a[3], layout);
	} else if (name == "vkBindImageMemory") {
		auto &device = device_of(a[0]);
		const auto &image = object_of(a[1], a[0], Kind::image);
		const auto memory = memories.find(a[2]);
		if (memory == memories.end() || memory->second.device != a[0])
			throw std::runtime_error("invalid Vulkan memory handle");
		result = static_cast<uint32_t>(vkBindImageMemory(device.handle, as_handle<VkImage>(image.handle), memory->second.handle, a[3]));
	} else if (name == "vkCreateImageView") {
		auto &device = device_of(a[0]);
		no_allocator(a[2]);
		auto info = load<VkImageViewCreateInfo>(a[1]);
		if (info.sType != VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO || info.pNext || info.flags)
			throw std::runtime_error("unsupported Vulkan image view create info");
		info.image = as_handle<VkImage>(object_of(reinterpret_cast<uint64_t>(info.image), a[0], Kind::image).handle);
		check_writable(a[3], 8);
		VkImageView view = VK_NULL_HANDLE;
		const auto status = vkCreateImageView(device.handle, &info, nullptr, &view);
		result = create(Kind::image_view, a[0], a[3], reinterpret_cast<uint64_t>(view), status);
	} else if (name == "vkCreateSemaphore") {
		auto &device = device_of(a[0]);
		no_allocator(a[2]);
		auto info = load<VkSemaphoreCreateInfo>(a[1]);
		if (info.sType != VK_STRUCTURE_TYPE_SEMAPHORE_CREATE_INFO || info.pNext || info.flags)
			throw std::runtime_error("unsupported Vulkan semaphore create info");
		check_writable(a[3], 8);
		VkSemaphore semaphore = VK_NULL_HANDLE;
		const auto status = vkCreateSemaphore(device.handle, &info, nullptr, &semaphore);
		result = create(Kind::semaphore, a[0], a[3], reinterpret_cast<uint64_t>(semaphore), status);
	} else if (name == "vkDestroyImage" || name == "vkDestroyImageView" || name == "vkDestroySemaphore") {
		auto &device = device_of(a[0]);
		no_allocator(a[2]);
		if (a[1]) {
			const auto kind = name == "vkDestroyImage" ? Kind::image : name == "vkDestroyImageView" ? Kind::image_view : Kind::semaphore;
			const auto object = object_of(a[1], a[0], kind);
			destroy_object(device.handle, object);
			objects.erase(a[1]);
		}
	} else if (name == "vkGetFenceStatus") {
		auto &device = device_of(a[0]);
		const auto found = fences.find(a[1]);
		if (found == fences.end() || found->second.device != a[0])
			throw std::runtime_error("invalid Vulkan fence handle");
		const auto status = vkGetFenceStatus(device.handle, found->second.handle);
		result = static_cast<uint32_t>(status);
		if (status == VK_SUCCESS)
			shadow_from_device(a[0]);
	} else if (name == "vkCmdCopyBufferToImage" || name == "vkCmdCopyImageToBuffer") {
		const auto &command = command_of(a[0]);
		const bool upload = name == "vkCmdCopyBufferToImage";
		const auto buffer = buffer_of(a[upload ? 1 : 3], command.device).handle;
		const auto image = as_handle<VkImage>(object_of(a[upload ? 2 : 1], command.device, Kind::image).handle);
		const auto regions = records.template operator()<VkBufferImageCopy>(a[5], a[4], 16);
		if (regions.empty())
			throw std::runtime_error("unsupported Vulkan copy region count");
		if (upload)
			vkCmdCopyBufferToImage(command.handle, buffer, image, VkImageLayout(a[3]), uint32_t(regions.size()), regions.data());
		else
			vkCmdCopyImageToBuffer(command.handle, image, VkImageLayout(a[2]), buffer, uint32_t(regions.size()), regions.data());
	} else if (name == "vkCmdPipelineBarrier") {
		const auto &command = command_of(a[0]);
		if (a[3] || a[4] > 8 || a[6] > 8 || a[8] > 8)
			throw std::runtime_error("unsupported Vulkan pipeline barrier");
		const auto memory = records.template operator()<VkMemoryBarrier>(a[5], a[4], 8);
		auto buffer_barriers = records.template operator()<VkBufferMemoryBarrier>(a[7], a[6], 8);
		auto image_barriers = records.template operator()<VkImageMemoryBarrier>(a[9], a[8], 8);
		for (const auto &barrier : memory)
			if (barrier.sType != VK_STRUCTURE_TYPE_MEMORY_BARRIER || barrier.pNext)
				throw std::runtime_error("unsupported Vulkan memory barrier");
		for (auto &barrier : buffer_barriers) {
			if (barrier.sType != VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER || barrier.pNext)
				throw std::runtime_error("unsupported Vulkan buffer barrier");
			barrier.buffer = buffer_of(reinterpret_cast<uint64_t>(barrier.buffer), command.device).handle;
		}
		for (auto &barrier : image_barriers) {
			if (barrier.sType != VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER || barrier.pNext)
				throw std::runtime_error("unsupported Vulkan image barrier");
			barrier.image = as_handle<VkImage>(object_of(reinterpret_cast<uint64_t>(barrier.image), command.device, Kind::image).handle);
		}
		vkCmdPipelineBarrier(command.handle, VkPipelineStageFlags(a[1]), VkPipelineStageFlags(a[2]), 0, uint32_t(memory.size()), memory.data(),
			uint32_t(buffer_barriers.size()), buffer_barriers.data(), uint32_t(image_barriers.size()), image_barriers.data());
	}
	process.return_api(result);
	return true;
}

}

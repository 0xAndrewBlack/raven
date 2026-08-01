#include "vulkan_bridge.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <stdexcept>
#include <sys/mman.h>

namespace raven {

// Names are kept in byte order because the guest provider binary searches its export table.
static constexpr std::array<std::string_view, 8> names{
	"vkAllocateCommandBuffers", "vkDestroyCommandPool", "vkFlushMappedMemoryRanges", "vkFreeCommandBuffers",
	"vkFreeMemory", "vkInvalidateMappedMemoryRanges", "vkMapMemory", "vkUnmapMemory"
};

std::span<const std::string_view> vulkan_resource_names()
{
	static const auto sorted = [] {
		std::array<std::string_view, 8> copy = names;
		std::sort(copy.begin(), copy.end());
		return copy;
	}();
	return sorted;
}

void VulkanBridge::check_writable(uint64_t address, size_t size) const
{
	process.write_memory(address, process.read_memory(address, size));
}

void VulkanBridge::shadow_to_device(uint64_t device)
{
	for (auto &[token, memory] : memories) {
		if (memory.device != device || !memory.host || !memory.shadow)
			continue;
		auto current = process.read_memory(memory.shadow, size_t(memory.mapped));
		auto *host = static_cast<uint8_t *>(memory.host);
		for (size_t index = 0; index < current.size(); ++index)
			if (current[index] != memory.snapshot[index]) {
				host[index] = current[index];
				memory.snapshot[index] = current[index];
			}
	}
}

void VulkanBridge::shadow_from_device(uint64_t device)
{
	for (auto &[token, memory] : memories) {
		if (memory.device != device || !memory.host || !memory.shadow)
			continue;
		const auto *host = static_cast<const uint8_t *>(memory.host);
		std::vector<uint8_t> current = process.read_memory(memory.shadow, size_t(memory.mapped));
		bool changed = false;
		for (size_t index = 0; index < current.size(); ++index)
			if (host[index] != memory.snapshot[index]) {
				current[index] = host[index];
				memory.snapshot[index] = host[index];
				changed = true;
			}
		if (changed)
			process.write_memory(memory.shadow, current);
	}
}

bool VulkanBridge::dispatch_resource(std::string_view name)
{
	if (std::find(names.begin(), names.end(), name) == names.end())
		return false;
	static const std::map<std::string_view, size_t, std::less<>> words{
		{"vkAllocateCommandBuffers", 3}, {"vkDestroyCommandPool", 3}, {"vkFlushMappedMemoryRanges", 3},
		{"vkFreeCommandBuffers", 4}, {"vkFreeMemory", 3}, {"vkInvalidateMappedMemoryRanges", 3}, {"vkMapMemory", 6}, {"vkUnmapMemory", 2}};
	auto a = process.api_arguments(words.at(name));
	// A 32-bit argument leaves the upper half of its register or stack slot undefined, so those are narrowed before use.
	static const std::map<std::string_view, std::vector<size_t>, std::less<>> narrow{
		{"vkMapMemory", {4}}, {"vkFlushMappedMemoryRanges", {1}}, {"vkInvalidateMappedMemoryRanges", {1}}, {"vkFreeCommandBuffers", {2}}};
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
	const auto memory_of = [&](uint64_t token, uint64_t device) -> Memory & {
		const auto found = memories.find(token);
		if (found == memories.end() || found->second.device != device)
			throw std::runtime_error("invalid Vulkan memory handle");
		return found->second;
	};
	const auto buffer_of = [&](uint64_t token, uint64_t device) -> Buffer & {
		const auto found = buffers.find(token);
		if (found == buffers.end() || found->second.device != device)
			throw std::runtime_error("invalid Vulkan buffer handle");
		return found->second;
	};
	const auto pool_of = [&](uint64_t token, uint64_t device) -> Pool & {
		const auto found = pools.find(token);
		if (found == pools.end() || found->second.device != device)
			throw std::runtime_error("invalid Vulkan command pool handle");
		return found->second;
	};
	const auto command_of = [&](uint64_t token) -> CommandBuffer & {
		const auto found = command_buffers.find(token);
		if (found == command_buffers.end())
			throw std::runtime_error("invalid Vulkan command buffer handle");
		return found->second;
	};
	const auto fence_of = [&](uint64_t token, uint64_t device) -> Fence & {
		const auto found = fences.find(token);
		if (found == fences.end() || found->second.device != device)
			throw std::runtime_error("invalid Vulkan fence handle");
		return found->second;
	};
	uint64_t result = 0;
if (name == "vkFreeMemory") {
		auto &device = device_of(a[0]);
		no_allocator(a[2]);
		if (a[1]) {
			auto &memory = memory_of(a[1], a[0]);
			if (memory.host) {
				vkUnmapMemory(device.handle, memory.handle);
				if (memory.shadow)
					process.unmap_memory(memory.shadow);
			}
			vkFreeMemory(device.handle, memory.handle, nullptr);
			memories.erase(a[1]);
		}
	} else if (name == "vkMapMemory") {
		auto &device = device_of(a[0]);
		auto &memory = memory_of(a[1], a[0]);
		const uint64_t offset = a[2], size = a[3] == VK_WHOLE_SIZE ? memory.size - std::min<uint64_t>(offset, memory.size) : a[3];
		if (a[4] || memory.host || offset >= memory.size || !size || size > memory.size - offset || size > (256ULL << 20))
			throw std::runtime_error("unsupported Vulkan memory mapping (offset " + std::to_string(offset) + ", size " + std::to_string(size) +
				", memory " + std::to_string(memory.size) + (memory.host ? ", already mapped" : "") + ", flags " + std::to_string(a[4]) + ")");
		check_writable(a[5], 8);
		void *host = nullptr;
		const auto status = vkMapMemory(device.handle, memory.handle, offset, size, 0, &host);
		result = static_cast<uint32_t>(status);
		if (status == VK_SUCCESS) {
			const auto rounded = (size_t(size) + 4095) & ~size_t(4095);
			const auto shadow = process.map_memory(rounded, PROT_READ | PROT_WRITE);
			memory.snapshot.assign(static_cast<const uint8_t *>(host), static_cast<const uint8_t *>(host) + size);
			process.write_memory(shadow, memory.snapshot);
			memory.host = host;
			memory.shadow = shadow;
			memory.offset = offset;
			memory.mapped = size;
			store(a[5], shadow);
		}
	} else if (name == "vkUnmapMemory") {
		auto &device = device_of(a[0]);
		auto &memory = memory_of(a[1], a[0]);
		if (!memory.host)
			throw std::runtime_error("Vulkan memory is not mapped");
		shadow_to_device(a[0]);
		vkUnmapMemory(device.handle, memory.handle);
		process.unmap_memory(memory.shadow);
		memory.host = nullptr;
		memory.shadow = 0;
		memory.snapshot.clear();
	} else if (name == "vkFlushMappedMemoryRanges" || name == "vkInvalidateMappedMemoryRanges") {
		device_of(a[0]);
		if (a[1] > 64)
			throw std::runtime_error("too many Vulkan mapped memory ranges");
		for (uint64_t index = 0; index < a[1]; ++index) {
			const auto range = load<VkMappedMemoryRange>(a[2] + index * sizeof(VkMappedMemoryRange));
			if (range.sType != VK_STRUCTURE_TYPE_MAPPED_MEMORY_RANGE || range.pNext)
				throw std::runtime_error("unsupported Vulkan mapped memory range");
			if (!memory_of(reinterpret_cast<uint64_t>(range.memory), a[0]).host)
				throw std::runtime_error("Vulkan memory is not mapped");
		}
		if (name == "vkFlushMappedMemoryRanges")
			shadow_to_device(a[0]);
		else
			shadow_from_device(a[0]);
	} else if (name == "vkDestroyCommandPool") {
		auto &device = device_of(a[0]);
		no_allocator(a[2]);
		if (a[1]) {
			const auto &pool = pool_of(a[1], a[0]);
			vkDestroyCommandPool(device.handle, pool.handle, nullptr);
			std::erase_if(command_buffers, [&](const auto &item) { return item.second.pool == a[1]; });
			pools.erase(a[1]);
		}
	} else if (name == "vkAllocateCommandBuffers") {
		auto &device = device_of(a[0]);
		auto info = load<VkCommandBufferAllocateInfo>(a[1]);
		if (info.sType != VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO || info.pNext || !info.commandBufferCount || info.commandBufferCount > 64)
			throw std::runtime_error("unsupported Vulkan command buffer allocate info");
		const auto pool_token = reinterpret_cast<uint64_t>(info.commandPool);
		const auto &pool = pool_of(pool_token, a[0]);
		info.commandPool = pool.handle;
		check_writable(a[2], size_t(info.commandBufferCount) * 8);
		std::vector<VkCommandBuffer> created(info.commandBufferCount);
		const auto status = vkAllocateCommandBuffers(device.handle, &info, created.data());
		result = static_cast<uint32_t>(status);
		if (status == VK_SUCCESS)
			for (size_t index = 0; index < created.size(); ++index) {
				const auto token = next_handle++;
				command_buffers.emplace(token, CommandBuffer{created[index], a[0], pool_token});
				store(a[2] + index * 8, token);
			}
	} else if (name == "vkFreeCommandBuffers") {
		auto &device = device_of(a[0]);
		const auto &pool = pool_of(a[1], a[0]);
		if (a[2] > 64)
			throw std::runtime_error("too many Vulkan command buffers");
		std::vector<VkCommandBuffer> handles;
		std::vector<uint64_t> tokens;
		for (uint64_t index = 0; index < a[2]; ++index) {
			const auto token = load<uint64_t>(a[3] + index * 8);
			if (!token)
				continue;
			const auto &buffer = command_of(token);
			if (buffer.pool != a[1])
				throw std::runtime_error("Vulkan command buffer belongs to another pool");
			handles.push_back(buffer.handle);
			tokens.push_back(token);
		}
		if (!handles.empty())
			vkFreeCommandBuffers(device.handle, pool.handle, uint32_t(handles.size()), handles.data());
		for (const auto token : tokens)
			command_buffers.erase(token);
		}
	process.return_api(result);
	return true;
}

}

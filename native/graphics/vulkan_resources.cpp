#include "vulkan_bridge.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <stdexcept>
#include <sys/mman.h>

namespace raven {

// Names are kept in byte order because the guest provider binary searches its export table.
static constexpr std::array<std::string_view, 25> names{
	"vkAllocateCommandBuffers", "vkAllocateMemory", "vkBeginCommandBuffer", "vkBindBufferMemory", "vkCmdCopyBuffer",
	"vkCreateBuffer", "vkCreateCommandPool", "vkCreateFence", "vkDestroyBuffer", "vkDestroyCommandPool", "vkDestroyFence",
	"vkEndCommandBuffer", "vkFlushMappedMemoryRanges", "vkFreeCommandBuffers", "vkFreeMemory", "vkGetBufferMemoryRequirements",
	"vkInvalidateMappedMemoryRanges", "vkMapMemory", "vkQueueSubmit", "vkQueueWaitIdle", "vkResetFences", "vkUnmapMemory",
	"vkWaitForFences", "vkGetDeviceMemoryCommitment", "vkResetCommandPool"
};

std::span<const std::string_view> vulkan_resource_names()
{
	static const auto sorted = [] {
		std::array<std::string_view, 25> copy = names;
		std::sort(copy.begin(), copy.end());
		return copy;
	}();
	return sorted;
}

void VulkanBridge::check_writable(uint64_t address, size_t size) const
{
	process.write_memory(address, process.read_memory(address, size));
}

template<typename T> T VulkanBridge::load(uint64_t address) const
{
	T result{};
	const auto bytes = process.read_memory(address, sizeof(T));
	std::memcpy(&result, bytes.data(), sizeof(T));
	return result;
}

template<typename T> void VulkanBridge::store(uint64_t address, const T &value) const
{
	process.write_memory(address, std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(&value), sizeof(T)));
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
		{"vkAllocateCommandBuffers", 3}, {"vkAllocateMemory", 4}, {"vkBeginCommandBuffer", 2}, {"vkBindBufferMemory", 4},
		{"vkCmdCopyBuffer", 5}, {"vkCreateBuffer", 4}, {"vkCreateCommandPool", 4}, {"vkCreateFence", 4}, {"vkDestroyBuffer", 3},
		{"vkDestroyCommandPool", 3}, {"vkDestroyFence", 3}, {"vkEndCommandBuffer", 1}, {"vkFlushMappedMemoryRanges", 3},
		{"vkFreeCommandBuffers", 4}, {"vkFreeMemory", 3}, {"vkGetBufferMemoryRequirements", 3}, {"vkInvalidateMappedMemoryRanges", 3},
		{"vkMapMemory", 6}, {"vkQueueSubmit", 4}, {"vkQueueWaitIdle", 1}, {"vkResetFences", 3}, {"vkUnmapMemory", 2}, {"vkWaitForFences", 5},
		{"vkGetDeviceMemoryCommitment", 3}, {"vkResetCommandPool", 3}};
	const auto a = process.api_arguments(words.at(name));
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
	if (name == "vkCreateBuffer") {
		auto &device = device_of(a[0]);
		no_allocator(a[2]);
		auto info = load<VkBufferCreateInfo>(a[1]);
		if (info.sType != VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO || info.pNext || info.flags || info.sharingMode != VK_SHARING_MODE_EXCLUSIVE ||
			info.queueFamilyIndexCount || info.pQueueFamilyIndices || !info.size || info.size > (1ULL << 30))
			throw std::runtime_error("unsupported Vulkan buffer create info");
		check_writable(a[3], 8);
		VkBuffer buffer = VK_NULL_HANDLE;
		const auto status = vkCreateBuffer(device.handle, &info, nullptr, &buffer);
		result = static_cast<uint32_t>(status);
		if (status == VK_SUCCESS) {
			const auto token = next_handle++;
			buffers.emplace(token, Buffer{buffer, a[0]});
			store(a[3], token);
		}
	} else if (name == "vkDestroyBuffer") {
		auto &device = device_of(a[0]);
		no_allocator(a[2]);
		if (a[1]) {
			const auto &buffer = buffer_of(a[1], a[0]);
			vkDestroyBuffer(device.handle, buffer.handle, nullptr);
			buffers.erase(a[1]);
		}
	} else if (name == "vkGetBufferMemoryRequirements") {
		auto &device = device_of(a[0]);
		const auto &buffer = buffer_of(a[1], a[0]);
		check_writable(a[2], sizeof(VkMemoryRequirements));
		VkMemoryRequirements requirements{};
		vkGetBufferMemoryRequirements(device.handle, buffer.handle, &requirements);
		store(a[2], requirements);
	} else if (name == "vkAllocateMemory") {
		auto &device = device_of(a[0]);
		no_allocator(a[2]);
		auto info = load<VkMemoryAllocateInfo>(a[1]);
		if (info.sType != VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO || info.pNext || !info.allocationSize || info.allocationSize > (256ULL << 20))
			throw std::runtime_error("unsupported Vulkan memory allocate info");
		check_writable(a[3], 8);
		VkDeviceMemory memory = VK_NULL_HANDLE;
		const auto status = vkAllocateMemory(device.handle, &info, nullptr, &memory);
		result = static_cast<uint32_t>(status);
		if (status == VK_SUCCESS) {
			const auto token = next_handle++;
			memories.emplace(token, Memory{memory, a[0], info.allocationSize});
			store(a[3], token);
		}
	} else if (name == "vkFreeMemory") {
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
	} else if (name == "vkBindBufferMemory") {
		auto &device = device_of(a[0]);
		const auto &buffer = buffer_of(a[1], a[0]);
		const auto &memory = memory_of(a[2], a[0]);
		result = static_cast<uint32_t>(vkBindBufferMemory(device.handle, buffer.handle, memory.handle, a[3]));
	} else if (name == "vkMapMemory") {
		auto &device = device_of(a[0]);
		auto &memory = memory_of(a[1], a[0]);
		const uint64_t offset = a[2], size = a[3] == VK_WHOLE_SIZE ? memory.size - std::min<uint64_t>(offset, memory.size) : a[3];
		if (a[4] || memory.host || offset >= memory.size || !size || size > memory.size - offset || size > (256ULL << 20))
			throw std::runtime_error("unsupported Vulkan memory mapping");
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
	} else if (name == "vkCreateCommandPool") {
		auto &device = device_of(a[0]);
		no_allocator(a[2]);
		auto info = load<VkCommandPoolCreateInfo>(a[1]);
		if (info.sType != VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO || info.pNext || (info.flags & ~uint32_t(VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT)))
			throw std::runtime_error("unsupported Vulkan command pool create info");
		check_writable(a[3], 8);
		VkCommandPool pool = VK_NULL_HANDLE;
		const auto status = vkCreateCommandPool(device.handle, &info, nullptr, &pool);
		result = static_cast<uint32_t>(status);
		if (status == VK_SUCCESS) {
			const auto token = next_handle++;
			pools.emplace(token, Pool{pool, a[0]});
			store(a[3], token);
		}
	} else if (name == "vkDestroyCommandPool") {
		auto &device = device_of(a[0]);
		no_allocator(a[2]);
		if (a[1]) {
			const auto &pool = pool_of(a[1], a[0]);
			vkDestroyCommandPool(device.handle, pool.handle, nullptr);
			std::erase_if(command_buffers, [&](const auto &item) { return item.second.pool == a[1]; });
			pools.erase(a[1]);
		}
	} else if (name == "vkResetCommandPool") {
		auto &device = device_of(a[0]);
		const auto &pool = pool_of(a[1], a[0]);
		result = static_cast<uint32_t>(vkResetCommandPool(device.handle, pool.handle, VkCommandPoolResetFlags(uint32_t(a[2]))));
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
	} else if (name == "vkBeginCommandBuffer") {
		auto &buffer = command_of(a[0]);
		auto info = load<VkCommandBufferBeginInfo>(a[1]);
		if (info.sType != VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO || info.pNext || info.pInheritanceInfo)
			throw std::runtime_error("unsupported Vulkan command buffer begin info");
		result = static_cast<uint32_t>(vkBeginCommandBuffer(buffer.handle, &info));
	} else if (name == "vkEndCommandBuffer") {
		result = static_cast<uint32_t>(vkEndCommandBuffer(command_of(a[0]).handle));
	} else if (name == "vkCmdCopyBuffer") {
		auto &command = command_of(a[0]);
		const auto &source = buffer_of(a[1], command.device);
		const auto &target = buffer_of(a[2], command.device);
		if (!a[3] || a[3] > 64)
			throw std::runtime_error("unsupported Vulkan buffer copy region count");
		std::vector<VkBufferCopy> regions(a[3]);
		for (size_t index = 0; index < regions.size(); ++index)
			regions[index] = load<VkBufferCopy>(a[4] + index * sizeof(VkBufferCopy));
		vkCmdCopyBuffer(command.handle, source.handle, target.handle, uint32_t(regions.size()), regions.data());
	} else if (name == "vkCreateFence") {
		auto &device = device_of(a[0]);
		no_allocator(a[2]);
		auto info = load<VkFenceCreateInfo>(a[1]);
		if (info.sType != VK_STRUCTURE_TYPE_FENCE_CREATE_INFO || info.pNext || (info.flags & ~uint32_t(VK_FENCE_CREATE_SIGNALED_BIT)))
			throw std::runtime_error("unsupported Vulkan fence create info");
		check_writable(a[3], 8);
		VkFence fence = VK_NULL_HANDLE;
		const auto status = vkCreateFence(device.handle, &info, nullptr, &fence);
		result = static_cast<uint32_t>(status);
		if (status == VK_SUCCESS) {
			const auto token = next_handle++;
			fences.emplace(token, Fence{fence, a[0]});
			store(a[3], token);
		}
	} else if (name == "vkDestroyFence") {
		auto &device = device_of(a[0]);
		no_allocator(a[2]);
		if (a[1]) {
			const auto &fence = fence_of(a[1], a[0]);
			vkDestroyFence(device.handle, fence.handle, nullptr);
			fences.erase(a[1]);
		}
	} else if (name == "vkResetFences" || name == "vkWaitForFences") {
		auto &device = device_of(a[0]);
		if (!a[1] || a[1] > 64)
			throw std::runtime_error("unsupported Vulkan fence count");
		std::vector<VkFence> handles;
		for (uint64_t index = 0; index < a[1]; ++index)
			handles.push_back(fence_of(load<uint64_t>(a[2] + index * 8), a[0]).handle);
		if (name == "vkResetFences") {
			result = static_cast<uint32_t>(vkResetFences(device.handle, uint32_t(handles.size()), handles.data()));
		} else {
			const auto status = vkWaitForFences(device.handle, uint32_t(handles.size()), handles.data(), a[3] & 1 ? VK_TRUE : VK_FALSE, a[4]);
			result = static_cast<uint32_t>(status);
			if (status == VK_SUCCESS)
				shadow_from_device(a[0]);
		}
	} else if (name == "vkQueueSubmit") {
		const auto found = queues.find(a[0]);
		if (found == queues.end())
			throw std::runtime_error("invalid Vulkan queue handle");
		const auto device_token = found->second.device;
		if (a[1] > 16)
			throw std::runtime_error("too many Vulkan submissions");
		std::vector<VkSubmitInfo> submits(a[1]);
		std::vector<std::vector<VkCommandBuffer>> lists(a[1]);
		for (size_t index = 0; index < submits.size(); ++index) {
			submits[index] = load<VkSubmitInfo>(a[2] + index * sizeof(VkSubmitInfo));
			auto &info = submits[index];
			if (info.sType != VK_STRUCTURE_TYPE_SUBMIT_INFO || info.pNext || info.waitSemaphoreCount || info.signalSemaphoreCount ||
				info.commandBufferCount > 64)
				throw std::runtime_error("unsupported Vulkan submit info");
			for (uint32_t buffer = 0; buffer < info.commandBufferCount; ++buffer) {
				const auto &command = command_of(load<uint64_t>(reinterpret_cast<uint64_t>(info.pCommandBuffers) + uint64_t(buffer) * 8));
				if (command.device != device_token)
					throw std::runtime_error("Vulkan command buffer belongs to another device");
				lists[index].push_back(command.handle);
			}
			info.pWaitSemaphores = nullptr;
			info.pWaitDstStageMask = nullptr;
			info.pSignalSemaphores = nullptr;
			info.pCommandBuffers = lists[index].data();
		}
		VkFence fence = VK_NULL_HANDLE;
		if (a[3])
			fence = fence_of(a[3], device_token).handle;
		shadow_to_device(device_token);
		result = static_cast<uint32_t>(vkQueueSubmit(found->second.handle, uint32_t(submits.size()), submits.data(), fence));
	} else if (name == "vkQueueWaitIdle") {
		const auto found = queues.find(a[0]);
		if (found == queues.end())
			throw std::runtime_error("invalid Vulkan queue handle");
		const auto status = vkQueueWaitIdle(found->second.handle);
		result = static_cast<uint32_t>(status);
		if (status == VK_SUCCESS)
			shadow_from_device(found->second.device);
	} else if (name == "vkGetDeviceMemoryCommitment") {
		auto &device = device_of(a[0]);
		const auto &memory = memory_of(a[1], a[0]);
		check_writable(a[2], 8);
		VkDeviceSize committed = 0;
		vkGetDeviceMemoryCommitment(device.handle, memory.handle, &committed);
		store(a[2], committed);
	}
	process.return_api(result);
	return true;
}

}

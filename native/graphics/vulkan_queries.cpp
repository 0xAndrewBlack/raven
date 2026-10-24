#include "vulkan_bridge.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <stdexcept>

namespace raven {

// Names are kept in byte order because the guest provider binary searches its export table.
static constexpr std::array<std::string_view, 13> names{
	"vkGetPhysicalDeviceFeatures2", "vkGetPhysicalDeviceFeatures2KHR", "vkGetPhysicalDeviceFormatProperties", "vkGetPhysicalDeviceFormatProperties2",
	"vkGetPhysicalDeviceFormatProperties2KHR", "vkGetPhysicalDeviceImageFormatProperties", "vkGetPhysicalDeviceMemoryProperties2",
	"vkGetPhysicalDeviceMemoryProperties2KHR", "vkGetPhysicalDeviceProperties2", "vkGetPhysicalDeviceProperties2KHR",
	"vkGetPhysicalDeviceQueueFamilyProperties2", "vkGetPhysicalDeviceQueueFamilyProperties2KHR", "vkGetPhysicalDeviceSparseImageFormatProperties"
};

std::span<const std::string_view> vulkan_query_names() { return names; }

namespace {

struct Known {
	VkStructureType type;
	size_t size;
};

// Feature and property structures that hold no pointers, generated from the Vulkan headers, plus the query heads themselves.
constexpr Known known[] = {
#include "vulkan_chain_table.inc"
	{VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FEATURES_2, sizeof(VkPhysicalDeviceFeatures2)},
};

const Known *find_known(uint32_t type)
{
	for (const auto &item : known)
		if (uint32_t(item.type) == type)
			return &item;
	return nullptr;
}

}

std::vector<VulkanBridge::ChainEntry> VulkanBridge::mirror_chain(uint64_t first, bool strict) const
{
	std::vector<ChainEntry> chain;
	uint64_t at = first;
	for (size_t depth = 0; at && depth < 64; ++depth) {
		const auto header = process.read_memory(at, 16);
		uint32_t type = 0;
		uint64_t next = 0;
		std::memcpy(&type, header.data(), 4);
		std::memcpy(&next, header.data() + 8, 8);
		if (const auto *entry = find_known(type)) {
			chain.push_back({at, process.read_memory(at, entry->size)});
		} else if (strict) {
			throw std::runtime_error("unsupported Vulkan structure in a pNext chain (type " + std::to_string(type) + ")");
		}
		at = next;
	}
	if (at)
		throw std::runtime_error("Vulkan pNext chain is too long");
	return chain;
}

void *VulkanBridge::link_chain(std::vector<ChainEntry> &chain)
{
	for (size_t index = 0; index < chain.size(); ++index) {
		void *next = index + 1 < chain.size() ? chain[index + 1].host.data() : nullptr;
		std::memcpy(chain[index].host.data() + 8, &next, 8);
	}
	return chain.empty() ? nullptr : chain.front().host.data();
}

void VulkanBridge::copy_back_chain(const std::vector<ChainEntry> &chain) const
{
	for (const auto &entry : chain)
		process.write_memory(entry.guest + 16, std::span<const uint8_t>(entry.host).subspan(16));
}

bool VulkanBridge::dispatch_queries(std::string_view name)
{
	if (std::find(names.begin(), names.end(), name) == names.end())
		return false;
	if (name.ends_with("KHR"))
		name.remove_suffix(3);
	auto a = process.api_arguments(name == "vkGetPhysicalDeviceSparseImageFormatProperties" ? 8 : name == "vkGetPhysicalDeviceImageFormatProperties" ? 7 :
		name == "vkGetPhysicalDeviceQueueFamilyProperties2" || name == "vkGetPhysicalDeviceFormatProperties" || name == "vkGetPhysicalDeviceFormatProperties2" ? 3 : 2);
	if (name == "vkGetPhysicalDeviceFormatProperties" || name == "vkGetPhysicalDeviceFormatProperties2" || name == "vkGetPhysicalDeviceImageFormatProperties")
		for (size_t index = 1; index < (name == "vkGetPhysicalDeviceImageFormatProperties" ? 6U : 2U); ++index)
			a[index] = uint32_t(a[index]);
	if (name == "vkGetPhysicalDeviceSparseImageFormatProperties")
		for (size_t index = 1; index < 6; ++index)
			a[index] = uint32_t(a[index]);
	const auto found = physical.find(a[0]);
	if (found == physical.end())
		throw std::runtime_error("invalid Vulkan physical device handle");
	const auto handle = found->second.handle;
	const auto read = [&]<typename T>(uint64_t address) {
		T result{};
		const auto bytes = process.read_memory(address, sizeof(T));
		std::memcpy(&result, bytes.data(), sizeof(T));
		return result;
	};
	const auto write = [&]<typename T>(uint64_t address, const T &value) {
		process.write_memory(address, std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(&value), sizeof(T)));
	};
	const auto head_check = [&](uint64_t address, VkStructureType expected, size_t size) {
		const auto bytes = process.read_memory(address, size);
		uint32_t type;
		std::memcpy(&type, bytes.data(), 4);
		if (type != uint32_t(expected))
			throw std::runtime_error("Vulkan query structure has the wrong type");
		process.write_memory(address, bytes);
		uint64_t next;
		std::memcpy(&next, bytes.data() + 8, 8);
		return next;
	};
	uint64_t result = 0;
	if (name == "vkGetPhysicalDeviceFeatures2") {
		auto chain = mirror_chain(head_check(a[1], VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FEATURES_2, sizeof(VkPhysicalDeviceFeatures2)), false);
		VkPhysicalDeviceFeatures2 features{};
		features.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FEATURES_2;
		features.pNext = link_chain(chain);
		vkGetPhysicalDeviceFeatures2(handle, &features);
		process.write_memory(a[1] + offsetof(VkPhysicalDeviceFeatures2, features),
			std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(&features.features), sizeof(features.features)));
		copy_back_chain(chain);
	} else if (name == "vkGetPhysicalDeviceProperties2") {
		auto chain = mirror_chain(head_check(a[1], VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PROPERTIES_2, sizeof(VkPhysicalDeviceProperties2)), false);
		VkPhysicalDeviceProperties2 properties{};
		properties.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PROPERTIES_2;
		properties.pNext = link_chain(chain);
		vkGetPhysicalDeviceProperties2(handle, &properties);
		process.write_memory(a[1] + offsetof(VkPhysicalDeviceProperties2, properties),
			std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(&properties.properties), sizeof(properties.properties)));
		copy_back_chain(chain);
	} else if (name == "vkGetPhysicalDeviceMemoryProperties2") {
		auto chain = mirror_chain(head_check(a[1], VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MEMORY_PROPERTIES_2, sizeof(VkPhysicalDeviceMemoryProperties2)), false);
		VkPhysicalDeviceMemoryProperties2 memory{};
		memory.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MEMORY_PROPERTIES_2;
		memory.pNext = link_chain(chain);
		vkGetPhysicalDeviceMemoryProperties2(handle, &memory);
		process.write_memory(a[1] + offsetof(VkPhysicalDeviceMemoryProperties2, memoryProperties),
			std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(&memory.memoryProperties), sizeof(memory.memoryProperties)));
		copy_back_chain(chain);
	} else if (name == "vkGetPhysicalDeviceFormatProperties") {
		process.write_memory(a[2], process.read_memory(a[2], sizeof(VkFormatProperties)));
		VkFormatProperties properties{};
		vkGetPhysicalDeviceFormatProperties(handle, VkFormat(a[1]), &properties);
		write(a[2], properties);
	} else if (name == "vkGetPhysicalDeviceFormatProperties2") {
		auto chain = mirror_chain(head_check(a[2], VK_STRUCTURE_TYPE_FORMAT_PROPERTIES_2, sizeof(VkFormatProperties2)), false);
		VkFormatProperties2 properties{};
		properties.sType = VK_STRUCTURE_TYPE_FORMAT_PROPERTIES_2;
		properties.pNext = link_chain(chain);
		vkGetPhysicalDeviceFormatProperties2(handle, VkFormat(a[1]), &properties);
		process.write_memory(a[2] + offsetof(VkFormatProperties2, formatProperties),
			std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(&properties.formatProperties), sizeof(properties.formatProperties)));
		copy_back_chain(chain);
	} else if (name == "vkGetPhysicalDeviceImageFormatProperties") {
		process.write_memory(a[6], process.read_memory(a[6], sizeof(VkImageFormatProperties)));
		VkImageFormatProperties properties{};
		const auto status = vkGetPhysicalDeviceImageFormatProperties(handle, VkFormat(a[1]), VkImageType(a[2]), VkImageTiling(a[3]),
			VkImageUsageFlags(a[4]), VkImageCreateFlags(a[5]), &properties);
		result = static_cast<uint32_t>(status);
		if (status == VK_SUCCESS)
			write(a[6], properties);
	} else if (name == "vkGetPhysicalDeviceSparseImageFormatProperties") {
		// (physical device, format, type, samples, usage, tiling, count, properties): the usual count-then-fill pair of calls.
		if (!a[6])
			throw std::runtime_error("sparse image format query needs a count");
		process.write_memory(a[6], process.read_memory(a[6], 4));
		uint32_t count = read.template operator()<uint32_t>(a[6]);
		if (a[7]) {
			if (count > 4096)
				throw std::runtime_error("sparse image format capacity exceeds limit");
			process.write_memory(a[7], process.read_memory(a[7], size_t(count) * sizeof(VkSparseImageFormatProperties)));
		}
		std::vector<VkSparseImageFormatProperties> properties(a[7] ? count : 0);
		vkGetPhysicalDeviceSparseImageFormatProperties(handle, VkFormat(a[1]), VkImageType(a[2]), VkSampleCountFlagBits(a[3]),
			VkImageUsageFlags(a[4]), VkImageTiling(a[5]), &count, a[7] ? properties.data() : nullptr);
		if (a[7])
			for (size_t index = 0; index < count && index < properties.size(); ++index)
				write(a[7] + index * sizeof(VkSparseImageFormatProperties), properties[index]);
		write(a[6], count);
	} else if (name == "vkGetPhysicalDeviceQueueFamilyProperties2") {
		process.write_memory(a[1], process.read_memory(a[1], 4));
		uint32_t count = 0;
		if (a[2]) {
			count = read.template operator()<uint32_t>(a[1]);
			if (count > 4096)
				throw std::runtime_error("Vulkan queue family capacity exceeds limit");
			process.write_memory(a[2], process.read_memory(a[2], size_t(count) * sizeof(VkQueueFamilyProperties2)));
		}
		std::vector<VkQueueFamilyProperties2> families(count);
		for (auto &family : families)
			family.sType = VK_STRUCTURE_TYPE_QUEUE_FAMILY_PROPERTIES_2;
		vkGetPhysicalDeviceQueueFamilyProperties2(handle, &count, a[2] ? families.data() : nullptr);
		if (a[2])
			for (size_t index = 0; index < count && index < families.size(); ++index)
				process.write_memory(a[2] + index * sizeof(VkQueueFamilyProperties2) + offsetof(VkQueueFamilyProperties2, queueFamilyProperties),
					std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(&families[index].queueFamilyProperties), sizeof(VkQueueFamilyProperties)));
		write(a[1], count);
	}
	process.return_api(result);
	return true;
}

}

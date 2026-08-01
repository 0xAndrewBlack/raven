// Commands marshaled from the Vulkan registry; see scripts/generate-vulkan-marshal.py.
#include "vulkan_marshal.h"

#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace raven {

#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#include "vulkan_marshal_generated.inc"

uint64_t Marshal::allocate_memory(const std::vector<uint64_t> &a)
{
	context(H::VkDevice, a[0]);
	require_null(a[2]);
	auto *info = decode_array_VkMemoryAllocateInfo(*this, a[1], 1);
	if (!info->allocationSize || info->allocationSize > (256ULL << 20))
		throw std::runtime_error("unsupported Vulkan memory allocation size");
	check_writable(a[3], 8);
	VkDeviceMemory memory = VK_NULL_HANDLE;
	const auto status = vkAllocateMemory(host_device, info, nullptr, &memory);
	if (status == VK_SUCCESS) {
		const auto token_value = bridge.next_handle++;
		bridge.memories.emplace(token_value, VulkanBridge::Memory{memory, a[0], info->allocationSize});
		store<uint64_t>(a[3], token_value);
	}
	return static_cast<uint32_t>(status);
}

std::span<const std::string_view> vulkan_generated_names()
{
	static const auto names = [] {
		std::vector<std::string_view> list{"vkAllocateMemory"};
		for (const auto &command : generated_commands)
			list.emplace_back(command.name);
		std::sort(list.begin(), list.end());
		return list;
	}();
	return names;
}

void VulkanBridge::destroy_generic_objects(uint64_t device_token)
{
	const auto found = devices.find(device_token);
	if (found == devices.end())
		return;
	// Newest first: an object is destroyed before what it was built from.
	std::vector<uint64_t> owned;
	for (const auto &[token, entry] : generic)
		if (entry.device == device_token)
			owned.push_back(token);
	std::sort(owned.rbegin(), owned.rend());
	Marshal marshal(*this, process);
	marshal.context(H::VkDevice, device_token);
	for (const auto token : owned) {
		const auto entry = generic.at(token);
		try { destroy_generated_handle(marshal, static_cast<H>(entry.type), entry.host); } catch (const std::runtime_error &) {}
		generic.erase(token);
	}
}

bool vulkan_generated_is_device(std::string_view name)
{
	if (name == "vkAllocateMemory")
		return true;
	for (const auto &command : generated_commands)
		if (name == command.name)
			return command.device;
	return false;
}

bool VulkanBridge::dispatch_generated(std::string_view name)
{
	if (name == "vkAllocateMemory") {
		const auto arguments = process.api_arguments(4);
		Marshal marshal(*this, process);
		process.return_api(marshal.allocate_memory(arguments));
		return true;
	}
	for (const auto &command : generated_commands) {
		if (name != command.name)
			continue;
		const auto arguments = process.api_arguments(command.arguments);
		std::array<uint64_t, 4> floating{};
		try { floating = process.api_float_arguments(); } catch (const std::runtime_error &) {}
		Marshal marshal(*this, process);
		process.return_api(command.function(*this, marshal, arguments, floating));
		return true;
	}
	return false;
}

}

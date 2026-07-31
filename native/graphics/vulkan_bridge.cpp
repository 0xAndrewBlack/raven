#include "vulkan_bridge.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <stdexcept>

namespace raven {

static constexpr std::array<std::string_view, 6> names{
	"vkCreateInstance", "vkDestroyInstance", "vkEnumerateInstanceVersion",
	"vkEnumeratePhysicalDevices", "vkGetInstanceProcAddr", "vkGetPhysicalDeviceProperties"
};

static_assert(sizeof(VkInstanceCreateInfo) == 64 && sizeof(VkApplicationInfo) == 48);
static_assert(sizeof(VkPhysicalDeviceProperties) == 824 && offsetof(VkPhysicalDeviceProperties, limits) == 296);

std::span<const std::string_view> VulkanBridge::exports() { return names; }

VulkanBridge::~VulkanBridge()
{
	for (const auto &[token, instance] : instances)
		vkDestroyInstance(instance, nullptr);
}

std::string VulkanBridge::string(uint64_t address)
{
	std::string result;
	for (size_t index = 0; index < 4096; ++index) {
		if (address > UINT64_MAX - index)
			break;
		const auto byte = process.read_memory(address + index, 1)[0];
		if (!byte)
			return result;
		result.push_back(static_cast<char>(byte));
	}
	throw std::runtime_error("invalid Vulkan guest string");
}

bool VulkanBridge::dispatch(std::string_view name)
{
	if (std::find(names.begin(), names.end(), name) == names.end())
		return false;
	const auto arguments = process.api_arguments(name == "vkEnumerateInstanceVersion" ? 1 :
		(name == "vkCreateInstance" || name == "vkEnumeratePhysicalDevices" ? 3 : 2));
	const auto read = [&]<typename T>(uint64_t address) {
		T result{};
		const auto bytes = process.read_memory(address, sizeof(T));
		std::memcpy(&result, bytes.data(), sizeof(T));
		return result;
	};
	const auto write = [&]<typename T>(uint64_t address, const T &value) {
		process.write_memory(address, std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(&value), sizeof(T)));
	};
	const auto writable = [&](uint64_t address, size_t size) {
		process.write_memory(address, process.read_memory(address, size));
	};
	uint64_t result = 0;
	if (name == "vkEnumerateInstanceVersion") {
		writable(arguments[0], 4);
		uint32_t version = 0;
		result = static_cast<uint32_t>(vkEnumerateInstanceVersion(&version));
		write(arguments[0], version);
	} else if (name == "vkGetInstanceProcAddr") {
		if (arguments[0] && !instances.contains(arguments[0]))
			throw std::runtime_error("invalid Vulkan instance handle");
		const auto symbol = string(arguments[1]);
		const bool global = symbol == "vkCreateInstance" || symbol == "vkEnumerateInstanceVersion" || symbol == "vkGetInstanceProcAddr";
		if ((arguments[0] || global) && std::find(names.begin(), names.end(), symbol) != names.end())
			result = modules.resolve({"vulkan-1.dll", symbol, 0, false, 0});
	} else if (name == "vkCreateInstance") {
		auto info = read.template operator()<VkInstanceCreateInfo>(arguments[0]);
		if (arguments[1] || info.pNext || info.sType != VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO ||
			info.flags || info.enabledLayerCount || info.enabledExtensionCount)
			throw std::runtime_error("Vulkan allocator, pNext, flags, layers or extensions are not implemented");
		VkApplicationInfo application{};
		std::string application_name, engine_name;
		if (info.pApplicationInfo) {
			application = read.template operator()<VkApplicationInfo>(reinterpret_cast<uint64_t>(info.pApplicationInfo));
			if (application.pNext || application.sType != VK_STRUCTURE_TYPE_APPLICATION_INFO)
				throw std::runtime_error("unsupported Vulkan application info");
			if (application.pApplicationName)
				application_name = string(reinterpret_cast<uint64_t>(application.pApplicationName));
			if (application.pEngineName)
				engine_name = string(reinterpret_cast<uint64_t>(application.pEngineName));
			application.pApplicationName = application.pApplicationName ? application_name.c_str() : nullptr;
			application.pEngineName = application.pEngineName ? engine_name.c_str() : nullptr;
			info.pApplicationInfo = &application;
		}
		info.ppEnabledLayerNames = nullptr;
		info.ppEnabledExtensionNames = nullptr;
		writable(arguments[2], 8);
		VkInstance instance = VK_NULL_HANDLE;
		const auto status = vkCreateInstance(&info, nullptr, &instance);
		result = static_cast<uint32_t>(status);
		if (status == VK_SUCCESS) {
			const auto token = next_handle++;
			try {
				instances.emplace(token, instance);
				write(arguments[2], token);
			} catch (...) {
				instances.erase(token);
				vkDestroyInstance(instance, nullptr);
				throw;
			}
		}
	} else if (name == "vkDestroyInstance") {
		if (arguments[1])
			throw std::runtime_error("Vulkan guest allocation callbacks are not implemented");
		if (arguments[0]) {
			const auto found = instances.find(arguments[0]);
			if (found == instances.end())
				throw std::runtime_error("invalid Vulkan instance handle");
			vkDestroyInstance(found->second, nullptr);
			instances.erase(found);
			std::erase_if(physical, [&](const auto &item) { return item.second.instance == arguments[0]; });
		}
	} else if (name == "vkEnumeratePhysicalDevices") {
		const auto found = instances.find(arguments[0]);
		if (found == instances.end())
			throw std::runtime_error("invalid Vulkan instance handle");
		writable(arguments[1], 4);
		uint32_t count = 0;
		if (arguments[2]) {
			count = read.template operator()<uint32_t>(arguments[1]);
			if (count > 4096)
				throw std::runtime_error("Vulkan physical device capacity exceeds limit");
			writable(arguments[2], size_t(count) * 8);
		}
		std::vector<VkPhysicalDevice> devices(count);
		VkPhysicalDevice zero_capacity = VK_NULL_HANDLE;
		const auto status = vkEnumeratePhysicalDevices(found->second, &count,
			arguments[2] ? (devices.empty() ? &zero_capacity : devices.data()) : nullptr);
		result = static_cast<uint32_t>(status);
		if (status == VK_SUCCESS || status == VK_INCOMPLETE) {
			if (arguments[2]) {
				for (size_t index = 0; index < count; ++index) {
					const auto existing = std::find_if(physical.begin(), physical.end(), [&](const auto &item) {
						return item.second.instance == arguments[0] && item.second.handle == devices.at(index);
					});
					uint64_t token = existing == physical.end() ? next_handle++ : existing->first;
					if (existing == physical.end())
						physical.emplace(token, Physical{devices.at(index), arguments[0]});
					write(arguments[2] + index * 8, token);
				}
			}
			write(arguments[1], count);
		}
	} else if (name == "vkGetPhysicalDeviceProperties") {
		const auto found = physical.find(arguments[0]);
		if (found == physical.end())
			throw std::runtime_error("invalid Vulkan physical device handle");
		writable(arguments[1], sizeof(VkPhysicalDeviceProperties));
		VkPhysicalDeviceProperties properties;
		std::memset(&properties, 0, sizeof(properties));
		vkGetPhysicalDeviceProperties(found->second.handle, &properties);
		write(arguments[1], properties);
	}
	process.return_api(result);
	return true;
}

}

#include "vulkan_bridge.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <stdexcept>

namespace raven {

// The export table of the guest provider is binary searched, so the names stay in byte order.
static constexpr std::array<std::string_view, 14> names{
	"vkCreateDevice",
	"vkCreateInstance",
	"vkDestroyDevice",
	"vkDestroyInstance",
	"vkDeviceWaitIdle",
	"vkEnumerateInstanceVersion",
	"vkEnumeratePhysicalDevices",
	"vkGetDeviceProcAddr",
	"vkGetDeviceQueue",
	"vkGetInstanceProcAddr",
	"vkGetPhysicalDeviceFeatures",
	"vkGetPhysicalDeviceMemoryProperties",
	"vkGetPhysicalDeviceProperties",
	"vkGetPhysicalDeviceQueueFamilyProperties"
};
// Entry points reached through a device rather than an instance.
static constexpr std::array<std::string_view, 4> device_names{"vkDestroyDevice", "vkGetDeviceQueue", "vkDeviceWaitIdle", "vkGetDeviceProcAddr"};

static_assert(sizeof(VkInstanceCreateInfo) == 64 && sizeof(VkApplicationInfo) == 48);
static_assert(sizeof(VkDeviceCreateInfo) == 72 && sizeof(VkDeviceQueueCreateInfo) == 40 && sizeof(VkQueueFamilyProperties) == 24);
static_assert(sizeof(VkPhysicalDeviceMemoryProperties) == 520 && sizeof(VkPhysicalDeviceFeatures) == 220);
static_assert(sizeof(VkPhysicalDeviceProperties) == 824 && offsetof(VkPhysicalDeviceProperties, limits) == 296);

std::span<const std::string_view> VulkanBridge::exports() { return names; }

VulkanBridge::~VulkanBridge()
{
	while (!devices.empty())
		destroy_device(devices.begin()->first);
	for (const auto &[token, instance] : instances)
		vkDestroyInstance(instance, nullptr);
}

void VulkanBridge::destroy_device(uint64_t token)
{
	const auto found = devices.find(token);
	if (found == devices.end())
		return;
	std::erase_if(queues, [&](const auto &item) { return item.second.device == token; });
	vkDestroyDevice(found->second.handle, nullptr);
	devices.erase(found);
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
	const auto words = [&]() -> size_t {
		if (name == "vkEnumerateInstanceVersion" || name == "vkDeviceWaitIdle")
			return 1;
		if (name == "vkGetDeviceQueue" || name == "vkCreateDevice")
			return 4;
		if (name == "vkCreateInstance" || name == "vkEnumeratePhysicalDevices" || name == "vkGetPhysicalDeviceQueueFamilyProperties")
			return 3;
		return 2;
	}();
	const auto arguments = process.api_arguments(words);
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
	} else if (name == "vkGetDeviceProcAddr") {
		if (!devices.contains(arguments[0]))
			throw std::runtime_error("invalid Vulkan device handle");
		const auto symbol = string(arguments[1]);
		if (std::find(device_names.begin(), device_names.end(), symbol) != device_names.end())
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
			// A device that outlives its instance would be undefined behaviour in the host driver.
			std::vector<uint64_t> owned;
			for (const auto &[token, device] : devices)
				if (physical.contains(device.physical) && physical.at(device.physical).instance == arguments[0])
					owned.push_back(token);
			for (const auto token : owned)
				destroy_device(token);
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
	} else if (name == "vkGetPhysicalDeviceMemoryProperties" || name == "vkGetPhysicalDeviceFeatures") {
		const auto found = physical.find(arguments[0]);
		if (found == physical.end())
			throw std::runtime_error("invalid Vulkan physical device handle");
		if (name == "vkGetPhysicalDeviceMemoryProperties") {
			writable(arguments[1], sizeof(VkPhysicalDeviceMemoryProperties));
			VkPhysicalDeviceMemoryProperties memory;
			std::memset(&memory, 0, sizeof(memory));
			vkGetPhysicalDeviceMemoryProperties(found->second.handle, &memory);
			write(arguments[1], memory);
		} else {
			writable(arguments[1], sizeof(VkPhysicalDeviceFeatures));
			VkPhysicalDeviceFeatures features;
			std::memset(&features, 0, sizeof(features));
			vkGetPhysicalDeviceFeatures(found->second.handle, &features);
			write(arguments[1], features);
		}
	} else if (name == "vkGetPhysicalDeviceQueueFamilyProperties") {
		const auto found = physical.find(arguments[0]);
		if (found == physical.end())
			throw std::runtime_error("invalid Vulkan physical device handle");
		writable(arguments[1], 4);
		uint32_t count = 0;
		if (arguments[2]) {
			count = read.template operator()<uint32_t>(arguments[1]);
			if (count > 4096)
				throw std::runtime_error("Vulkan queue family capacity exceeds limit");
			writable(arguments[2], size_t(count) * sizeof(VkQueueFamilyProperties));
		}
		std::vector<VkQueueFamilyProperties> families(count);
		vkGetPhysicalDeviceQueueFamilyProperties(found->second.handle, &count, arguments[2] ? families.data() : nullptr);
		if (arguments[2])
			for (size_t index = 0; index < count && index < families.size(); ++index)
				write(arguments[2] + index * sizeof(VkQueueFamilyProperties), families[index]);
		write(arguments[1], count);
	} else if (name == "vkCreateDevice") {
		const auto found = physical.find(arguments[0]);
		if (found == physical.end())
			throw std::runtime_error("invalid Vulkan physical device handle");
		if (arguments[2])
			throw std::runtime_error("Vulkan guest allocation callbacks are not implemented");
		auto info = read.template operator()<VkDeviceCreateInfo>(arguments[1]);
		if (info.sType != VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO || info.pNext || info.flags || info.enabledLayerCount ||
			info.enabledExtensionCount || !info.queueCreateInfoCount || info.queueCreateInfoCount > 16)
			throw std::runtime_error("Vulkan device pNext, flags, layers or extensions are not implemented");
		std::vector<VkDeviceQueueCreateInfo> queue_infos(info.queueCreateInfoCount);
		std::vector<std::vector<float>> priorities(info.queueCreateInfoCount);
		for (uint32_t index = 0; index < info.queueCreateInfoCount; ++index) {
			queue_infos[index] = read.template operator()<VkDeviceQueueCreateInfo>(
				reinterpret_cast<uint64_t>(info.pQueueCreateInfos) + uint64_t(index) * sizeof(VkDeviceQueueCreateInfo));
			auto &queue = queue_infos[index];
			if (queue.sType != VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO || queue.pNext || queue.flags || !queue.queueCount || queue.queueCount > 64)
				throw std::runtime_error("unsupported Vulkan queue create info");
			priorities[index].resize(queue.queueCount);
			const auto bytes = process.read_memory(reinterpret_cast<uint64_t>(queue.pQueuePriorities), size_t(queue.queueCount) * 4);
			std::memcpy(priorities[index].data(), bytes.data(), bytes.size());
			queue.pQueuePriorities = priorities[index].data();
		}
		VkPhysicalDeviceFeatures features{};
		if (info.pEnabledFeatures) {
			features = read.template operator()<VkPhysicalDeviceFeatures>(reinterpret_cast<uint64_t>(info.pEnabledFeatures));
			info.pEnabledFeatures = &features;
		}
		info.pQueueCreateInfos = queue_infos.data();
		info.ppEnabledLayerNames = nullptr;
		info.ppEnabledExtensionNames = nullptr;
		writable(arguments[3], 8);
		VkDevice device = VK_NULL_HANDLE;
		const auto status = vkCreateDevice(found->second.handle, &info, nullptr, &device);
		result = static_cast<uint32_t>(status);
		if (status == VK_SUCCESS) {
			const auto token = next_handle++;
			try {
				devices.emplace(token, Device{device, arguments[0]});
				write(arguments[3], token);
			} catch (...) {
				devices.erase(token);
				vkDestroyDevice(device, nullptr);
				throw;
			}
		}
	} else if (name == "vkDestroyDevice") {
		if (arguments[1])
			throw std::runtime_error("Vulkan guest allocation callbacks are not implemented");
		if (arguments[0]) {
			if (!devices.contains(arguments[0]))
				throw std::runtime_error("invalid Vulkan device handle");
			destroy_device(arguments[0]);
		}
	} else if (name == "vkGetDeviceQueue") {
		const auto found = devices.find(arguments[0]);
		if (found == devices.end())
			throw std::runtime_error("invalid Vulkan device handle");
		writable(arguments[3], 8);
		VkQueue handle = VK_NULL_HANDLE;
		vkGetDeviceQueue(found->second.handle, uint32_t(arguments[1]), uint32_t(arguments[2]), &handle);
		if (!handle)
			throw std::runtime_error("Vulkan queue was not requested at device creation");
		const auto existing = std::find_if(queues.begin(), queues.end(), [&](const auto &item) {
			return item.second.device == arguments[0] && item.second.family == uint32_t(arguments[1]) && item.second.index == uint32_t(arguments[2]);
		});
		uint64_t token = existing == queues.end() ? next_handle++ : existing->first;
		if (existing == queues.end())
			queues.emplace(token, Queue{handle, arguments[0], uint32_t(arguments[1]), uint32_t(arguments[2])});
		write(arguments[3], token);
	} else if (name == "vkDeviceWaitIdle") {
		const auto found = devices.find(arguments[0]);
		if (found == devices.end())
			throw std::runtime_error("invalid Vulkan device handle");
		result = static_cast<uint32_t>(vkDeviceWaitIdle(found->second.handle));
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

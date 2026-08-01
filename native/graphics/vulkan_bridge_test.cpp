#include "vulkan_bridge.h"
#include "nt/providers.h"

#include <array>
#include <cstring>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <sys/mman.h>

static void check(bool condition, const char *message)
{
	if (!condition)
		throw std::runtime_error(message);
}

int main(int argc, char **argv)
{
	try {
		check(argc == 3, "bootstrap and Vulkan fixture required");
		std::ifstream file(argv[2], std::ios::binary | std::ios::ate);
		check(file && file.tellg() > 0 && file.tellg() <= 1024 * 1024, "cannot read Vulkan fixture");
		std::vector<uint8_t> bytes(static_cast<size_t>(file.tellg()));
		file.seekg(0);
		check(bool(file.read(reinterpret_cast<char *>(bytes.data()), static_cast<std::streamsize>(bytes.size()))), "truncated Vulkan fixture");
		raven::ModuleSet modules;
		const auto base = raven::PEImage(bytes).image_base;
		auto &entry = modules.add("client.exe", std::move(bytes), base);
		const auto executed = raven::run_native_process(modules, entry, argv[1], std::chrono::seconds(5));
		check(executed.stop == raven::NativeStop::returned && executed.value == 0, "compiled Vulkan workflow failed");
		const auto field = [&]<typename T>(const std::string &name) {
			T value{};
			const auto offset = modules.resolve({"client.exe", name, 0, false, 0}) - base;
			const auto data = entry.loaded.data().subspan(offset, sizeof(T));
			std::memcpy(&value, data.data(), sizeof(T));
			return value;
		};
		uint32_t version = 0;
		check(vkEnumerateInstanceVersion(&version) == VK_SUCCESS && version == field.template operator()<uint32_t>("loader_version"), "guest loader version differs from host");
		VkInstanceCreateInfo info{};
		info.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
		VkInstance reference = VK_NULL_HANDLE;
		check(vkCreateInstance(&info, nullptr, &reference) == VK_SUCCESS, "host reference instance failed");
		VkPhysicalDeviceProperties expected{};
		uint32_t count = 0;
		const auto count_status = vkEnumeratePhysicalDevices(reference, &count, nullptr);
		std::vector<VkPhysicalDevice> devices(count);
		const auto devices_status = vkEnumeratePhysicalDevices(reference, &count, devices.data());
		if (count_status == VK_SUCCESS && devices_status == VK_SUCCESS && count)
			vkGetPhysicalDeviceProperties(devices[0], &expected);
		VkPhysicalDeviceMemoryProperties expected_memory{};
		VkPhysicalDeviceFeatures expected_features{};
		std::vector<VkQueueFamilyProperties> expected_families;
		if (count) {
			vkGetPhysicalDeviceMemoryProperties(devices[0], &expected_memory);
			vkGetPhysicalDeviceFeatures(devices[0], &expected_features);
			uint32_t family_total = 0;
			vkGetPhysicalDeviceQueueFamilyProperties(devices[0], &family_total, nullptr);
			expected_families.resize(family_total);
			vkGetPhysicalDeviceQueueFamilyProperties(devices[0], &family_total, expected_families.data());
		}
		vkDestroyInstance(reference, nullptr);
		check(count_status == VK_SUCCESS && devices_status == VK_SUCCESS && count == field.template operator()<uint32_t>("device_count"), "guest physical device count differs from host");
		const auto observed = field.template operator()<VkPhysicalDeviceProperties>("observed");
		check(observed.apiVersion == expected.apiVersion && observed.vendorID == expected.vendorID &&
			observed.deviceID == expected.deviceID && observed.deviceType == expected.deviceType &&
			std::strcmp(observed.deviceName, expected.deviceName) == 0 &&
			observed.limits.maxImageDimension2D == expected.limits.maxImageDimension2D &&
			observed.limits.maxMemoryAllocationCount == expected.limits.maxMemoryAllocationCount,
			"guest physical device properties differ from host");
		const auto families = field.template operator()<std::array<VkQueueFamilyProperties, 16>>("families");
		check(field.template operator()<uint32_t>("family_count") == expected_families.size() && !expected_families.empty(), "guest queue family count differs from host");
		for (size_t index = 0; index < expected_families.size(); ++index)
			check(families[index].queueFlags == expected_families[index].queueFlags && families[index].queueCount == expected_families[index].queueCount &&
				families[index].timestampValidBits == expected_families[index].timestampValidBits, "guest queue family differs from host");
		const auto memory_observed = field.template operator()<VkPhysicalDeviceMemoryProperties>("memory_properties");
		check(memory_observed.memoryTypeCount == expected_memory.memoryTypeCount && memory_observed.memoryHeapCount == expected_memory.memoryHeapCount &&
			std::memcmp(memory_observed.memoryTypes, expected_memory.memoryTypes, sizeof(expected_memory.memoryTypes)) == 0 &&
			std::memcmp(memory_observed.memoryHeaps, expected_memory.memoryHeaps, sizeof(expected_memory.memoryHeaps)) == 0, "guest memory properties differ from host");
		const auto features_observed = field.template operator()<VkPhysicalDeviceFeatures>("features");
		check(std::memcmp(&features_observed, &expected_features, sizeof(expected_features)) == 0, "guest device features differ from host");
		check(field.template operator()<uint32_t>("copy_workflow") == 1 && field.template operator()<uint32_t>("copy_fence_waits") == 1, "guest buffer copy through the device did not complete");
		const auto copied = field.template operator()<std::array<uint8_t, 256>>("copied");
		for (size_t index = 0; index < copied.size(); ++index)
			check(copied[index] == uint8_t(index * 7 + 3), "device copied different bytes than the guest wrote");
		check(field.template operator()<uint32_t>("device_workflow") == 1, "guest logical device workflow did not complete");
		std::vector<raven::LoadedImage *> images;
		for (const auto &[name, module] : modules.all())
			images.push_back(&module->loaded);
		raven::NativeProcess process(images, argv[1], std::chrono::seconds(2));
		raven::VulkanBridge bridge(process, modules);
		for (const auto &symbol : modules.all().at("vulkan-1.dll")->exports)
			process.add_api_trap(modules.resolve({"vulkan-1.dll", symbol.names.front(), 0, false, 0}));
		const auto memory = process.map_memory(4096, PROT_READ | PROT_WRITE);
		const auto rejected = [&](const std::string &name, std::span<const uint64_t> arguments) {
			const auto address = modules.resolve({"vulkan-1.dll", name, 0, false, 0});
			check(process.call(address, arguments, std::chrono::seconds(2)).stop == raven::NativeStop::api, "Vulkan negative test did not stop");
			bool failed = false;
			try { bridge.dispatch(name); } catch (const std::runtime_error &) { failed = true; }
			check(failed, "invalid Vulkan guest operation returned apparent success");
			process.return_api(0);
			check(process.resume(std::chrono::seconds(2)).stop == raven::NativeStop::returned, "negative Vulkan test did not restore guest caller");
		};
		const uint64_t forged[] = {0x1234, memory};
		rejected("vkGetPhysicalDeviceProperties", forged);
		const uint64_t bad_string[] = {0, UINT64_MAX};
		rejected("vkGetInstanceProcAddr", bad_string);
		process.write_memory(memory, std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(&info), sizeof(info)));
		const uint64_t allocator[] = {memory, 1, memory + 256};
		rejected("vkCreateInstance", allocator);
		const uint64_t bad_output[] = {memory, 0, UINT64_MAX};
		rejected("vkCreateInstance", bad_output);
		// Logical devices: forged handles, allocators and unimplemented create-info fields all fail before reaching the driver.
		const uint64_t forged_device[] = {0x4321, 0, 0, memory};
		rejected("vkGetDeviceQueue", forged_device);
		const uint64_t forged_wait[] = {0x4321};
		rejected("vkDeviceWaitIdle", forged_wait);
		const uint64_t forged_create[] = {0x1234, memory, 0, memory + 512};
		rejected("vkCreateDevice", forged_create);
		const uint64_t forged_proc[] = {0x4321, memory};
		rejected("vkGetDeviceProcAddr", forged_proc);
		const uint64_t forged_buffer[] = {0x4321, 0x7777, memory, 0};
		rejected("vkCreateBuffer", forged_buffer);
		const uint64_t forged_submit[] = {0x4321, 1, memory, 0};
		rejected("vkQueueSubmit", forged_submit);
		const uint64_t forged_queue[] = {0x4321};
		rejected("vkQueueWaitIdle", forged_queue);
		const uint64_t forged_map[] = {0x4321, 0x7777, 0, 4096, 0, memory};
		rejected("vkMapMemory", forged_map);
		const uint64_t forged_command[] = {0x7777, memory};
		rejected("vkBeginCommandBuffer", forged_command);
		process.unmap_memory(memory);
		std::cout << "Guest Vulkan instance, logical device, queues, memory and feature queries, stable physical handles, zero-capacity enumeration and checked negatives match host " << expected.deviceName << '\n';
		return 0;
	} catch (const std::exception &error) {
		std::cerr << error.what() << '\n';
		return 1;
	}
}

#include "vulkan_bridge.h"
#include "nt/providers.h"

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
		vkDestroyInstance(reference, nullptr);
		check(count_status == VK_SUCCESS && devices_status == VK_SUCCESS && count == field.template operator()<uint32_t>("device_count"), "guest physical device count differs from host");
		const auto observed = field.template operator()<VkPhysicalDeviceProperties>("observed");
		check(observed.apiVersion == expected.apiVersion && observed.vendorID == expected.vendorID &&
			observed.deviceID == expected.deviceID && observed.deviceType == expected.deviceType &&
			std::strcmp(observed.deviceName, expected.deviceName) == 0 &&
			observed.limits.maxImageDimension2D == expected.limits.maxImageDimension2D &&
			observed.limits.maxMemoryAllocationCount == expected.limits.maxMemoryAllocationCount,
			"guest physical device properties differ from host");
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
		process.unmap_memory(memory);
		std::cout << "Guest Vulkan instance, stable physical handles, zero-capacity enumeration and checked negatives match host " << expected.deviceName << '\n';
		return 0;
	} catch (const std::exception &error) {
		std::cerr << error.what() << '\n';
		return 1;
	}
}

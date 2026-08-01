#pragma once

#include "cpu/native_cpu.h"
#include "pe/module_set.h"
#include <vulkan/vulkan.h>

namespace raven {

class VulkanBridge {
public:
	VulkanBridge(NativeProcess &process, const ModuleSet &modules) : process(process), modules(modules) {}
	~VulkanBridge();
	VulkanBridge(const VulkanBridge &) = delete;
	VulkanBridge &operator=(const VulkanBridge &) = delete;
	static std::span<const std::string_view> exports();
	bool dispatch(std::string_view name);

private:
	NativeProcess &process;
	const ModuleSet &modules;
	std::map<uint64_t, VkInstance> instances;
	struct Physical { VkPhysicalDevice handle; uint64_t instance; };
	std::map<uint64_t, Physical> physical;
	struct Device { VkDevice handle; uint64_t physical; };
	std::map<uint64_t, Device> devices;
	struct Queue { VkQueue handle; uint64_t device; uint32_t family, index; };
	std::map<uint64_t, Queue> queues;
	uint64_t next_handle = 0x5600000000000001ULL;
	void destroy_device(uint64_t token);
	std::string string(uint64_t address);
};

}

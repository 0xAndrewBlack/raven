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
	uint64_t next_handle = 0x5600000000000001ULL;
	std::string string(uint64_t address);
};

}

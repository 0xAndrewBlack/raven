#pragma once

#include "cpu/native_cpu.h"
#include "pe/module_set.h"
#include <cstring>
#include <vulkan/vulkan.h>

namespace raven {

// Names of the memory, buffer, command and synchronisation entry points, in byte order.
std::span<const std::string_view> vulkan_resource_names();
std::span<const std::string_view> vulkan_compute_names();

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
	// Device memory with the guest-visible shadow that stands in for a host mapping, and the other resources a guest device owns.
	struct Memory {
		VkDeviceMemory handle; uint64_t device; VkDeviceSize size;
		void *host = nullptr; uint64_t shadow = 0; VkDeviceSize offset = 0, mapped = 0;
		std::vector<uint8_t> snapshot;
	};
	std::map<uint64_t, Memory> memories;
	struct Buffer { VkBuffer handle; uint64_t device; };
	std::map<uint64_t, Buffer> buffers;
	struct Pool { VkCommandPool handle; uint64_t device; };
	std::map<uint64_t, Pool> pools;
	struct CommandBuffer { VkCommandBuffer handle; uint64_t device, pool; };
	std::map<uint64_t, CommandBuffer> command_buffers;
	struct Fence { VkFence handle; uint64_t device; };
	std::map<uint64_t, Fence> fences;
	// Shader modules, descriptor and pipeline objects: one host handle each, owned by a device token.
	enum class Kind { shader, set_layout, pipeline_layout, pipeline, pool, set };
	struct Object { uint64_t handle; uint64_t device; Kind kind; uint64_t parent = 0; };
	std::map<uint64_t, Object> objects;
	bool dispatch_compute(std::string_view name);
	void destroy_object(const VkDevice &device, const Object &object);
	uint64_t next_handle = 0x5600000000000001ULL;
	void destroy_device(uint64_t token);
	// Copies between a guest shadow and the host mapping behind it, moving only the bytes that changed on one side.
	void shadow_to_device(uint64_t device);
	void shadow_from_device(uint64_t device);
	bool dispatch_resource(std::string_view name);
	template<typename T> T load(uint64_t address) const;
	template<typename T> void store(uint64_t address, const T &value) const;
	void check_writable(uint64_t address, size_t size) const;
	std::string string(uint64_t address);
};

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

}

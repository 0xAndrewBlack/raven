#pragma once

#include "cpu/native_cpu.h"
#include "pe/module_set.h"
#include <cstring>
#include <functional>
#include <optional>
#include <vulkan/vulkan.h>

namespace raven {

// Names of the memory, buffer, command and synchronisation entry points, in byte order.
std::span<const std::string_view> vulkan_resource_names();
std::span<const std::string_view> vulkan_enumerate_names();
std::span<const std::string_view> vulkan_query_names();
// Entry points written by hand on top of the generated ones: Windows surfaces over host windows and updates through descriptor templates.
std::span<const std::string_view> vulkan_hand_names();
// Commands marshaled from the Vulkan registry; empty when the registry was not available at build time.
std::span<const std::string_view> vulkan_generated_names();
bool vulkan_generated_is_device(std::string_view name);

class VulkanBridge {
public:
	VulkanBridge(NativeProcess &process, const ModuleSet &modules) : process(process), modules(modules) {}
	~VulkanBridge();
	VulkanBridge(const VulkanBridge &) = delete;
	VulkanBridge &operator=(const VulkanBridge &) = delete;
	static std::span<const std::string_view> exports();
	bool dispatch(std::string_view name);
	// Where a guest window's presentable surface comes from: the host display and surface that sit over the window, or nothing when the
	// host does not show it. Without a source a guest cannot create surfaces.
	struct SurfaceSource {
		std::function<std::optional<std::pair<void *, void *>>(uint64_t window)> create;
		std::function<void(uint64_t window)> release;
	};
	void set_surface_source(SurfaceSource value) { surface_source = std::move(value); }

	friend class Marshal;
	// Brings the guest's view of mapped memory and the driver's in line before and after work the driver does.
	void synchronize_to_device(uint64_t device) { shadow_to_device(device); }
	void synchronize_from_device(uint64_t device) { shadow_from_device(device); }

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
	enum class Kind { shader, set_layout, pipeline_layout, pipeline, pool, set, image, image_view, semaphore, render_pass, framebuffer, sampler };
	struct Object { uint64_t handle; uint64_t device; Kind kind; uint64_t parent = 0; bool borrowed = false; };
	std::map<uint64_t, Object> objects;
	bool dispatch_enumerate(std::string_view name);
	bool dispatch_hand(std::string_view name);
	SurfaceSource surface_source;
	// Surface tokens and the guest windows behind them.
	std::map<uint64_t, uint64_t> surface_windows;
	// What each descriptor update template writes, for updates that pass handles in raw data.
	std::map<uint64_t, std::vector<VkDescriptorUpdateTemplateEntry>> templates;
public:
	void remember_template(uint64_t token, const VkDescriptorUpdateTemplateCreateInfo *info);
private:
	bool dispatch_queries(std::string_view name);
	// A pNext chain of plain structures mirrored into host memory: the guest address of each element and a host copy of it.
	struct ChainEntry { uint64_t guest; std::vector<uint8_t> host; };
	std::vector<ChainEntry> mirror_chain(uint64_t first, bool strict) const;
	// Links the host copies and returns the first one, or null for an empty chain.
	static void *link_chain(std::vector<ChainEntry> &chain);
	// Writes what the host filled in back to the guest structures, leaving their sType and pNext alone.
	void copy_back_chain(const std::vector<ChainEntry> &chain) const;
	// Host names for the extension names a guest enables; false when one is not offered to guests.
	bool host_extension_names(const std::vector<std::string> &guest, bool device, std::vector<std::string> &host) const;
	void destroy_object(const VkDevice &device, const Object &object);
	// Objects created by generated commands that no hand-written map owns.
	struct Generic { uint64_t host; uint8_t type; uint64_t device; };
	std::map<uint64_t, Generic> generic;
	bool dispatch_generated(std::string_view name);
	void destroy_generic_objects(uint64_t device_token);
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

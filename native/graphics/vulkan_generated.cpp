// Commands marshaled from the Vulkan registry; see scripts/generate-vulkan-marshal.py.
#include "vulkan_marshal.h"
#include <vulkan/vulkan_wayland.h>

#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <sys/mman.h>
#include <unistd.h>

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
	VulkanBridge::Memory record{VK_NULL_HANDLE, a[0], info->allocationSize};
	// A plain host-visible allocation on a device that imports host memory comes from a memfd the guest will map as it is.
	const auto &device = bridge.devices.at(a[0]);
	// Allocation flags and priorities travel along with an import; any other structure (a dedicated allocation, an export) keeps the copy.
	bool importable = device.host_import && info->memoryTypeIndex < 32 && (device.host_visible_types >> info->memoryTypeIndex & 1);
	for (auto *next = static_cast<const VkBaseInStructure *>(info->pNext); next && importable; next = next->pNext)
		importable = next->sType == VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_FLAGS_INFO || next->sType == VK_STRUCTURE_TYPE_MEMORY_PRIORITY_ALLOCATE_INFO_EXT;
	if (importable) {
		const size_t size = size_t((info->allocationSize + device.import_alignment - 1) / device.import_alignment * device.import_alignment);
		const int file = memfd_create("raven-vulkan-memory", MFD_CLOEXEC);
		void *host = MAP_FAILED;
		if (file >= 0 && ftruncate(file, off_t(size)) == 0) {
			// The mapping starts at the alignment the driver asks for: a reservation large enough to hold an aligned window of the file.
			void *reserve = mmap(nullptr, size + device.import_alignment, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
			if (reserve != MAP_FAILED) {
				const auto start = (reinterpret_cast<uintptr_t>(reserve) + device.import_alignment - 1) / device.import_alignment * device.import_alignment;
				host = mmap(reinterpret_cast<void *>(start), size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, file, 0);
				if (start > reinterpret_cast<uintptr_t>(reserve))
					munmap(reserve, start - reinterpret_cast<uintptr_t>(reserve));
				const auto end = reinterpret_cast<uintptr_t>(reserve) + size + device.import_alignment;
				if (end > start + size)
					munmap(reinterpret_cast<void *>(start + size), end - (start + size));
			}
		}
		VkMemoryHostPointerPropertiesEXT pointer{VK_STRUCTURE_TYPE_MEMORY_HOST_POINTER_PROPERTIES_EXT};
		if (host != MAP_FAILED && device.host_pointer_properties(host_device, VK_EXTERNAL_MEMORY_HANDLE_TYPE_HOST_ALLOCATION_BIT_EXT, host, &pointer) == VK_SUCCESS &&
			(pointer.memoryTypeBits >> info->memoryTypeIndex & 1)) {
			VkImportMemoryHostPointerInfoEXT import{VK_STRUCTURE_TYPE_IMPORT_MEMORY_HOST_POINTER_INFO_EXT, info->pNext,
				VK_EXTERNAL_MEMORY_HANDLE_TYPE_HOST_ALLOCATION_BIT_EXT, host};
			VkMemoryAllocateInfo imported = *info;
			imported.pNext = &import;
			imported.allocationSize = size;
			if (vkAllocateMemory(host_device, &imported, nullptr, &memory) == VK_SUCCESS) {
				record.import_file = file;
				record.import_host = static_cast<uint8_t *>(host);
				record.import_size = size;
			}
		}
		if (!record.import_host) {
			memory = VK_NULL_HANDLE;
			if (host != MAP_FAILED)
				munmap(host, size);
			if (file >= 0)
				close(file);
		}
	}
	const auto status = memory ? VK_SUCCESS : vkAllocateMemory(host_device, info, nullptr, &memory);
	if (status == VK_SUCCESS) {
		const auto token_value = bridge.next_handle++;
		record.handle = memory;
		bridge.memories.emplace(token_value, record);
		store<uint64_t>(a[3], token_value);
	} else {
		VulkanBridge::release_import(record);
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

std::span<const std::string_view> vulkan_hand_names()
{
	static constexpr std::array<std::string_view, 4> names{"vkCreateWin32SurfaceKHR", "vkGetPhysicalDeviceWin32PresentationSupportKHR",
		"vkUpdateDescriptorSetWithTemplate", "vkUpdateDescriptorSetWithTemplateKHR"};
	// The swapchain commands below wrap the generated ones; they are dispatched here first and export under their own names.
	return names;
}

// A Windows surface over a guest HWND becomes a Wayland surface over the host window that shows it.
bool VulkanBridge::dispatch_hand(std::string_view name)
{
	if (name == "vkCreateWin32SurfaceKHR") {
		const auto a = process.api_arguments(4);
		Marshal marshal(*this, process);
		marshal.context(H::VkInstance, a[0]);
		marshal.require_null(a[2]);
		marshal.check_writable(a[3], 8);
		// VkWin32SurfaceCreateInfoKHR: sType, pNext, flags, hinstance, hwnd.
		if (load<uint32_t>(a[1]) != VK_STRUCTURE_TYPE_WIN32_SURFACE_CREATE_INFO_KHR)
			throw std::runtime_error("vkCreateWin32SurfaceKHR needs a Win32 surface create info");
		const auto window = load<uint64_t>(a[1] + 32);
		uint32_t status = static_cast<uint32_t>(VK_ERROR_INITIALIZATION_FAILED);
		const auto host = surface_source.create ? surface_source.create(window) : std::nullopt;
		if (host) {
			VkWaylandSurfaceCreateInfoKHR info{VK_STRUCTURE_TYPE_WAYLAND_SURFACE_CREATE_INFO_KHR, nullptr, 0,
				static_cast<struct wl_display *>(host->first), static_cast<struct wl_surface *>(host->second)};
			VkSurfaceKHR surface = VK_NULL_HANDLE;
			const auto created = marshal.proc<PFN_vkCreateWaylandSurfaceKHR>("vkCreateWaylandSurfaceKHR")(marshal.host_instance, &info, nullptr, &surface);
			status = static_cast<uint32_t>(created);
			if (created == VK_SUCCESS) {
				const auto token = marshal.new_token(H::VkSurfaceKHR, reinterpret_cast<uint64_t>(surface));
				surface_windows.emplace(token, window);
				surface_instances.emplace(token, a[0]);
				store<uint64_t>(a[3], token);
			} else if (surface_source.release) {
				surface_source.release(window);
			}
		}
		process.return_api(status);
		return true;
	}
	if (name == "vkGetPhysicalDeviceWin32PresentationSupportKHR") {
		auto a = process.api_arguments(2);
		a[1] = static_cast<uint32_t>(a[1]);
		const auto found = physical.find(a[0]);
		if (found == physical.end())
			throw std::runtime_error("invalid Vulkan physical device handle");
		uint32_t count = 0;
		vkGetPhysicalDeviceQueueFamilyProperties(found->second.handle, &count, nullptr);
		std::vector<VkQueueFamilyProperties> families(count);
		vkGetPhysicalDeviceQueueFamilyProperties(found->second.handle, &count, families.data());
		// Presentation goes through the host window the surface is created over; a family can present when it can draw.
		process.return_api(a[1] < count && (families[a[1]].queueFlags & VK_QUEUE_GRAPHICS_BIT) ? VK_TRUE : VK_FALSE);
		return true;
	}
	// A Windows surface reports the client area of its window as its only extent and a swapchain of another size is out of date.
	// The Wayland surface behind it has no extent of its own, so the window's size stands in for it.
	if (name == "vkGetPhysicalDeviceSurfaceCapabilitiesKHR" || name == "vkCreateSwapchainKHR" || name == "vkAcquireNextImageKHR" ||
		name == "vkQueuePresentKHR") {
		const auto arguments = process.api_arguments(name == "vkAcquireNextImageKHR" ? 6 : name == "vkCreateSwapchainKHR" ? 4 : 3);
		std::array<uint64_t, 4> floating{};
		try { floating = process.api_float_arguments(); } catch (const std::runtime_error &) {}
		Marshal marshal(*this, process);
		const auto window_size = [&](uint64_t surface) -> std::optional<std::pair<uint32_t, uint32_t>> {
			const auto window = surface_windows.find(surface);
			if (window == surface_windows.end() || !surface_source.size)
				return std::nullopt;
			return surface_source.size(window->second);
		};
		uint64_t result = 0;
		if (name == "vkGetPhysicalDeviceSurfaceCapabilitiesKHR") {
			result = cmd_vkGetPhysicalDeviceSurfaceCapabilitiesKHR(*this, marshal, arguments, floating);
			if (static_cast<int32_t>(result) == VK_SUCCESS)
				if (const auto size = window_size(arguments[1])) {
					// VkSurfaceCapabilitiesKHR: minImageCount, maxImageCount, then currentExtent, minImageExtent and maxImageExtent.
					for (const uint64_t offset : {8, 16, 24}) {
						store<uint32_t>(arguments[2] + offset, size->first);
						store<uint32_t>(arguments[2] + offset + 4, size->second);
					}
				}
		} else if (name == "vkCreateSwapchainKHR") {
			result = cmd_vkCreateSwapchainKHR(*this, marshal, arguments, floating);
			if (static_cast<int32_t>(result) == VK_SUCCESS) {
				// VkSwapchainCreateInfoKHR: surface at 24 and imageExtent at 44.
				const auto token = load<uint64_t>(arguments[3]);
				swapchains[token] = {load<uint64_t>(arguments[1] + 24), load<uint32_t>(arguments[1] + 44), load<uint32_t>(arguments[1] + 48)};
			}
		} else if (name == "vkAcquireNextImageKHR") {
			result = swapchain_stale(arguments[1]) ? static_cast<uint32_t>(VK_ERROR_OUT_OF_DATE_KHR)
				: cmd_vkAcquireNextImageKHR(*this, marshal, arguments, floating);
		} else {
			result = cmd_vkQueuePresentKHR(*this, marshal, arguments, floating);
			if (static_cast<int32_t>(result) == VK_SUCCESS) {
				// VkPresentInfoKHR: swapchainCount at 32 and pSwapchains at 40.
				const auto count = load<uint32_t>(arguments[1] + 32);
				const auto list = load<uint64_t>(arguments[1] + 40);
				for (uint32_t index = 0; index < count; ++index)
					if (swapchain_stale(load<uint64_t>(list + uint64_t(index) * 8)))
						result = static_cast<uint32_t>(VK_SUBOPTIMAL_KHR);
			}
		}
		process.return_api(result);
		return true;
	}
	if (name == "vkUpdateDescriptorSetWithTemplate" || name == "vkUpdateDescriptorSetWithTemplateKHR") {
		const auto a = process.api_arguments(4);
		Marshal marshal(*this, process);
		marshal.context(H::VkDevice, a[0]);
		const auto set = marshal.host(H::VkDescriptorSet, a[1]);
		const auto host_template = marshal.host(H::VkDescriptorUpdateTemplate, a[2]);
		const auto entries = templates.find(a[2]);
		if (entries == templates.end())
			throw std::runtime_error("descriptor update template was not created through the bridge");
		// The guest data holds guest handle tokens where the entries say descriptors live; the driver gets the same layout with host handles.
		size_t extent = 0;
		const auto element_size = [](VkDescriptorType type) -> size_t {
			switch (type) {
			case VK_DESCRIPTOR_TYPE_UNIFORM_TEXEL_BUFFER: case VK_DESCRIPTOR_TYPE_STORAGE_TEXEL_BUFFER: return 8;
			case VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER: case VK_DESCRIPTOR_TYPE_STORAGE_BUFFER: case VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER_DYNAMIC:
			case VK_DESCRIPTOR_TYPE_STORAGE_BUFFER_DYNAMIC: return sizeof(VkDescriptorBufferInfo);
			case VK_DESCRIPTOR_TYPE_SAMPLER: case VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER: case VK_DESCRIPTOR_TYPE_SAMPLED_IMAGE:
			case VK_DESCRIPTOR_TYPE_STORAGE_IMAGE: case VK_DESCRIPTOR_TYPE_INPUT_ATTACHMENT: return sizeof(VkDescriptorImageInfo);
			default: throw std::runtime_error("unsupported descriptor type in a template update");
			}
		};
		for (const auto &entry : entries->second)
			if (entry.descriptorCount)
				extent = std::max(extent, entry.offset + (entry.descriptorCount - 1) * entry.stride + element_size(entry.descriptorType));
		std::vector<uint8_t> data(extent, 0);
		for (const auto &entry : entries->second)
			for (uint32_t index = 0; index < entry.descriptorCount; ++index) {
				const auto at = entry.offset + size_t(index) * entry.stride;
				const auto guest = a[3] + at;
				if (entry.descriptorType == VK_DESCRIPTOR_TYPE_UNIFORM_TEXEL_BUFFER || entry.descriptorType == VK_DESCRIPTOR_TYPE_STORAGE_TEXEL_BUFFER) {
					const uint64_t view = marshal.host(H::VkBufferView, marshal.load<uint64_t>(guest));
					std::memcpy(data.data() + at, &view, 8);
				} else if (entry.descriptorType == VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER || entry.descriptorType == VK_DESCRIPTOR_TYPE_STORAGE_BUFFER ||
					entry.descriptorType == VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER_DYNAMIC || entry.descriptorType == VK_DESCRIPTOR_TYPE_STORAGE_BUFFER_DYNAMIC) {
					auto info = marshal.load<VkDescriptorBufferInfo>(guest);
					info.buffer = reinterpret_cast<VkBuffer>(marshal.host(H::VkBuffer, reinterpret_cast<uint64_t>(info.buffer)));
					std::memcpy(data.data() + at, &info, sizeof info);
				} else {
					auto info = marshal.load<VkDescriptorImageInfo>(guest);
					// Only the members the descriptor type reads are handles; the others are not initialised by programs and stay null.
					const bool uses_sampler = entry.descriptorType == VK_DESCRIPTOR_TYPE_SAMPLER || entry.descriptorType == VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER;
					const bool uses_view = entry.descriptorType != VK_DESCRIPTOR_TYPE_SAMPLER;
					info.sampler = uses_sampler ? reinterpret_cast<VkSampler>(marshal.host(H::VkSampler, reinterpret_cast<uint64_t>(info.sampler))) : VK_NULL_HANDLE;
					info.imageView = uses_view ? reinterpret_cast<VkImageView>(marshal.host(H::VkImageView, reinterpret_cast<uint64_t>(info.imageView))) : VK_NULL_HANDLE;
					std::memcpy(data.data() + at, &info, sizeof info);
				}
			}
		marshal.proc<PFN_vkUpdateDescriptorSetWithTemplate>("vkUpdateDescriptorSetWithTemplate")(marshal.host_device,
			reinterpret_cast<VkDescriptorSet>(set), reinterpret_cast<VkDescriptorUpdateTemplate>(host_template), data.data());
		process.return_api(0);
		return true;
	}
	return false;
}

bool VulkanBridge::swapchain_stale(uint64_t swapchain) const
{
	const auto found = swapchains.find(swapchain);
	if (found == swapchains.end() || !surface_source.size)
		return false;
	const auto window = surface_windows.find(found->second.surface);
	if (window == surface_windows.end())
		return false;
	const auto size = surface_source.size(window->second);
	return size && (size->first != found->second.width || size->second != found->second.height);
}

void VulkanBridge::remember_template(uint64_t token, const VkDescriptorUpdateTemplateCreateInfo *info)
{
	templates[token].assign(info->pDescriptorUpdateEntries, info->pDescriptorUpdateEntries + info->descriptorUpdateEntryCount);
}

bool vulkan_generated_is_device(std::string_view name)
{
	if (name == "vkAllocateMemory" || name == "vkUpdateDescriptorSetWithTemplate" || name == "vkUpdateDescriptorSetWithTemplateKHR")
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

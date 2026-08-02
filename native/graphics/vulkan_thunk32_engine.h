#pragma once

#include "vulkan_bridge.h"
#include "vulkan_thunk32.h"

#include <map>
#include <string_view>
#include <vector>

namespace raven {

// Vulkan for 32-bit programs: a call arrives with 32-bit stdcall arguments, is rebuilt in the layout the bridge reads (in a scratch region
// of the guest address space), is run by the bridge as if a 64-bit program had made it, and what the driver filled is copied back.
class VulkanThunk32 {
public:
	VulkanThunk32(NativeProcess &process, VulkanBridge &bridge);
	// The commands a 32-bit program can import with their word counts, limited to what the bridge implements (sorted names).
	static std::vector<std::pair<std::string_view, uint32_t>> exports(std::span<const std::string_view> bridge_names);
	bool dispatch(std::string_view name);

private:
	struct Record {
		uint16_t structure;
		uint64_t guest, converted;
		size_t count;
	};
	struct Context {
		const uint8_t *image;
		const std::vector<uint64_t> *words;
		uint32_t first_param;
	};
	NativeProcess &process;
	VulkanBridge &bridge;
	uint64_t scratch = 0, cursor = 0;
	std::vector<Record> tracked;
	std::map<uint64_t, uint32_t> handles;
	std::map<uint32_t, uint64_t> tokens;
	uint32_t next_handle = 0x00a10008;
	uint64_t allocate(size_t bytes);
	uint64_t token_of(uint32_t handle);
	uint32_t handle_of(uint64_t token);
	uint64_t evaluate(uint32_t program, const Context &context);
	uint64_t convert(uint16_t index, uint64_t guest, size_t count, bool track);
	uint64_t convert_chain(uint64_t guest, bool track);
	void convert_elements(const thunk32::StructInfo &structure, const uint8_t *source, uint8_t *target, bool track);
	void restore(const thunk32::StructInfo &structure, const uint8_t *source, uint8_t *target);
	void write_back();
	bool dispatch_surface(std::string_view name);
};

}

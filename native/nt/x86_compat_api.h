#pragma once

#include "desktop/windows.h"
#include "environment.h"

#include <map>
#include <vector>

namespace raven {

// Services a 32-bit program needs beyond the shared handlers: the process heap, and the ANSI forms of the window functions, which
// widen their strings and forward to the wide handler.
class NativeX86Compat {
public:
	NativeX86Compat(NativeProcess &process, NativeEnvironment &environment, NativeWindows &windows);
	bool dispatch(std::string_view name);
	static std::span<const std::pair<std::string_view, uint32_t>> exports();

private:
	NativeProcess &process;
	NativeEnvironment &environment;
	NativeWindows &windows;
	// Free blocks by payload size, and the bump region new blocks are cut from.
	std::map<uint32_t, std::vector<uint64_t>> free_blocks;
	uint64_t region = 0, region_left = 0;
	uint64_t scratch = 0, environment_block = 0;
	size_t scratch_slot = 0;
	uint64_t heap_alloc(uint32_t size, bool zero);
	void heap_free(uint64_t address);
	uint32_t block_size(uint64_t address) const;
	uint64_t scratch_base();
	uint32_t widen(uint64_t address);
	bool forward(std::string_view wide_name);
};

}

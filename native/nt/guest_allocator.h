#pragma once

#include "heap.h"
#include "memory.h"

#include <map>

namespace raven {

// Guest memory for blocks that host handlers hand to the program (LocalAlloc, GlobalAlloc, message buffers).
// Blocks come from the process heap when the RTL component provides one, otherwise from private pages.
class GuestAllocator {
public:
	GuestAllocator(NativeMemory &memory, NativeHeap &heap) : memory(memory), heap(heap) {}
	// Returns zero on exhaustion; zeroed blocks match HEAP_ZERO_MEMORY.
	uint64_t allocate(uint64_t size, bool zero = true);
	bool release(uint64_t address);
	// Usable size of a block, or UINT64_MAX when the address is not a block of this allocator.
	uint64_t size(uint64_t address);
	bool owns(uint64_t address);

private:
	NativeMemory &memory;
	NativeHeap &heap;
	std::map<uint64_t, uint64_t> pages;
};

}

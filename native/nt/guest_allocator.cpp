#include "guest_allocator.h"

namespace raven {

uint64_t GuestAllocator::allocate(uint64_t size, bool zero)
{
	if (heap.available())
		return heap.allocate(zero ? 8 : 0, std::max<uint64_t>(size, 1));
	const uint64_t rounded = (std::max<uint64_t>(size, 1) + 4095) & ~uint64_t(4095);
	const auto range = memory.allocate(0, rounded, 0x3000, 4);
	if (range.status)
		return 0;
	pages.emplace(range.address, std::max<uint64_t>(size, 1));
	return range.address;
}

bool GuestAllocator::release(uint64_t address)
{
	if (heap.available())
		return heap.release(address);
	const auto found = pages.find(address);
	if (found == pages.end())
		return false;
	pages.erase(found);
	return memory.free(address, 0, 0x8000).status == 0;
}

uint64_t GuestAllocator::size(uint64_t address)
{
	if (heap.available())
		return heap.block_size(address);
	const auto found = pages.find(address);
	return found == pages.end() ? UINT64_MAX : found->second;
}

bool GuestAllocator::owns(uint64_t address)
{
	return heap.available() ? heap.block_size(address) != UINT64_MAX : pages.contains(address);
}

}

#pragma once

#include "environment.h"

#include <map>
#include <array>
#include <iterator>
#include <optional>
#include <span>
#include <vector>

namespace raven {

struct NativeMemoryRange {
	uint64_t address = 0;
	uint64_t size = 0;
	uint32_t status = 0;
	uint32_t previous = 0;
};

// Windows reservation state above the existing stopped-process mapping owner.
class NativeMemory {
public:
	NativeMemory(NativeProcess &process, NativeEnvironment &environment, size_t limit = 512*1024*1024);
	NativeMemory(const NativeMemory &) = delete;
	NativeMemory &operator=(const NativeMemory &) = delete;
	NativeMemoryRange allocate(uint64_t address, uint64_t size, uint32_t type, uint32_t protection);
	// Maps a view of a shared host file (a section) as committed memory with the given PAGE_* access; VirtualFree-style release unmaps it.
	NativeMemoryRange map_view(int descriptor, uint64_t offset, uint64_t size, uint32_t access);
	NativeMemoryRange free(uint64_t address, uint64_t size, uint32_t type);
	NativeMemoryRange protect(uint64_t address, uint64_t size, uint32_t protection);
	std::optional<std::array<uint8_t,48>> query(uint64_t address) const;
	// A mapped program image: its pages can be protected and queried although the program never allocated them. Each section starts with
	// the access its flags give, and every later change is remembered.
	void remove_image(uint64_t base) { images.erase(base); }
	void add_image(uint64_t base, uint64_t size, std::span<const std::pair<std::pair<uint64_t,uint64_t>,uint32_t>> sections);
	bool dispatch(std::string_view name);
	static std::span<const std::string_view> nt_exports();
	// The address space held by reservations; commitment is counted separately and is what the limit applies to.
	size_t bytes() const { return reserved_total; }
	size_t count() const { return regions.size(); }

private:
	// The access of every page of a region as runs of equal pages, so a reservation of terabytes costs a few entries.
	class PageMap {
	public:
		PageMap(uint64_t count, uint32_t value) : total(count) { runs[0] = value; }
		uint64_t size() const { return total; }
		uint32_t at(uint64_t index) const { return std::prev(runs.upper_bound(index))->second; }
		// The first page after the run that holds `index`.
		uint64_t run_end(uint64_t index) const
		{
			const auto next = runs.upper_bound(index);
			return next == runs.end() ? total : next->first;
		}
		void fill(uint64_t first, uint64_t count, uint32_t value)
		{
			if (!count)
				return;
			split(first);
			split(first + count);
			runs.erase(runs.lower_bound(first), runs.lower_bound(first + count));
			runs[first] = value;
		}
		bool any_zero(uint64_t first, uint64_t count) const { return nonzero(first, count) != count; }
		uint64_t nonzero(uint64_t first, uint64_t count) const
		{
			uint64_t result = 0;
			for (uint64_t at = first; at < first + count;) {
				const auto end = std::min(run_end(at), first + count);
				if (at_value(at))
					result += end - at;
				at = end;
			}
			return result;
		}

	private:
		uint32_t at_value(uint64_t index) const { return at(index); }
		void split(uint64_t index)
		{
			if (index >= total || runs.count(index))
				return;
			runs[index] = at(index);
		}
		uint64_t total;
		std::map<uint64_t, uint32_t> runs;
	};
	struct Region {
		uint64_t size;
		uint32_t allocation_protection;
		PageMap pages;
	};
	struct Image {
		uint64_t size;
		std::vector<std::pair<std::pair<uint64_t,uint64_t>,uint32_t>> sections;
		std::map<uint64_t,uint32_t> pages;
		uint32_t access_of(uint64_t address) const;
	};
	std::map<uint64_t,Image>::iterator image_of(uint64_t address, uint64_t size);
	NativeProcess &process;
	NativeEnvironment &environment;
	std::map<uint64_t,Image> images;
	std::map<uint64_t,Region> regions;
	uint64_t next = 0x200000000ULL;
	uint64_t user_limit = native_user_limit;
	size_t used = 0, reserved_total = 0;
	size_t limit;
	std::map<uint64_t,Region>::iterator region(uint64_t address, uint64_t size);
};

}

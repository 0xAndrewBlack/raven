#pragma once

#include "environment.h"

#include <map>
#include <array>
#include <optional>

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
	NativeMemoryRange free(uint64_t address, uint64_t size, uint32_t type);
	NativeMemoryRange protect(uint64_t address, uint64_t size, uint32_t protection);
	std::optional<std::array<uint8_t,48>> query(uint64_t address) const;
	bool dispatch(std::string_view name);
	static std::span<const std::string_view> nt_exports();
	size_t bytes() const { return used; }
	size_t count() const { return regions.size(); }

private:
	struct Region {
		uint64_t size;
		uint32_t allocation_protection;
		std::vector<uint32_t> pages;
	};
	NativeProcess &process;
	NativeEnvironment &environment;
	std::map<uint64_t,Region> regions;
	uint64_t next = 0x200000000ULL;
	size_t used = 0;
	size_t limit;
	std::map<uint64_t,Region>::iterator region(uint64_t address, uint64_t size);
};

}

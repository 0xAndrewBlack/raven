#pragma once

#include "environment.h"

#include <map>
#include <array>
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
	NativeMemoryRange free(uint64_t address, uint64_t size, uint32_t type);
	NativeMemoryRange protect(uint64_t address, uint64_t size, uint32_t protection);
	std::optional<std::array<uint8_t,48>> query(uint64_t address) const;
	// A mapped program image: its pages can be protected and queried although the program never allocated them. Each section starts with
	// the access its flags give, and every later change is remembered.
	void remove_image(uint64_t base) { images.erase(base); }
	void add_image(uint64_t base, uint64_t size, std::span<const std::pair<std::pair<uint64_t,uint64_t>,uint32_t>> sections);
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
	size_t used = 0;
	size_t limit;
	std::map<uint64_t,Region>::iterator region(uint64_t address, uint64_t size);
};

}

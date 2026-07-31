#pragma once

#include "environment.h"

#include <map>
#include <optional>
#include <bitset>

namespace raven {

// Loader TLS for the initial thread. Allocations belong to NativeProcess.
class NativeTLS {
public:
	NativeTLS(NativeProcess &process, const NativeEnvironment &environment,
		std::span<const PEModule *const> order);
	void add(const PEModule &module);
	void remove(const PEModule &module);
	const std::vector<uint64_t> &callbacks(const PEModule &module) const;
	// Fresh static TLS for another thread: a slot vector at teb+0x58 and a block per module initialised from its template.
	void create_thread(uint64_t teb);
	void release_thread(uint64_t teb);

private:
	struct Template {
		uint64_t index;
		size_t size;
		size_t alignment;
		std::vector<uint8_t> bytes;
		std::vector<uint64_t> callbacks;
	};
	struct Entry {
		uint32_t slot = UINT32_MAX;
		uint64_t index = 0;
		uint64_t allocation = 0;
		uint64_t block = 0;
		size_t size = 0;
		std::vector<uint64_t> callbacks;
		size_t alignment = 16;
		std::vector<uint8_t> bytes;
	};
	// Storage owned by threads other than the first, released with the thread.
	std::map<uint64_t, std::vector<uint64_t>> thread_storage;
	NativeProcess &process;
	const NativeEnvironment &environment;
	uint64_t vector = 0;
	size_t total = 0;
	std::map<const PEModule *, Entry> entries;
	std::bitset<10000> occupied;
	std::optional<Template> parse(const PEModule *module, size_t allocated) const;
	void install(const PEModule &module, const std::optional<Template> &item);
	void validate() const;
};

}

#pragma once

#include "environment.h"
#include "pe/resources.h"

#include <map>
#include <optional>

namespace raven {

struct NativeResourceView {
	uint64_t address;
	uint32_t size;
	uint32_t language;
};

class NativeResources {
public:
	NativeResources(NativeProcess &process, NativeEnvironment &environment,
		const ModuleSet &modules, const PEModule &entry);
	bool dispatch(std::string_view name);
	std::optional<NativeResourceView> view(uint64_t handle, uint32_t type, uint64_t name, uint16_t language = 0);

private:
	NativeProcess &process;
	NativeEnvironment &environment;
	const ModuleSet &modules;
	const PEModule &entry;
	const PEModule *module(uint64_t handle);
	const std::vector<PEResource> &resources(const PEModule &image) const;
	// The last parse of each module's resource directory, with the parts of the directory it read and their bytes: a lookup compares those
	// parts of the live image and parses again only when one changed. Programs look up hundreds of resources while they start, and the
	// directory holds the resource payloads too, which the parse never reads.
	struct Parsed {
		std::vector<std::pair<size_t, size_t>> read;
		std::vector<uint8_t> bytes;
		std::vector<PEResource> resources;
		bool valid = false;
	};
	mutable std::map<const PEModule *, Parsed> parsed;
	std::optional<ResourceKey> key(uint64_t address, bool wide);
	uint64_t find(uint64_t handle, uint64_t type, uint64_t name, uint16_t language, bool wide);
	uint64_t access(uint64_t handle, uint64_t resource, bool size);
	uint64_t lock(uint64_t data);
};

}

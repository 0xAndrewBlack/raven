#pragma once

#include "environment.h"
#include "pe/resources.h"

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
	std::vector<PEResource> resources(const PEModule &image) const;
	std::optional<ResourceKey> key(uint64_t address, bool wide);
	uint64_t find(uint64_t handle, uint64_t type, uint64_t name, uint16_t language, bool wide);
	uint64_t access(uint64_t handle, uint64_t resource, bool size);
	uint64_t lock(uint64_t data);
};

}

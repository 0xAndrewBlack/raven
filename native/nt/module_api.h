#pragma once

#include "environment.h"

#include <optional>
#include <functional>

namespace raven {

class NativeModuleAPI {
public:
	NativeModuleAPI(NativeProcess &process, NativeEnvironment &environment,
		const ModuleSet &modules, const PEModule &entry);
	bool dispatch(std::string_view name);
	void set_loader(std::function<uint64_t(std::string)> load, std::function<bool(uint64_t)> free);

private:
	NativeProcess &process;
	NativeEnvironment &environment;
	const ModuleSet &modules;
	const PEModule &entry;
	std::function<uint64_t(std::string)> load;
	std::function<bool(uint64_t)> free;
	std::optional<std::string> guest_name(uint64_t address, bool wide) const;
	uint64_t module_handle(uint64_t address, bool wide);
	uint64_t procedure(uint64_t handle, uint64_t name);
};

}

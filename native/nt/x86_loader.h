#pragma once

#include "environment.h"
#include "paths.h"
#include "pe/module_set.h"

#include <functional>
#include <optional>
#include <vector>
#include <string>

namespace raven {

// LoadLibrary for 32-bit programs: a library the program ships or writes is read from the guest file system, the runtime's own
// components from beside the runtime, and everything it imports is loaded first. A library that cannot be bound is not kept.
class NativeX86Loader {
public:
	NativeX86Loader(NativeProcess &process, NativeEnvironment &environment, ModuleSet &modules, const NativePaths &paths,
		std::function<NativeResult(uint64_t, std::span<const uint64_t>)> call);
	// The base of the loaded library, or zero with the last error set.
	uint64_t load(std::string name);

private:
	NativeProcess &process;
	NativeEnvironment &environment;
	ModuleSet &modules;
	const NativePaths &paths;
	std::function<NativeResult(uint64_t, std::span<const uint64_t>)> call;
	std::vector<PEModule *> staged;
	PEModule *bring(const std::string &name);
	std::optional<std::vector<uint8_t>> read_library(const std::string &name, std::string &identity) const;
};

}

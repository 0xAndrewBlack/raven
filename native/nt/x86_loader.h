#pragma once

#include "environment.h"
#include "paths.h"
#include "x86_tls.h"
#include "pe/module_set.h"

#include <functional>
#include <map>
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
	// The base of a library already loaded from this path, zero when there is none; it takes no reference.
	uint64_t find(const std::string &name) const;
	// Gives one reference back; at the last one the library is told its process is done with it and a later load starts it afresh.
	// False when the handle is not a library loaded from a path.
	bool release(uint64_t handle);
	// Where the program lives, in the guest's spelling: a library named without a path is looked for there first.
	// Images with static thread local storage register there when they are mapped.
	void set_tls(NativeX86Tls *value) { tls = value; }
	// Called with each library once it is mapped, so memory services know its pages.
	void set_mapped(std::function<void(PEModule &)> hook) { mapped_hook = std::move(hook); }
	void set_application_directory(std::u16string directory) { application_directory = std::move(directory); }

private:
	NativeProcess &process;
	NativeEnvironment &environment;
	ModuleSet &modules;
	const NativePaths &paths;
	std::function<NativeResult(uint64_t, std::span<const uint64_t>)> call;
	std::vector<PEModule *> staged;
	struct Held {
		PEModule *module;
		size_t references;
	};
	// Libraries loaded from a file, by the lower case host path they were read from.
	std::map<std::string, Held> held;
	std::optional<std::string> path_key(const std::string &name) const;
	std::u16string application_directory;
	NativeX86Tls *tls = nullptr;
	std::function<void(PEModule &)> mapped_hook;
	PEModule *bring(const std::string &name);
	std::optional<std::vector<uint8_t>> read_library(const std::string &name, std::string &identity) const;
};

}

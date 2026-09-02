#pragma once

#include "pe/module_set.h"
#include "cpu/native_cpu.h"

#include <map>
#include <functional>
#include <optional>

namespace raven {

void validate_native_image(const PEImage &image,std::string_view name,bool is_64=true);
void load_initial_dependencies(ModuleSet &modules,
	const std::function<std::optional<std::vector<uint8_t>>(std::string_view)> &source,
	std::span<const std::string_view> native_modules,bool is_64=true,bool tolerate_missing=false);

std::vector<const PEModule *> initialization_order(const ModuleSet &modules, const PEModule &entry);
uint64_t initialize_loader_data(NativeProcess &process, uint64_t peb,
	const ModuleSet &modules, const PEModule &entry);

class NativeLoaderData {
public:
	NativeLoaderData(NativeProcess &process, uint64_t peb, const ModuleSet &modules, const PEModule &entry);
	void add(const PEModule &module);
	void initialized(const PEModule &module);
	void remove(const PEModule &module);
	uint64_t address() const { return loader; }

private:
	struct Node { uint64_t address; uint64_t allocation; };
	NativeProcess &process;
	const ModuleSet &modules;
	uint64_t peb;
	uint64_t loader;
	std::map<const PEModule *, Node> nodes;
	std::vector<const PEModule *> loaded;
	std::vector<const PEModule *> started;
	void validate() const;
	void publish(const std::map<const PEModule *, Node> &proposed,
		const std::vector<const PEModule *> &load, const std::vector<const PEModule *> &init);
};

}

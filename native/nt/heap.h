#pragma once

#include "environment.h"
#include "pe/module_set.h"
#include <functional>

namespace raven {

class NativeHeap {
public:
	NativeHeap(NativeProcess &process, NativeEnvironment &environment, ModuleSet &modules, const PEImage &entry);
	void initialize(std::function<NativeResult(uint64_t,std::span<const uint64_t>)> invoke);
	bool dispatch(std::string_view name);
	static std::span<const std::string_view> nt_exports();

private:
	NativeProcess &process;
	NativeEnvironment &environment;
	ModuleSet &modules;
	const PEImage &entry;
	std::function<NativeResult(uint64_t,std::span<const uint64_t>)> invoke;
	uint64_t call(std::string_view name, std::span<const uint64_t> arguments);
};

}

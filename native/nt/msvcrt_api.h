#pragma once

#include "environment.h"

#include <functional>

namespace raven {

// Original msvcrt-compatible startup, argument, math-control and random services for 32-bit guests.
class NativeCRT {
public:
	NativeCRT(NativeProcess &process, NativeEnvironment &environment);
	// Runs a guest function pointer, as _initterm needs.
	void set_call(std::function<NativeResult(uint64_t, std::span<const uint64_t>)> caller);
	bool dispatch(std::string_view name);
	// Every export name, sorted, and the subset that are variables rather than functions.
	static std::span<const std::string_view> exports();
	static std::span<const std::string_view> data_exports();
	// Seeds the exported variables once the provider image is mapped; addresses are keyed by export name.
	void initialize(const std::function<uint64_t(std::string_view)> &address);

private:
	NativeProcess &process;
	NativeEnvironment &environment;
	std::function<NativeResult(uint64_t, std::span<const uint64_t>)> invoke;
	uint64_t globals = 0;
	uint32_t seed = 1;
	uint32_t control_word = 0x9001f;
	uint64_t arguments_block = 0;
	void write32(uint64_t address, uint32_t value);
};

}

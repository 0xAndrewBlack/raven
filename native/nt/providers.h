#pragma once

#include "environment.h"
#include "desktop/presentation.h"
#include <functional>
#include <optional>

namespace raven {

// Original name-only PE64 modules for implemented environment and loader handlers.
std::vector<uint8_t> environment_provider(std::string_view name, uint64_t base);
std::vector<uint8_t> runtime_provider(std::string_view name, uint64_t base,
	std::span<const std::string_view> exports, bool x86 = false,
	std::span<const std::string_view> data_exports = {},
	std::span<const std::pair<std::string_view, uint16_t>> ordinal_exports = {},
	// Gives hot kernel32 services guest-side fast paths; their slow-path trap sits at a fixed offset inside the stub.
	bool fast_paths = false);
// Where the breakpoint of a 64-bit provider export sits inside its stub: past the guest-side path of a fast or served stub, at its start
// otherwise.
size_t fast_stub_trap_offset(std::string_view module, std::string_view name);
// Runs a PE32 process in host compatibility mode; only the API providers listed in x86_process.cpp exist so far.
// A source of libraries shipped beside the program lets a program import them statically: they are loaded with it, and their entry points run
// before the program's.
NativeResult run_native_process_x86(ModuleSet &modules, PEModule &entry,
	const std::string &bootstrap, std::chrono::milliseconds timeout, std::optional<NativeLaunch> launch = {},
	DesktopPresentation presentation = {},
	std::function<std::optional<std::vector<uint8_t>>(std::string_view)> source = {});
NativeResult run_native_process(ModuleSet &modules, PEModule &entry,
	const std::string &bootstrap, std::chrono::milliseconds timeout,
	std::function<std::optional<std::vector<uint8_t>>(std::string_view)> source = {},
	std::function<void(std::span<const uint8_t>)> debug = {}, DesktopPresentation presentation = {},
	std::optional<NativeLaunch> launch = {});

}

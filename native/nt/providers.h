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
	std::span<const std::string_view> data_exports = {});
// Runs a PE32 process in host compatibility mode; only the API providers listed in x86_process.cpp exist so far.
NativeResult run_native_process_x86(ModuleSet &modules, PEModule &entry,
	const std::string &bootstrap, std::chrono::milliseconds timeout, std::optional<NativeLaunch> launch = {},
	DesktopPresentation presentation = {});
NativeResult run_native_process(ModuleSet &modules, PEModule &entry,
	const std::string &bootstrap, std::chrono::milliseconds timeout,
	std::function<std::optional<std::vector<uint8_t>>(std::string_view)> source = {},
	std::function<void(std::span<const uint8_t>)> debug = {}, DesktopPresentation presentation = {},
	std::optional<NativeLaunch> launch = {});

}

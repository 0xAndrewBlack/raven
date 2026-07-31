#include "providers.h"
#include "object_api.h"

#include <algorithm>
#include <array>
#include <map>
#include <stdexcept>

namespace raven {

namespace {

// stdcall argument counts for every API the x86 process runner can dispatch.
constexpr std::array<std::pair<std::string_view, uint32_t>, 13> kernel32_exports{{
	{"CloseHandle", 1}, {"CreateEventA", 4}, {"CreateEventW", 4}, {"ExitProcess", 1}, {"GetCommandLineA", 0},
	{"GetCommandLineW", 0}, {"GetCurrentProcessId", 0}, {"GetCurrentThreadId", 0}, {"GetFileType", 1},
	{"GetLastError", 0}, {"GetStdHandle", 1}, {"SetLastError", 1}, {"WriteFile", 5},
}};

uint64_t provider_base(const ModuleSet &modules, uint32_t size)
{
	uint64_t base = 0x70000000ULL;
	for (;;) {
		bool overlap = false;
		for (const auto &[name, module] : modules.all()) {
			const uint64_t start = module->loaded.base();
			const uint64_t end = start + module->loaded.data().size();
			if (base < end && start < base + size) {
				base = (end + 65535) & ~uint64_t(65535);
				overlap = true;
				break;
			}
		}
		if (base >= 0xf0000000ULL - size)
			throw std::runtime_error("no address available for native x86 API provider");
		if (!overlap)
			return base;
	}
}

}

NativeResult run_native_process_x86(ModuleSet &modules, PEModule &entry,
	const std::string &bootstrap, std::chrono::milliseconds timeout, std::optional<NativeLaunch> launch)
{
	if (timeout.count() <= 0 || entry.image.is_64 || (entry.image.characteristics & 0x2000) ||
		!std::any_of(modules.all().begin(), modules.all().end(), [&](const auto &item) { return item.second.get() == &entry; }))
		throw std::runtime_error("native x86 process requires a PE32 executable graph and positive timeout");
	for (const auto &[name, module] : modules.all())
		if (module->image.is_64)
			throw std::runtime_error("native x86 process cannot mix PE64 modules: " + name);
	std::vector<std::string_view> names;
	for (const auto &[name, arguments] : kernel32_exports)
		names.push_back(name);
	std::map<uint64_t, std::pair<std::string_view, uint32_t>> traps;
	if (!modules.all().contains("kernel32.dll")) {
		const auto size = PEImage(runtime_provider("kernel32.dll", 0x70000000ULL, names, true)).image_size;
		const auto base = provider_base(modules, size);
		auto &provider = modules.add("kernel32.dll", runtime_provider("kernel32.dll", base, names, true), base);
		provider.runtime_api = true;
		for (const auto &symbol : provider.exports) {
			const auto found = std::find_if(kernel32_exports.begin(), kernel32_exports.end(),
				[&](const auto &item) { return item.first == symbol.names.at(0); });
			traps.emplace(provider.loaded.base() + symbol.address, std::pair{found->first, found->second * 4});
		}
	}
	modules.bind_imports();
	std::vector<LoadedImage *> images;
	for (const auto &[name, module] : modules.all())
		images.push_back(&module->loaded);
	const auto deadline = std::chrono::steady_clock::now() + timeout;
	NativeProcess process(images, bootstrap, timeout, NativeMode::x86);
	for (const auto &[address, api] : traps)
		process.add_api_trap(address, api.second);
	NativeEnvironment environment(process, entry.loaded.base(), 1, 1);
	if (!launch) {
		NativeLaunch initial;
		for (const char byte : entry.name) {
			const auto character = static_cast<unsigned char>(byte);
			if (character > 127)
				throw std::runtime_error("native default launch identity requires ASCII");
			initial.image_path.push_back(char16_t(character));
		}
		initial.command_line = u"\"" + initial.image_path + u"\"";
		launch = std::move(initial);
	}
	NativeObjects kernel_objects;
	std::array<uint64_t, 3> standard_handles{UINT64_MAX, UINT64_MAX, UINT64_MAX};
	for (size_t i = 0; i < 3; ++i) {
		if (launch->standard_fds[i] < 0)
			continue;
		const auto inherited = kernel_objects.inherit_file(launch->standard_fds[i]);
		if (inherited.status)
			throw std::runtime_error("cannot inherit native standard file");
		standard_handles[i] = inherited.value;
	}
	environment.prepare_parameters(*launch, standard_handles);
	NativeObjectAPI object_api(process, environment, kernel_objects, deadline);
	auto result = process.call(entry.loaded.base() + entry.image.entry, {}, timeout);
	while (result.stop == NativeStop::api) {
		const auto found = traps.find(result.value);
		if (found == traps.end())
			return result;
		if (found->second.first == "ExitProcess") {
			const auto code = uint32_t(process.api_arguments(1)[0]);
			process.abandon_call();
			return {NativeStop::exited, code, result.instruction, 0};
		}
		if (!environment.dispatch(found->second.first) && !object_api.dispatch(found->second.first))
			return result;
		const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
		if (remaining.count() <= 0)
			return {NativeStop::timeout, 0, result.instruction, 0};
		result = process.resume(remaining);
	}
	return result;
}

}

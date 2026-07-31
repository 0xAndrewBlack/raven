#include "providers.h"
#include "object_api.h"
#include "module_api.h"
#include "resources.h"
#include "memory.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <map>
#include <iostream>
#include <stdexcept>

namespace raven {

namespace {

// stdcall argument counts for every API the x86 process runner can dispatch.
constexpr std::array<std::pair<std::string_view, uint32_t>, 36> kernel32_exports{{
	{"CloseHandle", 1}, {"CreateEventA", 4}, {"CreateEventW", 4}, {"ExitProcess", 1}, {"FindResourceA", 3},
	{"FindResourceExA", 4}, {"FindResourceExW", 4}, {"FindResourceW", 3}, {"FreeLibrary", 1}, {"GetACP", 0},
	{"GetCommandLineA", 0}, {"GetCommandLineW", 0}, {"GetCurrentProcessId", 0}, {"GetCurrentThreadId", 0},
	{"GetFileType", 1}, {"GetLastError", 0}, {"GetModuleFileNameA", 3}, {"GetModuleHandleA", 1},
	{"GetModuleHandleW", 1}, {"GetProcAddress", 2}, {"GetStartupInfoA", 1}, {"GetStdHandle", 1},
	{"GetTickCount", 0}, {"LoadLibraryA", 1}, {"LoadLibraryW", 1}, {"LoadResource", 2}, {"LockResource", 1},
	{"OutputDebugStringA", 1}, {"SetLastError", 1}, {"SizeofResource", 2}, {"VirtualAlloc", 4},
	{"VirtualFree", 3}, {"VirtualProtect", 4}, {"WriteFile", 5}, {"lstrcpyW", 2}, {"lstrlenW", 1},
}};

// Guest strings and small kernel32 services that need no shared state.
bool kernel_string_api(NativeProcess &process, NativeEnvironment &environment, const PEModule &entry,
	const NativeLaunch &launch, std::string_view name)
{
	if (name == "GetTickCount") {
		const auto now = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch());
		process.return_api(uint32_t(now.count()));
		return true;
	}
	if (name == "OutputDebugStringA") {
		process.api_arguments(1);
		process.return_api(0);
		return true;
	}
	if (name == "lstrlenW" || name == "lstrcpyW") {
		const bool copy = name == "lstrcpyW";
		const auto args = process.api_arguments(copy ? 2 : 1);
		const uint64_t source = args[copy ? 1 : 0];
		size_t length = 0;
		try {
			while (process.read_memory(source + length * 2, 2) != std::vector<uint8_t>{0, 0}) {
				if (++length > 1024 * 1024)
					throw std::runtime_error("native string exceeds policy limit");
			}
			if (copy)
				process.write_memory(args[0], process.read_memory(source, length * 2 + 2));
		} catch (const std::runtime_error &failure) {
			const std::string_view message = failure.what();
			if (message.find("readable") == message.npos && message.find("writable") == message.npos)
				throw;
			environment.set_last_error(998);
			process.return_api(0);
			return true;
		}
		process.return_api(copy ? args[0] : length);
		return true;
	}
	if (name == "GetModuleFileNameA") {
		const auto args = process.api_arguments(3);
		if (args[0] && args[0] != entry.loaded.base()) {
			environment.set_last_error(126);
			process.return_api(0);
			return true;
		}
		std::string path;
		for (const auto character : launch.image_path)
			path.push_back(character > 127 ? '?' : char(character));
		const size_t size = uint32_t(args[2]);
		if (!size) {
			environment.set_last_error(122);
			process.return_api(0);
			return true;
		}
		const bool truncated = path.size() >= size;
		if (truncated)
			path.resize(size - 1);
		path.push_back('\0');
		process.write_memory(args[1], std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(path.data()), path.size()));
		if (truncated)
			environment.set_last_error(122);
		process.return_api(path.size() - 1);
		return true;
	}
	return false;
}

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
	NativeModuleAPI module_api(process, environment, modules, entry);
	NativeResources resources(process, environment, modules, entry);
	NativeMemory memory(process, environment);
	module_api.set_loader([&](std::string name) -> uint64_t {
		for (auto &character : name)
			if (character >= 'A' && character <= 'Z')
				character = static_cast<char>(character + ('a' - 'A'));
		if (name.find('.') == std::string::npos)
			name += ".dll";
		const auto found = modules.all().find(name);
		if (found == modules.all().end()) {
			environment.set_last_error(126);
			return 0;
		}
		return found->second->loaded.base();
	}, [&](uint64_t handle) -> bool {
		const bool known = std::any_of(modules.all().begin(), modules.all().end(),
			[&](const auto &item) { return item.second->loaded.base() == handle; });
		if (!known)
			environment.set_last_error(6);
		return known;
	});
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
		const auto api = found->second.first;
		if (!environment.dispatch(api) && !object_api.dispatch(api) && !module_api.dispatch(api) && !resources.dispatch(api) &&
			!memory.dispatch(api) && !kernel_string_api(process, environment, entry, *launch, api)) {
			std::cerr << "raven: unimplemented native x86 API " << api << '\n';
			return result;
		}
		const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
		if (remaining.count() <= 0)
			return {NativeStop::timeout, 0, result.instruction, 0};
		result = process.resume(remaining);
	}
	return result;
}

}

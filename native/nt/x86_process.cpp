#include "providers.h"
#include "object_api.h"
#include "module_api.h"
#include "resources.h"
#include "memory.h"
#include "desktop/api.h"
#include "desktop/windows.h"

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

// stdcall argument counts of the desktop exports, keyed by export name.
const std::map<std::string_view, uint32_t> &desktop_arguments()
{
	static const std::map<std::string_view, uint32_t> counts{
		{"AdjustWindowRect",3},{"AdjustWindowRectEx",4},{"BeginPaint",2},{"CallWindowProcW",5},{"ClientToScreen",2},
		{"CopyIcon",1},{"CreateIconFromResourceEx",7},{"CreateWindowExW",12},{"DefWindowProcW",4},{"DestroyIcon",1},
		{"DestroyMenu",1},{"DestroyWindow",1},{"DispatchMessageW",1},{"DrawIconEx",9},{"EndPaint",2},{"FillRect",3},
		{"FrameRect",3},{"GetActiveWindow",0},{"GetClassInfoExW",3},{"GetClassInfoW",3},{"GetClassLongA",2},
		{"GetClassLongPtrA",2},{"GetClassLongPtrW",2},{"GetClassLongW",2},{"GetClassNameA",3},{"GetClassNameW",3},
		{"GetClientRect",2},{"GetDC",1},{"GetDlgCtrlID",1},{"GetDlgItem",2},{"GetFocus",0},{"GetIconInfo",2},
		{"GetMenuItemCount",1},{"GetMenuItemID",2},{"GetMessageW",4},{"GetParent",1},{"GetSubMenu",2},{"GetSysColor",1},
		{"GetSysColorBrush",1},{"GetSystemMetrics",1},{"GetUpdateRect",3},{"GetWindowDC",1},{"GetWindowLongA",2},
		{"GetWindowLongPtrA",2},{"GetWindowLongPtrW",2},{"GetWindowLongW",2},{"GetWindowRect",2},{"GetWindowTextLengthW",1},
		{"GetWindowTextW",3},{"InternalGetWindowText",3},{"InvalidateRect",3},{"IsChild",2},{"IsMenu",1},{"IsWindow",1},
		{"IsWindowUnicode",1},{"IsWindowVisible",1},{"LoadMenuW",2},{"LoadStringW",4},{"LookupIconIdFromDirectoryEx",5},
		{"MapWindowPoints",4},{"PeekMessageW",5},{"PostMessageW",4},{"PostQuitMessage",1},{"PrivateExtractIconsW",8},
		{"RegisterClassExW",1},{"RegisterClassW",1},{"ReleaseDC",2},{"ScreenToClient",2},{"SendMessageW",4},
		{"SetClassLongA",3},{"SetClassLongPtrA",3},{"SetClassLongPtrW",3},{"SetClassLongW",3},{"SetFocus",1},
		{"SetWindowLongA",3},{"SetWindowLongPtrA",3},{"SetWindowLongPtrW",3},{"SetWindowLongW",3},{"SetWindowTextW",2},
		{"ShowWindow",2},{"TranslateMessage",1},{"UnregisterClassW",2},{"UpdateWindow",1},{"ValidateRect",2},
		{"BitBlt",9},{"CombineRgn",4},{"CreateCompatibleBitmap",3},{"CreateCompatibleDC",1},{"CreateDIBSection",6},
		{"CreateFontIndirectW",1},{"CreatePen",3},{"CreateRectRgn",4},{"CreateSolidBrush",1},{"DPtoLP",3},{"DeleteDC",1},
		{"DeleteObject",1},{"EqualRgn",2},{"ExcludeClipRect",5},{"ExtTextOutW",8},{"GdiFlush",0},{"GetBitmapBits",3},
		{"GetBkColor",1},{"GetBkMode",1},{"GetClipBox",2},{"GetClipRgn",2},{"GetCurrentObject",2},
		{"GetCurrentPositionEx",2},{"GetGraphicsMode",1},{"GetLayout",1},{"GetObjectA",3},{"GetObjectType",1},
		{"GetObjectW",3},{"GetRgnBox",2},{"GetStockObject",1},{"GetTextColor",1},{"GetTextExtentExPointW",7},
		{"GetTextExtentPoint32W",4},{"GetTextExtentPointW",4},{"GetTextMetricsW",2},{"GetViewportExtEx",2},
		{"GetWindowExtEx",2},{"IntersectClipRect",5},{"LPtoDP",3},{"LineTo",3},{"MoveToEx",4},{"OffsetRgn",3},
		{"PtInRegion",3},{"RectInRegion",2},{"SelectClipRgn",2},{"SelectObject",2},{"SetBkColor",2},{"SetBkMode",2},
		{"SetRectRgn",5},{"SetTextColor",2},{"TextOutW",5},{"LoadIconWithScaleDown",5},
	};
	return counts;
}

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
	const std::string &bootstrap, std::chrono::milliseconds timeout, std::optional<NativeLaunch> launch,
	DesktopPresentation presentation)
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
	const auto add_desktop = [&](const char *dll, std::span<const std::string_view> exports) {
		if (modules.all().contains(dll))
			return;
		const auto size = PEImage(runtime_provider(dll, 0x70000000ULL, exports, true)).image_size;
		const auto base = provider_base(modules, size);
		auto &provider = modules.add(dll, runtime_provider(dll, base, exports, true), base);
		provider.runtime_api = true;
		for (const auto &symbol : provider.exports) {
			const auto found = desktop_arguments().find(symbol.names.at(0));
			if (found == desktop_arguments().end())
				throw std::runtime_error("native x86 desktop export has no argument count: " + symbol.names.at(0));
			traps.emplace(provider.loaded.base() + symbol.address, std::pair{found->first, found->second * 4});
		}
	};
	add_desktop("user32.dll", NativeDesktop::user_exports());
	add_desktop("gdi32.dll", NativeDesktop::gdi_exports());
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
	DesktopObjects desktop_objects;
	NativeDesktop desktop(process, environment, desktop_objects, resources);
	NativeWindows windows(process, environment, desktop_objects);
	windows.set_deadline(deadline);
	windows.set_presentation(std::move(presentation));
	desktop.set_updated([&](uint64_t window) { windows.drawing(window); });
	struct ProcessExit { uint32_t code; uint64_t instruction; };
	const auto remaining = [&] { return std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()); };
	// Runs one guest call, answering every API trap until the call returns or stops for another reason.
	const auto invoke = [&](uint64_t address, std::span<const uint64_t> arguments) {
		auto budget = remaining();
		if (budget.count() <= 0)
			return NativeResult{NativeStop::timeout, 0, address, 0};
		auto result = process.active() ? process.callback(address, arguments, budget) : process.call(address, arguments, budget);
		while (result.stop == NativeStop::api) {
			const auto found = traps.find(result.value);
			if (found == traps.end())
				return result;
			const auto api = found->second.first;
			if (getenv("RAVEN_TRACE_X86")) std::cerr << "api " << api << '\n';
			if (api == "ExitProcess") {
				const auto code = uint32_t(process.api_arguments(1)[0]);
				process.abandon_call();
				throw ProcessExit{code, result.instruction};
			}
			if (!environment.dispatch(api) && !object_api.dispatch(api) && !module_api.dispatch(api) && !resources.dispatch(api) &&
				!memory.dispatch(api) && !kernel_string_api(process, environment, entry, *launch, api) &&
				!desktop.dispatch(api) && !windows.dispatch(api)) {
				std::cerr << "raven: unimplemented native x86 API " << api << '\n';
				return result;
			}
			budget = remaining();
			if (budget.count() <= 0)
				return NativeResult{NativeStop::timeout, 0, result.instruction, 0};
			result = process.resume(budget);
		}
		return result;
	};
	windows.set_call(invoke);
	try {
		const auto result = invoke(entry.loaded.base() + entry.image.entry, {});
		windows.shutdown();
		return result;
	} catch (const ProcessExit &request) {
		windows.shutdown();
		return {NativeStop::exited, request.code, request.instruction, 0};
	} catch (const NativeResult &stopped) {
		windows.shutdown();
		return stopped;
	}
}

}

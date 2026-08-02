#include "providers.h"
#include "object_api.h"
#include "module_api.h"
#include "resources.h"
#include "memory.h"
#include "advapi_api.h"
#include "msvcrt_api.h"
#include "prefix.h"
#include "profile_api.h"
#include "registry.h"
#include "desktop/api.h"
#include "desktop/windows.h"
#include "api.h"
#include "ansi_api.h"
#include "guest_allocator.h"
#include "heap.h"
#include "kernel_context.h"
#include "paths.h"
#include "x86_compat_api.h"
#include "registry_words.h"
#include "system_exports.h"
#include "x86_loader.h"
#include "x86_tls.h"
#ifdef RAVEN_VULKAN_THUNK32
#include "graphics/vulkan_thunk32_engine.h"
#endif
#include "x86_system_api.h"
#include "x86_d3d9.h"
#include "x86_thread_api.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <map>
#include <set>
#include <functional>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

namespace raven {

namespace {

// stdcall argument counts for every API the x86 process runner can dispatch.
constexpr std::array<std::pair<std::string_view, uint32_t>, 105> kernel32_exports{{
	{"CloseHandle", 1}, {"CreateEventA", 4}, {"CreateEventW", 4}, {"CreateThread", 6}, {"DeleteCriticalSection", 1}, {"EnterCriticalSection", 1}, {"ExitProcess", 1}, {"ExitThread", 1}, {"FindResourceA", 3},
	{"FindResourceExA", 4}, {"FindResourceExW", 4}, {"FindResourceW", 3}, {"FreeLibrary", 1}, {"GetACP", 0},
	{"GetCommandLineA", 0}, {"GetCommandLineW", 0}, {"GetCurrentProcessId", 0}, {"GetCurrentThreadId", 0}, {"GetExitCodeThread", 2},
	{"GetFileType", 1}, {"GetLastError", 0}, {"GetModuleFileNameA", 3}, {"GetModuleHandleA", 1},
	{"GetModuleHandleW", 1}, {"GetPrivateProfileIntW", 4}, {"GetPrivateProfileStringW", 6}, {"GetProcAddress", 2}, {"GetProcessHeap", 0}, {"GetStartupInfoA", 1}, {"GetStdHandle", 1},
	{"GetTickCount", 0}, {"HeapAlloc", 3}, {"HeapFree", 3}, {"HeapReAlloc", 4}, {"HeapSize", 3}, {"InitializeCriticalSection", 1}, {"LeaveCriticalSection", 1}, {"LoadLibraryA", 1}, {"LoadLibraryW", 1}, {"LoadResource", 2}, {"LockResource", 1},
	{"OutputDebugStringA", 1}, {"ResetEvent", 1}, {"ResumeThread", 1}, {"SetEvent", 1}, {"SetLastError", 1}, {"SetThreadPriority", 2}, {"SizeofResource", 2}, {"Sleep", 1}, {"SwitchToThread", 0}, {"TryEnterCriticalSection", 1}, {"VirtualAlloc", 4},
	// Services of the 32-bit CRT era: legacy file calls, global memory, code pages, environment and version queries.
	{"_lopen", 2}, {"_lcreat", 2}, {"_lread", 3}, {"_lwrite", 3}, {"_llseek", 3}, {"lstrcpyA", 2}, {"lstrlenA", 1}, {"GetWindowsDirectoryA", 2}, {"GlobalHandle", 1}, {"GetVersionExA", 1}, {"WinExec", 2}, {"GlobalUnlock", 1}, {"GlobalFree", 1}, {"GlobalAlloc", 2}, {"SetErrorMode", 1}, {"GlobalLock", 1}, {"GetCurrentProcess", 0}, {"SetHandleCount", 1}, {"GetOEMCP", 0}, {"GetCPInfo", 2}, {"WideCharToMultiByte", 8}, {"DeleteFileA", 1}, {"GetEnvironmentStrings", 0}, {"FreeEnvironmentStringsW", 1}, {"FreeEnvironmentStringsA", 1}, {"UnhandledExceptionFilter", 1}, {"RtlUnwind", 4}, {"HeapCreate", 3}, {"HeapDestroy", 1}, {"TerminateProcess", 2}, {"GetEnvironmentStringsW", 0}, {"GetVersion", 0}, {"GetFileAttributesA", 1},
	// File and clock services of the C runtime component: the shared handlers read 32-bit words; a 64-bit offset takes two.
	{"RaiseException", 4}, {"CreateFileW", 7}, {"DeleteFileW", 1}, {"GetEnvironmentVariableA", 3}, {"GetFileInformationByHandle", 2}, {"MultiByteToWideChar", 6},
	{"QueryPerformanceCounter", 1}, {"QueryPerformanceFrequency", 1}, {"ReadFile", 5}, {"SetFilePointer", 4}, {"SetFilePointerEx", 5},
	{"GetFileSizeEx", 2}, {"FlushFileBuffers", 1},
	{"VirtualFree", 3}, {"VirtualProtect", 4}, {"WaitForSingleObject", 2}, {"WriteFile", 5}, {"_lclose", 1}, {"lstrcpyW", 2}, {"lstrlenW", 1},
}};

// Shared-registry handlers that serve 32-bit programs as they are: every argument is one 32-bit word and no structure holds a pointer.
constexpr std::array shared_exports{
	NativeX86System::Export{"kernel32.dll", "CreateDirectoryW", 2}, NativeX86System::Export{"kernel32.dll", "CreateFileA", 7},
	NativeX86System::Export{"kernel32.dll", "CreateFileMappingA", 6}, NativeX86System::Export{"kernel32.dll", "FormatMessageA", 7}, NativeX86System::Export{"kernel32.dll", "GetEnvironmentVariableW", 3},
	NativeX86System::Export{"kernel32.dll", "GetModuleFileNameW", 3}, NativeX86System::Export{"kernel32.dll", "GetModuleHandleExA", 3},
	NativeX86System::Export{"kernel32.dll", "GetSystemTimeAsFileTime", 1}, NativeX86System::Export{"kernel32.dll", "GetTempPathA", 2},
	NativeX86System::Export{"kernel32.dll", "GetTickCount64", 0}, NativeX86System::Export{"kernel32.dll", "LocalFree", 1},
	NativeX86System::Export{"kernel32.dll", "MapViewOfFile", 5}, NativeX86System::Export{"kernel32.dll", "UnmapViewOfFile", 1},
	NativeX86System::Export{"user32.dll", "CallWindowProcA", 5}, NativeX86System::Export{"user32.dll", "DestroyCursor", 1},
	NativeX86System::Export{"user32.dll", "EnumDisplayMonitors", 4}, NativeX86System::Export{"user32.dll", "EnumDisplaySettingsW", 3},
	NativeX86System::Export{"user32.dll", "GetDCEx", 3}, NativeX86System::Export{"user32.dll", "GetDisplayConfigBufferSizes", 3},
	NativeX86System::Export{"user32.dll", "GetForegroundWindow", 0}, NativeX86System::Export{"user32.dll", "GetMonitorInfoW", 2},
	NativeX86System::Export{"user32.dll", "IsIconic", 1}, NativeX86System::Export{"user32.dll", "MonitorFromPoint", 3},
	NativeX86System::Export{"user32.dll", "OffsetRect", 3}, NativeX86System::Export{"user32.dll", "QueryDisplayConfig", 6},
	NativeX86System::Export{"gdi32.dll", "CreateBitmap", 5}, NativeX86System::Export{"gdi32.dll", "StretchBlt", 11},
};

// More shared handlers a 32-bit program may use as they are; their words come from the registry and their library from the public
// export lists. Anything with a pointer-width structure, a 64-bit argument or a callback into x64 conventions is not here.
constexpr std::string_view shared_allowed[] = {
	"WriteFile", "GetFileAttributesW", "GetFullPathNameA", "GetFullPathNameW", "GetCurrentDirectoryA", "GetCurrentDirectoryW",
	"SetCurrentDirectoryA", "SetCurrentDirectoryW", "FindFirstFileA", "FindFirstFileW", "FindNextFileA", "FindNextFileW", "FindClose",
	"CreateDirectoryA", "RemoveDirectoryA", "RemoveDirectoryW", "MoveFileA", "MoveFileW", "CopyFileA", "CopyFileW", "GetLocalTime",
	"GetSystemTime", "lstrcmpA", "lstrcmpW", "lstrcmpiA", "lstrcmpiW", "lstrcpynA", "lstrcatA", "OutputDebugStringW", "IsDebuggerPresent",
	"GetLogicalDrives", "GetDriveTypeA", "GetVolumeInformationA", "GetVolumeInformationW", "GetDiskFreeSpaceA", "MulDiv", "GetStringTypeW",
	"GetStringTypeA", "CompareStringA", "CompareStringW", "LCMapStringA", "LCMapStringW", "GetLocaleInfoA", "GetLocaleInfoW",
	"GetUserDefaultLCID", "GetSystemDefaultLCID", "IsValidCodePage", "SetEnvironmentVariableA", "SetEnvironmentVariableW",
	"ExpandEnvironmentStringsA", "ExpandEnvironmentStringsW", "CreateMutexA", "CreateMutexW", "ReleaseMutex", "GetFileTime", "SetFileTime",
	"FileTimeToLocalFileTime", "LocalFileTimeToFileTime", "FileTimeToDosDateTime", "DosDateTimeToFileTime", "GetFileSize", "SetEndOfFile",
	"GetSystemDirectoryW", "GetWindowsDirectoryW", "LocalAlloc", "LocalReAlloc", "GlobalReAlloc", "GlobalSize", "GetComputerNameA",
	"GetComputerNameW", "FileTimeToSystemTime", "SystemTimeToFileTime", "GetTimeZoneInformation", "GetCurrentProcessId", "SetFileAttributesA",
	"SetFileAttributesW", "GetLongPathNameA", "GetLongPathNameW", "GetShortPathNameA", "GetShortPathNameW", "SearchPathA", "SearchPathW",
	"GetModuleFileNameA", "IsDBCSLeadByte", "IsDBCSLeadByteEx", "GetCPInfoExA", "GetThreadLocale", "SetThreadLocale", "VerifyVersionInfoW",
	"GetUserNameA", "GetUserNameW", "FlsAlloc", "FlsFree", "FlsGetValue", "FlsSetValue",
};

struct NamedWords {
	std::string_view name;
	uint32_t words;
};

// The names a module exports from the host, with the words each takes: the fixed table, the shared handlers and the system services.
std::vector<NamedWords> host_exports(std::string_view module)
{
	std::vector<NamedWords> result;
	for (const auto &item : shared_exports)
		if (item.module == module)
			result.push_back({item.name, item.words});
	for (const auto &item : NativeX86System::exports())
		if (item.module == module)
			result.push_back({item.name, item.words});
	const auto published = system_export_names(module);
	for (const auto name : shared_allowed) {
		const auto words = registry_words(name);
		const auto duplicate = std::any_of(result.begin(), result.end(), [&](const auto &item) { return item.name == name; });
		if (words != UINT32_MAX && !duplicate && std::find(published.begin(), published.end(), name) != published.end())
			result.push_back({name, words});
	}
	return result;
}

const std::vector<NamedWords> &kernel32_table()
{
	static const auto table = [] {
		std::vector<NamedWords> result;
		for (const auto &[name, words] : kernel32_exports)
			result.push_back({name, words});
		for (const auto &item : host_exports("kernel32.dll"))
			if (std::none_of(result.begin(), result.end(), [&](const auto &fixed) { return fixed.name == item.name; }))
				result.push_back(item);
		return result;
	}();
	return table;
}

// stdcall argument counts of the desktop exports, keyed by export name.
const std::map<std::string_view, uint32_t> &desktop_arguments()
{
	static const auto counts = [] {
	std::map<std::string_view, uint32_t> counts{
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
		// Exports bound for real programs whose behavior is not implemented yet; each stops the process by name.
		{"CheckMenuItem",3},{"DialogBoxParamW",5},{"EndDialog",2},{"GetDesktopWindow",0},{"GetDlgItemInt",4},
		{"GetDlgItemTextW",4},{"GetMenuItemRect",4},{"KillTimer",2},{"LoadAcceleratorsW",2},{"LoadCursorW",2},
		{"LoadIconW",2},{"MessageBoxW",4},{"MoveWindow",6},{"PtInRect",3},{"ReleaseCapture",0},{"SetCapture",1},
		{"SetDlgItemInt",4},{"SetDlgItemTextW",3},{"SetMenu",2},{"SetRect",5},{"SetTimer",4},{"TranslateAcceleratorW",3},
		{"WinHelpW",4},{"wsprintfW",0},{"wsprintfA",0},{"GetDeviceCaps",2},{"SetDIBitsToDevice",12},{"SetLayout",2},{"SetPixel",4},
		{"SetROP2",2},
		// ANSI forms and cursor, key and text services served by the compat adapters or the shared registry.
		{"CreateWindowExA",12},{"DispatchMessageA",1},{"GetMessageA",4},{"PeekMessageA",5},{"RegisterClassA",1},{"RegisterClassExA",1},
		{"UnregisterClassA",2},{"LoadCursorA",2},{"LoadIconA",2},{"GetAsyncKeyState",1},{"SetCursor",1},{"GetCursorPos",1},{"SetCursorPos",2},
		{"DefWindowProcA",4},{"SendMessageA",4},{"PostMessageA",4},{"SetWindowTextA",2},
		{"CreateFontA",14},{"ExtTextOutA",8},{"GetDIBits",7},{"GetTextExtentPoint32A",4},{"GetTextMetricsA",2},{"SetDIBits",7},
		{"ExitWindowsEx",2},{"MessageBoxA",4},{"SetWindowPos",7},{"RealizePalette",1},{"SelectPalette",3},{"PatBlt",6},{"CreatePalette",1},
	};
	for (const auto module : {"user32.dll", "gdi32.dll"})
		for (const auto &item : host_exports(module))
			counts.emplace(item.name, item.words);
	return counts;
	}();
	return counts;
}

// Services of libraries Raven does not implement yet fail visibly instead of reporting success.
bool unsupported_library(NativeProcess &process, NativeEnvironment &environment, std::string_view name)
{
	const bool known = name == "PlaySoundW" || name == "ShellAboutW" || name == "InitCommonControlsEx";
	if (!known)
		return false;
	process.api_arguments(0);
	environment.set_last_error(120);
	process.return_api(0);
	return true;
}

// Guest strings and small kernel32 services that need no shared state.
bool kernel_string_api(NativeProcess &process, NativeEnvironment &environment, const PEModule &entry,
	const NativeLaunch &launch, std::string_view name)
{
	if (name == "GetTickCount" || name == "timeGetTime") {
		const auto now = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch());
		process.return_api(uint32_t(now.count()));
		return true;
	}
	if (name == "timeBeginPeriod" || name == "timeEndPeriod") {
		process.api_arguments(1);
		process.return_api(0);
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
	for (const auto &item : kernel32_table())
		names.push_back(item.name);
	std::sort(names.begin(), names.end());
	std::map<uint64_t, std::pair<std::string_view, uint32_t>> traps;
	if (!modules.all().contains("kernel32.dll")) {
		const auto size = PEImage(runtime_provider("kernel32.dll", 0x70000000ULL, names, true)).image_size;
		const auto base = provider_base(modules, size);
		auto &provider = modules.add("kernel32.dll", runtime_provider("kernel32.dll", base, names, true), base);
		provider.runtime_api = true;
		for (const auto &symbol : provider.exports) {
			const auto found = std::find_if(kernel32_table().begin(), kernel32_table().end(),
				[&](const auto &item) { return item.name == symbol.names.at(0); });
			traps.emplace(provider.loaded.base() + symbol.address, std::pair{found->name, found->words * 4});
		}
	}
	const auto add_desktop = [&](const char *dll, std::span<const std::string_view> implemented, std::span<const std::string_view> pending) {
		if (modules.all().contains(dll))
			return;
		std::vector<std::string_view> exports(implemented.begin(), implemented.end());
		exports.insert(exports.end(), pending.begin(), pending.end());
		std::sort(exports.begin(), exports.end());
		exports.erase(std::unique(exports.begin(), exports.end()), exports.end());
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
	std::vector<std::string_view> user_pending{"CheckMenuItem", "DialogBoxParamW", "EndDialog", "GetDesktopWindow",
		"GetDlgItemInt", "GetDlgItemTextW", "GetMenuItemRect", "KillTimer", "LoadAcceleratorsW", "LoadCursorW", "LoadIconW",
		"MessageBoxW", "MoveWindow", "PtInRect", "ReleaseCapture", "SetCapture", "SetDlgItemInt", "SetDlgItemTextW", "SetMenu",
		"SetRect", "SetTimer", "TranslateAcceleratorW", "WinHelpW", "wsprintfW", "wsprintfA", "CreateWindowExA", "DispatchMessageA",
		"GetMessageA", "PeekMessageA", "RegisterClassA", "RegisterClassExA", "UnregisterClassA", "LoadCursorA", "LoadIconA", "GetAsyncKeyState",
		"SetCursor", "GetCursorPos", "SetCursorPos", "DefWindowProcA", "SendMessageA", "PostMessageA", "SetWindowTextA",
		"ExitWindowsEx", "MessageBoxA", "SetWindowPos"};
	std::vector<std::string_view> gdi_pending{"GetDeviceCaps", "SetDIBitsToDevice", "SetLayout", "SetPixel", "SetROP2",
		"CreateFontA", "ExtTextOutA", "GetDIBits", "GetTextExtentPoint32A", "GetTextMetricsA", "SetDIBits",
		"RealizePalette", "SelectPalette", "PatBlt", "CreatePalette"};
	for (const auto &item : host_exports("user32.dll"))
		user_pending.push_back(item.name);
	for (const auto &item : host_exports("gdi32.dll"))
		gdi_pending.push_back(item.name);
	add_desktop("user32.dll", NativeDesktop::user_exports(), user_pending);
	add_desktop("gdi32.dll", NativeDesktop::gdi_exports(), gdi_pending);
	// Libraries whose argument counts come from their own implementation or the unsupported-service table.
	const auto add_library = [&](const char *dll, std::span<const std::string_view> exports, std::span<const std::string_view> data,
		const std::function<uint32_t(std::string_view)> &count) {
		if (modules.all().contains(dll))
			return;
		const auto size = PEImage(runtime_provider(dll, 0x70000000ULL, exports, true, data)).image_size;
		const auto base = provider_base(modules, size);
		auto &provider = modules.add(dll, runtime_provider(dll, base, exports, true, data), base);
		provider.runtime_api = true;
		for (const auto &symbol : provider.exports) {
			const auto &exported = symbol.names.at(0);
			if (std::find(data.begin(), data.end(), exported) != data.end())
				continue;
			const auto stable = std::find(exports.begin(), exports.end(), exported);
			traps.emplace(provider.loaded.base() + symbol.address, std::pair{*stable, count(exported) * 4});
		}
	};
	std::vector<std::string_view> advapi_names(NativeAdvapi::exports().begin(), NativeAdvapi::exports().end());
	for (const auto &item : host_exports("advapi32.dll"))
		advapi_names.push_back(item.name);
	std::sort(advapi_names.begin(), advapi_names.end());
	add_library("advapi32.dll", advapi_names, {}, [](std::string_view name) {
		for (const auto &item : host_exports("advapi32.dll"))
			if (item.name == name)
				return item.words;
		return NativeAdvapi::argument_count(name);
	});
	std::vector<std::string_view> setupapi_names;
	for (const auto &item : host_exports("setupapi.dll"))
		setupapi_names.push_back(item.name);
	std::sort(setupapi_names.begin(), setupapi_names.end());
	add_library("setupapi.dll", setupapi_names, {}, [](std::string_view name) {
		for (const auto &item : host_exports("setupapi.dll"))
			if (item.name == name)
				return item.words;
		return uint32_t(0);
	});
	add_library("msvcrt.dll", NativeCRT::exports(), NativeCRT::data_exports(), [](std::string_view name) { return uint32_t(0); });
	static constexpr std::array<std::string_view, 4> winmm_exports{"PlaySoundW", "timeBeginPeriod", "timeEndPeriod", "timeGetTime"};
	static constexpr std::array<std::string_view, 1> shell_exports{"ShellAboutW"};
	static constexpr std::array<std::string_view, 1> controls_exports{"InitCommonControlsEx"};
	add_library("winmm.dll", winmm_exports, {}, [](std::string_view name) { return uint32_t(name == "PlaySoundW" ? 3 : name == "timeGetTime" ? 0 : 1); });
	static constexpr std::array<std::string_view, 2> dsound_exports{"DirectSoundCreate", "DirectSoundCreate8"};
	add_library("dsound.dll", dsound_exports, {}, [](std::string_view) { return uint32_t(3); });
	// A Direct3D 9 library that ships beside the program is the program's choice (DXVK, for one); the built-in one answers otherwise.
	bool d3d9_beside = false;
	if (launch) {
		const auto probe_prefix = NativePrefix::from_environment();
		const NativePaths probe(probe_prefix);
		const auto program = probe.resolve(launch->image_path);
		if (program && program->exists)
			for (const auto &item : std::filesystem::directory_iterator(program->host.parent_path())) {
				auto filename = item.path().filename().string();
				for (auto &character : filename)
					if (character >= 'A' && character <= 'Z')
						character = static_cast<char>(character + ('a' - 'A'));
				d3d9_beside |= filename == "d3d9.dll";
			}
	}
	const auto d3d9_methods = NativeX86D3D9::method_names();
	if (!d3d9_beside) {
		add_library("d3d9.dll", NativeX86D3D9::entry_names(), {}, [](std::string_view) { return uint32_t(1); });
		add_library("raven-d3d9.dll", d3d9_methods, {}, [](std::string_view name) { return NativeX86D3D9::method_words(name); });
	}
#ifdef RAVEN_VULKAN_THUNK32
	// The Vulkan loader for 32-bit programs: every command the bridge implements, taking 32-bit stdcall arguments.
	static const auto vulkan_exports = VulkanThunk32::exports(VulkanBridge::exports());
	std::vector<std::string_view> vulkan_names;
	for (const auto &item : vulkan_exports)
		vulkan_names.push_back(item.first);
	add_library("vulkan-1.dll", vulkan_names, {}, [](std::string_view name) {
		for (const auto &item : vulkan_exports)
			if (item.first == name)
				return item.second;
		return uint32_t(0);
	});
#endif
	add_library("shell32.dll", shell_exports, {}, [](std::string_view) { return uint32_t(4); });
	add_library("comctl32.dll", controls_exports, {}, [](std::string_view) { return uint32_t(1); });
	modules.bind_imports();
	std::vector<LoadedImage *> images;
	for (const auto &[name, module] : modules.all())
		images.push_back(&module->loaded);
	const auto deadline = std::chrono::steady_clock::now() + timeout;
	NativeProcess process(images, bootstrap, timeout, NativeMode::x86);
	for (const auto &[address, api] : traps)
		process.add_api_trap(address, api.second);
	NativeEnvironment environment(process, entry.loaded.base(), 1, 1);
	NativeX86D3D9 direct3d9(process, environment);
	{
		std::map<std::string, uint64_t> method_traps;
		for (const auto &[address, api] : traps)
			if (api.first.starts_with("IDirect3D"))
				method_traps.emplace(std::string(api.first), address);
		direct3d9.set_trap_addresses(std::move(method_traps));
	}
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
	const auto prefix = NativePrefix::from_environment();
	NativeRegistry registry(prefix.registry_file());
	NativeAdvapi advapi(process, environment, registry);
	NativeProfile profile(process, environment, prefix);
	NativeCRT crt(process, environment);
	crt.initialize([&](std::string_view name) { return modules.resolve({"msvcrt.dll", std::string(name), 0, false, 0}); });
	NativeModuleAPI module_api(process, environment, modules, entry);
	NativePaths paths(prefix);
	std::function<NativeResult(uint64_t, std::span<const uint64_t>)> call_guest;
	NativeResources resources(process, environment, modules, entry);
	NativeMemory memory(process, environment);
	// Declared first so that it outlives the threads, which release their blocks through it when they are torn down.
	NativeX86Tls static_tls(process);
	NativeThreads guest_threads(process, environment, memory, nullptr, deadline);
	NativeX86Threads thread_api(process, environment, kernel_objects, guest_threads);
	NativeX86System system_api(process, environment, kernel_objects, guest_threads, memory);
	static_tls.attach_main(environment.teb());
	guest_threads.set_block_hooks([&](uint64_t teb) { static_tls.create_thread(teb); }, [&](uint64_t teb) { static_tls.release_thread(teb); });
	object_api.set_cooperative(true);
	NativeX86Loader library_loader(process, environment, modules, paths,
		[&](uint64_t address, std::span<const uint64_t> arguments) { return call_guest(address, arguments); });
	library_loader.set_tls(&static_tls);
	if (launch) {
		const auto separator = launch->image_path.find_last_of(u'\\');
		if (separator != std::u16string::npos)
			library_loader.set_application_directory(launch->image_path.substr(0, separator));
	}
	module_api.set_loader([&](std::string name) -> uint64_t {
		return library_loader.load(std::move(name));
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
	// Registry handlers whose arguments carry no pointer-width structures also serve 32-bit programs.
	ApiRegistry shared_api;
	windows.register_api(shared_api);
	desktop.register_gdi_api(shared_api);
	desktop.register_text_api(shared_api);
	desktop.register_image_api(shared_api);
	NativeX86Compat compat(process, environment, windows);
	// Shared handlers whose arguments are 32-bit words and whose structures carry no pointers.
	std::set<std::string_view> shared_names{"MoveWindow", "LoadCursorA", "LoadIconA", "GetAsyncKeyState", "SetCursor", "GetCursorPos", "SetCursorPos",
		"DefWindowProcA", "SendMessageA", "PostMessageA", "SetWindowTextA", "CreateFontA", "ExtTextOutA", "GetDIBits", "GetTextExtentPoint32A",
		"GetTextMetricsA", "SetDIBits", "MessageBoxA", "SetWindowPos", "SelectPalette", "PatBlt", "_lopen", "_lcreat", "_lread", "_lwrite", "_llseek", "lstrcpyA", "lstrlenA", "GetWindowsDirectoryA",
		"GlobalUnlock", "GlobalFree", "GlobalAlloc", "SetErrorMode", "GlobalLock", "GetOEMCP", "GetCPInfo", "WideCharToMultiByte", "DeleteFileA",
		"FreeEnvironmentStringsW", "GetEnvironmentStringsW", "GetVersion", "GetFileAttributesA", "CreateFileW", "DeleteFileW",
		"GetEnvironmentVariableA", "GetFileInformationByHandle", "MultiByteToWideChar", "QueryPerformanceCounter", "QueryPerformanceFrequency", "ReadFile",
		"SetFilePointer", "GetFileSizeEx", "FlushFileBuffers",
		"MonitorFromPoint"};
	for (const auto &item : shared_exports)
		shared_names.insert(item.name);
	for (const auto name : shared_allowed)
		shared_names.insert(name);
	windows.set_deadline(deadline);
#ifdef RAVEN_VULKAN_THUNK32
	VulkanBridge vulkan(process, modules);
	vulkan.set_surface_source({[&windows](uint64_t window) -> std::optional<std::pair<void *, void *>> {
		const auto surface = windows.host_surface(window);
		if (!surface)
			return std::nullopt;
		return std::pair<void *, void *>{surface->display, surface->surface};
	}, [&windows](uint64_t window) { windows.release_host_surface(window); },
		[&windows](uint64_t window) { return windows.client_size(window); }});
	VulkanThunk32 vulkan32(process, vulkan);
#endif
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
			if (getenv("RAVEN_TRACE_X86")) {
				// Argument words only reflect stdcall exports; cdecl and variadic entries report none.
				std::cerr << "api " << api << '(' << std::hex;
				const auto count = found->second.second / 4;
				if (count)
					for (const auto value : process.api_arguments(count))
						std::cerr << ' ' << value;
				std::cerr << std::dec << " )";
				// The names a program resolves at run time are what a diagnosis needs most.
				if (api == "LoadLibraryA" || api == "LoadLibraryW" || api == "GetProcAddress") {
					const auto words = process.api_arguments(api == "GetProcAddress" ? 2 : 1);
					const auto text = words[api == "GetProcAddress" ? 1 : 0];
					if (text > 0xffff) {
						try {
							const bool wide = api == "LoadLibraryW";
							const auto bytes = process.read_memory(text, 64);
							std::cerr << " \"";
							for (size_t at = 0; at + (wide ? 1 : 0) < bytes.size() && bytes[at] && (!wide || at % 2 == 0); at += wide ? 2 : 1)
								std::cerr << char(bytes[at]);
							std::cerr << '"';
						} catch (...) {}
					}
				}
				std::cerr << '\n';
			}
			if (api == "SetFilePointerEx") {
				// The 64-bit distance arrives as two words; the shared handler takes it whole.
				const auto words = process.api_arguments(5);
				const auto entry = shared_api.find("SetFilePointerEx");
				if (!entry) {
					std::cerr << "raven: unimplemented native x86 API " << api << '\n';
					return result;
				}
				ApiCall inner(process, environment, {words[0], uint64_t(int64_t(int32_t(words[2])) << 32 | words[1]), words[3], words[4]});
				entry->second(inner);
				process.return_api(inner.result);
				budget = remaining();
				result = process.resume(budget);
				continue;
			}
			if (api == "RaiseException") {
				const auto words = process.api_arguments(4);
				std::cerr << "raven: unhandled exception 0x" << std::hex << uint32_t(words[0]) << std::dec << " raised by the program\n";
				process.abandon_call();
				throw ProcessExit{uint32_t(words[0]), result.instruction};
			}
			if (api == "CreateFontA") {
				// The face name is an ANSI string; the shared handler takes the wide form of the same call.
				auto words = process.api_arguments(14);
				words[13] = compat.widen(words[13]);
				const auto entry = shared_api.find("CreateFontW");
				if (!entry) {
					std::cerr << "raven: unimplemented native x86 API " << api << '\n';
					return result;
				}
				ApiCall inner(process, environment, words);
				entry->second(inner);
				process.return_api(inner.result);
				budget = remaining();
				result = process.resume(budget);
				continue;
			}
			if (api == "MonitorFromPoint") {
				// A POINT passed by value is two words here and one packed word in the shared handler.
				const auto words = process.api_arguments(3);
				const auto entry = shared_api.find("MonitorFromPoint");
				if (!entry) {
					std::cerr << "raven: unimplemented native x86 API " << api << '\n';
					return result;
				}
				ApiCall inner(process, environment, {uint64_t(uint32_t(words[1])) << 32 | uint32_t(words[0]), words[2]});
				entry->second(inner);
				process.return_api(inner.result);
				budget = remaining();
				result = process.resume(budget);
				continue;
			}
			if (api == "TerminateProcess") {
				const auto words = process.api_arguments(2);
				if (words[0] != UINT32_MAX) {
					environment.set_last_error(6);
					process.return_api(0);
					budget = remaining();
					result = process.resume(budget);
					continue;
				}
				process.abandon_call();
				throw ProcessExit{uint32_t(words[1]), result.instruction};
			}
			if (api == "ExitProcess" || api == "exit" || api == "_exit") {
				const auto code = uint32_t(process.api_arguments(1)[0]);
				process.abandon_call();
				throw ProcessExit{code, result.instruction};
			}
			if (!environment.dispatch(api) && !thread_api.dispatch(api) && !system_api.dispatch(api) && !compat.dispatch(api) && !direct3d9.dispatch(api) &&
#ifdef RAVEN_VULKAN_THUNK32
				!vulkan32.dispatch(api) &&
#endif
				 !object_api.dispatch(api) && !module_api.dispatch(api) && !resources.dispatch(api) &&
				!memory.dispatch(api) && !kernel_string_api(process, environment, entry, *launch, api) &&
				!desktop.dispatch(api) && !windows.dispatch(api) && !advapi.dispatch(api) && !profile.dispatch(api) &&
				!crt.dispatch(api) && !unsupported_library(process, environment, api) &&
				!(shared_names.contains(api) && shared_api.dispatch(process, environment, api, true))) {
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
	guest_threads.set_runner(invoke);
	// Threads announce themselves to the images that keep per-thread state: TLS callbacks first, then the library entry points.
	guest_threads.set_notifier([&](uint32_t reason) {
		const auto notify = [&](const PEModule &module) {
			for (const auto callback : static_tls.callbacks(module)) {
				const uint64_t arguments[] = {module.loaded.base(), reason, 0};
				const auto result = invoke(callback, arguments);
				if (result.stop != NativeStop::returned)
					throw result;
			}
			if ((module.image.characteristics & 0x2000) && module.image.entry && !module.runtime_api && &module != &entry) {
				const uint64_t arguments[] = {module.loaded.base(), reason, 0};
				const auto result = invoke(module.loaded.base() + module.image.entry, arguments);
				if (result.stop != NativeStop::returned)
					throw result;
			}
		};
		if (reason == 2) {
			notify(entry);
			for (const auto &[name, module] : modules.all())
				if (module.get() != &entry)
					notify(*module);
		} else {
			for (const auto &[name, module] : modules.all())
				if (module.get() != &entry)
					notify(*module);
			notify(entry);
		}
	});
	call_guest = invoke;
	// File, memory, text and system handlers of the shared registry take 32-bit words as well; they get the same process services.
	NativeHeap guest_heap(process, environment, modules, entry.image);
	GuestAllocator allocator(memory, guest_heap);
	KernelContext kernel{process, environment, memory, allocator, kernel_objects, guest_threads, paths, modules, entry, *launch, invoke};
	register_file_api(shared_api, kernel);
	register_memory_api(shared_api, kernel);
	register_text_api(shared_api, kernel);
	register_system_api(shared_api, kernel);
	register_process_api(shared_api, kernel);
	register_ansi_adapters(shared_api);
	register_legacy_file_api(shared_api);
	windows.set_yield([&guest_threads] { return guest_threads.live() > 1 && guest_threads.yield(); });
	crt.set_call(invoke);
	try {
		// Images of the startup graph with thread local storage get their blocks, and their callbacks hear about the process starting.
		for (const auto &[name, module] : modules.all())
			static_tls.add(*module);
		for (const auto &[name, module] : modules.all())
			for (const auto callback : static_tls.callbacks(*module)) {
				const uint64_t arguments[] = {module->loaded.base(), 1, 0};
				const auto started = invoke(callback, arguments);
				if (started.stop != NativeStop::returned)
					throw started;
			}
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

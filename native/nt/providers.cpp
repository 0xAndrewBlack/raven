#include "providers.h"
#include "child_process.h"
#include "handle_channel.h"
#include "section.h"
#include "ansi_api.h"
#include "module_api.h"
#include "loader.h"
#include "tls.h"
#include "exceptions.h"
#include "resources.h"
#include "memory.h"
#include "object_api.h"
#include "heap.h"
#include "api.h"
#include "apiset.h"
#include "text.h"
#include "kernel_context.h"
#include "unwind.h"
#include "prefix.h"
#include "profile_api.h"
#include "runtime_profile.h"
#include "registry.h"
#include "system_exports.h"
#include "desktop/api.h"
#include "desktop/windows.h"
#ifdef RAVEN_VULKAN
#include "graphics/vulkan_bridge.h"
#endif

#include <unistd.h>
#include <sys/mman.h>
#include <x86intrin.h>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <array>
#include <stdexcept>
#include <csignal>

namespace raven {

// A whole host file in one read: libraries such as a browser's main DLL run to hundreds of megabytes, and reading them a character at
// a time through a stream iterator cost seconds in every process that loads them.
static std::vector<uint8_t> read_host_file(const std::filesystem::path &path)
{
	std::ifstream stream(path, std::ios::binary | std::ios::ate);
	const auto size = stream ? stream.tellg() : std::streampos(-1);
	if (size <= 0)
		return {};
	std::vector<uint8_t> bytes(static_cast<size_t>(size));
	stream.seekg(0);
	if (!stream.read(reinterpret_cast<char *>(bytes.data()), size))
		bytes.resize(static_cast<size_t>(stream.gcount()));
	return bytes;
}

// PathCchCombineEx and PathCchSkipRoot live in kernelbase.dll on Windows and are not in the import libraries the public lists come from.
static constexpr std::array<std::string_view, 47> names{
	"CloseHandle","CreateEventA","CreateEventW","ExitProcess",
	"FindResourceA", "FindResourceExA", "FindResourceExW", "FindResourceW", "FreeLibrary",
	"GetACP", "GetCommandLineA", "GetCommandLineW", "GetCurrentProcessId", "GetCurrentThreadId", "GetFileType", "GetLastError", "GetModuleHandleA",
	"GetModuleHandleW", "GetProcAddress", "GetProcessHeap", "GetStartupInfoA", "GetStartupInfoW", "GetStdHandle", "HeapAlloc", "HeapCreate", "HeapDestroy", "HeapFree", "HeapReAlloc", "HeapSize",
	"LoadLibraryA", "LoadLibraryW", "LoadResource",
	"LockResource", "MultiByteToWideChar", "PathCchCombineEx", "PathCchSkipRoot", "RaiseException", "ResetEvent", "SetEvent", "SetLastError", "SizeofResource",
	"VirtualAlloc", "VirtualFree", "VirtualProtect", "VirtualQuery", "WaitForSingleObject", "WriteFile"
};

std::vector<uint8_t> environment_provider(std::string_view name, uint64_t base)
{
	if (name != "kernel32.dll" && name != "kernelbase.dll")
		throw std::runtime_error("unsupported environment provider module");
	return runtime_provider(name, base, names);
}

namespace {

// Hot kernel32 services that run as guest machine code on the thread block; the slow path traps at offset 0x30.
struct FastStub {
	std::string_view name;
	std::vector<uint8_t> code;
};

const std::vector<FastStub> &fast_stubs()
{
	static const std::vector<FastStub> stubs = {
		// mov eax, gs:[0x68]; ret
		{"GetLastError", {0x65, 0x8b, 0x04, 0x25, 0x68, 0, 0, 0, 0xc3}},
		// mov eax, gs:[0x48]; ret (the thread's ClientId.UniqueThread)
		{"GetCurrentThreadId", {0x65, 0x8b, 0x04, 0x25, 0x48, 0, 0, 0, 0xc3}},
		// mov eax, gs:[0x40]; ret (the thread's ClientId.UniqueProcess)
		{"GetCurrentProcessId", {0x65, 0x8b, 0x04, 0x25, 0x40, 0, 0, 0, 0xc3}},
		// mov gs:[0x68], ecx; ret
		{"SetLastError", {0x65, 0x89, 0x0c, 0x25, 0x68, 0, 0, 0, 0xc3}},
		// mov rax, -1; ret (the pseudo handle of the current process)
		{"GetCurrentProcess", {0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff, 0xc3}},
		// mov rax, -2; ret (the pseudo handle of the current thread)
		{"GetCurrentThread", {0x48, 0xc7, 0xc0, 0xfe, 0xff, 0xff, 0xff, 0xc3}},
		// cmp ecx,64; jae slow; mov ecx,ecx; mov rax,gs:[rcx*8+0x1480]; mov dword gs:[0x68],0; ret
		{"TlsGetValue", {0x83, 0xf9, 0x40, 0x73, 0x2b, 0x8b, 0xc9, 0x65, 0x48, 0x8b, 0x04, 0xcd, 0x80, 0x14, 0, 0,
			0x65, 0xc7, 0x04, 0x25, 0x68, 0, 0, 0, 0, 0, 0, 0, 0xc3}},
		// cmp ecx,64; jae slow; mov ecx,ecx; mov gs:[rcx*8+0x1480],rdx; mov eax,1; ret
		{"TlsSetValue", {0x83, 0xf9, 0x40, 0x73, 0x2b, 0x8b, 0xc9, 0x65, 0x48, 0x89, 0x14, 0xcd, 0x80, 0x14, 0, 0,
			0xb8, 1, 0, 0, 0, 0xc3}},
		// mov rax,gs:[0x17c8]; test rax,rax; jz slow; cmp ecx,4080; jae slow; mov ecx,ecx; mov rax,[rax+rcx*8]; mov dword gs:[0x68],0; ret
		{"FlsGetValue", {0x65, 0x48, 0x8b, 0x04, 0x25, 0xc8, 0x17, 0, 0, 0x48, 0x85, 0xc0, 0x74, 0x22,
			0x81, 0xf9, 0xf0, 0x0f, 0, 0, 0x73, 0x1a, 0x8b, 0xc9, 0x48, 0x8b, 0x04, 0xc8,
			0x65, 0xc7, 0x04, 0x25, 0x68, 0, 0, 0, 0, 0, 0, 0, 0xc3}},
		// The same without touching the last error, as the second form does.
		{"FlsGetValue2", {0x65, 0x48, 0x8b, 0x04, 0x25, 0xc8, 0x17, 0, 0, 0x48, 0x85, 0xc0, 0x74, 0x22,
			0x81, 0xf9, 0xf0, 0x0f, 0, 0, 0x73, 0x1a, 0x8b, 0xc9, 0x48, 0x8b, 0x04, 0xc8, 0xc3}},
		// A one-time initialization that has completed answers in the guest; any other state is served.
		// mov rax,[rcx]; mov r10,rax; and r10,3; cmp r10,2; jne slow; test r9,r9; jz done; and rax,-4; mov [r9],rax; done: mov eax,1; ret
		{"InitOnceExecuteOnce", {0x48, 0x8b, 0x01, 0x49, 0x89, 0xc2, 0x49, 0x83, 0xe2, 0x03, 0x49, 0x83, 0xfa, 0x02, 0x75, 0x20,
			0x4d, 0x85, 0xc9, 0x74, 0x07, 0x48, 0x83, 0xe0, 0xfc, 0x49, 0x89, 0x01, 0xb8, 1, 0, 0, 0, 0xc3}},
	};
	return stubs;
}

}

// Calls that only read and write guest memory: their stubs leave the arguments in a block the runtime shares with the guest and spin until
// the answer is there, so the guest never stops for them.
static bool served_api(std::string_view module, std::string_view name)
{
	if (module == "kernel32.dll" || module == "kernelbase.dll")
		return name == "QueryPerformanceCounter" || name == "QueryPerformanceFrequency" || name == "WakeConditionVariable" ||
			name == "WakeAllConditionVariable";
	// Waking marks the sleepers; they run when the scheduler next picks a thread.
	if (module == "ntdll.dll")
		return name == "RtlWakeConditionVariable" || name == "RtlWakeAllConditionVariable";
	if (module != "vulkan-1.dll")
		return false;
	static constexpr std::array<std::string_view, 22> recording{
		"vkAcquireNextImageKHR", "vkAllocateCommandBuffers", "vkAllocateDescriptorSets", "vkBeginCommandBuffer", "vkEndCommandBuffer", "vkFreeCommandBuffers",
		"vkFreeDescriptorSets", "vkGetFenceStatus", "vkGetSemaphoreCounterValue", "vkGetSemaphoreCounterValueKHR", "vkQueueSubmit",
		"vkQueueSubmit2", "vkQueueSubmit2KHR", "vkResetCommandBuffer", "vkResetCommandPool", "vkResetDescriptorPool", "vkResetFences",
		"vkSignalSemaphore", "vkSignalSemaphoreKHR", "vkUpdateDescriptorSetWithTemplate", "vkUpdateDescriptorSetWithTemplateKHR",
		"vkUpdateDescriptorSets"};
	return name.starts_with("vkCmd") || std::find(recording.begin(), recording.end(), name) != recording.end();
}

// A served stub: it loads the block address from the provider's own pointer, which stays zero until the runtime maps the block, stores
// RCX, RDX, R8, R9, RSP and the low halves of XMM0 to XMM3, publishes its own address and spins until the runtime clears it. After a
// thousand rounds it stops at a breakpoint instead, which gives the processor to the runtime when the two compete for it.
static constexpr size_t served_stub_size = 128, served_trap = 0x70, served_wait = 85;

static std::vector<uint8_t> served_stub(int32_t to_pointer)
{
	std::vector<uint8_t> code{0x4c, 0x8b, 0x15, 0, 0, 0, 0, 0x4d, 0x85, 0xd2, 0x74, uint8_t(served_trap - 12),
		0x49, 0x89, 0x4a, 0x08, 0x49, 0x89, 0x52, 0x10, 0x4d, 0x89, 0x42, 0x18, 0x4d, 0x89, 0x4a, 0x20, 0x49, 0x89, 0x62, 0x28,
		0x66, 0x49, 0x0f, 0x7e, 0x42, 0x30, 0x66, 0x49, 0x0f, 0x7e, 0x4a, 0x38, 0x66, 0x49, 0x0f, 0x7e, 0x52, 0x40, 0x66, 0x49, 0x0f, 0x7e, 0x5a, 0x48,
		0x4c, 0x8d, 0x1d, 0xc1, 0xff, 0xff, 0xff, 0x4d, 0x89, 0x1a,
		// mov r11d, 1000; spin: pause; cmp qword [r10], 0; je done; dec r11d; jnz spin; int3; jmp to the compare; nop
		0x41, 0xbb, 0xe8, 0x03, 0x00, 0x00, 0xf3, 0x90, 0x49, 0x83, 0x3a, 0x00, 0x74, 0x0a, 0x41, 0xff, 0xcb, 0x75, 0xf3, 0xcc, 0xeb, 0xf2,
		0x66, 0x90,
		// done: mov rax, [r10+80]; ret
		0x49, 0x8b, 0x42, 0x50, 0xc3};
	const int32_t displacement = to_pointer - 7;
	std::memcpy(code.data() + 3, &displacement, 4);
	code.resize(served_trap + 2);
	code[served_trap] = 0xcc;
	code[served_trap + 1] = 0xc3;
	return code;
}

// The performance counter is read in the guest once the runtime has published how the processor's time stamp counter relates to it: the
// stub exported for it is a prelude that computes the count from RDTSC and falls back to its served stub until then. The calibration sits
// in the served block: the counter value at the base, the count at the base, and the multiplier, a 32.32 fixed-point count per tick of
// the time stamp counter, written last.
static bool guest_clock_api(std::string_view module, std::string_view name)
{
	return (module == "kernel32.dll" || module == "kernelbase.dll") && name == "QueryPerformanceCounter";
}

static constexpr size_t clock_prelude_size = 96, clock_calibration = 0x800;

static std::vector<uint8_t> clock_prelude(int32_t to_pointer, int32_t to_served)
{
	std::vector<uint8_t> code{
		// mov r10, [pointer]; test r10, r10; jz served
		0x4c, 0x8b, 0x15, 0, 0, 0, 0, 0x4d, 0x85, 0xd2, 0x0f, 0x84, 0, 0, 0, 0,
		// mov r11, [r10 + multiplier]; test r11, r11; jz served
		0x4d, 0x8b, 0x9a, 0x10, 0x08, 0, 0, 0x4d, 0x85, 0xdb, 0x0f, 0x84, 0, 0, 0, 0,
		// rdtsc; shl rdx, 32; or rax, rdx; sub rax, [r10 + base counter]; mul r11; shrd rax, rdx, 32; add rax, [r10 + base count]
		0x0f, 0x31, 0x48, 0xc1, 0xe2, 0x20, 0x48, 0x09, 0xd0, 0x49, 0x2b, 0x82, 0x00, 0x08, 0, 0, 0x49, 0xf7, 0xe3, 0x48, 0x0f, 0xac, 0xd0, 0x20,
		0x49, 0x03, 0x82, 0x08, 0x08, 0, 0,
		// mov [rcx], rax; mov eax, 1; ret
		0x48, 0x89, 0x01, 0xb8, 1, 0, 0, 0, 0xc3};
	const int32_t displacement = to_pointer - 7;
	std::memcpy(code.data() + 3, &displacement, 4);
	for (const size_t jump : {size_t(12), size_t(28)}) {
		const int32_t relative = to_served - int32_t(jump + 4);
		std::memcpy(code.data() + jump, &relative, 4);
	}
	return code;
}

// Committing pages that are already open in the guest is done by the guest itself: the runtime publishes the open ranges in the served
// block, and the prelude of VirtualAlloc logs a read-write commit that falls in one of them there instead of stopping; the runtime takes
// the log into its accounting before its next memory operation. Anything else jumps to the export's breakpoint.
static bool guest_commit_api(std::string_view module, std::string_view name)
{
	return (module == "kernel32.dll" || module == "kernelbase.dll") && name == "VirtualAlloc";
}

static constexpr size_t commit_prelude_size = 192, commit_jump = 37;

static std::vector<uint8_t> commit_prelude(int32_t to_pointer, int32_t to_trap)
{
	// mov r10,[pointer]; test r10,r10; jz slow; test rcx,rcx; jz slow; test rdx,rdx; jz slow; cmp r8d,MEM_COMMIT; jne slow;
	// cmp r9d,PAGE_READWRITE; je main; slow: jmp trap; restore: mov r8d,MEM_COMMIT; mov r9d,PAGE_READWRITE; jmp slow;
	// main: rax = first page, r11 = end page; jbe slow; look through the open ranges at commit_windows for one holding [rax, r11),
	// take a log slot with lock xadd at commit_log, store the range there and return rax; a full log or no range goes back to restore.
	std::vector<uint8_t> code{0x4c, 0x8b, 0x15, 0, 0, 0, 0, 0x4d, 0x85, 0xd2, 0x74, 0x19, 0x48, 0x85, 0xc9, 0x74, 0x14, 0x48, 0x85, 0xd2,
		0x74, 0x0f, 0x41, 0x81, 0xf8, 0x00, 0x10, 0x00, 0x00, 0x75, 0x06, 0x41, 0x83, 0xf9, 0x04, 0x74, 0x13, 0xe9, 0, 0, 0, 0, 0x41,
		0xb8, 0x00, 0x10, 0x00, 0x00, 0x41, 0xb9, 0x04, 0x00, 0x00, 0x00, 0xeb, 0xed, 0x48, 0x89, 0xc8, 0x48, 0x25, 0x00, 0xf0, 0xff,
		0xff, 0x4c, 0x8d, 0x9c, 0x11, 0xff, 0x0f, 0x00, 0x00, 0x49, 0x81, 0xe3, 0x00, 0xf0, 0xff, 0xff, 0x49, 0x39, 0xc3, 0x76, 0xd0,
		0x45, 0x8b, 0x82, 0x00, 0x0a, 0x00, 0x00, 0x4d, 0x8d, 0x8a, 0x08, 0x0a, 0x00, 0x00, 0x45, 0x85, 0xc0, 0x74, 0xc2, 0x49, 0x3b,
		0x01, 0x72, 0x30, 0x4d, 0x3b, 0x59, 0x08, 0x77, 0x2a, 0x41, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xf0, 0x45, 0x0f, 0xc1, 0x82, 0x10,
		0x0b, 0x00, 0x00, 0x41, 0x83, 0xf8, 0x30, 0x73, 0xa2, 0x49, 0xc1, 0xe0, 0x04, 0x4b, 0x89, 0x84, 0x02, 0x18, 0x0b, 0x00, 0x00,
		0x4f, 0x89, 0x9c, 0x02, 0x20, 0x0b, 0x00, 0x00, 0xc3, 0x49, 0x83, 0xc1, 0x10, 0x41, 0xff, 0xc8, 0xeb, 0xbd};
	static_assert(NativeMemory::commit_windows == 0xa00 && NativeMemory::commit_log == 0xb10 && NativeMemory::commit_window_count == 16 &&
		NativeMemory::commit_log_count == 48, "the commit prelude's offsets are written into its code");
	const int32_t displacement = to_pointer - 7;
	std::memcpy(code.data() + 3, &displacement, 4);
	const int32_t relative = to_trap - int32_t(commit_jump + 5);
	std::memcpy(code.data() + commit_jump + 1, &relative, 4);
	return code;
}

// Where the served stub behind an export sits: the export itself, or the stub a clock prelude falls back to; for a commit prelude, the
// breakpoint it falls back to.
static uint32_t served_stub_rva(std::span<const uint8_t> image, std::string_view module, std::string_view name, uint32_t rva)
{
	if (guest_commit_api(module, name)) {
		int32_t relative = 0;
		std::memcpy(&relative, image.data() + rva + commit_jump + 1, 4);
		return uint32_t(int64_t(rva) + commit_jump + 5 + relative);
	}
	if (!guest_clock_api(module, name))
		return rva;
	int32_t relative = 0;
	std::memcpy(&relative, image.data() + rva + 12, 4);
	return uint32_t(int64_t(rva) + 16 + relative);
}

// Offset of the slow-path breakpoint inside a fast or served stub.
size_t fast_stub_trap_offset(std::string_view module, std::string_view name)
{
	if (served_api(module, name))
		return served_trap;
	if (module != "kernel32.dll" && module != "kernelbase.dll")
		return 0;
	for (const auto &stub : fast_stubs())
		if (stub.name == name)
			return 0x30;
	return 0;
}

std::vector<uint8_t> runtime_provider(std::string_view name, uint64_t base,
	std::span<const std::string_view> exports, bool x86, std::span<const std::string_view> data_exports,
	std::span<const std::pair<std::string_view, uint16_t>> ordinal_exports, bool fast_paths)
{
	if (!x86 && !data_exports.empty())
		throw std::runtime_error("native data exports require an x86 provider");
	for (const auto symbol : data_exports)
		if (!std::binary_search(exports.begin(), exports.end(), symbol))
			throw std::runtime_error("native data export is missing from the export table");
	if (exports.empty() || exports.size() > 4096 || name.empty() || name.size() > 63 || name.find('\0') != name.npos ||
		!std::is_sorted(exports.begin(), exports.end()) || std::adjacent_find(exports.begin(), exports.end()) != exports.end())
		throw std::runtime_error("invalid native provider export table");
	size_t string_size = name.size() + 1;
	for (const auto symbol : exports) {
		if (symbol.empty() || symbol.find('\0') != symbol.npos || symbol.size() + 1 > 1024 * 1024 - string_size)
			throw std::runtime_error("native provider export names exceed policy limit");
		string_size += symbol.size() + 1;
	}
	// Every export owns a slot; public ordinals pin a name to its Windows slot and the other names fill the gaps.
	std::vector<uint32_t> slot_of(exports.size(), 0);
	uint32_t slot_count = 0;
	for (const auto &[exported, ordinal] : ordinal_exports) {
		const auto found = std::lower_bound(exports.begin(), exports.end(), exported);
		if (found == exports.end() || *found != exported || !ordinal)
			throw std::runtime_error("native provider ordinal names an unknown export");
		auto &slot = slot_of[size_t(found - exports.begin())];
		if (slot)
			throw std::runtime_error("native provider ordinal is assigned twice");
		slot = ordinal;
		slot_count = std::max<uint32_t>(slot_count, ordinal);
	}
	std::vector<bool> taken(size_t(slot_count) + exports.size() + 1, false);
	for (const auto slot : slot_of)
		if (slot && taken[slot])
			throw std::runtime_error("native provider ordinal collides with another export");
		else if (slot)
			taken[slot] = true;
	uint32_t next_slot = 1;
	for (auto &slot : slot_of)
		if (!slot) {
			while (taken[next_slot])
				++next_slot;
			slot = next_slot;
			taken[slot] = true;
			slot_count = std::max(slot_count, slot);
		}
	const bool numbered = !ordinal_exports.empty();
	const size_t function_count = numbered ? slot_count : exports.size();
	const size_t directory = 0x200 + exports.size() * 16;
	const size_t functions = directory + 40;
	const size_t name_table = functions + function_count * 4;
	const size_t ordinals = name_table + exports.size() * 4;
	const size_t module_name = ordinals + exports.size() * 2;
	// Each data export owns one zeroed 16-byte slot after the strings; the section becomes writable for them.
	const size_t data_start = (module_name + string_size + 15) & ~size_t(15);
	const bool kernel_module = fast_paths && !x86 && (name == "kernel32.dll" || name == "kernelbase.dll");
	size_t fast_count = 0;
	if (kernel_module)
		for (const auto symbol : exports)
			for (const auto &stub : fast_stubs())
				fast_count += stub.name == symbol;
	const size_t fast_start = (data_start + data_exports.size() * 16 + 63) & ~size_t(63);
	size_t served_count = 0;
	if (!x86)
		for (const auto symbol : exports)
			served_count += served_api(name, symbol);
	size_t clock_count = 0;
	if (!x86)
		for (const auto symbol : exports)
			clock_count += guest_clock_api(name, symbol);
	size_t commit_count = 0;
	if (!x86 && served_count)
		for (const auto symbol : exports)
			commit_count += guest_commit_api(name, symbol);
	// The block pointer of the served stubs, then the stubs, then the clock preludes, then the commit preludes.
	const size_t served_start = fast_start + fast_count * 64;
	const size_t clock_start = served_start + (served_count ? 64 + served_count * served_stub_size : 0);
	const size_t commit_start = clock_start + clock_count * clock_prelude_size;
	const size_t end = commit_start + commit_count * commit_prelude_size;
	std::vector<uint8_t> bytes((end + 511) & ~size_t(511));
	const auto rva = [](size_t offset) { return 0x1000 + offset - 0x200; };
	const auto put = [&](size_t offset, uint64_t value, size_t width = 4) {
		for (size_t index = 0; index < width; ++index)
			bytes.at(offset + index) = static_cast<uint8_t>(value >> (index * 8));
	};
	const auto text = [&](size_t offset, std::string_view value) {
		std::copy(value.begin(), value.end(), bytes.begin() + static_cast<ptrdiff_t>(offset));
	};
	put(0, 0x5a4d, 2);
	put(0x3c, 0x80);
	put(0x80, 0x4550);
	// PE32 headers end 16 bytes earlier: no BaseOfData widening, a 4-byte image base and 224 optional bytes.
	const size_t count_field = x86 ? 0xf4 : 0x104;
	const size_t section = x86 ? 0x178 : 0x188;
	put(0x84, x86 ? 0x14c : 0x8664, 2);
	put(0x86, 1, 2);
	put(0x94, x86 ? 224 : 240, 2);
	put(0x96, x86 ? 0x2103 : 0x2003, 2);
	put(0x98, x86 ? 0x10b : 0x20b, 2);
	if (x86 && base > UINT32_MAX - 0x100000)
		throw std::runtime_error("native x86 provider base exceeds the 32-bit address space");
	put(x86 ? 0xb4 : 0xb0, base, x86 ? 4 : 8);
	put(0xb8, 0x1000);
	put(0xbc, 0x200);
	put(0xd0, (rva(bytes.size()) + 4095) & ~size_t(4095));
	put(0xd4, 0x200);
	put(0xdc, 3, 2);
	put(count_field, 16);
	put(count_field + 4, rva(directory));
	// Data slots stay outside the export directory range, or loaders would treat them as forwarders.
	put(count_field + 8, data_start - directory);
	text(section, ".api");
	put(section + 8, bytes.size() - 0x200);
	put(section + 12, 0x1000);
	put(section + 16, bytes.size() - 0x200);
	put(section + 20, 0x200);
	put(section + 36, data_exports.empty() ? 0x60000020 : 0xe0000020);
	put(directory + 12, rva(module_name));
	// Only the independently verified common-controls identity receives a public ordinal.
	const bool icon_control = name == "comctl32.dll" && exports.size() == 1 && exports[0] == "LoadIconWithScaleDown";
	// Names without a public number take the top of the 16-bit ordinal range, where no program imports by number; ordinals are
	// words, and code that adds the base to an index in a word must not wrap.
	put(directory + 16, numbered ? 1 : icon_control ? 381 : uint32_t(0x10000 - function_count));
	put(directory + 20, function_count);
	put(directory + 24, exports.size());
	put(directory + 28, rva(functions));
	put(directory + 32, rva(name_table));
	put(directory + 36, rva(ordinals));
	text(module_name, name);
	size_t cursor = module_name + name.size() + 1;
	size_t fast_next = 0, served_next = 0, clock_next = 0, commit_next = 0;
	for (size_t index = 0; index < exports.size(); ++index) {
		size_t code = 0x200 + index * 16;
		bytes[code] = 0xcc;
		bytes[code + 1] = 0xc3;
		if (!x86 && served_api(name, exports[index])) {
			code = served_start + 64 + served_next++ * served_stub_size;
			const auto stub = served_stub(int32_t(served_start) - int32_t(code));
			std::copy(stub.begin(), stub.end(), bytes.begin() + ptrdiff_t(code));
			if (guest_clock_api(name, exports[index])) {
				const size_t served = code;
				code = clock_start + clock_next++ * clock_prelude_size;
				const auto prelude = clock_prelude(int32_t(served_start) - int32_t(code), int32_t(served) - int32_t(code));
				std::copy(prelude.begin(), prelude.end(), bytes.begin() + ptrdiff_t(code));
			}
		}
		if (!x86 && served_count && guest_commit_api(name, exports[index])) {
			const size_t trap = code;
			code = commit_start + commit_next++ * commit_prelude_size;
			const auto prelude = commit_prelude(int32_t(served_start) - int32_t(code), int32_t(trap) - int32_t(code));
			std::copy(prelude.begin(), prelude.end(), bytes.begin() + ptrdiff_t(code));
		}
		if (kernel_module)
			for (const auto &stub : fast_stubs())
				if (stub.name == exports[index]) {
					code = fast_start + fast_next++ * 64;
					std::copy(stub.code.begin(), stub.code.end(), bytes.begin() + ptrdiff_t(code));
					bytes[code + 0x30] = 0xcc;
					bytes[code + 0x31] = 0xc3;
				}
		const auto data = std::find(data_exports.begin(), data_exports.end(), exports[index]);
		const size_t entry = numbered ? slot_of[index] - 1 : index;
		put(functions + entry * 4, data == data_exports.end() ? rva(code) : rva(data_start + size_t(data - data_exports.begin()) * 16));
		put(name_table + index * 4, rva(cursor));
		put(ordinals + index * 2, entry, 2);
		text(cursor, exports[index]);
		cursor += exports[index].size() + 1;
	}
	return bytes;
}

// The native API providers sit high in the address space, as Windows places its system libraries: the low default bases are what
// programs' own libraries ask for (0x180000000 for most 64-bit DLLs), and a library that finds its base taken is relocated in every
// process that loads it. The host keeps its own mappings above 0x700000000000.
static uint64_t provider_base(const ModuleSet &modules, uint32_t size)
{
	uint64_t base = 0x6fff00000000ULL;
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
		if (base >= 0x800000000000ULL - size)
			throw std::runtime_error("no address available for native API provider");
		if (!overlap)
			return base;
	}
}

NativeResult run_native_process(ModuleSet &modules, PEModule &entry,
	const std::string &bootstrap, std::chrono::milliseconds timeout,
	std::function<std::optional<std::vector<uint8_t>>(std::string_view)> source,
	std::function<void(std::span<const uint8_t>)> debug, DesktopPresentation presentation,
	std::optional<NativeLaunch> launch)
{
	if (timeout.count() <= 0 || (entry.image.characteristics & 0x2000) ||
		!std::any_of(modules.all().begin(), modules.all().end(), [&](const auto &item) { return item.second.get() == &entry; }))
		throw std::runtime_error("native process requires an executable graph and positive timeout");
	for (const auto &[name,module]:modules.all()) validate_native_image(module->image,name);
	std::vector<std::string_view> native_modules{"kernel32.dll","kernelbase.dll","user32.dll","gdi32.dll","comctl32.dll","ntdll.dll"};
	for (const auto library : system_library_names())
		if (std::find(native_modules.begin(), native_modules.end(), library) == native_modules.end())
			native_modules.push_back(library);
#ifdef RAVEN_VULKAN
	native_modules.push_back("vulkan-1.dll");
#endif
	load_initial_dependencies(modules,source,native_modules);
	std::map<uint64_t, std::string> traps;
	std::map<uint64_t,std::pair<uint32_t,std::string>> services;
	std::vector<std::string_view> nt_names(NativeMemory::nt_exports().begin(),NativeMemory::nt_exports().end());
	nt_names.insert(nt_names.end(),NativeEnvironment::nt_exports().begin(),NativeEnvironment::nt_exports().end());
	nt_names.insert(nt_names.end(),NativeObjectAPI::nt_exports().begin(),NativeObjectAPI::nt_exports().end());
	const bool has_heap=modules.all().contains("raven-rtl.dll");
	if (has_heap) {
		if (modules.all().contains("ntdll.dll") && !modules.all().at("ntdll.dll")->runtime_api)
			throw std::runtime_error("native RTL component cannot share heap ownership with a supplied ntdll");
		nt_names.insert(nt_names.end(),NativeHeap::nt_exports().begin(),NativeHeap::nt_exports().end());
		for (const auto name : {"DbgBreakPoint","DbgPrint","NtQueryInformationThread","NtReleaseKeyedEvent",
			"NtWaitForKeyedEvent","RtlRaiseException","RtlRaiseStatus","ZwAllocateVirtualMemory","ZwFreeVirtualMemory",
			"ZwProtectVirtualMemory","ZwQueryPerformanceCounter","ZwQuerySystemInformation","ZwQueryVirtualMemory"})
			nt_names.push_back(name);
	}
	// Natives that the shared API registry implements.
	for (const auto name : {"NtQuerySection", "NtFlushInstructionCache", "RtlAddGrowableFunctionTable", "RtlGrowFunctionTable", "RtlDeleteGrowableFunctionTable",
		"NtWriteFile", "RtlNtStatusToDosError", "NtQueryObject", "NtMapViewOfSection", "NtUnmapViewOfSection",
		"RtlAcquireSRWLockExclusive", "RtlAcquireSRWLockShared", "RtlWakeConditionVariable", "RtlWakeAllConditionVariable", "RtlWaitOnAddress",
		"RtlWakeAddressSingle", "RtlWakeAddressAll"})
		if (std::find(nt_names.begin(),nt_names.end(),name)==nt_names.end()) nt_names.push_back(name);
	std::sort(nt_names.begin(),nt_names.end());
	// Every Windows system library that a program may import gets a provider; names without a handler stop visibly when called.
	std::vector<std::string> system_modules{"kernel32.dll", "kernelbase.dll", "user32.dll", "gdi32.dll", "comctl32.dll"};
	for (const auto library : system_library_names())
		if (std::find(system_modules.begin(), system_modules.end(), library) == system_modules.end())
			system_modules.emplace_back(library);
	// A number with no name known for it still gets an export, so a program that imports by that number binds, and the call it ends in names the number.
	std::map<std::string, std::vector<std::pair<std::string_view, uint16_t>>> unknown_ordinals;
	std::map<std::string, std::vector<std::string>> unknown_names;
	std::deque<std::string> unknown_storage;
	for (const auto &[module_name, module] : modules.all())
		for (const auto &symbol : module->imports) {
			if (!symbol.by_ordinal)
				continue;
			auto library = symbol.module;
			for (auto &character : library)
				if (character >= 'A' && character <= 'Z')
					character = static_cast<char>(character + ('a' - 'A'));
			if (library.find('.') == library.npos)
				library += ".dll";
			const auto known = system_export_ordinals(library);
			if (std::find(system_modules.begin(), system_modules.end(), library) == system_modules.end() || modules.all().contains(library) ||
				std::any_of(known.begin(), known.end(), [&](const auto &item) { return item.second == symbol.ordinal; }))
				continue;
			const auto text = "Ordinal" + std::to_string(symbol.ordinal);
			if (std::find(unknown_names[library].begin(), unknown_names[library].end(), text) != unknown_names[library].end())
				continue;
			unknown_names[library].push_back(text);
			unknown_ordinals[library].emplace_back(unknown_storage.emplace_back(text), symbol.ordinal);
		}
	for (const auto &name : system_modules) {
		const auto base_symbols = name == "ntdll.dll" ? std::span<const std::string_view>(nt_names) : name == "user32.dll" ? NativeDesktop::user_exports() :
			name == "gdi32.dll" ? NativeDesktop::gdi_exports() :
			name == "comctl32.dll" ? NativeDesktop::control_exports() :
			name == "kernel32.dll" || name == "kernelbase.dll" ? std::span<const std::string_view>(names) : std::span<const std::string_view>();
		const auto library = name == "kernelbase.dll" ? std::string_view("kernel32.dll") : std::string_view(name);
		std::vector<std::string_view> symbols(base_symbols.begin(), base_symbols.end());
		// ntdll.dll answers for what it implements and what the program imports: a program probing for other functions by name must not
		// find ones that cannot run, as it does not on a system that lacks them.
		const auto listed = library == "ntdll.dll" ? std::span<const std::string_view>() : system_export_names(library);
		symbols.insert(symbols.end(), listed.begin(), listed.end());
		if (library == "ntdll.dll")
			for (const auto &[module_name, module] : modules.all())
				for (const auto &symbol : module->imports) {
					auto imported = symbol.module;
					for (auto &character : imported)
						if (character >= 'A' && character <= 'Z')
							character = static_cast<char>(character + ('a' - 'A'));
					if ((imported == "ntdll.dll" || imported == "ntdll") && !symbol.by_ordinal)
						symbols.push_back(unknown_storage.emplace_back(symbol.name));
				}
		if (const auto extra = unknown_ordinals.find(std::string(name)); extra != unknown_ordinals.end())
			for (const auto &item : extra->second)
				symbols.push_back(item.first);
		if (library == "kernel32.dll")
			symbols.push_back("RcConsolidateFrames");
		std::sort(symbols.begin(), symbols.end());
		symbols.erase(std::unique(symbols.begin(), symbols.end()), symbols.end());
		if (symbols.empty())
			continue;
		const auto published_numbers = system_export_ordinals(library);
		std::vector<std::pair<std::string_view, uint16_t>> ordinals(published_numbers.begin(), published_numbers.end());
		if (const auto extra = unknown_ordinals.find(std::string(name)); extra != unknown_ordinals.end())
			ordinals.insert(ordinals.end(), extra->second.begin(), extra->second.end());
		PEModule *provider = nullptr;
		const auto found = modules.all().find(name);
		if (found != modules.all().end()) {
			if (!found->second->runtime_api)
				continue;
			provider = found->second.get();
		} else {
			const auto bytes = runtime_provider(name, 0x180000000ULL, symbols, false, {}, ordinals, true);
			const auto base = provider_base(modules, PEImage(bytes).image_size);
			provider = &modules.add(name, runtime_provider(name, base, symbols, false, {}, ordinals, true), base);
			provider->runtime_api = true;
		}
		// A guest component that implements part of a system library receives those calls directly instead of through a trap.
		if (provider->runtime_api) {
			struct Overlay { const char *library, *component, *prefix; };
			static constexpr Overlay overlays[] = {
				{"user32.dll", "raven-user32.dll", "raven-user32."}, {"comdlg32.dll", "raven-shell.dll", "raven-shell."},
				{"ole32.dll", "raven-shell.dll", "raven-shell."}, {"shell32.dll", "raven-shell.dll", "raven-shell."},
				// The heap, critical sections and the free paths of SRW locks and condition variables run in the guest RTL.
				{"kernel32.dll", "raven-rtl.dll", "raven-rtl."}, {"kernelbase.dll", "raven-rtl.dll", "raven-rtl."}};
			for (const auto &overlay_rule : overlays) {
				if (name != overlay_rule.library)
					continue;
				const auto overlay = modules.all().find(overlay_rule.component);
				if (overlay == modules.all().end() || overlay->second->runtime_api)
					continue;
				for (auto &symbol : provider->exports)
					if (!symbol.names.empty() && std::any_of(overlay->second->exports.begin(), overlay->second->exports.end(), [&](const auto &candidate) {
							return candidate.forwarder.empty() && std::find(candidate.names.begin(), candidate.names.end(), symbol.names.at(0)) != candidate.names.end();
						}))
						symbol.forwarder = overlay_rule.prefix + symbol.names.at(0);
			}
		}
		// The traps of ntdll.dll are made below, where the Zw names answer as their Nt twins.
		if (name != "ntdll.dll")
			for (const auto &symbol : provider->exports)
				if (symbol.address && !symbol.names.empty() && symbol.forwarder.empty())
					traps.emplace(provider->loaded.base() + (provider->runtime_api ? served_stub_rva(provider->loaded.data(), name, symbol.names.at(0), symbol.address) +
						fast_stub_trap_offset(name, symbol.names.at(0)) : symbol.address), symbol.names.at(0));
	}
	const auto nt=modules.all().find("ntdll.dll");
	const bool needs_nt=std::any_of(modules.all().begin(),modules.all().end(),[](const auto &item) {
		return std::any_of(item.second->imports.begin(),item.second->imports.end(),[](const auto &symbol) {
			auto name=symbol.module;
			for (auto &character : name)
				if (character>='A' && character<='Z') character=char(character+('a'-'A'));
			return name=="ntdll.dll" || name=="ntdll";
		});
	});
	if (nt==modules.all().end() && needs_nt) {
		const auto bytes=runtime_provider("ntdll.dll",0x180000000ULL,nt_names);
		const auto base=provider_base(modules,PEImage(bytes).image_size);
		auto &provider=modules.add("ntdll.dll",runtime_provider("ntdll.dll",base,nt_names),base);
		provider.runtime_api=true;
	}
	if (modules.all().contains("ntdll.dll"))
		for (const auto &symbol : modules.all().at("ntdll.dll")->exports)
			for (const auto &name : symbol.names)
				if (symbol.address && (modules.all().at("ntdll.dll")->runtime_api || std::find(nt_names.begin(),nt_names.end(),name)!=nt_names.end()) && symbol.forwarder.empty()) {
					const auto &image=*modules.all().at("ntdll.dll");
					if (image.runtime_api) {
						traps.emplace(image.loaded.base()+symbol.address+fast_stub_trap_offset("ntdll.dll",name),name.starts_with("Zw") ? "Nt"+name.substr(2) : name);
						continue;
					}
					const auto bytes=image.image.file_span(symbol.address,11);
					const bool first=bytes[0]==0xb8 && bytes[5]==0x4c && bytes[6]==0x8b && bytes[7]==0xd1;
					const bool second=bytes[0]==0x4c && bytes[1]==0x8b && bytes[2]==0xd1 && bytes[3]==0xb8;
					if ((!first && !second) || bytes[8]!=0x0f || bytes[9]!=0x05 || bytes[10]!=0xc3)
						throw std::runtime_error("unsupported native NT syscall stub: "+name);
					uint32_t number=0;
					for (size_t byte=0; byte<4; ++byte) number|=uint32_t(bytes[(first ? 1 : 4)+byte])<<(byte*8);
					services.emplace(image.loaded.base()+symbol.address+10,std::pair{number,name});
				}
#ifdef RAVEN_VULKAN
	const auto found_vulkan = modules.all().find("vulkan-1.dll");
	if (found_vulkan == modules.all().end()) {
		const auto bytes = runtime_provider("vulkan-1.dll", 0x180000000ULL, VulkanBridge::exports());
		const auto base = provider_base(modules, PEImage(bytes).image_size);
		auto &provider = modules.add("vulkan-1.dll", runtime_provider("vulkan-1.dll", base, VulkanBridge::exports()), base);
		provider.runtime_api = true;
	}
	if (modules.all().at("vulkan-1.dll")->runtime_api)
		for (const auto &symbol : modules.all().at("vulkan-1.dll")->exports)
			traps.emplace(modules.all().at("vulkan-1.dll")->loaded.base() + symbol.address + fast_stub_trap_offset("vulkan-1.dll", symbol.names.at(0)),
				symbol.names.at(0));
#endif
	alias_api_sets(modules);
	modules.bind_imports();
	auto order = initialization_order(modules, entry);
	// The user32 component registers the built-in classes in its DllMain, before any library that subclasses them.
	if (const auto controls = modules.all().find("raven-user32.dll"); controls != modules.all().end() && !controls->second->runtime_api) {
		const auto found = std::find(order.begin(), order.end(), controls->second.get());
		if (found != order.end()) {
			order.erase(found);
			order.insert(order.begin(), controls->second.get());
		}
	}
	std::vector<LoadedImage *> images;
	for (const auto &[name, module] : modules.all())
		images.push_back(&module->loaded);
	const auto deadline = std::chrono::steady_clock::now() + timeout;
	NativeProcess process(images, bootstrap, timeout);
	for (const auto &[address, name] : traps)
		process.add_api_trap(address);
	NativeEnvironment environment(process, entry.loaded.base(), uint32_t(::getpid()), 1);
	if (!launch) {
		NativeLaunch initial;
		for (const char byte : entry.name) {
			const auto character=static_cast<unsigned char>(byte);
			if (character>127) throw std::runtime_error("native default launch identity requires ASCII");
			initial.image_path.push_back(char16_t(character));
		}
		initial.command_line=u"\""+initial.image_path+u"\"";
		launch=std::move(initial);
	}
	NativeObjects kernel_objects;
	adopt_inherited(kernel_objects,launch->inherited);
	std::array<uint64_t,3> standard_handles{UINT64_MAX,UINT64_MAX,UINT64_MAX};
	for (size_t i=0;i<3;++i) {
		if (launch->standard_fds[i]<0) continue;
		const auto inherited=kernel_objects.inherit_file(launch->standard_fds[i]);
		if (inherited.status) throw std::runtime_error("cannot inherit native standard file");
		standard_handles[i]=inherited.value;
	}
	environment.prepare_parameters(*launch,standard_handles);
	ApiRegistry api_registry, desktop_api;
	NativeLoaderData loader_data(process, environment.peb(), modules, entry);
	NativeTLS tls(process, environment, order);
	NativeModuleAPI module_api(process, environment, modules, entry);
	NativeResources resources(process, environment, modules, entry);
	// What a program may commit: 512 MiB by default, as set by RAVEN_COMMIT_LIMIT_MB (large programs, a browser engine for one, need more).
	const size_t commit_limit=(std::getenv("RAVEN_COMMIT_LIMIT_MB") ? size_t(std::strtoull(std::getenv("RAVEN_COMMIT_LIMIT_MB"),nullptr,10)) : size_t(512))*1024*1024;
	NativeMemory memory(process,environment,commit_limit);
	register_images(memory,modules);
	NativeObjectAPI object_api(process,environment,kernel_objects,deadline);
	NativeHeap heap(process,environment,modules,entry.image);
	DesktopObjects desktop_objects;
	NativeDesktop desktop(process, environment, desktop_objects, resources);
	desktop.set_source(source);
	if (const auto component = modules.all().find("raven-user32.dll"); component != modules.all().end() && !component->second->runtime_api)
		desktop.set_oem_module(component->second->loaded.base());
	NativeWindows windows(process,environment,desktop_objects);
	windows.set_deadline(deadline);
	windows.set_menu_loader([&desktop](uint64_t instance,uint64_t identifier) { return desktop.menu_resource(instance,identifier); });
	windows.set_presentation(std::move(presentation));
	desktop.set_updated([&](uint64_t window) { windows.drawing(window); });
#ifdef RAVEN_VULKAN
	VulkanBridge vulkan(process, modules);
	vulkan.set_surface_source({[&windows](uint64_t window) -> std::optional<std::pair<void *, void *>> {
		const auto surface = windows.host_surface(window);
		if (!surface) return std::nullopt;
		return std::pair<void *, void *>{surface->display, surface->surface};
	}, [&windows](uint64_t window) { windows.release_host_surface(window); },
		[&windows](uint64_t window) { return windows.client_size(window); }});
#endif
	const auto remaining = [&] { return std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()); };
	size_t debug_bytes=0;
	KernelContext *kernel_ptr=nullptr;
	NativeThreads *threads_ptr=nullptr;
	auto last_service=std::chrono::steady_clock::now();
	const auto invoke = [&](uint64_t address, std::span<const uint64_t> arguments) {
		auto budget = remaining();
		if (budget.count() <= 0)
			return NativeResult{NativeStop::timeout, 0, address, 0};
		// Level of this loop in the callback nesting; an exception dispatch that redirects the guest resumes at its own level.
		const size_t level = process.active() ? process.callback_depth() + 1 : 0;
		auto result = process.active() ? process.callback(address, arguments, budget) : process.call(address, arguments, budget);
		while (result.stop == NativeStop::api || result.stop == NativeStop::syscall || result.stop==NativeStop::fault) {
			if (result.stop==NativeStop::fault) {
				const auto image=modules.all().find("ntdll.dll");
				if (!debug || image==modules.all().end() || result.signal!=SIGSEGV || result.signal_code!=SI_KERNEL || result.value!=1 ||
					result.instruction<image->second->loaded.base() || result.instruction-image->second->loaded.base()+4>image->second->image.image_size ||
					process.read_memory(result.instruction,4)!=std::vector<uint8_t>{0xcd,0x2d,0xcc,0xc3}) {
					if (result.signal==SIGTRAP && result.signal_code==TRAP_HWBKPT) {
						std::cerr << "watch: write by";
						if (kernel_ptr && kernel_ptr->describe_stack) {
							const auto saved=process.context();
							(void)saved;
						}
						const auto rip=process.context().registers.rip;
						for (const auto &[module_name,module]:modules.all())
							if (rip>=module->loaded.base() && rip<module->loaded.base()+module->image.image_size)
								std::cerr << ' ' << module_name << '+' << std::hex << rip-module->loaded.base() << std::dec;
						std::cerr << '\n';
						budget=remaining();
						result=process.resume(budget);
						continue;
					}
					if (std::getenv("RAVEN_TRACE_FAULT")) {
						const auto describe=[&](uint64_t at) {
							for (const auto &[module_name,module]:modules.all())
								if (at>=module->loaded.base() && at<module->loaded.base()+module->image.image_size)
									return module_name+"+"+std::to_string(at-module->loaded.base());
							return std::string("?");
						};
						const auto registers=process.context().registers;
						std::cerr << "fault: signal " << result.signal << " at " << std::hex << result.instruction << " (" << describe(result.instruction) << ")";
						try {
							const auto stack=process.read_memory(registers.rsp,16);
							uint64_t first=0,second=0;
							std::memcpy(&first,stack.data(),8);std::memcpy(&second,stack.data()+8,8);
							std::cerr << " [rsp]=" << first << " (" << describe(first) << ") [rsp+8]=" << second << " (" << describe(second) << ")";
						} catch (...) {}
						std::cerr << std::dec << '\n';
					}
					// A CPU fault is a Windows exception: structured handlers of the faulting frames get the first chance.
					if (!kernel_ptr || !kernel_ptr->raise_fault || result.signal==0)
						return result;
					try {
						kernel_ptr->raise_fault(result);
					} catch (const ExecutionRedirected &redirected) {
						if (redirected.level!=level) throw;
						budget=remaining();
						if (budget.count()<=0)
							return NativeResult{NativeStop::timeout,0,result.instruction,0};
						result=process.resume(budget);
						continue;
					}
					return result;
				}
				const auto context=process.context().registers;
				const auto length=uint32_t(context.rdx);
				if (length>512 || length>1024*1024-debug_bytes)
					return result;
				const auto message=process.read_memory(context.rcx,length);
				debug(message);
				debug_bytes+=length;
				process.complete_debug_print(result.instruction);
				const auto budget=remaining();
				if (budget.count()<=0)
					return NativeResult{NativeStop::timeout,0,result.instruction,0};
				result=process.resume(budget);
				continue;
			}
			if (result.stop==NativeStop::syscall) {
				const auto service=services.find(result.instruction);
				if (service==services.end() || service->second.first!=result.value)
					return result;
				process.enter_nt_service(result.instruction,service->second.first);
				if (!environment.dispatch(service->second.second) && !memory.dispatch(service->second.second) && !object_api.dispatch(service->second.second))
					throw std::runtime_error("identified NT service was not dispatched");
				const auto budget=remaining();
				if (budget.count()<=0)
					return NativeResult{NativeStop::timeout,0,result.instruction,0};
				result=process.resume(budget);
				continue;
			}
			const auto found = traps.find(result.value);
			if (found!=traps.end() && found->second=="ExitProcess") {
				const auto code=uint32_t(process.api_arguments(1)[0]);
				process.abandon_call();
				throw ProcessExit{code,result.instruction};
			}
			if (found == traps.end())
				return result;
			// RAVEN_TRACE_API is 1 for every call or a comma-separated list of API names to follow.
			bool tracing = false;
			if (const char *selection = std::getenv("RAVEN_TRACE_API")) {
				const std::string wanted = std::string(",") + selection + ",";
				tracing = wanted == ",1," || wanted.find("," + found->second + ",") != wanted.npos;
			}
			if (tracing) {
				std::cerr << "api " << found->second << '(' << std::hex;
				// RAVEN_TRACE_ARGS widens the argument list shown (the default is the four register arguments).
				const char *width = std::getenv("RAVEN_TRACE_ARGS");
				for (const auto value : process.api_arguments(width ? std::clamp(std::atoi(width), 1, 12) : 4))
					std::cerr << ' ' << value;
				std::cerr << std::dec << " )";
				if (std::getenv("RAVEN_TRACE_STRINGS"))
					for (const auto value : process.api_arguments(4))
						if (const auto text = describe_text(process, value); !text.empty())
							std::cerr << " <" << text << '>';
				// The caller shows which guest module and offset asked, which is what a diagnosis needs most.
				const auto stack = process.read_memory(process.context().registers.rsp, 8);
				uint64_t caller = 0;
				std::memcpy(&caller, stack.data(), 8);
				for (const auto &[module_name, module] : modules.all())
					if (caller >= module->loaded.base() && caller < module->loaded.base() + module->image.image_size)
						std::cerr << " from " << module_name << '+' << std::hex << caller - module->loaded.base() << std::dec;
				if (std::getenv("RAVEN_TRACE_STACK") && kernel_ptr && kernel_ptr->describe_stack)
					std::cerr << " stack:" << kernel_ptr->describe_stack();
				std::cerr << '\n';
			}
			if (const char *spec = std::getenv("RAVEN_STEP")) {
				// Diagnosis aid: NAME:OCCURRENCE:COUNT single-steps COUNT instructions after the OCCURRENCE-th return of NAME.
				static std::map<std::string,int> seen;
				const std::string text(spec);
				const auto first = text.find(':'), second = text.find(':', first + 1);
				if (first != text.npos && second != text.npos && found->second == text.substr(0, first) &&
					++seen[found->second] == std::stoi(text.substr(first + 1, second - first - 1)))
					process.trace_instructions(size_t(std::stoul(text.substr(second + 1))), [&modules](uint64_t rip) {
						std::cerr << "step";
						for (const auto &[module_name, module] : modules.all())
							if (rip >= module->loaded.base() && rip < module->loaded.base() + module->image.image_size)
								std::cerr << ' ' << module_name << '+' << std::hex << rip - module->loaded.base() << std::dec;
						std::cerr << '\n';
					});
			}
			if (found->second=="RtlRaiseStatus")
				return native_raise_rtl_exception(process,true);
			// A thread that never waits still answers the other processes, a few times every second at most.
			if (const auto now = std::chrono::steady_clock::now(); now - last_service >= std::chrono::milliseconds(2)) {
				last_service = now;
				if (threads_ptr)
					threads_ptr->serve();
			}
			bool dispatched;
			api_in_progress = found->second.c_str();
			const auto profile_start = RuntimeProfile::instance().enabled() ? std::chrono::steady_clock::now() : std::chrono::steady_clock::time_point{};
			const auto error_before = std::getenv("RAVEN_TRACE_FAIL") ? environment.last_error() : 0;
			const auto failure_arguments = std::getenv("RAVEN_TRACE_FAIL") ? process.api_arguments(4) : std::vector<uint64_t>{};
			try {
				// The generalized desktop services come first so that they replace the older narrow ones.
				dispatched = desktop_api.dispatch(process, environment, found->second) || environment.dispatch(found->second) || module_api.dispatch(found->second) || resources.dispatch(found->second) || memory.dispatch(found->second) || object_api.dispatch(found->second) || heap.dispatch(found->second) || desktop.dispatch(found->second) || windows.dispatch(found->second) || api_registry.dispatch(process, environment, found->second)
#ifdef RAVEN_VULKAN
					|| vulkan.dispatch(found->second)
#endif
					;
			} catch (const ExecutionRedirected &redirected) {
				if (redirected.level!=level) throw;
				budget=remaining();
				if (budget.count()<=0)
					return NativeResult{NativeStop::timeout,0,result.instruction,0};
				result=process.resume(budget);
				continue;
			}
			if (RuntimeProfile::instance().enabled())
				RuntimeProfile::instance().api(found->second, std::chrono::steady_clock::now() - profile_start);
			if (!dispatched && std::getenv("RAVEN_SURVEY_MISSING")) {
				// Survey aid: report each missing API once and fail it, so one run lists every API a program reaches.
				static std::set<std::string> reported;
				if (reported.insert(found->second).second)
					std::cerr << "raven: missing " << found->second << '\n';
				environment.set_last_error(120);
				process.return_api(0);
				budget = remaining();
				result = process.resume(budget);
				continue;
			}
			if (!dispatched) {
				std::cerr << "raven: unimplemented native API " << found->second << '\n';
				// RAVEN_CONTINUE_UNIMPLEMENTED lists every missing function of a run: each call fails with ERROR_CALL_NOT_IMPLEMENTED instead.
				if (!std::getenv("RAVEN_CONTINUE_UNIMPLEMENTED"))
					return result;
				environment.set_last_error(120);
				process.return_api(0);
				budget = remaining();
				result = process.resume(budget);
				continue;
			}
			if (tracing)
				std::cerr << "  -> " << std::hex << process.result_register() << std::dec << " (error " << environment.last_error() << ")\n";
			if (std::getenv("RAVEN_TRACE_FAIL") && environment.last_error() != error_before) {
				std::cerr << "fail " << found->second << " error " << environment.last_error() << " args";
				for (const auto value : failure_arguments) std::cerr << ' ' << std::hex << value << std::dec;
				if (found->second == "CreateWindowExW" && failure_arguments.size() > 1) {
					std::string class_name;
					try {
						if (failure_arguments[1] > 0xffff) {
							const auto text = process.read_memory(failure_arguments[1], 64);
							for (size_t i = 0; i < 32 && (text[i * 2] | text[i * 2 + 1]); ++i)
								class_name.push_back(char(text[i * 2]));
						} else
							class_name = "#" + std::to_string(failure_arguments[1]);
					} catch (...) {}
					std::cerr << " class=" << class_name;
				}

				for (const auto &[module_name, module] : modules.all()) {
					const auto stack = process.read_memory(process.context().registers.rsp, 8);
					uint64_t caller = 0;
					std::memcpy(&caller, stack.data(), 8);
					if (caller >= module->loaded.base() && caller < module->loaded.base() + module->image.image_size)
						std::cerr << " from " << module_name << '+' << std::hex << caller - module->loaded.base() << std::dec;
				}
				std::cerr << '\n';
			}

			budget = remaining();
			if (budget.count() <= 0)
				return NativeResult{NativeStop::timeout, 0, result.instruction, 0};
			if (RuntimeProfile::instance().enabled()) {
				const auto before = std::chrono::steady_clock::now();
				result = process.resume(budget);
				RuntimeProfile::instance().guest(std::chrono::steady_clock::now() - before);
			} else {
				try {
					result = process.resume(budget);
				} catch (const std::runtime_error &failure) {
					// A handler that leaves the call without its answer is named, since the global name may belong to another thread by now.
					throw std::runtime_error(std::string(failure.what()) + " after " + found->second);
				}
			}
		}
		return result;
	};
	const auto prefix = NativePrefix::from_environment();
	NativePaths paths(prefix);
	if (launch && !launch->directory.empty())
		paths.set_current(launch->directory);
	desktop.set_section_source([&](uint64_t handle) -> std::optional<std::pair<int, uint64_t>> {
		const auto section = kernel_objects.object_as<SectionObject>(handle);
		if (!section || section->descriptor < 0)
			return std::nullopt;
		return std::make_pair(section->descriptor, section->size);
	});
	desktop.set_host_files([&paths](std::u16string_view path) -> std::optional<std::vector<uint8_t>> {
		const auto resolved = paths.resolve(path);
		if (!resolved || !resolved->exists || !std::filesystem::is_regular_file(resolved->host))
			return std::nullopt;
		return read_host_file(resolved->host);
	});
	GuestAllocator allocator(memory, heap);
	NativeThreads threads(process, environment, memory, &tls, deadline);
	threads.set_runner(invoke);
	threads_ptr = &threads;
	// Other processes ask for handles of this one and send theirs; the scheduler answers them.
	threads.add_service([&kernel_objects] { receive_handles(kernel_objects); });
	object_api.set_cooperative(true);
	object_api.set_threads(&threads);
	windows.set_yield([&threads] { return threads.live() > 1 && threads.yield(); });
	KernelContext kernel{process, environment, memory, allocator, kernel_objects, threads, paths, modules, entry, *launch, invoke};
	windows.set_global_allocator([&allocator](uint64_t size) { return allocator.allocate(size,true); });
	kernel.message_ready=[&windows](uint32_t thread) { return windows.input_pending(thread); };
	windows.set_block([&threads](std::function<bool()> ready) {
		HostWait waiting;
		threads.block(std::move(ready), std::nullopt);
	});
#ifdef RAVEN_VULKAN
	vulkan.set_blocking([&threads](std::function<bool()> ready) {
		HostWait waiting;
		threads.block(std::move(ready), std::nullopt);
	}, [&threads] { threads.nudge(); });
#endif
	// The block the served stubs of every runtime provider share, and which stub serves which name.
	const int served_file = memfd_create("raven-served-calls", MFD_CLOEXEC);
	if (served_file < 0 || ftruncate(served_file, 4096) != 0)
		throw std::runtime_error("cannot create the served call block");
	auto *served_block = static_cast<uint64_t *>(mmap(nullptr, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, served_file, 0));
	if (served_block == MAP_FAILED)
		throw std::runtime_error("cannot map the served call block");
	const uint64_t served_guest = process.map_shared(served_file, 4096);
	close(served_file);
	std::map<uint64_t, std::string> served_names;
	// The pointers live in the module images, which outlast this process: they are cleared when it ends so that another process mapping
	// the same images starts with its stubs trapping.
	struct ServedPointers {
		std::vector<uint8_t *> places;
		~ServedPointers()
		{
			for (auto *place : places)
				std::memset(place, 0, 8);
		}
	} served_pointers;
	for (const auto &[module_name, module] : modules.all()) {
		if (!module->runtime_api)
			continue;
		for (const auto &symbol : module->exports) {
			if (!symbol.address || symbol.names.empty() || !symbol.forwarder.empty() || !served_api(module_name, symbol.names.at(0)))
				continue;
			auto image = module->loaded.data();
			const uint32_t stub = served_stub_rva(image, module_name, symbol.names.at(0), symbol.address);
			int32_t displacement = 0;
			std::memcpy(&displacement, image.data() + stub + 3, 4);
			std::memcpy(image.data() + stub + 7 + displacement, &served_guest, 8);
			served_pointers.places.push_back(image.data() + stub + 7 + displacement);
			served_names.emplace(module->loaded.base() + stub, symbol.names.at(0));
		}
	}
	std::vector<uint64_t> served_stubs;
	for (const auto &[stub, name] : served_names)
		served_stubs.push_back(stub);
	// A thread inside a commit prelude must not lose the processor between taking a log slot and filling it: the prelude counts as a
	// served stub for the scheduler, in two pieces as it is longer than one.
	for (const auto &[module_name, module] : modules.all())
		if (module->runtime_api)
			for (const auto &symbol : module->exports)
				if (symbol.address && !symbol.names.empty() && symbol.forwarder.empty() && guest_commit_api(module_name, symbol.names.at(0)) &&
					served_stub_rva(module->loaded.data(), module_name, symbol.names.at(0), symbol.address) != symbol.address)
					for (const uint64_t piece : {uint64_t(0), uint64_t(served_trap)})
						served_stubs.push_back(module->loaded.base() + symbol.address + piece);
	memory.set_commit_block(served_block);
	process.set_served_calls(served_block, std::move(served_stubs), served_trap, served_wait, [&, served_names = std::move(served_names)](uint64_t stub) {
		const auto found = served_names.find(stub);
		if (found == served_names.end())
			throw std::runtime_error("a served call came from an unknown stub");
		api_in_progress = found->second.c_str();
		const auto profile_start = RuntimeProfile::instance().enabled() ? std::chrono::steady_clock::now() : std::chrono::steady_clock::time_point{};
		const bool dispatched = api_registry.dispatch(process, environment, found->second)
#ifdef RAVEN_VULKAN
			|| vulkan.dispatch(found->second)
#endif
			;
		if (!dispatched)
			throw std::runtime_error("served call " + found->second + " has no handler");
		if (RuntimeProfile::instance().enabled())
			RuntimeProfile::instance().api(found->second, std::chrono::steady_clock::now() - profile_start);
	});
	// The guest reads the performance counter itself once the time stamp counter is calibrated against it over 200 ms: the base is taken
	// when published, so the guest's count goes on from the runtime's, and the multiplier is written last.
	struct ClockCalibration {
		uint64_t counter = __rdtsc(), ticks = counter_ticks();
		bool published = false;
	};
	threads.add_service([served_block, calibration = std::make_shared<ClockCalibration>()] {
		if (calibration->published || counter_ticks() - calibration->ticks < 2000000)
			return;
		const uint64_t counter = __rdtsc(), ticks = counter_ticks();
		if (counter <= calibration->counter)
			return;
		uint64_t *published = served_block + clock_calibration / 8;
		published[0] = counter;
		published[1] = ticks;
		const unsigned __int128 multiplier = (static_cast<unsigned __int128>(ticks - calibration->ticks) << 32) / (counter - calibration->counter);
		__atomic_store_n(&published[2], static_cast<uint64_t>(multiplier), __ATOMIC_RELEASE);
		calibration->published = true;
	});
	// RAVEN_SAMPLE_GUEST=1 reports every five seconds where the guest spent its running time, by module and 256-byte block.
	if (std::getenv("RAVEN_SAMPLE_GUEST")) {
		auto samples = std::make_shared<std::map<uint64_t, uint32_t>>();
		auto reported = std::make_shared<std::chrono::steady_clock::time_point>(std::chrono::steady_clock::now());
		process.set_guest_sampler(std::chrono::milliseconds(2), [&modules, samples, reported](uint64_t rip) {
			++(*samples)[rip & ~uint64_t(255)];
			if (std::chrono::steady_clock::now() - *reported < std::chrono::seconds(5))
				return;
			*reported = std::chrono::steady_clock::now();
			std::vector<std::pair<uint32_t, uint64_t>> top;
			uint32_t total = 0;
			for (const auto &[where, count] : *samples) {
				top.emplace_back(count, where);
				total += count;
			}
			std::sort(top.rbegin(), top.rend());
			std::cerr << "samples: " << total << " in the last period\n";
			for (size_t index = 0; index < std::min<size_t>(top.size(), 15); ++index) {
				std::string place = "?";
				for (const auto &[module_name, module] : modules.all())
					if (top[index].second >= module->loaded.base() && top[index].second < module->loaded.base() + module->image.image_size) {
						std::ostringstream text;
						text << module_name << '+' << std::hex << top[index].second - module->loaded.base();
						place = text.str();
					}
				std::cerr << "  " << top[index].first << ' ' << place << '\n';
			}
			samples->clear();
		});
	}
	kernel_ptr=&kernel;
	NativeUnwinder unwinder(process, modules);
	register_exception_api(api_registry, kernel, unwinder);
	register_system_api(api_registry, kernel);
	register_process_api(api_registry, kernel);
	register_security_api(api_registry, kernel);
	register_child_process_api(api_registry, kernel);
	register_winsock_api(api_registry, kernel);
	register_host_api(api_registry, kernel);
	register_pipe_api(api_registry, kernel);
	register_job_api(api_registry, kernel);
	register_wave_api(api_registry, kernel);
	register_crypt32_api(api_registry, kernel);
	register_process_info_api(api_registry, kernel);
	register_font_service(api_registry, kernel);
	register_sync_api(api_registry, kernel);
	register_thread_api(api_registry, kernel);
	register_text_api(api_registry, kernel);
	register_memory_api(api_registry, kernel);
	register_file_api(api_registry, kernel);
	register_shlwapi_api(api_registry, kernel);
	register_shell_api(api_registry, kernel);
	register_platform_api(api_registry, kernel);
	register_version_api(api_registry, kernel);
	windows.register_api(desktop_api);
	desktop.register_gdi_api(desktop_api);
	desktop.register_text_api(desktop_api);
	desktop.register_image_api(desktop_api);
	NativeRegistry hive(prefix.registry_file());
	register_registry_api(api_registry, kernel, hive);
	register_service_api(api_registry, kernel, hive);
	register_ansi_adapters(api_registry);
	register_legacy_file_api(api_registry);
	NativeProfile profile(process, environment, prefix);
	register_profile_api(api_registry, profile);
	std::vector<const PEModule *> attached;
	attached.reserve(order.size());
	const auto notify_tls = [&](const PEModule &module, uint64_t reason) {
		const uint64_t arguments[] = {module.loaded.base(), reason, 0};
		for (const auto address : tls.callbacks(module)) {
			const auto result = invoke(address, arguments);
			if (result.stop != NativeStop::returned)
				return result;
		}
		return NativeResult{NativeStop::returned, 0, 0, 0};
	};
	std::set<const PEModule *> detaching;
	const auto detach = [&](const PEModule &module, uint64_t reserved) {
		detaching.insert(&module);
		const auto tls_result = notify_tls(module, 0);
		if (tls_result.stop != NativeStop::returned)
			return tls_result;
		const uint64_t arguments[] = {module.loaded.base(), 0, reserved};
		if ((module.image.characteristics & 0x2000) && module.image.entry) {
			const auto result = invoke(module.loaded.base() + module.image.entry, arguments);
			if (result.stop != NativeStop::returned)
				return result;
		}
		detaching.erase(&module);
		return NativeResult{NativeStop::returned, 0, 0, 0};
	};
	std::set<const PEModule *> pinned;
	std::map<const PEModule *, uint64_t> references;
	for (const auto &[name, module] : modules.all()) {
		pinned.insert(module.get());
		references.emplace(module.get(), 0);
	}
	bool loading = false;
	// The thread that holds the loader: another thread that loads or frees a library meanwhile waits for it, as it would for the
	// loader lock.
	uint32_t loading_thread = 0;
	const auto await_loader = [&] {
		if (!loading || loading_thread == threads.current_id())
			return;
		HostWait waiting;
		threads.block([&] { return !loading; }, std::nullopt);
	};
	struct LoadFailure { uint32_t error; };
	const auto checked = [](NativeResult result) {
		if (result.stop != NativeStop::returned)
			throw result;
	};
	// Libraries loaded by explicit path keep their host file under the module identity (lower-case file name).
	std::map<std::string, std::filesystem::path> explicit_files;
	kernel.reference_module = [&](uint64_t base, bool pin) {
		const auto found = std::find_if(references.begin(), references.end(), [&](const auto &item) { return item.first->loaded.base() == base; });
		if (found == references.end())
			return;
		if (pin)
			pinned.insert(found->first);
		else if (found->second != UINT64_MAX)
			++found->second;
	};
	module_api.set_loader([&](std::string name) -> uint64_t {
		await_loader();
		if (name.empty()) {
			environment.set_last_error(126);
			return 0;
		}
		for (auto &character : name)
			if (static_cast<unsigned char>(character) < 32) {
				environment.set_last_error(87);
				return 0;
			}
		if (name.find_first_of("/\\:") != name.npos) {
			// A path names its module by file name; Windows system libraries are served natively wherever the path points.
			const auto slash = name.find_last_of("/\\");
			auto identity = name.substr(slash == name.npos ? 0 : slash + 1);
			for (auto &character : identity)
				if (character >= 'A' && character <= 'Z')
					character = static_cast<char>(character + ('a' - 'A'));
			if (identity.find('.') == identity.npos)
				identity += ".dll";
			if (!modules.all().contains(identity) && !apiset_host(identity).empty() == false) {
				const auto resolved = paths.resolve(from_utf8(name));
				if (!resolved || !resolved->exists || !std::filesystem::is_regular_file(resolved->host)) {
					environment.set_last_error(126);
					return 0;
				}
				explicit_files.emplace(identity, resolved->host);
			}
			name = identity;
		}
		for (auto &character : name) {
			if (static_cast<unsigned char>(character) > 127) {
				environment.set_last_error(120);
				return 0;
			}
			if (character >= 'A' && character <= 'Z')
				character = static_cast<char>(character + ('a' - 'A'));
		}
		if (name.back() == '.')
			name.pop_back();
		else if (name.find('.') == std::string::npos)
			name += ".dll";
		if (const auto host = apiset_host(name); !host.empty())
			name = host;
		const auto existing = modules.all().find(name);
		// A library that is already in the process can be named while another one starts (its initialization often asks for
		// kernel32): only a library that has to be brought in waits for the first load to finish.
		if (loading && existing != modules.all().end()) {
			if (const auto counted = references.find(existing->second.get()); counted != references.end() && counted->second > 0) {
				++counted->second;
				return existing->second->loaded.base();
			}
			if (existing->second->runtime_api && references.contains(existing->second.get())) {
				++references.at(existing->second.get());
				return existing->second->loaded.base();
			}
		}
		if (loading) {
			environment.set_last_error(120);
			return 0;
		}
		if (existing != modules.all().end()) {
			auto &count = references.at(existing->second.get());
			if (count == UINT64_MAX)
				throw std::runtime_error("native DLL reference count overflow");
			++count;
			return existing->second->loaded.base();
		}
		struct Staged { PEModule *module; bool mapped = false; bool listed = false; bool tls = false; bool attached = false; };
		std::vector<Staged> staged;
		bool guest_started = false;
		loading = true;
		loading_thread = threads.current_id();
		const auto rollback = [&] {
			for (auto item = attached.rbegin(); item != attached.rend(); ++item)
				if (std::any_of(staged.begin(), staged.end(), [&](const auto &s) { return s.module == *item && s.attached; }))
					checked(detach(**item, 0));
			std::erase_if(attached, [&](const auto *item) {
				return std::any_of(staged.begin(), staged.end(), [&](const auto &s) { return s.module == item; });
			});
			for (auto item = staged.rbegin(); item != staged.rend(); ++item) {
				if (item->tls)
					tls.remove(*item->module);
				if (item->listed)
					loader_data.remove(*item->module);
				if (item->mapped)
					{ memory.remove_image(item->module->loaded.base()); process.unmap_image(item->module->loaded.base()); }
				references.erase(item->module);
				modules.remove(*item->module);
			}
		};
		const auto acquire = [&](std::string identity) -> PEModule & {
			for (auto &character : identity)
				if (character >= 'A' && character <= 'Z')
					character = static_cast<char>(character + ('a' - 'A'));
			if (identity.find('.') == std::string::npos)
				identity += ".dll";
			// An API set name stands for the library that implements it, as it does for the libraries loaded at startup.
			if (const auto host = apiset_host(identity); !host.empty()) {
				if (const auto present = modules.all().find(host); present != modules.all().end()) {
					modules.add_alias(identity, host);
					return *present->second;
				}
				identity = host;
			}
			if (const auto found = modules.all().find(identity); found != modules.all().end())
				return *found->second;
			if (modules.all().size() >= 10000)
				throw std::runtime_error("native DLL graph exceeds module limit");
			if (!source || identity.find_first_of("/\\:") != std::string::npos) {
				if (std::getenv("RAVEN_TRACE_API"))
					std::cerr << "raven: library not loadable by path: " << identity << '\n';
				throw LoadFailure{126};
			}
			std::optional<ModuleBytes> bytes;
			if (const auto explicit_file = explicit_files.find(identity); explicit_file != explicit_files.end()) {
				bytes = ModuleBytes::map(explicit_file->second);
			} else if (auto read = source(identity)) {
				bytes.emplace(std::move(*read));
			}
			// A library loaded by path finds its dependencies in its own directory, as LOAD_WITH_ALTERED_SEARCH_PATH and a DLL directory
			// set to that folder do on Windows; programs that unpack themselves to a temporary folder rely on it.
			for (auto file = explicit_files.begin(); !bytes && file != explicit_files.end(); ++file) {
				std::error_code error;
				for (const auto &entry : std::filesystem::directory_iterator(file->second.parent_path(), error)) {
					auto candidate = entry.path().filename().string();
					for (auto &character : candidate)
						if (character >= 'A' && character <= 'Z')
							character = static_cast<char>(character + ('a' - 'A'));
					if (candidate != identity || !entry.is_regular_file(error))
						continue;
					bytes = ModuleBytes::map(entry.path());
					explicit_files.emplace(identity, entry.path());
					break;
				}
			}
			if (!bytes) {
				if (std::getenv("RAVEN_TRACE_API"))
					std::cerr << "raven: library file not found: " << identity << '\n';
				throw LoadFailure{126};
			}
			// Reject unsupported initialization before publishing an image.
			const PEImage image(*bytes);
			if (!image.is_64)
				throw LoadFailure{193};
			if (!(image.characteristics & 0x2000))
				throw LoadFailure{120};
			if (image.directories[13].address || image.directories[13].size)
				for (const auto &descriptor : image.delay_imports())
					if (!(image.file_span(descriptor.descriptor_address, 4)[0] & 1))
						throw LoadFailure{120};
			if (image.directories[14].address || image.directories[14].size)
				throw LoadFailure{120};
			staged.reserve(staged.size() + 1);
			auto &module = modules.add(identity, std::move(*bytes));
			staged.push_back({&module});
			references.emplace(&module, 0);
			return module;
		};
		try {
			auto &root = acquire(name);
			// Follow only activated import forwarders, not every optional export. Every missing export is reported before the load fails.
			bool missing = false;
			for (size_t index = 0; index < staged.size(); ++index) {
				for (const auto &symbol : staged[index].module->imports) {
					acquire(symbol.module);
					for (;;) {
						try {
							modules.resolve(symbol);
							break;
						} catch (const std::runtime_error &error) {
							const std::string_view message = error.what();
							if (message.starts_with("missing PE module: "))
								acquire(std::string(message.substr(19)));
							else if (message.starts_with("missing PE export: ")) {
								if (std::getenv("RAVEN_TRACE_API") || std::getenv("RAVEN_TRACE_FAIL"))
									std::cerr << "raven: cannot load " << name << ": " << staged[index].module->name << " imports " << message << '\n';
								missing = true;
								break;
							}
							else
								throw;
						}
					}
				}
			}
			if (missing)
				throw LoadFailure{127};
			modules.bind_imports();
			const auto dynamic_order = initialization_order(modules, entry);
			for (auto &item : staged) {
				process.map_image(item.module->loaded);
				register_image(memory, *item.module);
				item.mapped = true;
				loader_data.add(*item.module);
				item.listed = true;
				tls.add(*item.module);
				item.tls = true;
			}
			attached.reserve(attached.size() + staged.size());
			for (const auto *module : dynamic_order) {
				const auto found = std::find_if(staged.begin(), staged.end(), [&](const auto &s) { return s.module == module; });
				if (found == staged.end())
					continue;
				guest_started = true;
				checked(notify_tls(*module, 1));
				if (module->image.entry) {
					const uint64_t arguments[] = {module->loaded.base(), 1, 0};
					const auto result = invoke(module->loaded.base() + module->image.entry, arguments);
					checked(result);
					if (!static_cast<uint32_t>(result.value)) {
						checked(detach(*module, 0));
						throw LoadFailure{1114};
					}
				}
				found->attached = true;
				attached.push_back(module);
				loader_data.initialized(*module);
			}
			++references.at(&root);
			loading = false;
			return root.loaded.base();
		} catch (const NativeResult &) {
			// A fault or timeout is terminal; never execute extra guest cleanup.
			throw;
		} catch (const LoadFailure &failure) {
			rollback();
			loading = false;
			environment.set_last_error(failure.error);
			return 0;
		} catch (...) {
			if (!guest_started)
				rollback();
			loading = false;
			throw;
		}
	}, [&](uint64_t handle) {
		await_loader();
		const auto found = std::find_if(references.begin(), references.end(), [&](const auto &item) { return item.first->loaded.base() == handle; });
		if (found == references.end() || !found->second) {
			environment.set_last_error(found == references.end() ? 126 : 120);
			return false;
		}
		if (loading) {
			environment.set_last_error(120);
			return false;
		}
		--found->second;
		std::set<const PEModule *> reachable = pinned;
		std::vector<const PEModule *> pending;
		for (const auto &[module, count] : references)
			if (count || pinned.contains(module)) {
				reachable.insert(module);
				pending.push_back(module);
			}
		while (!pending.empty()) {
			const auto *module = pending.back();
			pending.pop_back();
			for (const auto &symbol : module->imports)
				for (const auto *dependency : modules.resolution_path(symbol))
					if (reachable.insert(dependency).second)
						pending.push_back(dependency);
		}
		std::vector<const PEModule *> released;
		loading = true;
		loading_thread = threads.current_id();
		for (auto item = attached.rbegin(); item != attached.rend(); ++item)
			if (!reachable.contains(*item)) {
				checked(detach(**item, 0));
				released.push_back(*item);
			}
		std::erase_if(attached, [&](const auto *item) { return !reachable.contains(item); });
		for (const auto *module : released) {
			tls.remove(*module);
			loader_data.remove(*module);
			memory.remove_image(module->loaded.base());
			process.unmap_image(module->loaded.base());
			references.erase(module);
			modules.remove(*module);
		}
		loading = false;
		return true;
	});
	// Thread notifications reach the executable's TLS callbacks first, then every loaded module in load order (reverse on exit).
	threads.set_notifier([&](uint32_t reason) {
		const auto notify = [&](const PEModule &module) {
			if (const auto stopped = notify_tls(module, reason); stopped.stop != NativeStop::returned)
				throw stopped;
			if ((module.image.characteristics & 0x2000) && module.image.entry && !module.runtime_api) {
				const uint64_t arguments[] = {module.loaded.base(), reason, 0};
				const auto result = invoke(module.loaded.base() + module.image.entry, arguments);
				if (result.stop != NativeStop::returned)
					throw result;
			}
		};
		// An entry point may load or free libraries, so the walk goes over a copy and skips a module that is gone by its turn.
		const auto modules_now = attached;
		const auto still_attached = [&](const PEModule *module) { return std::find(attached.begin(), attached.end(), module) != attached.end(); };
		if (reason == 2) {
			notify(entry);
			for (const auto *module : modules_now)
				if (module != &entry && still_attached(module))
					notify(*module);
		} else {
			for (auto module = modules_now.rbegin(); module != modules_now.rend(); ++module)
				if (*module != &entry && still_attached(*module))
					notify(**module);
			notify(entry);
		}
	});
	bool entry_tls_ready=false,cleanup_started=false;
	const auto exit_result = [&](ProcessExit request) {
		threads.stop_time_slicing();
		// The other threads end before the libraries are told the process detaches, so none of them runs on what detaching frees.
		threads.terminate_others(request.code);
		try {
			if (!cleanup_started && !request.terminated) {
				cleanup_started=true; loading=true;
				if (entry_tls_ready) {
					const auto stopped=notify_tls(entry,0);
					if (stopped.stop!=NativeStop::returned) { windows.shutdown(); return stopped; }
				}
				for (auto module=attached.rbegin();module!=attached.rend();++module) {
					if (detaching.contains(*module)) continue;
					const auto stopped=detach(**module,environment.peb());
					if (stopped.stop!=NativeStop::returned) { windows.shutdown(); return stopped; }
				}
			}
		} catch (const ProcessExit &repeated) { request=repeated; }
		catch (const NativeResult &stopped) { windows.shutdown(); return stopped; }
		windows.shutdown();
		return NativeResult{NativeStop::exited,request.code,request.instruction,0};
	};
	try {
		windows.set_call(invoke);
		desktop.set_call(invoke);
		heap.initialize(invoke);
		for (const auto *module : order) {
			if (module == &entry)
				continue;
			const auto tls_result = notify_tls(*module, 1);
			if (tls_result.stop != NativeStop::returned)
				return tls_result;
			if (!(module->image.characteristics & 0x2000) || !module->image.entry) {
				attached.push_back(module);
				continue;
			}
			const uint64_t arguments[] = {module->loaded.base(), 1, environment.peb()};
			const auto result = invoke(module->loaded.base() + module->image.entry, arguments);
			if (result.stop != NativeStop::returned)
				return result;
			if (static_cast<uint32_t>(result.value) == 0) {
				if (detach(*module, 0).stop != NativeStop::returned)
					throw std::runtime_error("native DLL failure cleanup did not return: " + module->name);
				for (auto previous = attached.rbegin(); previous != attached.rend(); ++previous)
					if (detach(**previous, 0).stop != NativeStop::returned)
						throw std::runtime_error("native DLL rollback did not return: " + (*previous)->name);
				throw std::runtime_error("DLL_PROCESS_ATTACH failed: " + module->name);
			}
			attached.push_back(module);
		}
		const auto tls_result = notify_tls(entry, 1);
		if (tls_result.stop != NativeStop::returned)
			return tls_result;
		entry_tls_ready=true;
		const auto result = invoke(entry.loaded.base() + entry.image.entry, {});
		if (result.stop != NativeStop::returned)
			return result;
		cleanup_started=true; loading=true;
		const auto tls_detach = notify_tls(entry, 0);
		if (tls_detach.stop != NativeStop::returned)
			return tls_detach;
		for (auto module = attached.rbegin(); module != attached.rend(); ++module) {
			const auto stopped = detach(**module, environment.peb());
			if (stopped.stop != NativeStop::returned)
				return stopped;
		}
		windows.shutdown();
		return result;
	} catch (const ProcessExit &request) {
		return exit_result(request);
	} catch (const NativeResult &stopped) {
		return stopped;
	}
}

}

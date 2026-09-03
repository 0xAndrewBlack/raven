#include "ansi_api.h"
#include "text.h"

#include <sys/mman.h>

namespace raven {

namespace {

constexpr uint32_t ansi_code_page = 1252;

// How one ANSI API maps onto its wide twin: arguments that are zero-terminated input strings, an optional output buffer
// with the argument holding its capacity in characters, and an argument that receives a pointer into that buffer.
struct Adapter {
	const char *name;
	std::initializer_list<size_t> strings;
	int buffer = -1;
	int capacity = -1;
	int file_part = -1;
	// WIN32_FIND_DATA output at this argument.
	int find_data = -1;
	// When the flags argument has any of these bits the string argument is not text (an address, for example).
	int flag_argument = -1;
	uint32_t flag_mask = 0;
};

const Adapter adapters[] = {
	{"CreateFileA", {0}},
	{"GetFileAttributesA", {0}},
	{"SetFileAttributesA", {0}},
	{"DeleteFileA", {0}},
	{"MoveFileA", {0, 1}},
	{"CopyFileA", {0, 1}},
	{"CreateDirectoryA", {0}},
	{"RemoveDirectoryA", {0}},
	{"FindFirstFileA", {0}, -1, -1, -1, 1},
	{"FindNextFileA", {}, -1, -1, -1, 1},
	{"GetModuleFileNameA", {}, 1, 2},
	{"GetEnvironmentVariableA", {0}, 1, 2},
	{"SetEnvironmentVariableA", {0, 1}},
	{"GetCurrentDirectoryA", {}, 1, 0},
	{"SetCurrentDirectoryA", {0}},
	{"GetFullPathNameA", {0}, 2, 1, 3},
	{"GetTempPathA", {}, 1, 0},
	{"GetLongPathNameA", {0}, 1, 2},
	{"GetShortPathNameA", {0}, 1, 2},
	{"ExpandEnvironmentStringsA", {0}, 1, 2},
	{"GetDriveTypeA", {0}},
	{"CreateMutexA", {2}},
	{"CreateEventA", {3}},
	{"CreateProcessA", {0, 1, 7}},
	{"CreateSemaphoreA", {3}},
	{"CreateFileMappingA", {5}},
	{"OpenMutexA", {2}},
	{"OpenEventA", {2}},
	{"OpenSemaphoreA", {2}},
	{"SearchPathA", {0, 1, 2}, 4, 3, 5},
	{"GetModuleHandleExA", {1}, -1, -1, -1, -1, 0, 4},
};

// Guest scratch that is released when the call returns.
class Scratch {
public:
	explicit Scratch(NativeProcess &process) : process(process) {}
	~Scratch() { for (const auto address : blocks) process.unmap_memory(address); }
	uint64_t block(size_t bytes)
	{
		const auto address = process.map_memory((bytes + 4095) & ~size_t(4095), PROT_READ | PROT_WRITE);
		blocks.push_back(address);
		return address;
	}
private:
	NativeProcess &process;
	std::vector<uint64_t> blocks;
};

}

void register_ansi_adapters(ApiRegistry &registry)
{
	for (const auto &adapter : adapters) {
		if (registry.has(adapter.name))
			continue;
		std::string wide_name(adapter.name);
		wide_name.back() = 'W';
		const auto base = registry.find(wide_name);
		if (!base)
			continue;
		const auto [arguments, handler] = *base;
		registry.add(adapter.name, arguments, [adapter, handler = handler, arguments = arguments](ApiCall &call) {
			Scratch scratch(call.process);
			std::vector<uint64_t> words;
			for (size_t index = 0; index < arguments; ++index)
				words.push_back(call[index]);
			const bool text_arguments = adapter.flag_argument < 0 || !(uint32_t(words[size_t(adapter.flag_argument)]) & adapter.flag_mask);
			for (const auto index : adapter.strings) {
				if (!text_arguments || index >= words.size() || !words[index])
					continue;
				const auto text = from_ansi(call.narrow(words[index]), ansi_code_page);
				const auto at = scratch.block((text.size() + 1) * 2);
				call.write(at, std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(text.c_str()), (text.size() + 1) * 2));
				words[index] = at;
			}
			uint64_t narrow_buffer = 0, wide_buffer = 0;
			uint32_t capacity = 0;
			if (adapter.buffer >= 0 && words[size_t(adapter.buffer)]) {
				narrow_buffer = words[size_t(adapter.buffer)];
				capacity = uint32_t(words[size_t(adapter.capacity)]);
				wide_buffer = scratch.block((size_t(capacity) + 1) * 2);
				words[size_t(adapter.buffer)] = wide_buffer;
			}
			uint64_t file_part = 0, wide_part = 0;
			if (adapter.file_part >= 0 && words[size_t(adapter.file_part)]) {
				file_part = words[size_t(adapter.file_part)];
				wide_part = scratch.block(8);
				words[size_t(adapter.file_part)] = wide_part;
			}
			uint64_t find_target = 0, find_wide = 0;
			if (adapter.find_data >= 0 && words[size_t(adapter.find_data)]) {
				find_target = words[size_t(adapter.find_data)];
				find_wide = scratch.block(592);
				words[size_t(adapter.find_data)] = find_wide;
			}
			ApiCall inner(call.process, call.environment, words);
			handler(inner);
			call.ret(inner.result);
			if (wide_buffer && inner.result && inner.result < capacity) {
				const auto text = call.wide(wide_buffer, capacity);
				const auto narrow = to_ansi(text, ansi_code_page);
				call.put_narrow(narrow_buffer, narrow, capacity);
				call.ret(narrow.size());
				if (file_part) {
					// The wide handler points into its own buffer; the same character of the narrow copy is what the caller gets.
					const auto part = call.load<uint64_t>(wide_part);
					if (part >= wide_buffer && part < wide_buffer + (uint64_t(capacity) + 1) * 2)
						call.store<uint64_t>(file_part, narrow_buffer +
							to_ansi(std::u16string_view(text).substr(0, size_t((part - wide_buffer) / 2)), ansi_code_page).size());
					else
						call.store<uint64_t>(file_part, 0);
				}
			}
			if (find_wide && inner.result) {
				// WIN32_FIND_DATAW and WIN32_FIND_DATAA agree up to the name fields.
				auto record = call.read(find_wide, 44);
				const auto name = call.wide(find_wide + 44, 260);
				const auto alternate = call.wide(find_wide + 44 + 520, 14);
				auto narrow_name = to_ansi(name, ansi_code_page), narrow_alternate = to_ansi(alternate, ansi_code_page);
				narrow_name.resize(260, '\0');
				narrow_alternate.resize(14, '\0');
				record.insert(record.end(), narrow_name.begin(), narrow_name.end());
				record.insert(record.end(), narrow_alternate.begin(), narrow_alternate.end());
				call.write(find_target, record);
			}
		});
	}
}

void register_legacy_file_api(ApiRegistry &registry)
{
	constexpr uint64_t file_error = 0xffffffffULL;
	const auto create = registry.find("CreateFileA"), read = registry.find("ReadFile"), write = registry.find("WriteFile"),
		seek = registry.find("SetFilePointerEx");
	if (!create || !read || !write || !seek)
		return;
	const auto run = [](const std::pair<uint32_t, ApiHandler> &entry, ApiCall &call, std::vector<uint64_t> words) {
		words.resize(entry.first, 0);
		ApiCall inner(call.process, call.environment, std::move(words));
		entry.second(inner);
		return inner;
	};
	const auto invalid_handle = [](uint64_t value) { return value == UINT64_MAX || uint32_t(value) == 0xffffffffU; };
	registry.add("_lopen", 2, [=](ApiCall &call) {
		const uint32_t mode = call.u32(1);
		const uint32_t access = (mode & 3) == 0 ? 0x80000000U : (mode & 3) == 1 ? 0x40000000U : 0xc0000000U;
		// Share modes: compatibility and deny none share everything, deny write leaves reading, deny read leaves writing, exclusive shares nothing.
		const uint32_t share = (mode & 0x70) == 0x10 ? 0 : (mode & 0x70) == 0x20 ? 1 : (mode & 0x70) == 0x30 ? 2 : 3;
		const auto done = run(*create, call, {call[0], access, share, 0, 3, 0x80, 0});
		call.ret(invalid_handle(done.result) ? file_error : done.result);
	});
	registry.add("_lcreat", 2, [=](ApiCall &call) {
		const auto done = run(*create, call, {call[0], 0xc0000000U, 0, 0, 2, uint64_t(call.u32(1) & 7) | 0x80, 0});
		call.ret(invalid_handle(done.result) ? file_error : done.result);
	});
	const auto transfer = [=](const std::pair<uint32_t, ApiHandler> &entry, ApiCall &call) {
		Scratch scratch(call.process);
		const auto count = scratch.block(8);
		const auto done = run(entry, call, {call[0], call[1], uint64_t(uint32_t(call.u32(2))), count, 0});
		call.ret(done.result ? uint64_t(call.load<uint32_t>(count)) : file_error);
	};
	registry.add("_lread", 3, [=](ApiCall &call) { transfer(*read, call); });
	registry.add("_hread", 3, [=](ApiCall &call) { transfer(*read, call); });
	registry.add("_lwrite", 3, [=](ApiCall &call) { transfer(*write, call); });
	registry.add("_hwrite", 3, [=](ApiCall &call) { transfer(*write, call); });
	registry.add("_llseek", 3, [=](ApiCall &call) {
		Scratch scratch(call.process);
		const auto position = scratch.block(8);
		const auto done = run(*seek, call, {call[0], uint64_t(int64_t(call.i32(1))), position, call.u32(2)});
		call.ret(done.result ? uint64_t(call.load<uint32_t>(position)) : file_error);
	});
}

}

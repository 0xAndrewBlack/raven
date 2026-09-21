#include "kernel_context.h"
#include "text.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <map>
#include <memory>

namespace raven {

namespace {

constexpr uint32_t mmio_rwmode = 0x3, mmio_create = 0x1000, mmio_parse = 0x100, mmio_delete = 0x200, mmio_exist = 0x4000;
constexpr uint32_t mmio_findchunk = 0x10, mmio_findriff = 0x20, mmio_findlist = 0x40, mmio_createriff = 0x20, mmio_createlist = 0x40, mmio_toupper = 0x10, mmio_dirty = 0x10000000;
constexpr uint32_t mmioerr_filenotfound = 257, mmioerr_cannotopen = 259, mmioerr_cannotwrite = 262, mmioerr_chunknotfound = 265,
	mmioerr_unbuffered = 266, mmsyserr_invalhandle = 5, mmsyserr_invalparam = 11;
constexpr uint32_t fourcc_mem = 0x204d454d, fourcc_riff = 0x46464952, fourcc_list = 0x5453494c;

// Where the fields of MMIOINFO sit; the structure is byte packed, so only the pointers' width moves them.
struct InfoLayout {
	uint32_t io_proc, error, buffer_size, buffer, disk_offset, info, handle, size;
};
constexpr InfoLayout layout32{8, 12, 0x14, 0x18, 0x2c, 0x30, 0x44, 0x48}, layout64{8, 16, 0x1c, 0x20, 0x44, 0x48, 0x5c, 0x64};

// An open stream: a host file, or guest memory the program handed over with the MEM procedure. Reads and writes go straight through,
// as with an unbuffered stream on Windows.
struct Stream {
	std::FILE *file = nullptr;
	uint64_t memory = 0;
	int64_t memory_size = 0, position = 0;
	~Stream()
	{
		if (file)
			std::fclose(file);
	}
	int64_t size()
	{
		if (!file)
			return memory_size;
		const long at = std::ftell(file);
		std::fseek(file, 0, SEEK_END);
		const long end = std::ftell(file);
		std::fseek(file, at, SEEK_SET);
		return end;
	}
	int64_t read(ApiCall &call, uint64_t address, int64_t count)
	{
		count = std::max<int64_t>(0, std::min(count, size() - position));
		if (!count)
			return 0;
		std::vector<uint8_t> bytes(size_t(count), 0);
		if (file) {
			std::fseek(file, long(position), SEEK_SET);
			count = int64_t(std::fread(bytes.data(), 1, bytes.size(), file));
			bytes.resize(size_t(count));
		} else {
			bytes = call.read(memory + uint64_t(position), size_t(count));
		}
		call.write(address, bytes);
		position += count;
		return count;
	}
	int64_t write(ApiCall &call, std::span<const uint8_t> bytes)
	{
		if (file) {
			std::fseek(file, long(position), SEEK_SET);
			const auto written = std::fwrite(bytes.data(), 1, bytes.size(), file);
			position += int64_t(written);
			return written == bytes.size() ? int64_t(written) : -1;
		}
		const auto count = std::min<int64_t>(int64_t(bytes.size()), memory_size - position);
		if (count <= 0)
			return bytes.empty() ? 0 : -1;
		call.write(memory + uint64_t(position), bytes.first(size_t(count)));
		position += count;
		return count;
	}
};

uint32_t four_characters(std::u16string_view text, bool upper)
{
	uint32_t code = 0;
	for (size_t index = 0; index < 4; ++index) {
		char16_t character = index < text.size() ? text[index] : u' ';
		if (upper)
			character = upper_case(character);
		code |= uint32_t(uint8_t(character)) << (index * 8);
	}
	return code;
}

}

// The multimedia file functions of winmm: RIFF chunks over files and over memory, as the animation control reads its clips and programs
// read and write their wave files.
void register_mmio_api(ApiRegistry &registry, KernelContext &context)
{
	const auto streams = std::make_shared<std::map<uint64_t, std::unique_ptr<Stream>>>();
	const auto next = std::make_shared<uint64_t>(0x6d000001);
	const auto stream_of = [streams](uint64_t handle) -> Stream * {
		const auto found = streams->find(uint32_t(handle));
		return found == streams->end() ? nullptr : found->second.get();
	};

	for (const bool wide : {true, false})
		registry.add(wide ? "mmioOpenW" : "mmioOpenA", 3, [&context, streams, next, wide](ApiCall &call) {
			const auto &layout = call.pointer_width() == 4 ? layout32 : layout64;
			const uint64_t info = call[1];
			const uint32_t flags = call.u32(2);
			const auto report = [&](uint32_t error) {
				if (info)
					call.store<uint32_t>(info + layout.error, error);
				call.ret(0);
			};
			auto stream = std::make_unique<Stream>();
			const uint32_t procedure = info ? call.load<uint32_t>(info + 4) : 0;
			if (info && call.load_pointer(info + layout.io_proc) && procedure != fourcc_mem) {
				report(mmioerr_cannotopen);
				return;
			}
			if (procedure == fourcc_mem) {
				stream->memory = call.load_pointer(info + layout.buffer);
				stream->memory_size = call.load<int32_t>(info + layout.buffer_size);
				if (!stream->memory) {
					report(mmioerr_cannotopen);
					return;
				}
			} else {
				if (!call[0]) {
					report(mmioerr_filenotfound);
					return;
				}
				const auto name = wide ? call.wide(call[0], 260) : widen_ascii(call.narrow(call[0], 260));
				const auto resolved = context.paths.resolve(name);
				if (flags & mmio_parse) {
					const auto full = context.paths.full(name);
					if (wide)
						call.put_wide(call[0], full, 128);
					else
						call.put_narrow(call[0], to_utf8(full), 128);
					call.ret(1);
					return;
				}
				if (flags & mmio_exist) {
					call.ret(resolved && resolved->exists);
					return;
				}
				if (flags & mmio_delete) {
					std::error_code error;
					call.ret(resolved && std::filesystem::remove(resolved->host, error));
					return;
				}
				if (!resolved || (!resolved->exists && !(flags & mmio_create))) {
					report(mmioerr_filenotfound);
					return;
				}
				const char *mode = flags & mmio_create ? "w+b" : (flags & mmio_rwmode) ? "r+b" : "rb";
				stream->file = std::fopen(resolved->host.c_str(), mode);
				if (!stream->file) {
					report(mmioerr_cannotopen);
					return;
				}
			}
			const uint64_t handle = (*next)++;
			if (info) {
				call.store<uint32_t>(info + layout.error, 0);
				call.store<uint32_t>(info + layout.handle, uint32_t(handle));
			}
			(*streams)[handle] = std::move(stream);
			call.ret(handle);
		});
	registry.add("mmioClose", 2, [streams](ApiCall &call) {
		call.ret(streams->erase(uint32_t(call[0])) ? 0 : mmsyserr_invalhandle);
	});
	registry.add("mmioRead", 3, [stream_of](ApiCall &call) {
		Stream *stream = stream_of(call[0]);
		call.ret(uint32_t(int32_t(stream ? stream->read(call, call[1], call.i32(2)) : -1)));
	});
	registry.add("mmioWrite", 3, [stream_of](ApiCall &call) {
		Stream *stream = stream_of(call[0]);
		const auto bytes = stream && call.i32(2) > 0 ? call.read(call[1], size_t(call.i32(2))) : std::vector<uint8_t>();
		call.ret(uint32_t(int32_t(stream ? stream->write(call, bytes) : -1)));
	});
	registry.add("mmioSeek", 3, [stream_of](ApiCall &call) {
		Stream *stream = stream_of(call[0]);
		if (!stream) {
			call.ret(uint32_t(-1));
			return;
		}
		const int32_t origin = call.i32(2);
		const int64_t base = origin == 1 ? stream->position : origin == 2 ? stream->size() : 0;
		const int64_t target = base + call.i32(1);
		if (target < 0 || (!stream->file && target > stream->memory_size)) {
			call.ret(uint32_t(-1));
			return;
		}
		stream->position = target;
		call.ret(uint32_t(target));
	});
	// MMCKINFO: the chunk's identifier, size, form or list type, where its data starts and its flags.
	registry.add("mmioDescend", 4, [stream_of](ApiCall &call) {
		Stream *stream = stream_of(call[0]);
		if (!stream || !call[1]) {
			call.ret(stream ? mmsyserr_invalparam : mmsyserr_invalhandle);
			return;
		}
		const uint32_t flags = call.u32(3);
		const uint32_t wanted_id = call.load<uint32_t>(call[1]), wanted_type = call.load<uint32_t>(call[1] + 8);
		int64_t end = stream->size();
		if (call[2])
			end = std::min<int64_t>(end, int64_t(call.load<uint32_t>(call[2] + 12)) + call.load<uint32_t>(call[2] + 4));
		for (;;) {
			const int64_t start = stream->position;
			if (start + 8 > end) {
				call.ret(mmioerr_chunknotfound);
				return;
			}
			std::vector<uint8_t> header(12, 0);
			const auto take = [&](int64_t at, size_t count) {
				if (stream->file) {
					std::fseek(stream->file, long(at), SEEK_SET);
					return std::fread(header.data(), 1, count, stream->file) == count;
				}
				if (at + int64_t(count) > stream->memory_size)
					return false;
				const auto bytes = call.read(stream->memory + uint64_t(at), count);
				std::memcpy(header.data(), bytes.data(), count);
				return true;
			};
			const bool listed = take(start, 8) && (std::memcmp(header.data(), "RIFF", 4) == 0 || std::memcmp(header.data(), "LIST", 4) == 0);
			if (!take(start, listed && start + 12 <= end ? 12 : 8)) {
				call.ret(mmioerr_chunknotfound);
				return;
			}
			uint32_t id, size, type = 0;
			std::memcpy(&id, header.data(), 4);
			std::memcpy(&size, header.data() + 4, 4);
			if (listed)
				std::memcpy(&type, header.data() + 8, 4);
			const bool match = (flags & mmio_findchunk) ? id == wanted_id
				: (flags & mmio_findriff) ? id == fourcc_riff && type == wanted_type
				: (flags & mmio_findlist) ? id == fourcc_list && type == wanted_type
				: true;
			if (match) {
				const uint32_t chunk[5]{id, size, type, uint32_t(start + 8), 0};
				call.write(call[1], std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(chunk), sizeof(chunk)));
				stream->position = start + (listed ? 12 : 8);
				call.ret(0);
				return;
			}
			stream->position = start + 8 + ((int64_t(size) + 1) & ~int64_t(1));
		}
	});
	registry.add("mmioAscend", 3, [stream_of](ApiCall &call) {
		Stream *stream = stream_of(call[0]);
		if (!stream || !call[1]) {
			call.ret(stream ? mmsyserr_invalparam : mmsyserr_invalhandle);
			return;
		}
		const uint32_t data = call.load<uint32_t>(call[1] + 12);
		uint32_t size = call.load<uint32_t>(call[1] + 4);
		// A chunk written since mmioCreateChunk learns its size now, and an odd one gets its pad byte.
		if (call.load<uint32_t>(call[1] + 16) & mmio_dirty) {
			size = uint32_t(stream->position - data);
			const int64_t back = stream->position;
			stream->position = data - 4;
			if (stream->write(call, std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(&size), 4)) != 4) {
				call.ret(mmioerr_cannotwrite);
				return;
			}
			stream->position = back;
			call.store<uint32_t>(call[1] + 4, size);
			call.store<uint32_t>(call[1] + 16, call.load<uint32_t>(call[1] + 16) & ~mmio_dirty);
			if (size & 1) {
				const uint8_t pad = 0;
				stream->write(call, std::span<const uint8_t>(&pad, 1));
			}
		}
		stream->position = int64_t(data) + ((int64_t(size) + 1) & ~int64_t(1));
		call.ret(0);
	});
	registry.add("mmioCreateChunk", 3, [stream_of](ApiCall &call) {
		Stream *stream = stream_of(call[0]);
		if (!stream || !call[1]) {
			call.ret(stream ? mmsyserr_invalparam : mmsyserr_invalhandle);
			return;
		}
		const uint32_t flags = call.u32(2);
		uint32_t header[3]{call.load<uint32_t>(call[1]), call.load<uint32_t>(call[1] + 4), call.load<uint32_t>(call[1] + 8)};
		if (flags & mmio_createriff)
			header[0] = fourcc_riff;
		else if (flags & mmio_createlist)
			header[0] = fourcc_list;
		const bool listed = flags & (mmio_createriff | mmio_createlist);
		const int64_t start = stream->position;
		const size_t count = listed ? 12 : 8;
		if (stream->write(call, std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(header), count)) != int64_t(count)) {
			call.ret(mmioerr_cannotwrite);
			return;
		}
		call.store<uint32_t>(call[1], header[0]);
		call.store<uint32_t>(call[1] + 12, uint32_t(start + 8));
		call.store<uint32_t>(call[1] + 16, mmio_dirty);
		call.ret(0);
	});
	// The streams have no buffer of their own: the information names the handle and where the stream is.
	registry.add("mmioGetInfo", 3, [stream_of](ApiCall &call) {
		Stream *stream = stream_of(call[0]);
		if (!stream || !call[1]) {
			call.ret(stream ? mmsyserr_invalparam : mmsyserr_invalhandle);
			return;
		}
		const auto &layout = call.pointer_width() == 4 ? layout32 : layout64;
		call.write(call[1], std::vector<uint8_t>(layout.size, 0));
		call.store<uint32_t>(call[1] + 4, stream->file ? 0x20534f44 : fourcc_mem);
		call.store<int32_t>(call[1] + layout.disk_offset, int32_t(stream->position));
		call.store<uint32_t>(call[1] + layout.handle, uint32_t(call[0]));
		call.ret(0);
	});
	registry.add("mmioSetInfo", 3, [stream_of](ApiCall &call) { call.ret(stream_of(call[0]) ? 0 : mmsyserr_invalhandle); });
	registry.add("mmioAdvance", 3, [stream_of](ApiCall &call) { call.ret(stream_of(call[0]) ? mmioerr_unbuffered : mmsyserr_invalhandle); });
	registry.add("mmioFlush", 2, [stream_of](ApiCall &call) {
		Stream *stream = stream_of(call[0]);
		if (stream && stream->file)
			std::fflush(stream->file);
		call.ret(stream ? 0 : mmsyserr_invalhandle);
	});
	registry.add("mmioSetBuffer", 4, [stream_of](ApiCall &call) { call.ret(stream_of(call[0]) ? 0 : mmsyserr_invalhandle); });
	registry.add("mmioInstallIOProcW", 3, [](ApiCall &call) { call.ret(0); });
	registry.add("mmioInstallIOProcA", 3, [](ApiCall &call) { call.ret(0); });
	registry.add("mmioStringToFOURCCW", 2, [](ApiCall &call) { call.ret(four_characters(call.wide(call[0], 64), call.u32(1) & mmio_toupper)); });
	registry.add("mmioStringToFOURCCA", 2, [](ApiCall &call) {
		call.ret(four_characters(widen_ascii(call.narrow(call[0], 64)), call.u32(1) & mmio_toupper));
	});
}

}

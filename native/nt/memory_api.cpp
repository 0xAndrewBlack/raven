#include "kernel_context.h"
#include "file_objects.h"

#include <cstring>
#include <map>
#include <sys/stat.h>
#include <unistd.h>

namespace raven {

namespace {

// A file mapping keeps the section name and size; views copy the file in and write it back on unmap.
class MappingObject : public KernelObject {
public:
	std::shared_ptr<FileObject> file;
	uint64_t size = 0;
	uint32_t protection = 0;
};

struct View {
	std::shared_ptr<MappingObject> mapping;
	uint64_t offset = 0, size = 0;
	bool writable = false;
};

}

void register_memory_api(ApiRegistry &registry, KernelContext &context)
{
	auto &allocator = context.allocator;
	auto &memory = context.memory;
	auto &objects = context.objects;
	constexpr uint32_t zero_flag = 0x40;
	registry.add("LocalAlloc", 2, [&](ApiCall &call) {
		const auto address = allocator.allocate(call[1], call.u32(0) & zero_flag);
		if (!address) {
			call.fail(8);
			return;
		}
		call.ret(address);
	});
	registry.add("GlobalAlloc", 2, [&](ApiCall &call) {
		const auto address = allocator.allocate(call[1], call.u32(0) & zero_flag);
		if (!address) {
			call.fail(8);
			return;
		}
		call.ret(address);
	});
	const auto free_block = [&](ApiCall &call) {
		if (call[0] && !allocator.release(call[0])) {
			call.fail(6, call[0]);
			return;
		}
		call.ret(0);
	};
	registry.add("LocalFree", 1, free_block);
	registry.add("GlobalFree", 1, free_block);
	const auto lock_block = [&](ApiCall &call) {
		if (allocator.size(call[0]) == UINT64_MAX) {
			call.fail(6);
			return;
		}
		call.ret(call[0]);
	};
	registry.add("LocalLock", 1, lock_block);
	registry.add("GlobalLock", 1, lock_block);
	const auto unlock_block = [](ApiCall &call) { call.set_last_error(0); };
	registry.add("LocalUnlock", 1, unlock_block);
	registry.add("GlobalUnlock", 1, unlock_block);
	const auto size_block = [&](ApiCall &call) {
		const auto size = allocator.size(call[0]);
		if (size == UINT64_MAX) {
			call.fail(6);
			return;
		}
		call.ret(size);
	};
	registry.add("LocalSize", 1, size_block);
	registry.add("GlobalSize", 1, size_block);
	const auto resize_block = [&](ApiCall &call) {
		const auto old = allocator.size(call[0]);
		if (old == UINT64_MAX) {
			call.fail(6);
			return;
		}
		const auto address = allocator.allocate(call[1], call.u32(2) & zero_flag);
		if (!address) {
			call.fail(8);
			return;
		}
		call.write(address, call.read(call[0], std::min<uint64_t>(old, call[1])));
		allocator.release(call[0]);
		call.ret(address);
	};
	registry.add("LocalReAlloc", 3, resize_block);
	registry.add("GlobalReAlloc", 3, resize_block);
	registry.add("GlobalMemoryStatusEx", 1, [](ApiCall &call) {
		std::vector<uint8_t> bytes(64);
		const uint32_t length = 64, load = 20;
		std::memcpy(bytes.data(), &length, 4);
		std::memcpy(bytes.data() + 4, &load, 4);
		const uint64_t values[] = {16ULL << 30, 8ULL << 30, 32ULL << 30, 16ULL << 30, 0x7fffffe0000ULL, 0x7fffff00000ULL, 0};
		std::memcpy(bytes.data() + 8, values, 56);
		call.write(call[0], bytes);
		call.ret(1);
	});
	registry.add("HeapSetInformation", 4, [](ApiCall &call) { call.ret(1); });
	registry.add("HeapValidate", 3, [](ApiCall &call) { call.ret(1); });
	registry.add("HeapCompact", 2, [](ApiCall &call) { call.ret(0x10000); });

	registry.add("CreateFileMappingW", 6, [&](ApiCall &call) {
		auto mapping = std::make_shared<MappingObject>();
		if (call[0] != UINT64_MAX) {
			mapping->file = objects.object_as<FileObject>(call[0]);
			if (!mapping->file) {
				call.fail(6);
				return;
			}
			struct stat metadata{};
			::fstat(mapping->file->descriptor, &metadata);
			mapping->size = (uint64_t(call.u32(4)) << 32 | call.u32(3)) ? (uint64_t(call.u32(4)) << 32 | call.u32(3)) : uint64_t(metadata.st_size);
		} else {
			mapping->size = uint64_t(call.u32(4)) << 32 | call.u32(3);
			if (!mapping->size) {
				call.fail(87);
				return;
			}
		}
		mapping->protection = call.u32(2);
		const auto made = objects.add_object(mapping);
		if (made.status) {
			call.fail(8);
			return;
		}
		call.ret(made.value);
	});
	const auto views_owner = std::make_shared<std::map<uint64_t, View>>();
	auto &views = *views_owner;
	registry.add("MapViewOfFile", 5, [&, views_owner](ApiCall &call) {
		const auto mapping = objects.object_as<MappingObject>(call[0]);
		if (!mapping) {
			call.fail(6);
			return;
		}
		const uint64_t offset = uint64_t(call.u32(2)) << 32 | call.u32(3);
		const uint64_t size = call[4] ? call[4] : mapping->size - offset;
		if (offset > mapping->size || size > mapping->size - offset) {
			call.fail(87);
			return;
		}
		const auto range = memory.allocate(0, (size + 4095) & ~uint64_t(4095), 0x3000, 4);
		if (range.status) {
			call.fail(8);
			return;
		}
		if (mapping->file) {
			std::vector<uint8_t> bytes(size);
			const auto count = ::pread(mapping->file->descriptor, bytes.data(), size, off_t(offset));
			if (count > 0)
				call.write(range.address, std::span<const uint8_t>(bytes.data(), size_t(count)));
		}
		views[range.address] = {mapping, offset, size, bool(call.u32(1) & 2)};
		call.ret(range.address);
	});
	const auto write_back = [&](uint64_t address, ApiCall &call) {
		const auto found = views.find(address);
		if (found == views.end() || !found->second.writable || !found->second.mapping->file)
			return;
		const auto bytes = call.read(address, found->second.size);
		::pwrite(found->second.mapping->file->descriptor, bytes.data(), bytes.size(), off_t(found->second.offset));
	};
	registry.add("FlushViewOfFile", 2, [write_back](ApiCall &call) {
		write_back(call[0], call);
		call.ret(1);
	});
	registry.add("UnmapViewOfFile", 1, [&, write_back](ApiCall &call) {
		if (!views.contains(call[0])) {
			call.fail(998);
			return;
		}
		write_back(call[0], call);
		views.erase(call[0]);
		memory.free(call[0], 0, 0x8000);
		call.ret(1);
	});
}

}

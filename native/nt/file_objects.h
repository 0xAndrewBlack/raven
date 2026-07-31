#pragma once

#include "objects.h"

#include <filesystem>
#include <string>
#include <unistd.h>
#include <vector>

namespace raven {

// An open file or directory; the host descriptor carries the Windows file pointer.
class FileObject : public KernelObject {
public:
	FileObject(int descriptor, uint32_t access, bool directory, std::filesystem::path path, std::u16string dos_path, uint32_t flags)
		: descriptor(descriptor), access(access), directory(directory), path(std::move(path)), dos_path(std::move(dos_path)), flags(flags) {}
	~FileObject() override;
	// Synchronous file handles are always signaled.
	int signaled(uint32_t) const override { return 1; }
	int descriptor;
	uint32_t access;
	bool directory;
	std::filesystem::path path;
	std::u16string dos_path;
	uint32_t flags;
	bool readable() const { return access & (0x80000000U | 0x10000000U | 0x1U); }
	bool writable() const { return access & (0x40000000U | 0x10000000U | 0x2U | 0x4U); }
};

// A snapshot of a directory listing consumed by FindNextFile.
class FindObject : public KernelObject {
public:
	struct Entry {
		std::u16string name;
		uint32_t attributes;
		uint64_t creation, access, write, size;
	};
	std::vector<Entry> entries;
	size_t next = 0;
};

}

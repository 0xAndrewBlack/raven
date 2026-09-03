#pragma once

#include "objects.h"

#include <filesystem>
#include <string>
#include <unistd.h>
#include <vector>

namespace raven {

class CompletionPort;

// An open file or directory; the host descriptor carries the Windows file pointer.
class FileObject : public KernelObject {
public:
	std::u16string_view type_name() const override { return u"File"; }
	uint32_t default_access() const override { return access; }
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
	bool describe(InheritedHandle &record) const override
	{
		if (descriptor < 0)
			return false;
		record.kind = "file";
		record.descriptor = descriptor;
		record.access = access;
		record.flags = flags;
		record.bits = directory ? 1 : 0;
		record.text = dos_path;
		record.path = path.string();
		return true;
	}
	bool readable() const { return access & (0x80000000U | 0x10000000U | 0x1U); }
	// The completion port the handle is associated with, and the key its packets carry. FILE_SKIP_COMPLETION_PORT_ON_SUCCESS: a
	// transfer that finishes inside the call does not also queue a completion; the event one does not set the event either.
	std::shared_ptr<CompletionPort> port;
	uint64_t key = 0;
	bool skip_port_on_success = false, skip_event_on_success = false;
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

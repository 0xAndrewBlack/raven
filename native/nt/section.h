#pragma once

#include "file_objects.h"
#include "shared_file.h"

#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>

namespace raven {

// A file mapping. Memory that is not backed by a file lives in a host file the views map shared, so processes that inherit or open the
// section see each other's writes; a section over a file keeps the older scheme in which views are copies written back when they end.
class SectionObject : public KernelObject {
public:
	std::u16string_view type_name() const override { return u"Section"; }
	~SectionObject() override
	{
		if (descriptor < 0)
			return;
		// A named section's file goes when nobody else holds it: a fresh lock attempt on the file succeeds only then.
		const int guard = backing.empty() ? -1 : lock_directory(std::filesystem::path(backing).parent_path());
		::close(descriptor);
		if (!backing.empty()) {
			const int probe = ::open(backing.c_str(), O_RDWR | O_CLOEXEC);
			if (probe >= 0) {
				if (::flock(probe, LOCK_EX | LOCK_NB) == 0)
					::unlink(backing.c_str());
				::close(probe);
			}
		}
		if (guard >= 0)
			::close(guard);
	}
	bool describe(InheritedHandle &record) const override
	{
		if (descriptor < 0)
			return false;
		record.kind = "section";
		record.descriptor = descriptor;
		record.access = protection;
		record.size = size;
		record.text = name;
		record.path = backing;
		return true;
	}
	std::shared_ptr<FileObject> file;
	int descriptor = -1;
	uint64_t size = 0;
	uint32_t protection = 0;
	std::u16string name;
	std::string backing;
};

}

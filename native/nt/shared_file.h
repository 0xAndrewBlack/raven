#pragma once

#include "host_names.h"
#include "text.h"

#include <atomic>
#include <cctype>
#include <fcntl.h>
#include <filesystem>
#include <functional>
#include <memory>
#include <string>
#include <sys/file.h>
#include <sys/mman.h>
#include <unistd.h>

namespace raven {

// The number of shared objects this process holds; waits on them are polled, so the scheduler looks more often while any exists.
extern std::atomic<int> shared_object_count;

// The state of a named kernel object that several processes of a prefix share: a small host file every holder maps. A holder keeps a
// shared lock on the file, which tells a live object from one that a past run left; the last holder removes the file.
class SharedFile {
public:
	SharedFile() = default;
	SharedFile(const SharedFile &) = delete;
	SharedFile &operator=(const SharedFile &) = delete;
	~SharedFile()
	{
		if (data)
			::munmap(data, size);
		if (descriptor >= 0)
			::close(descriptor);
		if (!path.empty()) {
			const int probe = ::open(path.c_str(), O_RDWR | O_CLOEXEC);
			if (probe >= 0) {
				if (::flock(probe, LOCK_EX | LOCK_NB) == 0)
					::unlink(path.c_str());
				::close(probe);
			}
		}
		if (counted)
			--shared_object_count;
	}

	// Opens or creates the object of a kind and name. `init` runs on the memory of a new object before anyone else can see it.
	static std::shared_ptr<SharedFile> open(const char *kind, const std::u16string &name, size_t size, bool create, bool &existed, uint32_t &error,
		const std::function<void(void *)> &init = {})
	{
		existed = false;
		std::filesystem::path base;
		if (const char *runtime = std::getenv("XDG_RUNTIME_DIR"); runtime && *runtime)
			base = runtime;
		else
			base = NativePrefix::from_environment().root();
		auto directory = base / ("raven-objects-" + prefix_tag());
		std::error_code failure;
		std::filesystem::create_directories(directory, failure);
		auto upper = to_utf8(name);
		for (auto &character : upper)
			character = char(std::toupper(static_cast<unsigned char>(character)));
		auto file = std::make_shared<SharedFile>();
		file->path = (directory / (std::string(kind) + "-" + hex_text(name_hash(upper)))).string();
		file->size = size;
		file->descriptor = ::open(file->path.c_str(), (create ? O_CREAT : 0) | O_RDWR | O_CLOEXEC, 0600);
		if (file->descriptor < 0) {
			file->path.clear();
			error = create ? 5 : 2;
			return nullptr;
		}
		const bool first = ::flock(file->descriptor, LOCK_EX | LOCK_NB) == 0;
		if (first && !create) {
			// Nobody holds the file: the object does not exist any more.
			::flock(file->descriptor, LOCK_UN);
			file->path.clear();
			error = 2;
			return nullptr;
		}
		if (first && (::ftruncate(file->descriptor, 0) || ::ftruncate(file->descriptor, off_t(size)))) {
			file->path.clear();
			error = 8;
			return nullptr;
		}
		file->data = ::mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, file->descriptor, 0);
		if (file->data == MAP_FAILED) {
			file->data = nullptr;
			file->path.clear();
			error = 8;
			return nullptr;
		}
		if (first) {
			if (init)
				init(file->data);
			::flock(file->descriptor, LOCK_SH);
		} else {
			::flock(file->descriptor, LOCK_SH);
			existed = true;
		}
		file->counted = true;
		++shared_object_count;
		return file;
	}

	void *data = nullptr;
	size_t size = 0;

private:
	int descriptor = -1;
	std::string path;
	bool counted = false;
};

}

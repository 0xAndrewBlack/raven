#include "shared_gpu_memory.h"
#include "cpu/native_cpu.h"

#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <memory>
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include <vector>

namespace raven {

std::optional<GpuMapping> map_gpu_memory(NativeProcess &process, void *host, size_t size)
{
	const uint64_t address = reinterpret_cast<uintptr_t>(host);
	if (!size || size > UINT64_MAX - address)
		return std::nullopt;
	std::ifstream maps("/proc/self/maps");
	std::string line;
	uint64_t offset = 0, delta = address & 4095, inode = 0;
	unsigned device_major = 0, device_minor = 0;
	bool found = false, drm = false;
	while (std::getline(maps, line)) {
		uint64_t first = 0, last = 0, backing = 0;
		char access[5]{};
		int path = 0;
		if (std::sscanf(line.c_str(), "%" SCNx64 "-%" SCNx64 " %4s %" SCNx64 " %x:%x %" SCNu64 " %n",
			&first, &last, access, &backing, &device_major, &device_minor, &inode, &path) != 7 ||
			first > address || last < address + size)
			continue;
		drm = path > 0 && std::string_view(line).substr(size_t(path)) == "anon_inode:i915.gem";
		if (std::string_view(access) != "rw-s" || (!drm && !inode))
			return std::nullopt;
		if (backing > UINT64_MAX - ((address & ~uint64_t(4095)) - first))
			return std::nullopt;
		offset = backing + (address & ~uint64_t(4095)) - first;
		found = true;
		break;
	}
	if (!found || size > SIZE_MAX - delta - 4095)
		return std::nullopt;
	const size_t length = (size + size_t(delta) + 4095) & ~size_t(4095);
	if (offset > INT64_MAX || length > INT64_MAX - offset)
		return std::nullopt;
	std::unique_ptr<DIR, int (*)(DIR *)> directory(opendir("/proc/self/fd"), closedir);
	if (!directory)
		return std::nullopt;
	std::optional<dev_t> device;
	std::vector<int> candidates;
	while (auto *entry = readdir(directory.get())) {
		char *end = nullptr;
		const auto number = std::strtol(entry->d_name, &end, 10);
		if (*end || number < 0 || number > INT32_MAX)
			continue;
		struct stat status{};
		if (fstat(int(number), &status) != 0)
			continue;
		if (drm) {
			if (!S_ISCHR(status.st_mode) || major(status.st_rdev) != 226)
				continue;
			// DRM offsets belong to the open file description. Multiple nodes leave the owner ambiguous.
			if (device && *device != status.st_rdev)
				return std::nullopt;
			device = status.st_rdev;
		} else if (!S_ISREG(status.st_mode) || status.st_dev != makedev(device_major, device_minor) || status.st_ino != inode) {
			continue;
		}
		candidates.push_back(int(number));
	}
	for (const auto candidate : candidates) {
		const int file = fcntl(candidate, F_DUPFD_CLOEXEC, 0);
		if (file < 0)
			continue;
		struct stat status{};
		if (fstat(file, &status) != 0 || (drm ? !S_ISCHR(status.st_mode) || !device || status.st_rdev != *device :
			!S_ISREG(status.st_mode) || status.st_dev != makedev(device_major, device_minor) || status.st_ino != inode ||
			status.st_size < 0 || offset > uint64_t(status.st_size) || length > uint64_t(status.st_size) - offset)) {
			close(file);
			continue;
		}
		void *alias = mmap(nullptr, length, PROT_READ | PROT_WRITE, MAP_SHARED, file, off_t(offset));
		if (alias == MAP_FAILED) {
			close(file);
			continue;
		}
		munmap(alias, length);
		try {
			const auto base = process.map_descriptor(file, length, offset);
			close(file);
			return GpuMapping{base + delta, base};
		} catch (...) {
			close(file);
			throw;
		}
	}
	return std::nullopt;
}

}

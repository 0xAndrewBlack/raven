#include "shared_pixels.h"

#include <new>
#include <stdexcept>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

namespace raven {

SharedPixels::SharedPixels(size_t size) : length(size)
{
	file = memfd_create("raven-pixels", MFD_CLOEXEC);
	if (file < 0)
		throw std::bad_alloc();
	if (ftruncate(file, off_t(size)) != 0) {
		close(file);
		throw std::bad_alloc();
	}
	void *address = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, file, 0);
	if (address == MAP_FAILED) {
		close(file);
		throw std::bad_alloc();
	}
	mapping = static_cast<uint8_t *>(address);
}

SharedPixels::SharedPixels(int section, uint64_t offset, size_t size) : length(size)
{
	if (offset % size_t(sysconf(_SC_PAGESIZE)))
		throw std::invalid_argument("section offset is not page aligned");
	file = fcntl(section, F_DUPFD_CLOEXEC, 3);
	if (file < 0)
		throw std::bad_alloc();
	void *address = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, file, off_t(offset));
	if (address == MAP_FAILED) {
		close(file);
		throw std::bad_alloc();
	}
	mapping = static_cast<uint8_t *>(address);
	view_offset = offset;
}

SharedPixels::~SharedPixels()
{
	if (mapping)
		munmap(mapping, length);
	if (file >= 0)
		close(file);
}

}

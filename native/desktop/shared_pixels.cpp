#include "shared_pixels.h"

#include <new>
#include <stdexcept>
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

SharedPixels::~SharedPixels()
{
	if (mapping)
		munmap(mapping, length);
	if (file >= 0)
		close(file);
}

}

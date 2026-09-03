#pragma once

#include <cstddef>
#include <cstdint>

namespace raven {

// Pixel storage the host and the guest both map, so drawing never copies a whole bitmap through the debugger interface.
class SharedPixels {
public:
	explicit SharedPixels(size_t size);
	// A view of a section a program created: `offset` must be a multiple of the page size.
	SharedPixels(int section, uint64_t offset, size_t size);
	SharedPixels(const SharedPixels &) = delete;
	SharedPixels &operator=(const SharedPixels &) = delete;
	~SharedPixels();
	int descriptor() const { return file; }
	uint8_t *data() const { return mapping; }
	size_t size() const { return length; }
	// Where in its descriptor the pixels start; zero for pixels that own their file.
	uint64_t offset() const { return view_offset; }

private:
	int file = -1;
	uint8_t *mapping = nullptr;
	size_t length = 0;
	uint64_t view_offset = 0;
};

}

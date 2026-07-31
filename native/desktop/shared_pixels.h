#pragma once

#include <cstddef>
#include <cstdint>

namespace raven {

// Pixel storage the host and the guest both map, so drawing never copies a whole bitmap through the debugger interface.
class SharedPixels {
public:
	explicit SharedPixels(size_t size);
	SharedPixels(const SharedPixels &) = delete;
	SharedPixels &operator=(const SharedPixels &) = delete;
	~SharedPixels();
	int descriptor() const { return file; }
	uint8_t *data() const { return mapping; }
	size_t size() const { return length; }

private:
	int file = -1;
	uint8_t *mapping = nullptr;
	size_t length = 0;
};

}

#pragma once

#include <cstdint>
#include <vector>

namespace raven {

// Top-down RGBA8 rows, straight alpha. Windows raster/mask operations stay above codecs.
struct Pixels {
	uint32_t width;
	uint32_t height;
	std::vector<uint8_t> rgba;
};

}

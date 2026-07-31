#pragma once

#include <cstdint>
#include <span>
#include <vector>

namespace raven {

enum class StretchOperation { bitmap, dibits };

// Packed top-down byte channels; measured positive-origin BLACKONWHITE behavior.
std::vector<uint8_t> stretch_blackonwhite(std::span<const uint8_t> source,
	uint32_t width, uint32_t height, uint32_t channels, uint32_t target_width, uint32_t target_height,
	StretchOperation operation = StretchOperation::dibits);

}

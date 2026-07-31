#pragma once

#include "pixels.h"

#include <span>

namespace raven {

struct IconBitmap {
	Pixels color;
	// Top-down one-byte bits. One-bit XOR indices remain separate from palette colors.
	std::vector<uint8_t> and_mask;
	std::vector<uint8_t> xor_mask;
	bool has_alpha;
};

IconBitmap decode_icon_dib(std::span<const uint8_t> bytes);

}

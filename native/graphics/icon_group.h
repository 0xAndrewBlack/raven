#pragma once

#include <cstdint>
#include <span>
#include <vector>

namespace raven {

struct IconEntry {
	uint32_t width;
	uint32_t height;
	uint16_t depth;
	uint32_t size;
	uint16_t id;
};

struct IconDisplay {
	uint32_t width = 32;
	uint32_t height = 32;
	uint16_t depth = 32;
};

std::vector<IconEntry> decode_icon_group(std::span<const uint8_t> bytes);
// Measured Wine reference policy; the documented size preference differs.
uint16_t lookup_icon(std::span<const IconEntry> entries, uint32_t width, uint32_t height,
	IconDisplay display, bool monochrome);

}

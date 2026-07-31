#include "icon_group.h"

#include <limits>
#include <stdexcept>

namespace raven {

static uint32_t number(std::span<const uint8_t> bytes, size_t offset, size_t size)
{
	uint32_t result = 0;
	for (size_t index = 0; index < size; ++index)
		result |= uint32_t(bytes[offset + index]) << (index * 8);
	return result;
}

std::vector<IconEntry> decode_icon_group(std::span<const uint8_t> bytes)
{
	if (bytes.size() < 6 || number(bytes, 0, 2) || number(bytes, 2, 2) != 1)
		throw std::runtime_error("invalid icon group header");
	const size_t count = number(bytes, 4, 2);
	if (!count || bytes.size() < 6 + count * 14)
		throw std::runtime_error("truncated or empty icon group");
	std::vector<IconEntry> entries;
	entries.reserve(count);
	for (size_t index = 0; index < count; ++index) {
		const size_t offset = 6 + index * 14;
		const auto size = number(bytes, offset + 8, 4);
		const auto id = uint16_t(number(bytes, offset + 12, 2));
		if (bytes[offset + 3] || !size || !id)
			throw std::runtime_error("invalid icon group entry");
		entries.push_back({bytes[offset] ? uint32_t(bytes[offset]) : 256,
			bytes[offset + 1] ? uint32_t(bytes[offset + 1]) : 256,
			uint16_t(number(bytes, offset + 6, 2)), size, id});
	}
	return entries;
}

uint16_t lookup_icon(std::span<const IconEntry> entries, uint32_t width, uint32_t height,
	IconDisplay display, bool monochrome)
{
	if (!display.width || !display.height || !display.depth)
		throw std::runtime_error("invalid icon display state");
	width = width ? width : display.width;
	height = height ? height : display.height;
	const auto distance = [&](const IconEntry &entry) {
		return uint64_t(width > entry.width ? width - entry.width : entry.width - width) +
			uint64_t(height > entry.height ? height - entry.height : entry.height - height);
	};
	const IconEntry *selected = nullptr;
	uint64_t nearest = std::numeric_limits<uint64_t>::max();
	const uint16_t depth = monochrome ? 1 : display.depth;
	for (const auto &entry : entries) {
		const auto delta = distance(entry);
		if (delta < nearest) {
			nearest = delta;
			selected = &entry;
		} else if (delta == nearest &&
			((entry.depth <= depth && (selected->depth > depth || entry.depth > selected->depth)) ||
			(entry.depth > depth && selected->depth > depth && entry.depth < selected->depth))) {
			selected = &entry;
		}
	}
	return selected ? selected->id : 0;
}

}

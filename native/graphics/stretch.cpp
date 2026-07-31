#include "stretch.h"

#include <algorithm>
#include <array>
#include <stdexcept>

namespace raven {

static std::vector<std::array<uint32_t, 2>> scan_ranges(uint32_t source, uint32_t target, StretchOperation operation)
{
	std::vector<std::array<uint32_t, 2>> ranges;
	ranges.reserve(target);
	for (uint32_t index = 0; index < target; ++index) {
		if (target >= source) {
			const auto start = uint32_t((uint64_t(index) * source + (source - 1) / 2) / target);
			ranges.push_back({start, start + 1});
		} else if (target == 1 && operation == StretchOperation::bitmap) {
			// Pinned Wine excludes the final source pixel here; Windows reference is pending.
			ranges.push_back({0, source - 1});
		} else {
			const uint64_t bias = (target - 1) / 2;
			const uint64_t position = uint64_t(index) * source;
			const auto start = position > bias ? (position - bias + target - 1) / target : 0;
			const auto end = std::min(uint64_t(source), (position + source - bias + target - 1) / target);
			ranges.push_back({uint32_t(start), uint32_t(end)});
		}
	}
	return ranges;
}

std::vector<uint8_t> stretch_blackonwhite(std::span<const uint8_t> source,
	uint32_t width, uint32_t height, uint32_t channels, uint32_t target_width, uint32_t target_height,
	StretchOperation operation)
{
	const uint32_t height_limit = channels == 1 ? 16384 : 8192;
	if (!width || !height || !target_width || !target_height || width > 8192 || height > height_limit ||
		target_width > 8192 || target_height > height_limit || (channels != 1 && channels != 4) ||
		(operation != StretchOperation::bitmap && operation != StretchOperation::dibits))
		throw std::runtime_error("invalid BLACKONWHITE geometry or channels");
	const uint64_t source_pixels = uint64_t(width) * height, target_pixels = uint64_t(target_width) * target_height;
	const uint64_t pixel_limit = channels == 1 ? 32 * 1024 * 1024 : 16 * 1024 * 1024;
	if (source_pixels > pixel_limit || target_pixels > pixel_limit || source.size() != source_pixels * channels)
		throw std::runtime_error("invalid BLACKONWHITE storage or pixel limit");
	const auto columns = scan_ranges(width, target_width, operation), rows = scan_ranges(height, target_height, operation);
	std::vector<uint8_t> output(size_t(target_pixels) * channels, 255);
	for (uint32_t y = 0; y < target_height; ++y) {
		for (uint32_t x = 0; x < target_width; ++x) {
			const size_t target = (size_t(y) * target_width + x) * channels;
			for (uint32_t sy = rows[y][0]; sy < rows[y][1]; ++sy)
				for (uint32_t sx = columns[x][0]; sx < columns[x][1]; ++sx)
					for (uint32_t channel = 0; channel < channels; ++channel)
						output[target + channel] &= source[(size_t(sy) * width + sx) * channels + channel];
		}
	}
	return output;
}

}

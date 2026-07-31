#include "png_codec.h"

#include <png.h>
#include <stdexcept>
#include <string>

namespace raven {

Pixels decode_png(std::span<const uint8_t> bytes)
{
	if (bytes.size() < 8 || bytes.size() > 16 * 1024 * 1024 || png_sig_cmp(bytes.data(), 0, 8))
		throw std::runtime_error("invalid PNG input or compressed-size policy limit");
	struct Image {
		png_image value{};
		~Image() { png_image_free(&value); }
	} image;
	image.value.version = PNG_IMAGE_VERSION;
	if (!png_image_begin_read_from_memory(&image.value, bytes.data(), bytes.size()))
		throw std::runtime_error("PNG header decoding failed: " + std::string(image.value.message));
	const uint32_t width = image.value.width;
	const uint32_t height = image.value.height;
	if (!width || !height || width > 8192 || height > 8192 || uint64_t(width) * height > 16 * 1024 * 1024)
		throw std::runtime_error("PNG dimensions exceed pixel policy limit");
	Pixels pixels{width, height, std::vector<uint8_t>(size_t(width) * height * 4)};
	image.value.format = PNG_FORMAT_RGBA;
	if (!png_image_finish_read(&image.value, nullptr, pixels.rgba.data(), 0, nullptr))
		throw std::runtime_error("PNG pixel decoding failed: " + std::string(image.value.message));
	return pixels;
}

}

#include "png_codec.h"
#include "pe/resources.h"
#include "pe/loaded_image.h"

#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <zlib.h>

static void check(bool condition, const char *message)
{
	if (!condition)
		throw std::runtime_error(message);
}

static std::vector<uint8_t> read_file(const std::filesystem::path &path)
{
	std::ifstream file(path, std::ios::binary | std::ios::ate);
	if (!file || file.tellg() < 0 || file.tellg() > 1024 * 1024 * 1024)
		throw std::runtime_error("invalid PNG test input");
	std::vector<uint8_t> bytes(static_cast<size_t>(file.tellg()));
	file.seekg(0);
	if (!file.read(reinterpret_cast<char *>(bytes.data()), static_cast<std::streamsize>(bytes.size())))
		throw std::runtime_error("cannot read PNG test input");
	return bytes;
}

static void rejected(const std::function<void()> &operation, std::string_view reason)
{
	std::string failure;
	try { operation(); } catch (const std::runtime_error &error) { failure = error.what(); }
	if (failure.empty() || failure.find(reason) == failure.npos)
		throw std::runtime_error("PNG negative expected " + std::string(reason) + "; observed: " + failure);
}

int main(int argc, char **argv)
{
	try {
		check(argc == 3, "application and PNG output directory required");
		const uint8_t known[] = {137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 0, 3, 0, 0, 0, 2, 8, 6, 0, 0, 0, 157, 116, 102, 26, 0, 0, 0, 31, 73, 68, 65, 84, 120, 156, 99, 248, 207, 192, 240, 31, 8, 27, 64, 20, 3, 167, 128, 3, 51, 35, 19, 243, 191, 255, 255, 255, 51, 2, 0, 108, 149, 8, 219, 131, 137, 245, 62, 0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130};
		const std::vector<uint8_t> expected{255, 0, 0, 255, 0, 255, 0, 128, 0, 0, 255, 0, 9, 16, 64, 3, 1, 2, 3, 254, 255, 255, 255, 1};
		const auto sample = raven::decode_png(known);
		check(sample.width == 3 && sample.height == 2 && sample.rgba == expected,
			"RGBA channels, row order or straight alpha differ");
		const auto bytes = read_file(argv[1]);
		const raven::PEImage image(bytes);
		const auto resources = image.resources();
		raven::LoadedImage loaded(image, image.image_base);
		const std::filesystem::path directory(argv[2]);
		std::filesystem::create_directories(directory);
		unsigned decoded = 0;
		std::vector<uint8_t> first;
		for (const auto &resource : resources) {
			if (resource.type != raven::ResourceKey(uint32_t(3)))
				continue;
			const auto data = std::span<const uint8_t>(loaded.data()).subspan(resource.data_address, resource.size);
			const std::array<uint8_t, 8> signature{137, 80, 78, 71, 13, 10, 26, 10};
			if (data.size() < 8 || !std::equal(signature.begin(), signature.end(), data.begin()))
				continue;
			const auto pixels = raven::decode_png(data);
			check(pixels.rgba.size() == size_t(pixels.width) * pixels.height * 4, "decoded PNG dimensions differ");
			const auto id = std::get<uint32_t>(resource.name);
			std::ofstream output(directory / (std::to_string(id) + ".rgba"), std::ios::binary | std::ios::trunc);
			const uint32_t header[] = {pixels.width, pixels.height};
			output.write(reinterpret_cast<const char *>(header), sizeof(header));
			output.write(reinterpret_cast<const char *>(pixels.rgba.data()), static_cast<std::streamsize>(pixels.rgba.size()));
			check(bool(output), "cannot save decoded PNG evidence");
			if (first.empty())
				first.assign(data.begin(), data.end());
			++decoded;
		}
		check(decoded == 2029, "real application PNG corpus changed");
		rejected([&] { raven::decode_png({}); }, "invalid PNG input");
		rejected([&] { raven::decode_png(std::span(first).first(20)); }, "header decoding failed");
		rejected([&] { raven::decode_png(std::span(first).first(first.size() / 2)); }, "pixel decoding failed");
		auto corrupted = first;
		corrupted[16] = 0;
		corrupted[17] = 0;
		corrupted[18] = 0x20;
		corrupted[19] = 1;
		const auto crc = crc32(0, corrupted.data() + 12, 17);
		for (size_t index = 0; index < 4; ++index)
			corrupted[29 + index] = static_cast<uint8_t>(crc >> ((3 - index) * 8));
		rejected([&] { raven::decode_png(corrupted); }, "pixel policy limit");
		corrupted = first;
		for (size_t index = 0; index < 4; ++index) {
			corrupted[16 + index] = static_cast<uint8_t>(4097U >> ((3 - index) * 8));
			corrupted[20 + index] = corrupted[16 + index];
		}
		const auto large_crc = crc32(0, corrupted.data() + 12, 17);
		for (size_t index = 0; index < 4; ++index)
			corrupted[29 + index] = static_cast<uint8_t>(large_crc >> ((3 - index) * 8));
		rejected([&] { raven::decode_png(corrupted); }, "pixel policy limit");
		corrupted = first;
		corrupted[29] ^= 1;
		rejected([&] { raven::decode_png(corrupted); }, "header decoding failed");
		std::cout << "Pinned libpng decoded " << decoded << " real application icons; malformed and bounded-allocation controls passed\n";
		return 0;
	} catch (const std::exception &error) {
		std::cerr << error.what() << '\n';
		return 1;
	}
}

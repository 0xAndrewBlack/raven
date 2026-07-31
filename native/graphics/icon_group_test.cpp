#include "icon_group.h"
#include "pe/loaded_image.h"
#include "pe/resources.h"

#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

static void check(bool condition, const char *message)
{
	if (!condition)
		throw std::runtime_error(message);
}

static std::vector<uint8_t> read_file(const char *path)
{
	std::ifstream file(path, std::ios::binary | std::ios::ate);
	check(bool(file) && file.tellg() > 0 && file.tellg() < 1024 * 1024 * 1024, "invalid group fixture");
	std::vector<uint8_t> bytes(static_cast<size_t>(file.tellg()));
	file.seekg(0);
	check(bool(file.read(reinterpret_cast<char *>(bytes.data()), static_cast<std::streamsize>(bytes.size()))), "cannot read group fixture");
	return bytes;
}

static void rejected(std::span<const uint8_t> bytes, std::string_view expected)
{
	std::string failure;
	try { raven::decode_icon_group(bytes); } catch (const std::runtime_error &error) { failure = error.what(); }
	check(failure.find(expected) != failure.npos, "group rejection failed for another reason");
}

int main(int argc, char **argv)
{
	try {
		check(argc == 2 || argc == 3, "application and optional selection output required");
		std::vector<uint8_t> bytes{0,0,1,0,1,0,0,0,0,0,1,0,32,0,1,0,0,0,5,0};
		const auto decoded = raven::decode_icon_group(bytes);
		check(decoded.size() == 1 && decoded[0].width == 256 && decoded[0].height == 256 && decoded[0].id == 5,
			"zero directory dimensions did not decode as 256");
		for (size_t size = 0; size < bytes.size(); ++size)
			rejected(std::span(bytes).first(size), size < 6 ? "header" : "truncated");
		auto invalid = bytes;
		invalid[0] = 1; rejected(invalid, "header");
		invalid = bytes; invalid[2] = 2; rejected(invalid, "header");
		invalid = bytes; invalid[4] = 0; rejected(invalid, "empty");
		invalid = bytes; invalid[9] = 1; rejected(invalid, "entry");
		invalid = bytes; invalid[14] = 0; rejected(invalid, "entry");
		invalid = bytes; invalid[18] = 0; rejected(invalid, "entry");
		const std::array<raven::IconEntry, 4> entries{{{16,16,32,1,1}, {32,32,8,1,2}, {32,32,32,1,3}, {48,48,32,1,4}}};
		check(raven::lookup_icon(entries, 24, 24, {}, false) == 1 &&
			raven::lookup_icon(entries, 25, 25, {}, false) == 3, "nearest reference size or tie order differs");
		check(raven::lookup_icon(entries, 24, 24, {}, true) == 2, "color depth did not resolve a size-distance tie");
		check(raven::lookup_icon(entries, 0, 0, {48,48,16}, false) == 4 &&
			raven::lookup_icon(entries, 0, 0, {32,32,16}, false) == 2 &&
			raven::lookup_icon(entries, 32, 32, {}, true) == 2, "display or minimum depth selection differs");
		check(raven::lookup_icon(entries, 0, 16, {48,48,32}, false) == 1 &&
			raven::lookup_icon({}, 1, 1, {}, false) == 0, "one-axis metric default or empty lookup differs");
		const auto file_bytes = read_file(argv[1]);
		raven::PEImage image(file_bytes);
		raven::LoadedImage loaded(image, image.image_base);
		const auto resources = image.resources();
		std::ofstream output;
		if (argc == 3) {
			output.open(argv[2], std::ios::trunc);
			check(bool(output), "cannot save icon selection output");
		}
		unsigned groups = 0;
		for (const auto &resource : resources) {
			if (resource.type != raven::ResourceKey(uint32_t(14)))
				continue;
			const auto group = raven::decode_icon_group(loaded.data().subspan(resource.data_address, resource.size));
			for (const auto &entry : group) {
				bool found = false;
				for (const auto &target : resources)
					if (target.type == raven::ResourceKey(uint32_t(3)) && target.name == raven::ResourceKey(uint32_t(entry.id)) &&
						target.language == resource.language && target.size == entry.size)
						found = true;
				check(found, "real group references missing image bytes");
			}
			const std::array<uint32_t, 25> sizes{0,1,12,13,15,16,17,20,24,25,31,32,33,40,47,48,49,64,96,128,192,200,255,256,300};
			const auto record = [&](uint32_t width, uint32_t height, bool monochrome) {
				const auto id = raven::lookup_icon(group, width, height, {}, monochrome);
				check(id != 0, "real icon group produced no selection");
				if (output.is_open())
					output << std::get<uint32_t>(resource.name) << ',' << width << ',' << height << ',' << monochrome << ',' << id << '\n';
			};
			for (bool monochrome : {false, true}) {
				for (const auto size : sizes)
					record(size, size, monochrome);
				for (uint32_t width = 16; width <= 48; width += 8)
					for (uint32_t height = 16; height <= 48; height += 8)
						if (width != height)
							record(width, height, monochrome);
			}
			++groups;
		}
		check(groups > 0 && (!output.is_open() || bool(output)), "icon group evidence failed");
		std::cout << groups << " real icon groups, checked references, size/depth selection and malformed controls passed\n";
		return 0;
	} catch (const std::exception &error) {
		std::cerr << error.what() << '\n';
		return 1;
	}
}

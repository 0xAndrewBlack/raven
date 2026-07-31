#include "resources.h"

#include <fstream>
#include <functional>
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
	if (!file || file.tellg() < 0 || file.tellg() > 1024 * 1024 * 1024)
		throw std::runtime_error("invalid resource fixture");
	std::vector<uint8_t> bytes(static_cast<size_t>(file.tellg()));
	file.seekg(0);
	if (!file.read(reinterpret_cast<char *>(bytes.data()), static_cast<std::streamsize>(bytes.size())))
		throw std::runtime_error("cannot read resource fixture");
	return bytes;
}

static void rejected(const std::function<void()> &operation, std::string_view reason)
{
	try {
		operation();
	} catch (const std::runtime_error &error) {
		check(std::string_view(error.what()).find(reason) != std::string_view::npos, "resource negative failed for a different reason");
		return;
	}
	throw std::runtime_error("malformed resource metadata was accepted");
}

int main(int argc, char **argv)
{
	try {
		check(argc == 3, "PE64 and PE32 resource fixtures required");
		for (int file = 1; file < argc; ++file) {
			const auto bytes = read_file(argv[file]);
			const raven::PEImage image(bytes);
			const auto resources = image.resources();
			check(image.is_64 == (file == 1) && resources.size() == 6, "compiled resource architecture/count differs");
			bool custom = false, mixed = false, french = false, neutral = false;
			for (const auto &resource : resources) {
				check(resource.size == 4 && image.file_span(resource.data_address, 4).size() == 4,
					"compiled resource payload is not file-backed");
				custom |= resource.type == raven::ResourceKey(std::u16string(u"CUSTOM")) && resource.name == raven::ResourceKey(uint32_t(7));
				mixed |= resource.type == raven::ResourceKey(uint32_t(10)) && resource.name == raven::ResourceKey(std::u16string(u"MIXED"));
				french |= resource.name == raven::ResourceKey(uint32_t(101)) && resource.language == 0x40c;
				neutral |= resource.name == raven::ResourceKey(uint32_t(102)) && resource.language == 0;
			}
			check(custom && mixed && french && neutral, "compiled resource identities differ");
			const auto directory = image.directories[2];
			const auto original = image.file_span(directory.address, directory.size);
			std::vector<uint8_t> altered(original.begin(), original.end());
			const auto put = [&](size_t offset, uint32_t value, size_t width = 4) {
				for (size_t index = 0; index < width; ++index)
					altered.at(offset + index) = static_cast<uint8_t>(value >> (index * 8));
			};
			const auto parse = [&] { raven::read_resources(directory, altered, image.image_size); };
			put(12, 0xffff, 2);
			rejected(parse, "exceeds directory");
			altered.assign(original.begin(), original.end());
			put(16, 0x80000000U | (directory.size + 2));
			rejected(parse, "exceeds directory");
			altered.assign(original.begin(), original.end());
			put(20, 0x80000000U);
			rejected(parse, "reused");
			altered.assign(original.begin(), original.end());
			put(20, 0x80000001U);
			rejected(parse, "unaligned");
			altered.assign(original.begin(), original.end());
			put(20, 0);
			rejected(parse, "before language");
			altered.assign(original.begin(), original.end());
			put(16, 7);
			rejected(parse, "partitions");
			altered.assign(original.begin(), original.end());
			const size_t leaf = resources[0].entry_address - directory.address;
			put(leaf, image.image_size + 1);
			rejected(parse, "payload exceeds image");
			altered.assign(original.begin(), original.end());
			put(leaf + 4, UINT32_MAX);
			rejected(parse, "payload exceeds image");
			altered.assign(original.begin(), original.end());
			put(leaf + 4, 0);
			check(raven::read_resources(directory, altered, image.image_size)[0].size == 0,
				"zero-length resource metadata was rejected");
			altered.assign(original.begin(), original.end());
			const auto read32 = [&](size_t offset) {
				uint32_t value = 0;
				for (size_t index = 0; index < 4; ++index)
					value |= uint32_t(original[offset + index]) << (index * 8);
				return value;
			};
			const size_t type = read32(28) & 0x7fffffffU;
			put(type + 32, 101);
			rejected(parse, "unordered or duplicated");
			altered.assign(original.begin(), original.end());
			const size_t languages = read32(type + 28) & 0x7fffffffU;
			put(languages + 20, 0x80000000U);
			rejected(parse, "language leaf");
			// IDs are stored in 32 bits, independently of MAKEINTRESOURCE's argument width.
			altered.assign(original.begin(), original.end());
			put(24, 70000);
			const auto wide_id = raven::read_resources(directory, altered, image.image_size);
			check(wide_id.back().type == raven::ResourceKey(uint32_t(70000)), "resource ID was truncated to WORD");
		}
		std::cout << "Compiled PE32/PE64 resource identities, payloads and malformed tree contracts passed\n";
		return 0;
	} catch (const std::exception &error) {
		std::cerr << error.what() << '\n';
		return 1;
	}
}

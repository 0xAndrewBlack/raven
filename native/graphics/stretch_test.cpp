#include "stretch.h"
#include "icon_bitmap.h"
#include "icon_data.h"

#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>

static void check(bool condition, const char *message)
{
	if (!condition)
		throw std::runtime_error(message);
}

static std::vector<uint8_t> read_file(const std::filesystem::path &path)
{
	std::ifstream file(path, std::ios::binary | std::ios::ate);
	check(bool(file) && file.tellg() > 0 && file.tellg() <= 64 * 1024 * 1024, "invalid raster fixture");
	std::vector<uint8_t> bytes(static_cast<size_t>(file.tellg()));
	file.seekg(0);
	check(bool(file.read(reinterpret_cast<char *>(bytes.data()), static_cast<std::streamsize>(bytes.size()))), "cannot read raster fixture");
	return bytes;
}

static uint32_t number(std::span<const uint8_t> bytes, size_t offset, size_t size = 4)
{
	check(offset <= bytes.size() && size <= bytes.size() - offset, "truncated raster fixture");
	uint32_t value = 0;
	for (size_t index = 0; index < size; ++index)
		value |= uint32_t(bytes[offset + index]) << (index * 8);
	return value;
}

static void rejected(std::span<const uint8_t> bytes, uint32_t width, uint32_t height,
	uint32_t channels, uint32_t target_width, uint32_t target_height, std::string_view expected)
{
	std::string failure;
	try { raven::stretch_blackonwhite(bytes, width, height, channels, target_width, target_height); }
	catch (const std::runtime_error &error) { failure = error.what(); }
	check(failure.find(expected) != failure.npos, "raster negative failed for another reason");
}

static std::vector<uint8_t> bitmap_pixels(std::span<const uint8_t> bytes)
{
	const auto width = number(bytes, 4), height = number(bytes, 8), stride = number(bytes, 12), depth = number(bytes, 18, 2);
	check(width && height && width <= 8192 && height <= 8192 && number(bytes, 16, 2) == 1 && (depth == 1 || depth == 32),
		"invalid reference bitmap");
	check(stride == (depth == 32 ? width * 4 : (width + 15) / 16 * 2) && uint64_t(stride) * height == bytes.size() - 32,
		"invalid reference bitmap storage");
	if (depth == 32)
		return {bytes.begin() + 32, bytes.end()};
	std::vector<uint8_t> pixels(size_t(width) * height);
	for (uint32_t y = 0; y < height; ++y)
		for (uint32_t x = 0; x < width; ++x)
			pixels[size_t(y) * width + x] = uint8_t((bytes[32 + size_t(y) * stride + x / 8] >> (7 - x % 8)) & 1);
	return pixels;
}

int main(int argc, char **argv)
{
	try {
		check(argc == 2 || argc == 4, "scan reference and optional bitmap manifest/output required");
		const std::array<uint8_t,4> pixel{1,2,4,8};
		rejected(pixel,0,1,4,1,1,"geometry");
		rejected(pixel,1,1,3,1,1,"channels");
		rejected(pixel,1,1,4,8193,1,"geometry");
		rejected(pixel,1,1,4,8192,8192,"limit");
		rejected(pixel,8192,8192,4,1,1,"limit");
		rejected(std::span(pixel).first(3),1,1,4,1,1,"storage");
		rejected(pixel,1,16385,1,1,1,"geometry");
		check(raven::stretch_blackonwhite(std::vector<uint8_t>(16384,1),1,16384,1,1,2) == std::vector<uint8_t>({1,1}),
			"bounded compound mask height was rejected");
		check(raven::stretch_blackonwhite(pixel,1,1,4,2,3) == std::vector<uint8_t>({1,2,4,8,1,2,4,8,1,2,4,8,1,2,4,8,1,2,4,8,1,2,4,8}),
			"constant alpha/channels did not survive expansion");
		const auto known_color = raven::decode_icon_dib(color_icon);
		check(raven::stretch_blackonwhite(known_color.color.rgba,3,2,4,2,1) ==
			std::vector<uint8_t>({0,0,0,0,0,0,8,0}),"known resource channels/alpha differ from Wine");
		check(raven::stretch_blackonwhite(known_color.color.rgba,3,2,4,2,1,raven::StretchOperation::bitmap) ==
			std::vector<uint8_t>({0,0,0,0,0,0,255,255}),"bitmap endpoint contract was mixed with DIB input");
		const auto known_mono = raven::decode_icon_dib(mono_icon);
		auto compound = known_mono.and_mask;
		compound.insert(compound.end(),known_mono.xor_mask.begin(),known_mono.xor_mask.end());
		check(raven::stretch_blackonwhite(compound,4,4,1,2,2) == std::vector<uint8_t>(4,0),
			"known monochrome compound resource differs from Wine");
		for (const auto operation : {raven::StretchOperation::bitmap,raven::StretchOperation::dibits}) {
			auto reference_path = std::filesystem::path(argv[1]);
			if (operation == raven::StretchOperation::dibits)
				reference_path.replace_filename("blackonwhite_dibits_reference.bin");
			const auto reference = read_file(reference_path);
			check(reference.size() >= 8 && std::string(reference.begin(), reference.begin() + 4) == "RBW1" && number(reference,4) == 2552,
				"scan reference identity differs");
			size_t offset = 8;
			for (unsigned test = 0; test < 2552; ++test) {
				const auto source = number(reference,offset,2), target = number(reference,offset+2,2);
				offset += 4;
				std::vector<std::array<uint32_t,2>> ranges;
				for (uint32_t index = 0; index < target; ++index) {
					const auto begin = number(reference,offset,2), end = number(reference,offset+2,2);
					check(begin < end && end <= source, "invalid scan reference interval");
					ranges.push_back({begin,end});
					offset += 4;
				}
				for (bool vertical : {false,true}) {
					for (uint32_t block = 0; block < source; block += 24) {
						std::vector<uint8_t> colors(size_t(source) * 4,255);
						for (uint32_t index = block; index < source && index < block+24; ++index)
							colors[size_t(index)*4+(index-block)/8] &= uint8_t(~(1U<<((index-block)%8)));
						const auto color = raven::stretch_blackonwhite(colors,vertical?1:source,vertical?source:1,4,
							vertical?1:target,vertical?target:1,operation);
						for (uint32_t index = 0; index < target; ++index) {
							uint32_t expected = 0xffffffff;
							for (uint32_t contributor = ranges[index][0]; contributor < ranges[index][1]; ++contributor)
								if (contributor >= block && contributor < block+24)
									expected &= ~(1U<<(contributor-block));
							check(number(color,size_t(index)*4) == expected,"color scan footprint differs");
						}
						const uint32_t width = vertical?24:source, height = vertical?source:24;
						std::vector<uint8_t> mono(size_t(width)*height,1);
						for (uint32_t bit=0; bit<24 && block+bit<source; ++bit)
							mono[size_t(vertical?block+bit:bit)*width+(vertical?bit:block+bit)] = 0;
						const uint32_t target_width = vertical?24:target, target_height = vertical?target:24;
						const auto mask = raven::stretch_blackonwhite(mono,width,height,1,target_width,target_height,operation);
						for (uint32_t index=0; index<target; ++index)
							for (uint32_t bit=0; bit<24; ++bit) {
								const bool contributes = block+bit<source && block+bit>=ranges[index][0] && block+bit<ranges[index][1];
								check(mask[size_t(vertical?index:bit)*target_width+(vertical?bit:index)] == !contributes,
									"monochrome scan footprint differs");
							}
					}
				}
			}
			check(offset == reference.size(),"unexpected scan reference bytes");
		}
		if (argc == 4) {
			std::ifstream manifest(argv[2]);
			std::filesystem::create_directories(argv[3]);
			std::string source_path,target_path,label;
			unsigned cases=0;
			std::string line;
			while (std::getline(manifest,line)) {
				std::istringstream fields(line);
				check(bool(fields>>source_path>>target_path>>label),"truncated raster manifest row");
				for (const char *suffix : {".color",".mask"}) {
					auto from=std::filesystem::path(source_path),to=std::filesystem::path(target_path);
					from.replace_extension(suffix);to.replace_extension(suffix);
					const auto input=read_file(from), expected=read_file(to);
					const auto pixels=bitmap_pixels(input), result=bitmap_pixels(expected);
					const uint32_t channels=number(input,18,2)==32?4:1;
					const auto actual=raven::stretch_blackonwhite(pixels,number(input,4),number(input,8),channels,number(expected,4),number(expected,8));
					check(actual==result,"real bitmap BLACKONWHITE output differs");
					std::ofstream file(std::filesystem::path(argv[3])/(label+suffix),std::ios::binary);
					file.write(reinterpret_cast<const char *>(actual.data()),static_cast<std::streamsize>(actual.size()));
					check(bool(file),"cannot save native raster evidence");
				}
				++cases;
			}
			check(manifest.eof() && cases>0 && cases<=10000,"incomplete real raster manifest");
			std::cout<<cases<<" real bitmap pairs matched\n";
		}
		std::cout<<"5,104 scan geometries per format, measured endpoint, channels/alpha and bounded-input controls passed\n";
		return 0;
	} catch (const std::exception &error) {
		std::cerr<<error.what()<<'\n';
		return 1;
	}
}

#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace raven {

struct TextMetrics {
	int32_t height,ascent,descent,internal_leading,external_leading,average_width,maximum_width;
	uint16_t first,last,default_character,break_character;
	uint8_t pitch;
};

struct TextExtent {
	int32_t width,height;
};

// Immutable typefaces and transient glyph masks; no Windows resource identities.
class TextRenderer {
public:
	explicit TextRenderer(const std::string &directory);
	~TextRenderer();
	TextRenderer(const TextRenderer &) = delete;
	TextRenderer &operator=(const TextRenderer &) = delete;
	TextMetrics metrics(std::span<const uint8_t,92> definition);
	TextExtent extent(std::span<const uint8_t,92> definition,std::span<const uint16_t> text);
	std::vector<int32_t> advances(std::span<const uint8_t,92> definition,std::span<const uint16_t> text);
	std::vector<uint8_t> mask(std::span<const uint8_t,92> definition,std::span<const uint16_t> text,
		uint32_t width,uint32_t height,int32_t x,int32_t y,std::span<const std::array<int32_t,2>> positions={});

private:
	struct State;
	std::unique_ptr<State> state;
};

}

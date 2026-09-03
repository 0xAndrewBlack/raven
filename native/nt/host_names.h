#pragma once

#include "prefix.h"

#include <cstdint>
#include <string>
#include <string_view>

namespace raven {

inline uint64_t name_hash(std::string_view text)
{
	uint64_t hash = 14695981039346656037ULL;
	for (const auto character : text) {
		hash ^= static_cast<unsigned char>(character);
		hash *= 1099511628211ULL;
	}
	return hash;
}

inline std::string hex_text(uint64_t value)
{
	char text[17];
	std::snprintf(text, sizeof(text), "%016llx", static_cast<unsigned long long>(value));
	return text;
}

// Names the objects of one prefix share between processes: the prefix keeps them apart from other prefixes on the same host.
inline const std::string &prefix_tag()
{
	static const std::string tag = hex_text(name_hash(NativePrefix::from_environment().root().string()));
	return tag;
}

}

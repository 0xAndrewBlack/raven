#pragma once

#include "objects.h"

#include <cstdint>
#include <vector>

namespace raven {

// The program's own access token: it names the account and holds no privilege.
class AccessToken : public KernelObject {
public:
	std::u16string_view type_name() const override { return u"Token"; }
};

// A SID with the given identifier authority and sub-authorities.
inline std::vector<uint8_t> make_sid(uint8_t authority, std::initializer_list<uint32_t> parts)
{
	std::vector<uint8_t> sid{1, uint8_t(parts.size()), 0, 0, 0, 0, 0, authority};
	for (const auto part : parts)
		for (int shift = 0; shift < 32; shift += 8)
			sid.push_back(uint8_t(part >> shift));
	return sid;
}

// The account the program runs as: the same identity the registry path of the current user names.
inline std::vector<uint8_t> user_sid() { return make_sid(5, {21, 1000, 1000, 1000, 1000}); }

}

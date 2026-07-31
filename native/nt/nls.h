#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace raven {

std::string encode_ansi(std::u16string_view text,uint32_t code_page);
std::string encode_utf8(std::u16string_view text,bool replace_invalid=false);

}

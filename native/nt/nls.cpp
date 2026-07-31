#include "nls.h"
#include "nls-cp1252.h"

#include <stdexcept>

namespace raven {

std::string encode_ansi(std::u16string_view text,uint32_t code_page)
{
	if (code_page!=1252) throw std::runtime_error("unsupported native ANSI code page");
	std::string result;
	result.reserve(text.size());
	for (const auto character : text) result.push_back(static_cast<char>(native_cp1252[character]));
	return result;
}

}

#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace raven {

// Lossless UTF-16 <-> UTF-8; lone surrogates become U+FFFD so host paths and messages stay valid text.
std::string to_utf8(std::u16string_view text);
std::u16string from_utf8(std::string_view text);
// Windows compares names with simple case mapping, never locale rules.
char16_t fold_case(char16_t character);
char16_t upper_case(char16_t character);
bool equal_fold(std::u16string_view left, std::u16string_view right);
int compare_fold(std::u16string_view left, std::u16string_view right);
std::u16string widen_ascii(std::string_view text);
// ANSI text of the process code page (1252, 437, ...) as UTF-16; unmapped bytes become U+FFFD.
std::u16string from_ansi(std::string_view text, uint32_t code_page);
// Inverse of from_ansi; characters the code page lacks become '?'.
std::string to_ansi(std::u16string_view text, uint32_t code_page);

}

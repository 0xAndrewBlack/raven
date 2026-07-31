#pragma once

#include <span>
#include <string>
#include <string_view>

namespace raven {

std::u16string launch_utf16(std::string_view text);
std::u16string launch_command_line(std::u16string_view image,std::span<const std::string_view> arguments);

}

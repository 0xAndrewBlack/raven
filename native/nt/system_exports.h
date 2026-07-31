#pragma once

#include <cstdint>
#include <span>
#include <string_view>
#include <utility>

namespace raven {

// Public export names of a Windows system library, empty when Raven knows no such library.
std::span<const std::string_view> system_export_names(std::string_view dll);
// Names that Windows also publishes under a fixed ordinal, which programs may import without a name.
std::span<const std::pair<std::string_view, uint16_t>> system_export_ordinals(std::string_view dll);
// Every library with a name list, in lower case with its ".dll" suffix.
std::span<const std::string_view> system_library_names();

}

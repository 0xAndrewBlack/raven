#include "system_exports.h"

#include <algorithm>
#include <array>

namespace raven {

namespace {

#include "system_exports.inc"

constexpr std::array<std::pair<std::string_view, uint16_t>, 6> comctl32_ordinals{{
	{"DefSubclassProc", 413}, {"GetWindowSubclass", 411}, {"InitCommonControls", 17}, {"LoadIconWithScaleDown", 381},
	{"RemoveWindowSubclass", 412}, {"SetWindowSubclass", 410},
}};
constexpr std::array<std::pair<std::string_view, uint16_t>, 1> shell32_ordinals{{{"SHCreateDirectory", 165}}};
constexpr std::array<std::pair<std::string_view, uint16_t>, 6> oleaut32_ordinals{{
	{"SysAllocString", 2}, {"SysAllocStringLen", 4}, {"SysFreeString", 6}, {"SysReAllocString", 3}, {"SysReAllocStringLen", 5},
	{"SysStringLen", 7},
}};

}

std::span<const std::string_view> system_export_names(std::string_view dll)
{
	for (const auto &[name, exports] : libraries)
		if (name == dll)
			return exports;
	return {};
}

std::span<const std::pair<std::string_view, uint16_t>> system_export_ordinals(std::string_view dll)
{
	if (dll == "comctl32.dll")
		return comctl32_ordinals;
	if (dll == "shell32.dll")
		return shell32_ordinals;
	if (dll == "oleaut32.dll")
		return oleaut32_ordinals;
	return {};
}

std::span<const std::string_view> system_library_names()
{
	static const auto names = [] {
		std::array<std::string_view, std::size(libraries)> list{};
		std::transform(std::begin(libraries), std::end(libraries), list.begin(), [](const auto &item) { return item.first; });
		return list;
	}();
	return names;
}

}

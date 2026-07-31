#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace raven {

struct MenuTemplateItem {
	uint32_t type=0,state=0,id=0;
	std::u16string text;
	std::optional<uint32_t> submenu_help;
	std::vector<MenuTemplateItem> children;
};

struct MenuTemplate {
	uint32_t help=0;
	std::vector<MenuTemplateItem> items;
};

MenuTemplate decode_menu(std::span<const uint8_t> bytes);

}

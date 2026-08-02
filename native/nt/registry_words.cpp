#include "registry_words.h"

#include <algorithm>
#include <array>
#include <utility>

namespace raven {

namespace {

constexpr std::pair<std::string_view, uint32_t> words[] = {
#include "registry_words.inc"
};

}

uint32_t registry_words(std::string_view name)
{
	const auto found = std::lower_bound(std::begin(words), std::end(words), name, [](const auto &item, std::string_view key) { return item.first < key; });
	return found != std::end(words) && found->first == name ? found->second : UINT32_MAX;
}

}

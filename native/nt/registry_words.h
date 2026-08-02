#pragma once

#include <cstdint>
#include <string_view>

namespace raven {

// The words a native API handler takes, or UINT32_MAX when the registry has no handler registered under that name literally.
uint32_t registry_words(std::string_view name);

}

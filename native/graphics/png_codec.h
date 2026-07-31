#pragma once

#include "pixels.h"

#include <span>

namespace raven {

Pixels decode_png(std::span<const uint8_t> bytes);

}

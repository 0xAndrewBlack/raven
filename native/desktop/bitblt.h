#pragma once
#include "objects.h"
#include <span>

namespace raven {
class NativeProcess;
bool bit_blt(NativeProcess &process,DesktopObjects &objects,std::span<const uint64_t> args);
}

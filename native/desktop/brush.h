#pragma once

#include "objects.h"

namespace raven {

class NativeProcess;
bool fill_rect(NativeProcess &process,DesktopObjects &objects,uint64_t dc,DesktopRect rect,uint64_t brush);

}

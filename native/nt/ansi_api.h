#pragma once

#include "api.h"

namespace raven {

// Registers the ANSI entry point of every file, environment and synchronisation API that only has a wide handler: strings the
// caller passes are widened before the wide handler runs, and text it returns is narrowed into the caller's buffer.
void register_ansi_adapters(ApiRegistry &registry);

}

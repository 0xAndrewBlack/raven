#pragma once

#include "api.h"

namespace raven {

// Registers the ANSI entry point of every file, environment and synchronisation API that only has a wide handler: strings the
// caller passes are widened before the wide handler runs, and text it returns is narrowed into the caller's buffer.
void register_ansi_adapters(ApiRegistry &registry);

// The 16-bit era file functions (_lopen, _lcreat, _lread, _lwrite, _llseek, _lclose, _hread, _hwrite), served by the file handlers of the
// current API. Registered after the file and ANSI handlers because they reuse them.
void register_legacy_file_api(ApiRegistry &registry);

}

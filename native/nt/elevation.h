#pragma once

#include "pe/pe.h"

#include <string_view>

namespace raven {

// Whether the program asks in its manifest to run with the administrator's full rights (requireAdministrator, or highestAvailable for
// an account that is an administrator), or names no level and is detected as an installer by its file name, as Windows decides when
// User Account Control starts it.
bool manifest_requests_elevation(const PEImage &image, std::string_view file_name);
// Whether this process runs elevated: its program asked for it, or the process that started it was elevated.
void set_process_elevated(bool elevated);
bool process_elevated();

}

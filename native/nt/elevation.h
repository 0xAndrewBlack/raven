#pragma once

#include "pe/pe.h"

namespace raven {

// Whether the program asks in its manifest to run with the administrator's full rights (requireAdministrator, or highestAvailable for
// an account that is an administrator), as Windows decides when User Account Control starts it.
bool manifest_requests_elevation(const PEImage &image);
// Whether this process runs elevated: its program asked for it, or the process that started it was elevated.
void set_process_elevated(bool elevated);
bool process_elevated();

}

#pragma once

#include "pe/pe.h"

#include <string_view>

namespace raven {

// Whether the program asks in its manifest to run with the administrator's full rights (requireAdministrator, or highestAvailable for
// an account that is an administrator), or names no level and is detected as an installer by its file name, as Windows decides when
// User Account Control starts it.
bool manifest_requests_elevation(const PEImage &image, std::string_view file_name);
// Whether a program looks like an installer: one that starts elevated, one named like a setup, update or redistributable package, the
// Windows Installer itself, a WiX bundle or an IExpress package. The runtime keeps a snapshot of the prefix before such a program runs.
bool installer_like(const PEImage &image, std::string_view file_name);
// Whether this process runs elevated: its program asked for it, or the process that started it was elevated.
void set_process_elevated(bool elevated);
bool process_elevated();
// Whether this process runs in the session services run in, as the Windows Installer server and the custom actions it starts do: its
// window station is not visible, so programs that look first show no dialog nobody could answer.
void set_process_noninteractive(bool noninteractive);
bool process_noninteractive();

}

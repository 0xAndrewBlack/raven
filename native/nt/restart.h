#pragma once

#include "prefix.h"

#include <filesystem>
#include <string>

namespace raven {

// MoveFileEx with MOVEFILE_DELAY_UNTIL_REBOOT: the move, or with no target the deletion, waits in the registry's
// PendingFileRenameOperations for the next start of Windows. Both names are full DOS paths; a replaced target is marked as Windows marks
// it. False when the registry could not be written.
bool queue_pending_rename(const NativePrefix &prefix, const std::u16string &from, const std::u16string &to, bool replace);

// What Windows does when it starts again: the pending moves and deletions are carried out, then the programs the RunOnce keys name run
// once, the machine's first and then the user's. `raven` is the runtime that runs them. Returns how many operations and programs ran.
size_t simulate_restart(const NativePrefix &prefix, const std::filesystem::path &raven);

}

#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace raven {

// Snapshots of a prefix, kept beside it in <prefix>.snapshots, one directory each, named by the time they were taken and what took
// them. A snapshot is never changed once taken: a file the prefix still holds unchanged is linked to the copy in the previous snapshot.
std::filesystem::path snapshot_directory(const std::filesystem::path &prefix);
std::vector<std::filesystem::path> list_snapshots(const std::filesystem::path &prefix);
std::filesystem::path take_snapshot(const std::filesystem::path &prefix, std::string_view label);
// Takes the prefix back to a snapshot, the newest when none is named; what the prefix held before is kept as a snapshot of its own,
// which is returned.
std::filesystem::path restore_snapshot(const std::filesystem::path &prefix, std::optional<std::string> name);
// Removes the oldest snapshots taken before installations beyond the newest `keep` of them.
void prune_snapshots(const std::filesystem::path &prefix, std::string_view suffix, size_t keep);

}

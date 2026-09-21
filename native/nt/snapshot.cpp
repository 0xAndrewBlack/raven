#include "snapshot.h"

#include <algorithm>
#include <cctype>
#include <ctime>
#include <stdexcept>

namespace raven {

namespace {

// Copies a tree: directories, symbolic links, and files with their modification times, which the next snapshot compares.
void copy_tree(const std::filesystem::path &from, const std::filesystem::path &to, const std::filesystem::path *previous)
{
	std::filesystem::create_directories(to);
	for (auto walk = std::filesystem::recursive_directory_iterator(from, std::filesystem::directory_options::skip_permission_denied);
		walk != std::filesystem::recursive_directory_iterator(); ++walk) {
		const auto relative = walk->path().lexically_relative(from);
		const auto target = to / relative;
		std::error_code error;
		if (walk->is_symlink(error)) {
			std::filesystem::copy_symlink(walk->path(), target);
		} else if (walk->is_directory(error)) {
			std::filesystem::create_directories(target);
		} else if (walk->is_regular_file(error)) {
			const auto size = walk->file_size(error);
			const auto modified = walk->last_write_time(error);
			if (previous) {
				// Unchanged since the previous snapshot: both snapshots share the one copy, which neither ever changes.
				const auto prior = *previous / relative;
				std::error_code missing;
				if (std::filesystem::is_regular_file(prior, missing) && std::filesystem::file_size(prior, missing) == size &&
					std::filesystem::last_write_time(prior, missing) == modified && !missing) {
					std::filesystem::create_hard_link(prior, target, error);
					if (!error)
						continue;
				}
			}
			std::filesystem::copy_file(walk->path(), target, std::filesystem::copy_options::overwrite_existing);
			std::filesystem::last_write_time(target, modified);
		}
	}
}

std::string timestamp()
{
	const std::time_t now = std::time(nullptr);
	std::tm parts{};
	localtime_r(&now, &parts);
	char text[32];
	std::strftime(text, sizeof(text), "%Y%m%d-%H%M%S", &parts);
	return text;
}

}

std::filesystem::path snapshot_directory(const std::filesystem::path &prefix)
{
	const auto plain = prefix.lexically_normal();
	const auto name = plain.has_filename() ? plain.filename() : plain.parent_path().filename();
	const auto parent = plain.has_filename() ? plain.parent_path() : plain.parent_path().parent_path();
	return parent / (name.string() + ".snapshots");
}

std::vector<std::filesystem::path> list_snapshots(const std::filesystem::path &prefix)
{
	std::vector<std::filesystem::path> found;
	std::error_code error;
	for (const auto &entry : std::filesystem::directory_iterator(snapshot_directory(prefix), error))
		if (entry.is_directory(error) && entry.path().extension() != ".partial")
			found.push_back(entry.path());
	std::sort(found.begin(), found.end());
	return found;
}

std::filesystem::path take_snapshot(const std::filesystem::path &prefix, std::string_view label)
{
	const auto store = snapshot_directory(prefix);
	std::filesystem::create_directories(store);
	const auto existing = list_snapshots(prefix);
	std::string name = timestamp() + "-";
	for (const char character : label)
		name.push_back(std::isalnum(static_cast<unsigned char>(character)) || character == '-' || character == '.' ? character : '_');
	// Two snapshots in the same second keep apart.
	const std::string first = name;
	for (int count = 2; std::filesystem::exists(store / name); ++count)
		name = first + "~" + std::to_string(count);
	const auto partial = store / (name + ".partial");
	std::filesystem::remove_all(partial);
	copy_tree(prefix, partial, existing.empty() ? nullptr : &existing.back());
	std::filesystem::rename(partial, store / name);
	return store / name;
}

std::filesystem::path restore_snapshot(const std::filesystem::path &prefix, std::optional<std::string> name)
{
	const auto snapshots = list_snapshots(prefix);
	std::filesystem::path chosen;
	if (name) {
		chosen = snapshot_directory(prefix) / *name;
		if (!std::filesystem::is_directory(chosen))
			throw std::runtime_error("no snapshot named " + *name);
	} else {
		if (snapshots.empty())
			throw std::runtime_error("the prefix has no snapshot");
		chosen = snapshots.back();
	}
	const auto kept = take_snapshot(prefix, "before-restore");
	std::error_code error;
	for (const auto &entry : std::filesystem::directory_iterator(prefix, error))
		std::filesystem::remove_all(entry.path());
	copy_tree(chosen, prefix, nullptr);
	return kept;
}

void prune_snapshots(const std::filesystem::path &prefix, std::string_view marker, size_t keep)
{
	std::vector<std::filesystem::path> marked;
	for (const auto &snapshot : list_snapshots(prefix))
		if (snapshot.filename().string().find(marker) != std::string::npos)
			marked.push_back(snapshot);
	for (size_t index = 0; index + keep < marked.size(); ++index)
		std::filesystem::remove_all(marked[index]);
}

}

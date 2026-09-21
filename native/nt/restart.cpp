#include "restart.h"
#include "paths.h"
#include "registry.h"
#include "text.h"

#include <cstring>
#include <spawn.h>
#include <sys/wait.h>
#include <vector>

extern char **environ;

namespace raven {

namespace {

constexpr uint64_t machine = 0x80000002ULL, user = 0x80000001ULL;
constexpr uint32_t multi_string = 7;
const std::u16string session_manager = u"SYSTEM\\CurrentControlSet\\Control\\Session Manager";

// REG_MULTI_SZ: strings each ended by a zero, the list ended by one more.
std::vector<std::u16string> strings_of(const std::vector<uint8_t> &data)
{
	std::vector<std::u16string> strings;
	std::u16string current;
	for (size_t at = 0; at + 1 < data.size(); at += 2) {
		const char16_t character = char16_t(data[at] | data[at + 1] << 8);
		if (character) {
			current.push_back(character);
			continue;
		}
		strings.push_back(current);
		current.clear();
	}
	// The terminator of the list reads as one empty string at the end.
	if (!strings.empty() && strings.back().empty() && data.size() >= 4)
		strings.pop_back();
	return strings;
}

std::vector<uint8_t> data_of(const std::vector<std::u16string> &strings)
{
	std::vector<uint8_t> data;
	for (const auto &text : strings) {
		for (const auto character : text) {
			data.push_back(uint8_t(character));
			data.push_back(uint8_t(character >> 8));
		}
		data.insert(data.end(), {0, 0});
	}
	data.insert(data.end(), {0, 0});
	return data;
}

// A path as the session manager writes it, \??\C:\..., to a DOS one.
std::u16string dos_path(std::u16string text)
{
	if (text.starts_with(u"!"))
		text.erase(0, 1);
	if (text.starts_with(u"\\??\\"))
		text.erase(0, 4);
	return text;
}

// Runs a command line the way a logon runs RunOnce entries, and waits for it.
void run_once(const NativePrefix &prefix, const std::filesystem::path &raven, const std::u16string &line)
{
	std::u16string program;
	if (line.starts_with(u"\"")) {
		const auto end = line.find(u'"', 1);
		program = line.substr(1, end == line.npos ? line.npos : end - 1);
	} else {
		program = line.substr(0, line.find_first_of(u" \t"));
	}
	const NativePaths paths(prefix);
	auto resolved = paths.resolve(program);
	if ((!resolved || !resolved->exists) && program.find_first_of(u"\\/:") == program.npos)
		resolved = paths.resolve(NativePaths::system_directory(true) + u"\\" + program);
	if (!resolved || !resolved->exists)
		return;
	std::vector<std::string> arguments{raven.string(), "--run-process", "--execution=native", "--timeout-ms=600000"};
	if (std::getenv("WAYLAND_DISPLAY"))
		arguments.push_back("--desktop=wayland");
	arguments.push_back("--command-line=" + to_utf8(line));
	arguments.push_back(resolved->host.string());
	std::vector<char *> argv;
	for (auto &argument : arguments)
		argv.push_back(argument.data());
	argv.push_back(nullptr);
	pid_t child = 0;
	if (::posix_spawn(&child, raven.c_str(), nullptr, nullptr, argv.data(), environ) == 0) {
		int status = 0;
		while (::waitpid(child, &status, 0) < 0 && errno == EINTR) {}
	}
}

}

bool queue_pending_rename(const NativePrefix &prefix, const std::u16string &from, const std::u16string &to, bool replace)
{
	NativeRegistry registry(prefix.registry_file());
	uint64_t key = 0;
	uint32_t disposition = 0;
	if (registry.create(machine, session_manager, key, disposition))
		return false;
	uint32_t type = 0;
	std::vector<uint8_t> data;
	auto strings = registry.query(key, u"PendingFileRenameOperations", type, data) || type != multi_string ? std::vector<std::u16string>() : strings_of(data);
	strings.push_back(u"\\??\\" + from);
	strings.push_back(to.empty() ? std::u16string() : (replace ? u"!\\??\\" : u"\\??\\") + to);
	const bool written = !registry.set(key, u"PendingFileRenameOperations", multi_string, data_of(strings));
	registry.close(key);
	return written;
}

size_t simulate_restart(const NativePrefix &prefix, const std::filesystem::path &raven)
{
	size_t done = 0;
	const NativePaths paths(prefix);
	{
		NativeRegistry registry(prefix.registry_file());
		uint64_t key = 0;
		if (!registry.open(machine, session_manager, key)) {
			for (const auto *value : {u"PendingFileRenameOperations", u"PendingFileRenameOperations2"}) {
				uint32_t type = 0;
				std::vector<uint8_t> data;
				if (registry.query(key, value, type, data) || type != multi_string)
					continue;
				const auto strings = strings_of(data);
				for (size_t index = 0; index + 1 < strings.size(); index += 2) {
					const auto source = paths.resolve(dos_path(strings[index]));
					if (!source || !source->exists)
						continue;
					std::error_code error;
					if (strings[index + 1].empty()) {
						std::filesystem::remove(source->host, error);
					} else {
						const auto target = paths.resolve(dos_path(strings[index + 1]));
						// Without the mark that allows it, an existing target is not replaced.
						if (!target || (target->exists && !strings[index + 1].starts_with(u"!")))
							continue;
						std::filesystem::rename(source->host, target->host, error);
					}
					if (!error)
						++done;
				}
				registry.remove_value(key, value);
			}
			registry.close(key);
		}
	}
	// RunOnce: each entry leaves the key before its program runs, unless its name starts with ! (then after); a name starting with *
	// would also run in safe mode.
	for (const uint64_t hive : {machine, user})
		for (const std::u16string root : {u"Software", u"Software\\Wow6432Node"}) {
			if (hive == user && root != u"Software")
				continue;
			const auto path = root + u"\\Microsoft\\Windows\\CurrentVersion\\RunOnce";
			std::vector<std::pair<std::u16string, std::u16string>> entries;
			{
				NativeRegistry registry(prefix.registry_file());
				uint64_t key = 0;
				if (registry.open(hive, path, key))
					continue;
				std::u16string name;
				uint32_t type = 0;
				std::vector<uint8_t> data;
				for (uint32_t index = 0; !registry.enum_value(key, index, name, type, data); ++index) {
					if (type != 1 && type != 2)
						continue;
					std::u16string text;
					for (size_t at = 0; at + 1 < data.size(); at += 2)
						if (const char16_t character = char16_t(data[at] | data[at + 1] << 8))
							text.push_back(character);
						else
							break;
					entries.emplace_back(name, text);
				}
				for (const auto &[name, text] : entries)
					if (!name.starts_with(u"!"))
						registry.remove_value(key, name);
				registry.close(key);
			}
			for (const auto &[name, text] : entries) {
				run_once(prefix, raven, text);
				++done;
				if (name.starts_with(u"!")) {
					NativeRegistry registry(prefix.registry_file());
					uint64_t key = 0;
					if (!registry.open(hive, path, key)) {
						registry.remove_value(key, name);
						registry.close(key);
					}
				}
			}
		}
	return done;
}

}

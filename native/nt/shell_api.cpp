#include "kernel_context.h"
#include "text.h"

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <sys/wait.h>
#include <unistd.h>

namespace raven {

namespace {

// Folder locations by CSIDL, relative to the user profile unless the path is absolute.
std::optional<std::u16string> folder_for(int csidl, const std::u16string &profile)
{
	switch (csidl & 0xff) {
	case 0x00: case 0x10: return profile + u"\\Desktop";
	case 0x02: return profile + u"\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs";
	case 0x05: return profile + u"\\Documents";
	case 0x06: return profile + u"\\Favorites";
	case 0x07: return profile + u"\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup";
	case 0x08: return profile + u"\\AppData\\Roaming\\Microsoft\\Windows\\Recent";
	case 0x09: return profile + u"\\AppData\\Roaming\\Microsoft\\Windows\\SendTo";
	case 0x0b: return profile + u"\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu";
	case 0x0d: return profile + u"\\Music";
	case 0x0e: return profile + u"\\Videos";
	case 0x14: return std::u16string(u"C:\\Windows\\Fonts");
	case 0x15: return profile + u"\\AppData\\Roaming\\Microsoft\\Windows\\Templates";
	case 0x16: return std::u16string(u"C:\\ProgramData\\Microsoft\\Windows\\Start Menu");
	case 0x17: return std::u16string(u"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs");
	case 0x19: return std::u16string(u"C:\\Users\\Public\\Desktop");
	case 0x1a: return profile + u"\\AppData\\Roaming";
	case 0x1c: return profile + u"\\AppData\\Local";
	case 0x20: return profile + u"\\AppData\\Local\\Microsoft\\Windows\\INetCache";
	case 0x21: return profile + u"\\AppData\\Local\\Microsoft\\Windows\\INetCookies";
	case 0x22: return profile + u"\\AppData\\Local\\Microsoft\\Windows\\History";
	case 0x23: return std::u16string(u"C:\\ProgramData");
	case 0x24: return std::u16string(u"C:\\Windows");
	case 0x25: case 0x29: return std::u16string(u"C:\\Windows\\System32");
	case 0x26: case 0x2b: return csidl == 0x2b ? std::u16string(u"C:\\Program Files\\Common Files") : std::u16string(u"C:\\Program Files");
	case 0x27: return profile + u"\\Pictures";
	case 0x28: return profile;
	case 0x2a: return std::u16string(u"C:\\Program Files (x86)");
	case 0x2c: return std::u16string(u"C:\\Program Files (x86)\\Common Files");
	default: return std::nullopt;
	}
}

// The double-NUL terminated file lists of SHFileOperation.
std::vector<std::u16string> file_list(ApiCall &call, uint64_t address)
{
	std::vector<std::u16string> result;
	if (!address)
		return result;
	for (;;) {
		auto item = call.wide(address, 32768);
		if (item.empty())
			return result;
		address += (item.size() + 1) * 2;
		result.push_back(std::move(item));
	}
}

}

void register_shell_api(ApiRegistry &registry, KernelContext &context)
{
	auto &paths = context.paths;
	registry.add("SHGetFolderPathW", 5, [&paths](ApiCall &call) {
		const int csidl = call.i32(1);
		const auto location = folder_for(csidl, paths.user_profile());
		if (!location) {
			call.ret(0x80070057U);
			return;
		}
		if (const auto resolved = paths.resolve(*location); resolved && csidl & 0x8000)
			std::filesystem::create_directories(resolved->host);
		call.put_wide(call[4], *location, 260);
		call.ret(0);
	});
	registry.add("SHGetSpecialFolderPathW", 4, [&paths](ApiCall &call) {
		const int csidl = call.i32(2);
		const auto location = folder_for(csidl, paths.user_profile());
		if (!location) {
			call.ret(0);
			return;
		}
		if (const auto resolved = paths.resolve(*location); resolved && call.u32(3))
			std::filesystem::create_directories(resolved->host);
		call.put_wide(call[1], *location, 260);
		call.ret(1);
	});
	registry.add("SHCreateDirectory", 2, [&paths](ApiCall &call) {
		const auto resolved = paths.resolve(call.wide(call[1]));
		if (!resolved) {
			call.ret(123);
			return;
		}
		std::error_code error;
		std::filesystem::create_directories(resolved->host, error);
		call.ret(error ? 5 : 0);
	});
	registry.add("SHCreateDirectoryExW", 3, [&paths](ApiCall &call) {
		const auto resolved = paths.resolve(call.wide(call[1]));
		if (!resolved) {
			call.ret(123);
			return;
		}
		std::error_code error;
		std::filesystem::create_directories(resolved->host, error);
		call.ret(error ? 5 : 0);
	});
	registry.add("CommandLineToArgvW", 2, [&context](ApiCall &call) {
		const auto line = call.wide(call[0]);
		std::vector<std::u16string> arguments;
		size_t at = 0;
		// Program name: quoted up to the next quote, otherwise up to the first blank.
		if (line.empty()) {
			arguments.push_back(context.launch.image_path);
		} else {
			std::u16string name;
			if (line[0] == u'"') {
				const auto end = line.find(u'"', 1);
				name = line.substr(1, end == line.npos ? line.npos : end - 1);
				at = end == line.npos ? line.size() : end + 1;
			} else {
				const auto end = line.find_first_of(u" \t");
				name = line.substr(0, end);
				at = end == line.npos ? line.size() : end;
			}
			arguments.push_back(name);
			bool quoted = false;
			std::u16string current;
			bool started = false;
			for (; at <= line.size(); ++at) {
				const char16_t character = at < line.size() ? line[at] : u'\0';
				if (!character || (!quoted && (character == u' ' || character == u'\t'))) {
					if (started)
						arguments.push_back(current);
					current.clear();
					started = false;
					continue;
				}
				started = true;
				if (character == u'\\') {
					size_t slashes = 0;
					while (at < line.size() && line[at] == u'\\') {
						++slashes;
						++at;
					}
					if (at < line.size() && line[at] == u'"') {
						current.append(slashes / 2, u'\\');
						if (slashes % 2)
							current.push_back(u'"');
						else
							quoted = !quoted;
					} else {
						current.append(slashes, u'\\');
						--at;
					}
				} else if (character == u'"') {
					quoted = !quoted;
				} else {
					current.push_back(character);
				}
			}
		}
		size_t bytes = arguments.size() * 8 + 8;
		for (const auto &argument : arguments)
			bytes += (argument.size() + 1) * 2;
		const auto block = context.allocator.allocate(bytes);
		if (!block) {
			call.fail(8);
			return;
		}
		uint64_t cursor = block + arguments.size() * 8 + 8;
		for (size_t index = 0; index < arguments.size(); ++index) {
			call.store<uint64_t>(block + index * 8, cursor);
			call.put_wide(cursor, arguments[index], arguments[index].size() + 1);
			cursor += (arguments[index].size() + 1) * 2;
		}
		call.store<uint64_t>(block + arguments.size() * 8, 0);
		if (call[1]) call.store<int32_t>(call[1], int32_t(arguments.size()));
		call.ret(block);
	});
	// The shell cannot show a tray icon or resolve file associations yet; callers see an honest failure.
	registry.add("Shell_NotifyIconW", 2, [](ApiCall &call) { call.fail(5); });
	registry.add("SHGetFileInfoW", 5, [](ApiCall &call) { call.ret(0); });
	registry.add("SHCreateItemFromParsingName", 4, [](ApiCall &call) {
		if (call[3]) call.store<uint64_t>(call[3], 0);
		call.ret(0x80070002U);
	});
	registry.add("DragQueryFileW", 4, [](ApiCall &call) { call.ret(0); });
	registry.add("DragQueryPoint", 2, [](ApiCall &call) { call.ret(0); });
	registry.add("DragFinish", 1, [](ApiCall &) {});
	registry.add("DragAcceptFiles", 2, [](ApiCall &) {});
	registry.add("ShellExecuteW", 6, [&paths](ApiCall &call) {
		const auto operation = call[1] ? call.wide(call[1]) : std::u16string(u"open");
		auto target = call.wide(call[2]);
		if (!equal_fold(operation, u"open") && !equal_fold(operation, u"edit") && !equal_fold(operation, u"explore")) {
			call.ret(31);
			return;
		}
		// Only documents, folders and URLs can be handed to the desktop; Windows programs need process creation.
		std::string argument;
		const bool url = target.find(u"://") != target.npos || target.starts_with(u"mailto:");
		if (url) {
			argument = to_utf8(target);
		} else if (const auto resolved = paths.resolve(target); resolved && resolved->exists) {
			const auto extension = std::filesystem::path(resolved->host).extension().string();
			if (equal_fold(from_utf8(extension), u".exe")) {
				call.ret(31);
				return;
			}
			argument = resolved->host.string();
		} else {
			call.ret(2);
			return;
		}
		const pid_t child = ::fork();
		if (child == 0) {
			::setsid();
			::execlp("xdg-open", "xdg-open", argument.c_str(), static_cast<char *>(nullptr));
			::_exit(127);
		}
		call.ret(child < 0 ? 0 : 42);
	});
	registry.add("SHFileOperationW", 1, [&paths](ApiCall &call) {
		const uint32_t function = call.load<uint32_t>(call[0] + 8);
		const uint64_t sources = call.load<uint64_t>(call[0] + 16), destinations = call.load<uint64_t>(call[0] + 24);
		const uint16_t flags = call.load<uint16_t>(call[0] + 32);
		const auto from = file_list(call, sources), to = file_list(call, destinations);
		call.store<int32_t>(call[0] + 36, 0);
		std::error_code error;
		for (size_t index = 0; index < from.size(); ++index) {
			const auto source = paths.resolve(from[index]);
			if (!source || !source->exists) {
				call.ret(0x402);
				return;
			}
			const auto destination = function == 3 ? std::nullopt : paths.resolve(to.size() == from.size() ? to[index] : to.empty() ? std::u16string() : to[0]);
			if (function == 3) {
				if (flags & 0x40) {
					// FOF_ALLOWUNDO: move into the prefix recycle bin instead of destroying the item.
					const auto bin = paths.resolve(u"C:\\$Recycle.Bin");
					std::filesystem::create_directories(bin->host, error);
					std::filesystem::rename(source->host, bin->host / source->host.filename(), error);
					if (error) {
						std::filesystem::remove_all(source->host, error);
					}
				} else {
					std::filesystem::remove_all(source->host, error);
				}
			} else if (function == 2 && destination) {
				auto target = destination->host;
				if (std::filesystem::is_directory(target) && !(flags & 0x400))
					target /= source->host.filename();
				std::filesystem::copy(source->host, target, std::filesystem::copy_options::recursive | std::filesystem::copy_options::overwrite_existing, error);
			} else if ((function == 1 || function == 4) && destination) {
				auto target = destination->host;
				if (function == 1 && std::filesystem::is_directory(target))
					target /= source->host.filename();
				std::filesystem::rename(source->host, target, error);
			}
			if (error) {
				call.ret(0x7c);
				return;
			}
		}
		call.ret(0);
	});
}

}

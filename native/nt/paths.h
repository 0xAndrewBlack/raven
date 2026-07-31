#pragma once

#include "prefix.h"

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

namespace raven {

// Windows path semantics over a prefix: C: is the prefix drive, Z: is the host root, other letters map to drive_<letter>.
class NativePaths {
public:
	explicit NativePaths(const NativePrefix &prefix);
	const std::u16string &current() const { return directory; }
	// The directory must exist; the stored form is a full path without a trailing separator (except for roots).
	bool set_current(std::u16string_view path);
	// Full drive-qualified path without "." or ".." parts and with backslashes; empty when the text is not a path.
	std::u16string full(std::u16string_view path) const;
	struct Resolved {
		std::filesystem::path host;
		bool exists = false;
		// Every directory above the final component exists, so a new file can be created.
		bool parent_exists = false;
	};
	std::optional<Resolved> resolve(std::u16string_view path) const;
	// DOS spelling of a host path inside a mapped drive.
	std::u16string dos(const std::filesystem::path &host) const;
	// User name shown to the guest; the host login name keeps profiles of different accounts apart.
	std::u16string user_name() const;
	// C:\Users\<user>, created on first use together with AppData\Roaming and AppData\Local\Temp.
	std::u16string user_profile() const;
	std::u16string temporary() const;
	// True for the DOS device names that are not files (NUL, CON, ...), optionally behind \\.\ or \\?\.
	static bool device(std::u16string_view path);

private:
	const NativePrefix &prefix;
	std::u16string directory;
	std::optional<std::filesystem::path> drive_root(char16_t letter) const;
};

}

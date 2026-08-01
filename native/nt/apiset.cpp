#include "apiset.h"

#include <array>

namespace raven {

std::string apiset_host(std::string_view name)
{
	std::string lower(name);
	for (auto &character : lower)
		if (character >= 'A' && character <= 'Z')
			character = char(character + ('a' - 'A'));
	if (lower.ends_with(".dll"))
		lower.resize(lower.size() - 4);
	if (!lower.starts_with("api-ms-win-") && !lower.starts_with("ext-ms-win-") && !lower.starts_with("api-ms-onecoreuap-"))
		return {};
	struct Family {
		std::string_view prefix, host;
	};
	static constexpr std::array<Family, 17> families{{
		{"api-ms-win-core-registry-", "advapi32.dll"}, {"api-ms-win-security-", "advapi32.dll"}, {"api-ms-win-core-security-", "advapi32.dll"},
		{"api-ms-win-eventing-", "advapi32.dll"}, {"api-ms-win-core-com-", "ole32.dll"}, {"api-ms-win-core-shlwapi-", "shlwapi.dll"},
		{"api-ms-win-shell-", "shell32.dll"}, {"api-ms-win-core-shell-", "shell32.dll"}, {"ext-ms-win-ntuser-", "user32.dll"},
		{"api-ms-win-core-localization-", "kernel32.dll"}, {"api-ms-win-gdi-", "gdi32.dll"}, {"ext-ms-win-gdi-", "gdi32.dll"},
		{"api-ms-win-core-ntuser-", "user32.dll"}, {"api-ms-win-service-", "advapi32.dll"}, {"api-ms-win-devices-", "setupapi.dll"},
		{"api-ms-win-core-psapi-", "psapi.dll"}, {"api-ms-win-crt-", "ucrtbase.dll"},
	}};
	for (const auto &family : families)
		if (lower.starts_with(family.prefix))
			return std::string(family.host);
	return "kernel32.dll";
}

}

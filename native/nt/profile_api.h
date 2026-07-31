#pragma once

#include "environment.h"
#include "prefix.h"

namespace raven {

// GetPrivateProfile* over INI files that live in the prefix.
class NativeProfile {
public:
	NativeProfile(NativeProcess &process, NativeEnvironment &environment, const NativePrefix &prefix);
	bool dispatch(std::string_view name);

private:
	NativeProcess &process;
	NativeEnvironment &environment;
	const NativePrefix &prefix;
	std::optional<std::u16string> text(uint64_t address) const;
};

}

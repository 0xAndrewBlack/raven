#pragma once

#include "environment.h"
#include "api.h"
#include "prefix.h"

namespace raven {

// GetPrivateProfile* over INI files that live in the prefix.
class NativeProfile {
public:
	NativeProfile(NativeProcess &process, NativeEnvironment &environment, const NativePrefix &prefix);
	bool dispatch(std::string_view name);
	// Runs one profile call with its arguments already read; false when the name is not a profile API.
	bool execute(std::string_view name, const std::vector<uint64_t> &args, uint64_t &result);

private:
	NativeProcess &process;
	NativeEnvironment &environment;
	const NativePrefix &prefix;
	std::optional<std::u16string> text(uint64_t address) const;
	uint64_t put_list(uint64_t address, size_t capacity, const std::vector<std::u16string> &entries) const;
};

void register_profile_api(ApiRegistry &registry, NativeProfile &profile);

}

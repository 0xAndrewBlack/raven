#pragma once

#include "environment.h"
#include "registry.h"

namespace raven {

// advapi32 registry entry points over one shared registry; results are Win32 error codes, not last-error values.
class NativeAdvapi {
public:
	NativeAdvapi(NativeProcess &process, NativeEnvironment &environment, NativeRegistry &registry);
	bool dispatch(std::string_view name);
	static std::span<const std::string_view> exports();
	// stdcall argument counts matching exports().
	static uint32_t argument_count(std::string_view name);

private:
	NativeProcess &process;
	NativeEnvironment &environment;
	NativeRegistry &registry;
	std::optional<std::u16string> guest_string(uint64_t address, bool wide, uint32_t &error) const;
	void write_value(uint64_t address, uint64_t value, size_t width);
};

}

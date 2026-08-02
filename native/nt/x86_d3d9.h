#pragma once

#include "environment.h"

#include <map>
#include <string>
#include <vector>

namespace raven {

// Direct3D 9 for 32-bit programs. Every method of the interfaces is a trap named "Interface.Method"; the objects a program holds
// are guest memory blocks whose first word points at a vtable of those traps.
class NativeX86D3D9 {
public:
	NativeX86D3D9(NativeProcess &process, NativeEnvironment &environment);
	// Export names and word counts of the method traps, and of the entry point the program resolves from d3d9.dll.
	static std::vector<std::string_view> method_names();
	static uint32_t method_words(std::string_view name);
	static std::span<const std::string_view> entry_names();
	// Where each method trap lives; vtables are built from it the first time a program asks for Direct3D.
	void set_trap_addresses(std::map<std::string, uint64_t> addresses) { trap_addresses = std::move(addresses); }
	bool dispatch(std::string_view name);

private:
	NativeProcess &process;
	NativeEnvironment &environment;
	std::map<std::string, uint64_t> trap_addresses;
	std::map<std::string, uint64_t> vtables;
	uint64_t vtable(const std::string &interface);
	uint64_t make_object(const std::string &interface);
	std::map<uint64_t, std::string> interfaces;
};

}

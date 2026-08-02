#pragma once

#include "environment.h"

#include <map>
#include <span>
#include <string>
#include <vector>

namespace raven {

struct ComMethod {
	std::string_view interface, name;
	uint32_t index, words;
};

// Export names and word counts of the method traps of a method table, for libraries that exist before the process does.
std::vector<std::string_view> com_names(std::span<const ComMethod> methods);
uint32_t com_words(std::span<const ComMethod> methods, std::string_view name);

// COM objects for 32-bit programs. Every method of an interface is a trap named "Interface.Method"; an object is a guest memory block
// whose first word points at a vtable of those traps and whose second word is its reference count.
class NativeX86Com {
public:
	NativeX86Com(NativeProcess &process, std::span<const ComMethod> methods);
	uint32_t words(std::string_view name) const;
	bool owns(std::string_view name) const { return by_name.contains(std::string(name)); }
	// Where each method trap lives; vtables are built from it when the first object is made.
	void set_trap_addresses(std::map<std::string, uint64_t> addresses) { trap_addresses = std::move(addresses); }
	uint64_t make_object(const std::string &interface);
	// The interface and method a trap name stands for.
	std::pair<std::string_view, std::string_view> split(std::string_view name) const;
	// Reference counting every object shares: true when the method was one of those.
	bool counted(std::string_view method, const std::vector<uint64_t> &args);
	void write32(uint64_t address, uint32_t value);
	uint32_t read32(uint64_t address);

private:
	NativeProcess &process;
	std::span<const ComMethod> methods;
	std::map<std::string, uint32_t> by_name;
	std::map<std::string, uint64_t> trap_addresses;
	std::map<std::string, uint64_t> vtables;
	uint64_t vtable(const std::string &interface);
};

}

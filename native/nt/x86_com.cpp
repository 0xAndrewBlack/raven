#include "x86_com.h"

#include <algorithm>
#include <deque>
#include <sys/mman.h>
#include <stdexcept>

namespace raven {

NativeX86Com::NativeX86Com(NativeProcess &process, std::span<const ComMethod> methods) : process(process), methods(methods)
{
	for (const auto &method : methods)
		by_name.emplace(std::string(method.interface) + "." + std::string(method.name), method.words);
}

std::vector<std::string_view> com_names(std::span<const ComMethod> methods)
{
	// The strings live as long as the process.
	static std::deque<std::string> storage;
	std::vector<std::string_view> result;
	for (const auto &method : methods) {
		storage.push_back(std::string(method.interface) + "." + std::string(method.name));
		result.push_back(storage.back());
	}
	std::sort(result.begin(), result.end());
	result.erase(std::unique(result.begin(), result.end()), result.end());
	return result;
}

uint32_t com_words(std::span<const ComMethod> methods, std::string_view name)
{
	for (const auto &method : methods)
		if (name.size() == method.interface.size() + 1 + method.name.size() && name.starts_with(method.interface) && name.ends_with(method.name))
			return method.words;
	return 0;
}

uint32_t NativeX86Com::words(std::string_view name) const
{
	const auto found = by_name.find(std::string(name));
	return found == by_name.end() ? 0 : found->second;
}

std::pair<std::string_view, std::string_view> NativeX86Com::split(std::string_view name) const
{
	const auto separator = name.find('.');
	return {name.substr(0, separator), name.substr(separator + 1)};
}

void NativeX86Com::write32(uint64_t address, uint32_t value)
{
	const uint8_t bytes[4] = {uint8_t(value), uint8_t(value >> 8), uint8_t(value >> 16), uint8_t(value >> 24)};
	process.write_memory(address, bytes);
}

uint32_t NativeX86Com::read32(uint64_t address)
{
	const auto bytes = process.read_memory(address, 4);
	return uint32_t(bytes[0]) | uint32_t(bytes[1]) << 8 | uint32_t(bytes[2]) << 16 | uint32_t(bytes[3]) << 24;
}

uint64_t NativeX86Com::vtable(const std::string &interface)
{
	const auto known = vtables.find(interface);
	if (known != vtables.end())
		return known->second;
	const auto base = process.map_memory(4096, PROT_READ | PROT_WRITE);
	size_t entries = 0;
	for (const auto &method : methods)
		if (method.interface == interface) {
			const auto name = interface + "." + std::string(method.name);
			const auto trap = trap_addresses.find(name);
			if (trap == trap_addresses.end())
				throw std::runtime_error("native COM method has no trap: " + name);
			write32(base + method.index * 4ULL, uint32_t(trap->second));
			++entries;
		}
	if (!entries)
		throw std::runtime_error("native COM has no interface " + interface);
	vtables[interface] = base;
	return base;
}

// An object is the vtable pointer, the reference count and room for the implementation.
uint64_t NativeX86Com::make_object(const std::string &interface)
{
	const auto object = process.map_memory(4096, PROT_READ | PROT_WRITE);
	write32(object, uint32_t(vtable(interface)));
	write32(object + 4, 1);
	return object;
}

bool NativeX86Com::counted(std::string_view method, const std::vector<uint64_t> &args)
{
	if (method != "AddRef" && method != "Release")
		return false;
	const auto count = read32(args[0] + 4) + (method == "AddRef" ? 1 : uint32_t(-1));
	write32(args[0] + 4, count);
	process.return_api(count);
	return true;
}

}
